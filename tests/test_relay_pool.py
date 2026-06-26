"""
Tests for the Nostr relay pool — dedup logic and reconnection.
"""

import asyncio
import pytest
from collections import OrderedDict
from plugins.platforms.nostr.relay_pool import RelayPool, RelayConnection, MAX_DEDUP_SIZE


class TestDedup:
    """Test event deduplication logic."""

    def test_new_event_is_accepted(self):
        """First sighting of an event ID should return True (new)."""
        pool = RelayPool([])
        assert pool._check_dedup("event1") is True

    def test_duplicate_event_is_rejected(self):
        """Second sighting of same event ID should return False (dup)."""
        pool = RelayPool([])
        pool._check_dedup("event1")
        assert pool._check_dedup("event1") is False

    def test_different_events_both_accepted(self):
        """Different event IDs should both be accepted."""
        pool = RelayPool([])
        assert pool._check_dedup("event1") is True
        assert pool._check_dedup("event2") is True

    def test_dedup_eviction_at_capacity(self):
        """Dedup set should evict oldest entries at capacity."""
        pool = RelayPool([])
        pool._max_dedup = 100  # Small limit for testing

        # Fill to capacity
        for i in range(100):
            pool._check_dedup(f"event_{i}")

        assert len(pool._seen_ids) == 100

        # Adding one more should trigger eviction (removes 25%)
        pool._check_dedup("new_event")
        # After eviction, size should be <= capacity (evicted 25, added 1)
        assert len(pool._seen_ids) <= 100
        assert "new_event" in pool._seen_ids
        # Oldest entries should have been evicted
        assert "event_0" not in pool._seen_ids


class TestRelayConnection:
    """Test RelayConnection class."""

    def test_init(self):
        """RelayConnection should initialize with correct URL."""
        conn = RelayConnection("wss://relay.example.com")
        assert conn.url == "wss://relay.example.com"
        assert conn.connected is False
        assert conn.ws is None

    def test_reconnect_delay_increases(self):
        """Reconnect delay should increase exponentially."""
        conn = RelayConnection("wss://relay.example.com")
        conn._reconnect_attempts = 0
        delay_0 = conn._reconnect_delay()
        conn._reconnect_attempts = 3
        delay_3 = conn._reconnect_delay()
        assert delay_3 > delay_0

    def test_reconnect_delay_capped(self):
        """Reconnect delay should be capped at 30s."""
        conn = RelayConnection("wss://relay.example.com")
        conn._reconnect_attempts = 10  # Very high
        delay = conn._reconnect_delay()
        assert delay <= 31  # 30s cap + 1s jitter


class TestRelayPool:
    """Test RelayPool management."""

    def test_init(self):
        """RelayPool should initialize with correct config."""
        pool = RelayPool(
            ["wss://relay1.com", "wss://relay2.com"],
        )
        assert len(pool.relay_urls) == 2
        assert pool._running is False

    def test_no_relays(self):
        """RelayPool with no relays should still initialize."""
        pool = RelayPool([])
        assert len(pool.relay_urls) == 0
        assert len(pool.connections) == 0


class TestSubscribeSubIds:
    """Test that subscribe() assigns unique, stable sub_ids."""

    async def test_sub_ids_unique_across_calls(self):
        """Two subscribe() calls must not produce colliding sub_ids."""
        pool = RelayPool([])
        ids1 = await pool.subscribe([{"kinds": [1]}, {"kinds": [4]}])
        ids2 = await pool.subscribe([{"kinds": [1059]}])
        all_ids = ids1 + ids2
        assert len(all_ids) == len(set(all_ids)), "sub_ids must be unique"

    async def test_subscriptions_stored_with_ids(self):
        """Each subscription is stored as (filter, sub_id) for reconnect."""
        pool = RelayPool([])
        await pool.subscribe([{"kinds": [1]}])
        assert len(pool._subscriptions) == 1
        f, sub_id = pool._subscriptions[0]
        assert f == {"kinds": [1]}
        assert sub_id.startswith("sub_")


class TestPublishRouting:
    """Test publish() collects OK frames via _handle_message routing."""

    async def test_publish_collects_ok_from_relays(self):
        """publish() should resolve per-relay futures when OK frames arrive."""
        pool = RelayPool([])
        conn = RelayConnection("wss://relay.example.com")
        conn.connected = True
        pool.connections[conn.url] = conn

        event = {"id": "abc123", "kind": 1, "content": "hi"}

        # Drive the publish concurrently and feed it an OK frame.
        async def feed_ok():
            await asyncio.sleep(0)  # let publish() register the future
            await pool._handle_message(conn, ["OK", "abc123", True, ""])

        feed_task = asyncio.create_task(feed_ok())
        results = await pool.publish(event, timeout=2.0)
        await feed_task
        assert conn.url in results
        assert results[conn.url]["accepted"] is True

    async def test_publish_timeout_omits_silent_relays(self):
        """Relays that never respond are omitted (not reported as accepted)."""
        pool = RelayPool([])
        conn = RelayConnection("wss://slow.example.com")
        conn.connected = True
        pool.connections[conn.url] = conn
        # No OK frame fed — should time out with empty result.
        results = await pool.publish({"id": "none"}, timeout=0.2)
        assert results == {}

    async def test_concurrent_same_event_id_publishes_both_resolve(self):
        """Two concurrent publishes of the same event_id must both get their
        OK resolved, instead of the second clobbering the first's futures."""
        pool = RelayPool([])
        conn = RelayConnection("wss://relay.example.com")
        conn.connected = True
        pool.connections[conn.url] = conn

        shared_event = {"id": "same_id", "kind": 1}

        async def feed_both():
            await asyncio.sleep(0)  # let both publishes register their groups
            # Two groups must now be registered for this event_id.
            assert len(pool._pending_ok["same_id"]) == 2
            # One OK frame should resolve BOTH groups' futures for this relay.
            await pool._handle_message(conn, ["OK", "same_id", True, ""])

        feed_task = asyncio.create_task(feed_both())
        # Run two concurrent publishes of the same event.
        r1, r2 = await asyncio.gather(
            pool.publish(shared_event, timeout=2.0),
            pool.publish(shared_event, timeout=2.0),
        )
        await feed_task
        # Both must report acceptance — the regression orphaned the first.
        assert r1.get(conn.url, {}).get("accepted") is True
        assert r2.get(conn.url, {}).get("accepted") is True


class TestQueryRouting:
    """Test query() collects events and stops at EOSE."""

    async def test_query_collects_events_until_eose(self):
        """query() should collect EVENT frames and stop at EOSE."""
        pool = RelayPool([])
        conn = RelayConnection("wss://relay.example.com")
        conn.connected = True
        pool.connections[conn.url] = conn

        async def feed():
            await asyncio.sleep(0)  # let query() register the sub
            # Find the active query sub_id.
            sub_id = next(iter(pool._active_queries))
            await pool._handle_message(conn, ["EVENT", sub_id, {"id": "e1"}])
            await pool._handle_message(conn, ["EVENT", sub_id, {"id": "e2"}])
            await pool._handle_message(conn, ["EOSE", sub_id])

        feed_task = asyncio.create_task(feed())
        events = await pool.query({"kinds": [1]}, timeout=2.0)
        await feed_task
        ids = [e["id"] for e in events]
        assert "e1" in ids and "e2" in ids

    async def test_query_deduplicates_events_across_relays(self):
        """The same event served by multiple relays must appear only once."""
        pool = RelayPool([])
        conn_a = RelayConnection("wss://a.example.com")
        conn_b = RelayConnection("wss://b.example.com")
        conn_a.connected = conn_b.connected = True
        pool.connections[conn_a.url] = conn_a
        pool.connections[conn_b.url] = conn_b

        async def feed():
            await asyncio.sleep(0)
            sub_id = next(iter(pool._active_queries))
            # Both relays deliver the identical event.
            await pool._handle_message(conn_a, ["EVENT", sub_id, {"id": "dup"}])
            await pool._handle_message(conn_b, ["EVENT", sub_id, {"id": "dup"}])
            await pool._handle_message(conn_a, ["EOSE", sub_id])
            await pool._handle_message(conn_b, ["EOSE", sub_id])

        feed_task = asyncio.create_task(feed())
        events = await pool.query({"kinds": [1]}, timeout=2.0)
        await feed_task
        ids = [e["id"] for e in events]
        assert ids.count("dup") == 1, "duplicate event across relays not deduped"


class TestConnectLifecycle:
    """Test connect()/disconnect() task management."""

    async def test_double_connect_cancels_old_tasks(self, monkeypatch):
        """A second connect() must cancel tasks from the first call, not
        spawn duplicates on the same RelayConnection (which would re-open
        sockets and recreate the double-connect leak)."""
        pool = RelayPool(["wss://a.example.com", "wss://b.example.com"])

        # Stub conn.connect() so no real websocket is opened; mark connected
        # so a listen task actually starts.
        async def fake_connect(self):
            self.connected = True
            return True

        async def fake_listen_relay(self, conn):
            # Park forever until cancelled — mimics a real listen loop.
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                raise

        monkeypatch.setattr(RelayConnection, "connect", fake_connect)
        monkeypatch.setattr(RelayPool, "_listen_relay", fake_listen_relay)

        await pool.connect()
        first_count = len(pool._listen_tasks)
        assert first_count == 2  # one per relay

        # Second connect without disconnect — must replace, not duplicate.
        await pool.connect()
        assert len(pool._listen_tasks) == 2, (
            "second connect() must cancel old tasks and spawn exactly one "
            "task per relay, not accumulate duplicates"
        )

        # Old tasks should be done/cancelled, not still running.
        for t in pool._listen_tasks:
            assert not t.done(), "current tasks should still be running"
        await pool.disconnect()

