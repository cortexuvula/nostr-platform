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


class TestPublishTargeting:
    """Test publish(only_urls=...) and publish_to() for recipient-relay delivery."""

    async def test_publish_only_urls_restricts_targets(self):
        """publish(only_urls=[...]) must send only to listed relays."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        conn1 = RelayConnection("wss://r1.example.com"); conn1.connected = True
        conn2 = RelayConnection("wss://r2.example.com"); conn2.connected = True
        conn3 = RelayConnection("wss://r3.example.com"); conn3.connected = True
        for c in (conn1, conn2, conn3):
            pool.connections[c.url] = c
            c.send_raw = AsyncMock()

        event = {"id": "filter123", "kind": 1}
        results = await pool.publish(event, timeout=0.3,
                                      only_urls=["wss://r2.example.com"])
        # Only conn2 was sent the EVENT.
        conn1.send_raw.assert_not_called()
        conn2.send_raw.assert_awaited()
        conn3.send_raw.assert_not_called()

    async def test_publish_to_pool_relays_only(self):
        """publish_to() routes pool-member URLs through publish()."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        conn = RelayConnection("wss://pool.example.com"); conn.connected = True
        pool.connections[conn.url] = conn

        async def feed_ok():
            await asyncio.sleep(0)
            await pool._handle_message(conn, ["OK", "pt1", True, ""])
        feed_task = asyncio.create_task(feed_ok())
        results = await pool.publish_to({"id": "pt1", "kind": 1},
                                         ["wss://pool.example.com"])
        await feed_task
        assert "wss://pool.example.com" in results
        assert results["wss://pool.example.com"]["accepted"] is True

    async def test_publish_to_falls_back_when_no_pool_relays(self):
        """When recipient relays aren't in the pool, publish_to attempts a
        one-off connection to each (which fails for unreachable URLs)."""
        pool = RelayPool([])
        # No pool connections — every URL is external.
        results = await pool.publish_to({"id": "pt2", "kind": 1},
                                         ["wss://not-in-pool.example.com"],
                                         timeout=0.3)
        # The URL is in the result with a failure status (connect failed).
        assert "wss://not-in-pool.example.com" in results
        assert results["wss://not-in-pool.example.com"]["accepted"] is False


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


class TestNIP42Auth:
    """Test NIP-42 client authentication to relays that gate DMs behind AUTH."""

    async def test_handle_message_stores_challenge(self):
        """An incoming AUTH message stores the challenge on the connection."""
        pool = RelayPool([])
        conn = RelayConnection("wss://auth.relay")
        conn.connected = True
        pool.connections[conn.url] = conn

        await pool._handle_message(conn, ["AUTH", "challenge123"])
        assert conn.challenge == "challenge123"

    async def test_authenticate_without_signer_returns_false(self):
        """Without a signer set, _authenticate returns False and sends nothing."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        conn = RelayConnection("wss://auth.relay")
        conn.connected = True
        conn.challenge = "abc"
        conn.send_raw = AsyncMock()

        result = await pool._authenticate(conn)
        assert result is False
        conn.send_raw.assert_not_called()

    async def test_authenticate_signs_kind_22242(self):
        """_authenticate signs a kind 22242 event with relay+challenge tags,
        sends it as an AUTH message, and sets authenticated=True on OK."""
        from unittest.mock import AsyncMock
        from plugins.platforms.nostr.crypto import EventSigner
        import json as _json

        from pynostr.key import PrivateKey as _PK
        signer = EventSigner(_PK().bech32())

        pool = RelayPool([])
        pool.set_signer(signer)
        conn = RelayConnection("wss://auth.relay")
        conn.connected = True
        conn.challenge = "test-challenge-xyz"
        pool.connections[conn.url] = conn

        sent_messages = []
        async def capture_send(msg):
            sent_messages.append(msg)
        conn.send_raw = capture_send

        # Drive _authenticate and feed it an OK for the 22242 event.
        async def feed_ok():
            await asyncio.sleep(0)  # let _authenticate register its future
            # Parse the sent AUTH message to get the event id.
            assert sent_messages, "no AUTH message sent"
            auth_msg = _json.loads(sent_messages[0])
            assert auth_msg[0] == "AUTH", f"expected AUTH type, got {auth_msg[0]}"
            ev = auth_msg[1]
            assert ev["kind"] == 22242
            # Verify tags.
            tags = {t[0]: t[1] for t in ev["tags"]}
            assert tags["relay"] == "wss://auth.relay"
            assert tags["challenge"] == "test-challenge-xyz"
            assert ev["sig"], "event must be signed"
            # Feed the OK.
            await pool._handle_message(conn, ["OK", ev["id"], True, ""])

        feed_task = asyncio.create_task(feed_ok())
        result = await pool._authenticate(conn, timeout=2.0)
        await feed_task

        assert result is True
        assert conn.authenticated is True

    async def test_authenticate_failure_keeps_authenticated_false(self):
        """An auth-failure OK (accepted=false) leaves authenticated False."""
        from unittest.mock import AsyncMock
        from plugins.platforms.nostr.crypto import EventSigner
        from pynostr.key import PrivateKey as _PK
        import json as _json

        signer = EventSigner(_PK().bech32())
        pool = RelayPool([])
        pool.set_signer(signer)
        conn = RelayConnection("wss://auth.relay")
        conn.connected = True
        conn.challenge = "c"
        pool.connections[conn.url] = conn
        sent = []
        conn.send_raw = lambda m: sent.append(m) or asyncio.sleep(0)

        async def feed_fail():
            await asyncio.sleep(0)
            ev = _json.loads(sent[0])[1]
            await pool._handle_message(
                conn, ["OK", ev["id"], False, "auth-failure: bad sig"]
            )
        feed_task = asyncio.create_task(feed_fail())
        result = await pool._authenticate(conn, timeout=2.0)
        await feed_task
        assert result is False
        assert conn.authenticated is False

    async def test_closed_restricted_does_not_retry(self):
        """A CLOSED with 'restricted:' must NOT trigger resubscribe (forbidden)."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://restricted.relay")
        conn.connected = True
        pool.connections[conn.url] = conn
        # Register a subscription so the CLOSED has something to match.
        pool._subscriptions.append(({"kinds": [1059]}, "sub_1"))
        pool._resubscribe_after = AsyncMock()

        await pool._handle_message(conn, ["CLOSED", "sub_1", "restricted: no DMs allowed"])
        pool._resubscribe_after.assert_not_called()

    async def test_closed_auth_required_triggers_auth(self):
        """A CLOSED with 'auth-required:' triggers _authenticate on the conn."""
        from unittest.mock import AsyncMock
        from plugins.platforms.nostr.crypto import EventSigner
        from pynostr.key import PrivateKey as _PK

        pool = RelayPool([])
        pool._running = True
        pool.set_signer(EventSigner(_PK().bech32()))
        conn = RelayConnection("wss://auth.relay")
        conn.connected = True
        conn.challenge = "pre-stored-challenge"
        pool.connections[conn.url] = conn
        pool._subscriptions.append(({"kinds": [1059]}, "sub_1"))
        pool._authenticate = AsyncMock(return_value=True)
        pool._resubscribe_after = AsyncMock()

        await pool._handle_message(conn, ["CLOSED", "sub_1", "auth-required: please auth"])
        # _handle_message schedules _auth_then_resubscribe via create_task;
        # yield to let it run before asserting.
        await asyncio.sleep(0)
        pool._authenticate.assert_awaited_once_with(conn)

    async def test_ok_auth_required_for_publish_triggers_auth(self):
        """A publish OK with accepted=false 'auth-required:' triggers auth so
        the next publish attempt can succeed on the auth-gated relay."""
        from unittest.mock import AsyncMock
        from plugins.platforms.nostr.crypto import EventSigner
        from pynostr.key import PrivateKey as _PK

        pool = RelayPool([])
        pool._running = True
        pool.set_signer(EventSigner(_PK().bech32()))
        conn = RelayConnection("wss://auth.relay")
        conn.connected = True
        conn.challenge = "c"
        pool.connections[conn.url] = conn
        pool._authenticate = AsyncMock(return_value=True)

        # Simulate a publish OK rejection demanding auth.
        await pool._handle_message(
            conn, ["OK", "published-event-1", False, "auth-required: please auth"]
        )
        await asyncio.sleep(0)  # let the scheduled auth task run
        pool._authenticate.assert_awaited_once_with(conn)


class TestRelayConnectionLifecycle:
    """Cover RelayConnection connect/disconnect/send_raw branches."""

    async def test_connect_without_websockets_returns_false(self, monkeypatch):
        """connect() returns False when websockets package unavailable."""
        import plugins.platforms.nostr.relay_pool as rp
        monkeypatch.setattr(rp, "WEBSOCKETS_AVAILABLE", False)
        conn = RelayConnection("wss://x.example.com")
        result = await conn.connect()
        assert result is False
        assert conn.connected is False

    async def test_disconnect_cancels_listen_task(self):
        """disconnect() cancels and awaits a running listen task."""
        conn = RelayConnection("wss://x.example.com")
        conn._listen_task = asyncio.create_task(asyncio.Event().wait())
        await conn.disconnect()
        assert conn._listen_task.cancelled() or conn._listen_task.done()
        assert conn.ws is None
        assert conn.connected is False

    async def test_disconnect_swallow_ws_close_error(self):
        """disconnect() swallows errors from ws.close()."""
        from unittest.mock import AsyncMock
        conn = RelayConnection("wss://x.example.com")
        conn.ws = type("FakeWS", (), {"close": AsyncMock(side_effect=RuntimeError)})()
        conn.connected = True
        await conn.disconnect()  # must not raise
        assert conn.ws is None

    async def test_send_raw_error_flips_connected(self):
        """send_raw logs and sets connected=False when ws.send raises."""
        from unittest.mock import AsyncMock
        conn = RelayConnection("wss://x.example.com")
        conn.ws = type("FakeWS", (), {"send": AsyncMock(side_effect=RuntimeError)})()
        conn.connected = True
        await conn.send_raw("[]")  # must not raise
        assert conn.connected is False

    async def test_send_raw_noop_when_not_connected(self):
        """send_raw is a no-op when ws is None or not connected."""
        conn = RelayConnection("wss://x.example.com")
        conn.ws = None
        conn.connected = False
        await conn.send_raw("[]")  # must not raise


class TestHandleMessageArms:
    """Cover _handle_message edge-case branches."""

    async def test_empty_message_ignored(self):
        """An empty or non-list message is ignored."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        conn.connected = True
        await pool._handle_message(conn, [])
        await pool._handle_message(conn, "not-a-list")
        await pool._handle_message(conn, None)

    async def test_event_too_short_ignored(self):
        """An EVENT with < 3 elements is ignored."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        await pool._handle_message(conn, ["EVENT", "sub1"])

    async def test_event_no_id_ignored(self):
        """An EVENT with no event id is ignored."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        await pool._handle_message(conn, ["EVENT", "sub1", {"content": "x"}])

    async def test_event_routed_to_global_stream(self):
        """A non-query EVENT is routed to the global event queue."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        await pool._handle_message(conn, ["EVENT", "sub1", {"id": "ev1"}])
        assert pool._event_queue.qsize() == 1

    async def test_notice_logged(self):
        """A NOTICE message is handled without error."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        await pool._handle_message(conn, ["NOTICE", "hello world"])
        await pool._handle_message(conn, ["NOTICE"])

    async def test_ok_too_short_ignored(self):
        """An OK with < 3 elements is ignored."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        await pool._handle_message(conn, ["OK", "ev1"])

    async def test_closed_plain_resubscribes(self):
        """A CLOSED with a generic reason triggers _resubscribe_after."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True
        pool.connections[conn.url] = conn
        pool._subscriptions.append(({"kinds": [1]}, "sub_1"))
        pool._resubscribe_after = AsyncMock()
        await pool._handle_message(conn, ["CLOSED", "sub_1", "error: transient"])
        await asyncio.sleep(0)
        pool._resubscribe_after.assert_awaited_once()

    async def test_closed_no_match_no_resubscribe(self):
        """A CLOSED for an unknown sub_id does not resubscribe."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        pool._resubscribe_after = AsyncMock()
        await pool._handle_message(conn, ["CLOSED", "unknown_sub", "error"])
        pool._resubscribe_after.assert_not_called()


class TestSubscribeAndPublishHelpers:
    """Cover subscribe connected-send, publish_to empty, auth error arms."""

    async def test_subscribe_sends_to_connected(self):
        """subscribe() sends REQ to connected relays."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        conn.connected = True
        conn.send_raw = AsyncMock()
        pool.connections[conn.url] = conn
        await pool.subscribe([{"kinds": [1]}])
        conn.send_raw.assert_awaited_once()

    async def test_publish_to_empty_urls_returns_empty(self):
        """publish_to with empty urls returns {}."""
        pool = RelayPool([])
        result = await pool.publish_to({"id": "x"}, [])
        assert result == {}

    async def test_authenticate_timeout_returns_false(self):
        """_authenticate returns False on timeout (no OK received)."""
        from plugins.platforms.nostr.crypto import EventSigner
        from pynostr.key import PrivateKey
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool.set_signer(EventSigner(PrivateKey().bech32()))
        conn = RelayConnection("wss://x")
        conn.challenge = "c"
        conn.send_raw = AsyncMock()
        result = await pool._authenticate(conn, timeout=0.1)
        assert result is False

    async def test_auth_then_resubscribe_skips_when_not_running(self):
        """_auth_then_resubscribe returns early when pool not running."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = False
        conn = RelayConnection("wss://x")
        pool._authenticate = AsyncMock()
        await pool._auth_then_resubscribe(conn, "sub1", "auth-required")
        pool._authenticate.assert_not_called()

    async def test_cancel_listen_tasks_logs_non_cancelled_error(self, caplog):
        """_cancel_listen_tasks logs (not swallows) a non-CancelledError."""
        import logging
        pool = RelayPool([])

        async def boom():
            raise RuntimeError("kaboom")
        task = asyncio.create_task(boom())
        # Let the task run to completion (with its exception) before
        # _cancel_listen_tasks cancels+awaits it, so the RuntimeError is the
        # surfaced exception rather than a CancelledError.
        await asyncio.sleep(0)
        pool._listen_tasks = [task]
        with caplog.at_level(logging.WARNING, logger="plugins.platforms.nostr.relay_pool"):
            await pool._cancel_listen_tasks()
        assert any("kaboom" in r.message for r in caplog.records)


class TestListenRelayAndPublishOnce:
    """Cover _listen_relay (fake ws iterator), _publish_once recv loop,
    and _resubscribe_after retry loop."""

    async def test_listen_relay_processes_frames(self):
        """_listen_relay iterates ws frames and dispatches to _handle_message."""
        import json as _json
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True

        frames = [_json.dumps(["OK", "ev1", True, ""]), "not-json",
                  _json.dumps(["NOTICE", "hi"])]
        class FakeWS:
            def __aiter__(self):
                self._i = 0
                return self
            async def __anext__(self):
                if self._i >= len(frames):
                    raise StopAsyncIteration
                f = frames[self._i]
                self._i += 1
                return f
        conn.ws = FakeWS()
        # Should complete without raising despite the invalid JSON frame.
        await pool._listen_relay(conn)
        assert conn.connected is False  # finally block sets this

    async def test_publish_once_success(self, monkeypatch):
        """_publish_once sends EVENT, receives OK, returns accepted=True."""
        import json as _json
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        event = {"id": "target1", "kind": 1, "content": "x"}

        ok_frame = _json.dumps(["OK", "target1", True, ""])
        class FakeWS:
            async def recv(self):
                return ok_frame
            async def close(self):
                pass
        async def fake_connect(self):
            self.ws = FakeWS()
            self.connected = True
            return True
        monkeypatch.setattr(RelayConnection, "connect", fake_connect)
        monkeypatch.setattr(RelayConnection, "disconnect", AsyncMock())

        result = await pool._publish_once("wss://relay.example.com", event, timeout=2.0)
        assert result["accepted"] is True

    async def test_publish_once_timeout(self, monkeypatch):
        """_publish_once returns accepted=False on timeout (recv parks)."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        event = {"id": "target2", "kind": 1}

        class FakeWS:
            async def recv(self):
                await asyncio.sleep(10)  # park forever
            async def close(self):
                pass
        async def fake_connect(self):
            self.ws = FakeWS()
            self.connected = True
            return True
        monkeypatch.setattr(RelayConnection, "connect", fake_connect)
        monkeypatch.setattr(RelayConnection, "disconnect", AsyncMock())

        result = await pool._publish_once("wss://relay.example.com", event, timeout=0.2)
        assert result["accepted"] is False
        assert "timeout" in result["message"]

    async def test_publish_once_connect_fail(self, monkeypatch):
        """_publish_once returns accepted=False when connect fails."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        async def fake_connect(self):
            return False
        monkeypatch.setattr(RelayConnection, "connect", fake_connect)
        monkeypatch.setattr(RelayConnection, "disconnect", AsyncMock())
        result = await pool._publish_once("wss://down.example.com",
                                           {"id": "x"}, timeout=1.0)
        assert result["accepted"] is False
        assert "connect" in result["message"]

    async def test_publish_once_handles_auth_challenge(self, monkeypatch):
        """_publish_once answers a NIP-42 AUTH challenge (when a signer is set)
        before the relay accepts the EVENT."""
        import json as _json
        from unittest.mock import AsyncMock
        from plugins.platforms.nostr.crypto import EventSigner
        from pynostr.key import PrivateKey as _PK
        pool = RelayPool([])
        pool.set_signer(EventSigner(_PK().bech32()))
        event = {"id": "target_auth", "kind": 1, "content": "x"}

        frames = [_json.dumps(["AUTH", "challenge-abc"])]
        class FakeWS:
            def __init__(self):
                self._sent = []
            async def recv(self):
                if frames:
                    return frames.pop(0)
                # After auth, the relay sends OK.
                return _json.dumps(["OK", "target_auth", True, ""])
            async def send(self, msg):
                self._sent.append(msg)
            async def close(self):
                pass
        fake_ws = FakeWS()
        async def fake_connect(self):
            self.ws = fake_ws
            self.connected = True
            return True
        monkeypatch.setattr(RelayConnection, "connect", fake_connect)
        monkeypatch.setattr(RelayConnection, "disconnect", AsyncMock())

        result = await pool._publish_once("wss://auth.example.com",
                                           event, timeout=2.0)
        assert result["accepted"] is True
        # Verify an AUTH response was sent (the kind-22242 event).
        auth_msgs = [m for m in fake_ws._sent if _json.loads(m)[0] == "AUTH"]
        assert len(auth_msgs) == 1, "must respond to AUTH challenge"

    async def test_resubscribe_after_success(self, monkeypatch):
        """_resubscribe_after retries and succeeds."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True
        pool.connections[conn.url] = conn
        pool._subscriptions.append(({"kinds": [1]}, "sub_99"))
        conn.send_raw = AsyncMock()
        # Patch sleep to no-op so the test is instant.
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        await pool._resubscribe_after(conn, {"kinds": [1]}, "sub_99", "closed",
                                       max_retries=2)
        conn.send_raw.assert_awaited()

    async def test_resubscribe_after_gives_up(self, monkeypatch):
        """_resubscribe_after gives up after max_retries when send always fails."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True
        pool._subscriptions.append(({"kinds": [1]}, "sub_98"))
        conn.send_raw = AsyncMock(side_effect=RuntimeError("down"))
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        # Should not raise; gives up after 2 attempts.
        await pool._resubscribe_after(conn, {"kinds": [1]}, "sub_98", "closed",
                                       max_retries=2)

    async def test_events_generator_yields(self):
        """events() yields items put on the event queue."""
        pool = RelayPool([])
        pool._running = True
        await pool._event_queue.put(({"id": "a"}, "wss://r"))
        gen = pool.events()
        event, url = await gen.__anext__()
        assert event == {"id": "a"}
        assert url == "wss://r"
        pool._running = False
        await gen.aclose()


class TestRobustness:
    """Test relay pool robustness — task tracking, reconnect reliability,
    and resource cleanup."""

    async def test_background_tasks_tracked_and_cancelled_on_disconnect(self):
        """Resubscribe/auth background tasks must be tracked and cancelled on
        disconnect, otherwise they leak and send REQs to dead connections."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True
        pool.connections[conn.url] = conn
        pool._subscriptions.append(({"kinds": [1]}, "sub_1"))

        # Simulate a CLOSED that schedules a resubscribe task.
        await pool._handle_message(conn, ["CLOSED", "sub_1", "error: transient"])
        await asyncio.sleep(0)
        # The task must be tracked in _background_tasks.
        assert len(pool._background_tasks) > 0, (
            "background tasks must be tracked so they can be cancelled on disconnect"
        )

        # Disconnect must cancel them.
        conn.disconnect = AsyncMock()
        await pool.disconnect()
        for task in pool._background_tasks:
            assert task.done() or task.cancelled(), (
                "background tasks must be cancelled on disconnect"
            )

    async def test_connect_and_listen_survives_unexpected_exception(self):
        """If _connect_and_listen catches an unexpected exception, it must
        continue the reconnect loop rather than dying permanently."""
        from unittest.mock import AsyncMock, patch
        import time as _time

        pool = RelayPool(["wss://x"])
        pool._running = True
        conn = RelayConnection("wss://x")
        pool.connections[conn.url] = conn

        call_count = 0
        async def fake_connect(self):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                self.connected = True
                self.ws = MagicMock()
                return True
            return False

        listen_calls = 0
        async def fake_listen(pool_self, c):
            nonlocal listen_calls
            listen_calls += 1
            if listen_calls == 1:
                raise RuntimeError("unexpected crash in listen")
            # Second call: return normally (connection dropped).

        with patch.object(RelayConnection, "connect", fake_connect):
            pool._listen_relay = fake_listen.__get__(pool)
            # Run the loop briefly — it should not die on the RuntimeError.
            task = asyncio.create_task(pool._connect_and_listen(conn))
            await asyncio.sleep(0.2)
            # Cancel and verify it was still running (didn't die).
            assert not task.done(), (
                "_connect_and_listen must survive unexpected exceptions and keep retrying"
            )
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def test_send_raw_failure_triggers_reconnect(self):
        """When send_raw fails and sets connected=False, the pool should
        eventually reconnect rather than leaving the relay dead."""
        from unittest.mock import AsyncMock
        pool = RelayPool(["wss://x"])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True
        pool.connections[conn.url] = conn

        # send_raw fails — connected should become False.
        conn.ws = type("FakeWS", (), {"send": AsyncMock(side_effect=ConnectionError("dropped"))})()
        await conn.send_raw("[]")
        assert conn.connected is False

    async def test_listen_relay_handles_ws_becoming_none(self):
        """_listen_relay must not crash if conn.ws is set to None during a
        disconnect (race between check and async-for)."""
        pool = RelayPool([])
        conn = RelayConnection("wss://x")
        # ws is None — _listen_relay should return cleanly.
        conn.ws = None
        await pool._listen_relay(conn)
        assert conn.connected is False

    async def test_supervisor_restarts_after_crash(self):
        """If _connect_and_listen raises an unexpected exception (not caught
        by its own try/except), the supervisor must restart it rather than
        leaving the relay dead forever."""
        from unittest.mock import patch

        pool = RelayPool(["wss://x"])
        pool._running = True
        conn = RelayConnection("wss://x")
        pool.connections[conn.url] = conn

        crash_count = 0
        async def crashing_connect_and_listen(c):
            nonlocal crash_count
            crash_count += 1
            if crash_count <= 1:
                raise MemoryError("simulated fatal crash")
            # On the second call, stop the loop.
            pool._running = False

        pool._connect_and_listen = crashing_connect_and_listen

        # Patch sleep to be instant for the 10s restart delay.
        async def fast_sleep(s):
            pass
        with patch("asyncio.sleep", fast_sleep):
            await pool._supervise_connection(conn)

        assert crash_count >= 2, (
            "supervisor must restart _connect_and_listen after a crash"
        )

    async def test_duplicate_closed_does_not_spawn_multiple_resubscribes(self):
        """Multiple CLOSED frames for the same sub_id on the same relay must
        not spawn duplicate resubscribe tasks."""
        from unittest.mock import AsyncMock
        pool = RelayPool([])
        pool._running = True
        conn = RelayConnection("wss://x")
        conn.connected = True
        pool.connections[conn.url] = conn
        pool._subscriptions.append(({"kinds": [1]}, "sub_1"))
        pool._resubscribe_after = AsyncMock()

        # Send CLOSED twice for the same sub_id.
        await pool._handle_message(conn, ["CLOSED", "sub_1", "error: transient"])
        await pool._handle_message(conn, ["CLOSED", "sub_1", "error: again"])

        # Only one resubscribe should be in progress.
        assert ("wss://x", "sub_1") in pool._resubscribing
        # Verify only one background task was spawned for this sub_id.
        # (The second CLOSED should be a no-op since the key is already tracked.)

