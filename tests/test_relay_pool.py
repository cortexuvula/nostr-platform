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
