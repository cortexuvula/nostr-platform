"""
Tests for the profile cache — relay fetch via query() and NIP-05 verification.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from plugins.platforms.nostr.profile_cache import ProfileCache


@pytest.fixture
def pool():
    """Mock relay pool with an AsyncMock query()."""
    pool = MagicMock()
    pool.connections = {"wss://relay.example.com": MagicMock(connected=True)}
    pool.query = AsyncMock(return_value=[])
    return pool


class TestFetchFromRelays:
    """Test that _fetch_from_relays parses kind 0 metadata via query()."""

    async def test_fetch_parses_latest_metadata(self, pool):
        """Should pick the highest created_at metadata event and parse JSON."""
        pool.query.return_value = [
            {"content": '{"name": "Old"}', "created_at": 100},
            {"content": '{"name": "Alice", "nip05": "alice@example.com"}',
             "created_at": 200},
        ]
        cache = ProfileCache(pool)
        profile = await cache._fetch_from_relays("pubkey123")
        assert profile["name"] == "Alice"
        assert profile["nip05"] == "alice@example.com"

    async def test_fetch_returns_none_when_no_events(self, pool):
        """No events from query() → None."""
        pool.query.return_value = []
        cache = ProfileCache(pool)
        assert await cache._fetch_from_relays("pubkey123") is None

    async def test_fetch_handles_invalid_json(self, pool):
        """Invalid JSON content should not crash; returns None."""
        pool.query.return_value = [{"content": "not json", "created_at": 1}]
        cache = ProfileCache(pool)
        assert await cache._fetch_from_relays("pubkey123") is None


class TestGetProfileCaching:
    """Test get_profile caches fetched profiles."""

    async def test_get_profile_caches_result(self, pool):
        """Fetched profile should be cached with fetched_at."""
        pool.query.return_value = [
            {"content": '{"name": "Bob"}', "created_at": 1}
        ]
        cache = ProfileCache(pool)
        profile = await cache.get_profile("pk_bob")
        assert profile["name"] == "Bob"
        # Second call should NOT re-query (cached).
        profile2 = await cache.get_profile("pk_bob")
        assert profile2["name"] == "Bob"
        assert pool.query.await_count == 1

    async def test_get_profile_fallback_when_no_metadata(self, pool):
        """No metadata on relay → minimal fallback with nip05=None."""
        pool.query.return_value = []
        cache = ProfileCache(pool)
        profile = await cache.get_profile("pk_unknown")
        assert profile["nip05"] is None
        assert "..." in profile["name"]


def _make_nip05_response(payload, status=200):
    """Build a fake aiohttp ClientSession whose get() yields the response.

    The code uses ``async with session.get(url) as resp:``, so get() must
    return an async context manager whose __aenter__ yields the response.
    """
    response = MagicMock()
    response.status = status
    response.json = AsyncMock(return_value=payload)

    get_cm = MagicMock()
    get_cm.__aenter__ = AsyncMock(return_value=response)
    get_cm.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.get.return_value = get_cm
    # `async with ClientSession() as session:` uses __aenter__/__aexit__.
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


class TestNip05Verification:
    """Test the NIP-05 .well-known verification flow."""

    async def test_nip05_verified_when_pubkey_matches(self, pool):
        """Matching pubkey in nostr.json → profile with nip05 set."""
        cache = ProfileCache(pool)
        session = _make_nip05_response({"names": {"alice": "pk_alice"}})

        with patch("aiohttp.ClientSession", return_value=session):
            result = await cache._nip05_lookup("pk_alice", "alice@example.com")
        assert result is not None
        assert result["nip05"] == "alice@example.com"

    async def test_nip05_rejected_when_pubkey_mismatch(self, pool):
        """Mismatched pubkey → None (don't trust the identifier)."""
        cache = ProfileCache(pool)
        session = _make_nip05_response({"names": {"alice": "some_other_pk"}})

        with patch("aiohttp.ClientSession", return_value=session):
            result = await cache._nip05_lookup("pk_alice", "alice@example.com")
        assert result is None

    async def test_nip05_http_error_returns_none(self, pool):
        """Non-200 response → None."""
        cache = ProfileCache(pool)
        session = _make_nip05_response({}, status=404)

        with patch("aiohttp.ClientSession", return_value=session):
            result = await cache._nip05_lookup("pk_alice", "alice@example.com")
        assert result is None

    async def test_nip05_invalid_identifier_returns_none(self, pool):
        """An identifier without '@' is invalid → None, no HTTP call."""
        cache = ProfileCache(pool)
        assert await cache._nip05_lookup("pk", "not-an-identifier") is None
        assert await cache._nip05_lookup("pk", "") is None
