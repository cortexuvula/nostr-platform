"""
Profile cache for Nostr — resolves pubkeys to human-readable names
via kind 0 metadata events and NIP-05 DNS verification.
"""

import asyncio
import json
import logging
import time
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)


class ProfileCache:
    """Caches kind 0 metadata and NIP-05 lookups with TTL expiry."""

    def __init__(self, relay_pool, ttl: int = 3600):
        self.cache: dict[str, dict] = {}
        self.ttl = ttl
        self.relay_pool = relay_pool

    async def get_profile(self, pubkey: str) -> dict:
        """Get cached profile or fetch from relays.

        Returns dict with: name, about, picture, nip05, fetched_at
        """
        entry = self.cache.get(pubkey)
        if entry and time.time() - entry.get("fetched_at", 0) < self.ttl:
            return entry

        # Try fetching from relays
        profile = await self._fetch_from_relays(pubkey)
        if profile:
            profile["fetched_at"] = time.time()
            self.cache[pubkey] = profile
            return profile

        # Fallback: try NIP-05
        nip05_profile = await self._nip05_lookup(pubkey)
        if nip05_profile:
            nip05_profile["fetched_at"] = time.time()
            self.cache[pubkey] = nip05_profile
            return nip05_profile

        # Return minimal profile
        fallback = {
            "name": pubkey[:12] + "...",
            "about": "",
            "picture": None,
            "nip05": None,
            "fetched_at": time.time(),
        }
        self.cache[pubkey] = fallback
        return fallback

    async def _fetch_from_relays(self, pubkey: str) -> Optional[dict]:
        """Fetch kind 0 metadata for a pubkey from relays."""
        if not self.relay_pool or not self.relay_pool.connections:
            return None

        # Send a REQ for kind 0 from this author
        import json as _json
        sub_id = f"profile_{pubkey[:8]}"

        filter_dict = {
            "kinds": [0],
            "authors": [pubkey],
            "limit": 1,
        }

        req = _json.dumps(["REQ", sub_id, filter_dict])

        # Send to all connected relays
        for conn in self.relay_pool.connections.values():
            if conn.connected:
                await conn.send_raw(req)

        # Wait briefly for responses
        await asyncio.sleep(2.0)

        # Send CLOSE
        close = _json.dumps(["CLOSE", sub_id])
        for conn in self.relay_pool.connections.values():
            if conn.connected:
                await conn.send_raw(close)

        # Check if any profile events arrived via the event queue
        # Note: this is a simplified approach. In production, we'd use
        # a dedicated response future/promise per query.
        # For now, return None — profiles will be populated by the
        # event router when it sees kind 0 events.
        return None

    async def update_from_event(self, pubkey: str, profile_data: dict):
        """Update cache from a kind 0 metadata event."""
        entry = self.cache.get(pubkey, {})
        entry.update(profile_data)
        entry["fetched_at"] = time.time()
        self.cache[pubkey] = entry
        logger.debug(f"Updated profile cache for {pubkey[:12]}...")

    async def _nip05_lookup(self, pubkey: str) -> Optional[dict]:
        """NIP-05 DNS-based verification lookup.

        Checks if the pubkey has a NIP-05 identifier by querying
        the relays for kind 0 first, then doing the DNS verification.
        """
        # This is a best-effort lookup. NIP-05 requires a known
        # identifier (user@domain) to query. We can't reverse-lookup
        # from pubkey alone. Return None for now.
        return None

    def get_display_name(self, pubkey: str) -> str:
        """Get a display name for a pubkey from cache (no fetch)."""
        entry = self.cache.get(pubkey)
        if entry:
            name = entry.get("name")
            if name:
                return name
            nip05 = entry.get("nip05")
            if nip05:
                return nip05
        return pubkey[:12] + "..."

    def clear(self):
        """Clear the entire profile cache."""
        self.cache.clear()
