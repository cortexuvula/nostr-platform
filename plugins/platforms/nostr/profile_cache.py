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
        # Reuse a single aiohttp session for all NIP-05 lookups instead of
        # creating one per request (resource leak at scale).
        self._http_session: Optional[aiohttp.ClientSession] = None

    async def get_profile(self, pubkey: str) -> dict:
        """Get cached profile or fetch from relays.

        Returns dict with: name, about, picture, nip05, fetched_at
        """
        entry = self.cache.get(pubkey)
        if entry and time.time() - entry.get("fetched_at", 0) < self.ttl:
            return entry

        # Fetch kind 0 metadata from relays. This carries the nip05 field
        # if the user published one.
        profile = await self._fetch_from_relays(pubkey)

        # If metadata declares a nip05 identifier, verify it resolves back to
        # this pubkey via the NIP-05 DNS/.well-known flow.
        if profile and profile.get("nip05"):
            verified = await self._nip05_lookup(pubkey, profile["nip05"])
            if verified is None:
                # Identifier present but verification failed: don't trust it.
                profile["nip05"] = None

        if profile:
            profile["fetched_at"] = time.time()
            self.cache[pubkey] = profile
            return profile

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
        """Fetch kind 0 metadata for a pubkey from relays via a one-shot query.

        Uses ``RelayPool.query()`` which routes the REQ's events back to us
        (rather than into the global event stream) and stops at EOSE.
        """
        if not self.relay_pool or not self.relay_pool.connections:
            return None

        filter_dict = {
            "kinds": [0],
            "authors": [pubkey],
            "limit": 1,
        }
        try:
            events = await self.relay_pool.query(filter_dict, timeout=5.0)
        except Exception as e:
            logger.debug(f"Profile query failed for {pubkey[:12]}...: {e}")
            return None

        if not events:
            return None

        # Most recent metadata event wins (highest created_at).
        latest = max(events, key=lambda e: e.get("created_at", 0))
        try:
            return json.loads(latest.get("content", "{}") or "{}")
        except (json.JSONDecodeError, TypeError):
            return None

    async def update_from_event(self, pubkey: str, profile_data: dict):
        """Update cache from a kind 0 metadata event."""
        entry = self.cache.get(pubkey, {})
        entry.update(profile_data)
        entry["fetched_at"] = time.time()
        self.cache[pubkey] = entry
        logger.debug(f"Updated profile cache for {pubkey[:12]}...")

    async def _nip05_lookup(self, pubkey: str, identifier: str) -> Optional[dict]:
        """NIP-05 verification: confirm *identifier* maps to *pubkey*.

        NIP-05 queries ``https://<domain>/.well-known/nostr.json?name=<user>``
        and checks the returned pubkey matches. Requires a known identifier
        (``user@domain``), which is taken from the sender's kind 0 metadata.
        Returns a profile dict with ``nip05`` set if verified, else None.
        """
        if not identifier or "@" not in identifier:
            return None
        name, _, domain = identifier.partition("@")
        if not name or not domain:
            return None

        url = f"https://{domain}/.well-known/nostr.json?name={name}"
        try:
            # Reuse a single session across lookups instead of creating
            # a new one each time (avoids socket / connection-pool churn).
            if self._http_session is None or self._http_session.closed:
                timeout = aiohttp.ClientTimeout(total=5.0)
                self._http_session = aiohttp.ClientSession(timeout=timeout)
            async with self._http_session.get(url) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
        except Exception as e:
            logger.debug(f"NIP-05 lookup failed for {identifier}: {e}")
            return None

        names = data.get("names", {})
        # NIP-05: names[<name>] == pubkey hex confirms the identifier.
        if names.get(name) == pubkey:
            return {
                "name": data.get("names", {}).get(name, name),
                "nip05": identifier,
                "picture": None,
                "about": "",
            }
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

    async def close(self):
        """Close the HTTP session and release resources."""
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
            self._http_session = None
