"""
Nostr event router — classifies incoming events by NIP kind and routes
them to the appropriate handler in the adapter.
"""

import json
import logging
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .adapter import NostrAdapter

from .crypto import unwrap_gift_wrap, nip04_decrypt


class EventRouter:
    """Routes incoming Nostr events to the correct adapter handler."""

    def __init__(self, adapter: "NostrAdapter"):
        self.adapter = adapter

    async def route(self, event: dict, relay_url: str):
        """Route an event by its kind."""
        kind = event.get("kind")

        if kind == 1059:  # NIP-17 gift-wrapped DM
            await self._handle_gift_wrap(event, relay_url)
        elif kind == 1:   # text note — check for mentions
            await self._handle_text_note(event, relay_url)
        elif kind == 4:   # NIP-04 DM (legacy)
            await self._handle_legacy_dm(event, relay_url)
        elif kind == 0:   # metadata — update profile cache
            await self._handle_metadata(event, relay_url)
        elif kind == 7:   # reaction — ignore for now
            pass
        # Unknown kinds: silently ignore

    async def _handle_gift_wrap(self, event: dict, relay_url: str):
        """NIP-17: unwrap a kind 1059 gift-wrapped event."""
        result = unwrap_gift_wrap(event, self.adapter.nsec)
        if result is None:
            logger.debug("Failed to unwrap gift-wrap — not for us or decrypt error")
            return

        rumor, seal_pubkey = result

        content = rumor.get("content", "")
        if not content:
            logger.debug("Gift-wrap rumor has no content")
            return

        # The actual sender is the seal's pubkey (not the ephemeral gift-wrap pubkey)
        actual_sender = seal_pubkey

        # Check rumor kind — kind 14 is a chat message, kind 4 is legacy DM
        rumor_kind = rumor.get("kind", 14)
        if rumor_kind in (4, 14, 15):  # DM-related kinds
            await self.adapter._handle_dm(actual_sender, content, event)
        else:
            logger.debug(f"Gift-wrap rumor kind {rumor_kind} — not a DM, ignoring")

    async def _handle_legacy_dm(self, event: dict, relay_url: str):
        """NIP-04: decrypt a legacy kind 4 DM."""
        sender_pubkey = event.get("pubkey", "")
        content = event.get("content", "")

        # Check this DM is addressed to us
        p_tags = [t for t in event.get("tags", []) if t[0] == "p"]
        our_pubkey = self.adapter.pubkey
        if not any(t[1] == our_pubkey for t in p_tags):
            return  # Not our DM

        try:
            from pynostr.key import PrivateKey
            from .crypto import nip04_decrypt

            recipient_privkey = PrivateKey.from_nsec(self.adapter.nsec)
            recipient_privkey_hex = recipient_privkey.hex()

            plaintext = nip04_decrypt(
                content,
                recipient_privkey_hex,
                sender_pubkey,
            )
        except Exception as e:
            logger.warning(f"Failed to decrypt legacy DM: {e}")
            return

        await self.adapter._handle_dm(sender_pubkey, plaintext, event)

    async def _handle_text_note(self, event: dict, relay_url: str):
        """Check if a kind 1 text note mentions our pubkey."""
        if not self.adapter.monitor_mentions:
            return

        our_pubkey = self.adapter.pubkey
        is_mention = False

        for tag in event.get("tags", []):
            if tag[0] == "p" and tag[1] == our_pubkey:
                is_mention = True
                break

        if not is_mention:
            return

        await self.adapter._handle_mention(event)

    async def _handle_metadata(self, event: dict, relay_url: str):
        """Update profile cache with kind 0 metadata."""
        pubkey = event.get("pubkey", "")
        if not pubkey:
            return

        try:
            profile = json.loads(event.get("content", "{}"))
            await self.adapter.profiles.update_from_event(pubkey, profile)
        except json.JSONDecodeError:
            pass
