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

from pynostr.event import Event
from .crypto import unwrap_gift_wrap, nip04_decrypt


def _verify_signature(event: dict) -> bool:
    """Verify an event's secp256k1 signature.

    Trusting event['pubkey'] without verification lets a relay forge a DM
    from an arbitrary pubkey (the decrypt key would be derived from that
    pubkey). Gift-wraps verify their seal in unwrap_gift_wrap; for plain
    events we verify here. Returns True only on a valid signature.
    """
    try:
        ev = Event.from_dict(event)
        return ev.verify()
    except Exception:
        return False


def _p_tag_pubkeys(event: dict) -> list[str]:
    """Return all pubkey values from 'p' tags, defensively.

    Tags from untrusted relays may be empty, non-list, or malformed, so each
    tag is checked for type and length before indexing (unlike a naive
    ``t[0] == 'p'`` which raises IndexError/TypeError on malformed tags).
    """
    pubkeys = []
    for tag in event.get("tags", []):
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p":
            pubkeys.append(tag[1])
    return pubkeys


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
            # Verify signature before trusting event['pubkey'] as the author;
            # otherwise a relay can forge a mention from an arbitrary pubkey.
            if not _verify_signature(event):
                logger.debug(f"Dropping kind 1 with invalid signature: {event.get('id', '?')[:16]}")
                return
            await self._handle_text_note(event, relay_url)
        elif kind == 4:   # NIP-04 DM (legacy)
            # Same forgery protection: a forged kind 4 could otherwise be
            # attributed to a spoofed sender pubkey.
            if not _verify_signature(event):
                logger.debug(f"Dropping kind 4 with invalid signature: {event.get('id', '?')[:16]}")
                return
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

        # NIP-17 security: "Clients MUST verify if pubkey of the kind:13 is
        # the same pubkey on the kind:14, otherwise any sender can impersonate
        # others by simply changing the pubkey on kind:14." The seal's pubkey
        # authoritatively identifies the sender; if the rumor claims a
        # different pubkey, this is a forgery and must be rejected.
        rumor_pubkey = rumor.get("pubkey")
        if rumor_pubkey and rumor_pubkey != seal_pubkey:
            logger.warning(
                f"Gift-wrap rumor pubkey {rumor_pubkey[:16]}... does not match "
                f"seal pubkey {seal_pubkey[:16]}... — possible impersonation, "
                f"dropping"
            )
            return

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

        # Check this DM is addressed to us (defensive p-tag parsing).
        our_pubkey = self.adapter.pubkey
        if our_pubkey not in _p_tag_pubkeys(event):
            return  # Not our DM

        try:
            from pynostr.key import PrivateKey

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

        await self.adapter._handle_dm(sender_pubkey, plaintext, event, dm_protocol="nip04")

    async def _handle_text_note(self, event: dict, relay_url: str):
        """Check if a kind 1 text note mentions our pubkey."""
        if not self.adapter.monitor_mentions:
            return

        our_pubkey = self.adapter.pubkey
        if our_pubkey not in _p_tag_pubkeys(event):
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
