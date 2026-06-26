"""
Nostr Platform Adapter for Hermes Agent.

Connects to Nostr relays via WebSocket, receives NIP-17 encrypted DMs
and optional public mentions, and replies as signed Nostr events.

Configuration via env vars:
    NOSTR_NSEC          Agent's private key (nsec1...)
    NOSTR_RELAYS        Comma-separated relay URLs
    NOSTR_ALLOWED_USERS Comma-separated npubs allowed to DM
    NOSTR_HOME_CHANNEL  Default npub for cron delivery

Or via config.yaml:
    gateway:
      platforms:
        nostr:
          enabled: true
          extra:
            relays: [wss://relay1.com, wss://relay2.com]
            monitor_mentions: false
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from pynostr.key import PrivateKey, PublicKey
    NOSTR_AVAILABLE = True
except ImportError:
    NOSTR_AVAILABLE = False
    PrivateKey = Any
    PublicKey = Any

from gateway.platforms.base import (
    BasePlatformAdapter,
    SendResult,
    MessageEvent,
    MessageType,
)
from gateway.config import Platform

from .relay_pool import RelayPool
from .event_router import EventRouter
from .profile_cache import ProfileCache
from .crypto import (
    EventSigner,
    create_gift_wrap,
    create_dm_rumor,
    nip04_encrypt,
    npub_to_hex,
    hex_to_npub,
)


# ---------------------------------------------------------------------------
# Key utilities
# ---------------------------------------------------------------------------

def _npub_to_hex(npub: str) -> str:
    """Convert npub (bech32) to hex pubkey."""
    return PublicKey.from_npub(npub).hex()


def _hex_to_npub(hex_key: str) -> str:
    """Convert hex pubkey to npub (bech32)."""
    return PublicKey.from_hex(hex_key).bech32()


# ---------------------------------------------------------------------------
# Requirement check
# ---------------------------------------------------------------------------

def check_requirements() -> bool:
    """Check if pynostr is installed."""
    return NOSTR_AVAILABLE


def validate_config(config) -> bool:
    """Validate config. Return True if valid, False otherwise."""
    nsec = os.getenv("NOSTR_NSEC")
    if not nsec:
        return False
    relays = os.getenv("NOSTR_RELAYS")
    if not relays:
        extra = getattr(config, "extra", {}) or {}
        if not extra.get("relays"):
            return False
    return True


def is_connected(config) -> bool:
    """Check if the adapter has a valid nsec and relay list."""
    return bool(os.getenv("NOSTR_NSEC") and os.getenv("NOSTR_RELAYS"))


def _env_enablement():
    """Seed PlatformConfig.extra from env vars before adapter construction."""
    extra = {}
    relays = os.getenv("NOSTR_RELAYS", "")
    if relays:
        extra["relays"] = [r.strip() for r in relays.split(",") if r.strip()]
    extra["monitor_mentions"] = os.getenv(
        "NOSTR_MONITOR_MENTIONS", ""
    ).lower() in {"1", "true", "yes"}
    extra["reply_publicly"] = os.getenv(
        "NOSTR_REPLY_PUBLICLY", ""
    ).lower() in {"1", "true", "yes"}
    extra["require_nip05"] = os.getenv(
        "NOSTR_REQUIRE_NIP05", ""
    ).lower() in {"1", "true", "yes"}
    extra["legacy_dm"] = os.getenv(
        "NOSTR_LEGACY_DM", "true"
    ).lower() in {"1", "true", "yes"}

    home_channel = os.getenv("NOSTR_HOME_CHANNEL")
    home = {}
    if home_channel:
        home["home_channel"] = home_channel
    return {"extra": extra, **home}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class NostrAdapter(BasePlatformAdapter):
    """Nostr gateway adapter.

    Receives NIP-17 encrypted DMs and optional public mentions,
    replies as signed Nostr events.
    """

    MAX_MESSAGE_LENGTH = 5000  # Nostr has no hard limit; practical

    def __init__(self, config, **kwargs):
        platform = Platform("nostr")
        super().__init__(config=config, platform=platform)

        extra = getattr(config, "extra", {}) or {}

        # --- Credentials ---
        self.nsec = os.getenv("NOSTR_NSEC", "")
        self._signer: Optional[EventSigner] = None
        self.pubkey = ""
        if self.nsec:
            try:
                self._signer = EventSigner(self.nsec)
                self.pubkey = self._signer.pubkey
            except Exception as e:
                logger.error(f"Failed to init Nostr signer: {e}")

        # --- Relays ---
        relay_urls = extra.get("relays", [])
        if not relay_urls:
            raw = os.getenv("NOSTR_RELAYS", "")
            relay_urls = [r.strip() for r in raw.split(",") if r.strip()]
        self.relay_urls = relay_urls

        # --- Authorization ---
        allowed = os.getenv("NOSTR_ALLOWED_USERS", "")
        self.allowed_users: set[str] = set()
        if allowed:
            for npub in allowed.split(","):
                npub = npub.strip()
                if npub:
                    try:
                        self.allowed_users.add(_npub_to_hex(npub))
                    except Exception:
                        logger.warning(
                            f"Could not parse npub in allowed users: "
                            f"{npub[:12]}..."
                        )

        self.allow_all = os.getenv(
            "NOSTR_ALLOW_ALL_USERS", ""
        ).lower() in {"1", "true", "yes"}

        # --- Features ---
        self.monitor_mentions = extra.get("monitor_mentions", False)
        self.reply_publicly = extra.get("reply_publicly", False)
        self.require_nip05 = extra.get("require_nip05", False)
        # Legacy NIP-04 (kind 4) DM ingestion. Defaults to True for backward
        # compat; set NOSTR_LEGACY_DM=false to run NIP-17-only.
        self.legacy_dm = extra.get(
            "legacy_dm",
            os.getenv("NOSTR_LEGACY_DM", "true").lower() in {"1", "true", "yes"},
        )

        # --- Components ---
        self.relay_pool = RelayPool(self.relay_urls)
        self.router = EventRouter(self)
        self.profiles = ProfileCache(self.relay_pool)

        # --- State ---
        self._running = False
        self._listen_task: Optional[asyncio.Task] = None
        # Pubkeys that have sent us legacy NIP-04 (kind 4) DMs. Replies to
        # these peers use nip04_encrypt so legacy-only clients can read them;
        # everyone else gets NIP-17 gift-wrapped replies.
        self._legacy_peers: set[str] = set()

    # ------------------------------------------------------------------
    # BasePlatformAdapter implementation
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        """Connect to relays and start listening."""
        if not self._signer:
            logger.error("Nostr: no nsec configured")
            return False

        if not self.relay_urls:
            logger.error("Nostr: no relays configured")
            return False

        await self.relay_pool.connect()

        # Subscribe to our DMs (NIP-17 gift wraps)
        # kind 1059 events with a p tag matching our pubkey
        # No "since" — fetch recent events so we don't miss DMs that
        # arrived while the gateway was down
        dm_filter = {
            "kinds": [1059],
            "#p": [self.pubkey],
            "limit": 50,
        }

        filters = [dm_filter]

        # Optionally monitor public mentions
        if self.monitor_mentions:
            mention_filter = {
                "kinds": [1],
                "#p": [self.pubkey],
                "limit": 10,
            }
            filters.append(mention_filter)

        # Legacy NIP-04 (kind 4) DMs — opt-in only. Defaults to on so
        # existing deployments keep receiving legacy DMs, but operators who
        # want NIP-17-only can disable it via NOSTR_LEGACY_DM=false.
        if self.legacy_dm:
            legacy_dm_filter = {
                "kinds": [4],
                "#p": [self.pubkey],
                "limit": 50,
            }
            filters.append(legacy_dm_filter)

        # NOTE: We do NOT add a kind 0 (metadata) subscription here. Kind 0
        # events are replaceable and carry no p-tags, so a "#p": [self.pubkey]
        # filter matches nothing, and a bare "kinds": [0] filter floods the
        # connection. Instead, profiles are resolved on demand by
        # ProfileCache.get_profile() via a targeted kind 0 query for a specific
        # author, and EventRouter still handles any incidental kind 0 events.

        await self.relay_pool.subscribe(filters)

        self._running = True
        self._listen_task = asyncio.create_task(self._listen_loop())
        logger.info(
            f"Nostr: connected to {len(self.relay_urls)} relays, "
            f"pubkey {self.pubkey[:16]}..."
        )
        return True

    async def disconnect(self) -> None:
        """Stop listening and close all relay connections."""
        self._running = False
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        await self.relay_pool.disconnect()
        logger.info("Nostr: disconnected")

    async def _listen_loop(self):
        """Main event loop — receives events from relay pool, routes them."""
        try:
            async for event, relay_url in self.relay_pool.events():
                if not self._running:
                    break
                try:
                    await self.router.route(event, relay_url)
                except Exception as e:
                    logger.error(
                        f"Nostr: error routing event "
                        f"{event.get('id', '?')[:16]}: {e}"
                    )
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Nostr: listen loop error: {e}")

    # ------------------------------------------------------------------
    # Inbound: called by EventRouter after DM decryption
    # ------------------------------------------------------------------

    async def _handle_dm(self, sender_pubkey: str, content: str,
                         original_event: dict, dm_protocol: str = "nip17"):
        """Handle a decrypted DM message.

        ``dm_protocol`` records how the inbound DM arrived so replies go back
        over the same wire format: "nip04" clients (legacy kind 4) only speak
        NIP-04, so replying with a NIP-17 gift-wrap would be invisible to them.
        """
        # Authorization check
        if not self.allow_all and sender_pubkey not in self.allowed_users:
            logger.info(
                f"Nostr: DM from unauthorized user {sender_pubkey[:16]}..."
            )
            return

        # NIP-05 verification (optional)
        if self.require_nip05:
            profile = await self.profiles.get_profile(sender_pubkey)
            if not profile.get("nip05"):
                logger.info(
                    f"Nostr: DM from non-NIP-05 user {sender_pubkey[:16]}..."
                )
                return

        # Remember which wire format this peer used, so send() replies in kind.
        # A legacy (NIP-04) client cannot read NIP-17 gift-wraps and vice versa.
        if dm_protocol == "nip04":
            self._legacy_peers.add(sender_pubkey)

        # Get sender display name
        sender_name = self.profiles.get_display_name(sender_pubkey)

        # Build SessionSource
        source = self.build_source(
            chat_id=sender_pubkey,
            chat_name=sender_name,
            chat_type="dm",
            user_id=sender_pubkey,
            user_name=sender_name,
            message_id=original_event.get("id"),
        )

        # Build MessageEvent
        event = MessageEvent(
            text=content,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=original_event,
            message_id=original_event.get("id"),
            timestamp=datetime.now(timezone.utc),
        )

        # Dispatch to gateway
        await self.handle_message(event)

    async def _handle_mention(self, event: dict):
        """Handle a public mention (kind 1 with our pubkey in p tags)."""
        sender_pubkey = event.get("pubkey", "")
        content = event.get("content", "")
        note_id = event.get("id", "")

        # Authorization
        if not self.allow_all and sender_pubkey not in self.allowed_users:
            return

        sender_name = self.profiles.get_display_name(sender_pubkey)

        # chat_id = sender pubkey so a private DM reply is correctly addressed.
        # thread_id = note id so the gateway forwards it as metadata["thread_id"],
        # which send() uses as the reply-to anchor for a public kind 1 reply.
        source = self.build_source(
            chat_id=sender_pubkey,
            chat_name=f"Nostr mention from {sender_name}",
            chat_type="group",
            user_id=sender_pubkey,
            user_name=sender_name,
            thread_id=note_id,
            message_id=note_id,
        )

        msg = MessageEvent(
            text=content,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=event,
            message_id=note_id,
            timestamp=datetime.now(timezone.utc),
        )
        await self.handle_message(msg)

    # ------------------------------------------------------------------
    # Outbound: send replies
    # ------------------------------------------------------------------

    async def send(self, chat_id: str, content: str = None,
                   text: str = None, metadata: dict = None,
                   reply_to: str = None, **kwargs) -> SendResult:
        """Send a reply message.

        ``chat_id`` is always a hex pubkey — the DM recipient or the mention
        author. For mention replies, the triggering note id is carried as
        ``metadata["thread_id"]`` (set from ``source.thread_id`` by the
        gateway's metadata builder) or as ``reply_to``.

        - Mention + reply_publicly: kind 1 text note replying to the note.
        - Mention + private (or any DM): NIP-17 gift-wrapped DM to chat_id.
        - Plain DM: NIP-17 gift-wrapped DM to chat_id.

        Accepts both 'content' (gateway convention) and 'text' (legacy).
        """
        # Normalize: gateway uses 'content', some callers use 'text'
        msg_text = content if content is not None else text
        if msg_text is None:
            return SendResult(success=False, error="No message text provided")
        if not self._signer:
            return SendResult(success=False, error="No nsec configured")

        # Resolve a reply-to note id (mention context), if any. The gateway
        # forwards source.thread_id as metadata["thread_id"]; reply_to is the
        # explicit reply anchor the gateway also passes.
        note_id = None
        if metadata:
            note_id = metadata.get("thread_id") or metadata.get("nostr_reply_to_note")
        if not note_id and reply_to:
            note_id = reply_to

        if note_id and self.reply_publicly:
            # Public reply (kind 1) to the triggering note.
            event = self._signer.sign_event(
                kind=1,
                content=msg_text,
                tags=[
                    ["e", note_id, "", "reply"],
                    ["p", chat_id],  # mention author
                ],
            )
            await self.relay_pool.publish(event)
            return SendResult(
                success=True,
                message_id=event.get("id"),
            )
        else:
            # DM reply to chat_id (a hex pubkey). Reply over the same wire
            # format the peer used to reach us: legacy NIP-04 (kind 4) for
            # peers known to speak only NIP-04, else NIP-17 gift-wrap.
            recipient = chat_id
            if recipient in self._legacy_peers:
                content = nip04_encrypt(
                    msg_text, self._signer._privkey_hex, recipient
                )
                dm_event = self._signer.sign_event(
                    kind=4,
                    content=content,
                    tags=[["p", recipient]],
                )
            else:
                rumor = create_dm_rumor(msg_text, recipient)
                dm_event = create_gift_wrap(rumor, recipient, self.nsec)
            await self.relay_pool.publish(dm_event)
            return SendResult(
                success=True,
                message_id=dm_event.get("id"),
            )

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Nostr has no typing indicator. No-op."""
        pass

    async def send_image(self, chat_id: str, image_url: str,
                         caption: str = None) -> SendResult:
        """Send an image via Nostr.

        Phase 1: send the URL in the DM text. Phase 2 will add NIP-96 upload.
        """
        text = image_url
        if caption:
            text = f"{caption}\n{image_url}"
        return await self.send(chat_id, text, metadata=None)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Get info about a chat (pubkey → profile)."""
        profile = await self.profiles.get_profile(chat_id)
        return {
            "name": profile.get("name", chat_id[:12] + "..."),
            "type": "dm",
            "chat_id": chat_id,
        }

    def format_message(self, content: str) -> str:
        """Format a message for Nostr.

        Nostr doesn't render markdown natively (clients vary).
        Return plain text.
        """
        return content

    # ------------------------------------------------------------------
    # Plugin registration
    # ------------------------------------------------------------------

def register(ctx):
    """Plugin entry point: called by the Hermes plugin system."""
    ctx.register_platform(
        name="nostr",
        label="Nostr",
        adapter_factory=lambda cfg: NostrAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_connected,
        required_env=["NOSTR_NSEC", "NOSTR_RELAYS"],
        install_hint="Install pynostr: pip install pynostr",
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="NOSTR_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send_async,
        allowed_users_env="NOSTR_ALLOWED_USERS",
        allow_all_env="NOSTR_ALLOW_ALL_USERS",
        max_message_length=5000,
        emoji="🟣",
    )


async def _standalone_send_async(
    pconfig,
    chat_id: str,
    message: str,
    *,
    thread_id: Optional[str] = None,
    media_files: Optional[list] = None,
    force_document: bool = False,
    **kwargs,
) -> dict:
    """Async standalone sender for cron / out-of-process delivery.

    Signature matches the gateway's standalone_sender_fn contract used by
    ``tools/send_message_tool.py`` and every other platform plugin:
    ``(pconfig, chat_id, message, *, thread_id, media_files, force_document)``.
    """
    try:
        nsec = os.getenv("NOSTR_NSEC", "")
        if not nsec:
            return {"error": "NOSTR_NSEC not set"}

        relays_raw = os.getenv("NOSTR_RELAYS", "")
        relay_urls = [r.strip() for r in relays_raw.split(",") if r.strip()]
        if not relay_urls:
            return {"error": "NOSTR_RELAYS not set"}

        recipient = chat_id
        if recipient.startswith("npub1"):
            recipient = _npub_to_hex(recipient)

        pool = RelayPool(relay_urls)
        # Use the full connect() (not connect_only) so per-relay listen loops
        # run and publish() can actually await OK frames. connect_only() opens
        # sockets with no reader, so the EVENT frame can be dropped before the
        # relay processes it and OK responses are never received.
        await pool.connect()

        rumor = create_dm_rumor(message, recipient)
        gift_event = create_gift_wrap(rumor, recipient, nsec)
        try:
            results = await pool.publish(gift_event, timeout=5.0)
            # publish() returns {} if no relay acknowledged within the timeout.
            accepted = any(r.get("accepted") for r in results.values())
            if not results or not accepted:
                urls = ", ".join(results.keys()) or "(no responses)"
                return {
                    "error": f"No relay accepted the event ({urls})",
                    "message_id": gift_event.get("id"),
                }
            return {"success": True, "message_id": gift_event.get("id")}
        finally:
            await pool.disconnect()
    except Exception as e:
        return {"error": f"Nostr standalone send failed: {e}"}
