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
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Persistence paths for state that must survive gateway restarts.
_HERMES_DIR = Path.home() / ".hermes"
_LEGACY_PEERS_FILE = _HERMES_DIR / "nostr_legacy_peers.json"
# Jumble encryption keypair — persistent so recipients who learned it from
# our kind 10044 can keep decrypting across restarts.
_ENC_KEY_FILE = _HERMES_DIR / "nostr_encryption_key.json"

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
    create_jumble_gift_wrap,
    create_dm_rumor,
    create_encryption_key_event,
    derive_pubkey,
    generate_encryption_keypair,
    nip04_encrypt,
    npub_to_hex,
    hex_to_npub,
    parse_encryption_pubkey,
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
        # NIP-42: inject the signer so the pool can answer AUTH challenges
        # from relays that gate DMs behind authentication.
        if self._signer:
            self.relay_pool.set_signer(self._signer)
        self.router = EventRouter(self)
        self.profiles = ProfileCache(self.relay_pool)

        # --- State ---
        self._running = False
        self._listen_task: Optional[asyncio.Task] = None
        # Pubkeys that have sent us legacy NIP-04 (kind 4) DMs. Replies to
        # these peers use nip04_encrypt so legacy-only clients can read them;
        # everyone else gets NIP-17 gift-wrapped replies.
        self._legacy_peers: set[str] = self._load_legacy_peers()
        # Pubkeys the agent has sent a DM to. These peers are allowed to reply
        # even if not in NOSTR_ALLOWED_USERS — makes bidirectional DMs work
        # naturally (agent initiates → user can reply).
        self._known_peers: set[str] = set()
        # Cache of recipient pubkey → (relay_urls, fetched_at) so we don't
        # re-query kind 10050 on every reply to the same peer. TTL-bounded.
        self._recipient_relay_cache: dict[str, tuple[list, float]] = {}
        self._recipient_relay_ttl = 600.0  # 10 minutes
        # Jumble kind-10044 encryption keypair. Persistent so Jumble users who
        # learned our encryption pubkey can keep decrypting across restarts.
        self._encryption_keypair: Optional[dict] = self._load_encryption_keypair()
        # Cache of recipient main pubkey → (encryption_pubkey, fetched_at).
        self._recipient_enc_cache: dict[str, tuple[str, float]] = {}

    def _load_encryption_keypair(self) -> Optional[dict]:
        """Load the Jumble encryption keypair from disk, or generate one."""
        try:
            if _ENC_KEY_FILE.exists():
                return json.loads(_ENC_KEY_FILE.read_text())
        except Exception as e:
            logger.debug(f"Could not load encryption keypair: {e}")
        # Generate and persist a fresh keypair on first run.
        kp = generate_encryption_keypair()
        self._save_encryption_keypair(kp)
        return kp

    def _save_encryption_keypair(self, kp: dict):
        """Persist the encryption keypair to disk."""
        try:
            _HERMES_DIR.mkdir(parents=True, exist_ok=True)
            _ENC_KEY_FILE.write_text(json.dumps(kp))
        except Exception as e:
            logger.warning(f"Could not save encryption keypair: {e}")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_legacy_peers(self) -> set[str]:
        """Load legacy NIP-04 peers from disk so state survives restarts."""
        try:
            if _LEGACY_PEERS_FILE.exists():
                data = json.loads(_LEGACY_PEERS_FILE.read_text())
                return set(data.get("peers", []))
        except Exception as e:
            logger.debug(f"Could not load legacy peers: {e}")
        return set()

    def _save_legacy_peers(self):
        """Persist legacy NIP-04 peers to disk."""
        try:
            _HERMES_DIR.mkdir(parents=True, exist_ok=True)
            _LEGACY_PEERS_FILE.write_text(
                json.dumps({"peers": list(self._legacy_peers)})
            )
        except Exception as e:
            logger.warning(f"Could not save legacy peers: {e}")

    # ------------------------------------------------------------------
    # NIP-17 relay list publication
    # ------------------------------------------------------------------

    async def _publish_dm_relays(self):
        """Publish kind 10050 (NIP-17 DM relay list) AND kind 10002 (NIP-65
        relay list) so clients know where to send gift-wrapped DMs to us.

        Per NIP-17, the kind 10050 event contains ``["relay", url]`` tags.
        The kind 10002 (NIP-65) is also published because Amethyst's fallback
        relay discovery checks NIP-65 read relays when a recipient's 10050
        isn't found or its relays are unreachable. Without the 10002, DMs
        from Amethyst users can be silently published to wrong relays.
        """
        if not self._signer or not self.relay_urls:
            return

        # Kind 10050: NIP-17 DM relay list (primary discovery mechanism).
        dm_tags = [["relay", url] for url in self.relay_urls]
        dm_event = self._signer.sign_event(
            kind=10050,
            content="",
            tags=dm_tags,
        )
        # Kind 10002: NIP-65 general relay list (fallback discovery). A single
        # ["r", url] tag per relay with no marker means both read and write
        # (NIP-65 spec). This is simpler and avoids malformed duplicate tags.
        nip65_tags = [["r", url] for url in self.relay_urls]
        nip65_event = self._signer.sign_event(
            kind=10002,
            content="",
            tags=nip65_tags,
        )
        try:
            results = await self.relay_pool.publish(dm_event, timeout=5.0)
            accepted = sum(1 for r in results.values() if r.get("accepted"))
            logger.info(
                f"Published kind 10050 DM relay list to {accepted}/"
                f"{len(results)} relays ({len(self.relay_urls)} relays listed)"
            )
            # Also publish the NIP-65 relay list.
            await self.relay_pool.publish(nip65_event, timeout=5.0)
            logger.info("Published kind 10002 NIP-65 relay list")
        except Exception as e:
            logger.warning(f"Failed to publish DM relay list: {e}")

    # ------------------------------------------------------------------
    # Recipient relay discovery (NIP-17 / NIP-65 cascade)
    # ------------------------------------------------------------------

    async def _resolve_recipient_relays(self, pubkey: str) -> list[str]:
        """Discover where a recipient listens for gift-wrapped DMs.

        Mirrors Amethyst's documented cascade
        (PR #2531): kind 10050 (DM relay list) → kind 10002 read relays →
        [] (caller falls back to own relays). Cached per-pubkey with a TTL
        so repeated replies to the same peer don't re-query relays.
        """
        cached = self._recipient_relay_cache.get(pubkey)
        if cached and time.time() - cached[1] < self._recipient_relay_ttl:
            return cached[0]

        relays: list[str] = []
        try:
            # 1. NIP-17 kind 10050: dedicated DM inbox relays.
            events = await self.relay_pool.query(
                {"kinds": [10050], "authors": [pubkey], "limit": 1},
                timeout=5.0,
            )
            for ev in events:
                for tag in ev.get("tags", []):
                    if (isinstance(tag, list) and len(tag) >= 2
                            and tag[0] == "relay" and tag[1]):
                        relays.append(tag[1])
        except Exception as e:
            logger.debug(f"kind 10050 query failed for {pubkey[:12]}...: {e}")

        if not relays:
            try:
                # 2. NIP-65 kind 10002: general relay list, read/both relays.
                events = await self.relay_pool.query(
                    {"kinds": [10002], "authors": [pubkey], "limit": 1},
                    timeout=5.0,
                )
                for ev in events:
                    for tag in ev.get("tags", []):
                        if (isinstance(tag, list) and len(tag) >= 2
                                and tag[0] == "r" and tag[1]):
                            marker = tag[2] if len(tag) > 2 else ""
                            # "read" or no marker = inbox-eligible.
                            if marker in ("", "read"):
                                relays.append(tag[1])
            except Exception as e:
                logger.debug(f"kind 10002 query failed for {pubkey[:12]}...: {e}")

        relays = list(dict.fromkeys(relays))  # dedup, preserve order
        # Only cache positive results — a transient relay failure shouldn't
        # lock in an empty list for the TTL, or DMs would go to our own relays
        # instead of the recipient's inbox until the cache expires.
        if relays:
            self._recipient_relay_cache[pubkey] = (relays, time.time())
        return relays

    async def _resolve_recipient_encryption_pubkey(
        self, main_pubkey: str
    ) -> Optional[str]:
        """Check if a recipient uses Jumble's kind-10044 encryption-keypair
        scheme. Returns their encryption pubkey if so, else None (→ the caller
        uses standard NIP-17). Cached per-pubkey with a TTL.
        """
        cached = self._recipient_enc_cache.get(main_pubkey)
        if cached and time.time() - cached[1] < self._recipient_relay_ttl:
            return cached[0]

        enc_pubkey = None
        try:
            events = await self.relay_pool.query(
                {"kinds": [10044], "authors": [main_pubkey], "limit": 1},
                timeout=5.0,
            )
            for ev in events:
                enc_pubkey = parse_encryption_pubkey(ev)
                if enc_pubkey:
                    break
        except Exception as e:
            logger.debug(f"kind 10044 query failed for {main_pubkey[:12]}...: {e}")

        # Only cache positive results — a transient relay failure or a user
        # who hasn't published 10044 yet shouldn't lock in None for the TTL,
        # or Jumble users would get standard-format DMs until the cache expires.
        if enc_pubkey:
            self._recipient_enc_cache[main_pubkey] = (enc_pubkey, time.time())
        return enc_pubkey

    async def _publish_encryption_key(self):
        """Publish our kind 10044 encryption-key announcement so Jumble users
        can send gift-wrapped DMs to our encryption pubkey. Called on connect
        alongside the kind 10050 DM relay list.
        """
        if not self._signer or not self._encryption_keypair:
            return
        event = create_encryption_key_event(
            self._encryption_keypair["pubkey_hex"], self._signer
        )
        try:
            await self.relay_pool.publish(event, timeout=5.0)
            logger.info(
                f"Published kind 10044 encryption key "
                f"({self._encryption_keypair['pubkey_hex'][:16]}...)"
            )
        except Exception as e:
            logger.warning(f"Failed to publish encryption key: {e}")

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

        # Subscribe to our DMs (NIP-17 gift wraps).
        #
        # The 'since' window is critical for reliable delivery: NIP-59 gift
        # wraps are backdated up to 2 days for privacy, so a filter without
        # 'since' + a hard 'limit' can return old backdated wraps that crowd
        # out actually-new DMs — causing intermittent delivery failures
        # (the root cause of unreliable DMs with Amethyst). We use a 9-day
        # window (7 days of history + 2-day backdate margin, matching
        # Amethyst's own filter) and NO hard limit so nothing gets crowded out.
        dm_since = int(time.time()) - 9 * 86400  # 9 days
        dm_filter = {
            "kinds": [1059],
            "#p": [self.pubkey],
            "since": dm_since,
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
                "since": dm_since,
            }
            filters.append(legacy_dm_filter)

        # NOTE: We do NOT add a kind 0 (metadata) subscription here. Kind 0
        # events are replaceable and carry no p-tags, so a "#p": [self.pubkey]
        # filter matches nothing, and a bare "kinds": [0] filter floods the
        # connection. Instead, profiles are resolved on demand by
        # ProfileCache.get_profile() via a targeted kind 0 query for a specific
        # author, and EventRouter still handles any incidental kind 0 events.

        await self.relay_pool.subscribe(filters)

        # Publish our DM relay list (NIP-17 kind 10050) so clients like
        # Jumble and Amethyst know where to send gift-wrapped DMs to us.
        await self._publish_dm_relays()
        # Publish our encryption key (Jumble kind 10044) so Jumble users can
        # send gift-wrapped DMs to our encryption pubkey.
        await self._publish_encryption_key()

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
        await self.profiles.close()
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
        # Authorization check: accept DMs from explicitly-allowed users OR
        # from known peers (pubkeys the agent has actively sent a DM to).
        # This makes bidirectional DMs work: agent sends to user → user can
        # reply without needing to be pre-authorized in NOSTR_ALLOWED_USERS.
        if (not self.allow_all
                and sender_pubkey not in self.allowed_users
                and sender_pubkey not in self._known_peers):
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
            self._save_legacy_peers()

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

        # Authorization: accept mentions from allowed users OR known peers
        # (matching _handle_dm's logic so mentions aren't dropped for peers
        # the agent has conversed with).
        if (not self.allow_all
                and sender_pubkey not in self.allowed_users
                and sender_pubkey not in self._known_peers):
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
                await self.relay_pool.publish(dm_event)
            else:
                # NIP-17 gift-wrapped DM. The rumor is reused for both the
                # recipient's copy and our self-copy (identical content, two
                # separate gift wraps p-tagged to each recipient).
                rumor = create_dm_rumor(msg_text, recipient, self.pubkey)

                # Detect Jumble recipients (they publish a kind 10044
                # encryption pubkey). Jumble's decrypt only tries the
                # encryption key, so a standard gift wrap is silently dropped.
                recipient_enc = await self._resolve_recipient_encryption_pubkey(
                    recipient
                )
                if recipient_enc and self._encryption_keypair:
                    recipient_event = create_jumble_gift_wrap(
                        rumor, recipient, recipient_enc, self.nsec,
                        self._encryption_keypair["privkey_hex"],
                    )
                else:
                    # Standard NIP-17 (Amethyst, Nostur, etc.).
                    recipient_event = create_gift_wrap(rumor, recipient, self.nsec)

                # Recipient's copy: publish to where THEY listen (their kind
                # 10050 / 10002 inbox relays). Without this, the wrap lands
                # only on our relays and is silently missed.
                recipient_relays = await self._resolve_recipient_relays(recipient)
                target_urls = recipient_relays or self.relay_urls
                await self.relay_pool.publish_to(recipient_event, target_urls)

                # Self-copy: gift-wrap the same rumor to OUR pubkey, publish to
                # our own relays so the message shows up in our sent history
                # across clients. If we have a Jumble encryption keypair, use
                # the Jumble format so our own sent-history decrypts in Jumble;
                # otherwise standard NIP-17 (Amethyst/Nostur).
                if self._encryption_keypair:
                    self_event = create_jumble_gift_wrap(
                        rumor, self.pubkey,
                        self._encryption_keypair["pubkey_hex"],
                        self.nsec,
                        self._encryption_keypair["privkey_hex"],
                    )
                else:
                    self_event = create_gift_wrap(rumor, self.pubkey, self.nsec)
                await self.relay_pool.publish(self_event)
                dm_event = recipient_event
            # Record this recipient as a known peer so they can reply even if
            # not in NOSTR_ALLOWED_USERS (bidirectional DM support).
            self._known_peers.add(recipient)
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


async def _query_recipient_relays(pool: "RelayPool", pubkey: str) -> list[str]:
    """Standalone relay discovery: kind 10050 → kind 10002 read relays.

    Shared between the adapter (which caches) and the standalone sender
    (one-shot). Returns [] when the recipient has published no relay list,
    in which case the caller falls back to its own configured relays.
    """
    relays: list[str] = []
    try:
        events = await pool.query(
            {"kinds": [10050], "authors": [pubkey], "limit": 1},
            timeout=5.0,
        )
        for ev in events:
            for tag in ev.get("tags", []):
                if (isinstance(tag, list) and len(tag) >= 2
                        and tag[0] == "relay" and tag[1]):
                    relays.append(tag[1])
    except Exception:
        pass
    if not relays:
        try:
            events = await pool.query(
                {"kinds": [10002], "authors": [pubkey], "limit": 1},
                timeout=5.0,
            )
            for ev in events:
                for tag in ev.get("tags", []):
                    if (isinstance(tag, list) and len(tag) >= 2
                            and tag[0] == "r" and tag[1]):
                        marker = tag[2] if len(tag) > 2 else ""
                        if marker in ("", "read"):
                            relays.append(tag[1])
        except Exception:
            pass
    return list(dict.fromkeys(relays))


async def _query_recipient_encryption_pubkey(pool: "RelayPool",
                                              pubkey: str) -> Optional[str]:
    """Standalone Jumble detection: query kind 10044, return the n-tag
    encryption pubkey, or None if the recipient isn't a Jumble user."""
    try:
        events = await pool.query(
            {"kinds": [10044], "authors": [pubkey], "limit": 1},
            timeout=5.0,
        )
        for ev in events:
            enc = parse_encryption_pubkey(ev)
            if enc:
                return enc
    except Exception:
        pass
    return None


def _load_persisted_encryption_key() -> Optional[dict]:
    """Load the persisted Jumble encryption keypair for standalone use.

    Returns None if no key has been persisted (the adapter generates one on
    first connect; standalone runs before that will fall back to standard
    NIP-17).
    """
    try:
        if _ENC_KEY_FILE.exists():
            return json.loads(_ENC_KEY_FILE.read_text())
    except Exception:
        pass
    return None


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

        our_pubkey = derive_pubkey(nsec)

        pool = RelayPool(relay_urls)
        # Use the full connect() (not connect_only) so per-relay listen loops
        # run and publish() can actually await OK frames. connect_only() opens
        # sockets with no reader, so the EVENT frame can be dropped before the
        # relay processes it and OK responses are never received.
        await pool.connect()

        rumor = create_dm_rumor(message, recipient, our_pubkey)

        # Detect Jumble recipients and use their encryption-keypair format if
        # applicable. The encryption keypair is loaded from the persisted file
        # the adapter created; without it, fall back to standard NIP-17.
        recipient_enc = await _query_recipient_encryption_pubkey(pool, recipient)
        enc_kp = _load_persisted_encryption_key()
        if recipient_enc and enc_kp:
            gift_event = create_jumble_gift_wrap(
                rumor, recipient, recipient_enc, nsec,
                enc_kp["privkey_hex"],
            )
        else:
            gift_event = create_gift_wrap(rumor, recipient, nsec)

        # Discover the recipient's DM inbox relays (kind 10050 → 10002) so the
        # gift wrap reaches where they actually listen. Falls back to our own
        # configured relays when no recipient relay list is published.
        recipient_relays = await _query_recipient_relays(pool, recipient)
        target_urls = recipient_relays or relay_urls

        # Self-copy: identical rumor, wrapped to ourselves, published to our own
        # relays so sent messages appear in our DM history. Use Jumble format
        # if we have a persisted encryption keypair (so our own Jumble view can
        # decrypt it), else standard NIP-17.
        if enc_kp:
            self_event = create_jumble_gift_wrap(
                rumor, our_pubkey, enc_kp["pubkey_hex"], nsec,
                enc_kp["privkey_hex"],
            )
        else:
            self_event = create_gift_wrap(rumor, our_pubkey, nsec)

        try:
            results = await pool.publish_to(gift_event, target_urls, timeout=5.0)
            accepted = any(r.get("accepted") for r in results.values())
            if not results or not accepted:
                urls = ", ".join(results.keys()) or "(no responses)"
                return {
                    "error": f"No relay accepted the event ({urls})",
                    "message_id": gift_event.get("id"),
                }
            # Best-effort self-copy; its failure doesn't fail the send.
            try:
                await pool.publish(self_event, timeout=5.0)
            except Exception as e:
                logger.debug(f"Standalone self-copy publish failed: {e}")
            return {"success": True, "message_id": gift_event.get("id")}
        finally:
            await pool.disconnect()
    except Exception as e:
        return {"error": f"Nostr standalone send failed: {e}"}
