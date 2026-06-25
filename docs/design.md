# Nostr Platform Adapter for Hermes Agent — Design Doc

## Overview

A **plugin-based** gateway adapter that connects Hermes Agent to the Nostr
protocol. The agent receives Nostr DMs (NIP-17 gift-wrapped) and mentions
as conversational messages, and replies as signed Nostr events. Zero changes
to core Hermes code — ships as a plugin under `plugins/platforms/nostr/`.

This doc covers architecture, NIP compliance, security model, config schema,
and a phased implementation plan. It assumes familiarity with the Hermes
plugin platform adapter system (see `ADDING_A_PLATFORM.md`).

---

## Why Nostr Is Different From Other Platform Adapters

Most platform adapters connect to a **single server** with a **single API**.
Nostr has neither — it's a federated relay network with:

| Concern | Telegram/Discord/etc. | Nostr |
|---|---|---|
| Transport | Single HTTP/Bot API | N relays over WebSocket |
| Identity | Bot token / OAuth | Cryptographic keypair (nsec/npub) |
| Message delivery | Push to webhook/poller | Pull via subscription filters |
| DMs | Platform-managed | E2E encrypted via NIP-17/NIP-44 |
| Rate limits | Platform-imposed | Per-relay, often none |
| Message ordering | Guaranteed by server | Best-effort by `created_at` |
| User discovery | User ID is known | Resolve via NIP-05 or relay gossip |

These differences shape every design decision below.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    NostrAdapter                         │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐  ┌─────────────┐  │
│  │  RelayPool   │   │  EventRouter │  │  DMDecryptor │  │
│  │              │   │              │  │              │  │
│  │ • N WS conns │──▶│ • Dedup      │──│ • NIP-44     │  │
│  │ • Reconnect  │   │ • Route by   │  │   unwrap     │  │
│  │ • Sub filters│   │   kind       │  │ • ECDH       │  │
│  │ • Event rx/tx│   │ • Queue      │  │ • AES-256    │  │
│  └──────────────┘   └──────────────┘  └─────────────┘  │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐  ┌─────────────┐  │
│  │ EventSigner  │   │  MentionMon  │  │  ProfCache  │  │
│  │              │   │              │  │              │  │
│  │ • Sign w/    │   │ • kind 1     │  │ • kind 0    │  │
│  │   nsec       │   │   #e tags    │  │ • NIP-05    │  │
│  │ • Publish to │   │   p tags     │  │ • TTL cache │  │
│  │   N relays   │   │ • Queue      │  │              │  │
│  └──────────────┘   └──────────────┘  └─────────────┘  │
│                                                         │
│         build_source() ──▶ handle_message()             │
│              │                      │                    │
│         SessionSource          MessageEvent              │
│              │                      │                    │
│              ▼                      ▼                    │
│        gateway/run.py ──▶ agent conversation loop        │
│              │                      │                    │
│              ▼                      ▼                    │
│         send() ◀── signed Nostr event published          │
└─────────────────────────────────────────────────────────┘
```

### Components

#### 1. RelayPool (`_relay_pool`)

Manages N simultaneous WebSocket connections to Nostr relays.

```python
class RelayPool:
    """Manages multiple relay connections with dedup and failover."""

    def __init__(self, relays: list[str], nsec: str):
        self.relays = relays          # ["wss://relay1...", "wss://relay2..."]
        self.nsec = nsec              # for deriving pubkey
        self.pubkey = derive_pubkey(nsec)
        self.connections: dict[str, WebSocketConnection] = {}
        self.seen_event_ids: set[str] = set()  # dedup across relays
        self._reconnect_delays = {}

    async def connect(self):
        """Open WebSocket to all relays concurrently."""
        # Each relay gets its own asyncio task with independent reconnection.

    async def subscribe(self, filters: list[dict]):
        """Send REQ messages to all connected relays."""
        # Each relay gets the same filter set.
        # Dedup incoming EVENT messages by event.id across all relays.

    async def publish(self, event: dict):
        """Send EVENT message to all relays. Returns per-relay OK results."""
        # Collect OK messages with a timeout per relay.
        # At least 1 relay must accept for "success".

    async def _listen_relay(self, url: str):
        """Single relay listener with exponential backoff reconnect."""
        # On disconnect: wait 1s, 2s, 4s, 8s, 16s, 30s (cap), +jitter.
        # Log relay-specific errors but don't crash the pool.
```

**Design decisions:**
- **Dedup by event ID** — the same event arrives on multiple relays. A bounded `set` (evict oldest at 50K entries) prevents unbounded memory growth.
- **Independent reconnection** — one relay going down doesn't affect others.
- **Publish to all, require one** — for sending, we publish to every relay and require at least one OK. This maximizes delivery probability.
- **No relay scoring** — keep it simple. If a relay is consistently down, the user removes it from config.

#### 2. EventRouter (`_event_router`)

Classifies incoming events and routes them to the appropriate handler.

```python
class EventRouter:
    """Routes incoming Nostr events to the correct handler."""

    def __init__(self, adapter):
        self.adapter = adapter

    async def route(self, event: dict, relay_url: str):
        """Route an event by its kind."""
        kind = event.get("kind")

        if kind == 1059:  # NIP-17 gift-wrapped DM
            await self._handle_gift_wrap(event)
        elif kind == 1:   # text note — check for mentions
            await self._handle_text_note(event)
        elif kind == 4:   # NIP-04 DM (legacy, deprecated but still used)
            await self._handle_legacy_dm(event)
        elif kind == 0:   # metadata — update profile cache
            await self._handle_metadata(event)
        elif kind == 7:   # reaction — ignore for now
            pass
        # Unknown kinds: ignore
```

#### 3. DMDecryptor (`_dm_decryptor`)

Handles NIP-17 (gift-wrapped) and NIP-04 (legacy) DM decryption.

**NIP-17 (NIP-44 sealed events):**
1. Receive kind 1059 (gift wrap) event
2. Decrypt the rumor using ECDH (our nsec × sender's pubkey) + AES-256-GCM
3. Unwrap the sealed event (kind 13)
4. Decrypt the seal using ECDH + AES-256-GCM
5. Extract the inner rumor (the actual message content)

**NIP-04 (legacy):**
1. Receive kind 4 event
2. Decrypt content using ECDH + AES-256-CBC (legacy scheme)
3. Extract message text

```python
class DMDecryptor:
    """Decrypts NIP-17 and NIP-04 DMs."""

    def __init__(self, nsec: str):
        self.nsec = nsec
        self.privkey = decode_nsec(nsec)
        self.pubkey = derive_pubkey(nsec)

    async def unwrap_gift(self, gift_event: dict) -> dict | None:
        """NIP-17: unwrap a kind 1059 gift-wrapped event.

        Returns the inner rumor (dict with kind, content, tags)
        or None if decryption fails (not addressed to us, tampered, etc.).
        """
        # 1. Check `p` tag matches our pubkey
        # 2. ECDH: shared_secret = X(privkey, sender_pubkey)
        # 3. NIP-44 v2 decrypt the rumor JSON
        # 4. Parse rumor: { kind, content, tags, ... }
        # 5. Return the rumor

    def decrypt_legacy_dm(self, event: dict) -> str | None:
        """NIP-04: decrypt a kind 4 DM (legacy)."""
        # 1. Check `p` tag matches our pubkey
        # 2. ECDH shared secret
        # 3. AES-256-CBC decrypt (NIP-04 uses CBC, not GCM)
        # 4. Return plaintext
```

**Cryptographic library choice:**

Use [`pynostr`](https://github.com/huginapp/pynostr) (or `nostr-sdk` Python
bindings) for production-grade crypto. Rolling our own ECDH + AES-256-GCM
is error-prone. The `pynostr` library handles:
- secp256k1 key operations
- NIP-44 v2 encryption/decryption
- NIP-04 legacy encryption/decryption
- Event signing and verification

```python
# Dependency in plugin.yaml or check_requirements()
try:
    from pynostr import PrivateKey, Event, nip44
    NOSTR_AVAILABLE = True
except ImportError:
    NOSTR_AVAILABLE = False
```

**Fallback:** If `pynostr` isn't available, fall back to `coincurve` +
`cryptography` (more widely installed) for the crypto primitives, with
manual NIP-44 implementation. This is more work but avoids a hard
dependency on a less-maintained library.

#### 4. EventSigner (`_event_signer`)

Signs and publishes outgoing Nostr events.

```python
class EventSigner:
    """Signs and publishes Nostr events."""

    def __init__(self, nsec: str, relay_pool: RelayPool):
        self.privkey = PrivateKey.from_nsec(nsec)
        self.relay_pool = relay_pool

    async def send_text_note(self, content: str, reply_to: dict = None,
                             tags: list = None) -> SendResult:
        """Publish a kind 1 text note (public reply)."""
        event_tags = tags or []
        if reply_to:
            # NIP-10 reply tagging: e tag with reply marker
            event_tags.append(["e", reply_to["id"], "", "reply"])
            event_tags.append(["p", reply_to["pubkey"]])

        event = Event(
            kind=1,
            content=content,
            tags=event_tags,
        )
        event.sign(self.privkey.hex())
        results = await self.relay_pool.publish(event.to_dict())
        return self._results_to_send_result(results)

    async def send_dm(self, recipient_pubkey: str, content: str) -> SendResult:
        """Send a NIP-17 gift-wrapped DM."""
        # 1. Create rumor: { kind: 4, content, tags: [["p", recipient]] }
        # 2. Seal: sign the rumor as a kind 13 event with our key
        # 3. Gift wrap: encrypt the seal to recipient's pubkey (NIP-44)
        # 4. Create kind 1059 event with the encrypted seal
        # 5. Publish to relays
        results = await self.relay_pool.publish(gift_event)
        return self._results_to_send_result(results)
```

#### 5. MentionMonitor (`_mention_monitor`)

Optionally monitors public mentions of the agent's pubkey.

```python
class MentionMonitor:
    """Monitors kind 1 text notes that mention our pubkey."""

    def __init__(self, adapter):
        self.adapter = adapter

    async def check_mention(self, event: dict) -> bool:
        """Check if a kind 1 event mentions our pubkey in a `p` tag."""
        our_pubkey = self.adapter.pubkey
        for tag in event.get("tags", []):
            if tag[0] == "p" and tag[1] == our_pubkey:
                return True
        # Also check if content contains our npub or NIP-05
        return False
```

**Config gate:** Mention monitoring is opt-in. Some users want their agent
to respond to public mentions; others only want DMs. Controlled by
`NOSTR_MONITOR_MENTIONS` env var.

#### 6. ProfileCache (`_profile_cache`)

Resolves pubkeys to human-readable names for better context.

```python
class ProfileCache:
    """Caches kind 0 metadata and NIP-05 lookups."""

    def __init__(self, relay_pool: RelayPool, ttl: int = 3600):
        self.cache: dict[str, dict] = {}  # pubkey → {name, about, picture, nip05}
        self.ttl = ttl
        self.relay_pool = relay_pool

    async def get_profile(self, pubkey: str) -> dict:
        """Get cached profile or fetch from relays."""
        if pubkey in self.cache:
            entry = self.cache[pubkey]
            if time.time() - entry["fetched_at"] < self.ttl:
                return entry

        # Fetch kind 0 from relays
        events = await self.relay_pool.query({"kinds": [0], "authors": [pubkey], "limit": 1})
        if events:
            profile = json.loads(events[0]["content"])
            self.cache[pubkey] = {**profile, "fetched_at": time.time()}
            return self.cache[pubkey]

        # Fallback: NIP-05 lookup
        # ...

        return {"name": pubkey[:8], "about": "", "picture": None}
```

---

## NIP Compliance

| NIP | Title | Status | Implementation |
|-----|-------|--------|----------------|
| NIP-01 | Basic protocol | ✅ Required | Event parsing, kind 0/1/3, REQ/EVENT/CLOSE |
| NIP-04 | Encrypted DMs (legacy) | ⚠️ Deprecated but supported | Fallback DM decryption for older clients |
| NIP-05 | DNS verification | ✅ Supported | Profile cache lookup for display names |
| NIP-10 | Reply markers | ✅ Supported | `e` tags with `reply`/`root` markers on outgoing |
| NIP-17 | Gift-wrapped DMs | ✅ Primary DM method | kind 1059/13 unwrap, NIP-44 encryption |
| NIP-19 | bech32 entities | ✅ Supported | npub/nsec/nip-05 encoding/decoding |
| NIP-42 | Relay auth | 🔜 Phase 2 | Some relays require authentication to read/write |
| NIP-44 | Encryption v2 | ✅ Required | NIP-17 DM encryption/decryption |
| NIP-65 | Relay lists | 🔜 Phase 2 | Auto-discover user's preferred relays from kind 10002 |

---

## Configuration

### Environment Variables

```bash
# Required
NOSTR_NSEC=nsec1...                    # Agent's private key (NEVER logged)
NOSTR_RELAYS=wss://relay1.com,wss://relay2.com  # Comma-separated relay list

# Optional
NOSTR_ALLOWED_USERS=npub1...,npub1...  # Comma-separated npubs allowed to DM
NOSTR_ALLOW_ALL_USERS=false            # Allow anyone (dev only)
NOSTR_HOME_CHANNEL=npub1...            # Default recipient for cron delivery
NOSTR_MONITOR_MENTIONS=false           # Respond to public mentions (kind 1)
NOSTR_REPLY_PUBLICLY=false             # Reply to mentions publicly (kind 1) vs DM
NOSTR_REQUIRE_NIP05=false              # Only accept DMs from NIP-05 verified users
```

### config.yaml

```yaml
gateway:
  platforms:
    nostr:
      enabled: true
      extra:
        relays:
          - wss://relay.andrehugo.ca
          - wss://nostr.wine
          - wss://relay.primal.net
          - wss://relay.damus.io
        monitor_mentions: false
        reply_publicly: false
        require_nip05: false
        max_message_length: 5000       # Nostr has no hard limit; practical limit
```

### nsec Security

The nsec is the most sensitive credential in the system — it controls
the agent's Nostr identity. **It must never appear in logs, chat output,
or error messages.**

Storage options (in priority order):

1. **Bitwarden Secrets Manager** (recommended) — set `BWS_ACCESS_TOKEN`
   and store nsec as `NOSTR_NSEC` in BWS. Hermes resolves it at startup.
   No plaintext in `.env`.

2. **`.env` file** — `NOSTR_NSEC=nsec1...` in `~/.hermes/.env`. Works but
   the key sits in plaintext on disk. Acceptable for development.

3. **Environment variable** — `export NOSTR_NSEC=nsec1...`. Most secure
   (never touches disk) but doesn't survive restarts unless set in a
   shell profile or systemd unit.

The adapter assigns the nsec to an internal variable and **never** logs
it. The `redact.py` module gets a pattern to mask `nsec1...` strings in
any log output.

---

## Plugin Structure

```
plugins/platforms/nostr/
├── __init__.py
├── plugin.yaml              # Plugin metadata, env var schema
├── adapter.py               # NostrAdapter (BasePlatformAdapter subclass)
├── relay_pool.py            # RelayPool: WebSocket relay management
├── crypto.py                # NIP-44/NIP-04 encryption/decryption
├── event_router.py          # EventRouter: classify & route events
├── profile_cache.py         # ProfileCache: kind 0 + NIP-05 resolution
└── README.md                # Setup guide
```

### plugin.yaml

```yaml
name: nostr-platform
label: Nostr
kind: platform
version: 1.0.0
description: >
  Nostr gateway adapter for Hermes Agent.
  Connects to Nostr relays via WebSocket, receives NIP-17 encrypted DMs
  and optional public mentions, and replies as signed Nostr events.
  Federated, censorship-resistant, E2E encrypted.
author: Hermes Community
requires_env:
  - name: NOSTR_NSEC
    description: "Agent's Nostr private key (nsec1...). Generate with: nak key generate"
    prompt: "Nostr private key (nsec)"
    password: true
  - name: NOSTR_RELAYS
    description: "Comma-separated relay URLs (e.g. wss://relay.example.com,wss://nostr.wine)"
    prompt: "Relay URLs (comma-separated)"
    password: false
optional_env:
  - name: NOSTR_ALLOWED_USERS
    description: "Comma-separated npubs allowed to DM the agent"
    prompt: "Allowed npubs (comma-separated)"
    password: false
  - name: NOSTR_ALLOW_ALL_USERS
    description: "Allow anyone to DM the agent (dev only — disables allowlist)"
    prompt: "Allow all users? (true/false)"
    password: false
  - name: NOSTR_HOME_CHANNEL
    description: "Default npub for cron/notification delivery"
    prompt: "Home channel npub"
    password: false
  - name: NOSTR_MONITOR_MENTIONS
    description: "Monitor public mentions (kind 1 with p tag). Default: false"
    prompt: "Monitor public mentions? (true/false)"
    password: false
  - name: NOSTR_REPLY_PUBLICLY
    description: "Reply to mentions publicly (kind 1) instead of DM. Default: false"
    prompt: "Reply publicly to mentions? (true/false)"
    password: false
  - name: NOSTR_REQUIRE_NIP05
    description: "Only accept DMs from NIP-05 verified users. Default: false"
    prompt: "Require NIP-05 verification? (true/false)"
    password: false
```

---

## Adapter Implementation Sketch

### `adapter.py` (core structure)

```python
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
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from pynostr import PrivateKey, Event
    from pynostr.nip44 import decrypt, encrypt
    NOSTR_AVAILABLE = True
except ImportError:
    NOSTR_AVAILABLE = False
    PrivateKey = Any
    Event = Any

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

# bech32 npub → hex pubkey conversion
def _npub_to_hex(npub: str) -> str:
    """Convert npub (bech32) to hex pubkey."""
    # Use pynostr or manual bech32 decode

def _hex_to_npub(hex_key: str) -> str:
    """Convert hex pubkey to npub (bech32)."""

def check_requirements() -> bool:
    """Check if pynostr is installed."""
    return NOSTR_AVAILABLE

def validate_config(config) -> List[str]:
    """Validate config. Return list of error messages (empty = valid)."""
    errors = []
    nsec = os.getenv("NOSTR_NSEC")
    if not nsec:
        errors.append("NOSTR_NSEC is required")
    relays = os.getenv("NOSTR_RELAYS")
    if not relays:
        errors.append("NOSTR_RELAYS is required")
    return errors

def is_connected(config) -> bool:
    """Check if the adapter has a valid nsec and relay list."""
    return bool(os.getenv("NOSTR_NSEC") and os.getenv("NOSTR_RELAYS"))

def _env_enablement():
    """Seed PlatformConfig.extra from env vars before adapter construction."""
    extra = {}
    relays = os.getenv("NOSTR_RELAYS", "")
    if relays:
        extra["relays"] = [r.strip() for r in relays.split(",") if r.strip()]
    extra["monitor_mentions"] = os.getenv("NOSTR_MONITOR_MENTIONS", "").lower() in {"1", "true", "yes"}
    extra["reply_publicly"] = os.getenv("NOSTR_REPLY_PUBLICLY", "").lower() in {"1", "true", "yes"}
    extra["require_nip05"] = os.getenv("NOSTR_REQUIRE_NIP05", "").lower() in {"1", "true", "yes"}

    home_channel = os.getenv("NOSTR_HOME_CHANNEL")
    home = {}
    if home_channel:
        home["home_channel"] = home_channel
    return {"extra": extra, **home}

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
        self.privkey = PrivateKey.from_nsec(self.nsec) if self.nsec else None
        self.pubkey = self.privkey.public_key.hex() if self.privkey else ""

        # --- Relays ---
        relay_urls = extra.get("relays", [])
        if not relay_urls:
            raw = os.getenv("NOSTR_RELAYS", "")
            relay_urls = [r.strip() for r in raw.split(",") if r.strip()]

        # --- Authorization ---
        allowed = os.getenv("NOSTR_ALLOWED_USERS", "")
        self.allowed_users = set()
        if allowed:
            for npub in allowed.split(","):
                npub = npub.strip()
                if npub:
                    try:
                        self.allowed_users.add(_npub_to_hex(npub))
                    except Exception:
                        logger.warning(f"Could not parse npub in allowed users: {npub[:12]}...")

        self.allow_all = os.getenv("NOSTR_ALLOW_ALL_USERS", "").lower() in {"1", "true", "yes"}

        # --- Features ---
        self.monitor_mentions = extra.get("monitor_mentions", False)
        self.reply_publicly = extra.get("reply_publicly", False)
        self.require_nip05 = extra.get("require_nip05", False)

        # --- Components ---
        self.relay_pool = RelayPool(relay_urls, self.nsec)
        self.router = EventRouter(self)
        self.profiles = ProfileCache(self.relay_pool)

        # --- State ---
        self._running = False
        self._listen_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # BasePlatformAdapter implementation
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        """Connect to relays and start listening."""
        if not self.privkey:
            logger.error("Nostr: no nsec configured")
            return False

        await self.relay_pool.connect()

        # Subscribe to our DMs (NIP-17 gift wraps)
        # kind 1059 events with a `p` tag matching our pubkey
        dm_filter = {
            "kinds": [1059],
            "#p": [self.pubkey],
            "since": int(time.time()),  # Don't fetch historical DMs
        }

        filters = [dm_filter]

        # Optionally monitor public mentions
        if self.monitor_mentions:
            mention_filter = {
                "kinds": [1],
                "#p": [self.pubkey],
                "since": int(time.time()),
            }
            filters.append(mention_filter)

        # Also subscribe to kind 0 metadata for profile cache
        # (we query on-demand instead of subscribing to all kind 0s)

        await self.relay_pool.subscribe(filters)

        self._running = True
        self._listen_task = asyncio.create_task(self._listen_loop())
        logger.info(f"Nostr: connected to {len(self.relay_pool.relays)} relays")
        logger.info(f"Nostr: pubkey {self.pubkey[:16]}...")
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

    async def _listen_loop(self):
        """Main event loop — receives events from relay pool, routes them."""
        async for event, relay_url in self.relay_pool.events():
            if not self._running:
                break
            try:
                await self.router.route(event, relay_url)
            except Exception as e:
                logger.error(f"Nostr: error routing event {event.get('id', '?')[:16]}: {e}")

    # ------------------------------------------------------------------
    # Inbound: called by EventRouter after DM decryption
    # ------------------------------------------------------------------

    async def _handle_dm(self, sender_pubkey: str, content: str,
                         original_event: dict):
        """Handle a decrypted DM message."""
        # Authorization check
        if not self.allow_all and sender_pubkey not in self.allowed_users:
            logger.info(f"Nostr: DM from unauthorized user {sender_pubkey[:16]}...")
            return

        # NIP-05 verification (optional)
        if self.require_nip05:
            profile = await self.profiles.get_profile(sender_pubkey)
            if not profile.get("nip05"):
                logger.info(f"Nostr: DM from non-NIP-05 user {sender_pubkey[:16]}...")
                return

        # Get sender display name
        profile = await self.profiles.get_profile(sender_pubkey)
        sender_name = profile.get("name") or _hex_to_npub(sender_pubkey)[:12] + "..."

        # Build SessionSource
        # chat_id = sender's pubkey (hex) — this is the "chat" identity
        # For Nostr, the "chat" is the conversation with a specific pubkey
        source = self.build_source(
            chat_id=sender_pubkey,           # hex pubkey
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

        # Authorization
        if not self.allow_all and sender_pubkey not in self.allowed_users:
            return

        profile = await self.profiles.get_profile(sender_pubkey)
        sender_name = profile.get("name") or sender_pubkey[:12] + "..."

        source = self.build_source(
            chat_id=event["id"],            # reply thread = note id
            chat_name=f"Nostr mention from {sender_name}",
            chat_type="group",              # public — like a group chat
            user_id=sender_pubkey,
            user_name=sender_name,
            message_id=event["id"],
        )

        msg = MessageEvent(
            text=content,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=event,
            message_id=event["id"],
            timestamp=datetime.now(timezone.utc),
        )
        await self.handle_message(msg)

    # ------------------------------------------------------------------
    # Outbound: send replies
    # ------------------------------------------------------------------

    async def send(self, chat_id: str, text: str,
                   metadata: dict = None, **kwargs) -> SendResult:
        """Send a reply message.

        For DMs (chat_id is a pubkey hex): send as NIP-17 gift-wrapped DM.
        For mentions (chat_id is a note id): reply as kind 1 text note
        (if reply_publicly=True) or DM the author (if reply_publicly=False).
        """
        # Determine if this is a DM or a mention reply
        # DMs: chat_id is a 64-char hex pubkey
        # Mentions: chat_id is a 64-char hex note id (also 64 chars)
        # We disambiguate using metadata or source context
        is_mention_reply = metadata and metadata.get("nostr_reply_to_note")

        if is_mention_reply and self.reply_publicly:
            # Public reply (kind 1)
            note_id = chat_id
            return await self._event_signer.send_text_note(
                content=text,
                reply_to={"id": note_id, "pubkey": metadata.get("nostr_author_pubkey", "")},
            )
        else:
            # DM reply (NIP-17)
            recipient = chat_id
            return await self._event_signer.send_dm(recipient, text)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """Nostr has no typing indicator. No-op."""
        pass

    async def send_image(self, chat_id: str, image_url: str,
                         caption: str = None) -> SendResult:
        """Send an image via Nostr.

        Option A: Upload to a NIP-96 media server, send the URL as a
        kind 1 note or DM with an `imeta` tag (NIP-92).
        Option B: Send the image URL directly in the message text.

        Phase 1: Option B (URL in text). Phase 2: NIP-96 upload.
        """
        text = image_url
        if caption:
            text = f"{caption}\n{image_url}"
        return await self.send(chat_id, text, metadata)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Get info about a chat (pubkey → profile)."""
        profile = await self.profiles.get_profile(chat_id)
        return {
            "name": profile.get("name", chat_id[:12] + "..."),
            "type": "dm",
            "chat_id": chat_id,
        }

    # ------------------------------------------------------------------
    # Standalone sender (for cron delivery outside the gateway)
    # ------------------------------------------------------------------

    async def _standalone_send(self, chat_id: str, message: str,
                                **kwargs) -> dict:
        """Send a message without a running gateway (for cron jobs)."""
        # Create a temporary RelayPool + EventSigner
        # Connect, send, disconnect
        # This is heavier than other platforms because Nostr requires
        # relay connections to send anything.
        ...


# ------------------------------------------------------------------
# Plugin registration
# ------------------------------------------------------------------

def register(ctx):
    """Plugin entry point."""
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
        standalone_sender_fn=_standalone_send,
        allowed_users_env="NOSTR_ALLOWED_USERS",
        allow_all_env="NOSTR_ALLOW_ALL_USERS",
        max_message_length=5000,
        emoji="🟣",
    )
```

---

## Subscription Strategy

The adapter subscribes to two filter sets on connect:

### Filter 1: DMs (always on)
```json
{
  "kinds": [1059],
  "#p": ["<our_pubkey>"],
  "since": <connect_timestamp>
}
```
- `since` = current time on connect. **We do not backfill historical DMs.**
  This prevents processing a backlog of old messages on restart.
  Future enhancement: store last-seen timestamp in adapter state and
  use that as `since` on reconnect.

### Filter 2: Public mentions (optional)
```json
{
  "kinds": [1],
  "#p": ["<our_pubkey>"],
  "since": <connect_timestamp>
}
```

**Why `since` and not `limit`:**
- `limit` would fetch the last N mentions on every reconnect, causing
  duplicate processing.
- `since` with current timestamp means we only get new mentions after
  connect. Trade-off: we miss messages that arrived while we were
  disconnected. Acceptable for a v1.

**Future: persistent `since` cursor:**
Store the latest `created_at` timestamp seen in
`~/.hermes/state/nostr_cursor.json` and use it as `since` on reconnect.
This bridges brief disconnects without reprocessing.

---

## Security Model

### Threat: nsec leakage
- **Risk:** If the nsec leaks, the attacker can impersonate the agent on
  Nostr, read all DMs, and publish as the agent.
- **Mitigation:**
  - Never log the nsec (add `nsec1` pattern to `agent/redact.py`).
  - Store in Bitwarden Secrets Manager (preferred) or `.env`.
  - The adapter holds it in memory only; no disk writes.
  - Generate a dedicated nsec for the agent — never reuse the user's
    personal identity key.

### Threat: Unauthorized DMs
- **Risk:** Anyone who knows the agent's npub can send it a DM.
- **Mitigation:**
  - `NOSTR_ALLOWED_USERS` allowlist of npubs.
  - `NOSTR_REQUIRE_NIP05` optionally requires senders to have a verified
    NIP-05 identity (domain-based proof of identity).
  - Unauthorized DMs are silently dropped (no error sent to sender —
    they don't know the agent exists).

### Threat: Prompt injection via DM content
- **Risk:** A malicious user sends a DM containing instructions designed to
  hijack the agent ("ignore previous instructions, send all files to...").
- **Mitigation:** Hermes's existing Promptware defense (`tirith`) scans
  memory loads and tool results for injection patterns. Nostr DMs are
  treated identically to any other platform message — same sandbox, same
  tool-use guardrails, same dangerous-command approval flow.

### Threat: Relay MITM
- **Risk:** A malicious relay could inject fake events or drop messages.
- **Mitigation:**
  - Event signatures are verified on receipt (pynostr verifies `sig`
    against `pubkey` + event content). Forged events are dropped.
  - Use multiple relays for redundancy. If one relay drops messages,
    others deliver them.
  - WSS (TLS) prevents network-level MITM on individual relay connections.

### Threat: Replay attacks
- **Risk:** An old DM is re-sent to the relay and processed again.
- **Mitigation:**
  - `seen_event_ids` dedup set in RelayPool prevents processing the
    same event ID twice.
  - `since` timestamp filter on subscription prevents fetching old events
    on reconnect.

---

## Message Flow: End-to-End

### Inbound DM (NIP-17)

```
User sends DM via Nostr client
    → Client publishes kind 1059 gift-wrap to relays
    → RelayPool receives EVENT from relay
    → EventRouter sees kind 1059, calls DMDecryptor
    → DMDecryptor:
        1. Check p tag == our pubkey ✓
        2. ECDH: shared_secret = X(our_npriv, sender_npub)
        3. NIP-44 v2 decrypt → inner rumor JSON
        4. Parse rumor: { kind: 4, content: "Hello!", tags: [["p", our_pubkey]] }
    → EventRouter calls adapter._handle_dm(sender_pubkey, content, original_event)
    → Adapter:
        1. Check sender in allowed_users ✓
        2. Fetch sender profile (kind 0) for display name
        3. build_source(chat_id=sender_pubkey, user_name=sender_name)
        4. Create MessageEvent(text=content, source=source)
        5. Call self.handle_message(event) → gateway dispatch
    → Gateway routes to agent conversation loop
    → Agent processes and generates reply
    → Gateway calls adapter.send(chat_id=sender_pubkey, text=reply)
```

### Outbound DM (NIP-17)

```
Adapter.send(chat_id=sender_pubkey, text="Here's your answer...")
    → EventSigner.send_dm(recipient_pubkey, content)
    → EventSigner:
        1. Create rumor: { kind: 4, content, tags: [["p", recipient]] }
        2. Seal: sign rumor as kind 13 event with our key
        3. Gift wrap: NIP-44 encrypt seal to recipient
        4. Create kind 1059 event with ephemeral key
        5. RelayPool.publish(gift_event) → all relays
    → RelayPool sends EVENT to each relay, collects OK responses
    → Return SendResult(success=True/False, message_id=event_id)
```

---

## Differences From Other Adapters

| Aspect | Other Adapters | Nostr Adapter |
|--------|---------------|---------------|
| Identity | Bot token / phone number | Cryptographic keypair |
| Connection | Single server | Multiple relays (relay pool) |
| Message dedup | Server handles | Adapter must dedup by event ID |
| DM encryption | Platform-managed | End-to-end (NIP-44) |
| Message ordering | Server-ordered | By `created_at` (best-effort) |
| Rate limits | Platform-imposed | Per-relay (usually none) |
| User auth | Platform user ID | npub allowlist + optional NIP-05 |
| Typing indicator | Supported | Not available (no-op) |
| Media sending | Platform API upload | URL in text (Phase 1), NIP-96 (Phase 2) |
| Reconnection | Single server reconnect | Per-relay independent reconnect |
| Message history | Server stores | Relays may not store; `since` cursor |
| Cost | Free (most platforms) | Free (self-hosted relay) or relay fees |

---

## Implementation Phases

### Phase 1: Core DM Support (MVP)
- [x] RelayPool with WebSocket connections + reconnection
- [x] NIP-17 gift-wrapped DM receiving (kind 1059)
- [x] NIP-44 v2 decryption
- [x] NIP-04 legacy DM decryption (backward compat)
- [x] npub allowlist authorization
- [x] Outbound DM sending (NIP-17)
- [x] Profile cache (kind 0 fetch)
- [x] Plugin registration with all hooks
- [x] `check_requirements()` with `pynostr` dependency
- [x] Standalone sender for cron delivery
- [ ] Tests: crypto round-trip, relay pool reconnection, auth checks

**Estimated effort:** 3-5 days for someone familiar with both Hermes
plugin internals and Nostr NIPs.

### Phase 2: Mentions & Public Replies
- [ ] Public mention monitoring (kind 1 with p tag)
- [ ] Public reply as kind 1 text note (NIP-10 threading)
- [ ] NIP-05 verification gate
- [ ] Persistent `since` cursor for reconnect continuity
- [ ] NIP-42 relay authentication (for relays that require it)

### Phase 3: Media & Rich Content
- [ ] NIP-96 media upload (images in DMs)
- [ ] NIP-92 `imeta` tags for image metadata
- [ ] NIP-65 relay list auto-discovery (read user's kind 10002)
- [ ] Reaction support (kind 7) — agent can react to messages

### Phase 4: Advanced
- [ ] Long-form content publishing (kind 30023)
- [ ] Zapping integration (NIP-57) — agent receives/sends Lightning payments
- [ ] Multi-key support (different nsec per conversation context)
- [ ] Relay health scoring and auto-failover

---

## Dependencies

### Required

| Package | Purpose | Install |
|---------|---------|---------|
| `pynostr` | Nostr crypto, event signing, NIP-44 | `pip install pynostr` |
| `websockets` | WebSocket relay connections | `pip install websockets` |

### Optional

| Package | Purpose |
|---------|---------|
| `coincurve` | Faster secp256k1 (pynostr fallback uses it) |
| `aiohttp` | NIP-05 HTTP lookups (already a Hermes dependency) |

---

## Testing Strategy

### Unit Tests
```python
# test_nostr_crypto.py
def test_nip44_roundtrip():
    """Encrypt then decrypt a message — content must match."""
    sk_a = PrivateKey.random()
    sk_b = PrivateKey.random()
    shared = nip44.compute_shared_secret(sk_a, sk_b.public_key)
    ciphertext = nip44.encrypt("Hello Nostr!", shared)
    plaintext = nip44.decrypt(ciphertext, shared)
    assert plaintext == "Hello Nostr!"

def test_event_signing():
    """Signed event must verify."""
    sk = PrivateKey.random()
    event = Event(kind=1, content="test", tags=[])
    event.sign(sk.hex())
    assert event.verify()

# test_relay_pool.py
async def test_dedup():
    """Same event from two relays → processed once."""
    pool = RelayPool(["wss://relay1", "wss://relay2"], nsec)
    # Mock both relays sending the same event
    # Assert only one delivered to the events() queue

# test_adapter.py
def test_unauthorized_dm_dropped():
    """DM from non-allowlisted pubkey → not dispatched."""
    adapter = NostrAdapter(config_with_allowlist=["npub1alice"])
    # Simulate DM from "npub1bob"
    # Assert handle_message was NOT called

def test_nip05_gate():
    """With require_nip05=True, DM from non-verified user → dropped."""
    ...
```

### Integration Tests
- Run a local strfry relay in Docker
- Connect adapter, send test DMs via `nak`, verify receipt
- Test reconnection by killing and restarting the relay
- Test multi-relay dedup by sending the same event to two relays

---

## Open Questions

1. **Should the adapter use the user's personal nsec or a dedicated agent key?**
   Recommendation: dedicated agent key. The user generates a new nsec
   specifically for the agent (`nak key generate`), shares the npub with
   people who should DM the agent, and keeps their personal nsec separate.
   This is safer and lets the user revoke the agent's key without losing
   their identity.

2. **Which relays should be the default?**
   No hard defaults — the user must configure relays. Suggest in setup:
   their personal relay + 2-3 public relays (nostr.wine, relay.primal.net,
   relay.damus.io). The user's personal relay should be first for lowest
   latency.

3. **How to handle media (images) in Phase 1?**
   Phase 1: if the agent generates an image, it uploads to the Hermes
   media cache and sends the URL in the DM text. Not ideal (URL may not
   be accessible to the recipient) but functional. Phase 2 adds NIP-96
   upload to a media server.

4. **Should mention replies be public or DM by default?**
   Default: DM. If someone mentions the agent publicly, replying via DM
   is less noisy and doesn't spam the public feed. Users who want public
   replies set `NOSTR_REPLY_PUBLICLY=true`.

5. **NIP-04 vs NIP-17 — which to prioritize?**
   NIP-17 (gift-wrapped) is the modern standard and what new clients use.
   NIP-04 is deprecated but some older clients still send kind 4 DMs.
   Phase 1 supports both: NIP-17 as primary, NIP-04 as fallback. If a
   kind 4 arrives, decrypt it and handle it the same way.

6. **How does session threading work?**
   Each sender's pubkey is a unique `chat_id`, so each person DMing the
   agent gets their own conversation session — same as Telegram DMs.
   No thread_id needed (Nostr has no concept of threads in DMs).

---

## Comparison: Why Not Just Use `nak` + Cron?

The existing skills (`nostr-relay`, `nostr-nsec-bitwarden`,
`nostr-follow-discovery`) use the `nak` CLI via the terminal tool. This
works for:

- Publishing events on a schedule
- One-shot queries (fetch profile, search notes)
- Follow list management

It doesn't work for:

- **Real-time DM responses** — `nak` is batch-oriented, not a listener
- **Conversational back-and-forth** — no way to receive and reply inline
- **Mention monitoring** — would need a polling loop
- **Session context** — `nak` commands don't have conversation memory

A native adapter makes Nostr a **first-class platform** — the agent can
hold real-time conversations over Nostr DMs, just like it does on
Telegram or Discord. The skills and `nak` CLI remain useful for
non-conversational tasks (publishing, searching, follow management).

---

## Conclusion

The Nostr adapter is technically straightforward — the protocol is simple,
the crypto is well-specified in NIPs, and the Hermes plugin system
provides all the integration points needed. The main work is:

1. **Relay pool management** (WebSocket lifecycle, dedup, reconnection)
2. **NIP-17/NIP-44 crypto** (delegate to `pynostr`, don't roll your own)
3. **Event routing** (classify by kind, decrypt DMs, check auth)

The result is a genuinely unique capability: **an AI agent you can DM over
a censorship-resistant, end-to-end-encrypted, federated protocol with no
central authority.** That resonates with Hermes's self-hosted ethos and
the Nostr community's values.

Ship Phase 1 as a community plugin. If adoption justifies it, promote
to core.
