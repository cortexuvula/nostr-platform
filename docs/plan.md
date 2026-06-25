# Implementation Plan: Nostr Platform Adapter Plugin

## Overview

Build a Hermes Agent platform plugin that connects to Nostr relays via
WebSocket, receives NIP-17 encrypted DMs, and replies as signed Nostr events.

**Repo:** https://github.com/cortexuvula/nostr-platform
**Design doc:** `docs/design.md`
**Hermes source:** `/Users/cortexuvula/hermes-agent/`
**Plugin examples:** `/Users/cortexuvula/hermes-agent/plugins/platforms/irc/`
and `/Users/cortexuvula/hermes-agent/plugins/platforms/simplex/`

## Target Structure

```
nostr-platform/
├── docs/
│   └── design.md              # Full architecture design doc (already exists)
├── plugins/
│   └── platforms/
│       └── nostr/
│           ├── __init__.py
│           ├── plugin.yaml     # Plugin metadata + env var schema
│           ├── adapter.py      # NostrAdapter (BasePlatformAdapter subclass)
│           ├── relay_pool.py   # RelayPool: WebSocket relay management
│           ├── crypto.py       # NIP-44/NIP-04 encryption/decryption
│           ├── event_router.py # EventRouter: classify & route events
│           └── profile_cache.py # ProfileCache: kind 0 + NIP-05 resolution
├── tests/
│   ├── test_crypto.py          # NIP-44 round-trip, event signing
│   ├── test_relay_pool.py      # Dedup, reconnection logic
│   ├── test_adapter.py         # Auth checks, message routing
│   └── test_event_router.py    # Event classification
├── pyproject.toml              # Package metadata + deps (pynostr, websockets)
├── README.md                   # Setup guide
└── .gitignore
```

## Tasks

### Task 1: Project Scaffold + Dependencies
- Create `pyproject.toml` with `pynostr` and `websockets` deps
- Create `plugins/platforms/nostr/__init__.py`
- Create `.gitignore`
- Create `README.md` with quick start
- Copy the existing `docs/design.md` if not already present

### Task 2: Crypto Module (`crypto.py`)
- `NIP44Crypto` class: encrypt/decrypt using pynostr's nip44 module
- `LegacyDMCrypto` class: NIP-04 AES-256-CBC decrypt (legacy)
- `EventSigner` class: sign events with nsec, verify signatures
- Key utilities: `derive_pubkey(nsec)`, `npub_to_hex(npub)`, `hex_to_npub(hex)`
- Gift-wrap unwrap: `unwrap_gift_wrap(gift_event, nsec) -> rumor dict`
- Gift-wrap create: `create_gift_wrap(rumor, recipient_pubkey, sender_nsec) -> kind 1059 event`
- Security: nsec never logged, passed only as private variable

### Task 3: Relay Pool (`relay_pool.py`)
- `RelayPool` class managing N WebSocket connections
- `connect()`: open connections to all relays concurrently
- `disconnect()`: close all connections gracefully
- `subscribe(filters)`: send REQ to all relays
- `publish(event)`: send EVENT to all relays, collect OK responses, require ≥1
- `events()`: async generator yielding `(event_dict, relay_url)` tuples
- Event dedup: bounded set of seen event IDs (evict oldest at 50K)
- Per-relay independent reconnection with exponential backoff + jitter
  (1s, 2s, 4s, 8s, 16s, 30s cap)
- Connection state tracking per relay (connected/disconnected/reconnecting)

### Task 4: Event Router (`event_router.py`)
- `EventRouter` class: classify incoming events by NIP kind
- Route kind 1059 → DM decryptor (NIP-17 gift wrap)
- Route kind 4 → DM decryptor (NIP-04 legacy)
- Route kind 1 → mention check (if monitor_mentions enabled)
- Route kind 0 → profile cache update
- Ignore unknown kinds
- Call adapter callback methods: `_handle_dm()`, `_handle_mention()`

### Task 5: Profile Cache (`profile_cache.py`)
- `ProfileCache` class with TTL-based expiry (default 3600s)
- `get_profile(pubkey)`: fetch kind 0 from relays, parse name/about/picture
- NIP-05 lookup: if profile has nip05 field, verify via DNS
- Cache stored as dict: pubkey → {name, about, picture, nip05, fetched_at}
- Fetch is async with 10s timeout per relay

### Task 6: Plugin Adapter (`adapter.py`)
- `NostrAdapter(BasePlatformAdapter)` — main adapter class
- `__init__`: parse config, nsec, relays, allowlist, feature flags
- `connect()`: init relay pool, subscribe to DMs + optional mentions, start listen loop
- `disconnect()`: stop listen loop, close relay pool
- `_listen_loop()`: async loop receiving events from relay pool, routing via EventRouter
- `_handle_dm(sender_pubkey, content, original_event)`: auth check, build source, dispatch
- `_handle_mention(event)`: auth check, build source, dispatch
- `send(chat_id, text, metadata)`: determine DM vs public reply, sign + publish
- `send_typing(chat_id)`: no-op (Nostr has no typing indicator)
- `send_image(chat_id, image_url, caption)`: send URL in text (Phase 1)
- `get_chat_info(chat_id)`: fetch profile for display name
- `format_message(content)`: plain text (Nostr doesn't render markdown)
- `_standalone_send()`: for cron delivery outside gateway

### Task 7: Plugin Registration + plugin.yaml
- `plugin.yaml` with all env vars (NOSTR_NSEC, NOSTR_RELAYS, etc.)
- `check_requirements()`: check pynostr is importable
- `validate_config()`: check nsec + relays present
- `is_connected()`: check nsec + relays present
- `_env_enablement()`: seed PlatformConfig.extra from env
- `register(ctx)` with all hooks:
  - `adapter_factory`
  - `check_fn`, `validate_config`, `is_connected`
  - `required_env`, `install_hint`
  - `env_enablement_fn`
  - `cron_deliver_env_var`
  - `standalone_sender_fn`
  - `allowed_users_env`, `allow_all_env`
  - `max_message_length`, `emoji`

### Task 8: Tests
- `test_crypto.py`: NIP-44 encrypt/decrypt round-trip, event signing/verification,
  gift-wrap unwrap round-trip, npub↔hex conversion
- `test_relay_pool.py`: event dedup (same ID from 2 relays → 1 delivery),
  reconnection backoff logic
- `test_adapter.py`: unauthorized DM dropped, allow_all bypass, config parsing
- `test_event_router.py`: kind 1059 → DM path, kind 1 → mention path,
  unknown kind → ignored

### Task 9: README + Final Polish
- Full setup guide: install deps, generate nsec, configure relays
- Config examples (env vars + config.yaml)
- NIP compliance table
- Security notes (dedicated nsec, nsec never logged)

## Key Reference Files in Hermes Source

Study these before implementing:
- `/Users/cortexuvula/hermes-agent/gateway/platforms/base.py` — BasePlatformAdapter, MessageEvent, SendResult, build_source()
- `/Users/cortexuvula/hermes-agent/gateway/config.py` — Platform enum (dynamic members for plugins)
- `/Users/cortexuvula/hermes-agent/plugins/platforms/irc/adapter.py` — IRC plugin (stdlib WebSocket-like, no deps)
- `/Users/cortexuvula/hermes-agent/plugins/platforms/irc/plugin.yaml` — plugin.yaml template
- `/Users/cortexuvula/hermes-agent/plugins/platforms/simplex/adapter.py` — SimpleX plugin (WebSocket-based, closest pattern)
- `/Users/cortexuvula/hermes-agent/gateway/platforms/ADDING_A_PLATFORM.md` — full integration checklist

## Implementation Rules

1. **Follow the design doc** (`docs/design.md`) — it has full code sketches
2. **Use `pynostr`** for all crypto — never roll your own ECDH/AES
3. **Never log the nsec** — add a class-level logger that masks it
4. **Test as you go** — run tests after each task, commit after each passes
5. **Follow the plugin pattern** from irc/simplex examples exactly
6. **The Platform enum uses dynamic members** — `Platform("nostr")` works
   automatically for plugins via the `_missing_` classmethod
7. **Python 3.10+** — use modern type hints (str | None, etc.)
