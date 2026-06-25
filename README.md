# Nostr Platform Adapter for Hermes Agent

A Hermes Agent platform plugin that connects to Nostr relays via WebSocket,
receives NIP-17 encrypted DMs, and replies as signed Nostr events.

> **Status:** Phase 1 (Core DM Support) — functional, tested.
> See `docs/design.md` for the full architecture and phased roadmap.

## Quick Start

### 1. Install dependencies

```bash
pip install pynostr websockets
```

Or from this repo:

```bash
cd nostr-platform
pip install -e ".[dev]"
```

### 2. Generate a dedicated Nostr key

```bash
# Using nak (https://github.com/fiatjaf/nak)
nak key generate

# Or using pynostr:
python3 -c "from pynostr.key import PrivateKey; print(PrivateKey().bech32())"
```

> **Security:** Generate a **dedicated** nsec for the agent — never reuse your
> personal Nostr identity key. The nsec is the most sensitive credential in
> the system. It is never logged.

### 3. Configure environment variables

Add to `~/.hermes/.env`:

```bash
NOSTR_NSEC=nsec1...your-agent-private-key
NOSTR_RELAYS=wss://relay.damus.io,wss://relay.primal.net,wss://nostr.wine
NOSTR_ALLOWED_USERS=npub1...alice,npub1...bob
```

Or in `config.yaml`:

```yaml
gateway:
  platforms:
    nostr:
      enabled: true
      extra:
        relays:
          - wss://relay.damus.io
          - wss://relay.primal.net
          - wss://nostr.wine
        monitor_mentions: false
        reply_publicly: false
        require_nip05: false
        max_message_length: 5000
```

### 4. Run

```bash
hermes gateway start
```

## Configuration

### Required Environment Variables

| Variable | Description |
|----------|-------------|
| `NOSTR_NSEC` | Agent's Nostr private key (`nsec1...`). Never logged. |
| `NOSTR_RELAYS` | Comma-separated relay WebSocket URLs |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NOSTR_ALLOWED_USERS` | _(empty)_ | Comma-separated npubs allowed to DM |
| `NOSTR_ALLOW_ALL_USERS` | `false` | Allow anyone to DM (dev only) |
| `NOSTR_HOME_CHANNEL` | _(empty)_ | Default npub for cron delivery |
| `NOSTR_MONITOR_MENTIONS` | `false` | Respond to public mentions (kind 1) |
| `NOSTR_REPLY_PUBLICLY` | `false` | Reply publicly to mentions instead of DM |
| `NOSTR_REQUIRE_NIP05` | `false` | Only accept DMs from NIP-05 verified users |

## NIP Compliance

| NIP | Title | Status |
|-----|-------|--------|
| NIP-01 | Basic protocol | ✅ Required |
| NIP-04 | Encrypted DMs (legacy) | ⚠️ Supported (fallback) |
| NIP-05 | DNS verification | ✅ Supported |
| NIP-10 | Reply markers | ✅ Supported |
| NIP-17 | Gift-wrapped DMs | ✅ Primary DM method |
| NIP-19 | bech32 entities | ✅ Supported |
| NIP-42 | Relay auth | 🔜 Phase 2 |
| NIP-44 | Encryption v2 | ✅ Required |
| NIP-65 | Relay lists | 🔜 Phase 2 |

## Architecture

```
nostr-platform/
├── docs/
│   └── design.md
├── plugins/platforms/nostr/
│   ├── __init__.py
│   ├── plugin.yaml
│   ├── adapter.py
│   ├── relay_pool.py
│   ├── crypto.py
│   ├── event_router.py
│   └── profile_cache.py
├── tests/
│   ├── test_crypto.py
│   ├── test_relay_pool.py
│   ├── test_adapter.py
│   └── test_event_router.py
├── pyproject.toml
└── README.md
```

## Security Notes

- **Dedicated nsec:** Always generate a separate Nostr key for the agent.
  Never reuse your personal identity key.
- **nsec never logged:** The adapter assigns the nsec to an internal variable
  and never includes it in log output, error messages, or chat responses.
- **E2E encryption:** All DMs are end-to-end encrypted via NIP-44 (NIP-17)
  or NIP-04 (legacy). The relay operator cannot read message content.
- **Allowlist:** By default, only npubs in `NOSTR_ALLOWED_USERS` can DM the
  agent. Unauthorized DMs are silently dropped.

## License

MIT
