# QA Bug Report — Nostr Platform Adapter Plugin

**Reviewer:** Codie (QA)  
**Date:** 2026-06-25  
**Repo:** `/Users/cortexuvula/nostr-platform`  
**Commit:** HEAD of `main`  
**Tests:** 37 passed (0.14s)  
**Lint:** ruff 0.15.10 — 35 errors found  

---

## Summary

The codebase is well-structured and all 37 tests pass, but the NIP-44 v2
encryption implementation is **fundamentally non-compliant with the spec** —
it uses AES-GCM instead of ChaCha20, derives keys incorrectly, and has a
wrong payload format. This means the adapter **cannot interoperate** with any
standard Nostr client. The NIP-17 gift-wrap flow is also broken: the seal
contains the rumor in plaintext instead of NIP-44 encrypting it, which is
another spec violation that breaks interop. Several relay pool functions
(publish, query) are stubs that don't actually work. No incoming event
signatures are verified, creating a relay-injection attack vector.

**Critical: 4 | High: 6 | Medium: 8 | Low: 6**

---

## CRITICAL

### C1. NIP-44 v2 uses AES-GCM instead of ChaCha20

**File:** `plugins/platforms/nostr/crypto.py`, lines 137–139  
**Spec:** NIP-44 v2 mandates ChaCha20 (RFC 8439), NOT AES-GCM  

```python
# Encrypt with AES-256-GCM   ← WRONG
aesgcm = AESGCM(enc_key)
ciphertext = aesgcm.encrypt(nonce, padded, None)
```

The spec is explicit: "ChaCha20 (not AES or XChaCha) — faster with better
security against multi-key attacks." AES-GCM produces a different ciphertext
format (includes a built-in GCM tag) and is incompatible.

**Impact:** Any message encrypted by this adapter cannot be decrypted by a
standard NIP-44 client, and vice versa.

**Fix:** Replace `AESGCM` with `cryptography.hazmat.primitives.ciphers.Cipher`
using `algorithms.ChaCha20` and a 12-byte nonce derived from the key
expansion. Compute the MAC separately with HMAC-SHA256.

---

### C2. NIP-44 v2 key derivation is wrong (salt, info, and length)

**File:** `plugins/platforms/nostr/crypto.py`, lines 118–131, 176–183  

The spec requires:
1. **Conversation key**: `hkdf_extract(salt=utf8("nip44-v2"), IKM=shared_x)`  
   — salt is the literal string "nip44-v2", NOT random
2. **Message keys**: `hkdf_expand(PRK=conversation_key, info=<32-byte random nonce>, L=76)`  
   — info is the nonce, NOT "nip44-v2"
3. Split 76 bytes: `chacha_key[0:32]`, `chacha_nonce[32:44]`, `hmac_key[44:76]`

The code does:
1. `salt = os.urandom(32)` — random salt instead of "nip44-v2" (line 119)
2. `info = b"nip44-v2"` — the string "nip44-v2" as info instead of the nonce (line 123)
3. `keys = _hkdf_expand(prk, info, 44)` — only 44 bytes, missing hmac_key (line 129)
4. MAC key derived separately as `_hkdf_expand(prk, b"nip44-v2-mac", 32)` — non-spec (line 145)

**Impact:** Completely breaks interoperability. The conversation key is
different on every encryption because the salt is random, so the same
plaintext encrypted twice produces different conversation keys — the spec
intends the conversation key to be deterministic per keypair.

**Fix:** Implement exactly as the spec:
```python
conversation_key = _hkdf_extract(b"nip44-v2", shared_x)
nonce = os.urandom(32)
keys = _hkdf_expand(conversation_key, nonce, 76)
chacha_key = keys[0:32]
chacha_nonce = keys[32:44]
hmac_key = keys[44:76]
mac = hmac_sha256(hmac_key, nonce + ciphertext)
payload = bytes([2]) + nonce + ciphertext + mac
```

---

### C3. NIP-44 v2 payload format and nonce size are wrong

**File:** `plugins/platforms/nostr/crypto.py`, lines 142, 168–171  

**Spec payload:** `base64(version(1) + nonce(32) + ciphertext + mac(32))`  
**Code payload:** `bytes([2]) + salt(32) + nonce(12) + ciphertext + mac(32)`

The code uses a 12-byte nonce (from the 44-byte expansion) and includes a
32-byte salt in the payload. The spec uses a 32-byte nonce (randomly
generated, not from HKDF) and no salt in the payload.

**Impact:** Payloads are structurally incompatible with standard clients.
Decryption will fail on payload length validation (spec requires 99–65603
bytes decoded).

**Fix:** Use 32-byte random nonce as the `info` parameter for HKDF-expand,
include it in the payload, remove the salt.

---

### C4. NIP-17 gift-wrap seal contains plaintext rumor (not encrypted)

**File:** `plugins/platforms/nostr/crypto.py`, lines 390–395  

Per NIP-59/NIP-17, the seal (kind 13) must have its **content** field set to
the NIP-44 encrypted rumor. The code stores the rumor as plaintext JSON:

```python
seal_content = json.dumps(rumor)  # ← PLAINTEXT, should be NIP-44 encrypted
seal = signer.sign_event(kind=13, content=seal_content, tags=[])
```

**Spec flow:**
1. Create rumor (unsigned)
2. **Seal**: NIP-44 encrypt rumor to recipient → kind 13 event signed by sender
3. **Gift wrap**: NIP-44 encrypt seal to recipient → kind 1059 event with ephemeral key

The code only does step 3 (encrypts the seal JSON), skipping the seal
encryption in step 2. The seal's content field contains the raw rumor JSON.

**Impact:** 
- Standard NIP-17 clients sending to this adapter will have their seal content
  NIP-44 encrypted. The `unwrap_gift_wrap` function does `json.loads(seal["content"])`
  which will fail on the encrypted base64 string.
- Messages from this adapter sent to standard clients will have an unencrypted
  seal, which clients may reject or fail to process.

**Fix:** In `create_gift_wrap`, encrypt the rumor before putting it in the seal:
```python
encrypted_rumor = nip44_encrypt(json.dumps(rumor), sender_privkey_hex, recipient_pubkey_hex)
seal = signer.sign_event(kind=13, content=encrypted_rumor, tags=[])
```
And in `unwrap_gift_wrap`, decrypt the seal content:
```python
seal_content = nip44_decrypt(seal["content"], recipient_privkey_hex, seal["pubkey"])
rumor = json.loads(seal_content)
```

---

## HIGH

### H1. No incoming event signature verification

**File:** `plugins/platforms/nostr/relay_pool.py`, lines 164–180;  
`plugins/platforms/nostr/event_router.py`, lines 24–38

When an EVENT message arrives from a relay, the event is added to the queue
and routed without verifying its signature. The `EventSigner.verify_event()`
method exists but is never called on incoming events.

**Impact:** A malicious relay could inject forged events with any pubkey,
allowing impersonation of any sender. The authorization check in
`_handle_dm` checks the sender pubkey, but if the event signature is
unverified, the pubkey can be freely forged.

**Fix:** In `_handle_message` or `EventRouter.route()`, verify the event
signature before processing:
```python
from .crypto import EventSigner
if not self._signer.verify_event(event):
    logger.warning(f"Forged event {event.get('id', '?')[:16]}")
    return
```

---

### H2. `publish()` never verifies relay acceptance

**File:** `plugins/platforms/nostr/relay_pool.py`, lines 214–237

The `publish()` method sends the EVENT message to all relays and sleeps
0.5s, but never checks for OK responses. The `results` dict is always
empty. The docstring says "At least one relay must accept for success"
but this is never enforced.

```python
results = {}  # ← always empty
# ...
await asyncio.sleep(0.5)  # ← blind wait
return results  # ← returns {}
```

**Impact:** `send()` returns `SendResult(success=True)` even if zero relays
accepted the event. The user thinks their message was sent when it may
have been silently dropped.

**Fix:** Implement a proper OK-response collector using futures per relay,
or at minimum check the listen loop's OK messages for the event_id.

---

### H3. `query()` never collects events — always returns empty list

**File:** `plugins/platforms/nostr/relay_pool.py`, lines 258–294

The `query()` method sends a REQ, sleeps for the timeout duration, then
returns `events` which is always `[]`. The `temp_queue` and `collected`
variables are created but never used.

```python
events = []        # ← never populated
collected = asyncio.Event()  # ← never set
temp_queue = asyncio.Queue()  # ← never used
```

**Impact:** `ProfileCache._fetch_from_relays()` relies on `query()` (indirectly),
and profile fetching from relays is completely non-functional. Any feature
depending on relay queries (NIP-05, profile lookup, historical DMs) is broken.

**Fix:** Route subscription-specific events to the temp_queue by checking
the subscription_id in `_handle_message`, then drain the queue until EOSE
or timeout.

---

### H4. Seal signature not verified in `unwrap_gift_wrap`

**File:** `plugins/platforms/nostr/crypto.py`, lines 468–486

The NIP-17 spec states: "Clients MUST verify that the pubkey of the kind 13
seal matches the pubkey of the contained rumor to prevent impersonation."

The `unwrap_gift_wrap` function parses the seal and extracts the rumor, but:
1. Does not verify the seal's signature
2. Does not check that the seal's pubkey matches the rumor's pubkey
3. Does not verify the gift-wrap event's signature

**Impact:** An attacker who can send gift-wrap events to the relay can
impersonate any sender by crafting a seal with a fake pubkey.

**Fix:** Call `EventSigner.verify_event(seal)` and check
`seal["pubkey"] == rumor.get("pubkey")`.

---

### H5. NIP-04 key derivation may not match spec (sha256 missing)

**File:** `plugins/platforms/nostr/crypto.py`, lines 263–264, 301–302  

The NIP-04 spec states the shared secret should be
`sha256(privkey_a * pubkey_b)` (hashed X coordinate). The code uses
`_get_shared_secret()` which calls `pynostr.PrivateKey.compute_shared_secret()`,
returning the raw X coordinate without sha256 hashing:

```python
shared = _get_shared_secret(sender_privkey_hex, recipient_pubkey_hex)
key = shared  # pynostr uses raw X directly as AES key  ← POSSIBLY WRONG
```

The comment claims "pynostr uses raw X directly" but this depends on the
pynostr version. If pynostr returns raw X (not sha256'd), this won't
interoperate with standard NIP-04 implementations that use sha256(X) as
the key.

**Impact:** NIP-04 DMs may not decrypt correctly from/to standard clients
that use sha256(X) as the AES key. Needs verification against the actual
pynostr implementation.

**Fix:** Verify what `compute_shared_secret` returns. If it returns raw X,
add `key = hashlib.sha256(shared).digest()`.

---

### H6. DM rumor uses kind 4 instead of kind 14

**File:** `plugins/platforms/nostr/crypto.py`, lines 489–495

```python
def create_dm_rumor(content: str, recipient_pubkey_hex: str) -> dict:
    return {
        "kind": 4,  # ← should be 14 per NIP-17
        ...
    }
```

Per NIP-17, chat message rumors should be kind 14, not kind 4. Kind 4 is
the legacy NIP-04 encrypted DM event kind. Using kind 4 in a NIP-17 rumor
is non-standard and may cause clients to misinterpret the message.

**Fix:** Change `"kind": 4` to `"kind": 14`.

---

## MEDIUM

### M1. NIP-44 padding scheme doesn't match spec

**File:** `plugins/platforms/nostr/crypto.py`, lines 198–238

The spec uses a specific chunk-based padding algorithm:
```python
def calc_padded_len(unpadded_len):
    next_power = 1 << (floor(log2(unpadded_len - 1)) + 1)
    if next_power <= 256:
        chunk = 32
    else:
        chunk = next_power // 8
    if unpadded_len <= 32:
        return 32
    return chunk * (floor((unpadded_len - 1) / chunk) + 1)
```

The code uses a simpler "next power of 2 minus 1" scheme (line 229) which
produces different padded sizes. The code also has dead/redundant
calculations (lines 210–220 are overwritten by line 229).

Also, `max_plaintext_size` should be 65535 bytes (per spec), but the code
caps at 40960 (line 224).

**Fix:** Implement `calc_padded_len` exactly as the spec pseudocode, and
validate padding on decrypt (check that the padded length matches the
expected value from `calc_padded_len`).

---

### M2. Double decryption in `_handle_gift_wrap` (performance + correctness)

**File:** `plugins/platforms/nostr/event_router.py`, lines 42–83

`unwrap_gift_wrap()` already decrypts the seal to get the rumor, but
`_handle_gift_wrap()` then re-decrypts the seal to extract the sender
pubkey (lines 74–83). This is wasteful and fragile.

The comments in the code acknowledge this: "Actually, we need to modify
unwrap to also return the seal pubkey."

**Fix:** Modify `unwrap_gift_wrap` to return a tuple `(rumor, seal_pubkey)`
or a dict with both, eliminating the second decryption.

---

### M3. No payload length validation on NIP-44 decrypt

**File:** `plugins/platforms/nostr/crypto.py`, lines 160–171

The spec requires validating the decoded payload length (99–65603 bytes)
before processing. The code only checks the version byte.

**Fix:** Add:
```python
if len(payload) < 99 or len(payload) > 65603:
    raise ValueError("Invalid NIP-44 payload length")
```

---

### M4. `_fetch_from_relays` is non-functional (always returns None)

**File:** `plugins/platforms/nostr/profile_cache.py`, lines 59–95

The method sends a REQ to relays, sleeps 2 seconds, sends CLOSE, then
returns None without collecting any events. The comment admits: "For now,
return None — profiles will be populated by the event router."

**Impact:** `get_profile()` will always fall through to the NIP-05 lookup
(which is also a no-op) and return a fallback profile. Profile display
names will always be truncated pubkeys unless a kind 0 event happens to
arrive via the subscription.

**Fix:** Either implement proper relay query response collection, or
document that profiles are only populated reactively from the event router.

---

### M5. NIP-05 lookup is a no-op

**File:** `plugins/platforms/nostr/profile_cache.py`, lines 105–114

```python
async def _nip05_lookup(self, pubkey: str) -> Optional[dict]:
    return None  # ← always None
```

The `require_nip05` feature will never work — profiles never have a `nip05`
field set, so all DMs will be rejected when `require_nip05=True`.

**Fix:** NIP-05 requires a known `user@domain` identifier to query — it
cannot reverse-lookup from a pubkey alone. The NIP-05 field should come
from the kind 0 metadata event's `content.nip05` field, populated by the
event router.

---

### M6. Subscription ID collisions on reconnect/resubscribe

**File:** `plugins/platforms/nostr/relay_pool.py`, lines 198–211

In `subscribe()`, sub IDs are `f"sub_{i}"` where `i` is the index in the
current filter batch. On reconnection, `_connect_and_listen` resubscribes
to all subscriptions using `_send_subscription`, which generates IDs as
`f"sub_{id(filter_dict)}"`. The ID scheme is inconsistent between initial
subscribe and resubscribe.

**Fix:** Generate a unique sub_id per filter and store it alongside the
filter in `self._subscriptions` for consistent reuse.

---

### M7. `RelayPool` stores nsec unnecessarily

**File:** `plugins/platforms/nostr/relay_pool.py`, line 93

```python
self.nsec = nsec  # ← stored but never used
```

The private key is stored in the relay pool but never referenced. This is
unnecessary exposure of the most sensitive credential.

**Fix:** Remove `self.nsec` from `RelayPool.__init__`. Only the adapter
and EventSigner need the nsec.

---

### M8. NIP-44 encrypt has dead/redundant key derivation code

**File:** `plugins/platforms/nostr/crypto.py`, lines 124–131

```python
enc_key = _hkdf_expand(prk, info, 32)          # line 124 — overwritten
nonce = _hkdf_expand(prk, info + b"\x01", 12)  # line 125 — overwritten
# ...
keys = _hkdf_expand(prk, info, 44)              # line 129 — final
enc_key = keys[:32]                             # line 130
nonce = keys[32:44]                             # line 131
```

Lines 124–125 are dead code — their results are immediately overwritten by
lines 129–131.

**Fix:** Remove lines 124–125 and the comment on line 127.

---

## LOW

### L1. 35 ruff lint errors (unused imports, dead variables)

**Files:** All source and test files

22 are auto-fixable. Notable issues:
- `adapter.py:24` — `import json` unused
- `adapter.py:56-57` — `npub_to_hex`, `hex_to_npub` imported but unused (adapter defines its own)
- `crypto.py:39` — `pk = PrivateKey.from_nsec` — dead nonsense code
- `crypto.py:180` — `expected_nonce` assigned but never used
- `relay_pool.py:226` — `ok_futures` assigned but never used
- `relay_pool.py:266,270` — `collected`, `temp_queue` assigned but never used
- `profile_cache.py:7,10,12` — `json`, `Any`, `aiohttp` all imported but unused
- `event_router.py:66,104` — `_get_shared_secret` imported but unused in inline imports

**Fix:** Run `ruff check --fix plugins/ tests/` to auto-fix 22 of 35.

---

### L2. `_handle_mention` can KeyError on missing event "id"

**File:** `plugins/platforms/nostr/adapter.py`, line 341

```python
source = self.build_source(
    chat_id=event["id"],  # ← KeyError if "id" missing
```

If a kind 1 event arrives without an `id` field (malformed), this will
raise an unhandled KeyError.

**Fix:** Use `event.get("id", "")` or add a guard.

---

### L3. Dead variable `pk` in `npub_to_hex`

**File:** `plugins/platforms/nostr/crypto.py`, line 39

```python
def npub_to_hex(npub: str) -> str:
    pk = PrivateKey.from_nsec  # not for npub  ← nonsense assignment
    from pynostr.key import PublicKey
    return PublicKey.from_npub(npub).hex()
```

`pk` is assigned to the class method `PrivateKey.from_nsec` (not called)
and never used.

**Fix:** Remove line 39 and the comment.

---

### L4. `format_message` is a no-op

**File:** `plugins/platforms/nostr/adapter.py`, lines 428–434

Returns content unchanged. This is correct behavior (Nostr doesn't render
markdown natively), but the docstring could note that some clients (e.g.
Damus) do render basic markdown.

**Severity:** Low — no action needed, just documentation.

---

### L5. `_standalone_send` method on class is dead code

**File:** `plugins/platforms/nostr/adapter.py`, lines 440–476

The `NostrAdapter._standalone_send` method exists but `register()` uses the
module-level `_standalone_send_async` function instead. The method is never
called.

**Fix:** Remove the `_standalone_send` method from the class.

---

### L6. `conftest.py` has hardcoded path

**File:** `tests/conftest.py`, line 10

```python
HERMES_SRC = Path("/Users/cortexuvula/hermes-agent")
```

This hardcoded path won't work on other machines or CI environments.

**Fix:** Use an environment variable or relative path discovery.

---

## Test Coverage Gaps

The 37 tests pass but have significant coverage gaps:

1. **No NIP-44 encrypt/decrypt tests** — the `test_crypto.py` file tests
   NIP-04 and gift-wrap round-trips but NOT `nip44_encrypt`/`nip44_decrypt`
   directly. This is why the completely wrong implementation passes tests —
   it's only tested in a self-consistent round-trip.

2. **No interop test vectors** — no tests against known NIP-44 v2 test
   vectors from the spec. The spec includes reference test vectors that
   should be used.

3. **No relay pool publish/query tests** — `publish()` and `query()` are
   untested. This is why the broken implementations (always empty results)
   go unnoticed.

4. **No signature verification tests** — no test verifies that incoming
   events have their signatures checked.

5. **No authorization tests** — `test_adapter.py` tests config parsing but
   not the actual `_handle_dm` authorization flow (allowlist enforcement).

6. **No NIP-05 gate tests** — the `require_nip05` path is untested.

---

## Security Assessment

| Check | Status | Notes |
|-------|--------|-------|
| nsec never logged | ✅ Pass | nsec is stored in `self.nsec` and `self._nsec`, never in log messages. Logger calls use truncated pubkey only. |
| nsec not in error messages | ✅ Pass | Error messages use truncated pubkey, not nsec. |
| nsec not exposed to relays | ⚠️ Warn | `RelayPool` stores nsec unnecessarily (M7). It's never sent to relays, but the exposure surface is wider than needed. |
| Event signatures verified | ❌ Fail | Incoming events are not signature-verified (H1). |
| Prompt injection defense | ✅ Pass | DMs are treated as user messages, same as other platforms. Hermes's tirith defense applies. |
| Allowlist enforcement | ✅ Pass | `_handle_dm` checks `sender_pubkey not in self.allowed_users`. |
| Unauthorized DMs silently dropped | ✅ Pass | No error sent to sender. |
| E2E encryption | ⚠️ Partial | NIP-44 implementation is wrong (C1–C3), NIP-04 may have wrong key derivation (H5). |

---

## Design Doc Compliance

| Design Doc Feature | Status | Notes |
|---------------------|--------|-------|
| RelayPool with WebSocket + reconnection | ✅ | Implemented with exponential backoff + jitter |
| Dedup by event ID (bounded set) | ✅ | OrderedDict with 50K cap, evicts 25% |
| Publish to all, require one | ❌ | Publish doesn't verify any relay accepted (H2) |
| NIP-17 gift-wrapped DM receiving | ⚠️ | Receives but seal not properly encrypted (C4) |
| NIP-44 v2 decryption | ❌ | Wrong cipher, key derivation, payload format (C1–C3) |
| NIP-04 legacy DM decryption | ⚠️ | Possible wrong key derivation (H5) |
| npub allowlist authorization | ✅ | Implemented correctly |
| Outbound DM sending (NIP-17) | ❌ | Seal not encrypted, kind 4 instead of 14 (C4, H6) |
| Profile cache (kind 0 fetch) | ❌ | Relay fetch non-functional (M4) |
| Plugin registration with all hooks | ✅ | All hooks present in register() |
| check_requirements() with pynostr | ✅ | Implemented |
| Standalone sender for cron delivery | ✅ | `_standalone_send_async` implemented |
| Public mention monitoring | ✅ | Implemented (Phase 2 feature shipped early) |
| NIP-10 reply markers | ✅ | `["e", note_id, "", "reply"]` in send() |
| Event signature verification | ❌ | Not implemented (H1) |
| Seal signature verification | ❌ | Not implemented (H4) |

---

## Files Reviewed

| File | Lines | Issues Found |
|------|-------|--------------|
| `plugins/platforms/nostr/crypto.py` | 495 | C1, C2, C3, C4, H4, H5, H6, M1, M3, M8, L3 |
| `plugins/platforms/nostr/relay_pool.py` | 294 | H1, H2, H3, M6, M7 |
| `plugins/platforms/nostr/event_router.py` | 149 | M2 |
| `plugins/platforms/nostr/profile_cache.py` | 130 | M4, M5 |
| `plugins/platforms/nostr/adapter.py` | 531 | L2, L5 |
| `plugins/platforms/nostr/plugin.yaml` | 44 | — |
| `plugins/platforms/nostr/__init__.py` | 3 | — |
| `tests/test_crypto.py` | 172 | Coverage gaps |
| `tests/test_relay_pool.py` | 94 | Coverage gaps |
| `tests/test_event_router.py` | 153 | Coverage gaps |
| `tests/test_adapter.py` | 174 | Coverage gaps |
| `tests/conftest.py` | 21 | L6 |

---

## Recommendations (Priority Order)

1. **Fix NIP-44 v2 implementation** (C1–C3) — this is the most critical
   issue. Replace AES-GCM with ChaCha20, fix key derivation to match spec
   exactly, fix payload format. Use the spec's reference test vectors.

2. **Fix NIP-17 seal encryption** (C4) — encrypt the rumor with NIP-44
   before putting it in the seal's content field.

3. **Add event signature verification** (H1, H4) — verify all incoming
   events and seal signatures before processing.

4. **Fix relay pool publish/query** (H2, H3) — implement proper OK response
   collection and query result routing.

5. **Fix DM rumor kind** (H6) — change from kind 4 to kind 14.

6. **Verify NIP-04 key derivation** (H5) — check if pynostr returns raw X
   or sha256(X), add sha256 if needed.

7. **Add NIP-44 test vectors** — test against known vectors from the spec
   to catch interop issues.

8. **Clean up lint** (L1) — run `ruff check --fix`.

---

*End of report.*
