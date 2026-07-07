"""
Nostr cryptographic operations: NIP-44 v2 encryption, NIP-04 legacy DM,
event signing, gift-wrap unwrap/create, and key utilities.

NIP-44 v2 spec: https://github.com/nostr-protocol/nips/blob/master/44.md
Uses pynostr for event signing/bech32 and the cryptography package for
ChaCha20 + HKDF + HMAC-SHA256.

Security: the nsec is never logged. It is passed as a private variable
and used only for cryptographic operations.
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import random
import struct
import time
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from pynostr.event import Event
from pynostr.key import PrivateKey, PublicKey

logger = logging.getLogger(__name__)

NIP44_VERSION = 0x02
MIN_PLAINTEXT_SIZE = 1
MAX_PLAINTEXT_SIZE = 65535
MIN_PAYLOAD_SIZE = 99  # 1 + 32 + 32 + 32 (version + nonce + min ciphertext + mac)
MAX_PAYLOAD_SIZE = 65603


# ---------------------------------------------------------------------------
# Key utilities
# ---------------------------------------------------------------------------

def derive_pubkey(nsec: str) -> str:
    """Derive hex pubkey from nsec (bech32) private key."""
    sk = PrivateKey.from_nsec(nsec)
    return sk.public_key.hex()


def npub_to_hex(npub: str) -> str:
    """Convert npub (bech32) to hex pubkey."""
    return PublicKey.from_npub(npub).hex()


def hex_to_npub(hex_key: str) -> str:
    """Convert hex pubkey to npub (bech32)."""
    return PublicKey.from_hex(hex_key).bech32()


# ---------------------------------------------------------------------------
# HKDF (RFC 5869) with SHA-256
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using HMAC-SHA256."""
    if len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand using HMAC-SHA256."""
    t = b""
    okm = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# ---------------------------------------------------------------------------
# ECDH shared secret
# ---------------------------------------------------------------------------

def _get_shared_secret(privkey_hex: str, pubkey_hex: str) -> bytes:
    """Compute ECDH shared secret (raw unhashed X coordinate) using secp256k1.

    Per NIP-44 spec: "Output of ECDH is the unhashed 32-byte x-coordinate."
    Uses pynostr's PrivateKey.compute_shared_secret which returns raw X.
    """
    sk = PrivateKey(bytes.fromhex(privkey_hex))
    return sk.compute_shared_secret(pubkey_hex)


def _get_conversation_key(privkey_hex: str, pubkey_hex: str) -> bytes:
    """NIP-44: conversation_key = HKDF-Extract(IKM=shared_x, salt='nip44-v2')."""
    shared_x = _get_shared_secret(privkey_hex, pubkey_hex)
    return _hkdf_extract(b"nip44-v2", shared_x)


def _get_message_keys(conversation_key: bytes, nonce: bytes) -> tuple:
    """NIP-44: derive per-message keys from conversation_key and nonce.

    Returns (chacha_key, chacha_nonce, hmac_key).
    """
    keys = _hkdf_expand(conversation_key, nonce, 76)
    chacha_key = keys[0:32]
    chacha_nonce = keys[32:44]
    hmac_key = keys[44:76]
    return chacha_key, chacha_nonce, hmac_key


# ---------------------------------------------------------------------------
# NIP-44 v2 padding
# ---------------------------------------------------------------------------

def _calc_padded_len(unpadded_len: int) -> int:
    """NIP-44 v2 padding size calculation per spec."""
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (math.floor((unpadded_len - 1) / chunk) + 1)


def _pad(plaintext: bytes) -> bytes:
    """NIP-44 v2 pad: [u16 BE length][plaintext][zero padding]."""
    unpadded_len = len(plaintext)
    if unpadded_len < MIN_PLAINTEXT_SIZE:
        raise ValueError("Plaintext too short")
    if unpadded_len > MAX_PLAINTEXT_SIZE:
        raise ValueError("Plaintext too long")

    padded_len = _calc_padded_len(unpadded_len)
    result = struct.pack(">H", unpadded_len) + plaintext
    padding_needed = padded_len + 2 - len(result)  # +2 for length prefix
    if padding_needed > 0:
        result += b"\x00" * padding_needed
    return result


def _unpad(padded: bytes) -> bytes:
    """NIP-44 v2 unpad: read u16 BE length, slice, verify zeros."""
    if len(padded) < 2:
        raise ValueError("Padded data too short")
    unpadded_len = struct.unpack(">H", padded[:2])[0]
    if unpadded_len < MIN_PLAINTEXT_SIZE or unpadded_len > MAX_PLAINTEXT_SIZE:
        raise ValueError("Invalid plaintext length in padding")
    plaintext = padded[2:2 + unpadded_len]
    if len(plaintext) != unpadded_len:
        raise ValueError("Padded data shorter than declared length")
    # Verify padding bytes are zeros
    padding = padded[2 + unpadded_len:]
    if any(b != 0 for b in padding):
        raise ValueError("Invalid padding bytes (non-zero)")
    # Verify padded length matches expected
    expected_padded = _calc_padded_len(unpadded_len)
    if len(padded) - 2 != expected_padded:
        raise ValueError("Padded length doesn't match expected size")
    return plaintext


# ---------------------------------------------------------------------------
# ChaCha20
# ---------------------------------------------------------------------------

def _chacha20_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 encryption (RFC 8439, counter=0).

    The cryptography library expects a 16-byte nonce. NIP-44 derives a
    12-byte nonce from HKDF. Per RFC 8439, the ChaCha20 nonce is 12 bytes,
    so we pad to 16 bytes by prepending 4 zero bytes (the counter prefix).
    """
    padded_nonce = b"\x00\x00\x00\x00" + nonce  # 4-byte counter prefix + 12-byte nonce
    cipher = Cipher(
        algorithms.ChaCha20(key, padded_nonce),
        mode=None,
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _chacha20_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 decryption (same as encryption — symmetric stream cipher)."""
    return _chacha20_encrypt(key, nonce, data)


# ---------------------------------------------------------------------------
# NIP-44 v2 encrypt / decrypt
# ---------------------------------------------------------------------------

def nip44_encrypt(plaintext: str, sender_privkey_hex: str,
                  recipient_pubkey_hex: str) -> str:
    """NIP-44 v2 encrypt.

    Returns base64-encoded payload: version(1) + nonce(32) + ciphertext + mac(32).
    """
    # 1. Calculate conversation key
    conversation_key = _get_conversation_key(sender_privkey_hex, recipient_pubkey_hex)

    # 2. Generate random 32-byte nonce
    nonce = os.urandom(32)

    # 3. Derive message keys
    chacha_key, chacha_nonce, hmac_key = _get_message_keys(conversation_key, nonce)

    # 4. Pad plaintext
    padded = _pad(plaintext.encode("utf-8"))

    # 5. Encrypt with ChaCha20
    ciphertext = _chacha20_encrypt(chacha_key, chacha_nonce, padded)

    # 6. Calculate MAC: HMAC-SHA256(hmac_key, nonce + ciphertext)
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()

    # 7. Encode: version + nonce + ciphertext + mac
    payload = bytes([NIP44_VERSION]) + nonce + ciphertext + mac

    return base64.b64encode(payload).decode("ascii")


def nip44_decrypt(payload_b64: str, recipient_privkey_hex: str,
                  sender_pubkey_hex: str) -> str:
    """NIP-44 v2 decrypt.

    Returns the plaintext string.
    """
    # 2. Decode base64 and validate size
    payload = base64.b64decode(payload_b64)
    if len(payload) < MIN_PAYLOAD_SIZE or len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Invalid NIP-44 payload length: {len(payload)}")

    # 3. Parse payload
    version = payload[0]
    if version != NIP44_VERSION:
        raise ValueError(f"Unsupported NIP-44 version: {version}")

    nonce = payload[1:33]
    mac = payload[-32:]
    ciphertext = payload[33:-32]

    # 4. Calculate conversation key and message keys
    conversation_key = _get_conversation_key(recipient_privkey_hex, sender_pubkey_hex)
    chacha_key, chacha_nonce, hmac_key = _get_message_keys(conversation_key, nonce)

    # 5. Verify MAC (constant-time)
    expected_mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("NIP-44 MAC verification failed")

    # 6. Decrypt with ChaCha20
    padded = _chacha20_decrypt(chacha_key, chacha_nonce, ciphertext)

    # 7. Remove padding
    plaintext_bytes = _unpad(padded)

    return plaintext_bytes.decode("utf-8")


# ---------------------------------------------------------------------------
# NIP-04 legacy DM encryption / decryption
# ---------------------------------------------------------------------------

def nip04_encrypt(plaintext: str, sender_privkey_hex: str,
                  recipient_pubkey_hex: str) -> str:
    """NIP-04 legacy DM encrypt (AES-256-CBC + ECDH).

    Returns base64-encoded ciphertext?iv format.
    """
    # ECDH shared secret (raw X coordinate)
    shared = _get_shared_secret(sender_privkey_hex, recipient_pubkey_hex)
    key = shared  # pynostr uses raw X directly as AES key

    # Generate random IV (16 bytes for AES-CBC)
    iv = os.urandom(16)

    # PKCS7 pad
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return f"{base64.b64encode(ciphertext).decode('ascii')}?iv={base64.b64encode(iv).decode('ascii')}"


def nip04_decrypt(payload: str, recipient_privkey_hex: str,
                  sender_pubkey_hex: str) -> str:
    """NIP-04 legacy DM decrypt.

    Payload format: base64(ciphertext)?iv=base64(iv). Raises ValueError on a
    malformed payload so callers can distinguish bad input from decrypt failure.
    """
    if "?iv=" not in payload:
        raise ValueError("Invalid NIP-04 payload: missing iv")

    ct_b64, iv_b64 = payload.split("?iv=", 1)

    # Strict base64 decode — reject non-canonical input (whitespace, bad
    # padding) up front with a clear error rather than a confusing AES failure.
    try:
        ciphertext = base64.b64decode(ct_b64, validate=True)
        iv = base64.b64decode(iv_b64, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid NIP-04 payload: bad base64 ({e})") from e

    if len(iv) != 16:
        raise ValueError(f"Invalid NIP-04 iv length: {len(iv)} (expected 16)")

    # ECDH shared secret (raw X coordinate)
    shared = _get_shared_secret(recipient_privkey_hex, sender_pubkey_hex)
    key = shared  # pynostr uses raw X directly as AES key

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # PKCS7 unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Event signing
# ---------------------------------------------------------------------------

class EventSigner:
    """Signs Nostr events using the agent's private key."""

    def __init__(self, nsec: str):
        self._nsec = nsec
        self._privkey = PrivateKey.from_nsec(nsec)
        self.pubkey = self._privkey.public_key.hex()
        self._privkey_hex = self._privkey.hex()

    def sign_event(self, kind: int, content: str,
                   tags: list = None, created_at: int = None) -> dict:
        """Create, sign, and return a Nostr event dict."""
        if tags is None:
            tags = []
        if created_at is None:
            created_at = int(datetime.now(timezone.utc).timestamp())

        event = Event(
            kind=kind,
            content=content,
            tags=tags,
            created_at=created_at,
        )
        event.sign(self._privkey_hex)
        return event.to_dict()

    def verify_event(self, event: dict) -> bool:
        """Verify an event's signature."""
        try:
            ev = Event.from_dict(event)
            return ev.verify()
        except Exception:
            return False


# ---------------------------------------------------------------------------
# NIP-17 gift-wrap operations
# ---------------------------------------------------------------------------

# NIP-59: seal & gift-wrap timestamps are randomized up to 2 days into the
# past to hide the real send time. Nostur's subscription cursor anchors to
# this 2-day window (issue #85), so a real-time timestamp can confuse it.
GIFT_WRAP_BACKDATE_MAX_DAYS = 2
# NIP-40 expiration tag on gift wraps: relays prune old kind-1059 events and
# Nostur/Amethyst honor the expiration. Two weeks is a sane default.
GIFT_WRAP_EXPIRATION_SECONDS = 14 * 86400


def _random_past_timestamp(max_days: int = GIFT_WRAP_BACKDATE_MAX_DAYS) -> int:
    """Return a Unix timestamp randomized within the past ``max_days`` days."""
    now = int(time.time())
    offset = random.randint(0, max_days * 86400)
    return now - offset


def create_gift_wrap(rumor: dict, recipient_pubkey_hex: str,
                     sender_nsec: str) -> dict:
    """Create a NIP-17 gift-wrapped event (kind 1059).

    Steps (per NIP-17/NIP-59):
    1. NIP-44 encrypt the rumor to recipient using sender's key → sealed content
    2. Create seal (kind 13) event with encrypted content, signed by sender
    3. Generate ephemeral keypair
    4. NIP-44 encrypt the seal to recipient using ephemeral key → gift-wrap content
    5. Create gift-wrap (kind 1059) event signed with ephemeral key

    Args:
        rumor: The inner rumor dict {kind, content, tags}
        recipient_pubkey_hex: Recipient's hex pubkey
        sender_nsec: Sender's nsec (bech32)

    Returns:
        Signed kind 1059 event dict ready to publish
    """
    sender_signer = EventSigner(sender_nsec)
    sender_privkey_hex = sender_signer._privkey_hex

    # Step 1: NIP-44 encrypt the rumor to recipient
    encrypted_rumor = nip44_encrypt(
        json.dumps(rumor),
        sender_privkey_hex,
        recipient_pubkey_hex,
    )

    # Step 2: Create seal (kind 13) with encrypted content, signed by sender.
    # NIP-59: backdate the seal's created_at up to 2 days (privacy).
    seal = sender_signer.sign_event(
        kind=13,
        content=encrypted_rumor,
        tags=[],
        created_at=_random_past_timestamp(),
    )

    # Step 3: Generate ephemeral keypair
    ephemeral_key = PrivateKey()
    ephemeral_privkey_hex = ephemeral_key.hex()

    # Step 4: NIP-44 encrypt the seal to recipient using ephemeral key
    encrypted_seal = nip44_encrypt(
        json.dumps(seal),
        ephemeral_privkey_hex,
        recipient_pubkey_hex,
    )

    # Step 5: Create gift-wrap (kind 1059) signed with ephemeral key.
    # NIP-59: backdate the created_at. NIP-40: add an expiration tag so
    # relays prune the wrap after delivery and clients honor disappearing DMs.
    gw_tags = [
        ["p", recipient_pubkey_hex],
        ["expiration", str(int(time.time()) + GIFT_WRAP_EXPIRATION_SECONDS)],
    ]
    ephemeral_signer = EventSigner(ephemeral_key.bech32())
    gift_wrap = ephemeral_signer.sign_event(
        kind=1059,
        content=encrypted_seal,
        tags=gw_tags,
        created_at=_random_past_timestamp(),
    )

    return gift_wrap


def create_jumble_gift_wrap(rumor: dict, recipient_main_pubkey_hex: str,
                             recipient_encryption_pubkey_hex: str,
                             sender_nsec: str,
                             sender_encryption_privkey_hex: str) -> dict:
    """Create a gift wrap in Jumble's non-standard encryption-keypair format.

    Differs from standard NIP-17 ``create_gift_wrap`` in three ways, all
    matching Jumble's wire format (verified against jumble.social v26.7.1):

    1. The seal's NIP-44 payload is encrypted to the recipient's
       **encryption** pubkey (from their kind 10044), not the main pubkey.
    2. The seal carries an ``n`` tag with the sender's encryption pubkey and
       is signed by the sender's identity key.
    3. The gift wrap carries **two** p-tags (encryption + main) and its
       NIP-44 payload is encrypted to the encryption pubkey.
    """
    sender_signer = EventSigner(sender_nsec)
    sender_enc_pubkey = PrivateKey(
        bytes.fromhex(sender_encryption_privkey_hex)
    ).public_key.hex()

    # Step 1: encrypt the rumor to the recipient's ENCRYPTION pubkey using
    # the sender's ENCRYPTION privkey (not the identity key).
    encrypted_rumor = nip44_encrypt(
        json.dumps(rumor),
        sender_encryption_privkey_hex,
        recipient_encryption_pubkey_hex,
    )

    # Step 2: seal signed by identity, carrying the sender's encryption pubkey.
    seal = sender_signer.sign_event(
        kind=13,
        content=encrypted_rumor,
        tags=[["n", sender_enc_pubkey]],
        created_at=_random_past_timestamp(),
    )

    # Step 3-4: ephemeral key, encrypt seal to recipient's ENCRYPTION pubkey.
    ephemeral_key = PrivateKey()
    encrypted_seal = nip44_encrypt(
        json.dumps(seal),
        ephemeral_key.hex(),
        recipient_encryption_pubkey_hex,
    )

    # Step 5: gift wrap with dual p-tags (encryption + main), backdated,
    # with expiration — encrypted to the encryption pubkey.
    gw_tags = [
        ["p", recipient_encryption_pubkey_hex],
        ["p", recipient_main_pubkey_hex],
        ["expiration", str(int(time.time()) + GIFT_WRAP_EXPIRATION_SECONDS)],
    ]
    ephemeral_signer = EventSigner(ephemeral_key.bech32())
    gift_wrap = ephemeral_signer.sign_event(
        kind=1059,
        content=encrypted_seal,
        tags=gw_tags,
        created_at=_random_past_timestamp(),
    )
    return gift_wrap


def unwrap_gift_wrap(gift_event: dict, recipient_nsec: str,
                     extra_privkeys: Optional[list] = None) -> Optional[tuple]:
    """Unwrap a NIP-17 gift-wrapped event (kind 1059).

    Steps:
    1. Verify event is kind 1059 with p tag matching our pubkey
    2. NIP-44 decrypt content → seal JSON (using ephemeral pubkey)
    3. Parse seal (kind 13)
    4. Verify seal signature
    5. NIP-44 decrypt seal content → rumor JSON
    6. Parse rumor
    7. Return (rumor, seal_pubkey)

    Args:
        gift_event: The kind 1059 gift-wrap event
        recipient_nsec: Our nsec (bech32)
        extra_privkeys: Additional recipient privkeys to try for the outer
            decrypt — used for Jumble's encryption-keypair scheme where the
            gift wrap is encrypted to a separate encryption pubkey, not the
            main identity key. The main key is tried first.

    Returns:
        Tuple of (rumor_dict, seal_pubkey_hex) or None if decryption fails
    """
    if gift_event.get("kind") != 1059:
        return None

    recipient_privkey = PrivateKey.from_nsec(recipient_nsec)
    recipient_privkey_hex = recipient_privkey.hex()
    recipient_pubkey = recipient_privkey.public_key.hex()

    # Check p tag matches our pubkey (main or any extra-derived pubkey).
    candidate_privkeys = [recipient_privkey_hex]
    if extra_privkeys:
        candidate_privkeys.extend(extra_privkeys)
    candidate_pubkeys = {
        PrivateKey(bytes.fromhex(pk)).public_key.hex()
        for pk in candidate_privkeys
    }
    p_tags = [t for t in gift_event.get("tags", [])
              if isinstance(t, list) and len(t) >= 2 and t[0] == "p"]
    if not any(t[1] in candidate_pubkeys for t in p_tags):
        return None

    sender_pubkey = gift_event.get("pubkey", "")
    if not sender_pubkey:
        return None

    # Step 2: NIP-44 decrypt the seal. Try each candidate privkey (main first,
    # then extras for the Jumble encryption-keypair case). Remember which one
    # worked — the inner layer uses the same recipient key.
    seal_json = None
    working_privkey_hex = None
    for pk_hex in candidate_privkeys:
        try:
            seal_json = nip44_decrypt(
                gift_event.get("content", ""), pk_hex, sender_pubkey,
            )
            working_privkey_hex = pk_hex
            break
        except Exception:
            continue
    if seal_json is None:
        logger.debug("Gift-wrap seal decryption failed for all candidate keys")
        return None

    # Step 3: Parse the seal
    try:
        seal = json.loads(seal_json)
    except json.JSONDecodeError:
        return None

    if seal.get("kind") != 13:
        return None

    seal_pubkey = seal.get("pubkey", "")
    if not seal_pubkey:
        return None

    # Step 4: Verify seal signature
    try:
        seal_event = Event.from_dict(seal)
        if not seal_event.verify():
            logger.debug("Seal signature verification failed")
            return None
    except Exception:
        return None

    # Step 5: NIP-44 decrypt the rumor from seal content. The seal's pubkey
    # for the NIP-44 conversation key is: the n-tag value (Jumble encryption
    # pubkey) if present, else seal_pubkey (standard NIP-17 identity).
    n_tag = next((t[1] for t in seal.get("tags", [])
                  if isinstance(t, list) and len(t) >= 2 and t[0] == "n"), None)
    seal_conv_pubkey = n_tag if n_tag else seal_pubkey

    try:
        rumor_json = nip44_decrypt(
            seal.get("content", ""), working_privkey_hex, seal_conv_pubkey,
        )
    except Exception as e:
        logger.debug(f"Rumor decryption failed: {e}")
        return None

    # Step 6: Parse rumor
    try:
        rumor = json.loads(rumor_json)
    except json.JSONDecodeError:
        return None

    return (rumor, seal_pubkey)


# ---------------------------------------------------------------------------
# Jumble kind-10044 encryption-keypair scheme
# ---------------------------------------------------------------------------

# Jumble (jumble.social) uses a non-standard "encryption keypair" layer on top
# of NIP-17/59: each user publishes a kind 10044 event advertising a separate
# encryption pubkey in an `n` tag. Gift-wrap seals and payloads are then
# encrypted to that encryption pubkey (not the main identity pubkey), seals
# carry an `n` tag with the sender's encryption pubkey, and gift wraps carry
# two p-tags (encryption + main). Without this, Jumble fetches our standard
# gift wraps but silently fails to decrypt them.
ENCRYPTION_KEY_KIND = 10044


def generate_encryption_keypair() -> dict:
    """Generate a fresh encryption keypair for the Jumble 10044 scheme.

    Returns ``{"privkey_hex", "pubkey_hex", "nsec"}``. This key is persistent
    (stored by the adapter in ~/.hermes/) so Jumble users who learn it from
    our kind 10044 can keep decrypting across restarts.
    """
    sk = PrivateKey()
    return {
        "privkey_hex": sk.hex(),
        "pubkey_hex": sk.public_key.hex(),
        "nsec": sk.bech32(),
    }


def create_encryption_key_event(encryption_pubkey_hex: str,
                                 signer: EventSigner) -> dict:
    """Sign a kind 10044 event advertising our encryption pubkey.

    Per Jumble's scheme: ``content`` is empty, a single ``n`` tag carries the
    encryption pubkey, and the event is signed by the identity key.
    """
    return signer.sign_event(
        kind=ENCRYPTION_KEY_KIND,
        content="",
        tags=[["n", encryption_pubkey_hex]],
    )


def parse_encryption_pubkey(kind10044_event: dict) -> Optional[str]:
    """Extract the encryption pubkey from a kind 10044 event's ``n`` tag.

    Returns the hex pubkey, or None if the event has no valid ``n`` tag.
    """
    for tag in kind10044_event.get("tags", []):
        if (isinstance(tag, list) and len(tag) >= 2
                and tag[0] == "n" and tag[1]):
            return tag[1]
    return None


def create_dm_rumor(content: str, recipient_pubkey_hex: str,
                    sender_pubkey_hex: str) -> dict:
    """Create a NIP-17 chat message rumor (kind 14 per NIP-17 spec).

    Per NIP-17 the rumor MUST carry the sender's real ``pubkey`` (it is
    not signed, but the recipient verifies ``rumor.pubkey == seal.pubkey``
    to prevent impersonation). ``id`` and ``sig`` are present but empty
    because the rumor is unsigned by design — deniability.

    ``created_at`` is set to the current Unix timestamp so the rumor
    carries a valid time even though it is encrypted inside the seal
    (which has its own timestamp).  Some relays and clients reject or
    deprioritize events with a zero timestamp.
    """
    return {
        "kind": 14,
        "content": content,
        "tags": [["p", recipient_pubkey_hex]],
        "created_at": int(time.time()),
        "id": "",
        "pubkey": sender_pubkey_hex,
        "sig": "",
    }
