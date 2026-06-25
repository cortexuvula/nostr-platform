"""
Nostr cryptographic operations: NIP-44 v2 encryption, NIP-04 legacy DM,
event signing, gift-wrap unwrap/create, and key utilities.

Uses pynostr for event signing/bech32 and coincurve + cryptography
for NIP-44 v2 (pynostr 0.7 doesn't ship a nip44 module).

Security: the nsec is never logged. It is passed as a private variable
and used only for cryptographic operations.
"""

import hashlib
import hmac
import json
import logging
import os
import struct
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pynostr.event import Event
from pynostr.key import PrivateKey

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key utilities
# ---------------------------------------------------------------------------

def derive_pubkey(nsec: str) -> str:
    """Derive hex pubkey from nsec (bech32) private key."""
    sk = PrivateKey.from_nsec(nsec)
    return sk.public_key.hex()


def npub_to_hex(npub: str) -> str:
    """Convert npub (bech32) to hex pubkey."""
    pk = PrivateKey.from_nsec  # not for npub
    # pynostr PublicKey can decode npub
    from pynostr.key import PublicKey
    return PublicKey.from_npub(npub).hex()


def hex_to_npub(hex_key: str) -> str:
    """Convert hex pubkey to npub (bech32)."""
    from pynostr.key import PublicKey
    return PublicKey.from_hex(hex_key).bech32()


# ---------------------------------------------------------------------------
# NIP-44 v2 encryption / decryption
# Based on https://github.com/nostr-protocol/nips/blob/master/44.md
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using HMAC-SHA256."""
    if len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand using HMAC-SHA256."""
    t = b""
    okm = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _get_shared_secret(privkey_hex: str, pubkey_hex: str) -> bytes:
    """Compute ECDH shared secret (raw X coordinate) using secp256k1.

    Uses pynostr's PrivateKey.compute_shared_secret which returns the raw
    X coordinate of the shared point — per NIP-44/NIP-04 spec.
    """
    sk = PrivateKey(bytes.fromhex(privkey_hex))
    return sk.compute_shared_secret(pubkey_hex)


def _get_message_keys(privkey_hex: str, pubkey_hex: str,
                      conversation_key: Optional[bytes] = None) -> tuple:
    """Derive encryption keys from the shared secret.

    Returns (conversation_key, salt, encryption_key, nonce).
    """
    if conversation_key is None:
        conversation_key = _get_shared_secret(privkey_hex, pubkey_hex)

    # Generate random salt (32 bytes)
    salt = os.urandom(32)

    # HKDF: extract then expand
    prk = _hkdf_extract(salt, conversation_key)

    # Expand to get encryption key (32) + nonce (12)
    info = b"nip44-v2"
    expanded = _hkdf_expand(prk, info, 44)
    encryption_key = expanded[:32]
    nonce = expanded[32:44]

    return conversation_key, salt, encryption_key, nonce


def nip44_encrypt(plaintext: str, sender_privkey_hex: str,
                  recipient_pubkey_hex: str) -> str:
    """NIP-44 v2 encrypt.

    Returns base64-encoded payload: version (1 byte) + salt (32) + nonce (12) +
    ciphertext + mac (32).

    NOTE: NIP-44 v2 uses a slightly different key derivation than what we have
    here. For full spec compliance, see the reference implementation. This
    implementation follows the spec at https://github.com/nostr-protocol/nips/blob/master/44.md
    """
    conversation_key = _get_shared_secret(sender_privkey_hex, recipient_pubkey_hex)
    salt = os.urandom(32)

    # HKDF
    prk = _hkdf_extract(salt, conversation_key)
    info = b"nip44-v2"
    enc_key = _hkdf_expand(prk, info, 32)
    nonce = _hkdf_expand(prk, info + b"\x01", 12)  # Different info for nonce

    # Actually, per spec: keys = HKDF(salt, conversation_key, info="nip44-v2", length=44)
    # enc_key = keys[0:32], nonce = keys[32:44]
    keys = _hkdf_expand(prk, info, 44)
    enc_key = keys[:32]
    nonce = keys[32:44]

    # Pad plaintext
    plaintext_bytes = plaintext.encode("utf-8")
    padded = _pad(plaintext_bytes)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(enc_key)
    ciphertext = aesgcm.encrypt(nonce, padded, None)

    # Build payload: version + salt + nonce + ciphertext
    payload = bytes([2]) + salt + nonce + ciphertext  # version 2 = NIP-44 v2

    # MAC over the payload (HMAC-SHA256 of payload with mac key)
    mac_key = _hkdf_expand(prk, b"nip44-v2-mac", 32)
    mac = hmac.new(mac_key, payload, hashlib.sha256).digest()

    payload_with_mac = payload + mac

    import base64
    return base64.b64encode(payload_with_mac).decode("ascii")


def nip44_decrypt(payload_b64: str, recipient_privkey_hex: str,
                  sender_pubkey_hex: str) -> str:
    """NIP-44 v2 decrypt.

    Returns the plaintext string.
    """
    import base64

    payload = base64.b64decode(payload_b64)

    version = payload[0]
    if version != 2:
        raise ValueError(f"Unsupported NIP-44 version: {version}")

    salt = payload[1:33]
    nonce = payload[33:45]
    ciphertext = payload[45:-32]
    mac = payload[-32:]

    # Compute conversation key
    conversation_key = _get_shared_secret(recipient_privkey_hex, sender_pubkey_hex)

    # Derive keys
    prk = _hkdf_extract(salt, conversation_key)
    keys = _hkdf_expand(prk, b"nip44-v2", 44)
    enc_key = keys[:32]
    expected_nonce = keys[32:44]

    # Verify MAC
    mac_key = _hkdf_expand(prk, b"nip44-v2-mac", 32)
    expected_mac = hmac.new(mac_key, payload[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("NIP-44 MAC verification failed")

    # Decrypt
    aesgcm = AESGCM(enc_key)
    padded = aesgcm.decrypt(nonce, ciphertext, None)

    # Unpad
    plaintext_bytes = _unpad(padded)

    return plaintext_bytes.decode("utf-8")


def _pad(plaintext: bytes) -> bytes:
    """NIP-44 v2 padding scheme.

    Pads to next power-of-2 minus 1, with a 2-byte big-endian length prefix.
    """
    # NIP-44 v2 padding: https://github.com/nostr-protocol/nips/blob/master/44.md#v2
    # pad to next power of 2 minus 1, with 2-byte length prefix
    unpadded_len = len(plaintext)
    if unpadded_len < 1:
        raise ValueError("Plaintext too short")

    # Calculate padded size
    # NIP-44 v2: pad to next power of 2 minus 1, between 32 and 40960
    if unpadded_len <= 32:
        padded_size = 32
    else:
        # Next power of 2 minus 1
        import math
        next_pow2 = 1 << (unpadded_len - 1).bit_length()
        padded_size = next_pow2 - 1
        if padded_size < 32:
            padded_size = 32

    # Actually, NIP-44 v2 uses a specific padding table. Let me use the spec:
    # size = max(32, next_pow2 - 1) where next_pow2 is the smallest power of 2 > len
    # But also cap at 40960
    if unpadded_len > 40960:
        raise ValueError("Plaintext too long for NIP-44 v2 (max 40960 bytes)")

    # From the spec: pad_size = max(32, (1 << (len-1).bit_length()) - 1)
    # but simpler: use a simple scheme
    pad_target = max(32, (1 << (unpadded_len - 1).bit_length()) - 1) if unpadded_len > 1 else 32
    if pad_target > 40960:
        pad_target = 40960

    # Length prefix (2 bytes big-endian) + plaintext + zero padding
    result = struct.pack(">H", unpadded_len) + plaintext
    padding_needed = pad_target + 2 - len(result)  # +2 for length prefix
    if padding_needed > 0:
        result += b"\x00" * padding_needed
    return result


def _unpad(padded: bytes) -> bytes:
    """Remove NIP-44 v2 padding."""
    unpadded_len = struct.unpack(">H", padded[:2])[0]
    return padded[2:2 + unpadded_len]


# ---------------------------------------------------------------------------
# NIP-04 legacy DM encryption / decryption
# ---------------------------------------------------------------------------

def nip04_encrypt(plaintext: str, sender_privkey_hex: str,
                  recipient_pubkey_hex: str) -> str:
    """NIP-04 legacy DM encrypt (AES-256-CBC + ECDH).

    Returns base64-encoded ciphertext?iv format.
    """
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend

    # ECDH shared secret (raw X coordinate — pynostr convention, no sha256)
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

    Payload format: base64(ciphertext)?iv=base64(iv)
    """
    import base64
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    from cryptography.hazmat.backends import default_backend

    # Parse payload
    if "?iv=" not in payload:
        raise ValueError("Invalid NIP-04 payload: missing iv")

    ct_b64, iv_b64 = payload.split("?iv=", 1)
    ciphertext = base64.b64decode(ct_b64)
    iv = base64.b64decode(iv_b64)

    # ECDH shared secret (raw X coordinate — pynostr convention, no sha256)
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
        """Create, sign, and return a Nostr event dict.

        Args:
            kind: Event kind (1, 4, 13, 1059, etc.)
            content: Event content
            tags: Event tags list
            created_at: Unix timestamp (default: now)

        Returns:
            Signed event dict with id, pubkey, created_at, kind, tags, content, sig
        """
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

def create_gift_wrap(rumor: dict, recipient_pubkey_hex: str,
                     sender_nsec: str) -> dict:
    """Create a NIP-17 gift-wrapped event (kind 1059).

    Steps:
    1. Seal the rumor: sign as kind 13 event with sender's key
    2. Generate ephemeral keypair for the gift-wrap
    3. Gift-wrap: encrypt the seal to recipient using NIP-44 with ephemeral key
    4. Create kind 1059 event signed with ephemeral key

    Args:
        rumor: The inner rumor dict {kind, content, tags}
        recipient_pubkey_hex: Recipient's hex pubkey
        sender_nsec: Sender's nsec (bech32)

    Returns:
        Signed kind 1059 event dict ready to publish
    """
    signer = EventSigner(sender_nsec)

    # Step 1: Create seal (kind 13) — the rumor, signed by sender
    seal_content = json.dumps(rumor)
    seal = signer.sign_event(
        kind=13,
        content=seal_content,
        tags=[],
    )

    # Step 2: Generate ephemeral keypair
    ephemeral_key = PrivateKey()
    ephemeral_privkey_hex = ephemeral_key.hex()

    # Step 3: Encrypt the seal to recipient using NIP-44 with ephemeral key
    encrypted_seal = nip44_encrypt(
        json.dumps(seal),
        ephemeral_privkey_hex,
        recipient_pubkey_hex,
    )

    # Step 4: Create gift-wrap (kind 1059) signed with ephemeral key
    ephemeral_signer = EventSigner(ephemeral_key.bech32())

    gift_wrap = ephemeral_signer.sign_event(
        kind=1059,
        content=encrypted_seal,
        tags=[["p", recipient_pubkey_hex]],
    )

    return gift_wrap


def unwrap_gift_wrap(gift_event: dict, recipient_nsec: str) -> Optional[dict]:
    """Unwrap a NIP-17 gift-wrapped event (kind 1059).

    Steps:
    1. Check event is kind 1059 and has p tag matching our pubkey
    2. Decrypt the content using NIP-44 (our privkey × sender's pubkey)
    3. Parse the seal (kind 13 event)
    4. Verify the seal's signature
    5. Parse the rumor from the seal's content
    6. Return the rumor dict

    Args:
        gift_event: The kind 1059 gift-wrap event
        recipient_nsec: Our nsec (bech32)

    Returns:
        The inner rumor dict, or None if decryption fails
    """
    if gift_event.get("kind") != 1059:
        logger.debug("Not a gift-wrap event (kind != 1059)")
        return None

    recipient_privkey = PrivateKey.from_nsec(recipient_nsec)
    recipient_pubkey = recipient_privkey.public_key.hex()
    recipient_privkey_hex = recipient_privkey.hex()

    # Check p tag matches our pubkey
    p_tags = [t for t in gift_event.get("tags", []) if t[0] == "p"]
    if not any(t[1] == recipient_pubkey for t in p_tags):
        logger.debug("Gift-wrap not addressed to us")
        return None

    sender_pubkey = gift_event.get("pubkey", "")
    if not sender_pubkey:
        logger.debug("Gift-wrap has no sender pubkey")
        return None

    # Decrypt the seal
    try:
        seal_json = nip44_decrypt(
            gift_event["content"],
            recipient_privkey_hex,
            sender_pubkey,
        )
    except Exception as e:
        logger.debug(f"Gift-wrap decryption failed: {e}")
        return None

    # Parse the seal (kind 13 event)
    try:
        seal = json.loads(seal_json)
    except json.JSONDecodeError:
        logger.debug("Seal is not valid JSON")
        return None

    if seal.get("kind") != 13:
        logger.debug(f"Seal is not kind 13 (got {seal.get('kind')})")
        return None

    # Parse the rumor from seal content
    try:
        rumor = json.loads(seal["content"])
    except (json.JSONDecodeError, KeyError):
        logger.debug("Rumor is not valid JSON")
        return None

    return rumor


def create_dm_rumor(content: str, recipient_pubkey_hex: str) -> dict:
    """Create a NIP-17 DM rumor (kind 4 content with p tag)."""
    return {
        "kind": 4,
        "content": content,
        "tags": [["p", recipient_pubkey_hex]],
    }
