"""
Tests for Nostr crypto module — NIP-04, event signing, gift-wrap round-trip.
"""

import json
import time
import pytest
from pynostr.key import PrivateKey, PublicKey

from plugins.platforms.nostr.crypto import (
    EventSigner,
    derive_pubkey,
    npub_to_hex,
    hex_to_npub,
    nip04_encrypt,
    nip04_decrypt,
    create_gift_wrap,
    unwrap_gift_wrap,
    create_dm_rumor,
)


@pytest.fixture
def keypair_a():
    """Generate keypair A."""
    sk = PrivateKey()
    return {
        "nsec": sk.bech32(),
        "hex": sk.hex(),
        "pubkey": sk.public_key.hex(),
        "npub": sk.public_key.bech32(),
    }


@pytest.fixture
def keypair_b():
    """Generate keypair B."""
    sk = PrivateKey()
    return {
        "nsec": sk.bech32(),
        "hex": sk.hex(),
        "pubkey": sk.public_key.hex(),
        "npub": sk.public_key.bech32(),
    }


class TestKeyUtilities:
    """Test key conversion utilities."""

    def test_derive_pubkey(self, keypair_a):
        """derive_pubkey should return correct hex pubkey."""
        pubkey = derive_pubkey(keypair_a["nsec"])
        assert pubkey == keypair_a["pubkey"]
        assert len(pubkey) == 64

    def test_npub_to_hex_roundtrip(self, keypair_a):
        """npub → hex → npub should be identity."""
        hex_key = npub_to_hex(keypair_a["npub"])
        assert hex_key == keypair_a["pubkey"]
        npub_again = hex_to_npub(hex_key)
        assert npub_again == keypair_a["npub"]


class TestEventSigning:
    """Test event signing and verification."""

    def test_sign_and_verify(self, keypair_a):
        """Signed event must verify."""
        signer = EventSigner(keypair_a["nsec"])
        event = signer.sign_event(
            kind=1,
            content="Hello Nostr!",
            tags=[["t", "test"]],
        )
        assert event["pubkey"] == keypair_a["pubkey"]
        assert event["id"]
        assert event["sig"]
        assert signer.verify_event(event)

    def test_verify_tampered_event(self, keypair_a):
        """Tampered event must fail verification."""
        signer = EventSigner(keypair_a["nsec"])
        event = signer.sign_event(kind=1, content="original")
        event["content"] = "tampered"
        assert not signer.verify_event(event)

    def test_signer_pubkey_matches(self, keypair_a):
        """EventSigner pubkey should match the nsec."""
        signer = EventSigner(keypair_a["nsec"])
        assert signer.pubkey == keypair_a["pubkey"]


class TestNIP04:
    """Test NIP-04 legacy DM encryption."""

    def test_encrypt_decrypt_roundtrip(self, keypair_a, keypair_b):
        """NIP-04 encrypt then decrypt — content must match."""
        message = "Hello from A to B!"
        ciphertext = nip04_encrypt(
            message,
            keypair_a["hex"],
            keypair_b["pubkey"],
        )
        plaintext = nip04_decrypt(
            ciphertext,
            keypair_b["hex"],
            keypair_a["pubkey"],
        )
        assert plaintext == message

    def test_decrypt_with_wrong_key_fails(self, keypair_a, keypair_b):
        """Decrypting with wrong key should fail."""
        sk_c = PrivateKey()
        message = "secret"
        ciphertext = nip04_encrypt(
            message, keypair_a["hex"], keypair_b["pubkey"]
        )
        with pytest.raises(Exception):
            nip04_decrypt(
                ciphertext, sk_c.hex(), keypair_a["pubkey"]
            )

    def test_unicode_message(self, keypair_a, keypair_b):
        """Unicode messages should roundtrip correctly."""
        message = "こんにちは🌍"
        ciphertext = nip04_encrypt(
            message, keypair_a["hex"], keypair_b["pubkey"]
        )
        plaintext = nip04_decrypt(
            ciphertext, keypair_b["hex"], keypair_a["pubkey"]
        )
        assert plaintext == message

    def test_empty_message_roundtrip(self, keypair_a, keypair_b):
        """Empty string should roundtrip (PKCS7 still adds a full block)."""
        ciphertext = nip04_encrypt("", keypair_a["hex"], keypair_b["pubkey"])
        plaintext = nip04_decrypt(
            ciphertext, keypair_b["hex"], keypair_a["pubkey"]
        )
        assert plaintext == ""

    def test_large_message_roundtrip(self, keypair_a, keypair_b):
        """A message spanning many AES blocks should roundtrip."""
        message = "x" * 100_000
        ciphertext = nip04_encrypt(
            message, keypair_a["hex"], keypair_b["pubkey"]
        )
        plaintext = nip04_decrypt(
            ciphertext, keypair_b["hex"], keypair_a["pubkey"]
        )
        assert plaintext == message

    def test_decrypt_rejects_malformed_payload(self, keypair_a):
        """Malformed payloads raise ValueError, not a confusing AES error."""
        from plugins.platforms.nostr.crypto import nip04_decrypt
        # Missing iv separator.
        with pytest.raises(ValueError, match="missing iv"):
            nip04_decrypt("justbase64", keypair_a["hex"], keypair_a["pubkey"])
        # Non-canonical base64 (whitespace inside).
        with pytest.raises(ValueError, match="bad base64"):
            nip04_decrypt("!! not b64 !!?iv=AAAAAAAAAAAAAAAAAAAAAA==", keypair_a["hex"], keypair_a["pubkey"])
        # Wrong IV length (8 bytes instead of 16).
        import base64 as _b64
        bad_iv = _b64.b64encode(b"12345678").decode()
        with pytest.raises(ValueError, match="iv length"):
            nip04_decrypt("AAAA?iv=" + bad_iv, keypair_a["hex"], keypair_a["pubkey"])


class TestNIP04Interop:
    """Cross-implementation interop against pynostr's reference encrypt/decrypt.

    These tests guard against silent interop regressions: our encrypt must be
    readable by the canonical pynostr client and vice versa. A self-roundtrip
    test cannot catch these — both sides must agree on the wire format.
    """

    def test_ours_encrypt_pynostr_decrypt(self, keypair_a, keypair_b):
        """Our ciphertext must decrypt with pynostr's PrivateKey.decrypt_message."""
        from pynostr.key import PrivateKey
        message = "cross-impl interop"
        ciphertext = nip04_encrypt(message, keypair_a["hex"], keypair_b["pubkey"])
        bob = PrivateKey(bytes.fromhex(keypair_b["hex"]))
        plaintext = bob.decrypt_message(ciphertext, keypair_a["pubkey"])
        assert plaintext == message

    def test_pynostr_encrypt_ours_decrypt(self, keypair_a, keypair_b):
        """pynostr's ciphertext must decrypt with our nip04_decrypt."""
        from pynostr.key import PrivateKey
        message = "cross-impl interop"
        alice = PrivateKey(bytes.fromhex(keypair_a["hex"]))
        ciphertext = alice.encrypt_message(message, keypair_b["pubkey"])
        plaintext = nip04_decrypt(ciphertext, keypair_b["hex"], keypair_a["pubkey"])
        assert plaintext == message

    def test_interop_unicode_and_empty(self, keypair_a, keypair_b):
        """Interop holds for unicode and empty messages, not just ASCII."""
        from pynostr.key import PrivateKey
        for message in ["こんにちは🌍", "", "x" * 4096]:
            ciphertext = nip04_encrypt(message, keypair_a["hex"], keypair_b["pubkey"])
            bob = PrivateKey(bytes.fromhex(keypair_b["hex"]))
            assert bob.decrypt_message(ciphertext, keypair_a["pubkey"]) == message

    def test_each_encryption_has_unique_iv(self, keypair_a, keypair_b):
        """Two encryptions of the same plaintext must differ (random IV)."""
        c1 = nip04_encrypt("msg", keypair_a["hex"], keypair_b["pubkey"])
        c2 = nip04_encrypt("msg", keypair_a["hex"], keypair_b["pubkey"])
        assert c1 != c2, "IV must be random — identical ciphertexts imply IV reuse"


class TestGiftWrap:
    """Test NIP-17 gift-wrap create/unwrap."""

    def test_rumor_has_required_fields(self, keypair_a, keypair_b):
        """NIP-17: the kind-14 rumor must carry id, pubkey (sender's), sig.

        Strict clients verify ``rumor.pubkey == seal.pubkey`` to prevent
        impersonation, so the sender's real pubkey must be present.
        """
        rumor = create_dm_rumor("hello", keypair_b["pubkey"], keypair_a["pubkey"])
        assert rumor["kind"] == 14
        assert rumor["content"] == "hello"
        assert rumor["id"] == ""
        assert rumor["pubkey"] == keypair_a["pubkey"]
        assert rumor["sig"] == ""
        assert rumor["created_at"] > 0
        # recipient p-tag present
        p_tags = [t for t in rumor["tags"] if t[0] == "p"]
        assert any(t[1] == keypair_b["pubkey"] for t in p_tags)

    def test_gift_wrap_roundtrip(self, keypair_a, keypair_b):
        """Gift-wrap then unwrap — rumor content must match."""
        original_content = "Encrypted DM via NIP-17!"
        rumor = create_dm_rumor(original_content, keypair_b["pubkey"],
                                keypair_a["pubkey"])
        gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                       keypair_a["nsec"])

        assert gift_event["kind"] == 1059
        assert gift_event["pubkey"]  # ephemeral key

        # Unwrap as recipient B
        result = unwrap_gift_wrap(gift_event, keypair_b["nsec"])
        assert result is not None
        unwrapped, seal_pubkey = result
        assert unwrapped["content"] == original_content
        assert unwrapped["kind"] == 14  # NIP-17 chat message
        assert seal_pubkey == keypair_a["pubkey"]  # sender's pubkey
        assert unwrapped["pubkey"] == keypair_a["pubkey"]  # sender's pubkey

    def test_unwrap_wrong_recipient_fails(self, keypair_a, keypair_b):
        """Unwrapping with wrong nsec should return None."""
        sk_c = PrivateKey()
        rumor = create_dm_rumor("test", keypair_b["pubkey"], keypair_a["pubkey"])
        gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                       keypair_a["nsec"])

        # Try to unwrap as C (not the recipient)
        unwrapped = unwrap_gift_wrap(gift_event, sk_c.bech32())
        assert unwrapped is None

    def test_gift_wrap_has_correct_tags(self, keypair_a, keypair_b):
        """Gift-wrap should have p tag with recipient pubkey."""
        rumor = create_dm_rumor("test", keypair_b["pubkey"], keypair_a["pubkey"])
        gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                       keypair_a["nsec"])

        p_tags = [t for t in gift_event["tags"] if t[0] == "p"]
        assert len(p_tags) >= 1
        assert p_tags[0][1] == keypair_b["pubkey"]

    def test_gift_wrap_created_at_is_backdated(self, keypair_a, keypair_b):
        """NIP-59: gift wrap created_at must be randomized up to 2 days in the
        past (privacy). A real-time timestamp leaks send time and breaks
        Nostur's subscription cursor logic.

        Over several wraps the timestamps must (a) all fall within the
        [now-2d, now] window and (b) vary — proving random backdating rather
        than always emitting the current time.
        """
        now = int(time.time())
        timestamps = []
        for _ in range(10):
            rumor = create_dm_rumor("x", keypair_b["pubkey"], keypair_a["pubkey"])
            gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                           keypair_a["nsec"])
            ts = gift_event["created_at"]
            assert now - 172800 <= ts <= now, (
                f"gift wrap created_at {ts} outside [now-2d, now] (now={now})"
            )
            timestamps.append(ts)
        # Variation proves the timestamp is randomized, not always == now.
        assert len(set(timestamps)) > 1, (
            "gift wrap created_at never varied across 10 wraps — not randomized"
        )

    def test_gift_wrap_has_expiration_tag(self, keypair_a, keypair_b):
        """NIP-40 expiration tag on the gift wrap — relays prune old 1059s and
        Nostur/Amethyst honor it. Must point to the future.
        """
        rumor = create_dm_rumor("test", keypair_b["pubkey"], keypair_a["pubkey"])
        gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                       keypair_a["nsec"])
        now = int(time.time())
        exp_tags = [t for t in gift_event["tags"] if t[0] == "expiration"]
        assert len(exp_tags) == 1, f"expected 1 expiration tag, got {len(exp_tags)}"
        exp_ts = int(exp_tags[0][1])
        assert exp_ts > now, f"expiration {exp_ts} not in the future (now={now})"

    def test_seal_created_at_is_backdated(self, keypair_a, keypair_b):
        """NIP-59: the seal (kind 13) created_at must also be backdated."""
        from plugins.platforms.nostr.crypto import nip44_decrypt
        from pynostr.key import PrivateKey

        now = int(time.time())
        timestamps = []
        for _ in range(10):
            rumor = create_dm_rumor("x", keypair_b["pubkey"], keypair_a["pubkey"])
            gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                           keypair_a["nsec"])

            # Decrypt the outer gift-wrap layer to recover the seal JSON.
            recipient_priv = PrivateKey.from_nsec(keypair_b["nsec"]).hex()
            sender_gw_pubkey = gift_event["pubkey"]
            seal_json = nip44_decrypt(gift_event["content"], recipient_priv,
                                       sender_gw_pubkey)
            seal = json.loads(seal_json)
            seal_ts = seal["created_at"]
            assert now - 172800 <= seal_ts <= now, (
                f"seal created_at {seal_ts} outside [now-2d, now] (now={now})"
            )
            timestamps.append(seal_ts)
        assert len(set(timestamps)) > 1, (
            "seal created_at never varied across 10 wraps — not randomized"
        )


class TestEncryptionKey:
    """Test Jumble kind-10044 encryption-keypair helpers."""

    def test_generate_encryption_keypair_shape(self):
        """generate_encryption_keypair returns privkey_hex, pubkey_hex, nsec."""
        from plugins.platforms.nostr.crypto import generate_encryption_keypair
        kp = generate_encryption_keypair()
        assert len(kp["privkey_hex"]) == 64
        assert len(kp["pubkey_hex"]) == 64
        assert kp["nsec"].startswith("nsec1")
        # pubkey must derive from privkey
        from pynostr.key import PrivateKey
        assert PrivateKey(bytes.fromhex(kp["privkey_hex"])).public_key.hex() == kp["pubkey_hex"]

    def test_create_encryption_key_event_shape(self, keypair_a):
        """create_encryption_key_event produces kind 10044 with empty content
        and a single n-tag carrying the encryption pubkey."""
        from plugins.platforms.nostr.crypto import (
            create_encryption_key_event, generate_encryption_keypair, EventSigner,
        )
        enc_kp = generate_encryption_keypair()
        signer = EventSigner(keypair_a["nsec"])
        event = create_encryption_key_event(enc_kp["pubkey_hex"], signer)
        assert event["kind"] == 10044
        assert event["content"] == ""
        assert event["pubkey"] == keypair_a["pubkey"]  # signed by identity
        n_tags = [t for t in event["tags"] if t[0] == "n"]
        assert len(n_tags) == 1
        assert n_tags[0][1] == enc_kp["pubkey_hex"]
        assert event["sig"]  # signed

    def test_parse_encryption_pubkey_extracts_n_tag(self):
        """parse_encryption_pubkey extracts the n-tag from a 10044 event."""
        from plugins.platforms.nostr.crypto import parse_encryption_pubkey
        event = {"kind": 10044, "tags": [["n", "abc123pubkey"]]}
        assert parse_encryption_pubkey(event) == "abc123pubkey"

    def test_parse_encryption_pubkey_returns_none_without_n_tag(self):
        """parse_encryption_pubkey returns None if no n-tag."""
        from plugins.platforms.nostr.crypto import parse_encryption_pubkey
        assert parse_encryption_pubkey({"kind": 10044, "tags": []}) is None
        assert parse_encryption_pubkey({"kind": 10044, "tags": [["x", "y"]]}) is None


class TestJumbleGiftWrap:
    """Test create_jumble_gift_wrap — Jumble's non-standard NIP-17 variant."""

    def test_jumble_gift_wrap_has_dual_p_tags(self, keypair_a, keypair_b):
        """Gift wrap must carry TWO p-tags: encryption pubkey + main pubkey."""
        from plugins.platforms.nostr.crypto import (
            create_jumble_gift_wrap, create_dm_rumor,
            generate_encryption_keypair,
        )
        sender_enc = generate_encryption_keypair()
        recip_enc = generate_encryption_keypair()
        rumor = create_dm_rumor("hi", keypair_b["pubkey"], keypair_a["pubkey"])
        gw = create_jumble_gift_wrap(
            rumor, keypair_b["pubkey"], recip_enc["pubkey_hex"],
            keypair_a["nsec"], sender_enc["privkey_hex"],
        )
        p_values = [t[1] for t in gw["tags"] if t[0] == "p"]
        assert recip_enc["pubkey_hex"] in p_values
        assert keypair_b["pubkey"] in p_values
        assert len(p_values) == 2

    def test_jumble_gift_wrap_seal_has_n_tag(self, keypair_a, keypair_b):
        """The seal must carry an n-tag with the sender's encryption pubkey."""
        from plugins.platforms.nostr.crypto import (
            create_jumble_gift_wrap, create_dm_rumor, generate_encryption_keypair,
            nip44_decrypt,
        )
        sender_enc = generate_encryption_keypair()
        recip_enc = generate_encryption_keypair()
        rumor = create_dm_rumor("hi", keypair_b["pubkey"], keypair_a["pubkey"])
        gw = create_jumble_gift_wrap(
            rumor, keypair_b["pubkey"], recip_enc["pubkey_hex"],
            keypair_a["nsec"], sender_enc["privkey_hex"],
        )
        # Decrypt gift-wrap layer to get the seal, using recipient's ENC key.
        seal_json = nip44_decrypt(
            gw["content"], recip_enc["privkey_hex"], gw["pubkey"],
        )
        seal = json.loads(seal_json)
        n_tags = [t for t in seal["tags"] if t[0] == "n"]
        assert len(n_tags) == 1
        assert n_tags[0][1] == sender_enc["pubkey_hex"]

    def test_jumble_seal_encrypted_to_encryption_pubkey(self, keypair_a, keypair_b):
        """The seal payload must decrypt with the recipient's ENC privkey, not main."""
        from plugins.platforms.nostr.crypto import (
            create_jumble_gift_wrap, create_dm_rumor, generate_encryption_keypair,
            nip44_decrypt,
        )
        sender_enc = generate_encryption_keypair()
        recip_enc = generate_encryption_keypair()
        rumor = create_dm_rumor("secret", keypair_b["pubkey"], keypair_a["pubkey"])
        gw = create_jumble_gift_wrap(
            rumor, keypair_b["pubkey"], recip_enc["pubkey_hex"],
            keypair_a["nsec"], sender_enc["privkey_hex"],
        )
        # Decrypt gift-wrap layer with recipient ENC key.
        seal_json = nip44_decrypt(
            gw["content"], recip_enc["privkey_hex"], gw["pubkey"],
        )
        seal = json.loads(seal_json)
        # Decrypt seal content with recipient ENC key + sender ENC pubkey.
        rumor_json = nip44_decrypt(
            seal["content"], recip_enc["privkey_hex"], sender_enc["pubkey_hex"],
        )
        unwrapped = json.loads(rumor_json)
        assert unwrapped["content"] == "secret"

    def test_jumble_gift_wrap_roundtrip(self, keypair_a, keypair_b):
        """Full create-as-Jumble-sender → unwrap-as-Jumble-recipient cycle."""
        from plugins.platforms.nostr.crypto import (
            create_jumble_gift_wrap, create_dm_rumor, generate_encryption_keypair,
        )
        sender_enc = generate_encryption_keypair()
        recip_enc = generate_encryption_keypair()
        rumor = create_dm_rumor("roundtrip", keypair_b["pubkey"], keypair_a["pubkey"])
        gw = create_jumble_gift_wrap(
            rumor, keypair_b["pubkey"], recip_enc["pubkey_hex"],
            keypair_a["nsec"], sender_enc["privkey_hex"],
        )
        # Unwrap as recipient using the ENC privkey as an extra key.
        result = unwrap_gift_wrap(
            gw, keypair_b["nsec"],
            extra_privkeys=[recip_enc["privkey_hex"]],
        )
        assert result is not None
        unwrapped, seal_pubkey = result
        assert unwrapped["content"] == "roundtrip"
        assert seal_pubkey == keypair_a["pubkey"]  # identity-signed seal

    def test_jumble_gift_wrap_backdated_and_expiration(self, keypair_a, keypair_b):
        """Jumble gift wraps must also backdate + carry expiration."""
        from plugins.platforms.nostr.crypto import (
            create_jumble_gift_wrap, create_dm_rumor, generate_encryption_keypair,
        )
        sender_enc = generate_encryption_keypair()
        recip_enc = generate_encryption_keypair()
        rumor = create_dm_rumor("x", keypair_b["pubkey"], keypair_a["pubkey"])
        gw = create_jumble_gift_wrap(
            rumor, keypair_b["pubkey"], recip_enc["pubkey_hex"],
            keypair_a["nsec"], sender_enc["privkey_hex"],
        )
        now = int(time.time())
        assert now - 172800 <= gw["created_at"] <= now
        exp_tags = [t for t in gw["tags"] if t[0] == "expiration"]
        assert len(exp_tags) == 1
        assert int(exp_tags[0][1]) > now


class TestErrorBranches:
    """Cover the defensive error branches in crypto.py (padding, HKDF,
    decrypt, unwrap). All pure-logic — no I/O mocking needed."""

    def test_hkdf_extract_empty_salt(self):
        """_hkdf_extract handles empty salt (defaults to 32 zero bytes)."""
        from plugins.platforms.nostr.crypto import _hkdf_extract
        result = _hkdf_extract(b"", b"ikm")
        assert len(result) == 32  # SHA-256 output

    def test_calc_padded_len_small_input(self):
        """_calc_padded_len returns 32 for inputs <= 32."""
        from plugins.platforms.nostr.crypto import _calc_padded_len
        assert _calc_padded_len(1) == 32
        assert _calc_padded_len(32) == 32

    def test_pad_too_short(self):
        """_pad raises on empty plaintext."""
        from plugins.platforms.nostr.crypto import _pad
        with pytest.raises(ValueError, match="too short"):
            _pad(b"")

    def test_pad_too_long(self):
        """_pad raises on plaintext > 65535 bytes."""
        from plugins.platforms.nostr.crypto import _pad
        with pytest.raises(ValueError, match="too long"):
            _pad(b"\x00" * 65536)

    def test_unpad_too_short(self):
        """_unpad raises on padded data < 2 bytes."""
        from plugins.platforms.nostr.crypto import _unpad
        with pytest.raises(ValueError, match="too short"):
            _unpad(b"")

    def test_unpad_invalid_length(self):
        """_unpad raises when declared length is out of range."""
        from plugins.platforms.nostr.crypto import _unpad
        with pytest.raises(ValueError, match="Invalid plaintext length"):
            _unpad(b"\x00\x00")  # declared length 0

    def test_unpad_shorter_than_declared(self):
        """_unpad raises when data is shorter than the declared length."""
        from plugins.platforms.nostr.crypto import _unpad
        with pytest.raises(ValueError, match="shorter than declared"):
            _unpad(b"\x00\x0a" + b"hi")  # declares 10, only 2 bytes

    def test_unpad_nonzero_padding(self):
        """_unpad raises when padding bytes are non-zero."""
        from plugins.platforms.nostr.crypto import _unpad, _calc_padded_len
        import struct
        unpadded_len = 1
        padded_len = _calc_padded_len(unpadded_len)
        # Build: [u16 len=1][1 byte plaintext][padding with a non-zero byte]
        data = struct.pack(">H", unpadded_len) + b"a"
        data += b"\x00" * (padded_len - unpadded_len - 1) + b"\xff"
        with pytest.raises(ValueError, match="non-zero"):
            _unpad(data)

    def test_unpad_wrong_total_size(self):
        """_unpad raises when padded length doesn't match expected size."""
        from plugins.platforms.nostr.crypto import _unpad
        with pytest.raises(ValueError, match="expected size"):
            _unpad(b"\x00\x01" + b"a" + b"\x00" * 5)  # too short for 32

    def test_nip44_decrypt_payload_too_short(self):
        """nip44_decrypt raises on payload < 99 bytes."""
        from plugins.platforms.nostr.crypto import nip44_decrypt
        import base64
        with pytest.raises(ValueError, match="payload length"):
            nip44_decrypt(base64.b64encode(b"short").decode(), "a" * 64, "b" * 64)

    def test_nip44_decrypt_wrong_version(self):
        """nip44_decrypt raises on unsupported version byte."""
        from plugins.platforms.nostr.crypto import nip44_decrypt, MIN_PAYLOAD_SIZE
        import base64
        payload = bytes([0x01]) + b"\x00" * (MIN_PAYLOAD_SIZE - 1)
        with pytest.raises(ValueError, match="version"):
            nip44_decrypt(base64.b64encode(payload).decode(), "a" * 64, "b" * 64)

    def test_verify_event_malformed(self):
        """EventSigner.verify_event returns False on malformed input."""
        from plugins.platforms.nostr.crypto import EventSigner
        from pynostr.key import PrivateKey
        signer = EventSigner(PrivateKey().bech32())
        assert signer.verify_event({}) is False

    def test_unwrap_wrong_kind(self):
        """unwrap_gift_wrap returns None for non-1059 events."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap
        from pynostr.key import PrivateKey
        nsec = PrivateKey().bech32()
        assert unwrap_gift_wrap({"kind": 1}, nsec) is None

    def test_unwrap_not_addressed_to_us(self):
        """unwrap_gift_wrap returns None when no p-tag matches our pubkey."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap
        from pynostr.key import PrivateKey
        sk = PrivateKey()
        other = PrivateKey().public_key.hex()
        event = {"kind": 1059, "pubkey": other,
                 "tags": [["p", other]], "content": ""}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_empty_sender_pubkey(self):
        """unwrap_gift_wrap returns None when sender pubkey is empty."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap
        from pynostr.key import PrivateKey
        sk = PrivateKey()
        event = {"kind": 1059, "pubkey": "",
                 "tags": [["p", sk.public_key.hex()]], "content": ""}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_missing_content_returns_none(self):
        """unwrap_gift_wrap returns None (not KeyError) when the gift wrap
        event is missing the 'content' field — a malformed relay payload."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap
        from pynostr.key import PrivateKey
        sk = PrivateKey()
        sender = PrivateKey()
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]]}  # no "content" key
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_all_keys_fail(self):
        """unwrap_gift_wrap returns None when no candidate key decrypts."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap
        from pynostr.key import PrivateKey
        import base64, os
        sk = PrivateKey()
        sender = PrivateKey()
        # Valid-length payload that will fail MAC verification.
        payload = base64.b64encode(
            bytes([0x02]) + os.urandom(98)
        ).decode()
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]], "content": payload}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_seal_not_json(self):
        """unwrap_gift_wrap returns None when seal decrypts to non-JSON."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap, nip44_encrypt
        from pynostr.key import PrivateKey
        sk = PrivateKey()
        sender = PrivateKey()
        content = nip44_encrypt("not_json{", sender.hex(), sk.public_key.hex())
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]], "content": content}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_seal_wrong_kind(self):
        """unwrap_gift_wrap returns None when seal kind != 13."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap, nip44_encrypt
        from pynostr.key import PrivateKey
        import json
        sk = PrivateKey()
        sender = PrivateKey()
        seal = {"kind": 99}
        content = nip44_encrypt(json.dumps(seal), sender.hex(), sk.public_key.hex())
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]], "content": content}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_seal_no_pubkey(self):
        """unwrap_gift_wrap returns None when seal has no pubkey."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap, nip44_encrypt
        from pynostr.key import PrivateKey
        import json
        sk = PrivateKey()
        sender = PrivateKey()
        seal = {"kind": 13}  # no pubkey field
        content = nip44_encrypt(json.dumps(seal), sender.hex(), sk.public_key.hex())
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]], "content": content}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_seal_bad_signature(self):
        """unwrap_gift_wrap returns None when seal signature is invalid."""
        from plugins.platforms.nostr.crypto import unwrap_gift_wrap, nip44_encrypt
        from pynostr.key import PrivateKey
        import json
        sk = PrivateKey()
        sender = PrivateKey()
        # Seal with valid structure but bogus signature.
        seal = {
            "kind": 13, "pubkey": sender.public_key.hex(), "content": "x",
            "sig": "00" * 64, "id": "00" * 32, "created_at": 1, "tags": [],
        }
        content = nip44_encrypt(json.dumps(seal), sender.hex(), sk.public_key.hex())
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]], "content": content}
        assert unwrap_gift_wrap(event, sk.bech32()) is None

    def test_unwrap_rumor_decrypt_fail(self):
        """unwrap_gift_wrap returns None when seal content can't be decrypted."""
        from plugins.platforms.nostr.crypto import (
            unwrap_gift_wrap, nip44_encrypt, EventSigner,
        )
        from pynostr.key import PrivateKey
        import json
        sk = PrivateKey()
        sender = PrivateKey()
        # Build a properly-signed seal with garbage content.
        signer = EventSigner(sender.bech32())
        seal = signer.sign_event(kind=13, content="garbage_not_valid_b64", tags=[])
        content = nip44_encrypt(json.dumps(seal), sender.hex(), sk.public_key.hex())
        event = {"kind": 1059, "pubkey": sender.public_key.hex(),
                 "tags": [["p", sk.public_key.hex()]], "content": content}
        assert unwrap_gift_wrap(event, sk.bech32()) is None
