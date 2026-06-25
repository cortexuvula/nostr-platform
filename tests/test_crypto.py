"""
Tests for Nostr crypto module — NIP-04, event signing, gift-wrap round-trip.
"""

import json
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


class TestGiftWrap:
    """Test NIP-17 gift-wrap create/unwrap."""

    def test_gift_wrap_roundtrip(self, keypair_a, keypair_b):
        """Gift-wrap then unwrap — rumor content must match."""
        original_content = "Encrypted DM via NIP-17!"
        rumor = create_dm_rumor(original_content, keypair_b["pubkey"])
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

    def test_unwrap_wrong_recipient_fails(self, keypair_a, keypair_b):
        """Unwrapping with wrong nsec should return None."""
        sk_c = PrivateKey()
        rumor = create_dm_rumor("test", keypair_b["pubkey"])
        gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                       keypair_a["nsec"])

        # Try to unwrap as C (not the recipient)
        unwrapped = unwrap_gift_wrap(gift_event, sk_c.bech32())
        assert unwrapped is None

    def test_gift_wrap_has_correct_tags(self, keypair_a, keypair_b):
        """Gift-wrap should have p tag with recipient pubkey."""
        rumor = create_dm_rumor("test", keypair_b["pubkey"])
        gift_event = create_gift_wrap(rumor, keypair_b["pubkey"],
                                       keypair_a["nsec"])

        p_tags = [t for t in gift_event["tags"] if t[0] == "p"]
        assert len(p_tags) >= 1
        assert p_tags[0][1] == keypair_b["pubkey"]
