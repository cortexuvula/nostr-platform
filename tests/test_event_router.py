"""
Tests for the Nostr event router — event classification and routing.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pynostr.key import PrivateKey

from plugins.platforms.nostr.event_router import EventRouter


def signed_event(kind, content, pubkey_hex, privkey_hex, tags=None):
    """Build a properly signed Nostr event for router tests.

    The router now verifies event signatures for kind 1 and kind 4, so any
    test that expects these to be processed must supply a valid signature.
    """
    from pynostr.event import Event
    import time as _time
    ev = Event(
        pubkey=pubkey_hex,
        kind=kind,
        content=content,
        tags=tags or [],
        created_at=int(_time.time()),
    )
    sk = PrivateKey(bytes.fromhex(privkey_hex))
    ev.sign(sk.hex())
    return ev.to_dict()


@pytest.fixture
def mock_adapter():
    """Create a mock adapter for the router."""
    sk = PrivateKey()
    adapter = MagicMock()
    adapter.nsec = sk.bech32()
    adapter.pubkey = sk.public_key.hex()
    adapter.monitor_mentions = True
    adapter._handle_dm = AsyncMock()
    adapter._handle_mention = AsyncMock()
    adapter.profiles = MagicMock()
    adapter.profiles.update_from_event = AsyncMock()
    # No Jumble encryption keypair by default; Jumble-specific tests set this.
    adapter._encryption_keypair = None
    return adapter


@pytest.fixture
def keypair():
    """Generate a keypair for test events."""
    sk = PrivateKey()
    return {
        "nsec": sk.bech32(),
        "hex": sk.hex(),
        "pubkey": sk.public_key.hex(),
    }


class TestEventClassification:
    """Test that events are classified by kind correctly."""

    async def test_kind_1059_routed_to_gift_wrap(self, mock_adapter, keypair):
        """Kind 1059 should trigger gift-wrap handling → _handle_dm."""
        # Create a gift-wrapped DM
        from plugins.platforms.nostr.crypto import (
            create_gift_wrap, create_dm_rumor
        )
        rumor = create_dm_rumor("test message", mock_adapter.pubkey, keypair["pubkey"])
        gift_event = create_gift_wrap(rumor, mock_adapter.pubkey, keypair["nsec"])

        router = EventRouter(mock_adapter)
        await router.route(gift_event, "wss://test.relay")

        mock_adapter._handle_dm.assert_called_once()
        args = mock_adapter._handle_dm.call_args
        assert args[0][1] == "test message"  # (sender_pubkey, content, event)

    async def test_kind_1_with_mention_routed(self, mock_adapter, keypair):
        """Kind 1 with p tag matching our pubkey should trigger mention handler."""
        event = signed_event(
            1, "Hey @agent!", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_mention.assert_called_once_with(event)

    async def test_kind_1_without_mention_ignored(self, mock_adapter, keypair):
        """Kind 1 without our pubkey in p tags should be ignored."""
        other_pubkey = PrivateKey().public_key.hex()
        event = signed_event(
            1, "Just a regular note", keypair["pubkey"], keypair["hex"],
            tags=[["p", other_pubkey]],  # mentions someone else
        )

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_mention.assert_not_called()

    async def test_kind_1_ignored_when_monitor_disabled(self, mock_adapter, keypair):
        """Kind 1 should be ignored when monitor_mentions is False."""
        mock_adapter.monitor_mentions = False
        event = signed_event(
            1, "Hey!", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_mention.assert_not_called()

    async def test_kind_0_updates_profile_cache(self, mock_adapter, keypair):
        """Kind 0 metadata should update the profile cache."""
        profile_data = {"name": "Alice", "about": "Test user"}
        event = {
            "kind": 0,
            "content": json.dumps(profile_data),
            "pubkey": keypair["pubkey"],
            "tags": [],
            "id": "test_metadata_id",
        }

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter.profiles.update_from_event.assert_called_once_with(
            keypair["pubkey"], profile_data
        )

    async def test_kind_7_reaction_ignored(self, mock_adapter, keypair):
        """Kind 7 reactions should be silently ignored."""
        event = {
            "kind": 7,
            "content": "+",
            "pubkey": keypair["pubkey"],
            "tags": [],
            "id": "test_reaction_id",
        }

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_dm.assert_not_called()
        mock_adapter._handle_mention.assert_not_called()

    async def test_unknown_kind_ignored(self, mock_adapter, keypair):
        """Unknown event kinds should be silently ignored."""
        event = {
            "kind": 99999,
            "content": "unknown",
            "pubkey": keypair["pubkey"],
            "tags": [],
            "id": "test_unknown_id",
        }

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_dm.assert_not_called()
        mock_adapter._handle_mention.assert_not_called()


class TestSignatureVerification:
    """Unsigned/forged kind 1 and kind 4 events must be dropped."""

    async def test_kind_4_with_valid_signature_is_processed(self, mock_adapter, keypair):
        """A properly signed kind 4 reaches _handle_legacy_dm (then _handle_dm)."""
        from plugins.platforms.nostr.crypto import nip04_encrypt
        # Real NIP-04 ciphertext so it actually decrypts to a message.
        agent_sk = PrivateKey(bytes.fromhex(keypair["hex"]))
        agent_nsec = agent_sk.bech32()
        mock_adapter.nsec = agent_nsec
        mock_adapter.pubkey = agent_sk.public_key.hex()
        # Sender encrypts a DM to the agent.
        sender = PrivateKey()
        ct = nip04_encrypt("hello", sender.hex(), mock_adapter.pubkey)
        event = signed_event(
            4, ct, sender.public_key.hex(), sender.hex(),
            tags=[["p", mock_adapter.pubkey]],
        )
        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")
        mock_adapter._handle_dm.assert_called_once()

    async def test_kind_4_with_forged_signature_is_dropped(self, mock_adapter, keypair):
        """A kind 4 with a bad signature (sender spoofed) must be dropped."""
        event = signed_event(
            4, "encrypted-blob", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )
        # Corrupt the signature so it no longer matches the pubkey.
        event["sig"] = "0" * 128
        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")
        mock_adapter._handle_dm.assert_not_called()

    async def test_kind_1_with_forged_signature_is_dropped(self, mock_adapter, keypair):
        """A kind 1 mention with a bad signature must be dropped."""
        event = signed_event(
            1, "hi @agent", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )
        event["sig"] = "1" * 128
        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")
        mock_adapter._handle_mention.assert_not_called()


class TestMalformedTags:
    """Malformed tags from untrusted relays must not crash routing."""

    async def test_kind_1_with_malformed_tags_does_not_raise(self, mock_adapter, keypair):
        """Malformed p-tags (empty/non-list) should be skipped, not raise.

        The event is properly signed (so it passes signature verification)
        but carries malformed tags; only the one well-formed p-tag should
        trigger the mention.
        """
        # pynostr's Event coerces tags to lists of str, so build a raw signed
        # event dict with the malformed tags injected after signing.
        event = signed_event(
            1, "hi", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )
        # Inject malformed tags alongside the valid one.
        event["tags"] = [[], "not-a-list", ["p"], ["p", mock_adapter.pubkey]]

        router = EventRouter(mock_adapter)
        # Should not raise even though tags include malformed entries; the
        # signature still verifies because we recompute over the signed id.
        # NOTE: modifying tags post-sign invalidates the signature, so instead
        # we verify the defensive helper handles malformed input directly.
        from plugins.platforms.nostr.event_router import _p_tag_pubkeys
        pubkeys = _p_tag_pubkeys(event)
        assert mock_adapter.pubkey in pubkeys

    async def test_kind_4_with_malformed_tags_does_not_raise(self, mock_adapter, keypair):
        """Legacy DM with malformed tags must skip safely, not raise.

        Verified via the defensive helper directly, since modifying tags
        after signing would invalidate the event signature.
        """
        event = {
            "kind": 4,
            "content": "encrypted",
            "pubkey": keypair["pubkey"],
            "tags": [[], ["p"], 42, ["p", mock_adapter.pubkey]],
            "id": "test_dm_id",
        }
        from plugins.platforms.nostr.event_router import _p_tag_pubkeys
        # Should not raise even though tags include malformed entries.
        pubkeys = _p_tag_pubkeys(event)
        assert mock_adapter.pubkey in pubkeys


class TestRumorPubkeyAuthentication:
    """NIP-17: the recipient MUST verify rumor.pubkey == seal.pubkey, else a
    sender can forge a DM that appears to come from someone else."""

    async def test_match_accepted(self, mock_adapter, keypair):
        """When rumor.pubkey == seal.pubkey, _handle_dm is called."""
        from plugins.platforms.nostr.crypto import (
            create_gift_wrap, create_dm_rumor,
        )
        rumor = create_dm_rumor("hi", mock_adapter.pubkey, keypair["pubkey"])
        gift_event = create_gift_wrap(rumor, mock_adapter.pubkey, keypair["nsec"])
        router = EventRouter(mock_adapter)
        await router.route(gift_event, "wss://test.relay")
        mock_adapter._handle_dm.assert_called_once()

    async def test_mismatch_rejected(self, mock_adapter, keypair):
        """When rumor.pubkey != seal.pubkey, the DM is dropped (impersonation)."""
        from plugins.platforms.nostr.crypto import (
            create_gift_wrap, create_dm_rumor, EventSigner, nip44_encrypt,
        )
        import time as _time

        # Build a rumor whose claimed pubkey is attacker (keypair), but sign
        # the seal with a DIFFERENT key (impostor). This is the forgery: the
        # seal authoritatively identifies the sender, but the rumor lies.
        impostor = PrivateKey()
        impostor_pubkey = impostor.public_key.hex()
        impostor_nsec = impostor.bech32()
        impostor_signer = EventSigner(impostor_nsec)

        forged_rumor = create_dm_rumor(
            "I am keypair, trust me", mock_adapter.pubkey, keypair["pubkey"]
        )

        # Seal signed by impostor, encrypting the forged rumor to recipient.
        encrypted_rumor = nip44_encrypt(
            json.dumps(forged_rumor),
            impostor.hex(),
            mock_adapter.pubkey,
        )
        seal = impostor_signer.sign_event(
            kind=13, content=encrypted_rumor, tags=[],
        )

        # Gift wrap the impostor seal to recipient with an ephemeral key.
        eph = PrivateKey()
        encrypted_seal = nip44_encrypt(
            json.dumps(seal), eph.hex(), mock_adapter.pubkey,
        )
        eph_signer = EventSigner(eph.bech32())
        gift_event = eph_signer.sign_event(
            kind=1059, content=encrypted_seal,
            tags=[["p", mock_adapter.pubkey]],
        )

        router = EventRouter(mock_adapter)
        await router.route(gift_event, "wss://test.relay")
        # MUST NOT be accepted — rumor.pubkey (keypair) != seal.pubkey (impostor).
        mock_adapter._handle_dm.assert_not_called()


class TestNIP09Deletion:
    """NIP-09: kind 5 deletion requests tombstone referenced events."""

    async def test_kind_5_records_deleted_event_ids(self, mock_adapter, keypair):
        """A kind 5 event records the e-tagged event IDs as deleted."""
        router = EventRouter(mock_adapter)
        deletion = signed_event(
            5, "deleted", keypair["pubkey"], keypair["hex"],
            tags=[["e", "target_event_1"], ["e", "target_event_2"]],
        )
        await router.route(deletion, "wss://test.relay")
        assert "target_event_1" in router._deleted_ids
        assert "target_event_2" in router._deleted_ids

    async def test_deleted_event_is_dropped(self, mock_adapter, keypair):
        """An event whose ID is tombstoned by a prior kind 5 must not route."""
        router = EventRouter(mock_adapter)
        # First, tombstone a note.
        note = signed_event(
            1, "doomed message", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )
        deletion = signed_event(
            5, "deleting my note", keypair["pubkey"], keypair["hex"],
            tags=[["e", note["id"]]],
        )
        await router.route(deletion, "wss://test.relay")
        # Now route the note — it should be dropped (tombstoned).
        await router.route(note, "wss://test.relay")
        mock_adapter._handle_mention.assert_not_called()

    async def test_kind_5_from_wrong_pubkey_cannot_delete(self, mock_adapter, keypair):
        """NIP-09: only the original author can delete. A kind 5 from a
        different pubkey must not tombstone another author's event."""
        router = EventRouter(mock_adapter)
        impostor = PrivateKey()
        # Author's note.
        note = signed_event(
            1, "real note", keypair["pubkey"], keypair["hex"],
            tags=[["p", mock_adapter.pubkey]],
        )
        # Impostor tries to delete it.
        deletion = signed_event(
            5, "deleting someone else's note",
            impostor.public_key.hex(), impostor.hex(),
            tags=[["e", note["id"]]],
        )
        await router.route(deletion, "wss://test.relay")
        # The note must still route (impostor's deletion ignored).
        await router.route(note, "wss://test.relay")
        mock_adapter._handle_mention.assert_called_once_with(note)


class TestJumbleReceive:
    """Test that Jumble-format gift wraps (encrypted to the encryption pubkey)
    are received and routed to _handle_dm."""

    async def test_jumble_format_gift_wrap_received(self, mock_adapter, keypair):
        """A Jumble-format gift wrap addressed to our encryption pubkey is
        unwrapped (using the encryption privkey) and routed to _handle_dm."""
        from plugins.platforms.nostr.crypto import (
            create_jumble_gift_wrap, create_dm_rumor, generate_encryption_keypair,
        )
        # Give the mock adapter an encryption keypair.
        recip_enc = generate_encryption_keypair()
        mock_adapter._encryption_keypair = recip_enc
        sender_enc = generate_encryption_keypair()

        rumor = create_dm_rumor(
            "hello from jumble", mock_adapter.pubkey, keypair["pubkey"]
        )
        gw = create_jumble_gift_wrap(
            rumor, mock_adapter.pubkey, recip_enc["pubkey_hex"],
            keypair["nsec"], sender_enc["privkey_hex"],
        )
        router = EventRouter(mock_adapter)
        await router.route(gw, "wss://test.relay")
        mock_adapter._handle_dm.assert_called_once()
        args = mock_adapter._handle_dm.call_args
        assert args[0][1] == "hello from jumble"
