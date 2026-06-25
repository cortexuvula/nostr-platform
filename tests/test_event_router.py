"""
Tests for the Nostr event router — event classification and routing.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pynostr.key import PrivateKey

from plugins.platforms.nostr.event_router import EventRouter


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
        rumor = create_dm_rumor("test message", mock_adapter.pubkey)
        gift_event = create_gift_wrap(rumor, mock_adapter.pubkey, keypair["nsec"])

        router = EventRouter(mock_adapter)
        await router.route(gift_event, "wss://test.relay")

        mock_adapter._handle_dm.assert_called_once()
        args = mock_adapter._handle_dm.call_args
        assert args[0][1] == "test message"  # (sender_pubkey, content, event)

    async def test_kind_1_with_mention_routed(self, mock_adapter, keypair):
        """Kind 1 with p tag matching our pubkey should trigger mention handler."""
        event = {
            "kind": 1,
            "content": "Hey @agent!",
            "pubkey": keypair["pubkey"],
            "tags": [["p", mock_adapter.pubkey]],
            "id": "test_note_id",
        }

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_mention.assert_called_once_with(event)

    async def test_kind_1_without_mention_ignored(self, mock_adapter, keypair):
        """Kind 1 without our pubkey in p tags should be ignored."""
        other_pubkey = PrivateKey().public_key.hex()
        event = {
            "kind": 1,
            "content": "Just a regular note",
            "pubkey": keypair["pubkey"],
            "tags": [["p", other_pubkey]],  # mentions someone else
            "id": "test_note_id",
        }

        router = EventRouter(mock_adapter)
        await router.route(event, "wss://test.relay")

        mock_adapter._handle_mention.assert_not_called()

    async def test_kind_1_ignored_when_monitor_disabled(self, mock_adapter, keypair):
        """Kind 1 should be ignored when monitor_mentions is False."""
        mock_adapter.monitor_mentions = False
        event = {
            "kind": 1,
            "content": "Hey!",
            "pubkey": keypair["pubkey"],
            "tags": [["p", mock_adapter.pubkey]],
            "id": "test_note_id",
        }

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
