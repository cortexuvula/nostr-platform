"""
Tests for the Nostr adapter — authorization, config parsing, message routing.
"""

import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pynostr.key import PrivateKey

from plugins.platforms.nostr.crypto import EventSigner


# Patch Platform enum to accept "nostr" since we're outside the gateway
@pytest.fixture(autouse=True)
def mock_platform(monkeypatch):
    """Allow Platform('nostr') to work in tests."""
    from gateway.config import Platform

    def _patched_missing(cls, value):
        if isinstance(value, str) and value.strip().lower() == "nostr":
            value = value.strip().lower()
            if value in cls._value2member_map_:
                return cls._value2member_map_[value]
            pseudo = object.__new__(cls)
            pseudo._value_ = value
            pseudo._name_ = "NOSTR"
            cls._value2member_map_[value] = pseudo
            cls._member_map_["NOSTR"] = pseudo
            return pseudo
        return None

    # Only patch if "nostr" isn't already a valid member
    try:
        Platform("nostr")
    except ValueError:
        monkeypatch.setattr(Platform, "_missing_", classmethod(_patched_missing))


@pytest.fixture
def mock_env(monkeypatch):
    """Set up mock environment variables."""
    sk = PrivateKey()
    monkeypatch.setenv("NOSTR_NSEC", sk.bech32())
    monkeypatch.setenv("NOSTR_RELAYS", "wss://relay1.com,wss://relay2.com")
    monkeypatch.setenv("NOSTR_ALLOWED_USERS", "")
    monkeypatch.setenv("NOSTR_ALLOW_ALL_USERS", "false")
    return {
        "nsec": sk.bech32(),
        "pubkey": sk.public_key.hex(),
        "npub": sk.public_key.bech32(),
    }


class TestConfigParsing:
    """Test adapter configuration parsing."""

    def test_nsec_parsed_correctly(self, mock_env):
        """NSEC should be parsed into a valid EventSigner."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://relay1.com"]}

        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
            assert adapter.nsec == mock_env["nsec"]
            assert adapter.pubkey == mock_env["pubkey"]
            assert adapter._signer is not None

    def test_relays_from_env(self, mock_env):
        """Relay URLs should be parsed from env var."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {}

        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
            assert len(adapter.relay_urls) == 2
            assert "wss://relay1.com" in adapter.relay_urls
            assert "wss://relay2.com" in adapter.relay_urls

    def test_relays_from_config(self, mock_env):
        """Relay URLs should be parsed from config.extra."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {
            "relays": ["wss://custom.relay1.com", "wss://custom.relay2.com"]
        }

        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
            assert "wss://custom.relay1.com" in adapter.relay_urls

    def test_allowed_users_parsed(self, mock_env, monkeypatch):
        """Allowed users should be parsed from NOSTR_ALLOWED_USERS."""
        sk2 = PrivateKey()
        monkeypatch.setenv(
            "NOSTR_ALLOWED_USERS",
            f"{sk2.public_key.bech32()}",
        )
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {}

        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
            assert sk2.public_key.hex() in adapter.allowed_users

    def test_allow_all_flag(self, mock_env, monkeypatch):
        """NOSTR_ALLOW_ALL_USERS should set allow_all."""
        monkeypatch.setenv("NOSTR_ALLOW_ALL_USERS", "true")
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {}

        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
            assert adapter.allow_all is True

    def test_feature_flags(self, mock_env):
        """Feature flags should be parsed from config.extra."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {
            "relays": ["wss://relay1.com"],
            "monitor_mentions": True,
            "reply_publicly": True,
            "require_nip05": True,
        }

        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
            assert adapter.monitor_mentions is True
            assert adapter.reply_publicly is True
            assert adapter.require_nip05 is True


class TestRequirementCheck:
    """Test check_requirements function."""

    def test_check_requirements_true_when_available(self):
        """check_requirements should return True when pynostr is available."""
        from plugins.platforms.nostr.adapter import check_requirements
        # pynostr is installed in test env
        assert check_requirements() is True


class TestValidateConfig:
    """Test config validation.

    validate_config returns True if valid, False otherwise (matches the
    Hermes framework contract in gateway/platform_registry.py).
    """

    def test_valid_config(self, mock_env):
        """Valid config should return True."""
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {}
        assert validate_config(config) is True

    def test_missing_nsec(self, mock_env, monkeypatch):
        """Missing NOSTR_NSEC should return False."""
        monkeypatch.delenv("NOSTR_NSEC")
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {}
        assert validate_config(config) is False

    def test_missing_relays(self, mock_env, monkeypatch):
        """Missing NOSTR_RELAYS should return False."""
        monkeypatch.delenv("NOSTR_RELAYS")
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {}
        assert validate_config(config) is False

    def test_relays_from_config_ok(self, mock_env, monkeypatch):
        """NOSTR_RELAYS unset but config.extra.relays present should be valid."""
        monkeypatch.delenv("NOSTR_RELAYS")
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {"relays": ["wss://relay.example.com"]}
        assert validate_config(config) is True


class TestSendRouting:
    """Test that send() addresses replies correctly for DMs vs mentions."""

    def _make_adapter(self, mock_env, monkeypatch, reply_publicly=False):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://relay1.com"], "reply_publicly": reply_publicly}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.relay_pool = MagicMock()
        adapter.relay_pool.publish = AsyncMock()
        return adapter

    async def test_dm_send_gift_wraps_to_chat_id(self, mock_env, monkeypatch):
        """A plain DM send should gift-wrap to chat_id (a hex pubkey)."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        recipient = PrivateKey().public_key.hex()
        await adapter.send(chat_id=recipient, content="hello")
        adapter.relay_pool.publish.assert_awaited_once()
        gift_event = adapter.relay_pool.publish.await_args.args[0]
        assert gift_event["kind"] == 1059
        # p tag must address the recipient pubkey, not arbitrary text.
        p_tags = [t for t in gift_event["tags"] if t[0] == "p"]
        assert p_tags[0][1] == recipient

    async def test_mention_private_reply_dms_author(self, mock_env, monkeypatch):
        """Mention reply with reply_publicly=False should DM the author pubkey."""
        adapter = self._make_adapter(mock_env, monkeypatch, reply_publicly=False)
        author = PrivateKey().public_key.hex()
        # mention context: note id carried as metadata["thread_id"]
        await adapter.send(
            chat_id=author,
            content="hi",
            metadata={"thread_id": "note_abc"},
        )
        adapter.relay_pool.publish.assert_awaited_once()
        gift_event = adapter.relay_pool.publish.await_args.args[0]
        assert gift_event["kind"] == 1059
        p_tags = [t for t in gift_event["tags"] if t[0] == "p"]
        assert p_tags[0][1] == author  # DM to the author, NOT the note id

    async def test_mention_public_reply_is_kind1(self, mock_env, monkeypatch):
        """Mention reply with reply_publicly=True should publish a kind 1 note."""
        adapter = self._make_adapter(mock_env, monkeypatch, reply_publicly=True)
        author = PrivateKey().public_key.hex()
        await adapter.send(
            chat_id=author,
            content="public reply",
            metadata={"thread_id": "note_abc"},
        )
        adapter.relay_pool.publish.assert_awaited_once()
        event = adapter.relay_pool.publish.await_args.args[0]
        assert event["kind"] == 1
        # e tag must reference the note id, p tag the author pubkey.
        e_tags = [t for t in event["tags"] if t[0] == "e"]
        p_tags = [t for t in event["tags"] if t[0] == "p"]
        assert e_tags[0][1] == "note_abc"
        assert p_tags[0][1] == author

    async def test_legacy_peer_reply_uses_nip04_kind4(self, mock_env, monkeypatch):
        """A reply to a peer that sent a legacy NIP-04 DM must go out as a
        kind 4 event (nip04_encrypt), NOT a NIP-17 gift-wrap — otherwise
        legacy-only clients can never read the reply."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        legacy_peer = PrivateKey().public_key.hex()
        adapter._legacy_peers.add(legacy_peer)

        await adapter.send(chat_id=legacy_peer, content="hi back")

        adapter.relay_pool.publish.assert_awaited_once()
        event = adapter.relay_pool.publish.await_args.args[0]
        assert event["kind"] == 4, "legacy peer must get a kind 4 (NIP-04) reply"
        # Content is the nip04 ciphertext (base64?iv=base64), not a gift-wrap payload.
        assert "?iv=" in event["content"]
        p_tags = [t for t in event["tags"] if t[0] == "p"]
        assert p_tags[0][1] == legacy_peer

    async def test_nip17_peer_reply_uses_gift_wrap(self, mock_env, monkeypatch):
        """A reply to an unknown (NIP-17) peer must use gift-wrap (kind 1059)."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        await adapter.send(chat_id=peer, content="hi")
        event = adapter.relay_pool.publish.await_args.args[0]
        assert event["kind"] == 1059


class TestStandaloneSendSignature:
    """Test the standalone sender matches the gateway contract.

    tools/send_message_tool.py calls standalone_sender_fn positionally as
    (pconfig, chat_id, message, *, thread_id, media_files, force_document),
    matching every sibling plugin (irc, discord, etc.). The nostr function
    must accept pconfig as its first positional arg.
    """

    def test_signature_accepts_pconfig_first(self):
        """First positional param is pconfig; second is chat_id; third message."""
        import inspect
        from plugins.platforms.nostr.adapter import _standalone_send_async
        sig = inspect.signature(_standalone_send_async)
        params = list(sig.parameters)
        assert params[0] == "pconfig", (
            "first positional arg must be `pconfig` to match the gateway "
            "standalone_sender_fn contract (irc/discord use this signature)"
        )
        assert params[1] == "chat_id"
        assert params[2] == "message"
        # thread_id / media_files / force_document must be keyword-only.
        for kw in ("thread_id", "media_files", "force_document"):
            assert sig.parameters[kw].kind == inspect.Parameter.KEYWORD_ONLY

    async def test_pconfig_not_treated_as_chat_id(self, mock_env, monkeypatch):
        """Calling with (pconfig, chat_id, message) must not treat pconfig as
        a recipient (the original bug: chat_id received the PlatformConfig)."""
        from plugins.platforms.nostr.adapter import _standalone_send_async
        # NOSTR_RELAYS unset → returns early, but only after reading chat_id
        # correctly. If pconfig leaked into chat_id, npub check would crash.
        monkeypatch.setenv("NOSTR_NSEC", "nsec1fake")
        monkeypatch.delenv("NOSTR_RELAYS", raising=False)
        pconfig = MagicMock()  # not a string
        result = await _standalone_send_async(
            pconfig,
            "npub1validish",
            "hello",
            thread_id=None,
            media_files=None,
            force_document=False,
        )
        # Must return the relays-missing error, NOT an AttributeError-derived
        # "standalone send failed" error (which is what the bug produced).
        assert result.get("error") == "NOSTR_RELAYS not set"
