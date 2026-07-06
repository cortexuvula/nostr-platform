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

    def test_adapter_injects_signer_into_pool(self, mock_env, monkeypatch):
        """The adapter's EventSigner must be injected into the relay pool so
        NIP-42 AUTH challenges can be answered (kind-22242 signing)."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://relay.example.com"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        assert adapter.relay_pool._signer is adapter._signer


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
        adapter.relay_pool.publish_to = AsyncMock()
        adapter._resolve_recipient_relays = AsyncMock(return_value=[])
        return adapter

    async def test_dm_send_gift_wraps_to_chat_id(self, mock_env, monkeypatch):
        """A plain DM send should gift-wrap to chat_id (a hex pubkey)."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        recipient = PrivateKey().public_key.hex()
        await adapter.send(chat_id=recipient, content="hello")
        # Recipient gift wrap goes out via publish_to.
        adapter.relay_pool.publish_to.assert_awaited_once()
        gift_event = adapter.relay_pool.publish_to.await_args.args[0]
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
        adapter.relay_pool.publish_to.assert_awaited_once()
        gift_event = adapter.relay_pool.publish_to.await_args.args[0]
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
        event = adapter.relay_pool.publish_to.await_args.args[0]
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

    async def test_standalone_publishes_to_recipient_and_self(
        self, mock_env, monkeypatch
    ):
        """Standalone sender must publish a recipient-targeted gift wrap (via
        publish_to) AND a self-copy (via publish), matching adapter.send()."""
        from plugins.platforms.nostr.adapter import _standalone_send_async

        sk = PrivateKey()
        nsec = sk.bech32()
        recipient = PrivateKey().public_key.hex()
        monkeypatch.setenv("NOSTR_NSEC", nsec)
        monkeypatch.setenv("NOSTR_RELAYS", "wss://own.relay")

        # Fake RelayPool: capture publish_to / publish, return [] from query
        # (no recipient 10050 → falls back to own relays).
        fake_pool = MagicMock()
        fake_pool.connect = AsyncMock()
        fake_pool.disconnect = AsyncMock()
        fake_pool.query = AsyncMock(return_value=[])
        fake_pool.publish_to = AsyncMock(
            return_value={"wss://own.relay": {"accepted": True}}
        )
        fake_pool.publish = AsyncMock(
            return_value={"wss://own.relay": {"accepted": True}}
        )
        with patch(
            "plugins.platforms.nostr.adapter.RelayPool",
            return_value=fake_pool,
        ):
            result = await _standalone_send_async(
                MagicMock(), recipient, "hello",
                thread_id=None, media_files=None, force_document=False,
            )

        assert result.get("success") is True
        # Recipient copy via publish_to.
        fake_pool.publish_to.assert_awaited_once()
        recip_event, urls = fake_pool.publish_to.await_args.args[:2]
        assert recip_event["kind"] == 1059
        p_tags = [t for t in recip_event["tags"] if t[0] == "p"]
        assert p_tags[0][1] == recipient
        # Self-copy via publish.
        fake_pool.publish.assert_awaited_once()
        self_event = fake_pool.publish.await_args.args[0]
        assert self_event["kind"] == 1059
        self_p_tags = [t for t in self_event["tags"] if t[0] == "p"]
        # Self-copy must address our main pubkey (standard: single; Jumble: dual).
        assert sk.public_key.hex() in [t[1] for t in self_p_tags]


class TestRecipientRelayDiscovery:
    """Test _resolve_recipient_relays() — the NIP-17 recipient-relay cascade.

    Without this, gift wraps are published only to the agent's own relays,
    so recipients listening on their own kind-10050 inbox relays never see
    the DM (silent delivery failure — the #1 'unreliable DM' cause).
    """

    def _make_adapter(self, mock_env, monkeypatch):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://own.relay"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.relay_pool = MagicMock()
        adapter.relay_pool.query = AsyncMock(return_value=[])
        adapter.relay_pool.publish = AsyncMock()
        adapter.relay_pool.publish_to = AsyncMock()
        return adapter

    async def test_resolves_kind_10050_relays(self, mock_env, monkeypatch):
        """A kind 10050 event with relay tags → those URLs returned."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        adapter.relay_pool.query.return_value = [{
            "kind": 10050,
            "tags": [["relay", "wss://peer-inbox1.com"],
                     ["relay", "wss://peer-inbox2.com"]],
        }]
        relays = await adapter._resolve_recipient_relays(peer)
        assert set(relays) == {"wss://peer-inbox1.com",
                                "wss://peer-inbox2.com"}

    async def test_falls_back_to_kind_10002_read_relays(self, mock_env, monkeypatch):
        """No kind 10050 → query kind 10002, use read/unmarked relays."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        # First query (kind 10050) returns nothing; second (kind 10002) returns
        # a read relay and a write relay.
        adapter.relay_pool.query.side_effect = [
            [],  # 10050 empty
            [{"kind": 10002, "tags": [
                ["r", "wss://read.relay", "read"],
                ["r", "wss://write.relay", "write"],
                ["r", "wss://both.relay"],  # no marker = both
            ]}],
        ]
        relays = await adapter._resolve_recipient_relays(peer)
        assert "wss://read.relay" in relays
        assert "wss://both.relay" in relays
        assert "wss://write.relay" not in relays

    async def test_returns_empty_when_no_relay_lists(self, mock_env, monkeypatch):
        """No 10050 and no 10002 → [] (caller falls back to own relays)."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        adapter.relay_pool.query.return_value = []
        relays = await adapter._resolve_recipient_relays(peer)
        assert relays == []

    async def test_caches_result_within_ttl(self, mock_env, monkeypatch):
        """Second call for same pubkey must not re-query the relay."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        adapter.relay_pool.query.return_value = [{
            "kind": 10050, "tags": [["relay", "wss://cached.relay"]],
        }]
        await adapter._resolve_recipient_relays(peer)
        await adapter._resolve_recipient_relays(peer)
        assert adapter.relay_pool.query.await_count == 1


class TestSelfCopyGiftWrap:
    """Test that send() publishes BOTH a recipient-targeted gift wrap AND a
    self-copy to the agent's own relays (so sent history appears in clients)."""

    def _make_adapter(self, mock_env, monkeypatch):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://own.relay"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.relay_pool = MagicMock()
        adapter.relay_pool.query = AsyncMock(return_value=[])
        adapter.relay_pool.publish = AsyncMock()
        adapter.relay_pool.publish_to = AsyncMock()
        # Patch recipient relay resolution to a known set.
        adapter._resolve_recipient_relays = AsyncMock(
            return_value=["wss://peer-inbox.com"]
        )
        return adapter

    async def test_send_publishes_to_recipient_relays(self, mock_env, monkeypatch):
        """send() must call publish_to with the recipient's relays, not own."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        await adapter.send(chat_id=peer, content="hello")
        adapter.relay_pool.publish_to.assert_awaited_once()
        event, urls = adapter.relay_pool.publish_to.await_args.args[:2]
        assert urls == ["wss://peer-inbox.com"]
        assert event["kind"] == 1059
        p_tags = [t for t in event["tags"] if t[0] == "p"]
        assert p_tags[0][1] == peer

    async def test_send_publishes_self_copy(self, mock_env, monkeypatch):
        """send() must also publish a self-copy (p-tagged to our pubkey)."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        await adapter.send(chat_id=peer, content="hello")
        adapter.relay_pool.publish.assert_awaited_once()
        self_event = adapter.relay_pool.publish.await_args.args[0]
        assert self_event["kind"] == 1059
        p_tags = [t for t in self_event["tags"] if t[0] == "p"]
        # Self-copy must address our main pubkey (standard: single tag;
        # Jumble: dual tag including encryption pubkey).
        assert adapter.pubkey in [t[1] for t in p_tags]

    async def test_send_unknown_recipient_uses_own_relays(self, mock_env, monkeypatch):
        """When recipient has no known relays, publish_to gets own relays."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter._resolve_recipient_relays = AsyncMock(return_value=[])
        peer = PrivateKey().public_key.hex()
        await adapter.send(chat_id=peer, content="hello")
        adapter.relay_pool.publish_to.assert_awaited_once()
        _, urls = adapter.relay_pool.publish_to.await_args.args[:2]
        assert urls == ["wss://own.relay"]


class TestHandleDmAuthorization:
    """Cover the security-critical _handle_dm authorization + NIP-05 paths
    (adapter.py:445-490) — these were previously at 0% test coverage."""

    def _make_adapter(self, mock_env, monkeypatch, require_nip05=False):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://r.example.com"],
                         "require_nip05": require_nip05}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        # Stub gateway-base methods so _handle_dm can run end-to-end.
        adapter.handle_message = AsyncMock()
        adapter.build_source = MagicMock(return_value={"chat_id": "src"})
        return adapter

    async def test_unauthorized_dm_dropped(self, mock_env, monkeypatch):
        """A DM from a pubkey not in allowed_users (and allow_all=False) is
        dropped — handle_message must NOT be called."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        stranger = PrivateKey().public_key.hex()
        await adapter._handle_dm(stranger, "hello", {"id": "ev1"})
        adapter.handle_message.assert_not_called()

    async def test_allowed_user_dm_dispatched(self, mock_env, monkeypatch):
        """A DM from an allowed user is dispatched to handle_message."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        allowed = PrivateKey().public_key.hex()
        adapter.allowed_users.add(allowed)
        await adapter._handle_dm(allowed, "hello", {"id": "ev1"})
        adapter.handle_message.assert_awaited_once()

    async def test_allow_all_accepts_anyone(self, mock_env, monkeypatch):
        """With allow_all=True, any pubkey is accepted."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.allow_all = True
        stranger = PrivateKey().public_key.hex()
        await adapter._handle_dm(stranger, "hello", {"id": "ev1"})
        adapter.handle_message.assert_awaited_once()

    async def test_nip05_required_blocks_unverified(self, mock_env, monkeypatch):
        """With require_nip05=True, a sender with no verified nip05 is dropped."""
        adapter = self._make_adapter(mock_env, monkeypatch, require_nip05=True)
        adapter.allowed_users.add(PrivateKey().public_key.hex())
        # Mock get_profile to return a profile with no nip05.
        allowed = next(iter(adapter.allowed_users))
        adapter.profiles.get_profile = AsyncMock(
            return_value={"name": "x", "nip05": None}
        )
        await adapter._handle_dm(allowed, "hello", {"id": "ev1"})
        adapter.handle_message.assert_not_called()

    async def test_nip05_required_accepts_verified(self, mock_env, monkeypatch):
        """With require_nip05=True, a sender with a verified nip05 is accepted."""
        adapter = self._make_adapter(mock_env, monkeypatch, require_nip05=True)
        allowed = PrivateKey().public_key.hex()
        adapter.allowed_users.add(allowed)
        adapter.profiles.get_profile = AsyncMock(
            return_value={"name": "x", "nip05": "x@example.com"}
        )
        await adapter._handle_dm(allowed, "hello", {"id": "ev1"})
        adapter.handle_message.assert_awaited_once()

    async def test_legacy_dm_peer_recorded(self, mock_env, monkeypatch):
        """A DM arriving via NIP-04 (dm_protocol='nip04') records the sender
        in _legacy_peers so replies use kind 4."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        allowed = PrivateKey().public_key.hex()
        adapter.allowed_users.add(allowed)
        # Avoid touching disk for the save.
        adapter._save_legacy_peers = MagicMock()
        await adapter._handle_dm(allowed, "hi", {"id": "ev1"}, dm_protocol="nip04")
        assert allowed in adapter._legacy_peers
        adapter._save_legacy_peers.assert_called_once()


class TestHandleMentionAuthorization:
    """Cover _handle_mention authorization (adapter.py:494-525)."""

    def _make_adapter(self, mock_env, monkeypatch):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://r.example.com"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.handle_message = AsyncMock()
        adapter.build_source = MagicMock(return_value={"chat_id": "src"})
        return adapter

    async def test_unauthorized_mention_dropped(self, mock_env, monkeypatch):
        """A mention from a non-allowed pubkey is dropped."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        stranger = PrivateKey().public_key.hex()
        await adapter._handle_mention(
            {"pubkey": stranger, "content": "hi", "id": "n1"}
        )
        adapter.handle_message.assert_not_called()

    async def test_allowed_mention_dispatched(self, mock_env, monkeypatch):
        """A mention from an allowed pubkey is dispatched with thread_id=note."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        allowed = PrivateKey().public_key.hex()
        adapter.allowed_users.add(allowed)
        await adapter._handle_mention(
            {"pubkey": allowed, "content": "hi", "id": "note_xyz"}
        )
        adapter.handle_message.assert_awaited_once()
        # build_source must have been called with thread_id=note_xyz.
        _, kwargs = adapter.build_source.call_args
        assert kwargs.get("thread_id") == "note_xyz"


class TestJumbleIntegration:
    """Test Jumble kind-10044 compatibility — encryption keypair, recipient
    detection, and the Jumble-format send branch."""

    def _make_adapter(self, mock_env, monkeypatch, tmp_path=None):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://own.relay"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.relay_pool = MagicMock()
        adapter.relay_pool.query = AsyncMock(return_value=[])
        adapter.relay_pool.publish = AsyncMock()
        adapter.relay_pool.publish_to = AsyncMock()
        adapter._resolve_recipient_relays = AsyncMock(return_value=[])
        return adapter

    def test_encryption_keypair_generated_on_init(self, mock_env, monkeypatch):
        """A fresh adapter has an encryption keypair (generated if none on disk)."""
        monkeypatch.setattr(
            "plugins.platforms.nostr.adapter._ENC_KEY_FILE", None  # force generate
        )
        adapter = self._make_adapter(mock_env, monkeypatch)
        assert adapter._encryption_keypair is not None
        assert "privkey_hex" in adapter._encryption_keypair
        assert "pubkey_hex" in adapter._encryption_keypair

    async def test_resolve_recipient_encryption_pubkey_finds_10044(
        self, mock_env, monkeypatch
    ):
        """A recipient with a kind 10044 event → returns the n-tag pubkey."""
        from pynostr.key import PrivateKey
        adapter = self._make_adapter(mock_env, monkeypatch)
        enc_pubkey = PrivateKey().public_key.hex()
        peer = PrivateKey().public_key.hex()
        adapter.relay_pool.query.return_value = [{
            "kind": 10044, "tags": [["n", enc_pubkey]],
        }]
        result = await adapter._resolve_recipient_encryption_pubkey(peer)
        assert result == enc_pubkey

    async def test_resolve_encryption_returns_none_for_standard_user(
        self, mock_env, monkeypatch
    ):
        """No kind 10044 → None (standard NIP-17 path)."""
        from pynostr.key import PrivateKey
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.query.return_value = []  # no 10044
        peer = PrivateKey().public_key.hex()
        result = await adapter._resolve_recipient_encryption_pubkey(peer)
        assert result is None

    async def test_resolve_encryption_does_not_cache_empty_result(
        self, mock_env, monkeypatch
    ):
        """A failed/empty encryption-pubkey lookup must NOT be cached, so a
        transient relay failure doesn't cause 10 minutes of wrong-format DMs."""
        from pynostr.key import PrivateKey
        from plugins.platforms.nostr.crypto import generate_encryption_keypair
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        enc_kp = generate_encryption_keypair()
        # First call: empty (transient failure). Second call: real 10044 event.
        adapter.relay_pool.query = AsyncMock(side_effect=[
            [],  # first call: nothing found
            [{"kind": 10044, "tags": [["n", enc_kp["pubkey_hex"]]]}],  # second: found
        ])
        first = await adapter._resolve_recipient_encryption_pubkey(peer)
        assert first is None
        second = await adapter._resolve_recipient_encryption_pubkey(peer)
        assert second == enc_kp["pubkey_hex"], (
            "empty result should not be cached — second call must re-query"
        )

    async def test_send_to_jumble_user_uses_jumble_format(
        self, mock_env, monkeypatch
    ):
        """Sending to a Jumble user (has 10044) produces a dual-p-tag gift wrap."""
        from pynostr.key import PrivateKey
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer_main = PrivateKey().public_key.hex()
        peer_enc = PrivateKey().public_key.hex()
        adapter._resolve_recipient_encryption_pubkey = AsyncMock(
            return_value=peer_enc
        )
        await adapter.send(chat_id=peer_main, content="hello jumble")
        adapter.relay_pool.publish_to.assert_awaited_once()
        recip_event, _ = adapter.relay_pool.publish_to.await_args.args[:2]
        assert recip_event["kind"] == 1059
        p_values = [t[1] for t in recip_event["tags"] if t[0] == "p"]
        assert peer_enc in p_values, "must p-tag the encryption pubkey"
        assert peer_main in p_values, "must p-tag the main pubkey"
        assert len(p_values) == 2

    async def test_send_to_standard_user_uses_single_p_tag(
        self, mock_env, monkeypatch
    ):
        """Sending to a standard user (no 10044) produces a single-p-tag wrap."""
        from pynostr.key import PrivateKey
        adapter = self._make_adapter(mock_env, monkeypatch)
        peer = PrivateKey().public_key.hex()
        adapter._resolve_recipient_encryption_pubkey = AsyncMock(return_value=None)
        await adapter.send(chat_id=peer, content="hello standard")
        adapter.relay_pool.publish_to.assert_awaited_once()
        recip_event, _ = adapter.relay_pool.publish_to.await_args.args[:2]
        p_values = [t[1] for t in recip_event["tags"] if t[0] == "p"]
        assert p_values == [peer], "standard user gets single main-pubkey p-tag"

    async def test_self_copy_uses_jumble_format_when_agent_has_enc_key(
        self, mock_env, monkeypatch
    ):
        """When the agent has an encryption keypair, the self-copy gift wrap
        must be Jumble-format (dual p-tags including the agent's encryption
        pubkey) so it decrypts in the agent's own Jumble sent-history view."""
        from pynostr.key import PrivateKey
        from plugins.platforms.nostr.crypto import generate_encryption_keypair
        adapter = self._make_adapter(mock_env, monkeypatch)
        # Give the agent a Jumble encryption keypair.
        adapter._encryption_keypair = generate_encryption_keypair()
        peer_main = PrivateKey().public_key.hex()
        peer_enc = PrivateKey().public_key.hex()
        adapter._resolve_recipient_encryption_pubkey = AsyncMock(
            return_value=peer_enc
        )
        await adapter.send(chat_id=peer_main, content="hello")
        # Self-copy goes through publish() (not publish_to).
        adapter.relay_pool.publish.assert_awaited_once()
        self_event = adapter.relay_pool.publish.await_args.args[0]
        assert self_event["kind"] == 1059
        p_values = [t[1] for t in self_event["tags"] if t[0] == "p"]
        # Must include BOTH the agent's main pubkey AND encryption pubkey.
        assert adapter.pubkey in p_values, "self-copy must p-tag agent main pubkey"
        assert adapter._encryption_keypair["pubkey_hex"] in p_values, (
            "self-copy must p-tag agent encryption pubkey for Jumble decrypt"
        )


class TestEnvAndConfigHelpers:
    """Cover env_enablement, check_requirements, is_connected, hex/npub utils."""

    def test_env_enablement_parses_env(self, monkeypatch):
        """_env_enablement reads relay + feature flags from env."""
        from plugins.platforms.nostr.adapter import _env_enablement
        monkeypatch.setenv("NOSTR_RELAYS", "wss://a.com, wss://b.com")
        monkeypatch.setenv("NOSTR_MONITOR_MENTIONS", "true")
        monkeypatch.setenv("NOSTR_REPLY_PUBLICLY", "yes")
        monkeypatch.setenv("NOSTR_REQUIRE_NIP05", "1")
        monkeypatch.setenv("NOSTR_LEGACY_DM", "false")
        monkeypatch.setenv("NOSTR_HOME_CHANNEL", "npub1home")
        result = _env_enablement()
        assert result["extra"]["relays"] == ["wss://a.com", "wss://b.com"]
        assert result["extra"]["monitor_mentions"] is True
        assert result["extra"]["reply_publicly"] is True
        assert result["extra"]["require_nip05"] is True
        assert result["extra"]["legacy_dm"] is False
        assert result["home_channel"] == "npub1home"

    def test_env_enablement_no_relays_no_home(self, monkeypatch):
        """_env_enablement handles unset relays and home channel."""
        from plugins.platforms.nostr.adapter import _env_enablement
        monkeypatch.delenv("NOSTR_RELAYS", raising=False)
        monkeypatch.delenv("NOSTR_HOME_CHANNEL", raising=False)
        result = _env_enablement()
        assert "relays" not in result["extra"]
        assert "home_channel" not in result

    def test_check_requirements(self, monkeypatch):
        """check_requirements returns NOSTR_AVAILABLE."""
        import plugins.platforms.nostr.adapter as mod
        from plugins.platforms.nostr.adapter import check_requirements
        monkeypatch.setattr(mod, "NOSTR_AVAILABLE", True)
        assert check_requirements() is True
        monkeypatch.setattr(mod, "NOSTR_AVAILABLE", False)
        assert check_requirements() is False

    def test_is_connected_truth_table(self, monkeypatch):
        """is_connected returns True only when both env vars are set."""
        from plugins.platforms.nostr.adapter import is_connected
        monkeypatch.setenv("NOSTR_NSEC", "x")
        monkeypatch.setenv("NOSTR_RELAYS", "wss://a")
        assert is_connected(None) is True
        monkeypatch.delenv("NOSTR_RELAYS", raising=False)
        assert is_connected(None) is False

    def test_hex_npub_roundtrip(self):
        """_hex_to_npub and _npub_to_hex roundtrip correctly."""
        from pynostr.key import PrivateKey
        from plugins.platforms.nostr.adapter import _npub_to_hex, _hex_to_npub
        sk = PrivateKey()
        npub = sk.public_key.bech32()
        hex_key = _npub_to_hex(npub)
        assert _hex_to_npub(hex_key) == npub

    def test_format_message_returns_input(self, mock_env):
        """format_message returns content unchanged."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        assert adapter.format_message("hello world") == "hello world"


class TestSendErrorPaths:
    """Cover send() early-return error paths."""

    def _make_adapter(self, mock_env, monkeypatch):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://r"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.relay_pool = MagicMock()
        adapter.relay_pool.publish = AsyncMock()
        return adapter

    async def test_send_no_message_text(self, mock_env, monkeypatch):
        """send() returns failure when no message text is provided."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        result = await adapter.send(chat_id="pk", content=None)
        assert result.success is False
        assert "No message text" in result.error

    async def test_send_typing_is_noop(self, mock_env, monkeypatch):
        """send_typing is a no-op that completes without error."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        await adapter.send_typing("pk")  # must not raise

    async def test_send_image_delegates_to_send(self, mock_env, monkeypatch):
        """send_image assembles text and delegates to send."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.send = AsyncMock()
        await adapter.send_image("pk", "https://img.example/x.png", "caption")
        adapter.send.assert_awaited_once()
        sent_text = adapter.send.await_args.args[1]
        assert "caption" in sent_text
        assert "https://img.example/x.png" in sent_text

    async def test_send_image_without_caption(self, mock_env, monkeypatch):
        """send_image with no caption sends just the URL."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.send = AsyncMock()
        await adapter.send_image("pk", "https://img.example/y.png")
        sent_text = adapter.send.await_args.args[1]
        assert sent_text == "https://img.example/y.png"

    async def test_get_chat_info(self, mock_env, monkeypatch):
        """get_chat_info returns profile-based dict."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.profiles = MagicMock()
        adapter.profiles.get_profile = AsyncMock(
            return_value={"name": "Alice", "nip05": "alice@x.com"}
        )
        info = await adapter.get_chat_info("pk123")
        assert info["name"] == "Alice"
        assert info["type"] == "dm"
        assert info["chat_id"] == "pk123"

    async def test_get_chat_info_fallback_name(self, mock_env, monkeypatch):
        """get_chat_info falls back to truncated pubkey when no name."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.profiles = MagicMock()
        adapter.profiles.get_profile = AsyncMock(return_value={})
        info = await adapter.get_chat_info("abcdef0123456789")
        assert info["name"] == "abcdef012345..."  # chat_id[:12] + "..."


class TestStandaloneHelpers:
    """Cover module-level standalone helper functions."""

    async def test_query_recipient_relays_10050_hit(self):
        """_query_recipient_relays returns relay tags from kind 10050."""
        from plugins.platforms.nostr.adapter import _query_recipient_relays
        pool = MagicMock()
        pool.query = AsyncMock(return_value=[
            {"tags": [["relay", "wss://a"], ["relay", "wss://b"]]}
        ])
        result = await _query_recipient_relays(pool, "pk")
        assert result == ["wss://a", "wss://b"]

    async def test_query_recipient_relays_10002_fallback(self):
        """_query_recipient_relays falls back to kind 10002 read relays."""
        from plugins.platforms.nostr.adapter import _query_recipient_relays
        pool = MagicMock()
        pool.query = AsyncMock(side_effect=[
            [],  # 10050 empty
            [{"tags": [["r", "wss://read", "read"], ["r", "wss://write", "write"]]}],
        ])
        result = await _query_recipient_relays(pool, "pk")
        assert "wss://read" in result
        assert "wss://write" not in result

    async def test_query_recipient_relays_query_fails(self):
        """_query_recipient_relays swallows query errors and returns []."""
        from plugins.platforms.nostr.adapter import _query_recipient_relays
        pool = MagicMock()
        pool.query = AsyncMock(side_effect=RuntimeError("down"))
        result = await _query_recipient_relays(pool, "pk")
        assert result == []

    async def test_query_recipient_encryption_pubkey_found(self):
        """_query_recipient_encryption_pubkey returns n-tag from 10044."""
        from plugins.platforms.nostr.adapter import _query_recipient_encryption_pubkey
        pool = MagicMock()
        pool.query = AsyncMock(return_value=[
            {"tags": [["n", "enc123"]]}
        ])
        result = await _query_recipient_encryption_pubkey(pool, "pk")
        assert result == "enc123"

    async def test_query_recipient_encryption_pubkey_none(self):
        """_query_recipient_encryption_pubkey returns None when no 10044."""
        from plugins.platforms.nostr.adapter import _query_recipient_encryption_pubkey
        pool = MagicMock()
        pool.query = AsyncMock(return_value=[])
        result = await _query_recipient_encryption_pubkey(pool, "pk")
        assert result is None

    def test_load_persisted_encryption_key_missing(self, monkeypatch):
        """_load_persisted_encryption_key returns None when file missing."""
        from pathlib import Path
        import plugins.platforms.nostr.adapter as mod
        from plugins.platforms.nostr.adapter import _load_persisted_encryption_key
        # Point the file at a nonexistent path.
        monkeypatch.setattr(mod, "_ENC_KEY_FILE", Path("/nonexistent/path/key.json"))
        assert _load_persisted_encryption_key() is None


class TestAdapterInternals:
    """Cover persistence helpers, publish helpers, resolve error paths,
    and connect guards."""

    def _make_adapter(self, mock_env, monkeypatch):
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {"relays": ["wss://r"]}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        adapter.relay_pool = MagicMock()
        adapter.relay_pool.publish = AsyncMock()
        adapter.relay_pool.publish_to = AsyncMock()
        adapter.relay_pool.query = AsyncMock(return_value=[])
        return adapter

    def test_load_legacy_peers_missing_file(self, monkeypatch):
        """_load_legacy_peers returns empty set when file missing."""
        from pathlib import Path
        import plugins.platforms.nostr.adapter as mod
        from plugins.platforms.nostr.adapter import NostrAdapter
        monkeypatch.setattr(mod, "_LEGACY_PEERS_FILE",
                            Path("/nonexistent/peers.json"))
        config = MagicMock()
        config.extra = {}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        assert adapter._legacy_peers == set()

    async def test_publish_dm_relays(self, mock_env, monkeypatch):
        """_publish_dm_relays signs and publishes a kind 10050 event."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.publish = AsyncMock(
            return_value={"wss://r": {"accepted": True}}
        )
        await adapter._publish_dm_relays()
        adapter.relay_pool.publish.assert_awaited_once()
        event = adapter.relay_pool.publish.await_args.args[0]
        assert event["kind"] == 10050
        assert any(t[0] == "relay" for t in event["tags"])

    async def test_publish_dm_relays_failure_swallowed(self, mock_env, monkeypatch):
        """_publish_dm_relays swallows publish errors."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.publish = AsyncMock(side_effect=RuntimeError("down"))
        await adapter._publish_dm_relays()  # must not raise

    async def test_publish_encryption_key(self, mock_env, monkeypatch):
        """_publish_encryption_key signs and publishes a kind 10044 event."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.publish = AsyncMock(
            return_value={"wss://r": {"accepted": True}}
        )
        await adapter._publish_encryption_key()
        adapter.relay_pool.publish.assert_awaited_once()
        event = adapter.relay_pool.publish.await_args.args[0]
        assert event["kind"] == 10044
        assert any(t[0] == "n" for t in event["tags"])

    async def test_publish_encryption_key_failure_swallowed(
        self, mock_env, monkeypatch
    ):
        """_publish_encryption_key swallows publish errors."""
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.publish = AsyncMock(side_effect=RuntimeError("down"))
        await adapter._publish_encryption_key()  # must not raise

    async def test_resolve_recipient_relays_query_fails(
        self, mock_env, monkeypatch
    ):
        """_resolve_recipient_relays returns [] when queries fail."""
        from pynostr.key import PrivateKey
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.query = AsyncMock(side_effect=RuntimeError("down"))
        peer = PrivateKey().public_key.hex()
        result = await adapter._resolve_recipient_relays(peer)
        assert result == []

    async def test_resolve_recipient_encryption_query_fails(
        self, mock_env, monkeypatch
    ):
        """_resolve_recipient_encryption_pubkey returns None on query fail."""
        from pynostr.key import PrivateKey
        adapter = self._make_adapter(mock_env, monkeypatch)
        adapter.relay_pool.query = AsyncMock(side_effect=RuntimeError("down"))
        peer = PrivateKey().public_key.hex()
        result = await adapter._resolve_recipient_encryption_pubkey(peer)
        assert result is None

    async def test_connect_returns_false_no_signer(self, monkeypatch):
        """connect() returns False when no nsec configured."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        monkeypatch.setenv("NOSTR_NSEC", "")
        monkeypatch.setenv("NOSTR_RELAYS", "wss://r")
        config = MagicMock()
        config.extra = {}
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        result = await adapter.connect()
        assert result is False

    async def test_connect_returns_false_no_relays(self, mock_env, monkeypatch):
        """connect() returns False when no relays configured."""
        from plugins.platforms.nostr.adapter import NostrAdapter
        config = MagicMock()
        config.extra = {}
        monkeypatch.setenv("NOSTR_RELAYS", "")  # no relays anywhere
        with patch("plugins.platforms.nostr.adapter.NOSTR_AVAILABLE", True):
            adapter = NostrAdapter(config)
        result = await adapter.connect()
        assert result is False


