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
    """Test config validation."""

    def test_valid_config(self, mock_env):
        """Valid config should return no errors."""
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {}
        errors = validate_config(config)
        assert len(errors) == 0

    def test_missing_nsec(self, mock_env, monkeypatch):
        """Missing NOSTR_NSEC should return error."""
        monkeypatch.delenv("NOSTR_NSEC")
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {}
        errors = validate_config(config)
        assert any("NOSTR_NSEC" in e for e in errors)

    def test_missing_relays(self, mock_env, monkeypatch):
        """Missing NOSTR_RELAYS should return error."""
        monkeypatch.delenv("NOSTR_RELAYS")
        from plugins.platforms.nostr.adapter import validate_config
        config = MagicMock()
        config.extra = {}
        errors = validate_config(config)
        assert any("NOSTR_RELAYS" in e for e in errors)
