"""Nostr platform adapter plugin for Hermes Agent."""

__version__ = "1.0.0"

# Re-export register() so the Hermes plugin loader finds it
from .adapter import register  # noqa: F401
