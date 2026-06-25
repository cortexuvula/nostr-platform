"""
Pytest configuration — adds Hermes source to sys.path and sets up
the Platform enum for testing.
"""
import sys
import os
from pathlib import Path

# Add Hermes source to path so we can import gateway.platforms.base etc.
HERMES_SRC = Path("/Users/cortexuvula/hermes-agent")
if HERMES_SRC.exists():
    sys.path.insert(0, str(HERMES_SRC))

# Add project root so we can import plugins.platforms.nostr
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Ensure plugins is importable as a package
plugins_dir = PROJECT_ROOT / "plugins"
if plugins_dir.exists():
    sys.path.insert(0, str(plugins_dir / "platforms"))
