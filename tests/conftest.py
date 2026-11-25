"""Test bootstrap: deterministic secrets, never real credentials."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.security.auth import hash_password  # noqa: E402

os.environ.setdefault("RUBEVPN_ADMIN_USER", "admin")
os.environ.setdefault("RUBEVPN_ADMIN_PASSWORD_HASH", hash_password("correct-horse-battery"))
os.environ.setdefault("RUBEVPN_SESSION_SECRET", "t" * 64)
os.environ.setdefault("RUBEVPN_COOKIE_SECURE", "false")
