"""playit.gg setup writes credentials safely and never echoes secrets."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import setup_playit as setup  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_portable_config(monkeypatch):
    """Keep test secrets out of the real repo-local portable file."""
    store = {}
    monkeypatch.setattr(setup.portable_config, "load", lambda: dict(store))
    monkeypatch.setattr(setup.portable_config, "save", lambda data: store.update(data))


def test_setup_writes_secret_and_endpoint_without_echoing(tmp_path: Path, capsys) -> None:
    config = tmp_path / "playit.toml"
    secret = "abcdef0123456789abcdef"
    assert setup.main.__name__ == "main"  # imported successfully
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--secret", secret,
                 "--endpoint", "edge.playit.gg:41234", "--config", str(config)]
    try:
        assert setup.main() == 0
    finally:
        _sys.argv = old

    content = config.read_text(encoding="utf-8")
    assert secret in content  # stored on disk only
    assert 'endpoint = "edge.playit.gg:41234"' in content
    assert secret not in capsys.readouterr().out


def test_setup_rejects_bad_endpoint(tmp_path: Path, capsys) -> None:
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--endpoint", "not-an-endpoint",
                 "--config", str(tmp_path / "playit.toml")]
    try:
        assert setup.main() == 1
    finally:
        _sys.argv = old
    assert "host:port" in capsys.readouterr().err


def test_setup_rejects_placeholder_secret(tmp_path: Path, capsys) -> None:
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--secret", "KEY",
                 "--endpoint", "NEWHOST:NEWPORT", "--config", str(tmp_path / "playit.toml")]
    try:
        assert setup.main() == 1
    finally:
        _sys.argv = old
    assert "Replace the placeholder secret" in capsys.readouterr().err


def test_setup_rejects_angle_bracket_placeholders(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("RUBEVPN_PLAYIT_SECRET", "<REAL_SECRET>")
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--endpoint", "<REAL_HOST>:<REAL_PORT>",
                 "--config", str(tmp_path / "playit.toml")]
    try:
        assert setup.main() == 1
    finally:
        _sys.argv = old
    assert "Replace the placeholder" in capsys.readouterr().err


def test_setup_reads_secret_from_env(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("RUBEVPN_PLAYIT_SECRET", "abcdef0123456789abcdef")
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--endpoint", "edge.ply.gg:41234",
                 "--config", str(tmp_path / "playit.toml")]
    try:
        assert setup.main() == 0
    finally:
        _sys.argv = old
    assert 'secret = "abcdef0123456789abcdef"' in (tmp_path / "playit.toml").read_text(
        encoding="utf-8")


def test_setup_rejects_saved_placeholder_credentials(tmp_path: Path, capsys) -> None:
    config = tmp_path / "playit.toml"
    config.write_text('secret = "paste-the-real-secret-here"\n'
                      'endpoint = "brave-falcon.tun.ply.gg:41234"\n', encoding="utf-8")
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--check", "--config", str(config)]
    try:
        assert setup.main() == 1
    finally:
        _sys.argv = old
    assert "still placeholder" in capsys.readouterr().err


def test_setup_check_reports_missing_config(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(setup.shutil, "which", lambda name: None)
    monkeypatch.delenv("RUBEVPN_PLAYIT_BIN", raising=False)
    import sys as _sys
    old = _sys.argv
    _sys.argv = ["setup_playit.py", "--check", "--config", str(tmp_path / "missing.toml")]
    try:
        code = setup.main()
    finally:
        _sys.argv = old
    assert code == 2
    output = capsys.readouterr().out
    assert "INCOMPLETE" in output
    assert "secret:   missing" in output
