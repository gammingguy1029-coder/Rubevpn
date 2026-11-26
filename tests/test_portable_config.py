"""Portable runner state survives an ephemeral GitHub VM."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import portable_config as pc  # noqa: E402


def test_seed_restores_keys_devices_and_playit(tmp_path: Path) -> None:
    portable = tmp_path / "rubevpn.local.json"
    pc.save({
        "keys": {"server": '{"private_key": "A" * 44}'},
        "devices": [{"id": "phone", "ip": "10.0.0.2", "public_key": "B" * 44,
                     "conf": "[Interface]\nAddress = 10.0.0.2/32\n"}],
        "playit": {"secret": "abc123", "endpoint": "edge.ply.gg:41234"},
        "tunnel_provider": "playit",
    }, portable)
    cfg = tmp_path / "wg"

    pc.seed(cfg, portable)

    assert (cfg / "server_keys.json").read_text(encoding="utf-8") == '{"private_key": "A" * 44}'
    assert (cfg / "devices" / "phone.json").is_file()
    assert "Address = 10.0.0.2/32" in (cfg / "devices" / "phone.conf").read_text(encoding="utf-8")
    playit = (cfg / "playit.toml").read_text(encoding="utf-8")
    assert 'secret = "abc123"' in playit
    assert 'endpoint = "edge.ply.gg:41234"' in playit
    assert pc.load(portable)["tunnel_provider"] == "playit"


def test_seed_does_not_overwrite_existing_files(tmp_path: Path) -> None:
    portable = tmp_path / "rubevpn.local.json"
    pc.save({"keys": {"server": "new"}}, portable)
    cfg = tmp_path / "wg"
    cfg.mkdir()
    (cfg / "server_keys.json").write_text("existing", encoding="utf-8")
    pc.seed(cfg, portable)
    assert (cfg / "server_keys.json").read_text(encoding="utf-8") == "existing"


def test_capture_persists_current_runner_state(tmp_path: Path) -> None:
    cfg = tmp_path / "wg"
    (cfg / "devices").mkdir(parents=True)
    (cfg / "server_keys.json").write_text("server-keys", encoding="ascii")
    (cfg / "devices" / "phone.json").write_text(json.dumps({
        "id": "phone", "ip": "10.0.0.2", "public_key": "B" * 44,
    }), encoding="ascii")
    (cfg / "devices" / "phone.conf").write_text("CONF", encoding="ascii")
    (cfg / "playit.toml").write_text('secret = "s"\nendpoint = "h:1"\n', encoding="utf-8")
    portable = tmp_path / "rubevpn.local.json"

    pc.capture(cfg, portable)
    data = pc.load(portable)
    assert data["keys"]["server"] == "server-keys"
    assert data["devices"][0]["conf"] == "CONF"
    assert data["playit"]["endpoint"] == "h:1"


def test_portable_file_is_gitignored() -> None:
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "config/rubevpn.local.json" in ignore
