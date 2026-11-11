"""Offline tests for the qBittorrent Web API client and OPSEC preferences."""

from pathlib import Path
from typing import Any

import httpx
import pytest

from torpool.config import TorPoolConfig
from torpool.qbittorrent import (
    PreferenceExpectation,
    QBittorrentClient,
    QBittorrentError,
    QBittorrentProcess,
    _pbkdf2_password,
    _write_profile_config,
    build_torrent_preferences,
    validate_preferences,
)
from torpool.torrent_manager import TorrentError, parse_torrent_source, safe_relative_path


def _prefs_payload() -> dict[str, Any]:
    return {
        "proxy_type": "SOCKS5",
        "proxy_ip": "127.0.0.1",
        "proxy_port": 41000,
        "proxy_auth_enabled": True,
        "proxy_username": "tp_test",
        "proxy_hostname_lookup": True,
        "proxy_peer_connections": True,
        "proxy_bittorrent": True,
        "anonymous_mode": True,
        "dht": False,
        "lsd": False,
        "upnp": False,
        "bittorrent_protocol": 1,
        "up_limit": 1024,
        "max_uploads": -1,
        "max_uploads_per_torrent": -1,
        "max_ratio": 0.0,
        "max_ratio_enabled": True,
        "max_ratio_act": 1,
        "max_seeding_time": 0,
        "max_seeding_time_enabled": True,
        "web_ui_address": "127.0.0.1",
        "web_ui_port": 42000,
        "web_ui_upnp": False,
        "current_network_interface": "lo",
        "save_path": "/tmp/quarantine/tmp",
        "listen_port": 43000,
    }


def test_build_preferences_is_conservative() -> None:
    cfg = TorPoolConfig()
    prefs = build_torrent_preferences(
        cfg,
        proxy_username="tp_test",
        proxy_password="secret",
        listener_port=41000,
        save_path=Path("/tmp/quarantine/tmp"),
        listen_port=43000,
        web_port=42000,
        download_limit_bytes_s=1000,
    )
    assert prefs["proxy_type"] == "SOCKS5"
    assert prefs["proxy_ip"] == "127.0.0.1"
    assert prefs["proxy_hostname_lookup"] is True
    assert prefs["proxy_peer_connections"] is True
    assert prefs["dht"] is False and prefs["lsd"] is False
    assert prefs["up_limit"] == 1
    assert prefs["max_uploads"] == 0
    assert prefs["max_ratio_enabled"] is True
    assert prefs["max_ratio_act"] == 1
    assert prefs["current_network_interface"] == "lo"
    assert prefs["bittorrent_protocol"] == 1


def test_validate_preferences_accepts_qbittorrent_normalization() -> None:
    expected = PreferenceExpectation(
        proxy_port=41000,
        proxy_username="tp_test",
        save_path="/tmp/quarantine/tmp",
        listen_port=43000,
        bind_interface="lo",
        web_port=42000,
    )
    validate_preferences(_prefs_payload(), expected)


@pytest.mark.parametrize(
    "mutation",
    [
        {"uploaded_up_limit": 0},
        {"max_uploads": 1},
        {"dht": True},
        {"proxy_hostname_lookup": False},
        {"proxy_ip": "0.0.0.0"},
        {"anonymous_mode": False},
        {"web_ui_address": "0.0.0.0"},
    ],
)
def test_validate_preferences_rejects_unsafe_values(mutation: dict[str, Any]) -> None:
    expected = PreferenceExpectation(
        proxy_port=41000,
        proxy_username="tp_test",
        save_path="/tmp/quarantine/tmp",
        listen_port=43000,
        bind_interface="lo",
        web_port=42000,
    )
    prefs = _prefs_payload()
    if "uploaded_up_limit" in mutation:
        prefs["up_limit"] = mutation["uploaded_up_limit"]
    else:
        prefs.update(mutation)
    with pytest.raises(QBittorrentError):
        validate_preferences(prefs, expected)


def test_webui_password_hash_format() -> None:
    value = _pbkdf2_password("secret", b"0" * 16)
    salt, digest = value.split(":")
    assert len(salt) > 0 and len(digest) > 0
    assert "secret" not in value


def test_profile_config_is_private_and_loopback_only(tmp_path: Path) -> None:
    path = _write_profile_config(tmp_path / "profile", 42000, "user", "pass")
    text = path.read_text(encoding="utf-8")
    assert "WebUI\\Address=127.0.0.1" in text
    assert "WebUI\\Port=42000" in text
    assert "WebUI\\Password_PBKDF2" in text
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.parent.parent.stat().st_mode & 0o777 == 0o700


def test_child_environment_scrubs_secrets_and_proxies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TOR_CONTROL_PASSWORD", "control-secret")
    monkeypatch.setenv("TORPOOL_PASSPHRASE", "passphrase-secret")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8080")
    process = QBittorrentProcess.create("qbittorrent-nox", tmp_path / "profile", 0)
    env = process._child_env()
    assert "TOR_CONTROL_PASSWORD" not in env
    assert "TORPOOL_PASSPHRASE" not in env
    assert "HTTP_PROXY" not in env
    assert "control-secret" not in str(env)
    assert "passphrase-secret" not in str(env)


@pytest.mark.asyncio
async def test_client_login_and_preferences_roundtrip() -> None:
    current = _prefs_payload()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v2/auth/login":
            return httpx.Response(200, text="Ok.")
        if request.url.path == "/api/v2/app/preferences":
            return httpx.Response(200, json=current)
        if request.url.path == "/api/v2/app/setPreferences":
            return httpx.Response(200)
        if request.url.path == "/api/v2/app/version":
            return httpx.Response(200, text="v5.1.4")
        return httpx.Response(404)

    client = QBittorrentClient(42000, "user", "pass", transport=httpx.MockTransport(handler))
    try:
        await client.login()
        assert await client.version() == "v5.1.4"
        expected = PreferenceExpectation(
            proxy_port=41000,
            proxy_username="tp_test",
            save_path="/tmp/quarantine/tmp",
            listen_port=43000,
            bind_interface="lo",
            web_port=42000,
        )
        await client.apply_and_verify(_prefs_payload(), expected)
    finally:
        await client.close()


def test_magnet_validation() -> None:
    source = parse_torrent_source(
        "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&tr=https://tracker.example/a&dn=name"
    )
    assert source.kind == "magnet"
    assert source.infohash == "0123456789abcdef0123456789abcdef01234567"
    assert "tracker" not in source.manifest_label
    with pytest.raises(TorrentError, match="Trackerless"):
        parse_torrent_source("magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567")
    with pytest.raises(TorrentError, match="xs/ws/as"):
        parse_torrent_source(
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&tr=x&ws=https://evil"
        )


def test_torrent_file_validation(tmp_path: Path) -> None:
    torrent = tmp_path / "sample.torrent"
    torrent.write_bytes(b"d4:infod4:name4:teste")
    source = parse_torrent_source(str(torrent))
    assert source.kind == "torrent"
    assert source.torrent_bytes is not None
    bad = tmp_path / "bad.torrent"
    bad.write_bytes(b"not-a-torrent")
    with pytest.raises(TorrentError):
        parse_torrent_source(str(bad))


@pytest.mark.parametrize(
    "path",
    ["../escape", "/absolute", "a/../../b", ""],
)
def test_safe_relative_path_rejects_escapes(path: str) -> None:
    with pytest.raises(TorrentError):
        safe_relative_path(path)
