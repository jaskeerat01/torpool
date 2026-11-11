"""Static checks for the Tor-only Docker deployment files."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_is_multistage_and_uses_uv() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert " AS builder" in text
    assert " AS runtime" in text
    assert "uv sync --frozen --no-dev" in text
    assert "qbittorrent-nox" in text
    assert "USER" not in text  # entrypoint drops privileges with gosu
    assert "cap_drop" not in text


def test_dockerfile_never_bakes_control_password() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "TOR_CONTROL_PASSWORD=" not in text
    assert "ARG TOR_CONTROL_PASSWORD" not in text
    assert "ENV TOR_CONTROL_PASSWORD" not in text


def test_compose_uses_internal_sidecar_network_and_secrets() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "torpool-internal:" in text
    assert "internal: true" in text
    assert "tor-egress" in text
    assert "TOR_CONTROL_PASSWORD_FILE" in text
    assert "secrets:" in text
    assert "tor_control_password:" in text
    assert "cap_drop:" in text
    assert "no-new-privileges:true" in text
    assert "read_only: true" in text
    assert "stop_grace_period" in text
    assert "ports:" not in text


def test_torpool_service_has_no_egress_network() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    torpool_block = text.split("  torpool:", 1)[1].split("\nsecrets:", 1)[0]
    assert "torpool-internal" in torpool_block
    assert "tor-egress" not in torpool_block
    assert "network_mode: host" not in torpool_block


def test_dockerignore_excludes_secrets_and_data() -> None:
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for pattern in (".env", "secrets/", "quarantine/", "*.sqlite", "*.torrent"):
        assert pattern in text


def test_sidecar_tor_image_and_entrypoint_exist() -> None:
    dockerfile = (ROOT / "docker" / "tor" / "Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "docker" / "tor" / "docker-entrypoint.sh").read_text(encoding="utf-8")
    assert "tor" in dockerfile
    assert "gosu" in dockerfile
    assert "HashedControlPassword" in entrypoint
    assert "CookieAuthentication 0" in entrypoint
    assert "IsolateSOCKSAuth" in entrypoint
    assert "172.30.0.2:9050" in entrypoint
    assert "SocksPolicy reject *" in entrypoint


def test_torpool_entrypoint_supports_secret_and_modes() -> None:
    text = (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8")
    assert "TOR_CONTROL_PASSWORD_FILE" in text
    assert "TORPOOL_TOR_MODE" in text
    assert "embedded" in text
    assert "external" in text
    assert 'echo "${TOR_CONTROL_PASSWORD}' not in text
