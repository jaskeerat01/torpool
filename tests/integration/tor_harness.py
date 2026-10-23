"""Tor test harness supporting system-Tor or Chutney configurations."""

import os
from pathlib import Path
from typing import Any, Optional


def get_tor_test_config(
    control_port: int = 9051,
    socks_port: int = 9050,
    password_env: str = "TOR_CONTROL_PASSWORD",
) -> dict[str, Any]:
    """Retrieve test parameters for live integration with system Tor or Chutney."""

    return {
        "control_port": int(os.environ.get("TOR_CONTROL_PORT", control_port)),
        "socks_port": int(os.environ.get("TOR_SOCKS_PORT", socks_port)),
        "password": os.environ.get(password_env, ""),
        "chutney_path": os.environ.get("CHUTNEY_PATH", ""),
    }


def generate_test_torrc(
    work_dir: Path,
    control_port: int = 9051,
    socks_port: int = 9050,
    hashed_password: Optional[str] = None,
) -> Path:
    """Generate a minimal runtime torrc for an ephemeral integration Tor instance."""
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    torrc_path = work_dir / "torrc"
    data_dir = work_dir / "tor_data"
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    lines = [
        f"DataDirectory {data_dir}",
        f"SocksPort 127.0.0.1:{socks_port} IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth",
        f"ControlPort 127.0.0.1:{control_port}",
        "CookieAuthentication 0",
    ]
    if hashed_password:
        lines.append(f"HashedControlPassword {hashed_password}")

    torrc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return torrc_path
