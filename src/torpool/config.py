"""Configuration loader reading TOML files, CLI overrides, and environment variables."""

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Fixed generic User-Agent matching standard Tor Browser release string
TOR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"


class ConfigError(Exception):
    """Raised when configuration or authentication setup is invalid."""


@dataclass
class TorPoolConfig:
    """Validated runtime configuration for TorPool."""

    circuits: int = 4
    control_port: int = 9051
    socks_port_base: int = 9050
    circuit_timeout: float = 30.0
    health_interval: float = 30.0
    health_probe_url: str = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
    chunk_size: int = 10 * 1024 * 1024  # 10 MiB
    max_retries_per_chunk: int = 5
    max_bandwidth: int = 0  # 0 means unlimited
    per_host_concurrency: int = 0  # 0 means equal to number of healthy circuits
    output_dir: Path = field(default_factory=lambda: Path("./quarantine"))
    temp_dir: Path = field(default_factory=lambda: Path("./quarantine/tmp"))
    encrypt: bool = False
    key_file: Optional[Path] = None
    verbosity: int = 0  # -1=quiet, 0=default, 1=-v, 2=-vv
    graph: bool = False
    graph_refresh: float = 1.0
    graph_window: int = 120
    log_file: Optional[Path] = None
    authorized_confirmed: bool = False
    config_path: Path = field(
        default_factory=lambda: Path.home() / ".config" / "torpool" / "config.toml"
    )

    def validate(self) -> None:
        """Validate configuration bounds and security constraints."""
        if not (1 <= self.circuits <= 16):
            raise ConfigError(f"circuits must be between 1 and 16 (got {self.circuits})")
        if self.chunk_size < 65536:
            raise ConfigError("chunk_size must be at least 64 KiB (65536 bytes)")
        if self.health_interval < 1.0:
            raise ConfigError("health_interval must be at least 1.0 second")
        if self.circuit_timeout < 1.0:
            raise ConfigError("circuit_timeout must be at least 1.0 second")
        if not (0.25 <= self.graph_refresh <= 5.0):
            raise ConfigError("graph_refresh must be between 0.25s and 5.0s")
        if self.graph_window < 10:
            raise ConfigError("graph_window must be at least 10 seconds")
        if self.max_bandwidth < 0:
            raise ConfigError("max_bandwidth cannot be negative")
        if self.per_host_concurrency < 0:
            raise ConfigError("per_host_concurrency cannot be negative")

    @staticmethod
    def get_control_password() -> str:
        """Retrieve Tor control password exclusively from TOR_CONTROL_PASSWORD."""
        pw = os.environ.get("TOR_CONTROL_PASSWORD")
        if not pw:
            raise ConfigError(
                "Missing TOR_CONTROL_PASSWORD environment variable. "
                "TorPool requires password authentication via TOR_CONTROL_PASSWORD and refuses to start without it."
            )
        return pw

    def get_passphrase(self) -> str:
        """
        Retrieve encryption/decryption passphrase.
        Checks key_file first, then TORPOOL_PASSPHRASE environment variable.
        If neither is set and stdin is a TTY, prompts interactively.
        """
        if self.key_file:
            kf = Path(self.key_file)
            if not kf.exists() or not kf.is_file():
                raise ConfigError(f"Specified key_file does not exist or is not a file: {kf}")
            passphrase = kf.read_text(encoding="utf-8").strip()
            if not passphrase:
                raise ConfigError(f"Specified key_file is empty: {kf}")
            return passphrase

        env_pw = os.environ.get("TORPOOL_PASSPHRASE")
        if env_pw:
            return env_pw

        if sys.stdin.isatty():
            import typer

            return typer.prompt("Enter encryption/decryption passphrase", hide_input=True)

        raise ConfigError(
            "Encryption requested but no passphrase supplied via --key-file, "
            "TORPOOL_PASSPHRASE environment variable, or interactive prompt."
        )


class ConfigLoader:
    """Loads configuration from TOML file and merges CLI overrides."""

    FORBIDDEN_KEYS = {"password", "control_password", "tor_control_password", "cookie"}

    @classmethod
    def load(
        cls,
        config_path: Optional[Path] = None,
        cli_overrides: Optional[dict[str, Any]] = None,
    ) -> TorPoolConfig:
        """Load TOML config, verify no password is stored in file, and apply CLI flags."""
        default_path = Path.home() / ".config" / "torpool" / "config.toml"
        target_path = config_path or default_path

        cfg = TorPoolConfig(config_path=target_path)

        if target_path.exists():
            with target_path.open("rb") as f:
                raw_data = tomllib.load(f)
            cls._check_forbidden_keys(raw_data)
            cls._apply_dict(cfg, raw_data)

        if cli_overrides:
            for k, v in cli_overrides.items():
                if v is not None and hasattr(cfg, k):
                    setattr(cfg, k, v)

        # Auto-disable graph if stdout or stderr is not a TTY
        if cfg.graph and (not sys.stdout.isatty() or not sys.stderr.isatty()):
            cfg.graph = False

        cfg.validate()
        return cfg

    @classmethod
    def _check_forbidden_keys(cls, data: dict[str, Any]) -> None:
        """Ensure config file never contains control passwords."""
        for k, v in data.items():
            if k.lower() in cls.FORBIDDEN_KEYS:
                raise ConfigError(
                    f"Security violation: Forbidden key '{k}' found in configuration file. "
                    "The control password must only be supplied via TOR_CONTROL_PASSWORD."
                )
            if isinstance(v, dict):
                cls._check_forbidden_keys(v)

    @classmethod
    def _apply_dict(cls, cfg: TorPoolConfig, data: dict[str, Any]) -> None:
        """Flatten sectioned TOML dictionary into TorPoolConfig."""
        for section in ("tor", "download", "ui", "auth"):
            sec_data = data.get(section, {})
            if isinstance(sec_data, dict):
                for key, val in sec_data.items():
                    if hasattr(cfg, key):
                        if key in ("output_dir", "temp_dir", "key_file", "log_file"):
                            setattr(cfg, key, Path(val) if val else None)
                        else:
                            setattr(cfg, key, val)

    @classmethod
    def save_authorization(cls, config_path: Path) -> None:
        """Persist authorization confirmation in local config file with 0600 permissions."""
        config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(config_path.parent, 0o700)
        content = ""
        if config_path.exists():
            content = config_path.read_text(encoding="utf-8")
        if "[auth]" not in content:
            content += "\n[auth]\nauthorized_confirmed = true\n"
        else:
            content = content.replace("authorized_confirmed = false", "authorized_confirmed = true")
        config_path.write_text(content, encoding="utf-8")
        os.chmod(config_path, 0o600)
