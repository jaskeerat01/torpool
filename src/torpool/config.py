"""Configuration loader reading TOML files, CLI overrides, and environment variables."""

import os
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# Fixed generic User-Agent matching standard Tor Browser release string
TOR_BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

MAX_CIRCUITS = 100
MIN_CIRCUIT_CREATION_DELAY = 0.5


class ConfigError(Exception):
    """Raised when configuration or authentication setup is invalid."""


@dataclass
class TorPoolConfig:
    """Validated runtime configuration for TorPool."""

    circuits: int = 4
    circuit_creation_delay: float = 1.0
    control_port: int = 9051
    tor_control_host: str = "127.0.0.1"
    socks_port_base: int = 9050
    tor_socks_host: str = "127.0.0.1"
    circuit_timeout: float = 30.0
    health_interval: float = 30.0
    health_probe_url: str = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
    chunk_size: int = 10 * 1024 * 1024  # 10 MiB
    max_retries_per_chunk: int = 5
    max_bandwidth: int = 0  # 0 means unlimited
    per_host_concurrency: int = 0  # 0 means equal to number of healthy circuits
    output_dir: Path = field(default_factory=lambda: Path("./quarantine"))
    temp_dir: Path = field(default_factory=lambda: Path("./quarantine/tmp"))
    state_dir: Optional[Path] = None
    encrypt: bool = False
    key_file: Optional[Path] = None
    verbosity: int = 0  # -1=quiet, 0=default, 1=-v, 2=-vv
    graph: bool = False
    graph_refresh: float = 1.0
    graph_window: int = 120
    log_file: Optional[Path] = None

    # Torrent / qBittorrent settings
    qbittorrent_executable: str = "qbittorrent-nox"
    qbittorrent_web_port: int = 0
    qbittorrent_temp_profile_dir: Path = field(default_factory=lambda: Path("./quarantine/tmp/qbt"))
    torrent_mode: str = "auto"
    torrent_max_instances: int = 8
    torrent_max_connections: int = 100
    dht_enabled: bool = False
    pex_enabled: bool = False
    lsd_enabled: bool = False
    torrent_bind_interface: str = "lo"
    torrent_metadata_timeout: float = 120.0
    torrent_poll_interval: float = 1.0

    authorized_confirmed: bool = False
    config_path: Path = field(
        default_factory=lambda: Path.home() / ".config" / "torpool" / "config.toml"
    )

    @property
    def effective_state_dir(self) -> Path:
        """Return the directory used for resume/status state files."""
        return self.state_dir if self.state_dir is not None else self.output_dir

    def validate(self) -> None:
        """Validate configuration bounds and security constraints."""
        if not (1 <= self.circuits <= MAX_CIRCUITS):
            raise ConfigError(
                f"circuits must be between 1 and {MAX_CIRCUITS} (got {self.circuits})"
            )
        if self.circuit_creation_delay < MIN_CIRCUIT_CREATION_DELAY:
            raise ConfigError(
                "circuit_creation_delay must be at least "
                f"{MIN_CIRCUIT_CREATION_DELAY} seconds and cannot be disabled"
            )
        if self.circuit_creation_delay > 60.0:
            raise ConfigError("circuit_creation_delay must not exceed 60 seconds")
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
        if not (1 <= self.torrent_max_instances <= MAX_CIRCUITS):
            raise ConfigError(f"torrent_max_instances must be between 1 and {MAX_CIRCUITS}")
        if self.torrent_mode not in ("auto", "multi_file", "single"):
            raise ConfigError("torrent_mode must be one of: auto, multi_file, single")
        if self.torrent_max_connections < 1:
            raise ConfigError("torrent_max_connections must be at least 1")
        if self.torrent_metadata_timeout < 1.0:
            raise ConfigError("torrent_metadata_timeout must be at least 1.0 second")
        if self.torrent_poll_interval < 0.25:
            raise ConfigError("torrent_poll_interval must be at least 0.25 seconds")
        if self.dht_enabled:
            raise ConfigError(
                "dht_enabled=true is refused: DHT uses UDP and cannot traverse Tor. "
                "This tool requires zero clearnet fallback."
            )
        if self.lsd_enabled:
            raise ConfigError(
                "lsd_enabled=true is refused: local peer discovery uses UDP/multicast "
                "and cannot traverse Tor."
            )
        if not self.torrent_bind_interface:
            raise ConfigError("torrent_bind_interface must not be empty")
        if not self.torrent_bind_interface.lower().startswith("lo"):
            raise ConfigError(
                "torrent_bind_interface must be a loopback interface (lo/lo0) "
                "to prevent direct clearnet interface use"
            )
        if self.qbittorrent_web_port < 0 or self.qbittorrent_web_port > 65535:
            raise ConfigError("qbittorrent_web_port must be between 0 and 65535")

    @staticmethod
    def get_control_password() -> str:
        """Retrieve Tor control password from TOR_CONTROL_PASSWORD or a Docker secret file."""
        pw = os.environ.get("TOR_CONTROL_PASSWORD")
        if not pw:
            secret_file = os.environ.get("TOR_CONTROL_PASSWORD_FILE")
            if secret_file:
                try:
                    with open(secret_file, encoding="utf-8") as handle:
                        pw = handle.read().strip()
                except OSError as exc:
                    raise ConfigError("Unable to read TOR_CONTROL_PASSWORD_FILE secret") from exc
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

    FORBIDDEN_KEYS = {
        "password",
        "control_password",
        "tor_control_password",
        "cookie",
        "torrent_max_uploads",
    }
    PATH_KEYS = {
        "output_dir",
        "temp_dir",
        "state_dir",
        "key_file",
        "log_file",
        "qbittorrent_temp_profile_dir",
    }

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

        cls._apply_env(cfg)

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
        """Ensure config file never contains control passwords or upload overrides."""
        for k, v in data.items():
            if k.lower() in cls.FORBIDDEN_KEYS:
                if k.lower() == "torrent_max_uploads":
                    raise ConfigError(
                        "Security violation: uploading and seeding are prohibited. "
                        "Remove 'torrent_max_uploads' from the configuration file."
                    )
                raise ConfigError(
                    f"Security violation: Forbidden key '{k}' found in configuration file. "
                    "The control password must only be supplied via TOR_CONTROL_PASSWORD."
                )
            if isinstance(v, dict):
                cls._check_forbidden_keys(v)

    @classmethod
    def _apply_dict(cls, cfg: TorPoolConfig, data: dict[str, Any]) -> None:
        """Flatten sectioned TOML dictionary into TorPoolConfig."""
        for section in ("tor", "download", "ui", "torrent", "auth"):
            sec_data = data.get(section, {})
            if isinstance(sec_data, dict):
                for key, val in sec_data.items():
                    if hasattr(cfg, key):
                        if key in cls.PATH_KEYS:
                            setattr(cfg, key, Path(val) if val else None)
                        else:
                            setattr(cfg, key, val)

    @classmethod
    def _apply_env(cls, cfg: TorPoolConfig) -> None:
        """Apply container-friendly environment overrides (CLI still wins)."""
        env_map: dict[str, tuple[str, type]] = {
            "TOR_CONTROL_HOST": ("tor_control_host", str),
            "TOR_SOCKS_HOST": ("tor_socks_host", str),
            "TOR_CONTROL_PORT": ("control_port", int),
            "TOR_SOCKS_PORT": ("socks_port_base", int),
            "TORPOOL_OUTPUT_DIR": ("output_dir", Path),
            "TORPOOL_STATE_DIR": ("state_dir", Path),
            "TORPOOL_TEMP_DIR": ("temp_dir", Path),
            "TORPOOL_LOG_FILE": ("log_file", Path),
            "TORPOOL_QBITTORRENT_EXECUTABLE": ("qbittorrent_executable", str),
            "TORPOOL_QBITTORRENT_TEMP_PROFILE_DIR": ("qbittorrent_temp_profile_dir", Path),
            "TORPOOL_TORRENT_MODE": ("torrent_mode", str),
            "TORPOOL_CIRCUITS": ("circuits", int),
            "TORPOOL_CIRCUIT_CREATION_DELAY": ("circuit_creation_delay", float),
            "TORPOOL_MAX_BANDWIDTH": ("max_bandwidth", int),
        }
        for env_name, (attr, caster) in env_map.items():
            raw = os.environ.get(env_name)
            if not raw:
                continue
            try:
                setattr(cfg, attr, caster(raw))
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"Invalid value for {env_name}: {exc}") from exc

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
