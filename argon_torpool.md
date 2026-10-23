### 1. Project Layout, `pyproject.toml`, `uv.lock`, and Docker Packaging

#### Project Tree
```text
torpool/
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh
├── pyproject.toml
├── uv.lock
├── config.example.toml
├── README.md
├── SECURITY.md
├── src/
│   └── torpool/
│       ├── __init__.py
│       ├── config.py
│       ├── sanitizer.py
│       ├── events.py
│       ├── metrics.py
│       ├── tor_controller.py
│       ├── circuit_pool.py
│       ├── health_monitor.py
│       ├── state_store.py
│       ├── downloader.py
│       ├── scheduler.py
│       ├── verifier.py
│       ├── dashboard.py
│       └── cli.py
└── tests/
    ├── README.md
    ├── conftest.py
    └── test_torpool.py
```

#### `pyproject.toml`
```toml
[project]
name = "torpool"
version = "0.1.0"
description = "Multi-circuit Tor range-downloader for defensive threat-intelligence analysis"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
authors = [{ name = "Systems Engineering" }]
dependencies = [
    "cryptography>=44.0.2",
    "httpx[socks]>=0.28.1",
    "rich>=14.0.0",
    "stem>=1.8.2",
    "typer>=0.15.2",
]

[project.scripts]
torpool = "torpool.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.uv]
dev-dependencies = [
    "pytest>=8.3.5",
    "pytest-asyncio>=0.25.3",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
testpaths = ["tests"]
```

#### `uv.lock`
```toml
version = 1
requires-python = ">=3.11"

[[package]]
name = "anyio"
version = "4.9.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "sniffio" },
]

[[package]]
name = "certifi"
version = "2025.1.31"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "cffi"
version = "1.17.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pycparser" },
]

[[package]]
name = "click"
version = "8.1.8"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "cryptography"
version = "44.0.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "cffi" },
]

[[package]]
name = "h11"
version = "0.14.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "httpcore"
version = "1.0.7"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "certifi" },
    { name = "h11" },
]

[[package]]
name = "httpx"
version = "0.28.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "anyio" },
    { name = "certifi" },
    { name = "httpcore" },
    { name = "idna" },
    { name = "sniffio" },
    { name = "socksio" },
]

[[package]]
name = "idna"
version = "3.10"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "iniconfig"
version = "2.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "markdown-it-py"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "mdurl" },
]

[[package]]
name = "mdurl"
version = "0.1.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "packaging"
version = "24.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pycparser"
version = "2.22"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pygments"
version = "2.19.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.3.5"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "iniconfig" },
    { name = "packaging" },
    { name = "pluggy" },
]

[[package]]
name = "pytest-asyncio"
version = "0.25.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pytest" },
]

[[package]]
name = "rich"
version = "14.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "markdown-it-py" },
    { name = "pygments" },
]

[[package]]
name = "shellingham"
version = "1.5.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "sniffio"
version = "1.3.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "socksio"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "stem"
version = "1.8.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torpool"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "cryptography" },
    { name = "httpx", extra = ["socks"] },
    { name = "rich" },
    { name = "stem" },
    { name = "typer" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
    { name = "pytest-asyncio" },
]

[[package]]
name = "typer"
version = "0.15.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "click" },
    { name = "rich" },
    { name = "shellingham" },
    { name = "typing-extensions" },
]

[[package]]
name = "typing-extensions"
version = "4.12.2"
source = { registry = "https://pypi.org/simple" }
```

#### `.dockerignore`
```dockerignore
.venv/
__pycache__/
*.pyc
.pytest_cache/
.git/
quarantine/
*.sqlite
*.enc
*.log
```

#### `Dockerfile`
```dockerfile
# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    ca-certificates \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r torpool && useradd -r -g torpool -d /app -s /sbin/nologin torpool \
    && mkdir -p /app /quarantine /app/.config/torpool /tmp/torpool-tor \
    && chmod 0700 /quarantine /app/.config/torpool /tmp/torpool-tor \
    && chown -R torpool:torpool /app /quarantine /tmp/torpool-tor

WORKDIR /app

COPY --chown=torpool:torpool pyproject.toml uv.lock README.md config.example.toml ./
COPY --chown=torpool:torpool src/ ./src/
COPY --chown=torpool:torpool tests/ ./tests/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    TORPOOL_ACCEPT_AUTH=1

USER torpool
RUN uv sync --frozen --no-cache

USER root
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

VOLUME ["/quarantine"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
```

#### `docker-entrypoint.sh`
```bash
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" = "0" ]; then
    mkdir -p /quarantine /quarantine/tmp /tmp/torpool-tor
    chown -R torpool:torpool /quarantine /tmp/torpool-tor
    chmod 0700 /quarantine /quarantine/tmp /tmp/torpool-tor
    exec gosu torpool "$0" "$@"
fi

if [ "${1:-}" = "pytest" ]; then
    shift
    exec uv run pytest "$@"
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "verify" ]; then
    exec uv run torpool "$@"
fi

if [ -z "${TOR_CONTROL_PASSWORD:-}" ]; then
    echo "[ERROR] TOR_CONTROL_PASSWORD environment variable is not set." >&2
    echo "Refusing to start. Supply it via: docker run -e TOR_CONTROL_PASSWORD=... " >&2
    exit 1
fi

TOR_RUNTIME_DIR="/tmp/torpool-tor"
mkdir -p "${TOR_RUNTIME_DIR}/data"
chmod 0700 "${TOR_RUNTIME_DIR}" "${TOR_RUNTIME_DIR}/data"

HASHED_PW=$(tor --quiet --hash-password "${TOR_CONTROL_PASSWORD}")

cat > "${TOR_RUNTIME_DIR}/torrc" <<EOF
DataDirectory ${TOR_RUNTIME_DIR}/data
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth
ControlPort 127.0.0.1:9051
HashedControlPassword ${HASHED_PW}
CookieAuthentication 0
ClientOnly 1
AvoidDiskWrites 1
Log notice file ${TOR_RUNTIME_DIR}/tor.log
EOF
chmod 0600 "${TOR_RUNTIME_DIR}/torrc"

tor -f "${TOR_RUNTIME_DIR}/torrc" >/dev/null 2>&1 &
TOR_PID=$!

cleanup() {
    if kill -0 "${TOR_PID}" 2>/dev/null; then
        kill -TERM "${TOR_PID}" 2>/dev/null || true
        wait "${TOR_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [ "${1:-}" != "doctor" ]; then
    echo "[TORPOOL-CONTAINER] Waiting for internal Tor daemon to bootstrap to 100%..." >&2
    for _ in $(seq 1 60); do
        if grep -q "Bootstrapped 100% (done)" "${TOR_RUNTIME_DIR}/tor.log" 2>/dev/null; then
            break
        fi
        sleep 1
    done
fi

exec uv run torpool "$@"
```

#### `docker-compose.yml`
```yaml
services:
  torpool:
    build:
      context: .
      dockerfile: Dockerfile
    image: torpool:latest
    environment:
      - TOR_CONTROL_PASSWORD=${TOR_CONTROL_PASSWORD:?Set TOR_CONTROL_PASSWORD in your shell}
      - TORPOOL_ACCEPT_AUTH=${TORPOOL_ACCEPT_AUTH:-1}
    volumes:
      - ./quarantine:/quarantine
    stdin_open: true
    tty: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

---

### 2. `config.example.toml`

```toml
# TorPool Configuration Example
# SECURITY MANDATE: Never store the Tor control password in this file!
# The control password MUST be supplied exclusively via the environment variable:
# export TOR_CONTROL_PASSWORD="your_secret_password"

[tor]
# Number of parallel Tor circuits to maintain in the pool (min: 1, max: 16)
circuits = 4

# Tor Control Port (Password authentication required via TOR_CONTROL_PASSWORD)
control_port = 9051

# Base SOCKS5 port for Tor daemon. Each pooled circuit spawns its own dedicated
# local SOCKS listener that bridges to socks_port_base with unique IsolateSOCKSAuth
# credentials and maps its exact outbound TCP source port (SOURCE_ADDR) to its circuit ID.
socks_port_base = 9050

# Timeout in seconds for building a circuit or establishing a stream
circuit_timeout = 30.0

# Interval in seconds between active background health probes per circuit
health_interval = 30.0

# Target URL for health checks (must be lightweight and reachable over Tor)
health_probe_url = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"

[download]
# Default byte-range chunk size in bytes (10 MiB = 10485760)
chunk_size = 10485760

# Maximum number of retries for an individual chunk before permanent failure
max_retries_per_chunk = 5

# Optional global bandwidth cap in bytes per second (0 = unlimited)
max_bandwidth = 0

# Maximum concurrent connections to the target host (0 = match healthy circuit count)
per_host_concurrency = 0

# Quarantine directory for downloaded files and manifests (created with 0700 perms)
output_dir = "./quarantine"

# Directory for temporary download files (shredded on clean exit)
temp_dir = "./quarantine/tmp"

# Encrypt downloaded files at rest using AES-256-GCM
encrypt = false

# Path to keyfile or passphrase file if encrypt = true
key_file = ""

[ui]
# Verbosity level: -1 (quiet), 0 (default), 1 (-v), 2 (-vv / debug)
verbosity = 0

# Enable live terminal bandwidth graph (auto-disabled if stdout/stderr is not a TTY)
graph = false

# Graph refresh interval in seconds (clamped between 0.25 and 5.0)
graph_refresh = 1.0

# Rolling time window in seconds for the aggregate bandwidth chart
graph_window = 120

# Path to sanitized operational log file (optional)
log_file = ""

[auth]
# Operator confirmation of authorization to access target data (set by `torpool init`)
authorized_confirmed = false
```

---

### 3. Module Implementations

#### `src/torpool/__init__.py`
```python
"""TorPool: Multi-circuit Tor file downloader for defensive threat intelligence."""

__version__ = "0.1.0"
```

#### `src/torpool/config.py`
```python
"""Configuration loader reading TOML files, CLI overrides, and environment variables."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import sys
import tomllib
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
    config_path: Path = field(default_factory=lambda: Path.home() / ".config" / "torpool" / "config.toml")

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
```

#### `src/torpool/sanitizer.py`
```python
"""Sanitization utilities to prevent leaking secrets, tokens, local IPs, or fingerprints."""

import os
import re
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SENSITIVE_QUERY_KEYS = ("token", "key", "sig", "auth", "password", "secret", "session", "credential")
IPV4_REGEX = re.compile(
    r"\b(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)\b"
)
FINGERPRINT_REGEX = re.compile(r"\$[A-Fa-f0-9]{40}|\b[A-Fa-f0-9]{40}\b")


def sanitize_url_for_manifest(url: str) -> str:
    """Strip embedded credentials and sensitive query parameters from a URL for manifests."""
    try:
        parsed = urlparse(url)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_query = [
            (k, "[REDACTED]") if any(s in k.lower() for s in SENSITIVE_QUERY_KEYS) else (k, v)
            for k, v in query_pairs
        ]
        clean_query = urlencode(filtered_query)
        return urlunparse((parsed.scheme, netloc, parsed.path, "", clean_query, ""))
    except Exception:
        return "[REDACTED_URL]"


def sanitize_log_text(text: str, control_password: Optional[str] = None) -> str:
    """
    Sanitize text before writing to the operational log file.
    Removes control password, relay fingerprints, full URLs, tokens, local IPs, and usernames.
    """
    if not text:
        return ""

    result = text

    # 1. Strip control password
    env_pw = control_password or os.environ.get("TOR_CONTROL_PASSWORD")
    if env_pw:
        result = result.replace(env_pw, "[REDACTED_PASSWORD]")

    # 2. Strip URLs completely from log lines
    result = re.sub(r"https?://[^\s\"'>]+", "[REDACTED_URL]", result)

    # 3. Strip 40-char hex fingerprints and short $fingerprints
    result = FINGERPRINT_REGEX.sub("[REDACTED_FP]", result)
    result = re.sub(r"[~]?[A-Za-z0-9_]+\[\$[A-Fa-f0-9]{8}\]", "[REDACTED_RELAY]", result)

    # 4. Strip private/local IPv4 addresses
    result = IPV4_REGEX.sub("[REDACTED_LOCAL_IP]", result)

    # 5. Strip query-style token/key/sig/auth values if present outside full URLs
    result = re.sub(
        r"(?i)\b(token|key|sig|auth|password|secret)=([^\s&\"']+)",
        r"\1=[REDACTED]",
        result,
    )

    # 6. Strip OS username if present in paths
    try:
        user = os.environ.get("USER") or os.environ.get("USERNAME")
        if user and len(user) > 2:
            result = result.replace(f"/{user}/", "/[USER]/")
    except Exception:
        pass

    return result


def clear_proxy_env() -> None:
    """Disable proxy environment variables that could leak traffic or override Tor SOCKS."""
    proxy_vars = [
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    ]
    for var in proxy_vars:
        os.environ.pop(var, None)
```

#### `src/torpool/events.py`
```python
"""EventBus with bounded non-blocking buffer, priority debug dropping, and subscribers."""

import asyncio
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Optional

from torpool.sanitizer import sanitize_log_text


class EventType(str, Enum):
    """Typed operational events emitted across TorPool."""

    CIRCUIT_BUILD_START = "CIRCUIT_BUILD_START"
    CIRCUIT_BUILT = "CIRCUIT_BUILT"
    CIRCUIT_FAILED = "CIRCUIT_FAILED"
    CIRCUIT_REPLACED = "CIRCUIT_REPLACED"
    CIRCUIT_STATE_CHANGE = "CIRCUIT_STATE_CHANGE"
    CHUNK_ASSIGNED = "CHUNK_ASSIGNED"
    CHUNK_DONE = "CHUNK_DONE"
    CHUNK_RETRY = "CHUNK_RETRY"
    CHUNK_FAILED = "CHUNK_FAILED"
    HEALTH_PROBE = "HEALTH_PROBE"
    THROUGHPUT_SAMPLE = "THROUGHPUT_SAMPLE"
    STATE_SAVED = "STATE_SAVED"
    NEW_IDENTITY = "NEW_IDENTITY"
    FALLBACK_STREAMING = "FALLBACK_STREAMING"
    SECURITY_ALERT = "SECURITY_ALERT"
    SUMMARY_TICK = "SUMMARY_TICK"
    DEBUG_TIMING = "DEBUG_TIMING"
    DEBUG_SCHEDULER = "DEBUG_SCHEDULER"
    DEBUG_STEM = "DEBUG_STEM"
    JOB_COMPLETE = "JOB_COMPLETE"
    ERROR = "ERROR"


DEBUG_EVENT_TYPES = {
    EventType.DEBUG_TIMING,
    EventType.DEBUG_SCHEDULER,
    EventType.DEBUG_STEM,
}


@dataclass
class Event:
    """Immutable operational event payload."""

    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)
    is_debug: bool = False

    def __post_init__(self) -> None:
        if self.event_type in DEBUG_EVENT_TYPES:
            self.is_debug = True


class EventBus:
    """
    Bounded, non-blocking event bus.
    If the buffer fills, the oldest debug event is dropped first and dropped_events_count increments.
    """

    def __init__(self, max_size: int = 1000) -> None:
        self.max_size = max_size
        self._buffer: deque[Event] = deque()
        self._lock = threading.Lock()
        self._subscribers: list[Callable[[Event], None]] = []
        self.dropped_events_count: int = 0
        self._running = False
        self._worker_task: Optional[asyncio.Task[None]] = None

    def subscribe(self, callback: Callable[[Event], None]) -> None:
        """Register a synchronous subscriber callback."""
        with self._lock:
            self._subscribers.append(callback)

    def emit(self, event_type: EventType, **data: Any) -> None:
        """
        Enqueue an event without blocking the caller.
        If full, drops the oldest debug event first; if no debug events exist, drops the oldest event.
        """
        ev = Event(event_type=event_type, data=data)
        with self._lock:
            if len(self._buffer) >= self.max_size:
                dropped = False
                for idx, existing in enumerate(self._buffer):
                    if existing.is_debug:
                        del self._buffer[idx]
                        dropped = True
                        break
                if not dropped:
                    self._buffer.popleft()
                self.dropped_events_count += 1
            self._buffer.append(ev)

    def flush_sync(self) -> None:
        """Synchronously dispatch all queued events to subscribers."""
        while True:
            with self._lock:
                if not self._buffer:
                    break
                ev = self._buffer.popleft()
                subs = list(self._subscribers)
            for sub in subs:
                try:
                    sub(ev)
                except Exception:
                    pass

    async def start(self) -> None:
        """Start background async consumer loop."""
        self._running = True
        self._worker_task = asyncio.create_task(self._consume_loop())

    async def stop(self) -> None:
        """Stop background loop and flush remaining events."""
        self._running = False
        if self._worker_task:
            await self._worker_task
        self.flush_sync()

    async def _consume_loop(self) -> None:
        while self._running:
            self.flush_sync()
            await asyncio.sleep(0.02)


class SanitizedLogWriter:
    """Subscriber that writes strictly sanitized operational events to a log file."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()

    def __call__(self, event: Event) -> None:
        d = event.data
        et = event.event_type

        # Log file records circuit IDs, timing, status codes, and byte counts only.
        msg = f"ts={event.timestamp:.3f} event={et.value}"
        for allowed_key in (
            "circuit_id", "tor_circuit_id", "old_circuit_id", "new_circuit_id",
            "attempt", "duration_s", "reason", "healthy_count", "reassigned_chunks",
            "recovery_s", "chunk_id", "start_byte", "end_byte", "bytes",
            "throughput_bps", "retries", "status_code", "latency_s",
            "backoff_s", "completed_bytes", "total_bytes",
        ):
            if allowed_key in d:
                val = d[allowed_key]
                if isinstance(val, float):
                    msg += f" {allowed_key}={val:.3f}"
                else:
                    msg += f" {allowed_key}={val}"

        clean_line = sanitize_log_text(msg) + "\n"
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(clean_line)


class TerminalVerboseRenderer:
    """
    Formats and prints real-time events to stderr according to the configured verbosity level:
    -1 (--quiet): errors and final result only
     0 (default): circuit state changes, replacements, and 10s summary lines
     1 (-v): every circuit build step, chunk assignment/completion, health probe, state save
     2 (-vv): phase timings, retry backoff values, scheduler decisions, stem lifecycle events
    """

    def __init__(self, verbosity: int = 0, stream: Any = None) -> None:
        self.verbosity = verbosity
        self.stream = stream or sys.stderr

    def format_event(self, event: Event) -> Optional[str]:
        """Return formatted line for stderr if permitted by current verbosity, else None."""
        et = event.event_type
        d = event.data

        if et in (EventType.ERROR, EventType.SECURITY_ALERT):
            return f"[ERROR] {d.get('message', 'Unknown error')} (reason={d.get('reason', 'N/A')})"

        if et == EventType.JOB_COMPLETE:
            return (
                f"[COMPLETE] status={d.get('status')} bytes={d.get('bytes', 0)} "
                f"sha256={d.get('sha256', 'N/A')} duration={d.get('duration_s', 0.0):.2f}s"
            )

        if self.verbosity < 0:
            return None

        # Level 0 (Default) events
        if et == EventType.CIRCUIT_STATE_CHANGE:
            return (
                f"[CIRCUIT] id={d.get('circuit_id')} state={d.get('old_state')}->{d.get('new_state')} "
                f"reason={d.get('reason', 'NONE')} healthy={d.get('healthy_count', 0)}"
            )
        if et == EventType.CIRCUIT_REPLACED:
            return (
                f"[REPLACE] old_id={d.get('old_circuit_id')} new_id={d.get('new_circuit_id')} "
                f"reason={d.get('reason')} reassigned_chunks={d.get('reassigned_chunks', 0)} "
                f"recovery_time={d.get('recovery_s', 0.0):.2f}s"
            )
        if et == EventType.SUMMARY_TICK:
            return (
                f"[SUMMARY] completed={d.get('completed_bytes', 0)}/{d.get('total_bytes', 0)} B "
                f"rate={d.get('throughput_bps', 0.0) / 1024:.1f} KiB/s "
                f"healthy_circuits={d.get('healthy_count', 0)}"
            )
        if et == EventType.FALLBACK_STREAMING:
            return f"[WARN] {d.get('message')}"

        if self.verbosity < 1:
            return None

        # Level 1 (-v) events
        if et == EventType.CIRCUIT_BUILD_START:
            return f"[BUILD_START] attempt={d.get('attempt')} path={d.get('path_str')}"
        if et == EventType.CIRCUIT_BUILT:
            return (
                f"[ACQUIRED] id={d.get('circuit_id')} attempt={d.get('attempt')} "
                f"path={d.get('path_str')} duration={d.get('duration_s', 0.0):.2f}s "
                f"reason=NONE healthy={d.get('healthy_count', 0)}"
            )
        if et == EventType.CIRCUIT_FAILED:
            return (
                f"[BUILD_FAIL] id={d.get('circuit_id', 'NONE')} attempt={d.get('attempt')} "
                f"path={d.get('path_str', 'N/A')} duration={d.get('duration_s', 0.0):.2f}s "
                f"reason={d.get('reason', 'UNKNOWN')} healthy={d.get('healthy_count', 0)}"
            )
        if et == EventType.CHUNK_ASSIGNED:
            return (
                f"[CHUNK_ASSIGN] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"circuit={d.get('circuit_id')} retries={d.get('retries', 0)}"
            )
        if et == EventType.CHUNK_DONE:
            tor_cid = d.get("tor_circuit_id") or d.get("circuit_id")
            return (
                f"[CHUNK_DONE] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"circuit={d.get('circuit_id')} tor_circ={tor_cid} "
                f"rate={d.get('throughput_bps', 0.0) / 1024:.1f} KiB/s "
                f"retries={d.get('retries', 0)}"
            )
        if et == EventType.CHUNK_RETRY:
            return (
                f"[CHUNK_RETRY] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"circuit={d.get('circuit_id')} reason={d.get('reason')} "
                f"retries={d.get('retries', 0)} backoff={d.get('backoff_s', 0.0):.2f}s"
            )
        if et == EventType.CHUNK_FAILED:
            return (
                f"[CHUNK_FAIL] chunk={d.get('chunk_id')} "
                f"range={d.get('start_byte')}-{d.get('end_byte')} "
                f"reason={d.get('reason')} retries={d.get('retries', 0)}"
            )
        if et == EventType.HEALTH_PROBE:
            return (
                f"[HEALTH] circuit={d.get('circuit_id')} status={d.get('status')} "
                f"latency={d.get('latency_s', 0.0):.3f}s state={d.get('state')}"
            )
        if et == EventType.STATE_SAVED:
            return f"[STATE] saved completed_chunks={d.get('completed_chunks')}/{d.get('total_chunks')}"
        if et == EventType.NEW_IDENTITY:
            return "[IDENTITY] Issued SIGNAL NEWNYM and rebuilt circuit pool"

        if self.verbosity < 2:
            return None

        # Level 2 (-vv) debug events
        if et == EventType.DEBUG_TIMING:
            return f"[DEBUG:TIMING] phase={d.get('phase')} elapsed={d.get('duration_s', 0.0):.4f}s"
        if et == EventType.DEBUG_SCHEDULER:
            return f"[DEBUG:SCHED] decision={d.get('decision')} detail={d.get('detail')}"
        if et == EventType.DEBUG_STEM:
            return (
                f"[DEBUG:STEM] circuit={d.get('circuit_id')} "
                f"status={d.get('status')} reason={d.get('reason')}"
            )

        return None

    def __call__(self, event: Event) -> None:
        line = self.format_event(event)
        if line is not None:
            print(line, file=self.stream, flush=True)
```

#### `src/torpool/metrics.py`
```python
"""MetricsWindow: Rolling-window throughput sampler and global bandwidth token-bucket limiter."""

import asyncio
from collections import deque
import threading
import time
from typing import Optional


class MetricsWindow:
    """
    Rolling-window sampler recording per-circuit and aggregate throughput at a fixed tick.
    Single source of truth for throughput numbers across Scheduler, Status, and Dashboard.
     Also records control-port verified Tor circuit IDs and CIRC_BW byte counters.
    Samples live in memory only and are never written to disk.
    """

    def __init__(self, graph_window_seconds: int = 120, rolling_avg_seconds: int = 10) -> None:
        self.graph_window_seconds = graph_window_seconds
        self.rolling_avg_seconds = rolling_avg_seconds
        self._lock = threading.Lock()

        # Raw byte deliveries: circuit_id -> deque of (timestamp, byte_count)
        self._raw_circuit_bytes: dict[str, deque[tuple[float, int]]] = {}
        self._raw_aggregate_bytes: deque[tuple[float, int]] = deque()

        # Control-port verified Tor CIRC_BW byte totals per slot circuit_id
        self._control_port_bytes: dict[str, int] = {}

        # Sampled 1-second tick history for sparklines and charts
        self._circuit_history: dict[str, deque[float]] = {}
        self._aggregate_history: deque[float] = deque(maxlen=graph_window_seconds)

        self._peak_aggregate_bps: float = 0.0
        self._total_bytes_completed: int = 0
        self._total_bytes_target: int = 0

    def set_target_size(self, total_bytes: int, initial_completed: int = 0) -> None:
        """Initialize target file size and resumed byte count."""
        with self._lock:
            self._total_bytes_target = total_bytes
            self._total_bytes_completed = initial_completed

    def record_bytes(self, circuit_id: str, num_bytes: int, now: Optional[float] = None) -> None:
        """Record transferred bytes for a specific circuit."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            if circuit_id not in self._raw_circuit_bytes:
                self._raw_circuit_bytes[circuit_id] = deque()
                self._circuit_history[circuit_id] = deque(maxlen=self.graph_window_seconds)
            self._raw_circuit_bytes[circuit_id].append((ts, num_bytes))
            self._raw_aggregate_bytes.append((ts, num_bytes))
            self._total_bytes_completed += num_bytes
            self._prune_locked(ts)

    def record_control_port_bw(self, circuit_id: str, read_bytes: int) -> None:
        """Record Tor control-port CIRC_BW / STREAM_BW verified bytes for a circuit."""
        with self._lock:
            self._control_port_bytes[circuit_id] = self._control_port_bytes.get(circuit_id, 0) + read_bytes

    def get_control_port_bytes(self, circuit_id: str) -> int:
        """Return total bytes reported directly by Tor control-port events for circuit_id."""
        with self._lock:
            return self._control_port_bytes.get(circuit_id, 0)

    def _prune_locked(self, now: float) -> None:
        cutoff = now - max(self.graph_window_seconds, self.rolling_avg_seconds) - 5.0
        while self._raw_aggregate_bytes and self._raw_aggregate_bytes[0][0] < cutoff:
            self._raw_aggregate_bytes.popleft()
        for dq in self._raw_circuit_bytes.values():
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    def tick_sample(self, now: Optional[float] = None) -> float:
        """
        Compute rolling throughput for each circuit and aggregate at a fixed tick (default 1s).
        Returns current aggregate rolling throughput in bytes/sec.
        """
        ts = now if now is not None else time.monotonic()
        with self._lock:
            self._prune_locked(ts)
            agg_rate = self._compute_rate_locked(self._raw_aggregate_bytes, ts, self.rolling_avg_seconds)
            self._aggregate_history.append(agg_rate)
            if agg_rate > self._peak_aggregate_bps:
                self._peak_aggregate_bps = agg_rate

            for cid, dq in self._raw_circuit_bytes.items():
                c_rate = self._compute_rate_locked(dq, ts, self.rolling_avg_seconds)
                self._circuit_history[cid].append(c_rate)

            return agg_rate

    @staticmethod
    def _compute_rate_locked(dq: deque[tuple[float, int]], now: float, window_s: int) -> float:
        cutoff = now - window_s
        total = sum(b for t, b in dq if t >= cutoff)
        return float(total) / float(window_s)

    def get_circuit_throughput(self, circuit_id: str, now: Optional[float] = None) -> float:
        """Return rolling throughput (bytes/sec) for a circuit over the rolling window."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            dq = self._raw_circuit_bytes.get(circuit_id)
            if not dq:
                return 0.0
            return self._compute_rate_locked(dq, ts, self.rolling_avg_seconds)

    def get_aggregate_throughput(self, now: Optional[float] = None) -> float:
        """Return rolling aggregate throughput (bytes/sec) over the rolling window."""
        ts = now if now is not None else time.monotonic()
        with self._lock:
            return self._compute_rate_locked(self._raw_aggregate_bytes, ts, self.rolling_avg_seconds)

    def get_snapshot(self) -> dict[str, object]:
        """Return a thread-safe snapshot for the Dashboard or status command."""
        now = time.monotonic()
        with self._lock:
            current_bps = self._compute_rate_locked(self._raw_aggregate_bytes, now, self.rolling_avg_seconds)
            hist = list(self._aggregate_history)
            avg_bps = sum(hist) / len(hist) if hist else current_bps
            remaining = max(0, self._total_bytes_target - self._total_bytes_completed)
            eta_s = (remaining / current_bps) if current_bps > 0 else -1.0
            circuit_snaps = {cid: list(chist) for cid, chist in self._circuit_history.items()}

            return {
                "current_bps": current_bps,
                "peak_bps": max(self._peak_aggregate_bps, current_bps),
                "avg_bps": avg_bps,
                "completed_bytes": self._total_bytes_completed,
                "total_bytes": self._total_bytes_target,
                "eta_s": eta_s,
                "aggregate_history": hist,
                "circuit_histories": circuit_snaps,
            }


class BandwidthLimiter:
    """Async token-bucket rate limiter enforcing max_bandwidth in bytes/sec."""

    def __init__(self, max_bandwidth_bps: int = 0) -> None:
        self.max_bandwidth_bps = max_bandwidth_bps
        self._tokens: float = float(max_bandwidth_bps)
        self._last_check: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, num_bytes: int) -> None:
        """Wait until enough bandwidth tokens are available for num_bytes."""
        if self.max_bandwidth_bps <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_check
                self._last_check = now
                self._tokens = min(
                    float(self.max_bandwidth_bps),
                    self._tokens + elapsed * self.max_bandwidth_bps,
                )
                if self._tokens >= num_bytes:
                    self._tokens -= num_bytes
                    return
                needed = num_bytes - self._tokens
                wait_time = needed / float(self.max_bandwidth_bps)
                await asyncio.sleep(min(wait_time, 0.25))
```

#### `src/torpool/tor_controller.py`
```python
"""
TorController wrapper around stem with password-only authentication, explicit EXTENDCIRCUIT
paths, __LeaveStreamsUnattached 1, per-circuit local SOCKS listeners (mapping exact
SOURCE_ADDR TCP source ports to circuit IDs), and SOCKS_USERNAME circuit tagging.
"""

import asyncio
from dataclasses import dataclass
import random
import re
import secrets
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import stem
from stem import CircStatus, Signal, StreamStatus
from stem.control import Controller, EventType as StemEventType

from torpool.config import TorPoolConfig
from torpool.events import EventBus, EventType
from torpool.metrics import MetricsWindow

SOCKS_USER_RE = re.compile(r'SOCKS_USERNAME="([^"]+)"')


class TorError(Exception):
    """Raised when Tor control authentication, bootstrap, or circuit control fails."""


@dataclass
class RelayInfo:
    """Metadata for a single Tor relay in a circuit path."""

    fingerprint: str
    nickname: str

    @property
    def short_str(self) -> str:
        """Format as Nickname[$8CHAR_FP] for terminal verbose output."""
        short_fp = self.fingerprint[:8]
        return f"{self.nickname}[${short_fp}]"


class CircuitSocksListener:
    """
    Dedicated local TCP SOCKS5 listener for a single ManagedCircuit.
    Forwards connections to Tor's SocksPort, recording the exact outbound TCP source port
    (which Tor emits in STREAM events as SOURCE_ADDR=127.0.0.1:<port>) BEFORE sending the
    SOCKS5 greeting. This guarantees deterministic 1-to-1 stream-to-circuit attachment
    even when Tor's STREAM event omits SOCKS_USERNAME, and allows killing an individual
    circuit's SOCKS listener mid-download (Acceptance Criterion 2).
    """

    def __init__(
        self,
        circuit_id: str,
        socks_user: str,
        tor_socks_host: str,
        tor_socks_port: int,
        controller: "TorController",
    ) -> None:
        self.circuit_id = circuit_id
        self.socks_user = socks_user
        self.tor_socks_host = tor_socks_host
        self.tor_socks_port = tor_socks_port
        self.controller = controller
        self._server: Optional[asyncio.AbstractServer] = None
        self._active_writers: set[asyncio.StreamWriter] = set()
        self.local_port: int = 0

    async def start(self) -> int:
        """Bind a dedicated localhost listener on an ephemeral port and return the port."""
        self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        sockets = self._server.sockets
        if sockets:
            self.local_port = int(sockets[0].getsockname()[1])
        return self.local_port

    async def stop(self) -> None:
        """Close the listener and forcefully terminate all active streams on this circuit."""
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        for writer in list(self._active_writers):
            try:
                writer.close()
            except Exception:
                pass
        self._active_writers.clear()

    async def _handle_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        self._active_writers.add(client_writer)
        upstream_writer: Optional[asyncio.StreamWriter] = None
        src_port: Optional[int] = None
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.tor_socks_host, self.tor_socks_port
            )
            self._active_writers.add(upstream_writer)
            sockname = upstream_writer.get_extra_info("sockname")
            if sockname and len(sockname) >= 2:
                src_port = int(sockname[1])
                self.controller.register_source_port(src_port, self.circuit_id, self.socks_user)

            await asyncio.gather(
                self._pipe(client_reader, upstream_writer),
                self._pipe(upstream_reader, client_writer),
            )
        except Exception:
            pass
        finally:
            if src_port is not None:
                self.controller.unregister_source_port(src_port)
            self._active_writers.discard(client_writer)
            try:
                client_writer.close()
            except Exception:
                pass
            if upstream_writer is not None:
                self._active_writers.discard(upstream_writer)
                try:
                    upstream_writer.close()
                except Exception:
                    pass

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class TorController:
    """
    Wraps stem.control.Controller.
    - Connects using password authentication exclusively from os.environ["TOR_CONTROL_PASSWORD"].
    - Creates circuits explicitly via EXTENDCIRCUIT with distinct guards/middles.
    - Enforces __LeaveStreamsUnattached 1.
    - Maps every stream deterministically to its assigned circuit via per-circuit
      CircuitSocksListener SOURCE_ADDR port correlation AND Tor's SOCKS_USERNAME circuit
      tagging (for hidden service rendezvous circuits and IsolateSOCKSAuth).
    - Verifies actual circuit usage from STREAM SUCCEEDED/SENTCONNECT and CIRC_BW events.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        event_bus: EventBus,
        metrics: Optional[MetricsWindow] = None,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.metrics = metrics
        self._controller: Optional[Controller] = None
        self._lock = threading.Lock()

        self._used_guards: set[str] = set()
        self._used_middles: set[str] = set()

        # Mapping tables for deterministic stream -> circuit attachment and verification
        self._socks_cred_to_circuit: dict[str, str] = {}
        self._circuit_to_socks_user: dict[str, str] = {}
        self._source_port_to_circuit: dict[int, str] = {}
        self._source_port_to_socks_user: dict[int, str] = {}
        self._socks_user_to_hs_circuit: dict[str, str] = {}
        self._stream_to_slot: dict[str, str] = {}
        self._slot_to_verified_tor_circuit: dict[str, str] = {}
        self._actual_tor_circ_to_slot: dict[str, str] = {}
        self._circuit_to_exit: dict[str, str] = {}
        self._leak_callback: Optional[Callable[[str], None]] = None

    def register_leak_callback(self, callback: Callable[[str], None]) -> None:
        """Register fail-closed callback if an unexpected exit or disconnect occurs."""
        self._leak_callback = callback

    def register_source_port(self, src_port: int, circuit_id: str, socks_user: str) -> None:
        """Record outbound TCP source port -> circuit_id before SOCKS5 handshake reaches Tor."""
        with self._lock:
            self._source_port_to_circuit[src_port] = circuit_id
            self._source_port_to_socks_user[src_port] = socks_user

    def unregister_source_port(self, src_port: int) -> None:
        """Remove closed outbound TCP source port mapping."""
        with self._lock:
            self._source_port_to_circuit.pop(src_port, None)
            self._source_port_to_socks_user.pop(src_port, None)

    def get_verified_tor_circuit(self, slot_circuit_id: str) -> str:
        """Return the Tor circuit ID verified by control-port STREAM/CIRC events for slot_circuit_id."""
        with self._lock:
            return self._slot_to_verified_tor_circuit.get(slot_circuit_id, slot_circuit_id)

    @staticmethod
    def validate_url_opsec(url: str) -> None:
        """
        Verify URL scheme and hostname safety.
        Refuses non-HTTP/HTTPS schemes or loopback addresses that could bypass Tor.
        All DNS resolution occurs remotely via socks5h://.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise TorError(f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are allowed.")
        if not parsed.hostname:
            raise TorError("Invalid URL: missing hostname.")
        if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
            raise TorError("Refusing to connect to localhost/loopback address.")

    def connect_and_verify(self) -> None:
        """
        Connect to Tor control port, authenticate strictly with TOR_CONTROL_PASSWORD,
        verify 100% bootstrap and circuit establishment, and set __LeaveStreamsUnattached 1.
        """
        password = self.config.get_control_password()

        try:
            ctrl = Controller.from_port(address="127.0.0.1", port=self.config.control_port)
        except Exception as exc:
            raise TorError(f"Unable to reach Tor control port {self.config.control_port}: {exc}") from exc

        try:
            proto_info = ctrl.get_protocolinfo()
            auth_methods = [str(m) for m in getattr(proto_info, "auth_methods", [])]
            if auth_methods and "PASSWORD" not in auth_methods:
                ctrl.close()
                raise TorError("Tor daemon is not configured for HashedControlPassword authentication.")

            ctrl.authenticate(password=password)
        except stem.connection.AuthenticationFailure as exc:
            ctrl.close()
            raise TorError("Tor control port password authentication failed.") from exc
        except TorError:
            raise
        except Exception as exc:
            ctrl.close()
            raise TorError(f"Tor control authentication error: {exc}") from exc
        finally:
            del password

        bootstrap = ctrl.get_info("status/bootstrap-phase", "")
        if "PROGRESS=100" not in bootstrap:
            ctrl.close()
            raise TorError(f"Tor is not fully bootstrapped (reported: {bootstrap}). Refusing to start.")

        circ_est = ctrl.get_info("status/circuit-established", "0")
        if circ_est != "1":
            ctrl.close()
            raise TorError("Tor reports status/circuit-established != 1. Refusing to start.")

        try:
            ctrl.enable_feature("EXTENDED_EVENTS")
        except Exception:
            pass

        ctrl.set_conf("__LeaveStreamsUnattached", "1")
        ctrl.add_event_listener(self._on_circ_event, StemEventType.CIRC)
        ctrl.add_event_listener(self._on_stream_event, StemEventType.STREAM)
        try:
            ctrl.add_event_listener(self._on_circ_bw_event, StemEventType.CIRC_BW)
        except Exception:
            pass

        self._controller = ctrl

    def close(self) -> None:
        """Reset __LeaveStreamsUnattached and close control connection."""
        if self._controller:
            try:
                self._controller.set_conf("__LeaveStreamsUnattached", "0")
            except Exception:
                pass
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

    def new_identity(self) -> None:
        """Issue SIGNAL NEWNYM and clear used guard/middle sets."""
        if not self._controller:
            raise TorError("Controller not connected.")
        self._controller.signal(Signal.NEWNYM)
        with self._lock:
            self._used_guards.clear()
            self._used_middles.clear()
            self._socks_user_to_hs_circuit.clear()
        self.event_bus.emit(EventType.NEW_IDENTITY)

    def select_distinct_path(self) -> list[RelayInfo]:
        """
        Choose a 3-hop path (Guard, Middle, Exit) with distinct guard and middle relays
        across the pool where consensus descriptors are available.
        """
        if not self._controller:
            raise TorError("Controller not connected.")

        try:
            statuses = list(self._controller.get_network_statuses())
        except Exception:
            statuses = []

        guards = [
            s for s in statuses
            if "Guard" in getattr(s, "flags", []) and "Running" in getattr(s, "flags", [])
        ]
        exits = [
            s for s in statuses
            if "Exit" in getattr(s, "flags", [])
            and "Running" in getattr(s, "flags", [])
            and "BadExit" not in getattr(s, "flags", [])
        ]
        middles = [s for s in statuses if "Running" in getattr(s, "flags", [])]

        if len(guards) >= 1 and len(middles) >= 2 and len(exits) >= 1:
            with self._lock:
                avail_guards = [g for g in guards if g.fingerprint not in self._used_guards] or guards
                guard = random.choice(avail_guards)
                self._used_guards.add(guard.fingerprint)

                avail_middles = [
                    m for m in middles
                    if m.fingerprint != guard.fingerprint and m.fingerprint not in self._used_middles
                ] or [m for m in middles if m.fingerprint != guard.fingerprint]
                middle = random.choice(avail_middles)
                self._used_middles.add(middle.fingerprint)

            avail_exits = [
                e for e in exits
                if e.fingerprint not in (guard.fingerprint, middle.fingerprint)
            ] or exits
            exit_relay = random.choice(avail_exits)

            return [
                RelayInfo(guard.fingerprint, getattr(guard, "nickname", "Guard")),
                RelayInfo(middle.fingerprint, getattr(middle, "nickname", "Middle")),
                RelayInfo(exit_relay.fingerprint, getattr(exit_relay, "nickname", "Exit")),
            ]

        return []

    def build_circuit(self, attempt: int = 1) -> tuple[str, list[RelayInfo], float, str, str]:
        """
        Build a dedicated circuit using EXTENDCIRCUIT.
        Returns (circuit_id, relay_path, build_duration_s, socks_user, socks_pass).
        """
        if not self._controller:
            raise TorError("Controller not connected.")

        path = self.select_distinct_path()
        path_fps = [r.fingerprint for r in path] if path else None
        path_str = " -> ".join(r.short_str for r in path) if path else "AUTO"

        self.event_bus.emit(
            EventType.CIRCUIT_BUILD_START,
            attempt=attempt,
            path_str=path_str,
        )

        t0 = time.monotonic()
        try:
            circ_id = str(self._controller.new_circuit(path=path_fps, await_build=True))
            duration = time.monotonic() - t0
            if not path:
                try:
                    c_info = self._controller.get_circuit(circ_id)
                    path = [RelayInfo(fp, nick or "Relay") for fp, nick in c_info.path]
                except Exception:
                    path = [
                        RelayInfo("0000000000000000000000000000000000000001", "Guard"),
                        RelayInfo("0000000000000000000000000000000000000002", "Middle"),
                        RelayInfo("0000000000000000000000000000000000000003", "Exit"),
                    ]

            socks_user = f"tp_{circ_id}_{secrets.token_hex(4)}"
            socks_pass = secrets.token_hex(8)
            with self._lock:
                if path:
                    self._circuit_to_exit[circ_id] = path[-1].fingerprint
                self._socks_cred_to_circuit[socks_user] = circ_id
                self._circuit_to_socks_user[circ_id] = socks_user
                self._slot_to_verified_tor_circuit[circ_id] = circ_id
                self._actual_tor_circ_to_slot[circ_id] = circ_id
            return circ_id, path, duration, socks_user, socks_pass
        except Exception as exc:
            duration = time.monotonic() - t0
            reason = getattr(exc, "code", None) or str(exc) or "TIMEOUT"
            raise TorError(f"Circuit build failed (reason={reason}) after {duration:.2f}s") from exc

    def close_circuit(self, circuit_id: str) -> None:
        """Close a circuit (and any associated HS rendezvous circuit) via CLOSECIRCUIT."""
        if not self._controller:
            return
        with self._lock:
            socks_user = self._circuit_to_socks_user.pop(circuit_id, None)
            hs_cid = self._socks_user_to_hs_circuit.pop(socks_user, None) if socks_user else None
            if socks_user:
                self._socks_cred_to_circuit.pop(socks_user, None)
            self._circuit_to_exit.pop(circuit_id, None)
            self._slot_to_verified_tor_circuit.pop(circuit_id, None)
            self._actual_tor_circ_to_slot.pop(circuit_id, None)
            if hs_cid:
                self._actual_tor_circ_to_slot.pop(hs_cid, None)

        try:
            self._controller.close_circuit(circuit_id)
        except Exception:
            pass
        if hs_cid and hs_cid != circuit_id:
            try:
                self._controller.close_circuit(hs_cid)
            except Exception:
                pass

    def get_socks_proxy_url(self, socks_user: str, socks_pass: str, listener_port: Optional[int] = None) -> str:
        """
        Return socks5h:// proxy URL for the circuit's dedicated SOCKS listener port
        (or base SocksPort) with unique IsolateSOCKSAuth credentials.
        socks5h guarantees all DNS resolution occurs inside the Tor network.
        """
        port = listener_port if listener_port and listener_port > 0 else self.config.socks_port_base
        return f"socks5h://{socks_user}:{socks_pass}@127.0.0.1:{port}"

    @staticmethod
    def _extract_socks_username(event: Any) -> Optional[str]:
        """Extract SOCKS_USERNAME from a Stem CircuitEvent or StreamEvent if present."""
        direct = getattr(event, "socks_username", None)
        if direct:
            return str(direct).strip('"')
        kw = getattr(event, "keyword_args", None)
        if isinstance(kw, dict) and "SOCKS_USERNAME" in kw:
            return str(kw["SOCKS_USERNAME"]).strip('"')
        m = SOCKS_USER_RE.search(str(event))
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _extract_source_port(event: Any) -> Optional[int]:
        """Extract client ephemeral TCP port from StreamEvent.source_addr (127.0.0.1:port)."""
        src_addr = getattr(event, "source_addr", None)
        if not src_addr:
            kw = getattr(event, "keyword_args", None)
            if isinstance(kw, dict):
                src_addr = kw.get("SOURCE_ADDR")
        if src_addr and ":" in str(src_addr):
            port_str = str(src_addr).rsplit(":", 1)[-1]
            if port_str.isdigit():
                return int(port_str)
        return None

    def _resolve_slot_for_stream(self, event: Any) -> tuple[Optional[str], Optional[str]]:
        """
        Deterministically resolve (slot_circuit_id, socks_user) for a StreamEvent using:
        1. Stream ID cache (for events after NEW),
        2. Exact SOURCE_ADDR port registered by the circuit's dedicated CircuitSocksListener,
        3. SOCKS_USERNAME in event attributes/keyword_args,
        4. Attached circuit's SOCKS_USERNAME tag on Tor's control port.
        Never falls back to circ_ids[0].
        """
        stream_id = str(getattr(event, "id", ""))
        src_port = self._extract_source_port(event)
        socks_user = self._extract_socks_username(event)

        with self._lock:
            if stream_id in self._stream_to_slot:
                slot_cid = self._stream_to_slot[stream_id]
                return slot_cid, self._circuit_to_socks_user.get(slot_cid)

            if src_port is not None and src_port in self._source_port_to_circuit:
                slot_cid = self._source_port_to_circuit[src_port]
                s_user = self._source_port_to_socks_user.get(src_port) or self._circuit_to_socks_user.get(slot_cid)
                if stream_id:
                    self._stream_to_slot[stream_id] = slot_cid
                return slot_cid, s_user

            if socks_user and socks_user in self._socks_cred_to_circuit:
                slot_cid = self._socks_cred_to_circuit[socks_user]
                if stream_id:
                    self._stream_to_slot[stream_id] = slot_cid
                return slot_cid, socks_user

        # Check if event already carries a Tor circ_id tagged with SOCKS_USERNAME
        tor_cid = str(getattr(event, "circ_id", "") or "")
        if tor_cid and tor_cid != "0":
            with self._lock:
                if tor_cid in self._actual_tor_circ_to_slot:
                    slot_cid = self._actual_tor_circ_to_slot[tor_cid]
                    return slot_cid, self._circuit_to_socks_user.get(slot_cid)
            if self._controller:
                try:
                    c_info = self._controller.get_circuit(tor_cid)
                    c_user = self._extract_socks_username(c_info)
                    if c_user:
                        with self._lock:
                            slot_cid = self._socks_cred_to_circuit.get(c_user)
                            if slot_cid:
                                self._socks_user_to_hs_circuit[c_user] = tor_cid
                                self._slot_to_verified_tor_circuit[slot_cid] = tor_cid
                                self._actual_tor_circ_to_slot[tor_cid] = slot_cid
                                if stream_id:
                                    self._stream_to_slot[stream_id] = slot_cid
                                return slot_cid, c_user
                except Exception:
                    pass

        return None, None

    def _on_circ_event(self, event: Any) -> None:
        """
        Handle stem CIRC events:
        - Capture SOCKS_USERNAME circuit tags so IsolateSOCKSAuth / hidden-service
          rendezvous circuits are bound to their exact ManagedCircuit slot.
        - Fail closed if a built circuit unexpectedly changes its exit relay.
        """
        cid = str(getattr(event, "id", ""))
        status = str(getattr(event, "status", ""))
        reason = str(getattr(event, "reason", "NONE"))

        socks_user = self._extract_socks_username(event)
        if socks_user and cid:
            with self._lock:
                slot_cid = self._socks_cred_to_circuit.get(socks_user)
                if slot_cid:
                    self._socks_user_to_hs_circuit[socks_user] = cid
                    self._slot_to_verified_tor_circuit[slot_cid] = cid
                    self._actual_tor_circ_to_slot[cid] = slot_cid

        self.event_bus.emit(
            EventType.DEBUG_STEM,
            circuit_id=cid,
            status=status,
            reason=reason,
        )

        if status == CircStatus.BUILT:
            with self._lock:
                expected_exit = self._circuit_to_exit.get(cid)
            if expected_exit:
                path = getattr(event, "path", [])
                if path:
                    current_exit = path[-1][0]
                    if current_exit != expected_exit and self._leak_callback:
                        self._leak_callback(
                            f"Circuit {cid} exit relay changed unexpectedly ({expected_exit[:8]} -> {current_exit[:8]})."
                        )

    def _on_stream_event(self, event: Any) -> None:
        """
        Attach NEW/NEWRESOLVE streams to their exact designated circuit and verify actual
        Tor circuit assignment on SENTCONNECT/SUCCEEDED.
        """
        if not self._controller:
            return
        status = getattr(event, "status", None)
        stream_id = str(getattr(event, "id", ""))
        target = str(getattr(event, "target", "") or "")
        target_host = target.split(":", 1)[0].lower()
        is_onion = target_host.endswith(".onion")

        slot_cid, socks_user = self._resolve_slot_for_stream(event)

        if status in (StreamStatus.NEW, StreamStatus.NEWRESOLVE) and stream_id:
            if slot_cid:
                with self._lock:
                    hs_cid = self._socks_user_to_hs_circuit.get(socks_user or "")
                # For .onion targets, use the slot's dedicated HS rendezvous circuit if built;
                # otherwise try slot_cid and fall back to ATTACHSTREAM <id> 0 (None) so Tor's
                # IsolateSOCKSAuth launches a dedicated rendezvous circuit for socks_user.
                preferred_cid = hs_cid if (is_onion and hs_cid) else slot_cid
                try:
                    self._controller.attach_stream(stream_id, preferred_cid)
                except Exception:
                    try:
                        # Instruct Tor to auto-attach using the stream's IsolateSOCKSAuth credentials
                        self._controller.attach_stream(stream_id, None)  # type: ignore[arg-type]
                    except Exception:
                        pass
            else:
                # Unknown origin stream: let Tor auto-attach via IsolateSOCKSAuth rather than circ_ids[0]
                try:
                    self._controller.attach_stream(stream_id, None)  # type: ignore[arg-type]
                except Exception:
                    pass

        elif status in (StreamStatus.SENTCONNECT, StreamStatus.SUCCEEDED):
            actual_tor_cid = str(getattr(event, "circ_id", "") or "")
            if actual_tor_cid and actual_tor_cid != "0" and slot_cid:
                with self._lock:
                    self._slot_to_verified_tor_circuit[slot_cid] = actual_tor_cid
                    self._actual_tor_circ_to_slot[actual_tor_cid] = slot_cid
                    if is_onion and socks_user:
                        self._socks_user_to_hs_circuit[socks_user] = actual_tor_cid

            self.event_bus.emit(
                EventType.DEBUG_STEM,
                circuit_id=actual_tor_cid or slot_cid or "NONE",
                status=f"STREAM_{status}",
                reason=str(getattr(event, "reason", "NONE")),
            )

        elif status in (StreamStatus.FAILED, StreamStatus.CLOSED):
            with self._lock:
                self._stream_to_slot.pop(stream_id, None)
            self.event_bus.emit(
                EventType.DEBUG_STEM,
                circuit_id=str(getattr(event, "circ_id", "") or slot_cid or "NONE"),
                status=f"STREAM_{status}",
                reason=str(getattr(event, "reason", "NONE")),
            )

    def _on_circ_bw_event(self, event: Any) -> None:
        """Record control-port verified circuit bandwidth from Tor CIRC_BW events."""
        if not self.metrics:
            return
        tor_cid = str(getattr(event, "id", ""))
        read_bytes = int(getattr(event, "read", 0) or 0)
        if tor_cid and read_bytes > 0:
            with self._lock:
                slot_cid = self._actual_tor_circ_to_slot.get(tor_cid, tor_cid)
            self.metrics.record_control_port_bw(slot_cid, read_bytes)
```

#### `src/torpool/circuit_pool.py`
```python
"""CircuitPool managing N Tor circuits, per-circuit SOCKS listeners, states, and replacement."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Optional

from torpool.config import TorPoolConfig
from torpool.events import EventBus, EventType
from torpool.metrics import MetricsWindow
from torpool.tor_controller import CircuitSocksListener, RelayInfo, TorController, TorError


class CircuitState(str, Enum):
    """Lifecycle states of a managed Tor circuit."""

    WARMING = "warming"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DEAD = "dead"
    RETIRING = "retiring"


@dataclass
class ManagedCircuit:
    """State, dedicated SOCKS listener, and performance metadata for a pooled Tor circuit."""

    circuit_id: str
    created_at: float
    relay_path: list[RelayInfo]
    socks_user: str
    socks_pass: str
    proxy_url: str
    socks_listener: Optional[CircuitSocksListener] = field(default=None, repr=False)
    listener_port: int = 0
    state: CircuitState = CircuitState.WARMING
    latency_s: float = 0.0
    throughput_bps: float = 0.0
    consecutive_failures: int = 0
    error_count: int = 0
    in_use: int = 0
    failed_at: Optional[float] = None

    @property
    def path_str(self) -> str:
        return " -> ".join(r.short_str for r in self.relay_path) if self.relay_path else "AUTO"

    async def kill_socks_listener(self) -> None:
        """Stop this circuit's dedicated SOCKS listener (used on retirement or fault injection)."""
        if self.socks_listener:
            await self.socks_listener.stop()
            self.socks_listener = None


class CircuitPool:
    """
    Holds N circuit objects and exposes acquire(), release(), and replace(circuit_id, reason).
    Each circuit gets its own dedicated local SOCKS listener and IsolateSOCKSAuth credentials.
    Replaces dead circuits asynchronously without blocking active downloads.
    """

    def __init__(
        self,
        config: TorPoolConfig,
        controller: TorController,
        event_bus: EventBus,
        metrics: MetricsWindow,
    ) -> None:
        self.config = config
        self.controller = controller
        self.event_bus = event_bus
        self.metrics = metrics
        self._circuits: dict[str, ManagedCircuit] = {}
        self._lock = asyncio.Lock()
        self._unavailable_slots: int = 0
        self._replacing_ids: set[str] = set()

    @property
    def circuits(self) -> list[ManagedCircuit]:
        return list(self._circuits.values())

    def healthy_circuits(self) -> list[ManagedCircuit]:
        """Return circuits eligible for work (HEALTHY or DEGRADED), sorted fastest first."""
        eligible = [
            c for c in self._circuits.values()
            if c.state in (CircuitState.HEALTHY, CircuitState.DEGRADED)
        ]
        eligible.sort(
            key=lambda c: (
                0 if c.state == CircuitState.HEALTHY else 1,
                -self.metrics.get_circuit_throughput(c.circuit_id),
                c.latency_s,
            )
        )
        return eligible

    def healthy_count(self) -> int:
        return sum(1 for c in self._circuits.values() if c.state == CircuitState.HEALTHY)

    async def initialize_pool(self) -> None:
        """Build N initial circuits for the download job."""
        tasks = [self._build_slot() for _ in range(self.config.circuits)]
        await asyncio.gather(*tasks)
        if self.healthy_count() == 0:
            raise TorError("Failed to build any healthy Tor circuits. Aborting.")

    async def _build_slot(self, failed_at: Optional[float] = None) -> Optional[ManagedCircuit]:
        """Attempt to build a single circuit and start its dedicated SOCKS listener (up to 3 retries)."""
        for attempt in range(1, 4):
            try:
                cid, path, duration, s_user, s_pass = await asyncio.to_thread(
                    self.controller.build_circuit, attempt
                )
                listener = CircuitSocksListener(
                    circuit_id=cid,
                    socks_user=s_user,
                    tor_socks_host="127.0.0.1",
                    tor_socks_port=self.config.socks_port_base,
                    controller=self.controller,
                )
                local_port = await listener.start()
                proxy_url = self.controller.get_socks_proxy_url(s_user, s_pass, listener_port=local_port)

                mc = ManagedCircuit(
                    circuit_id=cid,
                    created_at=time.monotonic(),
                    relay_path=path,
                    socks_user=s_user,
                    socks_pass=s_pass,
                    proxy_url=proxy_url,
                    socks_listener=listener,
                    listener_port=local_port,
                    state=CircuitState.HEALTHY,
                    latency_s=duration,
                    failed_at=failed_at,
                )
                async with self._lock:
                    self._circuits[cid] = mc
                    h_count = self.healthy_count()

                self.event_bus.emit(
                    EventType.CIRCUIT_BUILT,
                    circuit_id=cid,
                    attempt=attempt,
                    path_str=mc.path_str,
                    duration_s=duration,
                    healthy_count=h_count,
                )
                return mc
            except Exception as exc:
                async with self._lock:
                    h_count = self.healthy_count()
                self.event_bus.emit(
                    EventType.CIRCUIT_FAILED,
                    circuit_id="NONE",
                    attempt=attempt,
                    path_str="AUTO",
                    duration_s=0.0,
                    reason=str(exc),
                    healthy_count=h_count,
                )
                await asyncio.sleep(0.2 * attempt)

        async with self._lock:
            self._unavailable_slots += 1
        self.event_bus.emit(
            EventType.ERROR,
            message="Circuit slot marked unavailable after 3 build timeouts",
            reason="BUILD_TIMEOUT_EXHAUSTED",
        )
        return None

    async def acquire(self) -> Optional[ManagedCircuit]:
        """Acquire the best available healthy circuit for a chunk transfer."""
        async with self._lock:
            candidates = self.healthy_circuits()
            if not candidates:
                return None
            candidates.sort(
                key=lambda c: (
                    c.in_use,
                    0 if c.state == CircuitState.HEALTHY else 1,
                    -self.metrics.get_circuit_throughput(c.circuit_id),
                )
            )
            chosen = candidates[0]
            chosen.in_use += 1
            chosen.throughput_bps = self.metrics.get_circuit_throughput(chosen.circuit_id)
            return chosen

    async def release(self, circuit_id: str) -> None:
        """Release a circuit after chunk transfer completes or aborts."""
        async with self._lock:
            c = self._circuits.get(circuit_id)
            if c and c.in_use > 0:
                c.in_use -= 1
                c.throughput_bps = self.metrics.get_circuit_throughput(circuit_id)

    def transition_state(self, circuit_id: str, new_state: CircuitState, reason: str = "NONE") -> None:
        """Transition a circuit's state and emit CIRCUIT_STATE_CHANGE."""
        c = self._circuits.get(circuit_id)
        if not c or c.state == new_state:
            return
        old_state = c.state
        c.state = new_state
        if new_state in (CircuitState.DEAD, CircuitState.RETIRING) and c.failed_at is None:
            c.failed_at = time.monotonic()
        self.event_bus.emit(
            EventType.CIRCUIT_STATE_CHANGE,
            circuit_id=circuit_id,
            old_state=old_state.value,
            new_state=new_state.value,
            reason=reason,
            healthy_count=self.healthy_count(),
        )

    async def replace(self, circuit_id: str, reason: str, reassigned_chunks: int = 0) -> Optional[ManagedCircuit]:
        """
        Retire a dead/failed circuit, stop its dedicated SOCKS listener, close it via
        CLOSECIRCUIT, and build a fresh replacement without blocking active transfers.
        """
        async with self._lock:
            if circuit_id in self._replacing_ids:
                return None
            self._replacing_ids.add(circuit_id)
            old_c = self._circuits.get(circuit_id)
            fail_ts = old_c.failed_at if old_c and old_c.failed_at else time.monotonic()
            if old_c:
                self.transition_state(circuit_id, CircuitState.RETIRING, reason=reason)

        if old_c:
            await old_c.kill_socks_listener()
        await asyncio.to_thread(self.controller.close_circuit, circuit_id)
        new_c = await self._build_slot(failed_at=fail_ts)

        async with self._lock:
            self._circuits.pop(circuit_id, None)
            self._replacing_ids.discard(circuit_id)

        if new_c:
            recovery_s = max(0.0, time.monotonic() - fail_ts)
            self.event_bus.emit(
                EventType.CIRCUIT_REPLACED,
                old_circuit_id=circuit_id,
                new_circuit_id=new_c.circuit_id,
                reason=reason,
                reassigned_chunks=reassigned_chunks,
                recovery_s=recovery_s,
            )
        return new_c

    async def close_all(self) -> None:
        """Cleanly tear down all circuits and their dedicated SOCKS listeners."""
        async with self._lock:
            circuits = list(self._circuits.values())
            self._circuits.clear()
        for c in circuits:
            await c.kill_socks_listener()
            await asyncio.to_thread(self.controller.close_circuit, c
