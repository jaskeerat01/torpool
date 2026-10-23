# TorPool

Multi-circuit Tor range-downloader for **authorized** defensive threat-intelligence analysis.

TorPool builds a pool of dedicated, explicitly selected Tor circuits and spreads a single
byte-range download across them. It is designed for retrieving content that you are
legally and contractually authorized to access, such as your own organization's data,
published research datasets, or sources covered by a formal data-sharing agreement.

> **Authorization is mandatory.** Read `SECURITY.md` and the in-tool authorization notice
> before use. Do not use TorPool to evade access controls or to obtain data you have no
> right to access.

## Features

- Multiple parallel Tor circuits built with explicit 3-hop paths (`EXTENDCIRCUIT`).
- One dedicated local SOCKS5 listener per circuit, correlating Tor's `SOURCE_ADDR`
  stream port back to the exact circuit slot, so concurrent chunks really use separate
  circuits (not just separate credentials on one circuit).
- Per-circuit SOCKS credentials with `IsolateSOCKSAuth` and `socks5h://` (DNS resolved
  inside Tor).
- Control-port verification with `SOCKS_USERNAME` circuit tagging and `CIRC_BW` byte
  counters, plus verified Tor circuit IDs in verbose chunk output.
- Resumable byte-range downloads with SQLite chunk tracking and adaptive chunk splitting.
- Background health probes with automatic, non-blocking circuit replacement.
- Rolling-window throughput metrics and an optional live terminal bandwidth graph.
- SHA-256 verification, quarantine manifests, and optional AES-256-GCM encryption at rest.
- Sanitized operational logging: secrets, fingerprints, URLs, and local addresses are
  never written to the log file.

## Requirements

- Python 3.11+
- A local Tor daemon with:
  - `ControlPort 9051` configured with `HashedControlPassword`
  - `SocksPort 9050 IsolateSOCKSAuth`
- `TOR_CONTROL_PASSWORD` set in the environment. The control password is **never**
  stored in configuration files.

## Install

```bash
uv sync
```

or, with plain pip:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
pip install pytest pytest-asyncio
```

### Docker

The image bundles its own Tor daemon and runs the app as an unprivileged user. The
control password is hashed into a runtime-only `torrc`; it never appears in the image or
config file.

```bash
export TOR_CONTROL_PASSWORD="your_secret_password"
docker compose build

# One-off command
docker compose run --rm torpool doctor
docker compose run --rm torpool fetch "http://example.onion/artifact.bin" --circuits 4 -v

# Tests (offline)
docker compose run --rm torpool pytest

# Artifacts persist in ./quarantine
```

The compose service drops all capabilities, enables `no-new-privileges`, and mounts only
the quarantine volume. The container waits for its internal Tor to reach 100% bootstrap
before running the command.


## Configure

```bash
cp config.example.toml ~/.config/torpool/config.toml
export TOR_CONTROL_PASSWORD="your_secret_password"
uv run torpool init
```

`torpool init` prints the authorization notice, records your confirmation, and creates
the quarantine and temporary directories with `0700` permissions.

## Usage

```bash
# Verify control auth, bootstrap status, SOCKS listener, and permissions
uv run torpool doctor

# Download a file across four circuits into quarantine
uv run torpool fetch "http://example.onion/artifact.bin" --circuits 4 --chunk-size 10M

# Resume an interrupted download and verify a known digest
uv run torpool fetch "http://example.onion/artifact.bin" --resume --sha256 <hex>

# Rate-limit the pool to 5 MiB/s and show the live graph
uv run torpool fetch "http://example.onion/artifact.bin" --max-bandwidth 5M --graph

# Inspect and rotate circuits
uv run torpool circuits list
uv run torpool circuits rotate <circuit-id>

# Verify a quarantined artifact
uv run torpool verify ./quarantine/artifact.bin --sha256 <hex>
```

Verbosity: `--quiet` (errors and final result), default (state changes and 10 s summaries),
`-v` (build steps, chunk activity, health probes), `-vv` (scheduler/timing/stem debug).

## Security model

- Password-only Tor control authentication; cookie-only setups are rejected.
- Refuses to start unless Tor reports `PROGRESS=100` and `status/circuit-established=1`.
- `__LeaveStreamsUnattached 1` with deterministic stream attachment through each
  circuit's dedicated local SOCKS listener; unknown streams are never silently attached
  to the first circuit.
- Exit-relay changes on a built circuit trigger a fail-closed pause.
- Proxy environment variables are cleared before any network activity.
- Downloads land in a `0700` quarantine directory; files are `0600`.
- Cross-domain redirects are refused.

See `SECURITY.md` for reporting vulnerabilities and the full threat model.

## Tests

```bash
uv run pytest
```

Tests are offline: they exercise configuration, sanitization, metrics, state persistence,
scheduling primitives, the per-circuit SOCKS listener and source-port mapping,
verification, and rendering without contacting Tor.

