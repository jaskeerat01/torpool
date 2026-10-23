# TorPool

Multi-circuit Tor byte-range file downloader in Python 3.11+ for defensive threat-intelligence analysis. `torpool` pools several isolated Tor circuits, monitors their health in the background, replaces failed or degraded circuits without stalling active transfers, and combines their throughput into a single download written to encrypted quarantine storage.

---

## Source Restriction & Authorization Notice

> **AUTHORIZED USE ONLY**: This tool is strictly for retrieving content that the operator is legally and contractually authorized to access—such as their organization’s own data, published research datasets, or sources covered by a formal data-sharing agreement for defensive threat-intelligence analysis.
>
> Operators must **never** use `torpool` to obtain data from sources they have no right to access, register or log into illicit marketplaces or forums, interact with vendors, crawl/index URLs, or bypass access controls.

On first run (or when running `uv run torpool init`), `torpool` displays the authorization notice below and requires explicit operator confirmation before any network activity can occur:

```text
================================================================================
                        TORPOOL AUTHORIZATION NOTICE
================================================================================
This tool is strictly for retrieving content that you (the operator) are
legally and contractually authorized to access—such as your organization's own
data, published research datasets, or sources covered by a formal data-sharing
agreement for defensive threat-intelligence analysis.

You must NOT use this tool to obtain data from sources you have no right to
access, interact with illicit marketplaces, or evade access controls.
================================================================================
```

---

## Features

- **Pooled Tor Circuits**: Builds `N` circuits (`1..16`, default `4`) via `EXTENDCIRCUIT` with distinct Guard and Middle relays where consensus allows.
- **True Per-Circuit Stream Isolation**: Each pooled circuit runs its own dedicated local SOCKS5 listener (`CircuitSocksListener`) with unique `IsolateSOCKSAuth` credentials. The listener records the exact outbound TCP source port (`SOURCE_ADDR=127.0.0.1:<port>`) before forwarding the SOCKS5 handshake to Tor, and correlates Tor's `SOCKS_USERNAME` circuit tags and `STREAM SUCCEEDED` / `CIRC_BW` events so streams never collapse onto a single circuit.
- **Continuous Health Monitoring**: Background `HealthMonitor` probes each circuit every `health_interval`, marking circuits `degraded` after 2 consecutive failures or latency `> 3×` the pool median, and `dead` after 3 consecutive failures or a timeout. Dead circuits are closed via `CLOSECIRCUIT` and replaced asynchronously without blocking active chunk downloads.
- **Work-Stealing Range Scheduler**: Splits downloads into HTTP `Range: bytes=start-end` chunks, assigns chunks to the fastest healthy circuits, adapts chunk sizes downward for slow circuits, and falls back to single-circuit streaming if the server does not support HTTP range requests.
- **Crash-Safe Resume**: Persists the chunk completion bitmap and job metadata in a `0600` SQLite state store so interrupted downloads (`SIGINT`/`SIGTERM`) resume cleanly without re-downloading finished chunks.
- **Quarantine & At-Rest Encryption**: Writes all downloaded files to a `0700` quarantine directory with `0600` file permissions, verifies `SHA-256` digests, writes a sanitized `manifest.json`, and supports optional `AES-256-GCM` encryption at rest (`--encrypt`).
- **Live Terminal Telemetry**: Non-blocking `EventBus` and `MetricsWindow` power real-time verbose progress on `stderr` and an optional live Unicode/ASCII terminal bandwidth graph (`--graph`).

---

## Requirements

- **Python**: `3.11+`
- **Tooling**: [`uv`](https://docs.astral.sh/uv/) (All packaging, virtual-environment management, dependency locking, and execution are performed exclusively with `uv`. Never use bare `pip`, `python -m venv`, Poetry, or Pipenv.)
- **Tor Daemon**: Reachable ControlPort (default `127.0.0.1:9051`) configured with `HashedControlPassword`, and SocksPort (default `127.0.0.1:9050`) with `IsolateSOCKSAuth`.

---

## Setup with `uv`

```bash
git clone https://github.com/jaskeerat01/torpool.git
cd torpool

# Create virtual environment and install locked dependencies reproducibly
uv sync --frozen
```

---

## Configuring `TOR_CONTROL_PASSWORD`

`torpool` supports Tor Control Port **password authentication only** (`CookieAuthentication` is rejected). The control password is **never** accepted on the command line and **never** stored in any configuration file. It must be supplied exclusively via the `TOR_CONTROL_PASSWORD` environment variable.

1. Generate a hashed password for your `torrc`:
   ```bash
   tor --hash-password "your_strong_control_password"
   ```
2. Add the following to your `torrc` and reload Tor:
   ```text
   SocksPort 127.0.0.1:9050 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth
   ControlPort 127.0.0.1:9051
   HashedControlPassword 16:YOUR_HASH_FROM_STEP_1
   CookieAuthentication 0
   ```
3. Export `TOR_CONTROL_PASSWORD` in your shell before running `torpool`:
   ```bash
   # Prefix with a space if HISTCONTROL=ignorespace is enabled in your shell
   export TOR_CONTROL_PASSWORD="your_strong_control_password"
   ```

If `TOR_CONTROL_PASSWORD` is unset, empty, or rejected by Tor, `torpool` exits immediately with a clear error and performs **zero network activity**.

---

## Example Commands

```bash
# 1. Confirm the authorization notice and initialize ~/.config/torpool/config.toml & ./quarantine
uv run torpool init

# 2. Run preflight diagnostics (checks Tor reachability, password auth, 100% bootstrap, SOCKS, and 0700 perms)
uv run torpool doctor

# 3. Download a file across 4 Tor circuits with 10 MiB chunks, SHA-256 verification, and -v output
uv run torpool fetch "http://example2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xy.onion/dataset.tar.zst" \
  --circuits 4 \
  --chunk-size 10M \
  --out ./quarantine \
  --sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  -v

# 4. Download with live terminal bandwidth graph, at-rest AES-256-GCM encryption, and 5 MiB/s rate cap
uv run torpool fetch "https://example.org/published-research-dump.bin" \
  --circuits 6 \
  --chunk-size 8M \
  --max-bandwidth 5M \
  --per-host-concurrency 6 \
  --encrypt \
  --graph \
  --log-file ./quarantine/operational.log \
  -v

# 5. Resume an interrupted download from SQLite state without re-downloading finished chunks
uv run torpool fetch "https://example.org/published-research-dump.bin" \
  --out ./quarantine \
  --resume \
  -v

# 6. Issue SIGNAL NEWNYM and rebuild all circuits before starting a job
uv run torpool fetch "https://example.org/published-research-dump.bin" \
  --new-identity \
  -vv

# 7. Decrypt a downloaded ciphertext-only quarantine artifact to a destination file with 0600 permissions
uv run torpool decrypt ./quarantine/published-research-dump.bin.enc \
  --out ./quarantine/recovered.bin \
  --key-file ./secret_key.txt

# 8. Inspect live download progress, rotate circuits, or verify file integrity
# Note: 'torpool status' inspects atomic live-status files written by active fetch jobs.
# 'torpool circuits list/rotate' open fresh Tor control connections and do not alter in-flight fetch sessions.
uv run torpool status
uv run torpool circuits list
uv run torpool circuits rotate 12
uv run torpool verify ./quarantine/published-research-dump.bin --sha256 <EXPECTED_SHA256>
```

### Running via Docker CLI (Optional)

```bash
docker build -t torpool:latest .

export TOR_CONTROL_PASSWORD="your_strong_control_password"
mkdir -p ./quarantine && chmod 0700 ./quarantine

docker run --rm -it \
  -e TOR_CONTROL_PASSWORD \
  -v "$(pwd)/quarantine:/quarantine" \
  torpool:latest fetch "https://example.org/published-research-dump.bin" \
  --circuits 4 --out /quarantine -v --graph
```

---

## Development & Quality Gates

TorPool maintains automated quality gates running in GitHub Actions CI on every push and pull request. All checks can be executed locally with `uv`:

```bash
# Sync exact locked dependencies
uv sync --frozen

# Lint and check style rules (line-length 100, py311 target)
uv run ruff check

# Verify formatting
uv run ruff format --check

# Static type checking
uv run mypy

# Run default offline test suite (zero network access, runs in ~1s)
uv run pytest -q
```

---

## Stability

TorPool remains on `0.1.x` while encryption pipelines, live status coordination, and the integration harness settle.

- **Stable**: The CLI command structure, configuration schema (`config.toml`), `--key-file` semantics, and SQLite resume format (`.torpool_state_*.sqlite`) are stable across 0.1.x.
- **Subject to Refinement**: Low-level adaptive chunk scheduling heuristics and internal telemetry IPC will evolve as we approach 0.2.0.
- **Packaging**: The `uv.lock` lockfile is strictly version-controlled and reproducible. Docker builds enforce `uv sync --frozen`.

---

## Sample Verbose Output

All terminal output is written to `stderr` so `stdout` remains clean for scripting. Relay nicknames and short fingerprints appear on the terminal only and are never written to `--log-file`.

### Default (Circuit state changes, replacements, and 10s summary lines)
```text
[CIRCUIT] id=circ_2 state=healthy->retiring reason=TIMEOUT healthy=3
[REPLACE] old_id=circ_2 new_id=circ_5 reason=TIMEOUT reassigned_chunks=1 recovery_time=1.38s
[SUMMARY] completed=41943040/104857600 B rate=1924.6 KiB/s healthy_circuits=4
[COMPLETE] status=VERIFIED bytes=104857600 sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 duration=54.48s
```

### `-v` (Circuit build steps, chunk assignments/completions, health probes, and state saves)
```text
[BUILD_START] attempt=1 path=GuardAlpha[$9A1F22B0] -> MiddleRelay[$4C88E110] -> ExitNode[$77D019AA]
[ACQUIRED] id=circ_1 attempt=1 path=GuardAlpha[$9A1F22B0] -> MiddleRelay[$4C88E110] -> ExitNode[$77D019AA] duration=0.81s reason=NONE healthy=4
[CHUNK_ASSIGN] chunk=0 range=0-10485759 circuit=circ_1 retries=0
[HEALTH] circuit=circ_1 status=OK latency=0.294s state=healthy
[CHUNK_DONE] chunk=0 range=0-10485759 circuit=circ_1 tor_circ=14 rate=641.2 KiB/s retries=0
[STATE] saved completed_chunks=1/10
```

### `-vv` (Debug timings, retry backoffs, scheduler decisions, and Stem lifecycle events)
```text
[DEBUG:STEM] circuit=14 status=BUILT reason=NONE
[DEBUG:STEM] circuit=14 status=STREAM_SUCCEEDED reason=NONE
[DEBUG:SCHED] decision=ADAPT_CHUNK_SPLIT detail=Split chunk 4 into 4 and 10 for slow circuit circ_3
[DEBUG:TIMING] phase=chunk_0 elapsed=15.9672s
```

### `--quiet` (Errors and final result only)
```text
[COMPLETE] status=VERIFIED bytes=104857600 sha256=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 duration=54.48s
```

---

## Honesty Caveats & Technical Limitations

Operators must account for the following realities when using `torpool` (see [`SECURITY.md`](./SECURITY.md) for the full threat model):

1. **No Native Circuit Bonding**: Tor does not natively bond several circuits into a single network connection. `torpool` performs application-level HTTP byte-range splitting (`Range: bytes=start-end`) across independent circuits.
2. **No Guaranteed Speed**: Application-level parallel downloads may improve throughput on high-latency circuits, but **cannot guarantee any particular speed**. Performance depends on circuit quality, relay congestion, exit relays, destination server limits, and scheduling.
3. **No Guaranteed Unique Exit Relays**: Creating multiple logical circuits or `IsolateSOCKSAuth` sessions does not guarantee that every circuit uses a unique exit relay (or hidden-service rendezvous point).
4. **Circuit Replacement Caveat**: Replacing a failed or degraded circuit does not guarantee that Tor will select a different exit relay.
5. **No Absolute Anonymity**: Tor does not guarantee absolute anonymity. Operators remain vulnerable to endpoint compromise, timing correlation, and operational mistakes (such as leaking target URLs in shell history or terminal scrollback).
6. **SHA-256 Integrity vs. Authenticity**: A locally calculated `SHA-256` hash does not prove that a file is authentic or benign; it only confirms that the bytes received match the expected hash when one is supplied. Downloaded files are never executed, unpacked, or parsed by `torpool` and are written strictly to `0700` quarantine storage.
7. **Circuit List/Rotate Limitation**: `torpool circuits list` and `rotate` connect to Tor directly; they do not observe or manipulate the in-memory pool of a running fetch process.

---

## Security & OpSec Model

- **Tor-Only Routing & Fail-Closed Startup**: Refuses to start if the Tor control port is unreachable, `TOR_CONTROL_PASSWORD` authentication fails, or Tor is not 100% bootstrapped (`PROGRESS=100`). Clears `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` environment variables and never falls back to a direct connection.
- **Ciphertext-Only Downloading (`--encrypt`)**: Every chunk is encrypted with AES-256-GCM in memory prior to being written to disk. Only ciphertext and an HMAC-SHA256 authenticated index (`.idx`) exist on disk. No plaintext `.part` files are ever created. Plaintext is recovered only when the operator runs `torpool decrypt`. Passphrases are never stored or logged.
- **Zero Local DNS Leaks**: Enforces `socks5h://` on every request so all hostname resolution occurs inside the Tor network, and refuses `localhost`/`127.0.0.1`/`::1` targets.
- **Pre-download Space Checks**: Verifies filesystem capacity via `shutil.disk_usage` before preallocating storage and surfaces actionable errors on `ENOSPC`.
- **Fail-Closed Redirect Guidance**: Cross-domain redirects are rejected during probing; error instructions prompt the operator to supply the destination URL directly.
- **Fingerprinting Defense**: Uses the fixed Tor Browser User-Agent (`Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0`), sends no custom headers or cookies, and refuses cross-domain redirects.
- **Log & Manifest Sanitization**: Strips query tokens (`token`, `key`, `sig`, `auth`, `password`, `secret`), embedded credentials, local IPv4 addresses, OS usernames, relay fingerprints, and `TOR_CONTROL_PASSWORD` before writing logs or manifests. Temporary files are overwritten with random bytes (`shred_file`) before unlinking.

---

## Testing

### Offline Test Suite (Default)
The default test suite is completely offline, requires no network access or running Tor daemon, and executes in ~1 second:

```bash
uv run pytest -q
```

### Integration Test Suite (Optional)
TorPool includes an optional integration suite gated behind `TORPOOL_INTEGRATION=1`. It provides a local range-request HTTP server, SOCKS5 remote domain ATYP leak validation, dynamic file generators, and Tor harness fixtures. See [`tests/README.md`](./tests/README.md) for full instructions:

```bash
TORPOOL_INTEGRATION=1 uv run pytest -q
```

