# TorPool

Multi-circuit Tor downloader for HTTP(S), magnet links, and `.torrent` payloads in Python 3.11+. `torpool` pools isolated Tor circuits, monitors their health, replaces failed circuits, and aggregates throughput into one logical download written to restrictive quarantine storage. HTTP downloads use byte-range splitting; torrent downloads use isolated qBittorrent instances, each bound to one circuit's dedicated SOCKS listener.

---

## Source Restriction & Authorization Notice

> **AUTHORIZED USE ONLY**: This tool is strictly for retrieving content that the operator is legally and contractually authorized to access—such as their organization's own data, published research datasets, or sources covered by a formal data-sharing agreement for defensive threat-intelligence analysis.
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

- **Pooled Tor circuits**: builds `N` circuits (`1..100`, default `4`) sequentially via `EXTENDCIRCUIT`, with distinct Guard/Middle relays where consensus allows.
- **True per-circuit stream isolation**: each circuit gets a dedicated loopback SOCKS5 listener (`CircuitSocksListener`) and unique `IsolateSOCKSAuth` credentials. The listener correlates the exact outbound TCP source port (`SOURCE_ADDR`) and Tor `SOCKS_USERNAME`/`CIRC_BW` events. Unknown streams are never attached to another pool circuit.
- **Mandatory circuit-build throttling**: `circuit_creation_delay` defaults to `1.0s` (minimum `0.5s`, cannot be disabled). Builds are sequential, failures use exponential back-off, and NEWNYM is limited to once per 10 seconds. Every enforced wait emits `CIRCUIT_CREATION_THROTTLED`. Tor's control specification notes that NEWNYM may be rate-limited (Tor logs a delay when it throttles); Tor publishes no hard numeric minimum for `EXTENDCIRCUIT`, so the 1s default is deliberately conservative to keep the control port and circuit queue responsive.
- **HTTP range downloads**: work-stealing chunk scheduler, adaptive chunk splitting, retries, crash-safe SQLite resume, and single-circuit streaming fallback when the server lacks range support.
- **Magnet and torrent downloads through qBittorrent**: the official qBittorrent Web API is driven over loopback with `trust_env=False`. Each qBittorrent instance runs in a temporary `0700` profile with a random loopback WebUI password and is bound to one circuit's SOCKS listener.
- **Multi-file torrent acceleration**: files are greedily sharded across `min(circuits, files, torrent_max_instances)` isolated instances; each instance downloads a disjoint file subset through its own circuit. Aggregate throughput is recorded in the same `MetricsWindow` used by the live graph.
- **No uploading or seeding, ever**: qBittorrent is configured with disabled upload slots, a minimum upload-rate backstop, per-torrent 1 B/s limit, zero-ratio/zero-seeding-time removal, and immediate torrent removal on completion. The supervisor polls the uploaded-byte counter and aborts fail-closed on any payload upload.
- **Quarantine & at-rest encryption**: `0700` directories, `0600` files, per-file SHA-256, a deterministic tree digest for multi-file torrents, a sanitized `manifest.json`, and optional AES-256-GCM encryption using bounded-memory streaming for large files.
- **Live terminal telemetry**: non-blocking `EventBus`, rolling `MetricsWindow`, sanitized logs on `stderr`, and an optional Unicode/ASCII bandwidth graph with no extra network requests.

---

## Requirements

- **Python**: `3.11+`
- **Tooling**: [`uv`](https://docs.astral.sh/uv/) for all packaging, locking, and execution. Never use bare `pip`, `python -m venv`, Poetry, or Pipenv.
- **Tor**: ControlPort (default `127.0.0.1:9051`) with `HashedControlPassword`, and SocksPort (default `127.0.0.1:9050`) with `IsolateSOCKSAuth`.
- **Torrent downloads only**: `qbittorrent-nox` (recommended) or a headless-capable `qbittorrent` binary. The Docker image includes `qbittorrent-nox`. HTTP-only users can run `torpool doctor --skip-torrent`.

---

## Setup with `uv`

```bash
git clone https://github.com/jaskeerat01/torpool.git
cd torpool
uv sync --frozen
```

---

## Configuring `TOR_CONTROL_PASSWORD`

`torpool` supports Tor Control Port **password authentication only**; cookie authentication is rejected. The password is **never** accepted on the command line and **never** stored in a configuration file. Supply it through `TOR_CONTROL_PASSWORD`, or through a Docker secret that injects `TOR_CONTROL_PASSWORD_FILE`.

```bash
# Generate a hashed password for torrc
tor --hash-password "your_strong_control_password"
```

```text
SocksPort 127.0.0.1:9050 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth
ControlPort 127.0.0.1:9051
HashedControlPassword 16:YOUR_HASH_FROM_STEP_1
CookieAuthentication 0
```

```bash
# Prefix with a space if HISTCONTROL=ignorespace is enabled
export TOR_CONTROL_PASSWORD="your_strong_control_password"
```

If the password is unset, empty, rejected, or Tor is not 100% bootstrapped, `torpool` exits before any network activity.

---

## Example Commands

```bash
# 1. Confirm authorization and initialize config/quarantine
uv run torpool init

# 2. Preflight Tor, permissions, and qBittorrent proxy read-back
uv run torpool doctor

# 3. HTTP range download across 4 circuits
uv run torpool fetch "https://example.org/published-research-dump.bin" \
  --circuits 4 --chunk-size 10M --out ./quarantine \
  --sha256 <EXPECTED_SHA256> -v

# 4. Multi-circuit torrent download (multi-file torrents are sharded by file)
uv run torpool fetch "magnet:?xt=urn:btih:<INFOHASH>&tr=https://tracker.example/announce" \
  --circuits 4 --out ./quarantine --encrypt --graph -v

# 5. Private .torrent file (preferred; no trackerless magnet limitation)
uv run torpool fetch ./authorized-dataset.torrent \
  --circuits 8 --out ./quarantine --resume -v

# 6. Inspect or control a running torrent job
uv run torpool torrent status --out ./quarantine
uv run torpool torrent pause --out ./quarantine
uv run torpool torrent resume --out ./quarantine
uv run torpool torrent remove --out ./quarantine

# 7. Decrypt an encrypted quarantine artifact
uv run torpool decrypt ./quarantine/artifact.bin.enc \
  --out ./quarantine/recovered.bin --key-file ./secret_key.txt

# 8. Verify, inspect circuits, or check Tor health
uv run torpool verify ./quarantine/artifact.bin --sha256 <EXPECTED_SHA256>
uv run torpool circuits list
uv run torpool circuits rotate 12
uv run torpool healthcheck
```

### Torrent behaviour and limitations

- **Multi-file torrents** are split by content file across instances. Each instance only selects its assigned files via qBittorrent file priorities, so piece data is not duplicated.
- **Single-file torrents** use exactly one circuit and one qBittorrent instance. qBittorrent's Web API does not expose per-connection proxies or piece-range assignment; parallelising a single file would require duplicate downloads and extra swarm exposure, which TorPool refuses by default.
- **Trackerless magnets are refused** because DHT is disabled and cannot traverse Tor. Supply a `.torrent` file or a magnet with at least one `tr=` tracker.
- **Magnet parameters `xs`, `ws`, and `as` are refused** because they add additional fetch paths.
- **No uploads**: the tool removes the torrent the moment the download finishes and aborts if any uploaded payload byte is observed. Some peers/trackers may penalise this behaviour; that is an explicit trade-off.
- **`--sha256`**: for a single-file torrent it compares the file digest; for a multi-file torrent it compares a deterministic tree digest over sorted relative paths and per-file SHA-256 values.
- **Torrent plaintext staging**: qBittorrent must write plaintext pieces to disk while downloading. TorPool keeps staging under a `0700` directory and, with `--encrypt`, encrypts and shreds plaintext only after the torrent is stopped. There is no ciphertext-only torrent streaming path with qBittorrent.

---

## Docker

The default deployment is a **Tor sidecar on an internal Docker network**. The `torpool` container is attached only to that internal network, so it has no clearnet route even if an application setting is wrong. Tor has a second egress network.

```bash
# Create the secret without exposing it in shell history
mkdir -p secrets && chmod 0700 secrets
read -rsp "Tor control password: " TOR_CONTROL_PASSWORD; echo
printf '%s' "$TOR_CONTROL_PASSWORD" > secrets/tor_control_password
unset TOR_CONTROL_PASSWORD
chmod 0600 secrets/tor_control_password

mkdir -p quarantine state logs config
chmod 0700 quarantine state logs

docker compose build
docker compose run --rm torpool doctor
docker compose run --rm torpool fetch \
  "https://example.org/published-research-dump.bin" \
  --circuits 4 --out /quarantine --graph -v
docker compose run --rm torpool fetch \
  "magnet:?xt=urn:btih:<INFOHASH>&tr=https://tracker.example/announce" \
  --circuits 8 --out /quarantine --graph -v

# Optional offline test image
docker build --target test -t torpool:test .
docker run --rm torpool:test
```

- `TOR_CONTROL_PASSWORD` and `TOR_CONTROL_PASSWORD_FILE` are the only accepted secret sources.
- No Web UI or torrent ports are published.
- The entrypoint drops privileges with `gosu`; compose drops all capabilities, enables `no-new-privileges`, uses a read-only root, and mounts only `/quarantine`, `/state`, `/logs`, and read-only `/config`.
- `TORPOOL_TOR_MODE=external` is the compose default. `TORPOOL_TOR_MODE=embedded` remains available for a single-container setup, but it is weaker than sidecar network isolation and is documented as secondary.

### Docker with a host-provided Tor

If you already run Tor on the host, set `TORPOOL_TOR_MODE=external`, `TOR_SOCKS_HOST`, and `TOR_CONTROL_HOST`, and ensure the container can reach those endpoints. Host networking or an explicitly mapped bridge is a weaker isolation boundary than the sidecar network; operators must enforce host firewall rules so no clearnet route exists.

---

## Development & Quality Gates

```bash
uv lock
uv sync --frozen
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest -q
```

The default suite is offline and does not require Tor or qBittorrent. Optional integration tests are gated behind `TORPOOL_INTEGRATION=1`; torrent-specific real-process tests can additionally be gated behind `TORPOOL_TORRENT_INTEGRATION=1`.

---

## Sample Verbose Output

All terminal output goes to `stderr`; `stdout` stays clean for scripting. Relay nicknames and short fingerprints appear only on the terminal and are never written to `--log-file`.

```text
[CIRCUIT] id=circ_2 state=healthy->retiring reason=TIMEOUT healthy=3
[THROTTLE] reason=CIRCUIT_BUILD_ATTEMPT_1 wait=1.00s delay=1.00s
[QBIT] started instance=0 version=v5.1.4
[TORRENT] metadata infohash=9f86d081884c files=12 bytes=104857600
[SUMMARY] completed=41943040/104857600 B rate=1924.6 KiB/s healthy_circuits=4
[TORRENT-DONE] files=12 bytes=104857600 duration=54.48s
[COMPLETE] status=VERIFIED bytes=104857600 sha256=... duration=54.48s
```

---

## Honesty Caveats & Technical Limitations

1. **Tor does not bond circuits.** TorPool performs application-level HTTP range splitting or multi-file torrent sharding. It cannot turn many circuits into one TCP connection.
2. **No guaranteed speed.** Torrent over Tor is slower and more fragile than clearnet BitTorrent. Many trackers and peers reject Tor exits or time out; speed depends on circuit quality, relay congestion, exit policy, tracker behaviour, and peer availability.
3. **No guaranteed unique exit.** Multiple circuits may reuse the same exit relay. Per-instance isolation does not guarantee a unique exit per peer or connection.
4. **BitTorrent over Tor attracts scrutiny.** Exit-relay operators and destination networks may treat BitTorrent traffic as abuse. Use only for authorized data.
5. **DHT/PEX/LSD are not leak-free if enabled.** DHT and LSD use UDP and are refused. PEX is TCP and can traverse Tor, but it increases linkability; it is disabled by default.
6. **Circuit replacement is not identity rotation.** Replacing a failed circuit does not guarantee a different exit.
7. **Single-file torrents use one circuit.** This is a deliberate conservative limit, not a bug.
8. **No absolute anonymity.** Endpoint compromise, timing correlation, and operational mistakes remain risks.
9. **Shell history and scrollback** record magnet links, torrent filenames, and command arguments. Use a clean session and `HISTCONTROL=ignorespace` where appropriate.
10. **Docker does not remove host-side history risks.** The same shell/scrollback care applies on the host.
11. **SHA-256 integrity is not authenticity.** It only confirms bytes match an expected digest.
12. **Large circuit counts increase load.** Up to 100 circuits is supported, but every build waits for the mandatory delay and increases local Tor and network load.
13. **qBittorrent API normalisation.** qBittorrent normalises `max_uploads=0` to `-1` and its global upload-rate minimum is 1 KiB/s; TorPool additionally sets a per-torrent 1 B/s limit and aborts on any uploaded payload byte. The uploaded-byte counter is the authoritative zero-upload check.
14. **`torpool status`/`torpool torrent status` inspect live status files**; `circuits list/rotate` open independent control connections and do not manipulate an in-flight pool.

---

## Security & OpSec Model

- **Tor-only routing and fail-closed startup**: refuses to start if Tor control is unreachable, password authentication fails, bootstrap is not `PROGRESS=100`, or `status/circuit-established != 1`. Proxy environment variables are cleared; `trust_env=False` is set everywhere.
- **Loopback control plane**: qBittorrent WebUI is bound to `127.0.0.1` with random credentials and a `0600` profile. qBittorrent is bound to the loopback interface, and proxy hostname lookup/peer connections are mandatory and verified by read-back.
- **No clearnet fallback**: DHT/LSD/UPnP are disabled, TCP-only peer transport is enforced, and the container default has no clearnet route.
- **No upload/seeding**: disabled upload slots, minimum upload-rate backstop, per-torrent 1 B/s limit, zero share/seeding limits, immediate removal, and fail-closed uploaded-byte monitoring.
- **Ciphertext-only downloads (`--encrypt`)**: HTTP chunks are encrypted in memory before writing; torrent files are encrypted in bounded-memory chunks after qBittorrent stops. Only ciphertext and authenticated `.idx` indexes remain. No plaintext `.part` files are written.
- **Zero local DNS leaks**: `socks5h://` is used everywhere; qBittorrent proxy hostname lookup is enabled and verified.
- **Quarantine protections**: `0700` directories, `0600` files, `shutil.disk_usage` pre-checks, ENOSPC fail-closed handling, and random-byte shredding of temporary artifacts.
- **Sanitization**: logs, status files, and dashboards omit magnets, tracker credentials, torrent names/paths, WebUI secrets, local addresses, relay fingerprints, and the control password. Torrent manifests use opaque content IDs plus sizes and SHA-256 digests, not file names. HTTP manifests retain only the sanitized source and digest metadata needed for integrity review.

See [`SECURITY.md`](./SECURITY.md) for the full threat model.

---

## Stability

- **Stable**: CLI command structure, `config.toml` schema, `--key-file` semantics, the SQLite resume format, and the torrent state format in 0.2.x.
- **Subject to refinement**: adaptive scheduling heuristics and qBittorrent version compatibility shims.
- **Packaging**: `uv.lock` is version-controlled; Docker builds use `uv sync --frozen`.
