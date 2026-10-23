# AGENTS.md

## Project

TorPool is a Typer CLI that downloads one file over several explicitly built Tor circuits,
splitting it into byte ranges. Entry point: `torpool.cli:app`. Core invariant: **one pool
slot = one Tor circuit + one ephemeral loopback SOCKS listener**; that 1:1 mapping is what
makes concurrent chunks use distinct circuits.

## Commands

```bash
uv sync --frozen                                           # install locked dependencies
uv run ruff check                                          # lint check (line length 100, py311)
uv run ruff format --check                                 # format check
uv run mypy                                                # typecheck src/torpool and tests
uv run pytest -q                                           # full suite, offline (no Tor/network)
TORPOOL_INTEGRATION=1 uv run pytest -q                    # optional integration suite
uv run pytest -q tests/test_torpool.py::test_name          # single test
```

CI runs on every push and PR via `.github/workflows/ci.yml` running: `uv sync --frozen`, `ruff check`, `ruff format --check`, `mypy`, and `pytest`.
After changing dependencies: `uv lock` then `uv sync`. Never hand-edit `uv.lock`; the Docker
build uses `uv sync --frozen`.

Live Tor run (needs a daemon with a password-protected control port and `IsolateSOCKSAuth`):

```bash
export TOR_CONTROL_PASSWORD='...'
uv run torpool doctor --config /path/to/config.toml
uv run torpool fetch 'https://host/file' --config /path/to/config.toml \
  --out ./quarantine --circuits 4 --chunk-size 4M -v [--resume] [--sha256 HEX] [--graph] [--encrypt]
uv run torpool decrypt ./quarantine/file.enc --out ./recovered.file [--key-file /path/to/key]
```

- Default config is `~/.config/torpool/config.toml`; `--config` overrides it.
- `TORPOOL_ACCEPT_AUTH=1` bypasses the interactive authorization prompt (needed in non-TTY
  runs); `uv run torpool init` persists the confirmation.
- Docker bundles Tor: `docker compose run --rm torpool doctor|fetch|pytest`. The entrypoint
  hashes `TOR_CONTROL_PASSWORD` into a runtime `torrc` and waits for 100% bootstrap.

## Architecture map

- `config.py` — TOML + CLI overrides. Relative `output_dir`/`temp_dir` resolve against the
  **current working directory**, not the config file. Recursively rejects TOML keys named
  `password`, `control_password`, `tor_control_password`, or `cookie`. Validates `--key-file`
  for non-empty passphrase.
- `tor_controller.py` — stem wrapper: password auth, `EXTENDCIRCUIT`, `__LeaveStreamsUnattached 1`,
  per-circuit `CircuitSocksListener`, `SOURCE_ADDR` source-port mapping, `CIRC_BW` metrics.
- `circuit_pool.py` — slot lifecycle, health replacement, listener teardown.
- `scheduler.py` — work-stealing workers, adaptive chunk splitting for slow circuits, retries,
  pre-download disk space checks via `shutil.disk_usage`, fail-closed pause, and periodic atomic
  live status emission (`.torpool_status_<id>.json`).
- `state_store.py` — hidden SQLite resume file at
  `<output_dir>/.torpool_state_<sha256(url)[:16]>.sqlite`; deleted after successful completion.
  When relocating a partial download, move this file with it.
- `verifier.py` — SHA-256, append-only `manifest.json`, AES-256-GCM ciphertext-only download
  (`EncryptedFileSession`, `EncryptedChunkRecord`), HMAC-SHA256 authenticated index (`.idx`),
  and `decrypt_file` plaintext recovery to `0600` files.
- `cli.py` — signal handling and teardown order (dashboard, monitor, pool, controller, bus),
  `status` command reading live status files, and `decrypt` command.

## Non-obvious constraints

- stem reports password auth as `"Password"` (title case), not `"PASSWORD"`. Keep the auth
  check case-insensitive and keep the explicit `import stem.connection`.
- Stream targeting is security-critical: the listener registers its outbound TCP source port
  before the SOCKS greeting, and Tor's `STREAM SOURCE_ADDR` resolves the slot. Attach with
  `attach_stream(stream_id, 0)` for Tor auto-attach; **never** fall back to `circ_ids[0]` or
  another pool circuit. That fallback previously put every stream on one circuit.
- `CircuitSocksListener.stop()` must close writers and cancel tracked handler tasks before
  `Server.wait_closed()`; Python 3.12+ waits for active connections and will deadlock on an
  in-flight chunk otherwise.
- The live graph requires **both** stdout and stderr to be TTYs; `ConfigLoader` silently
  disables it otherwise. Use tmux for live viewing.
- `torpool status` checks for active status JSON files written by running fetch jobs in the
  quarantine output directory. `circuits list/rotate` open fresh Tor control connections and
  do not control or inspect an in-memory fetch pool.
- Ensure `output_dir`/`temp_dir` are on a filesystem with room for the full file. A pre-download
  disk usage check validates free space; runtime ENOSPC raises explicit `DownloadError(disk_full=True)`.
- Cross-domain redirects are refused during probing; the error instructs the operator to supply
  the final destination URL directly.
- `--key-file` is fully implemented: requires an existing, non-empty file with the passphrase.
- In encrypted downloads (`--encrypt`), only ciphertext and authenticated index exist on disk.
  No plaintext `.part` files are ever written. Decrypt with `torpool decrypt`.
- `manifest.json` reports `"status": "VERIFIED"` whenever hashing succeeds; it only compares
  a digest when `--sha256` is supplied. Verify separately when integrity matters.
- `argon_torpool.md` is the original design spec, but it is truncated mid-`CircuitPool.close_all()`
  and its `uv.lock` listing is invalid. Treat code, tests, and `uv.lock` as the source of truth.
- SIGINT during a circuit replacement can make shutdown wait on a non-cancellable control
  thread. Chunk state is checkpointed after every chunk; if teardown hangs, confirm
  `STATE_SAVED` in the log before resorting to `SIGKILL` (resume is safe).

## Security invariants

- Control password comes only from `TOR_CONTROL_PASSWORD`; never add it to TOML, logs, or argv.
- Always clear proxy environment variables and use `trust_env=False`; SOCKS URLs use
  `socks5h://` so DNS happens inside Tor.
- Do not log secrets, fingerprints, full URLs, or local addresses; route output through the
  event bus / sanitizer.
- Keep fail-closed behavior: reject cookie-only auth, require `PROGRESS=100` and
  `status/circuit-established=1`, and pause on unexpected exit-relay changes.
- Quarantine dirs are `0700`, files `0600`; failed hashes are renamed `*.failed.<ts>`.
- Keep the default test suite offline. Listener tests are real asyncio loopback tests and do
  not contact Tor; do not add network or control-port dependencies to them.

## Standing instructions for any future agent or model work

- Always read `AGENTS.md` and `SECURITY.md` before making changes.
- When a design choice is ambiguous, choose the more conservative security option.
- Never re-introduce cookie authentication or accept the control password from CLI arguments or config files.
- Keep the default test suite offline.
- Before claiming a change is finished, run `uv run ruff check`, `uv run mypy`, and `uv run pytest`.
- Update both `README.md` and `SECURITY.md` whenever behaviour that affects OpSec or honesty statements changes.
- Treat the invariant “one pool slot = one dedicated Tor circuit + one dedicated SOCKS listener” as non-negotiable.

