# TorPool Tests

## 1. Default Offline Test Suite

The default test suite is completely offline, fast, and does not require a running Tor daemon or internet access:

- Configuration loading, validation, and recursive forbidden-key rejection.
- Secret/URL/fingerprint log and manifest sanitization.
- Bounded event bus and sanitized log writer.
- Rolling throughput metrics, control-port `CIRC_BW` counters, and rate-limiter token bucket logic.
- Per-circuit SOCKS listener forwarding, TCP source-port correlation, and graceful listener teardown.
- Circuit-pool slot lifecycle with dedicated loopback SOCKS listeners.
- SQLite chunk state, resume, and dynamic split persistence.
- Pre-download disk space verification (`shutil.disk_usage`) and ENOSPC fail-closed handling.
- Cross-domain redirect fail-closed rejection with clear destination URL guidance.
- Ciphertext-only encryption model (`EncryptedFileSession`), authenticated record index (`.idx`), and `torpool decrypt` recovery with `0600` permissions.
- Dashboard sparkline/chart rendering and terminal fallbacks.

Run the default offline suite:

```bash
uv run pytest -q
```

---

## 2. Optional Integration Test Suite (`TORPOOL_INTEGRATION=1`)

TorPool includes an optional integration testing harness for end-to-end verification. It is marked with `@pytest.mark.integration` and gated behind the `TORPOOL_INTEGRATION=1` environment variable so normal CI and offline runs skip it automatically.

### Supporting Components (`tests/integration/`)

- **Range Request Test Server (`RangeServer`)**:
  Located in `tests/integration/server.py`. Spawns an ephemeral HTTP/1.1 server supporting RFC 7233 byte ranges (`Range: bytes=start-end`), `Accept-Ranges`, `Content-Range`, and `206 Partial Content`.
- **DNS Leak Detection (`DNSLeakDetector`)**:
  Located in `tests/integration/dns_leak.py`. Inspects SOCKS5 connection establishment handshakes to guarantee client uses ATYP=0x03 (domain name) rather than ATYP=0x01 (IPv4). Confirms zero clearnet DNS leaks.
- **Test File Generator (`generate_test_file`)**:
  Located in `tests/integration/file_generator.py`. Creates deterministic pseudo-random binary test files of arbitrary size with SHA-256 digest calculation.
- **Tor Environment Harness (`tor_harness.py`)**:
  Located in `tests/integration/tor_harness.py`. Provides helpers for pointing integration tests to an ephemeral local Tor daemon, system Tor instance, or Chutney network via environment variables (`TOR_CONTROL_PORT`, `TOR_SOCKS_PORT`, `TOR_CONTROL_PASSWORD`, `CHUTNEY_PATH`).

### Running the Integration Suite

```bash
# Run integration suite locally against mocked range server and DNS leak detectors:
TORPOOL_INTEGRATION=1 uv run pytest -q

# Run a specific integration test:
TORPOOL_INTEGRATION=1 uv run pytest -q tests/test_integration.py::test_integration_concurrent_chunk_download
```

