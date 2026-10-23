# TorPool Tests

These tests are fully offline. They exercise pure logic and local filesystem behavior only:

- configuration loading, validation, and forbidden-key rejection
- secret/URL/fingerprint sanitization
- bounded event bus and sanitized log writer
- rolling throughput metrics, control-port `CIRC_BW` counters, and rate-limiter no-op mode
- per-circuit SOCKS listener forwarding, source-port correlation, and listener teardown
- circuit-pool slot construction with dedicated listeners
- SQLite chunk state, resume, and dynamic split persistence
- chunk partitioning, size parsing, and URL OPSEC checks
- SHA-256 verification, manifests, AES-256-GCM encryption, and shredding
- dashboard sparkline/chart rendering and terminal fallbacks

No test contacts Tor, the control port, SOCKS, or the network.

Run:

```bash
uv run pytest
```
