# Security Policy

## Intended use

TorPool is a defensive threat-intelligence retrieval tool. It may only be used to
download content that the operator is legally and contractually authorized to access.
Using it to evade access controls, obtain data without authorization, or interact with
illicit marketplaces is prohibited and out of scope for support.

## Secrets handling

- The Tor control password must be supplied **only** through the
  `TOR_CONTROL_PASSWORD` environment variable.
- Configuration files containing keys named `password`, `control_password`,
  `tor_control_password`, or `cookie` are rejected at load time.
- The operator authorization flag is persisted in the local config file with `0600`
  permissions inside a `0700` directory.
- Encryption passphrases may be supplied via `TORPOOL_PASSPHRASE` or a key file; they are
  never written to manifests or logs.
- Operational logs are sanitized before writing: URLs, relay fingerprints, query tokens,
  private IPv4 addresses, OS usernames, and the control password are redacted.

## Network and circuit integrity

- Authentication is password-only. Tor instances offering only cookie authentication are
  rejected.
- TorPool refuses to start unless the daemon is fully bootstrapped (`PROGRESS=100`) and
  reports `status/circuit-established=1`.
- Circuits are built with explicit relay paths. `__LeaveStreamsUnattached 1` is set so
  streams are attached deliberately rather than by Tor's default stream isolation.
- Each circuit gets a dedicated, loopback-only SOCKS5 listener. The listener records the
  outbound TCP source port before forwarding the SOCKS greeting, and Tor's
  `SOURCE_ADDR` value is correlated to the exact circuit slot. Unknown streams are handed
  back to Tor for `IsolateSOCKSAuth` auto-attachment rather than being attached to the
  first pool circuit.
- Tor `SOCKS_USERNAME` circuit tags and `CIRC_BW` byte counters are used to verify the
  actual circuit used by each chunk; verbose chunk output includes the verified Tor
  circuit ID.
- SOCKS connections use `socks5h://` so all DNS resolution happens inside Tor.
- If the exit relay of a built circuit changes unexpectedly, the download is paused
  fail-closed.
- Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase
  variants) are cleared before any network activity.
- Hostnames resolving to loopback are refused, and non-HTTP(S) schemes are refused.
- Cross-domain redirects during target probing are refused.

## Threat model

### Assets
1. **Control password**: The credential granting authenticated control access to the local Tor daemon.
2. **Downloaded content**: High-risk or sensitive threat-intelligence payloads and artifacts retrieved by the operator.
3. **Circuit identity**: Ephemeral Tor circuit IDs, relay descriptors, guard/middle/exit fingerprints, and stream attachment mappings.
4. **Authorization state**: The cryptographic and local confirmation status indicating operator legal entitlement to retrieve specified content.

### Adversaries
1. **Local filesystem attacker**: Non-root local users, unprivileged concurrent processes, or unauthenticated processes on the host filesystem.
2. **Local network observer**: Passive eavesdroppers or active attackers situated on the local area network, Wi-Fi segment, or observing loopback sockets.
3. **Malicious exit or rendezvous relay**: Rogue, eavesdropping, or adversarial Tor relays positioned as exit nodes or onion-service rendezvous points attempting payload tampering or traffic fingerprinting.
4. **Operator error**: Operational mistakes by the user, such as omitting safe history controls, exposing URLs in interactive prompts, or configuring inadequate passphrases.

### Existing mitigations
- **Strict password-only authentication**: Tor control authentication requires `TOR_CONTROL_PASSWORD`; cookie authentication is rejected fail-closed; secrets are never accepted via argv, TOML files, or logged.
- **Ciphertext-only download model**: When `--encrypt` is enabled, chunks are encrypted with AES-256-GCM in memory before writing to disk. Only ciphertext (`.enc`) and an authenticated HMAC-SHA256 record index (`.idx`) exist on disk. Plaintext `.part` files are never written to disk during an encrypted download.
- **Plaintext recovery control**: Plaintext is restored only when the operator explicitly runs `torpool decrypt`, which enforces `0600` permissions on the recovered file and verifies SHA-256 integrity. The decryption passphrase is never logged or stored.
- **Strict loopback binding & stream isolation**: Each circuit slot binds a dedicated ephemeral SOCKS listener on `127.0.0.1`. The outbound TCP source port is tracked before SOCKS greeting to correlate Tor's `STREAM SOURCE_ADDR`. Streams never fall back to other pool circuits.
- **Fail-closed DNS & traffic routing**: All SOCKS proxy targets use `socks5h://` so hostname resolution is strictly handled by Tor. Clearnet proxy environment variables are wiped prior to execution.
- **Quarantine filesystem protections**: Quarantine and temp directories are created with `0700` permissions; files are created with `0600` permissions. Temporary artifacts are overwritten with random bytes (`shred_file`) and `fsync`ed before unlinking.
- **Log and manifest sanitization**: URLs, credentials, tokens, fingerprints, and local IP addresses are scrubbed prior to writing event logs and `manifest.json`.

### Residual risks
- **Shell history**: If `HISTCONTROL=ignorespace` is not configured or if an operator pastes secrets or URLs directly in shell arguments, interactive shells may record them to `~/.bash_history` or `~/.zsh_history`.
- **Terminal scrollback**: While logs avoid secrets, interactive terminal emulators retain screen history which may reveal timing metadata or invoked subcommands if unshielded.
- **Endpoint compromise**: A privileged local attacker (root or elevated process with `ptrace`) can inspect process memory while chunks are buffered in RAM prior to AES-256-GCM encryption.
- **Global passive adversary**: A global network adversary monitoring both the ingress to the Tor entry guard and the egress from the Tor exit relay can correlate traffic patterns and timing.
- **Operator supplying an unauthorized URL**: TorPool cannot verify external legal authority; the operator bears sole responsibility for verifying lawful authorization before initiating downloads.

## Data at rest

- When `--encrypt` is specified, **only ciphertext exists on disk throughout the entire transfer**. Chunks are encrypted in memory with AES-256-GCM and written directly to the ciphertext file. No plaintext partial (`.part`) files are ever created on disk.
- An authenticated index file (`.idx`) accompanies the ciphertext, mapping chunk offsets to ciphertext positions, nonces, and tags, protected by an HMAC-SHA256 signature derived via Scrypt (`N=2^14`, `r=8`, `p=1`).
- The plaintext is only recovered when the operator runs `torpool decrypt --out <destination>`. Recovered plaintext files are created with restrictive `0600` permissions.
- In unencrypted downloads, target files are sparse-allocated with `0600` permissions inside a `0700` quarantine directory.
- Temporary files and partial staging artifacts are shredded (overwritten with random bytes, `fsync`ed, and unlinked) on exit.
- Integrity verification failures rename artifacts to a `.failed.<timestamp>` suffix to prevent accidental execution and facilitate forensics.

## Logging

Log files record circuit IDs, timing, status codes, and byte counts only. Relay
nicknames/fingerprints, full URLs, query tokens, and local addresses are redacted. The
live dashboard never displays the target URL or local IP addresses.

## Container security

- The Docker image runs as the unprivileged `torpool` user (via `gosu`) after fixing
  volume ownership at startup.
- The control password is supplied only as an environment variable and hashed into a
  `0600` runtime `torrc` under `/tmp/torpool-tor`; it is never baked into the image.
- `docker-compose.yml` drops all Linux capabilities, sets `no-new-privileges`, and mounts
  only the quarantine volume.
- The bundled Tor daemon listens only on `127.0.0.1` inside the container.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers of the deployment
you received TorPool from. Include:

- A description of the issue and its impact.
- Reproduction steps, ideally against a local, disposable Tor instance.
- The TorPool version.
- Any relevant sanitized logs (do not include control passwords or target URLs).

Do not open public issues for vulnerabilities involving secret disclosure, circuit
identity leaks, or arbitrary file access.

## Operational recommendations

- Run TorPool as an unprivileged user with a dedicated quarantine directory.
- Rotate the Tor control password periodically and restrict `ControlPort` to loopback.
- Keep `cryptography`, `httpx`, `stem`, and `rich` up to date.
- Review the manifest and verify SHA-256 digests before using downloaded artifacts.
