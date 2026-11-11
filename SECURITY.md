# Security Policy

## Intended use

TorPool is a defensive threat-intelligence retrieval tool. It may only be used to
download content that the operator is legally and contractually authorized to access.
Using it to evade access controls, obtain data without authorization, or interact with
illicit marketplaces is prohibited and out of scope for support.

## Secrets handling

- The Tor control password must be supplied **only** through the
  `TOR_CONTROL_PASSWORD` environment variable, or a Docker secret exposed as
  `TOR_CONTROL_PASSWORD_FILE`. It is never accepted on the command line.
- Configuration files containing keys named `password`, `control_password`,
  `tor_control_password`, `cookie`, or `torrent_max_uploads` are rejected at load time.
  Uploading/seeding is not configurable.
- The operator authorization flag is persisted in the local config file with `0600`
  permissions inside a `0700` directory.
- Encryption passphrases may be supplied via `TORPOOL_PASSPHRASE` or a key file; they are
  never written to manifests or logs.
- qBittorrent temporary profiles contain a random loopback WebUI credential and are
  created `0700`/`0600` and securely removed on exit. The live torrent control file is
  `0600` and contains only ephemeral loopback credentials.
- Operational logs are sanitized before writing: URLs, magnets, torrent paths/names,
  relay fingerprints, query tokens, private IPv4 addresses, OS usernames, WebUI
  credentials, and the control password are redacted.

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
- Circuit builds are sequential and rate-limited by `circuit_creation_delay` (default
  1.0s, minimum 0.5s, non-disableable). NEWNYM is limited to once per 10 seconds.
  Failures use exponential back-off. Every wait emits `CIRCUIT_CREATION_THROTTLED`.
- HTTP(S), magnet, and `.torrent` inputs are supported. Magnet v1/v2 info-hashes are
  validated; `xs`, `ws`, and `as` parameters are refused; trackerless magnets are
  refused because DHT is disabled.
- Torrent downloads use one isolated qBittorrent instance per Tor circuit. Each
  instance is configured with SOCKS5 loopback proxy, authenticated circuit credentials,
  hostname lookup through the proxy, proxied peer connections, anonymous mode, and a
  loopback-only WebUI. Preferences are read back after every application and circuit
  rebind; any mismatch fails closed.
- qBittorrent is bound to `lo`, DHT/LSD/UPnP are disabled, peer transport is TCP-only,
  and connections not supported by the proxy are unavailable. This prevents UDP/DHT
  clearnet leaks.
- Multi-file torrents are sharded by file priority across instances. Single-file
  torrents use exactly one circuit and one instance; duplicate downloads are refused.
- Uploading and seeding are prohibited. Upload slots are requested as zero, the global
  upload rate is pinned to qBittorrent's minimum, each torrent gets a 1 B/s upload limit,
  share/seeding limits trigger removal, torrents are removed immediately on completion,
  and the supervisor aborts fail-closed if the uploaded-byte counter increases.
- Docker's default compose deployment attaches `torpool` only to an `internal: true`
  network shared with a Tor sidecar. The sidecar is the only service with an egress
  network; no WebUI or torrent ports are published.

## Threat model

### Assets
1. **Control password**: The credential granting authenticated control access to the local Tor daemon.
2. **Downloaded content**: High-risk or sensitive threat-intelligence payloads and artifacts retrieved by the operator.
3. **Circuit identity**: Ephemeral Tor circuit IDs, relay descriptors, guard/middle/exit fingerprints, and stream attachment mappings.
4. **Torrent metadata**: Magnet URIs, tracker passkeys, infohashes, file names, and qBittorrent WebUI credentials.
5. **Authorization state**: The cryptographic and local confirmation status indicating operator legal entitlement to retrieve specified content.

### Adversaries
1. **Local filesystem attacker**: Non-root local users, unprivileged concurrent processes, or unauthenticated processes on the host filesystem.
2. **Local network observer**: Passive eavesdroppers or active attackers situated on the local area network, Wi-Fi segment, or observing loopback sockets.
3. **Malicious exit or rendezvous relay**: Rogue, eavesdropping, or adversarial Tor relays positioned as exit nodes or onion-service rendezvous points attempting payload tampering or traffic fingerprinting.
4. **Malicious torrent peer/tracker**: A peer or tracker that attempts to correlate circuits, exploit torrent metadata, or induce a direct/clearnet connection.
5. **Operator error**: Operational mistakes by the user, such as omitting safe history controls, exposing URLs or magnets in interactive prompts, or configuring inadequate passphrases.

### Existing mitigations
- **Strict password-only authentication**: Tor control authentication requires `TOR_CONTROL_PASSWORD`; cookie authentication is rejected fail-closed; secrets are never accepted via argv, TOML files, or logged.
- **Ciphertext-only download model**: When `--encrypt` is enabled, chunks are encrypted with AES-256-GCM in memory before writing to disk. Only ciphertext (`.enc`) and an authenticated HMAC-SHA256 record index (`.idx`) exist on disk. Plaintext `.part` files are never written to disk during an encrypted download.
- **Plaintext recovery control**: Plaintext is restored only when the operator explicitly runs `torpool decrypt`, which enforces `0600` permissions on the recovered file and verifies SHA-256 integrity. The decryption passphrase is never logged or stored.
- **Strict loopback binding & stream isolation**: Each circuit slot binds a dedicated ephemeral SOCKS listener on `127.0.0.1`. The outbound TCP source port is tracked before SOCKS greeting to correlate Tor's `STREAM SOURCE_ADDR`. Streams never fall back to other pool circuits.
- **Fail-closed DNS & traffic routing**: All SOCKS proxy targets use `socks5h://` so hostname resolution is strictly handled by Tor. Clearnet proxy environment variables are wiped prior to execution.
- **Torrent proxy verification**: qBittorrent preferences are applied and read back. The job fails if the proxy type/IP/port/credentials, hostname lookup, peer proxying, anonymous mode, TCP-only transport, loopback WebUI, or clearnet-disabling settings do not match.
- **Zero-upload enforcement**: disabled upload slots, minimum global upload rate, 1 B/s per-torrent limit, zero share/seeding limits, immediate removal, and fail-closed uploaded-byte polling.
- **Torrent path safety**: content paths are rejected if absolute, traversing (`..`), symlinked, or escaping the quarantine root. Merging uses `0700` directories and `0600` regular files.
- **Docker network isolation**: the default compose layout gives the torpool container no clearnet route; only the Tor sidecar is dual-homed.
- **Quarantine filesystem protections**: Quarantine and temp directories are created with `0700` permissions; files are created with `0600` permissions. Temporary artifacts are overwritten with random bytes (`shred_file`) and `fsync`ed before unlinking.
- **Log and manifest sanitization**: URLs, magnets, credentials, tokens, fingerprints,
  torrent names/paths, and local IP addresses are scrubbed prior to writing event logs.
  `manifest.json` uses opaque content IDs, sizes, and SHA-256 digests rather than file names.

### Residual risks
- **Shell history**: If `HISTCONTROL=ignorespace` is not configured or if an operator pastes secrets or URLs directly in shell arguments, interactive shells may record them to `~/.bash_history` or `~/.zsh_history`.
- **Terminal scrollback**: While logs avoid secrets, interactive terminal emulators retain screen history which may reveal timing metadata or invoked subcommands if unshielded.
- **Endpoint compromise**: A privileged local attacker (root or elevated process with `ptrace`) can inspect process memory while chunks are buffered in RAM prior to AES-256-GCM encryption.
- **Global passive adversary**: A global network adversary monitoring both the ingress to the Tor entry guard and the egress from the Tor exit relay can correlate traffic patterns and timing.
- **Operator supplying an unauthorized URL**: TorPool cannot verify external legal authority; the operator bears sole responsibility for verifying lawful authorization before initiating downloads.
- **qBittorrent/libtorrent defects**: A vulnerability or regression in qBittorrent, libtorrent, or Qt could cause an unintended network path. Preference read-back and container network isolation reduce but do not eliminate this risk.
- **BitTorrent correlation**: Even with separate circuits, trackers and peers may correlate instances by infohash, timing, piece patterns, or shared exit addresses. PEX is disabled by default but circuit-level correlation remains possible.
- **Tracker refusal/scrutiny**: Tor exits are widely blocked by trackers and peers, and BitTorrent traffic may attract abuse scrutiny from exit operators or destination networks.
- **Single-file torrents**: A single-file torrent cannot be parallelised across circuits through the qBittorrent Web API without duplicate downloads, so it uses one circuit.
- **qBittorrent API normalisation**: qBittorrent normalises `max_uploads=0` to `-1` and its global upload-rate minimum is 1 KiB/s. TorPool adds a per-torrent 1 B/s limit and treats any uploaded payload byte as a hard failure; a very brief protocol-level upload before detection cannot be perfectly excluded.
- **Torrent plaintext staging**: qBittorrent writes plaintext pieces to a `0700` staging directory. `--encrypt` encrypts and shreds them after the torrent stops; ciphertext-only torrent streaming is not possible with the qBittorrent engine.
- **Docker host history**: Shell history and terminal scrollback on the host still record magnets, torrent filenames, and command arguments.
- **Embedded-Tor container mode**: The optional embedded mode relies primarily on application-level Tor-only enforcement rather than the sidecar's network-level isolation.

## Data at rest

- For HTTP downloads with `--encrypt`, **only ciphertext exists on disk throughout the entire transfer**. Chunks are encrypted in memory with AES-256-GCM and written directly to the ciphertext file. No plaintext partial (`.part`) files are ever created by TorPool.
- An authenticated index file (`.idx`) accompanies the ciphertext, mapping chunk offsets to ciphertext positions, nonces, and tags, protected by an HMAC-SHA256 signature derived via Scrypt (`N=2^14`, `r=8`, `p=1`).
- The plaintext is only recovered when the operator runs `torpool decrypt --out <destination>`. Recovered plaintext files are created with restrictive `0600` permissions.
- In unencrypted downloads, target files are sparse-allocated with `0600` permissions inside a `0700` quarantine directory.
- Torrent files are downloaded into `0700` per-instance plaintext staging directories, validated for path safety, merged into quarantine, hashed per file, and—after the torrent is stopped—optionally encrypted with bounded-memory streaming and shredded. Ciphertext-only torrent streaming is not supported by qBittorrent.
- Temporary files and partial staging artifacts are shredded (overwritten with random bytes, `fsync`ed, and unlinked) on exit where safe. Incomplete torrent staging is retained only for `--resume`.
- Integrity verification failures rename artifacts to a `.failed.<timestamp>` suffix to prevent accidental execution and facilitate forensics.

## Logging

Log files record circuit IDs, timing, status codes, and byte counts only. Relay
nicknames/fingerprints, full URLs, magnets, torrent names/paths, tracker credentials,
WebUI secrets, query tokens, and local addresses are redacted. The live dashboard never
displays target URLs, magnets, torrent names, WebUI credentials, or local IP addresses.

## Container security

- The default `docker-compose.yml` uses a Tor sidecar on an `internal: true` network shared
  only with `torpool`. `torpool` has no clearnet route; only the sidecar is dual-homed.
- No Web UI, control, SOCKS, or torrent ports are published.
- The Docker image runs as the unprivileged `torpool` user (via `gosu`) after fixing
  volume ownership at startup.
- The control password is supplied as a Docker secret (`TOR_CONTROL_PASSWORD_FILE`) or
  environment variable and is never baked into the image. The sidecar hashes it into a
  `0600` runtime `torrc` under `/tmp`.
- `docker-compose.yml` drops all Linux capabilities, sets `no-new-privileges`, uses a
  read-only root, limits pids, and mounts only quarantine/state/logs plus read-only config.
- The optional embedded-Tor image mode listens only on `127.0.0.1` inside the container;
  it is secondary because the sidecar provides network-level isolation.
- Host shell history and scrollback remain outside the container's protection.

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
- Keep `cryptography`, `httpx`, `stem`, `rich`, `qBittorrent`, and `uv` up to date.
- Keep DHT/LSD disabled and prefer TCP-only torrent transport. Do not re-enable UDP paths.
- Never configure upload/seeding limits; TorPool rejects upload configuration by design.
- Review the manifest and verify SHA-256 digests before using downloaded artifacts.
- Treat magnet links and torrent filenames as sensitive; use a clean shell and disable
  history recording when appropriate.
