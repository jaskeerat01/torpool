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

## Data at rest

- The quarantine directory and temporary directory are created with `0700` permissions.
- Downloaded files are created and verified with `0600` permissions.
- Temporary files are shredded (overwritten with random bytes, `fsync`ed, then unlinked)
  on clean exit.
- AES-256-GCM encryption uses a key derived with Scrypt (`N=2^14`, `r=8`, `p=1`) and a
  fresh 16-byte salt per file. The plaintext is shredded after encryption.
- Integrity failures rename the artifact to a `.failed.<timestamp>` suffix rather than
  overwriting existing failed artifacts.

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
