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
