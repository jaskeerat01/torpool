#!/usr/bin/env bash
set -euo pipefail

umask 077

# Resolve a Docker secret without ever echoing it or placing it in argv.
if [ -z "${TOR_CONTROL_PASSWORD:-}" ] && [ -n "${TOR_CONTROL_PASSWORD_FILE:-}" ]; then
    if [ ! -r "${TOR_CONTROL_PASSWORD_FILE}" ]; then
        echo "[ERROR] TOR_CONTROL_PASSWORD_FILE is not readable." >&2
        exit 1
    fi
    TOR_CONTROL_PASSWORD="$(cat "${TOR_CONTROL_PASSWORD_FILE}")"
    export TOR_CONTROL_PASSWORD
fi

if [ "$(id -u)" = "0" ]; then
    mkdir -p /quarantine /quarantine/tmp /state /logs /tmp/torpool-tor /tmp/torpool-qbt
    chown -R torpool:torpool /quarantine /state /logs /tmp/torpool-tor /tmp/torpool-qbt
    chmod 0700 /quarantine /quarantine/tmp /state /logs /tmp/torpool-tor /tmp/torpool-qbt
    exec gosu torpool "$0" "$@"
fi

if [ "${1:-}" = "pytest" ]; then
    shift
    exec python -m pytest "$@"
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "verify" ] || [ "${1:-}" = "decrypt" ]; then
    exec torpool "$@"
fi

if [ -z "${TOR_CONTROL_PASSWORD:-}" ]; then
    echo "[ERROR] TOR_CONTROL_PASSWORD (or TOR_CONTROL_PASSWORD_FILE) is not set." >&2
    echo "Refusing to start. Supply it via an environment variable or Docker secret." >&2
    exit 1
fi

TOR_MODE="${TORPOOL_TOR_MODE:-embedded}"

if [ "${TOR_MODE}" = "embedded" ]; then
    TOR_RUNTIME_DIR="/tmp/torpool-tor"
    mkdir -p "${TOR_RUNTIME_DIR}/data"
    chmod 0700 "${TOR_RUNTIME_DIR}" "${TOR_RUNTIME_DIR}/data"

    HASHED_PW=$(python3 -c 'import os; from torpool.tor_password import hash_control_password; print(hash_control_password(os.environ["TOR_CONTROL_PASSWORD"]))')

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

    echo "[TORPOOL-CONTAINER] Waiting for embedded Tor to bootstrap to 100%..." >&2
    for _ in $(seq 1 120); do
        if grep -q "Bootstrapped 100% (done)" "${TOR_RUNTIME_DIR}/tor.log" 2>/dev/null; then
            break
        fi
        sleep 1
    done
elif [ "${TOR_MODE}" = "external" ]; then
    echo "[TORPOOL-CONTAINER] Using external Tor at ${TOR_SOCKS_HOST:-tor}:${TOR_SOCKS_PORT:-9050}." >&2
else
    echo "[ERROR] TORPOOL_TOR_MODE must be 'embedded' or 'external'." >&2
    exit 1
fi

exec torpool "$@"
