#!/usr/bin/env bash
set -euo pipefail

umask 077

if [ -n "${TOR_CONTROL_PASSWORD_FILE:-}" ]; then
    if [ ! -r "${TOR_CONTROL_PASSWORD_FILE}" ]; then
        echo "[TOR] TOR_CONTROL_PASSWORD_FILE is not readable." >&2
        exit 1
    fi
    TOR_CONTROL_PASSWORD="$(cat "${TOR_CONTROL_PASSWORD_FILE}")"
fi

if [ -z "${TOR_CONTROL_PASSWORD:-}" ]; then
    echo "[TOR] TOR_CONTROL_PASSWORD or TOR_CONTROL_PASSWORD_FILE is required." >&2
    exit 1
fi

HASHED_PW=$(python3 - <<'PY'
import hashlib
import os
import secrets

password = os.environ["TOR_CONTROL_PASSWORD"].encode("utf-8")
salt = secrets.token_bytes(8)
iteration = 0x60
count = (16 + (iteration & 15)) << ((iteration >> 4) + 6)
block = salt + password
material = (block * ((count // len(block)) + 1))[:count]
digest = hashlib.sha1(material).digest()
print("16:" + (salt + bytes([iteration]) + digest).hex().upper())
PY
)
unset TOR_CONTROL_PASSWORD

mkdir -p /var/lib/tor /tmp/tor-config
chown -R tor:nogroup /var/lib/tor /tmp/tor-config
chmod 0700 /var/lib/tor /tmp/tor-config

cat > /tmp/tor-config/torrc <<EOF
DataDirectory /var/lib/tor
SocksPort 172.30.0.2:9050 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth
SocksPolicy accept 172.30.0.0/24
SocksPolicy reject *
ControlPort 172.30.0.2:9051
HashedControlPassword ${HASHED_PW}
CookieAuthentication 0
ClientOnly 1
AvoidDiskWrites 1
Log notice stdout
EOF
chmod 0600 /tmp/tor-config/torrc
chown tor:nogroup /tmp/tor-config/torrc

exec gosu tor tor -f /tmp/tor-config/torrc
