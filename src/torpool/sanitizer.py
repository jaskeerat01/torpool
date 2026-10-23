"""Sanitization utilities to prevent leaking secrets, tokens, local IPs, or fingerprints."""

import os
import re
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

SENSITIVE_QUERY_KEYS = (
    "token",
    "key",
    "sig",
    "auth",
    "password",
    "secret",
    "session",
    "credential",
)
IPV4_REGEX = re.compile(
    r"\b(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)\b"
)
FINGERPRINT_REGEX = re.compile(r"\$[A-Fa-f0-9]{40}|\b[A-Fa-f0-9]{40}\b")


def sanitize_url_for_manifest(url: str) -> str:
    """Strip embedded credentials and sensitive query parameters from a URL for manifests."""
    try:
        parsed = urlparse(url)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        filtered_query = [
            (k, "[REDACTED]") if any(s in k.lower() for s in SENSITIVE_QUERY_KEYS) else (k, v)
            for k, v in query_pairs
        ]
        clean_query = urlencode(filtered_query)
        return urlunparse((parsed.scheme, netloc, parsed.path, "", clean_query, ""))
    except Exception:
        return "[REDACTED_URL]"


def sanitize_log_text(text: str, control_password: Optional[str] = None) -> str:
    """
    Sanitize text before writing to the operational log file.
    Removes control password, relay fingerprints, full URLs, tokens, local IPs, and usernames.
    """
    if not text:
        return ""

    result = text

    # 1. Strip control password
    env_pw = control_password or os.environ.get("TOR_CONTROL_PASSWORD")
    if env_pw:
        result = result.replace(env_pw, "[REDACTED_PASSWORD]")

    # 2. Strip URLs completely from log lines
    result = re.sub(r"https?://[^\s\"'>]+", "[REDACTED_URL]", result)

    # 3. Strip 40-char hex fingerprints and short $fingerprints
    result = FINGERPRINT_REGEX.sub("[REDACTED_FP]", result)
    result = re.sub(r"[~]?[A-Za-z0-9_]+\[\$[A-Fa-f0-9]{8}\]", "[REDACTED_RELAY]", result)

    # 4. Strip private/local IPv4 addresses
    result = IPV4_REGEX.sub("[REDACTED_LOCAL_IP]", result)

    # 5. Strip query-style token/key/sig/auth values if present outside full URLs
    result = re.sub(
        r"(?i)\b(token|key|sig|auth|password|secret)=([^\s&\"']+)",
        r"\1=[REDACTED]",
        result,
    )

    # 6. Strip OS username if present in paths
    try:
        user = os.environ.get("USER") or os.environ.get("USERNAME")
        if user and len(user) > 2:
            result = result.replace(f"/{user}/", "/[USER]/")
    except Exception:
        pass

    return result


def clear_proxy_env() -> None:
    """Disable proxy environment variables that could leak traffic or override Tor SOCKS."""
    proxy_vars = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ]
    for var in proxy_vars:
        os.environ.pop(var, None)
