# syntax=docker/dockerfile:1

# ---- builder: produce an exact, locked virtual environment ----
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/torpool-venv

WORKDIR /build
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --frozen --no-dev --no-install-project
RUN uv sync --frozen --no-dev --no-editable


# ---- runtime: minimal image with qBittorrent and optional Tor ----
FROM python:3.12-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gosu \
    passwd \
    qbittorrent-nox \
    tor \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 10001 torpool \
    && useradd -r -u 10001 -g torpool -d /app -s /usr/sbin/nologin torpool \
    && mkdir -p /app /quarantine /state /logs /config /tmp/torpool-tor \
    && chmod 0700 /quarantine /state /logs /tmp/torpool-tor \
    && chown -R torpool:torpool /app /quarantine /state /logs /tmp/torpool-tor

WORKDIR /app
COPY --from=builder /opt/torpool-venv /opt/torpool-venv
COPY --chown=torpool:torpool src/ ./src/
COPY --chown=torpool:torpool config.example.toml README.md SECURITY.md ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

ENV PATH="/opt/torpool-venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TORPOOL_ACCEPT_AUTH=1 \
    TORPOOL_TOR_MODE=embedded

VOLUME ["/quarantine", "/state", "/logs"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]


# ---- optional test target: dev dependencies + offline test suite ----
FROM builder AS test

ENV PATH="/opt/torpool-venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY tests/ ./tests/
RUN uv sync --frozen

ENTRYPOINT ["python", "-m", "pytest"]
CMD ["-q"]
