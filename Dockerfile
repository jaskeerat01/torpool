# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    ca-certificates \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r torpool && useradd -r -g torpool -d /app -s /sbin/nologin torpool \
    && mkdir -p /app /quarantine /app/.config/torpool /tmp/torpool-tor \
    && chmod 0700 /quarantine /app/.config/torpool /tmp/torpool-tor \
    && chown -R torpool:torpool /app /quarantine /tmp/torpool-tor

WORKDIR /app

COPY --chown=torpool:torpool pyproject.toml uv.lock README.md config.example.toml ./
COPY --chown=torpool:torpool src/ ./src/
COPY --chown=torpool:torpool tests/ ./tests/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    TORPOOL_ACCEPT_AUTH=1

USER torpool
RUN uv sync --frozen --no-cache

USER root
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

VOLUME ["/quarantine"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
