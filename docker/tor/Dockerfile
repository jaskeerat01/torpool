# syntax=docker/dockerfile:1
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gosu \
    passwd \
    python3 \
    tor \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10002 -g nogroup -d /var/lib/tor -s /usr/sbin/nologin tor

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
