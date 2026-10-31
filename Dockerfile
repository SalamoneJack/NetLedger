# syntax=docker/dockerfile:1
# NetLedger container image: non-root, read-only-rootfs friendly, git + ssh included.

FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="NetLedger" \
      org.opencontainers.image.description="Multi-vendor network configuration backup to Git with health monitoring" \
      org.opencontainers.image.source="https://github.com/SalamoneJack/NetLedger" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --gid 0 --home-dir /data --shell /usr/sbin/nologin netledger \
 && mkdir -p /data /etc/netledger \
 && chown 10001:0 /data && chmod 0770 /data

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels netledger && rm -rf /wheels

ENV NETLEDGER_CONFIG=/etc/netledger/netledger.yaml \
    NETLEDGER_DATA_DIR=/data \
    HOME=/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "netledger"]
CMD ["serve"]
