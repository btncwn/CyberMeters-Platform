FROM node:24-bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates gcc make perl python3 libc6-dev && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY scripts/build-tls-engine.py scripts/build-tls-engine.py
COPY workers/network-probe/tls-engine/ workers/network-probe/tls-engine/
RUN printf '%s  %s\n' 'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505' \
    'workers/network-probe/tls-engine/trust/ca-bundle.pem' | sha256sum -c -
RUN python3 scripts/build-tls-engine.py --jobs 4
RUN python3 workers/network-probe/tls-engine/test-engine.py

FROM node:24-bookworm-slim
RUN mkdir -p /opt/cybermeters/trust && chown -R node:node /opt/cybermeters
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/.build/bin/tls-baseline-legacy /opt/cybermeters/tls-baseline-legacy
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/.build/bin/tls-baseline-modern /opt/cybermeters/tls-baseline-modern
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/trust/ca-bundle.pem /opt/cybermeters/trust/ca-bundle.pem
USER node
WORKDIR /home/node
CMD ["sleep", "infinity"]
