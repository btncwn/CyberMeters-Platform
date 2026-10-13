FROM python:3.14-bookworm@sha256:7ee7e4d4fb42c3ad45b8fdc473b64ec69c3cf6e80ae5d52f6fa55f77fac29027 AS build

RUN command -v gcc && command -v make && command -v perl && command -v python3
WORKDIR /build
COPY scripts/build-tls-engine.py scripts/build-tls-engine.py
COPY workers/network-probe/tls-engine/ workers/network-probe/tls-engine/
RUN printf '%s  %s\n' 'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505' \
    'workers/network-probe/tls-engine/trust/ca-bundle.pem' | sha256sum -c -
RUN apt-get update -qq && apt-get install -y -qq strace
RUN python3 scripts/build-tls-engine.py --jobs 4 || { \
    strace -f -o /tmp/tls-catalog-strace.log \
      workers/network-probe/tls-engine/.build/bin/tls-baseline-legacy \
      --control catalog --protocol ssl3 || true; \
    tail -60 /tmp/tls-catalog-strace.log; exit 1; }
RUN python3 workers/network-probe/tls-engine/test-engine.py

FROM node:24-bookworm-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
RUN mkdir -p /opt/cybermeters/trust /opt/cybermeters/licenses && chown -R node:node /opt/cybermeters
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/.build/bin/tls-baseline-legacy /opt/cybermeters/tls-baseline-legacy
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/.build/bin/tls-baseline-modern /opt/cybermeters/tls-baseline-modern
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/trust/ca-bundle.pem /opt/cybermeters/trust/ca-bundle.pem
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/LICENSE.openssl-1.0.2u /opt/cybermeters/licenses/LICENSE.openssl-1.0.2u
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/LICENSE.openssl-3.5.9 /opt/cybermeters/licenses/LICENSE.openssl-3.5.9
COPY --from=build --chown=node:node /build/workers/network-probe/tls-engine/LICENSE.mpl-2.0 /opt/cybermeters/licenses/LICENSE.mpl-2.0
USER node
WORKDIR /home/node
CMD ["sleep", "infinity"]
