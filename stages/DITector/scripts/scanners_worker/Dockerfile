# Scanners worker image — runs `scanners run` against a remote coordinator.
#
# Build context expected: the scanners repo root (so pyproject.toml + src/ etc.
# are at ./).
#
# The container needs Docker CLI on PATH (it spawns scanner containers via
# `docker run`); the *daemon* lives on the host, mounted as a volume:
#   -v /var/run/docker.sock:/var/run/docker.sock

FROM python:3.12-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG DOCKER_CHANNEL=stable

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg git \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian bookworm ${DOCKER_CHANNEL}" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md /app/
COPY src /app/src
RUN uv sync --frozen --no-dev --no-cache --link-mode=copy

ENV PATH="/app/.venv/bin:$PATH"

# The worker writes scanner output here; configs mount this from the host.
VOLUME ["/app/out", "/app/cache", "/app/work"]

ENTRYPOINT ["scanners"]
CMD ["run", "--help"]
