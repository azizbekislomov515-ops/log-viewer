# syntax=docker/dockerfile:1
# Build and check LogLens in a container; nothing but Docker is needed on the host.
#
#   docker build --target test .                   # ruff, mypy, bandit and the test suite
#   docker build --target deb --output dist .      # writes dist/loglens_<version>_amd64.deb
#
# Everything runs as an unprivileged user (uid 1000): several tests check what a normal
# user can and cannot read, and LogLens itself never needs root.

ARG UV_VERSION=0.12.5
ARG PYTHON_VERSION=3.12

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

FROM debian:12 AS base
ARG PYTHON_VERSION
COPY --from=uv /uv /uvx /usr/local/bin/
COPY ci/install-system-deps.sh /tmp/install-system-deps.sh
# Qt offscreen + Qt Charts libraries (CI's list), plus what the .deb build calls:
# python3 (reads the version from pyproject.toml), dpkg-deb and fakeroot.
RUN /tmp/install-system-deps.sh \
    && apt-get install -y -qq --no-install-recommends python3 dpkg-dev fakeroot file >/dev/null \
    && rm -rf /var/lib/apt/lists/* /tmp/install-system-deps.sh \
    && useradd --create-home --uid 1000 build
USER build
WORKDIR /home/build/loglens
ENV QT_QPA_PLATFORM=offscreen \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON=${PYTHON_VERSION} \
    PATH=/home/build/loglens/.venv/bin:$PATH
# Dependencies first, so editing the source does not re-download them.
COPY --chown=build:build pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/home/build/.cache/uv,uid=1000,gid=1000 \
    uv sync --frozen --no-install-project
COPY --chown=build:build . .
RUN --mount=type=cache,target=/home/build/.cache/uv,uid=1000,gid=1000 \
    uv sync --frozen

FROM base AS test
RUN ruff check src tests \
    && ruff format --check src tests \
    && mypy \
    && bandit -q -c pyproject.toml -r src \
    && pytest -m "not integration and not perf" -p no:cacheprovider -q

FROM base AS deb-build
RUN --mount=type=cache,target=/home/build/.cache/uv,uid=1000,gid=1000 \
    packaging/deb/build-deb.sh

FROM scratch AS deb
COPY --from=deb-build /home/build/loglens/dist/*.deb /
