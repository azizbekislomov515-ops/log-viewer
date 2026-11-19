#!/usr/bin/env bash
# Run the unit and offscreen GUI tests inside a Debian/Ubuntu container, as an
# unprivileged user (several tests check what a normal user can and cannot read; root
# can read everything). Used by CI's matrix job and for local checks:
#   docker run --rm -v "$PWD:/repo:ro" -v ~/.cache/uv:/uvcache -e UV_CACHE_DIR=/uvcache \
#       ubuntu:22.04 bash /repo/ci/test-in-container.sh 3.12
set -euo pipefail
PY="${1:-3.12}"
UV_VERSION="${UV_VERSION:-0.12.5}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
apt-get update -qq && apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null
"$SRC/ci/install-system-deps.sh"
# uid 1000 so a cache mounted from the host stays writable.
user="$(getent passwd 1000 | cut -d: -f1 || true)"
[ -n "$user" ] || { useradd -m -u 1000 ci; user=ci; }
home="$(getent passwd "$user" | cut -d: -f6)"
work="$home/loglens"
rm -rf "$work" && mkdir -p "$work"
tar -C "$SRC" --exclude=.venv --exclude=build --exclude=dist --exclude=.git -cf - . | tar -C "$work" -xf -
chown -R "$user:" "$home"
su "$user" -s /bin/bash -c "
    set -euo pipefail
    cd '$work'
    export QT_QPA_PLATFORM=offscreen PYTHONDONTWRITEBYTECODE=1 ${UV_CACHE_DIR:+UV_CACHE_DIR=$UV_CACHE_DIR}
    curl -LsSf https://astral.sh/uv/$UV_VERSION/install.sh | sh >/dev/null 2>&1
    ~/.local/bin/uv sync --frozen --python '$PY' -q
    ~/.local/bin/uv run pytest -m 'not integration and not perf' -p no:cacheprovider -q
"
