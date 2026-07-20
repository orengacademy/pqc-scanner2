#!/usr/bin/env bash
# Build the Linux x86_64 pqcscan binary against glibc 2.17 so it runs on
# old enterprise hosts (RHEL / Oracle Linux 7, glibc 2.17, and anything newer).
#
# Why: scripts/build-binary.sh inherits the glibc of the build host. Built on
# ubuntu-latest (glibc 2.39) the bundled libpython demands GLIBC_2.38 and the
# binary dies on OL7 with:
#   Failed to load Python shared library ... GLIBC_2.38 not found
#
# How: run the exact same PyInstaller build inside a manylinux2014 container
# (CentOS 7 userland, glibc 2.17). The interpreter is a uv-managed CPython
# (python-build-standalone), whose Linux builds target glibc 2.17 and ship the
# shared libpython PyInstaller needs. pip inside the container can only accept
# wheels tagged <= manylinux2014, so every bundled .so clears the same floor.
# The in-container `--help` smoke test in build-binary.sh doubles as the glibc
# gate: it executes on glibc 2.17.
#
# Requires: docker on the host. Output: dist/pqcscan (same as build-binary.sh).
#
# Env:
#   PQCSCAN_COMPAT_SMOKE=0   skip the Oracle Linux 7.9 container smoke test
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_IMG="quay.io/pypa/manylinux2014_x86_64"
SMOKE_IMG="oraclelinux:7.9"
PYVER="3.11"

command -v docker >/dev/null 2>&1 || {
    echo "error: docker is required for the glibc-2.17 compat build" >&2
    exit 2
}

docker run --rm \
    -u "$(id -u):$(id -g)" \
    -e HOME=/tmp/home \
    -e PQCSCAN_IN_COMPAT_BUILD=1 \
    -v "$REPO_ROOT:/work" \
    -w /work \
    "$BUILD_IMG" \
    bash -euo pipefail -c '
        mkdir -p "$HOME"
        curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
        export PATH="$HOME/.local/bin:$PATH"
        uv python install '"$PYVER"'
        uv venv --python '"$PYVER"' /tmp/venv
        source /tmp/venv/bin/activate
        uv pip install -e ".[build]"
        bash scripts/build-binary.sh
    '

if [[ "${PQCSCAN_COMPAT_SMOKE:-1}" == "1" ]]; then
    echo
    echo "Smoke test on ${SMOKE_IMG} (glibc 2.17) ..."
    docker run --rm \
        -v "$REPO_ROOT/dist:/dist:ro" \
        "$SMOKE_IMG" \
        bash -euo pipefail -c '/dist/pqcscan --help >/dev/null && /dist/pqcscan version'
    echo "OK — binary runs on Oracle Linux 7.9"
fi
