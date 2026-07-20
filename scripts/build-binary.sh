#!/usr/bin/env bash
# Build a single-file pqcscan binary via PyInstaller.
#
# Output:
#   dist/pqcscan          (Linux / macOS)
#   dist/pqcscan.exe      (Windows)
#
# Requires: pyinstaller>=6 on PATH (pip install pyinstaller).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# On Linux x86_64, delegate to the glibc-2.17 compat build (manylinux2014
# container) so the binary runs on RHEL / Oracle Linux 7+. Building directly
# on a modern distro links the bundled libpython against its glibc (e.g.
# GLIBC_2.38 on ubuntu-latest) and the binary aborts on older hosts. Set
# PQCSCAN_NO_COMPAT=1 to force a direct build (binary then only runs on
# hosts at least as new as this one).
if [[ "$(uname -s)/$(uname -m)" == "Linux/x86_64" \
      && "${PQCSCAN_IN_COMPAT_BUILD:-0}" != "1" \
      && "${PQCSCAN_NO_COMPAT:-0}" != "1" ]]; then
    if command -v docker >/dev/null 2>&1; then
        exec bash scripts/build-linux-compat.sh
    fi
    echo "warning: docker not found — building against this host's glibc." >&2
    echo "         The binary will NOT run on older hosts (RHEL/OL 7)." >&2
fi

if ! command -v pyinstaller >/dev/null 2>&1; then
    echo "error: pyinstaller not on PATH" >&2
    echo "       install with: pip install 'pyinstaller>=6'" >&2
    exit 2
fi

# Clean prior artifacts so we don't ship stale data.
rm -rf build/pqcscan-work dist/pqcscan dist/pqcscan.exe

pyinstaller \
    --clean \
    --noconfirm \
    --workpath build/pqcscan-work \
    build/pyinstaller.spec

# Smoke test: the binary must at least respond to --help.
BIN="dist/pqcscan"
[[ -f "${BIN}.exe" ]] && BIN="${BIN}.exe"

if [[ ! -x "$BIN" ]]; then
    echo "error: build did not produce $BIN" >&2
    exit 3
fi

"$BIN" --help >/dev/null

echo
echo "OK — built $(du -h "$BIN" | cut -f1) binary at $BIN"
