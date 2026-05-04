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
