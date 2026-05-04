#!/usr/bin/env bash
# Populate ./tools/ with FOSS-tool binaries (syft, grype) for the
# current platform, ready to be bundled into the PyInstaller binary.
#
# Output layout:
#   tools/
#   ├── syft     (or syft.exe on Windows)
#   └── grype    (or grype.exe on Windows)
#
# When tools/ exists at PyInstaller build time, build/pyinstaller.spec
# bundles it into the resulting binary. At runtime, the offline_pack
# resolver finds these tools under sys._MEIPASS / 'tools'.
#
# Skipping the larger Grype-DB snapshot (~1 GB) here — that's a separate
# F4 batch. Without the snapshot, grype falls back to its online DB sync.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TOOLS_DIR="$REPO_ROOT/tools"
mkdir -p "$TOOLS_DIR"

# Anchore's official installers download platform-correct binaries
# and install them into the directory passed via -b.
echo "→ Installing syft into $TOOLS_DIR"
curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$TOOLS_DIR"

echo "→ Installing grype into $TOOLS_DIR"
curl -sSfL https://get.anchore.io/grype | sh -s -- -b "$TOOLS_DIR"

echo
echo "OK — offline pack staged at $TOOLS_DIR"
ls -lh "$TOOLS_DIR"
