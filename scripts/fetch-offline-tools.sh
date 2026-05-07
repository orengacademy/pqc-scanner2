#!/usr/bin/env bash
# Populate ./tools/ with FOSS-tool binaries (syft) for the
# current platform, ready to be bundled into the PyInstaller binary.
#
# Output layout:
#   tools/
#   └── syft     (or syft.exe on Windows)
#
# When tools/ exists at PyInstaller build time, build/pyinstaller.spec
# bundles it into the resulting binary. At runtime, the offline_pack
# resolver finds these tools under sys._MEIPASS / 'tools'.
#
# Plan H.1 dropped: grype, trivy, pip-audit, npm, cargo-audit,
# govulncheck, lynis, bandit, gitleaks (CVE/secrets/audit out of PQC scope).
# Semgrep, testssl, sslyze, nmap remain expected on PATH or via separate
# installers — they are not staged by this script.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TOOLS_DIR="$REPO_ROOT/tools"
mkdir -p "$TOOLS_DIR"

# Anchore's official installer downloads platform-correct binary
# and installs it into the directory passed via -b.
echo "→ Installing syft into $TOOLS_DIR"
curl -sSfL https://get.anchore.io/syft | sh -s -- -b "$TOOLS_DIR"

echo
echo "OK — offline pack staged at $TOOLS_DIR"
ls -lh "$TOOLS_DIR"
