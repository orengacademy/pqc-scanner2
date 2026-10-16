#!/usr/bin/env bash
# Populate ./tools/ with FOSS-tool binaries (syft) for the current platform,
# ready to be bundled into the PyInstaller binary.
#
# Output layout:
#   tools/
#   └── syft     (or syft.exe on Windows)
#
# When tools/ exists at PyInstaller build time, build/pyinstaller.spec
# bundles it into the resulting binary. At runtime, the offline_pack
# resolver finds these tools under sys._MEIPASS / 'tools'.
#
# Supply chain: the version is pinned and the release tarball is verified
# against the checksums file published with that release — no `curl | sh`,
# no floating "latest". Bump SYFT_VERSION deliberately.
#
# Plan H.1 dropped: grype, trivy, pip-audit, npm, cargo-audit,
# govulncheck, lynis, bandit, gitleaks (CVE/secrets/audit out of PQC scope).
# Semgrep, testssl, sslyze, nmap remain expected on PATH or via separate
# installers — they are not staged by this script.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SYFT_VERSION="${SYFT_VERSION:-1.54.1}"
TOOLS_DIR="$REPO_ROOT/tools"
mkdir -p "$TOOLS_DIR"

case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=darwin ;;
    MINGW*|MSYS*|CYGWIN*) os=windows ;;
    *) echo "error: unsupported OS $(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "error: unsupported arch $(uname -m)" >&2; exit 2 ;;
esac

ext=tar.gz; [[ "$os" == windows ]] && ext=zip
asset="syft_${SYFT_VERSION}_${os}_${arch}.${ext}"
base="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "→ Fetching syft v${SYFT_VERSION} (${os}/${arch})"
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/checksums.txt" "$base/syft_${SYFT_VERSION}_checksums.txt"
(cd "$tmp" && grep " ${asset}\$" checksums.txt | sha256sum -c -)

if [[ "$ext" == zip ]]; then
    unzip -q -o "$tmp/$asset" -d "$tmp/x" && cp "$tmp/x/syft.exe" "$TOOLS_DIR/"
else
    tar -xzf "$tmp/$asset" -C "$tmp" syft && cp "$tmp/syft" "$TOOLS_DIR/"
fi
chmod +x "$TOOLS_DIR"/syft*

echo
echo "OK — offline pack staged at $TOOLS_DIR"
ls -lh "$TOOLS_DIR"
