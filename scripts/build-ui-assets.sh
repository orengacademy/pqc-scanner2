#!/usr/bin/env bash
# Build src/pqcscan/ui/static/tailwind.min.css from the current templates,
# and refresh htmx if missing or stub. Run when a template introduces new
# Tailwind utility classes that weren't previously emitted.
#
# Requires Node.js (for npx tailwindcss) and curl. ~20 seconds to run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATIC_DIR="$REPO_ROOT/src/pqcscan/ui/static"
TEMPLATES_DIR="$REPO_ROOT/src/pqcscan/ui/templates"

# 1. Tailwind v3 CSS, scoped to the templates we actually ship.
TW_TMP="$(mktemp -d)"
trap 'rm -rf "$TW_TMP"' EXIT

cat > "$TW_TMP/input.css" <<'EOF'
@tailwind base;
@tailwind components;
@tailwind utilities;
EOF

cat > "$TW_TMP/tailwind.config.js" <<EOF
module.exports = {
  content: ["$TEMPLATES_DIR/**/*.html"],
  darkMode: 'class',
  theme: { extend: {} },
};
EOF

echo "[1/2] Building tailwind.min.css from templates ..."
( cd "$TW_TMP" && npx --yes tailwindcss@3.4.17 \
    -i input.css -c tailwind.config.js \
    -o "$STATIC_DIR/tailwind.min.css" --minify )
echo "      -> $(wc -c < "$STATIC_DIR/tailwind.min.css") bytes"

# 2. htmx — vendored once, not regenerated. Skip if file is already real.
HTMX_FILE="$STATIC_DIR/htmx-1.9.10.min.js"
if [ ! -s "$HTMX_FILE" ] || [ "$(wc -c < "$HTMX_FILE")" -lt 10000 ]; then
  echo "[2/2] Fetching htmx 1.9.10 ..."
  curl -sL --max-time 30 "https://unpkg.com/htmx.org@1.9.10/dist/htmx.min.js" \
    -o "$HTMX_FILE"
  echo "      -> $(wc -c < "$HTMX_FILE") bytes"
else
  echo "[2/2] htmx already vendored, skipping."
fi

echo "Done."
