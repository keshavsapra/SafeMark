#!/usr/bin/env bash
# Package SafeMark into dist/SafeMark-<version>.zip.
# Zip contents live inside a top-level "SafeMark-<version>/" folder so
# extraction produces exactly one folder — point "Load unpacked" at it.
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
NAME="SafeMark-${VERSION}"
OUT="dist/${NAME}.zip"
mkdir -p dist
rm -f "$OUT"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME"
cp -r manifest.json background.js popup.html popup.css popup.js icons "$STAGE/$NAME/"

( cd "$STAGE" && zip -qr "$OLDPWD/$OUT" "$NAME" )

echo "built $OUT (contents inside $NAME/)"
