#!/usr/bin/env bash
# Package SafeMark into dist/SafeMark-v<version>.zip (the exact folder users load unpacked)
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
OUT="dist/SafeMark-v${VERSION}.zip"
mkdir -p dist
rm -f "$OUT"

zip -r "$OUT" \
  manifest.json background.js popup.html popup.css popup.js icons/

echo "built $OUT"
