#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# If the app has a request proxy, it lives where Next.js will actually load it. Next 16:
# proxy.ts at the same level as app/ (so src/proxy.ts when src/app exists). One placed at
# the repo root never ran, every route answered anonymous callers with 200, and only RLS
# prevented a breach. middleware.ts is the pre-16 name and is flagged too.
source "$(dirname "$0")/lib.sh"
APP="$ROOT/src/app"; [ -d "$APP" ] || APP="$ROOT/app"
[ -d "$APP" ] || { echo "ok [$GATE] no app dir"; exit 0; }
LEVEL="$(dirname "$APP")"
while IFS= read -r f; do
  base="$(basename "$f")"; dir="$(dirname "$f")"
  case "$base" in middleware.ts|middleware.js) fail "$f: 'middleware' is the pre-Next-16 name; rename to proxy.ts";; esac
  if [ "$dir" != "$LEVEL" ]; then fail "$f: must be at $LEVEL/ (same level as app/) or it never loads"; fi
done < <(find "$ROOT" -type f \( -name 'proxy.ts' -o -name 'proxy.js' -o -name 'middleware.ts' -o -name 'middleware.js' \) -not -path '*/node_modules/*' -not -path '*/.next/*' -not -path '*/.git/*' -not -path "$ROOT/tests/*")
finish
