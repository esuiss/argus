#!/usr/bin/env bash

set -euo pipefail
set +m
cd "$(git rev-parse --show-toplevel)"

BIND=127.0.0.1:8081
BASE="http://$BIND"
WORK="$(mktemp -d)"
trap 'pkill -f "argus-rotation-test" 2>/dev/null || true; rm -rf "$WORK"' EXIT

cargo build --release -p argus >/dev/null 2>&1

BIN="$WORK/argus-rotation-test"
cp target/release/argus "$BIN"

mkdir -p "$WORK/both" "$WORK/new-only"
"$BIN" keygen old-key "$WORK/both" >/dev/null
"$BIN" keygen new-key "$WORK/both" >/dev/null
cp "$WORK/both/new-key.pkcs8" "$WORK/new-only/"

start() {
  pkill -f "argus-rotation-test" 2>/dev/null || true
  sleep 0.5
  ARGUS_ISSUER="$BASE" ARGUS_BIND="$BIND" \
  ARGUS_SIGNING_KEY_DIR="$1" ARGUS_ACTIVE_KID="${2:-}" \
    "$BIN" >>"$WORK/server.log" 2>&1 &

  disown 2>/dev/null || true
  for _ in $(seq 1 40); do
    curl -sf "$BASE/.well-known/jwks.json" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  echo "sunucu ayaga kalkmadi" >&2
  exit 1
}

export ARGUS_ROTATION_BASE="$BASE"
export ARGUS_ROTATION_TOKENS="$WORK/tokens.json"

start "$WORK/both" old-key
python3 scripts/key_rotation_probe.py mint 200

start "$WORK/both" new-key
python3 scripts/key_rotation_probe.py expect 200

start "$WORK/new-only" new-key
python3 scripts/key_rotation_probe.py expect 401

echo "anahtar rotasyonu: 0 adet 401 (negatif kontrol de dogrulandi)"
