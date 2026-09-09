#!/usr/bin/env bash

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

UNSAFE_RE='(^|[^_[:alnum:]])unsafe([^_[:alnum:]]|$)'
ALLOWED_CRATES='argus-crypto|argus-sandbox'

fail=0

while IFS= read -r f; do
  case "$f" in
    *argus-crypto*|*argus-sandbox*) continue ;;
  esac
  if sed 's://.*::' "$f" | grep -qE "$UNSAFE_RE"; then
    echo "İHLAL: $f içinde unsafe (yalnızca argus-crypto ve argus-sandbox'ta serbest)"
    sed 's://.*::' "$f" | grep -nE "$UNSAFE_RE"
    fail=1
  fi
done < <(find crates -name '*.rs')

while IFS= read -r f; do
  case "$f" in
    *argus-crypto*|*argus-sandbox*) continue ;;
  esac
  if grep -q 'allow(unsafe_code)' "$f"; then
    echo "İHLAL: $f, unsafe_code lint'ini geçersiz kılıyor"
    fail=1
  fi
done < <(find crates -name '*.rs')

while IFS= read -r m; do
  crate=$(basename "$(dirname "$m")")
  if ! grep -q '^\[lints\]' "$m" && ! echo "$crate" | grep -qE "^($ALLOWED_CRATES)$"; then
    echo "İHLAL: $crate workspace lint'lerini devralmıyor ($m)"
    fail=1
  fi
done < <(find crates -name Cargo.toml)

for c in argus-crypto argus-sandbox; do
  [ -d "crates/$c/src" ] || continue
  while IFS= read -r hit; do
    file=${hit%%:*}
    rest=${hit#*:}
    line=${rest%%:*}
    prev=$((line - 1))
    if [ "$prev" -lt 1 ] || ! sed -n "${prev}p" "$file" | grep -qE '^[[:space:]]*//'; then
      echo "İHLAL: $file:$line — unsafe bloğunun üstünde gerekçe yorumu yok (§11)"
      fail=1
    fi
  done < <(grep -rnE "$UNSAFE_RE" "crates/$c/src" 2>/dev/null | grep -v ':[[:space:]]*//')
done

if [ "$fail" -eq 0 ]; then
  echo "unsafe denetimi: temiz"
fi
exit "$fail"
