#!/usr/bin/env bash
# `unsafe` denetimi — Faz 0 çıkış kriterinin özü.
#
# `cargo geiger --forbid-only` bir RAPOR aracıdır ve "yeşil"in ne demek olduğunu
# tanımlamaz. Argus'ta anlamı şudur ve burada zorlanır:
#
#   1. Workspace `unsafe_code = "forbid"` uygular; crate'ler ayrıca kaynakta
#      `#![forbid(unsafe_code)]` taşır (araçlar lint tablosunu görmüyor).
#   2. TEK istisna `argus-crypto` ve `argus-sandbox`'tır — ikisi de lint'i bilinçli
#      olarak geçersiz kılar (§11: FFI ve seccomp/Landlock için gerekli).
#   3. O ikisinde bile her `unsafe` bloğu GEREKÇE yorumu taşımak zorundadır.
#   4. Başka hiçbir crate `unsafe` içeremez ve lint'i geçersiz kılamaz.
#
# ⚠️ Desen satır başına BAĞLANMAZ: `pub unsafe fn` en yaygın biçimdir ve bu
# scriptin ilk sürümü tam olarak onu kaçırıyordu. Kapı, kasten eklenen bir ihlalle
# sınanmadan doğru kabul edilmemeli.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

# `unsafe` kelime sınırlarıyla; `unsafe_code` (lint adı) hariç.
# macOS grep'inde `\s` güvenilir değil, bu yüzden POSIX sınıfları kullanılıyor.
UNSAFE_RE='(^|[^_[:alnum:]])unsafe([^_[:alnum:]]|$)'
ALLOWED_CRATES='argus-crypto|argus-sandbox'

fail=0

# (1) İzin verilmeyen crate'lerde unsafe.
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

# (2) forbid lint'ini gizlice geçersiz kılanlar.
while IFS= read -r f; do
  case "$f" in
    *argus-crypto*|*argus-sandbox*) continue ;;
  esac
  if grep -q 'allow(unsafe_code)' "$f"; then
    echo "İHLAL: $f, unsafe_code lint'ini geçersiz kılıyor"
    fail=1
  fi
done < <(find crates -name '*.rs')

# (3) Manifest seviyesinde: yalnızca izinli iki crate workspace lint'lerinden ayrılabilir.
while IFS= read -r m; do
  crate=$(basename "$(dirname "$m")")
  if ! grep -q '^\[lints\]' "$m" && ! echo "$crate" | grep -qE "^($ALLOWED_CRATES)$"; then
    echo "İHLAL: $crate workspace lint'lerini devralmıyor ($m)"
    fail=1
  fi
done < <(find crates -name Cargo.toml)

# (4) İzinli crate'lerde her unsafe bloğunun ÜSTÜNDE gerekçe yorumu olmalı.
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
