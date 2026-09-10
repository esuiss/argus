# 7. Formel doğrulanmış kriptografi

> `ARGUS.md` §7'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§7 §X` referansları aynı anlamda.


> **Metodoloji notu:** Her iddianın yanında kaynak URL + tarih var. Doğrulayamadığım şeyleri **[DOĞRULANAMADI]** olarak işaretledim. crates.io rakamları 2026-09-08 tarihinde crates.io API'sinden doğrudan çekildi; "son 90 gün" indirme sayıları `recent_downloads` alanıdır. libcrux deposu `main` dalından tarball olarak indirilip yerel olarak incelendi (2026-09-08).

---

## 0. YÖNETİCİ ÖZETİ (önce bunu oku)

1. **2026'da Rust'tan kullanılabilir gerçek formel doğrulanmış kripto var** — ama sandığından dar. Ana adres: **libcrux** (CE Labs, eski adıyla Cryspen) ve altındaki **hacl-rs** (HACL*'dan üretilmiş saf Rust).
2. **Argus'un ihtiyaç listesinin büyük kısmı karşılanıyor:** SHA-2, HMAC, HKDF, Ed25519, ECDSA P-256, X25519, ChaCha20-Poly1305, Poly1305 ve **RSA-PSS** hepsi HACL*-doğrulanmış Rust olarak mevcut.
3. **Kritik boşluklar:** **RS256 (RSA PKCS#1 v1.5) doğrulanmış hâlde yok**, **Argon2 hiçbir yerde doğrulanmış değil**, **AES-GCM libcrux'ta "pre-verification"**, **SHA-3 libcrux'ta doğrulanmamış**, **CSPRNG (HMAC-DRBG) doğrulanmamış**, **RSA anahtar üretimi yok**.
4. **En önemli 2026 gelişmesi:** Nadim Kobeissi'nin *"Verification Theatre"* makalesi (Şubat–Haziran 2026), libcrux/hpke-rs'te **13 zafiyet** buldu — 9'u doğrulanmamış kodda, **4'ü sözde doğrulanmış spesifikasyon/ispat kodunda**. libcrux ML-KEM Rust kodunun yalnızca **%58,4'ünün** ispatları gerçekten SMT çözücüye gönderiliyor. "Formally verified" etiketi ≠ "her şey doğrulanmış".
5. **Pratik tavsiye:** Argus için **hibrit** bir yaklaşım — kritik JWT primitifleri için libcrux, geri kalanı için `aws-lc-rs` (FIPS + s2n-bignum HOL Light doğrulamalı aritmetik) — ve libcrux'a **pre-release** (`< 0.1`) olduğu için pin'lenmiş sürüm + kendi test vektörlerinizle.

---

## 1. HACL* / EverCrypt (Project Everest, F*)

### 1.1 Ne doğrulanıyor?

HACL* deposu üç özelliği garanti ediyor:

> "memory safety, functional correctness, and secret independence (resistance to some types of timing side-channels)"
> — https://github.com/hacl-star/hacl-star (erişim 2026-09-08)

Bu üç özelliğin anlamı:
- **Bellek güvenliği (memory safety):** Low* seviyesinde dizi sınırları, pointer geçerliliği, taşma yok.
- **Fonksiyonel doğruluk (functional correctness):** Uygulama, F*'ta yazılmış yüksek seviye matematiksel spesifikasyona karşı doğrulanmış.
- **Gizli bağımsızlık (secret independence):** Low*'un tip sistemi, gizli değerler üzerinde dallanma / gizli indeksle dizi erişimi / gizli operandla değişken zamanlı işlem (div, mod) yapılmasını **kaynak seviyesinde** yasaklıyor. Bu "constant-time"ın *kaynak kodu* yaklaşımıdır.

### 1.2 Ne doğrulanMIYOR? (Trusted Computing Base)

Bu kısım Argus için hayati. Kaynak: CE Labs/Cryspen'in kendi "Strengths and Limitations" yazısı (https://cryspen.com/post/strengths-and-limitations/, **12 Şubat 2026**) ve Kobeissi 2026:

- **Derleyici:** F* → C (KaRaMeL) → makine kodu (gcc/clang/LLVM). KaRaMeL ve C derleyicisi TCB içinde, doğrulanmamış. Derleyici gizli-bağımsızlığı bozabilir (ör. `cmov`'u branch'e çevirebilir).
- **Yürütülebilir dosyanın yan-kanal direnci:** libcrux README'sinin kendi ifadesiyle: *"executables compiled from the code in this repository are **not** verified to be side-channel resistant, although we try to enforce that the source code is secret-independent"* — https://github.com/celabshq/libcrux `Readme.md` (yerel kopya, 2026-09-08).
- **Donanım:** Spectre/Meltdown, önbellek, spekülatif yürütme kapsam dışı.
- **Platform soyutlamaları / intrinsics:** SIMD sarmalayıcıları çoğu zaman aksiyom olarak alınıyor (aşağıda V1 vakası).
- **Glue/wrapper kodu:** C API'sini Rust'a saran katman genelde doğrulanmamış.
- **Doğrulama araçlarının kendisi:** F*, Z3, KaRaMeL, hax.

EverCrypt makalesi bu konuda dürüst olmasıyla ayrışıyor: Kobeissi'nin ifadesiyle *"EverCrypt is notable for its precise accounting of trust assumptions, explicitly identifying the compiler, Vale embedding semantics, and hardware as trusted components"* (Verification Theatre, s. 23, eprint 2026/192).

### 1.3 Desteklenen algoritmalar

https://hacl-star.github.io/Supported.html (erişim 2026-09-08):

| Kategori | Algoritma | Uygulama |
|---|---|---|
| AEAD | AES-GCM | Intel ASM (AES-NI + CLMUL) — **sadece x64 assembly (Vale)** |
| AEAD | ChaCha20-Poly1305 | Portable C + 128/256-bit vektörize |
| Hash | SHA2-224/256 | Portable C, Intel ASM (SHAEXT) |
| Hash | SHA2-384/512 | Portable C |
| Hash | SHA3 | Portable C |
| Hash | BLAKE2 | Portable C (+128/256) |
| Hash | MD5, SHA1 | Legacy |
| MAC/KDF | HMAC, HKDF | Portable C + Intel ASM |
| MAC | Poly1305 | Portable C (128/256), Intel ASM |
| İmza | Ed25519 | Portable C |
| İmza/ECDH | P-256 | Portable C |
| ECDH | Curve25519 | Portable C + Intel ASM (BMI2+ADX) |
| Şifre | ChaCha20, AES-128/256 | — |

**Ek olarak:** RSA-PSS bu sayfada listelenmemiş ama depoda mevcut — `code/rsapss/` dizininde `Hacl.Spec.RSAPSS.fst`, `Hacl.Impl.RSAPSS.fst`, `Hacl.Impl.RSAPSS.MGF.fst`, `Hacl.Impl.RSAPSS.Padding.fst`, `Hacl.RSAPSS.fst` (https://github.com/hacl-star/hacl-star/tree/main/code/rsapss, erişim 2026-09-08). Bu, libcrux-rsa'nın kaynağı.

**Not:** HACL*'ta **RSA PKCS#1 v1.5 (RS256) yok**, **Argon2 yok**, **PBKDF2/scrypt yok** (hashlib/HKDF var).

### 1.4 Gerçek dağıtımlar (her biri ayrı doğrulandı)

| Proje | Ne kullanıyor | Kanıt | Tarih |
|---|---|---|---|
| **Mozilla Firefox / NSS** | ChaCha20, ChaCha20-Poly1305 (32/128/256), Curve25519 (51 & 64), **Ed25519**, Poly1305, SHA-3, **P-256, P-384, P-521** | `nss/lib/freebl/verified/` dizininde `Hacl_*.c` dosyaları | erişim 2026-09-08 — https://github.com/nss-dev/nss/tree/master/lib/freebl/verified |
| **Firefox / NSS (PQ)** | **libcrux ML-KEM 512/768/1024 + ML-DSA 44/65/87** (Eurydice/Charon/Karamel ile üretilmiş C) | `nss/lib/freebl/libcrux/` — README: *"a combined C extraction of the libcrux ML-KEM (FIPS 203) and ML-DSA (FIPS 204) implementations"*, upstream commit `87eda899b207aa8fecbdf7a6ecfa5f70a9b2c68c` | erişim 2026-09-08 — https://github.com/nss-dev/nss/tree/master/lib/freebl/libcrux |
| **Linux çekirdeği** | Curve25519 (64-bit yol) | `lib/crypto/curve25519-hacl64.c` başlığı: *"machine-generated formally verified implementation of Curve25519 ECDH from https://github.com/mitls/hacl-star"*, Telif: INRIA + Microsoft 2016-2017, Jason A. Donenfeld 2018-2019 | erişim 2026-09-08 — https://github.com/torvalds/linux/blob/master/lib/crypto/curve25519-hacl64.c |
| **Linux çekirdeği** | Curve25519 (32-bit yol) — **HACL* değil, fiat-crypto** | `lib/crypto/curve25519-fiat32.c` | erişim 2026-09-08 — https://github.com/torvalds/linux/blob/master/lib/crypto/curve25519-fiat32.c |
| **WireGuard** | Yukarıdaki iki Curve25519 dosyası (Zinc'ten çekirdeğe geçti) | https://www.wireguard.com/formal-verification/ | erişim 2026-09-08 |
| **CPython** | MD5, SHA1, SHA2, SHA3 — OpenSSL sağlamadığında **HACL* fallback**; ayrıca BLAKE2 | hashlib dokümantasyonu: *"Changed in version 3.12: For any of the MD5, SHA1, SHA2, or SHA3 algorithms that the linked OpenSSL does not provide we fall back to a verified implementation from the HACL* project"* — https://docs.python.org/3/library/hashlib.html; BLAKE2 için gh-99108 / commit `325e9b8` | Python **3.12+**, erişim 2026-09-08 |
| **mbedTLS, Tezos, ElectionGuard** | Belirtilmemiş primitifler | Sadece HACL*'ın kendi beyanı: https://hacl-star.github.io/ | **[BAĞIMSIZ DOĞRULANAMADI]** — hangi algoritma, hangi sürüm, hâlâ güncel mi tespit edemedim |

### 1.5 2025–2026 aktivite durumu

HACL* deposu **aktif**. `main` dalındaki son commit'ler: 2026-04-10 (`Merge pull request #1070`), 2026-04-09 (birden çok), 2026-03-24 — https://github.com/hacl-star/hacl-star/commits/main (erişim 2026-09-08). Depo `main` dalı F*'ın `master` dalını takip ediyor; ~19.000 commit.

**Lisans:** Kod Apache-2.0; üretilen C kodu ayrıca MIT altında.

**Uyarı (kendi ifadeleri):** *"HACL*, Vale, and EverCrypt remain ongoing research projects and should be treated as such."* — https://hacl-star.github.io/ (erişim 2026-09-08).

---

## 2. HACL* RUST'TA — "hacl-rs", Eurydice, Charon, Scylla

### 2.1 Doğru terminoloji (burası çok karıştırılıyor)

Rust'a giden **iki ayrı** boru hattı var:

**(A) hacl-rs — KaRaMeL'in Rust arka ucu (Low* → güvenli Rust).**
Jonathan Protzenko'nun duyurusu (**20 Mart 2024**, https://jonathan.protzenko.fr/2024/03/20/hacl-rs.html):
> HACL-rs hedefi: *"a fast, verified, **pure, safe Rust** library of cryptographic primitives"*, uzun vadede libcrux'taki HACL C kodunu değiştirip C FFI bağlarını kaldırmak.

Alfa sürümünde kapsanan algoritmalar: hash'ler (SHA-1, SHA-2, SHA-3, BLAKE2), akış şifreleri (ChaCha20, Salsa20), MAC'ler (Poly1305, HMAC), AEAD (ChaCha-Poly), bignum'lar ve **imzalar (Ed25519, ECDSA-P256, RSA-PSS, FFDHE)**. Kapsam dışı: EverCrypt çoğullama/çevik API'leri, vektörize varyantlar, K256, HKDF (o tarihte).

Mekanizma (https://jonathan.protzenko.fr/2024/01/05/eurydice.html, **5 Ocak 2024**): KaRaMeL'in Rust arka ucu Low* buffer'ları ödünç alınmış dilimlere (`&[T]`/`&mut [T]`) çeviriyor; pointer aritmetiğini ağaç-tabanlı statik analizle yönetiyor.

**(B) Eurydice — Rust → C (ters yön!).**
Eurydice, *Rust'ı C'ye* derliyor (Charon + KaRaMeL kütüphane olarak). Bu, hax ile doğrulanmış Rust ML-KEM'in Firefox NSS ve OpenSSH'e C olarak girmesini sağlayan araç. Yani "Eurydice = F*'tan Rust üretme" **değil**.

### 2.2 Aradığın makaleler — gerçek isimleri

Sorunda geçen "Verified Rust Monomorphization" diye bir makale bulamadım. **[BULUNAMADI]** Gerçek makaleler şunlar:

1. **Charon: An Analysis Framework for Rust** — Son Ho, Guillaume Boisseau, Lucas Franceschino, Yoann Prak, Aymeric Fromherz, Jonathan Protzenko. arXiv:2410.18042 (v2, Ocak 2025); CAV 2025'te yayımlandı (Springer: https://link.springer.com/chapter/10.1007/978-3-031-98685-7_18).
   - Charon = rustc ile program doğrulayıcıları arasında arayüz; ULLBC (CFG) ve LLBC (yapılandırılmış AST) temsilleri sunuyor.
   - Eurydice ≈ 5.000 satır OCaml.
   - **Doğrudan alıntı:** *"code compiled by Eurydice has been integrated into Mozilla Firefox, Google's BoringSSL and OpenSSH"*
   - **HACL*'ın Rust'a port'u ≈ 84 kLoC** olarak değerlendirilmiş (arama sonuçlarında "80,000 satır" olarak da geçiyor).
   - Charon üzerine kurulu bir **taint-checker** (constant-time ihlali dedektörü) var: KyberSlash-benzeri açığı **10 saniyeden kısa sürede** tespit ediyor; CI'ya uygun. — https://arxiv.org/html/2410.18042v2

2. **Compiling C to Safe Rust, Formalized ("Scylla")** — Aymeric Fromherz, Jonathan Protzenko. arXiv:2412.15042, **OOPSLA 2026**. libcrux'un `rsa` ve `ecdsa` alt-crate README'leri C→Rust dönüşümü için doğrudan **bu makaleye** referans veriyor. Tip-yönlendirmeli C alt-kümesi → güvenli Rust çevirisi. — https://arxiv.org/abs/2412.15042

3. **hax: Verifying Security-Critical Rust Software using Multiple Provers** — Bhargavan, Buyse, Franceschino, Letager Hansen, Kiefer, Schneider-Bensch, Spitters. eprint 2025/142, VSTTE 2024 bildirileri (Springer, 2025). — https://eprint.iacr.org/2025/142

> **Sonuç:** "hacl-rs: A Verified Rust Cryptographic Library" adlı bir USENIX/S&P makalesi **bulamadım**. hacl-rs'in akademik dayanağı Charon (CAV'25) + Scylla (OOPSLA'26) + orijinal HACL* makaleleridir. **[hacl-rs'e özel tekil makale DOĞRULANAMADI]**

### 2.3 crates.io'da hacl-rs var mı?

**`hacl-rs` adında bir crate YOK.** Gerçek isim **`libcrux-hacl-rs`**:

| Alan | Değer |
|---|---|
| Sürüm | **0.0.5** |
| Toplam indirme | **1.943.244** |
| Son 90 gün | 1.123.859 |
| İlk yayın | 2025-02-24 |
| Son güncelleme | 2026-05-13 |
| Lisans | Apache-2.0 |
| Açıklama | *"Formally verified Rust code extracted from HACL* - helper library"* |

Modülleri: `bignum`, `bignum25519_51`, `curve25519_51`, `streaming_types`, `fstar`, `lowstar`, `prelude`, `util`. HACL* commit `efbf82f29190e2aecdac8899e4f42c8cb9defc98`'den üretilmiş.
— crates.io API + https://docs.rs/libcrux-hacl-rs/latest/libcrux_hacl_rs/ (2026-09-08)

Bu crate doğrudan kullanılmıyor; algoritmalar `libcrux-*` crate'lerinden geliyor (bkz. Bölüm 3).

Eski/ölü crate'ler (kullanma): `hacl` 0.0.3-pre.1 (2023), `hacl-star` 0.1.0 (2019, C'ye binding), `hacl-sys`, `libcrux-hacl` 0.0.2-pre.2 (2024).

---

## 3. LIBCRUX — 2026 DURUMU (EN ÖNEMLİ BÖLÜM)

### 3.1 Kurumsal değişiklik: Cryspen → CE Labs

**Depo `github.com/cryspen/libcrux` → `github.com/celabshq/libcrux` adresine taşındı.** crates.io metadata hâlâ eski `cryspen/libcrux` URL'sini gösteriyor; README içindeki linkler de eski URL'yi kullanıyor. İletişim adresi artık `info@celabs.eu`, güvenlik bildirimi `security-reports@celabs.eu`.
— https://github.com/celabshq/libcrux (erişim 2026-09-08); depo `Readme.md` ve `SECURITY.md` (yerel kopya).

### 3.2 Doğrulama rozet sistemi (README'den birebir)

libcrux üç rozet kullanıyor — **bunları ezberle, Argus kararlarının temeli bu:**

- **`pre-verification`** (turuncu): *"most (or all) of the code that is contained in default features of that crate is not (yet) verified"*
- **`verified-hacl`** (yeşil): *"algorithms in a crate have been verified and extracted to Rust as part of the HACL* project. The source F* code in HACL* is verified for memory safety, functional correctness against a high-level spec, and secret independence... **Top-level Rust APIs in these crates accessing the code from HACL* may not be verified.**"*
- **`verified`** (yeşil): *"most (or all) of the Rust code... is verified using the hax toolchain... panic free and functionally correct against a mathematical spec"*

Ve kritik feragat:
> *"Importantly, executables compiled from the code in this repository are **not** verified to be side-channel resistant, although we try to enforce that the source code is secret-independent (also sometimes called 'constant-time')."*

Ayrıca:
> *"libcrux is in pre-release (all of its crates are versioned < `0.1`). If you wish to use any of these crates in production, get in touch with the maintainers and we can advise you on whether libcrux is a good fit for your use-case."*

— libcrux `Readme.md`, `main` dalı, indirilen tarball (2026-09-08)

### 3.3 Algoritma-bazında doğrulama durumu — TAM TABLO

Bunu her alt-crate'in kendi README'sinden **doğrudan okudum** (tarball, 2026-09-08). WebFetch özetlerine güvenme, bu tablo kaynak koddan:

| Crate | Algoritma | Rozet | Not |
|---|---|---|---|
| `libcrux-sha2` | SHA-224/256/384/512 | **verified-hacl** ✅ | |
| `libcrux-hmac` | HMAC | **verified-hacl** ✅ | HMAC-SHA1 desteği 0.0.4'te kaldırıldı (PR #1391) |
| `libcrux-hkdf` | HKDF | **verified-hacl** ✅ | |
| `libcrux-ed25519` | Ed25519 | **verified-hacl** ✅ | |
| `libcrux-ecdsa` | ECDSA P-256 | **verified-hacl** ✅ | **low-S normalizasyonu YOK** (kaynakta `low_s`/`normalize` grep'i boş döndü) |
| `libcrux-p256` | P-256 (ECDH) | **verified-hacl** ✅ | "internal to libcrux, do not use directly" |
| `libcrux-rsa` | **RSA-PSS** | **verified-hacl** ✅ | SHA-256/384/512; 2048/3072/4096/6144/8192 + varlen; **anahtar üretimi YOK** |
| `libcrux-curve25519` | X25519 | **verified-hacl** ✅ | |
| `libcrux-chacha20poly1305` | ChaCha20-Poly1305 | **verified-hacl** ✅ | **XChaCha20Poly1305 sarmalayıcısı DOĞRULANMAMIŞ** |
| `libcrux-poly1305` | Poly1305 | **verified-hacl** ✅ | |
| `libcrux-blake2` | BLAKE2 | **verified-hacl** ✅ | |
| `libcrux-ml-kem` | ML-KEM 512/768/1024 | **verified (hax)** ⚠️ | Kısmî — bkz. 3.5 |
| `libcrux-ml-dsa` | ML-DSA 44/65/87 | **verified (hax)** ⚠️ | Kısmî — sadece "field arithmetic, NTT, serialization" |
| `libcrux-kmac` | KMAC | **verified (hax)** | "verified for runtime safety using F*" (sadece panik-yokluğu) |
| **`libcrux-aes`** | **AES-GCM 128/256, AES-CCM** | **pre-verification** ❌ | Argus JWE için kritik boşluk |
| **`libcrux-sha3`** | **SHA-3 / SHAKE (FIPS 202)** | **pre-verification** ❌ | |
| **`libcrux-hmac-drbg`** | **HMAC-DRBG (CSPRNG)** | **pre-verification** ❌ | *"This crate is still pending verification."* |
| `libcrux-secrets` | gizli-bağımsızlık yardımcıları | **pre-verification** ❌ | |
| `libcrux-psq` | PSQ protokolü | **pre-verification** ❌ | |

> ⚠️ **Uyarı:** GitHub üzerinden yaptığım ilk otomatik özet SHA-3'ü ve AES-GCM'i "verified" olarak raporlamıştı — **bu yanlıştı**. Depo dosyalarının doğrudan okunması ikisinin de `pre-verification` olduğunu gösteriyor.

### 3.4 crates.io metrikleri (2026-09-08, canlı API)

| Crate | Sürüm | Toplam indirme | Son 90 gün | Son yayın | Lisans |
|---|---|---|---|---|---|
| `libcrux-sha3` | 0.0.10 | 3.051.978 | — | 2026-07-15 | Apache-2.0 |
| `libcrux-intrinsics` | 0.0.8 | 3.040.943 | — | 2026-07-15 | Apache-2.0 |
| `libcrux-ml-kem` | **0.0.10** | 2.771.531 | 1.212.756 | 2026-07-15 | Apache-2.0 |
| `libcrux-secrets` | 0.0.6 | 2.744.096 | 1.281.685 | 2026-07-15 | Apache-2.0 |
| `libcrux-traits` | 0.0.8 | 2.800.556 | — | 2026-07-15 | Apache-2.0 |
| `libcrux-hacl-rs` | 0.0.5 | 1.943.244 | 1.123.859 | 2026-05-13 | Apache-2.0 |
| `libcrux-sha2` | 0.0.8 | 1.937.139 | 1.119.955 | 2026-07-15 | Apache-2.0 |
| `libcrux-p256` | 0.0.8 | 1.730.753 | 1.038.793 | 2026-07-15 | Apache-2.0 |
| `libcrux-hmac` | 0.0.8 | 1.550.260 | 903.556 | 2026-07-15 | Apache-2.0 |
| `libcrux-chacha20poly1305` | 0.0.9 | 1.441.398 | 868.709 | 2026-07-15 | Apache-2.0 |
| `libcrux-hkdf` | 0.0.8 | 1.432.189 | — | 2026-07-15 | Apache-2.0 |
| `libcrux-curve25519` | 0.0.8 | 1.397.171 | 833.192 | 2026-07-15 | Apache-2.0 |
| `libcrux-aesgcm` | 0.0.8 | 1.117.406 | 757.157 | 2026-05-13 | Apache-2.0 |
| `libcrux-ed25519` | **0.0.9** | 266.180 | 117.793 | 2026-07-15 | Apache-2.0 |
| `libcrux-ml-dsa` | 0.0.10 | 171.691 | 113.789 | 2026-07-15 | Apache-2.0 |
| `libcrux-hmac-drbg` | 0.0.1 | 22.257 | 22.257 | 2026-07-15 | Apache-2.0 |
| **`libcrux-ecdsa`** | 0.0.8 | **4.985** | **721** | 2026-07-15 | Apache-2.0 |
| **`libcrux-rsa`** | 0.0.8 | **4.288** | **582** | 2026-07-15 | Apache-2.0 |
| `libcrux` (re-export) | 0.0.5 | 64.867 | 15.072 | 2026-07-15 | Apache-2.0 |

**Yorum:** ML-KEM/SHA-2/HMAC/X25519 milyonlarca indirme (Signal, NSS, HPKE zincirinden geliyor). Ama **Argus için en kritik iki crate — `libcrux-ecdsa` ve `libcrux-rsa` — 90 günde sırasıyla 721 ve 582 indirme** almış. Yani ES256 ve PS256 yolları pratikte neredeyse hiç kullanılmıyor. Bu bir **olgunluk/battle-testing riski**.

**MSRV:** 1.89.0 (varsayılan özellik seti; `no_std` de 1.89.0'dan itibaren).
**`no_std`:** Destekleniyor, ancak `libcrux-rsa` global allocator gerektiriyor.
**Lisans:** crates.io metadata Apache-2.0; depoda hem `LICENSE` hem `LICENSE-MIT` var (Apache-2.0 AND MIT).

### 3.5 libcrux-ml-kem: gerçek doğrulama kapsamı

Deponun kendi `libcrux-ml-kem/proofs/verification_status.md` dosyası (tarball, 2026-09-08) — ve dosyanın kendi uyarısı: *"This version was generated by a simple script, but we need a more precise way of visualizing the proof status... treat the table below as a rough guide"*.

**Generic modüller:**
| Modül | Fn | Panik-yok | Doğru |
|---|---|---|---|
| constant_time_ops | 7 | 7/7 | 7/7 |
| hash_functions | 49 | 49/49 | 49/49 |
| **ind_cpa** | 21 | **0/21** | **0/21** |
| ind_cca | 27 | 27/27 | 26/27 |
| polynomial | 35 | 35/35 | 34/35 |
| ntt | 8 | 4/8 | 4/8 |
| invert_ntt | 6 | 4/6 | 4/6 |
| **matrix** | 5 | **1/5** | **0/5** |
| serialize | 20 | 16/20 | **2/20** |
| **sampling** | 5 | **0/5** | **0/5** |

**Backend'ler:**
- **Portable:** arithmetic 13/13, ntt 10/10, serialize 22/22, compress 6/6, sampling 1/1 — **tam** ✅
- **AVX2:** arithmetic 12/12 panik-yok (11/12 doğru), ntt 5/7, serialize 19/22 — **kısmî** ⚠️
- **NEON (ARM64 = iOS, modern Android, Apple Silicon, AWS Graviton):** arithmetic **0/13**, ntt **0/7**, compress **0/7**, serialize **0/12** — **neredeyse hiç doğrulanmamış** ❌

**Ve F* Makefile'ından doğrudan (yerel kopya, `libcrux-ml-kem/proofs/fstar/extraction/Makefile`, 2026-09-08):**
```
SLOW_MODULES += Libcrux_ml_kem.Vector.Rej_sample_table.fsti
ADMIT_MODULES =  Libcrux_ml_kem.Sampling.fst \
              Libcrux_ml_kem.Ind_cpa.fst \
              Libcrux_ml_kem.Vector.Neon.Arithmetic.fst \
              Libcrux_ml_kem.Vector.Neon.Compress.fst \
              Libcrux_ml_kem.Vector.Neon.fsti \
              Libcrux_ml_kem.Vector.Neon.fst \
              Libcrux_ml_kem.Vector.Neon.Ntt.fst \
              Libcrux_ml_kem.Vector.Neon.Serialize.fst \
              Libcrux_ml_kem.Vector.Neon.Vector_type.fst
```
`ADMIT_MODULES`'daki modüller `--admit_smt_queries true` ile derleniyor — yani **ispatları hiç kontrol edilmiyor**. IND-CPA çekirdeği ve tüm NEON yolu bu listede, **bugün itibariyle hâlâ**.

### 3.6 ML-KEM/ML-DSA gerçek üretim benimsenmesi (somut kanıtlar)

| Kullanıcı | Kanıt | Tarih |
|---|---|---|
| **Mozilla Firefox / NSS** | `nss/lib/freebl/libcrux/` — libcrux ML-KEM+ML-DSA'nın Eurydice/Charon/Karamel C çıkarımı, upstream commit `87eda899b2` | erişim 2026-09-08 |
| **Signal (libsignal)** | `Cargo.toml`: `libcrux-ml-kem = { version = "0.0.10" }`, `hpke-rs = "0.7"`, `hpke-rs-crypto = "0.7"` | erişim 2026-09-08 — https://github.com/signalapp/libsignal/blob/main/Cargo.toml |
| **OpenSSH / OpenBSD** | `src/usr.bin/ssh/libcrux-mlkem-mldsa.c` (rev 1.1, **14 Haziran 2026**), `libcrux_internal.h`, `mlkem_mldsa.sh`. Commit mesajı: *"The ML-DSA implementation comes from libcrux. Thanks to Jonas Schneider-Bensch and Jonathan Protzenko"* | https://cvsweb.openbsd.org/src/usr.bin/ssh/ (erişim 2026-09-08) |
| **OpenSSH 9.9 (mlkem768x25519)** | Release notu ML-KEM+X25519 hibrit KEX eklendiğini söylüyor ama **kaynak kütüphaneyi belirtmiyor**. hax makalesi (eprint 2025/142) *"adopted by OpenSSH and by Mozilla for use in its NSS"* diyor. | Release 2024-09-19 — https://www.openssh.org/txt/release-9.9 — **[release notundan libcrux DOĞRULANAMADI, ancak 2026 CVS'i libcrux'u açıkça teyit ediyor]** |
| **Google (dahili)** | Kobeissi 2026, libcrux'un *"the ML-KEM implementation used internally at Google"* olduğunu, kaynak olarak Google bughunters blogunu gösteriyor. Blog gövdesini çekemedim. | **[BLOG GÖVDESİ DOĞRULANAMADI]** — https://bughunters.google.com/blog/6038863069184000/formally-verified-post-quantum-algorithms |
| **OpenMLS** | `openmls_libcrux_crypto` 0.4.0, 105.584 indirme, güncelleme 2026-08-25 | crates.io, 2026-09-08 |
| **Chrome / BoringSSL** | Charon makalesi Eurydice-üretimi kodun BoringSSL'e girdiğini söylüyor. Ancak BoringSSL'in ML-KEM'i kendi implementasyonu olabilir. | **[HANGİ KOD OLDUĞU DOĞRULANAMADI]** |

### 3.7 🔴 "VERIFICATION THEATRE" — 2026'nın en önemli bulgusu

**Kaynak:** Nadim Kobeissi (Symbolic Software, Paris), *"Verification Theatre: False Assurance in Formally Verified Cryptographic Libraries"*, IACR ePrint **2026/192**. Alındı 5 Şubat 2026, son revizyon **25 Haziran 2026**. — https://eprint.iacr.org/2026/192 (PDF'i indirip tam metnini çıkardım)

**13 zafiyet, 5 hata tipi taksonomisi:**

**Doğrulama sınırının dışında (Tip I–IV) — 9 adet:**

| # | Zafiyet | Tip | Etki |
|---|---|---|---|
| V1 | `_vxarq_u64` intrinsic sarmalayıcısı yanlış argüman geçiriyor → ARM64'te SHA-3 bozuk | I | libcrux-ml-dsa v0.0.3'te farklı platformlarda **farklı public key ve imza** üretiyordu. Filippo Valsorda bildirdi, Kasım 2025. **RUSTSEC-2025-0133** (2025-12-04), `libcrux-intrinsics` ≤0.0.3 etkileniyor, 0.0.4'te düzeltildi — https://rustsec.org/advisories/RUSTSEC-2025-0133.html |
| V2 | Incremental API'de backend'ler arası endianness tutarsızlığı | I | **Signal'in post-quantum ratchet'inde gerçek şifre çözme hataları.** Signal v0.76.3–v0.86.9 etkilendi; libsignal v0.86.12'de (15 Ocak 2026) düzeltildi. GuuJiang bildirdi 27 Aralık 2025; CE Labs 6 Ocak 2026'da merge etti, **güvenlik danışma belgesi yayınlamadı** |
| V3 | hpke-rs: X25519 all-zero paylaşılan sır kontrolü yok (RFC 9180 §7.1.4 "MUST") | II | Düşük mertebeli public key ile tüm HPKE key schedule'ı deterministik hale getirilebilir. **Signal `signal-crypto` ve OpenMLS etkileniyor** |
| V4 | hpke-rs: sequence number `u32`, taşma kontrolü `u128 > 2⁹⁶-1` ile karşılaştırıyor → **ölü kod** | II | Release build'de sayaç sessizce sıfıra sarıyor → **nonce yeniden kullanımı** → plaintext kurtarma ve evrensel forgery |
| V5 | ECDSA P-256: `s ≤ n/2` (low-S) kontrolü yok | III | İmza malleability. FIPS 186-5'e uygun ama Bitcoin/Ethereum gibi sistemlerin gerektirdiği teklik yok. **Kaynak kodda bugün de yok (grep ile teyit ettim, 2026-09-08)** |
| V6 | Ed25519 `key_gen` sarmalayıcısı tohumu **iki kez** clamp'liyor | IV | Etkin tohum entropisi **5 bit** azalıyor. **Düzeltildi** — güncel `crates/algorithms/ed25519/src/impl_hacl.rs`'te clamp yok |
| V7 | libcrux-psq: AES-GCM decrypt'te `.unwrap()` | IV | Tek bozuk ciphertext süreci çökertiyor; ayrıca **IND-CCA güvenliğini bozuyor** (decryption oracle ⊥ döndürmek yerine sonlanıyor) |
| V8 | ML-DSA doğrulayıcı norm kontrolü `2<<GAMMA1_EXPONENT` = `2γ₁` kullanıyor (doğrusu `γ₁-β`) → **ölü kod** | IV | Kötü niyetli imzalayan, libcrux'un kabul edip FIPS 204 uyumlu implementasyonların reddedeceği imzalar üretebilir. Commit `326c837a33` (7 Ocak 2025) |
| V9 | ML-DSA hint deserialization: yanlış değişken kontrol ediliyor (`previous_` yerine `current_`) | IV | Son satırda ω sınırı aşılabiliyor → keyfi hint pozisyonları; **strong unforgeability ihlali** |

**Sözde doğrulanmış kodun içinde (Tip V) — 4 adet:**

| # | Zafiyet | Detay |
|---|---|---|
| V10 | `Spec.MLKEM.Math.fst`'te `decompress_d` **yanlış sabit 1664** kullanıyor (doğrusu `2^(d-1)`) | FIPS 203 ile **d ∈ {1,4,5,10,11} için her girdide** uyuşmuyor. `decompress_d(d,0) ≠ 0`. Rust implementasyonu doğru, **spesifikasyon yanlış** |
| V11 | ML-KEM spesifikasyonunda eksik ters NTT | |
| V12 | Serialization'da **yanlış bir lemma sessizce kabul ediliyor** (lax modda `if lax_on () then iterAll tadmit`) | Modül `SLOW_MODULES`'ta olduğu için "tam" doğrulamada bile admit ediliyor |
| V13 | ML-DSA AVX2 intrinsics aksiyomlarında `i16_mul_32extended` **x·y yerine x² hesaplıyor** | Tüm AVX2 ispatlarının matematiksel temelini **sağlamsız (unsound)** kılıyor |

**Nicel analiz (Tablo 5, makale s. 16):**

| Bileşen | Doğrulanmış | Admit | Opaque | Çıkarılmamış | Toplam |
|---|---|---|---|---|---|
| ML-KEM generic | 8.986 | 1.464 | — | 3.198 | 13.648 |
| Portable backend | 1.431 | 748 | — | — | 2.179 |
| AVX2 backend | 1.732 | — | — | — | 1.732 |
| **NEON backend** | **0** | **792** | — | — | 792 |
| **libcrux-intrinsics** | 0 | — | **2.457** | — | 2.457 |
| **TOPLAM** | **12.149** | 3.004 | 2.457 | 3.198 | 20.808 |
| **Oran** | **%58,4** | %14,4 | %11,8 | %15,4 | %100 |

> **Bir ML-KEM dağıtımını oluşturan Rust kodunun yalnızca %58,4'ünün ispatları gerçekten SMT çözücü tarafından kontrol ediliyor.**

**Modül seviyesinde (Tablo 6):** 138 çıkarılmış F* modülünün 127'si (%92) kontrol ediliyor; ama admit edilen 11 modül **en güvenlik-kritik olanlar**: `Ind_cpa.fst`, `Sampling.fst`, 7 NEON modülü, ve V12'yi barındıran `Vector.Portable.Serialize.fst`. Ayrıca: *"no CI configuration ever sets `VERIFY_SLOW_MODULES=yes`; the slow modules have never been checked by any automated system."*

**İfşa süreci (Tablo 10) — Argus'un tedarikçi risk değerlendirmesi için önemli:**

| Tarih | Olay |
|---|---|
| Kas 2025 | Valsorda V1'i bildiriyor; CE Labs düzeltiyor, **güvenlik danışma belgesi yayınlamıyor** (advisory'yi Birr-Pixton açıyor) |
| 27 Ara 2025 | GuuJiang V2'yi bildiriyor (Signal PQ ratchet arızası) |
| 6 Oca 2026 | CE Labs V2 düzeltmesini merge ediyor, **yine advisory yok** |
| 5 Şub 2026 | Symbolic Software V3–V6 için test edilmiş PR'lar gönderiyor |
| 5–6 Şub | **CE Labs raportörün GitHub hesabını engelliyor**, 4 PR'ı da kapatıyor, ifşa anında depoda **mevcut olmayan** bir "documented Security Policy"ye atıfla |
| 9 Şub | CE Labs düzeltmeleri **atıf vermeden** merge ediyor |
| 12 Şub | CE Labs yanıt yayımlıyor: V1 ve V6'yı kabul, V3–V5 ve V7'yi atlıyor, **"no bugs have been found in the verified code"** diyor — V8–V13 bunu doğrudan yalanlıyor |
| Şub 2026 | V7, V10–V13 keşfediliyor; raporlama kanalı kalmadığı için public commit ile ifşa |
| 17 Şub | V8–V9 ifşa (2 FIPS 204 ihlali) |
| 4 Mar | CE Labs V8 ve V9 düzeltmelerini merge ediyor, **bu sefer atıf vererek** |

CE Labs'ın 12 Şubat 2026 tarihli yanıtı: https://cryspen.com/post/strengths-and-limitations/ — doğrulamanın güçlü yanlarını ve sınırlarını dürüstçe anlatıyor (platform stub'ları, sarmalayıcılar, sistem kütüphaneleri, F*/KaRaMeL/hax'in kendisi, ve *"we do not prove formal guarantees of side-channel resistance"* for compiled executables) ama **Symbolic Software'in bulgularına atıf yapmıyor**.

Symbolic Software'in ML-DSA yazısı: https://symbolic.software/blog/2026-02-17-ce-labs-mldsa/ (17 Şubat 2026) — *"Twenty-seven modules are in VERIFIED_MODULES; everything else is in ADMIT_MODULES, including the top-level signing and verification logic."*

### 3.8 libcrux CHANGELOG'undan güvenlik-ilgili düzeltmeler (yerel kopya, 2026-09-08)

**0.0.5 (2026-07-15):**
- **`(libcrux-aes) #1528`: "Use constant time comparison for AES-GCM and AES-CCM tag check"** — yani **2026 Temmuz'una kadar AES-GCM/CCM tag karşılaştırması sabit zamanlı değildi.** Argus JWE için doğrudan alakalı.
- `(libcrux-sha3) #1456`: AVX2 SHAKE-256'da **out-of-bounds indeksleme** düzeltmesi
- `(libcrux-secrets) #1460/#1461`: aarch64 select/swap'ta hatalı cmp
- `(libcrux-aes) #1474`: AES-GCM için RFC 5116 plaintext/AAD uzunluk limitleri eklendi

**0.0.4 (2026-05-13):**
- `(libcrux-ml-dsa) #1398`: hatalı AVX2 `use_hint`
- `(libcrux-ml-dsa) #1395`: AVX2'de iNTT girdilerinin tam indirgenmemesi
- `(libcrux-chacha20poly1305) #1386`: `encrypt`'te potansiyel panik (@fg0x0 bildirdi)

**Unreleased:** `(libcrux-hmac-drbg) #1558`: reseeding sarmalayıcılarının `fill_bytes` metodunda panik düzeltmesi

**Yorum:** Bu, sağlıklı bir güvenlik iyileştirme temposu — ama aynı zamanda kütüphanenin hâlâ olgunlaşma aşamasında olduğunun kanıtı.

### 3.9 libcrux'un constant-time test altyapısı (kopyalanmaya değer)

`crates/utils/ctgrind-test/` — **Valgrind memcheck ile CT testi.** `crabgrind` (Rust Valgrind Client Request binding'i, v0.3.1, 899.848 indirme, 2026-07-20) kullanıyor:
- Gizli veri `mark_memory` ile "undefined" işaretleniyor
- Kripto işlemi çalıştırılıyor
- Valgrind, undefined bit içeren bir değerin gözlemlenebilir davranış farkı yaratacak şekilde kullanılmasını (bellek adresi üretimi, kontrol akışı kararı, syscall parametresi) raporluyor

Test edilen binary'ler: `sha3`, `mlkem` (ML-KEM-512 decapsulate, undefined private key), `mldsa` (ML-DSA-44/65/87 sign).

`libcrux-secrets` crate'i `--cfg valgrind_ct_test` + `check-secret-independence` feature ile bu işaretlemeyi otomatikleştiriyor. Kendi uyarısı:
> *"Note that this does not check for other side channels, such as variable time instructions (e.g., div) or cache side channels."*

**Argus için doğrudan uygulanabilir bir desen.**

---

## 4. HAX TOOLCHAIN (Cryspen/CE Labs)

### 4.1 Ne yapıyor

Rust'ın bir alt kümesini alıp çoklu kanıt arka uçlarının giriş diline çeviriyor. İki parça: **frontend** (rustc'ye hook, zenginleştirilmiş AST döküyor) + **engine** (OCaml binary, çeviri fazlarını uygulayıp F*/Coq/... üretiyor).
— https://github.com/cryspen/hax, https://hax.cryspen.com/frontend/ (erişim 2026-09-08)

**Tarihçe:** Aralık 2023'te hacspec'ten sıfırdan yeniden başlatıldı. hacspec artık hax içinde bir **spesifikasyon dili** (saf fonksiyonel Rust alt kümesi) olarak yaşıyor.

### 4.2 Arka uç olgunluğu (2026-09-08)

| Backend | Durum |
|---|---|
| **F\*** | **Stable** — üretime hazır |
| **Lean (Charon + Aeneas üzerinden)** | **Aktif geliştirilen / önerilen** |
| Rocq (Coq) | Deneysel |
| ProVerif | Deneysel |
| SSProve | Deneysel |
| EasyCrypt | Deneysel |

— https://github.com/cryspen/hax (erişim 2026-09-08)

**Not:** Lean backend'in "önerilen" hâle gelmesi 2026'nın önemli bir değişimi; makale (2025/142) yazıldığında Lean henüz "gelecek çalışma"ydı.

### 4.3 Kanıtlanabilen özellikler

hax makalesi (eprint 2025/142) ve Cryspen'in ML-KEM yazısına göre (https://cryspen.com/post/ml-kem-implementation/, **16 Ocak 2024**) hax + F* ile üç özellik:
1. **Fonksiyonel doğruluk** (spesifikasyona karşı)
2. **Runtime safety / panic freedom** (panik yok, dizi sınırları, integer overflow yok)
3. **Secret independence** — gizli değerler üzerinde dallanmama, gizli-zamanlı işlem yapmama, gizli indeksli dizi erişimi yapmama

### 4.4 Rust alt kümesi kısıtları

- **`&mut T` dönüş tiplerinde ve aliasing durumunda yasak.**
- Desteklenmeyen özelliklerin listesi GitHub'da etiketli; bir kısmı "wontfix-v1".
— https://github.com/cryspen/hax (erişim 2026-09-08)

### 4.5 crates.io

`hax-lib` **0.4.0** (yayın **2026-09-07** — dün!), toplam 3.122.564 indirme, son 90 gün 1.344.309, Apache-2.0. Önceki: 0.3.7 (2026-05-20), 0.3.6 (2026-01-15).
— crates.io API, 2026-09-08

**Bu, hax'in aktif ve hızlı geliştirildiğini gösteriyor.** Ancak `hax-lib`'in yüksek indirme sayısı büyük ölçüde libcrux'un transitif bağımlılığı olmasından geliyor, bağımsız kullanımdan değil.

### 4.6 hax ile doğrulanan diğer projeler

- **Bertie** (TLS 1.3, Rust) — ProVerif ile sembolik güvenlik analizi + F* ile parsing/serialization panic-freedom (https://github.com/cryspen/bertie)
- **Crux-MIR** (Galois) hacspec'i benimsedi; **ring**'in SHA-1 ve SHA-2 implementasyonlarını hacspec spesifikasyonlarına karşı doğruladı (hax makalesi, eprint 2025/142)
- Coq backend ile **fiat-crypto** bağlantısı (Holdsbjerg-Larsen & Spitters, CoqPL'22)
- Rust akıllı sözleşmeleri (ConCert, Coq)

---

## 5. FIAT-CRYPTO (Coq, MIT PLV)

### 5.1 Ne üretiyor, ne kanıtlıyor

Coq içinde yazılmış **doğru-inşa-edilmiş sonlu cisim aritmetiği** üreticisi. Solinas indirgeme, Montgomery çarpımı, taban dönüşümü gibi stratejilerle P-256, P-384, P-521, Curve25519 vb. için alan işlemleri üretiyor.

**Kanıtlanan:** Alan aritmetiğinin **fonksiyonel doğruluğu**.

**Kanıtlanmayan — README'den birebir (https://raw.githubusercontent.com/mit-plv/fiat-crypto/master/README.md, erişim 2026-09-08):**

> *"The Bedrock2 backend comes with proofs that the Bedrock2 AST matches the semantics of our internal AST, but **none of the other backends have any proofs about them**."*

> *"there is no verification that the particular integer size casts that we emit are sufficient to ensure that gcc, clang, or whatever compiler is used on the code correctly selects integer sizes for expressions correctly"*

> *"Note that even the C code printed by the Bedrock2 backend does not have proofs that the conversion to strings is correct."*

**Constant-time:** README'de **açık bir constant-time iddiası YOK**. Üretilen kod yapısı gereği düz-çizgi (straight-line) ve dallanmasız olduğu için pratikte CT'dir, ama bu **formel olarak kanıtlanmış değildir**.

**Kapsam sınırı:** Sadece **alan aritmetiği** — tam protokol, hatta tam eğri grup işlemleri değil (Bedrock2 hattı P-256 nokta işlemlerini de kapsıyor, BoringSSL'de kullanılıyor).

### 5.2 Backend'ler ve bakım durumu

| Backend | Bakım | CI | Üretilen kod test edildiği yer |
|---|---|---|---|
| C | Tam | ✓ | BoringSSL |
| Bedrock2/C | Tam (ispatlı) | ✓ | BoringSSL |
| Go | Harici katkıcı | ✓ | — |
| **Rust** | **Harici katkıcı** | ✓ | **Dalek** |
| Zig | Harici katkıcı | ✓ | Zig stdlib |
| Java | **Bakımsız** | ✓ | **Bilinen hatalı** |
| JSON | Deneysel | ✓ | — |

> **Argus için kritik nüans:** Rust backend **harici bir katkıcı tarafından** bakılıyor ve **hakkında hiçbir ispat yok**. Yani "fiat-crypto Rust kodu formel doğrulanmıştır" ifadesi teknik olarak yanlıştır — doğrulanan şey Coq içindeki *iç AST*'tir; Rust'a yazdırma adımı doğrulanmamıştır.

### 5.3 Dağıtımlar

| Yer | Kanıt | Tarih |
|---|---|---|
| **BoringSSL** (→ Chrome, Android, Google altyapısı) | `third_party/fiat/` — *"Most files in this directory are generated using Fiat Cryptography"*; P-256 alan aritmetiği ve nokta işlemleri (Bedrock2 çevirisi); `asm/` dizini CryptOpt ile derlenmiş. Bazı rutinler açıkça `bedrock_unverified_platform.c.inc` olarak işaretli | erişim 2026-09-08 — https://boringssl.googlesource.com/boringssl/+/refs/heads/master/third_party/fiat/README.md |
| **Linux çekirdeği** | `lib/crypto/curve25519-fiat32.c` (32-bit Curve25519) | erişim 2026-09-08 |
| **Zig stdlib** | fiat-crypto README | erişim 2026-09-08 |
| **Chrome %90 iddiası** | *"About 90 percent of secure Chrome communications currently run fiat-crypto code"* — CSO Online / MIT CSAIL basın haberleri | **[TARİHİ ESKİ (~2019), 2026 İÇİN DOĞRULANAMADI]** |
| **Firefox** | NSS'in `verified/` dizini **HACL\*** kodu içeriyor, fiat değil. Firefox'un fiat-crypto kullandığına dair kanıt bulamadım | **[DOĞRULANAMADI — muhtemelen YANLIŞ]** |

**Akademik referans:** Erbsen, Philipoom, Gross, Sloan, Chlipala, *"Simple High-Level Code For Cryptographic Arithmetic — With Proofs, Without Compromises"*, IEEE S&P 2019. https://jasongross.github.io/papers/2019-fiat-crypto-ieee-sp.pdf

### 5.4 Rust ekosisteminde fiat-crypto (2026-09-08 crates.io verisi)

**`fiat-crypto` crate:** v**0.3.0**, **133.799.092** toplam indirme, son 90 gün 31.578.526, son yayın **2025-06-04**, MSRV 1.83.0, lisans MIT OR Apache-2.0 OR BSD-1-Clause.

**Kimler bağımlı (23 crate):**
- **`curve25519-dalek` 5.0.0** (2026-07-06) — `fiat-crypto ^0.3.0` **zorunlu bağımlılık**. Backend seçimi: `serial` (otomatik), **`fiat` (manuel seçim)**, `simd` (AVX2, otomatik), `avx512` (IFMA, otomatik). Dokümantasyondan: *"`fiat` | Manual | Formally verified field arithmetic from fiat-crypto | 32 and 64"*. — https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ (erişim 2026-09-08)
  → **EVET, dalek fiat backend'ini içeriyor ve hâlâ destekliyor. Ama VARSAYILAN DEĞİL** — `--cfg curve25519_dalek_backend="fiat"` ile açman gerekiyor.
- **`p384` 0.14.0** — `fiat-crypto ^0.3` **zorunlu**. Kaynak kodda: *"Arithmetic implementations have been synthesized using fiat-crypto."* `p384_backend = "fiat"` ile aktif. (erişim 2026-09-08)
- **`orion` 0.18.0**, `ed448-goldilocks 0.9.0`, `prio 0.17.0` ve çeşitli dalek fork'ları

**🔴 ÖNEMLİ BULGU — `p256` artık fiat-crypto kullanmıyor:**
`p256` **0.14.0** (2026-07-03) bağımlılıkları: `elliptic-curve`, `ecdsa`, `hash2curve`, **`primefield`**, `primeorder`, `serdect`, `sha2`. **`fiat-crypto` yok.** `p256/src/arithmetic/field.rs` `primefield::monty_field_params!` / `monty_field_element!` makrolarını kullanıyor (generic `crypto-bigint` Montgomery aritmetiği).

`primefield` crate'i şöyle tanımlıyor kendini: *"Generic implementation of prime fields built on `crypto-bigint`, along with macros for writing field element newtypes **including ones with formally verified arithmetic using `fiat-crypto`**"* — yani makro **var** ama `p256` onu kullanmıyor (bağımlılık listesinde fiat-crypto yok).
— crates.io API + https://docs.rs/crate/p256/latest/source/src/arithmetic/field.rs + https://docs.rs/crate/primefield/latest/source/src/lib.rs (2026-09-08)

> **Argus için sonuç:** ES256 (P-256) yolunda RustCrypto `p256` **artık fiat-doğrulanmış aritmetik kullanmıyor**. P-384 kullanıyor. Bu bir gerileme (ya da en azından değişim) ve dikkat edilmeli.

**Ölü/eski crate'ler (kullanma):** `curve25519-dalek-fiat` 0.1.0 (2021-02-16), `x25519-dalek-fiat` 0.1.0 (2021), `ed25519-dalek-fiat` 0.1.0 (2021) — Novi Financial fork'ları, 5 yıldır güncellenmemiş. Ana dalek'in `fiat` backend'ini kullan.

---

## 6. AWS-LC / s2n-bignum / SAW-Cryptol

### 6.1 aws-lc-verification (SAW + Cryptol + NSym + Coq)

**Kapsam sınırı README'nin ilk cümlesinde:** *"Portions of AWS-LC have been formally verified"* — "portions of" ifadesi kasıtlı ve önemli.

**CI'da doğrulanan algoritmalar (https://github.com/awslabs/aws-lc-verification, erişim 2026-09-08; ayrıca Kobeissi 2026 Tablo 8):**

| Algoritma | Platform | Araç | Caveat'lar |
|---|---|---|---|
| SHA-2 (384/512) | SandyBridge+ | SAW | NoEngine, MemCorrect |
| SHA-2 (384/512) | Neoverse | SAW + NSym | NoEngine, NoInline, MemCorrect, ArmSpecGap, ToolGap, LaxPointer |
| HMAC-SHA384 | SandyBridge+ | SAW | NoEngine, MemCorrect, InitZero, NoInline, CRYPTO_once_Correct |
| AES-KW(P) 256 | SandyBridge+ | SAW | InputLength, MemCorrect, NoInline |
| AES-GCM 256 | SandyBridge–Skylake | SAW | MemCorrect, NoInline, GcmSpecGap, GcmMultipleOf16, **GcmADNotVerified**, GcmIV9Tag16, GcmWellFoundedInduction |

**Sınırlı/bounded doğrulama — EVET:**
- *"The implementation is verified correct only on a limited number of input lengths"* (AES-KW)
- *"EVP_{Encrypt,Decrypt}Update are only verified for cases where whole blocks are encrypted/decrypted"*
- *"The AES-GCM functions are only verified for 12-byte IVs and 16-byte tags"*
- `GcmADNotVerified`: **additional data doğrulanmamış**

**ECDSA / ECDH / HKDF:** Proof script'leri depoda var ama **CI'da devre dışı ve README'den kaldırılmış** (Kobeissi 2026: *"a clear acknowledgment that their verification status has regressed"*). Doğrulama çabası s2n-bignum ve CBMC yaklaşımlarına kaydı.

**Doğrulanmadığı açıkça belirtilen bileşenler:** `OPENSSL_malloc`, `OPENSSL_free`, `CRYPTO_refcount_inc`, `ERR_put_error` — *"not verified, and assumed to behave correctly"*.

**26 adlandırılmış caveat** ve yapılandırılmış soundness dokümanları var. **CI her push ve PR'da 5 paralel iş çalıştırıyor** — libcrux'un aksine ispatlar gerçekten kontrol ediliyor.

### 6.2 s2n-bignum (HOL Light) — Argus için en alakalı kısım

AWS-LC README'sinden: *"assembly from s2n-bignum to implement algorithms or sub-routines for x86_64 and aarch64. These functions are **formally verified in HOL Light**."*

**Kapsanan primitifler:** **RSA, P-256, P-384, P-521, X25519, Ed25519** — hem x86-64 hem aarch64.
— https://github.com/aws/aws-lc (erişim 2026-09-08)

**SOUNDNESS.md'den (https://github.com/awslabs/s2n-bignum/blob/main/SOUNDNESS.md, erişim 2026-09-08):**

Kanıtlananlar:
1. **Fonksiyonel doğruluk** — *"If the machine state satisfies a precondition..., then execution on the formal ISA model is guaranteed eventually to reach a state satisfying a postcondition."*
2. **🔴 Constant-time yürütme ve bellek güvenliği** — **2025 sonundan itibaren** AWS-LC'nin kullandığı tüm fonksiyonlar için *"formal HOL Light proofs of the constant-time property alongside functional correctness"*

Bytes doğrudan **gerçek object dosyalarına** karşı doğrulanıyor — derleyici/assembler varsayımı yok. Bu, HACL*'ın C→derleyici boşluğunu **kapatan** bir yaklaşım.

Kanıtlanmayanlar:
- Spesifikasyon hataları (formül yanlış olabilir)
- **Donanımın gerçekten sabit zamanlı yürüttüğü** — *"does not and cannot guarantee that the hardware executes those instructions in constant time"*
- Eşzamanlılık (model sıralı, tek çekirdek, kullanıcı modu)
- Spectre-sınıfı spekülatif yürütme
- Fiziksel hata enjeksiyonu

Dört boşluk kategorisi: **A** (Spesifikasyon: A1 fonksiyonel spec doğruluğu, A2 önkoşullar, A3 constant-time [artık kanıtlı], A4 bellek güvenliği [artık kanıtlı]), **B** (Model sadakati: ISA model hataları, ELF loader, atlanan özellikler — cache/interrupt/sanal bellek), **C** (İspat altyapısı: HOL Light kernel/OCaml runtime hataları — Candle ve HOLTrace ile azaltılıyor), **D** (Entegrasyon: 64-bit/little-endian/hizalama varsayımları, C header–assembly arayüz uyumsuzlukları, çağıran tarafın önkoşul ihlalleri).

### 6.3 mlkem-native

AWS'nin FIPS 203 implementasyonu — C bellek/tip güvenliği için **CBMC**, assembly doğruluğu için **HOL Light**. Yapılandırılmış SOUNDNESS.md yayınlıyor. https://github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md

Kobeissi'nin karşılaştırması (Tablo 9):

| Boyut | AWS-LC Verification | libcrux |
|---|---|---|
| Kapsam iddiası | "portions of AWS libcrypto" | "the formally verified crypto library" |
| Caveat dokümantasyonu | 26 adlandırılmış caveat + yapılandırılmış soundness dokümanları | Manuel `verification_status.md`, caveat yok |
| CI'da ispatlar | Her push/PR'da (5 paralel iş) | PR'da lax; tam doğrulama sadece zamanlanmış; **slow modüller hiç doğrulanmıyor** |
| Admit edilen ispatlar | `do_prove` varsayılan true; fonksiyon başına açık `unsafe_assume_spec` | `ADMIT_MODULES` + otomatik-admit `SLOW_MODULES`; lax-mod kaçış kapısı |

---

## 7. RUSTCRYPTO EKOSİSTEMİ / ring / aws-lc-rs / dalek

### 7.1 RustCrypto'nun formel doğrulama duruşu

**Kısa cevap: yok.** RustCrypto organizasyonunun README'sinde, `hashes` veya `elliptic-curves` README'lerinde formel doğrulamaya dair **hiçbir iddia veya politika bulamadım** (erişim 2026-09-08). Yaklaşımları: saf Rust, `#![forbid(unsafe_code)]`, `subtle` ile "best-effort" constant-time, `zeroize` ile bellek temizleme, ve seçici üçüncü-taraf denetimleri.

### 7.2 Denetimler (audits)

**Bulabildiğim tek somut denetim:** NCC Group, **Şubat 2020**, MobileCoin sponsorluğunda:
- Kapsam: `aes-gcm` ve `chacha20poly1305` crate'leri
- Efor: 2 danışman × 5 kişi-gün (toplam 5 kişi-gün)
- Sonuç: **"no significant findings"** — zafiyet bulunmadı, performans iyileştirme önerileri yapıldı
- https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/ (2020-02-26); GitHub issue: https://github.com/RustCrypto/AEADs/issues/87

Her iki crate'in README'si bu denetime atıf yapıyor: *"This crate has received one security audit by NCC Group, with no significant findings."*

**Constant-time iddiası (aes-gcm ve chacha20poly1305 README'lerinden, erişim 2026-09-08):**
> Implementasyonlar ya donanım intrinsic'lerine (x86/x86_64'te AES-NI+CLMUL, AVX2) dayanıyor ya da **yalnızca sabit-zamanlı çarpma yapan işlemcilerde** sabit zamanlı olan taşınabilir bir implementasyon kullanıyor.
>
> **Caveat:** *"It is not suitable for use on processors with a variable-time multiplication operation"* — bazı 32-bit PowerPC CPU'lar ve ARM olmayan bazı mikrodenetleyiciler (çarpım-sıfırla/birle kısa devre yapabiliyor).

**Derleyici/LLVM kaynaklı zamanlama değişkenliği bu bölümlerde ele alınMIYOR.**

**Diğer crate'ler için denetim bulamadım** (`argon2`, `sha2`, `hmac`, `p256`, `rsa`, `ed25519-dalek`). **[YOKLUK KANITLANAMADI — sadece bulamadım]**

### 7.3 `subtle` — constant-time'ın temel taşı ve sınırları

crates.io: **v2.6.1**, **682.501.354** indirme, son 90 gün 155.010.763, **son güncelleme 2024-06-24 (2+ yıl önce)**, BSD-3-Clause.

Dokümantasyondan (https://docs.rs/subtle/latest/subtle/, erişim 2026-09-08) — birebir:
> *"This crate represents a 'best-effort' attempt, since side-channels are ultimately a property of a deployed cryptographic system including the hardware it runs on, not just of software."*
>
> **"USE AT YOUR OWN RISK"**

Garanti edemedikleri: Derleyiciler bit-düzeyi işlemleri koşullu atama olarak tanıyıp branch'e geri optimize edebilir. Crate bunu **volatile read tabanlı "optimization barrier"** ile engellemeye çalışıyor — ama bu **kesinlik değil, en iyi çaba**.

> **Argus için:** `subtle::ConstantTimeEq` kullan (alternatifi yok) ama bunun formel bir garanti olmadığını, sadece "LLVM'i kandırma denemesi" olduğunu bil. Kritik karşılaştırmalar için ek olarak ctgrind/Valgrind testi ekle (Bölüm 8).

### 7.4 `zeroize`

v**1.9.0**, 672.831.052 indirme, son 90 gün 168.883.175, güncelleme **2026-06-12**, MSRV 1.85, Apache-2.0 OR MIT. Aktif bakımda. Formel doğrulama iddiası yok; `core::ptr::write_volatile` + compiler fence ile çalışıyor.

### 7.5 `ring` — 2026 durumu (nüanslı!)

**crates.io:** son sürüm **0.17.14, 2025-03-11**. Sonrasında **18 aydır yeni sürüm yok** (2026-09-08 itibariyle). Toplam 719.974.964 indirme, son 90 gün 151.965.941. MSRV 1.66.0. Lisans "Apache-2.0 AND ISC". Açıklama hâlâ: *"An experiment."*

**RUSTSEC-2025-0007** ("*ring* is unmaintained"): Bildirim 2025-02-20, yayın 2025-02-21, son değişiklik 2025-03-06. **Durum: WITHDRAWN (geri çekildi).** Gerekçe zinciri:
1. Brian Smith süresiz ara verdiğini duyurdu (https://github.com/briansmith/ring/discussions/2414)
2. rustls ekibine erişim verildi, güvenlik bakımı taahhüdü
3. Son güncelleme: *"things are more-or-less back to how they were before, and in particular the situation isn't 'security maintenance only'"*
— https://rustsec.org/advisories/RUSTSEC-2025-0007.html (erişim 2026-09-08)

**Depo aktivitesi 2026'da CANLI:** son commit'ler 2026-07-22, 2026-07-15 (×4), 2026-06-30 (×5, aralarında "ECDSA signing: Cite FIPS 186-5 for steps") — https://github.com/briansmith/ring/commits/main (erişim 2026-09-08)

**0.16.20 ve öncesi:** tamamen bakımsız (https://github.com/briansmith/ring/discussions/2450)

**Doğrulanmış kod kullanıyor mu?** ring, BoringSSL/OpenSSL'den türetilmiş C ve assembly kodu kullanıyor; **fiat-crypto'yu doğrudan bağımlılık olarak kullanmıyor**. Ancak hax makalesi (eprint 2025/142) **Crux-MIR'ın ring'in SHA-1 ve SHA-2 implementasyonlarını hacspec spesifikasyonlarına karşı doğruladığını** belirtiyor. Bu, ring'in kendi doğrulama çabası değil, üçüncü taraf araştırma.

> **Argus için değerlendirme:** ring, "yarı-terk edilmiş ama canlı" bir durumda. 18 aydır sürüm çıkmaması bir risk sinyali. Yeni bir projede birincil seçenek olmamalı.

### 7.6 `aws-lc-rs` — güçlü alternatif

**crates.io:** v**1.18.1**, **2026-09-01** (bir hafta önce!), 214.910.906 indirme, son 90 gün **78.871.640**, MSRV 1.71.0, lisans "ISC AND (Apache-2.0 OR ISC)".

- **ring (v0.16) API-uyumlu**, "drop-in replacement" hedefli — https://github.com/aws/aws-lc-rs
- **FIPS:** `aws-lc-fips-sys` akredite laboratuvarda FIPS validasyon testini **tamamladı, NIST sertifikasyonuna sunuldu** (durum NIST CMVP listesinde takip ediliyor). `fips` feature ile AWS-LC-FIPS 4.x'e bağlanıyor. — https://docs.rs/aws-lc-rs/latest/aws_lc_rs/ (erişim 2026-09-08)
- **Formel doğrulama:** crate dokümantasyonunda **doğrudan bahsedilmiyor**, ama altında yatan AWS-LC'nin doğrulanmış bileşenlerini (Bölüm 6) miras alıyor.

**JWT için desteklenen imza algoritmaları** (https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html, erişim 2026-09-08):
- **RSA PKCS#1 v1.5 (RS256/384/512):** imzalama VE doğrulama ✅ — `RSA_PKCS1_SHA256/384/512` (imza), `RSA_PKCS1_2048_8192_SHA256/384/512` (doğrulama)
- **RSA-PSS (PS256/384/512):** imzalama VE doğrulama ✅ — `RSA_PSS_SHA256/384/512`, `RSA_PSS_2048_8192_SHA256/384/512`
- **ECDSA P-256/P-384/P-521:** imzalama VE doğrulama ✅ (ASN.1 DER ve fixed-length formatları)
- **Ed25519:** imzalama VE doğrulama ✅
- **ML-DSA-44/65/87:** imzalama VE doğrulama ✅
- Anahtar boyutu kısıtları: RSA doğrulamada modül 1024–8192 / 2048–8192 / 3072–8192 aralıkları

**Yani `aws-lc-rs`, Argus'un JWT ihtiyaçlarının %100'ünü tek başına karşılıyor** — RS256 dahil.

### 7.7 dalek ailesi

- **`curve25519-dalek` 5.0.0** (2026-07-06), 249.213.034 indirme, son 90 gün 57.755.858, MSRV **1.85.0**, BSD-3-Clause. Backend'ler: `serial`, **`fiat` (formel doğrulanmış, manuel seçim)**, `simd` (AVX2), `avx512` (IFMA).
- **`ed25519-dalek` 3.0.0** (2026-07-06), 205.163.505 indirme, MSRV 1.85, BSD-3-Clause. `curve25519-dalek ^5.0.0`, `sha2 ^0.11`, `subtle ^2.3` bağımlılıkları.

### 7.8 Argon2 — 🔴 DOĞRULANMIŞ İMPLEMENTASYON YOK

crates.io'da `argon2` (RustCrypto): v**0.6.0** (2026-08-27), 50.939.882 indirme, son 90 gün 18.352.369, MSRV 1.85, MIT OR Apache-2.0. Özellikler: `kdf`, `password-hash`, `rayon`, `zeroize`.

- README'de veya crate dokümantasyonunda **denetim bilgisi, formel doğrulama iddiası veya yan-kanal tartışması yok** (https://docs.rs/argon2/latest/argon2/, erişim 2026-09-08). Sadece "Argon2i: optimized to resist side-channel attacks" gibi algoritma-seviyesi açıklamalar var.
- crates.io'da "argon2 verified" / "password hash formally verified" aramaları **hiçbir doğrulanmış implementasyon döndürmedi** (2026-09-08).
- **HACL\*'ta Argon2 YOK.** libcrux'ta Argon2 YOK. AWS-LC-verification'da Argon2 YOK.
- Alternatifler: `rust-argon2` 3.0.0 (2025-07-17, 21M indirme), `argon2-kdf` 1.7.1 (C referans implementasyonuna sarmalayıcı).

**Constant-time endişesi:** Argon2**id**'in ikinci yarısı **tasarım gereği** veri-bağımlı bellek erişimi yapar (GPU/ASIC direnci için). Bu, parola hash'leme tehdit modelinde kabul edilmiş bir tavizdir; ancak aynı makinede kod çalıştırabilen bir saldırgan için cache-timing yüzeyi oluşturur. Argon2**i** veri-bağımsızdır ama daha zayıf TMTO direnci sunar. OWASP hâlâ Argon2id öneriyor.

> **Argus için sonuç: Parola hash'leme, formel doğrulama hikayenizin kapsamı dışında kalacak. Bunu açıkça belgeleyin.** Azaltıcı önlemler: sabit parametreler (m, t, p), `zeroize`, parola işlemlerini ayrı bir process/thread pool'da izole etme, ve `dudect-bencher`/ctgrind ile en azından **karşılaştırma** yollarının CT olduğunu test etme.

---

## 8. CONSTANT-TIME DOĞRULAMA — RUST'TA 2026'DA NE MÜMKÜN?

### 8.1 Araç envanteri

**Referans tarama:** https://neuromancer.sk/article/26 (**30 Ocak 2021**) — "The state of tooling for verifying constant-timeness of cryptographic implementations"

| Araç | Yıl | Tip | Yöntem | Rust'ta kullanılabilir mi? |
|---|---|---|---|---|
| **ct-verif** | 2015 | Statik | LLVM IR + SMT; sound & complete | Teorik olarak (LLVM IR üzerinden) ama Rust entegrasyonu yok; **kullanımı zor** |
| **FlowTracker** | 2016 | Statik | Program bağımlılık grafiği; sound ama incomplete | Hayır |
| **SideTrail** | 2018 | Statik | Zaman-dengeli implementasyon doğrulama; **Amazon s2n'de kullanıldı** | Hayır (C) |
| **FaCT** | 2019 | DSL | CT kod yazmak için ayrı dil | Kod tabanını yeniden yazmayı gerektirir |
| **Binsec/Rel** | 2020 | Statik | **İkili seviye** ilişkisel sembolik yürütme; derleyici kaynaklı sızıntıları yakalar; sound & complete | **EVET** — dil-bağımsız, derlenmiş binary üzerinde çalışır |
| **ctgrind / TIMECOP** | 2010/2020 | Dinamik | Valgrind memcheck; gizliyi "undefined" işaretle | **EVET — en pratik yol** |
| **dudect** | 2016 | Dinamik | Welch t-testi ile istatistiksel zamanlama analizi | **EVET** — `dudect-bencher` crate'i |
| **MicroWalk** | 2018 | Dinamik | DBI + karşılıklı bilgi analizi | Kısmen |
| **DATA** | 2018/2020 | Dinamik | Bellek erişim izleri + GUI | Kısmen |
| **ct-fuzz** | 2019 | Dinamik | Self-composition ile fuzzing | Hayır |

Makalenin çarpıcı sonucu (2021, ama 2026'da hâlâ büyük ölçüde geçerli):
> *"there is an abundance of tools... yet none seem to be actually used in an automated way outside of the papers that introduced them."* Sadece **dört** açık kaynak kripto kütüphanesi bunları CI'da kullanıyordu.

### 8.2 2026'da Rust'ta PRATİK olarak çalışan yol

**1. Valgrind/ctgrind yolu (EN İYİ SEÇENEK) ⭐**
- `crabgrind` v**0.3.1** (2026-07-20), 899.848 indirme — Rust'tan Valgrind Client Request arayüzü
- libcrux'un `crates/utils/ctgrind-test/` deseni: gizliyi `mark_memory` ile Undefined işaretle → işlemi çalıştır → Valgrind, undefined bit'lerin adres üretimi / kontrol akışı kararı / syscall parametresinde kullanılmasını raporlar
- `libcrux-secrets` crate'i (`--cfg valgrind_ct_test` + `check-secret-independence`) bunu tip sistemiyle otomatikleştiriyor
- **Sınırı (kendi ifadeleriyle):** *"this does not check for other side channels, such as variable time instructions (e.g., div) or cache side channels"*
- macOS/Apple Silicon'da Valgrind çalışmıyor → **Docker gerekli**

**2. dudect istatistiksel testi**
- `dudect-bencher` v**0.7.0** (2026-03-23), 191.096 indirme
- CI'da çalıştırılabilir; kesinlik yok ama regresyon dedektörü olarak iyi

**3. Tip-seviyesi gizli-bağımsızlık disiplini**
- `libcrux-secrets` v0.0.6 (2.744.096 indirme): `u8 → U8`, `i16 → I16` tip takası; `classify()`/`declassify()` ile açık geçişler
- Yakaladıkları: gizli karşılaştırma üzerinde dallanma, gizli indeksle dizi erişimi, `div`/`mod` gibi CT-olmayan işlemler
- **Sınırı:** *"No strict compile-time guarantees"* — typechecker uyarı veriyor, garanti değil. Ve crate'in kendisi `pre-verification`.
- Kavramsal olarak HACL*'ın Low* secret independence tip sisteminin Rust'a taşınması

**4. Charon tabanlı taint-checker (araştırma → pratik)**
- Charon makalesi (arXiv:2410.18042, CAV 2025): kripto kodu için taint-checker, KyberSlash benzeri açığı **<10 saniyede** buluyor, *"amenable to being used in a CI pipeline"*
- **[BAĞIMSIZ BİR CRATE OLARAK YAYINLANIP YAYINLANMADIĞINI DOĞRULAYAMADIM]**

**5. hax + F* ile kaynak-seviyesi secret independence**
- En güçlü garanti ama en yüksek maliyet: kodu hax'in Rust alt kümesinde yazmak (`&mut T` dönüş tipi yasağı vb.) + F* ispatları yazmak

**6. Binsec/Rel (ikili seviye)**
- ACM TOPS 2022 (https://dl.acm.org/doi/10.1145/3563037), arXiv:2209.01129
- **Derleyici kaynaklı sızıntıları yakalayan tek pratik yol** — `subtle`'ın "LLVM optimize edip branch'e çevirebilir" korkusunu doğrudan test eder
- Rust'a özgü değil, derlenmiş binary'de çalışır; küçük CT-kritik çekirdekler için harness yazmak gerekir
- 2026'da bazı Rust build pipeline'ları "checkct" modunu kullanıyor — **[SPESİFİK PROJE DOĞRULANAMADI]**

**7. Genel Rust doğrulama araçları (kripto-spesifik değil)**
- `kani-verifier` v**0.67.0** (2026-01-16), 566.714 indirme — AWS'nin bit-hassas model checker'ı (CBMC tabanlı). CT için değil ama panik-yokluğu/overflow için kullanışlı
- `creusot-contracts` v0.8.0 (2025-12-09), 14.220 indirme — dedüktif doğrulama (Why3)

### 8.3 Ek: 2026'nın yeni araçları

- **DALC-CT** — "Dynamic Analysis of Low-Level Code Traces for Constant-Time Verification", arXiv:2604.16832 (2026). **[İÇERİK OKUNMADI]**
- **Crucible** (Symbolic Software, **23 Mart 2026**) — ML-KEM/ML-DSA **uygunluk test çerçevesi**. Rust'ta yazılmış; JSON satır protokolü; 15 implementasyon için harness (Rust, Go, C, C++20, Java); 129 test (ML-KEM için 78, ML-DSA için 51). Gerçek denetim bulgularından türetilmiş hata sınıflarını kodluyor: *"off-by-one rounding, bounds check compiled to dead code, inverse NTT omitted from the decryption path"*. AWS-LC, Go stdlib, CIRCL ve libcrux dahil büyük implementasyonlarda **2 uygunluk boşluğu, 0 güvenlik açığı** buldu; **libcrux tüm ilgili testleri geçti**. — https://symbolic.software/blog/2026-03-23-crucible/

---

## 9. ARGUS İÇİN PRATİK DEĞERLENDİRME VE ÖNERİ

### 9.1 İhtiyaç → Doğrulanmış seçenek eşlemesi

| Argus ihtiyacı | Doğrulanmış seçenek | Durum | Notlar |
|---|---|---|---|
| **JWT HS256/384/512** | `libcrux-hmac` 0.0.8 | ✅ **verified-hacl** | HACL* HMAC. En güvenli seçim. |
| **JWT EdDSA (Ed25519)** | `libcrux-ed25519` 0.0.9 | ✅ **verified-hacl** | V6 (double clamping) düzeltildi. NSS'te de aynı HACL* kodu üretimde. |
| **JWT ES256 (P-256)** | `libcrux-ecdsa` 0.0.8 | ✅ **verified-hacl** ama ⚠️ | **90 günde 721 indirme** — pratikte test edilmemiş. low-S normalizasyonu yok (JWS için RFC 7515 gerektirmiyor, sorun değil; ama ES256K/blockchain entegrasyonu düşünüyorsan sorun). |
| **JWT PS256/384/512 (RSA-PSS)** | `libcrux-rsa` 0.0.8 | ✅ **verified-hacl** ama ⚠️ | HACL* `Hacl.RSAPSS`. SHA-256/384/512. 2048–8192 bit. **90 günde 582 indirme.** **Anahtar üretimi YOK.** |
| **🔴 JWT RS256/384/512 (PKCS#1 v1.5)** | **YOK** | ❌ | libcrux/HACL*'ta PKCS#1 v1.5 imza **yok**. `aws-lc-rs` (s2n-bignum aritmetiği HOL Light ile doğrulanmış) veya RustCrypto `rsa` (0.10.0-rc.18, hâlâ RC!) gerekiyor. **OIDC istemcilerinin ezici çoğunluğu RS256 bekler.** |
| **SHA-2 (JWT digest, JWKS thumbprint)** | `libcrux-sha2` 0.0.8 | ✅ **verified-hacl** | |
| **HKDF (anahtar türetme)** | `libcrux-hkdf` 0.0.8 | ✅ **verified-hacl** | |
| **JWE: ChaCha20-Poly1305** | `libcrux-chacha20poly1305` 0.0.9 | ✅ **verified-hacl** | **XChaCha20Poly1305 sarmalayıcısı doğrulanmamış** — 24-byte nonce istiyorsan bu doğrulama dışı. |
| **🔴 JWE: AES-GCM (A128GCM/A256GCM)** | `libcrux-aes` — **pre-verification** | ❌ | Ayrıca tag karşılaştırması **2026-07-15'e kadar** sabit zamanlı değildi (PR #1528). EverCrypt'te doğrulanmış AES-GCM var ama **sadece x64 Vale assembly**, Rust'tan erişilebilir değil. Alternatif: `aws-lc-rs` (SAW ile CI'da doğrulanmış AES-GCM-256, ama sınırlı: sadece 12-byte IV, 16-byte tag, tam blok, **AAD doğrulanmamış**). |
| **X25519 (hibrit iş)** | `libcrux-curve25519` 0.0.8 | ✅ **verified-hacl** | |
| **ML-KEM (PQ hibrit)** | `libcrux-ml-kem` 0.0.10 | ⚠️ **kısmî verified (hax)** | Portable backend tam; AVX2 kısmî; **NEON hiç doğrulanmamış** (ARM64 sunucular = Graviton, Apple Silicon dev makineleri). `ind_cpa` ve `sampling` admit edilmiş. Signal + NSS + OpenSSH üretimde. |
| **🔴 Argon2 (parola hash)** | **YOK** | ❌ | Hiçbir dilde doğrulanmış Argon2 bulamadım. RustCrypto `argon2` 0.6.0 kullan, denetimsiz. |
| **🔴 CSPRNG** | `libcrux-hmac-drbg` — **pre-verification** | ❌ | `getrandom` 0.4.3 (OS entropi: Linux `getrandom(2)`, macOS `getentropy`, Windows `ProcessPrng`) — doğrulanmamış ama işletim sistemine devrediyor, ki bu doğru mimari. |
| **Sabit-zamanlı karşılaştırma** | `subtle` 2.6.1 | ⚠️ | "best effort", "USE AT YOUR OWN RISK", 2 yıldır güncellenmedi. Alternatif: `libcrux-secrets` (pre-verification). |
| **🔴 SHA-3 / SHAKE** | `libcrux-sha3` — **pre-verification** | ❌ | HACL*'ta doğrulanmış SHA-3 C kodu **var** (NSS kullanıyor) ama libcrux'un Rust SHA-3'ü ayrı bir hax-hedefli implementasyon ve doğrulanmamış. Ayrıca 0.0.5'te AVX2 SHAKE-256'da OOB indeksleme düzeltildi. |
| **RSA anahtar üretimi (JWKS rotasyonu)** | **YOK (libcrux'ta)** | ❌ | `aws-lc-rs` veya `rsa` crate'i gerekiyor. |

### 9.2 Üç somut mimari seçenek

**SEÇENEK A — "Maksimum doğrulama, kabul edilen boşluklarla"**
```
HS256      → libcrux-hmac         ✅ verified
EdDSA      → libcrux-ed25519      ✅ verified
ES256      → libcrux-ecdsa        ✅ verified (az kullanılmış)
PS256      → libcrux-rsa          ✅ verified (imza/doğrulama; keygen ayrı)
SHA-2      → libcrux-sha2         ✅ verified
HKDF       → libcrux-hkdf         ✅ verified
JWE        → libcrux-chacha20poly1305 (AES-GCM YERİNE)  ✅ verified
X25519     → libcrux-curve25519   ✅ verified
ML-KEM     → libcrux-ml-kem       ⚠️ kısmî
Argon2     → RustCrypto argon2    ❌ doğrulanmamış
RNG        → getrandom            ❌ doğrulanmamış (OS'a devir)
CT-compare → subtle               ⚠️ best-effort
RSA keygen → aws-lc-rs veya rsa   ❌
RS256      → DESTEKLENMEZ (sadece PS256/ES256/EdDSA/HS256)
```
- **Artısı:** Gerçekten en yüksek doğrulama oranı. "En güvenli IdP" iddiası savunulabilir.
- **Eksisi:** **RS256 yok** → çoğu mevcut OIDC istemcisi bağlanamaz. libcrux pre-release (`<0.1`), API kırılmaları olabilir, üretim için maintainer'la konuşman isteniyor. `libcrux-ecdsa`/`libcrux-rsa` neredeyse hiç kullanılmıyor.

**SEÇENEK B — "aws-lc-rs tabanlı, pragmatik" ⭐ Tavsiyem**
```
Tüm JWT imza/doğrulama (RS256, PS256, ES256/384, EdDSA, HS256) → aws-lc-rs 1.18.1
JWE AES-GCM        → aws-lc-rs (SAW ile CI-doğrulanmış, caveat'lı)
JWE ChaCha20-Poly1305 → aws-lc-rs veya libcrux
Argon2             → RustCrypto argon2
RNG                → aws-lc-rs SystemRandom / getrandom
CT-compare         → aws-lc-rs constant_time veya subtle
ML-KEM             → aws-lc-rs veya libcrux-ml-kem
```
- **Artısı:** Tek bağımlılık, FIPS 140-3 yolu (sertifikasyon NIST'e sunuldu), tam algoritma kapsamı, aktif bakım (2026-09-01 sürüm), s2n-bignum aritmetiği **HOL Light ile hem fonksiyonel doğruluk hem constant-time için** kanıtlanmış (RSA, P-256/384/521, X25519, Ed25519), ispatlar **her push/PR'da CI'da** çalışıyor, 26 adlandırılmış caveat ile dürüst dokümantasyon, `jsonwebtoken` 11 zaten `CryptoProvider` ile destekliyor.
- **Eksisi:** C/assembly bağımlılığı (saf Rust değil), doğrulama "portions of" seviyesinde, üst-seviye protokol mantığı doğrulanmamış.

**SEÇENEK C — "Katmanlı hibrit" (en güçlü ama en karmaşık)**
```
Varsayılan sağlayıcı: aws-lc-rs (tam kapsam, FIPS, RS256 dahil)
İsteğe bağlı "high-assurance" profili: libcrux
  → HS256, EdDSA, ES256, PS256, SHA-2, HKDF, ChaCha20-Poly1305
Argon2: RustCrypto (her iki profilde)
Runtime'da hangi implementasyonun kullanıldığı loglanır/metriklenir
Her iki yolda ortak KAT (Known Answer Test) + differential test paketi
```
- **Artısı:** RS256 desteklerken "kritik yollar formel doğrulanmış" iddiasını da tutabiliyorsun. Cross-implementation differential testing (iki bağımsız kod tabanı) tek başına büyük bir güvenlik kazancı — nitekim Kobeissi'nin bulduğu hataların çoğu böyle yakalanırdı.
- **Eksisi:** İki kat bakım yükü, iki kat saldırı yüzeyi, sürüm yönetimi karmaşıklığı.

### 9.3 Argus'un "formel doğrulanmış" iddiasını nasıl kurmalı (Kobeissi'den ders)

Kobeissi'nin R1–R5 tavsiyeleri, senin **kendi** projene doğrudan uygulanabilir:

1. **R1 — Makine-okunur doğrulama manifestosu.** Her sürümde: hangi kod yolu, hangi özelliğe karşı, hangi hedef mimaride doğrulanmış. **Elle yazılmasın, build sisteminden üretilsin.** AWS'nin `s2n-bignum/SOUNDNESS.md` ve `mlkem-native/SOUNDNESS.md` dosyaları model alınabilir.
2. **R2 — İspatlar her commit'te CI'da.** libcrux'un `ADMIT_MODULES` deseni bir **doğrulama kusuru** sayılmalı. (Argus doğrudan ispat yazmıyorsa bile: bağımlılıklarının doğrulama durumunu CI'da kontrol et — örneğin libcrux sürüm yükseltmelerinde `verification_status.md`'yi diff'le.)
3. **R3 — Tactic'lerde lax-mod kaçış kapısı yok.**
4. **R4 — Net kapsam iletişimi.** *"'formally verified' without qualification should be reserved for systems where the verification boundary has been minimized to the hardware level, as in CompCert or seL4."* → **Argus asla niteliksiz "formally verified" dememeli.** Bunun yerine: "JWT imzalama/doğrulama primitifleri HACL*'dan türetilmiş, F* ile bellek güvenliği, fonksiyonel doğruluk ve gizli bağımsızlık için doğrulanmış kod kullanır; parola hash'leme, protokol mantığı ve derleme süreci doğrulama sınırının dışındadır."
5. **R5 — Savunma derinliği.** *"traditional practices—code review, specification compliance auditing, cross-platform testing, and fuzzing—catch categories of bugs that formal verification, as currently practiced, does not."*

**Ve Kobeissi'nin bulgularından çıkan somut Argus test listesi:**
- **Cross-platform determinism testi** (V1): Aynı deterministik girdiyle x86-64, ARM64, ve `RUSTFLAGS="-C target-feature=-avx2"` altında **aynı** çıktı alınmalı. CI'da zorunlu.
- **Cross-backend state uyumluluğu** (V2): Eğer incremental/streaming API kullanıyorsan, bir backend'de başlatıp diğerinde bitirmeyi test et.
- **Düşük mertebeli nokta / all-zero paylaşılan sır kontrolü** (V3): X25519 çıktısının sıfır olmadığını **kendi kodunda** kontrol et — kütüphaneye güvenme.
- **Nonce/sequence taşma testi** (V4): Sayaçların gerçekten taştığı senaryoyu test et; release build'de.
- **Panik denemesi** (V7): Bozuk ciphertext/imza ile fuzzing; `.unwrap()` avı; `#![deny(clippy::unwrap_used)]` kripto modüllerinde.
- **FIPS/RFC uygunluk testleri** (V8, V9): Wycheproof + NIST CAVP/ACVP vektörleri + **Crucible** (ML-KEM/ML-DSA kullanacaksan).
- **ctgrind/Valgrind CT testi** (Bölüm 8): En azından JWT imza, HMAC doğrulama ve parola karşılaştırma yollarında.

### 9.4 Kalan risklerin dürüst listesi

| Risk | Şiddet | Azaltma |
|---|---|---|
| **RS256 için doğrulanmış implementasyon yok** | Yüksek (uyumluluk) | `aws-lc-rs` kullan; ya da yeni istemcileri PS256/ES256/EdDSA'ya zorla, RS256'yı legacy modda tut |
| **Argon2 doğrulanmamış** | Orta | Kaçınılmaz. Denetlenmiş parametreler, `zeroize`, izolasyon, CT test |
| **AES-GCM (JWE) doğrulanmamış (libcrux) / sınırlı doğrulanmış (aws-lc-rs)** | Orta | JWE için ChaCha20-Poly1305'i **varsayılan** yap; AES-GCM'i sadece uyumluluk için |
| **libcrux pre-release (`<0.1`), API kırılabilir** | Orta | Tam sürüm pin'i (`=0.0.9`), `Cargo.lock` commit, kendi KAT paketi, sürüm yükseltmelerinde diff |
| **CE Labs'ın zafiyet ifşa süreci sorunlu (Şub 2026)** | Orta | Kendi test/fuzz katmanını kur; RUSTSEC + GitHub advisory'leri izle; `cargo audit`/`cargo deny` CI'da |
| **NEON/ARM64 yolunda ML-KEM ispatları hiç kontrol edilmemiş** | Orta (PQ kullanırsan) | ARM64'te `portable` backend'i zorla, ya da mlkem-native/aws-lc-rs kullan |
| **`ring` 18 aydır sürümsüz** | Düşük–Orta | Yeni kodda `ring` kullanma; `rustls` için `aws-lc-rs` provider'ını seç |
| **`subtle` 2 yıldır güncellenmedi + garanti vermiyor** | Düşük | Alternatifi yok; ctgrind ile test et |
| **Derleyici (LLVM) tüm HACL*/hax garantilerinin dışında** | Yapısal | Kabul et ve belgele. s2n-bignum (assembly-seviyesi ispat) bu boşluğu kapatan tek yaklaşım |

---

## 10. KAYNAK LİSTESİ (erişim tarihleri ile)

**Makaleler**
- Kobeissi, N. *Verification Theatre: False Assurance in Formally Verified Cryptographic Libraries.* IACR ePrint 2026/192, alındı 2026-02-05, son revizyon 2026-06-25 — https://eprint.iacr.org/2026/192
- Bhargavan, Buyse, Franceschino, Letager Hansen, Kiefer, Schneider-Bensch, Spitters. *hax: Verifying Security-Critical Rust Software using Multiple Provers.* IACR ePrint 2025/142, VSTTE 2024 — https://eprint.iacr.org/2025/142
- Ho, Boisseau, Franceschino, Prak, Fromherz, Protzenko. *Charon: An Analysis Framework for Rust.* arXiv:2410.18042 (v2, Oca 2025), CAV 2025 — https://arxiv.org/html/2410.18042v2
- Fromherz, Protzenko. *Compiling C to Safe Rust, Formalized (Scylla).* arXiv:2412.15042, OOPSLA 2026 — https://arxiv.org/abs/2412.15042
- Erbsen, Philipoom, Gross, Sloan, Chlipala. *Simple High-Level Code For Cryptographic Arithmetic.* IEEE S&P 2019 — https://jasongross.github.io/papers/2019-fiat-crypto-ieee-sp.pdf
- Bernstein et al. *KyberSlash: Exploiting secret-dependent division timings in Kyber implementations.* IACR ePrint 2024/1049
- Daniel, Bardin, Rezk. *Binsec/Rel.* ACM TOPS 2022 — https://dl.acm.org/doi/10.1145/3563037

**Depolar / dokümantasyon (hepsi 2026-09-08 erişimi)**
- https://github.com/hacl-star/hacl-star ; https://hacl-star.github.io/ ; https://hacl-star.github.io/Supported.html ; https://github.com/hacl-star/hacl-star/tree/main/code/rsapss ; https://github.com/hacl-star/hacl-star/commits/main
- https://github.com/celabshq/libcrux (Readme.md, SECURITY.md, CHANGELOG.md, crates/algorithms/*/Readme.md, libcrux-ml-kem/proofs/verification_status.md, libcrux-ml-kem/proofs/fstar/extraction/Makefile — tarball ile yerel inceleme)
- https://github.com/cryspen/hax ; https://hax.cryspen.com/frontend/ ; https://cryspen.com/hax-toolchain/
- https://github.com/mit-plv/fiat-crypto ; https://raw.githubusercontent.com/mit-plv/fiat-crypto/master/README.md
- https://github.com/awslabs/aws-lc-verification ; https://github.com/aws/aws-lc ; https://github.com/awslabs/s2n-bignum/blob/main/SOUNDNESS.md ; https://github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md
- https://github.com/aws/aws-lc-rs ; https://docs.rs/aws-lc-rs/latest/aws_lc_rs/ ; https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html
- https://github.com/briansmith/ring/commits/main ; https://github.com/briansmith/ring/discussions/2414 ; https://github.com/briansmith/ring/discussions/2450
- https://docs.rs/subtle/latest/subtle/ ; https://docs.rs/argon2/latest/argon2/ ; https://docs.rs/curve25519-dalek/latest/curve25519_dalek/ ; https://docs.rs/jsonwebtoken/latest/jsonwebtoken/ ; https://docs.rs/getrandom/latest/getrandom/ ; https://docs.rs/libcrux-hacl-rs/latest/libcrux_hacl_rs/ ; https://docs.rs/crate/libcrux-rsa/latest/source/src/lib.rs ; https://docs.rs/crate/p384/latest/source/src/arithmetic/field.rs ; https://docs.rs/crate/primefield/latest/source/src/lib.rs
- https://github.com/nss-dev/nss/tree/master/lib/freebl/verified ; https://github.com/nss-dev/nss/tree/master/lib/freebl/libcrux
- https://github.com/torvalds/linux/blob/master/lib/crypto/curve25519-hacl64.c ; .../curve25519-fiat32.c
- https://docs.python.org/3/library/hashlib.html ; https://github.com/python/cpython/issues/99108 ; commit `325e9b8ef400b86fb077aa40d5cb8cec6e4df7bb`
- https://cvsweb.openbsd.org/src/usr.bin/ssh/ ; https://www.openssh.org/txt/release-9.9 (2024-09-19)
- https://github.com/signalapp/libsignal/blob/main/Cargo.toml
- https://boringssl.googlesource.com/boringssl/+/refs/heads/master/third_party/fiat/README.md
- https://raw.githubusercontent.com/RustCrypto/AEADs/master/aes-gcm/README.md ; .../chacha20poly1305/README.md ; https://github.com/RustCrypto/AEADs/issues/87
- https://www.wireguard.com/formal-verification/

**Danışma belgeleri**
- https://rustsec.org/advisories/RUSTSEC-2025-0007.html (ring unmaintained — **WITHDRAWN**; 2025-02-21, son değişiklik 2025-03-06)
- https://rustsec.org/advisories/RUSTSEC-2025-0133.html (libcrux-intrinsics ≤0.0.3 aarch64 crypto-failure; 2025-12-04; GHSA-2cgv-28vr-rv6j)

**Blog / analiz**
- https://cryspen.com/post/strengths-and-limitations/ (CE Labs, 2026-02-12)
- https://cryspen.com/post/ml-kem-implementation/ (2024-01-16)
- https://cryspen.com/post/ml-kem-verification/
- https://symbolic.software/blog/2026-02-17-ce-labs-mldsa/ (2026-02-17)
- https://symbolic.software/blog/2026-03-23-crucible/ (2026-03-23)
- https://jonathan.protzenko.fr/2024/03/20/hacl-rs.html (2024-03-20)
- https://jonathan.protzenko.fr/2024/01/05/eurydice.html (2024-01-05)
- https://neuromancer.sk/article/26 (2021-01-30)
- https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/ (2020-02-26)

**Doğrulanamayanlar (tekrar):** Google bughunters blog gövdesi; OpenSSH 9.9'un ML-KEM kaynağının libcrux olduğu (2026 OpenBSD CVS'i teyit ediyor, 2024 release notu etmiyor); mbedTLS/Tezos/ElectionGuard'da HACL*'ın hangi algoritmalarda ve hâlâ kullanılıp kullanılmadığı; fiat-crypto'nun "Chrome trafiğinin %90'ı" iddiasının 2026 geçerliliği; Firefox'un fiat-crypto kullandığı iddiası (NSS kanıtı HACL*'a işaret ediyor); "Verified Rust Monomorphization" adlı bir makale; Charon taint-checker'ının bağımsız bir crate olarak yayınlanıp yayınlanmadığı.
