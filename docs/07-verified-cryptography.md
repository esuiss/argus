# §7 — Formel doğrulanmış kriptografi

Her iddianın yanında kaynak URL'si ve tarih verilmiştir. Doğrulanamayan konular açıkça işaretlenmiştir. crates.io rakamları 8 Eylül 2026'da crates.io API'sinden doğrudan çekilmiştir; son 90 gün indirme sayıları `recent_downloads` alanıdır. libcrux deposu `main` dalından tarball olarak indirilmiş ve yerel olarak incelenmiştir (8 Eylül 2026).

---

## 0. Yönetici özeti

2026'da Rust'tan kullanılabilir gerçek formel doğrulanmış kripto bulunmaktadır, ancak kapsamı sanıldığından dardır. Ana adres libcrux'tur (CE Labs, eski adıyla Cryspen) ve altındaki hacl-rs'tir, yani HACL*'tan üretilmiş saf Rust koddur.

Argus'un ihtiyaç listesinin büyük kısmı karşılanmaktadır: SHA-2, HMAC, HKDF, Ed25519, ECDSA P-256, X25519, ChaCha20-Poly1305, Poly1305 ve RSA-PSS'in hepsi HACL* ile doğrulanmış Rust olarak mevcuttur.

Kritik boşluklar şunlardır: RS256 (RSA PKCS#1 v1.5) doğrulanmış hâlde yoktur, Argon2 hiçbir yerde doğrulanmamıştır, AES-GCM libcrux'ta pre-verification statüsündedir, SHA-3 libcrux'ta doğrulanmamıştır, HMAC-DRBG tabanlı CSPRNG doğrulanmamıştır ve RSA anahtar üretimi bulunmamaktadır.

En önemli 2026 gelişmesi Nadim Kobeissi'nin Verification Theatre makalesidir (Şubat-Haziran 2026). Çalışma libcrux ve hpke-rs'te 13 zafiyet bulmuştur; dokuzu doğrulanmamış kodda, dördü sözde doğrulanmış spesifikasyon ve ispat kodundadır. libcrux ML-KEM Rust kodunun yalnızca %58,4'ünün ispatları gerçekten SMT çözücüye gönderilmektedir. Formally verified etiketi her şeyin doğrulandığı anlamına gelmemektedir.

Pratik tavsiye Argus için hibrit bir yaklaşımdır: kritik JWT primitifleri için libcrux, geri kalanı için `aws-lc-rs` (FIPS ve s2n-bignum HOL Light doğrulamalı aritmetik). libcrux pre-release olduğu için (`< 0.1`) sürümü pinlenmeli ve kendi test vektörlerimizle kullanılmalıdır.

---

## 1. HACL* ve EverCrypt (Project Everest, F*)

### 1.1 Ne doğrulanıyor

HACL* deposu üç özelliği garanti eder: bellek güvenliği, fonksiyonel doğruluk ve gizli bağımsızlık, yani bazı zamanlama yan kanallarına direnç (github.com/hacl-star/hacl-star, 8 Eylül 2026'da erişilmiştir).

Bellek güvenliği Low* seviyesinde dizi sınırlarının, pointer geçerliliğinin korunması ve taşma olmaması demektir. Fonksiyonel doğruluk, uygulamanın F*'ta yazılmış yüksek seviye matematiksel spesifikasyona karşı doğrulanmış olmasıdır. Gizli bağımsızlıkta Low*'un tip sistemi, gizli değerler üzerinde dallanmayı, gizli indeksle dizi erişimini ve gizli operandla değişken zamanlı işlem yapmayı (div, mod) kaynak seviyesinde yasaklar. Bu, sabit zamanlılığın kaynak kodu yaklaşımıdır.

### 1.2 Ne doğrulanmıyor: Trusted Computing Base

Bu kısım Argus için hayatidir. Kaynaklar CE Labs ve Cryspen'in kendi "Strengths and Limitations" yazısı (cryspen.com/post/strengths-and-limitations/, 12 Şubat 2026) ile Kobeissi 2026'dır.

**Derleyici.** Zincir F*'tan C'ye (KaRaMeL), oradan makine koduna (gcc, clang, LLVM) gider. KaRaMeL ve C derleyicisi TCB içindedir ve doğrulanmamıştır. Derleyici gizli bağımsızlığı bozabilir; örneğin `cmov`'u branch'e çevirebilir.

**Yürütülebilir dosyanın yan kanal direnci.** libcrux README'sinin kendi ifadesine göre bu depodaki koddan derlenen yürütülebilir dosyalar yan kanala dirençli olacak biçimde doğrulanmamıştır; yalnızca kaynak kodun gizli bağımsız olması sağlanmaya çalışılmaktadır (github.com/celabshq/libcrux, `Readme.md`, yerel kopya, 8 Eylül 2026).

**Donanım.** Spectre, Meltdown, önbellek ve spekülatif yürütme kapsam dışıdır.

**Platform soyutlamaları ve intrinsics.** SIMD sarmalayıcıları çoğu zaman aksiyom olarak alınır; V1 vakası aşağıdadır.

**Glue ve wrapper kodu.** C API'sini Rust'a saran katman genelde doğrulanmamıştır.

**Doğrulama araçlarının kendisi.** F*, Z3, KaRaMeL ve hax da TCB içindedir.

EverCrypt makalesi bu konuda dürüst olmasıyla ayrışır. Kobeissi'nin ifadesine göre EverCrypt güven varsayımlarını hassas biçimde hesaplaması ve derleyiciyi, Vale gömme semantiğini ve donanımı açıkça güvenilen bileşenler olarak tanımlamasıyla dikkat çekmektedir (Verification Theatre, s. 23, ePrint 2026/192).

### 1.3 Desteklenen algoritmalar

Kaynak: hacl-star.github.io/Supported.html, 8 Eylül 2026'da erişilmiştir.

| Kategori | Algoritma | Uygulama |
|---|---|---|
| AEAD | AES-GCM | Intel ASM (AES-NI ve CLMUL); yalnızca x64 assembly (Vale) |
| AEAD | ChaCha20-Poly1305 | Portable C ve 128 ile 256 bit vektörize |
| Hash | SHA2-224 ve SHA2-256 | Portable C, Intel ASM (SHAEXT) |
| Hash | SHA2-384 ve SHA2-512 | Portable C |
| Hash | SHA3 | Portable C |
| Hash | BLAKE2 | Portable C, 128 ve 256 dahil |
| Hash | MD5, SHA1 | Legacy |
| MAC ve KDF | HMAC, HKDF | Portable C ve Intel ASM |
| MAC | Poly1305 | Portable C (128, 256), Intel ASM |
| İmza | Ed25519 | Portable C |
| İmza ve ECDH | P-256 | Portable C |
| ECDH | Curve25519 | Portable C ve Intel ASM (BMI2, ADX) |
| Şifre | ChaCha20, AES-128 ve AES-256 | — |

RSA-PSS bu sayfada listelenmemiştir ancak depoda mevcuttur: `code/rsapss/` dizininde `Hacl.Spec.RSAPSS.fst`, `Hacl.Impl.RSAPSS.fst`, `Hacl.Impl.RSAPSS.MGF.fst`, `Hacl.Impl.RSAPSS.Padding.fst` ve `Hacl.RSAPSS.fst` bulunur (github.com/hacl-star/hacl-star/tree/main/code/rsapss, 8 Eylül 2026). Bu, libcrux-rsa'nın kaynağıdır.

HACL*'ta RSA PKCS#1 v1.5 (RS256), Argon2, PBKDF2 ve scrypt bulunmamaktadır; hashlib ve HKDF mevcuttur.

### 1.4 Gerçek dağıtımlar

Aşağıdaki kalemlerin her biri ayrı ayrı doğrulanmıştır.

| Proje | Ne kullanıyor | Kanıt | Tarih |
|---|---|---|---|
| Mozilla Firefox ve NSS | ChaCha20, ChaCha20-Poly1305 (32, 128, 256), Curve25519 (51 ve 64), Ed25519, Poly1305, SHA-3, P-256, P-384, P-521 | `nss/lib/freebl/verified/` dizinindeki `Hacl_*.c` dosyaları | 8 Eylül 2026; github.com/nss-dev/nss/tree/master/lib/freebl/verified |
| Firefox ve NSS, post-quantum | libcrux ML-KEM 512, 768, 1024 ve ML-DSA 44, 65, 87; Eurydice, Charon ve Karamel ile üretilmiş C | `nss/lib/freebl/libcrux/`; README dosyası bunun libcrux ML-KEM (FIPS 203) ve ML-DSA (FIPS 204) implementasyonlarının birleşik C çıkarımı olduğunu belirtir; upstream commit `87eda899b207aa8fecbdf7a6ecfa5f70a9b2c68c` | 8 Eylül 2026; github.com/nss-dev/nss/tree/master/lib/freebl/libcrux |
| Linux çekirdeği | Curve25519, 64 bit yol | `lib/crypto/curve25519-hacl64.c` başlığı kodun mitls/hacl-star kaynağından gelen, makine üretimi ve formel doğrulanmış bir Curve25519 ECDH implementasyonu olduğunu belirtir. Telif: INRIA ve Microsoft 2016-2017, Jason A. Donenfeld 2018-2019 | 8 Eylül 2026; github.com/torvalds/linux/blob/master/lib/crypto/curve25519-hacl64.c |
| Linux çekirdeği | Curve25519, 32 bit yol; HACL* değil fiat-crypto | `lib/crypto/curve25519-fiat32.c` | 8 Eylül 2026 |
| WireGuard | Yukarıdaki iki Curve25519 dosyası; Zinc'ten çekirdeğe geçmiştir | wireguard.com/formal-verification/ | 8 Eylül 2026 |
| CPython | MD5, SHA1, SHA2 ve SHA3 için OpenSSL sağlamadığında HACL* fallback'i; ayrıca BLAKE2 | hashlib dokümantasyonu, 3.12 ile birlikte bağlı OpenSSL'in sağlamadığı MD5, SHA1, SHA2 veya SHA3 algoritmalarında HACL* projesinden gelen doğrulanmış bir implementasyona düşüldüğünü belirtir; BLAKE2 için gh-99108 ve commit `325e9b8` | Python 3.12 ve üstü; 8 Eylül 2026 |
| mbedTLS, Tezos, ElectionGuard | Belirtilmemiş primitifler | Yalnızca HACL*'ın kendi beyanı (hacl-star.github.io/) | Bağımsız olarak doğrulanamamıştır; hangi algoritmanın, hangi sürümde ve hâlâ güncel olup olmadığı tespit edilememiştir |

### 1.5 2025-2026 aktivite durumu

HACL* deposu aktiftir. `main` dalındaki son commit'ler 10 Nisan 2026 (`Merge pull request #1070`), 9 Nisan 2026 (birden çok) ve 24 Mart 2026 tarihlidir (github.com/hacl-star/hacl-star/commits/main, 8 Eylül 2026). Depo `main` dalı F*'ın `master` dalını takip eder ve yaklaşık 19.000 commit içerir.

Lisans Apache-2.0'dır; üretilen C kodu ayrıca MIT altındadır.

> **Projenin kendi uyarısı.** HACL*, Vale ve EverCrypt devam eden araştırma projeleridir ve öyle değerlendirilmelidir (hacl-star.github.io/, 8 Eylül 2026).

---

## 2. HACL*'ın Rust'taki karşılığı: hacl-rs, Eurydice, Charon, Scylla

### 2.1 Terminoloji

Rust'a giden iki ayrı boru hattı bulunmaktadır ve bunlar sık karıştırılmaktadır.

**hacl-rs, KaRaMeL'in Rust arka ucudur ve Low*'tan güvenli Rust'a çevirir.** Jonathan Protzenko'nun 20 Mart 2024 tarihli duyurusuna göre HACL-rs'in hedefi hızlı, doğrulanmış, saf ve güvenli bir Rust kripto primitif kütüphanesidir; uzun vadede libcrux'taki HACL C kodunu değiştirmek ve C FFI bağlarını kaldırmaktır (jonathan.protzenko.fr/2024/03/20/hacl-rs.html).

Alfa sürümünde kapsanan algoritmalar hash'ler (SHA-1, SHA-2, SHA-3, BLAKE2), akış şifreleri (ChaCha20, Salsa20), MAC'ler (Poly1305, HMAC), AEAD (ChaCha-Poly), bignum'lar ve imzalardır (Ed25519, ECDSA-P256, RSA-PSS, FFDHE). Kapsam dışında EverCrypt çoğullama ve çevik API'leri, vektörize varyantlar, K256 ve o tarih itibarıyla HKDF bulunmaktadır.

Mekanizma şudur: KaRaMeL'in Rust arka ucu Low* buffer'larını ödünç alınmış dilimlere (`&[T]` ve `&mut [T]`) çevirir ve pointer aritmetiğini ağaç tabanlı statik analizle yönetir (jonathan.protzenko.fr/2024/01/05/eurydice.html, 5 Ocak 2024).

**Eurydice ise Rust'tan C'ye, yani ters yönde çalışır.** Eurydice Rust'ı C'ye derler; Charon ve KaRaMeL kütüphane olarak kullanılır. Bu araç, hax ile doğrulanmış Rust ML-KEM'in Firefox NSS'e ve OpenSSH'e C olarak girmesini sağlamıştır. Eurydice F*'tan Rust üretmez.

### 2.2 İlgili makaleler

"Verified Rust Monomorphization" adlı bir makale bulunamamıştır. Gerçek makaleler şunlardır.

**Charon: An Analysis Framework for Rust.** Son Ho, Guillaume Boisseau, Lucas Franceschino, Yoann Prak, Aymeric Fromherz, Jonathan Protzenko; arXiv:2410.18042 (v2, Ocak 2025); CAV 2025'te yayımlanmıştır. Charon, rustc ile program doğrulayıcıları arasında bir arayüzdür ve ULLBC (CFG) ile LLBC (yapılandırılmış AST) temsillerini sunar. Eurydice yaklaşık 5.000 satır OCaml'dır. Makale, Eurydice ile derlenen kodun Mozilla Firefox'a, Google'ın BoringSSL'ine ve OpenSSH'e entegre edildiğini belirtir. HACL*'ın Rust'a port'u yaklaşık 84 bin satır olarak değerlendirilmiştir. Charon üzerine kurulu bir taint-checker, yani sabit zaman ihlali dedektörü, KyberSlash benzeri bir açığı 10 saniyeden kısa sürede tespit eder ve CI'ya uygundur (arxiv.org/html/2410.18042v2).

**Compiling C to Safe Rust, Formalized (Scylla).** Aymeric Fromherz, Jonathan Protzenko; arXiv:2412.15042, OOPSLA 2026. libcrux'un `rsa` ve `ecdsa` alt crate README'leri C'den Rust'a dönüşüm için doğrudan bu makaleye referans verir. Yöntem tip yönlendirmeli bir C alt kümesinin güvenli Rust'a çevrilmesidir.

**hax: Verifying Security-Critical Rust Software using Multiple Provers.** Bhargavan, Buyse, Franceschino, Letager Hansen, Kiefer, Schneider-Bensch, Spitters; ePrint 2025/142, VSTTE 2024 bildirileri (Springer, 2025).

hacl-rs'e özel tekil bir USENIX veya S&P makalesi bulunamamıştır. hacl-rs'in akademik dayanağı Charon (CAV 2025), Scylla (OOPSLA 2026) ve orijinal HACL* makaleleridir.

### 2.3 crates.io'da hacl-rs

`hacl-rs` adında bir crate bulunmamaktadır. Gerçek isim `libcrux-hacl-rs`'tir.

| Alan | Değer |
|---|---|
| Sürüm | 0.0.5 |
| Toplam indirme | 1.943.244 |
| Son 90 gün | 1.123.859 |
| İlk yayın | 24 Şubat 2025 |
| Son güncelleme | 13 Mayıs 2026 |
| Lisans | Apache-2.0 |
| Açıklama | HACL*'tan çıkarılmış formel doğrulanmış Rust kodu; yardımcı kütüphane |

Modülleri `bignum`, `bignum25519_51`, `curve25519_51`, `streaming_types`, `fstar`, `lowstar`, `prelude` ve `util`'dir. HACL* commit `efbf82f29190e2aecdac8899e4f42c8cb9defc98`'den üretilmiştir (crates.io API ve docs.rs/libcrux-hacl-rs/latest/libcrux_hacl_rs/, 8 Eylül 2026).

Bu crate doğrudan kullanılmaz; algoritmalar `libcrux-*` crate'lerinden gelir.

Eski ve ölü crate'ler kullanılmaz: `hacl` 0.0.3-pre.1 (2023), `hacl-star` 0.1.0 (2019, C'ye binding), `hacl-sys`, `libcrux-hacl` 0.0.2-pre.2 (2024).

---

## 3. libcrux, 2026 durumu

### 3.1 Kurumsal değişiklik: Cryspen'den CE Labs'a

Depo `github.com/cryspen/libcrux` adresinden `github.com/celabshq/libcrux` adresine taşınmıştır. crates.io metadata hâlâ eski `cryspen/libcrux` URL'sini göstermektedir; README içindeki linkler de eski URL'yi kullanır. İletişim adresi artık `info@celabs.eu`, güvenlik bildirimi `security-reports@celabs.eu`'dur (github.com/celabshq/libcrux, 8 Eylül 2026; depo `Readme.md` ve `SECURITY.md`, yerel kopya).

### 3.2 Doğrulama rozet sistemi

libcrux üç rozet kullanır ve Argus kararlarının temeli bunlardır.

`pre-verification` rozeti, o crate'in varsayılan özelliklerinde bulunan kodun çoğunun veya tamamının henüz doğrulanmadığı anlamına gelir.

`verified-hacl` rozeti, crate'teki algoritmaların HACL* projesinin bir parçası olarak doğrulandığını ve Rust'a çıkarıldığını belirtir. HACL*'taki kaynak F* kodu bellek güvenliği, yüksek seviye bir spesifikasyona karşı fonksiyonel doğruluk ve gizli bağımsızlık için doğrulanmıştır. Ancak bu crate'lerde HACL* kodunu kullanan üst seviye Rust API'leri doğrulanmamış olabilir.

`verified` rozeti, crate'teki Rust kodunun çoğunun veya tamamının hax araç zinciri kullanılarak doğrulandığını, panik içermediğini ve matematiksel bir spesifikasyona karşı fonksiyonel olarak doğru olduğunu belirtir.

Kritik feragat şudur: bu depodaki koddan derlenen yürütülebilir dosyalar yan kanala dirençli olacak biçimde doğrulanmamıştır, yalnızca kaynak kodun gizli bağımsız olması sağlanmaya çalışılmaktadır.

Ayrıca libcrux pre-release aşamasındadır; tüm crate'leri `0.1`'in altında sürümlenmiştir. Bakımcılar, bu crate'lerin üretimde kullanılması düşünülüyorsa kendileriyle iletişime geçilmesini ve kullanım senaryosuna uygunluk konusunda danışılmasını istemektedir (libcrux `Readme.md`, `main` dalı, indirilen tarball, 8 Eylül 2026).

### 3.3 Algoritma bazında doğrulama durumu

Aşağıdaki tablo her alt crate'in kendi README dosyasından doğrudan okunmuştur (tarball, 8 Eylül 2026).

| Crate | Algoritma | Rozet | Not |
|---|---|---|---|
| `libcrux-sha2` | SHA-224, 256, 384, 512 | verified-hacl | — |
| `libcrux-hmac` | HMAC | verified-hacl | HMAC-SHA1 desteği 0.0.4'te kaldırılmıştır (PR #1391) |
| `libcrux-hkdf` | HKDF | verified-hacl | — |
| `libcrux-ed25519` | Ed25519 | verified-hacl | — |
| `libcrux-ecdsa` | ECDSA P-256 | verified-hacl | low-S normalizasyonu yoktur; kaynakta `low_s` ve `normalize` araması boş dönmüştür |
| `libcrux-p256` | P-256 (ECDH) | verified-hacl | libcrux'a içseldir, doğrudan kullanılmaz |
| `libcrux-rsa` | RSA-PSS | verified-hacl | SHA-256, 384, 512; 2048, 3072, 4096, 6144, 8192 ve değişken uzunluk; anahtar üretimi yoktur |
| `libcrux-curve25519` | X25519 | verified-hacl | — |
| `libcrux-chacha20poly1305` | ChaCha20-Poly1305 | verified-hacl | XChaCha20Poly1305 sarmalayıcısı doğrulanmamıştır |
| `libcrux-poly1305` | Poly1305 | verified-hacl | — |
| `libcrux-blake2` | BLAKE2 | verified-hacl | — |
| `libcrux-ml-kem` | ML-KEM 512, 768, 1024 | verified (hax) | Kısmîdir; 3.5'e bakınız |
| `libcrux-ml-dsa` | ML-DSA 44, 65, 87 | verified (hax) | Kısmîdir; yalnızca field aritmetiği, NTT ve serialization |
| `libcrux-kmac` | KMAC | verified (hax) | Yalnızca çalışma zamanı güvenliği için F* ile doğrulanmıştır, yani panik yokluğu |
| `libcrux-aes` | AES-GCM 128 ve 256, AES-CCM | pre-verification | Argus'un JWE ihtiyacı için kritik boşluktur |
| `libcrux-sha3` | SHA-3 ve SHAKE (FIPS 202) | pre-verification | — |
| `libcrux-hmac-drbg` | HMAC-DRBG (CSPRNG) | pre-verification | Crate henüz doğrulama beklemektedir |
| `libcrux-secrets` | Gizli bağımsızlık yardımcıları | pre-verification | — |
| `libcrux-psq` | PSQ protokolü | pre-verification | — |

> **Uyarı.** GitHub üzerinden yapılan ilk otomatik özet SHA-3 ve AES-GCM'i doğrulanmış olarak raporlamıştı; bu yanlıştır. Depo dosyalarının doğrudan okunması ikisinin de `pre-verification` statüsünde olduğunu göstermektedir.

### 3.4 crates.io metrikleri

8 Eylül 2026, canlı API:

| Crate | Sürüm | Toplam indirme | Son 90 gün | Son yayın | Lisans |
|---|---|---|---|---|---|
| `libcrux-sha3` | 0.0.10 | 3.051.978 | — | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-intrinsics` | 0.0.8 | 3.040.943 | — | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-ml-kem` | 0.0.10 | 2.771.531 | 1.212.756 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-secrets` | 0.0.6 | 2.744.096 | 1.281.685 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-traits` | 0.0.8 | 2.800.556 | — | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-hacl-rs` | 0.0.5 | 1.943.244 | 1.123.859 | 13 Mayıs 2026 | Apache-2.0 |
| `libcrux-sha2` | 0.0.8 | 1.937.139 | 1.119.955 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-p256` | 0.0.8 | 1.730.753 | 1.038.793 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-hmac` | 0.0.8 | 1.550.260 | 903.556 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-chacha20poly1305` | 0.0.9 | 1.441.398 | 868.709 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-hkdf` | 0.0.8 | 1.432.189 | — | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-curve25519` | 0.0.8 | 1.397.171 | 833.192 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-aesgcm` | 0.0.8 | 1.117.406 | 757.157 | 13 Mayıs 2026 | Apache-2.0 |
| `libcrux-ed25519` | 0.0.9 | 266.180 | 117.793 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-ml-dsa` | 0.0.10 | 171.691 | 113.789 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-hmac-drbg` | 0.0.1 | 22.257 | 22.257 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-ecdsa` | 0.0.8 | 4.985 | 721 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux-rsa` | 0.0.8 | 4.288 | 582 | 15 Temmuz 2026 | Apache-2.0 |
| `libcrux` (re-export) | 0.0.5 | 64.867 | 15.072 | 15 Temmuz 2026 | Apache-2.0 |

**Yorum.** ML-KEM, SHA-2, HMAC ve X25519 milyonlarca indirme almaktadır; bu trafik Signal, NSS ve HPKE zincirinden gelir. Ancak Argus için en kritik iki crate olan `libcrux-ecdsa` ve `libcrux-rsa` 90 günde sırasıyla 721 ve 582 indirme almıştır. ES256 ve PS256 yolları pratikte neredeyse hiç kullanılmamaktadır ve bu bir olgunluk ile saha testi riskidir.

MSRV varsayılan özellik setinde 1.89.0'dır; `no_std` de 1.89.0'dan itibaren desteklenir. `no_std` desteklenmekle birlikte `libcrux-rsa` global allocator gerektirir. Lisans crates.io metadata'sında Apache-2.0 görünür; depoda hem `LICENSE` hem `LICENSE-MIT` bulunur, yani Apache-2.0 ve MIT.

### 3.5 libcrux-ml-kem'in gerçek doğrulama kapsamı

Kaynak deponun kendi `libcrux-ml-kem/proofs/verification_status.md` dosyasıdır (tarball, 8 Eylül 2026). Dosya kendi uyarısını taşır: bu sürüm basit bir script ile üretilmiştir, ispat durumunu görselleştirmek için daha hassas bir yönteme ihtiyaç vardır ve aşağıdaki tablo kaba bir rehber olarak değerlendirilmelidir.

Generic modüller:

| Modül | Fonksiyon | Panik yok | Doğru |
|---|---|---|---|
| constant_time_ops | 7 | 7/7 | 7/7 |
| hash_functions | 49 | 49/49 | 49/49 |
| ind_cpa | 21 | 0/21 | 0/21 |
| ind_cca | 27 | 27/27 | 26/27 |
| polynomial | 35 | 35/35 | 34/35 |
| ntt | 8 | 4/8 | 4/8 |
| invert_ntt | 6 | 4/6 | 4/6 |
| matrix | 5 | 1/5 | 0/5 |
| serialize | 20 | 16/20 | 2/20 |
| sampling | 5 | 0/5 | 0/5 |

Backend'ler: portable backend tamdır (arithmetic 13/13, ntt 10/10, serialize 22/22, compress 6/6, sampling 1/1). AVX2 kısmîdir (arithmetic 12/12 panik yok ve 11/12 doğru, ntt 5/7, serialize 19/22). NEON, yani ARM64 üzerinde iOS, modern Android, Apple Silicon ve AWS Graviton, neredeyse hiç doğrulanmamıştır (arithmetic 0/13, ntt 0/7, compress 0/7, serialize 0/12).

F* Makefile'ından doğrudan (yerel kopya, `libcrux-ml-kem/proofs/fstar/extraction/Makefile`, 8 Eylül 2026):

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

`ADMIT_MODULES` listesindeki modüller `--admit_smt_queries true` ile derlenir, yani ispatları hiç kontrol edilmez. IND-CPA çekirdeği ve tüm NEON yolu bugün itibarıyla hâlâ bu listededir.

### 3.6 ML-KEM ve ML-DSA'nın gerçek üretim benimsenmesi

| Kullanıcı | Kanıt | Tarih |
|---|---|---|
| Mozilla Firefox ve NSS | `nss/lib/freebl/libcrux/`; libcrux ML-KEM ve ML-DSA'nın Eurydice, Charon ve Karamel ile yapılmış C çıkarımı, upstream commit `87eda899b2` | 8 Eylül 2026 |
| Signal (libsignal) | `Cargo.toml` dosyasında `libcrux-ml-kem = { version = "0.0.10" }`, `hpke-rs = "0.7"`, `hpke-rs-crypto = "0.7"` | 8 Eylül 2026; github.com/signalapp/libsignal/blob/main/Cargo.toml |
| OpenSSH ve OpenBSD | `src/usr.bin/ssh/libcrux-mlkem-mldsa.c` (rev 1.1, 14 Haziran 2026), `libcrux_internal.h`, `mlkem_mldsa.sh`. Commit mesajı ML-DSA implementasyonunun libcrux'tan geldiğini belirtir ve Jonas Schneider-Bensch ile Jonathan Protzenko'ya teşekkür eder | cvsweb.openbsd.org/src/usr.bin/ssh/, 8 Eylül 2026 |
| OpenSSH 9.9 (mlkem768x25519) | Release notu ML-KEM ve X25519 hibrit KEX eklendiğini söyler ancak kaynak kütüphaneyi belirtmez. hax makalesi (ePrint 2025/142) kütüphanenin OpenSSH ve Mozilla NSS tarafından benimsendiğini belirtir | 19 Eylül 2024; openssh.org/txt/release-9.9. Release notundan libcrux doğrulanamamıştır, ancak 2026 CVS kaydı libcrux'u açıkça teyit etmektedir |
| Google, dahili kullanım | Kobeissi 2026 libcrux'un Google'da dahili olarak kullanılan ML-KEM implementasyonu olduğunu belirtir ve kaynak olarak Google bughunters blogunu gösterir. Blog gövdesi çekilememiştir | Blog gövdesi doğrulanamamıştır; bughunters.google.com/blog/6038863069184000/formally-verified-post-quantum-algorithms |
| OpenMLS | `openmls_libcrux_crypto` 0.4.0, 105.584 indirme, güncelleme 25 Ağustos 2026 | crates.io, 8 Eylül 2026 |
| Chrome ve BoringSSL | Charon makalesi Eurydice üretimi kodun BoringSSL'e girdiğini söyler; ancak BoringSSL'in ML-KEM'i kendi implementasyonu olabilir | Hangi kodun kullanıldığı doğrulanamamıştır |

### 3.7 Verification Theatre: 2026'nın en önemli bulgusu

Kaynak Nadim Kobeissi'nin (Symbolic Software, Paris) "Verification Theatre: False Assurance in Formally Verified Cryptographic Libraries" başlıklı çalışmasıdır; IACR ePrint 2026/192, 5 Şubat 2026'da alınmış ve 25 Haziran 2026'da revize edilmiştir. PDF indirilip tam metni çıkarılmıştır.

Çalışma 13 zafiyet ve beş hata tipinden oluşan bir taksonomi sunar.

Doğrulama sınırının dışında kalan dokuz zafiyet:

| # | Zafiyet | Tip | Etki |
|---|---|---|---|
| V1 | `_vxarq_u64` intrinsic sarmalayıcısı yanlış argüman geçirmekte ve ARM64'te SHA-3 bozulmaktadır | I | libcrux-ml-dsa v0.0.3 farklı platformlarda farklı public key ve imza üretiyordu. Filippo Valsorda Kasım 2025'te bildirmiştir. RUSTSEC-2025-0133 (4 Aralık 2025), `libcrux-intrinsics` 0.0.3 ve altını etkiler, 0.0.4'te düzeltilmiştir |
| V2 | Incremental API'de backend'ler arası endianness tutarsızlığı | I | Signal'in post-quantum ratchet'inde gerçek şifre çözme hataları oluşmuştur. Signal v0.76.3 ile v0.86.9 arası etkilenmiş, libsignal v0.86.12'de (15 Ocak 2026) düzeltilmiştir. GuuJiang 27 Aralık 2025'te bildirmiş, CE Labs 6 Ocak 2026'da merge etmiş ancak güvenlik danışma belgesi yayımlamamıştır |
| V3 | hpke-rs'te X25519 all-zero paylaşılan sır kontrolü yoktur; RFC 9180 §7.1.4 bunu zorunlu kılar | II | Düşük mertebeli public key ile tüm HPKE key schedule'ı deterministik hâle getirilebilir. Signal `signal-crypto` ve OpenMLS etkilenmektedir |
| V4 | hpke-rs'te sequence number `u32`'dir ancak taşma kontrolü `u128 > 2⁹⁶-1` ile karşılaştırma yapar ve ölü koda dönüşür | II | Release build'de sayaç sessizce sıfıra sarar, nonce yeniden kullanılır ve plaintext kurtarma ile evrensel forgery mümkün olur |
| V5 | ECDSA P-256'da `s ≤ n/2` low-S kontrolü yoktur | III | İmza malleability oluşur. FIPS 186-5'e uygundur ancak Bitcoin ve Ethereum gibi sistemlerin gerektirdiği teklik sağlanmaz. Kaynak kodda bugün de yoktur; 8 Eylül 2026'da grep ile teyit edilmiştir |
| V6 | Ed25519 `key_gen` sarmalayıcısı tohumu iki kez clamp'lemektedir | IV | Etkin tohum entropisi beş bit azalır. Düzeltilmiştir; güncel `crates/algorithms/ed25519/src/impl_hacl.rs` dosyasında clamp yoktur |
| V7 | libcrux-psq'da AES-GCM decrypt içinde `.unwrap()` kullanılmaktadır | IV | Tek bozuk ciphertext süreci çökertir; ayrıca IND-CCA güvenliğini bozar, çünkü decryption oracle ⊥ döndürmek yerine sonlanır |
| V8 | ML-DSA doğrulayıcı norm kontrolü `2<<GAMMA1_EXPONENT`, yani `2γ₁` kullanmaktadır; doğrusu `γ₁-β`'dır ve kod ölü koda dönüşür | IV | Kötü niyetli bir imzalayan, libcrux'un kabul edeceği ancak FIPS 204 uyumlu implementasyonların reddedeceği imzalar üretebilir. Commit `326c837a33` (7 Ocak 2025) |
| V9 | ML-DSA hint deserialization'da yanlış değişken kontrol edilmektedir; `previous_` yerine `current_` | IV | Son satırda ω sınırı aşılabilir, keyfi hint pozisyonları oluşur ve strong unforgeability ihlal edilir |

Sözde doğrulanmış kodun içindeki dört zafiyet:

| # | Zafiyet | Detay |
|---|---|---|
| V10 | `Spec.MLKEM.Math.fst` dosyasında `decompress_d` yanlış sabit olan 1664'ü kullanmaktadır; doğrusu `2^(d-1)`'dir | FIPS 203 ile d değerinin 1, 4, 5, 10 ve 11 olduğu her girdide uyuşmaz. `decompress_d(d,0)` sıfır dönmez. Rust implementasyonu doğrudur, spesifikasyon yanlıştır |
| V11 | ML-KEM spesifikasyonunda ters NTT eksiktir | — |
| V12 | Serialization'da yanlış bir lemma sessizce kabul edilmektedir (`if lax_on () then iterAll tadmit`) | Modül `SLOW_MODULES` listesinde olduğu için tam doğrulamada bile admit edilir |
| V13 | ML-DSA AVX2 intrinsics aksiyomlarında `i16_mul_32extended` x ile y'nin çarpımı yerine x'in karesini hesaplamaktadır | Tüm AVX2 ispatlarının matematiksel temelini sağlamsız kılar |

Nicel analiz (Tablo 5, makale s. 16):

| Bileşen | Doğrulanmış | Admit | Opaque | Çıkarılmamış | Toplam |
|---|---|---|---|---|---|
| ML-KEM generic | 8.986 | 1.464 | — | 3.198 | 13.648 |
| Portable backend | 1.431 | 748 | — | — | 2.179 |
| AVX2 backend | 1.732 | — | — | — | 1.732 |
| NEON backend | 0 | 792 | — | — | 792 |
| libcrux-intrinsics | 0 | — | 2.457 | — | 2.457 |
| Toplam | 12.149 | 3.004 | 2.457 | 3.198 | 20.808 |
| Oran | %58,4 | %14,4 | %11,8 | %15,4 | %100 |

Bir ML-KEM dağıtımını oluşturan Rust kodunun yalnızca %58,4'ünün ispatları gerçekten SMT çözücü tarafından kontrol edilmektedir.

Modül seviyesinde (Tablo 6) 138 çıkarılmış F* modülünün 127'si, yani %92'si kontrol edilmektedir. Ancak admit edilen 11 modül en güvenlik kritik olanlardır: `Ind_cpa.fst`, `Sampling.fst`, yedi NEON modülü ve V12'yi barındıran `Vector.Portable.Serialize.fst`. Ayrıca hiçbir CI yapılandırması `VERIFY_SLOW_MODULES=yes` değerini ayarlamamaktadır; yavaş modüller hiçbir otomatik sistem tarafından kontrol edilmemiştir.

İfşa süreci Argus'un tedarikçi risk değerlendirmesi için önemlidir (Tablo 10):

| Tarih | Olay |
|---|---|
| Kasım 2025 | Valsorda V1'i bildirir; CE Labs düzeltir ancak güvenlik danışma belgesi yayımlamaz, advisory'yi Birr-Pixton açar |
| 27 Aralık 2025 | GuuJiang V2'yi bildirir; Signal post-quantum ratchet arızası |
| 6 Ocak 2026 | CE Labs V2 düzeltmesini merge eder, yine advisory yayımlamaz |
| 5 Şubat 2026 | Symbolic Software V3, V4, V5 ve V6 için test edilmiş PR'lar gönderir |
| 5-6 Şubat 2026 | CE Labs raportörün GitHub hesabını engeller, dört PR'ı kapatır ve ifşa anında depoda mevcut olmayan bir güvenlik politikasına atıf yapar |
| 9 Şubat 2026 | CE Labs düzeltmeleri atıf vermeden merge eder |
| 12 Şubat 2026 | CE Labs yanıt yayımlar: V1 ve V6'yı kabul eder, V3, V4, V5 ve V7'yi atlar ve doğrulanmış kodda hiç hata bulunmadığını söyler; V8 ile V13 arası bulgular bunu doğrudan yalanlar |
| Şubat 2026 | V7 ile V10-V13 keşfedilir; raporlama kanalı kalmadığı için public commit ile ifşa edilir |
| 17 Şubat 2026 | V8 ve V9 ifşa edilir; iki FIPS 204 ihlali |
| 4 Mart 2026 | CE Labs V8 ve V9 düzeltmelerini bu kez atıf vererek merge eder |

CE Labs'ın 12 Şubat 2026 tarihli yanıtı (cryspen.com/post/strengths-and-limitations/) doğrulamanın güçlü yanlarını ve sınırlarını dürüstçe anlatır: platform stub'ları, sarmalayıcılar, sistem kütüphaneleri, F*, KaRaMeL ve hax'in kendisi ile derlenmiş yürütülebilir dosyalar için yan kanal direncine dair formel garanti verilmediği belirtilir. Ancak yazı Symbolic Software'in bulgularına atıf yapmaz.

Symbolic Software'in ML-DSA yazısına göre (symbolic.software/blog/2026-02-17-ce-labs-mldsa/, 17 Şubat 2026) `VERIFIED_MODULES` listesinde yirmi yedi modül vardır; üst seviye imzalama ve doğrulama mantığı dahil olmak üzere geri kalan her şey `ADMIT_MODULES` içindedir.

### 3.8 libcrux CHANGELOG'undaki güvenlik düzeltmeleri

Yerel kopya, 8 Eylül 2026.

**0.0.5 (15 Temmuz 2026).** `libcrux-aes` #1528 AES-GCM ve AES-CCM tag kontrolünde sabit zamanlı karşılaştırmaya geçmiştir; yani Temmuz 2026'ya kadar tag karşılaştırması sabit zamanlı değildi ve bu Argus'un JWE ihtiyacı için doğrudan alakalıdır. `libcrux-sha3` #1456 AVX2 SHAKE-256'da out-of-bounds indekslemeyi düzeltmiştir. `libcrux-secrets` #1460 ve #1461 aarch64 select ve swap işlemlerindeki hatalı karşılaştırmayı düzeltmiştir. `libcrux-aes` #1474 AES-GCM için RFC 5116 plaintext ve AAD uzunluk limitlerini eklemiştir.

**0.0.4 (13 Mayıs 2026).** `libcrux-ml-dsa` #1398 hatalı AVX2 `use_hint` düzeltmesidir. `libcrux-ml-dsa` #1395 AVX2'de iNTT girdilerinin tam indirgenmemesini düzeltir. `libcrux-chacha20poly1305` #1386 `encrypt` içindeki potansiyel paniği düzeltir; fg0x0 bildirmiştir.

**Yayımlanmamış.** `libcrux-hmac-drbg` #1558 reseeding sarmalayıcılarının `fill_bytes` metodundaki paniği düzeltir.

Bu liste sağlıklı bir güvenlik iyileştirme temposunu göstermektedir, ancak aynı zamanda kütüphanenin hâlâ olgunlaşma aşamasında olduğunun kanıtıdır.

### 3.9 libcrux'un sabit zaman test altyapısı

`crates/utils/ctgrind-test/` dizini Valgrind memcheck ile sabit zaman testi yapar. `crabgrind` (Rust Valgrind Client Request binding'i, v0.3.1, 899.848 indirme, 20 Temmuz 2026) kullanılır. Gizli veri `mark_memory` ile undefined işaretlenir, kripto işlemi çalıştırılır ve Valgrind, undefined bit içeren bir değerin gözlemlenebilir davranış farkı yaratacak biçimde kullanılmasını raporlar; bu kullanımlar bellek adresi üretimi, kontrol akışı kararı ve syscall parametresidir.

Test edilen binary'ler `sha3`, `mlkem` (ML-KEM-512 decapsulate, undefined private key) ve `mldsa`'dır (ML-DSA-44, 65, 87 sign).

`libcrux-secrets` crate'i `--cfg valgrind_ct_test` ve `check-secret-independence` özelliğiyle bu işaretlemeyi otomatikleştirir. Kendi uyarısına göre bu yöntem değişken zamanlı komutlar (örneğin div) veya cache yan kanalları gibi diğer yan kanalları kontrol etmez.

Bu desen Argus için doğrudan uygulanabilirdir.

---

## 4. hax araç zinciri

### 4.1 Ne yapıyor

Rust'ın bir alt kümesini alıp çoklu kanıt arka uçlarının giriş diline çevirir. İki parçası vardır: frontend rustc'ye hook olur ve zenginleştirilmiş AST döker; engine ise bir OCaml binary'sidir ve çeviri fazlarını uygulayıp F*, Coq ve benzeri çıktıları üretir (github.com/cryspen/hax, hax.cryspen.com/frontend/, 8 Eylül 2026).

Araç Aralık 2023'te hacspec'ten sıfırdan yeniden başlatılmıştır. hacspec artık hax içinde bir spesifikasyon dili, yani saf fonksiyonel bir Rust alt kümesi olarak yaşamaktadır.

### 4.2 Arka uç olgunluğu

8 Eylül 2026 itibarıyla:

| Backend | Durum |
|---|---|
| F* | Stable; üretime hazırdır |
| Lean (Charon ve Aeneas üzerinden) | Aktif geliştirilmektedir ve önerilmektedir |
| Rocq (Coq) | Deneyseldir |
| ProVerif | Deneyseldir |
| SSProve | Deneyseldir |
| EasyCrypt | Deneyseldir |

Lean backend'in önerilen hâle gelmesi 2026'nın önemli bir değişimidir; makale (2025/142) yazıldığında Lean henüz gelecek çalışma olarak anılıyordu.

### 4.3 Kanıtlanabilen özellikler

hax makalesi (ePrint 2025/142) ve Cryspen'in ML-KEM yazısına göre (cryspen.com/post/ml-kem-implementation/, 16 Ocak 2024) hax ile F* üç özelliği kanıtlar: spesifikasyona karşı fonksiyonel doğruluk; çalışma zamanı güvenliği ve panik yokluğu (panik yok, dizi sınırları korunur, integer overflow olmaz); gizli bağımsızlık, yani gizli değerler üzerinde dallanmama, gizli zamanlı işlem yapmama ve gizli indeksli dizi erişimi yapmama.

### 4.4 Rust alt kümesi kısıtları

`&mut T` dönüş tiplerinde ve aliasing durumunda yasaktır. Desteklenmeyen özelliklerin listesi GitHub'da etiketlidir ve bir kısmı "wontfix-v1" olarak işaretlenmiştir (github.com/cryspen/hax, 8 Eylül 2026).

### 4.5 crates.io

`hax-lib` 0.4.0 sürümü 7 Eylül 2026'da yayımlanmıştır; toplam 3.122.564 indirme, son 90 günde 1.344.309 indirme almıştır ve Apache-2.0 lisanslıdır. Önceki sürümler 0.3.7 (20 Mayıs 2026) ve 0.3.6'dır (15 Ocak 2026). Kaynak crates.io API'si, 8 Eylül 2026.

Bu, hax'in aktif ve hızlı geliştirildiğini göstermektedir. Ancak `hax-lib`'in yüksek indirme sayısı büyük ölçüde libcrux'un transitif bağımlılığı olmasından gelir, bağımsız kullanımdan değil.

### 4.6 hax ile doğrulanan diğer projeler

Bertie bir Rust TLS 1.3 implementasyonudur; ProVerif ile sembolik güvenlik analizi ve F* ile parsing ile serialization için panik yokluğu doğrulaması yapılmıştır (github.com/cryspen/bertie). Galois'in Crux-MIR aracı hacspec'i benimsemiş ve ring'in SHA-1 ile SHA-2 implementasyonlarını hacspec spesifikasyonlarına karşı doğrulamıştır (hax makalesi, ePrint 2025/142). Coq backend'i ile fiat-crypto bağlantısı kurulmuştur (Holdsbjerg-Larsen ve Spitters, CoqPL'22). Rust akıllı sözleşmeleri ConCert ve Coq ile doğrulanmaktadır.

---
## 5. fiat-crypto (Coq, MIT PLV)

### 5.1 Ne üretiyor, ne kanıtlıyor

Coq içinde yazılmış, doğru inşa edilmiş bir sonlu cisim aritmetiği üreticisidir. Solinas indirgeme, Montgomery çarpımı ve taban dönüşümü gibi stratejilerle P-256, P-384, P-521 ve Curve25519 gibi eğriler için alan işlemleri üretir.

Kanıtlanan şey alan aritmetiğinin fonksiyonel doğruluğudur.

Kanıtlanmayanlar README'den doğrudan alınmıştır (raw.githubusercontent.com/mit-plv/fiat-crypto/master/README.md, 8 Eylül 2026). Bedrock2 backend'i için Bedrock2 AST'sinin iç AST semantiğiyle eşleştiğine dair ispatlar vardır; diğer hiçbir backend hakkında ispat yoktur. Üretilen integer boyut cast'lerinin, gcc, clang veya kullanılan derleyicinin ifadeler için integer boyutlarını doğru seçmesini sağlamaya yeterli olduğuna dair bir doğrulama yoktur. Bedrock2 backend'inin yazdırdığı C kodunda bile string'e dönüşümün doğru olduğuna dair ispat bulunmamaktadır.

README'de açık bir sabit zaman iddiası yoktur. Üretilen kod yapısı gereği düz çizgi ve dallanmasız olduğu için pratikte sabit zamanlıdır, ancak bu formel olarak kanıtlanmamıştır.

Kapsam yalnızca alan aritmetiğidir; tam protokol, hatta tam eğri grup işlemleri değildir. Bedrock2 hattı P-256 nokta işlemlerini de kapsar ve BoringSSL'de kullanılır.

### 5.2 Backend'ler ve bakım durumu

| Backend | Bakım | CI | Üretilen kodun test edildiği yer |
|---|---|---|---|
| C | Tam | Var | BoringSSL |
| Bedrock2 ve C | Tam, ispatlı | Var | BoringSSL |
| Go | Harici katkıcı | Var | — |
| Rust | Harici katkıcı | Var | Dalek |
| Zig | Harici katkıcı | Var | Zig stdlib |
| Java | Bakımsız | Var | Bilinen hatalıdır |
| JSON | Deneysel | Var | — |

> **Argus için kritik nüans.** Rust backend'i harici bir katkıcı tarafından bakılmaktadır ve hakkında hiçbir ispat yoktur. Dolayısıyla fiat-crypto Rust kodunun formel doğrulandığı ifadesi teknik olarak yanlıştır; doğrulanan şey Coq içindeki iç AST'dir, Rust'a yazdırma adımı doğrulanmamıştır.

### 5.3 Dağıtımlar

| Yer | Kanıt | Tarih |
|---|---|---|
| BoringSSL, dolayısıyla Chrome, Android ve Google altyapısı | `third_party/fiat/` dizinindeki dosyaların çoğu Fiat Cryptography ile üretilmiştir; P-256 alan aritmetiği ve nokta işlemleri Bedrock2 çevirisidir; `asm/` dizini CryptOpt ile derlenmiştir. Bazı rutinler açıkça `bedrock_unverified_platform.c.inc` olarak işaretlidir | 8 Eylül 2026; boringssl.googlesource.com |
| Linux çekirdeği | `lib/crypto/curve25519-fiat32.c`, 32 bit Curve25519 | 8 Eylül 2026 |
| Zig stdlib | fiat-crypto README'si | 8 Eylül 2026 |
| Chrome'un %90 iddiası | Güvenli Chrome iletişimlerinin yaklaşık %90'ının fiat-crypto kodu çalıştırdığı iddiası CSO Online ve MIT CSAIL basın haberlerindedir | Tarihi yaklaşık 2019'dur ve 2026 için doğrulanamamıştır |
| Firefox | NSS'in `verified/` dizini HACL* kodu içerir, fiat değil. Firefox'un fiat-crypto kullandığına dair kanıt bulunamamıştır | Doğrulanamamıştır ve muhtemelen yanlıştır |

Akademik referans: Erbsen, Philipoom, Gross, Sloan, Chlipala, "Simple High-Level Code For Cryptographic Arithmetic — With Proofs, Without Compromises", IEEE S&P 2019.

### 5.4 Rust ekosisteminde fiat-crypto

crates.io verisi, 8 Eylül 2026. `fiat-crypto` crate'i v0.3.0 sürümündedir, toplam 133.799.092 indirme ve son 90 günde 31.578.526 indirme almıştır, son yayın 4 Haziran 2025'tir, MSRV 1.83.0'dır ve lisansı MIT, Apache-2.0 veya BSD-1-Clause'dur.

Yirmi üç crate bağımlıdır. Öne çıkanlar şunlardır.

`curve25519-dalek` 5.0.0 (6 Temmuz 2026) `fiat-crypto ^0.3.0`'a zorunlu bağımlıdır. Backend seçenekleri `serial` (otomatik), `fiat` (manuel seçim), `simd` (AVX2, otomatik) ve `avx512`'dir (IFMA, otomatik). Dokümantasyon `fiat` seçeneğini fiat-crypto'dan gelen formel doğrulanmış alan aritmetiği olarak tanımlar ve 32 ile 64 bit için geçerli olduğunu belirtir (docs.rs/curve25519-dalek/latest/curve25519_dalek/, 8 Eylül 2026). Dalek fiat backend'ini içermekte ve hâlâ desteklemektedir, ancak varsayılan değildir; `--cfg curve25519_dalek_backend="fiat"` ile açılması gerekir.

`p384` 0.14.0 `fiat-crypto ^0.3`'e zorunlu bağımlıdır. Kaynak kodda aritmetik implementasyonlarının fiat-crypto ile sentezlendiği belirtilir. `p384_backend = "fiat"` ile aktif edilir.

`orion` 0.18.0, `ed448-goldilocks` 0.9.0, `prio` 0.17.0 ve çeşitli dalek fork'ları diğer bağımlılardır.

**Önemli bulgu: `p256` artık fiat-crypto kullanmamaktadır.** `p256` 0.14.0 (3 Temmuz 2026) bağımlılıkları `elliptic-curve`, `ecdsa`, `hash2curve`, `primefield`, `primeorder`, `serdect` ve `sha2`'dir; `fiat-crypto` listede yoktur. `p256/src/arithmetic/field.rs` dosyası `primefield::monty_field_params!` ve `monty_field_element!` makrolarını kullanır; bunlar generic `crypto-bigint` Montgomery aritmetiğidir.

`primefield` crate'i kendisini `crypto-bigint` üzerine kurulu generic bir asal cisim implementasyonu olarak tanımlar ve fiat-crypto kullanan formel doğrulanmış aritmetikli newtype'lar yazmak için makrolar içerdiğini belirtir. Yani makro mevcuttur ancak `p256` onu kullanmaz; bağımlılık listesinde fiat-crypto yoktur (crates.io API, docs.rs kaynak dosyaları, 8 Eylül 2026).

> **Argus için sonuç.** ES256, yani P-256 yolunda RustCrypto `p256` artık fiat ile doğrulanmış aritmetik kullanmamaktadır. P-384 kullanmaktadır. Bu bir gerilemedir veya en azından bir değişimdir ve dikkat edilmelidir.

Ölü ve eski crate'ler kullanılmaz: `curve25519-dalek-fiat` 0.1.0 (16 Şubat 2021), `x25519-dalek-fiat` 0.1.0 (2021), `ed25519-dalek-fiat` 0.1.0 (2021). Bunlar Novi Financial fork'larıdır ve beş yıldır güncellenmemiştir. Ana dalek'in `fiat` backend'i kullanılır.

---

## 6. AWS-LC, s2n-bignum ve SAW-Cryptol

### 6.1 aws-lc-verification (SAW, Cryptol, NSym, Coq)

Kapsam sınırı README'nin ilk cümlesindedir: AWS-LC'nin bölümleri formel olarak doğrulanmıştır. "Bölümleri" ifadesi kasıtlıdır ve önemlidir.

CI'da doğrulanan algoritmalar (github.com/awslabs/aws-lc-verification, 8 Eylül 2026; ayrıca Kobeissi 2026 Tablo 8):

| Algoritma | Platform | Araç | Caveat'lar |
|---|---|---|---|
| SHA-2 (384, 512) | SandyBridge ve üstü | SAW | NoEngine, MemCorrect |
| SHA-2 (384, 512) | Neoverse | SAW ve NSym | NoEngine, NoInline, MemCorrect, ArmSpecGap, ToolGap, LaxPointer |
| HMAC-SHA384 | SandyBridge ve üstü | SAW | NoEngine, MemCorrect, InitZero, NoInline, CRYPTO_once_Correct |
| AES-KW(P) 256 | SandyBridge ve üstü | SAW | InputLength, MemCorrect, NoInline |
| AES-GCM 256 | SandyBridge ile Skylake arası | SAW | MemCorrect, NoInline, GcmSpecGap, GcmMultipleOf16, GcmADNotVerified, GcmIV9Tag16, GcmWellFoundedInduction |

Doğrulama sınırlı ve bounded'dır. AES-KW yalnızca sınırlı sayıda girdi uzunluğunda doğru olarak doğrulanmıştır. `EVP_EncryptUpdate` ve `EVP_DecryptUpdate` yalnızca tam blokların şifrelendiği veya çözüldüğü durumlarda doğrulanmıştır. AES-GCM fonksiyonları yalnızca 12 baytlık IV ve 16 baytlık tag için doğrulanmıştır. `GcmADNotVerified` caveat'ı additional data'nın doğrulanmadığını belirtir.

ECDSA, ECDH ve HKDF için proof script'leri depoda bulunmaktadır ancak CI'da devre dışıdır ve README'den kaldırılmıştır. Kobeissi 2026 bunu doğrulama statüsünün gerilediğinin açık bir kabulü olarak niteler. Doğrulama çabası s2n-bignum ve CBMC yaklaşımlarına kaymıştır.

Doğrulanmadığı açıkça belirtilen bileşenler `OPENSSL_malloc`, `OPENSSL_free`, `CRYPTO_refcount_inc` ve `ERR_put_error`'dur; bunların doğru davrandığı varsayılmaktadır.

Yirmi altı adlandırılmış caveat ve yapılandırılmış soundness dokümanları bulunmaktadır. CI her push ve PR'da beş paralel iş çalıştırır; libcrux'un aksine ispatlar gerçekten kontrol edilmektedir.

### 6.2 s2n-bignum (HOL Light)

Bu bölüm Argus için en alakalı kısımdır.

AWS-LC README'sine göre proje x86_64 ve aarch64 için algoritmaları veya alt rutinleri implemente etmek üzere s2n-bignum'dan assembly kullanmaktadır ve bu fonksiyonlar HOL Light ile formel olarak doğrulanmıştır.

Kapsanan primitifler RSA, P-256, P-384, P-521, X25519 ve Ed25519'dur; hem x86-64 hem aarch64 için geçerlidir (github.com/aws/aws-lc, 8 Eylül 2026).

SOUNDNESS.md dosyasına göre (github.com/awslabs/s2n-bignum/blob/main/SOUNDNESS.md, 8 Eylül 2026) iki şey kanıtlanmaktadır.

Fonksiyonel doğruluk: makine durumu bir önkoşulu sağlıyorsa, formel ISA modeli üzerindeki yürütmenin eninde sonunda bir sonkoşulu sağlayan bir duruma ulaşacağı garanti edilir.

Sabit zamanlı yürütme ve bellek güvenliği: 2025 sonundan itibaren AWS-LC'nin kullandığı tüm fonksiyonlar için fonksiyonel doğrulukla birlikte sabit zaman özelliğinin HOL Light ispatları da bulunmaktadır.

Bayt düzeyinde doğrulama gerçek object dosyalarına karşı yapılır; derleyici veya assembler varsayımı yoktur. Bu yaklaşım HACL*'ın C ile derleyici arasındaki boşluğunu kapatır.

Kanıtlanmayanlar şunlardır: spesifikasyon hataları, yani formülün kendisinin yanlış olabilmesi; donanımın bu komutları gerçekten sabit zamanlı yürüttüğü, ki belge bunun garanti edilemeyeceğini açıkça söyler; eşzamanlılık, çünkü model sıralı, tek çekirdekli ve kullanıcı modundadır; Spectre sınıfı spekülatif yürütme; fiziksel hata enjeksiyonu.

Dört boşluk kategorisi tanımlanmıştır. A kategorisi spesifikasyondur: A1 fonksiyonel spec doğruluğu, A2 önkoşullar, A3 sabit zaman (artık kanıtlıdır) ve A4 bellek güvenliği (artık kanıtlıdır). B kategorisi model sadakatidir: ISA model hataları, ELF loader ve atlanan özellikler olan cache, interrupt ve sanal bellek. C kategorisi ispat altyapısıdır: HOL Light kernel ve OCaml runtime hataları; Candle ve HOLTrace ile azaltılmaktadır. D kategorisi entegrasyondur: 64 bit, little-endian ve hizalama varsayımları, C header ile assembly arayüz uyumsuzlukları ve çağıran tarafın önkoşul ihlalleri.

### 6.3 mlkem-native

AWS'nin FIPS 203 implementasyonudur. C bellek ve tip güvenliği için CBMC, assembly doğruluğu için HOL Light kullanır. Yapılandırılmış bir SOUNDNESS.md yayımlar (github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md).

Kobeissi'nin karşılaştırması (Tablo 9):

| Boyut | AWS-LC Verification | libcrux |
|---|---|---|
| Kapsam iddiası | AWS libcrypto'nun bölümleri | Formel doğrulanmış kripto kütüphanesi |
| Caveat dokümantasyonu | Yirmi altı adlandırılmış caveat ve yapılandırılmış soundness dokümanları | Manuel `verification_status.md`, caveat yok |
| CI'da ispatlar | Her push ve PR'da, beş paralel iş | PR'da lax; tam doğrulama yalnızca zamanlanmış; yavaş modüller hiç doğrulanmıyor |
| Admit edilen ispatlar | `do_prove` varsayılan olarak true; fonksiyon başına açık `unsafe_assume_spec` | `ADMIT_MODULES` ve otomatik admit edilen `SLOW_MODULES`; lax-mod kaçış kapısı |

---

## 7. RustCrypto ekosistemi, ring, aws-lc-rs ve dalek

### 7.1 RustCrypto'nun formel doğrulama duruşu

Kısa cevap: yoktur. RustCrypto organizasyonunun README'sinde, `hashes` veya `elliptic-curves` README'lerinde formel doğrulamaya dair hiçbir iddia veya politika bulunamamıştır (8 Eylül 2026). Yaklaşımları saf Rust, `#![forbid(unsafe_code)]`, `subtle` ile en iyi çaba sabit zamanlılık, `zeroize` ile bellek temizleme ve seçici üçüncü taraf denetimleridir.

### 7.2 Denetimler

Bulunabilen tek somut denetim NCC Group'un Şubat 2020'de MobileCoin sponsorluğunda yaptığı denetimdir. Kapsam `aes-gcm` ve `chacha20poly1305` crate'leridir. Efor iki danışman ve beş kişi-gündür. Sonuçta önemli bir bulgu çıkmamış, zafiyet bulunmamış ve performans iyileştirme önerileri yapılmıştır (research.nccgroup.com, 26 Şubat 2020; GitHub issue github.com/RustCrypto/AEADs/issues/87).

Her iki crate'in README'si bu denetime atıf yapar ve NCC Group tarafından bir güvenlik denetiminden geçtiklerini, önemli bir bulgu çıkmadığını belirtir.

Sabit zaman iddiası her iki README'de şöyledir (8 Eylül 2026): implementasyonlar ya donanım intrinsic'lerine dayanır (x86 ve x86_64'te AES-NI, CLMUL ve AVX2) ya da yalnızca sabit zamanlı çarpma yapan işlemcilerde sabit zamanlı olan taşınabilir bir implementasyon kullanır. Caveat şudur: bu implementasyon değişken zamanlı çarpma işlemi olan işlemcilerde kullanıma uygun değildir; bazı 32 bit PowerPC CPU'lar ve ARM olmayan bazı mikrodenetleyiciler çarpımı sıfırla veya birle kısa devre yapabilmektedir.

Derleyici ve LLVM kaynaklı zamanlama değişkenliği bu bölümlerde ele alınmamaktadır.

Diğer crate'ler için denetim bulunamamıştır: `argon2`, `sha2`, `hmac`, `p256`, `rsa`, `ed25519-dalek`. Yokluk kanıtlanmamıştır; yalnızca bulunamamıştır.

### 7.3 `subtle` ve sınırları

crates.io verisi: v2.6.1, 682.501.354 indirme, son 90 günde 155.010.763, son güncelleme 24 Haziran 2024, yani iki yıldan uzun süre önce, BSD-3-Clause.

Dokümantasyona göre (docs.rs/subtle/latest/subtle/, 8 Eylül 2026) crate bir en iyi çaba denemesini temsil eder, çünkü yan kanallar nihayetinde yalnızca yazılımın değil, üzerinde çalıştığı donanım dahil dağıtılmış kriptografik sistemin bir özelliğidir. Dokümantasyon kullanımın kullanıcının kendi riskinde olduğunu belirtir.

Garanti edemedikleri şudur: derleyiciler bit düzeyi işlemleri koşullu atama olarak tanıyıp branch'e geri optimize edebilir. Crate bunu volatile read tabanlı bir optimizasyon bariyeriyle engellemeye çalışır, ancak bu kesinlik değil en iyi çabadır.

> **Argus için.** `subtle::ConstantTimeEq` kullanılır çünkü alternatifi yoktur; ancak bunun formel bir garanti olmadığı, yalnızca LLVM'i engelleme denemesi olduğu bilinmelidir. Kritik karşılaştırmalar için ek olarak ctgrind ve Valgrind testi eklenir (8. bölüm).

### 7.4 `zeroize`

v1.9.0, 672.831.052 indirme, son 90 günde 168.883.175, güncelleme 12 Haziran 2026, MSRV 1.85, Apache-2.0 veya MIT. Aktif bakımdadır. Formel doğrulama iddiası yoktur; `core::ptr::write_volatile` ve compiler fence ile çalışır.

### 7.5 `ring`, 2026 durumu

crates.io'da son sürüm 0.17.14'tür ve 11 Mart 2025 tarihlidir. Sonrasında 8 Eylül 2026 itibarıyla 18 aydır yeni sürüm çıkmamıştır. Toplam 719.974.964 indirme, son 90 günde 151.965.941 indirme almıştır. MSRV 1.66.0'dır. Lisansı Apache-2.0 ve ISC'dir. Açıklaması hâlâ projeyi bir deney olarak tanımlar.

RUSTSEC-2025-0007 advisory'si ring'in bakımsız olduğunu bildirmiştir; bildirim 20 Şubat 2025, yayın 21 Şubat 2025, son değişiklik 6 Mart 2025 tarihlidir. Durumu geri çekilmiştir. Gerekçe zinciri şudur: Brian Smith süresiz ara verdiğini duyurmuş, rustls ekibine erişim verilmiş ve güvenlik bakımı taahhüt edilmiş, son güncellemeye göre durum aşağı yukarı eskiye dönmüş ve özellikle yalnızca güvenlik bakımı ile sınırlı kalmamıştır (rustsec.org/advisories/RUSTSEC-2025-0007.html, 8 Eylül 2026).

Depo aktivitesi 2026'da canlıdır; son commit'ler 22 Temmuz 2026, 15 Temmuz 2026 (dört adet) ve 30 Haziran 2026 (beş adet, aralarında ECDSA imzalama için FIPS 186-5'e atıf) tarihlidir (github.com/briansmith/ring/commits/main, 8 Eylül 2026).

0.16.20 ve öncesi tamamen bakımsızdır.

ring doğrulanmış kod kullanmamaktadır: BoringSSL ve OpenSSL'den türetilmiş C ve assembly kodu kullanır ve fiat-crypto'yu doğrudan bağımlılık olarak almaz. Ancak hax makalesi (ePrint 2025/142) Crux-MIR'ın ring'in SHA-1 ve SHA-2 implementasyonlarını hacspec spesifikasyonlarına karşı doğruladığını belirtir; bu ring'in kendi doğrulama çabası değil, üçüncü taraf araştırmadır.

> **Argus için değerlendirme.** ring yarı terk edilmiş ancak canlı bir durumdadır. 18 aydır sürüm çıkmaması bir risk sinyalidir. Yeni bir projede birincil seçenek olmamalıdır.

### 7.6 `aws-lc-rs`

crates.io verisi: v1.18.1, 1 Eylül 2026, 214.910.906 indirme, son 90 günde 78.871.640 indirme, MSRV 1.71.0, lisans ISC ve Apache-2.0 veya ISC.

Crate ring 0.16 API'siyle uyumludur ve drop-in replacement hedefler (github.com/aws/aws-lc-rs). FIPS tarafında `aws-lc-fips-sys` akredite bir laboratuvarda FIPS validasyon testini tamamlamış ve NIST sertifikasyonuna sunulmuştur; durum NIST CMVP listesinde takip edilmektedir. `fips` özelliği AWS-LC-FIPS 4.x'e bağlanır (docs.rs/aws-lc-rs/latest/aws_lc_rs/, 8 Eylül 2026). Formel doğrulama crate dokümantasyonunda doğrudan anılmaz, ancak altında yatan AWS-LC'nin doğrulanmış bileşenleri miras alınır.

JWT için desteklenen imza algoritmaları (docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html, 8 Eylül 2026): RSA PKCS#1 v1.5 (RS256, RS384, RS512) hem imzalama hem doğrulama için (`RSA_PKCS1_SHA256/384/512` imza, `RSA_PKCS1_2048_8192_SHA256/384/512` doğrulama); RSA-PSS (PS256, PS384, PS512) hem imzalama hem doğrulama için (`RSA_PSS_SHA256/384/512`, `RSA_PSS_2048_8192_SHA256/384/512`); ECDSA P-256, P-384 ve P-521 hem imzalama hem doğrulama için, ASN.1 DER ve sabit uzunluk formatlarıyla; Ed25519 hem imzalama hem doğrulama için; ML-DSA-44, 65 ve 87 hem imzalama hem doğrulama için. Anahtar boyutu kısıtları RSA doğrulamada 1024-8192, 2048-8192 ve 3072-8192 aralıklarıdır.

Dolayısıyla `aws-lc-rs` Argus'un JWT ihtiyaçlarının tamamını tek başına karşılamaktadır, RS256 dahil.

### 7.7 dalek ailesi

`curve25519-dalek` 5.0.0 (6 Temmuz 2026), 249.213.034 indirme, son 90 günde 57.755.858, MSRV 1.85.0, BSD-3-Clause. Backend'leri `serial`, `fiat` (formel doğrulanmış, manuel seçim), `simd` (AVX2) ve `avx512`'dir (IFMA).

`ed25519-dalek` 3.0.0 (6 Temmuz 2026), 205.163.505 indirme, MSRV 1.85, BSD-3-Clause. Bağımlılıkları `curve25519-dalek ^5.0.0`, `sha2 ^0.11` ve `subtle ^2.3`'tür.

### 7.8 Argon2: doğrulanmış implementasyon yok

crates.io'da RustCrypto'nun `argon2` crate'i v0.6.0 sürümündedir (27 Ağustos 2026), 50.939.882 indirme ve son 90 günde 18.352.369 indirme almıştır, MSRV 1.85'tir ve lisansı MIT veya Apache-2.0'dır. Özellikleri `kdf`, `password-hash`, `rayon` ve `zeroize`'dır.

README'de veya crate dokümantasyonunda denetim bilgisi, formel doğrulama iddiası veya yan kanal tartışması yoktur (docs.rs/argon2/latest/argon2/, 8 Eylül 2026); yalnızca Argon2i'nin yan kanal saldırılarına direnecek biçimde optimize edildiği gibi algoritma seviyesi açıklamalar bulunur. crates.io'da doğrulanmış parola hash implementasyonu aramaları hiçbir sonuç döndürmemiştir (8 Eylül 2026). HACL*'ta, libcrux'ta ve aws-lc-verification'da Argon2 yoktur. Alternatifler `rust-argon2` 3.0.0 (17 Temmuz 2025, 21 milyon indirme) ve `argon2-kdf` 1.7.1'dir (C referans implementasyonuna sarmalayıcı).

**Sabit zaman endişesi.** Argon2id'in ikinci yarısı tasarım gereği veri bağımlı bellek erişimi yapar; bu GPU ve ASIC direnci içindir. Parola hash'leme tehdit modelinde kabul edilmiş bir tavizdir, ancak aynı makinede kod çalıştırabilen bir saldırgan için cache timing yüzeyi oluşturur. Argon2i veri bağımsızdır ancak daha zayıf TMTO direnci sunar. OWASP hâlâ Argon2id önermektedir.

> **Argus için sonuç.** Parola hash'leme formel doğrulama hikâyesinin kapsamı dışında kalacaktır ve bu açıkça belgelenmelidir. Azaltıcı önlemler sabit parametreler (m, t, p), `zeroize`, parola işlemlerinin ayrı bir süreç veya thread havuzunda izole edilmesi ve `dudect-bencher` ile ctgrind kullanarak en azından karşılaştırma yollarının sabit zamanlı olduğunun test edilmesidir.

---

## 8. Sabit zaman doğrulama: Rust'ta 2026'da ne mümkün

### 8.1 Araç envanteri

Referans tarama: neuromancer.sk/article/26 (30 Ocak 2021), "The state of tooling for verifying constant-timeness of cryptographic implementations".

| Araç | Yıl | Tip | Yöntem | Rust'ta kullanılabilir mi |
|---|---|---|---|---|
| ct-verif | 2015 | Statik | LLVM IR ve SMT; sound ve complete | Teorik olarak LLVM IR üzerinden mümkündür ancak Rust entegrasyonu yoktur ve kullanımı zordur |
| FlowTracker | 2016 | Statik | Program bağımlılık grafiği; sound ancak incomplete | Hayır |
| SideTrail | 2018 | Statik | Zaman dengeli implementasyon doğrulaması; Amazon s2n'de kullanılmıştır | Hayır; C içindir |
| FaCT | 2019 | DSL | Sabit zamanlı kod yazmak için ayrı dil | Kod tabanını yeniden yazmayı gerektirir |
| Binsec/Rel | 2020 | Statik | İkili seviyede ilişkisel sembolik yürütme; derleyici kaynaklı sızıntıları yakalar; sound ve complete | Evet; dil bağımsızdır ve derlenmiş binary üzerinde çalışır |
| ctgrind ve TIMECOP | 2010 ve 2020 | Dinamik | Valgrind memcheck; gizli veri undefined işaretlenir | Evet; en pratik yoldur |
| dudect | 2016 | Dinamik | Welch t-testi ile istatistiksel zamanlama analizi | Evet; `dudect-bencher` crate'i vardır |
| MicroWalk | 2018 | Dinamik | DBI ve karşılıklı bilgi analizi | Kısmen |
| DATA | 2018 ve 2020 | Dinamik | Bellek erişim izleri ve GUI | Kısmen |
| ct-fuzz | 2019 | Dinamik | Self-composition ile fuzzing | Hayır |

Makalenin çarpıcı sonucu 2021 tarihlidir ancak 2026'da hâlâ büyük ölçüde geçerlidir: araç bolluğu vardır, ancak hiçbiri kendilerini tanıtan makalelerin dışında otomatik biçimde kullanılıyor görünmemektedir. Yalnızca dört açık kaynak kripto kütüphanesi bunları CI'da kullanmaktaydı.

### 8.2 2026'da Rust'ta pratik olarak çalışan yol

**Valgrind ve ctgrind yolu, en iyi seçenek.** `crabgrind` v0.3.1 (20 Temmuz 2026, 899.848 indirme) Rust'tan Valgrind Client Request arayüzü sağlar. libcrux'un `crates/utils/ctgrind-test/` deseni şöyledir: gizli veri `mark_memory` ile undefined işaretlenir, işlem çalıştırılır ve Valgrind undefined bit'lerin adres üretiminde, kontrol akışı kararında veya syscall parametresinde kullanılmasını raporlar. `libcrux-secrets` crate'i (`--cfg valgrind_ct_test` ve `check-secret-independence`) bunu tip sistemiyle otomatikleştirir. Sınırı kendi ifadeleriyle şudur: bu yöntem değişken zamanlı komutlar veya cache yan kanalları gibi diğer yan kanalları kontrol etmez. macOS ve Apple Silicon'da Valgrind çalışmadığı için Docker gerekir.

**dudect istatistiksel testi.** `dudect-bencher` v0.7.0 (23 Mart 2026, 191.096 indirme) CI'da çalıştırılabilir; kesinlik vermez ancak regresyon dedektörü olarak iyidir.

**Tip seviyesi gizli bağımsızlık disiplini.** `libcrux-secrets` v0.0.6 (2.744.096 indirme) `u8`'i `U8`'e, `i16`'yı `I16`'ya çevirir ve `classify()` ile `declassify()` üzerinden açık geçişler tanımlar. Yakaladıkları gizli karşılaştırma üzerinde dallanma, gizli indeksle dizi erişimi ve `div` ile `mod` gibi sabit zamanlı olmayan işlemlerdir. Sınırı kendi ifadesiyle katı derleme zamanı garantisi vermemesidir; typechecker uyarı üretir, garanti değildir. Ayrıca crate'in kendisi `pre-verification` statüsündedir. Kavramsal olarak HACL*'ın Low* gizli bağımsızlık tip sisteminin Rust'a taşınmış hâlidir.

**Charon tabanlı taint-checker.** Charon makalesi (arXiv:2410.18042, CAV 2025) kripto kodu için bir taint-checker tanımlar; KyberSlash benzeri bir açığı 10 saniyenin altında bulur ve CI hattında kullanılmaya elverişlidir. Bağımsız bir crate olarak yayımlanıp yayımlanmadığı doğrulanamamıştır.

**hax ve F* ile kaynak seviyesi gizli bağımsızlık.** En güçlü garantidir ancak en yüksek maliyetlidir: kodun hax'in Rust alt kümesinde yazılmasını (`&mut T` dönüş tipi yasağı gibi kısıtlarla) ve F* ispatlarının yazılmasını gerektirir.

**Binsec/Rel, ikili seviye.** ACM TOPS 2022 ve arXiv:2209.01129. Derleyici kaynaklı sızıntıları yakalayan tek pratik yoldur ve `subtle`'ın LLVM'in optimize edip branch'e çevirebileceği endişesini doğrudan test eder. Rust'a özgü değildir ve derlenmiş binary'de çalışır; küçük ve sabit zaman kritik çekirdekler için harness yazmak gerekir. 2026'da bazı Rust build hatlarının checkct modunu kullandığı belirtilmektedir ancak spesifik proje doğrulanamamıştır.

**Genel Rust doğrulama araçları.** Bunlar kriptoya özgü değildir. `kani-verifier` v0.67.0 (16 Ocak 2026, 566.714 indirme) AWS'nin CBMC tabanlı bit hassas model checker'ıdır; sabit zaman için değildir ancak panik yokluğu ve overflow için kullanışlıdır. `creusot-contracts` v0.8.0 (9 Aralık 2025, 14.220 indirme) Why3 tabanlı dedüktif doğrulama sağlar.

### 8.3 2026'nın yeni araçları

DALC-CT, "Dynamic Analysis of Low-Level Code Traces for Constant-Time Verification" başlığıyla arXiv:2604.16832'de yayımlanmıştır (2026); içeriği okunmamıştır.

Crucible (Symbolic Software, 23 Mart 2026) ML-KEM ve ML-DSA için bir uygunluk test çerçevesidir. Rust'ta yazılmıştır, JSON satır protokolü kullanır ve 15 implementasyon için harness sağlar (Rust, Go, C, C++20, Java). 129 test içerir; ML-KEM için 78, ML-DSA için 51. Gerçek denetim bulgularından türetilmiş hata sınıflarını kodlar: off-by-one yuvarlama, ölü koda derlenen sınır kontrolü ve şifre çözme yolundan çıkarılmış ters NTT. AWS-LC, Go stdlib, CIRCL ve libcrux dahil büyük implementasyonlarda iki uygunluk boşluğu bulmuş, güvenlik açığı bulmamıştır; libcrux tüm ilgili testleri geçmiştir (symbolic.software/blog/2026-03-23-crucible/).

---

## 9. Argus için değerlendirme ve öneri

### 9.1 İhtiyaçtan doğrulanmış seçeneğe eşleme

| Argus ihtiyacı | Doğrulanmış seçenek | Durum | Notlar |
|---|---|---|---|
| JWT HS256, HS384, HS512 | `libcrux-hmac` 0.0.8 | verified-hacl | HACL* HMAC'tir ve en güvenli seçimdir |
| JWT EdDSA (Ed25519) | `libcrux-ed25519` 0.0.9 | verified-hacl | V6 (çift clamping) düzeltilmiştir. Aynı HACL* kodu NSS'te de üretimdedir |
| JWT ES256 (P-256) | `libcrux-ecdsa` 0.0.8 | verified-hacl, ancak dikkat | 90 günde 721 indirme almıştır ve pratikte test edilmemiştir. low-S normalizasyonu yoktur; JWS için RFC 7515 bunu gerektirmediğinden sorun değildir, ancak ES256K veya blockchain entegrasyonu düşünülüyorsa sorundur |
| JWT PS256, PS384, PS512 (RSA-PSS) | `libcrux-rsa` 0.0.8 | verified-hacl, ancak dikkat | HACL* `Hacl.RSAPSS` temellidir. SHA-256, 384 ve 512; 2048-8192 bit. 90 günde 582 indirme almıştır. Anahtar üretimi yoktur |
| JWT RS256, RS384, RS512 (PKCS#1 v1.5) | Yoktur | Boşluk | libcrux ve HACL*'ta PKCS#1 v1.5 imza yoktur. `aws-lc-rs` (s2n-bignum aritmetiği HOL Light ile doğrulanmıştır) veya RustCrypto `rsa` (0.10.0-rc.18, hâlâ RC) gerekir. OIDC istemcilerinin ezici çoğunluğu RS256 bekler |
| SHA-2 (JWT digest, JWKS thumbprint) | `libcrux-sha2` 0.0.8 | verified-hacl | — |
| HKDF (anahtar türetme) | `libcrux-hkdf` 0.0.8 | verified-hacl | — |
| JWE: ChaCha20-Poly1305 | `libcrux-chacha20poly1305` 0.0.9 | verified-hacl | XChaCha20Poly1305 sarmalayıcısı doğrulanmamıştır; 24 baytlık nonce gerekiyorsa bu yol doğrulama dışıdır |
| JWE: AES-GCM (A128GCM, A256GCM) | `libcrux-aes` | pre-verification | Ayrıca tag karşılaştırması 15 Temmuz 2026'ya kadar sabit zamanlı değildi (PR #1528). EverCrypt'te doğrulanmış AES-GCM vardır ancak yalnızca x64 Vale assembly'dir ve Rust'tan erişilebilir değildir. Alternatif `aws-lc-rs`'tir; SAW ile CI'da doğrulanmış AES-GCM-256 sunar, ancak sınırlıdır: yalnızca 12 baytlık IV, 16 baytlık tag, tam blok ve AAD doğrulanmamıştır |
| X25519 (hibrit iş) | `libcrux-curve25519` 0.0.8 | verified-hacl | — |
| ML-KEM (PQ hibrit) | `libcrux-ml-kem` 0.0.10 | Kısmî verified (hax) | Portable backend tamdır, AVX2 kısmîdir, NEON hiç doğrulanmamıştır; ARM64 sunucular Graviton ve Apple Silicon geliştirme makineleridir. `ind_cpa` ve `sampling` admit edilmiştir. Signal, NSS ve OpenSSH üretimdedir |
| Argon2 (parola hash) | Yoktur | Boşluk | Hiçbir dilde doğrulanmış Argon2 bulunamamıştır. RustCrypto `argon2` 0.6.0 denetimsiz olarak kullanılır |
| CSPRNG | `libcrux-hmac-drbg` | pre-verification | `getrandom` 0.4.3 işletim sistemi entropisi kullanır (Linux'ta `getrandom(2)`, macOS'ta `getentropy`, Windows'ta `ProcessPrng`); doğrulanmamıştır ancak işletim sistemine devreder ve bu doğru mimaridir |
| Sabit zamanlı karşılaştırma | `subtle` 2.6.1 | Dikkat gerekir | En iyi çabadır, kullanıcının kendi riskindedir ve iki yıldır güncellenmemiştir. Alternatifi `libcrux-secrets`'tir ve o da pre-verification'dır |
| SHA-3 ve SHAKE | `libcrux-sha3` | pre-verification | HACL*'ta doğrulanmış SHA-3 C kodu vardır ve NSS bunu kullanır; ancak libcrux'un Rust SHA-3'ü ayrı bir hax hedefli implementasyondur ve doğrulanmamıştır. Ayrıca 0.0.5'te AVX2 SHAKE-256'da out-of-bounds indeksleme düzeltilmiştir |
| RSA anahtar üretimi (JWKS rotasyonu) | libcrux'ta yoktur | Boşluk | `aws-lc-rs` veya `rsa` crate'i gerekir |

### 9.2 Üç somut mimari seçenek

**Seçenek A: azami doğrulama, kabul edilen boşluklarla.**

```
HS256      → libcrux-hmac              verified
EdDSA      → libcrux-ed25519           verified
ES256      → libcrux-ecdsa             verified (az kullanılmış)
PS256      → libcrux-rsa               verified (imza ve doğrulama; keygen ayrı)
SHA-2      → libcrux-sha2              verified
HKDF       → libcrux-hkdf              verified
JWE        → libcrux-chacha20poly1305  verified (AES-GCM yerine)
X25519     → libcrux-curve25519        verified
ML-KEM     → libcrux-ml-kem            kısmî
Argon2     → RustCrypto argon2         doğrulanmamış
RNG        → getrandom                 doğrulanmamış (işletim sistemine devir)
CT karşılaştırma → subtle              en iyi çaba
RSA keygen → aws-lc-rs veya rsa        doğrulanmamış
RS256      → desteklenmez (yalnızca PS256, ES256, EdDSA, HS256)
```

Artısı gerçekten en yüksek doğrulama oranıdır ve en güvenli IdP iddiası savunulabilir hâle gelir. Eksisi RS256'nın bulunmaması ve çoğu mevcut OIDC istemcisinin bağlanamamasıdır; ayrıca libcrux pre-release olduğu için (`<0.1`) API kırılmaları olabilir, üretim için bakımcıyla konuşulması istenmektedir ve `libcrux-ecdsa` ile `libcrux-rsa` neredeyse hiç kullanılmamaktadır.

**Seçenek B: aws-lc-rs tabanlı, pragmatik. Önerilen seçenektir.**

```
Tüm JWT imza ve doğrulama (RS256, PS256, ES256, ES384, EdDSA, HS256) → aws-lc-rs 1.18.1
JWE AES-GCM           → aws-lc-rs (SAW ile CI'da doğrulanmış, caveat'lı)
JWE ChaCha20-Poly1305 → aws-lc-rs veya libcrux
Argon2                → RustCrypto argon2
RNG                   → aws-lc-rs SystemRandom veya getrandom
CT karşılaştırma      → aws-lc-rs constant_time veya subtle
ML-KEM                → aws-lc-rs veya libcrux-ml-kem
```

Artıları tek bağımlılık olması, FIPS 140-3 yolunun bulunması (sertifikasyon NIST'e sunulmuştur), tam algoritma kapsamı, aktif bakım (1 Eylül 2026 sürümü), s2n-bignum aritmetiğinin HOL Light ile hem fonksiyonel doğruluk hem sabit zaman için kanıtlanmış olması (RSA, P-256, P-384, P-521, X25519, Ed25519), ispatların her push ve PR'da CI'da çalışması, yirmi altı adlandırılmış caveat ile dürüst dokümantasyon ve `jsonwebtoken` 11'in `CryptoProvider` ile bunu zaten desteklemesidir.

Eksileri C ve assembly bağımlılığı olması, yani saf Rust olmaması; doğrulamanın bölümler seviyesinde kalması; üst seviye protokol mantığının doğrulanmamış olmasıdır.

**Seçenek C: katmanlı hibrit, en güçlü ancak en karmaşık.**

```
Varsayılan sağlayıcı: aws-lc-rs (tam kapsam, FIPS, RS256 dahil)
İsteğe bağlı yüksek güvence profili: libcrux
  → HS256, EdDSA, ES256, PS256, SHA-2, HKDF, ChaCha20-Poly1305
Argon2: RustCrypto (her iki profilde)
Çalışma zamanında hangi implementasyonun kullanıldığı loglanır ve metriklenir
Her iki yolda ortak KAT (Known Answer Test) ve differential test paketi koşar
```

Artısı RS256 desteklenirken kritik yolların formel doğrulanmış olduğu iddiasının da korunabilmesidir. Cross-implementation differential testing, yani iki bağımsız kod tabanının karşılaştırılması, tek başına büyük bir güvenlik kazancıdır; nitekim Kobeissi'nin bulduğu hataların çoğu bu yöntemle yakalanırdı. Eksisi iki kat bakım yükü, iki kat saldırı yüzeyi ve sürüm yönetimi karmaşıklığıdır.

### 9.3 Argus'un doğrulama iddiasını nasıl kurması gerektiği

Kobeissi'nin R1 ile R5 arası tavsiyeleri Argus'a doğrudan uygulanabilir.

**R1: makine okunur doğrulama manifestosu.** Her sürümde hangi kod yolunun, hangi özelliğe karşı, hangi hedef mimaride doğrulandığı belirtilir. Bu elle yazılmaz, build sisteminden üretilir. AWS'nin `s2n-bignum/SOUNDNESS.md` ve `mlkem-native/SOUNDNESS.md` dosyaları model alınabilir.

**R2: ispatlar her commit'te CI'da koşar.** libcrux'un `ADMIT_MODULES` deseni bir doğrulama kusuru sayılmalıdır. Argus doğrudan ispat yazmasa bile bağımlılıklarının doğrulama durumu CI'da kontrol edilmelidir; örneğin libcrux sürüm yükseltmelerinde `verification_status.md` diff'lenmelidir.

**R3: tactic'lerde lax-mod kaçış kapısı bulunmaz.**

**R4: net kapsam iletişimi.** Niteliksiz "formally verified" ifadesi, doğrulama sınırının CompCert veya seL4'te olduğu gibi donanım seviyesine indirildiği sistemlere saklanmalıdır.

| | İfade |
|---|---|
| İzin verilen | JWT imzalama ve doğrulama primitifleri HACL*'tan türetilmiş, F* ile bellek güvenliği, fonksiyonel doğruluk ve gizli bağımsızlık için doğrulanmış kod kullanır; parola hash'leme, protokol mantığı ve derleme süreci doğrulama sınırının dışındadır. |
| İzin verilmeyen | Argus formel olarak doğrulanmıştır (niteliksiz biçimde). |

**R5: savunma derinliği.** Geleneksel pratikler — kod incelemesi, spesifikasyon uyum denetimi, çapraz platform testi ve fuzzing — formel doğrulamanın bugünkü uygulanışıyla yakalayamadığı hata kategorilerini yakalar.

Kobeissi'nin bulgularından çıkan somut Argus test listesi şudur.

**Çapraz platform determinizm testi (V1).** Aynı deterministik girdiyle x86-64, ARM64 ve `RUSTFLAGS="-C target-feature=-avx2"` altında aynı çıktı alınmalıdır. CI'da zorunludur.

**Çapraz backend durum uyumluluğu (V2).** Incremental veya streaming API kullanılıyorsa bir backend'de başlatıp diğerinde bitirmek test edilir.

**Düşük mertebeli nokta ve all-zero paylaşılan sır kontrolü (V3).** X25519 çıktısının sıfır olmadığı kendi kodumuzda kontrol edilir, kütüphaneye güvenilmez.

**Nonce ve sequence taşma testi (V4).** Sayaçların gerçekten taştığı senaryo release build'de test edilir.

**Panik denemesi (V7).** Bozuk ciphertext ve imza ile fuzzing yapılır, `.unwrap()` kullanımları avlanır ve kripto modüllerinde `#![deny(clippy::unwrap_used)]` uygulanır.

**FIPS ve RFC uygunluk testleri (V8, V9).** Wycheproof, NIST CAVP ve ACVP vektörleri ile ML-KEM veya ML-DSA kullanılacaksa Crucible koşulur.

**ctgrind ve Valgrind sabit zaman testi (8. bölüm).** En azından JWT imzalama, HMAC doğrulama ve parola karşılaştırma yollarında uygulanır.

### 9.4 Kalan riskler

| Risk | Şiddet | Azaltma |
|---|---|---|
| RS256 için doğrulanmış implementasyon yoktur | Yüksek; uyumluluk riski | `aws-lc-rs` kullanılır; ya da yeni istemciler PS256, ES256 veya EdDSA'ya zorlanır ve RS256 legacy modda tutulur |
| Argon2 doğrulanmamıştır | Orta | Kaçınılmazdır. Denetlenmiş parametreler, `zeroize`, izolasyon ve sabit zaman testi uygulanır |
| AES-GCM (JWE) libcrux'ta doğrulanmamış, aws-lc-rs'te sınırlı doğrulanmıştır | Orta | JWE için ChaCha20-Poly1305 varsayılan yapılır; AES-GCM yalnızca uyumluluk için tutulur |
| libcrux pre-release'dir (`<0.1`) ve API kırılabilir | Orta | Tam sürüm pinlenir (`=0.0.9`), `Cargo.lock` commit edilir, kendi KAT paketimiz tutulur ve sürüm yükseltmelerinde diff alınır |
| CE Labs'ın zafiyet ifşa süreci sorunludur (Şubat 2026) | Orta | Kendi test ve fuzz katmanımız kurulur; RUSTSEC ile GitHub advisory'leri izlenir; `cargo audit` ve `cargo deny` CI'da koşar |
| NEON ve ARM64 yolunda ML-KEM ispatları hiç kontrol edilmemiştir | Orta; post-quantum kullanılırsa | ARM64'te portable backend zorlanır, ya da mlkem-native veya aws-lc-rs kullanılır |
| `ring` 18 aydır sürümsüzdür | Düşük ve orta arası | Yeni kodda `ring` kullanılmaz; `rustls` için `aws-lc-rs` provider'ı seçilir |
| `subtle` iki yıldır güncellenmemiştir ve garanti vermez | Düşük | Alternatifi yoktur; ctgrind ile test edilir |
| Derleyici, yani LLVM, tüm HACL* ve hax garantilerinin dışındadır | Yapısal | Kabul edilir ve belgelenir. s2n-bignum'un assembly seviyesindeki ispatı bu boşluğu kapatan tek yaklaşımdır |

---

## 10. Kaynaklar

**Makaleler.**

- Kobeissi, N. *Verification Theatre: False Assurance in Formally Verified Cryptographic Libraries.* IACR ePrint 2026/192, alınma 5 Şubat 2026, son revizyon 25 Haziran 2026 — eprint.iacr.org/2026/192
- Bhargavan, Buyse, Franceschino, Letager Hansen, Kiefer, Schneider-Bensch, Spitters. *hax: Verifying Security-Critical Rust Software using Multiple Provers.* IACR ePrint 2025/142, VSTTE 2024 — eprint.iacr.org/2025/142
- Ho, Boisseau, Franceschino, Prak, Fromherz, Protzenko. *Charon: An Analysis Framework for Rust.* arXiv:2410.18042 (v2, Ocak 2025), CAV 2025 — arxiv.org/html/2410.18042v2
- Fromherz, Protzenko. *Compiling C to Safe Rust, Formalized (Scylla).* arXiv:2412.15042, OOPSLA 2026 — arxiv.org/abs/2412.15042
- Erbsen, Philipoom, Gross, Sloan, Chlipala. *Simple High-Level Code For Cryptographic Arithmetic.* IEEE S&P 2019 — jasongross.github.io/papers/2019-fiat-crypto-ieee-sp.pdf
- Bernstein ve diğerleri. *KyberSlash: Exploiting secret-dependent division timings in Kyber implementations.* IACR ePrint 2024/1049
- Daniel, Bardin, Rezk. *Binsec/Rel.* ACM TOPS 2022 — dl.acm.org/doi/10.1145/3563037

**Depolar ve dokümantasyon.** Hepsine 8 Eylül 2026'da erişilmiştir.

- github.com/hacl-star/hacl-star; hacl-star.github.io/; hacl-star.github.io/Supported.html; github.com/hacl-star/hacl-star/tree/main/code/rsapss; github.com/hacl-star/hacl-star/commits/main
- github.com/celabshq/libcrux (Readme.md, SECURITY.md, CHANGELOG.md, crates/algorithms/*/Readme.md, libcrux-ml-kem/proofs/verification_status.md, libcrux-ml-kem/proofs/fstar/extraction/Makefile; tarball ile yerel inceleme)
- github.com/cryspen/hax; hax.cryspen.com/frontend/; cryspen.com/hax-toolchain/
- github.com/mit-plv/fiat-crypto; raw.githubusercontent.com/mit-plv/fiat-crypto/master/README.md
- github.com/awslabs/aws-lc-verification; github.com/aws/aws-lc; github.com/awslabs/s2n-bignum/blob/main/SOUNDNESS.md; github.com/pq-code-package/mlkem-native/blob/main/SOUNDNESS.md
- github.com/aws/aws-lc-rs; docs.rs/aws-lc-rs/latest/aws_lc_rs/; docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html
- github.com/briansmith/ring/commits/main; github.com/briansmith/ring/discussions/2414; github.com/briansmith/ring/discussions/2450
- docs.rs/subtle/latest/subtle/; docs.rs/argon2/latest/argon2/; docs.rs/curve25519-dalek/latest/curve25519_dalek/; docs.rs/jsonwebtoken/latest/jsonwebtoken/; docs.rs/getrandom/latest/getrandom/; docs.rs/libcrux-hacl-rs/latest/libcrux_hacl_rs/; docs.rs/crate/libcrux-rsa/latest/source/src/lib.rs; docs.rs/crate/p384/latest/source/src/arithmetic/field.rs; docs.rs/crate/primefield/latest/source/src/lib.rs
- github.com/nss-dev/nss/tree/master/lib/freebl/verified; github.com/nss-dev/nss/tree/master/lib/freebl/libcrux
- github.com/torvalds/linux/blob/master/lib/crypto/curve25519-hacl64.c ve curve25519-fiat32.c
- docs.python.org/3/library/hashlib.html; github.com/python/cpython/issues/99108; commit `325e9b8ef400b86fb077aa40d5cb8cec6e4df7bb`
- cvsweb.openbsd.org/src/usr.bin/ssh/; openssh.org/txt/release-9.9 (19 Eylül 2024)
- github.com/signalapp/libsignal/blob/main/Cargo.toml
- boringssl.googlesource.com/boringssl/+/refs/heads/master/third_party/fiat/README.md
- raw.githubusercontent.com/RustCrypto/AEADs/master/aes-gcm/README.md; chacha20poly1305/README.md; github.com/RustCrypto/AEADs/issues/87
- wireguard.com/formal-verification/

**Danışma belgeleri.**

- rustsec.org/advisories/RUSTSEC-2025-0007.html (ring bakımsız; geri çekilmiştir; 21 Şubat 2025, son değişiklik 6 Mart 2025)
- rustsec.org/advisories/RUSTSEC-2025-0133.html (libcrux-intrinsics 0.0.3 ve altı, aarch64 kripto arızası; 4 Aralık 2025; GHSA-2cgv-28vr-rv6j)

**Blog ve analiz.**

- cryspen.com/post/strengths-and-limitations/ (CE Labs, 12 Şubat 2026)
- cryspen.com/post/ml-kem-implementation/ (16 Ocak 2024)
- cryspen.com/post/ml-kem-verification/
- symbolic.software/blog/2026-02-17-ce-labs-mldsa/ (17 Şubat 2026)
- symbolic.software/blog/2026-03-23-crucible/ (23 Mart 2026)
- jonathan.protzenko.fr/2024/03/20/hacl-rs.html (20 Mart 2024)
- jonathan.protzenko.fr/2024/01/05/eurydice.html (5 Ocak 2024)
- neuromancer.sk/article/26 (30 Ocak 2021)
- research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/ (26 Şubat 2020)

**Doğrulanamayanlar.** Google bughunters blog gövdesi; OpenSSH 9.9'un ML-KEM kaynağının libcrux olduğu (2026 OpenBSD CVS kaydı teyit etmekte, 2024 release notu etmemektedir); mbedTLS, Tezos ve ElectionGuard'da HACL*'ın hangi algoritmalarda ve hâlâ kullanılıp kullanılmadığı; fiat-crypto'nun Chrome trafiğinin %90'ını oluşturduğu iddiasının 2026 geçerliliği; Firefox'un fiat-crypto kullandığı iddiası, çünkü NSS kanıtı HACL*'a işaret etmektedir; "Verified Rust Monomorphization" adlı bir makalenin varlığı; Charon taint-checker'ının bağımsız bir crate olarak yayımlanıp yayımlanmadığı.
