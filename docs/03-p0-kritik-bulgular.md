# 3. P0 kritik bulgular

> `ARGUS.md` §3'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§3 §X` referansları aynı anlamda.


**Kaynak:** Formel doğrulama, doğrulanmış kripto, yan kanal, sertleştirme, tedarik zinciri ve performans araştırmalarının sentezi.

Bu dosya, yapılmazsa "en güvenli IdP" iddiasını geçersiz kılan maddeleri içerir.

---

## 0. CRA — kimlik yönetimi Sınıf I'de, steward raporlaması 11 Aralık 2027

**AB Cyber Resilience Act, Ek III'te kimlik yönetim sistemlerini açıkça sayıyor:**

> *"Identity management systems and privileged access management software... including authentication and access control readers"*

Argus **Sınıf I "önemli ürün"** kategorisinde. Bu, varsayılan öz-değerlendirmeden daha ağır bir uygunluk rejimi demek.

| Tarih | Yükümlülük |
|---|---|
| 11 Eylül 2026 | Madde 14 **manufacturer**'lar için yürürlüğe girer (aktif sömürülen açıklar → ENISA/CSIRT) |
| **11 Aralık 2027** | **Açık kaynak steward'ları** raporlama yükümlülüğüne katılır (ENISA SRP FAQ). Steward'ları Madde 14'e bağlayan hüküm Madde 24(3)'tür ve Madde 24 bu tarihte uygulanmaya başlar. Arkasında tüzel kişi yoksa yükümlülük hiç doğmaz; monetize edilmeyen FOSS zaten kapsam dışı |
| 11 Aralık 2027 | SBOM (Ek I Böl. II.1: *"at the very least the top-level dependencies"*), koordineli açık bildirim politikası, destek süresi tanımı, teknik dokümantasyon (Ek VII), CE işareti |

**Şimdi yapılacak:** güvenlik iletişim adresi, `security.txt`, `SECURITY.md`, bildirim akış şeması. Madde 24 §1'in istediği "documented in a verifiable manner" güvenlik politikası zaten iyi mühendisliktir — tarihi beklemeye gerek yok.

⚠️ Doğrulanamayan: CRA yürürlük tarihi çelişkisi (Komisyon 10 Ara 2024, Wikipedia 12 Kas 2024) — Komisyon esas alınmalı. Ek IV tam listesi çekilemedi. CEN/CENELEC JTC13 uyumlaştırılmış standartlarının durumu araştırılmadı — **harmonised standard yoksa Sınıf I için üçüncü taraf uygunluk değerlendirmesi gerekebilir.**

---

## 1. Parser derinlik sınırı — doğrudan rakipte iki High CVE

Kanidm (Rust ile yazılmış, güvenlik odaklı IdP) 2026'da bu sınıftan **iki High severity** açık aldı:

| Advisory | Tarih | CVSS | Detay |
|---|---|---|---|
| **GHSA-r5fr-9gmv-jggh** (CVE-2026-46689) | 2026-05-06 | **8.7** | SCIM filter: `?filter=` query string'inde **birkaç bin iç içe parantez (4–12 KB)** → PEG parser worker thread'in stack guard page'ini aşıyor |
| **GHSA-qcxq-75wr-5cm8** | 2026-04-30 | **8.7** | LDAP filter: *"both PEG and ASN"* parser'ı stack tüketiyor |

**Neden ölümcül:** Rust'ta stack overflow yakalanabilir bir panic değil — `std::process::abort()`. `catch_unwind` işe yaramaz. Bir tokio worker thread'inde olsa bile **tüm süreç ölür**.

**Ve daha kötüsü:** Kanidm advisory'sinden birebir —

> *"The parse runs inside axum's `Query<ScimEntryGetQuery>` extractor, **before any handler body and therefore before any ACL check**."*

Yani kimliği doğrulanmamış bir GET isteği tüm IdP'yi kapatıyor.

**Zorunlu karşı önlemler:**

```rust
const MAX_FILTER_DEPTH: u32 = 32;

fn parse_expr(input: &str, depth: u32) -> Result<Expr, ParseError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(ParseError::TooDeep);   // panic DEĞİL
    }
    // ... parse_expr(inner, depth + 1)
}
```

- [ ] Her özyinelemeli parser'da explicit depth counter (≤32)
- [ ] Derinlik aşımında `Result::Err` — asla panic, asla abort
- [ ] Her custom axum extractor'ı ayrı tehdit yüzeyi olarak modelle; auth middleware pahalı extractor'lardan **önce** çalışsın
- [ ] `serde_json` varsayılan derinlik sınırı 128'dir; **`unbounded_depth` feature'ının hiçbir bağımlılıkta açık olmadığını CI'da assert et** (Cargo feature unification tuzağı)
- [ ] `quick-xml` ≥ 0.41.0; `Event::DocType` → belgeyi reddet (XXE/billion laughs yapısal olarak kapanır)
- [ ] x509/DER için boyut limiti ≤ 8 KB + fuzz ile doğrula
- [ ] WebAuthn CBOR (kimliği doğrulanmamış registration akışı!) için boyut + derinlik kontrolü

Aynı sınıftan 2026 advisory'leri: `time` RUSTSEC-2026-0009 (Cloudflare Pingora etkilendi), `quick-xml` RUSTSEC-2026-0195 (Routinator OOM), `lopdf` RUSTSEC-2026-0187, `protobuf` RUSTSEC-2024-0437.

---

## 2. Tedarik zinciri — `Cargo.lock` kullanıcıların %90'ını kurtardı

### arrayref saldırısı, 20 Ağustos 2026

Tipo-eşkıyalık değil, **maintainer ele geçirmesi**.

| Crate | Kötü sürüm | 10 yıllık indirme |
|---|---|---|
| `arrayref` | 0.3.10 | **~245.000.000** |
| `internment` | 0.8.7 | ~14.400.000 |
| `append-only-vec` | 0.1.9 | ~4.500.000 |

**Mekanizma üç aşamalı:**
1. Meşru crate'lere `proc-macro1` bağımlılığı eklendi — *"a dependency never seen before in a decade of the package's history"*
2. `proc-macro1`'in **`build.rs`**'i dropper. JFrog: *"compiled and executed automatically during `cargo build`, `cargo check`... **including CI and rust-analyzer driven builds**"* — **editörde dosya açmak yeterli**
3. Platforma özel payload (Linux/Windows/macOS), Base64 parçalı C2, **TLS doğrulaması kasten kapalı**

Yayında kalma: **86, 90, 107 dakika.** Etki: `arrayref` 0.3.10 yalnızca **2.285 kez** indirildi — trafiğin %10'undan azı.

> **Kullanıcıların %90'ını kurtaran tek şey `Cargo.lock`'taki sabit sürümdü.**

### PolinRider crates.io'ya ulaştı — 6 Eylül 2026

RUSTSEC-2026-0280: `greentic-setup-dev`, **~27 saat** yayında. Kuzey Kore bağlantılı kampanya (npm/Packagist/Go/Chrome'da 108+ paket).

**Kritik fark: `build.rs` kullanmıyor.** VS Code'un `.vscode/tasks.json` mekanizmasını kullanıyor. Yani `cargo build`'i sandbox'lamak yetmiyor.

### 2026 kötü amaçlı crate advisory'leri

| Yıl | Sayı |
|---|---|
| 2023 | 28 |
| **2024** | **0** |
| 2025 | 14 |
| **2026** | **32** (8 Eylül'e kadar) |

### Zorunlu önlemler

- [ ] **`Cargo.lock` commit + `--locked` her yerde** (5 dakikalık iş, kanıtlanmış %90 koruma)
- [ ] **Bağımlılık cooldown ≥ 7 gün** — Renovate `minimumReleaseAge: "7 days"`. 86–107 dakikalık saldırı penceresini tamamen kapatır
- [ ] **CI derlemesi ağsız** (`cargo vendor` + `--offline`) — payload indirme adımını engeller
- [ ] **Yeni `build.rs` bağımlılığı CI'da alarm üretsin** — arrayref'in tek sinyali buydu
- [ ] **Vendored ağaçta `.vscode/`, `.devcontainer/`, `.githooks/` tara ve reddet** (PolinRider vektörü)
- [ ] GitHub Actions'ları **commit SHA ile pinle** (`@v4` değil)
- [ ] Geliştirici makinelerinde `cargo:token` **kullanma** — `cargo:macos-keychain` / `cargo:libsecret`. Düz metin token, arrayref'in muhtemel giriş vektörü

### cargo-vet gerçek kapsam (ölçüldü)

Beş büyük audit seti (google, mozilla, bytecode-alliance, zcash, embark) klonlanıp sayıldı: **1.815 farklı crate**, 5.576 audit girdisi.

⚠️ SEO blogları "14.140 crate / 58.900 versiyon" iddia ediyor — **bu rakamlar uydurma**, AI üretimi içerik.

Argus yığınının kapsamı: **%51 (sürüm-tam) – %91 (crate-adı)** arası.

**Hiç denetlenmemiş, ve tam da en kritik olanlar:**
```
argon2, sqlx, sqlx-core, sqlx-macros, sqlx-postgres, blake2,
asn1-rs, der-parser, oid-registry, simple_asn1, pem
```
Parola hash'leme + veritabanı katmanı + ASN.1 ayrıştırma. İlk elle denetim bütçesi buraya.

---

## 3. Doğrulanmış kripto — iki büyük boşluk ve bir uyarı

### libcrux durumu (kaynak koddan doğrulandı)

| Algoritma | Rozet |
|---|---|
| SHA-2, HMAC, HKDF, Ed25519, ECDSA P-256, **RSA-PSS**, X25519, ChaCha20-Poly1305, Poly1305, BLAKE2 | ✅ **verified-hacl** |
| ML-KEM, ML-DSA | ⚠️ kısmî (hax) |
| **AES-GCM / AES-CCM** | ❌ **pre-verification** |
| **SHA-3 / SHAKE** | ❌ **pre-verification** |
| **HMAC-DRBG (CSPRNG)** | ❌ **pre-verification** |

### İki kapatılamayan boşluk

1. **RS256 (RSA PKCS#1 v1.5) için doğrulanmış implementasyon YOK** — HACL*'ta yok, libcrux'ta yok. Ve OIDC istemcilerinin ezici çoğunluğu RS256 bekliyor.
2. **Argon2 için doğrulanmış implementasyon hiçbir dilde YOK.** Parola hash'leme, formel doğrulama hikâyesinin kapsamı dışında kalacak — bunu açıkça belgele.

### ⚠️ "Verification Theatre" — Kobeissi, ePrint 2026/192

libcrux/hpke-rs'te **13 zafiyet**: 9'u doğrulama sınırının dışında, **4'ü sözde doğrulanmış spec/ispat kodunun içinde**.

Nicel: ML-KEM Rust kodunun yalnızca **%58,4'ünün** ispatları gerçekten SMT çözücüye gidiyor. `ADMIT_MODULES`'ta olanlar en kritik olanlar: `Ind_cpa.fst`, `Sampling.fst` ve **tüm NEON yolu** (ARM64 = Graviton, Apple Silicon).

Ve ifşa süreci sorunlu: CE Labs raportörün GitHub hesabını **engelledi**, 4 PR'ı kapattı, sonra düzeltmeleri atıf vermeden merge etti.

**Gerçek dünya sonucu (V1, RUSTSEC-2025-0133):** ARM64'te SHA-3 bozuk → libcrux-ml-dsa v0.0.3 farklı platformlarda **farklı public key ve imza** üretiyordu. Filippo Valsorda bildirdi.

**Kullanım gerçeği:** `libcrux-ecdsa` 90 günde **721 indirme**, `libcrux-rsa` **582**. ES256 ve PS256 yolları pratikte hiç test edilmemiş.

### Karar: aws-lc-rs birincil

`aws-lc-rs` 1.18.1 (1 Eylül 2026), Argus'un JWT ihtiyaçlarının **%100'ünü** karşılıyor — RS256 dahil. Altındaki **s2n-bignum, 2025 sonundan itibaren hem fonksiyonel doğruluk hem constant-time için HOL Light ispatları** taşıyor (RSA, P-256/384/521, X25519, Ed25519) ve bytes **gerçek object dosyalarına** karşı doğrulanıyor — derleyici varsayımı yok. Bu, HACL*'ın C→derleyici boşluğunu **kapatan** tek yaklaşım.

Ve AWS'in ispatları **her push/PR'da CI'da** çalışıyor; libcrux'un slow modülleri **hiçbir otomatik sistem tarafından hiç doğrulanmadı**.

### İddia dili — Kobeissi R4

> *"'formally verified' without qualification should be reserved for systems where the verification boundary has been minimized to the hardware level, as in CompCert or seL4."*

**Argus asla niteliksiz "formally verified" dememeli.** Doğru ifade: "JWT imzalama primitifleri HACL*'dan türetilmiş doğrulanmış kod kullanır; parola hash'leme, protokol mantığı ve derleme süreci doğrulama sınırının dışındadır."

---

## 4. Sabit-zamanlı karşılaştırma — "ölçülemez" argümanı öldü

### Timeless Timing Attacks (USENIX Security 2020)

> *"On web servers hosted over HTTP/2, we find that a timing difference as small as **100ns can be accurately inferred from the response order of approximately 40,000 request-pairs**. The smallest timing difference that we could observe in a traditional timing attack over the Internet was 10µs, **100 times higher**."*
>
> *"completely unaffected by network conditions, **regardless of the distance** between the adversary and the victim server."*

İki HTTP/2 isteği tek TCP paketinde birleşiyor → eşzamanlı işleniyor → yanıt sırası ölçülüyor. Ağ jitter'ı tamamen eleniyor.

**Argus HTTP/2 sunuyorsa, "tek haneli nanosaniye ölçülemez" argümanı geçersizdir.**

### Rust'ın kendi itirafı

`std::hint::black_box` dokümantasyonu, birebir:

> *"**This also means that this function does not offer any guarantees for cryptographic or security purposes.** This limitation is not specific to `black_box`; **there is no mechanism in the entire Rust language that can provide the guarantees required for constant-time cryptography.**"*

### Ve bu teorik değil

**RUSTSEC-2026-0003 / CVE-2026-23519** (14 Ocak 2026), `cmov` crate'i — tam da bu iş için yazılmış, `black_box`'ı bilinçli kullanan crate — **ARM32'de branch üretti**:
```asm
bne  .LBB0_2      ; Branch if Not Equal
```
v0.4.4 taktiksel `black_box` yamaladı; **v0.4.5 `asm!` ile yeniden yazıldı**. `black_box` çalışmıyor, `asm!` çalışıyor.

### Zorunlu yerler

| Yer | Not |
|---|---|
| Opak token DB araması | **Asıl çözüm hash'lemek** — `SHA-256(token)` sakla; DB indeks karşılaştırması da sızdırır |
| HMAC / JWS imza doğrulama | Klasik |
| **TOTP kodu** | Gerçek CVE: `totp-rs` RUSTSEC-2022-0018 |
| client_secret | Sabit uzunluk zorla |
| API anahtarı | Hash'le + CT karşılaştır |
| CSRF / state token | |
| Şifre sıfırlama / magic link | Hash'le + tek kullanımlık |

**Crate seçimi:** `constant_time_eq` 0.6.0 (2026-08-30, aktif). `subtle` 2.6.1 — **26 aydır commit yok**, bakım riski olarak kaydet.

---

## 5. `rsa` crate'i — Marvin hâlâ yamalı değil

**RUSTSEC-2023-0071:** `patched = []` — **boş**.

Ve yeni bir issue var: **#626 "Padding implementation is not constant-time"**, açılış **7 Ocak 2026**, hâlâ **AÇIK**. Maintainer:

> *"the remaining sidechannels... are instead **in this crate's implementation of RSA padding modes**."*

0.10.0 hâlâ **rc.18**'de (Nisan 2026'dan beri).

⚠️ Marvin proje sayfası bunu "Fixed" gösteriyor — **çelişkili**. Upstream'e güven: **düzeltilmemiş kabul et.**

**Kararlar:**
- [ ] `cargo tree -i rsa` — ağaçta varsa neden orada olduğunu belgele; private-key işlemi yapıyorsa **kaldır**
- [ ] `jsonwebtoken` 11'i **`aws_lc_rs` backend** ile kullan (`rust_crypto` feature'ı `rsa`'yı çeker)
- [ ] **JWE `alg=RSA1_5` hiç implemente etme.** `draft-ietf-jose-deprecate-none-rsa15`: *"Application developers **MUST disable support for these algorithms by default**"*
- [ ] `alg` allowlist'i **istemci metadata'sından** gelsin, JWS/JWE header'ından asla (downgrade)

---

## 6. Kullanıcı sayımı — dummy Argon2 yanlış çözüm

### Neden yanlış

1. **DoS:** m=19 MiB × 100 eşzamanlı sahte istek = **1,9 GB**. Saldırgan hiç geçerli kullanıcı adı bilmeden IdP'yi düşürür.
2. **Parametre göçü:** Farklı parametrelerle hash'lenmiş kullanıcılar varsa tek dummy ikisini de taklit edemez.
3. **Yetmiyor:** Django 2013'te dummy hash ekledi, **2024'te CVE-2024-39329** aldı — "unusable password" durumu sızıyordu.

### Rauthy'nin çözümü (kaynak koddan)

Dummy hash **çalıştırmıyor**. Bunun yerine:
- Başarılı login'lerin **koşan ortalaması** tutuluyor
- Başarısızlıkta yanıt o ortalamaya kadar **doldurulnuyor**
- Üstüne IP başına üstel ceza: `≥3 → +2s`, `≥5 → +3s`, `7 → 60s kara liste`, `10 → 600s`, `25 → 86400s`
- `max_hash_threads` varsayılan **2** — *"technically allow only one user login at the exact same time... makes an external rate limiting for the login obsolete"*

### Argon2 semaforu

```rust
static HASH_PERMITS: Semaphore = Semaphore::const_new(N);
// N = floor(available_memory_bytes * 0.5 / (m_cost_kib * 1024))

let permit = timeout(Duration::from_millis(500), HASH_PERMITS.acquire())
    .await.map_err(|_| Error::Overloaded)?;   // → 503 + Retry-After
tokio::task::spawn_blocking(move || argon2_verify(pw, hash)).await?
```

⚠️ **Kuyruğun kendisi bir yan kanaldır.** Sadece var olan kullanıcılar için hash çalıştırırsan, saldırgan kuyruğu doldurup gecikmeyi gözleyerek kullanıcı varlığını anlar.

### Zamanlama dışı sızıntılar (unutulanlar)

Kayıt akışında "email already in use"; MFA challenge'ında WebAuthn `allowCredentials` listesinin dolu/boş olması; **rate-limit davranış farkı** (var olan kullanıcı kilitleniyor, olmayan kilitlenmiyorsa kilit mekanizman oracle olur).

Keycloak **CVE-2026-4633** (23 Mart 2026): identity-first login + Organizations açıkken differential error message. Yani olgun bir IdP'de 2026'da hâlâ çıkıyor ve **zamanlamadan değil, yeni bir özellikten** sızıyor.

**→ Login akışını `user+password birlikte → MFA` yap.** Identity-first kullanma.

---

## 7. Formel doğrulama — nereye uygulanır, nereye uygulanmaz

### Araç durumu (2026-09)

| Araç | Durum | Argus'ta yeri |
|---|---|---|
| **Kani** | 0.67.0 (Oca 2026), 8 aydır sürüm yok ama ASE 2026 makalesi var | **Saat/expiry aritmetiği + rate limiter** |
| **Flux** | Çok aktif, **döngü invariant'larını otomatik çıkarır, sınırsız doğrular** | **İndeks/uzunluk/taşma — en ucuz kazanç** |
| **Verus** | En aktif (günde birden çok release) | Saf, senkron, I/O'suz çekirdek |
| Prusti | **ÖLÜ** (son commit 2024-03-26) | Kullanma |
| MIRAI | **ÖLÜ** (orijinal repo) | Kullanma |

**Kani NE yapamaz:** `async`/`await` — **hayır**. Eşzamanlılık — **hayır** (ve sessizce sıralı işler, sonra yanlış sonuç verir). Verus: `async fn`, `serde::Serialize`, `Mutex`/`RwLock` — **hiçbiri desteklenmiyor**.

> **HTTP/async katmanı formel doğrulama kapsamı dışıdır.** Hiçbir araç desteklemiyor.

### En yüksek getirili iki uygulama

**1. Saat/expiry aritmetiği (Kani).** Hifitime vakası: Kani bu sınıfta **6 gerçek hata** buldu — `i64::MIN.abs()` taşması, NaN yayılımı, ve kritik olarak **`Epoch`'ta `PartialEq`/`Ord` tutarsızlığı** ve `Duration`'da `a == b && a < b`'nin aynı anda sağlanabilmesi.

Bir IdP'de `Ord` tutarsızlığı doğrudan **süresi dolmuş token'ın kabul edilmesi** demektir.

**2. Rate limiter (Kani).** Firecracker'da nondeterministik saat değerleriyle doğrulandı ve **%0,01 bütçe aşımına izin veren yuvarlama hatası** bulundu.

### Cedar'ın deseni — kopyalanmalı

Cedar: 7 özellik Lean 4'te ispatlanmış, **sıfır CVE**. OpenFGA: **26 advisory, ~16'sı authorization bypass**.

Ama nüans: **kanıtlar Lean modeli hakkında, Rust üretim kodu hakkında değil.** Bağ **differential random testing** ile kuruluyor.

> **Argus için: F0 fazında naif ama doğru bir referans implementasyon yaz, sonraki her optimizasyonu ona karşı diferansiyel test et.**

Ve rustls'in duruşu unutulmamalı: **formel doğrulama kullanmıyor** — `forbid(unsafe_code)` + fuzzing + OSS-Fuzz. Dünyanın en çok kullanılan Rust TLS kütüphanesi, ağdan gelen veriyi işleyen **tüm crate'inde** unsafe'i yasaklamış.

---

## 8. Performans — en büyük kaldıraç kriptoda değil, sertifikada

rustls'in kendi ci-bench ölçümü (Xeon E-2386G, 2026-03-07):

| Değişiklik | Kazanç | Kanıt gücü |
|---|---|---|
| **RSA-2048 → ECDSA P-256 sunucu sertifikası** | **2,9× (TLS 1.3) / 4,8× (TLS 1.2)** handshake/sn | Güçlü |
| **Session resumption aç** | **5,4×** (TLS 1.2 full'e karşı) | Güçlü |
| OpenSSL → rustls | +%32…+%220 handshake; **5,2× az** oturum belleği | Güçlü |
| Allocator (→mimalloc) | ~%4 CPU, **+%30'a kadar RSS** | Orta |
| PGO | ~%1 (rustc) | Orta — **rustls ekibi değerlendirip reddetti** |
| SIMD JSON @ 200B–4KB | **3,3× YAVAŞ** | Yapma |

> **Sertifika değişimi, bu raporun tamamındaki en büyük tek performans kazancıdır** — allocator, PGO ve derleyici bayraklarının hepsinden fazla.

**OpenSSL 3.0 uyarısı:** 80 thread'de ciddi ölçekleme sorunları var (RHEL 9 / Ubuntu 22.04 varsayılanı). rustls ve BoringSSL düz kalıyor.

**tracing maliyeti:** no-op subscriber ile **~10 ns/span** amortize. fastrace'in "100× daha hızlı" iddiası elma-armut (senkron toplayan subscriber'la karşılaştırıyor).

⚠️ **Uydurma iddia uyarısı:** "Rust 1.85 varsayılan allocator'ı mimalloc'a geçirdi" — **yanlış**. Rust hiçbir zaman varsayılan allocator değiştirmedi.

---

## 9. İşletim — sessiz başarısızlıklar

| Konu | Tuzak |
|---|---|
| **musl allocator** | **7× gerçek / ~700× sentetik** yavaşlama. `mallocng` çözmedi. musl seçilirse **mimalloc zorunlu** |
| **K8s PSS "restricted"** | **`readOnlyRootFilesystem` içermiyor** — elle ekle |
| **Landlock** | Thread bazlı. `all_threads()` **ABI 8 = Linux 7.0** gerektiriyor ve best-effort modda **sessizce düşüyor**. Çözüm: tokio runtime'dan **önce ana thread'de** uygula (fork ile miras alınır) |
| **io_uring** | seccomp'u **bypass eder** (yapılmayan syscall filtrelenemez). Docker varsayılan profili zaten blokluyor. **Kullanma** |
| **`overflow-checks`** | Release'de varsayılan **kapalı**. IdP'de wraparound = yetki mantığı hatası. **Aç** |
| **hyper limitleri** | Doküman: *"default values of options are **not considered stable**"* — hepsini açıkça set et; `header_read_timeout` için **Timer şart**, yoksa panic |
| **Reproducible build** | Üç remap kuralı gerekli: proje dizini, **`CARGO_HOME`**, **`RUSTUP_HOME`**. `cargo trim-paths` hâlâ unstable |

---

## 10. Öncelik sırası

| # | Aksiyon | Efor |
|---|---|---|
| 1 | CRA bildirim süreci + security.txt | 1 hafta — **11 Eylül** |
| 2 | Parser derinlik sınırı + fuzz target | 1 hafta |
| 3 | `Cargo.lock` + `--locked` + cooldown ≥7 gün | 1 gün |
| 4 | `cargo-deny` CI kapısı (`bans licenses sources`) | 2 saat |
| 5 | `overflow-checks = true` | 5 dakika |
| 6 | ECDSA P-256 sertifika + session resumption | 1 gün |
| 7 | Argon2 semaforu + Rauthy tarzı adaptif gecikme | 2 gün |
| 8 | `aws-lc-rs` birincil kripto sağlayıcı; `rsa` crate'ini ağaçtan çıkar | 1 gün |
| 9 | SLSA Source L4 (branch protection + 2 onay + imzalı commit) | 2 saat |
| 10 | Landlock (ana thread, runtime'dan önce) + seccomp | 1 hafta |
| 11 | Denetlenmemiş 14 crate'i elle denetle (`argon2`, `sqlx`, ASN.1) | 3 hafta |
| 12 | Kani: expiry aritmetiği + rate limiter | 2 hafta |

---

## Kapatılamayan boşluklar

- Argon2 doğrulanmamış — kaçınılmaz, belgele
- RS256 için doğrulanmış implementasyon yok — `aws-lc-rs` ile azalt
- Derleyici (LLVM) tüm CT garantilerinin dışında — s2n-bignum'un assembly-seviyesi ispatı bunu kapatan tek yaklaşım
- Async/HTTP katmanı formel doğrulama kapsamı dışı
- crates.io'da yayımcı imzası yok — güven zinciri: HTTPS + platform güvenliği + checksum + Trusted Publishing


---

# KISIM II — ALAN BİLGİSİ

*Kimlik alanının genel referansı: terminoloji, protokoller, yöntemler, standart olgunluğu. Argus'a özgü değildir; araştırmanın üzerine kurulduğu zemindir.*
