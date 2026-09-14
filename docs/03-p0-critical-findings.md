# §3 — P0 kritik bulgular

Bu dosya formel doğrulama, doğrulanmış kripto, yan kanal, sertleştirme, tedarik zinciri ve performans araştırmalarının sentezidir.

İçerdiği maddeler, yapılmadığı takdirde "en güvenli IdP" iddiasını geçersiz kılan maddelerdir.

---

## 0. CRA: kimlik yönetimi Sınıf I'de, steward raporlaması 11 Aralık 2027

AB Cyber Resilience Act, Ek III'te kimlik yönetim sistemlerini açıkça saymaktadır: kimlik yönetim sistemleri ve ayrıcalıklı erişim yönetimi yazılımı, kimlik doğrulama ve erişim kontrolü okuyucuları dahil.

Argus Sınıf I "önemli ürün" kategorisindedir. Bu, varsayılan öz-değerlendirmeden daha ağır bir uygunluk rejimi anlamına gelir.

| Tarih | Yükümlülük |
|---|---|
| 11 Eylül 2026 | Madde 14 manufacturer'lar için yürürlüğe girer; aktif sömürülen açıklar ENISA ve CSIRT'e bildirilir |
| 11 Aralık 2027 | Açık kaynak steward'ları raporlama yükümlülüğüne katılır (ENISA SRP FAQ). Steward'ları Madde 14'e bağlayan hüküm Madde 24(3)'tür ve Madde 24 bu tarihte uygulanmaya başlar. Arkasında tüzel kişi bulunmayan projelerde yükümlülük doğmaz; monetize edilmeyen FOSS zaten kapsam dışıdır |
| 11 Aralık 2027 | SBOM (Ek I Bölüm II.1 asgari olarak üst düzey bağımlılıkları ister), koordineli açık bildirim politikası, destek süresi tanımı, teknik dokümantasyon (Ek VII) ve CE işareti |

**Şimdi yapılacaklar.** Güvenlik iletişim adresi, `security.txt`, `SECURITY.md` ve bildirim akış şeması. Madde 24 §1'in istediği, doğrulanabilir biçimde belgelenmiş güvenlik politikası zaten iyi mühendisliktir; tarihin beklenmesine gerek yoktur.

> **Doğrulanamayan konular.** CRA yürürlük tarihinde çelişki bulunmaktadır: Komisyon 10 Aralık 2024, Wikipedia 12 Kasım 2024 vermektedir; Komisyon esas alınmalıdır. Ek IV'ün tam listesi çekilememiştir. CEN/CENELEC JTC13 uyumlaştırılmış standartlarının durumu araştırılmamıştır; uyumlaştırılmış standart yoksa Sınıf I için üçüncü taraf uygunluk değerlendirmesi gerekebilir.

---

## 1. Parser derinlik sınırı: doğrudan rakipte iki High CVE

Kanidm, Rust ile yazılmış güvenlik odaklı bir IdP'dir ve 2026'da bu sınıftan iki High severity açık almıştır:

| Advisory | Tarih | CVSS | Detay |
|---|---|---|---|
| GHSA-r5fr-9gmv-jggh (CVE-2026-46689) | 6 Mayıs 2026 | 8,7 | SCIM filter: `?filter=` query string'inde birkaç bin iç içe parantez (4-12 KB), PEG parser worker thread'in stack guard page'ini aşıyor |
| GHSA-qcxq-75wr-5cm8 | 30 Nisan 2026 | 8,7 | LDAP filter: hem PEG hem ASN parser'ı stack tüketiyor |

**Bulgunun ölümcül olmasının nedeni.** Rust'ta stack overflow yakalanabilir bir panic değil, `std::process::abort()` çağrısıdır. `catch_unwind` işe yaramaz. Olay bir tokio worker thread'inde gerçekleşse dahi tüm süreç sonlanır.

Kanidm advisory'sinin kendi ifadesine göre ayrıştırma axum'un `Query<ScimEntryGetQuery>` extractor'ı içinde, herhangi bir handler gövdesinden ve dolayısıyla herhangi bir ACL kontrolünden önce koşmaktadır. Yani kimliği doğrulanmamış bir GET isteği tüm IdP'yi kapatabilmektedir.

**Zorunlu karşı önlemler.**

```rust
const MAX_FILTER_DEPTH: u32 = 32;

fn parse_expr(input: &str, depth: u32) -> Result<Expr, ParseError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(ParseError::TooDeep);   // panic değil
    }
    // ... parse_expr(inner, depth + 1)
}
```

1. Her özyinelemeli parser'da açık bir derinlik sayacı bulunur ve sınır 32'dir.
2. Derinlik aşımında `Result::Err` döner; panic ve abort kullanılmaz.
3. Her custom axum extractor'ı ayrı bir tehdit yüzeyi olarak modellenir; auth middleware pahalı extractor'lardan önce çalışır.
4. `serde_json` varsayılan derinlik sınırı 128'dir. `unbounded_depth` özelliğinin hiçbir bağımlılıkta açık olmadığı CI'da assert edilir; bu bir Cargo feature unification tuzağıdır.
5. `quick-xml` 0.41.0 veya üstü kullanılır ve `Event::DocType` görüldüğünde belge reddedilir; böylece XXE ve billion laughs yapısal olarak kapanır.
6. x509 ve DER için boyut sınırı 8 KB'yi geçmez ve fuzz ile doğrulanır.
7. WebAuthn CBOR için boyut ve derinlik kontrolü uygulanır; bu akış kimliği doğrulanmamış registration yoludur.

Aynı sınıftan 2026 advisory'leri: `time` RUSTSEC-2026-0009 (Cloudflare Pingora etkilendi), `quick-xml` RUSTSEC-2026-0195 (Routinator OOM), `lopdf` RUSTSEC-2026-0187, `protobuf` RUSTSEC-2024-0437.

---

## 2. Tedarik zinciri: `Cargo.lock` kullanıcıların %90'ını kurtardı

### arrayref saldırısı, 20 Ağustos 2026

Olay tipo-eşkıyalık değil, maintainer ele geçirmesidir.

| Crate | Kötü sürüm | 10 yıllık indirme |
|---|---|---|
| `arrayref` | 0.3.10 | Yaklaşık 245.000.000 |
| `internment` | 0.8.7 | Yaklaşık 14.400.000 |
| `append-only-vec` | 0.1.9 | Yaklaşık 4.500.000 |

Mekanizma üç aşamalıdır.

1. Meşru crate'lere `proc-macro1` bağımlılığı eklenmiştir; paketin on yıllık geçmişinde daha önce görülmemiş bir bağımlılıktır.
2. `proc-macro1`'in `build.rs` dosyası dropper'dır. JFrog'un tespitine göre bu dosya `cargo build` ve `cargo check` sırasında, CI ve rust-analyzer güdümlü derlemeler dahil, otomatik olarak derlenip çalıştırılır; editörde dosya açmak yeterlidir.
3. Payload platforma özeldir (Linux, Windows, macOS), C2 iletişimi Base64 parçalıdır ve TLS doğrulaması kasten kapatılmıştır.

Yayında kalma süreleri 86, 90 ve 107 dakikadır. Etki sınırlı kalmıştır: `arrayref` 0.3.10 yalnızca 2.285 kez indirilmiştir, yani trafiğin %10'undan azı.

Kullanıcıların %90'ını kurtaran tek şey `Cargo.lock`'taki sabit sürümdür.

### PolinRider crates.io'ya ulaştı, 6 Eylül 2026

RUSTSEC-2026-0280: `greentic-setup-dev` yaklaşık 27 saat yayında kalmıştır. Kuzey Kore bağlantılı bir kampanyadır; npm, Packagist, Go ve Chrome ekosistemlerinde 108'den fazla paketi kapsamaktadır.

Kritik fark, `build.rs` kullanılmamasıdır. Saldırı VS Code'un `.vscode/tasks.json` mekanizmasını kullanır. Dolayısıyla yalnızca `cargo build`'i sandbox'lamak yeterli değildir.

### 2026 kötü amaçlı crate advisory'leri

| Yıl | Sayı |
|---|---|
| 2023 | 28 |
| 2024 | 0 |
| 2025 | 14 |
| 2026 | 32 (8 Eylül'e kadar) |

### Zorunlu önlemler

1. `Cargo.lock` commit edilir ve her yerde `--locked` kullanılır. Beş dakikalık bir iştir ve %90 koruma sağladığı ölçülmüştür.
2. Bağımlılık cooldown süresi en az yedi gündür; Renovate'te `minimumReleaseAge: "7 days"`. Bu ayar 86-107 dakikalık saldırı penceresini tamamen kapatır.
3. CI derlemesi ağsız yapılır (`cargo vendor` ve `--offline`); böylece payload indirme adımı engellenir.
4. Yeni bir `build.rs` bağımlılığı CI'da alarm üretir. arrayref olayının tek sinyali buydu.
5. Vendored ağaçta `.vscode/`, `.devcontainer/` ve `.githooks/` dizinleri taranır ve reddedilir; bu PolinRider vektörüdür.
6. GitHub Actions commit SHA ile pinlenir, `@v4` biçimiyle değil.
7. Geliştirici makinelerinde `cargo:token` kullanılmaz; `cargo:macos-keychain` veya `cargo:libsecret` kullanılır. Düz metin token, arrayref olayının muhtemel giriş vektörüdür.

### cargo-vet gerçek kapsamı

Beş büyük audit seti (google, mozilla, bytecode-alliance, zcash, embark) klonlanıp sayılmıştır: 1.815 farklı crate ve 5.576 audit girdisi.

> **Uyarı.** SEO amaçlı bloglar 14.140 crate ve 58.900 sürüm iddia etmektedir. Bu rakamlar uydurmadır ve AI üretimi içeriktir.

Argus yığınının kapsamı sürüm-tam ölçümde %51, crate adı ölçümünde %91'dir.

Hiç denetlenmemiş olanlar tam da en kritik olanlardır:

```
argon2, sqlx, sqlx-core, sqlx-macros, sqlx-postgres, blake2,
asn1-rs, der-parser, oid-registry, simple_asn1, pem
```

Parola hash'leme, veritabanı katmanı ve ASN.1 ayrıştırma. İlk elle denetim bütçesi buraya ayrılır.

---

## 3. Doğrulanmış kripto: iki büyük boşluk ve bir uyarı

### libcrux durumu

Aşağıdaki tablo kaynak koddan doğrulanmıştır.

| Algoritma | Rozet |
|---|---|
| SHA-2, HMAC, HKDF, Ed25519, ECDSA P-256, RSA-PSS, X25519, ChaCha20-Poly1305, Poly1305, BLAKE2 | verified-hacl |
| ML-KEM, ML-DSA | Kısmî (hax) |
| AES-GCM ve AES-CCM | pre-verification |
| SHA-3 ve SHAKE | pre-verification |
| HMAC-DRBG (CSPRNG) | pre-verification |

### İki kapatılamayan boşluk

1. RS256 (RSA PKCS#1 v1.5) için doğrulanmış implementasyon bulunmamaktadır; ne HACL*'ta ne libcrux'ta. OIDC istemcilerinin ezici çoğunluğu ise RS256 beklemektedir.
2. Argon2 için doğrulanmış implementasyon hiçbir dilde bulunmamaktadır. Parola hash'leme formel doğrulama hikâyesinin kapsamı dışında kalacaktır; bu açıkça belgelenmelidir.

### Verification Theatre — Kobeissi, ePrint 2026/192

libcrux ve hpke-rs'te 13 zafiyet tespit edilmiştir: dokuzu doğrulama sınırının dışında, dördü sözde doğrulanmış spec ve ispat kodunun içindedir.

Nicel tablo şudur: ML-KEM Rust kodunun yalnızca %58,4'ünün ispatları gerçekten SMT çözücüye gitmektedir. `ADMIT_MODULES` listesinde bulunanlar en kritik olanlardır: `Ind_cpa.fst`, `Sampling.fst` ve NEON yolunun tamamı, yani ARM64 üzerinde Graviton ve Apple Silicon.

İfşa süreci de sorunludur. CE Labs raportörün GitHub hesabını engellemiş, dört PR'ı kapatmış, ardından düzeltmeleri atıf vermeden merge etmiştir.

**Gerçek dünya sonucu.** V1, RUSTSEC-2025-0133: ARM64'te SHA-3 bozuk olduğu için libcrux-ml-dsa v0.0.3 farklı platformlarda farklı public key ve imza üretmekteydi. Bulguyu Filippo Valsorda bildirmiştir.

**Kullanım gerçeği.** `libcrux-ecdsa` 90 günde 721, `libcrux-rsa` 582 indirme almıştır. ES256 ve PS256 yolları pratikte hiç test edilmemiştir.

### Karar: aws-lc-rs birincil

`aws-lc-rs` 1.18.1 (1 Eylül 2026) Argus'un JWT ihtiyaçlarının tamamını, RS256 dahil, karşılamaktadır. Altındaki s2n-bignum 2025 sonundan itibaren hem fonksiyonel doğruluk hem constant-time için HOL Light ispatları taşımaktadır (RSA, P-256, P-384, P-521, X25519, Ed25519) ve bayt düzeyinde gerçek object dosyalarına karşı doğrulanmaktadır; derleyici varsayımı yoktur. Bu, HACL*'ın C ile derleyici arasındaki boşluğunu kapatan tek yaklaşımdır.

AWS'in ispatları her push ve PR'da CI'da çalışmaktadır; libcrux'un yavaş modülleri ise hiçbir otomatik sistem tarafından doğrulanmamıştır.

### İddia dili — Kobeissi R4

Kobeissi'nin dördüncü tavsiyesine göre niteliksiz "formally verified" ifadesi, doğrulama sınırının CompCert veya seL4'te olduğu gibi donanım seviyesine indirildiği sistemlere saklanmalıdır.

| | İfade |
|---|---|
| İzin verilen | JWT imzalama primitifleri HACL*'tan türetilmiş doğrulanmış kod kullanır; parola hash'leme, protokol mantığı ve derleme süreci doğrulama sınırının dışındadır. |
| İzin verilmeyen | Argus formel olarak doğrulanmıştır (niteliksiz biçimde). |

---

## 4. Sabit zamanlı karşılaştırma: "ölçülemez" argümanı geçersiz

### Timeless Timing Attacks (USENIX Security 2020)

Çalışmanın bulgusu şudur: HTTP/2 üzerinden sunulan web sunucularında 100 ns kadar küçük bir zamanlama farkı, yaklaşık 40.000 istek çiftinin yanıt sırasından doğru biçimde çıkarılabilmektedir. İnternet üzerinden geleneksel bir zamanlama saldırısında gözlenebilen en küçük fark 10 µs'dir, yani 100 kat daha büyüktür. Yöntem ağ koşullarından tamamen bağımsızdır ve saldırgan ile kurban sunucu arasındaki mesafeden etkilenmez.

Mekanizma şudur: iki HTTP/2 isteği tek TCP paketinde birleşir, eşzamanlı işlenir ve yanıt sırası ölçülür. Ağ jitter'ı tamamen elenir.

Argus HTTP/2 sunduğu için "tek haneli nanosaniye ölçülemez" argümanı geçersizdir.

### Rust'ın kendi kısıtı

`std::hint::black_box` dokümantasyonu bu fonksiyonun kriptografik veya güvenlik amaçları için hiçbir garanti sunmadığını belirtir. Aynı dokümantasyon kısıtın `black_box`'a özgü olmadığını, Rust dilinin tamamında sabit zamanlı kriptografinin gerektirdiği garantileri sağlayabilecek bir mekanizma bulunmadığını söyler.

### Bulgunun teorik olmadığı

RUSTSEC-2026-0003 ve CVE-2026-23519 (14 Ocak 2026), `cmov` crate'ini etkilemiştir. Tam da bu iş için yazılmış ve `black_box`'ı bilinçli kullanan bu crate ARM32'de branch üretmiştir:

```asm
bne  .LBB0_2      ; Branch if Not Equal
```

v0.4.4 taktiksel bir `black_box` yaması uygulamış, v0.4.5 ise `asm!` ile yeniden yazılmıştır. `black_box` çalışmamakta, `asm!` çalışmaktadır.

### Zorunlu yerler

| Yer | Not |
|---|---|
| Opak token veritabanı araması | Asıl çözüm hash'lemektir: `SHA-256(token)` saklanır. Veritabanı indeks karşılaştırması da sızdırır |
| HMAC ve JWS imza doğrulama | Klasik uygulama alanı |
| TOTP kodu | Gerçek CVE mevcuttur: `totp-rs` RUSTSEC-2022-0018 |
| `client_secret` | Sabit uzunluk zorlanır |
| API anahtarı | Hash'lenir ve sabit zamanlı karşılaştırılır |
| CSRF ve state token'ı | — |
| Şifre sıfırlama ve magic link | Hash'lenir ve tek kullanımlık yapılır |

**Crate seçimi.** `constant_time_eq` 0.6.0 (30 Ağustos 2026) aktiftir. `subtle` 2.6.1'de 26 aydır commit bulunmamaktadır; bakım riski olarak kaydedilir.

---

## 5. `rsa` crate'i: Marvin hâlâ yamalı değil

RUSTSEC-2023-0071 kaydında `patched = []` alanı boştur.

Ayrıca yeni bir issue bulunmaktadır: #626 "Padding implementation is not constant-time", 7 Ocak 2026'da açılmış ve hâlâ açıktır. Maintainer'ın ifadesine göre kalan yan kanallar bu crate'in RSA padding modlarına ait implementasyonundadır.

0.10.0 sürümü Nisan 2026'dan beri hâlâ rc.18 aşamasındadır.

> **Uyarı.** Marvin proje sayfası durumu "Fixed" olarak göstermektedir ve bu upstream ile çelişmektedir. Upstream esas alınır: düzeltilmemiş kabul edilir.

**Kararlar.**

1. `cargo tree -i rsa` koşulur. Ağaçta varsa neden orada olduğu belgelenir; private-key işlemi yapıyorsa kaldırılır.
2. `jsonwebtoken` 11 `aws_lc_rs` backend'i ile kullanılır; `rust_crypto` özelliği `rsa`'yı çeker.
3. JWE `alg=RSA1_5` hiç implemente edilmez. `draft-ietf-jose-deprecate-none-rsa15` uygulama geliştiricilerinin bu algoritmaları varsayılan olarak devre dışı bırakmasını zorunlu kılar.
4. `alg` allowlist'i istemci metadata'sından gelir, JWS veya JWE header'ından değil; aksi hâlde downgrade yüzeyi doğar.

---

## 6. Kullanıcı sayımı: dummy Argon2 yanlış çözüm

### Yanlış olmasının nedenleri

1. **DoS.** m=19 MiB değeri ile 100 eşzamanlı sahte istek 1,9 GB tahsis ettirir. Saldırgan hiçbir geçerli kullanıcı adı bilmeden IdP'yi düşürebilir.
2. **Parametre göçü.** Farklı parametrelerle hash'lenmiş kullanıcılar varsa tek bir dummy ikisini birden taklit edemez.
3. **Yetersizlik.** Django 2013'te dummy hash eklemiş, 2024'te CVE-2024-39329 almıştır; "unusable password" durumu sızmaktaydı.

### Rauthy'nin çözümü

Rauthy kaynak kodunda dummy hash çalıştırılmamaktadır. Bunun yerine şu yapı kullanılır.

Başarılı login'lerin koşan ortalaması tutulur ve başarısızlıkta yanıt o ortalamaya kadar doldurulur. Üstüne IP başına üstel ceza uygulanır: üç ve üzeri denemede 2 sn, beş ve üzeri denemede 3 sn, yedi denemede 60 sn kara liste, on denemede 600 sn, yirmi beş denemede 86.400 sn. `max_hash_threads` varsayılanı 2'dir; Rauthy'nin ifadesiyle bu ayar teknik olarak aynı anda yalnızca bir kullanıcı girişine izin verir ve login için harici bir rate limiting'i gereksiz kılar.

### Argon2 semaforu

```rust
static HASH_PERMITS: Semaphore = Semaphore::const_new(N);
// N = floor(available_memory_bytes * 0.5 / (m_cost_kib * 1024))

let permit = timeout(Duration::from_millis(500), HASH_PERMITS.acquire())
    .await.map_err(|_| Error::Overloaded)?;   // 503 + Retry-After
tokio::task::spawn_blocking(move || argon2_verify(pw, hash)).await?
```

> **Uyarı.** Kuyruğun kendisi bir yan kanaldır. Hash yalnızca var olan kullanıcılar için çalıştırılırsa saldırgan kuyruğu doldurup gecikmeyi gözleyerek kullanıcı varlığını anlayabilir.

### Zamanlama dışı sızıntılar

Kayıt akışındaki "email already in use" mesajı; MFA challenge'ında WebAuthn `allowCredentials` listesinin dolu veya boş olması; rate limit davranış farkı — var olan kullanıcı kilitlenirken olmayanın kilitlenmemesi kilit mekanizmasını oracle hâline getirir.

Keycloak CVE-2026-4633 (23 Mart 2026): identity-first login ile Organizations birlikte açıkken differential error message üretilmektedir. Olgun bir IdP'de 2026'da hâlâ ortaya çıkan bu sızıntı zamanlamadan değil, yeni bir özellikten kaynaklanmaktadır.

Sonuç olarak login akışı kullanıcı adı ve parolanın birlikte alındığı, ardından MFA'nın geldiği biçimde kurulur. Identity-first kullanılmaz.

---

## 7. Formel doğrulama: nereye uygulanır, nereye uygulanmaz

### Araç durumu (Eylül 2026)

| Araç | Durum | Argus'taki yeri |
|---|---|---|
| Kani | 0.67.0 (Ocak 2026). Sekiz aydır sürüm çıkmamış ancak ASE 2026 makalesi mevcut | Saat ve expiry aritmetiği, rate limiter |
| Flux | Çok aktif. Döngü invariantlarını otomatik çıkarır ve sınırsız doğrular | İndeks, uzunluk ve taşma; en ucuz kazanç |
| Verus | En aktif; günde birden çok release | Saf, senkron, I/O içermeyen çekirdek |
| Prusti | Ölü; son commit 26 Mart 2024 | Kullanılmaz |
| MIRAI | Ölü; orijinal repo | Kullanılmaz |

Kani `async` ve `await` desteklemez. Eşzamanlılığı da desteklemez; sessizce sıralı işler ve ardından yanlış sonuç verir. Verus `async fn`, `serde::Serialize`, `Mutex` ve `RwLock` desteklemez.

HTTP ve async katmanı formel doğrulama kapsamı dışındadır; hiçbir araç desteklememektedir.

### En yüksek getirili iki uygulama

**Saat ve expiry aritmetiği (Kani).** Hifitime vakasında Kani bu sınıfta altı gerçek hata bulmuştur: `i64::MIN.abs()` taşması, NaN yayılımı ve kritik olarak `Epoch` tipinde `PartialEq` ile `Ord` tutarsızlığı ile `Duration`'da `a == b && a < b` koşulunun aynı anda sağlanabilmesi.

Bir IdP'de `Ord` tutarsızlığı doğrudan süresi dolmuş token'ın kabul edilmesi anlamına gelir.

**Rate limiter (Kani).** Firecracker'da nondeterministik saat değerleriyle doğrulama yapılmış ve %0,01 bütçe aşımına izin veren bir yuvarlama hatası bulunmuştur.

### Cedar'ın deseni

Cedar'da yedi özellik Lean 4'te ispatlanmıştır ve üründe sıfır CVE bulunmaktadır. OpenFGA'da 26 advisory vardır ve bunların yaklaşık 16'sı authorization bypass'tır.

Nüans şudur: kanıtlar Lean modeli hakkındadır, Rust üretim kodu hakkında değildir. İkisi arasındaki bağ differential random testing ile kurulmaktadır.

Argus için karşılığı şudur: F0 fazında naif ancak doğru bir referans implementasyon yazılır ve sonraki her optimizasyon ona karşı diferansiyel test edilir.

rustls'in duruşu da unutulmamalıdır: formel doğrulama kullanmaz, `forbid(unsafe_code)`, fuzzing ve OSS-Fuzz kullanır. Dünyanın en çok kullanılan Rust TLS kütüphanesi, ağdan gelen veriyi işleyen crate'inin tamamında unsafe'i yasaklamıştır.

---

## 8. Performans: en büyük kaldıraç kriptoda değil, sertifikada

rustls'in kendi ci-bench ölçümü (Xeon E-2386G, 7 Mart 2026):

| Değişiklik | Kazanç | Kanıt gücü |
|---|---|---|
| RSA-2048 yerine ECDSA P-256 sunucu sertifikası | Saniyedeki handshake sayısında 2,9× (TLS 1.3) ve 4,8× (TLS 1.2) | Güçlü |
| Session resumption açılması | TLS 1.2 full handshake'e karşı 5,4× | Güçlü |
| OpenSSL yerine rustls | Handshake'te %32 ile %220 arası artış; oturum belleğinde 5,2× azalma | Güçlü |
| Allocator değişimi (mimalloc) | Yaklaşık %4 CPU kazancı, RSS'te %30'a kadar artış | Orta |
| PGO | Yaklaşık %1 (rustc) | Orta; rustls ekibi değerlendirip reddetmiştir |
| 200 B - 4 KB aralığında SIMD JSON | 3,3× yavaş | Uygulanmaz |

Sertifika değişimi bu raporun tamamındaki en büyük tek performans kazancıdır; allocator, PGO ve derleyici bayraklarının toplamından fazladır.

**OpenSSL 3.0 uyarısı.** 80 thread'de ciddi ölçekleme sorunları bulunmaktadır; bu sürüm RHEL 9 ve Ubuntu 22.04 varsayılanıdır. rustls ve BoringSSL düz kalmaktadır.

**tracing maliyeti.** No-op subscriber ile span başına yaklaşık 10 ns amortize maliyet ölçülmüştür. fastrace'in 100 kat daha hızlı olduğu iddiası karşılaştırılamaz bir ölçüme dayanmaktadır; senkron toplayan bir subscriber ile karşılaştırma yapılmıştır.

> **Uydurma iddia uyarısı.** "Rust 1.85 varsayılan allocator'ı mimalloc'a geçirdi" ifadesi yanlıştır. Rust hiçbir zaman varsayılan allocator'ı değiştirmemiştir.

---

## 9. İşletim: sessiz başarısızlıklar

| Konu | Tuzak |
|---|---|
| musl allocator | Gerçek iş yükünde 7×, sentetik ölçümde yaklaşık 700× yavaşlama. `mallocng` sorunu çözmemiştir. musl seçilirse mimalloc zorunludur |
| K8s PSS "restricted" | `readOnlyRootFilesystem` içermez; elle eklenir |
| Landlock | Thread bazlıdır. `all_threads()` ABI 8, yani Linux 7.0 gerektirir ve best-effort modda sessizce düşer. Çözüm, tokio runtime'ından önce ana thread'de uygulamaktır; fork ile miras alınır |
| io_uring | seccomp'u bypass eder, çünkü yapılmayan syscall filtrelenemez. Docker varsayılan profili zaten bloklamaktadır. Kullanılmaz |
| `overflow-checks` | Release profilinde varsayılan olarak kapalıdır. Bir IdP'de wraparound yetki mantığı hatasına dönüşür. Açılır |
| hyper limitleri | Dokümantasyon seçeneklerin varsayılan değerlerinin stabil sayılmadığını belirtir; hepsi açıkça set edilir. `header_read_timeout` için Timer şarttır, yoksa panic oluşur |
| Reproducible build | Üç remap kuralı gereklidir: proje dizini, `CARGO_HOME` ve `RUSTUP_HOME`. `cargo trim-paths` hâlâ unstable'dır |

---

## 10. Öncelik sırası

| # | Aksiyon | Efor |
|---|---|---|
| 1 | CRA bildirim süreci ve `security.txt` | 1 hafta; 11 Eylül tarihine bağlı |
| 2 | Parser derinlik sınırı ve fuzz target | 1 hafta |
| 3 | `Cargo.lock`, `--locked` ve yedi günlük cooldown | 1 gün |
| 4 | `cargo-deny` CI kapısı (`bans licenses sources`) | 2 saat |
| 5 | `overflow-checks = true` | 5 dakika |
| 6 | ECDSA P-256 sertifikası ve session resumption | 1 gün |
| 7 | Argon2 semaforu ve Rauthy tarzı adaptif gecikme | 2 gün |
| 8 | `aws-lc-rs`'in birincil kripto sağlayıcı yapılması ve `rsa` crate'inin ağaçtan çıkarılması | 1 gün |
| 9 | SLSA Source L4: branch protection, iki onay, imzalı commit | 2 saat |
| 10 | Landlock (ana thread, runtime'dan önce) ve seccomp | 1 hafta |
| 11 | Denetlenmemiş 14 crate'in elle denetimi (`argon2`, `sqlx`, ASN.1) | 3 hafta |
| 12 | Kani: expiry aritmetiği ve rate limiter | 2 hafta |

---

## Kapatılamayan boşluklar

1. Argon2 doğrulanmamıştır; bu kaçınılmazdır ve belgelenir.
2. RS256 için doğrulanmış implementasyon bulunmamaktadır; risk `aws-lc-rs` ile azaltılır.
3. Derleyici (LLVM) tüm sabit zaman garantilerinin dışındadır; s2n-bignum'un assembly seviyesindeki ispatı bunu kapatan tek yaklaşımdır.
4. Async ve HTTP katmanı formel doğrulama kapsamı dışındadır.
5. crates.io'da yayımcı imzası bulunmamaktadır; güven zinciri HTTPS, platform güvenliği, checksum ve Trusted Publishing'den oluşur.

---

# Kısım II — Alan bilgisi

Bundan sonraki bölüm kimlik alanının genel referansıdır: terminoloji, protokoller, yöntemler ve standart olgunluğu. Argus'a özgü değildir; araştırmanın üzerine kurulduğu zemindir.
