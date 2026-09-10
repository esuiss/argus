# 5. Rust ekosistemi fizibilitesi

> `ARGUS.md` §5'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§5 §X` referansları aynı anlamda.


**Yöntem:** crates.io API, api.osv.dev, GitHub API/atom, **crate kaynak kodlarının indirilip incelenmesi**, Kanidm/Rauthy klonlanıp ölçülmesi.

---

### 0. Net cevap

**Rust bu iş için hazır — ama düşünülen yerlerde değil.**

Beklenen hikâye "Rust hızlı ama kütüphane yok"tu. Gerçek bunun tersi: **altyapı katmanı (TLS, kripto, HTTP, DB) Go'dan İYİ durumda. Boşluk tam olarak protokol-sunucu katmanında ve orası işin %70'i.**

| Katman | Karar |
|---|---|
| TLS / kripto / PQ | ✅ **Rust burada Go'yu geçiyor** (rustls PQ varsayılan açık, aws-lc-rs FIPS+ML-DSA) |
| HTTP / runtime | ✅ Hazır (axum + hyper 1.x + tower) |
| WebAuthn / Passkey | ✅ Hazır — ekosistemin en güçlü noktası |
| JOSE / JWT | ✅ Hazır **ama tek bir feature bayrağı hayat memat meselesi** |
| Veri katmanı | ✅ Hazır (yönetişim uyarısıyla) |
| **OAuth2/OIDC Authorization Server** | 🔴 **BOŞLUK — Fosite karşılığı YOK** |
| **SAML** | 🟠 2025'te boşluktu, 2026'da doldu ama **çok taze/kırılgan** |
| **LDAP sunucu** | 🟠 Wire protokol var, sunucu semantiği yok |
| **SCIM** | 🟠 Model+filtre var, sunucu yok |
| Çok kiracılık | 🔴 Her dilde sıfırdan |

**Rust/Go maliyet çarpanı: ~1.5–2x, ve farkın neredeyse tamamı tek bir kalemden: Fosite'ın yokluğu.**

---

### 1. Web / Runtime

Sürümler crates.io API'den 2026-09-08'de çekildi.

| Kütüphane | Sürüm | Tarih | Olgunluk | Karar |
|---|---|---|---|---|
| **axum** | 0.8.9 | 2026-04-14 | 5 | ✅ **SEÇ** |
| hyper | 1.11.1 | 2026-08-28 | 5 | ✅ (axum altında) |
| tower-http | 0.7.1 | 2026-08-31 | 5 | ✅ |
| tokio | 1.53.1 | 2026-07-20 | 5 | ✅ Argon2 izolasyonuyla |
| actix-web | 4.15.0 | 2026-08-21 | 4 | ⚠️ **CVE-2026-73051** |
| ntex | 3.12.3 | 2026-09-07 | 2 | ❌ |
| poem | 3.1.12 | 2025-07-28 | 2 | ❌ 13 aydır sürüm yok |
| h3 (HTTP/3) | 0.0.8 | 2025-05-06 | 1 | ❌ 16 aydır durgun |

#### Kararın dayanağı: benchmark değil, ekosistem kütlesi

TechEmpower sayıları IdP için anlamsız — istek bütçesinin %95'i Argon2 (50–100 ms) ve imzalamada geçer; framework overhead'i mikrosaniye.

crates.io ters bağımlılık sayıları:

| axum | actix-web | ntex |
|---|---|---|
| **8.508** | 1.695 | **76** |

ntex'in benchmark üstünlüğü gerçek ama **darboğaz değil**; ekosistem yoksunluğu her gün canı yakar.

**actix güvenlik geçmişi:** CVE-2026-73051 (HTTP/1.1 CL.TE request smuggling, 3.12.1'de düzeldi). Ayrıca 2018 (RUSTSEC-2018-0019, çoklu bellek güvenliği), 2020 (use-after-free), 2021 (smuggling). hyper'ın da geçmişi var ama 2022'den beri temiz.

**HTTP/3: yapma.** h3 16 aydır durgun; IdP'nin ihtiyacı yok, TLS terminasyonu yapan proxy isterse yapar.

---

### 2. TLS ve Kripto — Rust'ın Go'yu açık ara geçtiği yer

| Kütüphane | Sürüm | Tarih | Karar |
|---|---|---|---|
| **rustls** | 0.23.44 | 2026-09-07 | ✅ **SEÇ** |
| **aws-lc-rs** | 1.18.1 | 2026-09-01 | ✅ **SEÇ** (varsayılan provider) |
| ring | 0.17.14 | **2025-03-11** | ❌ Kaçın |
| **rsa** (RustCrypto) | 0.9.10 / 0.10.0-rc.18 | 2026-04-27 | 🔴 **ASLA** |

#### rustls: post-quantum VARSAYILAN AÇIK

docs.rs/rustls 0.23.44'ten birebir: `prefer-post-quantum` feature **varsayılan olarak etkin**, *"prioritizes post-quantum secure key exchange by default (using X25519MLKEM768)"*. Varsayılan provider **aws-lc-rs**.

**Bu, Go'nun crypto/tls'inden ileri bir konum.**

#### aws-lc-rs (kaynak kodundan doğrulandı)

`aws-lc-rs-1.18.1` tarball'ı açılıp incelendi:
- `src/kem.rs` → `ML_KEM_512 / 768 / 1024`
- `src/pqdsa.rs` → `ML_DSA_44 / 65 / 87`
- `fips` feature → `aws-lc-fips-sys`, **AWS-LC-FIPS 4.x**

**FIPS konusunda abartma:** lib.rs'in kendi ifadesi — *"has completed FIPS validation testing... and has been **submitted to NIST for certification**"* — sertifika **beklemede**. Ayrıca FIPS build'i **CMake + Go** gerektiriyor.

#### 🔴 `rsa` crate'i hâlâ Marvin'e açık

**RUSTSEC-2023-0071 / CVE-2023-49092.** OSV sorgusunda düzeltilmiş sürüm alanı **boş**. Advisory son güncelleme 2026-04-25. README'nin kendi ifadesi:

> *"This crate is vulnerable to the Marvin Attack... which could enable private key recovery by a network attacker."*

Proje **"Phase 1: Make it work 🚧"** olarak işaretli. 0.10 hâlâ `rc.18`.

> **Kural: RSA'yı asla `rsa` crate'i ile yapma. aws-lc-rs kullan.**

#### ring: ölmüyor ama duruyor

0.17.14, **2025-03-11** — 18 aydır sürüm yok. README projeyi *"An experiment"* diye tanımlıyor. **aws-lc-rs zaten ring-API uyumlu.**

#### Argon2 — kaynak koddan doğrulanmış

`argon2-0.6.0` kaynağı incelendi:
```
src/lib.rs:194   cpufeatures::new!(avx2_cpuid, "avx2");
src/lib.rs:530   #[target_feature(enable = "avx2")]
src/lib.rs:531   unsafe fn compress_avx2(...)
```
**AVX2 runtime-dispatch VAR.** 0.6.0 (2026-08-27) ayrıca `parallel` (rayon) feature'ı ekledi.

⚠️ **Ama NEON YOK.** `grep -i neon` boş döndü. **ARM'da (Graviton, Ampere) skaler yola düşülüyor.** ARM hedefleniyorsa `argon2-kdf` (C binding) ile kendi donanımda ölç.

---

### 3. Auth'a özel kütüphaneler — en kritik bölüm

#### 3.1 🔴 OAuth 2.1 Authorization Server: GERÇEK BOŞLUK

**Fosite'ın Rust karşılığı YOK.** Kanıtlar kaynak koddan:

**`openidconnect` 4.0.1 — istemci, sunucu değil.** `lib.rs:267`'den birebir:
> *"This library does not implement a complete OpenID Connect Provider, which requires functionality such as credential and session management."*

Üstelik `rsa ^0.9.2`'ye **zorunlu** bağımlı → Marvin'i miras alıyor.

**`oxide-auth` 0.6.1 — son sürüm 2024-06-02.** Bağımlılıkları: `hmac`, `sha2`, `rust-argon2`, `subtle`, `rmp-serde`. **Asimetrik kripto hiç yok** → `id_token` imzalayamaz, OIDC yapamaz. Bakımcı: *"Please respect that I maintain this on my own currently and have limited time"*. **Ters bağımlılık: 14.** 8 yıllık bir crate'in 14 kullanıcısı — fiilen kullanılmadığının kanıtı.

**Karşılaştırma:** Fosite (Go) 2.6k yıldız, aktif; RFC 6749/6819/7636/8252/9126 + OIDC Core'u hazır veriyor.

**Yazılması gerekenler (Fosite'ın bedava verdiği):** authorization code + PKCE (S256), refresh rotation & reuse detection, client_credentials, device grant (RFC 8628), token exchange (RFC 8693), introspection (7662), revocation (7009), PAR (9126), JAR (9101), DPoP (9449), Discovery/JWKS, DCR, sektör bazlı `sub`, pairwise identifier, consent/session, back/front-channel logout, OAuth 2.1 sıkılaştırmaları.

**Efor: 12–18 geliştirici-ayı.**

#### 3.2 ✅ JOSE/JWT: `jsonwebtoken` 11 — ama TEK BİR BAYRAK hayati

`jsonwebtoken-11.0.0` kaynağı incelendi. **Güvenlik tasarımı gerçekten iyi:**

| Savunma | Durum | Kanıt |
|---|---|---|
| `alg: none` | **Enum'da hiç yok** | `algorithms.rs` |
| HMAC↔RSA karışıklığı | **Tip düzeyinde engelli** | `jws.rs:42` `key.family() != header.alg.family()` |
| Algoritma allowlist | Zorunlu | `decoding.rs:278` |
| CVE-2026-25537 (type confusion) | **Düzeltilmiş** | `validation.rs:271,274` |
| Varsayılanlar | `validate_exp=true`, `validate_aud=true`, `exp` zorunlu, leeway 60s | `validation.rs:119` |

⚠️ **`validate_nbf` varsayılan `false`** — IdP'de aç.

🔴 **Kader belirleyen satır:**
```
default = ["use_pem"]              # kripto backend YOK
rust_crypto = [..., "dep:rsa", ...]   # Marvin'e açık
aws_lc_rs = ["dep:aws-lc-rs"]         # güvenli
```

> **`features = ["aws_lc_rs"]` ile kullan. `rust_crypto` seni doğrudan Marvin timing sidechannel'ına bağlar.**

**Diğerleri:**

| Crate | Backend | Değerlendirme |
|---|---|---|
| **jsonwebtoken 11.0.0** | aws-lc-rs *veya* rsa | ✅ **SEÇ** (aws_lc_rs ile) |
| jwt-simple 0.13.1 | superboring/boring | ⚠️ İyi tasarım (jedisct1), niş |
| josekit 0.10.3 | **openssl ^0.10.68** | ❌ C OpenSSL — 28 advisory, 2026'da 6 |
| biscuit 0.8.0 | ring ~0.17.13 | ⚠️ Duran backend |
| openidconnect 4.0.1 | **rsa zorunlu** | ❌ |

#### 3.3 ✅ WebAuthn: `webauthn-rs` — ekosistemin en güçlü noktası

`webauthn-rs 0.5.5` (2026-04-30) incelendi.

- **SUSE product security denetiminden geçmiş**
- WebAuthn **Level 3**, FIDO MDS attestation, `AttestationCaList`
- Hijyen: `danger-allow-state-serialisation`, `danger-credential-internals` gibi açıkça "tehlikeli" işaretli feature'lar
- **Kanidm ekibinin ürünü** — gerçek IdP'de üretimde; Rauthy de kullanıyor

⚠️ **İki gerçek sınır (kaynak koddan):**
1. **Conditional UI stabil değil:** `preview-features = ["conditional-ui"]` arkasında
2. **PRF extension YOK.** `grep -i prf` proto crate'inde boş döndü. CTAP seviyesinde `hmac-secret` var ama WebAuthn seviyesinde PRF yok

`resident-key-support` de ayrı, varsayılan-kapalı feature.

**Kalan iş:** kimlik bilgisi yaşam döngüsü, cihaz adlandırma, kurtarma akışları, **RP ID / origin çok kiracılık eşlemesi** (çok kiracılıkta sinsi zor).

#### 3.4 🟠 SAML: 2025'te boşluktu, 2026'da doldu — ama çok taze

**`samael` 0.0.22** (2026-07-07) kaynağı:
- `default = ["xmlsec"]` → `libc`, `lazy_static`, **`libxml`** (C libxml2)
- `src/crypto/xmlsec/wrapper/` → `xmlSecDSigCtxCreate` **ham FFI**
- xmlsec kapatılırsa `crypto_disabled.rs` → **imza doğrulama hiç olmaz**

**Sürpriz iyi haber:** samael'in **XSW savunması gerçekten güçlü.** `ReduceMode::ValidateAndMarkNoAncestors` **varsayılan** — imza doğrulandıktan sonra belge, imzalanmamış her şey silinerek yeniden inşa ediliyor. Bu, "iki farklı parser arasındaki fark" kök nedenini yapısal olarak kapatan **altın standart**. Ayrıca yinelenen-ID reddi, NCName kontrolü, `allowed_signature_algorithms` allowlist'i, gerçek saldırı test vektörleri.

🔴 **İki ciddi kusur:**
1. **`libxml = "=0.3.3"` (2023-07-18) tam sürüm sabitlemesi.** Güncel 0.3.21 — **3 yıl, 18 sürüm geride**, `=` olduğu için `cargo update` asla ilerletmez
2. **libxml2'nin altı çöküyor.** 2026-09-05'te **8 yeni CVE**; **CVE-2026-86144**: `xmlXIncludeProcess` `XML_PARSE_NONET` yaymıyor → **XXE/SSRF**. libxml2 README: ***"It's NOT recommended to use this software to process untrusted data."***

**Saf-Rust alternatif (2026'da doğdu):** `bergshamra` ailesi (Kushal Das) — `bergshamra-c14n` inclusive + **exclusive c14n + InclusiveNamespaces PrefixList**, `bergshamra-dsig` `#![forbid(unsafe_code)]`, koşulsuz yinelenen-ID reddi, `trusted_keys_only: true` / `strict_verification: true` varsayılanları, **xmlsec test suite 1148/1148**. Üstünde `gamlastan` SAML katmanı — ancak onun SPID uyum iddiası kendi beyanıdır ve o süit IdP'leri değil SP'leri test ettiği için Argus açısından kanıt değildir.

⚠️ **~80.000 satır, 6 aylık, tek kişi, bağımsız denetim yok, 6–11 yıldız.**

🔴 **crates.io isim-işgali tuzağı:** `saml-rs`, `opensaml`, `samlify`, `rustsaml`, `samlet`, `rust-saml`, `rustauth-saml` — **8 crate, tek sahip (`salasebas`), beyan edilen repo 404.** Hiçbirini kullanma.

**Bağlamsal sinyal:** Kanidm SAML'i **kalıcı olarak reddediyor** (19 Ara 2025): *"the security risks and feature scope of implementing SAML is too great and we should commit to not supporting it."*

**Perspektif — bu Rust sorunu değil, SAML sorunu:** crewjam/saml (Go, 10 yaşında) **8 advisory**; gosaml2 **12**; ruby-saml 2025'te tek yılda **5**.

**Asimetri kritik:** IdP tarafı (imza **üretmek**) belirgin kolay ve güvenli — girdi kendinin. SP tarafı (**doğrulamak**) düşmanca girdi işler. **Biz IdP yazıyoruz → SAML'in kolay yarısındayız.**

#### 3.5 🟠 LDAP sunucu

`ldap3_proto 0.8.1` (2026-08-14, Kanidm ekibi) — durum sanılandan iyi:
- **`LdapOp` protokol katmanı TAM:** Bind, Unbind, Search, Modify, Add, Del, ModifyDN, Compare, Abandon, Extended, Intermediate
- Gerçek tokio `Encoder`/`Decoder` codec'i
- ⚠️ **`ServerOps` kolaylık katmanı sadece okuma**
- ⚠️ **SASL:** tip var, **mekanizma implementasyonu yok**

**Kanidm'in gerçeği (klonlanıp ölçüldü):** LDAP implementasyonu **3.227 satır**, dokümantasyon *"read-only LDAP interface"* diyor. StartTLS bile yok (bilinçli).

**Efor: 9–15 geliştirici-ayı** (tam read-write + SASL). **Go'da da bedava değil** — GLAuth (2.8k yıldız) da ağırlıklı okuma. **Bu katmanda Rust'ın dezavantajı küçük.**

#### 3.6 🟠 SCIM

| Crate | Sürüm | Durum |
|---|---|---|
| `scim_v2` | 0.5.0 (2026-09-07) | **En iyisi** |
| `scim_proto` | 1.11.1 (2026-08-14) | Kanidm'in |
| `scim-server` | 0.5.3 (2025-09-21) | 1 yıl bayat, garip `rust-mcp-sdk` bağımlılığı |

`scim_v2 0.5.0` kaynağı: User/Group/EnterpriseUser/ResourceType modelleri, validation, ve **LALRPOP tabanlı gerçek SCIM filter parser** (RFC 7644 §3.4.2.2) — işin en zor kısmı çözülmüş.

**Yok olan:** endpoint'ler, PATCH semantiği, ETag/versiyonlama, bulk, `/Me`, persistence. **İşin ~%30-40'ı hazır. Efor: 4–6 geliştirici-ayı.**

---

### 4. Veri katmanı

| Seçenek | Sürüm | Karar |
|---|---|---|
| **sqlx** | 0.9.0 (2026-05-21) | ✅ **SEÇ** |
| tokio-postgres + deadpool | 0.7.18 / 0.14.2 | ✅ Sıcak yol için |
| diesel + diesel-async | 2.3.13 / 0.9.2 | ⚠️ 2026'da 6 advisory |
| sea-orm | 2.0.2 | ❌ Gereksiz katman |

**sqlx yönetişim bulgusu (CHANGELOG'dan birebir):**
> *"SQLx has not been owned or maintained by LaunchBadge, LLC. for a few years now, and has since been informally transferred to the collective ownership of its principal authors."*

Depo **github.com/transact-rs/sqlx**'e taşındı. Aktif ama **release kadansı yavaş**: yılda bir major.

**Compile-time query checking'in gerçek maliyeti:** `.sqlx/` dizini commit edilmeli; şema değişiminde her PR'da regenerate; derleme süresine ek. **Tavsiye: `query!` makrolarını sadece karmaşık sorgularda kullan**, sıcak yol için elle prepared statement + `query_as`.

⚠️ **diesel 2026'da 6 advisory aldı.** **RUSTSEC-2026-0136 (`COPY FROM`/`COPY TO` command injection) Postgres'i etkiler.** 2.3.8+ kullan.

**Bonus:** sqlx 0.9'un `sqlx.toml`'u `_sqlx_migrations` tablosunu yeniden adlandırmayı ve çoklu şemayı destekliyor.

**pgbouncer gerekli mi?** Tek instance için gereksiz. Çok instance'ta gerekir — **ama transaction mode + prepared statement çakışmasına dikkat.**

---

### 5. Prior art — gerçek Rust IdP'leri (klonlanıp ölçüldü)

| | **Kanidm** | **Rauthy** |
|---|---|---|
| Satır sayısı | **224.718** / 458 dosya | **84.242** / 331 dosya |
| Yaş | 7,5 yıl (Şub 2019) | 3,2 yıl (Tem 2023) |
| Son sürüm | v1.11.1 (2026-08-14) | **v0.36.2** (2026-08-08) — hâlâ 0.x |
| Depolama | **SQLite + kendi IDL/ARC cache** | **Hiqlite** (SQLite+openraft) veya Postgres |
| Web | axum | actix-web |
| HA | Eventually consistent, **maks 2 node** | Raft, N node |
| OIDC/OAuth2 | ✅ Kapsamlı | ✅ **Çok kapsamlı** (device flow, DPoP, DCR, backchannel logout, token exchange, resource indicators, FedCM) |
| **SAML** | ❌ (kalıcı red) | ❌ |
| LDAP | ⚠️ **Sadece okuma** (3.227 satır) | ❌ |
| SCIM | ⚠️ Sadece **gelen** | ⚠️ Sadece **giden** |
| WebAuthn | ✅ L3 + MDS | ✅ + resident keys |
| Bağımsız denetim | ❌ | ✅ **Radically Open Security / NGI Zero** |
| 12 aylık advisory | **10** (1 Critical) | 2 |
| Bus factor | ~1,5 (Firstyear 412/1000) | **1,0** (sebadob ~%89) |

#### Öğrenilecek 4 ders

**1. Kanidm Postgres kullanmadı — bilinçliydi.** `server/lib/src/be/`: `idl_sqlite.rs` (SQLite/rusqlite, WAL) → `idl_arc_sqlite.rs` (concread ARCache) → query server. IDL bitmap indeksleri + ARC cache.
> **Ders: IdP iş yükü ilişkisel join değil, indeksli entry lookup'tır. Depolama motorunu yazma, ama üstündeki index/cache katmanını sen yazman gerekebilir.**

**2. Tek yazıcı + kilitlenmeyen okuyucu doğru trade-off, ama replikasyonu baştan belirler.** Kanidm COW mimarisi yüzünden 2 node'da tıkandı. **Raft istiyorsan Rauthy gibi baştan koy.**

**3. Rust'ın bellek güvenliği güvenlik bütçenin küçük kısmını kapatır.** Kanidm'in 2026'daki 10 advisory'sinin **hiçbiri buffer overflow değil**: parser stack exhaustion (×3, biri incomplete fix), non-constant-time secret karşılaştırma, XSS, ve **Critical seviyede authenticated arbitrary write**.

Somut kural seti: her parser'a **decode'dan önce** derinlik+uzunluk limiti, tüm secret karşılaştırmalarında `subtle`, erişim kontrolü için property-based test.

**4. Rauthy'nin 84k satırı, tek kişinin 3 yılda yazdığı OIDC-only bir IdP'dir.** Bizim hedefimiz onun üstüne SAML + LDAP + SCIM + çok kiracılık ekliyor.

**Ayrıca:** authentik (Python) 2026'da bileşenlerini **Rust'a taşımaya başladı** (2026.5 worker, 2026.8 server + proxy outpost).

---

### 6. Acımasız değerlendirme

#### 6.1 Rust'ın Go'ya göre gerçek maliyeti: ~1.5–2x

| Katman | Rust | Go | Çarpan | Neden |
|---|---|---|---|---|
| HTTP/TLS/kripto | 1.0x | 1.0x | **1.0** | Rust **daha iyi** (PQ, FIPS) |
| **OAuth2/OIDC AS** | **12–18 ay** | **3–5 ay** | **🔴 3–4x** | **Fosite yok** |
| SAML (IdP tarafı) | 6–10 ay | 4–6 ay | 1.5x | samael/gamlastan var |
| LDAP sunucu | 9–15 ay | 7–12 ay | 1.2x | İki dilde de el işi |
| SCIM | 4–6 ay | 3–5 ay | 1.2x | filtre parser'ı yardım ediyor |
| WebAuthn | 2–3 ay | 2–3 ay | **1.0** | webauthn-rs ≈ go-webauthn |
| Çok kiracılık/admin/ops | 12–18 ay | 12–18 ay | **1.0** | Her dilde sıfırdan |
| **TOPLAM** | **~46–73 ay** | **~31–49 ay** | **~1.5x** | |

**Toplam efor: 4–6 geliştirici-yılı çekirdek; sertleştirme + sertifikasyon + operasyonel olgunlukla gerçekçi olarak 6–10 geliştirici-yılı.**

Kalibrasyon: Rauthy = 84k satır / 3 yıl / 1 kişi, sadece OIDC. Kanidm = 225k satır / 7,5 yıl / ~2 kişi, SAML yok.

**Kritik nüans: Rust'ın maliyeti "dil zorluğu"ndan gelmiyor.** Borrow checker'ın vergisi bu ölçekte %10-15 ve derleyicinin yakaladığı hatalarla fazlasıyla geri ödenir. **Maliyetin tamamı bir kütüphanenin yokluğu: Fosite.**

#### 6.2 Katman sınıflandırması

| ✅ HAZIR | ⚠️ KULLAN AMA DİKKAT | 🔴 BOŞLUK — YAZ | ❌ RUST'TA YAPMA |
|---|---|---|---|
| rustls 0.23 (PQ varsayılan) | jsonwebtoken (**`aws_lc_rs` şart**) | **OAuth2/OIDC AS** | HTTP/3 (h3) |
| aws-lc-rs (FIPS, ML-KEM/DSA) | argon2 (**ARM'da NEON yok**) | LDAP sunucu semantiği + SASL | ntex / poem |
| axum + hyper + tower | samael (**C libxml2 + `=0.3.3` pin**) | SCIM endpoint/PATCH/bulk | `rsa` crate'i (Marvin) |
| webauthn-rs (PRF hariç) | bergshamra/gamlastan (**6 aylık, tek kişi**) | Çok kiracılık modeli | `openidconnect` (sunucu için) |
| sqlx / tokio-postgres | ldap3_proto (codec var, semantik yok) | Consent/session/logout | josekit (C OpenSSL) |
| tokio (Argon2 izole) | diesel (2.3.8+) | Admin API + policy engine | `salasebas` SAML crate'leri |

#### 6.3 Rust'ın kötü fikir olduğu yerler

1. **HTTP/3** — h3 16 aydır durgun, faydası sıfır
2. **`rsa` crate'i ile RSA** — belgelenmiş, düzeltilmemiş timing sidechannel
3. **Saf-Rust XML güvenliği ile *SP tarafı*** — biz IdP'yiz, az etkileniyoruz
4. **Framework'te "en hızlısını" kovalamak** — ntex'in 76 ters bağımlılığı kazandığı mikrosaniyelerden pahalı

#### 6.4 Hibrit yaklaşım: dil hibriti değil, süreç hibriti

🔴 **Yanlış kısım — SAML'i ayrı DİLE taşımak.** Kazanç düşük: Rust'ta zaten yapılabiliyor ve **biz IdP tarafındayız = SAML'in kolay yarısı**. Ayrıca SAML assertion üretmek kullanıcı/oturum/consent durumuna sıkı bağlı — süreç sınırına koymak dağıtık durum problemi yaratır. **Kazanç < maliyet.**

✅ **Doğru kısım — LDAP'ı ayırmak.** Farklı protokol yüzeyi, farklı port, farklı tehdit modeli, **sadece-okuma** konumlandırılabilir. **Ama Go'da yazmaya gerek yok** — `ldap3_proto` işi görüyor.

✅✅ **Asıl doğru hibrit:**
- **Çekirdek (Rust):** OIDC/OAuth2 AS + WebAuthn + kullanıcı/oturum/policy + admin API. Tek süreç, tek veri modeli
- **Kenar gateway'ler (yine Rust, ayrı süreç):** LDAP-ro, SAML-IdP, RADIUS. Çekirdeği iç API üzerinden tüketirler. Blast radius izole

**Değerlendirilmesi gereken alternatif:** Fosite'ı sarmalayan bir Go süreci? 12–18 aylık en büyük riski ortadan kaldırır. Karşılığında protokol sınırında güven sınırı ve iki dilli operasyon yükü. **Tavsiye edilmez** — OAuth AS tam olarak IdP'nin kalbidir ve dışarıda tutmak geri kalanı kabuğa indirger. Ama dürüstçe hesaplanmalı.

#### 6.5 En riskli üç alan

**🥇 1. OAuth2/OIDC AS'in sıfırdan yazılması.** 12–18 ay ve **hataların doğrudan kimlik doğrulama atlatması demek**. Azaltma: OpenID Foundation sertifikasyon test suite'ini **1. günden** CI'a koy; PKCE S256'yı zorunlu, implicit/ROPC'yi mümkün kılma; refresh reuse detection'ı baştan tasarla.

**🥈 2. Tek-bakımcı yığın riski, üst üste binen katmanlarda.** webauthn-rs, ldap3_proto, concread → **hepsi Kanidm ekibi**. bergshamra + uppsala + gamlastan + kryptering → **hepsi tek kişi**. samael → 1 aktif bakımcı + 3 yıl geride pinlenmiş C kütüphanesi. **Bunlar bağımsız değil, korele riskler.** Azaltma: `cargo vendor`, fork kapasitesi, `cargo-audit` + `cargo-deny` CI'da bloklayıcı.

**🥉 3. SAML'in altındaki C yığını (libxml2).** 2026-09-05'te 8 yeni CVE; CVE-2026-86144 XXE/SSRF; kütüphanenin kendi README'si "güvenilmeyen veri için önerilmez". Azaltma: **ayrı, en az yetkili, sandbox'lı süreç**; libxml2 2.15.4+; samael fork'layıp pin güncelle; **veya SAML'i hiç destekleme.**

---

### 7. Tavsiye edilen yığın

```toml
# Runtime
axum = "0.8"                 # + tower-http
tokio = { version = "1.53", features = ["full"] }

# TLS — PQ varsayılan açık, FIPS'e hazır
rustls = { version = "0.23", features = ["fips"] }   # aws-lc-rs varsayılan provider

# JOSE — aws_lc_rs ŞART, rust_crypto ASLA
jsonwebtoken = { version = "11", default-features = false,
                 features = ["use_pem", "aws_lc_rs"] }

webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
argon2 = { version = "0.6", features = ["parallel"] }   # ARM'da NEON yok — ölç
sqlx = { version = "0.9", features = ["postgres", "runtime-tokio-rustls"] }
ldap3_proto = "0.8"          # sadece codec; semantik bizim
scim_v2 = "0.5"              # model + filtre parser; endpoint bizim
# samael = "0.0.22"          # SAML gerekiyorsa; ayrı süreçte, fork'layıp libxml pinini güncelle
```

---

### 8. Son söz

**Rust'ı seç — ama gerekçeyi düzelt.** "Maksimum performans" doğru gerekçe değil: darboğaz Argon2 ve RSA, ikisi de dilden bağımsız.

**Doğru gerekçe kripto ve TLS katmanının Go'dan iyi olması** (rustls'te PQ varsayılan açık, aws-lc-rs'te FIPS + ML-DSA, tip sistemiyle zorlanan algoritma-ailesi ayrımı) ve **bellek güvenliğinin bir IdP'de gerçekten önemli olması.**

İki illüzyonu bırak:
1. **Rust bellek güvenliği veriyor, güvenlik vermiyor.** Kanidm'in 2026'daki 10 advisory'sinin hiçbiri buffer overflow değildi. Bir Critical *authenticated arbitrary write*'ı hiçbir borrow checker durdurmaz.
2. **Fosite'ın yokluğu 12–18 aylık gerçek bir vergidir** ve bu projenin en büyük tek riskidir.

**Kanidm 7,5 yılda 225 bin satır yazdı ve SAML'i kasıtlı reddediyor. Rauthy 3 yılda 84 bin satır yazdı ve sadece OIDC yapıyor.** İkisi de bizim hedeflediğimizden dar kapsamda. **Kapsamı faz faz kesmek zorundayız.**
