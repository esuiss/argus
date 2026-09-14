# §5 — Rust ekosistemi fizibilitesi

Bu dosyanın yöntemi şudur: crates.io API'si, api.osv.dev, GitHub API ve atom akışları, crate kaynak kodlarının indirilip incelenmesi ile Kanidm ve Rauthy'nin klonlanıp ölçülmesi.

---

## 0. Net cevap

Rust bu iş için hazırdır, ancak beklenen yerlerde değil.

Beklenen hikâye Rust'ın hızlı olduğu ama kütüphanesinin bulunmadığıydı. Gerçek bunun tersidir: altyapı katmanı — TLS, kripto, HTTP, veritabanı — Go'dan iyi durumdadır. Boşluk tam olarak protokol sunucu katmanındadır ve orası işin %70'idir.

| Katman | Karar |
|---|---|
| TLS, kripto, post-quantum | Rust burada Go'yu geçmektedir: rustls'te PQ varsayılan açık, aws-lc-rs'te FIPS ve ML-DSA |
| HTTP ve runtime | Hazır: axum, hyper 1.x, tower |
| WebAuthn ve passkey | Hazır; ekosistemin en güçlü noktası |
| JOSE ve JWT | Hazır, ancak tek bir feature bayrağı belirleyici |
| Veri katmanı | Hazır; yönetişim uyarısıyla birlikte |
| OAuth2 ve OIDC Authorization Server | Boşluk; Fosite karşılığı bulunmamaktadır |
| SAML | 2025'te boşluktu, 2026'da dolmuştur ancak çok tazedir ve kırılgandır |
| LDAP sunucu | Wire protokolü mevcuttur, sunucu semantiği yoktur |
| SCIM | Model ve filtre mevcuttur, sunucu yoktur |
| Çok kiracılık | Her dilde sıfırdan yazılır |

Rust ile Go arasındaki maliyet çarpanı yaklaşık 1,5-2 katıdır ve farkın neredeyse tamamı tek bir kalemden, Fosite'ın yokluğundan gelmektedir.

---

## 1. Web ve runtime

Sürümler crates.io API'sinden 8 Eylül 2026'da çekilmiştir.

| Kütüphane | Sürüm | Tarih | Olgunluk | Karar |
|---|---|---|---|---|
| axum | 0.8.9 | 14 Nisan 2026 | 5 | Seçilir |
| hyper | 1.11.1 | 28 Ağustos 2026 | 5 | Axum altında kullanılır |
| tower-http | 0.7.1 | 31 Ağustos 2026 | 5 | Kullanılır |
| tokio | 1.53.1 | 20 Temmuz 2026 | 5 | Argon2 izolasyonuyla kullanılır |
| actix-web | 4.15.0 | 21 Ağustos 2026 | 4 | CVE-2026-73051 nedeniyle dikkat gerekir |
| ntex | 3.12.3 | 7 Eylül 2026 | 2 | Kullanılmaz |
| poem | 3.1.12 | 28 Temmuz 2025 | 2 | Kullanılmaz; 13 aydır sürüm çıkmamıştır |
| h3 (HTTP/3) | 0.0.8 | 6 Mayıs 2025 | 1 | Kullanılmaz; 16 aydır durgundur |

### 1.1 Kararın dayanağı: benchmark değil, ekosistem kütlesi

TechEmpower sayıları bir IdP için anlamsızdır; istek bütçesinin %95'i Argon2'de (50-100 ms) ve imzalamada geçer, framework overhead'i mikrosaniye mertebesindedir.

crates.io ters bağımlılık sayıları şöyledir:

| axum | actix-web | ntex |
|---|---|---|
| 8.508 | 1.695 | 76 |

ntex'in benchmark üstünlüğü gerçektir ancak darboğaz değildir; ekosistem yoksunluğu ise her gün maliyet üretir.

**actix güvenlik geçmişi.** CVE-2026-73051 (HTTP/1.1 CL.TE request smuggling) 3.12.1'de düzelmiştir. Ayrıca 2018'de RUSTSEC-2018-0019 (çoklu bellek güvenliği), 2020'de use-after-free ve 2021'de smuggling açıkları görülmüştür. hyper'ın da geçmişi vardır ancak 2022'den beri temizdir.

**HTTP/3.** h3 16 aydır durgundur; bir IdP'nin ihtiyacı yoktur ve TLS terminasyonu yapan proxy isterse sağlar.

---

## 2. TLS ve kripto

Bu katman Rust'ın Go'yu açık ara geçtiği yerdir.

| Kütüphane | Sürüm | Tarih | Karar |
|---|---|---|---|
| rustls | 0.23.44 | 7 Eylül 2026 | Seçilir |
| aws-lc-rs | 1.18.1 | 1 Eylül 2026 | Seçilir; varsayılan provider'dır |
| ring | 0.17.14 | 11 Mart 2025 | Kaçınılır |
| rsa (RustCrypto) | 0.9.10 ve 0.10.0-rc.18 | 27 Nisan 2026 | Kullanılmaz |

### 2.1 rustls: post-quantum varsayılan olarak açık

rustls 0.23.44 dokümantasyonuna göre `prefer-post-quantum` özelliği varsayılan olarak etkindir ve X25519MLKEM768 kullanarak post-quantum güvenli anahtar değişimini önceliklendirir. Varsayılan provider aws-lc-rs'tir.

Bu, Go'nun crypto/tls paketinden ileri bir konumdur.

### 2.2 aws-lc-rs

`aws-lc-rs-1.18.1` tarball'ı açılıp incelenmiştir. `src/kem.rs` ML_KEM_512, 768 ve 1024'ü; `src/pqdsa.rs` ML_DSA_44, 65 ve 87'yi tanımlar. `fips` özelliği `aws-lc-fips-sys` üzerinden AWS-LC-FIPS 4.x'i devreye alır.

> **FIPS konusunda abartılmaması gereken nokta.** lib.rs'in kendi ifadesine göre kütüphane FIPS doğrulama testini tamamlamış ve sertifikasyon için NIST'e sunulmuştur; sertifika beklemededir. Ayrıca FIPS build'i CMake ve Go gerektirir.

### 2.3 `rsa` crate'i hâlâ Marvin'e açık

RUSTSEC-2023-0071 ve CVE-2023-49092 kayıtlarında OSV sorgusunda düzeltilmiş sürüm alanı boştur. Advisory'nin son güncellemesi 25 Nisan 2026'dır. README'nin kendi ifadesine göre crate Marvin saldırısına açıktır ve bu, ağ üzerindeki bir saldırganın özel anahtarı kurtarmasına imkân verebilir.

Proje "Phase 1: Make it work" olarak işaretlidir. 0.10 hâlâ rc.18 aşamasındadır.

Kural şudur: RSA hiçbir zaman `rsa` crate'i ile yapılmaz, aws-lc-rs kullanılır.

### 2.4 ring

0.17.14 sürümü 11 Mart 2025 tarihlidir; 18 aydır yeni sürüm çıkmamıştır. README projeyi bir deney olarak tanımlar. aws-lc-rs zaten ring API'siyle uyumludur.

### 2.5 Argon2

`argon2-0.6.0` kaynağı incelenmiştir:

```
src/lib.rs:194   cpufeatures::new!(avx2_cpuid, "avx2");
src/lib.rs:530   #[target_feature(enable = "avx2")]
src/lib.rs:531   unsafe fn compress_avx2(...)
```

AVX2 runtime dispatch mevcuttur. 0.6.0 (27 Ağustos 2026) ayrıca rayon tabanlı `parallel` özelliğini eklemiştir.

> **Uyarı.** NEON desteği yoktur; `grep -i neon` boş dönmüştür. ARM üzerinde, yani Graviton ve Ampere'de skaler yola düşülür. ARM hedefleniyorsa `argon2-kdf` (C binding) ile kendi donanımında ölçüm yapılmalıdır.

---

## 3. Auth'a özel kütüphaneler

Bu bölüm dosyanın en kritik kısmıdır.

### 3.1 OAuth 2.1 Authorization Server: gerçek boşluk

Fosite'ın Rust karşılığı bulunmamaktadır. Kanıtlar kaynak kodundan gelmektedir.

**`openidconnect` 4.0.1 bir istemcidir, sunucu değildir.** `lib.rs:267`'deki ifadeye göre kütüphane, credential ve oturum yönetimi gibi işlevler gerektiren eksiksiz bir OpenID Connect Provider implementasyonu sunmamaktadır. Üstelik `rsa ^0.9.2`'ye zorunlu bağımlıdır ve Marvin'i miras alır.

**`oxide-auth` 0.6.1'in son sürümü 2 Haziran 2024 tarihlidir.** Bağımlılıkları `hmac`, `sha2`, `rust-argon2`, `subtle` ve `rmp-serde`'dir. Asimetrik kripto hiç bulunmaz, dolayısıyla `id_token` imzalayamaz ve OIDC yapamaz. Bakımcısı projeyi tek başına ve sınırlı zamanla sürdürdüğünü belirtmektedir. Ters bağımlılık sayısı 14'tür; sekiz yıllık bir crate'in 14 kullanıcısı olması fiilen kullanılmadığının kanıtıdır.

**Karşılaştırma.** Go tarafındaki Fosite 2.600 yıldıza sahiptir ve aktiftir; RFC 6749, 6819, 7636, 8252 ve 9126 ile OIDC Core'u hazır verir.

**Yazılması gerekenler**, yani Fosite'ın ücretsiz verdikleri: authorization code ve PKCE (S256), refresh rotation ile reuse detection, client_credentials, device grant (RFC 8628), token exchange (RFC 8693), introspection (7662), revocation (7009), PAR (9126), JAR (9101), DPoP (9449), Discovery ve JWKS, DCR, sektör bazlı `sub`, pairwise identifier, consent ve session yönetimi, back-channel ve front-channel logout, OAuth 2.1 sıkılaştırmaları.

Efor 12-18 geliştirici-ayıdır.

### 3.2 JOSE ve JWT: `jsonwebtoken` 11

`jsonwebtoken-11.0.0` kaynağı incelenmiştir. Güvenlik tasarımı gerçekten iyidir.

| Savunma | Durum | Kanıt |
|---|---|---|
| `alg: none` | Enum'da hiç bulunmaz | `algorithms.rs` |
| HMAC ile RSA karışıklığı | Tip düzeyinde engellenir | `jws.rs:42`, `key.family() != header.alg.family()` |
| Algoritma allowlist'i | Zorunludur | `decoding.rs:278` |
| CVE-2026-25537 (type confusion) | Düzeltilmiştir | `validation.rs:271` ve `274` |
| Varsayılanlar | `validate_exp=true`, `validate_aud=true`, `exp` zorunlu, leeway 60 sn | `validation.rs:119` |

> **Uyarı.** `validate_nbf` varsayılan olarak `false`'tur; bir IdP'de açılmalıdır.

Kader belirleyen satırlar şunlardır:

```
default = ["use_pem"]                 # kripto backend yok
rust_crypto = [..., "dep:rsa", ...]   # Marvin'e açık
aws_lc_rs = ["dep:aws-lc-rs"]         # güvenli
```

Crate `features = ["aws_lc_rs"]` ile kullanılır. `rust_crypto` doğrudan Marvin timing yan kanalına bağlar.

| Crate | Backend | Değerlendirme |
|---|---|---|
| jsonwebtoken 11.0.0 | aws-lc-rs veya rsa | Seçilir; `aws_lc_rs` ile |
| jwt-simple 0.13.1 | superboring veya boring | İyi tasarımdır (jedisct1), niştir |
| josekit 0.10.3 | openssl ^0.10.68 | Kullanılmaz; C OpenSSL, 28 advisory, 2026'da altı tanesi |
| biscuit 0.8.0 | ring ~0.17.13 | Duran backend nedeniyle dikkat gerekir |
| openidconnect 4.0.1 | rsa zorunlu | Kullanılmaz |

### 3.3 WebAuthn: `webauthn-rs`

Ekosistemin en güçlü noktasıdır. `webauthn-rs 0.5.5` (30 Nisan 2026) incelenmiştir.

Kütüphane SUSE product security denetiminden geçmiştir. WebAuthn Level 3, FIDO MDS attestation ve `AttestationCaList` destekler. Hijyen açısından `danger-allow-state-serialisation` ve `danger-credential-internals` gibi açıkça tehlikeli olarak işaretlenmiş özellikler sunar. Kanidm ekibinin ürünüdür ve gerçek bir IdP'de üretimdedir; Rauthy de kullanmaktadır.

> **İki gerçek sınır, kaynak koddan doğrulanmıştır.** Conditional UI stabil değildir ve `preview-features = ["conditional-ui"]` arkasındadır. PRF extension bulunmamaktadır; `grep -i prf` proto crate'inde boş dönmüştür, CTAP seviyesinde `hmac-secret` vardır ancak WebAuthn seviyesinde PRF yoktur.

`resident-key-support` de ayrı ve varsayılan olarak kapalı bir özelliktir.

**Kalan iş.** Kimlik bilgisi yaşam döngüsü, cihaz adlandırma, kurtarma akışları ve RP ID ile origin'in çok kiracılığa eşlenmesi. Sonuncusu çok kiracılıkta sinsi biçimde zordur.

### 3.4 SAML: 2025'te boşluktu, 2026'da doldu

**`samael` 0.0.22** (7 Temmuz 2026) kaynağında `default = ["xmlsec"]` tanımı `libc`, `lazy_static` ve C libxml2'yi saran `libxml`'i çeker. `src/crypto/xmlsec/wrapper/` altında `xmlSecDSigCtxCreate` ham FFI ile çağrılır. xmlsec kapatılırsa `crypto_disabled.rs` devreye girer ve imza doğrulama hiç yapılmaz.

**Sürpriz iyi haber.** samael'in XSW savunması gerçekten güçlüdür. `ReduceMode::ValidateAndMarkNoAncestors` varsayılandır; imza doğrulandıktan sonra belge, imzalanmamış her şey silinerek yeniden inşa edilir. Bu, iki farklı parser arasındaki farkı kök nedeninden kapatan altın standarttır. Ayrıca yinelenen ID reddi, NCName kontrolü, `allowed_signature_algorithms` allowlist'i ve gerçek saldırı test vektörleri bulunur.

**İki ciddi kusur.** Birincisi `libxml = "=0.3.3"` (18 Temmuz 2023) biçiminde tam sürüm sabitlemesidir; güncel sürüm 0.3.21'dir, yani üç yıl ve 18 sürüm geridedir ve `=` kullanıldığı için `cargo update` asla ilerletmez. İkincisi libxml2'nin altının çökmesidir: 5 Eylül 2026'da sekiz yeni CVE yayımlanmıştır ve CVE-2026-86144'te `xmlXIncludeProcess` `XML_PARSE_NONET` bayrağını yaymadığı için XXE ve SSRF mümkün olmaktadır. libxml2 README'si bu yazılımın güvenilmeyen veriyi işlemek için önerilmediğini belirtmektedir.

**Saf Rust alternatifi.** 2026'da doğan `bergshamra` ailesi Kushal Das tarafından geliştirilmektedir. `bergshamra-c14n` inclusive ve exclusive c14n ile InclusiveNamespaces PrefixList destekler; `bergshamra-dsig` `#![forbid(unsafe_code)]` bildirir, koşulsuz yinelenen ID reddi uygular ve `trusted_keys_only: true` ile `strict_verification: true` varsayılanlarını kullanır; xmlsec test süitinden 1148/1148 geçer. Üstünde `gamlastan` SAML katmanı bulunur; ancak onun SPID uyum iddiası kendi beyanıdır ve o süit IdP'leri değil SP'leri test ettiği için Argus açısından kanıt değildir.

> **Uyarı.** `bergshamra` ailesi yaklaşık 80.000 satırdır, altı aylıktır, tek kişi tarafından geliştirilmektedir, bağımsız denetimi yoktur ve 6-11 yıldıza sahiptir.

> **crates.io isim işgali tuzağı.** `saml-rs`, `opensaml`, `samlify`, `rustsaml`, `samlet`, `rust-saml` ve `rustauth-saml` adlı sekiz crate tek bir sahibe (`salasebas`) aittir ve beyan edilen repo 404 vermektedir. Hiçbiri kullanılmaz.

**Bağlamsal sinyal.** Kanidm SAML'i kalıcı olarak reddetmektedir; 19 Aralık 2025 tarihli açıklamaya göre SAML implementasyonunun güvenlik riskleri ve özellik kapsamı fazla büyüktür ve proje desteklememeye karar vermiştir.

**Perspektif.** Bu bir Rust sorunu değil, SAML sorunudur. Go tarafında on yaşındaki crewjam/saml sekiz advisory, gosaml2 on iki advisory almıştır; ruby-saml 2025'te tek yılda beş advisory almıştır.

**Kritik asimetri.** IdP tarafı, yani imza üretmek, belirgin biçimde kolay ve güvenlidir çünkü girdi kendi üretimimizdir. SP tarafı, yani doğrulamak, düşmanca girdi işler. Argus bir IdP yazdığı için SAML'in kolay yarısındadır.

### 3.5 LDAP sunucu

`ldap3_proto 0.8.1` (14 Ağustos 2026, Kanidm ekibi) sanılandan iyi durumdadır. `LdapOp` protokol katmanı tamdır: Bind, Unbind, Search, Modify, Add, Del, ModifyDN, Compare, Abandon, Extended ve Intermediate. Gerçek bir tokio `Encoder` ve `Decoder` codec'i bulunur.

> **İki sınır.** `ServerOps` kolaylık katmanı yalnızca okuma sağlar. SASL için tip tanımı vardır ancak mekanizma implementasyonu yoktur.

**Kanidm'in gerçeği.** Proje klonlanıp ölçülmüştür: LDAP implementasyonu 3.227 satırdır ve dokümantasyon bunu salt okunur bir LDAP arayüzü olarak tanımlar. StartTLS bile bilinçli olarak bulunmaz.

Efor tam read-write ve SASL için 9-15 geliştirici-ayıdır. Bu iş Go'da da ücretsiz değildir; 2.800 yıldızlı GLAuth da ağırlıklı olarak okuma sunar. Bu katmanda Rust'ın dezavantajı küçüktür.

### 3.6 SCIM

| Crate | Sürüm | Durum |
|---|---|---|
| `scim_v2` | 0.5.0 (7 Eylül 2026) | En iyisi |
| `scim_proto` | 1.11.1 (14 Ağustos 2026) | Kanidm'in crate'i |
| `scim-server` | 0.5.3 (21 Eylül 2025) | Bir yıl bayattır ve garip bir `rust-mcp-sdk` bağımlılığı taşır |

`scim_v2 0.5.0` kaynağında User, Group, EnterpriseUser ve ResourceType modelleri, validation ve LALRPOP tabanlı gerçek bir SCIM filter parser'ı (RFC 7644 §3.4.2.2) bulunmaktadır; işin en zor kısmı çözülmüştür.

Eksik olanlar endpoint'ler, PATCH semantiği, ETag ve versiyonlama, bulk, `/Me` ve persistence'tır. İşin yaklaşık %30-40'ı hazırdır ve efor 4-6 geliştirici-ayıdır.

---

## 4. Veri katmanı

| Seçenek | Sürüm | Karar |
|---|---|---|
| sqlx | 0.9.0 (21 Mayıs 2026) | Seçilir |
| tokio-postgres ve deadpool | 0.7.18 ve 0.14.2 | Sıcak yol için kullanılır |
| diesel ve diesel-async | 2.3.13 ve 0.9.2 | 2026'da altı advisory almıştır |
| sea-orm | 2.0.2 | Gereksiz katmandır |

**sqlx yönetişim bulgusu.** CHANGELOG'daki ifadeye göre SQLx birkaç yıldır LaunchBadge, LLC tarafından sahiplenilmemekte veya sürdürülmemektedir ve gayriresmî olarak başlıca yazarlarının kolektif sahipliğine devredilmiştir.

Depo github.com/transact-rs/sqlx adresine taşınmıştır. Proje aktiftir ancak release kadansı yavaştır: yılda bir major sürüm.

**Compile-time query checking'in gerçek maliyeti.** `.sqlx/` dizini commit edilmelidir; şema değişiminde her PR'da yeniden üretilmesi gerekir ve derleme süresine ek getirir. Tavsiye, `query!` makrolarının yalnızca karmaşık sorgularda kullanılması, sıcak yol için elle prepared statement ile `query_as` tercih edilmesidir.

> **Uyarı.** diesel 2026'da altı advisory almıştır. RUSTSEC-2026-0136 (`COPY FROM` ve `COPY TO` command injection) Postgres'i etkiler. 2.3.8 ve üstü kullanılmalıdır.

sqlx 0.9'un `sqlx.toml` dosyası `_sqlx_migrations` tablosunun yeniden adlandırılmasını ve çoklu şemayı destekler.

**pgbouncer gerekli mi.** Tek instance için gereksizdir. Çok instance'ta gerekir; ancak transaction mode ile prepared statement çakışmasına dikkat edilmelidir.

---

## 5. Prior art: gerçek Rust IdP'leri

Aşağıdaki iki proje klonlanıp ölçülmüştür.

| | Kanidm | Rauthy |
|---|---|---|
| Satır sayısı | 224.718 satır, 458 dosya | 84.242 satır, 331 dosya |
| Yaş | 7,5 yıl (Şubat 2019) | 3,2 yıl (Temmuz 2023) |
| Son sürüm | v1.11.1 (14 Ağustos 2026) | v0.36.2 (8 Ağustos 2026); hâlâ 0.x |
| Depolama | SQLite ile kendi IDL ve ARC cache'i | Hiqlite (SQLite ve openraft) veya Postgres |
| Web | axum | actix-web |
| HA | Eventually consistent, azami iki node | Raft, N node |
| OIDC ve OAuth2 | Kapsamlı | Çok kapsamlı: device flow, DPoP, DCR, backchannel logout, token exchange, resource indicators, FedCM |
| SAML | Yok; kalıcı olarak reddedilmiştir | Yok |
| LDAP | Yalnızca okuma; 3.227 satır | Yok |
| SCIM | Yalnızca gelen | Yalnızca giden |
| WebAuthn | L3 ve MDS | Mevcut; resident keys dahil |
| Bağımsız denetim | Yok | Var; Radically Open Security ve NGI Zero |
| 12 aylık advisory | 10, biri Critical | 2 |
| Bus factor | Yaklaşık 1,5; Firstyear 412/1000 | 1,0; sebadob yaklaşık %89 |

### 5.1 Öğrenilecek dört ders

**Kanidm Postgres kullanmadı ve bu bilinçliydi.** `server/lib/src/be/` altında `idl_sqlite.rs` (SQLite ve rusqlite, WAL), ardından `idl_arc_sqlite.rs` (concread ARCache) ve en üstte query server bulunur. IDL bitmap indeksleri ile ARC cache birlikte çalışır. Ders şudur: IdP iş yükü ilişkisel join değil, indeksli entry lookup'tır. Depolama motoru yazılmaz, ancak üstündeki indeks ve cache katmanının yazılması gerekebilir.

**Tek yazıcı ve kilitlenmeyen okuyucu doğru takastır, ancak replikasyonu baştan belirler.** Kanidm COW mimarisi nedeniyle iki node'da tıkanmıştır. Raft isteniyorsa Rauthy gibi baştan konur.

**Rust'ın bellek güvenliği güvenlik bütçesinin küçük bir kısmını kapatır.** Kanidm'in 2026'daki on advisory'sinin hiçbiri buffer overflow değildir: üç parser stack exhaustion (biri eksik düzeltme), sabit zamanlı olmayan secret karşılaştırması, XSS ve Critical seviyede authenticated arbitrary write. Somut kural seti şudur: her parser'a decode'dan önce derinlik ve uzunluk sınırı konur, tüm secret karşılaştırmalarında `subtle` kullanılır ve erişim kontrolü için property-based test yazılır.

**Rauthy'nin 84.000 satırı tek kişinin üç yılda yazdığı, yalnızca OIDC sunan bir IdP'dir.** Argus'un hedefi bunun üstüne SAML, LDAP, SCIM ve çok kiracılık eklemektedir.

Ayrıca authentik (Python) 2026'da bileşenlerini Rust'a taşımaya başlamıştır: 2026.5'te worker, 2026.8'de server ve proxy outpost.

---

## 6. Değerlendirme

### 6.1 Rust'ın Go'ya göre gerçek maliyeti

| Katman | Rust | Go | Çarpan | Neden |
|---|---|---|---|---|
| HTTP, TLS, kripto | 1,0× | 1,0× | 1,0 | Rust daha iyidir; PQ ve FIPS |
| OAuth2 ve OIDC AS | 12-18 ay | 3-5 ay | 3-4 | Fosite yoktur |
| SAML (IdP tarafı) | 6-10 ay | 4-6 ay | 1,5 | samael ve gamlastan mevcuttur |
| LDAP sunucu | 9-15 ay | 7-12 ay | 1,2 | İki dilde de el işidir |
| SCIM | 4-6 ay | 3-5 ay | 1,2 | Filtre parser'ı yardımcı olur |
| WebAuthn | 2-3 ay | 2-3 ay | 1,0 | webauthn-rs ile go-webauthn denktir |
| Çok kiracılık, admin, operasyon | 12-18 ay | 12-18 ay | 1,0 | Her dilde sıfırdan yazılır |
| Toplam | Yaklaşık 46-73 ay | Yaklaşık 31-49 ay | Yaklaşık 1,5 | — |

Toplam efor 4-6 geliştirici-yılı çekirdek, sertleştirme ile sertifikasyon ve operasyonel olgunluk dahil gerçekçi olarak 6-10 geliştirici-yılıdır.

Kalibrasyon noktaları: Rauthy 84.000 satır, üç yıl, bir kişi, yalnızca OIDC; Kanidm 225.000 satır, 7,5 yıl, yaklaşık iki kişi, SAML yok.

**Kritik nüans.** Rust'ın maliyeti dil zorluğundan gelmemektedir. Borrow checker'ın vergisi bu ölçekte %10-15'tir ve derleyicinin yakaladığı hatalarla fazlasıyla geri ödenir. Maliyetin tamamı tek bir kütüphanenin, Fosite'ın yokluğudur.

### 6.2 Katman sınıflandırması

| Hazır | Kullanılır, dikkat gerekir | Boşluk, yazılmalı | Rust'ta yapılmaz |
|---|---|---|---|
| rustls 0.23; PQ varsayılan | jsonwebtoken; `aws_lc_rs` şart | OAuth2 ve OIDC AS | HTTP/3 (h3) |
| aws-lc-rs; FIPS, ML-KEM, ML-DSA | argon2; ARM'da NEON yok | LDAP sunucu semantiği ve SASL | ntex ve poem |
| axum, hyper, tower | samael; C libxml2 ve `=0.3.3` pin | SCIM endpoint, PATCH, bulk | `rsa` crate'i; Marvin |
| webauthn-rs; PRF hariç | bergshamra ve gamlastan; altı aylık, tek kişi | Çok kiracılık modeli | `openidconnect`; sunucu için |
| sqlx ve tokio-postgres | ldap3_proto; codec var, semantik yok | Consent, session, logout | josekit; C OpenSSL |
| tokio; Argon2 izole | diesel 2.3.8 ve üstü | Admin API ve policy engine | `salasebas` SAML crate'leri |

### 6.3 Rust'ın kötü fikir olduğu yerler

1. HTTP/3: h3 16 aydır durgundur ve faydası sıfırdır.
2. `rsa` crate'i ile RSA: belgelenmiş ve düzeltilmemiş bir timing yan kanalı vardır.
3. Saf Rust XML güvenliği ile SP tarafı: Argus bir IdP olduğu için bu alandan az etkilenir.
4. Framework'te en hızlıyı kovalamak: ntex'in 76 ters bağımlılığı, kazandığı mikrosaniyelerden pahalıdır.

### 6.4 Hibrit yaklaşım: dil hibriti değil, süreç hibriti

**Yanlış kısım: SAML'i ayrı bir dile taşımak.** Kazanç düşüktür; Rust'ta zaten yapılabilmektedir ve Argus IdP tarafında, yani SAML'in kolay yarısındadır. Ayrıca SAML assertion üretmek kullanıcı, oturum ve consent durumuna sıkı bağlıdır; süreç sınırına koymak dağıtık durum problemi yaratır. Kazanç maliyetten düşüktür.

**Doğru kısım: LDAP'ı ayırmak.** Farklı protokol yüzeyi, farklı port ve farklı tehdit modeli vardır; salt okunur olarak konumlandırılabilir. Ancak Go'da yazmaya gerek yoktur; `ldap3_proto` işi görür.

**Asıl doğru hibrit.** Çekirdek Rust'tadır: OIDC ve OAuth2 AS, WebAuthn, kullanıcı, oturum ve policy ile admin API. Tek süreç, tek veri modeli. Kenar gateway'ler yine Rust'ta ancak ayrı süreçtedir: LDAP salt okunur, SAML IdP ve RADIUS. Bunlar çekirdeği iç API üzerinden tüketir ve blast radius izole edilir.

**Değerlendirilmesi gereken alternatif.** Fosite'ı sarmalayan bir Go süreci 12-18 aylık en büyük riski ortadan kaldırır. Karşılığında protokol sınırında bir güven sınırı ve iki dilli operasyon yükü doğar. Tavsiye edilmez: OAuth AS tam olarak IdP'nin kalbidir ve dışarıda tutmak geri kalanı kabuğa indirger. Yine de bu seçenek dürüstçe hesaplanmalıdır.

### 6.5 En riskli üç alan

**OAuth2 ve OIDC AS'in sıfırdan yazılması.** 12-18 ay sürer ve hatalar doğrudan kimlik doğrulama atlatması anlamına gelir. Azaltma: OpenID Foundation sertifikasyon test süiti birinci günden CI'a konur; PKCE S256 zorunlu kılınır, implicit ve ROPC hiç mümkün kılınmaz; refresh reuse detection baştan tasarlanır.

**Tek bakımcılı yığın riskinin üst üste binmesi.** webauthn-rs, ldap3_proto ve concread'in hepsi Kanidm ekibine aittir. bergshamra, uppsala, gamlastan ve kryptering'in hepsi tek kişiye aittir. samael'in bir aktif bakımcısı ve üç yıl geride pinlenmiş bir C kütüphanesi vardır. Bunlar bağımsız değil, korele risklerdir. Azaltma: `cargo vendor`, fork kapasitesi, CI'da bloklayıcı `cargo-audit` ve `cargo-deny`.

**SAML'in altındaki C yığını (libxml2).** 5 Eylül 2026'da sekiz yeni CVE yayımlanmıştır; CVE-2026-86144 XXE ve SSRF üretir; kütüphanenin kendi README'si güvenilmeyen veri için önerilmediğini söyler. Azaltma: ayrı, en az yetkili ve sandbox'lı süreç; libxml2 2.15.4 ve üstü; samael fork'lanıp pin güncellenir; veya SAML hiç desteklenmez.

---

## 7. Tavsiye edilen yığın

```toml
# Runtime
axum = "0.8"                 # + tower-http
tokio = { version = "1.53", features = ["full"] }

# TLS — PQ varsayılan açık, FIPS'e hazır
rustls = { version = "0.23", features = ["fips"] }   # aws-lc-rs varsayılan provider

# JOSE — aws_lc_rs şart, rust_crypto kullanılmaz
jsonwebtoken = { version = "11", default-features = false,
                 features = ["use_pem", "aws_lc_rs"] }

webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
argon2 = { version = "0.6", features = ["parallel"] }   # ARM'da NEON yok — ölç
sqlx = { version = "0.9", features = ["postgres", "runtime-tokio-rustls"] }
ldap3_proto = "0.8"          # yalnızca codec; semantik bizim
scim_v2 = "0.5"              # model + filtre parser; endpoint bizim
# samael = "0.0.22"          # SAML gerekiyorsa; ayrı süreçte, fork'layıp libxml pinini güncelle
```

---

## 8. Sonuç

Rust seçilir, ancak gerekçesi düzeltilir. Azami performans doğru gerekçe değildir; darboğaz Argon2 ve RSA'dır ve ikisi de dilden bağımsızdır.

Doğru gerekçe iki maddedir. Birincisi kripto ve TLS katmanının Go'dan iyi olmasıdır: rustls'te PQ varsayılan açıktır, aws-lc-rs FIPS ve ML-DSA sunar, algoritma ailesi ayrımı tip sistemiyle zorlanır. İkincisi bellek güvenliğinin bir IdP'de gerçekten önemli olmasıdır.

İki illüzyon bırakılmalıdır. Rust bellek güvenliği verir, güvenlik vermez; Kanidm'in 2026'daki on advisory'sinin hiçbiri buffer overflow değildi ve Critical seviyedeki authenticated arbitrary write'ı hiçbir borrow checker durduramaz. Fosite'ın yokluğu 12-18 aylık gerçek bir vergidir ve bu projenin en büyük tek riskidir.

Kanidm 7,5 yılda 225 bin satır yazmış ve SAML'i kasıtlı olarak reddetmiştir. Rauthy üç yılda 84 bin satır yazmış ve yalnızca OIDC sunmaktadır. İkisi de Argus'un hedeflediğinden dar kapsamdadır; dolayısıyla kapsam faz faz kesilmek zorundadır.
