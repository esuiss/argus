# 2. Çelişkiler ve çözümleri

> `ARGUS.md` §2'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§2 §X` referansları aynı anlamda.


**Neden bu dosya:** On üç araştırma hattı paralel yürütüldü. Bağımsız hatlar birbirinden habersiz çalıştığı için beş noktada birbiriyle çelişen ya da uzlaştırılmamış tavsiyeler üretti. Bu dosya her birini kaynaklarına inerek çözer. **Mimari karar dokümanı bu dosyanın çıktısını girdi alır — çelişkileri değil.**

Her madde şu formatta: **iddia A** / **iddia B** / **gerçekte ne oluyor** / **karar**.

---

## Çelişki 1 — İmza algoritması tanımlayıcısı: `ES256` mi `ESP256` mi?

**İddia A** (cok-kiracilik.md (§18)): Kiracı başına ES256 anahtar; `alg: ES256` ile imzala.
**İddia B** (gelecek-standartlari.md (§17) §HAT 1): **RFC 9864** (Ekim 2025, Standards Track), "Fully-Specified Algorithms for JOSE and COSE", `EdDSA`'yı deprecate ediyor ve fully-specified tanımlayıcılar getiriyor. §4.3 IANA talimatlarını güncelliyor: **artık yalnızca fully-specified algoritma tanımlayıcıları kaydedilebilir.**

### Gerçekte ne oluyor

İki iddia **aynı şey hakkında değil.** Ayrım şu:

| | JWS `alg` (JOSE) | COSE `alg` |
|---|---|---|
| **Asıl sorun** | `EdDSA` belirsizdi — Ed25519 mi Ed448 mü söylemiyordu | Aynı belirsizlik |
| **RFC 9864'ün getirdiği** | `Ed25519`, `Ed448` | `ESP256`, `ESP384`, `ESP512`, `Ed25519` |
| **`ES256`'ya ne oldu** | **Deprecate EDİLMEDİ.** `ES256` zaten fully-specified'dır — P-256 + SHA-256'yı tek başına belirtir. Belirsiz olan `EdDSA`'ydı | COSE tarafında `ESP256` yeni **tercih edilen** isim; `ES256` çalışmaya devam ediyor |

**RFC 9864'ün deprecate ettiği tek JOSE tanımlayıcısı `EdDSA`'dır.** `ES256`/`ES384`/`ES512` etkilenmemiştir. `ESP*` isimleri **COSE bağlamında** (yani WebAuthn `pubKeyCredParams`, CTAP, ve COSE_Key kullanan her yerde) ortaya çıkar — JWT imzalamada değil.

FIDO Server Requirements v2.3 (26 Şubat 2026) `ESP256/384/512` ve `Ed25519`'u **önerilen COSE listesine** aldı — bu WebAuthn credential algoritma müzakeresidir, IdP'nin token imzalama algoritması değil.

### Karar

> **Token imzalamada `ES256` kullanılır ve doğrudur. Çelişki yoktur.**
>
> Ancak üç ayrı yerde eylem gerekiyor:
>
> 1. **JWS `alg` beyaz listesinde `EdDSA` KABUL EDİLMEZ** — yalnızca `Ed25519` (RFC 9864). Gelen bir token'da `alg: EdDSA` görürsen reddet, çünkü hangi eğriyi kastettiği belirsizdir ve bu bir cross-curve karışıklık yüzeyidir.
> 2. **WebAuthn `pubKeyCredParams` listesine COSE tarafında `ESP256` ve `Ed25519` eklenir**, `ES256`/`EdDSA` geriye uyumluluk için listede kalır (sırada daha aşağıda).
> 3. **Credential ve anahtar veri modelinde `algorithm` alanı ve bir rotasyon yolu bugünden bulunur.** WebAuthn L4'teki #2437 "Support Algorithm Migration" issue'su tam olarak bunu tartışıyor; ML-DSA geldiğinde şema değişikliği yapmak istemezsin.
>
> **Kiracı başına anahtar kararı da değişmiyor** — bkz. cok-kiracilik.md (§18). Çelişki, `ESP256`'nın COSE'a ait olduğunun görülmemesinden kaynaklanıyordu.

---

## Çelişki 2 — `#![forbid(unsafe_code)]` ile aws-lc-rs bir arada durabilir mi?

**İddia A** (dogrulanmis-kripto.md (§7)): aws-lc-rs birincil kripto sağlayıcı olsun — FIPS modu, ML-DSA desteği, ve RSA/ECDSA tarafında **s2n-bignum'un HOL Light ile makine-kontrollü ispatları** var.
**İddia B** (sertlestirme.md (§11) §E.1): `#![forbid(unsafe_code)]` hedeflensin.

**Görünürdeki çelişki:** aws-lc-rs BoringSSL türevidir; **C ve assembly içerir.** `forbid(unsafe_code)` bir crate'te varsa o crate FFI yapamaz.

### Gerçekte ne oluyor

**Bu bir crate-düzeyi lint'tir, workspace-düzeyi bir politika değil.** Sertleştirme raporunun kendi önerdiği yapı zaten bunu çözüyor:

```
argus-core/        #![forbid(unsafe_code)]   ← iş mantığı, politika
argus-proto/       #![forbid(unsafe_code)]   ← OIDC/OAuth2/SCIM tipleri
argus-parse/       #![forbid(unsafe_code)]   ← TÜM parser'lar (en kritik olan)
argus-http/        #![forbid(unsafe_code)]   ← axum handler'ları
argus-store/       #![forbid(unsafe_code)]   ← DB katmanı
argus-sandbox/     #![deny(unsafe_code)] + sayılı, gerekçeli istisna  ← seccomp/landlock/prctl
argus-crypto/      (aws-lc-rs sarmalayıcısı — FFI burada yaşar, başka hiçbir yerde)
```

**Emsal doğrulanmış:** rustls'in kendi ifadesi — *"The entire crate which processes items on this trust boundary is `forbid(unsafe_code)`."* rustls de aws-lc-rs'i (veya ring'i) kullanır. **rustls tam olarak bu ayrımı yapıyor** ve endüstride en çok denetlenmiş Rust TLS yığını.

Ayrıca sertleştirme raporunun kendi uyarısı önemli:
> *"özyinelemeli bir parser'da derinlik sınırı yoksa, kimliği doğrulanmamış bir istekle tüm IdP'nizi kapatabilirim. Bu, Rust'ın bellek güvenliğinin sizi korumadığı bir sınıftır ve `#![forbid(unsafe_code)]` hiçbir işe yaramaz."*

Yani `forbid(unsafe_code)` bir güvenlik hedefi değil, **bir sınırlama beyanıdır**: "bu crate'te bellek güvenliği hatası aramaya gerek yok, başka şey ara."

### Karar

> **İkisi de doğru, çelişki yok. Politika şudur:**
>
> 1. **`#![forbid(unsafe_code)]` her Argus crate'inde varsayılandır** — istisnalar `argus-crypto` (FFI) ve `argus-sandbox` (syscall) ile sınırlıdır ve her ikisi de **incelenmiş, gerekçesi yazılmış, satır sayısı sabit** olmalıdır.
> 2. **`cargo geiger --forbid-only` CI'da bir gate'tir**, metrik değil. Bağımlılık ağacındaki toplam unsafe sayısını KPI yapma — yanıltıcıdır (tokio, hyper, h2 hepsi unsafe içerir ve içermek zorundadır).
> 3. **Kripto sağlayıcı aws-lc-rs kalır.** Gerekçe (a) FIPS modu, (b) ML-DSA, (c) s2n-bignum'un makine-kontrollü ispatları — RustCrypto'nun saf Rust'ının **sağlamadığı** üç şey.
> 4. **`rust_crypto` özelliği `jsonwebtoken`'da ASLA açılmaz** — bkz. yan-kanal.md (§8), `rsa` crate'i Marvin saldırısına açık.
> 5. **Asıl DoS savunması `forbid(unsafe_code)` değil, parser derinlik sınırlarıdır.** Bkz. [§3 — P0 kritik bulgular](#3-p0-kritik-bulgular).

---

## Çelişki 3 — SAML: saf Rust mı, süreç izolasyonu mu?

**İddia A** (kurumsal-protokoller.md (§16) §1.13.2): `bergshamra` XMLDSig/XMLEnc/C14N'i saf Rust'ta veriyor ve **xmlsec1'in kendi interop süitini 1148/1151 geçiyor** (Enc 701/0, DSig 447/0; atlanan 3'ü GOST). libxml/xmlsec/openssl-sys bağımlılığı **yok** — saf Rust zinciri doğrulandı.

>  ⚠️ **`gamlastan`'ın SPID uyum iddiası kanıt olarak kullanılamaz.** İki nedenle: rakam kütüphanenin kendi README'sinden geliyor (süitin birincil kaynaklarındaki sayılar **300+ kontrol, 7 aile**, interaktif aile için 111), ve daha önemlisi **`italia/spid-saml-check` Service Provider'ları test eder, Identity Provider'ları değil** — araç bir test IdP'si gibi davranıp SP'yi sınar. Argus bir IdP'dir. IdP tarafı için ayrı repo var (`AgID/spid-saml-check-idp`) ama olgunluğu çok düşük: **4 star, 1 fork, 51 commit**, Docker yok, test aileleri dokümante değil.
>
> Bu, aşağıdaki kararı **güçlendiriyor**: SAML domain modelini kendimiz yazma kararı zaten `gamlastan`'a güvenmemek üzerineydi. `bergshamra`'nın xmlsec1 interop sonucu (1148/1151) ise **bağımsız bir süite karşı** olduğu için geçerliliğini koruyor.

### Gerçekte ne oluyor

**Bu bir çelişki değil, iki farklı riskin cevabı.** Süreç izolasyonu tarihsel olarak **libxml2'nin bellek güvenliği** için önerilirdi. Saf Rust yığını o riski ortadan kaldırır. Ama izolasyonun **ikinci bir gerekçesi** var ve o hâlâ geçerli:

| Risk | Saf Rust çözüyor mu? |
|---|---|
| libxml2 bellek bozulması → RCE | ✅ **Evet, tamamen** |
| XXE / dış varlık genişletme | ✅ Evet (uppsala varsayılan kapalı) |
| **Billion laughs / özyinelemeli genişleme → bellek tükenmesi** | ❌ **Hayır** — bu bir algoritma sınıfı, dil sınıfı değil |
| **Derin iç içe XML → yığın tükenmesi → `process::abort()`** | ❌ **Hayır** — ve Rust'ta stack overflow **kurtarılamaz**, süreci öldürür |
| XSW (XML Signature Wrapping) — imzalanan ile işlenen düğümün farklı olması | ❌ **Hayır** — bu bir mantık hatası; kütüphane değil, senin doğrulama sıran belirler |
| Tek geliştirici / düşük benimseme riski | ❌ Hayır (bkz. aşağıdaki uyarı) |

⚠️ **Olgunluk uyarısı korunuyor:** `bergshamra` 0.9.0, Şubat 2026'da başlamış, **tek geliştiricili**. README *"Version 0.10.1 was released on August 02, 2026"* diyor ama crates.io'da azami sürüm **0.9.0** — 0.10.1 muhtemelen bağımlılığı `uppsala`'nın sürümü. **Bu sürüm/doküman tutarsızlığı başlı başına bir disiplin uyarısıdır.**

### Karar

> **Saf Rust (`bergshamra`) kullanılır — ama süreç izolasyonu da korunur. İkisi farklı şeyler için.**
>
> 1. **XMLDSig/XMLEnc/C14N için `bergshamra`.** Gerekçe: xmlsec1'in kendi süitini geçmesi, endüstride bir Rust kripto kütüphanesi için görülen en güçlü olgunluk sinyalidir. libxml2 FFI'ı ve onunla gelen tüm CVE tarihçesi ortadan kalkar.
> 2. **SAML domain modeli (Response/Assertion/NameID politikaları/attribute release) kendimiz yazılır** — `gamlastan` kullanılmaz. Bu **iş mantığıdır ve dışarıdan gelmemelidir**; ayrıca XSW savunması tam olarak burada yaşar.
> 3. **SAML işleme yine de ayrı bir süreçte çalışır** — ama gerekçe bellek güvenliği değil, **kaynak sınırlaması**: `RLIMIT_AS`, `RLIMIT_STACK`, ayrı bir wall-clock timeout, ve süreç ölürse ana IdP'nin ayakta kalması. Derin iç içe XML'in Rust'ta yığını tüketip `abort()` çağırması **gerçek ve kurtarılamaz** bir olaydır; onu izole bir sürecin içinde tutmak tek savunmadır.
> 4. **Parser derinlik sınırı süreç izolasyonundan önce gelir** — izolasyon son savunma hattıdır, birinci değil.
> 5. **`bergshamra`'nın kendi test süitinin bir kopyası Argus CI'ında koşar.** Tek geliştiricili bir bağımlılığın regresyonunu onun CI'ına güvenerek öğrenemezsin.

---

## Çelişki 4 — `revocation_epoch` ile yetkilendirme karar cache'i nasıl etkileşiyor?

**İddia A** (ha-dagitik-mimari.md (§19) §4.5): Kullanıcı başına monoton `revocation_epoch` sayacı + node-yerel cache. Bu "Argus'un omurgası olmalı." Değeri: **JWT doğrulaması DB gerektirmez** — public key bellekte, `exp`/`nbf` token'ın içinde, `revocation_epoch` node cache'inde. DB tamamen düşse bile kaynak sunucular etkilenmez.
**İddia B** (yetkilendirme-motoru.md (§20)): İnce taneli yetkilendirme (ReBAC/Cedar) için karar cache'i — aynı `(subject, action, resource)` üçlüsü tekrar tekrar sorulur, cache olmadan performans hedefleri tutmaz.

**Uzlaştırılmamış soru:** Bir kullanıcının **izni** değiştiğinde (rol alındı, ilişki silindi) `revocation_epoch` artar mı? Artarsa her izin değişikliği tüm oturumları düşürür — kabul edilemez. Artmazsa karar cache'i bayat kalır — güvenlik açığı.

### Gerçekte ne oluyor

**İki farklı geçersizleme ekseni tek sayaca sıkıştırılmaya çalışılıyor.** Doğru model üç ayrı epoch'tur:

| Epoch | Neyi geçersiz kılar | Ne zaman artar | Yayılım hedefi |
|---|---|---|---|
| **`session_epoch`** (kullanıcı başına) | Kullanıcının **tüm token'ları** | Parola değişimi, "tüm cihazlardan çık", hesap devre dışı, MFA kaydı, credential değişimi | **≤ 250 ms** — bu bir güvenlik olayıdır |
| **`authz_epoch`** (kiracı başına) | Kiracının **yetkilendirme karar cache'i** | Rol/politika/ilişki değişimi | **≤ 1 s** kabul edilebilir |
| **`key_epoch`** (kiracı başına) | JWKS cache'i | Anahtar rotasyonu | Dakikalar (overlap penceresi var) |

**Kritik ayrım:**
- `session_epoch` **token'ın içinde taşınır** (claim olarak) ve doğrulamada node cache'indeki değerle karşılaştırılır. Eşleşmiyorsa token ölü. **Bu, ağ turu gerektirmez.**
- `authz_epoch` **token'ın içinde taşınmaz.** Karar cache'inin anahtarının bir parçasıdır. **Tek geçerli anahtar tanımı** — §20 §7.1 ile aynı, uzunluk-önekli hash, string concat değil:
  ```
  cache_key = blake3_len_prefixed(tenant_id ‖ authz_epoch ‖ subject ‖ action ‖ resource ‖ model_id)
  ```
  ⚠️ *Düzeltme (2. inceleme turu): burada önceden `(authz_epoch, subject, action, resource)` yazıyordu — **tenant taşımıyordu**, ki bu §18'in kendi composite-key ilkesine aykırıydı; ayrıca §20 §7.1'deki tanımla uyuşmuyordu. İki tanım tek tanıma indirildi.* Epoch artınca eski anahtarlar erişilemez hâle gelir — **cache silinmez, sadece adreslenemez olur** ve doğal olarak tahliye edilir.
- ⚠️ **Ama bu, tazeliği TEK BAŞINA çözmez.** Epoch, cache'i *adreslenemez* kılar; cache'i *dolduran* okumanın tazeliği hakkında hiçbir şey söylemez. `E+1` epoch'u altında, eski bir replica snapshot'ından hesaplanmış bir karar yazılabilir ve orada kalır. Doldurma sözleşmesi §1 §10.3'te **kabul edilmiş başlangıç modeli** olarak, uçuşta karar semantiği ise **açık** olarak kayıtlıdır.

**Bu neden doğru:** Bir kullanıcının rolü değiştiğinde oturumunu düşürmek istemezsin — sadece bir sonraki yetkilendirme kararının taze olmasını istersin. `authz_epoch` tam olarak bunu yapar ve **oturuma hiç dokunmaz.**

**Ters yön de doğru:** `session_epoch` arttığında karar cache'ini temizlemeye gerek yoktur, çünkü o kullanıcının hiçbir token'ı zaten geçerli değildir.

### Zanzibar'ın zookie'siyle ilişkisi

yetkilendirme-motoru.md (§20)'deki **new-enemy problem** bu tasarımla şöyle ilişkilenir: `authz_epoch` bir **monoton sayaçtır**, bir zookie değildir — nedensel tutarlılık garantisi vermez. İki farklı ilişki değişikliğinin sırası korunmaz. **Bu kabul edilebilir bir takastır** ve şu koşulla:

> **Yetkilendirme kararı bir read replica'dan okunmuşsa `authz_epoch` yeterli değildir.** İzin *kaldırma* işlemleri (izin verme değil) **primary'den doğrulanmalıdır** — çünkü replikasyon gecikmesi tam olarak new-enemy penceresidir.

Bu, HA raporunun kendi tablosuyla tutarlı: **"Token iptali / `revocation_epoch` kontrolü → read replica'ya YÖNLENDİRİLEMEZ."** Aynı kural izin kaldırmaya da uygulanır.

### Karar

> ```rust
> struct EpochSet {
>     session_epoch: u64,   // kullanıcı başına — token claim'i, ≤250ms yayılım
>     authz_epoch:   u64,   // kiracı başına — karar cache anahtarı, ≤1s yayılım
>     key_epoch:     u64,   // kiracı başına — JWKS cache, dakikalar
> }
> ```
>
> 1. **`session_epoch` token'da taşınır ve node cache'iyle karşılaştırılır.** DB turu yok. HA raporunun kademeli bozulma özelliği korunur.
> 2. **`authz_epoch` karar cache anahtarının parçasıdır.** Artması cache'i adreslenemez kılar; temizleme işi yoktur.
> 3. **Üçü de aynı transactional outbox üzerinden yayılır** (100-250 ms polling — Keycloak'ın deseni). Postgres `LISTEN/NOTIFY` **kullanılmaz**: PgBouncer transaction modunda çalışmaz ve kuyruk dolduğunda **yazma işlemleri commit'te başarısız olur.**
> 4. **İzin *kaldırma* ve `session_epoch` kontrolü read replica'ya yönlendirilmez.** İzin *verme* yönlendirilebilir.
> 5. `authz_epoch`'un kiracı başına olması kasıtlıdır: kullanıcı başına olsaydı kiracı geneli politika değişimi N sayaç artışı gerektirirdi; global olsaydı bir kiracının değişimi tüm kiracıların cache'ini düşürürdü.

---

## Çelişki 5 — Formel doğrulama: Argus tamamen async, araçlar async desteklemiyor

**İddia A** (formel-dogrulama.md (§10)): Kani ve Verus ciddi güvence sağlıyor; Cedar'ın Lean 4 ile doğrulanması emsal.
**İddia B** (aynı dosya, doğrulanmış kısıtlar):
- **Kani:** *"Await ifadeleri / async → **Hayır**"*; "Concurrency out of scope"
- **Verus:** **`async fn`/async bloklar/`await` DESTEKLENMİYOR**, ayrıca `Pin`, I/O, **`serde::Serialize`**, kullanıcı tanımlı `Drop`, **`Mutex`/`RwLock`**
- **Flux:** heap ayıran tipler (`String`, `Vec`), smart pointer'lar (`Box`, `Rc`, `Arc`), async/await, dinamik trait object'ler — hiçbiri desteklenmiyor
- **KMIR:** async/await yok · **Miri:** ağ yok

**Ve Argus baştan sona axum + tokio, yani tamamen async.**

### Gerçekte ne oluyor

**Bu gerçek bir kısıttır ve çözümü aracı değiştirmek değil, mimariyi bölmektir.** Formel doğrulama raporunun kendi sonucu bunu zaten söylüyor:

> *"Verus'un yeri, saf, senkron, I/O'suz bir çekirdek modül — örneğin politika değerlendirme motoru veya token durum makinesi — ve bu modülün geri kalanla `external_body` sınırından konuşması."*

Ve HTTP katmanı için:
> *"**HTTP katmanı / async runtime (axum/tokio) → HİÇBİR formel araç değil** — sadece fuzz + entegrasyon testi + Shuttle."*

Yani soru "async'i nasıl doğrularım" değil, **"neyin senkron ve saf olması gerektiğine karar verdim mi"** sorusudur. Ve bu, formel doğrulamadan bağımsız olarak zaten iyi bir mimari karardır.

### Hangi bileşen saf ve senkron olabilir?

| Bileşen | Saf/senkron olabilir mi? | Doğrulama aracı |
|---|---|---|
| **OAuth AS durum makinesi** (grant tipi geçişleri, PKCE eşleştirme, code tek kullanımlık) | ✅ **Evet** — girdi bir `Request` struct'ı, çıktı bir `Decision` enum'u. I/O çağıran değil, I/O *isteyen* bir tasarım | **Kani** (bounded model checking, `#[kani::proof]`) |
| **Politika değerlendirme** (Cedar embed + kendi ReBAC katmanı) | ✅ **Evet** — Cedar zaten böyle tasarlanmış | **Cedar'ın Lean 4 ispatları** miras alınır; kendi ReBAC katmanı için **Kani** |
| **Delegasyon zinciri değişmezleri** (monoton daralma, TTL monotonluğu, derinlik, kesişim) | ✅ **Evet** — saf fonksiyon | **Kani** — bu, ajan kimliğindeki 6 invariant'ın makine-kontrollü hâli |
| **Epoch karşılaştırma mantığı** (Çelişki 4) | ✅ Evet | **Kani** |
| **Parser'lar** (JWT, JSON, XML, DER, SCIM filter) | ⚠️ Kısmen — derinlik sınırı mantığı saf, ayrıştırma değil | **cargo-fuzz** birincil; Kani derinlik invariant'ı için |
| **Kripto** | — | **Miras alınır** (s2n-bignum HOL Light, HACL*) — kendimiz doğrulamayız |
| **HTTP katmanı, DB katmanı, tokio runtime** | ❌ **Hayır** | **Hiçbir formel araç.** fuzz + entegrasyon testi + **Shuttle** (deterministik concurrency testi) |

### Karar

> **Formel doğrulama kapsamı, "async olmayan çekirdek" olarak yeniden tanımlanır ve bu bir mimari zorlamaya çevrilir.**
>
> 1. **`argus-core` I/O yapmaz.** Fonksiyonlar `async` değildir, `Result<Decision, Error>` döner. Veri erişimi çağıran tarafından *önceden* yapılır ve struct olarak geçirilir. **Bu kural CI'da zorlanır:** `argus-core`'da `async fn`, `tokio::`, `sqlx::` veya `reqwest::` görünmesi build'i kırar.
> 2. **Kani'nin hedefi dört şeydir:** OAuth durum makinesi geçişleri · delegasyon zinciri değişmezleri · epoch karşılaştırma · parser derinlik invariant'ları. Bunların hepsi saf ve sınırlı.
> 3. **Verus denenmez.** `serde::Serialize` ve `Mutex` desteklememesi, IdP kod tabanının hiçbir gerçek parçasına uymamasını neredeyse garanti ediyor. Kani'nin `#[kani::proof]` ergonomisi aynı işi kabul edilebilir bir maliyetle yapıyor. *(Bu, formel-dogrulama.md'nin sunduğu seçeneklerden bir sapmadır ve gerekçesi ergonomidir, yetenek değil.)*
> 4. **Async katman için formel doğrulama İDDİA EDİLMEZ.** Orada araç seti: `cargo-fuzz` (parser'lar ve protokol yüzeyleri), **Shuttle** (deterministik concurrency, tokio ile çalışır), property-based test (`proptest`), ve interop conformance süitleri.
> 5. **Cedar embed edilir, yeniden yazılmaz.** Lean 4 ile doğrulanmış bir politika motorunu kendi yazdığınla değiştirmek, kazanılmış tek ücretsiz güvenceyi atmaktır.
>
> ⚠️ **Dürüstlük kaydı:** Bu kapsamla "Argus formel olarak doğrulanmıştır" **denemez.** Denebilecek olan: *"Argus'un yetkilendirme çekirdeği ve protokol durum makinesi sınırlı model kontrolünden geçirilmiştir; kripto katmanı makine-kontrollü ispatları olan implementasyonlar kullanır; HTTP ve depolama katmanları fuzz ve deterministik concurrency testine tabidir."* **Pazarlama cümlesi bu olmalı, daha fazlası değil.**

---

## Özet — beş kararın tek tabloda hâli

| # | Çelişki | Karar | Etkilenen dosya |
|---|---|---|---|
| 1 | `ES256` vs `ESP256` | **Çelişki yoktu.** `ES256` JWS'te doğru; `ESP256` COSE/WebAuthn tarafında eklenir. **`alg: EdDSA` reddedilir.** Veri modelinde `algorithm` + rotasyon alanı bugünden | cok-kiracilik, gelecek-standartlari |
| 2 | `forbid(unsafe_code)` vs aws-lc-rs | **Çelişki yoktu.** Crate-düzeyi lint; FFI yalnızca `argus-crypto` ve `argus-sandbox`'ta. rustls emsali. `cargo geiger --forbid-only` gate | sertlestirme, dogrulanmis-kripto |
| 3 | SAML saf Rust vs süreç izolasyonu | **İkisi de.** `bergshamra` bellek güvenliği riskini çözer; süreç izolasyonu **kaynak sınırlaması** için kalır. Domain modeli kendimiz yazarız. Bağımlılığın test süiti bizim CI'ımızda koşar | kurumsal-protokoller, sertlestirme |
| 4 | `revocation_epoch` vs karar cache | **Üç ayrı epoch:** `session_epoch` (token claim'i, ≤250ms) · `authz_epoch` (cache anahtarı, ≤1s) · `key_epoch`. İzin *kaldırma* replica'dan okunmaz | ha-dagitik-mimari, yetkilendirme-motoru |
| 5 | Formel doğrulama vs async | **Kapsam "async olmayan çekirdek" olarak yeniden tanımlanır ve mimari zorlamaya çevrilir.** `argus-core` I/O yapmaz — CI'da zorlanır. Kani evet, Verus hayır. Async katmanda formel iddia yok | formel-dogrulama |

**Dört karar mimariyi değiştiriyor** (2, 3, 4, 5). **Bir tanesi yanlış anlaşılmaydı** (1).
En pahalı olanı **#5**: `argus-core`'un I/O'suz olması, ilk satırdan itibaren uyulması gereken bir kısıttır — sonradan uygulanamaz.
