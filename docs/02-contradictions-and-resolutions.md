# §2 — Çelişkiler ve çözümleri

On üç araştırma hattı paralel yürütülmüştür. Bağımsız hatlar birbirinden habersiz çalıştığı için beş noktada birbiriyle çelişen veya uzlaştırılmamış tavsiyeler üretmiştir. Bu dosya her birini kaynaklarına inerek çözer.

Mimari karar dokümanı bu dosyanın çıktısını girdi alır; çelişkilerin kendisini değil.

Her madde dört parçadan oluşur: iddia A, iddia B, gerçekte ne olduğu ve karar.

---

## Çelişki 1 — İmza algoritması tanımlayıcısı: `ES256` mi, `ESP256` mi

**İddia A (§18).** Kiracı başına ES256 anahtar kullanılır ve imzalama `alg: ES256` ile yapılır.

**İddia B (§17 §HAT 1).** RFC 9864 (Ekim 2025, Standards Track), "Fully-Specified Algorithms for JOSE and COSE", `EdDSA`'yı deprecate eder ve fully-specified tanımlayıcılar getirir. Belgenin §4.3 bölümü IANA talimatlarını güncelleyerek yalnızca fully-specified algoritma tanımlayıcılarının kaydedilebileceğini belirtir.

### Gerçekte ne oluyor

İki iddia aynı şey hakkında değildir. Ayrım şudur:

| | JWS `alg` (JOSE) | COSE `alg` |
|---|---|---|
| Asıl sorun | `EdDSA` belirsizdi; Ed25519 ile Ed448 arasında ayrım yapmıyordu | Aynı belirsizlik |
| RFC 9864'ün getirdiği | `Ed25519`, `Ed448` | `ESP256`, `ESP384`, `ESP512`, `Ed25519` |
| `ES256`'nın durumu | Deprecate edilmemiştir. `ES256` zaten fully-specified'dır; P-256 ile SHA-256'yı tek başına belirtir. Belirsiz olan `EdDSA`'dır | COSE tarafında `ESP256` tercih edilen yeni isimdir; `ES256` çalışmaya devam eder |

RFC 9864'ün deprecate ettiği tek JOSE tanımlayıcısı `EdDSA`'dır. `ES256`, `ES384` ve `ES512` etkilenmemiştir. `ESP*` isimleri COSE bağlamında ortaya çıkar — WebAuthn `pubKeyCredParams`, CTAP ve COSE_Key kullanan her yer — JWT imzalamada değil.

FIDO Server Requirements v2.3 (26 Şubat 2026) `ESP256`, `ESP384`, `ESP512` ve `Ed25519`'u önerilen COSE listesine almıştır. Bu bir WebAuthn credential algoritma müzakeresidir, IdP'nin token imzalama algoritması değildir.

### Karar

Token imzalamada `ES256` kullanılır ve doğrudur. Çelişki bulunmamaktadır. Buna karşılık üç ayrı yerde eylem gerekir.

1. JWS `alg` beyaz listesinde `EdDSA` kabul edilmez; yalnızca `Ed25519` kabul edilir (RFC 9864). `alg: EdDSA` taşıyan bir token reddedilir, çünkü hangi eğriyi kastettiği belirsizdir ve bu bir cross-curve karışıklık yüzeyidir.
2. WebAuthn `pubKeyCredParams` listesine COSE tarafında `ESP256` ve `Ed25519` eklenir; `ES256` ve `EdDSA` geriye uyumluluk için listede daha aşağıda kalır.
3. Credential ve anahtar veri modelinde `algorithm` alanı ve bir rotasyon yolu gün-1'de bulunur. WebAuthn L4'teki #2437 numaralı "Support Algorithm Migration" issue'su tam olarak bunu tartışmaktadır; ML-DSA geçişinde şema değişikliği gerekmemelidir.

Kiracı başına anahtar kararı değişmemiştir (§18). Çelişki, `ESP256`'nın COSE'a ait olduğunun görülmemesinden kaynaklanmıştır.

---

## Çelişki 2 — `#![forbid(unsafe_code)]` ile aws-lc-rs bir arada durabilir mi

**İddia A (§7).** aws-lc-rs birincil kripto sağlayıcı olmalıdır: FIPS modu, ML-DSA desteği ve RSA/ECDSA tarafında s2n-bignum'un HOL Light ile makine-kontrollü ispatları bulunmaktadır.

**İddia B (§11 §E.1).** `#![forbid(unsafe_code)]` hedeflenmelidir.

**Görünürdeki çelişki.** aws-lc-rs BoringSSL türevidir ve C ile assembly içerir. `forbid(unsafe_code)` bir crate'te varsa o crate FFI yapamaz.

### Gerçekte ne oluyor

Bu bir crate düzeyi lint'tir, workspace düzeyi bir politika değildir. Sertleştirme raporunun kendi önerdiği yapı sorunu zaten çözmektedir:

```
argus-core/        #![forbid(unsafe_code)]   ← iş mantığı, politika
argus-proto/       #![forbid(unsafe_code)]   ← OIDC/OAuth2/SCIM tipleri
argus-parse/       #![forbid(unsafe_code)]   ← tüm parser'lar (en kritik olan)
argus-http/        #![forbid(unsafe_code)]   ← axum handler'ları
argus-store/       #![forbid(unsafe_code)]   ← DB katmanı
argus-sandbox/     #![deny(unsafe_code)] + sayılı, gerekçeli istisna  ← seccomp/landlock/prctl
argus-crypto/      (aws-lc-rs sarmalayıcısı — FFI burada yaşar, başka hiçbir yerde)
```

**Emsal doğrulanmıştır.** rustls kendi ifadesinde bu güven sınırındaki öğeleri işleyen crate'in tamamının `forbid(unsafe_code)` olduğunu belirtir. rustls de aws-lc-rs veya ring kullanır. Aynı ayrımı yapan bu yığın endüstride en çok denetlenmiş Rust TLS yığınıdır.

Sertleştirme raporunun kendi uyarısı da önemlidir: özyinelemeli bir parser'da derinlik sınırı yoksa kimliği doğrulanmamış tek bir istek tüm IdP'yi durdurabilir. Bu, Rust'ın bellek güvenliğinin koruma sağlamadığı bir sınıftır ve `#![forbid(unsafe_code)]` bu sınıfta işe yaramaz.

Dolayısıyla `forbid(unsafe_code)` bir güvenlik hedefi değil, bir sınırlama beyanıdır: bu crate'te bellek güvenliği hatası aranmasına gerek yoktur, başka sınıfta aranmalıdır.

### Karar

İki iddia da doğrudur ve çelişki bulunmamaktadır. Politika şudur.

1. `#![forbid(unsafe_code)]` her Argus crate'inde varsayılandır. İstisnalar `argus-crypto` (FFI) ve `argus-sandbox` (syscall) ile sınırlıdır; her ikisi de incelenmiş, gerekçesi yazılmış ve satır sayısı sabit olmalıdır.
2. `cargo geiger --forbid-only` CI'da bir gate'tir, metrik değildir. Bağımlılık ağacındaki toplam unsafe sayısı KPI olarak kullanılmaz; yanıltıcıdır, çünkü tokio, hyper ve h2 unsafe içerir ve içermek zorundadır.
3. Kripto sağlayıcı aws-lc-rs olarak kalır. Gerekçeler FIPS modu, ML-DSA ve s2n-bignum'un makine-kontrollü ispatlarıdır; RustCrypto'nun saf Rust yığını bu üçünü sağlamaz.
4. `jsonwebtoken`'da `rust_crypto` özelliği açılmaz (§8); `rsa` crate'i Marvin saldırısına açıktır.
5. Asıl DoS savunması `forbid(unsafe_code)` değil, parser derinlik sınırlarıdır (§3).

---

## Çelişki 3 — SAML: saf Rust mı, süreç izolasyonu mu

**İddia A (§16 §1.13.2).** `bergshamra` XMLDSig, XMLEnc ve C14N'i saf Rust'ta sağlar ve xmlsec1'in kendi interop süitinden 1148/1151 geçer (Enc 701/0, DSig 447/0; atlanan üç kalem GOST'tur). libxml, xmlsec ve openssl-sys bağımlılığı bulunmaz; saf Rust zinciri doğrulanmıştır.

> **Uyarı — `gamlastan`'ın SPID uyum iddiası kanıt olarak kullanılamaz.** İki nedenle. Rakam kütüphanenin kendi README dosyasından gelmektedir; süitin birincil kaynaklarındaki sayılar 300'den fazla kontrol ve yedi aile, interaktif aile için 111'dir. Daha önemlisi `italia/spid-saml-check` Service Provider'ları test eder, Identity Provider'ları değil; araç bir test IdP'si gibi davranarak SP'yi sınar. Argus bir IdP'dir. IdP tarafı için ayrı bir repo bulunmaktadır (`AgID/spid-saml-check-idp`) ancak olgunluğu düşüktür: 4 yıldız, 1 fork, 51 commit, Docker desteği yok, test aileleri dokümante değil.
>
> Bu tespit aşağıdaki kararı güçlendirmektedir: SAML domain modelini kendimiz yazma kararı zaten `gamlastan`'a güvenmemek üzerine kuruluydu. `bergshamra`'nın xmlsec1 interop sonucu (1148/1151) bağımsız bir süite karşı alındığı için geçerliliğini korumaktadır.

**İddia B.** SAML işleme ayrı bir süreçte çalışmalıdır.

### Gerçekte ne oluyor

Bu bir çelişki değil, iki farklı riskin cevabıdır. Süreç izolasyonu tarihsel olarak libxml2'nin bellek güvenliği için önerilmiştir. Saf Rust yığını o riski ortadan kaldırır. Ancak izolasyonun ikinci bir gerekçesi vardır ve o hâlâ geçerlidir:

| Risk | Saf Rust çözüyor mu |
|---|---|
| libxml2 bellek bozulması ve buradan RCE | Evet, tamamen |
| XXE ve dış varlık genişletme | Evet; `uppsala` varsayılan olarak kapalıdır |
| Billion laughs ve özyinelemeli genişleme ile bellek tükenmesi | Hayır. Bu bir algoritma sınıfıdır, dil sınıfı değildir |
| Derin iç içe XML ile yığın tükenmesi ve `process::abort()` | Hayır. Rust'ta stack overflow kurtarılamaz ve süreci sonlandırır |
| XSW (XML Signature Wrapping): imzalanan düğüm ile işlenen düğümün farklı olması | Hayır. Bu bir mantık hatasıdır; kütüphane değil, doğrulama sırası belirler |
| Tek geliştirici ve düşük benimseme riski | Hayır; aşağıdaki uyarıya bakınız |

> **Olgunluk uyarısı korunmaktadır.** `bergshamra` 0.9.0 sürümündedir, Şubat 2026'da başlamıştır ve tek geliştiricilidir. README 0.10.1 sürümünün 2 Ağustos 2026'da yayımlandığını belirtmektedir ancak crates.io'daki azami sürüm 0.9.0'dır; 0.10.1 muhtemelen bağımlılığı olan `uppsala`'nın sürümüdür. Bu sürüm ile dokümantasyon arasındaki tutarsızlık başlı başına bir disiplin uyarısıdır.

### Karar

Saf Rust (`bergshamra`) kullanılır ve süreç izolasyonu da korunur. İkisi farklı risklere karşılık gelir.

1. XMLDSig, XMLEnc ve C14N için `bergshamra` kullanılır. Gerekçe, xmlsec1'in kendi süitini geçmesinin bir Rust kripto kütüphanesi için endüstride görülen en güçlü olgunluk sinyali olmasıdır. libxml2 FFI'ı ve onunla gelen tüm CVE tarihçesi ortadan kalkar.
2. SAML domain modeli — Response, Assertion, NameID politikaları, attribute release — kendimiz tarafından yazılır; `gamlastan` kullanılmaz. Bu bir iş mantığıdır ve dış bağımlılıktan gelmemelidir; ayrıca XSW savunması tam olarak bu katmanda yaşar.
3. SAML işleme yine de ayrı bir süreçte çalışır. Gerekçe bellek güvenliği değil kaynak sınırlamasıdır: `RLIMIT_AS`, `RLIMIT_STACK`, ayrı bir wall-clock timeout ve süreç sonlandığında ana IdP'nin ayakta kalması. Derin iç içe XML'in Rust'ta yığını tüketip `abort()` çağırması gerçek ve kurtarılamaz bir olaydır; onu izole bir sürecin içinde tutmak tek savunmadır.
4. Parser derinlik sınırı süreç izolasyonundan önce gelir. İzolasyon son savunma hattıdır, birincisi değildir.
5. `bergshamra`'nın kendi test süitinin bir kopyası Argus CI'ında koşar. Tek geliştiricili bir bağımlılığın regresyonu onun kendi CI'ına güvenilerek öğrenilemez.

---

## Çelişki 4 — `revocation_epoch` ile yetkilendirme karar cache'i nasıl etkileşir

**İddia A (§19 §4.5).** Kullanıcı başına monoton `revocation_epoch` sayacı ve node-yerel cache kullanılır; bu yapı Argus'un omurgası olmalıdır. Değeri, JWT doğrulamasının veritabanı gerektirmemesidir: public key bellektedir, `exp` ve `nbf` token'ın içindedir, `revocation_epoch` node cache'indedir. Veritabanı tamamen düşse dahi kaynak sunucular etkilenmez.

**İddia B (§20).** İnce taneli yetkilendirme (ReBAC ve Cedar) için karar cache'i gerekir; aynı `(subject, action, resource)` üçlüsü tekrar tekrar sorulur ve cache olmadan performans hedefleri tutmaz.

**Uzlaştırılmamış soru.** Bir kullanıcının izni değiştiğinde (rol alındığında, ilişki silindiğinde) `revocation_epoch` artar mı? Artarsa her izin değişikliği tüm oturumları düşürür ve bu kabul edilemez. Artmazsa karar cache'i bayat kalır ve bu bir güvenlik açığıdır.

### Gerçekte ne oluyor

İki farklı geçersizleme ekseni tek sayaca sıkıştırılmaya çalışılmaktadır. Doğru model üç ayrı epoch'tur:

| Epoch | Neyi geçersiz kılar | Ne zaman artar | Yayılım hedefi |
|---|---|---|---|
| `session_epoch` (kullanıcı başına) | Kullanıcının tüm token'ları | Parola değişimi, tüm cihazlardan çıkış, hesabın devre dışı bırakılması, MFA kaydı, credential değişimi | 250 ms veya altı; bu bir güvenlik olayıdır |
| `authz_epoch` (kiracı başına) | Kiracının yetkilendirme karar cache'i | Rol, politika veya ilişki değişimi | 1 sn veya altı kabul edilebilir |
| `key_epoch` (kiracı başına) | JWKS cache'i | Anahtar rotasyonu | Dakikalar; overlap penceresi bulunur |

Kritik ayrım şudur. `session_epoch` token'ın içinde claim olarak taşınır ve doğrulamada node cache'indeki değerle karşılaştırılır; eşleşmiyorsa token geçersizdir. Bu karşılaştırma ağ turu gerektirmez.

`authz_epoch` ise token'ın içinde taşınmaz; karar cache anahtarının bir parçasıdır. Tek geçerli anahtar tanımı §20 §7.1 ile aynıdır: uzunluk önekli hash, string concat değil.

```
cache_key = blake3_len_prefixed(tenant_id ‖ authz_epoch ‖ subject ‖ action ‖ resource ‖ model_id)
```

> **Düzeltme (2. tur).** Burada önceden `(authz_epoch, subject, action, resource)` yazıyordu ve tenant taşımıyordu; bu, §18'in kendi composite anahtar ilkesine aykırıydı ve §20 §7.1'deki tanımla uyuşmuyordu. İki tanım tek tanıma indirilmiştir.

Epoch arttığında eski anahtarlar erişilemez hâle gelir. Cache silinmez, yalnızca adreslenemez olur ve doğal olarak tahliye edilir.

> **Not.** Bu mekanizma tazeliği tek başına çözmez. Epoch cache'i adreslenemez kılar; cache'i dolduran okumanın tazeliği hakkında bir şey söylemez. `E+1` epoch'u altında, eski bir replica snapshot'ından hesaplanmış bir karar yazılabilir ve orada kalır. Doldurma sözleşmesi §1 §9.3'te kabul edilmiş başlangıç modeli olarak, uçuşta karar semantiği ise açık olarak kayıtlıdır.

Bu modelin doğru olmasının nedeni şudur: bir kullanıcının rolü değiştiğinde oturumunun düşürülmesi istenmez, yalnızca bir sonraki yetkilendirme kararının taze olması istenir. `authz_epoch` tam olarak bunu yapar ve oturuma hiç dokunmaz.

Ters yön de doğrudur: `session_epoch` arttığında karar cache'inin temizlenmesine gerek yoktur, çünkü o kullanıcının hiçbir token'ı zaten geçerli değildir.

### Zanzibar'ın zookie'siyle ilişkisi

§20'deki new-enemy problemi bu tasarımla şöyle ilişkilenir: `authz_epoch` monoton bir sayaçtır, zookie değildir ve nedensel tutarlılık garantisi vermez. İki farklı ilişki değişikliğinin sırası korunmaz. Bu kabul edilebilir bir takastır ve tek koşulu vardır.

Yetkilendirme kararı bir read replica'dan okunmuşsa `authz_epoch` yeterli değildir. İzin kaldırma işlemleri — izin verme değil — primary'den doğrulanmalıdır, çünkü replikasyon gecikmesi tam olarak new-enemy penceresidir.

Bu, HA raporunun kendi tablosuyla tutarlıdır: token iptali ve `revocation_epoch` kontrolü read replica'ya yönlendirilemez. Aynı kural izin kaldırmaya da uygulanır.

### Karar

```rust
struct EpochSet {
    session_epoch: u64,   // kullanıcı başına — token claim'i, ≤250ms yayılım
    authz_epoch:   u64,   // kiracı başına — karar cache anahtarı, ≤1s yayılım
    key_epoch:     u64,   // kiracı başına — JWKS cache, dakikalar
}
```

1. `session_epoch` token'da taşınır ve node cache'iyle karşılaştırılır. Veritabanı turu yapılmaz. HA raporunun kademeli bozulma özelliği korunur.
2. `authz_epoch` karar cache anahtarının parçasıdır. Artması cache'i adreslenemez kılar; temizleme işi yoktur.
3. Üçü de aynı transactional outbox üzerinden 100-250 ms polling ile yayılır. Postgres `LISTEN/NOTIFY` kullanılmaz: PgBouncer transaction modunda çalışmaz ve kuyruk dolduğunda yazma işlemleri commit aşamasında başarısız olur.
4. İzin kaldırma ve `session_epoch` kontrolü read replica'ya yönlendirilmez. İzin verme yönlendirilebilir.
5. `authz_epoch`'un kiracı başına olması kasıtlıdır. Kullanıcı başına olsaydı kiracı geneli bir politika değişimi N sayaç artışı gerektirirdi; global olsaydı bir kiracının değişimi tüm kiracıların cache'ini düşürürdü.

---

## Çelişki 5 — Formel doğrulama: Argus tamamen async, araçlar async desteklemiyor

**İddia A (§10).** Kani ve Verus ciddi güvence sağlamaktadır; Cedar'ın Lean 4 ile doğrulanması emsaldir.

**İddia B (aynı dosya, doğrulanmış kısıtlar).** Kani await ifadelerini ve async'i desteklemez, concurrency kapsam dışıdır. Verus `async fn`, async blok ve `await` desteklemez; ayrıca `Pin`, I/O, `serde::Serialize`, kullanıcı tanımlı `Drop`, `Mutex` ve `RwLock` da desteklenmez. Flux heap ayıran tipleri (`String`, `Vec`), smart pointer'ları (`Box`, `Rc`, `Arc`), async/await'i ve dinamik trait object'leri desteklemez. KMIR'de async/await yoktur; Miri'de ağ yoktur.

Argus ise baştan sona axum ve tokio üzerine kurulu, tamamen async bir sistemdir.

### Gerçekte ne oluyor

Bu gerçek bir kısıttır ve çözümü aracı değiştirmek değil, mimariyi bölmektir. Formel doğrulama raporunun kendi sonucu bunu zaten söylemektedir: Verus'un yeri saf, senkron ve I/O içermeyen bir çekirdek modüldür — örneğin politika değerlendirme motoru veya token durum makinesi — ve bu modül geri kalanla `external_body` sınırından konuşur.

Aynı rapor HTTP katmanı için hiçbir formel aracın uygun olmadığını, orada yalnızca fuzz, entegrasyon testi ve Shuttle'ın kullanılabileceğini belirtir.

Dolayısıyla asıl soru async'in nasıl doğrulanacağı değil, neyin senkron ve saf olması gerektiğine karar verilip verilmediğidir. Bu, formel doğrulamadan bağımsız olarak da doğru bir mimari karardır.

### Hangi bileşen saf ve senkron olabilir

| Bileşen | Saf ve senkron olabilir mi | Doğrulama aracı |
|---|---|---|
| OAuth AS durum makinesi: grant tipi geçişleri, PKCE eşleştirme, code'un tek kullanımlık olması | Evet. Girdi bir `Request` struct'ı, çıktı bir `Decision` enum'udur. I/O çağıran değil, I/O isteyen bir tasarımdır | Kani; bounded model checking, `#[kani::proof]` |
| Politika değerlendirme: Cedar embed ve kendi ReBAC katmanı | Evet. Cedar zaten bu biçimde tasarlanmıştır | Cedar'ın Lean 4 ispatları miras alınır; kendi ReBAC katmanı için Kani |
| Delegasyon zinciri değişmezleri: monoton daralma, TTL monotonluğu, derinlik, kesişim | Evet; saf fonksiyondur | Kani. Bu, ajan kimliğindeki altı invariantın makine-kontrollü hâlidir |
| Epoch karşılaştırma mantığı (Çelişki 4) | Evet | Kani |
| Parser'lar: JWT, JSON, XML, DER, SCIM filter | Kısmen. Derinlik sınırı mantığı saftır, ayrıştırmanın kendisi değildir | Birincil araç cargo-fuzz; derinlik invariantı için Kani |
| Kripto | — | Miras alınır: s2n-bignum HOL Light, HACL*. Kendimiz doğrulamayız |
| HTTP katmanı, DB katmanı, tokio runtime | Hayır | Hiçbir formel araç uygulanmaz. fuzz, entegrasyon testi ve Shuttle (deterministik concurrency testi) kullanılır |

### Karar

Formel doğrulama kapsamı "async olmayan çekirdek" olarak yeniden tanımlanır ve bu bir mimari zorlamaya çevrilir.

1. `argus-core` I/O yapmaz. Fonksiyonlar `async` değildir ve `Result<Decision, Error>` döner. Veri erişimi çağıran tarafından önceden yapılır ve struct olarak geçirilir. Kural CI'da zorlanır: `argus-core`'da `async fn`, `tokio::`, `sqlx::` veya `reqwest::` görünmesi build'i kırar.
2. Kani'nin hedefi dört alandır: OAuth durum makinesi geçişleri, delegasyon zinciri değişmezleri, epoch karşılaştırma ve parser derinlik invariantları. Bunların tamamı saf ve sınırlıdır.
3. Verus denenmez. `serde::Serialize` ve `Mutex` desteklememesi, aracın IdP kod tabanının hiçbir gerçek parçasına uymamasını neredeyse garanti eder. Kani'nin `#[kani::proof]` ergonomisi aynı işi kabul edilebilir bir maliyetle yapar. Bu, §10'un sunduğu seçeneklerden bir sapmadır ve gerekçesi yetenek değil ergonomidir.
4. Async katman için formel doğrulama iddia edilmez. Bu katmanda araç seti şudur: `cargo-fuzz` (parser'lar ve protokol yüzeyleri), Shuttle (deterministik concurrency, tokio ile çalışır), property-based test (`proptest`) ve interop conformance süitleri.
5. Cedar embed edilir, yeniden yazılmaz. Lean 4 ile doğrulanmış bir politika motorunun kendi yazdığımızla değiştirilmesi, kazanılmış tek maliyetsiz güvencenin terk edilmesi anlamına gelir.

| | İfade |
|---|---|
| İzin verilen | Argus'un yetkilendirme çekirdeği ve protokol durum makinesi sınırlı model kontrolünden geçirilmiştir; kripto katmanı makine-kontrollü ispatlara sahip implementasyonlar kullanır; HTTP ve depolama katmanları fuzz ve deterministik concurrency testine tabidir. |
| İzin verilmeyen | Argus formel olarak doğrulanmıştır. |

---

## Özet

| # | Çelişki | Karar | Etkilenen bölüm |
|---|---|---|---|
| 1 | `ES256` ile `ESP256` | Çelişki yoktu. `ES256` JWS'te doğrudur; `ESP256` COSE ve WebAuthn tarafında eklenir. `alg: EdDSA` reddedilir. Veri modelinde `algorithm` alanı ve rotasyon yolu gün-1'de bulunur | §18, §17 |
| 2 | `forbid(unsafe_code)` ile aws-lc-rs | Çelişki yoktu. Crate düzeyi lint'tir; FFI yalnızca `argus-crypto` ve `argus-sandbox`'tadır. rustls emsaldir. `cargo geiger --forbid-only` gate olarak koşar | §11, §7 |
| 3 | SAML: saf Rust ile süreç izolasyonu | İkisi de uygulanır. `bergshamra` bellek güvenliği riskini çözer; süreç izolasyonu kaynak sınırlaması için kalır. Domain modeli kendimiz yazarız. Bağımlılığın test süiti bizim CI'ımızda koşar | §16, §11 |
| 4 | `revocation_epoch` ile karar cache'i | Üç ayrı epoch kullanılır: `session_epoch` (token claim'i, 250 ms), `authz_epoch` (cache anahtarı, 1 sn), `key_epoch`. İzin kaldırma replica'dan okunmaz | §19, §20 |
| 5 | Formel doğrulama ile async | Kapsam "async olmayan çekirdek" olarak yeniden tanımlanır ve mimari zorlamaya çevrilir. `argus-core` I/O yapmaz ve bu CI'da zorlanır. Kani kullanılır, Verus kullanılmaz. Async katmanda formel iddia yoktur | §10 |

Beş karardan dördü mimariyi değiştirmektedir (2, 3, 4, 5); biri yanlış anlaşılmadan kaynaklanmıştır (1).

En pahalı olanı beşinci karardır: `argus-core`'un I/O içermemesi ilk satırdan itibaren uyulması gereken bir kısıttır ve sonradan uygulanamaz.
