# §4 — Kimlik ve kimlik doğrulama alan referansı

Sektörden bağımsız, uçtan uca bir referanstır. Kavramları, protokolleri, yöntemleri, tehditleri, ürünleri, mimari kalıpları, kullanıcı deneyimini, senaryo oyun kitaplarını, yeni nesil gelişmeleri, uyum gereksinimlerini ve anti-pattern'leri kapsar.

| Bölüm | Konu |
|---|---|
| I | Temeller ve kavram haritası (1-4) |
| II | Protokoller ve standartlar (5-14) |
| III | Kimlik doğrulama yöntemleri (15-24) |
| IV | Tehdit modeli (25-28) |
| V | Ürün envanteri (29-37) |
| VI | Mimari kalıpları (38-50) |
| VII | Kullanıcı deneyimi ve dönüşüm (51-56) |
| VIII | Senaryo oyun kitapları (57-68) |
| IX | Yeni nesil (69-78) |
| X | Uyum ve mevzuat (79-84) |
| XI | Komşu ekosistem (85-92) |
| XII | Anti-pattern kataloğu (93) |
| XIII | Seçim rehberi ve olgunluk (94-96) |
| XIV | Bu dokümanın sınırları (97) |
| XV | Kapatılan boşluklar: IGA, PAM, ulusal eID, DID/SSI, biyometrik satıcılar (98-102) |

---

## Bölüm I — Temeller

### 1. Terminoloji

| Terim | Anlamı | Cevapladığı soru |
|---|---|---|
| AuthN | Kimlik doğrulama | Bu gerçekten o kişi mi |
| AuthZ | Yetkilendirme | Bunu yapabilir mi |
| Identity proofing | Kimlik tespiti | Bu kişi gerçek dünyada var mı ve bu o mu |
| Federation | Kimliğin sistemler arası taşınması | Başka bir IdP'nin doğrulamasına güveniyor muyum |
| Provisioning | Hesabın yaratılması, güncellenmesi, silinmesi | İşten ayrılanın erişimi kesildi mi |
| Session | Doğrulanmış durumun sürdürülmesi | Her sayfada tekrar giriş gerekmesin |
| Consent | Kullanıcının veri ve erişim onayı | Bu uygulamaya hangi izni verdi |
| Entitlement | Somut hak | Premium özelliklere erişimi var mı |

Sık karıştırılan üç ayrım şudur.

OAuth bir yetkilendirme çerçevesidir, kimlik doğrulama protokolü değildir. OIDC bunun üzerine kimlik katmanı ekler. "OAuth ile giriş yaptım" ifadesi teknik olarak yanlıştır.

Authentication ile identity proofing aynı şey değildir. Passkey kullanıcının kim olduğunu söylemez; yalnızca kayıt anındaki kişiyle aynı olduğunu söyler.

SSO ile MFA aynı şey değildir. Biri kaç kez giriş yapıldığıyla, diğeri her girişte kaç kanıt istendiğiyle ilgilidir.

### 2. Ürün kategorileri

| # | Kategori | Ne yapar | Ne yapmaz | Örnekler |
|---|---|---|---|---|
| 1 | Tam IdP ve IAM platformu | Kimlik deposu, login arayüzü, protokol, admin konsolu | Ürünün içine gömülmez | Keycloak, Zitadel, Authentik |
| 2 | Headless kimlik altyapısı | API üzerinden kimlik ve token | Hazır login ekranı vermez | Ory, Logto, SuperTokens |
| 3 | Uygulama içi kütüphane | Auth'u backend'in parçası yapar | Diğer uygulamalara SSO vermez | Better Auth, Auth.js |
| 4 | Yönetilen CIAM (SaaS) | Her şeyi barındırır | Veri egemenliği ve maliyet kontrolü vermez | Auth0, Clerk, WorkOS |
| 5 | Protokol motoru | Sertifikalı OAuth ve OIDC mantığı | Kullanıcı deposu ve arayüz vermez | Authlete, Duende, node oidc-provider |
| 6 | Yetkilendirme motoru | Erişim kararı | Kimlik doğrulama yapmaz | OpenFGA, SpiceDB, Cerbos |
| 7 | Workload ve ajan kimliği | İnsan olmayan aktörlerin kimliği | İnsan login'i yapmaz | SPIFFE/SPIRE, Entra Agent ID |

Beş yakın kategori arasındaki ayrım şudur. IAM çalışan kimliğidir: dizin, kurumsal SSO, cihaz politikaları. CIAM müşteri kimliğidir: kayıt akışı, sosyal login, tüketici ölçeği, dönüşüm oranı. IGA yönetişimdir: erişim gözden geçirmeleri, onay akışları, sertifikasyon. PAM ayrıcalıklı erişimdir: kasa, oturum kaydı, JIT yükseltme. NHI insan olmayan kimliklerdir: servis hesapları, workload'lar, API anahtarları, ajanlar.

### 3. Aktör haritası

Auth tasarımı "kullanıcı" tekilinden çıkıp aktörleri ayırmakla başlar.

| Aktör | Örnek | Tipik yöntem |
|---|---|---|
| Son kullanıcı (tüketici) | Uygulama kullanıcısı | Passkey, sosyal login, magic link |
| Son kullanıcı (çalışan) | Kurumsal personel | SSO (SAML veya OIDC), phishing-resistant MFA |
| Yönetici ve operatör | Admin paneli | MFA zorunlu, PAM, oturum kaydı |
| Destek personeli | Müşteri temsilcisi | Kısıtlı impersonation, tam denetim izi |
| Geliştirici | API tüketicisi | API anahtarı, OAuth client credentials |
| Servis ve workload | Mikroservis | mTLS, SPIFFE, client credentials |
| Cihaz | IoT sensörü, TV, kiosk | Sertifika, device flow, provisioning |
| Ajan | AI asistanı | Delegasyon zinciri, kısa ömürlü token |
| Anonim ve misafir | Kayıtsız ziyaretçi | Oturum kimliği, sonradan yükseltme |
| Üçüncü taraf uygulama | Entegrasyon | OAuth, scope'lu erişim |

### 4. Kimlik veri modeli

Neredeyse her projede aynı hatalar tekrarlanmaktadır. Temel model şudur:

```
users            → id (opak, değişmez), created_at, status
identities       → user_id, provider (password/google/apple/passkey/saml),
                   provider_subject_id, verified_at
credentials      → user_id, type, secret_hash veya public_key, algorithm,
                   created_at, last_used_at
sessions         → user_id, device_id, acr, created_at, expires_at
```

Kurallar şunlardır.

Birincil anahtar e-posta olmamalıdır. İnsanlar e-posta değiştirir; opak ve değişmez bir `user_id` kullanılır.

Bir kullanıcının birden çok kimliği olur. Aynı kişi hem parola hem Google hem passkey ile gelebilir; `identities` tablosu bunu doğal karşılar.

Algoritma alanı saklanır. Parola hash'inde ve passkey açık anahtarında algoritma tanımlayıcısı yoksa migration bloke olur (§4 §24, §4 §77).

E-posta doğrulanmışlığı bir bayrak değil, kimlik başına bir özelliktir. Google'dan gelen e-posta doğrulanmıştır, elle yazılan değildir.

Silme yerine durum kullanılır. Hesap silme talebi mevzuat gerektirmedikçe hard delete olmamalıdır; anonimleştirme ve tombstone uygulanır.

Çakışma senaryosu baştan çözülür: aynı e-posta ile önce parola, sonra Google ile gelen kullanıcının ne olacağı tanımlanır (§4 §45).

---

## Bölüm II — Protokoller ve standartlar

### 5. OAuth 2.0 ve 2.1

| Grant | RFC | Durum |
|---|---|---|
| Authorization Code + PKCE | 6749 ve 7636 | Varsayılan; tüm istemci tipleri |
| Refresh Token | 6749 | Standart; rotasyonla kullanılır |
| Client Credentials | 6749 | Servis-servis |
| Device Authorization Grant | 8628 | TV, CLI, kısıtlı giriş cihazları |
| Token Exchange | 8693 | Delegasyon ve impersonation |
| JWT Bearer | 7523 | Servis-servis assertion |
| SAML Bearer | 7522 | Legacy köprü |
| Implicit | 6749 | Ölü; OAuth 2.1 kaldırmıştır |
| ROPC (password) | 6749 | Ölü; OAuth 2.1 kaldırmıştır |

OAuth 2.1 yeni bir protokol değil, güvenli varsayılanların zorunlu hâle getirilmesidir: PKCE her yerde, implicit ve ROPC yok, redirect URI tam eşleşme, bearer token query string'de taşınmıyor.

RFC 9700 (Security BCP) modern OAuth güvenliğinin referansıdır; FAPI 2.0 dahil tüm modern profiller bunu takip eder.

### 6. OpenID Connect

OAuth üzerine kurulan kimlik katmanıdır: ID Token (JWT), UserInfo endpoint, standart claim'ler ve Discovery sağlar.

| Uzantı | İşlev |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Dynamic Client Registration (7591 ve 7592) | İstemcinin kendini kaydetmesi; MCP'de deprecate edilmiştir |
| Client ID Metadata Documents (CIMD) | DCR'ın yerini alan model; istemci kimliği bir URL'de yayımlanır |
| RP-Initiated Logout | Merkezi çıkış |
| Front-channel ve back-channel logout | Oturum senkronizasyonu |
| Session Management | Oturum durumu izleme |
| CIBA | Backchannel kimlik doğrulama (§4 §13) |
| `prompt=create` | Doğrudan kayıt akışı |
| Native SSO | Uygulamalar arası token devri |

### 7. Kurumsal ve legacy protokoller

**SAML 2.0.** Kurumsal SSO'nun fiili standardıdır. XML tabanlıdır ve ağırdır, ancak B2B satışta kapı bekçisidir. Ory'nin desteklememesi ciddi bir boşluktur.

**LDAP ve Active Directory.** Dizin federasyonu.

**Kerberos.** İç ağ, bilet tabanlı.

**SCIM 2.0.** Otomatik provisioning (joiner, mover, leaver). Kurumsal alıcının en sık sorduğu özelliktir. Destekleyenler: Keycloak, WorkOS, Auth0, Entra External ID, Frontegg, Stytch, FusionAuth, Descope, SSOJet. Clerk'te yeni yayılmaktadır.

**RADIUS.** Ağ erişimi ve VPN.

**WS-Federation.** Neredeyse tamamen legacy.

**XACML.** Politika tabanlı yetkilendirmenin eski standardıdır; yerini modern policy engine'ler almıştır.

### 8. Güvenlik uzantıları

**PKCE (7636).** Authorization code interception'ı engeller. `code_verifier` üretilir, hash'i istekte gider ve token isteğinde verifier sunulur. Artık tüm akışlarda zorunludur.

**PAR (9126).** İstek parametreleri önce backchannel'dan gönderilir ve `request_uri` alınır. Parametreler tarayıcıdan hiç geçmez.

**RAR (9396).** Scope string'inin ifade edemediği yapısal yetki taleplerini `authorization_details` nesnesiyle taşır.

**JAR (9101).** İsteğin imzalanmış JWT olarak taşınmasıdır. JARM ise yanıtın imzalanmasıdır.

**DPoP (9449).** Uygulama katmanında sender-constrained token sağlar. İstemci bir anahtar çifti üretir ve her istekte imzalı proof JWT gönderir; AS açık anahtarın thumbprint'ini token'a bağlar. Çalınan token özel anahtar olmadan kullanılamaz. Replay nonce mekanizmasıyla engellenir. Keycloak'ta 26.4 sürümünden beri tam desteklidir.

**mTLS (8705).** İstemci kimlik doğrulaması ve token'ın sertifikaya bağlanmasıdır. Güvenlidir ancak üretimde bakımı DPoP'tan zordur.

**Resource Indicators (8707).** Token'ın hangi kaynak sunucusu için geçerli olduğunu belirtir. Replay sorununu çözer, consent sorununu çözmez.

**Step-up Challenge (9470).** Kaynak sunucusunun daha güçlü doğrulama talep edebilmesini sağlar; `acr_values` ve `max_age` ile kullanılır.

**Token Exchange (8693).** Token takasıdır; `act` claim'i ile delegasyon ve impersonation ayrımı yapılır. Ajan mimarilerinin temel taşıdır.

**Issuer Identification (9207).** Yanıtta `iss` parametresi taşınır ve çoklu AS senaryosunda mix-up saldırısını kapatır.

### 9. Kimlik doğrulama assurance çerçeveleri

#### NIST SP 800-63-4

Belge finaldir ve 800-63-3'ün yerini almıştır.

**IAL — kimlik tespiti gücü.** IAL1 yeniden tanımlanmıştır. Uzaktan ve gözetimsiz kimlik tespiti (video veya biyometrik) artık IAL2'ye tam yoldur.

**AAL — kimlik doğrulama gücü.** AAL1 tek faktördür. AAL2 iki farklı faktör gerektirir ve replay'e dirençlidir; yeni gereksinim olarak AAL2 uygulamaları phishing-resistant bir seçenek sunmak zorundadır, SMS OTP izinlidir ancak önerilmez. AAL3 açık anahtar kriptografisiyle sahiplik kanıtı, phishing-resistant authenticator, dışa aktarılamaz özel anahtar, açık kullanıcı niyeti ve FIPS 140-3 gerektirir; senkronize passkey kabul edilmez.

**FAL — federasyon.** FAL1 bearer assertion, FAL2 sahiplik kanıtı, FAL3 imzalı assertion ve endpoint doğrulamasıdır.

Phishing resistance'ın tanınan iki yöntemi channel binding ve verifier name binding'dir.

**Parola rehberi.** İhlal kanıtı olmadan periyodik zorunlu rotasyon, karakter tipi zorunlulukları ve güvenlik soruları yasaklanmıştır. Parola alanında yapıştırmaya izin verilmelidir. Rate limiting zorunludur.

#### eIDAS LoA

Low, Substantial ve High seviyeleri bulunur. EUDI Wallet High seviyesine hedeflenmektedir.

### 10. Kripto temelleri

**JWT imzalama.** RS256 yaygındır, ES256 tercih edilendir ve daha küçüktür, EdDSA moderndir. HS256 yalnızca tek taraflı senaryoda kullanılır ve public client ile paylaşılmaz.

**JWKS rotasyonu.** Yeni anahtar yayımlanır, eski anahtar JWKS'te en uzun token ömrü kadar tutulur, yeniyle imzalamaya başlanır ve ardından eski kaldırılır. `kid` header'ı zorunludur.

**Yaygın JWT hataları.** `alg: none` kabul etmek, algoritma karıştırmak (RS256 imzalı token'ı HS256 olarak doğrulamak), `aud` ve `iss` doğrulamamak, `exp` kontrolü yapmamak, saat kayması toleransı vermemek.

> **Uyarı.** `private_key_jwt` üreten istemcide sistem saati yanlışsa client authentication başarısız olur. İstemci, sunucunun HTTP `Date` header'ı ile saatini senkronize etmelidir; bu özellikle kullanıcı kontrolündeki cihazlarda önemlidir.

### 11. FAPI — Financial-grade API

Adı finansaldır ancak her yüksek değerli API için tasarlanmıştır; e-sağlık ve e-devlet de hedef alanlardadır.

**FAPI 1.0.** Baseline (Part 1) ve Advanced (Part 2) olmak üzere iki profili vardır. Açık bankacılık ekosistemlerinin çoğu bu profiller üzerinedir.

**FAPI 2.0 (Final, Şubat 2025).** RFC 9700 BCP'yi takip eder. Bearer token kabul edilmez; sender-constrained token (mTLS veya DPoP) zorunludur. Yalnızca confidential client'lar desteklenir. İstemci kimlik doğrulaması yalnızca mTLS veya `private_key_jwt` ile yapılır; `none` ve `client_secret_basic` yasaktır. PAR zorunludur ve ROPC reddedilmelidir. Kripto tarafında RSA en az 2048 bit olmalı, ES256 tercih edilmelidir. Refresh token rotation olağanüstü durumlar dışında kullanılmamalıdır.

**Pratik sonuç.** Mobil uygulama public client olduğu için FAPI 2.0 ona uygulanamaz; sunucu destekliyor olsa dahi. FAPI, üçüncü taraf istemcilerin erişimi için bir profildir.

**Sertifikalı implementasyonlar.** Authlete 3.0, IBM Verify (IAM v11, SaaS), node oidc-provider 9.2.0 ve üstü, go-oidc 0.11.0 ve üstü, Auth0 Highly Regulated Identity, WSO2 IS 7.1.0, NRI Uni-ID Libra 2.12, Zerobank BaaS, Vouch Server, BCP CAS V6, AUTHRDS. Keycloak 26.4 FAPI 2 final profillerini destekler ve conformance süitinden geçer.

### 12. FiPA — First-Party Applications

`draft-ietf-oauth-first-party-apps`, -04 revizyonu 1 Temmuz 2026 tarihlidir ve 2 Ocak 2027'de expire olur. Yazarları Parecki (Okta), Fletcher (Practical Identity) ve Kasselman (Defakto)'dır.

Yeni `authorization_challenge_endpoint` ile istemci kullanıcıdan bilgi toplar, POST eder ve ya authorization code ya hata kodu alır. Hata kodu ya daha fazla bilgi istenmesini ya tarayıcıya düşülmesini söyler.

Sonuç, native uygulamalar için tarayıcısız OAuth'tur; RFC 8252 redirect artık fallback konumundadır.

**Kısıtlar.** Yalnızca first-party senaryolarda kullanılır; AS ve uygulama aynı varlık olmalı ve kullanıcı da böyle algılamalıdır. SPA'lar kapsam dışıdır. Yüksek güven derecesi gerektirir. Yalnızca redirect'in kullanılabilirlik sorunu yarattığı yerlerde uygulanır.

### 13. CIBA

OIDC uzantısıdır ve ayrı bir grant type'tır. İstemci AS'e isteği son kullanıcının doğrulamasını söyler; AS kullanıcıyla iletişimi yönetir; işlem tamamlandığında token döner.

**Üç mod.** Poll modunda istemci sorgular, Ping modunda AS haber verir ve istemci çeker, Push modunda AS doğrudan gönderir.

**Kullanım alanı.** Kullanıcının işlemi başlatan cihazla etkileşemediği her senaryo: masaüstünde başlayan işlemi telefonda onaylamak, çağrı merkezinde kimlik doğrulamak, kiosk'ta yetki almak.

**Sınır.** CIBA tek başına neyin onaylandığını bağlamaz; imzalama ve payload bağlama ayrı bir iştir (§4 §48).

### 14. Standart olgunluk özeti

| Katman | Bugünün doğru cevabı |
|---|---|
| Yetkilendirme akışı | Authorization Code + PKCE |
| Token güvenliği | Public client'ta DPoP, sunucular arasında mTLS |
| İstek güvenliği | PAR ve gerekirse RAR |
| Kimlik doğrulama yöntemi | Passkey birincil, fallback ikincil |
| Kurumsal federasyon | OIDC, SAML ve SCIM |
| Oturum devamlılığı | Rotasyonlu refresh ve reuse detection |
| Yükseltme | RFC 9470 step-up |
| İptal | SSF ve CAEP (§4 §74) |

---

## Bölüm III — Kimlik doğrulama yöntemleri

### 15. Yöntem haritası

| Yöntem | Faktör | Phishing direnci | Kullanıcı deneyimi | Maliyet |
|---|---|---|---|---|
| Parola | Bilgi | Yok | Kötü | Düşük |
| SMS OTP | Sahiplik | Yok | Orta | Mesaj başına |
| E-posta OTP ve magic link | Sahiplik | Zayıf | İyi | Düşük |
| TOTP (authenticator) | Sahiplik | Yok | Orta | Sıfır |
| Push bildirimi | Sahiplik | Yok; fatigue'e açık | İyi | Altyapı |
| Push ve number matching | Sahiplik | Kısmi | İyi | Altyapı |
| Passkey (senkronize) | Sahiplik ve doğrulama | Var | Çok iyi | Düşük |
| Passkey (cihaza bağlı) | Sahiplik ve doğrulama | Var | İyi | Düşük |
| Donanım anahtarı | Sahiplik | Var | Orta | Cihaz başına |
| İstemci sertifikası | Sahiplik | Var | Kötü | PKI |
| Biyometri (cihaz) | Doğrulama | Platforma bağlı | Çok iyi | Sıfır |
| Sosyal login | Federasyon | IdP'ye bağlı | Çok iyi | Sıfır |
| Kurumsal SSO | Federasyon | IdP'ye bağlı | Çok iyi | Entegrasyon |
| Akıllı kart ve PIV | Sahiplik | Var | Kötü | Yüksek |

### 16. Parolalar

Parolalar hâlâ kullanımdadır ve doğru uygulanmalıdır.

#### Saklama

OWASP Password Storage Cheat Sheet'in 2026 tavsiyeleri aşağıdadır.

**Argon2id (birinci tercih).** Temel parametreler t=2, m=19.456 KiB (19 MiB) ve p=1'dir; modern bir x86 sunucu çekirdeğinde yaklaşık 100 ms doğrulama süresi verir. Bellek fazlaysa ve CPU'dan tasarruf isteniyorsa m=47.104 KiB (46 MiB), t=1, p=1 kullanılır. OWASP birbirine eşdeğer güçte beş parametre seti listeler; aralarındaki fark CPU ile bellek arasındaki takastır.

Kritik nokta, ASIC ve GPU saldırganlarını ezen şeyin zaman maliyetinden çok bellek maliyeti olmasıdır. Donanım kaldırabiliyorsa aralığın yüksek bellek ucu tercih edilir.

RFC 9106'nın, yani Argon2 yazarlarının kendi tavsiyeleri farklı ve daha agresiftir: yüksek bellek için t=1, p=4, m=2^21 (2 GiB); düşük bellek için t=3, p=4, m=2^16 (64 MiB).

**scrypt.** Argon2id kullanılamıyorsa devreye girer. Asgari CPU ve bellek maliyeti 2^17, blok boyutu 8 (1024 bayt), paralellik 1'dir. 2026'da nadiren doğru seçimdir; Argon2id scrypt'in yaptığı her şeyi daha iyi yapar.

**bcrypt (legacy).** Work factor en az 10, tercihen 12 ve üstüdür. 72 baytlık giriş sınırı bulunur; daha uzun parolalar için ön-hash gerekir. Bellek sertliği yoktur.

**PBKDF2.** Yalnızca FIPS-140 zorunluysa kullanılır. HMAC-SHA-256 ile asgari 600.000 iterasyon, SHA-512 ile 220.000 iterasyon gerekir. Eski kodda dolaşan 10.000 değeri kabul edilemez. GPU saldırılarına karşı dört seçeneğin en zayıfıdır.

**Pepper.** Veritabanı dışında saklanan ortak gizli değerdir; salt gibi benzersiz değil, paylaşımlıdır. Tek başına güvenlik özelliği eklemez, savunma derinliği katar. Hash fonksiyonunu hiçbir şekilde etkilemez; üstüne AES-GCM katmanı olarak uygulanır.

**Salt.** Her parolaya benzersiz, en az 16 bayt ve kriptografik rastgele olur.

**Migration.** MD5 veya SHA-1'den geliniyorsa mevcut hash'ler doğrudan dönüştürülmez; sarmalanır ve bir sonraki girişte yeniden hash'lenir. `PasswordNeedsRehash` benzeri bir kontrol her başarılı doğrulamadan sonra çalışmalıdır.

#### Politika

NIST 800-63-4 sonrası doğru politika şudur: en az 8 karakter (15 ve üstü önerilir) ve en fazla asgari 64 karakter; karakter tipi zorunluluğu yok; ihlal kanıtı yoksa periyodik zorunlu rotasyon yok; Have I Been Pwned k-anonymity API'si ile ihlal listesi kontrolü; Unicode ve boşluk kabulü; yapıştırmaya izin; güvenlik sorularının authenticator olarak kullanılmaması; zorunlu rate limiting.

### 17. OTP ve magic link

**SMS OTP.** En yaygın ve en zayıf yöntemdir. AiTM proxy'ye şeffaftır, SIM swap'e açıktır, teslimat güvenilirliği ülkeye göre değişir ve maliyeti mesaj başınadır. NIST AAL2'de izinlidir ancak önerilmez. Hindistan ve Endonezya gibi bazı ülkelerde hâlâ pratik bir zorunluluktur.

**E-posta OTP ve magic link.** Teslimat spam filtresine bağlıdır; e-posta hesabı ele geçmişse yöntem tamamen açıktır. Buna karşılık evrensel uyumluluk sağlar ve hâlâ en yaygın dağıtılmış passwordless yöntemidir.

**Magic link tuzakları.** Link önizleme botları (Outlook Safe Links, Slack unfurl) linki tıklar ve token'ı harcar; çözüm GET yerine onay ekranı koymak veya tek kullanımlık token yerine kısa ömürlü kod kullanmaktır. Farklı cihazda açılma sorunu için çözüm aynı cihaz kısıtı veya kod gösterimidir.

**TOTP.** Ücretsizdir, çevrimdışı çalışır ve phishing'e açıktır. Kurtarma kodları zorunlu eşlikçisidir.

### 18. Push bildirimi

Kullanıcı deneyimi iyidir ancak MFA fatigue saldırısına açıktır: saldırgan onay isteğini bombardıman eder ve kullanıcı yorgunlukla onaylar.

Number matching bu saldırıyı büyük ölçüde kapatır; ekranda gösterilen sayının kullanıcı tarafından telefonda seçilmesi gerekir. Yanına işlem bağlamı eklenmelidir: nereden, hangi uygulama, hangi işlem.

Yine de AiTM'e karşı koruma sağlamaz; proxy başarılı onayı bekler ve sonrasındaki oturumu alır.

### 19. Passkey, WebAuthn ve FIDO2

**Yapı.** WebAuthn W3C tarayıcı API'sidir, CTAP authenticator ile istemci arasındaki protokoldür ve güncel hattı 2.2'dir. İkisinin birleşimi FIDO2'dir.

| Tür | Saklama | Assurance |
|---|---|---|
| Senkronize passkey | iCloud Keychain, Google Password Manager, 1Password, Bitwarden | AAL2 |
| Cihaza bağlı passkey | Tek cihaz, dışa aktarılamaz | AAL2 üstü |
| Donanım anahtarı | YubiKey, Titan, Nitrokey, SoloKeys, Token2 | AAL3 |

**WebAuthn Level 3.** Temmuz 2026'da W3C Recommendation'a önerilmiştir. Şifreleme anahtarı türetme, cross-domain credentials ve otomatik liste senkronizasyonu birinci sınıf özelliklerdir.

**Kritik mekanizmalar.** Conditional UI (`mediation: conditional`) autofill içinde passkey önerisi sunar ve benimseme oranını en çok etkileyen tek mekanizmadır. User Verification platformun kullanıcıyı doğrulamasıdır; delegasyon bazı regülasyonlarda kabul edilmez (§4 §83). PRF extension passkey'den şifreleme anahtarı türetir ve uçtan uca şifreli uygulamalar için kullanılır. Attestation authenticator modelini kanıtlar ve tüketici senaryolarında genelde kapatılır. Discoverable credential (resident key) kullanıcı adı girmeden girişe imkân verir.

**Benimseme.** FIDO Alliance State of Passkeys 2026 çalışması 10 ülkede 11.000 tüketici ve 1.400 kurumsal karar verici ile Nisan 2026'da yapılmıştır. Yaklaşık 5 milyar aktif passkey bulunmaktadır. Farkındalık %90'dır (önceki yıl %75); yalnızca %7 hiç duymamıştır. Kullanıcıların %75'i en az bir hesapta etkinleştirmiş, %49'u düzenli kullanmaktadır. Kurumların %68'i çalışan girişi için dağıtmış, pilotlamış veya yaymaktadır. En büyük 100 sitenin yaklaşık %48'i desteklemektedir; bu oran 2022'nin iki katından fazladır. Giriş başarı oranı %93'tür; klasik yöntemlerde %63'tür.

**Bölgesel dağılım.** Japonya passkey benimsemesinde öndedir (%67); ardından Güney Kore (%62) ve Singapur (%58) gelir. Hindistan ve Brezilya magic link ağırlıklıdır (%75'in üzerinde).

**Gerçeklik kontrolü.** Passkey oluşturulması benimseme anlamına gelmez. İş gücü login'lerinin %10'undan azı tam passwordless'tır. Sebepleri kapsamanın eşitsiz olması (her uygulama WebAuthn konuşmaz), kurtarmanın çözülmemiş olması ve hibrit fazın yapışkan olmasıdır. Cihaz farkında yönlendirme olmadan benimseme %5-10 bandında takılır; orkestrasyon ham protokol desteğinden daha önemlidir.

Satıcı değerlendirirken sorulacak doğru soru "WebAuthn destekliyor musunuz" değil, "son 12 ayda başlayan müşterilerinizde medyan passkey benimseme oranı nedir" sorusudur.

**Geçiş kalıbı.** Önce passkey sunulur, parola 12-18 ay fallback tutulur ve aktif kullanıcıların yaklaşık %60'ı en az bir passkey kaydettiğinde emekliye ayrılır. 2024 ve 2025'in hatası kullanıcıları benimseme olgunlaşmadan zorlamak olmuştur.

### 20. Passkey taşınabilirliği: CXF ve CXP

Kilitlenme korkusu en büyük benimseme engellerinden biriydi; CSV export hassas bilgiyi düz metne döküyordu.

CXF sağlayıcılar arası aktarım formatıdır; ZIP içinde JSON taşır ve CXP'ye göre şifrelenir. CXP ise Diffie-Hellman ve HPKE ile uçtan uca şifreli transfer protokolüdür.

**Katkı verenler.** 1Password, Apple, Bitwarden, Dashlane, Enpass, Google, Microsoft, NordPass, Okta, Samsung, SK Telecom, Devolutions.

**Durum.** Apple iOS ve macOS 26'da CXF tabanlı aynı cihaz transferini yayımlamış ve CXP'yi ilk uygulayan büyük platform olmuştur. Android 14 ve üstü ile Play Services 26.21 ve üstünde import ile export desteklenmektedir; Android'de transfer hedef uygulamadan gelen bir import isteği olarak başlar. İleride ehliyet ve pasaport gibi credential'ları da kapsaması öngörülmektedir.

### 21. Sosyal login

**Kazanç.** Sektör çalışmalarına göre kayıt dönüşümünü ortalama %20-35 artırmaktadır.

| Sağlayıcı | Kime uygun |
|---|---|
| Google | Genel; en yüksek kapsama |
| Apple | iOS zorunluluğu; aşağıya bakınız |
| Microsoft | B2B ve kurumsal |
| GitHub | Geliştirici platformları |
| LinkedIn | B2B ve profesyonel ağlar |
| Discord | Oyun ve yaratıcı toplulukları; 200 milyondan fazla kullanıcı |
| Facebook | Düşüşte; veri endişeleri nedeniyle yedek seçenek |
| WeChat, DingTalk, Lark | Çin ve Asya pazarı |
| Kakao, Naver, LINE | Kore ve Japonya |
| VK | Rusya |

**App Store kuralı.** iOS'ta başka bir SSO sağlayıcı sunuluyorsa Apple ile Giriş zorunludur; kural 2020'den beri geçerlidir.

**Riskler.** Sosyal login zorunlu kılınmaz; e-posta alternatifi her zaman bulunur. Token'lar backend'de doğrulanır ve frontend'den gelen token'a güvenilmez; imza, süre ve `aud` claim'i kontrol edilir ve resmî doğrulama kütüphanesi kullanılır. IdP hesabı ele geçerse bağlı hesap da gider. Sağlayıcı politika değiştirirse — Facebook örneğindeki gibi — kullanıcı tabanı kilitlenir. E-posta yeniden kullanımı da bir risktir: bazı sağlayıcılar silinen hesabın e-postasını başkasına verebilir, dolayısıyla birincil eşleştirme anahtarı `sub` claim'i olur, e-posta değil.

### 22. Kurumsal SSO

B2B satışın kapı bekçisidir. Alıcının sorduğu üçlü SAML, SCIM ve denetim loglarıdır.

**JIT provisioning.** İlk SSO girişinde hesabın otomatik yaratılmasıdır. Hızlıdır ancak kullanıcı silme tarafını çözmez; onu SCIM çözer.

**Domain doğrulama.** Kurumsal alan adının kime ait olduğunun DNS ile kanıtlanmasıdır. Bu olmadan bir müşteri başka bir müşterinin kullanıcılarını çalabilir.

**Break-glass hesabı.** SSO çöktüğünde kullanılacak acil durum hesabıdır: SSO'dan bağımsız, donanım anahtarıyla korunmuş ve kullanımı alarm üreten bir hesap. Kurumsal kurulumda en sık unutulan kritik detaydır.

**IdP-initiated ile SP-initiated.** IdP-initiated SAML güvenlik açısından zayıftır ve replay'e açıktır; mümkünse yalnızca SP-initiated desteklenir.

### 23. Sertifika ve donanım tabanlı yöntemler

**İstemci sertifikası (mTLS).** Servisler ve cihazlar için idealdir, insanlar için kullanıcı deneyimi kötüdür. PKI işletme yükü ciddidir.

**Akıllı kart, PIV ve CAC.** Kamu ve savunmada standarttır; okuyucu donanımı gerektirir.

**Donanım güvenlik anahtarları.** AAL3'ün pratik yoludur. FIPS varyantları mevcuttur. Kayıp senaryosu için en az iki anahtar kaydettirme kuralı uygulanır.

**Mobil imza ve nitelikli elektronik imza.** Operatör tabanlıdır ve hukuki geçerliliği yüksektir. Her operatör için ayrı entegrasyon gerekir; bir operatörün altyapısı diğerinin hatlarıyla çalışmaz.

### 24. Post-quantum hazırlık

**Tehdit.** Shor algoritması RSA (2048 ve 4096) ile ECC'yi kırar. Bugünkü somut risk HNDL'dir: harvest now, decrypt later.

**Öncelik sırası.**

1. TLS handshake: hibrit ML-KEM. Her bağlantıyı etkiler ve HNDL'yi adresler.
2. Token imzalama: ML-DSA'ya geçiş. JWT ve SAML için PQC standartları IETF'te finalize edilmektedir.
3. Kod imzalama: NSA, NIST SP 800-208 (LMS ve XMSS) benimsenmesini diğer geçişlerin önünde ve hemen önermektedir.
4. Passkey ve FIDO2: FIDO Alliance ile IANA takip edilir.

**Bugün yapılacak ucuz iş.** Passkey enrollment şemasında açık anahtarın yanında algoritma tanımlayıcısı saklanır. Aksi hâlde migration bir şema değişikliğine bağlı kalır; bugün ucuz olan iş migration sırasında pahalı bir blokaja dönüşür.

**Donanım.** 2026 ve 2027'de alınan token'larda üreticiden doğrulanmış bir PQC firmware yolu bulunmalıdır; yoksa 2027-2030 arasında fiziksel değişim planlanır. HSM üreticileri PQC entegrasyonunu 2025-2026 için hedeflemektedir.

**Beklenti.** İlk tarayıcı ve authenticator PQC FIDO2 desteği 2027 sonu veya 2028 başında beklenmektedir.

**Ana sonuç.** Geçişten olaysız çıkacak kurumlar, kripto çevikliğini 2026'da bir satın alma gereksinimi hâline getirenler olacaktır.

---

## Bölüm IV — Tehdit modeli

### 25. Saldırı yüzeyi

Tasarımın çıkış noktası artık parolanın nasıl doğrulanacağı değil, başarılı kimlik doğrulamadan sonra oturumun çalınmasıdır.

#### AiTM, baskın teknik

Saldırgan tarayıcı ile IdP arasında ters proxy çalıştırır; kullanıcı MFA'yı doğru tamamlar ve saldırgan sonrasındaki oturum token'ını yakalar. Push, TOTP ve SMS OTP bu proxy'ye tamamen şeffaftır.

Kit ekosistemi: Evilginx ve Evilginx2, Tycoon 2FA (en yüksek hacimli), Rockstar 2FA, EvilProxy, Greatness, Mamba 2FA, Modlishka, Muraena. En yeni kitler AiTM'i BiTM (browser-in-the-middle) ile birleştirerek kimlik bilgilerini ve MFA kodlarını aktif akış içinde yakalamaktadır.

#### Infostealer

Tarayıcıdaki parolaları, oturum cookie'lerini ve autofill verisini sessizce çeker. Saldırgan kendi cihazından, anomali üretmeden giriş yapar.

Ölçek şudur: 2024'te 17 milyardan fazla tarayıcı cookie'si çalınmıştır. KELA 2024 için 3,9 milyar kimlik bilgisi ve 4,3 milyon enfekte cihaz raporlamıştır (Lumma, StealC, RedLine). Flashpoint 2025'in ilk yarısında 5,8 milyon cihazdan 1,8 milyar kimlik bilgisi tespit etmiştir; bu %800 artıştır.

#### Device code phishing

Cihaz yetkilendirme akışının kötüye kullanımıdır. Phishing sayfaları Nisan 2026'ya kadar 37,5 kat, tespitler %1.380 artmıştır.

#### Diğer teknikler

Credential stuffing, password spraying, MFA fatigue, OAuth consent phishing, OAuth tedarik zinciri saldırıları (SaaS satıcılarının ele geçirilip saklı token'larla downstream müşterilere girilmesi), SIM swap, hesap kurtarma suistimali, attestation relay, enumeration, CSRF, oturum sabitleme, açık yönlendirme ve subdomain takeover.

### 26. Rakamlar

| Kaynak | Bulgu |
|---|---|
| Verizon DBIR 2026 | İhlallerin %62'sinde insan unsuru bulunmaktadır |
| Proofpoint | Kurumların %67'si 2025'te en az bir başarılı ATO yaşamıştır; ele geçirilen hesapların %59'unda MFA açıktı |
| SpyCloud | 8,6 milyar çalınmış oturum cookie'si; başarılı phishing yıllık %400 artmıştır |
| IBM Cost of a Data Breach 2026 | En pahalı giriş noktası phishing ile ses ve SMS varyantlarıdır; ortalama 5,29 milyon USD |
| Microsoft Digital Defense Report 2025 | Modern MFA riski %99'dan fazla azaltmaktadır; buna karşılık gözlenen saldırıların %3'ünden azı token hırsızlığı ve AiTM gibi ileri kategorilerdedir |
| Genel | 2024'te dünya genelinde 8,2 milyardan fazla hesap kimlik bilgisi ihlallerde açığa çıkmıştır |

Son iki satır birlikte okunmalıdır: MFA çalışmaktadır ancak atlanmaktadır. Saldırı MFA'yı kırmaz; başarılı bir MFA girişini bekler ve sonrasındaki oturumu alır.

### 27. Ele geçirilmiş oturumun imzası

Saldırı başarısız giriş olarak değil, doğru kimlik doğrulanmış ancak yanlış yerden gelen oturum olarak görünür. Ortak davranışsal imza şudur.

Kullanıcının yerleşik örüntüsüyle uyumsuz yeni cihaz, ağ veya coğrafyadan devam eden oturum. Meşru giriş ile devam eden oturum arasında imkânsız seyahat. Hesapta hiç görülmemiş cihaz veya tarayıcı parmak izi. Oturumun başında iletişim bilgisi, kurtarma yöntemi veya alıcı değişikliği. Hızla yüksek değerli aksiyona yönelme ve kullanıcının normal ritmini bozan davranış.

Düzenleyici ve sektörel beklenti değişmiştir: kimlik doğrulama gücü artık yeterli assurance sayılmamakta, başarılı doğrulama sonrasında oluşan ele geçirmenin tespiti beklenmektedir.

### 28. Savunma matrisi

| Saldırı | Etkili kontrol | Etkisiz kontrol |
|---|---|---|
| Credential stuffing | Rate limit, ihlal listesi kontrolü, MFA | Karmaşıklık kuralları |
| Klasik phishing | Passkey ve FIDO2 | SMS OTP, TOTP |
| AiTM | Origin-bound passkey, DPoP, DBSC, oturum içi anomali | Push, TOTP, SMS |
| Infostealer ve cookie hırsızlığı | DBSC, cihaz bağlı token, kısa oturum | Uzun ömürlü bearer cookie |
| Token hırsızlığı | DPoP, mTLS, rotation ve reuse detection | Bearer token |
| SIM swap | Operatör entegrasyonu, değişiklik sonrası kısıt | Tek başına SMS OTP |
| MFA fatigue | Number matching, passkey | Basit onay push'u |
| Device code phishing | Akışı kapatma, `application_type` kısıtı | — |
| Kurtarma suistimali | Kimlik tespiti tekrarı, soğuma süresi | Güvenlik soruları |
| Enumeration | Tekdüze hata mesajı ve yanıt süresi | Farklı mesajlar |
| Oturum ele geçirme | SSF ve CAEP ile sürekli değerlendirme | Statik oturum ömrü |
| Consent phishing | Uygulama allowlist'i, scope incelemesi | — |

---

## Bölüm V — Ürün envanteri

### 29. Self-hosted IdP

#### Keycloak

Apache 2.0 lisanslı, Java ve Quarkus tabanlı, yaklaşık 26.7 sürümünde, CNCF incubating statüsünde, Red Hat destekli ve yaklaşık 35.700 yıldıza sahiptir.

**Artıları.** Bağımsız benchmark'ta izlenen 44 OIDC özelliğinden 40'ını karşılamaktadır; Ory Hydra 26 özellik karşılar. OIDC, OAuth 2.1, SAML 2.0, LDAP ve AD, Kerberos, SCIM, identity brokering ve Docker Auth desteklenir. 26.4 ile FAPI 2 final, tam DPoP desteği, login formlarında passkey (conditional ve modal arayüz), SPIFFE ve K8s service account ile Federated Client Authentication ve çok-AZ dağıtım gelmiştir. CIBA mevcuttur, ID-JAG deneyseldir. Referans değerleri 2.000 login/sn ve 10.000 token yenileme/sn'dir. Kullanıcıları arasında Avusturya BRZ (2 milyondan fazla vatandaş, 130'dan fazla hizmet) ve CERN bulunur. Realm bazlı çok kiracılık, FreeMarker temaları, custom Authenticator SPI, OpenFGA köprüsü ve lazy migration sunar.

**Eksileri.** En ağır seçenektir; JVM asgari 512 MB, tipik olarak 1-2 GB bellek ister. Yapılandırma karmaşıktır. Custom SPI Java gerektirir ve her major sürümde kırılma riski taşır. Login akışı tarayıcı formu merkezlidir. Realm modeli binlerce self-service kiracı için tasarlanmamıştır. Yetkilendirme kaba tanelidir. Dokümantasyonda özellik statüleri gecikmeli güncellenir.

#### Zitadel

Core tarafı AGPL-3.0, API ve SDK Apache 2.0 lisanslıdır. Go ile yazılmıştır, event-sourced mimariye sahiptir, yaklaşık v4.17 sürümündedir ve yaklaşık 14.800 yıldıza sahiptir.

**Artıları.** Gün birinden itibaren Organizations tabanlı çok kiracılık sunar. Yönetilen bulutta SOC 2 Type II ve ISO 27001:2022 sertifikalarına sahiptir; üç büyük açık kaynak IdP arasında bu sertifikalara sahip tek üründür. Event sourcing doğal bir denetim izi üretir. Geliştirici deneyimi moderndir.

**Eksileri.** AGPL dağıtım ve SaaS senaryolarında blokaj yaratabilir. Topluluğu küçüktür. SAML ve legacy derinliği azdır.

#### Authentik

Açık kaynaktır; bazı enterprise özellikler kapalıdır. Python ile yazılmıştır ve PostgreSQL zorunludur.

**Artıları.** En cilalı admin arayüzü, en pürüzsüz kurulum, forward auth ve proxy modu, OIDC, SAML, LDAP ve SCIM desteği ile esnek bir flow tasarımcısı sunar.

**Eksileri.** İleri özelleştirme Python scripting gerektirir. Proje gençtir. SDK ekosistemi ve oturum yönetimi derinliği zayıftır.

#### Authelia

Apache 2.0 lisanslıdır ve Go ile yazılmıştır. En hafif forward-auth SSO çözümüdür. Tam bir IdP değildir ve CIAM'e uygun değildir.

#### FusionAuth

Açık kaynak değildir; kaynağı görünürdür ve ücretsiz self-host edilebilir. Java ile yazılmıştır.

**Artıları.** Self-host ve bulut arasında tutarlı özellik seti, API-first tasarım, MAU limiti bulunmaması, yüksek MAU'da düşük maliyet ve SCIM desteği.

**Eksileri.** Lisansı yanlış anlaşılmaktadır. Bulut fiyatlandırması yaklaşık aylık 37 USD'den başlar. Topluluğu küçüktür.

#### Diğerleri

| Ürün | Yığın | Konum |
|---|---|---|
| Casdoor | Go ve React, Apache 2.0 | En geniş sosyal login kapsaması: WeChat, DingTalk, Lark |
| WSO2 IS | Java, Apache 2.0 | 7.1.0 sürümüyle FAPI 2.0 Final sertifikalı; 250'den fazla müşteride 1 milyondan fazla kimlik; API Manager entegrasyonu |
| Gluu | Java, Apache 2.0 | Destek yıllık yaklaşık 25.000 USD standart, 50.000 USD premium |
| Apereo CAS | Java | Eğitim sektörü, çok protokollü |
| Shibboleth IdP | Java | Akademik federasyon (eduGAIN), SAML odaklı |
| FreeIPA | Python ve C | Linux altyapı kimliği: Kerberos, LDAP, CA |
| Kanidm | Rust | Modern, hafif, güvenlik odaklı, genç |
| OpenIAM | Java | Yönetişim ve provisioning ağırlıklı |
| lemonldap-ng | Perl | Fransız kamu sektörü web SSO'su |

#### Ory

Apache 2.0 lisanslıdır, Go ile yazılmıştır ve servis başına yaklaşık 50 MB RAM kullanır. Bileşenleri şunlardır: Kratos (kimlik, kayıt, login, MFA, kurtarma), Hydra (OAuth ve OIDC provider), Keto (Zanzibar yetkilendirme) ve Oathkeeper (identity-aware proxy).

**Artıları.** Azami esneklik sağlar ve Kubernetes'e uygundur. OpenAI ChatGPT login akışını Ory üzerinde çalıştırmaktadır; yaklaşık 900 milyon haftalık aktif kullanıcı söz konusudur. Klarna da benimseyenler arasındadır. Bileşenler ayrı ayrı alınabilir.

**Eksileri.** Login arayüzü hiç yoktur. Hydra kimlik yönetmez ve Kratos eklendiğinde bileşen sayısı artar. Protokol kapsamı 44 özellikten 26'sıdır. SAML desteği yoktur. Çok kiracılık en zahmetli olan seçenektir. Ürün özelliği yazmadan önce ciddi yatırım gerektirir.

#### Logto

MPL 2.0 lisanslıdır, Node ve TypeScript ile yazılmıştır ve yaklaşık 12.000 yıldıza sahiptir. JS ekosisteminin en hızlı büyüyen açık kaynak IdP'sidir. Temiz SDK, iyi tasarlanmış konsol, yerleşik Organizations, WebAuthn passkey ve lazy migration sunar. FAPI, DPoP ve mTLS derinliği ile kurumsal federasyon bulunmaz.

#### SuperTokens

Apache 2.0 lisanslıdır; Java core ile Node, Python ve Go SDK'ları vardır. Standalone bir IdP değildir, uygulamanın içine gömülür. Self-host ücretsiz ve sınırsızdır; bulut 5.000 MAU'ya kadar ücretsizdir, sonrası MAU başına 0,02 USD'dir. Oturum yönetimi derinliği iyidir. Eklentiler ayrı ücretlendirilir: MFA MAU başına 0,01 USD ve aylık asgari 100 USD, account linking MAU başına 0,005 USD ve aylık asgari 100 USD, dashboard kullanıcısı aylık 20 USD.

#### Hanko ve Stack Auth

Hanko passwordless ve passkey odaklıdır, hazır arayüz sunar, self-host veya yönetilen olarak kullanılır; geniş bir platform değildir. Stack Auth açık kaynak Clerk alternatifidir: hazır arayüz bileşenleri, B2B organizasyonlar ve Clerk fiyat şoku yaşayanlar için göç hedefi. Çok gençtir.

### 31. Uygulama içi kütüphaneler

**Better Auth.** 2024'te çıkmıştır, Mayıs 2026'da v1.6 sürümüne ulaşmıştır ve yaklaşık 100.000 haftalık indirme almaktadır. Framework bağımsızdır (Next.js, SvelteKit, Nuxt, Hono, Express), uçtan uca TypeScript tip güvenliği ve eklenti mimarisi sunar. Kullanıcılar kendi Postgres'inizde durur. Birinci sınıf çok kiracılık, 20'den fazla OAuth sağlayıcı, TOTP, e-posta OTP, backup kod, magic link, passkey, phone OTP, Prisma, Drizzle ve Kysely adaptörleri ile yerleşik rate limiting bulunur. Gençtir, denetim geçmişi kısadır ve kurumsal federasyon yoktur.

**Auth.js (NextAuth).** v5 sürümündedir, yaklaşık 2,5 milyon haftalık indirme alır ve kategorinin standardıdır. OAuth odaklıdır; e-posta ve parola tarafı zayıftır; oturum için veritabanı kurulumu gerekir; v4'ten v5'e geçişte büyük API değişikliği olmuştur. Çoğu ekip yeni proje için değil, mevcut projede kaldığı için kullanmaktadır.

**Lucia.** Deprecate edilmektedir. Oturum yönetimi araç setidir; öğrenme kaynağı olarak değerlidir, yeni proje için uygun değildir.

**node oidc-provider.** 9.2.0 ve üstü sürümlerde FAPI 2.0 SP Final ve Message Signing Final sertifikalıdır. Node'da sertifikalı bir AS kurmanın yoludur. Arayüz ve kullanıcı deposu içermez.

**OpenIddict.** .NET tarafında Duende'nin açık kaynak alternatifidir; daha fazla manuel iş gerektirir.

**Diğerleri.** Passport.js modern standartlarda geridedir. Spring Security Java'da fiili standarttır ancak öğrenme eğrisi diktir. django-allauth, Devise ve Sorcery (Rails) ile go-oidc (0.11.0 ve üstünde FAPI 2.0 Final sertifikalı) diğer seçeneklerdir.

### 32. Yönetilen CIAM

| Ürün | Artı | Eksi |
|---|---|---|
| Auth0 (Okta) | 50.000 MAU altında yenilmesi zordur; derin federasyon, FedRAMP, Auth0 FGA ve Actions sunar; Highly Regulated Identity FAPI 2.0 Final sertifikalıdır; AI Agents Kasım 2025'te, Auth for MCP Mayıs 2026'da GA olmuştur | 100.000 MAU üstünde fiyat dikleşir; Actions lock-in üretir; toplam sahip olma maliyeti yüksektir |
| Clerk | Next.js ve React için en hızlı seçenektir; hazır ve kaliteli arayüz sunar; conditional-UI passkey varsayılan olarak açıktır; 50.000 MAU ücretsizdir | Kurumsal CIAM değildir; federasyon kuyruğu, Java ve .NET desteği, FedRAMP ve ISO 27001 eksik veya zayıftır; SCIM yenidir; veri ABD'dedir; 50.000 MAU sonrası pahalıdır |
| WorkOS | B2B kurumsal hazırlık için en doğrudan yoldur; bağlantı başına 125 USD ile müşteri sayısına göre ölçeklenir; olgun SAML ve SCIM ile self-servis Admin Portal sunar | B2C için uygun değildir; çok küçük müşteride pahalıdır |
| Stytch | API-first primitifler, esnek akış ve güçlü passwordless orkestrasyonu sunar | Görsel soyutlama azdır; beş bağlantı üstünde SSO ücretlidir |
| Descope | 2026'nın en güçlü görsel akış tasarımcısına (Flows) sahiptir; orkestrasyon lideridir; yerel AI ajan kimliği sunar | Passwordless-native değildir; kurumsal incumbent değildir |
| Frontegg | Gömülü B2B self-servis admin portalları sunar | Segmenti dardır |
| Firebase Auth | Mobil öncelikli startup için en hızlı seçenektir; ücretsiz kademesi cömerttir | Google bağımlılığı vardır; kurumsal özellikleri zayıftır; taşınabilirliği sınırlıdır |
| Supabase Auth | RLS, yetkilendirmenin ciddi bir kısmını otomatik çözer; açık kaynaktır ve self-host edilebilir | Yetkilendirme RLS içinde manueldir; tek bir veritabanı arka ucuna bağlıdır |
| MojoAuth | Passwordless uzmanıdır ve hızlıdır | Tam CIAM değildir |
| Authress | Yetkilendirme önceliklidir; yerel ReBAC ve FGA sunar ve Auth0 FGA ile WorkOS FGA'dan ucuzdur | Niştir |
| Kinde | Geliştirici önceliklidir | Gençtir |
| SSOJet | Kurumsal SSO ve SCIM broker'ıdır; testte 42 dakikada çalışan SAML kurulumu vermiştir | Odağı dardır |
| Okta Workforce | 7.000'den fazla entegrasyon, adaptif MFA ve lifecycle yönetimi sunar | CIAM değildir |
| Corbado, Passage, Beyond Identity | Mevcut IdP üzerine passkey orkestrasyonu sağlar | Tek katmandır |

### 33. Hyperscaler seçenekleri

**AWS Cognito.** AWS-native IAM entegrasyonu, FedRAMP High, PCI Level 1 ve HIPAA uyumu ile Managed Login'de yerel passkey sunar. 500.000 MAU üstünde birim ekonomisi SaaS rakiplerini geçer. Birinci sınıf Organizations bulunmaz; user-pool grupları, claim'ler ve Lambda trigger'ları ile kurulur. Passkey orkestrasyonu zayıftır ve AWS dışında geliştirici deneyimi savunulamaz.

**Microsoft Entra External ID.** 50.000 MAU ücretsizdir ve 100.000 MAU üstünde Cognito'dan da ucuzdur. Azure AD B2C'ye göre geliştirici deneyimi belirgin biçimde iyileşmiştir. FedRAMP High kapsamı beş büyük CIAM arasında en güçlüsüdür. Çok kiracılık Cognito'dan iyidir ancak WorkOS, Frontegg ve Auth0'ın gerisindedir. Geliştirici deneyiminde kalıcı sürtünme kaynakları referans öncelikli dokümantasyon, Azure AD terminolojisi ve kurumsal IT konsoludur.

**Google Identity Platform.** Firebase Auth'un kurumsal üst katmanıdır; çok kiracılık ve SAML ekler.

Genel kural şudur: B2B kiracılık ürünün kendisiyse, login'de tasarruf etmek için hyperscaler seçilmez.

### 34. Protokol motorları

**Authlete.** Protokol mantığını REST API olarak sunar; uç noktalar kendi tarafınızdadır. 3.0 sürümü FAPI 2.0 SP ve Message Signing Final sertifikalıdır. Regülatörün istediği açık bankacılık profili için sertifikaya sahiptir. Polyglot'tur; uç nokta katmanı Java, Go veya TypeScript olabilir.

**Duende IdentityServer.** ASP.NET Core üzerinde in-process bir SDK'dır; protokol mantığı, token üretimi ve depolaması kendi altyapınızda kalır. 2.500'den fazla kuruluşta üretimdedir. v8 ve üstünde Financial-Grade Security and Conformance raporu yapılandırmayı OAuth 2.1 ve FAPI 2.0'a karşı otomatik denetler. Kendi tavsiyesi, FAPI 2.0'a mTLS yerine `private_key_jwt` ile başlanmasıdır; mTLS üretimde bakımı zordur.

**Curity.** JVM tabanlı ve ticaridir; CIBA gibi ileri akışlar hazır gelir; finans odaklıdır.

**Ping Identity ve ForgeRock.** Kurumsal incumbent'lardır; olgun referans mimariler sunar ve maliyetleri büyük kurum ölçeğine göredir.

### 35. Yetkilendirme motorları

**Kavramlar.** FGA bir kullanım kategorisidir: ölçekte kaynak başına izin. ReBAC bir modeldir. Zanzibar Google'ın 2019 tarihli implementasyonudur. PBAC ise şemsiye paradigmadır: yetkilendirme mantığının uygulamadan çıkarılması. ReBAC ve ABAC'ın ikisi de PBAC'ın altındadır.

| Ürün | Model | Lisans | Not |
|---|---|---|---|
| OpenFGA | ReBAC | Apache 2.0, CNCF | Auth0 ve Okta kökenlidir, satıcı nötrdür, stateless'tır ve yatay ölçeklenir; Auth0 FGA yönetilen sürümüdür; Keycloak köprüsü mevcuttur |
| SpiceDB | ReBAC | Apache 2.0 | Authzed desteği, zengin araç seti ve K8s operator sunar |
| Ory Keto | ReBAC | Apache 2.0 | Ory yığınıyla doğal uyum |
| Cedar ve AWS Verified Permissions | ABAC | Apache 2.0 | Kararı zengin öznitelikler sürüyorsa uygundur |
| Cerbos | Policy (PDP) | Apache 2.0 | Çalışma zamanı iş bağlamı sağlar; IdP'yi tamamlar |
| Oso | Policy DSL | Karma | Uygulama içi kullanım |
| OPA ve Rego | Policy | Apache 2.0 | Altyapı ve K8s'te fiili standart |
| Casbin | ACL, RBAC, ABAC | Apache 2.0 | Hafif, çok dilli kütüphane |
| Warrant | ReBAC | — | Merkezi yetkilendirme servisi |
| Permit.io | Yönetilen FGA | Ticari | OPA ve Cedar üzerinde yönetim katmanı |

**Performans.** Üretimdeki FGA sorguları 1-10 ms arasındadır. Cache ve batch check ile yönetilebilir.

ReBAC kalıtımlı ince taneli izinler, liste operasyonları (görebildiği tüm belgeler) ve yetkilendirme verisinin iş mantığından ayrılması gerektiğinde seçilir. ABAC ise kararlar ilişkiden çok özniteliklerden sürüyorsa seçilir.

### 36. Karşılaştırma tabloları

**Lisans netliği.**

| Ürün | Lisans | Dikkat |
|---|---|---|
| Keycloak, Ory, Authelia, WSO2 IS, Gluu CE | Apache 2.0 | Temiz |
| Logto | MPL 2.0 | Zayıf copyleft |
| SuperTokens | Apache 2.0 | Eklentiler ücretli |
| Zitadel | AGPL-3.0 (core) | Dağıtım ve SaaS riski |
| FusionAuth | Tescilli | Açık kaynak değildir |
| Duende | Ticari | Üretimde lisans anahtarı gerekir |

**Fiyat modeli.**

| Model | Neyle ölçeklenir | Kimde |
|---|---|---|
| MAU başına | Toplam kullanıcı | Auth0, Clerk, Entra, Logto, FusionAuth Cloud |
| Bağlantı başına | Kurumsal müşteri sayısı | WorkOS (125 USD), Stytch (beş bağlantı sonrası) |
| Self-host | Altyapı ve operasyon | Keycloak, Ory, Authentik, SuperTokens |
| Kademeli ve eklentili | Karma | SuperTokens |

1 milyon MAU'da ucuz olanlar: Cognito, Entra, FusionAuth, SuperTokens ve WorkOS'un B2B şekli. Ancak ucuz olan en iyi değildir: altı aylık geliştirici deneyimi vergisiyle gelen 165 USD'lik bir fatura, bu çeyrek ürün çıkaran 1.200 USD'lik faturaya kaybedebilir.

### 37. Yap veya al kararı

Sıfırdan IdP yazmak savunulamaz: token imzalama, JWKS rotasyonu, oturum yönetimi, WebAuthn ceremony'leri, consent, admin API ve sertifika uyumunun hepsinin olgun karşılığı bulunmaktadır.

Kendi SAML ve SCIM implementasyonunu yazmak ayrıca kötüdür: sertifika rotasyonu, metadata ayrıştırma, IdP'ye özgü tuhaflıklar ve sürekli bakım gerekir. Yönetilen bir broker saatler veya günler içinde çalışan bağlantı verir; bir vakada 45 dakikada SAML kurulumu tamamlanmıştır.

Hangi ürün seçilirse seçilsin kurumda kalan işler şunlardır: cihaz kaydı ve anahtar yaşam döngüsü, hesap kurtarma akışının ürüne özgü tasarımı, risk sinyalleri ve adaptif doğrulama, doğrulama sonrası oturum izleme ve ürüne özgü kullanıcı yaşam döngüsü. Kullanıcı durum verisi IdP'nin user modeline zorlanırsa iki doğruluk kaynağı ortaya çıkar.

---

## Bölüm VI — Mimari kalıpları

### 38. Token sınıfları ve ömürleri

| Tür | Tipik ömür | Not |
|---|---|---|
| Access token | 5-15 dakika | Kısa tutulur; çalınırsa pencere dardır |
| Refresh token | Rotasyonlu | Hareketsizlik ve mutlak sınır birlikte uygulanır |
| ID token | Tek kullanımlık | Kimlik iddiasıdır; API'ye gönderilmez |
| Session cookie | Tarayıcı akışları | BFF deseninde sunucuda kalır |
| API anahtarı | Uzun | Servis-servis; rotasyon planı şarttır |

**Hareketsizlik süreleri.** B2B SaaS'ta 30 gün, mobilde 90 gün, hassas bağlamlarda daha kısadır. Üstüne mutlak bir tavan konur.

### 39. Refresh token rotation ve reuse detection

2026'da pazarlık konusu değildir. Her yenilemede yeni token verilir ve eski geçersiz olur. Geçersiz bir token tekrar görülürse tüm token ailesi iptal edilir.

Bu mekanizma çalınmış token'ı uzun vadeli bir yetenekten tespit edilebilir bir olaya çevirir: saldırgan token'ı kullanır, meşru kullanıcının sonraki yenilemesi çakışır ve iki oturum da iptal edilir.

Rotasyon açıkken aktif kullanıcı için erişim süresi pratikte sınırsızdır; kısıt hareketsizlik zaman aşımına kayar.

#### Mobildeki kritik tuzak

Birden fazla ekran aynı anda refresh'i yarıştırdığında biri harcanmış token'ı replay eder, reuse detection tetiklenir ve kullanıcı kendiliğinden atılır. Üstelik meşru rotasyonun ürettiği access token da anında 401 verir.

**Zorunlu koruma.** Aynı anda tek bir refresh uçuşta tutulur; eşzamanlı çağıranlar aynı promise'i bekler ve yenilenmiş token'ı alır. Bu davranış elle güvenilir biçimde tekrarlanamaz, dolayısıyla testle kapsanmalıdır.

### 40. Oturum modeli: platforma göre

| Platform | Kalıp |
|---|---|
| Web (SSR) | httpOnly, Secure ve SameSite cookie; sunucu tarafı oturum |
| Web (SPA) | BFF deseni; refresh token tarayıcıya hiç inmez, sunucuda tutulur |
| Mobil native | Secure Enclave veya Keystore'da token; DPoP ile cihaza bağlanır |
| Masaüstü | OS keychain; DBSC benzeri cihaz bağlama |
| CLI | Device Authorization Grant; token dosya izinleriyle korunur |
| TV ve kiosk | Device flow; kısa oturum ve otomatik çıkış |
| Tarayıcı eklentisi | Arka plan servis worker'ında tutulur; içerik script'inden izole edilir |

**Cookie öznitelikleri.** `HttpOnly` XSS'e karşıdır. `Secure` HTTPS zorunlu kılar. `SameSite=Lax` varsayılandır; `Strict` çok kısıtlayıcıdır, `None` yalnızca gerçek cross-site ihtiyacında ve `Secure` ile birlikte kullanılır. `__Host-` öneki subdomain sızıntısına karşı korur. `Path` ve `Domain` mümkün olduğunca dar tutulur.

### 41. Çok cihaz ve oturum yönetimi

Kullanıcıya sunulması gerekenler aktif oturumlar listesi (cihaz, konum, son kullanım) ve uzaktan çıkıştır. Bu artık temel bir beklentidir ve çoğu ihlalde kullanıcının ilk aradığı özelliktir.

Tasarım kararları şunlardır: kaç eşzamanlı oturuma izin verileceği, yeni cihaz girişinde bildirim yapılıp yapılmayacağı ve iptalin oturum başına mı yoksa toplu mu olacağı.

### 42. Cihaz kaydı ve cihaza bağlı anahtarlar

Donanım destekli depolar iOS'ta Secure Enclave, Android'de Keystore ve StrongBox'tır. Anahtarlar güvenli donanımda üretilir ve dışarı çıkmaz.

```
device_id, user_id, public_key, key_type, attested_at,
status (active/suspended/revoked), created_at, last_seen
```

Kullanım alanları cihaz bağlı oturum, işlem imzalama, tanıdık cihaz risk sinyali ve MFA hatırlamadır.

### 43. Cihaz attestation ve sınırları

**iOS App Attest.** Secure Enclave'a bağlı bir anahtar çifti kullanır. Canlı bir Apple doğrulama API'si yoktur; attestation objesi Apple köklerine karşı yerel olarak doğrulanır, açık anahtar saklanır ve sonrasında imzalı assertion'lar doğrulanır. Apple'ın tavsiyesi hesap tabanlı uygulamalarda kullanıcı başına bir anahtar kullanılması ve key ID'lerin Keychain'de tutulmasıdır. Anahtar uygulama güncellemesinden sağ çıkar ancak yeniden kurulum veya geri yüklemede kaybolur. Replay koruması için `newSignCount > oldSignCount` kontrolü yapılır.

**Android Play Integrity.** Farklı bir felsefeye sahiptir: iOS anahtar kalıcılığına odaklanırken Android istek başına verdict'e odaklanır. Sinyaller `PLAY_STORE`, `UNRECOGNIZED_VERSION`, `MEETS_DEVICE_INTEGRITY` ve `MEETS_BASIC_INTEGRITY`'dir.

**İki kritik sınır.**

Attestation runtime temizliğini kanıtlamaz. App Attest anahtarın gerçek olduğunu söyler, ortamın temiz olduğunu değil; jailbreak, hooking veya malware tespiti yapmaz. Operasyonel yük ağırdır: anahtar saklama ve rotasyon, cihaz göçü ve fraud assertion'larının yorumu.

Relay saldırıları ikinci sınırdır. Keystore X.509 attestation zincirini boolean bir cihaz bütünlüğü göstergesi gibi kullanan uygulamalar savunmasızdır. OID `1.3.6.1.4.1.11129.2.1.17` leaf anahtarın kabul edilebilir bir TEE veya StrongBox tarafından o challenge için üretildiğini kanıtlar; ancak o donanımı kanıtı sunan süreç veya oturumla bağlamaz. İmza doğrulama, kök pinning, tazelik, revocation, `deviceLocked=true` ve `verifiedBootState=Verified` kontrollerinin hepsi, temiz bir oracle telefondan röle edilmiş kanıtla geçebilir.

Sonuç olarak attestation bir kapı değil, risk skoruna giren bir sinyaldir.

### 44. Adaptif kimlik doğrulama ve risk

Girdi sinyalleri şunlardır: cihaz kimliği ve tanıdıklık, IP ve ASN ile itibar, coğrafya ve imkânsız seyahat, günün saati ve kullanıcı ritmi, oturum yaşı, davranışsal biyometri, attestation sonucu, ihlal listesi eşleşmesi, hesap yaşı ve yakın zamanlı kurtarma veya değişiklik.

Çıktı üç seçeneklidir: izin ver, yükselt, engelle. İkili karar neredeyse her zaman yanlıştır; orta katman kullanıcıyı kaybetmeden riski düşürür.

Step-up için standart yol RFC 9470 challenge'ı ve `acr_values`'tır.

### 45. Hesap bağlama ve birleştirme

Neredeyse her üründe ortaya çıkan, neredeyse hiç baştan tasarlanmayan problemdir.

**Senaryolar.** Kullanıcı parolayla kaydolur, sonra aynı e-postayla Google ile gelir. İki farklı sosyal sağlayıcı aynı e-postayı döndürür. Kullanıcı e-postasını değiştirir ve eskisi başkasına gider. Aynı kişinin farklı e-postalarla iki hesabı bulunur.

**Güvenli kurallar.** E-posta üzerinden otomatik bağlama yalnızca iki tarafın da doğrulanmış olması hâlinde yapılır; aksi hâlde saldırgan doğrulanmamış bir e-postayla hesap yaratıp kurbanın sosyal login'ini ele geçirir, bu klasik pre-account takeover saldırısıdır. Bağlama işlemi mevcut oturumda yeniden kimlik doğrulama ister. Birleştirme geri alınamaz olduğu için açık bir onay ekranı ve ne olacağının anlatımı gerekir. Birincil eşleştirme anahtarı sağlayıcının `sub` claim'idir, e-posta ikincildir.

### 46. Kurtarma tasarımı

Passkey mimarilerinin gerçek zayıf halkası ve ATO'nun en yoğun yüzeyidir.

**Prensipler.** Kurtarma korunan şeyden zayıf olamaz; aksi hâlde saldırgan doğrudan oraya gider. Güvenlik soruları authenticator olarak kullanılamaz; NIST bunu yasaklamaktadır. Kurtarma kodları tek kullanımlık olur, kayıt anında gösterilir, saklanması istenir ve hash'lenerek tutulur. Kurtarma sonrası bir soğuma süresi uygulanır; yeni cihaz veya yöntem aktif olduktan sonra bir süre yüksek riskli aksiyonlar kısıtlanır. Kurtarma girişimlerinde rate limiting yapılır ve eski kanal dahil bildirim gönderilir. Yüksek değerli hesaplarda manuel destek yolu ve alternatif doğrulanmış kanal bulunur. Yüksek assurance gereken yerlerde kurtarma, kimlik tespitinin tekrarını gerektirir.

### 47. Impersonation

Destek ekibinin ihtiyacı olan, en çok kötüye kullanılan özelliktir.

**Doğru tasarım.** Ayrı bir token tipi kullanılır ve `act` claim'i ile gerçek aktör belirtilir. Scope kısıtlıdır; para ve veri çıkışı bulunmaz. Süre sınırlıdır. Kullanıcıya bildirim gider ve tam denetim izi tutulur. Belirli bir eşiğin üstünde kullanıcı onayı gerekir. Bu özellik hiçbir zaman admin panelinden parola değiştirerek çözülmez.

### 48. İşlem ve aksiyon imzalama

Oturum açmak ile kritik bir aksiyon yapmak aynı güven seviyesinde değildir. Genel kalıp şudur.

1. Sunucu aksiyon payload'ını üretir: ne yapılacağı, nonce ve timestamp.
2. İstemci bunu ekranda gösterir; WYSIWYS ilkesi, yani imzalanan ile görülen aynıdır.
3. Kullanıcı ikinci faktörünü sunar.
4. Cihaz anahtarı tam olarak o payload'ı imzalar.
5. Sunucu imzayı doğrular ve aksiyonla karşılaştırır.

Payload değişirse imza tutmaz. Kullanım alanları ödeme onayı, ayrıcalık yükseltme, veri silme, üretim dağıtımı ve kritik yapılandırma değişikliğidir.

### 49. Rate limiting ve kötüye kullanım

**Katmanlar.** IP başına, hesap başına, global ve bunların kombinasyonu. Dağıtık credential stuffing tek IP limitini deler; hesap başına limit şarttır.

Exponential backoff ve geçici kilit uygulanır. Kalıcı kilit bir DoS vektörüdür.

**Enumeration önleme.** Kayıt, giriş ve şifre sıfırlamada tekdüze yanıt verilir: aynı mesaj ve benzer yanıt süresi. "Bu e-posta kayıtlı değil" ifadesi bilgi sızdırır.

**Kayıt akışı koruması.** NIST 800-63-4 kayıt süreçlerine karşı otomatik saldırıların önlenmesi gereksinimini eklemiştir. Araçlar Cloudflare Turnstile, hCaptcha, Arkose Labs, Castle ve DataDome'dur.

### 50. Anahtar ve sır yönetimi

Karara bağlanması gerekenler şunlardır: token imzalama anahtarlarının nerede duracağı (uygulama belleği, KMS veya HSM), FIPS 140-3 gereksinimi olup olmadığı, rotasyon periyodu ve JWKS'te eski anahtarın kalma süresi (en uzun token ömrü kadar), anahtar erişiminin denetim izi, istemci sırlarının hiçbir zaman repoda veya mobil binary'de bulunmaması ve kripto çevikliği (§4 §24).

Araçlar: HashiCorp Vault, AWS KMS ve CloudHSM, Azure Key Vault, GCP KMS, Thales ve Entrust HSM.

---

## Bölüm VII — Kullanıcı deneyimi ve dönüşüm

### 51. Kayıt akışı

Araştırmalara göre kullanıcıların %27'si formu fazla uzun bulduğu için terk etmektedir. Her ekstra alan geri dönmemek üzere çıkma sebebidir.

**Kurallar.** Tek zorunlu alanla başlanır, bu genelde e-postadır; kalanı onboarding sırasında toplanır, yani progressive profiling uygulanır. Alan sayısı üçe indirilir. Parola kuralları girilmeden önce görünür kılınır. CTA fayda odaklı yazılır ("Ücretsiz başla"), jenerik değil ("Gönder"). Çok adımlı akışlarda ilerleme göstergesi konur ("2/3"); bu tamamlanmayı artırır. Kredi kartsız deneme kayıtları artırır, dolayısıyla ödeme değer görüldükten sonraya bırakılır. Kullanıcıya ne kazanacağı gösterilir: önizleme, demo, açıklayıcı içerik.

**E-posta doğrulama.** Çoğu ürün için kullanıcı hemen içeri alınır ve doğrulama belirli aksiyonlar için zorunlu kılınır: şifre sıfırlama, güvenlik değişikliği, veri paylaşımı. Zorunlu ön doğrulama yalnızca kimlik doğrulamanın hizmetin özü olduğu yerlerde, örneğin regüle finansta, haklıdır.

### 52. Giriş akışı

Kullanıcı zaten girişliyse giriş ekranı hiç gösterilmez; en iyi giriş, giriş istememektir. İlk girişten sonra oturum kalıcı kılınır veya biyometriyle tek dokunuşa indirilir; ikinci girişte parola yeniden yazdırılmaz. En yaygın yöntem öne konur ve SSO düğmeleri formun üstüne alınır. Parola göster ikonu standarttır ve kaldırılmasının bir gerekçesi yoktur. "Şifremi unuttum" görünür bir yerde bulunur. Yöntem ne olursa olsun deneyim tutarlı olur; akış ve marka aynı hissettirmelidir. Dönen kullanıcı için e-postayla otomatik giriş linki veya deep link sunulur.

**2026 için önerilen kombinasyon.** Kayıtlı cihazda dönen kullanıcı için passkey birincildir; yeni kullanıcı ve kayıtsız cihaz için magic link birincildir; herkes için sosyal login hızlandırıcı bir alternatiftir.

### 53. MFA kayıt deneyimi

Kayıt anında zorlamak terk ettirir; ilk değerli aksiyondan sonra istenir. Neden gerektiği bir cümleyle açıklanır. Kurtarma kodları kayıt anında gösterilir ve saklandığı teyit ettirilir. İkinci bir yöntem eklenmesi teşvik edilir; tek yöntem kilitlenme demektir. Passkey için conditional UI zorunludur, yoksa benimseme yarıya düşer.

### 54. Hata mesajları ve karanlık desenler

**İyi hata mesajı.** Ne olduğunu, neden olduğunu ve ne yapılması gerektiğini söyler. "Geçersiz kimlik bilgileri" güvenlik açısından doğrudur ancak tek başına yetersizdir; "E-posta veya parola hatalı. Şifrenizi sıfırlayabilirsiniz." daha iyidir.

**Kaçınılacaklar.** Kayıt sırasında gizli abonelik onayı, çıkışı zorlaştırma, hesap silmeyi gizleme, MFA kapatmayı imkânsızlaştırma ve "hesabını sil" yerine "devre dışı bırak" tuzağı.

### 55. Erişilebilirlik

OTP alanları ekran okuyucuyla çalışmalıdır ve autocomplete ipuçları (`one-time-code`) tanımlı olmalıdır. Zaman aşımı uyarısı ve uzatma imkânı sunulur (WCAG 2.2.1). CAPTCHA alternatifleri sağlanır: ses, davranışsal doğrulama. Renk tek başına hata göstergesi olamaz. Klavye ile tam gezinme mümkün olmalıdır. Parola yöneticisi uyumluluğu için `autocomplete` öznitelikleri doğru verilmelidir.

### 56. Uluslararasılaştırma

**Telefon numarası.** E.164 biçiminde normalize edilir, ülke kodu seçimi sunulur ve bazı ülkelerde numara değişiminin çok yaygın olduğu hesaba katılır.

**İsim.** Tek alan kullanılır; ad ve soyad ayrımı birçok kültürde yanlıştır; uzunluk ve Unicode sınırı konmaz.

**E-posta.** Unicode adresler (IDN) ve `+` etiketleri geçerlidir; aşırı katı regex kullanıcı kaybettirir.

**SMS teslimatı.** Ülkeye göre çok değişkendir; alfanumerik gönderici bazı ülkelerde yasaktır; Türkiye'deki İYS gibi regülasyonlar izin yönetimi gerektirir.

**Sosyal login sağlayıcıları.** Bölgeye göre değişir: Çin'de WeChat ve DingTalk, Kore'de Kakao ve Naver, Japonya'da LINE.

**RTL diller.** Form ve akış yönü buna göre düzenlenir.

**Tarih, saat ve zaman dilimi.** Oturum ömrü mesajları yerel saatte gösterilir.

**Yasal metinler.** KVKK ve GDPR aydınlatma metinleri dil başına ayrı tutulur ve versiyonlanır.

---

## Bölüm VIII — Senaryo oyun kitapları

### 57. B2C tüketici uygulaması

**Öncelik.** Dönüşüm güvenlik teatrosunun önündedir. Sürtünme her adımda kullanıcı kaybettirir.

**Kalıp.** Sosyal login, magic link ve passkey birlikte kullanılır. Parola opsiyoneldir. MFA ilk değerli aksiyondan sonra önerilir, zorlanmaz.

**Ürünler.** Clerk, Logto, Better Auth, Supabase Auth, Firebase Auth.

**Dikkat.** Ölçek büyüdükçe MAU faturası artar; 100.000 MAU eşiğinde model değişimi planlanır.

### 58. B2B SaaS

**Öncelik.** Kurumsal hazırlıktır. İlk büyük müşteri SAML desteğini soracaktır.

**Zorunlu üçlü.** SAML (ve OIDC), SCIM ve denetim logları. Yanında Organizations veya tenant modeli, rol yönetimi, davet akışı, domain doğrulama ve break-glass hesabı gerekir.

**Ürünler.** WorkOS en hızlısıdır; Auth0, Keycloak (self-host), Zitadel, Frontegg ve SSOJet diğer seçeneklerdir.

**Fiyat notu.** Bağlantı başına model (WorkOS'ta 125 USD) az sayıda büyük müşteride ucuz, çok sayıda küçük müşteride pahalıdır.

**Yetkilendirme.** Rol tablosuyla başlanır; ilişki karmaşıklığı ortaya çıktığında OpenFGA veya SpiceDB'ye taşınır.

### 59. E-ticaret

**Öncelik.** Sepet terk oranıdır. Misafir ödeme zorunludur ve kayıt ödeme sonrasına bırakılır.

**Kalıp.** Anonim oturum, sipariş ve sipariş sonrası hesap oluşturma sırası izlenir (§4 §67).

**Risk.** Promo suistimali, hesap ele geçirme ve kayıtlı kart kullanımı. Fraud motoru (§4 §88) auth'tan ayrıdır ancak ona bağlıdır.

**Dikkat.** Kayıtlı ödeme aracı varsa hesap ele geçirme doğrudan para kaybıdır; adres ve e-posta değişikliğinde step-up uygulanır.

### 60. İç araçlar ve altyapı

**Öncelik.** Basitlik ve tek yerden yönetim.

**Kalıp.** Reverse proxy ve forward auth kullanılır. Uygulamaların kendi login'i bulunmaz.

**Ürünler.** Authelia (minimal), Authentik (flow, LDAP, SCIM), protokol genişliği gerekiyorsa Keycloak, Ory Oathkeeper.

**Dikkat.** Break-glass erişimi tanımlanır ve admin hesaplarında donanım anahtarı kullanılır.

### 61. Kurumsal iş gücü

**Öncelik.** Yaşam döngüsü ve uyum.

**Kalıp.** Merkezi IdP, SCIM provisioning, koşullu erişim ve ayrıcalıklı hesaplar için PAM.

**Ürünler.** Okta, Entra ID, Keycloak, Ping.

**Zorunlular.** Özellikle admin hesaplarında phishing-resistant MFA, erişim gözden geçirmeleri, ayrılan personelin erişiminin anında kesilmesi ve SSF ile CAEP üzerinden oturum iptali.

### 62. Sağlık

**Öncelik.** Hasta gizliliği ve erişim denetimi.

**Uyum.** HIPAA'nın 45 CFR 164.312(d) maddesi kişi ve kurum kimlik doğrulaması gerektirir; metodoloji için NIST 800-63 kullanılır. Avrupa'da GDPR kapsamında sağlık verisi özel niteliklidir.

**Kalıp.** Rol ve ilişki tabanlı yetkilendirme kurulur; örneğin bu doktorun bu hastanın tedavi ekibinde olup olmadığı sorgulanır. Acil durum erişimi (break-glass) ve sonrasında zorunlu gerekçelendirme ile ayrıntılı erişim logu bulunur.

**Dikkat.** Paylaşılan cihazlarda, örneğin hemşire istasyonunda, hızlı kullanıcı değişimi ve kısa otomatik kilit gerekir.

### 63. Eğitim

**Öncelik.** Ölçek, federasyon ve yaş.

**Kalıp.** Akademik federasyon (eduGAIN, Shibboleth, SAML), LMS entegrasyonu (LTI) ve okul hesabıyla SSO.

**Uyum.** FERPA (ABD), COPPA (13 yaş altı için veli onayı ve veri toplama kısıtı) ve GDPR'da çocuk verisi.

**Dikkat.** Öğrenci hesaplarında kurtarma, paylaşılan cihazlar ve öğretmen impersonation'ı ayrıca tasarlanır.

### 64. Kamu ve e-devlet

**Öncelik.** Assurance seviyesi ve erişilebilirlik.

**Kalıp.** Ulusal kimlik entegrasyonu, akıllı kart ve PIV, yüksek IAL ve AAL, eIDAS LoA High.

**Uyum.** FedRAMP (AAL2 veya AAL3, ayrıcalıklı hesaplarda phishing-resistant), OMB M-22-09 ve eIDAS.

**Dikkat.** Sistem herkes için erişilebilir olmalıdır: dijital okuryazarlığı düşük kullanıcılar, eski cihazlar ve yardımcı teknolojiler. Alternatif kanal, örneğin şube veya telefon, yasal bir zorunluluk olabilir.

### 65. Oyun

**Öncelik.** Hesap değeri (envanter, ilerleme) ve çoklu platform.

**Kalıp.** Platform hesabı (Steam, PSN, Xbox, Discord) ile kendi hesabın bağlanması ve cihazlar ile konsollar arası devamlılık.

**Risk.** Hesap satışı ve çalınması, bot çiftlikleri, çoklu hesap suistimali ve çocuk kullanıcı korumaları.

**Dikkat.** Konsol ve TV'de metin girişi zordur; device flow ve QR eşleştirme kullanılır.

### 66. Medya ve abonelik

**Öncelik.** Paylaşım kontrolü ve çoklu cihaz.

**Kalıp.** Hane ve profil modeli, eşzamanlı akış limiti, cihaz kaydı ve TV'de device flow.

**Dikkat.** Parola paylaşımı bir iş modeli sorunudur; cihaz veya konum bazlı hane tanımı hem teknik hem hukuki bir tercihtir.

### 67. Anonim kullanıcının kayıtlıya dönüşümü

Çoğu tüketici ürününde en değerli akıştır.

**Kalıp.** Anonim oturum kimliği verilir, kullanıcı değer üretir (sepet, taslak, ilerleme), değer görüldükten sonra hesap istenir ve anonim veri yeni hesaba taşınır.

**Kritik detay.** Taşıma idempotent ve atomik olmalıdır; yarım kalan geçiş kullanıcının işini kaybettirir. Anonim oturum ömrü uzun, haftalar mertebesinde olmalıdır.

### 68. IoT ve cihaz kimliği

Headless cihazlar — sensör, sayaç, aktüatör, set-top box — milyonlarca adette ve coğrafi olarak dağınıktır; elle provisioning ne pratik ne güvenlidir.

**Yaşam döngüsü.**

1. Onboarding: ilk bağlantıda benzersiz kriptografik kimlik ve sertifika verilmesi.
2. Policy enforcement: cihaz kimliği ve duruşuna göre zero-trust kararlar.
3. Rotation ve renewal: sertifika ve anahtarların süre dolmadan otomatik döndürülmesi.
4. Revocation: ele geçmiş veya hizmet dışı cihazın güveninin anında kaldırılması.

**Zero-touch provisioning kalıbı.** Cihaza üretim aşamasında bir grup provisioning sertifikası yüklenir; ilk açılışta bulut servisine bağlanıp kendine özgü sertifikasını alır. Böylece üretim hattında cihaz başına CSR ve CA turu gerekmez.

**Anahtar teknolojiler.** mTLS cihaz ile bulut arasındaki kimlik doğrulamanın fiili standardıdır; her cihaza benzersiz özel anahtar ve sertifika verilir. Secure element ve TPM değişmez cihaz kimliği sağlar ve anahtar donanımdan çıkmaz. Matter (CSA) akıllı ev alanında her üretilen birime bir DAC (Device Attestation Certificate) ve üstünde PAI ile PAA zinciri verir; Apple Home, Google Home, Alexa ve SmartThings commissioning sırasında bunu doğrular. Wi-Fi Easy Connect (DPP) cihaz etiketindeki QR kodunda cihazın açık anahtarını taşır; Android 10 ve üstü ile yeni iOS sürümlerinde kamera uygulamasıyla, uygulama kurmadan Wi-Fi provisioning sağlar. BRSKI, MASA ve EST ağ katmanında güvenli bootstrap sunar ve MUD dosyasıyla cihaz sınıfı bazlı erişim politikası tanımlanır. FDO (FIDO Device Onboard) cihaz sahipliğinin tedarik zinciri boyunca devrini sağlar. EPID grup imzası tabanlı sahiplik transferi sunar.

**Saha gerçekleri.** Üretim test jig'i ile firmware flash, eFuse'a benzersiz seri yazımı ve claim sertifikası enjeksiyonu tipik olarak cihaz başına 30-60 saniye sürer. Ağ çeşitliliği — gizli SSID, WPA2-Enterprise, portal doğrulamalı hotspot, aynı SSID'li çift bant, mobil hotspot — provisioning akışının karşılaması gereken gerçek kısıttır.

Cihaz bir kullanıcıya bağlıysa ayrıca cihaz ile hesap eşleştirmesi, ikinci el satışta sahiplik devri ve cihaz kaybında iptal akışı gerekir.

---

## Bölüm IX — Yeni nesil

### 69. Klasik modelin kırılma noktası

OAuth 2.0, OIDC ve SAML çok spesifik yapısal varsayımlar kodlar ve otonom ajanlar bunları inşaları gereği ihlal eder. Birincisi eşzamanlı bir insan onay olayı varsayımıdır. İkincisi tek sıçramalı delegasyon varsayımıdır: bir istemciden bir kaynak sunucusuna.

Bir ajan gece 03.00'te üç servis zinciri üzerinden çalıştığında iki varsayım da çöker. Alan bu sorunu yeni protokol icat ederek değil, mevcut yapı taşlarını yeniden birleştirerek çözmektedir.

### 70. Ajan kimliği

**İki yanlış kalıp.** Ajanların bir insanın kimliğiyle çalışması, bir şey ters gittiğinde atfın tamamen kaybolmasına yol açar. Paylaşılan servis hesabıyla çalışması ise uzun ömürlü sır, delegasyon zincirinin yokluğu ve patlama yarıçapının tüm kiracıya yayılması demektir.

**Sektörün cevabı.** Ajan birinci sınıf bir non-human identity'dir: kendi principal'ı olan, kriptografik olarak attest edilen, çalışma zamanında kısa ömürlü olan ve insanın token exchange yoluyla delege eden özne olarak korunduğu bir yapı.

**Dört mimari kalıp.** User-delegated: açık onayla kullanıcı olarak çalışır. Autonomous: kendi kalıcı kimliği vardır. Hybrid orchestrated: ajan ajana delege eder. Scoped impersonation: kullanıcı olarak ancak dar scope'ta çalışır.

**Protokol yığını.** Tarayıcı ajanları için OAuth 2.1 ve PKCE, servis-servis için JWT bearer assertion, araç çağırma için delegasyon bağlamı gömülü MCP ve delegasyon zinciri taşıyan imzalı ajan token'ları. Dördü kompoze olur. Buna karşılık kategori tek bir baskın standarda yakınsamamıştır; çoğu kurum özel claim'li JWT, bazıları kurumsal PKI'dan mTLS, azınlık bulut yönetilen kimlikleri kullanmaktadır.

**Mimari test.** Doğru soru hangi token formatının kullanılacağı değildir. Kalıcı ajan kimliğinin kurumsal IGA kataloğuna bağlı olup olmadığı sorulur: hangi ajanların var olduğu, sahiplerinin kim olduğu ve hangi scope'lara izinli oldukları otoriter biçimde cevaplanabiliyor mu.

**Görünürlük.** Gravitee'nin 2026 anketinde kurumların yalnızca %24,4'ü ajan ile ajan arasındaki iletişime tam görünürlüğe sahiptir.

**Düzenleme: Singapur CSA Addendum (Ekim 2025).** Kimlik sahteciliği ve taklidi T9 tehdidi olarak sınıflandırılmıştır. İstenenler güvenilir bir ajan kaydı, ajanların verifiable credentials ve kısa ömürlü OAuth veya OIDC token'larıyla doğrulanması ve açıkça yetkilendirilmedikçe ajanlar arası yetki delegasyonunun yasaklanmasıdır. Çalışma zamanında scope'lu token, rate limit ve aksiyon sınırı, yüksek riskli işlemde human-in-the-loop ve korelasyon kimliği taşıyan loglar beklenir. İzleme tarafında karar ve çıktı denetimi, politika ihlali tespiti, prompt injection ile model drift izleme ve bir kill-switch istenir. WEF'in Ocak 2026 Davos governance çerçevesi hesap verebilirlik, şeffaflık, insan gözetimi ve veri yönetişimini sayar.

**AIMS.** Ajanı sahibine bağlayan çift kimlik credential'ları tanımlar. Üç delegasyon akışı bulunur: Agent-Mediate, Owner-Mediate ve Server-Mediate; her biri insana geri giden denetlenebilir bir zincir üretir.

**Ürünler.** Microsoft Entra Agent ID OAuth 2.0, MCP ve A2A ile çalışır; üçüncü taraf ajanlar sidecar SDK veya workload identity federation ile bağlanır. Lisans tuzağı şudur: Agent ID tüm Entra müşterilerine açıktır ancak Entra güvenlik özelliklerini ajanlara genişletmek Microsoft Agent 365 gerektirir. Auth0 for AI Agents Kasım 2025'te, Auth for MCP Mayıs 2026'da GA olmuştur. Descope da bu alanda ürün sunar. A2A protokolü Linux Foundation altındadır; ajanlar auth'unu Agent Card üzerinden ilan eder ve SPIFFE ile mTLS doğal taşıma bağlamasıdır.

### 71. MCP yetkilendirme

Korumalı bir MCP sunucusu OAuth 2.1 resource server, istemci ise OAuth 2.1 client'tır. AS implementasyonu kapsam dışıdır. STDIO transport için uygulanmamalıdır; kimlik bilgileri ortamdan gelir.

**2025-06-18'den beri değişmeyenler.** Sunucular PRM (RFC 9728) yayımlamak zorundadır; istemciler AS keşfi için bunu kullanmak zorundadır; AS'ler en az bir keşif mekanizması (OAuth AS Metadata veya OIDC Discovery) sunmalı, istemciler ikisini de desteklemelidir. İstemciler her token'ı RFC 8707 resource indicators ile tek bir resource server'a bağlamak zorundadır.

**2026-07-28 revizyonu.** Lansmandan beri en büyük değişikliktir. Protokol çekirdeği stateless hâle gelmiş, session ve initialization handshake kaldırılmış ve üç temel özellik deprecate edilmiştir. DCR deprecate edilmiş, yerine Client ID Metadata Documents (CIMD) gelmiştir; geriye uyumluluk asgari 12 aydır. RFC 9207 `iss` doğrulaması (SEP-2468) AS mix-up açığını kapatır ve SHOULD'dan MUST'a çıkması beklenmektedir. `application_type` alanı DCR'de tanımlanmış (SEP-837) ve masaüstü ile CLI localhost redirect reddi çözülmüştür. List ve read yanıtlarına `ttlMs` ve `cacheScope` eklenmiştir (SEP-2549). Ayrıca Multi Round-Trip Requests, header tabanlı yönlendirme ve extensions çerçevesi gelmiştir.

**Ölçek.** Tier 1 SDK'larda ayda yaklaşık yarım milyar indirme gerçekleşmektedir; TypeScript ve Python SDK'ları toplamda 1 milyar indirmeyi geçmiştir.

**Sık yapılan yanlış.** RFC 8707 audience binding replay sorununu çözer, consent sorununu çözmez. İstemci başına consent registry, sağlamlaştırılmış state parametreleri ve katı cookie öznitelikleri hâlâ gereklidir.

### 72. Workload identity: SPIFFE ve SPIRE

**SVID iki formda bulunur.** X.509-SVID'de SPIFFE ID SAN alanında URI olarak taşınır ve mTLS ile doğrudan kullanılır. JWT-SVID'de ise `sub` claim'inde taşınır. Biçim `spiffe://trust-domain/service` şeklindedir.

**Attestation.** SPIRE kimliği vermeden önce workload'ın iddia ettiği yerde çalıştığını doğrular: K8s'te Kubelet'ten pod metadata, namespace ve service account; AWS'de EC2 instance identity document; bare-metal'de UID, GID ve binary SHA256. SPIRE Server güven çıpasıdır ve Registration Entry defteri ile CA'yı barındırır.

**Kısa ömürler.** X.509 SVID onlarca dakika ile birkaç saat, JWT SVID birkaç dakika ömürlüdür ve otomatik yenilenir. Bu yapı sırrı workload'dan tamamen kaldırır.

**Kritik sınır.** SPIFFE isim verir, izin vermez. Yerleşik bir yetkilendirme politikası yoktur; Istio gibi mesh'ler veya OPA gibi motorlar üstüne katmanlanır. Pratikte ikisi birlikte kullanılır: SPIFFE altyapı içi kimlik için, OAuth her sınırda karar için.

**WIMSE.** SPIFFE spec seti artık WIT-SVID içermektedir; bu, IETF WIMSE Workload Identity Token'ın bir alt profilidir, Incubating statüsündedir ve proof-of-possession zorunlu, bearer kullanımı yasaktır. 3 Ağustos 2026 itibarıyla 19 aktif WIMSE draft'ı bulunmaktadır ve çoğu ajanlarla ilgilidir.

**Ekosistem.** OpenAI SPIFFE JWT-SVID'lerini workload identity federation subject token'ı olarak kabul etmektedir; X.509-SVID kabul edilmez, token `sub`, `aud` ve `exp` yanında `iss`, `iat` ve `kid` taşımalıdır ve JWT-SVID bir OIDC ID token değildir. Keycloak 26.4 SPIFFE ve K8s service account token'ıyla Federated Client Authentication desteklemektedir. `spire-identity-exchange` GitHub Actions, GitLab CI ve K8s service account token'larını SPIRE SVID'leriyle takas eder; Apache 2.0 lisanslıdır ve deneyseldir.

### 73. Cross-App Access (XAA ve ID-JAG)

`draft-ietf-oauth-identity-assertion-authz-grant` taslağı, kurumsal IdP'nin iki uygulama arasındaki bağlantıyı yönetmesini tanımlar; kullanıcının manuel onayı yerine token exchange kullanılır. Taslak "Identity and Authorization Chaining Across Domains" üzerine kuruludur ve domainler arası hareket eden ID-JAG token'ının claim'lerini tanımlar.

**Değeri.** Uygulamalar birbirleriyle doğrudan güven kurmaz; tekrarlayan consent prompt'ları ve statik API anahtarları ortadan kalkar; merkezî IdP kontrolde kalır.

**Durum.** Keycloak'ta deneyseldir (draft-01) ve dokümantasyon üretimde kullanılmamasını söyler. Keycloak zaten Token Exchange (8693) ve JWT Authorization Grant (7523) ile chaining desteklemekteydi.

### 74. Sürekli erişim değerlendirmesi: SSF, CAEP ve RISC

**Problem.** Bir saatlik token verilmiştir; 40. dakikada kullanıcı işten çıkarılmış, cihaz jailbreak olmuş veya kimlik bilgisi bir breach dump'ında çıkmıştır. OAuth'ta ve OIDC'de bunu relying party'ye bildiren hiçbir mekanizma yoktur.

**Yapı.** SSF, Transmitter ile Receiver arasında asenkron ve gizliliği korunmuş güvenlik webhook'ları sağlar; RFC 8417 SET'leri taşır. CAEP oturum ve cihaz olaylarını taşır: `session-revoked`, `credential-change`, `device-compliance-change`. RISC hesap ele geçirme ve kimlik bilgisi ihlalini taşır. Üçü de 2 Eylül 2025'te Final olmuştur.

**CAEP Interoperability Profile 1.0 draft-01.** Temmuz 2026 tarihlidir; asgari uyumluluk setini ve SSF uç noktalarının OAuth ile yetkilendirilmesini tanımlar. Implementasyonun tüm senaryoları desteklemesi zorunlu değildir.

**Ajanlar için önemi.** Uzun görev yürüten bir ajan için "token 40 dakika daha geçerli" cevabının tam olarak yanlış olduğu durumdur. IETF ajan çerçevesi gözlemlenebilirliği bir güvenlik kontrolü hâline getirir: sinyal alındığında yetki daraltılır, cache'li token'lar düşürülür, daha sıkı kısıtlarla yeniden alınır ve politika yeniden çalıştırılır; geri çekilmiş yetkilendirme kullanılmaya devam edilmez.

**Benimseme.** Google Workspace SSF Receiver'ı Session Revocation için closed beta aşamasındadır. SailPoint receiver'ı Session Revoked ve Credential Change desteklemekte ve gelen olayı kimlik bağlamıyla otomatik zenginleştirmektedir.

### 75. DBSC — Device Bound Session Credentials

Cookie'lerin temel problemi bearer olmalarıdır. Masaüstünde uygulama izolasyonu zayıftır ve malware tarayıcının erişebildiği her şeye erişir.

DBSC oturumu cihaza bağlı bir anahtar çiftine bağlar; özel anahtar sistem seviyesinde exfiltrasyona karşı korunur. Her oturum benzersiz bir anahtar çifti kullanır, dolayısıyla cross-session takip oluşmaz ve kullanıcı temizlediğinde anahtarlar silinir.

**Durum.** Chrome 146 ile Nisan 2026'da Windows'ta GA olmuştur ve Origin Trial sona ermiştir. macOS desteği Secure Enclave ile yaklaşan sürümdedir. Diğer tarayıcılar değerlendirme aşamasındadır. Google'ın yol haritasında federated identity (cross-origin SSO binding), advanced registration (mTLS ve donanım anahtarı) ve güvenli donanımı olmayan cihazlar için yazılım anahtarları bulunmaktadır.

**SSF ile birleşik mimari.** Güvenlik aracı bir RISC sinyali üretir, IdP cihazın ele geçirildiğini bildiren bir CAEP olayı push eder, sonraki DBSC yenilemesinde sunucu imzayı reddeder ve oturum sonlanır. Bu, infostealer'ın çaldığı cookie'yi işlevsiz bırakan ilk yapısal cevaptır.

### 76. Dijital kimlik cüzdanları: eIDAS 2.0 ve EUDI

| Tarih | Yükümlülük |
|---|---|
| 20 Mayıs 2024 | Regülasyon (EU) 2024/1183 yürürlüğe girmiştir |
| Aralık 2026 | Her üye devlet en az bir sertifikalı EUDI Wallet sunmak zorundadır |
| Aralık 2027 | Bankacılık, sağlık, telekom ve büyük platformlar dahil yükümlü özel sektör Wallet'ı kabul etmek zorundadır |
| 2030 (hedef) | Vatandaşların %80'i |

**Teknik yığın.** ARF 3.0.0 (Temmuz 2026). Formatlar ISO/IEC 18013-5 mDL ve seçici ifşa için SD-JWT VC'dir. Taşıma OpenID4VCI (issuance) ve OpenID4VP (presentation) ile yapılır. Güven modeli eIDAS Trusted Lists'tir.

**Spec olgunluğu.** OpenID4VP 1.0 Final (Temmuz 2025), OpenID4VCI 1.0 Final (Eylül 2025) ve HAIP 1.0 Final (Aralık 2025).

**Format gerçeği.** EUDI SD-JWT VC belirtir ancak dünya çok formatlıdır: ehliyetler ISO mDL, QTSP ve devlet attestation'ları SD-JWT VC kullanır. RP'ler ikisini de desteklemelidir. Sphereon Verifier, Entra Verified ID veya Large Scale Pilot açık kaynakları çapraz format desteği verir; sıfırdan yazmak mümkündür ancak gereksizdir.

**Modlar.** Same-device modu `openid4vp://` şemasını, cross-device modu QR kodunu kullanır.

**Mevcut yığına etkisi.** EUDI federasyon broker'ını değiştirmez, üstüne bir VC düzlemi ekler. Broker'a bir OpenID4VP verifier uç noktası eklenir.

**RP entegrasyon eforu.** Trust framework kaydı 4-6 hafta, OID4VP entegrasyonu 8-12 hafta, Wallet attestation 2-4 hafta, status list ve revocation 2-4 hafta, sınır ötesi test 4-8 hafta sürer. Ayrıca cüzdan PID'i ile iç kullanıcı kaydı arasındaki ilişki — ilk provisioning, hesap bağlama, attribute yenileme, silme — ve consent ile audit güncellemesi gerekir.

**Mimari not.** Tek bir monolit yerine issuance, verification ve userinfo'nun ayrı servisler olarak OAuth, OpenID4VCI ve OpenID4VP ile bağlanması önerilmektedir.

### 77. Sonraki üç yılın izleme listesi

| Konu | Neden önemli | Ne zaman |
|---|---|---|
| Ajan kimlik standardizasyonu | Kategori henüz yakınsamamıştır | 2027-2028 |
| FiPA'nın RFC olması | Native login'in standart yolu olacaktır | 2027 |
| DBSC'nin diğer tarayıcılara yayılması | Cookie hırsızlığına yapısal cevaptır | 2027 |
| CXP finalizasyonu | Passkey taşınabilirliğini tamamlar | 2026-2027 |
| PQC FIDO2 | Donanım değişim döngüsünü belirler | 2027 sonu - 2028 |
| EUDI özel sektör yükümlülüğü | AB'de zorunlu kabul başlar | Aralık 2027 |
| WIMSE olgunlaşması | Workload ve ajan kimliği standardıdır | 2027 ve sonrası |

### 78. Yeni nesil olgunluk

| Teknoloji | Statü | Üretime alınır mı |
|---|---|---|
| SSF, CAEP, RISC | Final (Eylül 2025) | Evet; karşı taraf desteği sınırlıdır |
| MCP Authorization | Spec 2026-07-28 | Evet |
| CIMD | Draft; MCP'de benimsenmiştir | Kısmen |
| DBSC | Chrome Windows'ta GA | Kısmen; tek tarayıcı |
| OpenID4VP, OpenID4VCI, HAIP | Final | Evet |
| EUDI Wallet | ARF 3.0.0; son tarih Aralık 2026 | Pilot |
| CXF ve CXP | CXF yayımlanmıştır, CXP devam etmektedir | Kısmen ve hayır |
| FiPA | IETF WG draft-04 | Kalıp olarak evet |
| ID-JAG ve XAA | draft-01; Keycloak'ta deneysel | Hayır |
| WIMSE ve WIT-SVID | Incubating | Hayır |
| Ajan kimlik standartları | Yakınsamamıştır | Hayır |
| Post-quantum auth | Standartlar oluşmaktadır | Hazırlık aşaması |

---

## Bölüm X — Uyum ve mevzuat

### 79. Genel omurga

Coğrafyadan bağımsız ortak beklenti şudur: iki bağımsız faktör, işlem ve aksiyon bazlı doğrulama, oturum zaman aşımı, denetim izi, en az yetki ve veri minimizasyonu.

### 80. Veri koruma: GDPR, KVKK ve CCPA

**Hukuki dayanak.** Kimlik doğrulama verisi genelde sözleşmenin ifasına dayanır; biyometrik veri özel niteliklidir ve ayrı açık rıza gerektirir.

**Veri minimizasyonu.** Toplanmayan veri sızdırılamaz. Doğum tarihi gibi alanların gerçekten gerekli olup olmadığı sorgulanır.

**Saklama süresi.** Denetim logları için mevzuat süresi uygulanır; ötesinde anonimleştirme yapılır.

**Silme hakkı.** Hesap silme akışı ile denetim yükümlülüğü çelişebilir; çözüm anonimleştirme ve tombstone'dur.

**Taşınabilirlik.** Kullanıcı verisinin makine okunabilir biçimde dışa aktarımı sağlanır.

**Veri yerleşimi.** Yönetilen CIAM seçerken kritiktir; Clerk gibi bazı sağlayıcılar veriyi ABD'de tutar.

**Aydınlatma metinleri.** Dil başına ayrı ve versiyonlanmış tutulur; hangi kullanıcının hangi versiyonu onayladığı kayıt altına alınır.

### 81. Sektörel çerçeveler

| Çerçeve | Kapsam | Auth gereksinimi |
|---|---|---|
| PCI DSS 4.0 | Kart verisi | Requirement 8: kart sahibi veri ortamına tüm erişimlerde MFA |
| HIPAA | ABD sağlık | 45 CFR 164.312(d) kişi ve kurum kimlik doğrulaması; metodoloji NIST 800-63 |
| FERPA ve COPPA | ABD eğitim ve 13 yaş altı | Veli onayı, veri toplama kısıtı |
| FedRAMP | ABD kamu bulutu | AAL2 veya AAL3; ayrıcalıklı hesaplarda phishing-resistant MFA |
| OMB M-22-09 | ABD federal zero trust | Personel, yüklenici ve iş ortaklarına phishing-resistant MFA; uygulama katmanında MFA |
| SOC 2 ve ISO 27001 | Genel güvence | Erişim kontrolü, MFA, erişim gözden geçirmeleri, log |
| NIS2 | AB kritik altyapı | Çok faktörlü doğrulama ve olay bildirimi |
| DORA | AB finans | Operasyonel dayanıklılık, üçüncü taraf riski |
| eIDAS 2.0 | AB | 2027'de yükümlü sektörlerde EUDI Wallet kabulü |

### 82. PSD2 SCA

Avrupa ödemelerinde iki bağımsız faktör ve dynamic linking gerekir. Her işleme özgü bir authentication code üretilir; bu kod ödemenin tutarı ve alıcısıyla birlikte sürecin her adımında taşınır. Tutar ve alıcı ödeyene açıkça gösterilir; bu WYSIWYS ilkesidir. Kod veya detaylar değişirse işlem başarısız olmalıdır. İşlem verisinin gizliliği ve bütünlüğü süreç boyunca korunmalıdır. CIBA bu akış için standart teslim kanalıdır.

### 83. Türkiye: ödeme ve elektronik para kuruluşları

Bu bölüm bir örnektir ve ulusal mevzuatın genel standartların üstüne nasıl ek kısıt getirebildiğini gösterir.

**Dayanak.** 6493 sayılı Kanun, Ödeme Hizmetleri Yönetmeliği (1 Aralık 2021), Bilgi Sistemleri Tebliği (1 Aralık 2021) ve MASAK Genel Tebliği Sıra No: 19.

**Tebliğ madde 10 (GKD).** Birden fazla bileşen, müşteriye özgü ve taklit edilemez bileşenler, oturum güvenliği ve işlemsiz oturumların sonlandırılması istenir.

**Kritik hüküm: platform biyometrisi.** Kuruluşun mobil uygulamasının kontrolünde olmayıp cihaz üreticisinin kontrolünde olan parola, PIN veya biyometrik veriler güçlü kimlik doğrulama unsurları olarak kullanılamaz.

Bu hüküm WebAuthn'ın User Verification'ı platforma delege etme modeliyle doğrudan çatışır; telefonun kendi yüz veya parmak izi kilidine dayanmak GKD sayılmaz. Gereken kalıp, uygulamanın kendi kontrolündeki PIN ile uygulamanın ürettiği anahtar çiftidir. Genel ders şudur: platform biyometrisine dayanan bir mimari her yargı alanında geçerli değildir.

**SMS OTP kısıtı.** Sahiplik bileşeni olarak yalnızca mobil uygulamanın ilk kurulumu, etkinleştirilmesi, yeniden etkinleştirilmesi veya kullanılamaz hâle gelmesi durumlarında kullanılabilir.

**SIM değişikliği (madde 10/21).** Operatörlerle entegrasyon zorunludur; müşteri teyidi alınmadıkça değişiklikten itibaren 90 gün SIM tabanlı yöntem kullanılamaz, aksi hâlde ispat yükümlülüğü kuruluşa geçer.

**İşlem doğrulama kodu.** Müşteriye atanmış şifreleme gizli anahtarı ile imzalanması esastır; mümkün değilse SMS'e düşülür.

**Kimlik yerine geçen belgeler (madde 10/16).** Bu belgelerdeki bilgiler ve anne kızlık soyadı kimlik doğrulamada kullanılamaz; güvenlik sorusu da bunlardan biri olamaz.

**4 Eylül 2026 değişiklikleri (RG 33360).** Yönetmelik madde 41'e biyometrik yöntemler ve elektronik kimlik doğrulama kabiliyetli belgeler eklenmiştir. Tebliğ tarafında kimlik belgesi tanımlanmış, uzaktan kimlik tespiti (madde 22) sıkılaştırılmıştır: NFC yapılamıyorsa MASAK Tebliğ 19'daki güvenlik unsurları uygulanır, canlılık testi ve NFC çip fotoğrafıyla biyometrik karşılaştırma yapılır, cihaz ve ortam kontrolü (ışık, gürültü, sinyal) gerekir, belge orijinallik, bütünlük, yıpranma ve tahrif testleri uygulanır, yabancılar için ICAO 9303 NFC'li pasaport istenir. Madde 10/8'de kimlik belgesinin kart PIN'i veya biyometrik veri ile kullanılması ya da güvenli elektronik imza hâlinde GKD karşılanmış sayılır.

**Yönetişim.** Madde 22/7 süreç ve doğrulama kriterlerinin yazılı olarak dokümante edilmesini, madde 22/6 ise yılda en az iki kez test yapılmasını gerektirir.

**Sermaye piyasası.** SPK VII-128.10 benzer hükümler taşır: çok faktörlü doğrulama tanımı, kritik işlemlerde ek adım, SMS öncesi SIM ve numara taşıma kontrolü, teyitte iki faktörlü doğrulama esası ve ispat yükümlülüğü.

### 84. Ajanlar için düzenleyici hareket

Singapur CSA Addendum ve WEF çerçevesi §4 §70'te ele alınmıştır. Bir companion discussion paper ajan kimliği ve delegasyon şemalarını mimari olarak çözülmemiş bir boşluk olarak tanımlamakta ve standartlaştırılmış kimlik protokollerini araştırma önceliği ilan etmektedir.

---

## Bölüm XI — Komşu ekosistem

### 85. Kimlik tespiti (KYC ve IDV)

Kimlik doğrulamanın öncesindeki adımdır: kayıt anında kişinin gerçekten iddia ettiği kişi olduğunun tespiti.

**Bileşenler.** Belge yakalama (OCR, pasaportta MRZ), NFC çip okuma (dijital imza doğrulama ve MRZ ile karşılaştırma), yüz eşleştirme (canlı görüntü ile çip veya belge fotoğrafı, eşleşme skoru ve eşik), canlılık testi (pasif olarak doğal boyut ve ışık, aktif olarak baş çevirme ve göz kırpma), belge bütünlük testleri, cihaz ve ortam kontrolü, fraud tespiti (çoklu başvuru, tekrarlanan canlılık başarısızlığı, şüpheli IP) ve kesintisiz kayıt.

**Kalite kriterleri.** Yüz tanıma algoritmalarının NIST sertifikasyonu, canlılık için iBeta Level 1 ve 2 ile hem pasif hem aktif canlılık desteği.

**Sağlayıcılar.** Uluslararası tarafta Onfido, Jumio, Sumsub, IDEMIA ve Veriff bulunur. Türkiye'de İHS Teknoloji (Udentify) ve SCSoft gibi yerel sağlayıcılar NFC, OCR, yüz eşleştirme ve canlılık paketini uçtan uca sunmaktadır.

### 86. Fraud ve risk motorları

Auth kimin geldiğini söyler; fraud motoru bu davranışın normal olup olmadığını söyler. AiTM sonrası dünyada ikincisi olmadan birincisi yetmemektedir.

| Ürün | Odak | Kime uygun | Fiyat |
|---|---|---|---|
| Sardine | Fintech ve kripto; davranışsal biyometri: yazma ritmi, imleç, telefon tutuşu | Fintech, kripto ve yüksek risk; fraud ile compliance iç içeyse | Aylık yaklaşık 2.000-10.000 USD |
| Feedzai | Fraud ve AML'yi tek platformda birleştirir (RiskOps); omnichannel ve açıklanabilirlik sunar; yıllık yaklaşık 8 trilyon USD hacim iddiası vardır | Tier-1 ve Tier-2 bankalar | Yıllık 50.000 USD'den başlar; altı haneli yaygındır |
| Sift | Digital Trust and Safety: ödeme, hesap, ATO, içerik suistimali ve itiraz | Pazaryerleri, sosyal platformlar, çok vektörlü senaryolar | Yıllık yaklaşık 30.000-50.000 USD; 100.000 USD üstü mümkündür |
| SEON | Dijital ayak izi, cihaz zekâsı, skorlama ve AML; şeffaf fiyat ve hızlı kurulum | Hızlı fintech'ler ve orta ölçek | Aylık yaklaşık 699 USD; 30 gün deneme |
| Forter | Ters kurgu: daha çok iyi müşteriyi onaylamaya odaklanır; 1,8 milyar kimlikli Identity Graph | Yanlış reddin fraud'dan pahalı olduğu, 100 milyon USD üstü GMV'li perakende | Kurumsal |
| BioCatch | Saf davranışsal biyometri | Banka ATO ve sosyal mühendislik | Kurumsal |
| Featurespace | Kurumsal davranışsal analitik | Bankalar | Kurumsal |
| Unit21 | Uçtan uca vaka yönetimi, self-servis kural ve açıklanabilir AI | Gerçekten soruşturma yürüten ekipler | Kurumsal |
| Hawk:AI, NICE Actimize, DataVisor | Transaction monitoring, AML, denetimsiz ML | Bankalar ve büyük ölçek | Kurumsal |
| Signifyd ve Riskified | Garanti modeli; chargeback'i üstlenirler | E-ticaret | Korunan GMV'nin %0,6-1,5'i |
| Kount | Klasik e-ticaret | Perakende | Yıllık 50.000 USD'den başlar |
| Stripe Radar | Sıfır entegrasyon | Stripe müşterileri | Standart fiyatta ücretsiz, aksi hâlde işlem başına 5-7 sent |
| cside | Tarayıcı katmanı sinyalleri | Sinyal katmanı | Aylık yaklaşık 99-500 USD |

**Notlar.** Sentetik kimlik, ATO ve para katırı ağları kural tabanlı sistemlerle yakalanamamaktadır. Değerlendirme kriterleri gerçek zamanlı gecikme, yanlış pozitif oranı, API esnekliği, açıklanabilirlik ve AML ile KYC kapsamıdır. Kendi verisiyle pilot yapılmadan sözleşme imzalanmaz. Toplam maliyette implementasyon, özel kural yazımı ve itiraz yönetimi faturayı genelde ikiye katlar.

Yetkili push ödeme (APP) dolandırıcılığı, yani kullanıcının kendi onayladığı işlem, kart fraud araçlarının tamamen kaçırdığı bir vektördür; davranışsal araçlar oturumdaki tereddüt ve baskı örüntülerini yakalar.

### 87. Mobil sertleştirme (RASP ve app shielding)

| Ürün | Yaklaşım | Not |
|---|---|---|
| Guardsquare (DexGuard ve iXGuard) | Derleyici seviyesinde obfuscation | Derin kod koruması sağlar; build entegrasyonu gerekir |
| Promon SHIELD | Post-compile shielding | Fintech ve mobil bankacılıkta yoğun kullanılır; güçlü vaka çalışmaları vardır |
| Appdome | No-code; derlenmiş binary üzerinde çalışır | SDK gerektirmez; fraud, bot ve uyumluluk alanlarına uzanır |
| Talsec (freeRASP, RASP+, AppiCrypt) | SDK, freemium | Android, iOS, Flutter, React Native, Capacitor ve Cordova destekler. Tespit ettikleri: reverse engineering, root (Magisk), jailbreak (unc0ver, checkra1n, Dopamine), Frida, emülatör, bot, tampering, VPN, malware |
| Approov | Dinamik RASP ve API attestation | Yalnızca güvenli ortamdaki gerçek uygulamaya geçerli JWT verir; anlık kayıt ve iptal sunar |
| Verimatrix XTD | Shielding, telemetri ve müdahale | Geniş kapsam |
| Zimperium MAPS, AppSealing, DexProtector | Runtime tespit, zero-coding shielding, obfuscation | Alternatifler |

**Karar ekseni.** SDK gömme, post-compile veya no-code, build-time obfuscation seçeneklerinden biri seçilir. Cross-platform desteği (React Native, Flutter) ayrı bir kriterdir.

**Kural.** Çıktı bir sinyaldir, bloke kararı değildir. Rooted cihazı tamamen bloklamak meşru kullanıcı kaybettirir.

### 88. Bot ve kayıt suistimali koruması

Cloudflare Turnstile, hCaptcha, Arkose Labs, Castle ve DataDome bu alandaki araçlardır. NIST 800-63-4'ün kayıt süreçlerine karşı otomatik saldırı önleme gereksinimini karşılarlar.

### 89. Test ve conformance

OpenID Foundation Conformance Suite FAPI 1.0 ve 2.0'ı (DPoP ve nonce dahil), OIDC Core'u ve CIBA'yı kapsar; sertifikasyon buradan geçer. Keycloak FAPI Playground örnek istemci yapılandırmaları ve uçtan uca DPoP akışları sunar. Duende'nin Financial-Grade Security and Conformance raporu yapılandırmayı OAuth 2.1 ve FAPI 2.0'a karşı otomatik denetler. Passkeys Debugger ve passkeys.eu WebAuthn debug ve akış doğrulaması sağlar. Evilginx2 ve Modlishka AiTM dayanıklılığını kendi ortamında test etmek için kırmızı takım araçlarıdır. Yük testinde Keycloak referansları 2.000 login/sn ve 10.000 yenileme/sn'dir.

**Unutulan test senaryoları.** Eşzamanlı refresh yarışı; reuse detection ile aile iptali; saat kayması nedeniyle `private_key_jwt` başarısızlığı; cihaz değişimi sonrası eski cihaz davranışı; kurtarma rate limiti; hesap bağlama çakışması; enumeration'ın yanıt süresinden sızması.

### 90. Gözlemlenebilirlik ve denetim izi

**Kaydedilecekler.** Her doğrulama denemesi ve sonucu, kullanılan faktörler ile `acr` ve `amr` değerleri, cihaz kimliği, IP ve ASN, risk skoru ve karar, step-up tetiklenmesi, aksiyon imzası doğrulaması, yetki değişiklikleri, cihaz kaydı ve iptali, kurtarma girişimleri, oturum iptalleri ile consent verme ve geri alma.

**Kurallar.** Kayıtlar append-only tutulur ve mevzuata göre saklanır. Korelasyon kimliği kullanılır; bu, tek bir kullanıcı yolculuğunun tüm servislerdeki izidir, ajan senaryolarında denetlenebilirliğin ön şartıdır ve en ucuz kalemdir. Kayıtlarda kimlik bilgisi, token veya PIN hiçbir zaman görünmez. Veri SIEM'e gerçek zamanlı akar.

### 91. Toplam sahip olma maliyeti modellemesi

| Kalem | Self-hosted | Yönetilen |
|---|---|---|
| Lisans ve abonelik | Yok, yalnızca destek olabilir | MAU veya bağlantı başına |
| Altyapı | Sunucu, veritabanı, HA, yedek | Dahildir |
| Operasyon iş gücü | Yükseltme, izleme, nöbet | Minimaldir |
| Entegrasyon | SDK, tema, akış | SDK |
| Özelleştirme | SPI veya eklenti ile bakım | Actions ve Hooks; lock-in üretir |
| Uyumluluk | Denetim ve kanıt üretimi | Kısmen dahildir |
| Göç riski | Düşük | Yüksek |

**Eşikler.** 100.000 MAU yönetilen çözümün pahalılaşmaya başladığı noktadır; 500.000 MAU üstünde self-host ve hyperscaler ekonomisi kazanır.

### 92. Göç oyun kitabı

**Temel kısıt.** Yönetilen platformlardan parola hash'leri dışa aktarılamaz.

**Lazy migration.** Eski sisteme gelen login'e araya girilerek şeffaf taşıma yapılır. Auth0'da bir özellik olarak bulunur; Logto ve Keycloak genişletilebilir authenticator'larla aynı kalıbı destekler.

**Bulk import.** Hash formatı uyumluysa (bcrypt, argon2) mümkündür.

**Süre.** SDK yeniden yazımı ve hook ile Actions göçü dahil her iki yönde 60-90 gündür.

**Taşınması unutulanlar.** MFA kayıtları (TOTP secret'ları; passkey'ler origin'e bağlı olduğu için domain değişirse taşınamaz), oturumlar (kullanıcılar bir kez atılır), consent kayıtları, denetim geçmişi, özel claim mapping'leri ve harici IdP bağlantıları.

---

## Bölüm XII — Anti-pattern kataloğu

### 93. Yapılmaması gerekenler

**Kimlik ve veri modeli.** E-postayı birincil anahtar yapmak. Tek kimlik sağlayıcı varsayıp `identities` tablosunu atlamak. Parola hash'inde algoritma tanımlayıcısı saklamamak. Doğrulanmamış e-posta üzerinden otomatik hesap bağlamak; bu pre-account takeover üretir.

**Kimlik doğrulama.** Kendi kriptosunu veya kendi IdP'sini yazmak. SHA-256 gibi hızlı hash'lerle parola saklamak. Güvenlik sorularını authenticator olarak kullanmak. SMS OTP'yi tek MFA seçeneği yapmak. Periyodik zorunlu parola rotasyonu uygulamak. Parola alanında yapıştırmayı engellemek. Karakter tipi zorunlulukları koymak. Parola uzunluğuna düşük bir üst sınır koymak.

**Token ve oturum.** Bearer token'ı sender-constrained yapmadan uzun ömürlü vermek. Refresh token rotation'ı reuse detection olmadan kurmak. Mobilde eşzamanlı refresh korumasını atlamak. SPA'da refresh token'ı localStorage'da tutmak. JWT'de `alg: none` veya algoritma karıştırmasına açık doğrulama yapmak. `aud` ve `iss` doğrulamamak. JWT'yi iptal edilebilir sanmak; stateless token iptal edilemez, kısa ömür ve iptal listesi gerekir. Oturumu yalnızca zaman aşımıyla yönetip iptal mekanizması koymamak.

**Yetkilendirme.** Yetki kararlarını frontend'de vermek. Rolü token'a gömüp hiç tazelememek. IDOR üretmek, yani kaynak sahipliğini kontrol etmemek. Admin panelini yalnızca gizli bir URL ile korumak.

**Kullanıcı deneyimi.** Kayıtta sekiz alan istemek. Regülasyon gerektirmiyorsa e-posta doğrulamasını ürüne girmeden zorunlu kılmak. MFA'yı kayıt anında zorlamak. Kurtarma kodlarını göstermemek. Enumeration sızdıran hata mesajları vermek. Sosyal login'i zorunlu kılmak. Aktif oturum listesi ve uzaktan çıkış sunmamak.

**Operasyon.** İstemci sırrını mobil binary'ye veya repoya koymak. JWKS rotasyon planı bulundurmamak. Break-glass hesabı bulundurmamak. Attestation'ı boolean bir kapı gibi kullanmak; bu relay saldırısına açıktır. Denetim loglarına token veya PIN yazmak. Impersonation'ı denetim izi olmadan vermek. Rate limiting'i yalnızca IP bazlı kurmak.

---

## Bölüm XIII — Seçim rehberi

### 94. Karar eksenleri

Aşağıdaki eksenler etki sırasına göre sıralanmıştır.

1. Aktörler kimdir: tüketici, çalışan, servis, cihaz, ajan. Her biri farklı çözüm ister.
2. Üçüncü taraf istemci olacak mı. Olacaksa gerçek bir AS ve muhtemelen FAPI gerekir.
3. Kurumsal federasyon gerekiyor mu. SAML ve SCIM gerekiyorsa Ory elenir.
4. B2C mi B2B mi. B2B ise Organizations birinci sınıf olmalıdır.
5. Regülasyon var mı. Sağlık, finans ve kamu genelde self-hosted zorunlu kılar.
6. Ölçek ve fiyat modeli: MAU bazlı mı bağlantı bazlı mı; 100.000 MAU eşiği.
7. Operasyon kapasitesi. Doğru soru işin zor olup olmadığı değil, hangi topolojiye ihtiyaç duyulduğudur.
8. Lisans. AGPL (Zitadel core) dağıtımda blokaj yaratabilir; FusionAuth açık kaynak değildir.
9. Mobil ana akış mı. Öyleyse tarayıcı redirect'i olmayan bir kalıp gerekir.
10. Göç maliyeti. Hash taşınmaz; lazy migration gerekir; süre 60-90 gündür.
11. Kripto çevikliği. PQC bir satın alma gereksinimi olarak yazılır.

### 95. Hızlı yönlendirme

| Durum | Bakılacak |
|---|---|
| Protokol genişliği ve olgunluk gerekiyor, operasyon kapasitesi var | Keycloak |
| B2B çok kiracılık gerekiyor ve AGPL sorun değil | Zitadel |
| Apache lisanslı çok kiracılık gerekiyor | Keycloak Organizations |
| Kendi auth arayüzü ve ölçek hedefi var | Ory Hydra ve Kratos |
| Reverse proxy arkasında iç uygulamalar var | Minimal için Authelia; flow, LDAP ve SCIM için Authentik |
| Tüketici uygulaması ve gömülü auth isteniyor | SuperTokens |
| JavaScript ve TypeScript ile hızlı ürün gerekiyor | Logto veya Better Auth |
| Next.js ve React, 100.000 MAU altında | Clerk |
| B2B kurumsal SSO hızlı gerekiyor | WorkOS |
| Kurumsal genişlik ve FGA gerekiyor, bütçe var | Auth0 |
| AWS-native ve yüksek MAU | Cognito |
| Microsoft-native ve FedRAMP | Entra External ID |
| Supabase üzerinde çalışılıyor | Supabase Auth ve RLS |
| En geniş sosyal login, özellikle Asya | Casdoor |
| FAPI sertifikası gerekiyor | Authlete, WSO2 IS, Curity |
| .NET ve in-process token server | Duende IdentityServer |
| Node'da sertifikalı AS | node oidc-provider |
| Akademik federasyon | Shibboleth, CAS |
| İnce taneli yetkilendirme | OpenFGA veya SpiceDB |
| Çalışma zamanı bağlamlı karar | Cerbos |
| Workload ve ajan kimliği | SPIFFE, SPIRE ve OAuth |
| IoT filosu | mTLS, PKI (DigiCert, SSL.com) ve zero-touch provisioning |

### 96. Standart olgunluk özeti

| Teknoloji | Statü | Üretime alınır mı |
|---|---|---|
| OAuth 2.1 ve PKCE | Konsolide | Evet |
| DPoP | RFC, yaygın | Evet |
| PAR, RAR, JAR, JARM | RFC | Evet |
| Token Exchange | RFC | Evet |
| Step-up (9470) | RFC | Evet |
| FAPI 1.0 ve 2.0 | Final, sertifikalı | Evet; 2.0 confidential client ile |
| CIBA | Final | Evet |
| WebAuthn L2 ve passkey | Yaygın | Evet |
| WebAuthn L3 | W3C Recommendation'a önerildi | Kısmen |
| SCIM 2.0 | Olgun | Evet |
| Argon2id (RFC 9106) | Standart | Evet |
| Yeni nesil teknolojiler | §4 §78 | — |

---

## Bölüm XIV — Sınırlar

### 97. Bu dokümanın kapsamadıkları

Hiçbir eksiği olmayan bir auth dokümanı mümkün değildir; alan haftalık değişmektedir.

**Hızla eskiyecekler.** FiPA ve ID-JAG draft statüleri, MCP revizyonları, ürün sürüm özellikleri, DBSC tarayıcı desteği, EUDI ARF sürümü ve tüm fiyat rakamları. Bunlar 3-6 ayda kayabilir.

**Kaynak kalitesi.** Ürün karşılaştırmalarının çoğu satıcı bloglarından gelmektedir ve taraflıdır; bazıları açıkça çıkar beyanı yapmaktadır — yönetilen Keycloak satan bir firma, kendi ürününü karşılaştıran bir satıcı, rakiplerini yazan bir CIAM. Lisans ve sürüm gibi doğrulanabilir olgular çapraz teyit edilmiştir; "en iyi" türü yargılar edilmemiştir.

**Rakamlar.** Benimseme ve tehdit istatistikleri satıcı raporlarından gelmektedir ve metodolojileri farklıdır. Yön göstergesidir, kesin ölçüm değildir.

**Bu sürümde kapatılanlar.** IGA, PAM, ulusal eID şemaları, merkeziyetsiz kimlik ve biyometrik algoritma satıcıları artık Bölüm XV'tedir.

**Hâlâ araştırılmayanlar.** Ülke bazlı eID entegrasyonlarının teknik detayı; her şemanın kendi SDK'sı, sözleşme süreci ve test ortamı bulunduğu için tek tek incelenmesi gerekir. Kripto varlık hizmet sağlayıcı mevzuatı. Sektöre özgü kimlik federasyonları: havacılıkta IATA One ID, denizcilik, sağlıkta HL7 ve SMART on FHIR. Eski protokollerin (NTLM, RADIUS) modern ortamdaki konumu. Kimlik doğrulama alanındaki akademik literatür, yani formel güvenlik analizleri.

**Hukuki uyarı.** Mevzuat bölümleri metni aktarır, hukuki görüş vermez. Yorumlar hukuk danışmanıyla doğrulanmalıdır; sağlayıcı servis detayları — fiyat, kapsam, SLA — doğrudan sağlayıcıdan teyit edilmelidir.

---

## Bölüm XV — Kapatılan boşluklar

Bu bölüm, önceki sürümde araştırılmadı olarak işaretlenen beş alanı kapsar.

### 98. IGA — Identity Governance and Administration

IGA, kimin neye erişebilmesi gerektiği sorusunun yönetişimidir: erişim sertifikasyonları, yaşam döngüsü otomasyonu, rol yönetimi, görevler ayrılığı (SoD) ve uyum raporlaması.

**IGA ile PAM ayrımı.** IGA kimin ayrıcalıklı erişimi olması gerektiğini yönetir: rol politikaları ve onay akışları. PAM o erişimin nasıl kullanıldığını yönetir: vault, oturum kaydı ve JIT. Standart entegrasyon kalıbı şudur: IGA yaşam döngüsü olaylarına göre ayrıcalıklı hesaplar PAM vault'unda açılır ve kapanır.

| Ürün | Konum |
|---|---|
| SailPoint | Kurulu tabanıyla pazar lideridir. Erişim sertifikasyonları, yaşam döngüsü otomasyonu, rol yönetimi ve uyum sunar. Binlerce uygulamayı kapsayan geniş konnektör kütüphanesi, AI destekli erişim önerileri ve rol madenciliği bulunur. IdentityIQ'dan (on-prem) Identity Security Cloud'a (SaaS) göç, karmaşık on-prem kurulumlarda özellik boşlukları yaratmıştır. Pazar lideri yetenek ve geniş konnektör isteyen büyük kurumlar için uygundur |
| Saviynt | Bulut-native'dir; on-prem kod tabanından uyarlanmamıştır. Yakınsanmış IGA, PAM ve AAG satıcı dağınıklığını azaltır. SAP, Oracle ve Salesforce uygulama yönetişiminde özellikle güçlüdür; işlem seviyesinde SoD sunar, yani rol veya yetki seviyesinde değil fonksiyon kodu ve işlem seviyesinde çakışma yakalar, bu SOX için kritiktir. JIT erişim 2025'te üretime alınmıştır. Gartner Peer Insights Customers' Choice ödülünü beş yıl üst üste almış, 2026'da 249 doğrulanmış incelemeyle 4,8/5 puan elde etmiştir. SailPoint'ten düşük toplam sahip olma maliyeti sunar. Zayıf yönleri: PAM bileşeni PAM-lite düzeyindedir ve derin oturum kaydı ile vaulting gerekiyorsa CyberArk veya BeyondTrust'ın yerini tutmaz; sistem entegratörü partner ekosistemi küçüktür; konnektör kütüphanesi daha dardır; sık sürüm çıkışı büyük kurumlarda rahatsızlık yaratmaktadır; özel sermaye sahipliği (Carrick Capital) yol haritası endişesi doğurmaktadır |
| Omada | Avrupa merkezlidir; orta ve büyük kurumlara SaaS olarak sunulur |
| One Identity | Safeguard (PAM) ve Identity Manager (IGA) tek satıcıdan gelir; satın alma ve raporlamayı basitleştirir ancak her bileşen best-of-breed kadar derin değildir |
| Microsoft Entra ID Governance | Microsoft ekosisteminde doğal seçenektir |
| Okta Identity Governance | Okta üzerinde çalışılıyorsa uygundur |

İlk yılda en yüksek getirili kullanım çalışan kimlik yaşam döngüsünün otomasyonudur.

İlgili uyum çerçevesi SOX Bölüm 404'tür; iç kontrol değerlendirmesi ITGC'yi kapsar ve erişim sertifikasyonları buradan gelir.

### 99. PAM — Privileged Access Management

Ayrıcalıklı hesapların, kimlik bilgilerinin ve oturumların nasıl yaratıldığını, saklandığını, kullanıldığını ve izlendiğini yöneten kontrol kategorisidir. Kapsamı admin hesapları, servis hesapları, paylaşılan root kimlik bilgileri ve break-glass hesaplarıdır. Yetenekleri şifreli vault, JIT erişim, oturum kaydı ve denetim izidir.

Gartner MQ for PAM 2025'te birincil liderler CyberArk, BeyondTrust ve Delinea'dır; Saviynt bulut-native ve SaaS PAM alanında tanınmaktadır.

| Ürün | Güçlü yön | Kime uygun |
|---|---|---|
| CyberArk | Kategori kurulduğundan beri her MQ'da liderdir. Digital Vault mimarisinde kimlik bilgileri yalnızca Vault API üzerinden erişilebilen izole bir sunucuda durur; bu pazardaki en savunulabilir depolama modelidir. En derin kimlik bilgisi rotasyon kapsamı, en geniş sistem tipi desteği, en ayrıntılı CEF ve LEEF loglaması ile en derin SailPoint ve Saviynt entegrasyonlarına sahiptir. Kurumsal ölçekte profesyonel hizmet ve partner ekosistemi sunar | Büyük, hibrit ve çok domainli ortamlar; tam zamanlı SecOps ekibi bulunanlar; en derin oturum izleme ve davranışsal analitik ihtiyacı olanlar |
| BeyondTrust | Endpoint privilege management alanında en güçlüsüdür; Password Safe, Privileged Remote Access ve Endpoint Privilege Management ürünlerini sunar. Uzak ve tedarikçi erişimi ayırt edici özelliğidir ve ölçekte üçüncü taraf erişimi yönetenler için uygundur. Bulut öncelikli teslim ve esnek fiyat sunar | Orta ölçek ve kurumsal; tedarikçi ve yüklenici erişimi ağırlıklı olanlar |
| Delinea | Thycotic ile Centrify'ın birleşmesidir. Secret Server (vault), Privilege Manager (endpoint), Connection Manager (oturum) ve DevOps Secrets Vault ürünlerini sunar. Pazarın en hızlı time-to-value'suna sahiptir; orta ölçekli bir Secret Server kurulumu CyberArk'ın haftalarına karşılık günler içinde çalışır hâle gelir ve arayüzü pratisyenlerce en sezgisel bulunandır | 500-5.000 çalışanlı kurumlar; PAM mühendisliği kapasitesi sınırlı olanlar; tablolardan veya eski parola yöneticilerinden geçenler |
| Saviynt | Bu karşılaştırmadaki en güçlü bulut PAM'idir; AWS, Azure ve GCP'de on-prem vault bileşeni gerektirmeden gerçek agentless keşif ve kontrol sağlar. Mimari bahsi, PAM'in ayrı bir vault ürünü değil IGA ile yakınsanmış bir kimlik platformunun içinde olması gerektiğidir | IGA ve PAM konsolidasyonu isteyenler |
| Teleport | Altyapı erişimi (SSH, K8s, veritabanı) için modern ve sertifika tabanlıdır | Mühendislik ekipleri ve bulut-native ortamlar |
| HashiCorp Vault | Sır yönetimi ve dinamik kimlik bilgileri sunar; klasik PAM değildir | DevOps ve makine kimliği |
| One Identity Safeguard | IGA ile aynı satıcıdan gelir | Konsolidasyon isteyenler |

Venafi (makine kimliği) CyberArk tarafından satın alınmıştır.

**Karar kuralı.** En büyük risk ayrıcalıklı hesap ele geçirmesiyse PAM ile başlanır; en büyük sorun aşırı erişim ve kimde ne olduğu görünürlüğüyse IGA ile başlanır.

### 100. Ulusal dijital kimlik sistemleri

Bir ürün kurarken çoğu zaman bir ulusal eID'ye bağlanmak gerekir; ya kimlik tespiti için ya da doğrudan giriş yöntemi olarak.

Üç farklı kavram sık karıştırılmaktadır. eID kimlik doğrulama ve imzalama için kullanılan genel elektronik kimliktir. mDL, ISO/IEC 18013-5 üzerine kurulu telefon tabanlı ehliyettir ve yüz yüze kullanım ile yaş kontrolü içindir. ePassport ICAO standardında çipli seyahat belgesidir ve sınırlarda kullanılır.

Birçok ülke bunlardan birden fazlasını birlikte işletmektedir. Bir dizin 51 ülkede 86 şema saymaktadır.

Nisan 2026 itibarıyla canlı ulusal dijital kimlik sistemi bulunan ülkeler: Avusturya, Butan, Bosna-Hersek, Brezilya, Çin, Kosta Rika, Çekya, Danimarka, Estonya, Fransa, Yunanistan, Hindistan, Kuveyt, Maldivler, Polonya, Portekiz, Suudi Arabistan, Singapur, Güney Kore, İspanya, BAE ve Vietnam.

| Ülke | Şema | Not |
|---|---|---|
| Hindistan | Aadhaar | Dünyanın en büyüğüdür; 2009'dan beri UIDAI tarafından yürütülür. 12 haneli numara ile biyometrik (parmak izi, iris) ve demografik veri içerir; 2025 itibarıyla 1,3 milyardan fazla kişiyi kapsar. Sübvansiyon dağıtımı, SIM kart ve finansal kapsayıcılığın omurgasıdır. mAadhaar uygulaması dijital sürümüdür |
| Estonya | e-ID | En olgun örnektir; e-imza ve e-devletin temelidir |
| Singapur | Singpass | Devlet ve özel sektör hizmetlerine yaygın erişim sağlar; 2FA zorunludur. Kimlik bilgisi satışı vakaları raporlanmıştır |
| Danimarka | MitID | 2021'de devreye girmiştir; kamu-özel ortaklığıdır |
| Norveç | BankID | Özel bir şirket tarafından işletilir; küresel ölçekte alışılmadık bir modeldir |
| İspanya | MiDNI | Devlet geliştirmesidir |
| Ukrayna | Diia | Mobil önceliklidir ve uluslararası referans gösterilmektedir |
| Brezilya | gov.br | Geniş kapsamlıdır |
| Nijerya | NIN | Afrika'nın en büyüklerindendir |
| ABD | Login.gov, mDL, ePassport | Federal düzeyde parçalıdır; ulusal tek şema yoktur |
| AB | EUDI Wallet | 27 ülkede sınır ötesi çalışacak biçimde tasarlanmıştır (§4 §76) |

**Kritik teknik gerçek.** Ulusal eID'ler çoğunlukla sınır ötesi çalışmaz. eIDAS altında bildirilen AB şemaları AB içinde çalışır, ePassport'lar ICAO standardıyla küreseldir, EUDI Wallet sınır ötesi tasarlanmıştır; ancak çoğu ulusal eID yalnızca yereldir. Çok ülkeli bir ürün tek entegrasyonla çözülemez.

**Mimari eleştiri: ID phone home.** Merkezî sistemlerin yapısal zaafı, kimliğin her kullanımının merkezî bir sunucuya — genelde devlet otoritesi veya devlet onaylı satıcı — loglanması ve raporlanmasıdır. Gizlilik ve gözetim açısından eleştirilmektedir; seçici ifşa (SD-JWT VC) ve cüzdan modeli buna cevap olarak konumlanmaktadır.

**Bağımlılık riski.** 2018 SingHealth ihlali Singpass'i doğrudan içermese de bağlı sistemlerdeki riskin güveni nasıl aşındırdığını göstermiştir. Ulusal bir eID'ye bağlanmak o ekosistemin risklerini de devralmak anlamına gelir.

### 101. Merkeziyetsiz kimlik (DID ve SSI)

**Temel fikir.** Kullanıcı verifiable credential'ları kendi kontrolünde tutar; doğrulayıcı merkezî bir kimlik sağlayıcısına başvurmadan credential'ı kontrol eder. W3C standartları DID (merkezî kayıt gerektirmeden çalışan, küresel benzersiz ve kriptografik olarak doğrulanabilir tanımlayıcı) ve Verifiable Credentials'tır.

**Spec durumu.** DID v1.0 Temmuz 2022'de W3C Recommendation olmuştur. DIDs v1.1 güncellemesi yorum için yayımlanmıştır; yorumlar Nisan 2026'ya kadar alınmaktadır. W3C VC Working Group yedi Recommendation yayımlamıştır. W3C Federated Identity WG'den Digital Credentials API'nin ilk kamuya açık çalışma taslağı çıkmıştır. DIF (Decentralized Identity Foundation) tamamlayıcı spec'ler ve birlikte çalışabilirlik üzerinde çalışmaktadır.

**Benimseme gerçeği.** İstikrarlı ancak gösterişsizdir. Microsoft 2022'de Entra Verified ID'ye DID eklemiştir; Nuggets AI ajan kimlik doğrulama ürününü DID üzerine kurmuştur; Dock ve Vouched kullanmaktadır.

**Platformlar.** Microsoft ION ve Entra Verified ID (DID altyapısı), Spruce ID (açık geliştirici araçları), Dock ve Trinsic (uçtan uca credential platformları), Evernym (regüle sektör gizliliği).

2026'nın asıl benimseme sürükleyicisi teknoloji değil regülasyondur: AB eIDAS 2.0 EUDI Wallet ve ISO 18013-5 mDL'ler; ikisi de OpenID4VC ve seçici ifşa üzerine kuruludur.

**İki kritik netlik.** Merkeziyetsiz kimlik federe SSO'nun (SAML, OIDC) yerini almaz; ayrı bir düzlem ekler. Çoğu ekip issuer olarak değil verifier olarak başlamalıdır.

**Blockchain ilişkisi.** Kişisel bilgi zincire yazılmaz; yalnızca kriptografik hash'ler, proof'lar ve DID'ler tutulur, hassas veri zincir dışında cüzdanda kalır.

**Pazar.** Kuzey Amerika 2025'te %42 pay ile öndedir. Kimlik tipi kırılımında biyometri (parmak izi, yüz, iris) %62, biyometrik olmayan yöntemler (PKI, VC, passwordless) %38'dir.

### 102. Biyometrik algoritma satıcıları

Kimlik tespiti (§4 §85) ve yüz doğrulama satın alınırken altta çalışan algoritmanın kalitesi belirleyicidir.

**Bağımsız kıyaslamalar.** NIST FRTE (Face Recognition Technology Evaluation; eski adıyla FRVT) 1:1 doğrulama ve 1:N tanımlamayı ayrı raporlar. Ayrıca DHS RIVTD ile RIVR ve DHS Biometric Rally bulunur.

**Öne çıkanlar.** NEC en son FRTE 1:N Identification raporunda dünyanın en doğrusudur: 12 milyon kişilik durağan görüntü setinde %0,07 kimlik doğrulama hata oranı elde etmiştir. On ve on iki yıl öncesine ait görüntülerle yapılan iki yaşlanma testinde de birincidir ve NIST'in listelediği sekiz ana 1:N kategorisinin hepsinde ilk ikidedir. Paravision ABD merkezlidir; FRTE, DHS RIVTD ile RIVR ve Biometric Rally'de üst sıralardadır; demografik adaleti (etnik köken, cinsiyet, yaş) vurgular; bulut, mobil ve gömülü için modüler SDK sunar. Idemia kurumsal ve kamu tarafında, AFIS ağırlıklı çalışır. Innovatrics Slovakya merkezlidir; yüz, parmak izi ve multimodal çözümler sunar, ABD pazarında az tanınır ve kamu ile AFIS odaklıdır. SenseTime ve Megvii gibi Çin merkezli sağlayıcılar büyük ölçekli dağıtımlara sahiptir ancak ABD ticaret yaptırımları küresel benimsemeyi kısıtlamaktadır.

**Değerlendirme kriterleri.** Kategori bazında FRTE sıralaması (1:1 ve 1:N farklıdır), demografik hata oranı farkları, canlılık için iBeta Level 1 ve 2, gömülü ve mobil performansı, veri yerleşimi ve gizlilik rejimi ile lisans modeli.

> **Uyarı.** Sıralamalar sık değişmektedir ve kategoriye göre farklı satıcılar öndedir. Bir satıcının NIST'te birinci olduğu iddiası, hangi test, hangi kategori ve hangi tarih olduğu sorulmadan anlamlı değildir.

---

## Kaynaklar

**Standartlar.** IETF RFC 6749, 7522, 7523, 7591, 7592, 7636, 7009, 7662, 8252, 8414, 8417, 8628, 8693, 8705, 8707, 9101, 9106, 9126, 9207, 9396, 9449, 9470, 9700, 9728. OpenID Connect Core, Discovery, CIBA ve RP-Initiated Logout. FAPI 1.0 Part 1-2, FAPI 2.0 Security Profile Final, FAPI 2.0 Message Signing Final. OpenID CAEP 1.0, SSF, CAEP Interoperability Profile 1.0. OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0. W3C WebAuthn L2 ve L3, DID Core. FIDO CTAP, CXF ve CXP. ISO/IEC 18013-5 ve 18013-7. NIST SP 800-63-4 (A, B, C), SP 800-132, SP 800-208, FIPS 140-3. OWASP Password Storage Cheat Sheet. draft-ietf-oauth-first-party-apps-04, draft-ietf-oauth-identity-assertion-authz-grant, draft-ietf-oauth-client-id-metadata-document, draft-parecki-oauth-dpop-device-flow. Matter (CSA), Wi-Fi Easy Connect (DPP), BRSKI, EST, FDO.

**Ürün ve pazar.** Skycloak, StartWithIdentity, Tech-Insider, Nacho (CerberAuth) OpenID Providers Benchmark, CIAM Compass (guptadeepak.com), Duende, Cerbos, SuperTokens, PkgPulse, MakerKit, Security Boulevard, Keycloak sürüm notları ve dokümantasyonu, Authlete, OpenID Foundation sertifikasyon listeleri, Descope, Authgear, Eleken, Userpilot, euleinstitute/CorsoUX.

**Tehdit ve araştırma.** Verizon DBIR 2026, Proofpoint, SpyCloud, KELA, Flashpoint, IBM Cost of a Data Breach 2026, Microsoft Digital Defense Report 2025, Push Security, Huntress, Cisco Talos, Zscaler ThreatLabz, TrustSphere, HackTricks (Play Integrity attestation bypass), FIDO Alliance State of Passkeys 2026, arXiv 2604.23280 ve 2505.19301, Gravitee 2026.

**Yeni nesil.** Model Context Protocol 2026-07-28 spesifikasyonu ve blog, WorkOS, oauth.net Cross-App Access, Keycloak ID-JAG rehberi, MojoAuth (workload identity, PQC, passkey adoption), Aembit, Corbado (DBSC, CXP ve CXF), Chrome for Developers, WICG/dbsc, Google Workspace SSF, Apple WWDC26 App Attest, Talsec, Evertrust, Gataca, Notix, Indicio, Vidos (EUDI), Singapur CSA Securing Agentic AI Addendum, Bitwarden, 1Password, FIDO Alliance.

**Bölüm XV.** decryptiondigest.com (PAM ve IGA karşılaştırmaları, Gartner MQ analizleri), MajorKey Tech, Ciphers Security, Cyber Vendor Guide, Identity Logic Consulting, Regula Forensics (Digital ID by Country), StartWithIdentity (Digital IDs directory, decentralized identity platforms), Comparitech, identity.com, Biometric Update (W3C, DID), W3C DID WG ve VC WG, NEC, Paravision, NIST FRTE.

**Komşu ekosistem.** cside, ShadowDragon, Fraudio, SEON, Dupple, fintechdatabase.eu, İHS Teknoloji (Udentify), SCSoft, Müşavirler Kulübü, Türk Telekom Yetenekler Platformu, JetSMS, BTK, Turkcell Mobil İmza, Appsecsanta, PreEmptive, G2 ve Gartner Peer Insights, DigiCert, SSL.com, Device Authority, Zbotic.

---

# Kısım III — Teknoloji temeli

Bundan sonraki bölümler dil, kütüphane, kripto, doğrulama ve tedarik zinciri kararlarının dayanağını oluşturur.
