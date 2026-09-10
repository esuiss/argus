# 4. Kimlik ve kimlik doğrulama — alan referansı

> `ARGUS.md` §4'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§4 §X` referansları aynı anlamda.


Sektörden bağımsız, uçtan uca referans. Kavramlar, protokoller, yöntemler, tehditler, ürünler, mimari kalıpları, kullanıcı deneyimi, senaryo oyun kitapları, yeni nesil gelişmeler, uyum ve anti-pattern'ler.

**İçindekiler**

| Bölüm | Konu |
|---|---|
| I | Temeller ve kavram haritası (1–4) |
| II | Protokoller ve standartlar (5–14) |
| III | Kimlik doğrulama yöntemleri (15–24) |
| IV | Tehdit modeli (25–28) |
| V | Ürün envanteri (29–37) |
| VI | Mimari kalıpları (38–50) |
| VII | Kullanıcı deneyimi ve dönüşüm (51–56) |
| VIII | Senaryo oyun kitapları (57–68) |
| IX | Yeni nesil (69–78) |
| X | Uyum ve mevzuat (79–84) |
| XI | Komşu ekosistem (85–92) |
| XII | Anti-pattern kataloğu (93) |
| XIII | Seçim rehberi ve olgunluk (94–96) |
| XIV | Bu dokümanın sınırları (97) |
| XV | Kapatılan boşluklar: IGA, PAM, ulusal eID, DID/SSI, biyometrik satıcılar (98–102) |

---

## BÖLÜM I — TEMELLER

### 1. Terminoloji

| Terim | Anlamı | Cevapladığı soru |
|---|---|---|
| **AuthN** | Kimlik doğrulama | "Bu gerçekten o kişi mi?" |
| **AuthZ** | Yetkilendirme | "Bunu yapabilir mi?" |
| **Identity proofing** | Kimlik tespiti | "Bu kişi gerçek dünyada var mı ve bu o mu?" |
| **Federation** | Kimliğin sistemler arası taşınması | "Başka bir IdP'nin doğrulamasına güveniyor muyum?" |
| **Provisioning** | Hesabın yaratılması/güncellenmesi/silinmesi | "İşten ayrılanın erişimi kesildi mi?" |
| **Session** | Doğrulanmış durumun sürdürülmesi | "Her sayfada tekrar giriş yapmasın" |
| **Consent** | Kullanıcının veri/erişim onayı | "Bu uygulamaya hangi izni verdi?" |
| **Entitlement** | Somut hak | "Premium özelliklere erişimi var mı?" |

**Sık karıştırılan üç şey:**
- OAuth bir **yetkilendirme** çerçevesidir, kimlik doğrulama protokolü değildir. OIDC bunun üzerine kimlik katmanı ekler. "OAuth ile giriş yaptım" ifadesi teknik olarak yanlıştır
- Authentication ≠ Identity proofing. Passkey'in kimin olduğunu bilmezsin, sadece kayıt anındaki kişiyle aynı olduğunu bilirsin
- SSO ≠ MFA. Biri kaç kez giriş yapıldığıyla, diğeri her girişte kaç kanıt istendiğiyle ilgili

### 2. Ürün kategorileri

| # | Kategori | Ne yapar | Ne yapmaz | Örnekler |
|---|---|---|---|---|
| 1 | **Tam IdP / IAM platformu** | Kimlik deposu + login UI + protokol + admin konsolu | Ürününe gömülmez | Keycloak, Zitadel, Authentik |
| 2 | **Headless kimlik altyapısı** | API üzerinden kimlik + token | Hazır login ekranı vermez | Ory, Logto, SuperTokens |
| 3 | **Uygulama-içi kütüphane** | Auth'u backend'inin parçası yapar | Diğer uygulamalara SSO vermez | Better Auth, Auth.js |
| 4 | **Yönetilen CIAM (SaaS)** | Her şeyi barındırır | Veri egemenliği ve maliyet kontrolü vermez | Auth0, Clerk, WorkOS |
| 5 | **Protokol motoru** | Sertifikalı OAuth/OIDC mantığı | Kullanıcı deposu, UI vermez | Authlete, Duende, node oidc-provider |
| 6 | **Yetkilendirme motoru** | Erişim kararı | Kimlik doğrulama yapmaz | OpenFGA, SpiceDB, Cerbos |
| 7 | **Workload / ajan kimliği** | İnsan olmayan aktörlerin kimliği | İnsan login'i yapmaz | SPIFFE/SPIRE, Entra Agent ID |

**IAM vs CIAM vs IGA vs PAM vs NHI:**
- **IAM** — çalışan kimliği: dizin, kurumsal SSO, cihaz politikaları
- **CIAM** — müşteri kimliği: kayıt akışı, sosyal login, tüketici ölçeği, dönüşüm oranı
- **IGA** — yönetişim: erişim gözden geçirmeleri, onay akışları, sertifikasyon
- **PAM** — ayrıcalıklı erişim: kasa, oturum kaydı, JIT yükseltme
- **NHI** — insan olmayan kimlikler: servis hesapları, workload'lar, API anahtarları, ajanlar

### 3. Aktör haritası

Auth tasarımı "kullanıcı" tekilinden çıkıp aktörleri ayırmakla başlar:

| Aktör | Örnek | Tipik yöntem |
|---|---|---|
| Son kullanıcı (tüketici) | Uygulama kullanıcısı | Passkey, sosyal login, magic link |
| Son kullanıcı (çalışan) | Kurumsal personel | SSO (SAML/OIDC), phishing-resistant MFA |
| Yönetici / operatör | Admin paneli | MFA zorunlu, PAM, oturum kaydı |
| Destek personeli | Müşteri temsilcisi | Kısıtlı impersonation, tam denetim izi |
| Geliştirici | API tüketicisi | API anahtarı, OAuth client credentials |
| Servis / workload | Mikroservis | mTLS, SPIFFE, client credentials |
| Cihaz | IoT sensörü, TV, kiosk | Sertifika, device flow, provisioning |
| **Ajan** | AI asistanı | Delegasyon zinciri, kısa ömürlü token |
| Anonim / misafir | Kayıtsız ziyaretçi | Oturum kimliği, sonradan yükseltme |
| Üçüncü taraf uygulama | Entegrasyon | OAuth, scope'lu erişim |

### 4. Kimlik veri modeli

Neredeyse her projede aynı hatalar yapılıyor; temel model:

```
users            → id (opak, değişmez), created_at, status
identities       → user_id, provider (password/google/apple/passkey/saml),
                   provider_subject_id, verified_at
credentials      → user_id, type, secret_hash veya public_key, algorithm,
                   created_at, last_used_at
sessions         → user_id, device_id, acr, created_at, expires_at
```

**Kurallar:**
- **Birincil anahtar e-posta olmamalı.** İnsanlar e-posta değiştirir; opak, değişmez bir `user_id` kullan
- **Bir kullanıcı, çok kimlik.** Aynı kişi hem parola hem Google hem passkey ile gelebilir. `identities` tablosu bunu doğal karşılar
- **Algoritma alanını sakla.** Parola hash'inde ve passkey açık anahtarında algoritma tanımlayıcısı yoksa migration bloke olur (§24, §77)
- **E-posta doğrulanmışlığı bir bayrak değil, kimlik başına bir özellik.** Google'dan gelen e-posta doğrulanmış, elle yazılan değil
- **Silme değil, durum.** Hesap silme talebi mevzuat gerektirmedikçe hard delete olmamalı; anonimleştirme + tombstone
- **Çakışma senaryosunu baştan çöz:** Aynı e-postayla önce parola sonra Google ile gelen kullanıcı ne olacak? (§45)

---

## BÖLÜM II — PROTOKOLLER VE STANDARTLAR

### 5. OAuth 2.0 / 2.1

| Grant | RFC | Durum |
|---|---|---|
| Authorization Code + PKCE | 6749 + 7636 | **Varsayılan**, tüm istemci tipleri |
| Refresh Token | 6749 | Standart, rotasyonla |
| Client Credentials | 6749 | Servis-servis |
| Device Authorization Grant | 8628 | TV, CLI, kısıtlı giriş cihazları |
| Token Exchange | 8693 | Delegasyon ve impersonation |
| JWT Bearer | 7523 | Servis-servis assertion |
| SAML Bearer | 7522 | Legacy köprü |
| **Implicit** | 6749 | **Ölü** — OAuth 2.1 kaldırdı |
| **ROPC (password)** | 6749 | **Ölü** — OAuth 2.1 kaldırdı |

**OAuth 2.1:** Yeni protokol değil, güvenli varsayılanların zorunlu hale getirilmesi — PKCE her yerde, implicit ve ROPC yok, redirect URI tam eşleşme, bearer token query string'de taşınmıyor.

**RFC 9700 (Security BCP):** Modern OAuth güvenliğinin referansı; FAPI 2.0 dahil tüm modern profiller bunu takip ediyor.

### 6. OpenID Connect

OAuth üzerine kimlik katmanı: ID Token (JWT), UserInfo endpoint, standart claim'ler, Discovery.

| Uzantı | İşlev |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Dynamic Client Registration (7591/7592) | İstemcinin kendini kaydetmesi — MCP'de deprecate edildi |
| **Client ID Metadata Documents (CIMD)** | DCR'ın yerini alan model; istemci kimliği bir URL'de yayımlanıyor |
| RP-Initiated Logout | Merkezi çıkış |
| Front-/Back-Channel Logout | Oturum senkronizasyonu |
| Session Management | Oturum durumu izleme |
| CIBA | Backchannel kimlik doğrulama (§13) |
| `prompt=create` | Doğrudan kayıt akışı |
| Native SSO | Uygulamalar arası token devri |

### 7. Kurumsal ve legacy protokoller

- **SAML 2.0** — Kurumsal SSO'nun fiili standardı. XML tabanlı, ağır, ama B2B satışta kapı bekçisi. Ory'nin desteklememesi ciddi boşluk
- **LDAP / Active Directory** — Dizin federasyonu
- **Kerberos** — İç ağ, bilet tabanlı
- **SCIM 2.0** — Otomatik provisioning (joiner/mover/leaver). Kurumsal alıcının en sık sorduğu şey. Destekleyenler: Keycloak, WorkOS, Auth0, Entra External ID, Frontegg, Stytch, FusionAuth, Descope, SSOJet. Clerk'te yeni yayılıyor
- **RADIUS** — Ağ erişimi, VPN
- **WS-Federation** — Neredeyse tamamen legacy
- **XACML** — Politika tabanlı yetkilendirmenin eski standardı; yerini modern policy engine'ler aldı

### 8. Güvenlik uzantıları

**PKCE (7636)** — Authorization code interception'ı engeller. `code_verifier` üretilir, hash'i istekte gider, token isteğinde verifier sunulur. Artık tüm akışlarda zorunlu.

**PAR (9126)** — İstek parametreleri önce backchannel'dan gönderilir, `request_uri` alınır. Parametreler tarayıcıdan hiç geçmez.

**RAR (9396)** — Scope string'inin ifade edemediği yapısal yetki talepleri. `authorization_details` nesnesi.

**JAR (9101)** — İsteğin imzalanmış JWT olarak taşınması. **JARM** — yanıtın imzalanması.

**DPoP (9449)** — Uygulama katmanında sender-constrained token. İstemci anahtar çifti üretir, her istekte imzalı proof JWT gönderir; AS açık anahtarın thumbprint'ini token'a bağlar. Çalınan token özel anahtar olmadan kullanılamaz. Nonce mekanizmasıyla replay engelleniyor. Keycloak'ta 26.4'ten beri tam destekli.

**mTLS (8705)** — İstemci kimlik doğrulama ve token'ı sertifikaya bağlama. Güvenli ama üretimde bakımı DPoP'tan zor.

**Resource Indicators (8707)** — Token'ın hangi kaynak sunucusu için geçerli olduğu. Replay'i çözer, consent'i çözmez.

**Step-up Challenge (9470)** — Kaynak sunucusunun daha güçlü doğrulama talep edebilmesi. `acr_values` ve `max_age` ile.

**Token Exchange (8693)** — Token takası; `act` claim'i ile delegasyon/impersonation ayrımı. Ajan mimarilerinin temel taşı.

**Issuer Identification (9207)** — Yanıtta `iss` parametresi; çoklu AS senaryosunda mix-up saldırısını kapatır.

### 9. Kimlik doğrulama assurance çerçeveleri

#### NIST SP 800-63-4 (final, 63-3'ün yerini aldı)

**IAL — kimlik tespiti gücü.** IAL1 yeniden tanımlandı. Uzaktan, gözetimsiz kimlik tespiti (video veya biyometrik) artık IAL2'ye tam yol.

**AAL — kimlik doğrulama gücü:**
- AAL1 — tek faktör
- **AAL2** — iki farklı faktör, replay'e dirençli. Yeni: AAL2 uygulamaları **phishing-resistant bir seçenek sunmak zorunda**. SMS OTP izinli ama önerilmiyor
- **AAL3** — açık anahtar kriptografisiyle sahiplik kanıtı, phishing-resistant authenticator + **dışa aktarılamaz** özel anahtar, açık kullanıcı niyeti, FIPS 140-3. **Senkronize passkey kabul edilmiyor**

**FAL — federasyon:** FAL1 bearer assertion, FAL2 sahiplik kanıtı, FAL3 imzalı assertion + endpoint doğrulama.

**Phishing resistance'ın iki tanınan yöntemi:** channel binding ve verifier name binding.

**Parola rehberi:** Periyodik zorunlu rotasyon (ihlal kanıtı olmadan), karakter tipi zorunlulukları ve güvenlik soruları **yasaklandı**. Parola alanında yapıştırmaya izin verilmeli. Rate limiting zorunlu.

#### eIDAS LoA
Low / Substantial / High. EUDI Wallet High'a hedefleniyor.

### 10. Kripto temelleri

**JWT imzalama:** RS256 (yaygın), ES256 (tercih edilen, daha küçük), EdDSA (modern). HS256 yalnızca tek taraflı senaryoda — asla public client'la paylaşılmaz.

**JWKS rotasyonu:** Yeni anahtar yayımla → eski anahtarı JWKS'te bir süre tut (en uzun token ömrü kadar) → yeniyle imzalamaya başla → eskiyi kaldır. `kid` header'ı zorunlu.

**Yaygın JWT hataları:** `alg: none` kabul etmek, algoritma karıştırma (RS256 imzalı token'ı HS256 olarak doğrulamak), `aud` ve `iss` doğrulamamak, `exp` kontrolü yapmamak, saat kayması toleransı vermemek.

**Kritik uyarı:** `private_key_jwt` üreten istemcide sistem saati yanlışsa client authentication başarısız olur. İstemci sunucunun HTTP `Date` header'ıyla saatini senkronize etmeli — özellikle kullanıcı kontrolündeki cihazlarda.

### 11. FAPI — Financial-grade API

Adı finansal ama **her yüksek değerli API için** tasarlanmış: e-sağlık ve e-devlet de hedef alanlarda.

**FAPI 1.0** — Baseline (Part 1) ve Advanced (Part 2). Açık bankacılık ekosistemlerinin çoğu bunun üzerinde.

**FAPI 2.0 (Final, Şubat 2025)** — RFC 9700 BCP'yi takip eder:
- **Bearer token kabul edilmiyor** — sender-constrained zorunlu (mTLS veya DPoP)
- **Sadece confidential client**
- İstemci kimlik doğrulama sadece mTLS veya `private_key_jwt`; `none` ve `client_secret_basic` yasak
- PAR zorunlu, ROPC reddedilmeli
- Kripto: RSA min 2048 bit, ES256 tercih
- Refresh token rotation olağanüstü durumlar dışında kullanılmamalı

**Pratik sonuç:** Mobil uygulama public client olduğu için FAPI 2.0 ona uygulanamaz — sunucu destekliyor olsa bile. FAPI, üçüncü taraf istemcilerin erişimi için bir profildir.

**Sertifikalı implementasyonlar:** Authlete 3.0, IBM Verify (IAM v11, SaaS), node oidc-provider ≥9.2.0, go-oidc ≥0.11.0, Auth0 Highly Regulated Identity, WSO2 IS 7.1.0, NRI Uni-ID Libra 2.12, Zerobank BaaS, Vouch Server, BCP CAS V6, AUTHRDS. Keycloak 26.4 FAPI 2 final profillerini destekliyor ve conformance suite'ten geçiyor.

### 12. FiPA — First-Party Applications

`draft-ietf-oauth-first-party-apps`, **-04 revizyonu 1 Temmuz 2026**, 2 Ocak 2027'de expire. Yazarlar: Parecki (Okta), Fletcher (Practical Identity), Kasselman (Defakto).

Yeni `authorization_challenge_endpoint`: istemci kullanıcıdan bilgi toplar, POST eder, ya authorization code ya hata kodu alır. Hata kodu ya "daha fazla bilgi iste" ya "tarayıcıya düş" der.

Sonuç: native uygulamalar için **tarayıcısız** OAuth; RFC 8252 redirect artık fallback.

**Kısıtlar:** Yalnızca first-party (AS ve uygulama aynı varlık, kullanıcı da öyle algılıyor). SPA'lar hariç. Yüksek güven derecesi gerektiriyor. Yalnızca redirect'in kullanılabilirlik sorunu yarattığı yerde.

### 13. CIBA

OIDC uzantısı, ayrı grant type. İstemci AS'e "bu isteği son kullanıcı doğrulasın" der; AS kullanıcıyla iletişimi yönetir; tamamlanınca token döner.

**Üç mod:** Poll (istemci sorgular), Ping (AS haber verir, istemci çeker), Push (AS doğrudan gönderir).

**Kullanım:** Kullanıcının işlemi başlatan cihazla etkileşemediği her senaryo — masaüstünde başlayan işlemi telefonda onaylamak, çağrı merkezinde kimlik doğrulamak, kiosk'ta yetki almak.

**Sınır:** CIBA tek başına "ne onaylandığını" bağlamaz; imzalama ve payload bağlama ayrı iş (§48).

### 14. Standart olgunluk özeti

| Katman | Bugünün doğru cevabı |
|---|---|
| Yetkilendirme akışı | Authorization Code + PKCE |
| Token güvenliği | DPoP (public client) veya mTLS (server-server) |
| İstek güvenliği | PAR + (gerekirse) RAR |
| Kimlik doğrulama yöntemi | Passkey birincil, fallback ikincil |
| Kurumsal federasyon | OIDC + SAML + SCIM |
| Oturum devamlılığı | Rotasyonlu refresh + reuse detection |
| Yükseltme | RFC 9470 step-up |
| İptal | SSF/CAEP (§74) |

---

## BÖLÜM III — KİMLİK DOĞRULAMA YÖNTEMLERİ

### 15. Yöntem haritası

| Yöntem | Faktör | Phishing direnci | UX | Maliyet |
|---|---|---|---|---|
| Parola | Bilgi | Yok | Kötü | Düşük |
| SMS OTP | Sahiplik | Yok | Orta | Mesaj başına |
| E-posta OTP / magic link | Sahiplik | Zayıf | İyi | Düşük |
| TOTP (authenticator) | Sahiplik | Yok | Orta | Sıfır |
| Push bildirimi | Sahiplik | Yok (fatigue) | İyi | Altyapı |
| Push + number matching | Sahiplik | Kısmi | İyi | Altyapı |
| **Passkey (senkronize)** | Sahiplik + doğrulama | **Var** | **Çok iyi** | Düşük |
| **Passkey (cihaza bağlı)** | Sahiplik + doğrulama | **Var** | İyi | Düşük |
| **Donanım anahtarı** | Sahiplik | **Var** | Orta | Cihaz başına |
| İstemci sertifikası | Sahiplik | Var | Kötü | PKI |
| Biyometri (cihaz) | Doğrulama | Platforma bağlı | Çok iyi | Sıfır |
| Sosyal login | Federasyon | IdP'ye bağlı | Çok iyi | Sıfır |
| Kurumsal SSO | Federasyon | IdP'ye bağlı | Çok iyi | Entegrasyon |
| Akıllı kart / PIV | Sahiplik | Var | Kötü | Yüksek |

### 16. Parolalar — hâlâ var ve doğru yapılmalı

#### Saklama

OWASP Password Storage Cheat Sheet'in 2026 tavsiyeleri:

**Argon2id (birinci tercih).** Temel parametreler: **t=2, m=19.456 KiB (19 MiB), p=1** — modern bir x86 sunucu çekirdeğinde ~100 ms doğrulama süresi. Bellek fazlaysa ve CPU'dan tasarruf isteniyorsa: **m=47.104 KiB (46 MiB), t=1, p=1**. OWASP birbirine eşdeğer güçte beş parametre seti listeliyor; aralarındaki fark CPU–bellek takası.

**Kritik nokta:** ASIC ve GPU saldırganlarını ezen şey zaman maliyetinden çok **bellek maliyeti**. Kaldırabiliyorsan aralığın yüksek bellek ucuna yaslan.

RFC 9106'nın (Argon2 yazarları) kendi tavsiyeleri farklı ve daha agresif: yüksek bellek t=1, p=4, m=2^21 (2 GiB); düşük bellek t=3, p=4, m=2^16 (64 MiB).

**scrypt (Argon2id yoksa).** Minimum CPU/bellek maliyeti 2^17, blok boyutu 8 (1024 bayt), paralellik 1. 2026'da nadiren doğru seçim — Argon2id scrypt'in yaptığı her şeyi daha iyi yapıyor.

**bcrypt (legacy).** Work factor 10+ (12+ önerilir). **72 baytlık giriş sınırı** — daha uzun parolalar için ön-hash gerekiyor. Bellek-sertliği yok.

**PBKDF2 (yalnızca FIPS-140 zorunluysa).** HMAC-SHA-256 ile 600.000 iterasyon minimum; SHA-512 ile 220.000. Eski kodda dolaşan 10.000 değeri kabul edilemez. GPU saldırılarına karşı dördünün en zayıfı.

**Pepper:** Veri tabanı dışında saklanan ortak gizli değer; salt gibi benzersiz değil paylaşımlı. Tek başına güvenlik özelliği eklemiyor, savunma derinliği katıyor. Hash fonksiyonunu hiçbir şekilde etkilemiyor — üstüne AES-GCM katmanı olarak uygulanıyor.

**Salt:** Her parolaya benzersiz, minimum 16 bayt, kriptografik rastgele.

**Migration:** MD5/SHA-1'den geliyorsan mevcut hash'leri doğrudan dönüştürmeye çalışma — sar (wrap) ve bir sonraki girişte yeniden hash'le. `PasswordNeedsRehash` benzeri bir kontrol her başarılı doğrulamadan sonra çalışmalı.

#### Politika

NIST 800-63-4 sonrası doğru politika:
- Minimum 8 karakter (15+ öneriliyor), maksimum en az 64
- **Karakter tipi zorunluluğu yok**
- **Periyodik zorunlu rotasyon yok** (ihlal kanıtı varsa evet)
- İhlal listesi kontrolü (Have I Been Pwned k-anonymity API'si)
- Unicode ve boşluk kabul
- Yapıştırmaya izin
- **Güvenlik soruları authenticator olarak kullanılamaz**
- Rate limiting zorunlu

### 17. OTP ve magic link

**SMS OTP:** En yaygın, en zayıf. AiTM proxy'ye şeffaf, SIM swap'e açık, teslimat güvenilirliği ülkeye göre değişken, maliyeti mesaj başına. NIST AAL2'de izinli ama önerilmiyor. Bazı ülkelerde (Hindistan, Endonezya) hâlâ pratik zorunluluk.

**E-posta OTP / magic link:** Teslimat spam filtresine bağlı; e-posta hesabı ele geçmişse tamamen açık. Ama evrensel uyumluluk sağlıyor — hâlâ en yaygın dağıtılmış passwordless yöntemi.

**Magic link tuzakları:** Link önizleme botları (Outlook Safe Links, Slack unfurl) linki tıklıyor ve token'ı harcıyor — çözüm: GET yerine onay ekranı, veya tek kullanımlık token yerine kısa ömürlü kod. Farklı cihazda açılma sorunu — çözüm: aynı-cihaz kısıtı veya kod gösterme.

**TOTP:** Ücretsiz, offline çalışır, phishing'e açık. Kurtarma kodları zorunlu eşlikçi.

### 18. Push bildirimi

Kullanıcı deneyimi iyi, ama **MFA fatigue** saldırısına açık: saldırgan onay isteğini bombardıman eder, kullanıcı yorgunlukla onaylar.

**Number matching** bu saldırıyı büyük ölçüde kapatıyor: ekranda gösterilen sayıyı kullanıcının telefonda seçmesi gerekiyor. Yanına işlem bağlamı (nereden, hangi uygulama, hangi işlem) eklenmeli.

Yine de AiTM'e karşı koruma sağlamıyor — proxy başarılı onayı bekleyip sonrasındaki oturumu alıyor.

### 19. Passkey / WebAuthn / FIDO2

**Yapı:** WebAuthn (W3C tarayıcı API'si) + CTAP (authenticator–istemci protokolü, 2.2 güncel hat) = FIDO2.

**Türler:**
| Tür | Saklama | Assurance |
|---|---|---|
| Senkronize passkey | iCloud Keychain, Google Password Manager, 1Password, Bitwarden | AAL2 |
| Cihaza bağlı passkey | Tek cihaz, dışa aktarılamaz | AAL2 üstü |
| Donanım anahtarı | YubiKey, Titan, Nitrokey, SoloKeys, Token2 | AAL3 |

**WebAuthn Level 3:** Temmuz 2026'da W3C Recommendation'a önerildi — şifreleme anahtarı türetme, cross-domain credentials, otomatik liste senkronizasyonu birinci sınıf.

**Kritik mekanizmalar:**
- **Conditional UI (`mediation: conditional`)** — autofill içinde passkey önerisi. Benimseme oranını en çok etkileyen tek şey
- **User Verification (UV)** — platformun kullanıcıyı doğrulaması. **Delegasyon bazı regülasyonlarda kabul edilmiyor** (§83)
- **PRF extension** — passkey'den şifreleme anahtarı türetme; uçtan uca şifreli uygulamalar için
- **Attestation** — authenticator modelini kanıtlama; tüketici senaryolarında genelde kapatılıyor
- **Discoverable credential (resident key)** — kullanıcı adı girmeden giriş

**Benimseme (FIDO Alliance State of Passkeys 2026 — 10 ülke, 11.000 tüketici, 1.400 kurumsal karar verici, Nisan 2026):**
- ~5 milyar aktif passkey
- Farkındalık %90 (önceki yıl %75); yalnızca %7 hiç duymamış
- %75 en az bir hesapta etkinleştirmiş, %49 düzenli kullanıyor
- Kurumların %68'i çalışan girişi için dağıtmış/pilotluyor/yayıyor
- En büyük 100 sitenin ~%48'i destekliyor (2022'nin iki katından fazla)
- **Giriş başarı oranı %93** (klasik yöntemlerde %63)

**Bölgesel:** Japonya passkey benimsemesinde önde (%67), ardından Güney Kore (%62) ve Singapur (%58). Hindistan ve Brezilya magic link ağırlıklı (>%75).

**Gerçeklik kontrolü:** Oluşturma ≠ benimseme. İş gücü login'lerinin %10'undan azı tam passwordless. Sebepler: kapsama eşitsiz (her uygulama WebAuthn konuşmuyor), kurtarma çözülmemiş, hibrit faz yapışkan. Cihaz-farkında yönlendirme olmadan benimseme %5–10'da takılıyor — **orkestrasyon ham protokol desteğinden önemli**.

**Satıcı değerlendirirken doğru soru:** "WebAuthn destekliyor musunuz" değil, "son 12 ayda başlayan müşterilerinizde medyan passkey benimseme oranı ne?"

**Geçiş kalıbı:** Önce passkey sun, parolayı 12–18 ay fallback tut, aktif kullanıcıların ~%60'ı en az bir passkey kaydettiğinde emekliye ayır. 2024–2025'in hatası kullanıcıları benimseme olgunlaşmadan zorlamaktı.

### 20. Passkey taşınabilirliği — CXF / CXP

Kilitlenme korkusu en büyük benimseme engellerindendi; CSV export hassas bilgiyi düz metne döküyordu.

- **CXF** — sağlayıcılar arası aktarım formatı; ZIP içinde JSON, CXP'ye göre şifreli
- **CXP** — Diffie-Hellman + **HPKE** ile uçtan uca şifreli transfer protokolü

**Katkı verenler:** 1Password, Apple, Bitwarden, Dashlane, Enpass, Google, Microsoft, NordPass, Okta, Samsung, SK Telecom, Devolutions.

**Durum:** Apple iOS/macOS 26'da CXF tabanlı aynı-cihaz transferini shipledi ve CXP'yi ilk uygulayan büyük platform oldu. Android 14+ ve Play Services 26.21+ ile import/export destekleniyor (Android'de transfer hedef uygulamadan **import isteği** olarak başlıyor). İleride ehliyet ve pasaport gibi credential'ları da kapsaması öngörülüyor.

### 21. Sosyal login

**Kazanç:** Sektör çalışmalarına göre kayıt dönüşümünü ortalama **%20–35** artırıyor.

**Sağlayıcılar ve uygunluk:**
| Sağlayıcı | Kime uygun |
|---|---|
| Google | Genel, en yüksek kapsama |
| Apple | iOS zorunluluğu (aşağıya bak) |
| Microsoft | B2B, kurumsal |
| GitHub | Geliştirici platformları |
| LinkedIn | B2B, profesyonel ağlar |
| Discord | Oyun, yaratıcı toplulukları (200M+ kullanıcı) |
| Facebook | Düşüşte; veri endişeleri nedeniyle yedek seçenek |
| WeChat, DingTalk, Lark | Çin ve Asya pazarı |
| Kakao, Naver, LINE | Kore, Japonya |
| VK | Rusya |

**App Store kuralı:** iOS'ta başka SSO sağlayıcı sunuyorsan **Apple ile Giriş zorunlu** (2020'den beri).

**Riskler:**
- **Asla zorunlu kılma** — e-posta alternatifi hep olmalı
- Token'ları **backend'de doğrula**; frontend'den gelen token'a asla güvenme. İmza, süre ve `aud` claim'i kontrol et; resmî doğrulama kütüphanesi kullan
- IdP hesabı ele geçerse senin hesabın da gider
- Sağlayıcı politika değiştirirse (Facebook'un yaptığı gibi) kullanıcı tabanın kilitlenir
- **E-posta yeniden kullanımı:** Bazı sağlayıcılar silinen hesabın e-postasını başkasına verebilir; `sub` claim'ini birincil eşleştirme anahtarı yap, e-postayı değil

### 22. Kurumsal SSO

B2B satışın kapı bekçisi. Alıcının sorduğu üçlü: **SAML + SCIM + denetim logları**.

**JIT provisioning:** İlk SSO girişinde hesabın otomatik yaratılması. Hızlı ama kullanıcı silme tarafını çözmez — SCIM onu çözer.

**Domain doğrulama:** Kurumsal alan adının kime ait olduğunun DNS ile kanıtlanması; olmadan bir müşteri başka müşterinin kullanıcılarını çalabilir.

**Break-glass hesabı:** SSO çöktüğünde girecek acil durum hesabı — SSO'dan bağımsız, donanım anahtarıyla korunmuş, kullanımı alarm üretiyor. Kurumsal kurulumda unutulan en kritik detay.

**IdP-initiated vs SP-initiated:** IdP-initiated SAML güvenlik açısından zayıf (replay); mümkünse yalnızca SP-initiated destekle.

### 23. Sertifika ve donanım tabanlı

**İstemci sertifikası (mTLS):** Servisler ve cihazlar için ideal, insanlar için kötü UX. PKI işletme yükü ciddi.

**Akıllı kart / PIV / CAC:** Kamu ve savunmada standart; okuyucu donanımı gerektiriyor.

**Donanım güvenlik anahtarları:** AAL3'ün pratik yolu. FIPS varyantları mevcut. Kayıp senaryosu için en az iki anahtar kaydettirme kuralı.

**Mobil imza / nitelikli elektronik imza:** Operatör tabanlı; hukuki geçerliliği yüksek. Her operatör için ayrı entegrasyon gerekiyor — bir operatörün altyapısı diğerinin hatlarıyla çalışmıyor.

### 24. Post-quantum hazırlık

**Tehdit:** Shor algoritması RSA (2048/4096) ve ECC'yi kırıyor. Bugünkü somut risk **HNDL** (harvest now, decrypt later).

**Öncelik sırası:**
1. **TLS handshake** — hibrit ML-KEM. Her bağlantıyı etkiliyor, HNDL'yi adresliyor
2. **Token imzalama** — ML-DSA'ya geçiş; JWT/SAML PQC standartları IETF'te finalize ediliyor
3. **Kod imzalama** — NSA, **NIST SP 800-208 (LMS/XMSS)** benimsenmesini diğer geçişlerin önünde, hemen öneriyor
4. **Passkey/FIDO2** — FIDO Alliance ve IANA'yı izle

**Bugün yapılacak ucuz iş:** Passkey enrollment şemasında açık anahtarın yanında **algoritma tanımlayıcısı** sakla. Yoksa migration bir şema değişikliği bekliyor — bugün ucuz, migration sırasında pahalı blokaj.

**Donanım:** 2026–2027'de alınan token'larda üreticiden doğrulanmış PQC firmware yolu olmalı; yoksa 2027–2030'da fiziksel değişim planla. HSM üreticileri PQC entegrasyonunu 2025–2026 için hedefliyor.

**Beklenti:** 2027 sonu / 2028 başında ilk tarayıcı + authenticator PQC FIDO2 desteği.

**Ana mesaj:** Geçişten olaysız çıkacak kurumlar kripto çevikliğini 2026'da bir **satın alma gereksinimi** yapanlar olacak.

---

## BÖLÜM IV — TEHDİT MODELİ

### 25. Saldırı yüzeyi

Tasarımın çıkış noktası artık "parola nasıl doğrulanır" değil, **başarılı kimlik doğrulamadan sonra oturumun çalınması**.

#### AiTM — baskın teknik
Saldırgan tarayıcı ile IdP arasında ters proxy çalıştırır; kullanıcı MFA'yı doğru tamamlar, saldırgan sonrasındaki oturum token'ını yakalar. **Push, TOTP ve SMS OTP bu proxy'ye tamamen şeffaf.**

Kit ekosistemi: Evilginx/Evilginx2, Tycoon 2FA (en yüksek hacimli), Rockstar 2FA, EvilProxy, Greatness, Mamba 2FA, Modlishka, Muraena. En yeni kitler AiTM'i **BiTM** (browser-in-the-middle) ile birleştirip kimlik bilgilerini ve MFA kodlarını aktif akış içinde yakalıyor.

#### Infostealer
Tarayıcıdaki parolaları, **oturum cookie'lerini** ve autofill verisini sessizce çekiyor. Saldırgan kendi cihazından, anomali üretmeden giriyor.

Ölçek: 2024'te 17 milyardan fazla tarayıcı cookie'si çalındı. KELA 2024 için 3,9 milyar kimlik bilgisi ve 4,3 milyon enfekte cihaz (Lumma, StealC, RedLine). Flashpoint 2025 ilk yarısında 5,8 milyon cihazdan 1,8 milyar kimlik bilgisi — %800 artış.

#### Device code phishing
Cihaz yetkilendirme akışının kötüye kullanımı. Phishing sayfaları Nisan 2026'ya kadar **37,5 kat**, tespitler **%1.380** arttı.

#### Diğerleri
Credential stuffing, password spraying, MFA fatigue, OAuth consent phishing, **OAuth tedarik zinciri** (SaaS satıcıları ele geçirilip saklı token'larla downstream müşterilere girilmesi), SIM swap, hesap kurtarma suistimali, attestation relay, enumeration (hesap var mı yok mu sızdırma), CSRF, oturum sabitleme (fixation), açık yönlendirme (open redirect), subdomain takeover.

### 26. Rakamlar

- Verizon DBIR 2026: ihlallerin **%62'sinde** insan unsuru
- Proofpoint: kurumların **%67'si** 2025'te en az bir başarılı ATO yaşadı; ele geçirilen hesapların **%59'unda MFA açıktı**
- SpyCloud: 8,6 milyar çalınmış oturum cookie'si; başarılı phishing yıllık **%400** arttı
- IBM Cost of a Data Breach 2026: en pahalı giriş noktası phishing ve ses/SMS varyantları — ortalama **5,29 milyon USD**
- Microsoft Digital Defense Report 2025: modern MFA riski **%99'dan fazla** azaltıyor; ama gözlenen saldırıların **%3'ünden azı** token hırsızlığı ve AiTM gibi ileri kategorilerde
- 2024'te dünya genelinde **8,2 milyardan fazla** hesap kimlik bilgisi ihlallerde açığa çıktı

**Son iki rakam birlikte okunmalı:** MFA çalışıyor ama **atlanıyor**. Saldırı MFA'yı kırmıyor, başarılı bir MFA girişini bekleyip sonrasındaki oturumu alıyor.

### 27. Ele geçirilmiş oturumun imzası

Saldırı, başarısız giriş olarak değil **doğru kimlik doğrulanmış ama yanlış yerden gelen oturum** olarak görünür. Ortak davranışsal imza:

- Kullanıcının yerleşik örüntüsüyle uyumsuz yeni cihaz, ağ veya coğrafyadan devam eden oturum
- Meşru giriş ile devam eden oturum arasında imkânsız seyahat
- Hesapta hiç görülmemiş cihaz veya tarayıcı parmak izi
- Oturumun başında **iletişim bilgisi, kurtarma yöntemi veya alıcı değişikliği**
- Hızla yüksek değerli aksiyona yönelme, kullanıcının normal ritmini bozan davranış

**Düzenleyici ve sektörel beklenti değişti:** Kimlik doğrulama gücü artık yeterli assurance sayılmıyor; başarılı doğrulama **sonrasında** oluşan ele geçirmenin tespiti bekleniyor.

### 28. Savunma matrisi

| Saldırı | Etkili kontrol | Etkisiz kontrol |
|---|---|---|
| Credential stuffing | Rate limit, ihlal listesi kontrolü, MFA | Karmaşıklık kuralları |
| Klasik phishing | Passkey / FIDO2 | SMS OTP, TOTP |
| **AiTM** | Origin-bound passkey, DPoP, DBSC, oturum-içi anomali | Push, TOTP, SMS |
| **Infostealer / cookie hırsızlığı** | DBSC, cihaz bağlı token, kısa oturum | Uzun ömürlü bearer cookie |
| Token hırsızlığı | DPoP, mTLS, rotation + reuse detection | Bearer token |
| SIM swap | Operatör entegrasyonu, değişiklik sonrası kısıt | SMS OTP tek başına |
| MFA fatigue | Number matching, passkey | Basit onay push'u |
| Device code phishing | Akışı kapatma, `application_type` kısıtı | — |
| Kurtarma suistimali | Kimlik tespiti tekrarı, soğuma süresi | Güvenlik soruları |
| Enumeration | Tekdüze hata mesajı ve yanıt süresi | Farklı mesajlar |
| Oturum ele geçirme | SSF/CAEP sürekli değerlendirme | Statik oturum ömrü |
| Consent phishing | Uygulama allowlist'i, scope incelemesi | — |

---

## BÖLÜM V — ÜRÜN ENVANTERİ

### 29. Self-hosted IdP

#### Keycloak
Apache 2.0 · Java/Quarkus · ~26.7 · CNCF incubating · Red Hat · ~35.700 yıldız

**Artı:** Bağımsız benchmark'ta izlenen **44 OIDC özelliğinden 40'ı** (Ory Hydra 26). OIDC, OAuth 2.1, SAML 2.0, LDAP/AD, Kerberos, SCIM, identity brokering, Docker Auth. 26.4 ile FAPI 2 final, DPoP tam destek, passkey login formlarında (conditional + modal UI), SPIFFE/K8s service account ile Federated Client Authentication, çok-AZ dağıtım. CIBA var. ID-JAG deneysel. **2.000 login/sn ve 10.000 token yenileme/sn** referansı. Avusturya BRZ (2M+ vatandaş, 130+ hizmet), CERN. Realm çok kiracılık, FreeMarker temaları, custom Authenticator SPI, OpenFGA köprüsü, lazy migration.

**Eksi:** En ağır seçenek (JVM, min 512 MB, tipik 1–2 GB). Yapılandırma karmaşık. Custom SPI Java gerektiriyor ve her major sürümde kırılma riski. Login akışı tarayıcı formu merkezli. Realm modeli binlerce self-service kiracı için değil. Yetkilendirme kaba taneli. Dokümantasyonda özellik statüleri gecikmeli güncelleniyor.

#### Zitadel
**AGPL-3.0** (core; API/SDK Apache 2.0) · Go · event-sourced · ~v4.17 · ~14.800 yıldız

**Artı:** Gün birinden Organizations çok kiracılığı. Yönetilen bulutta **SOC 2 Type II + ISO 27001:2022** — üç büyük açık kaynak IdP arasında tek. Event sourcing → doğal denetim izi. Modern DX.
**Eksi:** AGPL dağıtım/SaaS senaryosunda bloke edebilir. Küçük topluluk. SAML/legacy derinliği az.

#### Authentik
Açık kaynak (bazı enterprise özellikler kapalı) · Python · PostgreSQL zorunlu
**Artı:** En cilalı admin arayüzü, en pürüzsüz kurulum, forward auth/proxy modu, OIDC+SAML+LDAP+SCIM, esnek flow tasarımcısı.
**Eksi:** İleri özelleştirme Python scripting; genç proje; SDK ekosistemi ve oturum yönetimi derinliği zayıf.

#### Authelia
Apache 2.0 · Go · En hafif forward-auth SSO. Tam IdP değil, CIAM'e uygun değil.

#### FusionAuth
**Açık kaynak değil** (kaynak görünür, ücretsiz self-host) · Java
**Artı:** Self-host/bulut tutarlı özellik seti, API-first, MAU limiti yok, yüksek MAU'da ucuz, SCIM.
**Eksi:** Lisans yanlış anlaşılıyor; bulut ~$37/ay'dan; küçük topluluk.

#### Diğerleri
| Ürün | Stack | Konum |
|---|---|---|
| **Casdoor** | Go+React, Apache 2.0 | En geniş sosyal login (WeChat, DingTalk, Lark) |
| **WSO2 IS** | Java, Apache 2.0 | **FAPI 2.0 Final sertifikalı (7.1.0)**; 250+ müşteride 1M+ kimlik; API Manager entegrasyonu |
| **Gluu** | Java, Apache 2.0 | Destek ~$25K/yıl standart, ~$50K/yıl premium |
| **Apereo CAS** | Java | Eğitim sektörü, çok protokollü |
| **Shibboleth IdP** | Java | Akademik federasyon (eduGAIN), SAML odaklı |
| **FreeIPA** | Python/C | Linux altyapı kimliği (Kerberos+LDAP+CA) |
| **Kanidm** | Rust | Modern, hafif, güvenlik odaklı, genç |
| **OpenIAM** | Java | Yönetişim ve provisioning ağırlıklı |
| **lemonldap-ng** | Perl | Fransız kamu sektörü web SSO |

### 30. Headless kimlik altyapısı

#### Ory
Apache 2.0 · Go · servis başına ~50 MB RAM
**Kratos** (kimlik, kayıt, login, MFA, kurtarma) · **Hydra** (OAuth/OIDC provider) · **Keto** (Zanzibar yetkilendirme) · **Oathkeeper** (identity-aware proxy)

**Artı:** Maksimum esneklik; Kubernetes'e uygun; **OpenAI ChatGPT login akışını Ory üzerinde çalıştırıyor (~900M haftalık aktif kullanıcı)**; Klarna da benimseyenler arasında; bileşenler ayrı alınabiliyor.
**Eksi:** Login UI **hiç yok**; Hydra kimlik yönetmiyor, Kratos ile bileşen sayısı artıyor; protokol kapsamı 44'te 26; **SAML yok**; çok kiracılık en zahmetli; ürün özelliği yazmadan önce ciddi yatırım.

#### Logto
MPL 2.0 · Node/TS · ~12k yıldız — JS ekosisteminin en hızlı büyüyen açık kaynak IdP'si. Temiz SDK, güzel konsol, yerleşik Organizations, WebAuthn passkey, lazy migration. FAPI/DPoP/mTLS derinliği ve kurumsal federasyon yok.

#### SuperTokens
Apache 2.0 · Java core + Node/Python/Go SDK. Standalone IdP değil, **uygulamana gömülüyor**. Self-host ücretsiz sınırsız; bulut 5.000 MAU'ya kadar ücretsiz, sonrası $0,02/MAU. Oturum yönetimi derinliği iyi. Eklentiler ayrı: MFA $0,01/MAU + $100/ay min, account linking $0,005/MAU + $100/ay min, dashboard kullanıcısı $20/ay.

#### Hanko / Stack Auth
Hanko passwordless/passkey odaklı, hazır UI, self-host veya yönetilen; geniş platform değil. Stack Auth "açık kaynak Clerk" — hazır UI bileşenleri, B2B organizasyonlar, Clerk fiyat şoku yaşayanların göç hedefi; çok genç.

### 31. Uygulama-içi kütüphaneler

**Better Auth** — 2024'te çıktı, **Mayıs 2026'da v1.6**, ~100k haftalık indirme. Framework-agnostik (Next.js, SvelteKit, Nuxt, Hono, Express), uçtan uca TS tip güvenliği, eklenti mimarisi, kullanıcılar senin Postgres'inde, birinci sınıf çok kiracılık, 20+ OAuth sağlayıcı, TOTP/e-posta OTP/backup kod, magic link, passkey, phone OTP, Prisma/Drizzle/Kysely adaptörleri, yerleşik rate limiting. Genç, denetim geçmişi kısa, kurumsal federasyon yok.

**Auth.js (NextAuth)** — v5, **~2,5M haftalık indirme**, kategorinin standardı. OAuth odaklı; e-posta/parola zayıf; oturum için DB kurulumu gerekiyor; v4→v5 büyük API değişikliği. Çoğu ekip yeni proje için değil, mevcut projede kaldığı için kullanıyor.

**Lucia** — **Deprecate ediliyor.** Oturum yönetimi araç seti; öğrenme kaynağı olarak değerli, yeni proje için değil.

**node oidc-provider** — **FAPI 2.0 SP Final + Message Signing Final sertifikalı** (≥9.2.0). Node'da sertifikalı AS kurmanın yolu. UI/kullanıcı deposu yok.

**OpenIddict** — .NET; Duende'nin açık kaynak alternatifi, daha çok manuel iş.

**Diğerleri:** Passport.js (modern standartlarda geride), Spring Security (Java'da fiili standart, dik eğri), django-allauth, Devise/Sorcery (Rails), go-oidc (FAPI 2.0 Final sertifikalı ≥0.11.0).

### 32. Yönetilen CIAM

| Ürün | Artı | Eksi |
|---|---|---|
| **Auth0 (Okta)** | 50k MAU altında yenmesi zor; derin federasyon; FedRAMP; Auth0 FGA; Actions; **Highly Regulated Identity FAPI 2.0 Final sertifikalı**; AI Agents (Kas 2025 GA) ve Auth for MCP (May 2026 GA) | 100k MAU üstü fiyat dikleşiyor; Actions lock-in; TCO yüksek |
| **Clerk** | Next.js/React için en hızlı; hazır kaliteli UI; **conditional-UI passkey varsayılan açık**; 50k ücretsiz | Kurumsal CIAM değil (federasyon kuyruğu, Java/.NET, FedRAMP, ISO 27001 eksik/zayıf); SCIM yeni; veri ABD'de; 50k sonrası pahalı |
| **WorkOS** | B2B kurumsal hazırlık için en direkt; **$125/bağlantı** (müşteri sayısıyla ölçekleniyor); olgun SAML+SCIM; self-servis Admin Portal | B2C için değil; çok küçük müşteride pahalı |
| **Stytch** | API-first primitifler, esnek akış, güçlü passwordless orkestrasyon | Görsel soyutlama az; 5 bağlantı üstü SSO ücretli |
| **Descope** | 2026'nın en güçlü görsel akış tasarımcısı (Flows); orkestrasyon lideri; yerel AI ajan kimliği | Passwordless-native değil; kurumsal incumbent değil |
| **Frontegg** | Gömülü B2B self-servis admin portalları | Dar segment |
| **Firebase Auth** | Mobil-öncelikli startup için en hızlı; cömert ücretsiz kademe | Google bağımlılığı; kurumsal özellikler zayıf; taşınabilirlik sınırlı |
| **Supabase Auth** | **RLS yetkilendirmenin ciddi kısmını otomatik çözüyor**; açık kaynak, self-host | Yetkilendirme RLS içinde manuel; tek DB arka ucuna bağlı |
| **MojoAuth** | Passwordless uzmanı, hızlı | Tam CIAM değil |
| **Authress** | Yetkilendirme-öncelikli; yerel ReBAC/FGA, Auth0 FGA ve WorkOS FGA'dan ucuz | Niş |
| **Kinde** | Geliştirici-öncelikli | Genç |
| **SSOJet** | Kurumsal SSO/SCIM broker; testte 42 dakikada çalışan SAML | Dar odak |
| **Okta Workforce** | 7.000+ entegrasyon, adaptif MFA, lifecycle | CIAM değil |
| **Corbado / Passage / Beyond Identity** | Mevcut IdP üstüne passkey orkestrasyonu | Tek katman |

### 33. Hyperscaler

**AWS Cognito** — AWS-native IAM entegrasyonu, **FedRAMP High + PCI Level 1 + HIPAA**, Managed Login'de yerel passkey, **500k MAU üstü birim ekonomisi SaaS rakiplerini yeniyor**. Birinci sınıf Organizations yok (user-pool grupları + claim + Lambda trigger); passkey orkestrasyonu zayıf; AWS dışında DX savunulamaz.

**Microsoft Entra External ID** — **50k MAU ücretsiz**, 100k+ MAU'da Cognito'dan da ucuz; Azure AD B2C'ye göre DX belirgin iyileşmiş; **FedRAMP High kapsamı beş büyük CIAM arasında en güçlüsü**; çok kiracılık Cognito'dan iyi ama WorkOS/Frontegg/Auth0'ın gerisinde. DX kalıcı sürtünme: referans-öncelikli dokümantasyon, Azure-AD terminolojisi, kurumsal-IT konsolu.

**Google Identity Platform** — Firebase Auth'un kurumsal üstü; çok kiracılık ve SAML ekliyor.

**Genel kural:** B2B kiracılık ürünün kendisiyse, login'de tasarruf için hyperscaler seçme.

### 34. Protokol motorları

**Authlete** — Protokol mantığı REST API olarak; uç noktalar sende. FAPI 2.0 SP + Message Signing Final sertifikalı (3.0). Regülatörünün istediği açık bankacılık profili için sertifika. **Polyglot** — uç nokta katmanı Java, Go veya TS olabilir.

**Duende IdentityServer** — ASP.NET Core, **in-process SDK**; protokol mantığı, token üretimi ve depolaması senin altyapında. 2.500+ kuruluş üretimde. v8+ **Financial-Grade Security and Conformance raporu** yapılandırmayı OAuth 2.1 ve FAPI 2.0'a karşı otomatik denetliyor. Kendi tavsiyesi: FAPI 2.0'a mTLS yerine `private_key_jwt` ile başla — mTLS üretimde bakımı zor.

**Curity** — JVM, ticari; CIBA gibi ileri akışlar hazır; finans odaklı.

**Ping Identity / ForgeRock** — Kurumsal incumbent'lar; olgun referans mimariler; büyük kurum ölçeğine göre maliyet.

### 35. Yetkilendirme motorları

**Kavramlar:** **FGA** kullanım kategorisi (ölçekte kaynak başına izin), **ReBAC** model, **Zanzibar** Google'ın 2019 implementasyonu. **PBAC** şemsiye paradigma — yetkilendirme mantığının uygulamadan çıkarılması; ReBAC ve ABAC ikisi de altında.

| Ürün | Model | Lisans | Not |
|---|---|---|---|
| **OpenFGA** | ReBAC | Apache 2.0, CNCF | Auth0/Okta kökenli, satıcı-nötr, stateless, yatay ölçek; Auth0 FGA yönetilen sürüm; Keycloak köprüsü |
| **SpiceDB** | ReBAC | Apache 2.0 | Authzed desteği, zengin araç seti, K8s operator |
| **Ory Keto** | ReBAC | Apache 2.0 | Ory stack'iyle doğal |
| **Cedar / AWS Verified Permissions** | ABAC | Apache 2.0 | Zengin öznitelik karar sürüyorsa |
| **Cerbos** | Policy (PDP) | Apache 2.0 | Çalışma zamanı iş bağlamı; IdP'yi tamamlar |
| **Oso** | Policy DSL | Karma | Uygulama içi |
| **OPA / Rego** | Policy | Apache 2.0 | Altyapı ve K8s'te fiili standart |
| **Casbin** | ACL/RBAC/ABAC | Apache 2.0 | Hafif, çok dilli, kütüphane |
| **Warrant** | ReBAC | — | Merkezi yetkilendirme servisi |
| **Permit.io** | Yönetilen FGA | Ticari | OPA/Cedar üstünde yönetim |

**Performans:** Üretim FGA sorguları **1–10 ms**. Cache ve batch check ile yönetilebilir.
**ReBAC seç:** Kalıtımlı ince taneli izinler, liste operasyonları ("görebildiği tüm belgeler"), yetkilendirme verisini iş mantığından ayırma.
**ABAC seç:** Kararlar ilişkiden çok özniteliklerden sürüyorsa.

### 36. Karşılaştırma tabloları

**Lisans netliği**
| Ürün | Lisans | Dikkat |
|---|---|---|
| Keycloak, Ory, Authelia, WSO2 IS, Gluu CE | Apache 2.0 | Temiz |
| Logto | MPL 2.0 | Zayıf copyleft |
| SuperTokens | Apache 2.0 | Eklentiler ücretli |
| **Zitadel** | **AGPL-3.0** (core) | Dağıtım/SaaS riski |
| **FusionAuth** | **Tescilli** | Açık kaynak **değil** |
| Duende | Ticari | Üretimde lisans anahtarı |

**Fiyat modeli**
| Model | Neyle ölçekleniyor | Kimde |
|---|---|---|
| MAU başına | Toplam kullanıcı | Auth0, Clerk, Entra, Logto, FusionAuth Cloud |
| Bağlantı başına | Kurumsal müşteri sayısı | WorkOS ($125), Stytch (5 sonrası) |
| Self-host | Altyapı + ops | Keycloak, Ory, Authentik, SuperTokens |
| Kademeli + eklenti | Karma | SuperTokens |

1M MAU'da ucuz: Cognito, Entra, FusionAuth, SuperTokens, WorkOS B2B şekli. Ama ucuz "en iyi" değil — altı aylık DX vergisiyle gelen $165'lık fatura, bu çeyrek shipleyen $1.200'lük faturaya kaybedebilir.

### 37. Yap / al

**Sıfırdan IdP yazmak** savunulamaz: token imzalama, JWKS rotasyonu, oturum yönetimi, WebAuthn ceremony'leri, consent, admin API, sertifika uyumu — hepsinin olgun karşılığı var.

**Kendi SAML/SCIM'ini yazmak** ayrıca kötü: sertifika rotasyonu, metadata ayrıştırma, IdP'ye özgü tuhaflıklar, sürekli bakım. Yönetilen broker saatler-günler içinde çalışan bağlantı veriyor (bir vaka: 45 dakikada SAML).

**Hangi ürünü seçersen seç sende kalanlar:** cihaz kaydı ve anahtar yaşam döngüsü, hesap kurtarma akışının ürüne özgü tasarımı, risk sinyalleri ve adaptif doğrulama, doğrulama sonrası oturum izleme, ürüne özgü kullanıcı yaşam döngüsü. **Kullanıcı durum verisini IdP'nin user modeline zorlarsan iki doğruluk kaynağı çıkar.**

---

## BÖLÜM VI — MİMARİ KALIPLARI

### 38. Token sınıfları ve ömürleri

| Tür | Tipik ömür | Not |
|---|---|---|
| Access token | 5–15 dk | Kısa; çalınırsa pencere dar |
| Refresh token | Rotasyonlu | Hareketsizlik + mutlak sınır |
| ID token | Tek kullanımlık | Kimlik iddiası; API'ye gönderilmez |
| Session cookie | Tarayıcı akışları | BFF'te sunucuda kalır |
| API anahtarı | Uzun | Servis-servis; rotasyon planı şart |

**Hareketsizlik:** B2B SaaS 30 gün, mobil 90 gün, hassas bağlamlarda daha kısa. Üstüne mutlak tavan.

### 39. Refresh token rotation ve reuse detection

2026'da pazarlık konusu değil. Her yenilemede yeni token verilir, eski geçersiz olur. Geçersiz token tekrar görülürse **tüm token ailesi** iptal edilir.

Bu, çalınmış token'ı uzun vadeli yetenekten **tespit edilebilir olaya** çevirir: saldırgan kullanır → meşru kullanıcının sonraki yenilemesi çakışır → iki oturum da iptal.

**Rotasyon açıkken** aktif kullanıcı için erişim süresi pratikte sınırsız; kısıt hareketsizlik zaman aşımına kayar.

#### Mobildeki kritik tuzak
Birden fazla ekran aynı anda refresh'i yarıştırdığında biri harcanmış token'ı replay eder, reuse detection tetiklenir, **kullanıcı kendiliğinden atılır** — üstelik meşru rotasyonun ürettiği access token da anında 401 verir.

**Zorunlu koruma:** Aynı anda tek refresh uçuşta; eşzamanlı çağıranlar aynı promise'i bekler ve yenilenmiş token'ı alır. Elle güvenilir şekilde tekrarlanamaz, **testle kapsanmalı**.

### 40. Oturum modeli — platforma göre

| Platform | Kalıp |
|---|---|
| **Web (SSR)** | httpOnly + Secure + SameSite cookie; sunucu tarafı oturum |
| **Web (SPA)** | **BFF deseni** — refresh token tarayıcıya hiç inmez, sunucuda tutulur |
| **Mobil native** | Secure Enclave/Keystore'da token; DPoP ile cihaza bağlı |
| **Masaüstü** | OS keychain; DBSC benzeri cihaz bağlama |
| **CLI** | Device Authorization Grant; token dosya izinleriyle korunur |
| **TV / kiosk** | Device flow; kısa oturum, otomatik çıkış |
| **Tarayıcı eklentisi** | Arka plan servis worker'ında; içerik script'inden izole |

**Cookie öznitelikleri:** `HttpOnly` (XSS), `Secure` (HTTPS), `SameSite=Lax` (varsayılan; `Strict` çok kısıtlayıcı, `None` yalnızca gerçek cross-site ihtiyacında ve `Secure` ile), `__Host-` öneki (subdomain sızıntısına karşı), `Path` ve `Domain` mümkün olduğunca dar.

### 41. Çok cihaz ve oturum yönetimi

Kullanıcıya sunulması gereken: **aktif oturumlar listesi** (cihaz, konum, son kullanım) ve **uzaktan çıkış**. Bu artık temel bir beklenti ve çoğu ihlalde kullanıcının ilk aradığı şey.

Tasarım kararları: kaç eşzamanlı oturum, yeni cihaz girişinde bildirim, oturum başına ayrı iptal mi hepsi mi.

### 42. Cihaz kaydı ve cihaza bağlı anahtarlar

Donanım destekli depo: iOS **Secure Enclave**, Android **Keystore/StrongBox**. Anahtarlar güvenli donanımda üretilir, dışarı çıkmaz.

```
device_id, user_id, public_key, key_type, attested_at,
status (active/suspended/revoked), created_at, last_seen
```

Kullanım alanları: cihaz bağlı oturum, işlem imzalama, "tanıdık cihaz" risk sinyali, MFA hatırlama.

### 43. Cihaz attestation ve sınırları

**iOS App Attest:** Secure Enclave'a bağlı anahtar çifti; **canlı Apple doğrulama API'si yok** — attestation objesi Apple köklerine karşı yerel doğrulanır, açık anahtar saklanır, sonrasında imzalı assertion'lar doğrulanır. Apple tavsiyesi: hesap tabanlı uygulamalarda kullanıcı başına bir anahtar; key ID'ler Keychain'de; uygulama güncellemesinden sağ çıkar ama yeniden kurulum/geri yüklemede kaybolur. Replay için `newSignCount > oldSignCount`.

**Android Play Integrity:** Farklı felsefe — iOS anahtar kalıcılığına, Android **istek başına verdict'e** odaklı. Sinyaller: `PLAY_STORE`, `UNRECOGNIZED_VERSION`, `MEETS_DEVICE_INTEGRITY`, `MEETS_BASIC_INTEGRITY`.

**İki kritik sınır:**

1. **Attestation runtime temizliğini kanıtlamaz.** App Attest anahtarın gerçek olduğunu söyler, ortamın temiz olduğunu değil — jailbreak, hooking, malware tespiti yapmaz. Operasyonel yük ağır: anahtar saklama ve rotasyon, cihaz göçü, fraud assertion'larının yorumu.

2. **Relay saldırıları.** Keystore X.509 attestation zincirini boolean "cihaz bütünlüğü" gibi kullanan uygulamalar savunmasız. OID `1.3.6.1.4.1.11129.2.1.17` leaf anahtarın kabul edilebilir bir TEE/StrongBox tarafından o challenge için üretildiğini kanıtlar, ama **o donanımı kanıtı sunan süreç veya oturumla bağlamaz.** İmza doğrulama, kök pinning, tazelik, revocation, `deviceLocked=true`, `verifiedBootState=Verified` kontrollerinin hepsi temiz bir "oracle" telefondan röle edilmiş kanıtla geçebilir.

**Sonuç:** Attestation bir kapı değil, **risk skoruna giren sinyal**.

### 44. Adaptif kimlik doğrulama ve risk

Girdi sinyalleri: cihaz kimliği ve tanıdıklık, IP/ASN ve itibar, coğrafya ve imkânsız seyahat, günün saati ve kullanıcı ritmi, oturum yaşı, davranışsal biyometri, attestation sonucu, ihlal listesi eşleşmesi, hesap yaşı, yakın zamanlı kurtarma/değişiklik.

Çıktı: **allow / step-up / block** üçlüsü. İkili karar (izin ver / engelle) neredeyse her zaman yanlış — orta katman kullanıcıyı kaybetmeden riski düşürür.

Step-up standart yolu: RFC 9470 challenge + `acr_values`.

### 45. Hesap bağlama ve birleştirme

Neredeyse her üründe çıkan, neredeyse hiç baştan tasarlanmayan problem.

**Senaryolar:**
- Kullanıcı parolayla kaydoldu, sonra aynı e-postayla Google ile geliyor
- İki farklı sosyal sağlayıcı aynı e-postayı döndürüyor
- Kullanıcı e-postasını değiştiriyor ve eskisi başkasına gidiyor
- Aynı kişinin farklı e-postalarla iki hesabı var

**Güvenli kurallar:**
- **E-posta üzerinden otomatik bağlama yalnızca ikisi de doğrulanmışsa.** Aksi halde saldırgan doğrulanmamış e-postayla hesap yaratıp kurbanın sosyal login'ini eline geçirir — klasik "pre-account takeover" saldırısı
- Bağlama işlemi mevcut oturumda **yeniden kimlik doğrulama** istemeli
- Birleştirme geri alınamaz olduğu için açık onay ekranı ve ne olacağının anlatımı
- Sağlayıcı `sub` claim'i birincil eşleştirme anahtarı; e-posta ikincil

### 46. Kurtarma tasarımı

Passkey mimarilerinin gerçek zayıf halkası ve ATO'nun en yoğun yüzeyi.

**Prensipler:**
- **Kurtarma korunan şeyden zayıf olamaz** — aksi halde saldırgan doğrudan oraya gider
- Güvenlik soruları authenticator olarak kullanılamaz (NIST yasaklıyor)
- Kurtarma kodları: tek kullanımlık, kayıt anında gösterilip saklanması istenen, hash'lenmiş
- **Kurtarma sonrası soğuma süresi** — yeni cihaz/yöntem aktif olduktan sonra bir süre yüksek riskli aksiyon kısıtı
- Kurtarma girişimlerinde rate limiting ve bildirim (eski kanala da)
- Yüksek değerli hesaplarda manuel destek yolu ve alternatif doğrulanmış kanal
- Yüksek assurance gereken yerde kurtarma kimlik tespitinin tekrarını gerektirir

### 47. Impersonation ("kullanıcı olarak giriş")

Destek ekibinin ihtiyacı, en çok kötüye kullanılan özellik.

**Doğru tasarım:** Ayrı bir token tipi (`act` claim'i ile gerçek aktör belirtilir), kısıtlı scope (para/veri çıkışı yok), süreli, kullanıcıya bildirim, tam denetim izi, kullanıcı onayı gerektiren eşik. Asla "admin panelinden parola değiştir" ile çözülmez.

### 48. İşlem/aksiyon imzalama

Oturum açmak ile kritik aksiyon yapmak aynı güven seviyesi değil. Genel kalıp:

1. Sunucu aksiyon payload'ını üretir (ne yapılacak + nonce + timestamp)
2. İstemci bunu **ekranda gösterir** (WYSIWYS — What You See Is What You Sign)
3. Kullanıcı ikinci faktörünü sunar
4. Cihaz anahtarı **tam olarak o payload'ı** imzalar
5. Sunucu imzayı doğrular ve aksiyonla karşılaştırır

Payload değişirse imza tutmaz. Kullanım: ödeme onayı, ayrıcalık yükseltme, veri silme, üretim dağıtımı, kritik yapılandırma değişikliği.

### 49. Rate limiting ve kötüye kullanım

**Katmanlar:** IP başına, hesap başına, global, ve bunların kombinasyonu. Dağıtık credential stuffing tek IP limitini deler — hesap başına limit şart.

**Exponential backoff + geçici kilit.** Kalıcı kilit DoS vektörüdür.

**Enumeration önleme:** Kayıt, giriş ve şifre sıfırlamada **tekdüze yanıt** — aynı mesaj, benzer yanıt süresi. "Bu e-posta kayıtlı değil" bilgi sızdırır.

**Kayıt akışı koruması:** NIST 800-63-4 kayıt süreçlerine karşı otomatik saldırıları önleme gereksinimi ekledi. Araçlar: Cloudflare Turnstile, hCaptcha, Arkose Labs, Castle, DataDome.

### 50. Anahtar ve sır yönetimi

- Token imzalama anahtarları nerede: uygulama belleği → KMS → HSM
- FIPS 140-3 gereksinimi var mı
- Rotasyon periyodu; JWKS'te eski anahtarın kalma süresi (en uzun token ömrü kadar)
- Anahtar erişiminin denetim izi
- İstemci sırları: asla repo'da, asla mobil binary'de
- Kripto çevikliği (§24)

Araçlar: HashiCorp Vault, AWS KMS/CloudHSM, Azure Key Vault, GCP KMS, Thales/Entrust HSM.

---

## BÖLÜM VII — KULLANICI DENEYİMİ VE DÖNÜŞÜM

### 51. Kayıt akışı

Araştırmalara göre kullanıcıların **%27'si** formu fazla uzun bulduğu için terk ediyor. Her ekstra alan geri dönmemek üzere çıkma sebebi.

**Kurallar:**
- **Tek zorunlu alanla başla** — genelde e-posta. Kalanını onboarding sırasında topla (progressive profiling)
- Alan sayısını üçe indir
- Parola kurallarını **görünür** yap, girmeden önce
- CTA'yı fayda odaklı yaz ("Ücretsiz başla"), jenerik değil ("Gönder")
- Çok adımlıysa ilerleme göstergesi ("2/3") — tamamlanmayı artırıyor
- Kredi kartsız deneme kayıtları artırıyor; ödemeyi değer görüldükten sonraya bırak
- Ne kazanacağını göster: önizleme, demo, açıklayıcı

**E-posta doğrulama:** Çoğu ürün için kullanıcıyı **hemen içeri al**, doğrulamayı belirli aksiyonlar için (şifre sıfırlama, güvenlik değişikliği, veri paylaşımı) zorunlu kıl. Zorunlu ön doğrulama yalnızca kimlik doğrulamanın hizmetin özü olduğu yerlerde (regüle finans gibi) haklı.

### 52. Giriş akışı

- **Zaten girişliyse giriş ekranını hiç gösterme.** En iyi giriş, giriş istememektir
- İlk girişten sonra oturumu kalıcı kıl veya biyometriyle tek dokunuş yap — ikinci girişte parola yeniden yazdırma
- En yaygın yöntemi öne koy; SSO düğmelerini formun üstüne
- Parola göster (göz ikonu) standart, çıkarmanın sebebi yok
- "Şifremi unuttum" görünür yerde
- Yöntem ne olursa olsun **tutarlı deneyim** — akış ve marka aynı hissettirmeli
- Dönen kullanıcı için e-postayla otomatik giriş linki veya deep link

**2026 önerilen kombinasyon:** kayıtlı cihazda dönen kullanıcı için **passkey birincil**; yeni kullanıcı ve kayıtsız cihaz için **magic link birincil**; herkes için **sosyal login hızlandırıcı alternatif**.

### 53. MFA kayıt deneyimi

- Kayıt anında zorlamak terk ettirir; ilk değerli aksiyondan sonra iste
- Neden gerektiğini bir cümleyle açıkla
- Kurtarma kodlarını **kayıt anında** göster ve saklandığını teyit ettir
- İkinci bir yöntem eklemeyi teşvik et (tek yöntem = kilitlenme)
- Passkey için conditional UI zorunlu; yoksa benimseme yarıya düşer

### 54. Hata mesajları ve karanlık desenler

**İyi hata mesajı:** Ne olduğunu, neden olduğunu ve ne yapması gerektiğini söyler. "Geçersiz kimlik bilgileri" güvenlik için doğru ama tek başına yetersiz — "E-posta veya parola hatalı. Şifreni sıfırlayabilirsin." daha iyi.

**Kaçınılacaklar:** Kayıt sırasında gizli abonelik onayı, çıkışı zorlaştırma, hesap silmeyi gizleme, MFA kapatmayı imkânsızlaştırma, "hesabını sil" yerine "devre dışı bırak" tuzağı.

### 55. Erişilebilirlik

- OTP alanları ekran okuyucuyla çalışmalı; autocomplete ipuçları (`one-time-code`) tanımlı olmalı
- Zaman aşımı uyarısı ve uzatma imkânı (WCAG 2.2.1)
- CAPTCHA alternatifleri (ses, davranışsal)
- Renk tek başına hata göstergesi olamaz
- Klavye ile tam gezinme
- Parola yöneticisi uyumluluğu — `autocomplete` öznitelikleri doğru olmalı

### 56. Uluslararasılaştırma

- **Telefon numarası:** E.164 normalize et; ülke kodu seçimi; bazı ülkelerde numara değişimi çok yaygın
- **İsim:** Tek alan kullan; "ad/soyad" ayrımı birçok kültürde yanlış; uzunluk ve Unicode sınırı koyma
- **E-posta:** Unicode adresler (IDN) ve `+` etiketleri geçerli; aşırı katı regex kullanıcı kaybettirir
- **SMS teslimatı** ülkeye göre çok değişken; alfanumerik gönderici bazı ülkelerde yasak; regülasyon (Türkiye'de İYS gibi) izin yönetimi gerektiriyor
- **Sosyal login sağlayıcıları** bölgeye göre değişir — Çin'de WeChat/DingTalk, Kore'de Kakao/Naver, Japonya'da LINE
- **RTL diller** için form ve akış yönü
- **Tarih/saat** ve zaman dilimi: oturum ömrü mesajları yerel saatte
- **Yasal metinler** (KVKK/GDPR aydınlatma) dil başına ayrı ve versiyonlanmış

---

## BÖLÜM VIII — SENARYO OYUN KİTAPLARI

### 57. B2C tüketici uygulaması

**Öncelik:** Dönüşüm > güvenlik teatrosu. Sürtünme her adımda kullanıcı kaybettirir.

**Kalıp:** Sosyal login + magic link + passkey. Parola opsiyonel. MFA'yı ilk değerli aksiyondan sonra öner, zorlama.
**Ürünler:** Clerk, Logto, Better Auth, Supabase Auth, Firebase Auth.
**Dikkat:** Ölçek büyüdükçe MAU faturası; 100k MAU eşiğinde model değişimini planla.

### 58. B2B SaaS

**Öncelik:** Kurumsal hazırlık. İlk büyük müşteri "SAML var mı?" diye soracak.

**Zorunlu üçlü:** SAML (ve OIDC) + SCIM + denetim logları. Yanına: Organizations/tenant modeli, rol yönetimi, davet akışı, domain doğrulama, **break-glass hesabı**.
**Ürünler:** WorkOS (en hızlı), Auth0, Keycloak (self-host), Zitadel, Frontegg, SSOJet.
**Fiyat notu:** Bağlantı başına model (WorkOS $125) az sayıda büyük müşteride ucuz, çok sayıda küçükte pahalı.
**Yetkilendirme:** Rol tablosuyla başla; ilişki karmaşıklığı çıkınca OpenFGA/SpiceDB'ye taşı.

### 59. E-ticaret

**Öncelik:** Sepet terk oranı. Misafir ödeme (guest checkout) zorunlu; kayıt ödeme sonrasına bırakılmalı.
**Kalıp:** Anonim oturum → sipariş → sipariş sonrası "hesap oluştur" (§67).
**Risk:** Promo suistimali, hesap ele geçirme, kayıtlı kart kullanımı. Fraud motoru (§88) auth'tan ayrı ama bağlı.
**Dikkat:** Kayıtlı ödeme aracı varsa hesap ele geçirme doğrudan para kaybı; adres/e-posta değişikliğinde step-up.

### 60. İç araçlar ve altyapı

**Öncelik:** Basitlik ve tek yerden yönetim.
**Kalıp:** Reverse proxy + forward auth. Uygulamaların kendi login'i olmasın.
**Ürünler:** Authelia (minimal), Authentik (flow + LDAP + SCIM), Keycloak (protokol genişliği gerekiyorsa), Ory Oathkeeper.
**Dikkat:** Break-glass erişimi, admin hesaplarında donanım anahtarı.

### 61. Kurumsal iş gücü (workforce)

**Öncelik:** Yaşam döngüsü ve uyum.
**Kalıp:** Merkezi IdP + SCIM provisioning + koşullu erişim + PAM ayrıcalıklı hesaplar için.
**Ürünler:** Okta, Entra ID, Keycloak, Ping.
**Zorunlu:** Phishing-resistant MFA (özellikle admin), erişim gözden geçirmeleri, ayrılan personelin anında kesilmesi, SSF/CAEP ile oturum iptali.

### 62. Sağlık

**Öncelik:** Hasta gizliliği ve erişim denetimi.
**Uyum:** HIPAA (ABD) 45 CFR 164.312(d) kişi/kurum kimlik doğrulaması gerektiriyor; metodoloji için NIST 800-63 kullanılıyor. Avrupa'da GDPR sağlık verisi özel nitelikli.
**Kalıp:** Rol + ilişki tabanlı yetkilendirme ("bu doktor bu hastanın tedavi ekibinde mi"), acil durum erişimi (break-glass) ve sonrasında zorunlu gerekçelendirme, ayrıntılı erişim logu.
**Dikkat:** Paylaşılan cihazlar (hemşire istasyonu) — hızlı kullanıcı değişimi, kısa otomatik kilit.

### 63. Eğitim

**Öncelik:** Ölçek, federasyon ve yaş.
**Kalıp:** Akademik federasyon (eduGAIN, Shibboleth, SAML), LMS entegrasyonu (LTI), okul hesabıyla SSO.
**Uyum:** FERPA (ABD), COPPA (13 yaş altı — veli onayı, veri toplama kısıtı), GDPR'da çocuk verisi.
**Dikkat:** Öğrenci hesaplarında kurtarma; paylaşılan cihazlar; öğretmen impersonation'ı.

### 64. Kamu ve e-devlet

**Öncelik:** Assurance seviyesi ve erişilebilirlik.
**Kalıp:** Ulusal kimlik entegrasyonu, akıllı kart/PIV, yüksek IAL/AAL, eIDAS LoA High.
**Uyum:** FedRAMP (AAL2/AAL3, ayrıcalıklıda phishing-resistant), OMB M-22-09, eIDAS.
**Dikkat:** Herkes için erişilebilir olmalı — dijital okuryazarlık düşük kullanıcılar, eski cihazlar, yardımcı teknolojiler. Alternatif kanal (şube, telefon) yasal zorunluluk olabilir.

### 65. Oyun

**Öncelik:** Hesap değeri (envanter, ilerleme) ve çoklu platform.
**Kalıp:** Platform hesabı (Steam, PSN, Xbox, Discord) + kendi hesabın bağlama; cihaz/konsol arası devamlılık.
**Risk:** Hesap satışı ve çalınması, bot çiftlikleri, çoklu hesap suistimali, çocuk kullanıcı korumaları.
**Dikkat:** Konsol ve TV'de metin girişi zor — device flow ve QR eşleştirme.

### 66. Medya ve abonelik

**Öncelik:** Paylaşım kontrolü ve çoklu cihaz.
**Kalıp:** Hane/profil modeli, eşzamanlı akış limiti, cihaz kaydı, TV'de device flow.
**Dikkat:** Parola paylaşımı iş modeli sorunu; cihaz/konum bazlı hane tanımı hem teknik hem hukuki bir tercih.

### 67. Anonim → kayıtlı dönüşümü

Çoğu tüketici ürününde en değerli akış.

**Kalıp:** Anonim oturum kimliği ver → kullanıcı değer üretsin (sepet, taslak, ilerleme) → değer görüldükten sonra hesap iste → anonim veriyi yeni hesaba **taşı**.

**Kritik detay:** Taşıma idempotent ve atomik olmalı; yarım kalan geçiş kullanıcının işini kaybettirir. Anonim oturum ömrü uzun olmalı (haftalar).

### 68. IoT ve cihaz kimliği

Headless cihazlar (sensör, sayaç, aktüatör, set-top box) milyonlarca adette ve coğrafi olarak dağınık — elle provisioning ne pratik ne güvenli.

**Yaşam döngüsü:**
1. **Onboarding** — ilk bağlantıda benzersiz kriptografik kimlik ve sertifika verilmesi
2. **Policy enforcement** — cihaz kimliği ve duruşuna göre zero-trust kararlar
3. **Rotation & renewal** — sertifika ve anahtarların süre dolmadan otomatik döndürülmesi
4. **Revocation** — ele geçmiş veya hizmet dışı cihazın güveninin anında kaldırılması

**Zero-touch provisioning kalıbı:** Cihaza üretim aşamasında bir **grup (batch) provisioning sertifikası** yüklenir; ilk açılışta bulut servisine bağlanıp kendine özgü sertifikasını alır. Böylece üretim hattında cihaz başına CSR/CA turu gerekmez.

**Anahtar teknolojiler:**
- **mTLS** — cihaz-bulut kimlik doğrulamasının fiili standardı; her cihaza benzersiz özel anahtar ve sertifika
- **Secure element / TPM** — değişmez cihaz kimliği; anahtar donanımdan çıkmaz
- **Matter (CSA)** — akıllı ev; her üretilen birime bir **DAC** (Device Attestation Certificate), üstünde **PAI/PAA** zinciri. Apple Home, Google Home, Alexa, SmartThings commissioning sırasında doğruluyor
- **Wi-Fi Easy Connect (DPP)** — cihaz etiketindeki QR kodunda cihazın açık anahtarı; Android 10+ ve yeni iOS'ta kamera uygulamasıyla, uygulama kurmadan Wi-Fi provisioning
- **BRSKI / MASA / EST** — ağ katmanında güvenli bootstrap; MUD dosyasıyla cihaz sınıfı bazlı erişim politikası
- **FDO (FIDO Device Onboard)** — cihaz sahipliğinin tedarik zinciri boyunca devri
- **EPID** — grup imzası tabanlı sahiplik transferi

**Saha gerçekleri:** Üretim test jig'i ile firmware flash + eFuse'a benzersiz seri + claim sertifikası enjeksiyonu tipik olarak cihaz başına 30–60 saniye. Ağ çeşitliliği (gizli SSID, WPA2-Enterprise, portal doğrulamalı hotspot, aynı SSID'li çift bant, mobil hotspot) provisioning akışının hepsini karşılaması gereken gerçek kısıt.

**Cihaz kullanıcıya bağlıysa** ayrıca: cihaz–hesap eşleştirme, sahiplik devri (ikinci el), ve cihaz kaybında iptal akışı.

---

## BÖLÜM IX — YENİ NESİL

### 69. Klasik modelin kırılma noktası

OAuth 2.0, OIDC ve SAML **çok spesifik yapısal varsayımlar** kodluyor ve otonom ajanlar bunları inşaları gereği ihlal ediyor:
- **Eşzamanlı bir insan onay olayı** varsayımı
- **Tek sıçramalı delegasyon** varsayımı (bir istemci → bir kaynak sunucusu)

Bir ajan gece 03:00'te, üç servis zinciri üzerinden çalıştığında ikisi de çöküyor. Alan bunu yeni protokol icat ederek değil, mevcut yapı taşlarını yeniden birleştirerek çözüyor.

### 70. Ajan kimliği

**İki yanlış kalıp:** Ajanların **bir insanın kimliğiyle** çalışması (bir şey ters gittiğinde atıf tamamen kayboluyor) veya **paylaşılan servis hesabıyla** çalışması (uzun ömürlü sır, delegasyon zinciri yok, patlama yarıçapı tüm tenant).

**Sektörün cevabı:** Ajan **birinci sınıf non-human identity** — kendi principal'ı, kriptografik olarak attest edilmiş, çalışma zamanında kısa ömürlü, insan token exchange yoluyla **delege eden özne** olarak korunuyor.

**Dört mimari kalıp:** user-delegated (açık onayla kullanıcı olarak), autonomous (kendi kalıcı kimliği), hybrid orchestrated (ajan ajana delege ediyor), scoped impersonation (kullanıcı olarak ama dar scope'ta).

**Protokol yığını:** OAuth 2.1 + PKCE (tarayıcı ajanları) · JWT bearer assertion (servis-servis) · MCP (araç çağırma, delegasyon bağlamı gömülü) · delegasyon zinciri taşıyan imzalı ajan token'ları. Dördü kompoze oluyor. **Ama kategori tek baskın standarda yakınsamadı** — çoğu kurum özel claim'li JWT, bazıları kurumsal PKI'dan mTLS, azınlık bulut yönetilen kimlikleri.

**Mimari test:** "Hangi token formatı" değil — kalıcı ajan kimliği kurumsal **IGA kataloğuna** bağlı mı? "Hangi ajanlar var, sahibi kim, hangi scope'lara izinli" otoriter cevaplanabiliyor mu?

**Görünürlük:** Gravitee 2026 anketinde kurumların yalnızca **%24,4'ü** ajan-ajan iletişimine tam görünürlüğe sahip.

**Düzenleme — Singapur CSA Addendum (Ekim 2025):** Kimlik sahteciliği ve taklidi **T9 tehdidi**. İstenenler: güvenilir **ajan kaydı (registry)**, ajanların **verifiable credentials + kısa ömürlü OAuth/OIDC token** ile doğrulanması, açıkça yetkilendirilmedikçe **ajanlar arası yetki delegasyonunun yasaklanması**. Runtime: scope'lu token, rate limit ve aksiyon sınırı, yüksek riskli işlemde human-in-the-loop, **korelasyon ID'li** loglar. İzleme: karar ve çıktı denetimi, politika ihlali tespiti, prompt injection ve model drift izleme, **kill-switch**. WEF Davos (Ocak 2026) governance çerçevesi: hesap verebilirlik, şeffaflık, insan gözetimi, veri yönetişimi.

**AIMS:** Ajanı sahibine bağlayan **çift kimlik credential'ları**; üç delegasyon akışı (**Agent-Mediate, Owner-Mediate, Server-Mediate**), her biri insana geri giden denetlenebilir zincir.

**Ürünler:** Microsoft Entra Agent ID (OAuth 2.0, MCP, A2A; üçüncü taraf ajanlar sidecar SDK veya workload identity federation ile — **lisans tuzağı:** Agent ID tüm Entra müşterilerine açık ama Entra güvenlik özelliklerini ajanlara genişletmek **Microsoft Agent 365** gerektiriyor); Auth0 for AI Agents (Kas 2025 GA) ve Auth for MCP (May 2026 GA); Descope; A2A protokolü (Linux Foundation — ajanlar auth'unu Agent Card üzerinden ilan ediyor, SPIFFE/mTLS doğal taşıma bağlaması).

### 71. MCP yetkilendirme

Korumalı MCP sunucusu **OAuth 2.1 resource server**, istemci **OAuth 2.1 client**. AS implementasyonu kapsam dışı. STDIO transport için uygulanmamalı — kimlik bilgileri ortamdan.

**2025-06-18'den beri değişmeyen:** Sunucular **PRM (RFC 9728)** yayımlamak zorunda; istemciler AS keşfi için kullanmak zorunda; AS'ler en az bir keşif mekanizması (OAuth AS Metadata veya OIDC Discovery), istemciler ikisini de desteklemeli. İstemciler her token'ı **RFC 8707 resource indicators** ile tek resource server'a bağlamak zorunda.

**2026-07-28 revizyonu — lansmandan beri en büyük değişiklik:**
- **Protokol çekirdeği stateless**; session ve initialization handshake kaldırıldı, üç temel özellik deprecate
- **DCR deprecate**, yerine **Client ID Metadata Documents (CIMD)**; geriye uyumluluk **min 12 ay**
- **RFC 9207 `iss` doğrulaması** (SEP-2468) — AS mix-up açığını kapatıyor; SHOULD'dan MUST'a çıkması bekleniyor
- **`application_type`** DCR'de (SEP-837) — masaüstü/CLI localhost redirect reddi çözülüyor
- List ve read yanıtlarında `ttlMs` ve `cacheScope` (SEP-2549)
- Multi Round-Trip Requests, header tabanlı yönlendirme, extensions çerçevesi

**Ölçek:** Tier 1 SDK'larda ayda **~yarım milyar indirme**; TS ve Python SDK'ları toplamda 1 milyar indirmeyi geçti.

**Sık yapılan yanlış:** RFC 8707 audience binding **replay'i** çözer, **consent'i** çözmez. Per-client consent registry, sağlamlaştırılmış state parametreleri ve katı cookie öznitelikleri hâlâ gerekli.

### 72. Workload identity — SPIFFE / SPIRE

**SVID** iki formda: **X.509-SVID** (SPIFFE ID SAN'da URI, mTLS ile doğrudan) ve **JWT-SVID** (`sub` claim'inde). Format: `spiffe://trust-domain/service`.

**Attestation:** SPIRE kimliği vermeden önce workload'ın iddia ettiği yerde çalıştığını doğruluyor — K8s'te Kubelet'ten pod metadata/namespace/service account, AWS'de EC2 instance identity document, bare-metal'de UID/GID/binary SHA256. **SPIRE Server** güven çıpası: Registration Entry defteri + CA.

**Kısa ömürler:** X.509 SVID onlarca dakika–birkaç saat, JWT SVID birkaç dakika, otomatik yenileme. **Sırrı workload'dan tamamen kaldırıyor.**

**Kritik sınır:** SPIFFE **isim** verir, **izin** vermez. Yerleşik yetkilendirme politikası yok; Istio gibi mesh'ler veya OPA gibi engine'ler üstüne katmanlanıyor. Pratikte ikisi birlikte: SPIFFE altyapı içi kimlik için, OAuth her sınırda karar için.

**WIMSE:** SPIFFE spec seti artık **WIT-SVID** içeriyor — IETF WIMSE Workload Identity Token alt profili, **Incubating**, **proof-of-possession zorunlu, bearer yasak**. 3 Ağustos 2026'da **19 aktif WIMSE draft'ı**, çoğu ajanlarla ilgili.

**Ekosistem:** OpenAI SPIFFE JWT-SVID'lerini workload identity federation subject token'ı olarak kabul ediyor (X.509-SVID değil; token `sub`/`aud`/`exp` yanında `iss`, `iat` ve `kid` taşımalı; JWT-SVID bir OIDC ID token değildir). Keycloak 26.4 SPIFFE/K8s service account token'ıyla Federated Client Authentication destekliyor. **spire-identity-exchange** GitHub Actions/GitLab CI/K8s service account token'larını SPIRE SVID'leriyle takas ediyor (Apache 2.0, deneysel).

### 73. Cross-App Access (XAA / ID-JAG)

`draft-ietf-oauth-identity-assertion-authz-grant`. Kurumsal IdP'nin iki uygulama arasındaki bağlantıyı yönetmesi; kullanıcının manuel onayı yerine **token exchange**. "Identity and Authorization Chaining Across Domains"in üstüne kurulu; domainler arası hareket eden **ID-JAG** token'ının claim'lerini tanımlıyor.

**Değeri:** Uygulamalar birbirleriyle doğrudan güven kurmuyor; tekrarlayan consent prompt'ları ve statik API key'leri ortadan kalkıyor; merkezi IdP kontrolde.

**Durum:** Keycloak'ta **deneysel** (draft-01); dokümantasyon üretimde kullanılmamasını söylüyor. Keycloak zaten Token Exchange (8693) ve JWT Authorization Grant (7523) ile chaining destekliyordu.

### 74. Sürekli erişim değerlendirmesi — SSF / CAEP / RISC

**Problem:** Bir saatlik token verdin; 40. dakikada kullanıcı işten çıkarıldı, cihaz jailbreak oldu veya kimlik bilgisi breach dump'ında çıktı. **OAuth'ta ve OIDC'de bunu relying party'ye söyleyen hiçbir şey yok.**

**Yapı:** **SSF** — Transmitter/Receiver arası asenkron, gizliliği korunmuş güvenlik webhook'ları; RFC 8417 SET'leri taşınıyor. **CAEP** — oturum ve cihaz olayları (`session-revoked`, `credential-change`, `device-compliance-change`). **RISC** — hesap ele geçirme ve kimlik bilgisi ihlali. **Üçü de 2 Eylül 2025'te Final.**

**CAEP Interoperability Profile 1.0 draft-01** (Temmuz 2026) minimum uyumluluk setini ve SSF uç noktalarının OAuth ile yetkilendirilmesini tanımlıyor; implementasyon tüm senaryoları desteklemek zorunda değil.

**Ajanlar için:** Uzun görev yürüten ajan, "token 40 dakika daha geçerli" cevabının tam olarak yanlış olduğu çağrandır. IETF ajan çerçevesi gözlemlenebilirliği **güvenlik kontrolü** yapıyor: sinyal alındığında **attenuate** et — cache'li token'ları düşür, daha sıkı kısıtla yeniden al, policy'yi yeniden çalıştır; geri çekilmiş yetkilendirmeyi kullanmaya **devam etme**.

**Benimseme:** Google Workspace SSF Receiver closed beta (Session Revocation); SailPoint receiver Session Revoked ve Credential Change destekliyor, gelen olayı kimlik bağlamıyla otomatik zenginleştiriyor.

### 75. DBSC — Device Bound Session Credentials

Cookie'lerin temel problemi bearer olmaları; masaüstünde uygulama izolasyonu zayıf, malware tarayıcının erişebildiği her şeye erişiyor.

DBSC oturumu **cihaza bağlı anahtar çiftine** bağlıyor; özel anahtar sistem seviyesinde exfiltrasyona karşı korunuyor. Her oturum benzersiz anahtar çiftiyle — cross-session takip oluşmuyor, kullanıcı temizleyince anahtarlar siliniyor.

**Durum:** **Chrome 146, Nisan 2026'da Windows'ta GA** (Origin Trial bitti). **macOS** desteği Secure Enclave ile yaklaşan sürümde. Diğer tarayıcılar değerlendiriyor. Google'ın yol haritası: federated identity (cross-origin SSO binding), advanced registration (mTLS/donanım anahtarı), güvenli donanımı olmayan cihazlar için yazılım anahtarları.

**SSF ile birleşik mimari:** Güvenlik aracı RISC sinyali → IdP CAEP olayı push ("cihaz ele geçirildi") → sonraki DBSC yenilemesinde sunucu imzayı reddediyor → oturum ölüyor. Infostealer'ın çaldığı cookie'yi işlevsiz bırakan ilk yapısal cevap.

### 76. Dijital kimlik cüzdanları — eIDAS 2.0 / EUDI

| Tarih | Yükümlülük |
|---|---|
| 20 Mayıs 2024 | Regülasyon (EU) 2024/1183 yürürlükte |
| **Q4 / Aralık 2026** | Her üye devlet en az bir sertifikalı EUDI Wallet sunmak zorunda |
| **Aralık 2027** | Bankacılık, sağlık, telekom ve büyük platformlar dahil yükümlü özel sektör Wallet'ı **kabul etmek zorunda** |
| 2030 (hedef) | Vatandaşların %80'i |

**Teknik yığın:** ARF 3.0.0 (Temmuz 2026). Formatlar: **ISO/IEC 18013-5 mDL** ve seçici ifşa için **SD-JWT VC**. Taşıma: **OpenID4VCI** (issuance) + **OpenID4VP** (presentation). Güven modeli eIDAS Trusted Lists.

**Spec olgunluğu:** OpenID4VP 1.0 Final (Tem 2025), OpenID4VCI 1.0 Final (Eyl 2025), **HAIP 1.0 Final** (Ara 2025).

**Format gerçeği:** EUDI SD-JWT VC belirtiyor ama dünya çok formatlı — ehliyetler ISO mDL, QTSP/devlet attestation'ları SD-JWT VC. RP'ler ikisini de desteklemeli. Sphereon Verifier, Entra Verified ID veya Large Scale Pilot açık kaynakları çapraz format veriyor; sıfırdan yazmak mümkün ama gereksiz.

**Modlar:** Same-device (`openid4vp://` şeması) ve cross-device (QR).

**Mevcut yığına etkisi:** EUDI federasyon broker'ını **değiştirmiyor**, üstüne bir VC düzlemi ekliyor. Broker'a bir OpenID4VP verifier uç noktası ekleniyor.

**RP entegrasyon eforu:** Trust framework kaydı 4–6 hafta · OID4VP entegrasyonu 8–12 hafta · Wallet attestation 2–4 hafta · Status list/revocation 2–4 hafta · Sınır ötesi test 4–8 hafta. Ayrıca cüzdan PID'i ile iç kullanıcı kaydı ilişkisi (ilk provisioning, hesap bağlama, attribute yenileme, silme) ve consent/audit güncellemesi.

**Mimari not:** Tek monolit yerine issuance, verification ve userinfo'yu ayrı servisler olarak OAuth/OpenID4VCI/OpenID4VP ile bağlamak öneriliyor.

### 77. Sonraki üç yılın izleme listesi

| Konu | Neden önemli | Ne zaman |
|---|---|---|
| Ajan kimlik standardizasyonu | Kategori henüz yakınsamadı | 2027–2028 |
| FiPA'nın RFC olması | Native login'in standart yolu | 2027 |
| DBSC'nin diğer tarayıcılara yayılması | Cookie hırsızlığına yapısal cevap | 2027 |
| CXP finalizasyonu | Passkey taşınabilirliği tamamlanır | 2026–2027 |
| PQC FIDO2 | Donanım değişim döngüsü | 2027 sonu–2028 |
| EUDI özel sektör yükümlülüğü | AB'de zorunlu kabul | Aralık 2027 |
| WIMSE olgunlaşması | Workload/ajan kimliği standardı | 2027+ |

### 78. Yeni nesil olgunluk

| Teknoloji | Statü | Üretime alınır mı |
|---|---|---|
| SSF / CAEP / RISC | Final (Eyl 2025) | Evet, karşı taraf desteği sınırlı |
| MCP Authorization | Spec 2026-07-28 | Evet |
| CIMD | Draft, MCP'de benimsendi | Kısmen |
| DBSC | Chrome Windows GA | Kısmen — tek tarayıcı |
| OpenID4VP/VCI/HAIP | Final | Evet |
| EUDI Wallet | ARF 3.0.0, deadline Q4 2026 | Pilot |
| CXF / CXP | CXF yayımlandı / CXP devam ediyor | Kısmen / Hayır |
| FiPA | IETF WG draft-04 | Kalıp olarak evet |
| ID-JAG / XAA | draft-01, Keycloak deneysel | Hayır |
| WIMSE / WIT-SVID | Incubating | Hayır |
| Ajan kimlik standartları | Yakınsamamış | Hayır |
| Post-quantum auth | Standartlar oluşuyor | Hazırlık |

---

## BÖLÜM X — UYUM VE MEVZUAT

### 79. Genel omurga

Coğrafyadan bağımsız ortak beklenti: iki bağımsız faktör, işlem/aksiyon bazlı doğrulama, oturum zaman aşımı, denetim izi, en az yetki, veri minimizasyonu.

### 80. Veri koruma — GDPR / KVKK / CCPA

- **Hukuki dayanak:** Kimlik doğrulama verisi genelde sözleşmenin ifası; **biyometrik veri özel nitelikli** ve ayrı açık rıza gerektiriyor
- **Veri minimizasyonu:** Toplamadığın veriyi sızdıramazsın. Doğum tarihi gerçekten gerekli mi?
- **Saklama süresi:** Denetim logları için mevzuat süresi; ötesinde anonimleştirme
- **Silme hakkı:** Hesap silme akışı ve denetim yükümlülüğü çelişebilir — anonimleştirme + tombstone
- **Taşınabilirlik:** Kullanıcı verisinin makine okunabilir dışa aktarımı
- **Veri yerleşimi:** Yönetilen CIAM seçerken kritik — Clerk gibi bazı sağlayıcılar veriyi ABD'de tutuyor
- **Aydınlatma metinleri** dil başına ayrı ve versiyonlanmış; hangi kullanıcının hangi versiyonu onayladığı kayıtlı

### 81. Sektörel

| Çerçeve | Kapsam | Auth gereksinimi |
|---|---|---|
| **PCI DSS 4.0** | Kart verisi | Requirement 8: kart sahibi veri ortamına **tüm erişimlerde MFA** |
| **HIPAA** | ABD sağlık | 45 CFR 164.312(d) kişi/kurum kimlik doğrulaması; metodoloji NIST 800-63 |
| **FERPA / COPPA** | ABD eğitim / 13 yaş altı | Veli onayı, veri toplama kısıtı |
| **FedRAMP** | ABD kamu bulutu | AAL2 veya AAL3; ayrıcalıklıda phishing-resistant MFA |
| **OMB M-22-09** | ABD federal zero trust | Personel, yüklenici ve iş ortaklarına phishing-resistant MFA; uygulama katmanında MFA |
| **SOC 2 / ISO 27001** | Genel güvence | Erişim kontrolü, MFA, erişim gözden geçirmeleri, log |
| **NIS2** | AB kritik altyapı | Çok faktörlü doğrulama ve olay bildirimi |
| **DORA** | AB finans | Operasyonel dayanıklılık, üçüncü taraf risk |
| **eIDAS 2.0** | AB | 2027'de yükümlü sektörlerde EUDI Wallet kabulü |

### 82. PSD2 SCA (Avrupa ödemeleri)

İki bağımsız faktör + **dynamic linking**: her işleme özgü authentication code, ödemenin tutarı ve alıcısıyla birlikte sürecin her adımında taşınıyor; tutar ve alıcı ödeyene açıkça gösteriliyor (**WYSIWYS**); kod veya detaylar değişirse işlem başarısız olmalı. İşlem verisinin gizliliği ve bütünlüğü süreç boyunca korunmalı. CIBA bu akış için standart teslim kanalı.

### 83. Türkiye — ödeme ve elektronik para kuruluşları

Bir örnek olarak: ulusal mevzuatın genel standartların üstüne nasıl ek kısıt getirebildiğini gösteriyor.

**Dayanak:** 6493 sayılı Kanun; Ödeme Hizmetleri Yönetmeliği (1/12/2021); Bilgi Sistemleri Tebliği (1/12/2021); MASAK Genel Tebliği Sıra No: 19.

**Tebliğ md. 10 (GKD):** Birden fazla bileşen; müşteriye özgü ve taklit edilemez bileşenler; oturum güvenliği ve işlemsiz oturumların sonlandırılması.

**Kritik hüküm — platform biyometrisi:**
> Kuruluşun mobil uygulamasının kontrolünde olmayıp **cihaz üreticisi kontrolünde olan parola, PIN ya da biyometrik veriler** güçlü kimlik doğrulama unsurları olarak kullanılamaz.

Bu, WebAuthn'ın **UV'yi platforma delege etme** modeliyle doğrudan çatışıyor — telefonun kendi yüz/parmak izi kilidine dayanmak GKD saymıyor. Gereken kalıp: uygulamanın kendi kontrolündeki PIN + uygulamanın ürettiği anahtar çifti. **Genel ders:** Platform biyometrisine dayanan bir mimari her yargı alanında geçerli değil.

**SMS OTP kısıtı:** Sahiplik bileşeni olarak yalnızca mobil uygulamanın ilk kurulumu, etkinleştirilmesi, yeniden etkinleştirilmesi veya kullanılamaz hale gelmesi durumlarında.

**SIM değişikliği (md. 10/21):** Operatörlerle entegrasyon zorunlu; müşteri teyidi alınmadıkça değişiklikten itibaren **90 gün** SIM tabanlı yöntem kullanılamıyor; aksi halde **ispat yükümlülüğü kuruluşa** geçiyor.

**İşlem doğrulama kodu:** **Müşteriye atanmış şifreleme gizli anahtarı ile imzalanması** esas; mümkün değilse SMS'e düşülüyor.

**Kimlik yerine geçen belgeler (md. 10/16):** Bu belgelerdeki bilgiler ve **anne kızlık soyadı** kimlik doğrulamada kullanılamaz; güvenlik sorusu da bunlardan biri olamaz.

**4 Eylül 2026 değişiklikleri (RG 33360):** Yönetmelik md. 41'e biyometrik yöntemler ve elektronik kimlik doğrulama kabiliyetli belgeler eklendi. Tebliğ tarafında: "kimlik belgesi" tanımlandı; uzaktan kimlik tespiti (md. 22) sıkılaştırıldı (NFC yapılamazsa MASAK Tebliğ 19'daki güvenlik unsurları); canlılık testi ve NFC çip fotoğrafıyla biyometrik karşılaştırma; cihaz ve ortam kontrolü (ışık, gürültü, sinyal); belge orijinallik/bütünlük/yıpranma/tahrif testleri; yabancılara **ICAO 9303 NFC'li pasaport**; md. 10/8'de kimlik belgesinin **kart PIN'i veya biyometrik veri** ile kullanılması ya da **güvenli elektronik imza** halinde GKD karşılanmış sayılıyor.

**Yönetişim:** Md. 22/7 süreç ve doğrulama kriterlerinin **yazılı dokümantasyonu**; md. 22/6 **yılda en az iki kez test**.

**Sermaye piyasası:** SPK VII-128.10 benzer hükümler taşıyor — çok faktörlü doğrulama tanımı, kritik işlemlerde ek adım, SMS öncesi SIM/numara taşıma kontrolü, teyitte iki faktörlü doğrulama esası ve ispat yükümlülüğü.

### 84. Ajanlar için düzenleyici hareket

Singapur CSA Addendum ve WEF çerçevesi §70'te. Bir companion discussion paper ajan kimliği ve delegasyon şemalarını **mimari olarak çözülmemiş bir boşluk** olarak tanımlıyor ve standartlaştırılmış kimlik protokollerini araştırma önceliği ilan ediyor.

---

## BÖLÜM XI — KOMŞU EKOSİSTEM

### 85. Kimlik tespiti (KYC / IDV)

Kimlik doğrulamanın öncesi: kayıt anında kişinin gerçekten iddia ettiği kişi olduğunun tespiti.

**Bileşenler:** Belge yakalama (OCR, pasaportta MRZ) → **NFC çip okuma** (dijital imza doğrulama, MRZ ile karşılaştırma) → yüz eşleştirme (canlı görüntü ile çip/belge fotoğrafı; eşleşme skoru ve eşik) → **canlılık testi** (pasif: doğal boyut ve ışık; aktif: baş çevirme, göz kırpma) → belge bütünlük testleri → cihaz/ortam kontrolü → fraud tespiti (çoklu başvuru, tekrarlanan canlılık başarısızlığı, şüpheli IP) → kesintisiz kayıt.

**Kalite kriterleri:** Yüz tanıma algoritmalarının **NIST** sertifikasyonu; canlılık için **iBeta Level 1 & 2**; hem pasif hem aktif canlılık.

**Sağlayıcılar:** Onfido, Jumio, Sumsub, IDEMIA, Veriff (uluslararası); Türkiye'de İHS Teknoloji (Udentify), SCSoft gibi yerel sağlayıcılar NFC + OCR + yüz + canlılık paketini uçtan uca sunuyor.

### 86. Fraud ve risk motorları

Auth "kim" der; fraud motoru "bu davranış normal mi" der. AiTM sonrası dünyada ikincisi olmadan birincisi yetmiyor.

| Ürün | Odak | Kime | Fiyat |
|---|---|---|---|
| **Sardine** | Fintech/kripto; **davranışsal biyometri** — yazma ritmi, imleç, telefon tutuşu | Fintech, kripto, yüksek risk; fraud+compliance iç içeyse | ~$2K–10K/ay |
| **Feedzai** | Fraud **ve** AML tek platformda (RiskOps), omnichannel, açıklanabilirlik; ~8 trilyon USD/yıl hacim iddiası | Tier-1/2 bankalar | $50K/yıl+, altı haneli yaygın |
| **Sift** | "Digital Trust & Safety" — ödeme, hesap, ATO, içerik suistimali, itiraz | Pazaryerleri, sosyal platformlar, çok vektörlü | ~$30–50K/yıl, $100K+ |
| **SEON** | Dijital ayak izi, cihaz zekâsı, skorlama + AML; **şeffaf fiyat, hızlı kurulum** | Hızlı fintech'ler, orta ölçek | ~$699/ay, 30 gün deneme |
| **Forter** | Ters kurgu: **daha çok iyi müşteriyi onaylamak**; 1,8 milyar kimlikli Identity Graph | Yanlış reddin fraud'dan pahalı olduğu $100M+ GMV perakende | Kurumsal |
| **BioCatch** | Saf davranışsal biyometri | Banka ATO, sosyal mühendislik | Kurumsal |
| **Featurespace** | Kurumsal davranışsal analitik | Bankalar | Kurumsal |
| **Unit21** | Uçtan uca vaka yönetimi, self-servis kural, açıklanabilir AI | Gerçekten soruşturan ekipler | Kurumsal |
| **Hawk:AI / NICE Actimize / DataVisor** | Transaction monitoring, AML, denetimsiz ML | Bankalar, büyük ölçek | Kurumsal |
| **Signifyd / Riskified** | **Garanti modeli** — chargeback'i üstleniyorlar | E-ticaret | Korunan GMV'nin %0,6–1,5'i |
| **Kount** | Klasik e-ticaret | Perakende | $50K/yıl+ |
| **Stripe Radar** | Sıfır entegrasyon | Stripe müşterileri | Standart fiyatta ücretsiz, aksi 5–7¢/işlem |
| **cside** | Tarayıcı katmanı sinyalleri | Sinyal katmanı | ~$99–500/ay |

**Notlar:** Sentetik kimlik, ATO ve para katırı ağları kural tabanlı sistemlerle yakalanamıyor. Kriterler: gerçek zamanlı gecikme, yanlış pozitif, API esnekliği, **açıklanabilirlik**, AML/KYC kapsamı. **Kendi verinle pilot yapmadan sözleşme imzalama.** Toplam maliyet: implementasyon + özel kural + itiraz yönetimi genelde faturayı ikiye katlıyor.

**Yetkili push ödeme (APP) dolandırıcılığı** — kullanıcının kendi onayladığı işlem — kart fraud araçlarının tamamen kaçırdığı vektör; davranışsal araçlar oturumdaki tereddüt ve baskı örüntülerini yakalıyor.

### 87. Mobil sertleştirme (RASP / app shielding)

| Ürün | Yaklaşım | Not |
|---|---|---|
| **Guardsquare (DexGuard/iXGuard)** | Derleyici seviyesi obfuscation | Derin kod koruması; build entegrasyonu gerekli |
| **Promon SHIELD** | Post-compile shielding | **Fintech ve mobil bankacılıkta yoğun**, güçlü vaka çalışmaları |
| **Appdome** | **No-code**, derlenmiş binary üzerinde | SDK gerektirmiyor; fraud, bot, uyumluluğa uzanıyor |
| **Talsec (freeRASP/RASP+/AppiCrypt)** | SDK, freemium | Android, iOS, Flutter, **React Native**, Capacitor, Cordova. Tespit: reverse engineering, root (Magisk), jailbreak (unc0ver, checkra1n, Dopamine), Frida, emülatör, bot, tampering, VPN, malware |
| **Approov** | Dinamik RASP + API attestation | Yalnızca güvenli ortamdaki gerçek uygulamaya geçerli JWT; anlık kayıt/iptal |
| **Verimatrix XTD** | Shielding + telemetri + müdahale | Geniş kapsam |
| **Zimperium MAPS / AppSealing / DexProtector** | Runtime tespit, zero-coding shielding, obfuscation | Alternatifler |

**Karar ekseni:** SDK gömme mi, post-compile/no-code mu, build-time obfuscation mu. Cross-platform (RN, Flutter) desteği ayrı kriter.
**Kural:** Çıktı bir **sinyal**, bloke kararı değil. Rooted cihazı tamamen bloke etmek meşru kullanıcı kaybettirir.

### 88. Bot ve kayıt suistimali koruması

Cloudflare Turnstile, hCaptcha, Arkose Labs, Castle, DataDome. NIST 800-63-4'ün kayıt süreçlerine karşı otomatik saldırı önleme gereksinimini karşılıyor.

### 89. Test ve conformance

- **OpenID Foundation Conformance Suite** — FAPI 1.0/2.0 (DPoP ve nonce dahil), OIDC Core, CIBA. Sertifikasyon buradan geçiyor
- **Keycloak FAPI Playground** — örnek istemci yapılandırmaları, uçtan uca DPoP akışları
- **Duende Financial-Grade Security and Conformance raporu** — yapılandırmayı OAuth 2.1/FAPI 2.0'a karşı otomatik denetliyor
- **Passkeys Debugger / passkeys.eu** — WebAuthn debug ve akış doğrulama
- **Evilginx2 / Modlishka** — AiTM dayanıklılığını kendi ortamında test (kırmızı takım)
- **Yük testi** — Keycloak için 2.000 login/sn, 10.000 yenileme/sn referansları

**Unutulan test senaryoları:** Eşzamanlı refresh yarışı; reuse detection aile iptali; saat kayması ile `private_key_jwt` başarısızlığı; cihaz değişimi sonrası eski cihaz davranışı; kurtarma rate limiti; hesap bağlama çakışması; enumeration'ın yanıt süresinden sızması.

### 90. Gözlemlenebilirlik ve denetim izi

**Kaydedilecekler:** Her doğrulama denemesi (başarılı/başarısız), kullanılan faktörler ve `acr`/`amr`, cihaz kimliği, IP ve ASN, risk skoru ve karar, step-up tetiklenmesi, aksiyon imzası doğrulaması, yetki değişiklikleri, cihaz kaydı/iptali, kurtarma girişimleri, oturum iptalleri, consent verme/geri alma.

**Kurallar:** Append-only; mevzuata göre saklama; **korelasyon ID'si** (tek kullanıcı yolculuğunun tüm servislerdeki izi — ajan senaryolarında denetlenebilirliğin ön şartı ve en ucuz kalem); kayıtlarda **kimlik bilgisi, token veya PIN asla** görünmemeli; SIEM'e gerçek zamanlı akış.

### 91. TCO modelleme

| Kalem | Self-hosted | Yönetilen |
|---|---|---|
| Lisans/abonelik | 0 (veya destek) | MAU veya bağlantı |
| Altyapı | Sunucu, DB, HA, yedek | Dahil |
| Ops iş gücü | Yükseltme, izleme, nöbet | Minimal |
| Entegrasyon | SDK, tema, akış | SDK |
| Özelleştirme | SPI/eklenti + bakım | Actions/Hooks (lock-in) |
| Uyumluluk | Denetim, kanıt üretimi | Kısmen dahil |
| Göç riski | Düşük | Yüksek |

**Eşikler:** 100k MAU yönetilenin acımaya başladığı yer; 500k+ MAU'da self-host/hyperscaler ekonomisi kazanıyor.

### 92. Göç oyun kitabı

**Temel kısıt:** Yönetilen platformlardan **parola hash'leri dışa aktarılamıyor**.

**Lazy migration (trickle):** Eski sisteme gelen login'i araya girip şeffaf taşıma. Auth0'da özellik olarak var; Logto ve Keycloak genişletilebilir authenticator'larla aynı kalıbı destekliyor.
**Bulk import:** Hash formatı uyumluysa (bcrypt, argon2) mümkün.
**Süre:** SDK yeniden yazımı ve hook/Actions göçüyle her iki yönde **60–90 gün**.

**Taşınması unutulanlar:** MFA kayıtları (TOTP secret'ları; **passkey'ler origin'e bağlı olduğu için domain değişirse taşınamaz**), oturumlar (kullanıcılar bir kez atılır), consent kayıtları, denetim geçmişi, özel claim mapping'leri, harici IdP bağlantıları.

---

## BÖLÜM XII — ANTI-PATTERN KATALOĞU

### 93. Yapılmaması gerekenler

**Kimlik ve veri modeli**
- E-postayı birincil anahtar yapmak
- Tek kimlik sağlayıcı varsayıp `identities` tablosunu atlamak
- Parola hash'inde algoritma tanımlayıcısı saklamamak
- Doğrulanmamış e-posta üzerinden otomatik hesap bağlama (**pre-account takeover**)

**Kimlik doğrulama**
- Kendi kripto veya kendi IdP'sini yazmak
- SHA-256 gibi hızlı hash'lerle parola saklamak
- Güvenlik sorularını authenticator olarak kullanmak
- SMS OTP'yi tek MFA seçeneği yapmak
- Periyodik zorunlu parola rotasyonu
- Parola alanında yapıştırmayı engellemek
- Karakter tipi zorunlulukları
- Parola uzunluğuna düşük üst sınır koymak

**Token ve oturum**
- Bearer token'ı sender-constrained yapmadan uzun ömürlü vermek
- Refresh token rotation'ı reuse detection olmadan kurmak
- Mobilde eşzamanlı refresh korumasını atlamak
- SPA'da refresh token'ı localStorage'da tutmak
- JWT'de `alg: none` veya algoritma karıştırmasına açık doğrulama
- `aud` ve `iss` doğrulamamak
- JWT'yi iptal edilebilir sanmak (stateless token iptal edilemez; kısa ömür + iptal listesi gerekir)
- Oturumu yalnızca zaman aşımıyla yönetip iptal mekanizması koymamak

**Yetkilendirme**
- Yetki kararlarını frontend'de vermek
- Rolü token'a gömüp hiç tazelememek
- IDOR: kaynak sahipliğini kontrol etmemek
- Admin panelini yalnızca "gizli URL" ile korumak

**UX**
- Kayıtta 8 alan istemek
- E-posta doğrulamasını ürüne girmeden zorunlu kılmak (regülasyon gerektirmiyorsa)
- MFA'yı kayıt anında zorlamak
- Kurtarma kodlarını göstermemek
- Enumeration sızdıran hata mesajları
- Sosyal login'i zorunlu kılmak
- Aktif oturum listesi ve uzaktan çıkış sunmamak

**Operasyon**
- İstemci sırrını mobil binary'ye veya repo'ya koymak
- JWKS rotasyon planı olmaması
- Break-glass hesabı olmaması
- Attestation'ı boolean kapı gibi kullanmak (**relay saldırısı**)
- Denetim loglarına token veya PIN yazmak
- Impersonation'ı denetim izi olmadan vermek
- Rate limiting'i yalnızca IP bazlı kurmak

---

## BÖLÜM XIII — SEÇİM REHBERİ

### 94. Karar eksenleri (etki sırasına göre)

1. **Aktörler kim?** Tüketici, çalışan, servis, cihaz, ajan — her biri farklı çözüm istiyor
2. **Üçüncü taraf istemci olacak mı?** Olacaksa gerçek AS ve muhtemelen FAPI
3. **Kurumsal federasyon gerekiyor mu?** SAML + SCIM gerekiyorsa Ory eleniyor
4. **B2C mi B2B mi?** B2B ise Organizations birinci sınıf olmalı
5. **Regülasyon var mı?** Sağlık, finans, kamu genelde self-hosted zorunlu kılıyor
6. **Ölçek ve fiyat modeli.** MAU vs bağlantı bazlı; 100k MAU eşiği
7. **Ops kapasitesi.** Doğru soru "zor mu" değil, hangi topolojiye ihtiyacın olduğu
8. **Lisans.** AGPL (Zitadel core) dağıtımda bloke edebilir; FusionAuth açık kaynak değil
9. **Mobil ana akış mı?** Tarayıcı redirect'i olmayan bir kalıp gerekiyor
10. **Göç maliyeti.** Hash taşınmaz; lazy migration; 60–90 gün
11. **Kripto çevikliği.** PQC'yi satın alma gereksinimi yaz

### 95. Hızlı yönlendirme

| Durum | Bakılacak |
|---|---|
| Protokol genişliği + olgunluk, ops var | Keycloak |
| B2B çok kiracılık, AGPL sorun değil | Zitadel |
| Apache lisanslı çok kiracılık | Keycloak Organizations |
| Kendi auth UI'ı, ölçek hedefi | Ory Hydra + Kratos |
| Reverse proxy arkası iç uygulamalar | Authelia (minimal) / Authentik (flow+LDAP+SCIM) |
| Tüketici uygulaması, auth gömülü | SuperTokens |
| JS/TS, hızlı ürün | Logto veya Better Auth |
| Next.js/React, <100k MAU | Clerk |
| B2B kurumsal SSO hızlı | WorkOS |
| Kurumsal genişlik + FGA, bütçe var | Auth0 |
| AWS-native, yüksek MAU | Cognito |
| Microsoft-native, FedRAMP | Entra External ID |
| Supabase üzerindesin | Supabase Auth + RLS |
| En geniş sosyal login (Asya) | Casdoor |
| FAPI sertifikası gerekli | Authlete, WSO2 IS, Curity |
| .NET, in-process token server | Duende IdentityServer |
| Node'da sertifikalı AS | node oidc-provider |
| Akademik federasyon | Shibboleth, CAS |
| İnce taneli yetkilendirme | OpenFGA veya SpiceDB |
| Çalışma zamanı bağlamlı karar | Cerbos |
| Workload / ajan kimliği | SPIFFE/SPIRE + OAuth |
| IoT filo | mTLS + PKI (DigiCert, SSL.com) + zero-touch provisioning |

### 96. Standart olgunluk özeti

| Teknoloji | Statü | Üretime alınır mı |
|---|---|---|
| OAuth 2.1 + PKCE | Konsolide | Evet |
| DPoP | RFC, yaygın | Evet |
| PAR / RAR / JAR / JARM | RFC | Evet |
| Token Exchange | RFC | Evet |
| Step-up (9470) | RFC | Evet |
| FAPI 1.0 / 2.0 | Final, sertifikalı | Evet (2.0 confidential client) |
| CIBA | Final | Evet |
| WebAuthn L2 / passkey | Yaygın | Evet |
| WebAuthn L3 | W3C Rec'e önerildi | Kısmen |
| SCIM 2.0 | Olgun | Evet |
| Argon2id (RFC 9106) | Standart | Evet |
| Yeni nesil | §78 | — |

---

## BÖLÜM XIV — SINIRLAR

### 97. Bu dokümanın kapsamadıkları

"Hiçbir eksiği olmayan" bir auth dokümanı mümkün değil; alan haftalık değişiyor.

**Hızla eskiyecekler:** FiPA ve ID-JAG draft statüleri, MCP revizyonları, ürün sürüm özellikleri, DBSC tarayıcı desteği, EUDI ARF sürümü, **tüm fiyat rakamları**. 3–6 ayda kayabilir.

**Kaynak kalitesi:** Ürün karşılaştırmalarının çoğu satıcı bloglarından geliyor ve taraflı — bazıları açıkça çıkar beyanı yapıyor (yönetilen Keycloak satan bir firma, kendi ürününü karşılaştıran bir satıcı, rakiplerini yazan bir CIAM). Lisans ve sürüm gibi doğrulanabilir olgular çapraz teyit edildi; "en iyi" türü yargılar edilmedi.

**Rakamlar:** Benimseme ve tehdit istatistikleri satıcı raporlarından ve metodolojileri farklı. Yön göstergesi, kesin ölçüm değil.

**Bu sürümde kapatılanlar:** IGA, PAM, ulusal eID şemaları, merkeziyetsiz kimlik ve biyometrik algoritma satıcıları artık Bölüm XV'te.

**Hâlâ araştırılmayanlar:** Ülke bazlı eID entegrasyonlarının teknik detayı (her şemanın kendi SDK'sı, sözleşme süreci ve test ortamı var — tek tek incelenmesi gerekir); kripto varlık hizmet sağlayıcı mevzuatı; sektöre özgü kimlik federasyonları (havacılık IATA One ID, denizcilik, sağlık HL7/SMART on FHIR); eski protokollerin (NTLM, RADIUS) modern ortamda konumu; kimlik doğrulama alanındaki akademik literatür (formal güvenlik analizleri).

**Hukuki uyarı:** Mevzuat bölümleri metni aktarır, **hukuki görüş vermez**. Yorumlar hukuk danışmanıyla doğrulanmalı; sağlayıcı servis detayları (fiyat, kapsam, SLA) doğrudan sağlayıcıdan teyit edilmeli.

---

## BÖLÜM XV — KAPATILAN BOŞLUKLAR

Önceki sürümde "araştırılmadı" diye işaretlediğim beş alan.

### 98. IGA — Identity Governance & Administration

IGA "kim neye erişebilmeli" sorusunun yönetişimi: erişim sertifikasyonları, yaşam döngüsü otomasyonu, rol yönetimi, görevler ayrılığı (SoD), uyum raporlaması.

**IGA vs PAM ayrımı:** IGA **kimin** ayrıcalıklı erişimi olması gerektiğini yönetir (rol politikaları, onay akışları); PAM o erişimin **nasıl kullanıldığını** yönetir (vault, oturum kaydı, JIT). Entegrasyon standart kalıp: IGA yaşam döngüsü olaylarına göre ayrıcalıklı hesaplar PAM vault'unda açılıp kapanıyor.

| Ürün | Konum |
|---|---|
| **SailPoint** | Kurulu tabanla pazar lideri. Erişim sertifikasyonları, yaşam döngüsü otomasyonu, rol yönetimi, uyum. Binlerce uygulamayı kapsayan geniş konnektör kütüphanesi, AI destekli erişim önerileri ve rol madenciliği. IdentityIQ (on-prem) → Identity Security Cloud (SaaS) göçü karmaşık on-prem kurulumlarda özellik boşlukları yarattı. **En iyi:** pazar lideri yetenek ve geniş konnektör isteyen büyük kurumlar |
| **Saviynt** | Bulut-native (on-prem kod tabanından uyarlanmamış). **Yakınsanmış IGA + PAM + AAG** satıcı dağınıklığını azaltıyor. SAP, Oracle ve Salesforce uygulama yönetişiminde özellikle güçlü — **işlem seviyesinde SoD**: rol veya yetki seviyesinde değil, fonksiyon kodu ve işlem seviyesinde çakışma yakalıyor (SOX için kritik). JIT erişim 2025'te üretimde. Gartner Peer Insights Customers' Choice beş yıl üst üste, 2026'da 249 doğrulanmış incelemeyle 4,8/5. SailPoint'ten düşük TCO. **Zayıf:** PAM bileşeni "PAM-lite" — derin oturum kaydı ve vaulting gerekiyorsa CyberArk/BeyondTrust yerini tutmaz; SI partner ekosistemi küçük; konnektör kütüphanesi daha dar; sık sürüm çıkışı büyük kurumlarda rahatsız edici; özel sermaye sahipliği (Carrick Capital) yol haritası endişesi yaratıyor |
| **Omada** | Avrupa merkezli, orta-büyük kurum; SaaS |
| **One Identity** | **Safeguard (PAM) + Identity Manager (IGA)** tek satıcıdan — satın alma ve raporlamayı basitleştiriyor, ama her bileşen best-of-breed kadar derin değil |
| **Microsoft Entra ID Governance** | Microsoft ekosisteminde doğal |
| **Okta Identity Governance** | Okta üzerindeyse |

**İlk yıl en yüksek getirili kullanım:** çalışan kimlik yaşam döngüsünün otomasyonu.

**İlgili uyum:** SOX Bölüm 404 iç kontrol değerlendirmesi ITGC'yi kapsıyor — erişim sertifikasyonları buradan geliyor.

### 99. PAM — Privileged Access Management

Ayrıcalıklı hesapların, kimlik bilgilerinin ve oturumların nasıl yaratıldığını, saklandığını, kullanıldığını ve izlendiğini yöneten kontrol kategorisi. Kapsam: admin hesapları, servis hesapları, paylaşılan root kimlik bilgileri, acil durum (break-glass) hesapları. Yetenekler: şifreli vault, **JIT erişim**, oturum kaydı, denetim izi.

Gartner MQ for PAM 2025'te birincil liderler: **CyberArk, BeyondTrust, Delinea**; Saviynt bulut-native ve SaaS PAM'de tanınıyor.

| Ürün | Güçlü yön | Kime |
|---|---|---|
| **CyberArk** | Kategori kurulduğundan beri her MQ'da lider. **Digital Vault** mimarisi — kimlik bilgileri yalnızca Vault API üzerinden erişilebilen izole sunucuda; pazardaki en savunulabilir depolama modeli. En derin kimlik bilgisi rotasyon kapsamı, en geniş sistem tipi desteği, en ayrıntılı CEF/LEEF loglaması, en derin SailPoint/Saviynt entegrasyonları. Kurumsal ölçekte profesyonel hizmet ve partner ekosistemi | Büyük, hibrit, çok domainli ortamlar; tam zamanlı SecOps ekibi; en derin oturum izleme ve davranışsal analitik ihtiyacı |
| **BeyondTrust** | **Endpoint privilege management'ta en güçlü**; Password Safe, Privileged Remote Access, Endpoint Privilege Management. **Uzak ve tedarikçi erişimi** ayırt edici — ölçekte üçüncü taraf erişimi yönetenler için. Bulut-öncelikli teslim ve esnek fiyat | Orta ölçek ve kurumsal; tedarikçi/yüklenici erişimi ağırlıklı |
| **Delinea** | Thycotic + Centrify birleşmesi. Secret Server (vault), Privilege Manager (endpoint), Connection Manager (oturum), DevOps Secrets Vault. **Pazarın en hızlı time-to-value'su** — orta ölçekli bir Secret Server kurulumu CyberArk'ın haftalarına karşılık günlerde çalışır hale geliyor; UI pratisyenlerce en sezgisel bulunan | 500–5.000 çalışanlı kurumlar; PAM mühendisliği kapasitesi sınırlı olanlar; tablolardan veya eski parola yöneticilerinden geçiş |
| **Saviynt** | Bu karşılaştırmadaki **en güçlü bulut PAM** — AWS, Azure, GCP'de on-prem vault bileşeni gerektirmeden gerçek agentless keşif ve kontrol. Mimari bahis: PAM ayrı bir vault ürünü değil, IGA ile yakınsanmış bir kimlik platformunun içinde olmalı | IGA + PAM konsolidasyonu isteyenler |
| **Teleport** | Altyapı erişimi (SSH, K8s, DB) için modern, sertifika tabanlı | Mühendislik ekipleri, bulut-native |
| **HashiCorp Vault** | Sır yönetimi ve dinamik kimlik bilgileri; klasik PAM değil | DevOps, makine kimliği |
| **One Identity Safeguard** | IGA ile aynı satıcıdan | Konsolidasyon isteyenler |

**Not:** Venafi (makine kimliği) CyberArk tarafından satın alındı.

**Karar kuralı:** En büyük riskin ayrıcalıklı hesap ele geçirmesiyse PAM'le başla; en büyük sorunun aşırı erişim ve "kimde ne var" görünürlüğüyse IGA'yla başla.

### 100. Ulusal dijital kimlik sistemleri

Bir ürün kurarken çoğu zaman bir ulusal eID'ye bağlanmak gerekiyor — ya kimlik tespiti için ya da doğrudan giriş yöntemi olarak.

**Üç farklı şey karıştırılıyor:**
- **eID** — kimlik doğrulama ve imzalama için genel elektronik kimlik
- **mDL** — ISO/IEC 18013-5 üzerine kurulu telefon tabanlı ehliyet; yüz yüze ve yaş kontrolü için
- **ePassport** — ICAO standardı çipli seyahat belgesi; sınırlarda

Birçok ülke birden fazlasını birlikte işletiyor. Bir dizin 51 ülkede 86 şema sayıyor.

**Nisan 2026 itibarıyla canlı ulusal dijital kimlik sistemi olan ülkeler:** Avusturya, Butan, Bosna-Hersek, Brezilya, Çin, Kosta Rika, Çekya, Danimarka, Estonya, Fransa, Yunanistan, Hindistan, Kuveyt, Maldivler, Polonya, Portekiz, Suudi Arabistan, Singapur, Güney Kore, İspanya, BAE, Vietnam.

**Öne çıkan şemalar:**
| Ülke | Şema | Not |
|---|---|---|
| Hindistan | **Aadhaar** | Dünyanın en büyüğü; 2009'dan beri UIDAI; 12 haneli numara + biyometrik (parmak izi, iris) ve demografik veri; 2025 itibarıyla **1,3 milyardan fazla** kişi. Sübvansiyon dağıtımı, SIM kart, finansal kapsayıcılığın omurgası. mAadhaar uygulaması dijital sürümü |
| Estonya | **e-ID** | En olgun örnek; e-imza ve e-devletin temeli |
| Singapur | **Singpass** | Devlet ve özel sektör hizmetlerine yaygın erişim; 2FA zorunlu. Kimlik bilgisi satışı vakaları raporlanmış |
| Danimarka | **MitID** | 2021'de devreye girdi, kamu-özel ortaklığı |
| Norveç | **BankID** | **Özel şirket işletiyor** — küresel ölçekte alışılmadık |
| İspanya | **MiDNI** | Devlet geliştirmesi |
| Ukrayna | **Diia** | Mobil-öncelikli, uluslararası referans gösteriliyor |
| Brezilya | **gov.br** | Geniş kapsama |
| Nijerya | **NIN** | Afrika'nın en büyüklerinden |
| ABD | **Login.gov**, mDL, ePassport | Federal düzeyde parçalı; ulusal tek şema yok |
| AB | **EUDI Wallet** | 27 ülkede sınır ötesi tasarlanmış (§76) |

**Kritik teknik gerçek:** **Ulusal eID'ler çoğunlukla sınır ötesi çalışmıyor.** eIDAS altında bildirilen AB şemaları AB içinde çalışıyor, ePassport'lar ICAO standardıyla küresel, EUDI Wallet sınır ötesi tasarlandı — ama çoğu ulusal eID **yalnızca yerel**. Çok ülkeli bir ürün kuruyorsan tek entegrasyonla çözemezsin.

**Mimari eleştiri — "ID phone home":** Merkezi sistemlerin yapısal zaafı, kimliğin her kullanımının merkezi bir sunucuya (genelde devlet otoritesi veya devlet onaylı satıcı) loglanması ve raporlanması. Gizlilik ve gözetim açısından eleştiriliyor; seçici ifşa (SD-JWT VC) ve cüzdan modeli buna cevap olarak konumlanıyor.

**Bağımlılık riski:** 2018 SingHealth ihlali Singpass'i doğrudan içermese de bağlı sistemlerdeki riskin güveni nasıl aşındırdığını gösterdi. Ulusal eID'ye bağlanmak, o ekosistemin risklerini de devralmak demek.

### 101. Merkeziyetsiz kimlik (DID / SSI)

**Temel fikir:** Kullanıcı verifiable credential'ları kendi kontrolünde tutuyor; doğrulayıcı merkezi bir kimlik sağlayıcısına başvurmadan credential'ı kontrol ediyor. W3C standartları: **DID** (merkezi kayıt gerektirmeden çalışan, küresel benzersiz, kriptografik olarak doğrulanabilir tanımlayıcı) ve **Verifiable Credentials**.

**Spec durumu:** DID v1.0 Temmuz 2022'de W3C Recommendation oldu. **DIDs v1.1** güncellemesi yorum için yayımlandı (yorumlar Nisan 2026'ya kadar). W3C VC Working Group **yedi Recommendation** yayımladı. W3C Federated Identity WG'den **Digital Credentials API** ilk kamuya açık çalışma taslağı çıktı. DIF (Decentralized Identity Foundation) tamamlayıcı spec'ler ve birlikte çalışabilirlik üzerinde çalışıyor.

**Benimseme gerçeği:** "İstikrarlı ama gösterişsiz." Microsoft 2022'de Entra Verified ID'ye DID ekledi; Nuggets AI ajan kimlik doğrulama ürününü DID üzerine kurdu; Dock ve Vouched kullanıyor.

**Platformlar:** Microsoft ION + Entra Verified ID (DID altyapısı), Spruce ID (açık geliştirici araçları), Dock ve Trinsic (uçtan uca credential platformları), Evernym (regüle sektör gizliliği).

**2026'nın asıl benimseme sürükleyicisi teknoloji değil, regülasyon:** AB eIDAS 2.0 EUDI Wallet ve ISO 18013-5 mDL'ler — ikisi de OpenID4VC ve seçici ifşa üzerine kurulu.

**İki kritik netlik:**
1. **Merkeziyetsiz kimlik federe SSO'nun (SAML, OIDC) yerini almıyor.** Ayrı bir düzlem ekliyor
2. **Çoğu ekip verifier olarak başlamalı**, issuer olarak değil

**Blockchain ilişkisi:** Kişisel bilgi zincire yazılmıyor; yalnızca kriptografik hash'ler, proof'lar ve DID'ler tutuluyor, hassas veri zincir dışında cüzdanda kalıyor.

**Pazar:** Kuzey Amerika 2025'te %42 pay ile önde. Kimlik tipi kırılımında biyometri (parmak izi, yüz, iris) %62, biyometrik olmayan (PKI, VC, passwordless) %38.

### 102. Biyometrik algoritma satıcıları

Kimlik tespiti (§85) ve yüz doğrulama satın alırken altta çalışan algoritmanın kalitesi belirleyici.

**Bağımsız kıyaslamalar:** NIST **FRTE** (Face Recognition Technology Evaluation; eski adıyla FRVT) — 1:1 doğrulama ve 1:N tanımlama ayrı raporlanıyor. Ayrıca DHS **RIVTD/RIVR** ve DHS Biometric Rally.

**Öne çıkanlar:**
- **NEC** — En son FRTE 1:N Identification raporunda **dünyanın en doğrusu**: 12 milyon kişilik durağan görüntü setinde **%0,07 kimlik doğrulama hata oranı**. 10 ve 12 yıl öncesine ait görüntülerle yapılan iki yaşlanma testinde de birinci; NIST'in listelediği sekiz ana 1:N kategorisinin hepsinde ilk ikide
- **Paravision** — ABD merkezli; FRTE, DHS RIVTD/RIVR ve Biometric Rally'de üst sıralar; **demografik adalet** (etnik köken, cinsiyet, yaş) vurgusu; bulut, mobil ve gömülü için modüler SDK
- **Idemia** — Kurumsal ve kamu, AFIS ağırlıklı
- **Innovatrics** — Slovakya; yüz + parmak izi + multimodal; ABD pazarında az tanınıyor, kamu/AFIS odaklı
- **Çin merkezli sağlayıcılar (SenseTime, Megvii vb.)** — Büyük ölçekli dağıtımlar, ancak ABD ticaret yaptırımları küresel benimsemeyi kısıtlıyor

**Değerlendirme kriterleri:** FRTE sıralaması (kategori bazında — 1:1 ve 1:N farklı), **demografik hata oranı farkları**, canlılık için iBeta Level 1 & 2, gömülü/mobil performansı, veri yerleşimi ve gizlilik rejimi, lisans modeli.

**Uyarı:** Sıralamalar sık değişiyor ve kategoriye göre farklı satıcılar önde. Bir satıcının "NIST'te birinci" iddiası hangi test, hangi kategori ve hangi tarih olduğu sorulmadan anlamlı değil.

---

### Kaynaklar

**Standartlar**
IETF RFC 6749, 7522, 7523, 7591, 7592, 7636, 7009, 7662, 8252, 8414, 8417, 8628, 8693, 8705, 8707, 9101, 9106, 9126, 9207, 9396, 9449, 9470, 9700, 9728 · OpenID Connect Core / Discovery / CIBA / RP-Initiated Logout · FAPI 1.0 Part 1–2, FAPI 2.0 Security Profile Final, FAPI 2.0 Message Signing Final · OpenID CAEP 1.0, SSF, CAEP Interoperability Profile 1.0 · OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0 · W3C WebAuthn L2/L3, DID Core · FIDO CTAP, CXF/CXP · ISO/IEC 18013-5/7 · NIST SP 800-63-4 (A/B/C), SP 800-132, SP 800-208, FIPS 140-3 · OWASP Password Storage Cheat Sheet · draft-ietf-oauth-first-party-apps-04, draft-ietf-oauth-identity-assertion-authz-grant, draft-ietf-oauth-client-id-metadata-document, draft-parecki-oauth-dpop-device-flow · Matter (CSA), Wi-Fi Easy Connect (DPP), BRSKI, EST, FDO

**Ürün ve pazar**
Skycloak · StartWithIdentity · Tech-Insider · Nacho (CerberAuth) OpenID Providers Benchmark · CIAM Compass (guptadeepak.com) · Duende · Cerbos · SuperTokens · PkgPulse · MakerKit · Security Boulevard · Keycloak sürüm notları ve dokümantasyonu · Authlete · OpenID Foundation sertifikasyon listeleri · Descope · Authgear · Eleken · Userpilot · euleinstitute/CorsoUX

**Tehdit ve araştırma**
Verizon DBIR 2026 · Proofpoint · SpyCloud · KELA · Flashpoint · IBM Cost of a Data Breach 2026 · Microsoft Digital Defense Report 2025 · Push Security · Huntress · Cisco Talos · Zscaler ThreatLabz · TrustSphere · HackTricks (Play Integrity attestation bypass) · FIDO Alliance State of Passkeys 2026 · arXiv 2604.23280, 2505.19301 · Gravitee 2026

**Yeni nesil**
Model Context Protocol 2026-07-28 spesifikasyonu ve blog · WorkOS · oauth.net Cross-App Access · Keycloak ID-JAG rehberi · MojoAuth (workload identity, PQC, passkey adoption) · Aembit · Corbado (DBSC, CXP/CXF) · Chrome for Developers · WICG/dbsc · Google Workspace SSF · Apple WWDC26 App Attest · Talsec · Evertrust, Gataca, Notix, Indicio, Vidos (EUDI) · Singapur CSA Securing Agentic AI Addendum · Bitwarden, 1Password, FIDO Alliance

**Bölüm XV**
decryptiondigest.com (PAM ve IGA karşılaştırmaları, Gartner MQ analizleri) · MajorKey Tech · Ciphers Security · Cyber Vendor Guide · Identity Logic Consulting · Regula Forensics (Digital ID by Country) · StartWithIdentity (Digital IDs directory, decentralized identity platforms) · Comparitech · identity.com · Biometric Update (W3C, DID) · W3C DID WG ve VC WG · NEC · Paravision · NIST FRTE

**Komşu ekosistem**
cside · ShadowDragon · Fraudio · SEON · Dupple · fintechdatabase.eu · İHS Teknoloji (Udentify) · SCSoft · Müşavirler Kulübü · Türk Telekom Yetenekler Platformu · JetSMS · BTK · Turkcell Mobil İmza · Appsecsanta · PreEmptive · G2 / Gartner Peer Insights · DigiCert · SSL.com · Device Authority · Zbotic


---

# KISIM III — TEKNOLOJİ TEMELİ

*Dil, kütüphane, kripto, doğrulama ve tedarik zinciri kararlarının dayanağı.*
