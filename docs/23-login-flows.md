# 23. Giriş akışları ve UX

> `ARGUS.md` §23'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§23 §X` referansları aynı anlamda.


Aşağıdaki bulgular ~50 arama/fetch sonucudur. Her iddiada kaynak + tarih var. Doğrulanamayanlar açıkça işaretlendi.

---

## 1. IDENTIFIER-FIRST AKIŞI

### 1.1 Endüstri neden geçti — gerçek gerekçe

Birincil gerekçe **estetik değil, federasyon yönlendirmesi**. Auth0'ın resmî dokümanı akışı açıkça bu şekilde tanımlıyor: kullanıcı e-postasını girer, Auth0 alan adının kayıtlı bir Enterprise connection ile eşleşip eşleşmediğine bakar; eşleşirse kurumsal IdP'ye yönlendirir, eşleşmezse yerel parola sorar ([Auth0 — Configure Identifier First Authentication](https://auth0.com/docs/authenticate/login/auth0-universal-login/identifier-first)). Auth0 üç varyant belgeliyor: Identifier + Password (tek ekran), Identifier First, Identifier First + Biometrics (WebAuthn kaydı için).

İkincil gerekçe: **kimlik doğrulama yönteminin kullanıcıya göre değişmesi**. Identifier alınmadan hangi yöntemin (parola / passkey / kurumsal SSO / magic link) gösterileceği bilinemez. Microsoft'un yeni sign-in UI'ının "kullanıcı için mevcut en güvenli yöntemi otomatik tespit edip önceliklendirdiğini" ve bu tasarımın **parola kullanımını %20'den fazla azalttığını** açıkladığı yer: [Microsoft Security Blog, 1 Mayıs 2025](https://www.microsoft.com/en-us/security/blog/2025/05/01/pushing-passkeys-forward-microsofts-latest-updates-for-simpler-safer-sign-ins/).

⚠️ **DOĞRULANMADI:** Google'ın 2015'teki identifier-first geçişine ait resmî bir tasarım gerekçesi belgesi bulunamadı. Sadece Google Cloud dokümanlarında davranışın tarifi var ([Google Cloud — Best practices for federating](https://docs.cloud.google.com/architecture/identity/best-practices-for-federating)).

### 1.2 Enumeration: yapısal olarak sızdırır mı? — EVET

Bu bir implementasyon hatası değil, **akışın yapısal sonucu**. İki adımlı akışta 1. adımın çıktısı zorunlu olarak "bu identifier için ne yapmalıyım" bilgisidir; bu da hesabın varlığını ima eder.

Somut kanıt:

- **CVE-2026-4633 (Keycloak)** — Organizations etkinken identity-first login flow'da farklılaşan hata mesajları üzerinden kullanıcı enumeration'ı. CVSS 3.7 (Low), CWE-209, yayın 27 Mart 2026 ([SentinelOne vuln DB](https://www.sentinelone.com/vulnerability-database/cve-2026-4633/)). Önerilen azaltmalar: yamalar, Organizations'ı kapatmak, rate limiting, CAPTCHA, jenerik hata mesajları.
- **Keycloak issue #17629** — Password-less browser login flow'undaki Username Form, olmayan kullanıcı için "Invalid username or email" dönüyor; varsayılan browser flow'daki UsernamePassword Form ise ayrım yapmıyor. Issue **"closed as not planned"** ile kapatıldı ([GitHub](https://github.com/keycloak/keycloak/issues/17629)). Yani üst düzey bir IdP bunu kabul edilebilir takas saymış.
- Keycloak brute-force koruması kilitli hesapta da aynı "Invalid username or password" mesajını gösteriyor — bu bilinçli bir tasarım ([Keycloak brute-force docs](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/threat/brute-force.adoc)).

**Ürünler bunu nasıl ele alıyor — en net belgelenmiş örnek Clerk** ([Clerk — User enumeration protection](https://clerk.com/docs/guides/secure/user-enumeration-protection)):

| Mod | Ne yapar | UX bedeli |
|---|---|---|
| **Bulk protection** | Rate limiting; normal sign-in deneyimi korunur | Kullanıcı hesabın var olmadığını yine öğrenir ("no account found") |
| **Strict protection** | Hesabın varlığı kimlik doğrulanana kadar gizlenir; olmayan hesaplar için password/Web3 stratejilerinde **gerçek doğrulama kodu gönderilmez** | Yanlış identifier'da hiçbir geri bildirim yok; **Open access mode zorunlu**, password başlangıç stratejisi olamaz, username identifier desteklenmez |

Bu tablo Argus için doğrudan kopyalanabilir bir tasarım: enumeration koruması bir *mod*, tek bir davranış değil — ve strict mod diğer özellikleri (username login, invite-only) yapısal olarak dışlıyor.

Corbado'nun analizi ek bir yapısal nokta koyuyor: **identifier adımını tamamen atlayan "Passkey ile giriş yap" butonu** (boş `allowCredentials`, discoverable credential) enumeration'ı sıfırlar — çünkü tarayıcı hiçbir sunucu sorgusu olmadan yerel credential'ı bulur. Amazon, Microsoft ve Google'ın fallback seçenekleri kaydın gerçekten var olup olmadığını maskeliyor ([Corbado — Account enumeration risk with passkeys](https://www.corbado.com/blog/passkey-login-best-practices/account-enumeration-risk-passkeys)).

OWASP'ın konumu net ve takası açıkça kabul ediyor: uygulama geçersiz kullanıcı, geçersiz parola, **kilitli hesap ve devre dışı hesap** için aynı mesajı dönmeli ("Login failed; Invalid user ID or password"); parola sıfırlamada "If that email address is in our database, we will send you an email". OWASP ayrıca "quick exit" kod desenlerinin **zamanlama üzerinden** sızdırdığını ve jenerik mesajların meşru kullanıcıyı kafası karışık bırakıp uygulamayı terk etmeye itebileceğini kabul ediyor; öneri, kritikliğe göre karar vermek ve jenerik mesajı CAPTCHA ile birleştirmek ([OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)).

### 1.3 Home Realm Discovery — güvenlik riskleri

HRD iki ayrı sızıntı yaratıyor:

**(a) Kullanıcının hangi kuruma ait olduğunun sızması.** Microsoft'un `getuserrealm.srf` endpoint'i kimlik doğrulama olmadan `FederationBrandName` ve hesabın Managed mi Federated mi olduğunu döndürüyor — tek istekle kurumun ADFS/Okta/Ping kullanıp kullanmadığı anlaşılıyor ([Sprocket Security — Tenant Enumeration is Back, 10 Aralık 2025](https://www.sprocketsecurity.com/blog/tenant-enumeration-is-back)). Microsoft MC1081538 (23 Mayıs 2025) ile Autodiscover SOAP servisini kısıtladı, rollout Haziran–Ağustos 2025; artık yalnızca sorgulanan alan adını dönüyor, toplu enumeration kırıldı. Ama `getuserrealm.srf` ve `/.well-known/openid-configuration` üzerinden tenant keşfi devam ediyor.

**(b) `domain_hint` ile otomatik hızlandırma (auto-acceleration).** Microsoft'un resmî tavsiyesi **auto-acceleration'a karşı**: "Microsoft advises against configuring auto-acceleration because it can hinder stronger authentication methods like FIDO and collaboration." Gerekçe güvenlik: bir uygulamanın gönderdiği `domain_hint=contoso.com` kullanıcıyı federe IdP'ye fırlatır, kullanıcı **managed credential'ını (FIDO) kullanamaz**, guest kullanıcılar giremez ([Microsoft Entra — Home Realm Discovery Policy](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/home-realm-discovery-policy), güncelleme 6 Nisan 2026).

Microsoft'un iki savunması:
1. **Domain confirmation dialog (Nisan 2023'ten beri)** — auto-acceleration veya smart link kullanan organizasyonlarda kullanıcıya "hangi tenant'a giriş yapıyorsun" onayı gösteriliyor. Doküman bunu doğrudan "part of Microsoft's security hardening efforts" olarak tanımlıyor. Kullanıcıya `kelly@contoso.com` identifier'ı ve hedef tenant domain'i gösterilip Confirm isteniyor.
2. **`DomainHintPolicy`** — `IgnoreDomainHintForDomains` / `RespectDomainHintForDomains` / `IgnoreDomainHintForApps` / `RespectDomainHintForApps`. "Respect" her zaman "Ignore"u ezer. `all_domains` ve `all_apps` wildcard'ları var. Dört fazlı rollout planı belgeleniyor ([Microsoft — Disable auto-acceleration sign-in](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/prevent-domain-hints-with-home-realm-discovery)).

Öncelik sırası: domain hint > service principal policy > organization policy > default. Not: `domain_hint` HRD policy'deki auto-acceleration'ı **ezer** — yani istemci sunucu politikasını geçersiz kılabiliyor, bu tek başına bir tasarım hatası sinyali. Ayrıca HRD policy'leri mobil/macOS brokered authentication'da çalışmıyor.

**Argus için çıkarım:** `domain_hint` benzeri bir parametreyi kabul edeceksek, tenant tarafında bunu *ignore* edebilme yetkisi zorunlu — ve istemci hint'i sunucu politikasını ezmemeli (Microsoft'un yaptığının tersi).

---

## 2. PASSKEY / WEBAUTHN UX — 2026 GERÇEĞİ

### 2.1 Conditional UI (autofill) — teknik durum

Chrome'un birincil dokümanı ([web.dev — Sign in with a passkey through form autofill](https://web.dev/articles/passkey-form-autofill)):

- `autocomplete="username webauthn"` (boşlukla ayrılmış); `autofocus` eklenirse prompt sayfa yüklenince tetiklenir
- `allowCredentials` **boş dizi** olmalı — tarayıcı o `rpId` için tüm credential'ları gösterir
- `mediation: 'conditional'` — promise, kullanıcı input'a dokunana kadar askıda kalır, UI gösterilmez
- Feature detection artık `PublicKeyCredential.getClientCapabilities()` üzerinden `conditionalGet === true`
- `AbortController.signal` ile programatik iptal
- `userVerification: "preferred"` ise authenticator data'daki **UV flag'i doğrulanmalı**
- Başarılı passkey doğrulamasından sonra ikinci faktör istenmemeli

**Tarayıcı/OS desteği:** Chrome/Edge 108+ (Aralık 2022), Safari 16+, Firefox 122+ — ama yalnızca alttaki OS Windows 11, macOS, Android veya iOS/iPadOS 16+ ise. Windows 10, eski ChromeOS ve çoğu in-app browser view'da aynı kod yolu **hiçbir şey döndürmez ve form hiçbir öneri göstermez** ([MojoAuth — Conditional UI browser support](https://mojoauth.com/blog/conditional-ui-browser-support-passkey-autofill)) ⚠️ satıcı kaynağı, ama teknik iddia Chrome dokümanlarıyla tutarlı.

### 2.2 Autofill vs modal — hangisi ne zaman

Chrome'un kendi kılavuzu net bir ayrım koyuyor:
- **Autofill (conditional)**: hem parola hem passkey kullanıcılarını aynı mevcut form içinde destekliyorsan
- **Modal**: passkey birincil yöntemin ise

Conditional UI'ın belgelenmiş dezavantajları ([Corbado — WebAuthn Conditional UI](https://www.corbado.com/blog/webauthn-conditional-ui-passkeys-autofill)):
1. **Sessiz başarısızlık ve ölçülemezlik** — site, dropdown'ın göründüğünü, boş göründüğünü veya kullanıcının görmezden geldiğini **ayırt edemez**. Bozuk implementasyon çalışan implementasyonla aynı görünür. (Bu Argus için kritik: telemetri tasarımını baştan buna göre kurmak gerekir.)
2. Password manager eklentileri DOM'u değiştirip `autocomplete` tag'ini ezebiliyor
3. Kullanıcı alana dokunmadan tetiklenmez
4. Yalnızca discoverable credential'lar listelenir
5. Platform desteği eşit değil

**Önerilen desen:** Conditional UI + her zaman bir "Passkey ile giriş yap" butonu; butona basıldığında bekleyen conditional isteği `AbortController` ile iptal et.

⚠️ **DOĞRULANMADI:** Conditional UI'ın modal'a kıyasla dönüşüm etkisine dair **bağımsız, birincil, sayısal** veri bulunamadı. "Conditional UI is usually the single biggest lever on adoption" iddiası satıcı içeriği (MojoAuth) ve doğrulanamadı.

### 2.3 Passkey benimseme — 2026 rakamları

**FIDO Alliance, World Passkey Day 2026 (7 Mayıs 2026)** — birincil kaynak ([FIDO Alliance](https://fidoalliance.org/fido-alliance-reports-accelerating-global-passkey-adoption-on-world-passkey-day-2026/)):

- Dünyada tahminen **5 milyar passkey** kullanımda
- Tüketici farkındalığı **%90** (2025'te %75'ti)
- **%75** en az bir hesapta passkey etkinleştirmiş
- **%49** mümkün olduğunda düzenli olarak kullanıyor
- **%68** kurum çalışan girişleri için passkey dağıtmış veya dağıtıyor
- **%82** tam passwordless'ı nihai hedef olarak belirtiyor; **%28** ulaşmış
- **%57** kurum hâlâ birincil çalışan girişinde phishable yöntemlere dayanıyor
- **%33** geçen yıl hesap ele geçirilmesi/ihlal bildirimi yaşamış (ABD'de %41)
- **%47** parolayı hatırlayamadığında satın almayı/girişi terk etme eğiliminde

**Metodoloji (önemli):** Sapio Research, Nisan 2026. Tüketici: 11.000 kişi, 10 ülke, ±%0,9 hata payı (%95 güven). İşgücü: 1.400 karar verici, 500+ çalışanlı kurumlar, ±%2,6. **Bunlar anket verisi — telemetri değil.** "%75 passkey etkinleştirdi" beyan edilen davranış; gerçek kullanım oranı değil.

Ek kırılım ([Descope 2026 FIDO raporu özeti](https://www.descope.com/blog/post/2026-fido-report)): benimseme sürücüleri phishing/MFA fatigue koruması %39, phishing-resistant auth %37, hız/UX %34. Engeller: legacy uyumluluk %38, bütçe %35, **cihaz kurtarma endişesi %33**.

**Gerçek telemetri (satıcı ama üretim verisi):**
- **Google, Mart–Nisan 2023:** aynı cihazda passkey başarı oranı **%63,8** vs parola **%13,8**; ortalama giriş süresi **14,9 sn** vs **30,4 sn** ([Google Online Security Blog, 5 Mayıs 2023](https://security.googleblog.com/2023/05/making-authentication-faster-than-ever.html))
- **Microsoft, 1 Mayıs 2025:** passkey kullanıcıları **~%98** vs parola **%32** başarı; passkey girişleri parola+MFA'dan **8x hızlı**; günde **~1 milyon** passkey kaydı; yeni sign-in UI parola kullanımını **%20+** azaltmış ([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/05/01/pushing-passkeys-forward-microsofts-latest-updates-for-simpler-safer-sign-ins/))
- **TikTok, Temmuz 2023:** %97 giriş başarısı, uygun kullanıcıların **yalnızca %14'ü** benimsemiş, SMS OTP kullanımında %2 düşüş ([Passkey Central — metrics](https://www.passkeycentral.org/identify-your-needs/passkey-authentication-metrics), Authenticate 2023 sunumu)
- **KAYAK:** giriş süresinde %50 azalma (aynı kaynak)
- **FIDO Passkey Index (13 Ekim 2025, Liminal ile):** passkey girişlerinde **%93** başarı vs diğer yöntemler **%63** → **%30 dönüşüm artışı**. ⚠️ Metodoloji: **9 FIDO üye kuruluşuna yapılan gizli anket** + 200 kuruluşluk Liminal çalışması ([FIDO Alliance](https://fidoalliance.org/fido-alliance-launches-passkey-index-revealing-significant-passkey-uptake-and-business-benefits/)). Anonim, agrege, denetlenmemiş — pazarlama ağırlığı yüksek.

**Kritik yorum:** Microsoft'un %98 vs %32'si ile Google'ın %63,8 vs %13,8'i aynı şeyi ölçmüyor ve her ikisi de **seçim yanlılığı** taşıyor — passkey kuran kullanıcı zaten aktif, cihazı elinde olan kullanıcıdır. Bu rakamları Argus'un iş gerekçesinde kullanacaksak "seçilmiş popülasyon" uyarısıyla kullanmalıyız.

### 2.4 Passkey UX başarısızlıkları — cross-device gerçeği

Bu, raporun en sert bulgusu.

**Android cross-device QR funnel (Google Authenticate 2025 verisi, Corbado tarafından derlenmiş):**
- Başlangıç sayfası → tarayıcı prompt'u: **%48**
- Tarayıcı prompt'u → QR taraması: **%29** ← kritik kopuş
- QR taraması → authenticator başarısı: **%64**
- Authenticator → oturum açık: **%89**
- **Uçtan uca: 10 Android kullanıcısından 1'inden azı** cross-device girişi tamamlıyor

([MojoAuth — Cross-device passkey QR flow](https://mojoauth.com/blog/cross-device-passkey-qr-flow-where-users-drop-off), kaynak: Corbado Passkey Benchmark 2026)

**Corbado Passkey Benchmark 2026, Q1 2026 üretim trafiği** ([Corbado](https://www.corbado.com/passkey-benchmark-2026/passkey-authentication-success-rate)):

| Platform | Başarı oranı | Cross-device gerektiren pay |
|---|---|---|
| iOS web | %85–95 | %0–5 |
| Android web | %70–85 | %5–10 |
| macOS web | %70–85 | %10–15 |
| **Windows 10/11 web** | **%45–60** | **%40–65** |

Bilinen cihaz (hatırlanan/yerel passkey): %95–99. Bilinmeyen cihaz (identifier-first): %55–95.

⚠️ Metodoloji şeffaflığı sınırlı — Corbado Research kendi müşteri trafiği; ülke/dikey kırılımlar ücretli katmanda. Ama **Windows'un felaket olduğu** yönü Google funnel verisiyle tutarlı ve teknik olarak açıklanabilir (Windows 10'da Bluetooth/hybrid transport eksikliği).

**Neden başarısız oluyor:** hybrid transport kullanıcıdan iki donanımı, bir kamerayı, bir radyoyu ve daha önce hiç görmediği bir zihinsel modeli koordine etmesini istiyor. Bluetooth yoksa, tarayıcı davranışı platforma göre değişiyorsa veya kurumsal ağ yolu kısıtlıysa kullanıcı **yalnızca jenerik bir timeout** görüyor ([Corbado — QR login failure](https://www.corbado.com/blog/qr-login-failure)).

⚠️ **DOĞRULANMADI:** "FIDO Alliance user testing (2024–2025) katılımcıların yaklaşık yarısının telefonu almaya gitmekten caydığını buldu" — MojoAuth üzerinden ikinci elden aktarılıyor, FIDO'nun kendi yayınında doğrulanamadı.

### 2.5 Signal API (WebAuthn L3) — hangi UX problemini çözüyor

[Chrome for Developers — Signal API](https://developer.chrome.com/docs/identity/webauthn-signal-api):

| Metot | Çözdüğü problem | Kritik uyarı |
|---|---|---|
| `signalUnknownCredential()` | Sunucuda silinen credential'ı passkey provider hâlâ öneriyor → başarısız giriş denemeleri. Başarısız denemeden sonra çağrılır, provider yereldeki kaydı siler. | **Oturum kapalıyken çağrılması güvenli** — tek bir credential ID'ye referans verir, kullanıcının kaç passkey'i olduğunu sızdırmaz |
| `signalAllAcceptedCredentials()` | Kullanıcı ayarlarda passkey silince provider listesi tutarsız kalıyor | **Asla kısmi listeyle çağırma.** Eksik credential'lar gizlenir ve meşru girişleri bloklar; boş liste tüm passkey'leri gizler. Yalnızca **doğrulanmış kullanıcı** için, **tam liste** ile |
| `signalCurrentUserDetails()` | Kullanıcı adı/görünen ad değişince provider metadata'sı eskiyor | Kullanıcının provider içindeki manuel düzenlemeleri otoriter kabul edilir, RP ezemez |

**Destek:** Chrome 132 ve Edge 132 (Ocak 2025). Safari 26 destekleyici sinyaller verdi ama implemente etmedi. Firefox görüş bildirmedi. Google Password Manager üçünü de destekliyor; üçüncü taraf eklentiler kendi karar veriyor.

Bu doğrudan "hangi cihazda passkey'im var" ve "passkey'i sildim ama hâlâ görünüyor" problemlerinin ilacı — ama **enumeration açısından da önemli**: `signalUnknownCredential` bilinçli olarak sızıntısız tasarlanmış, `signalAllAcceptedCredentials` ise değil (bu yüzden auth gerektiriyor).

### 2.6 Passkey + parola bir arada, "varsayılan yap" hamleleri

- **Google, Ekim 2023:** passkey'ler kişisel hesaplar için varsayılan; kullanıcılar "skip password when possible" seçeneğini açık görüyor ([Google blog](https://blog.google/technology/safety-security/passkeys-default-google-accounts/))
- **Microsoft, 1 Mayıs 2025:** yeni Microsoft hesapları **passwordless by default** — hiç parola kaydetmeden açılıyor; mevcut kullanıcılar ayarlardan parolayı silebiliyor ([Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/05/01/pushing-passkeys-forward-microsofts-latest-updates-for-simpler-safer-sign-ins/))
- **Entra:** parola kutusu Microsoft-managed tenant'larda varsayılan olmaktan çıkıyor, tam dağıtım Haziran 2026 sonu ⚠️ bu tarih ikincil kaynaklardan (Trackr.Live, PCWorld); Microsoft'un birincil duyurusunda doğrulanamadı

**FIDO'nun resmî desen kütüphanesi** ([Passkey Central — Design Guidelines](https://www.passkeycentral.org/design-guidelines/)):
- **Zorunlu desenler (2):** (1) Account Settings içinde passkey oluşturma/görme/yönetme, (2) passkey ile giriş + **diğer yöntemlere zarif fallback**
- **Opsiyonel desenler:** hesap kurtarmadan sonra passkey oluşturma, cross-device sign-in, SMS OTP'yi devre dışı bırakma, passkey-first hesap oluşturma, passkey silme, cross-platform sign-in

Araştırma süreci: UX Working Group (32 şirketten 128 kişi), yıllık Ocak–Mayıs, 60–90 dk birebir uzaktan görüşmeler, ABD 18–70 yaş. **2023 araştırması kör/az gören, TalkBack/VoiceOver kullanan katılımcıları içeriyordu.**

---

## 3. MFA UX VE GÜVENLİK TAKASLARI

### 3.1 MFA fatigue / push bombing

Saldırı Lapsus$ ve Yanluowang tarafından Microsoft, Cisco ve Uber ihlallerinde kanıtlanmış durumda ([BleepingComputer](https://www.bleepingcomputer.com/news/microsoft/microsoft-enforces-number-matching-to-fight-mfa-fatigue-attacks/)).

**Number matching — Microsoft'un mevcut durumu (birincil kaynak, güncelleme 13 Şubat 2026):** [Microsoft Entra — How number matching works](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match)

- **"Number matching is enabled for all Authenticator push notifications."** Zorunlu, kapatılamaz. "Can users opt out of number matching? **No.**"
- Kapsam: MFA, SSPR, birleşik kayıt, AD FS adapter, NPS extension
- **Kapsam dışı:** Apple Watch ve Android wearable — kullanıcı telefonu kullanmak zorunda
- **Same-device istisnası:** Kullanıcı Teams/Outlook gibi Microsoft mobil uygulamalarında Authenticator ile **aynı cihazda** giriş yapıyorsa Yes/No yeterli. Gerekçe açıkça belirtiliyor: "There's no increased risk... because the prompt only shows on the device that initiated the sign in." Edge/Chrome/Safari'de sayı girmek zorunlu.
- Eski Authenticator sürümü = kimlik doğrulama çalışmaz (yumuşak geçiş yok)
- Azure MFA Server'da desteklenmiyor (deprecated)

**Argus için doğrudan uygulanabilir kural:** Push onayında ekran-cihaz eşleşmesi tespit edilebiliyorsa number matching gereksiz; edilemiyorsa zorunlu. Bu, Microsoft'un gerekçelendirdiği ve ölçtüğü bir ayrım.

CISA da number matching'i ayrı bir fact sheet ile öneriyor ([CISA](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf)).

⚠️ **DOĞRULANMADI:** "number matching canlı müşteri ortamlarında MFA fatigue saldırılarını **ortadan kaldırdı**" iddiası — ikincil kaynaklarda dolaşıyor, Microsoft'un birincil yayınında sayısal karşılığı bulunamadı.

### 3.2 Adaptive / risk-based MFA'nın UX etkisi

**En iyi birincil kaynak akademik:** Wiefling, Dürmuth, Lo Iacono — *"More Than Just Good Passwords? A Study on Usability and Security Perceptions of Risk-based Authentication"*, ACSAC 2020 ([arXiv:2010.00339](https://arxiv.org/abs/2010.00339), [PDF](https://www.acsac.org/2020/files/web/2b-1_wiefling_morethanjustgoodpasswords.pdf)).

- Metodoloji: gruplar arası laboratuvar çalışması, **n=65**; iki RBA varyantı, bir 2FA varyantı, sadece-parola
- Bulgu: RBA, incelenen 2FA varyantlarından **daha kullanılabilir** algılanıyor; sadece-paroladan **daha güvenli**, 2FA ile **karşılaştırılabilir güvenlikte** algılanıyor
- RBA "daha az zaman alıcı" olarak algılanıyor
- Yazarlar RBA'ya özgü kullanılabilirlik problemleri de gözlemleyip azaltma önerileri veriyor

Bu, alandaki tek ciddi hakemli kullanılabilirlik verisi. Küçük örneklem (n=65), laboratuvar ortamı, 2020 — sınırları var ama satıcı içeriğinden kat kat güvenilir.

⚠️ **DOĞRULANMADI:** Adaptive MFA'nın prompt sayısını yüzde kaç azalttığına dair üretim verisi bulunamadı. LoginRadius/Palo Alto/miniOrange gibi kaynaklardaki "≤3 prompt/kullanıcı/hafta" gibi KPI'lar **hedef değerler**, ölçüm değil.

### 3.3 "Beni hatırla" — nasıl güvenli implemente edilir

**Microsoft'un konumu ve ölçülmüş takası** ([Entra — MFA prompts and session lifetime](https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-azure-multi-factor-authentication-prompts-session-lifetime), güncelleme 13 Şubat 2026):

En önemli cümle — bu tüm "sık sık yeniden doğrula" sezgisini tersine çeviriyor:

> "Asking users for credentials often seems like a sensible thing to do, but it can backfire. If users are trained to enter their credentials without thinking, they can unintentionally supply them to a malicious credential prompt."

- **Varsayılan sign-in frequency: 90 günlük kayan pencere**
- **"Remember multifactor authentication": 1–365 gün yapılandırılabilir**, kullanıcı "Don't ask again for X days" seçince **kalıcı çerez** koyar
- **"Stay signed in?"** ayrı bir kalıcı çerez — hem birinci hem ikinci faktörü hatırlar, yalnızca tarayıcı istekleri için
- **En kısıtlayıcı politika kazanır:** "Stay signed in" + "Remember MFA 14 gün" birlikteyse kullanıcı 14 günde bir yeniden doğrular
- Microsoft **"Remember MFA"den Conditional Access Sign-in frequency'ye göçü** öneriyor; P1/P2 varsa yalnızca CA politikaları kullanılmalı
- Uyarı: "Remember MFA"yi 90 günden kısa ayarlamak Office istemcileri için prompt sayısını **artırır**
- Oturum, IT politikası ihlalinde (parola değişimi, uyumsuz cihaz, hesap devre dışı) **otomatik iptal ediliyor** — asıl güvenlik mekanizması bu, süre değil
- Microsoft'un kendi tavsiyesi (Entra recommendation dokümanı): 90 gün ⚠️ ikincil kaynaktan aktarım

**Auth0'ın implementasyonu** ([Auth0 — Customize MFA](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa)):
- **Çerez tabanlı**
- Idle timeout: varsayılan **7 gün** (1 saat – 30 gün aralığı)
- Maximum lifetime: varsayılan **30 gün** (1 saat – 90 gün aralığı)
- İki katmanlı: idle + absolute — doğru desen bu
- API: `/api/v2/guardian/settings`; Actions içinde `allowRememberBrowser`
- Auth0'ın yasal uyarısı: "Customers are responsible for any diminishment in security posture resulting from a change to the 'Remember Me' Session Behavior lifespan"

**Argus için sentez:** çerez + idle timeout + absolute lifetime + politika olayında (parola değişimi, MFA yöntemi değişimi, cihaz uyumsuzluğu, admin iptali) **zorunlu geçersizleştirme**. Auth0'ın 7/30 gün varsayılanları makul bir başlangıç noktası; Microsoft'un 1–365 gün aralığı fazla geniş.

### 3.4 Step-up authentication — RFC 9470

[RFC 9470, Eylül 2023](https://www.rfc-editor.org/info/rfc9470/) — Vittorio Bertocci (Auth0/Okta) ve Brian Campbell (Ping).

Çözdüğü problem: authorization server yetkilendirme anında bildiğine göre karar verir; ama API, isteğin riskli olup olmadığını **istek anında** öğrenir.

Mekanizma:
- Resource server `401` + `WWW-Authenticate` içinde **`insufficient_user_authentication`** hata kodu döner
- İki challenge parametresi: **`acr_values`** (kimlik doğrulama gücü) ve **`max_age`** (tazelik) — OIDC authorization request parametrelerini yeniden kullanır
- Client, kullanıcı ajanını AS'ye bu parametrelerle yönlendirir

**Kritik ayrım:** `acr_values` **tavsiye niteliğinde**, `max_age` **zorlanabilir**. OIDC'ye göre AS `acr_values`ı karşılamayı *deneyebilir* (MAY) ama `max_age` aşıldığında yeniden kimlik doğrulamayı **denemek zorundadır** (MUST) ([WorkOS açıklaması](https://workos.com/blog/rfc-9470-step-up-authentication-challenge), [Authlete](https://www.authlete.com/developers/stepup_authn/)).

**UX'e yansıması:** Kullanıcı akışın ortasında (örn. para transferi onaylarken) aniden yeniden doğrulamaya atılıyor. Argus'ta bunun kullanıcıya **neden** olduğunu açıklayan bir ekran gerekiyor — aksi halde phishing'den ayırt edilemez. Microsoft'un yukarıdaki "kullanıcıyı düşünmeden credential girmeye alıştırma" uyarısı tam da buraya bakıyor.

---

## 4. HOSTED LOGIN vs EMBEDDED (SDK)

### 4.1 Neden hosted daha güvenli — birincil kaynak argümanları

**Okta'nın resmî konumu** ([Okta — Redirect vs embedded authentication](https://developer.okta.com/docs/concepts/redirect-vs-embedded/)):
- "Okta recommends the Okta-hosted widget for most integrations"
- Redirect: XSS yüzeyini azaltır, güvenlik güncellemelerini Okta yönetir
- Embedded: "slightly increased risk in security" — Okta doğru implementasyonu garanti edemez; **"XSS attacks on your app may result in stolen sign-in credentials"**
- Embedded ile **kaybedilenler**: uygulamalar arası otomatik SSO, Okta kontrollü politika güncellemeleri, kod değişikliği olmadan yeni özelliklere erişim
- Okta'nın hosted widget'ı "the recommended method for the highest levels of identity security"

**Auth0'ın konumu** ([Auth0 — Hosted vs embedded login](https://auth0.com/docs/authenticate/login/universal-vs-embedded-login)): temel argüman **otomatik güncelleme** — "Auth0 delivers security updates to the login experience transparently"; embedded'da güncellemeleri sen dağıtırsın. Ayrıca yerleşik cross-application SSO.

**Embedded'ın somut, belgelenmiş kırılganlığı** ([Auth0 — Cross-Origin Authentication](https://auth0.com/docs/authenticate/login/cross-origin-authentication)):
- Cross-origin auth **üçüncü taraf çerezlere** bağımlı
- "Modern browsers (including Firefox, Safari with ITP, and Chromium-based browsers) restrict or block third-party cookies by default"
- Sonuç: "Web applications relying on third-party cookies for cross-origin authentication **may fail** in those browsers"
- Çözüm: uygulama ve tenant aynı **top-level domain**'de olmalı (`example.com` + `login.example.com`) → çerez first-party olur
- **Yalnızca username/password directory doğrulaması** için çalışır; sosyal ve kurumsal federasyon zaten redirect kullanır

Yani embedded login 2026'da yalnızca custom domain ile ayakta duruyor — ki bu zaten hosted'a doğru bir adım.

**Gerçek riskler (sentez):** (a) credential uygulama koduna değer → uygulamadaki her XSS bir credential hırsızlığıdır; (b) kullanıcı artık "doğru origin'de miyim" kontrolünü yapamaz → phishing direnci kaybolur; (c) WebAuthn RP ID uygulama origin'ine bağlanır → çok-origin dağıtımda passkey parçalanır.

### 4.2 RFC 10017 — Browser-Based Apps BCP (Ağustos 2026)

**BCP 212, RFC 10017**, yazarlar A. Parecki, P. De Ryck, D. Waite; 49 sayfa; IETF OAuth WG ([RFC Editor](https://www.rfc-editor.org/info/rfc10017/)).

Önerilen mimariler:

| Mimari | Bölüm | Değerlendirme |
|---|---|---|
| **Backend for Frontend (BFF)** | §6.1 | **En güvenli.** BFF confidential client'tır, token'ları sunucuda tutar, tüm resource isteklerini proxy'ler. Token hırsızlığını ve saldırganın taze token almasını engeller; client hijacking'i engelleyemez |
| **Token-Mediating Backend** | §6.2 | Orta yol. Backend confidential client olarak token alır ama access token'ı tarayıcıya verir. Refresh token hırsızlığını engeller, **access token'ı XSS'e açık bırakır** |
| **Browser-Based OAuth Client** | §6.3 | Tüm OAuth tarayıcıda, public client. "Significantly increases the attack surface" ve **"not recommended for business applications, sensitive applications, and applications that handle personal data"** (§6.3.4.3) |

Diğer kritik hükümler:
- **§7.2: "Browser-based clients MUST NOT use the Implicit grant type"**
- **§7.3:** Resource Owner Password Credentials — önerilmiyor
- **§7.4:** OAuth akışını Service Worker'da yürütmek önerilmiyor
- **§6.3.2.3:** Tarayıcı client'ları refresh token kullanıyorsa **rotation veya sender-constrained** zorunlu; AS refresh token ömrünü ilk verilme ömrüyle sınırlamalı
- **§5.1.3:** Hiçbir depolama yaklaşımı en tehlikeli saldırıyı — saldırganın bağımsız bir OAuth akışı başlatarak **taze token alması**nı — engellemez
- **§6.3.4.2.2:** DPoP çalınan access token'ın dışa aktarımını engeller ama saldırganın kendi anahtar çiftiyle taze token almasını engellemez
- **§7.1 (First-Party Same-Domain Applications):** Frontend ve backend aynı domain'deyse **OAuth gereksiz olabilir**. "Simple applications are made needlessly complex by using OAuth to replace the concept of session management." Cookie tabanlı session yeterli.

**Argus için:** §7.1 doğrudan bizim admin console'umuz ve hosted login sayfamız hakkında. Aynı domain'deki first-party UI'lar için OAuth değil, doğrudan session cookie kullanmalıyız. SPA müşterilerimize ise BFF önermeliyiz ve dokümantasyonumuzda §6.3.4.3'ün "iş uygulamaları ve kişisel veri işleyen uygulamalar için önerilmez" ifadesini alıntılamalıyız.

### 4.3 Native uygulamalar — RFC 8252 hâlâ geçerli mi? Evet, ama bir nüansla

[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) (Ekim 2017): native uygulamalardan OAuth authorization request'leri **yalnızca harici user-agent** (sistem tarayıcısı) üzerinden yapılmalı; embedded WebView phishing'e açıktır çünkü uygulama UI'ı kontrol eder ve credential'ı yakalayabilir.

**Nüans — RFC 8252 yazarlarından William Denniss'in açıklaması (Kasım 2024, 2026'da hâlâ geçerli):** RFC 8252'nin hedefi **native uygulama içindeki embedded OAuth akışıydı**; politika, WebView'ı bir implementasyon detayı olarak kullanan **tarayıcı uygulamalarına** uygulanmak üzere yazılmadı. Ayrım: embedded WebView OAuth akışının sonunda kapsayıcı native uygulama bir **OAuth token** alır (ve umulur ki session cookie'yi atar); in-app browser'da ise kullanıcı IdP'de **oturum açık kalır** ve bu, o in-app browser'ın cookie jar'ında herhangi bir tarayıcı gibi kalıcıdır ([wdenniss.com — In-app browsers and RFC 8252](https://wdenniss.com/in-app-browsers-and-rfc-8252)).

### 4.4 First-Party Apps draft'ı dengeyi nasıl değiştiriyor

**draft-ietf-oauth-first-party-apps-04**, yayın **1 Temmuz 2026**, Standards Track, son kullanma 2 Ocak 2027 ([IETF Datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04)).

Authorization Challenge Endpoint tanımlıyor: first-party client kullanıcıdan yetkilendirmeyi **native bir deneyimle** alabilir — "an entirely browserless OAuth 2.0 experience", yalnızca beklenmedik/yüksek riskli/hata durumlarında tarayıcıya devrediyor.

**Spec'in kendi güvenlik uyarıları — bunlar Argus için karar verici:**
1. **Kötü niyetli uygulama taklidi:** sahte uygulama kullanıcıyı credential'ı doğrudan kendisine vermeye kandırabilir
2. **Kullanıcı kafa karışıklığı:** "a new place the user is expected to enter their credentials" yaratıldığı için güvenli giriş konusunda kullanıcı eğitmek zorlaşıyor
3. **Client impersonation:** güçlü client authentication olmadan saldırgan meşru uygulamayı taklit edebilir; spec **işletim sistemi attestation API'lerini** öneriyor
4. **Credential stuffing:** doğrudan credential işleme yeni bir brute-force vektörü; session başına rate limiting öneriliyor
5. AS **her aşamada** kendi risk değerlendirmesine göre redirect tabanlı akış talep **edebilir** (`redirect_to_web` hatası; client bunu ele almak zorunda)
6. "designed to be used only for first-party applications when the authorization server also has a high degree of trust of the client"

**Yorum:** Bu draft, hosted login'in phishing direncini bilinçli olarak **feda ediyor** ve karşılığında UX alıyor. Argus'ta destekleyeceksek, client attestation zorunlu olmalı ve varsayılan kapalı olmalı.

---

## 5. MARKALAMA, ÖZELLEŞTİRME VE ÇOK KİRACILIK

### 5.1 Üç ürünün yaklaşımı

| Ürün | Motor | Kapsam | Kısıt |
|---|---|---|---|
| **Keycloak** | Apache FreeMarker | 5 tema tipi: login, account, admin, email, welcome. Realm başına seçilir; client login tema override edebilir | Tema JAR olarak `providers/` dizinine veya `themes/` klasörüne konur |
| **Auth0 Universal Login** | **Liquid** page template | Prompt etrafındaki içerik (login box, MFA challenge). Tüm sayfalarda aynı template | **Custom Domain zorunlu**; yalnızca Management API ile güncellenebilir; Liquid'de JavaScript desteği sınırlı; `{%- auth0:head -%}` zorunlu |
| **Okta** | Sign-In Widget + custom HTML/CSS/JS | Admin Console'da kod editörü; brand başına | **CSP zorlaması**; Enforced / Report-only modları |

### 5.2 Özelleştirmenin güvenlik maliyeti — evet, gerçek bir vektör

**Keycloak — en sert uyarı, kendi dokümanlarından** ([Keycloak — Working with themes](https://www.keycloak.org/ui-customization/themes)):

> "Themes contain FreeMarker templates that the server renders at runtime, so a malicious template can run code as the Keycloak process."

Öneri: "Install themes only from trusted sources, and restrict write access to the `themes` directory."

**Bu, çok kiracılı bir IdP için ölümcül bir bulgu.** Keycloak'ın tema modeli **kiracı-sağlamalı özelleştirme için tasarlanmamış** — server-side template execution demek, kiracının RCE alması demek. Argus çok kiracılı olacaksa Keycloak'ın FreeMarker modelini **kopyalamamalı**.

**Auth0'ın yaklaşımı** ([Auth0 — Customize Universal Login Page Templates](https://auth0.com/docs/customize/login-pages/universal-login/customize-templates)): Liquid, kasıtlı olarak **templating dili, script dili değil**. Auth0'ın kendi güvenlik notu: URL'lerde değer kullanmadan önce JavaScript/data şemalarına karşı doğrulama yapılmalı; "the character allowlist does not eliminate all XSS risk in every rendering context".

**Okta'nın yaklaşımı** — CSP allowlist:
- Sign-in ve error sayfalarından hangi URL'lere link verilebileceği kontrol ediliyor
- "All external resources that aren't in this list are considered untrusted and aren't allowed to appear"
- **Enforced** vs **Not enforced (Report-only)** modları + violation report URI
- Gerekçe: "prevents the introduction of potentially malicious code to these pages"
- Meta tag ile CSP özelleştirmesi önerilmiyor; Admin Console'daki trusted resources listesi kullanılmalı
- ⚠️ "Maksimum 20 URI" ve HTTP header boyut limiti uyarısı arama sonuç özetinde geçti ama Okta'nın fetch edilen sayfasında doğrulanamadı — **DOĞRULANMADI**
- Not: Okta'nın kendi widget'ı runtime'da inline script/style blokları enjekte ediyor ve bu sıkı CSP'yi ihlal edebiliyor; `cspNonce` parametresi bunun için var ([Okta Sign-In Widget](https://github.com/okta/okta-signin-widget)). Yani widget'ın kendisi CSP ile gerilim içinde.

**Argus için model:** Okta'nın CSP-allowlist + Auth0'ın script-siz templating dili kombinasyonu. Kiracıya **asla** server-side template execution verme. Kiracı-sağlamalı JS varsa, ayrı bir origin'de sandbox'lanmış iframe dışında kabul etme.

### 5.3 Kiracı başına custom domain — passkey RP ID sonucu

Bu, çok kiracılıkta en sert kısıt.

**Okta'nın belgelediği kurallar** ([Okta — Passkeys and custom domains](https://developer.okta.com/docs/guides/custom-passkeys/main/)):
- RP ID, çağıran origin'in **effective domain'i** ya da onun **kaydedilebilir bir alan adı soneki (registrable domain suffix)** olmalı. `login.example.com` origin'i için `login.example.com` **ve** `example.com` geçerlidir; `com` geçerli **değildir** — eTLD+1 alt sınırdır. ⚠️ *Düzeltme (2. inceleme turu): bu satır önceden ilişkiyi ters kuruyordu ("eTLD+1 veya onun suffix'i"), ki bu okuma `com`'u geçerli RP ID gösterirdi.*
- Okta custom domain (`login.globex.com`): standart custom domain kurulumuyla zaten doğrulanmış
- Root domain (`globex.com`): altında doğrulanmış bir custom domain **ve** ayrı TXT record doğrulaması gerekir
- **RP ID değişirse:** "Existing passkey enrollments aren't deleted when you set a new RP ID. Those enrollments remain in the system, but **the browser doesn't present them at sign-in**." → kullanıcı yeniden kaydolmak zorunda
- Auth0 tarafında da aynı: RP ID özelleştirilince diğer domain'lerdeki tüm passkey'ler kullanılamaz hale gelir; **custom domain passkey'lerden ÖNCE yapılandırılmalı** ([Auth0 passkey docs](https://auth0.com/docs/authenticate/database-connections/passkeys/configure-passkey-policy))

**Çok-domain çözümü: Related Origin Requests (ROR)** ([passkeys.dev — Related Origins](https://passkeys.dev/docs/advanced/related-origins/)):
- RP, RP ID domain'i altında `/.well-known/webauthn` barındırır (örn. `https://shopping.com/.well-known/webauthn`)
- Dosya, o RP ID kapsamında geçerli origin dizisini içerir
- Origin RP ID ile eşleşmezse client bu endpoint'i sorgular
- **Label limiti:** WebAuthn en az 5 benzersiz label desteği şart koşuyor; **5'ten fazlasını destekleyen bilinen client yok — 5 pratik maksimum**. Label başına onlarca ccTLD olabilir
- Runtime tespit: `PublicKeyCredential.getClientCapabilities()` içinde `relatedOrigins`
- Okta root domain RP ID için dosyayı **sen** barındırırsın; Okta custom domain için Okta barındırır

**Argus için sonuç:** Kiracı başına custom domain + passkey birlikte tasarlanmalı, sonradan eklenemez. Kiracı sayısı 5 label'ı aşacaksa (ki aşacak), her kiracı **kendi RP ID'sini** almalı — paylaşımlı RP ID + ROR ölçeklenmiyor. Bu da "kiracı domain değiştirirse passkey'leri ölür" gerçeğini kalıcı kılıyor; kiracı onboarding'inde domain kararı **geri dönülemez** olarak işaretlenmeli.

### 5.4 Yerelleştirme

**Auth0 Universal Login** ([Auth0 — Universal Login internationalization](https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization)):
- **80+ dil**, bölgesel varyantlar dahil
- **RTL:** Arapça (standart, Mısır, Suudi Arabistan), İbranice, Farsça, Urduca. **"Right-to-left language support is available in Early Access"** — WCAG 2.2 AA uyumu gerektiriyor ve HTML template'lerde `dir` elemanı olmalı
- Dil seçim önceliği: `ui_locales` → tenant'ta etkin diller → tarayıcı `Accept-Language` → varsayılan
- `enabled_locales` Management API ile ayarlanıyor
- **Sınırlar:** `ui_locales` yalnızca OAuth 2.0'da çalışır (SAML/WS-Fed'de değil); **upstream IdP'lere iletilmez**; consent sayfasındaki scope'lar yerelleştirilemez

**Keycloak** ([Keycloak Server Admin Guide — Themes/i18n](https://www.keycloak.org/docs/latest/server_admin/index.html#_themes)):
- Realm Settings > Localization'dan realm başına açılır
- Locale öncelik zinciri (7 kademe): kullanıcı UI seçimi → kullanıcı profil tercihi → client `ui_locales` → tarayıcı çerezi → `Accept-Language` → realm varsayılanı → İngilizce
- `kc_locale` parametresi de destekleniyor; seçim **kalıcı çerezde** saklanıyor
- Realm'e özgü metinler Localization sekmesinden **tema dosyalarını değiştirmeden** override edilebiliyor
- ⚠️ Varsayılan gelen locale listesi dokümanda açıkça listelenmiyor — **DOĞRULANMADI**

**Argus için:** Auth0'ın 7 kademeli fallback zinciri ve "realm/tenant-specific text override" (dosya değil, veri) modeli doğru desen. RTL'i Early Access'e bırakmak Auth0'ın bile 2026'da zorlandığını gösteriyor — Argus'ta baştan `dir` desteği ile başlamak daha ucuz.

---

## 6. HATA MESAJLARI VE KURTARMA UX'İ

### 6.1 OAuth hataları kullanıcıya ne zaman gösterilir

[RFC 6749 §4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1):

> "the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI."

Yani `redirect_uri` veya `client_id` geçersizse **redirect yasak**, kullanıcıya doğrudan hata gösterilmeli. Diğer tüm hatalar redirect ile client'a döner.

Authorization endpoint hata kodları: `invalid_request`, `unauthorized_client`, `access_denied`, `unsupported_response_type`, `invalid_scope`, `server_error`, `temporarily_unavailable`.

**Pratik ayrım:**
- **Kullanıcıya gösterilir:** geçersiz redirect_uri/client_id (redirect edilemez), `access_denied` (kullanıcının kendi kararı), `temporarily_unavailable`
- **Client'a redirect edilir, kullanıcıya ham gösterilmez:** `invalid_scope`, `unsupported_response_type`, `invalid_request` — bunlar geliştirici hataları; kullanıcıya "uygulama yanlış yapılandırılmış" tarzı bir mesaj + korelasyon ID gösterilmeli
- RFC 10017 §7.1'e göre first-party same-domain uygulamalarda bu karmaşıklığın çoğu zaten gereksiz

### 6.2 "Bu hesap kilitli" vs jenerik — giriş tarafında ne yapılıyor

**OWASP:** kilitli ve devre dışı hesaplar dahil **her durumda aynı mesaj** ([OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)). Ayrıca HTTP response **kodu** farklı olursa jenerik HTML'e rağmen sızıntı devam eder — kod da aynı olmalı. Zamanlama da eşitlenmeli.

**Keycloak'ın pratiği bunu doğruluyor:** brute-force ile kilitlenen kullanıcı giriş denediğinde **"Invalid username or password"** görüyor — geçersiz kullanıcı ve geçersiz parolayla **aynı mesaj**, saldırganın hesabın devre dışı olduğunu anlamaması için ([Keycloak brute-force docs](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/threat/brute-force.adoc)). Keycloak brute-force korumasını yalnızca **password, OTP ve recovery code**'lara uyguluyor.

**Çatışma OWASP tarafından açıkça kabul ediliyor:** jenerik mesajlar UX sürtünmesi yaratır, meşru kullanıcı kafası karışıp uygulamayı terk edebilir. Öneri: kritikliğe göre karar ver, jenerik mesajı CAPTCHA ile birleştir.

**Clerk'ün ürünleşmiş çözümü** (yukarıda, §1.2) bu çatışmayı bir **konfigürasyon boyutuna** çeviriyor — Argus'un almalı olduğu ders bu.

**Auth0'ın katmanları** ([Auth0 — Attack Protection](https://auth0.com/docs/secure/attack-protection)):
- **Bot Detection** — bot şüphesi olan IP'den geldiğinde CAPTCHA adımı tetikler
- **Suspicious IP Throttling** — çok sayıda hesapta hızlı identifier/parola denemesi
- **Brute-force Protection** — tek hesaba tekrarlı denemeler
- **Breached Password Detection** — üçüncü taraf ihlal veritabanları
- **Monitoring mode** — engellemeden yalnızca loglar (rollout için doğru desen)
- ⚠️ Varsayılan eşikler bu sayfada belgelenmiyor

### 6.3 Kullanıcı nerede takılıyor — gerçek dropoff verisi

**Doğrulanmış olan:**
- Android cross-device QR: tarayıcı prompt'undan QR taramasına **%29** geçiş — funnel'ın tek büyük kopuş noktası (§2.4)
- Windows web'de passkey başarısı **%45–60**, girişlerin **%40–65**'i cross-device gerektiriyor (Corbado Q1 2026)
- FIDO 2026: **%47** parola hatırlayamadığında satın almayı terk etme eğiliminde (anket, davranış değil)

⚠️ **DOĞRULANMADI — bunlar satıcı içeriği, kullanmayın:**
- "Parola tabanlı akışlarda tamamlanma %60–75, parola+SMS 2FA %50–65, passwordless %85–95"
- "Parola giriş adımında %15–25 terk"
- "%24 hesap oluşturmaya zorlanınca terk ediyor"
- "%21 giriş bilgilerini unuttuğu için satın almayı terk etti"
- "%46 ABD tüketicisi kimlik doğrulama başarısızlığı yüzünden işlemi tamamlamıyor"

Bunların hiçbiri için birincil metodoloji bulunamadı.

**Sonuç:** Genel giriş funnel dropoff'u için güvenilir kamuya açık veri **yok**. Argus'un kendi telemetrisini kurması şart — ve conditional UI'ın sessiz başarısızlığı (§2.2) yüzünden bu telemetri özel tasarım gerektiriyor.

---

## 7. ERİŞİLEBİLİRLİK

### 7.1 WCAG 2.2 SC 3.3.8 — ne yasaklıyor

[W3C — Understanding SC 3.3.8 Accessible Authentication (Minimum), Level AA](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html):

> "Authentication that relies on a cognitive function test does not block access to content or functionality."

Bir cognitive function test, adımlardan biri şunlardan **en az birini** sağlamadıkça istenemez:
1. **Alternative** — cognitive function test'e dayanmayan başka bir yöntem
2. **Mechanism** — testi tamamlamaya yardımcı olan bir mekanizma
3. **Object Recognition** — test, nesneleri tanımaktan ibaretse
4. **Personal Content** — kullanıcının kendi sağladığı metin dışı içeriği tanımaksa

**"Cognitive function test" tanımı:** "A task that requires the user to remember, manipulate, or transcribe information" — ezberleme, transkripsiyon, doğru yazım, hesaplama, bulmaca çözme. **İsim, e-posta ve telefon numarası gibi yaygın identifier'lar cognitive function test sayılmaz.**

**Sorularınıza doğrudan yanıtlar:**

- **"Parolanızın 3. karakterini girin" → EVET, YASAK.** Doküman açıkça diyor: kopyalanan metin ile input alanı arasında farklı format kullanmak (örn. "Enter the 1st, 3rd, and 5th character of your password") kullanıcıyı transkripsiyona zorlar ve **başka bir yöntem mevcut değilse bu kriteri geçemez**.
- **CAPTCHA → tamamen yasak değil, koşullu.** AA seviyesinde object recognition ve personal content **istisna**. Yani "arabaları seç" tipi CAPTCHA AA'da geçer. Ama **AAA (SC 3.3.9) bu istisnaları kaldırıyor** — object/image recognition orada da yasak ([Understanding SC 3.3.9](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-enhanced.html)).
- **Password manager / autofill engellemek → başarısızlık.** Site, user agent ve password manager'ların alanları otomatik doldurmasına izin vermeli. Aktif olarak engelleniyorsa ve alternatif yoksa sayfa kalıyor. SC 1.3.5 (Input Purpose) ve 4.1.2 (Name, Role, Value) ile birlikte değerlendirilmeli.
- **Paste engellemek → başarısızlık.** "Copy and paste can be relied on to avoid transcription."
- **OTP / 2FA:** "A service that requires **manual** transcription of a verification code is not compliant." Kullanıcı kodu yapıştırabilmeli. Donanım cihazı, biyometri, OS kimlik doğrulaması cognitive function test **değil**.
- **Çok adımlı akışlarda tüm adımlar uyumlu olmalı.**

**WebAuthn bir "sufficient technique"** — passkey desteklemek bu kriteri otomatik karşılıyor ([Passkey Central — Passkey Accessibility](https://www.passkeycentral.org/resources-and-tools/passkey-accessibility)).

**W3C'nin CAPTCHA notu** ([Inaccessibility of CAPTCHA, Group Draft Note, 16 Aralık 2021](https://www.w3.org/TR/turingtest/)): görme, işitme ve bilişsel engelli kullanıcılar için bariyer; ses alternatifleri de bozulmuş olduğu için anlaşılmaz. Önerilen alternatifler: **etkileşimsiz yöntemler** (spam filtreleme, proof-of-work, sezgisel yöntemler, honeypot, rate limiting — "non-interactive solutions pose no accessibility challenges"), **WebAuthn ile kriptografik personhood attestation**, Privacy Pass token'ları, federated identity.

**Argus için doğrudan tasarım kısıtı:** OWASP jenerik-hata + CAPTCHA önerisi (§6.2) ile WCAG 3.3.8 çatışıyor. Çözüm W3C'nin kendi önerisi: CAPTCHA yerine **etkileşimsiz** bot savunması (rate limiting, proof-of-work, honeypot, device signals) — bunlar hem erişilebilir hem enumeration'a karşı etkili.

### 7.2 EU Accessibility Act (EAA)

**Kapsam** ([Avrupa Komisyonu — European Accessibility Act](https://commission.europa.eu/strategy-and-policy/policies/justice-and-fundamental-rights/disability/union-equality-strategy-rights-persons-disabilities-2021-2030/european-accessibility-act_en)): bilgisayarlar ve işletim sistemleri, ATM'ler, biletleme ve check-in makineleri, akıllı telefonlar, dijital TV ekipmanı, telefon hizmetleri, görsel-işitsel medya erişimi, hava/otobüs/demiryolu/su yolu yolcu taşıma hizmetleri, **bankacılık hizmetleri**, e-kitaplar, **e-ticaret**. Üye devletlere ulusal hukuka aktarma tarihi Haziran 2022.

**28 Haziran 2025 — yürürlüğe girdi mi? Evet.** ⚠️ Ancak bu tarihi yalnızca ikincil kaynaklardan doğrulayabildim; EUR-Lex'e üç farklı URL üzerinden erişilemedi (boş içerik döndü), dolayısıyla **Article 31 metni birincil kaynaktan doğrulanamadı**.

İkincil kaynaklara göre ([Pivotal Accessibility, Eylül 2025](https://www.pivotalaccessibility.com/2025/09/eaa-enforcement-in-europe-following-the-june-2025-deadline/); [Level Access](https://www.levelaccess.com/compliance-overview/european-accessibility-act-eaa/)):
- Uygulama **28 Haziran 2025**'te başladı, 27 üye devletin tamamı transpoze etti
- 2025'in ikinci yarısında çoğu ulusal otorite kapasite kurdu; bazıları denetim yapıp resmî bildirim çıkardı
- **Kimi kapsıyor:** özel sektör — e-ticaret, bankacılık, telekom, ulaşım, **EU tüketicilerine hizmet veren SaaS platformları, şirketin merkezi nerede olursa olsun**
- **Muafiyet:** yalnızca mikro-işletmeler — **10'dan az çalışan ve €2 milyon altı ciro**

⚠️ **Mikro-işletme muafiyetinin tam metni (Article 4(5)) ve EN 301 549 ile ilişkisi birincil kaynaktan DOĞRULANMADI.**

**Argus'a etkisi:** Argus bir SaaS IdP olarak, EU tüketicilerine hizmet veren müşterilerinin giriş akışını sağlıyor. Müşterimiz kapsamdaysa **bizim login sayfamız da fiilen kapsamda** — çünkü kullanıcının gördüğü ekran bizim. Bu, WCAG 2.2 AA'yı bir "nice to have" değil **satış engeli** yapıyor. Auth0'ın RTL desteğini "WCAG 2.2 AA compliance gerektirir" diye şartlaması da aynı baskının işareti.

### 7.3 Ekran okuyucu ile WebAuthn deneyimi

**FIDO Alliance / Passkey Central denetimi** ([Passkey Accessibility](https://www.passkeycentral.org/resources-and-tools/passkey-accessibility)):

Test matrisi: Windows/Chrome/JAWS, Windows/Chrome/NVDA, Windows/Edge, Mac/Safari/VoiceOver, iPhone varyantları.

Bulgular:
- **İyi haber:** "Passkey registration and sign-in procedures were consistently accessible" — platform yönetimi sürtünmeyi azaltıyor
- **Kötü haber 1 — autofill:** conditional UI canlı dağıtımlarda **tutarsız implemente edilmiş**, ekran okuyucu kullanıcıları için tutarsız deneyim. Doğru davranış: ekran okuyucuya **"has popup"** duyurulmalı ki kullanıcı aşağı ok tuşuyla gezinebileceğini bilsin
- **Kötü haber 2 — QR kodları:** "QR codes introduce barriers for individuals with mobility limitations or with vision limitations" — cihazı sabit tutmak veya kodu görsel olarak bulmak gerekiyor
- **Kötü haber 3:** erişilebilirlik kusurları çoğunlukla **sitenin genelinde** yaygın, sadece kimlik doğrulamada değil

FIDO'nun 2023 kullanılabilirlik araştırması kör/az gören, TalkBack/VoiceOver kullanan katılımcıları içeriyordu ([Passkey Central Design Guidelines](https://www.passkeycentral.org/design-guidelines/)).

**Argus için:** QR tabanlı cross-device akışı **tek yol olamaz** — hem %29 dönüşüm (§2.4) hem erişilebilirlik nedeniyle. Her zaman bir alternatif (e-posta magic link, TOTP, recovery code) sunulmalı.

---

## 8. ARGUS İÇİN GİRİŞ AKIŞI TASARIM KARARLARI

**1. Identifier-first varsayılan olsun, ama enumeration davranışı kiracı başına yapılandırılabilir bir MOD olsun — tek bir davranış değil.**
Clerk'ün "bulk protection" (rate limit + normal UX) / "strict protection" (varlık gizli, sahte kod gönderilmez) ikilisini modelle. Strict modun neyi imkânsız kıldığını (username identifier, password başlangıç stratejisi, invite-only) dokümante et. Kaynak: [Clerk](https://clerk.com/docs/guides/secure/user-enumeration-protection)

**2. Identifier adımının çıktısını sabit yap: aynı HTTP status, aynı gövde boyutu, aynı gecikme.**
OWASP hem "quick exit" zamanlama sızıntısını hem de jenerik HTML'e rağmen farklı HTTP kodunun sızdırdığını açıkça belirtiyor. Kilitli ve devre dışı hesap dahil tek mesaj. Kaynak: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

**3. Identifier-first'ü atlayan bir "Passkey ile giriş yap" yolu her zaman sun.**
Boş `allowCredentials` + discoverable credential ile sunucuya hiçbir identifier sızmaz; enumeration yüzeyi sıfırlanır. Kaynak: [Corbado](https://www.corbado.com/blog/passkey-login-best-practices/account-enumeration-risk-passkeys), [web.dev](https://web.dev/articles/passkey-form-autofill)

**4. Home Realm Discovery'yi varsayılan olarak KAPALI tut; açıksa hedef kiracıyı kullanıcıya onaylat.**
Microsoft auto-acceleration'a karşı tavsiye veriyor (FIDO'yu engelliyor, guest'leri kırıyor) ve Nisan 2023'ten beri domain confirmation dialog gösteriyor — bunu "security hardening" olarak tanımlıyor. Kaynak: [Microsoft Entra HRD](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/home-realm-discovery-policy)

**5. Client'ın gönderdiği `domain_hint`/`login_hint` benzeri parametreler kiracı politikasını EZMESİN.**
Microsoft'ta domain hint HRD policy'yi eziyor ve bunu düzeltmek için ayrı bir `DomainHintPolicy` (Ignore/Respect × Domains/Apps) katmanı gerekti. Argus'ta baştan doğru sırayı kur: kiracı politikası > client hint. Kaynak: [Microsoft — Disable auto-acceleration](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/prevent-domain-hints-with-home-realm-discovery)

**6. Conditional UI'ı destekle ama ASLA tek yol yapma; her zaman açık bir passkey butonu + `AbortController`.**
Conditional UI Windows 10, eski ChromeOS ve in-app browser'larda sessizce hiçbir şey göstermez; site bunu ölçemez bile. Kaynak: [web.dev](https://web.dev/articles/passkey-form-autofill), [Corbado](https://www.corbado.com/blog/webauthn-conditional-ui-passkeys-autofill)

**7. Telemetriyi conditional UI'ın körlüğünü telafi edecek şekilde tasarla.**
"Dropdown göründü mü, boş mu geldi, kullanıcı yok saydı mı" ayırt edilemiyor. Bunun yerine: `getClientCapabilities()` sonucunu, identifier alanına odaklanma olayını, ve conditional promise'in çözülüp çözülmediğini ayrı ayrı ölç. Kaynak: [Corbado](https://www.corbado.com/blog/webauthn-conditional-ui-passkeys-autofill)

**8. Platform tespit et ve cross-device QR'ı son çare yap — özellikle Windows'ta.**
Windows web'de passkey başarısı %45–60 ve girişlerin %40–65'i cross-device gerektiriyor; Android'de tarayıcı prompt'undan QR taramasına geçiş sadece %29. Windows kullanıcısına passkey'i tek yol olarak dayatma. Kaynak: [Corbado Benchmark 2026](https://www.corbado.com/passkey-benchmark-2026/passkey-authentication-success-rate), [Google Authenticate 2025 funnel](https://mojoauth.com/blog/cross-device-passkey-qr-flow-where-users-drop-off)

**9. WebAuthn Signal API'yi 1. günden implemente et — ama `signalAllAcceptedCredentials`'ı sadece doğrulanmış kullanıcı ve TAM listeyle çağır.**
`signalUnknownCredential` oturum kapalıyken güvenli (tek credential ID, sayı sızdırmaz) — başarısız passkey denemesinden sonra çağır. Kısmi liste meşru passkey'leri gizler. Chrome/Edge 132+. Kaynak: [Chrome for Developers](https://developer.chrome.com/docs/identity/webauthn-signal-api)

**10. Push onayında number matching'i zorunlu yap; tek istisna aynı-cihaz tespiti.**
Microsoft'ta artık tüm Authenticator push'larında zorunlu, opt-out yok. Aynı cihazda başlatılan girişte Yes/No'ya izin veriyor ve bunun risk artırmadığını gerekçelendiriyor. Wearable'lar kapsam dışı. Kaynak: [Microsoft — Number matching](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match)

**11. "Beni hatırla"yı iki katmanlı yap: idle timeout + absolute lifetime, ve politika olayında zorunlu iptal.**
Auth0: idle 7 gün (1s–30g), absolute 30 gün (1s–90g). Microsoft: 1–365 gün tek katman + "en kısıtlayıcı politika kazanır". Asıl güvenlik mekanizması süre değil, **olay tabanlı iptal** (parola değişimi, MFA yöntemi değişimi, cihaz uyumsuzluğu, admin revoke). Kaynak: [Auth0](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa), [Microsoft](https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-azure-multi-factor-authentication-prompts-session-lifetime)

**12. Agresif yeniden kimlik doğrulamadan kaçın — Microsoft bunu bir güvenlik RİSKİ olarak belgeliyor.**
"If users are trained to enter their credentials without thinking, they can unintentionally supply them to a malicious credential prompt." Entra varsayılanı 90 günlük kayan pencere. Sık prompt phishing'e yardım eder. Kaynak: [Microsoft](https://learn.microsoft.com/en-us/entra/identity/authentication/concepts-azure-multi-factor-authentication-prompts-session-lifetime)

**13. RFC 9470 step-up'ı destekle ve `acr_values` ile `max_age` arasındaki zorlama farkını doğru uygula.**
`acr_values` tavsiye (MAY), `max_age` zorunlu (MUST re-authenticate). Ve step-up ekranında kullanıcıya **neden** yeniden doğrulama istendiğini açıkla — aksi halde madde 12'deki phishing riskini kendin yaratırsın. Kaynak: [RFC 9470](https://www.rfc-editor.org/info/rfc9470/)

**14. Hosted (redirect) login'i tek desteklenen üretim modu yap; embedded'ı desteklersen custom domain zorunlu kıl.**
Okta: embedded'da "XSS attacks on your app may result in stolen sign-in credentials"; hosted "the recommended method for the highest levels of identity security". Auth0 cross-origin auth üçüncü taraf çerezlere bağlı ve modern tarayıcılarda **başarısız olabilir** — çözüm aynı top-level domain. Kaynak: [Okta](https://developer.okta.com/docs/concepts/redirect-vs-embedded/), [Auth0](https://auth0.com/docs/authenticate/login/cross-origin-authentication)

**15. SPA müşterilerine BFF'i resmî öneri yap; dokümantasyonda RFC 10017'nin kendi ifadesini alıntıla.**
§6.1 BFF en güvenli; §6.3.4.3 tarayıcı-içi OAuth client "not recommended for business applications, sensitive applications, and applications that handle personal data". Implicit grant **MUST NOT**. Refresh token varsa rotation veya sender-constrained zorunlu. Kaynak: [RFC 10017](https://www.rfc-editor.org/info/rfc10017/)

**16. Argus'un kendi admin console'u ve hosted login'i için OAuth değil, doğrudan session cookie kullan.**
RFC 10017 §7.1: "Simple applications are made needlessly complex by using OAuth to replace the concept of session management." Aynı domain'deki first-party UI'da OAuth gereksiz karmaşıklık. Kaynak: [RFC 10017 §7.1](https://www.rfc-editor.org/info/rfc10017/)

**17. Native SDK'da sistem tarayıcısı zorunlu; First-Party Apps akışını destekleyeceksen varsayılan KAPALI + client attestation zorunlu.**
RFC 8252 hâlâ geçerli. Authorization Challenge Endpoint draft'ının kendi güvenlik bölümü uygulama taklidi, kullanıcı kafa karışıklığı, client impersonation ve credential stuffing risklerini sayıyor ve OS attestation API'lerini öneriyor; AS her aşamada `redirect_to_web` ile tarayıcıya düşürebilmeli. Kaynak: [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html), [draft-ietf-oauth-first-party-apps-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04)

**18. Kiracıya ASLA server-side template execution verme — Keycloak'ın FreeMarker modelini kopyalama.**
Keycloak kendi dokümanında: "a malicious template can run code as the Keycloak process." Bu, kiracı-sağlamalı temalarda RCE demektir. Kaynak: [Keycloak — Working with themes](https://www.keycloak.org/ui-customization/themes)

**19. Özelleştirmeyi script-siz templating (Liquid tarzı) + CSP allowlist ile sınırla; Report-only modu sun.**
Auth0 Liquid'i "templating, not complex scripts" olarak konumlandırıyor ve yine de "character allowlist does not eliminate all XSS risk in every rendering context" uyarısı veriyor. Okta CSP'de Enforced/Report-only + violation report URI sunuyor — rollout için doğru desen. Kaynak: [Auth0](https://auth0.com/docs/customize/login-pages/universal-login/customize-templates), [Okta CSP](https://help.okta.com/oie/en-us/content/topics/security/healthinsight/csp-customization.htm)

**20. Kiracı custom domain'ini passkey'lerden ÖNCE zorunlu kıl ve domain değişimini geri dönülemez olarak işaretle.**
Okta: RP ID değişince eski kayıtlar silinmiyor ama "the browser doesn't present them at sign-in" — kullanıcı yeniden kaydolmak zorunda. Auth0 aynı. ROR (`/.well-known/webauthn`) pratikte **5 label** ile sınırlı, çok kiracılıkta ölçeklenmiyor → her kiracı kendi RP ID'sini almalı. Kaynak: [Okta — Passkeys and custom domains](https://developer.okta.com/docs/guides/custom-passkeys/main/), [passkeys.dev ROR](https://passkeys.dev/docs/advanced/related-origins/)

**21. Geçersiz `redirect_uri`/`client_id`'de redirect etme, kullanıcıya hata göster; diğer OAuth hatalarını kullanıcıya ham gösterme.**
RFC 6749 §4.1.2.1: "MUST NOT automatically redirect the user-agent to the invalid redirection URI." Geliştirici hataları için kullanıcıya sadece korelasyon ID'li nazik bir mesaj. Kaynak: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1)

**22. CAPTCHA yerine etkileşimsiz bot savunması kullan — hem WCAG hem etkinlik açısından.**
W3C: "non-interactive solutions pose no accessibility challenges" — rate limiting, proof-of-work, honeypot, sezgisel yöntemler, WebAuthn ile personhood attestation. CAPTCHA AA'da object recognition istisnasıyla geçer ama AAA'da geçmez. Kaynak: [W3C Inaccessibility of CAPTCHA](https://www.w3.org/TR/turingtest/), [Understanding SC 3.3.9](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-enhanced.html)

**23. Paste'i asla engelleme; password manager autofill'i asla bloklama; OTP alanlarını tek-alan yapıştırılabilir yap.**
SC 3.3.8: manuel transkripsiyon gerektiren doğrulama kodu uyumlu değil; "Enter the 1st, 3rd, and 5th character" **doğrudan başarısız**. `autocomplete` ve SC 1.3.5 Input Purpose'a uy. Kaynak: [W3C Understanding SC 3.3.8](https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html)

**24. WCAG 2.2 AA'yı satış gereksinimi olarak ele al, kozmetik olarak değil.**
EAA 28 Haziran 2025'ten beri uygulanıyor; e-ticaret, bankacılık ve EU tüketicilerine hizmet veren SaaS kapsamda, şirket merkezi neresi olursa olsun; muafiyet yalnızca 10 kişiden az / €2M altı mikro-işletmeler. Auth0 bile RTL desteğini WCAG 2.2 AA şartına bağlıyor. Kaynak: [Avrupa Komisyonu](https://commission.europa.eu/strategy-and-policy/policies/justice-and-fundamental-rights/disability/union-equality-strategy-rights-persons-disabilities-2021-2030/european-accessibility-act_en), [Auth0 i18n](https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization)

**25. Conditional UI'da ekran okuyucuya "has popup" duyur; QR'ı tek yol yapma.**
FIDO denetimi: passkey kayıt/giriş prosedürleri tutarlı biçimde erişilebilir, ama **autofill tutarsız implemente edilmiş** ve QR kodları hareket/görme kısıtlı kullanıcılar için bariyer. Kaynak: [Passkey Central — Accessibility](https://www.passkeycentral.org/resources-and-tools/passkey-accessibility)

**26. Yerelleştirmeyi çok kademeli fallback + tenant-level metin override ile kur; `dir` desteğini baştan koy.**
Keycloak 7 kademeli zincir (kullanıcı seçimi → profil → `ui_locales` → çerez → `Accept-Language` → realm varsayılanı → İngilizce) ve tema dosyası değiştirmeden realm-specific override sunuyor. Auth0 80+ dil ama RTL hâlâ Early Access ve `ui_locales` upstream IdP'lere iletilmiyor — Argus bunu iletmeyi hedeflemeli. Kaynak: [Keycloak](https://www.keycloak.org/docs/latest/server_admin/index.html#_themes), [Auth0](https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization)

**27. FIDO'nun iki "zorunlu deseni"ni ürün gereksinimi olarak kabul et.**
(1) Account Settings'te passkey oluşturma/görme/yönetme, (2) passkey ile giriş + **zarif fallback**. "Fallback yok" bir seçenek değil. Kaynak: [Passkey Central Design Guidelines](https://www.passkeycentral.org/design-guidelines/)

**28. Attack protection'a "monitoring mode" ekle.**
Auth0 bot detection / suspicious IP throttling / brute-force / breached password'ün her birini engellemeden yalnızca loglayan bir modda çalıştırabiliyor. Kiracı bir korumayı açmadan önce etkisini ölçebilmeli. Kaynak: [Auth0 Attack Protection](https://auth0.com/docs/secure/attack-protection)

---

## 9. DOĞRULANAMAYANLAR

**Benimseme / dönüşüm rakamları:**
1. ⚠️ FIDO 2026 raporundaki tüm yüzdeler **anket verisi** (Sapio Research, n=11.000 tüketici + 1.400 karar verici), telemetri değil. "%75 passkey etkinleştirdi" beyan, ölçüm değil.
2. ⚠️ FIDO Passkey Index'in "%30 dönüşüm artışı / %93 vs %63" rakamı **9 FIDO üyesine yapılan gizli anketten** agrege; bağımsız denetim yok.
3. ⚠️ Corbado Passkey Benchmark 2026'nın platform bazlı başarı oranları — metodoloji ayrıntıları ücretli katmanda; örneklem bileşimi bilinmiyor.
4. ⚠️ "Google Authenticate 2025 funnel verisi" Corbado üzerinden ikinci elden; Google'ın orijinal sunumu doğrulanamadı.
5. ⚠️ Google (%63,8/%13,8) ve Microsoft (%98/%32) rakamları birincil ama **seçim yanlılığı** içeriyor — passkey kuran kullanıcı zaten aktif ve cihazı elinde olan kullanıcı.
6. ⚠️ "Parola akışlarında tamamlanma %60–75, passwordless %85–95", "%24 hesap zorunluluğunda terk", "%21 şifre unutunca terk", "%46 auth başarısızlığından terk" — hepsi satıcı içeriği, birincil metodoloji yok. **Kullanmayın.**
7. ⚠️ Conditional UI'ın dönüşüm etkisine dair bağımsız sayısal veri **yok**. "Benimsemedeki en büyük kaldıraç" iddiası doğrulanamadı.
8. ⚠️ "FIDO kullanıcı testi (2024–2025): katılımcıların ~yarısı telefonu almaya gitmekten caydı" — MojoAuth üzerinden aktarım, FIDO'nun kendi yayınında bulunamadı.

**Ürün / tarih detayları:**
9. ⚠️ Entra'da parola kutusunun Haziran 2026 sonuna kadar kaldırılacağı — ikincil kaynaklar (Trackr.Live, PCWorld); Microsoft'un birincil duyurusunda doğrulanamadı.
10. ⚠️ Okta CSP'de "maksimum 20 trusted URI" ve HTTP header boyut limiti — arama özetinde geçti, Okta'nın fetch edilen sayfasında doğrulanamadı.
11. ⚠️ Auth0 attack protection varsayılan eşikleri belgelenmemiş.
12. ⚠️ Keycloak'ın varsayılan gelen locale listesi resmî dokümanda açıkça listelenmiyor.
13. ⚠️ Microsoft'un "Remember MFA için 90 gün önerisi" — ikincil kaynaktan; fetch edilen Entra dokümanında bu sayı geçmiyor (doküman CA Sign-in frequency'ye göçü öneriyor).
14. ⚠️ "Number matching canlı ortamlarda MFA fatigue saldırılarını ortadan kaldırdı" — Microsoft'un birincil yayınında sayısal karşılık bulunamadı.

**Mevzuat:**
15. ⚠️ **EAA Article 31 (uygulama tarihi), Article 2 (kapsam), Article 4(5) (mikro-işletme muafiyeti), Article 15 (harmonize standartlar) birincil metinden DOĞRULANMADI** — EUR-Lex'e üç farklı URL formatıyla erişilemedi (boş içerik). 28 Haziran 2025 tarihi ve €2M/10 çalışan eşiği yalnızca ikincil kaynaklardan. **Hukuki karar vermeden önce EUR-Lex'ten doğrulanmalı.**
16. ⚠️ EAA'nın EN 301 549 ve WCAG ile resmî ilişkisi birincil kaynaktan doğrulanamadı.

**Tarihsel:**
17. ⚠️ Google'ın 2015 identifier-first geçişine ait resmî tasarım gerekçesi bulunamadı.
