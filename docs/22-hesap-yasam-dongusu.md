# 22. Hesap yaşam döngüsü

> `ARGUS.md` §22'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§22 §X` referansları aynı anlamda.


**Kapsam:** Hesap kurtarma, hesap bağlama/birleştirme, impersonation, kullanıcı yaşam döngüsü, IdP göçü, kayıt/onboarding güvenliği, B2B organizasyon akışları.
**Neden bu doküman:** Protokol, kripto, HA ve yetkilendirme standartlaşmıştır — spec okur, uygularsın. Bu dosyadaki yedi akışın **hiçbiri standart değildir**. Her ürün kendi tasarımını yapar, tasarım hataları ürüne özgüdür ve saldırganların 2026'da fiilen kullandığı yüzey burasıdır.

**Yöntem:** NIST SP 800-63B-4 ve FIDO Alliance dokümanları ham metin olarak indirilip bölüm bölüm okundu (özet aracıyla yetinilmedi; bir vakada özet aracı uydurma alıntı üretti ve PDF doğrudan çözülerek düzeltildi). CVE'ler, satıcı dokümanları ve olay raporları birincil kaynaklardan doğrulandı.

> **Doğrulama notu:** Her iddia bir birincil kaynağa dayanır. Doğrulanamayan noktalar ⚠️ ile satır içinde işaretlenmiştir. Rakam, tarih veya URL uydurulmamıştır.

---

### İçindekiler

| Bölüm | Konu | §§ |
|---|---|---|
| **I** | **Hesap kurtarma** — NIST SP 800-63B-4 §4.2, dört kurtarma sınıfı, AAL matrisi, cooldown, Scattered Spider | 1-10 |
| **II** | **Hesap bağlama ve birleştirme** — pre-hijacking'in beş varyantı, `email_verified`'in yetersizliği, nOAuth, tanımlayıcı geri dönüşümü, birleştirmenin geri alınamazlığı | 11-16 |
| **III** | **Impersonation** — RFC 8693 delegasyon vs impersonation, `act`/`may_act`, on ürünün karşılaştırması, Twitter 2020 | 17-21 |
| **IV** | **Kullanıcı yaşam döngüsü, silme, tombstone** — SCIM'in boşlukları, RFC 9967, crypto-shredding, GDPR Md. 17 vs KVKK Md. 7, atıl hesaplar, taşınabilirlik | 22-29 |
| **V** | **Kayıt ve onboarding güvenliği** — NIST 63A sahtekârlık programı, CAPTCHA'nın ölümü, Privacy Pass, tek kullanımlık e-posta, enumeration | 30-35 |
| **VI** | **IdP göçü** — ürün ürün hash dışa/içe aktarımı, tembel göç, format uyumluluğu, göç edilemeyenler | 36-43 |
| **VII** | **B2B organizasyon akışları** — davet güvenliği, alan adı doğrulaması, sahiplik devri, break-glass, SSO zorlaması, SAMLjacking | 44-49 |

**Her bölüm bir "Argus kararları" tablosuyla biter.** Bu tablolar, mimari karar dokümanının ham girdisidir.

---

### 0. Yönetici özeti — on iki bulgu

1. **NIST SP 800-63B-4 §4.2 hesap kurtarmayı tamamen yeniden yazdı.** Rev-4'ün değişiklik kaydı bunu açıkça söylüyor: *"Section 4.2: Revises the requirements and methods for account recovery."* Artık dört kurtarma sınıfı, AAL'e göre normatif kombinasyon kuralları ve kurtarma kodları için mutlak TTL tavanları var. Rev-3'e göre tasarlanmış her IdP bu bölümde geride kaldı.

2. **AAL2 kurtarma için NIST tek bir kanıt kabul etmiyor.** Ya *farklı sınıflardan iki kurtarma kodu*, ya *bir kurtarma kodu + hesaba bağlı bir authenticator*, ya da *kimlik tespiti tekrarı*. Yaygın ürün davranışı olan "e-postaya link gönder, parolayı sıfırla" tek başına AAL2 kurtarma değildir.

3. **"Kurtarma korunan şeyden zayıf olamaz" ilkesinin birincil kaynağı FIDO Alliance'tır ve 2019'dan beri yazılıdır:** *"Implementing weaker account-recovery options is not recommended by the FIDO Alliance."* 2025 whitepaper'ı bunu sertleştirdi: *"The prohibition of phishable methods applies to both login and account recovery processes."*

4. **Netcraft'ın 7 Nisan 2026 öngörüsü doğrulandı ve kaynağı bulundu.** Yazı gerçek (yazar: Ginny Spicer) ve dört istismar yolunu FIDO'nun Mart 2025 whitepaper'ının §2.1–2.4'ünden alıyor. Ana cümle: *"This method is likely to become the most used of those highlighted by the FIDO Alliance."*

5. **NIST, senkron passkey'lerin kurtarma zafiyetini kendi metninde kabul ediyor:** *"Synced keys are accessible via cloud-based account recovery processes, which represent a potential weakness to the authenticators."* Yani passkey'in gücü, platform hesabının kurtarma akışının gücüyle sınırlıdır — ve o akış senin kontrolünde değildir.

6. **Soğuma süresinin amacı gecikme değil, itiraz penceresidir.** Google bunu açıkça yazıyor: gecikme boyunca kullanıcı bilgilendirilir *"so if someone else is trying to access your account, you have time to deny the request."* Ve ters orantı kuralı: hesabın koruması arttıkça gecikme **uzuyor**.

7. **Apple, "zayıf yolu kapat" toggle'ını ürünleştirmiş tek büyük sağlayıcı.** Recovery Key açıldığında *"you turn off Apple's standard account recovery process"* ve kaybedilirse *"you'll be locked out of your account permanently."* Bu, ilkenin en saf ticari uygulaması: kullanıcıya kalıcı kayıt riskini açıkça satıyor.

8. **Keycloak aynı sınıf kurtarma hatasını altı yıl arayla iki kez yaptı.** CVE-2020-1718 ve CVE-2026-18963 (CVSS 9.1, 24 Ağustos 2026) — ikisi de reset-credentials akışında kimlik doğrulama atlatma. İkincisinde saldırgana gereken tek şey bir kullanıcı adı; sonuç admin dahil her hesabın ele geçirilmesi.

9. **Daha derin ders açık duran bir issue'da:** Keycloak #40744, `reset-credentials-choose-user` provider'ının kullanıcıyı **doğrulamadan önce** authentication context'e bağladığını gösteriyor. Akıştan bir adım silmek auth bypass üretiyor. **Kurtarmayı silinebilir adımlardan oluşan genel amaçlı pluggable flow yapmak, yanlış konfigürasyonu güvenlik açığına çeviren bir mimari seçimdir.** Argus'un en net ayrışma noktalarından biri budur.

10. **Unit 42 (3 Ağustos 2026) kurtarma akışını bir saldırı primitifi olarak gösterdi.** "Golden Pass-ta-key" saldırısı, passkey durum dosyalarını silerek cihazı **yeniden onboarding'e zorluyor** ve o pencerede master anahtarı çıkarıyor. IdP tarafındaki azaltım listesinde birinci madde: kurtarma/onboarding akışlarının gereksiz yere yeniden tetiklenmesini tespit et ve kısıtla.

11. **Kurtarma bildirimlerinde NIST'in unutulan kuralı:** kurtarma kodunun gönderildiği adres hesaptaki tek diğer bildirim adresiyse, bildirim **posta adresine** gitmek zorunda. Mantık genellenebilir: *kurtarma kanalı, kurtarma bildiriminin kanalı olamaz.* Çoğu ürün bunu ihlal ediyor.

12. **Parola sıfırlama ≠ hesap kurtarma.** NIST bunu normatif olarak ayırıyor: kullanıcı hâlâ başka bir authenticator ile doğrulanabiliyorsa, unutulan parolanın değişimi **yeni authenticator bağlama**dır (§4.1.2.1), kurtarma değil. Bu ayrım veri modeline girmezse iki farklı risk profili tek akışta birleşir — Keycloak'ın hatası tam olarak buydu.

---

## BÖLÜM I — HESAP KURTARMA

### 1. Neden kurtarma passkey mimarisinin gerçek zayıf halkası

Passkey'in kriptografisi kırılmıyor. Kırılan, passkey'in **etrafındaki** akışlar. FIDO Alliance'ın Mart 2025 whitepaper'ı bunu doğrudan söylüyor:

> *"Note that the root cause of these attacks is not passkeys themselves, but rather issues with passkey deployments."*
> — FIDO Alliance, *Passkeys: The Journey to Prevent Phishing Attacks*, Part 2, Mart 2025

Aynı doküman §2'de passkey dağıtılmış RP'lerde dört zafiyet başlığı sayıyor:

| # | FIDO Pt2 §2 başlığı | Mekanizma |
|---|---|---|
| 2.1 | Passwords as vulnerabilities to bypass passkey authentication | Parola alternatif giriş yolu olarak duruyor; saldırgan passkey'e hiç dokunmuyor |
| 2.2 | Unauthorized passkey registration in compromised accounts | Passkey kaydı sadece parola ile yapılabiliyor; saldırgan phishing'le parolayı alıp **kendi passkey'ini** kaydediyor |
| 2.3 | Exploit account recovery mechanisms to bypass passkey authentication | Kurtarma e-posta/SMS OTP'ye dayanıyor; saldırgan birincil akışı hiç denemiyor |
| 2.4 | Social engineering attacks to downgrade account security level | Kullanıcıya passkey'i kapattırma |

**2.2 üzerine kritik not:** Bu, "passkey ekledik, artık phishing-resistant'ız" diyen ürünlerin en sık yaptığı hata. FIDO'nun tarifi: *saldırgan önce phishing ile parolayı alıp ilk erişimi sağlar, sonra yüksek riskli işlemler için konulmuş korumayı aşmak üzere kendi passkey'ini kaydeder.* Passkey artık saldırganın elinde ve **kalıcı**dır — parolayı değiştirmek onu düşürmez.

#### 1.1 Netcraft öngörüsü — doğrulandı

Kullanıcının sorduğu Netcraft öngörüsü **gerçektir**:

| Alan | Değer |
|---|---|
| Başlık | *Phishing After Passkeys: What Attacks to Expect* |
| Yayın | **7 Nisan 2026** |
| Yazar | Ginny Spicer |
| URL | https://www.netcraft.com/blog/phishing-after-passkeys-what-attacks-to-expect |

Ana cümle, hesap kurtarma başlığı altında:

> *"This method is likely to become the most used of those highlighted by the FIDO Alliance for exploitation of systems that allow passkeys but haven't completely outgrown passwords yet."*

**Dayanağı:** Netcraft dört yolu kendisi türetmiyor — FIDO Alliance'ın Mart 2025 whitepaper'ının §2.1–2.4'ünü referans alıyor ve içlerinden kurtarmayı en olası olarak işaretliyor. Downgrade saldırısı için açıkça *"a less likely option compared to the others"* diyor. Yazının veri tabanı: Q2 2025 itibarıyla masaüstü cihazların %98'i, mobilin %95'i passkey destekliyor — yani kapsama sorunu bitti, geriye **fallback ve kurtarma** kaldı.

**Argümanın yapısı şu:** passkey benimsemesi arttıkça saldırganın birincil akışa saldırma getirisi düşer; kurtarma akışına saldırma getirisi sabit kalır. Oran değişince trafik oraya kayar. Bu bir tahmin değil, bir ekonomik zorunluluk.

#### 1.2 NIST'in senkron passkey itirafı

NIST SP 800-63B-4 Appendix B (Syncable Authenticators), senkron passkey'lerin zayıflığını doğrudan yazıyor:

> *"Synced keys are accessible via cloud-based account recovery processes, which represent a potential weakness to the authenticators."*

Ve revocation'ın çözülmemiş olduğunu:

> *"Since syncable authenticators use RP-specific keys, the ability to centrally revoke access based on those keys is challenging. For example, with traditional PKI, CRLs can be used centrally to revoke access. A similar process is not available for syncable authenticators or any FIDO WebAuthn-based credentials."*

**Sonuç:** Senkron passkey'i kabul eden bir RP, güvenliğini **platform hesabının kurtarma akışına** devretmiştir. Apple ID veya Google hesabı kurtarılabiliyorsa, o hesaptaki tüm passkey'ler kurtarılabilir. Bu senin kontrolünde değildir ve bu yüzden RP kendi bağımsız kurtarma politikasını korumak zorundadır.

NIST'in Appendix B'deki azaltım listesi (sync fabric ve kurtarma başlığı altında):

- *"Implement authentication recovery processes that are consistent with SP 800-63B."*
- *"Bind multiple authenticators at AAL2 and above to support recovery."*
- *"Require AAL2 authentication to add any new authenticators for user access to the sync fabric."*
- *"Notify the user of any recovery activities."*
- *"Leverage a user-controlled secret (i.e., something not known to the sync fabric provider) to encrypt and recover keys."*

Son madde Apple'ın Advanced Data Protection'ının tam olarak yaptığı şeydir.

#### 1.3 Unit 42: kurtarma akışı bir saldırı primitifi

**"Pass the Passkey"**, Arie Olshtein, Unit 42 / Palo Alto Networks, **3 Ağustos 2026** — https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/

Hedef: Google senkron passkey ekosistemi, Windows + TPM. Üç saldırı:

| Saldırı | Mekanizma | Sonuç |
|---|---|---|
| **Pass-ta-key** | Yetkisiz malware Chrome'un wrapped identity key'ini diskten alır, Windows CNG API'leriyle challenge imzalar | Kullanıcı etkileşimi veya cihaz kilidi açma olmadan cihazı cloud authenticator'a karşı taklit eder |
| **Silver Pass-ta-key** | Passkey state dosyalarını **siler** → cihazı yeniden onboarding'e zorlar → "pending UV key" fazında saldırgan kontrollü doğrulama anahtarı kaydeder | UV (user verification) zorunlu olsa bile tam hesap ele geçirme |
| **Golden Pass-ta-key** | Yeniden onboarding'e zorlar, Chrome process belleğinden **Security Domain Secret**'ı çıkarır | Tüm senkron passkey özel anahtarları offline çözülebilir |

**Argus için ders:** Silver ve Golden saldırılarının ikisi de aynı primitife dayanıyor — *saldırgan kurtarma/onboarding akışını istediği zaman yeniden tetikleyebiliyor.* Unit 42'nin IdP azaltım listesinde bu üçüncü madde: **"Harden recovery flows: detect and restrict unnecessary re-triggering of onboarding/recovery operations."**

Yani kurtarma akışının kendisi rate-limit ve anomali tespiti gerektiren bir kaynaktır. "Kurtarma zaten nadir çalışır, izlemeye gerek yok" varsayımı yanlıştır.

---

### 2. NIST SP 800-63B-4 §4.2 — birincil metin

**Yayın:** SP 800-63-4 final, **31 Temmuz 2025** (csrc.nist.gov/pubs/sp/800/63/4/final). HTML sürüm: https://pages.nist.gov/800-63-4/sp800-63b.html
**Değişiklik kaydı:** *"Section 4.2: Revises the requirements and methods for account recovery"*

#### 2.1 Tanım ve en önemli ayrım

> *"Account recovery is when a subscriber recovers from losing control of the authenticators that are needed to authenticate at a desired AAL."*

Ve hemen ardından, **veri modeline girmesi gereken ayrım**:

> *"Replacement of a forgotten password where the subscriber can authenticate with one or more other authenticators is considered to be the binding of a new authenticator (see Sec. 4.1.2.1) rather than account recovery."*

**Bu iki ayrı akıştır ve iki ayrı risk profilidir:**

| | Yeni authenticator bağlama (§4.1.2.1) | Hesap kurtarma (§4.2) |
|---|---|---|
| Ön koşul | Kullanıcı hâlâ bir authenticator ile doğrulanabiliyor | Kullanıcı hiçbir authenticator ile doğrulanamıyor |
| Gereken kanıt | Mevcut AAL'de kimlik doğrulama | Kurtarma kodu / kimlik tespiti tekrarı kombinasyonu |
| Gecikme | Yok | Olabilir ve olmalı |
| Sıklık | Sık | Nadir |
| Saldırgan getirisi | Düşük (zaten girmiş olması lazım) | **Çok yüksek** |

Keycloak'ın CVE-2026-18963'ü tam olarak bu ayrımın yapılmamasından doğdu: tek bir "reset credentials" akışı hem parola unutanı hem authenticator'ını tamamen kaybedeni servis ediyordu.

#### 2.2 Soğuma süresinin normatif dayanağı

NIST, kurtarmanın yavaş olmasını bir kusur değil **beklenen özellik** olarak yazıyor:

> *"Account recovery differs from authentication in several ways. Since account recovery is expected to be invoked infrequently, it is generally less convenient than authentication and — depending on the situation and recovery methods offered by the CSP — **may involve extended waiting times**."*

Ve bildirimi kurtarmanın ayrılmaz parçası yapıyor:

> *"An account recovery event always causes one or more notifications to be sent to the subscriber to help detect the fraudulent use of account recovery."*

#### 2.3 Dört kurtarma sınıfı

> *"CSPs SHALL support one or more of these and MAY support an application-specific method (e.g., interaction with a CSP agent) to recover a subscriber account. The use of alternative methods SHALL be based on a risk analysis and documented by the CSP."*

**Dikkat:** "interaction with a CSP agent" = destek kanalı / yardım masası. NIST bunu dört ana sınıfa dahil etmiyor, "alternative method" olarak sınıflandırıyor ve **risk analizi + dokümantasyon SHALL** koşuluna bağlıyor. Yardım masası kurtarması NIST'e göre birinci sınıf bir yöntem değildir.

##### 4.2.1.1 Saved recovery codes (kayıtlı kurtarma kodları)

| Gereksinim | Norm |
|---|---|
| Entropi | **SHALL** ≥ 64 bit, approved RBG |
| Sunum | Sayısal, Base64 veya QR |
| Saklama | **SHALL** hash'li — approved one-way function (§3.1.1.2) |
| Doğrulama | **SHALL** §3.2.2 throttling'e tabi |
| Kullanım sonrası | **SHALL** invalidate **ve SHALL yeni kod ver** |
| Yenileme | Kullanıcı istediği zaman MAY; yeni kod verilmesi **SHALL** kurtarma bildirimi üretir |

Son iki satır çoğu üründe eksiktir: kod kullanıldıktan sonra otomatik yeni kod verilmesi ve **kod yenilemenin bildirim tetiklemesi**. İkincisi olmadan saldırgan sessizce kendi kurtarma kodunu üretir.

##### 4.2.1.2 Issued recovery codes (gönderilen kurtarma kodları)

Entropi ≥ 6 ondalık hane (§3.2.12'ye göre approved RBG).

**Mutlak TTL tavanları — `SHALL be valid for at most`:**

| Kanal | Azami geçerlilik |
|---|---|
| Posta (ABD kıtasal) | 21 gün |
| Posta (ABD dışı) | 30 gün |
| **SMS / sesli arama** | **10 dakika** |
| **E-posta** | **24 saat** |

Kurtarma adresi kurulumu: kimlik tespiti sırasında doğrulanmamışsa **SHALL** doğrulanacak (aynı özelliklerde confirmation code ile). *"CSPs SHALL allow the subscriber to establish at least two recovery addresses."*

##### 4.2.1.3 Recovery contacts (kurtarma kişileri)

Issued code kurallarıyla aynı, iki istisna:
- TTL **+24 saat uzatılabilir** (güvenilen kişinin kodu iletmesi için; örn. SMS'te 24 saat 10 dakika)
- Adres doğrulaması da +24 saat uzatılabilir

Ayrıca: CSP **SHALL** görüntüleme/yönetim arayüzü sağlayacak; **SHOULD** yıllık hatırlatma gönderecek.

##### 4.2.1.4 Repeated identity proofing (kimlik tespiti tekrarı)

> *"The CSP SHALL repeat the necessary steps of identity proofing consistent with the level of initial identity proofing and SHALL confirm that the claimant's identity is consistent with the previously established account."*

Optimizasyon izni: ilk tespitten biyometrik örnek veya kanıt kopyası yeterli kalitede saklanmışsa, **sadece verification kısmı** tekrarlanabilir (MAY).

#### 2.4 IAL/AAL'e göre kurtarma matrisi — normatif

Bu tablo dokümanın en operasyonel kısmı ve çoğu ürünün karşılamadığı yer:

| Hesap | Gereken (SHALL, aşağıdakilerden **biri**) |
|---|---|
| **Kimlik tespiti yapılmamış** (azami AAL1) | Saved code **veya** issued code **veya** recovery contact |
| **AAL2** | ① Farklı sınıflardan **iki** kurtarma kodu (saved / issued / contact kümesinden) — **veya** ② **bir** kurtarma kodu **+** hesaba bağlı tek-faktörlü bir authenticator ile doğrulama — **veya** ③ kimlik tespiti tekrarı (hesap proofed ise) |
| **AAL3, IAL1/IAL2 ile proofed** | AAL2 ile aynı |
| **AAL3, IAL3 ile proofed** | **SHALL** — ilk *yerinde, gözetimli* kimlik tespiti oturumunda toplanan biyometrik karakteristikle başarılı biyometrik karşılaştırma. CSP ayrıca ilk kanıtın sunulmasını **MAY** ister |

**Buradan çıkan en önemli tek çıkarım:** AAL2 bir hesap için *tek bir e-posta linki* NIST'e göre geçerli bir kurtarma değildir. Ya ikinci bağımsız bir kanal, ya hesaba bağlı bir authenticator, ya da kimlik tespiti gerekir. Sektörün fiili varsayılanı ("e-posta = kurtarma") standardın gerisindedir.

#### 2.5 Bildirim kuralları (§4.2.3 ve §4.6)

> *"In all cases, account recovery SHALL cause a notification to be sent to the subscriber or their designee."*
> *"CSPs SHALL support at least two notification addresses per subscriber account."*
> *"Notifications SHALL be sent to all notification addresses except postal addresses. However, notifications SHALL be sent to postal addresses if no other form of notification address is stored in the subscriber account or if the notification is for account recovery at AAL3. **Account recovery notifications SHALL also be sent to a postal address if the only other notification address in the subscriber account is the address to which an issued recovery code was sent.**"*

Kalın kısım genellenebilir bir tasarım kuralına dönüşür:

> **Kurtarma kanalı, o kurtarmanın bildirim kanalı olamaz.** Kurtarma kodu e-postaya gittiyse ve hesapta başka bildirim adresi yoksa, bildirim başka bir ortamdan gitmek zorundadır. Aksi halde e-postayı ele geçiren saldırgan hem kodu alır hem uyarıyı siler.

Çoğu ürün bu kuralı ihlal ediyor: kurtarma linki de "hesabınız kurtarıldı" bildirimi de aynı e-posta kutusuna düşüyor. Bildirim o durumda hiçbir güvenlik değeri taşımaz.

Ayrıca: *"The notification SHALL provide clear instructions, including contact information, in case the recipient repudiates the event"* — bildirim tek yönlü bir mesaj değil, **itiraz kanalının girişi**dir.

#### 2.6 Rate limiting (§3.2.2)

> *"the verifier SHALL limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100 by disabling that authenticator."*

100 bir **üst sınırdır**, hedef değil: *"The limit of 100 attempts is an upper bound, and agencies MAY impose lower limits."* Devre dışı bırakılan authenticator **SHALL** yeniden bind edilecek (§4.1).

Kilitlenmeyi azaltmak için MAY olan teknikler — ve bunlar aynen kurtarma akışına da uygulanır:
- Kimlik doğrulama denemesinden önce **bot tespit ve azaltım challenge'ı**
- Hesap limitine yaklaştıkça **artan bekleme** (örn. 30 saniyeden 1 saate)
- Risk-tabanlı / adaptif teknikler (IP, coğrafya, istek zamanlaması, tarayıcı metadata'sı)

Ve kritik bağlantı: hem saved hem issued recovery code doğrulaması **SHALL** aynı throttling'e tabidir. Kurtarma kodu 6 haneliyse ve throttling yoksa, 10⁶ uzayda 100 deneme hakkı bile anlamlıdır — bu yüzden throttling normatiftir.

#### 2.7 Kayıp/çalıntı bildirimi (§4.3) — asimetrik eşik

NIST burada bilinçli bir asimetri kuruyor:

> *"To facilitate the secure reporting of an authenticator's loss, theft, damage, or compromise, the CSP SHOULD provide the subscriber with a method of authenticating using a backup or alternate authenticator. **This backup authenticator SHALL be a password or a physical authenticator.** Either could be used, but **only one authentication factor is required** to make this report."*

Ve gerekçe §4.5'te:

> *"The consequences of not invalidating a compromised authenticator are usually more significant than the denial-of-service potential of invalidating one in error."*

**Tasarım kuralı:** *Güvenliği artıran işlemin eşiği düşük, güvenliği azaltan işlemin eşiği yüksek olmalıdır.* "Anahtarımı kaybettim, iptal et" tek faktörle yapılabilmeli; "yeni anahtar ekle" tam kurtarma gerektirmeli. Çoğu ürün ikisini aynı akışa koyup ikisini de zorlaştırıyor — sonuç: kullanıcı kaybı bildirmiyor.

Ayrıca **suspension** (askıya alma) desteği MAY: geri alınması geçerli bir authenticator ile doğrulama sonrası SHOULD; CSP geri almaya zaman sınırı koyabilir (MAY).

#### 2.8 Authenticator bağlama (§4.1.2) — kurtarma sonrası kritik

> *"When any new authenticator is bound to a subscriber account, the CSP SHALL ensure that the process requires authentication at either the maximum AAL currently available in the subscriber account or the maximum AAL at which the new authenticator will be used, whichever is lower."*

Ve cihazlar arası bağlama (§4.1.2.2) için binding code kuralları — QR/cross-device akışları tasarlayan herkesin bilmesi gereken:

| Gereksinim | Norm |
|---|---|
| Uzunluk | ≥ **40 bit** (kullanıcı bir identifier de girdiyse), aksi halde ≥ **112 bit** |
| Kullanım | **SHALL** tek kullanımlık |
| TTL | **SHALL** azami **10 dakika** |
| Kanal | **SHALL NOT** güvensiz kanaldan iletilecek (*"e.g., email"* — açıkça yazıyor) |
| Aktarım | Manuel veya yerel out-of-band (QR) |

NIST ayrıca QR'ı neden tercih ettiğini açıklıyor: QR genellikle kodun yanında **CSP'nin URL'ini** de taşır, bu yüzden kullanıcının kodu bir phishing sitesine girme ihtimali düşer.

---

### 3. "Kurtarma korunan şeyden zayıf olamaz" — ilkenin kaynakları ve pratiği

#### 3.1 Birincil kaynak: FIDO Alliance 2019

**Recommended Account Recovery Practices for FIDO Relying Parties**, Şubat 2019
Editörler: Hidehito Gomi (Yahoo! JAPAN), Bill Leddy (VISA), Dean H. Saxe (Amazon)
https://fidoalliance.org/wp-content/uploads/2019/02/FIDO_Account_Recovery_Best_Practices-1.pdf

> *"The entire ecosystem is only as strong as the weakest link, so account-recovery mechanisms and policies must be clearly defined."*

**İki adımlı strateji:**
1. **Hesap başına birden fazla authenticator** — kurtarma *ihtiyacını* azaltır
2. **Kimlik tespiti / onboarding'i tekrar çalıştır** — kurtarmanın fiili icrası

> *"RPs may fall back to identity proofing of their users using a mechanism at the **same or higher assurance level** as the initial account bootstrapping."*

Ve ilkenin en açık ifadesi:

> *"Weaker mechanisms may lower the bar for account recovery by providing a weaker pathway to user identity-proofing or authentication, but this approach would also reduce the value of the FIDO implementation. **Implementing weaker account-recovery options is not recommended by the FIDO Alliance.**"*

Doküman ayrıca Google Advanced Protection'ı örnek gösteriyor: iki FIDO güvenlik anahtarı zorunlu — yani kurtarma ihtiyacı tasarımdan siliniyor.

Anonim/pseudonim hesaplar için: kimlik tespiti mümkün olmadığından saved/issued code veya Facebook Delegated Recovery (github.com/facebook/DelegatedRecoverySpecification) öneriliyor; ve *"RPs should inform the user of the risk of account loss, allowing the user to make an informed decision."*

#### 3.2 2025 sertleşmesi

FIDO Pt2 (Mart 2025):

> *"Account recovery processes based on weak authentication methods create potential security bypasses and undermine the strength of passkey authentication systems."*
> *"**The prohibition of phishable methods applies to both login and account recovery processes.**"*

Ve derecelendirme: login, fallback ve hesap kurtarmanın **üçünde birden** phishing-resistant yöntem kullanan RP'ler, kurtarmada phishable yöntem kullananlardan daha dayanıklı sayılıyor.

#### 3.3 İlkenin pratik uygulaması — üç somut kural

İlke soyut; uygulanabilir hale getiren üç kural:

**Kural 1 — Kurtarma yolunun AAL'i, hesabın azami AAL'ine eşit veya ondan yüksek olmalı.**
Bu ölçülebilir bir invariant'tır ve test edilebilir. Argus'ta her kurtarma yönteminin bir `assurance_level` etiketi olmalı ve politika motoru şunu reddetmeli:
`max(recovery_paths.aal) < account.max_aal` → konfigürasyon hatası, çalışma zamanı hatası değil.

**Kural 2 — Kurtarma yolu, korunan varlığın *tamamına* değil, *yeniden inşasına* erişim vermeli.**
Kurtarma "içeri girme" değil, "yeni authenticator bağlama hakkı" vermelidir. Aradaki fark: kurtarma sonrası oturum tam yetkili bir oturum değil, **kısıtlı bir yeniden kurulum oturumu**dur (§4.3'te detaylandırılıyor).

**Kural 3 — En zayıf yol ölçülür ve raporlanır.**
Bir hesabın efektif güvenliği `min(tüm giriş yollarının AAL'i)`dir — kurtarma dahil. Argus admin konsolu bu sayıyı hesap başına göstermeli. Bugün hiçbir büyük IdP bunu göstermiyor. *(Bu bir tasarım önerisidir, mevcut bir üründen alıntı değildir.)*

#### 3.4 Apple: ilkenin ürünleştirilmiş hali

Apple, "zayıf yolu kapat" seçeneğini kullanıcıya açıkça satan tek büyük sağlayıcı.

**Recovery Key** (https://support.apple.com/en-us/109345) — 28 karakter:

> *"you turn off Apple's standard account recovery process"*
> *"If you can't provide your recovery key, you'll be **locked out of your account permanently**."*

Yani Recovery Key açmak, Apple destekli (ve dolayısıyla sosyal mühendisliğe açık) kurtarma yolunu **kapatır**. Sıfırlama için gereken: recovery key + güvenilen telefon numarasına giden doğrulama kodu.

Advanced Data Protection açıldığında Apple bunu zorunlu kılıyor: *"you need to set up at least one alternative recovery method — either a recovery key or a recovery contact."* Verinin uçtan uca şifrelenmesi, Apple'ın kurtarma yeteneğini kaldırdığı için kullanıcıya kurtarma sorumluluğu devrediliyor.

**Ders:** Kurtarma gücü ile veri gizliliği arasında kaçınılmaz bir takas vardır. Apple bunu gizlemek yerine kullanıcıya açık bir toggle olarak sunuyor. Argus da yüksek değerli hesaplar için "asistanlı kurtarmayı kapat" seçeneği sunmalı — ve kalıcı kayıt riskini açıkça göstermeli.

---

### 4. Kurtarma yöntemleri karşılaştırması

| Yöntem | Phishing direnci | Devretme riski | Ölçek | Kalıcı kayıp riski | NIST sınıfı |
|---|---|---|---|---|---|
| **Kurtarma kodları (saved)** | Yüksek (offline) | Kullanıcı ekran görüntüsü alır, buluta koyar | Sıfır operasyon | **Yüksek** — kaybedilir | §4.2.1.1 |
| **İkinci passkey / güvenlik anahtarı** | **En yüksek** | Fiziksel çalınma | Sıfır operasyon | Orta | §4.2.2.2 seçenek ② bileşeni |
| **Güvenilir cihaz** | Yüksek | Cihaz çalınması + shoulder surfing (Apple SDP'nin çözdüğü sorun) | Sıfır | Orta | §4.2.2.2 seçenek ② |
| **Kurtarma kişileri (sosyal)** | Orta-yüksek | Kişinin kendisi sosyal mühendisliğe uğrar | Sıfır | Düşük | §4.2.1.3 |
| **E-posta/SMS kodu (issued)** | **Düşük** | E-posta ele geçirme, SIM swap | Sıfır | Çok düşük | §4.2.1.2 |
| **Kimlik tespiti tekrarı** | Yüksek | Deepfake / sahte belge | Maliyetli, satıcı bağımlı | Düşük | §4.2.1.4 |
| **Destek kanalı (yardım masası)** | **En düşük** | Sosyal mühendislik — §5 | En pahalı | Yok | Sınıf dışı, "alternative method" |

**Okunuş:** Sağa doğru gidildikçe kullanıcı kaybı azalır, saldırgan başarısı artar. Doğru tasarım tek yöntem seçmek değil, **kombinasyon zorunlu kılmak** — NIST'in AAL2 kuralı zaten bunu söylüyor.

#### 4.1 Kurtarma kodları — sık yapılan altı hata

1. **Hash'lenmeden saklanması.** NIST **SHALL** hash diyor. Kurtarma kodu bir paroladır ve veritabanı sızıntısında parolayla aynı sonucu verir.
2. **Kullanıldıktan sonra yenisinin verilmemesi.** NIST: *"SHALL invalidate that recovery code and SHALL issue a new saved recovery code."* Aksi halde kullanıcı sessizce kodsuz kalır.
3. **Throttling uygulanmaması.** NIST §3.2.2'ye açık atıf yapıyor.
4. **Kod yenilemenin bildirim üretmemesi.** Saldırgan oturum çalarsa sessizce kalıcılık kurar.
5. **Kayıt anında gösterilip "sakladım" onayı alınmaması.** Gösterilip onaylanmayan kod, olmayan koddur.
6. **10 kod verilip hepsinin aynı anda geçersizleşmesi.** Tek kullanımlık olması gereken **her bir koddur**, set değil.

#### 4.2 İkinci passkey — en iyi çözüm ve neden çalışmıyor

FIDO'nun 2019'dan beri birinci önerisi bu ve teknik olarak doğru. Pratikte tıkanma noktası UX:

- Kullanıcı ikinci bir authenticator'ın **neden** gerektiğini anlamıyor
- Cihaz senkronizasyonu ("zaten iPhone'umda ve Mac'imde var") yanlış güvenlik hissi veriyor — ikisi **aynı** senkron passkey'dir, iki authenticator değil
- İkinci fiziksel anahtar maliyet ve kayıp riski demek

**Argus için somut öneri:** İki authenticator'ın *bağımsız* olup olmadığını modelde takip et. Aynı sync fabric'teki iki passkey `independence_group` değeri aynı olmalı ve **tek authenticator** sayılmalı. Bu, NIST'in "bind multiple authenticators" tavsiyesini anlamlı hale getiren tek yorumdur. Bugün hiçbir IdP bunu modellemiyor. *(Tasarım önerisi.)*

WebAuthn tarafında bunu kısmen çıkarabileceğin sinyaller: AAGUID (authenticator modeli), `backupEligible` (BE) ve `backupState` (BS) bayrakları. `BE=1` olan bir credential senkronizasyona uygundur; aynı AAGUID + `BE=1` olan iki credential büyük olasılıkla aynı fabric'tedir.

---

### 5. Kurtarma sonrası soğuma süresi (cooldown)

#### 5.1 Soğuma süresi ne işe yarar — yanlış anlaşılan amaç

Yaygın yanlış anlama: "gecikme saldırganı yıldırır." Yanlış. Gerçek amaç Google'ın kendi dokümanında yazılı:

> *"During this delay, Google uses your recovery info and other information you've provided to notify you that an account recovery request has been made, **so if someone else is trying to access your account, you have time to deny the request and secure your account**."*
> — https://support.google.com/accounts/answer/9412469

**Soğuma süresi bir itiraz penceresidir.** Saldırganın kurtarmayı tamamlaması ile hesabın fiilen devredilmesi arasına, meşru sahibin uyarıyı görüp iptal edebileceği bir aralık koyar. Bu yüzden:

- Soğuma **bildirimle birlikte** çalışır; bildirimsiz gecikme yalnızca kullanıcıyı sinirlendirir
- Bildirim, kurtarmayı tetikleyen kanaldan **farklı** bir kanaldan gitmelidir (NIST §4.6 kuralı, §2.5)
- İptal, kurtarmadan **daha kolay** olmalıdır (asimetri ilkesi, §2.7)

#### 5.2 Ne kadar olmalı — gerçek uygulamalar

| Sağlayıcı | Süre | Kapsam | Kaynak |
|---|---|---|---|
| **Google — security hold** | "a few hours or a number of days", risk faktörlerine göre | Kurtarma talebinin işlenmesi | support.google.com/accounts/answer/9412469 |
| **Google — kurtarma bilgisi değişimi** | **7 güne kadar** | Değişikliğin yürürlüğe girmesi; bu süre boyunca eski adrese de kod gidebilir | support.google.com/accounts/answer/7682439 |
| **Apple — Account Recovery** | *"several days or more"*, **kısaltılamaz** | Parola sıfırlama | support.apple.com/en-us/HT204921 |
| **Apple — Stolen Device Protection** | **1 saat** + iki kez biyometrik | Apple ID parolası, cihaz parolası, Face/Touch ID değişimi, Find My kapatma, SDP kapatma | Apple SDP; iOS 26.4'te varsayılan açık |
| **Microsoft Entra CAE** | Ters yön: token ömrü **28 saate** kadar uzatılıyor, iptal sinyalle yapılıyor (~15 dk propagasyon) | Oturum iptali | learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation |

**Google'ın ters orantı kuralı — en önemli tasarım sinyali:**

> *"if you added more security to your account by setting up 2-Step Verification, your account recovery request might be delayed for longer."*

Yani hesabın koruma seviyesi arttıkça kurtarma **daha yavaş** olur. Bu, "kurtarma korunan şeyden zayıf olamaz" ilkesinin zamansal boyutudur: güçlü koruma seçen kullanıcı, o korumayı atlatma girişimine karşı da daha uzun bir itiraz penceresi kazanır.

**Apple'ın 2026 hamlesi:** Stolen Device Protection iOS 26.4 ile **tüm iPhone'larda varsayılan açık** hale geldi (MacRumors, 16 Şubat 2026). Yani sektör "hassas değişiklikte gecikme"yi opt-in özellikten varsayılana taşıdı. Bu, Argus'un varsayılanını belirlerken dikkate alınması gereken bir sinyal.

Apple'ın "familiar location" istisnası da öğretici: gecikme **bağlama duyarlı**. Ev ağında gecikme yok, dışarıda var. Yani soğuma süresi sabit bir sayı değil, risk fonksiyonudur.

#### 5.3 Hangi işlemler kısıtlanmalı — somut liste

Kurtarma sonrası oturum **tam yetkili bir oturum değildir**. Argus'un `session.recovery_grace_until` alanı dolu olduğu sürece şu işlemler reddedilmeli veya ek doğrulama istemeli:

| Kategori | Kısıtlanacak işlem | Gerekçe |
|---|---|---|
| **Kimlik** | E-posta / telefon değişimi | Saldırgan kalıcılık kurar |
| **Kimlik** | Yeni kurtarma adresi ekleme | Bir sonraki kurtarmayı garantiler |
| **Kimlik** | Kurtarma kodu yeniden üretme | Aynı |
| **Authenticator** | Mevcut passkey/MFA **silme** | Meşru sahibi kilitler |
| **Authenticator** | Yeni authenticator ekleme — **kısmen** | Bir tane gerekli (yoksa kullanıcı içeri giremez); ikincisinden itibaren kısıt |
| **Federasyon** | Yeni IdP bağlama, mevcut bağı kaldırma | Kalıcılık ve devretme |
| **Yetki** | Rol yükseltme, üye davet etme, sahiplik devri | Yanal hareket |
| **Veri** | Toplu dışa aktarım, veri portabilite talebi | Tek hamlede tüm veri |
| **Finans** | Ödeme aracı değişimi, para çekme, fatura adresi | Doğrudan zarar |
| **API** | Yeni API anahtarı / uzun ömürlü token üretimi | Soğuma süresini atlar |
| **Hesap** | Hesap silme | İz temizleme |

**Kritik nokta:** "Yeni API anahtarı üretimi" listede olmazsa soğuma süresi anlamsızdır — saldırgan kurtarma sonrası hemen bir kalıcı token üretip beklemeye geçer. Soğuma süresini atlatan her mekanizma kapatılmalıdır.

**Süre önerisi (Argus varsayılanı, tasarım önerisi):**

| Hesap tipi | Kurtarma yöntemi | Soğuma |
|---|---|---|
| Tüketici, düşük değer | Kayıtlı kurtarma kodu | **0** (kod zaten güçlü kanıt) |
| Tüketici, düşük değer | E-posta kodu tek başına | **24 saat** |
| Tüketici, MFA'lı | İki kanal kombinasyonu (NIST AAL2 ①) | **1–24 saat**, risk skoruna göre |
| Tüketici, MFA'lı | Kimlik tespiti tekrarı | **0–1 saat** |
| Kurumsal çalışan | Yönetici onaylı TAP (§X) | **0** (out-of-band onay zaten var) |
| Yüksek değer / admin | Her yöntem | **En az 24 saat + ikinci yönetici onayı** |

Mantık: **soğuma süresi kullanılan kanıtın gücüyle ters orantılıdır.** Zayıf kanıtla kurtaran uzun bekler; güçlü kanıtla kurtaran beklemez. Sabit bir gecikme koymak hem güvenli kullanıcıyı cezalandırır hem zayıf yolu yeterince yavaşlatmaz.

#### 5.4 Anti-pattern'ler

| Anti-pattern | Neden yanlış |
|---|---|
| Soğuma süresi var, bildirim yok | Gecikmenin tek amacı itiraz penceresi açmak; bildirimsiz gecikme sadece UX cezası |
| Bildirim kurtarma kanalına gidiyor | Saldırgan o kanalı zaten kontrol ediyor (NIST §4.6'nın kapattığı delik) |
| Destek "aceleniz mi var" diyip süreyi kısaltıyor | Apple'ın açıkça reddettiği şey: *"Contacting Apple Support can't help you shorten this time."* Kısaltılabilen soğuma, sosyal mühendisliğin hedefi olur |
| Soğuma sadece parola değişiminde | Passkey ekleme, e-posta değişimi, API anahtarı üretimi kapsam dışı kalırsa etkisiz |
| Sabit süre, risk körü | Güvenli kullanıcıyı cezalandırır, saldırganı yeterince yavaşlatmaz |
| İptal linki kurtarmadan zor | Asimetri tersine dönmüş; iptal tek tıkla olmalı |

---

### 6. Passkey kaybı senaryoları

#### 6.1 Senkronize vs cihaza bağlı

| | Senkronize passkey (`BE=1`) | Cihaza bağlı (`BE=0`) |
|---|---|---|
| Tek cihaz kaybı | **Sorun yok** — diğer cihazlarda mevcut | **Credential kaybı** |
| Platform hesabı kaybı | **Tüm passkey'ler kaybolur** | Etkilenmez |
| Kurtarma sorumlusu | Platform sağlayıcısı (Apple/Google/MS) | RP |
| AAL3 uygunluğu | **Hayır** — NIST: exportable key, AAL3'te kullanılamaz | Evet |
| Kurtarma zafiyeti | Platform kurtarma akışı = senin zafiyetin | Yok, ama kayıp riski yüksek |

**RP açısından gerçek:** Senkron passkey, kullanıcı kaybı problemini çözer ama **kurtarma sorumluluğunu dışarı devreder**. Platform hesabı ele geçirilirse (§1.2, §1.3) o platformdaki tüm passkey'ler saldırganın olur ve RP'nin haberi olmaz. Bu yüzden RP kendi bağımsız risk sinyallerini korumalıdır:

- WebAuthn `backupState` (BS) bayrağının **değişimi**: `BE=1, BS=0 → BS=1` geçişi, credential'ın ilk kez yedeklendiği anlamına gelir. Bu bir olay olarak loglanmalıdır.
- Yeni bir cihazdan gelen ilk kimlik doğrulama, aynı credential ID ile bile olsa risk sinyalidir.
- AAGUID değişimi credential'ın taşındığını gösterir.

#### 6.2 Platform hesabı kaybı — kimsenin çözmediği senaryo

Kullanıcı Apple ID'sini kaybederse: iCloud Keychain'deki tüm passkey'ler gider. Apple'ın Account Recovery'si günler sürer ve Recovery Key varsa **hiç çalışmaz** (§3.4). Kullanıcı bu süre boyunca senin servisine giremez.

**Bu, RP'nin çözmesi gereken bir problemdir ve şu anda kimse çözmüyor.** Öneri:

> Argus, senkron passkey'i **tek** authenticator olarak kabul etmemeli. Kayıt akışında senkron passkey oluşturulduğunda, ikinci ve **bağımsız** bir kurtarma yolu (kayıtlı kurtarma kodu, ikinci cihaz-bağlı credential veya kurtarma kişisi) kurulmadan hesap "tam korumalı" sayılmamalı. Bu, NIST Appendix B'nin *"Bind multiple authenticators at AAL2 and above to support recovery"* tavsiyesinin doğrudan uygulanmasıdır.

#### 6.3 Origin bağı — göç ölümcül kesişimi

Passkey'ler RP ID'ye (etki alanı) bağlıdır. Domain değişirse passkey'ler ölür. Bu hem **göç** (§Bölüm V) hem **kurtarma** problemi doğurur: markanı değiştirirsen tüm kullanıcıların yeniden kayıt olması gerekir ve bu **toplu bir kurtarma olayıdır** — yani senin en zayıf kurtarma yolunun tüm kullanıcı tabanında aynı anda çalışması demektir. Saldırgan için mükemmel bir pencere.

**Ders:** Domain değişimi bir pazarlama kararı değil, güvenlik olayıdır. Planlanması, kademelendirilmesi ve kurtarma yolunun o dönem için sertleştirilmesi gerekir.

---
### 7. Yardım masası sosyal mühendisliği

#### 7.1 NIST'in kendi teşhisi

SP 800-63B-4 §6.3 (Authenticator Recovery), bu dokümanın tamamının özeti sayılabilecek cümleyi içeriyor:

> *"**The weak point in many authentication mechanisms is the process followed when a subscriber loses control of one or more authenticators and needs to replace them.** In many cases, the options for authenticating the subscriber are limited, and **economic concerns (e.g., the cost of maintaining call centers) motivate the use of inexpensive and often less secure backup authentication methods**. To the extent that authenticator recovery is human-assisted, social engineering attacks also pose risks."*

Ve hemen ardından, faktör izolasyonu kuralı:

> *"**To maintain the integrity of the authentication factors, it is essential that one authentication factor cannot be leveraged to obtain an authenticator of a different factor.** For example, a password must not be usable to obtain a new list of look-up secrets."*

Bu ikinci cümle FIDO'nun 2025'te "passkey kaydı sadece parola ile yapılamaz" dediği şeyin NIST versiyonudur ve Argus'un yetkilendirme motoruna bir invariant olarak girmelidir: **bir faktör, farklı sınıftaki bir faktörü üretmek için kullanılamaz.**

#### 7.2 Scattered Spider'ın kill chain'i — birincil kaynak

**Joint Cybersecurity Advisory AA23-320A**, ilk yayın Kasım 2023, **güncelleme 29 Temmuz 2025**. Yazarlar: FBI, CISA, RCMP, AFP, ACSC/CCCS, NCSC-UK.
PDF: https://www.cisa.gov/sites/default/files/2025-08/aa23-320a-scattered-spider-508c.pdf · https://www.ic3.gov/CSA/2025/250729.pdf

Advisory'nin en öğretici pasajı — saldırının **keşif aşamasının hedefi**:

> *"The social engineering attempts are designed to **first learn what steps are needed to conduct password resets from helpdesks**. Once that information is identified, the threat actors continue to conduct phone calls to employees and help desks to gather password reset specific information of a targeted employee. Finally, the threat actors conduct spearphishing calls to convince IT help desk personnel to reset passwords and/or transfer MFA tokens."*

**Buradan çıkan tek cümlelik ders:**

> **Kurtarma prosedürünün kendisi gizlilik değeri olan bir varlıktır.** Saldırgan önce "sizde parola sıfırlama nasıl yapılıyor" diye öğreniyor, sonra hedef çalışanı arıyor. Prosedürünüz kamuya açıksa saldırganın keşif aşaması sıfırlanır.

Advisory'nin diğer normatif noktaları:
- **T1199 Trusted Relationship:** *"Scattered Spider threat actors **abuse trusted relationships of contracted IT help desks**"* — taşeron yardım masası özel bir risk kategorisi
- **T1556.006 / T1606:** *"Scattered Spider threat actors then **register their own MFA tokens**"* — kurtarma sonrası kalıcılık; §5.3'teki kısıt listesinin gerekçesi
- **T1078:** *"maintain network access **even when passwords are changed**"* — parola değişimi yeterli müdahale değil
- Typosquat kalıpları: `hedefadi-sso[.]com`, `hedefadi-servicedesk[.]com`, `hedefadi-okta[.]com`, `hedefadi-helpdesk[.]com`, `oktalogin-hedefsirket[.]com`
- **Azaltım (birincil metinden):** *"Implement FIDO/WebAuthn authentication or Public Key Infrastructure (PKI)-based MFA. These MFA implementations are resistant to phishing and not susceptible to push bombing or SIM swap."* ve *"**Refrain from requiring recurring password changes.**"*

> **Dürüst not:** CISA advisory'sinin azaltım bölümü, yardım masası arayan-doğrulama kontrolleri konusunda **şaşırtıcı derecede zayıftır**. "Vishing'e karşı eğitin" diyor ama geri-arama, video doğrulama veya yönetici onayı gibi somut prosedürler **reçete etmiyor**. Bu boşluğun kendisi bir bulgudur.

#### 7.3 Vakalar

| Vaka | Tarih | Mekanizma | Etki |
|---|---|---|---|
| **MGM Resorts** | Eylül 2023 | Yardım masası araması, kimlik doğrulanmadan sıfırlama | Kanonik vaka. *Birincil kaynak doğrulanmadı — genel örüntü dışındaki detaylar için dikkat* |
| **Okta müşterileri** | Yaz 2023 | Saldırganlar servis masası personelini ikna edip yüksek ayrıcalıklı kullanıcıların **tüm MFA faktörlerini** sıfırlattı | 4 müşteri. Okta'nın kendi analizi: sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection/ |
| **Clorox → Cognizant davası** | İhlal Ağu 2023, dava **Temmuz 2025** | Cognizant yardım masasının, Clorox'un yazılı doğrulama talimatlarına aykırı olarak, saldırgana **parola ve MFA'yı kimlik doğrulamadan** sıfırladığı iddiası — iddiaya göre **en az üç kez** | **380 milyon USD** talep. Cognizant savunması: *"Cognizant did not manage cybersecurity for Clorox."* Rakamlar dava dilekçesine ilişkin habercilikten; dilekçe metninden değil |
| **M&S / Co-op / Harrods** | Nisan–Mayıs 2025 | Dış kaynaklı IT yardım masası aranıp çalışan taklidi, ayrıcalıklı hesapta **MFA sıfırlama** | M&S online sipariş ~6 hafta kapalı. CMC sınıflandırması: tek birleşik siber olay, **270–440 milyon GBP**. Temmuz 2025'te 4 gözaltı. DragonForce fidye yazılımı |
| **Sigorta sektörü dalgası** | Haziran 2025 | Aynı örüntü | Aflac, Erie Insurance, Philadelphia Insurance |
| **Havacılık/ulaştırma dalgası** | Haz–Tem 2025 | Aynı örüntü, FBI uyarısı | Hawaiian Airlines, Qantas, WestJet |
| **Twitter** | 15 Temmuz 2020 | Vishing ile çalışanlardan iç yönetim aracına erişim; push MFA onaylatıldı | 118.000+ USD bitcoin. NY DFS raporu (Ekim 2020) birincil kaynak |
| **Robinhood** | 3 Kasım 2021 | Destek temsilcisi telefonla ikna edilip uzaktan erişim yazılımı kurduruldu | ~7 milyon kişi etkilendi. SEC 8-K eki birincil kaynak |

> **2026 vakaları:** Belirli, iyi kaynaklı bir 2026 yardım masası olayı **bulunamadı**. Dolaşımdaki "2026 ortası itibarıyla 100+ ihlal, 100M+ USD fidye" iddiası doğrulanamadı — **yayımlamayın.**

#### 7.4 Karşı önlemler — Okta'nın yayımlanmış rehberi (birincil)

Okta Threat Intelligence, **29 Eylül 2025**, Moussa Diallo — https://www.okta.com/blog/threat-intelligence/help-desks-targeted-in-social-engineering-targeting-hr-applications/

En değerli öneri, **yetkiyi kaldırmak**:

> *"Create custom admin roles for front-line service desk professionals that **do not have the permissions required to modify factors** (reset user passwords, set temporary passwords, or reset or enroll factors). Instead, service desk professionals should be granted in their custom role the permission to **issue Temporary Access Codes** after a caller to the help desk has successfully verified their identity."*

Yani birinci seviye destek **sıfırlama yapamaz**; yalnızca zaman sınırlı, gruba özgü bir geçici erişim kodu **verebilir**. Sıfırlamayı kullanıcının kendisi yapar. Bu, yardım masasının yetkisini "hesabı devret"ten "hesaba geçici bir pencere aç"a indirir.

Diğer Okta önerileri:
- Uzak kullanıcı kimliğini doğrulamak için **standartlaştırılmış, dokümante, duyurulmuş** bir süreç; kilitlenme durumunda **kimlik doğrulama servisleri** kullanımı
- Yönetilen/kayıtlı cihaz zorunluluğu; *"Deny or require higher assurance for requests from rarely-used networks"*
- **Zero Standing Privileges** + JIT erişim için **çift onay** (dual authorization)
- Güçlü authenticator zorunluluğu (FastPass, FIDO2 WebAuthn, akıllı kart)

> **Dürüst not:** Video doğrulama, yönetici onayı ve out-of-band geri arama sektörde yaygın olarak önerilir, ancak **Okta'nın veya CISA'nın birincil dokümanlarında bu üçü isimle geçmiyor**. Bu dokümanda genel iyi uygulama olarak sunulmuşlardır, bu kurumlara atfedilmemişlerdir.

**NY DFS'in düzenleyici tavsiyesi ise doğrudan alıntılanabilir** (Twitter Investigation Report, Ekim 2020):

> *"Access to critical functions should require MFA. **Another possible control for high-risk functions is to require certification or approval by a second employee before the action can be taken.** An approval requirement can limit the damage if an attacker compromises one employee's access."*

Bir finansal düzenleyicinin, yüksek riskli işlemler için **dört göz onayı** önermesi — impersonation ve kurtarma tasarımında güçlü bir dayanak.

---

### 8. Gerçek dünya verisi — ve bulunamayan sayı

#### 8.1 En önemli negatif bulgu

> **"ATO'ların yüzde kaçı kurtarma akışından geçiyor?" sorusunun yayımlanmış bir cevabı yok.** Verizon DBIR, Okta, Sift, Javelin, Arkose dahil taranan kaynakların hiçbiri giriş akışı ile kurtarma akışı arasında bu ayrımı yapan bir metrik yayımlamıyor. Bu bir veri boşluğudur ve dürüstçe böyle raporlanmalıdır. Bu dokümanda kurtarmanın payına dair **hiçbir yüzde uydurulmamıştır.**

Dolaylı kanıtlar mevcut:

| Metrik | Değer | Kaynak | Güven |
|---|---|---|---|
| **Pretexting** (bahane uydurma) — DBIR 2026'da ilk kez ayrı bir ilk erişim vektörü olarak ayrıldı | **%6** | Verizon DBIR 2026 (yayın ~Mayıs 2026) | İkincil özetlerden; DBIR PDF'i doğrudan okunmadı |
| Kimlik bilgisi suistimali — ilk erişim vektörü | %13 (düşüş) | DBIR 2026 | İkincil |
| Kimlik bilgisi suistimali — ihlallerin herhangi bir yerinde | %39 | DBIR 2026 | İkincil |
| İnsan unsuru içeren ihlal | %62 | DBIR 2026 | İkincil |
| ATO kaybı 2025 | **15 milyar USD'yi aşkın** — %4 azalma | Javelin 2026 Identity Fraud Study, basın bülteni 21 Nisan 2026 | **Birincil** |
| ATO mağduru 2025 | **6 milyon kişi, 2024'e göre %18 artış** | Javelin 2026 | **Birincil** |
| Toplam kimlik dolandırıcılığı 2025 | 27,3 milyar USD / 18 milyon mağdur | Javelin 2026 | **Birincil** |
| Credential stuffing kriteri karşılayan giriş denemesi | %24,3 | Okta State of Secure Identity 2023 | Birincil |
| Aylık engellenen kimlik saldırısı | 3,9 milyar+ | Okta Secure Identity Commitment, Şub–Tem 2025 | Birincil |

**Javelin'in "illusion of progress" çerçevesi Argus için kullanışlı bir argüman:** kayıp %4 azalırken mağdur sayısı %18 arttı. Yani saldırılar başına kazanç düşüyor ama **saldırı hacmi artıyor** — savunmanın maliyeti mağdur başına değil, olay başına ölçeklenmelidir.

#### 8.2 DBIR'daki `pretexting` ayrımının önemi

DBIR 2026 pretexting'i ayrı bir vektör olarak ayırdığı için, önceki yıl metodolojisiyle ölçülseydi kimlik bilgisi suistimali %13 değil %16 olacaktı. Yani **insan kandırma, artık kimlik bilgisi hırsızlığından ayrı bir kategori olarak sayılmaya başlandı.** Bu, yardım masası vektörünün olgunlaştığının ölçüm tarafındaki yansımasıdır.

---

### 9. Kurumsal (workforce) vs tüketici kurtarma

Yapısal fark tek bir cümleyle özetlenebilir: **kurumsal kurtarmanın bir out-of-band güven çıpası vardır, tüketici kurtarmanın yoktur.**

Kurumsal tarafta işveren, İK kaydı, yönetici, yönetilen cihaz ve MDM var. NIST bunu Appendix B'de açıkça yazıyor:

> *"For enterprise use cases, concerns over sharing keys can be effectively mitigated using device management techniques that limit the ability for keys to be moved off of approved devices or sync fabrics. **However, similar mitigations are not currently available for public-facing use cases**, leaving RPs dependent on the sharing models adopted by syncable authenticator providers."*

| | Kurumsal | Tüketici |
|---|---|---|
| Güven çıpası | İK kaydı, yönetici, yönetilen cihaz, MDM | Yok |
| Araçlar | Entra **TAP**, Okta **Temporary Access Code**, cihaz yönetimi, kurumsal attestation | Kurtarma kodu, e-posta/SMS, kurtarma kişisi, kimlik tespiti, destek kuyruğu |
| Attestation | NIST: agencies **SHOULD** implement | NIST: *"The unavailability of attestations SHOULD NOT block the use of syncable authenticators for broad public-facing applications."* |
| Kurtarma hızı | Dakikalar (onaylı TAP) | Günler (Apple), 7+7 gün (Google recovery contact), 30 gün (Microsoft) |
| Ana risk | **Yardım masası sosyal mühendisliği** | E-posta/SMS ele geçirme, SIM swap |

#### 9.1 Entra ID Temporary Access Pass — parametreler

https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass

| Ayar | Varsayılan | İzin verilen aralık |
|---|---|---|
| Minimum ömür | 1 saat | 10 dk – 43.200 dk (30 gün) |
| Maksimum ömür | 8 saat | 10 dk – 43.200 dk |
| Varsayılan ömür | 1 saat | 10 dk – 43.200 dk |
| Tek kullanımlık | False | True/False |
| Uzunluk | 8 | 8–48 karakter |

Amaç, Microsoft'un kendi ifadesiyle: *"A TAP also **makes recovery easier when a user loses or forgets a strong authentication method**."*

Kritik kısıtlar:
- **Kullanıcı başına yalnızca bir TAP olabilir**
- Tek kullanımlık TAP ile passwordless yöntem kaydı **10 dakika** içinde tamamlanmalı
- TAP oturumunda verilen token'ların ömrü TAP bitişiyle sınırlı — **ama TAP'ın süresi dolması zaten kurulmuş oturumları geriye dönük iptal etmez**
- TAP oluşturma/silme/görüntüleme rolleri ayrı; hiçbiri **kendisi için** TAP oluşturamaz
- *"a TAP doesn't replace a user's password"*
- Dış misafirlere verilemez

**Argus için model:** TAP, "yardım masası hesabı devretmiyor, hesaba dar bir pencere açıyor" fikrinin ürünleşmiş hali. Argus'ta karşılığı: `recovery_grant` nesnesi — kim verdi, hangi gerekçeyle, ne kadar geçerli, kaç kullanımlık, hangi işlemleri açıyor (yalnızca "authenticator bağla"), ve verildiği anda hedef kullanıcıya out-of-band bildirim.

---

### 10. Kurtarma — veri modeli ve durum makinesi

#### 10.1 Durum makinesi

```
                    ┌──────────────────────────────────────┐
                    │                                      │
   [none] ──initiate──▶ REQUESTED ──evidence_ok──▶ EVIDENCE_MET
                    │       │                          │
                    │       │ evidence_fail            │ (cooldown > 0)
                    │       ▼                          ▼
                    │   THROTTLED              COOLING_DOWN ──user_denies──▶ DENIED
                    │       │                          │                       │
                    │       │ (max attempts)           │ cooldown_elapsed      │
                    │       ▼                          ▼                       ▼
                    └──▶ LOCKED                   REBIND_OPEN            (all sessions
                                                       │                  revoked, all
                                                       │ authenticator_bound   recovery
                                                       ▼                  paths frozen)
                                                  GRACE_PERIOD
                                                       │ grace_elapsed
                                                       ▼
                                                    CLOSED
```

**Geçiş kuralları:**

| Geçiş | Koşul | Yan etki |
|---|---|---|
| `→ REQUESTED` | Kurtarma başlatıldı | **Bildirim** tüm bildirim adreslerine (kurtarma kanalı hariç); rate-limit sayacı artar. ⚠️ **İncelenecek kötüye kullanım:** yalnızca e-posta adresini bilen biri bu geçişi tekrarlayarak bildirim ürettirebilir ve rate-limit bütçesini tüketip durum makinesini `throttled`/`locked`'a itebilir. Bu bir **oturum** DoS'u değil (oturum iptali yalnızca `DENIED`'da ve kanıt kapısının arkasında), **kurtarmanın engellenmesi**dir — meşru kullanıcının gerçekten ihtiyacı olduğunda yolu kapatabilir. Ayrı sınır gerekir |
| `REQUESTED → EVIDENCE_MET` | AAL'e göre gereken kanıt kombinasyonu sağlandı (§2.4) | Kullanılan kanıt sınıfları kaydedilir |
| `EVIDENCE_MET → COOLING_DOWN` | `cooldown = f(kanıt gücü, hesap değeri, risk skoru)` > 0 | İkinci bildirim: "X tarihinde tamamlanacak, değilseniz iptal et" |
| `COOLING_DOWN → DENIED` | Kullanıcı iptal linkine tıkladı **veya** mevcut bir authenticator ile giriş yaptı | **Kurtarma girişimi iptal edilir**, kurtarma yolları dondurulur, güvenlik olayı üretilir. ⚠️ **Oturum iptali bu geçişin otomatik yan etkisi DEĞİLDİR** (düzeltme, 2. inceleme turu): kurtarma girişimini iptal etmek ile mevcut oturumları topluca iptal etmek **ayrı güvenlik eylemleridir**. İkincisi ayrı gerekçe ve yetki koşuluyla, kanıt gücüne bağlı olarak tetiklenir; birincinin sessiz yan etkisi olarak bağlanmaz |
| `→ REBIND_OPEN` | Cooldown doldu | Oturum açılır ama **yalnızca authenticator bağlama** yetkisiyle |
| `REBIND_OPEN → GRACE_PERIOD` | En az bir authenticator bağlandı | Tam oturum verilir ama `recovery_grace_until` dolu |
| `GRACE_PERIOD → CLOSED` | Grace süresi doldu | Kısıtlar kalkar |

**Apple'ın "kullanıcı giriş yaparsa kurtarma iptal olur" davranışı `COOLING_DOWN → DENIED` geçişidir** ve kopyalanmalıdır: meşru sahibin normal girişi, devam eden kurtarmayı otomatik iptal etmelidir. Bu, hiçbir kullanıcı eylemi gerektirmeyen bir savunmadır.

#### 10.2 Veri modeli (öneri)

```
recovery_method
  id, user_id
  class            enum(saved_code, issued_code, recovery_contact, reproofing, agent_assisted)
  channel          enum(none, email, sms, voice, postal, contact_user)
  assurance_level  enum(aal1, aal2, aal3)          -- politika motoru bunu okur
  independence_group  text   -- aynı grup = aynı kanal ailesi, kombinasyonda tek sayılır
  address_ref      fk → notification_address (issued_code / recovery_contact için)
  secret_hash      bytea     -- saved_code için; approved one-way function (NIST §4.2.1.1)
  established_at, verified_at, last_used_at, revoked_at
  UNIQUE(user_id, class, address_ref) WHERE revoked_at IS NULL

notification_address
  id, user_id
  kind             enum(email, sms, voice, push, postal)
  value_hash       bytea     -- ham değer ayrı, şifreli sütunda
  verified_at
  is_recovery_target  bool    -- kurtarma kodu buraya gidiyor mu
  mailbox_owner_since timestamptz   -- RFC 7293 semantiği; kurumsal e-posta devri için
  -- NIST §4.6: en az iki adres SHALL

recovery_attempt
  id, user_id
  state            enum(requested, evidence_met, cooling_down, rebind_open,
                        grace_period, closed, denied, throttled, locked) NOT NULL
  requested_at, state_changed_at
  cooldown_until, grace_until
  evidence         jsonb   -- [{method_id, class, verified_at}, ...]
  achieved_aal     enum    -- sağlanan kanıtın AAL'i
  required_aal     enum    -- hesabın azami AAL'i
  -- ★ ana invariant — DURUMA KOŞULLU (⚠️ düzeltme, 2. inceleme turu)
  -- Koşulsuz `CHECK (achieved_aal >= required_aal)` iki halden birindeydi ve ikisi de kusurlu:
  --   (a) alanlar NOT NULL ise `requested`/`throttled`/`locked` durumlarında satır HİÇ yazılamaz;
  --   (b) nullable ise SQL üç değerli mantığı gereği NULL karşılaştırması UNKNOWN döner
  --       ve kısıt SESSİZCE GEÇER — yani yetki açan yolda hiçbir şey korumaz.
  --   (`state` yukarıda NOT NULL olarak işaretlendi; kısıt ona dayanır.)
  CHECK (
    state IN ('requested','throttled','locked','denied')
    OR (achieved_aal IS NOT NULL AND required_aal IS NOT NULL
        AND achieved_aal >= required_aal)
  )
  -- Enum karşılaştırması PostgreSQL'de bildirim sırasına bağlıdır:
  -- aal1 < aal2 < aal3 sırası BİLİNÇLİ bir şema sözleşmesidir, değiştirilemez.
  request_ip, request_asn, device_fp, risk_score
  denied_by        enum(user_link, user_login, admin, timeout)
  notifications_sent  jsonb  -- hangi adrese ne zaman; denetim için

account_recovery_policy   (realm veya kullanıcı seviyesinde)
  min_paths, required_independence_groups
  cooldown_matrix  jsonb   -- kanıt gücü × hesap değeri → süre
  assisted_recovery_enabled  bool  -- Apple Recovery Key modeli: zayıf yolu kapat
  permanent_loss_acknowledged_at  timestamptz  -- kullanıcı riski kabul etti mi
```

**Bu kısıt, "kurtarma korunan şeyden zayıf olamaz" ilkesini bir yorum satırından bir veritabanı kısıtına çevirir.**

> ⚠️ **Ama tek başına yetmez — önceki hâli ("bu dokümanın en önemli tek satırı") fazla iddialıydı (düzeltme, 2. inceleme turu).** Satırın **son hâlini** kontrol etmek, o hâle **doğrulanmış kanıttan** gelindiğini ispatlamaz. Yetki açan işlem tek bir atomik birimde şunları yapmalı: **mevcut durumu doğrula → kanıtın geçerliliğini doğrula → kanıtı TÜKET → yeni yetkiyi oluştur.** Kanıt tüketilmeden yetki üretilirse iki eşzamanlı istek aynı kanıtı kullanabilir; kabul testi de tam olarak budur (aynı kanıtla paralel iki `REBIND_OPEN` denemesi). Geçişlerin append-only kaydı **denetlenebilirlik** sağlar, geçiş **doğruluğu** sağlamaz — **geçiş kaydı, geçiş denetiminin yerine geçmemeli.**

#### 10.3 Argus'un ayrışma noktaları — kurtarma

| # | Ayrışma | Neden rakiplerde yok |
|---|---|---|
| 1 | **Kurtarma, konfigüre edilebilir bir "flow" değil; tipli bir durum makinesi.** Adım silinerek atlatılamaz | Keycloak #40744: akıştan adım silmek auth bypass üretiyor. Genel amaçlı flow motoru bunu yapısal olarak engelleyemez |
| 2 | **`achieved_aal >= required_aal` invariant'ı şemada zorlanıyor** | Hiçbir IdP kurtarma yolunun AAL'ini modellemiyor; dolayısıyla karşılaştıramıyor |
| 3 | **`independence_group`** — aynı sync fabric'teki iki passkey tek authenticator sayılır | NIST "bind multiple authenticators" diyor, hiçbir ürün bağımsızlığı ölçmüyor |
| 4 | **Hesabın efektif güvenliği = `min(tüm yolların AAL'i)` olarak admin konsolunda gösteriliyor** | Kimse en zayıf yolu raporlamıyor |
| 5 | **Kanıt gücüne ters orantılı, risk duyarlı cooldown** (sabit değil) | Google risk-tabanlı yapıyor ama açık kaynak IdP'lerde yok |
| 6 | **Bildirim kanalı ≠ kurtarma kanalı** kuralı şemada zorunlu | NIST §4.6 kuralı; ürünlerin çoğu ihlal ediyor |
| 7 | **`assisted_recovery_enabled = false`** — Apple Recovery Key modeli, kalıcı kayıp riski açıkça onaylatılarak | Yalnızca Apple sunuyor; hiçbir IdP ürünü sunmuyor |
| 8 | **`recovery_grant`** (Entra TAP eşdeğeri) — yardım masası hesabı devretmez, pencere açar | Keycloak'ta yok; Okta'da custom rol kurgusuyla elle inşa ediliyor |
| 9 | **Normal giriş, devam eden kurtarmayı otomatik iptal eder** | Apple yapıyor; IdP ürünlerinde yok |
| 10 | **Kurtarma/onboarding yeniden tetikleme oranı bir güvenlik metriği** | Unit 42'nin (Ağu 2026) doğrudan tavsiyesi; hiçbir üründe yok |

---


## BÖLÜM II — HESAP BAĞLAMA VE BİRLEŞTİRME

### 11. Pre-hijacking: hesap daha var olmadan ele geçirilir

**Kaynak (doğrulandı, yaygın atıf hatası düzeltildi):**
"**Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web**", Avinash Sudhodanan (bağımsız araştırmacı, MSRC hibesiyle) + Andrew Paverd (**Microsoft Security Response Center**), **USENIX Security '22**, Boston, 10-12 Ağustos 2022.
PDF: `usenix.org/system/files/sec22-sudhodanan.pdf` · arXiv:2205.10174 (20 May 2022) · MSRC blog: 23 Mayıs 2022.

> ⚠️ **İki yaygın hata:** (1) Bu çalışmanın **Ohio State ile ilgisi yoktur** — karışıklık muhtemelen üzerine inşa ettiği Ghasemisharif ve ark. (USENIX Security 2018, University of Illinois at Chicago) çalışmasından geliyor. Ayrıca "Microsoft Research" değil, **MSRC**. (2) Rakamlar sürekli karıştırılıyor: **75 servis test edildi → 35 servis zafiyetli → 56 ayrı zafiyet → 252 saldırı denemesi.**

**Tehdit modeli:** Saldırgan sıradan bir web saldırganıdır ve kurbanın **yalnızca e-posta adresini** bilir. Üç faz: (1) **Pre-hijack** — kurban daha hesap açmamışken saldırgan hareket eder, (2) **Kurban eylemi** — kurban hesabı oluşturur veya kurtarır, (3) **Saldırı** — saldırgan erişimi geri alır.

#### 11.1 Beş varyant

**1. Classic-Federated Merge (§4.1)** — Saldırgan kurbanın e-postasıyla klasik (e-posta+parola) kayıt yapar. Kurban sonra federe (SSO) yoldan gelir. Servis e-posta eşleşmesiyle birleştirir. Son durum **S8**: `Email=kurban, Passwd=saldırgan123, IdP=kurbanIdP`. Saldırgan parolayla, kurban SSO ile girer — ikisi de aynı hesaba.

**2. Unexpired Session (§4.2)** — Saldırgan hesabı açar, giriş yapar ve oturumu **süresiz canlı tutar** (scriptlenebilir keep-alive). Kurban kayıt olamaz, parolayı sıfırlar, kullanmaya başlar. Servis parola sıfırlamada diğer oturumları düşürmüyorsa → **S9**: `SessionId = saldırganSid + kurbanSid`. **En yaygın varyant** (74 potansiyel / 19 fiilî) — çünkü federasyon hiç gerekmiyor.

**3. Trojan Identifier (§4.3)** — 1 ve 2'nin birleşimi. Saldırgan klasik hesabı açar ve **kendi federe kimliğini** ona bağlar. Kurban parolayı sıfırlar; saldırganın IdP bağı hayatta kalır (**S10**). *Alternatif tanımlayıcı varyantı:* saldırgan kendi telefonunu veya ikinci e-postasını ekler, sonra oradan parola sıfırlama veya tek kullanımlık giriş linkiyle döner. Makale, benzer görünen adres seçmeyi (`victm@example.com` veya `hedefservis@example.com`) açıkça bir aldatma tekniği olarak sayıyor.

**4. Unexpired Email Change (§4.4)** — Saldırgan hesabı açar, e-posta değişimini **başlatır ama onaylamaz** (**S6**). Kurban parolayı sıfırlar ve kullanır. Saldırgan sonra hâlâ geçerli capability URL'ine tıklar → **S11**, e-posta artık saldırganın → parola sıfırlama tetiklenir. Ön koşul: e-posta değişim linkinin **günlerce geçerli** olması ve parola sıfırlamayla iptal edilmemesi.

**5. Non-verifying IdP (§4.5)** — 1'in **ayna görüntüsü**. Saldırgan, e-posta sahipliğini doğrulamayan bir IdP kullanarak kurbanın e-postasını taşıyan federe kimlik üretir; kurban sonra klasik kayıt olur ve servis birleştirir. Makale iki ismi açıkça veriyor: *"We found that these **IdPs [OneLogin and Okta]** did not perform email verification for test accounts, yet these accounts could still be used as federated identities at other services."* **Müşterilerin kendi IdP'sini getirebildiği (BYO IdP) her kurumsal plan bu yüzeydedir.**

**Ve altıncı teknik — "Email Verification Trick" (§4.6):** Saldırgan **kendi doğrulanmış** e-postasıyla kayıt olur, sonra birincil e-postayı kurbanınkiyle **değiştirir**. Servis yeni adresi doğrulamadan bağlıyorsa, kayıtta zorunlu doğrulama olsa bile yukarıdaki her saldırı yeniden mümkün olur (S4 → S7 → S14). **Bu, "kayıtta e-posta doğruluyoruz" savunmasının neden yetmediğidir.**

#### 11.2 Yaygınlık (Tablo 3, test penceresi Ocak–Haziran 2021)

| Saldırı | Potansiyel | **Zafiyetli** |
|---|---|---|
| Classic-Federated Merge | 54 | **13** |
| Unexpired Session | 74 | **19** |
| Trojan Identifier | 49 | **12** |
| Unexpired Email Change | 72 | **11** |
| Non-verifying IdP | 3 | **1** |
| **Toplam** | **252** | **56** |

**İsimli vakalar (§5.3):** Dropbox (Unexpired Email Change, HackerOne Haziran 2021) · Instagram (Trojan Identifier, alternatif tanımlayıcı) · **LinkedIn** (Unexpired Session + Trojan Identifier; **parola değişiminde aktif oturumları düşürmeyi varsayılan yaptı**) · Wordpress.com (HackerOne'da "Not Applicable" işaretlendi; self-hosted WordPress etkilenmiyordu çünkü her eylemden önce e-posta doğrulaması istiyor) · **Zoom** (Classic-Federated Merge — ücretsiz hesaplar doğrulama istiyordu ama **ücretli hesap oluşturma istemiyordu** — ve Non-verifying IdP, araştırmacılar OneLogin kullandı; Zoom ikisini de yüksek önemde kabul edip düzeltti).

#### 11.3 Bu sınıf hâlâ canlı: better-auth, Haziran 2026

**GHSA-qq9h-g4jm-xgf3**, yayın **26 Haziran 2026**, **CVSS 8.3 (High)**, CVE atanmadı.
Etkilenen: `better-auth >= 1.1.3, < 1.6.22` ve `1.7.0-beta.0`–`1.7.0-beta.9`.

Mekanizma: Saldırgan kurbanın adresiyle e-posta+parola kaydı yapar; hesap doğrulanmamış kalır. Kurban sonra **magic link / e-posta OTP** ile girer; bu e-postayı doğrulanmış işaretler ama **ne saldırganın parolasını siler ne de önceki oturumları iptal eder.**

Advisory'nin kendi cümlesi: *"A password set before anyone proved control of the mailbox kept working after the owner proved control."*

Düzeltme (1.6.22 / 1.7.0-beta.10): e-posta doğrulaması **otoriter** kabul edildi — **önceden var olan parola silinir, oturumlar iptal edilir, doğrulanmış işaretlenir ve taze bir oturum verilir.**

> **Argus için kural:** Sahiplik kanıtı geldiğinde, o kanıttan **önce** oluşturulmuş her credential ölür. Bu bir tercih değil, invariant.

#### 11.4 Makalenin kendi azaltma seti (§6.2)

- **Kök neden (§6.2.1): iddia edilen tanımlayıcının sahipliğinin doğrulanmaması** — genelde doğrulama *asenkron* yapılıp hesap bu arada kullanılabilir olduğu için. Çözüm: **doğrulama tamamlanmadan hiçbir hesap eylemine izin verme.** IdP'ye güveniliyorsa, IdP'nin doğrulamayı yaptığına dair **güçlü bir garanti** talep edilmeli.
- **Parola sıfırlamada:** (a) diğer tüm oturumları ve auth token'larını düşür; (b) **bekleyen tüm e-posta değişim işlemlerini iptal et**; (c) kullanıcıya bağlı federe kimlikleri, alternatif e-postaları ve telefonları göster ve **hangilerini tutacağını açıkça seçtir — varsayılan "bağı kopar"**. Makale bunu "tanımadıklarını işaretle" yaklaşımına tercih ediyor, çünkü kullanıcılar uyarıları görmezden geliyor.
- **Birleştirmede (birebir):** *"the service must ensure that the user currently controls both accounts. For example, when the user attempts to create an account via the federated route but a classic account already exists for the same email address, the user should be required to provide or reset the password for the classic account."*
- **E-posta değişim onayları:** capability geçerliliğini minimize et; aynı doğrulanmamış tanımlayıcıya **yeniden capability üretimini rate-limit'le**.
- **Doğrulanmamış hesap budama:** agresif buda, tanımlayıcı başına tekrar oluşturmayı sınırla — ama makale bunun **DoS riskini** işaretliyor (saldırgan meşru kullanıcının kotasını tüketir) ve sert kota yerine bot tespiti öneriyor.
- **MFA (birebir):** *"the service must also invalidate any sessions created prior to the activation of MFA"* — aksi hâlde MFA, Unexpired Session saldırısını durdurmaz.

---

### 12. "Her iki e-posta da doğrulanmış" yeterli mi? Hayır.

#### 12.1 OIDC Core 1.0 §5.7 — normatif kaynak (birebir)

Spec: *incorporating errata set 2*, **15 Aralık 2023**.

> "The `sub` (subject) and `iss` (issuer) Claims from the ID Token, used together, are the only Claims that an RP can rely upon as a stable identifier for the End-User… Therefore, the only guaranteed unique identifier for a given End-User is the combination of the `iss` Claim and the `sub` Claim.
>
> All other Claims carry no such guarantees… **For instance, an Issuer MAY re-use an `email` Claim Value across different End-Users at different points in time**…
>
> Therefore, other Claims such as `email`, `phone_number`, `preferred_username`, and `name` **MUST NOT be used as unique identifiers for the End-User**, whether obtained from the ID Token or the UserInfo Endpoint."

`email_verified` tanımı (§5.1, birebir):
> "True if the End-User's e-mail address has been verified… this means that **the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed.** The means by which an e-mail address is verified is context specific…"

> **Kritik okuma:** `email_verified: true` **bir ana dair** bir ifadedir ("at the time the verification was performed") ve **kontrolünde olmayan bir tarafça** yapılır. Kalıcı sahiplik kanıtı değildir; spec e-postanın farklı kullanıcılar arasında yeniden kullanımına açıkça izin verir.

#### 12.2 Sağlayıcılar arası gerçek durum

SlashID'nin sağlayıcı bazında taraması (18 Ocak 2024, Joseph Gardner, `slashid.com/blog/sso-safe-email-claim/`):

| Sağlayıcı | Doğrulama sinyali |
|---|---|
| Google | Her zaman doğrulanmış |
| Microsoft/Entra | **`xms_edov`** (Haziran 2023'te eklendi) |
| Okta | UserInfo'da `email_verified` |
| Apple | ID token'da `email_verified` |
| GitHub | API'de `primary`/`verified` |
| **GitLab** | API var ama **`email_verified` alanı yok** — kullanıcı doğrulamayı atlayabilir |
| Bitbucket | `is_primary`/`is_confirmed`, semantiği belirsiz |
| LINE | **`email_verified` yok** |
| **Facebook** | **`email_verified` alanı yok** |

Sonuç (birebir): *"It is unsafe to rely on the Issuer to verify the email of a user."*

#### 12.3 Satıcı kılavuzları

**Auth0:** *"Insecurely linking accounts can allow malicious actors to access legitimate user accounts."* · *"For both manual and automatic account links, your tenant should request authentication for **both** accounts before linking occurs."* · *"Every manual account link should prompt the user to enter credentials."*

**Keycloak — First Broker Login akışı** (`docs/documentation/server_admin/topics/identity-broker/first-login-flow.adoc`):
Sıra: **Review Profile → Create User If Unique → Confirm Link Existing Account → (ALTERNATIVE) Verify Existing Account By Email | Verify Existing Account By Re-authentication**, artı opsiyonel **Automatically Set Existing User**.
Kendi uyarısı (birebir): *"Automatically linking the existing local account to the external identity provider is a potential security hole. **You cannot always trust the information you get from the external identity provider.**"* AutoLink authenticator'ı için: *"dangerous in a generic environment where users can register themselves using arbitrary usernames or email addresses."*
**"Trust Email" per-IdP ayarı**: açıkken Keycloak IdP'nin e-posta claim'ini doğrulanmış sayar ve kendi doğrulamasını atlar. **Bu, Keycloak'ı Non-verifying IdP saldırısının kurbanı yapan tek toggle'dır.**

**Clerk — yayımlanmış en net karar matrisi:**
- Varsayılan varsayım: *"assuming a single owner for each email address."*
- **İkisi de doğrulanmış** → anında bağlanır, **parola korumalı hesaplarda bile**.
- **Clerk'te doğrulanmış, OAuth sağlayıcıda doğrulanmamış** → Clerk kendi doğrulamasını yapar, sonra bağlar.
- **Clerk'te doğrulanmamış** (doğrulanmamış e-posta+parola ile açılmış hesap) ve şimdi doğrulanmış OAuth e-postası geliyor → Clerk **bağlamadan önce parola değişimini zorunlu kılar**, çünkü *"Clerk cannot confirm the original ownership of the account."* ← **Classic-Federated Merge'in ürünleşmiş azaltması.**

**Firebase:** Varsayılan **e-posta başına tek hesap**; çoklu hesap opt-in. Açıldığında *"your app's sign-in flow cannot rely on an email address to identify a user account"* ve `signInWithPopup/Redirect`, `linkWithPopup/Redirect` **sağlayıcı profil bilgisi döndürmeyi bırakır**. Ayardan bağımsız invariant: *"Users can never create multiple accounts with the same email address and sign-in method."*

#### 12.4 Argus'un güvenli bağlama koşul seti

1. `email_verified == true` **RP'nin kendi kayıtlarında** — gelen IdP'nin iddiası yetmez.
2. Gelen IdP **açık bir güvenilir doğrulayıcı allowlist'inde** olmalı (Keycloak "Trust Email" per-IdP). **BYO/custom IdP'lere asla toptan güven** — bu, kelimenin tam anlamıyla Non-verifying IdP saldırısıdır.
3. Bağlama anında **mevcut hesabın kontrolünün kanıtı**: parola tekrarı, zaten bağlı bir IdP ile yeniden kimlik doğrulama, veya mevcut adrese onay e-postası.
4. **Mevcut hesap doğrulanmamış/atıl durumdaysa**, federe/passwordless girişi otoriter sahiplik kanıtı say ve **önceki credential'ı yok et** (better-auth'un düzeltmesi, Clerk'ün zorunlu parola değişimi).
5. Bağlama anında **tüm diğer oturumları ve bekleyen e-posta değişimlerini iptal et** — sadece parola sıfırlamada değil.
6. Birleştirme anahtarı olarak **`(iss, sub)`** sakla; e-postayı **yalnızca arama ipucu** olarak tut.
7. Gelen tarafın doğrulamadığı bir e-postayla asla otomatik bağlama; **doğrulamayan veya saldırganın kontrol edebileceği** bir issuer üzerinden asla otomatik bağlama.

---

### 13. `sub` vs e-posta ve tanımlayıcı geri dönüşümü

#### 13.1 nOAuth — e-postayı anahtar yapmanın gerçek bedeli

**Keşif:** Descope, **20 Haziran 2023** (`descope.com/blog/post/noauth`).

**Mekanizma:** **Herhangi bir** Entra ID tenant'ını kontrol eden saldırgan, tek kullanımlık bir kullanıcının `mail` niteliğini kurbanın e-posta adresine ayarlar. Kullanıcıları `sub`/`oid` yerine `email` ile anahtarlayan çok kiracılı bir SaaS uygulaması, "Microsoft ile giriş yap" akışında saldırgana kurbanın hesabını verir. Parola yok, MFA istemi yok — **MFA ve Conditional Access işe yaramaz**, çünkü kimlik doğrulamanın kendisi meşrudur.

**Zaman çizelgesi:** Microsoft'a bildirim 11 Nisan 2023 → claim dokümantasyonu güncellendi 18 Nisan 2023 → düzeltmeler ve MSRC blogu 20 Haziran 2023 → yeni **`xms_edov`** (Email Domain Owner Verified) claim'i ve **`RemoveUnverifiedEmailClaim`** uygulama bayrağı. **CVE atanmadı.**

**MSRC'nin kendi ifadesi** (20 Haziran 2023, "Potential Risk of Privilege Escalation in Azure AD Applications"): anti-pattern *"use of the email claim from access tokens for authorization"*; *"an attacker can falsify the email claim in tokens issued to applications"*; kök neden: *"AAD users without a provisioned mailbox can have any email address set for their Mail (Primary SMTP) attribute"* ve bu *"not guaranteed to come from a verified email address."*

**İki yıl sonra hâlâ canlı:** Semperis araştırması, **Haziran 2025** — test edilen **104 SaaS uygulamasından 9'u** zafiyetli; tahminî **~15.000 SaaS uygulaması** açık. Semperis'in en can alıcı tespiti: savunmacının, bir uygulamanın doğrulanmamış e-posta claim'i tüketip tüketmediğine dair **hiçbir görünürlüğü yok** — tek çare satıcıya baskı yapmak veya uygulamayı terk etmek.

> ⚠️ **Ölü URL:** `learn.microsoft.com/en-us/entra/identity-platform/migrate-off-email-claim-authorization` artık Entra hub sayfasına 301 yönlendiriyor (8 Eyl 2026'da curl ile doğrulandı). `xms_edov` için canlı referans: `learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference`.

#### 13.2 Kimler tanımlayıcı geri dönüştürüyor

**Google Workspace (yönetici kontrollü) — kurumsal tasarım için en önemli vaka:**
> *"Twenty days after a user's account is deleted, their email address is removed from Google Workspace."*
> *"However, you can reassign the address to another managed user before that 20-day period ends."*
> *"If you plan to use the email address for an unmanaged personal Google Account, you must wait 30 days to prevent account conflicts."*

**→ Evet: bir Workspace yöneticisi aynı e-posta adresini başka bir insana verebilir ve rutin olarak veriyor.** Google'ın kendi troubleshooting dokümanı, silinip yeniden oluşturulan kullanıcının *"a different Google identifier"* aldığını doğruluyor — bu yüzden takvim bildirimleri kesiliyor. Google'ın kendi tavsiyesi sil-ve-yeniden-oluşturdan kaçınmak.

> **Pratik sonuç: aynı e-posta, farklı `sub`.** E-postayla anahtarlayan RP, ayrılan çalışanın hesabını sessizce yerine gelene devreder. `sub` ile anahtarlayan RP onu doğru şekilde yeni bir insan sayar. **`sub` argümanının tamamı budur.**

**Google tüketici hesapları:** *"An inactive Google Account is an account that has not been used within a 2-year period. Google reserves the right to delete an inactive Google Account… if you are inactive across Google for at least two years."* Silme için en erken tarih 1 Aralık 2023.
> ⚠️ **DOĞRULANAMADI:** "Google bir hesabı sildikten sonra o Gmail adresiyle yeni hesap açılamaz" iddiası çok tekrarlanıyor ama **resmî destek sayfasının metninde bulunamadı.** Bu iddiayı yazma. Buna karşılık `sub`'ın asla yeniden kullanılmadığı garantisi Google'ın geliştirici dokümanlarında **açıkça yazılı** — atıf için onu kullan.

**Microsoft Entra ID:** Workspace'le aynı şekilde geri dönüşüm mümkün (yönetici UPN'yi yeniden oluşturur) ve ek olarak `mail` niteliği varsayılan olarak **keyfî ve doğrulanmamış**. Kararlı tanımlayıcılar: **`oid` + `tid`**, veya `sub` (uygulama+kullanıcı başına pairwise).

**GitHub — kullanıcı adı geri dönüşümü açıkça dokümante:**
> *"Your username will be available for anyone to use after **90 days**."*
İstisnalar (`OWNER/REPOSITORY-NAME` kombinasyonunun kalıcı emekliye ayrılması): namespace'te GitHub Marketplace action'ı olan bir public repo bulunması, veya silinmeden önceki hafta **>100 klon ya da >100 Actions kullanımı**. Container imajları: **>5.000 indirme**de kalıcı emeklilik.
**→ GitHub `login`/kullanıcı adıyla asla anahtarlama. Kararlı anahtar sayısal `id`.**

> ⚠️ **DOĞRULANAMADI:** Slack ve Okta için açık bir yeniden kullanım garantisi (olumlu ya da olumsuz) birincil dokümanlarda bulunamadı. İddia etme.

---

### 14. Birleştirme: geri alınamazlık, çakışma, denetim

**Auth0 — klasik yıkıcı birleştirmenin en net dokümante örneği:**
- Bağlamada: ikincil nitelikler → `profileData`; **ikincil hesabın `user_metadata` ve `app_metadata`'sı imha edilir**; ikincil hesap kullanıcı listesinden kaldırılır.
- Bağ kopardığında (birebir): *"The secondary account is removed from the identities array of the primary account. A new secondary user account is created."* — ve kritik cümle: *"**The secondary account will have no metadata.**"*
- **→ Bağla+kopar bir gidiş-dönüş DEĞİLDİR.** Metadata bağlama anında yok edilir ve geri getirilemez. Birleştirme geri alınamazlığının kesin, atıf verilebilir örneği budur.
- Bir kimliği tamamen kaldırmak için önce bağı kopar, sonra **yeni oluşan** ikincil hesabı sil.

**Atlassian:** Atlassian Administration'da bir "Account merge" veri yönetimi aracı var ama **beta ve yalnızca katılımcı organizasyonlara açık**. Genel self-service birleştirmenin uzun süredir yokluğunu açık feature request'ler doğruluyor (ID-240, ACCESS-1364). Topluluk kılavuzları org birleştirmelerinin **geri alınamaz ve otomatik un-merge'i olmadığını** söylüyor *(topluluk kaynağı — ikincil).*

**GitHub:** Hesap birleştirme **sunmuyor**; dokümante yol repoları transfer edip fazla hesabı silmek. Merge endpoint'i yok.

> ⚠️ **DOĞRULANAMADI:** Stripe ve Google için "iki hesabı birleştir" birincil dokümanı bulunamadı. Bu ürünlerin merge özelliği olduğunu **iddia etme**. Stripe'ın muadili primitif'ler ekip rolleri ve organizasyon üyeliğidir, hesap birleştirme değil.

**Tasarım sonucu:** Endüstrinin açığa vurulmuş tercihi şu — birleştirme ya **yok**, ya **kalıcı beta**, ya **destek kanalıyla kapılı**, ya da **kayıplı ve geri alınamaz**. Argus için dürüst çerçeve:
- **Bağlamayı (linking, geri alınabilir, eklemeli) birleştirmeye (merge, yıkıcı) tercih et.**
- Birleştirme kaçınılmazsa: yazmadan **önce her iki kaynak kaydın anlık görüntüsünü al**, her iki kaynak ID'yi ve operatör kimliğini taşıyan bir merge denetim olayı yaz, ve işlemi **tek yönlü** kabul et.

### 15. Bağ koparma: son kimlik doğrulama yöntemi koruması

- **Clerk** invariant'ı doğrudan ifade ediyor: *"Each user has at least one authentication identifier, which might be their email address, phone number, or a username."*
- **Auth0 — dikkat çekici olumsuz bulgu:** bağ koparma dokümantasyonunda kilitlenme veya son kimlik doğrulama yönteminin kaldırılması hakkında **hiçbir uyarı yok**. Sorumluluk tamamen uygulamada.
- **Firebase:** `unlink()` sağlayıcı bazında var; platform seviyesinde koruma dolaylı.
- **Keycloak:** hesap konsolu federe kimlik bağını koparmaya izin veriyor; koruma yerel parolanın veya başka bağlı bir IdP'nin kalmasıdır. ⚠️ **Açıkça dokümante edilmiş "son credential kaldırılamaz" zorlaması bulunamadı — DOĞRULANAMADI.**

> **Sentez (araştırma boşluğu değil, gerçek bulgu):** "Son kimlik doğrulama yöntemi" koruması dört üründe de büyük ölçüde **uygulama katmanı sorumluluğu**, IdP tarafından zorlanan bir invariant değil. Clerk buna en yakın olan. **Argus bunu şema seviyesinde zorlarsa gerçek bir ayrışma noktasıdır.**

### 16. E-posta değişimi ve eski posta kutusunun başkasına geçmesi

- **Kurumsal posta kutusu devri istisna değil, dokümante ve desteklenen davranıştır** — §13.2'deki Google Workspace 20 günlük yeniden atama penceresi. Ayrılan çalışanın `alice@sirket.com` adresi meşru şekilde başka birinin adresi olabilir ve o e-postayla anahtarlayan her RP hesabı yanlış kişiye atfeder.
- **Süresi dolmuş alan adı devralma — akademik dayanak:** *"Game of Registrars: An Empirical Analysis of Post-Expiration Domain Name Takeovers"*, **Lauinger ve ark., USENIX Security 2017.** Kritik istatistik: **tüm .com alan adlarının ~%10'u, eski kaydın silindiği gün** otomatik drop-catch servisleri tarafından yeniden kaydediliyor. **Terk ile düşmanca kontrol arasındaki pencere fiilen sıfır.**
- **Saldırı zinciri:** süresi dolmuş alan adını yeniden kaydet → **catch-all mail sunucusu** kur → `herhangi@terkedilmis-alan.com` kullanan her SaaS hesabında parola sıfırlama tetikle. PortSwigger Daily Swig tam olarak bunu belgeledi (araştırmacılar bir hukuk bürosunun Office 365 ve G Suite hesaplarına, oradan gizli belgelere ulaştı).
- **Azaltmalar:** `(iss, sub)`'a bağla · yüksek değerli hesaplar için e-posta sahipliğini periyodik yeniden doğrula · **alan adının MX/kayıt değişimini** yeniden doğrulama tetikleyicisi say · ayrıcalıklı hesaplarda parola sıfırlama için sadece e-posta linki değil **step-up auth** iste.

---

## BÖLÜM III — IMPERSONATION ("KULLANICI OLARAK GİRİŞ")

### 17. RFC 8693: impersonation ile delegasyonun farkı bir tasarım kararıdır

**Künye:** RFC 8693, **Ocak 2020**, Standards Track. Yazarlar: M. Jones, A. Nadalin (Microsoft); B. Campbell, Ed. (Ping Identity); J. Bradley (Yubico); C. Mortimore (Visa). Grant type: `urn:ietf:params:oauth:grant-type:token-exchange`.

#### 17.1 §1.1 — birebir

> "When principal A **impersonates** principal B, A is given all the rights that B has within some defined rights context and is **indistinguishable from B in that context**. Thus… insofar as any entity receiving such a token is concerned, they are actually dealing with B. It is true that some members of the identity system might have awareness that impersonation is going on, but **it is not a requirement**."

> "**Delegation** semantics are different… With delegation semantics, **principal A still has its own identity separate from B**, and it is explicitly understood that while B may have delegated some of its rights to A, any actions taken are being taken by A representing B. In a sense, **A is an agent for B**."

> "Delegation semantics are typically expressed in a token by including information about both the primary subject of the token as well as the actor… Such a token is sometimes referred to as a **composite token**."

> **Argus için tasarım dersi:** *Impersonation* olarak inşa edilmiş bir "kullanıcı olarak giriş" özelliği, tanım gereği **kaynak sunucuda atfedilemezdir** — RS, A'yı B'den ayırt edemez. *Delegation* olarak inşa edilmiş olan, operatörün kimliğini token'da tutar ve **her hop'ta denetlenebilirdir.** RFC 8693, impersonation'ın kimlik sistemine görünür olmasının bile gerekmediğini söylüyor.
>
> **→ Destek araçları impersonation semantiği değil, delegasyon semantiği kullanmalıdır.**

#### 17.2 `act` claim'i (§4.1, birebir)

> "The `act` (actor) claim provides a means within a JWT to express that delegation has occurred and identify the acting party to whom authority has been delegated… For example, the combination of the two claims `iss` and `sub` might be necessary to uniquely identify an actor."

> "However, claims within the `act` claim pertain only to the identity of the actor and are not relevant to the validity of the containing JWT… Consequently, **non-identity claims (e.g., `exp`, `nbf`, and `aud`) are not meaningful when used within an `act` claim and are therefore not used**."

Kanonik destek-impersonation şekli (Figure 5) — token kullanıcı **hakkında**, `act` yöneticiyi adlandırıyor:
```json
{ "aud":"https://consumer.example.com", "iss":"https://issuer.example.com",
  "exp":1443904177, "nbf":1443904077,
  "sub":"user@example.com",
  "act": { "sub":"admin@example.com" } }
```

İç içe zincirler (birebir):
> "**The outermost `act` claim represents the current actor while nested `act` claims represent prior actors. The least recent actor is the most deeply nested.**"

> "For the purpose of applying access control policy, **the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim. Prior actors identified by any nested `act` claims are informational only and are not to be considered in access control decisions.**"

#### 17.3 `may_act` — rızanın standart yeri (§4.4, birebir)

> "The `may_act` claim makes a statement that **one party is authorized to become the actor and act on behalf of another party.** The claim might be used, for example, when a `subject_token` is presented to the token endpoint in a token exchange request and `may_act` claim in the subject token can be used by the authorization server to determine whether the client… is authorized to engage in the requested delegation or impersonation."

```json
{ "aud":"https://consumer.example.com", "iss":"https://issuer.example.com",
  "sub":"user@example.com",
  "may_act": { "sub":"admin@example.com" } }
```

`act` ve `may_act`, token introspection yanıtında üst düzey üye olarak döndüğünde aynı semantiğe sahiptir.

> **`may_act`, kullanıcının impersonation'a rızasını kodlamak için standart-yerlisi yerdir** — ön-yetkilendirme ifadesi *öznenin kendi* token'ında taşınır. Bu, Salesforce'un "grant login access" modeliyle birebir örtüşür (§19).

#### 17.4 Yaşam döngüsü uyarısı (§2.1, birebir)

> "the act of performing a token exchange has no impact on the validity of the subject token or actor token… the exchange is a one-time event and **does not create a tight linkage between the input and output tokens**"

**→ İptal otomatik olarak yayılmaz.** "Bir impersonation oturumunu nasıl öldürürüm" sorusunun cevabı standartta yok; Argus'un kendi bağını kurması gerekiyor.

§5 Security Considerations (birebir): *"**Any time one principal is delegated the rights of another principal, the potential for abuse is a concern.** The use of the `scope` claim (in addition to other typical constraints such as a limited token lifetime) is suggested to mitigate potential for such abuse."*

### 18. Impersonation altında ne yasak olmalı

**Normatif bir RFC veya OWASP listesi yoktur** — bu, satıcı/uygulayıcı konsensüsüdür. Kaynaklar arasında yakınsayan set:

**Tutarlı şekilde engellenen:**
- Parola veya herhangi bir kimlik doğrulama credential'ının değiştirilmesi
- **MFA faktörü** kaydı, kaldırılması veya sıfırlanması
- Birincil **e-posta** veya telefon değişimi
- **Hesap silme** ve her türlü yıkıcı/toplu silme
- **Ödeme / faturalama** işlemleri
- **Toplu veri dışa aktarımı**
- Rol yükseltme, izin verme, yeni kullanıcı davet etme
- Yeni API anahtarı / uzun ömürlü token oluşturma

**Tutarlı şekilde zorunlu kılınan:**
- Kısa oturum (uygulayıcı literatüründe 10-15 dk; **WorkOS 60 dk**; **Okta destek erişimi 8 saat**)
- Impersonate edilen arayüzde görünür, kalıcı **banner**
- Oturum başında **zorunlu gerekçe** kaydı
- **Başlangıçta ve bitişte ayrı denetim olayları**, artı eylem başına **özneye değil operatöre** atıf
- Okuma yollarında bile hassas alanların **maskelenmesi**
- Impersonate edilen kullanıcıya bildirim

### 19. Ürünler — özellik özellik

**Salesforce — kullanıcı rızasının referans uygulaması.**
Varsayılan **kullanıcı-izin-verir**: son kullanıcı kişisel ayarlarından, açık bir **Access Duration** seçicisiyle (bitiş tarihi) giriş erişimi verir. Organizasyon bunu **"Administrators Can Log in as Any User"** ayarıyla ezebilir — bu rıza gereksinimini kaldırır. Başkası olarak girilmişken yapılan eylemler **Setup Audit Trail** ve **Login History**'de, eylemi yapan yöneticinin kullanıcı adıyla kaydedilir.
**→ `may_act` modelinin ürünleşmiş hâli:** rıza öznede yaşar, zaman sınırlıdır ve geri alınabilir.
> ⚠️ Salesforce Help bir JS SPA olarak render ediliyor ve fetcher'lara "CSS Error" kabuğu döndürüyor; **birebir alıntı çıkarılamadı.** URL'i kaynak göster ama birebir alıntı yapma.

**Okta — genel bir yönetici "kullanıcı olarak giriş" yok; dar, rıza kapılı bir destek varyantı var.**
Var olan: **destek vakasına bağlı Read-Only Impersonation Access.**
- *"Read-Only Impersonation Access will now be tied directly to a support case and only accessible by the Okta Support team members associated with the case."*
- **Onay gerekli**: *"The Super Admin for the organization and the Admin who entered the case."* Otomatik bildirim yok — destek mühendisi onayı doğrudan istemeli.
- **Süre: varsayılan 8 saat**; "Extend access by 1 day" linkiyle uzatılabilir (tıklamadan +24 saat).
- **Açıkça salt-okunur** — müşteri verisini değiştiremez.
- System log denetim olayları var.
> **Taramadaki en iyi tasarlanmış rıza modeli:** vakaya bağlı, çift onaylayıcı, zaman kutulu, salt-okunur, loglu.

**ServiceNow — en güçlü *zorlanan kısıtlama* modeli.**
Security Center 2.0 sertleştirme ayarı: **"Restrict Impersonation to Admin"**.
Zorlanan davranışlar: impersonate edilirken **impersonate edilen kullanıcıdan tüm scope-korumalı roller ve şifreleme-bağlamı rolleri kaldırılır**; bir uygulama-yöneticisi rolü (HR, Security Incident Response) olan kullanıcıyı impersonate eden yönetici **o rolün verdiği özelliklere erişemez**; **impersonate edenin kendi admin ayrıcalıkları askıya alınır** — admin modülleri yok, yükseltilmiş eylem yok. Süre boyunca **kırmızı banner**. `impersonator` rolü gerekir.
> **→ Konu B'deki en değerli tasarım deseni: "ayrıcalık kesişimi, ayrıcalık birleşimi değil."** Impersonate edilmiş oturum ne yöneticinin haklarını ne de hedefin tam haklarını alır.

**GitLab — en iyi denetim olayı modeli.**
Impersonation **varsayılan olarak açık**, instance genelinde kapatılabilir. Oturum boyunca sağ üstte **"Stop impersonation" düğmesi**. **Başlangıç ve bitiş için ayrı denetim olayları**, *artı* impersonate eden yöneticinin kimliğini taşıyan eylem başına denetim olayları. **Instance denetim olayları ve kullanıcının üyesi olduğu her grubun grup denetim olayları** olarak görünür. Microsoft Sentinel'de GitLab impersonation için hazır tespit kuralı bile var.
Canlı tartışma: kullanıcıların yöneticinin kendilerini impersonate etmesini **yasaklayabilmesi** talebi (gitlab-foss#40385) hâlâ açık.

**Zendesk — "Assume identity". Zayıf kontroller; öğretici karşı örnek.**
- *"An administrator or any agent with permission to edit user profiles can take on the credentials of an end user."*
- **Yalnızca son kullanıcılar assume edilebilir — agent'lar değil.**
- **Kritik zayıflık, birebir:** *"any actions you take, such as creating a ticket or adding a comment to a ticket, are done by the user you're logged in as."* → **Eylemler ajana değil kurbana atfedilir** — tam olarak RFC 8693 impersonation-semantiği problemi.
- **Son kullanıcı bildirimi dokümante değil. Dokümanda güvenlik uyarısı yok. Özel denetim izi ifadesi yok.**
- Zendesk'in *kendi* personeline karşı müşteri kontrolü: Admin Center > Account > Security > Advanced > **Account assumption**. **Varsayılan kapalı**, her an geri alınabilir, süre seçenekleri: *"One day, One week, One month, One year, or **Indefinitely**."* — **"Indefinitely" seçeneği eleştirilmeyi hak ediyor.**
> ⚠️ "Play as user" Zendesk Guide/Gather terminolojisidir ve "Assume identity" ile **aynı özellik değildir** — karıştırma.

**Shopify — impersonation yerine kapsamlı, rızalı, kendiliğinden sona eren kimlik.**
Partner istek gönderir → mağaza sahibi e-posta + Shopify Home bildirimi alır → **istekler 7 gün geçerli**. **4 haneli collaborator request kodu** — yalnızca kodu bilen partner istek gönderebilir; mağaza sahibi kodu yenileyerek dolaşımdaki bilgiyi geçersiz kılabilir. Onay anında uygulama/kanal bazında granüler izinler. **90 gün girişsizlikte erişim kendiliğinden sona erer.**
> **→ Shopify'ın "kullanıcı olarak giriş" cevabı: "yapma; onun yerine kapsamlı, rızalı, kendiliğinden sona eren bir kimlik ver."**

**WorkOS — modern, standart-hizalı referans uygulamaya en yakın olan** (`workos.com/blog/support-impersonation-delegated-sessions`, **25 Ağustos 2026**).
Dört kontrol: (1) **her iki kimlik de token'da — `sub` = impersonate edilen kullanıcı, `act` = destek ajanı, açıkça RFC 8693'ü izleyerek**; (2) **org-kapsamlı** — kullanıcı birden çok organizasyona üyeyse ajan tenant bağlamını seçmek zorunda; (3) **zaman sınırlı — AuthKit impersonation oturumları 60 dakikada otomatik sona erer**, API ile daha kısası mümkün; (4) aktör, hedefler ve metadata taşıyan, müşterinin bağımsızca sorgulayabildiği tam denetim izi.
**Varsayılan kapalı; org seviyesinde opt-in.** **Zorunlu gerekçe alanı** `session.created` olayına kaydedilir. **Ayrı denetim olayları** delege girişleri standart kimlik doğrulamadan ayırır.

**Auth0 — KULLANIMDAN KALDIRILDI.**
Legacy endpoint `POST /users/{user_id}/impersonate`, *"can only be used with **Global Client** credentials"*. Impersonate edilen kullanıcının profiline **`impersonated` ve `impersonator` nitelikleri yazar** (gömülü denetim mekanizması). Tenant bayrağı `disable_impersonation` var. Auth0 personeli (Gerald Czifra, 31 Tem 2025 forum): *"the deprecation of the Impersonation legacy feature… created security concerns."* Daha eski personel yanıtı (23 Şub 2023): *"we do not support impersonation."* Önerilen ikame: ayrı bir **Help Desk uygulaması** — `adminsOnly` app_metadata bayrağı, özel token claim'leri ve *"API middleware that distinguishes 'help-desk rep acting on another account' from 'user authenticating as themselves.'"*
> ⚠️ **Kesin kullanımdan kaldırma tarihi bulunamadı.** Özellik Auth0'ın resmî Deprecations and Migrations sayfasında **yer almıyor** (kontrol edildi: Rules/Hooks EOL 18 Kas 2026, Node 12/16 EOL 15 Ağu 2025, Azure AD v1 EOL 1 Eyl 2025, legacy connection enabled-clients EOL 13 Tem 2026, üçüncü-parti uygulama kontrolleri EOL 23 Eki 2026 — **impersonation kaydı yok**). **Belirli bir tarih yazma.**

**Discourse:** Impersonate özelliği var. Loglama talebi **2014'ten** beri açık; impersonate edilen kullanıcının bilgilendirilmesi talebi **hâlâ açık** — "özneyi bilgilendir" kontrolünün endüstride en az uygulanan kontrol olduğunun kanıtı. **Recursive impersonation** ayrı bir açık hata sınıfı (iç içe `act` ile paralel).

> ⚠️ **Grafana'da kullanıcı impersonation'ı YOK.** Dokümanlarındaki "impersonation" tamamen **BigQuery datasource'ları için Google Cloud servis hesabı impersonation'ıdır** — farklı bir kavram. İddia etme.
> ⚠️ **Stripe'ta "View Dashboard As"** yalnızca Connect platformu → bağlı hesap içindir, genel bir impersonation değil. Ve kendi dokümanı uyarıyor: *"For connected accounts that don't access the full Stripe Dashboard, such as Express and Custom accounts, you still see the full Stripe Dashboard… what you see isn't an exact representation of what the connected account sees."* → **"view as" sadakat-doğru değil.** Stripe'ın modeli roller (örn. refund yapabilen ama ayar değiştiremeyen **Support Specialist** rolü). ⚠️ Stripe'ta rıza kapılı geçici destek erişimi özelliği **bulunamadı** — iddia etme.

#### 19.1 Özet matris

| Ürün | Kullanıcı rızası | Banner | Süre sınırı | Denetim | Eylem kısıtı |
|---|---|---|---|---|---|
| **Salesforce** | ✅ varsayılan (kullanıcı verir, süreli) | ✅ | ✅ Access Duration | ✅ Setup Audit Trail + Login History | profil/izinler üzerinden |
| **Okta (destek)** | ✅ çift onaylayıcı, vakaya bağlı | — | ✅ 8s varsayılan, +24s | ✅ system log | ✅ **salt-okunur** |
| **WorkOS** | org opt-in (kullanıcı bazında değil) | ✅ | ✅ 60 dk | ✅ + zorunlu gerekçe | önerilir, zorlanmaz |
| **ServiceNow** | ❌ | ✅ kırmızı | ❌ | ✅ | ✅ **en güçlü** — roller sıyrılır, admin askıya alınır |
| **GitLab** | ❌ | ✅ stop düğmesi | ❌ | ✅ **başlangıç+bitiş+eylem başına** | ❌ |
| **Zendesk** | ✅ yalnız Zendesk personeli için | — | ✅ yalnız Zendesk personeli | ⚠️ zayıf; **eylemler kurbana atfedilir** | yalnız son kullanıcılar |
| **Shopify** | ✅ + 4 haneli kod | y.d. | ✅ 7g istek / 90g atıl | ✅ | ✅ kapsamlı izinler |
| **Stripe** | ❌ (platform→bağlı hesap) | — | ❌ | ✅ | ⚠️ sadakat-doğru değil |
| **Discourse** | ❌ | ✅ | ❌ | ⚠️ tarihsel olarak yok | ❌ |
| **Auth0** | ❌ | ❌ | ❌ | profile bayrak yazar | ❌ — **kaldırıldı** |

### 20. Suistimal olayları

#### 20.1 Twitter, 15 Temmuz 2020 — en iyi belgelenmiş vaka

**Birincil kaynak: NY DFS "Twitter Investigation Report", Ekim 2020.** Bir finansal düzenleyicinin iç araç suistimalini incelediği nadir belge.

**Araçların yetenekleri (birebir):**
> *"Some of the internal tools include nonpublic information about each Twitter user account, including the account's associated email address, phone number, and the… IP address for the user's login location. In response to user requests, authorized Twitter employees use the internal tools, in part, to **update email addresses, reset forgotten or expired passwords, or enable or disable multifactor authentication ('MFA')**."*

**→ §18'deki "yasak olmalı" listesindeki her işlem.**

**Erişim ölçeği (birebir):**
> *"Twitter did limit access to the internal tools, but **over 1,000 Twitter employees still had access to them**… Immediately after the Twitter Hack, however, Twitter further limited the number of employees with access to the internal tools, even though it caused a slowdown of some job functions."*

**Eksik olan kontroller (birebir — en alıntılanabilir kısım):**
> *"Authentication requirements should also be calibrated to match the risk… **Access to critical functions should require MFA. Another possible control for high-risk functions is to require certification or approval by a second employee before the action can be taken.** An approval requirement can limit the damage if an attacker compromises one employee's access."*

**→ Impersonation için dört-göz onayı, bir finansal düzenleyici tarafından tavsiye ediliyor.**

**Vektör:** vishing — saldırganlar çalışanları arayıp *"claim[ing] to be calling from the Help Desk in Twitter's IT department"* dedi; **uygulama tabanlı (push) MFA, çalışanları istemi onaylamaya ikna ederek yenildi**; DFS donanım güvenlik anahtarı öneriyor. Saldırgan *"a 17-year old hacker and his accomplices"*; kayıp **118.000$+ bitcoin**. Twitter'ın hack'ten **yedi ay önce, Aralık 2019'dan beri CISO'su yoktu**.

#### 20.2 Okta, Ekim 2023 — destek sistemi ihlali (impersonation özelliği suistimali DEĞİL)

İlk ele geçirme ~28 Eylül 2023 → Okta tespit 13 Ekim → kamuya açıklama 19 Ekim; yetkisiz dosya erişimi 28 Eylül – 17 Ekim.
Mekanizma: çalınan credential → Okta destek vaka yönetim sistemi → **müşterilerin sorun giderme için yüklediği HAR dosyaları canlı oturum token'ları içeriyordu** → parolasız, MFA'sız oturum ele geçirme.
Ölçek: başlangıçta ~%1 müşteri (~184 org); Okta sonradan **134 müşterinin HAR dosyasına** erişildiğini ve **5 müşteride** oturum ele geçirildiğini doğruladı — üçü kendi açıklamalarını yayımladı: **Cloudflare, 1Password, BeyondTrust.**

> **Çerçeveleme:** Bu, impersonation-özelliği riski değil **destek-kanalı** riskidir. Ders: destek araçları ve ürettikleri artefaktlar (HAR dosyaları, ekran görüntüleri, loglar) **kendi başlarına ayrıcalıklı erişim yüzeyidir.** Salesforce/Okta tarzı rızalı impersonation'dan **açıkça ayır.**

#### 20.3 Robinhood, 3 Kasım 2021 — destek sosyal mühendisliği

Saldırgan **bir Robinhood destek temsilcisini telefonla arayıp uzaktan erişim yazılımı kurdurdu** ve destek sistemlerine erişti. ~5 milyon kişinin e-posta adresi, farklı bir ~2 milyonluk kümenin tam adı, daha küçük bir grubun ad/e-posta/doğum tarihi/telefon/posta kodu açığa çıktı — toplam ~**7 milyon**. SSN, banka hesabı veya kart yok; müşteri finansal kaybı yok. Sonrasında şantaj talebi geldi; Mandiant devreye girdi.
**Birincil kaynak: SEC Form 8-K eki, 8 Kasım 2021.**

### 21. Argus için impersonation tasarımı

**Temel karar: impersonation semantiği hiç uygulanmayacak. Sadece delegasyon.**

```rust
struct DelegatedSession {
    subject_user_id: Uuid,          // token'ın sub'ı
    actor_user_id: Uuid,            // token'ın act.sub'ı — ASLA düşmez
    tenant_id: Uuid,                // WorkOS dersi: org-kapsamlı olmalı
    reason: String,                 // ZORUNLU, boş olamaz
    consent: ConsentRecord,         // aşağıya bak
    started_at: DateTime,
    expires_at: DateTime,           // mutlak tavan: 60 dk
    granted_scopes: Vec<Scope>,     // KESİŞİM, birleşim değil
    stripped_roles: Vec<RoleId>,    // ServiceNow modeli: sıyrılanlar kaydedilir
    read_only: bool,
    redaction_profile: RedactionProfileId,
}

enum ConsentRecord {
    SubjectGranted { at: DateTime, expires_at: DateTime },   // Salesforce/may_act modeli
    DualApproval { case_id: String, approver_a: Uuid, approver_b: Uuid },  // Okta modeli
    OrgPolicy { policy_id: PolicyId, org_admin: Uuid },      // WorkOS modeli
    BreakGlass { incident_id: String, four_eyes: (Uuid, Uuid) },  // NY DFS tavsiyesi
}
```

**Zorlanan invariantlar:**

| # | Invariant | Kaynak |
|---|---|---|
| 1 | Token daima `sub`=özne, `act`=operatör taşır. Impersonation modu **yoktur** | RFC 8693 §1.1 |
| 2 | **Ayrıcalık kesişimi:** oturum `granted ⊆ (operatör_hakları ∩ özne_hakları)`. Operatörün admin hakları **askıya alınır** | ServiceNow |
| 3 | §18'deki yasak işlem listesi **motor seviyesinde** engellenir, UI'da değil | Twitter/NY DFS |
| 4 | `reason` boş olamaz; `session.created` olayına yazılır | WorkOS |
| 5 | Mutlak TTL tavanı 60 dk; uzatma yeni rıza gerektirir | WorkOS |
| 6 | Başlangıç + bitiş + **eylem başına** denetim olayı, hepsi operatöre atıflı | GitLab |
| 7 | Özneye bildirim gönderilir (opsiyonel değil) | Discourse'un 12 yıllık açık talebi |
| 8 | Kullanıcı, kendisinin impersonate edilmesini **yasaklayabilir** (org politikası izin veriyorsa) | gitlab-foss#40385 |
| 9 | **Recursive delegation yasak** — `act` derinliği delege oturumlarda 1 | Discourse recursive impersonation hatası |
| 10 | Özne token'ında `may_act` yoksa ve org politikası yoksa → **reddet** | RFC 8693 §4.4 |
| 11 | Delege oturum, özne'nin normal oturumlarını **etkilemez** ve iptali ayrı yayılır | RFC 8693 §2.1 uyarısı |
| 12 | Destek artefaktları (HAR, ekran görüntüsü, log) ayrı bir ayrıcalık sınıfı; oturum token'ı içerenler otomatik redakte edilir | Okta Ekim 2023 |

**Bu listedeki hiçbir ürün 12'nin hepsini yapmıyor.** En yakın olanlar: WorkOS (1, 4, 5, 6), ServiceNow (2, 3), Okta (rıza modeli).

---

## BÖLÜM IV — KULLANICI YAŞAM DÖNGÜSÜ, SİLME VE TOMBSTONE

### 22. SCIM tek başına yaşam döngüsünü ifade edemez

#### 22.1 RFC'lerin gerçekte söylediği (birebir)

**RFC 7644 §3.6 — tüm tombstone tasarımının taşıyıcı cümlesi:**
> "Clients request resource removal via DELETE. Service providers **MAY choose not to permanently delete the resource** but **MUST return a 404 (Not Found)** error code for all operations associated with the previously deleted resource."

- Başarılı DELETE **204 No Content** döner.
- **Spec soft delete'i açıkça kutsuyor** — ama **404 zorunlu kılıyor, 410 Gone değil.** RFC 7644 hiçbir yerde 410'dan bahsetmiyor.
- **Sonuç:** Tombstone'lanmış bir kullanıcı, SCIM API üzerinden hiç var olmamış bir kullanıcıdan **ayırt edilemez olmalıdır.** 410 dönmek, silinmiş bir hesabın varlığını sızdırır — bu başlı başına bir mahremiyet ifşasıdır.

**RFC 7643 §4.1.1 — `active` niteliği (birebir):**
> "A Boolean value indicating the user's administrative status. **The definitive meaning of this attribute is determined by the service provider.** As a typical example, a value of true implies that the user is able to log in, while a value of false implies that the user's account has been **suspended**."

Kasıtlı belirsizliğe dikkat: **SCIM, deaktivasyonun ne anlama geldiğini tanımlamıyor.** Her IdP kendi semantiğini icat ediyor. **JML interop acısının kök nedeni budur.**

`meta` nitelikleri yalnızca `created`, `lastModified`, `version` (ETag), `location`, `resourceType`. **Çekirdek SCIM'de tombstone/deletedAt yoktur.**

#### 22.2 SCIM WG 2025-2026 — soru varsaydığından daha ileride

| RFC | Başlık | Tarih | Statü |
|---|---|---|---|
| **RFC 9865** | Cursor-Based Pagination of SCIM Resources | **2025-10** | Proposed Standard |
| **RFC 9944** | Device Schema Extensions to the SCIM Model | **2026-05** | Proposed Standard |
| **RFC 9967** | **SCIM Profile for Security Event Tokens (SETs)** | **2026-05** | Proposed Standard |

**RFC 9967, "SCIM Events" sorusunun cevabıdır — artık taslak değil, yayımlanmış RFC.** `draft-ietf-scim-events`'ten geldi ve **hem** RFC 7643'ü (yeni `ServiceProviderConfig` nitelikleri) **hem** RFC 7644'ü (opsiyonel asenkron istek yeteneği) güncelliyor.

**Tanımladığı olay tipleri — doğrudan durum makinemizi ilgilendiriyor:**
```
urn:ietf:params:scim:event:feed:add   /  :feed:remove
urn:ietf:params:scim:event:prov:create:{notice|full}
urn:ietf:params:scim:event:prov:patch:{notice|full}
urn:ietf:params:scim:event:prov:put:{notice|full}
urn:ietf:params:scim:event:prov:delete          ← kalıcı kaldırma
urn:ietf:params:scim:event:prov:activate        ← aktivasyon
urn:ietf:params:scim:event:prov:deactivate      ← deaktivasyon
urn:ietf:params:scim:event:misc:asyncresp
```

**RFC 9967 deaktivasyonu silmeden ayrı tel olayları olarak ayırıyor.** Deactivate, kaynağın *"has been deactivated and disabled"* olduğunu ve öznenin *"may no longer have an active security session"* durumunda olabileceğini bildirir. Delete kalıcı kaldırmayı bildirir, kaynak *"is also removed from the feed"*, karşılık gelen bir `feedRemove` **SHALL NOT** yayımlanır ve — kopyalanmaya değer detay — **delete olayları hiçbir payload niteliği taşımaz.** Yani olayın kendisi mahremiyet koruyucudur. **Bu, taklit edilmesi gereken tombstone desenidir.**

> ⚠️ **SCIM 2.1 diye bir çalışma kalemi YOK.** Aktif taslak yok. İddia etme.
> `draft-ietf-scim-roles-entitlements-01` (mover problemi — tenant başına keşfedilebilir geçerli rol/yetki değerleri) **süresi doldu ve arşivlendi**, RFC olmadı. `draft-ietf-scim-use-cases-reloaded-02` de süresi dolmuş. **Soft delete veya parola yönetimi üzerine SCIM taslağı yok.**

#### 22.3 Satıcı deprovisioning davranışı

**Okta:**

| | Deactivate | Delete |
|---|---|---|
| Oturumlar | "User is no longer able to create sessions, and all active sessions in Okta are stopped" | aynı |
| Gruplar | **Kaldırılmaz** — "deactivated users no longer have access to any apps, the users aren't removed from any groups" | "removed from all Okta groups, including all app assignments and role assignments through group membership" |
| Auth faktörleri | korunur | deaktive edilir ve kaldırılır |
| Geri alınabilir | evet | **"When you delete a user account, you can't undo the deletion."** |
| Veri | korunur | "Okta automatically initiates the **permanent deletion of Customer Data in 30 days**"; "any data referencing the user is kept for a period defined by the Okta Data Retention Policy" |

**Son satır gerçek dünyadaki tombstone'dur:** Okta kullanıcıyı hard-delete eder ama **referans veren veriyi** (denetim log satırları) ayrı bir saklama politikası altında **tutar.** Bu, tam olarak GDPR Md. 17 ile denetim saklama arasındaki ayrımın ürünleşmiş hâlidir.

Ayrıca Okta'da **oturum/token temizleme deaktivasyondan ayrı bir işlemdir** ("Clear User Sessions" — tüm IdP oturumlarını kaldırır ve *opsiyonel olarak* OIDC/OAuth refresh ve access token'larını iptal eder). **İki ayrı düğme olması bir tasarım hatasıdır; Argus'ta tek atomik işlem olmalı.**

**Microsoft Entra ID:** **30 günlük geri dönüşüm kutusu** ile soft delete. *"After that 30-day window passes, the permanent deletion process is automatically started and can't be stopped."* · *"A permanently deleted user can't be restored by anyone, including Microsoft customer support."*
> ⚠️ **Tombstone tasarımını doğrudan ilgilendiren bilinen operasyonel tehlike: orijinal kullanıcı soft-delete durumundayken UPN başka bir hesaba yeniden atanabiliyor ve geri yükleme çakışıyor/başarısız oluyor.** Bu, üretimdeki tekillik-kısıtı problemidir.

**Keycloak:** İptal **oturum tabanlı, token tabanlı değil.** *"Clicking 'Sign out all active sessions' does not revoke outstanding access tokens—outstanding tokens must expire naturally."* **Not-before (push revocation) politikası** onları iptal edebilir, **ama yalnızca Keycloak OIDC adaptörünü kullanan client'lar için — diğer adaptörlerde çalışmaz.** Offline token'lar hiç sona ermez ve SSO idle timeout'una tabi değildir; kullanıcı bazında (Consents sekmesi) veya iptal politikasıyla iptal edilmeleri gerekir.
Keycloak'ta **atıl kullanıcıları otomatik devre dışı bırakma/silme yoktur** — açık issue keycloak#38108.

> ⚠️ OneLogin davranışı için birincil kaynağa ulaşılamadı — **DOĞRULANMADI**, iddia etme.

#### 22.4 Mover / privilege creep — kanıt zayıf, dikkatli kullan

Niteliksel mekanizma iyi tanımlanmış ama **mover kaynaklı yetki birikimini izole eden titiz yayımlanmış bir istatistik bulunamadı.** Aşağıdaki rakamları araştırma değil, satıcı pazarlaması olarak değerlendir.

Mekanizma: creep **iki boyutludur** — yatay (daha çok sistem) ve dikey (aynı sistemde daha yüksek izin) — ve ikisi de rol değişiminde hızlanır. Kök nedenler: tekrar talep olmasın diye geniş verme, çalışan mevcut bir rolü kopyalama, ve transferde erişimi yerinde bırakma ("kaldırmak ödüllendirilmiyor ve biraz riskli").

> **Tasarım dokümanı için tavsiye:** yüzdeleri değil, **mekanizmayı ve düzenleyici eşikleri** (§26) kaynak göster.

#### 22.5 Yetim/hayalet hesap istatistikleri — kaynaklandırma zayıf, işaretle

Orchid Security raporu (10 Ağustos 2026) **metodoloji ve örneklem büyüklüğü açıklamadan başka satıcıları alıntılayan bir whitepaper**: "%44 kuruluş 1.000'den fazla yetim hesap bildiriyor" (Varonis'e atfen); "tüm hesapların %26'sı bayat olabilir (>90 gün kullanılmamış); bazı kuruluşlarda bu %90'a ulaşmış" (Varonis'e atfen); "2024'teki bulut ihlallerinin %27'si atıl credential kötüye kullanımı içeriyordu" (Trustle'a atfen).

> **Hiçbiri yayımlanmış bir metodolojiye izlenebilir değil. Ponemon veya Oomnitza yetim-hesap raporu bulunamadı.** Bu yüzdeleri tasarım dokümanında kullanma.

---

### 23. Hard delete vs anonimleştirme + tombstone

#### 23.1 GDPR Md. 17

Silme gerekçeleri 17(1)(a)-(f). **Denetim logunu taşıyan istisnalar 17(3)'te:**
- **(b)** Birlik/Üye Devlet hukuku kapsamında **yasal yükümlülüğe uyum**, veya kamu yararı/resmî otorite görevi
- **(e)** **hukuki taleplerin tesisi, kullanılması veya savunulması**
- ayrıca (a) ifade özgürlüğü, (c) halk sağlığı, (d) arşivleme/araştırma/istatistik

**Güvenlik denetim loglarına uygulanması:** **17(3)(e) beygirdir** — dolandırıcılık, yetkisiz erişim veya istihdam uyuşmazlıklarına karşı savunma için kimlik doğrulama/yetkilendirme olaylarını tutmak. 17(3)(b) sektörel hukukun saklama zorunlu kıldığı yerlerde geçerli.

> **Ama hiçbiri toptan bir ruhsat değildir:** istisna, o amaç için *gerekli* olanla sınırlıdır. Yani log, gerçekten o amaca hizmet eden alanlara **minimize edilmelidir** — ki bu tam olarak takma adlı denetim ID'leri argümanıdır (§23.5).

#### 23.2 ICO — "put beyond use" (yedekler)

ICO'nun dört parçalı testi — veri fiilen silinmemiş olsa bile "kullanım dışı bırakılmış" sayılması için veri sorumlusu:
1. Kişisel veriyi **herhangi bir bireye ilişkin herhangi bir kararı bilgilendirmek için kullanamaz veya kullanmaya teşebbüs etmez**;
2. **Başka hiçbir organizasyona erişim vermez**;
3. Veriyi **uygun teknik ve organizasyonel güvenlikle çevreler**; ve
4. Mümkün olduğunda veya olduğu anda **kalıcı silmeyi taahhüt eder**.

Yedeklere uygulanması: ICO, yedek verinin hemen üzerine yazılamadığı durumlarda bile kullanım dışı bırakılmışsa tatmin oluyor — veri *"merely held on the systems until it is replaced in line with an established schedule."*
ICO ayrıca veri sorumlularının bireylere *"absolutely clear… as to what will happen to their data when their erasure request is fulfilled, including in respect of backup systems"* olmasını vurguluyor.

> ⚠️ ICO'nun kendi sayfası otomatik fetch'e **HTTP 403** döndürüyor; ifade arama sonuçlarından kurtarıldı. **Yayımlamadan önce canlı sayfaya karşı doğrula.**

> **Tasarım sonucu: "put beyond use", tombstone + crypto-shred mimarisinin *hukuki dayanağıdır*.** Tombstone'un dört ayağı da karşılaması gerekir — özellikle **1. ayak**, tombstone'un asla kişi hakkında bir kararı beslememesi anlamına gelir (risk skorlaması yok, dolandırıcılık listesi yok), ve **4. ayak**, süresiz saklama değil **zamanlanmış gerçek silme işi** gerektirir.

#### 23.3 CNIL — log saklama

**Délibération n° 2021-122, 14 Ekim 2021.**
**"6 ay" iddiası yarı doğru.** CNIL'in temel çizgisi düz altı ay değil, **altı ay ile bir yıl arası bir aralık**:
> "une journalisation permettant d'assurer une traçabilité des accès et des actions des différents utilisateurs habilités à accéder aux systèmes d'information **pour une durée comprise entre six mois et un an**"

Belgelenmiş iç kontrol tedbirleriyle **üç yıla kadar** (ve gerekçelendirilmiş hâllerde daha uzun) uzatılabilir. Daha uzun saklamaya izin veren istisnalar: yasal yükümlülük (düzenlenmiş sektörler), özellikle yüksek risk (hassas işleme, kritik operatörler), veya izlerin dondurulmasını gerektiren süregelen olay/dava.

#### 23.4 Düzenleyici uygulama — 2026'nın en önemli gelişmesi

**EDPB Coordinated Enforcement Framework (CEF) 2025 — silme hakkı.** Rapor: **"Implementation of the right to erasure by controllers", kabul 18 Şubat 2026.**

Ölçek: **32 denetim otoritesi, 764 veri sorumlusu** (KOBİ'den çok uluslusuna, kamu ve özel).

**Bu tasarımı doğrudan vuran bulgular:**
- **Yedeklerde silme**, veri sorumluları için temel zorluk olarak işaretlendi.
- **"Reliance by some controllers on inefficient anonymisation techniques to handle erasure requests as an alternative to deletion"** — DPA'lar bunu açıkça bir başarısızlık modu olarak adlandırdı. **Bu, zayıf bir "silmek yerine anonimleştir" tombstone'una karşı doğrudan uyarıdır.**
- Saklama sürelerini belirlemede zorluk; iç prosedür eksikliği; veri öznesine yetersiz şeffaflık.

**Takip: dokuz DPA resmî soruşturma açtı; yirmi üçü olgu tespiti yürüttü**; İrlanda, Fransa, Portekiz, Slovenya ve Almanya'da devam ediyor.

**Silmeme cezaları:** Hamburg DPA — bir tahsilat şirketine, borçlu verisini yasal silme sürelerinin ötesinde (bazı vakalarda hukuki dayanaksız beş yıla kadar) tuttuğu için **900.000 €**.

#### 23.5 Anonimleştirme vs takma adlaştırma

**WP29 Görüş 05/2014 (WP216), kabul 10 Nisan 2014** — her tekniğin değerlendirilmesi gereken üç parçalı sağlamlık testi: **singling out, linkability, inference.**
> **Takma adlaştırma anonimleştirme DEĞİLDİR** — bağlanabilirliği azaltır ama GDPR kapsamından çıkarmaz.
> **Bu yüzden "hash'lenmiş kullanıcı ID'li tombstone" takma adlıdır, anonim değildir ve kapsamda kalır.**

**EDPB Görüş 28/2024 (AI modelleri), kabul 17 Aralık 2024** — anonimlik eşiğinin en güncel otoriter ifadesi: tanımlanma olasılığının, veri sorumlusu **veya üçüncü bir taraf** tarafından "makul olarak kullanılması muhtemel tüm araçlarla" **ihmal edilebilir** olması gerekir; **vaka bazında** değerlendirilir. **Geri çevrilebilir veya anahtarı saklanan bir dönüşümün "anonim" olduğu argümanını kapatır.**

#### 23.6 Crypto-shredding — pratik desen

Satırları değil, **kullanıcı başına anahtarı** yok et.

Mimari: **kullanıcı başına Data Encryption Key (DEK) ile envelope encryption**, PII'nin alan seviyesinde şifrelenmesi; silme = DEK'in imhası. "PII veritabanlarına, analitik tablolarına, yedek anlık görüntülerine, log dosyalarına, cache'lere ve warehouse export'larına yayılmış" probleminde her kopyayı bulmanın *"operationally painful and error-prone"* olmasını çözer.

> **Denetim logu uzlaştırması buradaki kilit içgörüdür: bütünlük hash'lerini *şifreli metin üzerinden* hesapla.** Böylece hash zinciri sağlam ve doğrulanabilir kalırken düz metin hesaplamalı olarak kurtarılamaz hâle gelir. **Bütünlük ve gizlilik birbirinden ayrışır.**

Kopyalanmaya değer operasyonel detay: **anahtar imhası gecikmesi bir güvenlik özelliğidir** — varsayılan 30 günlük pencere, yapılandırılabilir minimum 24 saat.

> ⚠️ **§23.4 ışığında uyarı:** crypto-shredding, ICO "put beyond use" altında savunulabilir ve anonimleştirme-ikamesinden güçlüdür — ama EDPB CEF raporu DPA'ların artık bu tekniklerin gerçekten etkili olup olmadığını **aktif olarak sorguladığını** gösteriyor. **Anahtar imha kanıtını belgele.**

---

### 24. Tombstone tasarımı — ID ve e-posta yeniden kullanımı

#### 24.1 E-posta yeniden kullanımı: Google "asla" diyor

**Gmail (birincil kaynak, `support.google.com/mail/answer/61177`):**
> **"Your Gmail address can't be used by anyone in the future."**

Kurtarma penceresi: *"Gmail deletes your emails and settings after 30 days"*; adres o dönemde kurtarılabilir.

> ⚠️ **Doğru sayfayı kaynak göster.** Google'ın **Inactive Account Policy** sayfası 2 yıl kuralını ve 1 Aralık 2023 başlangıç tarihini doğruluyor ama **adres yeniden kullanımı konusunda sessiz.** Yeniden kullanım ifadesi **Gmail silme sayfasında** yaşıyor, atıllık sayfasında değil. (Bkz. §13.2'deki doğrulanamayan iddia — bu, onun doğrulanmış hâlidir.)

#### 24.2 Yahoo 2013 — kanonik uyarı hikâyesi

Yahoo atıl Yahoo ID'lerini geri dönüştürdü; talep son tarihi 14 Temmuz 2013, 23:59 PT.
**Sonuç tam olarak parola-sıfırlama devralma riskiydi:** geri dönüştürülmüş ID'lerin yeni sahipleri, önceki sahibe yönelik e-postaları aldı — kişisel veriler dahil; eleştirmenler parola sıfırlamalarıyla gerçek kimlik devralma potansiyeli işaretledi. Yahoo'nun azaltmaları (bounce-back'ler, toplu abonelik iptalleri ve yeni bir SMTP başlığı) dönemin haberlerine göre **pratikte başarısız oldu.**

**O başlık gerçek bir standarda dönüştü:**
**RFC 7293, "The Require-Recipient-Valid-Since Header Field and SMTP Service Extension", Temmuz 2014, Standards Track.**
> "This document defines an extension for SMTP called 'RRVS' to provide a method for senders to indicate to receivers a point in time when the ownership of the target mailbox was known to the sender. This can be used to detect changes of mailbox ownership and thus prevent mail from being delivered to the wrong party."

Motivasyon metni tam senaryoyu adlandırıyor: *"employment changes at a company can cause an address used for an ex-employee to be assigned to a new employee"* ve hassas vakayı *"automatically generated messages, such as account statements or **password change instructions**"* olarak tanımlıyor.

> **Tasarım çıkarımı:** IdP, yeniden atanmış olabilecek bir kurumsal adrese hesap kurtarma postası gönderiyorsa **RRVS standartlaşmış azaltmadır.** Ve bu, IdP'nin **e-posta bağlaması başına `mailbox_owner_since` zaman damgası** tutması gerektiği anlamına gelir.

#### 24.3 GitHub — vahşi doğadaki en iyi belgelenmiş tombstone

GitHub bir `owner/repo` namespace'ini yeniden adlandırma veya hesap silme sırasında **kalıcı olarak emekliye ayırır** — **eğer** namespace Marketplace Action'ı olan public repo içeriyorsa, **veya** önceki hafta **>100 klon ya da >100 Actions kullanımı** varsa.

Emekliye ayrıldıktan sonra ad **kalıcı olarak kilitlenir — orijinal sahip bile yeniden kullanamaz**; o adı içeren yeniden kullanım, transfer ve yeniden adlandırmalar kullanıcılar ve organizasyonlar genelinde engellenir. Yalnızca GitHub personeli, nadiren, hukuki veya güvenlik gerekçesiyle geçebilir.

Gerekçe açıkça **kimliğe bürünme ve typosquatting karşıtı** (tedarik zinciri bağımlılık karışıklığı).

> **Çalınacak tasarım fikri: risk katmanlı emeklilik.** GitHub her namespace'i sonsuza kadar tombstone'lamıyor — yalnızca kanıtlanmış downstream bağımlılığı olanları. **IdP için ucuz analog:** bir kez bile verilmiş bir token'da, dış federasyon assertion'ında veya denetim açısından anlamlı bir grant'ta görünmüş tanımlayıcıları kalıcı tombstone'la; hiç aktive edilmemiş STAGED hesapların tanımlayıcılarının yeniden kullanımına izin ver.

#### 24.4 Slack — tekillik kısıtı kullanıcıya görünen bir hata olarak

Slack'te deaktivasyon geri alınabilir ve profil, mesajlar ve dosya yüklemeleri **Slack veritabanında kalır.** Daha önce deaktive edilmiş birini yeniden davet etmek şu hatayı üretir:
> **"This person is already in your workspace, but their account is deactivated"**

**Yani Slack, deaktive edilmiş (tombstone'lanmış) kayıtlara karşı bir tekillik kısıtı zorluyor** — ve bunu kullanıcıya görünür kılıyor. Bu, tekillik-kısıtının üretim sistemlerinde DB katmanında zorlandığının kanıtıdır.

#### 24.5 Argus için sentez

- **Kullanıcı ID'si: koşulsuz olarak asla yeniden kullanılmaz.** SCIM `id`, her downstream denetim kaydında, SET/CAEP olay öznesinde ve token `sub`'ında birleştirme anahtarıdır. **RFC 9967'nin `prov:delete` olayının hiçbir payload niteliği taşımaması modeldir** — hayatta kalan tek şey tanımlayıcıdır.
- **E-posta: üç uygulanabilir strateji, risk katmanına göre seç:**
  1. **Asla yeniden kullanma** (Google Gmail modeli) — en güvenli, sınırsız tombstone büyümesi.
  2. **Hash'lenmiş e-posta tombstone'u** — `HMAC(pepper, normalized_email)` + `deleted_at` sakla, düz metni at. Tekillik kısıtını ve "bu adres daha önce kullanıldı mı?" kontrolünü PII tutmadan korur. **Ama WP216'ya göre bu takma adlıdır, anonim değildir** — GDPR kapsamında kalır ve **pepper'ın kendisi bir crypto-shred kaldıracıdır.**
  3. **N gün tut, sonra serbest bırak** — yalnızca (a) eski adrese bağlı tüm kurtarma yollarını geçersiz kılarsan ve (b) `mailbox_owner_since` kaydedip giden kurtarma postasında RFC 7293 semantiğine uyarsan savunulabilir.
- **Tekillik kısıtı mekaniği:** tekilliği canlı satırlar *ve* tombstone'lar üzerinde zorla (tombstone'lanmış satırları içeren kısmî/filtreli unique index), aksi hâlde yeniden kayıt silinmiş bir principal'in tanımlayıcısını sessizce diriltir.
- **Tombstone'lanmış SCIM kaynağında asla 410 dönme** — RFC 7644 §3.6 **404** diyor.

---

### 25. Askıya alma/dondurma ve token etkileri

#### 25.1 CAEP / SSF — cevap "final"

**Üç Shared Signals spec'inin tamamı 2 Eylül 2025'te OpenID Final Specification olarak onaylandı.**
Oylama: **85 kabul, 1 itiraz, 25 çekimser — 433 üyeden 111'i (%25,6)**, %20 nisabını aştı.
*"A Final Specification provides intellectual property protections to implementers of the specification and **is not subject to further revision**."*

| Spec | Statü |
|---|---|
| **OpenID Shared Signals Framework 1.0** | **Final, 2 Eyl 2025** |
| **OpenID Continuous Access Evaluation Profile 1.0** | **Final** (belge tarihi 29 Ağu 2025) |
| **OpenID RISC 1.0** | **Final, 2 Eyl 2025** |

**CAEP 1.0 olay tipleri (8):** Session Revoked · Token Claims Change · Credential Change · Assurance Level Change · Device Compliance Change · **Session Established** · **Session Presented** · Risk Level Change.

`session-revoked` (birebir): *"Session Revoked signals that the session identified by the subject has been revoked. The explicit session identifier may be directly referenced in the subject or other properties of the session may be included to allow the receiver to identify applicable sessions."*

> ### ⭐ Bu raporun tek en değerli mimari bulgusu
>
> **CAEP'te hesap-deaktivasyonu veya hesap-silme olayı YOKTUR.** Spec hesap yaşam döngüsü sonlandırmasını hiç ele almıyor.
> **Bu boşluğu RFC 9967'nin `prov:deactivate` / `prov:delete` olayları dolduruyor.**
>
> **Tam bir tasarım için İKİSİ DE gerekir:** yaşam döngüsü durumu için **SCIM SET'leri**, oturum/erişim durumu için **CAEP**. Çoğu tasarım bu dikişi kaçırıyor.

**SSF↔CAEP ilişkisi:** SSF taşıma/yönetim katmanıdır (transmitter, receiver, stream konfigürasyonu, push ve poll teslimi, RFC 8417 SET'leri); CAEP onun üzerinde taşınan olay semantiğini tanımlayan bir *profildir*. RISC, hesap güvenliği olayları için kardeş profildir.

> ⚠️ **CAEP Interoperability Profile'ın Eylül 2026 statüsü DOĞRULANMADI.** Final'e ulaşıp ulaşmadığı teyit edilemedi.
> ⚠️ Microsoft Entra CAE dışındaki satıcı SSF/CAEP benimsemesi (Okta, Google, Apple, Cisco/Duo, SGNL) **birincil kaynaktan doğrulanmadı.**

#### 25.2 Microsoft Entra CAE — en iyi belgelenmiş gerçek uygulama

Doküman güncellemesi **2026-04-08**.

**TTL-vs-iptal sorusunun doğrudan cevabı (birebir):**
> *"Microsoft experimented with the '**blunt object**' approach of reduced token lifetimes but found they **degrade user experiences and reliability without eliminating risks**."*

**Neredeyse gerçek zamanlı iptali tetikleyen kritik olaylar (liste birebir):**
- **User Account is deleted or disabled**
- Password for a user is changed or reset
- Multifactor authentication is enabled for the user
- Administrator explicitly revokes all refresh tokens for a user
- High user risk detected by Microsoft Entra ID Protection

**Token ömrü:** *"Token lifetime increases to long-lived, **up to 28 hours**, in CAE sessions. Critical events and policy evaluation drive revocation, not just an arbitrary time period."* Configurable Token Lifetime politikası CAE-farkındalı oturumlarda **dikkate alınmaz.** CAE olmayan client'lar **1 saatlik** varsayılanda kalır.

**Gecikme:** kritik olay değerlendirmesi neredeyse gerçek zamanı hedefler ama *"latency of up to **15 minutes** might be observed because of event propagation time"*; IP-konum politikası zorlaması anlıktır.

**Mekanizma:** kaynak sağlayıcı, süresi dolmamış bir token'ı **HTTP 401 + claim challenge** ile reddeder; CAE yetenekli client cache'ini atlar ve Entra'dan yeniden ister. **Client desteği gerektirir.**

Kapsam: Exchange Online, SharePoint Online, Teams, MS Graph. **Misafir hesaplar desteklenmiyor.** Devre dışı bırakılmış kullanıcıyı yeniden etkinleştirmenin de gecikmesi var (SPO/Teams ~15 dk, Exchange ~35-40 dk). **Grup üyeliği ve CA politikası değişiklikleri bir güne kadar sürebiliyor** (bazı vakalarda iki saate optimize edildi) — **mover vakası için ciddi bir tuzak.**

#### 25.3 OAuth iptali — tam dil

**RFC 7009 §2.1 — destek asimetrisi (birebir):**
> *"Implementations **MUST** support the revocation of **refresh** tokens and **SHOULD** support the revocation of **access** tokens."*

Kaskad (birebir):
> *"If the particular token is a refresh token **and the authorization server supports the revocation of access tokens**, then the authorization server **SHOULD** also invalidate all access tokens based on the same authorization grant."*

> **Çift koşullu ifadeye dikkat** — kaskad bir SHOULD ve opsiyonel desteğe bağlı. **Bir refresh token'ı iptal etmek, dışarıdaki access token'ları güvenilir şekilde öldürmez.** CAEP/SSF tam olarak bu deliği kapatmak için var.

**RFC 7662 §2.2:** İptal edilmiş token'lar için AS **MUST** `active: false` döner ve inaktif bir token hakkında ek bilgi **SHOULD NOT** içerir.
§4 cache gerilimi (birebir): *"A more aggressive cache with a longer duration will minimize network traffic... but at the risk of stale information about the token."*

**RFC 9700 / BCP 240 (Ocak 2025):** *"Authorization and resource servers **SHOULD** use mechanisms for sender-constraining access tokens, such as mutual TLS [RFC8705] or DPoP [RFC9449]."* Authorization code'lar ilk kullanımdan sonra geçersiz kılınmalı; replay'de AS o code'dan verilmiş tüm token'ları iptal etmeli.
> ⚠️ RFC 9700'de **belirli bir sayısal access-token ömrü tavsiyesi bulunamadı** — iddia etme.

#### 25.4 Durum makinesi

**Okta'nın dokümante modeli** — API/SDK statü enum'u:
`STAGED`, `PROVISIONED`, `ACTIVE`, `RECOVERY`, `PASSWORD_EXPIRED`, `LOCKED_OUT`, `SUSPENDED`, `DEPROVISIONED`

| Durum | Okta'nın tam tanımı |
|---|---|
| **Staged** | "Accounts have a staged status when they're first created, before the activation flow is initiated" |
| **Pending user action** (PROVISIONED) | "the user hasn't provided verification by clicking through the activation email" |
| **Active** | admin parolayla ekledi, veya kullanıcı e-posta doğrulaması gerekmeden self-register oldu |
| **Password reset** (RECOVERY) | "when an admin requests a password reset" |
| **Password expired** | "the password has expired and the account requires an update" |
| **Locked out** | "the user exceeds the number of login attempts defined in the login policy" |
| **Suspended** | "when an admin explicitly suspends them. The user can't access apps" |
| **Deactivated** (DEPROVISIONED) | "an admin explicitly deactivates or deprovisions them. All app assignments are removed" |

- **Geçiş kısıtı:** zaten DEPROVISIONED olan bir kullanıcıda deactivate yapılamaz (**işlem idempotent değil**).
- **Okta modelinde `DELETED` durumu YOK** — silme kaydı durum makinesinden tamamen çıkarır ve 30 günlük Customer Data temizliğini başlatır. **Argus'un `deleted (tombstone)` terminal durumu Okta modelinin üst kümesidir ve daha savunulabilir tasarımdır.**
- **Korunması gereken semantik ayrım:** **LOCKED_OUT sistem kaynaklıdır** (politika/başarısız denemeler) ve **kendiliğinden kurtarılabilir**; **SUSPENDED admin kaynaklıdır** ve admin eylemi gerektirir. **İkisini birleştirmek "bunu kim geri alabilir" özelliğini kaybettirir.**

---

### 26. Atıl hesaplar

#### 26.1 Standart eşikleri — ikisi de doğrulandı

- **CIS Critical Security Controls v8 / v8.1, Safeguard 5.3 "Disable Dormant Accounts"** (birebir):
  > *"**Delete or disable any dormant accounts after a period of 45 days of inactivity, where supported.**"*
  **45 gün DOĞRULANDI.** "where supported" çekincesine ve **silme VEYA devre dışı bırakmaya** izin verdiğine dikkat.
  ⚠️ Implementation Group (IG1'den mi başlıyor) **DOĞRULANMADI.**

- **PCI DSS v4.0 / v4.0.1, Gereksinim 8.2.6** (birebir):
  > *"**Inactive user accounts are removed or disabled within 90 days of inactivity.**"*
  **90 gün DOĞRULANDI.** ⚠️ pcisecuritystandards.org kayıt duvarlı; standart PDF'ine karşı doğrula.

- **NIST SP 800-53 Rev. 5 AC-2(3) "Disable Accounts"** — atıllık tabanlı devre dışı bırakmanın standart referansı; **atıllık süresi kuruluş-tanımlı parametre** (sabit varsayılan yok). ⚠️ Tam metin çekilmedi — **DOĞRULANMADI.**

#### 26.2 Tüketici platform politikaları

**Google — Inactive Account Policy:** *"An **inactive** Google Account is an account that has not been used within a **2-year** period."* · *"**December 1, 2023** is the earliest a Google Account will be deleted due to this policy."*
Muafiyetler: güncel satın alımı olan hesaplar, hediye kartı bakiyesi, aktif işlemli yayımlanmış uygulamalar, yönetilen Family Link hesapları, dijital ürün satın alımları. **Yalnızca kişisel hesaplara uygulanır, okul veya iş (Workspace) hesaplarına değil.**

> ⚠️ Microsoft hesabı atıllık politikası, X/Twitter atıllığı (6 ay) ve handle geri dönüşümü, Apple ID atıllığı — **hiçbiri birincil kaynaktan doğrulanamadı.** İddia etme.

#### 26.3 Pratik not

Keycloak'ta otomatik atıl-hesap devre dışı bırakma/silme **yok** (keycloak#38108); Auth0 topluluğunda aynı boşluk görünüyor.

> **PCI DSS veya CIS hizalanması hedefliyorsan, atıllık süpürme miras alacağın değil, **inşa edeceğin** bir özelliktir.**
>
> Ve KVKK periyodik imhasıyla etkileşir: **tek bir zamanlanmış iş, CIS 5.3 / PCI 8.2.6 *devre dışı bırakmasını* ve KVKK periyodik *imhasını* ancak iki saati ayrı tutarsan karşılayabilir** — 45/90 günde devre dışı bırak, KVKK'nın ≤6 aylık döngüsünde imha et.

---

### 27. Veri taşınabilirliği (GDPR Md. 20)

#### 27.1 WP242 rev.01

**"Guidelines on the right to data portability", WP242 rev.01**, ilk kabul 13 Aralık 2016, revize ve kabul 5 Nisan 2017. EDPB tarafından ilk genel kurulunda onaylandı.
> ⚠️ EC PDF uç noktaları otomatik fetch'e ayrıştırılamaz binary döndürdü; aşağıdaki içerik arama çıkarımı + hukuk bürosu analizlerinden. **Alıntı olarak yayımlamadan önce PDF'e karşı doğrula.**

**Kapsam içi — "provided by" geniş okunuyor:**
- Hem **aktif ve bilinçli sağlanan** veri (form gönderimleri) hem de **"gözlemlenen" veri** (arama geçmişi, konum verisi). WP29, veri sorumlularını aşırı dar okumaya karşı açıkça uyarıyor.
- Revize metindeki gözlemlenen veri örnekleri: **"raw data processed by a smart meter or other connected objects, activity logs, history of website usage or search activities"**.

> **Bir IdP için bu belirleyicidir: kimlik doğrulama logları ve giriş geçmişi gözlemlenen veridir ve TAŞINABİLİRDİR.** Bu, denetim loglarını tamamen dahilî saymakla doğrudan çelişir.

**Kapsam dışı:** **Türetilmiş veya çıkarımsal veri** sağlanmak zorunda değil — algoritmik çıktılar, **kişisel veriden üretilen analitik profiller, değerlendirme raporları**, kredi skorları.

**Format:** Md. 20 "structured, commonly used and machine-readable" istiyor. Sektöre özgü format yaygın kullanımda değilse **CSV, XML ve JSON gibi açık formatlar** sağla.

**Üçüncü taraf verisi:** WP29, talep edenle ilgili ve onun tarafından sağlanmış bir veri kümesinde görünen üçüncü taraf verisi için aşırı dar okumaya karşı uyarıyor — **kişisel amaçlarla kullanıldığı sürece**; kanonik örnek: **gelen ve giden aramaları içeren telefon kayıtları.** Alıcı veri sorumlusu üçüncü taraf verisini onların aleyhine amaçlarla işleyemez.

#### 27.2 Md. 20 vs Md. 15

Md. 20 **dayanak** olarak daha dar (yalnızca rıza veya sözleşme, ve yalnızca otomatik işleme) ama **biçim** olarak daha güçlü (makine okunabilir ve teknik olarak mümkünse doğrudan veri sorumlusundan veri sorumlusuna iletim hakkı). Md. 15 erişim tüm hukuki dayanakları kapsar ama format garantisi taşımaz. **IdP export akışı ikisini de karşılamalı ama birbirlerinin yerine geçmezler.**

#### 27.3 EU Data Act ve DMA

- **Regulation (EU) 2023/2854 (Data Act) — 12 Eylül 2025'ten itibaren uygulanabilir. DOĞRULANDI.**
- **Bulut geçişi Bölüm VI, Madde 23-31**: IaaS, PaaS ve SaaS "veri işleme hizmetlerini" kapsıyor — her kapsam içi sözleşmede zorlanabilir geçiş hakları, sınırlanmış ihbar süreleri, veri alma pencereleri, egress ücreti sınırları.
- **IdP için ısıran hüküm budur, IoT bölümleri değil.** Barındırılan bir IdP makul olarak bir "veri işleme hizmetidir" ve bu, dışarı geçişi (kullanıcı, grup, yetki, credential metadata export'u) bir nezaket değil **sözleşmesel yükümlülük** yapar.
- ⚠️ "Geçiş ücretleri Ocak 2027'ye kadar tamamen kaldırılıyor" iddiası **DOĞRULANMADI** — Md. 29'a doğrudan bak.
- **DMA (Regulation (EU) 2022/1925) Md. 6(9)** (birebir): *"The gatekeeper shall provide end users and third parties authorised by an end user, at their request and free of charge, with **effective portability of data provided by the end user or generated through the activity of the end user**"* — ve etkin kullanım için araçlar, **sürekli ve gerçek zamanlı erişim dahil.**
- **Kimlik açısından:** Bir IdP, belirlenmiş bir gatekeeper'ın çekirdek platform hizmetinin parçasıysa (tüketici oturum açma), 6(9) taşınabilirliği toplu export'tan **sürekli, gerçek zamanlı bir API'ye** yükseltir — Md. 20'den mimari olarak farklı bir gereksinim.

#### 27.4 IdP export'u ne içermeli, ne içermemeli

> Parola hash'leri hakkında **otoriter bir düzenleyici ifade yoktur** — arandı, bulunamadı. Aşağısı gerekçelendirilmiş tasarım rehberliğidir, öyle işaretlenmiştir.

**Dahil et:** tanımlayıcılar (kullanıcı ID, kullanıcı adları, e-postalar, telefon) · profil nitelikleri · grup/rol/yetki atamaları · rıza ve grant kayıtları · bağlı dış/federe kimlikler · MFA **kayıt metadata'sı** (faktör tipi, kayıt zamanı, cihaz etiketi) · **kimlik doğrulama/giriş geçmişi** (gözlemlenen veri — WP242 aktivite loglarını açıkça kapsama alıyor) · hesap yaşam döngüsü durum geçmişi.

**Hariç tut:**
- **Parola hash'leri** — hash bir credential'dır, hiçbir anlamlı şekilde kullanıcı-sağlamış veri değildir; export etmek bir taşınabilirlik talebini **çevrimdışı kırma hediyesine** çevirir ve ele geçirilmiş bir export bir credential ihlaline dönüşür. Md. 20(4) ("başkalarının hak ve özgürlüklerini olumsuz etkilememeli") artı Md. 32 güvenlik yükümlülükleri saklamayı destekler.
- **MFA paylaşılan sırları / TOTP tohumları / kurtarma kodları / WebAuthn özel anahtar materyali** — aynı gerekçe, daha keskin.
- **Çıkarımsal/türetilmiş veri** — risk skorları, davranışsal profiller (WP242 hariç tutuyor).
- **Başkalarının verisi** — diğer kullanıcıları adlandıran denetim satırları, üye listelerini açığa vuran grup rosterları, admin-aktör kimlikleri. Redakte veya takma adlaştır.
- **Dolandırıcılık tespitini zayıflatacak dahilî güvenlik sinyalleri.**

> **Süreç:** WP242 talep edenin kimlik doğrulamasını ve iletimin güvenliğini vurguluyor.
> **Export uç noktası başlı başına yüksek değerli bir saldırı yüzeyidir — tam kimlik export'u veren bir hesap devralma, oturum erişimi verenden çok daha kötüdür.** Rate-limit uygula, **step-up/MFA ile yeniden kimlik doğrula** ve export'u denetlenebilir bir güvenlik olayı olarak logla.

---

### 28. KVKK — Türkiye

#### 28.1 6698 sayılı Kanun, Madde 7 (tam metin)

> **MADDE 7 – (1)** Bu Kanun ve ilgili diğer kanun hükümlerine uygun olarak işlenmiş olmasına rağmen, işlenmesini gerektiren sebeplerin ortadan kalkması hâlinde kişisel veriler **resen** veya **ilgili kişinin talebi üzerine** veri sorumlusu tarafından **silinir, yok edilir veya anonim hale getirilir**.
> **(2)** Kişisel verilerin silinmesi, yok edilmesi veya anonim hale getirilmesine ilişkin diğer kanunlarda yer alan hükümler saklıdır.
> **(3)** Kişisel verilerin silinmesine, yok edilmesine veya anonim hale getirilmesine ilişkin usul ve esaslar yönetmelikle düzenlenir.

- **7(2) "saklıdır"**, KVKK'nın GDPR Md. 17(3)(b) yapısal eşdeğeridir — sektörel saklama hukukunun (vergi, e-ticaret, elektronik haberleşme) silme yükümlülüğünü ezmesini sağlayan hüküm budur.
- **7(1)'deki "resen" GDPR'dan daha katı bir çerçeveleme:** proaktif, veri-sorumlusu-başlatmalı imha **olumlu bir görevdir**, sadece bir talebe yanıt değil. Yönetmelikteki periyodik imha makinesi bunu uygular.

#### 28.2 Yönetmelik

**"Kişisel Verilerin Silinmesi, Yok Edilmesi veya Anonim Hale Getirilmesi Hakkında Yönetmelik"**
**Resmî Gazete: 28 Ekim 2017, No. 30224 — DOĞRULANDI.** **Yürürlük: 1 Ocak 2018.**

**Periyodik imha — Madde 11. Altı ay iddiası DOĞRULANDI, tam cümle:**
> **"Bu süre her halde altı ayı geçemez."** (Madde 11/2)

> **Bu bir *azami aralıktır*, bir *saklama süresi* değildir** — tasarım için önemli bir ayrım. Periyodik imha aralıkları veri sorumlusunun kendi politikasında belirlenir ama yönetmelik **sert bir altı aylık tavan** koyar. **GDPR'ın böyle bir sert saati yoktur.**

**Saklama ve imha politikası — Madde 5-6:**
- **Madde 5/1:** **VERBİS'e kayıt yükümlülüğü olan** veri sorumluları, **kişisel veri işleme envanterine uygun olarak** bir saklama ve imha politikası hazırlamak zorundadır.
- **Madde 6:** Politika asgari olarak saklama/silme prosedürlerini, teknik ve idarî tedbirleri, imha yöntemlerini, **sorumlu personelin unvan/birim/görev tanımlarını** ve **periyodik imha sürelerini** içermelidir.
- **VERBİS bağlantısı tetikleyicidir** — politika yükümlülüğü evrensel değildir, kayıt sorumluluğunu takip eder.

**Madde 4 tanımları — KVKK'nın üç yönlü ayrımı GDPR'dan mimari olarak daha keskin:**

| KVKK terimi | Tanım (birebir) | IdP'de teknik karşılığı |
|---|---|---|
| **Silme** | *"Kişisel verilerin ilgili kullanıcılar için hiçbir şekilde erişilemez ve tekrar kullanılamaz hale getirilmesi işlemidir."* — **tanımlı bir kullanıcı kitlesine göreli, mutlak değil** | **Tombstone**: satır kalır, tüm uygulama kullanıcıları/rolleri için erişilemez; SCIM 404 döner |
| **Yok etme** | *"Kişisel verilerin hiç kimse tarafından hiçbir şekilde erişilemez, **geri getirilemez** ve tekrar kullanılamaz hale getirilmesi işlemidir."* — mutlak | **Hard delete + kullanıcı DEK'inin crypto-shred'i + yedek sona ermesi** |
| **Anonim hale getirme** | *"...başka verilerle eşleştirilse dahi hiçbir surette kimliği belirli veya belirlenebilir bir gerçek kişiyle ilişkilendirilemeyecek hale getirilmesidir."* | Denetim satırları özne referansı geri döndürülemez şekilde koparılarak tutulur — **ve WP216/EDPB 28/2024'e göre bir hash yetmez** |

**"Silme" tanımının göreli oluşu, KVKK'nın tombstone'a en yakın kavramıdır** ve bu, tombstone mimarisine GDPR'da olmayan doğrudan bir hukuki dayanak verir.

**Veri sahibi talepleri — Madde 12/1-a:**
> *"Veri sorumlusu talebe konu kişisel verileri siler, yok eder veya anonim hale getirir. Veri sorumlusu, ilgili kişinin talebini **en geç otuz gün içinde** sonuçlandırır."*

> ⚠️ **"3 ay" rakamı silme talepleri için DOĞRULANMADI — iddia etme.** Yönetmelikte bulunan tek süre 30 gündür.

#### 28.3 2024 değişikliği — yurt dışına aktarım

**7499 sayılı Kanun** (8. Yargı Paketi), **Resmî Gazete 12 Mart 2024, No. 32487.**
**Madde 34, 6698'in 9. maddesini ("Kişisel verilerin yurt dışına aktarılması") değiştirdi; değişiklikler 1 Haziran 2024'te yürürlüğe girdi. DOĞRULANDI.**

Yeni Md. 9 — eski rejimin yerine **üç kademeli kaskad**:
1. **Yeterlilik kararı** (Kurul tarafından);
2. yoksa **uygun güvenceler**: **standart sözleşme**, **bağlayıcı şirket kuralları**, **taahhütname** (Kurul izniyle), veya kamu kurumları arası uluslararası anlaşma;
3. ikisi de yoksa yalnızca **arızi** aktarımlar, **açık rıza** dahil gerekçelerle.

> **Önemli yapısal değişiklik: açık rıza, birincil dayanaktan son-çare/arızi-yalnızca dayanağa indirildi.** Kimlik verisini Türkiye dışı bölgelere replike eden bir IdP için **rıza artık uygulanabilir bir mimari değildir** — SCC veya BCR gerekir.

7499 ayrıca **Md. 6** (özel nitelikli veri işleme) ve **Md. 18**'i (idarî para cezaları) değiştirdi.

> ⚠️ **Doğrulanamayanlar:** VERBİS kayıt eşikleri (çalışan sayısı / yıllık bilanço muafiyetleri) · silmeme veya geç imha için KVKK Kurul kararları/cezaları (karar numarası bulunamadı, **iddia etme**) · güvenlik/denetim logu saklamanın silme yükümlülüğüyle ilişkisi hakkında KVKK rehberliği · KVKK Rehberi'ndeki teknik listesi (karartma/maskeleme, toplulaştırma, k-anonimlik, l-çeşitlilik, t-yakınlık vb.) — PDF metin çıkarımı yapılamadı, **madde madde doğrulanmadı.**

---

### 29. Bölüm IV için tasarım kararları

| # | Karar | Dayanak |
|---|---|---|
| 1 | Yaşam döngüsü durumları: `staged → provisioned → active ⇄ {locked_out, suspended} → deactivated → deleted(tombstone)`. **LOCKED_OUT ve SUSPENDED birleştirilmez** | Okta enum'u + "kim geri alabilir" özelliği |
| 2 | **SCIM DELETE tombstone yapar, hard delete yapmaz; sonrasında her işlem 404 döner (asla 410)** | RFC 7644 §3.6 |
| 3 | **Hem SCIM SET (RFC 9967) hem CAEP 1.0 transmitter'ı** — biri yaşam döngüsü, diğeri oturum | CAEP'te hesap silme olayı yok |
| 4 | Deaktivasyon **atomiktir**: durum + oturumlar + refresh token'lar + offline token'lar tek işlemde | Okta'da iki ayrı düğme olması hata |
| 5 | **Uzun ömürlü access token (28s'e kadar) + sinyal güdümlü iptal**, kısa TTL değil | Entra'nın "blunt object" bulgusu |
| 6 | Kullanıcı ID'si **asla** yeniden kullanılmaz; e-posta risk katmanına göre (varsayılan: asla) | RFC 9967 payload'suz delete + Gmail |
| 7 | Tekillik kısıtı **canlı satırlar + tombstone'lar** üzerinde | Slack'in üretim davranışı |
| 8 | Her PII alanı **kullanıcı başına DEK** ile şifreli; **yok etme = DEK imhası**, varsayılan 30 gün gecikmeli | Crypto-shredding + ICO 4. ayak |
| 9 | Denetim hash zinciri **şifreli metin üzerinden** hesaplanır | Bütünlük/gizlilik ayrışması |
| 10 | **Periyodik imha işi birinci sınıf ve saati atıllık saatinden ayrı** (imha ≤6 ay; devre dışı 45/90 gün) | KVKK Md. 11 + CIS 5.3 + PCI 8.2.6 |
| 11 | **`mailbox_owner_since`** her e-posta bağlamasında; giden kurtarma postasında RFC 7293 RRVS | Yahoo 2013 → RFC 7293 |
| 12 | **Risk katmanlı tanımlayıcı emekliliği**: token'da/federasyonda görünmüş tanımlayıcılar kalıcı tombstone; hiç aktive olmamış STAGED serbest | GitHub namespace modeli |
| 13 | Export **giriş geçmişini içerir**, parola hash'i ve MFA sırlarını **içermez**; **step-up auth** ve denetim olayı gerektirir | WP242 + Md. 20(4)/32 |
| 14 | Atıllık süpürme **inşa edilir** (miras alınmaz) | Keycloak#38108 |
| 15 | Tombstone **asla bir karar beslemez** — risk skoru yok, dolandırıcılık listesi yok | ICO "put beyond use" 1. ayak |

---

## BÖLÜM V — KAYIT VE ONBOARDING GÜVENLİĞİ

### 30. NIST SP 800-63-4 kayıt tarafında ne diyor

**Yayın: 31 Temmuz 2025** (CSRC belge geçmişi "07/31/25"), SP 800-63-3'ün (Haziran 2017) yerine.
> ⚠️ **Tuzak:** `pages.nist.gov`'daki HTML sürümleri sayfa gövdesinde **"Tue, 26 Aug 2025"** build damgası taşıyor. Bu bir **render tarihidir, yayın tarihi değildir.** Naif bir fetch bunu yayın tarihi olarak raporlar.

#### 30.1 SP 800-63B §3.2.2 "Rate Limiting (Throttling)" — birebir

> "When required by the authenticator type descriptions in Sec. 3.1, the verifier **SHALL** implement controls to protect against online guessing attacks. Unless otherwise specified…, the verifier **SHALL** limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to **no more than 100** by disabling that authenticator. If more than one authenticator is involved with an excessive number of authentication attempts…, **both authenticators SHALL be disabled.** Authenticators that have been disabled **SHALL** be required to rebind to the subscriber account…"

> "The limit of 100 attempts is an **upper bound**, and agencies **MAY** impose lower limits. The limit of 100 was chosen to balance the likelihood of a correct guess (e.g., 100 attempts against a six-digit decimal OTP authenticator output) versus the potential need for account recovery when the limit is exceeded."

**Bot savunması kancası** — 63B'nin "otomatik saldırılara direnç" gereksinimine en çok yaklaştığı yer; **`SHALL` değil `MAY` olduğuna dikkat:**
> "Additional techniques **MAY** be used… These include:
> - Requiring the claimant to complete a **bot detection and mitigation challenge** before attempting authentication
> - Requiring the claimant to wait after a failed attempt for a period of time that **increases** as the subscriber account approaches its maximum allowance (e.g., 30 seconds up to an hour)
> - Leveraging other **risk-based or adaptive** authentication techniques… (e.g., the use of the claimant's IP address, geolocation, timing of request patterns, or browser metadata)"

> "When the subscriber successfully authenticates, the verifier **SHOULD** disregard any previous failed attempts for the authenticators used in the successful authentication."

> ### ⭐ Tasarım dokümanı için kritik çerçeveleme
> 63-4'ün throttling gereksinimi **hesap-kapsamlı ve authenticator-kapsamlıdır** (100 ardışık başarısızlık → o authenticator'ı devre dışı bırak). **IP/edge rate limit DEĞİLDİR ve kayıt suistimali kontrolü DEĞİLDİR.**
> **63B'nin hiçbir yerinde CAPTCHA veya bot savunması zorunlu kılan bir `SHALL` yoktur** — "CAPTCHA" kelimesi belgede hiç geçmiyor. **Kayıt anındaki bot savunması 63A'da yaşıyor, 63B'de değil.**

63B'deki diğer throttling atıfları hep §3.2.2'ye işaret ediyor: §3.1.1.2 (parolalar) · look-up secret'lar · OTP/out-of-band (6 haneli minimum; *"Generating a new authentication secret **SHALL NOT** reset the failed authentication count"*) · **§4.2 kurtarma kodları** (*"The verification of saved recovery codes **SHALL** be subject to the throttling requirements in Sec. 3.2.2."*).

Ayrıca **§5.1 DBSC'yi açıkça tanıyor:**
> "Some technologies (e.g., the emerging device bound session credentials specification [DBSC]) mitigate the risk of theft of session secrets by using cryptographic protocols that **prove the possession** of a session secret rather than using them as bearer tokens… Session secrets used with such proof of possession techniques **MAY persist**. However, RPs and CSPs **SHALL** ensure that the session lifetime limits described in Sec. 2.2.3 are enforced even when a knowledge of the session secret is demonstrated."

#### 30.2 SP 800-63A — kimlik kanıtlama ve yeni sahtekârlık programı

**IAL tanımları, otomasyon karşıtı noktada birebir:**
> "**IAL1** is designed to limit highly scalable attacks (e.g., **automated enrollment attacks**) and to protect against **synthetic identities** and attacks using compromised personal information."
> "**IAL2** … is designed to limit scaled and targeted attacks and to protect against basic evidence falsification, evidence theft, and social engineering tactics."
> "**IAL3** adds the requirements for a trained CSP representative (i.e., proofing agent) to interact directly with the applicant as part of an **on-site attended** identity proofing session and the collection of at least one biometric characteristic."

**Core Attributes (§2.2):** CSP'ler **SHALL** bir devlet tanımlayıcısı içermeli ve **SHOULD** ad, orta ad/baş harf, soyad, doğum tarihi ve fiziksel/dijital adres içermeli.
**Core Attribute Validation:** *"The CSP **SHALL** validate all core attributes, whether obtained from identity evidence or **self-asserted by the applicant**, with an authoritative or credible source."*

> ⚠️ **Bölüm numarası uyarısı:** `pages.nist.gov` HTML'i başlıklarda bölüm numarası render etmiyor ve iki bağımsız çıkarım Attribute Validation'da çelişti (§2.4.2.3 vs §3.1.4). **Kararlı anchor'ları kaynak göster** (`#CoreAttributes`, `#AttrValid`, `#FraudMgmt`, `#CSPFraudMgmt`, `#DigInject`) veya PDF'e karşı doğrula. Fraud Management numaralandırması tutarlıydı: **§3.2 → §3.2.1 CSP Fraud Management, §3.2.2 RP Fraud Management, §3.2.3 Treatment of Fraud Check Failures.**

**Yeni CSP sahtekârlık programı gereksinimi (§3.2.1) — rev 4'te gerçekten yeni:**
> "CSPs **SHALL** establish and maintain a **fraud management program** that provides fraud identification, detection, investigation, reporting, and resolution capabilities…"
> "CSPs **SHALL** conduct a **privacy risk assessment** of all fraud checks and fraud mitigation technologies prior to implementation."
> "The CSP **SHALL** establish a **self-reporting mechanism** and investigation capability for subjects who believe they have been the victim of fraud…"
> "CSPs **SHALL** analyze all remote proofing communication channels to look for high-risk indicators (e.g., blocklisted proxies and IP addresses)."
> ⭐ **Enumeration gereksinimi, sahtekârlık bölümüne gömülü:** "The CSP **SHALL** take measures to **prevent unsuccessful applicants from inferring the accuracy of any self-asserted information** with that confirmed by authoritative or credible sources."
> "CSPs **SHALL** implement a **death records check** for all identity proofing processes… Such checks can aid in preventing **synthetic identity fraud**…"
> "CSPs **SHALL** establish a technical or process-based mechanism to communicate suspected and confirmed fraudulent events to RPs."
> "CSPs **SHOULD** communicate fraud events **in real time** to RPs through methods such as **shared signaling**, as described in Sec. 4.8 of [SP800-63C]." *(yani OpenID SSF/CAEP)*
> "CSPs **SHOULD** periodically employ independent testing (e.g., **red teaming**)…"
> "CSPs **SHALL** implement **insider threat controls** to detect and prevent collusion involving CSP representatives…"

**Kayıt suistimaliyle doğrudan ilgili `SHOULD` seviyesi kontroller:**
- **SIM swap tespiti** — telefon yakın zamanda taşınmamış olmalı
- **Cihaz veya hesap kıdemi kontrolü** — telefon/e-posta hesabının ne kadar süredir esaslı değişiklik olmadan var olduğu. **⭐ "Bu tek kullanımlık bir posta kutusu mu?" sorusunun standart-onaylı hâlidir.**
- **Posta adresi kontrolü** — sanal PO Box / yüksek riskli özellikler
- **Cihaz parmak izi** — *"to protect against scaled and automated attacks and **enrollment duplication**"*
- **İşlem analitiği** — *"Evaluate anticipated transaction characteristics (e.g., IP addresses, geolocations, **transaction velocities**)…"*
- **Fraud indicator check** — açık mahremiyet çekincesiyle: *"users **SHALL** be made aware of any privacy implications based on a privacy risk assessment."*

**RP tarafı (§3.2.2):** RP'ler **SHALL** bir sahtekârlık irtibat noktası kurmalı; CSP sahtekârlık kontrollerinin mahremiyet risk değerlendirmesini yapmalı; CSP'nin programını periyodik gözden geçirmeli; **SHOULD** kendi sahtekârlık yönetim programını kurmalı.

#### 30.3 Sentetik kimlik ve kayıt sahtekârlığı (63A §6, bilgilendirici)

Dört tehdit kategorisi: **Impersonation · False or fraudulent representation (sentetik kimlik) · Social engineering · Infrastructure attacks.**

Açık AI çerçevelemesi:
> "Many emerging attacks… pair **digital injection attacks** with increasingly effective and available **generative AI tools**. These AI tools are used to create or modify media that contain images or videos of applicants and evidence (i.e., **deepfakes**)…"
> "This section does not provide guidance or controls that specifically address AI as a discrete threat type. Instead, the mitigations below… address specific threats that may be **perpetrated or scaled** by attackers with AI tools."

**Tablo 2 (tehditler):**

| Tehdit | Tanım | Örnek |
|---|---|---|
| **Automated Enrollment Attempts** | "Attacker leverages scripts and automated processes to rapidly generate large volumes of enrollments" | "Bots leverage stolen data to submit benefits claims" |
| **Synthetic Identity Fraud** | "Attacker fabricates evidence of an identity that is not associated with a real person" | "A credit card opened under a fake name to create a credit file" |
| **Video or Image Injection Attack** | "Attacker creates a fake video feed to impersonate a real life person" | deepfake video |

**Tablo 3 (azaltmalar) — IdP'nin doğrudan alıntılaması gereken satır:**
> **Automated Enrollment Attempts →** "Web application firewall (WAF) controls and **bot detection technology**. **Out-of-band engagement (e.g., confirmation codes).** Biometric verification and liveness detection mechanisms. Traffic and network analysis capabilities…"

#### 30.4 Rev 4'ün eklediği (63A Değişiklik Kaydı, Ek D)

*"**Introduces the concept of core attributes**"* · *"Decouples the collection of identity attributes from the collection of identity evidence"* · *"**Introduces fraud management guidance and requirements**"* · *"**Provides guidance and requirements for digital injection prevention and forged media detection**"* · *"Expands acceptable evidence and attribute validation sources to include **credible sources**"* · *"Introduces… **trusted referees and applicant references**"* · *"Provides **non-biometric options** for identity verification at IALs 1 and 2"*.

63B değişiklik kaydından ilgili girdiler: *"§3.2.5 Adds a definition and updates requirements for **phishing-resistant authenticators**"* · *"§3.2.13 Adds a new section on requirements for the **non-exportability** of authenticator secrets"* · *"§4.2 Revises the requirements and methods for account recovery"* · *"**§5.1 Recognizes the use of device-bound session credentials**"* · *"§5.3 Adds guidelines for the use of **session monitoring (continuous authentication)**"*.

---

### 31. Bot koruması 2026 — CAPTCHA bir bulmaca olarak öldü

#### 31.1 Akademik kanıt

**"Breaking reCAPTCHAv2"** — Andreas Plesner, Tobias Vontobel, Roger Wattenhofer (**ETH Zürih**). arXiv **2409.08831**, 13 Eylül 2024; **COMPSAC 2024**'te kabul.
- YOLO modelleriyle (segmentasyon + sınıflandırma) **%100 çözüm oranı**; önceki çalışmalarda %68-71.
- **Tasarım için en önemli bulgu:** *"there is **no significant difference in the number of challenges humans and bots must solve**"*, ve makale reCAPTCHAv2'nin insanlığı yargılarken *"heavily based on **cookie and browser history data**"* olduğuna dair kanıt buluyor.
> **→ reCAPTCHA'nın gerçek savunması hiçbir zaman bulmaca değildi; Google'ın siteler arası kimlik grafiğiydi. Kendi bulmacasını barındıran bir IdP bunun hiçbirini elde etmez.**

**"Open CaptchaWorld"** (NeurIPS 2025), arXiv 2505.24878 — 20 tipte 225 CAPTCHA. *"state-of-the-art MLLM agents struggle significantly, with success rates at most **40.0%** by Browser-Use Openai-o3, far below human-level performance, **93.3%**."*

**"COGNITION: From Evaluation to Defense against Multimodal LLM CAPTCHA Solvers"** — arXiv 2512.02318, **USENIX Security '26'da kabul.** 7 MLLM × 18 gerçek dünya CAPTCHA tipi. Bulgu: MLLM'ler tanıma/düşük-etkileşim CAPTCHA'larını *"at **human-like cost and latency**"* çözüyor; ince taneli konumlandırma, çok adımlı uzamsal akıl yürütme ve kareler arası tutarlılık zor kalıyor. Yeniden tasarlanmış challenge'ları en gelişmiş MLLM'lerin başarı oranını *"from **over 95% to 0%**"* düşürüyor.

> **Sentez:** Saf görüntü tanıma öldü (%100 çözülebilir). *Etkileşim derinliği ve uzamsal akıl yürütme* CAPTCHA'ları hâlâ ölçülebilir bir boşluk tutuyor (%40 vs %93) — Arkose MatchKey ve COGNITION savunmalarının işgal ettiği alan tam olarak burası. **Ama boşluk hareketli bir hedef ve her model kuşağında yeniden kapanıyor.**

#### 31.2 Çözüm ekonomisi — CAPTCHA'yı öldüren rakam

2captcha.com fiyatlandırması (8 Eylül 2026'da çekildi), **1.000 çözüm başına USD**:

| Tip | Fiyat / 1000 |
|---|---|
| Normal / görüntü captcha | **$0,50 – $1,00** |
| reCAPTCHA v2 (Invisible, Callback dahil) | **$1,00 – $2,99** |
| reCAPTCHA v3, skor ≤ 0,3 | $1,45 |
| reCAPTCHA Enterprise | $1,00 – $2,99 |
| **Cloudflare Turnstile** | **$1,45** |
| **Arkose Labs / FunCaptcha** | **$1,45 – $50,00** |
| Friendly Captcha | $1,45 |
| Akamai / Kasada / PerimeterX | $0 (self-servis sunulmuyor) |

> **Tasarım sonucu: bir CAPTCHA kapısı saldırgana sahte hesap başına ≈ $0,001-$0,003 maliyet bindirir.** Getirisi ~$0,003'ü aşan her sahtekârlık etkilenmez.
> **Tablodaki tek anlamlı ekonomik değişiklik Arkose'un $1,45-$50 tavanıdır** — ve yüksek olmasının nedeni tam olarak MatchKey'in hedef başına model yeniden eğitimi zorlamasıdır (~30× maliyet artışı).

**Gecikme asimetrisi de gerçek:** çözücü servisler challenge başına **10-30 saniye** alıyor ve token'lar tipik olarak ~5 dakikada sona eriyor. Kararlı bir saldırganı durdurmasa da **yüksek hızlı kayıt selleri** için gerçek bir sürtünmedir.

#### 31.3 Satıcılar

| Satıcı | Mekanizma | Doğrulanmış olgular |
|---|---|---|
| **Cloudflare Turnstile** | Etkileşimsiz JS probları: *"proof-of-work (computational puzzles), **proof-of-space**, probing for web APIs"*, tarayıcı tuhaflıkları, insan davranış örüntüleri. Modlar: Managed / Non-interactive / Invisible | GA **29 Eyl 2023**. "25 milyondan fazla Cloudflare sitesi" challenge sayfalarında çalıştırıyor; bir müşteri "tek ayda 1 milyon+ otomatik kayıt denemesini sıfır bildirilen yanlış pozitifle" engelledi; *"even without asking users for any interactivity at all, Turnstile was just as effective as a CAPTCHA"*. **Ücretsiz plan:** 20 widget'a kadar, widget başına 10 hostname, 7 günlük analitik, **sınırsız challenge**. Gizlilik: *"processes only the data strictly necessary… does not access, store, or transmit user communications, form entries, or other page inputs."* Aynı zamanda bir **Privacy Pass attester'ı** (§32). ⚠️ WCAG seviyesi Cloudflare'in kendi iki sayfası arasında çelişiyor (2.2 AA vs AAA) |
| **hCaptcha** | Checkbox / Invisible / Enterprise "passive and nearly passive No-CAPTCHA modes" + **risk skorları** | IP adresi doğruluğu maddi olarak artırıyor ve Enterprise için risk skorlarını mümkün kılıyor. ⚠️ **Dokümanlarında GDPR/saklama iddiası YOK** — KVKK kapsamlı bir tasarım için not edilmeye değer bir boşluk |
| **Arkose Labs MatchKey** | Düşmanca bozulmuş challenge'lar: *"variations that aren't visible to humans but alter the machine interpretation"*; *"increase the cost for the adversaries to maintain and update the models"* | İddia (28 May 2024, satıcı yayını, bağımsız tekrarlanmadı): bir oyun müşterisinin parola sıfırlama akışında *"**less than 1% of the bots** could solve the AI-resistant challenge, compared to **over 92%** that could solve the non-altered image."* 2captcha'nın $50/1000 tavanı bunu dışarıdan doğruluyor |
| **Friendly Captcha** | Adaptif **proof-of-work**, görünmez, riske göre tırmanan. **Çerez yok, kalıcı tarayıcı depolaması yok, davranışsal parmak izi yok**; Alman şirketi, AB veri ikametgâhı | **Setin en güçlü GDPR/KVKK hikâyesi.** Ama 2captcha $1,45/1000 fiyatlıyor — **PoW tek başına ekonomik olarak caydırıcı değil** |
| **DataDome / Castle / Kasada / HUMAN** | Sunucu tarafı ML: cihaz + davranış + ağ sinyalleri; bulmaca-öncelikli değil | ⚠️ Self-servis değil; press sayfaları otomatik fetch'e **403** döndü. **DOĞRULANMADI.** 2captcha'nın onları "$0" listelemesi (yani self-servis çözüm hedefi olarak sunulmaması) token tabanlı CAPTCHA'lardan **daha zor farm edildiklerine** dair zayıf bir kanıt |

#### 31.4 Bot trafiği payı — tarihli sert rakamlar

**Imperva (Thales) Bad Bot Report 2025** (15 Nisan 2025):
- **Otomatik trafik = 2024'te tüm web trafiğinin %51'i** — on yılda ilk kez insanı geçti.
- **Kötü botlar = %37** (2023'te %32).
- Basit kötü botlar %40'ın altından **%45**'e çıktı.
- **ATO saldırıları 2024'te +%40**; **"tüm girişlerin %14'ü" devralma denemesi.**
- **Finansal hizmetler tüm ATO olaylarının %22'si**; Telekom/ISP %18; Bilişim %17.
- Gelişmiş botlar **%44 oranında API'leri** hedefliyor, uygulamaları %10.

**Imperva 2026, "Bots in the Agentic Age"** (29 Nisan 2026):
- **Botlar = 2025'te tüm web trafiğinin %53'ünden fazlası** (önceki yıl %51); insanlar %47'ye düştü.
- Bot saldırılarının **%27'si** API uç noktalarını hedefledi.
- Finansal hizmetler **tüm bot saldırılarının %24'ü**; **ATO olaylarının %46'sı.**
- ⚠️ 2026 yazısı "girişlerin yüzde kaçı ATO" rakamını **tekrarlamıyor.** 2025 raporunun %14'ünü kullan ve tarihlendir.

**Cloudflare Radar 2025 Year in Review** (Aralık 2025, 1 Oca – 2 Ara 2025):
- 2 Aralık 2025 itibarıyla **HTML isteklerinin**: **insan %47**, **AI olmayan botlar %44**, **AI botları (Googlebot hariç) ortalama %4,2**, **Googlebot %4,5**.
- Küresel internet trafiği 2025'te **+%19**.

> ⚠️ **Dolaşımdaki 2026 Cloudflare rakamlarını kullanma** ("Haziran 2026'da HTML trafiğinin %57,5'i", "Ağustos 2026'da %35,42") — üçüncü taraf toplayıcı bloglardan geliyorlar, **birbirleriyle çelişiyorlar** ve radar.cloudflare.com'a karşı doğrulanamadılar.

#### 31.5 CAPTCHA öldü mü? — savunulabilir pozisyon

1. **Turing testi olarak, evet.** reCAPTCHA v2 görüntülerinde %100 çözüm oranı (hakemli); çözüm maliyeti ~$0,001-$0,003; challenge artık insanı makineden ayırmıyor.
2. **Bir maliyet/gecikme vergisi ve sinyal toplama aracı olarak, hayır.** Turnstile'ın değeri, checkbox taklidi yaparken çalıştırdığı ~20 tarayıcı-ortam probudur, checkbox değil. **NIST 63B §3.2.2 "bot detection and mitigation challenge"ı üstel geri çekilme ve risk sinyalleriyle birlikte bir `MAY` olarak listeliyor** — yani onu üç değiştirilebilir teknikten biri sayıyor, asla *kontrolün kendisi* değil.
3. **Onun yerini fiilen ne aldı (maliyet sırasıyla dört katman):**
   - **Görünmez cihaz/tarayıcı-ortam sinyalleri** (Turnstile, hCaptcha Enterprise, DataDome, Castle, Kasada, HUMAN) — trafiğin büyük kısmı, ~sıfır kullanıcı sürtünmesi.
   - **Gri bölge için adaptif proof-of-work** (Friendly Captcha; Turnstile de içeride PoW/proof-of-space yapıyor). Mahremiyet açısından temiz; tek başına ekonomik olarak zayıf.
   - **Kriptografik attestation** platform sunuyorsa: **Privacy Pass / Private Access Tokens** (Apple), **Play Integrity** (Android), **WebAuthn/passkey**. İstek başına en güçlü sinyal, en dar kapsam.
   - **Step-up / bant dışı doğrulama** (hesap var olmadan önce e-posta veya SMS onay kodu) — ki bu aynı zamanda NIST 63A Tablo 3'ün otomatik kayıt azaltmasıdır *ve* WebAuthn spec'inin önerdiği enumeration düzeltmesidir. **⭐ Bu iki gereksinim tek bir kontrolde birleşir.**
4. **1. katman üzerindeki AB/KVKK kısıtı** — Türk bir IdP için bu opsiyonel bir renk değil:
   - **CNIL**, reCAPTCHA'nın otomatik olarak GDPR uyumlu olmadığına ve güvenlik dışındaki amaçlar için aşırı kişisel veri kullandığına hükmetti; **125.000 € Cityscoot cezası** reCAPTCHA kullanımına atıfta bulundu.
   - **28 Kasım 2024'te yayımlanan Avusturya kararı** — rıza reddedilmesine rağmen veri Google'a aktığında reCAPTCHA rızasız hukuka aykırı.
   - **→ AB/TR'ye bakan bir IdP için Turnstile veya Friendly Captcha, reCAPTCHA'ya tercih edilmeli** ve bu seçim bir KVKK/GDPR veri minimizasyonu kararı olarak belgelenmeli.

---

### 32. Privacy Pass / Private Access Tokens

#### 32.1 ⚠️ RFC numaralandırması — yaygın atıf hatası

| RFC | **Gerçek başlık** | Tarih | Statü |
|---|---|---|---|
| **9576** | **The Privacy Pass Architecture** | Haziran 2024 | Informational |
| **9577** | **The Privacy Pass HTTP Authentication Scheme** | Haziran 2024 | **Standards Track** |
| **9578** | **Privacy Pass Issuance Protocols** | Haziran 2024 | **Standards Track** |

> **"RFC 9577 = Privacy Pass Issuance Protocols" YANLIŞTIR** — 9577 HTTP Authentication Scheme'dir; Issuance Protocols **9578**'dir. Set **üç** RFC'dir, iki değil, hepsi **Haziran 2024**. (İlgili: **RFC 9497**, OPRF'ler, özel-doğrulanabilir varyantın temelidir.)

#### 32.2 `PrivateToken` şeması (RFC 9577)

**Challenge** — origin `401` ile yanıtlar:
```
WWW-Authenticate: PrivateToken challenge=<base64url>, token-key=<base64url>
```
- `challenge` — base64url `TokenChallenge`, **tüm challenge'lar için zorunlu**, padding içermeli.
- `token-key` — base64url issuer public key; *"MAY be omitted in deployments where Clients are able to retrieve the Issuer key using an out-of-band mechanism."*

**`TokenChallenge` yapısı:** 2 oktet `token_type` · `issuer_name` (ASCII) · `redemption_context` (**0 veya 32 bayt**) · `origin_info` (opsiyonel origin listesi).

**Redemption:** `Authorization: PrivateToken token="<base64url>"`
**`Token` yapısı:** 2 oktet `token_type` · 32 oktet istemci `nonce` · 32 oktet `challenge_digest` (TokenChallenge'ın SHA-256'sı) · değişken `token_key_id` · değişken `authenticator`.

**Issuance token tipleri (RFC 9578):**

| Kod | Ad | Doğrulama |
|---|---|---|
| **0x0001** | VOPRF(P-384, SHA-384) | **Özel** doğrulanabilir (issuer private key) |
| **0x0002** | Blind RSA (2048-bit) | **Herkese açık** doğrulanabilir (issuer public key) |

#### 32.3 Apple Private Access Tokens

- WWDC 2022'de duyuruldu; Apple geliştirici haberi **9 Haziran 2022**.
- **iOS 16 / iPadOS 16 / macOS Ventura** ve sonrasında destekleniyor.
- **Token tipi 0x0002 (herkese açık doğrulanabilir RSA Blind Signatures)** kullanıyor — kasıtlı olarak, böylece herhangi bir origin sadece issuer'ın açık anahtarıyla doğrulayabiliyor.
- Attestation **Secure Enclave** + cihazın Apple ID durumundan geliyor — yani Apple "bu, iyi durumda gerçek bir Apple hesabı olan gerçek bir cihaz" diye kefil oluyor, **hangisi olduğunu söylemeden.**
- Apple'ın adlandırdığı açık issuer dizinleri: Cloudflare (`demo-pat.issuer.cloudflare.com/.well-known/token-issuer-directory`) ve **Fastly** (`demo-issuer.private-access-tokens.fastly.com/...`).

#### 32.4 Cloudflare dağıtımı ve benimseme durumu

- Roller: **Origin** (doğrular) / **Issuer** (imzalar) / **Attester** (kimin token hak ettiğine karar verir).
- **⭐ En önemli operasyonel olgu:** *"Cloudflare Managed Challenge is a Privacy Pass origin serving two Privacy Pass challenges: one for Apple PAT Issuer, one for Cloudflare Research Issuer."* → **Cloudflare Managed Challenge'ın arkasındaysan, hiç PAT kodu yazmadan zaten PAT tüketiyorsun.**
- Cloudflare **Turnstile tabanlı bir attester** dağıttı (Turnstile'ı geç → token al) ve `pp-issuer-public.research.cloudflare.com`'da açık bir araştırma issuer'ı işletiyor.
- Cloudflare "Privacy Pass'ı WAF ve Bot Management ürünlerinde önemli bir sinyal olarak kullanıyor — bu da milyonlarca sitenin Privacy Pass'ı yerel olarak sunması demek."
- ⚠️ **Benimseme çekincesi, Cloudflare'in kendi dokümanından:** *"Privacy Pass is **not a self-serve product** at the moment: a production deployment is a **managed engagement with Cloudflare**."*

#### 32.5 IdP kayıt suistimalinde PAT kullanılabilir mi? — pratik hüküm

> **Evet, ama yalnızca *olumlu* bir sinyal olarak, asla bir kapı olarak.**

**✅ İşe yarayan:** Kayıt POST'unda geçerli bir `Authorization: PrivateToken` varsa ve güvenilen bir issuer anahtarına karşı doğrulanıyorsa, **o istek için CAPTCHA'yı atla ve rate limit'i gevşet.** Bu, PAT'ı saf sürtünme *kaldırmaya* çevirir — başarısızlık modu "kullanıcı CAPTCHA görür", "kullanıcı kilitlenir" değil.

**❌ İşe yaramayan:** PAT zorunlu kılmak. Kapsam yapısal olarak kısmî:
- **İstemci kapsamı pratikte esasen yalnızca Apple** (iOS 16+/macOS Ventura+, Safari ve sistem ağ yığınını kullanan uygulamalar). Türk bir tüketici IdP'si **hiç PAT yeteneği olmayan** büyük bir Android + Chrome/Windows çoğunluğu görecek.
- **Açık web için Google/Chrome eşdeğeri YOK** — WEI öldürüldü (§32.6). Turnstile-attester Cloudflare'in ikamesi ama o Turnstile'dır, cihaz attestation'ı değil.
- Cloudflare angajmanı olmadan veya kendi issuer + attester'ını kurmadan self-servis çalıştıramazsın.

**Rate-limiting nüansı:** `redemption_context` alanı (0 veya 32 bayt) token'ları bir bağlama bağlamana izin verir, ama token'lar **yapısal olarak bağlanamazdır** — "bu cihaz kaç kayıt yaptı"yı sayamazsın. **PAT sana *"gerçek bir cihaz bunu yaptı"* verir, asla *"aynı gerçek cihaz bunu 500 kez yaptı"* değil. Üzerine cihaz başına kota tasarlama.**

**IdP kayıt uç noktası için mantıklı katmanlı politika:**
1. Ucuz IP/ASN + hız kapısı (kütleyi reddeder, ~sıfır maliyet).
2. PAT varsa ve geçerliyse → hızlı yol, challenge yok.
3. Değilse → Turnstile/Friendly Captcha managed challenge.
4. **Her zaman** → hesap maddileşmeden önce e-posta/SMS bant dışı onay kodu (NIST 63A Tablo 3 + WebAuthn §14.6.2 — **tek kontrol, iki gereksinim**).

#### 32.6 Google tarafı

- **Web Environment Integrity — ÖLDÜĞÜ DOĞRULANDI.** Prototip Chromium'da **Mayıs → Kasım 2023** yaşadı; **2 Kasım 2023'te** Google, sürekli "web için DRM" eleştirisinin ardından öneriyi terk etti ve prototipi kaldırdı. İkame, kapsamı daraltılmış **Android WebView Media Integrity API**'ye indirgendi. **2026'da WEI'nin Chrome/web-platform halefi YOKTUR.**
- **Play Integrity API** — Android-yerlisi analog, ve **mobil uygulamada** kayıt suistimali için gerçekten kullanılabilir.
  - **Standard requests** (ucuz, gecikme dostu, *"delegating some protection against replayability and exfiltration to Google Play"*) vs **Classic requests** (*"more expensive… you are responsible for correctly implementing them"*).
  - Verdict'ler: **`appIntegrity`** (Google Play'in tanıdığı değiştirilmemiş binary) · **`deviceIntegrity`** (gerçek sertifikalı Android cihaz) · **`accountDetails`** (kullanıcı Play üzerinden kurdu/ödedi). Opt-in ekstralar: `MEETS_STRONG_INTEGRITY`, `appAccessRiskVerdict`, `playProtectVerdict`.
  - **Web çözümü DEĞİL** — yalnızca uygulama, yalnızca Google Play. **Root'lu/de-Google'lanmış/AOSP kullanıcıları başarısız olur** — açıkça karar vermen gereken gerçek bir erişilebilirlik ve kapsayıcılık maliyeti.
- **DBSC** — farklı problem (oturum ele geçirme, kayıt değil) ama artık **sevk ediliyor:** **Windows'ta GA** (TPM destekli); Google Workspace duyurusu **28 Mayıs 2026**, kademeli dağıtım **25 Mayıs 2026'dan** itibaren, tam görünürlüğe 60 güne kadar, **varsayılan açık ve yönetici kapatma anahtarı yok.** macOS (Secure Enclave destekli) sonraki sürümde. Detay için bkz. oturum-guvenligi.md (§21) §1.

#### 32.7 WebAuthn/passkey kaydı bot savunması olarak

> **Dürüst değerlendirme: bot savunması olarak zayıf, diğer her şey için güçlü.**

Passkey kaydı bir authenticator üzerinde *kullanıcı jesti* gerektirir ve bu scriptli kütle kaydın maliyetini yükseltir — ama yazılım authenticator'ları ve sanal authenticator API'leri (her WebAuthn test paketinin kullandığı) credential'ları programatik olarak yaratır. **Attestation olmadan `navigator.credentials.create()` ne insan ne de gerçek cihaz kanıtıdır.**

Savunulabilir versiyon: **attestation zorunlu kıl** (`attestationConveyancePreference: "direct"`) ve yüksek güvenceli kayıtlar için **FIDO Metadata Service**'e karşı doğrula. Bu seni PAT/Play Integrity ile karşılaştırılabilir bir cihaz-attestation duruşuna geri getirir — **yazılım passkey'lerini reddetme pahasına, yani çoğu tüketici passkey'ini reddetme pahasına.** Tüketici IdP'si için uygun değil; workforce/yüksek-IAL kayıt için uygun.

**Passkey'in kayıttaki gerçek kazancı başka yerde:** stuff edilecek parola yok, enumerate edilecek parola sıfırlama akışı yok, ve **§14.6.2'nin kayıt rehberliği enumeration düzeltmesini bedavaya veriyor** (§34).

---

### 33. Tek kullanımlık e-posta ve `+` etiketi

#### 33.1 Tespit teknikleri, kesinlik sırasıyla

1. **Statik alan adı blocklist'i.** `disposable-email-domains/disposable-email-domains` — ~**3.500 alan adı**, **CC0**, aktif bakımlı, **PyPI üretimde kayıt engellemek için kullanıyor.** Kendi README çekincesi dürüst olanı: *"We cannot guarantee all of these can still be considered disposable but we do basic checking so chances are they were disposable at one point in time."*
   **Başarısızlık modu:** tek kullanımlık sağlayıcılar alan adlarını herhangi bir listenin güncellenmesinden hızlı döndürüyor ve *özel alan adları* satıyorlar. **Blocklist tembel %80'i yakalar, başka bir şey yakalamaz.**
2. **MX kaydı kontrolleri.** Ucuz, yüksek değerli, farklı bir başarısızlık sınıfını yakalar:
   - **MX yok (ve A fallback yok) → sert red.** Bu bir *teslim edilebilirlik* kontrolüdür, suistimal kontrolü değil, ve neredeyse yanlış-pozitifsizdir.
   - **Bilinen tek kullanımlık altyapıyı gösteren MX** → alan adından daha güçlü sinyal, çünkü tek kullanımlık operatörler rotasyonlu alan adları arasında posta altyapısını yeniden kullanır.
   - **Kayıtta asla canlı SMTP `RCPT TO` sondajı yapma:** yavaş, greylist/blocklist'e alınmana yol açar ve çoğu sağlayıcı zaten catch-all `250` döndürür.
3. **Alan adı yaşı / kayıt yeniliği (WHOIS/RDAP).** 3 gün önce kaydedilmiş ve posta kabul eden bir alan adı güçlü bir suistimal sinyalidir. **⭐ Bu tam olarak NIST 63A §3.2.1'in "Device or account tenure check"idir** — standart-onaylı.
4. **Ticari API'ler** (ZeroBounce, Kickbox: gerçek zamanlı MX ve SMTP kontrolleri, `deliverable | undeliverable | risky | unknown` + Sendex skoru 0-1).
   > ⚠️ **Bunlar suistimal için değil, e-posta pazarlama teslim edilebilirliği için ayarlanmıştır.** "Risky" kovaları gönderen itibarını korumak için optimize edilmiştir ve **gizlilik relay'lerini seve seve işaretlerler.** Bir pazarlama doğrulayıcısının boolean'ını doğrudan hesap oluşturma `deny`'ına bağlama.

#### 33.2 ⭐ Yanlış pozitif problemi — gizlilik relay'leri tek kullanımlık DEĞİLDİR

**Apple — zaman çizelgesi önemli:**

| Tarih | Olay |
|---|---|
| **15 Haziran 2026** | Apple geliştirici haberi: *"New domain for Sign in with Apple and iCloud+ Hide My Email"* — **ikisini** de `private.icloud.com` altında birleştirme duyurusu |
| **24 Ağustos 2026** | Apple gizlilik tepkisi sonrası **kısmen geri adım attı**. **Hide My Email `icloud.com`'da kalıyor.** Sign in with Apple yine de `private.icloud.com`'a taşınıyor |

**Apple'ın geliştirici rehberliği, birebir:**
> **"Developers with apps or websites that use Sign in with Apple should ensure that their account systems, email validation logic, and allowlists accept addresses on the new `private.icloud.com` domain in addition to the existing `privaterelay.appleid.com` domain."**

Mevcut `@privaterelay.appleid.com` adresleri kesintisiz çalışmaya ve yönlendirmeye devam ediyor.

> **Apple neden geri adım attı:** Hide My Email'i `icloud.com`'da tutmak, servislerin iCloud+ takma adlarını **her sıradan iCloud kullanıcısını da engellemeden** alan adı seviyesinde engelleyememesi demek. **Bu, Apple'ın kasıtlı bir engelleme-karşıtı tasarım tercihidir ve politika sorusunu senin için kapatır: Hide My Email takma adlarını gerçek iCloud adreslerinden asla ayırt edemeyeceksin.**

> ### ⚠️ 2026'da sevk edilen her IdP için aksiyon maddesi
> **Allowlist'in HEM `privaterelay.appleid.com` HEM `private.icloud.com` içermeli.** Haziran 2026'dan önce kurulmuş bir sistem, **yeni Sign in with Apple kullanıcılarını sessizce reddetmeye başlayacak.** Bu, canlı ve tarihli bir kırılmadır.

**Allowlist'e alınması gereken diğer gizlilik relay'leri:**
- **Firefox Relay** — maskeler **`mozmail.com`** üzerinde (özel alt alan adları için `relay.firefox.com`'dan taşındı, yani `@altalan.mozmail.com` da oluyor). Mozilla'nın kendi SSS'i hasarı belgeliyor: *"Some sites may not accept an email address that includes a subdomain (@subdomain.mozmail.com) and others have stopped accepting all addresses except those from Gmail, Hotmail, or Yahoo accounts."*
- **SimpleLogin** (Proton) — `simplelogin.io`, `aleeas.com` ve kullanıcı özel alan adları. ⚠️ Güncel liste birincil kaynaktan doğrulanmadı; sabit kodlamadan önce kontrol et.
- **DuckDuckGo Email Protection** — `duck.com`. ⚠️ **DOĞRULANMADI.**

#### 33.3 Önerilen politika

> **"Tek kullanımlık" üzerinden asla engelleme. Skorla, ve zorlamayı onay kodu yapsın.**

1. **Yalnızca teslim edilebilirlik üzerinden sert reddet:** sözdizimsel olarak geçersiz, veya alan adının MX'i ve A kaydı yok. Sıfıra yakın yanlış pozitif.
2. **Adlandırılmış gizlilik relay'lerini allowlist'e al** — `privaterelay.appleid.com`, `private.icloud.com`, `mozmail.com`, `duck.com`, SimpleLogin alan adları — ve onları **sıradan adresler** olarak muamele et. Bunlar ödeme yapan, mahremiyet bilinçli, yüksek değerli kullanıcılardır ve Sign in with Apple muhtemelen *istediğin* birinci sınıf bir federasyon yoludur. **Onları engellemek kendine açtığın bir dönüşüm yarasıdır.**
3. **Tek kullanımlık liste isabetleri + alan adı yaşı + MX itibarı üzerinden skorla, engelleme.** Skoru risk tabanlı step-up'a besle (ek doğrulama, gecikmeli güven, daha düşük başlangıç rate limit'i), reddetmeye değil.
4. **Gerçek kapı bant dışı onay kodu olsun.** Zarif kısım bu: hesap oluşturulmadan önce zorunlu bir e-posta gidiş-dönüşü *sahte* adresleri otomatik yener (posta kutusu yok → kod yok → hesap yok), NIST 63A Tablo 3'ün otomatik kayıt azaltmasını karşılar, **ve** kayıt enumeration sızıntısını çözer (§34). **Kodu alan *çalışan* bir tek kullanımlık adres, kimlik doğrulama amaçları için çalışan bir adrestir** — taşıdığı risk bot-luk değil, **hesap kurtarılabilirliğidir.**
5. **Gerçek riski yeniden çerçevele.** Tek kullanımlık e-postanın bir IdP'ye gerçek zararı sahtekârlık değil, **yetim hesaplardır**: posta kutusu buharlaşır, kullanıcı asla hesap kurtarma yapamaz ve sen sonsuza kadar kurtarılamaz bir kimlik taşırsın. Bunu kayıt engellemeyle değil, **kurtarma yöntemi gereksinimleriyle** çöz (NIST 63B §4.2: *"CSPs **SHALL** allow the subscriber to establish at least two recovery addresses"*).
6. **Belirli bir suistimale duyarlı eylem için engellemen gerekiyorsa** (ücretsiz deneme, promosyon kredisi, referans bonusu), **kayıtta değil, o eylemde engelle.** Farklı risk, farklı kapı.

#### 33.4 `+` etiketi ve e-posta normalizasyonu

**Standartlar ne diyor:**

**RFC 5321 (SMTP), Ekim 2008 — belirleyici metin:**
- **§2.3.11:** *"the local-part MUST be interpreted and assigned semantics **only by the host specified in the domain part of the address**."*
- **§2.4:** *"The local-part of a mailbox **MUST BE treated as case sensitive**."*

**RFC 5233 (Sieve Subaddress Extension), Ocak 2008:** `:detail` alt-parçasını tanımlıyor, `:user`'dan *"a 'separator character sequence', such as '+'"* ile ayrılmış. **`+` ZORUNLU DEĞİL** — RFC açıkça *"the encoding of detailed addresses are site and/or implementation specific"* diyor. Qmail tarihsel olarak `-` kullandı; başka sistemler `=` veya `#`.

> **Tasarım dokümanı için hukuki sonuç:** RFC 5321 §2.3.11'e göre `user+tag@example.com` ve `user@example.com` **senin açından iki farklı adrestir.** Onları aynı kimlik saymak, **başkasının isim alanı hakkında yaptığın bir politika tercihidir** ve RFC 5321 o isim alanının senin yorumlamana ait olmadığını söylüyor.
> Aynı argüman noktalar için **daha da güçlü** geçerlidir — nokta-önemsizliği bir **Gmail ürün kararıdır**, bir e-posta standardı değil, ve bunu `@yandex.com.tr`'ye veya kurumsal bir Exchange alan adına uygulamak **gerçekten farklı kullanıcıları tek hesapta birleştirir.**

**Gerçek, belgelenmiş suistimal — Agari vakası (2018):** BEC aktörleri tek bir Gmail adresinin **56 farklı nokta varyantını** kullandı:
- 4 ABD finans kurumunda **48 kredi kartı başvurusu** → en az **65.000 $** sahte kredi onaylandı
- Bir online vergi servisinde **13** sahte vergi beyannamesi
- **12** USPS adres değişikliği talebi
- **11** sahte Sosyal Güvenlik yardım başvurusu
- Tek bir eyalette **9** işsizlik yardımı kimliği
- Ticari bir satış-lead servisinde **14** deneme hesabı (BEC hedefleme verisi toplamak için)
- **3** FEMA afet yardımı başvurusu

> **Listeyi dikkatli oku: her bir kalem *kişi başı bir kez* verilen bir haktır** (kredi, yardım, deneme, vergi iadesi). **Bir tanesi bile kimlik doğrulama ihlali değildir.** Tasarım dersinin tamamı budur.

**Sağlayıcı davranışı:**

| Sağlayıcı | Noktalar | `+` etiketleri |
|---|---|---|
| **Gmail / Workspace** | **Yoksayılır** — `j.doe@` ≡ `jdoe@` | Destekleniyor, yönlendirme için sıyrılıyor |
| **Outlook / Microsoft 365** | **Anlamlı** | Destekleniyor |
| **Yahoo** | Anlamlı | Klasik `+` yerine "base+keyword" tarzı |
| **Fastmail, Proton, iCloud** | Anlamlı | `+` destekleniyor |
| **Çoğu self-hosted / kurumsal** | Anlamlı | Değişken; qmail türevleri `-` kullanır |

> ⚠️ **Nokta-eşdeğerliği büyük sağlayıcılar arasında yalnızca Gmail'e özgüdür. Küresel olarak uygulamak bir hatadır.**

**Önerilen politika: kanonik sakla, ham üzerinden anahtarla.**

| Soru | Cevap | Neden |
|---|---|---|
| Kayıtta `+` **reddedeyim mi**? | **Hayır** | Meşru, yaygın öğretilen bir mahremiyet pratiğini kırar; kullanıcılar ihlalleri tespit etmek için kasten etiketler. Kimseyi durdurmaz (saldırganlar nokta kullanır, ya da $0,001'e yeni posta kutusu) |
| `a+x@gmail.com` ile `a@gmail.com` **aynı giriş** olsun mu? | **Hayır** | RFC 5321 §2.3.11 bunun alıcı host'un kararı olduğunu söylüyor. Kullanıcının ayrı sandığı hesapları birleştirmek bir doğruluk ve güvenlik hatasıdır — Gmail dışı alan adlarında nokta normalizasyonu **iki gerçek farklı insanı** birleştirebilir |
| Normalize edilmiş biçimi **saklayayım mı**? | **Evet** | `email_raw` (teslimat, RFC-doğru) **ve** `email_canonical` (küçük harfe çevrilmiş; **yalnızca bilinen Gmail alan adları için** noktalar ve `+tag` sıyrılmış). İkisini de indeksle |
| Kanonik biçimi **nerede kullanayım**? | **Yalnızca suistimal skorlaması ve müşteri-başı-bir haklar** | Ücretsiz denemeler, promosyon kredileri, referans bonusları, kayıt hız limitleri, çoklu hesap tespiti. Tam olarak Agari saldırı yüzeyi — ve *yalnızca* o yüzey |

**Ek korumalar:**
- **Etiketi sınırla:** absürt local-part'ları reddet (birden çok `+`, RFC 5321 başına >64 oktet) — ucuz, meşru kayıp yok.
- **⭐ Kanonik biçimi asla kullanıcıya görünen bir hatada yüzeye çıkarma.** *Kanonik* adres üzerinden anahtarlanmış "bu e-posta zaten kayıtlı", ham adres üzerinden anahtarlanmıştan **kesinlikle daha kötü bir enumeration oracle'ıdır**: yalnızca `some.one+test@gmail.com` deneyen bir saldırgana `someone@gmail.com`'un var olduğunu sızdırır.
- **Bilmediğin alan adları arasında normalize etme.** Nokta-önemsiz sağlayıcıların açık bir listesini tut (gerçekçi olarak: Google'ın alan adları). Diğer her şey: yalnızca küçük harfe çevir.

---

### 34. Enumeration önleme

#### 34.1 OWASP — normatif temel çizgi

**Authentication Cheat Sheet:**
- *"Incorrectly implemented error messages in the case of authentication functionality can be used for the purposes of user ID and password enumeration."*
- Şu durumların **hepsinde aynı genel hata mesajı**: "The user ID or password was incorrect. The account does not exist. The account is locked or disabled."
  - ✅ `"Login failed; Invalid user ID or password."`
  - ❌ `"Login for User foo: invalid password."` / `"Login failed, invalid user ID."`
- Parola kurtarma: *"If that email address is in our database, we will send you an email to reset your password."*
- Hesap oluşturma: *"A link to activate your account has been emailed to the address provided."*
- **Zamanlama üzerine, birebir:** *"the processing time can be significantly different according to the case (success vs failure) allowing an attacker to mount a **time-based attack** (delta of some seconds for example)."* Çare: "quick exit"ten kaçın — *"This code will go through the same process no matter what the user or the password is."*
- ⚠️ **OWASP dummy-hash tekniğini AÇIKÇA REÇETE ETMİYOR.** *Sonucu* reçete ediyor (aynı kod yolu, karşılaştırılabilir süre). Dummy-hash numarası bunun bir uygulamasıdır, standartlaşmış değildir.
- Otomatik saldırılara karşı: MFA, giriş throttling, **hesap kilitleme sayaçları "associated with the account itself, rather than the source IP address"**, ve CAPTCHA açıkça *"a **defense-in-depth** control to make brute-force attacks more time-consuming and expensive"* olarak çerçeveleniyor — yani birincil kontrol değil.

**WSTG-IDNT-04** test vektörleri: farklılaşmış **hata mesajları** · **yanıt zamanlaması** — *"Particularly where the request causes an interaction with an external service (such as sending a forgotten password email), this can add **several hundred milliseconds**"* · farklı **HTTP durum kodları** · farklı **Content-Length** · kayıt/profil sayfaları ve rezerve kullanıcı adları (`admin`, `administrator`).

> ### ⭐ Çoğu implementasyonun kaçırdığı nokta
> `several hundred milliseconds`. **E-posta göndermek bir Argon2 hash'inden kat kat pahalıdır.** Eğer *miss'te hash'liyor* ama *hit'te posta gönderiyorsan*, zamanlama farkını **iyileştirmedin, kötüleştirdin.**
> Düzeltme: posta gönderimini **her iki yolda da** asenkron yap (kuyruğa at, hemen dön) — miss yolunda bir no-op kuyruğa at.

#### 34.2 ⭐ Dummy-Argon2 tekniği doğru mu? — **Yarı doğru ve genelde uygulandığı hâliyle tehlikeli**

**Teknik:** Kullanıcı yoksa, gönderilen parolayı sabit kodlanmış sahte bir Argon2id hash'ine karşı hash'le ki yanıt süresi gerçek yolla eşleşsin.

**Nerede doğru:** İki dalın CPU/bellek profilini gerçekten eşitliyor ve erken `return 404`'ten kesinlikle daha iyi.

**Nerede yanlış — üç ayrı problem:**

**(a) Bir bilgi sızıntısını bellek-tükenmesi DoS'una çeviriyor.**
Argon2id, RFC 9106'nın ikinci önerilen ayarında **64 MiB × 3 iterasyon × 4 lane**'dir. Çöp kullanıcı adlarıyla 100 eşzamanlı istek gönderen kimliği doğrulanmamış bir saldırgan **6,4 GB yerleşik bellek tahsisi** zorlar — **sıfır** geçerli hesapla ve throttle'ın hesap-kapsamlıysa **sıfır** rate-limit sayacı artışıyla.
> **NIST 63B §3.2.2'nin throttling'i açıkça hesap-kapsamlı ve authenticator-kapsamlıdır ("on a single subscriber account"), yani var olmayan hesap seli onu yapısal olarak tamamen atlar.** Dummy hash, o boşluğu bir kaynak öldürmeye çeviren şeydir.

**(b) Parametre rehberliğinin kendisi riski kabul ediyor.**
OWASP Password Storage Cheat Sheet, birebir: *"If the work factor is too high, the performance of the application may be degraded, which could be used by an attacker to carry out a **denial of service attack by exhausting the server's CPU** with a large number of login attempts."* ve *"As a general rule, calculating a hash should take **less than one second**."*

OWASP'ın Argon2id ayarları RFC 9106'nınkinden **belirgin şekilde düşüktür**, tam da bu yüzden:
`m=47104 (46 MiB), t=1, p=1` · `m=19456 (19 MiB), t=2, p=1` · `m=12288 (12 MiB), t=3, p=1` · `m=9216 (9 MiB), t=4, p=1` · **`m=7168 (7 MiB), t=5, p=1`**

RFC 9106 (Eylül 2021, IRTF Informational) ise önce **t=1, p=4, m=2²¹ (2 GiB)**, sonra **t=3, p=4, m=2¹⁶ (64 MiB)** öneriyor. **RFC 9106'nın Security Considerations'ı yan kanalları kapsıyor ama hiçbir DoS/kaynak-tükenmesi analizi içermiyor** — boşluk gerçek ve OWASP onu dolduruyor.
> Yaygın olarak alıntılanan "64 MiB × 3" tam olarak **RFC 9106'nın ikinci önerisidir** ve **OWASP'ın en bellek-aç ayarının ~3 katıdır.**
> *(Argus'un seçtiği parametre ve gerekçesi için bkz. performans.md (§6) — ölçüm `m=7168, t=5`'in hem %16 ucuz hem daha iyi ölçeklendiğini gösterdi.)*

**(c) Zamanlama eşitlemesi zaten eksik.** Argon2 çalışma süresi parola uzunluğuna, GC/allocator davranışına ve cache durumuna göre değişir. Ve *sıfırlama* akışında baskın terim hash bile değildir — SMTP çağrısıdır.

**✅ Doğru kurulum — önce ucuz kapı, sonra pahalı iş.**
OWASP DoS Cheat Sheet ilkeyi doğrudan söylüyor: *"**Using validation that is cheap in resources first**: We want to reduce impact on these resources as soon as possible. More (CPU, memory and bandwidth) expensive validation should be performed afterward."*

Somut sırayla:
1. **Herhangi bir hash'lemeden önce ucuz kapı.** IP/ASN/subnet başına token bucket + hash'leme worker havuzunda global bir eşzamanlılık semaforu. **Bu kapı kimlikten bağımsız olmalı** ki hit ve miss'lere eşit uygulansın. Limiti aşan istekleri **hiç Argon2 belleği tahsis etmeden** reddet. Bu tek başına zamanlama savunmasını kaldırmadan DoS'u kaldırır.
2. **Sınırlı hash'leme eşzamanlılığı.** Kuyruğu olan sabit boyutlu worker havuzu (örn. `N = RAM_bütçesi / m_cost`). **Bellek kullanımı umutla değil, yapısal olarak sınırlanır.**
3. **Ancak o zaman** gerçek-veya-sahte hash'i çalıştır. Sınırlı havuzla dummy hash güvenlidir.
4. **Tekdüze asenkron yanıt.** E-postayı kuyruğa at (gerçek veya no-op) ve her iki yolda da aynı gövde, aynı durum, aynı `Content-Length` dön. **Yanıtı asla SMTP'yi beklemeye bırakma.**
5. **Opsiyonel: sabit taban yanıt süresi** (`t_start + 250ms`'e kadar bekle), dummy hash yerine veya ek olarak. Dummy-hash'ten ucuz ve **SMTP dahil tüm dalları eşitler** — herkes için bir gecikme tabanı pahasına. **Bu genelde daha iyi bir takastır** ve NIST 63B §3.2.2'nin "wait after a failed attempt" maddesinin işaret ettiği şeydir.
6. **Sıfırlama uç noktasını hesap başına da rate-limit'le**, ki bilinen geçerli bir hesap posta bombardımanı için amplifikatör olarak kullanılamasın.

> **Ayrıca:** **hesap-kapsamlı kilitleme** kullanıyorsan (OWASP: sayaç "associated with the account itself"), *ikinci* bir enumeration oracle'ı yaratmışsındır — saldırgan, kilitlenmenin hiç tetiklenip tetiklenmediğini gözlemleyerek hesabın varlığını tespit edebilir.
> **Hem hesap-kapsamlı hem IP-kapsamlı limitlere ihtiyacın var; hiçbiri tek başına yeterli değil.**

#### 34.3 Temel gerilim: kayıt yapısal olarak sızdırır

`e-posta zaten kullanımda`, mesajlaşarak kurtulabileceğin bir hata değildir — ya kullanıcıya söylersin (sızıntı) ya da hesabı oluşturamazsın (bozuk UX).

> ### ⭐ Çözüm mimaridir ve W3C WebAuthn spec'i §14.6.2'de birebir yazıyor
> *(W3C Recommendation, **25 Ağustos 2026**)*
>
> "If the Relying Party uses e-mail addresses to identify users: When initiating a registration ceremony, **interrupt the user interaction after the e-mail address is supplied and send a message to this address, containing an unpredictable one-time code** and instructions for how to use it to proceed with the ceremony. **Display the same message to the user in the web interface regardless of the contents of the sent e-mail and whether or not this e-mail address was already registered.**"
>
> "Note: This suggestion can be similarly adapted for other externally meaningful identifiers, for example, national ID numbers or credit card numbers…"

**Pratikte nasıl çalışır — Apple ve Google'ın yaptığı budur:**
1. Kullanıcı e-postayı gönderir. UI her zaman **"O adrese bir kod gönderdik"** der. Aynı yanıt, aynı durum, aynı zamanlama, **hesap oluşturulmaz.**
2. **Dallanma HTTP yanıtında değil, e-postanın içinde:**
   - Adres kayıtlı **değilse** → e-posta kayıt devam kodunu içerir.
   - Adres **zaten kayıtlıysa** → e-posta *"Biri bu adresle hesap oluşturmaya çalıştı. Zaten bir hesabın var — işte giriş linki / sıfırlama linki"* der, artı bir "ben değildim" bildirim yolu.
3. Hesap ancak kod geri döndükten sonra var olur.

**Bu neden bir IdP için doğru cevap:**
- Oracle, **yalnızca adres sahibinin okuyabildiği** bir kanala taşınır. Enumeration maliyeti "bir HTTP isteği"nden "posta kutusunu ele geçir"e çıkar.
- Aynı anda **NIST 63A Tablo 3**'ün otomatik-kayıt azaltmasını (*"Out-of-band engagement (e.g., confirmation codes)"*), **NIST 63A §3.2.1**'in çıkarım-karşıtı `SHALL`'ını, tek kullanımlık e-posta problemini (§33.3) **ve** OWASP'ın tekdüze-yanıt kuralını karşılar — **tek kontrol, dört gereksinim.**
- Zaten kayıtlı kullanıcı için dönüşümü de iyileştirir: çıkmaz bir hata yerine çalışan bir giriş linki alır.
- 63B §4.2'nin kod geçerlilik tavanlarını yeniden kullanabilirsin: **10 dk** SMS/ses, **24 saat** e-posta.

**Kaldıramayacağın artık sızıntı:** e-postanın *kendi yan etkisi* üzerinden enumeration — posta sunucusunu kontrol eden bir saldırgan posta gönderilip gönderilmediğini gözlemleyebilir. Kabul et; çok daha yüksek bir çıta. Ve throttle'ın yalnızca hesap-kapsamlıysa kararlı bir saldırgan **rate-limit farkı** üzerinden hâlâ enumerate edebilir. **IP-kapsamlı limitleri kimlikten bağımsız tut.**

#### 34.4 Passkey akışlarında enumeration

**Sızıntı 1 — WebAuthn §13.4.7 "Unprotected account detection" (normatif değil):**
> "if using authentication with server-side credentials as the first authentication step… the `allowCredentials` argument risks leaking information about which user accounts have WebAuthn credentials registered and which do not, **which may be a signal of account protection strength**… The attacker can then conclude that the latter user accounts likely do not require a WebAuthn assertion… and thus **focus an attack on those likely weaker accounts**."

**Sızıntı 2 — §14.6.3 "Privacy leak via credential IDs":**
> "Credential IDs are designed to not be correlatable between Relying Parties, **but the length of a credential ID might be a hint as to what type of authenticator created it**… **the number of credential IDs in `allowCredentials` and their lengths might serve as a global correlation handle to de-anonymize the user**. Knowing a user's credential IDs also makes it possible to confirm guesses about the user's identity given only momentary physical access to one of the user's authenticators."

**Spec-onaylı düzeltmeler, tercih sırasıyla:**
1. **"Use client-side discoverable credentials, so the `allowCredentials` argument is not needed."** ← temiz düzeltme. Boş `allowCredentials` + **conditional UI** (autofill) hem kullanıcı-adısız girişi hem sıfır sızıntıyı verir. **⭐ Eşleşmeye dikkat: conditional UI yalnızca `allowCredentials` boşken çalışır — mahremiyet düzeltmesi ve en iyi UX aynı tasarımdır.**
2. **"Perform a separate authentication step… before initiating the WebAuthn authentication ceremony and exposing the user's credential IDs."**
3. **Makul hayalî değerler (§14.6.2)** — kritik çekinceyle: *"If returned imaginary values noticeably differ from actual ones, clever attackers may be able to discern them… Examples of noticeably different values include if the values are always the same for all username inputs, **or are different in repeated attempts with the same username input**. The `allowCredentials` member could therefore be **populated with pseudo-random values derived deterministically from the username**."*
   > **⭐ Bu, dummy-hash'in WebAuthn analogudur ve spec bu konuda çoğu dummy-hash tavsiyesinden çok daha dikkatlidir:** kullanıcı adı başına **deterministik** ve **istatistiksel olarak ayırt edilemez** olmalı.
4. **"make it indistinguishable whether verification failed because the signature is invalid or because no such user or credential is registered."**
5. **Signalling API:** *"the WebAuthn Relying Party **SHOULD** use the `signalUnknownCredential(options)` method instead of the `signalAllAcceptedCredentials(options)` method to avoid exposing credential IDs to an unauthenticated caller."* **⭐ L3'te yeni — kimliği doğrulanmamış bir uç noktada `signalAllAcceptedCredentials` taze bir 2026 tuzağıdır.**

**Kayıt tarafı, RP'ye özgü kullanıcı adları için (§14.6.2):** *"disallow registration of usernames that are syntactically valid e-mail addresses"* — gerekçe: sızıntı kaçınılmazsa, en azından **sızan tanımlayıcıyı taşınamaz yap** (*"less likely that a user has the same username at this Relying Party as at other Relying Parties"*).

**Ayrıca §14.6.1 User Handle Contents:**
> "the Relying Party **MUST NOT** include personally identifying information, e.g., e-mail addresses or usernames, in the user handle. **This includes hash values of personally identifying information, unless the hash function is salted with salt values private to the Relying Party**, since hashing does not prevent probing for guessable input values. It is **RECOMMENDED to let the user handle be 64 random bytes**."
> **Yaygın bir IdP hatası `user.id`'yi e-postaya veya hash'ine ayarlamaktır — bu, herhangi bir authenticator'a doğrudan enumeration/korelasyon sızıntısıdır.**

#### 34.5 ⭐ Zamanlama enumeration'ı internet üzerinden gerçekçi mi? — **Evet, ve "jitter kurtarır" varsayımı artık geçersiz**

**"Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections"** — Tom Van Goethem, Christina Pöpper, Wouter Joosen, Mathy Vanhoef. **USENIX Security 2020.**

- **Klasik varsayım:** uzaktan zamanlama saldırıları çok ölçüm gerektirir çünkü **ağ jitter'ı** baskındır; milisaniye altı farklar internet üzerinden istismar edilemez.
- **Kırılma:** **tek bir pakette iki istek gönder** (HTTP/2 multiplexing / paket birleştirme), sunucunun onları eşzamanlı işlemesini sağla, ve farkı **yanıtların döndüğü sıradan** çıkar. Bu **hiç mutlak zamanlama bilgisi kullanmaz** — dolayısıyla **ağ jitter'ı tamamen iptal olur.**
- **HTTP/2 nginx (Amazon EC2'de)**, **Tor onion servisleri** ve **EAP-pwd**'ye karşı gösterildi; ~1.000.000 istek çiftiyle doğrulandı.

> ### ⚠️ Keskin tasarım sonucu
> *"Fark sadece birkaç yüz mikrosaniye, internet üzerinden kimse bunu ölçemez"* **artık hiçbir HTTP/2 veya HTTP/3 uç noktası için doğru değildir** — ki bu her modern IdP demektir.
> **Login/reset/registration'da zamanlama eşitlemesi 2026'da gerçek bir gereksinimdir, tiyatro değil.**
> **Rastgele jitter bir düzeltme DEĞİLDİR** — ortalamada erir ve timeless teknik altında zaten alakasızdır. Hayatta kalan düzeltmeler: **özdeş kod yolları, sabit yanıt süresi tabanı, ve yanıt kuyruklaması.**

**Bunun canlı bir hata sınıfı olduğunun ampirik teyidi: CVE-2025-3716** — ESET PROTECT (on-prem), **CWE-204** olarak sınıflandırıldı, *"enables an unauthenticated remote attacker to enumerate valid usernames by measuring differences in response timing."*

#### 34.6 Düzenleyici / sınıflandırma açısı

- **CWE-204: Observable Response Discrepancy** — *"the product provides different responses to incoming requests in a way that reveals internal state information to an unauthorized actor."* Kullanıcı enumeration'ının standart CVE sınıflandırması.
- **CWE-203: Observable Discrepancy** — üst sınıf, zamanlama/davranışsal varyantları kapsıyor.
- Enumeration **rutin olarak CVE alıyor** — CVE-2025-3716 (ESET PROTECT), CVE-2026-24664 (GUnet OpenEclass), IBM Sterling File Gateway. **Yani raporlanabilir, CVE-uygun bir zayıflıktır**, sadece bir sertleştirme inceliği değil. Bir satıcı IdP'si için bu önemlidir: müşteri pentest raporlarına düşer ve koordineli açıklama yükümlülüğü tetikler.
- **NIST SP 800-63A §3.2.1 bunu CSP'ler için bir `SHALL` yapıyor** — *"The CSP SHALL take measures to prevent unsuccessful applicants from inferring the accuracy of any self-asserted information…"* **800-63-4 uyumluluğu iddia eden her şey için enumeration direnci bir uyum gereksinimidir**, sadece iyi pratik değil.
- **GDPR/KVKK açısı:** "bu e-postanın [serviste] hesabı var" diyen bir enumeration oracle'ı, kişisel verinin (bir kişi ile bir servis arasındaki ilişkinin) yetkisiz bir tarafa ifşasıdır. ⚠️ Belirli bir örneğin bildirilebilir ihlal olup olmadığı olguya bağlıdır — **enumeration-ihlal konusunda doğrudan bir düzenleyici karar bulunamadı, DOĞRULANMADI. Abartma;** CWE sınıflandırması ve NIST `SHALL`'ıyla desteklenen bir veri minimizasyonu/gizlilik riski olarak çerçevele. **Hassas kategorili bir servis için** (sağlık, tanışma, siyasî, finansal) teyidin kendisi özel nitelikli veri olabilir, ki bu argümanı hayli güçlendirir.

---

### 35. Bölüm V için kayıt akışı tasarımı

**Argus'un kayıt uç noktası, sırayla:**

```
1. Sözdizimi + teslim edilebilirlik           → sert red (MX yok ve A yok)
2. Gizlilik relay allowlist'i                 → sıradan adres muamelesi
   { privaterelay.appleid.com, private.icloud.com, mozmail.com, duck.com, ... }
3. Ucuz kapı: IP/ASN/subnet token bucket      → KİMLİKTEN BAĞIMSIZ
   + hash worker havuzunda global semafor
4. PAT varsa ve geçerliyse                    → hızlı yol, challenge yok
5. Değilse → Turnstile / Friendly Captcha     → skor, sert kapı değil
6. Suistimal skoru: tek kullanımlık liste +   → step-up'a besle, RED'e değil
   alan adı yaşı + MX itibarı + kanonik
   e-posta hız kontrolü
7. HER ZAMAN: bant dışı onay kodu             → HESAP HENÜZ YOK
   → UI yanıtı her durumda AYNI
   → dallanma e-postanın İÇİNDE
8. Kod döndüğünde hesap oluşur                → email_verified = true
```

**Zorlanan invariantlar:**

| # | Invariant | Kaynak |
|---|---|---|
| 1 | Onay kodu dönmeden **hiçbir hesap satırı yaratılmaz** | WebAuthn §14.6.2 + pre-hijacking §6.2.1 |
| 2 | HTTP yanıtı gövde, durum, `Content-Length` ve **zamanlama** olarak her iki dalda özdeş | OWASP + WSTG-IDNT-04 |
| 3 | Posta gönderimi **her iki yolda da** asenkron kuyruğa atılır (miss'te no-op) | "several hundred milliseconds" |
| 4 | **Sabit yanıt süresi tabanı** (~250 ms), dummy-hash'e tercihen | Timeless timing attacks |
| 5 | Rate limit **hem IP-kapsamlı hem hesap-kapsamlı**; IP kapısı hash'lemeden **önce** | 63B §3.2.2 hesap-kapsamlı → yapısal boşluk |
| 6 | Argon2 worker havuzu **sabit boyutlu**; bellek yapısal olarak sınırlı | OWASP DoS Cheat Sheet |
| 7 | `email_raw` **ve** `email_canonical` saklanır; kanonik **yalnızca** suistimal skoru ve kişi-başı-bir haklar için | RFC 5321 §2.3.11 + Agari |
| 8 | Kanonik biçim **asla** kullanıcıya görünen bir hatada yüzeye çıkmaz | Daha kötü oracle |
| 9 | Nokta normalizasyonu **yalnızca açık Gmail alan adı listesinde** | Nokta-önemsizliği Gmail'e özgü |
| 10 | WebAuthn `user.id` = **64 rastgele bayt**, asla e-posta veya hash'i | §14.6.1 MUST NOT |
| 11 | Boş `allowCredentials` + conditional UI varsayılan; gerekirse **kullanıcı adından deterministik** hayalî değerler | §14.6.3 + §14.6.2 |
| 12 | `signalUnknownCredential` kullanılır, `signalAllAcceptedCredentials` **kimliği doğrulanmamış uç noktada asla** | L3 yeni tuzağı |
| 13 | reCAPTCHA **kullanılmaz**; Turnstile veya Friendly Captcha, KVKK gerekçesi belgelenerek | CNIL Cityscoot + Avusturya kararı |
| 14 | Kurtarma adresi **en az iki** (tek kullanımlık e-posta yetim hesap riskine karşı) | 63B §4.2 SHALL |
| 15 | Sahtekârlık olayları RP'lere **gerçek zamanlı SSF/CAEP ile** bildirilir | 63A §3.2.1 SHOULD |

---

## BÖLÜM VI — IdP GÖÇÜ

> **Neden bu bölüm Argus için stratejik:** Bir IdP'nin en büyük pazara giriş engeli, müşterinin mevcut IdP'sinden çıkamamasıdır. **İçeri göç yolları Argus'un satış argümanıdır; dışarı göç yolları ise dürüstlük iddiasıdır.** Bu bölüm, her büyük ürünün ne verip ne vermediğinin envanteridir.

### 36. Parola hash'i dışa aktarımı — ürün ürün

#### 36.1 Auth0 — varsayılan HAYIR; destek süreci var

**Standart toplu dışa aktarım hash içermez.** `POST /api/v2/jobs/users-exports` **NDJSON** ("due to the large size of the export files") veya CSV üretir. CSV **30 alanla** sınırlı; `app_metadata`/`user_metadata` CSV'de bütün nesne olarak dışa aktarılamaz. İş verisi 24 saat sonra silinir; indirme linki 60 saniyede sona erer (24 saat içinde yeniden üretilebilir).

**Hash + MFA sırrı dışa aktarımı ayrı, kapılı bir destek sürecidir:**
1. Tenant adı + **kendi PGP açık anahtarınla** destek vakası aç
2. **Uygunluk incelemesi** ("Not all requests qualify")
3. Yazılı yetkilendirme, **ikinci bir tenant yöneticisinin teyidi**, artı **CISO/CSO/VP seviyesinde bir yöneticiden imzalı onay formu**
4. Auth0 açık anahtarınla şifreler → kimlik doğrulamalı indirme linki, **3 günde sona erer**
5. Sen çözersin

**PGP anahtar gereksinimleri:** minimum **4096-bit RSA**, en az bir RSA-4096 şifreleme alt anahtarı; güçlü benzersiz parola; **oluşturulmadan ≥7 gün sonra sona erme**; ASCII-armored anahtar **≤35.000 karakter** (üçüncü taraf imzalarını temizle).

**Dışa aktarım formatı** (NDJSON, satır başına bir kullanıcı): `_id`, `alt_id`, `email`, `email_verified`, `passwordHash` (örn. `$2b$10$…`), `connection`, `identifiers[]`. **Doğrudan yeniden içe aktarılabilir değil** — NDJSON→JSON dizisi dönüşümü ve alan yeniden adlandırması gerekiyor.

**İçe aktarımda `custom_password_hash` 11 algoritma destekliyor:** `argon2` (PHC string) · `bcrypt` (`$2a$`/`$2b$`/`$2y$`, max 72 bayt girdi) · `hmac` · `ldap` (RFC-2307; **crypt şeması desteklenmiyor**) · `md4` · `md5` · `sha1` · `sha256` · `sha512` · `pbkdf2` (PHC, varsayılan `i=100000, l=64`) · `scrypt` (`keylen` zorunlu; `cost` varsayılan 16384).
Kodlamalar: hash/salt/key ∈ `base64|hex|utf8`; salt `position` ∈ `prefix|suffix`.

**İçe aktarım iş limitleri:** dosya başına **500 KB** (~1.000 kullanıcı), tenant başına **2 eşzamanlı iş**, **2 saatte** bitmezse iş başarısız, veri 24 saat sonra silinir.

#### 36.2 Okta — dışa aktarım fiilen HAYIR; içe aktarım 6 algoritmayla EVET

Okta parola hash'lerinin veya MFA faktörlerinin standart dışa aktarımına izin vermiyor. Tek belgelenmiş yol bir istisna sürecidir ve özellikle **Okta→Auth0** olarak çerçevelenmiştir (birebir):
> *"In a very limited number of cases and only with specific criteria met, it is possible to request an export of password hash values for active Okta users **during the organization's transition from Okta to Auth0**"* … *"this is a lengthy process that requires coordination between multiple Okta teams and a customer's technical and executive teams."*

**İçe aktarım — tam `password.hash` şeması** (BCRYPT, SHA-512, SHA-256, SHA-1, MD5, PBKDF2):
- `algorithm`, `value`, `salt`, `saltOrder` (PREFIX/POSTFIX), `workFactor` (**yalnızca BCRYPT, min 1, max 20**), `iterationCount` (**yalnızca PBKDF2, ≥ 4096 olmalı**), `keySize`, `digestAlgorithm`
- `salt`: **BCRYPT için Radix-64, tam 22 karakter**; diğer salt'lı hash'ler için Base64
```json
{"profile":{...},"credentials":{"password":{"hash":{
  "algorithm":"BCRYPT","workFactor":10,
  "salt":"pwxb1yjwfpa6jcV0XKBtau",
  "value":"MnDMlKOOxMY4Tc.7wgpqFoAPYKi5wSe"}}}}
```

**Password import inline hook** (Okta'ya tembel göç): kullanıcıyı `"credentials":{"password":{"hook":{"type":"default"}}}` ile oluştur. **Yalnızca ilk giriş denemesinde** tetiklenir. Başarı yanıtı `{"commands":[{"type":"com.okta.action.update","value":{"credential":"VERIFIED"}}]}`; red **HTTP 204 boş gövde**. `data.action.credential` *"currently always set to `UNVERIFIED`, meaning that the **default is to reject**."*

#### 36.3 Keycloak — credential'lar CLI dışa aktarımında VAR

**`kc.sh export` kullanıcıları ve credential'ları içerir.** `--users {skip|realm_file|same_file|different_files}` (varsayılan `different_files`, `--users-per-file` varsayılan **50**).

**Dışa aktarılMAYAN** (birebir): *"user and admin events, persisted sessions, workflow state or revoked tokens."*

> ⚠️ **Admin Console'un kısmî dışa aktarımı göç için KULLANILAMAZ** — sırlar `*` ile maskelenir ve kullanıcılar hariç tutulur. Yalnızca CLI dışa aktarımları yedek/aktarım için uygundur.

**Credential JSON şekli:**
```json
{"type":"password",
 "credentialData":"{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\",\"additionalParameters\":{}}",
 "secretData":"{\"value\":\"<base64 hash>\",\"salt\":\"<base64 salt>\",\"additionalParameters\":{}}"}
```

**Argon2, Keycloak 25.0'da (Haziran 2024) varsayılan parola hash algoritması oldu** — yalnızca **FIPS olmayan** dağıtımlar için; FIPS dağıtımları PBKDF2'de kalıyor. Varsayılanlar **hash isteği başına ~7 MB** gerektiriyor ve paralel Argon2 hesaplaması JVM'in gördüğü çekirdek sayısıyla sınırlı.

**Özel `PasswordHashProvider` SPI'ı** yabancı hash'ler için: `PasswordHashProvider` + `PasswordHashProviderFactory` implemente et, `META-INF/services/...` ile kaydet, Realm → Authentication → Policies → Hashing Algorithm'i ayarla. **Keycloak, kullanıcının ilk başarılı girişinde politika algoritmasına otomatik olarak yeniden hash'ler** — yerleşik trickle mekanizması budur.

> **Keycloak'ın taşınabilirlik açısından en büyük avantajı: OTP credential'ları aynı `credentials` dizisindedir (`type: "otp"`), dolayısıyla `kc.sh export --users` ile birlikte çıkarlar.** Bu, incelenen ürünler arasında **TOTP sırlarını self-servis dışa aktaran tek üründür.**

#### 36.4 AWS Cognito — dışa aktarım hâlâ HAYIR, ama **hash ile içe aktarım 15 Temmuz 2026'da geldi**

**Yeni: CSV ile parola hash içe aktarımı.** Duyuru **15 Temmuz 2026**, tüm Cognito bölgeleri.
```
aws cognito-idp create-user-import-job … \
  --password-hashing-algorithm BCRYPT|SCRYPT|ARGON2ID|PBKDF2_SHA256
```
**İş başına bir algoritma** (karışık hash'lerin varsa işleri böl). CSV'ye `password_hash` sütunu ekleniyor.

> ### ⚠️ Göç tuzağı: parametre tavanları
> | Algoritma | Format | **Tavan** |
> |---|---|---|
> | `BCRYPT` | `$2<a/b/x/y>$[cost]$[22-char salt][31-char hash]` | **max cost 12** |
> | `SCRYPT` | `N$r$p$hexSalt$hexHash` | **max N=65536, r=8, p=1** |
> | `ARGON2ID` | `$argon2id$v=N$m=M,t=T,p=P$salt$hash` | **max m=19456 KiB, t=2, p=1** |
> | `PBKDF2_SHA256` | `$pbkdf2-sha256$iterations$salt$hash` | **max 600.000 iterasyon** |
>
> Sınırları aşan hash'ler **kullanıcı başına başarısız olur.** AWS'in adlandırdığı fallback'ler: hash'siz içe aktar (→ `RESET_REQUIRED`), veya o kullanıcılar için migrate-user Lambda kullan.

Kullanıcılar **`CONFIRMED`** olarak içe aktarılır ve hemen giriş yapabilir. Cognito içe aktarılan hash'leri **çift hash'ler** ve ilk başarılı girişte şeffaf şekilde yerel SRP'ye dönüştürür.

**Kritik kısıt (birebir):** *"Until a user completes their first sign-in and Amazon Cognito migrates their credentials, **you can't use Secure Remote Password (SRP)**… Use `USER_PASSWORD_AUTH` or `ADMIN_USER_PASSWORD_AUTH`."*

> ⚠️ **Tüm user pool'larda mevcut değil** — yeni nesil Cognito altyapısı gerekiyor.

**CSV içe aktarım limitleri:** satır max **16.000 karakter**; dosya max **100 MB**; max **500.000 satır**; hesap başına **bir aktif iş**; presigned URL **15 dakika** geçerli; başlatılmamış işler 24-48 saatte `Expired`; `birthdate` `mm/dd/yyyy`; `updated_at` epoch saniye; **BOM'suz UTF-8**.

**Migrate User Lambda** (tembel yol): tetikleyiciler `UserMigration_Authentication`, `UserMigration_ForgotPassword`. **Passwordless girişte tetiklenmez.** Yanıt: `userAttributes` (**zorunlu**), `finalUserStatus`, `desiredDeliveryMediums` (**belirtilmezse SMS'e düşer**).
Açık uyarı (birebir): *"Amazon Cognito doesn't enforce the password strength policy … during migration using Lambda trigger"* — gücü kendin doğrulamalı ve başarısızsa `RESET_REQUIRED` ayarlamalısın.

#### 36.5 Firebase Auth — hash'leri gerçekten dışa aktaran tek ürün

**`firebase auth:export ACCOUNT_FILE --format=csv|json`** `passwordHash` ve `salt`'ı (base64) **dışa aktarır.** O iki alan için çağıranın **Editor veya Owner** rolü gerekir.

**Sert sınırlama (birebir):** *"the `auth:export` command **only exports passwords hashed using the scrypt algorithm**… Account records with passwords hashed using other algorithms are exported with **empty `passwordHash` and `salt` fields**."*

Hash parametreleri Console → Authentication → Users → ⋮:
```
hash_config { algorithm: SCRYPT, base64_signer_key: <hassas>,
              base64_salt_separator: <hassas>, rounds: 8, mem_cost: 14 }
```

**`--hash-algo` değerleri:** `BCRYPT, SCRYPT, STANDARD_SCRYPT, HMAC_SHA512, HMAC_SHA256, HMAC_SHA1, HMAC_MD5, MD5, SHA512, SHA256, SHA1, PBKDF_SHA1, PBKDF2_SHA256`.

> ⚠️ **`SCRYPT` ≠ `STANDARD_SCRYPT`** — `SCRYPT` Firebase'in kendi değiştirilmiş scrypt'i; **Firebase→Firebase göçünde bile `SCRYPT` belirtilmeli.**

**CSV = 26 sabit sütun:** 1 UID, 2 Email, 3 EmailVerified, **4 Password Hash (b64), 5 Password Salt (b64)**, 6 Name, 7 PhotoURL, 8-11 Google, 12-15 Facebook, 16-19 Twitter, 20-23 GitHub, 24 CreationTime (epoch ms), 25 LastSignInTime, 26 PhoneNumber.

Admin SDK `importUsers()`: **çağrı başına ≤1.000 kullanıcı**; uid/email/telefon üzerinde **tekilleştirme yapmaz.**

#### 36.6 Microsoft Entra External ID / Azure AD B2C — dışa aktarım HAYIR

Parola hash'lerini dışa aktarmanın desteklenen bir yolu **yok.** Microsoft'un "parolaları nasıl korurum" sorusuna kendi cevabı **JIT göçüdür**, dışa aktarım değil.

**B2C satış sonu / emeklilik — doğrulanmış tarihler:**
- *"Effective **1 Mayıs 2025**, Azure AD B2C will no longer be available to purchase for new customers"* — mevcut müşteriler devam ediyor; yeni tenant'lar yalnızca **P1** ile oluşturulabiliyor.
- *"Azure AD B2C **P2 will be discontinued on 15 Mart 2026**, for all customers."* Tüm P2 tenant'ları **Mart 2026 sonuna kadar** otomatik P1'e geçiyor.
- *"We'll continue supporting Azure AD B2C **until at least May 2030**."*

**Entra External ID'ye JIT parola göçü** (doküman güncelleme 25 Ağu 2026):
- Mekanizma: **`OnPasswordSubmit` özel kimlik doğrulama uzantısı.** Kullanıcılar Graph üzerinden ön-oluşturulur ve `toBeMigrated: true` dizin uzantı özelliğiyle işaretlenir.
- Akış: gönderilen parola kayıttakiyle eşleşmezse ve bayrak ayarlıysa, Entra **parolayı bir RSA açık anahtarıyla şifreler (JWE)** — özel anahtar **Azure Key Vault**'ta, Azure Function'ın managed identity ile eriştiği yerde — ve uzantını çağırır. Function çözer, eski IdP'ye karşı doğrular ve dört eylemden birini döner: **`MigratePassword`** (sakla, bayrağı temizle) · **`UpdatePassword`** (doğru ama zayıf → sıfırlamaya zorla) · **`Retry`** · **`Block`**.
- `disableStrongPassword` seçeneği bir arada yaşama sırasında karmaşıklık zorlamasını gevşetiyor (8 karakter minimum yine zorlanıyor). Microsoft bunu açıkça **zaman kutulu** bir takas olarak çerçeveliyor.
- Gerekli rol: **Authentication Extensibility Password Administrator**.

> **Dikkat çekici:** İncelenen ürünler arasında **gönderilen parolayı senin koduna vermeden önce şifreleyen (RSA JWE) tek ürün Entra'dır.** Argus da bunu yapmalı — özel bir uzantıya düz metin parola vermek bir tasarım hatasıdır.

#### 36.7 Diğerleri

| Ürün | Hash içe aktarımı | Hash dışa aktarımı | Not |
|---|---|---|---|
| **Stytch** | `bcrypt`, `md_5`, `argon_2i`, `argon_2id`, `sha_1`, `sha_512`, `scrypt`, `pbkdf_2`, `phpass` | **Yalnızca destek talebi** | scrypt: `n` 2'nin kuvveti, 1-262144 |
| **Clerk** | `password_digest` + `password_hasher`; şeffaf şekilde bcrypt'e yükseltiyor | **EVET** — Dashboard dışa aktarımı hash'li parolaları içeriyor | Hem toplu hem **trickle** göçü açıkça belgeliyor |
| **WorkOS** | `password_hash` + `password_hash_type`; bcrypt/scrypt/argon2 | y.d. | Açık kaynak göç araçları: `migrate-auth0-users`, `migrate-clerk-users` |
| **FusionAuth** | **istek başına ≤10.000 kullanıcı**; kullanıcı başına `encryptionScheme`; **özel parola şifreleyici eklentisi**; girişte bcrypt'e yeniden hash | Evet (belgelenmiş offboarding) | |
| **Ory Kratos** | **En geniş format listesi** (aşağıda) | Evet (Admin API) | **Webhook tabanlı nazik göç**: hash'siz içe aktar, Kratos girişte webhook'unu çağırır, başarıda hash'i saklar |
| **Supabase** | bcrypt + argon2i/id + Firebase scrypt | **API yok** — DB dump veya service role gerekiyor | |
| **SuperTokens** | BCrypt, Argon2 (+ Firebase scrypt) | y.d. | Tembel göç belgeli |
| **Descope** | Bcrypt, Argon2, Django, Firebase, PBKDF2, PHPass, MD5 | y.d. | JIT göçü destekli |

**Ory Kratos'un tam içe aktarım kodlamaları — bulunan en izin verici set, bir Rosetta taşı olarak kullan:**
```
$2a$10$…                                              (bcrypt)
$argon2id$v=$m=,t=,p=$salt$hash
$md5$<hash>  ·  $md5$pf=<fmt>$<salt>$<hash>
$sha1|sha256|sha512$pf=<fmt>$<salt>$<hash>
{SSHA} / {SSHA256} / {SSHA512}
$pbkdf2-<alg>$i=<iter>,l=<len>$<salt>$<hash>
$scrypt$ln=<cost>,r=<block>,p=<par>$<salt>$<hash>
$firescrypt$ln=<mem_cost>,r=<rounds>,p=<par>$<salt>$<hash>$<salt_separator>$<signer_key>
crypt(3) md5crypt / sha256crypt / sha512crypt
$hmac-<fn>$<hash>$<key>                               (peppered!)
```

> **Argus'un içe aktarım desteği bu listeyi hedeflemeli.** Bu, "her yerden bize gelinebilir" iddiasının somut karşılığıdır.

---

### 37. Tembel / trickle göç

**Genel desen:** ilk girişte eski sisteme karşı doğrula → **aynı istek içinde** hedef formata yeniden hash'le → göç edildi olarak işaretle.

**Platform bazında mekanizmalar:**

| Platform | Mekanizma | Kritik detay |
|---|---|---|
| **Auth0** | Custom DB connection + **"Import Users to Auth0"** toggle'ı; `login` ve `getUser` Node.js script'leri | Toggle **açık kalmalı** — kapalıysa Auth0 her kimlik doğrulamada script'leri kullanır. Göç edilmiş kullanıcıyı Auth0'dan silersen ve upstream'de hâlâ varsa **yeniden göç eder**. Karışık yöntemler → **`DUPLICATED_USER`** hataları, elle Management API temizliği |
| **Okta** | Password import inline hook | Yalnızca Okta'ya **içeri** göç eder |
| **Cognito** | Migrate User Lambda | Göç penceresinde SRP yok, parola politikası zorlanmıyor |
| **Entra External ID** | `OnPasswordSubmit` | **Parolayı RSA JWE ile şifreleyen tek platform** |
| **Keycloak** | Özel `PasswordHashProvider` (en temiz) · `UserStorageProvider` + `ImportedUserValidation` · özel `Authenticator` | İlk başarılı girişte **otomatik yeniden hash'ler** |
| **Ory Kratos** | Parola credential'ı olmadan içe aktar; girişte webhook | Onayında hash'i saklar |

**WorkOS'un operasyonel kuralları** (16 Haziran 2026) — kopyalanmaya değer:
- **Yeniden hash'lemeyi giriş isteği içinde senkron yap**, ertelenmiş değil
- Hem eski hem yeni doğrulayıcıda **sabit zamanlı karşılaştırma**
- **Yeniden hash başarısızlığını ölümcül olmayan say** — bir rehash hatası asla bir girişi engellememeli
- **Eski-hash sayısını dashboard'a koy** ki kuyruğun küçüldüğünü görebilesin

**Somut dezavantajlar:**
- **Uzun kuyruk.** Kuyruk zorla-sıfırlanacak kadar küçülene dek iki sistemin de parasını ödersin. Poppy **6 ay** çift çalıştırdı ve son birkaç bin kullanıcıyı zorla sıfırladı.
- **Çift sistem maliyeti + çift patlama yarıçapı** — eski IdP her göç edilmemiş ilk giriş için ayakta, yamalı ve rate-limit yapabilir durumda kalmalı.
- **Hiç dönmeyen kullanıcılar.** Tek çıkışlar: (a) kesim tarihinde e-postayla zorunlu sıfırlama, (b) atıl bırak ve saklama penceresinden sonra sil, (c) hash'leri dışa aktarabiliyorsan artığı sonda toplu içe aktar.
- **Eski format zayıflığı miras alınır.** Hiç dönmeyen kullanıcılar MD5 dönemi korumasında kalır. **Girişte-yeniden-hash bir *yakınsayan* düzeltmedir, anlık değil.**

---

### 38. Toplu içe aktarım — hash formatı çapraz uyumluluğu

#### 38.1 PHC string formatı (fiilî değişim formatı)

> ⚠️ **Spec TAŞINDI:** `github.com/P-H-C/phc-string-format` artık **`github.com/C2SP/C2SP/blob/main/phc-strings.md`**'ye yönlendiriyor. Eski repo yalnızca bir yönlendirme notu taşıyor — bu çok sayıda doküman linkini bozuyor.

Format: `$<id>[$v=<version>][$<param>=<value>(,...)*][$<salt>[$<hash>]]` — sıra **id → version → params → salt → hash**.
**B64** = *"the standard Base64 encoding (RFC 4648, section 4) **except that the padding `=` signs are omitted**."*

Kanonik Argon2 örneği:
`$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno`

**Pratik sonuç:** argon2, scrypt, pbkdf2 ve (gevşekçe) bcrypt string'leri **kendini tanımlar** — Cognito'nun 2026 içe aktarımı buna açıkça dayanıyor: *"All supported algorithms are self-describing… You only need to specify the algorithm name."*
**Kendini tanımlamayan her şey** (Django'nun `$` formatı, .NET'in paketlenmiş binary'si, Firebase'in bant dışı `hash_config`'i, LDAP şemaları) **bir parametre yan kanalı gerektirir.**

#### 38.2 bcrypt varyant karmaşası

`$2$` (orijinal, 1999) → **`$2a$`** (kanonik OpenBSD) → **`$2x$` / `$2y$`** (Haziran 2011 acil işaretleri, **crypt_blowfish**/PHP tarafından **8-bit işaret genişletme hatası** için eklendi) → **`$2b$`** (OpenBSD'nin **uzunluk taşması** düzeltmesi: parola uzunluğu `unsigned char`'da saklanıyordu, >255 karakterlik parolalar 255'te sarmalanıyordu).

**Göç için önemli interop kuralları:**
- **`$2x$` kasten "2011'in bozuk algoritmasını yeniden üret" demektir — `$2x$`'i asla `$2a$`'ya yeniden yazma.**
- `$2x$`/`$2y$` işaretleri **yalnızca crypt_blowfish/PHP tarafından benimsendi**; OpenBSD ve çoğu implementasyon bunları hiç üretmedi.
- 72 baytın altındaki 7-bit ASCII parolalar için `$2a$`, `$2b$`, `$2y$` **özdeş doğrular** — Auth0'ın üçünü de birbirinin yerine kabul etmesinin nedeni bu.
- **Bazı doğrulayıcılar bilinmeyen önekleri doğrudan reddeder.** İçe aktarmadan önce hedefin önek allowlist'ini kontrol et (Auth0: `$2a`/`$2b`/`$2y`; Cognito: `$2<a/b/x/y>`).

#### 38.3 bcrypt'in 72 bayt kesmesi ve ön-hash deseni

bcrypt girdiyi **72 baytta** sessizce keser.

**`bcrypt(sha256(pw))` deseni** — Dropbox `SHA-512(parola)` → `bcrypt(cost 10)` → pepper ile `AES-256` şifreleme kullanıyor.

**OWASP artık naif ön-hash'lemeye karşı uyarıyor:** hızlı bir algoritmayla ön-hash'lemeyi *"dangerous"* diye niteliyor — **null bayt** (bazı bcrypt implementasyonlarında C-string kesmesi) ve **password shucking** (sızmış bir MD5/SHA korpusuna sahip saldırgan iç hash'i çevrimdışı kırar, sonra dış bcrypt'i önemsizce test eder) nedeniyle. OWASP'ın azaltması: **pepper ile HMAC-SHA-384 kullanarak ön-hash'le** ve bcrypt'e vermeden önce base64'le.

> ### ⚠️ Göç sonucu
> Kaynak `bcrypt(sha256(pw))` yaptıysa, saklanan değer **geçerli bir bcrypt string'idir** ama **hedef IdP aynı ön-hash'i uygulamadıkça hiç kimseyi doğrulayamaz.**
> **Auth0/Okta/Cognito/Firebase'in hiçbiri içe aktarımda ön-hash adımı yapılandırmana izin vermiyor.** Bu desen fiilen tembel göçü veya özel bir hash sağlayıcısını zorunlu kılar — Keycloak, FusionAuth ve Ory eklenti yapmana izin veren tek üçlü.

#### 38.4 Peppered hash'ler — en zor engel

Pepper **global bir sırdır**, DB dışında tutulur (vault/HSM), her hash'e uygulanır. Hedef IdP onu yapılandıramıyorsa, **hiçbir dışa aktarılmış hash doğrulanabilir değildir** ve kullanıcı başına bir çözüm yolu **yoktur.**

Seçenekler: (a) pepper'ı hedefte bir **özel hash sağlayıcısına** taşı (Keycloak `PasswordHashProvider`, FusionAuth özel şifreleyici, **Ory'nin `$hmac-<fn>$<hash>$<key>` formatı fiilen tüketebildiği bir peppered formattır**); (b) pepper'ı tutan eski sistem üzerinden tembel göç et; (c) zorla sıfırlat.

> **Dropbox'ın AES-256 pepper katmanı *geri çevrilebilirdir*** — bu en azından ham bcrypt string'inin dışa aktarımdan önce kurtarılabileceği anlamına gelir; alışılmadık ve göç dostu bir özellik. **Geri çevrilemez (HMAC) pepper'lar kurtarılamaz.**

#### 38.5 Karşılaşacağın PBKDF2 kodlamaları

- **Django:** `<algoritma>$<iterasyon>$<salt>$<hash>` — örn. `pbkdf2_sha256$36000$5LjfzfBwQAVI$sbEcyHm7a27GFKOgOOymu+mauqVLhS2QKQE4yLk8B9Y=`. **Salt ham (base64 değil)**, hash base64. İterasyon varsayılanı her sürümde değişiyor.
- **Keycloak:** string bile değil — `credentialData` ve `secretData` arasında bölünmüş.
- **.NET / ASP.NET Core Identity:** **paketlenmiş binary blob, base64'lenmiş**, başta bir format işaretçi baytıyla:
  - `0x00` = **v2**: PBKDF2-**HMAC-SHA1**, 128-bit salt, 256-bit subkey, **1.000 iterasyon**
  - `0x01` = **v3**: `{ 0x01, prf (UInt32), iterCount (UInt32), saltLength (UInt32), salt, subkey }` — PBKDF2-**HMAC-SHA256**, varsayılan **10.000 iterasyon**
  > **Göç notu:** Hiçbir ana akım IdP bunu yerel olarak içe aktarmaz. Blob'u açıp PHC tarzı PBKDF2 olarak yeniden yayımlaman gerekir — **ve v2'nin PRF'i SHA-1'dir, yani `pbkdf2-sha1`'e eşlenir, ki Cognito'nun içe aktarımı bunu DESTEKLEMEZ (yalnızca PBKDF2_SHA256).**
- **Okta:** PBKDF2'yi string değil, ayrık alanlar olarak alır.

#### 38.6 ⚠️ Hedefin tavanı, kaynağın parametrelerini belirler

**OWASP'ın güncel önerileri:**
- **Argon2id:** `m=47104 (46 MiB), t=1, p=1` · `m=19456, t=2, p=1` · `m=12288, t=3, p=1` · `m=9216, t=4, p=1` · `m=7168, t=5, p=1`
- **scrypt:** `N=2^17 (128 MiB), r=8, p=1` · `2^16, r=8, p=2` · `2^15, r=8, p=3` · `2^14, r=8, p=5` · `2^13, r=8, p=10`
- **bcrypt:** *"as large as verification server performance will allow, with a **minimum of 10**."*
- **PBKDF2:** HMAC-SHA256 → **600.000**; HMAC-SHA512 → **220.000**; HMAC-SHA1 → **1.400.000** (yalnızca legacy)

> **Cognito'nun tavanlarıyla çakışmaya dikkat:** OWASP'ın *en düşük* önerilen Argon2id yapılandırması `m=7168`, *en yükseği* `m=47104`. **Cognito'nun içe aktarım tavanı `m=19456, t=2, p=1` — tam olarak OWASP'ın ikinci seçeneği.**
> **OWASP'ın 46 MiB ayarıyla hash'lenmiş hiçbir şey Cognito'ya içe aktarılamaz.** scrypt'te aynı hikâye: OWASP'ın minimumu `N=2^13` ile `p=10`, Cognito `p=1`'de tavan yapıyor.
>
> **→ Hash parametrelerini *hedefinin* tavanına göre planla. Bu tek kontrol, belgelenen en yaygın geç-aşama göç başarısızlığını önlerdi.**

**"Eski hash'i yenisiyle sarmalama"** — OWASP'ın **"Method Two: layering the hashes"**'i, örn. `bcrypt(md5($password))`. OWASP'ın kendi çekinceleri: düz metin gerektirmemesi iyi ama *"may make the hashes easier to crack"* (yine shucking) ve katmanlı hash'ler **kullanıcının bir sonraki girişinde değiştirilmeli.** **Hiçbir büyük IdP içe aktarım API'si katmanlı hash desteklemiyor** — bu desen yalnızca self-hosted bir seçenektir ve **çıkan taraf sensen kendisi bir göç engelidir.**

---

### 39. Göç edilemeyenler

#### 39.1 Passkey'ler / WebAuthn — alan adı değişiminde ölürler, nokta

**Neden ölürler:** RP ID, kayıtta `rp.id`'den sabitlenir ve çağıranın origin'inin **kaydedilebilir alan adı sonekiyle** sınırlanır. Authenticator, RP ID'yi (SHA-256'sı authenticator data'daki `rpIdHash`) **credential'ın içinde** saklar ve RP **her assertion'da** doğrulamak zorundadır.
> *"Only that Relying Party, as identified by its RP ID, is able to employ the public key credential."*

Yani `rp.id = app.example.com` ile oluşturulmuş bir credential, `rp.id = example.com` veya `login.yeniidp.com` ile **asla** kullanılamaz. **Yeniden kapsamlama API'si yok, yönetici geçişi yok, dışa aktarım yok.** Tek çare: **eski RP ID hâlâ çalışırken yeni RP ID altında yeniden kayıt.**

> ### ⭐ Bunun ima ettiği tasarım kuralı
> **RP ID'yi ilk kayıttan ÖNCE seç** — apex alan adı, login alt alan adı **değil**, ve **IdP satıcısının alan adı kesinlikle değil.**
> **Bu, geri alınamayan tek WebAuthn kararıdır.**

**Related Origin Requests (WebAuthn L3 §5.11) — *kısmen* yardım eder:**
`https://<RP_ID>/.well-known/webauthn` sun, `Content-Type: application/json`:
```json
{ "origins": ["https://site-2.com", "https://site-3.com"] }
```
Tarayıcılar listelenen her origin'i **eTLD+1 etiketine** indirger ve **maksimum 5 benzersiz etiket** zorlar; fazlası **sessizce yoksayılır.** `clientDataJSON`'daki `origin` RP ID değil, *isteyen* origin olarak kalır.
Tarayıcı desteği: **Chrome/Edge 128+ ve Safari 18** (ikisi de 2024); **Firefox 152 masaüstü ve Android, Mayıs 2026** — son büyük boşluk kapandı.

> **IdP göçü için ne satın alır, ne almaz:** ROR, *yeni bir origin*'in (örn. yeni IdP'nin barındırılan UI'ı) **mevcut, değişmemiş RP ID'yi** kullanmasına izin verir. **Bu gerçekten değerlidir** — aynı RP ID'yi koruyabiliyorsan ve well-known dosyasını hâlâ ondan sunabiliyorsan, giriş sayfasını passkey'leri öldürmeden yeni bir IdP'ye taşıyabilirsin.
> **RP ID'yi değiştirmene izin VERMEZ** ve credential'ları hiçbir yere taşımaz. Ayrıca yalnızca web: Android Digital Asset Links, iOS Associated Domains gerektirir.

**FIDO CXP / CXF — IdP göçüne YARDIM ETMEZ:**
- **CXF (Credential Exchange Format):** FIDO Alliance Proposed Standard, **Ağustos 2025**. ⚠️ v1.0'ın 9 Mart 2026 tarihi ikincil kaynaktan, **doğrulanmadı.**
- **CXP (Credential Exchange Protocol):** hâlâ **Working Draft** — çekilebilen en güncel hâli **3 Ekim 2024 WD**. Aktarımda uçtan uca şifreleme için HPKE kullanıyor.
- **Kapsam, taslaktan birebir:** *"This protocol describes the secure transmission of one or more credentials between two **credential providers**"* — katılımcılar credential sahibi ve **credential sağlayıcılarıdır (parola yöneticileri / platform credential yöneticileri). Relying party'ler ve identity provider'lar katılımcı DEĞİLDİR.**
- **Dolayısıyla:** CXP/CXF passkey'leri **1Password ↔ Bitwarden ↔ Apple ↔ Google ↔ Dashlane** arasında taşır. **Auth0-as-RP'den Okta-as-RP'ye taşımak için hiçbir şey yapmaz.** RP tarafındaki açık anahtar + credential ID zaten senin verindir (IdP'nin kriptosunda değil, senin DB'nde), ama **yalnızca RP ID özdeş kalırsa kullanılabilir.**
- **Apple, iOS 26 / macOS 26'da CXF tabanlı aynı-cihaz credential transferini sevk etti.**

#### 39.2 TOTP sırları

| Ürün | TOTP dışa aktarımı |
|---|---|
| **Keycloak** | ✅ **EVET** — OTP credential'ları aynı `credentials` dizisinde (`type: "otp"`), `kc.sh export --users` ile çıkar. **Keycloak'ın en büyük taşınabilirlik avantajı** |
| **Auth0** | Kapılı PGP destek sürecinde (parola hash'leriyle aynı) |
| **Okta** | ❌ Yok — yeniden kayıt |
| **Cognito** | ❌ Yok. `cognito:mfa_enabled` yalnızca boolean; MFA-zorunlu bir pool'a içe aktarılan kullanıcılar **geçerli bir faktör yapılandırana kadar giriş yapamaz** |
| **Firebase CLI** | ❌ Şemada MFA yok |
| **Entra/B2C** | ❌ Yok |

**Google Authenticator dışa aktarım formatı** (kullanıcılardan faktörleri kendilerinin taşımasını istiyorsan): QR, `otpauth-migration://offline?data=<base64>` kodlar ve payload standart `otpauth://` değil, bir **proto3 (Protocol Buffers) mesajıdır.**

#### 39.3 Oturumlar, refresh token'lar, rızalar, denetim geçmişi

**Taşınabilir değil.** Eski IdP'nin verdiği token'lar yenisi tarafından doğrulanamaz (farklı imzalama anahtarları, `iss`, `aud`, claim şekilleri, ömürler). Rıza/grant kayıtları `client_id` başınadır ve yeniden kurulmalıdır. Denetim geçmişi geride kalır.

**Bulunan tek ürünleşmiş azaltma: Descope session migration** (15 Aralık 2025) — frontend eski token'ı yeni IdP'ye verir, o doğrular, kullanıcıya eşler ve yerel bir oturum basar; **kimse çıkış yapmaz.** ⚠️ Yalnızca Auth0 kaynağı ve kendi SDK'ları gerekiyor.
**Aynı numarayı kendin kurabilirsin:** eski IdP'nin JWT'sini JWKS üzerinden doğrulayan ve yeni oturum veren bir token-exchange uç noktası. Mimo tam olarak bunu yaptı.

#### 39.4 ⭐ `sub` problemi — hafife alınan kritik engel

Yeni IdP'n upstream sosyal/kurumsal sağlayıcılarda **yeni OAuth client ID'leri** kaydediyorsa, aldığın `sub` değişebilir ve **hesap bağlaması sessizce kırılır.**

| Sağlayıcı | `sub` client ID'ler arasında kararlı mı? | Ne yapmalı |
|---|---|---|
| **Google** | *"unique among all Google Accounts and never reused"*; e-posta değişse bile `sub` değişmiyor. Ama Google **cross-project** garantisi vermiyor | Pratikte kararlı say, ama **kesimden önce ampirik doğrula.** Cross-project için **DOĞRULANMADI** |
| **Apple** | **HAYIR — `sub` geliştirici TAKIMINA kapsamlıdır.** Uygulamayı yeni takıma devret, `sub` değişir | **Transfer identifier** akışını kullan (§39.5) |
| **Microsoft Entra** | **HAYIR — `sub` uygulama başına pairwise'dır:** *"a pairwise identifier… unique to an application ID. If a single user signs into two different apps using two different client IDs, those apps receive two different values for the subject claim."* Public subject tipine **değiştirilemez** | **`oid` (+ `tid`) üzerinden anahtarla, `sub` değil** — Microsoft açıkça söylüyor: *"Use this claim instead of sub for uniquely identifying users — even across applications."* |
| **Facebook** | **HAYIR — Graph API v2.0'dan (2014) beri uygulama-kapsamlı kullanıcı ID'leri:** *"with app-scoped IDs, the ID for the same user will be different between apps."* | Aynı uygulamayı koru, veya aynı işletmenin sahip olduğu uygulamalar arasında **Business Mapping API** kullan |

> **Tasarım dokümanı için pratik kural: sağlayıcı pairwise subject kullanıyorsa, yeni IdP'de tam olarak AYNI upstream OAuth uygulama kayıtlarını / client ID'lerini yeniden kullan.**
> Kullanamıyorsan tek fallback'in **doğrulanmış e-posta üzerinden bağlamaktır**, ki bu (a) her zaman mevcut değildir (**Apple private relay!**) ve (b) güvenlik açısından hassas bir karardır — doğrulanmamış e-posta üzerinden otomatik bağlama bir hesap devralma vektörüdür (bkz. §11-12).

#### 39.5 Sign in with Apple — transfer identifier mekanizması

`POST https://appleid.apple.com/auth/usermigrationinfo` üzerinden iki faz:
1. **Devirden önce**, *gönderen* takım `operation=transfer_sub` + `client_id`, `client_secret`, `target=<alıcı takım id>` ile çağırır ve her kullanıcı için **geçici bir `transfer_sub`** basar.
2. **Devirden sonra**, *alan* takım `operation=exchange` + `transfer_sub` + kendi `client_id`/`client_secret`'ı ile çağırır ve yeni takım-kapsamlı kimliği alır:
```json
{"sub":"820417.faa325acbc78e1be1668ba852d492d8a.0219",
 "email":"ep9ks2tnph@privaterelay.appleid.com",
 "is_private_email": true}
```

- Devir tamamlandıktan sonra **60 günlük pencere.** Apple `transfer_sub`'ı o pencerede verilen ID token'lara da koyuyor, böylece girişte anında göç edebiliyorsun.
- **Transfer ID'ler takım *çifti* başına benzersizdir** — A→B ve B→C farklı transfer ID'ler üretir.
- ⚠️ **Pencereyi kaçırırsan eşleme kurtarılamaz:** kullanıcılar orijinal kimlikleriyle artık giriş yapamaz ve **yeni hesap açmak zorunda kalır.**

---

### 40. Her kaynağın fiilen dışa aktardığı

| | Kullanıcılar | Parola hash'i | MFA | Grup/Rol | Client/App | Org yapısı | Format |
|---|---|---|---|---|---|---|---|
| **Auth0** | ✅ | **Destek talebi** (PGP, yönetici imzası) | Normal export'ta yalnızca sağlayıcı listesi; **sırlar aynı talepte** | Management API (ayrı çağrılar) | Management API / CLI | Organizations API | NDJSON / CSV (max 30 alan) |
| **Okta** | ✅ (Users API) | ❌ (dar istisna, Okta→Auth0) | ❌ yeniden kayıt | Groups API | Apps API | y.d. | API'den JSON |
| **Cognito** | ✅ `ListUsers` (**5 req/s**) | ❌ export; **import 15 Tem 2026'dan beri** | ❌ yeniden kayıt | Groups API | API | y.d. | JSON; import için CSV |
| **Keycloak** | ✅ | **✅ EVET** (`--users`, `credentials[]` içinde) | **✅ EVET** (OTP aynı dizide) | Realm/client rolleri, gruplar, üyelikler | ✅ protocol mapper'lar dahil | Organizations (KC 26+) | **JSON** |
| **Firebase** | ✅ | **✅ yalnızca scrypt** (diğerleri boş) | ❌ | y.d. | y.d. | y.d. | JSON / CSV (26 sütun) |
| **Entra External ID / B2C** | Graph API | ❌ | ❌ | Graph | App registrations | Graph | JSON (Graph) |

> **Keycloak'ın dışa aktarımı beşinin en eksiksizi; Cognito'nunki ve Okta'nınki en az eksiksizi.** Auth0 ortada ve resmî (acı verici de olsa) bir hash kaçış kapağı olan tek ürün.

---

### 41. Sıfır kesinti stratejileri

- **Çift çalıştırma + kademeli trafik kaydırma**, sıfır kesintiyi fiilen sağlayan tek desendir; zamanlanmış bir big-bang geçişi sağlamaz. **Kohort veya tenant bazında** kaydır, hata oranı ve gecikmeyi izle, **geri kaydırma yeteneğini koru.**
- **Strangler fig / façade proxy** — iki IdP'nin önüne bir proxy koy ve istek başına yönlendir. IdP'ler için façade genelde kendi `/login` handler'ın veya kullanıcı başına hangi IdP'yi çağıracağına karar veren bir API gateway'idir.
- **Bir arada yaşama sırasında iki token tipini de doğrula** — backend eski-IdP ve yeni-IdP JWT'lerini **eşzamanlı** kabul etmeli (iki JWKS URL'i, iki issuer), **en uzun refresh token ömrü boyunca**. Aksi hâlde insanları çıkış yaptırırsın.
- **Oturum sürekliliği:** ya eski token'ı kabul edip yerel bir tanesiyle değiştir, ya da kesimin herkesi çıkış yaptıracağını kabul et — **bunu açıkça karara bağla**, kullanıcıya en görünür sonuç budur.
- **Hash'i dışa aktarılabilir bir kaynak için önerilen sıralama:** önce hash'leri toplu içe aktar (çoğu kullanıcı hiç fallback gerektirmez) → sonra artık için tembel göçü aç (export ile kesim arasında oluşturulan kullanıcılar) → sonra kuyruğu zorla sıfırlat. **Mimo tam olarak bunu yaptı ve en az hareketli parçası olan desen budur.**
- **İnsanların unuttuğu pratik detay:** Auth0, *hem* toplu içe aktarım *hem* otomatik göç kullanırsan veya silinmiş kullanıcıları yeniden oluşturursan **`DUPLICATED_USER`** hataları alacağını ve elle Management API temizliği gerekeceğini uyarıyor. **Kohort başına tek birincil yol seç ve onun üzerinden kapıla.**

---

### 42. Gerçek vaka çalışmaları

**Güçlü, birinci taraf, somut:**

**Mimo — 6.000.000 kullanıcı, Auth0 → Firebase Auth** (16 Kasım 2020). ~**2 hafta hazırlık**, göç başlangıcından uygulama yayınına **~8 saat**. Parola hesapları için **ikinci bir Auth0 export'u** gerekti çünkü hash'ler ilk export'ta yoktu. **Özel bir token-exchange uç noktası** kurdular çünkü refresh token'lar uyumsuzdu; export ile kesim arasındaki kayıtları yakalamak için Auth0 Rules kullandılar; aynı e-postayı paylaşan çoklu hesapları tekilleştirdiler. Sonuç: *"without anyone noticing"* ve *"without logging anyone out."*

**Keymate — 20.000.000+ kimlik, Keycloak'a** (Şubat 2026). Throughput **2M → 12M kimlik/saat (6×)** ayarlandı, **kaynak eklemeden.** Migrator: Quarkus + reaktif PostgreSQL istemcisi, 512 claimer, 512 eşzamanlı HTTP isteğine kadar, 2.000'lik batch'ler.
**Darboğazlar sırayla:** aşırı eşzamanlılıkta bağlantıları öldüren **HTTP/2 RST-flood koruması** · `user_entity`'de **2,5M ölü tuple**'dan gelen DB kilit çekişmesi · **2.750 eşzamanlı DB bağlantısının** debelenmesi · aşırı sağlanmış havuzlar.
**Alıntılanacak cümle:** *"**Keycloak was never the bottleneck.** It absorbed 95K concurrent requests without crashing."*
**Havuzları yüzlerden 50'ye indirmek ve uygulama eşzamanlılığını yarıya düşürmek throughput'u İKİYE KATLADI.**

**Poppy (Belçikalı ridesharing) — Auth0 → SuperTokens, 6 ay boyunca tembel göç.** İki sistemi paralel çalıştırdılar; *"customers didn't know anything about it."* Auth0'da yalnızca **birkaç bin** kullanıcı kaldığında onları zorla sıfırlattılar ve Auth0'ı kapattılar.

**BRZ (Avusturya Federal Bilgi İşlem Merkezi) — 2.000.000+ kullanıcı Keycloak'a**, 130+ kamu hizmetine mikroservis + GitOps ile hizmet veriyor (Ağustos 2025).

**Amazon Cognito'nun kendisi** *"hundreds of millions of user profiles with zero downtime"* yeni nesil depolama altyapısına göç etti (4 Haziran 2026) — ölçekte çevrimiçi IdP-veri-deposu göçünün varlık kanıtı.

> ⚠️ **Zayıf / satıcı yazımı — dikkatli alıntıla:** "500K MAU Auth0 → MojoAuth: 6 hafta, 3 mühendis, ~280 mühendis-saati, ~4.200$ çift çalıştırma maliyeti, 187.000$ ilk yıl tasarrufu" — satıcı pazarlama içeriği (Mayıs 2026), **bağımsız doğrulanabilir değil**; büyüklük mertebesi çıpası olarak kullan.
> ⚠️ **Hedefli aramaya rağmen BULUNAMADI:** Hey/Basecamp, Shopify, Zapier, PostHog, Cal.com, Supabase veya Vercel'den Auth0/Okta/Cognito'dan çıkış hakkında **kamuya açık mühendislik postmortem'i yok.** Bu şirketlerin böyle bir vaka çalışması yayımladığı iddiasını **DOĞRULANMAMIŞ** say.

---

### 43. Bölüm VI için Argus kararları

| # | Karar | Gerekçe |
|---|---|---|
| 1 | **İçe aktarım Ory Kratos'un format listesini hedefler** (bcrypt tüm önekleri, argon2i/id, scrypt, firescrypt, pbkdf2 tüm PRF'ler, SSHA*, crypt(3), **hmac/peppered**) | "Her yerden gelinebilir" iddiasının somut karşılığı |
| 2 | **Ön-hash ve pepper eklenebilir** — `PasswordHashProvider` benzeri bir eklenti noktası | `bcrypt(sha256(pw))` ve peppered hash'ler yalnızca böyle göç eder |
| 3 | **Parametre tavanı YOK** — OWASP'ın en yüksek ayarları dahil her şey kabul edilir | Cognito'nun `m=19456` tavanı belgelenmiş en yaygın göç başarısızlığı |
| 4 | **Girişte otomatik yeniden hash'leme**, senkron, **başarısızlığı ölümcül değil** | WorkOS operasyonel kuralı |
| 5 | **Dışa aktarım: hash'ler + TOTP sırları self-servis** (yönetici + step-up auth + denetim olayı ile) | Keycloak dışında kimse yapmıyor; **dürüstlük iddiası budur** |
| 6 | Dışa aktarım **PHC string** olarak, kendini tanımlayan | Yan kanal parametre gerektirmez |
| 7 | **`OnPasswordSubmit` eşdeğeri uzantı, parolayı JWE ile şifreler** | Entra'nın tek doğru yaptığı şey |
| 8 | **RP ID kurulumda tek seferlik ve değiştirilemez bir karar olarak sunulur**, uyarıyla | Geri alınamayan tek WebAuthn kararı |
| 9 | **`.well-known/webauthn` (ROR) birinci sınıf desteklenir**, 5 etiket limiti UI'da gösterilir | Barındırılan giriş UI'ına geçişi passkey'siz yapar |
| 10 | Upstream sosyal sağlayıcılarda **client ID yeniden kullanımı zorunlu tutulur**; farklı client ID girilirse **açık uyarı** | Apple/Entra/Facebook pairwise `sub` |
| 11 | Entra bağlantılarında **`oid`+`tid` üzerinden anahtarlanır**, `sub` değil | Microsoft'un kendi tavsiyesi |
| 12 | **Apple transfer identifier akışı yerleşik** (60 günlük pencere sayacıyla) | Kaçırılırsa kurtarılamaz |
| 13 | **Token-exchange uç noktası**: eski IdP'nin JWT'sini JWKS ile doğrula, yerel oturum bas | Kesimde kimse çıkış yapmaz |
| 14 | **Çift JWKS / çift issuer doğrulama** bir arada yaşama modu olarak yapılandırılabilir | En uzun refresh token ömrü boyunca gerekli |
| 15 | **Eski-hash sayacı** admin dashboard'unda birinci sınıf metrik | Kuyruğun küçüldüğünü görmek |

---

## BÖLÜM VII — B2B ORGANİZASYON AKIŞLARI

### 44. Davet akışı güvenliği

#### 44.1 Satıcı davranışı

**WorkOS AuthKit:** İki adımlı model — *"The inviter expresses intent for someone to join an organization. The invitee chooses to join that organization."* Açıkça, rıza olmadan bir organizasyona eklenmeye karşı savunma olarak çerçeveleniyor.

> ⭐ **Türk bir IdP referansı için not edilmesi gereken kritik tasarım kararı:** WorkOS kabulü alan adı sınıfına göre farklı bağlıyor (birebir):
> *"**Consumer domains:** the invited user must sign up using **exactly the same email address** to which the invitation was sent."*
> *"**Corporate domains:** the user can sign up with **any email address from the same domain** as the email on the invitation."*
> Bu, katı e-posta bağlamasının **kasıtlı** bir gevşetilmesidir ve tam olarak "davet edilenden farklı bir e-postayla kabul" davranış sınıfıdır — **yalnızca kurumsal alan adı doğrulanmışsa güvenlidir.**

Davet nesnesi **bir DB satırıdır**, durumsuz bir JWT değil: `id, email, state, token, organization_id, accepted_at, expires_at, created_at, updated_at`.
İlgili WorkOS SSO uyarısı: *"It is important to always validate the returned profile's organization ID. **It's unsafe to validate using email domains.**"*

**Clerk:** Uygulama davetleri **bir ayda** sona eriyor; organizasyon davetleri varsayılan 30 gün. Token URL'de `__clerk_ticket` sorgu parametresi olarak taşınıyor — **yani token URL'de, Referrer-Policy önemli.**
Clerk'ün açık uyarısı: *"**Revoking an invitation does not prevent the user from signing up on their own.**"* — davetin iptali, kayıt kısıtlanmadıkça erişimin iptali **değildir.**
Rate limit'ler: 100/saat tekil + 25/saat toplu (uygulama); 250/saat tekil + 50/saat toplu, çağrı başına max 10 (org).

**Auth0 Organizations:** **`ttl_sec` varsayılan 604800 (7 gün), maksimum 2592000 (30 gün)** — herhangi bir satıcının yayımladığı en somut TTL rakamları.
Katı bağlama: *"Invited users must log in or create an account with **the email address to which the invitation was sent**."* (WorkOS'un kurumsal-alan gevşetmesiyle zıt.)
Davet URL şekli: `https://myapp.com/login?invitation={ticket_id}&organization={org_id}&organization_name={name}` — yine URL'de token.
`roles` dizisi davet oluşturmada eklenebiliyor → **rol yetkilendirmesi *oluşturma* anında sunucu tarafında yapılmalı** (aşağıdaki rol yükseltme CVE'leri).

**Stytch B2B:** Magic/davet linkleri **kesinlikle tek kullanımlık** — gömülü token ilk başarılı tıklamada "tüketilir".
> ⚠️ **E-posta güvenlik tarayıcısı problemi (davet linklerinin başlıca gerçek dünya başarısızlık modu):** Kurumsal posta tarayıcıları linkleri otomatik tıklar ve **insan görmeden tek kullanımlık token'ı tüketir.** Stytch'in "Protected Email Magic Links"i cihaz istihbaratı kullanarak tarayıcı tıklamasının token'ı tüketmemesini sağlıyor. **Tek kullanımlık olan her davet tasarımı bunu ele almalıdır.**

Org ayarları davetleri kapılıyor: `email_invites` = `ALL_ALLOWED` / `RESTRICTED` / `NOT_ALLOWED`, `email_allowed_domains` ile; RESTRICTED iken kabul eden kullanıcının e-postası allowlist'le eşleşmeli ve **`gmail.com` gibi yaygın tüketici alan adlarına allowlist'te izin verilmiyor.**

**Frontegg:** Token oluşturmada `expiresInMinutes` (açık, çağıran kontrollü TTL). **Magic link alternatifi olarak 6 haneli magic code** sunuyor ve kodların *"considered more secure than Magic links (since it reduces the risk of unauthorized access if the email is compromised)"* olduğunu söylüyor — Referer/iletme sızıntısı açısından alakalı.

**Vercel** (nadir, yayımlanmış, farklılaştırılmış TTL): *"They have **7 days** to accept the invite (**30 days for SAML enforced teams**)."*

#### 44.2 URL'de token → Referer sızıntısı

OWASP Forgot Password Cheat Sheet (davet token'larına doğrudan uygulanabilir): token'lar CSPRNG'den, kaba kuvvete karşı yeterince uzun, **kullanımdan sonra geçersiz**, uygun sürede sona eren, **hash'lenmiş olarak güvenli saklanan** ve **veritabanında bireysel bir kullanıcıya bağlı** olmalı.
Açık Referer rehberliği: *"add the Referrer Policy tag with the **`noreferrer`** value in order to avoid referrer leakage."*

Gerçek raporlar: **HackerOne #342693** ("Password reset token leakage via referer") ve **#301526** ("Invitation token leaks to bat.bing.*").
> ⚠️ HackerOne rapor gövdeleri JS ile render ediliyor ve doğrudan çekilemedi; başlıklar/programlar arama indekslerinden. **Gövde detaylarını DOĞRULANMAMIŞ say.**

#### 44.3 Gerçek bug bounty raporları ve CVE'ler

**⭐ GitLab #356665 / HackerOne #1517554** — *"Ability to gain access to private project through an email invite by using other user's email address as an **unverified secondary email**"*. Bildiren `vaib25vicky`, **21 Mart 2022**.
GitLab, bir daveti, davet edilen adresi **doğrulanmamış ikincil e-posta** olarak tutan bir hesapla eşleştiriyordu → saldırgan kurbanın kurumsal adresini kendi hesabına önceden ekler ve **gelecekteki her daveti sessizce ele geçirir.**
> **Bu, "kabul edenin fiilen kontrol etmediği bir e-postaya bağlanmış davet" için en iyi kanonik örnektir.**

İlgili, güvenlik hatası olarak görünmeyen ama **aslında bağlama hataları olan** UX hataları: GitLab **#321324 ve #338022 — davet e-postası eşleştirmesi büyük/küçük harfe duyarlı**, yani `User@corp.com` ile `user@corp.com` ayrışıyor. **Davet edilen adresin büyük/küçük harf ve Unicode normalizasyonu gerçek bir tasarım gereksinimidir.**

**Slack, HackerOne #1663361 — "Bypass invite accept for victim"**, açıklama **17 Şubat 2023**, **1.500 $** ödül. Slack workspace yöneticileri, **kullanıcının daveti kabul etmesine gerek kalmadan** e-postayla keyfî bir kullanıcı ekleyebiliyordu — kabul adımını **ve** kurbanın saldırganın davetlerine koyduğu önceki engellemeyi atlayarak.

**ProductBoard / Satismeter, HackerOne #2586433 — "Insecure Invitation Link Handling"**, gönderim **31 Ekim 2024**: bir e-posta adresine gönderilen davet linki, **tamamen farklı bir e-posta adresiyle** organizasyona katılmak için kullanılabiliyordu.

**Shopify, HackerOne #2885269** — bir personel, davet edilen sahiplerin e-posta adreslerini görebiliyor, onlarla hesap oluşturabiliyor ve daveti kabul ederek **e-posta doğrulaması olmadan yükseltilmiş ayrıcalık** kazanabiliyordu. (Ödül rakamı arama indeksinden, **DOĞRULANMADI.**)

**Dropbox, Bugcrowd, 21 Şubat 2023** — *"privilege escalation allow the admin to takeover the org by invite the user as owner"*: davet edebilen bir saldırgan, **daveti değiştirerek takım sahibinin yerine geçebiliyordu.** P3, 300 $.
> **Bu, "davet payload'ını kurcalayarak rol yükseltme"nin kanonik örneğidir.**

**Budibase, GHSA-4wfw-r86x-qxrm / CVE-2026-25040 (Kritik)** — Davet etme UI izni olmayan Creator seviyesi bir kullanıcı `/api/global/users/multi/invite`'a POST atarak **herhangi bir rolle (Admin/Creator)** ve herhangi bir gruba kullanıcı davet edebiliyordu: *"The API does not verify the requesting user's permissions for user creation, role assignment, or group membership."*
> ⚠️ Advisory okunduğunda **henüz yamalanmamış** olarak listeleniyordu — "düzeltme sürümü"nü **DOĞRULANMAMIŞ** say.

**HackerOne'ın kendi programı**, davet akışı regresyonları (başlıklar doğrulandı, gövdeler DOĞRULANMADI):
- **#275293** — durum değişiminde davet geçersiz kılınmıyor
- **#214839** — Disclosure Assistance değişikliği **önceki bir düzeltmeyi geri aldı** (regresyon)
- **#48422, #66151** — kullanıcı takıma zaten eklendikten sonra davet yeniden kullanılabiliyor
- **#1491127** — eski davet linkleri, yeniden adlandırmadan sonra özel bir programın *yeni* handle'ını çözüyordu
- **#331691** — hesabı olmayan bir adrese gönderilen daveti **birden çok farklı araştırmacı hesabı** ziyaret edip kabul edebiliyordu
- **#269230, #2045722, #792927** — davet akışı üzerinden **davet edilen adresin ifşası**

#### 44.4 İmzalı token (durumsuz JWT) vs DB satırı

**İncelenen her büyük B2B IdP bir DB satırı kullanıyor**, çıplak durumsuz JWT değil: WorkOS (`state`/`revoked` ile davet nesnesi), Auth0 (`ticket_id` + `expires_at`), Clerk (iptal edilebilir kayıtlar), Stytch (sunucu tarafında tüketilen token), Frontegg (davet token kayıtları).

Belirleyici argüman iptaldir:
> *"JWTs let you go stateless, but magic links require single use enforcement which **inherently requires server side state** (a denylist on the `jti` claim). At that point you have **lost the statelessness benefit and gained the complexity cost** of JWT validation including algorithm confusion attacks. **Opaque random tokens stored server side as SHA-256 hashes are simpler and harder to misuse.**"*

**Argus için tasarım sonucu:**
```
URL'de opak yüksek-entropili token
    ↓
Depoda SHA-256 hash'li
    ↓
Tek DB satırı:
  { org_id, invited_email_normalized, role, inviter_id,
    expires_at, consumed_at, revoked_at }
```
- Tek kullanım `consumed_at` üzerinden, **transaction/unique constraint altında** zorlanır
- **Rol satırdan okunur, asla istekten değil**
- TTL 7 gün (Auth0/Vercel varsayılanı), max 30 gün
- Kabul sayfasında `Referrer-Policy: no-referrer`
- **Magic code fallback'i** (Frontegg) ve **tarayıcı-tıklaması toleransı** (Stytch) — tek kullanım kurumsal posta ortamlarında kırılmasın

#### 44.5 Klasik davet zafiyetleri kontrol listesi

Her maddenin yukarıda gerçek dünya atfı var:

| # | Zafiyet | Atıf |
|---|---|---|
| 1 | URL'de token → Referer/analitik sızıntısı | H1 #301526, #342693; OWASP `noreferrer` |
| 2 | Davet edilenden farklı e-postayla kabul | ProductBoard #2586433; WorkOS'un *kasıtlı* kurumsal gevşetmesi |
| 3 | Adresi **doğrulanmamış ikincil e-posta** olarak tutan hesapla kabul | **GitLab #356665** |
| 4 | Token kullanımdan / iptalden / yeniden adlandırmadan sonra geçersiz kılınmıyor | H1 #48422, #66151, #275293, #1491127, #214839 |
| 5 | Davet payload'ını kurcalayarak rol yükseltme | Dropbox Bugcrowd 2023; **Budibase CVE-2026-25040**; Luminate |
| 6 | Kabul adımı tamamen atlanıyor — kurban zorla ekleniyor | **Slack #1663361** |
| 7 | Davet edilen adresin davet edene/diğer üyelere ifşası | H1 #269230, #792927, #2045722 |
| 8 | Davet edilen adreste büyük/küçük harf ve Unicode normalizasyon ayrışması | **GitLab #321324, #338022** |
| 9 | Sonradan el değiştiren bir adrese davet | Truffle Security, npm expired-domain araştırması (§45) |
| 10 | **Zehirli tenant** — saldırgan kurbanın şirket adıyla tenant açar ve *senin* meşru davet e-postanı phishing taşıyıcısı yapar | §48 |

---

### 45. Alan adı doğrulaması, otomatik katılım ve alan adı ele geçirme

#### 45.1 Büyükler nasıl yapıyor

| Ürün | Yöntem | Detay |
|---|---|---|
| **Microsoft Entra ID** | DNS TXT `MS=msXXXXXXXX` | Graph `domain: verify`; en az ayrıcalıklı rol Domain Name Administrator |
| **Slack** | DNS TXT | Normal alan adı için host `@`, **wildcard** için `_slack-challenge`; **72 saate kadar** etkili olma süresi |
| **Atlassian** | Üç yöntem: alan adı kökünde **HTTPS dosyası** (`www`'ye bir yönlendirme kabul), **DNS TXT** (72 saate kadar), veya **IdP bağlantısı** (Google Workspace / Entra ID kendi alan adlarını otomatik doğruluyor) | Açıkça: *"You can't verify ownership of a public domain, such as gmail.com."* Alt alan adları ayrı ayrı doğrulanmalı. **Atlassian, doğrulamanın bir yöntem bozulunca hayatta kalması için birden çok yöntem öneriyor** |
| **Google Workspace** | Kayıt şirketinde DNS kayıtları | Deneme/sözleşme başlangıcından **9 gün** içinde doğrulanmalı, yoksa hesap kayıttan **21 gün** içinde otomatik siliniyor. Gerekçe açıkça: *"We don't want someone else to use your domain to sign up for Google Workspace."* |
| **Notion** | DNS kaydı | *"a change in the DNS record takes only minutes… may take up to 72 hours"*; **doğrulama kodları bir haftada sona eriyor.** Doğrulama SAML SSO'yu ve workspace oluşturma kontrolünü açıyor (doğrulamadan sonra varsayılan: **yalnızca workspace sahipleri** o alan adında workspace oluşturabilir). Enterprise sahipleri doğrulanmış bir alan adında oluşturulan workspace'leri görüntüleyebilir/talep edebilir/devredebilir/silebilir — **ama yalnızca ilk doğrulamadan sonraki 14 günlük bekleme süresinin ardından** |

#### 45.2 Otomatik katılım riski

**Notion'ın kendi rehberliği riskin en temiz ifadesi:** izin verilen bir e-posta alan adı olması, o alan adındaki herkesin workspace'e katılmasına izin verir ve bu *"could create a mismatch between membership in Identity Providers and Notion"*; **Notion tüm izinli e-posta alan adlarının kaldırılmasını ve erişimin yalnızca SSO üzerinden yönetilmesini öneriyor.**

**Tüketici/paylaşılan alan adları:** Atlassian public alan adlarının doğrulanmasını doğrudan engelliyor; Stytch `gmail.com` gibi yaygın alan adlarını `email_allowed_domains`'ten engelliyor.
> **Türkiye pazarı için tasarım, ulusal ücretsiz posta alan adlarını da tüketici alan adı saymalıdır** (`hotmail.com`, `yandex.com.tr`, `mynet.com`, `superonline.com`) — **ve daha önemlisi, tek bir kayıtlı alan adının binlerce ilgisiz insanı kapsadığı ISP/telko adreslerini ve üniversite alt alan adlarını.**

**Alt alan adı ele geçirme:** Doğrulama, sarkan bir alt alan adından (veya `www`'deki bir HTTPS dosyasından) sunulan bir token'ı kabul ediyorsa, **bir alt alan adı ele geçirmesi bir alan adı doğrulama atlatmasına dönüşür.**

**Süresi dolmuş alan adları:** **Doğrulama, kaydın kendisi kadar dayanıklıdır.** Ele geçirme literatüründen rehberlik: hizmetten çıkardıktan sonra bile doğrulama TXT kaydını yerinde tut, ve **doğrulamayı kalıcı saymak yerine periyodik olarak yeniden doğrula.**

#### 45.3 ⭐ Yönetilmeyen hesaplar, alan adı talebi ve yönetici devralma

**Microsoft Entra ID — self-service kayıt ve "viral"/yönetilmeyen tenant'lar:**
Bir self-service kayıt, **e-posta alan adından türetilen yönetilmeyen bir tenant'ta** (yani **Global Administrator'ı olmayan** bir tenant) **e-postası doğrulanmış bir kullanıcı** (`creationmethod=EmailVerified`) yaratır.
İki kontrol, ikisi de tenant genelinde: **`allowEmailVerifiedUsersToJoinOrganization`** ve **`allowedToSignUpEmailBasedSubscriptions`**. **İkisini de false yapmak sertleştirme duruşudur.**

**Microsoft Entra ID — yönetilmeyen bir dizinin yönetici devralması:**
- **İç devralma:** Yönetilmeyen tenant'ta bir kullanıcı bağlamı elde edersin (örn. `admin@alanadi` olarak Power BI'a kaydolarak), `portal.office.com/admintakeover`'a gidersin, "Yes, I want to be the admin"e tıklarsın, **DNS TXT kaydını eklersin** ve o tenant'ın Global Administrator'ı olursun.
- **Dış devralma:** Zaten yönettiğin bir tenant'tan alan adını ekler ve doğrularsın — *"Microsoft Entra ID **removes the domain name from the unmanaged organization and moves it to your existing organization**"*, **kullanıcıları, abonelikleri ve lisans atamalarını da alarak.** Graph `domain: verify` API'sinde **`forceTakeover = true`** gerektirir (`Confirm-MgDomain` cmdlet'i bunu açığa çıkarmaz). *"The unmanaged Microsoft Entra organization is **deleted 10 days** after a successful external admin takeover with the `forceTakeover` option."*

> ### ⭐ Tasarım dersi
> **DNS'i kontrol eden, bir gölge tenant'ı sahip olunan bir tenant'a çevirebilir ve kullanıcılarını miras alabilir. DNS güven kökündedir.**

**Google Workspace — çakışan hesaplar / Transfer aracı** (Şubat 2017): Yönetilmeyen = alan adınızda bağımsız oluşturulmuş kişisel bir Google Hesabı. Seçenekler: transfer talebi gönder (**kullanıcı kabul etmeli** → yönetici veriyi ve yönetimi kazanır) veya kullanıcıyı yeniden adlandırmaya zorla.
> ⭐ **Rıza asimetrisine dikkat: Google transferi *kullanıcının* kabul etmesini gerektiriyor; Microsoft'un dış devralması kullanıcı başına rıza gerektirmiyor, yalnızca DNS kontrolü.**

#### 45.4 Gerçek olaylar ve araştırmalar

**Obsidian Security — "From DNS Takeover to Org Admin: Secondary Attacks on Atlassian Cloud"**
Zincir: DNS'i ele geçir → alan adını Atlassian'da doğrula → hesapları talep et (**yönetici hesapları dahil**) → uygulama keşfi → **"Join as Admin"** → **kaldırılmadan sağ çıkan kalıcı org admin.**
İstatistikler: analiz edilen müşteriler arasında **%20'sinin talep edilmemiş org admin'i, %28'inin talep edilmemiş site admin'i var.**
**Birden çok organizasyon aynı alan adını doğrulayabiliyor, bu da talep etmede bir yarış koşulu yaratıyor**; otomatik talep açık olsa bile saldırgan pencerede elle talep edebiliyor.
Öneriler: tüm alan adlarını doğrula, **tüm hesapları talep et (özellikle admin'leri)**, her olaydan sonra DNS'i denetle, ve **`joined-as-org-admin` olaylarına alarm koy** (nadir bir olay olarak tanımlanıyor).
> ⚠️ Yayın tarihi **DOĞRULANMADI.**

**nOAuth** — mekanizma ve zaman çizelgesi için bkz. §13.1. B2B açısından kritik ek: Semperis'in 2025 çalışması **1.017 OIDC entegrasyonunu** inceledi, **Entra App Gallery'den 104 self-signup uygulamasına** odaklandı ve **9'unu (~%9) zafiyetli buldu** — açıklamadan **iki yıl sonra.** MSRC'ye Aralık 2024'te bildirildi; MSRC vakayı **Nisan 2025'te kapattı.**
The Hacker News (25 Haz 2025): Microsoft geliştiricilerin **`sub` + `iss`** üzerinden anahtarlaması gerektiğini yineledi ve **uyumsuz satıcıların Entra App Gallery'den çıkarılma riski** taşıdığını uyardı. Eric Woodruff (Semperis): *"It's **low effort, leaves almost no trace** and bypasses end-user protections."*

**Microsoft'un otoriter claim rehberliği** (birebir):
> *"**Never use claims like `email`, `preferred_username` or `unique_name`** to store or determine whether the user in an access token should have access to data. These claims aren't unique and can be controllable by tenant administrators or sometimes users, which make them **unsuitable for authorization decisions**. They're only usable for display purposes. **Also don't use the `upn` claim for authorization.**"*
> Doğrula: `aud`, `tid`; anahtarla: değişmez **`tid`+`oid`** (veya `sub`).

**⭐ Truffle Security / Dylan Ayrey — "Sign in with Google" + terk edilmiş startup alan adları:**
Zaman çizelgesi: Google'a bildirim **30 Eylül 2024** → Google **2 Ekim 2024'te "Won't fix"** işaretledi → ShmooCon 2025 konuşması **9 Aralık 2024'te** kabul edildi → Google **19 Aralık 2024'te bileti yeniden açtı ve 1.337 $ ödül ödedi.**
Mekanizma: RP'ler `hd` (hosted domain) + `email` üzerinden anahtarlıyor; iflas etmiş bir startup'ın alan adını satın alıp Google Workspace kullanıcılarını yeniden yaratmak o claim'leri **birebir yeniden üretiyor.**
> ⚠️ **Ve değişmez tanımlayıcı olması gereken `sub` claim'i güvenilmez olarak raporlanıyor** — büyük bir sağlayıcının mühendisine göre *"The `sub` claim changes in about **0.04%** of logins"* — bu yüzden RP'ler ondan kaçınıyor. **Bu, `sub`-üzerinden-anahtarla tavsiyesine karşı ciddi ve nadiren dile getirilen bir itirazdır.**
Ölçek: ~%90 startup başarısız oluyor; ~%50'si Google Workspace kullanıyor; **100.000'den fazla iflas etmiş startup alan adı satın alınabilir durumda** (TechCrunch, 19 Ocak 2025: **116.000**); tahminî **>10 milyon potansiyel olarak ele geçirilebilir SaaS hesabı.**
Ayrey'nin adlandırdığı en yüksek etkili hedefler: eski çalışanların **W-2'lerini, sosyal güvenlik numaralarını ve banka yönlendirme numaralarını** açığa çıkaran İK sistemleri; ayrıca Slack, ChatGPT, Zoom, Notion.

**npm expired-domain araştırması (aynı başarısızlık modu, ölçekte)** — NC State / Microsoft ortak çalışması: **2.818 bakımcı hesabı** süresi dolmuş alan adlarındaki e-posta adreslerini kullanıyordu ve **8.494 paketi** kontrol ediyordu (ortalama 2,43 doğrudan bağımlı). Saldırgan alan adını satın alır, posta kutusunu yeniden yaratır, parola sıfırlamayı tetikler, paketlere sahip olur.

> ⚠️ **Dürüstlük notu: "doğrulanmış bir alan adında otomatik katılımın vahşi doğada suistimal edildiği" yayımlanmış, teyit edilmiş bir olay BULUNAMADI.** En yakın gerçek kanıt (a) yukarıdaki Atlassian DNS→talep araştırması ve (b) alan adı yeniden edinme sınıfıdır (Truffle, npm). **Tasarım dokümanında bunu dürüstçe belirt, olay uydurma.**

---

### 46. Sahiplik devri ve son yönetici koruması

#### 46.1 Ürün politikaları

**GitHub:** *"We recommend that at least two people within each organization have the owner role."*
Devir bir **yükselt-sonra-indir/ayrıl** dizisidir; GitHub son sahibin ayrılmasını engeller. Sahipler **kendi rollerini değiştiremez** (`"You can't change your own role."`).
> **Temiz bir invariant: self-servis kendini-yükseltme yok, self-servis son-sahip-çıkışı yok.**
Kendini kaldırmak **faturalandırmayı güncellemez** — faturalandırma/sahiplik ayrışması gerçek bir operasyonel tuzak.

**Vercel:** *"a team can't be left without an Owner"*; iki adımlı (yeni Owner'ı yükselt → eskisini indir/kaldır); Pro **deneme** takımları tek Owner ile sınırlı ve **deneme sırasında owner değişiklikleri engelli.**

**Microsoft Entra ID** (acil erişim dokümanından):
> *"Microsoft Entra ID prevents the last Global Administrator account from being deleted, but **it doesn't prevent the account from being deleted or disabled on-premises**."*
> ⭐ **Önemli nüans: son-yönetici invariant'ı bulut dizininde zorlanıyor ama senkronize edilen doğruluk kaynağı üzerinden yenilebiliyor.**
Ayrıca işaretlenen: tüm Global Admin / Privileged Role Admin atamaları PIM-*eligible* ise, aktivasyon onay gerektiriyorsa ve **onaylayıcı yoksa, tenant yönetimi fiilen kilitlenir.**

**Google Workspace:** Kaybedilmiş tek süper yönetici için kurtarma: kurtarma e-postası/telefonu, yoksa **CNAME (veya TXT) kaydı ekleyerek alan adı doğrulaması**, yoksa destek destekli kurtarma (24 saate kadar yayılma).
Dikkat çekici: *"**If the administrators are inactive and unresponsive, Google will promote your user account**"* — **belgelenmiş bir "DNS-kontrolü-mevcut-yöneticiyi-yener" yükseltme yolu.**

**Stripe:** Sahiplik mevcut bir Super Administrator/Administrator'a devrolur. Connect için: Full Dashboard'da yalnızca mevcut sahip devredebilir; **sahip ulaşılamazsa Stripe Support müdahale etmelidir**; Express Dashboard'da **platform yöneticisi** sahibi değiştirebilir. Stripe hem eski hem yeni sahibin iş bilgilerini ve kimliklerini doğrulamayı ve yeni sahibin yetkilendirmesinin belgelenmesini şart koşuyor.
> **Yargı yetkisine özgü kural örneği:** Brezilya'daki bireysel/şahıs şirketi hesaplarında sahiplik devri **yasak.** *(Türkiye/KVKK muadili kontrol edilmeli.)*

#### 46.2 Argus için tasarım kuralları

| # | Kural | Kaynak |
|---|---|---|
| 1 | **Bir organizasyonun daima ≥1 aktif sahibi olmalı.** **Veri katmanında** zorla (yalnızca UI'da değil) ve **her yolda**: indir, kaldır, ayrıl, hesap-sil, SCIM deprovision, SSO-zorlama süpürmesi, faturalandırma iptali | GitHub + Vercel |
| 2 | **İki taraflı teyit:** devir = teklif + kabul. Alıcı **zaten doğrulanmış, zaten aktif** bir üye olmalı. **Devri asla ayrılan sahibin tek tıkı yapma** | Stripe + GitHub |
| 3 | **Soğuma + bildirim:** teklifte, kabulde ve tamamlanmada *tüm* sahiplere/yöneticilere (ve org'un güvenlik irtibatına) bildir; **geri alma penceresi tut** | Notion'ın 14 günü, Microsoft'un 10 günü |
| 4 | **Kendi rolünü değiştirme yasağı** — bir sahip kendi rolünü değiştiremez; ikinci bir sahip hareket etmeli | GitHub |
| 5 | **Sahipliği faturalandırmadan açıkça ayır** | GitHub belgelenmiş tuzak |
| 6 | **Vefat eden/ayrılan tek sahip:** incelenen her satıcı **bant dışı kimlik kanıtına** düşüyor ve Google ile Microsoft'ta o kanıt **DNS kontrolü.** IdP'nin doğrulanmış alan adları varsa DNS kontrolü zaten en güçlü bant dışı sinyalindir — **kurtarma yolunu bilinçli olarak onun etrafında tasarla ve gürültülü şekilde denetlenebilir yap, çünkü aynı zamanda saldırı yoludur** | Obsidian/Atlassian araştırması |

---

### 47. Break-glass hesap tasarımı

#### 47.1 Microsoft Entra ID — otoriter kontrol listesi

- **Yedeklilik için en az iki acil erişim hesabı.**
- **`.onmicrosoft.com` üzerinde yalnızca-bulut hesaplar** — federe değil, şirket içinden senkronize değil.
- **Phishing-dirençli yöntemler** — **passkey (FIDO2) öneriliyor**, veya PKI varsa sertifika tabanlı auth — ve bunlar **normal admin hesaplarının kullandığı yöntemlerden FARKLI olmalı** (admin'ler Authenticator kullanıyorsa break-glass FIDO2 kullanır).
  > ⭐ **Microsoft'un GÜNCEL rehberliği "MFA'dan muaf tut" DEĞİLDİR** — "zorunlu MFA'yı karşılayan phishing-dirençli bir yöntem kullan ve yalnızca girişi engelleyecek CA politikalarından muaf tut"dur.
- **Credential'lar/cihazlar sona ermemeli** veya atıllık temizliğine takılmamalı.
- **PIM'de Global Administrator'ı kalıcı aktif ata, eligible değil.**
- **Belirlenmiş güvenli iş istasyonu / Privileged Access Workstation.**
- **Credential'ları ayrı konumlarda, ayrı, yangına dayanıklı kasalarda sakla**, yalnızca yetkili kişilerce bilinsin; hiçbir bireysel kullanıcıya veya çalışan-tedarikli cihaza (telefonlara) bağlı olmasın.
- **Girişi engelleyen veya kısıtlayan Conditional Access politikalarından muaf tut** (report-only politikalar muafiyet gerektirmez); adanmış bir grup kullan; **üç ayda bir hâlâ giriş yapabildiklerini test et**; kesinti sırasında etkinleştirilecek **acil durum CA politikaları hazırla.**
- **Tüm giriş ve denetim aktivitesini izle, her kullanımda alarm** — alarm önem derecesi **0 – Kritik.**
- **En az 90 günde bir doğrula**, ayrıca BT personeli değişiklikleri/işten çıkarmalar ve abonelik değişikliklerinden sonra. Tatbikat: SOC'u bilgilendir; yetkili kullanıcı listesini gözden geçir; runbook'un güncel olduğunu teyit et; **hiçbir MFA/SSPR'nin bireyin cihazına veya kişisel bilgilerine kayıtlı olmadığını doğrula**; paylaşılan cihazın **ortak arıza modu olmayan iki yoldan** ağa ulaşabildiğini doğrula; **kasa kombinasyonlarını düzenli olarak ve erişimi olan biri ayrıldığında değiştir.**
- **Post-mortem ekibi:** her alarmdan sonra logları koru ve kullanımı sınıflandır: (a) planlı tatbikat, (b) gerçek acil durum, (c) **suistimal/yetkisiz.**
- **Federasyon rehberliği:** şirket içi acil erişim ile bulut acil erişimi tamamen bağımsız tut — çapraz bağımlılık yok.

**Dokümanın kendi "neden" listesi, kilitlenme nedenlerinin iyi bir sayımı:** federasyon/IdP kesintisi · tüm admin MFA cihazlarının veya MFA servisinin erişilemez olması · son Global Admin'in ayrılması · doğal afet/ağ kesintisi · **PIM tuzağı** (tüm atamalar eligible, onay gerekli, onaylayıcı yok).

#### 47.2 Okta

Break-glass süper admin hesapları **IP allowlist'i**, **fiziksel FIDO2 anahtarı artı makine-üretimi parola** ile MFA kullanmalı ve **her kullanım için yakından izlenmeli.**
Daha geniş admin rehberliği: sıfır duran ayrıcalık / JIT admin erişimi · özel admin rolleri · phishing-dirençli authenticator'lar · güvenilir yönetilen cihazlar · anonimleştirici proxy'leri engelleyen dinamik ağ bölgeleri · **Admin Console oturumu varsayılan 12 saat ömür, 15 dakika idle timeout** · **ASN Session Binding varsayılan açık** (ağ değişirse oturumu iptal eder) · opsiyonel IP Session Binding · kritik değişiklikler için yeniden kimlik doğrulama gerektiren **Protected Actions.**
Okta'nın admin dayanıklılığı önerisi: admin'lere Admin Console için **birden çok yedekli authenticator** ver.

#### 47.3 CISA / CIS

**CISA SCuBA:** Değerlendirme araçları (**ScubaGear** M365 için, **ScubaGoggles** Google Workspace için) **break-glass hesaplarını politika muafiyeti olarak açıkça saymanı gerektiriyor** — yani **break-glass muafiyetleri örtük değil, beyan edilmiş ve denetlenebilir olmalı.**

**CIS Microsoft 365 Foundations Benchmark, kontrol 1.1.2 "Ensure two emergency access accounts have been defined"** (v3.0.0 ve v4.0.0, Level 1) — **"iki break-glass hesabı" için en temiz atıf verilebilir uyum gereksinimi.**

> ⚠️ **NCSC'nin break-glass/acil yönetici hesaplarına özgü bir sayfası bulunamadı.** Doğrulanan en yakın NCSC materyali *Secure system administration* koleksiyonudur (Prensip 4: *"Carefully control who, where, when, why and how people perform system administration"*; *"someone, somewhere will have absolute control over your system"*). **Daha spesifik bir NCSC break-glass önerisi DOĞRULANMADI — atıf verme.**

#### 47.4 AWS root — quorum/split-knowledge fikrinin en zengin kaynağı

- **MFA zorunlu**: standalone, management ve member hesaplarının hepsi root MFA gerektiriyor; ilk konsol giriş denemesinden **35 gün** içinde kayıt. **Sekize kadar MFA cihazı** kaydedilebiliyor — dayanıklılık için birkaçını kaydet.
- **Asla root erişim anahtarı oluşturma**; programatik root kullanımı için `aws login` (geçici, otomatik döndürülen credential'lar).
- **⭐ Çok kişili onay (birebir):** *"Consider using **multi-person approval** to make sure that **no one person can access both MFA and password** for the root user. Some companies… set up **one group of administrators with access to the password, and another group with access to MFA**. One member from each group must come together to sign in as the root user."*
- **Grup e-posta adresi** root için, işletmece yönetilen, bir gruba yönlendiren, **başka hiçbir şey için kullanılmayan.**
- **⭐ Kurtarma ayrımı (birebir):** *"**No one person should have access to both the email inbox and phone number** since both are verification channels to recover your root user password."*
- **Root parolasını, kendisi o hesaba bağımlı olan bir araçta saklama.** (dairesel bağımlılık tuzağı)
- **Organizations:** root erişimini merkezî yönet ve member hesaplardan **root credential'larını tamamen kaldır**; root-yalnızca eylemler dışında root eylemlerini reddeden bir SCP kullan.
- **İzleme:** root girişi ve kullanımında alarm; CloudTrail root girişini ayrıcalıklı root oturumundan `sts:AssumeRoot` ile ayırıyor. **Alarm için belgelenmiş bir müdahale prosedürü olsun, sadece alarm değil.**

#### 47.5 Temel gerilim ve kaynakların çözümü

Gerilim gerçek: break-glass hesabı **en yüksek ayrıcalıklı kimliktir ve her şeyi koruyan kontrollerden kasten muaf tutulur.** Kaynakların yakınsadığı çözüm **muafiyet değil, ikame güç + quorum + tespit + tatbikattır:**

1. **Faktörü kaldırma, daha güçlüsünü ikame et** — Microsoft artık FIDO2/CBA reçete ediyor ve yalnızca *engelleyici CA politikalarından* muaf tutuyor; Okta fiziksel FIDO2 + makine-üretimi parola + IP allowlist reçete ediyor.
2. **Bağımlılıkları çeşitlendir** — normal admin'lerden farklı auth yöntemi; yalnızca-bulut, federasyon yok, şirket içi yok, kişisel telefon yok, tek ağ yolu yok.
3. **Quorum / bölünmüş bilgi** — AWS'in iki-grup parola/MFA ayrımı; ayrı konumlarda ayrı yangına dayanıklı kasalar.
4. **Tespit, önlemenin yerini alır** — *her* girişte Önem-0 alarmı, her kullanımı tatbikat/acil durum/suistimal olarak sınıflandıran zorunlu post-mortem.
5. **Zaman kutulama ve tatbikat** — 90 günlük doğrulama tatbikatları, üç aylık CA-muafiyeti testleri, personel ayrılışında kasa kombinasyonu rotasyonu.
6. **Beyan edilmiş muafiyetler** — CISA SCuBA break-glass muafiyetlerini değerlendirme yapılandırmasında saymaya zorluyor, **böylece muafiyetin kendisi denetlenebilir oluyor.**

> ### ⭐ Ödünç alınmaya değer ürün seviyesi analog: Stytch'in `is_breakglass` Member bayrağı
> `is_breakglass: true` olan bir üye, organizasyonun `RESTRICTED` `auth_methods` ve `mfa_methods` ayarlarını atlar. **Bayrağı ayarlamanın kendisi yetkilendirilmiş bir eylemdir** (`stytch.member` kaynağında `update.settings.is-breakglass`).
> **Bu, bir B2B IdP'sinde *break-glass'ın birinci sınıf, izinli, denetlenebilir bir nesne* olmasının en temiz mevcut örneğidir ve Argus için güçlü bir referanstır.**

> ⚠️ **Break-glass credential'larının adı geçen bir kamu ihlalinde suistimal edildiğine dair DOĞRULANMIŞ bir olay BULUNAMADI. İddia etme.** Sık dolaşan "2020 Microsoft/Okta kilitlenme hikâyeleri" ve "Entra ID sertifika-süresi kilitlenmesi" için birincil kaynak bulunamadı — **ya çıkar ya da açıkça teyit edilmemiş olarak etiketle.**

---

### 48. Org seviyesi SSO zorlaması, SSO atlatma ve SAMLjacking

#### 48.1 Artık-parola problemi

Obsidian'ın araştırmasından temel risk ifadesi: **SaaS uygulamalarının %90'ından fazlasında** organizasyonun SSO yapılandırması kullanıcı adı/parola girişinin **yanında opsiyoneldir** ve birçok uygulamada *SSO'nun opsiyonel mi zorunlu mu olduğu global değil kullanıcı başına yapılandırılır.*
> *"If an application allows a user to sign in with a local password while bypassing corporate SSO, **that application is a hole in your perimeter**."*
> ⚠️ %90 rakamı Obsidian'ın kendi araştırmasıdır; bağımsız istatistik değil.

**GitHub:**
> *"Enforcement **removes any members and administrators who have not authenticated via your IdP** from the organization. GitHub sends an email notification to each removed user."*
Kaldırılan üyeler **üç ay içinde** yeniden katılabilir ve erişimleri geri gelir.
> ⚠️ **IdP'de dış kimliği olmayan bot'lar ve servis hesapları da kaldırılır — klasik zorlama-günü kesintisi.**
GitHub zorlamadan önce kimlerin kaldırılacağını listeleyen bir uyarı gösteriyor ve açık teyit istiyor.
> ⚠️ **Zorlamanın bekleyen davetlere ve mevcut PAT'lere/SSH anahtarlarına ne yaptığı o dokümanda BELİRTİLMİYOR — DOĞRULANMADI.** Ama gerçek bir tarihsel atlatma var: GitHub **15 Eylül 2022'de** (changelog 2 Kasım 2022) **SAML SSO için yetkilendirilmemiş** OAuth/kişisel erişim token'larının SAML korumalı org'lardan `/issues` API'si üzerinden issue verisi (başlık, gövde, etiket, atanan) okuyabildiği bir hatayı düzeltti.
GitHub Enterprise Server'da şifreli assertion'larla uygunsuz kriptografik imza doğrulaması yoluyla SAML kimlik doğrulama atlatması: **CVE-2024-4985 / CVE-2024-9487.**

**Stytch** zorlamayı org ayarları olarak modelliyor: `auth_methods` `ALL_ALLOWED` vs `RESTRICTED` + `allowed_auth_methods` (`sso`, `magic_link`, `email_otp`, `password`, `google_oauth`, `microsoft_oauth`, …), ve `mfa_policy` `REQUIRED_FOR_ALL` / `OPTIONAL`. **`allowed_auth_methods: ["sso"]` org geneli SSO zorlamasıdır ve `is_breakglass` belgelenmiş, izinli istisnadır.**

**Auth0 Organizations** SSO'yu **organizasyon için hangi bağlantıların etkin olduğunu** kontrol ederek zorluyor. Bilinmesi gereken sınırlamalar: **yalnızca Universal Login**; Resource Owner Password, Device Authorization Flow veya WS-Fed ile desteklenmiyor; **organizasyon başına özel giriş alan adı yok.**

**WorkOS** **organizasyon ID'si** üzerinden yönlendiriyor ve e-posta-alan-adı tabanlı doğrulamanın güvensiz olduğunu açıkça uyarıyor; SSO authorization code'u **10 dakika** geçerli.

> **Belirtilmesi gereken tasarım invariant'ları:**
> - Zorlama **organizasyon seviyesinde** bir özellik olmalı, kullanıcı başına değil
> - **Mevcut credential'ları süpürmeli** (parolalar, API token'ları, SSH anahtarları, uzun ömürlü oturumlar, OAuth grant'ları), yalnızca gelecekteki girişleri değil
> - **Açık, izinli, alarmlı bir break-glass istisnası** olmalı (Stytch modeli)
> - **Zorlama anında bekleyen davetlere ne olacağını tanımlamalı** — GitHub'ın dokümanı bunu belirsiz bırakıyor; **Argus'unki bırakmamalı**

#### 48.2 ⭐ SAMLjacking ve zehirli tenant

**Push Security, 17 Ağustos 2023:**
- **SAMLjacking:** Bir SaaS tenant'ını kontrol eden saldırgan, o tenant'ın SAML SSO ayarlarını **saldırgan kontrollü bir IdP'yi** gösterecek şekilde ayarlar. O tenant üzerinden giriş yapan kullanıcılar **meşru bir SaaS URL'inden**, tam da credential girmeyi bekledikleri anda bir phishing sayfasına yönlendirilir.
- **Zehirli tenant:** Saldırgan gerçek bir SaaS ürününde hedef şirketin adıyla bir tenant kaydeder ve **ürünün kendi davet işlevini kullanarak** çalışanlara meşru görünen davetler yollar — *"the Nuclino app will send out **legit email invitations on your behalf**."*
- **Birçok SaaS ürünü ücretsiz denemelerde ve düşük katmanlarda bile özel SAML'a izin veriyor**, kombinasyonu ucuz kılan da bu.

**⭐ Vahşi doğada canlı örnek — Push Security, "Investigating a novel OpenAI poisoned tenant attack", 26 Haziran 2026:**
Push çalışanları, **OpenAI'nin meşru bildirim adresinden**, kimlik doğrulama kontrollerini geçen, **"Push Security Inc." adlı** bir organizasyona katılma davetleri aldı. Saldırganın hesabı **Push'un CEO'sunun adını** kullanıyordu, faturalandırmaya çalınmış bir Visa kartı ekliydi ve belirli çalışanları hedefliyordu.
> **Kabul, ek credential olmadan tek bir tık gerektiriyordu ve davet edilen çalışanlara sahte organizasyonda *owner seviyesinde yönetici erişimi* veriliyordu.**
OpenAI'nin ürünü davet eden ile alıcı arasındaki alan adı uyuşmazlığı için bir uyarı gösteriyordu — **tek satırlık bir metin** — ki araştırmacılar bunu yetersiz buldu.

> ### Davet akışı için doğrudan tasarım sonuçları
> **(a)** Davet edenin doğrulanmış alan adı davet edilenden farklıysa **güçlü, kaçırılamaz bir ara sayfa** göster
> **(b)** İlişkisiz bir kullanıcının **ilk kabulünde asla owner/admin verme**
> **(c)** Tenant-oluşturma + toplu-davet örüntülerini **rate-limit'le ve itibar kontrolünden geçir**
> **(d)** **Kendi işlemsel davet postanı saldırgan kontrollü bir phishing kanalı say** ve saldırganın sağladığı alanları (org adı, davet eden görünen adı, özel mesaj) buna göre kısıtla

#### 48.3 SCIM × organizasyon davetleri

> **JIT/otomatik-oluşturma ile SCIM'i aynı anda çalıştırma.** OpenAI'nin SCIM SSS'i Automatic Account Creation ile SCIM'in birlikte etkinleştirilmemesini öneriyor, çünkü bu *"may result in provisioning access to **unmanaged users**."*

**Yinelenen/paralel kayıtlar:** **Kararlı, paylaşılan bir tanımlayıcı olmadan** JIT artı SCIM push, paralel kullanıcı kayıtları üretir → yetkilendirme çakışmaları ve bozuk denetim izleri. SCIM create'te `409 Conflict` genelde bir yinelenen-kullanıcı problemidir; **IdP kayıt ID'leri gönderirken e-postayı SCIM `id`'si olarak kullanmak update/delete'te 404'lere yol açar.**

**SCIM-oluşturulmuş kullanıcılar ve davet e-postası:** Bazı ürünler, henüz workspace üyesi olmayan bir kullanıcıyı SCIM sağladığında hâlâ davet e-postası gönderiyor. **SCIM ve davetler birbirini dışlayan yollar değildir ve ikisi de *aynı* üyelik kaydında birleşmelidir.**

**Deprovisioning eksiksiz olmalı:** UI girişini devre dışı bırakmak yetmez — **API token'larını, oturumları ve gruptan türeyen izinleri iptal et.** Birçok platform denetim loglarını korumak için soft-delete yapıyor; **soft-delete'in canlı bir kimlik doğrulama yolu bırakmadığından emin ol.**

> **Belirtilecek tasarım kuralları:**
> 1. **SCIM etkinken üyelik için otoriterdir** → o org için davetler devre dışı bırakılmalı veya "erişim talebi"ne indirgenmeli
> 2. Her üyelik kaydı **`{external_id, source: invite|scim|jit|domain_autojoin}`** taşımalı ki köken denetlenebilir olsun
> 3. Gelen bir SCIM kullanıcısını mevcut davet-edilmiş-ama-kabul-edilmemiş bir kayıtla eşleştirmek **doğrulanmış bir tanımlayıcı** üzerinden olmalı — **asla doğrulanmamış ikincil e-posta üzerinden (GitLab #356665 dersi burada birebir geçerli)**
> 4. **SCIM deprovision, o kişi için bekleyen davetleri de iptal etmeli**

---

### 49. Bölüm VII için Argus kararları

```rust
struct Invitation {
    id: Uuid,
    org_id: Uuid,
    token_hash: [u8; 32],              // SHA-256; ham token yalnızca URL'de
    invited_email_normalized: String,  // NFKC + küçük harf (GitLab #321324)
    binding_mode: BindingMode,         // Exact | VerifiedCorporateDomain
    role: RoleId,                      // KABUL ANINDA BURADAN OKUNUR, istekten DEĞİL
    inviter_id: Uuid,
    expires_at: DateTime,              // varsayılan 7g, max 30g
    consumed_at: Option<DateTime>,     // unique constraint altında tek kullanım
    revoked_at: Option<DateTime>,
    scanner_clicks: u16,               // Stytch: tarayıcı tıklaması tüketmez
}

struct Membership {
    id: Uuid, org_id: Uuid, principal_id: Uuid,
    role: RoleId,
    source: MembershipSource,          // Invite | Scim | Jit | DomainAutojoin
    external_id: Option<String>,       // SCIM birleştirme anahtarı
    is_breakglass: bool,               // Stytch modeli — ayarlaması İZİNLİ bir eylem
}

struct VerifiedDomain {
    org_id: Uuid, domain: String,
    method: DnsTxt | HttpsFile | IdpConnection,
    verified_at: DateTime,
    reverify_after: DateTime,          // doğrulama KALICI DEĞİLDİR
    autojoin: AutojoinPolicy,          // Disabled | RequestAccess | Auto
    is_consumer_domain: bool,          // gmail/hotmail/yandex.com.tr/mynet/ISP/üniversite
}
```

| # | Karar | Kaynak |
|---|---|---|
| 1 | Davet = **opak token, DB satırı, SHA-256 hash'li**; JWT değil | Tüm satıcılar + iptal argümanı |
| 2 | **Rol satırdan okunur**, istekten asla | Dropbox, Budibase CVE-2026-25040 |
| 3 | Kabul anında **rol atama yetkisi yeniden kontrol edilir** (davet oluşturmada da) | Budibase: API izni doğrulamıyordu |
| 4 | Davet edilen adres **NFKC + küçük harf normalize** edilir | GitLab #321324/#338022 |
| 5 | Kabul, **yalnızca doğrulanmış** bir tanımlayıcıyla eşleşir — **doğrulanmamış ikincil e-posta asla** | **GitLab #356665** |
| 6 | `binding_mode`: tüketici alan adları **tam eşleşme**; kurumsal gevşetme **yalnızca alan adı doğrulanmışsa** | WorkOS |
| 7 | Kabul adımı **atlanamaz** — kimse rızası olmadan org'a eklenemez | Slack #1663361 |
| 8 | Kabul sayfası `Referrer-Policy: no-referrer`; **magic code fallback'i** sunulur | OWASP; Frontegg |
| 9 | **Tarayıcı tıklaması token'ı tüketmez** (cihaz sinyali ile) | Stytch Protected EML |
| 10 | **Davet eden ve edilenin doğrulanmış alan adları farklıysa güçlü ara sayfa**; ilk kabulde **asla owner/admin verilmez** | **OpenAI zehirli tenant, Haz 2026** |
| 11 | Tenant-oluşturma + toplu-davet örüntüsü rate-limit ve itibar kontrolüne tabi; **org adı/davet eden adı/özel mesaj saldırgan girdisi sayılır** | Aynı |
| 12 | **Org daima ≥1 aktif sahip** — veri katmanında, **her yolda** (SCIM deprovision ve SSO süpürmesi dahil) | GitHub, Vercel, Entra'nın on-prem boşluğu |
| 13 | **Kendi rolünü değiştirme yasak**; devir = teklif + kabul + soğuma + tüm sahiplere bildirim | GitHub, Stripe, Notion 14g |
| 14 | Alan adı doğrulaması **kalıcı değil** — `reverify_after` zorunlu; MX/kayıt değişimi yeniden doğrulama tetikler | Truffle, npm, Atlassian önerisi |
| 15 | **Aynı alan adını birden çok org doğrulayabilirse yarış koşulu var** — talep etme kilitli ve alarmlı | Obsidian/Atlassian |
| 16 | Tüketici + Türkiye ulusal ücretsiz posta + **ISP/üniversite** alan adları `is_consumer_domain` işaretli; otomatik katılım **yasak** | Atlassian, Stytch, TR pazarı |
| 17 | **Autojoin varsayılanı `Disabled`**; `RequestAccess` ara seçenek | Notion'ın kendi tavsiyesi |
| 18 | `is_breakglass` **birinci sınıf, izinli, alarmlı** bir alan; her kullanımda Önem-0 alarmı + zorunlu post-mortem sınıflandırması | **Stytch + Microsoft + CISA SCuBA** |
| 19 | **En az iki break-glass hesabı**; normal admin'lerden **farklı** phishing-dirençli yöntem; muafiyet yalnızca engelleyici politikalardan | Microsoft; CIS M365 1.1.2 |
| 20 | **Quorum seçeneği**: parola ve MFA farklı gruplarda | AWS root çok-kişili onay |
| 21 | SSO zorlaması **org seviyesinde**; **mevcut parolaları, API token'larını, oturumları, OAuth grant'larını süpürür**; **bekleyen davetlere ne olduğu açıkça tanımlı** | GitHub'ın belirsizliği |
| 22 | Zorlama öncesi **kimlerin kaldırılacağını gösteren önizleme** (servis hesapları dahil) | GitHub zorlama-günü kesintisi |
| 23 | SCIM etkinken **üyelik için otoriter**; davetler devre dışı veya "erişim talebi" | OpenAI SCIM SSS |
| 24 | Her üyelik `source` taşır; **SCIM deprovision bekleyen davetleri de iptal eder** | Denetlenebilirlik |
| 25 | Yetkilendirme **asla `email`/`preferred_username`/`upn` üzerinden**; org yönlendirmesi **org ID** üzerinden, e-posta alan adı üzerinden değil | Microsoft claims-validation; WorkOS |

> **Son not — `sub` hakkında dürüstlük:** Truffle Security araştırması, büyük bir sağlayıcının mühendisinden *"The `sub` claim changes in about **0.04%** of logins"* ifadesini aktarıyor. Bu, bu dokümanın her yerinde verilen "`(iss, sub)` üzerinden anahtarla" tavsiyesine karşı **gerçek bir itirazdır** ve şu şekilde ele alınmalıdır: `(iss, sub)` **birincil** anahtar olarak kalır, ama **`sub` değişimi tespit edildiğinde sessizce yeni hesap yaratmak yerine bir çakışma olayı üretilmeli** ve doğrulanmış e-posta + kullanıcı teyidiyle çözülmelidir. Sessiz yeni-hesap yaratma, kullanıcı için erişim kaybı; sessiz birleştirme ise §11'deki her saldırıdır.
