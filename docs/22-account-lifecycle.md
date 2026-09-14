# §22 — Hesap yaşam döngüsü

Bu bölüm `ARGUS.md` dosyasının 22. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§22 §X` referansları aynı anlamdadır.

Kapsamı hesap kurtarma, hesap bağlama ile birleştirme, kimliğe bürünme, kullanıcı yaşam döngüsü, kimlik sağlayıcı göçü, kayıt ile katılım güvenliği ile işletmeler arası organizasyon akışlarıdır.

Bu dokümanın neden gerektiği şudur: protokol, kripto, yüksek erişilebilirlik ile yetkilendirme standartlaşmıştır; şartname okunur ile uygulanır. Bu dosyadaki yedi akışın hiçbiri standart değildir. Her ürün kendi tasarımını yapmakta, tasarım hataları ürüne özgü olmakta ile saldırganların 2026'da fiilen kullandığı yüzey burası olmaktadır.

Yöntem şudur: NIST SP 800-63B-4 ile FIDO Alliance dokümanları ham metin olarak indirilip bölüm bölüm okunmuştur; özet aracıyla yetinilmemiştir, çünkü bir vakada özet aracı uydurma bir alıntı üretmiş ile PDF doğrudan çözülerek düzeltilmiştir. Güvenlik açıkları, satıcı dokümanları ile olay raporları birincil kaynaklardan doğrulanmıştır.

Bir doğrulama notu gerekmektedir: her iddia bir birincil kaynağa dayanmaktadır. Doğrulanamayan noktalar satır içinde işaretlenmiştir. Rakam, tarih ya da adres uydurulmamıştır.

---

### İçindekiler

| Bölüm | Konu | Kısımlar |
|---|---|---|
| I | Hesap kurtarma: NIST SP 800-63B-4 4.2, dört kurtarma sınıfı, güvence seviyesi matrisi, soğuma süresi ile Scattered Spider | 1 ile 10 |
| II | Hesap bağlama ile birleştirme: ön ele geçirmenin beş varyantı, doğrulanmış e-posta iddiasının yetersizliği, nOAuth, tanımlayıcı geri dönüşümü ile birleştirmenin geri alınamazlığı | 11 ile 16 |
| III | Kimliğe bürünme: RFC 8693 devretme ile kimliğe bürünme ayrımı, eylemde bulunan ile eylemde bulunabilir iddiaları, on ürünün karşılaştırması ile Twitter 2020 | 17 ile 21 |
| IV | Kullanıcı yaşam döngüsü, silme ile mezar taşı: SCIM'in boşlukları, RFC 9967, kripto parçalama, GDPR 17. madde ile KVKK yedinci madde, atıl hesaplar ile taşınabilirlik | 22 ile 29 |
| V | Kayıt ile katılım güvenliği: NIST 63A sahtekârlık programı, CAPTCHA'nın ölümü, Privacy Pass, tek kullanımlık e-posta ile numaralandırma | 30 ile 35 |
| VI | Kimlik sağlayıcı göçü: ürün ürün özet dışa ile içe aktarımı, tembel göç, format uyumluluğu ile göç edilemeyenler | 36 ile 43 |
| VII | İşletmeler arası organizasyon akışları: davet güvenliği, alan adı doğrulaması, sahiplik devri, acil durum erişimi, çoklu oturum açma zorlaması ile SAML ele geçirme | 44 ile 49 |

Her bölüm bir Argus kararları tablosuyla bitmektedir. Bu tablolar mimari karar dokümanının ham girdisidir.

---

### 0. Yönetici özeti: on iki bulgu

1. NIST SP 800-63B-4'ün 4.2 bölümü hesap kurtarmayı tamamen yeniden yazmıştır. Dördüncü revizyonun değişiklik kaydı bunu açıkça söylemektedir: *"Section 4.2: Revises the requirements and methods for account recovery."* Artık dört kurtarma sınıfı, güvence seviyesine göre normatif kombinasyon kuralları ile kurtarma kodları için mutlak yaşam süresi tavanları vardır. Üçüncü revizyona göre tasarlanmış her kimlik sağlayıcı bu bölümde geride kalmıştır.

2. İkinci güvence seviyesinde kurtarma için NIST tek bir kanıt kabul etmemektedir. Ya farklı sınıflardan iki kurtarma kodu, ya bir kurtarma kodu artı hesaba bağlı bir kimlik doğrulayıcı, ya da kimlik tespitinin tekrarı gerekmektedir. Yaygın ürün davranışı olan e-postaya bağlantı gönder ile parolayı sıfırla, tek başına ikinci seviye kurtarma değildir.

3. Kurtarmanın korunan şeyden zayıf olamayacağı ilkesinin birincil kaynağı FIDO Alliance'tır ile 2019'dan beri yazılıdır: *"Implementing weaker account-recovery options is not recommended by the FIDO Alliance."* 2025 beyaz kâğıdı bunu sertleştirmiştir: *"The prohibition of phishable methods applies to both login and account recovery processes."*

4. Netcraft'ın 7 Nisan 2026 tarihli öngörüsü doğrulanmış ile kaynağı bulunmuştur. Yazı gerçektir, yazarı Ginny Spicer'dır ile dört istismar yolunu FIDO'nun Mart 2025 beyaz kâğıdının 2.1 ile 2.4 bölümlerinden almaktadır. Ana cümlesi şudur: *"This method is likely to become the most used of those highlighted by the FIDO Alliance."*

5. NIST, senkron geçiş anahtarlarının kurtarma zafiyetini kendi metninde kabul etmektedir: *"Synced keys are accessible via cloud-based account recovery processes, which represent a potential weakness to the authenticators."* Yani geçiş anahtarının gücü, platform hesabının kurtarma akışının gücüyle sınırlıdır ile o akış sizin kontrolünüzde değildir.

6. Soğuma süresinin amacı gecikme değil bir itiraz penceresidir. Google bunu açıkça yazmaktadır: gecikme boyunca kullanıcı bilgilendirilmektedir, böylece başka biri hesaba erişmeye çalışıyorsa isteği reddetmek için zaman bulunmaktadır. Ters orantı kuralı da vardır: hesabın koruması arttıkça gecikme uzamaktadır.

7. Apple, zayıf yolu kapat düğmesini ürünleştirmiş tek büyük sağlayıcıdır. Kurtarma anahtarı açıldığında Apple'ın standart hesap kurtarma süreci kapatılmakta ile anahtar kaybedilirse hesaba kalıcı olarak erişim kaybedilmektedir. Bu, ilkenin en saf ticari uygulamasıdır: kullanıcıya kalıcı kayıt riski açıkça satılmaktadır.

8. Keycloak aynı sınıf kurtarma hatasını altı yıl arayla iki kez yapmıştır. CVE-2020-1718 ile CVE-2026-18963, ki ikincisi CVSS 9.1 puanlı ile 24 Ağustos 2026 tarihlidir; ikisi de kimlik bilgisi sıfırlama akışında kimlik doğrulama atlatmasıdır. İkincisinde saldırgana gereken tek şey bir kullanıcı adıdır; sonuç yönetici dahil her hesabın ele geçirilmesidir.

9. Daha derin ders açık duran bir konuda yatmaktadır: Keycloak'ın 40744 numaralı konusu, kullanıcı seçme sağlayıcısının kullanıcıyı doğrulamadan önce kimlik doğrulama bağlamına bağladığını göstermektedir. Akıştan bir adım silmek bir kimlik doğrulama atlatması üretmektedir. Kurtarmayı silinebilir adımlardan oluşan genel amaçlı takılabilir bir akış yapmak, yanlış yapılandırmayı bir güvenlik açığına çeviren mimari bir seçimdir. Argus'un en net ayrışma noktalarından biri budur.

10. Unit 42'nin 3 Ağustos 2026 tarihli çalışması kurtarma akışını bir saldırı ilkeli olarak göstermiştir. Altın geçiş anahtarı saldırısı, geçiş anahtarı durum dosyalarını silerek cihazı yeniden katılıma zorlamakta ile o pencerede ana anahtarı çıkarmaktadır. Kimlik sağlayıcı tarafındaki azaltım listesinin birinci maddesi şudur: kurtarma ile katılım akışlarının gereksiz yere yeniden tetiklenmesi tespit edilmeli ile kısıtlanmalıdır.

11. Kurtarma bildirimlerinde NIST'in unutulan bir kuralı vardır: kurtarma kodunun gönderildiği adres hesaptaki tek diğer bildirim adresiyse, bildirim posta adresine gitmek zorundadır. Mantık genellenebilirdir: kurtarma kanalı, kurtarma bildiriminin kanalı olamaz. Çoğu ürün bunu ihlal etmektedir.

12. Parola sıfırlama hesap kurtarma değildir. NIST bunu normatif olarak ayırmaktadır: kullanıcı hâlâ başka bir kimlik doğrulayıcıyla doğrulanabiliyorsa, unutulan parolanın değişimi yeni bir kimlik doğrulayıcı bağlamaktır, kurtarma değildir. Bu ayrım veri modeline girmezse iki farklı risk profili tek akışta birleşmektedir; Keycloak'ın hatası tam olarak buydu.

---

## Bölüm I — Hesap kurtarma

### 1. Kurtarmanın neden geçiş anahtarı mimarisinin gerçek zayıf halkası olduğu

Geçiş anahtarının kriptografisi kırılmamaktadır. Kırılan, geçiş anahtarının etrafındaki akışlardır. FIDO Alliance'ın Mart 2025 beyaz kâğıdı bunu doğrudan söylemektedir.

> *"Note that the root cause of these attacks is not passkeys themselves, but rather issues with passkey deployments."*
> FIDO Alliance, *Passkeys: The Journey to Prevent Phishing Attacks*, ikinci kısım, Mart 2025

Aynı doküman ikinci bölümünde geçiş anahtarı dağıtılmış bağlı taraflarda dört zafiyet başlığı saymaktadır.

| Sıra | Başlık | Mekanizma |
|---|---|---|
| 2.1 | Parolaların geçiş anahtarı kimlik doğrulamasını atlatma zafiyeti olması | Parola alternatif bir giriş yolu olarak durmaktadır ile saldırgan geçiş anahtarına hiç dokunmamaktadır |
| 2.2 | Ele geçirilmiş hesaplarda yetkisiz geçiş anahtarı kaydı | Geçiş anahtarı kaydı yalnızca parolayla yapılabilmekte ile saldırgan kimlik avıyla parolayı alıp kendi anahtarını kaydetmektedir |
| 2.3 | Kurtarma mekanizmalarını istismar ederek kimlik doğrulamayı atlatma | Kurtarma e-posta ya da kısa mesaj tek kullanımlık şifresine dayanmakta ile saldırgan birincil akışı hiç denememektedir |
| 2.4 | Sosyal mühendislikle hesap güvenlik seviyesini düşürme | Kullanıcıya geçiş anahtarını kapattırmaktır |

İkinci madde üzerine kritik bir not gerekmektedir: bu, geçiş anahtarı ekledik ile artık kimlik avına dirençliyiz diyen ürünlerin en sık yaptığı hatadır. FIDO'nun tarifi şudur: saldırgan önce kimlik avıyla parolayı alıp ilk erişimi sağlamakta, sonra yüksek riskli işlemler için konulmuş korumayı aşmak üzere kendi geçiş anahtarını kaydetmektedir. Geçiş anahtarı artık saldırganın elindedir ile kalıcıdır; parolayı değiştirmek onu düşürmemektedir.

#### 1.1 Netcraft öngörüsü, doğrulanmıştır

Sorulan Netcraft öngörüsü gerçektir.

| Alan | Değer |
|---|---|
| Başlık | *Phishing After Passkeys: What Attacks to Expect* |
| Yayın | 7 Nisan 2026 |
| Yazar | Ginny Spicer |
| Adres | www.netcraft.com/blog/phishing-after-passkeys-what-attacks-to-expect |

Ana cümle, hesap kurtarma başlığı altında şudur.

> *"This method is likely to become the most used of those highlighted by the FIDO Alliance for exploitation of systems that allow passkeys but haven't completely outgrown passwords yet."*

Dayanağı şudur: Netcraft dört yolu kendisi türetmemekte, FIDO Alliance'ın Mart 2025 beyaz kâğıdının 2.1 ile 2.4 bölümlerini referans almakta ile içlerinden kurtarmayı en olası olarak işaretlemektedir. Düşürme saldırısı için açıkça diğerlerine kıyasla daha az olası bir seçenek demektedir. Yazının veri tabanı şudur: 2025'in ikinci çeyreği itibarıyla masaüstü cihazların %98'i ile mobilin %95'i geçiş anahtarını desteklemektedir; yani kapsama sorunu bitmiş ile geriye yedek yol ile kurtarma kalmıştır.

Argümanın yapısı şudur: geçiş anahtarı benimsemesi arttıkça saldırganın birincil akışa saldırma getirisi düşmekte, kurtarma akışına saldırma getirisi sabit kalmaktadır. Oran değişince trafik oraya kaymaktadır. Bu bir tahmin değil bir ekonomik zorunluluktur.

#### 1.2 NIST'in senkron geçiş anahtarı itirafı

NIST SP 800-63B-4'ün senkronize edilebilir kimlik doğrulayıcılar eki, senkron geçiş anahtarlarının zayıflığını doğrudan yazmaktadır.

> *"Synced keys are accessible via cloud-based account recovery processes, which represent a potential weakness to the authenticators."*

İptalin çözülmemiş olduğunu da yazmaktadır.

> *"Since syncable authenticators use RP-specific keys, the ability to centrally revoke access based on those keys is challenging. For example, with traditional PKI, CRLs can be used centrally to revoke access. A similar process is not available for syncable authenticators or any FIDO WebAuthn-based credentials."*

Sonuç şudur: senkron geçiş anahtarını kabul eden bir bağlı taraf, güvenliğini platform hesabının kurtarma akışına devretmiştir. Apple kimliği ya da Google hesabı kurtarılabiliyorsa o hesaptaki tüm geçiş anahtarları kurtarılabilmektedir. Bu sizin kontrolünüzde değildir ile bu yüzden bağlı taraf kendi bağımsız kurtarma politikasını korumak zorundadır.

NIST'in ekteki azaltım listesi, senkronizasyon dokusu ile kurtarma başlığı altında, şunlardır.

- *"Implement authentication recovery processes that are consistent with SP 800-63B."*
- *"Bind multiple authenticators at AAL2 and above to support recovery."*
- *"Require AAL2 authentication to add any new authenticators for user access to the sync fabric."*
- *"Notify the user of any recovery activities."*
- *"Leverage a user-controlled secret (i.e., something not known to the sync fabric provider) to encrypt and recover keys."*

Son madde Apple'ın gelişmiş veri korumasının tam olarak yaptığı şeydir.

#### 1.3 Unit 42: kurtarma akışı bir saldırı ilkelidir

Arie Olshtein'ın Palo Alto Networks Unit 42 için yazdığı 3 Ağustos 2026 tarihli geçiş anahtarını aktarma çalışması unit42.paloaltonetworks.com/passwordless-authentication-security-risks adresindedir.

Hedefi Google senkron geçiş anahtarı ekosistemi ile Windows ve güvenilir platform modülüdür. Üç saldırı anlatılmaktadır.

| Saldırı | Mekanizma | Sonuç |
|---|---|---|
| Anahtarı aktarma | Yetkisiz kötü amaçlı yazılım Chrome'un sarmalanmış kimlik anahtarını diskten almakta ile Windows kripto API'leriyle meydan okumayı imzalamaktadır | Kullanıcı etkileşimi ya da cihaz kilidini açma olmadan cihazı bulut kimlik doğrulayıcısına karşı taklit etmektedir |
| Gümüş varyant | Geçiş anahtarı durum dosyalarını silmekte, cihazı yeniden katılıma zorlamakta ile bekleyen kullanıcı doğrulama anahtarı fazında saldırgan kontrollü bir doğrulama anahtarı kaydetmektedir | Kullanıcı doğrulaması zorunlu olsa bile tam hesap ele geçirmedir |
| Altın varyant | Yeniden katılıma zorlamakta ile Chrome süreç belleğinden güvenlik alanı sırrını çıkarmaktadır | Tüm senkron geçiş anahtarı özel anahtarları çevrimdışı çözülebilmektedir |

Argus için ders şudur: gümüş ile altın saldırıların ikisi de aynı ilkele dayanmaktadır, yani saldırgan kurtarma ile katılım akışını istediği zaman yeniden tetikleyebilmektedir. Unit 42'nin kimlik sağlayıcı azaltım listesinde bu üçüncü maddedir: kurtarma akışları sertleştirilmeli, yani katılım ile kurtarma işlemlerinin gereksiz yeniden tetiklenmesi tespit edilmeli ile kısıtlanmalıdır.

Yani kurtarma akışının kendisi hız sınırı ile anomali tespiti gerektiren bir kaynaktır. Kurtarma zaten nadir çalışır, izlemeye gerek yoktur varsayımı yanlıştır.

---

### 2. NIST SP 800-63B-4'ün 4.2 bölümü, birincil metin

Yayın SP 800-63-4 nihai sürümüdür, 31 Temmuz 2025; csrc.nist.gov/pubs/sp/800/63/4/final adresindedir. HTML sürümü pages.nist.gov/800-63-4/sp800-63b.html adresindedir. Değişiklik kaydı şunu söylemektedir: *"Section 4.2: Revises the requirements and methods for account recovery"*.

#### 2.1 Tanım ile en önemli ayrım

> *"Account recovery is when a subscriber recovers from losing control of the authenticators that are needed to authenticate at a desired AAL."*

Hemen ardından, veri modeline girmesi gereken ayrım gelmektedir.

> *"Replacement of a forgotten password where the subscriber can authenticate with one or more other authenticators is considered to be the binding of a new authenticator (see Sec. 4.1.2.1) rather than account recovery."*

Bunlar iki ayrı akış ile iki ayrı risk profilidir.

| | Yeni kimlik doğrulayıcı bağlama | Hesap kurtarma |
|---|---|---|
| Ön koşul | Kullanıcı hâlâ bir kimlik doğrulayıcıyla doğrulanabilmektedir | Kullanıcı hiçbir kimlik doğrulayıcıyla doğrulanamamaktadır |
| Gereken kanıt | Mevcut güvence seviyesinde kimlik doğrulamadır | Kurtarma kodu ya da kimlik tespiti tekrarı kombinasyonudur |
| Gecikme | Yoktur | Olabilir ile olmalıdır |
| Sıklık | Sıktır | Nadirdir |
| Saldırgan getirisi | Düşüktür, çünkü zaten girmiş olması gerekmektedir | Çok yüksektir |

Keycloak'ın 2026'daki 18963 numaralı açığı tam olarak bu ayrımın yapılmamasından doğmuştur: tek bir kimlik bilgisi sıfırlama akışı hem parolasını unutanı hem kimlik doğrulayıcısını tamamen kaybedeni servis etmekteydi.

#### 2.2 Soğuma süresinin normatif dayanağı

NIST, kurtarmanın yavaş olmasını bir kusur değil beklenen bir özellik olarak yazmaktadır.

> *"Account recovery differs from authentication in several ways. Since account recovery is expected to be invoked infrequently, it is generally less convenient than authentication and — depending on the situation and recovery methods offered by the CSP — may involve extended waiting times."*

Bildirimi de kurtarmanın ayrılmaz parçası yapmaktadır.

> *"An account recovery event always causes one or more notifications to be sent to the subscriber to help detect the fraudulent use of account recovery."*

#### 2.3 Dört kurtarma sınıfı

> *"CSPs SHALL support one or more of these and MAY support an application-specific method (e.g., interaction with a CSP agent) to recover a subscriber account. The use of alternative methods SHALL be based on a risk analysis and documented by the CSP."*

Dikkat edilmelidir: kimlik bilgisi hizmet sağlayıcısı temsilcisiyle etkileşim, yani destek kanalı ya da yardım masası, dört ana sınıfa dahil değildir. NIST bunu alternatif bir yöntem olarak sınıflandırmakta ile risk analizi ve dokümantasyon şartına bağlamaktadır. Yardım masası kurtarması NIST'e göre birinci sınıf bir yöntem değildir.

##### Kayıtlı kurtarma kodları

| Gereksinim | Norm |
|---|---|
| Entropi | En az 64 bit olmalı ile onaylı bir rastgele bit üretecinden gelmelidir |
| Sunum | Sayısal, Base64 ya da karekod biçiminde olabilir |
| Saklama | Onaylı bir tek yönlü fonksiyonla özetlenmiş olmalıdır |
| Doğrulama | Kısıtlama kurallarına tabi olmalıdır |
| Kullanım sonrası | Geçersiz kılınmalı ile yeni kod verilmelidir |
| Yenileme | Kullanıcı istediği zaman yenileyebilir; yeni kod verilmesi bir kurtarma bildirimi üretmelidir |

Son iki satır çoğu üründe eksiktir: kod kullanıldıktan sonra otomatik yeni kod verilmesi ile kod yenilemenin bildirim tetiklemesi. İkincisi olmadan saldırgan sessizce kendi kurtarma kodunu üretmektedir.

##### Gönderilen kurtarma kodları

Entropi en az altı ondalık hane olmalı ile onaylı bir rastgele bit üretecinden gelmelidir.

Mutlak yaşam süresi tavanları şunlardır.

| Kanal | Azami geçerlilik |
|---|---|
| Posta, ABD kıtası içi | 21 gündür |
| Posta, ABD dışı | 30 gündür |
| Kısa mesaj ya da sesli arama | 10 dakikadır |
| E-posta | 24 saattir |

Kurtarma adresi kurulumu şöyledir: kimlik tespiti sırasında doğrulanmamışsa doğrulanacaktır, aynı özelliklerde bir onay koduyla. Ayrıca kullanıcının en az iki kurtarma adresi tanımlamasına izin verilmelidir.

##### Kurtarma kişileri

Gönderilen kod kurallarıyla aynıdır, iki istisnayla. Yaşam süresi 24 saat uzatılabilmektedir, güvenilen kişinin kodu iletmesi için; örneğin kısa mesajda 24 saat 10 dakika olmaktadır. Adres doğrulaması da 24 saat uzatılabilmektedir.

Ayrıca hizmet sağlayıcı bir görüntüleme ile yönetim arayüzü sağlamalı ile yıllık bir hatırlatma göndermelidir.

##### Kimlik tespiti tekrarı

> *"The CSP SHALL repeat the necessary steps of identity proofing consistent with the level of initial identity proofing and SHALL confirm that the claimant's identity is consistent with the previously established account."*

Bir optimizasyon izni vardır: ilk tespitten biyometrik örnek ya da kanıt kopyası yeterli kalitede saklanmışsa yalnızca doğrulama kısmı tekrarlanabilmektedir.

#### 2.4 Kimlik ile kimlik doğrulayıcı güvence seviyesine göre kurtarma matrisi, normatif

Bu tablo dokümanın en operasyonel kısmı ile çoğu ürünün karşılamadığı yerdir.

| Hesap | Gerekenlerden biri |
|---|---|
| Kimlik tespiti yapılmamış, azami birinci seviye | Kayıtlı kod, gönderilen kod ya da kurtarma kişisi |
| İkinci seviye | Birincisi farklı sınıflardan iki kurtarma kodudur; ikincisi bir kurtarma kodu artı hesaba bağlı tek faktörlü bir kimlik doğrulayıcıyla doğrulamadır; üçüncüsü hesap tespit edilmişse kimlik tespiti tekrarıdır |
| Üçüncü seviye, birinci ya da ikinci kimlik seviyesiyle tespit edilmiş | İkinci seviyeyle aynıdır |
| Üçüncü seviye, üçüncü kimlik seviyesiyle tespit edilmiş | İlk yerinde ile gözetimli kimlik tespiti oturumunda toplanan biyometrik karakteristikle başarılı bir biyometrik karşılaştırma gerekmektedir. Hizmet sağlayıcı ayrıca ilk kanıtın sunulmasını isteyebilir |

Buradan çıkan en önemli tek çıkarım şudur: ikinci seviye bir hesap için tek bir e-posta bağlantısı NIST'e göre geçerli bir kurtarma değildir. Ya ikinci bağımsız bir kanal, ya hesaba bağlı bir kimlik doğrulayıcı, ya da kimlik tespiti gerekmektedir. Sektörün fiilî varsayılanı, yani e-posta eşittir kurtarma, standardın gerisindedir.

#### 2.5 Bildirim kuralları

> *"In all cases, account recovery SHALL cause a notification to be sent to the subscriber or their designee."*
> *"CSPs SHALL support at least two notification addresses per subscriber account."*
> *"Notifications SHALL be sent to all notification addresses except postal addresses. However, notifications SHALL be sent to postal addresses if no other form of notification address is stored in the subscriber account or if the notification is for account recovery at AAL3. Account recovery notifications SHALL also be sent to a postal address if the only other notification address in the subscriber account is the address to which an issued recovery code was sent."*

Son cümle genellenebilir bir tasarım kuralına dönüşmektedir: kurtarma kanalı, o kurtarmanın bildirim kanalı olamaz. Kurtarma kodu e-postaya gittiyse ile hesapta başka bir bildirim adresi yoksa, bildirim başka bir ortamdan gitmek zorundadır. Aksi hâlde e-postayı ele geçiren saldırgan hem kodu almakta hem uyarıyı silmektedir.

Çoğu ürün bu kuralı ihlal etmektedir: kurtarma bağlantısı da hesabınız kurtarıldı bildirimi de aynı posta kutusuna düşmektedir. Bildirim o durumda hiçbir güvenlik değeri taşımamaktadır.

Ayrıca şu da geçerlidir: *"The notification SHALL provide clear instructions, including contact information, in case the recipient repudiates the event"*. Yani bildirim tek yönlü bir mesaj değil bir itiraz kanalının girişidir.

#### 2.6 Hız sınırlama

> *"the verifier SHALL limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100 by disabling that authenticator."*

100 bir üst sınırdır, bir hedef değildir; kurumlar daha düşük sınırlar koyabilmektedir. Devre dışı bırakılan kimlik doğrulayıcı yeniden bağlanmalıdır.

Kilitlenmeyi azaltmak için izin verilen teknikler, ki aynen kurtarma akışına da uygulanmaktadır, şunlardır: kimlik doğrulama denemesinden önce bot tespit ile azaltım meydan okuması; hesap limitine yaklaştıkça artan bekleme, örneğin 30 saniyeden bir saate; ile risk tabanlı ya da uyarlanabilir teknikler, yani IP, coğrafya, istek zamanlaması ile tarayıcı metadata'sı.

Kritik bağlantı şudur: hem kayıtlı hem gönderilen kurtarma kodu doğrulaması aynı kısıtlamaya tabidir. Kurtarma kodu altı haneliyse ile kısıtlama yoksa, bir milyonluk uzayda 100 deneme hakkı bile anlamlıdır; bu yüzden kısıtlama normatiftir.

#### 2.7 Kayıp ile çalıntı bildirimi, asimetrik eşik

NIST burada bilinçli bir asimetri kurmaktadır.

> *"To facilitate the secure reporting of an authenticator's loss, theft, damage, or compromise, the CSP SHOULD provide the subscriber with a method of authenticating using a backup or alternate authenticator. This backup authenticator SHALL be a password or a physical authenticator. Either could be used, but only one authentication factor is required to make this report."*

Gerekçesi şudur.

> *"The consequences of not invalidating a compromised authenticator are usually more significant than the denial-of-service potential of invalidating one in error."*

Tasarım kuralı şudur: güvenliği artıran işlemin eşiği düşük, güvenliği azaltan işlemin eşiği yüksek olmalıdır. Anahtarımı kaybettim, iptal et talebi tek faktörle yapılabilmelidir; yeni anahtar ekle talebi tam kurtarma gerektirmelidir. Çoğu ürün ikisini aynı akışa koyup ikisini de zorlaştırmaktadır; sonuç kullanıcının kaybı bildirmemesidir.

Ayrıca askıya alma desteklenebilmektedir: geri alınması geçerli bir kimlik doğrulayıcıyla doğrulama sonrasında olmalıdır ile hizmet sağlayıcı geri almaya bir zaman sınırı koyabilir.

#### 2.8 Kimlik doğrulayıcı bağlama, kurtarma sonrası kritiktir

> *"When any new authenticator is bound to a subscriber account, the CSP SHALL ensure that the process requires authentication at either the maximum AAL currently available in the subscriber account or the maximum AAL at which the new authenticator will be used, whichever is lower."*

Cihazlar arası bağlama için bağlama kodu kuralları, ki karekod ile cihazlar arası akış tasarlayan herkesin bilmesi gerekmektedir, şunlardır.

| Gereksinim | Norm |
|---|---|
| Uzunluk | Kullanıcı bir tanımlayıcı da giriyorsa en az 40 bit, aksi hâlde en az 112 bittir |
| Kullanım | Tek kullanımlık olmalıdır |
| Yaşam süresi | En fazla 10 dakikadır |
| Kanal | Güvensiz bir kanaldan iletilmemelidir; e-posta açıkça örnek verilmektedir |
| Aktarım | Elle ya da yerel bant dışı, yani karekodla yapılmalıdır |

NIST ayrıca karekodu neden tercih ettiğini açıklamaktadır: karekod genellikle kodun yanında hizmet sağlayıcının adresini de taşımakta, bu yüzden kullanıcının kodu bir kimlik avı sitesine girme ihtimali düşmektedir.

---

### 3. Kurtarmanın korunan şeyden zayıf olamayacağı ilkesi, kaynakları ile pratiği

#### 3.1 Birincil kaynak: FIDO Alliance 2019

FIDO bağlı tarafları için önerilen hesap kurtarma uygulamaları, Şubat 2019. Editörleri Yahoo Japan'dan Hidehito Gomi, VISA'dan Bill Leddy ile Amazon'dan Dean H. Saxe'tir. fidoalliance.org/wp-content/uploads/2019/02/FIDO_Account_Recovery_Best_Practices-1.pdf adresindedir.

> *"The entire ecosystem is only as strong as the weakest link, so account-recovery mechanisms and policies must be clearly defined."*

İki adımlı strateji şudur. Birincisi hesap başına birden fazla kimlik doğrulayıcıdır ile kurtarma ihtiyacını azaltmaktadır. İkincisi kimlik tespiti ya da katılım sürecini tekrar çalıştırmaktır ile kurtarmanın fiilî icrasıdır.

> *"RPs may fall back to identity proofing of their users using a mechanism at the same or higher assurance level as the initial account bootstrapping."*

İlkenin en açık ifadesi şudur.

> *"Weaker mechanisms may lower the bar for account recovery by providing a weaker pathway to user identity-proofing or authentication, but this approach would also reduce the value of the FIDO implementation. Implementing weaker account-recovery options is not recommended by the FIDO Alliance."*

Doküman ayrıca Google gelişmiş korumasını örnek göstermektedir: iki FIDO güvenlik anahtarı zorunludur, yani kurtarma ihtiyacı tasarımdan silinmektedir.

Anonim ya da takma adlı hesaplar için kimlik tespiti mümkün olmadığından kayıtlı ya da gönderilen kod veya Facebook devredilmiş kurtarma spesifikasyonu önerilmektedir; ayrıca bağlı tarafların kullanıcıyı hesap kaybı riski konusunda bilgilendirmesi ile kullanıcının bilinçli bir karar vermesine izin verilmesi istenmektedir.

#### 3.2 2025 sertleşmesi

FIDO'nun Mart 2025 tarihli ikinci kısım belgesi şunları söylemektedir.

> *"Account recovery processes based on weak authentication methods create potential security bypasses and undermine the strength of passkey authentication systems."*
> *"The prohibition of phishable methods applies to both login and account recovery processes."*

Derecelendirme şöyledir: giriş, yedek yol ile hesap kurtarmanın üçünde birden kimlik avına dirençli yöntem kullanan bağlı taraflar, kurtarmada kimlik avına açık yöntem kullananlardan daha dayanıklı sayılmaktadır.

#### 3.3 İlkenin pratik uygulaması, üç somut kural

İlke soyuttur; uygulanabilir hâle getiren üç kural şunlardır.

Birinci kural şudur: kurtarma yolunun güvence seviyesi, hesabın azami güvence seviyesine eşit ya da ondan yüksek olmalıdır. Bu ölçülebilir bir değişmezdir ile test edilebilir. Argus'ta her kurtarma yönteminin bir güvence seviyesi etiketi olmalı ile politika motoru, kurtarma yollarının azami güvence seviyesi hesabın azami seviyesinin altındaysa bunu bir yapılandırma hatası olarak reddetmelidir; bir çalışma zamanı hatası olarak değil.

İkinci kural şudur: kurtarma yolu, korunan varlığın tamamına değil yeniden inşasına erişim vermelidir. Kurtarma içeri girme değil yeni kimlik doğrulayıcı bağlama hakkı vermelidir. Aradaki fark şudur: kurtarma sonrası oturum tam yetkili bir oturum değil kısıtlı bir yeniden kurulum oturumudur; beşinci kısımda detaylandırılmaktadır.

Üçüncü kural şudur: en zayıf yol ölçülmeli ile raporlanmalıdır. Bir hesabın etkin güvenliği tüm giriş yollarının güvence seviyelerinin en küçüğüdür; kurtarma dahildir. Argus yönetim konsolu bu sayıyı hesap başına göstermelidir. Bugün hiçbir büyük kimlik sağlayıcı bunu göstermemektedir. Bu bir tasarım önerisidir, mevcut bir üründen alıntı değildir.

#### 3.4 Apple: ilkenin ürünleştirilmiş hâli

Apple, zayıf yolu kapat seçeneğini kullanıcıya açıkça satan tek büyük sağlayıcıdır.

Kurtarma anahtarı 28 karakterdir; support.apple.com/en-us/109345 adresinde anlatılmaktadır.

> *"you turn off Apple's standard account recovery process"*
> *"If you can't provide your recovery key, you'll be locked out of your account permanently."*

Yani kurtarma anahtarını açmak, Apple destekli ile dolayısıyla sosyal mühendisliğe açık kurtarma yolunu kapatmaktadır. Sıfırlama için gereken kurtarma anahtarı artı güvenilen telefon numarasına giden doğrulama kodudur.

Gelişmiş veri koruması açıldığında Apple bunu zorunlu kılmaktadır: en az bir alternatif kurtarma yöntemi, yani bir kurtarma anahtarı ya da bir kurtarma kişisi kurulmalıdır. Verinin uçtan uca şifrelenmesi Apple'ın kurtarma yeteneğini kaldırdığı için kurtarma sorumluluğu kullanıcıya devredilmektedir.

Ders şudur: kurtarma gücüyle veri gizliliği arasında kaçınılmaz bir takas vardır. Apple bunu gizlemek yerine kullanıcıya açık bir düğme olarak sunmaktadır. Argus da yüksek değerli hesaplar için asistanlı kurtarmayı kapat seçeneği sunmalı ile kalıcı kayıp riskini açıkça göstermelidir.

---

### 4. Kurtarma yöntemleri karşılaştırması

| Yöntem | Kimlik avı direnci | Devretme riski | Ölçek | Kalıcı kayıp riski | NIST sınıfı |
|---|---|---|---|---|---|
| Kayıtlı kurtarma kodları | Yüksektir, çevrimdışıdır | Kullanıcı ekran görüntüsü alıp buluta koymaktadır | Sıfır operasyondur | Yüksektir; kaybedilmektedir | Kayıtlı kodlar |
| İkinci geçiş anahtarı ya da güvenlik anahtarı | En yüksektir | Fiziksel çalınmadır | Sıfır operasyondur | Ortadır | İkinci seçeneğin bileşenidir |
| Güvenilir cihaz | Yüksektir | Cihaz çalınması ile omuz üstünden izlemedir; Apple'ın gelişmiş korumasının çözdüğü sorundur | Sıfırdır | Ortadır | İkinci seçenektir |
| Kurtarma kişileri, yani sosyal kurtarma | Orta ile yüksektir | Kişinin kendisi sosyal mühendisliğe uğramaktadır | Sıfırdır | Düşüktür | Kurtarma kişileri |
| E-posta ya da kısa mesaj kodu | Düşüktür | E-posta ele geçirme ile SIM değiştirmedir | Sıfırdır | Çok düşüktür | Gönderilen kodlar |
| Kimlik tespiti tekrarı | Yüksektir | Derin sahte ile sahte belgedir | Maliyetlidir ile satıcıya bağımlıdır | Düşüktür | Kimlik tespiti tekrarı |
| Destek kanalı, yani yardım masası | En düşüktür | Sosyal mühendisliktir; yedinci kısma bakınız | En pahalıdır | Yoktur | Sınıf dışıdır, alternatif yöntemdir |

Okunuşu şudur: aşağı doğru gidildikçe kullanıcı kaybı azalmakta ile saldırgan başarısı artmaktadır. Doğru tasarım tek bir yöntem seçmek değil kombinasyon zorunlu kılmaktır; NIST'in ikinci seviye kuralı zaten bunu söylemektedir.

#### 4.1 Kurtarma kodları, sık yapılan altı hata

1. Özetlenmeden saklanmasıdır. NIST özetlemeyi zorunlu kılmaktadır. Kurtarma kodu bir paroladır ile veritabanı sızıntısında parolayla aynı sonucu vermektedir.
2. Kullanıldıktan sonra yenisinin verilmemesidir. NIST kodun geçersiz kılınmasını ile yeni bir kod verilmesini zorunlu kılmaktadır. Aksi hâlde kullanıcı sessizce kodsuz kalmaktadır.
3. Kısıtlama uygulanmamasıdır. NIST hız sınırlama bölümüne açık atıf yapmaktadır.
4. Kod yenilemenin bildirim üretmemesidir. Saldırgan oturum çalarsa sessizce kalıcılık kurmaktadır.
5. Kayıt anında gösterilip sakladım onayının alınmamasıdır. Gösterilip onaylanmayan kod olmayan koddur.
6. On kod verilip hepsinin aynı anda geçersizleşmesidir. Tek kullanımlık olması gereken her bir koddur, küme değildir.

#### 4.2 İkinci geçiş anahtarı, en iyi çözüm ile neden çalışmadığı

FIDO'nun 2019'dan beri birinci önerisi budur ile teknik olarak doğrudur. Pratikte tıkanma noktası kullanıcı deneyimidir.

Kullanıcı ikinci bir kimlik doğrulayıcının neden gerektiğini anlamamaktadır. Cihaz senkronizasyonu, yani zaten telefonumda ile bilgisayarımda var düşüncesi, yanlış bir güvenlik hissi vermektedir; ikisi aynı senkron geçiş anahtarıdır, iki kimlik doğrulayıcı değildir. İkinci fiziksel anahtar maliyet ile kayıp riski demektir.

Argus için somut öneri şudur: iki kimlik doğrulayıcının bağımsız olup olmadığı modelde takip edilmelidir. Aynı senkronizasyon dokusundaki iki geçiş anahtarı aynı bağımsızlık grubu değerini taşımalı ile tek bir kimlik doğrulayıcı sayılmalıdır. Bu, NIST'in birden fazla kimlik doğrulayıcı bağla tavsiyesini anlamlı hâle getiren tek yorumdur. Bugün hiçbir kimlik sağlayıcı bunu modellememektedir. Bir tasarım önerisidir.

WebAuthn tarafında bunu kısmen çıkarabileceğiniz sinyaller kimlik damgası, yani kimlik doğrulayıcı modeli, yedeklemeye uygunluk ile yedekleme durumu bayraklarıdır. Yedeklemeye uygun bir kimlik bilgisi senkronizasyona uygundur; aynı kimlik damgasına sahip ile yedeklemeye uygun iki kimlik bilgisi büyük olasılıkla aynı dokudadır.

---

### 5. Kurtarma sonrası soğuma süresi

#### 5.1 Soğuma süresi ne işe yaramaktadır, yanlış anlaşılan amaç

Yaygın yanlış anlama gecikmenin saldırganı yıldıracağıdır. Bu yanlıştır. Gerçek amaç Google'ın kendi dokümanında yazılıdır.

> *"During this delay, Google uses your recovery info and other information you've provided to notify you that an account recovery request has been made, so if someone else is trying to access your account, you have time to deny the request and secure your account."*
> support.google.com/accounts/answer/9412469

Soğuma süresi bir itiraz penceresidir. Saldırganın kurtarmayı tamamlamasıyla hesabın fiilen devredilmesi arasına, meşru sahibin uyarıyı görüp iptal edebileceği bir aralık koymaktadır. Bu yüzden şunlar geçerlidir. Soğuma bildirimle birlikte çalışmaktadır; bildirimsiz gecikme yalnızca kullanıcıyı sinirlendirmektedir. Bildirim, kurtarmayı tetikleyen kanaldan farklı bir kanaldan gitmelidir. İptal, kurtarmadan daha kolay olmalıdır, ki asimetri ilkesidir.

#### 5.2 Ne kadar olmalıdır, gerçek uygulamalar

| Sağlayıcı | Süre | Kapsam | Kaynak |
|---|---|---|---|
| Google güvenlik beklemesi | Risk faktörlerine göre birkaç saat ya da birkaç gündür | Kurtarma talebinin işlenmesidir | support.google.com/accounts/answer/9412469 |
| Google kurtarma bilgisi değişimi | Yedi güne kadardır | Değişikliğin yürürlüğe girmesidir; bu süre boyunca eski adrese de kod gidebilmektedir | support.google.com/accounts/answer/7682439 |
| Apple hesap kurtarma | Birkaç gün ya da daha fazladır ile kısaltılamamaktadır | Parola sıfırlamadır | support.apple.com/en-us/HT204921 |
| Apple çalıntı cihaz koruması | Bir saat artı iki kez biyometrik doğrulamadır | Apple kimliği parolası, cihaz parolası, yüz ya da parmak izi değişimi, cihazı bul kapatma ile korumayı kapatmadır | iOS 26.4'te varsayılan olarak açıktır |
| Microsoft Entra sürekli erişim değerlendirmesi | Ters yöndedir: token ömrü 28 saate kadar uzatılmakta ile iptal sinyalle yapılmaktadır, yaklaşık 15 dakikalık yayılımla | Oturum iptalidir | learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation |

Google'ın ters orantı kuralı en önemli tasarım sinyalidir.

> *"if you added more security to your account by setting up 2-Step Verification, your account recovery request might be delayed for longer."*

Yani hesabın koruma seviyesi arttıkça kurtarma daha yavaş olmaktadır. Bu, kurtarmanın korunan şeyden zayıf olamayacağı ilkesinin zamansal boyutudur: güçlü koruma seçen kullanıcı, o korumayı atlatma girişimine karşı da daha uzun bir itiraz penceresi kazanmaktadır.

Apple'ın 2026 hamlesi şudur: çalıntı cihaz koruması iOS 26.4 ile tüm telefonlarda varsayılan olarak açık hâle gelmiştir; MacRumors, 16 Şubat 2026. Yani sektör hassas değişiklikte gecikmeyi tercihe bağlı bir özellikten varsayılana taşımıştır. Bu, Argus'un varsayılanını belirlerken dikkate alınması gereken bir sinyaldir.

Apple'ın tanıdık konum istisnası da öğreticidir: gecikme bağlama duyarlıdır. Ev ağında gecikme yoktur, dışarıda vardır. Yani soğuma süresi sabit bir sayı değil bir risk fonksiyonudur.

#### 5.3 Hangi işlemler kısıtlanmalıdır, somut liste

Kurtarma sonrası oturum tam yetkili bir oturum değildir. Argus'un kurtarma ek süresi alanı dolu olduğu sürece şu işlemler reddedilmeli ya da ek doğrulama istemelidir.

| Kategori | Kısıtlanacak işlem | Gerekçe |
|---|---|---|
| Kimlik | E-posta ya da telefon değişimi | Saldırgan kalıcılık kurmaktadır |
| Kimlik | Yeni kurtarma adresi ekleme | Bir sonraki kurtarmayı garantilemektedir |
| Kimlik | Kurtarma kodunu yeniden üretme | Aynıdır |
| Kimlik doğrulayıcı | Mevcut geçiş anahtarını ya da çok faktörlü yöntemi silme | Meşru sahibi kilitlemektedir |
| Kimlik doğrulayıcı | Yeni kimlik doğrulayıcı ekleme, kısmen | Bir tanesi gereklidir, yoksa kullanıcı içeri girememektedir; ikincisinden itibaren kısıt uygulanmalıdır |
| Federasyon | Yeni kimlik sağlayıcı bağlama ile mevcut bağı kaldırma | Kalıcılık ile devretmedir |
| Yetki | Rol yükseltme, üye davet etme ile sahiplik devri | Yanal harekettir |
| Veri | Toplu dışa aktarım ile veri taşınabilirliği talebi | Tek hamlede tüm veridir |
| Finans | Ödeme aracı değişimi, para çekme ile fatura adresi | Doğrudan zarardır |
| API | Yeni API anahtarı ya da uzun ömürlü token üretimi | Soğuma süresini atlamaktadır |
| Hesap | Hesap silme | İz temizlemedir |

Kritik nokta şudur: yeni API anahtarı üretimi listede olmazsa soğuma süresi anlamsızdır; saldırgan kurtarma sonrası hemen kalıcı bir token üretip beklemeye geçmektedir. Soğuma süresini atlatan her mekanizma kapatılmalıdır.

Süre önerisi, yani Argus varsayılanı, bir tasarım önerisidir.

| Hesap tipi | Kurtarma yöntemi | Soğuma |
|---|---|---|
| Tüketici, düşük değer | Kayıtlı kurtarma kodu | Sıfırdır; kod zaten güçlü bir kanıttır |
| Tüketici, düşük değer | Tek başına e-posta kodu | 24 saattir |
| Tüketici, çok faktörlü | İki kanal kombinasyonu | Risk skoruna göre bir ile 24 saattir |
| Tüketici, çok faktörlü | Kimlik tespiti tekrarı | Sıfır ile bir saattir |
| Kurumsal çalışan | Yönetici onaylı geçici erişim koduyla | Sıfırdır; bant dışı onay zaten vardır |
| Yüksek değerli ya da yönetici | Her yöntem | En az 24 saat artı ikinci bir yönetici onayıdır |

Mantık şudur: soğuma süresi kullanılan kanıtın gücüyle ters orantılıdır. Zayıf kanıtla kurtaran uzun beklemekte, güçlü kanıtla kurtaran beklememektedir. Sabit bir gecikme koymak hem güvenli kullanıcıyı cezalandırmakta hem zayıf yolu yeterince yavaşlatmamaktadır.

#### 5.4 Karşı desenler

| Karşı desen | Neden yanlıştır |
|---|---|
| Soğuma süresi var ancak bildirim yok | Gecikmenin tek amacı bir itiraz penceresi açmaktır; bildirimsiz gecikme yalnızca bir kullanıcı deneyimi cezasıdır |
| Bildirim kurtarma kanalına gidiyor | Saldırgan o kanalı zaten kontrol etmektedir; NIST'in kapattığı delik budur |
| Destek aceleniz mi var deyip süreyi kısaltıyor | Apple'ın açıkça reddettiği şeydir: destekle iletişime geçmek bu süreyi kısaltmaya yardımcı olamamaktadır. Kısaltılabilen bir soğuma sosyal mühendisliğin hedefi olmaktadır |
| Soğuma yalnızca parola değişiminde | Geçiş anahtarı ekleme, e-posta değişimi ile API anahtarı üretimi kapsam dışı kalırsa etkisizdir |
| Sabit süre, riske kör | Güvenli kullanıcıyı cezalandırmakta ile saldırganı yeterince yavaşlatmamaktadır |
| İptal bağlantısı kurtarmadan zor | Asimetri tersine dönmüştür; iptal tek tıkla olmalıdır |

---

### 6. Geçiş anahtarı kaybı senaryoları

#### 6.1 Senkronize ile cihaza bağlı

| | Senkronize geçiş anahtarı | Cihaza bağlı geçiş anahtarı |
|---|---|---|
| Tek cihaz kaybı | Sorun yoktur; diğer cihazlarda mevcuttur | Kimlik bilgisi kaybıdır |
| Platform hesabı kaybı | Tüm geçiş anahtarları kaybolmaktadır | Etkilenmemektedir |
| Kurtarma sorumlusu | Platform sağlayıcısıdır | Bağlı taraftır |
| Üçüncü güvence seviyesine uygunluk | Hayır; NIST'e göre dışa aktarılabilir bir anahtar bu seviyede kullanılamamaktadır | Evet |
| Kurtarma zafiyeti | Platform kurtarma akışı sizin zafiyetinizdir | Yoktur ancak kayıp riski yüksektir |

Bağlı taraf açısından gerçek şudur: senkron geçiş anahtarı kullanıcı kaybı problemini çözmekte ancak kurtarma sorumluluğunu dışarı devretmektedir. Platform hesabı ele geçirilirse o platformdaki tüm geçiş anahtarları saldırganın olmakta ile bağlı tarafın haberi olmamaktadır. Bu yüzden bağlı taraf kendi bağımsız risk sinyallerini korumalıdır.

Yedekleme durumu bayrağının değişimi bir sinyaldir: yedeklemeye uygun bir kimlik bilgisinin yedeklenmemişten yedeklenmişe geçmesi, kimlik bilgisinin ilk kez yedeklendiği anlamına gelmektedir. Bu bir olay olarak günlüğe yazılmalıdır. Yeni bir cihazdan gelen ilk kimlik doğrulama, aynı kimlik bilgisiyle bile olsa bir risk sinyalidir. Kimlik damgası değişimi kimlik bilgisinin taşındığını göstermektedir.

#### 6.2 Platform hesabı kaybı, kimsenin çözmediği senaryo

Kullanıcı Apple kimliğini kaybederse iCloud anahtar zincirindeki tüm geçiş anahtarları gitmektedir. Apple'ın hesap kurtarması günler sürmekte ile kurtarma anahtarı varsa hiç çalışmamaktadır. Kullanıcı bu süre boyunca sizin servisinize girememektedir.

Bu, bağlı tarafın çözmesi gereken bir problemdir ile şu anda kimse çözmemektedir. Öneri şudur: Argus senkron geçiş anahtarını tek bir kimlik doğrulayıcı olarak kabul etmemelidir. Kayıt akışında senkron bir geçiş anahtarı oluşturulduğunda, ikinci ile bağımsız bir kurtarma yolu, yani kayıtlı bir kurtarma kodu, ikinci bir cihaza bağlı kimlik bilgisi ya da bir kurtarma kişisi kurulmadan hesap tam korumalı sayılmamalıdır. Bu, NIST ekinin ikinci seviye ve üstünde kurtarmayı desteklemek için birden fazla kimlik doğrulayıcı bağlanması tavsiyesinin doğrudan uygulanmasıdır.

#### 6.3 Köken bağı, göçle ölümcül kesişim

Geçiş anahtarları bağlı taraf kimliğine, yani etki alanına bağlıdır. Alan adı değişirse geçiş anahtarları ölmektedir. Bu hem bir göç hem bir kurtarma problemi doğurmaktadır: markanız değişirse tüm kullanıcıların yeniden kayıt olması gerekmekte ile bu toplu bir kurtarma olayı olmaktadır. Yani en zayıf kurtarma yolunuzun tüm kullanıcı tabanında aynı anda çalışması demektir. Saldırgan için mükemmel bir penceredir.

Ders şudur: alan adı değişimi bir pazarlama kararı değil bir güvenlik olayıdır. Planlanması, kademelendirilmesi ile kurtarma yolunun o dönem için sertleştirilmesi gerekmektedir.

---

### 7. Yardım masası sosyal mühendisliği

#### 7.1 NIST'in kendi teşhisi

SP 800-63B-4'ün kimlik doğrulayıcı kurtarma bölümü, bu dokümanın tamamının özeti sayılabilecek cümleyi içermektedir.

> *"The weak point in many authentication mechanisms is the process followed when a subscriber loses control of one or more authenticators and needs to replace them. In many cases, the options for authenticating the subscriber are limited, and economic concerns (e.g., the cost of maintaining call centers) motivate the use of inexpensive and often less secure backup authentication methods. To the extent that authenticator recovery is human-assisted, social engineering attacks also pose risks."*

Hemen ardından faktör izolasyonu kuralı gelmektedir.

> *"To maintain the integrity of the authentication factors, it is essential that one authentication factor cannot be leveraged to obtain an authenticator of a different factor. For example, a password must not be usable to obtain a new list of look-up secrets."*

Bu ikinci cümle, FIDO'nun 2025'te geçiş anahtarı kaydının yalnızca parolayla yapılamayacağını söylemesinin NIST sürümüdür ile Argus'un yetkilendirme motoruna bir değişmez olarak girmelidir: bir faktör, farklı sınıftaki bir faktörü üretmek için kullanılamaz.

#### 7.2 Scattered Spider'ın saldırı zinciri, birincil kaynak

Ortak siber güvenlik uyarısı AA23-320A, ilk yayını Kasım 2023, güncellemesi 29 Temmuz 2025'tir. Yazarları FBI, CISA, RCMP, AFP, ACSC ile CCCS ve Birleşik Krallık NCSC'dir. PDF'leri cisa.gov/sites/default/files/2025-08/aa23-320a-scattered-spider-508c.pdf ile ic3.gov/CSA/2025/250729.pdf adreslerindedir.

Uyarının en öğretici pasajı saldırının keşif aşamasının hedefini anlatmaktadır.

> *"The social engineering attempts are designed to first learn what steps are needed to conduct password resets from helpdesks. Once that information is identified, the threat actors continue to conduct phone calls to employees and help desks to gather password reset specific information of a targeted employee. Finally, the threat actors conduct spearphishing calls to convince IT help desk personnel to reset passwords and/or transfer MFA tokens."*

Buradan çıkan tek cümlelik ders şudur: kurtarma prosedürünün kendisi gizlilik değeri olan bir varlıktır. Saldırgan önce sizde parola sıfırlamanın nasıl yapıldığını öğrenmekte, sonra hedef çalışanı aramaktadır. Prosedürünüz kamuya açıksa saldırganın keşif aşaması sıfırlanmaktadır.

Uyarının diğer normatif noktaları şunlardır. Güvenilen ilişki tekniği kapsamında tehdit aktörleri taşeron bilgi teknolojileri yardım masalarının güvenilen ilişkilerini kötüye kullanmaktadır; taşeron yardım masası özel bir risk kategorisidir. Kimlik doğrulama süreçlerini değiştirme ile ağ arayüzü yakalama teknikleri kapsamında aktörler kendi çok faktörlü belirteçlerini kaydetmektedir; bu, kurtarma sonrası kalıcılıktır ile beşinci kısımdaki kısıt listesinin gerekçesidir. Geçerli hesaplar tekniği kapsamında aktörler parolalar değiştirildiğinde bile ağ erişimini korumaktadır; yani parola değişimi yeterli bir müdahale değildir. Yazım hatası alan adı kalıpları hedef adına çoklu oturum açma, servis masası, Okta ile yardım masası sözcüklerinin eklenmesiyle oluşturulmaktadır. Azaltım tarafında FIDO ile WebAuthn kimlik doğrulaması ya da açık anahtar altyapısı tabanlı çok faktörlü kimlik doğrulama önerilmektedir, çünkü bunlar kimlik avına dirençlidir ile anlık bildirim bombardımanına ve SIM değiştirmeye açık değildir; ayrıca yinelenen parola değişikliklerinin zorunlu tutulmaması istenmektedir.

Dürüst bir not gerekmektedir: uyarının azaltım bölümü, yardım masasının arayanı doğrulaması konusunda şaşırtıcı derecede zayıftır. Sesli kimlik avına karşı eğitilmesini söylemekte ancak geri arama, video doğrulaması ya da yönetici onayı gibi somut prosedürler reçete etmemektedir. Bu boşluğun kendisi bir bulgudur.

#### 7.3 Vakalar

| Vaka | Tarih | Mekanizma | Etki |
|---|---|---|---|
| MGM Resorts | Eylül 2023 | Yardım masası araması ile kimlik doğrulanmadan sıfırlama | Kanonik vakadır. Birincil kaynak doğrulanmamıştır; genel örüntü dışındaki detaylar için dikkat gerekmektedir |
| Okta müşterileri | Yaz 2023 | Saldırganlar servis masası personelini ikna edip yüksek ayrıcalıklı kullanıcıların tüm çok faktörlü yöntemlerini sıfırlatmıştır | Dört müşteri etkilenmiştir. Okta'nın kendi analizi sec.okta.com adresindedir |
| Clorox ile Cognizant davası | İhlal Ağustos 2023, dava Temmuz 2025 | Cognizant yardım masasının, Clorox'un yazılı doğrulama talimatlarına aykırı olarak, saldırgana parolayı ile çok faktörlü yöntemi kimlik doğrulamadan sıfırladığı iddiasıdır; iddiaya göre en az üç kez | 380 milyon dolar talep edilmiştir. Cognizant savunması siber güvenliği yönetmediğidir. Rakamlar dava dilekçesine ilişkin habercilikten alınmıştır, dilekçe metninden değil |
| M&S, Co-op ile Harrods | Nisan ile Mayıs 2025 | Dış kaynaklı bilgi teknolojileri yardım masası aranıp çalışan taklidi yapılmış ile ayrıcalıklı hesapta çok faktörlü yöntem sıfırlanmıştır | M&S çevrim içi siparişi yaklaşık altı hafta kapalı kalmıştır. Siber İzleme Merkezi sınıflandırması tek birleşik bir siber olaydır ile 270 ile 440 milyon sterlin arasıdır. Temmuz 2025'te dört gözaltı olmuştur. DragonForce fidye yazılımı kullanılmıştır |
| Sigorta sektörü dalgası | Haziran 2025 | Aynı örüntüdür | Aflac, Erie Insurance ile Philadelphia Insurance etkilenmiştir |
| Havacılık ile ulaştırma dalgası | Haziran ile Temmuz 2025 | Aynı örüntüdür, FBI uyarısı yayımlanmıştır | Hawaiian Airlines, Qantas ile WestJet etkilenmiştir |
| Twitter | 15 Temmuz 2020 | Sesli kimlik avıyla çalışanlardan iç yönetim aracına erişim sağlanmış ile anlık bildirimli çok faktörlü doğrulama onaylatılmıştır | 118 binden fazla dolarlık bitcoin alınmıştır. New York Finansal Hizmetler Dairesi'nin Ekim 2020 tarihli raporu birincil kaynaktır |
| Robinhood | 3 Kasım 2021 | Destek temsilcisi telefonla ikna edilip uzaktan erişim yazılımı kurdurulmuştur | Yaklaşık yedi milyon kişi etkilenmiştir. SEC 8-K eki birincil kaynaktır |

2026 vakaları konusunda bir not gerekmektedir: belirli ile iyi kaynaklı bir 2026 yardım masası olayı bulunamamıştır. Dolaşımdaki 2026 ortası itibarıyla 100'den fazla ihlal ile 100 milyon doların üzerinde fidye iddiası doğrulanamamıştır ile yayımlanmamalıdır.

#### 7.4 Karşı önlemler, Okta'nın yayımlanmış rehberi, birincil

Okta Tehdit İstihbaratı, 29 Eylül 2025, Moussa Diallo; okta.com/blog/threat-intelligence/help-desks-targeted-in-social-engineering-targeting-hr-applications adresindedir.

En değerli öneri yetkiyi kaldırmaktır.

> *"Create custom admin roles for front-line service desk professionals that do not have the permissions required to modify factors (reset user passwords, set temporary passwords, or reset or enroll factors). Instead, service desk professionals should be granted in their custom role the permission to issue Temporary Access Codes after a caller to the help desk has successfully verified their identity."*

Yani birinci seviye destek sıfırlama yapamamaktadır; yalnızca zaman sınırlı ile gruba özgü bir geçici erişim kodu verebilmektedir. Sıfırlamayı kullanıcının kendisi yapmaktadır. Bu, yardım masasının yetkisini hesabı devretten hesaba geçici bir pencere aça indirmektedir.

Diğer Okta önerileri şunlardır. Uzak kullanıcı kimliğini doğrulamak için standartlaştırılmış, dokümante ile duyurulmuş bir süreç kurulmalı ile kilitlenme durumunda kimlik doğrulama servisleri kullanılmalıdır. Yönetilen ya da kayıtlı cihaz zorunlu tutulmalı ile nadiren kullanılan ağlardan gelen istekler reddedilmeli ya da daha yüksek güvence istenmelidir. Sıfır kalıcı ayrıcalık ile tam zamanında erişim için çift onay uygulanmalıdır. Güçlü kimlik doğrulayıcılar, yani FastPass, FIDO2 WebAuthn ya da akıllı kart zorunlu tutulmalıdır.

Dürüst bir not gerekmektedir: video doğrulama, yönetici onayı ile bant dışı geri arama sektörde yaygın olarak önerilmektedir, ancak Okta'nın ya da CISA'nın birincil dokümanlarında bu üçü isimle geçmemektedir. Bu dokümanda genel iyi uygulama olarak sunulmuşlardır ile bu kurumlara atfedilmemişlerdir.

New York Finansal Hizmetler Dairesi'nin düzenleyici tavsiyesi ise doğrudan alıntılanabilir; Twitter soruşturma raporu, Ekim 2020.

> *"Access to critical functions should require MFA. Another possible control for high-risk functions is to require certification or approval by a second employee before the action can be taken. An approval requirement can limit the damage if an attacker compromises one employee's access."*

Bir finansal düzenleyicinin yüksek riskli işlemler için dört göz onayı önermesi, kimliğe bürünme ile kurtarma tasarımında güçlü bir dayanaktır.

#### 7.5 Kanidm'in modeli, önerinin yapısal hâli

Okta'nın 7.4'teki önerisi bir rol yapılandırmasıdır; servis masasına kimlik doğrulayıcı değiştirme izni verilmemesini söylemektedir. Yapılandırma ise açılabilmektedir. Kanidm aynı şeyi bir ürün değişmezi hâline getirmiştir ile modeli birincil kaynaktan doğrulanmıştır, erişim 13 Eylül 2026.

Kural şudur: kullanıcıların kimlik bilgileri onlar adına sıfırlanamamaktadır. Bunun yerine bir kimlik bilgisi sıfırlama belirteci üretilmekte ile kullanıcıya verilmektedir; kullanıcı kendi kimlik bilgisini etkileşimli ile tek seferlik olarak kendisi kurmaktadır. Belirteç `kanidm person credential create-reset-token` komutuyla ya da `/v1/person/:id/_credential/_update_intent` uç noktasıyla üretilmektedir. Öntanımlı geçerlilik bir saattir; daha uzunu istenebilmekte ancak azami 24 saattir. Sıfırlama işlendiği anda belirteç derhâl geçersizleşmekte ile bir daha asla kullanılamamaktadır. Belirteci üretebilmek için hesap üzerinde yazma yetkisi gerekmektedir; bu, hesabın kendisiyle ile üç yönetim grubuyla sınırlıdır.

Argus için önemi şudur. Fark bir izin ayarı değil bir ayrıcalık tavanıdır: yönetim API'sinde kimlik bilgisini doğrudan yazan bir uç nokta bulunmamaktadır, yalnızca niyet belirteci üreten bir uç nokta bulunmaktadır. Sonuç, servis masasının ele geçirilmesinin hesabın ele geçirilmesine dönüşmemesidir, çünkü servis masası hiçbir noktada kullanıcının kimlik doğrulayıcısını seçememektedir. Scattered Spider zincirinin son adımı, yani yardım masası personelinin parola sıfırlamaya ya da çok faktörlü belirteç aktarmaya ikna edilmesi, bu tasarımda saldırganın kendi kimlik doğrulayıcısını kaydetmesiyle sonuçlanamamaktadır; saldırgan yalnızca gerçek kullanıcıya gidecek bir pencere açtırabilmektedir.

Bu, 10.3'teki sekizinci ayrışma maddesinin, yani kurtarma yetkisi nesnesinin, gerçeklenme biçimidir. İkisi arasındaki fark şudur: geçici erişim kodu bir kimlik doğrulayıcıdır ile taşıyıcıya hesaba girme yetkisi vermektedir; niyet belirteci bir kimlik doğrulayıcı değildir ile yalnızca kimlik bilgisi kurma oturumu açmaktadır. Argus ikisini de sunmalı ancak varsayılanı niyet belirteci yapmalıdır, çünkü geçici erişim kodu telefonda okunabilmekte, niyet belirteci ise kayıtlı bir bildirim adresine gönderilmektedir ile bu adres kurtarma kanalından farklı olmak zorundadır.

Dört kısıt konmalıdır. Belirteç tek kullanımlıktır ile işlendiği anda geçersizleşmelidir. Azami ömür yapılandırılabilir olmalı ancak bir tavanı bulunmalıdır. Belirtecin üretilmesi ile kullanılması ayrı denetim olaylarıdır; üretim, yöneticinin kimliğini taşımalıdır. Belirteçle açılan oturum yalnızca kimlik bilgisi kurabilmeli, başka hiçbir hesap işlemi yapamamalıdır; yani oturumun kapsamı kimlik bilgisi güncellemesiyle sınırlıdır.

Bir sınır kaydedilmelidir: bu model kullanıcının bildirim adresine erişebildiğini varsaymaktadır. Adresin kendisi kaybedildiğinde niyet belirteci teslim edilememektedir ile akış 6. bölümdeki kalıcı kayıp senaryosuna düşmektedir. Yani niyet belirteci yardım masası riskini kaldırmakta, kanal kaybı riskini kaldırmamaktadır.

---

### 8. Gerçek dünya verisi ile bulunamayan sayı

#### 8.1 En önemli negatif bulgu

Hesap ele geçirmelerin yüzde kaçının kurtarma akışından geçtiği sorusunun yayımlanmış bir cevabı yoktur. Verizon veri ihlali araştırma raporu, Okta, Sift, Javelin ile Arkose dahil taranan kaynakların hiçbiri giriş akışıyla kurtarma akışı arasında bu ayrımı yapan bir metrik yayımlamamaktadır. Bu bir veri boşluğudur ile dürüstçe böyle raporlanmalıdır. Bu dokümanda kurtarmanın payına dair hiçbir yüzde uydurulmamıştır.

Dolaylı kanıtlar mevcuttur.

| Metrik | Değer | Kaynak | Güven |
|---|---|---|---|
| Bahane uydurma, 2026 raporunda ilk kez ayrı bir ilk erişim vektörü olarak ayrılmıştır | %6 | Verizon 2026 raporu, yaklaşık Mayıs 2026 | İkincil özetlerdendir; PDF doğrudan okunmamıştır |
| Kimlik bilgisi kötüye kullanımı, ilk erişim vektörü olarak | %13, düşüştedir | Aynı rapor | İkincildir |
| Kimlik bilgisi kötüye kullanımı, ihlallerin herhangi bir yerinde | %39 | Aynı rapor | İkincildir |
| İnsan unsuru içeren ihlal | %62 | Aynı rapor | İkincildir |
| 2025 hesap ele geçirme kaybı | 15 milyar doları aşkındır, %4 azalmıştır | Javelin 2026 kimlik dolandırıcılığı çalışması, basın bülteni 21 Nisan 2026 | Birincildir |
| 2025 hesap ele geçirme mağduru | Altı milyon kişidir, 2024'e göre %18 artmıştır | Javelin 2026 | Birincildir |
| 2025 toplam kimlik dolandırıcılığı | 27,3 milyar dolar ile 18 milyon mağdurdur | Javelin 2026 | Birincildir |
| Kimlik bilgisi doldurma kriterini karşılayan giriş denemesi | %24,3 | Okta güvenli kimlik durumu 2023 | Birincildir |
| Aylık engellenen kimlik saldırısı | 3,9 milyardan fazladır | Okta güvenli kimlik taahhüdü, Şubat ile Temmuz 2025 | Birincildir |

Javelin'in ilerleme yanılsaması çerçevesi Argus için kullanışlı bir argümandır: kayıp %4 azalırken mağdur sayısı %18 artmıştır. Yani saldırı başına kazanç düşmekte ancak saldırı hacmi artmaktadır; savunmanın maliyeti mağdur başına değil olay başına ölçeklenmelidir.

#### 8.2 Bahane uydurma ayrımının önemi

2026 raporu bahane uydurmayı ayrı bir vektör olarak ayırdığı için, önceki yıl metodolojisiyle ölçülseydi kimlik bilgisi kötüye kullanımı %13 değil %16 olacaktı. Yani insan kandırma artık kimlik bilgisi hırsızlığından ayrı bir kategori olarak sayılmaya başlanmıştır. Bu, yardım masası vektörünün olgunlaştığının ölçüm tarafındaki yansımasıdır.

---

### 9. Kurumsal ile tüketici kurtarma

Yapısal fark tek bir cümleyle özetlenebilir: kurumsal kurtarmanın bant dışı bir güven çıpası vardır, tüketici kurtarmanın yoktur.

Kurumsal tarafta işveren, insan kaynakları kaydı, yönetici, yönetilen cihaz ile mobil cihaz yönetimi bulunmaktadır. NIST bunu ekinde açıkça yazmaktadır.

> *"For enterprise use cases, concerns over sharing keys can be effectively mitigated using device management techniques that limit the ability for keys to be moved off of approved devices or sync fabrics. However, similar mitigations are not currently available for public-facing use cases, leaving RPs dependent on the sharing models adopted by syncable authenticator providers."*

| | Kurumsal | Tüketici |
|---|---|---|
| Güven çıpası | İnsan kaynakları kaydı, yönetici, yönetilen cihaz ile cihaz yönetimidir | Yoktur |
| Araçlar | Entra geçici erişim kodu, Okta geçici erişim kodu, cihaz yönetimi ile kurumsal kanıtlamadır | Kurtarma kodu, e-posta ya da kısa mesaj, kurtarma kişisi, kimlik tespiti ile destek kuyruğudur |
| Kanıtlama | NIST kurumların uygulamasını önermektedir | NIST, kanıtlamanın bulunmayışının kamuya açık uygulamalarda senkronize edilebilir kimlik doğrulayıcıların kullanımını engellememesi gerektiğini söylemektedir |
| Kurtarma hızı | Onaylı geçici erişim koduyla dakikalardır | Apple'da günler, Google kurtarma kişisinde yedi artı yedi gün, Microsoft'ta 30 gündür |
| Ana risk | Yardım masası sosyal mühendisliğidir | E-posta ya da kısa mesaj ele geçirme ile SIM değiştirmedir |

#### 9.1 Entra kimlik geçici erişim kodu, parametreler

learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass adresindedir.

| Ayar | Varsayılan | İzin verilen aralık |
|---|---|---|
| Asgari ömür | Bir saat | 10 dakika ile 30 gün arası |
| Azami ömür | Sekiz saat | 10 dakika ile 30 gün arası |
| Varsayılan ömür | Bir saat | 10 dakika ile 30 gün arası |
| Tek kullanımlık | Kapalıdır | Açık ya da kapalı |
| Uzunluk | 8 | 8 ile 48 karakter arası |

Amacı Microsoft'un kendi ifadesiyle şudur: geçici erişim kodu, bir kullanıcı güçlü bir kimlik doğrulama yöntemini kaybettiğinde ya da unuttuğunda kurtarmayı kolaylaştırmaktadır.

Kritik kısıtlar şunlardır. Kullanıcı başına yalnızca bir kod olabilmektedir. Tek kullanımlık kodla parolasız yöntem kaydı 10 dakika içinde tamamlanmalıdır. Kod oturumunda verilen token'ların ömrü kodun bitişiyle sınırlıdır; ancak kodun süresinin dolması zaten kurulmuş oturumları geriye dönük iptal etmemektedir. Kod oluşturma, silme ile görüntüleme rolleri ayrıdır ile hiçbiri kendisi için kod oluşturamamaktadır. Kod bir kullanıcının parolasının yerine geçmemektedir. Dış misafirlere verilememektedir.

Argus için model şudur: geçici erişim kodu, yardım masasının hesabı devretmediği yalnızca hesaba dar bir pencere açtığı fikrinin ürünleşmiş hâlidir. Argus'ta karşılığı bir kurtarma yetkisi nesnesidir: kim verdi, hangi gerekçeyle, ne kadar geçerli, kaç kullanımlık, hangi işlemleri açıyor, ki yalnızca kimlik doğrulayıcı bağlamadır, ile verildiği anda hedef kullanıcıya bant dışı bildirim gönderiliyor mu.

---

### 10. Kurtarma: veri modeli ile durum makinesi

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

Geçiş kuralları şunlardır.

| Geçiş | Koşul | Yan etki |
|---|---|---|
| Başlangıçtan talep edildi durumuna | Kurtarma başlatılmıştır | Kurtarma kanalı hariç tüm bildirim adreslerine bildirim gitmekte ile hız sınırı sayacı artmaktadır. İncelenecek bir kötüye kullanım vardır: yalnızca e-posta adresini bilen biri bu geçişi tekrarlayarak bildirim ürettirebilmekte ile hız sınırı bütçesini tüketip durum makinesini kısıtlanmış ya da kilitli duruma itebilmektedir. Bu bir oturum hizmet reddi değildir, çünkü oturum iptali yalnızca reddedildi durumunda ile kanıt kapısının arkasındadır; bu, kurtarmanın engellenmesidir ile meşru kullanıcının gerçekten ihtiyacı olduğunda yolu kapatabilmektedir. Ayrı bir sınır gerekmektedir |
| Talep edildiden kanıt sağlandıya | Güvence seviyesine göre gereken kanıt kombinasyonu sağlanmıştır | Kullanılan kanıt sınıfları kaydedilmektedir |
| Kanıt sağlandıdan soğumaya | Soğuma süresi kanıt gücü, hesap değeri ile risk skorunun bir fonksiyonudur ile sıfırdan büyüktür | İkinci bildirim gitmektedir: şu tarihte tamamlanacaktır, siz değilseniz iptal ediniz |
| Soğumadan reddedildiye | Kullanıcı iptal bağlantısına tıklamıştır ya da mevcut bir kimlik doğrulayıcıyla giriş yapmıştır | Kurtarma girişimi iptal edilmekte, kurtarma yolları dondurulmakta ile bir güvenlik olayı üretilmektedir. Oturum iptali bu geçişin otomatik bir yan etkisi değildir; kurtarma girişimini iptal etmekle mevcut oturumları topluca iptal etmek ayrı güvenlik eylemleridir. İkincisi ayrı bir gerekçe ile yetki koşuluyla, kanıt gücüne bağlı olarak tetiklenmelidir; birincinin sessiz yan etkisi olarak bağlanmamalıdır |
| Yeniden bağlama açıldıya | Soğuma süresi dolmuştur | Oturum açılmakta ancak yalnızca kimlik doğrulayıcı bağlama yetkisiyle |
| Yeniden bağlamadan ek süreye | En az bir kimlik doğrulayıcı bağlanmıştır | Tam oturum verilmekte ancak kurtarma ek süresi alanı dolu olmaktadır |
| Ek süreden kapalıya | Ek süre dolmuştur | Kısıtlar kalkmaktadır |

Apple'ın kullanıcı giriş yaparsa kurtarma iptal olur davranışı, soğumadan reddedildiye geçiştir ile kopyalanmalıdır: meşru sahibin normal girişi devam eden kurtarmayı otomatik iptal etmelidir. Bu, hiçbir kullanıcı eylemi gerektirmeyen bir savunmadır.

#### 10.2 Veri modeli önerisi

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
  -- ana invariant — DURUMA KOŞULLU
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

Bu kısıt, kurtarmanın korunan şeyden zayıf olamayacağı ilkesini bir yorum satırından bir veritabanı kısıtına çevirmektedir.

Ancak tek başına yetmemektedir; satırın son hâlini kontrol etmek, o hâle doğrulanmış bir kanıttan gelindiğini ispatlamamaktadır. Yetki açan işlem tek bir atomik birimde şunları yapmalıdır: mevcut durumu doğrula, kanıtın geçerliliğini doğrula, kanıtı tüket ile yeni yetkiyi oluştur. Kanıt tüketilmeden yetki üretilirse iki eşzamanlı istek aynı kanıtı kullanabilmektedir; kabul testi de tam olarak budur, yani aynı kanıtla paralel iki yeniden bağlama denemesi. Geçişlerin yalnızca ekleme yapılan kaydı denetlenebilirlik sağlamaktadır, geçiş doğruluğu sağlamamaktadır; geçiş kaydı geçiş denetiminin yerine geçmemelidir.

#### 10.3 Argus'un ayrışma noktaları, kurtarma

| Sıra | Ayrışma | Neden rakiplerde yoktur |
|---|---|---|
| 1 | Kurtarma yapılandırılabilir bir akış değil tipli bir durum makinesidir ile adım silinerek atlatılamamaktadır | Keycloak'ın 40744 numaralı konusu, akıştan adım silmenin bir kimlik doğrulama atlatması ürettiğini göstermektedir. Genel amaçlı bir akış motoru bunu yapısal olarak engelleyememektedir |
| 2 | Sağlanan güvence seviyesinin gerekenden küçük olmaması değişmezi şemada zorlanmaktadır | Hiçbir kimlik sağlayıcı kurtarma yolunun güvence seviyesini modellememekte ile dolayısıyla karşılaştıramamaktadır |
| 3 | Bağımsızlık grubu vardır; aynı senkronizasyon dokusundaki iki geçiş anahtarı tek bir kimlik doğrulayıcı sayılmaktadır | NIST birden fazla kimlik doğrulayıcı bağla demekte ancak hiçbir ürün bağımsızlığı ölçmemektedir |
| 4 | Hesabın etkin güvenliği, tüm yolların güvence seviyelerinin en küçüğü olarak yönetim konsolunda gösterilmektedir | Kimse en zayıf yolu raporlamamaktadır |
| 5 | Kanıt gücüne ters orantılı ile riske duyarlı soğuma süresi kullanılmaktadır, sabit değil | Google riske dayalı yapmaktadır ancak açık kaynak kimlik sağlayıcılarda yoktur |
| 6 | Bildirim kanalının kurtarma kanalından farklı olması kuralı şemada zorunludur | NIST kuralıdır; ürünlerin çoğu ihlal etmektedir |
| 7 | Asistanlı kurtarma kapatılabilmektedir, yani Apple kurtarma anahtarı modeli, kalıcı kayıp riski açıkça onaylatılarak | Yalnızca Apple sunmaktadır; hiçbir kimlik sağlayıcı ürünü sunmamaktadır |
| 8 | Kurtarma yetkisi nesnesi vardır, yani Entra geçici erişim kodu eşdeğeri; yardım masası hesabı devretmez pencere açar | Keycloak'ta yoktur; Okta'da özel rol kurgusuyla elle inşa edilmektedir |
| 9 | Normal giriş, devam eden kurtarmayı otomatik iptal etmektedir | Apple yapmaktadır; kimlik sağlayıcı ürünlerinde yoktur |
| 10 | Kurtarma ile katılımın yeniden tetiklenme oranı bir güvenlik metriğidir | Unit 42'nin Ağustos 2026 tarihli doğrudan tavsiyesidir; hiçbir üründe yoktur |

---

## Bölüm II — Hesap bağlama ile birleştirme

### 11. Ön ele geçirme: hesap daha var olmadan ele geçirilir

Kaynak doğrulanmış ile yaygın bir atıf hatası düzeltilmiştir: ön ele geçirilmiş hesaplar, web'de kullanıcı hesabı oluşturmadaki güvenlik başarısızlıklarının ampirik bir incelemesi; bağımsız araştırmacı Avinash Sudhodanan, Microsoft Güvenlik Yanıt Merkezi hibesiyle, ile Microsoft Güvenlik Yanıt Merkezi'nden Andrew Paverd; USENIX Security 2022, Boston, 10 ile 12 Ağustos 2022. PDF usenix.org/system/files/sec22-sudhodanan.pdf adresindedir; arXiv numarası 2205.10174'tür, 20 Mayıs 2022; Microsoft Güvenlik Yanıt Merkezi blog yazısı 23 Mayıs 2022 tarihlidir.

İki yaygın hata vardır. Birincisi, bu çalışmanın Ohio State ile ilgisi yoktur; karışıklık muhtemelen üzerine inşa ettiği Ghasemisharif ile arkadaşlarının USENIX Security 2018 çalışmasından gelmektedir. Ayrıca Microsoft Research değil Güvenlik Yanıt Merkezi'dir. İkincisi, rakamlar sürekli karıştırılmaktadır: 75 servis test edilmiş, 35 servis zafiyetli çıkmış, 56 ayrı zafiyet bulunmuş ile 252 saldırı denemesi yapılmıştır.

Tehdit modeli şudur: saldırgan sıradan bir web saldırganıdır ile kurbanın yalnızca e-posta adresini bilmektedir. Üç faz vardır: ön ele geçirmede kurban daha hesap açmamışken saldırgan hareket etmekte; kurban eyleminde kurban hesabı oluşturmakta ya da kurtarmakta; saldırı fazında saldırgan erişimi geri almaktadır.

#### 11.1 Beş varyant

Birincisi klasik ile federe birleştirmedir. Saldırgan kurbanın e-postasıyla klasik, yani e-posta ile parola kaydı yapmaktadır. Kurban sonra federe yoldan gelmektedir. Servis e-posta eşleşmesiyle birleştirmektedir. Son durumda e-posta kurbanın, parola saldırganın ile kimlik sağlayıcı kurbanınkidir. Saldırgan parolayla, kurban çoklu oturum açmayla girmekte ile ikisi de aynı hesaba ulaşmaktadır.

İkincisi süresi dolmayan oturumdur. Saldırgan hesabı açmakta, giriş yapmakta ile oturumu süresiz canlı tutmaktadır, ki betiklenebilir bir canlı tutma çağrısıdır. Kurban kayıt olamamakta, parolayı sıfırlamakta ile kullanmaya başlamaktadır. Servis parola sıfırlamada diğer oturumları düşürmüyorsa hem saldırganın hem kurbanın oturumu yaşamaktadır. En yaygın varyanttır, yani 74 potansiyele karşı 19 fiilî vakadır, çünkü federasyon hiç gerekmemektedir.

Üçüncüsü truva tanımlayıcısıdır. İlk ikisinin birleşimidir. Saldırgan klasik hesabı açmakta ile kendi federe kimliğini ona bağlamaktadır. Kurban parolayı sıfırlamakta ancak saldırganın kimlik sağlayıcı bağı hayatta kalmaktadır. Alternatif tanımlayıcı varyantında saldırgan kendi telefonunu ya da ikinci e-postasını eklemekte, sonra oradan parola sıfırlama ya da tek kullanımlık giriş bağlantısıyla dönmektedir. Makale, benzer görünen adres seçmeyi açıkça bir aldatma tekniği olarak saymaktadır.

Dördüncüsü süresi dolmayan e-posta değişimidir. Saldırgan hesabı açmakta, e-posta değişimini başlatmakta ancak onaylamamaktadır. Kurban parolayı sıfırlamakta ile kullanmaktadır. Saldırgan sonra hâlâ geçerli olan yetenek adresine tıklamakta, e-posta artık saldırganın olmakta ile parola sıfırlama tetiklenmektedir. Ön koşul e-posta değişim bağlantısının günlerce geçerli olması ile parola sıfırlamayla iptal edilmemesidir.

Beşincisi doğrulamayan kimlik sağlayıcıdır. Birincinin ayna görüntüsüdür. Saldırgan, e-posta sahipliğini doğrulamayan bir kimlik sağlayıcı kullanarak kurbanın e-postasını taşıyan bir federe kimlik üretmekte; kurban sonra klasik kayıt olmakta ile servis birleştirmektedir. Makale iki ismi açıkça vermektedir: *"We found that these [IdPs] did not perform email verification for test accounts, yet these accounts could still be used as federated identities at other services."* Söz konusu sağlayıcılar OneLogin ile Okta'dır. Müşterilerin kendi kimlik sağlayıcısını getirebildiği her kurumsal plan bu yüzeydedir.

Altıncı bir teknik daha vardır: e-posta doğrulama hilesi. Saldırgan kendi doğrulanmış e-postasıyla kayıt olmakta, sonra birincil e-postayı kurbanınkiyle değiştirmektedir. Servis yeni adresi doğrulamadan bağlıyorsa, kayıtta zorunlu doğrulama olsa bile yukarıdaki her saldırı yeniden mümkün olmaktadır. Kayıtta e-posta doğruluyoruz savunmasının neden yetmediği budur.

#### 11.2 Yaygınlık, Tablo 3, test penceresi Ocak ile Haziran 2021

| Saldırı | Potansiyel | Zafiyetli |
|---|---|---|
| Klasik ile federe birleştirme | 54 | 13 |
| Süresi dolmayan oturum | 74 | 19 |
| Truva tanımlayıcısı | 49 | 12 |
| Süresi dolmayan e-posta değişimi | 72 | 11 |
| Doğrulamayan kimlik sağlayıcı | 3 | 1 |
| Toplam | 252 | 56 |

İsimli vakalar şunlardır. Dropbox süresi dolmayan e-posta değişimiyle etkilenmiştir, HackerOne, Haziran 2021. Instagram truva tanımlayıcısıyla, alternatif tanımlayıcı varyantıyla etkilenmiştir. LinkedIn süresi dolmayan oturum ile truva tanımlayıcısıyla etkilenmiş ile parola değişiminde aktif oturumları düşürmeyi varsayılan yapmıştır. Wordpress.com HackerOne'da uygulanamaz işaretlenmiştir; kendi barındırılan WordPress etkilenmemiştir, çünkü her eylemden önce e-posta doğrulaması istemektedir. Zoom klasik ile federe birleştirmeden etkilenmiştir, çünkü ücretsiz hesaplar doğrulama istemekte ancak ücretli hesap oluşturma istememekteydi; ayrıca doğrulamayan kimlik sağlayıcı saldırısından da etkilenmiştir, araştırmacılar OneLogin kullanmıştır. Zoom ikisini de yüksek önemde kabul edip düzeltmiştir.

#### 11.3 Bu sınıf hâlâ canlıdır: better-auth, Haziran 2026

GHSA-qq9h-g4jm-xgf3, yayın 26 Haziran 2026, CVSS 8.3 yüksek; bir güvenlik açığı numarası atanmamıştır. Etkilenen sürümler 1.1.3 ile 1.6.22 arası ile 1.7.0 beta sürümlerinin ilk onudur.

Mekanizma şudur: saldırgan kurbanın adresiyle e-posta ile parola kaydı yapmakta ile hesap doğrulanmamış kalmaktadır. Kurban sonra sihirli bağlantı ya da e-posta tek kullanımlık şifresiyle girmekte; bu, e-postayı doğrulanmış işaretlemekte ancak ne saldırganın parolasını silmekte ne de önceki oturumları iptal etmektedir.

Uyarının kendi cümlesi şudur: *"A password set before anyone proved control of the mailbox kept working after the owner proved control."*

Düzeltmede e-posta doğrulaması otoriter kabul edilmiştir: önceden var olan parola silinmekte, oturumlar iptal edilmekte, adres doğrulanmış işaretlenmekte ile taze bir oturum verilmektedir.

Argus için kural şudur: sahiplik kanıtı geldiğinde, o kanıttan önce oluşturulmuş her kimlik bilgisi ölmektedir. Bu bir tercih değil bir değişmezdir.

#### 11.4 Makalenin kendi azaltma seti

Kök neden iddia edilen tanımlayıcının sahipliğinin doğrulanmamasıdır; genelde doğrulama eşzamansız yapılmakta ile hesap bu arada kullanılabilir olmaktadır. Çözüm doğrulama tamamlanmadan hiçbir hesap eylemine izin vermemektir. Kimlik sağlayıcıya güveniliyorsa, sağlayıcının doğrulamayı yaptığına dair güçlü bir garanti talep edilmelidir.

Parola sıfırlamada üç şey yapılmalıdır: diğer tüm oturumlar ile kimlik doğrulama token'ları düşürülmeli; bekleyen tüm e-posta değişim işlemleri iptal edilmeli; ile kullanıcıya bağlı federe kimlikler, alternatif e-postalar ile telefonlar gösterilip hangilerini tutacağı açıkça seçtirilmelidir, varsayılan bağı kopar olmalıdır. Makale bunu tanımadıklarını işaretle yaklaşımına tercih etmektedir, çünkü kullanıcılar uyarıları görmezden gelmektedir.

Birleştirmede kural birebir şudur: *"the service must ensure that the user currently controls both accounts. For example, when the user attempts to create an account via the federated route but a classic account already exists for the same email address, the user should be required to provide or reset the password for the classic account."*

E-posta değişim onaylarında yetenek geçerliliği asgariye indirilmeli ile aynı doğrulanmamış tanımlayıcıya yeniden yetenek üretimi hız sınırlanmalıdır.

Doğrulanmamış hesaplar agresif budanmalı ile tanımlayıcı başına tekrar oluşturma sınırlanmalıdır; ancak makale bunun hizmet reddi riskini işaretlemekte, yani saldırgan meşru kullanıcının kotasını tüketebilmektedir, ile sert kota yerine bot tespiti önermektedir.

Çok faktörlü kimlik doğrulama için kural birebir şudur: *"the service must also invalidate any sessions created prior to the activation of MFA"*. Aksi hâlde çok faktörlü doğrulama süresi dolmayan oturum saldırısını durdurmamaktadır.

---

### 12. Her iki e-posta da doğrulanmış olması yeterli midir? Hayır.

#### 12.1 OIDC Core 1.0'ın 5.7 bölümü, normatif kaynak, birebir

Şartname ikinci hata düzeltme kümesini içermektedir, 15 Aralık 2023.

> "The `sub` (subject) and `iss` (issuer) Claims from the ID Token, used together, are the only Claims that an RP can rely upon as a stable identifier for the End-User… Therefore, the only guaranteed unique identifier for a given End-User is the combination of the `iss` Claim and the `sub` Claim.
>
> All other Claims carry no such guarantees… For instance, an Issuer MAY re-use an `email` Claim Value across different End-Users at different points in time…
>
> Therefore, other Claims such as `email`, `phone_number`, `preferred_username`, and `name` MUST NOT be used as unique identifiers for the End-User, whether obtained from the ID Token or the UserInfo Endpoint."

Doğrulanmış e-posta iddiasının tanımı, 5.1 bölümünden, birebir şudur.

> "True if the End-User's e-mail address has been verified… this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context specific…"

Kritik okuma şudur: doğrulanmış e-posta iddiası bir ana dair bir ifadedir, yani doğrulamanın yapıldığı ana, ile kontrolünüzde olmayan bir tarafça yapılmaktadır. Kalıcı bir sahiplik kanıtı değildir; şartname e-postanın farklı kullanıcılar arasında yeniden kullanımına açıkça izin vermektedir.

#### 12.2 Sağlayıcılar arası gerçek durum

SlashID'nin sağlayıcı bazında taraması, 18 Ocak 2024, Joseph Gardner, slashid.com/blog/sso-safe-email-claim adresindedir.

| Sağlayıcı | Doğrulama sinyali |
|---|---|
| Google | Her zaman doğrulanmıştır |
| Microsoft ile Entra | `xms_edov` iddiasıdır, Haziran 2023'te eklenmiştir |
| Okta | Kullanıcı bilgisi uç noktasında doğrulanmış e-posta iddiasıdır |
| Apple | Kimlik token'ında doğrulanmış e-posta iddiasıdır |
| GitHub | API'de birincil ile doğrulanmış alanlarıdır |
| GitLab | API vardır ancak doğrulanmış e-posta alanı yoktur; kullanıcı doğrulamayı atlayabilmektedir |
| Bitbucket | Birincil ile onaylanmış alanları vardır, semantiği belirsizdir |
| LINE | Doğrulanmış e-posta alanı yoktur |
| Facebook | Doğrulanmış e-posta alanı yoktur |

Sonucu birebir şudur: *"It is unsafe to rely on the Issuer to verify the email of a user."*

#### 12.3 Satıcı kılavuzları

Auth0 şunları söylemektedir: hesapları güvensiz biçimde bağlamak kötü niyetli aktörlerin meşru kullanıcı hesaplarına erişmesine izin verebilmektedir; hem elle hem otomatik bağlamalarda kiracı, bağlama gerçekleşmeden önce her iki hesap için de kimlik doğrulama talep etmelidir; ile her elle hesap bağlaması kullanıcıya kimlik bilgisi girmesini istemelidir.

Keycloak'ın ilk aracı girişi akışı şu sırayla çalışmaktadır: profili gözden geçir, benzersizse kullanıcı oluştur, mevcut hesabı bağlamayı onayla, mevcut hesabı e-postayla ya da yeniden kimlik doğrulamayla doğrula; ayrıca isteğe bağlı olarak mevcut kullanıcıyı otomatik ayarla adımı bulunmaktadır. Kendi uyarısı birebir şudur: *"Automatically linking the existing local account to the external identity provider is a potential security hole. You cannot always trust the information you get from the external identity provider."* Otomatik bağlama doğrulayıcısı için ise kullanıcıların kendilerini keyfî kullanıcı adlarıyla ya da e-posta adresleriyle kaydedebildiği genel bir ortamda tehlikeli olduğunu söylemektedir. Kimlik sağlayıcı başına e-postaya güven ayarı açıkken Keycloak, sağlayıcının e-posta iddiasını doğrulanmış saymakta ile kendi doğrulamasını atlamaktadır. Bu, Keycloak'ı doğrulamayan kimlik sağlayıcı saldırısının kurbanı yapan tek düğmedir.

Clerk yayımlanmış en net karar matrisine sahiptir. Varsayılan varsayımı her e-posta adresi için tek bir sahip olduğudur. İkisi de doğrulanmışsa anında bağlanmakta, parola korumalı hesaplarda bile. Clerk'te doğrulanmış ancak OAuth sağlayıcıda doğrulanmamışsa Clerk kendi doğrulamasını yapmakta, sonra bağlamaktadır. Clerk'te doğrulanmamışsa, yani hesap doğrulanmamış bir e-posta ile parolayla açılmışsa ile şimdi doğrulanmış bir OAuth e-postası geliyorsa, Clerk bağlamadan önce parola değişimini zorunlu kılmaktadır, çünkü hesabın asıl sahipliğini teyit edememektedir. Bu, klasik ile federe birleştirmenin ürünleşmiş azaltmasıdır.

Firebase'in varsayılanı e-posta başına tek hesaptır; çoklu hesap tercihe bağlıdır. Açıldığında uygulamanın giriş akışı bir kullanıcı hesabını tanımlamak için e-posta adresine dayanamamakta ile açılır pencere ve yönlendirme tabanlı giriş ile bağlama çağrıları sağlayıcı profil bilgisi döndürmeyi bırakmaktadır. Ayardan bağımsız değişmez şudur: kullanıcılar aynı e-posta adresi ile aynı giriş yöntemiyle asla birden fazla hesap oluşturamamaktadır.

#### 12.4 Argus'un güvenli bağlama koşul seti

1. E-posta doğrulanmış olmalıdır ile bu bağlı tarafın kendi kayıtlarında olmalıdır; gelen kimlik sağlayıcının iddiası yetmemektedir.
2. Gelen kimlik sağlayıcı açık bir güvenilir doğrulayıcı izin listesinde olmalıdır. Kendi kimlik sağlayıcısını getiren ya da özel sağlayıcılara asla toptan güvenilmemelidir; bu, kelimenin tam anlamıyla doğrulamayan kimlik sağlayıcı saldırısıdır.
3. Bağlama anında mevcut hesabın kontrolünün kanıtı istenmelidir: parola tekrarı, zaten bağlı bir sağlayıcıyla yeniden kimlik doğrulama ya da mevcut adrese onay e-postası.
4. Mevcut hesap doğrulanmamış ya da atıl durumdaysa, federe ya da parolasız giriş otoriter bir sahiplik kanıtı sayılmalı ile önceki kimlik bilgisi yok edilmelidir; better-auth'un düzeltmesi ile Clerk'ün zorunlu parola değişimi budur.
5. Bağlama anında tüm diğer oturumlar ile bekleyen e-posta değişimleri iptal edilmelidir, yalnızca parola sıfırlamada değil.
6. Birleştirme anahtarı olarak veren ile özne çifti saklanmalı ile e-posta yalnızca bir arama ipucu olarak tutulmalıdır.
7. Gelen tarafın doğrulamadığı bir e-postayla asla otomatik bağlama yapılmamalı; doğrulamayan ya da saldırganın kontrol edebileceği bir veren üzerinden asla otomatik bağlama yapılmamalıdır.

---

### 13. Özne tanımlayıcısına karşı e-posta ile tanımlayıcı geri dönüşümü

#### 13.1 nOAuth: e-postayı anahtar yapmanın gerçek bedeli

Keşfi Descope'a aittir, 20 Haziran 2023, descope.com/blog/post/noauth adresindedir.

Mekanizma şudur: herhangi bir Entra kimlik kiracısını kontrol eden saldırgan, tek kullanımlık bir kullanıcının posta niteliğini kurbanın e-posta adresine ayarlamaktadır. Kullanıcıları özne ya da nesne kimliği yerine e-postayla anahtarlayan çok kiracılı bir bulut uygulaması, Microsoft ile giriş yap akışında saldırgana kurbanın hesabını vermektedir. Parola yoktur, çok faktörlü doğrulama istemi yoktur; çok faktörlü doğrulama ile koşullu erişim işe yaramamaktadır, çünkü kimlik doğrulamanın kendisi meşrudur.

Zaman çizelgesi şudur: Microsoft'a bildirim 11 Nisan 2023, iddia dokümantasyonunun güncellenmesi 18 Nisan 2023, düzeltmeler ile Güvenlik Yanıt Merkezi blog yazısı 20 Haziran 2023. Yeni bir e-posta alan adı sahibi doğrulandı iddiası ile doğrulanmamış e-posta iddiasını kaldıran bir uygulama bayrağı eklenmiştir. Bir güvenlik açığı numarası atanmamıştır.

Güvenlik Yanıt Merkezi'nin kendi ifadesi, 20 Haziran 2023 tarihli Azure kimlik uygulamalarında ayrıcalık yükseltme riski yazısında, şudur: karşı desen erişim token'larındaki e-posta iddiasının yetkilendirme için kullanılmasıdır; bir saldırgan uygulamalara verilen token'lardaki e-posta iddiasını tahrif edebilmektedir; kök neden ise posta kutusu tanımlanmamış dizin kullanıcılarının birincil posta niteliklerine herhangi bir e-posta adresi ayarlanabilmesi ile bunun doğrulanmış bir adresten geldiğinin garanti edilmemesidir.

İki yıl sonra hâlâ canlıdır: Semperis'in Haziran 2025 tarihli araştırmasına göre test edilen 104 bulut uygulamasından dokuzu zafiyetlidir ile tahminen 15.000 uygulama açıktır. Semperis'in en can alıcı tespiti şudur: savunmacının, bir uygulamanın doğrulanmamış e-posta iddiasını tüketip tüketmediğine dair hiçbir görünürlüğü yoktur; tek çare satıcıya baskı yapmak ya da uygulamayı terk etmektir.

Bir ölü adres uyarısı gerekmektedir: e-posta iddiası yetkilendirmesinden göç rehberinin adresi artık Entra merkez sayfasına yönlenmektedir, 8 Eylül 2026'da doğrulanmıştır. İlgili iddia için canlı referans Entra isteğe bağlı iddialar referans sayfasıdır.

#### 13.2 Kimler tanımlayıcı geri dönüştürmektedir

Google Workspace, yani yönetici kontrollü ortam, kurumsal tasarım için en önemli vakadır.

> *"Twenty days after a user's account is deleted, their email address is removed from Google Workspace."*
> *"However, you can reassign the address to another managed user before that 20-day period ends."*
> *"If you plan to use the email address for an unmanaged personal Google Account, you must wait 30 days to prevent account conflicts."*

Yani bir Workspace yöneticisi aynı e-posta adresini başka bir insana verebilmekte ile rutin olarak vermektedir. Google'ın kendi sorun giderme dokümanı, silinip yeniden oluşturulan kullanıcının farklı bir Google tanımlayıcısı aldığını doğrulamaktadır; takvim bildirimlerinin kesilmesinin sebebi budur. Google'ın kendi tavsiyesi sil ile yeniden oluştur yönteminden kaçınmaktır.

Pratik sonuç şudur: aynı e-posta, farklı özne tanımlayıcısı. E-postayla anahtarlayan bağlı taraf, ayrılan çalışanın hesabını sessizce yerine gelene devretmektedir. Özne tanımlayıcısıyla anahtarlayan bağlı taraf onu doğru şekilde yeni bir insan saymaktadır. Özne tanımlayıcısı argümanının tamamı budur.

Google tüketici hesapları tarafında kural şudur: iki yıllık bir dönemde kullanılmayan hesap atıl sayılmakta ile Google, tüm hizmetlerinde en az iki yıl atıl kalan bir hesabı silme hakkını saklı tutmaktadır. Silme için en erken tarih 1 Aralık 2023'tür. Bir doğrulanamayan iddia vardır: Google bir hesabı sildikten sonra o adresle yeni hesap açılamayacağı iddiası çok tekrarlanmakta ancak resmî destek sayfasının metninde bulunamamıştır. Bu iddia yazılmamalıdır. Buna karşılık özne tanımlayıcısının asla yeniden kullanılmadığı garantisi Google'ın geliştirici dokümanlarında açıkça yazılıdır; atıf için o kullanılmalıdır.

Microsoft Entra kimlik tarafında geri dönüşüm Workspace'le aynı şekilde mümkündür, yani yönetici kullanıcı asıl adını yeniden oluşturmaktadır; ek olarak posta niteliği varsayılan olarak keyfî ile doğrulanmamıştır. Kararlı tanımlayıcılar nesne kimliği ile kiracı kimliği çiftidir ya da uygulama ve kullanıcı başına ikili özne tanımlayıcısıdır.

GitHub'da kullanıcı adı geri dönüşümü açıkça dokümantedir: kullanıcı adı 90 gün sonra herkesin kullanımına açılmaktadır. İstisnalar, yani sahip ile depo adı kombinasyonunun kalıcı emekliye ayrılması, ad alanında GitHub Marketplace eylemi olan bir açık depo bulunması ya da silinmeden önceki hafta yüzden fazla klon veya yüzden fazla eylem kullanımı olmasıdır. Konteyner imajlarında beş binden fazla indirmede kalıcı emeklilik uygulanmaktadır. Dolayısıyla GitHub'da kullanıcı adıyla asla anahtarlama yapılmamalıdır; kararlı anahtar sayısal kimliktir.

Bir doğrulanamayan nokta daha vardır: Slack ile Okta için açık bir yeniden kullanım garantisi, olumlu ya da olumsuz, birincil dokümanlarda bulunamamıştır. İddia edilmemelidir.

---

### 14. Birleştirme: geri alınamazlık, çakışma ile denetim

Auth0 klasik yıkıcı birleştirmenin en net dokümante örneğidir. Bağlamada ikincil nitelikler profil verisine taşınmakta, ikincil hesabın kullanıcı ile uygulama metadata'sı imha edilmekte ile ikincil hesap kullanıcı listesinden kaldırılmaktadır. Bağ koparıldığında ikincil hesap birincil hesabın kimlikler dizisinden çıkarılmakta ile yeni bir ikincil kullanıcı hesabı oluşturulmaktadır; kritik cümle şudur: *"The secondary account will have no metadata."* Yani bağlama ile bağ koparma bir gidiş dönüş değildir. Metadata bağlama anında yok edilmekte ile geri getirilememektedir. Birleştirmenin geri alınamazlığının kesin ile atıf verilebilir örneği budur. Bir kimliği tamamen kaldırmak için önce bağ koparılmalı, sonra yeni oluşan ikincil hesap silinmelidir.

Atlassian'da yönetim konsolunda bir hesap birleştirme aracı bulunmaktadır ancak beta aşamasındadır ile yalnızca katılımcı organizasyonlara açıktır. Genel kendin yap birleştirmenin uzun süredir yokluğunu açık özellik talepleri doğrulamaktadır. Topluluk kılavuzları organizasyon birleştirmelerinin geri alınamaz olduğunu ile otomatik bir ayırma bulunmadığını söylemektedir; bu bir topluluk kaynağıdır, ikincildir.

GitHub hesap birleştirme sunmamaktadır; dokümante yol depoları transfer edip fazla hesabı silmektir. Bir birleştirme uç noktası yoktur.

Bir doğrulanamayan nokta vardır: Stripe ile Google için iki hesabı birleştir başlıklı birincil bir doküman bulunamamıştır. Bu ürünlerin birleştirme özelliği olduğu iddia edilmemelidir. Stripe'ın muadili ilkeller ekip rolleri ile organizasyon üyeliğidir, hesap birleştirme değildir.

Tasarım sonucu şudur: endüstrinin açığa vurulmuş tercihi birleştirmenin ya hiç olmaması, ya kalıcı beta olması, ya destek kanalıyla kapılı olması, ya da kayıplı ile geri alınamaz olmasıdır. Argus için dürüst çerçeve şudur: geri alınabilir ile eklemeli olan bağlama, yıkıcı olan birleştirmeye tercih edilmelidir. Birleştirme kaçınılmazsa yazmadan önce her iki kaynak kaydın anlık görüntüsü alınmalı, her iki kaynak kimliği ile operatör kimliğini taşıyan bir birleştirme denetim olayı yazılmalı ile işlem tek yönlü kabul edilmelidir.

### 15. Bağ koparma: son kimlik doğrulama yöntemi koruması

Clerk değişmezi doğrudan ifade etmektedir: her kullanıcının en az bir kimlik doğrulama tanımlayıcısı bulunmaktadır, ki e-posta adresi, telefon numarası ya da kullanıcı adı olabilir.

Auth0'da dikkat çekici bir olumsuz bulgu vardır: bağ koparma dokümantasyonunda kilitlenme ya da son kimlik doğrulama yönteminin kaldırılması hakkında hiçbir uyarı yoktur. Sorumluluk tamamen uygulamadadır.

Firebase'de bağ koparma sağlayıcı bazında bulunmakta ile platform seviyesindeki koruma dolaylıdır.

Keycloak'ta hesap konsolu federe kimlik bağını koparmaya izin vermektedir; koruma yerel parolanın ya da başka bağlı bir sağlayıcının kalmasıdır. Açıkça dokümante edilmiş bir son kimlik bilgisi kaldırılamaz zorlaması bulunamamıştır ile doğrulanamamıştır.

Sentez şudur ve bir araştırma boşluğu değil gerçek bir bulgudur: son kimlik doğrulama yöntemi koruması dört üründe de büyük ölçüde uygulama katmanı sorumluluğudur, kimlik sağlayıcı tarafından zorlanan bir değişmez değildir. Clerk buna en yakın olandır. Argus bunu şema seviyesinde zorlarsa gerçek bir ayrışma noktası olmaktadır.

### 16. E-posta değişimi ile eski posta kutusunun başkasına geçmesi

Kurumsal posta kutusu devri bir istisna değil dokümante ile desteklenen bir davranıştır; 13.2'deki Google Workspace 20 günlük yeniden atama penceresi buna örnektir. Ayrılan çalışanın adresi meşru şekilde başka birinin adresi olabilmekte ile o e-postayla anahtarlayan her bağlı taraf hesabı yanlış kişiye atfetmektedir.

Süresi dolmuş alan adı devralmasının akademik dayanağı Lauinger ile arkadaşlarının USENIX Security 2017'deki kayıt kuruluşları oyunu çalışmasıdır. Kritik istatistik şudur: tüm .com alan adlarının yaklaşık %10'u, eski kaydın silindiği gün otomatik yakalama servisleri tarafından yeniden kaydedilmektedir. Terk ile düşmanca kontrol arasındaki pencere fiilen sıfırdır.

Saldırı zinciri şudur: süresi dolmuş alan adı yeniden kaydedilmekte, yakala hepsini posta sunucusu kurulmakta ile o alan adını kullanan her bulut hesabında parola sıfırlama tetiklenmektedir. PortSwigger'ın haber sitesi tam olarak bunu belgelemiştir; araştırmacılar bir hukuk bürosunun ofis ile çalışma alanı hesaplarına, oradan gizli belgelere ulaşmıştır.

Azaltmalar şunlardır: veren ile özne çiftine bağlanmalı; yüksek değerli hesaplar için e-posta sahipliği periyodik yeniden doğrulanmalı; alan adının posta değişim kaydı ya da tescil değişimi bir yeniden doğrulama tetikleyicisi sayılmalı; ile ayrıcalıklı hesaplarda parola sıfırlama için yalnızca e-posta bağlantısı değil yükseltilmiş kimlik doğrulama istenmelidir.

#### 16.1 Kavramın adı: odak ile izdüşüm

Bu bölümün tamamı tek bir ayrımın etrafında dönmektedir ancak ayrımın adı konmamıştır. Kimlik yönetişimi tarafında adı vardır ile Evolveum'un midPoint'inde otuz yıllık bir modeldir, kaynak kendi mimari dokümanıdır, erişim 13 Eylül 2026.

Odak, yetkili kimlik nesnesidir. İzdüşüm, o kimliğin bir hedef sistemdeki hesabıdır. Eşleme ise ortak kimlik veri modelinin değerlerini hedef sistemin yerel niteliklerine dönüştüren mekanizmadır. midPoint'in model alt sistemi tüm etkinliklerin geçtiği yerdir; politika uygulama, eksik veri tamamlama, nitelik eşleme ile kimlik ilişkilendirme mantığı oradadır.

Argus bir yönetişim ürünü değildir ile olmamalıdır. Yine de ayrımın adının konması bu bölümdeki üç problemi tek bir çerçeveye oturtmaktadır. On birinci bölümdeki ön ele geçirme, izdüşümün odaktan önce yaratılmasıdır. On üçüncü bölümdeki tanımlayıcı geri dönüşümü, izdüşümün kimliğinin yeniden kullanılmasıdır. Bu bölümdeki posta kutusu devri ise eşlemenin girdisinin, yani e-posta adresinin, odağın değil izdüşümün özelliği olduğunun unutulmasıdır.

Buradan çıkan tek cümlelik kural şudur ile zaten on ikinci bölümün koşul setinin gerekçesidir: bir izdüşümün hiçbir niteliği odağın birincil anahtarı olarak kullanılamaz. E-posta, kullanıcı adı ile telefon numarası izdüşüm nitelikleridir; hepsi yukarı akış sisteminin kontrolündedir ile hepsi geri dönüştürülebilmektedir. Odağın kimliği yalnızca Argus'un ürettiği ile hiçbir yukarı akış sistemine bağlı olmayan bir değer olabilmektedir.

---

## Bölüm III — Kimliğe bürünme, yani kullanıcı olarak giriş

### 17. RFC 8693: kimliğe bürünmeyle devretme arasındaki fark bir tasarım kararıdır

Künyesi şudur: RFC 8693, Ocak 2020, standartlar yolu. Yazarları Microsoft'tan M. Jones ile A. Nadalin, Ping Identity'den editör B. Campbell, Yubico'dan J. Bradley ile Visa'dan C. Mortimore'dur. Yetki tipi token değişimidir.

#### 17.1 Birinci bölümün birinci alt bölümü, birebir

> "When principal A impersonates principal B, A is given all the rights that B has within some defined rights context and is indistinguishable from B in that context. Thus… insofar as any entity receiving such a token is concerned, they are actually dealing with B. It is true that some members of the identity system might have awareness that impersonation is going on, but it is not a requirement."

> "Delegation semantics are different… With delegation semantics, principal A still has its own identity separate from B, and it is explicitly understood that while B may have delegated some of its rights to A, any actions taken are being taken by A representing B. In a sense, A is an agent for B."

> "Delegation semantics are typically expressed in a token by including information about both the primary subject of the token as well as the actor… Such a token is sometimes referred to as a composite token."

Argus için tasarım dersi şudur: kimliğe bürünme olarak inşa edilmiş bir kullanıcı olarak giriş özelliği, tanım gereği kaynak sunucuda atfedilemezdir; kaynak sunucu operatörü kullanıcıdan ayırt edememektedir. Devretme olarak inşa edilmiş olan, operatörün kimliğini token'da tutmakta ile her sıçramada denetlenebilir olmaktadır. RFC 8693, kimliğe bürünmenin kimlik sistemine görünür olmasının bile gerekmediğini söylemektedir. Dolayısıyla destek araçları kimliğe bürünme semantiği değil devretme semantiği kullanmalıdır.

#### 17.2 Eylemde bulunan iddiası, 4.1, birebir

> "The `act` (actor) claim provides a means within a JWT to express that delegation has occurred and identify the acting party to whom authority has been delegated… For example, the combination of the two claims `iss` and `sub` might be necessary to uniquely identify an actor."

> "However, claims within the `act` claim pertain only to the identity of the actor and are not relevant to the validity of the containing JWT… Consequently, non-identity claims (e.g., `exp`, `nbf`, and `aud`) are not meaningful when used within an `act` claim and are therefore not used."

Kanonik destek kimliğe bürünme şekli, yani şartnamenin beşinci şekli, şöyledir; token kullanıcı hakkındadır ile eylemde bulunan iddiası yöneticiyi adlandırmaktadır.

```json
{ "aud":"https://consumer.example.com", "iss":"https://issuer.example.com",
  "exp":1443904177, "nbf":1443904077,
  "sub":"user@example.com",
  "act": { "sub":"admin@example.com" } }
```

İç içe zincirler için kural birebir şudur.

> "The outermost `act` claim represents the current actor while nested `act` claims represent prior actors. The least recent actor is the most deeply nested."

> "For the purpose of applying access control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim. Prior actors identified by any nested `act` claims are informational only and are not to be considered in access control decisions."

#### 17.3 Eylemde bulunabilir iddiası, rızanın standart yeri, 4.4, birebir

> "The `may_act` claim makes a statement that one party is authorized to become the actor and act on behalf of another party. The claim might be used, for example, when a `subject_token` is presented to the token endpoint in a token exchange request and `may_act` claim in the subject token can be used by the authorization server to determine whether the client… is authorized to engage in the requested delegation or impersonation."

```json
{ "aud":"https://consumer.example.com", "iss":"https://issuer.example.com",
  "sub":"user@example.com",
  "may_act": { "sub":"admin@example.com" } }
```

Eylemde bulunan ile eylemde bulunabilir iddiaları, token içgözlem yanıtında üst düzey üye olarak döndüğünde aynı semantiğe sahiptir.

Eylemde bulunabilir iddiası, kullanıcının kimliğe bürünmeye rızasını kodlamak için standart yerlisi yerdir; ön yetkilendirme ifadesi öznenin kendi token'ında taşınmaktadır. Bu, Salesforce'un giriş erişimi verme modeliyle birebir örtüşmektedir.

#### 17.4 Yaşam döngüsü uyarısı, 2.1, birebir

> "the act of performing a token exchange has no impact on the validity of the subject token or actor token… the exchange is a one-time event and does not create a tight linkage between the input and output tokens"

Yani iptal otomatik olarak yayılmamaktadır. Bir kimliğe bürünme oturumunun nasıl öldürüleceği sorusunun cevabı standartta yoktur; Argus'un kendi bağını kurması gerekmektedir.

Güvenlik değerlendirmeleri bölümü birebir şunu söylemektedir: *"Any time one principal is delegated the rights of another principal, the potential for abuse is a concern. The use of the `scope` claim (in addition to other typical constraints such as a limited token lifetime) is suggested to mitigate potential for such abuse."*

### 18. Kimliğe bürünme altında ne yasak olmalıdır

Normatif bir RFC ya da OWASP listesi yoktur; bu, satıcı ile uygulayıcı uzlaşısıdır. Kaynaklar arasında yakınsayan küme şudur.

Tutarlı şekilde engellenenler şunlardır: parolanın ya da herhangi bir kimlik doğrulama kimlik bilgisinin değiştirilmesi; çok faktörlü yöntemin kaydı, kaldırılması ya da sıfırlanması; birincil e-posta ya da telefon değişimi; hesap silme ile her türlü yıkıcı ya da toplu silme; ödeme ile faturalama işlemleri; toplu veri dışa aktarımı; rol yükseltme, izin verme ile yeni kullanıcı davet etme; ile yeni API anahtarı veya uzun ömürlü token oluşturma.

Tutarlı şekilde zorunlu kılınanlar şunlardır: kısa oturum, ki uygulayıcı literatüründe 10 ile 15 dakika, WorkOS'ta 60 dakika ile Okta destek erişiminde sekiz saattir; bürünülen arayüzde görünür ile kalıcı bir bilgi şeridi; oturum başında zorunlu gerekçe kaydı; başlangıçta ile bitişte ayrı denetim olayları, artı eylem başına özneye değil operatöre atıf; okuma yollarında bile hassas alanların maskelenmesi; ile bürünülen kullanıcıya bildirim.

### 19. Ürünler, özellik özellik

Salesforce kullanıcı rızasının referans uygulamasıdır. Varsayılanı kullanıcının izin vermesidir: son kullanıcı kişisel ayarlarından, açık bir erişim süresi seçicisiyle giriş erişimi vermektedir. Organizasyon bunu yöneticiler herhangi bir kullanıcı olarak giriş yapabilir ayarıyla ezebilmekte ile bu, rıza gereksinimini kaldırmaktadır. Başkası olarak girilmişken yapılan eylemler kurulum denetim izinde ile giriş geçmişinde, eylemi yapan yöneticinin kullanıcı adıyla kaydedilmektedir. Bu, eylemde bulunabilir iddiası modelinin ürünleşmiş hâlidir: rıza öznede yaşamakta, zaman sınırlı olmakta ile geri alınabilmektedir. Bir not gerekmektedir: Salesforce yardım sayfaları tek sayfa uygulaması olarak işlenmekte ile çekicilere hata kabuğu döndürmektedir; birebir alıntı çıkarılamamıştır. Adres kaynak gösterilmeli ancak birebir alıntı yapılmamalıdır.

Okta'da genel bir yönetici kullanıcı olarak giriş özelliği yoktur; dar ile rıza kapılı bir destek varyantı vardır. Var olan, destek vakasına bağlı salt okunur kimliğe bürünme erişimidir. Erişim doğrudan bir destek vakasına bağlanmakta ile yalnızca vakayla ilişkili Okta destek ekibi üyeleri erişebilmektedir. Onay gerekmektedir: organizasyonun süper yöneticisi ile vakayı açan yönetici. Otomatik bildirim yoktur; destek mühendisi onayı doğrudan istemelidir. Süre varsayılan sekiz saattir ile bir bağlantıyla 24 saat uzatılabilmektedir. Açıkça salt okunurdur ile müşteri verisini değiştirememektedir. Sistem günlüğü denetim olayları bulunmaktadır. Taramadaki en iyi tasarlanmış rıza modelidir: vakaya bağlı, çift onaylayıcılı, zaman kutulu, salt okunur ile günlüklüdür.

ServiceNow en güçlü zorlanan kısıtlama modelidir. Güvenlik merkezi sertleştirme ayarı kimliğe bürünmeyi yöneticiyle sınırlamaktadır. Zorlanan davranışlar şunlardır: bürünülürken bürünülen kullanıcıdan tüm kapsam korumalı roller ile şifreleme bağlamı rolleri kaldırılmakta; bir uygulama yöneticisi rolü olan kullanıcıya bürünen yönetici o rolün verdiği özelliklere erişememekte; ile bürünenin kendi yönetici ayrıcalıkları askıya alınmakta, yani yönetici modülleri ile yükseltilmiş eylemler kapanmaktadır. Süre boyunca kırmızı bir bilgi şeridi gösterilmektedir. Ayrı bir bürünme rolü gerekmektedir. Bu konudaki en değerli tasarım deseni budur: ayrıcalık kesişimi, ayrıcalık birleşimi değil. Bürünülmüş oturum ne yöneticinin haklarını ne de hedefin tam haklarını almaktadır.

GitLab en iyi denetim olayı modelidir. Kimliğe bürünme varsayılan olarak açıktır ile örnek genelinde kapatılabilmektedir. Oturum boyunca sağ üstte bir durdurma düğmesi bulunmaktadır. Başlangıç ile bitiş için ayrı denetim olayları, ayrıca bürünen yöneticinin kimliğini taşıyan eylem başına denetim olayları üretilmektedir. Bunlar hem örnek denetim olaylarında hem kullanıcının üyesi olduğu her grubun grup denetim olaylarında görünmektedir. Microsoft Sentinel'de GitLab kimliğe bürünmesi için hazır bir tespit kuralı bile bulunmaktadır. Canlı bir tartışma vardır: kullanıcıların yöneticinin kendilerine bürünmesini yasaklayabilmesi talebi hâlâ açıktır.

Zendesk'in kimlik varsayma özelliği zayıf kontrollere sahiptir ile öğretici bir karşı örnektir. Bir yönetici ya da kullanıcı profillerini düzenleme izni olan herhangi bir temsilci, bir son kullanıcının kimlik bilgilerini üstlenebilmektedir. Yalnızca son kullanıcılar varsayılabilmekte, temsilciler varsayılamamaktadır. Kritik zayıflık birebir şudur: *"any actions you take, such as creating a ticket or adding a comment to a ticket, are done by the user you're logged in as."* Yani eylemler temsilciye değil kurbana atfedilmektedir; tam olarak RFC 8693'ün kimliğe bürünme semantiği problemidir. Son kullanıcı bildirimi dokümante değildir, dokümanda bir güvenlik uyarısı yoktur ile özel bir denetim izi ifadesi bulunmamaktadır. Zendesk'in kendi personeline karşı müşteri kontrolü yönetim merkezindeki hesap varsayma ayarıdır; varsayılan kapalıdır, her an geri alınabilmekte ile süre seçenekleri bir gün, bir hafta, bir ay, bir yıl ya da süresizdir. Süresiz seçeneği eleştirilmeyi hak etmektedir. Bir not gerekmektedir: kullanıcı olarak oynat ifadesi Zendesk rehber ile topluluk terminolojisidir ile kimlik varsaymayla aynı özellik değildir; karıştırılmamalıdır.

Shopify kimliğe bürünme yerine kapsamlı, rızalı ile kendiliğinden sona eren bir kimlik vermektedir. İş ortağı istek göndermekte, mağaza sahibi e-posta ile ana ekran bildirimi almakta ile istekler yedi gün geçerli olmaktadır. Dört haneli bir iş birlikçi istek kodu vardır; yalnızca kodu bilen iş ortağı istek gönderebilmekte ile mağaza sahibi kodu yenileyerek dolaşımdaki bilgiyi geçersiz kılabilmektedir. Onay anında uygulama ile kanal bazında granüler izinler verilmektedir. 90 gün girişsizlikte erişim kendiliğinden sona ermektedir. Yani Shopify'ın kullanıcı olarak giriş cevabı şudur: yapmayın; onun yerine kapsamlı, rızalı ile kendiliğinden sona eren bir kimlik verin.

WorkOS modern ile standartla hizalı referans uygulamaya en yakın olandır; workos.com/blog/support-impersonation-delegated-sessions, 25 Ağustos 2026. Dört kontrolü vardır. Birincisi her iki kimlik de token'dadır: özne bürünülen kullanıcı, eylemde bulunan destek temsilcisidir; açıkça RFC 8693 izlenmektedir. İkincisi organizasyon kapsamlıdır: kullanıcı birden çok organizasyona üyeyse temsilci kiracı bağlamını seçmek zorundadır. Üçüncüsü zaman sınırlıdır: oturumlar 60 dakikada otomatik sona ermekte ile API ile daha kısası mümkün olmaktadır. Dördüncüsü aktör, hedefler ile metadata taşıyan, müşterinin bağımsızca sorgulayabildiği tam bir denetim izidir. Varsayılan kapalıdır ile organizasyon seviyesinde tercihe bağlıdır. Zorunlu gerekçe alanı oturum oluşturma olayına kaydedilmektedir. Ayrı denetim olayları devredilmiş girişleri standart kimlik doğrulamadan ayırmaktadır.

Auth0'da özellik kullanımdan kaldırılmıştır. Eski uç nokta yalnızca küresel istemci kimlik bilgileriyle kullanılabilmekteydi. Bürünülen kullanıcının profiline bürünülmüş ile bürünen nitelikleri yazılmaktaydı, ki gömülü bir denetim mekanizmasıdır. Kiracı bayrağıyla kapatılabilmekteydi. Auth0 personelinden Gerald Czifra'nın 31 Temmuz 2025 tarihli forum yanıtı şunu söylemektedir: eski kimliğe bürünme özelliğinin kullanımdan kaldırılması güvenlik kaygıları yaratmıştı. Daha eski bir personel yanıtı, 23 Şubat 2023, kimliğe bürünmenin desteklenmediğini söylemektedir. Önerilen ikame ayrı bir yardım masası uygulamasıdır: yalnızca yöneticilere açık bir uygulama metadata bayrağı, özel token iddiaları ile bir API ara katmanı; ara katman, başka bir hesap adına hareket eden yardım masası temsilcisini kendisi olarak kimlik doğrulayan kullanıcıdan ayırmalıdır. Kesin bir kullanımdan kaldırma tarihi bulunamamıştır. Özellik Auth0'ın resmî kullanımdan kaldırma ile göç sayfasında yer almamaktadır; kontrol edilen diğer kayıtlar kurallar ile kancaların 18 Kasım 2026, Node 12 ile 16'nın 15 Ağustos 2025, Azure dizin birinci sürümünün 1 Eylül 2025, eski bağlantı istemci listesinin 13 Temmuz 2026 ile üçüncü taraf uygulama kontrollerinin 23 Ekim 2026 kullanım sonu tarihleridir. Belirli bir tarih yazılmamalıdır.

Discourse'ta kimliğe bürünme özelliği bulunmaktadır. Günlükleme talebi 2014'ten beri açıktır ile bürünülen kullanıcının bilgilendirilmesi talebi hâlâ açıktır; özneyi bilgilendir kontrolünün endüstride en az uygulanan kontrol olduğunun kanıtıdır. Özyinelemeli kimliğe bürünme ayrı bir açık hata sınıfıdır ile iç içe eylemde bulunan iddialarıyla paraleldir.

İki not gerekmektedir. Grafana'da kullanıcı kimliğe bürünmesi yoktur; dokümanlarındaki bürünme tamamen BigQuery veri kaynakları için Google Cloud servis hesabı bürünmesidir ile farklı bir kavramdır, iddia edilmemelidir. Stripe'taki panoyu şu olarak görüntüle özelliği yalnızca bağlantı platformundan bağlı hesaba doğrudur ile genel bir kimliğe bürünme değildir. Kendi dokümanı uyarmaktadır: tam panoya erişmeyen bağlı hesaplar için yine de tam pano görülmekte ile görülen şey bağlı hesabın gördüğünün tam bir temsili olmamaktadır. Yani şu olarak görüntüle sadakat doğru değildir. Stripe'ın modeli rollerdir, örneğin iade yapabilen ancak ayar değiştiremeyen destek uzmanı rolü. Stripe'ta rıza kapılı geçici destek erişimi özelliği bulunamamıştır; iddia edilmemelidir.

#### 19.1 Özet matris

| Ürün | Kullanıcı rızası | Bilgi şeridi | Süre sınırı | Denetim | Eylem kısıtı |
|---|---|---|---|---|---|
| Salesforce | Vardır, varsayılandır; kullanıcı verir ile sürelidir | Vardır | Vardır, erişim süresi seçicisiyle | Vardır; kurulum denetim izi ile giriş geçmişi | Profil ile izinler üzerindendir |
| Okta destek varyantı | Vardır; çift onaylayıcılı ile vakaya bağlıdır | Yoktur | Vardır; varsayılan sekiz saat, 24 saat uzatılabilir | Vardır; sistem günlüğü | Vardır; salt okunurdur |
| WorkOS | Organizasyon seviyesinde tercihe bağlıdır, kullanıcı bazında değil | Vardır | Vardır; 60 dakika | Vardır; artı zorunlu gerekçe | Önerilmektedir, zorlanmamaktadır |
| ServiceNow | Yoktur | Vardır; kırmızıdır | Yoktur | Vardır | Vardır; en güçlüdür, roller sıyrılmakta ile yönetici askıya alınmaktadır |
| GitLab | Yoktur | Vardır; durdurma düğmesidir | Yoktur | Vardır; başlangıç, bitiş ile eylem başınadır | Yoktur |
| Zendesk | Yalnızca Zendesk personeli için vardır | Yoktur | Yalnızca Zendesk personeli için vardır | Zayıftır; eylemler kurbana atfedilmektedir | Yalnızca son kullanıcılardır |
| Shopify | Vardır; artı dört haneli koddur | Yerine göre değişmektedir | Vardır; yedi günlük istek ile 90 günlük atalet | Vardır | Vardır; kapsamlı izinlerdir |
| Stripe | Yoktur; platformdan bağlı hesabadır | Yoktur | Yoktur | Vardır | Sadakat doğru değildir |
| Discourse | Yoktur | Vardır | Yoktur | Tarihsel olarak yoktur | Yoktur |
| Auth0 | Yoktur | Yoktur | Yoktur | Profile bayrak yazmaktadır | Yoktur; özellik kaldırılmıştır |

### 20. Suistimal olayları

#### 20.1 Twitter, 15 Temmuz 2020, en iyi belgelenmiş vaka

Birincil kaynak New York Finansal Hizmetler Dairesi'nin Ekim 2020 tarihli Twitter soruşturma raporudur. Bir finansal düzenleyicinin iç araç suistimalini incelediği nadir bir belgedir.

Araçların yetenekleri birebir şöyle anlatılmaktadır.

> *"Some of the internal tools include nonpublic information about each Twitter user account, including the account's associated email address, phone number, and the… IP address for the user's login location. In response to user requests, authorized Twitter employees use the internal tools, in part, to update email addresses, reset forgotten or expired passwords, or enable or disable multifactor authentication ('MFA')."*

Yani 18. kısımdaki yasak olmalı listesindeki her işlem bu araçlarda bulunmaktaydı.

Erişim ölçeği birebir şöyledir.

> *"Twitter did limit access to the internal tools, but over 1,000 Twitter employees still had access to them… Immediately after the Twitter Hack, however, Twitter further limited the number of employees with access to the internal tools, even though it caused a slowdown of some job functions."*

Eksik olan kontroller, ki en alıntılanabilir kısımdır, birebir şöyledir.

> *"Authentication requirements should also be calibrated to match the risk… Access to critical functions should require MFA. Another possible control for high-risk functions is to require certification or approval by a second employee before the action can be taken. An approval requirement can limit the damage if an attacker compromises one employee's access."*

Yani kimliğe bürünme için dört göz onayı bir finansal düzenleyici tarafından tavsiye edilmektedir.

Vektör sesli kimlik avıdır: saldırganlar çalışanları arayıp Twitter'ın bilgi teknolojileri departmanındaki yardım masasından aradıklarını iddia etmiştir. Uygulama tabanlı anlık bildirimli çok faktörlü doğrulama, çalışanlar istemi onaylamaya ikna edilerek yenilmiştir; daire donanım güvenlik anahtarı önermektedir. Saldırgan 17 yaşında bir korsan ile suç ortaklarıdır; kayıp 118 binden fazla dolarlık bitcoindir. Twitter'ın saldırıdan yedi ay önce, Aralık 2019'dan beri bir bilgi güvenliği yöneticisi bulunmamaktaydı.

#### 20.2 Okta, Ekim 2023, destek sistemi ihlalidir, kimliğe bürünme özelliğinin suistimali değildir

İlk ele geçirme yaklaşık 28 Eylül 2023'te olmuş, Okta 13 Ekim'de tespit etmiş ile 19 Ekim'de kamuya açıklamıştır; yetkisiz dosya erişimi 28 Eylül ile 17 Ekim arasındadır.

Mekanizma şudur: çalınan kimlik bilgisiyle Okta destek vaka yönetim sistemine girilmiş, müşterilerin sorun giderme için yüklediği tarayıcı ağ kaydı dosyaları canlı oturum token'ları içermiş ile parolasız ve çok faktörsüz oturum ele geçirme yapılmıştır.

Ölçek şudur: başlangıçta müşterilerin yaklaşık %1'i, yani yaklaşık 184 organizasyon bildirilmiş; Okta sonradan 134 müşterinin dosyalarına erişildiğini ile beş müşteride oturum ele geçirildiğini doğrulamıştır. Üçü kendi açıklamalarını yayımlamıştır: Cloudflare, 1Password ile BeyondTrust.

Çerçevelemesi şudur: bu bir kimliğe bürünme özelliği riski değil bir destek kanalı riskidir. Ders şudur: destek araçları ile ürettikleri artefaktlar, yani ağ kaydı dosyaları, ekran görüntüleri ile günlükler, kendi başlarına ayrıcalıklı bir erişim yüzeyidir. Salesforce ile Okta tarzı rızalı kimliğe bürünmeden açıkça ayrılmalıdır.

#### 20.3 Robinhood, 3 Kasım 2021, destek sosyal mühendisliği

Saldırgan bir Robinhood destek temsilcisini telefonla arayıp uzaktan erişim yazılımı kurdurmuş ile destek sistemlerine erişmiştir. Yaklaşık beş milyon kişinin e-posta adresi, farklı bir yaklaşık iki milyonluk kümenin tam adı ile daha küçük bir grubun adı, e-postası, doğum tarihi, telefonu ile posta kodu açığa çıkmıştır; toplam yaklaşık yedi milyon kişidir. Sosyal güvenlik numarası, banka hesabı ya da kart bilgisi yoktur; müşteri finansal kaybı olmamıştır. Sonrasında şantaj talebi gelmiş ile Mandiant devreye girmiştir. Birincil kaynak 8 Kasım 2021 tarihli SEC 8-K ekidir.

### 21. Argus için kimliğe bürünme tasarımı

Temel karar şudur: kimliğe bürünme semantiği hiç uygulanmayacaktır, yalnızca devretme kullanılacaktır.

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

Zorlanan değişmezler şunlardır.

| Sıra | Değişmez | Kaynak |
|---|---|---|
| 1 | Token daima özne olarak kullanıcıyı ile eylemde bulunan olarak operatörü taşımaktadır. Bir kimliğe bürünme modu yoktur | RFC 8693 birinci bölüm |
| 2 | Ayrıcalık kesişimi uygulanmaktadır: verilen yetki, operatörün haklarıyla öznenin haklarının kesişiminin alt kümesidir. Operatörün yönetici hakları askıya alınmaktadır | ServiceNow |
| 3 | Yasak işlem listesi motor seviyesinde engellenmektedir, arayüzde değil | Twitter ile düzenleyici raporu |
| 4 | Gerekçe boş olamaz ile oturum oluşturma olayına yazılmaktadır | WorkOS |
| 5 | Mutlak yaşam süresi tavanı 60 dakikadır; uzatma yeni rıza gerektirmektedir | WorkOS |
| 6 | Başlangıç, bitiş ile eylem başına denetim olayı üretilmekte ile hepsi operatöre atfedilmektedir | GitLab |
| 7 | Özneye bildirim gönderilmektedir ile bu isteğe bağlı değildir | Discourse'un 12 yıllık açık talebi |
| 8 | Kullanıcı, organizasyon politikası izin veriyorsa kendisine bürünülmesini yasaklayabilmektedir | GitLab'ın açık talebi |
| 9 | Özyinelemeli devretme yasaktır; eylemde bulunan derinliği devredilmiş oturumlarda birdir | Discourse'un özyinelemeli bürünme hatası |
| 10 | Özne token'ında eylemde bulunabilir iddiası yoksa ile organizasyon politikası da yoksa istek reddedilmektedir | RFC 8693 4.4 |
| 11 | Devredilmiş oturum öznenin normal oturumlarını etkilememekte ile iptali ayrı yayılmaktadır | RFC 8693 2.1 uyarısı |
| 12 | Destek artefaktları ayrı bir ayrıcalık sınıfıdır; oturum token'ı içerenler otomatik olarak redakte edilmektedir | Okta, Ekim 2023 |

Bu listedeki hiçbir ürün on ikisinin hepsini yapmamaktadır. En yakın olanlar birinci, dördüncü, beşinci ile altıncı maddelerde WorkOS, ikinci ile üçüncü maddelerde ServiceNow ile rıza modelinde Okta'dır.

---

## Bölüm IV — Kullanıcı yaşam döngüsü, silme ile mezar taşı

### 22. SCIM tek başına yaşam döngüsünü ifade edememektedir

#### 22.1 RFC'lerin gerçekte söyledikleri, birebir

RFC 7644'ün 3.6 bölümü tüm mezar taşı tasarımının taşıyıcı cümlesidir.

> "Clients request resource removal via DELETE. Service providers MAY choose not to permanently delete the resource but MUST return a 404 (Not Found) error code for all operations associated with the previously deleted resource."

Başarılı bir silme 204 içerik yok dönmektedir. Şartname yumuşak silmeyi açıkça kutsamaktadır ancak 404 zorunlu kılmaktadır, 410 gitti değil. RFC 7644 hiçbir yerde 410'dan bahsetmemektedir. Sonuç şudur: mezar taşı konmuş bir kullanıcı, SCIM API'si üzerinden hiç var olmamış bir kullanıcıdan ayırt edilemez olmalıdır. 410 dönmek silinmiş bir hesabın varlığını sızdırmaktadır; bu başlı başına bir mahremiyet ifşasıdır.

RFC 7643'ün 4.1.1 bölümü aktiflik niteliğini şöyle tanımlamaktadır.

> "A Boolean value indicating the user's administrative status. The definitive meaning of this attribute is determined by the service provider. As a typical example, a value of true implies that the user is able to log in, while a value of false implies that the user's account has been suspended."

Kasıtlı belirsizliğe dikkat edilmelidir: SCIM, devre dışı bırakmanın ne anlama geldiğini tanımlamamaktadır. Her kimlik sağlayıcı kendi semantiğini icat etmektedir. Katılım, hareket ile ayrılma birlikte çalışabilirlik acısının kök nedeni budur.

Metadata nitelikleri yalnızca oluşturulma, son değişiklik, sürüm, konum ile kaynak tipidir. Çekirdek SCIM'de mezar taşı ya da silinme zamanı yoktur.

#### 22.2 SCIM çalışma grubu 2025 ile 2026: soru varsaydığından daha ileridedir

| RFC | Başlık | Tarih | Statü |
|---|---|---|---|
| RFC 9865 | SCIM kaynaklarının imleç tabanlı sayfalaması | Ekim 2025 | Önerilen standarttır |
| RFC 9944 | SCIM modeline cihaz şeması uzantıları | Mayıs 2026 | Önerilen standarttır |
| RFC 9967 | Güvenlik olayı belirteçleri için SCIM profili | Mayıs 2026 | Önerilen standarttır |

RFC 9967, SCIM olayları sorusunun cevabıdır ile artık bir taslak değil yayımlanmış bir RFC'dir. SCIM olayları taslağından gelmiş ile hem RFC 7643'ü, yani yeni servis sağlayıcı yapılandırma niteliklerini, hem RFC 7644'ü, yani isteğe bağlı eşzamansız istek yeteneğini güncellemektedir.

Tanımladığı olay tipleri doğrudan durum makinemizi ilgilendirmektedir.

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

RFC 9967 devre dışı bırakmayı silmeden ayrı tel olayları olarak ayırmaktadır. Devre dışı bırakma olayı, kaynağın devre dışı bırakıldığını ile öznenin artık aktif bir güvenlik oturumuna sahip olmayabileceğini bildirmektedir. Silme olayı kalıcı kaldırmayı bildirmekte, kaynak beslemeden de çıkarılmakta, karşılık gelen bir besleme çıkarma olayı yayımlanmamakta ile kopyalanmaya değer bir detay olarak silme olayları hiçbir yük niteliği taşımamaktadır. Yani olayın kendisi mahremiyet koruyucudur. Taklit edilmesi gereken mezar taşı deseni budur.

İki not gerekmektedir. SCIM 2.1 diye bir çalışma kalemi yoktur; aktif bir taslak yoktur ile iddia edilmemelidir. Roller ile yetkiler taslağı, yani hareket problemi için kiracı başına keşfedilebilir geçerli rol ve yetki değerleri öneren çalışma, süresi dolup arşivlenmiş ile RFC olmamıştır. Yeniden ele alınmış kullanım senaryoları taslağının da süresi dolmuştur. Yumuşak silme ya da parola yönetimi üzerine bir SCIM taslağı yoktur.

#### 22.3 Satıcı sağlama kaldırma davranışı

Okta şöyledir.

| | Devre dışı bırakma | Silme |
|---|---|---|
| Oturumlar | Kullanıcı artık oturum oluşturamamakta ile tüm aktif oturumları durdurulmaktadır | Aynıdır |
| Gruplar | Kaldırılmamaktadır; devre dışı kullanıcılar uygulamalara erişememekte ancak gruplardan çıkarılmamaktadır | Tüm gruplardan, uygulama atamalarından ile grup üyeliğiyle gelen rol atamalarından çıkarılmaktadır |
| Kimlik doğrulama faktörleri | Korunmaktadır | Devre dışı bırakılmakta ile kaldırılmaktadır |
| Geri alınabilirlik | Evet | Hayır; bir kullanıcı hesabı silindiğinde geri alınamamaktadır |
| Veri | Korunmaktadır | Müşteri verisinin kalıcı silinmesi otomatik olarak 30 gün içinde başlatılmakta; kullanıcıya atıfta bulunan veriler ise veri saklama politikasında tanımlı bir süre boyunca tutulmaktadır |

Son satır gerçek dünyadaki mezar taşıdır: Okta kullanıcıyı sert silmekte ancak referans veren veriyi, yani denetim günlüğü satırlarını, ayrı bir saklama politikası altında tutmaktadır. Bu, tam olarak GDPR 17. maddesiyle denetim saklama arasındaki ayrımın ürünleşmiş hâlidir.

Ayrıca Okta'da oturum ile token temizleme, devre dışı bırakmadan ayrı bir işlemdir; kullanıcı oturumlarını temizle komutu tüm kimlik sağlayıcı oturumlarını kaldırmakta ile isteğe bağlı olarak yenileme ve erişim token'larını iptal etmektedir. İki ayrı düğme olması bir tasarım hatasıdır; Argus'ta tek atomik bir işlem olmalıdır.

Microsoft Entra kimlikte 30 günlük bir geri dönüşüm kutusuyla yumuşak silme vardır. O 30 günlük pencere geçtikten sonra kalıcı silme süreci otomatik olarak başlamakta ile durdurulamamaktadır. Kalıcı olarak silinmiş bir kullanıcı, Microsoft müşteri desteği dahil hiç kimse tarafından geri yüklenememektedir. Mezar taşı tasarımını doğrudan ilgilendiren bilinen bir operasyonel tehlike vardır: orijinal kullanıcı yumuşak silinmiş durumdayken kullanıcı asıl adı başka bir hesaba yeniden atanabilmekte ile geri yükleme çakışmakta ya da başarısız olmaktadır. Üretimdeki tekillik kısıtı problemi budur.

Keycloak'ta iptal oturum tabanlıdır, token tabanlı değildir. Tüm aktif oturumlardan çıkış yapmak, dolaşımdaki erişim token'larını iptal etmemekte ile bu token'ların doğal olarak sona ermesi gerekmektedir. Şu andan önce geçersiz politikası, yani itmeli iptal, onları iptal edebilmekte ancak yalnızca Keycloak'ın OIDC adaptörünü kullanan istemciler için çalışmaktadır; diğer adaptörlerde çalışmamaktadır. Çevrimdışı token'lar hiç sona ermemekte ile çoklu oturum açma boşta kalma zaman aşımına tabi değildir; kullanıcı bazında ya da bir iptal politikasıyla iptal edilmeleri gerekmektedir. Keycloak'ta atıl kullanıcıları otomatik devre dışı bırakma ya da silme yoktur; 38108 numaralı konu açıktır.

OneLogin davranışı için birincil kaynağa ulaşılamamıştır; doğrulanmamıştır ile iddia edilmemelidir.

#### 22.4 Hareket eden çalışan ile ayrıcalık birikmesi: kanıt zayıftır, dikkatle kullanılmalıdır

Niteliksel mekanizma iyi tanımlanmıştır ancak hareket kaynaklı yetki birikimini izole eden titiz ile yayımlanmış bir istatistik bulunamamıştır. Aşağıdaki rakamlar araştırma değil satıcı pazarlaması olarak değerlendirilmelidir.

Mekanizma şudur: birikme iki boyutludur, yani yatay olarak daha çok sisteme ile dikey olarak aynı sistemde daha yüksek izne doğrudur, ile ikisi de rol değişiminde hızlanmaktadır. Kök nedenler tekrar talep olmasın diye geniş verme, çalışanın mevcut bir rolü kopyalaması ile transferde erişimin yerinde bırakılmasıdır; erişim kaldırmak ödüllendirilmemekte ile biraz riskli görülmektedir.

Tasarım dokümanı için tavsiye şudur: yüzdeler değil mekanizma ile düzenleyici eşikler kaynak gösterilmelidir.

#### 22.5 Yetim ile hayalet hesap istatistikleri: kaynaklandırma zayıftır, işaretlenmelidir

Orchid Security'nin 10 Ağustos 2026 tarihli raporu, metodoloji ile örneklem büyüklüğü açıklamadan başka satıcıları alıntılayan bir beyaz kâğıttır. Kuruluşların %44'ünün binden fazla yetim hesap bildirdiği, tüm hesapların %26'sının bayat olabileceği, yani 90 günden fazla kullanılmamış olduğu ile bazı kuruluşlarda bunun %90'a ulaştığı, ve 2024'teki bulut ihlallerinin %27'sinin atıl kimlik bilgisi kötüye kullanımı içerdiği iddiaları buradan gelmektedir; ilk ikisi Varonis'e, üçüncüsü Trustle'a atfedilmektedir.

Hiçbiri yayımlanmış bir metodolojiye izlenebilir değildir. Ponemon ya da Oomnitza yetim hesap raporu bulunamamıştır. Bu yüzdeler tasarım dokümanında kullanılmamalıdır.

---

### 23. Sert silme ile anonimleştirme ve mezar taşı karşılaştırması

#### 23.1 GDPR 17. madde

Silme gerekçeleri birinci fıkranın alt bentlerindedir. Denetim günlüğünü taşıyan istisnalar üçüncü fıkradadır: birlik ya da üye devlet hukuku kapsamında yasal yükümlülüğe uyum veya kamu yararı ile resmî otorite görevi; hukuki taleplerin tesisi, kullanılması ya da savunulması; ayrıca ifade özgürlüğü, halk sağlığı ile arşivleme, araştırma ve istatistik.

Güvenlik denetim günlüklerine uygulanmasında beygir hukuki taleplerin savunulması bendidir: dolandırıcılık, yetkisiz erişim ya da istihdam uyuşmazlıklarına karşı savunma için kimlik doğrulama ile yetkilendirme olaylarını tutmak. Yasal yükümlülük bendi ise sektörel hukukun saklamayı zorunlu kıldığı yerlerde geçerlidir.

Ancak hiçbiri toptan bir ruhsat değildir: istisna, o amaç için gerekli olanla sınırlıdır. Yani günlük, gerçekten o amaca hizmet eden alanlara asgariye indirilmelidir; takma adlı denetim kimlikleri argümanı tam olarak budur.

#### 23.2 ICO ile kullanım dışı bırakma, yedekler

ICO'nun dört parçalı testi şudur; veri fiilen silinmemiş olsa bile kullanım dışı bırakılmış sayılması için veri sorumlusu şunları yapmalıdır.

1. Kişisel veriyi herhangi bir bireye ilişkin herhangi bir kararı bilgilendirmek için kullanmamalı ya da kullanmaya teşebbüs etmemelidir.
2. Başka hiçbir organizasyona erişim vermemelidir.
3. Veriyi uygun teknik ile organizasyonel güvenlikle çevrelemelidir.
4. Mümkün olduğunda ya da olduğu anda kalıcı silmeyi taahhüt etmelidir.

Yedeklere uygulanmasında ICO, yedek verinin hemen üzerine yazılamadığı durumlarda bile kullanım dışı bırakılmışsa tatmin olmaktadır; veri yalnızca yerleşik bir takvime göre değiştirilene kadar sistemlerde tutulmaktadır. ICO ayrıca veri sorumlularının bireylere, silme talepleri yerine getirildiğinde verilerine ne olacağı konusunda, yedekleme sistemleri dahil, kesinlikle açık olmasını vurgulamaktadır.

ICO'nun kendi sayfası otomatik çekime 403 döndürmektedir; ifade arama sonuçlarından kurtarılmıştır ile yayımlamadan önce canlı sayfaya karşı doğrulanmalıdır.

Tasarım sonucu şudur: kullanım dışı bırakma, mezar taşı ile kripto parçalama mimarisinin hukuki dayanağıdır. Mezar taşının dört ayağı da karşılaması gerekmektedir; özellikle birinci ayak, mezar taşının asla kişi hakkında bir kararı beslememesi anlamına gelmektedir, yani risk skorlaması ile dolandırıcılık listesi olmamalıdır; dördüncü ayak ise süresiz saklama değil zamanlanmış gerçek bir silme işi gerektirmektedir.

#### 23.3 CNIL ile günlük saklama

14 Ekim 2021 tarihli 2021-122 sayılı karardır. Altı ay iddiası yarı doğrudur. CNIL'in temel çizgisi düz altı ay değil altı ay ile bir yıl arası bir aralıktır.

> "une journalisation permettant d'assurer une traçabilité des accès et des actions des différents utilisateurs habilités à accéder aux systèmes d'information pour une durée comprise entre six mois et un an"

Belgelenmiş iç kontrol tedbirleriyle üç yıla kadar, gerekçelendirilmiş hâllerde daha uzun süre uzatılabilmektedir. Daha uzun saklamaya izin veren istisnalar yasal yükümlülük, yani düzenlenmiş sektörler; özellikle yüksek risk, yani hassas işleme ile kritik operatörler; ve izlerin dondurulmasını gerektiren süregelen bir olay ya da davadır.

#### 23.4 Düzenleyici uygulama, 2026'nın en önemli gelişmesi

Avrupa Veri Koruma Kurulu'nun 2025 koordineli uygulama çerçevesi silme hakkını ele almıştır. Raporun adı veri sorumlularının silme hakkını uygulaması ile kabul tarihi 18 Şubat 2026'dır.

Ölçek 32 denetim otoritesi ile 764 veri sorumlusudur; küçük ve orta ölçekli işletmeden çok uluslusuna, kamu ile özel sektörü kapsamaktadır.

Bu tasarımı doğrudan vuran bulgular şunlardır. Yedeklerde silme, veri sorumluları için temel zorluk olarak işaretlenmiştir. Bazı veri sorumlularının silme taleplerini karşılamak için silme yerine verimsiz anonimleştirme tekniklerine dayanması, denetim otoritelerince açıkça bir başarısızlık modu olarak adlandırılmıştır; bu, zayıf bir silmek yerine anonimleştir mezar taşına karşı doğrudan bir uyarıdır. Ayrıca saklama sürelerini belirlemede zorluk, iç prosedür eksikliği ile veri öznesine yetersiz şeffaflık bulguları vardır.

Takibinde dokuz denetim otoritesi resmî soruşturma açmış ile yirmi üçü olgu tespiti yürütmüştür; İrlanda, Fransa, Portekiz, Slovenya ile Almanya'da süreç devam etmektedir.

Silmeme cezalarına örnek olarak Hamburg denetim otoritesi bir tahsilat şirketine, borçlu verisini yasal silme sürelerinin ötesinde, bazı vakalarda hukuki dayanaksız beş yıla kadar tuttuğu için 900.000 avro ceza vermiştir.

#### 23.5 Anonimleştirme ile takma adlaştırma

Çalışma grubunun 10 Nisan 2014'te kabul ettiği 05/2014 sayılı görüşü, her tekniğin değerlendirilmesi gereken üç parçalı bir sağlamlık testi tanımlamaktadır: tek başına ayırma, bağlanabilirlik ile çıkarım. Takma adlaştırma anonimleştirme değildir; bağlanabilirliği azaltmakta ancak GDPR kapsamından çıkarmamaktadır. Bu yüzden özetlenmiş kullanıcı kimliği taşıyan bir mezar taşı takma adlıdır, anonim değildir ile kapsamda kalmaktadır.

Kurulun 17 Aralık 2024'te kabul ettiği 28/2024 sayılı yapay zekâ modelleri görüşü, anonimlik eşiğinin en güncel otoriter ifadesidir: tanımlanma olasılığının, veri sorumlusu ya da üçüncü bir taraf tarafından makul olarak kullanılması muhtemel tüm araçlarla ihmal edilebilir olması gerekmektedir ile bu vaka bazında değerlendirilmektedir. Bu, geri çevrilebilir ya da anahtarı saklanan bir dönüşümün anonim olduğu argümanını kapatmaktadır.

#### 23.6 Kripto parçalama, pratik desen

Satırlar değil kullanıcı başına anahtar yok edilmektedir.

Mimarisi şudur: kullanıcı başına bir veri şifreleme anahtarıyla zarf şifreleme kullanılmakta, kişisel veri alan seviyesinde şifrelenmekte ile silme, anahtarın imhası olmaktadır. Kişisel verinin veritabanlarına, analitik tablolarına, yedek anlık görüntülerine, günlük dosyalarına, önbelleklere ile veri ambarı dışa aktarımlarına yayılmış olması probleminde her kopyayı bulmanın operasyonel olarak acı verici ile hataya açık olmasını çözmektedir.

Denetim günlüğü uzlaştırması buradaki kilit içgörüdür: bütünlük özetleri şifreli metin üzerinden hesaplanmalıdır. Böylece özet zinciri sağlam ile doğrulanabilir kalırken düz metin hesaplamalı olarak kurtarılamaz hâle gelmektedir. Bütünlük ile gizlilik birbirinden ayrışmaktadır.

Kopyalanmaya değer operasyonel detay şudur: anahtar imhası gecikmesi bir güvenlik özelliğidir; varsayılan 30 günlük bir pencere ile yapılandırılabilir asgari 24 saat kullanılmaktadır.

Bir uyarı gerekmektedir: kripto parçalama, kullanım dışı bırakma testinin altında savunulabilir ile anonimleştirme ikamesinden güçlüdür; ancak koordineli uygulama raporu, denetim otoritelerinin artık bu tekniklerin gerçekten etkili olup olmadığını aktif olarak sorguladığını göstermektedir. Anahtar imha kanıtı belgelenmelidir.

---

### 24. Mezar taşı tasarımı: kimlik ile e-posta yeniden kullanımı

#### 24.1 E-posta yeniden kullanımı: Google asla demektedir

Gmail'in birincil kaynağı support.google.com/mail/answer/61177 adresidir.

> "Your Gmail address can't be used by anyone in the future."

Kurtarma penceresi şudur: Gmail e-postaları ile ayarları 30 gün sonra silmektedir; adres o dönemde kurtarılabilmektedir.

Doğru sayfanın kaynak gösterilmesi gerekmektedir. Google'ın atıl hesap politikası sayfası iki yıl kuralını ile 1 Aralık 2023 başlangıç tarihini doğrulamakta ancak adres yeniden kullanımı konusunda sessizdir. Yeniden kullanım ifadesi Gmail silme sayfasında yaşamaktadır, atıllık sayfasında değil. Bu, 13.2'deki doğrulanamayan iddianın doğrulanmış hâlidir.

#### 24.2 Yahoo 2013, kanonik uyarı hikâyesi

Yahoo atıl kullanıcı kimliklerini geri dönüştürmüştür; talep son tarihi 14 Temmuz 2013'tür.

Sonuç tam olarak parola sıfırlama devralma riskidir: geri dönüştürülmüş kimliklerin yeni sahipleri, önceki sahibe yönelik e-postaları almıştır, kişisel veriler dahil; eleştirmenler parola sıfırlamalarıyla gerçek kimlik devralma potansiyelini işaretlemiştir. Yahoo'nun azaltmaları, yani geri dönen iletiler, toplu abonelik iptalleri ile yeni bir posta başlığı, dönemin haberlerine göre pratikte başarısız olmuştur.

O başlık gerçek bir standarda dönüşmüştür: RFC 7293, alıcının şu tarihten beri geçerli olması gereken başlık alanı ile posta servisi uzantısı, Temmuz 2014, standartlar yolu.

> "This document defines an extension for SMTP called 'RRVS' to provide a method for senders to indicate to receivers a point in time when the ownership of the target mailbox was known to the sender. This can be used to detect changes of mailbox ownership and thus prevent mail from being delivered to the wrong party."

Motivasyon metni tam senaryoyu adlandırmaktadır: bir şirketteki istihdam değişiklikleri, eski bir çalışan için kullanılan adresin yeni bir çalışana atanmasına yol açabilmektedir; hassas vaka ise hesap özetleri ya da parola değiştirme talimatları gibi otomatik üretilmiş mesajlardır.

Tasarım çıkarımı şudur: kimlik sağlayıcı, yeniden atanmış olabilecek bir kurumsal adrese hesap kurtarma postası gönderiyorsa bu standart, standartlaşmış azaltmadır. Bu da kimlik sağlayıcının e-posta bağlaması başına bir posta kutusu sahiplik başlangıcı zaman damgası tutması gerektiği anlamına gelmektedir.

#### 24.3 GitHub, vahşi doğadaki en iyi belgelenmiş mezar taşı

GitHub bir sahip ile depo ad alanını yeniden adlandırma ya da hesap silme sırasında kalıcı olarak emekliye ayırmaktadır; ancak bu, ad alanı Marketplace eylemi olan bir açık depo içeriyorsa ya da önceki hafta yüzden fazla klon veya yüzden fazla eylem kullanımı varsa geçerlidir.

Emekliye ayrıldıktan sonra ad kalıcı olarak kilitlenmektedir; orijinal sahip bile yeniden kullanamamaktadır. O adı içeren yeniden kullanım, transfer ile yeniden adlandırmalar kullanıcılar ile organizasyonlar genelinde engellenmektedir. Yalnızca GitHub personeli, nadiren, hukuki ya da güvenlik gerekçesiyle geçebilmektedir.

Gerekçe açıkça kimliğe bürünme ile yazım hatası alan adı karşıtlığıdır, yani tedarik zinciri bağımlılık karışıklığıdır.

Çalınacak tasarım fikri riske katmanlı emekliliktir. GitHub her ad alanını sonsuza kadar mezara koymamakta, yalnızca kanıtlanmış aşağı akış bağımlılığı olanları koymaktadır. Kimlik sağlayıcı için ucuz analog şudur: bir kez bile verilmiş bir token'da, dış bir federasyon doğrulamasında ya da denetim açısından anlamlı bir yetkide görünmüş tanımlayıcılar kalıcı olarak mezara konulmalı; hiç aktive edilmemiş hazırlanmış hesapların tanımlayıcılarının yeniden kullanımına izin verilmelidir.

#### 24.4 Slack: tekillik kısıtı kullanıcıya görünen bir hata olarak

Slack'te devre dışı bırakma geri alınabilir ile profil, mesajlar ile dosya yüklemeleri Slack veritabanında kalmaktadır. Daha önce devre dışı bırakılmış birini yeniden davet etmek şu hatayı üretmektedir.

> "This person is already in your workspace, but their account is deactivated"

Yani Slack, devre dışı bırakılmış, yani mezara konmuş kayıtlara karşı bir tekillik kısıtı zorlamakta ile bunu kullanıcıya görünür kılmaktadır. Bu, tekillik kısıtının üretim sistemlerinde veritabanı katmanında zorlandığının kanıtıdır.

#### 24.5 Argus için sentez

Kullanıcı kimliği koşulsuz olarak asla yeniden kullanılmamalıdır. SCIM kimliği, her aşağı akış denetim kaydında, güvenlik olayı öznesinde ile token öznesinde birleştirme anahtarıdır. RFC 9967'nin silme olayının hiçbir yük niteliği taşımaması modeldir; hayatta kalan tek şey tanımlayıcıdır.

E-posta için üç uygulanabilir strateji vardır ile risk katmanına göre seçilmelidir.

1. Asla yeniden kullanmamak, yani Google Gmail modelidir; en güvenlidir ancak sınırsız mezar taşı büyümesi getirmektedir.
2. Özetlenmiş e-posta mezar taşı: biberli bir mesaj doğrulama kodu ile silinme zamanı saklanmakta ile düz metin atılmaktadır. Tekillik kısıtını ile bu adres daha önce kullanıldı mı kontrolünü kişisel veri tutmadan korumaktadır. Ancak çalışma grubu görüşüne göre bu takma adlıdır, anonim değildir; GDPR kapsamında kalmakta ile biberin kendisi bir kripto parçalama kaldıracı olmaktadır.
3. N gün tutup sonra serbest bırakmak: yalnızca eski adrese bağlı tüm kurtarma yolları geçersiz kılınırsa ile posta kutusu sahiplik başlangıcı kaydedilip giden kurtarma postasında RFC 7293 semantiğine uyulursa savunulabilir.

Tekillik kısıtı mekaniği şudur: tekillik hem canlı satırlar hem mezar taşları üzerinde zorlanmalıdır, yani mezara konmuş satırları içeren kısmî bir benzersiz indeks kullanılmalıdır; aksi hâlde yeniden kayıt, silinmiş bir aslın tanımlayıcısını sessizce diriltmektedir.

Mezara konmuş bir SCIM kaynağında asla 410 dönülmemelidir; RFC 7644'ün 3.6 bölümü 404 demektedir.

---

### 25. Askıya alma ile dondurma ve token etkileri

#### 25.1 CAEP ile SSF: cevap nihaidir

Üç paylaşılan sinyal şartnamesinin tamamı 2 Eylül 2025'te OpenID nihai şartnamesi olarak onaylanmıştır. Oylama 85 kabul, bir itiraz ile 25 çekimserdir; 433 üyeden 111'i oy kullanmıştır, yani %25,6 katılım vardır ile %20'lik nisap aşılmıştır. Nihai bir şartname, gerçekleyicilere fikrî mülkiyet koruması sağlamakta ile daha fazla revizyona tabi olmamaktadır.

| Şartname | Statü |
|---|---|
| OpenID paylaşılan sinyaller çerçevesi 1.0 | Nihaidir, 2 Eylül 2025 |
| OpenID sürekli erişim değerlendirme profili 1.0 | Nihaidir; belge tarihi 29 Ağustos 2025'tir |
| OpenID RISC 1.0 | Nihaidir, 2 Eylül 2025 |

CAEP 1.0'ın sekiz olay tipi şunlardır: oturum iptali, token iddiası değişikliği, kimlik bilgisi değişikliği, güvence seviyesi değişikliği, cihaz uyumluluğu değişikliği, oturum kurulumu, oturum sunumu ile risk seviyesi değişikliği.

Oturum iptali olayı birebir şöyle tanımlanmaktadır: *"Session Revoked signals that the session identified by the subject has been revoked. The explicit session identifier may be directly referenced in the subject or other properties of the session may be included to allow the receiver to identify applicable sessions."*

Bu raporun tek en değerli mimari bulgusu şudur: CAEP'te hesap devre dışı bırakma ya da hesap silme olayı yoktur. Şartname hesap yaşam döngüsü sonlandırmasını hiç ele almamaktadır. Bu boşluğu RFC 9967'nin devre dışı bırakma ile silme olayları doldurmaktadır. Tam bir tasarım için ikisi de gerekmektedir: yaşam döngüsü durumu için SCIM güvenlik olayı belirteçleri, oturum ile erişim durumu için CAEP. Çoğu tasarım bu dikişi kaçırmaktadır.

Çerçeveyle profil ilişkisi şudur: paylaşılan sinyaller çerçevesi taşıma ile yönetim katmanıdır, yani verici, alıcı, akış yapılandırması, itme ve yoklama teslimi ile RFC 8417 belirteçleridir. CAEP onun üzerinde taşınan olay semantiğini tanımlayan bir profildir. RISC, hesap güvenliği olayları için kardeş bir profildir.

İki not gerekmektedir. CAEP birlikte çalışabilirlik profilinin Eylül 2026 statüsü doğrulanmamıştır; nihai aşamaya ulaşıp ulaşmadığı teyit edilememiştir. Microsoft Entra dışındaki satıcı benimsemesi, yani Okta, Google, Apple, Cisco ile Duo ve SGNL, birincil kaynaktan doğrulanmamıştır.

#### 25.2 Microsoft Entra sürekli erişim değerlendirmesi, en iyi belgelenmiş gerçek uygulama

Doküman güncellemesi 8 Nisan 2026'dır.

Yaşam süresine karşı iptal sorusunun doğrudan cevabı birebir şudur.

> *"Microsoft experimented with the 'blunt object' approach of reduced token lifetimes but found they degrade user experiences and reliability without eliminating risks."*

Neredeyse gerçek zamanlı iptali tetikleyen kritik olaylar şunlardır: kullanıcı hesabının silinmesi ya da devre dışı bırakılması; bir kullanıcının parolasının değiştirilmesi ya da sıfırlanması; kullanıcı için çok faktörlü kimlik doğrulamanın etkinleştirilmesi; yöneticinin bir kullanıcı için tüm yenileme token'larını açıkça iptal etmesi; ile kimlik koruması tarafından yüksek kullanıcı riski tespit edilmesi.

Token ömrü şöyledir: değerlendirme farkındalıklı oturumlarda token ömrü uzun, yani 28 saate kadar olmaktadır. İptali keyfî bir zaman dilimi değil kritik olaylar ile politika değerlendirmesi yönlendirmektedir. Yapılandırılabilir token ömrü politikası bu oturumlarda dikkate alınmamaktadır. Değerlendirme farkındalıklı olmayan istemciler bir saatlik varsayılanda kalmaktadır.

Gecikme şöyledir: kritik olay değerlendirmesi neredeyse gerçek zamanı hedeflemekte ancak olay yayılım süresi nedeniyle 15 dakikaya kadar gecikme gözlemlenebilmektedir; IP konum politikası zorlaması anlıktır.

Mekanizma şudur: kaynak sağlayıcı, süresi dolmamış bir token'ı 401 ile bir iddia meydan okumasıyla reddetmekte; yetenekli istemci önbelleğini atlamakta ile Entra'dan yeniden istemektedir. İstemci desteği gerekmektedir.

Kapsamı Exchange Online, SharePoint Online, Teams ile Microsoft Graph'tır. Misafir hesaplar desteklenmemektedir. Devre dışı bırakılmış bir kullanıcıyı yeniden etkinleştirmenin de gecikmesi vardır; SharePoint ile Teams'te yaklaşık 15, Exchange'te yaklaşık 35 ile 40 dakikadır. Grup üyeliği ile koşullu erişim politikası değişiklikleri bir güne kadar sürebilmektedir, bazı vakalarda iki saate optimize edilmiştir; hareket eden çalışan vakası için ciddi bir tuzaktır.

#### 25.3 OAuth iptali, tam dil

RFC 7009'un 2.1 bölümündeki destek asimetrisi birebir şudur.

> *"Implementations MUST support the revocation of refresh tokens and SHOULD support the revocation of access tokens."*

Basamaklanma birebir şudur.

> *"If the particular token is a refresh token and the authorization server supports the revocation of access tokens, then the authorization server SHOULD also invalidate all access tokens based on the same authorization grant."*

Çift koşullu ifadeye dikkat edilmelidir: basamaklanma bir öneridir ile isteğe bağlı bir desteğe bağlıdır. Bir yenileme token'ını iptal etmek, dışarıdaki erişim token'larını güvenilir şekilde öldürmemektedir. CAEP ile paylaşılan sinyaller çerçevesi tam olarak bu deliği kapatmak için vardır.

RFC 7662'nin 2.2 bölümüne göre iptal edilmiş token'lar için yetkilendirme sunucusu etkin değil yanıtı dönmek zorundadır ile etkin olmayan bir token hakkında ek bilgi içermemelidir. Dördüncü bölümdeki önbellek gerilimi birebir şudur: *"A more aggressive cache with a longer duration will minimize network traffic... but at the risk of stale information about the token."*

RFC 9700, yani Ocak 2025 tarihli BCP 240, şunu söylemektedir: yetkilendirme ile kaynak sunucuları, erişim token'larını gönderene kısıtlamak için karşılıklı TLS ya da DPoP gibi mekanizmalar kullanmalıdır. Yetkilendirme kodları ilk kullanımdan sonra geçersiz kılınmalı ile yeniden oynatmada sunucu o koddan verilmiş tüm token'ları iptal etmelidir. RFC 9700'de belirli bir sayısal erişim token'ı ömrü tavsiyesi bulunamamıştır; iddia edilmemelidir.

#### 25.4 Durum makinesi

Okta'nın dokümante modeli bir durum sıralamasıdır: hazırlanmış, sağlanmış, aktif, kurtarma, parolası dolmuş, kilitlenmiş, askıya alınmış ile sağlaması kaldırılmış.

| Durum | Okta'nın tam tanımı |
|---|---|
| Hazırlanmış | Hesaplar ilk oluşturulduğunda, aktivasyon akışı başlatılmadan önce bu durumdadır |
| Kullanıcı eylemi bekliyor | Kullanıcı aktivasyon e-postasındaki bağlantıya tıklayarak doğrulama sağlamamıştır |
| Aktif | Yönetici parolayla eklemiştir ya da kullanıcı e-posta doğrulaması gerekmeden kendi kaydolmuştur |
| Parola sıfırlama | Bir yönetici parola sıfırlaması istediğinde bu durumdadır |
| Parolası dolmuş | Parolanın süresi dolmuştur ile hesap bir güncelleme gerektirmektedir |
| Kilitlenmiş | Kullanıcı giriş politikasında tanımlı deneme sayısını aşmıştır |
| Askıya alınmış | Bir yönetici açıkça askıya aldığında oluşmaktadır; kullanıcı uygulamalara erişememektedir |
| Devre dışı | Bir yönetici açıkça devre dışı bıraktığında ya da sağlamasını kaldırdığında oluşmaktadır; tüm uygulama atamaları kaldırılmaktadır |

Bir geçiş kısıtı vardır: zaten sağlaması kaldırılmış bir kullanıcıda devre dışı bırakma yapılamamaktadır, yani işlem etkisiz kılınabilir değildir.

Okta modelinde bir silinmiş durumu yoktur; silme, kaydı durum makinesinden tamamen çıkarmakta ile 30 günlük müşteri verisi temizliğini başlatmaktadır. Argus'un mezar taşı terminal durumu Okta modelinin bir üst kümesidir ile daha savunulabilir bir tasarımdır.

Korunması gereken semantik ayrım şudur: kilitlenme sistem kaynaklıdır, yani politika ya da başarısız denemelerden gelmektedir, ile kendiliğinden kurtarılabilirdir; askıya alma yönetici kaynaklıdır ile bir yönetici eylemi gerektirmektedir. İkisini birleştirmek bunu kim geri alabilir özelliğini kaybettirmektedir.

---

### 26. Atıl hesaplar

#### 26.1 Standart eşikleri, ikisi de doğrulanmıştır

CIS kritik güvenlik kontrolleri sekizinci sürümünün 5.3 numaralı koruması atıl hesapların devre dışı bırakılmasıdır: desteklenen yerlerde 45 günlük hareketsizlikten sonra atıl hesaplar silinmeli ya da devre dışı bırakılmalıdır. 45 gün doğrulanmıştır. Desteklenen yerlerde çekincesine ile silme veya devre dışı bırakma seçeneğine izin verdiğine dikkat edilmelidir. Hangi uygulama grubundan başladığı doğrulanmamıştır.

PCI DSS dördüncü sürümünün 8.2.6 numaralı gereksinimi şudur: etkin olmayan kullanıcı hesapları 90 günlük hareketsizlik içinde kaldırılmakta ya da devre dışı bırakılmaktadır. 90 gün doğrulanmıştır. İlgili standart sitesi kayıt duvarlıdır; standardın PDF'ine karşı doğrulanmalıdır.

NIST SP 800-53 beşinci revizyonunun hesapları devre dışı bırakma kontrolü, hareketsizliğe dayalı devre dışı bırakmanın standart referansıdır; hareketsizlik süresi kuruluş tanımlı bir parametredir ile sabit bir varsayılanı yoktur. Tam metin çekilmemiş ile doğrulanmamıştır.

#### 26.2 Tüketici platform politikaları

Google'ın atıl hesap politikası şudur: iki yıllık bir dönemde kullanılmamış bir hesap atıldır ile bu politika nedeniyle bir hesabın silinebileceği en erken tarih 1 Aralık 2023'tür. Muafiyetler güncel satın alımı olan hesaplar, hediye kartı bakiyesi, aktif işlemli yayımlanmış uygulamalar, yönetilen aile bağlantısı hesapları ile dijital ürün satın alımlarıdır. Yalnızca kişisel hesaplara uygulanmaktadır, okul ya da iş hesaplarına değil.

Microsoft hesabı hareketsizlik politikası, X hareketsizliği ile kullanıcı adı geri dönüşümü ile Apple kimliği hareketsizliği birincil kaynaktan doğrulanamamıştır; iddia edilmemelidir.

#### 26.3 Pratik not

Keycloak'ta otomatik atıl hesap devre dışı bırakma ya da silme yoktur, yani 38108 numaralı konu açıktır; Auth0 topluluğunda aynı boşluk görünmektedir.

PCI DSS ya da CIS hizalanması hedefleniyorsa, hareketsizlik süpürmesi miras alınacak değil inşa edilecek bir özelliktir.

KVKK periyodik imhasıyla da etkileşmektedir: tek bir zamanlanmış iş, CIS ile PCI devre dışı bırakmasını ile KVKK periyodik imhasını ancak iki saat ayrı tutulursa karşılayabilmektedir; 45 ya da 90 günde devre dışı bırakılmalı ile KVKK'nın altı ayı geçmeyen döngüsünde imha edilmelidir.

---

### 27. Veri taşınabilirliği, GDPR 20. madde

#### 27.1 WP242 birinci revizyonu

Veri taşınabilirliği hakkına ilişkin kılavuz, WP242 birinci revizyonu, ilk kabulü 13 Aralık 2016, revizyonu ile kabulü 5 Nisan 2017'dir. Avrupa Veri Koruma Kurulu tarafından ilk genel kurulunda onaylanmıştır. Komisyon PDF uç noktaları otomatik çekime ayrıştırılamaz ikili veri döndürmüştür; aşağıdaki içerik arama çıkarımı ile hukuk bürosu analizlerindendir ile alıntı olarak yayımlanmadan önce PDF'e karşı doğrulanmalıdır.

Kapsam içinde sağlanan ifadesi geniş okunmaktadır: hem aktif ile bilinçli sağlanan veri, yani form gönderimleri, hem gözlemlenen veri, yani arama geçmişi ile konum verisi kapsamdadır. Çalışma grubu, veri sorumlularını aşırı dar okumaya karşı açıkça uyarmaktadır. Revize metindeki gözlemlenen veri örnekleri akıllı sayaç ya da diğer bağlı nesnelerce işlenen ham veri, etkinlik günlükleri, web sitesi kullanım geçmişi ile arama etkinlikleridir.

Bir kimlik sağlayıcı için bu belirleyicidir: kimlik doğrulama günlükleri ile giriş geçmişi gözlemlenen veridir ile taşınabilirdir. Bu, denetim günlüklerini tamamen dahilî saymakla doğrudan çelişmektedir.

Kapsam dışında türetilmiş ya da çıkarımsal veri bulunmaktadır; algoritmik çıktılar, kişisel veriden üretilen analitik profiller, değerlendirme raporları ile kredi skorları sağlanmak zorunda değildir.

Format konusunda 20. madde yapılandırılmış, yaygın kullanılan ile makine okunabilir bir biçim istemektedir. Sektöre özgü bir format yaygın kullanımda değilse CSV, XML ile JSON gibi açık formatlar sağlanmalıdır.

Üçüncü taraf verisi konusunda çalışma grubu, talep edenle ilgili ile onun tarafından sağlanmış bir veri kümesinde görünen üçüncü taraf verisi için aşırı dar okumaya karşı uyarmaktadır; kişisel amaçlarla kullanıldığı sürece kapsamdadır. Kanonik örnek gelen ile giden aramaları içeren telefon kayıtlarıdır. Alıcı veri sorumlusu üçüncü taraf verisini onların aleyhine amaçlarla işleyememektedir.

#### 27.2 Yirminci maddeyle on beşinci maddenin karşılaştırması

Yirminci madde dayanak olarak daha dardır, yani yalnızca rıza ya da sözleşmeye ve yalnızca otomatik işlemeye uygulanmaktadır; ancak biçim olarak daha güçlüdür, yani makine okunabilirlik ile teknik olarak mümkünse doğrudan veri sorumlusundan veri sorumlusuna iletim hakkı sunmaktadır. On beşinci madde erişimi tüm hukuki dayanakları kapsamakta ancak bir format garantisi taşımamaktadır. Kimlik sağlayıcı dışa aktarım akışı ikisini de karşılamalıdır ancak birbirlerinin yerine geçmemektedirler.

#### 27.3 Avrupa Birliği veri yasası ile dijital piyasalar yasası

2023/2854 sayılı veri yasası 12 Eylül 2025'ten itibaren uygulanabilirdir ile doğrulanmıştır.

Bulut geçişi bölümü, yani 23 ile 31. maddeler, altyapı, platform ile yazılım hizmeti biçimindeki veri işleme hizmetlerini kapsamaktadır; her kapsam içi sözleşmede zorlanabilir geçiş hakları, sınırlanmış ihbar süreleri, veri alma pencereleri ile çıkış ücreti sınırları getirmektedir.

Kimlik sağlayıcı için ısıran hüküm budur, nesnelerin interneti bölümleri değil. Barındırılan bir kimlik sağlayıcı makul olarak bir veri işleme hizmetidir ile bu, dışarı geçişi, yani kullanıcı, grup, yetki ile kimlik bilgisi metadata'sı dışa aktarımını, bir nezaket değil sözleşmesel bir yükümlülük yapmaktadır.

Geçiş ücretlerinin Ocak 2027'ye kadar tamamen kaldırıldığı iddiası doğrulanmamıştır; ilgili maddeye doğrudan bakılmalıdır.

Dijital piyasalar yasasının, yani 2022/1925 sayılı düzenlemenin, 6. maddesinin dokuzuncu fıkrası birebir şunu söylemektedir: *"The gatekeeper shall provide end users and third parties authorised by an end user, at their request and free of charge, with effective portability of data provided by the end user or generated through the activity of the end user"*. Ayrıca etkin kullanım için araçlar, sürekli ile gerçek zamanlı erişim dahil, sağlanmalıdır.

Kimlik açısından şu geçerlidir: bir kimlik sağlayıcı, belirlenmiş bir kapı bekçisinin çekirdek platform hizmetinin parçasıysa, yani tüketici oturum açmaysa, bu hüküm taşınabilirliği toplu dışa aktarımdan sürekli ile gerçek zamanlı bir API'ye yükseltmektedir; 20. maddeden mimari olarak farklı bir gereksinimdir.

#### 27.4 Kimlik sağlayıcı dışa aktarımı ne içermeli ile ne içermemelidir

Parola özetleri hakkında otoriter bir düzenleyici ifade yoktur; aranmış ile bulunamamıştır. Aşağısı gerekçelendirilmiş tasarım rehberliğidir ile öyle işaretlenmiştir.

Dahil edilmesi gerekenler şunlardır: tanımlayıcılar, yani kullanıcı kimliği, kullanıcı adları, e-postalar ile telefon; profil nitelikleri; grup, rol ile yetki atamaları; rıza ile yetki kayıtları; bağlı dış ve federe kimlikler; çok faktörlü kayıt metadata'sı, yani faktör tipi, kayıt zamanı ile cihaz etiketi; kimlik doğrulama ile giriş geçmişi, ki gözlemlenen veridir ve kılavuz etkinlik günlüklerini açıkça kapsama almaktadır; ile hesap yaşam döngüsü durum geçmişi.

Hariç tutulması gerekenler şunlardır. Parola özetleri hariç tutulmalıdır: özet bir kimlik bilgisidir ile hiçbir anlamlı şekilde kullanıcının sağladığı veri değildir; dışa aktarmak bir taşınabilirlik talebini çevrimdışı kırma hediyesine çevirmekte ile ele geçirilmiş bir dışa aktarım bir kimlik bilgisi ihlaline dönüşmektedir. Yirminci maddenin dördüncü fıkrası, yani başkalarının hak ile özgürlüklerini olumsuz etkilememe koşulu, artı 32. maddenin güvenlik yükümlülükleri saklamayı desteklemektedir. Çok faktörlü paylaşılan sırlar, tek kullanımlık şifre tohumları, kurtarma kodları ile WebAuthn özel anahtar materyali aynı gerekçeyle, daha keskin biçimde hariç tutulmalıdır. Çıkarımsal ile türetilmiş veri, yani risk skorları ile davranışsal profiller, kılavuzca hariç tutulmaktadır. Başkalarının verisi, yani diğer kullanıcıları adlandıran denetim satırları, üye listelerini açığa vuran grup listeleri ile yönetici aktör kimlikleri, redakte edilmeli ya da takma adlaştırılmalıdır. Dolandırıcılık tespitini zayıflatacak dahilî güvenlik sinyalleri de hariç tutulmalıdır.

Süreç konusunda kılavuz, talep edenin kimlik doğrulamasını ile iletimin güvenliğini vurgulamaktadır. Dışa aktarım uç noktası başlı başına yüksek değerli bir saldırı yüzeyidir: tam bir kimlik dışa aktarımı veren bir hesap devralma, oturum erişimi verenden çok daha kötüdür. Hız sınırı uygulanmalı, yükseltilmiş kimlik doğrulamayla yeniden doğrulama istenmeli ile dışa aktarım denetlenebilir bir güvenlik olayı olarak günlüğe yazılmalıdır.

---

### 28. KVKK, Türkiye

#### 28.1 6698 sayılı Kanun'un 7. maddesi, tam metin

> MADDE 7 – (1) Bu Kanun ve ilgili diğer kanun hükümlerine uygun olarak işlenmiş olmasına rağmen, işlenmesini gerektiren sebeplerin ortadan kalkması hâlinde kişisel veriler resen veya ilgili kişinin talebi üzerine veri sorumlusu tarafından silinir, yok edilir veya anonim hale getirilir.
> (2) Kişisel verilerin silinmesi, yok edilmesi veya anonim hale getirilmesine ilişkin diğer kanunlarda yer alan hükümler saklıdır.
> (3) Kişisel verilerin silinmesine, yok edilmesine veya anonim hale getirilmesine ilişkin usul ve esaslar yönetmelikle düzenlenir.

İkinci fıkradaki saklılık kaydı, KVKK'nın GDPR 17. maddesinin üçüncü fıkrasındaki yasal yükümlülük bendinin yapısal eşdeğeridir; sektörel saklama hukukunun, yani vergi, elektronik ticaret ile elektronik haberleşme mevzuatının, silme yükümlülüğünü ezmesini sağlayan hüküm budur.

Birinci fıkradaki resen ifadesi GDPR'dan daha katı bir çerçevelemedir: proaktif ile veri sorumlusunun başlattığı imha olumlu bir görevdir, yalnızca bir talebe yanıt değildir. Yönetmelikteki periyodik imha makinesi bunu uygulamaktadır.

#### 28.2 Yönetmelik

Kişisel verilerin silinmesi, yok edilmesi veya anonim hale getirilmesi hakkında yönetmelik, Resmî Gazete 28 Ekim 2017, sayı 30224; doğrulanmıştır. Yürürlüğü 1 Ocak 2018'dir.

Periyodik imha 11. maddededir. Altı ay iddiası doğrulanmıştır ile tam cümle şudur: bu süre her hâlde altı ayı geçememektedir.

Bu bir azami aralıktır, bir saklama süresi değildir; tasarım için önemli bir ayrımdır. Periyodik imha aralıkları veri sorumlusunun kendi politikasında belirlenmekte ancak yönetmelik sert bir altı aylık tavan koymaktadır. GDPR'ın böyle bir sert saati yoktur.

Saklama ile imha politikası beşinci ile altıncı maddelerdedir. Beşinci maddenin birinci fıkrasına göre veri sorumluları siciline kayıt yükümlülüğü olan veri sorumluları, kişisel veri işleme envanterine uygun olarak bir saklama ile imha politikası hazırlamak zorundadır. Altıncı maddeye göre politika asgari olarak saklama ile silme prosedürlerini, teknik ile idarî tedbirleri, imha yöntemlerini, sorumlu personelin unvanını, birimini ile görev tanımlarını ile periyodik imha sürelerini içermelidir. Sicil bağlantısı tetikleyicidir; politika yükümlülüğü evrensel değildir, kayıt sorumluluğunu takip etmektedir.

Dördüncü maddedeki tanımlar KVKK'nın üç yönlü ayrımını GDPR'dan mimari olarak daha keskin yapmaktadır.

| KVKK terimi | Tanım, birebir | Kimlik sağlayıcıdaki teknik karşılığı |
|---|---|---|
| Silme | Kişisel verilerin ilgili kullanıcılar için hiçbir şekilde erişilemez ve tekrar kullanılamaz hale getirilmesi işlemidir; tanımlı bir kullanıcı kitlesine görelidir, mutlak değildir | Mezar taşıdır: satır kalmakta, tüm uygulama kullanıcıları ile rolleri için erişilemez olmakta ile SCIM 404 dönmektedir |
| Yok etme | Kişisel verilerin hiç kimse tarafından hiçbir şekilde erişilemez, geri getirilemez ve tekrar kullanılamaz hale getirilmesi işlemidir; mutlaktır | Sert silme artı kullanıcı anahtarının kripto parçalanması artı yedeklerin sona ermesidir |
| Anonim hale getirme | Başka verilerle eşleştirilse dahi hiçbir surette kimliği belirli veya belirlenebilir bir gerçek kişiyle ilişkilendirilemeyecek hale getirilmesidir | Denetim satırları özne referansı geri döndürülemez şekilde koparılarak tutulmaktadır; ilgili görüşlere göre bir özet yeterli değildir |

Silme tanımının göreli oluşu, KVKK'nın mezar taşına en yakın kavramıdır ile bu, mezar taşı mimarisine GDPR'da olmayan doğrudan bir hukuki dayanak vermektedir.

Veri sahibi talepleri 12. maddenin birinci fıkrasının a bendindedir: veri sorumlusu talebe konu kişisel verileri silmekte, yok etmekte ya da anonim hâle getirmektedir ile ilgili kişinin talebini en geç otuz gün içinde sonuçlandırmaktadır.

Üç ay rakamı silme talepleri için doğrulanmamıştır ile iddia edilmemelidir. Yönetmelikte bulunan tek süre 30 gündür.

#### 28.3 2024 değişikliği, yurt dışına aktarım

7499 sayılı Kanun, yani sekizinci yargı paketi, Resmî Gazete 12 Mart 2024, sayı 32487. Otuz dördüncü maddesi 6698'in dokuzuncu maddesini, yani kişisel verilerin yurt dışına aktarılmasını değiştirmiş ile değişiklikler 1 Haziran 2024'te yürürlüğe girmiştir; doğrulanmıştır.

Yeni dokuzuncu madde, eski rejimin yerine üç kademeli bir basamak getirmektedir. Birincisi Kurul tarafından verilen bir yeterlilik kararıdır. Yoksa uygun güvenceler gerekmektedir: standart sözleşme, bağlayıcı şirket kuralları, Kurul izniyle taahhütname ya da kamu kurumları arası uluslararası anlaşma. İkisi de yoksa yalnızca arızi aktarımlar mümkündür ile açık rıza bunların dayanaklarından biridir.

Önemli yapısal değişiklik şudur: açık rıza birincil bir dayanaktan son çare ile yalnızca arızi bir dayanağa indirilmiştir. Kimlik verisini Türkiye dışı bölgelere replike eden bir kimlik sağlayıcı için rıza artık uygulanabilir bir mimari değildir; standart sözleşme ya da bağlayıcı şirket kuralları gerekmektedir.

Aynı kanun ayrıca özel nitelikli veri işlemeyi düzenleyen altıncı maddeyi ile idarî para cezalarını düzenleyen on sekizinci maddeyi de değiştirmiştir.

Doğrulanamayanlar şunlardır: sicile kayıt eşikleri, yani çalışan sayısı ile yıllık bilanço muafiyetleri; silmeme ya da geç imha için Kurul kararları ile cezaları, ki bir karar numarası bulunamamıştır ile iddia edilmemelidir; güvenlik ile denetim günlüğü saklamanın silme yükümlülüğüyle ilişkisi hakkında Kurum rehberliği; ile Kurum rehberindeki teknik listesi, yani karartma, maskeleme, toplulaştırma, k anonimliği ile benzerleri, çünkü PDF metin çıkarımı yapılamamış ile madde madde doğrulanmamıştır.

---

### 29. Dördüncü bölüm için tasarım kararları

| Sıra | Karar | Dayanak |
|---|---|---|
| 1 | Yaşam döngüsü durumları hazırlanmış, sağlanmış, aktif, kilitlenmiş ya da askıya alınmış, devre dışı ile mezar taşı sırasını izlemektedir. Kilitlenme ile askıya alma birleştirilmemektedir | Okta sıralaması artı bunu kim geri alabilir özelliği |
| 2 | SCIM silme mezar taşı koymaktadır, sert silme yapmamaktadır; sonrasında her işlem 404 dönmektedir, asla 410 değil | RFC 7644 3.6 |
| 3 | Hem SCIM güvenlik olayı belirteci hem CAEP 1.0 vericisi bulunmaktadır; biri yaşam döngüsü diğeri oturum içindir | CAEP'te hesap silme olayı yoktur |
| 4 | Devre dışı bırakma atomiktir: durum, oturumlar, yenileme token'ları ile çevrimdışı token'lar tek işlemdedir | Okta'da iki ayrı düğme olması bir hatadır |
| 5 | Kısa yaşam süresi yerine uzun ömürlü erişim token'ı, yani 28 saate kadar, artı sinyal güdümlü iptal kullanılmaktadır | Entra'nın kör nesne bulgusu |
| 6 | Kullanıcı kimliği asla yeniden kullanılmamaktadır; e-posta risk katmanına göre ele alınmaktadır, varsayılan asladır | RFC 9967'nin yüksüz silme olayı artı Gmail |
| 7 | Tekillik kısıtı canlı satırlar ile mezar taşları üzerindedir | Slack'in üretim davranışı |
| 8 | Her kişisel veri alanı kullanıcı başına bir anahtarla şifrelidir; yok etme anahtarın imhasıdır ile varsayılan 30 gün gecikmelidir | Kripto parçalama artı kullanım dışı bırakma testinin dördüncü ayağı |
| 9 | Denetim özet zinciri şifreli metin üzerinden hesaplanmaktadır | Bütünlükle gizliliğin ayrışması |
| 10 | Periyodik imha işi birinci sınıftır ile saati hareketsizlik saatinden ayrıdır; imha altı ayı geçmemekte, devre dışı bırakma 45 ya da 90 gündedir | KVKK 11. madde artı CIS ile PCI gereksinimleri |
| 11 | Her e-posta bağlamasında posta kutusu sahiplik başlangıcı tutulmakta ile giden kurtarma postasında RFC 7293 kullanılmaktadır | Yahoo 2013 ile RFC 7293 |
| 12 | Riske katmanlı tanımlayıcı emekliliği uygulanmaktadır: token'da ya da federasyonda görünmüş tanımlayıcılar kalıcı mezar taşıdır, hiç aktive olmamış hazırlanmış hesaplar serbesttir | GitHub ad alanı modeli |
| 13 | Dışa aktarım giriş geçmişini içermekte, parola özetini ile çok faktörlü sırları içermemektedir; yükseltilmiş kimlik doğrulama ile bir denetim olayı gerektirmektedir | Kılavuz artı 20. maddenin dördüncü fıkrası ve 32. madde |
| 14 | Hareketsizlik süpürmesi inşa edilmektedir, miras alınmamaktadır | Keycloak'ın açık konusu |
| 15 | Mezar taşı asla bir kararı beslememektedir; risk skoru ile dolandırıcılık listesi yoktur | Kullanım dışı bırakma testinin birinci ayağı |

---

## Bölüm V — Kayıt ile katılım güvenliği

### 30. NIST SP 800-63-4 kayıt tarafında ne demektedir

Yayın 31 Temmuz 2025'tir, yani belge geçmişindeki tarihtir; Haziran 2017 tarihli üçüncü sürümün yerine geçmiştir. Bir tuzak vardır: NIST'in sayfa alan adındaki HTML sürümleri, sayfa gövdesinde 26 Ağustos 2025 tarihli bir derleme damgası taşımaktadır. Bu bir işleme tarihidir, yayın tarihi değildir. Naif bir çekim bunu yayın tarihi olarak raporlamaktadır.

#### 30.1 SP 800-63B'nin 3.2.2 hız sınırlama bölümü, birebir

> "When required by the authenticator type descriptions in Sec. 3.1, the verifier SHALL implement controls to protect against online guessing attacks. Unless otherwise specified…, the verifier SHALL limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to no more than 100 by disabling that authenticator. If more than one authenticator is involved with an excessive number of authentication attempts…, both authenticators SHALL be disabled. Authenticators that have been disabled SHALL be required to rebind to the subscriber account…"

> "The limit of 100 attempts is an upper bound, and agencies MAY impose lower limits. The limit of 100 was chosen to balance the likelihood of a correct guess (e.g., 100 attempts against a six-digit decimal OTP authenticator output) versus the potential need for account recovery when the limit is exceeded."

Bot savunması kancası, yani 63B'nin otomatik saldırılara direnç gereksinimine en çok yaklaştığı yer, bir zorunluluk değil bir izindir.

> "Additional techniques MAY be used… These include:
> - Requiring the claimant to complete a bot detection and mitigation challenge before attempting authentication
> - Requiring the claimant to wait after a failed attempt for a period of time that increases as the subscriber account approaches its maximum allowance (e.g., 30 seconds up to an hour)
> - Leveraging other risk-based or adaptive authentication techniques… (e.g., the use of the claimant's IP address, geolocation, timing of request patterns, or browser metadata)"

> "When the subscriber successfully authenticates, the verifier SHOULD disregard any previous failed attempts for the authenticators used in the successful authentication."

Tasarım dokümanı için kritik çerçeveleme şudur: dördüncü revizyonun kısıtlama gereksinimi hesap kapsamlı ile kimlik doğrulayıcı kapsamlıdır, yani 100 ardışık başarısızlıkta o kimlik doğrulayıcı devre dışı bırakılmaktadır. Bir IP ya da kenar hız sınırı değildir ile bir kayıt suistimali kontrolü değildir. 63B'nin hiçbir yerinde CAPTCHA ya da bot savunması zorunlu kılan bir hüküm yoktur; CAPTCHA kelimesi belgede hiç geçmemektedir. Kayıt anındaki bot savunması 63A'da yaşamaktadır, 63B'de değil.

63B'deki diğer kısıtlama atıfları hep aynı bölüme işaret etmektedir: parolalar, arama sırları, tek kullanımlık ve bant dışı şifreler, ki asgari altı hane gerekmekte ile yeni bir kimlik doğrulama sırrı üretmek başarısız deneme sayacını sıfırlamamaktadır, ile kurtarma kodları; kayıtlı kurtarma kodlarının doğrulanması aynı kısıtlama gereksinimlerine tabidir.

Ayrıca beşinci bölümün birinci alt bölümü DBSC'yi açıkça tanımaktadır.

> "Some technologies (e.g., the emerging device bound session credentials specification [DBSC]) mitigate the risk of theft of session secrets by using cryptographic protocols that prove the possession of a session secret rather than using them as bearer tokens… Session secrets used with such proof of possession techniques MAY persist. However, RPs and CSPs SHALL ensure that the session lifetime limits described in Sec. 2.2.3 are enforced even when a knowledge of the session secret is demonstrated."

#### 30.2 SP 800-63A: kimlik kanıtlama ile yeni sahtekârlık programı

Kimlik güvence seviyesi tanımları, otomasyon karşıtı noktada birebir şöyledir.

> "IAL1 is designed to limit highly scalable attacks (e.g., automated enrollment attacks) and to protect against synthetic identities and attacks using compromised personal information."
> "IAL2 … is designed to limit scaled and targeted attacks and to protect against basic evidence falsification, evidence theft, and social engineering tactics."
> "IAL3 adds the requirements for a trained CSP representative (i.e., proofing agent) to interact directly with the applicant as part of an on-site attended identity proofing session and the collection of at least one biometric characteristic."

Çekirdek nitelikler bölümüne göre hizmet sağlayıcılar bir devlet tanımlayıcısı içermek zorundadır ile ad, orta ad ya da baş harf, soyad, doğum tarihi ile fiziksel veya dijital adres içermelidir. Çekirdek nitelik doğrulaması şöyledir: hizmet sağlayıcı, ister kimlik kanıtından elde edilmiş ister başvuran tarafından beyan edilmiş olsun, tüm çekirdek nitelikleri otoriter ya da güvenilir bir kaynakla doğrulamak zorundadır.

Bir bölüm numarası uyarısı gerekmektedir: NIST'in sayfa alan adındaki HTML'i başlıklarda bölüm numarası işlememekte ile iki bağımsız çıkarım nitelik doğrulama numarasında çelişmiştir. Kararlı bağlantı çıpaları kaynak gösterilmeli ya da PDF'e karşı doğrulanmalıdır. Sahtekârlık yönetimi numaralandırması tutarlıydı: hizmet sağlayıcı sahtekârlık yönetimi, bağlı taraf sahtekârlık yönetimi ile sahtekârlık kontrolü başarısızlıklarının ele alınması alt bölümleridir.

Yeni hizmet sağlayıcı sahtekârlık programı gereksinimi dördüncü revizyonda gerçekten yenidir.

> "CSPs SHALL establish and maintain a fraud management program that provides fraud identification, detection, investigation, reporting, and resolution capabilities…"
> "CSPs SHALL conduct a privacy risk assessment of all fraud checks and fraud mitigation technologies prior to implementation."
> "The CSP SHALL establish a self-reporting mechanism and investigation capability for subjects who believe they have been the victim of fraud…"
> "CSPs SHALL analyze all remote proofing communication channels to look for high-risk indicators (e.g., blocklisted proxies and IP addresses)."
> "The CSP SHALL take measures to prevent unsuccessful applicants from inferring the accuracy of any self-asserted information with that confirmed by authoritative or credible sources."
> "CSPs SHALL implement a death records check for all identity proofing processes… Such checks can aid in preventing synthetic identity fraud…"
> "CSPs SHALL establish a technical or process-based mechanism to communicate suspected and confirmed fraudulent events to RPs."
> "CSPs SHOULD communicate fraud events in real time to RPs through methods such as shared signaling, as described in Sec. 4.8 of [SP800-63C]."
> "CSPs SHOULD periodically employ independent testing (e.g., red teaming)…"
> "CSPs SHALL implement insider threat controls to detect and prevent collusion involving CSP representatives…"

Yedinci alıntıdaki paylaşılan sinyalleşme ifadesi OpenID paylaşılan sinyaller çerçevesi ile CAEP'e işaret etmektedir. Beşinci alıntı ise numaralandırma gereksiniminin sahtekârlık bölümüne gömülmüş hâlidir.

Kayıt suistimaliyle doğrudan ilgili öneri seviyesindeki kontroller şunlardır. SIM değiştirme tespiti yapılmalı, yani telefon yakın zamanda taşınmamış olmalıdır. Cihaz ya da hesap kıdemi kontrol edilmeli, yani telefonun veya e-posta hesabının ne kadar süredir esaslı değişiklik olmadan var olduğuna bakılmalıdır; bu, bu bir tek kullanımlık posta kutusu mu sorusunun standart onaylı hâlidir. Posta adresi kontrolü yapılmalı, yani sanal posta kutusu ile yüksek riskli özellikler aranmalıdır. Cihaz parmak izi, ölçekli ile otomatik saldırılara ve kayıt tekrarına karşı korumak için kullanılmalıdır. İşlem analitiği yapılmalı, yani beklenen işlem özellikleri, örneğin IP adresleri, coğrafi konumlar ile işlem hızları değerlendirilmelidir. Sahtekârlık göstergesi kontrolü yapılmalıdır; açık bir mahremiyet çekincesi vardır, yani kullanıcılar bir mahremiyet risk değerlendirmesine dayalı olarak mahremiyet sonuçlarından haberdar edilmelidir.

Bağlı taraf tarafında bağlı taraflar bir sahtekârlık irtibat noktası kurmak, hizmet sağlayıcı sahtekârlık kontrollerinin mahremiyet risk değerlendirmesini yapmak ile sağlayıcının programını periyodik gözden geçirmek zorundadır; ayrıca kendi sahtekârlık yönetim programlarını kurmaları önerilmektedir.

#### 30.3 Sentetik kimlik ile kayıt sahtekârlığı, 63A altıncı bölüm, bilgilendiricidir

Dört tehdit kategorisi kimliğe bürünme, yanlış ya da hileli beyan, yani sentetik kimlik, sosyal mühendislik ile altyapı saldırılarıdır.

Açık yapay zekâ çerçevelemesi şöyledir.

> "Many emerging attacks… pair digital injection attacks with increasingly effective and available generative AI tools. These AI tools are used to create or modify media that contain images or videos of applicants and evidence (i.e., deepfakes)…"
> "This section does not provide guidance or controls that specifically address AI as a discrete threat type. Instead, the mitigations below… address specific threats that may be perpetrated or scaled by attackers with AI tools."

Tehditler tablosu şöyledir.

| Tehdit | Tanım | Örnek |
|---|---|---|
| Otomatik kayıt denemeleri | Saldırgan, hızla büyük hacimde kayıt üretmek için betikler ile otomatik süreçler kullanmaktadır | Botlar çalıntı veriyi kullanarak yardım talebi göndermektedir |
| Sentetik kimlik sahtekârlığı | Saldırgan, gerçek bir kişiyle ilişkili olmayan bir kimliğin kanıtını uydurmaktadır | Bir kredi dosyası oluşturmak için sahte adla açılan kredi kartı |
| Video ya da görüntü enjeksiyon saldırısı | Saldırgan, gerçek bir kişiye bürünmek için sahte bir video akışı oluşturmaktadır | Derin sahte video |

Azaltmalar tablosunun kimlik sağlayıcının doğrudan alıntılaması gereken satırı şudur: otomatik kayıt denemelerine karşı web uygulaması güvenlik duvarı kontrolleri ile bot tespit teknolojisi, bant dışı etkileşim, yani onay kodları, biyometrik doğrulama ile canlılık tespiti mekanizmaları ile trafik ve ağ analizi yetenekleri kullanılmalıdır.

#### 30.4 Dördüncü revizyonun eklediği

63A değişiklik kaydından: çekirdek nitelikler kavramı getirilmiştir; kimlik niteliklerinin toplanması kimlik kanıtlarının toplanmasından ayrıştırılmıştır; sahtekârlık yönetimi rehberliği ile gereksinimleri getirilmiştir; dijital enjeksiyon önleme ile sahte medya tespiti için rehberlik ve gereksinimler sağlanmıştır; kabul edilebilir kanıt ile nitelik doğrulama kaynakları güvenilir kaynakları kapsayacak biçimde genişletilmiştir; güvenilir hakemler ile başvuran referansları getirilmiştir; ile birinci ve ikinci kimlik güvence seviyelerinde biyometrik olmayan doğrulama seçenekleri sunulmuştur.

63B değişiklik kaydından ilgili girdiler: kimlik avına dirençli kimlik doğrulayıcılar için bir tanım eklenmiş ile gereksinimler güncellenmiştir; kimlik doğrulayıcı sırlarının dışa aktarılamazlığı için yeni bir bölüm eklenmiştir; hesap kurtarma gereksinimleri ile yöntemleri revize edilmiştir; cihaza bağlı oturum kimlik bilgilerinin kullanımı tanınmıştır; ile oturum izleme, yani sürekli kimlik doğrulama kullanımı için kılavuzlar eklenmiştir.

---

### 31. Bot koruması 2026: CAPTCHA bir bulmaca olarak ölmüştür

#### 31.1 Akademik kanıt

reCAPTCHA ikinci sürümünü kırma çalışması, ETH Zürih'ten Andreas Plesner, Tobias Vontobel ile Roger Wattenhofer tarafından yazılmıştır; arXiv 2409.08831, 13 Eylül 2024, COMPSAC 2024'te kabul edilmiştir.

YOLO modelleriyle, yani bölütleme ile sınıflandırmayla, %100 çözüm oranına ulaşılmıştır; önceki çalışmalarda bu oran %68 ile %71 arasındaydı.

Tasarım için en önemli bulgu şudur: insanların ile botların çözmesi gereken meydan okuma sayısı arasında anlamlı bir fark bulunmamaktadır ile makale, reCAPTCHA'nın insanlığı yargılarken büyük ölçüde çerez ile tarayıcı geçmişi verisine dayandığına dair kanıt bulmaktadır. Yani reCAPTCHA'nın gerçek savunması hiçbir zaman bulmaca değildi; Google'ın siteler arası kimlik grafiğiydi. Kendi bulmacasını barındıran bir kimlik sağlayıcı bunun hiçbirini elde etmemektedir.

Açık CAPTCHA dünyası çalışması, NeurIPS 2025, arXiv 2505.24878, 20 tipte 225 CAPTCHA içermektedir: en gelişmiş çok modlu büyük dil modeli ajanları ciddi biçimde zorlanmakta ile başarı oranı en fazla %40 olmaktadır; insan performansı %93,3'tür.

Biliş çalışması, arXiv 2512.02318, USENIX Security 2026'da kabul edilmiştir. Yedi model ile 18 gerçek dünya CAPTCHA tipi incelenmiştir. Bulgusu şudur: modeller tanıma ile düşük etkileşimli CAPTCHA'ları insana benzer maliyet ile gecikmeyle çözmektedir; ince taneli konumlandırma, çok adımlı uzamsal akıl yürütme ile kareler arası tutarlılık zor kalmaktadır. Yeniden tasarlanmış meydan okumalar en gelişmiş modellerin başarı oranını %95'in üzerinden sıfıra düşürmektedir.

Sentez şudur: saf görüntü tanıma ölmüştür, yani %100 çözülebilirdir. Etkileşim derinliği ile uzamsal akıl yürütme gerektiren CAPTCHA'lar hâlâ ölçülebilir bir boşluk tutmaktadır, yani %40'a karşı %93. Arkose MatchKey ile biliş savunmalarının işgal ettiği alan tam olarak burasıdır. Ancak boşluk hareketli bir hedeftir ile her model kuşağında yeniden kapanmaktadır.

#### 31.2 Çözüm ekonomisi: CAPTCHA'yı öldüren rakam

2captcha.com fiyatlandırması, 8 Eylül 2026'da çekilmiştir; bin çözüm başına dolar cinsindendir.

| Tip | Bin çözüm başına fiyat |
|---|---|
| Normal ya da görüntü captcha'sı | 0,50 ile 1,00 dolar |
| reCAPTCHA ikinci sürüm, görünmez ile geri çağırmalı dahil | 1,00 ile 2,99 dolar |
| reCAPTCHA üçüncü sürüm, skor 0,3 ve altı | 1,45 dolar |
| reCAPTCHA kurumsal | 1,00 ile 2,99 dolar |
| Cloudflare Turnstile | 1,45 dolar |
| Arkose Labs ile FunCaptcha | 1,45 ile 50,00 dolar |
| Friendly Captcha | 1,45 dolar |
| Akamai, Kasada ile PerimeterX | Sıfırdır; kendin yap hizmeti sunulmamaktadır |

Tasarım sonucu şudur: bir CAPTCHA kapısı saldırgana sahte hesap başına yaklaşık binde bir ile binde üç dolar maliyet bindirmektedir. Getirisi binde üç doları aşan her sahtekârlık etkilenmemektedir. Tablodaki tek anlamlı ekonomik değişiklik Arkose'un 50 dolarlık tavanıdır; yüksek olmasının nedeni tam olarak MatchKey'in hedef başına model yeniden eğitimi zorlamasıdır, yani yaklaşık 30 kat maliyet artışıdır.

Gecikme asimetrisi de gerçektir: çözücü servisler meydan okuma başına 10 ile 30 saniye almakta ile belirteçler tipik olarak yaklaşık beş dakikada sona ermektedir. Kararlı bir saldırganı durdurmasa da yüksek hızlı kayıt selleri için gerçek bir sürtünmedir.

#### 31.3 Satıcılar

| Satıcı | Mekanizma | Doğrulanmış olgular |
|---|---|---|
| Cloudflare Turnstile | Etkileşimsiz JavaScript sondaları: iş kanıtı, yani hesaplamalı bulmacalar, alan kanıtı, web API'lerinin yoklanması, tarayıcı tuhaflıkları ile insan davranış örüntüleri. Modları yönetilen, etkileşimsiz ile görünmezdir | Genel kullanıma 29 Eylül 2023'te açılmıştır. 25 milyondan fazla site meydan okuma sayfalarında çalıştırmaktadır; bir müşteri tek ayda bir milyondan fazla otomatik kayıt denemesini sıfır bildirilen yanlış pozitifle engellemiştir; kullanıcılardan hiç etkileşim istenmeden bile CAPTCHA kadar etkili olduğu belirtilmektedir. Ücretsiz planı 20 bileşene kadar, bileşen başına 10 ana bilgisayar adı, yedi günlük analitik ile sınırsız meydan okuma sunmaktadır. Gizlilik açısından yalnızca kesinlikle gerekli veriyi işlemekte ile kullanıcı iletişimlerine, form girdilerine ya da diğer sayfa girdilerine erişmemekte, bunları saklamamakta ve iletmemektedir. Aynı zamanda bir Privacy Pass kanıtlayıcısıdır. Web erişilebilirlik kılavuzu seviyesi Cloudflare'in kendi iki sayfası arasında çelişmektedir |
| hCaptcha | Onay kutusu, görünmez ile kurumsal pasif ve neredeyse pasif modlar artı risk skorları | IP adresi doğruluğu maddi olarak artırmakta ile kurumsal sürüm için risk skorlarını mümkün kılmaktadır. Dokümanlarında GDPR ya da saklama iddiası yoktur; KVKK kapsamlı bir tasarım için not edilmeye değer bir boşluktur |
| Arkose Labs MatchKey | Düşmanca bozulmuş meydan okumalar: insanlara görünmeyen ancak makine yorumunu değiştiren varyasyonlar; amaç rakiplerin modellerini sürdürme ile güncelleme maliyetini artırmaktır | 28 Mayıs 2024 tarihli satıcı yayınındaki, bağımsız tekrarlanmamış iddiaya göre bir oyun müşterisinin parola sıfırlama akışında botların %1'inden azı yapay zekâya dirençli meydan okumayı çözebilmiş, değiştirilmemiş görüntüyü ise %92'den fazlası çözebilmiştir. 2captcha'nın 50 dolarlık tavanı bunu dışarıdan doğrulamaktadır |
| Friendly Captcha | Uyarlanabilir iş kanıtıdır, görünmezdir ile riske göre tırmanmaktadır. Çerez, kalıcı tarayıcı depolaması ile davranışsal parmak izi kullanmamaktadır; Alman şirketidir ile Avrupa Birliği veri ikametgâhı sunmaktadır | Setin en güçlü GDPR ile KVKK hikâyesidir. Ancak 2captcha bin çözümü 1,45 dolara fiyatlamaktadır; iş kanıtı tek başına ekonomik olarak caydırıcı değildir |
| DataDome, Castle, Kasada ile HUMAN | Sunucu tarafı makine öğrenimi: cihaz, davranış ile ağ sinyalleri; bulmaca öncelikli değildir | Kendin yap hizmeti değildir; basın sayfaları otomatik çekime 403 döndürmüştür ile doğrulanmamıştır. 2captcha'nın onları sıfır dolarla listelemesi, yani kendin yap çözüm hedefi olarak sunmaması, belirteç tabanlı CAPTCHA'lardan daha zor çiftlendiklerine dair zayıf bir kanıttır |

#### 31.4 Bot trafiği payı, tarihli sert rakamlar

Imperva'nın 15 Nisan 2025 tarihli 2025 kötü bot raporundan: otomatik trafik 2024'te tüm web trafiğinin %51'idir ile on yılda ilk kez insanı geçmiştir. Kötü botlar %37'dir, 2023'te %32'ydi. Basit kötü botlar %40'ın altından %45'e çıkmıştır. Hesap ele geçirme saldırıları 2024'te %40 artmıştır ile tüm girişlerin %14'ü bir devralma denemesidir. Finansal hizmetler tüm hesap ele geçirme olaylarının %22'sidir; telekom ile internet servis sağlayıcıları %18, bilişim %17'dir. Gelişmiş botlar %44 oranında API'leri, %10 oranında uygulamaları hedeflemektedir.

Imperva'nın 29 Nisan 2026 tarihli ajan çağında botlar raporundan: botlar 2025'te tüm web trafiğinin %53'ünden fazlasıdır, önceki yıl %51'di; insanlar %47'ye düşmüştür. Bot saldırılarının %27'si API uç noktalarını hedeflemiştir. Finansal hizmetler tüm bot saldırılarının %24'ü ile hesap ele geçirme olaylarının %46'sıdır. 2026 yazısı girişlerin yüzde kaçının hesap ele geçirme olduğu rakamını tekrarlamamaktadır; 2025 raporunun %14'ü kullanılmalı ile tarihlendirilmelidir.

Cloudflare Radar'ın Aralık 2025 tarihli yıl değerlendirmesinden, 1 Ocak ile 2 Aralık 2025 arasını kapsamaktadır: 2 Aralık 2025 itibarıyla HTML isteklerinin %47'si insan, %44'ü yapay zekâ olmayan botlar, ortalama %4,2'si Googlebot hariç yapay zekâ botları ile %4,5'i Googlebot'tur. Küresel internet trafiği 2025'te %19 artmıştır.

Dolaşımdaki 2026 Cloudflare rakamları kullanılmamalıdır; üçüncü taraf toplayıcı bloglardan gelmekte, birbirleriyle çelişmekte ile Cloudflare'in kendi radar sitesine karşı doğrulanamamaktadır.

#### 31.5 CAPTCHA ölmüş müdür, savunulabilir pozisyon

1. Bir Turing testi olarak evet ölmüştür. reCAPTCHA ikinci sürüm görüntülerinde %100 çözüm oranı hakemli bir çalışmayla gösterilmiştir; çözüm maliyeti binde bir ile binde üç dolardır; meydan okuma artık insanı makineden ayırmamaktadır.
2. Bir maliyet ile gecikme vergisi ve sinyal toplama aracı olarak hayır ölmemiştir. Turnstile'ın değeri, onay kutusu taklidi yaparken çalıştırdığı yaklaşık 20 tarayıcı ortam sondasıdır, onay kutusu değildir. NIST 63B, bot tespit ile azaltım meydan okumasını üstel geri çekilme ve risk sinyalleriyle birlikte bir izin olarak listelemektedir; yani onu üç değiştirilebilir teknikten biri saymaktadır, asla kontrolün kendisi değil.
3. Onun yerini fiilen ne aldığı, maliyet sırasıyla dört katmandır. Birincisi görünmez cihaz ile tarayıcı ortam sinyalleridir, yani Turnstile, hCaptcha kurumsal, DataDome, Castle, Kasada ile HUMAN; trafiğin büyük kısmını yaklaşık sıfır kullanıcı sürtünmesiyle karşılamaktadır. İkincisi gri bölge için uyarlanabilir iş kanıtıdır, yani Friendly Captcha; Turnstile de içeride iş ve alan kanıtı yapmaktadır. Mahremiyet açısından temizdir ancak tek başına ekonomik olarak zayıftır. Üçüncüsü platform sunuyorsa kriptografik kanıtlamadır, yani Apple'ın özel erişim belirteçleri, Android oynatma bütünlüğü ile WebAuthn geçiş anahtarı. İstek başına en güçlü sinyaldir ile en dar kapsamdır. Dördüncüsü yükseltilmiş ya da bant dışı doğrulamadır, yani hesap var olmadan önce e-posta veya kısa mesaj onay kodudur; bu aynı zamanda NIST 63A'nın otomatik kayıt azaltmasıdır ile WebAuthn şartnamesinin önerdiği numaralandırma düzeltmesidir. Bu iki gereksinim tek bir kontrolde birleşmektedir.
4. Birinci katman üzerindeki Avrupa Birliği ile KVKK kısıtı, Türk bir kimlik sağlayıcı için isteğe bağlı bir renk değildir. CNIL, reCAPTCHA'nın otomatik olarak GDPR uyumlu olmadığına ile güvenlik dışındaki amaçlar için aşırı kişisel veri kullandığına hükmetmiştir; 125.000 avroluk Cityscoot cezası reCAPTCHA kullanımına atıfta bulunmaktadır. 28 Kasım 2024'te yayımlanan Avusturya kararına göre, rıza reddedilmesine rağmen veri Google'a aktığında reCAPTCHA rızasız kullanımı hukuka aykırıdır. Dolayısıyla Avrupa Birliği ile Türkiye'ye bakan bir kimlik sağlayıcı için Turnstile ya da Friendly Captcha reCAPTCHA'ya tercih edilmeli ile bu seçim bir KVKK ve GDPR veri asgarileştirme kararı olarak belgelenmelidir.

---

### 32. Privacy Pass ile özel erişim belirteçleri

#### 32.1 RFC numaralandırması, yaygın bir atıf hatası

| RFC | Gerçek başlık | Tarih | Statü |
|---|---|---|---|
| 9576 | Privacy Pass mimarisi | Haziran 2024 | Bilgilendiricidir |
| 9577 | Privacy Pass HTTP kimlik doğrulama şeması | Haziran 2024 | Standartlar yoludur |
| 9578 | Privacy Pass verme protokolleri | Haziran 2024 | Standartlar yoludur |

RFC 9577'nin verme protokolleri olduğu yanlıştır; 9577 HTTP kimlik doğrulama şemasıdır ile verme protokolleri 9578'dir. Set üç RFC'dir, iki değil, ile hepsi Haziran 2024 tarihlidir. İlgili olarak RFC 9497, yani körleştirilmiş sözde rastgele fonksiyonlar, özel doğrulanabilir varyantın temelidir.

#### 32.2 Özel belirteç şeması, RFC 9577

Meydan okumada köken 401 ile yanıt vermektedir.

```
WWW-Authenticate: PrivateToken challenge=<base64url>, token-key=<base64url>
```

Meydan okuma alanı base64url kodlu bir meydan okuma yapısıdır, tüm meydan okumalar için zorunludur ile dolgu içermelidir. Belirteç anahtarı alanı base64url kodlu veren açık anahtarıdır; istemcilerin anahtarı bant dışı bir mekanizmayla alabildiği dağıtımlarda atlanabilmektedir.

Meydan okuma yapısı iki oktetlik bir belirteç tipi, ASCII veren adı, sıfır ya da 32 baytlık bir kullanım bağlamı ile isteğe bağlı bir köken listesinden oluşmaktadır.

Kullanımda yetkilendirme başlığı özel belirteci taşımaktadır. Belirteç yapısı iki oktetlik belirteç tipi, 32 oktetlik istemci nonce'ı, meydan okumanın SHA-256 özeti olan 32 oktetlik bir özet, değişken uzunlukta bir anahtar kimliği ile değişken uzunlukta bir doğrulayıcıdan oluşmaktadır.

Verme belirteç tipleri, RFC 9578'den, şunlardır.

| Kod | Ad | Doğrulama |
|---|---|---|
| 0x0001 | P-384 ile SHA-384 üzerinde doğrulanabilir körleştirilmiş fonksiyon | Özel doğrulanabilirdir; verenin özel anahtarı gerekmektedir |
| 0x0002 | 2048 bitlik kör RSA | Herkese açık doğrulanabilirdir; verenin açık anahtarı yeterlidir |

#### 32.3 Apple özel erişim belirteçleri

WWDC 2022'de duyurulmuştur; Apple geliştirici haberi 9 Haziran 2022 tarihlidir. iOS 16, iPadOS 16 ile macOS Ventura ve sonrasında desteklenmektedir. İkinci belirteç tipini, yani herkese açık doğrulanabilir kör RSA imzalarını kullanmaktadır; bu kasıtlıdır, böylece herhangi bir köken yalnızca verenin açık anahtarıyla doğrulayabilmektedir. Kanıtlama Secure Enclave ile cihazın Apple kimliği durumundan gelmektedir; yani Apple, bunun iyi durumda gerçek bir Apple hesabı olan gerçek bir cihaz olduğuna, hangisi olduğunu söylemeden kefil olmaktadır. Apple'ın adlandırdığı açık veren dizinleri Cloudflare ile Fastly'nindir.

#### 32.4 Cloudflare dağıtımı ile benimseme durumu

Roller kökendir, ki doğrulamaktadır; verendir, ki imzalamaktadır; ile kanıtlayıcıdır, ki kimin belirteç hak ettiğine karar vermektedir.

En önemli operasyonel olgu şudur: Cloudflare yönetilen meydan okuması bir Privacy Pass kökenidir ile iki meydan okuma sunmaktadır, biri Apple vereni diğeri Cloudflare araştırma vereni için. Yani Cloudflare yönetilen meydan okumasının arkasındaysanız, hiç ilgili kod yazmadan zaten bu belirteçleri tüketmektesiniz.

Cloudflare Turnstile tabanlı bir kanıtlayıcı dağıtmıştır, yani Turnstile geçilince belirteç alınmaktadır, ile açık bir araştırma vereni işletmektedir.

Cloudflare, Privacy Pass'ı web uygulaması güvenlik duvarı ile bot yönetimi ürünlerinde önemli bir sinyal olarak kullanmaktadır; bu da milyonlarca sitenin Privacy Pass'ı yerel olarak sunması demektir.

Bir benimseme çekincesi vardır, Cloudflare'in kendi dokümanından: Privacy Pass şu anda kendin yap bir ürün değildir ile üretim dağıtımı Cloudflare ile yönetilen bir angajmandır.

#### 32.5 Kimlik sağlayıcı kayıt suistimalinde kullanılabilir mi, pratik hüküm

Evet, ancak yalnızca olumlu bir sinyal olarak, asla bir kapı olarak.

İşe yarayan şudur: kayıt gönderisinde geçerli bir özel belirteç yetkilendirme başlığı varsa ile güvenilen bir veren anahtarına karşı doğrulanıyorsa, o istek için CAPTCHA atlanmalı ile hız sınırı gevşetilmelidir. Bu, belirteci saf bir sürtünme kaldırma aracına çevirmektedir; başarısızlık modu kullanıcının CAPTCHA görmesidir, kullanıcının kilitlenmesi değil.

İşe yaramayan şudur: belirteci zorunlu kılmak. Kapsam yapısal olarak kısmîdir.

İstemci kapsamı pratikte esasen yalnızca Apple'dır, yani iOS 16 ile macOS Ventura sonrası, Safari ile sistem ağ yığınını kullanan uygulamalardır. Türk bir tüketici kimlik sağlayıcısı, hiç bu yeteneği olmayan büyük bir Android ile Chrome ve Windows çoğunluğu görecektir. Açık web için Google ile Chrome eşdeğeri yoktur; web ortamı bütünlüğü önerisi öldürülmüştür. Turnstile kanıtlayıcısı Cloudflare'in ikamesidir ancak o Turnstile'dır, bir cihaz kanıtlaması değildir. Cloudflare angajmanı olmadan ya da kendi vereninizi ve kanıtlayıcınızı kurmadan kendiniz çalıştıramazsınız.

Hız sınırlama nüansı şudur: kullanım bağlamı alanı, yani sıfır ya da 32 bayt, belirteçleri bir bağlama bağlamanıza izin vermektedir; ancak belirteçler yapısal olarak bağlanamazdır, yani bu cihaz kaç kayıt yaptı sorusu sayılamamaktadır. Belirteç size gerçek bir cihaz bunu yaptı bilgisini vermekte, asla aynı gerçek cihaz bunu 500 kez yaptı bilgisini vermemektedir. Üzerine cihaz başına kota tasarlanmamalıdır.

Kimlik sağlayıcı kayıt uç noktası için mantıklı katmanlı politika şudur.

1. Ucuz IP ile otonom sistem numarası ve hız kapısı kütleyi reddetmektedir, yaklaşık sıfır maliyetle.
2. Özel erişim belirteci varsa ile geçerliyse hızlı yol açılmalı ile meydan okuma sorulmamalıdır.
3. Değilse Turnstile ya da Friendly Captcha yönetilen meydan okuması gösterilmelidir.
4. Her zaman, hesap maddileşmeden önce e-posta ya da kısa mesaj bant dışı onay kodu istenmelidir; bu, NIST 63A ile WebAuthn şartnamesinin gereksinimlerini tek bir kontrolde karşılamaktadır.

#### 32.6 Google tarafı

Web ortamı bütünlüğü önerisinin öldüğü doğrulanmıştır. Prototip Chromium'da Mayıs ile Kasım 2023 arasında yaşamıştır; 2 Kasım 2023'te Google, sürekli web için dijital hak yönetimi eleştirisinin ardından öneriyi terk etmiş ile prototipi kaldırmıştır. İkamesi kapsamı daraltılmış Android web görünümü medya bütünlüğü API'sine indirgenmiştir. 2026'da bunun bir Chrome ya da web platformu halefi yoktur.

Oynatma bütünlüğü API'si Android yerlisi analogdur ile mobil uygulamada kayıt suistimali için gerçekten kullanılabilir. Standart istekler ucuz ile gecikme dostudur ile yeniden oynatılabilirlik ve dışa sızdırmaya karşı korumanın bir kısmını Google Play'e devretmektedir; klasik istekler daha pahalıdır ile doğru gerçeklenmesinden siz sorumlusunuzdur. Kararları uygulama bütünlüğü, yani Google Play'in tanıdığı değiştirilmemiş ikili dosya; cihaz bütünlüğü, yani gerçek sertifikalı bir Android cihaz; ile hesap detaylarıdır, yani kullanıcının Play üzerinden kurup kurmadığı veya ödeyip ödemediğidir. Tercihe bağlı ekstralar güçlü bütünlük kararı, uygulama erişim riski kararı ile Play koruma kararıdır. Bir web çözümü değildir; yalnızca uygulama ile yalnızca Google Play içindir. Kök erişimli, Google'sızlaştırılmış ya da açık kaynak Android kullanıcıları başarısız olmaktadır; açıkça karar vermeniz gereken gerçek bir erişilebilirlik ile kapsayıcılık maliyetidir.

DBSC farklı bir problemdir, yani oturum ele geçirmedir, kayıt değildir; ancak artık sevk edilmektedir. Windows'ta genel kullanıma açılmıştır, güvenilir platform modülü destekliyle. Google Workspace duyurusu 28 Mayıs 2026'dır, kademeli dağıtım 25 Mayıs 2026'dan itibarendir, tam görünürlüğe 60 güne kadar sürmektedir ile varsayılan açıktır ve bir yönetici kapatma anahtarı yoktur. macOS sürümü Secure Enclave destekli olarak sonraki sürümdedir. Detay için §21'in birinci kısmına bakınız.

#### 32.7 WebAuthn ile geçiş anahtarı kaydı bir bot savunması olarak

Dürüst değerlendirme şudur: bot savunması olarak zayıftır, diğer her şey için güçlüdür.

Geçiş anahtarı kaydı bir kimlik doğrulayıcı üzerinde kullanıcı jesti gerektirmekte ile bu, betikli kütle kaydın maliyetini yükseltmektedir. Ancak yazılım kimlik doğrulayıcıları ile sanal kimlik doğrulayıcı API'leri, ki her WebAuthn test paketinin kullandığıdır, kimlik bilgilerini programatik olarak yaratmaktadır. Kanıtlama olmadan bir kimlik bilgisi oluşturma çağrısı ne insan ne gerçek cihaz kanıtıdır.

Savunulabilir sürüm şudur: kanıtlama zorunlu kılınmalı, yani doğrudan kanıtlama iletimi istenmeli, ile yüksek güvenceli kayıtlar FIDO metadata servisine karşı doğrulanmalıdır. Bu sizi cihaz kanıtlamasıyla karşılaştırılabilir bir duruşa geri getirmektedir; bedeli yazılım geçiş anahtarlarını reddetmek, yani çoğu tüketici geçiş anahtarını reddetmektir. Tüketici kimlik sağlayıcısı için uygun değildir; iş gücü ile yüksek güvenceli kayıt için uygundur.

Geçiş anahtarının kayıttaki gerçek kazancı başka yerdedir: doldurulacak parola yoktur, numaralandırılacak parola sıfırlama akışı yoktur ile şartnamenin kayıt rehberliği numaralandırma düzeltmesini bedavaya vermektedir.

---

### 33. Tek kullanımlık e-posta ile artı etiketi

#### 33.1 Tespit teknikleri, kesinlik sırasıyla

1. Statik alan adı engelleme listesi. İlgili açık depo yaklaşık 3.500 alan adı içermektedir, CC0 lisanslıdır, aktif bakımlıdır ile PyPI üretimde kayıt engellemek için kullanmaktadır. Kendi açıklamasındaki çekince dürüst olanıdır: bunların hepsinin hâlâ tek kullanımlık sayılabileceği garanti edilememekte ancak temel kontrol yapıldığı için bir zamanlar tek kullanımlık oldukları muhtemel görülmektedir. Başarısızlık modu şudur: tek kullanımlık sağlayıcılar alan adlarını herhangi bir listenin güncellenmesinden hızlı döndürmekte ile özel alan adları satmaktadır. Engelleme listesi tembel %80'i yakalamakta, başka bir şey yakalamamaktadır.
2. Posta değişim kaydı kontrolleri. Ucuzdur, yüksek değerlidir ile farklı bir başarısızlık sınıfını yakalamaktadır. Posta kaydı yoksa ile adres kaydı yedeği de yoksa sert reddedilmelidir; bu bir teslim edilebilirlik kontrolüdür, bir suistimal kontrolü değildir ile neredeyse yanlış pozitifsizdir. Bilinen tek kullanımlık altyapıyı gösteren bir posta kaydı, alan adından daha güçlü bir sinyaldir, çünkü tek kullanımlık operatörler rotasyonlu alan adları arasında posta altyapısını yeniden kullanmaktadır. Kayıtta asla canlı bir alıcı sondajı yapılmamalıdır: yavaştır, gri liste ya da engelleme listesine alınmanıza yol açmaktadır ile çoğu sağlayıcı zaten hepsini yakala yanıtı döndürmektedir.
3. Alan adı yaşı ile kayıt yeniliği, yani alan adı kayıt sorgusu. Üç gün önce kaydedilmiş ile posta kabul eden bir alan adı güçlü bir suistimal sinyalidir. Bu tam olarak NIST 63A'nın cihaz ya da hesap kıdemi kontrolüdür ile standart onaylıdır.
4. Ticari API'ler, yani ZeroBounce ile Kickbox; gerçek zamanlı posta kaydı ile sunucu kontrolleri yapmakta ile teslim edilebilir, edilemez, riskli ya da bilinmiyor kararıyla bir skor döndürmektedir. Bunlar suistimal için değil e-posta pazarlama teslim edilebilirliği için ayarlanmıştır. Riskli kovaları gönderen itibarını korumak için optimize edilmiştir ile gizlilik aktarıcılarını seve seve işaretlemektedir. Bir pazarlama doğrulayıcısının ikili kararı doğrudan hesap oluşturma reddine bağlanmamalıdır.

#### 33.2 Yanlış pozitif problemi: gizlilik aktarıcıları tek kullanımlık değildir

Apple tarafında zaman çizelgesi önemlidir.

| Tarih | Olay |
|---|---|
| 15 Haziran 2026 | Apple geliştirici haberi: Apple ile giriş ile e-postamı gizle için yeni alan adı; ikisini de aynı özel alan adı altında birleştirme duyurusudur |
| 24 Ağustos 2026 | Apple gizlilik tepkisi sonrası kısmen geri adım atmıştır. E-postamı gizle iCloud alan adında kalmaktadır. Apple ile giriş yine de yeni özel alan adına taşınmaktadır |

Apple'ın geliştirici rehberliği birebir şudur.

> "Developers with apps or websites that use Sign in with Apple should ensure that their account systems, email validation logic, and allowlists accept addresses on the new `private.icloud.com` domain in addition to the existing `privaterelay.appleid.com` domain."

Mevcut aktarıcı adresleri kesintisiz çalışmaya ile yönlendirmeye devam etmektedir.

Apple'ın neden geri adım attığı şudur: e-postamı gizle özelliğini iCloud alan adında tutmak, servislerin bu takma adları her sıradan iCloud kullanıcısını da engellemeden alan adı seviyesinde engelleyememesi demektir. Bu, Apple'ın kasıtlı bir engelleme karşıtı tasarım tercihidir ile politika sorusunu sizin için kapatmaktadır: bu takma adları gerçek iCloud adreslerinden asla ayırt edemeyeceksiniz.

2026'da sevk edilen her kimlik sağlayıcı için aksiyon maddesi şudur: izin listeniz hem eski aktarıcı alan adını hem yeni özel alan adını içermelidir. Haziran 2026'dan önce kurulmuş bir sistem, yeni Apple ile giriş kullanıcılarını sessizce reddetmeye başlayacaktır. Bu canlı ile tarihli bir kırılmadır.

İzin listesine alınması gereken diğer gizlilik aktarıcıları şunlardır. Firefox Relay maskeleri `mozmail.com` üzerindedir; özel alt alan adları için eski alan adından taşınmıştır, yani alt alan adlı biçimler de olabilmektedir. Mozilla'nın kendi sıkça sorulan soruları hasarı belgelemektedir: bazı siteler alt alan adı içeren bir e-posta adresini kabul etmemekte ile bazıları Gmail, Hotmail ya da Yahoo dışındaki tüm adresleri kabul etmeyi bırakmıştır. SimpleLogin, yani Proton, `simplelogin.io`, `aleeas.com` ile kullanıcı özel alan adlarını kullanmaktadır; güncel liste birincil kaynaktan doğrulanmamıştır ile sabit kodlamadan önce kontrol edilmelidir. DuckDuckGo e-posta koruması `duck.com` kullanmaktadır; doğrulanmamıştır.

#### 33.3 Önerilen politika

Tek kullanımlık olduğu gerekçesiyle asla engelleme yapılmamalıdır. Skorlanmalı ile zorlamayı onay kodu yapmalıdır.

1. Yalnızca teslim edilebilirlik üzerinden sert reddedilmelidir: sözdizimsel olarak geçersiz adresler ya da posta ve adres kaydı bulunmayan alan adları. Sıfıra yakın yanlış pozitif vardır.
2. Adlandırılmış gizlilik aktarıcıları izin listesine alınmalı ile sıradan adresler gibi muamele görmelidir. Bunlar ödeme yapan, mahremiyet bilinçli ile yüksek değerli kullanıcılardır; Apple ile giriş muhtemelen istediğiniz birinci sınıf bir federasyon yoludur. Onları engellemek kendinize açtığınız bir dönüşüm yarasıdır.
3. Tek kullanımlık liste isabetleri, alan adı yaşı ile posta kaydı itibarı üzerinden skorlanmalı, engellenmemelidir. Skor riske dayalı yükseltmeye beslenmelidir, yani ek doğrulama, gecikmeli güven ya da daha düşük başlangıç hız sınırına, reddetmeye değil.
4. Gerçek kapı bant dışı onay kodu olmalıdır. Zarif kısım şudur: hesap oluşturulmadan önce zorunlu bir e-posta gidiş dönüşü, sahte adresleri otomatik yenmektedir, yani posta kutusu yoksa kod yoktur ile hesap yoktur; NIST 63A'nın otomatik kayıt azaltmasını karşılamaktadır; ile kayıt numaralandırma sızıntısını çözmektedir. Kodu alan çalışan bir tek kullanımlık adres, kimlik doğrulama amaçları için çalışan bir adrestir; taşıdığı risk botluk değil hesap kurtarılabilirliğidir.
5. Gerçek risk yeniden çerçevelenmelidir. Tek kullanımlık e-postanın bir kimlik sağlayıcıya gerçek zararı sahtekârlık değil yetim hesaplardır: posta kutusu buharlaşmakta, kullanıcı asla hesap kurtarma yapamamakta ile siz sonsuza kadar kurtarılamaz bir kimlik taşımaktasınız. Bu, kayıt engellemeyle değil kurtarma yöntemi gereksinimleriyle çözülmelidir; NIST 63B'ye göre kullanıcının en az iki kurtarma adresi tanımlamasına izin verilmelidir.
6. Belirli bir suistimale duyarlı eylem için engelleme gerekiyorsa, yani ücretsiz deneme, promosyon kredisi ya da referans bonusu için, kayıtta değil o eylemde engellenmelidir. Farklı risk, farklı kapı demektir.

#### 33.4 Artı etiketi ile e-posta normalizasyonu

Standartlar şunu söylemektedir. RFC 5321, yani Ekim 2008 tarihli posta protokolü, iki belirleyici cümle içermektedir: adresin yerel kısmı yalnızca adresin alan adı kısmında belirtilen ana bilgisayar tarafından yorumlanmalı ile anlamlandırılmalıdır; ile bir posta kutusunun yerel kısmı harf büyüklüğüne duyarlı muamele edilmelidir.

RFC 5233, yani Ocak 2008 tarihli alt adres uzantısı, bir detay alt parçası tanımlamaktadır; bu, kullanıcı kısmından artı gibi bir ayırıcı karakter dizisiyle ayrılmaktadır. Artı işareti zorunlu değildir; RFC açıkça detaylı adreslerin kodlanmasının siteye ya da gerçeklemeye özgü olduğunu söylemektedir. Qmail tarihsel olarak eksi kullanmıştır; başka sistemler eşittir ya da kare işareti kullanmaktadır.

Tasarım dokümanı için hukuki sonuç şudur: RFC 5321'e göre etiketli ile etiketsiz adres sizin açınızdan iki farklı adrestir. Onları aynı kimlik saymak, başkasının isim alanı hakkında yaptığınız bir politika tercihidir ile RFC 5321 o isim alanının sizin yorumlamanıza ait olmadığını söylemektedir. Aynı argüman noktalar için daha da güçlü geçerlidir: nokta önemsizliği bir Gmail ürün kararıdır, bir e-posta standardı değildir; bunu başka bir sağlayıcıya ya da kurumsal bir alan adına uygulamak gerçekten farklı kullanıcıları tek hesapta birleştirmektedir.

Gerçek ile belgelenmiş suistimal Agari'nin 2018 vakasıdır. İşletme e-postası ele geçirme aktörleri tek bir Gmail adresinin 56 farklı nokta varyantını kullanmıştır. Dört ABD finans kurumunda 48 kredi kartı başvurusu yapılmış ile en az 65.000 dolarlık sahte kredi onaylanmıştır. Bir çevrim içi vergi servisinde 13 sahte beyanname verilmiştir. On iki posta idaresi adres değişikliği talebi yapılmıştır. On bir sahte sosyal güvenlik yardımı başvurusu yapılmıştır. Tek bir eyalette dokuz işsizlik yardımı kimliği alınmıştır. Ticari bir satış müşteri adayı servisinde 14 deneme hesabı açılmıştır. Üç afet yardımı başvurusu yapılmıştır.

Liste dikkatle okunmalıdır: her bir kalem kişi başına bir kez verilen bir haktır, yani kredi, yardım, deneme ile vergi iadesidir. Bir tanesi bile bir kimlik doğrulama ihlali değildir. Tasarım dersinin tamamı budur.

Sağlayıcı davranışı şöyledir.

| Sağlayıcı | Noktalar | Artı etiketleri |
|---|---|---|
| Gmail ile Workspace | Yok sayılmaktadır | Desteklenmekte ile yönlendirme için sıyrılmaktadır |
| Outlook ile Microsoft 365 | Anlamlıdır | Desteklenmektedir |
| Yahoo | Anlamlıdır | Klasik artı yerine taban ile anahtar sözcük tarzı kullanılmaktadır |
| Fastmail, Proton ile iCloud | Anlamlıdır | Artı desteklenmektedir |
| Çoğu kendi barındırılan ya da kurumsal sistem | Anlamlıdır | Değişkendir; qmail türevleri eksi kullanmaktadır |

Nokta eşdeğerliği büyük sağlayıcılar arasında yalnızca Gmail'e özgüdür. Küresel olarak uygulamak bir hatadır.

Önerilen politika kanonik saklamak ile ham üzerinden anahtarlamaktır.

| Soru | Cevap | Neden |
|---|---|---|
| Kayıtta artı reddedilmeli midir | Hayır | Meşru ile yaygın öğretilen bir mahremiyet pratiğini kırmaktadır; kullanıcılar ihlalleri tespit etmek için kasten etiketlemektedir. Kimseyi durdurmamaktadır, çünkü saldırganlar nokta kullanmakta ya da binde bir dolara yeni posta kutusu almaktadır |
| Etiketli ile etiketsiz adres aynı giriş olmalı mıdır | Hayır | RFC 5321 bunun alıcı ana bilgisayarın kararı olduğunu söylemektedir. Kullanıcının ayrı sandığı hesapları birleştirmek bir doğruluk ile güvenlik hatasıdır; Gmail dışı alan adlarında nokta normalizasyonu iki gerçek farklı insanı birleştirebilmektedir |
| Normalize edilmiş biçim saklanmalı mıdır | Evet | Ham adres teslimat ile RFC doğruluğu için, kanonik adres ise küçük harfe çevrilmiş ve yalnızca bilinen Gmail alan adları için noktalar ve etiket sıyrılmış olarak saklanmalıdır. İkisi de indekslenmelidir |
| Kanonik biçim nerede kullanılmalıdır | Yalnızca suistimal skorlaması ile müşteri başına bir kez verilen haklarda | Ücretsiz denemeler, promosyon kredileri, referans bonusları, kayıt hız limitleri ile çoklu hesap tespiti. Tam olarak Agari saldırı yüzeyidir ile yalnızca o yüzeydir |

Ek korumalar şunlardır. Etiket sınırlanmalı, yani absürt yerel kısımlar, örneğin birden çok artı işareti ya da 64 oktetten uzun kısımlar reddedilmelidir; ucuzdur ile meşru kayıp yoktur. Kanonik biçim asla kullanıcıya görünen bir hatada yüzeye çıkarılmamalıdır: kanonik adres üzerinden anahtarlanmış bu e-posta zaten kayıtlı mesajı, ham adres üzerinden anahtarlanmış olandan kesinlikle daha kötü bir numaralandırma kâhinidir, çünkü yalnızca etiketli bir adres deneyen saldırgana etiketsiz adresin var olduğunu sızdırmaktadır. Bilinmeyen alan adları arasında normalizasyon yapılmamalıdır; nokta önemsiz sağlayıcıların açık bir listesi tutulmalı, yani gerçekçi olarak Google'ın alan adları, ile diğer her şeyde yalnızca küçük harfe çevrilmelidir.

---

### 34. Numaralandırma önleme

#### 34.1 OWASP, normatif temel çizgi

Kimlik doğrulama özet sayfası şunları söylemektedir. Kimlik doğrulama işlevselliğinde yanlış gerçeklenmiş hata mesajları, kullanıcı kimliği ile parola numaralandırması amacıyla kullanılabilmektedir. Kullanıcı kimliği ya da parola yanlış, hesap yok ile hesap kilitli veya devre dışı durumlarının hepsinde aynı genel hata mesajı verilmelidir. Doğru mesaj giriş başarısız, kullanıcı kimliği ya da parola geçersiz biçimindedir; yanlış olanlar kullanıcı için geçersiz parola ya da geçersiz kullanıcı kimliği biçimindekilerdir. Parola kurtarmada mesaj, o e-posta adresi veritabanımızdaysa parolanızı sıfırlamanız için bir e-posta göndereceğiz olmalıdır. Hesap oluşturmada mesaj, hesabınızı etkinleştirecek bir bağlantı verdiğiniz adrese gönderildi olmalıdır.

Zamanlama üzerine birebir şunu söylemektedir: işleme süresi duruma göre, yani başarıya karşı başarısızlığa göre, anlamlı biçimde farklı olabilmekte ile bu, bir saldırganın zaman tabanlı bir saldırı kurmasına, örneğin birkaç saniyelik bir farkla, izin vermektedir. Çare hızlı çıkıştan kaçınmaktır; kod, kullanıcı ya da parola ne olursa olsun aynı süreçten geçmelidir.

OWASP sahte özet tekniğini açıkça reçete etmemektedir. Sonucu reçete etmektedir, yani aynı kod yolu ile karşılaştırılabilir süre. Sahte özet numarası bunun bir uygulamasıdır ile standartlaşmış değildir.

Otomatik saldırılara karşı çok faktörlü kimlik doğrulama, giriş kısıtlaması, kaynak IP adresi yerine hesabın kendisiyle ilişkilendirilmiş hesap kilitleme sayaçları önerilmektedir; CAPTCHA ise açıkça kaba kuvvet saldırılarını daha zaman alıcı ile pahalı yapan derinlemesine savunma kontrolü olarak çerçevelenmektedir, yani birincil kontrol değildir.

Web güvenliği test kılavuzunun kimlik testi vektörleri şunlardır: farklılaşmış hata mesajları; yanıt zamanlaması, özellikle istek harici bir servisle etkileşime yol açtığında, örneğin unutulan parola e-postası gönderdiğinde, bu birkaç yüz milisaniye eklemektedir; farklı HTTP durum kodları; farklı içerik uzunlukları; ile kayıt ve profil sayfaları ve rezerve kullanıcı adları.

Çoğu gerçeklemenin kaçırdığı nokta birkaç yüz milisaniyedir: e-posta göndermek bir Argon2 özetinden kat kat pahalıdır. Iskada özetliyor ancak isabette posta gönderiyorsanız, zamanlama farkını iyileştirmemiş kötüleştirmiş olursunuz. Düzeltme posta gönderimini her iki yolda da eşzamansız yapmaktır, yani kuyruğa atıp hemen dönmek ile ıska yolunda bir boş iş kuyruğa atmaktır.

#### 34.2 Sahte Argon2 tekniği doğru mudur: yarı doğrudur ile genelde uygulandığı hâliyle tehlikelidir

Teknik şudur: kullanıcı yoksa, gönderilen parola sabit kodlanmış sahte bir Argon2id özetine karşı özetlenmekte ile yanıt süresi gerçek yolla eşleştirilmektedir.

Nerede doğru olduğu şudur: iki dalın işlemci ile bellek profilini gerçekten eşitlemekte ile erken dönüşten kesinlikle daha iyidir.

Nerede yanlış olduğu üç ayrı problemdir.

Birincisi, bir bilgi sızıntısını bellek tükenmesi hizmet reddine çevirmektedir. Argon2id, RFC 9106'nın ikinci önerilen ayarında 64 mebibayt, üç yineleme ile dört şerittir. Çöp kullanıcı adlarıyla 100 eşzamanlı istek gönderen kimliği doğrulanmamış bir saldırgan 6,4 gigabaytlık yerleşik bellek tahsisi zorlamaktadır; hem de sıfır geçerli hesapla ile kısıtlama hesap kapsamlıysa sıfır hız sınırı sayacı artışıyla. NIST 63B'nin kısıtlaması açıkça hesap kapsamlı ile kimlik doğrulayıcı kapsamlıdır, yani tek bir abone hesabı üzerinedir; dolayısıyla var olmayan hesap seli onu yapısal olarak tamamen atlamaktadır. Sahte özet, o boşluğu bir kaynak öldürmeye çeviren şeydir.

İkincisi, parametre rehberliğinin kendisi riski kabul etmektedir. OWASP parola saklama özet sayfası birebir şunu söylemektedir: iş faktörü çok yüksekse uygulamanın performansı bozulabilmekte ile bu, bir saldırgan tarafından çok sayıda giriş denemesiyle sunucunun işlemcisini tüketerek bir hizmet reddi saldırısı yapmak için kullanılabilmektedir. Ayrıca genel bir kural olarak bir özetin hesaplanması bir saniyeden az sürmelidir denmektedir.

OWASP'ın Argon2id ayarları RFC 9106'nınkinden belirgin şekilde düşüktür, tam da bu yüzden. Sırasıyla 46 mebibayt ile bir yineleme, 19 mebibayt ile iki yineleme, 12 mebibayt ile üç yineleme, 9 mebibayt ile dört yineleme ile 7 mebibayt ve beş yinelemedir; hepsinde paralellik birdir.

RFC 9106, yani Eylül 2021 tarihli bilgilendirici belge, önce bir yineleme, dört paralellik ile iki gibibayt, sonra üç yineleme, dört paralellik ile 64 mebibayt önermektedir. RFC 9106'nın güvenlik değerlendirmeleri yan kanalları kapsamakta ancak hiçbir hizmet reddi ya da kaynak tükenmesi analizi içermemektedir; boşluk gerçektir ile OWASP onu doldurmaktadır. Yaygın olarak alıntılanan 64 mebibayt ile üç yineleme tam olarak RFC 9106'nın ikinci önerisidir ile OWASP'ın en bellek aç ayarının yaklaşık üç katıdır. Argus'un seçtiği parametre ile gerekçesi için §6'ya bakınız; ölçüm, 7 mebibayt ile beş yinelemenin hem %16 ucuz olduğunu hem daha iyi ölçeklendiğini göstermiştir.

Üçüncüsü, zamanlama eşitlemesi zaten eksiktir. Argon2 çalışma süresi parola uzunluğuna, çöp toplama ile ayırıcı davranışına ile önbellek durumuna göre değişmektedir. Sıfırlama akışında baskın terim özet bile değildir, posta çağrısıdır.

Doğru kurulum önce ucuz kapı, sonra pahalı iştir. OWASP hizmet reddi özet sayfası ilkeyi doğrudan söylemektedir: önce kaynak açısından ucuz olan doğrulama kullanılmalıdır; bu kaynaklar üzerindeki etki mümkün olduğunca erken azaltılmalı ile işlemci, bellek ve bant genişliği açısından daha pahalı doğrulama sonra yapılmalıdır.

Somut sıra şudur.

1. Herhangi bir özetlemeden önce ucuz bir kapı konulmalıdır: IP, otonom sistem numarası ya da alt ağ başına bir jeton kovası artı özetleme işçi havuzunda küresel bir eşzamanlılık semaforu. Bu kapı kimlikten bağımsız olmalıdır ki isabetlere ile ıskalara eşit uygulansın. Limiti aşan istekler hiç Argon2 belleği tahsis edilmeden reddedilmelidir. Bu tek başına zamanlama savunmasını kaldırmadan hizmet reddini kaldırmaktadır.
2. Özetleme eşzamanlılığı sınırlanmalıdır: kuyruğu olan sabit boyutlu bir işçi havuzu kullanılmalıdır, yani işçi sayısı bellek bütçesinin bellek maliyetine bölümüdür. Bellek kullanımı umutla değil yapısal olarak sınırlanmaktadır.
3. Ancak o zaman gerçek ya da sahte özet çalıştırılmalıdır. Sınırlı havuzla sahte özet güvenlidir.
4. Tekdüze eşzamansız yanıt verilmelidir: e-posta kuyruğa atılmalı, gerçek ya da boş iş olarak, ile her iki yolda da aynı gövde, aynı durum ile aynı içerik uzunluğu dönülmelidir. Yanıt asla posta sunucusunu beklemeye bırakılmamalıdır.
5. İsteğe bağlı olarak sabit bir taban yanıt süresi konulabilir, yani başlangıçtan itibaren 250 milisaniyeye kadar beklenebilir; sahte özet yerine ya da ona ek olarak. Sahte özetten ucuzdur ile posta dahil tüm dalları eşitlemektedir; bedeli herkes için bir gecikme tabanıdır. Bu genelde daha iyi bir takastır ile NIST 63B'nin başarısız denemeden sonra bekleme maddesinin işaret ettiği şeydir.
6. Sıfırlama uç noktası hesap başına da hız sınırlanmalıdır ki bilinen geçerli bir hesap posta bombardımanı için bir yükselteç olarak kullanılamasın.

Ayrıca hesap kapsamlı kilitleme kullanılıyorsa, yani sayaç hesabın kendisiyle ilişkilendirilmişse, ikinci bir numaralandırma kâhini yaratılmış olmaktadır: saldırgan, kilitlenmenin hiç tetiklenip tetiklenmediğini gözlemleyerek hesabın varlığını tespit edebilmektedir. Hem hesap kapsamlı hem IP kapsamlı limitlere ihtiyaç vardır; hiçbiri tek başına yeterli değildir.

#### 34.3 Temel gerilim: kayıt yapısal olarak sızdırmaktadır

E-posta zaten kullanımda mesajı, mesajlaşarak kurtulabileceğiniz bir hata değildir: ya kullanıcıya söylersiniz, ki bir sızıntıdır, ya da hesabı oluşturamazsınız, ki bozuk bir kullanıcı deneyimidir.

Çözüm mimaridir ile W3C WebAuthn şartnamesi bunu 14.6.2 bölümünde birebir yazmaktadır; W3C tavsiyesi, 25 Ağustos 2026.

> "If the Relying Party uses e-mail addresses to identify users: When initiating a registration ceremony, interrupt the user interaction after the e-mail address is supplied and send a message to this address, containing an unpredictable one-time code and instructions for how to use it to proceed with the ceremony. Display the same message to the user in the web interface regardless of the contents of the sent e-mail and whether or not this e-mail address was already registered."

> "Note: This suggestion can be similarly adapted for other externally meaningful identifiers, for example, national ID numbers or credit card numbers…"

Pratikte nasıl çalıştığı şudur ile Apple ile Google'ın yaptığı budur.

1. Kullanıcı e-postayı göndermektedir. Arayüz her zaman o adrese bir kod gönderdik demektedir. Aynı yanıt, aynı durum ile aynı zamanlama verilmekte ile hesap oluşturulmamaktadır.
2. Dallanma HTTP yanıtında değil e-postanın içindedir. Adres kayıtlı değilse e-posta kayıt devam kodunu içermektedir. Adres zaten kayıtlıysa e-posta, birinin bu adresle hesap oluşturmaya çalıştığını, zaten bir hesabın bulunduğunu ile giriş veya sıfırlama bağlantısını içermektedir, artı bir ben değildim bildirim yolu sunmaktadır.
3. Hesap ancak kod geri döndükten sonra var olmaktadır.

Bunun bir kimlik sağlayıcı için neden doğru cevap olduğu şudur. Kâhin, yalnızca adres sahibinin okuyabildiği bir kanala taşınmaktadır. Numaralandırma maliyeti bir HTTP isteğinden posta kutusunu ele geçirmeye çıkmaktadır. Aynı anda NIST 63A'nın otomatik kayıt azaltmasını, yani bant dışı etkileşimi, aynı belgenin çıkarım karşıtı zorunluluğunu, tek kullanımlık e-posta problemini ile OWASP'ın tekdüze yanıt kuralını karşılamaktadır; tek kontrol, dört gereksinim. Zaten kayıtlı kullanıcı için dönüşümü de iyileştirmektedir: çıkmaz bir hata yerine çalışan bir giriş bağlantısı almaktadır. 63B'nin kod geçerlilik tavanları yeniden kullanılabilir, yani kısa mesaj ile sesli aramada 10 dakika ile e-postada 24 saat.

Kaldıramayacağınız artık sızıntı, e-postanın kendi yan etkisi üzerinden numaralandırmadır: posta sunucusunu kontrol eden bir saldırgan posta gönderilip gönderilmediğini gözlemleyebilmektedir. Bu kabul edilmelidir; çok daha yüksek bir çıtadır. Kısıtlamanız yalnızca hesap kapsamlıysa kararlı bir saldırgan hız sınırı farkı üzerinden hâlâ numaralandırabilmektedir. IP kapsamlı limitler kimlikten bağımsız tutulmalıdır.

#### 34.4 Geçiş anahtarı akışlarında numaralandırma

Birinci sızıntı WebAuthn şartnamesinin korunmayan hesap tespiti bölümüdür; normatif değildir.

> "if using authentication with server-side credentials as the first authentication step… the `allowCredentials` argument risks leaking information about which user accounts have WebAuthn credentials registered and which do not, which may be a signal of account protection strength… The attacker can then conclude that the latter user accounts likely do not require a WebAuthn assertion… and thus focus an attack on those likely weaker accounts."

İkinci sızıntı kimlik bilgisi tanımlayıcıları üzerinden mahremiyet sızıntısıdır.

> "Credential IDs are designed to not be correlatable between Relying Parties, but the length of a credential ID might be a hint as to what type of authenticator created it… the number of credential IDs in `allowCredentials` and their lengths might serve as a global correlation handle to de-anonymize the user. Knowing a user's credential IDs also makes it possible to confirm guesses about the user's identity given only momentary physical access to one of the user's authenticators."

Şartname onaylı düzeltmeler tercih sırasıyla şunlardır.

1. İstemci tarafında keşfedilebilir kimlik bilgileri kullanılmalıdır, böylece izin verilen kimlik bilgileri listesi gerekmemektedir. Temiz düzeltme budur. Boş bir liste artı koşullu arayüz, yani otomatik doldurma, hem kullanıcı adısız girişi hem sıfır sızıntıyı vermektedir. Eşleşmeye dikkat edilmelidir: koşullu arayüz yalnızca liste boşken çalışmaktadır; mahremiyet düzeltmesiyle en iyi kullanıcı deneyimi aynı tasarımdır.
2. WebAuthn kimlik doğrulama töreni başlatılmadan ile kullanıcının kimlik bilgisi tanımlayıcıları açığa çıkarılmadan önce ayrı bir kimlik doğrulama adımı yapılmalıdır.
3. Makul hayalî değerler kullanılabilir; kritik çekince şudur: döndürülen hayalî değerler gerçek olanlardan belirgin biçimde farklıysa zeki saldırganlar bunları ayırt edebilmektedir. Belirgin farklara örnekler, değerlerin tüm kullanıcı adı girdileri için hep aynı olması ya da aynı kullanıcı adı girdisiyle tekrarlanan denemelerde farklı olmasıdır. Dolayısıyla liste, kullanıcı adından deterministik biçimde türetilmiş sözde rastgele değerlerle doldurulmalıdır. Bu, sahte özetin WebAuthn karşılığıdır ile şartname bu konuda çoğu sahte özet tavsiyesinden çok daha dikkatlidir: kullanıcı adı başına deterministik ile istatistiksel olarak ayırt edilemez olmalıdır.
4. Doğrulamanın, imzanın geçersiz olmasından mı yoksa böyle bir kullanıcı veya kimlik bilgisinin kayıtlı olmamasından mı başarısız olduğu ayırt edilemez kılınmalıdır.
5. Sinyalleşme API'sinde, kimlik bilgisi tanımlayıcılarını kimliği doğrulanmamış bir çağırana açığa çıkarmamak için bilinmeyen kimlik bilgisi sinyali yöntemi kullanılmalı, tüm kabul edilen kimlik bilgilerini sinyalleyen yöntem kullanılmamalıdır. Üçüncü seviyede yenidir; kimliği doğrulanmamış bir uç noktada ikincisi taze bir 2026 tuzağıdır.

Kayıt tarafında, bağlı tarafa özgü kullanıcı adları için, şartname sözdizimsel olarak geçerli e-posta adresi olan kullanıcı adlarının kaydına izin verilmemesini önermektedir; gerekçe şudur: sızıntı kaçınılmazsa en azından sızan tanımlayıcı taşınamaz yapılmalıdır, yani bir kullanıcının bu bağlı tarafta diğerlerindekiyle aynı kullanıcı adına sahip olma olasılığı azaltılmalıdır.

Kullanıcı tanıtıcısının içeriği hakkındaki kural şudur.

> "the Relying Party MUST NOT include personally identifying information, e.g., e-mail addresses or usernames, in the user handle. This includes hash values of personally identifying information, unless the hash function is salted with salt values private to the Relying Party, since hashing does not prevent probing for guessable input values. It is RECOMMENDED to let the user handle be 64 random bytes."

Yaygın bir kimlik sağlayıcı hatası kullanıcı kimliğini e-postaya ya da özetine ayarlamaktır; bu, herhangi bir kimlik doğrulayıcıya doğrudan bir numaralandırma ile korelasyon sızıntısıdır.

#### 34.5 Zamanlama numaralandırması internet üzerinden gerçekçi midir: evettir ile titreşim kurtarır varsayımı artık geçersizdir

Zamansız zamanlama saldırıları, yani uzak bağlantılar üzerinden sır sızdırmak için eşzamanlılığı istismar etme çalışması, Tom Van Goethem, Christina Pöpper, Wouter Joosen ile Mathy Vanhoef tarafından USENIX Security 2020'de sunulmuştur.

Klasik varsayım şuydu: uzaktan zamanlama saldırıları çok ölçüm gerektirmektedir, çünkü ağ titreşimi baskındır; milisaniye altı farklar internet üzerinden istismar edilememektedir.

Kırılma şudur: tek bir pakette iki istek gönderilmekte, yani HTTP/2 çoğullama veya paket birleştirmeyle, sunucunun onları eşzamanlı işlemesi sağlanmakta ile fark yanıtların döndüğü sıradan çıkarılmaktadır. Bu, hiç mutlak zamanlama bilgisi kullanmamaktadır; dolayısıyla ağ titreşimi tamamen iptal olmaktadır.

Amazon EC2 üzerindeki HTTP/2 nginx'e, Tor gizli servislerine ile EAP-pwd protokolüne karşı gösterilmiş ile yaklaşık bir milyon istek çiftiyle doğrulanmıştır.

Keskin tasarım sonucu şudur: fark sadece birkaç yüz mikrosaniyedir, internet üzerinden kimse bunu ölçemez ifadesi artık hiçbir HTTP/2 ya da HTTP/3 uç noktası için doğru değildir; bu, her modern kimlik sağlayıcı demektir. Girişte, sıfırlamada ile kayıtta zamanlama eşitlemesi 2026'da gerçek bir gereksinimdir, bir tiyatro değildir. Rastgele titreşim bir düzeltme değildir; ortalamada erimekte ile zamansız teknik altında zaten alakasızdır. Hayatta kalan düzeltmeler özdeş kod yolları, sabit yanıt süresi tabanı ile yanıt kuyruklamasıdır.

Bunun canlı bir hata sınıfı olduğunun ampirik teyidi CVE-2025-3716'dır: ESET PROTECT'in kendi barındırılan sürümündedir, gözlemlenebilir yanıt farklılığı zayıflığı olarak sınıflandırılmıştır ile kimliği doğrulanmamış uzak bir saldırganın yanıt zamanlamasındaki farkları ölçerek geçerli kullanıcı adlarını numaralandırmasına olanak vermektedir.

#### 34.6 Düzenleyici ile sınıflandırma açısı

Gözlemlenebilir yanıt farklılığı zayıflığı, ürünün gelen isteklere iç durum bilgisini yetkisiz bir aktöre açığa vuracak şekilde farklı yanıtlar vermesidir. Kullanıcı numaralandırmasının standart sınıflandırması budur. Üst sınıfı olan gözlemlenebilir farklılık, zamanlama ile davranışsal varyantları kapsamaktadır.

Numaralandırma rutin olarak güvenlik açığı numarası almaktadır: ESET PROTECT, GUnet OpenEclass ile IBM Sterling File Gateway örnekleri vardır. Yani raporlanabilir ile numara almaya uygun bir zayıflıktır, yalnızca bir sertleştirme inceliği değildir. Bir satıcı kimlik sağlayıcısı için bu önemlidir: müşteri sızma testi raporlarına düşmekte ile koordineli açıklama yükümlülüğü tetiklemektedir.

NIST SP 800-63A bunu hizmet sağlayıcılar için bir zorunluluk yapmaktadır: başarısız başvuranların, beyan ettikleri bilginin otoriter kaynaklarca doğrulananla uyumunu çıkarmalarını önleyecek tedbirler alınmalıdır. 800-63-4 uyumluluğu iddia eden her şey için numaralandırma direnci bir uyum gereksinimidir, yalnızca iyi bir pratik değildir.

GDPR ile KVKK açısından, bu e-postanın şu serviste hesabı vardır diyen bir numaralandırma kâhini, kişisel verinin, yani bir kişiyle bir servis arasındaki ilişkinin, yetkisiz bir tarafa ifşasıdır. Belirli bir örneğin bildirilebilir bir ihlal olup olmadığı olguya bağlıdır; numaralandırmayla ihlal ilişkisi konusunda doğrudan bir düzenleyici karar bulunamamıştır ile doğrulanmamıştır. Abartılmamalı, sınıflandırma ile NIST zorunluluğuyla desteklenen bir veri asgarileştirme ve gizlilik riski olarak çerçevelenmelidir. Hassas kategorili bir servis için, yani sağlık, tanışma, siyasî ya da finansal bir servis için, teyidin kendisi özel nitelikli veri olabilmektedir; bu, argümanı hayli güçlendirmektedir.

---

### 35. Beşinci bölüm için kayıt akışı tasarımı

Argus'un kayıt uç noktası sırayla şöyledir.

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

Zorlanan değişmezler şunlardır.

| Sıra | Değişmez | Kaynak |
|---|---|---|
| 1 | Onay kodu dönmeden hiçbir hesap satırı yaratılmamaktadır | WebAuthn şartnamesi artı ön ele geçirme makalesi |
| 2 | HTTP yanıtı gövde, durum, içerik uzunluğu ile zamanlama olarak her iki dalda özdeştir | OWASP ile test kılavuzu |
| 3 | Posta gönderimi her iki yolda da eşzamansız kuyruğa atılmaktadır; ıskada boş iş konulmaktadır | Birkaç yüz milisaniyelik fark |
| 4 | Sabit bir yanıt süresi tabanı, yaklaşık 250 milisaniye, sahte özete tercih edilmektedir | Zamansız zamanlama saldırıları |
| 5 | Hız sınırı hem IP kapsamlı hem hesap kapsamlıdır; IP kapısı özetlemeden öncedir | 63B'nin hesap kapsamlı kısıtlamasının yapısal boşluğu |
| 6 | Argon2 işçi havuzu sabit boyutludur; bellek yapısal olarak sınırlıdır | OWASP hizmet reddi özet sayfası |
| 7 | Ham ile kanonik e-posta saklanmaktadır; kanonik yalnızca suistimal skoru ile kişi başına bir kez verilen haklar içindir | RFC 5321 artı Agari vakası |
| 8 | Kanonik biçim asla kullanıcıya görünen bir hatada yüzeye çıkmamaktadır | Daha kötü bir kâhindir |
| 9 | Nokta normalizasyonu yalnızca açık Gmail alan adı listesindedir | Nokta önemsizliği Gmail'e özgüdür |
| 10 | WebAuthn kullanıcı kimliği 64 rastgele bayttır, asla e-posta ya da özeti değildir | Şartnamenin yasağı |
| 11 | Boş izin verilen kimlik bilgisi listesi artı koşullu arayüz varsayılandır; gerekirse kullanıcı adından deterministik hayalî değerler kullanılmaktadır | Şartnamenin mahremiyet bölümleri |
| 12 | Bilinmeyen kimlik bilgisi sinyali kullanılmakta, tüm kabul edilenleri sinyalleyen yöntem kimliği doğrulanmamış uç noktada asla kullanılmamaktadır | Üçüncü seviyenin yeni tuzağı |
| 13 | reCAPTCHA kullanılmamakta; Turnstile ya da Friendly Captcha, KVKK gerekçesi belgelenerek kullanılmaktadır | CNIL kararı ile Avusturya kararı |
| 14 | Kurtarma adresi en az iki tanedir; tek kullanımlık e-postanın yetim hesap riskine karşıdır | 63B'nin zorunluluğu |
| 15 | Sahtekârlık olayları bağlı taraflara gerçek zamanlı paylaşılan sinyallerle bildirilmektedir | 63A'nın önerisi |

---

## Bölüm VI — Kimlik sağlayıcı göçü

Bu bölümün Argus için neden stratejik olduğu şudur: bir kimlik sağlayıcının en büyük pazara giriş engeli, müşterinin mevcut sağlayıcısından çıkamamasıdır. İçeri göç yolları Argus'un satış argümanıdır; dışarı göç yolları ise dürüstlük iddiasıdır. Bu bölüm, her büyük ürünün ne verip ne vermediğinin envanteridir.

### 36. Parola özeti dışa aktarımı, ürün ürün

#### 36.1 Auth0: varsayılan hayırdır, bir destek süreci vardır

Standart toplu dışa aktarım özet içermemektedir. Dışa aktarım işi, dosya boyutları büyük olduğu için satır ayrılmış JSON ya da CSV üretmektedir. CSV 30 alanla sınırlıdır; uygulama ile kullanıcı metadata'sı CSV'de bütün bir nesne olarak dışa aktarılamamaktadır. İş verisi 24 saat sonra silinmekte ile indirme bağlantısı 60 saniyede sona ermektedir, 24 saat içinde yeniden üretilebilmektedir.

Özet ile çok faktörlü sır dışa aktarımı ayrı ile kapılı bir destek sürecidir.

1. Kiracı adı ile kendi PGP açık anahtarınızla bir destek vakası açılmaktadır.
2. Bir uygunluk incelemesi yapılmaktadır; her talep uygun bulunmamaktadır.
3. Yazılı yetkilendirme, ikinci bir kiracı yöneticisinin teyidi ile bilgi güvenliği veya güvenlik yöneticisi seviyesinde imzalı bir onay formu gerekmektedir.
4. Auth0 dosyayı açık anahtarınızla şifrelemekte ile kimlik doğrulamalı bir indirme bağlantısı vermektedir; bağlantı üç günde sona ermektedir.
5. Çözme işlemi size aittir.

PGP anahtar gereksinimleri şunlardır: asgari 4096 bitlik RSA, en az bir RSA 4096 şifreleme alt anahtarı, güçlü ile benzersiz bir parola, oluşturulmasından en az yedi gün sonraya sona erme ile ASCII zırhlı anahtarın 35.000 karakteri geçmemesi, yani üçüncü taraf imzalarının temizlenmesi.

Dışa aktarım formatı satır başına bir kullanıcı olacak şekilde satır ayrılmış JSON'dur ile kimlik, alternatif kimlik, e-posta, doğrulanmışlık, parola özeti, bağlantı ile tanımlayıcılar alanlarını taşımaktadır. Doğrudan yeniden içe aktarılabilir değildir; JSON dizisine dönüşüm ile alan yeniden adlandırması gerekmektedir.

İçe aktarımda özel parola özeti 11 algoritma desteklemektedir: Argon2 PHC dizgisi, bcrypt'in üç varyantı ile en fazla 72 baytlık girdi, HMAC, RFC 2307 dizin biçimi, ki crypt şeması desteklenmemektedir, MD4, MD5, SHA-1, SHA-256, SHA-512, varsayılanı yüz bin yineleme ve 64 uzunluk olan PBKDF2 ile anahtar uzunluğu zorunlu ve maliyeti varsayılan 16384 olan scrypt. Kodlamalar base64, onaltılık ya da UTF-8'dir; tuz konumu önek ya da sonek olabilmektedir.

İçe aktarım iş limitleri şunlardır: dosya başına 500 kibibayt, yani yaklaşık bin kullanıcı; kiracı başına iki eşzamanlı iş; iki saatte bitmezse iş başarısız olmakta ile veri 24 saat sonra silinmektedir.

#### 36.2 Okta: dışa aktarım fiilen hayırdır, içe aktarım altı algoritmayla evettir

Okta parola özetlerinin ya da çok faktörlü yöntemlerin standart dışa aktarımına izin vermemektedir. Tek belgelenmiş yol bir istisna sürecidir ile özellikle Okta'dan Auth0'a geçiş olarak çerçevelenmiştir.

> *"In a very limited number of cases and only with specific criteria met, it is possible to request an export of password hash values for active Okta users during the organization's transition from Okta to Auth0"* … *"this is a lengthy process that requires coordination between multiple Okta teams and a customer's technical and executive teams."*

İçe aktarımda tam parola özeti şeması bcrypt, SHA-512, SHA-256, SHA-1, MD5 ile PBKDF2'yi desteklemektedir. Alanları algoritma, değer, tuz, tuz sırası, yani önek ya da sonek, yalnızca bcrypt için geçerli ve bir ile 20 arası olan iş faktörü, yalnızca PBKDF2 için geçerli ve en az 4096 olması gereken yineleme sayısı, anahtar boyutu ile özet algoritmasıdır. Tuz bcrypt için tam 22 karakterlik Radix-64, diğer tuzlu özetler için base64'tür.

```json
{"profile":{...},"credentials":{"password":{"hash":{
  "algorithm":"BCRYPT","workFactor":10,
  "salt":"pwxb1yjwfpa6jcV0XKBtau",
  "value":"MnDMlKOOxMY4Tc.7wgpqFoAPYKi5wSe"}}}}
```

Parola içe aktarma satır içi kancası, yani Okta'ya tembel göç, şöyle çalışmaktadır: kullanıcı varsayılan kanca tipiyle oluşturulmaktadır. Yalnızca ilk giriş denemesinde tetiklenmektedir. Başarı yanıtı kimlik bilgisini doğrulanmış olarak güncelleyen bir komut dizisidir; ret ise boş gövdeli 204'tür. İlgili alan her zaman doğrulanmamış olarak ayarlanmaktadır, yani varsayılan reddetmektir.

#### 36.3 Keycloak: kimlik bilgileri komut satırı dışa aktarımında bulunmaktadır

Dışa aktarma komutu kullanıcıları ile kimlik bilgilerini içermektedir. Kullanıcı seçeneği atlama, alan dosyası, aynı dosya ya da farklı dosyalar değerlerini almakta, varsayılanı farklı dosyalardır ile dosya başına kullanıcı sayısı varsayılanı 50'dir.

Dışa aktarılmayanlar birebir şöyledir: kullanıcı ile yönetici olayları, kalıcılaştırılmış oturumlar, iş akışı durumu ile iptal edilmiş token'lar.

Yönetim konsolunun kısmî dışa aktarımı göç için kullanılamaz: sırlar maskelenmekte ile kullanıcılar hariç tutulmaktadır. Yalnızca komut satırı dışa aktarımları yedek ile aktarım için uygundur.

Kimlik bilgisi JSON şekli şöyledir.

```json
{"type":"password",
 "credentialData":"{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\",\"additionalParameters\":{}}",
 "secretData":"{\"value\":\"<base64 hash>\",\"salt\":\"<base64 salt>\",\"additionalParameters\":{}}"}
```

Argon2, Keycloak 25.0'da, yani Haziran 2024'te, varsayılan parola özet algoritması olmuştur; yalnızca FIPS olmayan dağıtımlar içindir, FIPS dağıtımları PBKDF2'de kalmaktadır. Varsayılanlar özet isteği başına yaklaşık yedi megabayt gerektirmekte ile paralel Argon2 hesaplaması sanal makinenin gördüğü çekirdek sayısıyla sınırlıdır.

Yabancı özetler için özel bir parola özet sağlayıcı arayüzü bulunmaktadır: ilgili arayüz ile fabrikası gerçeklenmekte, servis dosyasıyla kaydedilmekte ile alan ayarlarından özetleme algoritması seçilmektedir. Keycloak, kullanıcının ilk başarılı girişinde politika algoritmasına otomatik olarak yeniden özetlemektedir; yerleşik damlama mekanizması budur.

Keycloak'ın taşınabilirlik açısından en büyük avantajı şudur: tek kullanımlık şifre kimlik bilgileri aynı kimlik bilgisi dizisindedir, dolayısıyla kullanıcılarla birlikte dışa aktarılmaktadır. İncelenen ürünler arasında tek kullanımlık şifre sırlarını kendin yap biçimde dışa aktaran tek üründür.

#### 36.4 AWS Cognito: dışa aktarım hâlâ hayırdır ancak özetle içe aktarım 15 Temmuz 2026'da gelmiştir

Yeni özellik CSV ile parola özeti içe aktarımıdır. Duyuru 15 Temmuz 2026'dır ile tüm bölgelerde geçerlidir. Kullanıcı içe aktarma işi oluştururken parola özet algoritması bcrypt, scrypt, Argon2id ya da PBKDF2 SHA-256 olarak belirtilmektedir. İş başına bir algoritma kullanılmakta, yani karışık özetler varsa işler bölünmelidir. CSV'ye bir parola özeti sütunu eklenmektedir.

Göç tuzağı parametre tavanlarıdır.

| Algoritma | Format | Tavan |
|---|---|---|
| bcrypt | Standart bcrypt dizgisi | Azami maliyet 12'dir |
| scrypt | Maliyet, blok, paralellik, onaltılık tuz ile onaltılık özet | Azami maliyet 65536, blok sekiz ile paralellik birdir |
| Argon2id | Standart Argon2 PHC dizgisi | Azami bellek 19456 kibibayt, iki yineleme ile bir paralelliktir |
| PBKDF2 SHA-256 | Yineleme, tuz ile özet | Azami 600.000 yinelemedir |

Sınırları aşan özetler kullanıcı başına başarısız olmaktadır. AWS'in adlandırdığı yedek yollar özetsiz içe aktarmak, ki sıfırlama gerekli durumuna düşürmektedir, ya da o kullanıcılar için bir göç işlevi kullanmaktır.

Kullanıcılar onaylanmış olarak içe aktarılmakta ile hemen giriş yapabilmektedir. Cognito içe aktarılan özetleri çift özetlemekte ile ilk başarılı girişte şeffaf şekilde yerel güvenli uzak parola protokolüne dönüştürmektedir.

Kritik kısıt birebir şudur: *"Until a user completes their first sign-in and Amazon Cognito migrates their credentials, you can't use Secure Remote Password (SRP)… Use `USER_PASSWORD_AUTH` or `ADMIN_USER_PASSWORD_AUTH`."*

Özellik tüm kullanıcı havuzlarında mevcut değildir; yeni nesil altyapı gerekmektedir.

CSV içe aktarım limitleri şunlardır: satır en fazla 16.000 karakter, dosya en fazla 100 megabayt, en fazla 500.000 satır, hesap başına bir aktif iş, önceden imzalanmış adres 15 dakika geçerli, başlatılmamış işler 24 ile 48 saatte süresi dolmuş duruma geçmekte, doğum tarihi belirli bir biçimde, güncelleme zamanı epoch saniyesi olarak ile dosya bayt sırası işaretsiz UTF-8 olmalıdır.

Göç işlevi tembel yoldur: kimlik doğrulama ile parola unutma tetikleyicileri bulunmaktadır. Parolasız girişte tetiklenmemektedir. Yanıtı kullanıcı nitelikleri, ki zorunludur, nihai kullanıcı durumu ile istenen teslim ortamlarıdır; sonuncusu belirtilmezse kısa mesaja düşülmektedir. Açık uyarı birebir şudur: *"Amazon Cognito doesn't enforce the password strength policy … during migration using Lambda trigger"*. Gücü kendiniz doğrulamalı ile başarısızsa sıfırlama gerekli durumunu ayarlamalısınız.

#### 36.5 Firebase kimlik doğrulama: özetleri gerçekten dışa aktaran tek üründür

Dışa aktarma komutu parola özetini ile tuzu base64 olarak dışa aktarmaktadır. O iki alan için çağıranın düzenleyici ya da sahip rolü gerekmektedir.

Sert sınırlama birebir şudur: *"the `auth:export` command only exports passwords hashed using the scrypt algorithm… Account records with passwords hashed using other algorithms are exported with empty `passwordHash` and `salt` fields."*

Özet parametreleri konsoldaki kimlik doğrulama kullanıcılar bölümündedir.

```
hash_config { algorithm: SCRYPT, base64_signer_key: <hassas>,
              base64_salt_separator: <hassas>, rounds: 8, mem_cost: 14 }
```

Özet algoritması değerleri bcrypt, Firebase scrypt'i, standart scrypt, HMAC'in dört varyantı, MD5, SHA'nın üç varyantı, PBKDF SHA-1 ile PBKDF2 SHA-256'dır.

Firebase scrypt'i standart scrypt ile aynı değildir; Firebase'in kendi değiştirilmiş sürümüdür ile Firebase'den Firebase'e göçte bile açıkça belirtilmelidir.

CSV 26 sabit sütundur: kimlik, e-posta, doğrulanmışlık, base64 parola özeti, base64 parola tuzu, ad, fotoğraf adresi, Google, Facebook, Twitter ile GitHub sağlayıcı dörtlüleri, epoch milisaniye cinsinden oluşturma zamanı, son giriş zamanı ile telefon numarası.

Yönetici geliştirme kitinin içe aktarma çağrısı çağrı başına en fazla bin kullanıcı almakta ile kimlik, e-posta veya telefon üzerinde tekilleştirme yapmamaktadır.

#### 36.6 Microsoft Entra dış kimlik ile Azure AD B2C: dışa aktarım hayırdır

Parola özetlerini dışa aktarmanın desteklenen bir yolu yoktur. Microsoft'un parolaları nasıl korurum sorusuna kendi cevabı tam zamanında göçtür, dışa aktarım değildir.

B2C satış sonu ile emekliliğin doğrulanmış tarihleri şunlardır: 1 Mayıs 2025'ten itibaren yeni müşteriler satın alamamaktadır, mevcut müşteriler devam etmektedir ile yeni kiracılar yalnızca birinci kademeyle oluşturulabilmektedir. İkinci kademe 15 Mart 2026'da tüm müşteriler için sonlandırılmıştır; tüm ikinci kademe kiracıları Mart 2026 sonuna kadar otomatik olarak birinci kademeye geçmektedir. Destek en az Mayıs 2030'a kadar sürecektir.

Dış kimliğe tam zamanında parola göçü, dokümanın 25 Ağustos 2026 güncellemesine göre şöyledir. Mekanizma bir parola gönderimi özel kimlik doğrulama uzantısıdır. Kullanıcılar grafik API'si üzerinden ön oluşturulmakta ile göç edilecek bayrağıyla işaretlenmektedir. Akış şöyledir: gönderilen parola kayıttakiyle eşleşmezse ile bayrak ayarlıysa, Entra parolayı bir RSA açık anahtarıyla şifrelemekte, yani JSON web şifrelemesi kullanmakta, özel anahtar Azure anahtar kasasında yönetilen kimlikle erişilen yerde durmakta ile uzantınız çağrılmaktadır. İşlev çözmekte, eski sağlayıcıya karşı doğrulamakta ile dört eylemden birini döndürmektedir: parolayı göç ettir, yani sakla ile bayrağı temizle; parolayı güncelle, yani doğru ancak zayıf olduğu için sıfırlamaya zorla; yeniden dene; ya da engelle. Güçlü parola devre dışı seçeneği bir arada yaşama sırasında karmaşıklık zorlamasını gevşetmektedir, sekiz karakter asgarisi yine zorlanmaktadır; Microsoft bunu açıkça zaman kutulu bir takas olarak çerçevelemektedir. Gerekli rol kimlik doğrulama genişletilebilirliği parola yöneticisidir.

Dikkat çekicidir: incelenen ürünler arasında gönderilen parolayı sizin kodunuza vermeden önce şifreleyen tek ürün Entra'dır. Argus da bunu yapmalıdır; özel bir uzantıya düz metin parola vermek bir tasarım hatasıdır.

#### 36.7 Diğerleri

| Ürün | Özet içe aktarımı | Özet dışa aktarımı | Not |
|---|---|---|---|
| Stytch | bcrypt, MD5, Argon2'nin iki varyantı, SHA-1, SHA-512, scrypt, PBKDF2 ile phpass | Yalnızca destek talebiyle | scrypt maliyeti ikinin kuvveti olmalı ile bir ile 262144 arası bulunmalıdır |
| Clerk | Parola özeti ile özetleyici alanları; şeffaf şekilde bcrypt'e yükseltmektedir | Evet; pano dışa aktarımı özetli parolaları içermektedir | Hem toplu hem damlama göçünü açıkça belgelemektedir |
| WorkOS | Parola özeti ile tipi; bcrypt, scrypt ile Argon2 | Yerine göre değişmektedir | Açık kaynak göç araçları bulunmaktadır |
| FusionAuth | İstek başına en fazla 10.000 kullanıcı; kullanıcı başına şifreleme şeması; özel parola şifreleyici eklentisi; girişte bcrypt'e yeniden özetleme | Evet, belgelenmiş bir ayrılma yolu vardır | |
| Ory Kratos | En geniş format listesi, aşağıdadır | Evet, yönetim API'siyle | Kanca tabanlı nazik göç: özetsiz içe aktarılmakta, Kratos girişte kancanızı çağırmakta ile başarıda özeti saklamaktadır |
| Supabase | bcrypt, Argon2'nin iki varyantı ile Firebase scrypt'i | API yoktur; veritabanı dökümü ya da servis rolü gerekmektedir | |
| SuperTokens | bcrypt, Argon2 ile Firebase scrypt'i | Yerine göre değişmektedir | Tembel göç belgelidir |
| Descope | bcrypt, Argon2, Django, Firebase, PBKDF2, PHPass ile MD5 | Yerine göre değişmektedir | Tam zamanında göç desteklidir |

Ory Kratos'un tam içe aktarım kodlamaları, bulunan en izin verici settir ile bir Rosetta taşı olarak kullanılmalıdır.

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

Argus'un içe aktarım desteği bu listeyi hedeflemelidir. Her yerden bize gelinebilir iddiasının somut karşılığı budur.

---

### 37. Tembel ile damlama göç

Genel desen şudur: ilk girişte eski sisteme karşı doğrulanmakta, aynı istek içinde hedef formata yeniden özetlenmekte ile göç edildi olarak işaretlenmektedir.

Platform bazında mekanizmalar şunlardır.

| Platform | Mekanizma | Kritik detay |
|---|---|---|
| Auth0 | Özel veritabanı bağlantısı artı kullanıcıları içe aktar düğmesi; giriş ile kullanıcı getirme betikleri | Düğme açık kalmalıdır; kapalıysa Auth0 her kimlik doğrulamada betikleri kullanmaktadır. Göç edilmiş bir kullanıcı silinir ile yukarı akışta hâlâ varsa yeniden göç etmektedir. Karışık yöntemler yinelenen kullanıcı hatalarına ile elle yönetim API'si temizliğine yol açmaktadır |
| Okta | Parola içe aktarma satır içi kancası | Yalnızca Okta'ya içeri göç etmektedir |
| Cognito | Göç işlevi | Göç penceresinde güvenli uzak parola yoktur ile parola politikası zorlanmamaktadır |
| Entra dış kimlik | Parola gönderimi uzantısı | Parolayı şifreleyerek veren tek platformdur |
| Keycloak | Özel parola özet sağlayıcısı, ki en temizdir; kullanıcı depolama sağlayıcısı; ya da özel bir doğrulayıcı | İlk başarılı girişte otomatik yeniden özetlemektedir |
| Ory Kratos | Parola kimlik bilgisi olmadan içe aktarma; girişte kanca | Onayında özeti saklamaktadır |

WorkOS'un 16 Haziran 2026 tarihli operasyonel kuralları kopyalanmaya değerdir: yeniden özetleme giriş isteği içinde senkron yapılmalıdır, ertelenmiş değil; hem eski hem yeni doğrulayıcıda sabit zamanlı karşılaştırma kullanılmalıdır; yeniden özetleme başarısızlığı ölümcül olmayan sayılmalıdır, yani bir yeniden özetleme hatası asla bir girişi engellememelidir; ile eski özet sayısı panoya konmalıdır ki kuyruğun küçüldüğü görülebilsin.

Somut dezavantajlar şunlardır. Uzun bir kuyruk oluşmaktadır: kuyruk zorla sıfırlanacak kadar küçülene dek iki sistemin de parası ödenmektedir. Poppy altı ay çift çalıştırmış ile son birkaç bin kullanıcıyı zorla sıfırlatmıştır. Çift sistem maliyeti ile çift patlama yarıçapı vardır; eski sağlayıcı her göç edilmemiş ilk giriş için ayakta, yamalı ile hız sınırlayabilir durumda kalmalıdır. Hiç dönmeyen kullanıcılar bir problemdir; tek çıkışlar kesim tarihinde e-postayla zorunlu sıfırlama, atıl bırakıp saklama penceresinden sonra silme ya da özetler dışa aktarılabiliyorsa artığı sonda toplu içe aktarmadır. Eski format zayıflığı miras alınmaktadır: hiç dönmeyen kullanıcılar MD5 dönemi korumasında kalmaktadır. Girişte yeniden özetleme yakınsayan bir düzeltmedir, anlık değildir.

---

### 38. Toplu içe aktarım ile özet formatı çapraz uyumluluğu

#### 38.1 Parola özetleme yarışması dizgi formatı, fiilî değişim formatı

Şartname taşınmıştır: eski depo artık C2SP deposundaki parola özeti dizgileri belgesine yönlendirmektedir. Eski depo yalnızca bir yönlendirme notu taşımakta ile bu, çok sayıda doküman bağlantısını bozmaktadır.

Format kimlik, sürüm, parametreler, tuz ile özetten oluşmakta ile sıra bu şekildedir. Kullanılan base64, RFC 4648'in standart kodlamasıdır ancak dolgu işaretleri atlanmaktadır.

Kanonik Argon2 örneği şudur: `$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno`.

Pratik sonuç şudur: Argon2, scrypt, PBKDF2 ile gevşek biçimde bcrypt dizgileri kendini tanımlamaktadır. Cognito'nun 2026 içe aktarımı buna açıkça dayanmaktadır: desteklenen tüm algoritmalar kendini tanımlamaktadır ile yalnızca algoritma adının belirtilmesi yeterlidir. Kendini tanımlamayan her şey, yani Django'nun formatı, .NET'in paketlenmiş ikili verisi, Firebase'in bant dışı özet yapılandırması ile dizin şemaları, bir parametre yan kanalı gerektirmektedir.

#### 38.2 bcrypt varyant karmaşası

Orijinal 1999 öneki, kanonik OpenBSD öneki, Haziran 2011'de sekiz bitlik işaret genişletme hatası için eklenen iki acil işaret ile OpenBSD'nin uzunluk taşması düzeltmesini taşıyan önek sırayla gelmiştir. Son düzeltmenin sebebi parola uzunluğunun işaretsiz bir baytta saklanması ile 255 karakterden uzun parolaların sarmalanmasıdır.

Göç için önemli birlikte çalışabilirlik kuralları şunlardır. Acil işaretlerden biri kasten 2011'in bozuk algoritmasını yeniden üret demektir; asla kanonik önekle değiştirilmemelidir. Bu iki işaret yalnızca ilgili C kütüphanesi ile PHP tarafından benimsenmiştir; OpenBSD ile çoğu gerçekleme bunları hiç üretmemiştir. 72 baytın altındaki yedi bitlik ASCII parolalar için kanonik önek, düzeltilmiş önek ile acil işaretlerden biri özdeş doğrulamaktadır; Auth0'ın üçünü de birbirinin yerine kabul etmesinin nedeni budur. Bazı doğrulayıcılar bilinmeyen önekleri doğrudan reddetmektedir; içe aktarmadan önce hedefin önek izin listesi kontrol edilmelidir.

#### 38.3 bcrypt'in 72 bayt kesmesi ile ön özet deseni

bcrypt girdiyi 72 baytta sessizce kesmektedir.

Önce özetleyip sonra bcrypt uygulama deseni yaygındır. Dropbox parolayı SHA-512 ile özetlemekte, maliyeti 10 olan bcrypt uygulamakta ile sonucu biberle AES-256 ile şifrelemektedir.

OWASP artık naif ön özetlemeye karşı uyarmakta ile hızlı bir algoritmayla ön özetlemeyi tehlikeli olarak nitelemektedir. Sebepleri boş bayttır, ki bazı bcrypt gerçeklemelerinde dizgi kesmesine yol açmaktadır, ile parola soyma saldırısıdır, ki sızmış bir MD5 veya SHA külliyatına sahip saldırgan iç özeti çevrimdışı kırmakta sonra dış bcrypt'i önemsizce test etmektedir. OWASP'ın azaltması biberli HMAC-SHA-384 ile ön özetleme ile bcrypt'e vermeden önce base64 kodlamadır.

Göç sonucu şudur: kaynak önce özetleyip sonra bcrypt uyguladıysa, saklanan değer geçerli bir bcrypt dizgisidir ancak hedef sağlayıcı aynı ön özeti uygulamadıkça hiç kimseyi doğrulayamamaktadır. Auth0, Okta, Cognito ile Firebase'in hiçbiri içe aktarımda bir ön özet adımı yapılandırmanıza izin vermemektedir. Bu desen fiilen tembel göçü ya da özel bir özet sağlayıcısını zorunlu kılmaktadır; Keycloak, FusionAuth ile Ory eklenti yapmanıza izin veren tek üçlüdür.

#### 38.4 Biberli özetler, en zor engel

Biber küresel bir sırdır, veritabanı dışında tutulmaktadır ile her özete uygulanmaktadır. Hedef sağlayıcı onu yapılandıramıyorsa hiçbir dışa aktarılmış özet doğrulanabilir değildir ile kullanıcı başına bir çözüm yolu yoktur.

Seçenekler şunlardır: biberi hedefteki özel bir özet sağlayıcısına taşımak, ki Keycloak, FusionAuth ile Ory'nin biberli formatı bunu mümkün kılmaktadır; biberi tutan eski sistem üzerinden tembel göç etmek; ya da zorla sıfırlatmaktır.

Dropbox'ın AES-256 biber katmanı geri çevrilebilirdir; bu en azından ham bcrypt dizgisinin dışa aktarımdan önce kurtarılabileceği anlamına gelmektedir. Alışılmadık ile göç dostu bir özelliktir. Geri çevrilemez biberler kurtarılamamaktadır.

#### 38.5 Karşılaşacağınız PBKDF2 kodlamaları

Django algoritma, yineleme, tuz ile özeti dolarla ayırmaktadır; tuz hamdır, base64 değildir ile özet base64'tür. Yineleme varsayılanı her sürümde değişmektedir.

Keycloak'ta bir dizgi bile yoktur; veri iki alan arasında bölünmüştür.

ASP.NET Core kimlik sisteminde paketlenmiş ikili bir veri base64 kodlanmakta ile başta bir format işaretçi baytı bulunmaktadır. Sıfır değeri ikinci sürümü göstermekte, yani HMAC-SHA1 ile 128 bitlik tuz, 256 bitlik alt anahtar ile bin yineleme; bir değeri üçüncü sürümü göstermekte, yani sözde rastgele fonksiyon, yineleme sayısı, tuz uzunluğu, tuz ile alt anahtar alanlarını taşımakta ve varsayılanı HMAC-SHA256 ile on bin yinelemedir. Göç notu şudur: hiçbir ana akım sağlayıcı bunu yerel olarak içe aktarmamaktadır. İkili veri açılıp PHC tarzı PBKDF2 olarak yeniden yayımlanmalıdır; ikinci sürümün fonksiyonu SHA-1'dir, yani PBKDF2 SHA-1'e eşlenmektedir, ki Cognito'nun içe aktarımı bunu desteklememektedir.

Okta PBKDF2'yi bir dizgi değil ayrık alanlar olarak almaktadır.

#### 38.6 Hedefin tavanı kaynağın parametrelerini belirlemektedir

OWASP'ın güncel önerileri şunlardır. Argon2id için 46 mebibayt ile bir yinelemeden 7 mebibayt ile beş yinelemeye kadar beş yapılandırma verilmektedir. scrypt için 128 mebibayt ile bir paralellikten daha küçük bellekli ve daha yüksek paralellikli beş yapılandırmaya kadar bir dizi verilmektedir. bcrypt için doğrulama sunucusu performansının izin verdiği kadar büyük, asgari 10 maliyet önerilmektedir. PBKDF2 için HMAC-SHA256 ile 600.000, HMAC-SHA512 ile 220.000 ile yalnızca eski sistemler için HMAC-SHA1 ile 1.400.000 yineleme önerilmektedir.

Cognito'nun tavanlarıyla çakışmaya dikkat edilmelidir: OWASP'ın en düşük önerilen Argon2id yapılandırması 7 mebibayt, en yükseği 46 mebibayttır. Cognito'nun içe aktarım tavanı 19456 kibibayt, iki yineleme ile bir paralelliktir; tam olarak OWASP'ın ikinci seçeneğidir. OWASP'ın 46 mebibaytlık ayarıyla özetlenmiş hiçbir şey Cognito'ya içe aktarılamamaktadır. scrypt'te aynı hikâye geçerlidir: OWASP'ın asgarisi yüksek paralellikli bir yapılandırmadır, Cognito ise bir paralellikte tavan yapmaktadır.

Dolayısıyla özet parametreleri hedefinizin tavanına göre planlanmalıdır. Bu tek kontrol, belgelenen en yaygın geç aşama göç başarısızlığını önlerdi.

Eski özeti yenisiyle sarmalama, yani OWASP'ın katmanlama yöntemi, bir başka seçenektir. OWASP'ın kendi çekinceleri şunlardır: düz metin gerektirmemesi iyidir ancak özetleri kırmayı kolaylaştırabilmektedir, yine soyma saldırısı nedeniyle, ile katmanlı özetler kullanıcının bir sonraki girişinde değiştirilmelidir. Hiçbir büyük sağlayıcının içe aktarım API'si katmanlı özet desteklememektedir; bu desen yalnızca kendi barındırılan bir seçenektir ile çıkan taraf sizseniz kendisi bir göç engelidir.

---

### 39. Göç edilemeyenler

#### 39.1 Geçiş anahtarları ile WebAuthn: alan adı değişiminde ölmektedirler, nokta

Neden öldükleri şudur: bağlı taraf kimliği kayıtta sabitlenmekte ile çağıranın kökeninin kaydedilebilir alan adı sonekiyle sınırlanmaktadır. Kimlik doğrulayıcı, bağlı taraf kimliğini, ki özeti kimlik doğrulayıcı verisindedir, kimlik bilgisinin içinde saklamakta ile bağlı taraf her doğrulamada bunu kontrol etmek zorundadır. Şartname şöyle demektedir: yalnızca kendi bağlı taraf kimliğiyle tanımlanan o bağlı taraf, açık anahtar kimlik bilgisini kullanabilmektedir.

Yani bir alt alan adıyla oluşturulmuş bir kimlik bilgisi, apeks alan adıyla ya da başka bir sağlayıcının alan adıyla asla kullanılamamaktadır. Yeniden kapsamlama API'si, yönetici geçişi ile dışa aktarım yoktur. Tek çare, eski kimlik hâlâ çalışırken yeni kimlik altında yeniden kayıttır.

Bunun ima ettiği tasarım kuralı şudur: bağlı taraf kimliği ilk kayıttan önce seçilmelidir; apeks alan adı olmalıdır, giriş alt alan adı değil ile kesinlikle kimlik sağlayıcı satıcısının alan adı değil. Bu, geri alınamayan tek WebAuthn kararıdır.

İlgili kökenler istekleri kısmen yardım etmektedir. Bağlı taraf kimliğinin iyi bilinen WebAuthn adresinde bir JSON dosyası sunulmaktadır.

```json
{ "origins": ["https://site-2.com", "https://site-3.com"] }
```

Tarayıcılar listelenen her kökeni etkin üst düzey alan artı bir etiketine indirgemekte ile en fazla beş benzersiz etiket zorlamaktadır; fazlası sessizce yok sayılmaktadır. İstemci verisindeki köken, bağlı taraf kimliği değil isteyen köken olarak kalmaktadır. Tarayıcı desteği Chrome ile Edge 128 ve üstü, Safari 18, ki ikisi de 2024'tür, ile Mayıs 2026'da Firefox 152 masaüstü ve Android'dir; son büyük boşluk kapanmıştır.

Kimlik sağlayıcı göçü için ne satın aldığı ile ne almadığı şudur: bu mekanizma, yeni bir kökenin, örneğin yeni sağlayıcının barındırılan arayüzünün, mevcut ile değişmemiş bağlı taraf kimliğini kullanmasına izin vermektedir. Bu gerçekten değerlidir; aynı kimliği koruyabiliyorsanız ile iyi bilinen dosyayı hâlâ oradan sunabiliyorsanız, giriş sayfasını geçiş anahtarlarını öldürmeden yeni bir sağlayıcıya taşıyabilirsiniz. Ancak bağlı taraf kimliğini değiştirmenize izin vermemekte ile kimlik bilgilerini hiçbir yere taşımamaktadır. Ayrıca yalnızca web içindir; Android ile iOS'ta ayrı alan adı ilişkilendirme mekanizmaları gerekmektedir.

FIDO kimlik bilgisi değişim formatı ile protokolü kimlik sağlayıcı göçüne yardım etmemektedir. Format FIDO Alliance önerilen standardıdır, Ağustos 2025; birinci sürümünün 9 Mart 2026 tarihi ikincil kaynaktandır ile doğrulanmamıştır. Protokol hâlâ çalışma taslağıdır; çekilebilen en güncel hâli 3 Ekim 2024 taslağıdır ile aktarımda uçtan uca şifreleme için hibrit açık anahtar şifrelemesi kullanmaktadır. Kapsamı taslaktan birebir şudur: bu protokol, bir veya daha fazla kimlik bilgisinin iki kimlik bilgisi sağlayıcısı arasında güvenli iletimini tanımlamaktadır. Katılımcılar kimlik bilgisi sahibi ile kimlik bilgisi sağlayıcılarıdır, yani parola yöneticileri ile platform kimlik bilgisi yöneticileridir; bağlı taraflar ile kimlik sağlayıcılar katılımcı değildir. Dolayısıyla bu mekanizma geçiş anahtarlarını parola yöneticileri arasında taşımaktadır; bir bağlı taraftan diğerine taşımak için hiçbir şey yapmamaktadır. Bağlı taraf tarafındaki açık anahtar ile kimlik bilgisi tanımlayıcısı zaten sizin verinizdir, yani sağlayıcının kriptosunda değil sizin veritabanınızdadır; ancak yalnızca bağlı taraf kimliği özdeş kalırsa kullanılabilir. Apple iOS 26 ile macOS 26'da bu formata dayalı aynı cihaz kimlik bilgisi transferini sevk etmiştir.

#### 39.2 Tek kullanımlık şifre sırları

| Ürün | Dışa aktarım |
|---|---|
| Keycloak | Evet; kimlik bilgileri aynı dizide bulunmakta ile kullanıcılarla birlikte çıkmaktadır. Keycloak'ın en büyük taşınabilirlik avantajıdır |
| Auth0 | Kapılı PGP destek sürecindedir, parola özetleriyle aynıdır |
| Okta | Yoktur; yeniden kayıt gerekmektedir |
| Cognito | Yoktur. Çok faktörlü etkinlik yalnızca bir mantıksal değerdir; çok faktörlü zorunlu bir havuza içe aktarılan kullanıcılar geçerli bir faktör yapılandırana kadar giriş yapamamaktadır |
| Firebase komut satırı | Yoktur; şemada çok faktörlü alan yoktur |
| Entra ile B2C | Yoktur |

Google Authenticator dışa aktarım formatı, kullanıcılardan faktörleri kendilerinin taşımasını isteyecekseniz, şudur: karekod bir göç adresi kodlamakta ile yükü standart bir kimlik doğrulama adresi değil bir protokol arabelleği mesajıdır.

#### 39.3 Oturumlar, yenileme token'ları, rızalar ile denetim geçmişi

Bunlar taşınabilir değildir. Eski sağlayıcının verdiği token'lar yenisi tarafından doğrulanamamaktadır; imzalama anahtarları, veren, izleyici kitle, iddia şekilleri ile ömürler farklıdır. Rıza ile yetki kayıtları istemci başınadır ile yeniden kurulmalıdır. Denetim geçmişi geride kalmaktadır.

Bulunan tek ürünleşmiş azaltma Descope'un 15 Aralık 2025 tarihli oturum göçüdür: ön yüz eski token'ı yeni sağlayıcıya vermekte, o doğrulamakta, kullanıcıya eşlemekte ile yerel bir oturum basmaktadır; kimse çıkış yapmamaktadır. Yalnızca Auth0 kaynağı ile kendi geliştirme kitleri gerekmektedir. Aynı numara kendiniz kurulabilir: eski sağlayıcının JWT'sini anahtar seti üzerinden doğrulayan ile yeni oturum veren bir token değişimi uç noktası. Mimo tam olarak bunu yapmıştır.

#### 39.4 Özne tanımlayıcısı problemi, hafife alınan kritik engel

Yeni sağlayıcınız yukarı akış sosyal ya da kurumsal sağlayıcılarda yeni OAuth istemci kimlikleri kaydediyorsa, aldığınız özne tanımlayıcısı değişebilmekte ile hesap bağlaması sessizce kırılmaktadır.

| Sağlayıcı | Özne tanımlayıcısı istemci kimlikleri arasında kararlı mıdır | Ne yapılmalıdır |
|---|---|---|
| Google | Tüm Google hesapları arasında benzersizdir ile asla yeniden kullanılmamaktadır; e-posta değişse bile değişmemektedir. Ancak Google projeler arası bir garanti vermemektedir | Pratikte kararlı sayılmalı ancak kesimden önce ampirik doğrulanmalıdır. Projeler arası durum doğrulanmamıştır |
| Apple | Hayır; özne tanımlayıcısı geliştirici takımına kapsamlıdır. Uygulama yeni bir takıma devredilirse değişmektedir | Transfer tanımlayıcı akışı kullanılmalıdır |
| Microsoft Entra | Hayır; özne tanımlayıcısı uygulama başına ikilidir. Tek bir kullanıcı iki farklı istemci kimliğiyle iki farklı uygulamaya girerse, o uygulamalar iki farklı özne değeri almaktadır. Açık özne tipine değiştirilememektedir | Nesne kimliği ile kiracı kimliği üzerinden anahtarlanmalıdır, özne üzerinden değil; Microsoft açıkça bunu söylemektedir |
| Facebook | Hayır; 2014'teki grafik API'si ikinci sürümünden beri kullanıcı kimlikleri uygulama kapsamlıdır, yani aynı kullanıcının kimliği uygulamalar arasında farklıdır | Aynı uygulama korunmalı ya da aynı işletmenin sahip olduğu uygulamalar arasında işletme eşleme API'si kullanılmalıdır |

Tasarım dokümanı için pratik kural şudur: sağlayıcı ikili özne kullanıyorsa, yeni sağlayıcıda tam olarak aynı yukarı akış OAuth uygulama kayıtları ile istemci kimlikleri yeniden kullanılmalıdır. Kullanılamıyorsa tek yedek yol doğrulanmış e-posta üzerinden bağlamaktır; bu her zaman mevcut değildir, örneğin Apple özel aktarıcısında, ile güvenlik açısından hassas bir karardır. Doğrulanmamış e-posta üzerinden otomatik bağlama bir hesap devralma vektörüdür.

#### 39.5 Apple ile giriş, transfer tanımlayıcı mekanizması

Kullanıcı göç bilgisi uç noktası üzerinden iki faz vardır.

1. Devirden önce gönderen takım, özne transfer işlemiyle, istemci kimliği, istemci sırrı ile hedef takım kimliğini vererek her kullanıcı için geçici bir transfer tanımlayıcısı basmaktadır.
2. Devirden sonra alan takım, değişim işlemiyle, transfer tanımlayıcısını ile kendi istemci kimliği ve sırrını vererek yeni takım kapsamlı kimliği almaktadır.

```json
{"sub":"820417.faa325acbc78e1be1668ba852d492d8a.0219",
 "email":"ep9ks2tnph@privaterelay.appleid.com",
 "is_private_email": true}
```

Devir tamamlandıktan sonra 60 günlük bir pencere bulunmaktadır. Apple transfer tanımlayıcısını o pencerede verilen kimlik token'larına da koymakta, böylece girişte anında göç edilebilmektedir. Transfer tanımlayıcıları takım çifti başına benzersizdir; farklı çiftler farklı tanımlayıcılar üretmektedir. Pencere kaçırılırsa eşleme kurtarılamamaktadır: kullanıcılar orijinal kimlikleriyle artık giriş yapamamakta ile yeni hesap açmak zorunda kalmaktadır.

---

### 40. Her kaynağın fiilen dışa aktardığı

| | Kullanıcılar | Parola özeti | Çok faktörlü | Grup ile rol | İstemci ile uygulama | Organizasyon yapısı | Format |
|---|---|---|---|---|---|---|---|
| Auth0 | Evet | Destek talebiyle; PGP ile yönetici imzası gerekmektedir | Normal dışa aktarımda yalnızca sağlayıcı listesi; sırlar aynı talebededir | Yönetim API'siyle, ayrı çağrılar | Yönetim API'si ya da komut satırı | Organizasyonlar API'si | Satır ayrılmış JSON ya da en fazla 30 alanlı CSV |
| Okta | Evet, kullanıcılar API'siyle | Hayır; dar bir istisna vardır | Hayır; yeniden kayıt gerekmektedir | Gruplar API'si | Uygulamalar API'si | Yerine göre değişmektedir | API'den JSON |
| Cognito | Evet, kullanıcı listeleme çağrısıyla, saniyede beş istek sınırıyla | Dışa aktarım hayırdır; içe aktarım 15 Temmuz 2026'dan beri vardır | Hayır; yeniden kayıt gerekmektedir | Gruplar API'si | API | Yerine göre değişmektedir | JSON; içe aktarım için CSV |
| Keycloak | Evet | Evet; kimlik bilgileri dizisindedir | Evet; tek kullanımlık şifre aynı dizidedir | Alan ile istemci rolleri, gruplar ile üyelikler | Evet, protokol eşleyicileri dahil | Organizasyonlar, 26 ve üstü | JSON |
| Firebase | Evet | Yalnızca scrypt; diğerleri boş dönmektedir | Hayır | Yerine göre değişmektedir | Yerine göre değişmektedir | Yerine göre değişmektedir | JSON ya da 26 sütunlu CSV |
| Entra dış kimlik ile B2C | Grafik API'siyle | Hayır | Hayır | Grafik | Uygulama kayıtları | Grafik | Grafikten JSON |

Keycloak'ın dışa aktarımı beşinin en eksiksizidir; Cognito ile Okta'nınki en az eksiksizidir. Auth0 ortadadır ile acı verici de olsa resmî bir özet kaçış kapağı olan tek üründür.

---

### 41. Sıfır kesinti stratejileri

Çift çalıştırma ile kademeli trafik kaydırma, sıfır kesintiyi fiilen sağlayan tek desendir; zamanlanmış bir tek seferlik geçiş bunu sağlamamaktadır. Kohort ya da kiracı bazında kaydırılmalı, hata oranı ile gecikme izlenmeli ile geri kaydırma yeteneği korunmalıdır.

Boğan incir ya da cephe vekili deseninde iki sağlayıcının önüne bir vekil konmakta ile istek başına yönlendirilmektedir. Kimlik sağlayıcılar için cephe genelde kendi giriş işleyicinizdir ya da kullanıcı başına hangi sağlayıcının çağrılacağına karar veren bir API ağ geçididir.

Bir arada yaşama sırasında iki token tipi de doğrulanmalıdır: arka uç eski ile yeni sağlayıcı token'larını eşzamanlı kabul etmelidir, yani iki anahtar seti adresi ile iki veren, en uzun yenileme token'ı ömrü boyunca. Aksi hâlde insanlar çıkış yaptırılmaktadır.

Oturum sürekliliğinde ya eski token kabul edilip yerel bir tanesiyle değiştirilmeli ya da kesimin herkesi çıkış yaptıracağı kabul edilmelidir; bu açıkça karara bağlanmalıdır, çünkü kullanıcıya en görünür sonuç budur.

Özeti dışa aktarılabilir bir kaynak için önerilen sıralama şudur: önce özetler toplu içe aktarılmalıdır, çoğu kullanıcı hiç yedek yol gerektirmemektedir; sonra artık için tembel göç açılmalıdır, yani dışa aktarımla kesim arasında oluşturulan kullanıcılar için; sonra kuyruk zorla sıfırlatılmalıdır. Mimo tam olarak bunu yapmıştır ile en az hareketli parçası olan desen budur.

İnsanların unuttuğu pratik detay şudur: Auth0, hem toplu içe aktarım hem otomatik göç kullanılırsa ya da silinmiş kullanıcılar yeniden oluşturulursa yinelenen kullanıcı hataları alınacağını ile elle yönetim API'si temizliği gerekeceğini uyarmaktadır. Kohort başına tek bir birincil yol seçilmeli ile onun üzerinden kapılanmalıdır.

---

### 42. Gerçek vaka çalışmaları

Güçlü, birinci taraf ile somut olanlar şunlardır.

Mimo, altı milyon kullanıcıyı Auth0'dan Firebase kimlik doğrulamaya taşımıştır, 16 Kasım 2020. Yaklaşık iki hafta hazırlık, göç başlangıcından uygulama yayınına yaklaşık sekiz saat sürmüştür. Parola hesapları için ikinci bir dışa aktarım gerekmiştir, çünkü özetler ilk dışa aktarımda yoktu. Özel bir token değişimi uç noktası kurmuşlardır, çünkü yenileme token'ları uyumsuzdu; dışa aktarımla kesim arasındaki kayıtları yakalamak için kural motorunu kullanmışlardır; aynı e-postayı paylaşan çoklu hesapları tekilleştirmişlerdir. Sonuç kimse fark etmeden ile kimse çıkış yaptırılmadan olmuştur.

Keymate, 20 milyondan fazla kimliği Keycloak'a taşımıştır, Şubat 2026. İş hacmi saatte iki milyondan 12 milyon kimliğe, yani altı kata çıkarılmıştır, hem de kaynak eklemeden. Göç aracı Quarkus ile reaktif bir PostgreSQL istemcisidir; 512 talep edici, 512 eşzamanlı HTTP isteğine kadar ile 2.000'lik yığınlar kullanılmıştır. Darboğazlar sırayla şunlardır: aşırı eşzamanlılıkta bağlantıları öldüren HTTP/2 sıfırlama seli koruması; kullanıcı tablosundaki 2,5 milyon ölü demetten gelen veritabanı kilit çekişmesi; 2.750 eşzamanlı veritabanı bağlantısının debelenmesi; ile aşırı sağlanmış havuzlar. Alıntılanacak cümle şudur: Keycloak hiçbir zaman darboğaz olmamıştır ile 95 bin eşzamanlı isteği çökmeden soğurmuştur. Havuzları yüzlerden 50'ye indirmek ile uygulama eşzamanlılığını yarıya düşürmek iş hacmini ikiye katlamıştır.

Poppy, Belçikalı bir araç paylaşım şirketi, Auth0'dan SuperTokens'e altı ay boyunca tembel göç yapmıştır. İki sistemi paralel çalıştırmışlardır ile müşteriler bundan haberdar olmamıştır. Auth0'da yalnızca birkaç bin kullanıcı kaldığında onları zorla sıfırlatmış ile Auth0'ı kapatmışlardır.

Avusturya Federal Bilgi İşlem Merkezi, iki milyondan fazla kullanıcıyı Keycloak'a taşımış ile 130'dan fazla kamu hizmetine mikroservis ve GitOps ile hizmet vermektedir, Ağustos 2025.

Amazon Cognito'nun kendisi, yüz milyonlarca kullanıcı profilini sıfır kesintiyle yeni nesil depolama altyapısına göç etmiştir, 4 Haziran 2026; ölçekte çevrim içi kimlik veri deposu göçünün varlık kanıtıdır.

Zayıf ya da satıcı yazımı olanlar dikkatle alıntılanmalıdır. Aylık 500 bin aktif kullanıcının Auth0'dan MojoAuth'a altı haftada, üç mühendisle, yaklaşık 280 mühendis saatiyle, yaklaşık 4.200 dolarlık çift çalıştırma maliyetiyle ile 187.000 dolarlık ilk yıl tasarrufuyla taşındığı iddiası satıcı pazarlama içeriğidir, Mayıs 2026, ile bağımsız doğrulanabilir değildir; bir büyüklük mertebesi çıpası olarak kullanılmalıdır.

Hedefli aramaya rağmen bulunamayanlar şunlardır: Hey ile Basecamp, Shopify, Zapier, PostHog, Cal.com, Supabase ya da Vercel'den Auth0, Okta veya Cognito'dan çıkış hakkında kamuya açık bir mühendislik incelemesi yoktur. Bu şirketlerin böyle bir vaka çalışması yayımladığı iddiası doğrulanmamış sayılmalıdır.

---

### 43. Altıncı bölüm için Argus kararları

| Sıra | Karar | Gerekçe |
|---|---|---|
| 1 | İçe aktarım Ory Kratos'un format listesini hedeflemektedir: bcrypt tüm önekleri, Argon2'nin iki varyantı, scrypt, Firebase scrypt'i, PBKDF2'nin tüm fonksiyonları, dizin şemaları, crypt türevleri ile biberli format | Her yerden gelinebilir iddiasının somut karşılığıdır |
| 2 | Ön özet ile biber eklenebilir; bir özet sağlayıcı eklenti noktası bulunmaktadır | Önce özetleyip sonra bcrypt uygulayan ile biberli özetler yalnızca böyle göç etmektedir |
| 3 | Parametre tavanı yoktur; OWASP'ın en yüksek ayarları dahil her şey kabul edilmektedir | Cognito'nun tavanı belgelenmiş en yaygın göç başarısızlığıdır |
| 4 | Girişte otomatik yeniden özetleme yapılmaktadır; senkrondur ile başarısızlığı ölümcül değildir | WorkOS operasyonel kuralıdır |
| 5 | Dışa aktarım özetleri ile tek kullanımlık şifre sırlarını kendin yap biçimde vermektedir; yönetici yetkisi, yükseltilmiş kimlik doğrulama ile bir denetim olayı gerekmektedir | Keycloak dışında kimse yapmamaktadır; dürüstlük iddiası budur |
| 6 | Dışa aktarım kendini tanımlayan PHC dizgisi biçimindedir | Yan kanal parametresi gerektirmemektedir |
| 7 | Parola gönderimi eşdeğeri uzantı parolayı şifreleyerek vermektedir | Entra'nın tek doğru yaptığı şeydir |
| 8 | Bağlı taraf kimliği kurulumda tek seferlik ile değiştirilemez bir karar olarak, uyarıyla sunulmaktadır | Geri alınamayan tek WebAuthn kararıdır |
| 9 | İyi bilinen WebAuthn dosyası birinci sınıf desteklenmekte ile beş etiket limiti arayüzde gösterilmektedir | Barındırılan giriş arayüzüne geçişi geçiş anahtarlarını öldürmeden yapmaktadır |
| 10 | Yukarı akış sosyal sağlayıcılarda istemci kimliği yeniden kullanımı zorunlu tutulmakta; farklı bir kimlik girilirse açık uyarı verilmektedir | Apple, Entra ile Facebook ikili özne kullanmaktadır |
| 11 | Entra bağlantılarında nesne ile kiracı kimliği üzerinden anahtarlanmaktadır, özne üzerinden değil | Microsoft'un kendi tavsiyesidir |
| 12 | Apple transfer tanımlayıcı akışı yerleşiktir ile 60 günlük pencere sayacı bulunmaktadır | Kaçırılırsa kurtarılamamaktadır |
| 13 | Token değişimi uç noktası eski sağlayıcının token'ını anahtar setiyle doğrulamakta ile yerel bir oturum basmaktadır | Kesimde kimse çıkış yapmamaktadır |
| 14 | Çift anahtar seti ile çift veren doğrulaması bir arada yaşama modu olarak yapılandırılabilmektedir | En uzun yenileme token'ı ömrü boyunca gerekmektedir |
| 15 | Eski özet sayacı yönetim panosunda birinci sınıf bir metriktir | Kuyruğun küçüldüğünü görmek içindir |

---

## Bölüm VII — İşletmeler arası organizasyon akışları

### 44. Davet akışı güvenliği

#### 44.1 Satıcı davranışı

WorkOS AuthKit iki adımlı bir model kullanmaktadır: davet eden birinin bir organizasyona katılması niyetini ifade etmekte ile davet edilen o organizasyona katılmayı seçmektedir. Açıkça, rıza olmadan bir organizasyona eklenmeye karşı bir savunma olarak çerçevelenmektedir.

Türk bir kimlik sağlayıcı referansı için not edilmesi gereken kritik tasarım kararı şudur: WorkOS kabulü alan adı sınıfına göre farklı bağlamaktadır. Tüketici alan adlarında davet edilen kullanıcı, davetin gönderildiği adresin tam olarak aynısıyla kaydolmak zorundadır. Kurumsal alan adlarında kullanıcı, davetteki e-postayla aynı alan adından herhangi bir adresle kaydolabilmektedir. Bu, katı e-posta bağlamasının kasıtlı bir gevşetilmesidir ile tam olarak davet edilenden farklı bir e-postayla kabul davranış sınıfıdır; yalnızca kurumsal alan adı doğrulanmışsa güvenlidir.

Davet nesnesi bir veritabanı satırıdır, durumsuz bir JWT değildir; kimlik, e-posta, durum, belirteç, organizasyon kimliği, kabul zamanı, sona erme ile oluşturma ve güncelleme zamanlarını taşımaktadır. İlgili bir WorkOS uyarısı şudur: dönen profilin organizasyon kimliği daima doğrulanmalıdır ile e-posta alan adlarıyla doğrulama yapmak güvensizdir.

Clerk'te uygulama davetleri bir ayda sona ermekte ile organizasyon davetleri varsayılan 30 gündür. Belirteç adreste bir sorgu parametresi olarak taşınmaktadır; yani belirteç adrestedir ile yönlendiren politikası önemlidir. Clerk'ün açık uyarısı şudur: bir daveti iptal etmek kullanıcının kendi başına kaydolmasını engellememektedir. Yani davetin iptali, kayıt kısıtlanmadıkça erişimin iptali değildir. Hız sınırları uygulama için saatte 100 tekil ile 25 toplu, organizasyon için saatte 250 tekil ile 50 toplu ve çağrı başına en fazla 10'dur.

Auth0 organizasyonlarında yaşam süresi varsayılanı yedi gün, azamisi 30 gündür; herhangi bir satıcının yayımladığı en somut yaşam süresi rakamlarıdır. Bağlama katıdır: davet edilen kullanıcılar davetin gönderildiği e-posta adresiyle giriş yapmalı ya da hesap oluşturmalıdır; WorkOS'un kurumsal alan gevşetmesiyle zıttır. Davet adresi bilet kimliğini, organizasyon kimliğini ile adını sorgu parametresi olarak taşımaktadır; yine belirteç adrestedir. Davet oluşturmada bir roller dizisi eklenebilmektedir, dolayısıyla rol yetkilendirmesi oluşturma anında sunucu tarafında yapılmalıdır.

Stytch'in işletmeler arası ürününde sihirli ile davet bağlantıları kesinlikle tek kullanımlıktır; gömülü belirteç ilk başarılı tıklamada tüketilmektedir. E-posta güvenlik tarayıcısı problemi, davet bağlantılarının başlıca gerçek dünya başarısızlık modudur: kurumsal posta tarayıcıları bağlantıları otomatik tıklamakta ile insan görmeden tek kullanımlık belirteci tüketmektedir. Stytch'in korumalı sihirli bağlantıları cihaz istihbaratı kullanarak tarayıcı tıklamasının belirteci tüketmemesini sağlamaktadır. Tek kullanımlık olan her davet tasarımı bunu ele almalıdır.

Organizasyon ayarları davetleri kapılamaktadır: e-posta davetleri tümü izinli, kısıtlı ya da izinsiz olabilmekte ile izinli alan adı listesiyle birlikte kullanılmaktadır. Kısıtlıyken kabul eden kullanıcının e-postası izin listesiyle eşleşmeli ile yaygın tüketici alan adlarına izin listesinde izin verilmemektedir.

Frontegg belirteç oluşturmada dakika cinsinden bir sona erme parametresi, yani açık ile çağıran kontrollü bir yaşam süresi sunmaktadır. Sihirli bağlantı alternatifi olarak altı haneli bir sihirli kod sunmakta ile kodların sihirli bağlantılardan daha güvenli sayıldığını, çünkü e-posta ele geçirilirse yetkisiz erişim riskini azalttığını söylemektedir; yönlendiren ile iletme sızıntısı açısından alakalıdır.

Vercel nadir, yayımlanmış ile farklılaştırılmış bir yaşam süresi vermektedir: daveti kabul için yedi gün, SAML zorunlu takımlar için 30 gün.

#### 44.2 Adreste belirteç ile yönlendiren sızıntısı

OWASP parola unutma özet sayfası, ki davet belirteçlerine doğrudan uygulanabilir, şunları söylemektedir: belirteçler kriptografik olarak güvenli bir rastgele üreteçten gelmeli, kaba kuvvete karşı yeterince uzun olmalı, kullanımdan sonra geçersiz kılınmalı, uygun sürede sona ermeli, özetlenmiş olarak güvenli saklanmalı ile veritabanında bireysel bir kullanıcıya bağlanmalıdır. Açık yönlendiren rehberliği, yönlendiren sızıntısını önlemek için yönlendiren politikası başlığının yönlendiren yok değeriyle eklenmesidir.

Gerçek raporlar HackerOne'daki 342693 numaralı parola sıfırlama belirtecinin yönlendirenle sızması ile 301526 numaralı davet belirtecinin bir reklam alan adına sızması raporlarıdır. HackerOne rapor gövdeleri JavaScript ile işlenmekte ile doğrudan çekilememiştir; başlıklar ile programlar arama indekslerindendir. Gövde detayları doğrulanmamış sayılmalıdır.

#### 44.3 Gerçek hata ödülü raporları ile güvenlik açıkları

GitLab'ın 356665 numaralı konusu ile HackerOne'daki 1517554 numaralı rapor, başka bir kullanıcının e-posta adresini doğrulanmamış ikincil e-posta olarak kullanarak e-posta davetiyle özel bir projeye erişim kazanmayı anlatmaktadır. Bildiren 21 Mart 2022'de raporlamıştır. GitLab bir daveti, davet edilen adresi doğrulanmamış ikincil e-posta olarak tutan bir hesapla eşleştirmekteydi; saldırgan kurbanın kurumsal adresini kendi hesabına önceden eklemekte ile gelecekteki her daveti sessizce ele geçirmekteydi. Bu, kabul edenin fiilen kontrol etmediği bir e-postaya bağlanmış davet için en iyi kanonik örnektir.

İlgili, güvenlik hatası olarak görünmeyen ancak aslında bağlama hataları olan kullanıcı deneyimi hataları GitLab'ın 321324 ile 338022 numaralı konularıdır: davet e-postası eşleştirmesi büyük küçük harfe duyarlıdır, yani aynı adresin farklı yazımları ayrışmaktadır. Davet edilen adresin harf büyüklüğü ile Unicode normalizasyonu gerçek bir tasarım gereksinimidir.

Slack'in HackerOne'daki 1663361 numaralı raporu kurban için kabulü atlamayı anlatmaktadır; açıklama 17 Şubat 2023'tür ile ödülü 1.500 dolardır. Slack çalışma alanı yöneticileri, kullanıcının daveti kabul etmesine gerek kalmadan e-postayla keyfî bir kullanıcı ekleyebilmekteydi; hem kabul adımını hem kurbanın saldırganın davetlerine koyduğu önceki engellemeyi atlamaktaydı.

ProductBoard ile Satismeter'in 2586433 numaralı raporu, 31 Ekim 2024 gönderimi, güvensiz davet bağlantısı işlemeyi anlatmaktadır: bir e-posta adresine gönderilen davet bağlantısı, tamamen farklı bir e-posta adresiyle organizasyona katılmak için kullanılabilmekteydi.

Shopify'ın 2885269 numaralı raporunda bir personel, davet edilen sahiplerin e-posta adreslerini görebilmekte, onlarla hesap oluşturabilmekte ile daveti kabul ederek e-posta doğrulaması olmadan yükseltilmiş ayrıcalık kazanabilmekteydi. Ödül rakamı arama indeksindendir ile doğrulanmamıştır.

Dropbox'ın Bugcrowd'daki 21 Şubat 2023 tarihli raporu, yöneticinin kullanıcıyı sahip olarak davet ederek organizasyonu devralmasına izin veren bir ayrıcalık yükseltmesini anlatmaktadır: davet edebilen bir saldırgan, daveti değiştirerek takım sahibinin yerine geçebilmekteydi. Üçüncü öncelikli sayılmış ile 300 dolar ödenmiştir. Bu, davet yükünü kurcalayarak rol yükseltmenin kanonik örneğidir.

Budibase'in GHSA-4wfw-r86x-qxrm ile CVE-2026-25040 numaralı kritik açığında, davet etme arayüzü izni olmayan yaratıcı seviyesindeki bir kullanıcı çoklu davet uç noktasına gönderi yaparak herhangi bir rolle, yani yönetici ya da yaratıcı rolüyle, ile herhangi bir gruba kullanıcı davet edebilmekteydi. Açıklama şudur: API, isteği yapan kullanıcının kullanıcı oluşturma, rol atama ya da grup üyeliği izinlerini doğrulamamaktadır. Uyarı okunduğunda henüz yamalanmamış olarak listelenmekteydi; düzeltme sürümü doğrulanmamış sayılmalıdır.

HackerOne'ın kendi programındaki davet akışı gerilemeleri, ki başlıklar doğrulanmış ancak gövdeler doğrulanmamıştır, şunlardır: durum değişiminde davetin geçersiz kılınmaması; bir değişikliğin önceki bir düzeltmeyi geri alması; kullanıcı takıma zaten eklendikten sonra davetin yeniden kullanılabilmesi; eski davet bağlantılarının yeniden adlandırmadan sonra özel bir programın yeni tanıtıcısını çözmesi; hesabı olmayan bir adrese gönderilen daveti birden çok farklı araştırmacı hesabının ziyaret edip kabul edebilmesi; ile davet akışı üzerinden davet edilen adresin ifşası.

#### 44.4 İmzalı belirteçle veritabanı satırının karşılaştırması

İncelenen her büyük işletmeler arası kimlik sağlayıcı bir veritabanı satırı kullanmaktadır, çıplak durumsuz bir JWT değil: WorkOS durum ile iptal alanlı bir davet nesnesi, Auth0 bilet kimliği ile sona erme, Clerk iptal edilebilir kayıtlar, Stytch sunucu tarafında tüketilen bir belirteç ile Frontegg davet belirteci kayıtları kullanmaktadır.

Belirleyici argüman iptaldir.

> *"JWTs let you go stateless, but magic links require single use enforcement which inherently requires server side state (a denylist on the `jti` claim). At that point you have lost the statelessness benefit and gained the complexity cost of JWT validation including algorithm confusion attacks. Opaque random tokens stored server side as SHA-256 hashes are simpler and harder to misuse."*

Argus için tasarım sonucu şudur.

```
URL'de opak yüksek-entropili token
    ↓
Depoda SHA-256 hash'li
    ↓
Tek DB satırı:
  { org_id, invited_email_normalized, role, inviter_id,
    expires_at, consumed_at, revoked_at }
```

Tek kullanım, tüketim zamanı alanı üzerinden ile bir işlem veya benzersizlik kısıtı altında zorlanmalıdır. Rol satırdan okunmalıdır, asla istekten değil. Yaşam süresi yedi gün olmalı, ki Auth0 ile Vercel varsayılanıdır, ile azami 30 gün olmalıdır. Kabul sayfasında yönlendiren yok politikası uygulanmalıdır. Sihirli kod yedek yolu ile tarayıcı tıklaması toleransı bulunmalıdır ki tek kullanım kurumsal posta ortamlarında kırılmasın.

#### 44.5 Klasik davet zafiyetleri kontrol listesi

Her maddenin yukarıda gerçek dünya atfı bulunmaktadır.

| Sıra | Zafiyet | Atıf |
|---|---|---|
| 1 | Adreste belirteç ile yönlendiren veya analitik sızıntısı | HackerOne raporları ile OWASP yönlendiren politikası |
| 2 | Davet edilenden farklı e-postayla kabul | ProductBoard raporu; WorkOS'un kasıtlı kurumsal gevşetmesi |
| 3 | Adresi doğrulanmamış ikincil e-posta olarak tutan hesapla kabul | GitLab konusu |
| 4 | Belirtecin kullanımdan, iptalden ya da yeniden adlandırmadan sonra geçersiz kılınmaması | HackerOne'ın kendi program raporları |
| 5 | Davet yükünü kurcalayarak rol yükseltme | Dropbox raporu ile Budibase açığı |
| 6 | Kabul adımının tamamen atlanması ile kurbanın zorla eklenmesi | Slack raporu |
| 7 | Davet edilen adresin davet edene ya da diğer üyelere ifşası | HackerOne raporları |
| 8 | Davet edilen adreste harf büyüklüğü ile Unicode normalizasyon ayrışması | GitLab konuları |
| 9 | Sonradan el değiştiren bir adrese davet | Truffle Security ile npm süresi dolmuş alan adı araştırması |
| 10 | Zehirli kiracı: saldırgan kurbanın şirket adıyla kiracı açmakta ile sizin meşru davet e-postanızı bir kimlik avı taşıyıcısı yapmaktadır | 48. kısım |

---

### 45. Alan adı doğrulaması, otomatik katılım ile alan adı ele geçirme

#### 45.1 Büyükler nasıl yapmaktadır

| Ürün | Yöntem | Detay |
|---|---|---|
| Microsoft Entra kimlik | DNS metin kaydı | Grafik doğrulama çağrısı kullanılmakta ile en az ayrıcalıklı rol alan adı yöneticisidir |
| Slack | DNS metin kaydı | Normal alan adı için kök, joker için özel bir ana bilgisayar kullanılmakta ile 72 saate kadar etkili olma süresi bulunmaktadır |
| Atlassian | Üç yöntem: alan adı kökünde HTTPS dosyası, DNS metin kaydı ya da kimlik sağlayıcı bağlantısı | Açıkça belirtilmektedir: bir tüketici alan adının sahipliği doğrulanamamaktadır. Alt alan adları ayrı ayrı doğrulanmalıdır. Atlassian, doğrulamanın bir yöntem bozulunca hayatta kalması için birden çok yöntem önermektedir |
| Google Workspace | Kayıt şirketinde DNS kayıtları | Deneme ya da sözleşme başlangıcından itibaren dokuz gün içinde doğrulanmalıdır, yoksa hesap kayıttan 21 gün içinde otomatik silinmektedir. Gerekçe açıktır: başka birinin sizin alan adınızı kullanarak kaydolması istenmemektedir |
| Notion | DNS kaydı | Kayıt değişikliği dakikalar sürmekte ancak 72 saate kadar uzayabilmektedir; doğrulama kodları bir haftada sona ermektedir. Doğrulama, SAML çoklu oturum açmayı ile çalışma alanı oluşturma kontrolünü açmaktadır; doğrulamadan sonra varsayılan olarak yalnızca çalışma alanı sahipleri o alan adında çalışma alanı oluşturabilmektedir. Kurumsal sahipler doğrulanmış bir alan adında oluşturulan çalışma alanlarını görüntüleyebilmekte, talep edebilmekte, devredebilmekte ya da silebilmektedir; ancak yalnızca ilk doğrulamadan sonraki 14 günlük bekleme süresinin ardından |

#### 45.2 Otomatik katılım riski

Notion'ın kendi rehberliği riskin en temiz ifadesidir: izin verilen bir e-posta alan adı olması, o alan adındaki herkesin çalışma alanına katılmasına izin vermekte ile bu, kimlik sağlayıcılardaki üyelikle Notion'daki üyelik arasında bir uyumsuzluk yaratabilmektedir. Notion tüm izinli e-posta alan adlarının kaldırılmasını ile erişimin yalnızca çoklu oturum açma üzerinden yönetilmesini önermektedir.

Tüketici ile paylaşılan alan adları konusunda Atlassian açık alan adlarının doğrulanmasını doğrudan engellemekte ile Stytch yaygın alan adlarını izin listesinden çıkarmaktadır. Türkiye pazarı için tasarım, ulusal ücretsiz posta alan adlarını da tüketici alan adı saymalıdır; daha önemlisi, tek bir kayıtlı alan adının binlerce ilgisiz insanı kapsadığı internet servis sağlayıcı adreslerini ile üniversite alt alan adlarını da saymalıdır.

Alt alan adı ele geçirme bir başka risktir: doğrulama, sarkan bir alt alan adından ya da kök dışındaki bir konumdan sunulan bir belirteci kabul ediyorsa, bir alt alan adı ele geçirmesi bir alan adı doğrulama atlatmasına dönüşmektedir.

Süresi dolmuş alan adları konusunda kural şudur: doğrulama, kaydın kendisi kadar dayanıklıdır. Ele geçirme literatüründen gelen rehberlik, hizmetten çıkardıktan sonra bile doğrulama kaydının yerinde tutulması ile doğrulamanın kalıcı sayılmak yerine periyodik olarak yeniden yapılmasıdır.

#### 45.3 Yönetilmeyen hesaplar, alan adı talebi ile yönetici devralma

Microsoft Entra kimlikte kendin kaydol ile yönetilmeyen kiracılar şöyle çalışmaktadır: bir kendin kaydol işlemi, e-posta alan adından türetilen yönetilmeyen bir kiracıda, yani küresel yöneticisi olmayan bir kiracıda, e-postası doğrulanmış bir kullanıcı yaratmaktadır. İki kontrol vardır ile ikisi de kiracı genelindedir: e-postası doğrulanmış kullanıcıların organizasyona katılmasına izin verme ile e-posta tabanlı aboneliklere kaydolmaya izin verme. İkisini de kapatmak sertleştirme duruşudur.

Yönetilmeyen bir dizinin yönetici devralması iki biçimdedir. İç devralmada yönetilmeyen kiracıda bir kullanıcı bağlamı elde edilmekte, yönetici devralma sayfasına gidilmekte, yönetici olmak istiyorum seçilmekte, DNS metin kaydı eklenmekte ile o kiracının küresel yöneticisi olunmaktadır. Dış devralmada zaten yönetilen bir kiracıdan alan adı eklenip doğrulanmakta ile Entra alan adını yönetilmeyen organizasyondan kaldırıp mevcut organizasyonunuza taşımakta, kullanıcıları, abonelikleri ile lisans atamalarını da almaktadır. Grafik doğrulama API'sinde zorla devralma bayrağı gerekmektedir; standart komut bunu açığa çıkarmamaktadır. Başarılı bir dış devralmadan 10 gün sonra yönetilmeyen organizasyon silinmektedir.

Tasarım dersi şudur: DNS'i kontrol eden, bir gölge kiracıyı sahip olunan bir kiracıya çevirebilmekte ile kullanıcılarını miras alabilmektedir. DNS güven kökündedir.

Google Workspace tarafında çakışan hesaplar ile transfer aracı, Şubat 2017'den beri şöyle çalışmaktadır: yönetilmeyen hesap, alan adınızda bağımsız oluşturulmuş kişisel bir Google hesabıdır. Seçenekler bir transfer talebi göndermek, ki kullanıcı kabul etmelidir ve sonrasında yönetici veriyi ve yönetimi kazanmaktadır, ya da kullanıcıyı yeniden adlandırmaya zorlamaktır. Rıza asimetrisine dikkat edilmelidir: Google transferi kullanıcının kabul etmesini gerektirmekte, Microsoft'un dış devralması kullanıcı başına rıza gerektirmemekte ile yalnızca DNS kontrolü istemektedir.

#### 45.4 Gerçek olaylar ile araştırmalar

Obsidian Security'nin DNS devralmasından organizasyon yöneticiliğine başlıklı Atlassian bulut çalışması şu zinciri anlatmaktadır: DNS ele geçirilmekte, alan adı Atlassian'da doğrulanmakta, hesaplar talep edilmekte, ki yönetici hesapları dahildir, uygulama keşfi yapılmakta, yönetici olarak katıl seçeneği kullanılmakta ile kaldırılmadan sağ çıkan kalıcı bir organizasyon yöneticiliği elde edilmektedir. İstatistikleri şunlardır: analiz edilen müşteriler arasında %20'sinin talep edilmemiş organizasyon yöneticisi ile %28'inin talep edilmemiş site yöneticisi bulunmaktadır. Birden çok organizasyon aynı alan adını doğrulayabilmekte ile bu, talep etmede bir yarış koşulu yaratmaktadır; otomatik talep açık olsa bile saldırgan pencerede elle talep edebilmektedir. Önerileri tüm alan adlarının doğrulanması, tüm hesapların özellikle yöneticilerin talep edilmesi, her olaydan sonra DNS'in denetlenmesi ile yönetici olarak katılma olaylarına alarm konulmasıdır; bu nadir bir olay olarak tanımlanmaktadır. Yayın tarihi doğrulanmamıştır.

nOAuth'un mekanizması ile zaman çizelgesi 13.1'dedir. İşletmeler arası açıdan kritik ek şudur: Semperis'in 2025 çalışması 1.017 OIDC tümleşimini incelemiş, Entra uygulama galerisindeki 104 kendin kaydol uygulamasına odaklanmış ile dokuzunu, yani yaklaşık %9'unu zafiyetli bulmuştur; hem de açıklamadan iki yıl sonra. Güvenlik yanıt merkezine Aralık 2024'te bildirilmiş ile merkez vakayı Nisan 2025'te kapatmıştır. The Hacker News'in 25 Haziran 2025 tarihli haberine göre Microsoft geliştiricilerin özne ile veren üzerinden anahtarlaması gerektiğini yinelemiş ile uyumsuz satıcıların galeriden çıkarılma riski taşıdığını uyarmıştır. Semperis'ten Eric Woodruff şunu söylemektedir: düşük çabalıdır, neredeyse hiç iz bırakmamaktadır ile son kullanıcı korumalarını atlamaktadır.

Microsoft'un otoriter iddia rehberliği birebir şudur.

> *"Never use claims like `email`, `preferred_username` or `unique_name` to store or determine whether the user in an access token should have access to data. These claims aren't unique and can be controllable by tenant administrators or sometimes users, which make them unsuitable for authorization decisions. They're only usable for display purposes. Also don't use the `upn` claim for authorization."*

Doğrulanması gerekenler izleyici kitle ile kiracı kimliğidir; anahtarlanması gerekenler değişmez kiracı ile nesne kimliğidir, ya da özne tanımlayıcısıdır.

Truffle Security'den Dylan Ayrey'in Google ile giriş ve terk edilmiş girişim alan adları çalışmasının zaman çizelgesi şudur: Google'a bildirim 30 Eylül 2024, Google'ın düzeltilmeyecek işareti 2 Ekim 2024, ShmooCon 2025 konuşmasının kabulü 9 Aralık 2024 ile Google'ın bileti yeniden açıp 1.337 dolar ödemesi 19 Aralık 2024'tür. Mekanizma şudur: bağlı taraflar barındırılan alan adı ile e-posta üzerinden anahtarlamaktadır; iflas etmiş bir girişimin alan adını satın alıp Workspace kullanıcılarını yeniden yaratmak o iddiaları birebir yeniden üretmektedir. Ayrıca değişmez tanımlayıcı olması gereken özne iddiası güvenilmez olarak raporlanmaktadır: büyük bir sağlayıcının mühendisine göre özne iddiası girişlerin yaklaşık binde dördünde değişmektedir, bu yüzden bağlı taraflar ondan kaçınmaktadır. Bu, özne üzerinden anahtarla tavsiyesine karşı ciddi ile nadiren dile getirilen bir itirazdır. Ölçek şöyledir: girişimlerin yaklaşık %90'ı başarısız olmakta, yaklaşık yarısı Google Workspace kullanmakta ile yüz binden fazla iflas etmiş girişim alan adı satın alınabilir durumdadır; TechCrunch'ın 19 Ocak 2025 haberine göre 116.000'dir. Tahminen 10 milyondan fazla bulut hesabı potansiyel olarak ele geçirilebilirdir. Ayrey'in adlandırdığı en yüksek etkili hedefler, eski çalışanların vergi belgelerini, sosyal güvenlik numaralarını ile banka bilgilerini açığa çıkaran insan kaynakları sistemleridir; ayrıca Slack, ChatGPT, Zoom ile Notion'dır.

npm süresi dolmuş alan adı araştırması aynı başarısızlık modunu ölçekte göstermektedir. Kuzey Karolina Eyalet Üniversitesi ile Microsoft ortak çalışmasına göre 2.818 bakımcı hesabı süresi dolmuş alan adlarındaki e-posta adreslerini kullanmakta ile 8.494 paketi kontrol etmekteydi; paket başına ortalama 2,43 doğrudan bağımlı bulunmaktadır. Saldırgan alan adını satın almakta, posta kutusunu yeniden yaratmakta, parola sıfırlamayı tetiklemekte ile paketlere sahip olmaktadır.

Bir dürüstlük notu gerekmektedir: doğrulanmış bir alan adında otomatik katılımın vahşi doğada suistimal edildiğine dair yayımlanmış ile teyit edilmiş bir olay bulunamamıştır. En yakın gerçek kanıt yukarıdaki Atlassian çalışması ile alan adı yeniden edinme sınıfıdır. Tasarım dokümanında bu dürüstçe belirtilmeli ile bir olay uydurulmamalıdır.

---

### 46. Sahiplik devri ile son yönetici koruması

#### 46.1 Ürün politikaları

GitHub her organizasyonda en az iki kişinin sahip rolüne sahip olmasını önermektedir. Devir bir yükselt sonra indir ya da ayrıl dizisidir; GitHub son sahibin ayrılmasını engellemektedir. Sahipler kendi rollerini değiştirememektedir. Temiz bir değişmez şudur: kendin yap kendini yükseltme yoktur ile kendin yap son sahip çıkışı yoktur. Kendini kaldırmak faturalandırmayı güncellememektedir; faturalandırmayla sahipliğin ayrışması gerçek bir operasyonel tuzaktır.

Vercel'de bir takım sahipsiz kalamamaktadır; iki adımlı bir süreç vardır, yani yeni sahip yükseltilmekte ile eskisi indirilmekte ya da kaldırılmaktadır. Profesyonel deneme takımları tek sahiple sınırlıdır ile deneme sırasında sahip değişiklikleri engellenmektedir.

Microsoft Entra kimlik, acil erişim dokümanında şunu söylemektedir: son küresel yönetici hesabının silinmesi engellenmekte ancak hesabın şirket içinde silinmesi ya da devre dışı bırakılması engellenmemektedir. Önemli nüans şudur: son yönetici değişmezi bulut dizininde zorlanmakta ancak senkronize edilen doğruluk kaynağı üzerinden yenilebilmektedir. Ayrıca şu işaretlenmektedir: tüm küresel yönetici ile ayrıcalıklı rol yöneticisi atamaları yalnızca uygun statüsündeyse, aktivasyon onay gerektiriyorsa ile onaylayıcı yoksa, kiracı yönetimi fiilen kilitlenmektedir.

Google Workspace'te kaybedilmiş tek süper yönetici için kurtarma yolları kurtarma e-postası ya da telefonu, yoksa bir DNS kaydı ekleyerek alan adı doğrulaması, yoksa destek destekli kurtarmadır; yayılma 24 saate kadar sürebilmektedir. Dikkat çekici bir ifade vardır: yöneticiler atıl ile yanıt vermiyorsa Google kullanıcı hesabınızı yükseltmektedir. Belgelenmiş bir DNS kontrolü mevcut yöneticiyi yener yükseltme yoludur.

Stripe'ta sahiplik mevcut bir süper yönetici ya da yöneticiye devrolmaktadır. Bağlantı ürünü için tam panoda yalnızca mevcut sahip devredebilmekte; sahip ulaşılamazsa destek müdahale etmelidir. Basitleştirilmiş panoda platform yöneticisi sahibi değiştirebilmektedir. Stripe hem eski hem yeni sahibin iş bilgilerinin ile kimliklerinin doğrulanmasını ile yeni sahibin yetkilendirmesinin belgelenmesini şart koşmaktadır. Yargı yetkisine özgü bir kural örneği vardır: Brezilya'daki bireysel ile şahıs şirketi hesaplarında sahiplik devri yasaktır. Türkiye ile KVKK muadili kontrol edilmelidir.

#### 46.2 Argus için tasarım kuralları

| Sıra | Kural | Kaynak |
|---|---|---|
| 1 | Bir organizasyonun daima en az bir aktif sahibi olmalıdır. Bu veri katmanında zorlanmalıdır, yalnızca arayüzde değil, ile her yolda geçerli olmalıdır: indirme, kaldırma, ayrılma, hesap silme, SCIM sağlama kaldırma, çoklu oturum açma zorlama süpürmesi ile faturalandırma iptali | GitHub ile Vercel |
| 2 | İki taraflı teyit gerekmektedir: devir bir teklif artı kabuldür. Alıcı zaten doğrulanmış ile zaten aktif bir üye olmalıdır. Devir asla ayrılan sahibin tek tıkı olmamalıdır | Stripe ile GitHub |
| 3 | Soğuma ile bildirim gerekmektedir: teklifte, kabulde ile tamamlanmada tüm sahiplere, yöneticilere ile organizasyonun güvenlik irtibatına bildirilmeli ile bir geri alma penceresi tutulmalıdır | Notion'ın 14 günü ile Microsoft'un 10 günü |
| 4 | Kendi rolünü değiştirme yasaktır; bir sahip kendi rolünü değiştirememeli ile ikinci bir sahip hareket etmelidir | GitHub |
| 5 | Sahiplik faturalandırmadan açıkça ayrılmalıdır | GitHub'ın belgelenmiş tuzağı |
| 6 | Vefat eden ya da ayrılan tek sahip durumunda incelenen her satıcı bant dışı kimlik kanıtına düşmektedir ile Google ve Microsoft'ta o kanıt DNS kontrolüdür. Kimlik sağlayıcının doğrulanmış alan adları varsa DNS kontrolü zaten en güçlü bant dışı sinyalidir; kurtarma yolu bilinçli olarak onun etrafında tasarlanmalı ile gürültülü şekilde denetlenebilir yapılmalıdır, çünkü aynı zamanda saldırı yoludur | Obsidian ile Atlassian araştırması |

---

### 47. Acil durum erişimi hesabı tasarımı

#### 47.1 Microsoft Entra kimlik, otoriter kontrol listesi

Yedeklilik için en az iki acil erişim hesabı bulunmalıdır.

Hesaplar varsayılan bulut alan adında yalnızca bulut hesapları olmalıdır; federe olmamalı ile şirket içinden senkronize edilmemelidir.

Kimlik avına dirençli yöntemler kullanılmalıdır; geçiş anahtarı önerilmektedir ya da açık anahtar altyapısı varsa sertifika tabanlı kimlik doğrulama kullanılmalıdır. Bunlar normal yönetici hesaplarının kullandığı yöntemlerden farklı olmalıdır; yöneticiler bir kimlik doğrulama uygulaması kullanıyorsa acil erişim FIDO2 kullanmalıdır. Microsoft'un güncel rehberliği çok faktörlüden muaf tut değildir; zorunlu çok faktörlüyü karşılayan kimlik avına dirençli bir yöntem kullan ile yalnızca girişi engelleyecek koşullu erişim politikalarından muaf tut şeklindedir.

Kimlik bilgileri ile cihazlar sona ermemeli ya da hareketsizlik temizliğine takılmamalıdır.

Ayrıcalıklı kimlik yönetiminde küresel yönetici rolü kalıcı aktif atanmalıdır, yalnızca uygun değil.

Belirlenmiş bir güvenli iş istasyonu ya da ayrıcalıklı erişim iş istasyonu kullanılmalıdır.

Kimlik bilgileri ayrı konumlarda, ayrı ile yangına dayanıklı kasalarda saklanmalı, yalnızca yetkili kişilerce bilinmeli ile hiçbir bireysel kullanıcıya veya çalışan tedarikli cihaza bağlı olmamalıdır.

Girişi engelleyen ya da kısıtlayan koşullu erişim politikalarından muaf tutulmalıdır; yalnızca rapor modundaki politikalar muafiyet gerektirmemektedir. Adanmış bir grup kullanılmalı, üç ayda bir hâlâ giriş yapabildikleri test edilmeli ile kesinti sırasında etkinleştirilecek acil durum politikaları hazırlanmalıdır.

Tüm giriş ile denetim etkinliği izlenmeli ile her kullanımda alarm verilmelidir; alarm önem derecesi kritiktir.

En az 90 günde bir doğrulanmalı, ayrıca bilgi teknolojileri personeli değişikliklerinden, işten çıkarmalardan ile abonelik değişikliklerinden sonra tekrarlanmalıdır. Tatbikat şunları içermelidir: güvenlik operasyon merkezi bilgilendirilmeli; yetkili kullanıcı listesi gözden geçirilmeli; başucu kitabının güncel olduğu teyit edilmeli; hiçbir çok faktörlü yöntemin ya da kendin yap parola sıfırlamanın bireyin cihazına veya kişisel bilgilerine kayıtlı olmadığı doğrulanmalı; paylaşılan cihazın ortak arıza modu olmayan iki yoldan ağa ulaşabildiği doğrulanmalı; ile kasa kombinasyonları düzenli olarak ve erişimi olan biri ayrıldığında değiştirilmelidir.

Her alarmdan sonra bir inceleme ekibi günlükleri korumalı ile kullanımı sınıflandırmalıdır: planlı tatbikat, gerçek acil durum ya da suistimal ve yetkisiz kullanım.

Federasyon rehberliği şudur: şirket içi acil erişim ile bulut acil erişimi tamamen bağımsız tutulmalı ile çapraz bağımlılık olmamalıdır.

Dokümanın kendi neden listesi, kilitlenme nedenlerinin iyi bir sayımıdır: federasyon ya da kimlik sağlayıcı kesintisi; tüm yönetici çok faktörlü cihazlarının veya servisinin erişilemez olması; son küresel yöneticinin ayrılması; doğal afet ya da ağ kesintisi; ile ayrıcalıklı kimlik yönetimi tuzağı, yani tüm atamaların yalnızca uygun olması, onay gerekmesi ile onaylayıcı bulunmaması.

#### 47.2 Okta

Acil durum süper yönetici hesapları IP izin listesi, fiziksel bir FIDO2 anahtarı artı makine üretimi bir parolayla çok faktörlü kimlik doğrulama kullanmalı ile her kullanım için yakından izlenmelidir.

Daha geniş yönetici rehberliği şunlardır: sıfır kalıcı ayrıcalık ile tam zamanında yönetici erişimi; özel yönetici rolleri; kimlik avına dirençli kimlik doğrulayıcılar; güvenilir yönetilen cihazlar; anonimleştirici vekilleri engelleyen dinamik ağ bölgeleri; yönetim konsolu oturumunun varsayılan 12 saatlik ömrü ile 15 dakikalık boşta kalma zaman aşımı; varsayılan açık olan otonom sistem numarası oturum bağlaması, ki ağ değişirse oturumu iptal etmektedir; isteğe bağlı IP oturum bağlaması; ile kritik değişiklikler için yeniden kimlik doğrulama gerektiren korumalı eylemler. Okta'nın yönetici dayanıklılığı önerisi, yöneticilere yönetim konsolu için birden çok yedekli kimlik doğrulayıcı vermektir.

#### 47.3 CISA ile CIS

CISA'nın bulut güvenliği temel yapılandırma değerlendirme araçları, acil erişim hesaplarının politika muafiyeti olarak açıkça sayılmasını gerektirmektedir; yani acil erişim muafiyetleri örtük değil beyan edilmiş ile denetlenebilir olmalıdır.

CIS Microsoft 365 temel karşılaştırmasının 1.1.2 numaralı kontrolü, iki acil erişim hesabının tanımlanmasını gerektirmektedir; üçüncü ile dördüncü ana sürümlerde birinci seviyededir. İki acil durum hesabı için en temiz atıf verilebilir uyum gereksinimidir.

NCSC'nin acil durum erişimi ya da acil yönetici hesaplarına özgü bir sayfası bulunamamıştır. Doğrulanan en yakın NCSC materyali güvenli sistem yönetimi koleksiyonudur; dördüncü ilkesi kimlerin, nerede, ne zaman, neden ile nasıl sistem yönetimi yaptığının dikkatle kontrol edilmesini istemekte ile birilerinin bir yerde sisteminiz üzerinde mutlak kontrole sahip olacağını belirtmektedir. Daha spesifik bir NCSC önerisi doğrulanmamıştır ile atıf verilmemelidir.

#### 47.4 AWS kök kullanıcısı, yeter sayı ile bölünmüş bilgi fikrinin en zengin kaynağı

Çok faktörlü kimlik doğrulama zorunludur: bağımsız, yönetim ile üye hesaplarının hepsi kök çok faktörlü doğrulama gerektirmektedir ile ilk konsol giriş denemesinden itibaren 35 gün içinde kayıt yapılmalıdır. Sekize kadar cihaz kaydedilebilmektedir; dayanıklılık için birkaçı kaydedilmelidir.

Asla kök erişim anahtarı oluşturulmamalıdır; programatik kök kullanımı için geçici ile otomatik döndürülen kimlik bilgileri veren giriş komutu kullanılmalıdır.

Çok kişili onay birebir şöyle anlatılmaktadır: *"Consider using multi-person approval to make sure that no one person can access both MFA and password for the root user. Some companies… set up one group of administrators with access to the password, and another group with access to MFA. One member from each group must come together to sign in as the root user."*

Kök için bir grup e-posta adresi kullanılmalıdır; işletmece yönetilmeli, bir gruba yönlendirmeli ile başka hiçbir şey için kullanılmamalıdır.

Kurtarma ayrımı birebir şudur: *"No one person should have access to both the email inbox and phone number since both are verification channels to recover your root user password."*

Kök parolası, kendisi o hesaba bağımlı olan bir araçta saklanmamalıdır; dairesel bağımlılık tuzağıdır.

Organizasyonlar ürününde kök erişimi merkezî yönetilmeli ile üye hesaplardan kök kimlik bilgileri tamamen kaldırılmalıdır; yalnızca köke özgü eylemler dışındaki kök eylemlerini reddeden bir hizmet kontrol politikası kullanılmalıdır.

İzlemede kök girişi ile kullanımında alarm verilmelidir; olay kaydı, kök girişini ayrıcalıklı kök oturumundan ayırmaktadır. Alarm için belgelenmiş bir müdahale prosedürü olmalıdır, yalnızca alarm değil.

#### 47.5 Temel gerilim ile kaynakların çözümü

Gerilim gerçektir: acil durum erişimi hesabı en yüksek ayrıcalıklı kimliktir ile her şeyi koruyan kontrollerden kasten muaf tutulmaktadır. Kaynakların yakınsadığı çözüm muafiyet değil ikame güç, yeter sayı, tespit ile tatbikattır.

1. Faktör kaldırılmamalı, daha güçlüsü ikame edilmelidir. Microsoft artık FIDO2 ya da sertifika tabanlı doğrulama reçete etmekte ile yalnızca engelleyici politikalardan muaf tutmaktadır; Okta fiziksel FIDO2, makine üretimi parola ile IP izin listesi reçete etmektedir.
2. Bağımlılıklar çeşitlendirilmelidir: normal yöneticilerden farklı kimlik doğrulama yöntemi, yalnızca bulut, federasyon yok, şirket içi yok, kişisel telefon yok ile tek ağ yolu yok.
3. Yeter sayı ile bölünmüş bilgi uygulanmalıdır: AWS'in iki grup parola ve çok faktörlü ayrımı; ayrı konumlarda ayrı yangına dayanıklı kasalar.
4. Tespit, önlemenin yerini almalıdır: her girişte en yüksek önem derecesinde alarm, her kullanımı tatbikat, acil durum ya da suistimal olarak sınıflandıran zorunlu bir inceleme.
5. Zaman kutulama ile tatbikat yapılmalıdır: 90 günlük doğrulama tatbikatları, üç aylık muafiyet testleri ile personel ayrılışında kasa kombinasyonu rotasyonu.
6. Muafiyetler beyan edilmelidir: CISA değerlendirme araçları acil erişim muafiyetlerinin değerlendirme yapılandırmasında sayılmasını zorlamakta, böylece muafiyetin kendisi denetlenebilir olmaktadır.

Ödünç alınmaya değer ürün seviyesi analog Stytch'in acil erişim üye bayrağıdır. Bu bayrağı taşıyan bir üye, organizasyonun kısıtlı kimlik doğrulama ile çok faktörlü yöntem ayarlarını atlamaktadır. Bayrağı ayarlamanın kendisi yetkilendirilmiş bir eylemdir. Bu, bir işletmeler arası kimlik sağlayıcıda acil erişimin birinci sınıf, izinli ile denetlenebilir bir nesne olmasının en temiz mevcut örneğidir ile Argus için güçlü bir referanstır.

Acil erişim kimlik bilgilerinin adı geçen bir kamu ihlalinde suistimal edildiğine dair doğrulanmış bir olay bulunamamıştır; iddia edilmemelidir. Sık dolaşan kilitlenme hikâyeleri için birincil kaynak bulunamamıştır; ya çıkarılmalı ya da açıkça teyit edilmemiş olarak etiketlenmelidir.

---

### 48. Organizasyon seviyesi çoklu oturum açma zorlaması, atlatma ile SAML ele geçirme

#### 48.1 Artık parola problemi

Obsidian'ın araştırmasından temel risk ifadesi şudur: bulut uygulamalarının %90'ından fazlasında organizasyonun çoklu oturum açma yapılandırması kullanıcı adı ile parola girişinin yanında isteğe bağlıdır ile birçok uygulamada çoklu oturum açmanın zorunlu olup olmadığı küresel değil kullanıcı başına yapılandırılmaktadır. Kendi ifadesiyle: bir uygulama kullanıcının kurumsal çoklu oturum açmayı atlayarak yerel bir parolayla girmesine izin veriyorsa, o uygulama çevrenizde bir deliktir. %90 rakamı Obsidian'ın kendi araştırmasıdır ile bağımsız bir istatistik değildir.

GitHub'ın zorlama davranışı şudur: zorlama, kimlik sağlayıcı üzerinden kimlik doğrulamamış tüm üyeleri ile yöneticileri organizasyondan kaldırmakta ile her kaldırılan kullanıcıya bir e-posta bildirimi göndermektedir. Kaldırılan üyeler üç ay içinde yeniden katılabilmekte ile erişimleri geri gelmektedir. Kimlik sağlayıcıda dış kimliği olmayan botlar ile servis hesapları da kaldırılmaktadır; klasik bir zorlama günü kesintisidir. GitHub zorlamadan önce kimlerin kaldırılacağını listeleyen bir uyarı göstermekte ile açık teyit istemektedir. Zorlamanın bekleyen davetlere ile mevcut kişisel erişim token'larına ve SSH anahtarlarına ne yaptığı o dokümanda belirtilmemektedir ile doğrulanmamıştır. Ancak gerçek bir tarihsel atlatma vardır: GitHub 15 Eylül 2022'de, değişiklik günlüğü 2 Kasım 2022'de, SAML çoklu oturum açma için yetkilendirilmemiş OAuth ile kişisel erişim token'larının SAML korumalı organizasyonlardan konu verisini, yani başlık, gövde, etiket ile atanan bilgilerini okuyabildiği bir hatayı düzeltmiştir. GitHub Enterprise Server'da şifreli doğrulamalarla uygunsuz kriptografik imza doğrulaması yoluyla bir SAML kimlik doğrulama atlatması CVE-2024-4985 ile CVE-2024-9487 numaralarıyla açıklanmıştır.

Stytch zorlamayı organizasyon ayarları olarak modellemektedir: kimlik doğrulama yöntemleri tümü izinli ya da kısıtlı olabilmekte, izinli yöntemler listesi verilebilmekte ile çok faktörlü politika herkes için zorunlu ya da isteğe bağlı olabilmektedir. İzinli yöntemler yalnızca çoklu oturum açma olarak ayarlanırsa bu bir organizasyon geneli zorlamadır ile acil erişim bayrağı belgelenmiş, izinli bir istisnadır.

Auth0 organizasyonları çoklu oturum açmayı, organizasyon için hangi bağlantıların etkin olduğunu kontrol ederek zorlamaktadır. Bilinmesi gereken sınırlamalar şunlardır: yalnızca evrensel giriş desteklenmektedir; kaynak sahibi parola akışı, cihaz yetkilendirme akışı ya da WS-Federation ile desteklenmemektedir; ile organizasyon başına özel giriş alan adı yoktur.

WorkOS organizasyon kimliği üzerinden yönlendirmekte ile e-posta alan adı tabanlı doğrulamanın güvensiz olduğunu açıkça uyarmaktadır; çoklu oturum açma yetkilendirme kodu 10 dakika geçerlidir.

Belirtilmesi gereken tasarım değişmezleri şunlardır. Zorlama organizasyon seviyesinde bir özellik olmalıdır, kullanıcı başına değil. Mevcut kimlik bilgilerini süpürmelidir, yani parolaları, API token'larını, SSH anahtarlarını, uzun ömürlü oturumları ile OAuth yetkilerini; yalnızca gelecekteki girişleri değil. Açık, izinli ile alarmlı bir acil erişim istisnası olmalıdır. Zorlama anında bekleyen davetlere ne olacağı tanımlanmalıdır; GitHub'ın dokümanı bunu belirsiz bırakmaktadır, Argus'unki bırakmamalıdır.

#### 48.2 SAML ele geçirme ile zehirli kiracı

Push Security'nin 17 Ağustos 2023 tarihli çalışmasına göre iki teknik vardır.

SAML ele geçirmede, bir bulut kiracısını kontrol eden saldırgan o kiracının SAML çoklu oturum açma ayarlarını saldırgan kontrollü bir kimlik sağlayıcıyı gösterecek şekilde ayarlamaktadır. O kiracı üzerinden giriş yapan kullanıcılar meşru bir bulut adresinden, tam da kimlik bilgisi girmeyi bekledikleri anda bir kimlik avı sayfasına yönlendirilmektedir.

Zehirli kiracıda saldırgan gerçek bir bulut ürününde hedef şirketin adıyla bir kiracı kaydetmekte ile ürünün kendi davet işlevini kullanarak çalışanlara meşru görünen davetler yollamaktadır; uygulama sizin adınıza gerçek davet e-postaları göndermektedir.

Birçok bulut ürünü ücretsiz denemelerde ile düşük katmanlarda bile özel SAML'a izin vermektedir; kombinasyonu ucuz kılan da budur.

Vahşi doğada canlı bir örnek Push Security'nin 26 Haziran 2026 tarihli OpenAI zehirli kiracı saldırısı incelemesidir. Push çalışanları, OpenAI'nin meşru bildirim adresinden, kimlik doğrulama kontrollerini geçen ile şirketin kendi adını taşıyan bir organizasyona katılma davetleri almıştır. Saldırganın hesabı şirketin genel müdürünün adını kullanmakta, faturalandırmaya çalınmış bir kart ekli bulunmakta ile belirli çalışanları hedeflemekteydi. Kabul, ek kimlik bilgisi olmadan tek bir tık gerektirmekte ile davet edilen çalışanlara sahte organizasyonda sahip seviyesinde yönetici erişimi verilmekteydi. OpenAI'nin ürünü davet edenle alıcı arasındaki alan adı uyuşmazlığı için tek satırlık bir uyarı göstermekteydi; araştırmacılar bunu yetersiz bulmuştur.

Davet akışı için doğrudan tasarım sonuçları şunlardır. Davet edenin doğrulanmış alan adı davet edilenden farklıysa güçlü ile kaçırılamaz bir ara sayfa gösterilmelidir. İlişkisiz bir kullanıcının ilk kabulünde asla sahip ya da yönetici yetkisi verilmemelidir. Kiracı oluşturma ile toplu davet örüntüleri hız sınırlanmalı ile itibar kontrolünden geçirilmelidir. Kendi işlemsel davet postanız saldırgan kontrollü bir kimlik avı kanalı sayılmalı ile saldırganın sağladığı alanlar, yani organizasyon adı, davet edenin görünen adı ile özel mesaj, buna göre kısıtlanmalıdır.

#### 48.3 SCIM ile organizasyon davetleri

Tam zamanında ya da otomatik oluşturma ile SCIM aynı anda çalıştırılmamalıdır. OpenAI'nin SCIM sıkça sorulan soruları, otomatik hesap oluşturmayla SCIM'in birlikte etkinleştirilmemesini önermektedir, çünkü bu yönetilmeyen kullanıcılara erişim sağlanmasıyla sonuçlanabilmektedir.

Yinelenen ya da paralel kayıtlar konusunda kural şudur: kararlı ile paylaşılan bir tanımlayıcı olmadan tam zamanında oluşturmayla SCIM itmesi paralel kullanıcı kayıtları üretmekte, bu da yetkilendirme çakışmalarına ile bozuk denetim izlerine yol açmaktadır. SCIM oluşturmada çakışma yanıtı genelde bir yinelenen kullanıcı problemidir; kimlik sağlayıcı kayıt kimlikleri gönderirken e-postayı SCIM kimliği olarak kullanmak güncelleme ile silmede bulunamadı hatalarına yol açmaktadır.

SCIM ile oluşturulmuş kullanıcılar ile davet e-postası konusunda bir sorun vardır: bazı ürünler, henüz çalışma alanı üyesi olmayan bir kullanıcıyı SCIM ile sağladığında hâlâ davet e-postası göndermektedir. SCIM ile davetler birbirini dışlayan yollar değildir ile ikisi de aynı üyelik kaydında birleşmelidir.

Sağlama kaldırma eksiksiz olmalıdır: arayüz girişini devre dışı bırakmak yetmemektedir. API token'ları, oturumlar ile gruptan türeyen izinler iptal edilmelidir. Birçok platform denetim günlüklerini korumak için yumuşak silme yapmaktadır; yumuşak silmenin canlı bir kimlik doğrulama yolu bırakmadığından emin olunmalıdır.

Belirtilecek tasarım kuralları şunlardır.

1. SCIM etkinken üyelik için otoriterdir; o organizasyon için davetler devre dışı bırakılmalı ya da bir erişim talebine indirgenmelidir.
2. Her üyelik kaydı bir dış kimlik ile bir kaynak alanı taşımalıdır, yani davet, SCIM, tam zamanında ya da alan adı otomatik katılımı; böylece köken denetlenebilir olmaktadır.
3. Gelen bir SCIM kullanıcısını mevcut davet edilmiş ancak kabul edilmemiş bir kayıtla eşleştirmek doğrulanmış bir tanımlayıcı üzerinden olmalıdır; asla doğrulanmamış ikincil e-posta üzerinden olmamalıdır, ki GitLab dersi burada birebir geçerlidir.
4. SCIM sağlama kaldırma, o kişi için bekleyen davetleri de iptal etmelidir.

---

### 49. Yedinci bölüm için Argus kararları

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

| Sıra | Karar | Kaynak |
|---|---|---|
| 1 | Davet opak bir belirteçtir, bir veritabanı satırıdır ile SHA-256 özetlidir; JWT değildir | Tüm satıcılar artı iptal argümanı |
| 2 | Rol satırdan okunmaktadır, istekten asla | Dropbox ile Budibase açıkları |
| 3 | Kabul anında rol atama yetkisi yeniden kontrol edilmektedir; davet oluşturmada da kontrol edilmektedir | Budibase API'yi doğrulamamaktaydı |
| 4 | Davet edilen adres Unicode normalizasyonu ile küçük harfe çevrilmektedir | GitLab konuları |
| 5 | Kabul yalnızca doğrulanmış bir tanımlayıcıyla eşleşmektedir; doğrulanmamış ikincil e-posta asla kullanılmamaktadır | GitLab konusu |
| 6 | Bağlama modu tüketici alan adlarında tam eşleşmedir; kurumsal gevşetme yalnızca alan adı doğrulanmışsa geçerlidir | WorkOS |
| 7 | Kabul adımı atlanamamaktadır; kimse rızası olmadan organizasyona eklenememektedir | Slack raporu |
| 8 | Kabul sayfasında yönlendiren yok politikası uygulanmakta ile sihirli kod yedek yolu sunulmaktadır | OWASP ile Frontegg |
| 9 | Tarayıcı tıklaması belirteci tüketmemektedir; bir cihaz sinyaliyle ayırt edilmektedir | Stytch korumalı bağlantıları |
| 10 | Davet eden ile edilenin doğrulanmış alan adları farklıysa güçlü bir ara sayfa gösterilmekte; ilk kabulde asla sahip ya da yönetici verilmemektedir | OpenAI zehirli kiracı, Haziran 2026 |
| 11 | Kiracı oluşturma ile toplu davet örüntüsü hız sınırı ile itibar kontrolüne tabidir; organizasyon adı, davet edenin adı ile özel mesaj saldırgan girdisi sayılmaktadır | Aynı kaynak |
| 12 | Organizasyonda daima en az bir aktif sahip bulunmaktadır; veri katmanında ile her yolda zorlanmaktadır, SCIM sağlama kaldırma ile çoklu oturum açma süpürmesi dahil | GitHub, Vercel ile Entra'nın şirket içi boşluğu |
| 13 | Kendi rolünü değiştirme yasaktır; devir teklif, kabul, soğuma ile tüm sahiplere bildirimden oluşmaktadır | GitHub, Stripe ile Notion |
| 14 | Alan adı doğrulaması kalıcı değildir; yeniden doğrulama zamanı zorunludur ile posta kaydı veya tescil değişimi yeniden doğrulama tetiklemektedir | Truffle, npm ile Atlassian önerisi |
| 15 | Aynı alan adını birden çok organizasyon doğrulayabiliyorsa bir yarış koşulu vardır; talep etme kilitli ile alarmlıdır | Obsidian ile Atlassian |
| 16 | Tüketici, Türkiye ulusal ücretsiz posta ile internet servis sağlayıcısı ve üniversite alan adları tüketici işaretlidir; otomatik katılım yasaktır | Atlassian, Stytch ile Türkiye pazarı |
| 17 | Otomatik katılım varsayılanı kapalıdır; erişim talebi bir ara seçenektir | Notion'ın kendi tavsiyesi |
| 18 | Acil erişim bayrağı birinci sınıf, izinli ile alarmlı bir alandır; her kullanımda en yüksek önem derecesinde alarm ile zorunlu bir inceleme sınıflandırması yapılmaktadır | Stytch, Microsoft ile CISA |
| 19 | En az iki acil erişim hesabı bulunmaktadır; normal yöneticilerden farklı, kimlik avına dirençli bir yöntem kullanılmaktadır ile muafiyet yalnızca engelleyici politikalardan verilmektedir | Microsoft ile CIS kontrolü |
| 20 | Yeter sayı seçeneği bulunmaktadır: parola ile çok faktörlü yöntem farklı gruplardadır | AWS kök çok kişili onayı |
| 21 | Çoklu oturum açma zorlaması organizasyon seviyesindedir; mevcut parolaları, API token'larını, oturumları ile OAuth yetkilerini süpürmektedir; bekleyen davetlere ne olduğu açıkça tanımlıdır | GitHub'ın belirsizliği |
| 22 | Zorlama öncesinde kimlerin kaldırılacağını gösteren bir önizleme sunulmaktadır, servis hesapları dahil | GitHub'ın zorlama günü kesintisi |
| 23 | SCIM etkinken üyelik için otoriterdir; davetler devre dışıdır ya da erişim talebine indirgenmiştir | OpenAI SCIM rehberi |
| 24 | Her üyelik bir kaynak alanı taşımaktadır; SCIM sağlama kaldırma bekleyen davetleri de iptal etmektedir | Denetlenebilirlik |
| 25 | Yetkilendirme asla e-posta, tercih edilen kullanıcı adı ya da asıl ad üzerinden yapılmamaktadır; organizasyon yönlendirmesi organizasyon kimliği üzerindendir, e-posta alan adı üzerinden değil | Microsoft iddia doğrulama rehberi ile WorkOS |

Son bir dürüstlük notu özne tanımlayıcısı hakkındadır. Truffle Security araştırması, büyük bir sağlayıcının mühendisinden özne iddiasının girişlerin yaklaşık binde dördünde değiştiği ifadesini aktarmaktadır. Bu, bu dokümanın her yerinde verilen veren ile özne üzerinden anahtarla tavsiyesine karşı gerçek bir itirazdır ile şöyle ele alınmalıdır: veren ile özne çifti birincil anahtar olarak kalmalı, ancak özne değişimi tespit edildiğinde sessizce yeni hesap yaratmak yerine bir çakışma olayı üretilmeli ile doğrulanmış e-posta ve kullanıcı teyidiyle çözülmelidir. Sessiz yeni hesap yaratma kullanıcı için bir erişim kaybıdır; sessiz birleştirme ise 11. kısımdaki her saldırıdır.
