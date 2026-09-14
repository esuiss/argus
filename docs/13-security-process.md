# §13 — Güvenlik süreci

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır. Tarih 8 Eylül 2026'dır. Argus, sıfırdan yazılmış, Rust tabanlı, Keycloak sınıfında ve en güvenli olmayı hedefleyen açık kaynak bir kimlik sağlayıcıdır.

Her iddianın yanında kaynak adresi ve tarihi vardır. Doğrulanamayan kalemler açıkça işaretlenmiştir; hiçbir rakam uydurulmamıştır.

---

## A. Bir IdP için tehdit modelleme

### A.1 Çerçeveler

**STRIDE.** Klasik teknik güvenlik çerçevesidir; spoofing, tampering, repudiation, information disclosure, denial of service ve elevation of privilege başlıklarından oluşur. Bir IdP için doğrudan uygulanabilirdir, çünkü kimlik taklidi IdP'nin temel savunma yüzeyidir. Threat Dragon ile Microsoft Threat Modeling Tool gibi araçlarda yerleşik desteklenir.

**LINDDUN.** Gizlilik odaklı bir tehdit modellemedir ve bir IdP kişisel veri tuttuğu için son derece ilgilidir. Yedi tehdit türü linking (bağlanabilirlik), identifying (tanımlama), non-repudiation, detecting, data disclosure, unawareness ile unintervenability ve non-compliance'tır. LINDDUN açık bir çerçevedir ve tehdit ağacı bilgi tabanı sunar. Kaynakları KU Leuven'in LINDDUN eğitimi (lirias.kuleuven.be/retrieve/331950) ile arXiv 2308.02272'dir.

LINDDUN'un IdP'ye özgü yanı linkability'dir: iki ilgi nesnesinin aynı özneye ait olup olmadığını ayırt edebilme yeteneğidir. Bir IdP'de bu doğrudan çift taraflı subject identifier, yani PPID ve sector identifier tasarımına bağlanır. Farklı RP'lere aynı `sub` verilirse RP'ler kullanıcıyı çapraz izleyebilir ve linkability tanımlamaya dönüşür. NIST SP 800-63C bunu PPII olarak zorunlu kılar, A.4'e bakınız. Not olarak arama sonuçları LINDDUN'ı PPID ile doğrudan eşleyen akademik bir metin döndürmemiştir; bu eşleme bir çıkarımdır ve doğrulanmamıştır, ancak her iki kavram bağımsız olarak doğrulanmıştır.

**PASTA**, yani Process for Attack Simulation and Threat Analysis, iş etkisi odaklı, yedi aşamalı ve risk merkezlidir. VerSprite'ın metodolojisidir; kaynağı versprite.com'un tehdit modelleme araçları karşılaştırmasıdır.

**Saldırı ağaçları** hedeften alt hedefe ayrıştırma yapar; bir IdP için "Golden SAML üret" veya "oturum token'ı çal" gibi kökler kullanılır.

### A.2 Araçların olgunluğu ve maliyeti

Kaynaklar VerSprite'ın 2026 karşılaştırması ile OWASP Threat Dragon sayfasıdır.

| Araç | Model | Maliyet | Argus'taki yeri |
|---|---|---|---|
| OWASP Threat Dragon | Görsel ve diyagram tabanlıdır; STRIDE, LINDDUN, CIA, DIE ile PLOT4ai destekler | Ücretsiz ve açık kaynaktır | Başlangıç için idealdir; hem STRIDE hem LINDDUN tek araçtadır |
| Microsoft Threat Modeling Tool | Diyagram tabanlıdır ve Windows'a özgüdür | Ücretsizdir | Windows ekipleri içindir; Argus için daha az uygundur |
| Threagile | YAML ile deklaratiftir, yani tehdit modelini kod olarak tutar; risk kuralları ve diyagram üretir | Ücretsiz ve açıktır | Argus için en uygun kod olarak model seçeneğidir; model kodla versiyonlanır ve CI'a girer |
| pytm (OWASP) | Python ile model tanımlanır ve veri akış diyagramı üretir | Ücretsiz ve açıktır | Rust ile CI hattına Python ek adımıyla girer |
| IriusRisk | Ticaridir; AI destekli tehdit kütüphanesi eşlemesi yapar | Ticaridir | Kurumsal ölçek içindir; erken aşama açık kaynak için gereksizdir |

Uyumluluk uyarısı şudur: Threat Dragon dosya formatı pytm, Threagile ve Open Threat Model ile uyumlu değildir. Tehdit modelini kod olarak tutma felsefesi, yani Threagile ile pytm yaklaşımı, Argus'un deposuna model dosyası koyup PR'larda güncellemeye çok uygundur.

### A.3 Öğrenilecek yayımlanmış IdP ve OAuth tehdit modelleri

**RFC 9700, Best Current Practice for OAuth 2.0 Security.** RFC numarası doğrulanmıştır. Statüsü BCP 240, yayımı Ocak 2025, yazarları T. Lodderstedt, J. Bradley, A. Labunets ve D. Fett'tir. RFC 6749, 6750 ve 6819'u günceller. İçeriği PKCE zorunluluğu, tam redirect_uri eşleştirmesi, implicit ile password grant'ın kullanımdan kaldırılması, mix-up saldırısı önlemleri, sender-constrained token (DPoP ve mTLS) ve yüksek güvenlik için PAR'dır. OAuth 2.1'e dahil edilmiştir. Kaynakları rfc-editor.org/info/rfc9700 ile oauth.net/2/oauth-best-practice'tir.

**RFC 6819, OAuth 2.0 Threat Model.** Ocak 2013 tarihli ve informational statüsündedir. İstemci, authorization endpoint, token endpoint, akış ve kaynak erişimi olmak üzere beş tehdit kategorisi tanımlar. RFC 9700 tarafından güncellenmiştir. Kaynağı rfc-editor.org/rfc/rfc6819'dur.

**NIST SP 800-63C, federasyon ve assertion'lar.** FAL1, FAL2 ve FAL3 seviyelerini, assertion imzalamayı (SHALL), replay önleme için benzersiz `jti` değerini, PPII'yi yani çift taraflı takma adı, FAL2 ve üstünde şifrelemeyi ve RP başına benzersiz simetrik anahtarı tanımlar. Kaynağı pages.nist.gov/800-63-3/sp800-63c.html'dir ve Argus'ta doğrudan SAML ile OIDC assertion tasarımına uygulanır.

Keycloak ile Ory'nin doğrudan yayımlanmış tekil tehdit modeli dokümanı bu araştırmada bulunamamıştır ve doğrulanamamıştır; ayrı hedefli arama gerekir, çünkü web arama bütçesi tükenmiştir.

### A.4 MITRE ATT&CK kimlik teknikleri

Kaynağı attack.mitre.org/techniques/T1606'dır.

**T1606 Forge Web Credentials**, mevcut kimlik bilgisini çalmak yerine sahtesini üretmektir. Alt tekniği T1606.001 Web Cookies oturum çerezlerini uydurmadır. T1606.002 SAML Tokens ise Golden SAML'dir: IdP'nin imzalama anahtarı ele geçirilirse saldırgan istediği kullanıcı ve rol için geçerli bir SAML assertion üretir ve çok adımlı doğrulamayı atlar. Argus'ta imzalama anahtarının HSM veya KMS'te tutulması, anahtar rotasyonu ve ayrı bir imza anahtarı bu tehdide karşı birincil savunmadır. Azaltımları ayrıcalıklı hesap yönetimi, tam zamanında yönetim ve gelişmiş denetimdir.

**T1556 Modify Authentication Process**, kimlik doğrulama akışının kendisini değiştirmektir; örneğin sahte bir kimlik doğrulama modülü yerleştirmek. Argus'ta eklenti ve authenticator zincirinin bütünlüğü ile imzalı yapılandırma bununla ilgilidir. Tekniğin adı arama sonucundan doğrulanmıştır, ayrıntı sayfası çekilmemiştir.

**T1550 Use Alternate Authentication Material** ile **T1621 MFA Request Generation**, yani çok adımlı doğrulama yorgunluğu saldırısı, kullanıcı adlarıyla doğrulanmıştır; ayrıntı sayfaları çekilmemiştir, dolayısıyla tekniklerin varlığı doğrulanmış ancak ayrıntıları doğrulanmamıştır. T1621 için Argus'ta numara eşleştirme, hız sınırlama ve push kısıtlaması önemlidir.

---

## B. Güvenlik açığı açıklama programı

### B.1 security.txt, RFC 9116

Kaynakları rfc-editor.org/info/rfc9116 ile ietf.org'daki RFC 9116 PDF'idir.

Zorunlu alanlar yalnızca ikidir: `Contact` ve `Expires`. `Contact` en az bir yöntem içerir (`mailto:`, `https:` veya `tel:`) ve tercih sırasına göre birden çok verilebilir. `Expires` ISO 8601 biçimindedir ve en fazla bir yıl ileride olması önerilir; dosyanın bayatlama tarihidir. Konumu `/.well-known/security.txt`'tir ve HTTPS üzerinden servis edilmelidir. Opsiyonel ve önerilen alanlar `Canonical`, `Encryption`, `Preferred-Languages`, `Policy` ile `Acknowledgments`'tır.

Argus'ta bu dosya hem proje sitesine hem demo örneğine konmalı ve PGP anahtarı `Encryption` ile bağlanmalıdır.

### B.2 SECURITY.md ve koordineli açıklama

GitHub'da private security advisory, yani GHSA taslakları, ve private fork ile düzeltmeler ambargo altında geliştirilebilir. GitHub, GHSA için sizin adınıza CVE talep edebilir. Kaynağı rustsec.org/contributing.html'deki yönlendirmedir.

Ambargo süresi olarak endüstri normu 90 gündür ve Argus'un SECURITY.md dosyasında netleştirilmelidir. Bu araştırmada 90 günü bir IdP'ye özel olarak zorunlu kılan tekil bir kaynak bulunmamıştır; 90 gün genel bir normdur ve IdP'ye özgü olduğu doğrulanmamıştır.

### B.3 CNA olmak

Kaynakları OSSF'in "becoming a CNA as an OSS project" kılavuzu ile cve.org'daki CNA Rules v4.1.0 PDF'idir.

**Süre.** İlk temastan kamu duyurusuna en az dört haftadır; ilk resmî görüşmeden en az üç hafta önce başvurulmalıdır.

**Gereksinimler.** İki veya daha fazla irtibat kişisi (isim, e-posta, telefon); net ve dar bir kapsam beyanı, ki başvuruların en çok takıldığı yer burasıdır; yayımlanmış bir açıklama politikası ve triyaj süreci; itirazlara üç gün içinde onay ve beş gün içinde karar; altı ay hareketsizlik hâlinde CNA statüsünün kaldırılması.

**Süreç.** Tercih edilen Root ile iletişime geçilir; açık kaynak için Red Hat önerilir (`RootCNA-Coordination@redhat.com`). Talep cveform.mitre.org üzerinden yapılır; ardından onboarding formu, bir saatlik çağrı, alıştırma egzersizleri, onay ve duyuru gelir.

**Alternatifler ve Argus için pratik öneri.** CNA olmak zorunlu değildir. GitHub, GHSA için bir CNA'dır ve açık kaynak projeleri adına CVE atar; MITRE de son çare olarak CNA-LR sıfatıyla CVE verir. Argus erken aşamada GitHub'ı CNA olarak kullanmalı, ölçek büyüyünce kendi CNA'sına geçebilir.

**RustSec.** Rust crate açıklarını bildirmek için rustsec/advisory-db deposuna PR açılır; `crates/<crate>/RUSTSEC-0000-0000.md` şablonu TOML ile Markdown olarak doldurulur ve onay sonrası RUSTSEC-YYYY-NNNN kimliği atanır. Önce upstream'e bildirilmelidir. RustSec ambargolu açık kabul etmez; açık kamuya açıklanmadan PR açılamaz. Kaynakları advisory-db'nin CONTRIBUTING.md dosyası ile rustsec.org/contributing.html'dir.

**Rust Foundation'ın CNA durumu.** AWS ile Alpha-Omega blogunda Rust Foundation'ın 2025'te resmî bir CVE Numbering Authority olduğu ifadesi geçmektedir; kaynağı AWS Open Source Blog'un 2026 tarihli yazısıdır. Ancak Rust Foundation'ın kendi haber ve güvenlik girişimi sayfalarında bunu doğrulayan doğrudan metin bu çekimde görünmemiştir; yani ikincil kaynakla doğrulanmış, birincil kaynakla doğrulanamamıştır.

### B.4 Bug bounty, 2026'da geçerlilik

**GitHub Secure Open Source Fund.** 1,25 milyon dolar ve 125 proje ile 2025 başında başlamıştır; başvuru sürekli açıktır. Kaynakları GitHub Blog duyurusu ile github.com/open-source/github-secure-open-source-fund'dur.

**Google OSS VRP.** Ödülleri projenin önemi ve bulgunun ciddiyetine göre 100 ile 31.337 dolar arasındadır; tedarik zinciri odaklıdır; Ağustos 2023'te başlamış ve hâlâ aktiftir. Kaynağı Google Security Blog'un Ağustos 2023 yazısıdır. Argus Google'ın kendi projesi olmadığı için OSS VRP kapsamına girmez, ancak model olarak referanstır.

**Internet Bug Bounty ile HackerOne ve Bugcrowd'un açık kaynak programları.** Varlıkları arama sonuçlarında geçmiştir, ancak Internet Bug Bounty'nin Argus'u kapsayıp kapsamadığı doğrulanamamıştır.

**Argus için gerçekçi yol.** Kendi bütçesiyle ödül programı başlatmak yerine kritik altyapı fonlarına, yani C bölümündekilere, girmek ve GitHub Secure Open Source Fund'a başvurmaktır.

---

## C. Bağımsız güvenlik denetimi

### C.1 Rauthy denetimi, kilit veri noktası

Rauthy'nin (sebadob/rauthy) gerçek PDF denetim raporu indirilip metni çıkarılmıştır. Kaynakları depodaki `security_audit_report_v0.32.pdf`, sebadob.github.io/rauthy proje notu ile nlnet.nl/project/Rauthy fonlama sayfasıdır.

Denetimi Radically Open Security B.V. (Amsterdam) yapmıştır; sızma testçileri Frank Plattel ile Morgan Hill, yazarları Morgan Hill, Frank Plattel ve Marcus Bointon, onaylayanı Melanie Rieback'tir. Rapor v1.0 ve 15 Eylül 2025 tarihlidir; taslağı 22 Ağustos 2025'tir. Denetim dönemi 14 Temmuz ile 22 Ağustos 2025 arasıdır. Fonlaması NGI Zero Core'dur (NLnet, AB Next Generation Internet, hibe numarası 101092990) ve dönemi Ocak ile Ağustos 2025 arasıdır. Türü crystal-box, yani kaynak kod erişimli bir sızma testi ve kod denetimidir.

Sonuç bir Elevated, üç Low ve üç Not Applicable bulgudur.

RAUTHY-007, Elevated, kalıcı XSS: profil resmi olarak yüklenen SVG içine JavaScript enjeksiyonudur ve kullanıcı etkileşimiyle frontend ele geçirilir. Girdi doğrulama ve temizleme ile çözülmüştür.

RAUTHY-005, Low, zamanlama sızıntısı: `client_secret` için sabit zamanlı olmayan string karşılaştırması kullanılmaktadır ve teorik bir zamanlama saldırısı mümkündür. Sabit zamanlı karşılaştırmayla çözülmüştür.

RAUTHY-006, Low, erişilebilir `unwrap` ve hizmet reddi: proje içi `hiqlite` bağımlılığında bir HTTP isteğiyle tetiklenen panic bulunmaktadır. `unwrap` yerine hata dönülerek çözülmüştür.

RAUTHY-009, Low, açığa çıkmış kimlik bilgileri: depoda statik CA zinciri ve özel anahtar taşınmaktadır. Kaldırılarak ve kurulumda üretilerek çözülmüştür.

RAUTHY-001, Not Applicable, savunmasız bağımlılık: `rsa` crate'inde CVE-2023-49092, yani Marvin saldırısı, mevcuttur ancak bu bağlamda sömürülemez. Yeniden test edilmemiştir.

RAUTHY-004, Not Applicable, mantık hatası: `page_size=0` değeri kullanıcı ve oturum listelemede sıfıra bölmeye yol açmaktadır. Çözülmüştür.

RAUTHY-008, Not Applicable, güvensiz yapılandırma: geliştirme ortamı portları tüm arayüzlerde, yani `0.0.0.0` üzerinde dinlemektedir. Yeniden test edilmemiştir; loopback önerilmiştir.

Genel kanı şudur: proje güvenliği baştan düşünmüştür ve çok iyi iş çıkarmaktadır, bulguların çoğu saatler içinde düzeltilmiştir. Bulgular Rauthy v0.32.1'de giderilmiştir. Gelecek iş önerileri Hiqlite ile PAM modülü için ayrı hedefli denetim, düzeltmelerin yeniden testi ve düzenli periyodik denetimdir.

> **Argus için ders.** Birincisi şudur: bir Rust IdP'sinde bile bulgular mimari kripto kırılması değil klasik web ve implementasyon hataları etrafında yoğunlaşmaktadır; SVG üzerinden XSS, sabit zamanlı olmayan karşılaştırma, `unwrap` panic'i, depoda gömülü anahtar ve bağımlılık CVE'si. Bunlar Argus'un regresyon test setinin çekirdeği olmalıdır. İkincisi NGI Zero ile Radically Open Security kombinasyonunun açık kaynak bir IdP için kanıtlanmış ve tekrar edilebilir bir denetim yolu olmasıdır.

### C.2 NLnet ve NGI Zero fonlaması, 2026 durumu

Avrupa Birliği, Horizon Europe 2025 çalışma programından NGI fonunu çıkarmıştır; kaynakları EDRi'nin 2024 yazısı ile FSFE'nin 19 Temmuz 2024 tarihli haberidir.

Ancak 2026'da NGI Zero Commons Fund hâlâ açıktır: çağrı 2026-06Z, son başvuru 1 Haziran 2026 ve toplam bütçe 6,1 milyon avrodur. İlk başvuru 50.000 avroya kadar, sonraki ödüller 150.000 avroya kadardır; üçüncü taraf başına yaşam boyu tavan 500.000 avrodur. Kaynağı DevelopmentAid'in 2026-06Z kaydı ile yukarıdaki kesinti bağlamıdır.

Güvenlik denetimi ayni hizmet olarak sağlanmaktadır: NGI hibesi alanlar bir Radically Open Security denetimini destek hizmeti olarak talep edebilir; sonuçlar gizli iletilir ve koordineli açıklamayla kamuya açılabilir. Erken talep edilmesi tavsiye edilir. Kaynağı nlnet.nl/events/20240111'dir.

> **Argus için.** NGI Zero Commons Fund'a başvurmak hem küçük bir geliştirme hibesi hem de ücretsiz bağımsız denetim demektir; yani Rauthy modelidir ve en yüksek getirili tek adımdır.

### C.3 Diğer fon ve denetim programları

**OSTIF**, yani Open Source Technology Improvement Fund, kâr amacı gütmeyen bir kuruluştur; on yılda 800'den fazla açık bulmuştur (121'i kritik veya yüksek) ve 13.000 saatten fazla güvenlik çalışması yapmıştır. Denetim maliyetine idari ve lojistik destek dahildir. Kaynakları ostif.org/ostif-helps-foundations ile github.com/ostif-org/OSTIF'tir. Not olarak STA rapor PDF'i 403 döndürmüştür ve net dolar rakamı doğrulanamamıştır.

**Alpha-Omega** (OpenSSF ve Linux Foundation) 70'ten fazla hibe ve 20 milyon doların üzerinde destek vermiştir. Mart 2026'da AWS, Anthropic, Google, Microsoft ve OpenAI'den 12,5 milyon dolar alınmıştır; bu, AI üretimi açık raporları içindir. Rust'ın TLS (rustls) ve AV1 implementasyonlarını fonlamıştır; 2025'te Rust Foundation'ın crates.io Trusted Publishing çalışmasını ve CNA olmasını desteklemiştir. Kaynakları openssf.org/category/alpha-omega ile AWS blogudur.

**Sovereign Tech Agency ve Fund** (Almanya) 2026'da aktiftir; Fund, 2026 Fellowship ve 24 Ağustos 2026'da duyurulan yeni Sovereign Tech Standards ile EU-STF çok uluslu pilotunu yürütmektedir. Kaynakları sovereign.tech, sovereign.tech/programs/fund ile GamingOnLinux'un Nisan 2026 haberidir.

**Mozilla SOS Fund ile Google'ın açık kaynak güvenlik çalışması** model olarak mevcuttur; Argus'a özel güncel uygunluk doğrulanamamıştır, çünkü web arama bütçesi tükenmiştir.

**Denetim firmaları** olarak Rust, kripto ve protokol alanında Trail of Bits, Radically Open Security (Rauthy'yi denetleyen), Cure53, NCC Group, Include Security, Quarkslab, X41 D-Sec, 7ASecurity ile Least Authority sayılabilir. Kaynakları cure53.de ile 7asecurity.com/publications'tır. Maliyet açısından iki ile altı haftalık bir denetim için doğrulanmış tekil bir dolar rakamı bu araştırmada bulunamamıştır. Pratikte NLnet, OSTIF veya Alpha-Omega bu maliyeti üstlenir ve Argus'un cebinden ödemesi gerekmeyebilir.

**İyi bir denetim kapsamı.** Rauthy raporu şablon niteliğindedir: hedef net tanımlıdır (IdP kodu), crystal-box yani kaynak erişimlidir, risk sınıflandırması yapar, bulguyla birlikte öneri ve durum verir (çözüldü veya kabul edildi) ve gelecek iş başlığı taşır (alt bileşen denetimi ve yeniden test). Denetimin bulamadıkları şunlardır: tam kapsam garantisi değildir, tek seferlik bir anlık görüntüdür; ambargolu sıfır günleri kapsamaz; denetim sonrası regresyonları göremez. Bu yüzden periyodik denetim ile CI regresyonu şarttır.

---

## D. Red team ve düşmanca test

### D.1 Evilginx v3.x ve ortadaki saldırgan oltalaması

Kaynakları github.com/kgretzky/evilginx2 ile darkreading'in Evilginx MFA bypass yazısıdır.

Go ile yazılmış bağımsız bir ters vekil ortadaki saldırgan çatısıdır; v3.x, 2017'deki nginx tabanlı sürümden tam bir yeniden yazımdır. Lisansı BSD-3-Clause'tur, yaklaşık 15,6 bin yıldızı vardır ve aktiftir. Kurban ile gerçek site arasında oturur; kimlik bilgisini, oturum çerezini ve ikinci adım token'ını yakalar ve oturumu yeniden oynatır. Star Blizzard gibi gerçek tehdit aktörlerince kullanılmaktadır.

**Argus'un neyi durdurması gerekir.** Origin'e bağlı WebAuthn ve passkey. FIDO2 kimlik bilgisi gerçek origin'e kriptografik olarak bağlıdır; Evilginx farklı bir alan adı sunduğu için tarayıcı kimlik bilgisini serbest bırakmaz ve Evilginx bu modeli kıramaz. Kaynakları golinuxcloud'un Evilginx yazısı ile gottaphish'in AiTM yazısıdır.

**Argus laboratuvar kullanımı.** Kendi test ortamında Evilginx ile TOTP, SMS ve push akışlarının kırıldığını, passkey akışının kırılmadığını kanıtlayan bir kabul testi koşulmalıdır.

### D.2 Browser-in-the-Middle, passkey yetmez

Kaynakları Google Cloud ile Mandiant'ın "BitM Up!" yazısı, SpecterOps CuddlePhish dokümanları ve github.com/Mayyhem/cuddlephish'tir.

Bu saldırıda kurban, saldırganın sunucusundaki gerçek bir Chrome örneğini uzaktan kullanır; kimlik doğrulama gerçek sitede olur ve saldırgan oturum token'ını ele geçirir. Mandiant'ın iç aracı Delusion'dır; kamuya açık olanı çok kullanıcılı CuddlePhish'tir.

**Kritik nüans.** FIDO2 ile passkey'in origin bağlaması sayesinde bu saldırı kimlik doğrulama adımını çözemez, çünkü kripto kanıtı üretilemez. Ancak doğrulama gerçek origin'de tamamlandıktan sonra oturum çerezi hâlâ çalınabilir. Yani passkey oltalamayı durdurur, oturum token'ı hırsızlığını durdurmaz. Mandiant'a göre token çalınınca çok adımlı doğrulama etkisizleşir.

**Azaltım oturumu cihaza bağlamaktır**: DBSC, yani Device Bound Session Credentials, ve token binding veya DPoP ile cihaza bağlı oturum.

### D.3 DBSC, 2026 durumu

Kaynakları Chrome geliştirici dokümanı, w3.org/TR/dbsc-1, Help Net Security'nin 10 Nisan 2026 haberi ile Security Boulevard'ın Ağustos 2026 yazısıdır.

Chrome 146'da Windows'ta genel kullanıma açılmıştır (Nisan 2026); macOS Secure Enclave desteği yoldadır. W3C Web Application Security çalışma grubunda standart yolundadır ve First Public Working Draft aşamasındadır; Google ile Microsoft ortak tasarımıdır. Oturumu cihazın TPM'ine veya güvenli donanımına bağlar, böylece çalınan çerez başka bir cihazda işe yaramaz. Google kendi servislerinde oturum hırsızlığında ölçülebilir bir düşüş bildirmiştir. Yol haritasında federe kimlik, mTLS ile donanım anahtarı kaydı ve yazılım tabanlı anahtarlar vardır.

**Argus'taki yeri.** Uzun vadeli oturumlar için DBSC entegrasyonu, bilgi hırsızıyla çalınan çerezin yeniden oynatılmasına karşı en güncel savunmadır. Not olarak KnowBe4, DBSC'nin de hâlâ oltalanabilir ve kırılabilir olduğunu belirtmektedir; tek başına sihir değildir. Kaynağı blog.knowbe4.com'un DBSC yazısıdır.

### D.4 Diğer araçlar

Ortadaki saldırgan ve tarayıcı araya girme araçları Modlishka, Muraena, EvilnoVNC ile CuddlePhish'tir; CuddlePhish doğrulanmıştır, diğerleri isim düzeyinde geçmiştir.

OAuth ve SAML saldırı araçları, yani Burp eklentileri, JWT Editor, EsPReSSO, SAML Raider ile OAuth Scan'dir. Bu araştırmada arama bütçesi bittiği için isimler görevden gelmektedir ve bu oturumda doğrulanmamıştır.

Purple team CI olarak Evilginx ile tarayıcı araya girme laboratuvar senaryoları, passkey akışının kırılmadığını doğrulayan otomatik regresyon testleri hâlinde koşulmalıdır; bu, Rauthy'nin gelecek iş olarak yeniden test felsefesiyle uyumludur.

---

## E. Güvenlik regresyon testi

### E.1 Project Wycheproof, 2026'da bakımlıdır

Kaynakları github.com/C2SP/wycheproof, docs.rs/wycheproof, github.com/randombit/wycheproof-rs ile appsec.guide'ın Wycheproof sayfasıdır.

Wycheproof artık bir C2SP projesi olarak bakımı yeniden canlandırılmıştır; JSON test vektörleri ve JSON şeması sunar.

Rust `wycheproof` crate'i doğrulanmıştır ve bakımlıdır: randombit/wycheproof-rs, v0.6.0, 5 Eylül 2026, Apache-2.0 lisanslıdır. Kapsamı AES-GCM ile diğer AEAD'ler, ECDSA, EdDSA, DSA, ECDH ile Montgomery eğrileri, RSA OAEP, PKCS1v1.5 ile PSS, HKDF, MAC, anahtar sarmalama ve asallık testleridir. Argus'un tüm imza ve şifreleme yollarına, yani JWT ile JWS için ECDSA, EdDSA ve RSA-PSS'e, oturum şifrelemesi için AES-GCM'e ve HKDF'e, CI'da uygulanmalıdır.

### E.2 OpenID Foundation Conformance Suite

Kaynakları gitlab.com/openid/conformance-suite, openid.net/certification/fees ile FAPI OP test sayfasıdır.

Açık kaynaktır (MIT), GitLab'dadır, Docker ile çalışır ve CI'a uygundur (Auto DevOps). Kapsamı OIDC OP (basic, implicit, hybrid, config, dynamic), FAPI 1 Advanced, FAPI 2.0, FAPI-CIBA ile OpenBanking ve CDR'dir. Canlı örneği certification.openid.net'tir. Test süitini çalıştırmak ücretsizdir ve Argus bunu CI'da koşabilir.

Sertifikasyon, yani listeleme ücreti, üyeler için dağıtım başına 700 dolar, üye olmayanlar için 3.500 dolardır; FAPI-CIBA üye toplamı 1.000 dolardır ve pilot profiller ücretsizdir. Sertifika talep eden OIDF üyesi olmalıdır. Argus önce ücretsiz süitle kendi kendini test etmeli, ürün olgunlaşınca resmî sertifikasyona geçmelidir.

### E.3 Diğer uygunluk ve test setleri

SAML (SAML2Int ve Kantara) ile SCIM uygunluk setleri bu araştırmada doğrulanamamıştır.

WebAuthn ile FIDO sertifikasyonu için FIDO Alliance Functional Certification vardır; seviyeleri L1, L1+, L2, L3 ve L3+'tır ve yedi adımdan oluşur: gizlilik sözleşmesi, uygunluk öz doğrulaması, birlikte çalışabilirlik, authenticator sertifikası (en az L1), başvuru, ticari marka ve MDS. Kaynağı fidoalliance.org/certification/functional-certification'dır. Net ücret bu sayfada yayımlanmamıştır ve maliyet doğrulanamamıştır. Argus bir relying party veya authenticator sağlayıcı değilse tam FIDO sertifikası zorunlu değildir; uygunluk test araçları yine de değerlidir.

### E.4 Bilinen saldırı regresyon testleri, Argus CI çekirdeği

Aşağıdakiler CI'da açık negatif testler olarak kodlanmalıdır; kaynağı RFC 9700 ile Rauthy bulgularıdır. `alg=none`; algoritma karışıklığı, yani RS256 ile HS256 arasında; IdP mix-up; `redirect_uri` manipülasyonu ve tam eşleşme; PKCE downgrade; callback'te CSRF ile state; assertion replay'i ve `jti`; SAML için XML Signature Wrapping. Rauthy'de çıkan desenler de eklenir: SVG ile XSS temizliği, sabit zamanlı sır karşılaştırması, `unwrap` kaynaklı panic ile hizmet reddi için fuzzing ve `page_size` gibi sınır değer testleri (0 ile `u16::MAX`).

Açık ve hazır tekil bir korpus kaynağı bulunamamıştır ve doğrulanamamıştır; ancak RFC 9700 ile OpenID conformance suite bunların çoğunu kapsar.

### E.5 FIPS, CAVP ve ACVP

NIST CAVP ile ACVP ve FIPS 140-3 kripto validasyonu, açık kaynak bir IdP için genellikle kapsam dışıdır; maliyeti yüksektir ve resmî laboratuvar gerektirir. NIST SP 800-63C yalnızca FAL ile AAL2 ve üstü devlet dağıtımlarında imza ve şifreleme anahtarları için FIPS 140 Level 1 ve üstünü ister. Argus için not düşülmeli ancak önceliklendirilmemelidir.

### E.6 OWASP ASVS 5.0 ve Top 10 2025

**ASVS 5.0** 30 Mayıs 2025'te Barselona'daki Global AppSec EU'da yayımlanmıştır; 17 bölüm ve yaklaşık 350 gereksinim içerir, her gereksinime izlenebilir bir kimlik verilmiştir. Argus için madde madde bir kontrol listesidir. Kaynakları owasp.org'un ASVS RC1 blog yazısı, github.com/OWASP/ASVS ile softwaremill'in ASVS 5.0 yazısıdır.

**OWASP Top 10:2025** yayımlanmıştır. İki yeni kategori vardır: A03 Software Supply Chain Failures ile A10 Mishandling of Exceptional Conditions. SSRF, A01 Broken Access Control'e katılmıştır ve BOLA ile BFLA da oraya dahildir. Security Misconfiguration beşinci sıradan ikinci sıraya çıkmıştır. Çalışma 175.000'den fazla CVE analizine dayanmaktadır. Kaynakları owasp.org/Top10/2025 ile Qualys'in analizidir. Argus için anlamı şudur: bağımlılık ile tedarik zinciri (A03) ve hata yönetimi ile fail-open (A10) doğrudan Rauthy bulgularıyla, yani bağımlılık CVE'si ile `unwrap` panic'iyle örtüşmektedir.

---

## Argus için önceliklendirilmiş özet öneri

1. **Hemen.** security.txt (RFC 9116), SECURITY.md ve GitHub private advisory'leri; GHSA CNA olarak kullanılır. Threagile veya pytm ile tehdit modeli kod olarak tutulur; STRIDE ile LINDDUN uygulanır, yani çift taraflı subject tasarımı yapılır.
2. **Kripto ve regresyon.** `wycheproof` crate'i CI'a alınır; RFC 9700 saldırı testleri kodlanır (`alg=none`, algoritma karışıklığı, mix-up, PKCE downgrade, XSW); OpenID conformance suite ücretsiz ve Docker ile CI'da koşulur.
3. **Kimlik avı direnci.** Origin'e bağlı WebAuthn ile passkey birincildir ve Evilginx laboratuvar testiyle kanıtlanır; oturum token'ı hırsızlığına karşı DBSC (Chrome 146, 2026) ile DPoP yol haritasına alınır.
4. **Bağımsız denetim.** NGI Zero Commons Fund'a başvurulur (2026-06Z, son tarih 1 Haziran 2026) ve Radically Open Security ayni denetimi alınır, yani Rauthy modeli uygulanır; paralelde OSTIF, Alpha-Omega ve Sovereign Tech değerlendirilir.
5. **Standart uyumu.** ASVS 5.0'ın 350 maddelik kontrol listesi kullanılır; Top 10:2025'te A03 ile A10'a özel dikkat gösterilir.

**Doğrulanamayan kalemler**, tekrar arama gerektirir, çünkü web arama bütçesi 200 üzerinden 200 dolmuştur: Keycloak ile Ory'nin yayımlanmış tehdit modeli; Rust Foundation CNA'sının birincil kaynak teyidi; denetim firmalarının dolar maliyet aralıkları; T1550, T1621 ile T1556'nın ayrıntı sayfaları; SAML2Int ile SCIM uygunluğu; Burp eklentilerinin (SAML Raider, JWT Editor, EsPReSSO) güncel teyidi; FIDO sertifikasyon ücretleri; Internet Bug Bounty ile Mozilla SOS'un güncel uygunluğu.

---

# Kısım IV — Protokoller

Argus'un konuşacağı protokoller: MCP ile ajan kimliğinden kurumsal protokollere ve gelecek standartlarına.
