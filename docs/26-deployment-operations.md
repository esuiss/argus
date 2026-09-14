# §26 — Dağıtım ve operatör deneyimi

Bu bölüm `ARGUS.md` dosyasının 26. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§26 §X` referansları aynı anlamdadır.

---

## 1. Kurulum ile ilk çalıştırma deneyimi

### 1.1 Keycloak'ın derleme ile başlatma ikiliği: neden vardır, ne acıtmaktadır

Keycloak, Quarkus artırma modeli üzerine kuruludur. Resmî doküman ayrımı net biçimde tanımlamaktadır: derleme seçenekleri imaja kalıcı olarak gömülmekte, yapılandırma seçenekleri çalışma anında uygulanmaktadır.

> "This `build` command performs a set of optimizations for the startup and runtime behavior."
> "The `--optimized` parameter tells Keycloak to assume a pre-built, already optimized Keycloak image is used. As a result, Keycloak avoids checking for and running a build directly at startup."

Derleme adımının yaptıkları şunlardır: kurulu sağlayıcılar hakkında kapalı dünya varsayımı, yapılandırma dosyalarının önceden ayrıştırılması, ki giriş çıkış azaltmaktadır, ile veritabanına özgü kaynakların önceden yapılandırılması.

Üretim modu varsayılan olarak güvenlidir.

> "Production mode expects a hostname to be set up and an HTTPS/TLS setup to be available when started."
> "HTTP is disabled as transport layer security (HTTPS) is essential"

Operatörlerin şikâyetinin somut kanıtı 30460 numaralı konudur: geliştirme modunda bir kez çalıştırdıktan sonra üretim başlatması şu hatayla patlamaktaydı.

> "You can not 'start' the server in development mode. Please re-build the server first, using 'kc.sh build' for the default production mode."

Hata ile gerileme olarak etiketlenmiş ile bir öneriyle kapatılmıştır. Ders şudur: iki modlu tasarım, mod geçişlerinde sessiz ya da kafa karıştırıcı hata sınıfları üretmektedir. Kullanıcı aynı komutu çalıştırdım, biri oldu biri olmadı durumuna düşmektedir.

Geliştirme veritabanı tarafında Keycloak'ın varsayılanı bir dosya tabanlı H2'dir ile doküman açıkça üretime uygun olmadığını ve değiştirilmesi gerektiğini söylemektedir. Başlangıç sayfası tek bir komut vermektedir.

```
docker run -p 127.0.0.1:8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.7.3 start-dev
```

Yani beş dakikada bir kimlik sağlayıcı hedefine Keycloak ulaşmaktadır; ancak geliştirmeden üretime geçiş bir uçurumdur: farklı veritabanı, farklı komut, zorunlu ana bilgisayar adı ile TLS ve ayrı bir derleme adımı.

### 1.2 Rakiplerin kurulum modelleri, 2026 durumu

| Ürün | Süreç modeli | Veritabanı | Lisans | İlk çalıştırma |
|---|---|---|---|---|
| Keycloak | Tek sanal makine süreci artı operatör | PostgreSQL 14 ile 18, MySQL, MariaDB, Oracle, MSSQL ile Aurora | Apache 2.0 | Tek bir çalıştırma komutu, H2 |
| Zitadel | Dört konteyner: ters vekil, Go API'si, Next.js giriş uygulaması ile PostgreSQL | PostgreSQL; CockroachDB üçüncü ana sürümde düşürülmüştür | AGPL 3.0, üçüncü sürümden beri | İki dakika, tek bir bileşim komutu |
| authentik | Sunucu, işçi ile PostgreSQL | PostgreSQL 14 ile 18 | Doğrulanmamıştır | Bileşim dosyası, en az iki işlemci ile iki gigabayt bellek |
| Ory | Ayrı ayrı kimlik, yetkilendirme, izin ile ağ geçidi bileşenleri | PostgreSQL, MySQL ile CockroachDB; SQLite üretim dağıtımında kullanılmamalıdır | Apache 2.0 artı kurumsal lisans | Beş ile 15 megabaytlık ikili dosya, sistem bağımlılığı olmadan |
| SuperTokens | Çekirdek artı arka uç geliştirme kiti | Yalnızca PostgreSQL; çekirdeğin 11.0.0 sürümü diğerlerini düşürmüştür | Çekirdek Apache 2.0 artı lisans anahtarlı premium | Tek bir çalıştırma komutu |
| Casdoor | Tek Go ikili dosyası artı React arayüzü | MySQL, PostgreSQL, SQLite ile MSSQL | Apache 2.0 | Hepsi bir arada imajla tek komut, SQLite ile hazır yönetici |
| Kanidm | Tek konteyner, kendi veritabanı ile replikasyonu | Kendi yüksek performanslı veritabanı ile replikasyon sistemi | MPL 2.0 | Tek konteyner, iki düğümlü yüksek erişilebilirlik replikasyonu |
| Pocket ID | Tek ikili dosya ya da Docker | SQLite ya da PostgreSQL | BSD iki maddeli | Yalnızca geçiş anahtarı |

### 1.3 Gömülü veritabanıyla başlamak bir kimlik sağlayıcı için mantıklı mıdır

Sektörde dört farklı duruş vardır.

1. Yasaktır, Ory'de: SQLite desteklenmektedir ancak üretim dağıtımında kullanılmamalıdır. Yalnızca geliştirme içindir.
2. Meşrudur, Casdoor ile Pocket ID'de: hepsi bir arada imaj SQLite ile çalışmakta ile Pocket ID SQLite'ı gerçek bir dağıtım seçeneği olarak sunmaktadır.
3. Kendi motorunu yazmaktır, Kanidm'de: kurumsal dizin sunucusu deneyimine dayalı kendi yüksek performanslı veritabanı ile replikasyon sistemi geliştirilmiştir; 3.000 kullanıcıda FreeIPA'ya göre yaklaşık üç kat hızlı arama bildirilmektedir.
4. Sahte gömülüdür, Keycloak'ta: dosya tabanlı H2 üretimde açıkça yasaktır ile bu, geliştirme ile üretim uçurumunun ana kaynağıdır.

Argus için çıkarım şudur: Keycloak modelinin en büyük operasyonel bedeli, geliştirme modunun üretimle aynı kod yolunu kullanmamasıdır. Casdoor ile Pocket ID modeli, yani aynı ikili dosya, aynı şema ile yalnızca farklı bağlantı dizgisi, daha az sürpriz üretmektedir. Ancak PostgreSQL'e özgü özellikler, yani nicelikli senkron işleme, doğrulanmamış kısıt ile tavsiye kilidi kullanılacaksa SQLite ile şema paritesi maliyetli olmaktadır.

### 1.4 Beş dakikada çalışan bir kimlik sağlayıcıya kim en yakındır

Ölçülebilir iddialar şunlardır: Zitadel resmî bileşim dokümanında iki dakika demektedir ile varsayılan bir yönetici hesabı sunmaktadır. Casdoor tek bir çalıştırma komutu, SQLite ile hazır demo kimlik bilgileri sunmaktadır. Keycloak tek bir geliştirme komutu sunmaktadır. authentik dört adım gerektirmektedir: bileşim dosyasını indirme, parola üretme, ayağa kaldırma ile yönetici parolasını ayarlama.

Bunlar gerçekçidir. Ancak hepsinin ortak kusuru şudur: beş dakikada çalışan şey beş dakikada üretim değildir. Zitadel'in ana anahtar uyarısı bunun tipik örneğidir.

---

## 2. Konteyner ile Kubernetes

### 2.1 Dağıtımsız ile sıfırdan imajlar, Rust için gerçek rakamlar

Distroless projesinin resmî rakamları, hepsi Debian 13 tabanlı, şöyledir.

| İmaj | Boyut | İçerik |
|---|---|---|
| Statik | Yaklaşık iki mebibayt | Statik ikili dosyalar içindir; kabuk ya da paket yöneticisi yoktur |
| C ve C++ çalışma zamanlı | — | C ve C++ çalışma zamanı kütüphaneleri bulunmaktadır |
| Temel | — | Standart C kütüphanesi artı sertifika otoriteleri ile saat dilimi verisi |
| SSL'siz temel | — | Sertifika demeti olmadan |

Proje şunu söylemektedir: en küçük dağıtımsız imaj yaklaşık iki mebibayttır; bu, Alpine'ın yaklaşık yarısı ile Debian'ın yüzde ikisinden azıdır.

Hata ayıklama varyantları bir kabuk içermektedir; kök olmayan etiketler düşük ayrıcalıkla çalışmaktadır. Mimariler amd64, arm64, arm, s390x, ppc64le ile riscv64'tür.

Rust için özel rakamlar şunlardır: cargo-chef ile dağıtımsız imaj yaklaşık 26,2 megabayt, musl ile sıfırdan imaj yaklaşık 8,38 megabayttır. Bu rakamlar ikincil kaynaktandır ile doğrulanmamıştır. Bir Rust proje rehberi yalnızca Debian ince ya da Alpine üzerindeki bir Rust ikili dosyasının tipik olarak 50 megabaytın altında olduğunu söylemektedir.

musl tuzağı kritiktir. Mayıs 2020 tarihli bir yazıya göre musl ile derlenen Rust kodu çok iş parçacıklı bir kıyaslamada yaklaşık 30 kat yavaş çalışmıştır. Önerilen çözüm jemalloc'a geçmektir, ki ripgrep'in aynı sorunu böyle çözdüğü belirtilmektedir; ancak yazar bölütleme hatası almış ile musl'u tamamen bırakıp Debian ince imajına dönmüştür. Yazarın sonucu şudur: sorun yalnızca ayırıcı değil musl'daki iş parçacığı yönetiminin temel sorunlarıdır. Bu bulgu 2020 tarihlidir ile doğrulanmamıştır; musl'un sonraki sürümlerinde ayırıcı iyileştirmeleri vardır ile 2026 için yeniden ölçülmelidir. Ancak Argus gibi Argon2 ağırlıklı, çok iş parçacıklı ile yoğun ayırma yapan bir iş yükü için musl'a körlemesine geçmek risklidir.

### 2.2 cargo-chef ile derleme önbelleği

cargo-chef üç aşamalıdır: planlayıcı, manifest ile kilit dosyasının iskeletinden bir tarif üretmektedir; pişirme, yalnızca bağımlılıkları derlemekte ile bu katman önbeleklenmektedir; ile derleyici, uygulama kodunu derlemektedir. Beş kata kadar hızlanma iddia edilmektedir.

Deponun iki uyarısı vardır. Birincisi, pişirme ile derleme aynı çalışma dizininden çalıştırılmalıdır, çünkü cargo mutlak yol metadata'sı kullanmaktadır. İkincisi, cargo derlemesi mevcut projenin dışındaki yerel bağımlılıkları değişmemiş olsalar bile sıfırdan derlemektedir; zaman damgası tabanlı parmak izi mantığı yüzündendir. Yani çalışma alanı dışında yol bağımlılığı kullanılıyorsa önbellek tutmamaktadır.

### 2.3 Keycloak operatörü, kaynak tanımı modeli, sınırlar ile gerçek arızalar

Kaynak tanımı olgunluğu tarafında 45795 numaralı konu şunu göstermektedir: ilgili tanımlar yıllarca alfa sürümünde kalmış ile 26.6.0'da beta sürümüne terfi ettirilmiştir. Gerekçe tanımların daha olgun olması ile istemciler için gerekenler gibi yeni tanımlardan sürümlemeyi ayırmaktır.

Alan içe aktarma tanımının yapısal sınırı şudur: yalnızca yeni alan oluşturmakta, güncellememekte ile silmemektedir; Keycloak üzerinde doğrudan yapılan değişiklikler kaynağa geri senkronize edilmemektedir. Yani bir GitOps illüzyonu vardır: kaynağınız gerçeğin kaynağı değildir.

Gerçek arızalar şunlardır. 3 Şubat 2026 tarihli 45966 numaralı konuda içe aktarılan alan veritabanına yazılmakta ancak yönetim konsolunda durum kümesi yeniden başlatılana kadar görünmemektedir. Kök neden raportörün ifadesiyle şudur: çalışan Keycloak düğümleri bir geçersizleştirme olayı almamaktadır; geçici içe aktarma işiyle çalışan kapsüller arasında bir önbellek geçersizleştirme kanalı yoktur. Bir öneriyle kapatılmıştır. 24526 numaralı konuda ise kaynaklar bir GitOps hattında art arda uygulandığında alan içe aktarma işi, işlenen hazır olmadan başlamakta ile geri çekilme limitine kadar kapsül başarısız olmaktadır.

Ders şudur: kaynak tanımlarıyla yönetilen bir kimlik sağlayıcıda, veritabanına yazan yan süreçlerle çalışan düğümlerin önbelleği arasındaki geçersizleştirme, tasarımın birinci sınıf parçası olmak zorundadır. Keycloak bunu 26.7'de veritabanı destekli bir giden kutusu desenine taşımıştır.

### 2.4 Helm paketiyle operatörün karşılaştırması ile Bitnami felaketi

Keycloak'ın resmî bir Helm paketi yoktur. Kurulum dokümanı yalnızca operatör yaşam döngüsü yöneticisini ya da bir kubectl komutunu göstermektedir. Güçlü bir uyarı vardır: elle onay modu şiddetle önerilmektedir, ki otomatik bir operatör güncellemesi istenmeyen bir Keycloak yükseltmesi tetiklemesin.

Bitnami'nin 2025 değişikliği, 28 Ağustos 2025 yürürlüklüdür. Ana Docker kayıt defterindeki depo yalnızca sınırlı bir topluluk alt kümesine, yalnızca en son etikete ile geliştirme kullanımına indirgenmiştir. Sürümlü ile eski imajlar bir eski depoya taşınmıştır; o depo hiçbir güncelleme ya da destek almayacak ile yalnızca geçici göç için kullanılmalıdır. OCI Helm artefaktları güncelleme almamaktadır; paketlenen imajlar geçersiz kılınmazsa dağıtımlar patlamaktadır. Açık katalog silinmesi 29 Eylül 2025'e ertelenmiş ile Ağustos ve Eylül 2025'te kesinti denemeleri yapılmıştır. GitHub'daki paket ile konteyner kaynak kodu Apache 2.0 altında kalmıştır.

Doğrulama şudur: eski depo sayfası, deponun artık güncellenmediğini ile gelecekte kaldırılabileceğini belirtmektedir.

Argus için ders şudur: üçüncü taraf bir paket ya da imaj dağıtım kanalına bağımlılık, tek bir kurumsal kararla gecede kırılabilmektedir. Kendi Helm paketiniz kendi OCI kayıt defterinizde yayımlanmalı ile paketin imaj referansı kendi imajınıza sabitlenmelidir.

Helm mi operatör mü sorusunun cevabı bir gözlemdir: operatör, ancak kaynak tanımlarının çözdüğü gerçek bir problem varsa değer üretmektedir; yani yuvarlanan güncelleme uygunluk kararı, alan uzlaştırması ya da veritabanı göçü orkestrasyonu. Keycloak operatörünün en çok değer kattığı yer üçüncüsüdür.

### 2.5 Yuvarlanan güncelleme ile oturum kaybı

Keycloak operatörünün güncelleme stratejisi seçenekleri şunlardır: imaj değişiminde yeniden oluşturma, ki varsayılandır ile durum kümesini küçültüp kesinti yaratmaktadır; otomatik, ki yuvarlanan mı yeniden oluşturma mı gerektiğini kendisi tespit etmekte ve bunun için geçici bir iş başlatmaktadır; ile açık, ki yalnızca bir revizyon alanı değişince yuvarlanan güncelleme yapmaktadır.

Karar mekanizması bir güncelleme uyumluluğu komutudur; eski sürümle metadata üretilmekte ile yeni sürümle kontrol edilmektedir. Çıkış kodları şöyledir: sıfır yuvarlanan güncellemenin mümkün olduğunu, üç imkânsız olduğunu ile dört ilgili özelliğin kapalı olduğunu göstermektedir.

Yeniden oluşturma gerektiren değişiklikler sürüm farkı, çok bölgeli, kalıcı kullanıcı oturumları ile durumsuz özellik anahtarları ve veritabanı sağlayıcısı, önbellek tipi, önbellek yığını veya bağlantı parametreleri değişimidir.

Bir uyarı vardır: desteklenmeyen bir kapsül şablonu alanı kullanılıyorsa operatör, şablondan ya da yapılandırma ve birim kaynaklarından gelen sır değişikliklerinden yanlış sonuç çıkarabilmektedir.

Durumsuz tasarımda oturum kaybı konusunda Keycloak 26.7'nin durumsuz önizlemesiyle kimlik doğrulama oturumları, eylem token'ları ile kaba kuvvet sayaçları veritabanına taşınmıştır. Temmuz 2026 duyurusundaki sonuç şudur: tam küme yeniden başlatmaları artık yükseltmeler sırasında uçucu durumu sıfırlamamaktadır. Bedeli kimlik doğrulama etkileşimi başına sekiz ile 10 milisaniye gecikme ile veritabanı işlemcisi ve giriş çıkış işlemlerinin kabaca iki katına çıkmasıdır.

### 2.6 Zarif kapanış, sonlandırma sinyalinden sonra ne kadar beklenmelidir

Keycloak'ın somut değerleri şunlardır.

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| Kapanış gecikmesi | Bir saniye | Sunucunun kapanmaya hazırlandığı ön kapanış fazının uzunluğudur; yük dengeleyici yeniden yapılandırması ile bağlantı boşaltması içindir |
| Kapanış zaman aşımı | 10 saniye | Çalışmakta olan HTTP isteklerinin bitmesini ile dağıtık önbelleklerin oturmasını bekleme süresidir |

26.6 ile gelen özellik şudur: HTTP yığınının zarif kapanışı, yani sonlandırma sinyali alındıktan sonra kapanışı geciktirme ile HTTP bağlantılarının boşaltılması.

Kubernetes'teki asıl yarış koşulu bu ürüne özgü değil Kubernetes'in kendi tasarımıdır: kapsül sonlanıyor işaretlenmekte, kontrol düzlemi uç nokta diliminden çıkarmakta, kubelet ön kapanış kancasını çalıştırmakta, dönünce sonlandırma sinyali göndermekte ile zarif kapanış süresi sonunda öldürme sinyali gelmektedir. Kritik nokta şudur.

> "endpoint removal and SIGTERM are not sequenced against each other. Endpoint removal has to reach every kube-proxy, every ingress controller, and every sidecar proxy in the mesh. That propagation is eventually consistent and takes real time, often a second or more on a busy cluster, while signal delivery to a local process takes microseconds."

Yani ön kapanış beklemesi uygulamanın boşaltma mantığı için değil, uç nokta yayılım boşluğunu kapatmak için vardır.

Uçuştaki OAuth akışları için özel bir durum vardır: yetkilendirme kodu akışı tek bir HTTP isteğinden uzundur. Kullanıcı yetkilendirme uç noktasına gelmekte, giriş formunu doldurmakta, kimlik doğrulama eylemine gönderi yapmakta, sonra token uç noktasına gitmektedir. Bu adımlar arası dakikalar geçebilmektedir. Durumsuz olmayan bir tasarımda düğüm ölürse akış kaybolmaktadır; Keycloak'ın çözümü tam olarak kimlik doğrulama oturumlarını veritabanına taşımak olmuştur. Argus için aynı sonuç geçerlidir: uçuştaki OAuth akışları zarif kapanış süresiyle korunmaya çalışılmamalı, veritabanına yazılmalıdır.

### 2.7 Yoklama tasarımı

Keycloak dört uç nokta sunmaktadır ile bunlar 9000 numaralı yönetim portundadır: başlatma yoklaması, yani canlılık yoklaması devralmadan önceki ilk başlatma için; canlılık yoklaması, ki başarısızsa yeniden başlatma gerekmektedir; hazır olma yoklaması, ki Keycloak'ın istekleri işlemeye hazır olup olmadığını kontrol etmektedir; ile hepsinin toplamı.

Kontrol edilenler veritabanı bağlantı havuzu durumu, küme ağ bölünmesi durumu, zarif kapanış hazırlığı ile sunucu başlatmasıdır. Doküman komut çalıştırmalı canlılık yoklaması yerine HTTP yoklaması önermektedir; karşılıklı TLS varsa yönetim istemci kimlik doğrulaması gevşetilmelidir ki yoklama istekleri istemci sertifikası istemesin.

26.6'da eklenen kritik detay şudur: başlatma ile canlılık yoklamaları göçler sırasında ayakta durumu döndürmektedir. Yani şema göçü sırasında kapsül öldürülmemektedir. Bu, uzun süren bir göçün yeniden başlatma döngüsüne girmesini önleyen zorunlu bir davranıştır.

### 2.8 Kesinti bütçesi, topoloji dağılımı ile karşıtlık

Kapsül kesinti bütçesi yalnızca gönüllü kesintileri, yani düğüm boşaltmasını korumaktadır; donanım arızası, kaynak baskısı kaynaklı tahliye ile uygulama çökmesi kapsam dışıdır. Asgari kullanılabilir ya da azami kullanılamaz değerlerinden yalnızca biri verilebilmektedir. Durumsuz bir ön yüz için önerilen asgari %90 kullanılabilirliktir. Tam kullanılabilirlik istenirse düğüm boşaltması sonsuza kadar asılı kalmaktadır. Yalnızca sağlıklı kapsüller sayılmaktadır, yani çalışan ile hazır olma yoklamasını geçmiş olanlar. Sağlıksız kapsül tahliye politikası varsayılan olarak her zaman izin vermektedir; alternatif politika bütçeyi ihlal etmiyorsa tahliye etmektedir.

Topoloji dağılımı kısıtları için kimlik sağlayıcıya uygun doğru desen şudur.

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule     # AZ dağılımı SERT kısıt
    minDomains: 3
    labelSelector: { matchLabels: { app: argus } }
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway    # node dağılımı YUMUŞAK
    matchLabelKeys: [pod-template-hash]
```

Kapsül şablonu özetine göre eşleşme, yuvarlanan güncelleme sırasında eski ile yeni kopya kümelerinin kapsüllerinin birbirini saymasını engellemektedir; dağıtımlarda kritiktir.

Topoloji dağılımıyla karşıtlık arasındaki fark şudur: dağılım azami sapma değeriyle dengeleyicidir, karşıtlık ise ikili, yani evet ya da hayır biçiminde ayırıcıdır. Dağılım çok alan için tasarlanmıştır, karşıtlık küçük kısıtlar için daha iyidir.

Keycloak operatörünün varsayılanı şudur: kapsüller bölgeler ile düğümler arasında otomatik dağılım kısıtları almaktadır ile kaynak, karşıtlık, tolerasyon, topoloji dağılımı ve öncelik sınıfı alanlarını açığa çıkarmaktadır. Varsayılan kaynak bellek isteği 1700 mebibayt ile limiti iki gibibayttır. Kesinti bütçesi yerel bir alan değildir; kendiniz yazmalısınız.

Veritabanı katmanı için CloudNativePG nettir.

> "The multi-availability zone Kubernetes architecture with three (3) or more zones is the one that we recommend for PostgreSQL usage."
> "Deploy Postgres nodes in multiples of three—ideally with one node per availability zone."

Hiçbir şey paylaşmayan mimari önerilmektedir: farklı işçi düğüm, farklı erişilebilirlik alanı ile her düğümde yerel disk, paylaşımlı birim değil. Depolama seviyesi replikasyona açıkça karşı çıkılmaktadır. Kritik sınır şudur: bu operatör kümeler arası otomatik devralma yapamamaktadır; replika kümesinin yükseltilmesi elle ya da harici orkestrasyon gerektirmektedir. Bu, tek bölge ile üç erişilebilirlik alanı tercihini doğrudan desteklemektedir.

---

## 3. Yapılandırma yönetimi

### 3.1 Sır yönetimi

Harici sır operatörü şu kaynakları tanımlamaktadır: ad alanlı ve küme geneli sır depoları, ki nasıl erişileceğini söylemektedir; harici sır, ki neyin çekileceğini söylemektedir; ile itmeli sır. Kırktan fazla sağlayıcı desteklenmektedir.

Operatörün kapsam dışı bıraktığı şey kritiktir: sırrın yaşam döngüsünü yöneten bir sır operatörü yoktur. Yani sır döndüğünde kapsülleri yeniden başlatmak bu operatörün işi değildir. Rotasyonu gerçekten çalıştırmak için ayrı bir yeniden yükleme mekanizması ya da uygulamanın kendisinin dosyayı yeniden okuması gerekmektedir.

Vault'un PostgreSQL sır motoru dinamik kimlik bilgisi, kiralama yaşam süresi ile oluşturma ifadeleriyle rol tanımı sunmaktadır.

```sql
CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
```

Statik roller bir rotasyon periyoduyla, kök kimlik bilgisi olmadan parola döndürmektedir. Uygulamaya yüklediği yük kiralama süresi dolmadan yenileme ile süre bitince yeniden bağlanma mantığıdır. Bu, bağlantı havuzlu bir Rust servisinde önemsiz değildir: havuzdaki mevcut bağlantılar geçerli kalmakta ancak yeni bağlantılar yeni parolayı kullanmalıdır.

Rust'ta bellek hijyeni şöyledir. Sır kütüphanesi düşürmede belleği sıfırlamaktadır ancak açıkça belirtmektedir: bellek kilitleme temelli daha gelişmiş koruma mekanizmaları sunulmamaktadır. Yani takas alanına ile çekirdek dökümüne karşı koruma yoktur. Sıfırlama kütüphanesi derleyicinin optimize edip atmasını engelleyen taşınabilir bir sıfırlama sunmaktadır; sınırları nettir: vektör, dizgi ile C dizgi gerçeklemeleri arka arabelleğin tüm kapasitesini sıfırlamakta ancak arabellek yeniden tahsisiyle daha önce kopya çıkarılmadığını garanti edememektedir. Dolayısıyla arabellekler doğru kapasiteyle başlatılıp yeniden tahsis engellenmelidir. Ayrıca mikromimari sızıntılara karşı hiçbir garanti verilmemektedir. Bellek güvenliği kütüphanesi ise bellek eşleme ile kilitleme, Linux'ta ek olarak döküme dahil etmeme ile çatallamada silme bayrakları sunmaktadır. İmzalama anahtarları için doğru katman budur.

### 3.2 Yapılandırma doğrulama: hızlı başarısızlık

En iyi örnek Keycloak'ın üretim modudur: ana bilgisayar adı ile TLS yoksa başlamayı reddetmektedir; başlatma kasıtlı olarak bir hata mesajıyla başarısız olmakta ile güvensiz dağıtımlar önlenmektedir. Doğru desen budur: güvensiz yapılandırma çalışmamalıdır, uyarı vermemelidir.

Zitadel'in karşıt örneği şudur: ana anahtar üretilmezse de başlamakta ancak sonradan değiştirilememektedir. Bu, sessizce yanlış kategorisinin ders kitabı örneğidir.

### 3.3 Yanlış yapılandırma tuzakları, sessizce güvensiz hâle gelen ayarlar

Birincisi yönlendirme adresi eşleştirmesidir ile kanıtlanmış bir hesap ele geçirme vektörüdür. CVE-2024-52289'da authentik yönlendirme adresini düzenli ifadeyle eşleştirmekte ile nokta karakterini kaçırmamaktaydı. Yapılandırılmış bir alt alan adı, benzer görünen başka bir alan adıyla eşleşmekteydi. Sonuç şudur.

> "If the victim is already authenticated with the IdP, they are not prompted to authenticate and are directly redirected to the attacker without further user interaction."

Zaman çizelgesi şöyledir: bildirim 8 Ekim 2024, kendi müşteri portalında kavram kanıtı 31 Ekim 2024 ile yama 21 Kasım 2024'tür. Düzeltme varsayılan katı dizgi eşleştirmesidir; düzenli ifade ancak yönetici açıkça açarsa kullanılmaktadır.

RFC 9700, gizli ile açık istemciler için tam eşleşmeyi zorunlu kılmakta ile joker karakterleri yasaklamaktadır. Yayın ayı doğrulanmamıştır.

İkincisi veren ile ana bilgisayar adıdır; token sahteciliği riskidir. Keycloak dokümanı şunu söylemektedir.

> "If the hostname was dynamically interpreted from a hostname header, an attacker could manipulate a URL in an email, redirect a user to a fake domain, and steal sensitive data. By explicitly setting the hostname option, we avoid a situation where tokens could be issued by a fraudulent issuer."

Üçüncüsü vekil başlığı güvenidir; IP izin listesini çökerten sessiz hatadır. Keycloak'ın ters vekil sayfasındaki uyarılar aynen şöyledir.

> "If these headers are incorrectly configured, rogue clients can inject false values and trick Keycloak into thinking the client is connecting from a different IP address than the actual one." — "especially critical if you do any deny or allow listing of IP addresses."
> "Ensure the proxy overwrites (not just appends to) forwarded headers to prevent clients from injecting false values."
> "Do not use `forwarded` or `xforwarded` with TLS passthrough. Misconfiguration will leave Keycloak exposed to security vulnerabilities."
> "Restrict network access so that Keycloak accepts connections only from the proxy"

Bu, kaba kuvvet sayaçlarını ile hız sınırını sessizce işe yaramaz hâle getiren tuzağın ta kendisidir.

Dördüncüsü yönetim konsolunun internete açık olmasıdır. Keycloak, yönetim API'sinin ile arayüzünün farklı bir ana bilgisayar adı veya yol üzerinde sunulmasını önermekte, saldırı yüzeyini azaltmak içindir; ayrı bir ana bilgisayar adı ayarıyla ayrılmaktadır.

### 3.4 Keycloak üretim modu kontrol listesi: ne zorlamakta, ne zorlamamaktadır

| Madde | Durum |
|---|---|
| TLS ile HTTPS | Zorunludur; HTTP üretimde kapalıdır |
| Ana bilgisayar adı | Zorunludur |
| Üretim veritabanı | Belgelenmiştir ancak teknik olarak zorlanmamaktadır |
| Ters vekil | Önerilmektedir |
| Hazır olma yoklaması | Önerilmektedir |
| Yönetim ile genel ana bilgisayar adı ayrımı | Yalnızca öneridir |
| Yük atma ile azami kuyruk uzunluğu | Yalnızca öneridir |
| En az iki örnek | Yalnızca öneridir |

Bu tablo Argus için bir fırsat listesidir: yalnızca öneri satırlarının çoğu ölümcül yanlış yapılandırmalardır. Argus bunları başlangıçta zorlayabilir ya da en azından bir güvensiz bayrağı olmadan başlatmayı reddedebilir.

---

## 4. Yükseltme ile şema göçü

### 4.1 PostgreSQL'de hangi işlem kilitlemektedir

Tablo değiştirme dokümanının notlar bölümünden kilit seviyeleri şunlardır: erişimi dışlayan kilit varsayılandır, aksi belirtilmedikçe her alt komut bunu almaktadır; paylaşımlı güncelleme dışlayan kilit istatistik ayarı, kümeleme, öznitelik seçenekleri, kısıt doğrulama ile bölüm eklemede alınmaktadır; paylaşımlı satır dışlayan kilit yabancı anahtar ekleme ile tetikleyici etkinleştirme veya devre dışı bırakmada alınmaktadır.

Yeniden yazma gerektirmeyen, yani yalnızca metadata işlemleri şöyledir.

> "When a column is added with `ADD COLUMN` and a non-volatile `DEFAULT` is specified, the default value is evaluated at the time of the statement and the result stored in the table's metadata... making the `ALTER TABLE` very fast even on large tables."

Uçucu olmayan varsayılanla sütun eklemede yeniden yazma yoktur, PostgreSQL 11 ve üstünde. Uçucu varsayılanla tam yeniden yazma olmaktadır. Saklanan üretilmiş sütun ile kimlik sütunu yeniden yazma gerektirmektedir. Sanal üretilmiş sütun asla yeniden yazma gerektirmemektedir. Tip değişiminde, dönüşüm yan tümcesi içeriği değiştirmiyorsa ile eski tip yeni tipe ikili olarak zorlanabiliyorsa yeniden yazma gerekmemektedir; aksi hâlde tablo ile tüm indeksleri yeniden yazılmaktadır.

Genişlet ile daralt deseninin PostgreSQL'deki altın kuralı şudur.

> "The main purpose of the `NOT VALID` constraint option is to reduce the impact of adding a constraint on concurrent updates. With `NOT VALID`, the `ADD CONSTRAINT` command does not scan the table and can be committed immediately."

İki adımlı desen şöyledir.

```sql
ALTER TABLE distributors ADD CONSTRAINT distfk FOREIGN KEY (address)
    REFERENCES addresses (address) NOT VALID;     -- anında commit
ALTER TABLE distributors VALIDATE CONSTRAINT distfk;  -- SHARE UPDATE EXCLUSIVE
```

İki tehlikeli detay vardır. Birincisi yeniden yazan formlar çok sürümlü eşzamanlılık denetimi açısından güvenli değildir: bir tablo yeniden yazıldıktan sonra, yeniden yazmadan önce alınmış bir anlık görüntü kullanan eşzamanlı işlemlere tablo boş görünmektedir. İkincisi yeniden yazma geçici olarak iki katına kadar disk alanı gerektirmektedir.

PostgreSQL 18'in getirdiği, sıfır kesinti için en önemli değişiklik şudur: boş olmama kısıtları artık gerçek kısıt kayıtlarıdır ile isimlendirilebilmektedir. Doğrulanmamış olarak boş olmama kısıtı eklenebilmekte, sonra daha hafif bir kilit altında doğrulanabilmektedir. Daha önce bu işlem tüm tabloyu en ağır kilit altında taramaktaydı. Ayrıca geçerli bir kontrol kısıtı boş olmadığını kanıtlıyorsa tablo taraması atlanabilmektedir.

PostgreSQL 18'in yükseltme aracı planlayıcı istatistiklerini korumaktadır, yani yükseltme sonrası uzun bir analiz gerekmemektedir; paralel kontroller ile en hızlı yöntem olan dizin takası modu bulunmaktadır.

### 4.2 Rust göç araçları, olgunluk ile geri alma

| Araç | Geri alınabilir mi | Notlar |
|---|---|---|
| sqlx | Evet; yukarı ile aşağı dosyalarıyla, sonraki tüm göçler de geri alınabilir olmaktadır. Çalıştırma, geri alma ile bilgi komutları ile kaynak dizini seçeneği bulunmaktadır | Dosya adı sürüm ile açıklamadan oluşmaktadır; sürüm pozitif bir tam sayıdır |
| refinery | Hayır; tasarımı Flyway'e dayanmakta ile onun eski felsefesini paylaşmaktadır: bir göçü geri almak için yeni bir göç üretmeniz gerekmektedir | Birçok sürücüyü desteklemekte ile sqlx ile de bir yapılandırma üzerinden çalışmaktadır |
| diesel göçleri | Evet; yukarı ile aşağı vardır | Diesel'in kendi diline bağlıdır |

sqlx'in tavsiye kilidiyle eşzamanlı göç koruması ile sağlama toplamı ve kirli durum davranışı doküman üzerinden doğrulanamamıştır; kaynak koddan teyit edilmelidir.

Pratik gerçek şudur: aşağı göçler üretimde nadiren çalıştırılmaktadır. Sıfır kesintinin gerçek cevabı geri alma değil genişlet ile daralttır. Martin Fowler'ın evrimsel veritabanı tasarımı tanımı şudur.

> "A transition phase is a period of time when the database supports both the old access pattern and the new ones simultaneously."

Örnek şudur: tablo yeniden adlandırılmakta, eski adla bir görünüm oluşturulmakta, tüketiciler kendi hızlarında geçmekte ile sonra görünüm düşürülmektedir.

### 4.3 Keycloak'ın yükseltme deneyimi

Ana ile küçük sürüm yükseltmeleri çevrimdışı zorunludur: her sitedeki dağıtım yükseltme prosedürü sırasında çevrimdışı alınmakta ile sitelerde farklı ana veya küçük sürümler çalıştırmak desteklenmemektedir.

Yama yükseltmeleri sıfır kesintilidir; 26.6'da desteklenen seviyeye terfi etmiş ile varsayılan açık olmuştur.

Elle göç mümkündür: bir göç stratejisi ayarıyla SQL dosyası üretilebilmektedir. Strateji değerleri elle, güncelle ile doğrula, ayrıca boş başlat ile göç dışa aktarımıdır.

Etki büyüklüğü şudur: 43252 numaralı konuya göre bu özelliğin hedefi topluluk kullanıcıları için yıllık Keycloak kesintilerini yaklaşık yirmiden dörde indirmektir. Yılda 20 planlı kesinti, Keycloak operatörünün 2025 öncesi gerçeğiydi.

Aynı konuda belirtilen iki engel şudur: dağıtık önbellek kütüphanesinin ilgili sürümü sıfır kesintili yükseltme yapamamaktadır, çünkü protokol ile serileştirme geriye dönük uyumluluğu gerekmektedir; ile uyumsuz göçler ve indeks oluşturma kilitleri, yuvarlanan güncellemeler sırasında eski örneklerin kümeye katılmasını engelleyebilmektedir.

Keycloak'ın göçlerinin yalnızca ileri yönlü, geri alınamaz olduğu ile geri yükleme gerektirdiği iddiası ikincil bir kaynaktandır ile resmî dokümanda doğrulanamamıştır; ancak strateji seçeneklerinde aşağı göç bulunmaması bunu desteklemektedir.

### 4.4 Bir önceki sürümle uyumluluk: iki sürüm aynı veritabanına yazarken

Keycloak'ın 26.6 ile 26.7'de vardığı çözüm üç parçalıdır.

1. Uyumluluk metadata'sıyla önceden karar verilmektedir: eski yapılandırmayla metadata üretilmekte, yeni yapılandırmayla kontrol edilmekte ile bir çıkış kodu alınmaktadır. Yuvarlanan güncelleme ancak sürüm aynıysa, özellik anahtarları değişmemişse ile kümeleme veya veri bütünlüğünü etkileyen yapılandırma değişmemişse mümkündür.
2. Uçucu durum veritabanına taşınmaktadır: durumsuz önizlemede kimlik doğrulama oturumları, eylem token'ları ile kaba kuvvet sayaçları veritabanındadır.
3. Veritabanı destekli giden kutusuyla önbellek geçersizleştirmesi yapılmaktadır: sistem yoklamalı bir veritabanı kuyruk tablosu kullanmakta, kümeler arası geçersizleştirme mesajları bu giden kutusu üzerinden varsayılan 100 milisaniyelik bir aralıkla yayılmakta ile kümeler arası doğrudan ağ bağımlılıkları ortadan kalkmaktadır.

Çok kümeli ön koşullar senkron replike edilmiş bir veritabanı ile siteler arası 10 milisaniyenin altında gecikmedir; duyuru açıkça tutarlılığı erişilebilirliğe tercih ettiğini söylemektedir.

Kıyaslamadan gecikme kanıtı şudur: 1 Ekim 2025 tarihli 26.4 performans kıyaslamasında 20 milisaniyelik gidiş dönüş eklenince yanıt süresi 26.3'te 51 milisaniyeden 1076 milisaniyeye fırlamış ile 26.4'te 130 milisaniyeye düşürülmüştür. Ağ gecikmesi çok bölgeli bir kimlik sağlayıcıda birinci sınıf bir tasarım kısıtıdır.

### 4.5 Sürüm politikaları

| Proje | Politika |
|---|---|
| Keycloak | Düzeltmeler yüksek şiddetli sorunlar için güncel ana ve küçük sürüme, düşük şiddetliler için bir sonraki sürüme uygulanmaktadır. Uzun dönem destek isteniyorsa Red Hat derlemesi kullanılmalıdır. Güncel sürüm 26.7.3'tür |
| Zitadel | Ana sürüm üç ayda bir, küçük sürüm iki haftada bir, yama gerektikçe çıkmaktadır; ana sürüm öncesi bir yayın adayı verilmektedir ile küçük sürümler arası geriye dönük uyumluluk bulunmaktadır. Sürüm düşürme, yükseltmeden sonra token almış tüm kullanıcıları her zaman çıkış yaptırmaktadır |
| Ory | Açık kaynak sürüm deney ile kritik olmayan iş yükleri için ücretsizdir; hizmet seviyeli güvenlik sürümleri ile açık yamaları kurumsal lisansla gelmektedir |

Keycloak ile Zitadel için formel uzun dönem destek ile destek penceresi sayfaları bulunamamıştır; ilgili adresler 404 dönmüştür. Doğrulanmamıştır.

---

## 5. Yedekleme ile felaket kurtarma

### 5.1 PostgreSQL yedekleme

pgBackRest şunları sunmaktadır: tam, fark ile artımlı yedek; WAL arşivleme, eşzamansız yığın yüklemeyle uzak depo iş hacmi; zaman damgası, günlük sıra numarası, işlem kimliği ya da adlandırılmış kurtarma noktasıyla zaman içinde geri yükleme; fark geri yüklemesi, ki SHA-1 özet karşılaştırmasıyla değişmemiş dosyaları korumaktadır ve azami süreç seçeneğiyle birleştiğinde çok verimlidir, kurtarma süresini en çok düşüren tek özelliktir; istemci tarafında AES-256 depo şifrelemesi; yerel artı bulut depolarının eşzamanlı kullanımıyla coğrafi yedeklilik; ile depo bütünlüğü doğrulaması. Dokümanın kendi tavsiyesi şudur: hangi deponun en verimli olacağını yalnızca geri yükleme testi belirleyebilmektedir.

wal-g Apache 2.0 lisanslıdır, yaklaşık 4.200 yıldızlıdır ile aktiftir; dört sıkıştırma algoritması, fark yedeği, üç şifreleme seçeneği, hız sınırlama ile metrik desteği sunmaktadır. PostgreSQL dışında birçok veritabanını desteklemektedir.

Mantıksal döküm ile zaman içinde geri yükleme karşılaştırması şudur: döküm mantıksaldır, taşınabilirdir ile seçicidir, ancak kurtarma noktası hedefi son döküme kadardır, yani saatlerdir. Zaman içinde geri yüklemeyle kurtarma noktası hedefi son arşivlenen günlük kesimidir, yani saniyeler ile dakikalardır. Bir kimlik sağlayıcı için yalnızca döküm yeterli değildir: kimlik verisi kaybı hesap kaybıdır.

### 5.2 İmzalama anahtarlarının yedeklenmesi, sektörün en zayıf noktası

Keycloak'ta anahtar durumları aktif, yani yeni imza üretmektedir; pasif, yani mevcut imzaları doğrulamaktadır; ile devre dışıdır. Rotasyon önerisi üç ile altı ayda bir yeni anahtar üretmek ile eskisini bir ile iki ay sonra kaldırmaktır. Sağlayıcılar otomatik üretim, PEM içe aktarımı ile ana bilgisayardaki bir anahtar deposu dosyasından okumadır.

Yedekleme prosedürü dokümante edilmemiştir. Yalnızca ele geçirme durumunda yeni anahtar üretmek ile bir iptal politikası itmek denmektedir.

Yani otomatik üretim kullanan bir Keycloak'ta imzalama anahtarları veritabanının içindedir; veritabanı yedeği kaybolursa anahtarlar da kaybolmaktadır. Anahtar deposu kullanılırsa anahtar veritabanı dışındadır ancak kapsülün dosya sistemindedir ile veritabanı yedeğiyle senkron değildir. Her iki seçenek de operatöre tuzak kurmaktadır.

Zitadel'in daha keskin tuzağı ana anahtardır: hareketsiz veriyi şifrelemekte ile ilk kurulumdan sonra değiştirilememektedir.

Şifrelediği alanlar alan adı doğrulama belirteçleri, kimlik sağlayıcı yapılandırmaları, OIDC token ile oturumları, SAML doğrulamaları, tek kullanımlık şifre sırları, kısa mesaj ile posta kimlik bilgileri, kullanıcı verisi ile siteler arası istek sahteciliği çerezleridir. Ana anahtar kaybı, veritabanı yedeği elinizde olsa bile kurtarılamaz veri demektir. Üstelik ana anahtar bileşim komutunda sessizce üretilmektedir.

Donanım güvenlik modülü ya da anahtar yönetim servisi seçeneğinde AWS KMS şunları sunmaktadır: imzalama için RSA'nın üç boyutu, üç NIST eliptik eğrisi, Ed25519, bir Koblitz eğrisi ile kuantum sonrası imza algoritmalarının üç seviyesi. Özel anahtar servisi hiç şifresiz terk etmemektedir. Açık anahtar indirilip servis dışında doğrulama yapılabilmektedir; yani anahtar seti uç noktası her istekte servise gitmemektedir. Ters yüzü şudur: özel anahtar hiç dışa aktarılamamaktadır; felaket kurtarma planınız çok bölgeli anahtar ya da içe aktarılmış anahtar materyaliyle yapılmalıdır, yoksa bölge kaybı anahtar kaybıdır.

Anahtar kaybının etkisi asimetriktir: veritabanı kaybı kullanıcı kaybıdır, ki kötüdür. İmzalama anahtarı kaybı ise tüm çıkarılmış token'ların, yenileme token'larının ile oturumların ölmesi, ayrıca hiçbir bağlı tarafın eski JWT'leri doğrulayamaması demektir, ki felakettir. Bu yüzden anahtarların yedekleme yaşam döngüsü veritabanınkinden ayrı olmalıdır.

### 5.3 Kurtarma tatbikatı, neyi test etmek gerekmektedir

pgBackRest'in kendi ifadesi tatbikatı zorunlu kılmaktadır. Bir kimlik sağlayıcı için test edilmesi gerekenler şunlardır.

1. Zaman içinde geri yüklemeyle belirli bir ana geri dönme, yalnızca tam geri yükleme değil.
2. Geri yüklenen veritabanıyla birlikte imzalama anahtarlarının da geri gelmesi; anahtar ayrı bir sistemdeyse iki geri yüklemenin tutarlı bir noktada birleşmesi.
3. Geri yükleme sonrası anahtar setinin aynı anahtar kimliklerini sunması; aksi hâlde bağlı taraflar önbelleklerindeki anahtarla doğrulayamamaktadır.
4. Göç sürümünün ikili dosya sürümüyle uyumu, yani eski veritabanı ile yeni ikili dosya.
5. Fark geri yüklemesiyle kurtarma süresinin ölçülmesi, paralellik ayarlı ile ayarsız.
6. Depo bütünlüğünün doğrulanması.

### 5.4 Kiracı bazında geri yükleme, dürüst cevap

Geri yükleme aracının dokümanı seçici geri yükleme seçenekleri vermektedir: tablo, şema, şema hariç tutma, yalnızca veri, liste dosyası ile süzgeç.

Ancak uyarılar ölümcüldür.

> "When `-t` is specified, pg_restore makes no attempt to restore any other database objects that the selected table(s) might depend upon. Therefore, there is no guarantee that a specific-table restore into a clean database will succeed."

> "While pg_dump's `-t` flag will also dump subsidiary objects (such as indexes) of the selected table(s), pg_restore's `-t` flag does not include such subsidiary objects."

> "pg_restore cannot restore large objects selectively... all large objects will be restored, or none of them."

Yalnızca veri seçeneğiyle yabancı anahtar ile tetikleyici sorunları için tetikleyicileri devre dışı bırakmak gerekmektedir.

Sonuç şudur: tek şemada, bir kiracı kimliği sütunuyla çok kiracılı bir tasarımda satır seviyesinde tek bir kiracıyı geri almak bu araçla mümkün değildir. Gerçekçi yollar şunlardır.

Birincisi kiracı başına şemadır; şema bazlı geri yükleme gerçekten çalışmaktadır ancak binlerce kiracıda katalog şişmektedir. İkincisi yan geri yükleme ile mantıksal kopyalamadır: yedek ayrı bir örneğe geri yüklenmekte, oradan kiracı kimliğiyle satırlar hedef veritabanına kopyalanmaktadır. Bağımlılık sırasını ile yabancı anahtarları kendiniz yönetmelisiniz. En yaygın ile en gerçekçi yoldur. Üçüncüsü uygulama seviyesinde yumuşak silme ile denetim günlüğüdür; geri yükleme ihtiyacını en baştan azaltmaktadır.

---

## 6. Kaynak gereksinimleri ile boyutlandırma

### 6.1 Keycloak'ın kapasite formülleri, birincil kaynak

| Metrik | Formül | Test edilen üst sınır |
|---|---|---|
| Parolayla giriş | Saniyede her 15 parola tabanlı giriş için kümeye bir sanal işlemci ayrılmalıdır | Saniyede 300'e kadar |
| İstemci kimlik bilgisi yetkisi | Saniyede her 120 yetki için bir sanal işlemci | Saniyede 2.000'e kadar |
| Yenileme token'ı | Saniyede her 120 istek için bir sanal işlemci | Saniyede 435'e kadar |
| Kapsül başına bellek | Alan verisi önbellekleri ile 10.000 önbeleklenmiş oturum dahil temel bellek kullanımı 1250 megabayttır | — |
| Yığın | Bellek limitinin %70'i yığın tabanlı belleğe ayrılmakta ile yaklaşık 300 megabayt yığın dışı bellek kullanılmaktadır | — |
| Pay | İşlemci kullanımı için ani artışları karşılamak üzere %150 ek pay bırakılmalıdır | — |
| Veritabanı | Saniyede her 100 giriş, çıkış ya da yenileme isteği için 1400 yazma giriş çıkış işlemi bütçelenmeli ile 0,35 ile 0,7 sanal işlemci ayrılmalıdır | — |

Test ortamı belirli bir bulut makine havuzu, OpenShift, çok bölgeli Aurora PostgreSQL ile OpenJDK 21'dir.

En önemli sayı 15'e karşı 120'dir. Parola girişi istemci kimlik bilgisi yetkisinden sekiz kat pahalıdır. Fark neredeyse tamamen parola özetlemedir. Bu, Argus'un boyutlandırma modelinin merkezine Argon2'yi koyması gerektiğini kanıtlamaktadır.

Kıyaslama rakamları, 1 Ekim 2025, şöyledir: üç kapsül, 24 ile 74 sanal işlemci, dört ile sekiz gigabayt bellek, OpenShift ile Aurora PostgreSQL 17.5 üzerinde saniyede 12.000 istek, yani saniyede 2.000 giriş artı 10.000 yenileme. Keycloak test edilen aralıkta neredeyse doğrusal olarak dikey ölçeklenmektedir. Önbellek 10.000'den 200.000 girdiye çıkarılınca Aurora tepe işlemcisi %77,77'den %63,77'ye düşmüştür.

### 6.2 Argon2 ile işçi havuzu boyutlandırması

OWASP'ın eşdeğer parametre setleri, hepsi paralellik bir olmak üzere, şöyledir.

| Bellek, kibibayt | Bellek, mebibayt | Yineleme |
|---|---|---|
| 47104 | 46 | 1 |
| 19456 | 19 | 2 |
| 12288 | 12 | 3 |
| 9216 | 9 | 4 |
| 7168 | 7 | 5 |

OWASP hedefi bir özetin hesaplanmasının bir saniyeden az sürmesidir.

Keycloak'ın seçimi şudur: Haziran 2024'teki 25.0.0 sürümünden beri varsayılan Argon2'dir ile özet isteği başına yedi megabayt kullanılmaktadır, yani OWASP'ın son satırıdır. Ayrıca paralel özet hesaplaması varsayılan olarak sanal makinenin gördüğü çekirdek sayısıyla sınırlanmaktadır. Keycloak 24'te PBKDF2 yinelemesi 27.500'den 210.000'e çıkarılmış ile işlemci zamanı on kattan fazla artmıştı; Argon2 ile neredeyse aynı işlemci zamanında daha iyi güvenlik sağlanmaktadır.

OWASP'ın açık hizmet reddi uyarısı şudur: iş faktörü aşırıysa saldırgan çok sayıda giriş denemesiyle sunucunun işlemcisini tüketerek bir hizmet reddi saldırısı yapabilmektedir.

Zitadel aynı gerçeği kabul etmektedir: parola özetleme işlemci tepeleri yaratabilmektedir, bunun için dört işlemci çekirdeği ayrılmalıdır.

Argus için türetme, yedi megabayt ile beş yineleme parametreleriyle, şöyledir. Eşzamanlı N özet, N çarpı yedi megabayt tepe bellek demektir; 64 eşzamanlı istek yalnızca özet arenaları için 448 megabayt eder. Argon2 işlemci bağımlı ile bloklayıcıdır; eşzamansız çalışma zamanında asla doğrudan çalıştırılmamalıdır, ayrı bir sınırlı iş parçacığı havuzunda ile bir semaforla sınırlı olmalıdır. Havuz boyutu yaklaşık fiziksel çekirdek sayısı kadar olmalı, kuyruk derinliği kapsül belleğine göre sınırlanmalı ile kuyruk dolunca 429 ile yük atılmalıdır, ki Keycloak'ın azami kuyruk mantığıdır. Kapsül bellek limiti temel değer artı azami eşzamanlı özet çarpı yedi megabayt artı bağlantı havuzu artı önbellek olmalıdır. Bu, Rust'ta sanal makinesiz olarak Keycloak'ın 1250 megabaytının çok altında tutulabilmektedir; asıl kazanç buradadır.

### 6.3 PgBouncer ile hazırlanmış ifade sorunu 2026'da çözülmüş müdür

Evet, 1.21.0'dan beri.

> "Since version 1.21.0 PgBouncer can track prepared statements in transaction pooling mode and make sure they get prepared on-the-fly on the linked server connection. To enable this feature, `max_prepared_statements` needs to be set to a non-zero value."

Azami hazırlanmış ifade sayısı, tek bir sunucu bağlantısında aktif tutulan ifade sayısıdır ile en az kullanılan önbellek olarak çalışmaktadır; sıfır kapalı demektir. 1.22.0 sürümünde işlem havuzlamada bu destek açıkken ilgili temizleme komutları da desteklenmeye başlanmıştır. Kritik sınır şudur: bu yalnızca veritabanı protokolü üzerinden yönetilen hazırlanmış ifadelerde çalışmakta ile basit metin sorgusu olarak gönderilen hazırlama komutlarını ele alamamaktadır.

sqlx genişletilmiş sorgu protokolünü kullandığı için bu uyumludur. sqlx ile işlem havuzlama kombinasyonunun 2026'daki pratik durumu birincil kaynaktan doğrulanamamıştır.

### 6.4 Küçükten büyüğe topoloji

| Ölçek | Öneri | Dayanak |
|---|---|---|
| Yaklaşık 100 kullanıcı, ev laboratuvarı ya da iç araç | Tek düğüm, tek PostgreSQL, günlük döküm artı günlük arşivi. Kanidm ya da Casdoor modeli tek konteynerdir. Zitadel'in referansına göre uygulama için bir işlemci ile 512 megabayt fazlasıyla yeterlidir | Zitadel dağıtım genel bakışı |
| Yaklaşık 100 bin kullanıcı | Üç erişilebilirlik alanında üç durumsuz düğüm, birincil artı iki senkron bekleme düğümlü PostgreSQL, işlem modunda havuzlayıcı ile bulut depolamaya yedek. Zitadel referansına göre veritabanı saniyede 100 istek için yaklaşık bir çekirdek ile çekirdek başına dört gigabayt bellek gerektirmekte; üç düğümlü yüksek erişilebilirlikte düğüm başına dört çekirdek ile 16 gigabayt önerilmektedir | Zitadel üretim dokümanı |
| Yaklaşık 10 milyon kullanıcı | Keycloak'ın gerçek verisi üç kapsül ile 24 ile 74 sanal işlemcide saniyede 12.000 istektir. Argon2 iş yükü için ayrı bir düğüm havuzu ile azami kuyruk ayarıyla yük atma, okuma replikaları ile büyütülmüş önbellek gerekmektedir; önbellek büyütmesi veritabanı işlemcisini %14 düşürmüştür. Çok bölgeli yönetilen PostgreSQL ya da üç alanlı operatör kullanılmalıdır | Keycloak kıyaslaması ile boyutlandırma dokümanı |

Senkron yeter sayı işlemesi şöyledir.

> "The keyword `ANY`, coupled with `num_sync`, specifies a quorum-based synchronous replication and makes transaction commits wait until their WAL records are replicated to at least `num_sync` listed standbys."

Öncelik tabanlı varyantta bir bekleme düğümü düşerse listedeki bir sonraki en yüksek öncelikli ile anında değiştirilmektedir.

> "Even when synchronous replication is enabled, individual transactions can be configured not to wait for replication by setting the `synchronous_commit` parameter to `local` or `off`."

Bu, Argus için önemli bir kaldıraçtır: senkron işleme ayarı işlem bazında yapılabilmektedir. Kullanıcı kaydı, parola değişikliği ile anahtar rotasyonu yeter sayı beklemeli; kaba kuvvet sayacı, son giriş zamanı ile telemetri yerel işlemeyle yazılmalıdır. Böylece senkron replikasyonun gecikme bedelini yalnızca gerçekten dayanıklılık gereken yazmalar ödemektedir.

---

## 7. Açık kaynak proje operasyonu

### 7.1 Lisans seçimi, kimlik sağlayıcı alanında kim ne yapmıştır

| Proje | Lisans | Hareket |
|---|---|---|
| Keycloak | Apache 2.0 | Değişmemiştir; uzun dönem destek ayrı bir ticari ürün üzerinden verilmektedir |
| Zitadel | Apache 2.0'dan AGPL 3.0'a, üçüncü ana sürümle 31 Mart 2025 yürürlüklü | Hizmet sağlamak için yapılan değişikliklerin topluluğa açılması gerekmektedir. Kademelidir: yalnızca yeni katkılar yeni lisanstadır, önceki sürümler eski lisansta kalmaktadır, geliştirme kitleri mevcut lisansını korumaktadır ile ticari lisans mevcuttur |
| Ory | Apache 2.0 artı kurumsal lisans | Açık çekirdektir: hizmet seviyeli güvenlik sürümleri, yüksek performanslı havuzlama ile bazı veritabanı destekleri kurumsal lisanstadır. İş açısından kritik bir sistemde çalıştırılıyorsa ticari lisans önerilmektedir |
| SuperTokens | Çekirdek Apache 2.0 artı lisans anahtarlı premium | — |
| Casdoor | Apache 2.0 | — |
| Kanidm | MPL 2.0 | Dosya bazlı karşılıklı paylaşımdır; AGPL'den ılımlı, Apache'den korumalıdır |
| Pocket ID | BSD iki maddeli | — |

Gözlem şudur: kimlik sağlayıcı alanında saf izin verici lisans azınlıkta ile azalmaktadır. İki baskın strateji vardır: AGPL artı ticari çift lisans ile Apache 2.0 artı kapalı bir kurumsal katman. Keycloak'ın Apache 2.0 kalabilmesinin nedeni ticarileşmenin ayrı bir üründe olmasıdır.

Argus için pratik sonuç şudur: Apache 2.0, bağlı taraf ile geliştirme kiti ekosisteminin benimsemesi için en düşük sürtünmedir; ancak kimlik sağlayıcı sunucusu için AGPL ile geliştirme kitleri için Apache 2.0, yani Zitadel'in yaptığı ayrım, hem benimsenmeyi korumakta hem bulut bedavacılığını sınırlamaktadır. MPL 2.0 bir ara yoldur: dosya bazlıdır ile ağ üzerinden kullanımı tetiklememektedir.

### 7.2 Avrupa Birliği siber dayanıklılık yasası, tarihler ile gerçek yükümlülük

Görev tanımındaki bir varsayım düzeltilmelidir: 11 Eylül 2026 raporlama yükümlülüğü açık kaynak vekilleri için o tarihte başlamamaktadır.

Yasanın yürürlük maddesine göre 11 Haziran 2026'da dördüncü bölüm uygulanmaya başlamakta, 11 Eylül 2026'da 14. madde yürürlüğe girmekte ile 11 Aralık 2027'de düzenlemenin tamamı uygulanmaktadır.

ENISA'nın tek raporlama platformu sıkça sorulan soruları bunu netleştirmektedir: üreticiler 11 Eylül 2026'dan itibaren raporlamakta, açık kaynak yazılım vekilleri raporlama yükümlülüklerine 11 Aralık 2027'de katılmaktadır.

Nedeni yapısaldır: 14. madde üreticilere doğrudan uygulanmakta; vekilleri bu maddeye bağlayan hüküm 24. maddenin üçüncü fıkrasıdır ile 24. madde ancak 11 Aralık 2027'de uygulanmaya başlamaktadır.

Raporlama süreleri her iki grup için aynıdır: farkına varıldığında 24 saat içinde erken uyarı, 72 saat içinde zafiyet ya da olay bildirimi ile düzeltici önlem hazır olduktan sonra 14 gün veya 72 saatlik bildirimden sonra bir ay içinde nihai rapor. Portal EU giriş hesabıyla ile atanmış bir temsilci üzerinden kullanılmaktadır. Birlik genelinde şube yapısı ne olursa olsun olay başına tek bildirim yapılmaktadır. Bildirim üreticinin ana yerleşimindeki ulusal müdahale ekibine gitmekte, oradan diğer üye devletlere dağıtılmaktadır.

Aktif olarak istismar edilen zafiyet tanımı, kötü niyetli bir aktör tarafından istismar edildiğine dair güvenilir kanıt bulunmasıdır.

Kapsam dışı kalmak konusunda Komisyon sayfası şunu söylemektedir: üreticileri tarafından paraya çevrilmeyen özgür ile açık kaynak yazılım niteliğindeki dijital öğeli ürünler kapsam dışıdır. Kontrol etmedikleri projelere kaynak kodu katkısı yapan bireysel geliştiriciler de muaftır.

Vekil tanımı ile 24. madde yükümlülükleri şöyledir. Vekil, ticari faaliyetlere yönelik belirli bir özgür ve açık kaynak yazılımın geliştirilmesine sürdürülebilir biçimde ile sistematik olarak destek veren ve bu ürünlerin yaşayabilirliğini sağlayan tüzel kişilerdir. Birinci fıkra belgelenmiş ile doğrulanabilir bir siber güvenlik politikası istemektedir: zafiyetlerin belgelenmesi, ele alınması ile giderilmesi, topluluk içinde bilgi paylaşımı ile gönüllü zafiyet bildiriminin teşviki. İkinci fıkra pazar gözetim otoriteleriyle iş birliğini ile talep hâlinde politikanın otoritenin kolayca anlayabileceği bir dilde sunulmasını istemektedir. Üçüncü fıkra, geliştirmede rol alınıyorsa aktif istismar edilen zafiyet ile geliştirme altyapısını etkileyen ciddi olaylar için bildirim yükümlülüğü getirmektedir. Olmayanlar şunlardır: uygunluk işareti yoktur, uygunluk değerlendirmesi yoktur, teknik dokümantasyon saklama zorunluluğu yoktur ile ilgili madde uyarınca idarî para cezası yoktur.

Açık düzenleyici uyum çalışma grubunun beyaz kâğıdındaki pratik rehber şudur: vekil, projeden ayrı tescilli bir tüzel kişi olmalıdır. Bugün çoğu açık kaynak projesinin, özellikle küçük olanların bir vekili yoktur; vekili olmayan küçük projelerin bir yükümlülüğü de yoktur. Yapılacaklar güvenlik politikasını bir güvenlik dosyasında yayımlamak, zafiyet bildirimi ile önceliklendirme sürecini tanımlamak, atanmış müdahale ekibini belgelemek ile olay bildirimlerini kimin yapacağını belirlemektir. Kullanıcılar zamanında, tercihen makine okunabilir bir formatta bilgilendirilmelidir.

### 7.3 Zafiyet bildirimi ile güvenlik açığı numarası

GitHub bir numaralandırma otoritesidir; taslak bir danışmanlık oluştururken bir numara talep edilebilmekte ile talep genellikle 72 saat içinde incelenmektedir. Numara talebi danışmanlığı açık yapmamakta; yayımlanana kadar gizli kalmaktadır. Gizli bir çatalda gizli düzeltme ile özel zafiyet bildirimi akışı bulunmaktadır. Yayımlanan danışmanlık GitHub danışmanlık veritabanına girmekte ile bağımlılık uyarılarını tetiklemektedir. Bir kısıt vardır: proje başka bir numaralandırma otoritesinin kapsamındaysa GitHub numara atayamamaktadır.

Argus için pratik sonuç şudur: kendi numaralandırma otoritenizin olmasına gerek yoktur. GitHub otoritesi, bir güvenlik dosyası ile özel zafiyet bildirimi hem yasanın belgeleme, ele alma ve giderme gereksinimini hem numaralandırmayı karşılamaktadır.

Örnek olarak Keycloak'ın politikası şöyledir: bir güvenlik posta listesi kullanılmakta ile yedi iş günü içinde alındı bildirimi yapılmaktadır. Talep edilenler bir kavram kanıtı, yani yalnızca tarayıcı çıktısı değil, asgari yeniden üretilebilir bir örnek, düz metin gövde ile bulgu başına ayrı rapordur. Deneysel özellikler genellikle numara almamakta, normal açık hatalar olarak yönetilmektedir. Üçüncü taraf kütüphane açıkları bir konu olarak açılmaktadır. Araştırmacıya kredi isim, takma ad, şirket ya da kullanıcı adıyla verilmekte; e-posta ile bağlantıyla değil.

### 7.4 Sürüm imzalama, tedarik zinciri seviyeleri ile yeniden üretilebilir derlemeler

Sigstore ile cosign şöyle çalışmaktadır: anahtarsız modda bir kimlik sağlayıcı üzerinden kısa ömürlü bir sertifika alınmakta ile imza bir şeffaflık günlüğüne yazılmaktadır. Komut basittir. Anahtar yönetim servisi adresleri desteklenmektedir. İmzalar OCI referans verenler şartnamesine göre eklenmekte, bir ağaç komutuyla bulunmakta ile bir temizleme komutuyla silinmektedir. Tek bir konteynere birden çok imza eklenebilmektedir.

Tedarik zinciri seviyeleri şöyledir: birinci seviyede bir köken bilgisi bulunmakta ancak eksik veya imzasız olabilmektedir. İkinci seviyede barındırılan bir derleme platformu kullanılmakta, köken bilgisi dijital olarak imzalanmakta ile tüketici doğrulamaktadır; derlemeden sonra kurcalamayı önlemektedir. Üçüncü seviyede sertleştirme vardır: aynı proje içinde bile çalıştırmaların birbirini etkilemesini önleyen güçlü kontroller ile köken bilgisini imzalamak için kullanılan sır materyalinin derleme adımlarından erişilemez olması gerekmektedir.

Önemli bir nokta vardır: bu seviye tanımları hermetik ya da yeniden üretilebilir derleme gerektirmemektedir. GitHub Actions, kimlik sağlayıcı tümleşmesi ile anahtarsız imzalamayla ikinci seviye makul biçimde erişilebilirdir; üçüncü seviye için izole bir koşucu gerekmektedir.

Rust'ta yeniden üretilebilir derleme gerçekçi midir sorusunun cevabı şudur: Rust ile cargo, yeniden üretilebilir derlemeler projesinin sürekli tümleştirme test listesinde yoktur; listede birçok dağıtım ile dil bulunmaktadır. Cargo kitabının derleme önbelleği bölümü yeniden üretilebilirlikten hiç bahsetmemektedir. Sonuç şudur: Rust'ta bit bit yeniden üretilebilir derleme 2026'da resmî olarak garantilenmiş bir özellik değildir. Argus'un gerçekçi hedefi kilit dosyasını işlemek, kilitli derleme yapmak, araç zincirini sabitlemek, yol öneklerini yeniden eşlemek, ikinci seviye köken bilgisi üretmek ile imzalamaktır. Bit bit yeniden üretilebilirlik taahhüt edilmemelidir.

Tedarik zinciri gerçekliği, Rust ekosisteminde 2025 ile 2026'da şöyledir. 20 Ağustos 2026'daki arrayref saldırısında bakımcının kimlik bilgileri ya da bilgisayarı ele geçirilmiş ile paket, kötü amaçlı bir bağımlılıkla yeniden yayımlanmıştır; bağımlılık, kötü amaçlı bir yük indiren bir derleme betiği içermekteydi. Zararlı sürümler 86 ile 107 dakika arasında yayında kalmıştır. Bir güvenlik araştırma ekibi tespit etmiştir. 12 Eylül 2025'te bir kimlik avı kampanyası yaşanmıştır. 2025'in son çeyreğinde dört ayrı kötü amaçlı crate olayı olmuştur. 11 Nisan 2025'te bir oturum çerezi güvenlik olayı yaşanmıştır.

Argus için doğrudan sonuç şudur: derleme betiği çalıştıran bir bağımlılık, derleme makinenizde keyfî kod çalıştırmaktadır. Bir kimlik sağlayıcının derleme hattı için lisans ile danışmanlık taraması, bağımlılık denetimi, ikili dosyaya yazılım malzeme listesi gömme, satıcılaştırılmış ve sabitlenmiş bağımlılıklar ile derleme betiği içeren yeni bağımlılıkların elle incelenmesi gerekmektedir.

---

## Argus için dağıtım ile operasyon kararları

1. Bir derleme adımı olmamalı; tek komut ile tek mod bulunmalıdır. Keycloak'ın üçlemesi bir çerçeve artefaktıdır ile mod geçişlerinde gerileme üretmiştir. Rust'ta bu bedel yoktur, çünkü derleme zaten önceden yapılmaktadır. Argus tek bir ikili dosya ile tek bir servis komutu olmalıdır; geliştirmeyle üretim arasındaki fark yalnızca yapılandırma değerleri olmalı, farklı bir kod yolu olmamalıdır.

2. Güvensiz yapılandırmayla başlamak reddedilmelidir, uyarılmamalıdır. Keycloak üretim modunun doğru yaptığı tek şey budur. Argus da veren adresini, TLS'i ile yönetim arayüzü bağlama adresini başlangıçta doğrulamalı; eksikse açık bir güvensizlik bayrağı olmadan başlamamalıdır.

3. Geliştirme veritabanı tuzağına düşülmemeli ancak gömülü veritabanını üretimde yasaklama konusunda Ory taklit edilmelidir. Keycloak'ın dosya tabanlı varsayılanı üretime uygun değildir ile uçurumun kökenidir. Ory'nin duruşu daha dürüsttür. Argus için tek düğüm ile bin kullanıcı altındaki senaryoda SQLite resmen desteklenmeli, ancak yüksek erişilebilirlik topolojisinde başlatılırsa reddedilmelidir.

4. Yönlendirme adresi eşleştirmesi yalnızca tam dizgi olmalı; düzenli ifade ile joker karakter hiçbir koşulda bulunmamalıdır. İlgili açıkta kaçırılmamış bir düzenli ifade noktası hesap devralmaya yol açmış ile düzeltme varsayılan katı dizgi eşleştirmesi olmuştur. RFC 9700 zaten tam eşleşmeyi zorunlu kılmaktadır. Argus'ta düzenli ifade desteği hiç gerçeklenmemelidir; tercihe bağlı tehlikeli bir özellik bile olmamalıdır.

5. Vekil başlığı güveni varsayılan olarak kapalı tutulmalı ile açıkken güvenilir vekil adres listesi zorunlu olmalıdır. Keycloak'ın uyarısı nettir: sahte değerler enjekte edilebilmekte ile bu, özellikle IP izin ya da yasak listesi kullanılıyorsa kritiktir; vekil başlıkları eklemeli değil üzerine yazmalıdır. Kaba kuvvet sayaçları ile hız sınırı doğrudan buna dayandığı için, güven açıkken liste boşsa Argus başlamamalıdır.

6. Uçucu durum, yani kimlik doğrulama oturumu, eylem token'ı ile kaba kuvvet sayacı veritabanına yazılmalı; uçuştaki akışlar zarif kapanışa emanet edilmemelidir. Keycloak'ın durumsuz modu tam olarak bunu yapmıştır. Bedeli kimlik doğrulama başına sekiz ile 10 milisaniye ile veritabanı yükünün yaklaşık iki katıdır. Rust'ta bu bedel sanal makinesizken daha da kabul edilebilirdir; Argus için varsayılan olmalıdır, bir seçenek değil.

7. Önbellek geçersizleştirmesi bir ağ protokolüyle değil veritabanı destekli bir giden kutusuyla yapılmalıdır. Keycloak'ın dağıtık önbellek geçersizleştirmesi, veritabanına yazan yan süreçlerle senkronize olamamıştır; alan veritabanında görünmekte ancak konsolda görünmemekteydi ile yeniden başlatma gerekmekteydi. 26.7'nin çözümü bir veritabanı kuyruğu ile yoklamadır, varsayılan 100 milisaniyelik aralıkla. Argus'ta bir giden kutusu tablosu ile yoklama ya da §1'in 10.2 bölümünde seçilecek diğer kalıcı mekanizma kullanılmalıdır. Dinle ile bildir iptal yayınında kullanılmaz; §6'nın 4.5 bölümüne bakınız. Hiçbir durumda düğümden düğüme bir küme protokolü kullanılmamalıdır.

8. Zarif kapanışta ön kapanış beklemesi, boşaltma gecikmesi ile istek zaman aşımı üçlüsü ayrı ayrı yapılandırılabilir olmalıdır. Keycloak'ın somut değerleri referanstır: bir saniyelik kapanış gecikmesi ile 10 saniyelik kapanış zaman aşımı. Kubernetes'te uç nokta kaldırma ile sonlandırma sinyali sıralı değildir ile yayılım yoğun bir kümede çoğu zaman bir saniye veya daha fazla sürmektedir. Argus önerisi beş saniyelik bir ön kapanış beklemesi, iki saniyelik boşaltma gecikmesi, 15 saniyelik kapanış zaman aşımı ile 45 saniyelik zarif kapanış süresidir.

9. Başlatma ile canlılık yoklamaları göç sırasında ayakta dönmelidir. Keycloak 26.6 bunu düzeltmiştir. Aksi hâlde uzun bir şema göçü sonsuz bir yeniden başlatma döngüsüne girmektedir. Argus'ta göç durumu canlılık için ayakta, hazır olma için kapalı olmalı; ayrı bir başlatma uç noktası başlatma yoklamasına hizmet etmeli ile Keycloak'ın ayrı yönetim portu modeli gibi ayrı bir porttan sunulmalıdır.

10. Yuvarlanan güncelleme uygunluğu makine tarafından karar verilebilir hâle getirilmelidir. Keycloak'ın uyumluluk komutu ile çıkış kodları operatöre deterministik bir karar vermektedir. Argus, göçünün geriye dönük uyumlu mu yoksa kırıcı mı olduğunu ikili dosyanın kendisi raporlayabilmeli; böylece hem sürekli teslim hattı hem operatör otomatik karar vermelidir.

11. Şema göçünde genişlet ile daralt zorunludur; her sürüm yalnızca genişletme ya da yalnızca daraltma içermelidir, ikisi birden değil. Fowler'ın geçiş fazı tanımı, bir önceki sürümle uyumluluğun tek güvenli yoludur. PostgreSQL desteği şudur: doğrulanmamış kısıt ekleme anında işlenmekte ile doğrulama yalnızca hafif bir kilit almaktadır. PostgreSQL 18 ile aynı desen artık boş olmama kısıtı için de geçerlidir; dolayısıyla Argus'un asgari PostgreSQL hedefi 18 olmalıdır.

12. Göç aracı olarak sqlx seçilmeli ancak aşağı göçler bir operasyonel kurtarma planı sayılmamalıdır. sqlx yukarı ile aşağı dosyaları üretmekte ile geri alma sunmaktadır; refinery ise geri almayı reddetmekte ve yeni bir göç üretmenizi istemektedir. Aşağı göçler test için tutulmalı; üretim geri alma planı zaman içinde geri yüklemedir, geri alma değildir.

13. Yuvarlanan güncelleme sırasında şema değişikliği uygulama başlatmasına bırakılmamalı; ayrı ile tekil bir göç işi olmalıdır. Keycloak'ın ilgili konusu engelleri açıkça listelemektedir: uyumsuz göçler ile indeks oluşturma kilitleri, yuvarlanan güncellemeler sırasında eski örneklerin kümeye katılmasını engelleyebilmektedir. Argus'ta göç ayrı bir komut ya da iş olmalı; uygulama süreci başlangıçta yalnızca doğrulama yapmalı ile şema uyumsuzsa hızlıca ölmelidir.

14. İndeksler her zaman eşzamanlı olarak eklenmeli ile göç işleminin dışında tutulmalıdır. Tablo değiştirme varsayılanı en ağır kilittir; yeniden yazan formlar ayrıca çok sürümlü eşzamanlılık açısından güvenli değildir ile iki katına kadar disk istemektedir. Bu, kimlik verisi taşıyan bir tabloda kabul edilemez.

15. İmzalama anahtarları veritabanının dışına çıkarılmalı ile veritabanı yedeğinden bağımsız yedeklenmelidir. Keycloak otomatik üretim kullanınca anahtarlar veritabanındadır ile doküman bir yedekleme prosedürü vermemektedir; anahtar deposu seçeneği ise ana bilgisayar dosya sisteminden okumaktadır. Zitadel'in ana anahtarı değiştirilememekte ile bileşim komutunda sessizce üretilmektedir. Anahtar kaybı veritabanı kaybından daha yıkıcıdır. Argus'ta anahtar materyali için takılabilir bir arka uç, yani dosya, anahtar yönetim servisi ya da donanım arayüzü bulunmalı, varsayılan olarak veritabanından ayrı olmalı ile başlangıçta anahtarınızı yedeklediniz mi onayı olmadan üretilmemelidir.

16. Anahtar yönetim servisi ile donanım modülü tümleşmesi birinci sınıf olmalı ancak anahtar seti servise bağlanmamalıdır. Bir bulut anahtar servisi RSA'nın üç boyutunu, üç eliptik eğriyi, Ed25519'u ile kuantum sonrası imza algoritmalarını desteklemektedir; özel anahtar servisi şifresiz terk etmemekte ile açık anahtar indirilebilmektedir. Argus'ta imzalama devredilebilmeli ancak anahtar seti uç noktası yerel bir açık anahtar önbelleğinden servis edilmelidir; her istekte servise çağrı yapılmamalıdır. Felaket kurtarma uyarısı şudur: anahtar dışa aktarılamamaktadır, dolayısıyla çok bölgeli anahtar ya da içe aktarılmış anahtar materyali şarttır.

17. Anahtar rotasyonu aktif, pasif ile devre dışı modeliyle yapılmalı ile emeklilik penceresi token ömründen uzun olmalıdır. Keycloak'ın modeli ile önerisi doğrudan alınabilir: üç ile altı ayda bir yeni anahtar, eskisini bir ile iki ay sonra kaldırma. Kritik nokta şudur: pasif anahtar, en uzun yenileme token'ı ömrü artı bağlı taraf anahtar seti önbellek yaşam süresi kadar yaşamalıdır.

18. Argon2 için ayrı, sınırlı bir bloklayıcı işçi havuzu olmalı ile kuyruk dolunca 429 dönülmelidir. Kanıt zinciri şudur: boyutlandırmada parola girişi saniyede 15, istemci kimlik bilgisi saniyede 120'dir; sekiz kat fark özetlemedendir. Keycloak'ın varsayılanı istek başına yedi megabayttır ile paralelliği çekirdek sayısıyla sınırlamaktadır. Zitadel dört çekirdek ayrılmasını söylemektedir. OWASP'ın hizmet reddi uyarısı açıktır. Argus'ta bir eşzamanlılık semaforu bulunmalı, kapsül bellek limiti temel değer artı azami eşzamanlı özet çarpı bellek maliyeti formülüyle hesaplanmalı ile kuyruk dolunca 429 ve yeniden dene başlığı dönülmeli, kuyruğa alıp bekletilmemelidir.

19. Argon2 parametreleri OWASP setlerinden seçilebilir olmalı; orta bir set varsayılan, en bellek verimli set yüksek eşzamanlılık profili olmalıdır. OWASP beş seti eşdeğer saymakta ile hedefi bir saniyenin altıdır. Keycloak en bellek verimli ucu seçmiştir. Argus dağıtım profiline göre seçtirmeli ile seçilen profilin bellek bütçesini başlangıçta hesaplayıp günlüğe yazmalıdır.

20. Bağlantı havuzlayıcının işlem modu desteklenmeli; hazırlanmış ifade sayısı sıfırdan büyük gerektirilmeli ile protokol seviyesinde hazırlama kullanılmalıdır. Havuzlayıcının 1.21.0 ve üstü işlem havuzlamada hazırlanmış ifadeleri takip etmekte, 1.22.0 ilgili temizleme komutlarını desteklemektedir. Kısıt yalnızca genişletilmiş sorgu protokolüdür. sqlx bunu kullandığı için uyumludur; ancak dokümanda ilgili ayarın sıfır bırakılmasının performans çöküşü yaratacağı uyarısı bulunmalıdır.

21. Senkron işleme ayarı işlem sınıfına göre yapılmalıdır. PostgreSQL bireysel işlemlerin replikasyonu beklememesini yapılandırmaya izin vermektedir. Argus'ta kullanıcı, kimlik ile anahtar yazmaları yeter sayı beklemeli; kaba kuvvet sayaçları, son giriş zamanı ile telemetri yerel işlemeyle yazılmalıdır. Böylece üç alanlı senkron yeter sayının gecikme bedeli yalnızca dayanıklılık gerektiren yazmalara yansımaktadır.

22. Kendi konteyner imajınız dağıtımsız bir tabana kurulmalı ancak musl'a körlemesine geçilmemelidir. Statik dağıtımsız imaj yaklaşık iki mebibayttır; temel varyant sertifika otoriteleri ile saat dilimi verisi içermektedir. Ancak musl ayırıcısının ile iş parçacığı yönetiminin çok iş parçacıklı Rust'ta ciddi yavaşlama ürettiği raporlanmıştır; Argon2 ile eşzamansız çalışma zamanı iş yükünde kendi kıyaslamanızı yapmadan musl'a geçilmemelidir. Güvenli varsayılan standart C kütüphaneli dağıtımsız imajdır; musl ile sıfırdan imaj isteğe bağlıdır.

23. Derleme cargo-chef ile katmanlanmalı ancak çalışma alanı dışında yol bağımlılığı kullanılmamalıdır. Aracın iki katı kuralı şudur: pişirme ile derleme aynı çalışma dizininden çalıştırılmalıdır ile proje dışındaki yerel bağımlılıklar değişmemiş olsalar bile sıfırdan derlenmektedir. Argus'un depo düzeni tek bir çalışma alanı olmalıdır.

24. Dağıtım kanalı bağımsızlığı için kendi paketiniz kendi kayıt defterinizde yayımlanmalı ile imaj referansları kendi imajınıza sabitlenmelidir. Bitnami 28 Ağustos 2025'te sürümlü imajları bir eski depoya taşımış, artefaktlar güncellenmemekte ile paketlenmiş imajlar geçersiz kılınmazsa dağıtımlar patlamaktadır. Argus'un paketi hiçbir üçüncü taraf imaj kataloğuna, özellikle bir veritabanı alt paketine bağımlı olmamalıdır; veritabanı harici bir gereksinim olarak belgelenmeli ile pakete gömülmemelidir.

25. Operatör Helm'in üstüne değil yanına konulmalı ile yalnızca kaynak tanımlarının gerçekten çözdüğü sorunlar için kullanılmalıdır. Keycloak'ın resmî bir paketi yoktur, yalnızca operatör vardır ile kurulum elle onay uyarısıyla gelmektedir. Kaynak tanımları yıllarca alfa sürümünde kalmış ile alan içe aktarma tanımı yalnızca oluşturmaktadır. Argus için Helm paketi birinci sınıf olmalıdır; operatörün gerekçesi yalnızca yuvarlanan güncelleme uygunluk kararı ile göç işi orkestrasyonu olmalıdır. Alan ile istemci uzlaştırması bir Terraform sağlayıcısına bırakılmalıdır.

26. Kesinti bütçesi en fazla bir kullanılamaz kapsüle izin vermeli; topoloji dağılımı bölgede sert, ana bilgisayarda yumuşak olmalı ile kapsül şablonu özetiyle eşleşme kullanılmalıdır. Bütçe yalnızca gönüllü kesintileri korumakta ile tam kullanılabilirlik istenirse boşaltma sonsuza kadar askıda kalmaktadır. Şablon özetiyle eşleşme, yuvarlanan güncelleme sırasında eski ile yeni kopya kümelerinin kapsüllerinin birbirini saymasını önlemektedir. Sağlıksız kapsül tahliye politikası varsayılanında bırakılmalıdır; aksi hâlde sağlıksız kapsüller boşaltmayı kilitlemektedir.

27. Veritabanı topolojisi tek bir Kubernetes kümesi, üç ve üzeri erişilebilirlik alanı, hiçbir şey paylaşmayan mimari ile üçün katı düğüm olmalıdır. Operatörün resmî tavsiyesi budur; her düğümde yerel disk kullanılmalı ile depolama seviyesi replikasyon kullanılmamalıdır. Sınır şudur: bu operatör kümeler arası otomatik devralma yapamamaktadır; bu, tek bölge kararının doğruluğunu operatör tarafından da onaylamaktadır.

28. Kurtarma noktası ile kurtarma süresi hedefleri pgBackRest ile hedeflenmeli; mantıksal döküm tek yedek stratejisi yapılmamalıdır. Araç zaman içinde geri yükleme, fark geri yüklemesi, depo şifreleme, çoklu depo ile doğrulama sunmaktadır. Dokümanın kendi uyarısı şudur: hangi deponun en verimli olacağını yalnızca geri yükleme testi belirleyebilmektedir. Dolayısıyla geri yükleme tatbikatı Argus'un operasyon dokümantasyonunda zorunlu bir bölüm olmalıdır.

29. Kiracı bazında geri yükleme bir ürün özelliği olarak vaat edilmemeli; kiracı başına şema ya da yan geri yükleme deseni belgelenmelidir. Geri yükleme aracının dokümanı seçici geri yüklemenin bağımlılıkları getirmediğini, yardımcı nesneleri dahil etmediğini ile büyük nesnelerde ya hep ya hiç davrandığını söylemektedir. Tek şema ile kiracı kimliği tasarımında satır seviyesi geri yükleme mümkün değildir. Argus'un dürüst duruşu şudur: yedeği ayrı bir örneğe geri yükleyip kiracı süzgeçli mantıksal kopyalama başucu kitabı yayımlamak ile uygulama katmanında yumuşak silme ve denetim günlüğüyle geri yükleme ihtiyacını azaltmaktır.

30. Lisans olarak sunucu için AGPL 3.0 ya da MPL 2.0, geliştirme kitleri için Apache 2.0 seçilmelidir. Zitadel üçüncü sürümle geçiş yapmış, yalnızca yeni katkıları yeni lisansa almış, geliştirme kitlerini korumuş ile ticari lisans sunmuştur. Alternatif model Ory'nin açık çekirdeğidir; ancak açık yamalarının ile hizmet seviyeli güvenlik sürümlerinin ticari katmanda olması bir kimlik sağlayıcı için etik olarak tartışmalıdır. Kanidm'in lisansı ılımlı bir ara yoldur. Argus için tavsiye sunucunun AGPL ya da MPL, geliştirme kitlerinin Apache olması ile güvenlik yamalarının asla ticari katmana kilitlenmemesidir.

31. Siber dayanıklılık hazırlığı 11 Aralık 2027'ye göre planlanmalı ancak güvenlik dosyası bugün yazılmalıdır. Yürürlük maddesine göre dördüncü bölüm 11 Haziran 2026'da, 14. madde 11 Eylül 2026'da ile tamamı 11 Aralık 2027'de uygulanmaktadır. ENISA açıkça belirtmektedir: üreticiler 11 Eylül 2026'dan, açık kaynak vekilleri 11 Aralık 2027'den itibaren raporlamaktadır. Argus'un arkasında bir tüzel kişi yoksa vekil yükümlülüğü hiç doğmamaktadır; paraya çevrilmeyen açık kaynak zaten kapsam dışıdır. Ancak 24. maddenin istediği doğrulanabilir biçimde belgelenmiş siber güvenlik politikası zaten iyi mühendisliktir; şimdi yazılmalıdır.

32. GitHub numaralandırma otoritesi ile özel zafiyet bildirimi kullanılmalı; kendi otoriteniz kurulmamalıdır. Taslak danışmanlıktan numara talep edilebilmekte ile yaklaşık 72 saatte incelenmektedir; yayımlanan danışmanlık veritabanına ile bağımlılık uyarılarına akmaktadır. Keycloak'ın politikası bir şablon olarak alınabilir: yedi iş günü alındı bildirimi, zorunlu kavram kanıtı, bulgu başına ayrı rapor ile araştırmacıya kredi.

33. Sürüm imzalamada anahtarsız imzalama ile ikinci seviye tedarik zinciri hedeflenmeli; yeniden üretilebilir derleme taahhüt edilmemelidir. Anahtarsız zincir basittir. İkinci seviye barındırılan platform artı imzalı köken bilgisi, üçüncü seviye derleme izolasyonu artı imzalama anahtarının erişilemezliğidir; hiçbiri yeniden üretilebilir derleme gerektirmemektedir. Rust ilgili listede yoktur ile Cargo kitabı bundan bahsetmemektedir. Argus'un taahhüdü kilitli derleme, sabitlenmiş araç zinciri, ikinci seviye köken bilgisi ile imzalamadır; bit bit yeniden üretilebilirlik elden gelenin en iyisidir.

34. Tedarik zincirinde derleme betiği içeren her yeni bağımlılık elle incelenmelidir. 20 Ağustos 2026 saldırısında bakımcı hesabı ele geçirilmiş ile kötü amaçlı bağımlılık bir yük indiren derleme betiği içermekteydi; zararlı sürümler 86 ile 107 dakika arasında yayında kalmıştır. 2025'te ayrıca bir kimlik avı kampanyası ile dört ayrı kötü amaçlı paket olayı yaşanmıştır. Bir kimlik sağlayıcı için lisans ile danışmanlık taraması, bağımlılık denetimi, denetlenebilir ikili dosya, satıcılaştırılmış bağımlılıklar ile derleme betiği incelemesi isteğe bağlı değildir.

35. Sır yönetiminde dosya tabanlı sırlar ile sır ve sıfırlama kütüphaneleri, imzalama anahtarları için bellek kilitleme kullanılmalı ile rotasyonda kapsül yeniden yüklemesi kendiniz çözülmelidir. Sır kütüphanesi bellek kilitleme sunmamakta, sıfırlama kütüphanesi yeniden tahsis öncesi kopyaları garanti edememekte ile bellek güvenliği kütüphanesi kilitleme ve döküm dışlama bayrakları sunmaktadır. Harici sır operatörü ise sırrın yaşam döngüsünü yönetmemektedir; rotasyon sonrası kapsül yeniden yüklemesi onun işi değildir. Argus sır dosyalarını dosya sistemi olaylarıyla izleyip yeniden yüklemeli ile yeniden başlatma gerektirmemelidir.

36. Vault dinamik veritabanı kimlik bilgileri desteklenmeli; kiralama yenileme ile süre bitiminde yeniden bağlanma havuzda ele alınmalıdır. İlgili sır motoru dinamik kullanıcıları bir geçerlilik tarihiyle üretmekte ile statik rollerde bir rotasyon periyoduyla parola döndürmektedir. Argus'un bağlantı havuzu, parola değiştiğinde yeni bağlantıların yeni parolayı kullanmasını sağlamalı ile mevcut bağlantıları gereksiz yere kapatmamalıdır.

---

## Doğrulanamayanlar

1. Rust dağıtımsız ile sıfırdan imajlarının kesin boyutları yalnızca ikincil bir blog kaynağındandır. Kendi ölçümünüzü yapmalısınız.
2. musl ayırıcı ile iş parçacığı performansının 2026'daki durumu doğrulanamamıştır; tek kaynak 2020 tarihlidir ile sonraki ayırıcı iyileştirmelerinden sonra yeniden ölçülmelidir.
3. RFC 9700'ün tam yayın tarihi doğrulanamamıştır; arama sonucu bir tarih vermiş ancak RFC metninden doğrulanmamıştır.
4. Keycloak göçlerinin yalnızca ileri yönlü olduğu ile geri alma için veritabanı geri yüklemesi gerektiği yalnızca ikincil bir kaynaktandır; resmî dokümanda açık bir ifade bulunamamıştır.
5. Keycloak ile Zitadel için formel uzun dönem destek ile destek penceresi sayfaları bulunamamıştır; ilgili adresler 404 dönmüştür.
6. Red Hat derlemesinin yaşam döngüsü tarihleri bulunamamıştır; ilgili adres 404 dönmüştür.
7. authentik'in lisansı doğrulanamamıştır.
8. sqlx göçlerinin tavsiye kilidiyle eşzamanlılık koruması ile sağlama toplamı ve kirli durum davranışı belgelenmemiştir; kaynak koddan teyit gerekmektedir.
9. crates.io güvenilir yayımlama özelliğinin mevcut durumu ile köken ve kanıtlama desteği doğrulanamamıştır; ilgili sayfa içerik döndürmemiştir.
10. Keycloak'ın büyük kurulumlarda ana sürüm yükseltme göç süresi doğrulanamamıştır; resmî dokümanda somut bir rakam yoktur, yalnızca ikincil kaynaklarda büyük veritabanlarında göçün önemli zaman alabileceği belirtilmektedir.
11. Kanidm'in veritabanı motorunun SQLite tabanlı olup olmadığı doğrulanamamıştır; deposu kendi yüksek performanslı veritabanı demekte ile SQLite'tan bahsetmemektedir.
12. Zitadel ana anahtarının kaybı durumunda bir kurtarma prosedürü olup olmadığı doğrulanamamıştır; değiştirilemez ifadesi doğrulanmış ancak kayıp senaryosu için resmî bir prosedür bulunamamıştır.
13. Keycloak'ın imzalama anahtarları için donanım modülü arayüzü desteği doğrulanamamıştır; anahtar deposu sağlayıcısı doğrulanmıştır ancak doğrudan donanım desteği doğrulanamamıştır.
14. Yeter sayı işlemesiyle üç erişilebilirlik alanı arasındaki gerçek gecikme maliyeti doğrulanamamıştır; PostgreSQL dokümanı sözdizimini vermekte, sayısal etkiyi vermemektedir. Keycloak kıyaslamasındaki gidiş dönüş verisi dolaylı bir göstergedir.
