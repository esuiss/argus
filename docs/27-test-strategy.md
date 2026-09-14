# §27 — Test stratejisi

Bu bölüm `ARGUS.md` dosyasının 27. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§27 §X` referansları aynı anlamdadır.

Tarih 8 Eylül 2026'dır. Tüm iddialar kaynaklandırılmıştır; doğrulanamayanlar açıkça işaretlenmiştir.

---

## 1. Uyum test süitleri

### 1.1 OpenID Foundation uyum süiti

Kendi barındırdığınız ortamda çalıştırılabilmektedir, Docker ile. Süit açık kaynaktır. Vakfın resmî sayfası, süitin bağımsız test çalıştırmak isteyen geliştiriciler için yerel Docker kurulumunu desteklediğini ile tüm testlerin yerel olarak ya da vakfın sunucuları üzerinden çalıştırılabileceğini söylemektedir.

Bileşim dosyasının içeriği birincil kaynaktan şöyledir: bir MongoDB 6.0.13 servisi, dışarı portsuz ile yerel bir veri bağlaması; bir nginx servisi, 8443 portunda HTTPS ile; ile bir Java uygulama sunucusu, nginx arkasında. Yani MongoDB artı Java uygulaması artı nginx TLS sonlandırması. Kayda değer bir ayrıntı vardır: jar adı hâlâ eski finansal API test süiti adını taşımaktadır; süitin kökeni bağışlanan bir açık bankacılık çerçevesidir.

Kapsanan şartnameler OpenID Connect, birinci ile ikinci sürüm finansal API profilleri, geri kanal kimlik doğrulama profili ile kimlik güvencesidir. Buna federasyon ile doğrulanabilir kimlik bilgisi profilleri de eklenmiştir.

Sağlayıcı profilleri yedi adettir ile doğrulanmıştır.

| Profil | Ne test etmektedir |
|---|---|
| Temel sağlayıcı | Yetkilendirme kodu temel akışıdır |
| Örtük sağlayıcı | Örtük yanıt tipleridir |
| Hibrit sağlayıcı | Hibrit akışlardır |
| Yapılandırma sağlayıcısı | İyi bilinen yapılandırma keşfidir |
| Dinamik sağlayıcı | Dinamik istemci kaydıdır |
| Form gönderimli sağlayıcı | Form gönderimi yanıt modudur |
| Üçüncü taraf başlatmalı giriş sağlayıcısı | Üçüncü tarafça başlatılan giriştir |

Aynı sayfadan doğrulanan operasyonel detaylar şunlardır: test için sertifikasyon sitesine bir sosyal hesapla girilmektedir. Dinamik istemci kaydı desteklenmiyorsa üç istemci elle kaydedilmelidir: iki tanesi temel kimlik doğrulamalı, biri gönderi kimlik doğrulamalı, ki ilkiyle çakışabilmektedir. Yönlendirme adresi sertifikasyon sitesinin takma ad bazlı geri çağırma yoludur. Sertifikasyon kriteri tüm testlerin geçti, incelenecek, uyarı ya da atlandı olmasıdır; başarısız ya da kesildi olmamalıdır.

Çıkış profilleri dört adettir: bağlı tarafça başlatılan çıkış, oturum yönetimi, ön kanal çıkışı ile arka kanal çıkışı. Sertifikasyon için bağlı tarafça başlatılan çıkış artı diğer üçünden en az biri gerekmektedir. Test tanımlayıcıları bir adlandırma kuralı izlemektedir. Bir not gerekmektedir: bu sayfa kendini artık hizmet dışı bırakılmış eski test süitiyle ilgili tarihsel bir sayfa olarak tanımlamaktadır; yeni süitte plan adları farklı olabilir.

Test planı adları birincil olarak Ory Hydra'nın sürekli tümleştirme kodundan doğrulanmıştır. İlgili test dosyası gerçek plan adlarını içermektedir.

```
oidcc-basic-certification-test-plan
oidcc-implicit-certification-test-plan
oidcc-hybrid-certification-test-plan
oidcc-config-certification-test-plan
oidcc-dynamic-certification-test-plan
oidcc-formpost-basic-certification-test-plan
oidcc-formpost-implicit-certification-test-plan
oidcc-formpost-hybrid-certification-test-plan
oidcc-test-plan
```

Aynı dosya süitin REST API'sini de açığa çıkarmaktadır ile bu Argus için kritiktir: bir plan uç noktasına plan adı ile varyant gönderilip plan tanımlayıcısı alınmakta; plan içinde birden çok modül bulunmakta; bir koşucu uç noktasına modül, plan ile varyant gönderilip test örneği oluşturulmakta; ile bir bilgi uç noktası üstel geri çekilmeyle yoklanmaktadır, durum bitti ile sonuç geçti, uyarı veya başarısız olabilmektedir. Hydra başarısız ya da kesilmiş testleri en fazla beş kez yeniden denemektedir; kararsızlık gerçek bir problemdir.

Hydra'nın kurulumu bir uyum dizini altında bileşim dosyası, imaj tanımı, yapılandırma, başlatma, test, yayımlama ile temizleme betikleri, test kodu ile yardımcı dizinlerden oluşmaktadır. Test betiği yalnızca 60 dakikalık bir zaman aşımıyla Go testlerini çalıştırmaktadır; tam plan setinin sürekli tümleştirme süresi hakkında iyi bir sinyaldir.

Resmî sürekli tümleştirme aracı bir plan çalıştırma betiğidir. Vakıf, yetkilendirme sunucusu geliştiricilerinin bunu geliştirme hatlarına entegre etmesinin şiddetle önerildiğini söylemektedir. Doğrulanan arayüzü şöyledir: argümanları test planı adı ile yapılandırma dosyası çiftleridir, birden fazla verilebilmektedir; ayrıca dışa aktarma dizini, paralellik kapatma, beklenen başarısızlıklar dosyası, beklenen atlamalar dosyası, yeniden çalıştırma, listeleme ile ayrıntı seçenekleri bulunmaktadır. Ortam değişkenleri sunucu adresi, ki zorunludur, belirteç, karşılıklı TLS adresi, yerel adres, dış adres, azami ardışık başarısızlık ile yeniden başlatma denemesidir. Çıkış kodu bir olmaktadır: modül tamamlanmadıysa, beklenmeyen bir başarısızlık ya da uyarı varsa, beklenen bir başarısızlık listede olup gerçekleşmediyse, ki bayat temel çizgi tespitidir, ya da sunucu sağlıksızsa. Çıkış kodu sıfır olmaktadır: hepsi tamamlandıysa ile beklenen başarısızlıklarla eşleştiyse.

Bu, tam olarak Argus'un istediği modeldir: temel çizgili, sürekli tümleştirme dostu ile çıkış kodlu.

Test sayıları doğrulanamamıştır; hiçbir birincil kaynakta bir planın kaç test içerdiğine dair bir sayı bulunamamıştır. Sayı, plan oluşturulduğunda varyantlara göre dinamik olarak belirlenmektedir. Kesin sayı ancak plan oluşturma çağrısından dönen modül listesinden öğrenilmektedir.

Ücret tarafında testleri çalıştırmak ücretsizdir; sertifikasyon ücretlidir.

| Kategori | Üye | Üye olmayan |
|---|---|---|
| OpenID Connect ile doğrulanabilir kimlik bilgisi profilleri | Dağıtım başına 700 dolar | Dağıtım başına 3.500 dolar |
| Finansal API profilleri ile geri kanal profili | Dağıtım başına 1.000 dolar | Dağıtım başına 5.000 dolar |

Açık kaynak projeler için bir ücret muafiyeti politikası bulunmaktadır. Argus sertifika hedeflemediği için maliyet sıfırdır.

### 1.2 Finansal API ikinci sürümü

Güvenlik profilinin nihai sürümü Şubat 2025'te onaylanmıştır. Nihai uyum testleri 9 Temmuz 2025'te duyurulmuştur; hem yetkilendirme sunucusu hem istemci içindir. Mesaj imzalama profili önerilen nihai aşamadadır ile yayını Ağustos 2025'te beklenmekteydi.

Desteklenen şartnameler birinci sürümün gelişmiş nihai profili, ikinci sürümün nihai güvenlik profili, ikinci sürümün gerçekleyici taslağı ile mesaj imzalama taslağıdır.

İstemci kimlik doğrulama varyantları karşılıklı TLS ile özel anahtar JWT'sidir. Ekosistem varyantları çeşitli ülkelerin açık bankacılık profilleridir.

Önemli bir nokta vardır: sertifikasyon amacıyla artık her seçenekle yalnızca bir test çalıştırmak yeterlidir; kombinatoryal patlama sınırlanmıştır.

DPoP desteği uyum testlerine eklenmiştir. Tam plan adı hiçbir sayfada açıkça yazılı değildir ile doğrulanamamıştır.

### 1.3 Geri kanal kimlik doğrulama profili

Plan adı geri kanal test planıdır. Bir varyant örneği yoklama ile karşılıklı TLS birleşimidir. Yoklama modu zorunludur, anlık bildirim isteğe bağlıdır. Bazı ekosistemler için önekli varyantlar bulunmaktadır. Bir uyarı vardır: adında istemci geçen planlar sağlayıcı testi için kullanılmamalıdır.

### 1.4 OpenID Federation

Üç test planı bulunmaktadır: dağıtılmış federasyon varlığı testi, ki yaprak, ara ile güven çıpası rollerini ve metadata yanıt yapısını kapsamaktadır; test federasyonuna katılmış varlık sağlayıcı testi, ki süit bağlı taraf ve güven çıpası rolü oynamaktadır ve sağlayıcı süiti yetki ipuçlarına eklemelidir; ile test federasyonuna katılmış varlık bağlı taraf testi, ki süit sağlayıcı ve güven çıpası rolü oynamaktadır.

Olgunluk uyarısı doğrudan sayfadadır: üretimde şu anda mevcut test seti erken aşamadadır. Argus için düşük önceliklidir.

### 1.5 Doğrulanabilir kimlik bilgisi profilleri, Argus yol haritası için bonus

Kendi kendine sertifikasyon 26 Şubat 2026'da açılmıştır; ilgili sunum, verme ile yüksek güvence profilleri kapsamdadır ile 38 yargı bölgesi bu şartnameleri seçmiş durumdadır.

### 1.6 Model bağlam protokolü uyum süiti

Depo birincil olarak doğrulanmıştır.

Ne test ettiği şudur: istemci tarafında başlatma el sıkışması, araç çağrısı, OAuth akışları ile metadata; sunucu tarafında başlatma, yetenekler, araç listeleme ile çağırma, kaynaklar ile istemler.

Nasıl çalıştığı şudur.

```
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
npx @modelcontextprotocol/conformance client --command "<cmd>" --scenario initialize
```

Şartname sürümleri tarihli sürümler ile bir taslaktır; iki yaşam döngüsü vardır, yani başlatma el sıkışmalı durumlu ile istek başına metadatalı durumsuz.

Beklenen başarısızlıklar temel çizgisi bir YAML dosyasında tutulabilmekte; böylece sürekli tümleştirme yeşil kalırken gerilemeler yakalanmaktadır. Kontrol başına temel çizgileme vardır; tüm senaryoyu değil tek bir kontrolü muaf tutabilmektesiniz. Bayat temel çizgiler de raporlanmaktadır.

Çıktısı uyum kontrolleri ile tel şeması doğrulamasıdır; hem gerçeklemenin hem test koşum aracının gönderdiği mesajlar için JSON şemasına karşı sentetik kontroller üretilmektedir.

Sürekli tümleştirme tarafında depo bir GitHub eylemi içermektedir; bir katman kontrolü alt komutu geliştirme kitlerini bir katmanlama önerisine göre değerlendirmektedir.

Senaryo sayısı depo ağacından sayılmıştır: yetkilendirme sunucusu kategorisinde iki ana senaryo vardır, yani yetkilendirme kodu yetkisi ile yetkilendirme sunucusu metadata'sı, artı bir alt dizin; sunucu kategorisinde yaklaşık 17 senaryo bulunmaktadır, yani önbellekleme, alan adı yeniden bağlama, istem varsayılanları ile sıralamaları, standart başlıklar, girdi gerekli sonucu, JSON şeması, yaşam döngüsü, olumsuz senaryolar, istemler, kaynaklar, oturum yaşam döngüsü, çoklu akışlar, yoklama, durumsuzluk ile araçlar; istemci kategorisi sayılmamıştır.

Argus için en değerli kısım yetkilendirme sunucusu senaryolarıdır: Argus bir model bağlam protokolü sunucusunun koruduğu kaynak için yetkilendirme sunucusu rolü oynayacaksa, metadata ile yetkilendirme kodu senaryoları doğrudan Argus'u test etmektedir. Ayrıca alan adı yeniden bağlama ile standart başlık senaryoları güvenlik açısından ilgilidir.

Tek bir senaryo içinde yirmiden fazla kontrol bulunduğu belirtilmektedir; yani senaryo sayısı kontrol sayısına eşit değildir ile toplam kontrol sayısı birkaç yüz mertebesindedir. Kesin toplam doğrulanamamıştır.

### 1.7 SCIM

Resmî bir uyum süiti yoktur. İlgili RFC'ler için bir uyum programı bulunmamakta ile ekosistem satıcı araçlarıyla yürümektedir. Bulunan araçlar şunlardır.

| Araç | Ne yapmaktadır | Erişim | Not |
|---|---|---|---|
| Microsoft doğrulayıcısı | Sağlama servisiyle uyumu doğrulamaktadır. Üç modu vardır: varsayılan nitelikler, şema keşfi, ki önerilmektedir, ile şema yükleme. Nitelik değerleri için ifade desteği bulunmaktadır | Web üzerinden ücretsizdir | Uygulama mağazasına yayımlanacak bağlayıcılar için daha katı kurallar uygulamaktadır. Bilinen bir sorun yama testlerinin farklı yük formatı yüzünden başarısız olmasıdır |
| Okta test süiti | On üç ardışık işlem içermektedir: kullanıcı oluşturma, atama, nitelik güncelleme, devre dışı bırakma, yeniden etkinleştirme ile kaldırma | Bir test platformuna JSON içe aktarımıyla | Mağaza yayını için ayrıca elle bir test planı gerekmektedir. Kritik davranış şudur: Okta uygulamanızdaki kullanıcı profillerini silmemekte, kaydı etkin değil olarak işaretlemektedir |
| scim2-tester | Keşif, oluştur oku güncelle sil ile yamanın tüm varyantlarını, iki RFC'yi kapsamaktadır | pip ile kurulan bir kütüphanedir; komut satırı için ayrı bir araç vardır | Sürekli tümleştirme için tasarlanmıştır ile etiket bazlı süzme sunmaktadır. Argus için en pratik programatik seçenektir |
| WSO2 uyum süiti | Kullanıcılar, gruplar, ben, kurumsal kullanıcı, servis sağlayıcı yapılandırması, kaynak tipi, şemalar ile toplu işlemleri kapsamaktadır | Bir web arşivi dağıtımıyla | Apache 2.0 lisanslıdır ile düşük aktiviteye sahiptir |
| SCIM kum havuzu | Sunucu yöneticisi, uyum ile oyun alanı bileşenleri sunmaktadır; herhangi bir SCIM temel adresine geçti ya da kaldı raporu vermektedir | Site 403 döndürmüş ile doğrudan doğrulanamamıştır | Açık kaynak olduğu iddia edilmektedir; doğrulanmamıştır |

Test sayıları için hiçbirinde resmî bir sayı yoktur; Okta'nın on üç operasyonu hariç.

### 1.8 SAML

Resmî uyum tarafında ilgili OASIS belgesi uyum gereksinimlerini tanımlamaktadır ancak çalıştırılabilir bir test süiti değildir. Birlikte çalışabilirlik testleri tarihseldir; bir kamu programı 2007'de bunu zorunlu kılmıştı ile sertifikasyon işlevi sonradan Kantara girişimine geçmiştir. Kantara'nın bugünkü çıktısı normatif bir profildir: federasyon birlikte çalışabilirliği için gerçekleme profili ile dağıtım profili. Bunlar bir kontrol listesidir, otomatik koşan bir süit değildir. Kantara'nın hâlen aktif bir SAML sertifikasyon programı işletip işletmediği doğrulanamamıştır.

Pratikte çalıştırılabilir tek büyük SAML süiti İtalyan kamu kimlik sistemine aittir.

Burada bir düzeltme yapılmalıdır. İlgili deponun açıklamasına göre süitte yedi aileye bölünmüş 300'den fazla bireysel kontrol bulunmaktadır: dört aile servis sağlayıcı metadata'sının biçimsel doğrulaması, üç aile servis sağlayıcı istek doğrulaması ile bir aile, 111 kontrolle, kimlik sağlayıcı yanıtlarına karşı servis sağlayıcı davranışının etkileşimli doğrulamasıdır.

Bu süit servis sağlayıcıları test etmektedir, kimlik sağlayıcıları değil. Araç bir test kimlik sağlayıcısı gibi davranarak servis sağlayıcıyı sınamaktadır.

Çalıştırma tek bir konteyner komutuyla yapılmakta ile bir web arayüzünden erişilmektedir. Bileşenleri bir komut satırı aracı, bir doğrulayıcı arayüzü ile bir demo kimlik sağlayıcısıdır.

263 test rakamı doğrulanamamıştır; birincil kaynakta geçen sayılar 300'den fazla ile 111'dir. 263 muhtemelen belirli bir profil için süzülmüş bir alt küme ya da eski bir sürümün rakamıdır. Bu iddianın düzeltilmesi önerilmektedir.

Kimlik sağlayıcı tarafı için ayrı bir depo vardır: aynı kurumun kimlik sağlayıcı uyum test aracı, Apache 2.0 lisanslıdır. Ancak olgunluğu çok düşüktür: dört yıldız, bir çatal ile 51 işleme. Docker yoktur; belirli bir Node.js sürümü ile yardımcı araçlar gerektirmekte, elle sertifika üretimi istemektedir. Açıklaması test ailelerini ya da bir sayı belirtmemektedir. Kimlik sağlayıcı tarafında ne test ettiği doğrulanamamıştır; Argus için ancak keşif amaçlı denenebilir, güvenilir bir doğruluk ölçütü değildir.

İlgili komut satırı aracı 13 profil sunmaktadır. Çok sayıda sahte yanıt gönderen bir modu vardır; yani servis sağlayıcının kötü niyetli kimlik sağlayıcı yanıtlarına dayanıklılığını test etmektedir. Argus kimlik sağlayıcı olduğu için bu araç doğrudan Argus'u test etmemektedir; ancak Argus'un servis sağlayıcı tümleşmelerini, yani federasyon ya da aracı rolünü test etmek için kullanılabilir.

### 1.9 LDAP

Resmî bir uyum süiti yoktur. Mevcut olanlar şunlardır.

OpenLDAP'ın kendi test süiti kaynak ağacında bulunmakta ile arka uç başına numaralı testler içermektedir. Bu, projenin kendi gerileme süitidir; üçüncü taraf bir sunucuya kolayca yöneltilememektedir ile harici sunucuya karşı çalıştırılabilirliği doğrulanamamıştır. Yapılandırma test aracı yalnızca sunucu yapılandırmasını doğrulamakta ile protokol uyumuyla ilgisi yoktur. Pratik yaklaşım standart dizin komut satırı araçlarıyla davranışsal doğrulama ile gerçek istemcilerle birlikte çalışabilirliktir. Yük testi için iki araç vardır: biri bir dizin sunucusu paketiyle gelmekte ile eşzamansız işlemler, çok iş parçacığı, arama, ekleme, silme ve bağlanma desteklemektedir; diğeri dizine özel bir kıyaslama tezgâhıdır. Bir test için hazır bir Docker imajı bulunmaktadır.

### 1.10 WebAuthn ile FIDO

Bağlı taraf, yani sunucu tarafı test edilebilmektedir. FIDO uyum araçları masaüstü uygulaması sunucu testleri çalıştırmaktadır.

Erişim için FIDO Alliance'a bir test aracı erişim talebi formu doldurulup indirme talebi gönderilmektedir; şartname listesinden ilgili sürüm seçilmektedir. Onay sonrası e-postayla kimlik bilgileri ile indirme bağlantısı gelmektedir. Üyelik gerekliliği açıkça belirtilmemektedir; yalnızca resmî bir talep ile onay süreci vardır. Sertifikasyon ücretleri ayrıdır ile ödeme yapılana kadar işlem yapılmamaktadır; ücret tutarları sayfada yayımlanmamıştır.

Sunucunun sunması gereken dört REST uç noktası kanıtlama seçenekleri ile sonucu, ve doğrulama seçenekleri ile sonucudur. Bu, uyum testi için tanımlanmış normatif olmayan bir API'dir; yani Argus'un üretim API'sinden farklıdır ile yalnızca teste özel bir adaptör yazmak gerekmektedir.

Test sayısı için bir kütüphane dokümanındaki örnek çıktı 160 geçen test göstermektedir. Bu resmî bir beyan değil bir örnek koşu çıktısıdır; FIDO'nun kendi dokümanında sayı belirtilmemektedir.

Sertifikasyon yolu kendi kendine doğrulama artı bir birlikte çalışabilirlik etkinliği ile başvurudur. Argus sertifika hedeflemediği için yalnızca kendi kendine doğrulama kısmı ilgilidir.

Ücretsiz alternatif ile sürekli tümleştirme için asıl pratik yol Chrome geliştirici araçları protokolündeki sanal kimlik doğrulayıcıdır. CTAP2, USB ile kalıcı anahtar emülasyonu sunmakta ile WebAuthn arayüzü kapatılabilmektedir. Tarayıcı otomasyon araçlarıyla sürülmektedir. Sınırı yalnızca Chromium olmasıdır; Safari ile Firefox desteklememektedir. Rust'ta bir yazılım kimlik doğrulayıcı kütüphanesi araştırmada doğrulanamamıştır.

### 1.11 OAuth genel

OAuch açık kaynak bir OAuth 2.0 yetkilendirme sunucusu güvenlik ile tehdit modeli uyum analizörüdür. On üç kategoride 195 test durumu bulunmaktadır: doküman desteği on, özellik desteği 19, token uç noktası 30, cihaz yetkilendirme uç noktası beş, erişim ile yenileme token'ları dokuz, kimlik token'ları 15, JWT'ler 11, PKCE sekiz, iptal sekiz, eşzamanlılık beş, yetkilendirme uç noktası 26 ile API uç noktası sekiz. OIDC sağlayıcılarını da desteklemektedir. Akademik temeli RAID 2022'deki bir makaledir; yüz kamuya açık sağlayıcı taranmıştır. Ortalama bir sağlayıcı güvenlik şartlarının %34'ünü, zorunluların %20'sini uygulamamaktadır; 97 sağlayıcıda en az bir tehdit tamamen azaltılmamıştır ile sağlayıcı başına ortalama dört azaltılmamış tehdit bulunmaktadır. Argus için vakıf süitinden sonraki en yüksek değerli araç budur, çünkü vakıf süiti şartnameye uyumu, bu araç ise en iyi uygulama ile tehdit modelini karşılamayı ölçmektedir.

Senaryo tabanlı bir başka test aracı Python'da esnek OAuth ile OIDC senaryoları sunmakta, bir vekil eklentisiyle HTTP izi manipülasyonu yapmakta, kötü niyetli bir sağlayıcı simüle etmekte ile sürekli tümleştirmeyle entegre olmaktadır. Argus kimlik sağlayıcı olduğu için kötü niyetli sağlayıcı kısmı doğrudan uygulanmamaktadır; ancak Argus'un yukarı akış kimlik sağlayıcı aracısı, yani sosyal giriş ile federasyon için birebir uygundur.

Bir satıcının çevrim içi hata ayıklayıcısı ücretsizdir; JWT çözme ile oluşturma, token alma, iptal ile harici API çağrılarına token ekleme sunmakta ile paylaşılabilir çalışma alanları desteklemektedir. Gerekliliği OAuth servislerinin internetten erişilebilir olmasıdır; yani yerel bir kurulum için tünel gerekmektedir. Manuel bir keşif aracıdır, bir sürekli tümleştirme aracı değildir.

Bir başka satıcı vakıf süitine test ortamı ile kod katkısı yapmıştır; süitin belgelerinde bir otomatik örnek yapılandırma sayfası bulunmaktadır.

Bir Apache modülünün test setleri özel bir uyum test seti olarak doğrulanamamıştır; bilinen kullanımı bir bağlı taraf gerçeklemesi olmasıdır.

---

## 2. Birlikte çalışabilirlik testi, gerçek karşı taraflarla

### 2.1 Ücretsiz ya da kum havuzu erişimi olan servis sağlayıcılar

| Karşı taraf | Erişim | Doğrulama durumu |
|---|---|---|
| Okta | Tümleştirici ücretsiz planında kurum hesabı ücretsiz oluşturulabilmektedir; SCIM sağlaması ücretsiz katmanda etkinleştirilebilmektedir, sağlama sekmesi altından API tümleşmesi yapılandırılarak. Özel SCIM tümleşme örneği yalnızca oluşturulduğu kurumda kullanılabilmektedir | Doğrulanmıştır, geliştirici forumu ile geliştirici belgeleri kaynaklıdır |
| Microsoft Entra kimliği | Ücretsiz kiracı ile özel SCIM uç noktası desteklenmektedir; doğrulayıcı ayrıca ücretsiz bir web aracıdır | Doğrulanmıştır. Hangi ürün seviyesinin giden uygulama sağlamasını içerdiği, yani birinci kademe premium gerekip gerekmediği doğrulanamamıştır; bu önemli bir maliyet riskidir |
| Salesforce | Geliştirici sürümü kurumları ücretsizdir ile SAML servis sağlayıcısı olarak yapılandırılabilmektedir. Bir uyarı vardır: 2026 yaz sürümü tek yapılandırmalı SAML çoklu oturum çerçevesini kaldırmaktadır, tüm müşteriler çok yapılandırmalı SAML'a geçmelidir; kum havuzu önizlemesi 8 Mayıs 2026, üretim 15 Mayıs ile 5 ve 12-13 Haziran 2026 tarihlerindedir | Doğrulanmıştır. Argus'un SAML çıktısının bu yeni çerçeveyle test edilmesi gerekmektedir |
| ServiceNow | Kişisel geliştirici örneği ücretsizdir | Doğrulanamamıştır; arama sonuçlarında bu örneğin SAML çoklu oturumu desteklediğine dair birincil kaynak bulunamamıştır |
| Workday, Slack, Zoom, Atlassian, AWS kimlik merkezi ile Google Workspace | — | Doğrulanamamıştır; hiçbiri için ücretsiz geliştirici ya da kum havuzu katmanının SAML veya SCIM içerdiği birincil kaynaktan doğrulanamamıştır. Google Workspace özelinde bir satıcı analizine göre Google SCIM'i kamuya açık biçimde desteklememektedir; yalnızca veri çekilebilmekte, itilememektedir |

Pratik sonuç şudur: ücretsiz ile güvenilir biçimde erişilebilen gerçek karşı taraflar Okta, Entra ile Salesforce geliştirici sürümü üçlüsüdür. Diğerleri için ya ücretli katman ya da iş ortağı programı gerekmektedir. Kalan servis sağlayıcılar için davranış emülasyonu tek gerçekçi yoldur.

### 2.2 SCIM istemcilerinin çelişkili davranışları, doğrulanmış liste

Bir satıcının 15 Kasım 2024 tarihli SCIM zorlukları yazısı birincil olarak en zengin kaynaktır. Doğrulanan farklar şunlardır.

| Konu | Okta | Entra kimliği |
|---|---|---|
| Sağlama kaldırma | Güncelleme ya da yama ile etkin bayrağını kapatmaktadır; silme kullanmamaktadır | Silme uç noktasını kullanmaktadır, ayrıca kullanıcı yamasıyla etkin bayrağını kapatmaktadır |
| Grup üyeliği | Yama ile güncellemenin ikisini de desteklemektedir; tümleşme ağı şablonlarında öntanımlı yamadır | Yalnızca yama ekle ve çıkar göndermektedir; 200 yanıtı aldıktan sonra üyeleri bir daha doğrulamamaktadır, kendini doğruluk kaynağı kabul etmekte ile tam mutabakat yapmamaktadır |
| Eşzamanlama sıklığı | Gerçek zamanlıdır | Öntanımlı 40 dakikadır, ya da talep üzerinedir |
| Askıya alınmış kullanıcı | Kullanıcı askıya alındıysa grup üyelik değişikliklerini bildirmemektedir | Hâlâ sağlanmış bir grupta olan kullanıcıyı askıya almamaktadır |
| Özel nitelik | Çekirdek kullanıcı şeması ön ekli özel nitelikleri üst düzey olarak işlemektedir | Şema uzantısı ön eki ile iç içe yapı beklemektedir |
| Süzme | Son değişiklik alanıyla süzmeyi desteklememektedir | Bulut yönetimli ile eşzamanlanmış kullanıcılar için e-posta alımı farklıdır |
| Grup itme | Desteklemektedir; itme için atamadan ayrı gruplar gerekmektedir | — |

Diğerleri şöyledir: bir satıcı kullanıcıyı askıya almak yerine silmekte ile yalnızca grup üyeliğiyle sağlamaktadır. Bir başkası grup silindiğinde başka etkin grupta olmayan tüm üyeleri devre dışı bırakmaktadır. Genel olarak dış tanımlayıcı tutarlı biçimde benzersiz kimlik kabul edilmemekte; toplu işlemler isteğe bağlı ile desteği tutarsızdır; e-posta çoğu yerde zorunlu olmadığından geçersiz olay üretilmektedir.

Argus tasarımı için ek bir doğrulanmış tehlike vardır. Entra 2000 üyeli bir grup güncellemesi gönderdiğinde, sunucu her yamada tüm üye dizisini değiştiriyorsa ile istek zaman aşımına uğrarsa kısmi durum kalmaktadır, yani 2000 yerine 1200 üye, ile Entra bunu hiç doğrulamamaktadır. Yani Argus'un SCIM grup yaması atomik ile eş güçlü olmalı, değiştirme anlambilimi asla kısmi uygulanmamalıdır.

Bir satıcının soru cevap platformunda raporlanmış iki gerçek dünya sorunu vardır: doğrulayıcının yama testlerinin farklı yük formatı yüzünden başarısız olması, ile başarılı üye eklemesinden sonra tekrarlayan grup yaması çağrıları.

### 2.3 Kum havuzu kurulumu, pratik reçete

Birinci adım Okta tümleştirici ücretsiz planında kurum açmak, özel SCIM tümleşmesi eklemek, Argus'un SCIM temel adresi ile taşıyıcı belirtecini vermek ile on üç adımlı oluştur oku güncelle sil süitini koşturmaktır.

İkinci adım Entra ücretsiz kiracısında kurumsal uygulama olarak galeri dışı bir uygulama açıp sağlama sekmesinden SCIM tanımlamaktır. Ayrıca doğrulayıcıyı şema keşfi modunda Argus'a yöneltmektir.

Üçüncü adım şudur: Argus yerel olduğu için her ikisi de kamuya erişilebilir bir adres istemektedir, yani bir tünel ya da geçici önizleme ortamı gerekmektedir. Bu, bu katmanın sürekli tümleştirmede her birleştirme isteğinde koşamayacağı anlamına gelmektedir; aşağıdaki tabloda gecelik olarak konumlanmıştır.

Dördüncü adım yakalanan gerçek trafiği kaydetmek ile bir kimlik sağlayıcı istemci emülatörü test düzeneğine dönüştürmektir. Böylece Okta ile Entra davranışları hermetik olarak, tünelsiz, her birleştirme isteğinde yeniden oynatılabilmektedir. Bu, ücretsiz katmanı olmayan servis sağlayıcılar için de tek ölçeklenebilir yaklaşımdır.

### 2.4 Test matrisi ne kadar büyümektedir

Naif çarpım şudur. Protokoller yedidir: OIDC, OAuth 2.1, SAML, SCIM, LDAP, WebAuthn ile model bağlam protokolü. Karşı taraflar protokol başına gerçekçi olarak üç ile sekiz arasındadır; SCIM için beş, SAML için yedi, OIDC bağlı taraf için beşten fazla. Senaryolar mutlu yol, hata yolları, çok kiracılık izolasyonu, belirteç ile oturum yaşam döngüsü, anahtar rotasyonu ile sağlama kaldırma dâhil on ile yirmi arasındadır.

Yedi çarpı altı çarpı on beş yaklaşık 630 birlikte çalışabilirlik kombinasyonu etmektedir. Bu, tam kombinatoryal koşumun imkânsız olduğu anlamına gelmektedir.

Matrisi kırmanın yolu üç eksende ayrıştırmadır. Birincisi protokol doğruluğudur, karşı taraftan bağımsızdır ile uyum süitleriyle ölçülmektedir; protokol çarpı senaryo, karşı taraf yoktur, yaklaşık 105 eder. İkincisi karşı taraf tuhaflıklarıdır; protokolden bağımsız değildir ancak senaryodan büyük ölçüde bağımsızdır ile her karşı taraf için davranış profili olarak kodlanmaktadır, yani sağlama kaldırma yöntemi, yama anlambilimi, süzme desteği ile eşzamanlama sıklığı. Beş ile sekiz profil çarpı yaklaşık on doğrulama, 60 ile 80 eder. Üçüncüsü gerçek uçtan uca duman testidir; yalnızca kritik çiftler için, gecelik ya da haftalık, yaklaşık on kombinasyon.

Toplam 630 yerine yaklaşık 200 anlamlı test etmektedir. İkili ya da kombinatoryal test tasarımı burada doğal yaklaşımdır.

---

## 3. Yük testi, kimlik sağlayıcıya özgü

### 3.1 Keycloak kıyaslama projesi, birincil sayılar

Proje Keycloak deposunun kıyaslama bileşenidir ile Gatling tabanlı olduğu doğrulanmıştır. Üç modülü vardır: Gatling yük testlerini içeren kıyaslama modülü; gözlemlenebilirlikli minikube ile Docker bileşimi sunan hazırlama modülü; ile bir veri kümesi modülü, ki tanımı bir yük testine hazırlamak üzere Keycloak veri deposunda varlık oluşturabilen bir eklentidir. Bu sonuncusu Argus için doğrudan kopyalanabilir bir fikirdir.

Senaryolar depo ağacından okunmuştur: özel, yönetim, kimlik doğrulama ile temel paketleri; ortak simülasyon ile senaryo oluşturucu sınıfları. Kimlik doğrulama paketi altında yetkilendirme kodu, istemci sırrı ile kullanıcı adı parola girişi bulunmaktadır. Temel paket altında bir alma senaryosu vardır. Belgelerde ayrıca oturum listeleme ile bölge oluşturma geçmektedir.

Yapılandırma açısından hem açık hem kapalı model bulunmaktadır. Saniyedeki kullanıcı seçeneği, öntanımlı bir, açık iş yükü modelini vermektedir; eşzamanlı kullanıcı seçeneği kapalı modeli vermektedir. Ayrıca rampa süresi, öntanımlı beş saniye, ölçüm süresi, öntanımlı otuz saniye, ile düşünme süresi, öntanımlı sıfır bulunmaktadır. Bölge sayısı, bölge başına kullanıcı ile bölge başına istemci seçenekleri çok kiracılık ölçekleme parametreleridir ile Argus için birebir uygundur. Son olarak hizmet seviyesi hata yüzdesi, öntanımlı sıfır, ile başarısızlıkta HTTP günlükleme seçenekleri vardır.

### 3.2 Yayımlanmış Keycloak 26.4 sonuçları, en değerli veri

Ekim 2025 tarihli resmî kıyaslama yazısından alınmıştır.

| Saniyedeki giriş | Saniyedeki belirteç yenileme | Kapsül işlemcisi | Kapsül belleği | Veritabanı örneği |
|---|---|---|---|---|
| 500 | 2.500 | 24 | 4 GB | db.r8g.2xlarge |
| 1.000 | 5.000 | 40 | 8 GB | db.r8g.4xlarge |
| 2.000 | 10.000 | 74 | 8 GB | db.r8g.16xlarge |

Birincil boyutlandırma formülleri şunlardır: bir sanal işlemci çekirdeği yaklaşık 15 giriş ya da yaklaşık 120 yenileme belirteci isteği taşımaktadır; trafik sıçramaları için yüzde 150 pay önerilmektedir.

Darboğaz cevabı nettir: giriş, yenilemeden yaklaşık sekiz kat pahalıdır. Kapasite planlaması saniyedeki giriş üzerinden yapılmaktadır.

Diğer doğrulanmış bulgular şunlardır. Ağ gecikmesine aşırı hassasiyet vardır: çok bölgeli dağıtımda 10 milisaniyelik gecikme 99. yüzdelik yanıt süresini 47 milisaniyeden 84 milisaniyeye çıkarmıştır. Argus çok bölgeli olacaksa bu tek başına bir tasarım kısıtıdır. Veritabanı işlemci kullanımı yüzde 77'de tepe yapmıştır; Keycloak önbelleği 10 binden 200 bin girdiye çıkarılınca veritabanı yükü yüzde 63'e düşmüştür. Giriş ile yenileme oranı birde beştir; bu kıyaslamanın seçtiği profildir, yayımlanmış bir üretim oranı değildir.

Yük profili konusunda yayımlanmış üretim verisi doğrulanamamıştır. Büyük satıcıların gerçek giriş, yenileme ile iç gözlem oranlarını yayımladığına dair birincil kaynak bulunamamıştır. Bulunabilenler yalnızca hız sınırlarıdır: bir satıcının kimlik motorunda kullanıcı başına beş saniyede yirmi istek; bir başkasında istemci kimliği başına hesap başına yüz yenileme belirteci. Keycloak'ın birde beş oranı elimizdeki tek gerekçelendirilebilir başlangıç noktasıdır. İç gözlem oranı için hiçbir yayımlanmış veri yoktur; ancak mimari olarak JWT erişim belirteci kullanılırsa iç gözlem sıfıra yakındır, opak belirteç kullanılırsa iç gözlem her API çağrısı demektir, yani girişten iki üç büyüklük mertebesi fazla olabilmektedir. Argus opak belirteç destekleyecekse iç gözlemin en yüksek hacimli uç nokta olacağını varsaymak güvenlidir.

Gatling raporlamasında Keycloak 99. yüzdeliği almaktadır.

Bir çekince vardır: Keycloak ekibi Gatling'den memnun değildir ile olası ardıllarının değerlendirilmesine dair açık bir konu bulunmaktadır.

### 3.3 Eşgüdümlü atlama, hangi araç doğru ölçmektedir

Problem şudur: yük üreteci, test edilen sistem yavaşladığında istek gönderimini istemeden yavaşlatmakta ile kuyruk gecikmesi sıçramaları ölçümden düşmektedir. Klasik üreteçler gecikmeyi gönderimden yanıta kadar ölçmektedir; bu model yüksek gecikme yapay eserlerinin çoğunu göz ardı etmektedir.

Doğru ölçen araçlar şunlardır.

| Araç | Eşgüdümlü atlama durumu | Detay |
|---|---|---|
| wrk2 | Doğrudur | Gil Tene'nin wrk çatalıdır. Sabit hız bayrağı ile bir yüksek dinamik aralık histogramı sunmaktadır. Gecikmeyi gerçekte gönderildiği andan değil, yapılandırılan verime göre gönderilmesi gereken andan ölçmektedir |
| k6 | Şartlı doğrudur | Sabit varış hızı yürütücüsüyle doğrudur; öntanımlı yürütücüler eşgüdümlü atlamaya açıktır. Doğrulanmış seçenekleri zorunlu hız, öntanımlı bir saniyelik zaman birimi, zorunlu süre, zorunlu ön ayrılmış sanal kullanıcı ile azami sanal kullanıcıdır. Yinelemeler sistem yanıtından bağımsız başlamaktadır, saniyede onda yaklaşık 100 milisaniye aralıkla. Belgedeki kritik uyarı şudur: çok düşük bir ön ayrılmış sanal kullanıcı ayarı testin istenen hızdaki süresini kısaltmaktadır. Yani havuz yetersizse hedef hız tutturulamamakta ile eşgüdümlü atlama sessizce geri dönmektedir |
| Gatling | Şartlı doğrudur | Saniyedeki kullanıcı seçeneğiyle açık model mevcuttur. Eşgüdümlü atlamayı özel olarak nasıl ele aldığına dair birincil kaynak bulunamamış ile doğrulanamamıştır |
| Locust | Kısmen | Açık ile kapalı model ayrımını belgelemektedir; her kullanıcı bir yeşil iş parçacığı olduğundan tek düğüm verimi k6'dan düşüktür |
| Vegeta ile autocannon | Doğrudur | wrk2'nin açık döngü yaklaşımını benimsemişlerdir |
| oha | Belirsizdir | Rust ile yazılmış, metin arayüzlü bir alternatiftir. Eşgüdümlü atlama açısından doğruluğu doğrulanamamıştır; duman testi için uygundur, kapasite ölçümü için değildir |

Argus için sonuç şudur: kapasite sayıları k6'nın sabit varış hızı yürütücüsüyle ya da wrk2 ile üretilmelidir; ön ayrılmış ile azami sanal kullanıcı mutlaka bilinçli ayarlanmalı ile düşen yineleme metriği başarısızlık koşulu yapılmalıdır.

### 3.4 Argon2 yük testini nasıl bozmaktadır ile istemci tarafında ne gerekmektedir

Doğrulanmış gerçekler şunlardır. Keycloak'ta Argon2'ye geçiş sanal makinede büyük çöp toplama artışı ile yüksek işlemci kullanımı yaratmıştır; ilgili konuda uygulamaların orta ile yüksek yük altında anormal davrandığı belirtilmektedir. Argon2 ile scrypt bellek sıkı algoritmalardır, yani grafik işlemci ile özel donanım direnci yüksektir; ancak bu bellek maliyeti eşzamanlılığı düşürmektedir. Aritmetik açıktır: 200 eşzamanlı giriş çarpı 64 mebibayt, 12,8 gibibayt bellek talebi etmektedir. Bellek maliyeti ortalamaya değil tepe eşzamanlılığa göre boyutlandırılmalıdır. Öneri paralelliği bir tutmaktır, ki bir özet bir çekirdeğe eşlensin, birkaç çekirdeğe değil; ile işçi havuzu hem işlemci hem bellek bütçesine göre sınırlanmalıdır. Hedef, doğrulama 300 milisaniyenin altında kalırken sunucunun sürdürebileceği bellek maliyetini azamiye çıkarmaktır; kıyaslama üretime denk donanımda yapılmalıdır.

İstemci tarafında işlemci bağımlı bir uç noktayı test etmek için gerekenler şunlardır.

Birincisi, kapalı model kullanılmamalıdır. Test edilen sistem yavaşladıkça istemci de yavaşlamakta ile gerçek doygunluk noktası hiç görünmemektedir. Açık model, yani sabit varış hızı zorunludur.

İkincisi, yük üreteci ayrı makinede olmalıdır. Argon2 bellek sıkı olduğu için aynı makinedeki üreteç, test edilen sistemin önbelleğini ile bellek bant genişliğini çalmakta ile ölçüm kirlenmektedir. Bu, HTTP bağımlı uç noktalarda önemsizdir, Argon2'de belirleyicidir.

Üçüncüsü, kuyruk derinliği ile reddedilen istekler ayrı ölçülmelidir. Argon2 doyduğunda sistem gecikme artışı yerine kuyrukta biriktirme yapmaktadır; yalnızca 99. yüzdeliğe bakan bir test doygunluğu geç fark etmektedir. Düşen yineleme ya da kabul denetimi reddi bir metrik olmalıdır.

Dördüncüsü, ayrı bir yalnızca özetleme mikro kıyaslaması tutulmalıdır, Rust'ta bir kıyaslama çerçevesiyle, böylece Argon2 parametre değişikliğinin etkisi HTTP gürültüsünden bağımsız görünmektedir.

Beşincisi, giriş yükü yenileme ile iç gözlem yükünden ayrı senaryolarda çalıştırılmalı, sonra karışık profilde koşulmalıdır. Keycloak'ın çekirdek başına 15'e karşı 120 istek farkı, karışık profilde girişin kaynak açlığına yol açacağını göstermektedir; yani bölme duvarı ya da ayrı iş parçacığı havuzu tasarımının test edilmesi gereken bir davranış olduğu anlamına gelmektedir.

Altıncısı, boyutlandırma formülü şudur: hedef saniyedeki giriş çarpı Argon2 doğrulama süresi, gerekli eşzamanlı özet sayısını vermekte; bu da bellek maliyetiyle çarpılınca gerekli belleği vermektedir. Saniyede 500 giriş çarpı 300 milisaniye, 150 eşzamanlı özet eder; çarpı 64 mebibayt, yalnızca özetleme için yaklaşık 9,6 gibibayt eder.

---

## 4. Kaos ile dayanıklılık testi

### 4.1 Deterministik simülasyon testi, genel

FoundationDB modeli şöyledir. Tüm bir küme tek iş parçacıklı tek süreç içinde deterministik simüle edilmektedir. Anahtar fikir, aynı kodun hem üretimde hem simülasyonda çalışması, yalnızca arayüz gerçeklemelerinin takas edilmesidir. Determinizmsizliğin tüm kaynakları soyutlanmaktadır: ağ, disk, zaman ile sözde rastgele sayı üreteci. Tohumlu üreteç tüm rastgeleliği değiştirmektedir. Aktör tabanlı eşzamanlılık diliyle sıkı tümleşiktir. Ölçek her gece on binlerce simülasyondur; toplamda yaklaşık bir trilyon işlemci saati eşdeğeridir. Ekip diske gerçek veri yazmadan on sekiz ay simülasyon çerçevesi inşa etmiştir.

TigerBeetle'ın simülatörü şunu yapmaktadır: görüntü damgalı çoğaltma protokolünü, ağ simülatörü ile bellek içi depolama arıza simülatörüyle tek süreçte bulanıklaştırmaktadır. Zamanı istediği kadar hızlandırmaktadır; belgelerine göre simülatör zamanının bir dakikası gerçek dünya testinin günlerine denktir. Bir durum denetleyicisi tüm kopyalara kanca takmakta, her durum geçişi anında doğrulanmakta ile kriptografik özet zincirlemesiyle nedensellik kanıtlanmaktadır. Determinizm tohum ile depo işlemesiyle sağlanmakta, yani hatalar birebir yeniden üretilmektedir. İlham kaynakları bir film, bir dosya eşzamanlama motoru ile FoundationDB'dir. Devam eden çalışma protokol farkındalıklı deterministik simülasyon testi ile dört bulanıklaştırıcıya dair iki yazıda anlatılmaktadır.

Antithesis farklı bir yol tutmaktadır: deterministik bir hiper yönetici içinde normal, determinizmsiz yazılımı çalıştırmakta, yani sistemi yeniden tasarlamadan deterministik simülasyon testi sunmaktadır. Konteyner imajı yüklenmekte ile üretim replikası deterministik hiper yöneticide önyüklenmektedir. Ele aldıkları determinizmsizlik kaynakları saat, iş parçacığı serpiştirmesi ile sistem rastgeleliğidir. Belgelerinde açıkça yazılı ödünleşimler şunlardır: deterministik bir simülasyon ortamı kurmak karmaşık ile kaynak yoğun bir iştir, her sistem deterministik simülasyon testini mümkün kılacak biçimde tasarlanamamaktadır, ile harici bağımlılıklar taklit edilmelidir. Fiyat işlemci saati bazlıdır; kurumsal müşteriler tipik olarak yıllık 20 bin ile 100 bin dolar üzeri ödemektedir. Aralık 2025'te 105 milyon dolarlık bir A serisi turu duyurulmuştur. Argus için fiyat engelleyicidir; ancak sistemi yeniden tasarlamama özelliği, kütüphane düzeyindeki deterministik simülasyona göre tümleştirme maliyetini sıfırlamaktadır. Erken aşamada hayır, ürün olgunlaştığında yeniden değerlendirilmelidir.

### 4.2 Rust'ta uygulanabilirlik

| Araç | Ne yapmaktadır | Olgunluk | Argus'a uygunluk |
|---|---|---|---|
| turmoil | Tek iş parçacığında birden fazla eşzamanlı ana makine sunmaktadır; ağ ile dosya sistemine gecikme, düşme, bölünme, çökme ile yırtık yazma enjekte etmektedir; elle kontrol ya da tohumlu üreteçle. Paket ailesi çekirdek paket, ağ paketi, dosya sistemi paketi ile bir giriş çıkış halkası paketinden oluşmaktadır | 1300 yıldız, aktif geliştirme ile MIT lisansı. Tokio ekibi 2023'te duyurmuş ile paketin hâlâ deneysel olduğunu söylemiştir. TLS desteği, tokio sürüm kısıtları ile desteklenmeyen özellikler benioku dosyasında açıkça yazılı değildir ile doğrulanamamıştır | Ortadır. Argus'un Postgres'e gerçek TCP ile bağlanması, turmoil altında ağ paketine taşınmayı gerektirmektedir; Postgres istemcisi doğrudan çalışmayabilir. En pratik kullanım Argus düğümleri arası yayılımın, yani çağ ile önbellek geçersizleştirme yayılımının simülasyonudur, veritabanı taklit edilerek |
| madsim | tokio benzeri ancak deterministik bir koşum ortamıdır. Bağımlılık takasıyla kullanılmakta ile bir derleyici bayrağıyla etkinleştirilmektedir. Simülatör paketleri tokio, gRPC, etcd istemcisi, Kafka istemcisi ile bir nesne depolama geliştirme kitidir. Ayrıca zaman ölçme, rastgelelik, yeniden deneme, Postgres istemcisi ile akış paketlerinin yamalı sürümleri bulunmaktadır | 1200 yıldız, 343 işleme ile Apache lisansı. Dağıtık bir akış işleme veritabanı üretimde kullanmaktadır; bu en güçlü olgunluk sinyalidir | Yüksektir. Postgres istemcisi yaması olması Argus için belirleyicidir, çünkü veritabanı istemcisi simülasyon altında çalışabilmektedir. API kapsama yüzdesi ile başarım ek yükü belgelenmemiştir |
| mad-turmoil | madsim'in sistem kütüphanesi sembol geçersiz kılma yaklaşımıyla turmoil tabanlı simülasyonu birleştirmektedir; sürekli tümleştirmede bir üst test aynı tohumu yeniden koşup izleme seviyesi günlükleri bayt bayt karşılaştırmaktadır | Yeni ile düşük olgunluktadır | Deneyseldir |
| Shuttle | Rastgeleleştirilmiş eşzamanlılık testidir. İş parçacığı çizelgelemesini kontrol etmekte ile sezgisel rastgele çizelgeleme uygulamaktadır. tokio ile rastgelelik sarmalayıcıları artı standart kütüphanenin eşzamanlama ile koleksiyon ilkelerini sunmaktadır. Eşzamansız desteklidir | 1100 yıldız, 319 işleme ile crates.io'da yayımlıdır | Dar kapsamda yüksektir. Depodaki açık ödünleşim şudur: sağlam değildir, yani geçen bir test kodun doğru olduğunu kanıtlamamaktadır, ancak Loom'dan çok daha büyük test durumlarına ölçeklenmektedir. Argus'ta hedef oturum deposu, önbellek geçersizleştirme, bağlantı havuzu ile hız sınırlayıcı gibi paylaşımlı durum bileşenleridir |
| stateright | Bir model denetleyicisidir; rastgele alt küme değil, şartname içindeki tüm gözlemlenebilir davranışları test etmektedir. Aktör modeli, gömülü model denetleyicisi, keşif arayüzü ile hafif bir aktör koşum ortamı sunmaktadır. Bir doğrusallaştırılabilirlik testçisi içermekte ile benzer çözümlerden daha kapsamlı kapsama iddia etmektedir. Her zaman ile bazen özellikleri tanımlanabilmektedir. Örnekleri tek kararlı Paxos ile iki aşamalı işlemedir | Bir kitabı bulunmaktadır; 2025 ile 2026 etkinliği doğrulanamamıştır | Ortadır. Argus'un tam sistemini modellemek pahalıdır; protokol durum makinelerini, yani yetkilendirme kodu yaşam döngüsü, DPoP tek seferlik değeri, geri kanal yoklaması ile oturum ve çıkış yayılımını modellemek için idealdir |

### 4.3 Jepsen bir kimlik sağlayıcıya uygulanabilir mi

Kısmen, ancak doğrudan değil. Jepsen doğrusallaştırılabilirlik ile yalıtım ihlallerini aramaktadır; bunun için sistemin bir okuma yazma geçmişi üretmesi gerekmektedir. Bir kimlik sağlayıcının çoğu uç noktası bu kalıba oturmamaktadır; ancak şunlar oturmaktadır: oturum deposu, yani oluşturma, okuma ile iptal, ki doğrusallaştırılabilirlik sorusu anlamlıdır; yenileme belirteci rotasyonu, ki çift kullanım tespiti tam olarak bir eşzamanlılık ile yalıtım problemidir; onay ile yetki kayıtları; ile çok kiracılı yapılandırma çağının yayılımı.

Jepsen'in PostgreSQL analizleri bulunmakta ile doğrudan Argus'u ilgilendirmektedir.

29 Nisan 2025 tarihli yönetilen PostgreSQL 17.4 analizinde test edilen, çok bölgeli yönetilen kümelerdir, 13.15'ten 17.4'e, hem birincil hem salt okunur uç noktalara karşı. İş yükü benzersiz tam sayı listeleri üzerinde okuma ile ekleme işlemleridir, bir döngü denetleyicisiyle. Bulgular anlık görüntü yalıtımı ihlalleridir: bitişik olmayan döngüler ile uzun çatal. Saniyede yaklaşık 150 yazma ile 1600 okuma gibi mütevazı eşzamanlılıkta bu birkaç dakikada bir gerçekleşmektedir. Arıza enjeksiyonu yoktur, yani normal çalışmada olmaktadır. Sonuç, yönetilen hizmetin standart anlık görüntü yalıtımı yerine muhtemelen paralel anlık görüntü yalıtımı sağladığıdır; rapor bu davranışın standart PostgreSQL'de gerçekleşmemesi gerektiğini söylemektedir.

Argus için doğrudan çıkarım şudur: okuma kopyalarından okuma yapan bir kimlik sağlayıcı, yönetilen hizmetler üzerinde tek düğümlü Postgres'ten zayıf yalıtım garantileri almaktadır. Çağ ile iptal yayılımı kendi yazdığını okuma varsayımına dayanıyorsa bu bir güvenlik açığıdır, yani iptal edilmiş bir belirtecin kopyada hâlâ geçerli görünmesi. Bu, Argus'un test etmesi gereken birinci sınıf bir senaryodur.

20 Haziran 2025 tarihli 18 numaralı Jepsen yazısı bir akış ürününü, yönetilen PostgreSQL 17.4'ü ile TigerBeetle 0.16.1'i kapsamaktadır.

Patroni için resmî bir Jepsen analizi yoktur; ancak bağımsız bir çalışma bulunmaktadır. 2 Aralık 2024 tarihli bir blog yazısı, Patroni üzerinde Jepsen testinin okuma işlenmiş yalıtım ihlali olan bilinen bir sorunu yeniden ürettiğini ile üç düğümden biri kaybedildiğinde kümenin toparlanamadığını gözlemlemektedir. Bu birincil bir Jepsen raporu değil bağımsız bir blogdur ile ihtiyatla kullanılmalıdır.

### 4.4 Postgres devralma ile bölünmüş beyin, somut kaos senaryoları

Bir bulut yerel Postgres operatöründe bölünmüş beyin yeniden üretimi elimizdeki en değerli somut veridir; 29 Temmuz 2026 tarihlidir. Kurulum beş düğümlü bir hafif Kubernetes dağıtımı, operatörün 1.30.0 sürümü, PostgreSQL 18.4 ile bir kaos aracının 2.7.2 sürümünün ağ kaosu bileşenidir; üç istemci sürekli yazmaktadır. Deney birincil kapsülü kopyalardan, operatörden ile API sunucusundan izole etmektir.

Ne olduğu şudur: izolasyon kontrolü doğru çalışmış ile yaklaşık 34. saniyede kapsül sonlandırması tetiklemiştir, ancak birincil 177 saniye daha yazmaya devam etmiştir, çünkü nazik kapanış zaman aşımı öntanımlı 180 saniyedir. Terfi eden kopya bu sırada yazmaya başlamıştır; yani yaklaşık 99 saniyelik bir çift birincil penceresi oluşmuş ile her ikisi de işlemeleri onaylamıştır.

Hasar şudur: bölünme iyileştikten ile geri sarma aracı bir hayatta kalanı seçtikten sonra 562 yazma farklı istemcilere yeniden atanmış, 291 yazma tamamen kaybolmuştur; onaylanmış 1.472 yazmanın yalnızca 619'u bozulmadan kalmıştır. Küme kendini mükemmel sağlıklı raporlamış ile hiçbir kısıt ihlali oluşmamıştır.

Azaltma şudur: nazik kapanış zaman aşımını sıfır yapmak ile devralma gecikmesini otuz saniyeye ayarlamak birlikte örtüşmeyi tamamen ortadan kaldırmış ile öntanımlıya kıyasla veri bozulmasını yüzde 80 azaltmıştır.

Argus için çıkarım şudur: veritabanı yüksek erişilebilirlik çözümüne sahip olmak veri kaybı olmaması anlamına gelmemektedir. Onaylanmış yazmaların yüzde 58'i öntanımlı yapılandırmada kaybolmuş ya da bozulmuştur. Bir kimlik sağlayıcı için bu, iptal edilmiş belirtecin geri gelmesi ya da kullanıcının yanlış kiracıya atanması demektir. Argus'un yüksek erişilebilirlik yapılandırması bu iki parametre için açık teste sahip olmalıdır.

Aynı operatör için 16 Ocak 2025 tarihli diğer kaos verileri şunlardır. Üç deney yapılmıştır: bir yük aracıyla 300 saniyelik işlemci çekişmesi, yani gürültülü komşu; on milyon satırlık bir tabloya boş olamaz kısıtı eklenerek kilit çekişmesi; ile birincil kapsülün silinmesiyle birincil arızası. Ölçülen devralma süresi, birincil kapsül silindikten sonra sorgu işlemenin geri gelmesi için yaklaşık üç dakikadır. Gözlem çekirdek içi izleme ile Postgres istatistik görünümleriyle yapılmıştır.

Operatörün 2025 iyileştirmeleri Aralık 2025 tarihli bir yazıda anlatılmaktadır: birincilde ağ izolasyonu tespiti için deneysel bir canlılık yoklaması, yani kendini indirgeme; birincil izolasyon kontrolü, yani kendini çitleme; ile devralmanın ancak düğüm çoğunluğu hemfikirse gerçekleşmesini sağlayan çoğunluk tabanlı bir mekanizma. Ayrıca proje bir vakıf kuluçkasına kabul edilmiştir. Bir mentorluk projesi bu operatör için bir kaos testi çerçevesi teslim etmiştir; sürekli tümleştirmeye entegredir ile devralma süresi ve veri tutarlılığı metrikleri toplamaktadır.

### 4.5 Argus'ta ne test edilmelidir, somut liste

| Senaryo | Beklenen davranış | Nasıl test edilmektedir |
|---|---|---|
| Veritabanı tamamen kayıp | Yeni belirteç yoktur; mevcut JWT'ler doğrulanmaya devam etmektedir, durumsuz doğrulama sayesinde; iç gözlem 503 dönmektedir, asla etkin değil yanıtı değil. Kapalı mı açık mı arıza verileceği kararı açıkça verilmiş olmalıdır | Test konteynerlerinde Postgres durdurulmaktadır |
| Kopya gecikmesi | İptal ile çıkış asla bayat kopyadan okunmamaktadır; çağ okumaları birincilden ya da tekdüze okuma garantili yapılmaktadır | Yapay gecikme eklenmektedir; Jepsen bulgusu ışığında okuma kopyasından yetkilendirme kararı verilmemelidir |
| Çağ yayılımı gecikmesi | Kiracı yapılandırma değişikliği, örneğin bir istemcinin devre dışı bırakılması, sınırlı ile ölçülen bir süre içinde tüm düğümlere ulaşmaktadır; süre aşımında kapalı arıza verilmektedir | turmoil ya da madsim ile düğümler arası bölünme; iptalden sonra belirli bir süre içinde tüm düğümlerin reddetmesi değişmezi |
| JWKS rotasyonu sırasında kesinti | Eski anahtar kimliğiyle imzalanmış belirteçler örtüşme penceresi boyunca doğrulanmakta; yeni anahtar kimliği bağlı taraflarca çekilebilmekte; rotasyon sırasında hiçbir istek 401 almamaktadır | Rotasyon yük altında tetiklenmektedir; k6 senaryosunda 401 sayısı sıfır eşiği konmaktadır. Vakıf süitinde anahtar rotasyonu modülü tam olarak bunu test etmektedir |
| Bölünmüş beyin | Onaylanmış hiçbir yetki ya da belirteç kaybolmamaktadır | Kaos aracıyla ağ kaosu, artı nazik kapanış zaman aşımı ile devralma gecikmesi matrisi; yukarıdaki metodoloji izlenmektedir |
| Yenileme belirteci yeniden kullanım yarışı | Aynı yenileme belirtecinin iki eşzamanlı kullanımında biri başarılı olmakta, diğeri tüm aileyi iptal etmektedir | Shuttle ile süreç içi, artı gerçek eşzamanlı HTTP serpiştirmesi |
| Bağlantı havuzu tükenmesi | Argon2 kuyruğu veritabanı havuzunu aç bırakmamalıdır, bölme duvarı gereklidir | Karışık yük profili ile havuz metrikleri |

---

## 5. Güvenlik testi

### 5.1 Protokole özgü saldırı test setleri

SAML tarafında üç kaynak vardır.

Birincisi bir güvenlik firmasının Burp eklentisidir; SAML mesaj manipülasyonu ile X.509 sertifika yönetimi sunmaktadır. Tekrarlayıcıya bir panel ekleyip imza sarmalama saldırılarını tek tıkla uygulamaktadır. Sekiz yaygın XML imza sarmalama varyantı bulunmaktadır; örneğin birincisi yanıt mesajına, mevcut imzadan sonra imzasız bir klon eklemektedir.

İkincisi bağımsız bir otomatik sondalama aracıdır; SAML uç noktalarını imza sarmalama için yoklamakta ile çok sayıda üretilmiş XML yükü oluşturmaktadır.

Üçüncüsü 10 Aralık 2025 tarihli, 21 Ocak 2026'da güncellenen bir araştırma yazısıdır ile üç yeni saldırı sınıfı tanımlamaktadır; Argus için doğrudan test vektörüdür.

Birincisi nitelik kirlenmesidir: ayrıştırıcılar arası tutarsız ad alanı işleme yüzünden, nitelik sırasına ile ayrıştırıcıya göre farklı nitelikler çözülmektedir.

İkincisi ad alanı karışıklığıdır: rezerve XML ad alanı bildirimlerini manipüle ederek imza öğelerini bazı ayrıştırıcılara görünür, bazılarına görünmez yapmak ile doğrulama mantığını ikiye bölmek mümkündür.

Üçüncüsü boş kanonikleştirmedir ile yeni bir saldırı sınıfıdır: kanonikleştirme, çözülemeyen göreli adreslerle karşılaşınca güvenli biçimde başarısız olmak yerine boş dizge döndürmekte, yani boş içeriğin geçerli özeti üretilmektedir.

Etkilenenler belirli sürümlerin altındaki Ruby, PHP ile ilgili XML güvenlik kütüphaneleri ile libxml2 tabanlı gerçeklemelerdir. Etkilenmeyenler bir XML güvenlik kütüphanesi ile bir federasyon projesinin imza aracıdır.

Yayımlananlar örnek depoda altın SAML yanıtı XML yükleri ile otomatik bir Burp eklentisidir; bunun SAML eklentisine entegre edilmesi planlanmıştır.

Gerçekleyicilere öneriler şunlardır: kısıtlayıcı XML şeması ile asgari uzantı noktası kullanmak; yalnızca imzalanmış öğelerin aşağı akışta işlenmesini sağlamak; kütüphaneleri güncel tutmak; ile erişim kontrolünde e-posta alan adı sonekine güvenmemek.

Argus için çıkarım şudur: Rust'ta sıfırdan SAML yazarken bu üç sınıf gerileme test derleminin çekirdeği olmalıdır. Özellikle boş kanonikleştirme kritiktir; Argus'un kanonikleştirmesi çözülemeyen adreste sert başarısız olmalıdır.

JWT tarafında bir Python aracı on ikiden fazla saldırı modu sunmaktadır: algoritma karışıklığı, yani asimetrik imzayı simetrik özete çevirip açık anahtarı sır olarak kullanmak; algoritma yok atlatması; anahtar kimliği enjeksiyonu, yani dizin gezinme ya da SQL enjeksiyonu; talep kurcalama; ile zayıf sır kaba kuvveti. Bağlam şudur: yalnızca 2025'te altı kritik zafiyet yaygın kullanılan JWT kütüphanelerini etkilemiş, birkaçı tek bir sahte belirteçle tam hesap devralmaya izin vermiştir. Anahtar seti adresi enjeksiyonu ile anahtar kimliği üzerinden SQL enjeksiyonu ayrı vektörlerdir.

OAuth ile OIDC tarafında iki araç öne çıkmaktadır. Yukarıda ayrıntılandırılan 195 testlik analizör, Argus için en yüksek getirili güvenlik aracıdır; tehdit modeline karşı otomatik uyum ölçmektedir. Senaryo tabanlı diğer araç saldırgan sağlayıcı senaryoları sunmakta ile Argus'un federasyon ya da aracı rolü için uygundur.

### 5.2 Web güvenlik tarayıcılarıyla OIDC otomasyonu

Kısmen otomatikleştirilebilmektedir, ancak sürtünmelidir.

Bir açık kaynak tarayıcının otomasyon çerçevesi YAML dosyalarıyla tarama yapılandırmaktadır; örümcek, etkin tarama ile API tanımı içe aktarma işleri bulunmaktadır. OAuth için betik tabanlı kimlik doğrulama önerilmektedir; belirteci alan ile isteklere ekleyen özel bir betik yazılmaktadır. Kurumsal dizin ile çoklu oturum birlikte kullanım hâlâ toplulukta tartışılan, tam çözülmemiş bir konudur.

Gerçekçi değerlendirme şudur: bu tarayıcılar bir kimlik sağlayıcının protokol mantığını test etmemektedir; web katmanı için, yani siteler arası betik, başlıklar, istek sahteciliği ile enjeksiyon için iyidirler. Protokol seviyesi için vakıf süiti artı tehdit modeli analizörü artı senaryo aracı gerekmektedir.

Argus için tavsiye şudur: bu tarayıcılar yönetim konsolu ile onay ve giriş arayüzü için kullanılmalıdır, yani klasik web açıkları için; protokol uç noktaları için değil.

### 5.3 Kimlik sağlayıcıya özgü bulanıklaştırma hedefleri

Genel bulanıklaştırma yöntemleri §11'de araştırılmıştır; burada yalnızca kimlik sağlayıcıya özgü hedefler ele alınmaktadır.

| Hedef | Neden | Derlem kaynağı |
|---|---|---|
| XML ayrıştırıcı ile kanonikleştirme | En yüksek riskli yüzeydir. Yukarıdaki üç saldırı sınıfı doğrudan buradadır | Araştırma yazısının altın SAML örnekleri; sekiz imza sarmalama varyantı; kamu kimlik sistemi test yanıtları |
| XML imza doğrulaması | İmzalanmış ile işlenen öğenin ayrışmasıdır | Burp eklentisi çıktıları |
| SAML metadata ayrıştırıcı | Güvenilmeyen federasyon metadata'sıdır | Federasyon metadata örnekleri |
| JOSE, yani imza ile şifreleme başlığı ve serileştirmeleri | Algoritma karışıklığı, anahtar kimliği enjeksiyonu, kritik başlık ile sıkıştırma bombasıdır | JWT aracının üretimleri |
| Anahtar seti ayrıştırıcı | Uzaktan çekilen güvenilmeyen anahtar setleridir; dev boyut, garip eğri ile yinelenen anahtar kimliği | — |
| LDAP kodlama çözücüsü | Ham bayt protokolüdür, klasik bellek güvenliği yüzeyidir; Rust'ta panik ya da hizmet reddine dönüşmektedir | İlgili RFC mesaj yapıları ile yük aracı trafiği |
| LDAP arama süzgeci ayrıştırıcısı | Süzgeç dizgeleridir; iç içe geçme derinliği yığın taşmasına yol açmaktadır | — |
| SCIM süzgeç ayrıştırıcısı | Süzgeç grameridir; mantıksal işleçler ile bileşik nitelik yolları | Test kütüphanesinin yükleri |
| SCIM yama yolu ayrıştırıcısı | Üye eşitliği ile nitelik erişimi gibi ifadelerdir | — |
| CBOR ile COSE, yani WebAuthn kanıtlaması | Kanıtlama nesnesi ile kimlik doğrulayıcı verisidir; derinlik ile boyut saldırıları | FIDO uyum aracı trafiği |
| CTAP2 kanıtlama formatı | Paketli, güvenlik yongası, platform ile eski varyantlardır | — |
| Adres ile yönlendirme eşleştiricisi | Açık yönlendirme ile normalleştirme farklarıdır | Analizörün yönlendirme testleri |
| Sıkıştırma ile açma, yani SAML yeniden yönlendirme bağlaması | Sıkıştırma bombası ile açma kaynaklı hizmet reddidir | — |
| Model bağlam protokolü mesaj ayrıştırıcısı | Uyum süitinin tel şeması doğrulaması bunu kısmen kapsamaktadır | Uyum koşum aracı trafiği |

Öncelik sırası şudur: XML kanonikleştirme ile imza, sonra JOSE, sonra LDAP kodlaması, sonra SCIM süzgeci, sonra CBOR ile COSE.

### 5.4 Ayrımsal test, Keycloak'a karşı Argus

Pratik midir? Kısmen; şu koşullarda evet.

Uygun olduğu yerler şunlardır. Saf fonksiyonlar ile ayrıştırıcılarda aynı JWT, aynı SAML iddiası ile aynı SCIM süzgeci ikisine verilip kabul ya da ret kararı karşılaştırılabilmektedir. Karar tek bir bittir, karşılaştırması kolaydır ile kâhin sorunu yoktur. Bu klasik ayrımsal bulanıklaştırmadır ile çok değerlidir: Argus kabul edip Keycloak reddediyorsa muhtemelen Argus'ta bir güvenlik açığı vardır. Keşif dokümanlarında, yani yapılandırma, şema ile servis sağlayıcı yapılandırma uç noktalarında yapısal fark alınabilmektedir. Hata kodlarında aynı bozuk istek için hata ile açıklama alanları karşılaştırılabilmektedir; bağlı taraflar bunlara bağımlıdır.

Uygun olmadığı yerler şunlardır: belirteç içerikleri, yani tek seferlik değer, belirteç kimliği, verilme zamanı ile imza, çünkü determinizmsizdir; oturum ile çerez davranışı ve HTML giriş sayfaları; ile Keycloak'ın şartnameden sapan davranışları. Keycloak bir kâhin değildir, referans gerçekleme değildir; Keycloak'a uymak şartnameye uymak demek değildir.

Argus için önerilen konumlandırma şudur: ayrımsal test birincil doğruluk ölçütü değil bir hata bulucu olarak kullanılmalıdır. Birincil ölçüt uyum süitleridir. Fark bulunduğunda hakem şartname metnidir, Keycloak değildir. Pratik uygulama anlık görüntü testleri artı Keycloak'ın test konteyneriyle gecelik bir ayrışma raporudur; başarısız etmeyen, yalnızca raporlayan bir iştir.

OIDC ile SAML gerçeklemelerinin otomatik ayrımsal testi üzerine akademik yazın bu araştırmada doğrulanamamıştır; arama bütçesi dolmuştur.

---

## 6. Test altyapısı

### 6.1 Rust tümleşme testi

Rust'ın test konteynerleri kütüphanesi iki pakettir: bir çekirdek paket ile toplulukça sürdürülen hazır imajlar paketi. Eşzamansız API birinci sınıftır; senkron testler için bir engelleyici özellik bulunmaktadır. Genel imaj tipiyle keyfî bir Docker imajı kullanılabilmektedir. Olgunluk 1100 yıldız, 195 çatal, 839 işleme ile ikili lisanstır. Kesin sürüm ile son yayın tarihi doğrulanamamıştır.

Mevcut topluluk modülleri arasında Postgres, OpenLDAP, bir kimlik sağlayıcı, nesne depolama taklitleri, çeşitli veritabanları ile tarayıcı otomasyonu bulunmaktadır.

Argus için sonuç şudur. Postgres hazırdır. OpenLDAP hazırdır; Argus'un LDAP istemci tarafı ya da göç senaryoları için kullanılabilmektedir. Rust'ta Keycloak modülü yoktur, Java ile Go'da vardır; ayrımsal test için genel imaj tipiyle elle sarmalamak gerekmektedir. SAML servis sağlayıcı konteyneri yoktur; genel imaj tipiyle bir açık kaynak servis sağlayıcı imajı sarmalanmalıdır. Kamu kimlik sisteminin SAML denetim imajı hazır bir SAML test partneri olarak takılabilmektedir. Vakıf uyum süitinin kendisi de Docker bileşimiyle ayağa kalktığı için sürekli tümleştirmede aynı yolla sürülebilmektedir.

### 6.2 Anlık görüntü testi

Rust'ın anlık görüntü kütüphanesi şunu sunmaktadır: serileştirilebilir çıktı JSON olarak anlık görüntülenmekte; format seçenekleri JSON, YAML, TOML ile CSV'dir. Protokol yanıtları için kritik özellik karartmadır; belgeye göre rastgele ya da değişen değerler söz konusu olduğunda anlık görüntüleri kararlı kılmak üzere değerlerin sabit değerlerle değiştirilmesine izin vermektedir. Sözdizimi seçici ile yerine koyulan değer çiftidir, isteğe bağlı bir eşleşme ifadesiyle. İnceleme için bir komut satırı alt komutu, bir düzenleyici eklentisi ile terminalde fark gösterimi bulunmaktadır.

Argus'ta nereye uygulanacağı şudur: keşif yapılandırması ile anahtar seti, anahtar kimliği karartılarak, ve OAuth hata yanıtları; SCIM şemaları, kaynak tipleri ile servis sağlayıcı yapılandırması; çözülmüş JWT talep kümesi, imza değil, ve belirteç kimliği, verilme zamanı, son kullanma ile tek seferlik değer karartılarak; SAML metadata'sı, sertifika ile tanımlayıcı karartılarak, ve iddianın kanonikleştirilmiş hâli; ile LDAP kök girdi tanımı.

Bu, protokol yanıtını yanlışlıkla değiştirme gerilemesini çok ucuza yakalamakta ile uyum süitinin çalışmadığı birleştirme isteklerinde ilk savunma hattı olmaktadır.

### 6.3 Test verisi üretimi

Keycloak'ın veri kümesi modülü doğrudan model alınmalıdır; tanımı bir yük testine hazırlamak üzere veri deposunda varlık oluşturabilen bir eklentidir. Kıyaslamanın ölçeklendirme parametreleri, yani bölge sayısı, bölge başına kullanıcı ile bölge başına istemci, gerçekçi bir çok kiracılı grafiğin hangi eksenlerde büyüdüğünü göstermektedir.

Argus için gerçekçi kiracı, kullanıcı ile rol grafiğinin eksenleri şunlardır: kiracı sayısı çarpı kiracı başına kullanıcı, Zipf dağılımıyla, yani birkaç dev kiracı ile uzun kuyrukta küçük kiracılar; kullanıcı başına grup üyeliği, ki dizin protokollerinde üyelik niteliği patlaması yaşanmakta ile bir dizin sunucusunun belgelerinde büyük gruplar ile üyelik ayarı ayrı bir başlıktır; rol ile kapsam grafiğinin derinliği, yani iç içe grup çözümleme maliyeti; istemci sayısı, yönlendirme adresi sayısı ile etkin oturum ve yenileme belirteci sayısı. Sınır vakaları zorunludur: 2000 üyeli grup, ki Entra'nın gerçek davranışıdır, Unicode ile benzer görünümlü kullanıcı adları, ile çok uzun ayırt edici adlar.

Üretim deterministik tohumlu bir üreteçle yapılmalıdır; aynı tohum aynı veri kümesini vermeli, böylece kıyaslama sonuçları karşılaştırılabilir olmalıdır.

### 6.4 Sürekli tümleştirme süre bütçesi

Rust'ın hızlı test koşucusu Argus'un ölçeğinde zorunludur. Test başına süreç modeli kullanmaktadır; her test kendi sürecinde koştuğu için gerçek yalıtım sağlanmakta, yani bir panik ya da bölümleme hatası diğerlerini düşürmemekte, ile çizelgeleme iyileşmektedir. Hız kaynaklara göre standart test koşucusuna kıyasla iki ile beş kattır; bazı ölçümlerde yüzde 60'a varan hızlanma ya da üç kat belirtilmektedir.

Bölümleme ile parçalama sürekli tümleştirme matrisi için kullanılmaktadır.

```
cargo nextest run --partition count:1/3   # job 1
cargo nextest run --partition count:2/3   # job 2
cargo nextest run --partition count:3/3   # job 3
```

İki mod vardır: sayı tabanlı ile özet tabanlı. Kararsız testler için yeniden deneme seçeneği ile JUnit XML çıktısı bulunmaktadır.

Referans süreler şunlardır. Ory Hydra'nın tam OIDC uyum koşumu için ayrılan zaman aşımı 60 dakikadır. Vakıf süitinin plan çalıştırma betiği paralel çalışmaktadır, bir bayrakla kapatılabilmektedir; yani uyum kendi içinde paralelleşebilmektedir.

Argus için gerçekçi bütçe şudur.

| Aşama | Hedef süre | İçerik |
|---|---|---|
| İşleme öncesi, hızlı | İki dakikanın altı | Biçimlendirme, tüy denetimi, birim testleri ile anlık görüntüler |
| Birleştirme isteği, engelleyici | On beş dakikanın altı | Dört ile sekiz parçalı koşum: birim, test konteynerli tümleşme, özellik testi, Shuttle, sabit tohumla ve kısa, ile kaydedilmiş kimlik sağlayıcı emülatörü tekrarı |
| Ana dala birleştirme | Yaklaşık 45 dakika | Ek olarak vakıf uyum planları, yani temel, yapılandırma, dinamik ile çıkış, model bağlam protokolü uyumu, SCIM test kütüphanesi ile tehdit modeli analizörü |
| Gecelik | İki ile dört saat | Ek olarak finansal API ikinci sürüm planları, deterministik simülasyon testi, yüksek tohum sayısıyla, kısa bulanıklaştırma, Keycloak ayrımsal raporu ile tünelli gerçek kum havuzu koşumu |
| Haftalık | Uzun | Yük testleri, sabit varış hızıyla, kaos, yani bölünmüş beyin matrisi, uzun bulanıklaştırma kampanyaları ile FIDO uyum araçları, elle ya da yarı otomatik |

Uyumu birleştirme isteğinde tutmanın anahtarı beklenen başarısızlıklar temel çizgisidir; hem vakıf betiği hem model bağlam protokolü süiti bunu desteklemektedir. Böylece bilinen eksikler sürekli tümleştirmeyi kırmamakta, ancak gerileme ile bayat temel çizgi yakalanmaktadır.

---

## 7. Argus için test stratejisi, somut tablo

### 7.1 Ana matris

| # | Katman | Araç | Ne ölçmektedir | Sıklık | Sürekli tümleştirme aşaması | Engelleyici mi |
|---|---|---|---|---|---|---|
| 1 | Birim | Hızlı test koşucusu | Fonksiyon doğruluğudur | Her işleme | İşleme öncesi ile birleştirme isteği | Evet |
| 2 | Özellik | Özellik testi kütüphanesi | Ayrıştırıcı ile serileştirici gidiş dönüşü, süzgeç grameri değişmezleridir | Her birleştirme isteği | Birleştirme isteği | Evet |
| 3 | Anlık görüntü | Karartmalı anlık görüntü kütüphanesi | Protokol yanıt yapılarıdır: keşif, anahtar seti, SCIM şemaları, hata kodları ile SAML metadata'sı | Her birleştirme isteği | Birleştirme isteği | Evet |
| 4 | Eşzamanlılık | Shuttle | Oturum deposu, yenileme belirteci rotasyon yarışı, önbellek geçersizleştirme ile havuzdur | Her birleştirme isteğinde kısa, gecelik uzun | Birleştirme isteği ile gecelik | Kısa koşumda evet |
| 5 | Tümleşme | Test konteynerleri, yani Postgres, OpenLDAP ile genel imaj | Gerçek veritabanı ile dizin üzerinden uçtan uca doğruluktur | Her birleştirme isteği | Birleştirme isteği, parçalı | Evet |
| 6 | Kimlik sağlayıcı istemci emülatörü | Kaydedilmiş gerçek trafiğin tekrarı | SCIM istemci tuhaflıklarıdır: yama anlambilimi, etkinlik bayrağı, silme ile iç içe uzantı | Her birleştirme isteği | Birleştirme isteği | Evet |
| 7 | OIDC uyumu | Kendi barındırdığınız vakıf süiti ile plan çalıştırma betiği | Temel, yapılandırma, dinamik, örtük, hibrit ile form gönderimli sertifikasyon planlarıdır | Birleştirmede | Ana dal | Evet, temel çizgili |
| 8 | Çıkış uyumu | Vakıf süiti | Bağlı tarafça başlatılan ile arka kanal, ayrıca ön kanal çıkışıdır | Birleştirmede | Ana dal | Evet, temel çizgili |
| 9 | OAuth güvenlik uyumu | Kendi barındırdığınız tehdit modeli analizörü | On üç kategoride 195 test, tehdit modeli ile en iyi uygulamalardır | Birleştirmede | Ana dal | Evet, temel çizgili |
| 10 | Model bağlam protokolü uyumu | Uyum paketi ile GitHub eylemi | Yetkilendirme sunucusu senaryoları, yani yetkilendirme kodu ile metadata, artı sunucu senaryolarıdır | Birleştirmede | Ana dal | Evet, kontrol başına temel çizgiyle |
| 11 | SCIM uyumu | SCIM test kütüphanesi | İlgili RFC'ler: keşif, oluştur oku güncelle sil ile yama işlemleridir | Birleştirmede | Ana dal | Evet |
| 12 | SCIM satıcı uyumu | Entra doğrulayıcısı, şema keşfi modunda, ile Okta'nın on üç işlemlik süiti | Gerçek istemci uyumudur | Haftalık ya da yayın öncesi | Elle ile gecelik | Hayır, yalnızca rapor |
| 13 | Finansal API ikinci sürümü | Vakıf süiti, nihai güvenlik profili planı | Yüksek güvenlik profili doğruluğudur | Gecelik | Gecelik | Önce rapor, sonra engelleyici |
| 14 | SAML doğruluğu | Kamu kimlik sisteminin servis sağlayıcı denetim imajı, ile deneysel kimlik sağlayıcı aracı | Yedi ailede 300'den fazla kontroldür, servis sağlayıcı tarafında | Gecelik | Gecelik | Hayır, yalnızca rapor |
| 15 | SAML güvenliği | Sekiz imza sarmalama varyantı ile üç yeni saldırı sınıfının örnekleri, gerileme derlemi olarak | Nitelik kirlenmesi, ad alanı karışıklığı ile boş kanonikleştirmedir | Her birleştirme isteğinde, derlem olarak | Birleştirme isteği | Evet |
| 16 | JWT güvenliği | JWT saldırı aracının vektörleri, gerileme derlemi olarak | Algoritma karışıklığı, algoritma yok, anahtar kimliği enjeksiyonu ile anahtar seti adresi enjeksiyonudur | Her birleştirme isteğinde, derlem olarak | Birleştirme isteği | Evet |
| 17 | WebAuthn, ucuz yol | Tarayıcı protokolünün sanal kimlik doğrulayıcısı ile bir tarayıcı otomasyon kütüphanesi | Bağlı taraf akışı uçtan uca, yalnızca Chromium'da | Her birleştirme isteği | Birleştirme isteği | Evet |
| 18 | WebAuthn, resmî yol | FIDO uyum araçları, talep formuyla edinilmektedir; dört test uç noktası için adaptör gerekmektedir | FIDO2 sunucu uyumudur, örnek koşumda yaklaşık 160 test | Yayın öncesi | Elle | Hayır |
| 19 | LDAP doğruluğu | Standart dizin komut satırı senaryoları ile gerçek istemciler | Davranışsal birlikte çalışabilirliktir | Gecelik | Gecelik | Hayır, yalnızca rapor |
| 20 | LDAP yükü | Bir dizin sunucusunun yük aracı ya da bir kıyaslama tezgâhı | Bağlanma, arama ile değiştirme hızı, büyük grup ile üyelik niteliği | Haftalık | Başarım işi | Hayır |
| 21 | Bulanıklaştırma | Rust'ın bulanıklaştırma aracı, hedefler §5.3 önceliğine göre | Bellek, panik ile hizmet reddidir | Gecelik kısa, haftalık uzun | Gecelik | Hayır; çökme bir konuya dönüşmektedir |
| 22 | Deterministik simülasyon, düğümler arası | madsim birincildir, Postgres istemci yaması bulunmaktadır; turmoil alternatiftir | Çağ yayılımı, JWKS rotasyonu ile bölünme altında iptaldir | Gecelik, yüksek tohum sayısıyla | Gecelik | Hayır; tohum kaydedilmektedir |
| 23 | Model denetleme | stateright | Yetkilendirme kodu yaşam döngüsü, yenileme rotasyonu, geri kanal yoklaması ile çıkış yayılımı durum makineleridir; her zaman ile bazen özellikleriyle | Haftalık | Doğrulama işi | Hayır |
| 24 | Yük | Sabit varış hızlı k6 birincildir, wrk2 alternatiftir; ayrı makinede koşmaktadır | Saniyedeki giriş, yenileme ile iç gözlem, ve 99. yüzdelik gecikmedir | Haftalık ile yayın öncesi | Başarım işi | Evet, eşik olarak |
| 25 | Argon2 mikro kıyaslaması | Rust'ın kıyaslama kütüphanesi | Özet süresi ile bellek, parametre değişimi gerilemesidir | Her birleştirme isteği | Birleştirme isteği | Evet, gerileme eşiğiyle |
| 26 | Kaos, veritabanı | Kaos aracının ağ bileşeni ile bulut yerel Postgres operatörü; yukarıdaki metodoloji | Bölünmüş beyin veri kaybı ile devralma süresidir | Haftalık | Kaos işi | Önce hayır, sonra evet |
| 27 | Ayrımsal | Genel imajla Keycloak ile anlık görüntü farkı | Ayrıştırıcı kabul ret farkları ile keşif farklarıdır | Gecelik | Gecelik | Hayır, yalnızca rapor; asla engelleyici değildir |
| 28 | Web güvenliği | Açık kaynak tarayıcının otomasyon çerçevesi | Yönetim konsolu ile giriş ve onay arayüzüdür, yani siteler arası betik, başlıklar ile istek sahteciliği; protokol için değildir | Gecelik | Gecelik | Hayır, yalnızca rapor |
| 29 | Federasyon aracısı | Saldırgan sağlayıcı senaryo aracı | Argus yukarı akış kimlik sağlayıcıya bağlanırken kötü niyetli sağlayıcıya dayanıklılıktır | Gecelik | Gecelik | Hayır, yalnızca rapor |

### 7.2 Uygulama sırası

Birinci faz temeldir ile hemen yapılmalıdır: matristeki ilk beş satır ile Argon2 mikro kıyaslaması. Hızlı test koşucusu ile bölümleme baştan kurulmalıdır. Anlık görüntüler protokol yanıtları yazılırken beraber yazılmalıdır; sonradan eklemek beş kat daha pahalıdır.

İkinci faz doğruluğu ölçmeye başlamaktır: OIDC uyumu, OAuth güvenlik uyumu, SCIM uyumu, SAML güvenliği ile JWT güvenliği. Kendi barındırdığınız vakıf süiti, plan çalıştırma betiği ile beklenen başarısızlıklar temel çizgisi Argus'un tek en yüksek getirili yatırımıdır; Ory Hydra'nın sürekli tümleştirme testi hazır bir referans gerçeklemedir. Tehdit modeli analizörü hemen yanına konmalıdır; şartname uyumu ile güvenlik uyumu farklı şeylerdir ile analizörün yüz kimlik sağlayıcılık çalışması bu farkın ne kadar büyük olduğunu göstermektedir.

Üçüncü faz birlikte çalışabilirliktir: kimlik sağlayıcı istemci emülatörü, model bağlam protokolü uyumu, SCIM satıcı uyumu ile ucuz WebAuthn yolu. Gerçek kum havuzu koşumu bir kez yapılıp trafik kaydedilmeli, sonra her birleştirme isteğinde tekrar oynatılmalıdır.

Dördüncü faz dayanıklılıktır: deterministik simülasyon, yük ile kaos. Postgres izolasyon garantileri ile bölünmüş beyin penceresi açıkça test edilmelidir.

Beşinci faz derinliktir: finansal API ikinci sürümü, SAML doğruluğu, resmî WebAuthn yolu, bulanıklaştırma, model denetleme ile ayrımsal test.

### 7.3 Üç stratejik karar

Birincisi şudur: sertifikasyon hedeflenmemektedir ancak süitler koşulacaktır. Argus tüm uyum süitlerini ücretsiz olarak kendi barındırdığı ortamda çalıştırabilmektedir. Ödenecek tek maliyet mühendislik zamanıdır. Yine de sertifikasyon sitesinden bir API belirteci alıp vakfın sunucusunu kullanmak, kendi süitinizi güncel tutma yükünü ortadan kaldırmaktadır; ancak sürekli tümleştirmeyi harici bir servise bağımlı kılmaktadır. Öneri şudur: kendi barındırdığınız Docker kurulumu, yani Hydra modeli, artı gecelik olarak vakıf sunucusuna karşı çapraz doğrulama.

İkincisi şudur: Keycloak bir kâhin değildir. Ayrımsal test bir hata bulucudur, doğruluk ölçütü değildir. Tek hakem şartname metnidir.

Üçüncüsü şudur: matris patlaması tasarımla çözülmelidir, §2.4'te anlatıldığı gibi. Protokol doğruluğu, yani uyum, çarpı karşı taraf profili, yani kodlanmış davranış sözleşmesi, çarpı az sayıda gerçek uçtan uca duman testi. 630 kombinasyon yerine yaklaşık 200 anlamlı test.

---

## 8. Doğrulanamayanlar

Birincisi, kamu kimlik sistemi süitinin 263 test rakamıdır. Birincil kaynaklarda geçen sayılar yedi ailede 300'den fazla kontrol ile etkileşimli servis sağlayıcı davranış ailesinde 111 kontroldür. 263 rakamı hiçbir yerde doğrulanamamıştır. Ayrıca önemli bir düzeltme vardır: ilgili araç servis sağlayıcıları test etmektedir, kimlik sağlayıcıları değil. Kimlik sağlayıcı tarafı için ayrı ile çok olgunlaşmamış bir depo bulunmaktadır, dört yıldız ile 51 işleme; test aileleri ile sayısı belgelenmemiştir.

İkincisi, vakıf uyum planlarındaki test sayılarıdır. Hiçbir plan için resmî test sayısı bulunamamıştır. Sayı varyant seçimine göre dinamiktir; ancak plan oluşturma çağrısının yanıtından öğrenilebilmektedir.

Üçüncüsü, finansal API ikinci sürüm test planının tam adıdır; hiçbir vakıf sayfasında açıkça yazılı değildir.

Dördüncüsü, FIDO'nun 160 test rakamıdır; bu bir kütüphane belgesindeki örnek koşum çıktısıdır, birliğin resmî beyanı değildir.

Beşincisi, FIDO uyum araçları için üyelik gerekliliği ile ücretlerdir. Form ile onay süreci doğrulanmıştır; üyelik zorunluluğu ile fiyat tutarları hiçbir sayfada yayımlanmamıştır.

Altıncısı, Kantara'nın aktif SAML sertifikasyon programıdır. Birlikte çalışabilirlik profilleri doğrulanmıştır, ki bunlar normatif profillerdir, çalıştırılabilir süit değildir; bugün işleyen bir sertifikasyon programı olup olmadığı doğrulanamamıştır.

Yedincisi, OASIS SAML uyum programının durumudur. İlgili belge mevcuttur, ancak programın devam edip etmediği doğrulanamamıştır.

Sekizincisi, OpenLDAP test hedefinin harici sunucuya yöneltilebilirliğidir. Kendi gerileme süiti olduğu doğrulanmıştır; üçüncü taraf bir LDAP sunucusuna karşı çalıştırılabildiğine dair kanıt yoktur.

Dokuzuncusu, turmoil'in desteklemediği özelliklerdir. TLS desteği, tokio sürüm kısıtları ile Postgres istemci uyumluluğu benioku dosyasında yazılı değildir. Hâlâ deneysel ifadesi 2023 duyurusundandır; 2026 itibarıyla güncel olgunluk seviyesi doğrulanamamıştır.

Onuncusu, madsim'in API kapsama yüzdesi, başarım ek yükü ile bilinen sınırlarıdır; belgelenmemiştir. Üretim kullanımı doğrulanmıştır ancak kapsam derinliği bilinmemektedir.

On birincisi, Gatling'in eşgüdümlü atlama davranışıdır. Açık model desteği doğrulanmıştır, ancak gecikmeyi amaçlanan gönderim anına göre mi ölçtüğü doğrulanamamıştır.

On ikincisi, oha'nın eşgüdümlü atlama doğruluğudur; doğrulanamamıştır. Duman testi için uygundur, kapasite ölçümü için güvenilmemelidir.

On üçüncüsü, üretim kimlik sağlayıcı trafik oranlarıdır, yani giriş, yenileme ile iç gözlem. Büyük satıcılardan yayımlanmış veri bulunamamıştır. Elimizdeki tek referans Keycloak kıyaslamasının birde beş giriş yenileme profilidir; bu bir kıyaslama seçimidir, üretim ölçümü değildir. İç gözlem için hiçbir veri yoktur.

On dördüncüsü, bir hizmet yönetim platformunun kişisel geliştirici örneğinde SAML çoklu oturum desteği, ile diğer altı büyük servis sağlayıcının ücretsiz geliştirici katmanında SAML ya da SCIM erişimidir; hiçbiri birincil kaynaktan doğrulanamamıştır. Google Workspace için negatif bir doğrulama vardır: bir satıcıya göre SCIM itme desteklenmemektedir.

On beşincisi, Entra kimliğinin hangi ürün seviyesinin giden uygulama sağlamasını içerdiğidir, yani birinci kademe premium gerekip gerekmediği; doğrulanamamıştır ile Argus'un birlikte çalışabilirlik bütçesi için bir maliyet riskidir.

On altıncısı, bir SCIM kum havuzu sitesidir; site 403 döndürmüştür, açık kaynak ya da kendi barındırılabilir olduğu ile kaç kontrol koştuğu doğrulanamamıştır.

On yedincisi, model bağlam protokolü uyumunun toplam kontrol sayısıdır. Senaryo dizinleri sayılmıştır, yani sunucu kategorisinde yaklaşık 17, yetkilendirme sunucusu kategorisinde iki artı bir alt dizin, istemci kategorisi sayılmamıştır; ancak toplam kontrol sayısı doğrulanamamıştır. Tek bir senaryoda yirmiden fazla kontrol olduğu belirtilmektedir.

On sekizincisi, Patroni'nin resmî Jepsen analizidir; yoktur. Bulunan çalışma Aralık 2024 tarihli bağımsız bir blogdur ile ihtiyatla değerlendirilmelidir.

On dokuzuncusu, bir Apache modülünün test setlerinin bir uyum test seti olarak varlığıdır; doğrulanamamıştır.

Yirmincisi, Rust'ta yazılım tabanlı bir WebAuthn kimlik doğrulayıcı kütüphanesidir; doğrulanamamıştır. Tarayıcı protokolünün sanal kimlik doğrulayıcısı tek doğrulanmış ücretsiz yoldur, yalnızca Chromium'da.

Yirmi birincisi, OIDC ile SAML gerçeklemelerinin otomatik ayrımsal testi üzerine akademik yazındır; arama bütçesi dolduğu için araştırılamamıştır.

Yirmi ikincisi, Keycloak test süitinin toplam test sayısıdır. Mimarisi doğrulanmıştır, sayı bulunamamıştır.

Yirmi üçüncüsü, stateright'ın 2025 ile 2026 bakım durumudur; doğrulanamamıştır.

Bir not gerekmektedir: bu oturumda web arama bütçesi tükenmiş ile kalan doğrulamalar doğrudan adres üzerinden yapılmıştır. Yirmi birinci madde ile simülasyon kütüphanelerinin olgunluk detayları için ek bir oturum gerekmektedir.
