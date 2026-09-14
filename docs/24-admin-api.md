# §24 — Yönetim API'si ile devredilmiş yönetim

Bu bölüm `ARGUS.md` dosyasının 24. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§24 §X` referansları aynı anlamdadır.

Yöntem yaklaşık 45 arama ile çekme işlemidir; iki alt ajan dahildir. Birincil kaynaklar önceliklendirilmiştir.

---

## 1. Mevcut kimlik sağlayıcıların yönetim API'si tasarımı

### 1.1 Keycloak yönetim REST API'si, kendi bakımcısının itiraf listesi

En değerli bulgu şudur: Keycloak'ın çekirdek bakımcısı, mevcut birinci sürüm yönetim API'sinin tasarım hatalarını 26 Şubat 2025 tarihli 37655 numaralı tartışmada tek tek listelemiştir. Bu bir blog eleştirisi değil ürünün sahibinin pişmanlık listesidir.

| Sorun | Bakımcının kendi ifadesi, 26 Şubat 2025 |
|---|---|
| Sürümleme yoktur | *"Lack of versioning — this will be a must as we introduce a v2, and to solve known usability issues it will have to be a breaking change requiring a new major API version."* |
| Fiil semantiği tutarsızdır | *"POST sometimes work as a PUT, and sometimes as a PATCH, depends randomly on the endpoint."* |
| OpenAPI kalitesizdir | *"Bad quality OpenAPI specification — these are incomplete, and usually not sufficient to generate clients."* |
| Oluşturma yanıtı boştur | *"Creating new resources like a realm returns an empty response, with the ID in the location header — this is very inconvenient to use as it requires separating parsing of location headers."* |
| Doğrulama yoktur | *"Lack of validation — there's very little validation in Admin APIs today, often leading to issues later on."* |
| Varsayılan şişmesi vardır | *"I create a client with a couple fields, and get back a client with 50 fields."* |
| Kimlikle arama zorunludur | *"Not able to use user defined IDs when looking up resources; for example clients are looked up on UUID, and not on clientId."* |

Ek olarak, 19 Mart 2025'te aynı bakımcı boş değer ayarlanamadığını belirtmiştir: bir alanın hiç ayarlanmamış mı yoksa açıkça boşa mı ayarlandığı bilinememektedir. Bu, JSON birleştirme yamasının kullanılmamasının doğrudan sonucudur.

Topluluk katkıları şunlardır. Sayfalama performansı konusunda 17 Temmuz 2025'te belirtildiği gibi atla ile al yaklaşımı performanslı değildir; tüm kullanıcılar arasında sayfalanırken yeni bir kullanıcının kaydolma ihtimali çok gerçektir ile sonuçlar kullanıcı kimliğine göre sıralandığından ve kimlikler ardışık olmadığından o kullanıcı atlanabilmektedir. Yani uzaklık tabanlı sayfalamada kayıt kaçırma problemi vardır. N artı bir sorgu problemi 12 Temmuz 2025'te bildirilmiştir: kullanıcı, rol ile grup çekmek için bir artı n artı n istek gerekmektedir. Toplu silme yoktur; 27 Kasım 2025'te bildirildiği gibi milyonlarca hesap için doğrudan veritabanı sorgusu gibi tehlikeli geçici çözümlere zorlamaktadır.

### 1.2 Keycloak'ın kendi REST API kılavuzu, yazılı ancak uygulanmamıştır

Topluluk deposundaki tasarım kılavuzunda dikkat çekici bir durum vardır: Keycloak'ın yazılı bir API tasarım kılavuzu bulunmakta ile birinci sürüm bu kılavuza uymamaktadır. Kılavuzun kuralları şunlardır.

Sürümleme yoldadır ile sürüm Keycloak sürüm numarasına bağlı değildir; API'nin kararlılık durumunu ifade etmektedir. Sayfalama ilk ile azami sorgu parametreleriyle yapılmakta ile yanıtta RFC 5988 bağlantı başlığı bulunmaktadır. Hata gövdesi zorunlu bir hata kodu ile isteğe bağlı bir açıklama içermektedir. Yama işlemi RFC 7396 JSON birleştirme yamasıdır, içerik tipiyle ayrışmakta ile başarıda 204 dönmektedir. Kaynak isimlerinde depo kaynakları çoğul isim, denetleyici kaynakları ise fiil almaktadır. OpenAPI hakkında hiçbir kural yoktur; kılavuzun kendi boşluğudur.

### 1.3 İkinci sürüm yönetim API'si, fiilen ne çıkmıştır

25 Nisan 2025 tarihli 39220 numaralı ikinci sürüm yönetim API'si destanı planlanmadı olarak kapanmıştır. Ancak iş ölmemiş kapsam daralmıştır: istemci yönetim API'sinin ikinci sürümü Keycloak 26.7.0'da, Temmuz 2026'da deneysel olarak çıkmıştır.

Somut tasarımı şöyledir.

```
/admin/api/{realmName}/clients/v2
```

Sürüm yolun sonunda ile kaynak başınadır. Yani API global olarak sürümlenmemekte, her kaynak kendi hızında ikinci sürüme geçmektedir. Bu, tek seferlik büyük bir göçten kaçınmanın somut yoludur.

Gönderi 201 ile tam temsili gövdede döndürmektedir; birinci sürümün konum başlığı sorunu düzeltilmiştir. Yerleştirme bir ekle ya da güncelle işlemidir: yaratıldıysa 201, güncellendiyse 200 döner ile etkisiz kılınabilirdir. Yama birleştirme yaması içerik tipiyle çalışmakta ile 200 dönmektedir. Sayfalama sıfır tabanlı uzaklık ile varsayılanı 100 olan bir limitten oluşmaktadır. Bir özellik bayrağıyla açılmaktadır. Keycloak operatörü bu API'yi istemci özel kaynak tanımları için kullanmaktadır.

Sorgulama dili çok önemlidir: Keycloak, SCIM filtre sözdiziminin bir alt kümesini seçmiş ile kendi alan diline özgü sözdizimini icat etmemiştir.

```
GET /admin/api/{realm}/clients/v2?q=clientId eq "my-app" and enabled eq true&fields=clientId,displayName
```

Operatörler eşittir, eşit değildir, içerir, ile başlar, ile biter ile mevcuttur; bunlara ve, veya, değil ile parantez eklenmektedir. Büyüktür ile küçüktür operatörleri desteklenmemektedir; bilinçli bir kısıtlamadır. Alanlar parametresiyle izdüşüm yapılmaktadır. Bilinmeyen bir alan 400 döndürmektedir; SCIM'in sessizce yok say davranışının aksinedir ile daha iyi bir karardır. Dokümanda sıralama ile imleç tabanlı sayfalamaya dair açıklama yoktur.

### 1.4 Yönetim API'sinin kendi kimlik doğrulaması, Keycloak'ın merkezîlik problemi

Sunucu geliştirme dokümanındaki örnek şöyledir.

```bash
curl -d "client_id=admin-cli" -d "username=admin" -d "password=password" \
     -d "grant_type=password" \
     http://localhost:8080/realms/master/protocol/openid-connect/token
```

Varsayılan yönetim komut satırı istemcisi doğrudan erişim yetkisiyle çalışmaktadır. Token varsayılan olarak bir dakika yaşamaktadır. Servis hesabı alternatifi ana alanda bir istemci, bir yönetici alan rolü ile istemci kimlik bilgileri akışıdır. Kritik nokta şudur: erişim token'ı, hangi alan yönetiliyor olursa olsun ana alandan gelmek zorundadır.

Bu son madde Keycloak'ın merkezî zayıflığıdır: ana alan bir tek arıza noktası ile tek ele geçirme noktasıdır. Alan başına kiracı modelinde kiracı yöneticisini yönetmek için ya ana alanda hesap açılacaktır, ki kiracılar arası bir risktir, ya da alan yönetimi istemci rollerine düşülecektir.

### 1.5 Okta yönetim API'si, hız sınırı mimarisi

Okta'nın modeli üç bağımsız katmandan oluşmaktadır ile bu ayrım Argus için doğrudan kopyalanabilirdir.

Birincisi kova tabanlı zaman penceresi limitleridir. Bir hız sınırlama kovası, bir kotayı paylaşan bir veya daha fazla uç nokta kümesidir. Kova eşleşmesi HTTP yöntemiyle en uzun önek üzerinden yapılmakta; joker karakterli kovalar tam eşleşme yoksa devreye girmektedir. Başlıklar limit, kalan ile sıfırlama zamanını taşımakta, sonuncusu UTC epoch saniyesindedir.

İkincisi eşzamanlılık limitidir ile zaman penceresinden tamamen ayrıdır. Okta'nın ifadesiyle eşzamanlılık limitleri kuruluşunuzun aynı anda kaç isteği işleyebileceğini kontrol etmektedir; zaman içinde değil, saniye ya da dakika başına değil. İş gücü ile müşteri kimliği kuruluşlarında 75 eşzamanlı işlem, ücretsiz tümleştirici planında 35 işlem izinlidir. Microsoft Office 365 trafiği ayrı sayılmakta ile aynı varsayılanlar geçerlidir. Aşımda 429 ile bir sistem günlüğü olayı üretilmektedir. Eşzamanlılık ihlalinde limit ile kalan başlıkları sıfır dönmekte ile sıfırlama başlığı yalnızca tahmini bir değer taşımaktadır.

Üçüncüsü kullanıcı ile uç nokta bazlı korumadır. Yönetim konsolu ile son kullanıcı panosunda kullanıcı başına uç nokta başına 10 saniyede 40 istek izinlidir; bir kullanıcının diğerlerini boğmasını engellemektedir. Kimlik motorunda kullanıcı başına beş saniyede 20 istek ile durum belirteci başına beş saniyede 10 istek izinlidir. Kimlik doğrulama ile token uç noktalarında kullanıcı başına saniyede dört istek izinlidir.

Dördüncüsü bir ürün özelliği olarak gözlemlenebilirliktir, yani hız sınırı panosudur. Kova başına mevcut limit yüzdesi, 24 saatlik ile son bir saatlik ortalama kullanım ile etki süresi gösterilmektedir. En çok tüketenler bölümü IP adresi, API belirteci ile OAuth uygulaması kırılımıyla ilk on tüketiciyi listelemektedir. Dört sistem günlüğü olay tipi bulunmaktadır: hız sınırı ihlali, eşzamanlılık limiti ihlali, ani artış ile uyarı. Yapılandırılabilir bir yüzde eşiğinde e-posta uyarısı gönderilmektedir; yalnızca eşiğe ilk ulaşımda ile kuruluş kapsamlı kova kullanımına göre, belirteç ya da uygulama bazında değil.

### 1.6 Auth0 yönetim API'si

Token ömrü varsayılan 86.400 saniye, yani 24 saattir.

Kritik güvenlik notu Auth0'ın kendi ifadesidir: verildikten sonra bir erişim token'ı iptal edilememektedir. Yani 24 saatlik, iptal edilemez ile tam yetkili bir yönetici token'ı söz konusudur. Bu kötü bir tasarımdır.

İzleyici kitle yönetim API'sinin kendisidir. Kapsam modeli uç nokta başınadır; her uç nokta belirli bir kapsam kümesi gerektirmektedir. Hız sınırı bir jeton kovasıdır: kova boyutu ani artış limiti, doldurma hızı ise sürdürülebilir limittir. Ücretsiz ile deneme kiracılarında saniyede iki istek ile 10 ani artış izinlidir. Kurumsal genel performans ani artışında varsayılan saniyede 100 istek, ek modülle 200 ile 400 istektir. Başlıklar limit, kalan ile sıfırlama değerlerini taşımaktadır.

### 1.7 Microsoft Graph, kısıtlama

429 yanıtı bir yeniden dene başlığı saniye cinsinden taşımakta ile bu değer otoriterdir; doküman 14 Ocak 2025 tarihli ile 6 Ağustos 2025 güncellemelidir.

Limitler çok boyutludur: tüm kiracılarda uygulama başına, tüm uygulamalarda kiracı başına, kiracı başına uygulama başına ile istek tipine göre.

30 Eylül 2025'ten itibaren kiracı başına uygulama ya da kullanıcı limiti, toplam kiracı limitinin yarısına düşürülmüştür; tek bir uygulamanın ya da kullanıcının kiracı kotasını tüketmesini engellemek içindir. Bu, gürültülü komşu probleminin sonradan yamalanmasıdır.

Bir kaynak birimi başlığıyla istek başına maliyet açıklanmaktadır; sabit bir istek eşittir bir birim kuralı yoktur.

Yığın uç noktası, 21 Şubat 2025 dokümanına göre şöyledir. Yığın başına en fazla 20 istek gönderilebilmektedir. Bağımlılık alanıyla sıralı bağımlılık kurulmakta ile bağımlılık başarısız olursa 424 başarısız bağımlılık dönmektedir. Microsoft'un kendi tavsiyesi yığının ya tamamen sıralı ya tamamen paralel olması, karışık olmamasıdır. Dış yanıt 200 dönmektedir, zarf ayrıştırılabiliyorsa; her alt istek kendi durumunu taşımaktadır. Yığın kısıtlamayı atlamamaktadır: yığındaki istekler geçerli kısıtlama limitlerine karşı bireysel değerlendirilmekte ile herhangi biri limiti aşarsa 429 ile başarısız olmaktadır. Geliştirme kiti yığın içindeki 429'ları otomatik yeniden denememekte ile çağıran, başarısız alt isteklerin en büyük yeniden dene değerini kullanarak elle yeniden denemelidir. Gerçek toplu veri çıkarımı için Microsoft REST'ten tamamen vazgeçirmekte ile ayrı bir veri bağlantısı ürününe yönlendirmektedir, ki kısıtlama limitlerine tabi olmadığı belirtilmektedir. Bu, yığın uç noktasının toplu iş için yetersizliğinin örtük itirafıdır.

### 1.8 OpenAPI: üretilen mi elle yazılan mı

| Ürün | Durum | Kaynak |
|---|---|---|
| Okta | Üretilmektedir; yönetim API'sinden doğrudan üretilmiş bir anlık görüntü olduğu belirtilmektedir. Depo topluluk katkısı kabul etmemektedir. Tüm yönetim geliştirme kitleri bu şartnameden derlenmektedir. Eski elle yazılmış şartnameler bir arşiv dalındadır | okta/okta-management-openapi-spec |
| Keycloak birinci sürüm | Üretilmektedir ancak kalitesizdir; bakımcının kendi ifadesiyle eksiktir ile genellikle istemci üretmeye yetmemektedir | 37655 numaralı tartışma |
| Keycloak ikinci sürüm | Güvenilir istemci üretimini mümkün kılan doğru bir şartname sunulmaktadır; yönetim arayüzü üzerinde ayrı bir OpenAPI uç noktası bulunmakta ile komut satırı araçları ve üreticiler bağlandıkları sunucunun sürümüne göre komutlarını uyarlayabilmektedir | 26.7.0 sürüm notları |
| Auth0 ile Microsoft Graph | Doğrulanamamıştır; arama bütçesi tükenmiştir | — |

Argus için ders şudur: Okta'nın modeli doğrudur; şartname koddan üretilmeli, elle bakımı yapılmamalı ile geliştirme kitleri zorunlu olarak şartnameden üretilmelidir. Keycloak'ın ikinci sürümündeki çalışma zamanı OpenAPI uç noktası ek bir iyi fikirdir: komut satırı sürüm uyumsuzluğu problemini ortadan kaldırmaktadır.

---

## 2. Devredilmiş yönetim, en zor kısım

### 2.1 Keycloak alan yönetimi istemci rolleri

Her alanda alan yönetimi adında yerleşik bir istemci bulunmakta ile istemci seviyesindeki rolleri alan yönetim izinlerini tanımlamaktadır. Bilinen roller alan yöneticisi, ki bileşiktir, kullanıcıları yönet, kullanıcıları görüntüle, kullanıcı sorgula, grup sorgula, istemcileri yönet, istemcileri görüntüle, istemci sorgula, alanı yönet, alanı görüntüle, kimlik sağlayıcıları yönet, kimlik sağlayıcıları görüntüle, olayları yönet, olayları görüntüle, yetkilendirmeyi yönet, yetkilendirmeyi görüntüle, kimliğe bürünme ile istemci oluşturmadır.

Bu liste kısmen doğrulanmıştır: tamamı tek bir birincil kaynaktan çekilememiş, ilgili yönetim kılavuzu bölümü çekim sırasında kesilmiştir. Rol isimleri Keycloak ekosisteminde yaygın ile tutarlıdır ancak resmî tablo doğrulanmamıştır.

Granülerlik sınırlarının somut örnekleri şunlardır. Kullanıcı sorgulama rolü tek başına verildiğinde kullanıcı listesi çağrısı 200 dönmekte ancak liste boş olmaktadır. Bu, yalnızca konsolda kullanıcılar bölümünü göstermek için tasarlanmıştır, veri erişimi için değil. Bu ayrım bir güvenlik açığına dönüşmüştür. Ayrıcalık yükseltme koruması tarafında dokümantasyon, yöneticilerin yalnızca kendilerinde zaten bulunan rolleri devredebileceği ilkesini beyan etmektedir; yani kullanıcıları yönet yetkisi olan bir yönetici yalnızca kendisinde olan yönetici rollerini atayabilmektedir.

### 2.2 İnce taneli yönetici izinlerinin ikinci sürümü: bu grubun yöneticisi yapılabilmektedir

Sorunun cevabı evettir, Keycloak 26.2'den beri. Mayıs 2025 duyurusuna göre şunlar geçerlidir.

Keycloak'ın kendi ifadesiyle bu, devredilmiş yönetimi getirme yolunda büyük bir adımdır. Kaynak tipleri kullanıcılar, istemciler, gruplar ile rollerdir; organizasyonlar sonradan gelmiştir. Kapsamlar üyeleri görüntüle, üyeleri yönet, rolleri eşle ile kimliğe bürünmedir; her kapsam açıktır ile gizli bağımlılık yoktur. İki granülerlik seviyesi vardır: tekil kaynak, yani belirli bir kullanıcı veya istemci kümesi; ya da tip bazında tümü, örneğin tüm gruplar. Yönetim konsolunda tek bir izinler bölümü bulunmakta ile tüm ince taneli izinler görüntülenip denetlenebilmektedir. Alan başına bağımsız etkinleştirilebilmekte ile kademeli benimseme mümkün olmaktadır. Birinci sürümden otomatik göç yoktur.

Organizasyonlar için ince taneli izinler, 7 Mayıs 2026, Keycloak 26.7.0 ile gelmiştir. Yalnızca iki kapsam vardır: yönet, yani tam kontrol, ile görüntüle, yani salt okuma. Kaynak gizleme özelliği şöyledir: bir organizasyonda yönetme ile görüntüleme, başka birinde yalnızca görüntüleme yetkisi verilen bir yönetici her iki organizasyonu görmekte ancak yalnızca birincisini güncelleyebilmektedir; diğer tüm organizasyonlar tamamen gizlenmektedir, hem yönetim konsolunda hem REST API'sinde. İlk sürümde alt kaynak izinleri yoktur; bir organizasyonun üyelerini, gruplarını ya da kimlik sağlayıcılarını ayrı ayrı kontrol etmek mümkün değildir.

### 2.3 Okta özel yönetici rolleri ile kaynak kümeleri

Kaynak kümesi bir kaynak koleksiyonudur ile yalnızca özel yönetici rolleri içindir.

Sert limitleri şunlardır: en fazla 10.000 kaynak kümesi, küme başına en fazla 1.000 kaynak ile aynı rol ve kaynak kümesi kombinasyonuna en fazla 1.000 yönetici.

İzin alanları kullanıcı, grup, kimlik ve erişim yönetimi, uygulama, destek, profil kaynağı, iş akışı, yetkilendirme sunucusu, özelleştirme, dizinler, kimlik sağlayıcı, cihazlar, alanlar, ajanlar, kaynak koleksiyonları, görevler ayrılığı, etiketler, olay kancaları, satır içi kancalar, felaket kurtarma, politikalar ile bot korumasıdır.

Önemli bir boşluk vardır: Okta'nın izin dokümantasyonu ayrıcalık yükseltme riski taşıyan izinleri işaretlememektedir. Kullanıcıları yönet izni tüm profil ile kimlik bilgisi bilgisini görüntüleme, oluşturma, düzenleme ve silme yetkisi vermektedir; yani parola sıfırlama yoluyla hesap ele geçirmeye izin vermektedir. API belirteçlerini yönet izni de benzerdir. Doküman bu tuzağa dair hiçbir uyarı içermemektedir.

Kısmi bir koruma mevcuttur: iş akışı yöneticisi rolüne sahip bir yönetici bu rolü başkasına atayamamakta, yalnızca süper yönetici atayabilmektedir.

### 2.4 Entra kimlik: yönetim birimleri, ayrıcalıklı kimlik yönetimi ile korunan eylemler

Kısıtlı yönetim birimlerinde yalnızca o birime atanmış yöneticiler içindeki kullanıcı nesnelerini değiştirebilmektedir; bu kısıt küresel yönetici dahil herkes için geçerlidir. Platform yöneticisi bile göremesin gereksiniminin ürünleşmiş hâlidir.

Ciddi kısıtları vardır: bu birimlere yalnızca kullanıcılar, cihazlar ile güvenlik grupları konabilmektedir; diğer grup tipleri konamamaktadır. Ayrıcalıklı kimlik yönetimi bu birimlerdeki grupları desteklememektedir; hak yönetimi de desteklememektedir. Yani en güçlü izolasyon mekanizması en güçlü yönetişim mekanizmasıyla birlikte çalışmamaktadır.

Korunan eylemler, 19 Şubat 2026 güncellemesiyle, Argus için en kopyalanabilir fikirdir.

Belirli izinlere koşullu erişim politikası iliştirilmekte ile zorlama girişte ya da rol aktivasyonunda değil eylemin yapıldığı anda gerçekleşmektedir; kullanıcılara yalnızca gerektiğinde istem gösterilmektedir. Korunabilir izin kategorileri koşullu erişim politikası yönetimi, kiracılar arası erişim ayarları, bazı dizin nesnelerinin kalıcı silinmesi, adlandırılmış konumlar ile korunan eylem yönetiminin kendisidir. Mekanizma koşullu erişim kimlik doğrulama bağlamıdır; servis içindeki ince taneli kaynaklar için politika uygulanmasını sağlamaktadır.

Kritik uygulama sınırı Microsoft'un kendi listesidir: Entra yönetim merkezi, Graph PowerShell modülü ile Graph gezgini yükseltilmiş kimlik doğrulamayı desteklemektedir; Azure PowerShell başarısız olmaktadır. Ayrıca yeni kullanım koşulları ya da özel kontrol oluşturmak da başarısız olmaktadır, çünkü bunlar koşullu erişime kaydolmakta ile ilgili korunan eylemlere takılmaktadır; çözüm olarak politikanın geçici kaldırılması önerilmektedir.

Microsoft'un kendi uyarısı şudur: korunan eylemler kimliğe ya da grup üyeliğine dayalı erişim engellemek için kullanılmamalıdır; belirli izinlere kimin erişimi olduğu bir yetkilendirme kararıdır ile rol ataması tarafından kontrol edilmelidir. Yani korunan eylemler yetkilendirme değildir; ikisi ayrı katmandır.

Ayrıcalıklı kimlik yönetimiyle ilişkisi şudur: o, rol aktivasyonunda zorlamakta ile daha kapsamlıdır; korunan eylemler ise eylem anında zorlamakta ile rolden bağımsızdır. İkisi birlikte daha güçlü kapsama için kullanılabilmektedir.

Acil erişim hesabı kilitlenmeye karşı politikadan hariç tutulmalıdır. Birinci kademe lisans gerekmektedir.

### 2.5 Ayrıcalık yükseltme tuzağı: problemin adı ile gerçek güvenlik açıkları

Formal adı güvenlik problemidir. Harrison, Ruzzo ile Ullman'ın 1976 tarihli işletim sistemlerinde koruma makalesinde tanımlanmıştır.

Formal ifadesi şudur: bir koruma durumundan hareketle güvenlik sorusu, herhangi bir öznenin herhangi bir nesne üzerinde belirli bir hakkı elde edip edemeyeceğini sormaktadır. Sonuçları şunlardır.

Genel hâlde güvenlik karar verilemezdir; koruma sistemi keyfi bir Turing makinesini simüle edebilmekte ile bir hakkın sızması makinenin nihai duruma girmesine karşılık gelmektedir. Kısıtlı hâllerde oluşturma işlemleri olmadan problem PSPACE tam olmaktadır; silme işlemleri olmadan hâlâ karar verilemezdir; tek işlemli komutlarda ise karar verilebilirdir.

Argus için doğrudan sonuç şudur: bu izin setiyle bir yönetici kendini yükseltebilir mi sorusuna genel bir statik analizle cevap verilememektedir. Bu matematiksel bir gerçektir, bir mühendislik eksikliği değildir. Tek uygulanabilir strateji yükseltme yollarını çalışma zamanında bir değişmez olarak kapatmaktır.

Bunun gerçekte ne kadar acı verdiği Keycloak'ın ince taneli izin güvenlik açığı serisidir.

| Tanımlayıcı | Ne olmuştur | Sürüm | Tarih |
|---|---|---|---|
| CVE-2025-7784 | İkinci sürüm ince taneli izinler açıkken kullanıcıları yönet yetkili bir yönetici, rol eşleme işlemlerinde eksik ayrıcalık sınırı kontrolü nedeniyle kendi hesabına alan yöneticisi rolünü atayabilmektedir | 26.2.0 ile 26.2.5 etkilenmiştir; 26.2.6 ile 26.3.0 düzeltmiştir | 2025 |
| CVE-2026-9099 | Alt grup ekleme uç noktasında yetkilendirme kontrolü yoktur; düşük yetkili bir grup yöneticisi, alan yöneticisi rolüne sahip yüksek yetkili bir grubu kendi grubunun altına taşımakta ile hiyerarşik izin kalıtımı sayesinde o grubun üyelerine parola sıfırlama yetkisi kazanmaktadır; sonuç tam alan devralmadır. Zayıflık sınıfı kullanıcı kontrollü anahtarla yetkilendirme atlatması, CVSS 7,7 yüksektir | 26.6.4 öncesi; 26.6.4 düzeltmiştir | 26 Haziran 2026 |
| CVE-2026-3121 | Alan seviyesinde yönetici izinleri açıkken istemcileri yönet yetkili bir yönetici roller ile kullanıcılar üzerinde yetkisiz kontrol kazanmaktadır. Keycloak ekibinden bir geliştirici tarafından 2 Mart 2026'da bildirilmiştir | 26.4.11, 26.5.6 ile 26.6.0 etiketlidir | 2026 |
| CVE-2026-9795 | Hatalı kapsam eşleme zorlaması yoluyla ayrıcalık yükseltmesidir | — | Haziran 2026 |
| CVE-2026-9796 | İstemcileri yönet rollerini etkileyen bir kontrol ile kullanım arası yarış koşuludur | — | Haziran 2026 |
| CVE-2024-3656 | Korumasız yönetim REST uç noktalarıdır; alandaki düz kullanıcılar yönetimsel fonksiyonları kullanabilmektedir. Zayıflık sınıfları hatalı ayrıcalık yönetimi ile hatalı erişim kontrolüdür, orta şiddettedir | 24.0.5 öncesi | 11 Haziran 2024 |

Ayrıca tarihsel bir düzeltme vardır: sınırlı alan yönetim izinli geliştiriciler, istemci protokol eşleyicilerini ya da istemci kapsamlarını yöneterek yönetici rollerini token'a eşleyip yönetim API'sine erişebilmekteydi; artık engellenmiştir.

Bu tablo tek başına en güçlü bulgudur: Keycloak devredilmiş yönetimi ikinci sürüm olarak sıfırdan tasarlamış ile yayımlandığı ilk 14 ayda en az beş ayrı ayrıcalık yükseltme açığı almıştır. Hepsi aynı sınıftandır: bir uç nokta izin kontrolünü atlamakta ya da izin sınırını kendi üzerine uygulamamaktadır.

### 2.6 Diğer ürünlerde aynı sınıf hatalar

authentik'in CVE-2024-37905 açığında yetersiz izin kontrolü nedeniyle herhangi bir kimliği doğrulanmış kullanıcı bir API belirteci yaratıp belirtecin ait olduğu kullanıcı kimliğini değiştirerek süper kullanıcı olabilmekteydi. Düzeltme sürümleri 2024.6.0, 2024.4.3 ile 2024.2.4'tür. Geçici çözüm olarak ters vekil seviyesinde belirteç uç noktalarını bloklamak önerilmiştir. Ders şudur: kimlik bilgisi ile belirteç nesnelerinin sahip alanı asla değiştirilebilir olmamalıdır.

Zitadel'in CVE-2025-27507 açığı, CVSS 9,0, yönetim API'sindeki 12 HTTP uç noktasının kimlik ve erişim yöneticisi olmayan sıradan kimliği doğrulanmış kullanıcılara açık olmasıdır. Kök neden gRPC servis tanımlarındaki yanlış izin kapsamıdır; işleme farkı, izinlerin organizasyon kapsamlı yerine sistem kapsamlı olarak düzeltildiğini göstermektedir. Etkisi örnek dizin ayarlarını değiştirip tüm dizin girişlerini saldırganın sunucusuna yönlendirmek ile dizin sunucusu parolasının ifşasıdır. Dokuz ayrı yama sürümüyle düzeltilmiştir.

Zitadel'in CVE-2025-53895 açığı oturum yönetimi API'sindeki eksik izin kontrolüdür: hedef oturum kimliğini bilen herhangi bir kimliği doğrulanmış kullanıcı, oturum belirtecini sunmadan o oturumu güncelleyebilmekteydi. 2.53.0'da oturum belirteci zorunluluğu gevşetilince ortaya çıkmıştır; öncesi etkilenmemiştir.

Zitadel'in CVE-2026-27946 açığında ikinci sürüm kullanıcı API'sinde istek yükü manipüle edilerek kendi e-posta ya da telefonunu meydan okuma yanıtı tamamlamadan doğrulamak mümkündü.

GitLab'ın CVE-2026-35595 açığında paylaşılan bir alt proje üzerinde yazma yetkisi olan, yani yönetici olmayan bir kullanıcı, bir üst proje kimliği sıfır gönderek projeyi üstünden koparabilmekteydi; yönetici gereksinimi atlanmaktaydı. Keycloak'ın yeniden ebeveynleme açığıyla aynı sınıftandır: hiyerarşi mutasyonu hem kaynak hem hedef üzerinde izin gerektirmemektedir.

GitLab'ın CVE-2026-6267 açığı, CVSS 8,5, 29 Temmuz 2026: yüksek ayrıcalık seviyesine ya da iç operasyonlara yönelik bazı istekler yalnızca geliştirici rolündeki bir kullanıcı tarafından başlatıldığında bile işlenip yanıtlanabilmekteydi.

Zitadel ile GitLab örneklerinin ortak dersi şudur: izin kontrolü uç nokta başına bir ek açıklama olarak yazıldığında, birinin yanlış yazılması sessizce 12 uç noktayı açmaktadır. Bu kaçınılmazdır, çünkü insan yazmaktadır. Çözüm ek açıklamayı iyileştirmek değil, her uç noktanın gerektirdiği izni testle doğrulamaktır.

### 2.7 WorkOS modeli, devretmenin ikinci ekseni

Buraya kadarki bölüm devretmeyi tek bir eksende ele almaktadır: kimlik sağlayıcıyı işleten kuruluşun kendi içinde yetkiyi bölmesi. Keycloak'ın alan yönetimi rolleri, Okta'nın özel yönetici rolleri ile Entra'nın yönetim birimleri bu eksendedir. İkinci bir eksen vardır ile incelenen açık kaynak ürünlerin hiçbirinde bulunmamaktadır: kiracının kendi bilişim sorumlusuna devretme.

WorkOS'un yönetim portalı bu ikinci ekseni ürünleştirmiştir. Dokümanına göre portal, bilişim sorumlusunun alan adı doğrulaması yapması, çoklu oturum ile dizin eşzamanlama bağlantılarını yapılandırması için hazır bir arayüz sunmaktadır; her kimlik sağlayıcı için ayrı yönlendirmeli doküman bulunmakta ile kuruluşlar satıcının mühendislik ekibinden destek almadan devreye alınabilmektedir. Yayımlanmış bir müşteri örneğinde 100'den fazla çoklu oturum bağlantısının kurulumunda 300 saatten fazla tasarruf bildirilmektedir. Erişim 13 Eylül 2026.

Argus için önemi bir ürün özelliği olmasının ötesindedir. Kiracının bilişim sorumlusu, Argus'un yönetim API'sinin bir tüketicisidir ancak ne platform yöneticisidir ne de kiracı yöneticisinin tamamıdır; üçüncü bir aktördür ile yetkisi tek bir işe, yani kendi kuruluşunun kurumsal bağlantısını kurmaya indirgenmiştir. Bu aktör 19. maddedeki iki yüzeyli modelde yoktur. Yüzey ayrımı yapılmazsa iki sonuçtan biri çıkmaktadır: ya bilişim sorumlusuna kiracı yöneticisi yetkisi verilmekte, ki aşırı yetkidir, ya da bağlantı kurulumu satıcının destek ekibine düşmektedir, ki WorkOS'un ölçtüğü 300 saatlik maliyettir.

İkinci bir bağlantı §27 §2.2'yedir. Kiracının kendi kimlik sağlayıcısını bağlaması, Argus'un Okta ile Entra tuhaflıklarına dayanıklı olmasını gerektirmektedir; o tuhaflıklar orada listelenmiştir. Kendi kendine hizmet yüzeyi, o listedeki her farkı bir destek biletine değil bir hata mesajına çevirmek zorundadır.

---

## 3. Yönetim API'si güvenliği

### 3.1 Güvenlik danışmanlığı yoğunluğu, sınıf dağılımı

Keycloak'ın danışmanlık sayfasından yalnızca ilk sayfa, yani 10 kayıt, hepsi 2026 tarihlidir.

| Tanımlayıcı | Başlık | Şiddet | Tarih |
|---|---|---|---|
| GHSA-95cx-vmr5-3cmr | Varsayılan dinamik istemci kaydı politikası, kullanıcı özelliği eşleyicileri yoluyla rol sahteciliğine izin vermektedir | Yüksek | 6 Ağustos 2026 |
| GHSA-95rm-h7g9-rhcf | Protokol eşleyici tip değiştirme yoluyla politika atlatması ayrıcalık yükseltmeye izin vermektedir | Yüksek | 6 Ağustos 2026 |
| GHSA-2888-g6qc-w4mj | Yol eşleyicide normalize edilmemiş adres eşleştirmesiyle yetkilendirme atlatmasıdır | Yüksek | 6 Ağustos 2026 |
| GHSA-f8m4-v488-rmrm | SAML aracı metadata içe aktarımı yanıt imza doğrulamasını devre dışı bırakmaktadır | Yüksek | 6 Ağustos 2026 |
| GHSA-fgq2-hxm5-8xg2 | SAML kimlik sağlayıcı başlatmalı aracı girişi yalnızca bağlama kısıtını atlamaktadır | Yüksek | 6 Ağustos 2026 |
| GHSA-hmr6-pxx9-552p | Dizin girdi adıyla kullanıcı arama, yapılandırılmış kullanıcı dizin sınırını atlamaktadır | Orta | 6 Ağustos 2026 |
| GHSA-3692-rrj9-24qw | İstek kontrollü hata metniyle sınırsız metrik kardinalitesidir | Orta | 6 Ağustos 2026 |
| GHSA-j97h-3f8r-mrjr | JWT algoritma karışıklığıyla kimlik doğrulama atlatmasıdır | Yüksek | 26 Haziran 2026 |
| GHSA-f5p5-6xmx-p252 | Hatalı adres karşılaştırmasıyla yetkilendirme atlatmasıdır | Yüksek | 26 Haziran 2026 |
| GHSA-w3p3-7cjg-vgfw | Yönetilen erişim izin bileti atlatmasıyla yetkisiz erişimdir | Orta | 26 Haziran 2026 |

Toplam danışmanlık sayısı doğrulanamamıştır; birinci sayfadan fazlası çekilememiştir.

Sınıf dağılımı gözlemi şudur: 10 kayıttan yedisi bir atlatmadır, yani yetkilendirme atlatması, imza doğrulama atlatması, kısıt atlatması, sınır atlatması ile bilet atlatması. Sıfır bellek güvenliği, sıfır enjeksiyon vardır. Kimlik sağlayıcılardaki gerçek zafiyet sınıfı bellek güvenliği değil yetkilendirme mantığıdır. Rust'ın bellek güvenliği bu kategoriye sıfır katkı sağlamaktadır.

Özellikle iki kayıt, yani normalize edilmemiş adres eşleştirmesi ile hatalı adres karşılaştırması, aynı sınıftandır: yola dayalı yetkilendirme yapan her sistemin klasik tuzağıdır.

### 3.2 Yatay ayrıcalık ihlali, CVE-2026-17059, en öğretici vaka

Escape Research'ten Enzo Mongin tarafından bulunmuştur; Red Hat 24 Temmuz 2026'da yayımlamış ile Keycloak 28 Temmuz 2026'da 26.7.0 ile düzeltmiştir.

Mekanizma şudur: yalnızca kullanıcı sorgulama ile alanı görüntüleme izinli kısıtlı bir yönetici söz konusudur. Kullanıcılar uç noktası bu belirtece boş liste dönmektedir, ki doğru davranıştır. Ancak rol üyeleri uç noktası aynı belirtece tam kullanıcı kayıtlarını vermektedir: kullanıcı adı, e-posta, ad, soyad, hesap durumu ile e-posta doğrulama durumu. Kök neden şudur: rol üyeleri uç noktası yalnızca geniş rol görüntüleme ile kullanıcı sorgulama izinlerini zorlamakta ile aynı kullanıcı başına yetkilendirme filtresini uygulamamaktadır.

Bu, yan kapı uç noktası karşı deseninin ders kitabı örneğidir. Ana listeleme uç noktası doğru süzmekte; kullanıcı nesnesi döndüren ikincil bir uç nokta aynı filtreyi uygulamayı unutmaktadır. Uç nokta başına yetkilendirme yazıldığı sürece bu hata kaçınılmazdır, çünkü uç nokta çarpı kaynak tipi kombinasyonu insan denetimini aşmaktadır. Filtre veri erişim katmanında olmalıdır, işleyicide değil.

### 3.3 Yönetim konsolu bir tek sayfa uygulamasıdır, XSS ile siteler arası istek sahteciliği yüzeyi

CVE-2024-4028'de yönetim konsolundan kaynak ya da izin yaratırken izin alanına kötü niyetli bir yük konarak depolanmış XSS elde edilmekteydi; 26.2.0 öncesi sürümlerde geçerlidir.

GHSA-755v-r4x4-qf7m'de grup adına konan bir yük gruplar açılır listesinde depolanmış XSS üretmekteydi.

Ana bilgisayar başlığı yansımasında Keycloak yönetim konsolu, bu başlığı web kaynak konumlarını belirlemek için kabul etmekteydi; kötü niyetli bir sunucu üzerinden kimliği doğrulanmış kullanıcıya karşı yansımalı XSS mümkündü.

Siteler arası istek sahteciliği çerezi oturuma bağlı değildi: Keycloak'ta bu koruma için kullanılan çerez her oturuma özgü değildi ile saldırgan kimliği doğrulanmış kullanıcı oturumuna erişebilmekteydi.

Kritik gözlem şudur: bu XSS açıklarının çoğu ayrıcalıklı bir saldırgan gerektirmektedir; yani düşük yetkili bir yönetici, yüksek yetkili bir yöneticinin tarayıcısında kod çalıştırmaktadır. Devredilmiş yönetimle yönetim tek sayfa uygulaması birleşince XSS, ayrıcalık yükseltmeye giden en kısa yoldur. Kiracı yöneticisinin girdiği bir grup adı platform yöneticisinin konsolunda işleniyorsa kiracı izolasyonu XSS ile çökmektedir.

### 3.4 Yönetici oturumları için ayrı politika, Okta'nın modeli

Okta'nın yönetici oturumlarını koruma yazısı 2023 ihlali sonrası inşa edilmiştir ile katman katman tarihlidir.

| Kontrol | Detay | Tarih |
|---|---|---|
| Otonom sistem numarası oturum bağlaması | Bir API ya da web isteği sırasında gözlemlenen numara, oturum kurulduğunda kaydedilenden farklıysa Okta yönetimsel oturumu otomatik iptal etmektedir. Yayından üç ay içinde dokuz binden fazla kuruluş benimsemiş ile Okta tüm iş gücü müşterileri için varsayılan açık yapmıştır | Konsolda varsayılan 23 Ekim 2023 |
| IP oturum bağlaması | Aynı mantık IP seviyesindedir. Yeni kuruluşlarda varsayılan açıktır | Erken erişim 7 Şubat 2024 ile 1 Mart 2024 |
| Yönetici oturum ömrü | Varsayılan 12 saat ömür ile 15 dakika boşta kalma | Genel kullanım 8 Ocak 2024 |
| Korunan eylemler | Yöneticiler konsolda kritik görevler yaptığında yeniden kimlik doğrulama istemi almaktadır | Erken erişim 7 Şubat 2024 |
| Çok faktörlü zorunluluğu | Tek faktörlü erişime izin veren kimlik doğrulama politikaları engellenmektedir | Erken erişim Mayıs 2024 |

Oturum ömrü yapılandırma sınırları şunlardır: ömür önerilen 12 saat, azami 24 saat ile asgari bir dakikadır. Boşta kalma önerilen 15 dakikadır, NIST kılavuzuna dayanmaktadır; azami iki saat ile asgari bir dakikadır. Kısıt ömrün boşta kalmadan büyük ya da eşit olmasıdır. Süre dolmadan önce bir uyarı penceresi gösterilmektedir: zaman aşımı 10 dakikadan uzunsa son beş dakikada, kısaysa son 30 saniyede.

Kapsam sınırı Okta'nın kendi ifadesidir: diğer Okta uygulamalarındaki yönetimsel oturumlar etkilenmemektedir, yani iş akışları, erişim ağ geçidi ile gelişmiş sunucu erişimi. Yani yönetici oturum politikası tüm yönetici yüzeylerini kapsamamaktadır. Argus için ders şudur: yönetici oturum politikası merkezî olmalıdır, konsola özel değil.

Auth0 ile karşılaştırma şudur: Auth0'ın yönetim API'si token'ı 24 saatlik ile iptal edilemezdir. Okta'nın yönetim konsolu oturumu 12 saat artı 15 dakika boşta kalma artı numara bağlaması artı korunan eylemlerdir. Aynı sorunun iki ucudur ile Auth0 tarafı belirgin şekilde zayıftır.

### 3.5 Kimliğe bürünme

Keycloak'ta kimliğe bürünme yönetim REST API'si üzerinden programatik olarak erişilebilirdir ile dönen erişim token'ı hedef kullanıcı için tam geçerli bir token'dır; aşağı akış API çağrılarında kullanıcının kendi aldığı token'dan ayırt edilememektedir. İkinci sürüm ince taneli izinler bunu açık bir kapsam hâline getirmiştir.

Denetim tarafında yönetim konsolundaki yönetici olayları bölümünde token değişimi filtresiyle hangi hesapların ne zaman bürünüldüğü izlenebilmektedir.

Bu bölümdeki en iyi uygulamaların, yani beş dakikalık token ömrü ile sır yöneticisi önerilerinin kaynağı blog yazılarıdır; birincil kaynak değildir ile doğrulanmamıştır.

---

## 4. Yapılandırma yönetimi ile GitOps

### 4.1 Keycloak alan içe ile dışa aktarımı, kod olarak yapılandırma için yetersizdir

Tam komut satırı dışa aktarımında tüm düğümler durdurulmalıdır: dışa aktarımın tutarlılığı, tüm düğümler durdurulmadıkça garanti edilmemektedir. Yani canlı kullanım için tasarlanmamıştır. Hariç tutulanlar kullanıcı ile yönetici olayları, kalıcılaştırılmış oturumlar, iş akışı durumu ile iptal edilmiş token'lardır.

Kısmi dışa aktarımda kullanıcılar hiç dışa aktarılamamaktadır. Hassas değerler, yani parolalar ile istemci sırları maskelenmektedir; dolayısıyla fark alınamamakta ile yeniden uygulanamamaktadır. Keycloak'ın kendi ifadesiyle yedekleme ya da sunucular arası veri transferi için uygun değildir. İstemci kapsamları ile kapsam eşlemeleri kısmi içe aktarım sırasında yok sayılmaktadır. Dokümantasyon yetersiz kabul edilmektedir.

Determinizm kabul edilmiş bir problemdir: dışa aktarım deterministik değildir. Dizi sıralaması çalıştırmalar arası değişmekte ile alan kimlikleri silme ve yeniden oluşturmada yeniden üretilmektedir; sonuç devasa sahte farklardır. Düzeltme Keycloak çekirdeğinde değil yapılandırma komut satırı aracının içinde yapılmıştır, yani sıralı diziler ile kimlik yerine koymayla. Topluluk bunu doğrudan Keycloak ekibine de taşımıştır.

### 4.2 Keycloak yapılandırma komut satırı aracı

adorsys/keycloak-config-cli deklaratif ile etkisiz kılınabilir bir YAML veya JSON'dan yönetim API'sine senkronizasyon aracıdır. Ham bir içe ve dışa aktarım sarmalayıcısı değildir: canlı alan durumuyla fark alıp artımlı değişiklik uygulamaktadır. Yeniden başlatma gerektirmemektedir.

Kapsamı istemciler, roller, gruplar, kimlik bilgileriyle birlikte kullanıcılar, kimlik doğrulama akışları ile yürütmeleri, kimlik sağlayıcılar ile eşleyicileri, istemci kapsamları, bileşenler, kullanıcı federasyonu, istemci politikaları, ince taneli izinlerin her iki sürümü, mesaj paketleri, organizasyonlar ile iş akışlarıdır.

Kısıtları şunlardır: ikinci sürüm ince taneli izinlerde yönetici izinleri istemci yetkilendirmesi sistem yönetimlidir ile içe aktarımda açıkça atlanmaktadır. Sürüme özgü tuzaklar elle müdahale gerektirmektedir.

Bakımı aktiftir. En son sürüm 22 Mayıs 2026 tarihli 6.5.1'dir; öncesinde 12 Mart 2026 tarihli 6.5.0, 28 Ocak 2026 tarihli 6.4.1 ile 21 Şubat 2025 tarihli 6.4.0 bulunmaktadır. Politikası mümkün olduğunca son dört Keycloak sürümünü desteklemektir. Gün seviyesindeki tarihler bir çekme özetinden gelmiştir, ham veriden değil; yaklaşık kabul edilmelidir.

### 4.3 Terraform sağlayıcıları

Keycloak tarafında mrparkers sağlayıcısı 9 Aralık 2024'te Keycloak projesi tarafından resmen devralınmıştır. Yeni bakımcılar Sebastian Schuster ile Thomas Darimont'tur. Lisans Apache 2.0'a geçmiştir. Göç bir durum değiştirme komutuyla yapılmaktadır. Devralma gerekçesi şudur: topluluk anketi bunu en yaygın alan yapılandırma aracı olarak göstermiştir.

Devralma sonrası aktiftir: Nisan 2025'teki 5.2.0'dan Temmuz 2026'daki 5.9.0'a gelmiştir; ikinci sürüm ince taneli izin kaynakları, alan kapsamlı içe aktarım ile 26.4 uyumu eklenmiştir.

Bilinen problemleri şunlardır. Kimlik doğrulama yürütmesi sıralaması, API sınırlaması nedeniyle açık bir bağımlılık bildirimi gerektirmektedir; deklaratif olmayan bir bağımlılığı deklaratif bir araca zorla giydirmedir. İstemci sırrı taşıyan öznitelikler, yapılandırmada belirtilmese bile Terraform durumunda önbeleklenmektedir.

Auth0'ın resmî sağlayıcısında kalıcı sahte kayma vardır: gerçek yapılandırma istenen duruma ulaşmış olsa bile sahte kaymalar tutarlı biçimde yüzeye çıkmaktadır. Değişiklikleri yok say direktifi bağlantı kimlik bilgileri için tam çalışmamaktadır; kimlik bilgisi sıfırlanma riski doğmaktadır. API kullanımdan kaldırmaları sağlayıcıyı kırmaktadır: etkin istemciler alanının kaldırılması, 13 Temmuz 2026 kullanım sonuyla, 1.29.0 öncesi sağlayıcıyı tamamen kırmıştır.

Okta'nın resmî sağlayıcısında sunucu tarafı, uygulamadan sonra alanları otomatik doldurmakta ya da düzeltmektedir; sonraki planlarda durum yapılandırmadan ayrışmaktadır. Kullanıcı grup üyeliklerinde sahte kayma vardır: öznitelikler gerçek bir değişiklik olmadan uygulamadan sonra bilinecek durumuna dönmektedir.

### 4.4 Kubernetes operatörleri

Keycloak operatörü şöyledir. Keycloak özel kaynak tanımı dağıtım ile altyapıyı yönetmekte, yani giriş, servis ile yönetici kimlik bilgisi sırrını, ancak veritabanını yönetmemektedir. Alan içe aktarma tanımı yalnızca oluşturmayı desteklemektedir: yeni alanların oluşturulmasını desteklemekte, bunları güncellememekte ya da silmemekte ile Keycloak üzerinde doğrudan yapılan değişiklikler kaynağa geri senkronize edilmemektedir. Yani kayma uzlaştırması yoktur. Bu boşluk için ayrı bir proje bulunmaktadır: kendi tanımıyla geçici bir çözüm olan alan operatörü, eski operatörden çatallanıp dağıtım mantığı çıkarılmış ile alan, istemci ve kullanıcı için tam oluştur oku güncelle sil ve kayma uzlaştırması eklemiştir. Yerel kaynak tanımı desteği gelene kadar ana operatörün yanında çalışacaktır. Küçük ölçeklidir ile tek kaynaktan doğrulanmıştır. 26.7.0 ile yön değişmiştir: operatör artık istemci kaynak tanımlarını ikinci sürüm istemci yönetim API'si üzerinden yönetmektedir; yani operatör birinci sürümün buyurgan API'sinden çıkıp ikinci sürümün deklaratif API'sine geçmektedir.

authentik'in taslakları ilk günden deklaratif tasarlanmış birinci taraf bir mekanizmadır. YAML tabanlıdır ile model ve durum alanları taşımaktadır; durum değerleri mevcut, oluşturulmuş, oluşturulmalı ile yok değerleridir. İki uygulama modu vardır: bağlanmış bir dosya, ki işçi yaklaşık 60 dakikada bir yeniden okumaktadır, ya da API veya arayüz üzerinden tek seferlik içe aktarım. Resmî bir Kubernetes operatörü yoktur; kaynak tanımı ile operatör fikri bir konuda açılmış ancak uygulanmamış görünmektedir ile resmî Kubernetes dağıtımı yalnızca bir Helm paketidir.

Zitadel API önceliklidir. Katmanlı yapılandırması öncelik sırasıyla Go yapı varsayılanları, paketlenmiş varsayılan YAML, özel yapılandırma YAML'ı, ortam değişkenleri ile komut satırı bayraklarıdır. İlk örnek önyüklemesi bir YAML bloğu ile bir kurulum komutuyla yapılmaktadır. Kiracı, organizasyon ile uygulama seviyesindeki sürekli yapılandırma API önceliklidir; resmî bir Terraform sağlayıcısı bulunmaktadır. Boşlukları şunlardır: yürütmeler için kaynak yoktur; sağlayıcı yapılandırmayı hevesle yüklemekte ile taze Helm dağıtımlarıyla önyükleme sıralama çakışması yaşanmaktadır.

### 4.5 Deklaratifle buyurganın karşılaştırması, kim pişman olmuştur

Keycloak bir ders kitabı vaka çalışmasıdır. Yalnızca topluluk şikâyeti değil bakımcının yazılı analizi vardır: 18 Eylül 2024 tarihli deklaratif yapılandırma API'si tartışması. Mevcut API'nin deklaratif kullanıma neden direndiğini kataloglamıştır: gönderi ile yerleştirme tutarsızlığı; oluştur ya da güncelle semantiğinin olmaması; çok istekli varlık yaratma, örneğin istemci artı roller için iki çağrı; ile isim yerine benzersiz tanımlayıcı tabanlı adresleme.

Önerdiği çözümler yerleştirme tabanlı oluştur ya da güncelle, isim tabanlı adresleme ile uzlaştırma döngüsünü önlemek için istenen durumla çalışma zamanı durumunun ayrılmasıdır. Açıkça ikinci sürüm yönetim API'sinin zemini olarak konumlandırılmıştır.

Sonuç şudur: Keycloak'ın buyurgan ile gelişigüzel evrilmiş yönetim API'si yıllarca üçüncü taraf araçların, yani yapılandırma komut satırı aracının, birden fazla Terraform sağlayıcısının ile birden fazla operatörün her birinin bağımsız olarak etkisiz kılınabilirlik, fark alma ile normalleştirmeyi çözmesine yol açmıştır. Çekirdek ekip şimdi ikinci sürümle deklaratif semantiği geriye dönük giydirmeye çalışmaktadır.

Karşı örnekler şunlardır: authentik birinci günden deklaratiftir, yani birinci taraf taslaklarıyla. Zitadel API öncelikli yaklaşımla resmî Terraform sağlayıcısını sancılı yol olarak seçmiştir; yalnızca önyükleme ile örnek seviyesinde YAML kullanmaktadır.

### 4.6 Kayma tespiti, ne bozulmaktadır, ortak arıza sınıfları

1. Deterministik olmayan serileştirme, Keycloak'ta: dizi sıralaması çalıştırmalar arası değişmekte ile normalleştirme çekirdekte değil istemci tarafındadır.
2. Sunucu tarafı varsayılanların kayma sanılması: Auth0 ile Okta sağlayıcılarında kalıcı sahte farklar bulunmaktadır.
3. Sırların durum ya da dışa aktarım içinde olması: Keycloak kısmi dışa aktarımı sırları maskelemekte ile fark alınamamaktadır; Terraform durumu sırları önbeleklemekte ile Auth0'da değişiklikleri yok say direktifi kimlik bilgilerini korumamaktadır.
4. Tek yönlü uzlaştırma: alan içe aktarma tanımı yalnızca oluşturmaktadır ile bant dışı değişiklikler sessizce hiç düzeltilmemektedir.
5. API'nin deklaratif ifade edemediği sıralama bağımlılıkları: kimlik doğrulama yürütmesi sıralaması buna örnektir.
6. Önyükleme yarışları: Zitadel sağlayıcısı taze bir Helm kurulumunda çakışmaktadır.

---

## 5. Yönetim API'siyle çok kiracılığın kesişimi

### 5.1 Auth0'ın kendi organizasyonum API'si, en önemli mimari bulgu

21 Nisan 2026 tarihli Auth0 blog yazısına göre Auth0, yönetim API'sini devredilmiş organizasyon yönetimi için kullanmanın çalışmadığını kabul edip ayrı bir API inşa etmiştir. Kendi gerekçesi şudur.

> *"The Management API is intended to configure Auth0 tenants globally and is not designed for frequent, granular calls. It can quickly become a bottleneck for routine operations like updating settings or inviting members."*

Geliştiricilerin, işleri büyüdükçe ile kiracıdaki organizasyon sayısı arttıkça hız sınırı duvarına çarptığı belirtilmektedir.

| Boyut | Yönetim API'si | Kendi organizasyonum API'si |
|---|---|---|
| Amaç | Küresel kiracı yapılandırmasıdır | Organizasyona özgü devredilmiş operasyonlardır; çok daha yüksek performans ile ölçeklenebilirlik sunmaktadır |
| İzleyici kitle | Genel yönetim adresidir | Ayrı bir organizasyon adresidir |
| Kapsamlar | Kiracı geneli okuma ile yazma kapsamlarıdır | Organizasyona özgü ayrıntı okuma ile güncelleme kapsamlarıdır |
| Kiracı bağlamı | Yolda ya da parametrede organizasyon kimliği taşınmaktadır | Kimliği doğrulanmış kullanıcının organizasyon üyeliğinden türetilmektedir |
| Sınır | Kiracı genelidir | Organizasyon sınırı içindedir |

Bu, Argus için tek başına en aksiyona dönüştürülebilir mimari derstir: platform yönetici API'siyle kiracı yönetici, yani kendin yap API'si ayrı yüzeyler olmalıdır; ayrı izleyici kitle, ayrı kapsam ad alanı ile ayrı hız sınırı bütçesi gerekmektedir. Tek bir yönetim API'sini hem platform hem kiracı yönetimi için kullanmak, Auth0'ın kendi ifadesiyle hız sınırı duvarına ile performans darboğazına çarpmaktadır.

### 5.2 Kiracı bağlamı kimden gelmektedir, güvenlik açısından

Değişmez kural, çapraz kaynak doğrulanmıştır: kiracı kimliği doğrulanmış bir token iddiasından türetilmelidir; başlıktan, sorgudan ya da gövdeden asla güvenilmemelidir. Yoldan, alt alan adından ya da başlıktan gelen bir kiracı bağlamı varsa token iddiasıyla eşleştiği doğrulanmalıdır.

Auth0'ın kendi organizasyonum API'si bunu en temiz şekilde yapmaktadır: organizasyon bağlamı kimliği doğrulanmış kullanıcının organizasyon üyeliğinden gelmekte ile istemci hiçbir yerde organizasyon kimliği göndermemektedir. Bu tasarım, güvensiz doğrudan nesne referansı sınıfını yapısal olarak ortadan kaldırmaktadır.

Bu bölümdeki genel en iyi uygulama literatürü çoğunlukla blog kaynaklıdır ile birincil bir şartname kaynağı yoktur. Ancak Auth0'ın somut tasarımı ile Zitadel'in organizasyon kapsamlıyla sistem kapsamlı karışıklığından doğan açığı bu kuralı ampirik olarak desteklemektedir.

### 5.3 Keycloak'ın iki modeli

| | Kiracı başına alan | Organizasyonlar, tek alan |
|---|---|---|
| İzolasyon | Serttir; ayrı yapılandırma, tema ile yönetici vardır | Yumuşaktır; alan paylaşılmaktadır |
| OIDC vereni | Her alanın kendi vereni vardır; her arka uç servisi belirli bir alanın keşif uç noktasına karşı yapılandırılmalıdır | Tek verendir |
| Yönetici token'ı | Ana alandan gelmelidir; merkezî bir risktir | Organizasyon kapsamlı ince taneli izinlerdir |
| Devredilmiş yönetim | Alan yönetimi rolleridir | Yönet ile görüntüle kapsamları artı kaynak gizlemedir |
| Operasyonel maliyet | Yüksektir | Düşüktür |

Keycloak'ın organizasyonları 26.7.0'da ince taneli izinlerle birleşince gerçek bir devredilmiş yönetim sağlamaktadır: organizasyon yöneticisi hesap konsolundan ya da organizasyon REST API'sini çağıran özel bir portaldan kendi organizasyonunu yönetmekte ile diğer organizasyonları görememekte veya etkileyememektedir.

Entra'nın kısıtlı yönetim birimi daha güçlü bir garanti sunmaktadır: küresel yönetici dahil hiç kimse birim içindeki nesneleri değiştirememektedir. Platform yöneticisi bile göremesin gereksiniminin ürünleşmiş hâlidir; ancak ayrıcalıklı kimlik yönetimiyle birlikte çalışmamaktadır.

---

## 6. Toplu ile yığın işlemler

### 6.1 SCIM toplu uç noktası: şartname vardır, kimse uygulamamaktadır

RFC 7644'ün 3.7 bölümü, 2015, şunları tanımlamaktadır. Toplu kimlik istemci üretimi geçici bir tanımlayıcıdır ile gönderi için zorunludur; henüz yaratılmamış kaynaklara aynı yük içinde referans vermeyi sağlamakta ile sunucu aynı kimliği gerçek kaynak kimliğine eşleyip geri döndürmelidir. Hatada durma alanı istemcinin belirlediği, kaç hata sonrası yığının durdurulacağıdır; yoksa hepsi işlenmekte ile tüm hatalar raporlanmaktadır. Azami işlem sayısı ile azami yük boyutu sunucu tarafından servis sağlayıcı yapılandırmasında ilan edilmektedir.

Gerçek dünya benimsemesi neredeyse sıfırdır.

| Ürün | Durum |
|---|---|
| Keycloak | Toplu destek kapalıdır; toplu uç noktası düzgün bir yanıt bile dönmemektedir. Açık bir özellik talebi vardır ancak kilometre taşı yoktur |
| Microsoft Entra | SCIM istemcisi olarak toplu uç noktasını hiç kullanmamakta, kullanıcı başına ayrı çağrı yapmaktadır. Tek istisna galeri uygulamalarında 20 grup üyelik değişikliğini tek bir yamada toplamaktır, ki RFC mekanizması değildir |
| Okta | Gelen sağlamada SCIM toplu işlemini desteklememektedir; tek istekte çoklu kaynak değişikliği için toplu operasyonların şu anda sağlama servisi tarafından kullanılmadığı belirtilmektedir |
| PingFederate | Toplu destek kapalıdır ile limitler sıfırdır; doğrulanamamıştır, birincil doküman çekimi başarısız olmuştur |

Sonuç şudur: SCIM toplu uç noktası standardın en az uygulanan büyük özelliğidir. İncelenen her satıcı bunun yerine şartname dışı kendi eşzamansız iş API'sini inşa etmiştir. Argus'un yalnızca ilgili RFC bölümüne yatırım yapması, gerçek dünyada karşılığı olmayan bir özelliği kopyalamak olur.

### 6.2 Auth0 işleri, çalışan eşzamansız model

Kullanıcı içe aktarma işi uç noktası şöyle çalışmaktadır: 202 ile birlikte kimlik, bekliyor durumu, tip ile oluşturma zamanı dönmekte; istemci iş durumunu yoklamaktadır. Dosya boyutu 500 ile 512 kilobayt arasındadır; Auth0'ın hata metni azami izin verilen içerik uzunluğunun aşıldığını söylemektedir. Metadata küçük tutulursa yaklaşık bin kullanıcı sığmaktadır. Eşzamanlılık kiracı başına iki iştir; üçüncüsü 429 ile iki aktif içe aktarma işi bulunduğu mesajını almaktadır. Bu limitin üstündeki kurumsal müşterilere Auth0 dokümante bir API çözümü değil teknik hesap yöneticisine başvurmayı önermektedir. Yaşam döngüsü bekliyordan tamamlandı ya da başarısıza gitmektedir; iki saatte zaman aşımına uğramakta ile tüm iş verisi, hata detayı dahil, 24 saatte otomatik silinmektedir. Hata dosyası uç noktası başarısız kayıt başına yapılandırılmış bir hata nesnesi vermektedir: makine kodu, yaklaşık 19 kod vardır, artı insan mesajı. Ekle ya da güncelle bayrağı ile bir dış kimlikle etkisiz kılınabilir benzeri yeniden çalıştırma mümkündür. Tamamlanma bildirimi bir e-postadır, itmeli bir kanca değildir.

Kullanıcı dışa aktarma işi aynı eşzamansız iş ile yoklama desenini kullanmaktadır; bağlantı kapsamı, format, azami kayıt ile alan listesi seçilebilmektedir.

### 6.3 Okta toplu işlemleri, çekirdek API'de yoktur

Okta'nın çekirdek kullanıcılar API'sinde Auth0'ın iş uç noktalarının karşılığı yoktur. Okta'nın kendi göç kılavuzu betiklenmiş, sıralı ile kullanıcı başına gönderi tarif etmekte; hız sınırı başlıklarına dayanmayı ile göç pencerelerinde limitleri geçici yükseltmek için destekle koordine olmayı önermektedir.

Gerçek yığın mekanizması iş akışları ürünündedir, platform API'sinde değil: oturum başına en fazla 10.000 kullanıcı, en fazla 50 gönderi ile her biri 200 kullanıcıdır.

Dokümante edilenle gözlenen davranış arasında bir fark vardır: bir müşteri, doküman 10.000 derken toplu içe aktarımın 50 kayıttan sonra durduğunu raporlamıştır. Okta'nın kendi destek yanıtı mekanizmayı teyit etmiş ancak tutarsızlığı açıklayamamış ile resmî bir destek kaydı açmaya yönlendirmiştir.

### 6.4 Microsoft'un gerçek toplu cevabı: yükleme uç noktası, SCIM toplu uç noktası değil

API güdümlü gelen sağlama, 20 Ağustos 2026 güncellemesiyle, şöyledir: senkron 202 kabul edildi dönmekte, sonra sağlama günlükleri API'si kayıt başına durum için yoklanmaktadır; tam olarak uzun süren işlem şeklidir. Kısıtlama beş saniyelik pencerede 40 çağrıdır. Kiracı seviyesinde 24 saatte 2.000 çağrı, yönetişim lisansıyla 6.000 çağrı izinlidir. Microsoft'un kendi tavsiyesi SCIM toplu yüklerini API çağrısı başına 50 operasyona kadar optimize etmektir; günlük kotayı korumak içindir. SCIM şema yapılarını kullanmakta ancak SCIM toplu protokol uç noktasını kullanmamaktadır.

### 6.5 Uzun süren işlem desenleri

RFC 7240, IETF 2014, eşzamansız yanıt tercihini tanımlamaktadır; 202 kodunun ötesinde bu kodun nasıl ve ne zaman kullanılacağına dair az rehberlik verildiği ile işlemin nihai sonucunun belirlenme sürecinin tamamen tanımsız bırakıldığı söylenmektedir. Yani yoklama mekaniğini bilinçli olarak standartlaştırmamaktadır.

Google'ın 151 numaralı API geliştirme ilkesi, yaklaşık 10 saniyeden uzun sürmesi beklenen her yöntemin, ki iyi bir kestirme kural denmektedir, nihai kaynağı değil bir uzun süren işlem nesnesi döndürmesini ile zorunlu bir işlemler servisi bulunmasını istemektedir. İşlem nesnesi, ilerleme ile kısmî hata raporlaması için terminal yanıt tipinden ayrı bir metadata tipi taşımaktadır.

Microsoft ile Azure REST kılavuzları boş gövdeli 202 kabul edildi artı bir durum izleyici kaynağına işaret eden konum başlığı istemektedir; her terminal olmayan yoklama yanıtı kendi yeniden dene değerini taşımalıdır. Azure ayrıca işlem konumu adresinde bir API sürümü parametresi istemektedir.

Takas şudur: üç şartname de itmeli bildirimi zorunlu kılmamakta ile hepsi yoklama tabanlı durum izleyicisini temel kabul edip itmeyi isteğe bağlı bir katman olarak bırakmaktadır. Yoklama basittir, önbellek dostudur ile her HTTP altyapısından geçmektedir; kanca yoklama yükünü azaltmakta ancak çağıranın erişilebilir bir uç nokta açmasını ile etkisiz kılınabilir teslimat ve yeniden deneme yönetmesini gerektirmektedir.

### 6.6 Etkisizleştirme anahtarları

IETF durumu 8 Eylül 2026 itibarıyla şöyledir: ilgili taslağın yedinci revizyonu 15 Ekim 2025'te yayımlanmış, 18 Nisan 2026'da süresi dolmuştur; standartlar yolundadır ile HTTP API çalışma grubunda hâlâ aktif bir internet taslağıdır, bir RFC değildir.

Başlık RFC 8941 yapılandırılmış alan dizgisidir ile UUID önerilmektedir. İsteğe bağlı bir etkisizleştirme parmak izi, yani yükün sağlama toplamı, tanımlanmaktadır; sunucu aynı anahtarla farklı yükü reddedebilsin diyedir. Önerilen durum kodları gereken yerde anahtar yoksa 400, anahtar farklı bir yükle yeniden kullanılmışsa 422 ile aynı anahtarı paylaşan eşzamanlı uçuştaki istekler için 409'dur. Saklama penceresi kasıtlı olarak tanımsızdır; her API kendi belirleyip yayımlamalıdır. Atıf yapılan uygulayıcılar Stripe, PayPal, Adyen, Square, WorldPay ile açık bankacılık girişimleridir.

Stripe referans uygulamadır. Birinci sürüm API'sinde anahtarlar 24 saat tanınmaktadır; eşleşen anahtarla uyuşmayan parametre hata vermekte ile ilk isteğin sonucu, başarı ya da hata, beş yüzlü kodlar dahil, yeniden denemede aynen tekrar oynatılmaktadır. İkinci sürümde pencere 30 güne uzatılmıştır, aynı API ile aynı hesap kapsamında. Davranış değişmiştir: ilk deneme başarısızsa yeniden denemede yeniden çalıştırılmakta, yalnızca tekrar oynatılmamaktadır; başarılıysa hâlâ kısa devre yapıp saklanmış sonucu döndürmektedir. Kritik incelik şudur: Stripe etkisizleştirme sonucunu yalnızca çalıştırma başladıktan sonra kalıcılaştırmaktadır; doğrulama hataları ya da aynı anahtar üzerinde başka bir uçuştaki istekle çakışan istekler saklanmamakta, böylece güvenle yeniden denenebilmekte ile farklı parametre hatası tetiklenmemektedir. Anahtar en fazla 255 karakterdir ile anahtar değerine kişisel veri gömülmemesi açıkça önerilmektedir.

Kimlik sağlayıcılarda durum şöyledir. WorkOS bulunan tek komşudur ile çok dardır: etkisizleştirme anahtarı yalnızca denetim günlüğü olayı oluşturma uç noktasında onurlandırılmaktadır; diğer uç noktalar başlığı sessizce kabul edip tekilleştirme yapmamaktadır, yani yeniden denenen bir değişiklik hâlâ çift yaratabilmektedir. Geliştirme kitleri gönderilere otomatik bir benzersiz tanımlayıcı eklemektedir ancak yalnızca iç yeniden denemeler için, bir çağıran garantisi olarak değil. Auth0'ın yönetim API'si yalnızca kaynak seviyesi semantikle kısmen etkisizleştirilebilirdir, örneğin içe aktarma işindeki ekle ya da güncelle bayrağıyla; etkisizleştirme anahtarı başlığı desteği dokümante edilmemiştir. Okta'da başlık desteği bulunamamıştır; oluşturma için istemcinin sağladığı bir dış kimlikle fiilî bir etkisizleştirme vardır, ki bir istek belirteci değil doğal anahtar etkisizleştirmesidir.

Hiçbir büyük genel amaçlı kimlik sağlayıcı bu deseni Stripe'ın yaptığı gibi uygulamamaktadır. Argus'un farklılaşabileceği somut bir boşluktur.

### 6.7 Hız sınırıyla toplu işlem çelişkisi, dokümante edilmiş cevaplar

| Ürün | Yığın kaç istek sayılmaktadır | Kaynak |
|---|---|---|
| Graph yığın uç noktası | N sayılmaktadır; her alt istek ayrı değerlendirilmekte, zarf her alt istek 429 olsa bile 200 dönmekte ile her biri kendi kaynak birimini tüketmektedir | Kısıtlama dokümanı |
| Entra yükleme uç noktası | Bir çağrı sayılmaktadır, içindeki en fazla 50 operasyondan bağımsız. Bu yüzden Microsoft çağrı başına 50 operasyona kadar doldurun demektedir; çağrı sayısı bütçesini korumak içindir | Gelen sağlama kavramları |
| Auth0 içe aktarma işi | Bir çağrı sayılmakta ancak ayrı bir eşzamanlılık bütçesiyle yönetilmektedir, yani kiracı başına iki iş; dosyadaki kullanıcı sayısından bağımsızdır | Topluluk ile API dokümanı |
| Okta iş akışları toplu içe aktarımı | 50 gönderinin her biri normal bir API çağrısıdır; doküman muafiyet belirtmemektedir, yani N çağrıdır, N en fazla 50'dir | Eşzamanlılık limitleri |

Desen şudur: ölçeklenen iki tasarım ya alt operasyon başına ücretlendirip istemciyi bütçelemeye zorlamaktadır, ki Graph böyledir; ya da çağrı başına ücretlendirip çağrı başına operasyon sayısını ve günlük toplam çağrıyı sınırlamaktadır, ki Entra böyledir. Yani zarfı hız sınırlamakta, yükü değil; ancak zarf boyutunu sınırlayarak kimsenin tek çağrıda sınırsız iş kaçırmasını engellemektedir. Auth0 soruyu tamamen atlatmakta: toplu işi istek hızı sınırlayıcısından çıkarıp küçük tam sayılı bir eşzamanlılık semaforuna taşımaktadır. Üçü de meşrudur. Hiçbiri tek bir HTTP çağrısında N öğeyi bedava saymamaktadır.

---

## 7. Argus için somut tasarım kararları

Her madde bir kaynağa dayanmaktadır.

### API şekli ile sürümleme

1. Sürüm kaynak başına ile yolun sonunda taşınmalıdır; Keycloak'ın ikinci sürüm deseni gibi. Global bir API sürümü tek seferlik büyük bir göçe zorlamaktadır; kaynak başına sürümleme her kaynağın kendi hızında evrilmesine izin vermektedir. Keycloak'ın global ikinci sürüm destanı planlanmadı olarak kapanmış ancak kaynak bazlı istemci API'si ikinci sürümü 26.7.0'da çıkmıştır. Kapsam daraltmak işe yaramıştır.

2. Yerleştirme bir ekle ya da güncelle, gönderi bir oluşturma ile yama bir JSON birleştirme yaması olmalıdır. Bakımcının gönderinin bazen yerleştirme bazen yama gibi çalıştığı itirafı ile bir başka katkıcının oluştur ya da güncelle semantiğinin bulunmadığı tespiti bu kuralın maliyetini göstermektedir. Birleştirme yaması ayrıca açık boş değer problemini çözmektedir; Keycloak bir alanın ayarlanmadığını mı yoksa boşa mı ayarlandığını bilememektedir.

3. Oluşturma yanıtı tam temsili gövdede döndürmelidir, yani 201 ile gövde; yalnızca konum başlığı değil. Bakımcının ifadesiyle konum başlığı ayrıştırmayı gerektirmesi çok elverişsizdir.

4. Kaynaklar hem benzersiz tanımlayıcıyla hem kararlı, insan okunur bir doğal anahtarla adreslenmelidir. Keycloak'ın yalnızca benzersiz tanımlayıcıya dayanan adreslemesi hem API kullanımını hem GitOps'u bozmaktadır: alan silinip yeniden oluşturulduğunda kimlikler yeniden üretilmekte ile devasa sahte farklar doğmaktadır.

5. Sorgu dili olarak SCIM filtre sözdiziminin bir alt kümesi benimsenmeli, kendi alan diline özgü sözdizimi icat edilmemelidir; Keycloak'ın ikinci sürümde yaptığı budur. Keycloak'ın iyi kararı da kopyalanmalıdır: bilinmeyen alan 400 dönmelidir, SCIM'in sessizce yok saymasıyla değil. Sessiz yok sayma, filtresi hiç uygulanmamış bir sorgunun tüm kayıtları döndürmesi demektir; bu bir güvenlik hatasıdır.

6. İmleç tabanlı sayfalama kullanılmalıdır, uzaklık tabanlı değil. Keycloak'ın kendi kullanıcısı uzaklık tabanlı sayfalamanın kayıt kaçırdığını göstermiştir: sonuçlar kullanıcı kimliğine göre sıralandığından ile kimlikler ardışık olmadığından bir kullanıcı atlanabilmektedir. Keycloak ikinci sürümde bu uyarıya rağmen uzaklık ile limit seçmiştir; bu hata tekrarlanmamalıdır. Yanıtta RFC 5988 bağlantı başlığı verilmelidir, ki Keycloak'ın kendi kılavuzunun kuralıdır.

7. Bir kaynak tek istekte tam yaratılabilir olmalıdır. Keycloak'ta bir istemci artı roller iki çağrı gerektirmektedir; çok istekli varlık yaratma her deklaratif aracı bir işlem ile geri alma problemine sokmaktadır. İlişkili N artı bir problemi için genişletme desteği de verilmelidir.

8. OpenAPI şartnamesi koddan üretilmeli, elle bakılmamalı ile geliştirme kitleri zorunlu olarak şartnameden üretilmelidir. Okta'nın modeli budur: şartname yönetim API'sinden doğrudan üretilmiş bir anlık görüntüdür, depo topluluk katkısı kabul etmemektedir ile tüm yönetim kitleri bu şartnameden derlenmek zorundadır. Karşı örnek Keycloak birinci sürümüdür: eksiktir ile genellikle istemci üretmeye yetmemektedir. Ek olarak Keycloak'ın ikinci sürümdeki fikri alınmalıdır: çalışma zamanında bir OpenAPI uç noktası yayımlanmalı ki araçlar bağlandıkları sunucunun sürümüne uyum sağlasın.

### Yetkilendirme ile devretme

9. Yetkilendirme filtresi veri erişim katmanına konmalıdır, işleyiciye değil. CVE-2026-17059 tam olarak bunun yokluğundan doğmuştur: kullanıcılar uç noktası doğru süzmekte ancak rol üyeleri uç noktası aynı kullanıcı başına filtreyi uygulamadan aynı belirtece tam kişisel veri vermekteydi. Rust'ta bu tip sistemiyle zorlanabilir: süzülmemiş bir kullanıcı koleksiyonunun serileştirilebilir bir tipe dönüşmesi derleme zamanında imkânsız olmalıdır.

10. Her uç noktanın gerektirdiği izin testle doğrulanmalıdır; ek açıklamaya güvenilmemelidir. Zitadel'in CVSS 9,0 puanlı açığı, gRPC servis tanımlarında bir kapsamın yanlış yazılmasından 12 uç noktayı sıradan kullanıcılara açmıştır. Argus'ta her yolun gerektirdiği izin makine okunur bir bildirimde durmalı ile sürekli tümleştirmede bildirimi olmayan bir yol derlemeyi kırmalı ve her yol için bu izin olmadan 403 döner testi otomatik üretilmelidir.

11. Hiyerarşi mutasyonu, yani yeniden ebeveynleme ya da taşıma, hem kaynak hem hedef üzerinde izin gerektirmelidir. CVE-2026-9099'da alt grup ekleme yetkilendirme kontrolü yapmamakta; düşük yetkili bir grup yöneticisi alan yöneticisi grubunu kendi altına taşıyıp hiyerarşik kalıtımla o grubun üyelerine parola sıfırlama yetkisi kazanmakta ile tam alan devralmaktaydı. GitLab'ın üst proje kimliği açığı aynı sınıftandır. Ek bir değişmez gerekmektedir: bir taşıma, taşıyanın etkin izin kümesini artıramaz.

12. Kimlik bilgisi ile belirteç nesnelerinin sahip alanı değişmez olmalıdır. authentik'in açığında herhangi bir kimliği doğrulanmış kullanıcı bir API belirteci yaratıp kullanıcı kimliğini değiştirerek süper kullanıcı olmuştu. Geçici çözüm ters vekilde uç nokta bloklamaktı; tasarımın ne kadar kırıldığının göstergesidir. Argus'ta belirteç sahipliği yaratılışta sabitlenmeli ile hiçbir güncelleme yolu onu değiştirememelidir.

13. Yükseltme kapatma statik analizle değil bir çalışma zamanı değişmeziyle çözülmelidir. Güvenlik problemi genel hâlde karar verilemezdir; oluşturma işlemleri olmadan bile PSPACE tamdır. Yani bu izin seti güvenli midir sorusuna genel bir analizle cevap verilememektedir. Uygulanabilir değişmez şudur: hiçbir aktör kendi etkin izin kümesinin üstünde bir izni hiçbir yolla verememelidir. Keycloak bu prensibi beyan etmiş ancak beş ayrı açık almıştır, çünkü kontrol her yolda uygulanmamaktaydı. Kontrol rol atama, grup üyeliği, hiyerarşi taşıma, kapsam eşleme, protokol eşleyici ile token değişimi yollarının hepsinde aynı merkezî fonksiyondan geçmelidir.

14. Kapsam eşleme ile protokol eşleyici bir ayrıcalık yükseltme yüzeyi olarak sınıflandırılmalıdır. Keycloak'ta sınırlı yetkili geliştiriciler bunları yöneterek yönetici rollerini token'a eşleyip yönetim API'sine erişebilmekteydi; ilgili iki açık aynı ailedendir. Token'a iddia yazabilen her mekanizma, yetkilendirme kararını etkiliyorsa yetki veren bir işlemdir ile on üçüncü maddedeki değişmeze tabidir.

15. Kaynak gizleme varsayılan olmalıdır: yetkin olmadığınız kaynak listede görünmemeli, 403 bile alınmamalıdır. Keycloak organizasyon izinlerinin modeli budur: diğer tüm organizasyonlar tamamen gizlenmektedir, hem konsolda hem REST API'sinde. 403 dönmek bir varlık ifşasıdır.

16. Kritik işlemler için yeniden kimlik doğrulama zorunlu kılınmalı ancak bu yetkilendirmenin yerine değil üstüne konmalıdır. Entra korunan eylemlerinin modeli budur: politika girişte değil eylem anında zorlanmaktadır. Microsoft'un kendi uyarısı da uygulanmalıdır: korunan eylemler kimliğe ya da grup üyeliğine dayalı erişim engellemek için kullanılmamalıdır; bu bir yetkilendirme kararıdır ile rol atamasıyla kontrol edilmelidir. Aday işlemler kalıcı silme, izin ya da politika değişikliği, kiracılar arası ayarlar, imzalama anahtarı rotasyonu, kimliğe bürünme başlatma ile kimlik sağlayıcı bağlantı ayarlarıdır; Zitadel açığının hedefi tam olarak sonuncusuydu. Acil erişim hesabı politikadan hariç tutulmalıdır.

17. Yönetici oturum politikası merkezî olmalı ile tüm yönetici yüzeylerini kapsamalıdır. Okta'nın 12 saat ömür artı 15 dakika boşta kalma artı otonom sistem numarası oturum bağlaması artı isteğe bağlı IP bağlaması modeli benimsenmelidir. Ancak Okta'nın hatası yapılmamalıdır: diğer ürünlerindeki yönetimsel oturumlar bu politikadan etkilenmemektedir. Bir yönetici oturum politikası yalnızca konsolu koruyorsa diğer yüzeyler açık kapıdır.

18. Yönetim API'si token'ları kısa ömürlü ile iptal edilebilir olmalıdır. Auth0'ın karşı örneği 24 saatlik ile iptal edilemez bir token'dır. Keycloak'ın yönetim komut satırı token'ı bir dakikadır; bu tarafta doğrudur. Argus'ta kısa ömür artı sunucu tarafı iptal listesi ya da içgözlem, yönetici token'ları için zorunludur.

### Çok kiracılık

19. Platform yönetici API'siyle kiracı yönetici API'si ayrı yüzeyler olmalıdır: ayrı izleyici kitle, ayrı kapsam ad alanı ile ayrı hız sınırı bütçesi. Auth0 bunu 21 Nisan 2026'da yapmak zorunda kalmıştır; yönetim API'sinin sık ile ince taneli çağrılar için tasarlanmadığını ile hızla bir darboğaza dönüşebildiğini kendisi söylemektedir. Argus bunu birinci günde yapmalıdır.

20. Kiracı bağlamı istemciden alınmamalı, doğrulanmış token'dan türetilmelidir. Auth0'ın kendi organizasyonum API'sinde bağlam kimliği doğrulanmış kullanıcının üyeliğinden gelmekte ile istemci hiçbir yerde kimlik göndermemektedir. Bu, güvensiz doğrudan nesne referansı sınıfını yapısal olarak ortadan kaldırmaktadır. Yolda ya da alt alan adında kiracı görünüyorsa bile token iddiasıyla eşleşme her istekte doğrulanmalıdır.

21. Ana kiracıdan her şeyi yönet modelinden kaçınılmalıdır. Keycloak'ta erişim token'ı hangi alan yönetiliyor olursa olsun ana alandan gelmelidir; ana alan hem tek arıza hem tek ele geçirme noktasıdır. Argus'ta kiracı yöneticisi kendi kiracısının vereninden aldığı token'la yönetmeli ile platform yöneticisi ayrı, dar bir kontrol düzleminden çalışmalıdır.

22. Platform yöneticisi bile göremesin seçeneği ürünleştirilmelidir; Entra'nın kısıtlı yönetim birimi gibi, ki kısıt küresel yöneticiler dahil tüm yöneticilere uygulanmaktadır. Ancak Entra'nın tuzağına düşülmemelidir: bu birim ayrıcalıklı kimlik yönetimi ile hak yönetimiyle çalışmamaktadır. Argus'ta izolasyon mekanizması yönetişim mekanizmasıyla aynı gün tasarlanmalıdır; sonradan birleştirilememektedir.

### Yapılandırma

23. Dışa aktarım deterministik ile fark alınabilir olmalıdır: sıralı diziler, üretilmiş kimlikler ile zaman damgaları isteğe bağlı olarak çıkarılabilmelidir. Keycloak'ın dışa aktarımı deterministik değildir ile düzeltme çekirdekte değil bir üçüncü taraf aracında yapılmıştır. Bu, her aracın aynı işi tekrar çözmesi demektir.

24. Sırlar deklaratif dokümandan referansla ayrılmalıdır, yani ortam değişkeni ya da sır yöneticisi işaretçisiyle; asla gömülü ile asla maskeli olmamalıdır. Keycloak kısmi dışa aktarımı sırları maskelemekte ile doküman ne fark alınabilmekte ne yeniden uygulanabilmektedir; Terraform sağlayıcısı sırları duruma önbeleklemekte ile Auth0'da değişiklikleri yok say direktifi kimlik bilgilerini korumamaktadır. Üçü de aynı kök nedendendir: sır, yapılandırma dokümanının bir alanı olarak modellenmiştir.

25. Tam oluştur oku güncelle sil artı kayma uzlaştırması verilmelidir, yalnızca oluşturan bir içe aktarım değil. Keycloak'ın alan içe aktarma tanımı yalnızca oluşturmayı desteklemekte ile doğrudan yapılan değişiklikler geri senkronize edilmemektedir; o kadar yetersizdir ki Keycloak ayrı bir alan operatörünü geçici çözüm olarak yayımlamak zorunda kalmıştır.

26. İstenen durumla çalışma zamanı durumu API seviyesinde ayrılmalıdır. Bu, bir Keycloak katkıcısının önerisidir ile sunucu tarafı varsayılanların kayma olarak görünmesini engelleyen tek yapısal çözümdür. Auth0 ile Okta sağlayıcılarındaki kalıcı sahte kayma bu ayrımın yokluğundandır. Somut kural şudur: bir okuma çağrısı, kullanıcının ayarlamadığı alanları ayarlanmış gibi göstermemelidir.

27. Sıralamaya bağlı yapılandırma, yani kimlik doğrulama akışı yürütmeleri, deklaratif olarak ifade edilebilir olmalıdır. Keycloak Terraform sağlayıcısında bu, API sınırlaması nedeniyle açık bir bağımlılık bildirimi gerektirmektedir; yani deklaratif bir araca buyurgan bir kaçış deliği açılmıştır. Sıra kaynağın kendi alanı olmalıdır, ayrı bir API çağrısı değil.

### Toplu işlem ile hız sınırı

28. Toplu işlem için eşzamansız bir iş API'si yapılmalı ile SCIM toplu uç noktasına yatırım yapılmamalıdır. İlgili RFC bölümü iyi şartnamelenmiştir ancak incelenen her büyük satıcı desteklemediğini söylemekte ya da hiç yönlendirmemektedir; hepsi kendi eşzamansız iş API'sini yazmıştır. Argus'un modeli bir iş gönderisi, 202 ile iş kaynağı ile yoklamadır. Yaklaşık 10 saniyeden uzun her işlem bir uzun süren işlem olmalıdır. İlerleme ile kısmî hatalar terminal sonuçtan ayrı tiplerde taşınmalıdır.

29. İş sonuçları yeterince uzun saklanmalı ile yapılandırılmış bir öğe başına hata dosyası verilmelidir. Auth0'ın hata formatı doğrudur ancak 24 saatte silmesi ile iki saatte zaman aşımına uğraması kısıtlayıcıdır. Ayrıca kiracı başına iki eşzamanlı iş limiti o kadar dardır ki kurumsal müşterilere dokümante bir API çözümü yerine teknik hesap yöneticisine başvurmaları denmektedir; bu tekrarlanmamalıdır.

30. Hız sınırı üç bağımsız katman olarak tasarlanmalıdır, yani Okta'nın modeli: kova tabanlı zaman penceresi, yöntem ile en uzun önek eşleşmesiyle uç nokta grupları; eşzamanlılık semaforu, yani aynı anda kaç isteğin işlendiği; ile aktör bazlı koruma, yani kullanıcı başına uç nokta başına limit, tek bir aktörün kiracı kotasını yemesini engellemek için. Microsoft bu üçüncü katmanı 30 Eylül 2025'te sonradan eklemek zorunda kalmıştır; baştan yapılmalıdır.

31. Yığın bir zarf olarak hız sınırlanmalı ancak zarf boyutu sınırlanmalıdır. İki meşru model vardır: Graph alt istek başına saymaktadır, Entra bir çağrı saymakta ancak çağrı başına operasyon ile günlük çağrı sayısını sınırlamaktadır. Argus Entra modelini seçmelidir; istemcinin bütçe hesabı basitleşmektedir. Ancak Graph'ın hatası yapılmamalıdır: zarf 200 dönerken içindeki her şey 429 olursa istemciler sessizce veri kaybetmektedir. Argus'un yığın yanıtı, herhangi bir alt işlem başarısızsa bunu zarf seviyesinde de sinyallemelidir.

32. Bağımlılık desteği verilirse Microsoft'un tavsiyesi bir kurala çevrilmelidir: yığın ya tamamen sıralı ya tamamen paralel olmalıdır. Karışık bir bağımlılık grafiği hem istemcide hem sunucuda bir hata kaynağıdır; başarısız bağımlılık için 424 semantiği nettir.

33. Etkisizleştirme anahtarı başlığı birinci günden tüm değiştiren uç noktalarda desteklenmelidir; ilgili taslağın semantiğiyle, yani yapılandırılmış dizgi, yük parmak iziyle anahtar yeniden kullanım tespiti ile 400, 422 ve 409 kod ayrımıyla. Stripe'ın ikinci sürüm davranışı alınmalıdır: başarılı ilk deneme kısa devre yapmakta, başarısız olan yeniden çalıştırılmaktadır; sonuç yalnızca çalıştırma başladıktan sonra kalıcılaştırılmalıdır ki doğrulama hataları ile uçuştaki çakışmalar güvenle yeniden denenebilsin. Saklama penceresi açıkça yayımlanmalıdır; Stripe'ın 30 günü iyi bir referanstır. Anahtar en fazla 255 karakter olmalı ile kişisel veri içermemelidir. Bu bir farklılaşma noktasıdır: büyük sağlayıcıların hiçbiri bunu yapmamaktadır ile WorkOS yalnızca tek bir uç noktada yapmakta ve diğerlerinde başlığı sessizce yutmaktadır; sessiz yutma en kötü seçenektir, ya desteklenmeli ya reddedilmelidir.

### Yönetim arayüzü ile gözlemlenebilirlik

34. Yönetim konsolu ayrı bir kökende çalıştırılmalı ile kiracı kontrollü her dizgi güvenilmez kabul edilmelidir. Keycloak'ın depolanmış XSS açıkları ile ana bilgisayar başlığı yansımalı açığı hep ayrıcalıklı saldırgan senaryosudur: düşük yetkili bir yönetici, yüksek yetkili bir yöneticinin tarayıcısında kod çalıştırmaktadır. Devredilmiş yönetimde bu, kiracı izolasyonunu tek hamlede çökertmektedir. Siteler arası istek sahteciliği belirteci oturuma bağlanmalıdır; Keycloak'ın hatası tam olarak buydu. Sıkı bir içerik güvenlik politikası ile ana bilgisayar başlığına asla güvenmeyen adres üretimi gerekmektedir.

35. Hız sınırı gözlemlenebilirliği bir ürün özelliği yapılmalıdır. Okta'nın hız sınırı panosu referanstır: kova başına anlık yüzde, 24 saatlik ile bir saatlik ortalama, en çok tüketen on kırılımı, dört ayrı sistem günlüğü olay tipi ile yapılandırılabilir eşikte e-posta uyarısı. Bir yönetim API'si kotasının nerede tükendiğini gösteremiyorsa operasyonel olarak kullanılamaz. Bir uyarı gerekmektedir: metrik etiketleri istekten türetilmemelidir; 6 Ağustos 2026 tarihli bir danışmanlık tam olarak istek kontrollü hata metniyle sınırsız metrik kardinalitesidir.

36. Kimliğe bürünme ayrı ile açık bir kapsam yapılmalı ile her kullanımı denetlenebilir kılınmalıdır. Keycloak ikinci sürümde bunu açık bir kapsam yapmıştır, ki doğru bir karardır; ancak dönen token hedef kullanıcının kendi token'ından ayırt edilememektedir. Argus'ta kimliğe bürünme token'ı bir eylemde bulunan iddiası taşımalı ki aşağı akış servisleri ayırt edebilsin; ömrü normal token'dan kısa olmalı ile yeniden kimlik doğrulama kapısının arkasında durmalıdır.

37. Rust'ın bellek güvenliğine güvenip yetkilendirme testlerinden kısılmamalıdır. Keycloak danışmanlıklarının ilk sayfasındaki 10 kayıttan yedisi bir atlatma sınıfındadır; sıfır bellek güvenliği ile sıfır enjeksiyon vardır. Özellikle iki tanesi adres normalleştirmesiyle ilgilidir; yola dayalı yetkilendirme yapılıyorsa karşılaştırmadan önce tek bir kanonikleştirme fonksiyonundan geçilmeli ile bu, özellik testiyle doğrulanmalıdır.

38. İnce taneli izinler bitmiş bir özellik sanılmamalı ile kademeli açılıp kapatılabilir olmalıdır. Keycloak ikinci sürümü Nisan 2025'te yayımlamış ile ilk yaklaşık 14 ayda en az beş ayrıcalık yükseltme açığı almıştır. Keycloak'ın doğru yaptığı şey alan başına bağımsız etkinleştirmedir; sorun çıkan kiracıda kapatılabilmektedir. Argus'ta da devredilmiş yönetim kiracı başına bayraklanmalı ile birinci sürümden ikinci sürüme otomatik göç vaat edilmemelidir; Keycloak da verememiştir.

### Devredilmiş kendi kendine hizmet ile uzlaştırma

39. Kiracının bilişim sorumlusu üçüncü bir aktör olarak modellenmelidir; 19. maddedeki iki yüzey yetmemektedir. Yetkisi tek bir işe indirgenmelidir: kendi kuruluşunun kurumsal bağlantısını, yani çoklu oturum ile dizin eşzamanlamasını kurmak ve alan adını doğrulamak. Bu yüzey kiracı yönetici API'sinin bir alt kümesi değil, ayrı bir izleyici kitle ile ayrı bir kapsam ad alanı taşıyan bağımsız bir yüzey olmalıdır; gerekçe 19. maddeyle aynıdır. Erişim bir davet bağlantısıyla verilmeli, süreli olmalı ile her oturumu denetlenmelidir. Model WorkOS'un yönetim portalıdır; 2.7'ye bakınız.

40. Yönetim API'sinde bir kullanıcının kimlik bilgisini doğrudan yazan uç nokta bulunmamalıdır. Yalnızca tek kullanımlık, süreli bir kimlik bilgisi kurma niyet belirteci üreten bir uç nokta bulunmalıdır; kullanıcı kendi kimlik doğrulayıcısını kendisi kurmalıdır. Bu bir izin ayarı değil bir ayrıcalık tavanıdır ile 13. maddedeki değişmezin kurtarma yolundaki özel hâlidir: servis masası, hiçbir yolla, kullanıcının kimlik doğrulayıcısını seçememelidir. Model Kanidm'dir; öntanımlı belirteç ömrü bir saat, azami 24 saat, kullanımda derhâl geçersizleşme. Belirtecin üretilmesi ile kullanılması ayrı denetim olaylarıdır. Ayrıntı §22 §7.5'tedir.

41. Uzlaştırmanın yönü ile çakışma semantiği açıkça tanımlanmalıdır; 25. madde uzlaştırma istemekte ancak yönü söylememektedir. authentik'in modeli birinci taraf taslaklarını 60 dakikada bir yeniden uygulamaktadır; bu, yönetim arayüzünden yapılan bir değişikliğin bir saat sonra sessizce geri alınması demektir. Bir kimlik sağlayıcıda bunun güvenlik sonucu vardır: acil bir müdahalede kapatılan bir istemci ya da iptal edilen bir bağlantı, kimse fark etmeden geri gelebilmektedir. Argus'ta üç kural gerekmektedir. Deklaratif kaynağın yönettiği alanlar açıkça işaretlenmeli ile yönetim arayüzünde salt okunur gösterilmelidir. İşaretli bir alana bant dışı yazma denemesi sessizce kabul edilip geri alınmamalı, reddedilmelidir. Acil müdahale için bir kaçış yolu bulunmalı ile bu yol uzlaştırmayı o kaynak için, bir işaretle ve denetim kaydıyla, açıkça durdurmalıdır.

---

## 8. Doğrulanamayanlar

1. Keycloak alan yönetimi rollerinin tam resmî listesi ile açıklamaları; ilgili kılavuz bölümü çekim sırasında kesilmiştir. Rol isimleri ekosistemde tutarlıdır ancak resmî tablo doğrulanmamıştır.
2. Keycloak'ın toplam danışmanlık sayısı ile tam sınıf dağılımı; yalnızca ilk sayfa çekilebilmiştir.
3. Üç 2026 açığı için puanlar, tam saldırı yolu ile kesin düzeltme sürümleri; ilgili kayıtlar teknik detay içermemektedir.
4. Auth0 ile Microsoft Graph'ın OpenAPI şartnamesini üretip üretmediği ya da elle mi yazdığı; arama bütçesi tükendiği için araştırılamamıştır.
5. Auth0 yönetim API'sinin güncel istek hızı rakamları; topluluk kaynakları bir tahmin vermekte ancak resmî sayfada katman bazlı bir tablo bulunamamıştır. Gösterge niteliğindedir, bugün için otoriter değildir.
6. Okta'nın belirli uç noktalar için sayısal hız sınırı tavanları ile abonelik katmanına göre farkları; Okta bunları dokümanda vermemekte ile kuruluş içindeki panoya yönlendirmektedir.
7. PingFederate'in toplu destek değeri; birincil doküman sayfası çekilememiştir, arama özeti üzerindendir. Muhtemelen doğrudur ancak bağımsız doğrulanmamıştır.
8. Salesforce, OneLogin ile Google Workspace'in SCIM toplu destek değerleri hiç araştırılmamıştır.
9. Google'ın ilgili ilkesindeki bekleme semantiği ile yoklamaya karşı bildirim takasının resmî ele alınışı; çekilen sayfa bunları içermemektedir.
10. Yapılandırma aracı ile Terraform sağlayıcısı sürümlerinin gün seviyesi tarihleri; GitHub API hız sınırına takıldığı için çekme özetlerinden alınmıştır. Sürüm sırası ile aktif bakımda olma durumu sağlamdır, kesin tarihler yaklaşıktır.
11. Alan operatörünün güncel yıldız ile konu sayıları ile olgunluk değerlendirmesi; tek bir çekimdendir ile ikinci bir kaynakla çapraz kontrol edilmemiştir.
12. authentik'in resmî Kubernetes operatörü konusundaki en güncel duruşu; yalnızca 2023 tarihli ile uygulanmamış bir konu ve topluluk alternatifleri bulunmuştur, çok yeni bir değişiklik olmuş olabilir.
13. Keycloak kimliğe bürünme en iyi uygulamaları; kaynak blog yazılarıdır, birincil kaynak değildir.
14. Çok kiracılıkta kiracı bağlamı taşıma konusunda birincil bir şartname ya da standart kaynağı; bulunanlar ağırlıklı olarak bloglardır. İlgili sonuç Auth0'ın somut tasarımı ile Zitadel açığından çıkarım yoluyla desteklenmiştir, normatif bir dokümandan değil.
15. CVE-2024-3656'nın hangi belirli yönetim uç noktalarının korumasız olduğu; danışmanlık uç nokta isimlerini, kök nedeni ile puanı vermemektedir.
16. Okta iş akışları toplu içe aktarımındaki 10.000 ile 50 kayıt tutarsızlığının çözümü; Okta'nın kendi destek yanıtı da açıklayamamış ile resmî bir destek kaydına yönlendirmiştir.

---

# Kısım VII — İşletim

Gözlemlenebilirlik, dağıtım ile test: ürünü çalışır ile doğrulanabilir tutan katman.
