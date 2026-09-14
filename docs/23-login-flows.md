# §23 — Giriş akışları ve kullanıcı deneyimi

Bu bölüm `ARGUS.md` dosyasının 23. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§23 §X` referansları aynı anlamdadır.

Aşağıdaki bulgular yaklaşık 50 arama ile çekme sonucudur. Her iddiada kaynak ile tarih vardır. Doğrulanamayanlar açıkça işaretlenmiştir.

---

## 1. Önce tanımlayıcı akışı

### 1.1 Endüstri neden geçmiştir, gerçek gerekçe

Birincil gerekçe estetik değil federasyon yönlendirmesidir. Auth0'ın resmî dokümanı akışı açıkça bu şekilde tanımlamaktadır: kullanıcı e-postasını girmekte, Auth0 alan adının kayıtlı bir kurumsal bağlantıyla eşleşip eşleşmediğine bakmakta, eşleşirse kurumsal kimlik sağlayıcıya yönlendirmekte ile eşleşmezse yerel parola sormaktadır. Auth0 üç varyant belgelemektedir: tanımlayıcı ile parolanın tek ekranda alınması, önce tanımlayıcı ile önce tanımlayıcı artı biyometri, ki WebAuthn kaydı içindir.

İkincil gerekçe kimlik doğrulama yönteminin kullanıcıya göre değişmesidir. Tanımlayıcı alınmadan hangi yöntemin, yani parola, geçiş anahtarı, kurumsal çoklu oturum açma ya da sihirli bağlantının gösterileceği bilinememektedir. Microsoft'un 1 Mayıs 2025 tarihli güvenlik blog yazısı, yeni giriş arayüzünün kullanıcı için mevcut en güvenli yöntemi otomatik tespit edip önceliklendirdiğini ile bu tasarımın parola kullanımını %20'den fazla azalttığını açıklamaktadır.

Bir doğrulanamayan nokta vardır: Google'ın 2015'teki önce tanımlayıcı geçişine ait resmî bir tasarım gerekçesi belgesi bulunamamıştır. Yalnızca Google Cloud dokümanlarında davranışın tarifi bulunmaktadır.

### 1.2 Numaralandırma: yapısal olarak sızdırmakta mıdır? Evet

Bu bir gerçekleme hatası değil akışın yapısal sonucudur. İki adımlı akışta birinci adımın çıktısı zorunlu olarak bu tanımlayıcı için ne yapmalıyım bilgisidir; bu da hesabın varlığını ima etmektedir.

Somut kanıtlar şunlardır.

CVE-2026-4633, Keycloak'ta, organizasyonlar etkinken önce kimlik giriş akışında farklılaşan hata mesajları üzerinden kullanıcı numaralandırmasıdır. CVSS 3,7 düşük, zayıflık sınıfı gözlemlenebilir farklılık, yayın 27 Mart 2026. Önerilen azaltmalar yamalar, organizasyonların kapatılması, hız sınırlama, CAPTCHA ile jenerik hata mesajlarıdır.

Keycloak'ın 17629 numaralı konusu, parolasız tarayıcı giriş akışındaki kullanıcı adı formunun olmayan bir kullanıcı için geçersiz kullanıcı adı ya da e-posta döndürdüğünü, varsayılan tarayıcı akışındaki kullanıcı adı ile parola formunun ise ayrım yapmadığını göstermektedir. Konu planlanmadı olarak kapatılmıştır. Yani üst düzey bir kimlik sağlayıcı bunu kabul edilebilir bir takas saymıştır.

Keycloak kaba kuvvet koruması kilitli hesapta da aynı geçersiz kullanıcı adı ya da parola mesajını göstermektedir; bu bilinçli bir tasarımdır.

Ürünlerin bunu nasıl ele aldığının en net belgelenmiş örneği Clerk'tür.

| Mod | Ne yapmaktadır | Kullanıcı deneyimi bedeli |
|---|---|---|
| Toplu koruma | Hız sınırlama uygulanmakta ile normal giriş deneyimi korunmaktadır | Kullanıcı hesabın var olmadığını yine öğrenmektedir |
| Katı koruma | Hesabın varlığı kimlik doğrulanana kadar gizlenmekte ile olmayan hesaplar için parola ve Web3 stratejilerinde gerçek doğrulama kodu gönderilmemektedir | Yanlış tanımlayıcıda hiçbir geri bildirim yoktur; açık erişim modu zorunludur, parola bir başlangıç stratejisi olamamaktadır ile kullanıcı adı tanımlayıcısı desteklenmemektedir |

Bu tablo Argus için doğrudan kopyalanabilir bir tasarımdır: numaralandırma koruması bir moddur, tek bir davranış değildir; ile katı mod diğer özellikleri, yani kullanıcı adıyla girişi ile yalnızca davetle katılımı yapısal olarak dışlamaktadır.

Corbado'nun analizi ek bir yapısal nokta koymaktadır: tanımlayıcı adımını tamamen atlayan geçiş anahtarıyla giriş yap düğmesi, yani boş kimlik bilgisi listesi ile keşfedilebilir kimlik bilgisi kullanımı, numaralandırmayı sıfırlamaktadır; çünkü tarayıcı hiçbir sunucu sorgusu olmadan yerel kimlik bilgisini bulmaktadır. Amazon, Microsoft ile Google'ın yedek seçenekleri kaydın gerçekten var olup olmadığını maskelemektedir.

OWASP'ın konumu nettir ile takası açıkça kabul etmektedir: uygulama geçersiz kullanıcı, geçersiz parola, kilitli hesap ile devre dışı hesap için aynı mesajı dönmelidir; parola sıfırlamada o adres veritabanımızdaysa bir e-posta göndereceğiz denmelidir. OWASP ayrıca hızlı çıkış kod desenlerinin zamanlama üzerinden sızdırdığını ile jenerik mesajların meşru kullanıcıyı kafası karışık bırakıp uygulamayı terk etmeye itebileceğini kabul etmektedir; önerisi kritikliğe göre karar vermek ile jenerik mesajı bir bot kontrolüyle birleştirmektir.

### 1.3 Ev alanı keşfi, güvenlik riskleri

Bu mekanizma iki ayrı sızıntı yaratmaktadır.

Birincisi kullanıcının hangi kuruma ait olduğunun sızmasıdır. Microsoft'un kullanıcı alanı sorgulama uç noktası kimlik doğrulama olmadan federasyon marka adını ile hesabın yönetilen mi federe mi olduğunu döndürmektedir; tek istekle kurumun hangi federasyon ürününü kullandığı anlaşılmaktadır. Sprocket Security'nin 10 Aralık 2025 tarihli kiracı numaralandırması geri döndü yazısı bunu belgelemektedir. Microsoft 23 Mayıs 2025 tarihli bir mesaj merkezi duyurusuyla otomatik keşif servisini kısıtlamıştır; dağıtım Haziran ile Ağustos 2025 arasındadır. Artık yalnızca sorgulanan alan adı dönmekte ile toplu numaralandırma kırılmıştır. Ancak kullanıcı alanı sorgulaması ile iyi bilinen OIDC yapılandırması üzerinden kiracı keşfi devam etmektedir.

İkincisi alan adı ipucuyla otomatik hızlandırmadır. Microsoft'un resmî tavsiyesi otomatik hızlandırmaya karşıdır: otomatik hızlandırma yapılandırmasının önerilmediği, çünkü FIDO gibi daha güçlü kimlik doğrulama yöntemlerini ile iş birliğini engelleyebileceği belirtilmektedir. Gerekçe güvenliktir: bir uygulamanın gönderdiği alan adı ipucu kullanıcıyı federe sağlayıcıya fırlatmakta, kullanıcı yönetilen kimlik bilgisini kullanamamakta ile misafir kullanıcılar girememektedir. Doküman güncellemesi 6 Nisan 2026'dır.

Microsoft'un iki savunması vardır. Birincisi Nisan 2023'ten beri gösterilen alan adı onay penceresidir: otomatik hızlandırma ya da akıllı bağlantı kullanan organizasyonlarda kullanıcıya hangi kiracıya giriş yaptığı onayı gösterilmektedir. Doküman bunu doğrudan Microsoft'un güvenlik sertleştirme çabalarının parçası olarak tanımlamaktadır; kullanıcıya tanımlayıcısı ile hedef kiracının alan adı gösterilip onay istenmektedir. İkincisi alan adı ipucu politikasıdır: belirli alan adları ile uygulamalar için ipucunun yok sayılması ya da dikkate alınması ayarlanabilmektedir. Dikkate al her zaman yok say kuralını ezmektedir. Tüm alan adları ile tüm uygulamalar için joker değerler bulunmaktadır. Dört fazlı bir dağıtım planı belgelenmektedir.

Öncelik sırası alan adı ipucu, servis aslı politikası, organizasyon politikası ile varsayılandır. Not edilmelidir: alan adı ipucu, keşif politikasındaki otomatik hızlandırmayı ezmektedir; yani istemci sunucu politikasını geçersiz kılabilmektedir, ki bu tek başına bir tasarım hatası sinyalidir. Ayrıca bu politikalar mobil ile macOS aracılı kimlik doğrulamasında çalışmamaktadır.

Argus için çıkarım şudur: alan adı ipucu benzeri bir parametre kabul edilecekse, kiracı tarafında bunu yok sayabilme yetkisi zorunludur ile istemci ipucu sunucu politikasını ezmemelidir; Microsoft'un yaptığının tersi olmalıdır.

---

## 2. Geçiş anahtarı ile WebAuthn kullanıcı deneyimi, 2026 gerçeği

### 2.1 Koşullu arayüz, yani otomatik doldurma, teknik durum

Chrome'un birincil dokümanından çıkanlar şunlardır.

Otomatik tamamlama özniteliği kullanıcı adı ile WebAuthn değerlerini boşlukla ayrılmış olarak taşımalıdır; otomatik odaklanma eklenirse istem sayfa yüklenince tetiklenmektedir. İzin verilen kimlik bilgileri boş bir dizi olmalıdır; tarayıcı o bağlı taraf kimliği için tüm kimlik bilgilerini göstermektedir. Aracılık koşullu olmalıdır; söz, kullanıcı girdiye dokunana kadar askıda kalmakta ile arayüz gösterilmemektedir. Özellik tespiti artık istemci yetenekleri çağrısındaki koşullu alma bayrağı üzerindendir. Bir iptal denetleyicisi sinyaliyle programatik iptal mümkündür. Kullanıcı doğrulaması tercih edilir ayarındaysa kimlik doğrulayıcı verisindeki doğrulama bayrağı kontrol edilmelidir. Başarılı bir geçiş anahtarı doğrulamasından sonra ikinci faktör istenmemelidir.

Tarayıcı ile işletim sistemi desteği Chrome ve Edge 108 ve üstü, yani Aralık 2022, Safari 16 ve üstü ile Firefox 122 ve üstüdür; ancak yalnızca alttaki işletim sistemi Windows 11, macOS, Android ya da iOS ve iPadOS 16 ve üstüyse geçerlidir. Windows 10, eski ChromeOS ile çoğu uygulama içi tarayıcı görünümünde aynı kod yolu hiçbir şey döndürmemekte ile form hiçbir öneri göstermemektedir. Bu bir satıcı kaynağıdır ancak teknik iddia Chrome dokümanlarıyla tutarlıdır.

### 2.2 Otomatik doldurmayla kalıcı pencerenin karşılaştırması

Chrome'un kendi kılavuzu net bir ayrım koymaktadır: hem parola hem geçiş anahtarı kullanıcıları aynı mevcut form içinde destekleniyorsa koşullu arayüz, geçiş anahtarı birincil yöntemse kalıcı pencere kullanılmalıdır.

Koşullu arayüzün belgelenmiş dezavantajları şunlardır.

1. Sessiz başarısızlık ile ölçülemezlik. Site, açılır listenin göründüğünü, boş göründüğünü ya da kullanıcının görmezden geldiğini ayırt edememektedir. Bozuk bir gerçekleme çalışan bir gerçeklemeyle aynı görünmektedir. Bu Argus için kritiktir: telemetri tasarımı baştan buna göre kurulmalıdır.
2. Parola yöneticisi eklentileri belge nesne modelini değiştirip otomatik tamamlama etiketini ezebilmektedir.
3. Kullanıcı alana dokunmadan tetiklenmemektedir.
4. Yalnızca keşfedilebilir kimlik bilgileri listelenmektedir.
5. Platform desteği eşit değildir.

Önerilen desen şudur: koşullu arayüz artı her zaman bir geçiş anahtarıyla giriş yap düğmesi; düğmeye basıldığında bekleyen koşullu istek bir iptal denetleyicisiyle iptal edilmelidir.

Bir doğrulanamayan nokta vardır: koşullu arayüzün kalıcı pencereye kıyasla dönüşüm etkisine dair bağımsız, birincil ile sayısal bir veri bulunamamıştır. Koşullu arayüzün benimseme üzerindeki en büyük tek kaldıraç olduğu iddiası satıcı içeriğidir ile doğrulanamamıştır.

### 2.3 Geçiş anahtarı benimsemesi, 2026 rakamları

FIDO Alliance'ın 7 Mayıs 2026 tarihli dünya geçiş anahtarı günü raporu birincil kaynaktır.

Dünyada tahminen beş milyar geçiş anahtarı kullanımdadır. Tüketici farkındalığı %90'dır, 2025'te %75'ti. Kullanıcıların %75'i en az bir hesapta geçiş anahtarı etkinleştirmiştir. %49'u mümkün olduğunda düzenli olarak kullanmaktadır. Kurumların %68'i çalışan girişleri için geçiş anahtarı dağıtmış ya da dağıtmaktadır. %82'si tam parolasızlığı nihai hedef olarak belirtmekte ile %28'i ulaşmıştır. Kurumların %57'si hâlâ birincil çalışan girişinde kimlik avına açık yöntemlere dayanmaktadır. %33'ü geçen yıl bir hesap ele geçirilmesi ya da ihlal bildirimi yaşamıştır; ABD'de bu oran %41'dir. Tüketicilerin %47'si parolayı hatırlayamadığında satın almayı ya da girişi terk etme eğilimindedir.

Metodoloji önemlidir: Sapio Research, Nisan 2026. Tüketici tarafında 11.000 kişi, 10 ülke ile %95 güvende artı eksi 0,9 puan hata payı. İş gücü tarafında 500'den fazla çalışanlı kurumlardan 1.400 karar verici ile artı eksi 2,6 puan hata payı. Bunlar anket verisidir, telemetri değildir. Geçiş anahtarı etkinleştirdim beyanı bir davranış beyanıdır, gerçek kullanım oranı değildir.

Ek kırılım şudur: benimseme sürücüleri kimlik avı ile çok faktörlü yorgunluk koruması %39, kimlik avına dirençli kimlik doğrulama %37 ile hız ve kullanıcı deneyimi %34'tür. Engeller eski sistem uyumluluğu %38, bütçe %35 ile cihaz kurtarma endişesi %33'tür.

Gerçek telemetri, satıcı kaynaklı ancak üretim verisi olanlar şunlardır. Google'ın Mart ile Nisan 2023 verisine göre aynı cihazda geçiş anahtarı başarı oranı %63,8, parola %13,8'dir; ortalama giriş süresi 14,9 saniyeye karşı 30,4 saniyedir. Microsoft'un 1 Mayıs 2025 verisine göre geçiş anahtarı kullanıcıları yaklaşık %98, parola kullanıcıları %32 başarı oranına sahiptir; geçiş anahtarı girişleri parola artı çok faktörlüden sekiz kat hızlıdır; günde yaklaşık bir milyon geçiş anahtarı kaydı yapılmaktadır ile yeni giriş arayüzü parola kullanımını %20'den fazla azaltmıştır. TikTok'un Temmuz 2023 verisine göre giriş başarısı %97'dir ancak uygun kullanıcıların yalnızca %14'ü benimsemiştir ile kısa mesaj tek kullanımlık şifre kullanımında %2 düşüş olmuştur. KAYAK giriş süresinde %50 azalma bildirmiştir. FIDO geçiş anahtarı endeksi, 13 Ekim 2025, Liminal ile birlikte, geçiş anahtarı girişlerinde %93 başarı, diğer yöntemlerde %63 başarı ile %30 dönüşüm artışı bildirmektedir. Metodolojisi dokuz FIDO üye kuruluşuna yapılan gizli bir anket artı 200 kuruluşluk bir Liminal çalışmasıdır; anonim, toplu ile denetlenmemiştir ile pazarlama ağırlığı yüksektir.

Kritik yorum şudur: Microsoft'un rakamlarıyla Google'ınkiler aynı şeyi ölçmemekte ile her ikisi de seçim yanlılığı taşımaktadır; geçiş anahtarı kuran kullanıcı zaten aktif, cihazı elinde olan kullanıcıdır. Bu rakamlar Argus'un iş gerekçesinde kullanılacaksa seçilmiş popülasyon uyarısıyla kullanılmalıdır.

### 2.4 Geçiş anahtarı kullanıcı deneyimi başarısızlıkları, cihazlar arası gerçek

Bu, raporun en sert bulgusudur.

Android cihazlar arası karekod hunisi, Google'ın Authenticate 2025 verisinden Corbado tarafından derlenmiştir.

| Adım | Oran |
|---|---|
| Başlangıç sayfasından tarayıcı istemine | %48 |
| Tarayıcı isteminden karekod taramasına | %29; kritik kopuş buradadır |
| Karekod taramasından kimlik doğrulayıcı başarısına | %64 |
| Kimlik doğrulayıcıdan açık oturuma | %89 |

Uçtan uca on Android kullanıcısından birinden azı cihazlar arası girişi tamamlamaktadır.

Corbado'nun 2026 karşılaştırması, 2026'nın ilk çeyreği üretim trafiğinden, şöyledir.

| Platform | Başarı oranı | Cihazlar arası gerektiren pay |
|---|---|---|
| iOS web | %85 ile %95 | %0 ile %5 |
| Android web | %70 ile %85 | %5 ile %10 |
| macOS web | %70 ile %85 | %10 ile %15 |
| Windows 10 ile 11 web | %45 ile %60 | %40 ile %65 |

Bilinen cihazda, yani hatırlanan ya da yerel geçiş anahtarında başarı %95 ile %99'dur. Bilinmeyen cihazda, yani önce tanımlayıcı akışında %55 ile %95'tir.

Metodoloji şeffaflığı sınırlıdır; Corbado kendi müşteri trafiğini kullanmakta ile ülke ve dikey kırılımlar ücretli katmandadır. Ancak Windows'un felaket olduğu yönü Google huni verisiyle tutarlıdır ile teknik olarak açıklanabilirdir; Windows 10'da Bluetooth ve hibrit taşıma eksikliği vardır.

Neden başarısız olduğu şudur: hibrit taşıma kullanıcıdan iki donanımı, bir kamerayı, bir radyoyu ile daha önce hiç görmediği bir zihinsel modeli koordine etmesini istemektedir. Bluetooth yoksa, tarayıcı davranışı platforma göre değişiyorsa ya da kurumsal ağ yolu kısıtlıysa kullanıcı yalnızca jenerik bir zaman aşımı görmektedir.

Bir doğrulanamayan nokta vardır: FIDO Alliance'ın 2024 ile 2025 kullanıcı testlerinin katılımcıların yaklaşık yarısının telefonu almaya gitmekten caydığını bulduğu iddiası ikinci elden aktarılmakta ile FIDO'nun kendi yayınında doğrulanamamaktadır.

### 2.5 Sinyal API'si, WebAuthn üçüncü seviye, hangi kullanıcı deneyimi problemini çözmektedir

| Yöntem | Çözdüğü problem | Kritik uyarı |
|---|---|---|
| Bilinmeyen kimlik bilgisi sinyali | Sunucuda silinen bir kimlik bilgisini geçiş anahtarı sağlayıcısı hâlâ önermekte ile başarısız giriş denemeleri oluşmaktadır. Başarısız denemeden sonra çağrılmakta ile sağlayıcı yereldeki kaydı silmektedir | Oturum kapalıyken çağrılması güvenlidir; tek bir kimlik bilgisi tanımlayıcısına referans vermekte ile kullanıcının kaç geçiş anahtarı olduğunu sızdırmamaktadır |
| Tüm kabul edilen kimlik bilgileri sinyali | Kullanıcı ayarlarda geçiş anahtarı silince sağlayıcı listesi tutarsız kalmaktadır | Asla kısmi bir listeyle çağrılmamalıdır; eksik kimlik bilgileri gizlenmekte ile meşru girişler bloklanmaktadır, boş liste tüm geçiş anahtarlarını gizlemektedir. Yalnızca doğrulanmış kullanıcı için ile tam listeyle çağrılmalıdır |
| Mevcut kullanıcı detayları sinyali | Kullanıcı adı ya da görünen ad değişince sağlayıcı metadata'sı eskimektedir | Kullanıcının sağlayıcı içindeki elle düzenlemeleri otoriter kabul edilmekte ile bağlı taraf bunu ezememektedir |

Destek Chrome 132 ile Edge 132'dedir, Ocak 2025. Safari 26 destekleyici sinyaller vermiş ancak gerçeklememiştir. Firefox görüş bildirmemiştir. Google parola yöneticisi üçünü de desteklemekte ile üçüncü taraf eklentiler kendi karar vermektedir.

Bu doğrudan hangi cihazda geçiş anahtarım var ile geçiş anahtarını sildim ama hâlâ görünüyor problemlerinin ilacıdır. Numaralandırma açısından da önemlidir: bilinmeyen kimlik bilgisi sinyali bilinçli olarak sızıntısız tasarlanmıştır, tüm kabul edilenleri sinyalleyen yöntem ise değildir; bu yüzden kimlik doğrulama gerektirmektedir.

### 2.6 Geçiş anahtarıyla parolanın bir arada olması ile varsayılan yap hamleleri

Google Ekim 2023'te geçiş anahtarlarını kişisel hesaplar için varsayılan yapmıştır; kullanıcılar mümkün olduğunda parolayı atla seçeneğini açık görmektedir.

Microsoft 1 Mayıs 2025'te yeni hesapları varsayılan olarak parolasız yapmıştır; hesaplar hiç parola kaydetmeden açılmakta ile mevcut kullanıcılar ayarlardan parolayı silebilmektedir.

Entra tarafında parola kutusu Microsoft yönetimli kiracılarda varsayılan olmaktan çıkmakta ile tam dağıtım Haziran 2026 sonudur. Bu tarih ikincil kaynaklardandır ile Microsoft'un birincil duyurusunda doğrulanamamıştır.

FIDO'nun resmî desen kütüphanesi iki zorunlu desen tanımlamaktadır: hesap ayarları içinde geçiş anahtarı oluşturma, görme ile yönetme; ile geçiş anahtarıyla giriş artı diğer yöntemlere zarif bir yedek yol. İsteğe bağlı desenler hesap kurtarmadan sonra geçiş anahtarı oluşturma, cihazlar arası giriş, kısa mesaj tek kullanımlık şifreyi devre dışı bırakma, önce geçiş anahtarıyla hesap oluşturma, geçiş anahtarı silme ile platformlar arası giriştir.

Araştırma süreci şöyledir: kullanıcı deneyimi çalışma grubu 32 şirketten 128 kişiden oluşmakta, yıllık olarak Ocak ile Mayıs arasında çalışmakta ile 60 ile 90 dakikalık birebir uzaktan görüşmeler yapmaktadır; katılımcılar ABD'de 18 ile 70 yaş arasındadır. 2023 araştırması kör ile az gören, ekran okuyucu kullanan katılımcıları içermekteydi.

---

## 3. Çok faktörlü kimlik doğrulama deneyimi ile güvenlik takasları

### 3.1 Çok faktörlü yorgunluk ile anlık bildirim bombardımanı

Saldırı Lapsus$ ile Yanluowang tarafından Microsoft, Cisco ile Uber ihlallerinde kanıtlanmış durumdadır.

Sayı eşleştirme konusunda Microsoft'un mevcut durumu, 13 Şubat 2026 güncellemesiyle, şudur.

Sayı eşleştirme tüm kimlik doğrulama uygulaması anlık bildirimlerinde etkindir. Zorunludur ile kapatılamamaktadır; kullanıcılar devre dışı bırakamamaktadır. Kapsamı çok faktörlü doğrulama, kendin yap parola sıfırlama, birleşik kayıt, federasyon adaptörü ile ağ politika sunucusu uzantısıdır. Kapsam dışı olanlar Apple ile Android giyilebilir cihazlardır; kullanıcı telefonu kullanmak zorundadır. Aynı cihaz istisnası vardır: kullanıcı Teams ya da Outlook gibi Microsoft mobil uygulamalarında kimlik doğrulama uygulamasıyla aynı cihazda giriş yapıyorsa evet ile hayır yeterlidir. Gerekçe açıkça belirtilmektedir: istem yalnızca girişi başlatan cihazda gösterildiği için artan bir risk bulunmamaktadır. Tarayıcılarda sayı girmek zorunludur. Eski bir kimlik doğrulama uygulaması sürümü kimlik doğrulamanın çalışmaması demektir; yumuşak bir geçiş yoktur. Kullanımdan kaldırılmış sunucu ürününde desteklenmemektedir.

Argus için doğrudan uygulanabilir kural şudur: anlık bildirim onayında ekranla cihazın eşleştiği tespit edilebiliyorsa sayı eşleştirme gereksizdir; edilemiyorsa zorunludur. Bu, Microsoft'un gerekçelendirdiği ile ölçtüğü bir ayrımdır.

CISA da sayı eşleştirmeyi ayrı bir bilgi notuyla önermektedir.

Bir doğrulanamayan nokta vardır: sayı eşleştirmenin canlı müşteri ortamlarında çok faktörlü yorgunluk saldırılarını ortadan kaldırdığı iddiası ikincil kaynaklarda dolaşmakta ancak Microsoft'un birincil yayınında sayısal karşılığı bulunamamaktadır.

### 3.2 Uyarlanabilir ile riske dayalı çok faktörlü doğrulamanın kullanıcı deneyimi etkisi

En iyi birincil kaynak akademiktir: Wiefling, Dürmuth ile Lo Iacono'nun ACSAC 2020'deki riske dayalı kimlik doğrulamanın kullanılabilirlik ile güvenlik algıları üzerine çalışması, arXiv 2010.00339.

Metodolojisi gruplar arası bir laboratuvar çalışmasıdır; 65 katılımcı, iki riske dayalı varyant, bir iki faktörlü varyant ile yalnızca parola koşulu bulunmaktadır. Bulgusu şudur: riske dayalı kimlik doğrulama, incelenen iki faktörlü varyantlardan daha kullanılabilir algılanmaktadır; yalnızca paroladan daha güvenli, iki faktörlüyle karşılaştırılabilir güvenlikte algılanmaktadır. Daha az zaman alıcı olarak algılanmaktadır. Yazarlar bu yaklaşıma özgü kullanılabilirlik problemleri de gözlemleyip azaltma önerileri vermektedir.

Bu, alandaki tek ciddi hakemli kullanılabilirlik verisidir. Küçük örneklem, laboratuvar ortamı ile 2020 tarihi sınırlarıdır; ancak satıcı içeriğinden kat kat güvenilirdir.

Bir doğrulanamayan nokta vardır: uyarlanabilir çok faktörlü doğrulamanın istem sayısını yüzde kaç azalttığına dair üretim verisi bulunamamıştır. Satıcı kaynaklarındaki haftada kullanıcı başına üç istemin altı gibi göstergeler hedef değerlerdir, ölçüm değildir.

### 3.3 Beni hatırla, nasıl güvenli gerçeklenmelidir

Microsoft'un konumu ile ölçülmüş takası, 13 Şubat 2026 güncellemesiyle şöyledir. En önemli cümle tüm sık sık yeniden doğrula sezgisini tersine çevirmektedir.

> "Asking users for credentials often seems like a sensible thing to do, but it can backfire. If users are trained to enter their credentials without thinking, they can unintentionally supply them to a malicious credential prompt."

Varsayılan giriş sıklığı 90 günlük kayan bir penceredir. Çok faktörlü doğrulamayı hatırla ayarı bir ile 365 gün arasında yapılandırılabilmekte ile kullanıcı belirli bir süre boyunca tekrar sorma seçeneğini işaretlediğinde kalıcı bir çerez konmaktadır. Oturumu açık tut ayrı bir kalıcı çerezdir; hem birinci hem ikinci faktörü hatırlamakta ile yalnızca tarayıcı istekleri için geçerlidir. En kısıtlayıcı politika kazanmaktadır: oturumu açık tut ile 14 günlük çok faktörlü hatırlama birlikteyse kullanıcı 14 günde bir yeniden doğrulamaktadır. Microsoft, çok faktörlü hatırlamadan koşullu erişim giriş sıklığına göçü önermektedir; birinci ya da ikinci kademe lisans varsa yalnızca koşullu erişim politikaları kullanılmalıdır. Bir uyarı vardır: çok faktörlü hatırlamayı 90 günden kısa ayarlamak Office istemcileri için istem sayısını artırmaktadır. Oturum, bilgi teknolojileri politikası ihlalinde, yani parola değişimi, uyumsuz cihaz ya da hesabın devre dışı bırakılmasında otomatik iptal edilmektedir; asıl güvenlik mekanizması budur, süre değil. Microsoft'un kendi tavsiyesi 90 gündür; bu ikincil kaynaktan aktarılmıştır.

Auth0'ın gerçeklemesi şöyledir: çerez tabanlıdır. Boşta kalma zaman aşımı varsayılanı yedi gündür, bir saatle 30 gün arasında ayarlanabilmektedir. Azami ömür varsayılanı 30 gündür, bir saatle 90 gün arasında ayarlanabilmektedir. İki katmanlıdır, yani boşta kalma artı mutlak; doğru desen budur. Yönetim API'sindeki koruma ayarları uç noktasıyla ile eylemler içindeki tarayıcıyı hatırlamaya izin ver bayrağıyla kontrol edilmektedir. Auth0'ın yasal uyarısı şudur: müşteriler, beni hatırla oturum davranışı ömrünü değiştirmekten kaynaklanan güvenlik duruşu zayıflamasından sorumludur.

Argus için sentez şudur: çerez artı boşta kalma zaman aşımı artı mutlak ömür artı politika olayında zorunlu geçersizleştirme. Politika olayları parola değişimi, çok faktörlü yöntem değişimi, cihaz uyumsuzluğu ile yönetici iptalidir. Auth0'ın yedi ile 30 gün varsayılanları makul bir başlangıç noktasıdır; Microsoft'un bir ile 365 gün aralığı fazla geniştir.

### 3.4 Yükseltilmiş kimlik doğrulama, RFC 9470

RFC 9470, Eylül 2023, yazarları Auth0 ve Okta'dan Vittorio Bertocci ile Ping'den Brian Campbell'dır.

Çözdüğü problem şudur: yetkilendirme sunucusu yetkilendirme anında bildiğine göre karar vermektedir; ancak API, isteğin riskli olup olmadığını istek anında öğrenmektedir.

Mekanizması şöyledir: kaynak sunucu 401 ile birlikte kimlik doğrulama yetersiz hata kodunu bir kimlik doğrulama başlığında döndürmektedir. İki meydan okuma parametresi bulunmaktadır: kimlik doğrulama gücünü belirten bağlam sınıfı değerleri ile tazeliği belirten azami yaş; ikisi de OIDC yetkilendirme isteği parametrelerini yeniden kullanmaktadır. İstemci, kullanıcı aracısını bu parametrelerle yetkilendirme sunucusuna yönlendirmektedir.

Kritik ayrım şudur: bağlam sınıfı değerleri tavsiye niteliğindedir, azami yaş zorlanabilirdir. OIDC'ye göre sunucu bağlam sınıfı değerlerini karşılamayı deneyebilir ancak azami yaş aşıldığında yeniden kimlik doğrulamayı denemek zorundadır.

Kullanıcı deneyimine yansıması şudur: kullanıcı akışın ortasında, örneğin bir para transferini onaylarken, aniden yeniden doğrulamaya atılmaktadır. Argus'ta bunun kullanıcıya neden olduğunu açıklayan bir ekran gerekmektedir; aksi hâlde kimlik avından ayırt edilememektedir. Microsoft'un yukarıdaki kullanıcıyı düşünmeden kimlik bilgisi girmeye alıştırma uyarısı tam da buraya bakmaktadır.

---

## 4. Barındırılan girişle gömülü girişin karşılaştırması

### 4.1 Barındırılanın neden daha güvenli olduğu, birincil kaynak argümanları

Okta'nın resmî konumu şudur: çoğu tümleştirme için Okta barındırmalı bileşen önerilmektedir. Yönlendirme XSS yüzeyini azaltmakta ile güvenlik güncellemelerini Okta yönetmektedir. Gömülü yaklaşım güvenlikte hafif bir risk artışı getirmektedir; Okta doğru gerçeklemeyi garanti edememekte ile uygulamanızdaki XSS saldırıları çalınmış giriş kimlik bilgileriyle sonuçlanabilmektedir. Gömülüyle kaybedilenler uygulamalar arası otomatik çoklu oturum açma, Okta kontrollü politika güncellemeleri ile kod değişikliği olmadan yeni özelliklere erişimdir. Okta'nın barındırılan bileşeni en yüksek kimlik güvenliği seviyeleri için önerilen yöntem olarak tanımlanmaktadır.

Auth0'ın konumunda temel argüman otomatik güncellemedir: Auth0 giriş deneyimine güvenlik güncellemelerini şeffaf biçimde teslim etmekte, gömülüde güncellemeleri siz dağıtmaktasınız. Ayrıca yerleşik uygulamalar arası çoklu oturum açma vardır.

Gömülünün somut ile belgelenmiş kırılganlığı kökenler arası kimlik doğrulamadır. Bu, üçüncü taraf çerezlere bağımlıdır. Auth0'ın kendi ifadesiyle modern tarayıcılar, yani Firefox, akıllı izleme önlemeli Safari ile Chromium tabanlı tarayıcılar, üçüncü taraf çerezleri varsayılan olarak kısıtlamakta ya da engellemektedir. Sonuç, kökenler arası kimlik doğrulama için üçüncü taraf çerezlere dayanan web uygulamalarının o tarayıcılarda başarısız olabilmesidir. Çözüm, uygulamayla kiracının aynı üst düzey alan adında olmasıdır; böylece çerez birinci taraf olmaktadır. Yalnızca kullanıcı adı ile parola dizin doğrulaması için çalışmaktadır; sosyal ile kurumsal federasyon zaten yönlendirme kullanmaktadır.

Yani gömülü giriş 2026'da yalnızca özel alan adıyla ayakta durmaktadır; ki bu zaten barındırılana doğru bir adımdır.

Gerçek riskler sentez olarak şunlardır: kimlik bilgisi uygulama koduna değmekte ile uygulamadaki her XSS bir kimlik bilgisi hırsızlığı olmaktadır; kullanıcı artık doğru kökende miyim kontrolünü yapamamakta ile kimlik avı direnci kaybolmaktadır; ile WebAuthn bağlı taraf kimliği uygulama kökenine bağlanmakta ve çok kökenli dağıtımda geçiş anahtarları parçalanmaktadır.

### 4.2 RFC 10017, tarayıcı tabanlı uygulamalar en iyi uygulama belgesi, Ağustos 2026

BCP 212, yani RFC 10017, yazarları A. Parecki, P. De Ryck ile D. Waite; 49 sayfadır ile IETF OAuth çalışma grubundandır.

Önerilen mimariler şunlardır.

| Mimari | Bölüm | Değerlendirme |
|---|---|---|
| Ön yüz için arka uç | 6.1 | En güvenlidir. Arka uç gizli bir istemcidir, token'ları sunucuda tutmakta ile tüm kaynak isteklerini vekillemektedir. Token hırsızlığını ile saldırganın taze token almasını engellemekte ancak istemci ele geçirmeyi engelleyememektedir |
| Token aracılı arka uç | 6.2 | Orta yoldur. Arka uç gizli istemci olarak token almakta ancak erişim token'ını tarayıcıya vermektedir. Yenileme token'ı hırsızlığını engellemekte, erişim token'ını XSS'e açık bırakmaktadır |
| Tarayıcı tabanlı OAuth istemcisi | 6.3 | Tüm OAuth tarayıcıdadır ile açık istemcidir. Saldırı yüzeyini anlamlı ölçüde artırmaktadır ile iş uygulamaları, hassas uygulamalar ve kişisel veri işleyen uygulamalar için önerilmemektedir |

Diğer kritik hükümler şunlardır. Tarayıcı tabanlı istemciler örtük yetki tipini kullanmamalıdır. Kaynak sahibi parola kimlik bilgileri önerilmemektedir. OAuth akışını bir servis işçisinde yürütmek önerilmemektedir. Tarayıcı istemcileri yenileme token'ı kullanıyorsa rotasyon ya da gönderen kısıtlama zorunludur ile sunucu yenileme token'ı ömrünü ilk verilme ömrüyle sınırlamalıdır. Hiçbir depolama yaklaşımı en tehlikeli saldırıyı, yani saldırganın bağımsız bir OAuth akışı başlatarak taze token almasını engellememektedir. DPoP çalınan bir erişim token'ının dışa aktarımını engellemekte ancak saldırganın kendi anahtar çiftiyle taze token almasını engellememektedir. Birinci taraf aynı alan adlı uygulamalar bölümünde şu denmektedir: ön yüzle arka uç aynı alan adındaysa OAuth gereksiz olabilir; basit uygulamalar oturum yönetimi kavramını OAuth ile değiştirerek gereksiz yere karmaşıklaştırılmaktadır. Çerez tabanlı oturum yeterlidir.

Argus için bu bölüm doğrudan yönetim konsolumuz ile barındırılan giriş sayfamız hakkındadır. Aynı alan adındaki birinci taraf arayüzler için OAuth değil doğrudan oturum çerezi kullanılmalıdır. Tek sayfa uygulaması müşterilerimize ön yüz için arka uç önerilmeli ile dokümantasyonumuzda iş uygulamaları ve kişisel veri işleyen uygulamalar için önerilmez ifadesi alıntılanmalıdır.

### 4.3 Yerel uygulamalar: RFC 8252 hâlâ geçerli midir? Evet, bir nüansla

RFC 8252, Ekim 2017, yerel uygulamalardan OAuth yetkilendirme isteklerinin yalnızca harici bir kullanıcı aracısı, yani sistem tarayıcısı üzerinden yapılmasını istemektedir; gömülü web görünümü kimlik avına açıktır, çünkü uygulama arayüzü kontrol etmekte ile kimlik bilgisini yakalayabilmektedir.

Nüans, RFC 8252 yazarlarından William Denniss'in Kasım 2024 tarihli açıklamasıdır ile 2026'da hâlâ geçerlidir: RFC'nin hedefi yerel uygulama içindeki gömülü OAuth akışıydı; politika, web görünümünü bir gerçekleme detayı olarak kullanan tarayıcı uygulamalarına uygulanmak üzere yazılmamıştır. Ayrım şudur: gömülü web görünümü OAuth akışının sonunda kapsayıcı yerel uygulama bir OAuth token'ı almakta ile umulur ki oturum çerezini atmaktadır; uygulama içi tarayıcıda ise kullanıcı sağlayıcıda oturumu açık kalmakta ile bu, o tarayıcının çerez kavanozunda herhangi bir tarayıcı gibi kalıcı olmaktadır.

### 4.4 Birinci taraf uygulamalar taslağı dengeyi nasıl değiştirmektedir

`draft-ietf-oauth-first-party-apps-04`, yayın 1 Temmuz 2026, standartlar yolu, son kullanma 2 Ocak 2027.

Bir yetkilendirme meydan okuması uç noktası tanımlamaktadır: birinci taraf istemci kullanıcıdan yetkilendirmeyi yerel bir deneyimle alabilmektedir, yani tamamen tarayıcısız bir OAuth deneyimi; yalnızca beklenmedik, yüksek riskli ya da hatalı durumlarda tarayıcıya devretmektedir.

Şartnamenin kendi güvenlik uyarıları Argus için karar vericidir.

1. Kötü niyetli uygulama taklidi: sahte bir uygulama kullanıcıyı kimlik bilgisini doğrudan kendisine vermeye kandırabilmektedir.
2. Kullanıcı kafa karışıklığı: kullanıcının kimlik bilgisini girmesi beklenen yeni bir yer yaratıldığı için güvenli giriş konusunda kullanıcı eğitmek zorlaşmaktadır.
3. İstemci taklidi: güçlü istemci kimlik doğrulaması olmadan saldırgan meşru uygulamayı taklit edebilmektedir; şartname işletim sistemi kanıtlama API'lerini önermektedir.
4. Kimlik bilgisi doldurma: doğrudan kimlik bilgisi işleme yeni bir kaba kuvvet vektörüdür; oturum başına hız sınırlama önerilmektedir.
5. Sunucu her aşamada kendi risk değerlendirmesine göre yönlendirme tabanlı akış talep edebilmektedir; istemci bunu ele almak zorundadır.
6. Şartname yalnızca birinci taraf uygulamalar için ile sunucunun istemciye yüksek derecede güven duyduğu durumlarda kullanılmak üzere tasarlanmıştır.

Yorum şudur: bu taslak, barındırılan girişin kimlik avı direncini bilinçli olarak feda etmekte ile karşılığında kullanıcı deneyimi almaktadır. Argus'ta destekleneceksek istemci kanıtlaması zorunlu olmalı ile varsayılan kapalı olmalıdır.

---

## 5. Markalama, özelleştirme ile çok kiracılık

### 5.1 Üç ürünün yaklaşımı

| Ürün | Motor | Kapsam | Kısıt |
|---|---|---|---|
| Keycloak | Apache FreeMarker | Beş tema tipi: giriş, hesap, yönetim, e-posta ile karşılama. Alan başına seçilmekte ile istemci giriş temasını ezebilmektedir | Tema bir JAR olarak sağlayıcılar dizinine ya da temalar klasörüne konmaktadır |
| Auth0 evrensel giriş | Liquid sayfa şablonu | İstemin etrafındaki içerik, yani giriş kutusu ile çok faktörlü meydan okuma. Tüm sayfalarda aynı şablon kullanılmaktadır | Özel alan adı zorunludur; yalnızca yönetim API'siyle güncellenebilmektedir; Liquid'de JavaScript desteği sınırlıdır ile belirli bir baş etiketi zorunludur |
| Okta | Giriş bileşeni artı özel HTML, CSS ile JavaScript | Yönetim konsolunda bir kod düzenleyici bulunmakta ile marka başına yapılandırılmaktadır | İçerik güvenlik politikası zorlanmaktadır; zorlanan ile yalnızca rapor modları vardır |

### 5.2 Özelleştirmenin güvenlik maliyeti, evet gerçek bir vektördür

Keycloak'ın kendi dokümanlarından en sert uyarı şudur.

> "Themes contain FreeMarker templates that the server renders at runtime, so a malicious template can run code as the Keycloak process."

Önerisi temaların yalnızca güvenilir kaynaklardan kurulması ile temalar dizinine yazma erişiminin kısıtlanmasıdır.

Bu, çok kiracılı bir kimlik sağlayıcı için ölümcül bir bulgudur. Keycloak'ın tema modeli kiracının sağladığı özelleştirme için tasarlanmamıştır; sunucu tarafı şablon çalıştırma, kiracının uzaktan kod çalıştırma alması demektir. Argus çok kiracılı olacaksa Keycloak'ın bu modelini kopyalamamalıdır.

Auth0'ın yaklaşımında Liquid kasıtlı olarak bir şablonlama dilidir, bir betik dili değildir. Auth0'ın kendi güvenlik notu şudur: adreslerdeki değerler kullanılmadan önce JavaScript ile veri şemalarına karşı doğrulanmalıdır ile karakter izin listesi her işleme bağlamında tüm XSS riskini ortadan kaldırmamaktadır.

Okta'nın yaklaşımı bir içerik güvenlik politikası izin listesidir. Giriş ile hata sayfalarından hangi adreslere bağlantı verilebileceği kontrol edilmektedir. Bu listede olmayan tüm dış kaynaklar güvenilmez sayılmakta ile görünmelerine izin verilmemektedir. Zorlanan ile yalnızca rapor modları artı bir ihlal rapor adresi bulunmaktadır. Gerekçe bu sayfalara potansiyel olarak kötü amaçlı kod girmesini önlemektir. Meta etiketiyle politika özelleştirmesi önerilmemekte ile yönetim konsolundaki güvenilir kaynaklar listesi kullanılmalıdır. En fazla 20 adres ile HTTP başlık boyutu limiti uyarısı arama sonuç özetinde geçmiş ancak Okta'nın çekilen sayfasında doğrulanamamıştır. Bir not gerekmektedir: Okta'nın kendi bileşeni çalışma zamanında satır içi betik ile stil blokları enjekte etmekte ile bu, sıkı bir politikayı ihlal edebilmektedir; bunun için bir tek kullanımlık değer parametresi bulunmaktadır. Yani bileşenin kendisi politikayla gerilim içindedir.

Argus için model şudur: Okta'nın izin listesiyle Auth0'ın betiksiz şablonlama dilinin birleşimi. Kiracıya asla sunucu tarafı şablon çalıştırma verilmemelidir. Kiracının sağladığı JavaScript varsa ayrı bir kökende kum havuzuna alınmış bir çerçeve dışında kabul edilmemelidir.

### 5.3 Kiracı başına özel alan adı ile geçiş anahtarı bağlı taraf kimliği sonucu

Bu, çok kiracılıkta en sert kısıttır.

Okta'nın belgelediği kurallar şunlardır. Bağlı taraf kimliği, çağıran kökenin etkin alan adı ya da onun kaydedilebilir bir alan adı soneki olmalıdır. Bir giriş alt alan adı kökeni için hem o alt alan adı hem apeks alan adı geçerlidir; üst düzey alan adının kendisi geçerli değildir, yani etkin üst düzey alan artı bir alt sınırdır. Okta özel alan adı standart kurulumla zaten doğrulanmıştır. Kök alan adı için altında doğrulanmış bir özel alan adı ile ayrı bir metin kaydı doğrulaması gerekmektedir. Bağlı taraf kimliği değişirse mevcut geçiş anahtarı kayıtları silinmemekte, sistemde kalmakta ancak tarayıcı bunları girişte sunmamaktadır; kullanıcı yeniden kaydolmak zorundadır. Auth0 tarafında da aynıdır: bağlı taraf kimliği özelleştirilince diğer alan adlarındaki tüm geçiş anahtarları kullanılamaz hâle gelmektedir ile özel alan adı geçiş anahtarlarından önce yapılandırılmalıdır.

Çok alan adlı çözüm ilgili köken istekleridir. Bağlı taraf, kendi kimlik alan adı altında iyi bilinen bir WebAuthn dosyası barındırmaktadır. Dosya, o kimlik kapsamında geçerli kökenlerin dizisini içermektedir. Köken kimlikle eşleşmezse istemci bu uç noktayı sorgulamaktadır. Etiket limiti şudur: WebAuthn en az beş benzersiz etiket desteğini şart koşmaktadır ile beşten fazlasını destekleyen bilinen bir istemci yoktur; beş pratik azamidir. Etiket başına onlarca ülke alan adı olabilmektedir. Çalışma zamanı tespiti istemci yetenekleri çağrısındaki ilgili kökenler bayrağıyla yapılmaktadır. Okta'da kök alan adı kimliği için dosyayı siz barındırmakta, özel alan adı için Okta barındırmaktadır.

Argus için sonuç şudur: kiracı başına özel alan adıyla geçiş anahtarı birlikte tasarlanmalıdır, sonradan eklenememektedir. Kiracı sayısı beş etiketi aşacaksa, ki aşacaktır, her kiracı kendi bağlı taraf kimliğini almalıdır; paylaşımlı kimlikle ilgili kökenler ölçeklenmemektedir. Bu da kiracı alan adı değiştirirse geçiş anahtarlarının öleceği gerçeğini kalıcı kılmaktadır; kiracı katılımında alan adı kararı geri dönülemez olarak işaretlenmelidir.

### 5.4 Yerelleştirme

Auth0 evrensel giriş tarafında durum şöyledir: bölgesel varyantlar dahil 80'den fazla dil desteklenmektedir. Sağdan sola diller Arapçanın üç varyantı, İbranice, Farsça ile Urducadır; sağdan sola dil desteği erken erişimdedir, WCAG 2.2 ikinci seviye uyumu gerektirmekte ile HTML şablonlarında yön özniteliği bulunmalıdır. Dil seçim önceliği arayüz yerel ayarı parametresi, kiracıda etkin diller, tarayıcının kabul edilen dil başlığı ile varsayılandır. Etkin yerel ayarlar yönetim API'siyle belirlenmektedir. Sınırları şunlardır: arayüz yerel ayarı parametresi yalnızca OAuth 2.0'da çalışmakta, SAML ile WS-Federation'da çalışmamaktadır; yukarı akış sağlayıcılara iletilmemektedir; ile rıza sayfasındaki kapsamlar yerelleştirilememektedir.

Keycloak tarafında yerelleştirme alan ayarlarından alan başına açılmaktadır. Yerel ayar öncelik zinciri yedi kademelidir: kullanıcı arayüz seçimi, kullanıcı profil tercihi, istemci arayüz yerel ayarı, tarayıcı çerezi, kabul edilen dil başlığı, alan varsayılanı ile İngilizce. Bir yerel ayar parametresi de desteklenmekte ile seçim kalıcı bir çerezde saklanmaktadır. Alana özgü metinler yerelleştirme sekmesinden tema dosyaları değiştirilmeden ezilebilmektedir. Varsayılan gelen yerel ayar listesi dokümanda açıkça listelenmemektedir ile doğrulanamamıştır.

Argus için ders şudur: Auth0'ın yedi kademeli yedek zinciri ile kiracıya özgü metin ezme modeli, yani dosya değil veri modeli, doğru desendir. Sağdan sola desteğinin erken erişimde bırakılması Auth0'ın bile 2026'da zorlandığını göstermektedir; Argus'ta baştan yön desteğiyle başlamak daha ucuzdur.

---

### 5.5 Betiksiz özelleştirmenin mekanizması, akış düğümü sözleşmesi

Buraya kadarki bölüm kiracıya betik ya da şablon çalıştırtmanın neden reddedildiğini kurmaktadır. Reddedilen şeyin yerine ne konacağı ise açıkta kalmaktadır; 19. karar ile 28. sonraki karar bir yasak ile bir ürün kararıdır, bir mekanizma değildir. Mekanizma Ory Kratos'ta çalışan hâliyle mevcuttur.

Ne yaptığı şudur. Bir kendi kendine hizmet akışı başlatıldığında Kratos JSON döndürmektedir. Yanıt bir arayüz nesnesi taşımakta, bu nesne bir eylem adresi, bir HTTP yöntemi ile bir düğüm dizisi içermektedir. İstemci formu bu bilgiyle kendisi çizmektedir. Kimlik şemasında tanımlanan alanlar doğrudan form girdi öğelerine ayrıştırılmaktadır. Referans arayüz gerçeklemesi giriş, kayıt, ayarlar, kurtarma ile doğrulama akışlarının tamamını aynı sözleşmeyle kapsamaktadır. Kaynak Ory'nin kendi kendine hizmet dokümanı ile referans arayüz deposudur, erişim 13 Eylül 2026.

Argus için önemi şudur. Sunucu hiçbir şey çizmemektedir; yalnızca ne çizileceğini bildiren tipli bir yapı döndürmektedir. Şablon motoru ortadan kalkmakta, dolayısıyla 19. kararın gerekçesindeki uzaktan kod çalıştırma riski bir azaltma değil yapısal bir imkânsızlık hâline gelmektedir. Kiracı markalaması ile alan düzeni, sunucuda hiçbir kiracı kodu koşmadan istemci tarafında yapılabilmektedir.

İkinci bir kazanç daha vardır ile 8. bölümün 30. maddesine bağlanmaktadır: akış bir nesne olduğunda o nesne kalıcılaştırılabilmekte ile yeniden yüklenebilmektedir. Askıya alınabilir kimlik doğrulama, ayrı bir mekanizma değil bu sözleşmenin doğal sonucudur.

Üç sınır not edilmelidir. Birincisi, düğüm sözleşmesi bir güvenlik sınırı değildir; istemcinin hangi düğümü çizdiği sunucunun kararını değiştirmemelidir. Sunucu, istemcinin göndermediği ya da uydurduğu alanları reddetmelidir. İkincisi, sözleşme bir genel arayüz olduğu için sürüm uyumluluğu gerektirmektedir; düğüm tipi eklemek geriye dönük uyumludur, düğüm tipi kaldırmak değildir. Üçüncüsü, barındırılan girişin kendisi bu sözleşmenin bir tüketicisidir; yani Argus'un kendi giriş sayfası, kiracının yazabileceği bir istemciyle aynı yüzeyi kullanmalıdır, aksi hâlde sözleşme test edilmeden çürümektedir.

## 6. Hata mesajları ile kurtarma deneyimi

### 6.1 OAuth hataları kullanıcıya ne zaman gösterilmektedir

RFC 6749'un 4.1.2.1 bölümü şunu söylemektedir.

> "the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI."

Yani yönlendirme adresi ya da istemci kimliği geçersizse yönlendirme yasaktır ile kullanıcıya doğrudan hata gösterilmelidir. Diğer tüm hatalar yönlendirmeyle istemciye dönmektedir.

Yetkilendirme uç noktası hata kodları geçersiz istek, yetkisiz istemci, erişim reddedildi, desteklenmeyen yanıt tipi, geçersiz kapsam, sunucu hatası ile geçici olarak kullanılamaz değerleridir.

Pratik ayrım şudur. Kullanıcıya gösterilenler geçersiz yönlendirme adresi ile istemci kimliği, ki yönlendirilememektedir; erişim reddedildi, ki kullanıcının kendi kararıdır; ile geçici olarak kullanılamaz durumudur. İstemciye yönlendirilen ancak kullanıcıya ham gösterilmeyenler geçersiz kapsam, desteklenmeyen yanıt tipi ile geçersiz istektir; bunlar geliştirici hatalarıdır ile kullanıcıya uygulama yanlış yapılandırılmış tarzı bir mesaj artı bir korelasyon kimliği gösterilmelidir. RFC 10017'nin birinci taraf aynı alan adı bölümüne göre bu karmaşıklığın çoğu zaten gereksizdir.

### 6.2 Bu hesap kilitli mesajıyla jenerik mesajın karşılaştırması

OWASP kilitli ile devre dışı hesaplar dahil her durumda aynı mesajı istemektedir. Ayrıca HTTP yanıt kodu farklı olursa jenerik HTML'e rağmen sızıntı devam etmektedir; kod da aynı olmalıdır. Zamanlama da eşitlenmelidir.

Keycloak'ın pratiği bunu doğrulamaktadır: kaba kuvvetle kilitlenen kullanıcı giriş denediğinde geçersiz kullanıcı adı ya da parola görmektedir; geçersiz kullanıcı ile geçersiz parolayla aynı mesajdır ile saldırganın hesabın devre dışı olduğunu anlamaması içindir. Keycloak kaba kuvvet korumasını yalnızca parola, tek kullanımlık şifre ile kurtarma kodlarına uygulamaktadır.

Çatışma OWASP tarafından açıkça kabul edilmektedir: jenerik mesajlar kullanıcı deneyimi sürtünmesi yaratmakta ile meşru kullanıcı kafası karışıp uygulamayı terk edebilmektedir. Öneri kritikliğe göre karar vermek ile jenerik mesajı bir bot kontrolüyle birleştirmektir.

Clerk'ün ürünleşmiş çözümü bu çatışmayı bir yapılandırma boyutuna çevirmektedir; Argus'un alması gereken ders budur.

Auth0'ın katmanları şunlardır: bot tespiti, bot şüphesi olan bir IP'den gelindiğinde bir bot kontrolü adımı tetiklemektedir; şüpheli IP kısıtlaması, çok sayıda hesapta hızlı tanımlayıcı ile parola denemelerini yakalamaktadır; kaba kuvvet koruması tek hesaba tekrarlı denemeleri yakalamaktadır; ihlal edilmiş parola tespiti üçüncü taraf ihlal veritabanlarını kullanmaktadır; ile izleme modu engellemeden yalnızca günlüğe yazmaktadır, ki dağıtım için doğru desendir. Varsayılan eşikler bu sayfada belgelenmemektedir.

### 6.3 Kullanıcı nerede takılmaktadır, gerçek terk verisi

Doğrulanmış olanlar şunlardır. Android cihazlar arası karekod akışında tarayıcı isteminden karekod taramasına geçiş %29'dur; huninin tek büyük kopuş noktasıdır. Windows web'de geçiş anahtarı başarısı %45 ile %60 arasındadır ile girişlerin %40 ile %65'i cihazlar arası akış gerektirmektedir. FIDO'nun 2026 anketine göre kullanıcıların %47'si parola hatırlayamadığında satın almayı terk etme eğilimindedir; bu bir anket beyanıdır, davranış ölçümü değildir.

Doğrulanamayanlar şunlardır ile satıcı içeriğidir, kullanılmamalıdır: parola tabanlı akışlarda tamamlanmanın %60 ile %75, parola artı kısa mesajlı iki faktörlüde %50 ile %65, parolasızda %85 ile %95 olduğu iddiası; parola giriş adımında %15 ile %25 terk olduğu iddiası; hesap oluşturmaya zorlanınca %24 terk olduğu iddiası; giriş bilgilerini unuttuğu için %21 satın alma terki olduğu iddiası; ile ABD tüketicilerinin %46'sının kimlik doğrulama başarısızlığı yüzünden işlemi tamamlamadığı iddiası. Bunların hiçbiri için birincil bir metodoloji bulunamamıştır.

Sonuç şudur: genel giriş hunisi terki için güvenilir, kamuya açık bir veri yoktur. Argus'un kendi telemetrisini kurması şarttır; koşullu arayüzün sessiz başarısızlığı nedeniyle bu telemetri özel bir tasarım gerektirmektedir.

---

## 7. Erişilebilirlik

### 7.1 WCAG 2.2'nin erişilebilir kimlik doğrulama kriteri, ne yasaklamaktadır

W3C'nin ikinci seviye erişilebilir kimlik doğrulama kriteri şunu söylemektedir.

> "Authentication that relies on a cognitive function test does not block access to content or functionality."

Bir bilişsel işlev testi, adımlardan biri şunlardan en az birini sağlamadıkça istenememektedir: bilişsel işlev testine dayanmayan bir alternatif; testi tamamlamaya yardımcı olan bir mekanizma; testin yalnızca nesne tanımaktan ibaret olması; ya da kullanıcının kendi sağladığı metin dışı içeriği tanımak olması.

Bilişsel işlev testinin tanımı şudur: kullanıcının bilgiyi hatırlamasını, işlemesini ya da kopyalamasını gerektiren bir görev; yani ezberleme, kopyalama, doğru yazım, hesaplama ile bulmaca çözme. İsim, e-posta ile telefon numarası gibi yaygın tanımlayıcılar bilişsel işlev testi sayılmamaktadır.

Doğrudan yanıtlar şunlardır.

Parolanızın üçüncü karakterini girin türü bir istem yasaktır. Doküman açıkça şunu söylemektedir: kopyalanan metinle girdi alanı arasında farklı bir format kullanmak kullanıcıyı kopyalamaya zorlamakta ile başka bir yöntem mevcut değilse bu kriteri geçememektedir.

CAPTCHA tamamen yasak değildir, koşulludur. İkinci seviyede nesne tanıma ile kişisel içerik istisnadır; yani arabaları seç tipi bir CAPTCHA ikinci seviyede geçmektedir. Ancak üçüncü seviye bu istisnaları kaldırmaktadır; nesne ile görüntü tanıma orada da yasaktır.

Parola yöneticisi ya da otomatik doldurmayı engellemek bir başarısızlıktır. Site, kullanıcı aracısı ile parola yöneticilerinin alanları otomatik doldurmasına izin vermelidir. Aktif olarak engelleniyorsa ile bir alternatif yoksa sayfa kriteri karşılamamaktadır. Girdi amacı ile ad, rol ve değer kriterleriyle birlikte değerlendirilmelidir.

Yapıştırmayı engellemek bir başarısızlıktır: kopyala yapıştır, kopyalamayı önlemek için güvenilebilecek bir yöntemdir.

Tek kullanımlık şifre ile iki faktörlü doğrulamada şu geçerlidir: bir doğrulama kodunun elle kopyalanmasını gerektiren bir hizmet uyumlu değildir. Kullanıcı kodu yapıştırabilmelidir. Donanım cihazı, biyometri ile işletim sistemi kimlik doğrulaması bilişsel işlev testi değildir.

Çok adımlı akışlarda tüm adımlar uyumlu olmalıdır.

WebAuthn yeterli bir tekniktir; geçiş anahtarı desteklemek bu kriteri otomatik karşılamaktadır.

W3C'nin CAPTCHA notu, 16 Aralık 2021 tarihli grup taslağı, şunu söylemektedir: görme, işitme ile bilişsel engelli kullanıcılar için bir bariyerdir; ses alternatifleri de bozulmuş olduğu için anlaşılmazdır. Önerilen alternatifler etkileşimsiz yöntemlerdir, yani istenmeyen ileti süzme, iş kanıtı, sezgisel yöntemler, bal küpü ile hız sınırlama; etkileşimsiz çözümler hiçbir erişilebilirlik zorluğu çıkarmamaktadır. Ayrıca WebAuthn ile kriptografik kişilik kanıtlaması, Privacy Pass belirteçleri ile federe kimlik önerilmektedir.

Argus için doğrudan tasarım kısıtı şudur: OWASP'ın jenerik hata artı CAPTCHA önerisiyle erişilebilirlik kriteri çatışmaktadır. Çözüm W3C'nin kendi önerisidir: CAPTCHA yerine etkileşimsiz bot savunması, yani hız sınırlama, iş kanıtı, bal küpü ile cihaz sinyalleri kullanılmalıdır; bunlar hem erişilebilir hem numaralandırmaya karşı etkilidir.

### 7.2 Avrupa Birliği erişilebilirlik yasası

Kapsamı şudur: bilgisayarlar ile işletim sistemleri, bankamatikler, biletleme ile giriş makineleri, akıllı telefonlar, dijital televizyon ekipmanı, telefon hizmetleri, görsel işitsel medya erişimi, hava, otobüs, demiryolu ile su yolu yolcu taşıma hizmetleri, bankacılık hizmetleri, elektronik kitaplar ile elektronik ticaret. Üye devletlere ulusal hukuka aktarma tarihi Haziran 2022'dir.

28 Haziran 2025'te yürürlüğe girmiş midir sorusunun cevabı evettir. Ancak bu tarih yalnızca ikincil kaynaklardan doğrulanabilmiştir; EUR-Lex'e üç farklı adres üzerinden erişilememiş, boş içerik dönmüştür; dolayısıyla ilgili madde metni birincil kaynaktan doğrulanamamıştır.

İkincil kaynaklara göre uygulama 28 Haziran 2025'te başlamış ile 27 üye devletin tamamı aktarmıştır. 2025'in ikinci yarısında çoğu ulusal otorite kapasite kurmuş, bazıları denetim yapıp resmî bildirim çıkarmıştır. Kapsadığı kesim özel sektördür: elektronik ticaret, bankacılık, telekomünikasyon, ulaşım ile Avrupa Birliği tüketicilerine hizmet veren bulut platformları, şirketin merkezi nerede olursa olsun. Muafiyet yalnızca mikro işletmeleredir, yani 10'dan az çalışanı ile iki milyon avronun altında cirosu olanlara.

Mikro işletme muafiyetinin tam metni ile uyumlu Avrupa standardıyla ilişkisi birincil kaynaktan doğrulanamamıştır.

Argus'a etkisi şudur: Argus bir bulut kimlik sağlayıcı olarak, Avrupa Birliği tüketicilerine hizmet veren müşterilerinin giriş akışını sağlamaktadır. Müşterimiz kapsamdaysa bizim giriş sayfamız da fiilen kapsamdadır, çünkü kullanıcının gördüğü ekran bizimdir. Bu, ikinci seviye erişilebilirlik uyumunu bir güzel olur özelliği değil bir satış engeli yapmaktadır. Auth0'ın sağdan sola desteğini bu uyuma şartlaması da aynı baskının işaretidir.

### 7.3 Ekran okuyucuyla WebAuthn deneyimi

FIDO Alliance ile Passkey Central'ın denetimi şu test matrisini kullanmaktadır: Windows'ta Chrome ile iki farklı ekran okuyucu, Windows'ta Edge, Mac'te Safari ile ekran okuyucu ile telefon varyantları.

Bulguları şunlardır. İyi haber şudur: geçiş anahtarı kayıt ile giriş prosedürleri tutarlı biçimde erişilebilirdir; platform yönetimi sürtünmeyi azaltmaktadır. Birinci kötü haber otomatik doldurmadır: koşullu arayüz canlı dağıtımlarda tutarsız gerçeklenmiştir ile ekran okuyucu kullanıcıları için tutarsız bir deneyim doğurmaktadır. Doğru davranış ekran okuyucuya bir açılır pencere bulunduğunun duyurulmasıdır, böylece kullanıcı aşağı ok tuşuyla gezinebileceğini bilmektedir. İkinci kötü haber karekodlardır: hareket ya da görme kısıtlı kişiler için bariyer oluşturmaktadır, çünkü cihazı sabit tutmak ya da kodu görsel olarak bulmak gerekmektedir. Üçüncü kötü haber, erişilebilirlik kusurlarının çoğunlukla sitenin genelinde yaygın olmasıdır, yalnızca kimlik doğrulamada değil.

FIDO'nun 2023 kullanılabilirlik araştırması kör ile az gören, ekran okuyucu kullanan katılımcıları içermekteydi.

Argus için sonuç şudur: karekod tabanlı cihazlar arası akış tek yol olamaz; hem %29 dönüşüm hem erişilebilirlik nedeniyle. Her zaman bir alternatif, yani e-posta sihirli bağlantısı, tek kullanımlık şifre ya da kurtarma kodu sunulmalıdır.

---

## 8. Argus için giriş akışı tasarım kararları

1. Önce tanımlayıcı varsayılan olmalı ancak numaralandırma davranışı kiracı başına yapılandırılabilir bir mod olmalıdır, tek bir davranış değil. Clerk'ün toplu koruma ile katı koruma ikilisi modellenmelidir. Katı modun neyi imkânsız kıldığı, yani kullanıcı adı tanımlayıcısı, parolayla başlangıç stratejisi ile yalnızca davetle katılım, dokümante edilmelidir.

2. Tanımlayıcı adımının çıktısı sabitlenmelidir: aynı HTTP durumu, aynı gövde boyutu ile aynı gecikme. OWASP hem hızlı çıkış zamanlama sızıntısını hem jenerik HTML'e rağmen farklı HTTP kodunun sızdırdığını açıkça belirtmektedir. Kilitli ile devre dışı hesap dahil tek bir mesaj verilmelidir.

3. Önce tanımlayıcıyı atlayan bir geçiş anahtarıyla giriş yap yolu her zaman sunulmalıdır. Boş kimlik bilgisi listesiyle keşfedilebilir kimlik bilgisi kullanıldığında sunucuya hiçbir tanımlayıcı sızmamakta ile numaralandırma yüzeyi sıfırlanmaktadır.

4. Ev alanı keşfi varsayılan olarak kapalı tutulmalı; açıksa hedef kiracı kullanıcıya onaylatılmalıdır. Microsoft otomatik hızlandırmaya karşı tavsiye vermekte, çünkü FIDO'yu engellemekte ile misafirleri kırmaktadır; Nisan 2023'ten beri bir alan adı onay penceresi göstermekte ile bunu güvenlik sertleştirmesi olarak tanımlamaktadır.

5. İstemcinin gönderdiği alan adı ya da giriş ipucu benzeri parametreler kiracı politikasını ezmemelidir. Microsoft'ta alan adı ipucu keşif politikasını ezmekte ile bunu düzeltmek için ayrı bir politika katmanı gerekmiştir. Argus'ta baştan doğru sıra kurulmalıdır: kiracı politikası istemci ipucundan önce gelmelidir.

6. Koşullu arayüz desteklenmeli ancak asla tek yol yapılmamalıdır; her zaman açık bir geçiş anahtarı düğmesi ile bir iptal denetleyicisi bulunmalıdır. Koşullu arayüz Windows 10, eski ChromeOS ile uygulama içi tarayıcılarda sessizce hiçbir şey göstermemekte ile site bunu ölçememektedir.

7. Telemetri koşullu arayüzün körlüğünü telafi edecek şekilde tasarlanmalıdır. Açılır listenin görünüp görünmediği, boş gelip gelmediği ya da kullanıcının yok sayıp saymadığı ayırt edilememektedir. Bunun yerine istemci yetenekleri sonucu, tanımlayıcı alanına odaklanma olayı ile koşullu sözün çözülüp çözülmediği ayrı ayrı ölçülmelidir.

8. Platform tespit edilmeli ile cihazlar arası karekod son çare yapılmalıdır, özellikle Windows'ta. Windows web'de başarı %45 ile %60 ile girişlerin %40 ile %65'i cihazlar arası akış gerektirmektedir; Android'de tarayıcı isteminden karekod taramasına geçiş yalnızca %29'dur. Windows kullanıcısına geçiş anahtarı tek yol olarak dayatılmamalıdır.

9. WebAuthn sinyal API'si birinci günden gerçeklenmelidir; ancak tüm kabul edilen kimlik bilgilerini sinyalleyen yöntem yalnızca doğrulanmış kullanıcı için ile tam listeyle çağrılmalıdır. Bilinmeyen kimlik bilgisi sinyali oturum kapalıyken güvenlidir, yani tek bir kimlik bilgisi tanımlayıcısı taşımakta ile sayı sızdırmamaktadır; başarısız bir geçiş anahtarı denemesinden sonra çağrılmalıdır. Kısmi liste meşru geçiş anahtarlarını gizlemektedir. Destek Chrome ile Edge 132 ve üstündedir.

10. Anlık bildirim onayında sayı eşleştirme zorunlu yapılmalı ile tek istisna aynı cihaz tespiti olmalıdır. Microsoft'ta artık tüm anlık bildirimlerde zorunludur ile devre dışı bırakılamamaktadır. Aynı cihazda başlatılan girişte evet ile hayıra izin verilmekte ile bunun riski artırmadığı gerekçelendirilmektedir. Giyilebilir cihazlar kapsam dışıdır.

11. Beni hatırla iki katmanlı yapılmalıdır: boşta kalma zaman aşımı artı mutlak ömür, ile politika olayında zorunlu iptal. Auth0'da boşta kalma yedi gün, mutlak 30 gündür. Microsoft'ta bir ile 365 gün arası tek katman ile en kısıtlayıcı politika kazanır kuralı vardır. Asıl güvenlik mekanizması süre değil olay tabanlı iptaldir: parola değişimi, çok faktörlü yöntem değişimi, cihaz uyumsuzluğu ile yönetici iptali.

12. Agresif yeniden kimlik doğrulamadan kaçınılmalıdır; Microsoft bunu bir güvenlik riski olarak belgelemektedir. Kullanıcılar düşünmeden kimlik bilgisi girmeye alıştırılırsa bunları istemeden kötü amaçlı bir isteme verebilmektedir. Entra varsayılanı 90 günlük kayan bir penceredir. Sık istem kimlik avına yardım etmektedir.

13. RFC 9470 yükseltmesi desteklenmeli ile bağlam sınıfı değerleriyle azami yaş arasındaki zorlama farkı doğru uygulanmalıdır. Bağlam sınıfı değerleri tavsiyedir, azami yaş zorunludur. Yükseltme ekranında kullanıcıya neden yeniden doğrulama istendiği açıklanmalıdır; aksi hâlde on ikinci maddedeki kimlik avı riski kendi elinizle yaratılmaktadır.

14. Barındırılan, yani yönlendirmeli giriş tek desteklenen üretim modu yapılmalıdır; gömülü desteklenecekse özel alan adı zorunlu kılınmalıdır. Okta'ya göre gömülüde uygulamanızdaki XSS saldırıları çalınmış giriş kimlik bilgileriyle sonuçlanabilmekte ile barındırılan en yüksek kimlik güvenliği seviyeleri için önerilen yöntemdir. Auth0'da kökenler arası kimlik doğrulama üçüncü taraf çerezlere bağlıdır ile modern tarayıcılarda başarısız olabilmektedir; çözüm aynı üst düzey alan adıdır.

15. Tek sayfa uygulaması müşterilerine ön yüz için arka uç resmî öneri yapılmalı ile dokümantasyonda RFC 10017'nin kendi ifadesi alıntılanmalıdır. Bu mimari en güvenlidir; tarayıcı içi OAuth istemcisi iş uygulamaları, hassas uygulamalar ile kişisel veri işleyen uygulamalar için önerilmemektedir. Örtük yetki tipi yasaktır. Yenileme token'ı varsa rotasyon ya da gönderen kısıtlama zorunludur.

16. Argus'un kendi yönetim konsolu ile barındırılan girişi için OAuth değil doğrudan oturum çerezi kullanılmalıdır. RFC 10017'nin ifadesiyle basit uygulamalar oturum yönetimini OAuth ile değiştirerek gereksiz yere karmaşıklaştırılmaktadır.

17. Yerel geliştirme kitinde sistem tarayıcısı zorunlu olmalıdır; birinci taraf uygulamalar akışı desteklenecekse varsayılan kapalı olmalı ile istemci kanıtlaması zorunlu tutulmalıdır. RFC 8252 hâlâ geçerlidir. İlgili taslağın kendi güvenlik bölümü uygulama taklidi, kullanıcı kafa karışıklığı, istemci taklidi ile kimlik bilgisi doldurma risklerini saymakta ile işletim sistemi kanıtlama API'lerini önermektedir; sunucu her aşamada tarayıcıya düşürebilmelidir.

18. Kiracıya asla sunucu tarafı şablon çalıştırma verilmemelidir; Keycloak'ın FreeMarker modeli kopyalanmamalıdır. Keycloak kendi dokümanında kötü niyetli bir şablonun süreç olarak kod çalıştırabileceğini söylemektedir. Bu, kiracının sağladığı temalarda uzaktan kod çalıştırma demektir.

19. Özelleştirme betiksiz bir şablonlama diliyle ile bir içerik güvenlik politikası izin listesiyle sınırlanmalı; yalnızca rapor modu sunulmalıdır. Auth0 Liquid'i karmaşık betikler değil şablonlama olarak konumlandırmakta ile yine de karakter izin listesinin her işleme bağlamında tüm XSS riskini ortadan kaldırmadığı uyarısını vermektedir. Okta zorlanan ile yalnızca rapor modları artı bir ihlal rapor adresi sunmaktadır; dağıtım için doğru desendir.

20. Kiracı özel alan adı geçiş anahtarlarından önce zorunlu kılınmalı ile alan adı değişimi geri dönülemez olarak işaretlenmelidir. Okta'ya göre bağlı taraf kimliği değişince eski kayıtlar silinmemekte ancak tarayıcı bunları girişte sunmamaktadır; kullanıcı yeniden kaydolmak zorundadır. Auth0 aynıdır. İlgili kökenler mekanizması pratikte beş etiketle sınırlıdır ile çok kiracılıkta ölçeklenmemektedir; her kiracı kendi bağlı taraf kimliğini almalıdır.

21. Geçersiz yönlendirme adresi ya da istemci kimliğinde yönlendirme yapılmamalı ile kullanıcıya hata gösterilmelidir; diğer OAuth hataları kullanıcıya ham gösterilmemelidir. RFC 6749 geçersiz yönlendirme adresine otomatik yönlendirmeyi yasaklamaktadır. Geliştirici hataları için kullanıcıya yalnızca korelasyon kimliği taşıyan nazik bir mesaj verilmelidir.

22. CAPTCHA yerine etkileşimsiz bot savunması kullanılmalıdır; hem erişilebilirlik hem etkinlik açısından. W3C'ye göre etkileşimsiz çözümler hiçbir erişilebilirlik zorluğu çıkarmamaktadır: hız sınırlama, iş kanıtı, bal küpü, sezgisel yöntemler ile WebAuthn ile kişilik kanıtlaması. CAPTCHA ikinci seviyede nesne tanıma istisnasıyla geçmekte ancak üçüncü seviyede geçmemektedir.

23. Yapıştırma asla engellenmemeli, parola yöneticisi otomatik doldurması asla bloklanmamalı ile tek kullanımlık şifre alanları tek alanlı ve yapıştırılabilir yapılmalıdır. İlgili kriter, elle kopyalama gerektiren bir doğrulama kodunun uyumlu olmadığını söylemektedir; belirli karakterleri girin türü bir istem doğrudan başarısızdır. Otomatik tamamlama ile girdi amacı kriterine uyulmalıdır.

24. İkinci seviye erişilebilirlik uyumu bir satış gereksinimi olarak ele alınmalıdır, kozmetik olarak değil. Erişilebilirlik yasası 28 Haziran 2025'ten beri uygulanmaktadır; elektronik ticaret, bankacılık ile Avrupa Birliği tüketicilerine hizmet veren bulut hizmetleri kapsamdadır, şirket merkezi neresi olursa olsun; muafiyet yalnızca 10 kişiden az çalışanı ile iki milyon avronun altında cirosu olan mikro işletmeleredir. Auth0 bile sağdan sola desteğini bu uyum şartına bağlamaktadır.

25. Koşullu arayüzde ekran okuyucuya bir açılır pencere bulunduğu duyurulmalı ile karekod tek yol yapılmamalıdır. FIDO denetimine göre geçiş anahtarı kayıt ve giriş prosedürleri tutarlı biçimde erişilebilirdir ancak otomatik doldurma tutarsız gerçeklenmiştir ile karekodlar hareket ya da görme kısıtlı kullanıcılar için bir bariyerdir.

26. Yerelleştirme çok kademeli bir yedek zinciriyle ile kiracı seviyesinde metin ezmeyle kurulmalı ile yön desteği baştan konulmalıdır. Keycloak yedi kademeli bir zincir ile tema dosyası değiştirmeden alana özgü ezme sunmaktadır. Auth0 80'den fazla dil sunmakta ancak sağdan sola hâlâ erken erişimdedir ile arayüz yerel ayarı yukarı akış sağlayıcılara iletilmemektedir; Argus bunu iletmeyi hedeflemelidir.

27. FIDO'nun iki zorunlu deseni ürün gereksinimi olarak kabul edilmelidir: hesap ayarlarında geçiş anahtarı oluşturma, görme ile yönetme; ile geçiş anahtarıyla giriş artı zarif bir yedek yol. Yedek yok bir seçenek değildir.

28. Saldırı korumasına bir izleme modu eklenmelidir. Auth0 bot tespiti, şüpheli IP kısıtlaması, kaba kuvvet koruması ile ihlal edilmiş parola tespitinin her birini engellemeden yalnızca günlüğe yazan bir modda çalıştırabilmektedir. Kiracı bir korumayı açmadan önce etkisini ölçebilmelidir.

29. Kiracı özelleştirmesi bir şablon motoruyla değil bir düğüm sözleşmesiyle verilmelidir. Sunucu ne çizileceğini bildiren tipli bir yapı döndürmeli, çizimi istemci yapmalıdır; mekanizma 5.5'tedir. On dokuzuncu madde bir yasaktır, bu madde onun yerine konan şeydir. Sunucu, istemcinin göndermediği ya da uydurduğu alanları reddetmelidir; düğüm sözleşmesi bir güvenlik sınırı değildir.

30. Askıya alınabilir ile yeniden başlatılabilir kimlik doğrulama birinci sınıf modellenmelidir. Bu bir yapılandırma kolaylığı değil bir ürün gereksinimidir: sihirli bağlantı, bant dışı onay ile geri kanal kimlik doğrulaması akışın ortasında duraklayıp başka bir cihazda ya da başka bir zamanda sürdürülmesini gerektirmektedir. Ping'in 2026'da eklediği geri kanal yolculukları tam olarak bunu yapmaktadır, iki yeni düğümle. Argus'un tipli durum makinesi bu durumu modellemek zorundadır ile modellemezse sihirli bağlantı akışları durum makinesinin dışında, yani denetlenmeyen bir yan kanalda gerçeklenmektedir. Askıya alınan durum için dört kural konmalıdır: durum sunucuda tutulmalı ile istemciye verilen tek şey opak bir tanıtıcı olmalıdır; tanıtıcı tek kullanımlık olmalıdır; askı penceresinin mutlak bir ömrü olmalıdır; ile sürdürme, askıya alma anındaki güvence seviyesini yükseltmemelidir, yani askıya alınan bir akış sürdürüldüğünde eksik faktörler hâlâ eksiktir.

31. Durum makinesi ile token üretimi arasındaki arayüz tipli tek bir değer olmalıdır, serbest bir talep haritası değil. Değer hangi yöntemin kullanıldığını, ulaşılan güvence seviyesini, bağlanan kimlik doğrulayıcıyı ile kiracı bağlamını taşımalıdır; token üretimi kimlik doğrulama yolunun kendisine erişememelidir. Desen PingFederate'in bağdaştırıcıdan token üreticisine giden politika sözleşmesinde ile AD FS'in üç aşamalı talep işleme hattında mevcuttur; ikisinin de ayrıntıları birincil kaynaktan doğrulanmamıştır. Kazanç §1 §5.1'de açıklanmıştır.

32. On sekizinci maddedeki yasak şablona özgü okunmamalıdır. Kiracının sunucu sürecinde kod çalıştırması üç şablon olmayan yüzeyde de gerçekleşmektedir: WSO2 Identity Server'ın uyarlanabilir kimlik doğrulama betikleri, Zitadel'in eylemleri ile authentik'in ifade politikaları. Üçü de kiracının yazdığı kodu kimlik sağlayıcı sürecinde koşturmaktadır. Yasak bu yüzeyleri de kapsamalı ile 19. karar buna göre genişletilmiştir.

33. Akış kompozisyonu kiracıya açılmamalıdır, askıya alınabilirlik ise açılmalıdır. Bu ikisi yolculuk ürünlerinde tek bir özellik gibi sunulmaktadır ancak farklı şeylerdir. Kompozisyon, yani adım sırasını kiracının değiştirebilmesi, Keycloak'ın 40744 numaralı hatasının sınıfını üretmektedir ile reddedilmiştir. Bir çekince kayda geçirilmelidir: reddin gerekçesi tek bir üründeki tek bir hatadır ile Ping'in on yıllık yolculuk ürününün aynı hata sınıfını üretip üretmediği incelenmemiştir. Üçüncü bir tasarım noktası da çürütülmeden bırakılmıştır; Janssen'in Agama'sı akışı yapılandırma değil bir dilde yazılmış kaynak metin yapmakta ile bu, atlatma hatasını çalışma zamanından derleme zamanına taşıyabilmektedir. Argus ikinci bir dil ile onun derleyicisini bakım yüzeyi olarak kabul etmediği için reddetmektedir; gerekçe "akış motoru bunu engelleyemez" değildir.

---

## 9. Doğrulanamayanlar

Benimseme ile dönüşüm rakamları tarafında şunlar doğrulanamamıştır.

1. FIDO'nun 2026 raporundaki tüm yüzdeler anket verisidir, yani 11.000 tüketici ile 1.400 karar verici; telemetri değildir. Geçiş anahtarı etkinleştirdim oranı bir beyandır, bir ölçüm değildir.
2. FIDO geçiş anahtarı endeksinin dönüşüm artışı ile başarı oranı rakamları dokuz üyeye yapılan gizli bir anketten toplanmıştır; bağımsız bir denetim yoktur.
3. Corbado'nun platform bazlı başarı oranlarının metodoloji ayrıntıları ücretli katmandadır ile örneklem bileşimi bilinmemektedir.
4. Google'ın 2025 huni verisi Corbado üzerinden ikinci eldendir; orijinal sunum doğrulanamamıştır.
5. Google ile Microsoft rakamları birincildir ancak seçim yanlılığı içermektedir; geçiş anahtarı kuran kullanıcı zaten aktif ile cihazı elinde olan kullanıcıdır.
6. Parola akışlarında tamamlanma oranları, hesap zorunluluğunda terk, şifre unutunca terk ile kimlik doğrulama başarısızlığından terk iddialarının hepsi satıcı içeriğidir ile birincil bir metodolojisi yoktur; kullanılmamalıdır.
7. Koşullu arayüzün dönüşüm etkisine dair bağımsız bir sayısal veri yoktur. Benimsemedeki en büyük kaldıraç olduğu iddiası doğrulanamamıştır.
8. FIDO'nun 2024 ile 2025 kullanıcı testinde katılımcıların yaklaşık yarısının telefonu almaya gitmekten caydığı iddiası bir aktarımdır ile FIDO'nun kendi yayınında bulunamamıştır.

Ürün ile tarih detayları tarafında şunlar doğrulanamamıştır.

9. Entra'da parola kutusunun Haziran 2026 sonuna kadar kaldırılacağı ikincil kaynaklardandır ile Microsoft'un birincil duyurusunda doğrulanamamıştır.
10. Okta içerik güvenlik politikasındaki azami 20 güvenilir adres ile HTTP başlık boyutu limiti arama özetinde geçmiş ancak çekilen sayfada doğrulanamamıştır.
11. Auth0 saldırı koruması varsayılan eşikleri belgelenmemiştir.
12. Keycloak'ın varsayılan gelen yerel ayar listesi resmî dokümanda açıkça listelenmemektedir.
13. Microsoft'un çok faktörlü hatırlama için 90 gün önerisi ikincil kaynaktandır; çekilen dokümanda bu sayı geçmemekte, doküman koşullu erişim giriş sıklığına göçü önermektedir.
14. Sayı eşleştirmenin canlı ortamlarda çok faktörlü yorgunluk saldırılarını ortadan kaldırdığı iddiasının Microsoft'un birincil yayınında sayısal bir karşılığı bulunamamıştır.

Mevzuat tarafında şunlar doğrulanamamıştır.

15. Erişilebilirlik yasasının uygulama tarihi, kapsamı, mikro işletme muafiyeti ile harmonize standartlar maddeleri birincil metinden doğrulanamamıştır; EUR-Lex'e üç farklı adres biçimiyle erişilememiş ile boş içerik dönmüştür. 28 Haziran 2025 tarihi ile eşik değerleri yalnızca ikincil kaynaklardandır. Hukuki bir karar vermeden önce birincil kaynaktan doğrulanmalıdır.
16. Yasanın ilgili Avrupa standardı ile erişilebilirlik kılavuzuyla resmî ilişkisi birincil kaynaktan doğrulanamamıştır.

Tarihsel tarafta bir nokta doğrulanamamıştır.

17. Google'ın 2015 önce tanımlayıcı geçişine ait resmî bir tasarım gerekçesi bulunamamıştır.
