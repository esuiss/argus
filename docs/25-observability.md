# §25 — Gözlemlenebilirlik ve ölçekte denetim

Bu bölüm `ARGUS.md` dosyasının 25. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§25 §X` referansları aynı anlamdadır.

Tarih 8 Eylül 2026'dır. Toplam yaklaşık 55 arama ile çekme yapılmıştır. Tüm iddialar kaynaklıdır; doğrulanamayanlar sonda listelenmiştir.

---

## 0. En kritik bulgu: ön ölçümünüz literatürle birebir örtüşmektedir

Olay başına özet zincirli denetim günlüğü ölçümündeki sekiz bağlantının bir bağlantıya eşit olması bir tesadüf değildir. Yapısal olan yalnızca şudur: tek bir doğrusal zincirde ardışık zincir özetlerinin hesaplanması arasında seri bağımlılık vardır. Ölçülen saniyede yaklaşık 5.900 değeri bu uygulamaya ile donanıma özgüdür, evrensel bir tavan değildir; §6'nın 4.4 bölümüne bakınız. İki bağımsız kaynak seri bağımlılığı doğrulamaktadır.

Crosby ile Wallach'ın USENIX Security 2009'daki kurcalama kanıtlı günlükleme için verimli veri yapıları makalesi indirilmiş ile metni çıkarılmıştır. İkinci tablosu, tek çekirdek Intel Core2 Duo 2,4 GHz, SHA-1 ile 1024 bitlik DSA ile şunları vermektedir.

| Adım | İşlemci payı | İzole hız |
|---|---|---|
| A, sistem günlüğü mesajını ayrıştırma | %2,4 | Saniyede 81.000 olay |
| B, olayı günlüğe ekleme | %2,6 | Saniyede 66.000 olay |
| C, taahhüt üretme, yani Merkle kökü | %11,8 | Saniyede 15.000 olay |
| D, taahhüdü imzalama | %83,3 | Saniyede 2.100 olay |
| Üyelik kanıtı, yerellikle | — | Saniyede 8.600 |
| Üyelik kanıtı, yerellik olmadan | — | Saniyede 32 |

Uçtan uca saniyede 1.750 olaydır, yani her olayda imza atılırsa; imzalar başka bir çekirdeğe ya da donanım güvenlik modülüne devredilirse saniyede 10.500 olaydır, ki saniyede 1,9 megabayt ile haftada 1,1 terabayttır. Makaleden doğrudan alıntılar şunlardır: imzalar bir eklemenin çalışma zamanı maliyetinin %80'inden fazlasını oluşturmaktadır; ile olayları günlüğe eklemek, taahhüt üretip imzalamaktan yirmi kat hızlıdır.

Makale tam olarak sizin kararınızı önermektedir.

> *"The logger may amortize the costs of generating a signed commitment over many inserted events... Under light load, the logger could sign every commitment and insert 1,750 events per second. With increasing load, the logger might sign one in every 16 commitments to obtain an estimated insert rate of 17,000 events per second. Clients will still receive signed commitments within a fraction of a second, but several clients can now receive the same commitment."*

Yani yaklaşık 10 kat iş hacmi artışı vardır ile karşılığındaki tek takas birden fazla istemcinin aynı taahhüdü almasıdır. Ölçülen düz yalnızca ekleme değeri, ki §6'nın 4.4 bölümündedir ile yeniden üretim beklemektedir, bu tabloya oturmaktadır: A ile B adımları teorik tavanı vermekte ile gerçek veritabanı senkronizasyon maliyetiyle ölçülen değer makul kalmaktadır.

Ajan uçuş kaydedici çalışması, arXiv 2609.01931, 1 Eylül 2026, beş kademeli bir ayrıştırma yapmaktadır; örneklem 10.000 olaydır.

| Yapılandırma | Medyan gecikme | 95. yüzdelik | 99. yüzdelik | Olay başına bayt |
|---|---|---|---|---|
| Temel, düz JSON | 20,3 mikrosaniye | 26,2 | 30,7 | 272 |
| Şema, deterministik CBOR | 6,0 mikrosaniye | 8,2 | 10,0 | 476 |
| Artı zincir, SHA-256 özet zinciri | 48,2 mikrosaniye | 57,2 | 76,8 | 477 |
| Artı Merkle, 100 olaylık dönem | 48,8 mikrosaniye | 60,8 | Yaklaşık 4,1 milisaniye | 512 |
| Artı tam, zincir üstü çıpalama | 47,6 mikrosaniye | 60,2 | Yaklaşık 30 milisaniye | 512 |

Yani özet zinciri tek başına medyan gecikmeyi altı mikrosaniyeden 48 mikrosaniyeye, yani sekiz kat çıkarmaktadır. Merkle yığınlama bunun üstüne neredeyse hiç medyan maliyet eklememektedir; yalnızca 99. yüzdelikte dönem sınırında yaklaşık dört milisaniyelik bir tepe vardır. Bu, özet zincirinin pahalı, Merkle denetim noktasının bedava olduğu tezinin bağımsız doğrulamasıdır.

Kritik bir ek bulgu vardır: özet zincirinin asıl maliyeti ekleme değil doğrulamadır. Crosby ile Wallach şunu söylemektedir: klasik bir özet zinciri, 80 milyon olaylık bir günlükte rastgele seçilmiş bir olayın bulunduğunu kanıtlamak için 800 megabaytlık bir iz gerektirebilirken, prototipleri aynı semantikle üç kilobaytlık bir kanıt döndürmektedir.

| | Özet zinciri | Atlama listesi | Geçmiş ağacı |
|---|---|---|---|
| Ekleme | Sabit zamanlıdır | Sabit zamanlıdır | Logaritmanın karesi mertebesindedir |
| Artımlı kanıt boyutu | Doğrusaldır | Doğrusaldır | Logaritmanın karesi mertebesindedir |
| Üyelik kanıtı boyutu | Doğrusaldır | Doğrusaldır | Logaritmanın karesi mertebesindedir |

Yani özet zincirinin sabit zamanlı eklemesi cazip görünmekte ancak denetçi iki anlık görüntü arasındaki her ara olayı taramak zorunda kalmaktadır. Merkle ya da geçmiş ağacı yapısı hem eklemeyi yığınlanabilir kılmakta hem kanıtı logaritmik yapmaktadır. Özet zinciri ölçekte iki kere kaybetmektedir.

---

## 1. Denetim günlüğü standartları ile şemaları

### 1.1 RFC 8417 güvenlik olayı belirteci, bir denetim formatı olarak

Standartlar yolundadır, Temmuz 2018.

İddiaları şunlardır: veren zorunludur, veriliş zamanı zorunludur, benzersiz tanımlayıcı zorunludur ile istemciler tarafından belirli bir belirtecin zaten alınıp alınmadığını izlemek için kullanılabilmektedir, olaylar nesnesi zorunludur ve adresten JSON yüküne bir eşlemedir, izleyici kitle önerilmektedir, özne alanları bulunmaktadır, işlem alanı korelasyon içindir ile olayın gerçekleşme zamanı veriliş zamanından farklıdır.

Kritik semantik sınır şudur: güvenlik olayları taraflar arasında verilen komutlar değildir. Belirteç bir olgu bildirimidir, bir komut değildir. Bu, denetim günlüğü semantiğiyle mükemmel uyumludur.

Denetim için doğrudan destek şudur: bir belirteç denetim amacıyla saklanacaksa, imza onun gerçekliğinin doğrulanması için kullanılabilmektedir. İmza JWS ile atılmakta; gizlilik gerekiyorsa JWE kullanılmaktadır.

Değerlendirme şudur: belirteç, Argus'un dışa yayın formatı olarak mükemmeldir, çünkü paylaşılan sinyal ekosisteminin tamamı bunu konuşmaktadır. Ancak dahilî depolama formatı olarak kötüdür: JWT ile JWS her kayda 700'den fazla bayt base64 ek yükü ile olay başına imza getirmektedir, ki Crosby'nin %83'lük adımıdır. Kanonik ikili biçimde depolanmalı ile belirteç olarak yayımlanmalıdır.

### 1.2 RFC 9967, SCIM belirteç profili

Standartlar yolundadır, Mayıs 2026; çok yenidir. RFC 7643 ile 7644'ü güncellemektedir.

Üç sınıfta 12 olay adresi bulunmaktadır: besleme ekleme ile çıkarma; sağlama tarafında oluşturma, yama, yerleştirme, silme, etkinleştirme ile devre dışı bırakma; ile çeşitli sınıfında eşzamansız yanıt.

Bildirim ile tam varyantı ayrımı önemlidir: bildirim yalnızca değişti demektedir ile kişisel veri yaymamaktadır, tam ise veriyi taşımaktadır. Argus'un denetim yayınında bildirim varyantı varsayılan olmalıdır.

Dayanıklılık şartı şudur: olay alıcıları, belirteçlerin alındığını onaylamadan önce olayların doğrudan ya da dolaylı olarak yerel kurtarma ihtiyaçlarını karşılayacak şekilde kalıcılaştırıldığından emin olmak zorundadır.

Özne tanımlayıcısı kullanımı zorunludur, yani format tipi, kaynak adresi, dış kimlik ile benzersiz kimlik taşınmalıdır.

### 1.3 OpenTelemetry anlamsal sözleşmeleri, kimlik ile kimlik doğrulama durumu

Güncel sürüm 1.44.0'dır.

Kapsanan alanlar genel, sürekli tümleştirme, bulut sağlayıcıları, bulut olayları, veritabanı, istisnalar, işlev olarak hizmet, özellik bayrakları, üretken yapay zekâ, GraphQL, HTTP, mesajlaşma, nesne depoları, uzak yordam çağrısı, sistem, .NET, uygulamalar, Azure, tarayıcı, komut satırı, alan adı sistemi, donanım, mobil, ağ dosya sistemi, geliştirme kiti, çalışma zamanı ile adreslerdir.

Yani kimlik doğrulama, kimlik ile güvenlik olayları için adanmış bir anlamsal sözleşme yoktur. Bu Argus için önemlidir: OpenTelemetry'nin kimlik olayları için hazır bir taksonomisi bulunmamaktadır ile kendi taksonominizi kurmanız ve OCSF'e eşlemeniz gerekmektedir.

Son kullanıcı öznitelikleri hikâyesinin kesin durumu şöyledir.

| Öznitelik | Durum, 1.44 sürümünde |
|---|---|
| Son kullanıcı kimliği | Aktiftir, geliştirme kararlılığındadır ile hassas kişisel veri içermektedir |
| Son kullanıcı takma kimliği | Aktiftir, geliştirme kararlılığındadır; rastgele ile bağlanmamış bir değerdir |
| Son kullanıcı rolü | Kullanımdan kaldırılmıştır; yerine kullanıcı rolleri gelmiştir |
| Son kullanıcı kapsamı | Kullanımdan kaldırılmıştır ile yerine geçen yoktur |
| Kullanıcı kimliği, adı, e-postası, tam adı, rolleri ile özeti | Hepsi geliştirme aşamasındadır, kararlı değildir |

Tarihçe şöyledir: son kullanıcı kimliği bir öneriyle kullanımdan kaldırılıp kullanıcı kimliğine taşınmış; ancak kullanıcı kimliğinin kimlik doğrulanmış mı anonim mi olduğu belirsizliği şikâyet konusu olmuş; ilgili konu bir öneriyle kapanmış ile son kullanıcı kimliği geri getirilmiştir. Şimdi kimliği doğrulanmış son kullanıcı ile takma adlı kullanıcı ayrımı bulunmaktadır.

Pratik sonuç şudur: takma kimlik iz ile metrik yolunda, gerçek kullanıcı kimliği yalnızca denetim günlüğü yolunda kullanılmalıdır. Hiçbiri kararlı değildir; anlamsal sözleşmelere sabit kodlu bağımlılık kurulmamalı ile bir eşleme katmanı konulmalıdır.

OpenTelemetry olay modelinde olay, bir olay adı taşıyan bir günlük kaydıdır. Kural şudur: olay adları dinamik değer içermemelidir; oluşum başına değişen tanımlayıcılar, adlar ya da diğer değerler için öznitelikler kullanılmalıdır. Durumu geliştirme aşamasındadır.

### 1.4 OCSF, en güçlü aday ile büyük bir sürpriz

Güncel sürüm 1.9.0'dır, 3 Ağustos 2026. Sürüm geçmişi 28 Nisan 2025'teki 1.5.0'dan 3 Ağustos 2026'daki 1.9.0'a uzanmaktadır; yılda yaklaşık üç sürümle hızlı hareket eden bir standarttır.

Kimlik ile erişim yönetimi kategorisi, 1.9.0'da, şu sınıfları içermektedir.

| Sınıf | Tanımlayıcı |
|---|---|
| Hesap değişikliği | 3001 |
| Kimlik doğrulama | 3002 |
| Oturum yetkilendirme | 3003 |
| Varlık yönetimi | 3004 |
| Kullanıcı erişim yönetimi | 3005 |
| Grup yönetimi | 3006 |
| Kullanıcı yönetimi | 3007, 1.9.0'da yenidir |
| Rol yönetimi | 3008, 1.9.0'da yenidir |

Kimlik doğrulama sınıfının detayı şöyledir: zorunlu alanlar kategori tanımlayıcısı, sınıf tanımlayıcısı, önem tanımlayıcısı, zaman, metadata ile kullanıcıdır; ayrıca hedef uç nokta ya da servisten biri gerekmektedir. Etkinlik tanımlayıcısı giriş, çıkış, kimlik doğrulama bileti, servis bileti isteği, servis bileti yenileme ile hesap değiştirme değerlerini almaktadır. Anahtar alanlar kimlik doğrulama protokolü, giriş tipi, çok faktörlü bayrağı, oturum, aktör, kaynak uç nokta ile durum tanımlayıcısıdır.

Bir sürpriz vardır: OCSF 1.9.0'ın kayıt bütünlüğü profili, Argus'un tam olarak yaptığı şeyi standartlaştırmıştır. Profil, olayın kendisi üzerinde bir veya daha fazla kriptografik kanıtlama eklemekte ile alana özgü içerikten bağımsız bütünlük, gerçeklik ile inkâr edilemezlik sağlamaktadır. Seksenden fazla olay sınıfına uygulanabilmektedir. Tek özniteliği bir kanıtlama listesidir.

Kanıtlama nesnesinin alanları şunlardır: kanıtlamayı üreten otorite tanımlayıcısı; zincir tanımlayıcısı, ki adli ya da denetim günlüğü gibi yalnızca eklenen bir zincirin tanımlayıcısıdır; parmak izi, ki olayın kanonik serileştirmesinin parmak izidir; önceki olay, ki kurcalama kanıtlı bir zincirdeki bir önceki olaya referanstır; imzalar, ki parmak izi üzerinden hesaplanan bir veya daha fazla dijital imzadır; ile bir benzersiz tanımlayıcı.

Çoklu kanıtlama desteklenmektedir: yazma anındaki bir üretici ile alım anındaki bir aşağı akış işleyicisi bağımsız kanıtlama ekleyebilmektedir.

Yani Argus'un Merkle denetim noktası modeli, bu profille tel uyumlu olarak ifade edilebilmektedir. Her olayda önceki olay alanını doldurmak zorunlu değildir, isteğe bağlıdır; denetim noktası ayrı bir kanıtlama olarak yayımlanabilir. Bu, Argus'un denetim çıktısını doğrudan güvenlik bilgi ve olay yönetimi sistemlerinin anlayabileceği hâle getirmektedir.

Benimseme tarafında AWS Security Lake bu şemayı yerel olarak kullanmakta ile özel kaynaklar şema artı Apache Parquet formatına uymak zorundadır. Yönetim olayları API etkinliği, kimlik doğrulama ya da hesap değişikliği sınıflarına eşlenmektedir. Security Lake şu an daha eski şema sürümlerini kullanmaktadır; yani AWS, standardın en son sürümünün epey gerisindedir. Bu, sürüm uyumluluğunun Argus'ta yapılandırılabilir olması gerektiği anlamına gelmektedir.

### 1.5 CADF, CEF ile LEEF hâlâ alakalı mıdır

CADF, DMTF bulut yönetimi girişimi altında aktif bir standarttır. Pratik kullanımı esas olarak OpenStack kimlik servisiyle sınırlıdır. Bir OpenStack profili mevcuttur. Argus için niştir; OpenStack ekosistemine satılmıyorsa görmezden gelinebilir.

CEF, LEEF ile benzerleri satıcı formatlarıdır. Bir standart evrimi analizine göre CEF basitliği, okunabilirliği, günlük kategorizasyonu ile sistem günlüğü üzerinden kolay aktarılabilirliği nedeniyle yaygın benimsenmiştir; ancak şeması ağ güvenliği merkezliydi ile ağ dışı veriye genişletme mekanizması zorlamaydı. Ayrıca serileştirme odağı hâlâ tek satırlık sistem günlüğündeydi, dünyanın geri kalanı JSON'a geçerken.

Satıcı şemaları, yani Splunk, Elastic, Chronicle ile Microsoft şemaları, satıcıya bağımlılık yaratmaktadır.

OCSF birinci sürümü 2023'te çıkmış ile topluluk güdümlü halef olarak konumlanmıştır.

Karar şudur: OCSF birincil olmalı, CEF ile LEEF yalnızca isteğe bağlı bir çıktı adaptörü olmalıdır; eski güvenlik bilgi ve olay yönetimi müşterileri için yaklaşık 200 satırlık bir biçimlendirici yeterlidir.

### 1.6 NIST SP 800-53 beşinci revizyon denetim ailesi, kimlik sağlayıcı için hangileri bağlayıcıdır

| Kontrol | İçerik | Temel çizgi | Argus'a etkisi |
|---|---|---|---|
| Olay günlükleme | Günlükleme yetenekleri belirlenmeli, hangi olayların ve hangi sıklıkta günlükleneceği tanımlanmalı, gerekçelendirilmeli ile periyodik gözden geçirilmelidir. Örnek olaylar parola değişiklikleri, başarısız girişler ile erişimler, güvenlik ya da mahremiyet özniteliği değişiklikleri, yönetim ayrıcalığı kullanımı, kimlik kartı kullanımı, veri eylem değişiklikleri, sorgu parametreleri ile dış kimlik bilgisi kullanımıdır | Düşük ve üstü | Olay tipi kataloğu yapılandırılabilir olmalıdır, sabit değil |
| İçerik | Altı zorunlu eleman: olay tipi, ne zaman, nerede, kaynak, sonuç ile olayla ilişkili bireylerin veya varlıkların kimliği. Bir geliştirme ek bilgi istemekte, bir başkası kişisel veriyi sınırlamaktadır | Düşük ve üstü | Şema tasarımının asgari sözleşmesidir |
| Koruma | Yetkisiz erişim, değiştirme ile silmeden korunmalıdır; beşinci revizyonda kurcalama olunca alarm eklenmiştir. Geliştirmeleri ayrı fiziksel sistem, kriptografik bütünlük koruması ile yetkili alt kümedir | Orta ve üstü | Merkle ile imza tam olarak kriptografik bütünlük geliştirmesidir; ayrık depolama diğeridir |
| İnkâr edilemezlik | Belirli bir bireyin ya da sürecin tanımlı eylemleri gerçekleştirdiğine dair çürütülemez kanıt gerekmektedir | Yalnızca yüksek | Merkle denetim noktası artı imza bunu karşılamaktadır |
| Denetim kaydı üretimi | Sistemin tanımlı olayları üretme yeteneğidir | Düşük ve üstü | — |

Bağlayıcılık analizi şudur: genel amaçlı bir kimlik sağlayıcı çoğu müşteride orta temel çizgiye düşmektedir; yani kriptografik bütünlük zaten orta seviyededir. İnkâr edilemezlik yalnızca yüksek seviyededir, ancak kimlik sağlayıcı tanım gereği kimlik iddialarının kaynağı olduğu için müşterilerin yüksek seviyeli sistemleri sizin günlüğünüze dayanacaktır. Argus inkâr edilemezliği varsayılan olarak karşılamalıdır; bu, Merkle denetim noktasının imzalanması gerektiği anlamına gelmektedir, çünkü yalnızca özet yeterli değildir.

### 1.7 PCI DSS dördüncü sürüm, onuncu gereksinim

Günlüklenecekler şunlardır: tüm kart sahibi verisi erişimi, kök ya da yönetici yetkisiyle yapılan tüm işlemler, denetim izlerine erişim, geçersiz mantıksal erişim denemeleri, kimlik doğrulama mekanizmalarının kullanımı, denetim günlüğünün başlatılması ile sistem seviyesinde nesne oluşturma ve silme.

Her kayıt en az altı eleman içermelidir: kullanıcı kimliği, olay tipi, tarih ile saat, başarı ya da başarısızlık, olay kaynağı ile etkilenen veri, sistem bileşeni veya kaynak kimliği. Bu, denetim içeriği kontrolüyle neredeyse birebirdir.

Koruma tarafında görüntüleme iş ihtiyacıyla sınırlanmalı, dosyalar yetkisiz değişiklikten korunmalı, değiştirilmesi zor merkezî bir sunucuya yedeklenmeli ile dosya bütünlüğü izleme veya değişiklik tespit yazılımıyla değişiklikte alarm verilmelidir.

Saklama en az 12 aydır ile son üç ay hemen analize hazır olmalıdır. 4.0.1 sürümünde saklama ile gözden geçirme sıklığı hedefli bir risk analiziyle özelleştirilebilmektedir.

Denetim izlerine erişimin kendisinin günlüklenmesi maddesi çok kritiktir ile sıkça atlanmaktadır: Argus'ta denetim günlüğü okuma API'si de bir denetim olayı üretmelidir. Sonsuz döngüye girmemek için üst denetim olayları ayrı bir zincirde ya da akışta tutulmalı veya hız sınırlanıp birleştirilmelidir.

---

## 2. Bütünlük, yani kurcalama kanıtı, ölçekte

### 2.1 Özet zinciri, Merkle ağacı ile şeffaflık günlüğünün karşılaştırması

RFC 9162, sertifika şeffaflığının ikinci sürümü, deneysel statüdedir, Aralık 2021. Deneysel statüsü kafa karıştırıcıdır; ekosistemde fiilen birinci sürüm ile onun halefi olan statik API kullanılmaktadır.

Teknik özeti şöyledir. Merkle ağacı özeti boş liste için doğrudan bir özet, tek yaprak için sıfır bayt önekiyle özet ile iç düğüm için bir bayt önekiyle sol ve sağın birleşiminin özetidir. Alan ayrımı, yani sıfır ile bir bayt önekleri, ikinci ön görüntü direnci için zorunludur; bunu atlamak klasik bir hatadır. Dahil olma kanıtı logaritmik sayıda düğümdür. Tutarlılık kanıtı logaritmanın tavanı artı bir düğümdür. İmzalı ağaç başlığı zaman damgası, ağaç boyutu, kök özeti ile uzantıları taşımakta ve imzalıdır; her sonraki zaman damgası bir öncekinden daha yeni olmak zorundadır. Azami birleştirme gecikmesi, imzalı bir zaman damgası verildikten sonra günlüğün girdiyi ağaca dahil etme taahhüdüdür; indeks tahsisi, kök hesabı ile ağaç başlığının imzalanmasını kapsamaktadır.

Azami birleştirme gecikmesi kavramı, Argus'un saniyede bir denetim noktası kararının standart karşılığıdır. Argus için bu gecikme yaklaşık bir saniye ilan edilebilir ile bir hizmet seviyesi taahhüdü olarak yayımlanabilir.

### 2.2 Döşeli günlükler, 2024 ile 2026'nın gerçek dersi

Sertifika şeffaflığı ekosistemi canlı veritabanı ile API modelinden statik dosya döşemelerine geçmiştir. Bu, Argus için doğrudan bir mimari derstir.

Sunlight ile statik sertifika şeffaflığı API'sinde günlükler döşeme adı verilen düz dosya koleksiyonları olarak temsil edilmektedir. Filippo Valsorda tek bir sunucuda bir Sunlight günlüğü çalıştırmakta ile toplam maliyet yılda yaklaşık 10.000 dolardır. Bant genişliğinde bir döşeli günlük 400 ile 800 megabit üretirken eski nesil günlükler bir ile iki gigabit üretmektedir; statik API bant genişliğini yaklaşık %80 azaltmaktadır.

Let's Encrypt'in 11 Haziran 2025 tarihli bir yıllık Sunlight değerlendirmesine göre her günlüğün yazma tarafı tek bir makineyle rahatça karşılanmıştır. Birleştirme gecikmesi fiilen sıfırdır: günlükler, gönderene imzalı bir zaman damgası döndürmeden önce yeni gönderilen sertifikaları her zaman tamamen dahil etmektedir. Yani bu gecikmeyi sıfıra indirmek mümkündür ile tercih edilmektedir. Let's Encrypt kendi ürettiği tüm sertifikaları, ki kamuya güvenilir hacmin çoğunluğudur, işlemiştir. Statik API günlükleri birinci nesil günlüklerden belirgin biçimde daha düşük kaynak gereksinimi taşımaktadır.

Sigstore'un ikinci sürüm kayıt günlüğü 10 Ekim 2025'te genel kullanıma açılmıştır. Trillian'dan döşeme destekli Tessera'ya geçilmiştir. Sürüm istekleri yığınlamakta ile bu, daha yüksek sorgu hızını ile tanıklığı mümkün kılmaktadır; takas yanıtların birkaç saniye sürmesidir. Döşemeler değişmez, içerik adresli ile içerik dağıtım ağından servis edilebilirdir. Yıllık parçalama yapılmakta ile eski parçalar dondurulup statik döşeme olarak arşivlenmektedir. Eski günlük sunucusu ile imzalayıcı örnekleri tamamen kapatılmış; altyapı maliyeti ile karmaşıklığı düşmüştür. Basitleştirme kapsamında birçok girdi tipi kaldırılmış ile yalnızca ikisi bırakılmıştır.

Tessera kıyaslamaları Argus için en değerli sayılardır.

| Arka uç | İş hacmi |
|---|---|
| Yerel NVMe dosya sistemi | Saniyede yaklaşık 10.000 yazma; sunucu için yedi çekirdeğe kadar kullanılmakta, istenmeyen içerik koruması açıktır |
| Yerel SAS disk | Koruma kapalıyken saniyede yaklaşık 2.900, açıkken 1.600 yazmadır |
| GCP Spanner, 100 işlem birimi ile bir ön uç | Korumasız saniyede üç binden fazla, korumalı 800'den fazla sorgudur |
| GCP Spanner, 300 işlem birimi ile iki ön uç | Korumalı saniyede beş binden fazla sorgudur |
| CephFS ağ depolama, dört düğüm | Saniyede binden fazla sorgudur |
| Ücretsiz katman küçük örnek ile kalıcı disk | Saniyede 1.500'den fazla yazmadır |

Mimarisi sıralama, yani dayanıklı indeks atama ile sıra garantisi olmadan, ile bütünleştirme, yani arka planda Merkle ağacına birleştirme olarak ayrılmıştır. Yığınlama, denetim noktası aralığı ile yeniden yayımlama aralığı yapılandırılabilmektedir. Yığın boyutu bir olabilmektedir ancak bu sıralamayı pahalı kılmaktadır.

Bir karşılaştırma buradan kaldırılmıştır. Önceden burada Argus'un ölçülen işlem hızının Tessera'nın iki katı olduğu yazmaktaydı. Bu bir elmayla armut karşılaştırmasıdır: Tessera'nın saniyede 10.000 sorgusu sıralama ile bütünleştirme yapan tam bir şeffaflık günlüğünün değeridir; karşılaştırılan sayı ise Merkle'sız, imzasız ile uygulama mantığı olmayan çıplak bir ekleme ölçümüdür. Ayakta kalan sonuç sayılardan değil yapıdan gelmektedir: olay başına özet zinciri seri bağımlılık yaratmakta, Merkle denetim noktası yaratmamaktadır. Karar bu gerekçeyle doğrudur.

### 2.3 AWS QLDB emekli olmuştur

Ürün 31 Temmuz 2025'te tamamen destek dışı kalmıştır.

Resmî bir duyuru yapılmamış; yalnızca dokümantasyon güncellenmiş ile müşterilere Temmuz 2024'te e-posta gönderilmiştir. AWS'in önerdiği göç yolu Amazon Aurora PostgreSQL'dir, yani defter benzeri yetenekler eklentilerle sağlanmaktadır; ancak bu göç kriptografik doğrulanabilirliği kaybettirmektedir. Ürün 2018'de duyurulmuş, 2019'da genel kullanıma açılmış ile yaklaşık altı yıl yaşamıştır.

Argus için stratejik ders şudur: kriptografik olarak doğrulanabilir defter, bir yönetilen hizmet kategorisi olarak ticari başarısızlığa uğramıştır; çünkü müşteriler ayrı bir veritabanı değil var olan veritabanlarında bir bütünlük özelliği istemiştir. Bu, Argus'un PostgreSQL içinde yalnızca ekleme artı Merkle denetim noktası kararını doğrulamaktadır: ayrı bir defter sistemi kurmak yerine mevcut deponun üzerine ince bir bütünlük katmanı konulmalıdır. Ayrıca yönetilen defter hizmetlerine bağımlılık kurulmamalıdır.

### 2.4 PostgreSQL'de yalnızca ekleme zorlaması

Katman katman savunma şöyledir.

1. Denetim tablosunda güncelleme ile silme yetkisi herkesten geri alınmalı ile uygulama rolüne yalnızca ekleme, gerekiyorsa okuma verilmelidir. Uyum rejimi veritabanı seviyesinde yalnızca ekleme istiyorsa her rolden geri alınmalıdır.
2. Güncelleme ile silme öncesi bir tetikleyici istisna fırlatmalıdır. Ancak yeterli değildir.
3. Kesme deliği vardır. PostgreSQL'de kesme, satır seviyesi değil ifade seviyesi bir işlemdir ile satır seviyesi tetikleyiciler onun için hiç çalışmamaktadır. Satır seviyesi tetikleyicilerle korunan bir tablo kesmeyle tamamen boşaltılabilmektedir. Çözüm ayrıca bir kesme öncesi ifade seviyesi tetikleyicisidir. Bu, yalnızca ekleme iddiasında en sık kaçırılan açıktır.
4. Satır seviyesi güvenlik okuma tarafında kiracı izolasyonu içindir ile yazma korumasının yerini tutmamaktadır.
5. Temel gerçek şudur: düzenlemeleri engellemek, düzenlemeleri tespit edilebilir kılmakla aynı şey değildir. İzinlerle değişiklikler azaltılabilir ancak yeterli erişimi olan herkes hâlâ geçmişi değiştirebilmektedir. Kurcalama kanıtı bu gerçeği kabul edip değişikliklerin belirgin bir parmak izi bırakmasını sağlamaktadır. Süper kullanıcı her zaman kazanmaktadır; bu yüzden Merkle denetim noktaları dış tanıklara yayımlanmalıdır.

pgaudit Argus için uygun değildir. Oturum ile nesne denetim günlüklemesi sunmaktadır. Ayarlara bağlı olarak muazzam hacimde günlük üretebilmektedir; analitik tablo eklemelerinde disk hızla dolmakta ile günlükler metin olduğu için gerçek veriden çok daha büyük olmaktadır. Kesme, nesne denetim günlüklemesinde desteklenmemektedir. En önemlisi, denetim günlüklemesi elden gelenin en iyisi biçimindedir ile işlemsel değildir; çökmede kayıt kaybolabilmektedir. Bu tek başına onu uyum seviyesinde denetim için diskalifiye etmektedir. Süper kullanıcı denetimi güvenilir değildir. Çıktı standart PostgreSQL günlük tesisine gitmekte ile yapılandırılmış sorgu için elverişsizdir.

pgaudit, veritabanı seviyesinde ikincil bir kontrol olarak, yani Argus veritabanına dışarıdan yapılan doğrudan erişimi yakalamak için değerlidir; birincil denetim kaynağı olarak değil.

Saklama için bölümleme şöyledir. Bir bölümü düşürmek milyonlarca kaydı anında silmekte, temizleme yükü getirmemekte ancak erişimi dışlayan bir kilit istemektedir. Bölümü eşzamanlı ayırmak yalnızca daha hafif bir kilit istemektedir; üretimde tercih edilmelidir ile veriyi bağımsız bir tablo olarak korumaktadır. Bölüm eklemede önceden bir kontrol kısıtı konursa tam tablo taramasından kaçınılmaktadır. Bölüm budama hem plan hem yürütme zamanında çalışmaktadır. Bir kısıt vardır: benzersizlik ile birincil anahtar kısıtları bölüm anahtarını içermek zorundadır ile yabancı anahtarlar bölüm hiyerarşisinde çalışmamaktadır.

Bu, Keycloak'ın toplu silmeyle temizleme yaparken veritabanını kilitleme problemine yapısal bir çözümdür.

### 2.5 Merkle denetim noktası sıklığıyla doğrulanabilirlik takası, literatürdeki ölçümler

| Kaynak | Denetim noktası ya da dönem | Sonuç |
|---|---|---|
| Crosby ile Wallach 2009 | Her taahhüt imzalanmaktadır | Saniyede 1.750 olaydır |
| Crosby ile Wallach 2009 | 16 taahhütte bir imza atılmaktadır | Saniyede yaklaşık 17.000 olaydır, yaklaşık 10 kattır |
| Ajan uçuş kaydedici 2026 | 100 olaylık dönem | Medyanda 0,6 mikrosaniye eklemekte ile 99. yüzdelikte yaklaşık 4,1 milisaniyelik bir tepe yaratmaktadır |
| Ajan uçuş kaydedici 2026 | 100 olaylık dönem artı ikinci katman çıpalama | Ele geçirme penceresi 100 saniyedir; maliyet ikinci katmanda 100 bin olay başına 2,30 dolar, birinci katmanda 6.885 dolardır; çıpa başına 91.800 birim işlem ücreti gerekmektedir |
| Let's Encrypt Sunlight 2025 | Etkin sıfır birleştirme gecikmesi | Tek makine tüm hacmi kaldırmıştır |
| İkinci sürüm kayıt günlüğü 2025 | Yığınlama ile tanıklık | Yanıt birkaç saniye sürmektedir |

Takas yasası şudur: denetim noktası aralığı ele geçirme penceresine eşittir, yani günlük operatörünün tespit edilmeden ne kadar geçmişi yeniden yazabileceğine. Bir saniyelik denetim noktası bir saniyelik pencere demektir. Bu, Okta, Auth0 ile Keycloak'ın hiç sunmadığı bir garantidir; onlar sıfır garanti sunmaktadır.

Ancak dikkat edilmelidir: denetim noktası bir dış tanığa ya da istemciye yayımlanmadıkça pencere sonsuzdur. Crosby'nin ifadesiyle güvenilmez bir günlükleyici, farklı anlık görüntülerin geçmiş hakkında tutarsız iddialarda bulunmasını sağlamakta serbesttir. Bunun tespiti için tutarlılık kanıtı denetimi, yani dedikodu ya da tanıklık şarttır. Denetim noktasını yalnızca kendi veritabanınızda tutmak bütünlük sağlamamaktadır.

### 2.6 Kripto parçalamayla bütünlük zincirinin bir arada kullanımı

Desen tüm kaynaklarda aynıdır: özet şifreli metin üzerinden alınmalıdır. Böylece anahtar imha edildiğinde satır yerinde kalmakta, özet değişmemekte, zincir kırılmamakta ancak içerik geri döndürülememektedir.

Kaynaklardan biri tetikleyici değişmez defter korumasıyla atomik kripto parçalamayı anlatmaktadır: özne başına anahtar satırının anahtar materyali boşa çekilmekte, anahtar referansı mezar taşı hayatta kalmakta, bildirim güdümlü düz metin temizliği yapılmakta ile tek bir değişmez silme olgusu satırı eklenmektedir. Deftere hiç dokunulmamaktadır. Bir diğer kaynak, 18 Ocak 2026 tarihli, GDPR 17. maddeyle finansal kayıt tutma yükümlülüklerinin uzlaştırılmasını anlatmaktadır. Bir diğeri Kafka'da aynı deseni, bir başkası .NET gerçeklemesini göstermektedir.

Hukuki bir uyarı çok önemlidir. Avrupa Veri Koruma Kurulu'nun 16 Ocak 2025'te kabul ettiği takma adlaştırma kılavuzu şunu söylemektedir: takma adlaştıran veri sorumlusunun sakladığı tüm ek bilgiler silinmiş olsa bile, takma adlı veri ancak anonimlik koşulları karşılanıyorsa anonim sayılabilmektedir.

Yani anahtar silmek otomatik olarak anonimleştirme değildir. Kripto parçalama, GDPR 17. madde uyumu için yeterli diye pazarlanamaz; risk tabanlı bir argümandır. Anahtarın gerçekten yok edilip edilmediği, yedeklerde kalıp kalmadığı ile şifreli metnin kırılabilirliği, kuantum sonrası dahil, sorgulanmaktadır. Argus dokümantasyonunda bu, silme değil günlük içeriğinin geri döndürülemez kimliksizleştirilmesi olarak ile veri sorumlusunun kendi etki değerlendirmesine tabi biçimde konumlandırılmalıdır. Gerçek uygulamalar vardır ancak düzenleyici kesinlik yoktur.

---

## 3. Ölçekte günlük hacmi ile maliyet

### 3.1 Gerçek kimlik sağlayıcıların saklama süreleri, çarpıcı tablo

| Sağlayıcı | Sıcak saklama |
|---|---|
| Okta sistem günlüğü | 90 gündür |
| Auth0 başlangıç katmanı | Bir gündür |
| Auth0 temel katmanlar | Beş gündür |
| Auth0 profesyonel katmanlar | 10 gündür |
| Auth0 kurumsal | 30 gündür |
| Entra kimlik ücretsiz, denetim ile giriş | Yedi gündür |
| Entra kimlik birinci ile ikinci kademe, denetim ile giriş | 30 gündür |
| Entra kimlik ikinci kademe, riskli oturum açmalar | 90 gündür |
| Entra dış kimlik temel | Yedi gündür |

Sektör deseni açık ile şaşırtıcıdır: hiçbir büyük kimlik sağlayıcı PCI DSS'in 12 aylık saklama gereksinimini kendi içinde karşılamamaktadır. Hepsi kısa sıcak pencere artı akışlı dışa aktarım modeline geçmiştir. Müşteri kendi güvenlik bilgi ve olay yönetimi sisteminde ya da arşivinde uzun saklamayı yapmaktadır.

Ek bulgular şunlardır: Auth0 kiracınız için gerçek zamanlı günlük sağlamamaktadır; olaylar geldikçe indekslenmeye çalışılmakta ancak gecikmeler görülebilmektedir. Okta'nın olay akışında yaklaşık 30 saniye gecikme vardır. Auth0'da kiracı başına varsayılan iki günlük akışı bulunmakta, kurumsalda talep üzerine üçe çıkmaktadır.

Okta günlük akışı yalnızca Amazon EventBridge ile Splunk Cloud hedeflerini desteklemektedir; Okta tüm sistem günlüğü olaylarını yapılandırılmış hedefe göndermekte ile olay süzme desteklenmemektedir.

Olay hızı ile günlük hacmi rakamları konusunda bir uyarı gerekmektedir: Okta, Auth0 ya da Keycloak için kamuya açık, birincil kaynaklı bir saniyede olay ya da günde gigabayt rakamı bulunamamıştır. Sektör dolaylı olarak yalnızca saklama süreleri ile hız sınırlarıyla konuşmaktadır.

Kıyaslanabilir tek somut hacim ölçüsü Crosby ile Wallach'ın 2009 verisidir: saniyede 10.500 olay, yani saniyede 1,9 megabayt ham sistem günlüğü ile haftada 1,1 terabayt. Buradaki haftada yaklaşık 2,3 terabaytlık tahmin, çıplak ekleme ölçümünü sürekli hacim saymaktan çıkmaktaydı; o sayı 12 saniyelik bir ölçümdür ile yedi gün yirmi dört saat tepe yük varsayımıyla çarpılamaz. Hacim planı, gerçek olay hızı ölçüldükten sonra yeniden yapılmalıdır. Yapısal sonuç değişmemektedir: bu büyüklük sınıfında ham olaylar sıkıştırmasız olarak PostgreSQL'de tutulamamaktadır.

### 3.2 Örnekleme denetimde kabul edilebilir midir

Hayır. Bulunan tüm kaynaklar hemfikirdir.

Yüksek hacimli, düşük etkili uygulama metrikleri için örnekleme düşünülebilir ancak denetim izleri adli değeri korumak için eksiksiz kalmalıdır. Hassas veri, ayrıcalıklı eylem ya da düzenlenmiş süreç içeren operasyonlar her zaman izlenmeli ile bu kritik operasyonlar iz öznitelikleriyle işaretlenip örneklemeden muaf tutulmalıdır. PCI DSS'in onuncu gereksinimi tüm bireysel erişim ile kök veya yönetici yetkisiyle yapılan tüm işlemler demektedir; tüm kelimesi örneklemeyi yasaklamaktadır. NIST'in olay günlükleme kontrolünde hangi olayların günlükleneceği seçilmektedir, yani olay seçimi yapılmaktadır; seçilen olay tipinin örneklenmesi değil.

Doğru ayrım şudur: denetimde örnekleme değil olay seçimi vardır. Kontrolün izin verdiği şey bu olay tipini hiç günlükleme kararıdır, ki dokümante bir gerekçeyle alınan bir politika kararıdır; bu olay tipinin yüzde onunu günlükle değildir. Bu ikisini karıştırmak denetimde bir başarısızlıktır.

İz tarafında ise örnekleme zorunludur: OpenTelemetry'nin kendi performans kıyaslama standardı varsayılan olarak saniyede 10.000 aralık ölçmektedir; yüksek hacimli bir kimlik sağlayıcıda yüzde yüz iz örneklemesi ekonomik değildir.

Argus'ta iki ayrı yol olmalıdır: denetim yolu yüzde yüz, dayanıklı ile kurcalama kanıtlı olmalı; telemetri yolu örneklenmiş, elden gelenin en iyisi ile düşürülebilir olmalıdır. Bunları aynı boru hattına koymak en yaygın mimari hatadır.

### 3.3 Sıcakla soğuk katman ayrımı, gerçek üretim deseni

Phase Two'nun 6 Temmuz 2026 tarihli Keycloak olay depolamasını günlükler, S3 ile ClickHouse kullanarak ölçekleme yazısı Argus için doğrudan uygulanabilir bir referans mimaridir.

Keycloak'ın kalıcılık katmanı olay deposunun dört temel arızası şunlardır. Birincisi istek yolu vergisidir: olay yazımı kimlik doğrulamayla aynı işlemdedir ile giriş isteği veritabanı eklemesini beklemek zorundadır. İkincisi operasyonel kırılganlıktır: olay tablosu on milyonlarca ya da yüz milyonlarca satıra ulaşınca şema değişikliği riskli olmaktadır, çünkü aktif isteklerin bağlı olduğu tablo kilitlenmektedir. Üçüncüsü sona erme çekişmesidir: toplu silmeyle sona erdirme yazma yoğun tabloya karşı çalışmakta ile kilit çekişmesi ve giriş çıkış tepesi yaratmaktadır. Dördüncüsü analitik imkânsızlığıdır: 90 gündeki başarısız girişler sorgusu üretim tablosunda tam tablo taramasıdır.

Boru hattı şöyledir.

1. Bir olay günlüğü deposu sağlayıcısı olayları JSON günlük satırı olarak yaymaktadır; alanlar olay tipi, kullanıcı kimliği, istemci kimliği, IP adresi ile alan adıdır. Kalıcılık katmanıyla çift yazma yapılabilmekte ile doğrulandıktan sonra tek başına kullanılmaktadır.
2. Fluent Bit yönlendirmesiyle tüm günlükler bir günlük deposuna, yalnızca olay satırları ise kişisel verisi redakte edilmiş ile küme ve tarihe göre bölümlenmiş biçimde S3'e gitmektedir.
3. ClickHouse'un S3 kuyruğu tablo motoru kovayı sürekli izlemekte; ClickHouse Keeper işlenen dosyaları takip etmekte ile tam bir kez benzeri teslimat sağlanmaktadır. Kafka yoktur ile zamanlanmış bir yığın işi yoktur. Öğrenilen bir ders vardır: S3 destekli tablo depolaması birleştirmeler sırasında küme başına saniyede 150 istek üretmiş ile yerel NVMe'ye geçilmiştir.
4. Sorgu ağ geçidi bir API ağ geçidi arkasında çalışan bir işlevdir; parametrik REST uç noktaları, JWT ile kiracı izolasyonu sunmakta ile serbest biçimli SQL'e izin vermemektedir.
5. Pano metrikleri özet tablolarından, olay aramaları tipli tablolardan gelmektedir.

Sonuçlar şunlardır: ham olaylar S3'te süresiz tutulmakta, özet granülaritesi beş dakikadır ile bir yıllık giriş eğilimi sorgusu onlarca milisaniyede dönmektedir. Her katman bağımsız değiştirilebilirdir, çünkü sözleşme yalnızca yapılandırılmış JSON günlük satırlarıdır.

ClickHouse'un kendi gözlemlenebilirlik kılavuzu, günlükleri ile izleri ortalama 14 kata kadar sıkıştırdığını belirtmektedir.

Argus'un katman planı şudur: sıcak katman PostgreSQL'dir, 30 ile 90 gün, bölümlenmiş, yalnızca ekleme ile Merkle zincirinin kaynağıdır; soğuk katman Parquet ile S3'tür, süresiz ve OCSF şemalıdır; analitik katman isteğe bağlı olarak ClickHouse'tur. AWS Security Lake'in özel kaynak sözleşmesi de tam olarak OCSF artı Parquet'tir; bu yüzden soğuk katmanı bu formatta yazmak Argus'u ücretsiz olarak uyumlu yapmaktadır.

### 3.4 Çelişen saklama gereksinimleri nasıl uzlaştırılmaktadır

| Rejim | Gereksinim |
|---|---|
| PCI DSS dördüncü sürüm | En az 12 ay, son üç ay hemen erişilebilirdir |
| CNIL kararı, 14 Ekim 2021 | Genel olarak altı ay ile bir yıl arası; iç kontrollerle dokümante gerekçeyle altı ay ile üç yıl arası; üç yıl üstü yalnızca yasal yükümlülük ya da özel tehditle |
| CNIL, günlük içeriği | En az kullanıcı kimliği, erişim tarih ile saati, kullanılan ekipman kimliği; ayrıca otomatik bir analiz sistemi kurulmalıdır, pasif saklama yetmemektedir |
| GDPR beşinci madde | Depolama sınırlaması: amaç için gerekli süreden fazla tutulmamalıdır |
| NIST denetim kaydı saklama kontrolü | Kurum tanımlıdır |
| SOC 2 | Sabit bir sayı yoktur; pratikte genellikle bir yıllık gözlem penceresi kullanılmaktadır. Birincil kaynak bulunamamıştır |

Sektörde fiilen uygulanan uzlaşma deseni şudur.

1. Saklama süresi Argus'un kararı değil kiracının yapılandırmasıdır. Hukuki çelişki müşterinin sorumluluğundadır; Argus mekanizmayı sunmaktadır, yani kiracı ile olay sınıfı başına yaşam süresi.
2. Kişisel veriyle olay iskeleti ayrılmalıdır. Olayın varlığı, yani kim, ne, ne zaman ile sonuç, takma adlı bir kimlikle 12 aydan uzun tutulabilmektedir; IP, kullanıcı aracısı ile e-posta gibi kişisel veri alanları altı ayda kripto parçalanabilmektedir. CNIL'in altı ay endişesi kişisel veriye, PCI'nin 12 ayı olay izine yöneliktir. Bunlar aynı satırda olmak zorunda değildir.
3. Sıcak katman kısa, soğuk katman uzun olmalıdır; soğuk katman şifreli ile özne başına anahtarla korunmalıdır.

---

## 4. Rust gözlemlenebilirlik yığını, 2026 üretim gerçeği

### 4.1 opentelemetry-rust kararlılık tablosu, Eylül 2026

| Bileşen | Durum |
|---|---|
| Günlük API'si | Kararlıdır |
| Günlük geliştirme kiti | Kararlıdır |
| Günlük dışa aktarıcısı | Yayın adayıdır |
| Metrik API'si | Kararlıdır |
| Metrik geliştirme kiti | Kararlıdır |
| Metrik dışa aktarıcısı | Yayın adayıdır |
| İz API'si | Betadır |
| İz geliştirme kiti | Betadır |
| İz dışa aktarıcısı | Betadır |
| Bağlam | Betadır |
| Bagaj | Yayın adayıdır |
| Yayıcılar | Betadır |

Asgari desteklenen Rust sürümü 1.75'tir; politika güncel kararlı sürüm artı son üç küçük sürümdür.

En kritik operasyonel gerçek şudur: her crate hâlâ birinci ana sürüm öncesindedir. Kararlı işaretli sinyaller bile sıfır ana sürümde yaşamakta; kırıcı değişiklikler küçük sürümlerde gelmekte ile tüm birinci taraf crate'ler birlikte sürümlenmektedir. Kararlı şartname özelliklerinin deneysel bayraklardan mezun edilmesini isteyen konu hâlâ açıktır.

Rust'ta OpenTelemetry, diğer dillerin tersine, günlükleri ile metrikleri izlerden önce kararlı hâle getirmiştir. Bu Argus için aslında iyi bir haberdir: denetim ile günlük yolu kararlı bir API üzerindedir, iz yolu ise daha az kritiktir ile betadadır.

Ancak birlikte sürümlenen sıfır ana sürüm, Argus'un doğrudan OpenTelemetry API'sine kod boyunca bağımlı olmasını riskli kılmaktadır. Kendi ince cepheniz yazılmalı ile kütüphane yalnızca dışa aktarıcı kenarında kullanılmalıdır.

### 4.2 tracing ekosistemi

tracing 0.1.44'tür, 6 Eylül 2026. Performansla ilgili tek resmî iddia şudur: performans nedeniyle, şu anda aktif hiçbir abone belirli bir metadata kümesiyle ilgilenmiyorsa, karşılık gelen aralık ya da olay hiç oluşturulmamaktadır.

Derleme zamanı süzme, azami seviye özellik bayraklarıyla yapılmaktadır; yayın derlemesinde belirli seviyelerin altındaki makroların tamamen derlenmemesini sağlamaktadır.

Pratik kılavuz şunları söylemektedir: devre dışıyken günlük ile izleme kütüphaneleri sıfır maliyetlidir, etkinken aralık başına küçük bir ek yük vardır, çünkü aralık kaydı küçük bir ayırma yapmaktadır. Her zaman yığın aralık işleyicisi kullanılmalıdır, basit olan değil; yığınlama ağ ek yükünü büyük ölçüde azaltmaktadır. Pahalı katmanlara süzgeç uygulanmalı ya da küresel bir süzgeç kullanılmalıdır ki devre dışı aralıklar o katmanlardan geçmesin. Yığın işleyici ayrı bir arka plan iş parçacığında çalışmaktadır; araçlar hafif kilitlidir ile çöp toplama yoktur.

İzleme ile ilgili kütüphaneler için nanosaniye seviyesinde bağımsız yayımlanmış bir kıyaslama bulunamamıştır. Kendi ölçümünüzü almanız gerekecektir, özellikle yüksek istek hızında araç makrosunun istek başına aralık maliyeti için.

### 4.3 Metrik cephesiyle OpenTelemetry metriklerinin karşılaştırması

| | Metrik cephesi | OpenTelemetry metrikleri |
|---|---|---|
| Model | Bir cephedir, arka uç takılabilirdir | Tam bir geliştirme kitidir |
| Dışa aktarıcılar | Prometheus, StatsD ile özel dışa aktarıcılar; araç kodunu değiştirmeden | Prometheus ile OTLP |
| Olgunluk | Ekosistemde yaygındır, çoğu uygulama için standart seçim sayılmaktadır | API ile geliştirme kiti kararlıdır ancak crate sıfır ana sürümdedir |
| İz ile günlük korelasyonu | Yoktur | Vardır, tek OTLP hattıyla |

Argus için OpenTelemetry metrikleri seçilmelidir. Gerekçeleri şunlardır: metrik API'si ile geliştirme kiti zaten kararlıdır; tek hatta metrik, günlük ile iz korelasyonu sağlanmaktadır; kiracılara kendi OTLP uç noktanıza gönderelim demek satılabilir bir özelliktir; ile metrik cephesinin arka uçtan bağımsızlığı Argus'un tek OTLP hedefi olan senaryosunda değer üretmemektedir. Cephenin tek avantajı olan arka uç değiştirme, OpenTelemetry toplayıcısıyla zaten çözülmektedir.

### 4.4 Yüksek kardinalite, kiracı ya da istemci başına etiket

Sayısal gerçek şudur: bir milyon aktif zaman serisi olan bir Prometheus örneği, yalnızca baş blok için tipik olarak dört ile altı gigabayt bellek tüketmektedir.

Argus için hesap şudur: bin kiracı çarpı 50 istemci çarpı 20 olay tipi çarpı beş sonuç durumu beş milyon seri eder; yani yaklaşık 20 ile 30 gigabayt bellek. Tek başına yıkıcıdır.

Çözümler şunlardır.

1. Etiket disiplini: kullanıcı kimliği, istek kimliği, IP ya da tam adres gibi tanımlayıcılar asla etiket olarak kullanılmamalıdır. Kiracı kimliği bile tehlikeli sınırdadır.
2. Örnekleyiciler: bir örnekleyici, bir histogram kovasına bir iz kimliği iliştirmekte; böylece hem toplu metrik hem belirli bir yavaş isteğe inme imkânı, istek başına etiketin kardinalite maliyetini ödemeden sağlanmaktadır. Argus'un doğru cevabı budur.
3. Yerel histogramlar: Prometheus 2.40'tan beri deneyseldir ile üçüncü ana sürüm hattında araçları olgunlaşmıştır. Histogramlar seri sayısına hâkimse yapısal düzeltme budur; klasik histogram kovaları seri sayısını kova sayısıyla çarpmakta, yerel histogram bunu tek seriye indirmektedir.
4. Kiracı başına izolasyon: Grafana Mimir, Cortex ya da Thanos ile kiracı başına azami seri, alım hızı ile sorgu limitleri konmaktadır; kaçak etiketler o kiracının içinde kalmaktadır.

Argus deseni şudur: metrikte kiracı yoktur, denetim günlüğünde kiracı vardır. Kiracı kırılımlı sayılar Prometheus'tan değil analitik katmandaki özet tablolarından gelmelidir. İstisna en fazla yaklaşık 50 en büyük kiracı için izin listeli, düşük kardinaliteli bir metrik setidir.

### 4.5 Yapılandırılmış günlüklemede kişisel veri ile sır sızıntısı

`secrecy` crate'inin 0.10.3 sürümü şunları sağlamaktadır: sır kutusu, sır dizgi ile sır dilim tipleri görüntüleme ile hata ayıklama arayüzlerini gerçeklememektedir. Erişim için sırrı açığa çıkar arayüzü üzerinden açık bir çağrı gerekmektedir. Düşürmede bellek sıfırlanmaktadır. Serde tarafında sır kutusu varsayılan olarak serileştirilememektedir; veri sızıntısını engellemek içindir. Seri durumdan çıkarma desteklenmekte ile serileştirme için ayrı bir arayüzün elle gerçeklenmesi gerekmektedir. Bu, JSON günlüklemede kazara sızıntıyı yapısal olarak engellemektedir. Kütüphane standart kütüphanesiz ortamlarla uyumludur ile güvensiz kod yasaklıdır. Bellek kilitleme gibi ileri korumalar kasten yoktur; onlar için başka bir crate önerilmektedir. Alternatifleri redaksiyon ile sıfırlama sunan birkaç crate'tir.

Rust'a özgü bir tuzak vardır: türetilmiş hata ayıklama bir yapıdaki bütün alanları basmaktadır. İzleme kütüphanesinin hata ayıklama sözdizimi bu gerçeklemeyi çağırmaktadır. Bir yapıya sonradan bir parola özeti ya da yenileme token'ı alanı eklendiğinde, hiçbir günlük satırı değiştirilmese bile o an sızıntı başlamaktadır. Türetmenin sessiz genişlemesi zamanla artan bir risktir.

Argus kuralı şudur: kişisel veri ya da sır taşıyan hiçbir tipte türetilmiş hata ayıklama olmayacaktır. Elle yazılmış bir gerçekleme ya da sır sarmalayıcıları kullanılacaktır. Bu, sürekli tümleştirmede bir denetim kuralıyla zorunlu kılınmalıdır; standart kural ters yönde çalıştığı için kendi kuralınızı yazmanız gerekmektedir.

Sıfırlamanın bir sınırı vardır: bir güvenlik danışmanlığında bir bağımlılık değişikliğinin şifreleme sırlarının bellekte daha fazla kopyasını yarattığı bildirilmiştir. Danışmanlığın kendi notu şudur: mutlak sıfırlama konusunda Rust'ın doğasından gelen sınırlar pratik şiddeti azaltmaktadır. Yani sıfırlama elden gelenin en iyisidir, bir garanti değildir; taşıma semantiği, optimize edici ile takas alanı nedeniyle.

---

## 5. Denetim günlüğü bir güvenlik ürünü olarak

### 5.1 Paylaşılan sinyal vericisi, Argus'un asıl farklılaştırıcısı

CAEP 1.0 ile paylaşılan sinyaller çerçevesi 1.0, nihai şartname olarak onaylanmış ile 2 Eylül 2025'te yayımlanmıştır. Oylama 85 kabul, bir ret ile 25 çekimserdir; 433 üyeden 111 oy kullanılmış ile %20 yeter sayısı aşılmıştır.

CAEP 1.0'ın sekiz olay tipi ile Argus'un iç denetim olayı karşılıkları şöyledir.

| Sıra | Olay | Argus karşılığı |
|---|---|---|
| 1 | Oturum kuruldu | Giriş başarılıdır ile oturum oluşturulmuştur |
| 2 | Oturum sunuldu | Oturumun vericide etkin olarak gözlemlendiğini teyit etmektedir; token yenileme ya da çoklu oturum açma yeniden kullanımıdır |
| 3 | Oturum iptal edildi | Çıkış, yönetici oturum sonlandırma ya da küresel çıkıştır |
| 4 | Kimlik bilgisi değişti | Parola değişimi, çok faktörlü kayıt ya da kaldırma, geçiş anahtarı ekleme veya silme ile kurtarma kodu üretimidir |
| 5 | Güvence seviyesi değişti | Yükseltilmiş kimlik doğrulama ile bağlam sınıfı değişimidir |
| 6 | Token iddiaları değişti | Rol, grup ya da iddia değişimidir, SCIM yaması sonrası |
| 7 | Cihaz uyumluluğu değişti | Varsa cihaz duruşu tümleştirmesidir |
| 8 | Risk seviyesi değişti | Risk motoru skoru değişimidir |

Eşleme analizi şudur: Argus'un iç denetim olay evreninin büyük çoğunluğu bu sekiz tipe düşmemektedir. CAEP olayları durum değişikliği bildirimleridir, yani bağlı tarafın aksiyon alması içindir; denetim olayları ise olgu kayıtlarıdır. Örneğin başarısız bir giriş denemesinin CAEP'te karşılığı yoktur, çünkü oturum kurulmamış ile kimlik bilgisi değişmemiştir. Bir yöneticinin istemci sırrını döndürmesinin de karşılığı yoktur.

Doğru mimari iki ayrı yayın kanalı, tek kaynaktan şeklindedir. CAEP akışı sekiz tiptir; gerçek zamanlıdır, bağlı taraflara gider, aksiyon odaklıdır ile düşük hacimlidir. Denetim akışı tam taksonomidir; güvenlik bilgi ve olay yönetimi sistemlerine ve arşive gider ile yüksek hacimlidir. İkisi de aynı iç olay yolundan beslenmeli ile aynı işlem tanımlayıcısıyla korele edilmelidir.

Paylaşılan sinyaller çerçevesinin akış yönetimi şöyledir. İtmeli teslimde alıcı bir uç nokta adresi vermekte ile verici gönderi yapmaktadır; alıcı bir yetkilendirme başlığı sağlayabilmektedir. Yoklamalı teslimde verici uç nokta adresini vermektedir; teslim yöntemi belirtilmezse varsayılan budur. Yapılandırma uç noktası oluşturma, okuma, kısmi güncelleme, tam değiştirme ile silmeyi desteklemektedir; başarılı oluşturma 201 ile akış kimliği, veren, izleyici kitle ile teslim edilen olayları döndürmektedir. Özne yönetiminde ekleme ile çıkarma uç noktaları bulunmakta; doğrulanmış bayrağı alıcının özne sahipliğini teyit ettiğini belirtmektedir. Basit özne tam eşleşme, karmaşık özne joker semantiği kullanmaktadır. Doğrulama olayları hem kalp atışı hem uçtan uca doğrulama sağlamakta; opak bir durum değeri yankılanmaktadır. Değerin kimliği akış kimliği olmak zorundadır ile akışı tanımlayan özne örtük olarak eklenmekte ve kaldırılamamaktadır.

Sıralama ile dayanıklılık konusunda Argus için kritik normatif metin şudur: duraklatma durumunda verici, duraklamışken ileteceği olayları tutmalı ile akışın durumu etkine dönünce iletmelidir. Ayrıca verici aynı özneyi etkileyen ardışık olayları tutuyorsa, bu olayların üretildikleri zaman sırasına göre iletilmesini sağlamak zorundadır ya da yalnızca aynı özneyi etkileyen önceki olayların işlenmesini gerektirmeyen son olayları göndermek zorundadır.

Yani özne başına sıralama garantisi zorunludur, küresel sıralama değil. Bu, Argus'un yayın kuyruğunu özne kimliğiyle bölümlemesini gerektirmektedir.

Etkinsizlik zaman aşımı vardır: alıcı etkinliği yoksa akış duraklatılabilir, devre dışı bırakılabilir ya da silinebilir.

Genel bir sıralama garantisi yoktur: olay alıcıları, doğrulama olayının senkron olarak ya da mevcut olay kuyruğuna göre belirli bir sırada iletileceğine bağımlı olmamalıdır.

### 5.2 Güvenlik bilgi ve olay yönetimi tümleştirmesi, kimlik sağlayıcılar ne göndermektedir

| Hedef | Format ya da mekanizma |
|---|---|
| Okta'dan Splunk Cloud'a | HTTP olay toplayıcısı, ham sistem günlüğü JSON'ı |
| Okta'dan AWS'e | Amazon EventBridge, yaklaşık 30 saniye gecikme, süzme yoktur |
| AWS Security Lake | Özel kaynak için zorunlu OCSF artı Apache Parquet |
| Auth0 | Günlük akışları, kiracı başına iki ya da üç, artı pazar yeri bağlayıcıları |
| Entra kimlik | Azure izleme, günlük analizi, olay merkezi ya da depolama hesabı |
| Eski sistemler | CEF, LEEF ile sistem günlüğü |

Satıcı normalize şemaları Splunk, Elastic, Chronicle ile Microsoft şemalarıdır; hepsi satıcıya özgüdür ile bağımlılık yaratmaktadır.

Argus'un çıktı stratejisi şudur: bir kanonik iç format, yani OCSF uyumlu, artı adaptörler. Adaptörler OCSF ile Parquet'ten S3'e, güvenlik olayı belirteci ile imzasından itmeli ve yoklamalı akışa, OTLP günlüklerine, HTTP olay toplayıcısına ile sistem günlüğü ve CEF'e yazmalıdır. Her adaptör 500 satırdan azdır. Kanonik formatı OCSF yapmak adaptör sayısını asgariye indirmektedir, çünkü Security Lake, Sentinel ile Splunk bu şemayı almaktadır.

### 5.3 Okta sistem günlüğü API'si ile taksonomisi

Katalogda 1.178 olay tipi bulunmaktadır; sayı doğrudan sayfadandır.

Adlandırma hiyerarşiktir ile nokta ayrıklıdır: üst, alt seviye ile eylem şeklindedir. Örnekler erişim isteği ile incelemesi, kullanıcı yaşam döngüsü, hesabı, kimlik doğrulaması ile oturumu, uygulama OAuth ile SAML olayları, uygulama yaşam döngüsü, politika oturum açma ile kural olayları, cihaz kaydı ile yaşam döngüsü, sistem olayları ile kuruluş hesabı olaylarıdır.

Olaylarda metadata etiketleri bulunmaktadır: olay kancasına uygun, değişiklik detayı içerir ile yalnızca yeni kimlik motorunda geçerli.

Tam katalog CSV olarak indirilebilmektedir. Sistem günlüğü tablosu arayüzden CSV olarak dışa aktarılabilmektedir.

Argus için ders şudur: 1.178 sayısı olgun bir kimlik sağlayıcının denetim taksonomisinin gerçek büyüklüğüdür. Ancak bu sayı 20 yıllık organik büyümenin ürünüdür. Argus sıfırdan yazıldığı için şunlar yapılmalıdır. Üst, alt seviye ile eylem hiyerarşisi benimsenmelidir; sorgu ile okunabilirlik içindir. Her olay tipi bir sıralama ile bir kayıt defterinde tanımlanmalı ile OCSF sınıfına ve varsa CAEP tipine statik olarak eşlenmelidir. Yetenek etiketleri eklenmelidir; hangi olayın kancaya ya da sinyal akışına uygun olduğu şemadan okunmalıdır. Katalog makine okunabilir olarak yayımlanmalıdır; bu bir uyum artefaktıdır ile hangi olayları günlüklüyoruz gerekçelendirmesini otomatikleştirmektedir.

### 5.4 Keycloak olay arayüzü, bilinen sınırlamalar

Keycloak resmî dokümantasyonu kullanıcı ile yönetici olaylarını, bir olay dinleyici arayüzünü, veritabanında saklamayı ile yapılandırılabilir sona ermeyi anlatmaktadır.

Veritabanına yazma bir performans sorunudur. Kanıtlar şunlardır.

Phase Two'nun 6 Temmuz 2026 tarihli yazısına göre olay yazımları istek işlemine binmektedir; olay yazımı kimlik doğrulamayla aynı işlemdedir ile giriş isteği eklemeyi beklemektedir. Olay tablosu on milyonlarca ya da yüz milyonlarca satırda şema değişikliğini riskli kılmaktadır. Sona erdirme toplu silmesi yazma yoğun tabloya karşı çalışmakta ile kilit çekişmesi ve giriş çıkış tepesi yaratmaktadır. Analitik için tam tablo taraması gerekmektedir.

Aynı şirketin 1 Ağustos 2025 tarihli kullanıcı olayları yazısına göre temizleme sırasında büyük hacimlerin aynı anda silinmesi performans sorunlarına ya da kesintiye yol açabilmekte ile veritabanını fiilen kilitleyip devasa gecikme sorunları yaratabilmektedir. Önerilen küçük yığınlarla elle bir temizleme betiği ya da saklama penceresini yavaşça daraltmaktır.

Diğer bulgular şunlardır: olay tablosunda sınırlı indeksleme vardır; uzun zaman aralığı ya da karmaşık süzgeç kombinasyonlarında sorgu performansı tablo büyüdükçe bozulmaktadır. Bütünlük yoktur: veritabanı erişimi olan herkes satırları değiştirebilmekte ya da silebilmektedir, ki uyum kanıtı için kabul edilemezdir. Öneri veritabanı olay deposunu yedi ile 30 günlük operasyonel arama için kullanmak, uzun saklama ile uyum için harici bir sistem kullanmaktır.

Bu, Argus'un en somut rekabet avantajıdır. Keycloak'ın denetimi istek yolunda senkrondur, kurcalama kanıtlı değildir, temizlemesi veritabanını kilitlemektedir ile analitik yapılamamaktadır. Argus dördünü de yapısal olarak çözebilir.

---

## 6. Kullanıcıya görünen denetim

### 6.1 Büyük sağlayıcıların yaklaşımı

Google'ın cihazlar sayfası, kullanıcının Google hesabına yakın zamanda giriş yaptığı ya da yapmış olduğu bilgisayarları, telefonları ile diğer cihazları göstermektedir; kapsam son birkaç haftadır. Gösterilen alanlar cihaz tipi ile adı, oturum bilgisi, son iletişim zaman damgası, ki dikkat edilmelidir, bu giriş zamanı değil cihaz veya oturumla Google sistemleri arasındaki son iletişim zamanıdır, oturum durumu ile yaklaşık konumdur. Aksiyonlar cihaz detayını görüntüleme, çıkış yapma ile aynı cihazdaki birden fazla oturumu ayrı yönetmedir.

GitHub'ın kullanıcı hesabı güvenlik günlüğü giriş ile çıkışı, başarısız kimlik doğrulamayı, parola ile SSH anahtarı değişikliklerini, iki faktörlü olayları ile OAuth belirteci verme ve iptallerini kapsamaktadır. Adlandırma kategori ile operasyon şeklindedir. Kategorileri kimlik doğrulama ile erişim, hesap yönetimi, depo operasyonları, iş birliği, güvenlik özellikleri, eylemler, faturalama ile sponsorluklar, uygulamalar ile tümleştirmeler ve çeşitli ürün alanlarıdır. Organizasyon ile kurumsal denetim günlüğü ayrı bir şeydir; kimin ayarları, izinleri ya da üyelikleri değiştirdiğini göstermektedir. Kullanıcı güvenlik günlüğünün saklama süresi ile dışa aktarım seçeneği dokümante edilmemiştir.

Apple'ın kullanıcıya gösterilen giriş geçmişi için birincil kaynak doğrulanamamıştır.

Ortak desen şudur.

1. Aksiyon odaklıdır, bir arşiv değildir. Google son birkaç haftayı göstermekte ile yanına bir çıkış düğmesi koymaktadır. Amaç adli değil hesap kurtarma ile tepkidir.
2. Alan seti asgaridir: ne, ne zaman, nereden yaklaşık olarak ile hangi cihaz.
3. Konum yaklaşıktır; Google tam IP göstermemekte, GitHub göstermektedir.
4. İki ayrı sistem vardır: kullanıcı güvenlik günlüğü organizasyon denetim günlüğünden farklıdır.

### 6.2 GDPR 15. ile 20. maddeleriyle ilişkisi, önemli bir düzeltme

On beşinci madde, yani erişim hakkı, işleme amaçlarını, ilgili kişisel veri kategorilerini, alıcıları ile alıcı kategorilerini, özellikle üçüncü ülkeleri, saklama süresini, hakları, şikâyet yolunu, verinin kaynağını ile otomatik karar vermeyi kapsamaktadır. Elektronik bir talepte bilgi yaygın kullanılan elektronik bir biçimde sağlanmalıdır. Giriş geçmişi bu maddede ayrı bir kategori olarak sayılmamakta ancak işleniyorsa ilgili kişisel veri kategorileri altına girmektedir.

Yirminci madde, yani taşınabilirlik, kişinin bir veri sorumlusuna sağladığı kişisel veriyi kapsamaktadır; koşulları rıza ya da sözleşme temelli olması ile otomatik araçlarla işlenmesidir. Format yapılandırılmış, yaygın kullanılan ile makine okunabilir olmalıdır. Teknik olarak mümkünse doğrudan veri sorumlusundan veri sorumlusuna transfer yapılmalıdır.

Kritik nüans şudur: sağladığı ifadesi gözlemlenen veriyi kapsamaktadır. Çalışma grubunun otomatik bireysel karar verme ile profilleme kılavuzu, 3 Ekim 2017'de kabul edilmiş ile 6 Şubat 2018'de revize edilmiştir; PDF indirilip metni çıkarılmıştır ile açıkça şunu söylemektedir.

> *"This differs from the right to data portability under Article 20 where the controller only needs to communicate the data provided by the data subject or observed by the controller and not the profile itself."*

Aynı belge veri kategorilerini üçe ayırmaktadır: doğrudan ilgili kişilerce sağlanan veri, kişiler hakkında gözlemlenen veri ile türetilmiş veya çıkarımsal veri.

Yani giriş geçmişi gözlemlenen veridir ile yirminci madde kapsamındadır. Daha önceki tespit doğrudur ile şimdi birincil bir kaynakla desteklenmiştir. Türetilmiş veri, yani risk skoru ile davranışsal profil, kapsam dışıdır.

Argus'ta bunun karşılığı şudur: ham denetim olayları, yani giriş zamanı, IP, cihaz ile sonuç taşınabilirdir; risk skorları ile anomali sinyalleri taşınabilir değildir ve kullanıcıya da gösterilmemelidir, çünkü tersine mühendislik riski taşımaktadır. Bu ayrım şemada bir taşınabilirlik bayrağıyla kodlanmalıdır.

### 6.3 Kullanıcıya gösterilenle güvenlik operasyonlarına gösterilenin farkı

| Boyut | Kullanıcıya, kendin yap | Güvenlik operasyonlarına |
|---|---|---|
| Zaman penceresi | Son 30 ile 90 gündür; Google'da birkaç haftadır | Tam saklama süresidir, 12 ay ve üstü |
| Olay kapsamı | Kendi hesabıdır; başarılı ile başarısız kimlik doğrulama, kimlik bilgisi değişimi ile oturumdur | Tüm kiracıdır; ayrıca yönetici, yapılandırma, politika, token ile üst denetim olaylarıdır |
| Konum | Şehir ya da ülke düzeyindedir | Tam IP, otonom sistem numarası, coğrafya ile vekil sinyalleridir |
| Risk sinyalleri | Gösterilmemektedir; tersine mühendislik riskidir | Tamdır |
| Diğer kullanıcılar | Asla gösterilmemektedir | Kiracı kapsamında hepsidir |
| Aksiyon | Çıkış yapma, kimlik bilgisi iptali ile bu ben değildim bildirimidir | Sorgulama, korelasyon ile dışa aktarımdır |
| Format | İnsan okunabilir arayüz artı taşınabilirlik dışa aktarımıdır | OCSF, güvenlik olayı belirteci ile Parquet'tir |
| Hız sınırı | Sıkıdır; numaralandırma ile kazımaya karşıdır | Gevşektir, API anahtarıyladır |
| Gecikme | Yakın gerçek zaman kabul edilebilirdir | Yakın gerçek zaman istenmektedir |
| Erişimin kendisi günlüklenir mi | Evet | Evet |

Ek bir güvenlik notu gerekmektedir: kullanıcıya görünen denetimin kendisi bir saldırı yüzeyidir. IP ile konum göstermek, hesabı ele geçirmiş bir saldırgana kurbanın hareketlerini göstermektedir. Google'ın yaklaşık konum kullanması muhtemelen bilinçlidir. Argus'ta kullanıcı görünümünde IP maskelenmeli, yani yalnızca alt ağ ya da şehir gösterilmeli; tam IP yalnızca erişim hakkı dışa aktarımında verilmelidir.

---

## 7. Argus için somut tasarım kararları

K1. Düz yalnızca ekleme artı yaklaşık bir saniyelik Merkle denetim noktası kararı doğrudur; olay başına özet zinciri tamamen bırakılmalıdır. Crosby ile Wallach'ın tablosunda taahhüt imzalama ekleme maliyetinin %83,3'üdür ile tek başına saniyede 2.100 olay tavanı getirmektedir; 16'da bir imzayla saniyede 1.750'den yaklaşık 17.000'e çıkılmaktadır. Ajan uçuş kaydedici özet zincirinin medyan gecikmeyi altı mikrosaniyeden 48 mikrosaniyeye çıkardığını, Merkle yığınlamanın üstüne yalnızca 0,6 mikrosaniye eklediğini göstermektedir.

K2. Denetim noktası aralığı azami birleştirme gecikmesi olarak ilan edilmeli ile bir hizmet seviyesi taahhüdü yapılmalıdır. RFC 9162'nin kavramına göre günlük, imzalı bir zaman damgası verdikten sonra girdiyi ağaca dahil etmeyi taahhüt etmektedir. Argus için bu bir saniye ya da altı olmalıdır. Let's Encrypt bunu fiilen sıfıra indirmiştir; Argus da yüksek değerli olaylar, yani yönetici ile kimlik bilgisi değişimi için senkron denetim noktası modu sunabilir.

K3. Özet zinciri yerine geçmiş ağacı ya da döşeli günlük yapısı kullanılmalıdır; kanıt boyutu içindir. Özet zincirinde artımlı ile üyelik kanıtı doğrusal, geçmiş ağacında logaritmanın karesi mertebesindedir. 80 milyon olaylı bir günlükte rastgele bir olayın kanıtı özet zincirinde 800 megabayt, geçmiş ağacında üç kilobayttır. Argus'un doğrulama API'si ancak logaritmik bir yapıyla kullanılabilirdir.

K4. Sıralama ile bütünleştirme ayrılmalıdır, yani Tessera modeli. Sıralama dayanıklı bir indeks atamakta, bütünleştirme arka planda Merkle'a birleştirmektedir. Yerel NVMe üzerinde Tessera saniyede 10.000 yazma sorgusunu yedi çekirdekle karşılamaktadır; bu, sıralama ile bütünleştirme yapan tam bir döşeli günlüğün değeridir ile Argus için gerçekçi bir hedef büyüklüğüdür. Önceden burada çıplak ekleme ölçümüyle bir karşılaştırma yapılmaktaydı; o ölçüm bu rakamla kıyaslanabilir değildir. Taşınan sonuç şudur: sıralama ile bütünleştirme ayrımı, denetim noktası eklemenin iş hacmini öldürmediğini göstermektedir.

K5. İmzalama ayrı bir çekirdeğe ya da donanım güvenlik modülüne devredilmeli ile ekleme yolundan çıkarılmalıdır. Crosby'ye göre imza devredilince saniyede 1.750'den 10.500 olaya çıkılmaktadır. Argus'ta denetim noktası imzalama ayrı bir görevde olmalı ile ekleme yolu asla imza beklememelidir.

K6. Denetim noktaları dışarı yayımlanmalıdır, yani tanıklara ya da dedikodu ağına; yoksa bütünlük iddiası boştur. Crosby'nin ifadesiyle güvenilmez bir günlükleyici, farklı anlık görüntülerin geçmiş hakkında tutarsız iddialarda bulunmasını sağlamakta serbesttir. Ayrıca PostgreSQL süper kullanıcısı her koruma katmanını aşabilmektedir. Yayın hedefleri müşteri kancası, nesne kilitli S3 ile isteğe bağlı bir açık şeffaflık günlüğüdür. Bu, Keycloak'ın veritabanı erişimi olan herkesin satırları değiştirebilmesi zaafına verilen doğrudan cevaptır.

K7. PostgreSQL yalnızca ekleme üç katmanda zorlanmalı ile kesme öncesi tetikleyici unutulmamalıdır: güncelleme ile silme yetkisi her rolden geri alınmalı, güncelleme ile silme öncesi satır seviyesi bir tetikleyici konulmalı ile kesme öncesi ifade seviyesi bir tetikleyici eklenmelidir. Satır seviyesi tetikleyiciler kesmede ateşlenmemektedir; bu, yalnızca ekleme iddiasındaki en yaygın sessiz deliktir.

K8. Denetimin pahalı işi istek işleminden çıkarılmalı ancak kabulü çıkarılmamalıdır. Keycloak'ın birinci arızası doğru bir teşhistir: olay yazımları istek işlemine binmekte ile giriş isteği eklemeyi beklemektedir.

Bu maddenin önceki hâli yanlıştı. Önceden denetim olayının sınırlı ile geri basınçlı bir bellek içi kuyruğa yazılacağı, kuyruk dolarsa isteğin reddedileceği söylenmekteydi. Kuyruğu sınırlamak taşmayı önlemekte ancak süreç çökmesini karşılamamaktadır: iş değişikliği kalıcılaşmakta, kullanıcı başarılı yanıt almakta ile olay bellekte beklerken süreç ölürse değişiklik kalıcı olmakta ancak denetim kaydı bulunmamaktadır. İlgili kontrollerin tümünü kapsama gereği tam olarak bunu yasaklamaktadır. Ayrıca bu, hemen üstteki K4 ile çelişmekteydi; K4 sıralamanın dayanıklı bir indeks attığını söylemektedir.

Doğrusu iki aşamayı ayırmaktır. Birincisi kalıcı kabuldür ile aynı işlemdedir: iş değişikliğiyle atomik olarak asgari bir giden kutusu satırı yazılmalıdır. Ya ikisi de olmalı ya hiçbiri. Maliyeti tek bir küçük eklemedir, Merkle ya da imza değildir. İkincisi pahalı işlemedir ile arka plandadır: Merkle birleştirme, denetim noktası imzalama ile dışa yayın kuyruk üzerinden, istek yolunun dışında yürümelidir. Bu kuyruk bellekte olabilir, çünkü kaybı yalnızca gecikme yaratmakta, kayıt kaybı yaratmamaktadır.

Ayrıca tanımlanması gereken bir nokta vardır: başarısız giriş gibi kalıcılaşmış bir iş değişikliği bulunmayan olayların kalıcılığı ayrı bir kuraldır, çünkü atomik bağlanacağı bir işlem yoktur. Bu olaylar için kabul noktası açıkça seçilmelidir. Karar satırı §1'in birinci bölümündeki 23. maddedir; statüsü §1'in 10.3 bölümündedir.

K9. Saklama, bölüm düşürme ya da ayırmayla yapılmalı, asla toplu silmeyle yapılmamalıdır. Keycloak'ın temizlemesi veritabanını fiilen kilitlemekte ile devasa gecikme sorunlarına yol açmaktadır. Argus'ta günlük ya da haftalık aralık bölümleri kullanılmalı, eşzamanlı ayırmayla ayrılmalı, S3'e arşivlenmeli ile sonra düşürülmelidir.

K10. Katmanlama şöyle olmalıdır: PostgreSQL sıcak katman, 30 ile 90 gün; OCSF ile Parquet biçiminde S3 soğuk katman, süresiz; ile isteğe bağlı ClickHouse analitik katmanı. Phase Two'nun kanıtlanmış boru hattıdır; ClickHouse yaklaşık 14 kat sıkıştırmakta ile bir yıllık giriş eğilimi sorgusu onlarca milisaniyede dönmektedir. Onların öğrendiği ders şudur: ClickHouse tablo depolaması S3'te tutulmamalıdır, çünkü birleştirmeler küme başına saniyede 150 istek üretmiştir; yerel NVMe kullanılmalıdır.

K11. Soğuk katman OCSF ile Parquet biçiminde yazılmalı ile bedavaya AWS Security Lake uyumu kazanılmalıdır. Özel kaynak sözleşmesi tam olarak budur. Ayrıca bu şema birçok platformda alınmaktadır. Sürüm uyumluluğu yapılandırılabilir yapılmalıdır: Security Lake hâlâ eski şema sürümlerini kullanmaktadır.

K12. OCSF kayıt bütünlüğü profili benimsenmelidir; Merkle modeliniz için hazır bir tel formatıdır. Kanıtlama nesnesi zincir tanımlayıcısı, parmak izi, önceki olay, imzalar ile otorite tanımlayıcısı alanlarını taşımaktadır. Çoklu kanıtlama desteklenmektedir. Argus'un denetim noktası, olaya gömülü bir olay başına zincir yerine ayrı bir kanıtlama olarak ifade edilebilmektedir.

K13. Kanonik iç şema OCSF kimlik ile erişim yönetimi sınıfları olmalı; güvenlik olayı belirteci yalnızca dışa yayın için kullanılmalıdır. Kimlik doğrulama sınıfının zorunlu alanları asgari sözleşmedir; etkinlik, protokol, çok faktörlü bayrağı, giriş tipi ile durum alanları doğrudan Argus alanlarına eşlenmektedir. Belirteç bir depolama formatı yapılmamalıdır; base64 ek yükü ile olay başına imza getirmektedir, ki K1'in reddettiği şeydir.

K14. Benzersiz tanımlayıcı, işlem tanımlayıcısı ile olay gerçekleşme zamanı üçlüsü şemada birinci sınıf yapılmalıdır. RFC 8417'ye göre benzersiz tanımlayıcı etkisizleştirme ile tekilleştirme içindir, işlem tanımlayıcısı korelasyon içindir ile gerçekleşme zamanı kayıt zamanıyla karıştırılmamalıdır. Argus'ta üç farklı zaman damgası olmalıdır: gerçekleşme, kayıt ile denetim noktası zamanı. Adli analizde bu ayrım kritiktir.

K15. Belirteç yayınında özne başına sıralama garantisi zorunludur. Şartnameye göre verici, aynı özneyi etkileyen olayları üretildikleri sıraya göre iletmek ya da yalnızca son olayları göndermek zorundadır. Yayın kuyruğu özne kimliğiyle bölümlenmelidir; küresel sıralama gerekmemektedir ile maliyetlidir.

K16. İki ayrı yayın kanalı olmalıdır: sekiz tipli, aksiyon odaklı CAEP akışı ile tam taksonomili, kayıt odaklı denetim akışı. CAEP'in sekiz tipi Argus'un iç olay evreninin küçük bir alt kümesini kapsamaktadır; başarısız girişin ya da bir yöneticinin istemci sırrını döndürmesinin karşılığı yoktur. Aynı olay yolu, iki adaptör ile ortak işlem tanımlayıcısı kullanılmalıdır. Yoklamalı teslim varsayılan olmalıdır, ki şartnamenin kendi varsayılanıdır.

K17. Denetimde örnekleme yasaktır; yalnızca olay seçimi vardır. PCI DSS tüm bireysel erişimi ile tüm ayrıcalıklı işlemleri istemektedir. NIST olay tipi seçimine izin vermektedir, ki gerekçelendirilmiş ile periyodik gözden geçirilendir; olay tipinin örneklenmesine değil. Telemetri yolunda örnekleme serbest ile zorunludur. İki yol asla aynı boru hattına konulmamalıdır.

K18. Denetim günlüğüne erişim de bir denetim olayı üretmelidir. PCI DSS tüm denetim izlerine erişimin günlüklenmesini istemektedir. Sonsuz döngü riskine karşı üst denetim ayrı bir zincirde ile birleştirilmiş olmalıdır, yani sorgu başına bir kayıt, sonuç satırı başına değil. En sık atlanan gereksinimdir.

K19. Kriptografik bütünlük orta temel çizgide zaten zorunludur; inkâr edilemezlik varsayılan yapılmalıdır. İlgili geliştirme orta ve üstü temel çizgidedir; beşinci revizyon kurcalama alarmı eklemiştir; inkâr edilemezlik yüksek seviyededir. Kimlik sağlayıcı tanım gereği yüksek seviyeli sistemlerin kimlik kaynağıdır; dolayısıyla denetim noktaları yalnızca özetlenmemeli imzalanmalıdır.

K20. Denetim içeriği ile PCI'nin birleşik asgari alan seti şemanın değişmez çekirdeği olmalıdır: olay tipi, ne zaman, nerede, kaynak, sonuç, özne ile nesne kimliği ile etkilenen kaynak kimliği. Mahremiyet temel çizgisi kişisel veriyi sınırlamayı emretmektedir; bu yüzden her alan kişisel veri mi değil mi ile saklama sınıfı etiketleriyle işaretlenmelidir, ki K22'yi mümkün kılsın.

K21. Saklama süresi Argus'un değil kiracının kararıdır; mekanizma kiracı ile olay sınıfı başına sunulmalıdır. Çelişki gerçektir: PCI 12 ay, CNIL altı ay ile bir yıl arası, GDPR depolama sınırlaması. Sektör deseni Okta'da 90 gün, Entra'da 30 gün ile Auth0'da bir ile 30 gündür; hiçbir büyük kimlik sağlayıcı PCI'nin 12 ayını kendi içinde karşılamamakta ile hepsi akışlı dışa aktarıma devretmektedir. Argus da bu modeli benimsemeli ancak daha uzun bir sıcak pencere sunarak farklılaşabilir.

K22. Olay iskeleti kişisel veriden ayrılmalıdır: iskelet uzun, kişisel veri kısa yaşamalıdır. PCI'nin 12 ayı olay izine, CNIL'in altı ayı kişisel veriye yöneliktir. Argus'ta bir denetim olayı tablosu takma adlı özne kimliği, olay tipi, sonuç ile zaman damgasını 12 aydan uzun tutmalı; bir denetim olayı kişisel veri tablosu IP, kullanıcı aracısı ile e-postayı özne başına anahtarla şifreli tutup altı ayda kripto parçalamalıdır. İkisi de aynı Merkle ağacında olmalı ile özet şifreli metin üzerinden alınmalıdır. Bu, K23'ün ön şartıdır.

K23. Kripto parçalamada özet şifreli metin üzerinden alınmalı ancak bu GDPR silmesi diye pazarlanmamalıdır. Desen doğrudur ile uygulanmaktadır: özne başına anahtar, anahtar materyalinin boşa çekilmesi, anahtar referansı mezar taşının kalması, tek bir değişmez silme olgusu satırının eklenmesi ile deftere dokunulmaması. Ancak kurul kılavuzuna göre takma adlı veri ancak anonimlik koşulları karşılanıyorsa anonim sayılabilmektedir; anahtar silmek otomatik anonimleştirme değildir. Dokümantasyonda bu, günlük içeriğinin geri döndürülemez kimliksizleştirilmesi ile veri sorumlusunun kendi etki değerlendirmesine tabi olarak konumlandırılmalıdır.

K24. Rust yığını izleme cephesi artı OpenTelemetry günlükleri ve metrikleri, ki kararlıdır, artı izler, ki betadır ve dikkatli kullanılmalıdır, şeklinde olmalıdır. Asgari desteklenen Rust sürümü 1.75'tir. Hepsi birinci ana sürüm öncesidir, birlikte sürümlenmektedir ile kırıcı değişiklikler küçük sürümlerde gelmektedir; kütüphane kod tabanına yayılmamalı ile kendi ince cephenizin arkasına konulmalıdır.

K25. Metrik için OpenTelemetry metrikleri seçilmelidir, metrik cephesi değil. Metrik API'si ile geliştirme kiti zaten kararlıdır; tek hatta günlük, metrik ile iz korelasyonu sağlanmaktadır; kiracıya kendi uç noktanıza gönderelim demek satılabilir bir özelliktir. Cephenin tek avantajı olan arka uç değiştirme, toplayıcıyla zaten çözülmektedir.

K26. Metrikte kiracı etiketi olmamalı ile kiracı kırılımı analitik katmanın özet tablolarından gelmelidir. Bir milyon aktif seri yalnızca baş blok için dört ile altı gigabayt bellek demektir; varsayılan kırılım beş milyon seriye, yani 20 ile 30 gigabayta çıkmaktadır ki yıkıcıdır. Çözümler örnekleyicilerle histogram kovasına iz kimliği iliştirmek, yerel histogramlarla seri sayısını yapısal düşürmek, kiracı kırılımını beş dakikalık özet tablolarından almak ile en fazla yaklaşık 50 büyük kiracı için izin listeli bir metrik seti tutmaktır.

K27. Kişisel veri ya da sır taşıyan hiçbir tipte türetilmiş hata ayıklama olmamalı ile bu sürekli tümleştirmede zorunlu kılınmalıdır. Sır kütüphanesi görüntüleme ile hata ayıklama arayüzlerini gerçeklememekte, açık bir çağrı istemekte, düşürmede belleği sıfırlamakta ile varsayılan olarak serileştirilememektedir. Rust'a özgü tuzak şudur: türetilmiş hata ayıklama, yapıya sonradan eklenen bir yenileme token'ı alanını hiçbir günlük satırı değişmeden sızdırmaktadır. Sıfırlama elden gelenin en iyisidir, bir garanti değildir.

K28. Telemetride takma kullanıcı kimliği, denetimde gerçek kullanıcı kimliği kullanılmalıdır. Anlamsal sözleşmelerin 1.44 sürümünde ilgili alanların durumu değişkendir ile bazıları kullanımdan kaldırılmıştır. Sözleşmelere sabit bağımlılık kurulmamalı ile bir eşleme katmanı konulmalıdır.

K29. Kendi olay taksonominiz kurulmalıdır; OpenTelemetry'de kimlik ile kimlik doğrulama sözleşmesi yoktur. Okta'nın üç parçalı hiyerarşisi benimsenmeli, ki Okta'da 1.178 olay tipi vardır ve olgun bir kimlik sağlayıcının gerçek büyüklüğüdür; her tip bir sıralama ile kayıt defterinde tanımlanıp OCSF sınıfına ve varsa CAEP tipine statik eşlenmeli; yetenek etiketleri eklenmeli; ile katalog makine okunabilir yayımlanmalıdır. Bu, hangi olayları neden günlüklüyoruz gerekçelendirmesini otomatikleştiren bir uyum artefaktıdır. Olay adları dinamik değer içermemelidir.

K30. Kullanıcıya görünen denetim aksiyon odaklı, 30 ile 90 günlük, IP maskeli ile risk sinyalsiz olmalıdır. Google son birkaç haftayı ile bir çıkış düğmesini, GitHub kategori ile operasyon adlandırmasıyla giriş, iki faktörlü, anahtar ile OAuth olaylarını göstermektedir. Kullanıcı görünümünde IP maskelenmelidir; hesabı ele geçirmiş bir saldırgana kurbanın hareketleri gösterilmemelidir. Risk skorları hiç gösterilmemelidir.

K31. Taşınabilirlik dışa aktarımında gözlemlenen veri dahil, türetilmiş veri hariç olmalı ile bu şemada bir bayrakla kodlanmalıdır. Çalışma grubu kılavuzuna göre veri sorumlusu yalnızca veri öznesinin sağladığı ya da kendisinin gözlemlediği veriyi iletmek zorundadır, profilin kendisini değil. Giriş geçmişi gözlemlenen veridir ile taşınabilirdir; risk skoru ile profil türetilmiştir ile taşınabilir değildir. Format yapılandırılmış, yaygın kullanılan ile makine okunabilir olmalıdır; JSON, tercihen OCSF.

K32. pgaudit birincil denetim kaynağı yapılmamalı ile ikincil bir veritabanı seviyesi kontrolü olarak kullanılmalıdır. Denetim günlüklemesi elden gelenin en iyisidir ile işlemsel değildir; çökmede kayıt kaybolmaktadır, bu tek başına uyum seviyesinde denetim için diskalifiye edicidir. Ayrıca kesme desteklenmemekte, süper kullanıcı denetimi güvenilmez olmakta ile muazzam hacimde günlük üretebilmektedir. Değeri Argus veritabanına uygulama dışından yapılan doğrudan erişimi yakalamaktır.

K33. Yönetilen defter hizmetlerine bağımlılık kurulmamalıdır. AWS QLDB 31 Temmuz 2025'te, resmî bir duyuru bile yapılmadan destek dışı kalmıştır. Önerilen göç yolu kriptografik doğrulanabilirliği kaybettirmektedir. Ders şudur: kriptografik defter ayrı bir ürün kategorisi olarak ticari bir başarısızlıktır; müşteriler ayrı bir veritabanı değil mevcut veritabanında bir bütünlük özelliği istemektedir. Argus'un kararı bu dersle uyumludur.

K34. Yıllık günlük parçaları ile statik döşeme arşivi kullanılmalıdır, yani ikinci sürüm kayıt günlüğü deseni. Yıl başına yeni bir parça açılmakta, eski parça dondurulup statik döşeme olarak arşivlenmekte ile döşemeler değişmez, içerik adresli ve içerik dağıtım ağından önbeleklenebilir olmaktadır. Bu, hem Merkle ağacının sınırsız büyümesini hem doğrulama maliyetini sınırlamaktadır. Argus'ta kiracı çarpı yıl parçalaması yapılmalı ile dondurulmuş parçanın son denetim noktası sonsuza dek doğrulanabilir kalmalıdır.

K35. Tek bir kanonik format ile ince adaptörler kullanılmalıdır; her adaptör 500 satırdan az olmalıdır. Hedefler S3'e OCSF ve Parquet, itmeli ile yoklamalı sinyal akışına belirteç ve imza, OTLP günlükleri, HTTP olay toplayıcısı ile eski sistemler için sistem günlüğü ve CEF'tir. CEF ölmemiştir ancak ağ güvenliği merkezli ile tek satır odaklıdır; OCSF haleftir. Kanonik formatı OCSF yapmak adaptör sayısını ile dönüşüm kaybını asgariye indirmektedir. Okta'nın olay süzmesi desteklenmiyor kısıtı tekrarlanmamalıdır; Argus akışlarında olay tipi süzgeci bulunmalıdır.

K36. Merkle alan ayrımı doğru yapılmalıdır: yaprak sıfır bayt, düğüm bir bayt önekiyle. Bu önekler ikinci ön görüntü direnci için zorunludur; atlamak yaprakla düğümü karıştırma saldırısına açmaktadır. Ayrıca imzalı ağaç başlığı kuralı şudur: her sonraki zaman damgası bir öncekinden daha yeni olmak zorundadır.

K37. Kanıt üretiminde yerellik mimarinin merkezine konulmalıdır. Crosby'nin tablosunda üyelik kanıtı yerellikle saniyede 8.600, yerelliksiz 32'dir; 269 kat farktır. Bu, Merkle düğümlerinin disk yerleşiminin, yani son sıra gezinme, sabit boyutlu düğüm ile doğrudan erişimin, kanıt API'sinin kullanılabilirliğini tek başına belirlediği anlamına gelmektedir. Değişken boyutlu olay içeriği ayrı bir tek yazımlık, yalnızca ekleme değer deposunda tutulmalı ile ağaç yaprakları bir uzaklık taşımalıdır.

K38. Bütünlük çıpası için blok zincirine gerek yoktur; tanık yeterlidir. Ölçüme göre ikinci katman çıpalama 100 bin olay başına 2,30 dolar, birinci katman 6.885 dolardır. Önceki hesap çıplak ekleme ölçümünü sürekli hacim sayıp günde milyarlarca olay türetmekteydi; o sayı böyle çarpılamaz. Yön yine de sağlamdır: olay başına zincir üstü çıpalama maliyeti, herhangi bir ciddi kimlik sağlayıcı hacminde tanık ya da nesne kilidi alternatifinin yanında kabul edilemez kalmaktadır. Alternatif denetim noktasını müşteri kancasına, nesne kilitli S3'e ile isteğe bağlı üçüncü taraf bir tanığa yayımlamaktır. Ele geçirme penceresi aynı, maliyet yaklaşık sıfırdır.

---

## 8. Doğrulanamayanlar

1. Büyük kimlik sağlayıcıların gerçek günlük hacimleri doğrulanamamıştır. Okta, Auth0, Keycloak ya da Entra kimlik için kamuya açık, birincil kaynaklı bir saniyede olay ya da günde gigabayt rakamı bulunamamıştır. Sektör yalnızca saklama süreleri üzerinden konuşmaktadır. Tek somut kıyas 2009 tarihli çalışmadır ile o da o dönemin sistem günlüğüdür.
2. Okta sistem günlüğü API'sinin hız sınırları doğrulanamamıştır; dokümantasyon bunları panoya havale etmektedir.
3. GitHub kullanıcı güvenlik günlüğünün saklama süresi ile dışa aktarım seçeneği doğrulanamamıştır.
4. Apple'ın kullanıcıya gösterdiği giriş ile hesap etkinliği geçmişi doğrulanamamıştır; birincil kaynak bu oturumda getirilememiştir. Google ile GitHub deseni üzerinden genelleme yapılmıştır.
5. Splunk kimlik doğrulama veri modelinin tam alan listesi ile etiketleri doğrulanamamıştır; ilgili doküman iki farklı adreste 403 döndürmüştür.
6. SOC 2'nin sayısal günlük saklama gereksinimi doğrulanamamıştır; birincil kaynak bulunamamıştır. Pratikte bir yıllık gözlem penceresi yaygındır ancak bu bir denetim uygulamasıdır, normatif bir eşik değildir.
7. İzleme kütüphaneleri için nanosaniye seviyesinde yayımlanmış bağımsız bir kıyaslama doğrulanamamıştır; yalnızca niteliksel iddialar vardır. Argus'un hedef hızında araç makrosunun maliyeti kendiniz ölçülmelidir.
8. Tessera'nın varsayılan yığın boyutu ile denetim noktası aralığı değerleri doğrulanamamıştır; dokümanlar yapılandırma adlarını vermekte ancak varsayılanları belirtmemektedir.
9. İkinci sürüm kayıt günlüğünün somut maliyet düşüş yüzdesi ile sorgu hızı rakamları doğrulanamamıştır; duyuru yalnızca niteliksel ifadeler kullanmaktadır.
10. OCSF 1.9.0'ın tam sürüm notları doğrulanamamıştır; ilgili sayfa 404 döndürmüş ile bilgi liste sayfasından ve şema dosyalarından derlenmiştir. Sürüm ile tarih listeden doğrulanmıştır.
11. Taşınabilirlik kılavuzunun doğrudan metni kısmen doğrulanamamıştır; indirme denemesi başka bir belgeye yönlenmiştir. Ancak o belge aynı hukuki noktayı açıkça ifade etmektedir, bu yüzden K31'in dayanağı birincil ile geçerlidir; yalnızca etkinlik günlükleri ile arama geçmişi örneklerini içeren spesifik paragraf alıntılanamamıştır.
12. CNIL kararının tam metni doğrulanamamıştır; resmî duyuru sayfası doğrulanmış ancak kararın PDF'i getirilememiştir.
13. PCI DSS 4.0.1'in resmî metni doğrulanamamıştır; kurumun kendi PDF'i kayıt gerektirdiği için getirilememiş ile içerik ikincil ancak tutarlı kaynaklardan derlenmiştir. Sayısal eşikler birden fazla bağımsız kaynakta tutarlıdır.
14. CADF'in 2025 ile 2026'daki güncel benimseme durumu doğrulanamamıştır; standardın varlığı görülmekte ancak OpenStack dışında güncel bir kullanıcı ya da son yıllara ait bir güncelleme kanıtı bulunamamıştır.

---

## Kaynaklar

Standartlar ile RFC'ler şunlardır: RFC 8417 güvenlik olayı belirteci; RFC 9967 güvenlik olayı belirteçleri için SCIM profili; RFC 9162 sertifika şeffaflığı ikinci sürümü; OpenID CAEP 1.0 nihai sürümü; OpenID paylaşılan sinyaller çerçevesi 1.0 nihai sürümü; ile OpenID Foundation'ın üç paylaşılan sinyal şartnamesinin onaylandığına dair duyurusu.

OCSF kaynakları şunlardır: schema.ocsf.io üzerindeki 1.9.0 kategorileri, kimlik doğrulama sınıfı ile kayıt bütünlüğü profili sayfaları; ocsf-schema deposundaki ham kanıtlama nesnesi tanımı ile sürüm listesi; ile AWS Security Lake dokümanındaki şema sayfası.

Uyum ile mevzuat kaynakları şunlardır: NIST SP 800-53 beşinci revizyonun denetim ailesi kontrolleri; PCI DSS onuncu gereksinim ile günlük saklama analizleri; CNIL'in günlükleme tedbirleri tavsiyesi; Avrupa Veri Koruma Kurulu'nun 01/2025 sayılı takma adlaştırma kılavuzu; GDPR'ın 15. ile 20. maddeleri; ile çalışma grubunun otomatik karar verme ve profilleme kılavuzu.

Bütünlük ile şeffaflık günlüğü kaynakları şunlardır: Crosby ile Wallach'ın USENIX Security 2009 makalesi; ajan uçuş kaydedici çalışması; Tessera'nın performans ile genel bakış dokümanları; ikinci sürüm kayıt günlüğü duyurusu; Let's Encrypt'in bir yıllık değerlendirmesi; Filippo Valsorda'nın şeffaflık günlüğü çalıştırma yazısı; QLDB'nin kapanışına dair haberler; yalnızca ekleme deliği yazısı; pgaudit deposu ile PostgreSQL bölümleme dokümanı; ile kripto parçalama üzerine iki çalışma.

Kimlik sağlayıcı, ölçek ile güvenlik bilgi ve olay yönetimi kaynakları şunlardır: Phase Two'nun iki yazısı; Keycloak sunucu yönetim kılavuzu; Okta olay tipi kataloğu, saklama ile günlük akışı sayfaları; Auth0 günlük saklama sayfası; Microsoft Entra veri saklama sayfası; Query.ai'nin normalizasyon standartları analizi; DMTF ile OpenStack denetim sayfaları; ClickHouse gözlemlenebilirlik kılavuzu; ile denetim günlükleme üzerine iki yazı.

Rust ile OpenTelemetry kaynakları şunlardır: opentelemetry-rust deposu ile ilgili konu; anlamsal sözleşmeler sitesi ile ilgili öznitelik, olay ve konu sayfaları; performans kıyaslama şartnamesi; izleme ile sır kütüphanelerinin dokümanları ile ilgili güvenlik danışmanlığı; metrik cephesi ile Prometheus alıştırmaları; ile yüksek kardinalite üzerine üç yazı.

Kullanıcıya görünen denetim kaynakları Google'ın cihazlar ile son güvenlik etkinliği sayfası ile GitHub'ın güvenlik günlüğü olayları sayfasıdır.
