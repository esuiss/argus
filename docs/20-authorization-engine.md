# §20 — Yetkilendirme motoru

Bu bölüm `ARGUS.md` dosyasının 20. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§20 §X` referansları aynı anlamdadır.

## 0. Yönetici özeti: önce üç düzeltme

Birincisi, saniyenin 2,6 milyonda biri başına karar referansı gerçektir ancak yanıltıcıdır. arXiv'deki 2609.00267 numaralı çalışma mevcuttur: Dantuluri ile Sundi'nin 31 Ağustos 2026 tarihli, çok ajanlı büyük dil modeli sistemlerinde kimlik, yetkilendirme ile çalışma zamanı yönetişiminin ampirik boşluk analizi başlıklı yazısı. Ancak PDF'ten çıkarılan metodoloji şudur.

> "We implement the broker in Python (∼160 lines, standard library only). Tokens are HMAC-signed in the style of macaroons and OAuth Token Exchange"
> "Enforcement costs ∼2.6µs per authorization (∼3.9×10⁵ decisions/s) and a token exchange ∼5.4µs, measured over 2×10⁵ calls each on a laptop."

Bu bir ilişki tabanlı erişim kontrolü graf çözümlemesi değildir; bir yetenek token'ının koşullarının HMAC ile doğrulanmasıdır. Grafik yürüyüşü, veritabanı okuması ile ilişki çözümlemesi yoktur. 160 satırlık Python'un 2,6 mikrosaniyede yaptığı iş, OpenFGA ile SpiceDB'nin yaptığı işle aynı problem sınıfında değildir. Bu rakamı Argus'un ilişki tabanlı kontrol hedefi olarak almak bir kategori hatası olur. Doğru okuma şudur: yetki token'a gömülüyse doğrulama neredeyse bedavadır. Bu, Argus için gerçekten kullanışlı bir mimari sinyaldir ve 4.5'te ele alınmaktadır.

İkincisi, bir ile 10 milisaniye iddiasının gerçek kaynağı Zanzibar makalesidir ile koşulları çok spesifiktir. Google'ın kendi rakamı güvenli yolda 95. yüzdelik için 9,46 milisaniyedir. Ancak bu, tutarlılık belirteci 10 saniyeden eski olan istekler içindir. Belirteci taze olan, yani yakın zamanlı isteklerde 95. yüzdelik 60,0 milisaniyedir. Yani 10 milisaniye rakamı, tutarlılıktan feragat edilmiş yoldur.

Üçüncüsü, OpenFGA'nın güvenlik açığı sicili ciddi bir risk sinyalidir. OSV'den çekilen kayıtlara göre OpenFGA'nın 26 güvenlik danışmanlığı vardır ile bunların çoğu doğrudan yetkilendirme atlatma sınıfındadır. Yalnızca 2026'da yedi tanesi bulunmaktadır. Bu, bir kimlik sağlayıcının sıcak yoluna gömülecek bir bileşen için hafife alınacak bir istatistik değildir.

Karar kısaca şudur: Argus kendi ilişki tabanlı erişim kontrolü motorunu Rust'ta yazmalı ile harici bir motora bağımlı olmamalıdır; dış dünyaya AuthZEN politika karar noktası olarak konuşmalıdır; token'a gömme ile merkezî denetimi açıkça iki ayrı katman olarak sunmalıdır. Gerekçeler yedinci bölümdedir.

---

## Bölüm 1 — Zanzibar ve türevleri

### 1.1 Zanzibar makalesi, USENIX ATC 2019, birincil kaynaktan

Makale indirilmiş ile metni çıkarılmıştır. Aşağıdakiler makalenin kendi ifadeleridir.

#### İlişki demeti grameri

```
⟨tuple⟩   ::= ⟨object⟩ '#' ⟨relation⟩ '@' ⟨user⟩
⟨object⟩  ::= ⟨namespace⟩ ':' ⟨object id⟩
⟨user⟩    ::= ⟨user id⟩ | ⟨userset⟩
⟨userset⟩ ::= ⟨object⟩ '#' ⟨relation⟩
```

Birincil anahtar ad alanı, nesne kimliği, ilişki ile kullanıcıdan oluşmaktadır. Kullanıcı kimliği bir tam sayıdır, yani Google'ın iç kullanıcı kimliğidir; nesne kimliği bir dizgidir.

Kritik tasarım kararı makalenin kendi cümlesiyle şudur: *"Defining our data model around tuples, instead of per-object ACLs, allows us to unify the concepts of ACLs and groups and to support efficient reads and incremental updates."* Yani erişim denetim listesiyle grup aynı şeydir. Grup, üyelik semantiği taşıyan bir erişim denetim listesidir. Argus için doğrudan aktarılabilir bir ilkedir.

#### Yeni düşman problemi, makaledeki tam iki örnek

Makale bunu iki senaryoyla tanımlamaktadır.

> **Example A: Neglecting ACL update order**
> 1. Alice removes Bob from the ACL of a folder;
> 2. Alice then asks Charlie to move new documents to the folder, where document ACLs inherit from folder ACLs;
> 3. Bob should not be able to see the new documents, but may do so if the ACL check neglects the ordering between the two ACL changes.

> **Example B: Misapplying old ACL to new content**
> 1. Alice removes Bob from the ACL of a document;
> 2. Alice then asks Charlie to add new contents to the document;
> 3. Bob should not be able to see the new contents, but may do so if the ACL check is evaluated with a stale ACL from before Bob's removal.

Çözüm için iki özellik gerekmektedir; makale bunları iki temel tutarlılık özelliği olarak adlandırmaktadır. Birincisi dışsal tutarlılıktır: nedensel olarak ilişkili x ile y güncellemeleri sıralı zaman damgası almaktadır. İkincisi sınırlı bayatlıkla anlık görüntü okumasıdır: denetimin değerlendirme anlık görüntüsü, içerik güncellemesine atanan nedensel zaman damgasından daha eski olamaz.

Zanzibar bunu Spanner'ın TrueTime soyutlaması üzerine kurmaktadır: *"Zanzibar builds on Spanner's TrueTime abstraction to provide linearizable commit timestamps encoded as zookies."*

Yaşam süreli bir önbelleğin bunu neden çözemediği şudur: problem tazelik değil nedenselliktir. 10 saniyelik bir yaşam süresi, Bob'un çıkarılmasından 200 milisaniye sonra eklenen belgeyi korumaz, çünkü sorun sürenin uzunluğu değil iki olayın sırasının kaybolmasıdır. Tutarlılık belirteci, istemcinin bu içerik şu andan sonra yazılmıştır, o yüzden erişim listesini de en az o andan itibaren oku diyebilmesini sağlamaktadır. Bu, uygulamanın belirteci korunan kaynağın yanında saklamasını gerektirmektedir; yani belirteç yalnızca bir motor özelliği değil bir uygulama sözleşmesidir.

#### Leopard indeksleme sistemi

Devreye girme koşulu makalede nettir: *"Recursive pointer chasing during check evaluation has difficulty maintaining low latency with groups that are deeply nested or have a large number of child groups. For selected namespaces that exhibit such structure..."* Yani tüm ad alanları için değil, seçilmiş olanlar içindir.

Veri yapısı küme tipi, 64 bitlik küme kimliği ile eleman kimliğinden oluşan üçlülerdir. İki küme tipi vardır: gruptan gruba eşleme, ki kaynak ata grup ile hedef doğrudan ya da dolaylı alt gruptur; ile üyeden gruba eşleme, ki kaynak kullanıcı ile hedef doğrudan üyesi olduğu gruptur.

Üyelik testi şudur.

```
(MEMBER2GROUP(U) ∩ GROUP2GROUP(G)) ≠ ∅
```

Depolama şöyle anlatılmaktadır: *"Index tuples are stored as ordered lists of integers in a structure such as a skip list, thus allowing for efficient union and intersections among sets."*

Sistem üç parçalıdır: servis sistemi, çevrimdışı periyodik indeks oluşturucu ile çevrimiçi gerçek zamanlı artımlı katman.

Argus için ders şudur: bu, grup üyeliğinin bir erişilebilirlik problemi olduğu ile düzleştirilebileceği fikrinin kanonik ifadesidir. Düzleştirme sıralı tam sayı listeleri ile kesişimle yapılmaktadır; roaring bitmap'e çok yakın bir şeydir. Rust'ta bu, en verimli yapabileceğimiz işlerden biridir.

#### Üretim rakamları, Tablo 2 ile dördüncü bölüm, Aralık 2018, yedi günlük örneklem

Ölçek şöyledir.

| Metrik | Değer |
|---|---|
| İlişki demeti sayısı | İki trilyondan fazladır |
| Toplam veri | Yaklaşık 100 terabayttır |
| Ad alanı başına demet | Onlarcadan bir trilyona kadardır, medyan yaklaşık 15.000'dir |
| Ad alanı yapılandırma boyutu | Onlarcadan binlerce satıra kadardır, medyan yaklaşık 500 satırdır |
| Replikasyon | 30'dan fazla coğrafi lokasyonda tam replikasyondur |
| Sunucu | 10.000'den fazladır, birkaç düzine küme, medyan küme başına yaklaşık 500 sunucudur |
| Toplam istemci sorgu hızı | Saniyede 10 milyondan fazladır |
| Denetim tepe | Saniyede 4,2 milyondur |
| Okuma tepe | Saniyede 8,2 milyondur |
| Genişletme tepe | Saniyede 760 bindir |
| Yazma tepe | Saniyede 25 bindir |

Okuma yazma oranı iki mertebedir; bu, önbellek tasarımının neden bu kadar merkezî olduğunu açıklamaktadır.

Gecikme, Tablo 2'den, ortalama ile standart sapma, milisaniye cinsinden şöyledir.

| API | 50. yüzdelik | 95. yüzdelik | 99. yüzdelik |
|---|---|---|---|
| Güvenli denetim | 3,0 (0,091) | 9,46 (0,3) | 15,0 (1,19) |
| Güvenli okuma | 2,18 (0,031) | 3,71 (0,094) | 8,03 (3,28) |
| Güvenli genişletme | 4,27 (0,313) | 8,84 (0,586) | 34,1 (4,35) |
| Yakın zamanlı denetim | 2,86 (0,087) | 60,0 (2,1) | 76,3 (2,59) |
| Yakın zamanlı okuma | 2,21 (0,054) | 40,1 (2,03) | 86,2 (3,84) |
| Yakın zamanlı genişletme | 5,79 (0,224) | 45,6 (3,44) | 121,0 (2,38) |
| Yazma | 127,0 (3,65) | 233,0 (23,0) | 401,0 (133,0) |

Ayrıca Şekil 4, yani yedi günlük güvenli denetim eğrisi, 50, 95, 99 ile 99,9. yüzdelik tepe değerlerini yaklaşık 3, 11, 20 ile 93 milisaniye vermektedir.

Güvenli ile yakın zamanlı ayrımının tanımı şudur: replikasyon kalp atışı aralığı sekiz saniyedir. Tutarlılık belirteci 10 saniyeden eski olan istekler güvenlidir ile çoğunlukla bölge içinde servis edilmektedir. 10 saniyeden yeni olanlar yakın zamanlıdır ile sıklıkla bölgeler arası gidiş dönüş gerektirmektedir. Güvenli istekler yakın zamanlılardan iki mertebe daha fazladır.

Bu, raporun en önemli tek tablosudur. Zanzibar 10 milisaniyede denetim yapar cümlesi, ancak istemci 10 saniye bayat veriyi kabul ederse kaydıyla doğrudur. Tazelik istendiği anda 95. yüzdelik altı katına çıkmaktadır.

Erişilebilirlik üç yıl boyunca %99,999'un üzerindedir. Tanım şudur: güvenli için beş saniye, yakın zamanlı için 15 saniye eşiği içinde başarıyla yanıtlanan nitelikli uzak yordam çağrısı oranıdır ile 90 günlük pencerelerde yoklayıcılarla ölçülmüştür, canlı trafikle değil. Çeyrek başına iki dakikanın altında küresel kesinti vardır.

İç mekanikler, yani 4.4 bölümü, önbellek verimliliği hakkında çarpıcı bir gerçek vermektedir.

| Metrik | Değer |
|---|---|
| Tepe devredilmiş iç uzak yordam çağrısı | Saniyede 22 milyon, okuma ile denetim arasında yaklaşık eşit |
| Bellek içi önbellek araması | Saniyede yaklaşık 200 milyon, 150 milyonu denetim ile 50 milyonu okumadır |
| Denetim önbellek isabeti, devredilen taraf | %10, artı kilit tablosu %12 |
| Denetim önbellek isabeti, devreden taraf | %2, artı kilit tablosu %3 |
| Okuma önbellek isabeti, devredilen taraf | %24, artı kilit tablosu %9 |
| Okuma önbellek isabeti, devreden taraf | %1'in altındadır |
| Çok sıcak grup ön yüklemesi | Grupların binde biridir |
| Spanner'a giden okuma çağrısı | Saniyede 20 milyondur |
| Spanner okuma boyutu | Çağrı başına medyan 1,5 satır, 99. yüzdelik yaklaşık 1000 satırdır |
| Spanner okuma gecikmesi | Medyan 0,5 milisaniye, 95. yüzdelik iki milisaniyedir |
| Riskten korunmadan faydalanan | %1, yani saniyede 200 bindir |

Makalenin kendi yorumu şudur: *"While these hit rates appear low, they prevent 500K internal RPCs per second from creating hot spots."*

Argus için kritik ders şudur: Zanzibar'ın denetim önbelleği isabet oranı %10'dur. Önbellek burada bir gecikme optimizasyonu değil bir sıcak nokta korumasıdır. Kim önbellek koyarız ile %90 isabet alırız diyorsa Google'ın kendi verisiyle çelişmektedir. İlişki tabanlı denetimlerin anahtar uzayı, yani kullanıcı çarpı ilişki çarpı nesne, devasadır ile doğal olarak seyrektir.

Leopard performansı şudur: medyan saniyede 1,56 milyon sorgu, 99. yüzdelik saniyede 2,22 milyon sorgu; yanıt medyanda 150 mikrosaniyenin, 99. yüzdelikte bir milisaniyenin altındadır; artımlı katman medyanda saniyede yaklaşık 500, 99. yüzdelikte saniyede yaklaşık 1.500 indeks güncellemesi yapmaktadır.

Bu, gerçeklenmiş indeksin ham graf yürüyüşüne karşı üstünlüğünün sayısal kanıtıdır: 150 mikrosaniyeye karşı üç milisaniye, yani 20 kat.

### 1.2 OpenFGA, iç mimari ile 2026 durumu

Kimliği şudur: sürüm 1.19.0, 25 Ağustos 2026. CNCF kuluçka aşamasındadır, 28 Ekim 2025; kum havuzuna girişi 14 Eylül 2022'dir. CNCF proje sayfasındaki metrikler 2.548 katkıcı, 898 katkıda bulunan kuruluş ile 100 üzerinden 87 sağlık skorudur. Apache 2.0 lisanslıdır ile Go ile yazılmıştır.

#### En kritik mimari fark: tutarlılık belirteci yoktur

OpenFGA'nın kendi dokümanı şunu söylemektedir.

> "The Zanzibar paper has a feature called Zookies, which is a consistency token that is returned from Write operation. OpenFGA is considering a similar feature in future releases."

Bunun yerine iki modlu bir seçenek vardır.

| Mod | Davranış |
|---|---|
| `MINIMIZE_LATENCY`, varsayılan | "OpenFGA will serve queries from the cache when possible" |
| `HIGHER_CONSISTENCY` | "OpenFGA will skip the cache and query the database directly" |

Doküman açıkça uyarmaktadır.

> "If you write a tuple and you immediately make a Check on a relation affected by that tuple using MINIMIZE_LATENCY, the tuple change might not be taken in consideration if OpenFGA serves the result from the cache."
> "Always specifying HIGHER_CONSISTENCY will have a significant impact in performance."

Yani OpenFGA'da yeni düşman problemi çözülmemiştir; istemciye her istek için ya hızlı ya doğru seç ikilemi olarak devredilmiştir. Bu, Zanzibar'ın çözdüğü asıl problemin türevde kaybolmuş olması demektir. Argus gibi güvenlik kritik bir üründe bu bilinçli bir kabul olmalı ile bir kaza olmamalıdır.

Doküman bir hile bile önermektedir: uygulamanın kendi veritabanında değişiklik zaman damgası kontrol edilip hangi sorgunun hangi tutarlılık seviyesine ihtiyaç duyduğuna karar verilmelidir. Bu, aslında tutarlılık belirtecini elle uygulamak demektir.

#### Yapılandırma ile sabit limitler, varsayılanlarıyla

Bunlar Argus'un tasarım kısıtlarını anlamak için önemlidir, çünkü kendi motorumuzda bu limitleri biz seçeceğiz.

| Ayar | Ortam değişkeni | Varsayılan |
|---|---|---|
| Denetim sorgu önbelleği | `OPENFGA_CHECK_QUERY_CACHE_ENABLED` | false |
| Denetim önbellek boyutu | `OPENFGA_CHECK_QUERY_CACHE_LIMIT` | 10.000 |
| Denetim önbellek yaşam süresi | `OPENFGA_CHECK_QUERY_CACHE_TTL` | 10 saniye |
| Yineleyici önbelleği | `OPENFGA_CHECK_ITERATOR_CACHE_ENABLED` | false |
| Yineleyici önbelleği azami sonuç | `OPENFGA_CHECK_ITERATOR_CACHE_MAX_RESULTS` | 10.000 |
| Önbellek denetleyicisi | `OPENFGA_CACHE_CONTROLLER_ENABLED` | false |
| Önbellek denetleyicisi yaşam süresi | `OPENFGA_CACHE_CONTROLLER_TTL` | 10 saniye |
| Paylaşılan yineleyici | `OPENFGA_SHARED_ITERATOR_ENABLED` | false |
| Çözümleme derinliği | `OPENFGA_RESOLVE_NODE_LIMIT` | 25 |
| Çözümleme genişliği | `OPENFGA_RESOLVE_NODE_BREADTH_LIMIT` | 10 |
| Nesne listeleme son tarihi | `OPENFGA_LIST_OBJECTS_DEADLINE` | üç saniye |
| Nesne listeleme azami sonuç | `OPENFGA_LIST_OBJECTS_MAX_RESULTS` | 1000 |
| Kullanıcı listeleme son tarihi | `OPENFGA_LIST_USERS_DEADLINE` | üç saniye |
| Kullanıcı listeleme azami sonuç | `OPENFGA_LIST_USERS_MAX_RESULTS` | 1000 |
| Yazma başına azami demet | `OPENFGA_MAX_TUPLES_PER_WRITE` | 100 |
| Model başına azami tip | `OPENFGA_MAX_TYPES_PER_AUTHORIZATION_MODEL` | 100 |
| İstek zaman aşımı | `OPENFGA_REQUEST_TIMEOUT` | üç saniye |
| Veritabanı azami bağlantı | `OPENFGA_DATASTORE_MAX_OPEN_CONNS` | 30 |
| Gönderim kısıtlaması | `OPENFGA_CHECK_DISPATCH_THROTTLING_ENABLED` | false, eşik 100 |

Dikkat edilmelidir: tüm önbellekler varsayılan olarak kapalıdır. Yani kutudan çıkan OpenFGA her denetimde veritabanına gitmektedir. Yayımlanmış hızlı rakamlar önbellek açıkken alınmışsa bu belirtilmelidir.

Çözümleme düğüm limiti 25'tir; 25 seviyeden derin bir ilişki zinciri çözülmez ile hata döner. Genişlik limiti 10'dur ile eşzamanlı dallanma sınırıdır.

#### API'ler ile maliyetleri

| API | İş | Maliyet karakteri |
|---|---|---|
| `Check` | Tek kullanıcı, ilişki ile nesne | Nokta sorgu ile graf yürüyüşü |
| `BatchCheck` | Çoklu denetim | Azami yığın boyutu varsayılan 50, azami paralel istek varsayılan 10. Doküman şunu demektedir: *"Less efficient than parallel Check calls for fewer than 10 checks"* |
| `Expand` | Bir nesnenin kullanıcı kümesi ağacı | Özyinelemelidir ile hata ayıklama içindir |
| `ListObjects` | Kullanıcının eriştiği nesneler | Ters genişletmedir. Doküman şunu demektedir: küçük koleksiyonlarda erişim farkındalıklı süzme için tasarlanmıştır ile büyük veri kümelerinde kaynak yoğun olabilir |
| `StreamedListObjects` | Akış varyantı | Azami sonuç sınırını aşmak içindir |
| `ListUsers` | Nesneye erişen kullanıcılar | Aynı sınıf maliyettir |

#### Ağırlıklı graf çözümlemesi, yeni ile önemli

21 Temmuz 2026 tarihli OpenFGA blog yazısı, Tyler Nix'in ağırlıklı graf çözümlemesine geçiş yazısı, bunu anlatmaktadır. Ağırlıklı graf tabanlı bir çözümleme algoritması denetim, yığın denetimi, nesne listeleme, genişletme ile kullanıcı listelemeye yayılmaktadır; nesne listeleme zaten kullanmaktadır. Sürüm notlarında `weighted_graph_check` deneysel bir bayrak olarak görünmektedir ile 1.18.1 ile 1.19.0 arasında birçok düzeltme vardır.

Bu esasen bir sorgu planlayıcıdır: model grafındaki kenarlara maliyet ağırlığı atayıp hangi yoldan gidileceğine karar vermektedir. Argus için doğrudan alınabilir bir fikirdir ve 7.4'te ele alınmaktadır.

Bir uyarı gerekmektedir: 1.18.2 ile 1.18.3 sürüm notları `weighted_graph_check` içinde aralıklı yanlış dönüşler ile önbellek anahtarı çakışmaları düzeltmelerinden bahsetmektedir. Yani yeni motor hâlâ yanlış cevap vermekteydi. Deneysel özellik deneyseldir.

#### Model sürümleme

Modeller değişmezdir. Her değişiklik yeni bir model kimliği üretmektedir.

Kritik davranış şudur: *"The tuples that are not valid according to the specified model, are ignored when evaluating queries."* Yani geçersiz demetler silinmemekte, sessizce yok sayılmakta ancak sorgu performansını düşürmektedir.

Göç sırası şudur: yeni model yayımlanır, yeni demetler yazılır, uygulama güncellenir ile model kimliği değiştirilir.

Bu sessiz yok sayma davranışı bir güvenlik tuzağıdır. Bir ilişki yeniden adlandırılırsa eski demetler hâlâ veritabanındadır ile model geri alınırsa yeniden canlanmaktadırlar. Argus'ta bu davranış açıkça günlüğe yazılmalı ile metriklenmelidir.

#### Üretim rehberi

Doküman, önbellek isabet oranını artırmak için çok sayıda sunucudan oluşan büyük bir havuz yerine yüksek kapasiteli, yani bellek ile işlemci çekirdeği bakımından güçlü, küçük bir sunucu havuzu önermektedir.

Veritabanı OpenFGA sunucularıyla aynı fiziksel veri merkezinde ile ağda olmalı ile başka bir uygulamayla paylaşılmamalıdır.

Önbellek açmak isteklerin gecikmesini azaltmakta ancak OpenFGA yanıtlarının bayatlığını artırmaktadır.

Gömülebilirlik konusunda durum şudur: OpenFGA bir Go modülüdür ile teknik olarak süreç içinde kullanılabilir; ancak dokümantasyon gömülü kullanım için resmî bir rehber vermemekte ile dağıtım topolojisi, yani yardımcı kap, merkezî ya da gömülü, hakkında hiçbir şey söylememektedir. Rust'tan yalnızca gRPC ya da HTTP istemcisiyle kullanılabilir.

### 1.3 SpiceDB, iç mimari

Kimliği şudur: sürüm 1.56.1, 26 Ağustos 2026, Go ile yazılmıştır ile Authzed tarafından geliştirilmektedir.

Lisans konusunda bir not gerekmektedir: crates ile GitHub API hız sınırı nedeniyle lisans bu oturumda birincil kaynaktan teyit edilememiştir ile doğrulanmamıştır. Geçmişte Apache 2.0'dı; kullanmadan önce lisans dosyası kontrol edilmelidir.

#### ZedToken ile dört tutarlılık seviyesi

SpiceDB, Zanzibar'ın tutarlılık belirtecini gerçekten uygulamıştır. OpenFGA'ya karşı en büyük mimari avantajı budur.

| Seviye | Davranış | Not |
|---|---|---|
| `minimize_latency` | Önbellekten servis edilir ile yeni düşman penceresi açıktır | Okumalar için varsayılandır |
| `at_least_as_fresh` | Verilen belirteçten en az o kadar tazedir | Dengeli seçimdir ile önerilmektedir |
| `at_exact_snapshot` | Tam o anlık görüntüdür | Anlık görüntü süresi doldu riski vardır, çöp toplama penceresine bağlıdır; yalnızca kısa pencerede sayfalama içindir |
| `fully_consistent` | Önbellek tamamen atlanır | Yazmalar için varsayılandır; *"dramatically increasing latency"* denmektedir |

Önemli bir ince nokta vardır: *"the snapshot used will be loaded at the beginning of the API call, and that new data written after the API starts executing will be ignored."*

CockroachDB uyarısı Argus'un çok dikkat etmesi gereken bir noktadır.

> "fully_consistent does not guarantee read-after-write consistency on CockroachDB"

Sebep düğüm saat kaymasıdır, yani tipik olarak 500 milisaniyelik azami sapmadır. Bunun yerine belirteçle birlikte `at_least_as_fresh` kullanılmalıdır.

Yani en güçlü tutarlılık seviyesi, en çok önerilen arka uçta en güçlü garantiyi vermemektedir. Tutarlılık belirteci mekanizması isteğe bağlı bir konfor değil bir zorunluluktur.

#### Veri deposu soyutlaması

| Arka uç | Üretim durumu | Revizyon mekanizması | Not |
|---|---|---|---|
| CockroachDB | Kendi barındıran için önerilmektedir | `cluster_logical_timestamp()` | Çok bölgelidir ile yüksek operasyonel karmaşıklık taşımaktadır |
| Cloud Spanner | GCP için önerilmektedir | TrueTime | Doğrusallaştırılabilirlik varsayımı vardır ile örtüşme stratejisi gereksizdir |
| PostgreSQL | Tek bölge için önerilmektedir | Özel çok sürümlü eşzamanlılık denetimi, satırlarda işlem kimliği | PostgreSQL 15 ve üstü idealdir; standart dışı eklenti gerekmez; izleme API'si için `track_commit_timestamp=on` gerekir; 16 okuma replikası adresine kadar desteklenir |
| MySQL | *"Not recommended; only use if you cannot use PostgreSQL"* | Özel çok sürümlü eşzamanlılık denetimi | Replika tutarlılığı için iki gidiş dönüş gerekmektedir |
| memdb | Yalnızca geliştirme ile testtir | Bellek içi çok sürümlü eşzamanlılık denetimi | Süreç ölünce veri gider ile yüksek erişilebilirlik yoktur |

Argus için değerli olan şudur: SpiceDB'nin PostgreSQL arka ucu standart dışı eklenti gerektirmemekte ile satırlara işlem kimliği gömerek çok sürümlü eşzamanlılık denetimini kendisi uygulamaktadır. Bu, Argus'un PostgreSQL'de aynı yaklaşımı kopyalayabileceğini göstermektedir; Argus zaten PostgreSQL'e bağımlı olacaktır.

#### Gönderim katmanı

SpiceDB'nin gönderim ile önbellekleme dokümantasyon sayfalarına bu oturumda erişilememiştir, 404 dönmüştür. Bilinen mimari, yani tutarlı özetlemeyle küme gönderimi, tek uçuş tekilleştirmesi ile gönderim önbelleği, bu oturumda birincil kaynaktan doğrulanmamıştır. Zanzibar'ın devretme modelinin bir uyarlaması olduğu genel olarak bilinmektedir ancak sayısal bir iddiada bulunulmayacaktır.

### 1.4 Ory Keto hâlâ aktif midir

Kısa cevap şudur: teknik olarak evet, pratik olarak hayır.

| Sürüm | Tarih |
|---|---|
| 26.2.0 | 20 Mart 2026 |
| 25.4.0 | 7 Kasım 2024 |
| 0.14.0 | 6 Mart 2024 |

Kasım 2024 ile Mart 2026 arasında 16 aylık bir sürüm boşluğu vardır. 26.2.0'ın içeriği ağırlıklı olarak hata düzeltmesi ile güvenliktir: GHSA-7h2j-956f-4vf2, PostgreSQL işlem yeniden denemesi, SQL boş değer işleme ile anahtar kümesi sayfalaması. Yani bu bir özellik sürümü değil bir bakım sürümüdür.

Deponun kendi açıklaması Ory'nin konumlandırmasını açık etmektedir: kendi barındırılan Keto, deney yapmak, prototip üretmek ya da önemsiz iş yükleri çalıştırmak isteyen bireyler, araştırmacılar, hacker'lar ile şirketler için iyi bir seçimdir denmektedir.

Önemsiz iş yükleri ifadesini kendi projesi hakkında yazan bir ekibin ürününü bir kimlik sağlayıcının yetkilendirme çekirdeğine koymak savunulamaz. Üretim için Ory Network ile Ory Permissions'a yönlendirilmektedir.

Mart 2026'da CVE-2026-33505 açıklanmıştır; yüksek önem derecesindedir ile CVSS 3.1 vektörü `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` şeklindedir. Açıklama şudur: *"Ory Keto has a SQL injection via forged pagination tokens"*. Bir yetkilendirme motorunda sayfalama belirteci üzerinden SQL enjeksiyonu mimari bir kod kalitesi sinyalidir.

Karar şudur: Keto Argus için değerlendirilmemelidir.

### 1.5 Nesne ile kullanıcı listeleme, gizli darboğaz

Bu, soruda haklı olarak öne çıkarılan bir noktadır ile verilerle desteklenmektedir.

Neden pahalı olduğu şudur: denetim bir nokta sorgusudur, yani şu kullanıcının şu nesneyle şu ilişkisi var mıdır sorusudur; grafta hedeften kaynağa doğru yürünmekte ile ilk pozitif yolda durulabilmektedir. Nesne listeleme ters yöndedir, yani şu kullanıcının şu ilişkiye sahip olduğu tüm nesneler sorusudur; bu, kullanıcıdan başlayıp erişilebilir tüm nesneleri keşfetmeyi gerektirmektedir. Yayılım sınırsızdır ile erken çıkış yoktur.

Ürünlerin kendi itirafları şunlardır. OpenFGA nesne listelemeyi küçük koleksiyonlarda erişim farkındalıklı süzme için tasarlandığı ile büyük veri kümelerinde kaynak yoğun olabileceği şeklinde tanımlamaktadır. Varsayılan üç saniyelik son tarih ile 1000 sonuç limiti bir performans ayarı değil bir hasar kontrolüdür. Google tarafında Leopard'ın var oluş sebebi tam olarak budur: denetim değerlendirmesi sırasındaki özyinelemeli işaretçi takibi, derin iç içe geçmiş ya da çok sayıda alt gruba sahip gruplarda düşük gecikmeyi korumakta zorlanmaktadır.

En tehlikeli kısmı nesne listelemenin denetimle tutarsız olabilmesidir. Güvenlik açığı listesi bunu kanıtlamaktadır.

| Tanımlayıcı | Ürün | Sorun |
|---|---|---|
| CVE-2025-65111 | SpiceDB, 1.47.1 öncesi | *"LookupResources with Multiple Entrypoints across Different Definitions Can Return Incomplete Results"* |
| CVE-2023-35930 | SpiceDB, 1.22.0 ile 1.22.2 | *"LookupResources may return partial results"* |
| CVE-2024-32001 | SpiceDB, 1.30.1 öncesi | *"LookupSubjects may return partial results"* |
| CVE-2022-21646 | SpiceDB, 1.3.0 ile 1.4.0 | *"Lookup operations do not take into account wildcards"* |
| CVE-2022-39340 | OpenFGA, 0.2.4 öncesi | *"Information Disclosure via streamed-list-objects endpoint"* |

Beş ayrı güvenlik açığı, iki ayrı üründe ile aynı operasyon sınıfındadır. Bu bir tesadüf değildir: nesne listelemeyi doğru yapmak denetimi doğru yapmaktan kategorik olarak zordur ile sektörün en olgun iki motoru da defalarca yanlış yapmıştır.

Argus için doğrudan sonuç şudur: nesne listelemeyi birinci sınıf bir API olarak sunmak risklidir. Alternatifler şunlardır.

1. Öğe başına denetim: uygulama kendi veritabanından sayfayı çekmekte, yani 50 satırlık bir limit koymakta, sonra 50 elemanlık bir yığın denetimi yapmaktadır. Doğruluk garantisi denetimle aynıdır. Maliyeti sayfa doldurma sorunlarıdır, çünkü süzülen elemanlar sayfayı seyrekleştirmektedir.
2. Gerçeklenmiş indeks, yani Leopard yolu: yalnızca ihtiyaç duyulan kullanıcı, ilişki ile tip üçlüleri için düzleştirilmiş bitmap tutmaktır.
3. Filtre ifadesine indirgeme: yetki sorgusunu bir SQL `WHERE` yan tümcesine çevirmektir, ki OPA'nın kısmi değerlendirmesinin yaptığıdır. Yalnızca dar model sınıflarında mümkündür.

Öneri 7.5'tedir.

### 1.6 Gömme mi yan servis mi

Verilerle karşılaştırma şöyledir.

| Yaklaşım | Karar gecikmesi mertebesi | Erişilebilirlik | Kaynak |
|---|---|---|---|
| Süreç içi, Rust ile Cedar | Medyan dört ile 11 mikrosaniyedir | Süreçle aynıdır | arXiv 2403.04651 ölçümüdür |
| Süreç içi, Go ile OpenFGA bellek veritabanı | Medyan 89 ile 746 mikrosaniyedir | Süreçle aynıdır | Aynı ölçümdür |
| Yerel gRPC, yardımcı kap | Yaklaşık 0,1 ile bir milisaniye eklemektedir | Yardımcı kap bağımlılığı vardır | Bir mertebe tahminidir; kesin sayı doğrulanmamıştır |
| Ağ üzerinden merkezî | Zanzibar güvenli yolda üç ile 15, yakın zamanlıda 60 ile 76 milisaniyedir | Ayrı hata alanıdır | Zanzibar Tablo 2'dir |

Ne OpenFGA'nın ne de SpiceDB'nin resmî bir gömülü kütüphane hikâyesi vardır. OpenFGA'nın üretim dokümanı dağıtım topolojisi hakkında hiçbir şey söylememektedir. İkisi de Go'dur ile Rust'a gömülemezler. cgo ya da yabancı fonksiyon arayüzü köprüsü teorik olarak mümkündür ancak Go çalışma zamanını, yani çöp toplayıcıyı, zamanlayıcıyı ile sinyal işlemeyi, bir Rust sürecine sokmak ciddi bir mühendislik borcudur ile bunu üretimde yapan bilinen bir örnek bulunamamıştır.

Argus Rust olduğu için bu tercih zaten yapılmıştır: harici bir motor kullanılacaksa ağ ya da gRPC sıçraması kaçınılmazdır. Bu da her istekte bir ile 15 milisaniye demektir. Bir kimlik sağlayıcının token uç noktası için bu kabul edilemez.

---

## Bölüm 2 — Rust'ta yetkilendirme

Tüm rakamlar crates.io API'sinden 8 Eylül 2026'da çekilmiştir.

### 2.1 Ekosistem tablosu

| Crate | Sürüm | Son yayın | Toplam indirme | Son 90 gün | Lisans | Değerlendirme |
|---|---|---|---|---|---|---|
| cedar-policy | 4.12.0 | 28 Temmuz 2026 | 8.375.517 | 2.698.101 | Apache 2.0 | Olgun, aktif ile formel doğrulanmıştır |
| biscuit-auth | 6.0.0 | 16 Temmuz 2025 | 11.159.305 | 1.116.227 | Apache 2.0 | Olgundur ancak 14 aydır sürüm yoktur |
| casbin | 2.20.0 | 4 Şubat 2026 | 3.032.454 | 1.479.081 | Apache 2.0 | Aktiftir; modeli sınırlıdır |
| regorus | 0.12.0 | 1 Eylül 2026 | 2.157.219 | 1.001.705 | MIT, Apache 2.0 ile BSD 3 maddeli | Çok aktiftir; sıfır ana sürümdedir |
| openfga-client | 0.6.1 | 6 Ağustos 2026 | 74.567 | 30.650 | Apache 2.0 | Tek ciddi OpenFGA Rust istemcisidir |
| oso | 0.27.3 | 13 Ocak 2024 | 942.295 | 65.026 | Apache 2.0 | İki buçuk yıldır sürüm yoktur |
| spicedb-rust | 0.3.4 | 1 Aralık 2024 | 12.637 | 771 | MIT | Bakımsızdır |
| openfga-rs | 0.1.0 | 8 Nisan 2024 | 1.632 | 25 | MIT ile Apache 2.0 | Ölüdür |
| authzed | 0.0.1 | 26 Ocak 2021 | 1.876 | 9 | Apache 2.0 | Ölüdür |

Kendi ilişki tabanlı motorunu yazacaklar için Datalog ile artımlı motorlar şunlardır.

| Crate | Sürüm | Son yayın | Toplam | Son 90 gün | Lisans |
|---|---|---|---|---|---|
| ascent | 0.8.1 | 29 Ağustos 2026 | 494.673 | 161.281 | MIT |
| crepe | 0.2.0 | 14 Aralık 2025 | 790.590 | 82.103 | MIT ile Apache 2.0 |
| differential-dataflow | 0.25.1 | 15 Temmuz 2026 | 454.556 | 60.589 | MIT |
| proptest | 1.11.0 | 24 Mart 2026 | 182.638.062 | 46.079.380 | MIT ile Apache 2.0 |

### 2.2 Sonuç: Rust'ta üretime hazır bir Zanzibar yoktur

Bu, raporun en net bulgularından biridir. `openfga-rs` son 90 günde 25 kez indirilmiştir. `authzed` crate'i dokuz kez indirilmiş ile 2021'den beri güncellenmemiştir. `spicedb-rust` 771'dedir. Bunlar terk edilmiş projelerdir.

Tek ciddi seçenek `openfga-client`'tır, yani 0.6.1, Ağustos 2026, 90 günde 30.650 indirme. Ancak bu bir istemcidir, motor değildir. Argus'un yanında bir OpenFGA sunucusu çalıştırmayı gerektirmektedir.

Yani Rust'ta ilişki tabanlı erişim kontrolü isteniyorsa ya Go'ya gRPC ile konuşulacak ya da kendi yazılacaktır. Üçüncü bir seçenek yoktur.

### 2.3 Cedar, AWS, derinlemesine

#### Kimlik ile API

cedar-policy 4.12.0, 28 Temmuz 2026, Apache 2.0 lisanslıdır. Rust ile yazılmıştır ile Argus için birinci sınıf bir uyumdur.

Ana tipleri `Authorizer`, `PolicySet`, `Entities`, `Request`, `Schema`, `EntityUid`, `Context`, `Response`, `Diagnostics` ile `Validator`'dır.

Çağrı `Authorizer::is_authorized(&request, &policy_set, &entities) -> Response` ile `response.decision()` şeklindedir.

Özellik bayrakları şunlardır. Varsayılanlar `ipaddr`, `decimal` ile `datetime`'dır. İsteğe bağlı olanlar `heap-profiling`, `corpus-timing` ile `wasm`'dır. Deneysel ile kararsız olanlar `partial-eval`, tip farkındalıklı kısmi değerlendirme anlamına gelen `tpe`, kullanımdan kaldırılmış `entity-manifest`, `protobufs`, `tolerant-ast` ile `extended-schema`'dır.

Bir not gerekmektedir: kısmi değerlendirme hâlâ deneyseldir ile varlık dilimleme sağlayan `entity-manifest` kullanımdan kaldırılmıştır. Yani Cedar ile SQL filtresi üretme yolu üretime hazır değildir.

#### Formel doğrulama, tam olarak ne kanıtlanmıştır

Kaynak, arXiv 2407.01688 numaralı, FSE Companion 2024'te yayımlanan Cedar'ı doğrulama güdümlü bir yaklaşımla nasıl inşa ettik başlıklı yazıdır. PDF'ten çıkarılan yedi kanıtlanmış özellik şunlardır.

1. Yasak izni alt eder: herhangi bir yasak politikası sağlanırsa istek reddedilmektedir.
2. Varsayılan reddir: hiçbir izin sağlanmazsa reddedilmektedir.
3. Açık izin: izin verildiyse bir izin politikası sağlanmıştır.
4. Sıra bağımsızlığı: yetkilendirici, politika değerlendirme sırasından ile tekrarlardan bağımsız olarak aynı kararı vermektedir.
5. Sağlam dilimleme: dilimleme algoritması, tam politika kümesiyle aynı kararı üreten bir alt küme seçmektedir.
6. Doğrulama sağlamlığı: doğrulayıcı bir politikayı kabul ederse değerlendirmesi asla tip hatası üretmemektedir. Makale bunu şimdiye kadar yaptıkları en karmaşık kanıt diye nitelemektedir.
7. Sonlanma: Cedar fonksiyonları her zaman sonlanmaktadır.

Örnek olarak birinci özelliğin tam Lean ifadesi makalede verilmektedir.

```lean
theorem forbid_trumps_permit (request : Request)
  (entities : Entities) (policies : Policies) :
  (∃ (policy : Policy), policy ∈ policies ∧ policy.effect = forbid ∧
   satisfied policy request entities) →
  (isAuthorized request entities policies).decision = deny
```

Dafny'den Lean'e geçiş gerçekleşmiştir, yani cedar-policy deposundaki 0032 numaralı öneri. Model Lean 4'tedir.

Ölçek, Tablo 1'den, satır sayısı cinsinden şöyledir.

| Bileşen | Lean model | Lean kanıt | Rust üretim | Rust test |
|---|---|---|---|---|
| Özel kümeler ile eşlemeler | 244 | 681 | — | — |
| Ayrıştırıcı | — | — | 4.114 | 3.599 |
| Değerlendirici ile yetkilendirici | 897 | 347 | 4.877 | 7.061 |
| Doğrulayıcı | 532 | 4.686 | 6.702 | 9.798 |
| Toplam | 1.673 | 5.714 | 15.693 | 20.458 |

Kanıtın modele oranı 3,4'e birdir. Tüm kanıtların doğrulanması yaklaşık üç dakika sürmektedir.

Bulunan hatalar şunlardır: kanıt süreci doğrulayıcıda dört hata ortaya çıkarmıştır; diferansiyel rastgele test ile özellik tabanlı test 21 hata daha bulmuştur. Toplam 25'tir.

Çok önemli bir nüans vardır: kanıtlar Lean modeli hakkındadır, Rust üretim kodu hakkında değildir. Rust ile model arasındaki bağ diferansiyel rastgele testle kurulmakta, kanıtla kurulmamaktadır. Yani Cedar formel olarak doğrulanmıştır cümlesi doğru ancak eksiktir: tasarımı doğrulanmıştır ile gerçeklemesi diferansiyel olarak test edilmiştir. Makale bunu dürüstçe söylemektedir.

#### Cedar performansı, gerçek ölçüm

Kaynak arXiv 2403.04651'dir, yani OOPSLA 2024 genişletilmiş sürümünün 5.2 bölümüdür.

Deney koşulları tam olarak şunlardır. Donanım Amazon EC2 m5.4xlarge ile Amazon Linux 2'dir. Sürümler Cedar 3.0.1, OPA Rego 0.61.0 ile OpenFGA'nın `bbb4a07` işlemesidir. Her veri noktası için 200 ayrı veri deposu çarpı 500 rastgele istek, yani 100.000 istek koşulmuştur. Tüm politika ile varlık verisi bellektedir; depolama erişimi, ayrıştırma ile HTTP hariç tutulmuştur. Yalnızca çekirdek yetkilendirme fonksiyonu ölçülmüştür.

Sonuçlar, medyan ile mikrosaniye cinsinden şöyledir.

| Motor | gdrive, beş varlık | gdrive, 50 varlık | github, beşten 50'ye |
|---|---|---|---|
| Cedar | 4,0 | 5,0 | Yaklaşık 11,0; aralık boyunca sabittir |
| OpenFGA | 89 | 219 | 235'ten 746'ya |
| Rego | 76 | 676 | — |

99. yüzdelik şöyledir.

| Motor | gdrive |
|---|---|
| Cedar | Tüm boyutlarda 10 mikrosaniyenin altındadır |
| OpenFGA | 283'ten 3012 mikrosaniyeye çıkmaktadır |
| Rego | 391'den 1933 mikrosaniyeye çıkmaktadır |

Toplu oranlar şöyledir: Cedar, OpenFGA'dan gdrive, github ile TinyTodo veri kümelerinde sırasıyla 28,7, 34,4 ile 35,2 kat; Rego'dan ise 60,4, 80,8 ile 42,8 kat daha hızlıdır.

Bu ölçümün dürüst okunması için üç kayıt gerekmektedir.

1. Makalenin kendi altıncı dipnotu şunu söylemektedir: *"Based on communication with the OpenFGA developers, the OpenFGA in-memory datastore is intended mainly for debugging and is not optimized."* Yani OpenFGA en kötü yapılandırmasında ölçülmüştür.
2. Veri kümeleri minik, yani beş ile 50 varlıktır. Gerçek dünyada milyonlarca demet vardır. Cedar'ın sabit kalması tüm varlık grafını belleğe koyabildiği içindir ile bu, ölçekte geçerli olmayan bir varsayımdır.
3. Bu, AWS'nin kendi makalesidir ile kendi ürünü lehinedir. Bağımsız replikasyon doğrulanmamıştır.

Buna rağmen dört ile 11 mikrosaniye rakamı Argus için anlamlı bir üst sınırdır: Rust'ta, bellekteki veriyle, politika değerlendirme mertebesinin tek haneli mikrosaniye olduğunu göstermektedir.

İkinci bağımsız veri noktası doğrulama güdümlü geliştirme makalesinin 3.2 bölümüdür: diferansiyel rastgele test sırasında Lean yetkilendiricisi medyanda altı, Rust 10 mikrosaniyededir. İki bağımsız ölçüm aynı mertebeyi vermektedir.

#### Cedar'ın SMT analizi

Cedar'ın sembolik derleyicisi politikaları SMT-LIB'e indirgemektedir. Örnek modellerdeki politikalar için analiz soruları ortalama 75,1 milisaniyede kodlanıp çözülmektedir. Bu, şu yeniden düzenleme yetkileri değiştirdi mi gibi soruları sürekli tümleştirme hattında sorabilmek demektir, çalışma zamanında değil.

#### Cedar'ın ilişki tabanlı erişim kontrolü sınırı, kritik

Cedar'ın ilişki modeli varlık hiyerarşisi üzerinden, yani `in` operatörüyle gitmektedir ile bu bir yönlü çevrimsiz graftır. Makale şunu söylemektedir: *"The parent relation on entities forms a directed acyclic graph (DAG), called the entity hierarchy."*

Cedar'ın yapamadığı iki şey vardır.

1. Varlık deposu yoktur. `Entities` nesnesi Cedar'a dışarıdan verilmektedir. Yani Alice hangi gruplardadır sorusunu Cedar cevaplamamakta, cevap Cedar'a beslenmektedir. İlişki tabanlı erişim kontrolünün zor kısmı, yani geçişli kapanışın depolanması ile sorgulanması, Cedar'ın kapsamı dışındadır.
2. Kullanıcının erişebildiği tüm kaynaklar sorgusu yoktur. Nesne listelemenin bir karşılığı bulunmamaktadır.

Bu, Cedar ile Zanzibar'ın rakip değil tamamlayıcı olduğu anlamına gelmektedir. Cedar bir politika değerlendirme motorudur. Zanzibar bir ilişki deposu ile graf çözümleyicisidir. Argus'un ikisine de ihtiyacı vardır ile Cedar ikincisini vermemektedir.

### 2.4 biscuit-auth

Ne verdiği şudur: Ed25519 imzalı ile çevrimdışı zayıflatma yapılabilen bir yetenek token'ıdır. Herhangi bir tutucu yeni bir blok ekleyerek yetkiyi daraltabilmekte ancak asla genişletememektedir. Üçüncü taraf bloklarıyla devretme, mühürlemeyle daha fazla değişikliği engelleme ile Datalog tabanlı bir yetkilendirici sunmaktadır.

Güvenlik denetimi durumu dikkat gerektirmektedir. Deponun kendi ifadesi şudur: *"looking for an audit of the token's design, cryptographic primitives and implementations."* Yani tamamlanmış bağımsız bir denetim yoktur.

Sicil de temiz değildir.

| Tanımlayıcı | Tarih | Şiddet | Etkilenen | Açıklama |
|---|---|---|---|---|
| CVE-2022-31053 | 17 Haziran 2022 | Kritik | biscuit-auth 2.0.0 öncesi | Biscuit'te imza sahteciliğidir |
| CVE-2024-41949 ile CVE-2024-42350 | 31 Temmuz 2024 | Düşük | 4.0.0 ile 5.0.0 arası | Üçüncü taraf blokta açık anahtar karışıklığıdır |

Bir yetenek token'ı kütüphanesinde imza sahteciliği, yani 2022'deki kritik açık, ciddi bir olaydır. Düzeltilmiş olsa da denetimsiz kripto kodunun riskini göstermektedir.

Sürüm durumu şudur: 6.0.0, 16 Temmuz 2025; 14 aydır yeni sürüm yoktur. İndirme hacmi yüksektir, yani toplam 11,2 milyondur, ancak momentum düşüktür.

Kullananlar Clever Cloud ile Apache Pulsar'dır, yani biscuit-pulsar'dır.

Kimlik sağlayıcıdaki yeri şudur: Argus için doğrudan bir token formatı olarak önerilmemektedir, çünkü OIDC ile OAuth ekosistemi JWT beklemekte ile birlikte çalışabilirlik kırılmaktadır. Ancak fikir olarak çok değerlidir: zayıflatma, devretme zincirinde yetki daraltmanın doğru yoludur ile ajan senaryolarının cevabıdır. arXiv 2609.00267'nin komisyoncusu tam olarak bunu macaroon tarzıyla yapmaktadır. Argus bunu JWT içinde kısıtlama iddiaları olarak taklit edebilir, yani RFC 9396 zengin yetkilendirme istekleriyle ya da OAuth token değişimiyle.

### 2.5 regorus, Microsoft, Rust'ta Rego

Kimliği şudur: 0.12.0, 1 Eylül 2026, yani bir hafta öncesi; çok aktiftir. Lisansı MIT ile Apache 2.0 ile BSD 3 maddelidir. 90 günde bir milyon indirmesi vardır.

OPA uyumu deponun kendi ifadesiyle şudur: Regorus, OPA'nın son sürümü olan 1.2.0 ile büyük ölçüde uyumludur ile yerleşiğe özgü olmayan tüm testleri geçmektedir. Ancak 20 test paketi, eksik yerleşikler nedeniyle, yani JWT, kriptografik ile ağ fonksiyonları nedeniyle, tam geçmemektedir.

Performans, deponun Azure Container Instances politikası kıyaslamasında şöyledir: Regorus 4,6 artı eksi 0,2 milisaniye, OPA 45,2 artı eksi 0,6 milisaniyedir; yaklaşık 10 kat hızlıdır.

Bu, Microsoft'un kendi kıyaslamasıdır ile tek bir politika kümesi üzerindedir. Bağımsız doğrulaması yapılmamıştır. Ayrıca 4,6 milisaniyelik mutlak değer Cedar'ın dört ile 11 mikrosaniyesinden yaklaşık 1000 kat yavaştır; Rego semantiği pahalıdır.

Eksikleri şunlardır: kriptografik yerleşikler tasarım gereği desteklenmemektedir. JWT doğrulama, `glob.match`, GraphQL ile CIDR işlemleri yoktur.

Bağlamaları C, C++, C#, Java, Python, Go, JavaScript ile WebAssembly'dir. `no_std` uyumludur ile gömülü senaryolar için dikkate değerdir.

Argus için değerlendirme şudur: Rego'nun kimlik sağlayıcıda yeri ancak müşteriler zaten Rego politikası yazıyorsa vardır. Sıcak yol için 4,6 milisaniye kabul edilemez. Yapılandırma zamanı politika değerlendirmesi için, örneğin şu istemci şu yetki tipini kullanabilir mi sorusu için, uygun olabilir.

### 2.6 casbin-rs ile oso

casbin, yani 2.20.0, 4 Şubat 2026, 90 günde 1,48 milyon indirme, aktiftir. İlke, etki, istek ile eşleştiriciden oluşan PERM metamodeliyle rol tabanlı, öznitelik tabanlı ile liste tabanlı erişim kontrolü sunmaktadır. Ancak Zanzibar tarzı ilişki tabanlı erişim kontrolü için tasarlanmamıştır: geçişli ilişki çözümlemesi ile demet deposu semantiği yoktur. Rol hiyerarşisini desteklemektedir, o kadar. Argus'un ihtiyacını karşılamamaktadır. OSV'de crates.io ekosisteminde bir güvenlik açığı kaydı yoktur.

oso, yani 0.27.3, 13 Ocak 2024, iki buçuk yıldır sürüm çıkarmamıştır. Oso'nun dokümantasyonu artık tamamen Oso Cloud'u, yani Polar üzerine kurulmuş merkezî bir yetkilendirme servisini anlatmaktadır. Açık kaynak kütüphanenin resmî kullanımdan kaldırma açıklaması bulunamamıştır ile doğrulanmamıştır, ancak sürüm geçmişi kendi başına yeterince açıktır. Son 90 günde hâlâ 65 bin indirme vardır, ki eski bağımlılıklardandır, ancak yeni bir proje için seçilmemelidir.

### 2.7 Kendi motorunu yazmak için Rust altyapısı

Argus kendi ilişki tabanlı erişim kontrolü motorunu yazacaksa, ki öneri budur, Rust ekosistemi güçlüdür.

| Crate | Ne için | Değerlendirme |
|---|---|---|
| ascent, 0.8.1, 29 Ağustos 2026 | Rust içinde makro tabanlı Datalog | Aktif geliştirmededir, 90 günde 161 bin indirme; kullanıcı kümesi yeniden yazma kurallarını Datalog olarak ifade etmek için doğal bir adaydır |
| crepe, 0.2.0, Aralık 2025 | Prosedürel makro Datalog | Daha basit ile daha az esnektir |
| differential-dataflow, 0.25.1, Temmuz 2026 | Artımlı hesaplama | Leopard benzeri gerçeklenmiş indeksi artımlı tutmak için teorik olarak idealdir. Ancak ilişki tabanlı gerçekleme için üretimde kullanan bilinen bir örnek bulunamamıştır ile doğrulanmamıştır. Operasyonel karmaşıklığı yüksektir |
| proptest, 1.11.0 | Özellik tabanlı test | Yetkilendirme değişmezlerini test etmek için zorunludur, 6.2'ye bakınız |

Bir not gerekmektedir: `roaring` crate'i, yani roaring bitmap, bu oturumda sorgulanmamıştır ancak Leopard tarzı küme kesişimi için standart araçtır.

### 2.8 Cedarling: Cedar'ın istemciye kadar itilmesi

1.6 gömme ile yan servis arasında seçim yapmaktadır. Üçüncü bir konum vardır ile bu bölümde eksiktir: karar noktasının kimlik sağlayıcının dışına, tüketen uygulamanın içine yerleştirilmesi. Janssen Projesi bunu Cedarling adıyla gerçeklemiştir ile Argus için önemi doğrudandır, çünkü Argus'un yazabileceği şeyin çalışan örneğidir.

Ne olduğu şudur, kaynak Janssen deposu ile Cedarling genel bakış dokümanıdır, erişim 13 Eylül 2026. Gömülebilir, durumlu bir politika karar noktasıdır. Sorduğu soru şudur: bu JWT'ler verildiğinde uygulama bu kaynak üzerinde bu eylemi yapmaya izin vermeli midir. Rust ile yazılmıştır; WebAssembly, iOS, Android ile Python bağlamaları bulunmaktadır. Cedar'ın Rust motoru üzerine kuruludur; JWT'leri doğrulamakta ile JSON yük taleplerini Cedar varlıklarına eşlemektedir. Tarayıcıda WebAssembly bileşeni olarak, mobil uygulamada ya da sunucuda çalışabilmektedir.

Argus için üç çıkarım vardır.

Birincisi, 2.3'teki Cedar değerlendirmesi eksik kalmaktadır. Cedar orada bir politika dili ile bir kütüphane olarak ele alınmaktadır; Cedarling, aynı motorun kimlik sağlayıcının verdiği belirteçleri anlayan bir dağıtım biçimi olduğunu göstermektedir. Yani belirteç ile politika arasındaki eşleme, motorun değil ürünün katmanıdır ile o katman yazılabilirdir.

İkincisi, bu konum 4.5'teki token'a gömmek ile her istekte sormak ikilemini üçüncü bir noktaya taşımaktadır. İstemci içi karar noktası her istekte sormamakta ancak kararı token'a da gömmemektedir; politikayı ile gerekli varlıkları önceden almakta ile kararı yerel olarak vermektedir. Maliyeti nettir: karar tanım gereği bayat çalışmaktadır. Bayatlık penceresi, politikanın ile varlık verisinin tazelenme aralığıdır ile bu §1 §9.1'deki açık iptal sözleşmesinin istemci tarafındaki hâlidir.

Üçüncüsü, bu bir farklılaşma fırsatıdır ancak §1 §9.1 kapatılmadan değerlendirilemez. Argus istemci içi bir karar noktası dağıtacaksa, iptalin o noktaya ne kadar sürede ulaştığını sözleşmeye bağlamak zorundadır; bugün sunucu tarafı için bile bağlanmamıştır.

Doğrulanamayan nokta şudur ile önemlidir: Cedarling'in durumlu olduğu doğrulanmıştır, ancak hangi durumu tuttuğu, iptali nasıl aldığı ile bayatlık penceresinin ne olduğu doğrulanamamıştır. Bu üç soru cevaplanmadan model Argus'a kopyalanamaz.

### 2.9 Durumsuz karar noktası, üçüncü tasarım ekseni

Bölüm 1 ilişki verisini motorun tuttuğu modeli, 2.3 ise politikanın dil olduğu modeli incelemektedir. Üçüncü bir eksen daha vardır: motorun hiçbir veri düzlemi tutmaması ile ilişki verisinin her istekte çağıran tarafından gönderilmesi. Cerbos bu noktadadır; politikalar YAML dosyalarıdır ile motor bir karar fonksiyonudur. Topaz ise açık politika aracısıyla Zanzibar modelini birleştirerek politika dili artı yerel ilişki deposu sunmaktadır. İkisinin de ayrıntıları bu oturumda birincil kaynaktan doğrulanmamıştır.

Argus açısından bu eksen en yakın olandır ile bu bölümde konumlandırılmamıştır. Gerekçe şudur: Argus ilişki verisini zaten PostgreSQL'de, kiracı kapsamlı ile satır seviyesi güvenlikli tutmaktadır. Bir Zanzibar motoruna ikinci bir kopya vermek, 4.2'deki geçersizleştirme problemini ikiye katlamakta ile §1 kararı 2 ile 3'ün kapsamı dışına veri çıkarmaktadır. Durumsuz bir karar fonksiyonu bu ikinci kopyayı hiç yaratmamaktadır.

Karşı argüman da kayda geçirilmelidir: durumsuz model, 1.5'teki nesne listeleme problemini çözmemektedir. Çağıran, kararı verdirmek için gereken ilişki kümesini kendisi getirmek zorundadır; ters sorgu, yani bu kullanıcının erişebildiği tüm nesneler, durumsuz bir motorda ifade edilememektedir. Argus'un üç katmanlı sıcak yolu bu yüzden saf durumsuz olamaz; ancak karar katmanının kendisi durumsuz bir fonksiyon olarak yazılabilir ile veri getirme ayrı bir katman olarak kalabilir. Bu ayrım, motorun test edilebilirliğini doğrudan artırmaktadır: karar fonksiyonu saf olduğunda özellik testi veri deposu olmadan koşmaktadır.

---

## Bölüm 3 — AuthZEN

### 3.1 Doğrulama: tarih doğrudur

Belirtilen tarih doğrudur. Şartname dokümanının kendi yayın tarihi 11 Ocak 2026, OpenID Foundation'ın onay duyurusu 12 Ocak 2026'dır.

Oylama 81 kabul, bir ret ile 25 çekimser, yani 107 oydur; 378 üyenin %28,3'üdür ile %20'lik yeter sayının üzerindedir.

Aşamalar şöyledir: gerçekleyici taslağı Kasım 2024'te, nihai şartname Ocak 2026'dadır.

Nihai şartname statüsü gerçekleyicilere fikrî mülkiyet koruması sağlamaktadır ile daha fazla revizyona tabi değildir; yani API yüzeyi dondurulmuştur. Argus için bu iyi bir haberdir: hedef sabittir.

### 3.2 Şartnamenin tam teknik içeriği

#### Erişim değerlendirme API'si, `POST /access/v1/evaluation`

İstek şeması şöyledir.

```json
{
  "subject":  { "type": "string (REQUIRED)", "id": "string (REQUIRED)", "properties": "object (OPTIONAL)" },
  "resource": { "type": "string (REQUIRED)", "id": "string (REQUIRED)", "properties": "object (OPTIONAL)" },
  "action":   { "name": "string (REQUIRED)", "properties": "object (OPTIONAL)" },
  "context":  "object (OPTIONAL)"
}
```

Şartnameden birebir örnek şudur.

```json
{
  "subject":  { "type": "user", "id": "alice@example.com" },
  "resource": { "type": "account", "id": "123" },
  "action":   { "name": "can_read", "properties": { "method": "GET" } },
  "context":  { "time": "1985-10-26T01:22-07:00" }
}
```

Yanıt şöyledir.

```json
{ "decision": true }
```

Gerekçeli ret şöyledir.

```json
{
  "decision": false,
  "context": {
    "reason_admin": { "403": "Request failed policy C076E82F" },
    "reason_user":  { "403": "Insufficient privileges. Contact your administrator" }
  }
}
```

Yönetici gerekçesiyle kullanıcı gerekçesi ayrımı iyi bir tasarımdır: yönetici tam nedeni görmekte, kullanıcı bilgi sızdırmayan bir mesaj almaktadır.

#### Toplu erişim değerlendirme API'si, `POST /access/v1/evaluations`

Üst seviyede özne, eylem, kaynak ile bağlam varsayılan olarak verilmekte; `evaluations` dizisindeki her eleman bunları geçersiz kılmaktadır. Bu, N artı bir sorununu ağ katmanında çözmektedir.

```json
{
  "subject": { "type": "user", "id": "alice@example.com" },
  "context": { "time": "2024-05-31T15:22-07:00" },
  "action":  { "name": "can_read" },
  "evaluations": [
    { "resource": { "type": "document", "id": "boxcarring.md" } },
    { "resource": { "type": "document", "id": "subject-search.md" } }
  ]
}
```

`options.evaluations_semantic` alanının üç değeri şunlardır.

| Değer | Anlam |
|---|---|
| `execute_all` | *"Execute all of the requests (potentially in parallel), return all of the results."* |
| `deny_on_first_deny` | *"Any denial (error, or `"decision": false`) short-circuits."* |
| `permit_on_first_permit` | *"Converse short-circuiting semantic."* |

Argus için önemli olan şudur: `deny_on_first_deny`, tüm bu koşullar sağlanmalıdır anlamındaki ve semantiğini ağ seviyesinde vermekte ile erken çıkışla iş tasarrufu sağlamaktadır. Bu, sıcak yol için birinci sınıf bir optimizasyon kancasıdır.

#### Arama API'leri, nihai şartnamenin içindedir

Üçü de 1.0 nihai sürüme dahildir, ayrı bir taslak değildir.

| Uç nokta | Soru |
|---|---|
| `POST /access/v1/search/subject` | Bu kaynağa bu eylemi kim yapabilir; öznenin kimliği atlanmalıdır |
| `POST /access/v1/search/resource` | Bu özne bu eylemi hangi kaynaklarda yapabilir; kaynağın kimliği atlanır. Nesne listelemenin karşılığıdır |
| `POST /access/v1/search/action` | Bu özne bu kaynakta hangi eylemleri yapabilir; eylem alanı yoktur |

Ortak yanıt şeması sayfalamayla birlikte şöyledir.

```json
{
  "page":    { "next_token": "string (REQUIRED)", "count": "int (OPT)", "total": "int (OPT)", "properties": "object (OPT)" },
  "context": "object (OPTIONAL)",
  "results": "array (REQUIRED)"
}
```

İstekteki `page` nesnesi opak bir `token`, yani önceki `next_token`, bir `limit` ile `properties` alanlarını taşımaktadır. Yanıtta `next_token` boş bir dizgiyse liste bitmiştir.

Bu, 1.5'teki tehlikeli operasyonun standartlaştırılmış hâlidir. Şartname sayfalamayı zorunlu kılarak, yani `next_token` alanını zorunlu yaparak, en azından sınırsız yayılımı yapısal olarak engellemektedir. Argus bu uç noktayı gerçeklerken her zaman bir son tarih ile azami sonuç sınırı uygulamalıdır.

#### `.well-known/authzen-configuration`

`GET` ile 200 OK döner ile `application/json` içerir.

| Alan | Zorunluluk |
|---|---|
| `policy_decision_point` | Zorunludur; HTTPS adresidir, sorgu ile parça içermez |
| `access_evaluation_endpoint` | Zorunludur |
| `access_evaluations_endpoint` | İsteğe bağlıdır |
| `search_subject_endpoint` | İsteğe bağlıdır |
| `search_action_endpoint` | İsteğe bağlıdır |
| `search_resource_endpoint` | İsteğe bağlıdır |
| `capabilities` | İsteğe bağlıdır; IANA tekdüzen kaynak adı dizisidir |
| `signed_metadata` | İsteğe bağlıdır; metadata iddialarını içeren bir JWT'dir |

Doğrulama kuralı şudur: dönen politika karar noktası, iyi bilinen adresin inşa edildiği tanımlayıcıyla aynı olmak zorundadır.

#### Hata yönetimi ile güvenlik

| Kod | Durum |
|---|---|
| 200 | Başarılıdır; karar `decision` alanındadır |
| 400, 401, 403 ile 500 | Sırasıyla hatalı istek, yetkisiz, yasak ile iç hatadır |

Kritik semantik ayrım şudur: *"A successful request that results in a deny is indicated by a 200 OK status code with a `{ "decision": false }` payload."* Yani ret bir HTTP hatası değildir. 403 ise politika uygulama noktasının karar noktasına erişim yetkisinin olmamasıdır. Bu ayrımı karıştırmak açık başarısızlığa yol açmaktadır.

`X-Request-ID` başlığı varsa karar noktası yanıtta aynı başlıkla bir istek tanımlayıcısı döndürmek zorundadır.

Güvenlik bölümü şunları söylemektedir. Uygulama noktasıyla karar noktası arasındaki bağlantı güvenli kılınmak zorundadır, yani HTTP REST için TLS gerekmektedir. Karar noktası çağıran uygulama noktasını kimlik doğrulamalıdır; mTLS, önerilen yol olarak OAuth 2.0 ya da API anahtarı kullanılabilir. Karar noktası yanıtını imzalayabilir. I-JSON profili, yani RFC 7493, geçerlidir; UTF-8 ile IEEE 754 çift duyarlık sınırları uygulanır. Hizmet reddi koruması yük boyutu, istek sayısı, geçersiz JSON, iç içe JSON saldırıları ile bellek tüketimini kapsamalıdır. Güven modeli şöyle ifade edilmektedir: *"The architecture of this model assumes the PDP must trust the PEP, as the PEP is ultimately responsible for enforcing the decision the PDP produces."*

Taşıma katmanında HTTPS ile JSON bağlaması normatiftir; gRPC ile CoAP bağlamaları profillerde tanımlanabilir. Uç noktalar `v1` içermelidir. Alıcılar bilinmeyen alanları yok saymak zorundadır, ki ileri uyumluluk içindir. JSON üye sıralaması varsayılmamalıdır.

### 3.3 2026'nın yeni profilleri, Argus için doğrudan alakalıdır

15 Haziran 2026'da, Identiverse etkinliğinde, iki yeni çalışma grubu taslağı onaylanmıştır.

Birincisi AuthZEN erişim isteği ile onay profilidir. Politika bir eylemi henüz yetkilendiremediğinde, yani onay, rıza, kanıtlama ya da risk değerlendirmesi gibi ön koşullar eksik olduğunda, bunları isteme, izleme, karşılama ile yeniden değerlendirme için birlikte çalışabilir kalıplar tanımlamaktadır. Yani hayır yerine henüz değil, şu gerekmektedir demektedir.

İkincisi model bağlam protokolü araç yetkilendirmesi için AuthZEN profilidir. Farklı bilgi modellerinin AuthZEN'in özne, eylem, kaynak ile bağlam yapısına nasıl eşleneceğini standartlaştırmakta; model bağlam protokolü araçlarının ajan iş akışlarında yetkilendirme gereksinimlerini açığa vurmasını hedeflemektedir.

GitHub deposunda, yani openid/authzen içinde, ek taslaklar vardır ile bunlar bir kimlik sağlayıcı için kritiktir.

| Taslak | Neden Argus'u ilgilendirmektedir |
|---|---|
| OAuth 2.0 token verme profili | Token verme kararının dışsallaştırılmasıdır ile doğrudan Argus'un token uç noktasıdır |
| OAuth 2.0 token değişimi bağlaması | RFC 8693 ile AuthZEN tümleşmesidir ile devretme zincirlerini ilgilendirmektedir |
| Yetkilendirme iddiaları profili | JWT iddialarının AuthZEN'den kaynaklanmasıdır ile yetkiyi token'a gömmenin standart yoludur |
| COAZ çerçevesi ile model bağlam protokolü bağlaması | Protokolden bağımsız eşlemedir |

Bu, raporun en stratejik bulgusudur. Yetkilendirme iddiaları profili, tam olarak 4.5'te tartışılan token'a gömmek mi sormak mı ikilemine standart bir cevap vermektedir. Argus bunu erken takip etmelidir, çünkü bir kimlik sağlayıcının bu profili gerçeklemesi onu AuthZEN ekosisteminde benzersiz bir konuma koymaktadır; çoğu karar noktası satıcısı token vermemektedir.

### 3.4 Birlikte çalışabilirlik ile sertifikasyon

Sertifikasyon tarafında OpenID Foundation, yetkilendirme API'si için bir uygunluk sertifikasyon programı geliştirmektedir; böylece gerçekleyiciler bir politika karar noktasının şartnameye uyduğunu gösterebilecektir. Lansman tarihi yoktur.

Birlikte çalışabilirlik altyapısı `authzen-interop.net` adresindedir; bir yapılacaklar uygulaması üzerine kurulu senaryolardan oluşmaktadır. Docusaurus sitesi, React ön yüzü ile TypeScript arka ucu vardır. Katılımcı satıcı listesi bu oturumda birincil kaynaktan çekilememiştir, yani site erişilememiştir; belirli karar noktası ile uygulama noktası satıcı listesi doğrulanmamıştır.

Etkinlikler, OpenID blog başlıklarından, şunlardır: Gartner kimlik ile erişim yönetimi zirvesinde AuthZEN'in kurumsal hazırlığı gösterdiği, yaklaşık 100 katılımcıyla; Gartner Londra etkinliğinde bu nedir sorusundan bunu nasıl gerçekleriz sorusuna geçildiği; ile Identiverse 2026'da ajan çağında yetkilendirme temasıyla AuthZEN oturumlarının ustalık sınıfı ile ana program seviyesine yükseldiği.

### 3.5 AuthZEN ile Zanzibar birlikte nasıl çalışmaktadır

Bunlar rakip değil farklı katmanlardır. AuthZEN bir taşıma protokolü ile API sözleşmesidir; politika dili tanımlamamaktadır ile bu bilinçlidir. Zanzibar bir veri modeli ile karar algoritmasıdır.

Bir Zanzibar motorunun AuthZEN cephesi sunması doğaldır ancak üç empedans uyuşmazlığı vardır.

Birincisi özne, eylem, kaynak ile bağlam yapısının demete eşlenmesidir. AuthZEN'in özne tipi ile kimliği, eylem adı ile kaynak tipi ile kimliğinden oluşan üçlüsü, Zanzibar'ın nesne, ilişki ile kullanıcı demetine neredeyse birebir oturmaktadır.

```
resource.type:resource.id # action.name @ subject.type:subject.id
```

Sorun eylem adının ilişkiye eşlenmesindedir. Zanzibar'da ilişkiler model tarafından tanımlanmaktadır, örneğin görüntüleyen ile düzenleyen; AuthZEN'de eylemler uygulama fiilleridir, örneğin okuyabilir ile silebilir. Bir eşleme tablosu gerekmektedir. COAZ profili tam olarak bu problemi çözmeye çalışmaktadır.

İkincisi kaynak aramasının nesne listelemeye karşılık gelmesidir. Semantik olarak aynıdır ancak AuthZEN sayfalamayı zorunlu kılmaktadır ile bu iyidir. Zanzibar motorlarının imleçli nesne listelemesi buna eşlenebilir.

Üçüncüsü tutarlılık belirtecinin nereye konulacağıdır ile bu çözülmemiştir. AuthZEN şartnamesinde belirteç için ayrılmış bir alan yoktur. Tek yer serbest formlu ile isteğe bağlı `context` nesnesidir.

```json
"context": { "zookie": "GhUKEzE3NTc..." }
```

Bu işe yaramakta ancak satıcıya özgüdür ile birlikte çalışabilirlik kırılmaktadır. Aynı şekilde yanıtta yeni belirteci döndürmek için de standart bir alan yoktur ile `context` kullanılmalıdır.

Argus için tavsiye şudur: `context.consistency_token` anahtarı kullanılmalı, iyi bilinen yapılandırmadaki yetenekler dizisinde bu ilan edilmeli ile AuthZEN çalışma grubuna bu boşluk bildirilmelidir. Bu, standart öncüsü bir konum sağlamaktadır.

---

## Bölüm 4 — Sıcak yol performansı

### 4.1 Mertebe haritası, kanıtlı

Bu tablo tüm mimari kararların dayanması gereken temeldir. Her satır ölçülmüş bir kaynaktan gelmektedir.

| Katman | Gecikme | Kaynak ile koşullar |
|---|---|---|
| HMAC koşul doğrulama, Python, süreç içi | 2,6 mikrosaniye | arXiv 2609.00267; 160 satır Python, dizüstü, 200 bin çağrı |
| Yetenek token değişimi, Python | 5,4 mikrosaniye | Aynı kaynak |
| Cedar politika değerlendirme, Rust, bellekte, beş ile 50 varlık | Medyan dört ile 11, 99. yüzdelik 10 ile 20 mikrosaniyenin altı | arXiv 2403.04651; EC2 m5.4xlarge, 100 bin istek |
| Cedar, Lean referans modeli | Medyan altı mikrosaniye | arXiv 2407.01688, diferansiyel rastgele test |
| Leopard indeks araması | Medyan 150 mikrosaniyenin, 99. yüzdelik bir milisaniyenin altı | Zanzibar 4.4; medyan saniyede 1,56 milyon sorgu |
| OpenFGA süreç içi denetim, Go, bellek veritabanı | Medyan 89 ile 746, 99. yüzdelik 283 ile 3012 mikrosaniye | arXiv 2403.04651; optimize edilmemiş bellek veritabanı |
| Regorus, Rust Rego, Azure Container Instances politikası | 4,6 artı eksi 0,2 milisaniye | Microsoft deposu |
| OPA, Go Rego, aynı politika | 45,2 artı eksi 0,6 milisaniye | Aynı kaynak |
| Spanner okuması, Zanzibar'ın veritabanı | Medyan 0,5, 95. yüzdelik iki milisaniye | Zanzibar 4.4 |
| Zanzibar güvenli denetim, belirteç 10 saniyeden eski | 50. yüzdelik 3,0, 95. yüzdelik 9,46, 99. yüzdelik 15,0 milisaniye | Zanzibar Tablo 2 |
| Zanzibar yakın zamanlı denetim, belirteç 10 saniyeden yeni | 50. yüzdelik 2,86, 95. yüzdelik 60,0, 99. yüzdelik 76,3 milisaniye | Zanzibar Tablo 2 |
| Zanzibar yazma | 50. yüzdelik 127, 99. yüzdelik 401 milisaniye | Zanzibar Tablo 2 |

Dört mertebe vardır ile aralarındaki sıçramalar 10 ile 100 kattır.

```
~µs        : in-process, bellekteki veri, derlenmiş politika
~100 µs    : in-process + materialized index lookup (Leopard)
~1 ms      : in-process graph walk + yerel DB okuması
~10 ms     : ağ + dağıtık graph çözümlemesi (bayat veri kabul edilerek)
~60-100 ms : ağ + taze veri gerektiren dağıtık çözümleme
```

Bir kimlik sağlayıcının token uç noktası için bütçe tipik olarak 50 ile 200 milisaniyedir, yani imzalama, veritabanı ile oturumu kapsamaktadır. Yetkilendirmeye ayrılabilecek pay gerçekçi olarak birkaç milisaniyedir. Yani en alttaki iki satır kabul edilemez ile ilk üçü hedeflenmelidir.

### 4.2 Önbellek stratejileri ile geçersizleştirme

#### Google'ın gerçek önbellek verimliliği, çok önemli olduğu için tekrar

| Önbellek katmanı | İsabet oranı |
|---|---|
| Denetim, devredilen taraf | %10 |
| Denetim, devredilen taraf kilit tablosu | %12 |
| Denetim, devreden taraf | %2 |
| Denetim, devreden taraf kilit tablosu | %3 |
| Okuma, devredilen taraf | %24 |
| Okuma, devreden taraf | %1'in altı |

Google'ın kendi değerlendirmesi şudur: *"While these hit rates appear low, they prevent 500K internal RPCs per second from creating hot spots."*

Ders şudur: karar önbelleği bir gecikme çözümü değil bir sıcak nokta çözümüdür. Argus'un tasarımı %90 isabet oranı varsayımı üzerine kurulmamalıdır. Kullanıcı, ilişki ile nesne anahtar uzayı doğal olarak seyrektir; aynı kullanıcı aynı nesneyi kısa sürede tekrar sormamakta ancak aynı ara düğümü, örneğin bir kuruluşun üye ilişkisini, çok sık sormaktadır. Bu yüzden önbeleklenmesi gereken şey nihai karar değil ara alt problem sonuçlarıdır. OpenFGA'nın denetim sorgu önbelleği tam olarak bunu yapmakta ile denetim alt problemi sonucunu önbeleklemektedir.

#### Geçersizleştirme, dört yaklaşım

| Strateji | Nasıl | Artı | Eksi |
|---|---|---|---|
| Yaşam süresi | Süre dolunca atılır | Basittir | Nedenselliği korumaz ile yeni düşman açık kalır |
| Yazarken geçirme | Yazma anında ilgili girdiler düşürülür | Tazedir | Hangi girdilerin etkilendiği bir geçişli kapanış problemidir; bir grup üyeliği değişince binlerce karar etkilenir |
| Olay güdümlü | Değişiklik günlüğü ya da izleme akışı dinlenir | Ölçeklenir | Gecikme vardır ile sıralama garantisi gerekir |
| Sürümlü anlık görüntü, yani tutarlılık belirteci | Önbellek anahtarına revizyon konur | Nedensel doğruluk sağlar | İstemci sözleşmesi gerektirir |

OpenFGA'nın yaklaşımı `ReadChanges` API'sidir: devam belirteciyle kronolojik sıralı bir demet değişiklik listesidir. Sayfa boyutu en fazla 100'dür ile nesne tipine göre süzülebilir. Önbellek denetleyicisi bunu yoklamayla kullanmaktadır, varsayılan yaşam süresi 10 saniyedir. Doküman açıkça uyarmaktadır: bu, yetkilendirme modelindeki güncellemeler gibi diğer değişiklikleri içermemektedir. Yani model değişiklikleri önbellek geçersizleştirmesini tetiklememektedir.

SpiceDB'nin yaklaşımı tutarlılık belirtecidir. Önbellek anahtarı revizyonu içerdiği için `at_least_as_fresh` ile yapılan bir sorgu eski önbellek girdisini yapısal olarak kullanamamaktadır. Geçersizleştirme problemi ortadan kalkmaktadır, çünkü eski girdi yanlış anahtar altındadır. Bu, yaşam süresine karşı kategorik olarak üstün bir tasarımdır.

Argus için tavsiye şudur: tutarlılık belirteci eşdeğeri baştan konulmalıdır. Sonradan eklenemez, çünkü API sözleşmesini ile istemci davranışını değiştirmektedir. OpenFGA'nın sonraki sürümlerde düşünüyoruz durumu bu borcun ne kadar ağır olduğunun kanıtıdır.

#### Olumsuz önbellek, özel dikkat

Bu kullanıcının bu yetkisi yoktur sonucunu önbeleklemek cazip ile etkilidir, çünkü retler genellikle izinlerden çok daha sıktır. Ancak iki risk vardır. Birincisi, yetki verildikten sonra kullanıcının hâlâ girememesidir; bu bir kullanıcı deneyimi felaketi ile destek yüküdür. İkincisi, olumsuz önbellek yaşam süresinin olumludan kısa olması gerektiğidir; güvenlik açısından bayat bir hayır zararsız, bayat bir evet tehlikelidir. Ancak ürün açısından tam tersidir.

Öneri şudur: olumsuz önbellek yaşam süresi çok kısa, yani bir saniye ya da altı olmalı, ya da yazarken geçersizleştirme kullanılmalıdır. Yetki verme işlemi ilgili olumsuz girdileri senkron olarak düşürmelidir.

### 4.3 Politika derleme

#### Cedar'ın yaklaşımı: dilimleme ile isteğe bağlı tipleme

Cedar'ın sağlam dilimleme özelliği formel olarak kanıtlanmıştır, yani beşinci özelliktir. Politika kapsamındaki asıl ile kaynak kısıtları bir indeksleme anahtarı olarak kullanılmaktadır: gelen istek için yalnızca ilgili politika alt kümesi değerlendirilmektedir.

Makalenin 5.3 bölümündeki ölçümü şudur: gdrive şablonlarında dört statik politika ile bir şablon, github şablonlarında üç statik ile beş şablon vardır. Şablon bağlantıları varlık çifti başına 0,05 olasılıkla üretilmektedir; yani bağlantı sayısı varlık sayısında kuadratiktir. Dilimleme bu senaryoda anlamlı bir kazanç sağlamaktadır.

Kritik nüans şudur: *"The sound policy slicing scheme does not benefit our Cedar gdrive and github examples because their policies do not have scope-level constraints on principal and resource."* Yani dilimleme ancak politikalar doğru yazılırsa işe yaramaktadır. Otomatik bir kazanç değil bir modelleme disiplinidir.

#### OpenFGA'nın yaklaşımı: ağırlıklı graf çözümlemesi

Model grafındaki kenarlara ağırlık atayıp çözümleme yolunu seçen bir sorgu planlayıcıdır, yani 21 Temmuz 2026 tarihli blog yazısıdır. Denetim, yığın denetimi, nesne listeleme, genişletme ile kullanıcı listelemeye yayılmaktadır.

Bu, klasik veritabanı sorgu optimizasyonunun ilişki tabanlı erişim kontrolüne uygulanmasıdır ile doğru bir fikirdir: üst nesneden gelen görüntüleyen ya da düzenleyen gibi bir ifadede hangi dalın önce denenmesi gerektiği, o dalın beklenen yayılımına bağlıdır.

Uyarı tekrar edilmelidir: 1.18.2 ile 1.18.3 sürüm notları bu motorda aralıklı yanlış dönüşleri ile önbellek anahtarı çakışmalarını düzeltmektedir. Sorgu planlayıcı yazmak yanlış cevap üretme riskini artırmaktadır. Argus bunu yaparsa planlayıcılı ile planlayıcısız yolların diferansiyel test edilmesi zorunludur, ki Cedar'ın diferansiyel rastgele testinin yaptığıdır.

#### Gerçeklenmiş indeks, Leopard yolu

En büyük kazanç buradadır: 150 mikrosaniyeye karşı üç milisaniye, yani 20 kat.

Mekanizma şudur: geçişli grup kapanışı önceden hesaplanmakta, sıralı tam sayı listeleri olarak, yani atlama listesi ya da roaring bitmap olarak saklanmakta ile üyelik testi bir küme kesişimine indirgenmektedir.

```
(MEMBER2GROUP(U) ∩ GROUP2GROUP(G)) ≠ ∅
```

Maliyeti artımlı güncelleme katmanıdır. Zanzibar'ın Leopard'ı saniyede medyan yaklaşık 500, 99. yüzdelikte yaklaşık 1.500 indeks güncellemesi işlemektedir; buna karşılık yazma yükü saniyede 25 bindir. Yani yazma yükünün küçük bir yüzdesi indeks güncellemesi tetiklemektedir, çünkü çoğu demet grup üyeliği değildir.

Argus için bu, `differential-dataflow` crate'inin teorik olarak parladığı yerdir. Ancak üretimde ilişki tabanlı gerçekleme için kullanan bilinen bir örnek bulunamamıştır ile doğrulanmamıştır. Daha güvenli yol elle yazılmış artımlı kapanış ile roaring bitmap'tir.

### 4.4 Yığın denetimi

| Sistem | Mekanizma | Limitler |
|---|---|---|
| OpenFGA | `BatchCheck` | Azami yığın boyutu 50, azami paralel istek 10. *"Less efficient than parallel Check calls for fewer than 10 checks"* |
| SpiceDB | `CheckBulkPermissions` | Limitler bu oturumda doğrulanmamıştır |
| AuthZEN | `/access/v1/evaluations` | Varsayılan alan devralma ile üç kısa devre semantiği |

N artı bir yetkilendirme problemi şudur: bir liste sayfasında 50 öğe gösteriliyorsa naif kod 50 ayrı denetim yapmaktadır. Ağ üzerinden bu 50 çarpı üç milisaniye, yani 150 milisaniyedir. Yığınla bu tek bir gidiş dönüş ile paralel çözümleme olmaktadır.

AuthZEN'in ilk rette durma semantiği özellikle değerlidir: bu beş koşulun hepsi sağlanmalıdır sorusunda ilk rette durulmaktadır.

### 4.5 Token'a gömmek ile her istekte sormak

Bu, Argus'un vereceği en önemli tek mimari karardır.

#### Karşılaştırma

| Boyut | Token'a gömme | Her istekte denetim |
|---|---|---|
| Sıcak yol maliyeti | Mikrosaniye mertebesindedir, yani imza doğrulamadır | 0,1 ile 15 milisaniyedir |
| Tazelik | Token yaşam süresi kadar bayattır | Önbellek yaşam süresi kadar bayattır |
| İptal | Zordur; token süresi dolana kadar geçerlidir | Anındadır |
| Boyut | Şişmektedir | Sabittir |
| Karar noktası erişilemezse | Çalışmaya devam etmektedir | Durmaktadır, ya da açık başarısızlık riski taşımaktadır |
| Denetlenebilirlik | Karar anı kullanım anından farklıdır | Her kullanım günlüğe yazılmaktadır |
| İnce tanelilik | Kabadır, yani rol ile kapsam düzeyindedir | İncedir, yani kaynak başınadır |

#### Token şişmesi, gerçek limitler

Bunlar mimari sabitlerdir. Çerez sınırı dört kibibayttır, ki RFC 6265 uyumlu tarayıcı limitidir. HTTP başlık sınırı varsayılan olarak sekiz kibibayttır; nginx'te büyük istemci başlık arabellekleriyle, Envoy'da azami istek başlığı kibibayt ayarıyla belirlenmektedir, ki Envoy varsayılanı 60 kibibayttır ancak yukarı akış sunucuları genelde sekiz kibibayttadır.

Bu değerler yaygın varsayılanlardır; bu oturumda birincil dokümantasyondan yeniden doğrulanmamıştır ile kesin sürüme özgü değerler doğrulanmamıştır.

Bir kullanıcının 500 belgeye erişimi varsa bu kimlikleri token'a koymak imkânsızdır. İnce taneli yetki token'a sığmamaktadır; bu matematiksel bir gerçektir, bir mühendislik tercihi değildir.

#### Keycloak'ın UMA ile talep eden taraf token'ı yaklaşımı neden ölçeklenmemektedir

Keycloak'ın yetkilendirme servisleri izinleri bir talep eden taraf token'ının içine koymaktadır. Kullanıcının erişebildiği kaynak sayısı arttıkça bu token büyümektedir. Bu, tam olarak yukarıdaki duvara çarpmaktadır. Projenin kendi açıklamasında da bu bir kaba tanelilik zayıflığı olarak not edilmiştir ile teknik kökeni budur.

#### Doğru sentez: iki katmanlı

```
Katman 1 — Token'a göm (kaba, sabit boyutlu):
  • roller, tenant/org üyeliği, plan/tier, scope'lar
  • boyut: kullanıcı sayısından bağımsız, ~O(rol sayısı)
  • TTL: kısa (5-15 dk)
  • Maliyet: imza doğrulama, ~µs

Katman 2 — Her istekte sor (ince, kaynak başına):
  • "bu kullanıcı BU belgeyi görebilir mi?"
  • Katman 1'in verdiği bağlamı contextual input olarak kullan
  • Maliyet: in-process ~µs-ms
```

Kritik kural şudur: birinci katman asla tek başına bir yetki kanıtı olmamalıdır. Token'daki yönetici rolü iddiası, yönetici olduğu iddia edilmektedir bilgisidir; bu kaynağa erişebilir kararı değildir. Bu ayrımı bulanıklaştırmak, güvensiz doğrudan nesne referanslarının doğduğu yerdir.

AuthZEN'in yetkilendirme iddiaları profili taslağı tam olarak birinci katmanı standartlaştırmaktadır. Argus'un bunu takip etmesi gerekmektedir.

### 4.6 Rust'ta mikrosaniye altı karar mümkün müdür

Dürüst cevap kararın türüne bağlıdır.

| Karar türü | Mikrosaniye altı mıdır | Gerekçe |
|---|---|---|
| İmza ile HMAC doğrulama | Evet | Python'da 2,6 mikrosaniyedir; Rust'ta 0,3 ile bir mikrosaniye beklenebilir. Ed25519 doğrulama tipik olarak yaklaşık 50, HMAC-SHA256 yaklaşık bir mikrosaniyedir; bu bir mertebe tahminidir ile doğrulanmamıştır |
| Bitmap kesişimi ile boşluk testi | Evet | Roaring bitmap kesişimi tek gruplarda yüzlerce nanosaniye mertebesindedir |
| Önceden derlenmiş rol tablosu araması | Evet | Karma tablo araması 20 ile 50 nanosaniye mertebesindedir |
| Cedar tarzı politika değerlendirme | Hayır; dört ile 11 mikrosaniyedir | Ölçülmüştür |
| İlişki tabanlı graf yürüyüşü, bellekte | Hayır; 10 mikrosaniye ve üstüdür | Yayılıma bağlıdır |
| İlişki tabanlı denetim artı veritabanı okuması | Kesinlikle hayır; bir milisaniye ve üstüdür | Spanner bile 0,5 milisaniyededir |

Yani mikrosaniye altı yetkilendirme ancak kararın önceden gerçeklenmiş olması hâlinde mümkündür. 2,6 mikrosaniyelik komisyoncu bunu yapmaktadır: karar zaten token'da yazılıdır ile yalnızca imzası doğrulanmaktadır.

Argus için gerçekçi hedef şudur.

| Yol | Hedef |
|---|---|
| Token doğrulama artı kaba yetki, birinci katman | 99. yüzdelikte beş mikrosaniyenin altı |
| İnce taneli denetim, önbellek isabeti ya da gerçeklenmiş | 99. yüzdelikte 100 mikrosaniyenin altı |
| İnce taneli denetim, önbellek ıskası, yerel veritabanı | 99. yüzdelikte beş milisaniyenin altı |
| Arama ile nesne listeleme | 99. yüzdelikte 50 milisaniyenin altı, zorunlu son tarihle |

Bunlar Zanzibar'ın ürettiğinden daha iyidir, çünkü Argus tek bölgede ile süreç içinde çalışacak ile küresel replikasyon vergisi ödemeyecektir.

---

## Bölüm 5 — Veri modeli ile göç

### 5.1 Rol tabanlıdan ilişki tabanlıya, doğru soyutlama

Projenin kendi açıklamasında şu tavsiye vardır: rol tablosuyla başlanmalı ile ilişki karmaşıklığı çıkınca OpenFGA ya da SpiceDB'ye taşınmalıdır.

Bu tavsiyenin tehlikeli tarafı şudur: rol tablosuyla başlanırsa uygulama kodu kullanıcının rolünü yönetici mi diye sormaktadır. Bu, kaynağa özgü olmayan bir sorudur ile ilişki tabanlı modele taşınırken her çağrı yerinin yeniden yazılması gerekmektedir. Maliyet tablo göçünde değil uygulama kodunun tamamındadır.

Doğru soyutlama, ilk günden özne, eylem ile kaynak alan bir denetim çağrısıdır. İçeride ne olduğu önemli değildir.

```rust
// Gün 1 — arkasında basit bir rol tablosu olabilir
authz.check(&user, "read", &Resource::document("doc-42")).await?

// Gün 500 — arkasında tam ReBAC var; ÇAĞRI YERİ DEĞİŞMEDİ
authz.check(&user, "read", &Resource::document("doc-42")).await?
```

Anahtar ilke şudur: kaynak parametresi ilk günden zorunlu olmalıdır, o gün için modelde kullanılmasa bile. Çünkü sonradan eklenemez; eklemek her çağrı yerini bulmayı gerektirmektedir.

Rol tabanlı erişim kontrolü ilişki tabanlının bir alt kümesidir: bir yönetici rolünün üyeliği de bir demettir. Yani ilişki tabanlı modelle başlayıp yalnızca rol şeklinde demetler yazmak hiçbir şey kaybettirmemekte ile göç maliyetini sıfırlamaktadır.

### 5.2 Şema evrimi

OpenFGA'nın modeli değişmez modellerdir; her değişiklikte yeni bir model kimliği üretilmektedir. Uygulama hangi model kimliğini kullanacağını belirtmektedir. Demetler modelden bağımsız saklanmaktadır.

Kritik ile tehlikeli davranış şudur: *"The tuples that are not valid according to the specified model, are ignored when evaluating queries."*

Bunun üç sonucu vardır.

1. Bir ilişki silinirse demetler kalmakta ile performansı düşürmektedir.
2. Model geri alınırsa o demetler yeniden aktif olmakta ile yetki sessizce geri gelmektedir.
3. Yeniden adlandırma sırasında hem eski hem yeni demetler bir süre yaşamaktadır, yani bir çift yazma penceresi vardır.

Argus için tasarım kararı şudur: geçersiz demetler sessizce yok sayılmamalıdır. En azından şunlar gerekmektedir: depo, tip ile ilişki etiketli bir yetim demet sayacı metriği; model yayımlarken bu değişikliğin kaç demeti yetimleştireceği uyarısı; ile yetim demetler için açık bir temizleme işi.

### 5.3 Yetkilendirme verisini kim yazmaktadır

Bu, sektörün en az konuşulan ancak en çok soruna yol açan problemidir.

| Model | Nasıl | Risk |
|---|---|---|
| Uygulama yazar | Belge oluşturulunca uygulama demeti yazar | İki fazlı işleme problemidir: uygulama veritabanına yazılmış ancak yetkilendirmeye yazılamamıştır; sonuç yetim bir kaynaktır, yani kimse erişememektedir, ya da tersidir, yani herkes erişmektedir |
| Kimlik sağlayıcı ya da yetkilendirme yazar | Merkezî bir API üzerinden | Uygulamanın iş mantığını bilmemektedir |
| Giden kutusu deseni | Uygulama kendi işleminde giden kutusu tablosuna yazar, ayrı bir işçi yetkilendirmeye taşır | En sağlamdır; nihai tutarlılık kabul edilmektedir |
| Değişiklik verisi yakalama | Uygulama veritabanından yakalanır | Şema bağımlılığı kırılgandır |

Senkronizasyon probleminin somut örneği şudur.

```
1. App: INSERT INTO documents (id, owner) VALUES ('doc-42', 'alice')  COMMIT
2. App: authz.write(document:doc-42#owner@user:alice)                 TIMEOUT
Sonuç: Belge var, sahibi yok. Alice kendi belgesini göremiyor.
```

Ters yön daha kötüdür.

```
1. App: authz.write(document:doc-42#viewer@user:bob)   OK
2. App: DELETE FROM documents WHERE id='doc-42'        OK
3. Yeni belge oluşturuldu, ID yeniden kullanıldı: 'doc-42'
Sonuç: Bob yeni belgeyi görüyor. YETKİ SIZINTISI.
```

Argus için zorunlu kurallar şunlardır.

1. Kaynak kimlikleri asla yeniden kullanılmamalıdır. UUID ya da ULID kullanılmalıdır. Bu, demet sızıntısının tek yapısal savunmasıdır.
2. Giden kutusu deseni birinci sınıf desteklenmelidir. Argus bekleyen yazmalar için bir API sunmalı ile demet yazma etkisiz kılınabilir olmalıdır; aynı demeti iki kez yazmak bir hata olmamalıdır, ki OpenFGA bunu 31 Ekim 2025'te yinelenen demetleri yazarken yok say özelliğiyle eklemiştir.
3. Silme işleminde art arda silme semantiği gerekmektedir: bir nesne silinince o nesneye ait tüm demetler silinmelidir. Argus bunu bir API olarak sunmalıdır, yoksa her uygulama kendi eksik sürümünü yazacaktır.

---

## Bölüm 6 — Güvenlik

### 6.1 Güvenlik açığı tablosu, gerçek veriler, OSV.dev, 8 Eylül 2026

#### OpenFGA, 26 danışmanlık

En kritik olanlar şunlardır; yetkilendirme atlatma sınıfı ayrıca belirtilmiştir.

| Tanımlayıcı | Tarih | Şiddet | Etkilenen | Özet |
|---|---|---|---|---|
| CVE-2026-55689 | 19 Haziran 2026 | Orta | 1.18.0 öncesi | OIDC izleyici kitle doğrulaması, ilgili bayrak ayarlanmamışsa atlanmaktadır |
| CVE-2026-55170 | 18 Haziran 2026 | Düşük | 1.18.0 öncesi | Hatalı politika uygulamasıdır |
| CVE-2026-48096 | 11 Haziran 2026 | Orta | 1.16.0 öncesi | Paylaşılan yineleyici ile ikinci sürüm yineleyicide önbellek anahtarı ayırıcı enjeksiyonudur; depo içi karar zehirlenmesine yol açmaktadır |
| CVE-2026-41131 | 22 Nisan 2026 | Orta | 1.14.1 öncesi | Hatalı politika uygulamasıdır |
| CVE-2026-40293 | 8 Nisan 2026 | Orta | 0.1.4 ile 1.14.0 arası | Kimlik doğrulamasız oyun alanı uç noktası önceden paylaşılmış API anahtarını HTML yanıtta sızdırmaktadır |
| CVE-2026-34972 | 7 Nisan 2026 | Orta | 1.8.0 ile 1.14.0 arası | Yığın denetimi içi tekilleştirme, liste değerli önbellek anahtarı çakışmasıyla yanlış karar üretmektedir |
| CVE-2026-33729 | 26 Mart 2026 | Orta | 1.13.1 öncesi | Önbeleklenmiş anahtarlar üzerinden yetkilendirme atlatmasıdır |
| CVE-2026-24851 | 5 Şubat 2026 | Orta | 1.8.5 ile 1.11.3 arası | Hatalı politika uygulamasıdır |
| CVE-2025-64751 | 20 Kasım 2025 | Orta | 1.4.0 ile 1.11.1 arası | Hatalı politika uygulamasıdır |
| CVE-2025-55213 | 18 Ağustos 2025 | Orta | 1.9.3 ile 1.9.5 arası | Yetkilendirme atlatmasıdır |
| CVE-2025-48371 | 23 Mayıs 2025 | Orta | 1.8.0 ile 1.8.13 arası | Yetkilendirme atlatmasıdır |
| CVE-2025-46331 | 30 Nisan 2025 | Orta | 1.3.6 ile 1.8.11 arası | Yetkilendirme atlatmasıdır |
| CVE-2025-25196 | 19 Şubat 2025 | Orta | 1.8.5 öncesi | Yetkilendirme atlatmasıdır |
| CVE-2024-56323 | 13 Ocak 2025 | Orta | 1.3.8 ile 1.8.3 arası | Yetkilendirme atlatmasıdır |
| CVE-2024-42473 | 9 Ağustos 2024 | Yüksek | 1.5.7 ile 1.5.9 arası | Yetkilendirme atlatmasıdır |
| CVE-2024-31452 | 16 Nisan 2024 | Yüksek | 1.5.0 ile 1.5.3 arası | Yetkilendirme atlatmasıdır |
| CVE-2024-23820 | 26 Ocak 2024 | Orta | 1.4.3 öncesi | Hizmet reddidir |
| CVE-2023-45810 | 18 Ekim 2023 | Yüksek | 1.3.4 öncesi | Hizmet reddidir |
| CVE-2023-43645 | 28 Eylül 2023 | Orta | 1.3.2 öncesi | Dairesel ilişki tanımlarından hizmet reddidir |
| CVE-2023-40579 | 25 Ağustos 2023 | Orta | 1.3.1 öncesi | Yetkilendirme atlatmasıdır |
| CVE-2023-35933 | 28 Haziran 2023 | Orta | 1.1.1 öncesi | Dairesel ilişki hizmet reddidir |
| CVE-2022-23542 | 20 Aralık 2022 | Yüksek | 0.3.0 ile 0.3.1 arası | Yetkilendirme atlatmasıdır |
| CVE-2022-39352 | 8 Kasım 2022 | Orta | 0.2.5 öncesi | Yetkilendirme atlatmasıdır |
| CVE-2022-39342 | 25 Ekim 2022 | Orta | 0.2.4 öncesi | Yetkilendirme atlatmasıdır |
| CVE-2022-39341 | 25 Ekim 2022 | Orta | 0.2.4 öncesi | Demet kümesi joker karakteriyle yetkilendirme atlatmasıdır |
| CVE-2022-39340 | 25 Ekim 2022 | Orta | 0.2.4 öncesi | Akışlı nesne listelemeyle bilgi ifşasıdır |

Kalıp analizi bir hikâye anlatmaktadır. Yaklaşık 16 tanesi doğrudan yetkilendirme atlatmasıdır; bu bir hizmet reddi ya da bilgi sızıntısı değil motorun temel işlevini yanlış yapmasıdır. En az üç tanesi önbellek kaynaklıdır, yani 2026'nın 48096, 33729 ile 34972 numaralı kayıtlarıdır; önbellek anahtarı üretimi bu sınıfta tekrarlayan bir zayıflık noktasıdır. 2026'da yedi yeni danışmanlık vardır ile hız yavaşlamamaktadır.

#### SpiceDB, 16 danışmanlık

| Tanımlayıcı | Tarih | Şiddet | Etkilenen | Özet |
|---|---|---|---|---|
| CVE-2026-55866 | 19 Haziran 2026 | Düşük | 1.34.0 ile 1.54.0 arası | Koşullu ilişkilerde denetim, koşullu izin beklenirken koşulsuz izin verebilmektedir |
| CVE-2026-46668 | 21 Mayıs 2026 | Düşük | 1.15.0 ile 1.52.0 arası | İç içe listeli koşul yapıları hatalı önbellek yeniden kullanımına yol açmaktadır |
| CVE-2026-40091 | 14 Nisan 2026 | Orta | 1.49.0 ile 1.51.1 arası | Veri deposu bağlantı adresi başlangıç günlüklerinde sızmaktadır |
| GHSA-vhvq-fv9f-wh4q | 6 Şubat 2026 | Düşük | 1.29.3 ile 1.49.1 arası | Kaynak arama imleci kurcalanınca ayrıştırma paniğiyle süreç çökmektedir |
| CVE-2025-65111 | 21 Kasım 2025 | Düşük | 1.47.1 öncesi | Kaynak arama eksik sonuç döndürmektedir |
| CVE-2025-64529 | 13 Kasım 2025 | Düşük | 1.45.2 öncesi | İlişki yazma yükü çok büyükse sessizce başarısız olmaktadır |
| CVE-2025-49011 | 6 Haziran 2025 | Düşük | 1.44.2 öncesi | Koşullu denetim, izin beklenirken izin vermemektedir |
| CVE-2024-48909 | 14 Ekim 2024 | Düşük | 1.35.0 ile 1.37.1 arası | İkinci sürüm kaynak aramada koşul bağlamı eksik hatasıdır |
| CVE-2024-46989 | 18 Eylül 2024 | Orta | 1.35.3 öncesi | Aynı tipte çoklu koşulda hatalı olarak izin verilmemektedir |
| CVE-2024-38361 | 20 Haziran 2024 | Orta | 1.33.1 öncesi | Dışlamalar izin beklenirken izin vermemektedir |
| CVE-2024-32001 | 10 Nisan 2024 | Düşük | 1.30.1 öncesi | Özne aramada kısmi sonuç dönmektedir |
| CVE-2024-27101 | 1 Mart 2024 | Yüksek | 1.29.2 öncesi | Parçalama yardımcısında tam sayı taşmasıdır; gönderim eleman kaçırmakta ya da panik oluşmaktadır |
| CVE-2023-46255 | 31 Ekim 2023 | Orta | 1.27.0-rc1 öncesi | Adres ayrıştırılamazsa günlük sızıntısıdır |
| CVE-2023-35930 | 28 Haziran 2023 | Düşük | 1.22.0 ile 1.22.2 arası | Kaynak aramada kısmi sonuçtur |
| CVE-2023-29193 | 13 Nisan 2023 | Yüksek | 1.19.1 öncesi | Metrik portu güvensiz ağa bağlanmakta ile komut satırı bayraklarını sızdırmaktadır |
| CVE-2022-21646 | 13 Ocak 2022 | Yüksek | 1.3.0 ile 1.4.0 arası | Arama operasyonları joker karakterleri hesaba katmamaktadır |

SpiceDB'nin kalıbı farklı ile öğreticidir. Çoğu bulgu kapalı başarısızlık yönündedir, yani izin verilmesi gerekirken verilmemektedir; bu bir kullanılabilirlik sorunudur, bir güvenlik açığı değildir. Bu, SpiceDB'nin tasarımının hata durumunda güvenli tarafa düştüğünü göstermektedir. İstisna 2026'nın 55866 numaralı kaydıdır: koşullu izin beklenirken koşulsuz izin verilmektedir. Bu gerçek bir atlatmadır.

Ayrıca koşul mekanizması SpiceDB'nin en hatalı alanıdır: beş ayrı kayıt vardır. Argus koşullu demetleri destekleyecekse bu alan yoğun test gerektirmektedir.

#### Diğerleri

| Ürün | Tanımlayıcı | Tarih | Şiddet | Özet |
|---|---|---|---|---|
| Ory Keto | CVE-2026-33505 | 20 Mart 2026 | Yüksek | Sahte sayfalama belirteçleriyle SQL enjeksiyonudur |
| biscuit-auth | CVE-2022-31053 | 17 Haziran 2022 | Kritik | İmza sahteciliğidir, 2.0.0 öncesi |
| biscuit-auth | CVE-2024-41949 ile 42350 | 31 Temmuz 2024 | Düşük | Üçüncü taraf blokta açık anahtar karışıklığıdır, dördüncü ana sürüm |
| OPA | CVE-2025-46569 | 1 Mayıs 2025 | Yüksek | Veri API'sinin HTTP yolu üzerinden Rego enjeksiyonudur |
| OPA | CVE-2022-36085 | 16 Eylül 2022 | Yüksek | `with` anahtar kelimesiyle güvensiz yerleşik kısıtlamasının atlatılmasıdır |
| OPA | CVE-2024-8260 | 30 Ağustos 2024 | Orta | Windows'ta SMB zorunlu kimlik doğrulamasıdır |
| cedar-policy | Kayıt yoktur | — | — | OSV'de crates.io ekosisteminde bir kayıt bulunamamıştır |
| casbin, crates.io | Kayıt yoktur | — | — | — |
| regorus, crates.io | Kayıt yoktur | — | — | — |
| Cerbos | Kayıt yoktur | — | — | — |

Cedar'ın sicilinin temiz olması dikkate değerdir ile muhtemelen bir tesadüf değildir. Formel doğrulama, diferansiyel rastgele test ile bulanık test birleşimi ölçülebilir bir fark yaratıyor görünmektedir. Cedar'ın OpenFGA'dan daha genç ile daha dar kapsamlı olduğu kaydı düşülmelidir.

### 6.2 Açık sınıfları ile test yaklaşımları

#### Birinci sınıf: önbellek anahtarı hataları

İlgili kayıtlar ayırıcı enjeksiyonu, önbeleklenmiş anahtarlarla atlatma, liste değeri çakışması ile iç içe liste önbellek yeniden kullanımıdır.

Kök neden şudur: önbellek anahtarı, yapılandırılmış veriden, yani demetten ile koşul bağlamından, dizgi birleştirmeyle üretilmektedir. Ayırıcı içeren bir alan, iki farklı girdinin aynı anahtarı üretmesine yol açabilmektedir.

Argus için savunma şudur.

```rust
// YANLIŞ
let key = format!("{}:{}#{}@{}", ns, obj, rel, user);

// DOĞRU — uzunluk-önekli veya kriptografik hash
let mut h = blake3::Hasher::new();
for field in [ns, obj, rel, user] {
    h.update(&(field.len() as u32).to_le_bytes());
    h.update(field.as_bytes());
}
```

Uzunluk öneki ayırıcı enjeksiyonunu yapısal olarak imkânsız kılmaktadır. Bu, tek satırlık bir savunmadır ile dört güvenlik açığını önlerdi.

#### İkinci sınıf: model hataları, yani kullanıcının kendi ayağına sıkması

Fazla geniş ilişki tanımı, yanlış üst nesne üzerinden miras kuran hatalı demet kümesi eşlemesi, joker karakterli demetler, ki 2022'nin 39341 ile 21646 numaralı kayıtları tam olarak budur, ile dışlamanın yanlış kullanımı, yani çift olumsuzlama hataları bu sınıftadır.

Bu, motorun hatası değil ancak motorun sorumluluğudur. Argus, model yayımlanırken statik analiz yapmalı ile bu modelin bir joker karakterle yazma yetkisi verdiği konusunda uyarmalıdır.

#### Üçüncü sınıf: kimlik karışıklığı ile kiracı sızıntısı

Kullanıcı silinip aynı kimliğin yeniden kullanılması eski demetlerin yeni kullanıcıya yetki vermesine yol açmaktadır. Özne kimliği ad alanı çakışması, örneğin aynı sayısal kimliğin hem kullanıcı hem servis olarak kullanılması, bir başka yoldur. Çok kiracılı yapıda depo ile kiracı sınırının denetim yolunda her adımda kontrol edilmemesi üçüncüsüdür.

Savunma şudur: kimlikler küresel olarak benzersiz ile yeniden kullanılamaz olmalıdır, yani ULID kullanılmalıdır. Kiracı kimliği önbellek anahtarının parçası olmalıdır; 2026'nın 48096 numaralı kaydındaki depo içi zehirlenme ifadesi bunun ihlalidir.

#### Dördüncü sınıf: uygulama noktası boşluğu ile kontrol ile kullanım arası yarış

Denetim yapılmış ancak uygulanmamıştır durumu buradadır. AuthZEN şartnamesinin kendi güven modeli bunu kabul etmektedir: *"the PDP must trust the PEP, as the PEP is ultimately responsible for enforcing the decision."*

Güvensiz doğrudan nesne referansı ile nesne düzeyi yetkilendirme kırılması, yani OWASP API ilk onusunun birincisi, burada doğmaktadır. Bir yetkilendirme motoru kullanmak bunu çözmemekte, yalnızca doğru soruyu sormayı mümkün kılmaktadır. Kod belge işleyicisinde denetim çağırmıyorsa dünyanın en iyi motoru işe yaramamaktadır.

Argus'un yapabileceği şudur: ara katman ile çıkarıcı seviyesinde varsayılan olarak kapalı başarısız olan bir tasarım. Rust'ın tip sistemi burada gerçek bir avantajdır.

```rust
// Resource'a erişim, ancak bir AuthorizedResource token'ı ile mümkün
// Bu token yalnızca check() tarafından üretilebilir
fn get_document(auth: Authorized<Document, Read>) -> Document { ... }
```

Bu, denetim yapmayı unutmayı bir derleme zamanı hatasına dönüştürmektedir. Argus'un Rust'ta olmasının en büyük tek güvenlik avantajıdır ile Go tabanlı rakiplerin yapamayacağı bir şeydir.

#### Beşinci sınıf: şaşkın vekil

Argus'un kendi yönetim API'si bir yetki yükseltme yoludur. Kim demet yazabilir sorusu Argus'un kendi yetkilendirme modeliyle cevaplanmalıdır, yani kendi ürününü kullanmalıdır; ancak bu bir önyükleme problemi yaratmaktadır. Ayrı, basit ile denetlenmiş bir yol gerekmektedir.

### 6.3 Erişim kontrolü mantığını test etmek

#### Cedar'ın yaklaşımı, sektörün en iyisi

Üç katmanlı doğrulama güdümlü geliştirmedir.

1. Lean 4 ile formel kanıt: yedi özellik, 5.714 satır kanıt ile 1.673 satır model. Tüm kanıtlar üç dakikada doğrulanmaktadır. Dört hata bulmuştur.
2. Diferansiyel rastgele test: milyonlarca rastgele girdi, yani politika, veri ile istek, hem Lean modeline hem Rust üretim koduna gönderilmekte ile farklı cevap bir hata sayılmaktadır. `cargo-fuzz` ile libfuzzer kullanılmakta ile hedef başına altı saat koşulmaktadır.
3. Özellik tabanlı test: modellenmemiş üretim bileşenleri içindir.

Diferansiyel ile özellik tabanlı test birlikte 21 hata bulmuştur. Toplam 25'tir.

Makalenin çok değerli bir itirafı şudur: *"Complete line coverage alone does not guarantee effective testing"*. Bir üretici tam satır kapsamı sağlasa bile üretilen girdilerin çoğu ilginç değildi. Diferansiyel test bazı hataları kaçırmıştır, sonlanmama hatası dahil, çünkü tetikleyici girdiyi üretme olasılığı çok düşüktü.

Girdi üretimi stratejisi tip güdümlüdür: politika, varlık ile istek üretimi korelasyonludur. Rastgele üretim yetersizdir, çünkü çoğu rastgele istek hiçbir politikayla eşleşmemekte ile hedef kodu çalıştırmamaktadır.

#### Argus için somut test planı

| Katman | Araç | Ne test edilmektedir |
|---|---|---|
| Özellik tabanlı | `proptest` 1.11.0 | Aşağıdaki değişmezlerdir |
| Diferansiyel | İki bağımsız gerçekleme | Naif referans çözümleyiciyle optimize edilmiş motor aynı cevabı vermelidir |
| Bulanık test | `cargo-fuzz` | Model ayrıştırıcısı, demet ayrıştırıcısı, önbellek anahtarı üretimi ile imleç çözme |
| Model testleri | YAML tabanlı, OpenFGA'nın model testi gibi | Kullanıcının kendi modeli için doğrulamalardır |
| Metamorfik | Elle | Aşağıdaki dönüşümlerdir |

Test edilecek değişmezler, `proptest` ile ifade edilebilir biçimde şunlardır.

```
1. Determinizm:        check(s,a,r,T) == check(s,a,r,T)
2. Monotonluk (+):     tuple eklemek hiçbir ALLOW'u DENY'a çeviremez
                       (exclusion içermeyen modellerde)
3. Monotonluk (-):     tuple silmek hiçbir DENY'ı ALLOW'a çeviremez
4. Check/List uyumu:   r ∈ list_objects(s,a)  ⟺  check(s,a,r) == ALLOW
                       ← BU BEŞ CVE'NİN KAYNAĞI, EN ÖNEMLİ TEST
5. List/Search uyumu:  s ∈ search_subject(a,r) ⟺ check(s,a,r) == ALLOW
6. Cache şeffaflığı:   check_cached(...) == check_uncached(...)
                       ← CVE-2026-33729, 48096, 34972'nin kaynağı
7. Batch tutarlılığı:  batch_check([q1..qn])[i] == check(qi)
                       ← CVE-2026-34972'nin kaynağı
8. Tenant izolasyonu:  store A'daki hiçbir tuple, store B'nin kararını etkilemez
9. Sonlanma:           her check sonlu adımda biter (döngüsel modellerde bile)
                       ← CVE-2023-43645, CVE-2023-35933'ün kaynağı
10. Zookie monotonluğu: t2 > t1 ise, t1'de görünen her tuple t2'de de görünür
```

Dördüncü, altıncı ile yedinci değişmezi test etmek, incelenen güvenlik açıklarının en az sekizini önlerdi. Bu bir spekülasyon değildir; açık özetleri doğrudan bu değişmezlerin ihlalidir.

Formel doğrulamanın Argus için gerçekçi olup olmadığı sorusunun cevabı şudur: Cedar'ın 5.714 satır Lean kanıtı ile 3,4'e bir kanıt model oranı ciddi bir yatırımdır. Ancak kısmi bir yol vardır: yalnızca çekirdek karar fonksiyonunun, yani Cedar'ın ilk dört özelliğinin muadilinin modellenmesi, tam bir ilişki tabanlı çözümleyicinin doğrulanmasından çok daha ucuzdur. Öneri şudur: birinci sürüm için diferansiyel ile özellik tabanlı test yeterlidir ile formel doğrulama ikinci sürüm hedefidir.

### 6.4 Açık başarısızlık ile kapalı başarısızlık

AuthZEN'in duruşu şudur: ret, 200 OK ile olumsuz karar yüküdür. Hata, yani dört yüzlü ya da beş yüzlü kod, bir karar değildir. Şartname bu ayrımı net yapmakta ancak karar noktasına ulaşılamazsa ne yapılması gerektiği konusunda uygulama noktasına bırakmaktadır; güven modeli gereğidir.

Sektör pratiği ile doğru cevap kapalı başarısızlıktır. Ancak bu bir kullanılabilirlik riski yaratmaktadır: karar noktası çökerse tüm sistem durmaktadır.

Zanzibar'ın cevabı erişilebilirliği o kadar yükseltmektir ki soru sorulmasın: %99,999'un üzerinde, üç yıl, 30'dan fazla bölge ile 10.000'den fazla sunucu. Bu, çoğu ekibin ulaşamayacağı bir yatırımdır.

Argus'un cevabı farklı olmalıdır: karar noktası ayrı bir hata alanı yapılmamalıdır. Yetkilendirme motoru kimlik sağlayıcı sürecinin içindeyse, karar noktası erişilemez durumu kimlik sağlayıcı erişilemez durumundan ayrı değildir. Ağ sıçramasını kaldırmak, bir performans optimizasyonu olduğu kadar bir erişilebilirlik optimizasyonudur.

Devre kesici ile son bilinen iyi karar önbelleği tehlikelidir: yetkisi geri alınmış bir kullanıcı, karar noktası kesintisi sırasında önbellekteki eski izinle içeri girmektedir. Bu, saldırganın karar noktasına hizmet reddi yaparak yetki elde edebileceği anlamına gelmektedir. Öneri şudur: kesinti sırasında yalnızca olumlu kararların yaşam süresi uzatılmamalı, olumsuz kararlar serbestçe uzatılabilmelidir.

### 6.5 Denetlenebilirlik

| Ürün | Mekanizma |
|---|---|
| OpenFGA | `Expand` API'sidir; nesnenin kullanıcı kümesi ağacını döndürmektedir |
| SpiceDB | Hata ayıklama ile izleme, yani denetim hata ayıklama izidir |
| Cedar | `Diagnostics`'tir; kararı belirleyen politikalar ile hataları vermektedir |
| OPA | Karar günlükleridir |
| AuthZEN | Bağlam içindeki yönetici ile kullanıcı gerekçesidir |

AuthZEN'in yönetici ile kullanıcı gerekçesi ayrımı doğru bir tasarımdır ile Argus benimsemelidir: yönetici hangi politikanın başarısız olduğunu görmekte, kullanıcı yetersiz ayrıcalık mesajı almaktadır. Kullanıcıya tam nedeni söylemek kaynak varlığını ile model yapısını sızdırmaktadır.

Argus'un sunması gerekenler şunlardır.

1. Karar izi: hangi demetler, hangi ilişkiler ile hangi yol. Hata ayıklama modundadır ile üretimde örneklenmiştir.
2. Karar günlüğü: her karar için zaman damgası, özne, eylem, kaynak, karar, model kimliği, tutarlılık belirteci ile gecikme. Kişisel veri riski vardır, çünkü özne ile kaynak kimlikleri hassas olabilmektedir; özetlenmiş bir varyant seçeneği sunulmalıdır.
3. Erişim gözden geçirme sorguları, yani SOC 2 ile ISO 27001 için: şu roldeki tüm kullanıcılar ile şu kaynağa erişebilen herkes. Bunlar özne arama uç noktasıdır. Yani AuthZEN'in arama API'si yalnızca bir özellik değil bir uyum gereksinimidir.

### 6.6 Kimlik sağlayıcının yetkilendirme motoru olmasının ek riskleri

| Risk | Açıklama | Azaltma |
|---|---|---|
| Patlama yarıçapı | Kimlikle yetki aynı süreçtedir ile bir uzaktan kod çalıştırma her ikisini de vermektedir | Süreç içi ayrıcalık ayrımı ile yetkilendirme yazma yolunun ayrı yetkilendirilmesidir |
| Yönetim API'si bir yetki yükseltme yoludur | Demet yazabilen kendine yönetici verebilmektedir | Yönetim API'sinin kendisi ince taneli korunmalı ile acil durum erişimi ayrı olmalıdır |
| Çok kiracılı izolasyon | Depo sınırı her katmanda kontrol edilmelidir | Kiracı kimliğinin önbellek anahtarı ile tip sistemi seviyesinde taşınmasıdır |
| Önyükleme | İlk yöneticiyi kim yaratmaktadır | Ayrı, basit ile tam denetlenen bir yoldur |

---

## Bölüm 7 — Argus için karar ile mimari

### 7.1 Karşılaştırma özeti

| Kriter | OpenFGA | SpiceDB | Cedar | Ory Keto | Kendi motorumuz |
|---|---|---|---|---|---|
| Dil | Go | Go | Rust | Go | Rust |
| Model | İlişki tabanlı | İlişki tabanlı | Öznitelik tabanlı artı hiyerarşi | İlişki tabanlı | İlişki artı öznitelik tabanlı |
| Rust'a gömülebilir | Hayır | Hayır | Evet | Hayır | Evet |
| Tutarlılık belirteci | Hayır | Evet | Yoktur, durumsuzdur | Hayır | Evet, tasarlanacaktır |
| Varlık ile demet deposu | Evet | Evet | Hayır | Evet | Evet |
| Nesne listeleme | Evet, risklidir | Evet, risklidir | Hayır | Evet | Evet, kısıtlıdır |
| Formel doğrulama | Hayır | Hayır | Evet; yedi özellik, Lean 4 | Hayır | Kısmidir, hedeftir |
| Atlatma açığı sayısı | Yaklaşık 16 | Yaklaşık üç | Sıfır | Bir, SQL enjeksiyonu | — |
| Olgunluk | CNCF kuluçka | Üretim | Üretim, AWS | Bakım modu | Yoktur |
| Lisans | Apache 2.0 | Doğrulanmamıştır | Apache 2.0 | Apache 2.0 | Bizimdir |
| Ölçülmüş gecikme | 89 ile 746 mikrosaniye, bellek veritabanı | — | Dört ile 11 mikrosaniye | — | Hedef 100 mikrosaniyenin altıdır |
| Son sürüm | 1.19.0, 25 Ağustos 2026 | 1.56.1, 26 Ağustos 2026 | 4.12.0, 28 Temmuz 2026 | 26.2.0, 20 Mart 2026 | — |

### 7.2 Karar: gömülü, kendi motorumuz ile Cedar'dan ilham alan

#### Gerekçe

Birincisi, harici bir motor Rust'ta mümkün değildir. OpenFGA ile SpiceDB Go'dur. Rust'tan kullanmak bir gRPC sıçraması, yani her istekte bir ile 15 milisaniye artı ayrı bir hata alanı demektir. Bir kimlik sağlayıcının token uç noktası için kabul edilemez. Rust ilişki tabanlı erişim kontrolü crate'leri, yani 90 günde 25 indirmeli `openfga-rs` ile dokuz indirmeli `authzed`, ölüdür.

İkincisi, Cedar tek başına yetmemektedir. Varlık deposu yoktur ile nesne listelemesi yoktur. İlişki tabanlı erişim kontrolünün zor kısmını, yani ilişki depolamayı ile geçişli çözümlemeyi çözmemektedir. Ancak bir politika değerlendirme katmanı olarak mükemmeldir: dört ile 11 mikrosaniye, formel doğrulanmış, sıfır güvenlik açığı ile Rust yerlisidir.

Üçüncüsü, güvenlik açığı verileri olgun ürünü al argümanını zayıflatmaktadır. OpenFGA'nın 16 atlatma açığı, bu problem sınıfının doğası gereği zor olduğunu göstermektedir; hazır bir çözüm almak riski ortadan kaldırmamakta, yalnızca başkasının hataları devralınmaktadır. OpenFGA gömülemediği için hata düzeltmeleri de kontrol edilememektedir.

Dördüncüsü, Rust'ın tip sistemi rakiplerin veremeyeceği bir güvenlik avantajı sunmaktadır; 6.2'nin dördüncü sınıfına bakınız.

#### Riskin dürüst kabulü

Kendi motorunu yazmak, incelenen 42 güvenlik açığının kendi sürümlerini yazmak demektir. Bu kararın tek savunması, 6.3'teki test disiplinini birinci günden uygulamaktır. Cedar bunu yapmıştır ile sicili temizdir. OpenFGA yapmamıştır ile 16 atlatma açığı vardır. Fark bir tesadüf değildir.

### 7.3 Arayüz tasarımı

#### Çekirdek özellik, tüm sistemin taahhüdüdür

```rust
/// Yetkilendirme kararının tek giriş noktası.
/// Bu imza SABİTTİR — arkasındaki her şey değişebilir.
#[async_trait]
pub trait AuthzEngine: Send + Sync {
    /// Tek karar. Sıcak yol. Hedef: p99 < 100 µs (cache hit).
    async fn check(&self, req: &CheckRequest) -> Result<Decision, AuthzError>;

    /// Toplu karar. N+1'i önler. AuthZEN /evaluations'a eşlenir.
    async fn batch_check(
        &self,
        reqs: &[CheckRequest],
        semantics: BatchSemantics,   // ExecuteAll | DenyOnFirstDeny | PermitOnFirstPermit
    ) -> Result<Vec<Decision>, AuthzError>;

    /// Öznenin erişebildiği kaynaklar. PAHALI — deadline ZORUNLU.
    /// AuthZEN /search/resource'a eşlenir.
    async fn search_resources(&self, req: &ResourceSearchRequest)
        -> Result<Page<ResourceRef>, AuthzError>;

    /// Kaynağa erişebilen özneler. PAHALI. Uyum/denetim için.
    async fn search_subjects(&self, req: &SubjectSearchRequest)
        -> Result<Page<SubjectRef>, AuthzError>;

    /// Karar ağacını açıklar. Debug ve denetim.
    async fn explain(&self, req: &CheckRequest) -> Result<DecisionTrace, AuthzError>;

    /// İlişki yazma. Idempotent.
    async fn write(&self, ops: &[TupleOp]) -> Result<ConsistencyToken, AuthzError>;

    /// Değişiklik akışı. Cache invalidation ve dış senkronizasyon için.
    fn watch(&self, from: ConsistencyToken)
        -> impl Stream<Item = Result<TupleChange, AuthzError>>;
}
```

```rust
pub struct CheckRequest {
    pub subject:  EntityRef,          // type + id
    pub action:   ActionRef,          // name
    pub resource: EntityRef,          // type + id
    pub context:  Context,            // ABAC öznitelikleri (Cedar'a gider)

    /// Zookie eşdeğeri. None = minimize_latency.
    pub consistency: Consistency,

    /// Kalıcı olmayan, istek-kapsamlı tuple'lar (OpenFGA'nın contextual tuples'ı).
    /// GÜVENLİK: bunlar yalnızca GÜVENİLEN PEP'lerden kabul edilmeli.
    pub contextual_tuples: Vec<Tuple>,
}

pub enum Consistency {
    /// Cache'ten servis edilebilir. Varsayılan.
    MinimizeLatency,
    /// En az bu token kadar taze. new enemy'ye karşı doğru araç.
    AtLeastAsFresh(ConsistencyToken),
    /// Cache atlanır, DB'ye gidilir.
    FullyConsistent,
}

pub struct Decision {
    pub allowed: bool,
    /// AuthZEN reason_admin/reason_user ayrımı
    pub reason_admin: Option<Reason>,
    pub reason_user:  Option<Reason>,
    /// Kararın hangi revision'da verildiği
    pub evaluated_at: ConsistencyToken,
}
```

#### Derleme zamanı zorlama, Rust'ın süper gücü

```rust
/// Yalnızca check() başarılı olursa üretilebilen bir kanıt token'ı.
/// Yapıcısı private — kaçış yok.
pub struct Authorized<R, A> { resource: R, _action: PhantomData<A> }

// Handler imzası, yetkilendirmeyi ZORUNLU kılar.
// check çağrılmazsa DERLEME HATASI.
async fn delete_document(doc: Authorized<Document, actions::Delete>) -> Result<()> {
    // Buraya gelindiyse yetki kanıtlanmıştır.
}
```

Bu kalıp, denetim yapmayı unutma hatasını, yani güvensiz doğrudan nesne referansının birincil kaynağını, yapısal olarak ortadan kaldırmaktadır. Go tabanlı hiçbir motor bunu veremez.

### 7.4 Veri modeli

#### Demet: Zanzibar'ın grameri, iyileştirmelerle

```
object_type : object_id # relation @ subject_type : subject_id [# subject_relation]
                                                    [with condition_name(params)]
```

Zanzibar'dan sapmalar ile gerekçeleri şunlardır.

| Karar | Gerekçe |
|---|---|
| Özne kimliği bir dizgidir, tam sayı değildir | Zanzibar tam sayı kullanmaktadır, ki Google'ın iç kimliğidir. Argus'un dış kimlikleri vardır. ULID zorunludur ile yeniden kullanım yoktur |
| Koşullu demet desteği vardır | Öznitelik tabanlı erişim ihtiyacı gerçektir. Ancak SpiceDB'nin beş koşul açığı göz önüne alınarak yoğun test gerekmektedir |
| Depo kimliği her satırda ile her önbellek anahtarındadır | Kiracı izolasyonudur, yani 2026'nın 48096 numaralı kaydının dersidir |

#### PostgreSQL şeması

```sql
CREATE TABLE tuples (
    store_id        UUID        NOT NULL,
    object_type     TEXT        NOT NULL,
    object_id       TEXT        NOT NULL,
    relation        TEXT        NOT NULL,
    subject_type    TEXT        NOT NULL,
    subject_id      TEXT        NOT NULL,
    subject_relation TEXT       NOT NULL DEFAULT '',   -- '' = doğrudan subject
    condition_name  TEXT,
    condition_ctx   JSONB,
    -- MVCC: SpiceDB'nin Postgres yaklaşımı
    created_xid     BIGINT      NOT NULL,
    deleted_xid     BIGINT      NOT NULL DEFAULT 9223372036854775807,  -- +sonsuz
    PRIMARY KEY (store_id, object_type, object_id, relation,
                 subject_type, subject_id, subject_relation, created_xid)
);

-- İleri yön: Check ve Expand ("bu nesneye kimlerin R ilişkisi var?")
CREATE INDEX tuples_fwd ON tuples
    (store_id, object_type, object_id, relation)
    INCLUDE (subject_type, subject_id, subject_relation)
    WHERE deleted_xid = 9223372036854775807;

-- Ters yön: ListObjects/search_resource ("bu özne hangi nesnelere bağlı?")
CREATE INDEX tuples_rev ON tuples
    (store_id, subject_type, subject_id, subject_relation, relation)
    INCLUDE (object_type, object_id)
    WHERE deleted_xid = 9223372036854775807;

-- Değişiklik akışı: watch() ve cache invalidation
CREATE INDEX tuples_changelog ON tuples (store_id, created_xid);
```

Neden iki indeks gerektiği şudur: denetim ileri yönde, nesne listeleme ters yönde yürümektedir. Tek bir indeks ikisini de veremez; bu, nesne listelemenin neden pahalı olduğunun depolama seviyesindeki açıklamasıdır.

Neden çok sürümlü eşzamanlılık denetimi kullanıldığı şudur: tutarlılık belirtecinin temelidir. Silinme işlem kimliği koşuluyla herhangi bir geçmiş revizyonda sorgu yapılabilmektedir. SpiceDB'nin PostgreSQL arka ucu tam olarak bunu yapmakta ile standart dışı eklenti gerektirmemektedir.

#### Tutarlılık belirteci, yani Zanzibar belirtecinin eşdeğeri

```rust
/// Opak, imzalı. İstemci içeriğine bağımlı olmamalı.
pub struct ConsistencyToken(Box<str>);
// içerik: base64(HMAC(store_id || xid || issued_at))
```

Sözleşme istemciye açıkça anlatılmalıdır.

1. Yazma işlemi bir belirteç döndürmektedir.
2. İstemci, korunan kaynağın yanında bu belirteci saklamaktadır, ki Zanzibar'ın modelidir.
3. O kaynak için denetim yaparken en az bu kadar taze koşuluyla göndermektedir.
4. Argus, o revizyondan eski bir önbellek girdisi kullanmayacağını garanti etmektedir.

Çöp toplama penceresi şöyledir: belirteç, önerilen 24 saatlik pencereden eski olursa anlık görüntü süresi doldu hatası dönmekte ile istemci tam tutarlı moda düşmektedir. Bu davranış dokümante edilmelidir.

### 7.5 Sıcak yol tasarımı

#### Üç katmanlı çözümleme

```
İstek gelir
    │
    ├─ KATMAN 0: Token claim'i (kaba yetki)          ~1 µs
    │    "kullanıcı bu tenant'ta mı? rolü ne?"
    │    Kaynak: doğrulanmış JWT. DB yok, cache yok.
    │    Yeterli olamaz — sadece hızlı ret için.
    │            │
    │            └─ Kesin ret → dön (fail-closed)
    │
    ├─ KATMAN 1: Karar cache (decision cache)        ~200 ns
    │    Anahtar: blake3(store_id ‖ subject ‖ action ‖ resource ‖ model_id ‖ rev)
    │    UZUNLUK-ÖNEKLİ hash — string concat DEĞİL (CVE-2026-48096)
    │    Beklenen hit oranı: %10-20 (Google'ın gerçek verisi)
    │            │
    │            └─ hit → dön
    │
    ├─ KATMAN 2: Materialized index (Leopard yolu)   ~1-10 µs
    │    Roaring bitmap: MEMBER2GROUP ∩ GROUP2GROUP
    │    Sadece "sıcak" relation'lar için (grup üyeliği, org üyeliği)
    │    Zanzibar ölçümü: 150 µs medyan — biz in-process olduğumuz için daha hızlı
    │            │
    │            └─ kesin cevap → cache'e yaz, dön
    │
    ├─ KATMAN 3: Graph çözümleme + alt-problem cache  ~10-100 µs
    │    Ağırlıklı graf planlayıcı (OpenFGA'nın weighted graph fikri)
    │    Alt-problem sonuçları cache'lenir (Google: bu asıl kazanç)
    │    Derinlik limiti 25, genişlik limiti 10 (döngü koruması)
    │            │
    │            └─ tuple gerekiyorsa ↓
    │
    └─ KATMAN 4: Postgres okuması                     ~0.5-2 ms
         Singleflight deduplikasyon (aynı sorgu paralel gelirse tek gider)
         Batch/pooling: aynı check'in tüm okumaları gruplanır (Zanzibar'ın yöntemi)
```

#### Öznitelik koşulları: Cedar gömülmelidir

Üçüncü katmanda bir koşullu demete rastlanırsa, koşulu Argus'un kendi mini diliyle değerlendirmek yerine `cedar-policy` crate'i çağrılmalıdır. Gerekçeleri şunlardır: ölçülmüş dört ile 11 mikrosaniye bütçe içindedir; yedi formel kanıtlanmış özelliği vardır; sıfır güvenlik açığı kaydı vardır; Rust yerlisidir ile yabancı fonksiyon arayüzü gerektirmemektedir; ile bakımını AWS yapmaktadır.

Bu, kendi motorunu yaz kararının en akıllı istisnasıdır: ilişki tabanlı grafı kendimiz yazmaktayız, çünkü kimse Rust'ta vermemektedir; ancak politika ile koşul değerlendirmesini yazmamaktayız, çünkü Cedar zaten en iyisini yapmıştır.

#### Önbellek geçersizleştirme

Üç mekanizma birlikte kullanılmalıdır.

1. Revizyon önbellek anahtarındadır ile yapısal geçersizleştirme sağlamaktadır. Yeni revizyon yeni anahtar demektir ile eski girdi erişilemez hâle gelmektedir, ki SpiceDB modelidir. Bu ana mekanizmadır.
2. İzleme akışı: yazma olduğunda etkilenen alt ağaçlar öngörülü biçimde düşürülmektedir.
3. Yaşam süresi: son savunma hattıdır. Olumlu için 10 saniye, olumsuz için bir saniye ya da altıdır.

#### Zorunlu kotalar, hasar kontrolü

| Limit | Değer | Gerekçe |
|---|---|---|
| Çözümleme derinliği | 25 | OpenFGA ile aynıdır; döngü korumasıdır, 2023'ün 43645 numaralı kaydı |
| Çözümleme genişliği | 10 | Yayılım patlaması korumasıdır |
| Denetim zaman aşımı | 100 milisaniye | Sıcak yol bütçesidir |
| Arama son tarihi | Bir saniye, serttir | Nesne listeleme tehlikesidir |
| Arama azami sonucu | 1000 | Sayfalama zorunludur |
| Yazma başına demet | 1000 | OpenFGA'nın 100'ünden yüksektir; yığın giden kutusu içindir |
| Depo başına tip | 200 | Model karmaşıklığı sınırıdır |

### 7.6 AuthZEN politika karar noktası olmak, kontrol listesi

Argus'un AuthZEN uyumlu olması için gerekenler şunlardır.

| Sıra | Gereksinim | Zorunluluk | Argus'ta karşılığı |
|---|---|---|---|
| 1 | `POST /access/v1/evaluation` | Zorunludur | Denetim çağrısıdır |
| 2 | `POST /access/v1/evaluations` artı üç semantik | İsteğe bağlıdır, yapılmalıdır | Yığın denetimidir |
| 3 | `POST /access/v1/search/resource` | İsteğe bağlıdır, yapılmalıdır | Kaynak aramasıdır |
| 4 | `POST /access/v1/search/subject` | İsteğe bağlıdır, uyum için gereklidir | Özne aramasıdır |
| 5 | `POST /access/v1/search/action` | İsteğe bağlıdır | Eylem aramasıdır |
| 6 | `GET /.well-known/authzen-configuration` | Zorunludur | Metadata uç noktasıdır |
| 7 | Ret, 200 ile olumsuz karar yüküdür | Zorunludur | Hata semantiği karıştırılmamalıdır |
| 8 | `X-Request-ID` yankısı | Varsa zorunludur | İz korelasyonudur |
| 9 | Bilinmeyen alanları yok say | Zorunludur | serde düzleştirme dikkatli kullanılmalıdır |
| 10 | TLS ile uygulama noktası kimlik doğrulaması | Sırasıyla zorunlu ile önerilendir | mTLS ya da OAuth'tur |
| 11 | I-JSON, RFC 7493 | Önerilendir | UTF-8 ile IEEE 754 sınırlarıdır |
| 12 | Hizmet reddi korumaları | Önerilendir | Yük boyutu ile iç içe geçme derinliğidir |
| 13 | Yönetici ile kullanıcı gerekçesi | İsteğe bağlıdır, yapılmalıdır | Bilgi sızıntısı kontrolüdür |

Ek olarak tutarlılık belirteci `context.consistency_token` altında taşınmalı, yetenekler dizisinde ilan edilmeli ile bu boşluk AuthZEN çalışma grubuna bildirilmelidir.

Stratejik olarak OAuth 2.0 token verme profili ile yetkilendirme iddiaları profili taslakları takip edilmelidir. Bir kimlik sağlayıcının bunları gerçeklemesi Argus'u AuthZEN ekosisteminde benzersiz kılmaktadır, çünkü diğer karar noktası satıcıları token vermemektedir.

### 7.7 Yol haritası

| Faz | Kapsam | Doğrulama |
|---|---|---|
| F0 | Motor özelliği ile naif referans gerçeklemesi; önbellek yok, indeks yok ile doğruluk odaklıdır | Bu, diferansiyel testin referans kâhini olacaktır |
| F1 | PostgreSQL çok sürümlü demet deposu, tutarlılık belirteci, graf çözümleme ile derinlik ve genişlik limitleri | `proptest` ile 10 değişmez; F0'a karşı diferansiyel test |
| F2 | Cedar tümleştirmesi, yani koşullu demetler, artı alt problem önbelleği ile tek uçuş tekilleştirmesi | Altıncı değişmez, yani önbellek şeffaflığı; bir güvenlik açığı sınıfını kapatmaktadır |
| F3 | AuthZEN karar noktası uç noktaları, iyi bilinen yapılandırma ile yığın semantikleri | Yedinci değişmez, yani yığın tutarlılığı |
| F4 | Arama API'leri, sert son tarih ile sayfalamayla | Dördüncü değişmez, yani denetim ile liste uyumu; beş güvenlik açığının sınıfıdır |
| F5 | Sıcak ilişkiler için gerçeklenmiş indeks, yani roaring bitmap | Dördüncü ile altıncı değişmez tekrar; indeksli ile indekssiz diferansiyel test |
| F6 | Ağırlıklı graf planlayıcı | Planlayıcılı ile planlayıcısız diferansiyel test; OpenFGA'nın 1.18.2'de düzelttiği hataların dersidir |
| F7 | Çekirdek karar fonksiyonunun Lean modeli, yani Cedar'ın ilk dört özelliğinin muadili | Formel kanıt |

Her fazda F0 referansına karşı diferansiyel test zorunludur. Bu, Cedar'ın diferansiyel rastgele testinin Argus'a uyarlanmasıdır ile incelenen güvenlik açıklarının çoğunu önleyecek tek disiplindir.

---

## Kaynaklar

Birincil akademik kaynaklar şunlardır. Zanzibar: Google'ın tutarlı, küresel yetkilendirme sistemi, USENIX ATC 2019; PDF indirilip metni çıkarılmıştır ile Tablo 2, 2.1, 2.2, 3.2.4 ile dördüncü bölümler kullanılmıştır; www.usenix.org/system/files/atc19-pang.pdf. Cedar: açıklayıcı, hızlı, güvenli ile analiz edilebilir yetkilendirme için yeni bir dil, genişletilmiş sürüm, arXiv 2403.04651, Mart 2024; 5.2 bölümündeki kıyaslama kullanılmıştır. Cedar'ı nasıl inşa ettik: doğrulama güdümlü bir yaklaşım, arXiv 2407.01688, FSE Companion 2024; 3.2 bölümündeki yedi özellik ile Tablo 1 kullanılmıştır. Güvensiz devretme, Dantuluri ile Sundi, arXiv 2609.00267, 31 Ağustos 2026; 7.2 ile 7.3 bölümleri kullanılmıştır. Cedar'ın OOPSLA 2024 yayını ACM sayısal kütüphanesindedir, doi 10.1145/3649835; erişilememiş ile arXiv sürümü kullanılmıştır.

Birincil şartname kaynakları şunlardır. Yetkilendirme API'si 1.0 nihai sürümü, 11 Ocak 2026, openid.net/specs/authorization-api-1_0-final.html. Nihai şartnamenin onay duyurusu, 12 Ocak 2026, oylama 81 kabul, bir ret ile 25 çekimser. AuthZEN çalışma grubu sayfası ile AuthZEN blog etiketi. Yeni çalışma grubu taslakları duyurusu, 15 Haziran 2026. openid/authzen GitHub deposu.

Birincil ürün dokümantasyonu şunlardır. OpenFGA yapılandırma seçenekleri, ki tüm bayrak varsayılanları oradandır; sorgu tutarlılığı sayfası, ki tutarlılık belirtecinin yokluğu oradandır; ilişki sorguları sayfası, ki yığın denetimi limitleri ile nesne listeleme uyarıları oradandır; model göçü sayfası; değişiklik okuma sayfası; üretimde çalıştırma sayfası; blog, ki 21 Temmuz 2026 tarihli ağırlıklı graf çözümlemesi yazısı oradandır; GitHub sürümleri, ki 25 Ağustos 2026 tarihli 1.19.0 oradandır; ile CNCF proje sayfası, ki 28 Ekim 2025 tarihli kuluçka statüsü oradandır. SpiceDB tutarlılık sayfası, ki belirteç, dört seviye ile CockroachDB uyarısı oradandır; veri deposu sayfası; ile GitHub sürümleri, ki 26 Ağustos 2026 tarihli 1.56.1 oradandır. Ory Keto deposu ile sürümleri, ki 20 Mart 2026 tarihli 26.2.0 oradandır. cedar-policy docs.rs sayfası, 4.12.0. cedar-spec deposu ile Dafny'den Lean'e taşımayı anlatan 0032 numaralı öneri. microsoft/regorus deposu, ki OPA 1.2.0 uyumu ile 4,6 milisaniyeye karşı 45,2 milisaniye oradandır. biscuit-auth deposu, ki denetim arandığı ifadesi oradandır. Oso dokümantasyonu.

Birincil güvenlik ile paket verisi kaynakları şunlardır. OSV.dev sorgu API'si, ki tüm güvenlik açığı tabloları, yani OpenFGA'nın 26, SpiceDB'nin 16 kaydı ile Keto, OPA ile biscuit-auth kayıtları oradandır. crates.io API'si, ki tüm sürüm, indirme ile lisans verileri 8 Eylül 2026'da çekilmiştir.

Bu oturumda erişilemeyenler ile doğrulanamayanlar şunlardır: SpiceDB gönderim ile önbellekleme dokümanları, 404 dönmüştür; authzen-interop.net katılımcı listesi, ağ hatası alınmıştır; OpenFGA PostgreSQL göç SQL'i, GitHub API hız sınırına takılmıştır; SpiceDB lisans dosyası; ile ACM sayısal kütüphanesindeki Cedar makalesi, 403 dönmüştür.

---

Üç uyarı tekrarlanmalıdır. Birincisi, 2,6 mikrosaniye rakamı bir HMAC doğrulamasıdır, bir ilişki tabanlı denetim değildir; bir hedef olarak alınmamalıdır. İkincisi, Zanzibar'ın 10 milisaniyelik 95. yüzdeliği yalnızca 10 saniye bayat veri kabul edildiğinde geçerlidir; tazelik istendiğinde 60 milisaniyedir. Üçüncüsü, OpenFGA'nın 16 yetkilendirme atlatma açığı hazır çözüm almanın riski ortadan kaldırmadığını göstermektedir; Cedar'ın sıfır açığı ise test disiplininin işe yaradığını göstermektedir.
