# §19 — Yüksek erişilebilirlik ve dağıtık mimari

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

**Kapsam.** Rust ile PostgreSQL kullanarak sıfırdan yazılan genel amaçlı bir IdP için yüksek erişilebilirlik ile dağıtım kararları.

> **Metodoloji notu.** Bu oturumda web arama bütçesi, yani 200 çağrı, erken tükenmiştir; araştırmanın büyük bölümü birincil kaynakların, yani resmî dokümanların, satıcı mühendislik bloglarının, GitHub tartışmalarının ile PostgreSQL sürüm notlarının doğrudan çekilip okunmasıyla yapılmıştır. Aşağıdaki her rakamın yanında kaynağı ile tarihi vardır. Doğrulanamayanlar açıkça işaretlenmiştir ve hiçbir rakam uydurulmamıştır.

---

## 0. Yönetici özeti, sekiz cümlelik cevap

1. **2026'da sektörün gittiği yön nettir: Infinispan ile Redis gibi ayrı dağıtık durum katmanlarını atıp uçucu durumu senkron replike edilmiş bir veritabanına koymak.** Keycloak bunu 17 Temmuz 2026'da stateless ile Multi-Cluster v2 olarak duyurmuş, Zitadel ise Şubat 2026'da saf olay kaynaklılıktan hibrit ilişkisel modele geçtiğini açıklamıştır.
2. Bunun ölçülmüş bedeli kimlik doğrulama etkileşimi başına yaklaşık 8 ile 10 milisaniye ek gecikme ile veritabanı işlemci ve giriş çıkış işlem sayısında yaklaşık iki kat artıştır; Keycloak, 17 Temmuz 2026. Bu, bir IdP için kabul edilebilir bir takastır.
3. **Çok bölgeli senkron yazma kimlik için çalışmamaktadır.** Keycloak 26.4 ölçümüne göre bölgeler arası gidiş dönüş süresi sıfır milisaniyeyken 99. yüzdelik 47 milisaniye, 10 milisaniyeyken 84 milisaniye, 20 milisaniyeyken 130 milisaniyedir; bir önceki sürümde 20 milisaniyelik gidiş dönüş 1.076 milisaniyelik bir 99. yüzdelik üretmekteydi. Keycloak'ın resmî sınırı şudur: bölgeler arası veritabanı gidiş dönüşü için beş milisaniyenin altı önerilir, on milisaniyenin altı zorunludur.
4. Kanidm'in iki düğümde tıkanmasının sebebi ölçek değil bilinçli bir CAP tercihidir: quorum yoktur, erişilebilirlik ile bölünme toleransı seçilmiştir ve nitelik seviyesinde son yazan kazanır kuralı vardır. Bu tasarım kilitlenme ile oturum yazımının bölünme sırasında da çalışmasını sağlar ancak çakışma çözümünü bir güvenlik açığına dönüştürür. Argus bu yolu seçmemelidir.
5. **İptal yayını için Redis yayın ve abonelik bir güvenlik hatasıdır.** Redis resmî dokümanı kelimesi kelimesine mesajın sonsuza kadar kaybolduğunu söylemektedir. Bir iptal sinyali kaybolursa iptal edilmiş bir token yaşamaya devam eder. Doğru desen işlemsel giden kutu ile yoklamadır; Keycloak tam olarak bunu yapmaktadır ve varsayılan yoklama aralığı 100 milisaniyedir.
6. **Okuma replikasından token iptali veya oturum doğrulaması okumak gerçek bir güvenlik riskidir**, teorik değildir. CockroachDB'nin takipçi okuması bile en az 4,2 saniye geçmişten okumaktadır. Argus'ta iptal kontrolü asla asenkron bir replikaya gitmemelidir.
7. **Argus için önerilen topoloji şudur:** tek bölge, üç erişilebilirlik alanı, senkron quorum kesinleştirmeli PostgreSQL, yani Patroni veya CloudNativePG; durumsuz Rust düğümleri; uçucu durum veritabanında; iptal yayını veritabanı giden kutusu ile 100 ile 250 milisaniyelik yoklama; düğüme yerel bir iptal dönemi önbelleği. Redis opsiyonel bir hızlandırıcı olmalıdır, bir doğruluk kaynağı değil.
8. Çok bölgelilik veri replikasyonuyla değil, Okta'nın yaptığı gibi bölge başına izole bir hücreyle çözülmelidir; bu aynı zamanda veri yerleşimi probleminin de tek gerçekçi cevabıdır.

---

## Bölüm 1 — Mevcut IdP'lerin yüksek erişilebilirlik mimarileri

### 1.1 Keycloak: sektörün en iyi belgelenmiş hikâyesi ile en dürüst itirafı

#### 1.1.1 Eski model: Infinispan bölgeler arası replikasyonu, Multi-Site v1

İki bağımsız Keycloak kümesi düşük gecikmeli bir ağla bağlı iki bölgede çalışmaktadır.

| Katman | Replikasyon | Not |
|---|---|---|
| Kullanıcı, realm, istemci ile çevrimdışı oturum | Senkron veritabanı replikasyonu | Aurora PostgreSQL ile test edilmiştir |
| Oturum verisi | Infinispan replikalı önbellekten harici veri ızgarasına, oradan karşı bölgeye senkron | Bölgeler arası yedek kanalıdır |
| Realm önbelleği geçersizleştirmesi | `work` önbelleği üzerinden geçersizleştirme mesajı | Düğüme yerel önbeleklerdir |

Keycloak asenkron replikasyonu bilinçli olarak reddetmiştir. Resmî gerekçesi şudur:

> "Lost changes leading to users being able to log in with an old password because database changes are not replicated to the other site."

Bu, bir IdP için asenkron çoklu bölgenin neden yanlış olduğunun en net tek cümlelik ifadesidir: asenkron replikasyon parola değişikliğinin kaybolması, yani eski parolayla giriş demektir.

Belgelenmiş sınırları şunlardır, erişim 8 Eylül 2026. Bu kurulum yalnızca iki bölgeyle test edilmiş ile desteklenmektedir, yani üç bölge desteklenmemektedir. Bölge arızasında yük dengeleyici `/lb-check` ile tespit etmekte ve trafiği yönlendirmektedir; kurtarma iki dakikanın altındadır ancak bu sırada bir kısım istek hata almaktadır. Başarılı bir devralma, önceki arızalardan bozulmamış bir kurulum gerektirmektedir, yani bir önceki arızadan sonra elle yeniden senkronizasyon yapılmamışsa devralma veri kaybettirmektedir. Infinispan'ın senkronizasyon dışı kalma durumu şu anda izlenmesi zordur ve tam bir elle yeniden senkronizasyon gerektirmektedir.

Bu son madde kritiktir: birinci sürüm mimarisi, operatör elle müdahale etmediği sürece sessizce bozulabilen bir sistemdir.

#### 1.1.2 Yeni model: Multi-Cluster v2 ile stateless, Keycloak 26.7, Temmuz 2026, önizleme

Kaynağı Alexander Schwartz'ın 17 Temmuz 2026 tarihli "Multi-Cluster v2 and Stateless Mode now in Preview" yazısıdır.

Bu, Argus için en önemli tek kaynaktır. Keycloak Infinispan'ı kimlik doğrulama yolundan tamamen çıkarmaktadır.

| Veri | Eskiden | Şimdi, stateless modda |
|---|---|---|
| Kimlik doğrulama oturumu, yani girişin ortasındaki kullanıcı | Infinispan dağıtık önbelleği | Veritabanı |
| Eylem token'ı, yani e-posta doğrulama, parola sıfırlama ile OAuth kodu | Infinispan | Veritabanı |
| Giriş başarısızlığı sayacı, yani kaba kuvvet koruması | Infinispan | Veritabanı |
| Realm ile yetkilendirme verisi | Düğüme yerel önbellek | Düğüme yerel önbellek, değişmemiştir |
| Küme içi önbellek geçersizleştirmesi | JGroups | JGroups, değişmemiştir |
| Kümeler arası önbellek geçersizleştirmesi | Infinispan bölgeler arası | Veritabanı giden kutusu tablosu ile yoklama, varsayılanı 100 milisaniyedir |

Ölçülmüş maliyeti blog yazısından doğrudan şöyledir: kimlik doğrulama etkileşimi başına yaklaşık 8 ile 10 milisaniye ek gecikme vardır ve etkileşimli giriş akışları için ihmal edilebilirdir; veritabanı işlemci yükü ile giriş çıkış işlem sayısı kabaca iki kat artabilir.

Ön koşulu doğrudan alıntıyla şudur: senkron replike edilmiş bir veritabanı ile bölgeler arasında düşük gecikmeli bir ağ gerekir; beş milisaniyenin altı önerilir, veritabanı gidiş dönüşü için on milisaniyenin altı zorunludur.

Tasarım felsefesi doğrudan alıntıyla şudur: yeni stateless özelliği tutarlılığı erişilebilirliğe tercih etmektedir; her yazma senkron replike edilmektedir, dolayısıyla devralma sırasında veri kaybolmamakta, bunun bedeli bölgeler arasında düşük gecikmeli bir ağ gerektirmesidir.

Kabul edilen sınırları şunlardır: yalnızca tek bölgedir, çünkü senkron replike edilen veritabanları genelde birden çok bölgede kullanılamamaktadır; yama yükseltmeleri sıfır kesintilidir ancak küçük ile büyük sürüm yükseltmeleri için bir bölge hariç hepsini kapatmak gerekmektedir.

Infinispan'ı neden attıkları kendi itiraflarıdır: kaybolan veya yeniden başlayan bir düğümde dağıtık önbellek yeniden dengelemesi olmakta; bir düğüm beklenmedik şekilde kaybolursa giriş akışlarında geçici hatalar çıkmakta; büyük kurulumlarda giriş başarısızlığı önbelleği kayda değer büyüyerek önemli bellek tüketmekte ile uzun yeniden dengeleme sürelerine yol açmakta; tam küme yeniden başlatması, yani küçük sürüm yükseltmesi, uçucu durumu sıfırlamakta; ve mimari Kubernetes ile AWS'e bağlı olup AWS Lambda ile Prometheus uyarıları gerektirmekteydi.

> **Argus için ders.** Keycloak on yıldan uzun süren dağıtık önbellek yatırımını 2026'da terk etmiştir. Sıfırdan yazan bir proje hiç o yola girmemelidir: uçucu durum PostgreSQL'de, kümeler arası sinyalleşme veritabanı giden kutusunda olmalıdır.

#### 1.1.3 Keycloak'ın farklı bölgelere yaymayın gerekçesi, rakamlarla

Kaynağı Ekim 2025 tarihli Keycloak 26.4 performans kıyaslamalarıdır.

Test koşulları Amazon Aurora PostgreSQL 17.5, 100.000 kullanıcı, üç farklı erişilebilirlik alanında üç Keycloak podu ile 20 ile 50 adet t4g.small yük üretecidir.

Ağ gecikmesinin 99. yüzdelik yanıt süresine etkisi, saniyede 500 giriş ile 2.500 token yenileme altında şöyledir.

| Bölgeler arası gidiş dönüş | KC 26.3, 99. yüzdelik | KC 26.4, 99. yüzdelik |
|---|---|---|
| 0 ms | 51 ms | 47 ms |
| 10 ms | 116 ms | 84 ms |
| 20 ms | 1.076 ms | 130 ms |

Bu tablo, önermiyoruz ifadesinin arkasındaki fiziği göstermektedir: 20 milisaniyelik gidiş dönüşte 26.3 çökmektedir, yani 21 kat bozulmaktadır. 26.4 çok daha dayanıklıdır ancak 20 milisaniyede hâlâ 2,8 kat bozulma vardır. Kıtalar arası gidiş dönüş 70 ile 150 milisaniye olduğuna göre sistem bu bölgede kullanılamaz hâle gelmektedir.

Sebebi amplifikasyondur: Keycloak dokümanı her istek veri güncellendiğinde bölgeler arasında birden çok tur yapabileceğini açıkça söylemekte ve istek başına birden çok veritabanı etkileşiminin bu etkiyi amplifiye ettiğini belirtmektedir. Yani 20 milisaniye gidiş dönüş ile beş ile yedi yazma 100 ile 140 milisaniyelik bir taban gecikme, üstüne de kuyruklama demektir.

#### 1.1.4 Keycloak kapasite rakamları, Argus'un kendi hedefini konumlandırmak için

| Metrik | Değer | Kaynak |
|---|---|---|
| Sanal işlemci başına | Saniyede 15 giriş | KC 26.4 kıyaslaması, Ekim 2025 |
| Sanal işlemci başına | Saniyede 120 yenileme token'ı isteği | Aynı |
| Üç pod, 24 sanal işlemci ile 4 GB, db.r8g.2xlarge | Saniyede 500 giriş ile 2.500 yenileme | Aynı |
| Üç pod, 40 sanal işlemci ile 8 GB, db.r8g.4xlarge | Saniyede 1.000 giriş ile 5.000 yenileme | Aynı |
| Üç pod, 74 sanal işlemci ile 8 GB, db.r8g.16xlarge | Saniyede 2.000 giriş ile 10.000 yenileme | Aynı |
| Önbellek 10 binden 200 bin girdiye çıkarılınca | Aurora zirve işlemcisi %77,77'den %63,77'ye inmekte, bellek 1,30'dan 1,45 GB'a çıkmaktadır | Aynı |

Rapor, Keycloak'ın test edilen aralıkta neredeyse doğrusal biçimde dikey ölçeklendiğini söylemektedir.

> **Argus için kıyas hedefi.** Java ile Infinispan kullanan Keycloak bir sanal işlemcide saniyede 15 giriş yapmaktadır. Argon2id maliyeti girişin baskın maliyeti olduğu için Rust'ın avantajı girişte değil yenileme, içgözlem ile JWKS yolunda ortaya çıkacaktır. Argus'un gerçekçi hedefi yenileme yolunda sanal işlemci başına saniyede 300 ile 600'dür; bu bir tahmindir ve ölçülmemiştir.

#### 1.1.5 Keycloak arıza modu özeti

| Senaryo | Davranış |
|---|---|
| Tek düğüm kaybı, birinci sürüm, Infinispan | Dağıtık önbellek veriyi en az iki düğümde tuttuğu için veri kaybı yoktur, ancak yeniden dengeleme ile giriş akışlarında geçici hatalar olur |
| Tek düğüm kaybı, ikinci sürüm, stateless | Hiçbir şey olmaz, çünkü kimlik doğrulama yolunda Infinispan trafiği yoktur |
| Tam küme yeniden başlatma, birinci sürüm | Devam eden girişler ile kaba kuvvet sayaçları sıfırlanır |
| Tam küme yeniden başlatma, ikinci sürüm | Korunur, çünkü veritabanındadır |
| Bölge kaybı, birinci sürüm | Yük dengeleyici yönlendirir ve iki dakikanın altında toparlanır; önceki arızadan sonra yeniden senkronizasyon yapılmamışsa veri kaybı olur |
| Bölge kaybı, ikinci sürüm | Senkron veritabanı sayesinde veri kaybı yoktur ve kullanıcılar giriş yapmış kalır |
| Bölgeler arası ağ kopması | Birinci sürümde Infinispan senkronizasyon dışı kalır, tespiti zordur ve tam elle yeniden senkronizasyon gerekir. İkinci sürümde senkron veritabanı kendi quorum'una göre davranır ve tutarlılık erişilebilirliğe tercih edilir |
| Bölünmüş beyin | Birinci sürümde Infinispan seviyesinde mümkündür ile izlenmesi zordur. İkinci sürümde risk veritabanı katmanına devredilir ve Patroni ile dağıtık yapılandırma deposu quorum'u çözer |

### 1.2 Zitadel: olay kaynaklılığın yüksek erişilebilirlikteki bedeli ve geri adım

**Mimarisi** olay kaynaklılık ile komut sorgu sorumluluk ayrımıdır. Yazma tarafı değişmez bir olay deposuna yazmakta, okuma tarafı bir projeksiyonu, yani denormalize bir görünümü okumaktadır.

**Tutarlılık modeli.** Resmî doküman şöyle der: olay kaynaklılık ile komut sorgu sorumluluk ayrımının birleşimi Zitadel'i nihai tutarlı yapmaktadır. Sorgu görünümleri asenkron güncellenmektedir; ancak kimlikle yapılan tekil kaynak aramaları olay deposuna karşı doğrulanarak güçlü tutarlılık alabilmektedir.

**Projeksiyon gecikmesi yüksek erişilebilirlikte ne yapmaktadır.** Kritik nokta şudur: Zitadel bakımcısının 2024 tarihli açıklaması, 7636 numaralı GitHub tartışması:

> "At the moment we do not (yet) support the usage of read replicas because we want to keep most data consistent."

Yani olay kaynaklı bir IdP bile, projeksiyon gecikmesi bir güvenlik anlamı taşıdığı için okuma replikası kullanmayı reddetmektedir. Bu, 2.4'teki iptal edilmiş bir token replikada geçerli görünür mü sorusunun sektörden gelen dolaylı cevabıdır: evet, o yüzden kimse yapmamaktadır.

**Çok bölge duruşu**, aynı tartışmadan: PostgreSQL ile çok erişilebilirlik alanlı tek bölge kümesi ile felaket kurtarma amaçlı bölgeler arası replikasyon kullanılmaktadır, aktif aktif yoktur. CockroachDB veya Spanner ile bölgeler arası aktif aktif dağıtımlar çalışmaktadır, ancak bölgeler birbirinden uzaksa gecikme tarafında biraz feda edilmektedir.

**2026 gelişmesi: Zitadel olay kaynaklılıktan kısmen geri çekilmektedir.** Kaynağı kurucu ile genel müdür Florian Forster'ın 12 Şubat 2026 tarihli "Scaling Cloud-Native Identity: Optimizing Performance with Caching" yazısıdır:

> "We are currently working on a major evolution of our core engine—shifting to a hybrid relational model that combines the speed of traditional tables with the auditability of events. This change will drastically reduce the need for complex read models."

Önbellek bağlayıcıları için ölçülmüş bir rakam da vardır: PostgreSQL önbellek bağlayıcısıyla yalnızca bu varsayılan kurulumu kullanarak saniyede 30.000'in üzerinde istek yapan müşteriler görülmektedir.

Ayrıca bellek içi önbellek hakkında bir uyarı vardır: çok konteynerli bir ortamda yapışkan oturum olmadan kullanılamaz, çünkü kullanıcılar veri tutarsızlığı yaşayabilir, örneğin bir istekte çıkış yapmış diğerinde giriş yapmış olabilirler.

| Zitadel arıza modu | Davranış |
|---|---|
| Düğüm kaybı | Uygulama katmanı durumsuzdur ve veritabanına devredilmiştir |
| Projeksiyon gecikmesi | Okuma tarafı bayat olabilir; kritik okumalar olay deposuna düşer |
| Redis önbelleği kaybı | Önbellek ıskalanır ve veritabanına düşülür; bu bir bozulmadır, kesinti değildir |
| Bölünmüş beyin | Uygulama katmanında yoktur ve veritabanı katmanına devredilmiştir |
| Bölge kaybı, Postgres ile | Felaket kurtarma devralması yapılır ve asenkron bölgeler arası replikasyon nedeniyle veri kaybı riski vardır |

> **Argus için ders.** Olay kaynaklılık yüksek erişilebilirliği çözer diye seçilmemelidir. Zitadel bunu sekiz yıl uyguladıktan sonra hibrit ilişkisel modele dönmektedir. Argus doğrudan ilişkisel bir modelle ve ayrı bir yalnızca ekleme yapılan denetim tablosuyla başlamalıdır.

### 1.3 Kanidm: neden iki düğümde tıkanmıştır

Kaynakları replikasyon tasarım notları dokümanı, erişim 8 Eylül 2026, ile 4099 numaralı GitHub tartışmasıdır.

Bu bir tıkanma değil bilinçli bir CAP tercihidir ve tercih Argus için yanlıştır.

Kanidm erişilebilirlik ile bölünme toleransını seçen, tutarlılığı feda eden bir sistemdir. Gerekçesi doğrudan tasarım dokümanındadır: quorum gerektirmek bölünme sırasında yazamamak demektir ve bu kimlik yönetimi için kabul edilemezdir, çünkü oturum oluşturma ile güvenlik kilitlemesi bölünme sırasında da çalışmalıdır.

Nasıl çalıştığı şöyledir. Seçim yoktur ve quorum yoktur; tüm düğümler yazma kabul etmektedir. Her değişiklik bir değişiklik kimliği almaktadır: zaman damgası ile sunucu evrensel benzersiz kimliği. Zaman damgaları her zaman ileri gitmekte, asla geri gitmemektedir ve gerektiğinde ileri sürüklenmektedir. Nitelik seviyesinde son yazan kazanmaktadır: her nitelik kendi son değişim kimliğini tutar ve çakışmada yüksek kimlik kazanır. Replika güncelleme vektörü her başlatıcı sunucu için asgari ile azami değişiklik aralığını tutar; tüketici vektörünü sağlayıcıya gönderir ve sağlayıcı farkı hesaplar; bu, vekil replikasyona izin verir ve tam örgü gerektirmez. Topoloji rolleri okuma yazma, yazma kabul etmeyip yalnızca ileten taşıma merkezi ile yalnızca okumadır. Silme bir mezar taşıdır ve replikasyon penceresinden sonra toplanır.

Sınırları ile arıza modları, dokümanın kendi belirtilen sınırlamalar bölümünden:

| Sorun | Sonuç |
|---|---|
| Zombi kayıt | Bir düğüm çok geri kalırsa mezar taşı ona ulaşmadan toplanır ve silinmiş bir kayıt dirilir. Kanidm bunu geri kalan düğümü dondurarak, yani gelen ile giden replikasyonu durdurarak önlemektedir |
| Benzersizlik çakışması | En olası çakışma kaynağıdır. Düğümler uzun süre ayrı kalırsa aynı e-posta ya da kullanıcı adı iki düğümde yaratılabilir ve kayıt çakışma durumuna düşer |
| Şema başkalaşımı | Birleştirme sırasında bir kayıt sınıf değiştirip şemayı ihlal edebilir, örneğin gruptan kişiye dönebilir |
| Mezar taşı penceresi takası | Uzun bir pencere zombiyi önler ancak çakışma riskini artırır |
| Tutarlılık garantisi yokluğu | İstemciler bayat veri okuyabilir; yalnızca nihai tutarlılık vardır |

Düğüm sayısı açısından iki düğüm resmî olarak desteklenmektedir. Üç düğüm teknik olarak desteklenmemektedir ancak çalışmaktadır; sebebi mimari değil test eksikliğidir, 4099 numaralı tartışma.

> **Argus için en önemli olumsuz dersimiz budur.** Son yazan kazanır çakışma çözümü kimlikte bir güvenlik açığıdır, yalnızca bir veri tutarsızlığı değildir. Somut senaryo şudur: bölünme sırasında A düğümünde kullanıcı parolasını değiştirir, değişiklik kimliği 100; B düğümünde saldırgan eski oturumundan bir kimlik bilgisi ekler, değişiklik kimliği 101. Birleştirmede saldırganın değişikliği kazanır. Aynı şekilde bir düğümde hesap kilitlenir, diğerinde daha yüksek kimlikli bir kilit açma olur ve kilit kaybolur. Kanidm bunu nitelik seviyesinde çözünürlük ile dondurmayla hafifletmektedir ancak kaldıramamaktadır. Argus quorum'lu, yani tutarlılık ile bölünme toleransını seçen bir sistem olmalıdır; bölünme sırasında yazamamak kimlikte doğru davranıştır.

### 1.4 Rauthy ile Hiqlite: Raft tabanlı gömülü yaklaşım

Kaynakları Rauthy'nin yüksek erişilebilirlik dokümanı, `hiqlite` crate'i ile `openraft` deposudur, erişim 8 Eylül 2026.

Ne yaptıkları şudur: Hiqlite, `rusqlite` üzerine bir asenkron sarmalayıcı ile `openraft` tabanlı Raft konsensüsüdür. Rauthy'nin tüm örnekleri tek bir yüksek erişilebilirlikli önbellek katmanı paylaşmaktadır.

Neden Raft sorusunun cevabı şudur: Rauthy'nin bazı verileri yalnızca önbellekte yaşamaktadır, özellikle authorization code'lar. Bir authorization code'un tek bir düğümde kalması, yük dengelenmiş bir ortamda token takasının başarısız olması demektir. Redis'e bağımlı olmadan bunu çözmenin yolu gömülü konsensüstür.

`openraft`'ın standart Raft'a göre farkı kendi README dosyasındadır: genelleştirilmiş üyelik değişimi, yani tek bir işlemde keyfi bir düğüm kümesi değişimi, ile azaltılmış seçim çatışması oranı, yani bölünmüş oyun yeni bir döneme zorlamaması.

Ölçülmüş rakamlar şunlardır. Hiqlite yazarının ilk kıyaslaması ucuz bir tüketici M2 SSD'de saniyede yaklaşık 24.500 tekil ekleme göstermektedir; üç ayrı süreç, yerel makinede ancak gerçek ağ kullanımıyla. Eski SATA SSD'li bir makinede saniyede yaklaşık 16.500 eklemedir. Rauthy dokümanı üç replika önermekte, daha yüksek dayanıklılık için beş demektedir; bir noktada yazma iş hacminin bozulacağını belirtmektedir, yani sonsuz ölçeklenmemektedir. Zarif kapanma en az 15 saniye, lider seçimi ile küme durumu değişimi sırasında 25 ile 30 saniye sürmektedir. Postgres kullanılsa bile kalıcı bir birim sağlanması gerekmektedir, çünkü Raft durumu diskte yaşamalıdır.

| Senaryo | Davranış |
|---|---|
| Üç düğümden birinin kaybı | Quorum korunur, yani üçte iki; yazma devam eder ve lider seçimi gerekiyorsa kısa bir kesinti olur |
| Üç düğümden ikisinin kaybı | Quorum kaybolur ve yazma durur; bu Raft'ın doğasıdır ve tutarlılık ile bölünme toleransını seçen bir sistemdir |
| Bölünmüş beyin | Yapısal olarak imkânsızdır; Raft'ın temel garantisidir |
| Düğüm ekleme | Yazma iş hacmi düşer, çünkü her yazma daha çok düğüme replike edilir |

> **Argus için ders.** Rauthy'nin çözümü doğrudur ancak Argus'un ölçeğine yanlıştır. Raft yazma iş hacmi düğüm sayısıyla ters orantılıdır ve beş düğümün üstü mantıksızdır. Argus zaten PostgreSQL'e sahipse ikinci bir konsensüs sistemi taşımanın anlamı yoktur; Postgres'in kendi replikasyonu, yani Patroni ile etcd, aynı garantiyi zaten vermektedir. Rauthy'nin Raft'a ihtiyacı Postgres opsiyoneldir ve SQLite ile de çalışsın hedefinden doğmaktadır; Argus'un böyle bir kısıtı yoktur.

### 1.5 Ory Hydra ile Kratos: yüksek erişilebilirliği tamamen veritabanına devretme

**Tasarımı.** Hydra ile Kratos durumsuz süreçlerdir. Onay ile giriş durumu, oturum ile yenileme token'ı hepsi SQL veritabanındadır. Uygulama katmanında hiçbir küme koordinasyonu, dedikodu protokolü ya da önbellek geçersizleştirmesi yoktur. Yüksek erişilebilirlik veritabanını yüksek erişilebilir yapmak, N kopya çalıştırmak ile bir yük dengeleyici koymaktan ibarettir.

**Bu tasarımın gerçek dünyada çarptığı duvar en değerli olumsuz veri noktamızdır.** ory/kratos deposundaki 3134 numaralı tartışmada küresel CockroachDB ile ciddi performans sorunları anlatılmaktadır: `SELECT session_devices.* FROM session_devices WHERE session_id = $1` sorgusu, yani düz bir birincil anahtar araması, ortalama 230 milisaniye sürmektedir; giriş yapmış kullanıcılar için toplam yaklaşık bir saniye ek gecikme oluşmaktadır. CockroachDB desteğinin teşhisi tabloların küresel olarak yapılandırılmamış olması ve sorguların bölgeler arasında dolaşmasıdır.

Ory bakımcısı aeneasr üç şey söylemektedir ve üçü de Argus için doğrudan geçerlidir. Birincisi fiziktir: her yazılım sistemi fizik nedeniyle bu soruna sahip olacaktır; SQL sorgularınız derin deniz kablolarında 400 milisaniye yol alıyorsa her SQL sorgusu yavaş olacaktır. İkincisi açık kaynağın yönetilen ağdan farkıdır: açık kaynak Kratos, yalnızca Ory'nin yönetilen ağında bulunan tescilli küresel optimizasyon kodundan yoksundur ve küresel TCP yönlendirmesi gibi şeyler gerekmektedir. Üçüncüsü hukukun teknikle çelişmesidir: küresel tablolar, kişisel veri saklandığında bölgesel veri gizliliği yasalarını, yani GDPR ile CCPA'yı, ihlal etmektedir.

Üçüncü madde çok önemlidir: CockroachDB'nin çok bölgeli düşük gecikme çözümü, yani küresel tablolar, kişisel veri için yasal olarak kullanılamamaktadır. Yani CockroachDB kullan ve çok bölgelilik çözülür cümlesi kimlik iş yükü için yanlıştır.

**Ory Network'ün gerçek mimarisi** kendi blog yazısındadır: Kubernetes, ArgoCD, Crossplane, Grafana ile CockroachDB kullanılmaktadır. Tam replikasyon değil coğrafi parçalama, yani veri yurtlandırma vardır: kişisel veri kullanıcının kendi ülkesinde kalmakta ancak bölgeler arasında birleşik bir kullanıcı kimliği korunmaktadır. Ölçek iddiası günde yaklaşık üç milyar API isteği ile 11.000'den fazla üretim ortamıdır. Reddedilen alternatifler homomorfik şifreleme, ki bir milyon kat daha hızlanma gerekmektedir, ile kolon seviyesinde şifrelemedir, ki yabancı anahtar, benzersizlik kısıtı ile aralık sorgularıyla uyumlu açık kaynak bir çözüm yoktur.

Bir satıcı iddiası bağımsız olarak doğrulanmamıştır: Ory ile Cockroach Labs'ın ortak blogu, ChatGPT'nin haftada 800 milyondan fazla aktif kullanıcısı için girişi bu kombinasyonun çalıştırdığını söylemektedir. Bu pazarlama içerikli ortak bir yazıdır ve teknik detay, yani bölge sayısı, 99. yüzdelik ile tablo yerleşimi, verilmemektedir.

### 1.6 authentik ve 2026'da Redis'ten çıkışı

Kaynağı docs.goauthentik.io'nun mimari sayfasıdır, sürüm 2026.8, erişim 8 Eylül 2026.

Bileşenleri sunucu, yani çekirdek ile gömülü dış nokta, işçi, yani arka plan görevleri, ile PostgreSQL'dir.

Dikkat çekici olan şudur: 2026.8 mimari dokümanında Redis artık zorunlu bir bileşen olarak listelenmemektedir. 2025.8 sürüm notlarında sebebi yazmaktadır:

> "The authentik worker and background tasks have been reworked... This rework also allowed us to not depend on Redis for background tasks."

Celery'den Postgres tabanlı bir görev kuyruğuna geçmişlerdir. Geçiş sorunsuz bir göç yolu içermemektedir; yüksek trafikli kurulumlarda yükseltme sırasında görev kaybı olabilmektedir ve sürüm notlarında açık bir uyarı vardır. Helm paketinde Redis hâlâ vardır, 8.0'dan 8.2'ye güncellenmiştir, ve önbellek ile oturum içindir.

Yüksek erişilebilirlik modeli şudur: sunucu ile işçi yatay ölçeklenmektedir, yani durumsuzdur, ve durum PostgreSQL'dedir. Bu, Keycloak'ın ikinci sürümü ile Ory'nin desenine aynıdır.

> **Argus için ders.** Üç bağımsız proje, yani Keycloak, authentik ile Zitadel, 2025 ile 2026'da aynı yöne gitmiştir: ayrı durum sistemini sil ve PostgreSQL'e taşı. Bu bir moda değil operasyonel gerçeğin dayattığı bir yakınsamadır.

### 1.7 Karşılaştırma tablosu: IdP yüksek erişilebilirlik modelleri

| Ürün | Tutarlılık modeli | Dağıtık durum nerededir | Azami düğüm ile bölge | Bölünmüş beyin | Düğüm kaybında | Operasyonel maliyet |
|---|---|---|---|---|---|---|
| Keycloak birinci sürüm, 26.6 ve altı | Senkron veritabanı ile senkron Infinispan | Harici Infinispan | İki bölge, test ile destek kapsamında | Infinispan seviyesinde mümkündür ile izlemesi zordur | Yeniden dengeleme ile geçici giriş hataları | Çok yüksektir: Infinispan kümesi, izleme, Lambda ile geri dönüş prosedürü gerekir |
| Keycloak ikinci sürüm stateless, 26.7 ve üstü, önizleme | Senkron veritabanı; tutarlılık erişilebilirliğe tercih edilir | PostgreSQL | İki ve üzeri küme, tek bölge | Veritabanına devredilmiştir | Etkisizdir | Düşüktür; yalnızca yüksek erişilebilirlikli veritabanı gerekir |
| Zitadel | Nihai tutarlılık; kimlik aramasında güçlü tutarlılık | PostgreSQL veya CockroachDB, opsiyonel Redis önbelleğiyle | Sınırsızdır, durumsuzdur | Yoktur | Etkisizdir | Ortadır; olay deposu ile projeksiyon işletimi gerekir |
| Kanidm | Nihai tutarlılık, erişilebilirlik ile bölünme toleransı, son yazan kazanır | Kendi replikasyonu, replika güncelleme vektörüyle | İki resmî, üç test dışı | Vardır; çakışma normal işleyiştir | Diğer düğüm yazma alır | Düşüktür ancak çakışma riski bir güvenlik riskidir |
| Rauthy | Doğrusallaştırılabilir, Raft ile | Hiqlite, yani SQLite ile openraft | Üç ile beş | İmkânsızdır | Üçte birlik kayıp sorunsuzdur, üçte iki kayıpta yazma durur | Düşüktür, gömülüdür |
| Ory Hydra ile Kratos | Veritabanına devredilmiştir | SQL veritabanı | Sınırsızdır, durumsuzdur | Yoktur | Etkisizdir | Uygulamada düşüktür, veritabanına kayar |
| authentik | Veritabanına devredilmiştir | PostgreSQL, opsiyonel Redis önbelleğiyle | Sınırsızdır | Yoktur | Etkisizdir | Düşüktür |

---

## Bölüm 2 — PostgreSQL ile yüksek erişilebilirlik

### 2.1 Devralma araçları, 2026 durumu

| Araç | Konum | Güçlü yanı | Zayıf yanı | 2026 tavsiyesi |
|---|---|---|---|---|
| Patroni 4.1.x | Sanal makine ile Kubernetes | Endüstri standardıdır; etcd, Consul, ZooKeeper ile Kubernetes'i dağıtık yapılandırma deposu olarak kullanır; REST API'si vardır; `pg_rewind` ile eski birincili geri alarak kendini onarır; dağıtık yapılandırma deposu için güvenli mod sunar | Ayrı bir dağıtık yapılandırma deposu kümesi taşıma yükü vardır ile iki düğümde quorum sorunları çıkar | Sanal makine ile çıplak donanım için varsayılandır |
| CloudNativePG 1.28 ile 1.29, 1.30 geliştirmede | Yalnızca Kubernetes | Patroni gerektirmez; doğrudan Kubernetes API sunucusunu dağıtık yapılandırma deposu olarak kullanır ve ayrı etcd istemez; bildirimsel özel kaynak tanımları vardır; StatefulSet kullanmaz ve kendi kalıcı birim yönetimini yapar | Kubernetes dışında yoktur | Sıfırdan Kubernetes kurulumları için varsayılandır |
| pg_auto_failover | Sanal makine | Patroni'den basit, repmgr'dan otomatiktir; iki düğümde quorum derdi yoktur | İzleyici tek bir hata noktasıdır; birincil düşerken izleyici de düşükse devralma olmaz | Küçük kurulumlar içindir |
| repmgr | Sanal makine | Basittir ve dağıtık yapılandırma deposu gerektirmez | Düğümler doğrudan haberleşir ve bölünmüş beyin riski daha yüksektir | Yeni kurulumda önerilmez |
| Stolon | — | — | Proje etkinliği durmuştur | Arşiv durumu doğrulanamamıştır |

Patroni'nin kritik davranışı resmî sıkça sorulan sorularındadır, erişim 8 Eylül 2026. Otomatik devralma bir lider yarışıdır: lider kilidi yaşam süresi içinde yenilenmezse dağıtık yapılandırma deposundan düşer, tüm düğümler aday olur ve kilidi ilk alan yükselir. Dağıtık yapılandırma deposu kaybedilirse ona dayanan tüm Patroni kümeleri salt okunur moda geçer, meğerki güvenli mod etkinleştirilmiş olsun. Dağıtık yapılandırma deposunda çoğunluk kaybedilirse depo yanıt vermez hâle gelir ve bu, Patroni'nin mevcut okuma yazma yapan Postgres düğümünü düşürmesine sebep olur.

> **Argus için doğrudan sonuç.** etcd kümesi çökerse PostgreSQL salt okunur olur. Yani Argus'un giriş akışı durur ancak token doğrulama devam edebilir. Bu, yedinci bölümdeki kademeli bozulma tasarımının temel taşıdır ve güvenli mod mutlaka açılmalıdır.

Patroni devralma süresinin gerçek formülü şöyledir. Kısıt `ttl >= loop_wait + 2 * retry_timeout` şeklindedir. Asgari değerler yaşam süresi 20, döngü bekleme iki ile yeniden deneme zaman aşımı üçtür. Birincil arızasında en kötü durum döngü bekleme artı birincil başlatma zaman aşımı artı döngü beklemedir; birincil başlatma zaman aşımı sıfırsa yalnızca döngü beklemedir. `patronictl list` çıktısı döngü bekleme saniyesi kadar gecikmeli olabilir. Bir saha raporuna göre, ki ikincil bir kaynaktır, yaşam süresi 20, döngü bekleme beş, yeniden deneme zaman aşımı beş ile gözcü güvenlik payı üç ayarlarıyla sağlıklı bir altyapıda 25 saniyenin altında devralma görülmektedir; stackharbor.com bilgi bankası, 2026.

CloudNativePG'nin birincil arıza akışı, doküman 1.28, arıza modları bölümü: operatör en düşük replikasyon gecikmesine sahip beklemedeki düğümü yükseltir; okuma yazma servisi yeni birincile yönlenir; arızalı pod okuma ile okuma yazma servislerinden çıkarılır; beklemedeki düğümler yeni birincilden replike etmeye başlar; eski birincilin kalıcı birimi varsa `pg_rewind` ile geri katılır, yoksa yedekten yeni bir bekleme düğümü yaratılır.

CloudNativePG bir CNCF projesidir; olgunluk seviyesi, yani kum havuzu mu kuluçka mı olduğu, bu araştırmada doğrulanamamıştır.

### 2.2 Senkron mu asenkron mu, bir IdP için cevap

**2.2.1 `synchronous_commit` seviyeleri.**

| Değer | Kesinleştirme ne zaman döner | Veri kaybı riski | IdP'de kullanımı |
|---|---|---|---|
| `off` | Yazma ileri günlüğü diske bile yazılmadan | Çökmede son işlemler kaybolur | Asla kullanılmaz |
| `local` | Yerel yazma ileri günlüğü eşitlendikten sonra | Düğüm kaybında kayıp olur | Yalnızca tek düğümlü geliştirme ortamı |
| `remote_write` | Bekleme düğümü günlüğü işletim sistemine yazdıktan sonra | Bekleme düğümünün işletim sistemi çökerse kayıp olur | Kabul edilebilir bir orta yoldur |
| `on`, varsayılan senkron | Bekleme düğümü günlüğü eşitledikten sonra | Bekleme düğümü ayaktayken kayıp yoktur | Argus'un varsayılanıdır |
| `remote_apply` | Bekleme düğümü günlüğü uyguladıktan sonra, yani replikada görünür olduğunda | Kayıp yoktur ve replikada anında okunabilir | Yalnızca kritik yollarda kullanılır |

**2.2.2 Ölçülmüş maliyet.** Kaynağı EDB'nin PostgreSQL senkron replikasyonunun maliyet etkileri yazısıdır. Test üç adet AWS `r5.2xlarge`, yani sekiz sanal işlemci ile 64 GB, tek erişilebilirlik alanında, yaklaşık 150 GB veriyle, yani pgbench ölçeği 10.000, her sunucuda ikişer io2 EBS diskiyle, yani 10.000 giriş çıkış işlemiyle, biri veri biri günlük için; gecikme Linux trafik kontrolüyle yapay eklenmiş ve `synchronous_standby_names = '2 ("pg-node-2","pg-node-3")'` kullanılmıştır.

| Koşul | İstemci | `local` yazma gecikmesi | `remote_write` | Fark |
|---|---|---|---|---|
| 10 milisaniye ağ gecikmesi | 40 | 9,5 ms | 16 ms | %67 artış |
| 10 milisaniye ağ gecikmesi | 80 | 17 ms | 20 ms | %19 artış |
| 3 milisaniye ağ gecikmesi | 40 | — | Saniyedeki işlem `local`'ın %92'sidir | — |
| 3 milisaniye ağ gecikmesi | 80 | — | Saniyedeki işlem `local` ile eşittir | — |
| 3 milisaniye, 120 ve üzeri istemci | — | — | `local` ile %1 içindedir | — |
| 3 milisaniyede sorgu gecikmesi | Hepsi | Tüm modlar bir milisaniye içinde birbirine yakındır | | |

Ayrıca bir Percona ölçümüne göre `synchronous_commit=off` ayarı `remote_apply`'a göre iki kattan fazla performans göstermektedir.

Kritik yorum şudur: senkron replikasyonun maliyeti yükle birlikte düşmektedir, çünkü artan eşzamanlılık yazma ileri günlüğü boşaltmalarını gruplamaktadır. Yani senkron replikasyon pahalıdır iddiası düşük eşzamanlılıkta doğru, bir IdP'nin gerçek yük profilinde büyük ölçüde yanlıştır.

Erişilebilirlik alanları arasındaki gerçek gecikme aynı bölgede tipik olarak bir ile iki milisaniye mertebesindedir; kesin rakam doğrulanamamıştır, çünkü cloudping.co ile AWS resmî hizmet düzeyi anlaşması bu oturumda çekilememiştir. Ancak Keycloak'ın bölgeler arası beş milisaniyenin altı önerilir ile on milisaniyenin altı zorunludur eşiği, 17 Temmuz 2026, tam olarak çok erişilebilirlik alanlı tek bölge senaryosunu tariflemekte ve EDB'nin üç milisaniyelik testinin neredeyse bedava sonucuyla uyuşmaktadır.

**2.2.3 Argus için karar.** Bir IdP veri kaybı tolere edemez. Somut nedenleri şunlardır.

| İşlem | Kayıp olursa ne olur |
|---|---|
| Parola değişimi | Kullanıcı eski parolayla giriş yapabilir; Keycloak'ın kendi gerekçesidir |
| Token ile oturum iptali | İptal edilmiş oturum yaşamaya devam eder |
| Çok adımlı doğrulama kaydının silinmesi | Saldırganın eklediği kimlik doğrulayıcı geri gelir |
| Yenileme token'ı rotasyonu | Yeniden kullanım tespiti kırılır ve çalınmış token tekrar kullanılabilir |
| Kaba kuvvet sayacı | Kilitleme sıfırlanır |
| Hesap kilitleme ile devre dışı bırakma | İşten çıkarılan çalışanın erişimi geri gelir |

Kararı şudur. Varsayılan `synchronous_commit = on` ile quorum kesinleştirmedir: `synchronous_standby_names = 'ANY 1 (standby_a, standby_b)'`. Bu, üç erişilebilirlik alanında bir bekleme düğümünün kaybını tolere ederken veri kaybını sıfırlar. Neden `ANY 1` ile `FIRST 1` değil sorusunun cevabı şudur: `ANY N` en hızlı N bekleme düğümünü beklemektedir ve belirli bir düğüm yavaşlarsa sistem takılmaz.

Kritik nokta bir kendini vurma tuzağıdır: tek bekleme düğümüyle `synchronous_commit=on` yapılırsa ve o düğüm düşerse birincil tüm yazmalarda asılır. Bu yüzden en az iki bekleme düğümü ile `ANY 1` zorunludur; aksi hâlde yüksek erişilebilirlik çözümü tek başına bir kesinti kaynağı olur.

Denetim günlüğü ile telemetri yazmaları ayrı bir bağlantıda `synchronous_commit = local` ile yazılabilir, yani oturum seviyesinde ayarlanabilir; bir denetim satırının kaybı güvenlik kararını değiştirmez, yalnızca iz kaybettirir. Bu, giriş çıkış işlemlerinin %30 ile %50'sini senkron yoldan çıkarır. Bu bir tasarım önerisidir ve ölçülmemiştir.

### 2.3 Devralma sırasında Argus ne yapar

Gerçekçi zaman çizelgesi, Patroni ile yaşam süresi 20, döngü bekleme beş ile yeniden deneme zaman aşımı beş ayarlarında:

| Zaman | Olay | Argus'un görevi |
|---|---|---|
| 0 saniye | Birincil düşer | Aktif sorgular TCP hatası ya da zaman aşımı alır |
| 0 ile 20 saniye | Lider kilidi yaşam süresi dolar | Yazma imkânsızdır; giriş, token takası ile yenileme başarısız olur |
| Yaklaşık 20 ile 25 saniye | Lider yarışı olur ile yeni birincil yükselir | — |
| Yaklaşık 25 saniye | Sanal IP, DNS ya da havuzlayıcı yeni birincile yönelir | Bağlantı havuzu yeniden kurulur |
| 25 saniye sonrası | Normale döner | — |

Argus bu 25 saniyede ne yapmalıdır; bu bir tasarım kararıdır, varsayılan davranış değildir.

1. JWT doğrulaması devam etmelidir. İmza doğrulama veritabanı gerektirmez, JWKS bellektedir ile iptal dönemi düğüme yerel önbellektedir. Kaynak sunucular etkilenmez ve bu, Argus'un en değerli kademeli bozulma özelliğidir.
2. `/token` yenileme akışı durur, çünkü rotasyon bir yazma gerektirir. İstemcilere 503 ile `Retry-After: 5` dönülmeli, `400 invalid_grant` asla dönülmemelidir; çünkü `invalid_grant` istemci SDK'larının çoğunda kullanıcıyı çıkış yaptırmaktadır. Bu ayrım, 25 saniyelik bir veritabanı devralmasının milyonlarca kullanıcıyı çıkış yaptırmasıyla hiç fark edilmemesi arasındaki farktır.
3. Giriş akışı durur ve kullanıcıya geçici bir sorun olduğu ile tekrar denemesi söylenir; bu bir kimlik hatası değildir.
4. Bağlantı havuzu davranışı önemlidir: `sqlx` ya da `deadpool` havuzundaki tüm bağlantılar ölüdür. Sağlık kontrolüyle hızlı tahliye ile üstel geri çekilmeyle yeniden kurma şarttır; yoksa 25 saniyelik bir kesinti, havuz doygunluğu yüzünden iki ile üç dakikaya uzar.

Bağlantı dizesi tarafında `libpq`, yani PostgreSQL 18 dokümanı, erişim 8 Eylül 2026, çok host ile `target_session_attrs=read-write` desteklemektedir; istemci ilk kabul edilebilir sunucuyu seçmektedir. Ancak bu, devralmayı bir sonraki bağlantı kurulumunda çözmekte, mevcut bağlantıları çözmemektedir. `load_balance_hosts=random` ile bekleme düğümlerine okuma dağıtımı yapılabilir. Not olarak `sqlx`'in bu semantiği tam desteklediği doğrulanmamıştır; Argus kendi devralma farkındalıklı havuz mantığını yazmalı veya havuzlayıcıya devretmelidir.

### 2.4 Okuma replikası: hangi sorgu nereye gider

**2.4.1 Kritik soru: iptal edilmiş bir token replikada hâlâ geçerli görünür mü.**

Cevap evettir ve bu teorik değil ölçülebilir bir açıktır.

Kanıt zinciri şöyledir. Birincisi PostgreSQL akış replikasyonu varsayılan olarak asenkrondur; replikasyon gecikmesi normal işletimde milisaniye mertebesindedir ancak kontrol noktası, uzun sorgu, vakumlama, disk baskısı ya da ağ sıkışması altında saniyelere ile dakikalara çıkmaktadır, ve tam da bu anlarda, yani yük altında, saldırı olma olasılığı yüksektir. İkincisi sektörün davranışı bu riski doğrulamaktadır: Zitadel bakımcısı okuma replikası desteğini verilerin çoğu tutarlı kalsın diye reddetmektedir, 7636 numaralı tartışma. Üçüncüsü dağıtık veritabanlarında bile durum aynıdır: CockroachDB'nin `follower_read_timestamp()` fonksiyonu en az 4,2 saniye geçmişten okumaktadır, erişim 8 Eylül 2026. Yani en yakın replikadan hızlı okuma 4,2 saniyelik bir iptal penceresi demektir.

Somut saldırı senaryosu şudur: kullanıcı tüm cihazlarından çıkmak ister veya güvenlik operasyon merkezi bir hesabı devre dışı bırakır. Birincilde iptal dönemi artırılır. Bu sırada Argus'un yedinci düğümü bir içgözlem isteğini bir okuma replikasına yönlendirir. Replikasyon üç saniye geridedir. Saldırgan bu üç saniyede yenileme token'ını kullanır ve yeni, tam ömürlü bir access token alır. Erişim iptalden saatler sonrasına kadar uzar.

Argus için kural pazarlık edilemez.

| Sorgu tipi | Replikaya gidebilir mi | Gerekçe |
|---|---|---|
| Token iptali ile iptal dönemi kontrolü | Hayır | Yukarıdaki senaryo |
| Oturum doğrulaması, yani aktif mi | Hayır | Aynı |
| Yenileme token'ı rotasyonu ile yeniden kullanım tespiti | Hayır, zaten bir yazmadır | Bayat okuma yeniden kullanım tespitini kırar |
| Parola ile kimlik bilgisi doğrulaması | Hayır | Parola değişimi ile kilitleme bayat kalır |
| Kaba kuvvet sayacı okuması | Hayır | Sayaç bayatsa kilit çalışmaz |
| Onay kontrolü | Hayır | Geri çekilmiş onay bayat kalır |
| JWKS ile keşif metadata'sı | Evet, ancak zaten bellekte olmalıdır | Anahtar rotasyonu planlı ile yavaştır ve ayrıca bir örtüşme penceresi vardır |
| Yönetici kullanıcı arama ile listeleme | Evet | Bayatlık zararsızdır |
| Yönetici raporları ile denetim izi görüntüleme | Evet | Salt okunur analitiktir |
| Kullanıcı profil sayfası okuması, yani kendi kendine servis | Evet, dikkatle | Kendi yazdığını okuma gereklidir, aşağıya bakınız |
| Grup ile rol üyeliği, yani yetkilendirme kararı | Hayır | Kaldırılan rol bayat kalır |

Genel kural şudur: bir sorgunun sonucu bir güvenlik kararını etkiliyorsa birincilden okunur.

**2.4.2 Bunu güvenli yapmanın yolları.**

| Teknik | Nasıl | Maliyet | Argus'taki yeri |
|---|---|---|---|
| Birincile sabitleme | Güvenlik kritik okumalar hep birincile gider | Birincilde okuma yükü artar | Varsayılandır |
| `synchronous_commit = remote_apply` | Kesinleştirme, bekleme düğümü uygulayana kadar bekler ve replikada anında görünür | En pahalı moddur; Percona'ya göre `off` ayarına göre iki kat yavaştır | Yalnızca iptal ile kilitleme yazmalarında, oturum seviyesinde ayarlanarak |
| Günlük sıra numarası tabanlı kendi yazdığını okuma | Yazmadan sonra `pg_current_wal_lsn()` alınır ile çerez ya da token'a konur; replikada `pg_last_wal_replay_lsn()` ile karşılaştırılır ve geride ise birincile düşülür | Uygulama karmaşıklığı | Kendi kendine servis profil ekranları için |
| Sınırlı bayatlık | Gecikme eşiğini aşan replika devre dışı bırakılır | İzleme gerekir | Genel sağlık koruması |
| Düğüme yerel dönem önbelleği ile kısa yaşam süresi | 4.5'e bakınız | Küçüktür | Ana ölçekleme kaldıracıdır |

En pratik Argus deseni şudur: replikadan hiç güvenlik okuması yapılmaz. Bunun yerine iptal durumu düğüm belleğine önbeleklenir ile o önbellek giden kutusu ve yoklamayla 100 ile 250 milisaniye içinde güncellenir. Bu, hem replikadan hızlı hem birincilden doğrudur.

### 2.5 Bağlantı havuzlaması ile devralma etkileşimi

| Havuzlayıcı | Devralma davranışı | Performans, Tembo kıyaslaması | Argus'a uygunluğu |
|---|---|---|---|
| PgBouncer | Replika devralma desteği zayıftır; duraklat ile devam et elle yapılır ve genelde sanal IP ya da DNS değişimine bağımlıdır | 50'den az istemcide en iyi gecikme ile iş hacmini vermektedir | Basittir ile kanıtlanmıştır; Patroni'nin geri çağrılarıyla birleştirilmelidir |
| pgcat, Rust ile yazılmıştır | Otomatik devralma, okuma replikası yük dağıtımı ile parçalama sunar | 50'den fazla istemcide PgBouncer'dan iyidir; PgBouncer'a göre eksi %17 ile artı %24 aralığındadır | Argus için en uygunudur; Rust'tır ve okuma yazma ayrımı yerleşiktir |
| Supavisor, Elixir ile yazılmıştır | Kiracı duraklatmayla zarif devralma sunar ile çok kiracılıdır | %80 ile %160 daha yüksek gecikme vermektedir | Argus'un profiline uymamaktadır |
| Odyssey | — | — | Değerlendirilmemiştir ve doğrulanamamıştır |

Kaynağı Tembo'nun PostgreSQL bağlantı havuzlayıcıları kıyaslamasıdır.

Kritik uyarı şudur: PgBouncer'ı işlem havuzlama modunda kullanmak hazırlanmış ifadeleri ile geçici tabloları kısıtlamaktadır. Argus `sqlx` ile hazırlanmış ifadelere yoğun olarak dayanmaktadır. PgBouncer 1.21 ve üstü isimli hazırlanmış ifade desteği eklemiştir ancak Argus'un bunu doğrulaması gerekir ve doğrulanmamıştır. pgcat ya da doğrudan uygulama havuzu, yani `sqlx`, ile pgcat kombinasyonu daha az sürprizlidir.

### 2.6 PostgreSQL 18: yüksek erişilebilirlik açısından ne değişmiştir

Kaynağı PostgreSQL 18.0 sürüm notlarıdır, Eylül 2025.

| Özellik | Yüksek erişilebilirlik ile IdP anlamı |
|---|---|
| Asenkron giriş çıkış: `io_method`, Linux'ta `io_uring` ile her yerde işçi yedeği; `io_combine_limit` ile `pg_aios` görünümü | Ardışık ile bit eşlem taramaları ile vakumlama hızlanmaktadır. IdP'de doğrudan etkisi sınırlıdır, çünkü iş yükü indeks araması ağırlıklıdır; ancak vakumlamanın hızlanması oturum tablolarındaki şişme baskısını azaltmaktadır |
| `uuidv7()`, yani zaman sıralı evrensel benzersiz kimlik | Argus için önemlidir. UUID sürüm dört birincil anahtarlar B ağacını parçalamakta, UUID sürüm yedi eklemeleri indeksin sonuna yazmaktadır. Oturum ile token tabloları gibi yüksek ekleme hacimli tablolarda indeks şişmesi ile günlük hacmi ciddi azalmaktadır |
| `idle_replication_slot_timeout` | Terk edilmiş mantıksal yuvaların günlüğü sonsuz biriktirip diski doldurarak birincili öldürmesini engellemektedir. Bu klasik bir üretim kesinti sebebidir |
| `pg_recvlogical --enable-failover` | Devralma yuvalarıdır; mantıksal replikasyon devralmadan sağ çıkmaktadır |
| `pg_createsubscriber --all` | Tüm veritabanları için mantıksal replika oluşturmaktadır |
| Mantıksal replikasyon çakışma günlüklemesi | Aktif aktif denemelerinde çakışmaları görünür kılmaktadır |
| Büyük sürüm yükseltmesinde planlayıcı istatistiklerinin korunması | Yükseltme sonrası performans çukuru ortadan kalkmakta ve planlı bakım penceresi kısalmaktadır |
| OAuth istemci kimlik doğrulama desteği | Argus'un kendisi PostgreSQL'e OAuth ile bağlanabilmektedir; ironiktir ancak gerçektir |

Not olarak mantıksal replikasyon yuvası senkronizasyonu, yani `sync_replication_slots`, PostgreSQL 17 ile gelmiştir; 18 bunun araç desteğini tamamlamaktadır.

PostgreSQL 19 normal takvimde Eylül 2026'da beklenmektedir. Bu araştırmada içeriği doğrulanamamıştır.

---

## Bölüm 3 — Çok bölgeli kimlik

### 3.1 Giriş akışı kaç yazma yapmaktadır, çok bölgeliliğin gerçek maliyeti

Bir OIDC authorization code ile PKCE akışında Argus'un yapması gereken yazmalar şunlardır.

| # | Yazma | Zorunlu mudur |
|---|---|---|
| 1 | Kimlik doğrulama oturumu, giriş formu gösterildiğinde | Evet; Keycloak ikinci sürümü bunu veritabanına taşımıştır |
| 2 | Kaba kuvvet ile giriş başarısızlığı sayacı güncellemesi | Evet, başarısızlıkta |
| 3 | Authorization code, tek kullanımlık ile kısa ömürlü | Evet |
| 4 | Kullanıcı oturumu kaydı | Evet |
| 5 | Yenileme token'ı kaydı, rotasyon ailesiyle | Evet |
| 6 | Son giriş zamanı güncellemesi | Genelde |
| 7 | Denetim olayı | Evet |
| 8 | DPoP `jti` ya da nonce kaydı, DPoP kullanılıyorsa | Duruma göre |

Yani beş ile yedi yazma vardır. Bu bir mimari tahmindir; Keycloak'ın istek başına birden çok veritabanı etkileşimi ifadesiyle uyumludur ancak Argus için ölçülmemiştir.

Şimdi çarpalım.

| Topoloji | Yazma başına konsensüs maliyeti | Altı yazmalık giriş |
|---|---|---|
| Tek erişilebilirlik alanı | Yaklaşık sıfır | Tabandır |
| Üç erişilebilirlik alanı, tek bölge, gidiş dönüş bir ile iki milisaniye | Yaklaşık bir ile iki milisaniye | Artı altı ile 12 milisaniye; uygundur |
| İki bölge, 10 milisaniye gidiş dönüş | Yaklaşık 10 milisaniye | Artı 60 milisaniye; dikkat gerekir |
| İki bölge, 20 milisaniye gidiş dönüş | Yaklaşık 20 milisaniye | Artı 120 milisaniye; uygun değildir, Keycloak 26.3'te 99. yüzdelik 1.076 milisaniyeydi |
| Doğu ABD ile batı Avrupa, yaklaşık 80 ile 90 milisaniye gidiş dönüş, doğrulanamamıştır | Yaklaşık 40 ile 90 milisaniye | Artı 240 ile 540 milisaniye; kesinlikle uygun değildir |

Bu tablo Keycloak'ın farklı bölgelere yaymayın cümlesinin tüm gerekçesidir. Argus için boru hattını kısaltmak, yani yazma sayısını altıdan üçe indirmek, çok bölgeliliği mümkün kılmaz, yalnızca acıyı yarıya indirir.

### 3.2 Dağıtık SQL seçenekleri, kimlik iş yükü için

| Ürün | Tutarlılık | Bölgeler arası yazma | Postgres uyumu | Kimlik iş yükü için sorun | Lisans ile maliyet |
|---|---|---|---|---|---|
| CockroachDB | Serileştirilebilir, Raft ile | Vardır, satır seviyesinde yurtlandırmayla | Kablo uyumludur ancak PL/pgSQL ile birçok uzantı yoktur | Ory'nin yaşadığıdır: birincil anahtar aramasında 230 milisaniye. Küresel tablolar kişisel veri için GDPR'a aykırıdır | 24.3.0'dan itibaren CockroachDB yazılım lisansıdır. Kurumsal ücretsiz kullanım yıllık cironun 10 milyon doların altında olmasını, zorunlu telemetriyi ile telemetri yedi gün gitmezse kısıtlamayı içerir; üstü ücretlidir |
| Aurora DSQL | Anlık görüntü izolasyonu, iyimser eşzamanlılık kontrolü ile güçlü tutarlılık | Aktif aktiftir, iki bölgesel uç noktayla | PostgreSQL 16 uyumludur | Tetikleyici, PL/pgSQL ile geçici tablo yoktur; işlem başına 3.000 satır ile bir DDL limiti vardır; bağlantı bir saatte kopmaktadır; tek bir `postgres` veritabanı ile yalnızca `C` harmanlaması vardır. Kıtalar arası çok bölgelilik yoktur | AWS'e kilitlidir |
| YugabyteDB | Raft ile serileştirilebilir ya da anlık görüntü | Bölgeler arası küme ile coğrafi bölümleme | En yüksek PostgreSQL uyumu iddiasındadır, çünkü PostgreSQL kod tabanını yeniden kullanmaktadır | Bu araştırmada bağımsız bir kıyaslama bulunamamış ile doğrulanamamıştır | Çekirdeği Apache 2.0'dır |
| TiDB | Raft | Vardır | MySQL uyumludur | Argus Postgres'e yazılmaktadır, dolayısıyla kapsam dışıdır | Apache 2.0 |
| Vitess | MySQL parçalaması | Çok bölge için tasarlanmamıştır | MySQL | Kapsam dışıdır | Apache 2.0 |
| Neon | PostgreSQL, depolama ile hesaplama ayrımıyla | Bölgeler arası replika sınırlıdır | Tam PostgreSQL'dir | Sunucusuz soğuk başlangıç bir IdP için risklidir ile çok bölgeli aktif aktif yoktur. Databricks satın alması sonrası yol haritası belirsizdir ve doğrulanamamıştır | — |
| AlloyDB ile AlloyDB Omni | PostgreSQL uyumludur | Bölgeler arası asenkron replikasyon | Yüksektir | Aktif aktif değildir | Omni hariç GCP'ye kilitlidir |
| Spanner, PostgreSQL arayüzüyle | Dış tutarlılık, TrueTime ile | Gerçekten küreseldir | Kısıtlı bir PostgreSQL arayüzü vardır | Maliyet ile GCP kilidi vardır | GCP |

**3.2.1 CockroachDB'yi kimlik için doğru anlamak.** Tablo yerleşimleri şöyledir, erişim 8 Eylül 2026.

| Yerleşim | Okuma | Yazma | Kimlikte kullanımı |
|---|---|---|---|
| Tabloya göre bölgesel | Yurt bölgesinde hızlı, dışarıdan yavaştır | Yurt bölgesinde hızlıdır | Bölgeye özgü tablolar içindir |
| Satıra göre bölgesel | Satırın yurt bölgesinde hızlıdır, dışarıdan düşük gecikmeli takipçi okuması vardır | Yurt bölgesinde hızlı, dışarıdan yavaştır | Kullanıcı verisi için doğru araçtır; satır bazında bölgeye sabitlenir |
| Küresel | Her bölgeden düşük gecikmelidir | Yüksektir, çünkü bir kesinleştirme bekleme adımı vardır | Realm, istemci ile politika metadata'sı için idealdir; kişisel veri için yasal olarak kullanılamaz |

Hayatta kalma hedefi `ZONE`, yani varsayılan, erişilebilirlik alanı kaybından sağ çıkar; `REGION` bölge kaybından sağ çıkar ancak tüm yazmalar en az bir ek bölgeye danışmak zorundadır ve yazma gecikmesi artar. Süper bölge için en az üç bölge gerekir.

Sert sınırları şunlardır: takipçi okuması en az 4,2 saniye geçmiştir ve bir güvenlik kararı için kullanılamaz; küresel tablolarda düğümler arası gidiş dönüş 150 milisaniyeyi aşarsa düzensiz yüksek gecikme oluşmaktadır, ki bu Cockroach dokümanından bir arama sonucu üzerinden gelmekte ve doğrudan sayfa doğrulanmamaktadır; yeni kümelerde küresel yazma gecikmesini düşürmek için `--max-offset 250ms` önerilmektedir.

Sonuç şudur: CockroachDB, kullanıcıyı bölgeye sabitle ile metadata'yı küresel yap deseni için gerçekten tasarlanmış tek olgun açık üründür. Ancak Ory'nin deneyimi kutudan çıktığı gibi çalışmadığını göstermektedir: tablo yerleşimlerini tek tek elle tasarlamak, sorguları yeniden yazmak ile küresel TCP yönlendirmesi eklemek gerekmektedir. Ayrıca Kasım 2024'teki lisans değişikliği kendi kendine barındırmayı ticari bir karar hâline getirmiştir.

### 3.3 PostgreSQL mantıksal replikasyonuyla çok bölge, aktif aktif

| Çözüm | Durum | Çakışma çözümü |
|---|---|---|
| pgEdge ile Spock | Açık kaynaktır ile aktif geliştirmededir | Son yazan kazanır ile kullanıcı tanımlı |
| pgactive, AWS | RDS içindir | Son yazan kazanır |
| EDB Postgres Distributed | Ticaridir | Gelişmiştir; çatışmasız replike veri tipi sayaçları dahildir |
| PostgreSQL 18 yerel | Aktif aktif değildir; çakışma günlüklemesi eklenmiştir | — |

Argus için cevap hayırdır.

Gerekçesi Kanidm bölümüyle aynıdır ve daha güçlüdür: son yazan kazanır çakışma çözümü kimlikte bir güvenlik açığıdır. Aktif aktif mantıksal replikasyon, iki bölgede aynı kullanıcının parolasını, çok adımlı doğrulamasını ya da rollerini eşzamanlı değiştirebilir ile saat kaymasına göre kazananı seçer. Bir IdP'de son yazan kazanır demek, saldırgan saatini ileri alırsa kazanır demektir.

İstisnası çakışmayan ve bölgeye özgü tablolardır, örneğin bölgesel denetim günlükleri; bunlar için mantıksal replikasyon tek yönlü toplama amacıyla kullanılabilir.

### 3.4 Veri yerleşimi, çok bölgeliliğin gerçek sürücüsü

Burada kritik bir tersine çevirme vardır: çoğu ekip çok bölgeliliği düşük gecikme sandığı için istemektedir. Gerçekte çok bölge ihtiyacının %90'ı yasal veri yerleşimidir ve bu iki hedef birbiriyle çelişmektedir. Düşük gecikme çok bölgeli okuma ister, yani veriyi her yere kopyala; veri yerleşimi ise veriyi hiçbir yere kopyalama der.

Ory'nin bakımcısı bunu doğrudan söylemektedir: küresel tablolar kişisel veri için GDPR ile CCPA ihlalidir. Ory Network bu yüzden veri yurtlandırması yapmaktadır: kişisel veri kullanıcının ülkesinde kalmakta, yalnızca kimlik referansı küresel olmaktadır.

Sektörün gerçek cevabı replikasyon değil izolasyondur.

Okta'nın hücre tabanlı mimarisi, kendi beyaz kâğıtlarından: her hücre izole, hiçbir şeyi paylaşmayan ve aynı Okta altyapısının tam bir kopyasıdır; yönlendiriciden yük dengeleyiciye, oradan veritabanına kadar uzanır. Hücreler bağımsız çalışmakta ve hata izolasyonu erişilebilirlik stratejisinin temelini oluşturmaktadır. AWS bölgeleri üzerinde Kuzey Amerika, Avrupa, Avustralya ile Japonya'da bulunmaktadır. Amacı açıkça hem erişilebilirlik hem veri yerleşimidir.

Auth0 aynı modeli kullanmaktadır: bölgesel kiracılar, yani ABD, AB, Avustralya ile Japonya; kiracı bölgeler arasında taşınmamakta ile replike edilmemektedir. Auth0'ın 2026 tarihli mimari yazısı bu oturumda doğrulanamamıştır.

> **Argus için ders.** Çok bölgeli kimlik, bölge başına bağımsız bir Argus kurulumu, yani hücre, artı kiracıların bir hücreye atanması artı hücreler arasında hiçbir veri replikasyonu demektir. Bu, dağıtık SQL'in tüm karmaşıklığını ortadan kaldırmakta ve yasal gereksinimi doğal olarak karşılamaktadır. Küresel olan tek şey kontrol düzlemidir: hangi kiracının hangi hücrede olduğu haritası; küçüktür, nadiren değişir ile önbeleklenebilir.

### 3.5 Çok bölge karar tablosu, Argus için

| Yaklaşım | Tutarlılık | Giriş gecikmesi | Arıza modu | Operasyonel maliyet | Argus kararı |
|---|---|---|---|---|---|
| Tek bölge, üç erişilebilirlik alanı, senkron Postgres | Güçlüdür | Taban artı altı ile 12 milisaniye | Bölge kaybı bir kesintidir ve felaket kurtarmaya geçilir | Düşüktür | Birinci sürümde seçilir |
| İki bölge, aynı bölgede, senkron, yani Keycloak ikinci sürüm modeli | Güçlüdür | Etkileşim başına artı sekiz ile 10 milisaniye, veritabanı işlemcisi iki kat | Bölge kaybında veri kaybı yoktur | Ortadır | İkinci sürümde seçilir |
| Hücre başına bölge, yani Okta modeli | Hücre içinde güçlüdür | Tabandır, çünkü kullanıcı kendi hücresindedir | Hücre kaybı yalnızca o hücreyi etkiler | Orta ile yüksektir, çünkü N kurulum vardır | Üçüncü sürümde hedeftir |
| CockroachDB satıra göre bölgesel | Serileştirilebilirdir | Yurt bölgesinde düşük, dışarıda yüksektir | Bölge kaybı tolere edilir | Yüksektir; şema tasarımı ile lisans nedeniyle | Yalnızca gerçek bir küresel gereksinim varsa |
| Postgres aktif aktif, mantıksal | Nihai tutarlılık ile son yazan kazanır | Düşüktür | Çakışma bir güvenlik açığıdır | Yüksektir | Asla seçilmez |
| Aurora DSQL | Anlık görüntü ile iyimser eşzamanlılık | Kıta içinde iyidir | Bölge kaybı tolere edilir | Düşüktür ancak AWS kilidi ile ağır SQL kısıtları vardır | Yalnızca yalnızca AWS ürün stratejisinde |

---

## Bölüm 4 — Dağıtık durum ve iptal yayını

### 4.1 Yayın mekanizmalarının karşılaştırması

| Mekanizma | Teslim garantisi | Gecikme | Düğüm kaybında | Ek altyapı | Kimlik için karar |
|---|---|---|---|---|---|
| Redis ile Valkey yayın aboneliği | En fazla bir kez | Yaklaşık bir milisaniye | Mesaj sonsuza kadar kaybolur | Redis | Tek başına asla kullanılmaz |
| Redis akışları | En az bir kez, tüketici grubuyla | Yaklaşık bir milisaniye | Kalıcıdır ile yeniden oynatılabilir | Redis | Kabul edilebilirdir |
| NATS çekirdeği | En fazla bir kez | Bir milisaniyenin altı | Kaybolur | NATS | Kullanılmaz |
| NATS JetStream | En az bir kez, onay ile yeniden teslim ile sıra numarasıyla | Bir ile beş milisaniye | Akış diskte durur ile yeniden oynatılır | NATS ile depolama | Uygundur ancak fazladan bir sistemdir |
| Kafka | En az bir kez, kalıcı günlükle | 5 ile 50 milisaniye | Kalıcıdır | Kafka ile ZooKeeper ya da KRaft | Bir IdP için aşırıdır |
| Dedikodu protokolü | Nihai, olasılıksaldır | 100 milisaniyeden saniyelere | Yakınsar | Yoktur | Yakınsama süresi belirsizdir |
| Veritabanı yoklaması | Olay veritabanında kalıcıdır ile teslimat en az bir kezdir | Yoklama aralığı kadar | Kaybolmaz | Yoktur | Uygundur |
| Veritabanı işlemsel giden kutusu ile yoklama | Atomik üretim, yani iş değişikliğiyle aynı işlemde, ile en az bir kez teslimat | Yoklama aralığı kadar, yani 100 milisaniye | Kaybolmaz | Yoktur | En uygunudur; Keycloak'ın seçimidir |
| PostgreSQL `LISTEN` ile `NOTIFY` | En fazla bir kez; bağlantı koparsa kaybolur | Bir milisaniyenin altı | Kaybolur | Yoktur | İptal yayınında kullanılmaz, §6'nın 4.5 bölümü |

> **Üçüncü inceleme turunda yapılan düzeltme.** Son iki satırda önceden tam bir kez yazıyordu. Bu, teslimat semantiği olarak fazla güçlü ile genel olarak yanlıştır. Olayın veritabanında kalıcı olması ile tüketicinin etkisinin tam bir kez uygulanması ayrı şeylerdir: tüketici satırı okuyup önbelleğe uygulamadan ölürse, yeniden başladığında aynı olayı yeniden alır. Doğru hedef üç parçalıdır ve üçü de ayrı ayrı tasarlanır: atomik üretim, yani olay ile iş değişikliğinin aynı işlemde olması; en az bir kez teslimat, yani yeniden teslimatın normal olması; ile idempotent ve monoton uygulama, yani dönemin yalnızca artması ve aynı olayın iki kez uygulanmasının sonucu değiştirmemesi.

### 4.2 Redis yayın aboneliğinin güvenlik problemi: bu bir görüş değil belgelenmiş bir davranıştır

Redis resmî dokümanının teslimat semantiği bölümü, erişim 8 Eylül 2026, doğrudan alıntıyla şöyledir:

> "Redis' Pub/Sub exhibits at-most-once message delivery semantics. As the name suggests, it means that a message will be delivered once if at all. Once the message is sent by the Redis server, there's no chance of it being sent again. If the subscriber is unable to handle the message (for example, due to an error or a network disconnect) the message is forever lost."

Mesaj kaybının somut sebepleri abonesiz bir kanala gönderim, bağlantısı kopmuş bir abone, çıkış tamponu taşması, yani yavaş bir abonenin mesajının Redis tarafından sessizce düşürülmesi, ile birincilden replikaya geçiştir.

Bir IdP'de bu şu demektir: iptal sinyali kaybolan düğüm iptal edilmiş token'ı kabul etmeye devam eder ve bunu sessizce yapar. Ne günlük ne alarm vardır. Bu, bir güvenlik kontrolünün var sanılıp olmaması durumudur ve hiç olmamasından beterdir.

Redis'i tamamen atmak gerekmez ancak bir doğruluk kaynağı olamaz. Doğru kullanımı, veritabanındaki gerçeği hızlandıran ve kaybolduğunda yoklamanın yakaladığı opsiyonel bir hızlandırıcı olmasıdır.

### 4.3 İşlemsel giden kutusu: Keycloak'ın çözümü ile Argus'un çözümü olmalıdır

Keycloak Multi-Cluster v2'de, 17 Temmuz 2026:

> "Between clusters, a database outbox pattern propagates invalidation messages via polling, with a default interval of 100 milliseconds."
>
> "Cross-cluster cache invalidation is handled through a database queuing table, not through direct network connections between clusters."

Bunun neden doğru olduğu şudur: iptal işlemi ile iptal sinyali aynı işlemde yazılır, yani ya ikisi de olur ya hiçbiri. Redis'e ayrı bir yayın yapmak ikili yazma problemidir: veritabanı kesinleşir, Redis yayını başarısız olur ve kalıcı bir güvenlik açığı oluşur.

**Argus için somut şema.**

```sql
-- Kullanıcı başına iptal epoch'u (asıl gerçek)
CREATE TABLE user_revocation (
  user_id       uuid PRIMARY KEY,
  epoch         bigint NOT NULL DEFAULT 0,   -- monoton artan
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Outbox: küme-geneli invalidation kuyruğu
CREATE TABLE revocation_outbox (
  seq        bigserial PRIMARY KEY,          -- monoton; node'lar kaldıkları yerden okur
  subject    text NOT NULL,                  -- 'user:<uuid>' | 'session:<id>' | 'client:<id>'
  epoch      bigint,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON revocation_outbox (seq);
```

İptal işlemi şöyledir:

```sql
BEGIN;
  UPDATE user_revocation SET epoch = epoch + 1, updated_at = now()
    WHERE user_id = $1 RETURNING epoch;
  INSERT INTO revocation_outbox (subject, epoch) VALUES ('user:'||$1, $2);
  -- oturum satırlarını da işaretle
COMMIT;
```

Her Argus düğümü 100 ile 250 milisaniyede bir şu sorguyu çalıştırır:

```sql
SELECT seq, subject, epoch FROM revocation_outbox
 WHERE seq > $last_seen_seq ORDER BY seq LIMIT 1000;
```

Sonuçlar düğüme yerel dönem önbelleğine uygulanır. Son görülen sıra numarası düğümün belleğindedir; düğüm yeniden başlarsa sıra numarasını sıfırdan almak yerine önbelleği boşaltıp önbellek ıskalamasında veritabanına sor moduyla ısınır, 6.4'e bakınız.

**`bigserial` boşluk tuzağı klasik bir hatadır.** Eşzamanlı işlemlerde 105 numaralı sıra kesinleşmiş, 104 numaralı henüz kesinleşmemiş olabilir. Naif bir sıra numarası karşılaştırmalı yoklama 104'ü kalıcı olarak atlar. Çözümlerden biri seçilmelidir: zaman penceresiyle örtüşme, yani son beş saniyeyi her turda yeniden taramak, ki idempotent olduğu için zararsızdır; anlık görüntünün asgari işlem kimliğini takip etmek, yani yalnızca kesin kesinleşmiş satırları işlemek; ya da bir işlem kimliği kolonu ile anlık görüntü karşılaştırması, ki Debezium'un yaptığı budur.

> **İkinci ile üçüncü inceleme turunda yapılan düzeltme: birinci seçim geri alınmıştır, çünkü yeterli değildir.**
>
> Birinci seçenek bir doğruluk mekanizması değildir. PostgreSQL'de `now()` işlemin başlangıç zamanını döndürmektedir, kesinleşme zamanını değil; dolayısıyla oluşturma zamanı, satır işlem açıldığı anla damgalanmaktadır. Pencereden uzun süren tek bir işlem, ki yukarıdaki güncelleme ile ekleme deseninin normal şeklidir, satırı zaten pencerenin dışına düşmüş bir oluşturma zamanıyla görünür kılar. Tüketici duraksarsa da pencere kayar ile satır kalıcı olarak atlanır. Pencere en fazla bir hızlandırıcı olabilir.
>
> İkinci seçenek de yazıldığı hâliyle eksiktir: şemada işlem kimliği tutulmamaktadır ile imlecin nasıl ilerleyeceği tanımlı değildir. Ayrıca sıra numarası tabanlı bir imleç bu problemi prensipte çözemez, çünkü kesinleşmemiş bir işlemin satırı çok sürümlü eşzamanlılık kontrolü altında görünmez ve uçuştaki bir işleme ait en düşük sıra numarası tablodan hesaplanamaz.
>
> **Teslimat algoritması bu belgede açık bir karardır.** İki aday, yani işlem kimliği su hattı üzerinden yoklama ile mantıksal çözümleme, ve ikisinin de ortak sınanacağı arıza matrisi için §1'in 10.2 bölümüne bakınız. Karşılaştırma yapılmadan ile matris koşulmadan buraya bir seçim yazılmayacaktır.

Maliyet, seçime bağlı bir hipotezdir: sıra numarası indeksi üzerinden yoklama varsayımıyla düğüm başına saniyede dört ile 10 küçük indeksli sorgu, 20 düğümde saniyede 80 ile 200 sorgu demektir ve bu Postgres için önemsizdir. Ancak bu rakam artık teslimat algoritmasının seçimine bağlıdır; seçilen aday sıra numarası indeksini kullanmayabilir ve asgari işlem kimliği adayı sistem sütunu üzerinden çalışırsa indeks kullanamaz ile ardışık tarama riski taşır, o durumda bu maliyet tahmini geçersizdir ile yeniden ölçülmelidir.

Saklama süresi açık bir karardır: giden kutusu tablosu bir pencereyle budanmalıdır, yani bölümlenmiş bir tablo ile bölüm düşürme kullanılmalıdır, yoksa şişer. Ancak 24 saat henüz güvenli bir karar değildir: tüketici penceresinden uzun süre düşerse bölüm düşürmek olayları kalıcı olarak yok eder. Yeniden senkronizasyon tasarımı tamamlanmadan hiçbir bölüm düşürülemez; pencere süresi o tasarımın çıktısı olarak belirlenecektir, §1'in 10.2 bölümü ile arıza matrisinin üçüncü senaryosu.

> **`NOTIFY` hızlandırması kullanılmaz; ikinci inceleme turunda yapılan düzeltmedir.** Bu paragraf önceden isteğe bağlı hızlandırma başlığıyla, aynı işlemin sonunda bir bildirim yapılmasını öneriyordu. Bu, §6'nın 4.5 bölümündeki mutlak yasakla ile §1'in 4.1 bölümü ve §2'nin dördüncü çelişkisinin karar satırlarıyla çelişmekteydi. Daha önemlisi opsiyonel çerçevesi hata modundan kaçamamaktadır: bildirim iptal yazımıyla aynı işlemin içinde olduğu için, bildirim kuyruğu dolduğunda kaybolan bir hızlandırma değil iptalin kendisinin kesinleşememesi söz konusudur. Yani iptal mekanizması veritabanının yazma yolunu düşürebilir hâle gelir ve §6'nın 4.5 bölümü bunu zaten kabul edilemez bir hata modu ilan etmiştir. Tek konum şudur: `LISTEN` ile `NOTIFY` iptal yayınında hiç kullanılmaz.

### 4.4 Bloom ile guguk filtresiyle iptal listesi

Bulgu şudur: bu araştırmada üretim IdP'lerinde token iptali için Bloom ya da guguk filtresi kullanan doğrulanmış bir örnek bulunamamıştır.

Birinci ilkelerden güvenlik analizi şöyledir. Bloom filtresi yanlış pozitif verir, yanlış negatif vermez. İptal listesi bağlamında yanlış pozitif bu token iptal edilmiştir demektir, oysa değildir, ve geçerli bir token reddedilerek kullanıcı gereksiz yere çıkış yapar. Yanlış negatif imkânsızdır, yani iptal edilmiş bir token asla kaçmaz. Yani yön güvenlidir ve güvenli tarafa düşmektedir; bu önemlidir ile çoğu kişi tersini sanmaktadır.

Ancak pratik problemler vardır. Birincisi silme yoktur: standart Bloom filtresinden eleman çıkarılamaz, token süresi dolduğunda filtreden çıkarılamaz, filtre doyar ile yanlış pozitif oranı zamanla tavana vurur; sayan Bloom ya da silmeyi destekleyen guguk filtresi gerekir. İkincisi yanlış pozitif oranı rastgele çıkış oranıdır: yüzde birlik bir oran kullanıcıların yüzde birinin rastgele çıkış yapması demektir ve kabul edilemez, on binde bire inmek için filtre büyür. Üçüncüsü iptal dönemi deseninin aynı işi sekiz baytla ile sıfır hatayla yapmasıdır; Bloom'un tek avantajı bellektir ve dönem deseni zaten bir bellek problemi yaratmamaktadır.

Karar şudur: Argus kullanmamalıdır. Tek meşru kullanım alanı DPoP `jti` yeniden oynatma koruması gibi çok yüksek kardinaliteli, kısa ömürlü ile yanlış pozitifi yalnızca tek bir isteği reddetmek olan, kullanıcı çıkışı olmayan durumlardır. Orada bile Redis kümesi ile yaşam süresi daha basittir.

### 4.5 İptal dönemi deseni: Argus'un omurgası olmalıdır

Desen şudur: kullanıcı başına monoton artan bir sayaç tutulur. Token'a bir dönem claim'i konur veya `iat` ile karşılaştırılır. Doğrulamada token'ın dönemi kullanıcının güncel döneminden küçükse token ölüdür.

Tek bir `UPDATE ... SET epoch = epoch + 1` ifadesi o kullanıcının şimdiye kadar verilmiş tüm token'larını öldürür.

Kim kullanmaktadır sorusunun cevabı şudur: bu, token sürümü, token nesli ile oturum nesli adlarıyla yaygın bir desendir. Django'nun `AbstractBaseUser.get_session_auth_hash()` fonksiyonu, Rails'in `devise` eklentisindeki kimlik doğrulanabilir tuz ile Firebase Auth'un `tokensValidAfterTime` alanı aynı fikrin varyasyonlarıdır; bu ürün eşleşmeleri genel bilgiye dayanmaktadır ve bu oturumda tek tek doğrulanmamıştır. Genel teknik yazın bunu token sürümleme olarak tarif etmekte ve tek bir veritabanı güncellemesinin kullanıcının şimdiye kadar verdiği her token'ı geçersiz kıldığını, kullanıcı başına yalnızca sekiz bayt depolama gerektirdiğini söylemektedir; bu ikincil ile düşük otoriteli bir kaynaktır, yani michal-drozd.com ile techinterview.org gibi blog yazılarıdır, bağımsız bir üretim ölçümü değildir.

> **Uyarı.** Aramada karşılaşılan saniyede 10.000 istek ile 100 bin kullanıcıda token sürümü doğrulamasının önbeleklenmiş aramayla yalnızca 0,3 milisaniye eklediği, kısa sona ermenin 0,05 milisaniye ile engelleme listesinin 0,2 milisaniye olduğu rakamları düşük otoriteli blog yazılarından gelmektedir ile bağımsız olarak doğrulanamamıştır. Argus bunları bir planlama girdisi olarak kullanmamalı ile kendi ölçümünü yapmalıdır.

`iat` değerinin dönem zaman damgasından küçük olması varyantı ile sayaç varyantının karşılaştırması şöyledir.

| Varyant | Artısı | Eksisi |
|---|---|---|
| Monoton sayaç, yani `epoch: bigint` | Saat kaymasından bağımsızdır ile kesindir | Token'a ekstra bir claim gerekir |
| Zaman damgası, yani `revoked_before: timestamptz`, `iat` ondan küçükse ölüdür | Ekstra claim gerekmez, çünkü `iat` zaten vardır | Saat kayması riski vardır: bir saniye içinde çıkarılan token'lar aynı saniyeye düşer; ayrıca `iat` saniye çözünürlüklüdür ve aynı saniyede iptal ile yeni token verilirse yeni token da ölür |

Argus önerisi her ikisidir: token'da bir `rev` claim'i, yani dönem sayısı, taşınır; kullanıcı tablosunda hem dönem hem dönemin ayarlandığı zaman tutulur. Doğrulama sayaç üzerinden yapılır, çünkü kesindir; zaman damgası yalnızca gözlemlenebilirlik ile denetim içindir.

**4.5.1 Ölçekleme davranışı ile düğümlere yayılım.** Bu desenin tek zorluğu her token doğrulamasında kullanıcının dönemini bilmek gerekmesidir. Naif uygulama her istekte bir veritabanı sorgusudur ve ölçeklenmez.

Argus'un çözümü üç katmanlıdır.

```
Katman 1: Node-yerel epoch cache (moka/DashMap)
          - key: user_id → epoch
          - kapasite: aktif kullanıcı sayısı (~1M kullanıcı × 24 byte ≈ 24 MB)
          - TTL: yok; outbox invalidation ile güncellenir

Katman 2: Outbox polling (100–250 ms)
          - epoch değişimlerini cache'e uygular
          - "en kötü durumda iptal gecikmesi" = polling aralığı

Katman 3: PostgreSQL primary (doğruluk kaynağı)
          - cache miss → tekil sorgu
          - node soğuk başlangıcında baskın yol
```

Kritik güvenlik detayı olumsuz önbellek tuzağıdır: önbellekte olmayan bir kullanıcı için dönem sıfırdır varsaymak kabul edilemez, çünkü bir iptal kaçırılabilir. Doğru davranış önbellek ıskalamasında mutlaka veritabanına sormaktır; önbellek yalnızca bilinen, yani olumlu değerleri hızlandırır.

Alternatif bir optimizasyon küresel dönem tabanıdır: düğüm, gördüğü en yüksek giden kutusu sıra numarasını ile son N dakikada iptal edilen kullanıcıların kümesini tutar. Token'ın `iat` değeri düğümün tam senkronize olduğu andan sonraysa ve kullanıcı iptal kümesinde değilse veritabanı sorgusu gerekmez. Bu, önbellek ıskalamalarının büyük çoğunluğunu ortadan kaldırır ile yalnızca son N dakikada iptal edilenler kadar bellek ister. N bir saat ve saatte 10.000 iptal olursa 10.000 evrensel benzersiz kimlik yaklaşık 160 kilobayt eder. Bu, Argus'un en verimli tasarımıdır.

Ölçek açısından bu desen kullanıcı sayısıyla sabit davranır, çünkü maliyet iptal hızıyla orantılıdır, kullanıcı sayısıyla değil. Yüz milyon kullanıcılı bir sistemde bile saniyede 100 iptal varsa giden kutusu trafiği önemsizdir.

### 4.6 Gecikme bütçesi: anında iptal kaç milisaniye olmalıdır

Sektörde fiilen kabul edilen değerler şunlardır.

| Sistem | İptal yayılım süresi | Kaynak |
|---|---|---|
| Keycloak Multi-Cluster v2 | 100 milisaniye, giden kutusu yoklama varsayılanı | keycloak.org, 17 Temmuz 2026, doğrulanmıştır |
| CockroachDB takipçi okuması | En az 4,2 saniye, kaçınılmaz bayatlık | cockroachlabs dokümanı, doğrulanmıştır |
| OAuth 2.0 access token ömrü, yaygın pratik | Beş ile 15 dakika; fiilî iptal gecikmesi budur | Genel pratiktir |
| CAEP ile SSF sinyal teslimi | İtme modelinde saniyeler | Sayısal hizmet düzeyi doğrulanmamıştır |

Argus için önerilen bütçe şöyledir.

| Katman | Hedef | Nasıl |
|---|---|---|
| Aynı düğüm | Sıfır milisaniye, senkron | İptal işlemi kendi düğümünde önbelleği hemen günceller |
| Diğer düğümler, aynı küme | 99. yüzdelikte 250 milisaniyenin altı; bu bir hedeftir ve teslimat algoritması açık bir karardır, §1'in 10.2 bölümü | Giden kutusu yoklaması 100 milisaniyedir; `NOTIFY` hızlandırması kullanılmaz, 4.3'e bakınız |
| Diğer küme ya da bölge | 99. yüzdelikte 500 milisaniyenin altı | Senkron veritabanı ile giden kutusu yoklaması |
| Kaynak sunucular | Access token ömrü kadar | Kısa access token, yani beş dakika, ile içgözlemde 250 milisaniye |
| Federe ilgili taraflar | Saniyeler | SSF ile CAEP itmesi |

Bu bütçenin savunması şudur: kullanıcı tüm cihazlarından çıkmak istediğinde Argus'un kendi yüzeyi, yani giriş, yenileme ile içgözlem, iptali 250 milisaniye içinde uygular. Access token'ı hâlâ elinde tutan bir kaynak sunucu, token süresi dolana kadar, yani en fazla beş dakika, kabul edebilir; bu tasarım gereğidir, bir hata değildir, ve yalnızca DPoP ile içgözlem zorunluluğuyla kapatılabilir.

Karşı tez ile cevabı şudur: anında iptal isteyen ekipler genellikle içgözlemi zorunlu kılmayı reddetmektedir, çünkü gecikme istememektedir. Bu ikisi aynı anda olamaz. Argus bu takası açıkça belgelemeli ile iki profil sunmalıdır: hızlı profilde JWT kendi kendine yeterlidir, beş dakikalıktır ile iptal beş dakikaya kadar sürer; katı profilde içgözlem zorunludur ile iptal 250 milisaniyeye kadar sürer.

---

## Bölüm 5 — Dağıtık hız sınırlama

### 5.1 Algoritmalar

| Algoritma | Bellek | Ani yük davranışı | Dağıtıklaştırılabilirlik | Not |
|---|---|---|---|---|
| Sabit pencere | En azdır, tek sayaçtır | Pencere sınırında iki kat ani yüke izin verir | Kolaydır; artır ile süre ver yeterlidir | Sınır davranışı kabul edilemezdir |
| Kayan pencere günlüğü | Yüksektir, her istek kaydedilir | Kesindir | Zordur ile pahalıdır | Doğrudur ancak pahalıdır |
| Kayan pencere sayacı | Düşüktür, iki sayaç ile bir ağırlık | İyi bir yaklaşımdır | Kolaydır | Pratik tatlı noktadır |
| Jeton kovası | Düşüktür, iki alan: jeton ile zaman damgası | Kontrollü ani yüke izin verir | Kolaydır | Yaygındır |
| GCRA, yani genel hücre hızı algoritması | En düşüktür, tek bir teorik varış zamanı değeri | Kontrollü ani yüke izin verir ile arka planda bir damlatma süreci gerektirmez | Kolaydır, tek atomik değerdir | Teknik olarak en zarifidir |

GCRA'nın neden üstün olduğu şudur: tek bir teorik varış zamanı değeri saklar; ne bir sayaç dizisi ne bir zamanlayıcı gerekir ve sürekli, yani kayan bir zaman penceresi verir. redis-cell'in README dosyası bunu açıkça söylemektedir: kayan bir zaman penceresi sağlar ile arka planda bir damlatma sürecine bağımlı değildir.

### 5.2 Rust ekosistemi ile dağıtık moddaki boşluk

`governor` 0.10.4, docs.rs'e göre son güncellemesi 5 Eylül 2026'dır. GCRA uygulamaktadır; varsayılan doğrudan hız sınırlayıcı, yani tek durumlu, ile varsayılan anahtarlı hız sınırlayıcı, yani anahtar başına durumlu ve `dashmap` tabanlı, sunmaktadır. Tamamen süreç içidir; bağımlılıkları, yani `dashmap`, `parking_lot`, `quanta` ile `spinning_top`, bunu doğrulamaktadır, çünkü hiçbir ağ ya da depolama arka ucu yoktur.

`tower-governor` crate'i `governor`'ı bir Tower ara katmanı olarak sarmaktadır ve aynı sınıra sahiptir: süreç içidir.

> **Net sonuç: Rust'ta hazır, olgun ile dağıtık bir hız sınırlayıcı yoktur.** `governor` mükemmel bir yerel sınırlayıcıdır; dağıtık katmanı Argus'un kendisi yazmak zorundadır.

`redis-cell`, erişim 8 Eylül 2026: GCRA'yı bir Redis modülü olarak uygulamakta ile `CL.THROTTLE` komutunu sunmaktadır. Performansı bir Redis istemcisinden görüldüğü kadarıyla komut başına kabaca 0,1 milisaniyedir ve basit bir kümeleme işleminin biraz iki katından azdır. 2026 durumu şudur: paket elden gelenin en iyisi bakım modundadır, yani yazarı aktif geliştirmemektedir. Bir modül yüklemek gerektiği için yönetilen Redis servislerinin çoğunda kullanılamaz, örneğin ElastiCache ile Memorystore'da.

### 5.3 Doğruluk ile performans: yaklaşık sayaçlar kabul edilebilir midir

Cevap sınırın türüne bağlıdır ile bu ayrım kritiktir.

| Sınır tipi | Doğruluk gereksinimi | Neden |
|---|---|---|
| Kaba trafik ile hizmet reddi koruması, IP başına istek | Yaklaşık kabul edilebilirdir | Yüzde onluk bir hata hiçbir şeyi değiştirmez |
| API kotası, müşteri başına ücretli | Ortadır | Bir fatura anlaşmazlığıdır, güvenlik değildir |
| Hesap başına parola denemesi, yani kimlik bilgisi doldurma | Kesin olmalıdır | Aşağıya bakınız |
| Tek kullanımlık parola ile çok adımlı doğrulama deneme sayısı | Kesin olmalıdır | Altı haneli bir parolada her ekstra deneme entropiyi doğrudan yemektedir |
| Parola sıfırlama ile e-posta gönderimi | Ortadır | Bir suistimaldir, güvenlik değildir |

Hesap başına sınırın neden kesin olması gerektiğinin matematiği şudur. Altı haneli bir tek kullanımlık parolanın bir milyon olası değeri vardır. Saldırganın hesap başına beş denemesi varsa başarı olasılığı beş bölü bir milyon, yani iki yüz binde birdir. Argus 10 düğüme dağıtılmışsa ile her düğüm bağımsız bir yerel sayaç tutuyorsa, saldırgan istekleri düğümlere dağıtarak 10 çarpı beş, yani 50 deneme yapar ve başarı olasılığı on kat artar. Düğüm sayısı arttıkça açık büyür; yani yatay ölçekleme doğrudan bir güvenlik zafiyetine dönüşmektedir.

Aynı mantık kimlik bilgisi doldurma için de geçerlidir: hesap başına dakikada beş denemelik bir sınır, 20 düğümde fiilen dakikada 100 olur.

### 5.4 Argus için iki katmanlı tasarım

```
KATMAN A — Yerel, yaklaşık (governor)
  Amaç: node'u ve DB'yi korumak; kaba suistimal
  Kapsam: IP başına, endpoint başına, global QPS tavanı
  Doğruluk: yaklaşık, node başına (N node = N× gerçek sınır) — KABUL EDİLEBİLİR
  Maliyet: ~0 (bellek içi, kilitsiz)

KATMAN B — Paylaşılan, kesin
  Amaç: güvenlik sınırları
  Kapsam: hesap başına parola denemesi, OTP denemesi, MFA challenge,
          refresh token reuse, hesap kilitleme sayacı
  Doğruluk: KESİN, küme geneli
  Uygulama: PostgreSQL satırı (atomik UPDATE) veya Redis Lua (GCRA)
  Maliyet: yazma başına 1 DB round-trip (~1 ms aynı AZ)
```

İkinci katmanı PostgreSQL'de yapmak Argus için doğru tercihtir:

```sql
-- Tek atomik ifade, GCRA benzeri, kilit tutmadan
UPDATE login_throttle
   SET tat = GREATEST(tat, now()) + interval '12 seconds',   -- 5/dakika
       updated_at = now()
 WHERE user_id = $1
   AND GREATEST(tat, now()) - interval '60 seconds' <= now() -- burst penceresi
RETURNING tat;
-- 0 satır dönerse → limit aşıldı
```

Neden Redis değil de Postgres sorusunun üç cevabı vardır. Birincisi Postgres zaten senkron replike edilmektedir ve sayaç devralmada kaybolmamaktadır; Redis'te saniyelik ekleme günlüğüyle bile son bir saniye kaybolabilir ve replika yükseltmesinde sayaç geri gidebilir, yani saldırgan sayacı sıfırlamak için devralmayı tetiklemeye çalışabilir. İkincisi aynı işlemde kilitleme kararıyla birlikte yazılabilmesi ve tutarsızlık olmamasıdır. Üçüncüsü bir bağımlılığın daha az olması ve bunun birinci bölümdeki sektör yakınsamasıyla tutarlı olmasıdır.

Maliyet endişesi ile cevabı şudur: her giriş denemesinde bir yazma pahalı görünmektedir. Ancak Argus zaten giriş başına beş ile yedi yazma yapmaktadır, 3.1'e bakınız, ve Keycloak durumsuz modunda tam olarak bunu yapmaktadır, yani giriş başarısızlığı sayacını veritabanında tutmaktadır; ölçülmüş maliyeti etkileşim başına sekiz ile 10 milisaniyedir. Bu, Argon2id'nin kasten 100 ile 500 milisaniye olan maliyetinin yanında görünmezdir.

Redis'in kullanılacağı yer birinci katmanın küme geneli sürümüdür, yani IP başına küresel sınırdır, çünkü kaybı tolere edilebilirdir. Redis düşerse Argus yerel `governor` sınırlarına düşer; daha gevşek olur ancak çalışır.

### 5.5 Gerçek ölçümler: bulunanlar ile bulunamayanlar

| Ölçüm | Değer | Kaynak ile durum |
|---|---|---|
| redis-cell `CL.THROTTLE` gecikmesi | İstemciden yaklaşık 0,1 milisaniye, basit bir kümeleme işleminin yaklaşık iki katı | redis-cell README dosyası; yazar bunlara gayriresmî kıyaslamalar demektedir |
| Cloudflare'in milyonlarca alan adı için hız sınırlama mimarisi | — | Blog sayfası çekilebilmiş ancak içerik ayıklanamamıştır ve doğrulanamamıştır |
| Stripe ile Heroku'nun Redis ile Lua hız sınırlayıcı deneyimi | Niteldir: redis-cell yazarı bunu hem Heroku'da hem Stripe'ta gördüğünü söylemektedir ve naif implementasyonlar yaygındır | redis-cell README dosyası |
| Yerel ile periyodik senkronizasyonlu yaklaşık dağıtık sınırlayıcı üretim raporları | — | Bu araştırmada bulunamamış ile doğrulanamamıştır |

---

## Bölüm 6 — Ölçeklenme ve kapasite

### 6.1 Postgres N bağlantının üstünde çöker iddiası ile gerçek eğri

Bu sorunun en iyi cevabı PostgreSQL çekirdek katkıcısı Andres Freund'un, o dönem Microsoft'ta, yaptığı analizdir: 8 Ekim 2020 tarihli bağlantı ölçeklenebilirliği sınırları yazısı ile devamı olan anlık görüntü yazısı.

Ölçülmüş bulguları şunlardır.

| Bulgu | Değer | Koşul |
|---|---|---|
| Bağlantı başına bellek | İki mebibayttan azdır | Büyük sayfalar açık olduğunda. Yazarın sonucu bağlantı bellek ek yükünün kabul edilebilir olduğudur |
| Gecikmesiz yalnızca okuma pgbench zirvesi | Yaklaşık 48 istemci | 20 çekirdekli ile 40 iş parçacıklı bir iş istasyonunda, yerel makinede |
| 10 gigabit ethernet üzerinden, yakın makinelerde | Zirve yaklaşık 48'den yaklaşık 500 bağlantıya çıkmaktadır | Ağ gecikmesi eklendiğinde |
| Bir milisaniye ağ ile bir milisaniye uygulama işleme gecikmesi | Zirve yaklaşık 3.000 bağlantıdır | Aynı donanımda |
| Asıl darboğaz | Bellek değil anlık görüntü ölçeklenebilirliğidir, yani `GetSnapshotData()` | Boştaki bağlantılar bile her anlık görüntüde taranmaktaydı |
| PostgreSQL 14 düzeltmesi | Çok yüksek bağlantı sayılarında bile ölçeklenebilirlik sorununa dair az kanıt bulunmaktadır | Azure F72s_v2 sanal makinesinde öncesi ile sonrası ölçümüyle |

Bu üç rakam bir arada okunmalıdır ve çoğu ekibin yanlış anladığı yer burasıdır.

> Postgres 100 bağlantıdan sonra çöker ifadesi yanlıştır. Doğrusu şudur: aktif olarak, yani aynı anda sorgu çalıştıran bağlantı sayısı çekirdek sayısını çok aşarsa iş hacmi düşmektedir. Ancak gerçek uygulamalarda bağlantılar zamanın büyük kısmında boştadır, çünkü ağ gecikmesi ile uygulama işleme süresi vardır. Bir milisaniye ağ ile bir milisaniye işleme süresiyle zirve 3.000 bağlantıya çıkmaktadır.

PostgreSQL 14 öncesinde boştaki bağlantılar bile anlık görüntü alma maliyetini artırmaktaydı ve asıl çökme buydu. PostgreSQL 14 ve üstü, yani Argus'un hedeflediği 17 ile 18, bu problemi büyük ölçüde çözmüştür.

Argus için pratik sonuç şudur: `max_connections = 500` PostgreSQL 18'de tamamen makuldür. Yine de bir havuzlayıcı kullanılmalıdır, çünkü bağlantı kurma maliyeti, yani TLS, gecikme ile Postgres süreç çatallanması, hâlâ yüksektir.

### 6.2 Bağlantı, işçi ile havuz boyutu ilişkisi

Argus için, yani Rust, tokio ile asenkron yapı için, hesap şöyledir.

```
Argus node sayısı           : N
Node başına havuz boyutu    : P
Toplam DB bağlantısı        : N × P   (+ pooler varsa pooler→DB ayrı)
```

Rehber şudur.

| Parametre | Öneri | Gerekçe |
|---|---|---|
| Veritabanı işlemcisi başına aktif bağlantı | İki ile dört | Klasik formül çekirdek sayısının iki katı artı etkin iğ sayısıdır; NVMe'de iğ terimi sıfıra yakındır |
| Düğüm başına havuz | Sekiz ile 16 | Asenkron çalışma zamanında bir bağlantı çok istek servis etmektedir; büyük bir havuz yalnızca kuyruğu veritabanına taşır |
| Toplam bağlantının üst sınırı | Veritabanının azami bağlantı sayısının %70'i | Kalanı yönetici, replikasyon, yedekleme ile migration içindir |
| Ayrı havuz, kritik yol | Dört ile sekiz bağlantı, yüksek öncelikli | Token doğrulama ile içgözlem, uzun yönetici sorgularının arkasında kuyruğa girmemelidir |
| Ayrı havuz, yönetici ile rapor | İki ile dört, kısa zaman aşımıyla | Bir yönetici sorgusu giriş akışını asla aç bırakmamalıdır |
| Ayrı havuz, okuma replikası | Ayrı tutulur | Yalnızca 2.4'te izin verilen sorgular içindir |

Anti desen şudur: düğüm başına 100 bağlantılık bir havuz ile 20 düğüm 2.000 bağlantı demektir. Bu, veritabanında kuyruk oluşturmakta ile gecikmeyi görünmez kılmaktadır, çünkü istekler veritabanında beklemekte ancak uygulama metriklerinde hızlı görünmektedir. Doğrusu havuzu küçük tutmak, kuyruğu uygulamada tutmak ile kuyruk derinliğini bir metrik yapmaktır; bu, geri basınç ile yük atma için tek doğru yerdir.

### 6.3 Yatay ölçeklenmede neyin paylaşılması zorunludur

Bu, Argus'un mimarisinin özüdür.

| Durum | Paylaşım zorunlu mudur | Nerededir | Kaybı tolere edilir mi |
|---|---|---|---|
| JWKS ile imzalama anahtarları | Evet, aynı anahtar seti gerekir | Veritabanından okunur ile bellekte tutulur; rotasyon bir örtüşme penceresiyle yapılır | Hayır; ancak nadiren değişir ile önbeleklenebilir |
| Oturum | Evet | PostgreSQL | Hayır |
| Kimlik doğrulama oturumu, girişin ortası | Evet | PostgreSQL; Keycloak ikinci sürümünün yaptığıdır | Kullanıcı girişi baştan yapar; tolere edilebilir ancak kötü bir deneyimdir |
| Authorization code | Evet | PostgreSQL; tek kullanımlıktır ile yapışkan oturuma güvenilemez | Hayır; Rauthy'nin Raft'a ihtiyaç duymasının sebebi tam olarak budur |
| Yenileme token'ı ile rotasyon ailesi | Evet | PostgreSQL | Hayır; yeniden kullanım tespiti kırılır |
| İptal durumu ile iptal dönemi | Evet | Gerçeği PostgreSQL'de, hızı düğüm önbelleğindedir | Hayır |
| Kaba kuvvet ile hesap kilitleme sayacı | Evet, kesin olarak | PostgreSQL | Hayır, 5.3'e bakınız |
| DPoP `jti` yeniden oynatma listesi | Evet | Yaşam süreli Redis veya PostgreSQL | Kısmen; kayıp bir yeniden oynatma penceresi açar |
| Anlık istek nesnesi tanımlayıcısı | Evet | PostgreSQL | Hayır |
| Nonce ile state | Evet | Şifreli çerezle istemci tarafında tercih edilir, yoksa veritabanında | — |
| IP başına kaba hız limiti | Hayır, yaklaşık yeterlidir | Düğüme yerel `governor` | Evet |
| Realm, istemci ile politika metadata'sı | Hayır, önbeleklenebilir | Düğüme yerel önbellek ile giden kutusu geçersizleştirmesi | Evet, yeniden yüklenir |
| Kullanıcı profil verisi | Hayır | Veritabanından okunur | Evet |

Kritik gözlem şudur: bu listede paylaşılması zorunlu olan her şey PostgreSQL'de olabilir. Tek istisna DPoP `jti` değeridir ve o bile Postgres'te bölümlenmiş bir tablo ile agresif budamayla yapılabilir. Argus'un Redis'e mimari bir bağımlılığı olmamalıdır.

### 6.4 Soğuk başlangıç ile ısınma problemi

Yeni bir Argus düğümü önbeleksiz geldiğinde şunlar olur.

| Problem | Etki | Çözüm |
|---|---|---|
| Realm ile istemci önbelleği boştur | İlk isteklerde veritabanına N sorgu yapılır | Hazır olma yoklaması, önbellek doldurma tamamlanana kadar başarısız dönmelidir; düğüm yük dengeleyiciye erken girmemelidir |
| İptal dönemi önbelleği boştur | Her token doğrulamasında bir veritabanı sorgusu yapılır ile veritabanında ani yük oluşur | 4.5.1'deki senkronize olma zamanı deseni kullanılır: düğüm başlarken son bir saatin iptal kümesini tek bir sorguyla çeker, sonra giden kutusuna takılır. Bu, kullanıcı başına sorgu yerine tek bir sorgudur |
| JWKS yüklenmemiştir | İmzalama başarısız olur | Başlangıçta zorunlu yükleme yapılır ile başarısızsa süreç başlamaz |
| Bağlantı havuzu boştur | İlk isteklerde TLS ile kimlik doğrulama el sıkışması yapılır | Havuz asgari bağlantı ayarıyla önceden doldurulur |
| Gürleyen sürü | Aynı anda 10 düğüm başlarsa veritabanına 10 kat ısınma yükü biner | Başlangıçta sıfır ile beş saniye arası rastgele bir sapma ile yuvarlanan dağıtım kullanılır |

Keycloak'ın aynı problemi vardır: kıyaslama raporu önbellek boyutunu 10.000'den 200.000 girdiye çıkarmanın Aurora tepe işlemcisini %77,77'den %63,77'ye düşürdüğünü ölçmüştür. Yani önbellek eksikliği doğrudan veritabanı işlemcisine yansımaktadır ile soğuk bir düğüm kalıcı olarak sıfır önbellek demektir. Bu yüzden hazır olma kapısı şarttır.

---

## Bölüm 7 — Felaket senaryoları ve kademeli bozulma

### 7.1 Kademeli bozulma matrisi, Argus tasarımı

Bu matris Argus'un açık bir tasarım kararı olarak uygulanmalıdır; varsayılan bir davranış değildir.

| Senaryo | Giriş | Token yenileme | JWT doğrulama | İçgözlem | Yönetim API'si | Kullanıcı kaydı |
|---|---|---|---|---|---|---|
| Normal | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır |
| Veritabanı birincili düştü, devralma sürüyor, 0 ile 30 saniye | 503 döner | 503 ile yeniden dene döner, asla `invalid_grant` dönmez | Çalışır | Dönem önbeleğinden çalışır, bayatlık riski vardır | Durur | Durur |
| Veritabanı tamamen erişilemez, dakikalar | Durur | Durur | Çalışır, bozulmuş modda | Yalnızca önbellekten çalışır ve yaşam süresi sonrası kapalı başarısız olur | Durur | Durur |
| Dağıtık yapılandırma deposu kaybı, Postgres salt okunur | Durur | Durur | Çalışır | Çalışır, okuma çalışmaktadır | Salt okunur çalışır | Durur |
| Okuma replikası kaybı | Çalışır | Çalışır | Çalışır | Çalışır | Yavaşlar, birincile düşer | Çalışır |
| Redis ile Valkey kaybı | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır, çünkü Redis kritik yolda değildir |
| Üç erişilebilirlik alanından birinin kaybı | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır | Çalışır |
| İki erişilebilirlik alanı kaybı, yani quorum kaybı | Durur | Durur | Çalışır | Bayatlık riskiyle çalışır | Durur | Durur |
| Bölge tamamen kayboldu | Hücre modelinde diğer hücreler etkilenmez | | | | | |

### 7.2 Bozulmuş mod: veritabanı düştüğünde token doğrulamaya devam etmek

Bu mümkün müdür sorusunun cevabı evettir ve Argus'un en değerli farklılaştırıcısı olabilir. Ancak sınırları net olmalıdır.

Neden mümkün olduğu şudur: JWT imza doğrulaması veritabanı gerektirmez. Gereken tek şeyler açık anahtardır, ki bellektedir; sona erme ile geçerlilik başlangıcıdır, ki token'ın içindedir; ile iptal dönemidir, ki düğüm önbeleğindedir.

Tehlike şudur: önbellek bayatladıkça iptal edilmiş token'ları kabul etme olasılığı artmaktadır. Sonsuza kadar bozulmuş mod bir güvenlik açığıdır.

Argus'un uygulaması bozulmuşken bayat kullanma penceresidir.

```
DB erişilemez süresi:
  0 – 60 sn   : Tam degraded mode. JWT doğrulama epoch cache'iyle devam.
                Metrik: argus_degraded_mode=1, alarm tetiklenir.
  60 – 300 sn : Uyarı modu. Doğrulama devam ama her yanıta
                `X-Argus-Degraded: true` header'ı; introspection
                yanıtında `active:true` ama düşük güven işareti.
  > 300 sn    : FAIL-CLOSED. Introspection 503 döner.
                Self-contained JWT doğrulaması (RS/RP tarafında) hâlâ
                geçerlidir — Argus bunu engelleyemez, bu yüzden
                kısa access token ömrü tek gerçek koruma.
```

Kritik gerçek şudur: Argus, kaynak sunucuların JWT'yi yerel olarak doğrulamasını engelleyemez. Bu nedenle bozulmuş modun gerçek güvenlik sınırı access token ömrüdür. Beş dakikalık bir access token en kötü durumda beş dakikalık bir maruziyet demektir. Bu, kısa token ömrünün en güçlü tek gerekçesidir ile bozulmuş mod tasarımının ön koşuludur.

### 7.3 Redis ile Valkey düşerse

Argus'un önerilen mimarisinde Redis kritik yolda değildir, bu yüzden cevap kısadır: sistem yerel `governor` sınırlarına düşer, kaba hız sınırlaması gevşer ile hiçbir güvenlik kararı bozulmaz.

Eğer Redis kritik yola konulursa, ki bu bir tasarım hatasıdır ancak yaygındır, kaybının anlamı şudur. Oturum Redis'teyse tüm kullanıcılar çıkış yapar. İptal listesi Redis'teyse iptal kontrolü açık mı kapalı mı başarısız olacaktır sorusu doğar; açık başarısızlık bir güvenlik açığı, kapalı başarısızlık tam bir kesintidir ve ikisi de kötüdür. Hız limiti Redis'teyse ve açık başarısız oluyorsa kimlik bilgisi doldurma penceresi açılır.

Bu, Argus'un Redis'i bir doğruluk kaynağı yapmama kararının tek gerekçesidir.

### 7.4 Bir bölge tamamen kaybolursa

| Topoloji | Sonuç | Kurtarma süresi hedefi | Kurtarma noktası hedefi |
|---|---|---|---|
| Tek bölge, felaket kurtarma yok | Tam kesintidir | Yedekten geri yükleme süresidir | Son yedektir |
| Tek bölge ile asenkron bölgeler arası bekleme düğümü | Elle ya da otomatik yükseltme yapılır | Dakikalardır | Replikasyon gecikmesi kadar veri kaybıdır |
| İki bölge aynı coğrafi bölgede, Keycloak ikinci sürümü | Bölge kaybı kapsanmaz, çünkü ikisi de aynı bölgededir | — | — |
| Hücre başına bölge, Okta modeli | Yalnızca o hücredeki kiracılar etkilenir | Hücrenin felaket kurtarması kadardır | Hücrenin felaket kurtarması kadardır |
| CockroachDB, bölge hayatta kalma hedefiyle, üç ve üzeri bölgede | Otomatiktir ile kesintisizdir | Yaklaşık sıfırdır | Sıfırdır |

Argus için gerçekçi cevap şudur: bölge kaybını sıfır kurtarma noktası hedefiyle tolere etmek yalnızca CockroachDB sınıfı bir veritabanı ya da Aurora DSQL ile mümkündür ve bunun bedeli üçüncü bölümde sayılan gecikme, karmaşıklık ile lisans maliyetidir.

Pragmatik orta yol bölgeler arası asenkron bir bekleme düğümü ile açıkça belgelenmiş bir kurtarma noktası hedefidir. Bir IdP için son N saniyenin yazmalarını kaybedebiliriz demek, bölge kaybı gibi felaket bir olayda birkaç saniyelik parola değişikliği kaybını kabul ediyoruz demektir; bu, tam bir kesintiye tercih edilebilir bir takastır, ancak karar bilinçli verilmeli ile dokümante edilmelidir. Felaket sonrası prosedür şudur: yükseltmeden hemen sonra tüm dönemler küresel olarak artırılır, yani herkes çıkarılır; kaybolmuş bir iptali kaçırmaktansa herkesi yeniden giriş yaptırmak doğrudur.

### 7.5 Acil durum erişimi, dağıtık mimaride

Problem şudur: Argus kendi altyapısının kimlik doğrulamasını da yapıyorsa, Argus çöktüğünde operatörler Argus'u düzeltmek için giriş yapamaz. Bu klasik bir döngüsel bağımlılıktır ile gerçek kesintilerin uzamasının bir numaralı sebebidir.

Argus için tasarım ilkeleri şunlardır.

| İlke | Uygulama |
|---|---|
| 1. Acil durum yolu normal yoldan bağımsız bir kod yolu olmalıdır | Ayrı bir endpoint, yani `/break-glass`, ile ayrı bir doğrulama fonksiyonu kullanılır ve normal kimlik doğrulama boru hattının hiçbir parçası, yani hız sınırlayıcı, risk motoru ile çok adımlı doğrulama orkestratörü, çağrılmaz |
| 2. Bağımlılık zinciri asgari olmalıdır | Yalnızca yerel diskten ya da ortam değişkeninden okunan bir açık anahtar ile saat kullanılır; veritabanına, Redis'e ya da harici bir IdP'ye bağımlı olunmaz |
| 3. Kimlik donanım anahtarıyla ve çevrimdışı doğrulanabilir olmalıdır | Acil durum kimlik bilgileri önceden dağıtılmış FIDO2 anahtarlarının açık anahtarları ya da çevrimdışı imzalanmış, kısa ömürlü bir yetki belgesidir, yani N kişiden M imzasıdır. Her düğümün yapılandırmasında bulunur |
| 4. Yerel doğrulanabilirlik olmalıdır | Düğüm, acil durum token'ını hiçbir ağ çağrısı yapmadan doğrulayabilmelidir |
| 5. Yetki kısıtlı olmalıdır | Acil durum yolu yalnızca operasyonel işlemler yapabilmelidir, yani yapılandırma okuma, sağlık kontrolü, özellik bayrağı ile dönem sıfırlama; kullanıcı verisi okuma ya da değiştirme yapılmamalıdır |
| 6. Zorunlu ile silinemez bir iz olmalıdır | Kullanım anında yerel bir dosyaya, sistem günlüğüne ile erişilebiliyorsa harici bir güvenlik bilgi ve olay yönetimi sistemine yazılır. Argus'un kendi denetim tablosuna güvenilemez, çünkü veritabanı düşmüş olabilir |
| 7. Otomatik alarm olmalıdır | Kullanım anında tüm nöbetçilere bildirim gider ile sessiz bir acil durum erişimi olmamalıdır |
| 8. Kısa ömürlü ile tek kullanımlık olmalıdır | Belge 15 dakika geçerlidir ile kullanımdan sonra rotasyon zorunludur |
| 9. Düzenli tatbikat yapılmalıdır | Çeyrekte bir test edilmeyen bir acil durum yolu çalışmayan bir acil durum yoludur. Bu teknik değil bir süreç gereksinimidir |
| 10. Hücre başına ayrı olmalıdır | Her hücrenin kendi acil durum kimlik bilgisi vardır ile birinin sızması diğerlerini etkilemez |

Anti desen acil durum yönetici hesabıdır: veritabanında duran ile parolası kasada olan bir kullanıcı. Veritabanı düştüğünde işe yaramaz ile normal zamanda kalıcı bir saldırı yüzeyidir.

---

## Bölüm 8 — Argus için net topoloji önerisi

### 8.1 Birinci aşama: tek bölge, üç erişilebilirlik alanı ile sıkı tutarlılık

```
                    ┌────────────────────────┐
                    │   Global LB / Anycast  │
                    └───────────┬────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
   ┌────▼─────┐           ┌─────▼────┐           ┌──────▼───┐
   │  AZ-a    │           │   AZ-b   │           │   AZ-c   │
   │ Argus×2  │           │ Argus×2  │           │ Argus×2  │  ← stateless Rust
   │          │           │          │           │          │
   │ pgcat    │           │ pgcat    │           │ pgcat    │  ← pooler (sidecar)
   └────┬─────┘           └─────┬────┘           └──────┬───┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
              ┌─────────────────▼──────────────────┐
              │  PostgreSQL 18 (Patroni / CNPG)    │
              │  primary(AZ-a) ─┬─ sync standby(b) │
              │                 └─ sync standby(c) │
              │  synchronous_commit = on           │
              │  synchronous_standby_names =       │
              │      'ANY 1 (sb_b, sb_c)'          │
              │  + async replica (raporlama)       │
              │  + cross-region async DR standby   │
              └────────────────────────────────────┘
                                │
              ┌─────────────────▼──────────────────┐
              │  etcd × 3 (her AZ'de bir)          │
              │  DCS Failsafe Mode: ON             │
              └────────────────────────────────────┘
```

Yapılandırma kararları şunlardır.

| Karar | Değer | Gerekçe |
|---|---|---|
| `synchronous_commit` | `on` | Veri kaybı olmaz, 2.2.3'e bakınız |
| `synchronous_standby_names` | `ANY 1 (sb_b, sb_c)` | Bir bekleme düğümünün kaybını tolere eder ile birincil asılmaz |
| Denetim yazmaları | Oturum seviyesinde `synchronous_commit = local` | Giriş çıkış işlemi tasarrufu sağlar ile güvenlik etkisi yoktur |
| Patroni | Yaşam süresi 20, döngü bekleme beş, yeniden deneme zaman aşımı beş ile gözcü | Yaklaşık 25 saniyelik devralma |
| Dağıtık yapılandırma deposu güvenli modu | Açık | etcd kaybı salt okunur demektir, tam kesinti değil |
| Birincil anahtarlar | PostgreSQL 18'in `uuidv7()` fonksiyonu | İndeks şişmesi ile günlük hacmi için |
| Uçucu durum | Tamamı PostgreSQL'dedir | Keycloak ikinci sürümü, authentik ile Ory yakınsamasıdır |
| Redis ile Valkey | Birinci sürümde hiç yoktur | Bağımlılık azaltmadır; sonradan opsiyonel bir hızlandırıcı olur |
| İptal yayını | Giden kutusu tablosu ile 100 milisaniyelik yoklama; `NOTIFY` hızlandırması kullanılmaz ile imleç algoritması açık bir karardır | 4.3 ile §1'in 10.2 bölümü |
| İptal modeli | Kullanıcı başına monoton iptal dönemi sayacı ile düğüm önbelleği | 4.5 |
| Hız sınırlaması | Kaba sınır için yerel `governor`, hesap başına için PostgreSQL atomik güncellemesi | 5.4 |
| Havuz | Düğüm başına sekiz ile 16; ayrı havuzlar kritik, yönetici ile replika içindir | 6.2 |
| Okuma replikası | Yalnızca yönetici araması, raporlama ile denetim izi görüntüleme için | 2.4.1'deki tablo |
| Access token ömrü | Beş dakika | Bozulmuş modun güvenlik sınırıdır, 7.2 |

Bu topolojinin karşıladıkları erişilebilirlik alanı kaybı, ki kesintisizdir; düğüm kaybı, ki kesintisizdir; veritabanı birincilinin kaybı, ki yaklaşık 25 saniye sürer, veri kaybı yoktur ile token doğrulama kesilmez; ile etcd kaybıdır, ki salt okunur bir bozulmadır.

Karşılamadığı bölge kaybıdır; asenkron felaket kurtarmayla kurtarma noktası hedefi sıfırdan büyüktür ile kurtarma süresi dakikalardır.

### 8.2 İkinci aşama: iki küme, tek bölge, Keycloak Multi-Cluster v2 deseni

Yalnızca iki bağımsız Kubernetes ya da dağıtım alanı gerekiyorsa, örneğin aynı metropolde farklı veri merkezleri varsa, şu yapılır.

İki bağımsız Argus kümesi ile senkron replike edilmiş tek bir mantıksal veritabanı, yani Patroni'nin çok veri merkezli kurulumu ya da Aurora, kullanılır. Bölgeler arası veritabanı gidiş dönüşü beş milisaniyenin altında hedeflenir ile 10 milisaniyelik bir tavan konur; bu Keycloak'ın doğrulanmış eşiğidir. Kümeler arası geçersizleştirme aynı giden kutusu tablosuyla yapılır ile hiçbir ek altyapı gerekmez. Yük dengeleyici `/lb-check` benzeri bir sağlık uç noktasıyla bölge devralması yapar.

Beklenen maliyet, ki Keycloak'ın ölçtüğüdür ile Argus için de geçerli olması muhtemeldir, etkileşim başına sekiz ile 10 milisaniye ek gecikme ile veritabanı işlemcisi ve giriş çıkış işlemlerinde yaklaşık iki kat artıştır.

### 8.3 Üçüncü aşama: hücre başına bölge, Okta modeli

Çok bölgeli bir gereksinim ortaya çıktığında bu veri replikasyonuyla değil izolasyonla çözülür.

```
  ┌── control plane (küçük, global) ────────────────┐
  │  tenant → hücre haritası; DNS/routing            │
  │  cache'lenebilir, nadiren değişir                │
  └──────────────┬───────────────┬──────────────────┘
                 │               │
       ┌─────────▼──────┐ ┌──────▼─────────┐ ┌──────────────┐
       │ HÜCRE: eu-c1   │ │ HÜCRE: us-e1   │ │ HÜCRE: tr-1  │
       │ tam Argus v1   │ │ tam Argus v1   │ │ tam Argus v1 │
       │ kendi Postgres │ │ kendi Postgres │ │ kendi PG     │
       │ kendi etcd     │ │ kendi etcd     │ │ kendi etcd   │
       │ kendi break-   │ │ kendi break-   │ │ kendi break- │
       │   glass        │ │   glass        │ │   glass      │
       └────────────────┘ └────────────────┘ └──────────────┘
              ↑ HÜCRELER ARASI VERİ REPLİKASYONU YOK
```

Kazanımları şunlardır: veri yerleşimi yapısal olarak çözülür, yani GDPR, KVKK ile veri yerelleştirme gereksinimleri karşılanır; hata izolasyonu sağlanır ve bir hücrenin çökmesi diğerlerini etkilemez; bölgeler arası konsensüs maliyeti sıfırdır, çünkü her hücre içinde tek bölge vardır; ölçekleme doğrusal ile tahmin edilebilirdir, çünkü kapasite eklemek hücre eklemektir; ve Türkiye'nin ödeme ile elektronik para kuruluşları için verinin yurt içinde tutulması gereksinimi doğal olarak karşılanır.

Bedelleri şunlardır: N hücre N operasyonel yüzey demektir ile otomasyon zorunludur, yani GitOps ile tek bir şablon gerekir; kiracılar hücreler arasında taşınamaz veya taşıma ayrı bir projedir; küresel kullanıcı, yani birden çok hücrede aynı kişi, desteklenmez ya da kontrol düzleminde federe bir kimlik referansıyla çözülür, ki Ory'nin veri yurtlandırma yaklaşımıdır; ve kontrol düzlemi yeni bir kritik bileşendir, kendisi yüksek erişilebilir olmalı ile hücrelerin çalışması için gerekli olmamalıdır, yalnızca yönlendirme için kullanılmalıdır.

### 8.4 Ne yapılmamalıdır, Argus için kırmızı çizgiler

| Yapılmaz | Neden |
|---|---|
| Redis yayın aboneliğiyle iptal yayını | En fazla bir kez teslimat vardır ve Redis dokümanı mesajın sonsuza kadar kaybolduğunu söylemektedir |
| İptal, oturum ile kilit sorgularını okuma replikasına yönlendirmek | Bayat okuma bir güvenlik açığıdır, 2.4.1; Zitadel bu yüzden replikayı hiç desteklememektedir |
| Postgres mantıksal replikasyonuyla aktif aktif | Son yazan kazanır çakışma çözümü kimlikte bir güvenlik açığıdır; Kanidm dersidir |
| Kanidm tarzı quorum'suz çok birincilli yapı | Aynı sebeptir |
| Kıtalar arası senkron yazma | Keycloak 26.3'te 20 milisaniyelik gidiş dönüşte 99. yüzdelik 1.076 milisaniyedir |
| Tek bekleme düğümüyle `synchronous_commit=on` | Bekleme düğümü düşünce birincil asılır ile yüksek erişilebilirlik çözümü bir kesinti kaynağı olur |
| Infinispan ya da Hazelcast tarzı gömülü dağıtık önbellek | Keycloak 2026'da bu yoldan geri dönmüştür |
| Düğüm başına bağımsız hesap bazlı hız limiti | Yatay ölçekleme bir güvenlik zafiyetine dönüşmektedir, 5.3 |
| Bloom filtresi tabanlı iptal listesi | İptal dönemi aynı işi sıfır hatayla yapmaktadır ile doğrulanmış bir üretim örneği yoktur |
| Veritabanında duran acil durum yönetici hesabı | Veritabanı düştüğünde işe yaramaz ile sürekli bir saldırı yüzeyidir |
| Yenileme devralmasında `400 invalid_grant` dönmek | İstemci SDK'ları kullanıcıyı çıkarmaktadır; 503 ile yeniden dene kullanılmalıdır |

---

## Bölüm 9 — Kaynaklar

### 9.1 Birinci elden çekilip okunanlar, erişim 8 Eylül 2026

**Keycloak.** Ekim 2025 tarihli 26.4 performans kıyaslamaları yazısı, ki tüm kapasite ile gidiş dönüş rakamları oradandır. Alexander Schwartz'ın 17 Temmuz 2026 tarihli Multi-Cluster v2 ile stateless önizleme yazısı, ki sekiz ile 10 milisaniye, iki kat veritabanı, beş ile 10 milisaniyelik eşikler ile 100 milisaniyelik giden kutusu yoklaması oradandır. Çok kümeli dağıtım kavramları sayfası, ki iki bölge sınırı, elle yeniden senkronizasyon ile iki dakikanın altında kurtarma oradandır. Aralık 2024 tarihli Keycloak 26'da oturum saklama yazısı, ki kalıcı kullanıcı oturumları anlatılmaktadır. Keycloak blog dizini, ki sürüm takibi için kullanılmıştır, 26.7.3, 31 Ağustos 2026.

**Zitadel.** Florian Forster'ın 12 Şubat 2026 tarihli önbeleklemeyle performans optimizasyonu yazısı, ki saniyede 30 binden fazla istek ile hibrit ilişkisel modele geçiş oradandır. 7636 numaralı tartışma, ki okuma replikası reddi oradandır. Yazılım mimarisi dokümanı, ki komut sorgu sorumluluk ayrımı ile nihai tutarlılık oradandır.

**Kanidm.** Replikasyon tasarım notları, ki erişilebilirlik tercihi, değişiklik kimliği, replika güncelleme vektörü, mezar taşı ile dondurma oradandır. 4099 numaralı tartışma, ki üç düğümün teknik olarak desteklenmediği oradandır.

**Rauthy ile Hiqlite.** Rauthy yüksek erişilebilirlik yapılandırması, ki üç ile beş replika ile 15 ile 30 saniyelik kapanma oradandır. `hiqlite` crate'i ile deposu, ki saniyede 24,5 bin ile 16,5 bin ekleme oradandır. `openraft` deposu, ki genelleştirilmiş üyelik değişimi oradandır.

**Ory.** 3134 numaralı tartışma, ki 230 milisaniyelik birincil anahtar araması, yaklaşık bir saniyelik ek gecikme ile küresel tablo ve GDPR çelişkisi oradandır. Bölgeler arası küresel kimlik ile erişim yönetimi yazısı, ki veri yurtlandırması ile günde üç milyar istek oradandır. Ory ile CockroachDB ortak yazısı, ki pazarlama içeriklidir.

**authentik.** Mimari sayfası, sürüm 2026.8. 2025.8 sürüm notları, ki Redis'ten çıkış oradandır.

**PostgreSQL.** PostgreSQL 18.0 sürüm notları, Eylül 2025, ki asenkron giriş çıkış, `uuidv7()`, `idle_replication_slot_timeout` ile devralma yuvaları oradandır. PostgreSQL 18 libpq bağlantı dizeleri dokümanı, ki `target_session_attrs` ile `load_balance_hosts` oradandır. Andres Freund'un 8 Ekim 2020 tarihli bağlantı ölçeklenebilirliği analizi, ki bağlantı başına iki mebibayttan az ile 48'den 500'e ve 3.000'e çıkan zirve oradandır. Aynı yazarın anlık görüntü yazısı, ki PostgreSQL 14 düzeltmesi oradandır. EDB'nin senkron replikasyon maliyeti yazısı, ki 9,5'ten 16'ya ile 17'den 20 milisaniyeye tablosu oradandır. Percona'nın `synchronous_commit` seçenekleri yazısı, ki `off` ile `remote_apply` arasındaki iki kat oradandır. Patroni 4.1.5 sıkça sorulan sorular, ki lider yarışı ile dağıtık yapılandırma deposu kaybında salt okunur ve düşürme oradandır. Patroni dinamik yapılandırma dokümanı, ki yaşam süresi formülü oradandır. CloudNativePG 1.28 arıza modları, ki birincil ile bekleme arıza akışı oradandır. Tembo'nun bağlantı havuzlayıcı kıyaslaması, ki PgBouncer, pgcat ile Supavisor karşılaştırması oradandır.

**Dağıtık SQL.** CockroachDB takipçi okumaları dokümanı, ki en az 4,2 saniyelik bayatlık oradandır. Çok bölgeli genel bakış, ki hayatta kalma hedefleri ile tablo yerleşimleri oradandır. Çok bölgeli yapılandırma seçme rehberi, ki `--max-offset 250ms` oradandır. Lisanslama sıkça sorulan sorular, ki 10 milyon doların altı ciroyla ücretsizlik, zorunlu telemetri ile yedi günde kısıtlama oradandır. Amazon Aurora DSQL nedir dokümanı, ki erişilebilirlik oranları ile kıtalar arası olmayışı oradandır. PostgreSQL'den Aurora DSQL'e geçiş dokümanı, ki iyimser eşzamanlılık kontrolü, 3.000 satır, PL/pgSQL yokluğu ile bir saatlik bağlantı oradandır.

**Mesajlaşma ile hız sınırlama.** Redis yayın aboneliği teslimat semantiği, ki sonsuza kadar kaybolur ifadesi oradandır. NATS JetStream dokümanı, ki çekirdeğin en fazla bir kez, JetStream'in en az bir kez olduğu oradandır. redis-cell deposu, ki GCRA, yaklaşık 0,1 milisaniye ile elden gelenin en iyisi bakım modu oradandır. `governor` 0.10.4 dokümanı, 5 Eylül 2026, ki GCRA ile süreç içi olduğu oradandır.

**Kurumsal mimariler.** Okta'nın 50 milyar kullanıcıya ölçekleme ile ölçeklenebilir altyapı inşa etme beyaz kâğıtları, ki hücre tabanlı mimari oradandır.

### 9.2 İkincil ile düşük otoriteli kaynaklar, dikkatle kullanılmalıdır

Patroni devralma süresinin 25 saniyenin altında olduğu iddiası stackharbor.com bilgi bankasındandır, 2026.

İptal dönemi performans rakamları, yani 0,3 milisaniye, 0,05 milisaniye ile 0,2 milisaniye, michal-drozd.com, techinterview.org ile oneuptime.com bloglarındandır; bağımsız doğrulanmamıştır ile bir planlama girdisi olarak kullanılmamalıdır.

Patroni, repmgr ile pg_auto_failover'ın 2026 karşılaştırması Tomasz Gintowt'un Temmuz 2026 tarihli Medium yazısındandır.

### 9.3 Doğrulanamayanlar listesi, açıkça işaretlenenler

| Konu | Durum |
|---|---|
| CloudNativePG'nin CNCF olgunluk seviyesi | Doğrulanamamıştır |
| Stolon'un arşiv durumu | Doğrulanamamıştır |
| pg_auto_failover'ın 2026 bakım durumu | Doğrulanamamıştır |
| AWS bölgeler arası kesin gidiş dönüş rakamları | Doğrulanamamıştır; cloudping.co çekilememiştir |
| Erişilebilirlik alanları arası kesin gidiş dönüş, yani bir ile iki milisaniye iddiası | Doğrulanamamıştır |
| CockroachDB'de gidiş dönüşün 150 milisaniyeyi aşmasıyla küresel tabloda düzensiz gecikme | Arama özetindendir; doğrudan doküman sayfası doğrulanmamıştır |
| Auth0'ın 2026 tarihli mimari yazısı ile bölgesel kiracı modeli detayı | Bulunamamıştır |
| Google ile Cloudflare Access'in kimlik doğrulama mimarisi yazıları | Bulunamamıştır |
| YugabyteDB'nin kimlik iş yükü için bağımsız kıyaslaması | Bulunamamıştır |
| Bloom ya da guguk filtresiyle token iptalinin üretim örneği | Bulunamamıştır |
| Cloudflare'in dağıtık hız sınırlama mimarisi detayı | Sayfa çekilmiş ancak içerik ayıklanamamıştır |
| Yerel ile periyodik senkronizasyonlu dağıtık hız sınırlama üretim raporları | Bulunamamıştır |
| PgBouncer 1.21 ve üstündeki isimli hazırlanmış ifade desteğinin sqlx ile uyumu | Doğrulanamamıştır |
| `sqlx`'in `target_session_attrs` çok sunuculu desteği | Doğrulanamamıştır |
| PostgreSQL 19 içeriği ile takvimi | Doğrulanamamıştır |
| Argus'un giriş akışındaki yazma sayısı, yani beş ile yedi | Bir mimari tahmindir ve ölçülmemiştir |
| Rust'ın Keycloak'a göre yenileme yolu avantajı tahmini | Bir tahmindir ve ölçülmemiştir |

### Ek: bir sonraki araştırma için açık kalan sorular

1. AWS ile GCP'nin bölgeler arası ile erişilebilirlik alanları arası gerçek gidiş dönüş matrisi; Argus'un çok bölge kararının sayısal temeli için gereklidir.
2. Auth0 ile Cloudflare Access'in yayımlanmış mimarisi; bu oturumda bulunamamıştır ve Okta'nın beyaz kâğıtları tek somut kurumsal referanstır.
3. YugabyteDB'nin kimlik iş yükünde bağımsız ölçümü; CockroachDB'ye tek gerçek açık alternatiftir ancak veri yoktur.
4. Bir Rust IdP prototipiyle gerçek bir kıyaslama; Keycloak'ın sanal işlemci başına saniyede 15 giriş rakamına karşı Argus'un gerçek değeri. Bu, tüm kapasite planlamasının temelidir ile şu an yalnızca bir tahmindir.
5. Giden kutusu yoklamasının 20 ve üzeri düğümde veritabanı üzerindeki ölçülmüş maliyeti; 100 milisaniyelik yoklamanın gerçek sorgu hızı ile işlemci etkisi.
