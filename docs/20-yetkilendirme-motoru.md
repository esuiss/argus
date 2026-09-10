# 20. Yetkilendirme motoru

> `ARGUS.md` §20'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§20 §X` referansları aynı anlamda.



### 0. YÖNETİCİ ÖZETİ — ÖNCE ÜÇ DÜZELTME

**(1) "2,6 µs/karar" referansı gerçek ama yanıltıcı.** arXiv:2609.00267 mevcut: *"Delegation Without Trust: An Empirical Gap Analysis of Identity, Authorization, and Runtime Governance in Multi-Agent LLM Systems"*, Dantuluri & Sundi, 31 Ağustos 2026 (cs.CR). Ancak PDF'ten çıkardığım metodoloji şu:

> "We implement the broker in Python (∼160 lines, standard library only). Tokens are HMAC-signed in the style of macaroons and OAuth Token Exchange"
> "Enforcement costs ∼2.6µs per authorization (∼3.9×10⁵ decisions/s) and a token exchange ∼5.4µs, measured over 2×10⁵ calls each on a laptop."

Bu **ReBAC graph çözümlemesi değil** — bir capability token'ın caveat'lerinin HMAC ile doğrulanmasıdır. Grafik yürüyüşü, veritabanı okuması, ilişki çözümlemesi yok. 160 satırlık Python'un 2,6 µs'de yaptığı iş, OpenFGA/SpiceDB'nin yaptığı işin **aynı problem sınıfı değildir**. Bu rakamı Argus'un ReBAC check hedefi olarak almak kategori hatası olur. Doğru okuma: *"yetki token'a gömülüyse doğrulama neredeyse bedava"* — ki bu Argus için gerçekten kullanışlı bir mimari sinyaldir (bkz. Bölüm 4.5).

**(2) "1-10 ms" iddiasının gerçek kaynağı Zanzibar makalesidir ve koşulları çok spesifiktir.** Google'ın kendi rakamı: Check Safe p95 = 9,46 ms. Ama bu, zookie'si 10 saniyeden eski olan istekler içindir. Zookie'si taze olan ("Recent") isteklerde p95 = **60,0 ms**. Yani "10 ms" rakamı, tutarlılıktan feragat edilmiş yoldur.

**(3) OpenFGA'nın CVE sicili ciddi bir risk sinyalidir.** OSV'den çektiğim kayıtlara göre OpenFGA'nın **26 güvenlik danışmanlığı** var ve bunların çoğu doğrudan **authorization bypass** sınıfında. Sadece 2026'da 7 tane. Bu, bir IdP'nin sıcak yoluna gömülecek bileşen için hafife alınacak bir istatistik değil.

**Kararım kısaca:** Argus **kendi ReBAC motorunu Rust'ta yazmalı**, harici motora bağımlı olmamalı; dış dünyaya **AuthZEN PDP** olarak konuşmalı; token'a gömme ile merkezî check'i **açıkça iki ayrı katman** olarak sunmalı. Gerekçeler Bölüm 7'de.

---

## BÖLÜM 1 — ZANZIBAR VE TÜREVLERİ

### 1.1 Zanzibar makalesi (USENIX ATC 2019) — birincil kaynaktan

Makaleyi indirip metnini çıkardım. Aşağıdakiler makalenin kendi ifadeleridir.

#### Relation tuple grameri

```
⟨tuple⟩   ::= ⟨object⟩ '#' ⟨relation⟩ '@' ⟨user⟩
⟨object⟩  ::= ⟨namespace⟩ ':' ⟨object id⟩
⟨user⟩    ::= ⟨user id⟩ | ⟨userset⟩
⟨userset⟩ ::= ⟨object⟩ '#' ⟨relation⟩
```

Birincil anahtar: `⟨namespace⟩, ⟨object id⟩, ⟨relation⟩, ⟨user⟩`. `⟨user id⟩` bir **integer** (Google'ın iç kullanıcı ID'si), `⟨object id⟩` bir string.

Kritik tasarım kararı, makalenin kendi cümlesiyle: *"Defining our data model around tuples, instead of per-object ACLs, allows us to unify the concepts of ACLs and groups and to support efficient reads and incremental updates."* — ACL ile grup **aynı şeydir**. Grup, üyelik semantiği taşıyan bir ACL'dir. Argus için doğrudan aktarılabilir bir ilke.

#### New enemy problem — makaledeki tam iki örnek

Makale bunu iki senaryoyla tanımlıyor:

> **Example A: Neglecting ACL update order**
> 1. Alice removes Bob from the ACL of a folder;
> 2. Alice then asks Charlie to move new documents to the folder, where document ACLs inherit from folder ACLs;
> 3. Bob should not be able to see the new documents, but may do so if the ACL check neglects the ordering between the two ACL changes.

> **Example B: Misapplying old ACL to new content**
> 1. Alice removes Bob from the ACL of a document;
> 2. Alice then asks Charlie to add new contents to the document;
> 3. Bob should not be able to see the new contents, but may do so if the ACL check is evaluated with a stale ACL from before Bob's removal.

Çözüm için **iki** özellik gerekiyor (makale bunu "two key consistency properties" diye adlandırıyor):
1. **External consistency** — nedensel olarak ilişkili x ≺ y güncellemeleri Tx < Ty timestamp alır.
2. **Snapshot reads with bounded staleness** — check'in değerlendirme snapshot'ı, içerik güncellemesine atanan nedensel timestamp'ten daha eski olamaz.

Zanzibar bunu Spanner'ın **TrueTime**'ı üzerine kuruyor: *"Zanzibar builds on Spanner's TrueTime abstraction to provide linearizable commit timestamps encoded as zookies."*

**Neden TTL'li cache bunu çözemez:** Problem tazelik değil, **nedensellik**. 10 saniyelik TTL, Bob'un çıkarılmasından 200 ms sonra eklenen belgeyi korumaz — çünkü sorun sürenin uzunluğu değil, iki olayın sırasının kaybolmasıdır. Zookie, istemcinin "bu içerik şu andan sonra yazıldı, o yüzden ACL'i de en az o andan itibaren oku" diyebilmesini sağlar. Bu, uygulamanın zookie'yi **korunan kaynağın yanında saklamasını** gerektirir — yani zookie sadece bir motor özelliği değil, bir **uygulama sözleşmesidir**.

#### Leopard indeksleme sistemi

Devreye girme koşulu makalede net: *"Recursive pointer chasing during check evaluation has difficulty maintaining low latency with groups that are deeply nested or have a large number of child groups. For selected namespaces that exhibit such structure..."* — yani **tüm namespace'ler için değil**, seçilmiş olanlar için.

Veri yapısı: `(T, s, e)` üçlüleri; T = set tipi enum, s ve e = 64-bit set ID ve element ID. İki set tipi:
- `GROUP2GROUP(s) → {e}` — s atası grup, e doğrudan/dolaylı alt grup
- `MEMBER2GROUP(s) → {e}` — s kullanıcı, e doğrudan üyesi olduğu grup

Üyelik testi:
```
(MEMBER2GROUP(U) ∩ GROUP2GROUP(G)) ≠ ∅
```

Depolama: *"Index tuples are stored as ordered lists of integers in a structure such as a skip list, thus allowing for efficient union and intersections among sets."*

Üç parçalı: (a) serving system, (b) offline periyodik index builder, (c) online real-time incremental layer.

**Argus için ders:** Bu, "grup üyeliği reachability problemidir, düzleştirilebilir" fikrinin kanonik ifadesi. Ve düzleştirme **sıralı integer listeleri + kesişim** ile yapılıyor — roaring bitmap'e çok yakın bir şey. Rust'ta bu, en verimli yapabileceğimiz işlerden biri.

#### Üretim rakamları (Tablo 2 ve §4, Aralık 2018, 7 günlük örneklem)

**Ölçek:**

| Metrik | Değer |
|---|---|
| Relation tuple sayısı | **> 2 trilyon** |
| Toplam veri | **~100 TB** |
| Namespace başına tuple | onlarca → 1 trilyon, **medyan ~15.000** |
| Namespace config boyutu | onlarca → binlerce satır, **medyan ~500 satır** |
| Replikasyon | **30+ coğrafi lokasyon**, tam replikasyon |
| Sunucu | **> 10.000**, birkaç düzine cluster, medyan ~500 sunucu/cluster |
| Toplam istemci QPS | **> 10 milyon** |
| Check tepe | **4,2M QPS** |
| Read tepe | **8,2M QPS** |
| Expand tepe | **760K QPS** |
| Write tepe | **25K QPS** |

Okuma/yazma oranı iki mertebe — bu, cache tasarımının neden bu kadar merkezî olduğunu açıklıyor.

**Gecikme (Tablo 2 — ortalama (std. sapma), milisaniye):**

| API | p50 | p95 | p99 |
|---|---|---|---|
| **Safe** Check | 3,0 (0,091) | 9,46 (0,3) | 15,0 (1,19) |
| **Safe** Read | 2,18 (0,031) | 3,71 (0,094) | 8,03 (3,28) |
| **Safe** Expand | 4,27 (0,313) | 8,84 (0,586) | 34,1 (4,35) |
| **Recent** Check | 2,86 (0,087) | **60,0 (2,1)** | **76,3 (2,59)** |
| **Recent** Read | 2,21 (0,054) | 40,1 (2,03) | 86,2 (3,84) |
| **Recent** Expand | 5,79 (0,224) | 45,6 (3,44) | 121,0 (2,38) |
| **Write** | 127,0 (3,65) | 233,0 (23,0) | 401,0 (133,0) |

Ayrıca Şekil 4 (Check Safe, 7 gün): p50/p95/p99/p99.9 tepe değerleri **~3, 11, 20, 93 ms**.

**Safe/Recent ayrımının tanımı:** Replikasyon heartbeat aralığı 8 saniye. Zookie'si **10 saniyeden eski** olan istekler "Safe" — çoğunlukla bölge içinde servis edilir. **10 saniyeden yeni** olanlar "Recent" — sıklıkla bölgeler arası gidiş-dönüş gerektirir. Safe istekleri Recent'ten **iki mertebe** daha fazla.

**Bu, raporun en önemli tek tablosu.** "Zanzibar 10 ms'de check yapar" cümlesi, ancak "istemci 10 saniye bayat veriyi kabul ederse" kaydıyla doğrudur. Tazelik istendiği anda p95 6 katına çıkıyor.

**Erişilebilirlik:** 3 yıl boyunca > %99,999. Tanım: Safe için 5 sn, Recent için 15 sn eşiği içinde başarıyla yanıtlanan "nitelikli" RPC oranı; 90 günlük pencerelerde prober'larla ölçülmüş (canlı trafikle değil). Çeyrek başına < 2 dakika global kesinti.

**İç mekanikler (§4.4) — cache verimliliği hakkında çarpıcı gerçek:**

| Metrik | Değer |
|---|---|
| Tepe "delegated" iç RPC | 22M/sn (read ve check arasında ~eşit) |
| In-memory cache lookup | ~200M/sn (150M check, 50M read) |
| Check cache hit — delegate tarafı | **%10** (+ lock table %12) |
| Check cache hit — delegator tarafı | **%2** (+ lock table %3) |
| Read cache hit — delegate tarafı | %24 (+ lock table %9) |
| Read cache hit — delegator tarafı | **< %1** |
| "Super-hot" grup ön-yükleme | grupların %0,1'i |
| Spanner'a giden read RPC | 20M/sn |
| Spanner read boyutu | medyan 1,5 satır/RPC, **p99 ~1000 satır** |
| Spanner read gecikmesi | 0,5 ms medyan, 2 ms p95 |
| Hedging'den faydalanan | %1 (200K/sn) |

Makalenin kendi yorumu: *"While these hit rates appear low, they prevent 500K internal RPCs per second from creating hot spots."*

**Argus için kritik ders:** Zanzibar'ın check cache hit oranı **%10**. Cache burada latency optimizasyonu değil, **hot-spot koruması**. Kim "cache koyarız, %90 hit alırız" diyorsa Google'ın kendi verisiyle çelişiyor. ReBAC check'lerinin anahtar uzayı (user × relation × object) devasadır ve doğal olarak seyrektir.

**Leopard performansı:** medyan 1,56M QPS, p99 2,22M QPS; yanıt **< 150 µs medyan, < 1 ms p99**; incremental layer medyan ~500 index güncellemesi/sn, p99 ~1,5K/sn.

Bu, materialize edilmiş indeksin ham graph yürüyüşüne karşı üstünlüğünün sayısal kanıtı: **150 µs vs 3 ms — 20 kat.**

### 1.2 OpenFGA — iç mimari ve 2026 durumu

**Kimlik:** v1.19.0 (25 Ağustos 2026). CNCF **Incubating** — 28 Ekim 2025 (sandbox: 14 Eylül 2022). CNCF proje sayfasındaki metrikler: 2.548 katkıcı, 898 katkıda bulunan kuruluş, sağlık skoru 87/100. Apache-2.0. Go ile yazılmış.

#### En kritik mimari fark: **zookie yok**

OpenFGA'nın kendi dokümanı:

> "The Zanzibar paper has a feature called Zookies, which is a consistency token that is returned from Write operation. **OpenFGA is considering a similar feature in future releases.**"

Bunun yerine iki modlu bir seçenek var:

| Mod | Davranış |
|---|---|
| `MINIMIZE_LATENCY` (varsayılan) | "OpenFGA will serve queries from the cache when possible" |
| `HIGHER_CONSISTENCY` | "OpenFGA will skip the cache and query the database directly" |

Ve doküman açıkça uyarıyor:

> "If you write a tuple and you immediately make a Check on a relation affected by that tuple using MINIMIZE_LATENCY, the tuple change might not be taken in consideration if OpenFGA serves the result from the cache."
> "Always specifying HIGHER_CONSISTENCY will have a significant impact in performance."

**Yani OpenFGA'da new enemy problem çözülmemiştir; istemciye "her istek için ya hızlı ya doğru seç" ikilemi olarak devredilmiştir.** Bu, Zanzibar'ın çözdüğü asıl problemin türevde kaybolmuş olması demektir. Argus gibi güvenlik-kritik bir üründe bu, bilinçli bir kabul olmalıdır — kaza olmamalıdır.

Doküman bile bir "hile" öneriyor: uygulamanızın kendi veritabanında değişiklik zaman damgasını kontrol edip hangi sorgunun hangi tutarlılık seviyesine ihtiyacı olduğuna karar verin. Bu, aslında **zookie'yi elle uygulamak** demektir.

#### Konfigürasyon ve sabit limitler (varsayılanlarla)

Bunlar Argus'un tasarım kısıtlarını anlamak için önemli — çünkü kendi motorumuzda bu limitleri biz seçeceğiz.

| Ayar | Env var | Varsayılan |
|---|---|---|
| Check sorgu cache | `OPENFGA_CHECK_QUERY_CACHE_ENABLED` | **false** |
| Check cache boyutu | `OPENFGA_CHECK_QUERY_CACHE_LIMIT` | 10.000 |
| Check cache TTL | `OPENFGA_CHECK_QUERY_CACHE_TTL` | **10s** |
| Iterator cache | `OPENFGA_CHECK_ITERATOR_CACHE_ENABLED` | false |
| Iterator cache max sonuç | `OPENFGA_CHECK_ITERATOR_CACHE_MAX_RESULTS` | 10.000 |
| Cache controller | `OPENFGA_CACHE_CONTROLLER_ENABLED` | false |
| Cache controller TTL | `OPENFGA_CACHE_CONTROLLER_TTL` | 10s |
| Shared iterator | `OPENFGA_SHARED_ITERATOR_ENABLED` | false |
| **Çözümleme derinliği** | `OPENFGA_RESOLVE_NODE_LIMIT` | **25** |
| **Çözümleme genişliği** | `OPENFGA_RESOLVE_NODE_BREADTH_LIMIT` | **10** |
| ListObjects deadline | `OPENFGA_LIST_OBJECTS_DEADLINE` | **3s** |
| ListObjects max sonuç | `OPENFGA_LIST_OBJECTS_MAX_RESULTS` | **1000** |
| ListUsers deadline | `OPENFGA_LIST_USERS_DEADLINE` | 3s |
| ListUsers max sonuç | `OPENFGA_LIST_USERS_MAX_RESULTS` | 1000 |
| Yazma başına max tuple | `OPENFGA_MAX_TUPLES_PER_WRITE` | **100** |
| Model başına max tip | `OPENFGA_MAX_TYPES_PER_AUTHORIZATION_MODEL` | 100 |
| İstek zaman aşımı | `OPENFGA_REQUEST_TIMEOUT` | 3s |
| DB max bağlantı | `OPENFGA_DATASTORE_MAX_OPEN_CONNS` | 30 |
| Dispatch throttling | `OPENFGA_CHECK_DISPATCH_THROTTLING_ENABLED` | false (eşik 100) |

**Dikkat: tüm cache'ler varsayılan olarak KAPALI.** Yani "kutudan çıkan" OpenFGA her check'te veritabanına gider. Yayımlanmış "hızlı" rakamlar cache açıkken alınmışsa bu belirtilmelidir.

**resolveNodeLimit = 25** — 25 seviyeden derin ilişki zinciri çözülmez, hata döner. resolveNodeBreadthLimit = 10 — eşzamanlı dallanma sınırı.

#### API'ler ve maliyetleri

| API | İş | Maliyet karakteri |
|---|---|---|
| `Check` | tek user-relation-object | Nokta sorgu, graph yürüyüşü |
| `BatchCheck` | çoklu check | `maxBatchSize` vars. **50**, `maxParallelRequests` vars. **10**. Doküman: *"Less efficient than parallel Check calls for fewer than 10 checks"* |
| `Expand` | bir nesnenin userset ağacı | Özyinelemeli; debug için |
| `ListObjects` | kullanıcının eriştiği nesneler | **Reverse expansion.** Doküman: "designed for access-aware filtering on **small** collections", "can be resource-intensive for large datasets" |
| `StreamedListObjects` | streaming varyant | Max-results sınırını aşmak için |
| `ListUsers` | nesneye erişen kullanıcılar | Aynı sınıf maliyet |

#### Weighted graph resolution (yeni ve önemli)

21 Temmuz 2026 tarihli OpenFGA blog yazısı (Tyler Nix): *"OpenFGA's Move to Weighted Graph Resolution: What's Changing"*. Ağırlıklı graf tabanlı bir çözümleme algoritması Check, BatchCheck, ListObjects, Expand ve ListUsers'a yayılıyor; ListObjects zaten kullanıyor. Sürüm notlarında `weighted_graph_check` deneysel bayrak olarak görünüyor (v1.18.1–v1.19.0 arası birçok düzeltme).

Bu, esasen bir **sorgu planlayıcıdır**: model grafındaki kenarlara maliyet ağırlığı atayıp hangi yoldan gidileceğine karar veriyor. Argus için doğrudan çalınabilir bir fikir (Bölüm 7.4).

**Uyarı:** v1.18.2 ve v1.18.3 sürüm notları `weighted_graph_check`'te "intermittent false returns" ve "cache key collisions" düzeltmelerinden bahsediyor. Yani yeni motor **hâlâ yanlış cevap veriyordu**. Deneysel özellik, deneysel.

#### Model versiyonlama

- Modeller **immutable**. Her değişiklik yeni bir model ID üretir.
- Kritik davranış: *"The tuples that are not valid according to the specified model, are ignored when evaluating queries."* — geçersiz tuple'lar silinmez, **sessizce yok sayılır**, ama sorgu performansını düşürür.
- Migrasyon: yeni model yayımla → yeni tuple'ları yaz → uygulamayı güncelle → model ID'yi değiştir.

**Bu sessiz yok sayma davranışı bir güvenlik tuzağıdır.** Bir relation'ı yeniden adlandırırsanız, eski tuple'lar hâlâ veritabanındadır ve modeli geri alırsanız **yeniden canlanırlar**. Argus'ta bu davranış açıkça log'lanmalı ve metriklenmelidir.

#### Üretim rehberi

- *"a small pool of servers with high capacity (memory and CPU cores) instead of a big pool of servers"* — cache hit oranını artırmak için.
- Veritabanı OpenFGA sunucularıyla **aynı fiziksel datacenter/ağda**, **başka uygulamayla paylaşılmamış**.
- Cache açmak *"will reduce latency of requests, but it will increase the staleness of OpenFGA's responses."*

**Gömülebilirlik:** OpenFGA bir Go modülüdür ve teknik olarak in-process kullanılabilir; ancak dokümantasyon **gömülü kullanım için resmî bir rehber vermiyor** — deployment topolojisi (sidecar/merkezî/gömülü) hakkında hiçbir şey söylemiyor. Rust'tan yalnızca gRPC/HTTP istemcisiyle kullanılabilir.

### 1.3 SpiceDB — iç mimari

**Kimlik:** v1.56.1 (26 Ağustos 2026). Go. Authzed tarafından geliştiriliyor.

*Lisans notu: crates/GitHub API rate limit'i nedeniyle lisansı bu oturumda birincil kaynaktan teyit edemedim — **DOĞRULANMADI**. Geçmişte Apache-2.0'dı; kullanmadan önce LICENSE dosyası kontrol edilmelidir.*

#### ZedToken ve dört tutarlılık seviyesi

SpiceDB, Zanzibar'ın zookie'sini **gerçekten uygulamıştır**. OpenFGA'ya karşı en büyük mimari avantajı budur.

| Seviye | Davranış | Not |
|---|---|---|
| `minimize_latency` | Cache'ten servis; new enemy penceresi açık | Okumalar için varsayılan |
| `at_least_as_fresh` | Verilen ZedToken'dan **en az** o kadar taze | Dengeli seçim; önerilen |
| `at_exact_snapshot` | Tam o snapshot | **"Snapshot Expired"** riski (`--datastore-gc-window`); sadece kısa pencerede sayfalama için |
| `fully_consistent` | Cache tamamen atlanır | Yazmalar için varsayılan; *"dramatically increasing latency"* |

Ve önemli bir ince nokta: *"the snapshot used will be loaded at the beginning of the API call, and that new data written after the API starts executing will be ignored."*

**CockroachDB uyarısı (Argus'un çok dikkat etmesi gereken):**

> "fully_consistent does not guarantee read-after-write consistency on CockroachDB" — düğüm saat kayması nedeniyle (`max_offset`, tipik olarak **500 ms**). Bunun yerine ZedToken + `at_least_as_fresh` kullanılmalı.

Yani en güçlü tutarlılık seviyesi, en çok önerilen backend'de en güçlü garantiyi **vermiyor**. Zookie mekanizması opsiyonel bir konfor değil, **zorunluluk**.

#### Datastore soyutlaması

| Backend | Üretim durumu | Revision mekanizması | Not |
|---|---|---|---|
| **CockroachDB** | Self-hosted için **önerilen** | `cluster_logical_timestamp()` | Çok bölgeli; yüksek operasyonel karmaşıklık |
| **Cloud Spanner** | GCP için önerilen | **TrueTime** | Linearizability varsayımı; overlap stratejisi gereksiz |
| **PostgreSQL** | **Tek bölge için önerilen** | Özel MVCC, satırlarda transaction ID | PG 15+ ideal; **standart dışı eklenti gerekmez**; Watch API için `track_commit_timestamp=on`; 16 read replica URI'ye kadar |
| **MySQL** | *"Not recommended; only use if you cannot use PostgreSQL"* | Özel MVCC | Replika tutarlılığı için iki round-trip |
| **memdb** | Sadece geliştirme/test | In-memory MVCC | Süreç ölünce veri gider; HA yok |

**Argus için değerli:** SpiceDB'nin Postgres backend'i standart dışı eklenti gerektirmiyor ve satırlara transaction ID gömerek MVCC'yi kendisi uyguluyor. Bu, Argus'un Postgres'te aynı yaklaşımı kopyalayabileceğini gösteriyor — Argus zaten Postgres'e bağımlı olacak.

#### Dispatch katmanı

SpiceDB'nin dispatch/caching dokümantasyon sayfalarına bu oturumda erişemedim (404). Bilinen mimari — consistent hashing ile cluster dispatch, singleflight deduplikasyon, dispatch cache — **bu oturumda birincil kaynaktan doğrulanmadı**; Zanzibar'ın delegation modelinin uyarlaması olduğu genel olarak bilinir ama sayısal iddiada bulunmayacağım.

### 1.4 Ory Keto — hâlâ aktif mi?

**Kısa cevap: teknik olarak evet, pratik olarak hayır.**

| Sürüm | Tarih |
|---|---|
| v26.2.0 | **20 Mart 2026** |
| v25.4.0 | 7 Kasım 2024 |
| v0.14.0 | 6 Mart 2024 |

**16 aylık sürüm boşluğu** (Kasım 2024 → Mart 2026). Ve v26.2.0'ın içeriği ağırlıklı olarak bug fix ve güvenlik: GHSA-7h2j-956f-4vf2, Postgres transaction retry, SQL NULL işleme, keyset pagination. Yani bu bir özellik sürümü değil, bir **bakım sürümü**.

README'nin kendi ifadesi, Ory'nin konumlandırmasını açık ediyor:

> Self-hosted Keto "is a great fit for individuals, researchers, hackers, and companies that want to experiment, prototype, or **run unimportant workloads**."

"Unimportant workloads" — kendi projesi hakkında bunu yazan bir ekibin ürününü bir IdP'nin yetkilendirme çekirdeğine koymak savunulamaz. Üretim için Ory Network / Ory Permissions'a yönlendiriyorlar.

Ve Mart 2026'da **CVE-2026-33505** (HIGH, CVSS 3.1 AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H): *"Ory Keto has a SQL injection via forged pagination tokens"*. Bir yetkilendirme motorunda pagination token'ı üzerinden SQL injection, mimari bir kod kalitesi sinyalidir.

**Karar: Keto Argus için değerlendirilmemeli.**

### 1.5 list-objects / list-users — gizli darboğaz

Bu, sorunuzda haklı olarak öne çıkardığınız nokta ve verilerle destekleniyor.

**Neden pahalı:** Check bir *nokta sorgusudur* — "U'nun O'ya R ilişkisi var mı?" — grafta hedeften kaynağa doğru yürünür ve ilk pozitif yolda durulabilir. ListObjects **ters yöndedir**: "U'nun R ilişkisi olan TÜM O'lar" — bu, U'dan başlayıp erişilebilir tüm nesneleri keşfetmeyi gerektirir. Fan-out sınırsızdır ve erken çıkış yoktur.

**Ürünlerin kendi itirafları:**
- OpenFGA: ListObjects *"designed for access-aware filtering on small collections"*, *"can be resource-intensive for large datasets"*. Varsayılan **3 saniye deadline** ve **1000 sonuç** limiti — bunlar performans ayarı değil, **hasar kontrolüdür**.
- Google: Leopard'ın var oluş sebebi tam olarak bu — *"Recursive pointer chasing during check evaluation has difficulty maintaining low latency with groups that are deeply nested or have a large number of child groups."*

**Ve en tehlikeli kısmı: ListObjects ile Check tutarsız olabilir.** CVE listesi bunu kanıtlıyor:

| CVE | Ürün | Sorun |
|---|---|---|
| CVE-2025-65111 | SpiceDB (<1.47.1) | *"LookupResources with Multiple Entrypoints across Different Definitions Can Return **Incomplete Results**"* |
| CVE-2023-35930 | SpiceDB (1.22.0–1.22.2) | *"LookupResources may return **partial results**"* |
| CVE-2024-32001 | SpiceDB (<1.30.1) | *"LookupSubjects may return **partial results**"* |
| CVE-2022-21646 | SpiceDB (1.3.0–1.4.0) | *"Lookup operations do not take into account **wildcards**"* |
| CVE-2022-39340 | OpenFGA (<0.2.4) | *"Information Disclosure via **streamed-list-objects** endpoint"* |

**Beş ayrı CVE, iki ayrı üründe, aynı operasyon sınıfında.** Bu tesadüf değil — ListObjects'i doğru yapmak Check'i doğru yapmaktan kategorik olarak zordur ve sektörün en olgun iki motoru da defalarca yanlış yapmıştır.

**Argus için doğrudan sonuç:** ListObjects'i **birinci sınıf API olarak sunmak riskli**. Alternatifler:
1. **Check-per-item**: uygulama kendi veritabanından sayfayı çeker (LIMIT 50), sonra 50 elemanlık BatchCheck yapar. Doğruluk garantisi Check ile aynıdır. Maliyet: sayfa doldurma sorunları (filtrelenen elemanlar sayfayı seyrekleştirir).
2. **Materialized index (Leopard yolu)**: yalnızca ihtiyaç duyulan (kullanıcı, relation, tip) üçlüleri için düzleştirilmiş bitmap tutmak.
3. **Filtre ifadesine indirgeme**: yetki sorgusunu SQL `WHERE` yan tümcesine çevirmek (OPA partial evaluation'ın yaptığı). Sadece dar model sınıflarında mümkün.

Önerim Bölüm 7.5'te.

### 1.6 Gömme mi, yan servis mi?

**Verilerle karşılaştırma:**

| Yaklaşım | Karar gecikmesi mertebesi | Erişilebilirlik | Kaynak |
|---|---|---|---|
| In-process (Rust, Cedar) | **4–11 µs medyan** | Süreçle aynı | arXiv:2403.04651 ölçümü |
| In-process (Go, OpenFGA memdb) | **89–746 µs medyan** | Süreçle aynı | Aynı ölçüm |
| Yerel gRPC (sidecar) | + ~0,1–1 ms | Sidecar bağımlılığı | Mertebe tahmini — **kesin sayı DOĞRULANMADI** |
| Ağ üzerinden merkezî | **3–15 ms** (Zanzibar Safe) / **60–76 ms** (Recent) | Ayrı hata alanı | Zanzibar Tablo 2 |

**Ne OpenFGA ne de SpiceDB'nin resmî gömülü kütüphane hikâyesi var.** OpenFGA'nın üretim dokümanı deployment topolojisi hakkında hiçbir şey söylemiyor. İkisi de Go'dur; Rust'a gömülemezler (cgo/FFI köprüsü teorik olarak mümkün ama Go runtime'ını Rust sürecine sokmak — GC, scheduler, sinyal işleme — ciddi bir mühendislik borcudur ve **bunu üretimde yapan bilinen bir örnek bulamadım**).

**Argus Rust olduğu için bu tercih zaten yapılmıştır:** Harici motor kullanacaksak ağ/gRPC hop'u kaçınılmazdır. Bu da her istekte 1–15 ms demektir. Bir IdP'nin token endpoint'i için bu kabul edilemez.

---

## BÖLÜM 2 — RUST'TA YETKİLENDİRME

Tüm rakamlar crates.io API'sinden 8 Eylül 2026'da çekildi.

### 2.1 Ekosistem tablosu

| Crate | Sürüm | Son yayın | Toplam indirme | Son 90 gün | Lisans | Değerlendirme |
|---|---|---|---|---|---|---|
| **cedar-policy** | 4.12.0 | 2026-07-28 | 8.375.517 | **2.698.101** | Apache-2.0 | Olgun, aktif, formal doğrulanmış |
| **biscuit-auth** | 6.0.0 | 2025-07-16 | 11.159.305 | 1.116.227 | Apache-2.0 | Olgun ama 14 aydır sürüm yok |
| **casbin** | 2.20.0 | 2026-02-04 | 3.032.454 | 1.479.081 | Apache-2.0 | Aktif; model sınırlı |
| **regorus** | 0.12.0 | **2026-09-01** | 2.157.219 | 1.001.705 | MIT/Apache-2.0/BSD-3 | Çok aktif; 0.x |
| **openfga-client** | 0.6.1 | 2026-08-06 | 74.567 | 30.650 | Apache-2.0 | Tek ciddi OpenFGA Rust istemcisi |
| **oso** | 0.27.3 | 2024-01-13 | 942.295 | 65.026 | Apache-2.0 | **2,5 yıldır sürüm yok** |
| **spicedb-rust** | 0.3.4 | 2024-12-01 | 12.637 | 771 | MIT | Bakımsız |
| **openfga-rs** | 0.1.0 | 2024-04-08 | 1.632 | **25** | MIT/Apache-2.0 | **Ölü** |
| **authzed** | 0.0.1 | 2021-01-26 | 1.876 | **9** | Apache-2.0 | **Ölü** |

**Datalog/incremental motorlar (kendi ReBAC'ını yazacaksan):**

| Crate | Sürüm | Son yayın | Toplam | Son 90 gün | Lisans |
|---|---|---|---|---|---|
| **ascent** | 0.8.1 | **2026-08-29** | 494.673 | 161.281 | MIT |
| **crepe** | 0.2.0 | 2025-12-14 | 790.590 | 82.103 | MIT/Apache-2.0 |
| **differential-dataflow** | 0.25.1 | 2026-07-15 | 454.556 | 60.589 | MIT |
| **proptest** | 1.11.0 | 2026-03-24 | 182.638.062 | 46.079.380 | MIT/Apache-2.0 |

### 2.2 Sonuç: Rust'ta üretim-hazır Zanzibar YOK

Bu, raporun en net bulgularından biri. `openfga-rs` son 90 günde **25 kez** indirildi. `authzed` crate'i **9 kez**, 2021'den beri güncellenmemiş. `spicedb-rust` 771. Bunlar terk edilmiş projelerdir.

Tek ciddi seçenek `openfga-client` (0.6.1, Ağustos 2026, 30.650 indirme/90gün) — ama bu bir **istemci**, motor değil. Argus'un yanında bir OpenFGA sunucusu çalıştırmayı gerektirir.

**Yani: Rust'ta ReBAC istiyorsan ya Go'ya gRPC ile konuşacaksın ya kendin yazacaksın.** Üçüncü seçenek yok.

### 2.3 Cedar (AWS) — derinlemesine

#### Kimlik ve API

cedar-policy 4.12.0, 28 Temmuz 2026, Apache-2.0. **Rust ile yazılmış** — Argus için birinci sınıf uyum.

Ana tipler: `Authorizer`, `PolicySet`, `Entities`, `Request`, `Schema`, `EntityUid`, `Context`, `Response`, `Diagnostics`, `Validator`.

Çağrı: `Authorizer::is_authorized(&request, &policy_set, &entities) -> Response`, `response.decision()`.

**Feature flag'ler:**
- Varsayılan: `ipaddr`, `decimal`, `datetime`
- Opsiyonel: `heap-profiling`, `corpus-timing`, `wasm`
- **Deneysel (kararsız):** `partial-eval`, `tpe` (type-aware partial evaluation), `entity-manifest` (**deprecated**), `protobufs`, `tolerant-ast`, `extended-schema`

**Not:** Partial evaluation hâlâ deneyseldir ve `entity-manifest` (entity slicing) deprecate edilmiştir. Yani "Cedar ile SQL filtresi üretme" yolu **üretim-hazır değildir**.

#### Formal doğrulama — ne tam olarak kanıtlandı

Kaynak: *"How We Built Cedar: A Verification-Guided Approach"* (arXiv:2407.01688, FSE Companion '24). PDF'ten çıkardığım **yedi** kanıtlanmış özellik:

1. **Forbid trumps permit** — herhangi bir forbid politikası sağlanırsa istek reddedilir.
2. **Default deny** — hiçbir permit sağlanmazsa reddedilir.
3. **Explicit allow** — izin verildiyse bir permit sağlanmıştır.
4. **Order independence** — authorizer, politika değerlendirme sırasından ve tekrarlardan bağımsız aynı kararı verir.
5. **Sound slicing** — slicing algoritması, tam politika kümesiyle aynı kararı üreten bir alt küme seçer.
6. **Validation soundness** — validator bir politikayı kabul ederse, değerlendirmesi asla tip hatası üretmez. *(Makale bunu "the most involved proof we have done so far" diye niteliyor.)*
7. **Termination** — Cedar fonksiyonları her zaman sonlanır.

Örnek olarak Property 1'in tam Lean ifadesi makalede veriliyor:
```lean
theorem forbid_trumps_permit (request : Request)
  (entities : Entities) (policies : Policies) :
  (∃ (policy : Policy), policy ∈ policies ∧ policy.effect = forbid ∧
   satisfied policy request entities) →
  (isAuthorized request entities policies).decision = deny
```

**Dafny → Lean geçişi gerçekleşti** (RFC 0032, cedar-policy/rfcs). Model **Lean 4**'te.

**Ölçek (Tablo 1, LOC):**

| Bileşen | Lean model | Lean kanıt | Rust üretim | Rust test |
|---|---|---|---|---|
| Custom sets/maps | 244 | 681 | — | — |
| Parser | — | — | 4.114 | 3.599 |
| Evaluator + Authorizer | 897 | 347 | 4.877 | 7.061 |
| Validator | 532 | **4.686** | 6.702 | 9.798 |
| **Toplam** | **1.673** | **5.714** | **15.693** | **20.458** |

Kanıt/model oranı **3,4:1**. Tüm kanıtların doğrulanması **~3 dakika**.

**Bulunan hatalar:** Kanıt süreci validator'da **4 hata** ortaya çıkardı; DRT + PBT ek **21 hata** buldu. Toplam 25.

**Çok önemli bir nüans:** Kanıtlar **Lean modeli** hakkındadır, Rust üretim kodu hakkında değil. Rust ile model arasındaki bağ **differential random testing** ile kurulur — kanıtla değil. Yani "Cedar formal olarak doğrulanmıştır" cümlesi doğru ama eksiktir: *tasarımı* doğrulanmıştır, *implementasyonu* diferansiyel olarak test edilmiştir. Makale bunu dürüstçe söylüyor.

#### Cedar performansı — gerçek ölçüm

Kaynak: arXiv:2403.04651 (OOPSLA 2024 genişletilmiş sürüm), §5.2.

**Deney koşulları (tam olarak):**
- Donanım: **Amazon EC2 m5.4xlarge**, Amazon Linux 2
- Sürümler: Cedar 3.0.1, Rego (OPA) 0.61.0, OpenFGA commit `bbb4a07`
- Her veri noktası için 200 ayrı datastore × 500 rastgele istek = **100.000 istek**
- **Tüm politika ve entity verisi bellekte**; depolama erişimi, parse, HTTP hariç tutulmuş
- Sadece çekirdek `is_authorized()` ölçülmüş

**Sonuçlar (medyan, µs):**

| Motor | gdrive (5 entity) | gdrive (50 entity) | github (5→50) |
|---|---|---|---|
| **Cedar** | **4,0** | **5,0** | ~11,0 (aralık boyunca sabit) |
| **OpenFGA** | 89 | 219 | 235 → 746 |
| **Rego** | 76 | 676 | — |

**p99:**

| Motor | gdrive |
|---|---|
| **Cedar** | **< 10 µs** (tüm boyutlarda) |
| **OpenFGA** | 283 → **3012 µs** |
| **Rego** | 391 → 1933 µs |

**Toplu oranlar:** Cedar, OpenFGA'dan **28,7× / 34,4× / 35,2×** (gdrive/github/TinyTodo), Rego'dan **60,4× / 80,8× / 42,8×** daha hızlı.

**Bu ölçümün dürüst okunması — üç önemli kayıt:**

1. **Makalenin kendi dipnotu (fn. 6):** *"Based on communication with the OpenFGA developers, the OpenFGA in-memory datastore is intended mainly for debugging and is not optimized."* Yani OpenFGA en kötü konfigürasyonunda ölçüldü.
2. **Veri kümeleri minik:** 5–50 entity. Gerçek dünyada milyonlarca tuple var. Cedar'ın "sabit kalması", tüm entity grafını belleğe koyabildiği içindir — bu, ölçekte geçerli olmayan bir varsayımdır.
3. **AWS'nin kendi makalesi, kendi ürünü lehine.** Bağımsız replikasyon **DOĞRULANMADI**.

**Buna rağmen 4–11 µs rakamı Argus için anlamlı bir üst sınırdır:** Rust'ta, bellekteki veriyle, politika değerlendirme mertebesinin **tek haneli mikrosaniye** olduğunu gösteriyor.

İkinci bağımsız veri noktası (VGD makalesi, §3.2): DRT sırasında **Lean authorizer medyan 6 µs, Rust 10 µs**. İki bağımsız ölçüm aynı mertebeyi veriyor.

#### Cedar'ın SMT analizi

Cedar'ın symbolic compiler'ı politikaları SMT-LIB'e indirger. Örnek modellerdeki politikalar için analiz soruları **ortalama 75,1 ms**'de kodlanıp çözülüyor. Bu, "bu refactor yetkileri değiştirdi mi?" gibi soruları **CI'da** sorabilmek demektir — çalışma zamanında değil.

#### Cedar'ın ReBAC sınırı — kritik

Cedar'ın ilişki modeli **entity hierarchy** (`in` operatörü) üzerinden gider ve bu bir DAG'dır. Makale: *"The parent relation on entities forms a directed acyclic graph (DAG), called the entity hierarchy."*

**Cedar'ın YAPAMADIĞI iki şey:**

1. **Entity store yoktur.** Cedar'a `Entities` nesnesini **siz verirsiniz**. Yani "Alice hangi gruplarda?" sorusunu Cedar cevaplamaz — cevabı Cedar'a siz beslersiniz. ReBAC'ın zor kısmı (transitive closure'ın depolanması ve sorgulanması) Cedar'ın kapsamı **dışındadır**.
2. **"Kullanıcının erişebildiği tüm kaynaklar" sorgusu yoktur.** ListObjects karşılığı yok.

**Bu, Cedar ile Zanzibar'ın rakip değil tamamlayıcı olduğu anlamına gelir.** Cedar = politika değerlendirme motoru. Zanzibar = ilişki deposu + graph çözümleyici. Argus'un ikisine de ihtiyacı var ve Cedar ikincisini vermez.

### 2.4 biscuit-auth

**Ne veriyor:** Ed25519 imzalı, **offline attenuation** yapılabilen capability token. Herhangi bir tutucu yeni bir blok ekleyerek yetkiyi **daraltabilir**, ama asla **genişletemez**. Third-party block'lar ile delegasyon; sealing ile daha fazla değişikliği engelleme; **Datalog** tabanlı authorizer.

**Güvenlik denetimi durumu — dikkat:** Deponun kendi ifadesi: *"looking for an audit of the token's design, cryptographic primitives and implementations."* Yani **tamamlanmış bağımsız denetim yok**.

Ve sicil temiz değil:

| CVE | Tarih | Şiddet | Etkilenen | Açıklama |
|---|---|---|---|---|
| CVE-2022-31053 | 2022-06-17 | **CRITICAL** | biscuit-auth < 2.0.0 | **Signature forgery in Biscuit** |
| CVE-2024-41949 / CVE-2024-42350 | 2024-07-31 | LOW | 4.0.0 ≤ v < 5.0.0 | Third party block'ta public key confusion |

Bir capability token kütüphanesinde **imza sahteciliği** (2022, kritik) ciddi bir olaydır — düzeltilmiş olsa da denetimsiz kripto kodunun riskini gösterir.

**Sürüm durumu:** 6.0.0, 16 Temmuz 2025 — **14 aydır yeni sürüm yok**. İndirme hacmi yüksek (11,2M toplam) ama momentum düşük.

**Kullananlar:** Clever Cloud, Apache Pulsar (biscuit-pulsar).

**IdP'de yeri:** Argus için **doğrudan token formatı olarak önerilmez** (OIDC/OAuth ekosistemi JWT bekler, interop kırılır). Ancak **fikir olarak** çok değerli: attenuation, delegasyon zincirinde yetki daraltmanın doğru yoludur ve ajan senaryolarının cevabıdır. arXiv:2609.00267'nin brokerı tam olarak bunu macaroon tarzıyla yapıyor. Argus bunu **JWT içinde kısıtlama claim'leri** olarak taklit edebilir (RFC 9396 RAR / OAuth Token Exchange ile).

### 2.5 regorus (Microsoft) — Rust'ta Rego

**Kimlik:** 0.12.0, **1 Eylül 2026** (bir hafta önce — çok aktif). MIT AND Apache-2.0 AND BSD-3-Clause. 1,0M indirme/90gün.

**OPA uyumu (README'den):** *"Regorus is mostly compliant with the latest OPA release v1.2.0."* — *"passes all the non-builtin specific tests"*, ancak **20 test suite** eksik builtin'ler nedeniyle tam geçmiyor (JWT, kriptografik, ağ fonksiyonları).

**Performans (README'deki ACI politikası benchmark'ı):**
- Regorus: **4,6 ms ± 0,2 ms**
- OPA: **45,2 ms ± 0,6 ms**
- **~10× hızlı**

*Not: Bu Microsoft'un kendi benchmark'ı, tek bir politika kümesi (Azure Container Instances) üzerinde. Bağımsız doğrulama **DOĞRULANMADI**. Ayrıca 4,6 ms mutlak değeri Cedar'ın 4–11 µs'inden **~1000× yavaştır** — Rego semantiği pahalıdır.*

**Eksikler:** *"Cryptographic builtins are not supported by design."* — JWT doğrulama, `glob.match`, GraphQL, CIDR işlemleri yok.

**Bağlamalar:** C, C++, C#, Java, Python, Go, JS/WASM, Ruby. **`no_std` uyumlu** — gömülü senaryolar için dikkate değer.

**Argus için değerlendirme:** Rego'nun IdP'de yeri, ancak müşteriler zaten Rego politikası yazıyorsa vardır. Sıcak yol için 4,6 ms kabul edilemez. **Konfigürasyon-zamanı politika değerlendirmesi** için (örn. "bu client bu grant type'ı kullanabilir mi?") uygun olabilir.

### 2.6 casbin-rs ve oso

**casbin (2.20.0, 4 Şubat 2026, 1,48M indirme/90gün):** Aktif. PERM metamodeli (Policy, Effect, Request, Matchers) ile RBAC/ABAC/ACL. **Ancak Zanzibar tarzı ReBAC için tasarlanmamıştır** — transitif ilişki çözümlemesi ve tuple deposu semantiği yoktur. RBAC'ın rol hiyerarşisini destekler, o kadar. Argus'un ihtiyacını karşılamaz. OSV'de **CVE kaydı yok** (crates.io ekosisteminde).

**oso (0.27.3, 13 Ocak 2024):** **2,5 yıldır sürüm yok.** Oso'nun dokümantasyonu artık tamamen **Oso Cloud**'u — *"a centralized authorization service built on Polar"* — anlatıyor. OSS kütüphanenin resmî deprecation açıklamasını bulamadım (**DOĞRULANMADI**), ama sürüm geçmişi kendi başına yeterince açık. Son 90 günde hâlâ 65K indirme var (eski bağımlılıklar), ama yeni proje için seçilmemeli.

### 2.7 Kendi motorunu yazmak için Rust altyapısı

Eğer Argus kendi ReBAC motorunu yazacaksa (önerim bu), Rust ekosistemi güçlü:

| Crate | Ne için | Değerlendirme |
|---|---|---|
| **ascent** (0.8.1, 29 Ağu 2026) | Rust içinde Datalog, makro tabanlı | Aktif geliştirme (161K/90gün); userset rewrite kurallarını Datalog olarak ifade etmek için doğal aday |
| **crepe** (0.2.0, Ara 2025) | Prosedürel makro Datalog | Daha basit, daha az esnek |
| **differential-dataflow** (0.25.1, Tem 2026) | Incremental hesaplama | Leopard benzeri materialized index'i **incremental** tutmak için teorik olarak ideal. **Ancak ReBAC materialization için üretimde kullanan bilinen bir örnek bulamadım — DOĞRULANMADI.** Operasyonel karmaşıklığı yüksek |
| **proptest** (1.11.0) | Property-based testing | Yetkilendirme invariant'larını test etmek için zorunlu (Bölüm 6.2) |

**Not:** `roaring` crate'i (roaring bitmap) bu oturumda sorgulanmadı ama Leopard tarzı set kesişimi için standart araçtır.

---

## BÖLÜM 3 — AuthZEN

### 3.1 Doğrulama: tarih doğru

Belirttiğiniz tarih doğrudur. Spec dokümanının kendi yayın tarihi **11 Ocak 2026**; OpenID Foundation'ın onay duyurusu **12 Ocak 2026**.

**Oylama:** 81 kabul, 1 ret, 25 çekimser = 107 oy (378 üyenin %28,3'ü; %20 yeter sayısının üzerinde).

**Aşamalar:** Implementer's Draft — Kasım 2024 → Final — Ocak 2026.

Final Specification statüsü, implementer'lara IP koruması sağlar ve *"is not subject to further revision"* — yani API yüzeyi dondurulmuştur. Argus için bu iyi haber: hedef sabit.

### 3.2 Spec'in tam teknik içeriği

#### Access Evaluation API — `POST /access/v1/evaluation`

**İstek şeması:**
```json
{
  "subject":  { "type": "string (REQUIRED)", "id": "string (REQUIRED)", "properties": "object (OPTIONAL)" },
  "resource": { "type": "string (REQUIRED)", "id": "string (REQUIRED)", "properties": "object (OPTIONAL)" },
  "action":   { "name": "string (REQUIRED)", "properties": "object (OPTIONAL)" },
  "context":  "object (OPTIONAL)"
}
```

Spec'ten birebir örnek:
```json
{
  "subject":  { "type": "user", "id": "alice@example.com" },
  "resource": { "type": "account", "id": "123" },
  "action":   { "name": "can_read", "properties": { "method": "GET" } },
  "context":  { "time": "1985-10-26T01:22-07:00" }
}
```

**Yanıt:**
```json
{ "decision": true }
```

Gerekçeli ret:
```json
{
  "decision": false,
  "context": {
    "reason_admin": { "403": "Request failed policy C076E82F" },
    "reason_user":  { "403": "Insufficient privileges. Contact your administrator" }
  }
}
```

`reason_admin` / `reason_user` ayrımı iyi bir tasarım: yönetici tam nedeni görür, kullanıcı bilgi sızdırmayan bir mesaj alır.

#### Access Evaluations API (batch) — `POST /access/v1/evaluations`

Üst seviyede `subject`, `action`, `resource`, `context` **varsayılan** olarak verilir; `evaluations` dizisindeki her eleman bunları **override eder**. Bu, N+1 sorununu ağ katmanında çözer:

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

**`options.evaluations_semantic` üç değeri:**

| Değer | Anlam |
|---|---|
| `execute_all` | *"Execute all of the requests (potentially in parallel), return all of the results."* |
| `deny_on_first_deny` | *"Any denial (error, or `"decision": false`) short-circuits."* |
| `permit_on_first_permit` | *"Converse short-circuiting semantic."* |

**Argus için önemli:** `deny_on_first_deny`, "tüm bu koşullar sağlanmalı" (AND) semantiğini ağ seviyesinde verir ve erken çıkışla iş tasarrufu sağlar. Bu, sıcak yol için birinci sınıf bir optimizasyon kancasıdır.

#### Search API'leri — **Final spec'in İÇİNDE**

Üçü de v1.0 Final'e dahil (ayrı draft değil):

| Endpoint | Soru |
|---|---|
| `POST /access/v1/search/subject` | "Bu kaynağa bu eylemi yapabilen **kim**?" (`subject.id` **omit edilmeli**) |
| `POST /access/v1/search/resource` | "Bu özne bu eylemi **hangi kaynaklarda** yapabilir?" (`resource.id` omit) — **ListObjects karşılığı** |
| `POST /access/v1/search/action` | "Bu özne bu kaynakta **hangi eylemleri** yapabilir?" (`action` alanı yok) |

**Ortak yanıt şeması (pagination ile):**
```json
{
  "page":    { "next_token": "string (REQUIRED)", "count": "int (OPT)", "total": "int (OPT)", "properties": "object (OPT)" },
  "context": "object (OPTIONAL)",
  "results": "array (REQUIRED)"
}
```
İstek `page` nesnesi: `token` (opaque, önceki `next_token`), `limit`, `properties`. Yanıtta `next_token` **boş string** = liste bitti.

**Bu, Bölüm 1.5'teki tehlikeli operasyonun standartlaştırılmış hâlidir.** Spec, pagination'ı zorunlu kılarak (`next_token` REQUIRED) en azından sınırsız fan-out'u yapısal olarak engelliyor. Argus bu endpoint'i implemente ederken **her zaman** deadline + max-results uygulamalıdır.

#### `.well-known/authzen-configuration`

`GET`, 200 OK, `application/json`.

| Alan | Zorunluluk |
|---|---|
| `policy_decision_point` | **REQUIRED** — HTTPS URL, query/fragment yok |
| `access_evaluation_endpoint` | **REQUIRED** |
| `access_evaluations_endpoint` | OPTIONAL |
| `search_subject_endpoint` | OPTIONAL |
| `search_action_endpoint` | OPTIONAL |
| `search_resource_endpoint` | OPTIONAL |
| `capabilities` | OPTIONAL — IANA URN dizisi |
| `signed_metadata` | OPTIONAL — metadata claim'leri içeren JWT |

Doğrulama kuralı: dönen `policy_decision_point`, well-known URI'nin inşa edildiği PDP tanımlayıcısıyla **aynı olmak ZORUNDA**.

#### Hata yönetimi ve güvenlik

| Kod | Durum |
|---|---|
| 200 | Başarılı (karar `decision` alanında) |
| 400 / 401 / 403 / 500 | Bad request / Unauthorized / Forbidden / Internal |

**Kritik semantik ayrım:** *"A successful request that results in a deny is indicated by a 200 OK status code with a `{ "decision": false }` payload."* — Ret, HTTP hatası **değildir**. 403 ise PEP'in PDP'ye erişim yetkisinin olmamasıdır. Bu ayrımı karıştırmak fail-open'a yol açar.

`X-Request-ID` header'ı varsa PDP yanıtta **aynı header ile** bir istek tanımlayıcısı döndürmek ZORUNDA.

**Güvenlik bölümü:**
- PEP↔PDP bağlantısı *"MUST be secured"* (HTTP REST için TLS).
- PDP çağıran PEP'i *"SHOULD authenticate"* — mTLS, OAuth 2.0 (önerilen), API key.
- PDP yanıtını **imzalayabilir** (MAY).
- I-JSON profili (RFC 7493) — UTF-8, IEEE 754 double sınırları.
- DoS koruması: payload boyutu, istek sayısı, geçersiz JSON, iç içe JSON saldırıları, bellek tüketimi.
- **Güven modeli:** *"The architecture of this model assumes the PDP must trust the PEP, as the PEP is ultimately responsible for enforcing the decision the PDP produces."*

**Transport:** HTTPS+JSON binding normatiftir; gRPC/CoAP binding'leri **profillerde** tanımlanabilir. Endpoint'ler `v1` içermeli (SHOULD). Alıcılar bilinmeyen alanları **yok saymak ZORUNDA** (forward compatibility). JSON üye sıralaması varsayılmamalı.

### 3.3 2026'nın yeni profilleri — Argus için doğrudan alakalı

15 Haziran 2026'da (Identiverse'te) **iki yeni Working Group Draft** onaylandı:

**1. AuthZEN Access Request and Approval Profile (AARP)**
Politika bir eylemi henüz yetkilendiremediğinde — onay, rıza, attestation, risk değerlendirmesi gibi ön koşullar eksik olduğunda — bunları **isteme, izleme, karşılama ve yeniden değerlendirme** için birlikte çalışabilir kalıplar tanımlıyor. Yani "hayır" yerine "henüz değil, şu gerekiyor".

**2. AuthZEN Profile for Model Context Protocol Tool Authorization (COAZ)**
Farklı bilgi modellerinin AuthZEN'in **SARC** (Subject-Action-Resource-Context) yapısına nasıl eşleneceğini standartlaştırıyor; MCP araçlarının ajan iş akışlarında yetkilendirme gereksinimlerini açığa vurmasını hedefliyor.

**Ve GitHub deposunda (openid/authzen) ek taslaklar var — bunlar bir IdP için kritik:**

| Taslak | Neden Argus'u ilgilendiriyor |
|---|---|
| **OAuth 2.0 Token Issuance Profile** | Token verme kararının dışsallaştırılması — **doğrudan Argus'un token endpoint'i** |
| **OAuth 2.0 Token Exchange Binding** | RFC 8693 ile AuthZEN entegrasyonu — delegasyon zincirleri |
| **Authorization Claims Profile** | **AuthZEN'den JWT claim'lerinin kaynaklanması** — "yetkiyi token'a gömme"nin standart yolu |
| COAZ Framework + COAZ-MCP Binding | Protokol-nötr eşleme; MCP |

**Bu, raporun en stratejik bulgusu.** "Authorization Claims Profile", tam olarak Bölüm 4.5'te tartıştığımız "token'a gömmek mi, sormak mı" ikilemine standart bir cevap veriyor. Argus bunu **erken** takip etmeli — çünkü bir IdP'nin bu profili implemente etmesi, onu AuthZEN ekosisteminde benzersiz bir konuma koyar (çoğu PDP satıcısı token *vermez*).

### 3.4 Interop ve sertifikasyon

**Sertifikasyon:** OpenID Foundation *"developing a conformance certification program for the Authorization API, so that implementers can demonstrate that a Policy Decision Point conforms to the specification."* — **Lansman tarihi yok.**

**Interop altyapısı:** `authzen-interop.net` — bir "Todo" uygulaması üzerine kurulu senaryolar; Docusaurus sitesi, React frontend (`todo.authzen-interop.net`), TypeScript backend. *Katılımcı satıcı listesini bu oturumda birincil kaynaktan çekemedim (site erişilemedi) — **belirli PDP/PEP satıcı listesi DOĞRULANMADI**.*

**Etkinlikler (OpenID blog başlıklarından):**
- Gartner IAM Summit — *"AuthZEN shows enterprise readiness"*, ~100 katılımcı
- Gartner IAM London — *"From 'what is this' to 'how do we implement it'"*
- Identiverse 2026 — *"authorization in the agent era"*; AuthZEN oturumları masterclass ve ana program seviyesine yükseldi

### 3.5 AuthZEN + Zanzibar birlikte nasıl çalışır

Bunlar **rakip değil, farklı katmanlar**:
- **AuthZEN** = taşıma protokolü / API sözleşmesi. Politika dili tanımlamaz — bilinçli olarak.
- **Zanzibar** = veri modeli + karar algoritması.

Bir Zanzibar motorunun AuthZEN cephesi sunması **doğal** ama üç impedance mismatch var:

**(1) SARC → tuple eşlemesi.** AuthZEN'in `subject{type,id} × action{name} × resource{type,id}` üçlüsü, Zanzibar'ın `object#relation@user` tuple'ına neredeyse birebir oturur:
```
resource.type:resource.id # action.name @ subject.type:subject.id
```
Sorun `action.name` ↔ `relation` eşlemesinde. Zanzibar'da relation'lar model tarafından tanımlanır (`viewer`, `editor`); AuthZEN'de action'lar uygulama fiilleridir (`can_read`, `can_delete`). Bir **eşleme tablosu** gerekir. COAZ profili tam olarak bu problemi çözmeye çalışıyor.

**(2) Search Resource ↔ ListObjects.** Semantik olarak aynı, ama AuthZEN pagination'ı zorunlu kılıyor (`next_token` REQUIRED) — bu iyi. Zanzibar motorlarının cursor'lu ListObjects'i buna eşlenebilir.

**(3) Consistency token'ı nereye koyacağız — çözülmemiş.** AuthZEN spec'inde zookie/ZedToken için **ayrılmış bir alan yok**. Tek yer `context` nesnesi (serbest form, OPTIONAL). Yani:
```json
"context": { "zookie": "GhUKEzE3NTc..." }
```
Bu işe yarar ama **satıcıya özgüdür** — interop kırılır. Aynı şekilde yanıtta yeni zookie'yi döndürmek için de standart alan yok; `context` kullanılmalı.

**Argus için tavsiye:** `context.consistency_token` anahtarını kullanın, `.well-known` içindeki `capabilities` dizisinde bunu ilan edin, ve AuthZEN WG'ye bu boşluğu bildirin. Bu, standart-öncü bir konum sağlar.

---

## BÖLÜM 4 — SICAK YOL PERFORMANSI

### 4.1 Mertebe haritası — kanıtlı

Bu tablo, tüm mimari kararların dayanması gereken temeldir. Her satır ölçülmüş bir kaynaktan gelir.

| Katman | Gecikme | Kaynak ve koşullar |
|---|---|---|
| HMAC caveat doğrulama (Python, in-process) | **2,6 µs** | arXiv:2609.00267 — 160 satır Python, laptop, 2×10⁵ çağrı |
| Capability token exchange (Python) | **5,4 µs** | Aynı |
| Cedar policy eval (Rust, bellekte, 5–50 entity) | **4–11 µs** medyan, **<10–20 µs** p99 | arXiv:2403.04651 — EC2 m5.4xlarge, 100K istek |
| Cedar (Lean referans modeli) | 6 µs medyan | arXiv:2407.01688, DRT |
| **Leopard indeks lookup** | **< 150 µs** medyan, **< 1 ms** p99 | Zanzibar §4.4, 1,56M QPS medyan |
| OpenFGA in-process check (Go, memdb) | **89–746 µs** medyan, **283–3012 µs** p99 | arXiv:2403.04651 — *optimize edilmemiş memdb* |
| Regorus (Rust Rego) ACI politikası | **4,6 ms** ± 0,2 | Microsoft README |
| OPA (Go Rego) ACI politikası | **45,2 ms** ± 0,6 | Aynı |
| Spanner read (Zanzibar'ın DB'si) | 0,5 ms medyan, 2 ms p95 | Zanzibar §4.4 |
| **Zanzibar Check Safe** (zookie >10sn) | **3,0 ms** p50, **9,46 ms** p95, **15,0 ms** p99 | Zanzibar Tablo 2 |
| **Zanzibar Check Recent** (zookie <10sn) | 2,86 ms p50, **60,0 ms** p95, **76,3 ms** p99 | Zanzibar Tablo 2 |
| Zanzibar Write | 127 ms p50, 401 ms p99 | Zanzibar Tablo 2 |

**Dört mertebe var ve aralarındaki sıçramalar 10–100×:**

```
~µs        : in-process, bellekteki veri, derlenmiş politika
~100 µs    : in-process + materialized index lookup (Leopard)
~1 ms      : in-process graph walk + yerel DB okuması
~10 ms     : ağ + dağıtık graph çözümlemesi (bayat veri kabul edilerek)
~60-100 ms : ağ + taze veri gerektiren dağıtık çözümleme
```

**Bir IdP'nin token endpoint'i için bütçe tipik olarak 50–200 ms'dir** (imzalama, DB, oturum). Yetkilendirmeye ayrılabilecek pay gerçekçi olarak **birkaç ms**. Yani en alttaki iki satır kabul edilemez; ilk üçü hedeflenmelidir.

### 4.2 Cache stratejileri ve invalidation

#### Google'ın gerçek cache verimliliği (tekrar, çünkü çok önemli)

| Cache katmanı | Hit oranı |
|---|---|
| Check — delegate tarafı | **%10** |
| Check — delegate lock table | %12 |
| Check — delegator tarafı | **%2** |
| Check — delegator lock table | %3 |
| Read — delegate tarafı | %24 |
| Read — delegator tarafı | **< %1** |

Google'ın kendi değerlendirmesi: *"While these hit rates appear low, they prevent 500K internal RPCs per second from creating hot spots."*

**Ders: karar cache'i bir latency çözümü değil, bir hot-spot çözümüdür.** Argus'un tasarımı %90 hit oranı varsayımı üzerine kurulmamalıdır. `(user, relation, object)` anahtar uzayı doğal olarak seyrektir; aynı kullanıcı aynı nesneyi kısa sürede tekrar sormaz — ama aynı *ara düğümü* (örn. "acme-org#member") çok sık sorar. **Bu yüzden cache'lenmesi gereken şey nihai karar değil, ara alt-problem sonuçlarıdır.** OpenFGA'nın `checkQueryCache`'i tam olarak bunu yapıyor: *"caching of check subproblem result"*.

#### Invalidation — dört yaklaşım

| Strateji | Nasıl | Artı | Eksi |
|---|---|---|---|
| **TTL** | Süre dolunca at | Basit | Nedenselliği korumaz; new enemy açık kalır |
| **Write-through** | Yazma anında ilgili girdileri düşür | Taze | Hangi girdiler etkilendi? Transitif kapanış problemi — bir grup üyeliği değişince binlerce karar etkilenir |
| **Event-driven** | Changelog/Watch stream'i dinle | Ölçeklenir | Gecikme var; sıralama garantisi gerekir |
| **Versioned snapshot (zookie)** | Cache anahtarına revision koy | **Nedensel doğruluk** | İstemci sözleşmesi gerekir |

**OpenFGA'nın yaklaşımı:** `ReadChanges` API'si — kronolojik sıralı tuple değişiklik listesi, continuation token ile. Sayfa boyutu ≤100. Nesne tipine göre filtrelenebilir. `cacheController` bunu polling ile kullanıyor (varsayılan TTL 10s). Doküman açıkça uyarıyor: *"does not include other changes, like updates to your authorization model"* — **model değişiklikleri cache invalidation'ı tetiklemiyor.**

**SpiceDB'nin yaklaşımı:** ZedToken. Cache anahtarı revision'ı içerdiği için, `at_least_as_fresh` ile yapılan bir sorgu eski cache girdisini **yapısal olarak** kullanamaz. Invalidation problemi ortadan kalkar çünkü eski girdi yanlış anahtar altındadır. Bu, TTL'e karşı kategorik olarak üstün bir tasarımdır.

**Argus için: zookie eşdeğerini baştan koyun.** Sonradan eklenemez — çünkü API sözleşmesini ve istemci davranışını değiştirir. OpenFGA'nın "sonraki sürümlerde düşünüyoruz" durumu, bu borcun ne kadar ağır olduğunun kanıtıdır.

#### Negatif cache — özel dikkat

"Bu kullanıcının bu yetkisi YOK" sonucunu cache'lemek cazip ve etkilidir (deny'lar genellikle allow'lardan çok daha sık). Ama iki risk:
1. **Yetki verildikten sonra kullanıcı hâlâ giremiyor** — kullanıcı deneyimi felaketi, destek yükü.
2. Negatif cache TTL'i pozitiften **kısa** olmalıdır — güvenlik açısından bayat "hayır" zararsız, bayat "evet" tehlikelidir. Ama ürün açısından tam tersi.

**Öneri:** Negatif cache TTL'i çok kısa (≤1 sn) veya write-through invalidation ile. Yetki verme (`Write`) işlemi ilgili negatif girdileri **senkron** olarak düşürmelidir.

### 4.3 Politika derleme

#### Cedar'ın yaklaşımı: slicing + optional typing

Cedar'ın "sound slicing" özelliği **formal olarak kanıtlanmıştır** (Property 5). Politika scope'undaki `principal in ?principal` / `resource == ?resource` kısıtları **indeksleme anahtarı** olarak kullanılır: gelen istek için sadece ilgili politika alt kümesi değerlendirilir.

Makalenin ölçümü (§5.3): `gdrive-templates` 4 statik politika + 1 template, `github-templates` 3 statik + 5 template. Template link'ler entity çifti başına 0,05 olasılıkla üretiliyor — yani link sayısı entity sayısında **kuadratik**. Slicing bu senaryoda anlamlı kazanç sağlıyor.

Ama kritik nüans: *"The sound policy slicing scheme does not benefit our Cedar gdrive and github examples because their policies do not have scope-level constraints on principal and resource."* — **Slicing ancak politikalar doğru yazılırsa işe yarar.** Otomatik bir kazanç değil, bir modelleme disiplini.

#### OpenFGA'nın yaklaşımı: weighted graph resolution

Model grafındaki kenarlara ağırlık atayıp çözümleme yolunu seçen bir **sorgu planlayıcı** (blog, 21 Temmuz 2026). Check, BatchCheck, ListObjects, Expand, ListUsers'a yayılıyor.

Bu, klasik veritabanı sorgu optimizasyonunun ReBAC'a uygulanmasıdır ve doğru fikirdir: `viewer or editor from parent` gibi bir ifadede hangi dalın önce denenmesi gerektiği, o dalın beklenen fan-out'una bağlıdır.

**Uyarı (tekrar):** v1.18.2/v1.18.3 sürüm notları bu motorda "intermittent false returns" ve "cache key collisions" düzeltiyor. **Sorgu planlayıcı yazmak, yanlış cevap üretme riskini artırır.** Argus bunu yaparsa, planlayıcılı ve planlayıcısız yolların **diferansiyel test edilmesi zorunludur** (Cedar'ın DRT'sinin yaptığı gibi).

#### Materialized index (Leopard yolu)

En büyük kazanç burada: **150 µs vs 3 ms — 20 kat.**

Mekanizma: transitif grup kapanışını önceden hesapla, sıralı integer listeleri (skip list / roaring bitmap) olarak sakla, üyelik testini **set kesişimi**ne indirge:
```
(MEMBER2GROUP(U) ∩ GROUP2GROUP(G)) ≠ ∅
```

**Maliyeti:** Incremental güncelleme katmanı. Zanzibar'ın Leopard'ı medyan ~500, p99 ~1,5K index güncellemesi/sn işliyor — 25K QPS'lik Write yüküne karşı. Yani **yazma yükünün küçük bir yüzdesi** index güncellemesi tetikliyor (çünkü çoğu tuple grup üyeliği değil).

**Argus için:** Bu, `differential-dataflow` crate'inin teorik olarak parladığı yer. Ama üretimde ReBAC materialization için kullanan bilinen örnek **bulamadım (DOĞRULANMADI)**. Daha güvenli yol: elle yazılmış incremental closure + roaring bitmap.

### 4.4 Batch check

| Sistem | Mekanizma | Limitler |
|---|---|---|
| **OpenFGA** | `BatchCheck` | `maxBatchSize` **50**, `maxParallelRequests` **10**. *"Less efficient than parallel Check calls for fewer than 10 checks"* |
| **SpiceDB** | `CheckBulkPermissions` | *Limitler bu oturumda doğrulanmadı* |
| **AuthZEN** | `/access/v1/evaluations` | Varsayılan alan devralma + üç short-circuit semantiği |

**N+1 yetkilendirme problemi:** Bir liste sayfasında 50 öğe gösteriliyorsa, naif kod 50 ayrı check yapar. Ağ üzerinden bu 50 × 3 ms = 150 ms'dir. Batch ile bu, tek round-trip + paralel çözümleme olur.

**AuthZEN'in `deny_on_first_deny` semantiği** özellikle değerlidir: "bu 5 koşulun hepsi sağlanmalı" sorusunda ilk ret'te durur.

### 4.5 Token'a gömmek vs her istekte sormak

Bu, Argus'un vereceği **en önemli tek mimari karardır**.

#### Karşılaştırma

| Boyut | Token'a gömme | Her istekte check |
|---|---|---|
| Sıcak yol maliyeti | **~µs** (imza doğrulama) | 0,1–15 ms |
| Tazelik | Token TTL kadar bayat | Cache TTL kadar bayat |
| Revocation | **Zor** — token süresi dolana kadar geçerli | Anında |
| Boyut | **Şişer** | Sabit |
| PDP erişilemezse | Çalışmaya devam eder | Durur (veya fail-open riski) |
| Denetlenebilirlik | Karar anı ≠ kullanım anı | Her kullanım loglanır |
| İnce tanelilik | Kaba (rol/scope) | **İnce (kaynak başına)** |

#### Token şişmesi — gerçek limitler

Bunlar mimari sabitlerdir:
- **Cookie: 4 KB** (RFC 6265 uyumlu tarayıcı limiti)
- **HTTP header: 8 KB** varsayılan (nginx `large_client_header_buffers`, Envoy `max_request_headers_kb` varsayılanı 60 KB ama upstream'ler genelde 8 KB)

*Not: bu değerler yaygın varsayılanlardır; bu oturumda birincil dokümantasyondan yeniden doğrulanmadı — **kesin sürüm-spesifik değerler DOĞRULANMADI**.*

Bir kullanıcının 500 belgeye erişimi varsa, bu ID'leri token'a koymak imkânsızdır. **İnce taneli yetki token'a sığmaz — bu matematiksel bir gerçektir, bir mühendislik tercihi değil.**

#### Keycloak'ın UMA/RPT yaklaşımı neden ölçeklenmiyor

Keycloak'ın Authorization Services'i, izinleri bir "Requesting Party Token" (RPT) içine koyar. Kullanıcının erişebildiği kaynak sayısı arttıkça RPT büyür. Bu, tam olarak yukarıdaki duvara çarpar. Projenizin README'sinde de bu "kaba taneli zayıflık" olarak not edilmiş — teknik kökeni budur.

#### Doğru sentez: **iki katmanlı**

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

**Ve kritik kural:** Katman 1 asla tek başına yetki kanıtı olmamalıdır. Token'daki `role: admin` claim'i, "admin olduğu iddia ediliyor" bilgisidir — "bu kaynağa erişebilir" kararı değildir. Bu ayrımı bulanıklaştırmak, IDOR'un doğduğu yerdir.

**AuthZEN'in "Authorization Claims Profile" taslağı tam olarak Katman 1'i standartlaştırıyor.** Argus'un bunu takip etmesi gerekir.

### 4.6 Rust'ta mikrosaniye altı karar mümkün mü?

**Dürüst cevap: kararın türüne bağlı.**

| Karar türü | Mikrosaniye altı? | Gerekçe |
|---|---|---|
| İmza/HMAC doğrulama | **Evet** | 2,6 µs Python'da; Rust'ta ~0,3–1 µs beklenebilir (Ed25519 doğrulama tipik olarak ~50 µs, HMAC-SHA256 ~1 µs — *mertebe tahmini, DOĞRULANMADI*) |
| Bitmap AND + boşluk testi | **Evet** | Roaring bitmap kesişimi, tek gruplarda yüzlerce ns mertebesinde |
| Önceden derlenmiş rol tablosu lookup | **Evet** | HashMap lookup ~20–50 ns mertebesi |
| Cedar tarzı politika değerlendirme | **Hayır** — 4–11 µs | Ölçülmüş |
| ReBAC graph yürüyüşü (bellekte) | **Hayır** — ≥10 µs | Fan-out'a bağlı |
| ReBAC + DB okuması | **Kesinlikle hayır** — ≥1 ms | Spanner bile 0,5 ms |

**Yani: "mikrosaniye altı yetkilendirme" ancak kararın önceden materialize edilmiş olması hâlinde mümkündür.** 2,6 µs'lik broker bunu yapıyor — karar zaten token'da yazılı, sadece imzası doğrulanıyor.

**Argus için gerçekçi hedef:**

| Yol | Hedef |
|---|---|
| Token doğrulama + kaba yetki (Katman 1) | **< 5 µs** p99 |
| İnce taneli check, cache hit / materialized | **< 100 µs** p99 |
| İnce taneli check, cache miss, yerel DB | **< 5 ms** p99 |
| Search/ListObjects | **< 50 ms** p99, zorunlu deadline |

Bunlar Zanzibar'ın ürettiğinden daha iyidir — çünkü Argus tek bölgede, in-process çalışacak, global replikasyon vergisi ödemeyecek.

---

## BÖLÜM 5 — VERİ MODELİ VE MİGRASYON

### 5.1 RBAC'tan ReBAC'a — doğru soyutlama

Projenizin README'sinde şu tavsiye var: *"Rol tablosuyla başla; ilişki karmaşıklığı çıkınca OpenFGA/SpiceDB'ye taşı."*

**Bu tavsiyenin tehlikeli tarafı şudur:** Rol tablosuyla başlarsanız, uygulama kodunuz `if user.role == "admin"` yazar. Bu, kaynak-özgü olmayan bir sorudur ve ReBAC'a taşınırken **her çağrı yerinin yeniden yazılması** gerekir. Maliyet, tablo migrasyonunda değil, **uygulama kodunun tamamındadır**.

**Doğru soyutlama, ilk günden `check(subject, action, resource)` şeklindedir.** İçeride ne olduğu önemli değil:

```rust
// Gün 1 — arkasında basit bir rol tablosu olabilir
authz.check(&user, "read", &Resource::document("doc-42")).await?

// Gün 500 — arkasında tam ReBAC var; ÇAĞRI YERİ DEĞİŞMEDİ
authz.check(&user, "read", &Resource::document("doc-42")).await?
```

**Anahtar ilke: `resource` parametresi ilk günden zorunlu olmalıdır**, o gün için modelde kullanılmasa bile. Çünkü sonradan eklenemez — eklemek her çağrı yerini bulmayı gerektirir.

RBAC, ReBAC'ın bir alt kümesidir: `role:admin#member@user:alice` bir tuple'dır. Yani ReBAC modeliyle başlayıp sadece RBAC şekilli tuple'lar yazmak **hiçbir şey kaybettirmez** ve migrasyon maliyetini sıfırlar.

### 5.2 Şema evrimi

**OpenFGA'nın modeli:** Immutable model'ler, her değişiklikte yeni model ID. Uygulama hangi model ID'yi kullanacağını belirtir. Tuple'lar modelden bağımsız saklanır.

**Kritik ve tehlikeli davranış:** *"The tuples that are not valid according to the specified model, are ignored when evaluating queries."*

Bunun üç sonucu var:
1. Bir relation'ı silerseniz, tuple'lar **kalır** ve performansı düşürür.
2. Modeli **geri alırsanız**, o tuple'lar **yeniden aktif olur** — sessizce yetki geri gelir.
3. Yeniden adlandırma sırasında hem eski hem yeni tuple'lar bir süre yaşar — çift yazma penceresi.

**Argus için tasarım kararı:** Geçersiz tuple'lar sessizce yok sayılmamalı. En azından:
- `authz_orphaned_tuples_total{store,type,relation}` metriği
- Model yayımlarken "bu değişiklik N tuple'ı yetimleştirecek" uyarısı
- Yetim tuple'lar için açık bir temizleme (GC) işi

### 5.3 Yetkilendirme verisini kim yazar?

Bu, sektörün en az konuşulan ama en çok soruna yol açan problemidir.

| Model | Nasıl | Risk |
|---|---|---|
| **Uygulama yazar** | Belge oluşturulunca app tuple yazar | **İki-fazlı commit problemi**: app DB'sine yazıldı, authz'a yazılamadı → yetim kaynak (kimse erişemez) veya tersi (herkes erişir) |
| **IdP/authz yazar** | Merkezî API | App'in iş mantığını bilmez |
| **Outbox pattern** | App kendi transaction'ında outbox tablosuna yazar, ayrı worker authz'a taşır | En sağlam; **eventual consistency** kabul edilir |
| **CDC** | App DB'sinden change data capture | Şema bağımlılığı kırılgan |

**Senkronizasyon problemi somut örneği:**
```
1. App: INSERT INTO documents (id, owner) VALUES ('doc-42', 'alice')  ✓ COMMIT
2. App: authz.write(document:doc-42#owner@user:alice)                 ✗ TIMEOUT
→ Belge var, sahibi yok. Alice kendi belgesini göremiyor.
```

**Ters yön daha kötü:**
```
1. App: authz.write(document:doc-42#viewer@user:bob)   ✓
2. App: DELETE FROM documents WHERE id='doc-42'        ✓
3. Yeni belge oluşturuldu, ID yeniden kullanıldı: 'doc-42'
→ Bob yeni belgeyi görüyor. YETKİ SIZINTISI.
```

**Argus için zorunlu kurallar:**
1. **Kaynak ID'leri asla yeniden kullanılmamalı.** UUID/ULID kullanın. Bu, tuple sızıntısının tek yapısal savunmasıdır.
2. **Outbox pattern'i birinci sınıf destekleyin** — Argus bir "pending writes" API'si sunmalı, idempotent tuple yazma (aynı tuple'ı iki kez yazmak hata olmamalı — OpenFGA bunu 31 Ekim 2025'te ekledi: *"Ignore Duplicate Tuples On Write"*).
3. **Silme işleminde cascade semantiği**: `document:doc-42` silinince, o objeye ait tüm tuple'lar silinmeli. Argus bunu bir API olarak sunmalı (`DeleteObject`), yoksa her uygulama kendi eksik versiyonunu yazar.

---

## BÖLÜM 6 — GÜVENLİK

### 6.1 CVE tablosu — gerçek veriler (OSV.dev, 8 Eylül 2026)

#### OpenFGA — 26 danışmanlık

En kritik olanlar (authorization bypass sınıfı kalınlaştırılmıştır):

| CVE | Tarih | Şiddet | Etkilenen | Özet |
|---|---|---|---|---|
| **CVE-2026-55689** | 2026-06-19 | MODERATE (C:H/I:H) | < 1.18.0 | **OIDC audience doğrulaması `--authn-oidc-audience` ayarlanmamışsa atlanıyor** |
| **CVE-2026-55170** | 2026-06-18 | LOW | < 1.18.0 | Improper Policy Enforcement |
| **CVE-2026-48096** | 2026-06-11 | MODERATE | < 1.16.0 | **shared-iterator ve v2 iterator'da cache-key delimiter injection → store içi karar zehirlenmesi** |
| **CVE-2026-41131** | 2026-04-22 | MODERATE | < 1.14.1 | Improper Policy Enforcement |
| **CVE-2026-40293** | 2026-04-08 | MODERATE | 0.1.4–1.14.0 | **Kimlik doğrulamasız playground endpoint'i preshared API key'i HTML yanıtta sızdırıyor** |
| **CVE-2026-34972** | 2026-04-07 | MODERATE | 1.8.0–1.14.0 | **BatchCheck içi deduplikasyon, list-value cache-key çakışması ile yanlış karar üretiyor** |
| **CVE-2026-33729** | 2026-03-26 | MODERATE | < 1.13.1 | **Cache'lenmiş anahtarlar üzerinden authorization bypass** |
| **CVE-2026-24851** | 2026-02-05 | MODERATE | 1.8.5–1.11.3 | Improper Policy Enforcement |
| **CVE-2025-64751** | 2025-11-20 | MODERATE | 1.4.0–1.11.1 | Improper Policy Enforcement |
| **CVE-2025-55213** | 2025-08-18 | MODERATE | 1.9.3–1.9.5 | Authorization Bypass |
| **CVE-2025-48371** | 2025-05-23 | MODERATE | 1.8.0–1.8.13 | Authorization Bypass |
| **CVE-2025-46331** | 2025-04-30 | MODERATE | 1.3.6–1.8.11 | Authorization Bypass |
| **CVE-2025-25196** | 2025-02-19 | MODERATE | < 1.8.5 | Authorization Bypass |
| **CVE-2024-56323** | 2025-01-13 | MODERATE | 1.3.8–1.8.3 | Authorization Bypass |
| **CVE-2024-42473** | 2024-08-09 | **HIGH** (VI:H) | 1.5.7–1.5.9 | Authorization Bypass |
| **CVE-2024-31452** | 2024-04-16 | **HIGH** (C:H/I:H/A:H) | 1.5.0–1.5.3 | Authorization Bypass |
| CVE-2024-23820 | 2024-01-26 | MODERATE | < 1.4.3 | DoS |
| CVE-2023-45810 | 2023-10-18 | HIGH | < 1.3.4 | DoS |
| CVE-2023-43645 | 2023-09-28 | MODERATE | < 1.3.2 | **Dairesel ilişki tanımlarından DoS** |
| CVE-2023-40579 | 2023-08-25 | MODERATE (C:H) | < 1.3.1 | Authorization Bypass |
| CVE-2023-35933 | 2023-06-28 | MODERATE | < 1.1.1 | Dairesel ilişki DoS |
| CVE-2022-23542 | 2022-12-20 | HIGH | 0.3.0–0.3.1 | Authorization Bypass |
| CVE-2022-39352 | 2022-11-08 | MODERATE | < 0.2.5 | Authorization Bypass |
| CVE-2022-39342 | 2022-10-25 | MODERATE (I:H) | < 0.2.4 | Authorization Bypass |
| CVE-2022-39341 | 2022-10-25 | MODERATE (I:H) | < 0.2.4 | **Tupleset wildcard ile Authorization Bypass** |
| CVE-2022-39340 | 2022-10-25 | MODERATE | < 0.2.4 | streamed-list-objects ile bilgi ifşası |

**Kalıp analizi — bu tablo bir hikâye anlatıyor:**
- **~16 tanesi doğrudan yetkilendirme bypass'ı.** Bu bir DoS veya bilgi sızıntısı değil; motorun **temel işlevini yanlış yapması**.
- **En az 3 tanesi cache kaynaklı** (CVE-2026-48096, CVE-2026-33729, CVE-2026-34972). Cache anahtarı üretimi, bu sınıfta tekrarlayan bir zayıflık noktası.
- 2026'da **7 yeni danışmanlık** — hız yavaşlamıyor.

#### SpiceDB — 16 danışmanlık

| CVE | Tarih | Şiddet | Etkilenen | Özet |
|---|---|---|---|---|
| **CVE-2026-55866** | 2026-06-19 | LOW | 1.34.0–1.54.0 | **Caveat'li relation'larda check, koşullu izin beklenirken KOŞULSUZ izin verebiliyor** |
| **CVE-2026-46668** | 2026-05-21 | LOW | 1.15.0–1.52.0 | **İç içe listeli caveat yapıları → hatalı cache yeniden kullanımı** |
| CVE-2026-40091 | 2026-04-14 | MODERATE | 1.49.0–1.51.1 | `SPICEDB_DATASTORE_CONN_URI` başlangıç loglarında sızıyor |
| GHSA-vhvq-fv9f-wh4q | 2026-02-06 | LOW | 1.29.3–1.49.1 | LookupResources cursor kurcalama → `tuple.MustParse` panic ile süreç çökmesi |
| **CVE-2025-65111** | 2025-11-21 | LOW | < 1.47.1 | **LookupResources eksik sonuç döndürüyor** |
| CVE-2025-64529 | 2025-11-13 | LOW | < 1.45.2 | WriteRelationships payload çok büyükse **sessizce başarısız** |
| **CVE-2025-49011** | 2025-06-06 | LOW | < 1.44.2 | Caveat'li check, izin beklenirken izin vermiyor |
| CVE-2024-48909 | 2024-10-14 | LOW | 1.35.0–1.37.1 | LookupResources2 caveat "context missing" hatası |
| **CVE-2024-46989** | 2024-09-18 | MODERATE | < 1.35.3 | Aynı tipte çoklu caveat → hatalı izin yok |
| **CVE-2024-38361** | 2024-06-20 | MODERATE | < 1.33.1 | **Exclusion'lar izin beklenirken izin vermiyor** |
| CVE-2024-32001 | 2024-04-10 | LOW | < 1.30.1 | LookupSubjects kısmi sonuç |
| CVE-2024-27101 | 2024-03-01 | **HIGH** | < 1.29.2 | Chunking helper'da integer overflow → dispatch eleman kaçırıyor veya panic |
| CVE-2023-46255 | 2023-10-31 | MODERATE | < 1.27.0-rc1 | URI parse edilemezse log sızıntısı |
| CVE-2023-35930 | 2023-06-28 | LOW | 1.22.0–1.22.2 | LookupResources kısmi sonuç |
| CVE-2023-29193 | 2023-04-13 | **HIGH** | < 1.19.1 | Metrics portu güvensiz ağa bağlanıyor, CLI flag'leri sızdırıyor |
| **CVE-2022-21646** | 2022-01-13 | **HIGH** | 1.3.0–1.4.0 | **Lookup operasyonları wildcard'ları hesaba katmıyor** |

**SpiceDB'nin kalıbı farklı ve öğretici:** Çoğu bulgu **fail-closed** yönde (izin verilmesi gerekirken verilmiyor) — kullanılabilirlik sorunu, güvenlik açığı değil. Bu, SpiceDB'nin tasarımının hata durumunda güvenli tarafa düştüğünü gösteriyor. **İstisna: CVE-2026-55866** — koşullu izin beklenirken koşulsuz izin. Bu gerçek bir bypass.

Ayrıca **caveat (koşul) mekanizması SpiceDB'nin en hatalı alanı**: 5 ayrı CVE. Argus koşullu tuple'ları destekleyecekse, bu alan yoğun test gerektirir.

#### Diğerleri

| Ürün | CVE | Tarih | Şiddet | Özet |
|---|---|---|---|---|
| **Ory Keto** | CVE-2026-33505 | 2026-03-20 | **HIGH** | **Sahte pagination token'ları ile SQL injection** |
| **biscuit-auth** | CVE-2022-31053 | 2022-06-17 | **CRITICAL** | **İmza sahteciliği** (< 2.0.0) |
| **biscuit-auth** | CVE-2024-41949/42350 | 2024-07-31 | LOW | Third-party block'ta public key confusion (4.x) |
| **OPA** | CVE-2025-46569 | 2025-05-01 | **HIGH** | Data API HTTP path üzerinden **Rego enjeksiyonu** |
| **OPA** | CVE-2022-36085 | 2022-09-16 | HIGH | `with` keyword ile `WithUnsafeBuiltins` bypass'ı |
| **OPA** | CVE-2024-8260 | 2024-08-30 | MODERATE | Windows'ta SMB force-authentication |
| **cedar-policy** | **(kayıt yok)** | — | — | **OSV'de crates.io ekosisteminde CVE bulunamadı** |
| **casbin** (crates.io) | (kayıt yok) | — | — | — |
| **regorus** (crates.io) | (kayıt yok) | — | — | — |
| **Cerbos** | (kayıt yok) | — | — | — |

**Cedar'ın sicilinin temiz olması dikkate değer** — ve muhtemelen tesadüf değil. Formal doğrulama + DRT + fuzzing kombinasyonu ölçülebilir bir fark yaratıyor gibi görünüyor. (Cedar'ın OpenFGA'dan daha genç ve daha dar kapsamlı olduğu kaydıyla.)

### 6.2 Açık sınıfları ve test yaklaşımları

#### Sınıf 1: Cache anahtarı hataları

CVE-2026-48096 (delimiter injection), CVE-2026-33729 (cached keys bypass), CVE-2026-34972 (list-value collision), CVE-2026-46668 (nested list cache reuse).

**Kök neden:** Cache anahtarı, yapılandırılmış veriden (tuple, koşul bağlamı) **string birleştirme** ile üretiliyor. `user:a|b` ile `user:a` + `b` aynı anahtarı üretebiliyor.

**Argus için savunma:**
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
Uzunluk öneki, delimiter injection'ı **yapısal olarak** imkânsız kılar. Bu, tek satırlık bir savunma ve dört CVE'yi önlerdi.

#### Sınıf 2: Model hataları (kullanıcının kendi ayağına sıkması)

- Fazla geniş relation tanımı
- Yanlış `tuple_to_userset` (yanlış parent üzerinden miras)
- **Wildcard tuple'ları** (`user:*`) — CVE-2022-39341 ve CVE-2022-21646 tam olarak bu
- Exclusion'ın (`but not`) yanlış kullanımı — çift olumsuzlama hataları

**Bu, motorun hatası değil ama motorun sorumluluğudur.** Argus, model yayımlanırken statik analiz yapmalı: "bu model `user:*` wildcard'ı ile bir yazma yetkisi veriyor — emin misiniz?"

#### Sınıf 3: ID confusion ve tenant sızıntısı

- Kullanıcı silinip aynı ID'nin yeniden kullanılması → eski tuple'lar yeni kullanıcıya yetki verir
- Subject ID namespace çakışması: `user:123` ile `service:123`
- Multi-tenant: store/tenant sınırının check yolunda **her adımda** kontrol edilmemesi

**Savunma:** ID'ler global olarak benzersiz ve **yeniden kullanılmaz** (ULID). Tenant ID cache anahtarının parçası (CVE-2026-48096'nın "intra-store poisoning" ifadesi bunun ihlalidir).

#### Sınıf 4: PEP boşluğu ve TOCTOU

"Check yaptım ama enforce etmedim" — AuthZEN spec'inin kendi güven modeli bunu kabul ediyor: *"the PDP must trust the PEP, as the PEP is ultimately responsible for enforcing the decision."*

**IDOR/BOLA (OWASP API Top 10 #1) burada doğar.** Bir yetkilendirme motoru kullanmak IDOR'u **çözmez** — sadece doğru soruyu sormayı mümkün kılar. Kod `/documents/:id` handler'ında check çağırmıyorsa, dünyanın en iyi motoru işe yaramaz.

**Argus'un yapabileceği:** Middleware/extractor seviyesinde **fail-closed by default** bir tasarım. Rust'ın tip sistemi burada gerçek bir avantaj:
```rust
// Resource'a erişim, ancak bir AuthorizedResource token'ı ile mümkün
// Bu token yalnızca check() tarafından üretilebilir
fn get_document(auth: Authorized<Document, Read>) -> Document { ... }
```
Bu, "check yapmayı unutma"yı **derleme zamanı hatası** hâline getirir. Bu, Argus'un Rust'ta olmasının en büyük tek güvenlik avantajıdır ve Go tabanlı rakiplerin yapamayacağı bir şeydir.

#### Sınıf 5: Confused deputy

Argus'un kendi admin API'si, yetki yükseltme yoludur. "Kim tuple yazabilir?" sorusu, Argus'un kendi yetkilendirme modeliyle cevaplanmalıdır (dogfooding) — ama bu, bootstrap problemi yaratır. Ayrı, basit, denetlenmiş bir yol gerekir.

### 6.3 Erişim kontrolü mantığını test etmek

#### Cedar'ın yaklaşımı — sektörün en iyisi

Üç katmanlı **verification-guided development**:

1. **Formal kanıt (Lean 4):** 7 özellik, 5.714 satır kanıt, 1.673 satır model. Tüm kanıtlar 3 dakikada doğrulanıyor. **4 hata** buldu.
2. **Differential Random Testing (DRT):** Milyonlarca rastgele girdi (politika + veri + istek) hem Lean modeline hem Rust üretim koduna gönderiliyor; farklı cevap = hata. `cargo-fuzz` + libfuzzer, hedef başına 6 saat.
3. **Property-Based Testing (PBT):** Modellenmemiş üretim bileşenleri için.

DRT + PBT birlikte **21 hata** buldu. Toplam 25.

**Makalenin çok değerli bir itirafı:** *"Complete line coverage alone does not guarantee effective testing"* — bir generator tam satır kapsamı sağlasa bile üretilen girdilerin çoğu ilginç değildi. Ve DRT bazı hataları **kaçırdı** (non-termination hatası dahil), çünkü tetikleyici girdiyi üretme olasılığı çok düşüktü.

**Girdi üretimi stratejisi:** *"type directed"* — politika, entity ve istek üretimi **korelasyonlu**. Rastgele üretim yetersiz çünkü çoğu rastgele istek hiçbir politikayla eşleşmez ve hedef kodu çalıştırmaz.

#### Argus için somut test planı

| Katman | Araç | Ne test edilir |
|---|---|---|
| **Property-based** | `proptest` 1.11.0 | Invariant'lar (aşağıda) |
| **Differential** | İki bağımsız implementasyon | Naif referans çözümleyici vs optimize edilmiş motor — **aynı cevabı vermeli** |
| **Fuzzing** | `cargo-fuzz` | Model parser, tuple parser, cache key üretimi, cursor decode |
| **Model testleri** | YAML tabanlı (OpenFGA'nın `fga model test`i gibi) | Kullanıcının kendi modeli için assertion'lar |
| **Metamorfik** | Elle | Aşağıdaki dönüşümler |

**Test edilecek invariant'lar (proptest ile ifade edilebilir):**

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

**Invariant 4, 6 ve 7'yi test etmek, incelediğim CVE'lerin en az 8'ini önlerdi.** Bu, spekülasyon değil — CVE özetleri doğrudan bu invariant'ların ihlalidir.

**Formal doğrulama Argus için gerçekçi mi?** Cedar'ın 5.714 satır Lean kanıtı ve 3,4:1 kanıt/model oranı, ciddi bir yatırımdır. Ama **kısmi** yol var: sadece çekirdek karar fonksiyonunun (Cedar'ın Property 1–4 muadili) modellenmesi, tam bir ReBAC çözümleyicisinin doğrulanmasından çok daha ucuzdur. Önerim: **v1 için diferansiyel + property-based test yeterli; formal doğrulama v2 hedefi.**

### 6.4 Fail-open vs fail-closed

**AuthZEN'in duruşu:** Ret, `200 OK` + `{"decision": false}`. Hata (4xx/5xx) ise **karar değildir**. Spec bu ayrımı net yapıyor ama "PDP'ye ulaşılamazsa ne yapılmalı" konusunda PEP'e bırakıyor — güven modeli gereği.

**Sektör pratiği ve doğru cevap: fail-closed.** Ancak bu, bir kullanılabilirlik riski yaratır: PDP çökerse tüm sistem durur.

**Zanzibar'ın cevabı: erişilebilirliği o kadar yükselt ki soru sorulmasın.** >%99,999, 3 yıl, 30+ bölge, 10.000+ sunucu. Bu, çoğu ekibin ulaşamayacağı bir yatırımdır.

**Argus'un cevabı farklı olmalı: PDP'yi ayrı bir hata alanı yapmamak.** Yetkilendirme motoru IdP sürecinin **içindeyse**, "PDP erişilemez" durumu "IdP erişilemez" durumundan ayrı değildir. Ağ hop'unu kaldırmak, bir performans optimizasyonu olduğu kadar bir **erişilebilirlik** optimizasyonudur.

**Circuit breaker + "son bilinen iyi karar" cache'i tehlikelidir:** Yetki geri alınmış bir kullanıcı, PDP kesintisi sırasında cache'teki eski ALLOW ile içeri girer. Bu, saldırganın PDP'ye DoS yaparak yetki elde edebileceği anlamına gelir. **Öneri: kesinti sırasında sadece pozitif kararların TTL'i uzatılmamalı; negatif kararlar serbestçe uzatılabilir.**

### 6.5 Denetlenebilirlik

| Ürün | Mekanizma |
|---|---|
| **OpenFGA** | `Expand` API — nesnenin userset ağacını döndürür |
| **SpiceDB** | Debug/trace (CheckDebugTrace) |
| **Cedar** | `Diagnostics` — kararı belirleyen politikalar + hatalar |
| **OPA** | Decision logs |
| **AuthZEN** | `context.reason_admin` / `context.reason_user` |

**AuthZEN'in `reason_admin`/`reason_user` ayrımı doğru tasarımdır ve Argus benimsemelidir:** Yönetici "policy C076E82F başarısız" görür; kullanıcı "yetersiz ayrıcalık" görür. Kullanıcıya tam nedeni söylemek, kaynak varlığını ve model yapısını sızdırır.

**Argus'un sunması gerekenler:**
1. **Karar izi (decision trace)** — hangi tuple'lar, hangi relation'lar, hangi yol. Debug modunda; üretimde örneklenmiş.
2. **Karar logu** — her karar için `(timestamp, subject, action, resource, decision, model_id, consistency_token, latency)`. PII riski: subject ve resource ID'leri hassas olabilir — hash'lenmiş varyant seçeneği.
3. **Erişim gözden geçirme sorguları** (SOC 2 / ISO 27001 için): "X rolündeki tüm kullanıcılar", "Y kaynağına erişebilen herkes" — bunlar `search_subject` endpoint'idir. Yani AuthZEN'in Search API'si sadece bir özellik değil, bir **uyum gereksinimidir**.

### 6.6 IdP'nin authz motoru olmasının ek riskleri

| Risk | Açıklama | Azaltma |
|---|---|---|
| **Blast radius** | Kimlik + yetki aynı süreçte; bir RCE her ikisini de verir | Süreç içi ayrıcalık ayrımı; authz yazma yolunun ayrı yetkilendirilmesi |
| **Admin API = yetki yükseltme** | Tuple yazabilen, kendine admin verebilir | Admin API'nin **kendisi** ince taneli korunmalı; break-glass ayrı |
| **Multi-tenant izolasyon** | Store sınırı her katmanda kontrol edilmeli | Tenant ID'nin cache anahtarı ve tip sistemi seviyesinde taşınması |
| **Bootstrap** | "Kim ilk admin'i yaratır?" | Ayrı, basit, tam denetlenen bir yol |

---

## BÖLÜM 7 — ARGUS İÇİN KARAR VE MİMARİ

### 7.1 Karşılaştırma özeti

| Kriter | OpenFGA | SpiceDB | Cedar | Ory Keto | Kendi motorumuz |
|---|---|---|---|---|---|
| Dil | Go | Go | **Rust** | Go | **Rust** |
| Model | ReBAC | ReBAC | ABAC+hiyerarşi | ReBAC | ReBAC+ABAC |
| Rust'a gömülebilir | ✗ | ✗ | **✓** | ✗ | **✓** |
| Zookie/consistency token | **✗** | **✓** | Yok (stateless) | ✗ | **✓ (tasarlanacak)** |
| Entity/tuple deposu | ✓ | ✓ | **✗** | ✓ | ✓ |
| ListObjects | ✓ (riskli) | ✓ (riskli) | **✗** | ✓ | ✓ (kısıtlı) |
| Formal doğrulama | ✗ | ✗ | **✓ (7 özellik, Lean 4)** | ✗ | Kısmi (hedef) |
| Bypass CVE sayısı | **~16** | ~3 | **0** | 1 (SQLi) | — |
| Olgunluk | CNCF Incubating | Üretim | Üretim (AWS) | **Bakım modu** | Yok |
| Lisans | Apache-2.0 | *DOĞRULANMADI* | Apache-2.0 | Apache-2.0 | Bizim |
| Ölçülmüş gecikme | 89–746 µs (memdb) | — | **4–11 µs** | — | Hedef: <100 µs |
| Son sürüm | v1.19.0 (25 Ağu 2026) | v1.56.1 (26 Ağu 2026) | 4.12.0 (28 Tem 2026) | v26.2.0 (20 Mar 2026) | — |

### 7.2 Karar: **gömülü, kendi motorumuz, Cedar'dan ilham alan**

#### Gerekçe

**1. Harici motor Rust'ta mümkün değil.** OpenFGA ve SpiceDB Go'dur. Rust'tan kullanmak = gRPC hop'u = her istekte 1–15 ms + ayrı hata alanı. Bir IdP'nin token endpoint'i için kabul edilemez. Rust ReBAC crate'leri (`openfga-rs` 25 indirme/90gün, `authzed` 9) **ölüdür**.

**2. Cedar tek başına yetmez.** Entity store'u yok, ListObjects'i yok. ReBAC'ın zor kısmını (ilişki depolama + transitif çözümleme) çözmüyor. Ama **politika değerlendirme katmanı olarak mükemmel**: 4–11 µs, formal doğrulanmış, sıfır CVE, Rust-native.

**3. CVE verileri, "olgun ürünü al" argümanını zayıflatıyor.** OpenFGA'nın 16 bypass CVE'si, bu problem sınıfının **doğası gereği** zor olduğunu gösteriyor — hazır çözüm almak riski ortadan kaldırmıyor, sadece başkasının hatalarını devralıyorsunuz. Ve OpenFGA'yı gömemediğimiz için hata düzeltmelerini de kontrol edemiyoruz.

**4. Rust'ın tip sistemi, rakiplerin veremeyeceği bir güvenlik avantajı sunuyor** (Bölüm 6.2, Sınıf 4).

#### Riskin dürüst kabulü

Kendi motorunu yazmak, incelediğim 42 CVE'nin kendi versiyonlarını yazmak demektir. Bu kararın tek savunması, **Bölüm 6.3'teki test disiplinini gün 1'den uygulamaktır.** Cedar bunu yaptı ve sicili temiz. OpenFGA yapmadı ve 16 bypass CVE'si var. Fark tesadüf değil.

### 7.3 Arayüz tasarımı

#### Çekirdek trait — bu, tüm sistemin taahhüdüdür

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

#### Derleme-zamanı enforcement (Rust'ın süper gücü)

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

Bu kalıp, "check yapmayı unutma" hatasını (IDOR'un birincil kaynağı) **yapısal olarak** ortadan kaldırır. Go tabanlı hiçbir motor bunu veremez.

### 7.4 Veri modeli

#### Tuple — Zanzibar'ın grameri, iyileştirmelerle

```
object_type : object_id # relation @ subject_type : subject_id [# subject_relation]
                                                    [with condition_name(params)]
```

**Zanzibar'dan sapmalar ve gerekçeleri:**

| Karar | Gerekçe |
|---|---|
| `subject_id` string (integer değil) | Zanzibar integer kullanıyor (Google'ın iç ID'si). Argus'un dış kimlikleri var. **ULID zorunlu** — yeniden kullanım yok |
| Koşullu tuple desteği | ABAC ihtiyacı gerçek. **Ama SpiceDB'nin 5 caveat CVE'si göz önüne alınarak yoğun test** |
| `store_id` her satırda + her cache anahtarında | Tenant izolasyonu (CVE-2026-48096 dersi) |

#### Postgres şeması

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

**Neden iki indeks:** Check ileri yönde, ListObjects ters yönde yürür. Tek indeks ikisini de veremez — bu, ListObjects'in neden pahalı olduğunun depolama-seviyesi açıklamasıdır.

**Neden MVCC (created_xid/deleted_xid):** Zookie'nin temelidir. `deleted_xid > ?` ile herhangi bir geçmiş revision'da sorgu yapılabilir. SpiceDB'nin Postgres backend'i tam olarak bunu yapıyor ve **standart dışı eklenti gerektirmiyor**.

#### Consistency token (zookie eşdeğeri)

```rust
/// Opak, imzalı. İstemci içeriğine bağımlı olmamalı.
pub struct ConsistencyToken(Box<str>);
// içerik: base64(HMAC(store_id || xid || issued_at))
```

**Sözleşme (istemciye açıkça anlatılmalı):**
1. `write()` bir token döndürür.
2. İstemci, korunan kaynağın **yanında** bu token'ı saklar (Zanzibar'ın modeli).
3. O kaynak için check yaparken `AtLeastAsFresh(token)` gönderir.
4. Argus, o revision'dan eski cache girdisi kullanmayacağını garanti eder.

**GC penceresi:** Token, `--gc-window`'dan (öneri: 24 saat) eski olursa `SnapshotExpired` döner ve istemci `FullyConsistent`'a düşer. Bu davranış dokümante edilmelidir.

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
    │    ⚠ UZUNLUK-ÖNEKLİ hash — string concat DEĞİL (CVE-2026-48096)
    │    Beklenen hit oranı: %10-20 (Google'ın gerçek verisi!)
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

#### ABAC koşulları: Cedar'ı gömün

Katman 3'te bir koşullu tuple'a rastlanırsa, koşulu Argus'un kendi mini-diliyle değerlendirmek yerine **cedar-policy crate'ini çağırın**:

- Ölçülmüş 4–11 µs — bütçe içinde
- 7 formal kanıtlanmış özellik
- Sıfır CVE
- Rust-native, FFI yok
- Bakımını AWS yapıyor

**Bu, "kendi motorunu yaz" kararının en akıllı istisnasıdır:** ReBAC graph'ını kendimiz yazıyoruz (kimse Rust'ta vermiyor), ama politika/koşul değerlendirmesini yazmıyoruz (Cedar zaten en iyisini yapmış).

#### Cache invalidation

**Üç mekanizma birlikte:**

1. **Revision cache anahtarında** → yapısal invalidation. Yeni revision = yeni anahtar. Eski girdi erişilemez hâle gelir (SpiceDB modeli). **Bu ana mekanizmadır.**
2. **Watch stream'i** → yazma olduğunda etkilenen alt-ağaçlar proaktif düşürülür.
3. **TTL** → son savunma hattı. Pozitif 10 sn, **negatif ≤1 sn**.

#### Zorunlu kotalar (hasar kontrolü)

| Limit | Değer | Gerekçe |
|---|---|---|
| Çözümleme derinliği | 25 | OpenFGA ile aynı; döngü koruması (CVE-2023-43645) |
| Çözümleme genişliği | 10 | Fan-out patlaması koruması |
| Check zaman aşımı | 100 ms | Sıcak yol bütçesi |
| **Search deadline** | **1 s (sert)** | ListObjects tehlikesi |
| **Search max sonuç** | **1000** | Sayfalama zorunlu |
| Yazma başına tuple | 1000 | OpenFGA'nın 100'ünden yüksek; batch outbox için |
| Store başına tip | 200 | Model karmaşıklığı sınırı |

### 7.6 AuthZEN PDP olmak — kontrol listesi

Argus'un AuthZEN uyumlu olması için gerekenler:

| # | Gereksinim | Zorunluluk | Argus'ta |
|---|---|---|---|
| 1 | `POST /access/v1/evaluation` | **REQUIRED** | `check()` |
| 2 | `POST /access/v1/evaluations` + 3 semantik | Opsiyonel (yapılmalı) | `batch_check()` |
| 3 | `POST /access/v1/search/resource` | Opsiyonel (yapılmalı) | `search_resources()` |
| 4 | `POST /access/v1/search/subject` | Opsiyonel (**uyum için gerekli**) | `search_subjects()` |
| 5 | `POST /access/v1/search/action` | Opsiyonel | `search_actions()` |
| 6 | `GET /.well-known/authzen-configuration` | **REQUIRED** | Metadata endpoint |
| 7 | Ret = `200` + `{"decision": false}` | **MUST** | Hata semantiğini karıştırma |
| 8 | `X-Request-ID` yankısı | **MUST** (varsa) | Trace korelasyonu |
| 9 | Bilinmeyen alanları yok say | **MUST** | serde `#[serde(flatten)]` dikkatli |
| 10 | TLS + PEP kimlik doğrulaması | MUST / SHOULD | mTLS veya OAuth |
| 11 | I-JSON (RFC 7493) | SHOULD | UTF-8, IEEE754 sınırları |
| 12 | DoS korumaları | SHOULD | Payload boyutu, nesting derinliği |
| 13 | `reason_admin` / `reason_user` | Opsiyonel (yapılmalı) | Bilgi sızıntısı kontrolü |

**Ek: consistency token'ı `context.consistency_token` altında taşıyın**, `capabilities` dizisinde ilan edin ve bunu AuthZEN WG'ye boşluk olarak bildirin.

**Ve stratejik olarak:** "OAuth 2.0 Token Issuance Profile" ve "Authorization Claims Profile" taslaklarını takip edin. Bir IdP'nin bunları implemente etmesi, Argus'u AuthZEN ekosisteminde **benzersiz** kılar — çünkü diğer PDP satıcıları token vermez.

### 7.7 Yol haritası

| Faz | Kapsam | Doğrulama |
|---|---|---|
| **F0** | `AuthzEngine` trait'i + naif referans implementasyon (cache yok, indeks yok, doğruluk odaklı) | Bu, diferansiyel testin **referans oracle**'ı olacak |
| **F1** | Postgres MVCC tuple deposu + consistency token + graph çözümleme + derinlik/genişlik limitleri | proptest ile 10 invariant; F0'a karşı diferansiyel |
| **F2** | Cedar entegrasyonu (koşullu tuple'lar) + alt-problem cache + singleflight | Invariant 6 (cache şeffaflığı) — **CVE sınıfını kapatır** |
| **F3** | AuthZEN PDP endpoint'leri + `.well-known` + batch semantikleri | Invariant 7 (batch tutarlılığı) |
| **F4** | Search API'leri (sert deadline + sayfalama) | **Invariant 4** (check/list uyumu) — 5 CVE'nin sınıfı |
| **F5** | Materialized index (roaring bitmap) sıcak relation'lar için | Invariant 4 ve 6 yeniden; indeksli/indekssiz diferansiyel |
| **F6** | Ağırlıklı graf planlayıcı | Planlayıcılı/planlayıcısız diferansiyel (OpenFGA'nın v1.18.2'de düzelttiği hataların dersi) |
| **F7** | Çekirdek karar fonksiyonunun Lean modeli (Cedar Property 1–4 muadili) | Formal kanıt |

**Her fazda F0 referansına karşı diferansiyel test zorunludur.** Bu, Cedar'ın DRT'sinin Argus'a uyarlanmasıdır ve incelediğim CVE'lerin çoğunu önleyecek tek disiplindir.

---

### KAYNAKLAR

**Birincil — akademik**
- [Zanzibar: Google's Consistent, Global Authorization System](https://www.usenix.org/system/files/atc19-pang.pdf) — USENIX ATC 2019 (PDF indirilip metni çıkarıldı; Tablo 2, §2.1, §2.2, §3.2.4, §4)
- [Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization (Extended)](https://arxiv.org/abs/2403.04651) — arXiv, Mart 2024; §5.2 benchmark (PDF metni çıkarıldı)
- [How We Built Cedar: A Verification-Guided Approach](https://arxiv.org/abs/2407.01688) — FSE Companion '24; §3.2 yedi özellik, Tablo 1 (PDF metni çıkarıldı)
- [Delegation Without Trust](https://arxiv.org/abs/2609.00267) — Dantuluri & Sundi, 31 Ağu 2026; §7.2–7.3 (PDF metni çıkarıldı)
- [Cedar OOPSLA 2024](https://dl.acm.org/doi/10.1145/3649835) — ACM DL (erişilemedi, arXiv sürümü kullanıldı)

**Birincil — spesifikasyon**
- [Authorization API 1.0 Final](https://openid.net/specs/authorization-api-1_0-final.html) — 11 Ocak 2026
- [Final Specification Approved](https://openid.net/authorization-api-1-0-final-specification-approved/) — 12 Ocak 2026, oylama 81/1/25
- [AuthZEN Working Group](https://openid.net/wg/authzen/) · [AuthZEN blog etiketi](https://openid.net/tag/authzen/)
- [Yeni WG taslakları (AARP, COAZ)](https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/) — 15 Haziran 2026
- [openid/authzen deposu](https://github.com/openid/authzen)

**Birincil — ürün dokümantasyonu**
- [OpenFGA Configuration Options](https://openfga.dev/docs/getting-started/setup-openfga/configuration) — tüm flag varsayılanları
- [OpenFGA Query Consistency](https://openfga.dev/docs/interacting/consistency) — zookie yokluğu
- [OpenFGA Relationship Queries](https://openfga.dev/docs/interacting/relationship-queries) — BatchCheck limitleri, ListObjects uyarıları
- [OpenFGA Model Migration](https://openfga.dev/docs/modeling/migrating/migrating-models)
- [OpenFGA ReadChanges](https://openfga.dev/docs/interacting/read-tuple-changes)
- [OpenFGA Running in Production](https://openfga.dev/docs/getting-started/running-in-production)
- [OpenFGA Blog](https://openfga.dev/blog) — weighted graph resolution, 21 Tem 2026
- [OpenFGA GitHub Releases](https://github.com/openfga/openfga/releases) — v1.19.0, 25 Ağu 2026
- [OpenFGA CNCF sayfası](https://www.cncf.io/projects/openfga/) — Incubating, 28 Eki 2025
- [SpiceDB Consistency](https://authzed.com/docs/spicedb/concepts/consistency) — ZedToken, 4 seviye, CockroachDB uyarısı
- [SpiceDB Datastores](https://authzed.com/docs/spicedb/concepts/datastores)
- [SpiceDB Releases](https://github.com/authzed/spicedb/releases) — v1.56.1, 26 Ağu 2026
- [Ory Keto](https://github.com/ory/keto) · [Releases](https://github.com/ory/keto/releases) — v26.2.0, 20 Mar 2026
- [cedar-policy docs.rs](https://docs.rs/cedar-policy/latest/cedar_policy/) — 4.12.0
- [cedar-spec](https://github.com/cedar-policy/cedar-spec) · [RFC 0032 Dafny→Lean](https://github.com/cedar-policy/rfcs/blob/main/text/0032-port-formalization-to-lean.md)
- [microsoft/regorus](https://github.com/microsoft/regorus) — OPA v1.2.0 uyumu, 4,6 ms vs 45,2 ms
- [biscuit-auth/biscuit](https://github.com/biscuit-auth/biscuit) — denetim aranıyor
- [Oso docs](https://www.osohq.com/docs)

**Birincil — güvenlik ve paket verisi**
- [OSV.dev API](https://api.osv.dev/v1/query) — tüm CVE tabloları (OpenFGA 26, SpiceDB 16, Keto, OPA, biscuit-auth kayıtları)
- crates.io API — tüm sürüm/indirme/lisans verileri, 8 Eylül 2026

**Erişilemeyenler (bu oturumda doğrulanamadı):** SpiceDB dispatch/caching dokümanları (404), authzen-interop.net katılımcı listesi (ağ hatası), OpenFGA Postgres migration SQL'i (GitHub API rate limit), SpiceDB lisans dosyası, ACM DL Cedar makalesi (403).

---

**Üç uyarıyı tekrarlıyorum:** (1) 2,6 µs rakamı bir HMAC doğrulamasıdır, ReBAC check'i değil — hedef olarak alınmamalıdır. (2) Zanzibar'ın "10 ms" p95'i yalnızca 10 saniye bayat veri kabul edildiğinde geçerlidir; tazelik istendiğinde 60 ms'dir. (3) OpenFGA'nın 16 authorization-bypass CVE'si, hazır çözüm almanın riski ortadan kaldırmadığını gösteriyor — Cedar'ın sıfır CVE'si ise test disiplininin işe yaradığını.
