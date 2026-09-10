# 19. Yüksek erişilebilirlik ve dağıtık mimari

> `ARGUS.md` §19'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§19 §X` referansları aynı anlamda.


**Kapsam:** Rust + PostgreSQL ile sıfırdan yazılan genel amaçlı IdP için HA/dağıtım kararları

> **Metodoloji notu:** Bu oturumda WebSearch bütçesi (200 çağrı) erken tükendi; araştırmanın büyük bölümü birincil kaynakların (resmi dokümanlar, satıcı mühendislik blogları, GitHub tartışmaları, PostgreSQL release notes) doğrudan çekilip okunmasıyla yapıldı. Aşağıdaki her rakamın yanında kaynak ve tarih var. Doğrulayamadıklarımı `[DOĞRULANMADI]` ile işaretledim. **Hiçbir rakam uydurulmadı.**

---

### 0. YÖNETİCİ ÖZETİ — 8 CÜMLELİK CEVAP

1. **2026'da sektörün gittiği yön net: Infinispan/Redis gibi ayrı dağıtık durum katmanlarını atıp, uçucu durumu senkron replike edilmiş veritabanına koymak.** Keycloak bunu 17 Temmuz 2026'da "stateless / Multi-Cluster v2" olarak duyurdu; Zitadel Şubat 2026'da saf event-sourcing'den "hibrit ilişkisel modele" geçtiğini açıkladı.
2. Bunun ölçülmüş bedeli **kimlik doğrulama etkileşimi başına ~8–10 ms ek gecikme ve veritabanı CPU/IOPS'unda ~2 kat artış**tır (Keycloak, 2026-07-17). Bu, bir IdP için kabul edilebilir bir takas.
3. **Çok bölgeli senkron yazma kimlik için çalışmıyor.** Keycloak 26.4 ölçümü: site'lar arası RTT 0 ms'de p99 = 47 ms, 10 ms'de 84 ms, 20 ms'de 130 ms; bir önceki sürümde 20 ms RTT **1.076 ms p99** üretiyordu. Keycloak resmî sınırı: **site'lar arası DB gidiş-dönüş <5 ms önerilir, <10 ms zorunlu.**
4. Kanidm'in 2 node'da tıkanmasının sebebi ölçek değil, **bilinçli bir CAP tercihi**: quorum'suz, AP, attribute-level last-write-wins. Bu tasarım "kilitlenme/oturum yazımı partition sırasında da çalışsın" der ama **çakışma çözümünü güvenlik açığına dönüştürür**. Argus bu yolu seçmemeli.
5. **İptal (revocation) yayını için Redis pub/sub bir güvenlik hatasıdır.** Redis resmî dokümanı kelimesi kelimesine: "mesaj sonsuza kadar kaybolur". İptal sinyali kaybolursa iptal edilmiş bir token yaşamaya devam eder. Doğru desen **transactional outbox + polling**'dir — Keycloak tam olarak bunu yapıyor, **varsayılan polling aralığı 100 ms**.
6. **Read replica'dan token iptali/oturum doğrulama okumak gerçek bir güvenlik riskidir**, teorik değil. CockroachDB'nin follower read'i bile **en az 4,2 saniye geçmişten** okur. Argus'ta iptal kontrolü asla asenkron replica'ya gitmemeli.
7. **Argus için önerilen topoloji: tek bölge, 3 AZ, senkron quorum commit'li PostgreSQL (Patroni veya CloudNativePG), stateless Rust node'ları, uçucu durum DB'de, iptal yayını DB outbox + 100–250 ms polling, node-yerel `revocation_epoch` cache.** Redis opsiyonel bir hızlandırıcı olmalı, doğruluk kaynağı değil.
8. Çok bölgelilik **veri replikasyonu ile değil, Okta'nın yaptığı gibi bölge başına izole "hücre" (cell) ile** çözülmeli — bu aynı zamanda veri yerleşimi (data residency) probleminin de tek gerçekçi cevabı.

---

## BÖLÜM 1 — MEVCUT IdP'LERİN HA MİMARİLERİ

### 1.1 Keycloak — sektörün en iyi belgelenmiş HA hikâyesi (ve en dürüst itirafı)

#### 1.1.1 Eski model: Infinispan cross-site replication (Multi-Site v1)

İki bağımsız Keycloak kümesi, **düşük gecikmeli ağ** ile bağlı iki site'ta çalışır:

| Katman | Replikasyon | Not |
|---|---|---|
| Kullanıcı/realm/client/offline session | **Senkron DB replikasyonu** | Aurora PostgreSQL ile test edildi |
| Oturum verisi | Infinispan `replicated` cache → harici Data Grid → karşı site'a **senkron** | Cross-site "backup" kanalı |
| Realm cache invalidation | `work` cache üzerinden invalidation mesajı | Node-yerel cache'ler |

Keycloak asenkron replikasyonu **bilinçli olarak reddetti**. Resmî gerekçe (keycloak.org multi-cluster/concepts):

> "Lost changes leading to users being able to log in with an old password because database changes are not replicated to the other site."

Bu, bir IdP için asenkron çoklu-site'ın neden yanlış olduğunun en net tek cümlelik ifadesidir: **asenkron replikasyon = parola değişikliğinin kaybolması = eski parolayla giriş.**

**Belgelenmiş sınırlar (keycloak.org/high-availability/multi-cluster/concepts, erişim 2026-09-08):**
- "This setup is tested and supported only with **two sites**." — üç site desteklenmiyor.
- Site arızasında load balancer `/lb-check` ile tespit eder, trafiği yönlendirir; **kurtarma <2 dakika**, ama bu sırada bir kısım istek hata alır.
- "A successful failover requires a setup **not degraded from previous failures**." — Bir önceki arızadan sonra manuel resync yapılmamışsa failover **veri kaybettirir**.
- Infinispan'ın "out of sync" durumu: "**currently difficult to monitor**, and it would need a **full manual re-sync**."

Bu son madde kritik: v1 mimarisi, **operatörün elle müdahale etmediği sürece sessizce bozulabilen** bir sistemdir.

#### 1.1.2 Yeni model: Multi-Cluster v2 + "stateless" (Keycloak 26.7, Temmuz 2026 — preview)

Kaynak: [Multi-Cluster v2 and Stateless Mode now in Preview](https://www.keycloak.org/2026/07/multi-cluster-v2-and-stateless-mode), Alexander Schwartz, **17 Temmuz 2026**.

Bu Argus için en önemli tek kaynak. Keycloak, Infinispan'ı kimlik doğrulama yolundan **tamamen çıkarıyor**:

| Veri | Eskiden | Şimdi (stateless) |
|---|---|---|
| Authentication session (login ortasındaki kullanıcı) | Infinispan distributed cache | **Veritabanı** |
| Action token (e-posta doğrulama, parola sıfırlama, OAuth code) | Infinispan | **Veritabanı** |
| Login failure counter (brute-force) | Infinispan | **Veritabanı** |
| Realm/authorization verisi | Node-yerel cache | Node-yerel cache (değişmedi) |
| Küme içi cache invalidation | JGroups | JGroups (değişmedi) |
| **Kümeler arası cache invalidation** | Infinispan cross-site | **DB outbox tablosu + polling, varsayılan 100 ms** |

**Ölçülmüş maliyet (blog yazısından doğrudan):**
- "**Approximately 8-10 milliseconds of additional latency per authentication interaction**, negligible for interactive login flows."
- "**Database CPU load and IOPS can increase by roughly a factor of two.**"

**Ön koşul (doğrudan alıntı):**
> "A synchronously replicated database and a low-latency network between sites (**less than 5 ms suggested, below 10 ms required for database round-trip**)."

**Tasarım felsefesi (doğrudan alıntı):**
> "The new stateless feature **prioritizes consistency over availability**. Every write is synchronously replicated, so no data is lost during failover at the cost of requiring a low-latency network between sites."

**Kabul edilen sınırlar:**
- "**Single-region only**: Synchronously replicated databases are generally not available across multiple regions."
- Patch upgrade sıfır kesinti; **minor/major upgrade için bir site hariç hepsini kapatmak gerekiyor**.

**Neden Infinispan'ı attılar (kendi itirafları):**
- Kaybolan/yeniden başlayan node'da distributed cache rebalancing
- "Transient failures in login flows if a node unexpectedly disappears"
- "In large installations, the **login failure cache can grow significantly**, consuming substantial memory and causing **long rebalancing times**"
- Tam küme yeniden başlatması (minor upgrade) uçucu durumu sıfırlıyordu
- Mimari Kubernetes ve AWS'e bağlıydı (AWS Lambda + Prometheus alert'leri gerekiyordu)

> **Argus için ders:** Keycloak, 10+ yıllık dağıtık cache yatırımını 2026'da terk etti. Sıfırdan yazan bir proje **hiç o yola girmemeli.** Uçucu durum PostgreSQL'de, cross-cluster sinyalizasyon DB outbox'ta.

#### 1.1.3 Keycloak'ın "farklı bölgelere yaymayın" gerekçesi — rakamlarla

Kaynak: [Keycloak Performance Benchmarks (26.4)](https://www.keycloak.org/2025/10/keycloak-benchmark), **Ekim 2025**.

**Test koşulları:** Amazon Aurora PostgreSQL 17.5, 100.000 kullanıcı, 3 Keycloak pod'u 3 farklı AZ'de, yük üreteci 20–50 adet t4g.small.

**Ağ gecikmesinin p99 yanıt süresine etkisi** (500 login/s + 2.500 token refresh/s altında):

| Site'lar arası RTT | KC 26.3 p99 | KC 26.4 p99 |
|---|---|---|
| 0 ms | 51 ms | 47 ms |
| **10 ms** | 116 ms | 84 ms |
| **20 ms** | **1.076 ms** | 130 ms |

Bu tablo, "önermiyoruz" ifadesinin arkasındaki fiziği gösteriyor: **20 ms RTT'de 26.3 çöküyor (21× bozulma).** 26.4 çok daha dayanıklı ama hâlâ 20 ms'de 2,8× bozulma var. Kıtalar arası RTT 70–150 ms olduğuna göre bu bölgede sistem kullanılamaz hale gelir.

**Sebep amplifikasyon:** Keycloak dokümanı açıkça diyor ki her istek veri güncellendiğinde site'lar arasında **birden çok tur** yapabilir; "Multiple database interactions per request amplify this effect." Yani 20 ms RTT × 5–7 yazma = 100–140 ms taban gecikme, üstüne kuyruklama.

#### 1.1.4 Keycloak kapasite rakamları (Argus'un kendi hedefini konumlandırmak için)

| Metrik | Değer | Kaynak |
|---|---|---|
| 1 vCPU başına | **15 login/s** | KC benchmark 26.4, Ekim 2025 |
| 1 vCPU başına | **120 refresh token isteği/s** | Aynı |
| 3 pod × 24 vCPU + 4 GB, db.r8g.2xlarge | 500 login/s, 2.500 refresh/s | Aynı |
| 3 pod × 40 vCPU + 8 GB, db.r8g.4xlarge | 1.000 login/s, 5.000 refresh/s | Aynı |
| 3 pod × 74 vCPU + 8 GB, db.r8g.16xlarge | 2.000 login/s, 10.000 refresh/s | Aynı |
| Cache 10k→200k entry | Aurora peak CPU **%77,77 → %63,77**; bellek 1,30 → 1,45 GB | Aynı |

Rapor "Keycloak scales vertically almost linearly in the tested range" diyor.

> **Argus için kıyas hedefi:** Java/Infinispan'lı Keycloak 1 vCPU'da 15 login/s yapıyor. Argon2id maliyeti login'in baskın maliyeti olduğu için Rust'ın avantajı **login'de değil, refresh/introspection/JWKS yolunda** ortaya çıkacak. Argus'un gerçekçi hedefi: refresh yolunda vCPU başına 300–600/s. `[TAHMİN — ölçülmedi]`

#### 1.1.5 Keycloak failure mode özeti

| Senaryo | Davranış |
|---|---|
| Tek node kaybı (v1, Infinispan) | Distributed cache en az 2 node'da tuttuğu için veri kaybı yok, ama **rebalancing** ve login akışlarında geçici hatalar |
| Tek node kaybı (v2, stateless) | **Hiçbir şey olmaz** — auth yolunda Infinispan trafiği yok |
| Tam küme yeniden başlatma (v1) | Devam eden login'ler, brute-force sayaçları **sıfırlanır** |
| Tam küme yeniden başlatma (v2) | Korunur (DB'de) |
| Site kaybı (v1) | LB yönlendirir, <2 dk; **önceki arızadan resync yapılmamışsa veri kaybı** |
| Site kaybı (v2) | Senkron DB sayesinde **veri kaybı yok**, kullanıcılar giriş yapmış kalır |
| Site'lar arası ağ kopması | v1: Infinispan out-of-sync, tespit zor, **tam manuel resync** gerekir. v2: senkron DB kendi quorum'una göre davranır; consistency>availability |
| **Split-brain** | v1'de Infinispan seviyesinde mümkün ve **izlenmesi zor**. v2'de split-brain riski DB katmanına devredilir (Patroni/DCS quorum'u çözer) |

---

### 1.2 Zitadel — event sourcing'in HA'daki bedeli (ve geri adım)

**Mimari:** Event Sourcing + CQRS. Yazma tarafı immutable event store'a yazar; okuma tarafı **projeksiyon** (denormalize view) okur.

**Tutarlılık modeli:** Resmî doküman (zitadel.com/docs/concepts/architecture/software): "The combination of Event Sourcing and CQRS makes Zitadel **eventual consistent**." Query view'lar **asenkron** güncellenir; ancak **ID ile tekil kaynak araması event store'a karşı doğrulanarak strong consistency** alabiliyor.

**Projeksiyon gecikmesi HA'da ne yapıyor?** İşte kritik nokta: Zitadel bakımcısının 2024 tarihli açıklaması (GitHub Discussion [#7636](https://github.com/zitadel/zitadel/discussions/7636)):

> "At the moment we do not (yet) support the usage of **read replicas** because we want to keep most data **consistent**."

Yani event-sourced bir IdP bile, projeksiyon gecikmesi güvenlik anlamı taşıdığı için **read replica kullanmayı reddediyor.** Bu, Bölüm 2.4'teki "iptal edilmiş token replica'da geçerli görünür mü?" sorusunun sektörden gelen dolaylı cevabıdır: **evet, o yüzden kimse yapmıyor.**

**Multi-region duruşu (aynı tartışma):**
- **PostgreSQL ile:** çok-AZ tek bölge küme + **felaket kurtarma amaçlı** cross-region replikasyon. Aktif-aktif **yok**.
- **CockroachDB/Spanner ile:** "cross region active-active deployments work" — ama "You might sacrifice a little on the latency side if your regions are far apart."

**2026 GELİŞMESİ — Zitadel event sourcing'den kısmen geri çekiliyor.** Kaynak: [Scaling Cloud-Native Identity: Optimizing Performance with Caching](https://zitadel.com/blog/scaling-cloud-native-identity-optimizing-performance-with-caching), Florian Forster (kurucu/CEO), **12 Şubat 2026**:

> "We are currently working on a **major evolution of our core engine—shifting to a hybrid relational model** that combines the speed of traditional tables with the auditability of events. This change will **drastically reduce the need for complex read models**."

Ve caching connector'ları için ölçülmüş bir rakam:
> PostgreSQL cache connector için: "We see customers running **north of 30,000 requests per second** using just this default setup."

Ayrıca in-memory cache hakkında uyarı: çok-container ortamda sticky session olmadan kullanılamaz — "users may experience data inconsistencies (e.g., **being logged out on one request and logged in on the next**)".

| Zitadel failure mode | Davranış |
|---|---|
| Node kaybı | Stateless uygulama katmanı; DB'ye devredilmiş |
| Projeksiyon gecikmesi | Okuma tarafı bayat olabilir; kritik okumalar event store'a düşer |
| Redis cache kaybı | Cache miss → DB'ye düşer (degrade, kesinti değil) |
| Split-brain | Uygulama katmanında yok; DB katmanına devredilmiş |
| Bölge kaybı (Postgres) | DR failover, **veri kaybı riski var** (asenkron cross-region) |

> **Argus için ders:** Event sourcing'i "HA çözer" diye seçme. Zitadel bunu 8 yıl uyguladıktan sonra hibrit ilişkisel modele dönüyor. **Argus doğrudan ilişkisel + ayrı append-only audit tablosu ile başlamalı.**

---

### 1.3 Kanidm — neden 2 node'da tıkandı

Kaynak: [Replication Design and Notes](https://kanidm.github.io/kanidm/master/developers/designs/replication_design_and_notes.html) (erişim 2026-09-08) ve GitHub Discussion [#4099](https://github.com/kanidm/kanidm/discussions/4099).

**Bu bir "tıkanma" değil, bilinçli bir CAP tercihidir ve tercih Argus için yanlıştır.**

Kanidm **AP** sistemidir (CAP'te Availability + Partition tolerance; Consistency feda edilir). Gerekçesi doğrudan tasarım dokümanında: quorum gerektirmek, partition sırasında yazamamak demektir; ve bu IDM için kabul edilemez — çünkü **oturum oluşturma ve güvenlik kilitlemesi (lockout) partition sırasında da çalışmalı**.

**Nasıl çalışıyor:**
- **Seçim yok, quorum yok.** Tüm node'lar yazma kabul eder.
- Her değişiklik bir **CID** alır: `(timestamp, server UUID)`. Timestamp'ler "her zaman ileri gider, asla geri gitmez" (gerektiğinde ileri sürüklenir).
- **Attribute-level last-write-wins:** her attribute kendi son değişim CID'sini tutar; çakışmada **yüksek CID kazanır**.
- **RUV (Replica Update Vector):** her originating server için min/max değişiklik aralığı. Consumer RUV'unu supplier'a gönderir, supplier farkı hesaplar. Bu, **proxy replikasyon**a izin verir — full-mesh gerekmez.
- Topoloji rolleri: Read-Write, **Transport Hub** (yazma kabul etmez, sadece iletir), Read-Only.
- Silme = **tombstone**; replikasyon penceresinden sonra reap edilir.

**Sınırlar ve failure mode'lar (dokümanın kendi "Stated Limitations" bölümünden):**

| Sorun | Sonuç |
|---|---|
| **Zombie entry** | Node çok geri kalırsa tombstone o node'a ulaşmadan reap edilir → silinmiş kayıt **dirilir**. Kanidm bunu "**lagging node'u dondurarak**" (inbound+outbound replikasyonu durdurarak) önlüyor |
| **Uniqueness çakışması** | En olası çakışma kaynağı. Node'lar uzun ayrı kalırsa aynı e-posta/username iki node'da yaratılabilir → entry conflict state'e düşer |
| **Schema morphing** | Merge sırasında entry sınıf değiştirip şemayı ihlal edebilir (group→person) |
| **Tombstone penceresi takası** | Uzun pencere zombie'yi önler ama çakışma riskini artırır |
| **Tutarlılık garantisi yok** | "Clients may read stale data; eventual consistency only" |

**Node sayısı:** 2 node resmî destekli. 3 node "**technically unsupported**" ama çalışıyor — sebep mimari değil, **test eksikliği** (Discussion #4099).

> **Argus için ders — bu en önemli negatif dersimiz:**
>
> LWW çakışma çözümü kimlikte bir **güvenlik açığıdır**, sadece bir veri tutarsızlığı değil. Somut senaryo: Partition sırasında A node'unda kullanıcı parolasını değiştirir (CID=100), B node'unda saldırgan eski oturumundan bir credential ekler (CID=101). Merge'de **saldırganın değişikliği kazanır.** Aynı şekilde: bir node'da hesap kilitlenir, diğerinde daha yüksek CID'li bir "unlock" olur → kilit kaybolur.
>
> Kanidm bunu attribute-level çözünürlük ve dondurma ile hafifletiyor ama **kaldıramıyor**. Argus quorum'lu (CP) bir sistem olmalı; "partition sırasında yazamamak" kimlikte **doğru** davranıştır.

---

### 1.4 Rauthy + Hiqlite — Raft'lı gömülü yaklaşım

Kaynak: [Rauthy HA docs](https://sebadob.github.io/rauthy/config/ha.html), [hiqlite crate](https://crates.io/crates/hiqlite), [openraft](https://github.com/databendlabs/openraft) (erişim 2026-09-08).

**Ne yaptılar:** Hiqlite = `rusqlite` üzerine async wrapper + `openraft` ile Raft konsensüsü. Rauthy'nin tüm instance'ları **tek bir HA cache katmanı** paylaşır.

**Neden Raft?** Çünkü Rauthy'nin bazı verileri **yalnızca cache'te** yaşıyor — özellikle **authorization code**'lar. Bir authorization code'un tek bir node'da kalması, load-balanced ortamda token exchange'in başarısız olması demek. Redis'e bağımlı olmadan bunu çözmenin yolu gömülü konsensüs.

**openraft'ın standart Raft'a göre farkı (kendi README'sinden):** generalized membership change (tek işlemde keyfi node kümesi değişimi) ve azaltılmış election conflict oranı (split vote yeni term'e zorlamıyor).

**Ölçülmüş rakamlar:**
- Hiqlite yazarının ilk benchmark'ı: **ucuz tüketici M2 SSD'de ~24.500 tekil insert/s**; 3 ayrı process, localhost ama **gerçek networking** ile. Eski SATA SSD'li makinede **~16.500 insert/s**.
- Rauthy dokümanı: **3 replika önerilir, 5 daha yüksek dayanıklılık için.** "at some point, the write throughput will degrade" — sonsuz ölçeklenemez.
- Graceful shutdown **en az 15 saniye**, leader election / küme durumu değişimi sırasında **25–30 saniye**.
- Postgres kullanılsa bile "you should provide a **persistent volume**" — Raft state diskte yaşamalı.

**Failure mode'lar:**

| Senaryo | Davranış |
|---|---|
| 3 node'dan 1 kaybı | Quorum korunur (2/3), yazma devam eder, leader election gerekiyorsa kısa kesinti |
| 3 node'dan 2 kaybı | **Quorum kaybı → yazma durur.** Raft'ın doğası; CP sistem |
| Split-brain | **Yapısal olarak imkânsız** — Raft'ın temel garantisi |
| Node ekleme | Yazma throughput'u düşer (her yazma daha çok node'a replike) |

> **Argus için ders:** Rauthy'nin çözümü **doğru ama Argus'un ölçeğine yanlış.** Raft yazma throughput'u node sayısıyla ters orantılıdır; 5 node üstü mantıksız. Argus zaten PostgreSQL'e sahipse **ikinci bir konsensüs sistemi taşımanın anlamı yok** — Postgres'in kendi replikasyonu (Patroni + etcd) aynı garantiyi zaten veriyor. Rauthy'nin Raft'a ihtiyacı, "Postgres opsiyonel, SQLite ile de çalışsın" hedefinden doğuyor; Argus'un böyle bir kısıtı yok.

---

### 1.5 Ory Hydra / Kratos — HA'yı tamamen DB'ye devretme

**Tasarım:** Hydra ve Kratos **stateless** process'lerdir. Consent/login state, session, refresh token — hepsi SQL veritabanında. Uygulama katmanında hiçbir küme koordinasyonu, gossip, cache invalidation yok. HA = "DB'yi HA yap, N tane kopya çalıştır, LB koy."

**Bu tasarımın gerçek dünyada çarptığı duvar — en değerli negatif veri noktası:**

GitHub Discussion [ory/kratos#3134](https://github.com/ory/kratos/discussions/3134) — global CockroachDB ile ciddi performans sorunları:
- `SELECT session_devices.* FROM session_devices WHERE session_id = $1` — **düz bir primary key lookup'ta 230 ms ortalama gecikme**
- Giriş yapmış kullanıcılar için **toplam ~1 saniye ek gecikme**
- CockroachDB desteğinin teşhisi: tablolar `GLOBAL` yapılandırılmadığı için sorgular bölgeler arası dolaşıyor

Ory bakımcısı (aeneasr) üç şey söylüyor ve üçü de Argus için doğrudan geçerli:

1. **Fizik:** "Every software system will have this problem... because of physics. If your SQL queries travel 400 ms through deep sea cables, then **every SQL query will be slow**."
2. **Açık kaynak ≠ Ory Network:** "open-source Kratos lacks proprietary global optimization code available only in Ory's managed network" — global TCP routing gibi şeyler gerekiyor.
3. **Hukuk teknikle çelişiyor:** "**GLOBAL tables violate regional data privacy laws** (GDPR, CCPA, etc.) when storing personal information."

Üçüncü madde çok önemli: CockroachDB'nin çok bölgeli düşük gecikme çözümü (`GLOBAL` tablolar) **kişisel veri için yasal olarak kullanılamaz.** Yani "CockroachDB kullan, multi-region çözülür" cümlesi kimlik iş yükü için **yanlıştır**.

**Ory Network'ün gerçek mimarisi** ([ory.com/blog/global-identity-and-access-management-multi-region](https://www.ory.com/blog/global-identity-and-access-management-multi-region)):
- Kubernetes, ArgoCD, Crossplane, Grafana, CockroachDB
- **Tam replikasyon değil, coğrafi sharding** — "data homing": kişisel veri kullanıcının kendi ülkesinde kalır, ama "unified user identity across regions" korunur
- Ölçek iddiası: günde **~3 milyar API isteği**, **11.000+ production environment**
- Reddedilen alternatifler: homomorfik şifreleme ("another 1 million times" hızlanma gerekir), column-level encryption (FK/unique constraint ve range query'lerle uyumlu açık kaynak çözüm yok)

**Satıcı iddiası `[BAĞIMSIZ DOĞRULANMADI]`:** Ory + Cockroach Labs ortak blogu, ChatGPT'nin **800M+ haftalık aktif kullanıcı** için login'i bu kombinasyonun çalıştırdığını söylüyor ([ory.sh/blog/the-future-of-identity-ory-and-cockroach-labs-iam-for-agentic-ai](https://www.ory.sh/blog/the-future-of-identity-ory-and-cockroach-labs-iam-for-agentic-ai)). Bu pazarlama içerikli bir ortak yazıdır; teknik detay (bölge sayısı, p99, tablo yerleşimi) verilmiyor.

---

### 1.6 Authentik — ve 2026'da Redis'ten çıkışı

Kaynak: [docs.goauthentik.io/core/architecture](https://docs.goauthentik.io/core/architecture) (sürüm 2026.8, erişim 2026-09-08).

**Bileşenler:** Server (Core + embedded outpost) · Worker (arka plan görevleri) · PostgreSQL.

**Dikkat çeken:** 2026.8 mimari dokümanında **Redis artık zorunlu bileşen olarak listelenmiyor.** 2025.8 release notes'ta sebebi yazıyor:

> "The authentik worker and background tasks have been reworked... This rework also allowed us to **not depend on Redis for background tasks**."

Celery → Postgres tabanlı görev kuyruğuna geçtiler. Geçiş "seamless migration path" içermiyor; yüksek trafikli kurulumlarda **upgrade sırasında görev kaybı** olabiliyor (release notes'ta açık uyarı var). Helm chart'ta Redis hâlâ var (8.0→8.2 güncellendi), cache/oturum için.

**HA modeli:** Server ve worker yatay ölçeklenir (stateless), durum PostgreSQL'de. Keycloak v2 / Ory ile aynı desen.

> **Argus için ders:** Üç bağımsız proje (Keycloak, authentik, Zitadel) 2025–2026'da aynı yöne gitti: **ayrı durum sistemini sil, PostgreSQL'e taşı.** Bu bir moda değil, operasyonel gerçeğin dayattığı yakınsama.

---

### 1.7 Karşılaştırma tablosu — IdP HA modelleri

| Ürün | Tutarlılık modeli | Dağıtık durum nerede | Max node/site | Split-brain | Node kaybında | Operasyonel maliyet |
|---|---|---|---|---|---|---|
| **Keycloak v1** (≤26.6) | Senkron DB + senkron Infinispan | Harici Infinispan | **2 site** (test/destek) | Infinispan seviyesinde mümkün, **izlemesi zor** | Rebalancing + geçici login hataları | **Çok yüksek** (Infinispan kümesi + monitoring + Lambda + failback prosedürü) |
| **Keycloak v2 stateless** (26.7+, preview) | Senkron DB, consistency>availability | **PostgreSQL** | 2+ küme, tek bölge | DB'ye devredilmiş | Etkisiz | **Düşük** (sadece HA DB) |
| **Zitadel** | Eventual (CQRS); ID lookup'ta strong | PostgreSQL / CockroachDB (+opsiyonel Redis cache) | Sınırsız (stateless) | Yok | Etkisiz | Orta (event store + projeksiyon operasyonu) |
| **Kanidm** | **Eventual, AP, LWW** | Kendi replikasyonu (RUV) | **2 (resmî), 3 test dışı** | **Var — çakışma normal işleyiş** | Diğer node yazma alır | Düşük ama **çakışma riski güvenlik riski** |
| **Rauthy** | **Linearizable (Raft)** | Hiqlite (SQLite+openraft) | **3–5** | **İmkânsız** | 1/3 kaybı OK; 2/3 kaybı **yazma durur** | Düşük (gömülü) |
| **Ory Hydra/Kratos** | DB'ye devredilmiş | SQL veritabanı | Sınırsız (stateless) | Yok | Etkisiz | Düşük (uygulama), DB'ye kayar |
| **Authentik** | DB'ye devredilmiş | PostgreSQL (+Redis cache) | Sınırsız | Yok | Etkisiz | Düşük |

---

## BÖLÜM 2 — POSTGRESQL İLE HA

### 2.1 Failover araçları — 2026 durumu

| Araç | Konum | Güçlü yanı | Zayıf yanı | 2026 tavsiyesi |
|---|---|---|---|---|
| **Patroni** (4.1.x) | VM + Kubernetes | Endüstri standardı; etcd/Consul/ZooKeeper/K8s DCS; REST API; self-healing (`pg_rewind` ile eski primary'yi geri alır); **DCS Failsafe Mode** | Ayrı DCS kümesi taşıma yükü; 2 node'da quorum sorunları | **VM/bare-metal için varsayılan** |
| **CloudNativePG** (1.28/1.29, 1.30 devel) | Sadece Kubernetes | Patroni'siz; **doğrudan Kubernetes API server'ı DCS olarak kullanır**, ayrı etcd yok; declarative CRD; StatefulSet kullanmaz, kendi PVC yönetimi | K8s dışında yok | **Greenfield Kubernetes için varsayılan** |
| **pg_auto_failover** | VM | Patroni'den basit, repmgr'dan otomatik; 2 node'da quorum derdi yok | **Monitor tek hata noktası** — primary düştüğünde monitor de düşükse failover olmaz | Küçük kurulumlar |
| **repmgr** | VM | Basit, DCS gerekmez | Node'lar arası doğrudan iletişim → **split-brain riski daha yüksek** | Yeni kurulumda önerilmez |
| **Stolon** | — | — | Proje aktivitesi durmuş | `[DOĞRULANMADI — arşiv durumu teyit edilmedi]` |

**Patroni'nin kritik davranışı (resmî FAQ, erişim 2026-09-08):**
- Otomatik failover = "**leader race**": leader lock TTL süresinde yenilenmezse DCS'ten düşer, tüm node'lar aday olur, ilk lock'u alan promote olur.
- **DCS kaybedilirse:** "all the Patroni clusters that rely on that DCS will go to **read-only mode** – unless DCS Failsafe Mode is enabled."
- **DCS'te çoğunluk kaybedilirse:** "The DCS will become unresponsive, which will cause Patroni to **demote the current read/write Postgres node**."

> **Argus için doğrudan sonuç:** etcd kümesi çökerse PostgreSQL **salt-okunur** olur. Yani **Argus'un login akışı durur ama token doğrulama devam edebilir.** Bu, Bölüm 7'deki kademeli bozulma tasarımının temel taşı. **DCS Failsafe Mode mutlaka açılmalı.**

**Patroni failover süresi — gerçek formül:**
- Kısıt: `ttl >= loop_wait + 2 * retry_timeout`
- Minimum değerler: `ttl=20, loop_wait=2, retry_timeout=3`
- Primary arızasında en kötü durum: `loop_wait + primary_start_timeout + loop_wait` (`primary_start_timeout=0` ise sadece `loop_wait`)
- `patronictl list` çıktısı `loop_wait` saniyeye kadar gecikmeli olabilir
- Saha raporu `[İKİNCİL KAYNAK]`: `ttl=20, loop_wait=5, retry_timeout=5, watchdog.safety_margin=3` ile **sağlıklı altyapıda 25 saniyenin altında failover** (stackharbor.com bilgi bankası, 2026)

**CloudNativePG primary arıza akışı** (docs 1.28, Failure Modes):
1. Operator, **en düşük replikasyon gecikmesine sahip** standby'ı promote eder
2. `-rw` service yeni primary'ye yönlenir
3. Arızalı pod `-r` ve `-rw` service'lerinden çıkar
4. Standby'lar yeni primary'den replike etmeye başlar
5. Eski primary PVC'si varsa `pg_rewind` ile geri katılır, yoksa backup'tan yeni standby yaratılır

CNPG bir CNCF projesidir; **olgunluk seviyesi (Sandbox/Incubating) bu araştırmada doğrulanamadı** `[DOĞRULANMADI]`.

### 2.2 Senkron mu asenkron mu — bir IdP için cevap

#### 2.2.1 `synchronous_commit` seviyeleri

| Değer | Commit ne zaman döner | Veri kaybı riski | IdP'de kullanımı |
|---|---|---|---|
| `off` | WAL diske bile yazılmadan | **Crash'te son işlemler kaybolur** | Asla |
| `local` | Yerel WAL fsync sonrası | Node kaybında kayıp | Yalnız tek-node dev |
| `remote_write` | Standby WAL'i **OS'a yazdı** | Standby OS crash'inde kayıp | Kabul edilebilir orta yol |
| `on` (varsayılan senkron) | Standby WAL'i **fsync etti** | Kayıp yok (standby ayakta) | **Argus'un varsayılanı** |
| `remote_apply` | Standby WAL'i **uyguladı** — replica'da görünür | Kayıp yok + **replica'da anında okunabilir** | Yalnız kritik yollarda |

#### 2.2.2 Ölçülmüş maliyet

Kaynak: [EDB — The Cost Implications of PostgreSQL Synchronous Replication](https://www.enterprisedb.com/blog/the-varying-cost-synchronous-replication).
**Test:** 3× AWS `r5.2xlarge` (8 vCPU, 64 GB), **tek AZ**, ~150 GB veri (pgbench scale 10.000), her sunucuda 2× io2 EBS (10.000 IOPS; biri data biri WAL), gecikme Linux `tc` ile yapay eklendi, `synchronous_standby_names = '2 ("pg-node-2","pg-node-3")'`.

| Koşul | İstemci | `local` yazma gecikmesi | `remote_write` | Fark |
|---|---|---|---|---|
| **10 ms ağ gecikmesi** | 40 | 9,5 ms | **16 ms** | **+%67** |
| **10 ms ağ gecikmesi** | 80 | 17 ms | **20 ms** | **+%19** |
| **3 ms ağ gecikmesi** | 40 | — | TPS `local`'ın **%92**'si | — |
| **3 ms ağ gecikmesi** | 80 | — | TPS `local` ile **eşit** | — |
| **3 ms**, 120+ istemci | — | — | `local` ile **%1 içinde** | — |
| **3 ms** sorgu gecikmesi | tümü | tüm modlar **1 ms içinde birbirine yakın** | | |

Ayrıca Percona ölçümü: `synchronous_commit=off`, `remote_apply`'a göre **2 kattan fazla** performans gösteriyor ([percona.com/blog/postgresql-synchronous_commit-options...](https://www.percona.com/blog/postgresql-synchronous_commit-options-and-synchronous-standby-replication/)).

**Kritik yorum:** Senkron replikasyonun maliyeti **yükle birlikte düşüyor** — çünkü artan eşzamanlılık, WAL flush'ları gruplar (group commit). Yani "senkron replikasyon pahalı" iddiası **düşük eşzamanlılıkta doğru, IdP'nin gerçek yük profilinde büyük ölçüde yanlış**.

**AZ'ler arası gerçek gecikme:** Aynı bölgede AZ'ler arası RTT tipik olarak **1–2 ms** mertebesindedir `[KESİN RAKAM DOĞRULANMADI — cloudping.co veya AWS resmî SLA'sı bu oturumda çekilemedi]`. Ancak Keycloak'ın "site'lar arası **<5 ms önerilir, <10 ms zorunlu**" eşiği (2026-07-17) tam olarak çok-AZ tek bölge senaryosunu tarifliyor ve EDB'nin 3 ms testinin "neredeyse bedava" sonucuyla uyumlu.

#### 2.2.3 Argus için karar

**Bir IdP veri kaybı tolere edemez.** Somut nedenler:

| İşlem | Kayıp olursa ne olur |
|---|---|
| Parola değişimi | **Kullanıcı eski parolayla giriş yapabilir** (Keycloak'ın kendi gerekçesi) |
| Token/oturum iptali | **İptal edilmiş oturum yaşamaya devam eder** |
| MFA kaydı silme | Saldırganın eklediği authenticator geri gelir |
| Refresh token rotation | **Reuse detection kırılır** — çalınmış token tekrar kullanılabilir |
| Brute-force sayacı | Kilitleme sıfırlanır |
| Hesap kilitleme/deaktivasyon | **İşten çıkarılan çalışanın erişimi geri gelir** |

**Karar:**
- **Varsayılan:** `synchronous_commit = on` + **quorum commit**: `synchronous_standby_names = 'ANY 1 (standby_a, standby_b)'`. Bu, 3 AZ'de **bir standby'ın kaybını tolere ederken** veri kaybını sıfırlar.
- **Neden `ANY 1` ve `FIRST 1` değil:** `ANY N` en hızlı N standby'ı bekler; belirli bir standby yavaşlarsa sistem takılmaz.
- **Kritik nokta — kendini vurma tuzağı:** Tek standby ile `synchronous_commit=on` yapılırsa ve standby düşerse **primary tüm yazmalarda asılır**. Bu yüzden **en az 2 standby + `ANY 1`** zorunludur. Aksi halde HA çözümü tek başına kesinti kaynağı olur.
- **Audit log ve telemetri yazmaları** ayrı bir bağlantıda `synchronous_commit = local` ile yazılabilir (session-level `SET`) — audit satırının kaybı güvenlik kararını değiştirmez, sadece iz kaybettirir. Bu, IOPS'un %30–50'sini senkron yoldan çıkarır. `[TASARIM ÖNERİSİ — ölçülmedi]`

### 2.3 Failover sırasında Argus ne yapar

Gerçekçi zaman çizelgesi (Patroni, `ttl=20/loop_wait=5/retry_timeout=5`):

| t | Olay | Argus'un görevi |
|---|---|---|
| 0 s | Primary düşer | Aktif sorgular TCP hatası/timeout alır |
| 0–20 s | Leader lock TTL'i dolar | **Yazma imkânsız.** Login, token exchange, refresh **başarısız** |
| ~20–25 s | Leader race, yeni primary promote | — |
| ~25 s | VIP/DNS/pooler yeni primary'ye yönelir | Bağlantı havuzu yeniden kurulur |
| 25 s+ | Normal | — |

**Argus bu 25 saniyede ne yapmalı — bu tasarım kararıdır, varsayılan davranış değil:**

1. **JWT doğrulama devam etmeli.** İmza doğrulama DB gerektirmez. JWKS bellekte. `revocation_epoch` node-yerel cache'te. → **Kaynak sunucular etkilenmez.** Bu, Argus'un en değerli kademeli bozulma özelliğidir.
2. **`/token` refresh akışı durur** (rotation yazma gerektirir). İstemcilere **`503 + Retry-After: 5`** dönülmeli, `400 invalid_grant` **asla** — çünkü `invalid_grant` istemci SDK'larının çoğunda kullanıcıyı **logout ettirir**. Bu ayrım, 25 saniyelik bir DB failover'ının milyonlarca kullanıcıyı çıkış yaptırmasıyla hiç fark edilmemesi arasındaki farktır.
3. **Login akışı durur** → kullanıcıya "geçici sorun, tekrar deneyin" (kimlik hatası değil).
4. **Bağlantı havuzu davranışı:** `sqlx`/`deadpool` havuzundaki tüm bağlantılar ölü. Health-check ile hızlı tahliye + exponential backoff ile yeniden kurma şart; yoksa 25 saniyelik kesinti, havuz doygunluğu yüzünden 2–3 dakikaya uzar.

**Bağlantı dizesi:** `libpq` (PostgreSQL 18 dokümanı, erişim 2026-09-08) çok-host + `target_session_attrs=read-write` destekliyor — istemci ilk kabul edilebilir host'u seçer. Ancak bu **failover'ı bir sonraki bağlantı kurulumunda** çözer, mevcut bağlantıları değil. `load_balance_hosts=random` ile standby'lara okuma dağıtımı yapılabilir. **Not:** `sqlx`'in bu semantiği tam desteklediği doğrulanmadı `[DOĞRULANMADI]`; Argus kendi failover-aware havuz mantığını yazmalı veya pooler'a devretmeli.

### 2.4 Read replica — hangi sorgu nereye gider

#### 2.4.1 Kritik soru: **iptal edilmiş token replica'da hâlâ geçerli görünür mü?**

**Cevap: EVET, ve bu teorik değil, ölçülebilir bir açıktır.**

Kanıt zinciri:

1. **PostgreSQL streaming replication varsayılan olarak asenkrondur.** Replikasyon gecikmesi normal işletimde ms mertebesindedir ama **checkpoint, uzun sorgu, VACUUM, disk baskısı veya ağ sıkışması altında saniyelere ve dakikalara çıkar** — ve tam da bu anlarda (yük altında) saldırı olma olasılığı yüksektir.
2. **Sektörün davranışı bu riski doğruluyor:** Zitadel bakımcısı, read replica desteğini **"most data consistent" kalsın diye reddediyor** ([zitadel#7636](https://github.com/zitadel/zitadel/discussions/7636)).
3. **Dağıtık DB'lerde bile durum aynı:** CockroachDB'nin `follower_read_timestamp()` fonksiyonu **en az 4,2 saniye geçmişten** okur (docs.cockroachlabs.com/docs/stable/follower-reads, erişim 2026-09-08). Yani "en yakın replikadan hızlı okuma" = **4,2 saniyelik iptal penceresi**.

**Somut saldırı senaryosu:**
> Kullanıcı "tüm cihazlarımdan çık" der veya SOC bir hesabı devre dışı bırakır. Primary'de `revocation_epoch` artırılır. Bu sırada Argus node'u #7 introspection isteğini bir read replica'ya yönlendirir. Replikasyon 3 saniye geride. Saldırgan bu 3 saniyede refresh token'ı kullanır → **yeni, tam ömürlü bir access token alır.** Erişim iptalden **saatler sonrasına kadar** uzar.

**Argus için kural — pazarlık edilemez:**

| Sorgu tipi | Replica'ya gidebilir mi | Gerekçe |
|---|---|---|
| **Token iptali / `revocation_epoch` kontrolü** | **HAYIR** | Yukarıdaki senaryo |
| **Oturum doğrulama (aktif mi)** | **HAYIR** | Aynı |
| **Refresh token rotation + reuse detection** | **HAYIR** (yazma zaten) | Bayat okuma reuse detection'ı kırar |
| **Parola/credential doğrulama** | **HAYIR** | Parola değişimi/kilitleme bayat kalır |
| **Brute-force sayacı okuma** | **HAYIR** | Sayaç bayatsa kilit çalışmaz |
| **Consent kontrolü** | **HAYIR** | Geri çekilmiş consent bayat kalır |
| **JWKS / discovery metadata** | Evet (ama zaten bellekte olmalı) | Anahtar rotasyonu planlı ve yavaş; ayrıca overlap penceresi var |
| **Admin kullanıcı arama/listeleme** | **EVET** | Bayatlık zararsız |
| **Admin raporları, denetim izi görüntüleme** | **EVET** | Salt okuma analitik |
| **Kullanıcı profil sayfası okuma (self-service)** | Evet, dikkatle | Read-your-writes gerekli (aşağıda) |
| **Grup/rol üyeliği (yetkilendirme kararı)** | **HAYIR** | Kaldırılan rol bayat kalır |

**Genel kural:** *Bir sorgunun sonucu bir **güvenlik kararını** etkiliyorsa, primary'den okunur.*

#### 2.4.2 Bunu güvenli yapmanın yolları

| Teknik | Nasıl | Maliyet | Argus'ta yeri |
|---|---|---|---|
| **Primary'ye pinleme** | Güvenlik-kritik okumaları hep primary'ye | Primary'de okuma yükü | **Varsayılan** |
| **`synchronous_commit = remote_apply`** | Commit, standby **uygulayana** kadar bekler → replica'da anında görünür | En pahalı mod (Percona: `off`'a göre 2× yavaş) | Yalnız iptal/kilitleme yazmalarında, session-level `SET` ile |
| **LSN tabanlı read-your-writes** | Yazmadan sonra `pg_current_wal_lsn()` alınır, cookie/token'a konur; replica'da `pg_last_wal_replay_lsn()` ile karşılaştırılır, geride ise primary'ye düşülür | Uygulama karmaşıklığı | Self-service profil ekranları için |
| **Bounded staleness** | Lag eşiği aşan replica devre dışı | İzleme gerekir | Genel sağlık koruması |
| **Node-yerel epoch cache + kısa TTL** | Bkz. Bölüm 4.5 | Küçük | **Ana ölçekleme kaldıracı** |

**En pratik Argus deseni:** Replikadan hiç güvenlik okuması yapma. Bunun yerine **iptal durumunu node belleğine cache'le** ve o cache'i outbox/polling ile **100–250 ms içinde** güncelle. Bu, hem replica'dan hızlı hem primary'den doğrudur.

### 2.5 Connection pooling ve failover etkileşimi

| Pooler | Failover davranışı | Performans (Tembo benchmark) | Argus'a uygunluk |
|---|---|---|---|
| **PgBouncer** | Replica failover desteği zayıf; `PAUSE`/`RESUME` manuel; genelde VIP/DNS değişimine bağımlı | **<50 istemcide en iyi gecikme ve throughput** | Basit, kanıtlanmış; Patroni'nin callback'leriyle birleştirilmeli |
| **pgcat** (Rust) | **Otomatik failover + read replica yük dağıtımı + sharding** | >50 istemcide PgBouncer'dan iyi; PgBouncer'a göre −%17…+%24 aralığında | **Argus için en uygun** — Rust, read/write split yerleşik |
| **Supavisor** (Elixir) | Tenant pausing ile graceful failover; çok kiracılı | **%80–160 daha yüksek gecikme** | Argus'un profiline uymuyor |
| **Odyssey** | — | — | Değerlendirilmedi `[DOĞRULANMADI]` |

Kaynak: [Tembo — Benchmarking PostgreSQL connection poolers](https://legacy.tembo.io/blog/postgres-connection-poolers/).

**Kritik uyarı:** PgBouncer'ı **transaction pooling** modunda kullanmak, prepared statement'ları ve geçici tabloları kısıtlar. Argus `sqlx` ile prepared statement'a yoğun olarak dayanır. PgBouncer 1.21+ named prepared statement desteği ekledi ama Argus'un bunu doğrulaması gerekir `[DOĞRULANMADI]`. **pgcat veya doğrudan uygulama havuzu (sqlx) + pgcat kombinasyonu** daha az sürprizli.

### 2.6 PostgreSQL 18 — HA açısından ne değişti

Kaynak: [PostgreSQL 18.0 Release Notes](https://www.postgresql.org/docs/release/18.0/) (Eylül 2025).

| Özellik | HA/IdP anlamı |
|---|---|
| **Asenkron I/O (AIO)** — `io_method` (Linux'ta `io_uring`, her yerde worker fallback); `io_combine_limit`, `pg_aios` view | Sequential/bitmap scan ve VACUUM hızlanır. **IdP'de doğrudan etkisi sınırlı** (iş yükü index lookup ağırlıklı) ama VACUUM hızlanması oturum tablolarındaki bloat baskısını azaltır |
| **`uuidv7()`** — zaman sıralı UUID | **Argus için önemli.** UUIDv4 birincil anahtarlar B-tree'yi parçalar; UUIDv7 insert'leri index'in sonuna yazar. Oturum/token tabloları gibi yüksek insert hacimli tablolarda index bloat ve WAL hacmi ciddi azalır |
| **`idle_replication_slot_timeout`** | Terk edilmiş logical slot'ların WAL'i sonsuz biriktirip **diski doldurup primary'yi öldürmesini** engeller. Bu klasik bir üretim kesinti sebebidir |
| **`pg_recvlogical --enable-failover`** | Failover slot'ları — logical replication failover'dan sağ çıkar |
| **`pg_createsubscriber --all`** | Tüm veritabanları için logical replica oluşturma |
| **Logical replication çakışma loglama** | Aktif-aktif denemelerinde çakışmaların görünür olması |
| **Major upgrade'de planner istatistiklerinin korunması** | Upgrade sonrası "performans çukuru" ortadan kalkar — **planlı bakım penceresini kısaltır** |
| **OAuth istemci kimlik doğrulama desteği** | Argus'un kendisi PostgreSQL'e OAuth ile bağlanabilir (ironik ama gerçek) |

**Not:** Logical replication slot senkronizasyonu (`sync_replication_slots`) **PostgreSQL 17** ile geldi; 18 bunun araç desteğini tamamlıyor.

**PostgreSQL 19:** Normal takvimde Eylül 2026'da beklenir. Bu araştırmada içeriği doğrulanamadı `[DOĞRULANMADI]`.

---

## BÖLÜM 3 — ÇOK BÖLGELİ (MULTI-REGION) KİMLİK

### 3.1 Login akışı kaç yazma yapıyor — çok bölgeliliğin gerçek maliyeti

Bir OIDC authorization code + PKCE akışında Argus'un yapması gereken yazmalar:

| # | Yazma | Zorunlu mu |
|---|---|---|
| 1 | Authentication session (login formu gösterildiğinde) | Evet (Keycloak v2 bunu DB'ye taşıdı) |
| 2 | Brute-force / login failure sayacı güncelleme | Evet (başarısızlıkta) |
| 3 | Authorization code (tek kullanımlık, kısa ömürlü) | Evet |
| 4 | User session kaydı | Evet |
| 5 | Refresh token kaydı (rotation ailesiyle) | Evet |
| 6 | `last_login_at` güncelleme | Genelde |
| 7 | Audit event | Evet |
| 8 | DPoP `jti` / nonce kaydı (DPoP kullanılıyorsa) | Duruma göre |

**~5–7 yazma.** `[MİMARİ TAHMİN — Keycloak'ın "multiple database interactions per request" ifadesiyle uyumlu, ancak Argus için ölçülmedi]`

Şimdi çarpalım:

| Topoloji | Yazma başına konsensüs maliyeti | 6 yazmalık login |
|---|---|---|
| Tek AZ | ~0 | taban |
| **3 AZ, tek bölge** (RTT ~1–2 ms) | ~1–2 ms | **+6–12 ms** ✅ |
| İki site, 10 ms RTT | ~10 ms | +60 ms ⚠️ |
| İki site, 20 ms RTT | ~20 ms | +120 ms ❌ (Keycloak 26.3'te 1.076 ms p99) |
| **us-east ↔ eu-west** (~80–90 ms RTT `[DOĞRULANMADI]`) | ~40–90 ms | **+240–540 ms** ❌❌ |

Bu tablo, Keycloak'ın "farklı bölgelere yaymayın" cümlesinin tüm gerekçesidir. **Argus için pipeline'ı kısaltmak (yazma sayısını 6'dan 3'e indirmek) çok bölgeliliği mümkün kılmaz, sadece acıyı yarıya indirir.**

### 3.2 Dağıtık SQL seçenekleri — kimlik iş yükü için

| Ürün | Tutarlılık | Cross-region yazma | Postgres uyumu | Kimlik iş yükü için sorun | Lisans/maliyet |
|---|---|---|---|---|---|
| **CockroachDB** | Serializable, Raft | Var (`REGIONAL BY ROW` ile row-level homing) | Wire uyumlu, ama PL/pgSQL ve birçok uzantı yok | **Ory'nin yaşadığı: PK lookup'ta 230 ms.** `GLOBAL` tablolar GDPR'a aykırı (kişisel veri için) | 24.3.0'dan itibaren **CockroachDB Software License**. Enterprise Free: **<$10M yıllık ciro**, telemetri zorunlu, **7 gün telemetri gitmezse throttle**. Üstü ücretli |
| **Aurora DSQL** | Snapshot isolation, **OCC**, strong consistency | **Aktif-aktif, iki bölgesel endpoint** | PG16 uyumlu | **Tetikleyici yok, PL/pgSQL yok, geçici tablo yok, işlem başına 3.000 satır limiti, işlem başına 1 DDL, bağlantı 1 saatte kopar, tek `postgres` DB, sadece `C` collation.** Kıtalar arası multi-region **yok** | AWS'e kilitli |
| **YugabyteDB** | Raft, serializable/snapshot | xCluster + geo-partitioning | En yüksek PG uyumu iddiası (PG kod tabanını yeniden kullanıyor) | Bu araştırmada bağımsız benchmark bulunamadı `[DOĞRULANMADI]` | Apache 2.0 (core) |
| **TiDB** | Raft | Var | **MySQL uyumlu** | Argus Postgres'e yazılıyor — dışarıda | Apache 2.0 |
| **Vitess** | MySQL sharding | Multi-region için tasarlanmadı | MySQL | Dışarıda | Apache 2.0 |
| **Neon** | Postgres, storage/compute ayrımı | Cross-region replica sınırlı | **Tam PostgreSQL** | Serverless soğuk başlangıç IdP için risk; multi-region aktif-aktif yok. Databricks satın alması sonrası yol haritası belirsiz `[DOĞRULANMADI]` | — |
| **AlloyDB / AlloyDB Omni** | Postgres uyumlu | Cross-region replikasyon (asenkron) | Yüksek | Aktif-aktif değil | GCP'ye kilitli (Omni hariç) |
| **Spanner (PG arayüzü)** | External consistency (TrueTime) | Gerçek global | Kısıtlı PG arayüzü | Maliyet; GCP kilidi | GCP |

#### 3.2.1 CockroachDB'yi kimlik için doğru anlamak

Tablo yerleşimleri (docs.cockroachlabs.com, erişim 2026-09-08):

| Yerleşim | Okuma | Yazma | Kimlikte kullanımı |
|---|---|---|---|
| `REGIONAL BY TABLE` | Home region'da hızlı, dışarıdan yavaş | Home region'da hızlı | Bölgeye özgü tablolar |
| `REGIONAL BY ROW` | Satırın home region'ında hızlı; dışarıdan **düşük gecikmeli follower read** | Home region'da hızlı; dışarıdan yazma **yavaş** | **Kullanıcı verisi için doğru araç** — satır bazında bölgeye pin |
| `GLOBAL` | **Her bölgeden düşük gecikmeli** | **Yüksek** (commit-wait adımı) | Realm/client/policy metadata için ideal; **kişisel veri için yasal olarak kullanılamaz** |

**Survival goal:**
- `ZONE` (varsayılan): AZ kaybından sağ çıkar
- `REGION`: bölge kaybından sağ çıkar, ama **tüm yazmalar en az bir ek bölgeye danışmak zorunda** → yazma gecikmesi artar. Super region için **en az 3 bölge** gerekir.

**Sert sınırlar:**
- Follower read (`follower_read_timestamp()`): **en az 4,2 saniye geçmiş** — güvenlik kararı için kullanılamaz
- `GLOBAL` tablolarda **node'lar arası RTT >150 ms ise düzensiz yüksek gecikme** `[Cockroach dokümanından arama sonucu üzerinden; doğrudan sayfa doğrulanmadı]`
- Yeni kümelerde `--max-offset 250ms` öneriliyor (`GLOBAL` yazma gecikmesini düşürmek için)

**Sonuç:** CockroachDB, "kullanıcıyı bölgeye pin'le, metadata'yı global yap" deseni için gerçekten tasarlanmış tek olgun açık ürün. Ama Ory'nin deneyimi gösteriyor ki **out-of-the-box çalışmıyor** — tablo yerleşimlerini tek tek elle tasarlamak, sorguları yeniden yazmak ve global TCP routing eklemek gerekiyor. Ve lisans değişikliği (2024-11) self-host'u ticari bir karar haline getirdi.

### 3.3 PostgreSQL logical replication ile çok bölge (aktif-aktif)

| Çözüm | Durum | Çakışma çözümü |
|---|---|---|
| **pgEdge / Spock** | Açık kaynak, aktif geliştirme | LWW + kullanıcı tanımlı |
| **pgactive** (AWS) | RDS için | LWW |
| **EDB Postgres Distributed (PGD)** | Ticari | Gelişmiş, CRDT sayaçlar dahil |
| **PostgreSQL 18 native** | Aktif-aktif değil; çakışma **loglama** eklendi | — |

**Argus için verdiğim cevap: HAYIR.**

Gerekçe Kanidm bölümüyle aynı ve daha güçlü: **LWW çakışma çözümü kimlikte bir güvenlik açığıdır.** Aktif-aktif logical replication, iki bölgede aynı kullanıcının parolasını/MFA'sını/rollerini eşzamanlı değiştirebilir ve **saat kaymasına göre kazananı seçer.** Bir IdP'de "son yazan kazanır" demek, "saldırgan saatini ileri alırsa kazanır" demektir.

İstisna: **çakışmayan, bölgeye özgü tablolar** (örn. bölgesel audit log'ları) için logical replication tek yönlü toplama amacıyla kullanılabilir.

### 3.4 Veri yerleşimi (data residency) — çok bölgeliliğin gerçek sürücüsü

Burada kritik bir tersine çevirme var: **Çoğu ekip "multi-region" ister çünkü düşük gecikme sanır. Gerçekte multi-region ihtiyacının %90'ı yasal veri yerleşimidir — ve bu iki hedef birbiriyle çelişir.**

- Düşük gecikme çok bölgeli okuma ister → veriyi **her yere kopyala**
- Veri yerleşimi → veriyi **hiçbir yere kopyalama**

Ory'nin bakımcısı bunu doğrudan söylüyor: `GLOBAL` tablolar kişisel veri için GDPR/CCPA ihlali. Ory Network bu yüzden **"data homing"** yapıyor: kişisel veri kullanıcının ülkesinde kalır, sadece kimlik referansı global.

**Sektörün gerçek cevabı: replikasyon değil, izolasyon.**

**Okta — cell-based architecture** (okta.com whitepapers, "Scaling Okta to 50 Billion Users" / "How Okta Builds and Runs Scalable Infrastructure"):
- Her "cell" = **izole, shared-nothing, aynı Okta altyapısının tam kopyası** — router ve load balancer'dan veritabanına kadar
- Cell'ler bağımsız çalışır → **hata izolasyonu availability stratejisinin temeli**
- AWS bölgeleri üzerinde: Kuzey Amerika, Avrupa, Avustralya, Japonya
- Amaç açıkça hem availability hem **veri yerleşimi**

**Auth0** aynı modeli kullanıyor: bölgesel tenant'lar (US/EU/AU/JP), tenant bölgeler arası **taşınmaz, replike edilmez** `[Auth0'ın 2026 tarihli mimari yazısı bu oturumda doğrulanamadı]`.

> **Argus için ders:** Çok bölgeli kimlik = **bölge başına bağımsız Argus kurulumu (hücre)** + tenant'ların bir hücreye atanması + hücreler arası **hiçbir veri replikasyonu**. Bu, dağıtık SQL'in tüm karmaşıklığını ortadan kaldırır ve yasal gereksinimi doğal olarak karşılar. Global tek şey **kontrol düzlemi**dir: "hangi tenant hangi hücrede" haritası (küçük, nadiren değişen, cache'lenebilir).

### 3.5 Çok bölge karar tablosu — Argus

| Yaklaşım | Tutarlılık | Login gecikmesi | Failure mode | Op. maliyeti | Argus kararı |
|---|---|---|---|---|---|
| Tek bölge, 3 AZ, senkron Postgres | Strong | **Taban +6–12 ms** | Bölge kaybı = kesinti (DR'a failover) | Düşük | ✅ **v1** |
| İki site, aynı bölge, senkron (Keycloak v2 modeli) | Strong | +8–10 ms/etkileşim, DB CPU 2× | Site kaybı = veri kaybı yok | Orta | ✅ **v2** |
| Hücre başına bölge (Okta modeli) | Hücre içinde strong | Taban (kullanıcı kendi hücresinde) | Hücre kaybı = **sadece o hücre** | Orta-yüksek (N kurulum) | ✅ **v3 — hedef** |
| CockroachDB `REGIONAL BY ROW` | Serializable | Home region'da düşük, dışarıda yüksek | Bölge kaybı tolere edilir (REGION survival) | **Yüksek** (şema tasarımı + lisans) | ⚠️ Yalnız gerçek global gereksinim varsa |
| Postgres aktif-aktif (logical) | **Eventual + LWW** | Düşük | **Çakışma = güvenlik açığı** | Yüksek | ❌ **Asla** |
| Aurora DSQL | Snapshot, OCC | İyi (kıta içi) | Bölge kaybı tolere | Düşük ama **AWS kilidi + ağır SQL kısıtları** | ⚠️ Yalnız AWS-only ürün stratejisinde |

---

## BÖLÜM 4 — DAĞITIK DURUM VE İPTAL YAYINI

### 4.1 Yayın mekanizmaları karşılaştırması

| Mekanizma | Teslim garantisi | Gecikme | Node kaybında | Ek altyapı | Kimlik için verdict |
|---|---|---|---|---|---|
| **Redis/Valkey pub/sub** | **At-most-once** | ~1 ms | **Mesaj sonsuza kadar kaybolur** | Redis | ❌ **Tek başına asla** |
| **Redis Streams** | At-least-once (consumer group) | ~1 ms | Kalıcı, replay edilebilir | Redis | ⚠️ Kabul edilebilir |
| **NATS core** | **At-most-once** | <1 ms | Kaybolur | NATS | ❌ |
| **NATS JetStream** | **At-least-once**, ack + redelivery, sequence number | ~1–5 ms | Stream diskte, replay edilir | NATS + storage | ✅ Ama fazladan sistem |
| **Kafka** | At-least-once, kalıcı log | 5–50 ms | Kalıcı | Kafka + ZK/KRaft | ❌ **IdP için aşırı** |
| **Gossip** | Eventual, olasılıksal | 100 ms–saniyeler | Yakınsar | Yok | ⚠️ Yakınsama süresi belirsiz |
| **DB polling** | Olay DB'de kalıcı; **teslimat at-least-once** | Polling aralığı | Kaybolmaz | **Yok** | ✅ |
| **DB transactional outbox + polling** | **Atomik üretim** (iş değişikliğiyle aynı transaction) + **at-least-once teslimat** | Polling aralığı (100 ms) | Kaybolmaz | **Yok** | ✅✅ **Keycloak'ın seçimi** |
| **PostgreSQL `LISTEN/NOTIFY`** | At-most-once (bağlantı kopunca kaybolur) | <1 ms | **Kaybolur** | Yok | ❌ **İptal yayınında kullanılmaz** (§6 §4.5) |

> ⚠️ **Düzeltme (3. inceleme turu): son iki satırda önceden "exactly-once" yazıyordu.** Bu, teslimat semantiği olarak fazla güçlü ve genel olarak yanlış. **Olayın DB'de kalıcı olması** ile **tüketicinin etkisinin tam bir kez uygulanması** ayrı şeylerdir: tüketici satırı okuyup cache'e uygulamadan ölürse, yeniden başladığında aynı olayı yeniden alır. Doğru hedef üç parçalıdır ve üçü de ayrı ayrı tasarlanır:
> **atomik üretim** (olay ile iş değişikliği aynı transaction) + **at-least-once teslimat** (yeniden teslimat normaldir) + **idempotent/monoton uygulama** (epoch yalnızca artar; aynı olayın iki kez uygulanması sonucu değiştirmez).

### 4.2 Redis pub/sub'ın güvenlik problemi — bu bir görüş değil, dokümante edilmiş davranış

Redis resmî dokümanı ([redis.io/docs/latest/develop/pubsub/](https://redis.io/docs/latest/develop/pubsub/), "Delivery semantics", erişim 2026-09-08), doğrudan alıntı:

> "Redis' Pub/Sub exhibits **at-most-once** message delivery semantics. As the name suggests, it means that a message will be delivered once if at all. Once the message is sent by the Redis server, there's no chance of it being sent again. If the subscriber is unable to handle the message (for example, due to an error or a network disconnect) **the message is forever lost**."

Mesaj kaybının somut sebepleri: abonesiz kanala gönderim, bağlantısı kopmuş abone, **çıkış tamponu (output buffer) taşması** (yavaş abone → Redis sessizce düşürür), master/replica switchover.

**IdP'de bu ne demek:** İptal sinyali kaybolan node, iptal edilmiş token'ı **kabul etmeye devam eder** — ve bunu **sessizce** yapar. Ne log, ne alarm. Bu, "güvenlik kontrolü var sanıp olmaması" durumudur ve hiç olmamasından beterdir.

**Redis'i tamamen atmak gerekmiyor** — ama **doğruluk kaynağı olamaz.** Doğru kullanım: DB'deki gerçeği hızlandıran, kaybolduğunda polling'in yakaladığı **opsiyonel bir hızlandırıcı**.

### 4.3 Transactional outbox — Keycloak'ın çözümü, Argus'un çözümü olmalı

**Keycloak Multi-Cluster v2'de (2026-07-17):**
> "Between clusters, a **database outbox pattern** propagates invalidation messages via **polling, with a default interval of 100 milliseconds**."
> "Cross-cluster cache invalidation is handled through a **database queuing table, not through direct network connections between clusters**."

**Neden bu doğru:** İptal işlemi ve iptal sinyali **aynı transaction'da** yazılır. Ya ikisi de olur ya hiçbiri. Redis'e ayrı bir `PUBLISH` yapmak "dual write" problemidir: DB commit olur, Redis publish başarısız olur → **kalıcı güvenlik açığı**.

#### Argus için somut şema

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

İptal işlemi:
```sql
BEGIN;
  UPDATE user_revocation SET epoch = epoch + 1, updated_at = now()
    WHERE user_id = $1 RETURNING epoch;
  INSERT INTO revocation_outbox (subject, epoch) VALUES ('user:'||$1, $2);
  -- oturum satırlarını da işaretle
COMMIT;
```

Her Argus node'u:
```sql
SELECT seq, subject, epoch FROM revocation_outbox
 WHERE seq > $last_seen_seq ORDER BY seq LIMIT 1000;
```
her 100–250 ms'de bir. Sonuçlar node-yerel epoch cache'ine uygulanır. `last_seen_seq` node'un belleğinde; **node yeniden başlarsa `seq`'i sıfırdan değil, cache'i boşaltıp "cache miss = DB'ye sor" moduyla ısınır** (bkz. Bölüm 6.4).

**`bigserial` gap tuzağı — bu klasik bir hatadır:** Eşzamanlı transaction'larda `seq=105` commit olup `seq=104` henüz commit olmamış olabilir. Naif `seq > last_seen` polling'i **104'ü kalıcı olarak atlar.** Çözümlerden biri seçilmeli:
1. **Zaman penceresiyle örtüşme:** `WHERE created_at > now() - interval '5 seconds'` ile son 5 saniyeyi her turda yeniden tara (idempotent olduğu için zararsız).
2. **`pg_snapshot_xmin(pg_current_snapshot())` takibi:** Sadece xmin'in altındaki, kesin commit olmuş satırları işle.
3. **`txid` kolonu + snapshot karşılaştırma** (Debezium'un yaptığı).

⚠️ **Düzeltme (2. ve 3. inceleme turu): (1) seçimi GERİ ALINDI — yeterli değil.**

Seçenek (1) bir doğruluk mekanizması değildir. PostgreSQL'de `now()` transaction'ın
**başlangıç** zamanını döndürür, commit zamanını değil; dolayısıyla `created_at`, satır
transaction açıldığı anla damgalanır. Pencereden uzun süren tek bir transaction — ki yukarıdaki
`UPDATE` + `INSERT` deseninin normal şeklidir — satırı zaten pencerenin dışına düşmüş
`created_at` ile görünür kılar. Tüketici duraksarsa da pencere kayar ve satır kalıcı olarak
atlanır. Pencere en fazla bir **hızlandırıcı** olabilir.

Seçenek (2) de yazıldığı hâliyle eksiktir: şemada transaction kimliği tutulmuyor ve cursor'un
nasıl ilerleyeceği tanımlı değil. Ayrıca sequence tabanlı bir cursor bu problemi **prensipte**
çözemez — commit etmemiş bir transaction'ın satırı MVCC altında görünmez, dolayısıyla
"uçuştaki transaction'a ait en düşük `seq`" değeri tablodan hesaplanamaz.

**Teslimat algoritması bu belgede AÇIK KARARDIR.** İki aday (xid watermark üzerinden polling ·
logical decoding) ve ikisinin de ortak sınanacağı arıza matrisi için bkz. **§1 §10.2**.
Karşılaştırma yapılmadan ve matris koşulmadan buraya bir seçim yazılmayacak.

**Maliyet `[SEÇİME BAĞLI HİPOTEZ]`:** *sequence indeksi üzerinden* polling varsayımıyla node başına saniyede 4–10 küçük indeksli sorgu; 20 node'da 80–200 qps — Postgres için önemsiz. ⚠️ **Bu rakam artık teslimat algoritmasının seçimine bağlıdır (§1 §10.2).** Seçilen aday sequence indeksini kullanmayabilir: `xmin` adayı sistem sütunu üzerinden çalışırsa indeks kullanamaz ve **seq scan** riski taşır — o durumda bu maliyet tahmini geçersizdir ve yeniden ölçülmelidir.

**Retention `[AÇIK]`:** outbox tablosu bir pencereyle budanmalı (partitioned table + `DROP PARTITION`), yoksa şişer. ⚠️ **Ama 24 saat henüz güvenli bir karar değil:** tüketici penceresinden uzun süre düşerse partition düşürmek olayları kalıcı olarak yok eder. **Yeniden senkronizasyon tasarımı tamamlanmadan hiçbir partition düşürülemez** — pencere süresi, o tasarımın çıktısı olarak belirlenecek (§1 §10.2, arıza matrisi senaryo 3).

**⚠️ `NOTIFY` hızlandırması KULLANILMAZ — düzeltme (2. inceleme turu).** Bu paragraf önceden "isteğe bağlı hızlandırma" başlığıyla, aynı transaction'ın sonunda `NOTIFY revocation` yapılmasını öneriyordu. Bu, §6 §4.5'teki mutlak yasakla ve §1 §4.1 / §2 Çelişki 4'ün karar satırlarıyla çelişiyordu. Daha önemlisi, **"opsiyonel" çerçevesi hata modundan kaçmıyor:** `NOTIFY` iptal yazımıyla *aynı transaction'ın* içinde olduğu için, bildirim kuyruğu dolduğunda kaybolan bir hızlandırma değil — **iptalin kendisi commit olamaz**. Yani iptal mekanizması DB'nin yazma yolunu düşürebilir hâle gelir; §6 §4.5 bunu zaten "kabul edilemez bir hata modu" ilan etmişti. **Tek konum: `LISTEN/NOTIFY` iptal yayınında hiç kullanılmaz.**

### 4.4 Bloom / cuckoo filter ile iptal listesi

**Bulgu:** Bu araştırmada, üretim IdP'lerinde token iptali için Bloom/cuckoo filter kullanan **doğrulanmış bir örnek bulunamadı** `[DOĞRULANMADI]`.

**Güvenlik analizi (birinci ilkelerden):**

Bloom filter **yanlış pozitif** verir, yanlış negatif vermez. İptal listesi bağlamında:
- Yanlış pozitif = "bu token iptal edilmiş" (aslında değil) → **geçerli token reddedilir** → kullanıcı gereksiz yere çıkış yapar
- Yanlış negatif **imkânsız** = iptal edilmiş token asla kaçmaz ✅

**Yani yön güvenlidir** — fail-safe tarafa düşer. Bu önemli ve çoğu kişi tersini sanır.

**Ama pratik problemler:**
1. **Silme yok.** Standart Bloom'dan eleman çıkarılamaz. Token süresi dolduğunda filtreden çıkaramazsın → filtre doyar, yanlış pozitif oranı zamanla **tavana vurur**. Counting Bloom veya **cuckoo filter** (silme destekler) gerekir.
2. **Yanlış pozitif oranı = rastgele logout oranı.** %1 FP oranı, kullanıcıların %1'inin rastgele çıkış yapması demektir. Bu kabul edilemez; %0,01'e inmek için filtre büyür.
3. **`revocation_epoch` deseni aynı işi 8 byte ile ve %0 hatayla yapıyor.** Bloom'un tek avantajı bellek — ve epoch deseni zaten bellek problemi yaratmıyor.

**Verdict: Argus kullanmamalı.** Tek meşru kullanım alanı: **DPoP `jti` replay koruması** gibi çok yüksek kardinaliteli, kısa ömürlü ve "yanlış pozitif = tek isteği reddet" (kullanıcı çıkışı değil) olan durumlar. Orada bile Redis SET + TTL daha basit.

### 4.5 `revocation_epoch` deseni — Argus'un omurgası olmalı

**Desen:** Kullanıcı başına monoton artan bir sayaç. Token'a `epoch` claim'i (veya `iat` ile karşılaştırma) konur. Doğrulamada:

```
if token.epoch < current_epoch(user)  →  token ÖLÜ
```

Tek bir `UPDATE ... SET epoch = epoch + 1` **o kullanıcının şimdiye kadar verilmiş tüm token'larını öldürür.**

**Kim kullanıyor:**
- Bu, "token version" / "token generation" / "session generation" adlarıyla yaygın bir desendir. Django'nun `AbstractBaseUser.get_session_auth_hash()`, Rails'in `devise` `authenticatable_salt`'ı ve Firebase Auth'un `tokensValidAfterTime` alanı aynı fikrin varyasyonlarıdır `[Bu ürün eşleşmeleri genel bilgiye dayanıyor, bu oturumda tek tek doğrulanmadı]`.
- Genel teknik yazın bunu "token versioning" olarak tarif ediyor: "one database update invalidates every token the user has ever issued, requiring only **8 bytes of storage per user**" `[İKİNCİL/DÜŞÜK OTORİTE KAYNAK — michal-drozd.com, techinterview.org gibi blog yazıları; bağımsız üretim ölçümü değil]`.

**⚠️ Uyarı:** Aramada karşılaşılan "**10.000 istek/s ve 100k kullanıcıda token version doğrulaması cache'li lookup ile sadece 0,3 ms ekliyor; kısa expiry 0,05 ms, denylist 0,2 ms**" rakamları **düşük otoriteli blog yazılarından** geliyor ve **bağımsız olarak doğrulanamadı**. Argus bunları planlama girdisi olarak kullanmamalı; kendi ölçümünü yapmalı.

**`iat < epoch_timestamp` varyantı vs sayaç varyantı:**

| Varyant | Artı | Eksi |
|---|---|---|
| **Monoton sayaç** (`epoch: bigint`) | Saat kaymasından bağımsız; kesin | Token'a ekstra claim gerekir |
| **Zaman damgası** (`revoked_before: timestamptz`, `iat < revoked_before ⇒ ölü`) | Ekstra claim gerekmez, `iat` zaten var | **Saat kayması** riski: 1 sn içinde çıkarılan token'lar aynı saniyeye düşer; ayrıca `iat` saniye çözünürlüklü — **aynı saniyede iptal + yeni token = yeni token da ölür** |

**Argus önerisi: her ikisi.** Token'da `rev` (epoch sayısı) claim'i taşı; kullanıcı tablosunda hem `epoch` hem `epoch_set_at` tut. Doğrulama sayaç üzerinden yapılır (kesin), zaman damgası sadece gözlemlenebilirlik/denetim için.

#### 4.5.1 Ölçekleme davranışı ve node'lara yayılım

Bu desenin tek zorluğu: **her token doğrulamasında kullanıcının epoch'unu bilmek gerekir.** Naif uygulama = her istekte bir DB sorgusu = ölçeklenmez.

**Argus'un çözümü — üç katmanlı:**

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

**Kritik güvenlik detayı — negatif cache tuzağı:** Cache'te olmayan bir kullanıcı için "epoch = 0 varsay" **kabul edilemez**, çünkü bir iptal kaçırılabilir. Doğru davranış: **cache miss → mutlaka DB'ye sor.** Cache yalnızca **pozitif** (bilinen) değerleri hızlandırır.

**Alternatif optimizasyon — global epoch floor:** Node, gördüğü en yüksek `outbox.seq`'i ve son N dakikada iptal edilen kullanıcıların **set**'ini tutar. Token'ın `iat`'ı node'un "tam senkronize olduğu andan" (`synced_since`) sonraysa ve kullanıcı iptal setinde değilse, **DB sorgusu gerekmez.** Bu, cache miss'lerin büyük çoğunluğunu ortadan kaldırır ve sadece "son N dakikada iptal edilenler" kadar bellek ister. N = 1 saat, saatte 10.000 iptal → 10.000 UUID ≈ 160 KB. Bu, Argus'un en verimli tasarımıdır.

**Ölçek:** Bu desen kullanıcı sayısıyla O(1) davranır çünkü maliyet **iptal hızıyla** orantılıdır, kullanıcı sayısıyla değil. 100M kullanıcılı bir sistemde bile saniyede 100 iptal varsa outbox trafiği önemsizdir.

### 4.6 Gecikme bütçesi — "anında iptal" kaç ms olmalı

**Sektörde fiilen kabul edilen değerler:**

| Sistem | İptal yayılım süresi | Kaynak |
|---|---|---|
| **Keycloak Multi-Cluster v2** | **100 ms** (outbox polling varsayılanı) | keycloak.org, 2026-07-17 ✅ |
| **CockroachDB follower read** | **≥4,2 saniye** (kaçınılmaz bayatlık) | cockroachlabs docs ✅ |
| OAuth 2.0 access token ömrü (yaygın pratik) | 5–15 dakika — **fiili iptal gecikmesi bu** | Genel pratik |
| CAEP/SSF sinyal teslimi | Push modelinde saniyeler | `[Sayısal SLA doğrulanmadı]` |

**Argus için önerilen bütçe:**

| Katman | Hedef | Nasıl |
|---|---|---|
| **Aynı node** | **0 ms** (senkron) | İptal işlemi kendi node'unda cache'i hemen günceller |
| **Diğer node'lar, aynı küme** | **p99 < 250 ms** ⚠️ *hedef; teslimat algoritması açık karar (§1 §10.2)* | Outbox polling 100 ms (⚠️ `NOTIFY` hızlandırması **kullanılmaz** — §4.3) |
| **Diğer küme / site** | **p99 < 500 ms** | Senkron DB + outbox polling |
| **Kaynak sunucular (RS)** | **≤ access token ömrü** | Kısa access token (5 dk) + introspection ile 250 ms |
| **Federe RP'ler** | **saniyeler** | SSF/CAEP push |

**Bu bütçenin savunması:** Kullanıcı "tüm cihazlarımdan çık" dediğinde, Argus'un kendi yüzeyi (login, refresh, introspection) **250 ms içinde** iptali uygular. Access token'ı hâlâ elinde tutan bir kaynak sunucu, token süresi dolana kadar (max 5 dk) kabul edebilir — **bu tasarım gereğidir, hata değil**, ve yalnız DPoP + introspection zorunluluğu ile kapatılabilir.

**Karşı tez ve cevabı:** "Anında iptal" isteyen ekipler genellikle introspection'ı zorunlu kılmayı reddeder çünkü gecikme istemez. **Bu ikisi aynı anda olamaz.** Argus bu takası açıkça belgelemeli ve iki profil sunmalı: *fast* (JWT self-contained, 5 dk, iptal ≤5 dk) ve *strict* (introspection zorunlu, iptal ≤250 ms).

---

## BÖLÜM 5 — DAĞITIK RATE LIMITING

### 5.1 Algoritmalar

| Algoritma | Bellek | Burst davranışı | Dağıtıklaştırılabilirlik | Not |
|---|---|---|---|---|
| **Fixed window** | En az (1 sayaç) | **Pencere sınırında 2× burst** | Kolay (INCR + EXPIRE) | Sınır davranışı kabul edilemez |
| **Sliding window log** | Yüksek (her istek kaydı) | Kesin | Zor/pahalı | Doğru ama pahalı |
| **Sliding window counter** | Düşük (2 sayaç + ağırlık) | İyi yaklaşım | Kolay | **Pratik tatlı nokta** |
| **Token bucket** | Düşük (2 alan: token, ts) | Kontrollü burst | Kolay | Yaygın |
| **GCRA** (Generic Cell Rate Algorithm) | **En düşük (tek `tat` değeri)** | Kontrollü burst; **arka plan drip process gerektirmez** | Kolay (tek atomik değer) | **Teknik olarak en zarif** |

**GCRA neden üstün:** Tek bir "theoretical arrival time" (TAT) değeri saklar. Ne sayaç dizisi ne zamanlayıcı gerekir; sürekli (rolling) zaman penceresi verir. redis-cell'in README'si bunu açıkça söylüyor: "provides a rolling time window and **doesn't depend on a background drip process**."

### 5.2 Rust ekosistemi — ve dağıtık moddaki boşluk

**`governor` 0.10.4** (docs.rs, son güncelleme **5 Eylül 2026**):
- GCRA uygular
- `DefaultDirectRateLimiter` (tek durum) ve `DefaultKeyedRateLimiter` (key başına durum, `dashmap` ile)
- **Tamamen süreç-içi.** Bağımlılıkları (`dashmap`, `parking_lot`, `quanta`, `spinning_top`) bunu doğruluyor — hiçbir ağ/depolama backend'i yok.

**`tower-governor`:** `governor`'ı Tower middleware'i olarak sarar. Aynı sınır: **süreç-içi.**

> **Net sonuç: Rust'ta hazır, olgun, dağıtık bir rate limiter YOK.** `governor` mükemmel bir **yerel** limiter'dır; dağıtık katmanı Argus'un kendisi yazmak zorunda.

**`redis-cell`** (github.com/brandur/redis-cell, erişim 2026-09-08):
- GCRA'yı Redis modülü olarak uygular; `CL.THROTTLE <key> <max_burst> <count> <period> [<quantity>]`
- Performans: "**very roughly 0.1 ms per command** as seen from a Redis client", basit bir `SET`'in "biraz iki katından az" süresi
- **⚠️ 2026 durumu: "This package is in 'best effort' maintenance mode."** Yazar aktif geliştirmiyor. Modül yüklemek gerektiği için yönetilen Redis servislerinin çoğunda **kullanılamaz** (ElastiCache, Memorystore).

### 5.3 Doğruluk vs performans — yaklaşık sayaçlar kabul edilebilir mi

**Cevap sınırın türüne bağlıdır ve bu ayrım kritiktir:**

| Sınır tipi | Doğruluk gereksinimi | Neden |
|---|---|---|
| **Kaba trafik/DoS koruması** (IP başına istek) | **Yaklaşık kabul edilebilir** | %10 hata hiçbir şeyi değiştirmez |
| **API kotası** (müşteri başına ücretli) | Orta | Fatura anlaşmazlığı, güvenlik değil |
| **Hesap başına parola denemesi (credential stuffing)** | **KESİN OLMALI** | Aşağıda |
| **OTP/MFA deneme sayısı** | **KESİN OLMALI** | 6 haneli OTP'de her ekstra deneme entropiyi doğrudan yer |
| **Parola sıfırlama / e-posta gönderimi** | Orta | Suistimal, güvenlik değil |

**Neden hesap başına sınır kesin olmalı — matematik:**

6 haneli bir OTP'nin 1.000.000 olası değeri var. Saldırganın hesap başına 5 denemesi varsa başarı olasılığı 5/10⁶ = **1/200.000**. Eğer Argus 10 node'a dağıtılmışsa ve her node **bağımsız yerel sayaç** tutuyorsa, saldırgan istekleri node'lara dağıtarak **10 × 5 = 50 deneme** yapar → başarı olasılığı **10 kat artar**. Node sayısı arttıkça açık büyür — yani **yatay ölçekleme doğrudan güvenlik zafiyetine dönüşür.**

Aynı mantık credential stuffing için: hesap başına 5/dakika sınırı, 20 node'da fiilen 100/dakika olur.

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

**Katman B'yi PostgreSQL'de yapmak — Argus için doğru tercih:**

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

**Neden Redis değil de Postgres:**
1. **Zaten senkron replike ediliyor** → sayaç failover'da kaybolmuyor. Redis'te AOF `everysec` ile bile son 1 saniye kaybolabilir; ve replica promote'ta sayaç geri gidebilir → **saldırgan sayacı sıfırlamak için failover'ı tetiklemeye çalışabilir.**
2. **Aynı transaction'da kilitleme kararıyla birlikte yazılabilir** → tutarsızlık yok.
3. **Bir bağımlılık daha az** (Bölüm 1'deki sektör yakınsamasıyla tutarlı).

**Maliyet endişesi ve cevabı:** "Her login denemesinde bir yazma" pahalı görünür. Ama Argus zaten login başına 5–7 yazma yapıyor (Bölüm 3.1) ve Keycloak stateless modunda tam olarak bunu yapıyor (login failure counter DB'de) — ölçülmüş maliyet **etkileşim başına 8–10 ms**. Bu, Argon2id'nin (kasten) 100–500 ms olan maliyetinin yanında görünmez.

**Redis nerede kullanılır:** Katman A'nın küme-geneli versiyonu için (IP başına global sınır), **kaybı tolere edilebilir** olduğu için. Redis düşerse Argus yerel `governor` sınırlarına düşer — daha gevşek ama çalışır.

### 5.5 Gerçek ölçümler — bulunanlar ve bulunamayanlar

| Ölçüm | Değer | Kaynak/durum |
|---|---|---|
| redis-cell `CL.THROTTLE` gecikmesi | **~0,1 ms** (istemciden), basit `SET`'in ~2 katı | redis-cell README (yazar "informal benchmarks" diyor) |
| Cloudflare'in milyonlarca domain için rate limiting mimarisi | — | Blog sayfası çekilebildi ama **içerik ayıklanamadı** `[DOĞRULANMADI]` |
| Stripe/Heroku'nun Redis+Lua rate limiter deneyimi | Nitel: redis-cell yazarı "I've seen this at both Heroku and Stripe" — naif implementasyonlar yaygın | redis-cell README |
| Yerel+periyodik senkronizasyon (approximate distributed) üretim raporları | — | **Bu araştırmada bulunamadı** `[DOĞRULANMADI]` |

---

## BÖLÜM 6 — ÖLÇEKLENME VE KAPASİTE

### 6.1 "Postgres N bağlantı üstünde çöker" — gerçek eğri

Bu sorunun en iyi cevabı Andres Freund'un (PostgreSQL core committer, o dönem Microsoft) analizidir: [Analyzing the Limits of Connection Scalability in Postgres](https://techcommunity.microsoft.com/blog/adforpostgresql/analyzing-the-limits-of-connection-scalability-in-postgres/1757266), **8 Ekim 2020** ve devamı [Improving Postgres Connection Scalability: Snapshots](https://techcommunity.microsoft.com/blog/adforpostgresql/improving-postgres-connection-scalability-snapshots/1806462).

**Ölçülmüş bulgular:**

| Bulgu | Değer | Koşul |
|---|---|---|
| **Bağlantı başına bellek** | **< 2 MiB** | `huge_pages` **açık** olduğunda. Yazar sonuç: "connection memory overhead is **acceptable**" |
| **Gecikmesiz pgbench read-only zirvesi** | **~48 istemci** | 20 çekirdek / 40 thread iş istasyonu, localhost |
| **10GbE üzerinden, yakın makineler** | zirve **~48 → ~500 bağlantı** | Ağ gecikmesi eklenince |
| **1 ms ağ + 1 ms uygulama işleme gecikmesi** | zirve **~3.000 bağlantı** | Aynı donanım |
| **Asıl darboğaz** | Bellek değil, **snapshot ölçeklenebilirliği** (`GetSnapshotData()`) | Boştaki bağlantılar bile her snapshot'ta taranıyordu |
| **PostgreSQL 14 düzeltmesi** | "little evidence of scalability issues even at **very high connection counts**" | Azure F72s_v2 VM'de before/after |

**Bu üç rakam bir arada okunmalı — ve çoğu ekibin yanlış anladığı yer burası:**

> "Postgres 100 bağlantıdan sonra çöker" **yanlıştır.** Doğrusu: *aktif, aynı anda sorgu çalıştıran* bağlantı sayısı çekirdek sayısını çok aşarsa throughput düşer. Ama gerçek uygulamalarda bağlantılar zamanın büyük kısmında **boştadır** (ağ gecikmesi + uygulama işleme). 1 ms ağ + 1 ms işleme ile zirve **3.000 bağlantıya** çıkıyor.

**PostgreSQL 14 öncesi** boştaki bağlantılar bile `GetSnapshotData()` maliyetini artırıyordu — asıl "çökme" buydu. **PostgreSQL 14+ (yani Argus'un hedeflediği 17/18) bu problemi büyük ölçüde çözdü.**

**Argus için pratik sonuç:** `max_connections = 500` PostgreSQL 18'de tamamen makul. Yine de pooler kullanılmalı — bağlantı **kurma** maliyeti (TLS + latency + Postgres process fork) hâlâ yüksek.

### 6.2 Bağlantı / worker / havuz boyutu ilişkisi

Argus (Rust, `tokio`, async) için hesap:

```
Argus node sayısı           : N
Node başına havuz boyutu    : P
Toplam DB bağlantısı        : N × P   (+ pooler varsa pooler→DB ayrı)
```

**Rehber:**

| Parametre | Öneri | Gerekçe |
|---|---|---|
| **DB CPU başına aktif bağlantı** | 2–4 | Klasik `connections ≈ (2 × cores) + effective_spindle_count`; NVMe'de spindle terimi ~0 |
| **Node başına havuz (`P`)** | **8–16** | Async runtime'da bir bağlantı çok istek servis eder; büyük havuz sadece kuyruğu DB'ye taşır |
| **`N × P` üst sınırı** | DB `max_connections`'ın **%70'i** | Kalan: admin, replikasyon, backup, migration |
| **Ayrı havuz: kritik yol** | 4–8 bağlantı, yüksek öncelik | Token doğrulama/introspection, uzun admin sorgularının arkasında kuyruğa girmesin |
| **Ayrı havuz: admin/rapor** | 2–4, timeout kısa | Admin sorgusu login akışını asla aç bırakmamalı |
| **Ayrı havuz: read replica** | Ayrı | Yalnız Bölüm 2.4'te izin verilen sorgular |

**Anti-pattern:** Node başına 100 bağlantılık havuz + 20 node = 2.000 bağlantı. Bu, DB'de kuyruk oluşturur ve **gecikmeyi görünmez kılar** — istekler DB'de bekler, uygulama metriklerinde "hızlı" görünür. Doğrusu: **havuzu küçük tut, kuyruğu uygulamada tut, kuyruk derinliğini metrik yap** (bu, backpressure ve load shedding için tek doğru yerdir).

### 6.3 Yatay ölçeklenmede neyin paylaşılması ZORUNLU

Bu, Argus'un mimarisinin özüdür.

| Durum | Paylaşım zorunlu mu | Nerede | Kaybı tolere edilir mi |
|---|---|---|---|
| **JWKS / imzalama anahtarları** | **Evet** (aynı anahtar seti) | DB'den okunur, **bellekte tutulur**; rotasyon overlap penceresiyle | Hayır — ama nadiren değişir, cache'lenebilir |
| **Oturum (session)** | **Evet** | **PostgreSQL** | Hayır |
| **Authentication session (login ortası)** | **Evet** | **PostgreSQL** (Keycloak v2'nin yaptığı) | Kullanıcı login'i baştan yapar — tolere edilebilir ama kötü UX |
| **Authorization code** | **Evet** | **PostgreSQL** (tek kullanımlık; sticky session'a güvenilemez) | Hayır — Rauthy'nin Raft'a ihtiyaç duymasının sebebi tam olarak bu |
| **Refresh token + rotation ailesi** | **Evet** | **PostgreSQL** | Hayır — reuse detection kırılır |
| **İptal durumu / `revocation_epoch`** | **Evet** | PostgreSQL (gerçek) + node cache (hız) | Hayır |
| **Brute-force / hesap kilitleme sayacı** | **Evet** (kesin) | **PostgreSQL** | Hayır (Bölüm 5.3) |
| **DPoP `jti` replay listesi** | **Evet** | Redis (TTL'li) veya PostgreSQL | Kısmen — kayıp = replay penceresi açılır ⚠️ |
| **PAR request_uri** | **Evet** | PostgreSQL | Hayır |
| **Nonce / state (OIDC)** | Evet | Client-side (şifreli cookie) tercih edilir; yoksa DB | — |
| **IP başına kaba rate limit** | Hayır (yaklaşık yeter) | Node-yerel `governor` | Evet |
| **Realm/client/policy metadata** | Hayır (cache'lenebilir) | Node-yerel cache + outbox invalidation | Evet (yeniden yüklenir) |
| **Kullanıcı profil verisi** | Hayır | DB'den okunur | Evet |

**Kritik gözlem:** Bu listede **paylaşılması zorunlu olan her şey PostgreSQL'de olabilir.** Tek istisna DPoP `jti` — ve o bile Postgres'te partitioned tablo + agresif budama ile yapılabilir. **Argus'un Redis'e mimari bağımlılığı olmamalı.**

### 6.4 Cold start / warm-up problemi

Yeni bir Argus node'u cache'siz geldiğinde:

| Problem | Etki | Çözüm |
|---|---|---|
| Realm/client cache boş | İlk isteklerde DB'ye N sorgu | **Readiness probe'u cache doldurma tamamlanana kadar başarısız döndür.** Node LB'ye erken girmemeli |
| `revocation_epoch` cache boş | **Her token doğrulamasında DB sorgusu** → DB'de ani yük | Bölüm 4.5.1'deki `synced_since` deseni: node başlarken **son 1 saatin iptal setini** tek sorguyla çeker, sonra outbox'a takılır. Bu **tek sorgu**, kullanıcı başına sorgu yerine |
| JWKS yüklenmemiş | İmzalama başarısız | Başlangıçta zorunlu yükleme; başarısızsa **başlama** |
| Bağlantı havuzu boş | İlk isteklerde TLS + auth el sıkışması | Havuzu `min_connections` ile önceden doldur |
| **Thundering herd** | Aynı anda 10 node başlarsa DB'ye 10× ısınma yükü | Başlangıçta **jitter** (0–5 sn rastgele) + rolling deploy |

**Keycloak'ın aynı problemi:** benchmark raporu, cache boyutunu 10.000'den 200.000 entry'ye çıkarmanın Aurora tepe CPU'sunu **%77,77 → %63,77**'ye düşürdüğünü ölçtü. Yani cache eksikliği doğrudan DB CPU'suna yansıyor — ve soğuk node **kalıcı olarak %0 cache** demektir. Bu yüzden readiness gate'i şart.

---

## BÖLÜM 7 — FELAKET SENARYOLARI VE KADEMELİ BOZULMA

### 7.1 Kademeli bozulma (graceful degradation) matrisi — Argus tasarımı

Bu matris, Argus'un **açık bir tasarım kararı** olarak uygulanmalı; varsayılan davranış değildir.

| Senaryo | Login | Token refresh | **Token doğrulama (JWT)** | Introspection | Admin API | Kullanıcı kaydı |
|---|---|---|---|---|---|---|
| **Normal** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **DB primary düştü, failover sürüyor (0–30 s)** | ❌ 503 | ❌ **503 + Retry-After** (asla `invalid_grant`) | ✅ **çalışır** | ⚠️ epoch cache'ten (bayat riski) | ❌ | ❌ |
| **DB tamamen erişilemez (dakikalar)** | ❌ | ❌ | ✅ **çalışır (degraded mode)** | ⚠️ **cache-only, TTL sonrası fail-closed** | ❌ | ❌ |
| **DCS (etcd) kaybı, Postgres salt-okunur** | ❌ | ❌ | ✅ | ✅ (okuma çalışıyor) | 👁️ salt-okunur | ❌ |
| **Read replica kaybı** | ✅ | ✅ | ✅ | ✅ | ⚠️ yavaş (primary'ye düşer) | ✅ |
| **Redis/Valkey kaybı** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ — *çünkü Redis kritik yolda değil* |
| **Bir AZ kaybı (3 AZ'den)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **İki AZ kaybı (quorum kaybı)** | ❌ | ❌ | ✅ | ⚠️ | ❌ | ❌ |
| **Bölge tamamen kayboldu** | Hücre modelinde: **diğer hücreler etkilenmez** | | | | | |

### 7.2 "Degraded mode" — DB düştüğünde token doğrulamaya devam

**Bu mümkün mü? Evet, ve Argus'un en değerli farklılaştırıcısı olabilir.** Ama sınırları net olmalı.

**Neden mümkün:** JWT imza doğrulaması DB gerektirmez. Gereken tek şey: (a) public key — bellekte, (b) `exp`/`nbf` — token'ın içinde, (c) `revocation_epoch` — node cache'inde.

**Tehlike:** Cache bayatladıkça, iptal edilmiş token'ları kabul etme olasılığı artar. **Sonsuza kadar degraded mode = güvenlik açığı.**

**Argus'un uygulaması — "stale-while-degraded" penceresi:**

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

**Kritik gerçek:** Argus, kaynak sunucuların JWT'yi yerel olarak doğrulamasını **engelleyemez**. Bu nedenle degraded mode'un gerçek güvenlik sınırı **access token ömrüdür**. 5 dakikalık access token = en kötü durumda 5 dakikalık maruziyet. **Bu, kısa token ömrünün en güçlü tek gerekçesidir** ve degraded mode tasarımının önkoşuludur.

### 7.3 Redis/Valkey düşerse

Argus'un önerilen mimarisinde **Redis kritik yolda değil**, bu yüzden cevap kısa: sistem yerel `governor` sınırlarına düşer, kaba rate limiting gevşer, hiçbir güvenlik kararı bozulmaz.

**Eğer Redis kritik yola konulursa** (bu tasarım hatasıdır ama yaygındır), kaybının anlamı:
- Oturum Redis'te → **tüm kullanıcılar çıkış yapar**
- İptal listesi Redis'te → **iptal kontrolü fail-open mu fail-closed mu?** Fail-open = güvenlik açığı, fail-closed = tam kesinti. İkisi de kötü.
- Rate limit Redis'te → **fail-open** ise credential stuffing penceresi açılır

Bu, Argus'un Redis'i doğruluk kaynağı yapmama kararının tek gerekçesi.

### 7.4 Bir bölge tamamen kaybolursa

| Topoloji | Sonuç | RTO | RPO |
|---|---|---|---|
| Tek bölge, DR yok | **Tam kesinti** | Yedekten geri yükleme süresi | Son yedek |
| Tek bölge + asenkron cross-region standby | Manuel/otomatik promote | Dakikalar | **Replikasyon gecikmesi kadar veri kaybı** ⚠️ |
| İki site aynı bölge (Keycloak v2) | Bölge kaybı **kapsanmaz** — ikisi de aynı bölgede | — | — |
| **Hücre başına bölge (Okta modeli)** | **Sadece o hücredeki tenant'lar etkilenir** | Hücre DR'ı | Hücre DR'ı |
| CockroachDB, REGION survival, 3+ bölge | **Otomatik, kesintisiz** | ~0 | 0 |

**Argus için gerçekçi cevap:** Bölge kaybını sıfır RPO ile tolere etmek **yalnızca CockroachDB sınıfı bir DB veya Aurora DSQL ile** mümkündür ve bunun bedeli Bölüm 3'te sayılan gecikme + karmaşıklık + lisans maliyetidir.

**Pragmatik orta yol:** Cross-region **asenkron** standby + açıkça belgelenmiş RPO. IdP için "son N saniyenin yazmalarını kaybedebiliriz" demek, **"bölge kaybı gibi felaket bir olayda birkaç saniyelik parola değişikliği kaybını kabul ediyoruz"** demektir — bu, tam kesintiye tercih edilebilir bir takastır, ama **karar bilinçli verilmeli ve dokümante edilmeli.** Felaket sonrası prosedür: promote'tan hemen sonra **tüm epoch'ları global olarak artır** (herkesi çıkart) — kaybolmuş bir iptali kaçırmaktansa herkesi yeniden giriş yaptırmak doğrudur.

### 7.5 Break-glass erişimi — dağıtık mimaride

**Problem:** Argus, kendi altyapısının kimlik doğrulamasını da yapıyorsa, Argus çöktüğünde **operatörler Argus'u düzeltmek için giriş yapamaz.** Bu klasik döngüsel bağımlılıktır ve gerçek kesintilerin uzamasının bir numaralı sebebidir.

**Argus için tasarım ilkeleri:**

| İlke | Uygulama |
|---|---|
| **1. Break-glass yolu, normal yoldan bağımsız kod yolu olmalı** | Ayrı endpoint (`/break-glass`), ayrı doğrulama fonksiyonu, **normal auth pipeline'ının hiçbir parçasını çağırmamalı** — rate limiter, risk motoru, MFA orkestratörü dahil |
| **2. Bağımlılık zinciri minimum** | Yalnız: yerel disk/env'den okunan public key + saat. **DB'ye, Redis'e, harici IdP'ye bağımlı olmamalı** |
| **3. Kimlik: donanım anahtarı, çevrimdışı doğrulanabilir** | Break-glass credential'ları = önceden dağıtılmış **FIDO2 anahtar** public key'leri veya **çevrimdışı imzalanmış, kısa ömürlü yetki belgesi** (m-of-n imza). Her node'un config'inde |
| **4. Yerel doğrulanabilirlik** | Node, break-glass token'ını **hiçbir ağ çağrısı yapmadan** doğrulayabilmeli |
| **5. Kısıtlı yetki** | Break-glass yalnız operasyonel işlemler yapabilmeli (config okuma, sağlık, feature flag, epoch reset). **Kullanıcı verisi okuma/değiştirme YOK** |
| **6. Zorunlu, silinemez iz** | Kullanım anında: yerel dosyaya + syslog'a + (erişilebilirse) harici SIEM'e. **Argus'un kendi audit tablosuna güvenilemez — DB düşmüş olabilir** |
| **7. Otomatik alarm** | Kullanım anında tüm on-call'a bildirim; "sessiz break-glass" olmamalı |
| **8. Kısa ömür + tek kullanım** | Belge 15 dakika geçerli; kullanımdan sonra rotasyon zorunlu |
| **9. Düzenli tatbikat** | **Çeyrekte bir test edilmeyen break-glass, çalışmayan break-glass'tır.** Bu bir süreç gereksinimidir, teknik değil |
| **10. Hücre başına ayrı** | Her hücrenin kendi break-glass credential'ı; birinin sızması diğerlerini etkilemez |

**Anti-pattern:** "Acil durum admin hesabı" — DB'de duran, parolası kasada olan bir kullanıcı. **DB düştüğünde işe yaramaz** ve normal zamanda kalıcı bir saldırı yüzeyidir.

---

## BÖLÜM 8 — ARGUS İÇİN NET TOPOLOJİ ÖNERİSİ

### 8.1 Aşama 1 (v1) — "Tek bölge, üç AZ, sıkı tutarlılık"

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

**Yapılandırma kararları:**

| Karar | Değer | Gerekçe |
|---|---|---|
| `synchronous_commit` | `on` | Veri kaybı yok (Bölüm 2.2.3) |
| `synchronous_standby_names` | `ANY 1 (sb_b, sb_c)` | Bir standby kaybını tolere eder, **primary asılmaz** |
| Audit yazmaları | session-level `synchronous_commit = local` | IOPS tasarrufu, güvenlik etkisi yok |
| Patroni | `ttl=20, loop_wait=5, retry_timeout=5` + watchdog | ~25 sn failover |
| **DCS Failsafe Mode** | **ON** | etcd kaybı = salt-okunur, tam kesinti değil |
| Birincil anahtarlar | **`uuidv7()`** (PG18) | Index bloat ve WAL hacmi |
| Uçucu durum | **Tamamı PostgreSQL'de** | Keycloak v2 / authentik / Ory yakınsaması |
| Redis/Valkey | **Yok** (v1'de hiç) | Bağımlılık azaltma; sonradan opsiyonel hızlandırıcı |
| İptal yayını | **Outbox tablosu + 100 ms polling** (⚠️ `NOTIFY` hızlandırması kullanılmaz); **cursor algoritması AÇIK KARAR** | Bölüm 4.3, §1 §10.2 |
| İptal modeli | **`revocation_epoch` (per-user monoton sayaç) + node cache** | Bölüm 4.5 |
| Rate limiting | **Yerel `governor`** (kaba) + **PostgreSQL atomik UPDATE** (hesap başına) | Bölüm 5.4 |
| Havuz | Node başına 8–16; ayrı havuzlar: kritik / admin / replica | Bölüm 6.2 |
| Read replica | **Yalnız admin arama, raporlama, denetim izi görüntüleme** | Bölüm 2.4.1 tablosu |
| Access token ömrü | **5 dakika** | Degraded mode'un güvenlik sınırı (Bölüm 7.2) |

**Bu topolojinin karşıladığı:** AZ kaybı (kesintisiz), node kaybı (kesintisiz), DB primary kaybı (~25 sn, veri kaybı yok, token doğrulama kesilmez), etcd kaybı (salt-okunur degrade).

**Karşılamadığı:** Bölge kaybı (asenkron DR ile RPO > 0, RTO dakikalar).

### 8.2 Aşama 2 (v2) — "İki küme, tek bölge" (Keycloak Multi-Cluster v2 deseni)

Yalnızca **iki bağımsız Kubernetes/deploy alanı** gerekiyorsa (ör. farklı veri merkezleri, aynı metro):

- İki bağımsız Argus kümesi, senkron replike edilmiş **tek mantıksal DB** (Patroni multi-DC veya Aurora)
- **Site'lar arası DB RTT < 5 ms hedef, < 10 ms tavan** (Keycloak'ın doğrulanmış eşiği)
- Cross-cluster invalidation: **aynı outbox tablosu** — hiçbir ek altyapı yok
- LB: `/lb-check` benzeri sağlık endpoint'i ile site failover

**Beklenen maliyet (Keycloak'ın ölçtüğü, Argus için de geçerli olması muhtemel):** etkileşim başına **+8–10 ms**, DB CPU/IOPS **~2×**.

### 8.3 Aşama 3 (v3) — "Hücre başına bölge" (Okta modeli)

Çok bölgeli gereksinim ortaya çıktığında **veri replikasyonuyla değil, izolasyonla** çöz:

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

**Kazanımlar:**
- Veri yerleşimi **yapısal olarak** çözülür (GDPR/KVKK/veri yerelleştirme)
- Hata izolasyonu: bir hücrenin çökmesi diğerlerini etkilemez
- Cross-region konsensüs maliyeti **sıfır** — her hücre içinde tek bölge
- Ölçekleme: kapasite eklemek = hücre eklemek (doğrusal, tahmin edilebilir)
- Türkiye'nin ödeme/e-para kuruluşları için veri yurt içinde tutma gereksinimi doğal olarak karşılanır (README §83 ile bağlantılı)

**Bedeller:**
- N hücre = N operasyonel yüzey → **otomasyon zorunlu** (GitOps, tek şablon)
- Tenant'lar hücreler arası **taşınamaz** (veya taşıma ayrı bir proje)
- "Global kullanıcı" (birden çok hücrede aynı kişi) desteklenmez veya kontrol düzleminde federe bir kimlik referansıyla çözülür (Ory'nin "data homing" yaklaşımı)
- Kontrol düzlemi yeni bir kritik bileşen — kendisi HA olmalı ve **hücrelerin çalışması için gerekli olmamalı** (yalnız routing için)

### 8.4 Ne YAPILMAMALI — Argus için kırmızı çizgiler

| ❌ Yapma | Neden |
|---|---|
| **Redis pub/sub ile iptal yayını** | At-most-once; "message is forever lost" (Redis docs) |
| **İptal/oturum/kilit sorgularını read replica'ya yönlendirme** | Bayat okuma = güvenlik açığı (Bölüm 2.4.1); Zitadel bu yüzden replica'yı hiç desteklemiyor |
| **Postgres logical replication ile aktif-aktif** | LWW çakışma çözümü = kimlikte güvenlik açığı (Kanidm dersi) |
| **Kanidm tarzı quorum'suz çok-master** | Aynı |
| **Kıtalar arası senkron yazma** | Keycloak 26.3: 20 ms RTT'de p99 1.076 ms |
| **Tek standby ile `synchronous_commit=on`** | Standby düşünce primary asılır — HA çözümü kesinti kaynağı olur |
| **Infinispan/Hazelcast tarzı gömülü dağıtık cache** | Keycloak 2026'da bu yoldan geri döndü |
| **Node başına bağımsız hesap-bazlı rate limit** | Yatay ölçekleme = güvenlik zafiyeti (Bölüm 5.3) |
| **Bloom filter tabanlı iptal listesi** | `revocation_epoch` aynı işi %0 hatayla yapıyor; doğrulanmış üretim örneği yok |
| **DB'de duran "acil durum admin hesabı"** | DB düştüğünde işe yaramaz; sürekli saldırı yüzeyi |
| **Refresh failover'ında `400 invalid_grant`** | İstemci SDK'ları kullanıcıyı çıkartır; **503 + Retry-After** kullan |

---

## BÖLÜM 9 — KAYNAKLAR

### 9.1 Birinci elden çekilip okunan (erişim: 8 Eylül 2026)

**Keycloak**
1. [Keycloak Performance Benchmarks: A Deep Dive into Scaling and Sizing (26.4)](https://www.keycloak.org/2025/10/keycloak-benchmark) — Ekim 2025 — **tüm kapasite ve RTT rakamları**
2. [Multi-Cluster v2 and Stateless Mode now in Preview](https://www.keycloak.org/2026/07/multi-cluster-v2-and-stateless-mode) — Alexander Schwartz, **17 Temmuz 2026** — **8-10 ms, 2× DB, <5/<10 ms, 100 ms outbox polling**
3. [Concepts for multi-cluster deployments](https://www.keycloak.org/high-availability/multi-cluster/concepts) — iki site sınırı, manuel resync, <2 dk kurtarma
4. [Storing sessions in Keycloak 26](https://www.keycloak.org/2024/12/storing-sessions-in-kc26) — Aralık 2024 — persistent user sessions
5. [Keycloak blog index](https://www.keycloak.org/blog) — sürüm takibi (26.7.3, 31 Ağustos 2026)

**Zitadel**
6. [Scaling Cloud-Native Identity: Optimizing Performance with Caching](https://zitadel.com/blog/scaling-cloud-native-identity-optimizing-performance-with-caching) — Florian Forster, **12 Şubat 2026** — **>30.000 req/s Postgres cache, hibrit ilişkisel modele geçiş**
7. [Does Zitadel support multi-region with Postgres? #7636](https://github.com/zitadel/zitadel/discussions/7636) — read replica reddi
8. [Zitadel Software Architecture](https://zitadel.com/docs/concepts/architecture/software) — CQRS/eventual consistency

**Kanidm**
9. [Replication Design and Notes](https://kanidm.github.io/kanidm/master/developers/designs/replication_design_and_notes.html) — AP tercihi, CID, RUV, tombstone, dondurma
10. [Three-node replication topology #4099](https://github.com/kanidm/kanidm/discussions/4099) — 3 node "technically unsupported"

**Rauthy / Hiqlite**
11. [Rauthy HA Configuration](https://sebadob.github.io/rauthy/config/ha.html) — 3/5 replika, 15–30 sn shutdown
12. [hiqlite crate](https://crates.io/crates/hiqlite) / [github](https://github.com/sebadob/hiqlite) — 24.5k / 16.5k insert/s
13. [openraft](https://github.com/databendlabs/openraft) — generalized membership change

**Ory**
14. [Severe performance issues with global CockroachDB #3134](https://github.com/ory/kratos/discussions/3134) — **230 ms PK lookup, ~1 s ek gecikme, GLOBAL tablo/GDPR çelişkisi**
15. [Global IAM Across Regions](https://www.ory.com/blog/global-identity-and-access-management-multi-region) — data homing, 3 milyar istek/gün
16. [Ory & CockroachDB for Scalable Identity](https://www.ory.sh/blog/the-future-of-identity-ory-and-cockroach-labs-iam-for-agentic-ai) — ⚠️ pazarlama içerikli

**authentik**
17. [Architecture](https://docs.goauthentik.io/core/architecture) — sürüm 2026.8
18. [Release 2025.8](https://docs.goauthentik.io/releases/2025.8) — Redis'ten çıkış

**PostgreSQL**
19. [PostgreSQL 18.0 Release Notes](https://www.postgresql.org/docs/release/18.0/) — Eylül 2025 — AIO, uuidv7, `idle_replication_slot_timeout`, failover slots
20. [libpq Connection Strings (PG18)](https://www.postgresql.org/docs/18/libpq-connect.html) — `target_session_attrs`, `load_balance_hosts`
21. [Andres Freund — Analyzing the Limits of Connection Scalability in Postgres](https://techcommunity.microsoft.com/blog/adforpostgresql/analyzing-the-limits-of-connection-scalability-in-postgres/1757266) — 8 Ekim 2020 — **<2 MiB/bağlantı, 48 → 500 → 3.000 zirve**
22. [Andres Freund — Improving Postgres Connection Scalability: Snapshots](https://techcommunity.microsoft.com/blog/adforpostgresql/improving-postgres-connection-scalability-snapshots/1806462) — PG14 düzeltmesi
23. [EDB — The Cost Implications of PostgreSQL Synchronous Replication](https://www.enterprisedb.com/blog/the-varying-cost-synchronous-replication) — **9,5→16 ms / 17→20 ms tablosu**
24. [Percona — PostgreSQL synchronous_commit options](https://www.percona.com/blog/postgresql-synchronous_commit-options-and-synchronous-standby-replication/) — `off` vs `remote_apply` 2×
25. [Patroni FAQ (4.1.5)](https://patroni.readthedocs.io/en/latest/faq.html) — leader race, DCS kaybı → salt-okunur / demote
26. [Patroni Dynamic Configuration](https://patroni.readthedocs.io/en/latest/dynamic_configuration.html) — `ttl >= loop_wait + 2*retry_timeout`
27. [CloudNativePG Failure Modes (1.28)](https://cloudnative-pg.io/docs/1.28/failure_modes/) — primary/standby arıza akışı
28. [Tembo — Benchmarking PostgreSQL connection poolers](https://legacy.tembo.io/blog/postgres-connection-poolers/) — PgBouncer/pgcat/Supavisor

**Dağıtık SQL**
29. [CockroachDB Follower Reads](https://docs.cockroachlabs.com/docs/stable/follower-reads) — **≥4,2 saniye bayatlık**
30. [CockroachDB Multi-Region Overview](https://docs.cockroachlabs.com/docs/stable/multiregion-overview) — survival goals, table localities
31. [CockroachDB — How to Choose a Multi-Region Configuration](https://docs.cockroachlabs.com/docs/stable/choosing-a-multi-region-configuration) — `--max-offset 250ms`
32. [CockroachDB Licensing FAQs](https://www.cockroachlabs.com/docs/stable/licensing-faqs) — **<$10M ciro Free, telemetri zorunlu, 7 gün throttle**
33. [What is Amazon Aurora DSQL?](https://docs.aws.amazon.com/aurora-dsql/latest/userguide/what-is-aurora-dsql.html) — 99,99/99,999, kıtalar arası yok
34. [Migrating from PostgreSQL to Aurora DSQL](https://docs.aws.amazon.com/aurora-dsql/latest/userguide/working-with-postgresql-compatibility-unsupported-features.html) — **OCC, 3.000 satır, no PL/pgSQL, 1 saat bağlantı**

**Mesajlaşma / rate limiting**
35. [Redis Pub/sub — Delivery semantics](https://redis.io/docs/latest/develop/pubsub/) — **"forever lost"**
36. [NATS JetStream](https://docs.nats.io/nats-concepts/jetstream) — core at-most-once, JetStream at-least-once
37. [redis-cell](https://github.com/brandur/redis-cell) — GCRA, ~0,1 ms, **best-effort maintenance mode**
38. [governor 0.10.4](https://docs.rs/governor/latest/governor/) — 5 Eylül 2026, GCRA, süreç-içi

**Kurumsal mimariler**
39. [Okta — Scaling Okta to 50 Billion Users](https://www.okta.com/resources/whitepapers/scaling-okta-to-billions-of-users/) ve [How Okta Builds and Runs Scalable Infrastructure](https://www.okta.com/resources/whitepapers/how-okta-builds-and-runs-scalable-infrastructure/) — cell-based architecture

### 9.2 İkincil / düşük otorite kaynaklar (dikkatle kullanılmalı)

- Patroni failover süresi "sub-25 seconds" — stackharbor.com bilgi bankası (2026)
- `revocation_epoch` performans rakamları (0,3 ms / 0,05 ms / 0,2 ms) — michal-drozd.com, techinterview.org, oneuptime.com blogları — **bağımsız doğrulanmadı, planlama girdisi olarak kullanılmamalı**
- Patroni/repmgr/pg_auto_failover 2026 karşılaştırması — Medium (Tomasz Gintowt, Temmuz 2026)

### 9.3 `[DOĞRULANMADI]` listesi — açıkça işaretlenenler

| Konu | Durum |
|---|---|
| CloudNativePG'nin CNCF olgunluk seviyesi (Sandbox/Incubating) | Doğrulanamadı |
| Stolon'un arşiv durumu | Doğrulanamadı |
| pg_auto_failover'ın 2026 bakım durumu | Doğrulanamadı |
| AWS bölgeler arası kesin RTT rakamları (us-east↔eu-west) | Doğrulanamadı — cloudping.co çekilemedi |
| AZ'ler arası kesin RTT (1–2 ms iddiası) | Doğrulanamadı |
| CockroachDB "RTT >150 ms'de GLOBAL tablo düzensiz gecikme" | Arama özetinden; doğrudan doküman sayfası doğrulanmadı |
| Auth0'ın 2026 tarihli mimari yazısı / bölgesel tenant modeli detayı | Bulunamadı |
| Google/Cloudflare Access'in kimlik doğrulama mimarisi yazıları | Bulunamadı |
| YugabyteDB'nin kimlik iş yükü için bağımsız benchmark'ı | Bulunamadı |
| Bloom/cuckoo filter ile token iptalinin üretim örneği | **Bulunamadı** |
| Cloudflare dağıtık rate limiting mimarisi detayı | Sayfa çekildi, içerik ayıklanamadı |
| Yerel+periyodik senkronizasyonlu dağıtık rate limiting üretim raporları | Bulunamadı |
| PgBouncer 1.21+ named prepared statement desteğinin sqlx ile uyumu | Doğrulanamadı |
| `sqlx`'in `target_session_attrs` çok-host desteği | Doğrulanamadı |
| PostgreSQL 19 içeriği/takvimi | Doğrulanamadı |
| Argus'un login akışındaki yazma sayısı (5–7) | **Mimari tahmin**, ölçülmedi |
| Rust'ın Keycloak'a göre refresh yolu avantajı tahmini | **Tahmin**, ölçülmedi |

---

### EK: BİR SONRAKİ ARAŞTIRMA İÇİN AÇIK KALAN SORULAR

1. **AWS/GCP bölgeler arası ve AZ'ler arası gerçek RTT matrisi** — Argus'un çok bölge kararının sayısal temeli için gerekli.
2. **Auth0 ve Cloudflare Access'in yayımlanmış mimarisi** — bu oturumda bulunamadı; Okta'nın whitepaper'ları tek somut kurumsal referans.
3. **YugabyteDB'nin kimlik iş yükünde bağımsız ölçümü** — CockroachDB'ye tek gerçek açık alternatif, ama veri yok.
4. **Rust IdP prototipi ile gerçek benchmark** — Keycloak'ın 15 login/s/vCPU rakamına karşı Argus'un gerçek değeri. Bu, tüm kapasite planlamasının temeli ve **şu an sadece tahmin.**
5. **Outbox polling'in 20+ node'da DB üzerindeki ölçülmüş maliyeti** — 100 ms polling'in gerçek qps ve CPU etkisi.
