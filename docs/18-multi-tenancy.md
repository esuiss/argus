# §18 — Çok kiracılık mimarisi

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

---

## 0. Yönetici özeti, net karar

| # | Karar | Seçim | Gerekçe |
|---|---|---|---|
| 1 | Veri izolasyonu | `tenant_id` ile zorlanmış satır seviyesi güvenlik, `SET LOCAL` ve işlem havuzlaması; birinci günden bir `placement_id` kaçış kolonuyla | Kiracı başına şema, 1.200 şemada 383 milisaniyelik katalog taramasına ile iki saatlik migration'a çarpmaktadır; satır bazlı yaklaşım milyonlara ölçeklenmektedir |
| 2 | İmzalama anahtarı | Kiracı başına, varsayılanı ES256; müzakere edilemez | Storm-0558 ile CVE-2026-23552, paylaşımlı anahtarda tek savunmanın ilgili tarafın `iss` kontrolü olduğunu ve ilgili tarafların bunu yapmadığını kanıtlamıştır |
| 3 | Kullanıcı kimliği | Kiracıya yerel, yani `UNIQUE(tenant_id, …)`; asla global olmaz ve çapraz erişim açık bir yetki ile bağla verilerek yapılır | E-posta ile otomatik birleştirme nOAuth sınıfı hesap devralmaya açmaktadır |
| 4 | Hiyerarşi | Düz kiracı listesi; ağaç, kiracının içindeki gruplarla kurulur | Zitadel, Auth0, Okta, Entra ile WorkOS'un hepsi iç içe kiracıyı reddetmiştir; Frontegg yapmıştır ve miras JWT'ye sığmamaktadır |
| 5 | Issuer | Birincil olarak alt alan adı, yani `acme.argus.io`, joker sertifikayla; özel alan adı bir yükseltmedir; path tabanlı desteklenir ancak varsayılan değildir | Ayrı köken, tarayıcı düzeyinde çerez ile XSS izolasyonu demektir; CVE-2023-6717 bunun bedelini göstermiştir |
| 6 | `client_id` | Küresel benzersiz, Keycloak'ın aksine | RFC 6749 §2.2 `client_id`'yi yalnızca yetkilendirme sunucusu içinde benzersiz kılmaktadır ve iki bağımsız savunma katmanı gerekmektedir |
| 7 | Rust | Kiracı tipte kodlanır; markalı yaşam süreleriyle, yani `generativity` ile, çapraz erişim bir derleme hatası olur | Olgun bir mekanizma vardır, 3,99 milyon indirme; çok kiracılığa uygulanmış yayımlanmış bir örnek yoktur ve Argus ilk olur |

Tek cümlelik gerekçe şudur: bu kararların hiçbiri en kolay olan değildir; hepsi sonradan değiştirilemeyen kararlardır ve piyasadaki her IdP bunlardan en az birinde yanlış seçim yapıp yıllarca bedelini ödemiştir.

Bunu en iyi özetleyen tek kanıt, olgun bir Rust IdP'si olan Kanidm'in bakımcısı William Brown'ın 12 Haziran 2026 tarihli ifadesidir:

> "It would be a very large undertaking to add this support within Kanidm. We discussed it many years ago and the complexity and risks (especially security wise) were not worth it."

Sonuç 13 Haziran 2026'da planlanmadı olarak kapatılmasıdır; kanidm deposunda 4395 numaralı issue'dur.

---

## Bölüm I — Mevcut IdP'lerin çok kiracılık modelleri

### 1.1 Keycloak realm'i: mimari, maliyet ile tavan

**Realm nedir ve neyi izole eder.** Resmî tanımı sunucu yönetimi dokümanındadır:

> "A realm is a space where you manage objects, including users, applications, roles, and groups. A user belongs to and logs into a realm."
>
> "One Keycloak deployment can define, store, and manage as many realms as there is space for in the database."

Bu ikinci cümle aşağıdaki üretim kanıtlarıyla doğrudan çelişmektedir. Resmî dokümanın realm sayısı hakkındaki tek ifadesi budur ve yanlıştır.

Kaynak kodundan doğrulanmıştır. `jpa-changelog-1.0.0.Final.xml`, ana dal, ilk şema, 29 tablo içermektedir. `REALM_ID` ayırıcı kolonunu taşıyanlar şunlardır:

```
CLIENT, EVENT_ENTITY, FED_PROVIDERS, KEYCLOAK_ROLE, REALM_APPLICATION, REALM_ATTRIBUTE,
REALM_DEFAULT_ROLES, REALM_EVENTS_LISTENERS, REALM_REQUIRED_CREDENTIAL, REALM_SMTP_CONFIG,
REALM_SOCIAL_CONFIG, USERNAME_LOGIN_FAILURE, USER_ENTITY, USER_FEDERATION_PROVIDER,
USER_SESSION, USER_SOCIAL_LINK
```

Keycloak satır bazlı çok kiracılık kullanmaktadır. Realm başına şema yoktur, realm başına veritabanı yoktur ve satır seviyesi güvenlik yoktur. Güncel `UserEntity.java` şöyledir:

```java
@Table(name="USER_ENTITY", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "REALM_ID", "USERNAME" }),
        @UniqueConstraint(columnNames = { "REALM_ID", "EMAIL_CONSTRAINT" })
})
@Column(name = "REALM_ID")
protected String realmId;      // ← düz String. @ManyToOne DEĞİL. FK YOK.
```

`CLIENT` tablosunda `UNIQUE(REALM_ID, CLIENT_ID)` vardır, yani `client_id` realm kapsamlıdır, küresel değildir.

İzole etmedikleri, hepsi doğrulanmış olarak şunlardır.

| İzole değildir | Kanıt |
|---|---|
| Veritabanı şeması | Tek bir paylaşımlı şema ile `REALM_ID` satır ayırıcısı vardır |
| Bağlantı havuzu | Tek havuzdur; keycloak.org'un yüksek erişilebilirlik dokümanı |
| JVM ile yığın | Tek JVM'dir |
| Infinispan önbellekleri | `realms`, `users` ile `keys` tek küresel önbellektir, realm başına değildir |
| HTTP portu ile köken | `/realms/{realm}/…` bir yol segmentidir, yani aynı kökendir |
| Tema önbelleği | Anahtarı isim ile tipten oluşmaktadır, realm'e göre anahtarlanmamaktadır; sınırsız bir eşleme tablosudur ve tahliye yoktur |
| Sağlayıcı sınıf yükleyicisi | Sunucu başına bir kezdir |

**Realm başına maliyet, somut olarak.**

Anahtarlar tarafında `DefaultKeyProviders.createProviders(RealmModel)` realm başına dört sağlayıcı kurmaktadır: `rsa-generated` imza için, `rsa-enc-generated` RSA-OAEP şifreleme için, `hmac-generated-hs512` ile `aes-generated`. `AbstractGeneratedRsaKeyProviderFactory` içinde varsayılan anahtar boyutu 2048'dir.

Yani realm başına iki adet RSA-2048 çifti üretilmektedir. Doküman şöyle demektedir: "When a realm is created, a key pair and a self-signed certificate is automatically generated."

Bu makinede ölçülmüştür; macOS ile Apple Silicon, LibreSSL 3.3.6 ve süreç başlatma tabanı olan 1,90 milisaniye çıkarılmıştır.

| Algoritma | Ham | Net |
|---|---|---|
| EC P-256, yani ES256 | 2,29 ms | Yaklaşık 0,4 ms |
| Ed25519, ssh-keygen ile ve girdi çıktı dahil | 4,43 ms | Yaklaşık 2,5 ms |
| RSA-2048 | 54,99 ms | Yaklaşık 53 ms |
| RSA-4096 | 584,13 ms | Yaklaşık 582 ms |

RSA-2048, P-256'dan yaklaşık 130 kat yavaştır. Keycloak'ın realm başına iki RSA-2048 anahtarı kiracı başına yaklaşık 110 milisaniye saf işlemci demektir; 100.000 kiracı için tek çekirdekte yaklaşık üç saat eder. ES256 ile aynı iş yaklaşık 80 saniyedir.

> **Literatürde tartışılmayan bir bağımlılık vardır: algoritma seçimi izolasyon mimarisini belirlemektedir.** RSA seçilirse kiracı başına anahtar ölçeklenmez ve ekip paylaşımlı anahtara itilir; üçüncü bölümde gösterildiği gibi bu ölümcüldür.

Önbellek tarafında `docs/guides/server/caching.adoc` şöyle demektedir: "Local caches for realms, users, and authorization are configured to hold up to 10,000 entries per default."

`realms` önbelleği düz, küresel ve 10.000 girdilik bir en az kullanılanı çıkaran önbellektir ve realm başına bir girdi tutmamaktadır; realm ile her istemci, istemci kapsamı, rol ve grup hem kimlik hem isimle anahtarlanmaktadır. 1 Ağustos 2024 tarihli bir forum gözlemi şöyledir:

> "I have one 'test' realm configured in addition to the master realm… I see that the realm cache jumps up to hundreds of entries."

Yüzlerce realm tavanının mekanizması budur: sabit küresel önbellek bütçesi, değişken realm başı girdi sayısına bölünmektedir.

**Neden binlerce realm çalışmamaktadır, ölçülmüştür.**

Proje lideri Stian Thorgersen 11 Ekim 2018'de keycloak-dev listesinde şöyle demiştir: "Keycloak simply doesn't scale well with regards to large number of realms today."

Kök mimari kusur master realm'in O(N) bağlamasıdır. Keycloak katkıcısı Alexander Schwartz 3 Haziran 2022 tarihli 12332 numaralı tartışmada şunu açıklamıştır: her realm master içinde bir `xxx-realm` istemcisi yaratmakta ve master'a girişte bu bileşik roller değerlendirilmektedir; kalıcılık bağlamı büyümekte ve bu, Hibernate'in kirli kontrolünü yavaşlatmaktadır. Üç bin realm'de yapışkan oturumla yaklaşık 50 saniye, yapışkan oturum olmadan yaklaşık 110 saniye giriş süresi ölçülmüştür.

Bakımcı stianst bu düzeltmeyi reddetmiştir: "This approach doesn't work I'm afraid as there's a clear use-case for managing all realms from the master realm." Yani O(N) bağlama kasıtlıdır ve kalıcıdır.

Kronolojik ölçümler şöyledir.

| Sürüm ile tarih | Realm | Bulgu | Kaynak |
|---|---|---|---|
| KC 4.8.1, 31 Ocak 2019 | 0'dan 350'ye | Realm yaratma 1104'ten 11535 milisaniyeye, token alma 636'dan 3197 milisaniyeye çıkmıştır, yani beş kat; yaklaşık 470'te temelde kullanılamaz hâle gelmiştir | Stack Overflow 54465114 |
| KC 16.1, 18 Ocak 2022 | 5'ten 350'ye | Master yönetim konsolunun soğuk açılışı 50 milisaniyeden iki dakikaya çıkmıştır, yani 2400 kat; realm'e yerel yönetim konsolu etkilenmemiştir | Forum 13127 |
| KC 17, 1 Nisan 2022 | Yaklaşık 620 | Üstel bozulma görülmüş ve test terk edilmiştir. Optimizasyon dalıyla üç bin realm'de doğrusal kalmıştır | Tartışma 11074 |
| KC 20.0.5, 18 Nisan 2023 | 400 | Yönetim konsolu yüklenmemekte, kullanıcı listesi zaman aşımına uğramakta ve JDBC sızıntısı olmaktadır. Planlanmadı olarak kapatılmıştır | Issue 19793 |
| KC 20, 19 Mayıs 2023 | 307 | `/admin/realms?briefRepresentation=true` isteği 107 saniye sürmektedir; KC 17'de yaklaşık 15 saniyeydi, yani yedi kat gerileme vardır | Issue 20453 |
| KC 26, 29 Mayıs 2024 | 600'den fazla | Realm açılır listesinin açılması yaklaşık altı dakika sürmektedir. Düzeltme arka uçta değil arayüzde sayfalamadır, 30219 numaralı issue | Issue 29978 |

On yıllık aynı kusur Temmuz 2026'da düzelmiştir. 50369 numaralı issue, 26 Haziran 2026, KC 26.7.0: bileşik rol genişletmesinde `getChildRoles` N artı bir sorgusu ile her sorgudan önce tam otomatik boşaltma vardı. Ölçüm şudur: bileşik genişletmenin işlemci payı %62'den %5,6'ya, saniyedeki veritabanı sorgusu 5526'dan 614'e, yani %89 azalmıştır.

Pratik tavan uzlaşısı küme başına 200 ile 500 realm, bozulmanın 100 ile 200'de başlamasıdır.

| Kaynak | Rakam |
|---|---|
| xgp, Phase Two, 1 Nisan 2021 | Yaklaşık 400 realm'in üzerinde ciddi sorunlar |
| Cloud-IAM, ticari Keycloak barındırıcısı, 8 Ocak 2025 | Yüz civarı realm'in ötesinde performans bozulmaktadır |
| Phase Two, 21 Nisan 2025 | 50, 100 veya 500 kiracıda basitçe ölçeklenmemektedir |
| Klathmon, Hacker News, 11 Şubat 2024 | Yaklaşık 200 realm'den sonra işler bozulmaya başlamaktadır |
| Üretim, KC 11.0.3, 25 Ağustos 2021 | 373 realm'de girişte 20 ile 30 saniye; çöp toplayıcı büyümesi aylık yeniden başlatma gerektirmektedir |
| Üretim, KC 24.0.5, 2 Ekim 2024 | 31. realm'de `/admin/serverinfo` isteği token veya başlık boyutu nedeniyle 400 döndürmektedir |

26.x ne değiştirmiştir sorusunun cevabı mimari olarak hiçbir şeydir. Topluluktan gelen en iyimser iddia 5 Ekim 2025 tarihli 11074 numaralı tartışmadadır: Keycloak 26.4 ile realm önbelleğini artırmaya devam ettiğiniz sürece bin ve üzeri realm çalıştırmak sorun olmamalıdır. Bu bir ayar geçici çözümüdür ve kiracıyı yığın belleğiyle satın almaktır. Çok bölgeli ile çok kümeli yapı, yani 26.7, bir felaket kurtarma özelliğidir; `realms` önbelleği düğüme yereldir ve bölge eklemek realm tavanını yükseltmez.

Resmî bir azami realm sayısı beyanı yoktur ve bu doğrulanamamıştır. Resmî 26.4 kıyaslamasında realm sayısı boyutu hiç yoktur; bu boşluk başlı başına bir bilgidir.

**Keycloak Organizations, Keycloak'ın kendi itirafı.**

KC 25'te önizleme, 26.0.0 ile genel kullanıma açılmıştır, 4 Ekim 2024. Resmî çerçeve bir müşteri kimlik yönetimi boşluğudur; itiraf sözel değil yapısaldır: Keycloak realm'in içine ikinci bir kiracılık ilkeli inşa etmiştir, yani organizasyon başına kimlik sağlayıcı, organizasyon başına alan adı, üyelik ile token'da organizasyon claim'leri, çünkü realm çoğaltılamıyordu.

Dokümandan doğrulanan kritik tasarım kararları şunlardır.

Takma ad hakkında: "The alias is unique within a realm and must be URL-friendly… Once defined, the alias cannot be changed afterwards." Yani değişmez bir kiracı kısa adıdır.

Alan adı hakkında: "A domain cannot be shared by different organizations within a realm."

Üyelik hakkında: "An organization member is basically a realm user but with a link to one or more organizations." Yani kullanıcı realm'e aittir, küreseldir ve organizasyon bir üyelik bağıdır.

Yönetilen ile yönetilmeyen üyeler hakkında: organizasyon silinince yönetilen üyeler silinir, yönetilmeyenler realm'de kalır. 30747 numaralı issue şöyle demektedir: üyeler yalnızca bir yönetilen üyeliğe sahip olabilir. Yani çok üyelik vardır ancak yaşam döngüsünü tam olarak bir tanesi sahiplenir. Bu, bu kullanıcıyı kim silebilir sorusunun en temiz formülasyonudur.

Alan adı eşlemesi hakkında: tam eşleşme ile joker karakter, yani `.example.com`, vardır; en spesifik eşleşme kazanır ve bu alan adı parçası sayısıyla ölçülür; en az iki, en fazla on parça olur ve `com` ile `*.com` reddedilir.

Dürüst karşı argüman xgp'nin 8 Temmuz 2025 tarihli forum yazısındadır:

> "In a Realm, every user is in the same 'pool' of users. There is not a concept of 'logging into a tenant'… The Keycloak organizations functionality is essentially a different way of associating users with a group on steroids."

Organizations'ın kendisi de yeni gerilemeler üretmiştir: 46681 numaralı issue, 27 Şubat 2026, hâlâ açıktır; `/admin/realms/{r}/users` isteği kullanıcı başına bir organizasyon üyelik sorgusu tetiklemektedir, hiç organizasyon olmasa bile.

Delege yönetim genel kullanıma açılmadan iki yıl sonra gelmiştir, 26.7.0, 9 Temmuz 2026: `manage-organizations` ile `view-organizations` rolleri ve ince taneli yönetim izinleri eklenmiştir. Kalan sınır birebir şöyledir: "Sub-resource permissions — such as separate control over an organization's members, groups, or identity providers — are not included in this milestone."

### 1.2 Zitadel: olay kaynaklı izolasyon ve ondan geri dönüş

**Gerçek DDL, kaynak koddan.** `cmd/initialise/sql/08_events_table.sql`, ana dal, 8 Eylül 2026:

```sql
CREATE TABLE IF NOT EXISTS eventstore.events2 (
    instance_id TEXT NOT NULL
  , aggregate_type TEXT NOT NULL
  , aggregate_id TEXT NOT NULL
  , event_type TEXT NOT NULL
  , "sequence" BIGINT NOT NULL
  , revision SMALLINT NOT NULL
  , created_at TIMESTAMPTZ NOT NULL
  , payload JSONB
  , creator TEXT NOT NULL
  , "owner" TEXT NOT NULL          -- org veya instance id
  , "position" DECIMAL NOT NULL
  , in_tx_order INTEGER NOT NULL
  , PRIMARY KEY (instance_id, aggregate_type, aggregate_id, "sequence")
);
CREATE INDEX es_projection ON eventstore.events2 (instance_id, aggregate_type, event_type, "position");
```

Dikkatle okunmalıdır. `instance_id` birincil anahtarın ilk kolonudur ve her indeksin başındadır; gerçek bölümleme anahtarı örnektir. `owner`, yani organizasyon, birincil anahtarda değildir ve hiçbir indekste değildir; yani organizasyon fiziksel bir sınır değil indekslenmiş bir özniteliktir. `owner` iddia edilmez, miras alınır: `commands_to_events()` içinde `CASE WHEN c.enforce_owner THEN c.owner ELSE COALESCE(e.owner, c.owner) END` ifadesi vardır ve bir agregatın organizasyonu ilk olayıyla sabitlenir. Kullanıcıların organizasyonlar arası taşınamamasının teknik nedeni tam olarak budur.

Benzersizlik kapsamı da örnektir; `10_unique_constraints_table.sql` içinde `PRIMARY KEY (instance_id, unique_type, unique_field)` vardır. Organizasyon kapsamlı kullanıcı adı bir dize kurgusuyla sağlanmaktadır, yani `user@orgdomain.instancedomain` biçimiyle, bir veritabanı kısıtıyla değil.

> Not olarak zitadel.com'un olay deposu implementasyon sayfası hâlâ birinci sürüm `events` tablosunu belgelemektedir. SQL'e güvenilmeli, o sayfaya güvenilmemelidir.

**Organizasyonun izole ettikleri ile etmedikleri.** İzole ettikleri giriş davranışı, çok adımlı doğrulama, parolasız akış ile oturum ömrü, kimlik sağlayıcılar, parola karmaşıklığı ile süresi, kilitleme, markalama, mesaj metinleri, alan adları, proje yetkileri ile kullanıcı adı biçimidir. İzole etmedikleri OIDC issuer'ı, giriş alan adı, benzersizlik kapsamı, projeksiyon durumu ile hız ve kota limitleridir; hepsi örnek seviyesindedir.

Özel alan adı dokümanı birebir şöyle demektedir: "by default, you cannot access ZITADEL at an organization's domain. Organization level domains are intended for routing users by their login methods to their correct organization."

Organizasyon seçimi bir OIDC kapsamıyla yapılmaktadır: `urn:zitadel:iam:org:id:{id}`. Doküman şöyle der: "ZITADEL will enforce that the user is a member of the selected organization."

**Kullanıcı modeli, ikinci okul, saf hâliyle.** Doküman şöyledir:

> "Users exist strictly within one Organization." ve "It is currently not possible to move users between organizations." ve "You can reuse the same email address for different user accounts across organizations."

Çapraz erişim harici kullanıcı yetkisiyle sağlanmaktadır: bir organizasyon başka bir organizasyonun kullanıcılarını kendi projelerine davet eder. Bu ikinci bir üyelik değil bir yetkidir.

Hiyerarşi yoktur ve gerekçesi kayıttadır; 11 Haziran 2026 tarihli 12248 numaralı tartışma:

> "zitadel orgs are flat by design (no built-in parent/child)" … "Grants only work one level deep (Parent → Child) and you can't do Parent → Child → Grandchild so pls keep your hierarchy flat."

Önerilen çözüm ebeveyn ile çocuk eşlemesini kendi uygulama veritabanınızda tutmaktır.

**Birinci gün çok kiracılık iddiası ne kadar gerçektir.**

Gerçek olan şudur: `instance_id` ile `owner` temel şemadan beri her olaydadır; sınırsız organizasyon vardır ve yayımlanmış bir organizasyon limiti yoktur.

Gerçek olmayanlar beş maddedir.

1. Organizasyon bir bölümleme değil bir kolon değeridir. Organizasyon yaratmak ucuzdur ancak organizasyon fiziksel bir izolasyon birimi değildir. Kiracı başına örnek ise bir duvardır: 70'ten fazla projeksiyonun her biri örnek başına ayrı bir durum tutmakta ve ayrı bir tavsiye kilidi almaktadır.
2. Zitadel N üzeri N sorununu kendisi kabul etmektedir; 12 Şubat 2026 tarihli blog yazısı şöyle der: her istek için bağlam çözümlemek bir N üzeri N ölçekleme darboğazı yaratmaktadır. Çözüm önbelleklemedir, ancak o önbellek v4.17'de hâlâ deneysel betadır ve varsayılan olarak kapalıdır.
3. Yayımlanmış bir kıyaslama yoktur: hedefler yazılıdır, yani saniyede 1000 kimlik doğrulama ile 1200 giriş, ancak sonuçlar için yukarıdaki hedefe ulaşılır ulaşılmaz belirleneceği söylenmektedir.
4. Gerçek rakamlar mütevazıdır; 31 Ocak 2025 tarihli 9285 numaralı tartışmaya göre tek bir Postgres ile saniyede yaklaşık 175 istek karşılanmakta ve 100 sanal kullanıcıda giriş 95. yüzdelikte 4,86 saniye sürmektedir. Bakımcı fforootd darboğazı bcrypt maliyeti 12 ile 14 olarak saptamıştır.
5. Çok organizasyonlu kullanıcı desteği hâlâ yoktur: 5822 numaralı issue 11 Mayıs 2023'ten beri açıktır ve 11 kriterden biri tamamlanmıştır. Bakımcı hifabienne 8518 numaralı tartışmada platformun doğrudan bu kullanım senaryosu için tasarlanmadığını söylemektedir.

**En önemlisi: v5'te projeksiyonları terk etmektedirler.** 9599 numaralı "Relational database tables" issue'su, 21 Mart 2025, kilometre taşı Zitadel v5'tir ve 66 alt görevin 47'si tamamlanmıştır. Durumu olay kaynaklı projeksiyonlardan düz ilişkisel tablolara taşımaktadırlar; olay deposu yalnızca denetim için kalmaktadır. Birebir gerekçe şöyledir:

> "This approach gave us a number of issues… Projections can become eventual consistent… This confuses tools like terraform"

Karar günlüğü sürücüyü doğrusal ölçeklenebilirlik sorunları olarak adlandırmakta ve kiracılık şeklini sabitlemektedir: kimlik benzersizliği, 4 Kasım 2025, kimlikler yalnızca örnek seviyesinde benzersizdir ve birincil anahtarlar `instance_id` ile kaynak kimliğini kullanmaktadır.

v5 prototip şemasında, yani `backend/v3/storage/database/repository/inheritance.sql` dosyasında, organizasyon artık kullanıcı birincil anahtarına girmektedir:

```sql
CREATE TABLE users ( username VARCHAR(50) NOT NULL,
    PRIMARY KEY (instance_id, org_id, id) ) INHERITS (org_objects);
```

> **Argus için ders.** Zitadel organizasyonu bir projeksiyon özniteliği yapmış, şimdi ölçeklenebilirlik için tüm depolama katmanını yeniden yazmakta ve organizasyonu anahtara geri koymaktadır. Kiracı birinci günde birincil anahtara konmalıdır.

### 1.3 Diğer ürünler, hızlı ancak kesin

**Auth0 Organizations.** Kullanıcılar kiracı seviyesindedir ve organizasyon bir üyelik katmanıdır. Kimliği organizasyon değil bağlantı sahiplenmektedir: "Every organization that uses the Auth0 Organizations feature uses exactly one Auth0 connection."

Varlık limiti politikasından birebir limitler şunlardır.

| Varlık | Limit |
|---|---|
| Kiracı başına organizasyon | 100.000 |
| Organizasyon başına üye | 100.000 |
| Organizasyon başına bağlantı | 10 |
| Organizasyon başına keşif alan adı | 100 |
| Organizasyon üyesi başına rol ataması | 50 |

Pazarlama sayısıyla çelişen iki gerçek limit vardır.

Birincisi yönetim API'sindeki bin kayıt tavanıdır. Auth0 personelinden rueben.tiow 27 Şubat 2025'te şöyle demiştir: organizasyonları alma ile bir organizasyona ait üyeleri alma isteklerinin ikisinde de bin kayıt limiti vardır; ayrıca binden fazla organizasyon almak için kontrol noktası sayfalaması yoktur. Yani 100.000 organizasyon saklayabilirsiniz ancak bir kullanıcının organizasyonlarını binin ötesinde sayamazsınız.

İkincisi organizasyon seçicisinin yirmi tane göstermesidir; 10 Eylül 2025 güncellemesinde yalnızca 20 organizasyonun gösterildiği yazmaktadır.

`org_name` bir tuzaktır. Kiracı genelinde açılır, organizasyon başına açılamaz; isimler değişebilir ile yeniden kullanılabilir ve uzun ömürlü token'lar bir organizasyon adını değiştirdiğinde süresi dolmaz. Birebir uyarı şöyledir: "If your API does not verify `iss` claims, an organization with the same name in a different tenant could generate tokens that are incorrectly accepted." Auth0'ın kendi tavsiyesi şudur: "Using organization IDs for token validation remains the recommended approach."

Organizasyon başına özel alan adı yoktur ve doküman kaçış yolunu açıkça yazmaktadır: "you would need to use multiple Auth0 tenants." Ayrıca evrensel giriş zorunludur; kaynak sahibi parola kimlik bilgisi, cihaz akışı ile WS-Fed uyumsuzdur.

Altı yıl sonra hâlâ boşluk doldurmaktadırlar: 29 Temmuz 2026'da organizasyon seviyesinde roller erken erişime açılmıştır. O güne kadar roller kiracı genelinde küreseldi ve yalnızca ataması organizasyon kapsamlıydı.

**WorkOS.** En temiz organizasyon modelidir ancak gerçek sınır ortamdır: "Email addresses are unique to each WorkOS environment." Kullanıcı küreseldir ve `OrganizationMembership` ile çok organizasyonlu olabilir.

Aktif e-posta birleştirmesi yapmaktadırlar; 1 Kasım 2024 tarihli blog yazısı şöyledir: kullanıcı aynı e-postayı kullandığı sürece WorkOS yinelenmeyi tespit edecek ve bu kimlikleri aynı kullanıcı altında bağlayarak çözecektir.

> Bu, nOAuth'un tam olarak kötüye kullandığı ilkeldir. Savunmaları kimlik katmanında değil alan adı katmanındadır: ortam başına yalnızca bir organizasyon belirli bir alan adını kendi alan adı politikasına dahil edebilir. Ayrıca WorkOS gmail.com gibi yaygın tüketici alan adlarının eklenmesine izin vermemektedir.

Çok organizasyonlu giriş akışı doğru tasarlanmıştır: `organization_selection_required` durumundan `pending_authentication_token` ile `urn:workos:oauth:grant-type:organization-selection` grant tipine gidilmektedir. JWT içeriği `sub`, `sid`, `iss`, `org_id`, `role` ile `permissions`'tır.

Sert kenar şudur: bir organizasyonda birden çok çoklu oturum açma bağlantısı varsa organizasyon seçicisi kırılmakta ve `ambiguous_connection_selector` hatası dönmektedir.

Limitleri API anahtarı başına 60 saniyede 6.000 istek ile organizasyon silmede 60 saniyede 50 istektir; yayımlanmış bir azami organizasyon sayısı yoktur, ki 1,88 MB'lık doküman dökümü taranmıştır ve bu doğrulanamamıştır.

**Frontegg, hiyerarşiyi gerçekten yapan tek üründür ve bedeli vardır.** `parentTenantId` gerçektir ve API gerçektir, yani `POST /resources/hierarchy/v1`. Rol mirası gerçektir: bir üst hesapta verilen bir rol, altındaki her alt hesaba otomatik olarak uygulanır.

Ancak taşıyıcı uyarı birebir şöyledir:

> "When users are granted access to sub-accounts, the accounts where they are allowed will not appear on the user's access token (JWT) or the user's state."

Uygulama, kullanıcının hangi hesaplara erişebildiğini bir API çağrısıyla hesaplamak zorundadır.

> **Hiyerarşinin bedeli tek cümlededir: miras geçişli hâle gelince token'a sığmayı bırakır ve her yetkilendirme kararı bir graf sorgusuna dönüşür.**

Azami derinlik hiçbir yerde belgeli değildir ve doğrulanamamıştır. Ayrıca engelleyici bir sınır vardır: özel giriş kutuları etkinleştirilmiş hesaplar arasında kiracı değiştirme desteklenmemektedir. Yani kiracı başına markalı giriş ile sorunsuz kiracı değişimi arasında seçim yapmak zorunda kalırsınız.

Her planda geçerli sert bir kenar daha vardır: çoklu oturum açma yapılandırması yazma işlemi dakikada beş ile on istektir, kurumsal plan dahil. Binlerce kiracının çoklu oturum açma bağlantısını sağlamak, ne kadar ödenirse ödensin kısıtlıdır.

**authentik'te marka çok kiracılık değil markalamadır.** Doküman sayfasının başlığı birebir markalamadır. Marka alanları `authentik/brands/models.py` içinde alan adı, varsayılan bayrağı, markalama başlığı, logosu, favicon'u, özel CSS'i ile arka planı, dokuz varsayılan akış yabancı anahtarı, varsayılan uygulama, web sertifikası, istemci sertifikaları ile öznitelikler şeklindedir.

Markadan kullanıcıya, gruba, role, sağlayıcıya, kaynağa ya da politikaya hiçbir yabancı anahtar veya çoktan çoğa ilişki yoktur. Marka, hostname başına bir sunum ile varsayılan akış kaydıdır.

İzole etmediklerinin kanıtı 20 Haziran 2023 tarihli 6020 numaralı issue'dur: uygulamalarım listesi, kullanıcının en son eriştiği kiracıya göre uygulama kümesini göstermektedir. Planlanmadı olarak kapatılmış ve eski ile düzeltilmeyecek etiketleri verilmiştir. 6140 numaralı kiracı sayımı issue'su da planlanmadı olarak kapatılmıştır.

Gerçek çok kiracılık, yani Postgres şemaları ile `django-tenants`, alfa aşamasındadır ve kurumsal sürüme kapalıdır. Bakımcı dewi-tik 23 Aralık 2025 tarihli 19009 numaralı issue'da şöyle demiştir:

> "Multi-tenancy is still in early preview and likely to remain that way for the foreseeable future. It is also likely to remain an enterprise feature. However, there's nothing preventing you from running multiple instances and syncing users between them."

Belgeli sınır şudur: ifade politikalarının şu anda tüm kiracılara erişimi vardır.

**Okta'nın hücre mimarisi.** Eylül 2022 tarihli yüksek erişilebilirlik mimarisi beyaz kâğıdı şöyle demektedir:

> "One of the most critical aspects of Okta's architecture is that it is completely multi-tenant. With this design, customers share the same underlying environment."
>
> "Each Okta environment is called a cell… Because each cell can operate independently, they form the basis of our availability strategy by helping to limit the number of customers impacted by an outage."
>
> "every cell is an isolated, shared-nothing, identical replica of our infrastructure, spanning routers and load-balancers within our edge to databases."

status.okta.com yaklaşık 26 tanımlayıcı listelemektedir, yani onlarca hücre vardır, yüzlerce değil.

Organizasyon modeli şöyledir: organizasyonlar sert sınırlardır, dolayısıyla nesneler organizasyonlar arasında paylaşılamaz. Federasyonla bile kullanıcılar her organizasyonda ayrı ayrı var olmaktadır. Alt organizasyon yoktur. Tek organizasyonlu kiracılık grup ile isim konvansiyonuyla yapılır; dokümanın kendi örneği `app-1-johndoe` biçimindedir.

Hız limiti organizasyon başınadır: `/oauth2/v1/authorize` için dakikada 1200 istek, `/api/v1/users/*` için dakikada 1000 istek.

İhlaller veri düzleminde değil destek düzleminde olmuştur. Ekim 2023'te tehdit aktörü, son destek talepleri kapsamında bazı Okta müşterilerinin yüklediği dosyaları, yani HAR dosyaları ile oturum token'larını, görüntüleyebilmiştir. Okta destek talebi yönetim sisteminin üretim servisinden ayrı olduğunu belirtmiştir.

> **Argus için ders.** Organizasyon sınırı tutmuştur; başarısız olan, müşteri kiracılarının içinde geçerli kimlik bilgisi tutan bant dışı bir sistemdi. Destek ile kimliğe bürünme araçları kasıtlı bir çapraz kiracı kontrol düzlemidir ve mimariden daha fazla inceleme hak eder.

**Entra ID'de kiracı bir güvenlik sınırı, bölüm bir ölçek birimidir.** learn.microsoft.com'un mimari sayfası, tarih 7 Mayıs 2026, şöyle demektedir:

> "For the Microsoft Entra data tier, scale units are called partitions." Birincil replika tüm yazmaları almakta ve farklı bir veri merkezindeki ikincile anında replike etmektedir; okumalar coğrafi dağıtık ikincillerden ve asenkron yapılmaktadır.
>
> "The directory model is one of eventual consistency." Ve kritik olarak: "For application-only requests, Microsoft Entra ID does not provide session consistency."

Token seviyesinde izolasyon birebir şöyledir:

> "If a single user exists in multiple tenants, the user contains a different object ID in each tenant — they're considered different accounts."
>
> "Don't use the `idp` claim to store information about a user in an attempt to correlate users across tenants. It doesn't work, as the `oid` and `sub` claims for a user change across tenants, by design."

Servis limitleri, tarih 29 Temmuz 2026: kullanıcı başına en fazla 500 kiracı üyeliği; 200 kiracı yaratma; doğrulanmış alan adlı kiracıda 300.000 nesne; 240 koşullu erişim politikası; SAML token'ında 150, JWT'de 200 ile koşullu erişim değerlendirmesinde 4.096 grup.

Raporun en kolay gözden kaçan mimari gerçeği şudur: External ID iki dizin ölçek modu yayımlamaktadır; standart mod 15 milyon nesneye kadardır, üstünde yüksek ölçekli mod vardır ve bu modda gelişmiş sorgular, delta sorguları ile giden SCIM sağlaması desteklenmemektedir. Doküman şöyle der: yüksek ölçekli mod, sorgu yoğun veya olay güdümlü dizin işlemleri yerine ölçekte kararlılık ile iş hacmini önceliklendirmektedir.

**Rust dünyasında kimse bunu yapmamaktadır.**

| Proje | Durum |
|---|---|
| Kanidm | Reddetmiştir; planlanmadı, 13 Haziran 2026. Gerekçesi yukarıdadır |
| Rauthy | Çok kiracılık yoktur. 1678 numaralı issue'da kullanıcı sormaktadır ve cevap yoktur |
| Ory Kratos | Doküman şöyle der: Ory Kratos'un açık kaynak sürümü yalnızca tek kiracılı kullanım içindir ve veri modeli çok kiracılı bir ortamın veri izolasyonu, ölçeklenebilirlik ile operasyonel ihtiyaçlarını destekleyecek şekilde mimarlanmamıştır. 407 numaralı issue Mayıs 2020'den beri açıktır; 3129 numaralı issue planlanmadı olarak kapatılmıştır |

crates.io taramasına göre, 8 Eylül 2026, hazır bir çok kiracılık altyapısı yoktur. En büyüğü `pg_multitenant`'tır ve 1.617 indirmesi vardır, son güncellemesi 2024'tür, yani ölüdür. Karşılaştırma olarak `generativity` 3.991.685 indirmelidir ve aktiftir.

### 1.4 Ürün modellerinin karşılaştırması

| Ürün | Kiracı birimi | İzolasyon gücü | Ölçek sınırı | Kullanıcı kapsamı | Neyi yanlış yapmıştır |
|---|---|---|---|---|---|
| Keycloak realm'i | Realm | Veride güçlüdür ancak yabancı anahtarsız bir ayırıcıdır; çalışma zamanında sıfırdır | Küme başına 200 ile 500 | Realm'e yereldir | Master realm O(N) bağlaması, sabit 10 bin küresel önbellek ile on yıllık Hibernate N artı bir sorunu |
| Keycloak Organizations | Realm içi organizasyon | Zayıftır; paylaşımlı kullanıcı havuzu, paylaşımlı anahtar ile paylaşımlı tema vardır | Realm başına birkaç bin | Realm genelinde küresel artı üyelik | Genel kullanıma açılmadan iki yıl sonra delege yönetim gelmiştir ve kendi N artı bir sorununu üretmiştir |
| Zitadel örneği | Örnek | Güçlüdür; birincil anahtarın ilk kolonudur | Projeksiyon başına doğrusal maliyet | Örnek | — |
| Zitadel organizasyonu | Organizasyon | Zayıftır; indekslenmiş bir özniteliktir, birincil anahtarda değildir | Yayımlanmamıştır | Organizasyona yereldir ve taşınamaz | Organizasyonu anahtar yapmamıştır ve v5'te tüm depolamayı yeniden yazmaktadır |
| Auth0 organizasyonu | Kiracı içi organizasyon | Ortadır; kimliği bağlantı sahiplenmektedir | 100 bin saklanır, bin sayılabilir ile 20 gösterilir | Kiracı genelinde küreseldir | Bağlantı sahipli kimlik; organizasyon kapsamlı roller 2026'da erken erişimdedir |
| WorkOS organizasyonu | Ortam içi organizasyon | İyidir; her bağlantı, dizin ile günlük organizasyona aittir | Yayımlanmamıştır | Ortam genelinde küreseldir ve e-postayla otomatik birleştirilir | E-posta birleştirmesi bir nOAuth yüzeyidir |
| Frontegg hesabı | Hesap ile alt hesap | Ortadır | Yayımlanmamıştır; çoklu oturum açma yazma işlemi dakikada 5 ile 10'dur | Ortam genelinde küreseldir ve otomatik birleştirilir | Miras JWT'ye ulaşmamaktadır; özel giriş ile kiracı değiştirme arasında çelişki vardır |
| authentik markası | Marka | Yoktur; yalnızca markalamadır | — | Tek havuzdur | Kiracı adını markalamaya vermiştir ve gerçek kiracılık iki yıldır alfadır |
| Okta organizasyonu | Organizasyon ile hücre | Çok güçlüdür; hiçbir şeyi paylaşmayan hücre yapısıdır | Yaklaşık onlarca hücre | Organizasyona yereldir | Destek düzlemi iki kez ihlal edilmiştir |
| Entra kiracısı | Kiracı ile bölüm | Çok güçlüdür; bir güvenlik sınırıdır | Kullanıcı başına 500 kiracı, 300 bin nesne | Kiracıya yereldir; `oid` tasarım gereği değişir | Paylaşımlı Microsoft hesabı anahtarı Storm-0558'e yol açmıştır |
| Stytch organizasyonu | Organizasyon | Güçlüdür; üye organizasyona yereldir | Yayımlanmamıştır | Organizasyona yereldir | Gençtir ve ilk ölçek göçünün önündedir |
| Logto organizasyonu | Kiracı içi organizasyon | Bulutta satır seviyesi güvenlik ile kiracı başına Postgres rolü vardır | — | Logto kiracısı genelinde küreseldir | Satır seviyesi güvenlik ya hep ya hiçtir: 60'tan fazla tabloda zorunludur, yoksa başlamamaktadır |
| SuperTokens kiracısı | Uygulama ile kiracı | İyidir; varsayılan olarak izole havuz vardır | — | Uygulama kimliği, kiracı kimliği ile e-posta sıralıdır | 2023'te sonradan eklenmiştir: 33 tablo ile tüm birincil anahtarlar basamaklı olarak düşürülmüş ve dünyayı durduran bir migration yapılmıştır |

---

## Bölüm II — Veritabanı izolasyon stratejileri

### 2.1 Üç strateji, ölçülmüş karşılaştırma

| Boyut | Satır bazlı, `tenant_id` ile satır seviyesi güvenlik | Kiracı başına şema | Kiracı başına veritabanı |
|---|---|---|---|
| Pratik kiracı tavanı | Bir milyon ve üzeri; Citus bir ile bir milyonun üzerini vermektedir | 1.000 ile 2.000; satıcı aralığı 100 ile 10.000 | Yaklaşık 50; Crunchy 50 müşteri ve üzerinde uzak durun demektedir |
| Migration maliyeti | Sabittir, tek bir DDL yeterlidir | Kiracı sayısıyla doğrusaldır: 1.200 kiracı iki saat, 1.500 kiracı beş saat | Kiracı sayısıyla doğrusaldır, artı bağlantı çoğullaması |
| Yedekleme ile geri yükleme ayrıntısı | Zayıftır; mantıksal dışa aktarım gerekir | İyidir, `DROP SCHEMA CASCADE` vardır; ancak pg_dump ile 20 bin şema 24 saatten uzun sürmektedir | Mükemmeldir, `DROP DATABASE` yeterlidir |
| Bağlantı havuzu | En iyisidir; tek havuz ile `SET LOCAL` sunucu garantilidir | Kırılgandır; `search_path` bir oturum durumudur ve PgBouncer 1.20 ve üstünde `track_extra_parameters` gerekir | En kötüsüdür; havuz çarpımı olur |
| Gürültülü komşu | Kötüdür; her şey paylaşımlıdır ve tek yerel araç `citus_stat_tenants`'tır | Ortadır | En iyisidir |
| Kişisel veri silme | `DELETE` ölü kayıt ile vacuum baskısı üretir; bölümlenmişse ayır ve düşür yapılır | Anındadır | Anındadır |
| İşlem kimliği ile nesne kimliği dolanması | Düşüktür | Düşüktür | Yüksektir; bunlar küme genelinde tek bir sayaçtır |
| Satıcı kılavuzu | Crunchy milyonlar, Citus bir ile bir milyon üzeri demektedir | Crunchy yüzler, Citus bir ile on bin, PlanetScale birkaç yüz demektedir | Crunchy 50'den kaçının demektedir |

Kaynakları AWS öngörülü rehberlik matrisi, Crunchy Data'dan Craig Kerstiens'in 14 Kasım 2023 tarihli yazısı, Citus 12 için Marco Slot'un 18 Temmuz 2023 tarihli yazısı ile PlanetScale'in 21 Nisan 2026 tarihli yazısıdır.

### 2.2 Kritik sayı: PostgreSQL kaç şemayı gerçekten kaldırmaktadır

Cevap düşük binlerdir. Bağlayıcı kısıt katalog tarama maliyeti, arka uç başına ilişki önbelleği ile migration ve yedekleme duvar saatidir, depolama değildir.

**Birinci kanıt: migration katili, en aktarılabilir sayı.** pgsql-performance listesinde Ulf Lohbrügge, 27 Haziran 2017, PostgreSQL 9.5.7. Yaklaşık 1.200 şema ile şema başına yaklaşık 200 tablo, yani yaklaşık 240.000 tablo vardır. `SELECT * FROM information_schema.tables WHERE table_schema='foo' AND table_name='bar';` sorgusunun yürütmesi 383,784 milisaniye sürmüş, `pg_class` üzerinde ardışık tarama yapılmış, 1.305.161 satır filtreyle elenmiş ve sıfır satır dönmüştür. Sebebi `information_schema` görünümlerinin satır başına `pg_has_role()` çağırmasıdır ve bu, sistem katalogları üzerinde indekslenemez. İş etkisi tüm kiracılarda Flyway migration'ının yaklaşık iki saat sürmesidir, çünkü kiracı başına on ve üzeri `information_schema` sorgusu yapılmaktadır.

> Bu, raporun en aktarılabilir sayısıdır: `information_schema` sorgulayan her nesne ilişkisel eşleyici ile migration aracı, her çağrıda tam bir `pg_class` taraması ödemektedir ve bu maliyet toplam ilişki sayısıyla doğrusaldır. Kiracı başına şema sorun değil, migration'ı otomatikleştir tavsiyesinin pratikte neden çöktüğünün açıklaması budur.

Doğrulayıcı bir kaynak django-tenant-schemas deposundaki 387 numaralı issue'dur, 29 Eylül 2016: 1500'den fazla kiracıda migration beş saatten uzun sürmektedir.

**İkinci kanıt: pg_dump duvarı.** pgsql-hackers listesinde "pg_dump and thousands of schemas" başlıklı konu, Mayıs ile Kasım 2012 arası. Üretimde Hugo'nun PostgreSQL 9.0 kurulumunda 20.000'den fazla şema, yaklaşık 500.000 ilişki ile 40 GB veri vardır; tek bir boş şemanın dökümü yaklaşık 12 dakika, tam döküm 24 saatten uzun sürmektedir, oysa monolitik şemadayken iki ile üç saatti; dolayısıyla günlük tutarlı bir yedek imkânsızdır. 2.311 şemalı örnek veritabanında üç saat sürmektedir. Sentetik testte Tatsuo Ishii 100.000 tabloyla PostgreSQL 9.0.2'de 188 dakika ölçmüş, sunucu tarafı kilit düzeltmesinden sonra süre dört dakikanın altına inmiştir, yani %97 azalmıştır. Mekanizması `LockReassignCurrentOwner` fonksiyonunun O(N²) olmasıdır ve PostgreSQL 9.2'de düzeltilmiştir. Ancak Denis, PostgreSQL 9.2.1 ile 6 Kasım 2012'de hâlâ tek şema dökümünde veri boyutundan bağımsız 30 ile 40 saniye görmekteydi; `pg_class`, `pg_depend` ile `pg_authid` birleştirmesi tek başına 10 ile 15 saniye sürmekteydi.

**Üçüncü kanıt: autovacuum çöküşü, 13750 numaralı hata.** David Gould, 30 Ekim 2015, PostgreSQL 9.4.5, 80 donanım iş parçacığı ile 1 TB bellek: yaklaşık 200.000 tablo ve `pg_class` içinde 500.000'den fazla satır vardır.

| autovacuum işçisi | Saatte işlem | İşçi başına |
|---|---|---|
| 1 | 2110,1 | 2110,1 |
| 4 | 647,3 | 161,8 |
| 72 | 62,0 | 0,9 |

İşçi eklemek iş hacmini düşürmektedir. Belirtileri `pg_attribute` tablosunun 200 GB'a çıkması ile yeni bağlantıların başlangıçta takılmasıdır; kataloglar artık tampon önbelleğe sığmamaktadır.

**Dördüncü kanıt: arka uç başına bellek, yoğunluk sınırı.** PostgreSQL dokümanının §5.12.6 bölümü birebir şöyledir:

> "the server's memory consumption may grow significantly over time, especially if many sessions touch large numbers of partitions. That's because each partition requires its metadata to be loaded into the local memory of each session that touches it."

Citus aynı mekanizmayı on binden fazla şemada bir başarısızlık modu olarak adlandırmakta ve PostgreSQL'in süreç başına katalog önbelleğinin aşırı bellek tükettiğini söylemektedir.

**Uzman uzlaşısı.** John R Pierce, 30 Eylül 2016: bin şema ile şema başına yüz tablo, postgres kataloğunun devasa şişmesine yol açar ve ayrıca önbelleklemeyi daha az etkili kılar. Jeff Janes, 1 Ekim 2016: çok veritabanlı ile çok şemalı arasındaki çalışma zamanı farkı PostgreSQL 9.3'ten sonra büyük ölçüde kapanmıştır; seçim çalışma zamanı maliyetine göre değil geri yükleme ayrıntısına göre yapılmalıdır. Paul Jungwirth, 30 Eylül 2016: kiracı başına şema, katalog sorgularıyla kiracı sayısını sızdırmaktadır.

**Mutlak tavan PostgreSQL değil dosya sistemidir.** kspeakman, 8 Şubat 2019: 1,3 milyon tablo yaratılmış, yaklaşık 4 GB boş tablo oluşmuş ve 13 GB boş alan varken `53100: No space left on device` hatası alınmıştır, yani düğüm numaraları tükenmiştir.

### 2.3 sqlx 0.9'daki `sqlx.toml` gerçekte ne vermektedir

Cevap beklenenden çok azıdır.

sqlx 0.9.0 21 Mayıs 2026'da yayımlanmıştır, crates.io API'sine göre; 0.9.0-alpha.1 ise 15 Ekim 2025 tarihlidir.

`[migrate]` anahtarları docs.rs'teki `migrate::Config` sayfasında şöyledir. `table-name` yürütülen migration'ları izlemek için kullanılan tablonun adını değiştirmektedir; varsayılanı `_sqlx_migrations`'tır ve şema nitelikli olabilir, çok kiracılı veritabanları için yararlı denmektedir. `create-schemas` zaten yoksa yaratılacak şemaların adlarını belirtmektedir. Ayrıca `migrations-dir`, `ignored-chars` ile `defaults` vardır.

Deponun `examples/postgres/multi-tenant` örneği kiracı çok kiracılığı değildir. Üç crate, yani ana, hesaplar ile ödemeler, tek bir veritabanında kendi şemasını yönetmektedir. `sqlx.toml` dosyasının tamamı şudur:

```toml
[migrate]
# Move `migrations/` to under `src/` to separate it from subcrates.
migrations-dir = "src/migrations"
```

Doküman ayrıca `search_path` kullanımına karşı uyarmakta ve şema nitelikli isim önermektedir: `search_path` değeri `public,accounts,payments` olarak ayarlanırsa migration aracı bir hata fırlatacaktır.

> **Sonuç: `sqlx.toml` dinamik, kiracı başına şema migration'ı vermemektedir.** Şema listesi yapılandırma zamanında sabittir. N kiracı için N şemayı migrate etmek tamamen sizin yazacağınız koddur. Bu, kiracı başına şema seçeneğinin Rust'taki ekstra maliyetidir.

### 2.4 Bağlantı havuzu ile oturum durumu sızıntısı, kesin cevap

Soru şudur: PgBouncer'ın işlem modunda `SET app.tenant_id` gerçek bir sızıntı riski midir.

Cevap şudur: `SET` kullanılırsa evet, gerçek bir güvenlik açığıdır; `SET LOCAL` kullanılırsa hayır ve garanti havuzlayıcıdan değil sunucudan gelmektedir.

PgBouncer dokümanı birebir şöyledir:

> "When transaction pooling is used, the `server_reset_query` is not used, because in that mode, clients must not use any session-based features, since each transaction ends up in a different connection and thus gets a different session state."

`server_reset_query` varsayılanı `DISCARD ALL`'dır ve `server_reset_query_always` varsayılan olarak kapalıdır. Özellik matrisinde işlem havuzlaması için `SET` ile `RESET` asla olarak işaretlidir.

PostgreSQL'in `SET` dokümanı birebir şöyledir:

> "The effects of `SET LOCAL` last only till the end of the current transaction, whether committed or not. After `COMMIT` or `ROLLBACK`, the session-level setting takes effect again."
>
> "Issuing this outside of a transaction block emits a warning and otherwise has no effect."

Doğru kalıp şudur:

```sql
BEGIN;
  SELECT set_config('argus.tenant_id', $1, true);   -- true = SET LOCAL
  -- sorgular
COMMIT;   -- GUC gitti, sunucu garantili
```

Üç ölümcül tuzak vardır. Birincisi işlem dışında `SET LOCAL` sessizce hiçbir şey yapmamakta, yalnızca uyarı vermektedir; açık bir işlem zorunludur. İkincisi `LOCAL` olmadan düz `SET`, kesinleştirmede sunucu bağlantısında kalmakta ve PgBouncer'ın işlem modunda `DISCARD ALL` çalışmadığı için bir sonraki istemci onu miras almaktadır. Üçüncüsü aynı işlemde önce `SET` sonra `SET LOCAL` kullanmaktır; PostgreSQL dokümanı şöyle der: `SET LOCAL` değeri işlemin sonuna kadar görülecek, ancak sonrasında, işlem kesinleştirilirse, `SET` değeri yürürlüğe girecektir.

AWS RDS Proxy PostgreSQL için pratikte diskalifiyedir. Sabitleme dokümanı şöyle der: bir parametre ayarlamak, özellikle `SET` ile `set_config` komutlarını kullanmak, sabitlemeye yol açmaktadır. Ayrıca RDS Proxy PostgreSQL için oturum sabitleme filtrelerini desteklememektedir, yani vazgeçilemez. `SET LOCAL` muafiyeti yalnızca MySQL bölümünde yazmaktadır; PostgreSQL bölümü `SET`'i koşulsuz listelemektedir ve muafiyet doğrulanamamıştır, varsayılmamalıdır.

Kiracı başına şemanın havuz hikâyesi yapısal olarak daha kırılgandır. Citus 12 için PgBouncer 1.20 ve üstü ile `track_extra_parameters = search_path` gerekmektedir. `search_path`, havuzlayıcının izleyip yeniden uygulaması gereken bir oturum durumudur ve `SET LOCAL`'ın sunucu garantisinden kesinlikle daha zayıftır.

### 2.5 Bölümlemeyle kiracı: kilitler planlamadan önce çarpmaktadır

PostgreSQL dokümanının §5.12.6 bölümü şöyle der: sorgu planlayıcısı, tipik sorguların planlayıcının küçük bir bölüm dışındakileri budamasına izin verdiği varsayımıyla, birkaç bin bölüme kadar olan hiyerarşileri genelde iyi ele alabilmektedir. §5.12.4 ise şöyle der: bu aşamada yapılan bölüm budamasıyla kaldırılan bölümler, yürütmenin başında hâlâ kilitlidir.

Ölçüm olarak Kaarel Moppel, 18 Nisan 2023, PostgreSQL 15.2, pgbench ölçeği 5000, 56 saat: planlama süresi 16 bölümde %51,8 artmış, 4096 bölümde %128,8 artmıştır. Yürütme süresi neredeyse sabit kalmıştır, artı %4,6 ile eksi %5 arasında. `max_locks_per_transaction` değerini 64'ten 128'e çıkarmak zorunda kalınmıştır.

PostgresAI'ın 3 Ekim 2024 tarihli PostgreSQL 16 ölçümüne göre yeni bir bağlantıda bin bölüm için planlama 12,435 milisaniye, yürütme 0,354 milisaniyedir, yani 35 kat fark vardır. 4 Ekim 2024 tarihli önemli düzeltmesine göre yeniden kullanılan bir bağlantıda ikinci `EXPLAIN` çağrısı bin bölümde bile 0,1 milisaniyenin altındadır. Yani bölüm planlama maliyeti bir soğuk bağlantı maliyetidir; sıcak arka uç tutan bir havuzlayıcıyla büyük ölçüde kaybolmakta, sunucusuz veya kısa ömürlü bağlantılarda ise baskın gecikme olmaktadır.

Asıl tehlike planlama değil kilittir. Kyle Hailey, Nisan 2023, PostgreSQL 13, saniyede 10.000 sorgu: 40 bölüm ile 22 indeks sorgu başına 880 kilit demektir; zirvede 150.000 kilit görülmüş, 500 oturum kilit yöneticisi hafif ağırlıklı kilidinde beklemiş ve saniyede 1.000 hata alınmıştır. Başlangıcı yalnızca yaklaşık 12 bölümde, yani 220'den fazla kilitte gerçekleşmiştir.

Mekanizması şudur: PostgreSQL 17'ye kadar her arka uçta tam olarak 16 hızlı yol kilit yuvası vardır. Christophe Pettus, 17 Ağustos 2026: birincil anahtarı ile 20 ikincil indeksi olan tek bir tablo sorgu başına 22 kilit gerektirmekte ve tüm hızlı yol yuvalarını doldurmaktadır.

PostgreSQL 18 bunu düzeltmektedir; Tomas Vondra'nın `c4d5cb71d` commit'i hızlı yol kilitlerini `max_locks_per_transaction` değerinden boyutlanan değişken dizilere taşımaktadır, yani varsayılanla arka uç başına 64 yuva olmaktadır. PostgresAI kıyaslaması, 9 Ekim 2025, `max_locks_per_transaction=1024` ile uçurumun hiç oluşmadığını göstermektedir.

Bütçe formülü şudur: bölüm sayısı ile bölüm başına indeks sayısının bir fazlasının çarpımı, planlayıcının plan zamanında budayamadığı her sorgunun kilit maliyetidir.

### 2.6 Satır seviyesi güvenlik: gerçek performans ile gerçek atlatma yüzeyi

**Atlatma yüzeyi, PostgreSQL dokümanından birebir.**

> "Superusers and roles with the `BYPASSRLS` attribute always bypass the row security system when accessing a table. Table owners normally bypass row security as well, though a table owner can choose to be subject to row security with `ALTER TABLE ... FORCE ROW LEVEL SECURITY`."

> Bir numaralı sessiz başarısızlık modu budur: uygulamanız tablo sahibi olarak bağlanıyorsa, ki her migration aracının varsayılanı budur, `ENABLE ROW LEVEL SECURITY` kelimenin tam anlamıyla hiçbir şey yapmamaktadır.

> "Referential integrity checks, such as unique or primary key constraints and foreign key references, always bypass row security to ensure that data integrity is maintained. Care must be taken when developing schemas and row level policies to avoid 'covert channel' leaks of information through such referential integrity checks."

> **Argus için doğrudan sonuç doğuran türetilmiş sonuç:** küresel bir `UNIQUE(email)` kısıtı satır seviyesi güvenliği atlamakta ve bir benzersizlik ihlali hatası kiracı A'ya bu e-postanın başka bir kiracıda var olduğu bilgisini sızdırmaktadır. `UNIQUE(tenant_id, email)` bir tercih değil bir gizli kanal savunmasıdır.

> "(The only exceptions to this rule are `leakproof` functions, which are guaranteed to not leak information; the optimizer may choose to apply such functions ahead of the row-security check.)"

Sonucu pganalyze'de Lukas Fittl'in 28 Temmuz 2022 tarihli yazısında görülmektedir: sızdırma güvencesi olmayan operatörler indeks kullanımını tamamen kaybettirebilmektedir ve satır seviyesi güvenlik açılınca `ILIKE` operatörünün GIN indeksini yok saydığı belgeli bir vaka vardır. Yönetilen servislerde bir fonksiyonu sızdırma güvenceli işaretlemek süper kullanıcı gerektirmektedir, yani RDS ile Cloud SQL'de düzeltilemez.

Görünümler varsayılan olarak tanımlayıcı güvenlikle çalışmaktadır. PostgreSQL 15 `CREATE VIEW ... WITH (security_invoker = true)` seçeneğini eklemiştir.

**Satır seviyesi güvenlik CVE'lerinde bir örüntü vardır.**

| CVE | Açıklama | Düzeltildiği sürümler | CVSS |
|---|---|---|---|
| CVE-2026-14666, 13 Ağustos 2026 | Satır güvenliği önbelleklemesi rol değişikliklerini dikkate almamaktadır | 18.6, 17.11, 16.15, 15.19 ile 14.24 | 4,2 |
| CVE-2024-10976 | Alt sorguların altındaki satır güvenliği kullanıcı kimliği değişikliklerini dikkate almamaktadır | 17.1, 16.5, 15.9 ile 14.14 | 4,2 |
| CVE-2023-2455 | Satır güvenliği politikaları satır içine alma sonrası kullanıcı kimliği değişikliklerini dikkate almamaktadır | 15.3 ile 14.8 | 4,2 |
| CVE-2023-39418 | MERGE güncelleme ile seçme satır güvenliği politikalarını uygulayamamaktadır | 15.4 | 3,1 |

> Dördün üçü aynı hata sınıfındandır: oturum içinde etkin rol değiştiğinde satır seviyesi güvenlik politika önbelleğinin geçersizleştirilmemesi. Bu tam olarak işlem başına `SET ROLE` yapan bir bağlantı havuzlayıcısının tetiklediği şeydir. Satır seviyesi güvenlik ile `SET ROLE` ile havuzlama birlikte kullanılıyorsa agresif yamalanmalı ve asgari sürüm sabitlenmelidir.

Ayrıca CVE-2019-10130 vardır: sızdıran bir operatör, planlayıcı istatistiklerinden örneklenmiş veri okuyabilmekteydi; bu veri bir satır güvenliği politikasınca yasaklanmış satırlardan değerler içeriyorsa kullanıcı politikayı etkili biçimde atlayabilmekteydi.

Komşu bir gerçek dünya kırılması Heroku Postgres'tedir; 29 Ekim 2025'te açıklanmış ve 4 Kasım 2025'te düzeltilmiştir. `_heroku` şemasındaki `search_path` niteliksiz bir tanımlayıcı güvenlikli fonksiyon vardı; saldırgan `public` şemasında `pg_event_trigger_ddl_commands()` fonksiyonunu gölgelemiş, `rds_superuser` yetkisi kazanmış ve diğer müşterilerin veritabanlarını okuyup yazmıştır. Kaynağı allistair.sh'tir.

> **Ders şudur:** `SET search_path` içermeyen bir tanımlayıcı güvenlikli fonksiyon, herhangi bir Postgres kiracılık modelinden çıkışın standart kaçış yoludur.

**Satır seviyesi güvenlik performansında dört büyüklük mertebesi vardır.** Supabase'in kendi kıyaslaması, 100 bin satırlık bir tablo üzerinde:

| Optimizasyon | Önce | Sonra |
|---|---|---|
| Satır seviyesi güvenlik kolonuna indeks | 171 ms | 0,1 ms'nin altı |
| `auth.uid()` çağrısını `(select auth.uid())` yapmak | 179 ms | 9 ms |
| Tanımlayıcı güvenlikli `has_role()` fonksiyonunu `select` ile sarmak | 178.000 ms | 12 ms |
| Politikaya `TO authenticated` eklemek | 170 ms | 0,1 ms'nin altı |

Bir milyon satır ile takım üyeliğinde:

| Politika biçimi | İndeks | 10 takım | 500 takım |
|---|---|---|---|
| `= ANY(user_teams())` | Yok | İki dakikanın üzeri | İki dakikanın üzeri |
| `= ANY(ARRAY(select user_teams()))` | Yok | 170 ms | 3.300 ms |
| `= ANY(ARRAY(select user_teams()))` | Var | 2 ms | 3 ms |

Mekanizması şudur: `(select ...)` ile sarmak planlayıcıya bir başlangıç planı kurdurmakta, fonksiyon satır başına değil sorgu başına bir kez değerlendirilmekte ve ardışık tarama indeks taramasına dönmektedir. Kısıtı dokümanda yazmaktadır: bu yalnızca sorgunun ya da fonksiyonun sonuçları satır verisine göre değişmiyorsa geçerlidir.

> **Satır seviyesi güvenlik yavaş değildir.** Naif yazılmış satır seviyesi güvenlik bir felakettir, ayarlanmış olanı bedavaya yakındır. Fark dört ile beş büyüklük mertebesidir ve tamamen politika biçimine bağlıdır.

Bağımsız bir ölçüm Scott Pierce'ındır, 5 Ocak 2025: bir milyon blog ile 1,8 milyon üyelikte doğrudan ilişkili sayım 31,162 milisaniye, alt sorgulu `IN` ise 106,628 milisaniye sürmektedir, yani 3,4 kat fark vardır.

Ölçülmemiş bir bilinmeyen vardır ve doğrulanamamıştır: satır seviyesi güvenlik ile genel plan önbelleklemesinin etkileşimi. `current_setting()` kararlıdır ve yürütme başına yeniden değerlendirilir, dolayısıyla doğruluk korunmaktadır. Ancak on satırlı bir kiracı için seçilen genel plan, on milyon satırlı bir kiracı için felaket olabilir. Bu konuda ölçülmüş hiçbir çalışma bulunamamıştır ve kendi iş yükünüzde test edilmelidir.

### 2.7 Citus, kiracı başına havuz ile PostgreSQL 17 ve 18

**Citus 12'nin şema tabanlı parçalaması**, Temmuz 2023, `SET citus.enable_schema_based_sharding TO on;` ile açılmaktadır. Sınırları şunlardır: yabancı anahtarlar ile birleştirmeler tek bir şema içinde kalmalıdır, referans tabloları hariç; paralel çapraz kiracı sorgusu yoktur; on binden fazla şemada süreç başına katalog önbelleği belleğinden bozulmaktadır. Tek yerel gürültülü komşu aracı `citus_stat_tenants`'tır ve Citus 11.3 ile gelmiştir.

**Ölçekte gerçekte ne yapılmaktadır.** Notion 32 örnek ile örnek başına 15 mantıksal parça, yani 480 mantıksal parça kullanmakta ve bunu çalışma alanı kimliğine göre yapmaktadır; sonra 96 örnek ile beş parçaya geçmiş ancak toplam hâlâ 480 kalmıştır. Figma 2020'den beri yaklaşık yüz kat büyümüştür; kullanıcı kimliği, dosya kimliği ile organizasyon kimliğine göre yatay parçalanmış yerleşimler kullanmaktadır ve ilk yatay parçalanmış tablosu Eylül 2023'te dokuz aylık bir projenin sonunda gelmiştir. İkisi de satır bazlı ile kiracı anahtarlı parçalamayı seçmiştir, kiracı başına şemayı değil.

**Kiracı başına havuz aritmetiği.** PgBouncer havuzları kullanıcı ile veritabanı çiftine göre anahtarlanmaktadır ve `default_pool_size` havuz başınadır, küresel değildir. 200 kiracı veritabanı ile onluk havuz 2.000 potansiyel sunucu bağlantısı demektir. Kontrolleri `max_db_connections` ile `max_user_connections`'tır.

AWS matrisi birebir şöyledir: silo modeli için kayda değer efor gerekir, yani kiracı başına bir bağlantı havuzu, ve daha az verimlidir. Köprü ya da şema modeli için daha az efor gerekir ancak bağlantı yeniden kullanımı `SET ROLE` veya `SET SCHEMA` ile yalnızca oturum havuz modunda mümkündür. Havuz modeli, yani `tenant_id` ile, en az efor gerektirir ve en verimlidir, çünkü tüm kiracılar için tek bir bağlantı havuzu vardır.

> **Az takdir edilen can alıcı nokta:** kiracı başına şemanın herkese tek havuz avantajı, işlem modunda havuzlamaya ihtiyaç duyduğunuz anda buharlaşmaktadır, çünkü `search_path` bir oturum durumudur.

**PostgreSQL 17**, 26 Eylül 2024: vacuum'un yeni bellek yapısı 20 kat daha az bellek kullanmaktadır ve bu, 2.2'deki çok tablolu autovacuum çöküşüyle doğrudan ilgilidir.

**PostgreSQL 18**, 25 Eylül 2025: birçok ilişkiye erişen sorguların kilitleme performansı iyileştirilmiştir, Vondra'nın `c4d5cb71d` commit'i; bu, çok bölümlü ile çok indeksli kullanan herkes için en alakalı değişikliktir. Birçok bölüme erişen sorguların planlanma verimliliği iyileştirilmiştir. `pg_upgrade --swap` seçeneği eklenmiştir ve özellikle çok ilişkili kümelerde bağlama, klonlama ile kopyalama seçeneklerinden daha iyi performans gösterebilmektedir. `pg_dump --no-policies` seçeneği satır seviyesi güvenlik politikalarını migration'da yönetmek için eklenmiştir.

PostgreSQL 18 sürüm notlarında ilişki ile katalog önbelleğinin arka uç başına belleğini veya çok ilişkili autovacuum zamanlamasını ele alan hiçbir madde yoktur. 2.2 ile 2.4'teki sınırlar 2026'da hâlâ canlıdır.

---

## Bölüm III — İzolasyonun veriden ötesi

### 3.1 Kiracı başına imzalama anahtarı, müzakere edilemez

**Saldırı zinciri**, kendi türetimimizdir ve birincil kaynaklarla temellendirilmiştir.

Birinci adım RFC 6749 §2.2'dir: "The client identifier is unique to the authorization server." Çok kiracılı bir IdP'de her kiracı ayrı bir yetkilendirme sunucusudur. Yani kiracı A ile kiracı B'de aynı `webapp` istemci kimliği olabilir ve bu spesifikasyona tamamen uygundur. Keycloak bunu şema düzeyinde yapmaktadır: `UNIQUE(REALM_ID, CLIENT_ID)`.

İkinci adım şudur: imzalama anahtarı paylaşımlıysa, kiracı A'nın verdiği bir token kiracı B'nin JWKS'iyle de doğrulanır.

Üçüncü adımda `aud` kontrolü de geçer, çünkü iki kiracıda da audience `webapp`'tır.

Dördüncü adımda geriye tek bir savunma kalır: `iss` kontrolü. OIDC Core §3.1.3.7 birebir şöyledir: "The Issuer Identifier for the OpenID Provider… MUST exactly match the value of the `iss` (issuer) Claim."

Beşinci adım şudur: ilgili taraflar bunu yapmamaktadır.

**Bu teorik değildir ve iki kez olmuştur.**

Storm-0558, Wiz Research, 21 Temmuz 2023:

> "The compromised MSA key was trusted to sign any OpenID v2.0 access token for personal accounts and mixed-audience (multi-tenant or personal account) AAD applications."
>
> "Any token signed by the MSA tenant for an Azure AD account could be deemed valid, as long as it impersonates a personal account" — çünkü birçok uygulamada issuer doğrulaması yoktu.
>
> Microsoft'un issuer doğrulama uzantısı hakkında: "This extension is specific to Microsoft and the responsibility of its implementation rests with the application owner. Therefore, there is a concern that many applications lack this procedure."

Microsoft zorunlu doğrulamayı resmî Azure SDK'sına ancak 12 Temmuz 2023'te eklemiştir. CISA'nın siber güvenlik inceleme kurulu PDF'i 403 döndürmüştür ve doğrulanamamıştır.

CVE-2026-23552, 23 Şubat 2026, CVSS 9,1, Apache Camel'ın Keycloak bileşeni; NVD'den birebir:

> "The Camel-Keycloak KeycloakSecurityPolicy does not validate the `iss` (issuer) claim of JWT tokens against the configured realm. A token issued by one Keycloak realm is silently accepted by a policy configured for a completely different realm, breaking tenant isolation."

> Yedi ay önce ve CVSS 9,1 olarak tam olarak budur. Keycloak realm başına ayrı anahtar kullandığı için tam bir istismar imza doğrulamasının da gevşek olmasını gerektirir; ancak sessizce kabul edilir ifadesi, izolasyonun tüketici disiplinine ne kadar bağımlı olduğunu kanıtlamaktadır.

**Kim ne yapmaktadır.**

| IdP | Anahtar kapsamı | Kanıt |
|---|---|---|
| Keycloak | Realm başına | "When a realm is created, a key pair and a self-signed certificate is automatically generated." Realm başına iki RSA-2048 ile HMAC ve AES anahtarı üretilmektedir |
| Auth0 | Kiracı başına | — |
| Entra | Paylaşımlı Microsoft hesabı ile kurumsal ayrımı yetersizdi | Storm-0558 |

**Rotasyonda Keycloak'ın modeli doğrudur.**

> "Keycloak has a single active key pair at a time, but can have several passive keys as well. The active key pair is used to create new signatures, while the passive key pair can be used to verify previous signatures."
>
> Tavsiyesi şöyledir: "Consider creating new keys every three to six months and deleting old keys one to two months after you create the new keys. If a user was inactive in the period between the new keys being added and the old keys being removed, that user will have to re-authenticate."

**Argus kuralları.**

1. Kiracı başına bir aktif ile N pasif anahtar tutulur; JWKS her ikisini de yayımlar.
2. `kid` küresel benzersiz ve kiracıyı sızdırmayan opak bir değerdir; kiracı kısa adı `kid` içine konmaz, çünkü bu bir sayım yüzeyidir.
3. Rotasyon kiracı başına bağımsız zamanlanabilir.
4. Varsayılan ES256'dır; RSA yalnızca eski ilgili taraf uyumu için ve talep üzerine, yani tembel, üretilir, her kiracı için peşinen değil.
5. `client_id` küresel benzersizdir, Keycloak'ın aksine; bu iki bağımsız savunma katmanı demektir.

### 3.2 Issuer URL stratejisi, RFC seviyesinde karşılaştırma

**Kritik bir spesifikasyon çelişkisi vardır** ve doğrudan doğrulanmıştır.

RFC 8414 §3.1, Haziran 2018, araya ekleme yapmaktadır:

> "If the issuer identifier value contains a path component, any terminating `/` MUST be removed before inserting `/.well-known/` and the well-known URI suffix between the host component and the path component."
>
> Örneği şudur: issuer `https://example.com/issuer1` ise istek `GET /.well-known/oauth-authorization-server/issuer1` olur.
>
> "Using path components enables supporting multiple issuers per host. This is required in some multi-tenant hosting configurations."

OIDC Discovery 1.0 §4 ise sona ekleme yapmaktadır:

> "OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string `/.well-known/openid-configuration` to the Issuer."
>
> Örneği şudur: `GET /issuer1/.well-known/openid-configuration`.

> **İki spesifikasyon aynı issuer için farklı URL üretmektedir.** Path tabanlı issuer kullanılacaksa her ikisini de servis etmek zorunludur. Bu, path tabanlı yaklaşımın en sık gözden kaçan maliyetidir.

**Sertifika aritmetiği**, Let's Encrypt, sayfa tarihi 5 Ağustos 2026. Birebir limitler şunlardır: kayıtlı alan adı başına yedi günde 50 sertifika verilebilir; tek bir hesap üç saatte 300 yeni sipariş oluşturabilir; tek bir sertifika 100 tanımlayıcıya kadar içerebilir.

Sonuçları şöyledir. `acme.argus.io` biçiminde kiracı başına ayrı sertifika alınırsa 50. kiracıda duvara çarpılır; bu ölümcüldür. Tek bir joker sertifika, yani DNS-01 ile `*.argus.io`, sınırsız kiracı demektir ve doğru cevap budur; uyarısı jokerin yalnızca tek seviyeyi kapsamasıdır. `login.acme.com` biçiminde özel alan adında her kiracının kendi kayıtlı alan adı ile kendi haftalık 50 sertifika bütçesi vardır; bu ölçeklenir ancak hesap başına üç saatte 300 sipariş, yani günde yaklaşık 2.400 yeni özel alan adı, bir tavandır. Sertifika başına 100 tanımlayıcıyla paketleme çok kiracılıkta önerilmez, çünkü tek bir alan adı doğrulaması düşerse tüm sertifika yenilemesi düşer.

**Karşılaştırma.**

| Boyut | Path, yani `/t/acme` | Alt alan adı, yani `acme.argus.io` | Özel, yani `login.acme.com` |
|---|---|---|---|
| Sertifika | Tek sertifika | Tek joker sertifika | Kiracı başına ACME |
| DNS işi | Yoktur | Tek joker kaydı | Kiracı başına CNAME ile doğrulama |
| Keşif | İki farklı yol servis edilmelidir | Kök `/.well-known/…` kullanılır ve çelişki yoktur | Kök kullanılır ve çelişki yoktur |
| İlgili taraf kütüphane uyumu | Path içeren issuer'da kırılganlık vardır | Sorunsuzdur | Sorunsuzdur |
| Tarayıcı köken izolasyonu | Yoktur, aynı kökendir | Vardır; çerez, depolama ile XSS ayrılır | Vardır |
| Katılım gecikmesi | Anındadır | Anındadır | Dakikalardır, ACME nedeniyle |
| Kurumsal beklenti | Düşüktür | Ortadır | Yüksektir |

Köken izolasyonu argümanı belirleyicidir ve az konuşulmaktadır. CVE-2023-6717, CVSS 6,0, tam da bunu göstermektedir:

> "This issue may allow a malicious admin in one realm or a client with registration access to target users in different realms or applications, executing arbitrary JavaScript in their contexts… compromising the confidentiality, integrity, and availability of the complete KC instance."

Aynı kökende servis edilen çok kiracılı bir arayüzün bedeli budur. Alt alan adı bunu tarayıcının kendi güvenlik modeliyle kapatmaktadır.

**RFC 9207 birinci günden zorunludur.** RFC 9207, Mart 2022, birebir şöyle der:

> "In authorization responses to the client, including error responses, an authorization server supporting this specification MUST indicate its identity by including the `iss` parameter in the response."

Bu, mix-up saldırılarına karşıdır. Çok kiracılı bir IdP'de her kiracı ayrı bir yetkilendirme sunucusudur, dolayısıyla `iss` parametresi başlangıçtan itibaren verilmelidir.

### 3.3 Hız limiti, kota ile gürültülü komşu

Gerçek ürünlerin kiracı başına yayımladıkları şunlardır.

| Ürün | Limit |
|---|---|
| Okta | `/oauth2/v1/authorize` için organizasyon başına dakikada 1200 istek; `/api/v1/users/*` için organizasyon başına dakikada 1000 istek; `/api/v1/authn` için kullanıcı adı başına saniyede dört istek. Doküman şöyle der: bir kova için en genel kapsam tüm organizasyondur |
| Entra External ID | Kiracı ile IP başına saniyede 20 istek, kiracı başına saniyede 200 istek. Kayıt altı, giriş dört jeton tüketmektedir, dolayısıyla saniyedeki jeton sayısı 200 bölü tüketimdir |
| Auth0 | Kimlik doğrulama API'si kiracı seviyesinde paylaşımlı ve ortam genelinde küresel bir limite sahiptir; kurumsal örneği saniyede 100 istektir. Bir IP'den aynı hesaba dakikada 20 deneme, sonrasında dakikada on denemeye düşmektedir. Organizations API'si için sayısal bir limit yayımlanmamıştır ve doğrulanamamıştır |
| WorkOS | API anahtarı başına 60 saniyede 6.000 istek; çoklu oturum açma yetkilendirmesi için bağlantı başına 60 saniyede 1.000 istek; dizin senkronizasyonu için dizin başına saniyede dört istek |
| Frontegg | `GET /resources/tenants/v1` için Launch planında dakikada 30 istek; çoklu oturum açma yapılandırması yazma işlemi her planda dakikada beş ile on istek |

Postgres tarafında kiracı atfı için tek yerel araç `citus_stat_tenants`'tır; Citus 11.3, Mayıs 2023. Kiracı başına işlemci kullanımı ile sorgu sayısını kayan zaman kovalarında vermekte ve `citus.stat_tenants_limit` ile en yüksek N kiracıyı göstermektedir.

### 3.4 Kiracı başına özelleştirme, kod çalıştırmanın bedeli

Bu sorunun güvenlik cevabı iki CVE'de yazılıdır.

CVE-2022-36051, 31 Ağustos 2022, CVSS 8,7, Zitadel; birebir:

> "Actions… is a feature, where users with role `ORG_OWNER` are able to create Javascript Code, which is invoked by the system at certain points during the login… Due to a missing authorization check, Actions were able to grant authorizations for projects that belong to other organizations inside the same Instance."

CVE-2019-10170, 8 Mayıs 2020, CVSS 6,6, Keycloak:

> "the realm management interface permits a script to be set via the policy. This flaw allows an attacker with authenticated user and realm management permissions to configure a malicious script to trigger and [execute]"

> **Kural şudur: kiracının yazdığı kod asla küresel yazma yetkisi olan bir bağlamda çalışmamalıdır.** Argus'ta kiracı özelleştirmesi, yani claim eşlemesi ile akış kararları, tercihen veri olmalıdır, yani bildirimsel bir kural motoru olmalıdır, kod değil. Kod gerekiyorsa WASM sanal alanı, kiracı kapsamlı yetenekler ile yazma API'lerine erişimin olmaması şarttır.

Bir bonus tuzak CVE-2026-19608'dir, 18 Ağustos 2026, CVSS 5,3, Keycloak:

> "group-based policies using tokens that only contain group names rather than full paths. If two groups in different parts of the organization share the same name, a user in the unauthorized group can be mistake[nly authorized]"

> **İsim tabanlı yetkilendirme çok kiracılıkta çökmektedir.** Her zaman tam yol veya opak kimlik kullanılır.

### 3.5 Kiracı başına denetim günlüğü ile saklama

Entra ID'nin resmî tablosu, tarih 6 Ocak 2026, güncelleme 25 Mart 2026:

| Rapor | Ücretsiz | P1 | P2 |
|---|---|---|---|
| Denetim günlükleri | 7 gün | 30 gün | 30 gün |
| Oturum açmalar | 7 gün | 30 gün | 30 gün |
| Riskli oturum açmalar | 7 gün | 30 gün | 90 gün |

> "You can retain the audit and sign-in activity data for longer than the default retention period by routing it to an Azure storage account."
>
> "Log retention changes aren't retroactive."

Auth0'da bu plana göre değişmektedir. Okta'da System Log kullanılmaktadır. authentik'in kiracılık modülünde `event_retention` varsayılanı 365 gündür ve kiracı başına ayarlanabilir.

> **Argus için ders.** Dünyanın en büyük IdP'si bile denetim günlüğünü IdP içinde yalnızca 30 gün tutmaktadır. Uzun saklama dışarı akıtma demektir. Argus'ta IdP içinde kısa bir sıcak pencere, varsayılanı 30 ile 90 gün, tutulur ve kiracı başına ayarlanabilir olur; kiracı başına bir dışa aktarım hedefi, yani S3, GCS, web kancası veya güvenlik bilgi ve olay yönetimi sistemi, birinci günden bulunur; günlük tablosu kiracı kimliği ile zamana göre bölümlenir, böylece kiracı silme bir ayırma ile düşürme işlemine dönüşür.

---

## Bölüm IV — Hiyerarşi ve kullanıcı kimliği

### 4.1 Düz mü ağaç mı: piyasa düz demiştir

| Ürün | İç içe midir | Kanıt |
|---|---|---|
| Zitadel | Hayır | Organizasyonlar tasarım gereği düzdür ve hiyerarşiyi düz tutun denmektedir |
| Auth0 | Hayır | Personel, 13 Temmuz 2022: Auth0 şu anda alt organizasyonları desteklememektedir |
| Okta | Hayır | Organizasyonlar sert sınırlardır |
| Entra yönetim birimleri | Hayır | Yönetim birimleri iç içe olamaz |
| WorkOS | Hayır | `parent_organization_id` alanı yoktur |
| Keycloak | Organizasyon düzdür; 26.6.0'dan beri organizasyon içinde hiyerarşik gruplar vardır | keycloak.org'un Nisan 2026 tarihli organizasyon grupları yazısı |
| Frontegg | Evet | Belgeli bir derinlik sınırı yoktur ve doğrulanamamıştır |
| AWS Organizations | Evet | Kök altında beş seviye sert sınır vardır |

**Hiyerarşiyi yapanların ödediği bedel iki yönden aynı derstir.** Frontegg'te miras JWT'ye ulaşmamaktadır, dolayısıyla her yetki kararı bir API çağrısıdır. AWS Organizations'ta organizasyon birimi başına en fazla on servis kontrol politikası ile beş seviye vardır; bir hesabın etkin politikası, kimsenin ona iliştirmediği yaklaşık 50 belgenin kesişimidir. Birebir şöyle der: miras yoluyla bir organizasyon birimini ya da hesabı etkileyen politikalar bu limitlere sayılmamaktadır. `OU_DEPTH_LIMIT_EXCEEDED` hata kodu bir sebeple vardır. SpiceDB'de varsayılan sınır 50 sıçramadır; amaca özel bir ilişki tabanlı erişim kontrolü motoru bile derinliği sınırlamaktadır. Zanzibar, USENIX ATC 2019, trilyonlarca erişim kontrol listesi ile saniyede milyonlarca istekte 95. yüzdelikte on milisaniyenin altında kalmaktadır; ancak bu, Google'ın ölçeğinde amaca özel inşa edilmiş bir sistemdir.

> **Kopyalanacak kalıp şudur: düz kiracılar ile kiracı içinde hiyerarşik gruplar.** Hiyerarşi yetkilendirme katmanında kalır ve kimlik doğrulama ile kiracı çözümlemesinin sıcak yolundan çıkar. Keycloak 26.6.0 tam olarak buraya varmıştır. Geçişli miras gerekiyorsa bu bir ilişki tabanlı erişim kontrolü problemidir, yani OpenFGA ya da SpiceDB konusudur, bir kiracı modeli problemi değildir.

Postgres tarafında ağaç sorgu maliyeti bağlayıcı bir kısıt değildir, çünkü kiracı ağaçları küçük ile sığdır. Bağlayıcı kısıtlar taşıma ile yeniden ebeveynlemedeki yazma amplifikasyonu, ltree'de uygulamanın sorumlu olduğu yol bütünlüğü ile mirasın semantik belirsizliğidir; hiçbir indeks bunu düzeltmez.

### 4.2 Kullanıcı kimliği: iki okul ile ayırt edici soru

Ayırt edici soru şudur: IdP her kiracı için kimlik bilgisini sahiplenmekte midir.

| Ürün | Benzersizlik kapsamı | Aynı e-posta iki kiracıda |
|---|---|---|
| Birinci okul: küresel kullanıcı ile üyelik | | |
| WorkOS | Ortam | Tek kullanıcı ile N üyelik; otomatik birleştirme yapılmaktadır |
| Auth0 | Bağlantı | Bağlantı paylaşımlıysa tek kullanıcı olur |
| Keycloak, realm içinde | Realm | Tek realm kullanıcısı ile N organizasyon üyeliği; tam bir yönetilen üyelik vardır |
| Logto | Logto kiracısı | Tek kullanıcı ile N organizasyon |
| Frontegg | Ortam | Her zaman tektir; bölme yolu yoktur ve doğrulanamamıştır |
| İkinci okul: kiracıya yerel gölge nesne | | |
| Zitadel | Organizasyon, dize kurgusuyla | İki ayrı kullanıcı olur ve taşınamazlar |
| Okta | Organizasyon | İki ayrı kullanıcı olur |
| Entra | Kiracı | İki ayrı nesne olur; `oid` ile `sub` tasarım gereği farklıdır |
| Stytch | Organizasyon | İki ayrı üye olur |
| SuperTokens | Uygulama kimliği, kiracı kimliği ile e-posta | Varsayılan olarak iki olur; paylaşım isteğe bağlı açılır |

**Entra B2B ikinci okulun referans uygulaması ile en çok düşünülmüş hâlidir.** Nesne davetle ve kullanım öncesinde yaratılır: bu hesabın kendisiyle ilişkili hiçbir kimlik bilgisi yoktur, çünkü kimlik doğrulama misafir kullanıcının kimlik sağlayıcısı tarafından yapılmaktadır. Çakışmayı yapısal olarak imkânsız kılan bir kullanıcı asıl adı kurgusu vardır: `john@contoso.com` değeri `john_contoso.com#EXT#@fabrikam.onmicrosoft.com` hâline gelmektedir. `UserType` üye ile misafir değerlerini alır ve bu, barındıran kiracıyla ilişkiyi anlatır, nasıl giriş yapıldığından bağımsızdır: kullanıcı tipinin kullanıcının nasıl oturum açtığıyla hiçbir ilgisi yoktur. `identities` özelliği ana kiracıya bir işaretçidir ve `ExternalAzureAD`, `google.com`, `mail` veya bir SAML issuer URI'si olabilir. Keskin bir operasyonel kenar vardır: bir misafir kullanıcı sonradan e-posta adresini değiştirirse yeni e-posta otomatik olarak senkronize olmamaktadır.

Keycloak'ın en temiz formülasyonu 30747 numaralı issue'dadır: üyeler yalnızca bir yönetilen üyeliğe sahip olabilir. Yani çok üyelik vardır ancak tam olarak bir tanesi kullanıcının yaşam döngüsünü sahiplenir. Bu, saf çoktan çoğa ilişkinin bıraktığı bu kullanıcıyı kim silebilir ile parolasını kim sıfırlayabilir belirsizliğini çözmektedir.

### 4.3 E-posta ile kimlik: üç bağımsız ihlal

**Birincisi nOAuth'tur**, Descope tarafından 20 Haziran 2023'te açıklanmıştır. Saldırgan kendi Entra kiracısında yöneticidir, hesabının e-posta alanını kurbanınkiyle değiştirir, ki doğrulama yoktur, ve Microsoft ile giriş yap der. E-postayla eşleştirip birleştiren bir uygulamada bu tam bir hesap devralmasıdır ve kurbanın bir Microsoft hesabı olmasına bile gerek yoktur. Entra'nın `email` claim'i hem değiştirilebilirdir hem doğrulanmamıştır. Azaltımları `xms_edov` claim'i ile `RemoveUnverifiedEmailClaim` ayarıdır.

İki yıl sonra hâlâ canlıdır; Semperis, 26 Haziran 2025: test edilen 104 Entra uygulama galerisi uygulamasının dokuzu, yani %9'u, savunmasızdır.

**İkincisi Entra alan adı devralmasıdır.** Bir kullanıcı bir bulut servisine kaydolunca e-posta alan adına göre yönetilmeyen bir Entra dizinine eklenmektedir; buna viral veya gölge kiracı denir. Sonrasında DNS TXT kaydıyla sahiplik kanıtlanarak harici yönetici devralması yapılabilmektedir: Microsoft Entra ID alan adını yönetilmeyen organizasyondan kaldırmakta ve mevcut organizasyonunuza taşımakta, kullanıcıları, abonelikleri ile lisansları da taşımaktadır. `forceTakeover` değeri doğru yapılır ve yönetilmeyen organizasyon on gün sonra silinir.

**Üçüncüsü Truffle Security'nin 13 Ocak 2025 tarihli bulgusudur** ve en önemlisidir, çünkü alan adı doğrulamasının kendisini yenmektedir: başarısız bir girişimin süresi dolmuş alan adı satın alınır, kendi çalışma alanınızda `user@faileddomain.com` yeniden yaratılır ve `hd` ile `email` claim'lerine göre eşleştiren bulut yazılımlarına girilir. Uygulama, orijinal şirket sahipleriyle yeni alan adı alıcısını ayırt edememektedir. 100.000'den fazla uygun alan adı tespit edilmiştir.

> **DNS sahipliği bir gerçek değil bir kiralamadır.** Doğrulanmış bir alan adına dayanan her kiracı yönlendirme kuralı, o alan adının süre bitim riskini miras almaktadır.

Ürünlerin savunmaları şunlardır. Clerk: doğrulanmış bir alan adı tek kullanımlık bir alan adı veya yaygın bir e-posta sağlayıcısı olamaz; örneğin gmail.com için doğrulanmış alan adı yaratılamaz. Stytch: gmail.com gibi yaygın alan adlarına izin verilmemektedir; ayrıca oltalama karşıtı bir koruma vardır: e-posta alan adına göre anlık kullanıcı yaratımı için organizasyonda aynı e-posta alan adına sahip doğrulanmış e-postalı en az bir üye zaten bulunmalıdır, yani bir alan adının ilk kullanıcısı kendini mevcut bir organizasyona sokamaz. WorkOS: ortam başına yalnızca bir organizasyon belirli bir alan adını içerebilir.

### 4.4 Politika çakışmasına yalnızca Entra tam cevap vermektedir

Üç tutarlı strateji vardır.

Birincisi tasarımla yok etmektir; Zitadel, Okta ile Entra B2B bunu yapar: bir kullanıcı bir kiracıya aittir ve çakışma yoktur.

İkincisi oturumu kiracıya kapsamaktır; Stytch, WorkOS, Auth0'ın organizasyon girişi ile Keycloak'ın organizasyon bağlamlı token'ı bunu yapar: bağlayıcı politika hedef organizasyonunkidir ve o organizasyona giriş yapılırken değerlendirilir. Organizasyon değiştirmek yeni bir kimlik doğrulamadır. Birinci okul için doğru model budur.

Üçüncüsü güvenip federe etmektir; Entra'nın koşullu erişimi ile çapraz kiracı güveni bunu yapar: kaynak kiracının politikası her zaman geçerlidir ve ana kiracının sağladığı faktörler yalnızca gelen güven yapılandırılmışsa kanıt olarak kabul edilir. Varsayılan güven yokluğudur.

Entra'nın ilkesi birebir şöyledir ve aynen benimsenmelidir:

> "MFA is completed at resource tenancy to ensure predictability."

Entra'nın asimetrik metot tablosu gerçek bir tuzaktır: ana kiracıda kabul edilenler FIDO2, Windows Hello ile sertifikadır; kaynak kiracıda kabul edilenler yalnızca SMS, sesli arama, Authenticator bildirimi ile yazılım tabanlı OATH'tır. Yani çok adımlı doğrulama güveni kapatılırsa, yalnızca oltalamaya dirençli bir politika harici bir kullanıcı tarafından hiç sağlanamaz.

> **Kaçınılacak dördüncü, söylenmemiş seçenek: tek küresel oturum ile politikaların birleşimi.** Kullanıcının tek bir oturumu varsa ve kiracı A passkey istiyorsa, kiracı B'nin zayıf politikasıyla kurulan bir oturum kiracı A erişimi vermemelidir. Pratikte organizasyon kapsamlı bir access token yalnızca o organizasyonun politikası mevcut oturumda sağlandığında verilebilir; bu, organizasyon değişiminde bir yükseltme ile `amr` ve `acr` alanlarında gerçekten sağlananın kaydı demektir.

### 4.5 Kiracının kendisinin yetkilendirme sunucusuna dönüşmesi

Buraya kadarki bölüm kiracıyı Argus'un müşterisi olarak ele almaktadır. Adı konmamış bir senaryo daha vardır ile Argus'un veri modeli bunu zaten mümkün kılmaktadır: kiracının kendi uygulaması, kendi kullanıcıları için bir yetkilendirme sunucusu gibi davranmaktadır.

Stytch'in bağlı uygulamalar özelliği bunu ürünleştirmiştir; dokümanına göre müşterinin uygulaması bir kimlik sağlayıcı gibi davranarak yapay zekâ ajanlarıyla etkileşebilmekte, eklenti etkinleştirebilmekte ile kimlik doğrulama durumunu aktarabilmektedir. Erişim 13 Eylül 2026.

Senaryo §14 ile §15'in kesişimindedir ile gerçek talebi ajan ekosistemi yaratmaktadır: kiracının uygulaması bir model bağlam protokolü sunucusu barındırdığında, o sunucuya erişen ajanın belirtecini kim vermektedir. İki cevap vardır. Argus verir ile kiracının uygulaması yalnızca kaynak sunucudur; bu, §14'ün varsayılan modelidir. Ya da kiracının uygulaması kendi belirtecini verir ile Argus yalnızca kullanıcı kimlik doğrulamasını sağlar.

İkinci model adı konmadan bırakılırsa üç şey tasarlanmamış kalmaktadır.

Birincisi veren alanının ayrımıdır. Kiracının verdiği belirteçler Argus'un verdiği belirteçlerden ayırt edilebilmelidir; aksi hâlde bir kaynak sunucu, kiracının verdiği bir belirteci Argus'un verdiği sanabilmektedir. Kiracı başına veren adresi zaten 4.2'nin gereğidir, ancak burada gereken daha fazlasıdır: belirteç tipi ya da izleyici kitle üzerinden, verenin Argus mu kiracı mı olduğu açık olmalıdır.

İkincisi anahtar ayrımıdır. Kiracının kendi imzalama anahtarı olacaksa, o anahtar §1 kararı 25 gereği veritabanı dışında tutulmalıdır ile bu, kiracı başına bir anahtar arka ucu demektir. Kiracı Argus'un anahtarıyla imzalıyorsa, Argus kiracının verdiği her belirtecin içeriğinden sorumlu hâle gelmektedir; bu, §1 §5.1'deki kiracının belirteç içeriğine müdahale sınırıyla doğrudan çelişmektedir.

Üçüncüsü iptalin kapsamıdır. Kiracının verdiği bir belirteç, Argus'un oturum çağı sayacıyla iptal edilebilmeli midir? Edilebilmeliyse kiracının yetkilendirme sunucusu Argus'un iptal yayınına abone olmak zorundadır; edilemiyorsa kullanıcının Argus'taki oturumunu sonlandırması kiracı uygulamasındaki erişimi sonlandırmamaktadır ile bu, kullanıcıya söylenmesi gereken bir sınırdır.

Öneri şudur: ikinci model birinci günde desteklenmemeli ancak yasaklanmamalıdır. Veri modeli veren alanını kiracı başına ayrı tutmalı ile anahtar arka ucu kiracı başına adreslenebilir olmalıdır; bu iki şey sonradan eklenemez. Gerçek destek ise §1 §9.1'deki iptal sözleşmesi kapatıldıktan sonra değerlendirilmelidir, çünkü üçüncü soru o sözleşmenin bir uzantısıdır.

---

## Bölüm V — Güvenlik: çapraz kiracı sızıntısı

### 5.1 Doğrulanmış çapraz kiracı sınır ihlalleri

NVD API'sinden doğrudan çekilmiştir; `keywordSearch=keycloak` ile 296 sonuç taranmış ve sınır aşımı belirtilenler alınmıştır.

| CVE | Tarih | CVSS | Ne olmuştur |
|---|---|---|---|
| CVE-2026-23552 | 23 Şubat 2026 | 9,1 | Camel ile Keycloak `iss` doğrulamamaktadır; bir realm'in token'ı başka bir realm'in politikasınca sessizce kabul edilmektedir |
| CVE-2022-36051 | 31 Ağustos 2022 | 8,7 | Zitadel Actions, yani kiracının JavaScript kodu, başka organizasyonların projelerine yetki verebilmekteydi |
| CVE-2019-14832 | 15 Ekim 2019 | 7,5 | Keycloak REST API'si, kullanıcının yapılandırılmadığı bir realm'den kullanıcı erişimine izin vermekteydi; unutulmuş bir `AND realm_id = ?` koşuludur |
| CVE-2026-41166 | 22 Nisan 2026 | 7,0 | OpenRemote `{realm}` yol segmentini kullanmakta ancak çağıranın o realm'i yönetebileceğini kontrol etmemektedir; master yöneticiye yükselme mümkündür |
| CVE-2026-18215 | 31 Temmuz 2026 | 6,8 | Keycloak'ta Microsoft organizasyon kısıtı token takasında yok sayılmaktadır; başka bir organizasyonun token'ıyla realm'e erişilmektedir |
| CVE-2023-6717 | 25 Nisan 2024 | 6,0 | Bir realm'deki kötü niyetli bir yönetici farklı realm'lerdeki kullanıcıları hedefleyebilmektedir; aynı köken XSS'idir |
| CVE-2020-1697 | 10 Şubat 2020 | 6,1 | Diğer realm'lerdeki kullanıcıları kandırma; yönetim konsolunda saklanan XSS |

Bunlardan üçü Argus'un mimarisini doğrudan belirlemektedir. CVE-2019-14832 yabancı anahtarsız bir ayırıcı kolonun kaçınılmaz sonucudur ve satır seviyesi güvenliği bir savunma derinliği olarak zorunlu kılmaktadır. CVE-2026-41166 çok kiracılı bir API'nin kanonik hatasıdır: kiracıyı yol parametresinden almak ancak yetkiyi kontrol etmemek. Tip sisteminde çözülmesi gereken tam olarak budur. CVE-2022-36051 kiracı kodunun küresel yazma bağlamında çalışmaması gerektiğini göstermektedir.

Ayrıca bulut izolasyonu araştırması bağlamı vardır: Wiz ile Orca serisi, yani ChaosDB, Azure PostgreSQL Flexible Server'da çapraz kiracıya izin veren ExtraReplica ile BingBang; Okta destek sistemi ihlalleri, Ekim 2023 ile Ocak 2022; ve Storm-0558. Bu vakaların ayrıntılı teknik dökümü için ayrılan araştırma akışı bu raporun yazımı sırasında tamamlanmamıştır; yukarıdakiler kendi birincil kaynak doğrulamalarımızdır. Asana MCP olayı ile Wiz serisinin tam teknik ayrıntısı bu raporda doğrulanmamıştır ve talep edilirse ayrıca çıkarılabilir.

### 5.2 Savunma derinliği olarak satır seviyesi güvenlik ne kadar etkilidir

Etkilidir, ancak yalnızca beş kuralın hepsi uygulanırsa. Logto'nun deneyimi bunun bedelini göstermektedir ve kanıt depodadır.

`packages/schemas/tables/_after_each.sql` dosyası her tabloya uygulanmaktadır:

```sql
create trigger set_tenant_id before insert on ${name} for each row execute procedure set_tenant_id();
alter table ${name} enable row level security;
create policy ${name}_tenant_id on ${name} as restrictive
  using (tenant_id = (select id from tenants where db_user = current_user));
```

`_before_all.sql` dosyası `create role logto_tenant_${database} password '${password}' noinherit;` satırını içermektedir. `_after_all.sql` dosyasında `tenants` tablosu kendini korumaktadır; tüm yetkiler geri alınmakta ve yalnızca kimlik, veritabanı kullanıcısı, askıya alınma durumu ile etiket kolonlarında seçme yetkisi verilmektedir.

Ödedikleri bedel birincil kaynaklardan şöyledir.

7596 numaralı PR, 29 Temmuz 2025: tek kolonlu yabancı anahtarlar başka kiracılardan kullanıcıların bir organizasyona atanmasına izin vermekteydi; satır seviyesi güvenlik sonra okumayı engelleyip 500 hatası üretmekteydi. Düzeltme kiracı kimliği ile kullanıcı kimliğinden oluşan bileşik yabancı anahtarlardır. Yani satır seviyesi güvenlik ile kiracı kimliği, şemadaki her yabancı anahtarı bileşik yapmaya zorlamaktadır.

7685 numaralı issue, 14 Ağustos 2025, birebir şöyledir: Logto başlatılırken satır seviyesi güvenliğin her iş tablosunda uygulanması gerekmektedir. Yaklaşık 60'tan fazla tablonun eksik olduğu tespit edilmiştir. Yani satır seviyesi güvenlik değişmezi ya hep ya hiçtir ve önyükleme sırasını hassaslaştırmaktadır.

### 5.3 Çapraz kiracı sızıntısını sistematik test etmek

Bu alanda yayımlanmış olgun bir metodoloji bulunamamıştır ve doğrulanamamıştır. Aşağıdakiler kanıtlanmış hata sınıflarından türetilmiş ve Argus'a özgü önerilerdir.

**Birincisi şema değişmezi sürekli entegrasyon kontrolüdür**; Logto'nun 7685 numaralı issue'da öğrendiği derstir.

```sql
-- CI'da FAIL: RLS'siz iş tablosu
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='argus' AND c.relkind='r'
  AND c.relname NOT IN (/* whitelist: tenants, _sqlx_migrations */)
  AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);

-- CI'da FAIL: tenant_id'siz tablo
-- CI'da FAIL: tenant_id içeren tabloya tenant_id'siz FK (composite değil)
-- CI'da FAIL: SET search_path olmayan SECURITY DEFINER fonksiyon (Heroku dersi)
-- CI'da FAIL: BYPASSRLS taşıyan uygulama rolü
```

**İkincisi ikiz kiracı diferansiyel testidir.** Tüm entegrasyon test paketi iki kiracı için aynı verilerle çalıştırılır, sonra şu iddia edilir: A'nın herhangi bir sorgusunun döndürdüğü satır kümesinin B'nin verisiyle kesişimi boştur. Bu, CVE-2019-14832 sınıfını, yani unutulmuş yüklemi, yakalar.

**Üçüncüsü özellik tabanlı bir değişmezdir**, proptest ile yazılır. Rastgele bir kiracı, kullanıcı ile istemci grafiği üretilir; değişmez şudur: hiçbir API çağrısı, çağıranın kiracısı dışındaki bir kiracı kimliğine ait satır döndürmez. Özellikle yol parametresindeki kiracının token'daki kiracıdan farklı olduğu kombinasyonlar üretilir; bu CVE-2026-41166 sınıfıdır.

**Dördüncüsü bir token karışıklığı bulandırıcısıdır.** Kiracı A'nın token'ı kiracı B'nin her endpoint'ine gönderilir. Beklenen 401 veya 403'tür, asla 200 değildir. Bu, Storm-0558 ile CVE-2026-23552 sınıfıdır.

**Beşincisi gizli kanal testidir.** Kiracı A'da var olan bir e-postayla kiracı B'de kayıt denenir; benzersizlik ihlali asla sızmamalıdır. Bu, PostgreSQL dokümanının gizli kanal uyarısının doğrudan testidir.

**Altıncısı olumsuz yapılandırma değişkeni testidir.** `argus.tenant_id` ayarlanmamışken her sorgunun sıfır satır döndürdüğü iddia edilir, yani kapalı başarısızlık sağlanır, tüm satırların dönmesi değil.

---

## Bölüm VI — Rust'a özgü konular

### 6.1 Ortam bağlamı tehlikelidir, doğrulanmıştır

`tokio::task_local!` cazip görünmektedir. İki nedenle reddedilmelidir.

Birincisi `spawn` çağrısına miras kalmamasıdır. Göreve yerel veri `tokio::spawn` çağrılarına yayılmamaktadır; bu, iş parçacığına yerel verinin davranışıyla aynıdır. Kaynakları tokio deposundaki 2396 numaralı issue ile 4317 numaralı tartışmadır. Bir geçici çözüm crate'i vardır, yani `tokio-inherit-task-local`, ancak kendisi şöyle der: bu, `tokio::task_local` ile yaratılan değerleri miras almamaktadır. Sonuç şudur: arka plan bir işe spawn ettiğiniz an kiracı bağlamı sessizce kaybolmaktadır.

İkincisi erişimin panic etmesidir. `LocalKey::with()` ile `get()` dokümanı şöyle der: göreve yerel değişkenin ayarlanmış bir değeri yoksa bu fonksiyon panic etmektedir. Bir IdP'de bu bir hizmet reddidir.

### 6.2 Kiracıyı tip sisteminde kodlamak mümkündür ve kimse yapmamıştır

Mekanizma olgun ile yaygındır.

| Crate | Sürüm | İndirme | Son güncelleme |
|---|---|---|---|
| `generativity` | 1.2.1 | 3.991.685 | 26 Nisan 2026 |
| `qcell` | 0.5.5 | 469.916 | 17 Eylül 2025 |
| `ghost-cell` | 0.2.6 | 119.002 | 28 Ocak 2024 |
| `indexing`, bluss | 0.4.1 | 64.816 | 2019, ölüdür |

Teknik temeli GhostCell'dir; Yanovski ve arkadaşları, ICFP 2021, PACMPL, doi 10.1145/3473597. Makale şöyle der: markalı tipler, ki Haskell'in ST monadıyla örneklenmiştir, hayalet tipler ile ikinci mertebe çok biçimliliği birleştirmektedir. Sağlamlığı RustBelt ile Coq'ta formel olarak kanıtlanmıştır.

`generativity` dokümanına göre `Guard` ile `Id` yaşam süresi parametresinde değişmezdir: herhangi bir somut yaşam süresi için, `'static` dahil, `Id<'a>` değerini `Id<'b>` yerine koymak ya da zorlamak asla geçerli değildir.

Çok kiracılığa uygulanmış yayımlanmış bir örnek bulunamamıştır. Aranmıştır ve yoktur. Bu geçerli bir bulgudur: Argus bunu yapan ilk sistem olur.

### 6.3 Önerilen Rust kalıbı, üç katman

```rust
// ── KATMAN 1: Opak, sızdırmaz tenant kimliği ───────────────────────────
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(uuid::Uuid);
// Debug KASITEN türetilmedi -> log'a sızmaz; kendi impl'i redakte eder.
// Deserialize KASITEN türetilmedi -> istek gövdesinden ASLA gelemez.

// ── KATMAN 2: Branded scope — çapraz erişim DERLEME HATASI ─────────────
use generativity::{Guard, Id};

/// 'brand tek bir istek/transaction'ı işaretler. Invariant lifetime.
pub struct TenantScope<'brand> {
    id: TenantId,
    _brand: Id<'brand>,
}

/// Yalnızca bu scope'a ait olabilen veri.
pub struct Scoped<'brand, T> {
    inner: T,
    _brand: Id<'brand>,
}

impl<'brand, T> Scoped<'brand, T> {
    pub fn get(&self, _proof: &TenantScope<'brand>) -> &T { &self.inner }
}

// ── KATMAN 3: Executor'ı scope'a bağla — kapsamsız sorgu İMKÂNSIZ ──────
pub struct TenantTx<'brand, 'c> {
    tx: sqlx::Transaction<'c, sqlx::Postgres>,
    scope: TenantScope<'brand>,
}

impl<'brand, 'c> TenantTx<'brand, 'c> {
    /// Tek giriş noktası. GUC transaction içinde, fail-closed.
    pub async fn begin(
        pool: &'c sqlx::PgPool,
        tenant: TenantId,
        guard: Guard<'brand>,
    ) -> Result<Self, Error> {
        let mut tx = pool.begin().await?;                  // explicit BEGIN — ZORUNLU
        sqlx::query("SELECT set_config('argus.tenant_id', $1, true)")  // true = SET LOCAL
            .bind(tenant.0.to_string())
            .execute(&mut *tx).await?;
        Ok(Self { tx, scope: TenantScope { id: tenant, _brand: guard.into() } })
    }

    pub async fn find_user(&mut self, id: UserId)
        -> Result<Option<Scoped<'brand, User>>, Error> { /* … */ }
}
```

Kullanımı şöyledir:

```rust
generativity::make_guard!(guard);              // taze, benzersiz 'brand
let mut tx = TenantTx::begin(&pool, tenant_a, guard).await?;
let user = tx.find_user(uid).await?;

generativity::make_guard!(guard2);
let mut tx_b = TenantTx::begin(&pool, tenant_b, guard2).await?;

// tx_b.delete_user(user);
// ^^^ DERLEME HATASI: lifetime mismatch. 'brand'lar birleşmez.
```

Ne kazandırdığı ile ne kazandırmadığı dürüstçe şöyledir.

| Kazandırır | Kazandırmaz |
|---|---|
| Kiracı A'dan okunan bir varlığı kiracı B'nin yazma yoluna sokmak bir derleme hatasıdır | Yanlış kiracıyı `begin()` fonksiyonuna vermeyi engellemez; bu dördüncü katmanın işidir |
| Kapsamsız, yani kiracısız bir sorgu yazmak imkânsızdır, çünkü böyle bir tip yoktur | Ham SQL'de `AND tenant_id = ?` koşulunu unutmayı engellemez; satır seviyesi güvenlik bunun içindir |
| Yapılandırma değişkeninin işlem içinde ayarlandığını yapısal olarak garanti eder | — |

**Dördüncü katman: istek sınırında kiracı çözümlemesi, Axum ile.**

```rust
// Middleware: Host header -> TenantId; ASLA istek gövdesinden veya
// doğrulanmamış bir yol parametresinden. (CVE-2026-41166 dersi.)
async fn resolve_tenant(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let host = req.headers().get(HOST).and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let tenant = TENANT_CACHE.by_host(host).ok_or(StatusCode::NOT_FOUND)?;
    req.extensions_mut().insert(tenant);       // Extension, task_local DEĞİL
    Ok(next.run(req).await)
}

// Token tenant'ı ile yol/host tenant'ı EŞLEŞMELİ.
// CVE-2026-41166: "{realm} path segment… does not check that the caller may
// administer that realm" — Argus'ta bu bir extractor invariantı olmalı:
impl<S> FromRequestParts<S> for AuthenticatedTenant {
    async fn from_request_parts(parts: &mut Parts, s: &S) -> Result<Self, Self::Rejection> {
        let route_tenant: TenantId = *parts.extensions.get().ok_or(Rejection::NoTenant)?;
        let claims: Claims = /* token doğrula */;
        if claims.tenant != route_tenant { return Err(Rejection::TenantMismatch); }  // ← ZORUNLU
        Ok(AuthenticatedTenant(route_tenant))
    }
}
```

**Havuz seviyesinde güvenli başarısızlık.** `sqlx::PoolOptions` kancalarında `after_release` fonksiyonu `Ok(false)` veya bir hata dönerse bağlantı kapatılmaktadır.

```rust
PgPoolOptions::new()
    .after_release(|conn, _| Box::pin(async move {
        // Kemer + askı: SET LOCAL zaten COMMIT'te temizlenir, ama bir
        // yerde düz SET kullanıldıysa bağlantıyı havuza kirli döndürme.
        sqlx::query("RESET ALL").execute(conn).await?;
        Ok(true)
    }))
```

---

## Bölüm VII — Argus için öneri

### 7.1 Somut şema

```sql
-- ═══ TENANT KAYDI ════════════════════════════════════════════════════
CREATE TABLE tenants (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- DEĞİŞMEZ. Keycloak alias dersi: "Once defined, the alias cannot be changed."
    slug            text NOT NULL UNIQUE
                    CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    -- Silo kaçış yolu — GÜN-1. Bu kolon olmadan tenant'ı ayrı bir kümeye
    -- taşımak için tüm veri katmanını yeniden yazmak gerekir.
    placement_id    text NOT NULL DEFAULT 'pool-default',
    status          text NOT NULL DEFAULT 'active'
                    CHECK (status IN ('provisioning','active','suspended','purging')),
    -- Tenant başına ayarlar
    audit_retention_days int NOT NULL DEFAULT 90,
    rate_limit_rps       int NOT NULL DEFAULT 100,
    created_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

-- ═══ ISSUER / DOMAIN ═════════════════════════════════════════════════
CREATE TABLE tenant_domains (
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname     text NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('subdomain','custom')),
    -- Truffle Security dersi: DNS sahipliği bir KİRALAMADIR, yeniden doğrula.
    verified_at  timestamptz,
    reverify_at  timestamptz,
    cert_status  text,
    PRIMARY KEY (tenant_id, hostname)
);
-- Bir hostname tek tenant'a: WorkOS'un "one org per domain per environment" kuralı
CREATE UNIQUE INDEX tenant_domains_host_uniq ON tenant_domains (lower(hostname));

-- ═══ KULLANICI — TENANT-YEREL (Okul B) ═══════════════════════════════
CREATE TABLE users (
    tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id            uuid NOT NULL DEFAULT gen_random_uuid(),
    username      text NOT NULL,
    email         text,
    email_verified_at timestamptz,
    status        text NOT NULL DEFAULT 'active',
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- Zitadel v5 dersi: tenant PK'nın parçası, öznitelik değil.
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT users_tenant_username_uniq UNIQUE (tenant_id, username)
);

-- Keycloak'ın sentetik EMAIL_CONSTRAINT hack'ine GEREK YOK.
-- PG: "null values are not considered equal, unless NULLS NOT DISTINCT is specified"
-- GLOBAL unique ASLA: RLS'i bypass eder, "bu e-posta başka tenant'ta var"ı sızdırır.
CREATE UNIQUE INDEX users_tenant_email_uniq
    ON users (tenant_id, lower(email)) WHERE email IS NOT NULL;

-- Aynı insan, iki tenant: AÇIK, denetlenebilir bağ. ASLA otomatik e-posta birleştirme.
CREATE TABLE identity_links (
    a_tenant uuid NOT NULL, a_user uuid NOT NULL,
    b_tenant uuid NOT NULL, b_user uuid NOT NULL,
    linked_by uuid NOT NULL,
    linked_at timestamptz NOT NULL DEFAULT now(),
    proof     text NOT NULL,   -- 'invite_token' | 'admin_action' | 'verified_idp_subject'
    CHECK (a_tenant <> b_tenant),
    FOREIGN KEY (a_tenant, a_user) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (b_tenant, b_user) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

-- ═══ CLIENT — client_id GLOBAL BENZERSİZ (Keycloak'ın AKSİNE) ════════
CREATE TABLE clients (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id         uuid NOT NULL DEFAULT gen_random_uuid(),
    -- RFC 6749 §2.2: client_id yalnız AS içinde benzersiz olmak ZORUNDA.
    -- Global yapmak, paylaşımlı-anahtar hatasına karşı İKİNCİ bağımsız savunma.
    client_id  text NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT clients_client_id_global_uniq UNIQUE (client_id)
);

-- ═══ İMZALAMA ANAHTARLARI — TENANT BAŞINA ════════════════════════════
CREATE TABLE signing_keys (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid        text NOT NULL,          -- opak, tenant slug'ı İÇERMEZ (enumeration)
    alg        text NOT NULL CHECK (alg IN ('ES256','EdDSA','RS256')),
    -- Keycloak modeli: 1 aktif + N pasif
    state      text NOT NULL CHECK (state IN ('active','passive','disabled')),
    public_jwk jsonb NOT NULL,
    private_ref text NOT NULL,         -- KMS/HSM referansı, ham anahtar DEĞİL
    created_at timestamptz NOT NULL DEFAULT now(),
    retire_at  timestamptz,
    PRIMARY KEY (tenant_id, kid),
    CONSTRAINT signing_keys_kid_global_uniq UNIQUE (kid)
);
CREATE UNIQUE INDEX signing_keys_one_active
    ON signing_keys (tenant_id, alg) WHERE state = 'active';

-- ═══ DENETİM — tenant + zaman partition'lı (GDPR: DETACH + DROP) ═════
CREATE TABLE audit_events (
    tenant_id  uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    id         uuid NOT NULL,
    actor      jsonb, action text NOT NULL, target jsonb, detail jsonb,
    PRIMARY KEY (tenant_id, occurred_at, id)
) PARTITION BY RANGE (occurred_at);
-- Partition sayısını YÜZLERDE tut, binlerde değil (kilit bütçesi, §2.5).

-- ═══ RLS ═════════════════════════════════════════════════════════════
-- Uygulama rolü tablo sahibi DEĞİL ve BYPASSRLS YOK.
CREATE ROLE argus_app NOLOGIN NOBYPASSRLS;

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['users','clients','signing_keys','tenant_domains','audit_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    -- FORCE olmadan tablo sahibi RLS'i ATLAR. 1 numaralı sessiz başarısızlık.
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    -- FAIL-CLOSED: GUC yoksa current_setting(...,true) NULL -> sıfır satır.
    -- COALESCE/OR ile "admin modu" ASLA yazmayın: fail-open olur.
    EXECUTE format($p$
      CREATE POLICY %1$I_tenant ON %1$I AS RESTRICTIVE TO argus_app
      USING (tenant_id = (SELECT current_setting('argus.tenant_id', true)::uuid))
    $p$, t);
  END LOOP;
END $$;
```

Politika yazım kuralı 2.6'daki Supabase ölçümünden gelmektedir: fonksiyon her zaman `(SELECT …)` ile sarılır, çünkü bu bir başlangıç planı kurmakta ve satır başına değil sorgu başına bir kez değerlendirmektedir. Fark 178.000 milisaniyeden 12 milisaniyeye inmektedir.

### 7.2 Birinci günde kurulması gerekenler, sonradan imkânsızdır

| # | Madde | Sonradan neden imkânsızdır | Kanıt |
|---|---|---|---|
| 1 | `tenant_id` her tabloda ile her birincil anahtarda bulunur | Tüm birincil anahtarları düşürüp yeniden kurmak dünyayı durduran bir migration demektir | SuperTokens: 33 tablo, tüm birincil anahtarlar basamaklı, çevrimdışı migration |
| 2 | Her yabancı anahtar bileşiktir ve `tenant_id` içerir | Tek kolonlu yabancı anahtarlar çapraz kiracı referansa izin vermekte ve satır seviyesi güvenlik sonra okumayı bozmaktadır | Logto'nun 7596 numaralı PR'ı |
| 3 | Satır seviyesi güvenlik, zorlama ile sahip olmayan rol tüm tablolarda uygulanır | Sonradan eklemek ya hep ya hiçtir ve eksik bir tablo sessiz bir sızıntıdır | Logto'nun 7685 numaralı issue'su: her iş tablosunda |
| 4 | Kiracı başına imzalama anahtarı kullanılır | Paylaşımlıdan kiracı başınaya geçiş tüm ilgili tarafların JWKS önbelleğinin geçersizleştirilmesi ile koordineli bir kesinti demektir | Storm-0558 ile CVE-2026-23552 |
| 5 | `client_id` küresel benzersizdir | Sonradan küreselleştirmek müşteri istemci kimliklerini yeniden adlandırmak, yani her ilgili taraf yapılandırmasını kırmak demektir | RFC 6749 §2.2 |
| 6 | Kullanıcı benzersizliği kiracıya yereldir | Küreselden kiracıya yerele geçiş bir veri göçü ile güvenlik incelemesi gerektirir; tersi imkânsızdır | Zitadel: kullanıcıları organizasyonlar arasında taşımak mümkün değildir |
| 7 | Kiracı kısa adı değişmezdir | Kısa ad issuer URL'indedir ve değişirse her ilgili tarafın keşfi kırılır | Keycloak: takma ad sonradan değiştirilemez |
| 8 | Issuer stratejisi ile RFC 9207 `iss` parametresi belirlenir | Issuer değişimi tüm ilgili tarafların yeniden yapılandırılması demektir | RFC 8414 ile OIDC Discovery çelişkisi |
| 9 | `placement_id` silo kaçış kolonu konur | Yoksa düzenlemeye tabi bir kiracıyı ayrı bir kümeye taşımak bir mimari yeniden yazımdır | AWS'nin silo, havuz ile köprü modelleri |
| 10 | Denetim günlüğü kiracı ile zamana göre bölümlenir | Milyarlarca satırlı bir tabloyu sonradan bölümlemek pratikte imkânsızdır | Kişisel veri mevzuatının silme hakkı |
| 11 | Yetkilendirme isim tabanlı değil opak kimlik ile tam yol tabanlıdır | Token'da isim taşıyan her şey yeniden yazılır | CVE-2026-19608 |
| 12 | Token takasında kiracı kısıtı uygulanır | Ayrıcalıklı bir yoldur ve sonradan eklenirse mevcut entegrasyonlar kırılır | CVE-2026-18215 |
| 13 | Hız limiti ile kota boyutu şemada bulunur | Sonradan kiracı boyutu eklemek tüm sayaç durumunu geçersiz kılar | Okta ile Entra'nın organizasyon başına limitleri |
| 14 | Kiracı tip sisteminde markalı kapsam olarak bulunur | Sonradan eklemek her sorgu yolunu elden geçirmek demektir | CVE-2019-14832 |

### 7.3 Sonradan eklenebilecekler, birinci günde gerek yoktur

Özel alan adı ile ACME otomasyonu; kiracı başına tema; organizasyon içi grup hiyerarşisi; SCIM; kiracı başına politika motoru; Citus'a geçiş, ki `tenant_id` zaten parça anahtarıdır; hücre mimarisi, ki `placement_id` yolu açık bırakmaktadır.

### 7.4 Reddedilen alternatifler ile gerekçeleri

| Alternatif | Neden hayır |
|---|---|
| Kiracı başına şema | 1.200 kiracıda 383 milisaniyelik katalog taraması ile iki saatlik migration vardır; `search_path` havuzlamayı kırılganlaştırmaktadır; sqlx dinamik şema migration'ı vermemektedir |
| Kiracı başına veritabanı | Yaklaşık 50 kiracı tavanı, havuz çarpımı ile küme genelinde işlem ile nesne kimliği baskısı vardır |
| Realm benzeri ağır kiracı | Keycloak'ın 200 ile 500 tavanı, master realm O(N) bağlaması ile sabit küresel önbellek kanıtlanmış bir çıkmazdır |
| Küresel kullanıcı ile e-posta birleştirme | nOAuth, Entra alan adı devralması ile Truffle'ın terk edilmiş alan adı bulgusu üç bağımsız ihlaldir |
| Paylaşımlı imzalama anahtarı | Storm-0558 ile CVSS 9,1 puanlı CVE-2026-23552 |
| İç içe kiracı, yani ağaç | Zitadel, Auth0, Okta, Entra ile WorkOS reddetmiştir; Frontegg yapmıştır ve miras JWT'ye sığmamaktadır |
| `task_local` ile ortam kiracısı | `spawn` çağrısına miras kalmamakta ve erişimde panic etmektedir |
| Varsayılan RSA | 130 kat anahtar üretim maliyeti kiracı başına anahtarı ekonomik olarak imkânsız kılmaktadır |

---

## Bölüm VIII — Doğrulanamayanlar

Bunlar asla gerçek olarak sunulmamalıdır.

Wiz'in bulut izolasyon serisinin, yani ExtraReplica, ChaosDB ile BingBang'in teknik ayrıntısı ile Asana MCP olayı: bu konulara ayrılan araştırma akışı rapor yazımı sırasında tamamlanmamıştır.

Kiracı başına anahtar ile JWKS ve hız limiti konularının ayrıntılı satıcı karşılaştırması: aynı sebeple kısmidir; yukarıdakiler kendi birincil doğrulamalarımızdır.

CISA siber güvenlik inceleme kurulunun Storm-0558 raporu: PDF 403 döndürmüştür.

CYBERTEC'in çok fazla tablo size zarar verir yazısı: site 403 döndürmüştür ve `CacheMemoryContext` rakamları doğrulanmamıştır.

CVE-2025-8713: arama özetlerinde görünmüş ancak postgresql.org güvenlik listesinde doğrulanamamıştır.

Keycloak'ın KEYCLOAK-4593 ile diğer Jira kayıtları: izleyici artık herkese açık değildir ve yalnızca tanımlayıcı olarak anılmıştır.

Realm başına yığın bayt rakamı: yetkili bir kaynak yoktur.

Auth0'ın Organizations API hız limiti sayıları ile organizasyon metadata limitleri.

Frontegg'in azami hiyerarşi derinliği ile hak mirası.

Okta'nın hücre başına organizasyon sayısı ile organizasyon başına azami kullanıcı ve uygulama sayısı.

Satır seviyesi güvenlik ile genel plan önbelleklemesinin kiracılar arasında yanlış plan seçimine yol açması: ölçülmüş hiçbir çalışma yoktur.

N kiracı ile M havuz dağıtımının ölçülmüş ve kamuya açık bir hesabı: literatürün en zayıf noktasıdır ve bir prototip gerektirir.

İki bin şema ile şema başına 50 tabloda katalog taramalarının DDL'i yavaşlattığı iddiası: yalnızca AI üretimi blog içeriğine dayanmaktadır ve kullanılmamalıdır.

AWS'nin bulut yazılımı beyaz kâğıdındaki silo, havuz ile köprü tanımları: birinci sayfa doğrulanmış ancak alt sayfa çekimi başarısız olmuştur.

### Bir cümlelik kapanış

Argus'un çok kiracılığı satır bazlı olmalı, satır seviyesi güvenlikle desteklenmeli, kiracıyı hem birincil anahtarda hem Rust tip sisteminde taşımalı, kiracı başına imzalama anahtarı kullanmalı, alt alan adı issuer'ı benimsemeli ile düz bir kiracı listesi tutmalıdır. Bu kararların on dördü birinci günde verilmelidir, çünkü piyasadaki her IdP bunlardan en az birini ertelemiştir ve Keycloak on yılla, Zitadel bir depolama katmanı yeniden yazımıyla, SuperTokens dünyayı durduran bir migration'la ve Kanidm özelliği tamamen reddetmekle ödemiştir.
