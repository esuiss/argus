# 18. Çok kiracılık mimarisi

> `ARGUS.md` §18'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§18 §X` referansları aynı anlamda.



---

### 0. YÖNETİCİ ÖZETİ — NET KARAR

| # | Karar | Seçim | Gerekçe (tek cümle) |
|---|---|---|---|
| 1 | Veri izolasyonu | **`tenant_id` + RLS (FORCE) + `SET LOCAL` + transaction pooling**, gün-1'den `placement_id` kaçış kolonuyla | Schema-per-tenant 1.200 şemada 383 ms katalog taraması ve 2 saatlik migration'a çarpıyor; satır bazlı milyonlara ölçekleniyor |
| 2 | İmzalama anahtarı | **Tenant başına, ES256 varsayılan** — müzakere edilemez | Storm-0558 ve CVE-2026-23552, paylaşımlı anahtarda tek savunmanın RP'nin `iss` kontrolü olduğunu ve RP'lerin bunu yapmadığını kanıtladı |
| 3 | Kullanıcı kimliği | **Tenant-yerel** (`UNIQUE(tenant_id, …)`), asla global; çapraz erişim açık `grant`/`link` ile | E-posta ile otomatik birleştirme nOAuth sınıfı hesap devralmaya açıyor |
| 4 | Hiyerarşi | **Düz tenant listesi**; ağaç tenant İÇİNDE gruplarla | Zitadel, Auth0, Okta, Entra, WorkOS — hepsi iç içe tenant'ı reddetti; Frontegg yaptı ve miras JWT'ye sığmıyor |
| 5 | Issuer | **Subdomain birincil** (`acme.argus.io`, wildcard sertifika), custom domain yükseltme, path-based destekli ama varsayılan değil | Ayrı origin = tarayıcı düzeyinde çerez/XSS izolasyonu; CVE-2023-6717 bunun bedelini gösterdi |
| 6 | `client_id` | **Global benzersiz** (Keycloak'ın aksine) | RFC 6749 §2.2 client_id'yi yalnız AS içinde benzersiz kılıyor; iki bağımsız savunma katmanı gerekli |
| 7 | Rust | Tenant tipte kodlanır; **branded lifetime** (`generativity`) ile çapraz erişim derleme hatası | Olgun mekanizma var (3,99M indirme), çok kiracılığa uygulanmış yayımlanmış örnek yok — Argus ilk olur |

**Tek cümlelik gerekçe:** Bu kararların hiçbiri "en kolay" değil; hepsi **sonradan değiştirilemeyen** kararlar ve piyasadaki her IdP bunlardan en az birinde yanlış seçim yapıp yıllarca bedelini ödedi.

**Bunu en iyi özetleyen tek kanıt** — Kanidm (olgun bir Rust IdP) bakımcısı William Brown, 12 Haziran 2026:

> "It would be a very large undertaking to add this support within Kanidm. We discussed it many years ago and the complexity and risks (**especially security wise**) were not worth it."

Sonuç: "not planned", 13 Haziran 2026. ([kanidm#4395](https://github.com/kanidm/kanidm/issues/4395))

---

## BÖLÜM I — MEVCUT IdP'LERİN ÇOK KİRACILIK MODELLERİ

### 1.1 Keycloak realm — mimari, maliyet, tavan

#### Realm nedir, neyi izole eder

Resmî tanım ([server_admin](https://www.keycloak.org/docs/latest/server_admin/index.html)):

> "A realm is a space where you manage objects, including users, applications, roles, and groups. A user belongs to and logs into a realm."
> "**One Keycloak deployment can define, store, and manage as many realms as there is space for in the database.**"

Bu ikinci cümle, aşağıdaki üretim kanıtlarıyla **doğrudan çelişiyor**. Resmî dokümanın realm sayısı hakkındaki tek ifadesi bu ve yanlış.

**Kaynak kodundan doğruladım.** `jpa-changelog-1.0.0.Final.xml` (main branch) — ilk şema, 29 tablo:

```
REALM_ID ayırıcı kolonu taşıyanlar:
CLIENT, EVENT_ENTITY, FED_PROVIDERS, KEYCLOAK_ROLE, REALM_APPLICATION, REALM_ATTRIBUTE,
REALM_DEFAULT_ROLES, REALM_EVENTS_LISTENERS, REALM_REQUIRED_CREDENTIAL, REALM_SMTP_CONFIG,
REALM_SOCIAL_CONFIG, USERNAME_LOGIN_FAILURE, USER_ENTITY, USER_FEDERATION_PROVIDER,
USER_SESSION, USER_SOCIAL_LINK
```

**Keycloak satır bazlı çok kiracılık kullanıyor.** Schema-per-realm yok, database-per-realm yok, RLS yok. Güncel `UserEntity.java` (main):

```java
@Table(name="USER_ENTITY", uniqueConstraints = {
        @UniqueConstraint(columnNames = { "REALM_ID", "USERNAME" }),
        @UniqueConstraint(columnNames = { "REALM_ID", "EMAIL_CONSTRAINT" })
})
@Column(name = "REALM_ID")
protected String realmId;      // ← düz String. @ManyToOne DEĞİL. FK YOK.
```

`CLIENT` tablosunda: `UNIQUE(REALM_ID, CLIENT_ID)` → **`client_id` realm kapsamlı, global değil.**

**İzole ETMEDİKLERİ** (hepsi doğrulandı):

| İzole değil | Kanıt |
|---|---|
| DB şeması | Tek paylaşımlı şema, `REALM_ID` satır ayırıcısı |
| Bağlantı havuzu | Tek havuz ([keycloak.org/high-availability](https://www.keycloak.org/high-availability/multi-cluster/concepts-database-connections)) |
| JVM / heap | Tek JVM |
| Infinispan cache'leri | `realms`, `users`, `keys` **tek global cache**, realm başına değil |
| HTTP portu / origin | `/realms/{realm}/…` yol segmenti — **aynı origin** |
| Tema cache'i | `ThemeKey = (name, type)` — realm'e göre anahtarlanmıyor, **sınırsız `ConcurrentHashMap`, eviction yok** |
| Provider classloader | Sunucu başına bir kez |

#### Realm başına maliyet — somut

**Anahtarlar.** `DefaultKeyProviders.createProviders(RealmModel)` realm başına **dört** sağlayıcı: `rsa-generated` (SIG), `rsa-enc-generated` (ENC, RSA-OAEP), `hmac-generated-hs512`, `aes-generated`. `AbstractGeneratedRsaKeyProviderFactory`: `private int defaultKeySize = 2048;`

Yani **realm başına iki adet RSA-2048 çifti**. Doküman: *"When a realm is created, a key pair and a self-signed certificate is automatically generated."*

**Bu makinede ölçtüm** (macOS/Apple Silicon, LibreSSL 3.3.6; süreç başlatma tabanı 1,90 ms çıkarıldı):

| Algoritma | Ham | Net |
|---|---|---|
| EC P-256 (ES256) | 2,29 ms | **~0,4 ms** |
| Ed25519 (ssh-keygen, G/Ç dahil) | 4,43 ms | ~2,5 ms |
| RSA-2048 | 54,99 ms | **~53 ms** |
| RSA-4096 | 584,13 ms | ~582 ms |

**RSA-2048, P-256'dan ~130× yavaş.** Keycloak'ın realm başına 2×RSA-2048'i = ~110 ms saf CPU/tenant → 100.000 tenant = **~3 saat tek çekirdek**. ES256 ile aynı iş **~80 saniye**.

> **Literatürde tartışılmayan bağımlılık: algoritma seçimi izolasyon mimarisini belirliyor.** RSA seçersen "tenant başına anahtar" ölçeklenmez ve ekibi paylaşımlı anahtara iter — ki bu Bölüm III'te gösterdiğim üzere ölümcül.

**Cache.** `docs/guides/server/caching.adoc` (main):

> "Local caches for realms, users, and authorization are configured to hold up to **10,000 entries per default**."

`realms` cache **düz, global, 10.000 girdilik LRU** ve realm başına bir girdi tutmuyor — realm + her client + client scope + rol + grup, hem ID hem isimle anahtarlanmış. Üretim gözlemi ([forum, 1 Ağu 2024](https://forum.keycloak.org/t/realm-cache-entries-are-greater-than-the-number-of-realms/27277)):

> "I have one 'test' realm configured in addition to the master realm… I see that the realm cache jumps up to **hundreds of entries**."

**İşte "yüzlerce realm" tavanının mekanizması budur:** sabit global cache bütçesi ÷ değişken realm-başı girdi sayısı.

#### Neden binlerce realm çalışmıyor — ölçülmüş

Proje lideri Stian Thorgersen, keycloak-dev, **11 Ekim 2018**:

> "**Keycloak simply doesn't scale well with regards to large number of realms today.**"

**Kök mimari kusur — master realm O(N) bağlaması.** Keycloak collaborator Alexander Schwartz (ahus1), [Discussion #12332](https://github.com/keycloak/keycloak/discussions/12332), 3 Haz 2022: her realm `xxx` master'da `xxx-realm` client'ı yaratır; master'a login'de bu composite roller değerlendirilir. *"the persistence context grows, which slows down Hibernate's dirty checking."*

> **3000 realm: sticky session ile ~50 saniye login, sticky olmadan ~110 saniye.**

Bakımcı **stianst bu düzeltmeyi reddetti**: *"This approach doesn't work I'm afraid as there's a clear use-case for managing all realms from the master realm."* → **O(N) bağlama kasıtlı ve kalıcı.**

**Kronolojik ölçümler:**

| Sürüm/Tarih | Realm | Bulgu | Kaynak |
|---|---|---|---|
| KC 4.8.1, 31 Oca 2019 | 0→350 | Realm yaratma 1104→11535 ms; **token alma 636→3197 ms (5×)**; ~470'te "basically unusable" | [SO 54465114](https://stackoverflow.com/questions/54465114/) |
| KC 16.1, 18 Oca 2022 | 5→350 | Master admin console soğuk açılış **50 ms → 2 dakika (2400×)**; realm-yerel admin console **etkilenmiyor** | [forum 13127](https://forum.keycloak.org/t/performance-with-500-realms/13127) |
| KC 17, 1 Nis 2022 | ~620 | Üstel bozulma, test terk edildi. Optimizasyon dalıyla 3000 realm'de lineer | [#11074](https://github.com/keycloak/keycloak/discussions/11074) |
| KC 20.0.5, 18 Nis 2023 | 400 | Admin Console yüklenmiyor, `/admin/realms/{r}/users` timeout, JDBC leak. **"not planned" kapatıldı** | [#19793](https://github.com/keycloak/keycloak/issues/19793) |
| KC 20, 19 May 2023 | 307 | `/admin/realms?briefRepresentation=true` **107 saniye** (KC 17'de ~15 sn → **7× regresyon**) | [#20453](https://github.com/keycloak/keycloak/issues/20453) |
| KC 26, 29 May 2024 | 600+ | Realm dropdown açılması **~6 dakika**. Düzeltme: **UI sayfalama** (#30219), backend değil | [#29978](https://github.com/keycloak/keycloak/issues/29978) |

**On yıllık aynı kusur, Temmuz 2026'da düzeldi.** [#50369](https://github.com/keycloak/keycloak/issues/50369), 26 Haz 2026, KC 26.7.0: composite rol genişletmesi `getChildRoles` N+1 + her sorgudan önce full auto-flush. Ölçüm: composite genişletme CPU payı **%62 → %5,6**; DB sorgu/sn **5526 → 614 (−%89)**.

**Pratik tavan konsensüsü: 200–500 realm/küme, bozulma 100–200'de başlıyor.**

| Kaynak | Rakam |
|---|---|
| xgp (Phase Two), 1 Nis 2021 | "serious problems when using more than **~400 realms**" |
| Cloud-IAM (ticari Keycloak host), 8 Oca 2025 | "Performance is degraded beyond **a hundred or so** realms" |
| Phase Two, 21 Nis 2025 | "simply doesn't scale when you have 50, 100, or 500 tenants" |
| Klathmon, HN, 11 Şub 2024 | "after around **200 realms** things start breaking" |
| Üretim, KC 11.0.3, 25 Ağu 2021 | **373 realm**: login'de 20-30 sn; GC büyümesi → **aylık restart** |
| Üretim, KC 24.0.5, 2 Eki 2024 | **31. realm'de** `/admin/serverinfo` 400 Bad Request (token/header boyutu) |

26.x ne değiştirdi? **Mimari olarak hiçbir şey.** En iyimser iddia topluluktan ([#11074](https://github.com/keycloak/keycloak/discussions/11074), 5 Eki 2025): *"With Keycloak 26.4, it should be fine to run Keycloak with 1k+ realms **as long as you keep increasing the realm cache**."* — Bu bir ayar geçici çözümü, tenant'ı heap'le satın alıyorsun. Multi-site/multi-cluster (26.7) bir DR özelliği; `realms` cache düğüm-yereldir, **site eklemek realm tavanını yükseltmez**.

**Resmî bir maksimum realm sayısı beyanı yok** `[DOĞRULANAMADI]`. Resmî 26.4 benchmark'ında **realm sayısı boyutu hiç yok** — bu boşluk başlı başına bilgi.

#### Keycloak Organizations — Keycloak'ın kendi itirafı

KC 25 preview → **26.0.0 GA (4 Eki 2024)**. Resmî çerçeve bir CIAM boşluğu; **itiraf sözel değil, yapısal**: Keycloak realm içine ikinci bir tenancy primitifi inşa etti — org başına IdP, org başına domain, üyelik, token'da org claim'leri — çünkü realm çoğaltılamıyordu.

Dokümandan doğruladığım kritik tasarım kararları:

- Alias: *"The alias is unique within a realm and must be URL-friendly… **Once defined, the alias cannot be changed afterwards.**"* → **değişmez tenant slug'ı.**
- *"A domain cannot be shared by different organizations within a realm."*
- Üyelik: *"An organization member is **basically a realm user but with a link to** one or more organizations."* → **kullanıcı realm'e ait (global), org bir üyelik bağı.**
- Managed vs unmanaged: org silinince managed üyeler silinir, unmanaged'lar realm'de kalır. [#30747](https://github.com/keycloak/keycloak/issues/30747): *"members can have only **one managed membership**"* → **çok üyelik, ama yaşam döngüsünü tam bir tanesi sahiplenir.** Bu, "bu kullanıcıyı kim silebilir" sorusunun en temiz formülasyonu.
- Domain eşleme: exact vs wildcard (`.example.com`), *"The most specific match wins, measured by the number of domain parts"*; en az 2, en fazla 10 parça; `com`, `*.com` reddedilir.

**Dürüst karşı-argüman** — xgp (Phase Two), [forum, 8 Tem 2025](https://forum.keycloak.org/t/best-practice-for-keycloak-multi-tenancy/12893):

> "In a Realm, every user is in the same 'pool' of users. There is not a concept of 'logging into a tenant'… The Keycloak organizations functionality is essentially **a different way of associating users with a group on steroids**."

Ve Organizations'ın kendisi yeni regresyonlar üretti: [#46681](https://github.com/keycloak/keycloak/issues/46681) (27 Şub 2026, **hâlâ açık**) — `/admin/realms/{r}/users` kullanıcı başına org üyelik N+1 sorgusu tetikliyor, hiç org olmasa bile.

Delegated admin GA'dan **iki yıl sonra** geldi (26.7.0, 9 Tem 2026): `manage-organizations` / `view-organizations` rolleri + FGAP. Kalan sınır, verbatim: *"Sub-resource permissions — such as separate control over an organization's members, groups, or identity providers — are not included in this milestone."*

---

### 1.2 Zitadel — event-sourced izolasyon, ve ondan geri dönüş

#### Gerçek DDL (kaynak koddan)

`cmd/initialise/sql/08_events_table.sql` (main, 8 Eyl 2026):

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

Dikkatli okuyun:

- **`instance_id` birincil anahtarın ilk kolonu ve her indeksin başında.** Gerçek bölümleme anahtarı instance.
- **`owner` (organizasyon) PK'da DEĞİL, hiçbir indekste DEĞİL.** → **Org fiziksel bir sınır değil, indekslenmiş bir öznitelik.**
- `owner` iddia edilmez, **miras alınır**: `commands_to_events()` içinde `CASE WHEN c.enforce_owner THEN c.owner ELSE COALESCE(e.owner, c.owner) END` — bir aggregate'in org'u ilk olayıyla sabitlenir. **Kullanıcıların org'lar arası taşınamamasının teknik nedeni tam olarak budur.**

Benzersizlik kapsamı da instance (`10_unique_constraints_table.sql`): `PRIMARY KEY (instance_id, unique_type, unique_field)`. Org kapsamlı kullanıcı adı **dize kurgusuyla** sağlanıyor (`user@orgdomain.instancedomain`), DB kısıtıyla değil.

> **Not:** [zitadel.com/docs/concepts/eventstore/implementation](https://zitadel.com/docs/concepts/eventstore/implementation) hâlâ v1 `events` tablosunu belgeliyor. SQL'e güvenin, o sayfaya değil.

#### Org'un izole ettikleri, etmedikleri

**İzole:** login davranışı/MFA/passwordless/oturum ömrü, IdP'ler, parola karmaşıklığı/süresi, kilitleme, markalama, mesaj metinleri, domain'ler, proje grant'leri, kullanıcı adı formatı.

**İzole DEĞİL:** OIDC issuer, login domain'i, benzersizlik kapsamı, projeksiyon durumu, rate/kota limitleri — hepsi instance seviyesinde.

Verbatim, [custom-domain dokümanı](https://zitadel.com/docs/self-hosting/manage/custom-domain): *"by default, you cannot access ZITADEL at an organization's domain. Organization level domains are intended for routing users by their login methods to their correct organization."*

Org seçimi OIDC scope'uyla: `urn:zitadel:iam:org:id:{id}` — *"ZITADEL will enforce that the user is a member of the selected organization."*

#### Kullanıcı modeli — School B, saf haliyle

> "Users exist strictly within **one** Organization." / "It is currently not possible to move users between organizations." / "**You can reuse the same email address for different user accounts across organizations.**"
> — [zitadel.com/docs/concepts/structure/users](https://zitadel.com/docs/concepts/structure/users)

Çapraz erişim **External User Grant** ile: bir org başka org'un kullanıcılarını kendi projelerine davet eder. İkinci bir üyelik değil, bir **grant**.

Hiyerarşi yok, ve gerekçesi kayıtta — [Discussion #12248](https://github.com/zitadel/zitadel/discussions/12248), 11 Haz 2026:

> "**zitadel orgs are flat by design (no built-in parent/child)**" … "**Grants only work one level deep (Parent → Child) and you can't do Parent → Child → Grandchild so pls keep your hierarchy flat.**"

Önerilen çözüm: ebeveyn-çocuk eşlemesini **kendi uygulama veritabanında tut**.

#### "Gün-1 çok kiracılık" iddiası ne kadar gerçek

**Gerçek olan:** `instance_id` ve `owner` temel şemadan beri her olayda. Sınırsız org, yayımlanmış org limiti yok.

**Gerçek olmayan:**

1. **Org bir bölümleme değil, kolon değeri.** Org yaratmak ucuz; org fiziksel izolasyon birimi değil. Instance-per-tenant ise duvar: 70+ projeksiyonun her biri instance başına ayrı durum tutuyor ve ayrı advisory lock alıyor.
2. Zitadel N-over-N sorununu **kendi kabul ediyor** ([blog, 12 Şub 2026](https://zitadel.com/blog/scaling-cloud-native-identity-optimizing-performance-with-caching)): *"resolving context for every request creates an 'N-over-N' scaling bottleneck"* — çözüm cache. **Ama o cache v4.17'de hâlâ "experimental beta" ve varsayılan KAPALI.**
3. Yayımlanmış benchmark **yok**: hedefler yazılı (1000 auth/sn, 1200 login/sn), sonuçlar *"Will be established as soon as the goal described above is reached."*
4. Gerçek rakamlar mütevazı ([#9285](https://github.com/zitadel/zitadel/discussions/9285), 31 Oca 2025): tek Postgres ~175 req/s; login p95 100 VU'da 4,86 sn. Bakımcı fforootd darboğazı bcrypt cost 12-14 olarak saptadı.
5. Çok org'lu kullanıcı desteği **hâlâ yok**: [#5822](https://github.com/zitadel/zitadel/issues/5822) 11 May 2023'ten beri açık, 11 kriterin 1'i tamam. Bakımcı hifabienne, [#8518](https://github.com/zitadel/zitadel/discussions/8518): platform *"is not directly designed for your use case."*

#### En önemlisi: v5'te projeksiyonları terk ediyorlar

[#9599 "Relational database tables"](https://github.com/zitadel/zitadel/issues/9599), 21 Mar 2025, milestone **Zitadel v5**, 66 alt-görevin 47'si tamam. Durumu event-sourced projeksiyonlardan düz ilişkisel tablolara taşıyorlar; eventstore yalnız denetim için kalıyor. Verbatim gerekçe:

> "This approach gave us a number of issues… Projections can become eventual consistent… **This confuses tools like terraform**"

[Decision Log](https://github.com/zitadel/zitadel/wiki/Decision-Log) sürücüyü **"linear scalability issues"** olarak adlandırıyor ve tenancy şeklini sabitliyor: *"**ID Uniqueness (Nov 4, 2025): IDs are unique at the instance level only.** Primary keys use `instance_id + resource_id`."*

v5 prototip şeması (`backend/v3/storage/database/repository/inheritance.sql`) — dikkat, **org artık kullanıcı PK'sına giriyor**:

```sql
CREATE TABLE users ( username VARCHAR(50) NOT NULL,
    PRIMARY KEY (instance_id, org_id, id) ) INHERITS (org_objects);
```

> **Argus için ders:** Zitadel org'u projeksiyon **özniteliği** yaptı, şimdi ölçeklenebilirlik için tüm depolama katmanını yeniden yazıyor ve org'u **anahtara** geri koyuyor. Tenant'ı gün-1'de birincil anahtara koy.

---

### 1.3 Diğer ürünler — hızlı ama kesin

#### Auth0 Organizations

Kullanıcılar **tenant seviyesinde**, org bir üyelik katmanı. Kimliği org değil **connection** sahiplenir: *"Every organization that uses the Auth0 Organizations feature uses exactly one Auth0 connection."*

**Limitler, verbatim** ([Entity Limit Policy](https://auth0.com/docs/troubleshoot/customer-support/operational-policies/entity-limit-policy)):

| Varlık | Limit |
|---|---|
| Organizations per Tenant | **100.000** |
| Members per Organization | **100.000** |
| **Connections per Organization** | **10** |
| Discovery Domains per Organization | 100 |
| Role Assignments per Organization Member | 50 |

**Pazarlama sayısıyla çelişen iki gerçek limit:**

1. **Management API 1000 kayıt tavanı.** Auth0 personeli rueben.tiow, 27 Şub 2025: *"Both the Get Organizations and Get members who belong to an organization have a **1000 record limit**."* Ve *"there is not checkpoint pagination to retrieve more than 1000 organizations."* → **100.000 org saklayabilirsin; bir kullanıcının org'larını 1.000'in ötesinde sayamazsın.**
2. **Organization Picker 20 gösterir** (güncelleme 10 Eyl 2025): *"only 20 Organizations are shown."*

**`org_name` bir tuzak.** Tenant genelinde açılır, org başına açılamaz; isimler değişebilir ve yeniden kullanılabilir; *"long-lived tokens do not expire when an organization changes its name."* Ve verbatim: *"**If your API does not verify `iss` claims, an organization with the same name in a different tenant could generate tokens that are incorrectly accepted.**"* Auth0'ın kendi tavsiyesi: *"Using organization IDs for token validation remains the recommended approach."*

**Org başına custom domain YOK.** Doküman kaçış yolunu açıkça yazıyor: *"you would need to use multiple Auth0 tenants."* Ayrıca Universal Login zorunlu; ROPC, Device Flow, WS-Fed uyumsuz.

Ve altı yıl sonra hâlâ boşluk dolduruyorlar — **29 Tem 2026: Organization-Level Roles (Early Access).** O güne kadar roller tenant-global, yalnız *ataması* org kapsamlıydı.

#### WorkOS

En temiz org modeli, ama gerçek sınır **environment**: *"**Email addresses are unique to each WorkOS environment.**"* Kullanıcı global, `OrganizationMembership` ile çok-org.

Ve aktif e-posta birleştirme yapıyorlar ([blog, 1 Kas 2024](https://workos.com/blog/model-your-b2b-saas-with-organizations)): *"as long as the user keeps using the same email, **WorkOS will identify the duplication and resolve it by linking these identities under the same user**."*

> Bu, nOAuth'un tam olarak kötüye kullandığı primitif. Savunmaları kimlik katmanında değil, domain katmanında: *"Only one organization can include a specific domain in its domain policy per environment."* Ve *"WorkOS does not allow addition of common consumer domains, like `gmail.com`."*

Çok-org login akışı doğru tasarlanmış: `organization_selection_required` → `pending_authentication_token` → `urn:workos:oauth:grant-type:organization-selection`. JWT: `sub`, `sid`, `iss`, `org_id`, `role`, `permissions`.

Sert kenar: bir org'da birden çok SSO bağlantısı varsa `organization` seçicisi kırılıyor — `ambiguous_connection_selector`.

Limitler: 6.000 req/60s per API key; org silme 50/60s; **yayımlanmış maksimum org sayısı yok** (1,88 MB doküman dökümü tarandı) `[DOĞRULANAMADI]`.

#### Frontegg — hiyerarşiyi gerçekten yapan tek ürün, ve bedeli

`parentTenantId` gerçek, API gerçek (`POST /resources/hierarchy/v1`). Rol mirası gerçek: *"a role granted at a parent account automatically applies to every sub-account beneath it."*

**Ama taşıyıcı uyarı, verbatim:**

> "When users are granted access to sub-accounts, **the accounts where they are allowed will not appear on the user's access token (JWT) or the user's state.**"

Uygulama, kullanıcının hangi hesaplara erişebildiğini **API çağrısıyla hesaplamak zorunda.**

> **Hiyerarşinin bedeli tek cümlede: miras geçişli hale gelince token'a sığmayı bırakır ve her yetkilendirme kararı bir graf sorgusuna dönüşür.**

Maksimum derinlik hiçbir yerde belgeli değil `[DOĞRULANAMADI]`. Ayrıca engelleyici bir sınır: *"switchTenant is not supported between accounts that have custom login boxes enabled."* — Tenant başına markalı login ile sorunsuz tenant değişimi arasında seçim yapmak zorundasın.

Ve her planda geçerli sert bir kenar: **SSO config yazma 5–10/dakika, Enterprise dahil.** Binlerce tenant'ın SSO bağlantısını sağlamak, ne kadar ödersen öde kısıtlı.

#### authentik — "brand" çok kiracılık değil, markalama

Doküman sayfasının başlığı literal olarak **"Branding"**. Brand alanları (`authentik/brands/models.py`): `domain`, `default`, `branding_title/logo/favicon/custom_css/background`, **dokuz varsayılan flow FK'sı**, `default_application`, `web_certificate`, `client_certificates`, `attributes`.

**Brand'den User, Group, Role, Provider, Source, Policy'ye hiçbir FK veya M2M yok.** Brand = hostname başına sunum + varsayılan akış kaydı.

Kanıt ki izole etmiyorlar — [#6020](https://github.com/goauthentik/authentik/issues/6020) (20 Haz 2023): *"The 'My Applications' listing… will show the set of applications based on the last tenant accessed by the user."* **"not planned" kapatıldı, `legacy/wontfix`.** [#6140](https://github.com/goauthentik/authentik/issues/6140) "tenant enumeration" — o da "not planned".

Gerçek çok kiracılık (Postgres şemaları, `django-tenants`) alpha ve Enterprise'a kapalı. Bakımcı dewi-tik, [#19009](https://github.com/goauthentik/authentik/issues/19009), 23 Ara 2025:

> "Multi-tenancy is still in **early preview and likely to remain that way for the foreseeable future**. It is also likely to remain an enterprise feature. However, **there's nothing preventing you from running multiple instances** and syncing users between them."

Belgeli sınır: *"Expression policies currently have access to all tenants."*

#### Okta — hücre (cell) mimarisi

[High Availability Architecture whitepaper, Eyl 2022](https://www.okta.com/sites/default/files/2022-09/Okta%20High%20Availability%20Architecture_Whitepaper.pdf):

> "One of the most critical aspects of Okta's architecture is that it is **completely multi-tenant**. With this design, customers share the same underlying environment."
> "Each Okta environment is called a **cell**… Because each cell can operate independently, they form the basis of our availability strategy by helping to limit the number of customers impacted by an outage."
> "every cell is an **isolated, shared-nothing, identical replica** of our infrastructure, spanning routers and load-balancers within our edge to databases."

`status.okta.com` ~26 tanımlayıcı listeliyor → **onlarca hücre, yüzlerce değil.**

Org modeli: *"Orgs are hard boundaries, so **objects can't be shared across orgs**."* Federasyonla bile *"the users still exist in each org separately."* **Alt-org yok.** Tek-org tenancy grup + isim konvansiyonuyla — dokümanın kendi örneği `app-1-johndoe`.

Rate limit **org başına**: `/oauth2/v1/authorize` 1200 req/dk/org; `/api/v1/users/*` 1000 req/dk/org.

**İhlaller veri düzleminde değil, destek düzleminde oldu.** Eki 2023: *"The threat actor was able to view files uploaded by certain Okta customers as part of recent support cases"* (HAR dosyaları, oturum token'ları). Okta: *"The Okta support case management system is separate from the production Okta service."*

> **Argus için ders:** org sınırı tuttu; başarısız olan, müşteri kiracılarının İÇİNDE geçerli kimlik bilgisi tutan bant-dışı bir sistemdi. Destek/impersonation araçları kasıtlı bir çapraz-tenant kontrol düzlemidir ve mimariden daha fazla incelemeyi hak eder.

#### Entra ID — tenant güvenlik sınırı, partition ölçek birimi

> "For the Microsoft Entra data tier, **scale units are called partitions**." Birincil replika tüm yazmaları alır, farklı bir veri merkezindeki ikincile anında replike eder; okumalar coğrafi dağıtık ikincillerden, asenkron.
> "The directory model is one of **eventual consistency**." Ve kritik: *"**For application-only requests, Microsoft Entra ID does not provide session consistency.**"*
> — [learn.microsoft.com/entra/architecture](https://learn.microsoft.com/en-us/entra/architecture/architecture) (ms.date 2026-05-07)

Token seviyesinde izolasyon, verbatim:

> "If a single user exists in multiple tenants, the user contains a **different object ID in each tenant — they're considered different accounts**."
> "Don't use the `idp` claim to store information about a user in an attempt to **correlate users across tenants. It doesn't work**, as the `oid` and `sub` claims for a user change across tenants, **by design**."

Servis limitleri ([ms.date 2026-07-29](https://learn.microsoft.com/en-us/entra/identity/users/directory-service-limits-restrictions)): kullanıcı başına max **500 tenant** üyeliği; **200 tenant** yaratma; doğrulanmış domain'li tenant **300.000 nesne**; **240 Conditional Access politikası**; SAML token'da **150** grup, JWT'de **200**, CA değerlendirmesinde **4.096**.

**Raporun en kolay gözden kaçan mimari gerçeği** — External ID iki dizin ölçek modu yayımlıyor: standart mod 15 milyon nesneye kadar; üstünde **HSC modu**, ve HSC'de gelişmiş sorgular, delta sorguları ve **giden SCIM sağlama DESTEKLENMİYOR**. *"HSC mode prioritizes stability and throughput at scale over query-heavy or event-driven directory operations."*

#### Rust dünyası — kimse yapmıyor

| Proje | Durum |
|---|---|
| **Kanidm** | Reddetti. "not planned", 13 Haz 2026. Gerekçe yukarıda. |
| **Rauthy** | Çok kiracılık yok. [#1678](https://github.com/sebadob/rauthy/issues/1678) kullanıcı soruyor, cevap yok. |
| **Ory Kratos** | *"The Ory Kratos open-source version is intended for **single-tenant use only**. Its data model isn't architected to support the data isolation, scalability, and operational needs of a multi-tenant environment."* [#407](https://github.com/ory/kratos/issues/407) May 2020'den beri açık; [#3129](https://github.com/ory/kratos/issues/3129) `not_planned` kapatıldı. |

**crates.io taraması (8 Eyl 2026):** hazır çok kiracılık altyapısı **yok**. En büyüğü `pg_multitenant` 1.617 indirme, son güncelleme 2024 (ölü). Karşılaştırma: `generativity` 3.991.685 indirme, aktif.

---

### 1.4 KARŞILAŞTIRMA TABLOSU — ürün modelleri

| Ürün | Tenant birimi | İzolasyon gücü | Ölçek sınırı | Kullanıcı kapsamı | Neyi yanlış yaptı |
|---|---|---|---|---|---|
| **Keycloak realm** | Realm | Veri: güçlü (ama FK'sız discriminator). Runtime: **sıfır** | **200–500/küme** | Realm-yerel | Master realm O(N) bağlaması; sabit 10k global cache; 10 yıllık Hibernate N+1 |
| **Keycloak Organizations** | Org (realm içi) | Zayıf — paylaşımlı kullanıcı havuzu, paylaşımlı anahtar, paylaşımlı tema | "birkaç bin/realm" | Realm-global + üyelik | GA'dan 2 yıl sonra delegated admin; kendi N+1'ini üretti |
| **Zitadel Instance** | Instance | Güçlü (PK'nın ilk kolonu) | Projeksiyon başına lineer maliyet | Instance | — |
| **Zitadel Org** | Org | **Zayıf — indekslenmiş öznitelik**, PK'da değil | Yayımlanmamış | **Org-yerel, taşınamaz** | Org'u anahtar yapmadı → v5'te tüm depolamayı yeniden yazıyor |
| **Auth0 Org** | Org (tenant içi) | Orta — connection kimliği sahipleniyor | 100k saklanır / **1k sayılabilir / 20 gösterilir** | Tenant-global | Connection-owned kimlik; org-scoped roller 2026'da EA |
| **WorkOS Org** | Org (env içi) | İyi — her connection/directory/log org'a ait | Yayımlanmamış | **Env-global, e-posta ile OTOMATİK BİRLEŞTİRME** | E-posta birleştirmesi nOAuth yüzeyi |
| **Frontegg Account** | Account + alt-account | Orta | Yayımlanmamış; SSO yazma **5-10/dk** | Env-global, otomatik birleştirme | Miras JWT'ye ulaşmıyor; custom login ↔ tenant switch çelişkisi |
| **authentik Brand** | Brand | **YOK — sadece markalama** | — | Tek havuz | "tenant" adını markalamaya verdi; gerçek tenancy 2 yıldır alpha |
| **Okta Org** | Org (+ hücre) | **Çok güçlü — shared-nothing hücre** | ~onlarca hücre | Org-yerel | Destek düzlemi iki kez ihlal edildi |
| **Entra Tenant** | Tenant (+ partition) | **Çok güçlü — güvenlik sınırı** | 500 tenant/kullanıcı; 300k nesne | Tenant-yerel (`oid` tasarımca değişir) | Paylaşımlı MSA anahtarı → Storm-0558 |
| **Stytch Org** | Org | Güçlü — Member org-yerel | Yayımlanmamış | **Org-yerel** | Genç, ilk ölçek migrasyonu önünde |
| **Logto Org** | Org (tenant içi) | Cloud'da **RLS + tenant başına PG rolü** | — | Logto-tenant-global | RLS ya hep ya hiç: 60+ tabloda zorunlu, yoksa başlamıyor |
| **SuperTokens Tenant** | App → Tenant | İyi — varsayılan izole havuz | — | `appId→tenantId→email` | 2023'te retrofit: 33 tablo, tüm PK'lar CASCADE ile düşürüldü, **dünya-durduran migration** |

---

## BÖLÜM II — VERİTABANI İZOLASYON STRATEJİLERİ

### 2.1 Üç strateji — ölçülmüş karşılaştırma

| Boyut | Satır bazlı (`tenant_id` + RLS) | Schema-per-tenant | Database-per-tenant |
|---|---|---|---|
| **Pratik tenant tavanı** | **1M+** (Citus: 1–1.000.000+) | **1.000–2.000**, vendor aralığı 100–10.000 | **~50** (Crunchy: "50 customers or more steer clear") |
| **Migration maliyeti** | **O(1)** — tek DDL | **O(N)**: 1.200 tenant = **2 saat**; 1.500 tenant = **5 saat** | O(N) + bağlantı çoğullaması |
| **Backup/restore granülerliği** | Zayıf — mantıksal export gerekir | İyi — `DROP SCHEMA CASCADE`, ama pg_dump: **20k şema = >24 saat** | Mükemmel — `DROP DATABASE` |
| **Connection pool** | **En iyi** — tek havuz, `SET LOCAL` sunucu-garantili | Kırılgan — `search_path` oturum durumu; PgBouncer ≥1.20 `track_extra_parameters` gerekir | En kötü — havuz çarpımı |
| **Gürültülü komşu** | Kötü — paylaşımlı her şey; `citus_stat_tenants` tek native araç | Orta | En iyi |
| **GDPR silme** | `DELETE` → ölü tuple + vacuum baskısı (partition'lıysa `DETACH`+`DROP`) | Anında | Anında |
| **XID/OID wraparound** | Düşük | Düşük | **Yüksek** — "OID/XID is a single PostgreSQL clusterwide counter" |
| **Vendor kılavuzu** | Crunchy "milyonlar"; Citus 1–1M+ | Crunchy "100'ler"; Citus 1–10k; PlanetScale "birkaç yüz" | Crunchy "50'den kaçın" |

Kaynaklar: [AWS Prescriptive Guidance matrisi](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-managed-postgresql/matrix.html) · [Crunchy Data, Craig Kerstiens, 14 Kas 2023](https://www.crunchydata.com/blog/designing-your-postgres-database-for-multi-tenancy) · [Citus 12, Marco Slot, 18 Tem 2023](https://www.citusdata.com/blog/2023/07/18/citus-12-schema-based-sharding-for-postgres/) · [PlanetScale, 21 Nis 2026](https://planetscale.com/blog/approaches-to-tenancy-in-postgres)

### 2.2 KRİTİK SAYI: PostgreSQL kaç şemayı gerçekten kaldırır?

**Cevap: düşük binler. Bağlayıcı kısıt katalog tarama maliyeti + backend başına relcache + migration/backup duvar saati — depolama değil.**

#### Kanıt 1 — migration katili (en aktarılabilir sayı)

pgsql-performance, **Ulf Lohbrügge, 27 Haz 2017, PG 9.5.7** ([mesaj](https://www.postgresql.org/message-id/CABZYQRKnp=FxZ7tQeyytDjUOnHP9J90irxRBEAc+-XGbKdgf2A@mail.gmail.com)):

- **~1.200 şema × ~200 tablo ≈ 240.000 tablo**
- `SELECT * FROM information_schema.tables WHERE table_schema='foo' AND table_name='bar';`
  → **execution 383,784 ms**, `pg_class` üzerinde **sequential scan**, **1.305.161 satır filtreyle elendi**, dönen satır: **0**
- Sebep: `information_schema` view'ları satır başına `pg_has_role()` çağırıyor — sistem katalogları üzerinde indekslenemez
- İş etkisi: **tüm tenant'larda Flyway migration ≈ 2 saat** (tenant başına 10+ `information_schema` sorgusu)

> **Bu, raporun en aktarılabilir sayısıdır:** `information_schema` sorgulayan her ORM/migration aracı, **her çağrıda** tam bir `pg_class` taraması öder ve bu maliyet toplam relation sayısıyla lineerdir. "Schema-per-tenant sorun değil, migration'ı otomatikleştir" tavsiyesinin pratikte neden çöktüğünün açıklaması budur.

Doğrulayıcı: [django-tenant-schemas #387](https://github.com/bernardopires/django-tenant-schemas/issues/387), 29 Eyl 2016 — *"more than 1500 tenants, migration takes more than 5 hours."*

#### Kanıt 2 — pg_dump duvarı

pgsql-hackers, *"pg_dump and thousands of schemas"*, May–Kas 2012:

- Üretim (Hugo, PG 9.0): **>20.000 şema, ~500.000 relation, 40 GB.** Tek boş şema dökümü **~12 dakika**; **tam döküm >24 saat** (monolitik şemayken 2-3 saat) → günlük tutarlı yedek imkânsız. 2.311 şemalı örnek DB: **3 saat**.
- Sentetik (Tatsuo Ishii), **100.000 tablo**: PG 9.0.2 **188 dakika** → sunucu-taraflı lock düzeltmesinden sonra **4 dakikanın altı** (%97 azalma)
- Mekanizma: `LockReassignCurrentOwner` **O(N²)** — PG 9.2'de düzeltildi. Ama Denis (PG 9.2.1, 6 Kas 2012) hâlâ tek şema dökümünde **veri boyutundan bağımsız 30-40 sn** görüyordu; `pg_class`/`pg_depend`/`pg_authid` join'i tek başına **10-15 sn**.

#### Kanıt 3 — autovacuum çöküşü (BUG #13750)

**David Gould, 30 Eki 2015, PG 9.4.5**, 80 HW thread / 1 TB RAM: **~200.000 tablo, `pg_class` >500.000 satır.**

| autovacuum worker | işlem/saat | worker başına |
|---|---|---|
| 1 | 2110,1 | 2110,1 |
| 4 | 647,3 | 161,8 |
| **72** | **62,0** | **0,9** |

**Worker eklemek throughput'u DÜŞÜRÜYOR.** Belirtiler: `pg_attribute` **200 GB**'a çıktı; yeni bağlantılar başlangıçta takıldı çünkü kataloglar artık buffer cache'e sığmıyordu.

#### Kanıt 4 — backend başına bellek (yoğunluk sınırı)

PostgreSQL dokümanı §5.12.6, verbatim:

> "the server's memory consumption may grow significantly over time, especially if many sessions touch large numbers of partitions. That's because **each partition requires its metadata to be loaded into the local memory of each session that touches it**."

Citus aynı mekanizmayı >10.000 şema başarısızlık modu olarak adlandırıyor: *"PostgreSQL's per-process catalog cache consuming excessive memory."*

#### Uzman konsensüsü

- **John R Pierce**, 30 Eyl 2016: 1000 şema × 100 tablo → *"massive bloat of the postgres catalog and also makes caching less effective."*
- **Jeff Janes**, 1 Eki 2016: çok-veritabanı ile çok-şema arasındaki runtime farkı **PG 9.3'ten sonra büyük ölçüde kapandı**; seçimi *restore granülerliğine* göre yap, runtime maliyetine göre değil.
- **Paul Jungwirth**, 30 Eyl 2016: schema-per-tenant, katalog sorgularıyla **tenant sayısını sızdırır.**

#### Mutlak tavan (dosya sistemi, PostgreSQL değil)
[kspeakman, 8 Şub 2019](https://dev.to/kspeakman/breaking-postgres-with-too-many-tables-4pg0): **1,3 milyon tablo** yaratıldı; ~4 GB boş tablo; `53100: No space left on device` — 13 GB boş alanla → **inode tükenmesi**.

### 2.3 sqlx 0.9 `sqlx.toml` — gerçekte ne veriyor

**Cevap: beklediğinizin çok azını.**

- **sqlx 0.9.0 yayın: 2026-05-21** (crates.io API). 0.9.0-alpha.1: 2025-10-15.
- `[migrate]` anahtarları ([docs.rs, migrate::Config](https://docs.rs/sqlx/latest/sqlx/_config/migrate/struct.Config.html)):
  - `table-name` — "Override the name of the table used to track executed migrations." Varsayılan `_sqlx_migrations`. "May be schema-qualified… Useful for multi-tenant databases."
  - `create-schemas` — "Specify the names of schemas to create if they don't already exist."
  - `migrations-dir`, `ignored-chars`, `defaults`

**Ve deponun `examples/postgres/multi-tenant` örneği tenant çok kiracılığı DEĞİL.** Üç crate (main/accounts/payments) tek DB'de kendi şemasını yönetiyor. `sqlx.toml`'un tamamı:

```toml
[migrate]
# Move `migrations/` to under `src/` to separate it from subcrates.
migrations-dir = "src/migrations"
```

Doküman ayrıca `search_path` kullanımına karşı **uyarıyor**, schema-qualified isim öneriyor: *"if `search_path` is set to `public,accounts,payments`… the migrator… would throw an error."*

> **SONUÇ: `sqlx.toml` dinamik, tenant başına şema migration'ı VERMEZ.** Şema listesi config zamanında sabittir. N tenant için N şema migrate etmek tamamen sizin yazacağınız koddur. Bu, schema-per-tenant seçeneğinin Rust'ta ekstra maliyetidir.

### 2.4 Bağlantı havuzu + oturum durumu sızıntısı — KESİN CEVAP

**Soru:** PgBouncer transaction mode'da `SET app.tenant_id` gerçek bir sızıntı riski mi?

**Cevap: `SET` → EVET, gerçek bir güvenlik açığı. `SET LOCAL` → HAYIR, ve garanti sunucudan gelir, pooler'dan değil.**

PgBouncer dokümanı, verbatim:

> "When transaction pooling is used, **the `server_reset_query` is not used**, because in that mode, clients must not use any session-based features, since each transaction ends up in a different connection and thus gets a different session state."

(`server_reset_query` varsayılanı `DISCARD ALL`; `server_reset_query_always` varsayılan kapalı.)

Feature matrisinde transaction pooling: `SET`/`RESET` = **"Never"**.

PostgreSQL `SET` dokümanı, verbatim:

> "The effects of `SET LOCAL` last only till the end of the current transaction, **whether committed or not**. After `COMMIT` or `ROLLBACK`, the session-level setting takes effect again."
> "**Issuing this outside of a transaction block emits a warning and otherwise has no effect.**"

**Doğru kalıp:**

```sql
BEGIN;
  SELECT set_config('argus.tenant_id', $1, true);   -- true = SET LOCAL
  -- sorgular
COMMIT;   -- GUC gitti, sunucu garantili
```

**Üç ölümcül tuzak:**

1. **Transaction dışında `SET LOCAL` SESSİZCE hiçbir şey yapmaz** — sadece warning. Explicit transaction zorunlu.
2. **Düz `SET` (LOCAL'sız)** commit'te sunucu bağlantısında kalır; PgBouncer transaction mode'da `DISCARD ALL` çalışmaz → **bir sonraki client onu miras alır.**
3. **`SET` sonra `SET LOCAL` aynı transaction'da**: PG dokümanı — *"the `SET LOCAL` value will be seen until the end of the transaction, but afterwards (if the transaction is committed) the `SET` value will take effect."*

**AWS RDS Proxy PostgreSQL için pratikte diskalifiye.** [Pinning dokümanı](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-pinning.html): *"Setting a parameter… Specifically, using `SET` and `set_config` commands"* pinning'e yol açar. Ve *"**RDS Proxy doesn't support session pinning filters for PostgreSQL**"* — vazgeçemezsiniz. `SET LOCAL` muafiyeti yalnızca MySQL bölümünde yazıyor; PostgreSQL bölümü `SET`'i koşulsuz listeliyor `[Muafiyet DOĞRULANAMADI — varsaymayın]`.

**Schema-per-tenant'ın havuz hikâyesi yapısal olarak daha kırılgan.** Citus 12 için PgBouncer **≥1.20** ve **`track_extra_parameters = search_path`** gerekiyor. `search_path`, pooler'ın *izleyip yeniden uygulaması* gereken oturum durumudur — `SET LOCAL`'ın sunucu garantisinden kesinlikle daha zayıf.

### 2.5 Partition'la tenant — kilitler planlamadan önce çarpar

PostgreSQL dokümanı §5.12.6:
> "The query planner is generally able to handle partition hierarchies with **up to a few thousand partitions** fairly well, provided that typical queries allow the query planner to prune all but a small number of partitions."
> §5.12.4: "any partitions removed by the partition pruning done at this stage are **still locked** at the beginning of execution."

**Ölçüm — Kaarel Moppel, 18 Nis 2023, PG 15.2**, pgbench scale 5000, 56 saat: planlama süresi 16 partition'da **+%51,8** → 4096'da **+%128,8**. Yürütme süresi neredeyse sabit (+%4,6 … −%5). `max_locks_per_transaction` 64→128 çıkarmak zorunda kaldı.

**Ölçüm — PostgresAI, 3 Eki 2024, PG 16**: yeni bağlantıda **1.000 partition = planlama 12,435 ms vs yürütme 0,354 ms (35×)**. **4 Eki 2024 düzeltmesi (önemli):** *yeniden kullanılan* bağlantıda ikinci `EXPLAIN` 1.000 partition'da bile **<0,1 ms**. → **Partition planlama maliyeti soğuk-bağlantı maliyetidir.** Sıcak backend tutan pooler ile büyük ölçüde kaybolur; serverless/kısa ömürlü bağlantıda baskın gecikmedir.

**Asıl tehlike planlama değil, KİLİT.** Kyle Hailey, Nis 2023, PG 13, 10.000 qps: 40 partition × 22 indeks = **sorgu başına 880 kilit**; zirvede **150.000 kilit**, 500 oturum `LWLock:LockManager`'da bekliyor, **saniyede 1.000 hata**. Başlangıç sadece ~12 partition'da (>220 kilit).

Mekanizma: **PostgreSQL 17'ye kadar her backend'de tam 16 fast-path lock slotu var.** Christophe Pettus, 17 Ağu 2026: *"A single table with a primary key and 20 secondary indexes requires 22 locks per query — filling all fast-path slots."*

**PostgreSQL 18 bunu düzeltiyor** (commit `c4d5cb71d`, Tomas Vondra): fast-path kilitleri `max_locks_per_transaction`'dan boyutlanan değişken dizilere taşındı → varsayılan 64, backend başına 64 slot. PostgresAI benchmark'ı (9 Eki 2025): `max_locks_per_transaction=1024` ile **uçurum hiç oluşmadı.**

**Bütçe formülü:** `partition_sayısı × (1 + partition_başına_indeks)` = planlayıcının plan zamanında budayamadığı her sorgunun kilit maliyeti.

### 2.6 RLS — gerçek performans ve gerçek bypass yüzeyi

#### Bypass yüzeyi — PostgreSQL dokümanından verbatim

> "**Superusers and roles with the `BYPASSRLS` attribute always bypass** the row security system when accessing a table. **Table owners normally bypass row security as well**, though a table owner can choose to be subject to row security with `ALTER TABLE ... FORCE ROW LEVEL SECURITY`."

> **1 numaralı sessiz başarısızlık modu bu:** uygulamanız tablo sahibi olarak bağlanıyorsa (ki her migration aracının varsayılanı budur), `ENABLE ROW LEVEL SECURITY` **kelimenin tam anlamıyla hiçbir şey yapmaz.**

> "**Referential integrity checks, such as unique or primary key constraints and foreign key references, always bypass row security** to ensure that data integrity is maintained. Care must be taken when developing schemas and row level policies to avoid **'covert channel' leaks** of information through such referential integrity checks."

> **Türetilmiş sonuç — Argus için doğrudan sonuç doğuran:** global bir `UNIQUE(email)` kısıtı RLS'i **atlar** ve bir unique-violation hatası tenant A'ya "bu e-posta başka bir tenant'ta var" bilgisini sızdırır. **`UNIQUE(tenant_id, email)` bir tercih değil, bir gizli kanal savunmasıdır.**

> "(The only exceptions to this rule are **`leakproof` functions**, which are guaranteed to not leak information; the optimizer may choose to apply such functions ahead of the row-security check.)"

Sonuç (pganalyze, Lukas Fittl, 28 Tem 2022): **leakproof olmayan operatörler indeks kullanımını tamamen kaybettirebilir** — RLS açılınca `ILIKE`'ın GIN indeksini yok saydığı belgeli bir vaka var. Yönetilen servislerde bir fonksiyonu LEAKPROOF işaretlemek superuser gerektirir → **RDS/Cloud SQL'de düzeltilemez.**

**View'lar varsayılan `SECURITY DEFINER`'dır.** PG 15 `CREATE VIEW ... WITH (security_invoker = true)` ekledi.

#### RLS CVE'leri — bir örüntü var

| CVE | Açıklama | Düzeltildi | CVSS |
|---|---|---|---|
| **CVE-2026-14666** (13 Ağu 2026) | "PostgreSQL row security caching **disregards role modifications**" | 18.6, 17.11, 16.15, 15.19, 14.24 | 4.2 |
| **CVE-2024-10976** | "row security below e.g. subqueries **disregards user ID changes**" | 17.1, 16.5, 15.9, 14.14 | 4.2 |
| **CVE-2023-2455** | "Row security policies **disregard user ID changes** after inlining" | 15.3, 14.8 | 4.2 |
| **CVE-2023-39418** | "MERGE fails to enforce UPDATE or SELECT row security policies" | 15.4 | 3.1 |

> **Dördün üçü AYNI hata sınıfı: oturum içinde etkin rol değiştiğinde RLS politika cache'inin geçersizleştirilmemesi.** Bu tam olarak transaction başına `SET ROLE` yapan bir connection pooler'ın tetiklediği şeydir. **RLS + `SET ROLE` + pooling kombinasyonu kullanıyorsanız agresif yamalayın ve minimum sürüm sabitleyin.**

Ayrıca **CVE-2019-10130**: "leaky operator" optimizer istatistiklerinden örneklenmiş veri okuyabiliyordu — *"if this included values from rows forbidden by a row security policy, the user could effectively bypass the policy."*

**Komşu gerçek dünya kırılması — Heroku Postgres, 29 Eki 2025 açıklandı, 4 Kas 2025 düzeltildi:** `_heroku` şemasındaki `search_path` niteliksiz bir `SECURITY DEFINER` fonksiyonu; saldırgan `public` içinde `pg_event_trigger_ddl_commands()`'i gölgeledi, `rds_superuser` kazandı, **diğer müşterilerin veritabanlarını okuyup yazdı.** ([allistair.sh](https://allistair.sh/blog/breaking-heroku-postgres/))

> **Ders: `SET search_path` olmayan `SECURITY DEFINER`, herhangi bir Postgres tenancy modelinden çıkışın standart kaçış yoludur.**

#### RLS performansı — dört büyüklük mertebesi

Supabase'in kendi benchmark'ı, 100K satırlık tablo ([kaynak](https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv)):

| Optimizasyon | Önce | Sonra |
|---|---|---|
| RLS kolonuna indeks | 171 ms | **<0,1 ms** |
| `auth.uid()` → `(select auth.uid())` | 179 ms | 9 ms |
| security-definer `has_role()`'ü `select` ile sar | **178.000 ms** | **12 ms** |
| Politikaya `TO authenticated` ekle | 170 ms | **<0,1 ms** |

1M satır, takım üyeliği:

| Politika biçimi | İndeks | 10 takım | 500 takım |
|---|---|---|---|
| `= ANY(user_teams())` | hayır | >2 dk | >2 dk |
| `= ANY(ARRAY(select user_teams()))` | hayır | 170 ms | 3.300 ms |
| `= ANY(ARRAY(select user_teams()))` | **evet** | **2 ms** | **3 ms** |

**Mekanizma:** `(select ...)` ile sarmak planlayıcıya **InitPlan** kurdurur — fonksiyon satır başına değil **sorgu başına bir kez** değerlendirilir, seq scan index scan'e döner. Kısıt (dokümandan): yalnızca *"if the results of the query or function do not change based on the row data."*

> **RLS "yavaş" değildir. Naif yazılmış RLS felakettir, ayarlanmış RLS bedavaya yakındır.** Fark dört-beş büyüklük mertebesi ve tamamen politika biçimine bağlıdır.

Bağımsız ölçüm (Scott Pierce, 5 Oca 2025): 1M blog / 1,8M üyelik — doğrudan korelasyonlu count **31,162 ms** vs `IN (subquery)` **106,628 ms** (3,4×).

**Ölçülmemiş bilinmeyen `[DOĞRULANAMADI]`:** RLS + generic plan caching. `current_setting()` STABLE'dır, yürütme başına yeniden değerlendirilir → *doğruluk* korunur. Ama 10 satırlı bir tenant için seçilen generic plan, 10M satırlı tenant için felaket olabilir. **Bu konuda ölçülmüş hiçbir çalışma bulunamadı — kendi iş yükünüzde test edin.**

### 2.7 Citus, tenant başına havuz, PG 17/18

**Citus 12 schema-based sharding** (Tem 2023): `SET citus.enable_schema_based_sharding TO on;`. **Sınırlar:** FK ve join'ler tek şema içinde kalmalı (reference tablolar hariç); **paralel cross-tenant sorgu YOK**; **>10.000 şemada per-process katalog cache belleğinden bozuluyor.** Tek native gürültülü-komşu aracı: `citus_stat_tenants` (Citus 11.3).

**Ölçekte gerçekten ne yapılıyor:**
- **Notion**: 32 instance × 15 mantıksal shard = **480 mantıksal shard**, workspace ID'ye göre; sonra 96 instance × 5 shard, **hâlâ 480**.
- **Figma**: 2020'den beri ~100× büyüme; yatay shard'lı "colo"lar (`UserId`, `FileId`, `OrgID`); ilk yatay shard'lı tablo Eyl 2023, 9 aylık proje.

**İkisi de satır bazlı/tenant-anahtarlı sharding seçti, schema-per-tenant değil.**

**Tenant başına havuz aritmetiği:** PgBouncer havuzları **(user, database)** çiftine göre anahtarlanır; `default_pool_size` havuz başınadır, global değil. 200 tenant DB × 10 = **2.000 potansiyel sunucu bağlantısı**. Kontroller: `max_db_connections`, `max_user_connections`.

AWS matrisi, verbatim:
- Silo: *"Significant effort. (One connection pool per tenant.)"* / *"Less efficient."*
- Bridge/şema: *"Less effort"* ama *"Connection reuse through `SET ROLE` or `SET SCHEMA` **in session pool mode only**."*
- Pool (`tenant_id`): *"**Least effort**"* / *"**Most efficient. (One connection pool for all tenants.)**"*

> **Az takdir edilen can alıcı nokta:** schema-per-tenant'ın "herkese tek havuz" avantajı, transaction-mode pooling'e ihtiyaç duyduğunuz anda **buharlaşır**, çünkü `search_path` oturum durumudur.

**PG 17 (26 Eyl 2024):** vacuum'un yeni bellek yapısı **20× daha az bellek** — §2.3'teki çok-tablolu autovacuum çöküşüyle doğrudan ilgili.

**PG 18 (25 Eyl 2025):**
- *"Improve the locking performance of queries that access many relations"* (Vondra, `c4d5cb71d`) — **çok partition/çok indeks kullanan herkes için en alakalı değişiklik**
- *"Improve the efficiency of planning queries accessing many partitions"*
- `pg_upgrade --swap` — *"can outperform --link, --clone, --copy… especially on clusters with **many relations**"*
- `pg_dump --no-policies` — RLS politikalarını migration'da yönetmek için

**PG 18 sürüm notlarında relcache/catcache backend-başı belleğini veya çok-relation'lı autovacuum zamanlamasını ele alan HİÇBİR madde yok. §2.3 ve §2.4 sınırları 2026'da hâlâ canlı.**

---

## BÖLÜM III — İZOLASYONUN VERİDEN ÖTESİ

### 3.1 Tenant başına imzalama anahtarı — müzakere edilemez

#### Saldırı zinciri (kendi türetmem, birincil kaynaklarla temellendirilmiş)

**Adım 1** — RFC 6749 §2.2, verbatim:
> "The client identifier is **unique to the authorization server**."

Çok kiracılı IdP'de her tenant ayrı bir AS'tir. Yani tenant A ve tenant B'de **aynı `webapp` client_id'si olabilir ve bu spec'e tamamen uygundur.** Keycloak bunu şema düzeyinde yapıyor: `UNIQUE(REALM_ID, CLIENT_ID)`.

**Adım 2** — imzalama anahtarı paylaşımlıysa, tenant A'nın verdiği token tenant B'nin JWKS'iyle de doğrulanır.

**Adım 3** — `aud` kontrolü de **geçer**, çünkü iki tenant'ta da `aud = "webapp"`.

**Adım 4** — Geriye tek savunma kalır: `iss` kontrolü. OIDC Core §3.1.3.7, verbatim:
> "The Issuer Identifier for the OpenID Provider… **MUST exactly match** the value of the `iss` (issuer) Claim."

**Adım 5** — Ve RP'ler bunu yapmaz.

#### Bu teorik değil. İki kez oldu.

**Storm-0558** ([Wiz Research, 21 Tem 2023](https://www.wiz.io/blog/storm-0558-compromised-microsoft-key-enables-authentication-of-countless-micr)):

> "The compromised MSA key was trusted to sign **any** OpenID v2.0 access token for personal accounts and **mixed-audience (multi-tenant or personal account) AAD applications**."
> "**Any token signed by the MSA tenant for an Azure AD account could be deemed valid**, as long as it impersonates a personal account" — çünkü birçok uygulamada issuer doğrulaması yoktu.
> Microsoft'un issuer doğrulama uzantısı hakkında: "This extension is specific to Microsoft and **the responsibility of its implementation rests with the application owner. Therefore, there is a concern that many applications lack this procedure.**"

Microsoft zorunlu doğrulamayı resmî Azure SDK'sına ancak **12 Tem 2023**'te ekledi. (CISA CSRB PDF'i 403 döndü `[DOĞRULANAMADI]`.)

**CVE-2026-23552** (23 Şub 2026, **CVSS 9.1**), Apache Camel Keycloak bileşeni, NVD'den verbatim:

> "The Camel-Keycloak KeycloakSecurityPolicy **does not validate the `iss` (issuer) claim** of JWT tokens against the configured realm. **A token issued by one Keycloak realm is silently accepted by a policy configured for a completely different realm, breaking tenant isolation.**"

> **Yedi ay önce, CVSS 9.1 olarak, tam olarak bu.** Keycloak realm başına ayrı anahtar kullandığı için tam sömürü imza doğrulamasının da gevşek olmasını gerektirir — ama "sessizce kabul edilir" ifadesi, izolasyonun tüketici disiplinine ne kadar bağımlı olduğunu kanıtlıyor.

#### Kim ne yapıyor

| IdP | Anahtar kapsamı | Kanıt |
|---|---|---|
| **Keycloak** | **Realm başına** | *"When a realm is created, a key pair and a self-signed certificate is automatically generated."* Realm başına 2×RSA-2048 + HMAC + AES |
| Auth0 | Tenant başına | — |
| Entra | **Paylaşımlı MSA/kurumsal ayrımı yetersizdi** | Storm-0558 |

#### Rotasyon — Keycloak'ın modeli doğru

> "Keycloak has a **single active key pair** at a time, but can have **several passive keys** as well. The active key pair is used to create new signatures, while the passive key pair can be used to verify previous signatures."
> Tavsiye: *"Consider creating new keys every three to six months and deleting old keys one to two months after you create the new keys. **If a user was inactive in the period between the new keys being added and the old keys being removed, that user will have to re-authenticate.**"*

**Argus kuralları:**
1. Tenant başına **1 aktif + N pasif** anahtar; JWKS her ikisini de yayınlar
2. `kid` **global benzersiz** ve tenant'ı sızdırmayan opak değer (tenant slug'ı `kid`'e KOYMAYIN — enumeration)
3. Rotasyon **tenant başına bağımsız** zamanlanabilir
4. **ES256 varsayılan**; RSA yalnız eski RP uyumu için ve **talep üzerine (lazy) üretilsin** — her tenant için peşinen değil
5. `client_id` **global benzersiz** (Keycloak'ın aksine) → iki bağımsız savunma katmanı

### 3.2 Issuer URL stratejisi — RFC seviyesinde karşılaştırma

#### Kritik spec çelişkisi (kendim doğruladım, verbatim)

**RFC 8414 §3.1** (Haz 2018) — **ARAYA EKLE**:
> "If the issuer identifier value contains a path component, any terminating `/` MUST be removed before **inserting** `/.well-known/` and the well-known URI suffix **between the host component and the path component**."
> Örnek: issuer `https://example.com/issuer1` → `GET /.well-known/oauth-authorization-server/issuer1`
> "Using path components enables supporting multiple issuers per host. **This is required in some multi-tenant hosting configurations.**"

**OIDC Discovery 1.0 §4** — **SONA EKLE**:
> "OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by **concatenating** the string `/.well-known/openid-configuration` **to the Issuer**."
> Örnek: `GET /issuer1/.well-known/openid-configuration`

> **İki spec aynı issuer için FARKLI URL üretir.** Path-based issuer kullanacaksanız **her ikisini de servis etmek zorundasınız**. Bu, path-based'in en sık gözden kaçan maliyetidir.

#### Sertifika aritmetiği (Let's Encrypt, sayfa tarihi 5 Ağu 2026)

Verbatim limitler:
- "Up to **50 certificates** can be issued **per registered domain** every 7 days."
- "Up to **300 new orders** can be created by a single account every 3 hours."
- "A single certificate can include up to **100 identifiers**."

**Sonuçlar:**
- `acme.argus.io` + tenant başına ayrı sertifika → **50. tenant'ta duvara çarparsınız.** Ölümcül.
- **Tek wildcard `*.argus.io` (DNS-01) → sınırsız tenant.** Doğru cevap. (Uyarı: wildcard yalnız tek seviye kapsar.)
- `login.acme.com` custom domain → her tenant kendi kayıtlı domain'i, kendi 50/hafta bütçesi. Ölçeklenir, ama hesap başına 300 sipariş/3 saat ≈ **2.400 yeni custom domain/gün** tavanı.
- **SAN paketleme (100 identifier/sertifika) çok kiracılıkta ÖNERİLMEZ**: tek bir domain doğrulaması düşerse tüm sertifika yenilemesi düşer.

#### Karşılaştırma

| Boyut | Path (`/t/acme`) | **Subdomain (`acme.argus.io`)** | Custom (`login.acme.com`) |
|---|---|---|---|
| Sertifika | Tek sertifika | **Tek wildcard** | Tenant başına ACME |
| DNS işi | Yok | Tek wildcard kaydı | Tenant başına CNAME + doğrulama |
| **Discovery** | **İKİ farklı yol servis edilmeli** | Kök `/.well-known/…` — çelişki yok | Kök — çelişki yok |
| RP kütüphane uyumu | Path'li issuer'da kırılganlık | **Sorunsuz** | Sorunsuz |
| **Tarayıcı origin izolasyonu** | **YOK — aynı origin** | **VAR — çerez/storage/XSS ayrı** | VAR |
| Onboarding gecikmesi | Anında | Anında | Dakikalar (ACME) |
| Kurumsal beklenti | Düşük | Orta | Yüksek |

**Origin izolasyonu argümanı belirleyicidir ve az konuşulur.** CVE-2023-6717 (CVSS 6.0) tam da bunu gösteriyor:

> "This issue may allow **a malicious admin in one realm** or a client with registration access **to target users in different realms or applications**, executing arbitrary JavaScript in their contexts… compromising the confidentiality, integrity, and availability of **the complete KC instance**."

Aynı origin'de servis edilen çok kiracılı UI'ın bedeli budur. **Subdomain, bunu tarayıcının kendi güvenlik modeliyle kapatır.**

#### RFC 9207 — gün-1 zorunlu

RFC 9207 (Mar 2022), verbatim:
> "In authorization responses to the client, including error responses, an authorization server supporting this specification **MUST indicate its identity by including the `iss` parameter** in the response."

Mix-up saldırılarına karşı. **Çok kiracılı IdP'de her tenant ayrı bir AS'tir → `iss` parametresi başlangıçtan itibaren.**

### 3.3 Rate limit, kota, gürültülü komşu

Gerçek ürünlerin tenant başına yayımladıkları:

| Ürün | Limit |
|---|---|
| **Okta** | `/oauth2/v1/authorize` **1200 req/dk/org**; `/api/v1/users/*` **1000 req/dk/org**; `/api/v1/authn` 4/sn/kullanıcı adı. *"The most general scope for a bucket is the entire org."* |
| **Entra External ID** | **20 req/sn/IP/tenant**, **200 req/sn/tenant**. Kayıt 6 tüketir, giriş 4 → `Tokens/sn = 200 / tüketim` |
| **Auth0** | Authentication API "shared, environment-wide global limit at the tenant level"; Enterprise örneği **100 RPS**. Bir IP'den aynı hesaba 20 deneme/dk → sonra 10/dk. Organizations API'si için **sayısal limit yayımlanmamış** `[DOĞRULANAMADI]` |
| **WorkOS** | 6.000 req/60s/API key; SSO authorize 1.000/60s/connection; Directory Sync **4 req/sn/directory** |
| **Frontegg** | `GET /resources/tenants/v1` **30/dk** (Launch); **SSO config yazma 5-10/dk her planda** |

**Postgres tarafında tek native tenant atıf aracı:** `citus_stat_tenants` (Citus 11.3, May 2023) — tenant başına CPU kullanımı ve sorgu sayısı, kayan zaman kovalarında, `citus.stat_tenants_limit` ile top-N.

### 3.4 Tenant başına özelleştirme — kod çalıştırmanın bedeli

Bu sorunun güvenlik cevabı iki CVE'de yazılı:

**CVE-2022-36051** (31 Ağu 2022, CVSS 8.7) — **Zitadel**, verbatim:
> "**Actions**… is a feature, where users with role `ORG_OWNER` are able to create Javascript Code, which is invoked by the system at certain points during the login… **Due to a missing authorization check, Actions were able to grant authorizations for projects that belong to other organizations inside the same Instance.**"

**CVE-2019-10170** (8 May 2020, CVSS 6.6) — Keycloak:
> "the **realm management interface permits a script to be set via the policy**. This flaw allows an attacker with authenticated user and realm management permissions to configure a malicious script to trigger and [execute]"

> **Kural: tenant'ın yazdığı kod ASLA global yazma yetkisi olan bir bağlamda çalışmamalıdır.** Argus'ta tenant özelleştirmesi (claim mapping, akış kararları) tercihen **veri** olmalı (bildirimsel kural motoru), kod değil. Kod gerekiyorsa: WASM sandbox, tenant-scoped capability, ve yazma API'lerine erişim yok.

**Ve bir bonus tuzak — CVE-2026-19608** (18 Ağu 2026, CVSS 5.3), Keycloak:
> "group-based policies using tokens that only contain **group names rather than full paths**. If two groups in different parts of the organization **share the same name**, a user in the unauthorized group can be mistake[nly authorized]"

> **İSİM TABANLI YETKİLENDİRME ÇOK KİRACILIKTA ÇÖKER.** Her zaman tam yol veya opak ID.

### 3.5 Tenant başına denetim logu ve saklama

**Entra ID resmî tablosu** (ms.date 2026-01-06, güncelleme 2026-03-25):

| Rapor | Free | P1 | P2 |
|---|---|---|---|
| Audit logs | 7 gün | **30 gün** | **30 gün** |
| Sign-ins | 7 gün | **30 gün** | **30 gün** |
| Risky sign-ins | 7 gün | 30 gün | 90 gün |

> "You can retain the audit and sign-in activity data for longer than the default retention period **by routing it to an Azure storage account**."
> "Log retention changes **aren't retroactive**."

**Auth0**: plana göre değişir. **Okta**: System Log. **authentik tenancy**: `event_retention` varsayılan 365 gün, tenant başına ayarlanabilir.

> **Argus için ders:** Dünyanın en büyük IdP'si bile denetim logunu IdP içinde **yalnızca 30 gün** tutuyor. Uzun saklama = dışarı akıtma. Argus:
> - IdP içinde kısa sıcak pencere (varsayılan 30-90 gün), **tenant başına ayarlanabilir**
> - **Tenant başına export hedefi** (S3/GCS/webhook/SIEM) gün-1'den
> - Log tablosu `(tenant_id, zaman)` ile **partition'lanmalı** → tenant silme = `DETACH` + `DROP`

---

## BÖLÜM IV — HİYERARŞİ VE KULLANICI KİMLİĞİ

### 4.1 Düz mü ağaç mı — piyasa oy verdi: DÜZ

| Ürün | İç içe? | Kanıt |
|---|---|---|
| Zitadel | **Hayır** | "orgs are **flat by design**"; "pls keep your hierarchy flat" |
| Auth0 | **Hayır** | Personel, 13 Tem 2022: "**Auth0 does not currently support sub-organizations**" |
| Okta | **Hayır** | "Orgs are hard boundaries" |
| Entra AU | **Hayır** | "**Administrative units can't be nested**" |
| WorkOS | **Hayır** | `parent_organization_id` alanı yok |
| Keycloak | Org düz; **26.6.0'dan beri org İÇİNDE hiyerarşik gruplar** | [keycloak.org/2026/04/org-groups](https://www.keycloak.org/2026/04/org-groups) |
| **Frontegg** | **Evet** | Belgeli derinlik sınırı yok `[DOĞRULANAMADI]` |
| AWS Organizations | Evet | **Kök altında 5 seviye sert sınır** |

**Hiyerarşiyi yapanların ödediği bedel — iki yönden aynı ders:**

- **Frontegg**: miras JWT'ye ulaşmıyor → her yetki kararı API çağrısı
- **AWS Organizations**: OU başına max 10 SCP × 5 seviye = bir hesabın *etkin* politikası, kimsenin ona iliştirmediği ~50 belgenin kesişimi. Ve verbatim: *"Policies that affect an OU or account **by inheritance do not count against these limits**."* Hata kodları `OU_DEPTH_LIMIT_EXCEEDED` bir sebeple var.
- **SpiceDB**: *"By default, this limit is **50 hops**."* Amaca özel ReBAC motoru bile derinliği sınırlıyor.
- **Zanzibar** (USENIX ATC '19): trilyonlarca ACL, milyonlarca istek/sn, **p95 <10 ms** — ama bu Google'ın ölçeğinde amaca özel inşa edilmiş bir sistem.

> **Kopyalanacak kalıp: DÜZ tenant'lar + tenant İÇİNDE hiyerarşik gruplar.** Hiyerarşi yetkilendirme katmanında kalır, kimlik doğrulama/tenant-çözümleme sıcak yolundan çıkar. Keycloak 26.6.0 tam olarak buraya vardı. Geçişli miras gerekirse bu bir ReBAC problemidir (OpenFGA/SpiceDB), tenant modeli problemi değil.

Postgres tarafında ağaç sorgu maliyeti **bağlayıcı kısıt değildir** — tenant ağaçları küçük ve sığdır. Bağlayıcı kısıtlar: (a) taşıma/yeniden-ebeveynlemede yazma amplifikasyonu, (b) ltree'de uygulama-sorumlu yol bütünlüğü, (c) mirasın semantik belirsizliği — hiçbir indeks bunu düzeltmez.

### 4.2 Kullanıcı kimliği — iki okul ve ayırt edici soru

**Ayırt edici soru: IdP her tenant için kimlik bilgisini (credential) sahiplenıyor mu?**

| Ürün | Benzersizlik kapsamı | Aynı e-posta iki tenant'ta |
|---|---|---|
| **Okul A — global kullanıcı + üyelik** | | |
| WorkOS | **Environment** | Tek kullanıcı, N üyelik. **OTOMATİK BİRLEŞTİRME.** |
| Auth0 | **Connection** | Connection paylaşımlıysa tek kullanıcı |
| Keycloak (realm içi) | Realm | Tek realm kullanıcısı + N org üyeliği; **tam bir "managed" üyelik** |
| Logto | Logto tenant'ı | Tek kullanıcı, N org |
| Frontegg | Environment | Her zaman tek; **bölme yolu yok** `[DOĞRULANAMADI]` |
| **Okul B — tenant-yerel gölge nesne** | | |
| Zitadel | **Org** (dize kurgusuyla) | İki ayrı kullanıcı. **Taşınamaz.** |
| Okta | **Org** | İki ayrı kullanıcı |
| Entra | **Tenant** | İki ayrı nesne; `oid`/`sub` tasarımca farklı |
| **Stytch** | **Organization** | **İki ayrı Member** |
| SuperTokens | `appId→tenantId→email` | Varsayılan iki; opt-in paylaşım |

**Entra B2B, Okul B'nin referans uygulaması ve en çok düşünülmüş hâli:**

- Nesne davetle yaratılır, kullanım öncesi: *"This account **doesn't have any credentials** associated with it because authentication is performed by the guest user's identity provider."*
- Çakışmayı yapısal olarak imkânsız kılan UPN kurgusu: `john@contoso.com` → **`john_contoso.com#EXT#@fabrikam.onmicrosoft.com`**
- `UserType` ∈ {Member, Guest} = *host ile ilişki*, nasıl giriş yaptığından bağımsız: *"The UserType has **no relation to how the user signs in**."*
- `identities` özelliği ana kiracıya işaretçi: `ExternalAzureAD`, `google.com`, `mail`, veya SAML issuer URI'si
- Keskin operasyonel kenar: *"If a guest user… later changes their email address, the new email **doesn't automatically sync**."*

**Ve Keycloak'ın en temiz formülasyonu** ([#30747](https://github.com/keycloak/keycloak/issues/30747)):
> "members can have only **one managed membership**"

Yani: **çok üyelik, ama tam bir tanesi kullanıcının yaşam döngüsünü sahiplenir.** Bu, saf many-to-many'nin bıraktığı "bu kullanıcıyı kim silebilir / parolasını kim sıfırlayabilir" belirsizliğini çözer.

### 4.3 E-posta ile kimlik — üç bağımsız ihlal

**1. nOAuth** (Descope, açıklama 20 Haz 2023): saldırgan **kendi** Entra kiracısında admin, hesabının e-posta alanını kurbanınkiyle değiştirir (doğrulama yok), "Log in with Microsoft" der. E-postayla eşleştirip birleştiren uygulama → **tam hesap devralma. Kurbanın Microsoft hesabı olmasına bile gerek yok.** Entra'nın `email` claim'i hem değiştirilebilir hem doğrulanmamış. Azaltımlar: `xms_edov`, `RemoveUnverifiedEmailClaim`.

**İki yıl sonra hâlâ canlı** (Semperis, 26 Haz 2025): test edilen 104 Entra App Gallery uygulamasının **9'u (%9) savunmasız.**

**2. Entra domain takeover.** Kullanıcı bir bulut servisine kaydolunca *"they're added to an unmanaged Microsoft Entra directory **based on their email domain**"* — "viral"/"gölge" tenant. Sonra: DNS TXT ile ownership kanıtı → **external admin takeover**: *"Microsoft Entra ID **removes the domain name from the unmanaged organization and moves it to your existing organization**"*, kullanıcıları/abonelikleri/lisansları taşıyarak. `forceTakeover = true`; yönetilmeyen org **10 gün sonra silinir**.

**3. Truffle Security, 13 Oca 2025** — en önemlisi, çünkü **domain doğrulamasının kendisini yeniyor**: başarısız bir startup'ın süresi dolmuş domain'ini satın al, kendi Workspace'inde `user@faileddomain.com`'u yeniden yarat, `hd` + `email` ile eşleştiren SaaS'lara gir. Uygulama *"cannot distinguish between the original company owners and the new domain purchaser."* **>100.000 uygun domain** tespit edildi.

> **DNS sahipliği bir gerçek değil, bir kiralamadır.** Doğrulanmış domain'e dayanan her tenant yönlendirme kuralı, o domain'in süre bitim riskini miras alır.

**Ürünlerin savunmaları:**
- **Clerk**: *"A Verified Domain cannot be a disposable domain or common email provider. For example, you cannot create a Verified Domain for @gmail.com"*
- **Stytch**: *"Common domains such as `gmail.com` are not allowed"*; ve anti-phishing koruması: e-posta-domain JIT için *"there must already be at least one Member in the Organization **with a verified email address with the same email domain**"* — bir domain'in ilk kullanıcısı mevcut bir org'a kendini sokamaz
- **WorkOS**: *"Only one organization can include a specific domain… per environment"*

### 4.4 Politika çakışması — sadece Entra tam cevap veriyor

Üç tutarlı strateji var:

1. **Tasarımla yok et** (Zitadel, Okta, Entra B2B): bir kullanıcı bir tenant'a ait → çakışma yok.
2. **Oturumu tenant'a kapsa** (Stytch, WorkOS, Auth0 org login, Keycloak org-context token): bağlayıcı politika **hedef** org'unkidir, o org'a giriş yaparken değerlendirilir. Org değiştirmek yeni bir kimlik doğrulamadır. **Okul A için doğru model budur.**
3. **Güven ve federe et** (Entra CA + cross-tenant trust): kaynak tenant'ın politikası her zaman geçerli; ana tenant'ın sağladığı faktörler **yalnızca inbound trust yapılandırılmışsa** kanıt olarak kabul edilir. Varsayılan: güven yok.

**Entra'nın ilkesi, verbatim ve aynen benimsenmeli:**
> "**MFA is completed at resource tenancy to ensure predictability.**"

Entra'nın asimetrik metot tablosu gerçek bir tuzak: **ana** tenant'ta kabul edilenler FIDO2, Windows Hello, sertifika; **kaynak** tenant'ta kabul edilenler yalnızca SMS, sesli arama, Authenticator push, OATH software. → **MFA güvenini kapatırsanız, phishing-resistant-only bir politika harici kullanıcı tarafından hiç sağlanamaz.**

> **Kaçınılacak dördüncü, söylenmemiş seçenek: tek global oturum + politikaların birleşimi.** Kullanıcının tek oturumu varsa ve tenant A passkey istiyorsa, tenant B'nin zayıf politikasıyla kurulan bir oturum tenant A erişimi vermemelidir. Pratikte: org-kapsamlı access token yalnızca o org'un politikası mevcut oturumda sağlandığında verilebilir → org değişiminde step-up, `amr`/`acr`'de gerçekten sağlananın kaydı.

---

## BÖLÜM V — GÜVENLİK: CROSS-TENANT SIZINTI

### 5.1 Doğrulanmış cross-tenant sınır ihlalleri

NVD API'sinden doğrudan çektim (`keywordSearch=keycloak`, 296 sonuç tarandı, sınır aşımı belirtilenler):

| CVE | Tarih | CVSS | Ne oldu |
|---|---|---|---|
| **CVE-2026-23552** | 2026-02-23 | **9.1** | Camel-Keycloak `iss` doğrulamıyor → **bir realm'in token'ı başka realm'in politikasınca sessizce kabul ediliyor** |
| **CVE-2022-36051** | 2022-08-31 | **8.7** | **Zitadel Actions** (tenant JS kodu) **başka organizasyonların projelerine yetki verebiliyordu** |
| **CVE-2019-14832** | 2019-10-15 | **7.5** | Keycloak REST API *"would permit user access from a realm the user was not configured"* — **unutulmuş `AND realm_id = ?`** |
| **CVE-2026-41166** | 2026-04-22 | 7.0 | OpenRemote: *"uses the `{realm}` path segment… but **does not check that the caller may administer that realm**"* → master admin'e yükselme |
| **CVE-2026-18215** | 2026-07-31 | 6.8 | Keycloak: Microsoft org kısıtı **token exchange'de yok sayılıyor** → başka org'un token'ıyla realm'e erişim |
| **CVE-2023-6717** | 2024-04-25 | 6.0 | *"a malicious admin in one realm… to target users in **different realms**"* — aynı origin XSS |
| **CVE-2020-1697** | 2020-02-10 | 6.1 | *"trick users in other realms"* — admin console stored XSS |

**Bunlardan üçü Argus'un mimarisini doğrudan belirliyor:**

- **CVE-2019-14832** → FK'sız discriminator kolonunun kaçınılmaz sonucu. **RLS savunma derinliği olarak zorunlu.**
- **CVE-2026-41166** → çok kiracılı API'nin kanonik hatası: tenant'ı yol parametresinden al, yetkiyi kontrol etme. **Tip sisteminde çözülmesi gereken tam olarak bu.**
- **CVE-2022-36051** → tenant kodu global yazma bağlamında çalışmamalı.

**Ayrıca — bulut izolasyon araştırması bağlamı:** Wiz/Orca serisi (ChaosDB, ExtraReplica — Azure PostgreSQL Flexible Server cross-tenant, BingBang), Okta destek sistemi ihlalleri (Eki 2023, Oca 2022), Storm-0558. Bu vakaların ayrıntılı teknik dökümü için ayrılan araştırma akışı bu raporun yazımı sırasında tamamlanmadı; yukarıdakiler **kendi birincil-kaynak doğrulamalarımdır.** Asana MCP olayı ve Wiz serisinin tam teknik ayrıntısı bu raporda **`[DOĞRULANAMADI]`** — talep ederseniz ayrıca çıkarabilirim.

### 5.2 RLS savunma derinliği olarak — ne kadar etkili?

**Etkili, ama yalnızca beş kuralın hepsi uygulanırsa.** Logto'nun deneyimi bunun bedelini gösteriyor — ve kanıt depoda:

`packages/schemas/tables/_after_each.sql`, **her tabloya** uygulanıyor:
```sql
create trigger set_tenant_id before insert on ${name} for each row execute procedure set_tenant_id();
alter table ${name} enable row level security;
create policy ${name}_tenant_id on ${name} as restrictive
  using (tenant_id = (select id from tenants where db_user = current_user));
```
`_before_all.sql`: `create role logto_tenant_${database} password '${password}' noinherit;`
`_after_all.sql`: `tenants` tablosu kendini koruyor — `revoke all… grant select (id, db_user, is_suspended, tag)`.

**Ödedikleri bedel, birincil kaynaklardan:**

- **[PR #7596](https://github.com/logto-io/logto/pull/7596)** (29 Tem 2025): tek kolonlu FK'lar *"assign users from other tenants to an organization"*'a izin veriyordu; RLS sonra okumayı engelleyip **500 hatası** üretiyordu. Düzeltme: `(tenant_id, user_id)` composite FK'lar.
  > **RLS + tenant_id, şemadaki HER FK'yı composite yapmaya zorlar.**
- **[Issue #7685](https://github.com/logto-io/logto/issues/7685)** (14 Ağu 2025), verbatim: **"Row-level security has to be enforced on EVERY business table when starting Logto"** — ~60+ tablo eksik tespit edildi.
  > **RLS değişmezi ya-hep-ya-hiçtir ve bootstrap sırasını hassas hale getirir.**

### 5.3 Cross-tenant sızıntıyı sistematik test etmek

Bu alanda yayımlanmış olgun bir metodoloji **bulunamadı** `[DOĞRULANAMADI]`. Aşağıdakiler kanıtlanmış hata sınıflarından türetilmiş, Argus'a özgü önerilerdir:

**1. Şema değişmezi CI kontrolü** (Logto'nun #7685'te öğrendiği ders):
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

**2. İkiz-tenant diferansiyel testi.** Tüm entegrasyon test paketini iki tenant için **aynı verilerle** çalıştır, sonra assert et: A'nın herhangi bir sorgusunun döndürdüğü satır kümesi ∩ B'nin verisi = ∅. Bu, CVE-2019-14832 sınıfını (unutulmuş yüklem) yakalar.

**3. Property-based (proptest) değişmez.** Rastgele tenant/kullanıcı/client grafiği üret; değişmez: *hiçbir API çağrısı, çağıranın tenant'ı dışındaki bir `tenant_id`'ye ait satır döndürmez.* Özellikle **yol parametresi tenant'ı ≠ token tenant'ı** kombinasyonlarını üret — CVE-2026-41166 sınıfı.

**4. Token confusion fuzzer'ı.** Tenant A'nın token'ını tenant B'nin her endpoint'ine gönder. Beklenen: 401/403, **hiçbir zaman 200**. Storm-0558 / CVE-2026-23552 sınıfı.

**5. Gizli kanal testi.** Tenant A'da var olan bir e-postayla tenant B'de kayıt dene → **unique violation ASLA sızmamalı.** PG dokümanının "covert channel" uyarısının doğrudan testi.

**6. Negatif GUC testi.** `argus.tenant_id` set edilmemişken her sorgunun **sıfır satır** döndürdüğünü assert et (fail-closed), tüm satırları değil.

---

## BÖLÜM VI — RUST'A ÖZGÜ

### 6.1 Ambient context TEHLİKELİDİR — doğrulanmış

`tokio::task_local!` cazip görünüyor. İki nedenle reddedin:

**1. `spawn`'a miras kalmaz.** Task-local veri `tokio::spawn` çağrılarına propagate **edilmez** (thread-local davranışıyla aynı) — [tokio#2396](https://github.com/tokio-rs/tokio/issues/2396), [discussion #4317](https://github.com/tokio-rs/tokio/discussions/4317). Geçici çözüm crate'i var (`tokio-inherit-task-local`) ama *"This does not inherit values created by `tokio::task_local`."*

> **Sonuç: arka plan işine spawn ettiğiniz an tenant bağlamı SESSİZCE kaybolur.**

**2. Erişim panic eder.** `LocalKey::with()` ve `get()`: *"This function panics if the task local doesn't have a value set."* Bir IdP'de bu bir DoS'tur.

### 6.2 Tenant'ı tip sisteminde kodlamak — mümkün, ve kimse yapmamış

**Mekanizma olgun ve yaygın:**

| Crate | Sürüm | İndirme | Son güncelleme |
|---|---|---|---|
| `generativity` | 1.2.1 | **3.991.685** | 2026-04-26 |
| `qcell` | 0.5.5 | 469.916 | 2025-09-17 |
| `ghost-cell` | 0.2.6 | 119.002 | 2024-01-28 |
| `indexing` (bluss) | 0.4.1 | 64.816 | **2019 — ölü** |

Teknik temel: **GhostCell** (Yanovski et al., ICFP 2021, PACMPL, [doi:10.1145/3473597](https://dl.acm.org/doi/10.1145/3473597)) — *"branded types (as exemplified by Haskell's ST monad), which combine phantom types and rank-2 polymorphism."* Sağlamlığı RustBelt ile Coq'ta **formel kanıtlanmış**.

`generativity` dokümanı: `Guard` ve `Id` lifetime parametresinde **invariant**; *"it is never valid to substitute or otherwise coerce `Id<'a>` into `Id<'b>`, for any concrete `'a` and `'b`, including `'static`."*

**Çok kiracılığa uygulanmış yayımlanmış bir örnek BULUNAMADI.** Aradım; yok. Bu geçerli bir bulgudur: **Argus bunu yapan ilk sistem olur.**

### 6.3 Önerilen Rust kalıbı — üç katman

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

Kullanım:

```rust
generativity::make_guard!(guard);              // taze, benzersiz 'brand
let mut tx = TenantTx::begin(&pool, tenant_a, guard).await?;
let user = tx.find_user(uid).await?;

generativity::make_guard!(guard2);
let mut tx_b = TenantTx::begin(&pool, tenant_b, guard2).await?;

// tx_b.delete_user(user);
// ^^^ DERLEME HATASI: lifetime mismatch. 'brand'lar birleşmez.
```

**Ne kazanır, ne kazanmaz — dürüstçe:**

| Kazanır | Kazanmaz |
|---|---|
| A tenant'ından okunan bir varlığı B tenant'ının yazma yoluna sokmak = derleme hatası | Yanlış tenant'ı `begin()`'e vermeyi engellemez (bu Katman 4'ün işi) |
| Kapsamsız (tenant'sız) sorgu yazmak = tip yok, imkânsız | Ham SQL'de `AND tenant_id = ?` unutmayı engellemez → **RLS bunun içindir** |
| GUC'un transaction içinde set edildiğini yapısal garanti eder | — |

#### Katman 4 — istek sınırında tenant çözümlemesi (Axum)

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

#### Havuz seviyesi fail-safe

`sqlx::PoolOptions` hook'ları ([docs.rs](https://docs.rs/sqlx/latest/sqlx/pool/struct.PoolOptions.html)) — `after_release` `Ok(false)`/`Err` dönerse bağlantı **kapatılır**:

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

## BÖLÜM VII — ARGUS İÇİN ÖNERİ

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

**Politika yazım kuralı (Supabase ölçümü, §2.6): fonksiyonu her zaman `(SELECT …)` ile sarın** — InitPlan kurar, satır başına değil sorgu başına bir kez değerlendirir. Fark 178.000 ms → 12 ms.

### 7.2 GÜN-1'DE KURULMALI — sonradan imkânsız

| # | Madde | Sonradan neden imkânsız | Kanıt |
|---|---|---|---|
| 1 | **`tenant_id` her tabloda VE her birincil anahtarda** | Tüm PK'ları düşürüp yeniden kurmak = dünya-durduran migration | SuperTokens: 33 tablo, tüm PK'lar CASCADE, offline migration |
| 2 | **Her FK composite (`tenant_id` dahil)** | Tek kolonlu FK'lar çapraz-tenant referansa izin verir; RLS sonra okumayı bozar | Logto PR #7596 |
| 3 | **RLS + FORCE + non-owner rol, tüm tablolarda** | Sonradan eklemek "ya hep ya hiç"; eksik tablo = sessiz sızıntı | Logto #7685: "EVERY business table" |
| 4 | **Tenant başına imzalama anahtarı** | Paylaşımlıdan tenant başınaya geçiş = tüm RP'lerin JWKS cache'ini invalidasyonu + koordineli kesinti | Storm-0558; CVE-2026-23552 |
| 5 | **`client_id` global benzersiz** | Sonradan globalleştirmek = müşteri client_id'lerini yeniden adlandırmak = her RP config'i kırılır | RFC 6749 §2.2 |
| 6 | **Kullanıcı benzersizliği tenant-yerel** | Global→tenant-yerel geçiş veri migration'ı + güvenlik incelemesi; tersi imkânsız | Zitadel: "not possible to move users between organizations" |
| 7 | **Değişmez tenant slug'ı** | Slug issuer URL'inde → değişirse her RP'nin discovery'si kırılır | Keycloak: "alias cannot be changed afterwards" |
| 8 | **Issuer stratejisi + RFC 9207 `iss`** | Issuer değişimi = tüm RP yeniden yapılandırması | RFC 8414/OIDC Discovery çelişkisi |
| 9 | **`placement_id` silo kaçış kolonu** | Yoksa düzenlemeye tabi bir tenant'ı ayrı kümeye taşımak mimari yeniden yazımdır | AWS: silo/pool/bridge |
| 10 | **Denetim logu tenant+zaman partition'lı** | Milyarlarca satırlı tabloyu sonradan partition'lamak pratikte imkânsız | GDPR Art.17 |
| 11 | **İsim tabanlı değil, opak-ID/tam-yol tabanlı yetkilendirme** | Token'da isim taşıyan her şey yeniden yazılır | CVE-2026-19608 |
| 12 | **Token exchange'de tenant kısıtı** | Ayrıcalıklı yol; sonradan eklenirse mevcut entegrasyonlar kırılır | CVE-2026-18215 |
| 13 | **Rate limit / kota boyutu şemada** | Sonradan tenant boyutu eklemek tüm sayaç durumunu geçersiz kılar | Okta/Entra org başına limitler |
| 14 | **Tip sisteminde tenant (branded scope)** | Sonradan retrofit = her sorgu yolunu elden geçirmek | CVE-2019-14832 |

### 7.3 Sonradan eklenebilir (gün-1'de gerek yok)

Custom domain / ACME otomasyonu · Tenant başına tema · Org içi grup hiyerarşisi · SCIM · Tenant başına politika motoru · Citus'a geçiş (`tenant_id` zaten shard key) · Cell/hücre mimarisi (`placement_id` yolu açık bırakıyor)

### 7.4 Reddedilen alternatifler ve gerekçeleri

| Alternatif | Neden hayır |
|---|---|
| **Schema-per-tenant** | 1.200 tenant'ta 383 ms katalog taraması, 2 saat migration; `search_path` pooling'i kırılganlaştırır; sqlx dinamik şema migration'ı vermez |
| **Database-per-tenant** | ~50 tenant tavanı; havuz çarpımı; küme-geneli XID/OID baskısı |
| **Realm-benzeri ağır tenant** | Keycloak 200-500 tavanı, master realm O(N), sabit global cache — kanıtlanmış çıkmaz |
| **Global kullanıcı + e-posta birleştirme** | nOAuth, Entra takeover, Truffle defunct-domain — üç bağımsız ihlal |
| **Paylaşımlı imzalama anahtarı** | Storm-0558; CVE-2026-23552 (CVSS 9.1) |
| **İç içe tenant (ağaç)** | Zitadel/Auth0/Okta/Entra/WorkOS reddetti; Frontegg yaptı, miras JWT'ye sığmıyor |
| **`task_local` ile ambient tenant** | `spawn`'a miras kalmaz + erişimde panic |
| **RSA varsayılan** | 130× keygen maliyeti tenant-başına-anahtarı ekonomik olarak imkânsız kılar |

---

## BÖLÜM VIII — DOĞRULANAMAYANLAR

Bunları **asla gerçek olarak sunmayın**:

- **Wiz bulut izolasyon serisinin (ExtraReplica, ChaosDB, BingBang) teknik ayrıntısı ve Asana MCP olayı** — bu konulara ayrılan araştırma akışı rapor yazımı sırasında tamamlanmadı
- **Tenant başına anahtar/JWKS ve rate-limit konularının ayrıntılı vendor karşılaştırması** — aynı sebeple kısmi; yukarıdakiler kendi birincil doğrulamalarım
- CISA CSRB Storm-0558 raporu (PDF 403 döndü)
- CYBERTEC *"Too many tables are bad for you"* — site 403; `CacheMemoryContext` rakamları doğrulanmadı
- CVE-2025-8713 — arama özetlerinde göründü, postgresql.org güvenlik listesinde doğrulanamadı
- Keycloak Jira KEYCLOAK-4593 ve diğerleri — tracker artık herkese açık değil; yalnızca tanımlayıcı olarak anıldı
- Realm başına heap-byte rakamı — yetkili kaynak yok
- Auth0 Organizations API rate limit sayıları; Auth0 org metadata limitleri
- Frontegg maksimum hiyerarşi derinliği; entitlement mirası
- Okta hücre başına org sayısı; org başına maksimum kullanıcı/uygulama
- RLS + generic plan caching'in tenant'lar arası yanlış plan seçimi — ölçülmüş hiçbir çalışma yok
- N-tenant × M-havuz dağıtımının ölçülmüş kamuya açık hesabı — literatürün en zayıf noktası; prototip gerektirir
- "2.000 şema × 50 tablo'da katalog taramaları DDL'i yavaşlatır" — yalnızca AI üretimi blog içeriğine dayanıyor, **kullanmayın**
- AWS SaaS whitepaper'ının silo/pool/bridge tanımları — birinci sayfa doğrulandı, alt sayfa fetch'i başarısız

---

### Bir cümlelik kapanış

Argus'un çok kiracılığı **satır bazlı, RLS destekli, tenant'ı hem birincil anahtarda hem Rust tip sisteminde taşıyan, tenant başına imzalama anahtarı olan, subdomain issuer kullanan, düz tenant listeli** olmalı — ve bu kararların on dördü gün-1'de verilmeli, çünkü piyasadaki her IdP bunlardan en az birini erteledi ve Keycloak on yıl, Zitadel bir depolama katmanı yeniden yazımı, SuperTokens dünya-durduran bir migration, Kanidm ise özelliği tamamen reddetmekle ödedi.
