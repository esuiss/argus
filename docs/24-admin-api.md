# 24. Admin API ve delege yönetim

> `ARGUS.md` §24'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§24 §X` referansları aynı anlamda.


**Yöntem:** ~45 arama/fetch (2 alt-ajan dahil). Birincil kaynaklar önceliklendirildi.

---

## 1. Mevcut IdP'lerin Admin API Tasarımı

### 1.1 Keycloak Admin REST API — kendi maintainer'ının itiraf listesi

En değerli bulgu: Keycloak'ın core maintainer'ı **@stianst**, mevcut Admin API v1'in tasarım hatalarını [Discussion #37655](https://github.com/keycloak/keycloak/discussions/37655)'te (26 Şubat 2025) tek tek listelemiş. Bu bir blog eleştirisi değil, ürünün sahibinin pişmanlık listesi:

| Sorun | stianst'in kendi ifadesi (26 Şub 2025) |
|---|---|
| Versiyonlama yok | *"Lack of versioning — this will be a must as we introduce a v2, and to solve known usability issues it will have to be a breaking change requiring a new major API version."* |
| Verb semantiği tutarsız | *"POST sometimes work as a PUT, and sometimes as a PATCH, depends randomly on the endpoint."* |
| OpenAPI kalitesiz | *"Bad quality OpenAPI specification — these are incomplete, and usually not sufficient to generate clients."* |
| Create yanıtı boş | *"Creating new resources like a realm returns an empty response, with the ID in the location header — this is very inconvenient to use as it requires separating parsing of location headers."* |
| Validation yok | *"Lack of validation — there's very little validation in Admin APIs today, often leading to issues later on."* |
| Default şişmesi | *"I create a client with a couple fields, and get back a client with 50 fields."* |
| ID ile lookup zorunlu | *"Not able to use user defined IDs when looking up resources; for example clients are looked up on UUID, and not on clientId."* |

Ek olarak (19 Mart 2025, stianst): **null ayarlanamıyor** — *"We don't know if `RealmRepresentation#displayName=null` means it was just not set, or if it was explicitly set to null."* Bu, JSON Merge Patch kullanılmamasının doğrudan sonucu.

Topluluk katkıları:
- **Pagination performansı** (17 Tem 2025, @Plasmadog): *"Skip/Take approach is not performant… when paging through all users, there is a very real possibility that a new user registers before finished. Since results are ordered by user Id, and user Ids are not sequential, that user can be skipped."* → offset pagination'da **kayıt kaçırma** (kayıp okuma) problemi.
- **N+1 sorgu** (12 Tem 2025, @schuerg): kullanıcı + rol + grup çekmek için `1 + n + n` istek.
- **Toplu silme yok** (27 Kas 2025, @jesperronn): milyonlarca hesap için doğrudan DB sorgusu gibi tehlikeli workaround'lara zorluyor.

### 1.2 Keycloak'ın kendi REST API kılavuzu (yazılı ama uygulanmamış)

[keycloak-community/design/rest-api-guideline.md](https://github.com/keycloak/keycloak-community/blob/main/design/rest-api-guideline.md) — dikkat çekici: Keycloak'ın **yazılı bir API tasarım kılavuzu var** ve v1 bu kılavuza uymuyor. Kılavuzun kuralları:

- Versiyonlama path'te: `/{realm}/apis/{API_GROUP}/{version}`. Versiyon **Keycloak sürüm numarasına bağlı değil** — API'nin kararlılık durumunu ifade ediyor.
- Pagination: `first` + `max` query param, yanıtta **RFC 5988 `Link` header** (next/prev).
- Hata gövdesi: `error` (zorunlu, snake_case kod) + `error_description` (opsiyonel).
- PATCH: **RFC 7396 JSON Merge Patch**, `Content-Type` ile ayrışıyor, başarıda `204 No Content`.
- Kaynak isimleri: store resource → çoğul isim; controller resource → fiil (camelCase).
- OpenAPI hakkında **hiçbir kural yok** (kılavuzun kendi boşluğu).

### 1.3 Admin API v2 — fiilen ne çıktı

[Issue #39220](https://github.com/keycloak/keycloak/issues/39220) (25 Nis 2025) "Admin API v2" epic'i **"closed as not planned"** olarak kapanmış. Ama iş ölmedi, kapsam daraltıldı: **Client Admin API v2** Keycloak **26.7.0**'da (Temmuz 2026) deneysel olarak çıktı ([26.7.0 release notes](https://www.keycloak.org/2026/07/keycloak-2670-released), [Discussion #50186](https://github.com/keycloak/keycloak/discussions/50186)).

Somut tasarımı ([admin-api-v2 reference](https://www.keycloak.org/admin-api/admin-api-v2)):

```
/admin/api/{realmName}/clients/v2
```

**Versiyon path'in SONUNDA, kaynak başına.** Yani API global olarak versiyonlanmıyor — her kaynak kendi hızında v2'ye geçiyor. Bu, big-bang v2 migrasyonundan kaçınmanın somut yolu.

- `POST` → 201 + **tam temsil gövdede** (v1'in Location-header sorunu düzeltilmiş)
- `PUT` → upsert: yaratıldıysa 201, güncellendiyse 200 (idempotent)
- `PATCH` → `application/merge-patch+json` (RFC 7396), 200
- Pagination: `offset` (0-tabanlı, default 0) + `limit` (default 100)
- Feature flag: `--features=client-admin-api:v2`
- Keycloak Operator bu API'yi `KeycloakOIDCClient` / `KeycloakSAMLClient` CRD'leri için kullanıyor

**Sorgulama dili** ([querying guide](https://www.keycloak.org/admin-api/querying)) — bu çok önemli: Keycloak, **SCIM filter syntax'ının (RFC 7644 §3.4.2.2) bir alt kümesini** seçmiş, kendi DSL'ini icat etmemiş:

```
GET /admin/api/{realm}/clients/v2?q=clientId eq "my-app" and enabled eq true&fields=clientId,displayName
```

- Operatörler: `eq`, `ne`, `co`, `sw`, `ew`, `pr` + `and`/`or`/`not` + parantez
- `gt`/`ge`/`lt`/`le` **desteklenmiyor** (bilinçli kısıtlama)
- `fields=` ile projection
- **Bilinmeyen alan → HTTP 400** (SCIM'in "sessizce yoksay" davranışının aksine — bu daha iyi bir karar)
- ⚠️ Dokümanda sıralama (sort) ve cursor pagination'a dair açıklama yok

### 1.4 Admin API'nin kendi kimlik doğrulaması — Keycloak'ın merkezîlik problemi

[admin-rest-api.adoc](https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_development/topics/admin-rest-api.adoc) (main branch):

```bash
curl -d "client_id=admin-cli" -d "username=admin" -d "password=password" \
     -d "grant_type=password" \
     http://localhost:8080/realms/master/protocol/openid-connect/token
```

- Varsayılan `admin-cli` client'ı, **direct access grant** (ROPC) ile
- **Token varsayılan olarak 1 dakika yaşıyor**
- Service account alternatifi: master realm'de client + `admin` realm rolü + `client_credentials`
- **Kritik:** *"The access token must come from the master realm regardless of which realm you're administering."*

Bu son madde Keycloak'ın merkezî zayıflığı: **master realm bir tek-arıza-noktası ve tek-ele-geçirme-noktası.** Realm-per-tenant modelinde tenant admin'i yönetmek için ya master realm'de hesap açacaksın (cross-tenant risk) ya da `realm-management` client rollerine düşeceksin.

### 1.5 Okta Management API — rate limit mimarisi

Okta'nın modeli üç bağımsız katmandan oluşuyor ve bu ayrım Argus için doğrudan kopyalanabilir:

**(a) Bucket tabanlı zaman-penceresi limitleri** ([rl2-monitor](https://developer.okta.com/docs/reference/rl2-monitor/)):
- "Rate limiting bucket" = bir kota paylaşan bir veya daha fazla endpoint kümesi
- Bucket eşleşmesi **HTTP method + en-uzun-önek** ile: `/api/v1/users*` gibi wildcard bucket'lar tam eşleşme yoksa devreye giriyor
- Header'lar: `X-Rate-Limit-Limit`, `X-Rate-Limit-Remaining`, `X-Rate-Limit-Reset` (UTC epoch saniye)

**(b) Eşzamanlılık (concurrency) limiti** — zaman penceresinden tamamen ayrı ([rl2-concurrency](https://developer.okta.com/docs/reference/rl2-concurrency/)):
- *"Concurrency limits control how many requests your org can have processing at the same time—not over time, and not per second or minute."*
- Workforce & Customer Identity org: **75 eşzamanlı transaction**
- Integrator Free plan: **35**
- Microsoft Office 365 trafiği **ayrı sayılıyor**, aynı varsayılanlarla
- Aşımda: HTTP 429 + System Log'da `core.concurrency.org.limit.violation`
- Concurrency ihlalinde `X-Rate-Limit-Limit` ve `-Remaining` **0** dönüyor, `-Reset` sadece **tahmini** bir değer

**(c) Kullanıcı/endpoint bazlı koruma** ([rl-global-mgmt](https://developer.okta.com/docs/reference/rl-global-mgmt/)):
- Admin Console + End-User Dashboard: **kullanıcı başına endpoint başına 10 saniyede 40 istek** — bir kullanıcının diğerlerini boğmasını engelliyor
- Identity Engine: kullanıcı başına 5 saniyede 20 istek; **state token başına 5 saniyede 10 istek**
- `/api/v1/authn` ve `/oauth2/v1/token`: kullanıcı başına saniyede 4 istek

**(d) Rate Limit Dashboard** — bir ürün özelliği olarak gözlemlenebilirlik (Reports → Rate Limits):
- Bucket başına: mevcut limit yüzdesi, 24 saatlik ve son 1 saatlik ortalama kullanım, etki süresi
- **Top offenders**: IP adresi / API token / OAuth 2.0 app kırılımıyla ilk 10 tüketici
- 4 System Log event tipi: `system.rate.limit.violation` (429), `core.concurrency.org.limit.violation`, `system.rate.limit.burst`, `system.rate.limit.warning`
- Yapılandırılabilir yüzde eşiğinde **e-posta uyarısı** (sadece eşiğe ilk ulaşımda, org-scoped bucket kullanımına göre — token/app bazlı değil)

### 1.6 Auth0 Management API

- **Token ömrü: 86.400 saniye (24 saat)** varsayılan ([management-api-access-tokens](https://auth0.com/docs/secure/tokens/access-tokens/management-api-access-tokens))
- **Kritik güvenlik notu, Auth0'ın kendi ifadesi:** *"Once issued, an access token cannot be revoked."* → 24 saatlik, iptal edilemez, tam yetkili admin token. Bu kötü bir tasarım.
- Audience: `https://{domain}/api/v2/`
- Scope modeli endpoint başına ("Each Management API endpoint requires a specific set of scopes")
- Rate limit: **token bucket** — bucket size = burst limit, refill rate = sustained limit ([rate-limit-policy](https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy)). Free/trial tenant: **2 rps, burst 10**. Enterprise "Public Performance Burst": 100 RPS default, add-on ile 200–400 RPS.
- Header'lar: `X-RateLimit-Limit` / `-Remaining` / `-Reset`

### 1.7 Microsoft Graph — throttling

- 429 + **`Retry-After` (saniye)**, ve bu değer otoriter ([graph/throttling](https://learn.microsoft.com/en-us/graph/throttling), 14 Oca 2025 / güncelleme 6 Ağu 2025)
- Limitler **çok boyutlu**: per-app across-all-tenants, per-tenant across-all-apps, per-app-per-tenant, request tipine göre (GET/POST/PATCH)
- **30 Eylül 2025'ten itibaren** per-app/per-user per-tenant limiti, toplam tenant limitinin **yarısına** düşürüldü — *tek bir app/kullanıcının tenant kotasını tüketmesini engellemek için*. Bu, "gürültülü komşu" probleminin sonradan yamalanması.
- `x-ms-resource-unit` header'ı ile **istek başına maliyet** açıklanıyor — sabit "1 istek = 1 birim" değil

**`$batch` endpoint'i** ([json-batching](https://learn.microsoft.com/en-us/graph/json-batching), 21 Şub 2025):
- **Batch başına maksimum 20 istek**
- `dependsOn` ile sıralı bağımlılık; bağımlılık başarısız olursa **424 Failed Dependency**
- Microsoft'un kendi tavsiyesi: batch ya **tamamen sıralı ya tamamen paralel** olsun, karışık değil
- Dış yanıt 200 döner (envelope parse edilebiliyorsa), her alt-istek kendi status'ünü taşır
- **Batch throttling'i BYPASS ETMİYOR:** *"Requests in a batch are evaluated individually against the applicable throttling limits and if any request exceeds the limits, it fails with a status of 429."* SDK batch içindeki 429'ları otomatik retry etmiyor — caller, başarısız alt-isteklerin en büyük `Retry-After` değerini kullanarak manuel retry yapmalı.
- Gerçek toplu veri çıkarımı için Microsoft REST'ten **tamamen vazgeçiriyor** ve **Graph Data Connect**'e yönlendiriyor ("not subject to throttling limits") — bu, `$batch`'in bulk için yetersizliğinin örtük itirafı.

### 1.8 OpenAPI: üreten mi, elle yazan mı?

| Ürün | Durum | Kaynak |
|---|---|---|
| **Okta** | **Üretiliyor** — *"a snapshot of the OpenAPI spec generated directly from the Okta Management API"*. Repo **community PR kabul etmiyor**. Tüm management SDK'ları bu spec'ten build ediliyor. Eski elle-yazılmış Swagger'lar `tree/legacy-v1-swagger` branch'inde arşivde. | [okta/okta-management-openapi-spec](https://github.com/okta/okta-management-openapi-spec) |
| **Keycloak v1** | Üretiliyor ama **kalitesiz** — maintainer'ın kendi ifadesiyle "incomplete, usually not sufficient to generate clients" | [#37655](https://github.com/keycloak/keycloak/discussions/37655) |
| **Keycloak v2** | *"an accurate OpenAPI specification that enables reliable client generation"*; management interface üzerinde **ayrı bir OpenAPI endpoint'i** var — CLI/generator'lar bağlandıkları sunucunun sürümüne göre komutlarını uyarlayabiliyor | [26.7.0 release notes](https://www.keycloak.org/2026/07/keycloak-2670-released) |
| **Auth0 / Microsoft Graph** | ⚠️ **DOĞRULANMADI** — arama bütçesi tükendiği için doğrulanamadı |

> **Argus için ders:** Okta'nın modeli doğru — spec **koddan üretilsin**, elle bakımı yapılmasın, ve SDK'lar **zorunlu olarak** spec'ten generate edilsin. Keycloak v2'nin runtime OpenAPI endpoint'i ek bir iyi fikir: CLI sürüm uyumsuzluğu problemini ortadan kaldırıyor.

---

## 2. Delege Yönetim — en zor kısım

### 2.1 Keycloak `realm-management` client rolleri

Her realm'de `realm-management` adında built-in bir client var; client-level rolleri realm yönetim izinlerini tanımlıyor. Bilinen roller: `realm-admin` (composite), `manage-users`, `view-users`, `query-users`, `query-groups`, `manage-clients`, `view-clients`, `query-clients`, `manage-realm`, `view-realm`, `manage-identity-providers`, `view-identity-providers`, `manage-events`, `view-events`, `manage-authorization`, `view-authorization`, `impersonation`, `create-client`.

⚠️ **Kısmen doğrulandı:** Bu listenin tamamını tek bir birincil kaynaktan çekemedim — Red Hat 26.2 Server Administration Guide Chapter 11'in ilgili bölümü ("Full list of permissions") fetch sırasında kesildi. Rol isimleri Keycloak ekosisteminde yaygın ve tutarlı ama **resmî tablo doğrulanmadı**.

**Granülerlik sınırları — somut örnekler:**
- `query-users` tek başına verildiğinde kullanıcı listesi çağrısı **200 döner ama liste boştur**. Bu "sadece Users bölümünü konsolda gösterme" için tasarlanmış, veri erişimi için değil. Bu ayrım güvenlik açığına dönüştü (bkz. §3.2, CVE-2026-17059).
- Ayrıcalık yükseltme koruması: dokümantasyon *"administrators can only delegate roles they themselves already possess"* prensibini beyan ediyor ([Keycloak Server Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html#admin_permissions)) — yani `manage-users`'lı bir admin, sadece **kendisinde olan** admin rollerini atayabiliyor.

### 2.2 FGAP V2 — "bu grubun yöneticisi" YAPILABİLİYOR

Sorunun cevabı: **Evet, Keycloak 26.2'den beri.** [Fine-Grained Admin Permissions V2](https://www.keycloak.org/2025/05/fgap-kc-26-2) (Mayıs 2025):

- Keycloak'ın kendi ifadesiyle *"a major step towards introducing delegated administration to Keycloak"*
- Kaynak tipleri: **Users, Clients, Groups, Roles** (Organizations sonradan geldi)
- Scope'lar: `view-members`, `manage-members`, `map-roles`, `impersonate` — ve *"every scope is explicit"*, gizli bağımlılık yok
- İki granülerlik seviyesi: **tekil kaynak** (belirli bir kullanıcı/client kümesi) VEYA **tip bazında tümü** (örn. tüm gruplar)
- Admin Console'da tek bir **Permissions** bölümü: tüm fine-grained izinleri görüntüleme ve denetleme
- **Realm başına bağımsız etkinleştirilebiliyor** — kademeli benimseme mümkün
- ⚠️ V1'den **otomatik migrasyon yok** ("Automatic migration is not available")

**Organizations için FGAP** ([org-fgap](https://www.keycloak.org/2026/05/org-fgap), 7 May 2026, Keycloak **26.7.0**):
- Sadece iki scope: **`manage`** (tam kontrol) ve **`view`** (salt okuma)
- **Resource hiding:** *"An administrator who is granted manage and view on Org A and view on Org B will see both organizations, but would be able to update just Org A… all other organizations are hidden entirely"* — hem Admin Console'da hem **REST API'de** gizli
- ⚠️ İlk sürümde **alt-kaynak izinleri yok** (bir org'un members/groups/IdP'lerini ayrı ayrı kontrol etmek mümkün değil)

### 2.3 Okta custom admin roles + resource sets

- Resource set = kaynak koleksiyonu; **sadece custom admin role'ler için** ([custom-admin-roles](https://help.okta.com/oie/en-us/content/topics/security/custom-admin-role/custom-admin-roles.htm))
- **Sert limitler:** maks. **10.000 resource set**, her set için maks. **1.000 kaynak**, aynı rol+resource-set kombinasyonuna maks. **1.000 admin**
- İzin domain'leri ([role-permissions](https://help.okta.com/en-us/Content/Topics/Security/custom-admin-role/about-role-permissions.htm)): User, Group, IAM, Application, Support, Profile source, Workflow, Authorization server, Customization, Directories, Identity Provider, Devices, Realms, Agents, Resource collections, Separation of duties, Labels, Event hooks, Inline hooks, Disaster recovery, Policies, Bot Protection
- ⚠️ **Önemli boşluk:** Okta'nın izin dokümantasyonu **ayrıcalık yükseltme riski taşıyan izinleri işaretlemiyor.** "Manage users" izni *"view, create, edit, and delete all profile and credential information"* veriyor — yani parola sıfırlama yoluyla hesap ele geçirme. "Manage API tokens" da benzer. Doküman bu tuzağa dair hiçbir uyarı içermiyor.
- Kısmi koruma mevcut: Workflows Administrator rolüne sahip bir admin, **bu rolü başkasına atayamıyor** — sadece super admin atayabiliyor ([Okta blog, Nis 2024](https://www.okta.com/blog/2024/04/least-privilege-for-your-critical-identity-roles-introducing-govern-okta-admin-roles/))

### 2.4 Entra ID — Administrative Units, PIM, Protected Actions

**Restricted Management Administrative Units (RMAU):** Sadece o birime atanmış admin'ler içindeki user objelerini değiştirebilir — bu kısıt **Global Administrator dahil** herkes için geçerli. Bu, "platform admin'i bile göremesin" gereksiniminin ürünleşmiş hali.

⚠️ Ciddi kısıtlar: RMAU'ya sadece **Users, Devices, Security Groups** konabiliyor (M365/Distribution/Mail-enabled group'lar hayır). Ve **PIM, RMAU içindeki grupları desteklemiyor** — Entitlement Management de öyle. Yani en güçlü izolasyon mekanizması, en güçlü governance mekanizmasıyla birlikte çalışmıyor.

**Protected Actions** ([protected-actions-overview](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/protected-actions-overview), güncelleme 19 Şub 2026) — Argus için en kopyalanabilir fikir:

- Belirli **izinlere** Conditional Access policy iliştiriliyor; enforcement **sign-in'de veya rol aktivasyonunda değil, eylemin yapıldığı anda**: *"policy enforcement occurs at the time the user attempts to perform the protected action… users are prompted only when needed"*
- Korunabilir izin kategorileri: Conditional Access policy yönetimi, cross-tenant access ayarları, **bazı directory objelerinin hard-delete'i**, named locations, protected action yönetiminin kendisi
- Somut izin örnekleri: `microsoft.directory/conditionalAccessPolicies/{create,delete,basic/update}`, `microsoft.directory/deletedItems/delete`, `microsoft.directory/namedLocations/*`, `microsoft.directory/crossTenantAccessPolicy/*`
- Mekanizma: **Conditional Access authentication context** — servis içindeki ince-taneli kaynaklar için policy uygulanmasını sağlıyor
- **Kritik uygulama sınırı (Microsoft'un kendi listesi):** Entra admin center, Microsoft Graph PowerShell ve Graph Explorer step-up auth destekliyor; **Azure PowerShell BAŞARISIZ OLUYOR.** Ayrıca yeni Terms of Use / custom control oluşturmak da başarısız oluyor (bunlar CA'ya kaydolduğu için CA create/update/delete protected action'larına takılıyor) — çözüm olarak *geçici olarak policy'yi kaldırmak* öneriliyor.
- Microsoft'un kendi uyarısı: *"Don't use protected actions to block access based on identity or group membership. …Who has access to specific permissions is an authorization decision and should be controlled by role assignment."* → **Protected actions ≠ authorization. İkisi ayrı katman.**
- PIM ile ilişkisi: PIM rol aktivasyonunda enforce eder (daha kapsamlı), protected actions eylem anında enforce eder (role bağımsız). *"can be used together for stronger coverage."*
- Emergency account (break-glass) policy'den hariç tutulmalı — kilitlenmeye karşı
- Entra ID P1 lisansı gerekiyor

### 2.5 Ayrıcalık yükseltme tuzağı — problemin adı ve gerçek CVE'ler

**Formal adı: "safety problem" (HRU model).** Harrison, Ruzzo, Ullman, *"Protection in Operating Systems"*, Communications of the ACM 19(8):461–471, 1976 ([ACM DL](https://dl.acm.org/doi/10.1145/360303.360333)).

Formal ifade: *"Given a protection state of an HRU model, the safety question asks if some subject can ever obtain a specific right with respect to some object."* Sonuç:

- **Genel halde safety KARAR VERİLEMEZ (undecidable)** — protection sistemi keyfi bir Turing makinesini simüle edebiliyor; bir hakkın "sızması" makinenin final state'e girmesine karşılık geliyor.
- Kısıtlı hallerde: **create operasyonları olmadan → PSPACE-complete**; delete/destroy olmadan → **hâlâ undecidable**; mono-operational komutlar (her subject eşit yaratılıyor, başlangıç hakkı yok) → **karar verilebilir**.

> **Argus için doğrudan sonuç:** "Bu izin setiyle admin kendini yükseltebilir mi?" sorusuna **genel bir statik analizle cevap verilemez.** Bu matematiksel bir gerçek, mühendislik eksikliği değil. Tek uygulanabilir strateji: yükseltme yollarını **çalışma zamanında, invariant olarak** kapatmak (bkz. §7 kararlar).

**Ve bunun gerçekte ne kadar acı verdiği — Keycloak'ın FGAP V2 CVE serisi:**

| CVE / GHSA | Ne oldu | Sürüm | Tarih |
|---|---|---|---|
| **CVE-2025-7784** ([GHSA-27gp-8389-hm4w](https://github.com/keycloak/keycloak/security/advisories/GHSA-27gp-8389-hm4w)) | FGAPv2 açıkken `manage-users` yetkili admin, **role mapping işlemlerinde eksik ayrıcalık sınırı kontrolü** nedeniyle kendi hesabına **realm-admin** atayabiliyor | 26.2.0–26.2.5 etkilendi; 26.2.6 / 26.3.0 düzeltti | 2025 |
| **CVE-2026-9099** ([GHSA-2qxf-v3g6-73v9](https://github.com/keycloak/keycloak/security/advisories/GHSA-2qxf-v3g6-73v9)) | `GroupResource.addChild()` endpoint'inde **yetkilendirme kontrolü yok** → düşük yetkili grup admin'i, `realm-admin` rolüne sahip yüksek yetkili bir grubu **kendi grubunun altına reparent** ediyor; hiyerarşik izin kalıtımı sayesinde o grubun üyelerine parola sıfırlama yetkisi kazanıyor → **tam realm devralma**. CWE-639 (Authorization Bypass Through User-Controlled Key), **CVSS 7.7 High** | <26.6.4; 26.6.4 düzeltti | 26 Haz 2026 |
| **CVE-2026-3121** ([issue #46719](https://github.com/keycloak/keycloak/issues/46719)) | Realm seviyesinde Admin Permissions açıkken `manage-clients` yetkili admin roller ve kullanıcılar üzerinde yetkisiz kontrol kazanıyor. Bildiren: rmartinc (Keycloak ekibi), 2 Mar 2026 | 26.4.11 / 26.5.6 / 26.6.0 etiketli | 2026 |
| **CVE-2026-9795** | Improper scope mapping enforcement yoluyla ayrıcalık yükseltme | — | Haz 2026 |
| **CVE-2026-9796** | `manage-clients` rollerini etkileyen **TOCTOU race condition** | — | Haz 2026 |
| **CVE-2024-3656** ([GHSA-2cww-fgmg-4jqc](https://github.com/keycloak/keycloak/security/advisories/GHSA-2cww-fgmg-4jqc)) | *"Unguarded admin REST API endpoints"* — realm'deki **düz kullanıcılar** yönetimsel fonksiyonları kullanabiliyor. CWE-269 + CWE-284, Moderate | <24.0.5 | 11 Haz 2024 |

Ayrıca bir tarihsel düzeltme: sınırlı realm yönetim izinli geliştiriciler, **client protocol mapper'ları veya client scope'ları yöneterek admin rollerini token'a map edip Admin API'ye erişebiliyordu** — artık engellendi.

> **Bu tablo tek başına en güçlü bulgu:** Keycloak, delege yönetimi V2 olarak sıfırdan tasarladı ve **yayınlandığı ilk 14 ayda en az 5 ayrı ayrıcalık yükseltme CVE'si aldı.** Hepsi aynı sınıftan: bir endpoint izin kontrolünü atlıyor veya izin sınırını kendi üzerine uygulamıyor.

### 2.6 Diğer ürünlerde aynı sınıf hatalar

- **authentik CVE-2024-37905** ([docs.goauthentik.io](https://docs.goauthentik.io/security/cves/CVE-2024-37905/)): Yetersiz izin kontrolü nedeniyle **herhangi bir kimliği doğrulanmış kullanıcı** bir API token yaratıp **token'ın ait olduğu user ID'yi değiştirerek** superuser olabiliyordu. Düzeltme: 2024.6.0, 2024.4.3, 2024.2.4. Geçici çözüm olarak **reverse-proxy seviyesinde `/api/v3/core/tokens*` bloklamak** öneriliyordu. → Ders: **credential/token nesnelerinin `owner` alanı asla mutable olmamalı.**
- **Zitadel CVE-2025-27507** ([GHSA-f3gh-529w-v32x](https://github.com/zitadel/zitadel/security/advisories/GHSA-f3gh-529w-v32x), **CVSS 9.0**): Admin API'de **12 HTTP endpoint**, IAM manager olmayan sıradan kimliği doğrulanmış kullanıcılara açıktı. Kök neden: **gRPC servis tanımlarında yanlış izin scope'u** — commit diff'i izinlerin `org.idp` (org-scoped) yerine `iam.idp` (system-scoped) olarak düzeltildiğini gösteriyor. Etki: instance LDAP ayarlarını değiştirip **tüm LDAP login'lerini saldırganın sunucusuna yönlendirmek**, LDAP sunucu parolasının ifşası. Düzeltme: 2.71.0, 2.70.1, 2.69.4, 2.68.4, 2.67.8, 2.66.11, 2.65.6, 2.64.5, 2.63.8.
- **Zitadel CVE-2025-53895**: Session management API'de eksik izin kontrolü — hedef session ID'yi bilen herhangi bir kimliği doğrulanmış kullanıcı, **session token'ı sunmadan** o session'ı güncelleyebiliyordu. 2.53.0'da session token zorunluluğu gevşetilince ortaya çıktı; öncesi etkilenmiyor.
- **Zitadel CVE-2026-27946**: V2 User API'de request payload'ı manipüle ederek **kendi e-posta/telefonunu challenge-response tamamlamadan doğrulama**.
- **GitLab CVE-2026-35595**: Bir shared child project üzerinde Write (Admin değil) yetkisi olan kullanıcı, **`parent_project_id: 0` göndererek** projeyi parent'ından koparabiliyor — Admin gereksinimi baypas ediliyor. (Keycloak'ın reparenting CVE'siyle **aynı sınıf**: hiyerarşi mutasyonu, hem kaynak hem hedef üzerinde izin gerektirmiyor.)
- **GitLab CVE-2026-6267** (CVSS 8.5, 29 Tem 2026): Yüksek ayrıcalık seviyesine veya iç operasyonlara yönelik bazı istekler, sadece **Developer** rolündeki kullanıcı tarafından başlatıldığında bile işlenip yanıtlanabiliyordu.

**Zitadel ve GitLab örneklerinin ortak dersi:** İzin kontrolü **endpoint başına annotation** olarak yazıldığında, birinin yanlış yazılması (`org.idp` vs `iam.idp`) sessizce 12 endpoint'i açıyor. Bu kaçınılmaz — insan yazıyor. Çözüm annotation'ı iyileştirmek değil, **her endpoint'in gerektirdiği izni test ile assert etmek.**

---

## 3. Admin API Güvenliği

### 3.1 GHSA yoğunluğu — sınıf dağılımı

Keycloak'ın [advisories sayfasından](https://github.com/keycloak/keycloak/security/advisories) sadece **ilk sayfa** (10 kayıt, hepsi 2026):

| GHSA | Başlık | Şiddet | Tarih |
|---|---|---|---|
| GHSA-95cx-vmr5-3cmr | default dcr policy allows **role forgery** via user property mappers | High | 6 Ağu 2026 |
| GHSA-95rm-h7g9-rhcf | dcr protocol mapper **type-swap policy bypass** allows privilege escalation | High | 6 Ağu 2026 |
| GHSA-2888-g6qc-w4mj | **authorization bypass via unnormalized URI matching** in PathMatcher | High | 6 Ağu 2026 |
| GHSA-f8m4-v488-rmrm | saml broker metadata import **disables response signature validation** | High | 6 Ağu 2026 |
| GHSA-fgq2-hxm5-8xg2 | saml idp-initiated broker login **bypasses link-only restriction** | High | 6 Ağu 2026 |
| GHSA-hmr6-pxx9-552p | ldap entry-dn user search **bypasses configured users DN boundary** | Moderate | 6 Ağu 2026 |
| GHSA-3692-rrj9-24qw | **unbounded metric cardinality** via request-controlled error text | Moderate | 6 Ağu 2026 |
| GHSA-j97h-3f8r-mrjr | authentication bypass via **JWT algorithm confusion** | High | 26 Haz 2026 |
| GHSA-f5p5-6xmx-p252 | authorization bypass via **incorrect URI comparison** | High | 26 Haz 2026 |
| GHSA-w3p3-7cjg-vgfw | unauthorized access via **UMA permission ticket bypass** | Moderate | 26 Haz 2026 |

⚠️ **DOĞRULANMADI:** Toplam advisory sayısı — sayfa 1'den fazlasını çekemedim (arama bütçesi tükendi).

**Sınıf dağılımı gözlemi:** 10 kayıttan **7'si "bypass"** (authorization bypass, signature validation bypass, restriction bypass, boundary bypass, ticket bypass). Sıfır memory-safety, sıfır injection. **IdP'lerdeki gerçek zafiyet sınıfı bellek güvenliği değil, yetkilendirme mantığıdır.** Rust'ın bellek güvenliği bu kategoriye **sıfır** katkı sağlar.

Özellikle **GHSA-2888-g6qc-w4mj** ve **GHSA-f5p5-6xmx-p252**: ikisi de **URI normalizasyon/karşılaştırma** hatası. Path tabanlı yetkilendirme yapan her sistemin klasik tuzağı.

### 3.2 Yatay ayrıcalık ihlali — CVE-2026-17059 (en öğretici vaka)

Escape Research (Enzo Mongin) tarafından bulundu ([escape.tech](https://escape.tech/blog/escape-research-pii-disclosure-keycloak-cve-2026-17059/)); Red Hat **24 Tem 2026**'da yayınladı, Keycloak **28 Tem 2026**'da **26.7.0** ile düzeltti.

Mekanizma:
- Sadece `query-users` + `view-realm` izinli kısıtlı bir admin
- **`/users` endpoint'i bu token'a boş liste dönüyor** (doğru davranış)
- Ama **`role-members` endpoint'i aynı token'a tam kullanıcı kayıtlarını veriyor**: username, e-posta, ad, soyad, hesap durumu, e-posta doğrulama durumu
- Kök neden: *"The role-members endpoint enforced only broad role-viewing and user-query permissions without applying the same per-user authorization filter."*

> **Bu, "yan kapı endpoint" anti-pattern'inin ders kitabı örneği.** Ana listeleme endpoint'i doğru filtreliyor; kullanıcı nesnesi döndüren **ikincil** bir endpoint aynı filtreyi uygulamayı unutuyor. Endpoint başına yetkilendirme yazıldığı sürece bu hata **kaçınılmaz** — çünkü N endpoint × M kaynak tipi kombinasyonu insan denetimini aşıyor. Filtre **veri erişim katmanında** olmalı, handler'da değil.

### 3.3 Admin konsolu bir SPA — XSS/CSRF yüzeyi

- **CVE-2024-4028** ([GHSA-q4xq-445g-g6ch](https://github.com/advisories/GHSA-q4xq-445g-g6ch)): Admin console'dan Resource/Permission yaratırken permission alanına kötü niyetli payload → **stored XSS**. 26.2.0 öncesi. Paket: `org.keycloak:keycloak-admin-ui`.
- **[GHSA-755v-r4x4-qf7m](https://github.com/keycloak/keycloak/security/advisories/GHSA-755v-r4x4-qf7m)**: Grup adına payload → groups dropdown'da **stored XSS**.
- **HOST header yansıması**: Keycloak admin console'da HOST header'ı web resource konumlarını belirlemek için kabul ediyordu → kötü niyetli sunucu üzerinden kimliği doğrulanmış kullanıcıya karşı **reflected XSS**.
- **CSRF cookie session'a bağlı değildi**: *"the cookie used for CSRF prevention in Keycloak was not unique to each session"* → saldırgan kimliği doğrulanmış kullanıcı oturumuna erişebiliyordu.

**Kritik gözlem:** Bu XSS'lerin çoğu **"privileged attacker"** gerektiriyor — yani düşük yetkili bir admin, **yüksek yetkili bir admin'in tarayıcısında kod çalıştırıyor.** Delege yönetim + admin SPA kombinasyonunda XSS, ayrıcalık yükseltmeye giden en kısa yol. Tenant admin'in girdiği bir grup adı, platform admin'inin konsolunda render ediliyorsa, tenant izolasyonu XSS ile çöker.

### 3.4 Admin oturumları için ayrı politika — Okta'nın modeli

[sec.okta.com/articles/protectingadminsessions](https://sec.okta.com/articles/protectingadminsessions/) — 2023 ihlali sonrası inşa edilmiş, tarihli katman katman:

| Kontrol | Detay | Tarih |
|---|---|---|
| **ASN Session Binding** | *"Okta automatically revokes an administrative session if the ASN observed during an API or web request differs from the ASN recorded when the session was established."* Yayından 3 ay içinde **9.000+ org** benimsedi → Okta tüm Workforce müşterileri için **varsayılan açık** yaptı | Admin Console'da varsayılan: **23 Eki 2023** |
| **IP Session Binding** | Aynı mantık, IP seviyesinde. Yeni org'larda varsayılan açık | EA: 7 Şub 2024 (Console), 1 Mar 2024 (Workflows/Access Requests/PA) |
| **Admin session lifetime** | Varsayılan **12 saat lifetime + 15 dk idle** | GA: 8 Oca 2024 |
| **Protected Actions** | *"Admins receive re-authentication prompts when they perform critical tasks in the Admin Console"* | EA: 7 Şub 2024 |
| **MFA zorunluluğu** | Tek faktörlü erişime izin veren authentication policy'leri engelliyor | EA: May 2024 |

Session lifetime konfigürasyon sınırları ([configure-admin-session](https://help.okta.com/en-us/content/topics/security/policies/configure-admin-session.htm)):
- Lifetime: önerilen 12 saat, **maks 24 saat**, min 1 dakika
- Idle: önerilen 15 dakika (**NIST kılavuzuna dayalı**), **maks 2 saat**, min 1 dakika
- Kısıt: lifetime ≥ idle
- Süre dolmadan önce **uyarı popup'ı**: timeout >10 dk ise son 5 dk içinde, <10 dk ise son 30 sn içinde
- ⚠️ **Kapsam sınırı, Okta'nın kendi ifadesi:** *"Administrative sessions in other Okta applications are unaffected, including Okta Workflows, Okta Access Gateway, and Advanced Server Access."* → Admin session policy'si **tüm admin yüzeylerini kapsamıyor.** Argus için ders: admin session politikası **merkezî** olmalı, konsola özel değil.

**Auth0 ile karşılaştırma:** Auth0'ın Management API token'ı **24 saat, iptal edilemez**. Okta'nın admin console session'ı **12 saat + 15 dk idle + ASN binding + protected actions**. Aynı sorunun iki ucu — ve Auth0 tarafı belirgin şekilde zayıf.

### 3.5 Impersonation

Keycloak'ta impersonation Admin REST API üzerinden programatik olarak erişilebilir ve **dönen `access_token` hedef kullanıcı için tam geçerli bir token** — downstream API çağrılarında kullanıcının kendi aldığı token'dan ayırt edilemez. FGAP V2 bunu `impersonate` scope'u olarak explicit hale getirdi.

Denetim: Admin Console → Events → Admin events, `TOKEN_EXCHANGE` filtresi ile hangi hesapların ne zaman impersonate edildiği izlenebiliyor.

⚠️ Bu bölümdeki "best practice"lerin (5 dk token ömrü, secrets manager) kaynağı Medium/blog yazıları — **birincil kaynak değil, DOĞRULANMADI.**

---

## 4. Konfigürasyon Yönetimi ve GitOps

### 4.1 Keycloak realm import/export — config-as-code için yetersiz

**Full CLI export (`kc.sh export`)** ([importExport.adoc](https://github.com/keycloak/keycloak/blob/main/docs/guides/server/importExport.adoc)):
- **Tüm node'lar durdurulmalı**: *"Consistency of an export is not guaranteed unless all Keycloak nodes are stopped prior to running the export."* → canlı/online kullanım için tasarlanmamış
- Hariç: user/admin events, persisted sessions, workflow state, revoked tokens

**Partial export (Admin Console)**:
- Kullanıcıları **hiç export edemiyor**
- Hassas değerler (parolalar, client secret'lar) **`*` ile maskeleniyor** → diff edilemez, yeniden uygulanamaz
- Keycloak'ın kendi ifadesiyle **backup veya sunucular arası veri transferi için uygun değil**
- `clientScopes` / `clientScopeMappings` partial import sırasında **yok sayılıyor** ([#16289](https://github.com/keycloak/keycloak/issues/16289))
- Dokümantasyon yetersiz kabul ediliyor ([#41061](https://github.com/keycloak/keycloak/issues/41061))

**Determinizm — kabul edilmiş problem:** Export **deterministik değil**. Array sıralaması çalıştırmalar arası değişiyor; realm ID'leri delete/recreate'te yeniden üretiliyor → devasa sahte diff'ler ([keycloak-config-cli #799](https://github.com/adorsys/keycloak-config-cli/issues/799)). Düzeltme **Keycloak core'da değil**, config-cli'nin içinde (PR #1207, sıralı array'ler + ID substitution) yapıldı. Topluluk bunu doğrudan Keycloak ekibine de taşımış ([#30643](https://github.com/keycloak/keycloak/discussions/30643)).

### 4.2 keycloak-config-cli

[adorsys/keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli) — deklaratif, idempotent YAML/JSON → Admin API senkronizasyonu. Raw import/export wrapper'ı **değil**: canlı realm durumuyla diff alıp inkremental değişiklik uyguluyor. Restart gerektirmiyor.

Kapsam ([FEATURES.md](https://github.com/adorsys/keycloak-config-cli/blob/main/docs/FEATURES.md)): clients, roles, groups, users+credentials, auth flows/executions, identity providers + mappers, client scopes, components, user federation, client policies, FGAP v1/v2, message bundles, Organizations, Workflows.

Kısıtlar:
- **FGAP v2 (Keycloak ≥26.2) admin-permissions client authorization'ı system-managed ve import'ta explicit olarak atlanıyor**
- Sürüme özgü tuzaklar manuel müdahale gerektiriyor (örn. Keycloak 25.0.1'in "basic" scope değişikliği `sub` claim'ini etkiliyor)

Bakım: **aktif.** En son **v6.5.1 (22 May 2026)**; öncesi v6.5.0 (12 Mar 2026), v6.4.1 (28 Oca 2026), v6.4.0 (21 Şub 2025). *"latest 4 Keycloak releases where possible"* politikası ([compatibility](https://adorsys.github.io/keycloak-config-cli/compatibility/keycloak-versions/)).
⚠️ Gün-seviyesi tarihler WebFetch özetinden geldi, ham JSON'dan değil — **yaklaşık kabul edin.**

### 4.3 Terraform provider'ları

**Keycloak:** `mrparkers/terraform-provider-keycloak` → **Keycloak projesi tarafından resmen devralındı, 9 Ara 2024** ([keycloak.org duyurusu](https://www.keycloak.org/2024/12/terraform-provider-adoption)). Yeni maintainer'lar: Sebastian Schuster, Thomas Darimont. Lisans **Apache 2.0**'a geçti. Migrasyon: `terraform state replace-provider mrparkers/keycloak keycloak/keycloak`. Devralma gerekçesi: topluluk anketi bunu **en yaygın realm-config aracı** olarak gösterdi ([#30643](https://github.com/keycloak/keycloak/discussions/30643)).

Devralma sonrası aktif: v5.2.0 (Nis 2025) → **v5.9.0 (Tem 2026)**; FGAPv2 admin-permission kaynakları, realm-scope import, Keycloak 26.4 uyumu eklendi.

Bilinen problemler:
- `keycloak_authentication_execution` sıralaması **API sınırlaması nedeniyle explicit `depends_on` gerektiriyor** ([#890](https://github.com/keycloak/terraform-provider-keycloak/issues/890)) — deklaratif olmayan bir bağımlılığı deklaratif araca zorla giydirme
- Client secret taşıyan attribute'lar, config'de belirtilmese bile **Terraform state'inde cache'leniyor** ([#1058](https://github.com/keycloak/terraform-provider-keycloak/issues/1058))

**Auth0** (`auth0/terraform-provider-auth0`, resmî):
- Kalıcı sahte drift: *"dummy config drifts consistently surface even though the actual config has reached desired state"* ([#1312](https://github.com/auth0/terraform-provider-auth0/issues/1312))
- `ignore_changes` connection credential'ları için tam çalışmıyor → **credential sıfırlanma riski** ([#1291](https://github.com/auth0/terraform-provider-auth0/issues/1291))
- API deprecation'ları provider'ı kırıyor: `enabled_clients` alanının kaldırılması (EOL 13 Tem 2026) provider <1.29.0'ı **tamamen kırdı** ([Auth0 Support](https://support.auth0.com/center/s/article/auth0-terraform-provider-operations-fail-after-legacy-field-end-of-life))

**Okta** (`okta/terraform-provider-okta`, resmî):
- Sunucu tarafı apply sonrası alanları **otomatik dolduruyor/düzeltiyor** → sonraki plan'larda state config'den ayrışıyor
- `okta_user_group_memberships`'te sahte drift: attribute'lar gerçek değişiklik olmadan "Known after apply"a dönüyor ([#2254](https://github.com/okta/terraform-provider-okta/issues/2254))

### 4.4 Kubernetes operator'lar

**Keycloak Operator:**
- `Keycloak` CRD: deployment/infra yönetiyor (Ingress, Service, admin-credential Secret) ama **veritabanını yönetmiyor** ([basic-deployment](https://www.keycloak.org/operator/basic-deployment))
- `KeycloakRealmImport` CRD: **sadece create** — *"only supports creation of new realms and does not update or delete those… changes performed directly on Keycloak are not synced back in the CR"* ([realm-import](https://www.keycloak.org/operator/realm-import)). Yani **drift reconciliation yok.**
- Bu boşluk için ayrı bir proje var: [`keycloak/keycloak-realm-operator`](https://github.com/keycloak/keycloak-realm-operator) — kendi tanımıyla **"temporary workaround"**, eski operator'dan fork'lanıp deployment mantığı çıkarılmış, Realm/Client/User için tam CRUD + drift reconciliation ekliyor. Native CRD desteği gelene kadar ana operator'ın yanında çalışacak. ⚠️ Küçük ölçek (~39 star), tek kaynaktan doğrulandı.
- **26.7.0 ile yön değişti:** Operator artık `KeycloakOIDCClient` / `KeycloakSAMLClient` CRD'lerini **Client Admin API v2 üzerinden** yönetiyor — yani operator, v1'in imperative API'sinden çıkıp v2'nin deklaratif API'sine geçiyor.

**authentik — Blueprints:** İlk günden deklaratif tasarlanmış birinci-parti mekanizma ([blueprints](https://docs.goauthentik.io/customize/blueprints/)). YAML (schema version 1), `model` + `state` alanları: `present` / `created` / `must_created` / `absent`. İki uygulama modu: mount edilmiş dosya (worker ~60 dakikada bir yeniden okuyor) veya API/UI üzerinden tek seferlik import.
⚠️ **Resmî Kubernetes operator YOK.** CRD/operator fikri [#5675](https://github.com/goauthentik/authentik/issues/5675)'te açılmış ama uygulanmamış görünüyor; resmî K8s dağıtımı **sadece Helm chart**.

**Zitadel — API-first:** Katmanlı config, öncelik sırasıyla: Go-struct default'ları → paketlenmiş `cmd/defaults.yaml` → özel `--config` YAML → env vars (`ZITADEL_*`) → CLI flag'leri ([configure](https://zitadel.com/docs/self-hosting/manage/configure), [defaults.yaml](https://github.com/zitadel/zitadel/blob/main/cmd/defaults.yaml)). İlk instance bootstrap'ı `FirstInstance` YAML bloğu + `zitadel setup --steps`.
Tenant/org/app seviyesindeki sürekli config **API-first**: resmî [terraform-provider-zitadel](https://github.com/zitadel/terraform-provider-zitadel). Boşluklar: "Executions" için kaynak yok ([#271](https://github.com/zitadel/terraform-provider-zitadel/issues/271)); provider config'i eager yüklüyor → taze Helm deployment'larıyla **bootstrap sıralama çakışması** ([#167](https://github.com/zitadel/terraform-provider-zitadel/issues/167)).

### 4.5 Deklaratif vs imperative — kim pişman oldu

**Keycloak = ders kitabı vaka çalışması.** Sadece topluluk şikayeti değil, **maintainer'ın yazılı analizi** var: [Discussion #33049 "Declarative configuration API"](https://github.com/keycloak/keycloak/discussions/33049) (18 Eyl 2024, contributor **vmuzikar**). Mevcut API'nin deklaratif kullanıma neden direndiğini kataloglamış:

- POST/PUT tutarsızlığı
- **create-or-update (upsert) semantiği yok**
- Çok-istekli entity yaratma (örn. client + roller = 2 çağrı)
- **İsim yerine UUID tabanlı adresleme**

Önerdiği çözümler: **PUT tabanlı upsert**, **isim tabanlı adresleme**, ve reconciliation döngüsünü önlemek için **"desired vs runtime state" ayrımı.** Explicit olarak Admin API v2'nin zemini olarak konumlandırılmış.

**Sonuç:** Keycloak'ın imperative, ad-hoc evrilmiş Admin API'si yıllarca üçüncü-parti araçların (config-cli, birden fazla Terraform provider, birden fazla operator) **her birinin bağımsız olarak idempotency/diffing/normalization çözmesine** yol açtı. Core ekip şimdi v2 ile deklaratif semantiği geriye dönük giydirmeye çalışıyor.

**Karşı örnekler:** authentik günü birinde deklaratif (Blueprints, birinci parti). Zitadel API-first + resmî Terraform provider'ı sancılı yol olarak seçmiş; sadece bootstrap/instance seviyesi YAML.

### 4.6 Drift tespiti — ne bozuluyor (ortak arıza sınıfları)

1. **Deterministik olmayan serileştirme** (Keycloak): array sıralaması çalıştırmalar arası değişiyor; normalizasyon core'da değil, client tarafında ([#799](https://github.com/adorsys/keycloak-config-cli/issues/799))
2. **Sunucu tarafı default'lar drift sanılıyor**: Auth0 ve Okta provider'larında kalıcı sahte diff'ler ([Auth0 #1312](https://github.com/auth0/terraform-provider-auth0/issues/1312), [Okta #2254](https://github.com/okta/terraform-provider-okta/issues/2254))
3. **Secret'lar state/export içinde**: Keycloak partial export secret'ları `*` ile maskeliyor (diff edilemez); Terraform state secret'ları cache'liyor ([#1058](https://github.com/keycloak/terraform-provider-keycloak/issues/1058)); Auth0 `ignore_changes` credential'ları korumuyor ([#1291](https://github.com/auth0/terraform-provider-auth0/issues/1291))
4. **Tek yönlü reconciliation**: `KeycloakRealmImport` sadece create — band-dışı değişiklikler **sessizce hiç düzeltilmiyor**
5. **API'nin deklaratif ifade edemediği sıralama bağımlılıkları**: auth execution ordering ([#890](https://github.com/keycloak/terraform-provider-keycloak/issues/890))
6. **Bootstrap yarışları**: Zitadel provider'ı taze Helm bring-up'ta çakışıyor ([#167](https://github.com/zitadel/terraform-provider-zitadel/issues/167))

---

## 5. Admin API × Çok Kiracılık Kesişimi

### 5.1 Auth0'ın "My Organization API" — en önemli mimari bulgu

[auth0.com/blog/managing-auth0-organizations-my-organization-api](https://auth0.com/blog/managing-auth0-organizations-my-organization-api/) (**21 Nis 2026**):

Auth0, Management API'yi delege org yönetimi için kullanmanın **çalışmadığını kabul edip ayrı bir API inşa etti.** Kendi gerekçesi:

> *"The Management API is intended to configure Auth0 tenants globally and is not designed for frequent, granular calls. It can quickly become a bottleneck for routine operations like updating settings or inviting members."*

> Geliştiriciler *"often hit a wall with rate limits as their businesses grow and the number of organizations in their Auth0 tenant expands."*

| Boyut | Management API | My Organization API |
|---|---|---|
| Amaç | Global tenant konfigürasyonu | Org-spesifik delege operasyonlar, *"much higher performance and scalability"* |
| Audience | `https://{domain}/api/v2/` | **`https://{domain}/my-org/`** |
| Scope'lar | `read:users`, `create:users`… (tenant-geniş) | **`read:my_org:details`, `update:my_org:details`** |
| Tenant bağlamı | Path/parametre içinde org ID | **Kimliği doğrulanmış kullanıcının org üyeliğinden türetiliyor** |
| Sınır | Tenant-geniş | Organizasyon sınırı içinde |

**Bu, Argus için tek başına en aksiyona dönüştürülebilir mimari ders:** Platform-admin API'si ile tenant-admin (self-servis) API'si **ayrı yüzeyler** olmalı — ayrı audience, ayrı scope namespace'i, ayrı rate limit bütçesi. Tek bir admin API'yi hem platform hem tenant yönetimi için kullanmak, Auth0'ın kendi ifadesiyle rate limit duvarına ve performans darboğazına çarpıyor.

### 5.2 Tenant bağlamı kimden geliyor — güvenlik açısından

**Değişmez kural (çapraz-kaynak doğrulanmış):** Tenant kimliği **doğrulanmış token claim'inden** türetilmeli; header/query/body'den **asla** güvenilmemeli. Path/subdomain/header'dan gelen tenant bağlamı varsa, token claim'iyle **eşleştiği doğrulanmalı**.

Auth0'ın My Organization API'si bunu en temiz şekilde yapıyor: org bağlamı **kimliği doğrulanmış kullanıcının org üyeliğinden** geliyor — istemci hiçbir yerde org ID'si göndermiyor. Bu tasarım, IDOR sınıfını **yapısal olarak** ortadan kaldırıyor.

⚠️ Bu bölümdeki genel best-practice literatürü çoğunlukla blog kaynaklı; **birincil spec kaynağı yok.** Ancak Auth0'ın somut tasarımı ve §2.6'daki Zitadel CVE-2025-27507 (org-scoped vs iam-scoped karışıklığı) bu kuralı ampirik olarak destekliyor.

### 5.3 Keycloak'ın iki modeli

| | Realm-per-tenant | Organizations (tek realm) |
|---|---|---|
| İzolasyon | Sert — ayrı config, tema, admin | Yumuşak — paylaşılan realm |
| OIDC issuer | **Her realm kendi issuer'ı** → her backend servisi belirli bir realm'in discovery endpoint'ine karşı konfigüre edilmeli | Tek issuer |
| Admin token | **Master realm'den gelmeli** (§1.4) → merkezî risk | FGAP org scope'ları |
| Delege yönetim | `realm-management` rolleri | `manage` / `view` + **resource hiding** |
| Operasyonel maliyet | Yüksek | Düşük |

Keycloak'ın Organizations'ı 26.7.0'da FGAP ile birleşince gerçek delege yönetim sağlıyor: org admin'i Account Console'dan veya Organizations REST API'yi çağıran özel bir portaldan kendi org'unu yönetiyor, **diğer org'ları göremiyor veya etkileyemiyor.**

Entra'nın RMAU'su daha güçlü bir garanti sunuyor: **Global Administrator dahil** hiç kimse RMAU içindeki objeleri değiştiremiyor. Bu, "platform admin'i bile göremesin" gereksiniminin ürünleşmiş hali — ama PIM ile birlikte çalışmıyor (§2.4).

---

## 6. Bulk / Batch İşlemler

### 6.1 SCIM `/Bulk` — spec var, kimse uygulamıyor

**Spec** ([RFC 7644 §3.7](https://datatracker.ietf.org/doc/html/rfc7644#section-3.7), 2015):
- `bulkId`: client-üretimi geçici tanımlayıcı, POST için **ZORUNLU**; henüz yaratılmamış kaynaklara aynı payload içinde referans vermeyi sağlıyor; sunucu aynı `bulkId`'yi gerçek kaynak ID'sine map ederek geri döndürmeli
- `failOnErrors`: client'ın belirlediği, kaç hata sonrası batch'in durdurulacağı; yoksa hepsi işlenir ve tüm hatalar raporlanır
- `maxOperations` / `maxPayloadSize`: **sunucu** tarafından `ServiceProviderConfig`'in `bulk` complex attribute'unda ilan ediliyor ([RFC 7643 §5](https://www.rfc-editor.org/rfc/rfc7643.html#section-5))

**Gerçek dünya benimseme — neredeyse sıfır:**

| Ürün | Durum |
|---|---|
| **Keycloak** | `bulk.supported: false`; `POST /scim/v2/Bulk` düzgün `BulkResponse` bile dönmüyor. Açık feature request, milestone yok ([#50366](https://github.com/keycloak/keycloak/issues/50366)) |
| **Microsoft Entra** | SCIM **client** olarak `/Bulk`'ı **hiç kullanmıyor** — kullanıcı başına ayrı çağrı. Tek istisna: gallery app'lerde 20 grup-üyelik değişikliğini tek PATCH'te toplama (RFC `/Bulk` mekanizması **değil**) |
| **Okta** | Inbound provisioning'de SCIM bulk desteklemiyor; *"bulk operations for multiple resource changes in a single request aren't currently used by the Okta provisioning service"* |
| **PingFederate** | `bulk.supported: false`, `maxOperations: 0`, `maxPayloadSize: 0` — ⚠️ **DOĞRULANMADI**, birincil doc fetch'i başarısız |

> **Sonuç:** SCIM `/Bulk`, standardın **en az uygulanan** büyük özelliği. İncelenen her satıcı bunun yerine **spec dışı, kendi async job API'sini** inşa etmiş. Argus'un sadece RFC 7644 §3.7'ye yatırım yapması, gerçek dünyada karşılığı olmayan bir özelliği kopyalamak olur.

### 6.2 Auth0 jobs — çalışan async model

`POST /api/v2/jobs/users-imports` ([post-users-imports](https://auth0.com/docs/api/management/v2/jobs/post-users-imports)):
- **202** + `{id, status: "pending", type: "users_import", created_at}`; client `GET /api/v2/jobs/{id}` ile poll ediyor
- **Dosya boyutu: 500KB–512KB** (Auth0'ın hata metni: *"Payload content length greater than maximum allowed: 512000"*) → metadata küçük tutulursa ~1.000 kullanıcı
- **Eşzamanlılık: tenant başına 2 iş.** 3.'sü 429 + *"There are 2 active import users jobs, please wait until some of them are finished and try again."* Bu limitin üstündeki enterprise müşterilere Auth0 **dokümante edilmiş API çözümü değil, Technical Account Manager'a başvurma** öneriyor ([Auth0 Community](https://community.auth0.com/t/understanding-auth0s-limits-on-concurrent-bulk-user-import-jobs-per-tenant/125157))
- Yaşam döngüsü: `pending` → `completed`/`failed`; **2 saatte timeout**; tüm iş verisi (hata detayı dahil) **24 saatte otomatik siliniyor**
- **Hata dosyası**: `GET .../jobs/{id}/errors` → başarısız kayıt başına yapılandırılmış hata objesi, makine kodu (`CONFLICT_EMAIL`, `INVALID_TYPE`, `FORMAT`, `DUPLICATED_USER`, `ENUM_MISMATCH` — ~19 kod) + insan mesajı
- `upsert` (bool) ve `external_id` ile idempotent-benzeri yeniden çalıştırma
- Tamamlanma bildirimi: `send_completion_email` — **push webhook değil, e-posta**

`POST /api/v2/jobs/users-exports`: aynı async-job/poll deseni; connection scope, format (CSV/JSON), maks kayıt, alan listesi seçilebiliyor.

### 6.3 Okta bulk — çekirdek API'de yok

Okta'nın core Users API'sinde Auth0'ın jobs endpoint'lerinin karşılığı **yok.** Okta'nın kendi migrasyon kılavuzu **script'lenmiş, sıralı, kullanıcı başına POST** tarif ediyor; rate-limit header'larına dayanmayı ve migrasyon pencerelerinde **Okta Support ile limitleri geçici yükseltmek için koordine olmayı** öneriyor ([migrate-to-okta-bulk](https://developer.okta.com/docs/guides/migrate-to-okta-bulk/main/), [migrate-to-okta-with-scripts](https://developer.okta.com/docs/guides/migrate-to-okta-with-scripts/main/)).

Gerçek batch mekanizması **Okta Workflows'ta**, platform API'sinde değil ([Bulk User Import connector](https://help.okta.com/wf/en-us/content/topics/workflows/connector-reference/okta/actions/bulkuserimport.htm)): oturum başına maks **10.000 kullanıcı**, en fazla **50 POST**, her biri **200 kullanıcı** (200 × 50 = 10.000).

⚠️ **Dokümante edilen ile gözlenen davranış arasında fark:** Bir müşteri, doküman 10.000 derken bulk import'un **50 kayıttan sonra durduğunu** raporladı; Okta'nın kendi destek yanıtı mekanizmayı (200/batch × 50 istek) teyit etti ama **tutarsızlığı açıklayamadı** ve resmî destek kaydı açmaya yönlendirdi ([Okta Support](https://support.okta.com/help/s/question/0D54z0000AE7QiVCQV/bulk-user-import-stops-after-processing-50-records-documentation-states-10000-users-per-session)).

### 6.4 Microsoft'un gerçek bulk cevabı: `/bulkUpload` (SCIM `/Bulk` değil)

[API-driven inbound provisioning](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/inbound-provisioning-api-concepts) (güncelleme 20 Ağu 2026):
- Senkron **202 Accepted**, sonra **provisioning logs API**'sini kayıt başına status için poll etme → tam olarak AIP-151/Azure LRO şekli
- Throttle: **5 saniyelik pencerede 40 çağrı**
- **Tenant seviyesinde: 24 saatte 2.000 çağrı (P1/P2) veya 6.000 çağrı (Governance lisansı)**
- Microsoft'un kendi tavsiyesi: *"optimize SCIM bulk payloads to include up to 50 operations per API call"* — **günlük kotayı korumak için**
- SCIM **şema** yapılarını kullanıyor ama SCIM `/Bulk` **protokol** endpoint'ini değil

### 6.5 Uzun süren işlem desenleri

- **RFC 7240** (`Prefer: respond-async`, IETF 2014): 202 kodunun ötesinde *"little guidance is given on how and when to use the response code and the process for determining the subsequent final result of the operation is left entirely undefined"* — polling mekaniğini **bilinçli olarak standartlaştırmıyor**
- **Google AIP-151** ([aip.dev/151](https://google.aip.dev/151)): **~10 saniyeden uzun** sürmesi beklenen her method ("a good rule of thumb") nihai kaynağı değil bir `google.longrunning.Operation` objesi dönmeli, + zorunlu `Operations` servisi. `Operation`, ilerleme/kısmî hata raporlaması için terminal `response` tipinden **ayrı bir `metadata` tipi** taşıyor.
- **Microsoft/Azure REST guidelines**: **202 Accepted** (boş gövde) + `Location`/`Operation-Location` header'ı status-monitor kaynağına; her terminal-olmayan poll yanıtı **kendi `Retry-After`'ını** taşımalı; Azure ayrıca Operation-Location URL'inde `api-version` query param'ı istiyor
- **Tradeoff:** Üç spec de (RFC 7240, AIP-151, MS) push bildirimi **zorunlu kılmıyor**; hepsi **poll tabanlı status monitor**'u baseline kabul edip push'u opsiyonel katman olarak bırakıyor. Polling basit, cache dostu, her HTTP altyapısından geçiyor; webhook polling yükünü azaltıyor ama caller'ın erişilebilir endpoint açmasını ve idempotent teslimat/retry yönetmesini gerektiriyor.

### 6.6 Idempotency key'ler

**IETF durumu (8 Eyl 2026 itibarıyla):** [`draft-ietf-httpapi-idempotency-key-header-07`](https://www.ietf.org/archive/id/draft-ietf-httpapi-idempotency-key-header-07.html), yayın 15 Eki 2025, expire 18 Nis 2026, Standards Track, HTTPAPI working group'ta **hâlâ aktif Internet-Draft — RFC değil.**

- Header, RFC 8941 Structured Field String; UUID öneriliyor
- Opsiyonel **"idempotency fingerprint"** (payload'ın checksum/digest'i) → sunucu aynı key + farklı payload'ı reddedebilsin
- Önerilen status kodları: **400** (gereken yerde key yok), **422** (key farklı payload'la yeniden kullanılmış), **409** (aynı key'i paylaşan eşzamanlı in-flight istekler)
- **Saklama penceresi kasıtlı olarak tanımsız** — her API kendi belirleyip yayınlamalı
- Atıf yapılan uygulayıcılar: Stripe, PayPal (`PayPal-Request-Id`), Adyen, Square, WorldPay, Open Banking

**Stripe (referans uygulama)** ([docs.stripe.com/api/idempotent_requests](https://docs.stripe.com/api/idempotent_requests), [api-v2-overview](https://docs.stripe.com/api-v2-overview)):
- **API v1:** key'ler **24 saat** tanınıyor; eşleşen key + uyuşmayan parametre → hata; **ilk** isteğin sonucu (başarı veya hata, **500'ler dahil**) retry'de aynen tekrar oynatılıyor
- **API v2:** pencere **30 güne** uzatıldı, aynı API + aynı hesap/sandbox scope'unda. **Davranış değişti:** ilk deneme **başarısızsa retry'de yeniden çalıştırılıyor** (sadece replay değil); **başarılıysa** hâlâ kısa devre yapıp saklanmış sonucu dönüyor
- **Kritik incelik:** Stripe idempotent sonucu **sadece çalıştırma başladıktan sonra** kalıcılaştırıyor — validation hataları veya aynı key üzerinde başka bir in-flight istekle çakışan istekler **saklanmıyor**, böylece güvenle retry edilebiliyorlar ve "farklı parametre" hatası tetiklenmiyor
- Key maks **255 karakter**; key değerine **PII gömülmemesi** açıkça öneriliyor

**IdP'lerde durum:**
- **WorkOS**: bulunan tek IdP-komşusu; ve **çok dar** — `Idempotency-Key` sadece **Create Audit Log Event** endpoint'inde onurlandırılıyor; diğer endpoint'ler header'ı sessizce kabul edip **deduplication yapmıyor** → retry edilen bir mutation hâlâ çift-yaratabiliyor. SDK'ları POST'lara otomatik UUIDv4 ekliyor ama sadece iç retry'ler için, caller garantisi olarak değil.
- **Auth0**: Management API sadece kaynak-seviyesi semantikle "kısmen idempotent" (örn. users-import job'ında `upsert`); **`Idempotency-Key` header desteği dokümante edilmemiş**
- **Okta**: `Idempotency-Key` desteği bulunamadı; create için **client-supplied external ID** ile de-facto idempotency (request-token değil, natural-key idempotency'si)

> **Hiçbir büyük genel amaçlı IdP (Okta, Auth0, Entra) IETF `Idempotency-Key` desenini Stripe'ın yaptığı gibi uygulamıyor. Argus'un farklılaşabileceği somut bir boşluk.**

### 6.7 Rate limit ile bulk çelişkisi — dokümante edilmiş cevaplar

| Ürün | Batch kaç istek sayılıyor | Kaynak |
|---|---|---|
| **Graph `$batch`** | **N** — her alt-istek ayrı değerlendiriliyor; envelope her alt-istek 429 olsa bile 200 dönüyor; her biri kendi `x-ms-resource-unit`'ini tüketiyor | [throttling](https://learn.microsoft.com/en-us/graph/throttling) |
| **Entra `/bulkUpload`** | **1 çağrı** — içindeki ≤50 operasyondan bağımsız. Bu yüzden Microsoft "çağrı başına 50 op'a kadar doldurun" diyor: **çağrı sayısı bütçesini korumak için** | [inbound-provisioning-api-concepts](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/inbound-provisioning-api-concepts) |
| **Auth0 `/jobs/users-imports`** | **1 çağrı** normal rps/rpm bütçesinde, ama **ayrı bir concurrency bütçesiyle** yönetiliyor (tenant başına 2 iş) — dosyadaki kullanıcı sayısından bağımsız | Auth0 Community + API docs |
| **Okta Workflows Bulk Import** | 50 POST'un her biri normal API çağrısı; doküman **muafiyet belirtmiyor** → **N çağrı**, N ≤ 50 | [concurrency limits](https://developer.okta.com/docs/reference/rl2-concurrency/) |

**Desen:** Ölçeklenen iki tasarım ya (a) **alt-operasyon başına ücretlendirip** client'ı bütçelemeye zorluyor (Graph), ya da (b) **çağrı başına ücretlendirip** ama çağrı-başına-op ve günlük-toplam-çağrı'yı sınırlıyor (Entra) — yani **zarfı** rate-limit ediyor, payload'ı değil, ama zarf boyutunu sınırlayarak kimsenin tek çağrıda sınırsız iş kaçırmasını engelliyor. Auth0 soruyu tamamen atlatıyor: bulk işi rps limiter'ından çıkarıp **küçük tamsayılı bir concurrency semaphore'una** taşıyor. Üçü de meşru. **Hiçbiri "tek HTTP çağrısında N item"ı bedava saymıyor.**

---

## 7. Argus için Somut Tasarım Kararları

> Her madde bir kaynağa dayalı. Numaralar §referanslarına bağlı.

**API şekli ve versiyonlama**

1. **Versiyonu kaynak başına, path'in sonunda taşı** — Keycloak v2'nin `/admin/api/{tenant}/clients/v2` deseni gibi. Global API versiyonu bir big-bang migrasyona zorlar; kaynak-başına versiyonlama her kaynağın kendi hızında evrilmesine izin verir. Keycloak'ın global "Admin API v2" epic'i [#39220](https://github.com/keycloak/keycloak/issues/39220) **"not planned" olarak kapandı**, ama kaynak-bazlı Client API v2 26.7.0'da **çıktı.** Kapsam daraltmak işe yaradı. (§1.3)

2. **PUT = upsert, POST = create, PATCH = RFC 7396 JSON Merge Patch.** stianst'in *"POST sometimes work as a PUT, and sometimes as a PATCH, depends randomly on the endpoint"* itirafı ([#37655](https://github.com/keycloak/keycloak/discussions/37655)) ve vmuzikar'ın *"no create-or-update semantics"* tespiti ([#33049](https://github.com/keycloak/keycloak/discussions/33049)) bu kuralın maliyetini gösteriyor. Merge Patch ayrıca **explicit null** problemini çözüyor — Keycloak `displayName=null`'ın "set edilmedi" mi "null'a set edildi" mi olduğunu bilemiyor. (§1.1, §1.2)

3. **Create yanıtı tam temsili gövdede dönsün** (201 + body), sadece `Location` header'ı değil. stianst: *"very inconvenient to use as it requires separating parsing of location headers."* (§1.1)

4. **Kaynakları hem UUID hem stabil, insan-okunur doğal anahtarla adresle** (`clientId`, `tenantSlug`). Keycloak'ın UUID-only adreslemesi hem API kullanımını ([#37655](https://github.com/keycloak/keycloak/discussions/37655)) hem GitOps'u ([#33049](https://github.com/keycloak/keycloak/discussions/33049)) bozuyor: realm delete/recreate'te ID'ler yeniden üretiliyor ve devasa sahte diff üretiyor ([config-cli #799](https://github.com/adorsys/keycloak-config-cli/issues/799)). (§1.1, §4.1, §4.5)

5. **Sorgu dili olarak SCIM filter syntax'ının (RFC 7644 §3.4.2.2) bir alt kümesini benimse, kendi DSL'ini icat etme** — Keycloak v2 bunu yaptı: `eq/ne/co/sw/ew/pr` + `and/or/not`, `fields=` ile projection. **Ve Keycloak'ın iyi kararını kopyala: bilinmeyen alan → HTTP 400**, SCIM'in "sessizce yoksay"ı değil. Sessiz yoksayma, filtresi hiç uygulanmamış bir sorgunun tüm kayıtları döndürmesi demektir — bu bir güvenlik hatasıdır. (§1.3)

6. **Cursor tabanlı pagination kullan, offset değil.** Keycloak'ın kendi kullanıcısı @Plasmadog (17 Tem 2025) offset pagination'ın **kayıt kaçırdığını** gösterdi: *"Since results are ordered by user Id, and user Ids are not sequential, that user can be skipped."* Keycloak v2 bu uyarıya rağmen `offset`/`limit` seçti — bu hatayı tekrarlama. Yanıtta RFC 5988 `Link` header'ı ver (Keycloak'ın kendi kılavuzunun kuralı). (§1.1, §1.2, §1.3)

7. **Bir kaynağı tek istekte tam yaratılabilir yap.** vmuzikar'ın tespiti: Keycloak'ta "client + roller = 2 çağrı" ([#33049](https://github.com/keycloak/keycloak/discussions/33049)). Çok-istekli entity yaratma her deklaratif aracı bir transaction/rollback problemine sokuyor. İlişkili N+1 problemi için de expansion desteği ver — @schuerg'ün `1 + n + n` şikayeti ([#37655](https://github.com/keycloak/keycloak/discussions/37655)). (§1.1, §4.5)

8. **OpenAPI spec'i koddan üret, elle bakma, ve SDK'ları zorunlu olarak spec'ten generate et.** Okta'nın modeli: *"a snapshot of the OpenAPI spec generated directly from the Okta Management API"*, repo community PR kabul etmiyor, *"All of our management SDKs must be built from this spec."* Karşı örnek Keycloak v1: *"incomplete, and usually not sufficient to generate clients."* Ek olarak Keycloak v2'nin fikrini al: **runtime'da OpenAPI endpoint'i yayınla** — CLI/generator'lar bağlandıkları sunucunun sürümüne uyum sağlar. (§1.8)

**Yetkilendirme ve delegasyon**

9. **Yetkilendirme filtresini veri erişim katmanına koy, handler'a değil.** CVE-2026-17059 tam olarak bunun yokluğundan doğdu: `/users` doğru filtreliyordu ama `role-members` *"without applying the same per-user authorization filter"* aynı token'a tam PII veriyordu. Rust'ta bu tip sistemiyle zorlanabilir: filtrelenmemiş bir kullanıcı koleksiyonunun serileştirilebilir bir tipe dönüşmesi **derleme zamanında imkânsız** olsun (örn. `Vec<User>` asla doğrudan response'a gitmesin, sadece `Authorized<Vec<User>>` gitsin). (§3.2)

10. **Her endpoint'in gerektirdiği izni test ile assert et — annotation'a güvenme.** Zitadel CVE-2025-27507 (**CVSS 9.0**), gRPC servis tanımlarında `org.idp` yerine `iam.idp` yazılmamış olmasından **12 endpoint'i** sıradan kullanıcılara açtı. Argus'ta: her route'un gerektirdiği izin makine-okunur bir manifest'te dursun, ve CI'da (a) manifest'i olmayan route derlemeyi kırsın, (b) her route için "bu izin olmadan 403 döner" testi otomatik üretilsin. (§2.6)

11. **Hiyerarşi mutasyonu (reparent/move) hem kaynak hem hedef üzerinde izin gerektirsin.** CVE-2026-9099 (CVSS 7.7, CWE-639): `GroupResource.addChild()` yetkilendirme kontrolü yapmıyordu; düşük yetkili grup admin'i `realm-admin` grubunu kendi altına taşıyıp hiyerarşik kalıtımla o grubun üyelerine parola sıfırlama yetkisi kazandı → tam realm devralma. GitLab CVE-2026-35595 (`parent_project_id: 0`) **aynı sınıf.** Ek invariant: bir taşıma, taşıyanın efektif izin kümesini **artıramaz**. (§2.5, §2.6)

12. **Credential/token nesnelerinin `owner` alanı immutable olsun.** authentik CVE-2024-37905: herhangi bir kimliği doğrulanmış kullanıcı bir API token yaratıp **token'ın user ID'sini değiştirerek** superuser oldu. Geçici çözüm reverse-proxy'de endpoint bloklamaktı — bu, tasarımın ne kadar kırıldığının göstergesi. Argus'ta token sahipliği yaratılışta sabitlensin, hiçbir update path'i onu değiştiremesin. (§2.6)

13. **Yükseltme kapatmayı statik analizle değil, çalışma zamanı invariant'ıyla çöz.** HRU safety problem (Harrison/Ruzzo/Ullman, CACM 19(8):461–471, 1976) genel halde **karar verilemez**; create operasyonları olmadan bile PSPACE-complete. Yani "bu izin seti güvenli mi?" sorusuna genel bir analizle cevap veremezsin. Uygulanabilir invariant: **hiçbir aktör, kendi efektif izin kümesinin üstünde bir izni hiçbir yolla veremez** (Keycloak'ın beyan ettiği *"administrators can only delegate roles they themselves already possess"* prensibi) — ve bu kontrol rol atama, grup üyeliği, hiyerarşi taşıma, scope mapping, protocol mapper ve token exchange yollarının **hepsinde** aynı merkezî fonksiyondan geçsin. Keycloak bu prensibi beyan etti ama **5 ayrı CVE aldı** çünkü kontrol her yolda uygulanmıyordu. (§2.1, §2.5)

14. **Scope mapping ve protocol mapper'ı ayrıcalık yükseltme yüzeyi olarak sınıflandır.** Keycloak'ta sınırlı yetkili geliştiriciler client protocol mapper/client scope yöneterek **admin rollerini token'a map edip Admin API'ye erişebiliyordu**; CVE-2026-9795 (improper scope mapping enforcement) ve GHSA-95cx-vmr5-3cmr (DCR policy → role forgery via user property mappers, 6 Ağu 2026) aynı aileden. Token'a claim yazabilen her mekanizma, yetkilendirme kararını etkiliyorsa **yetki-veren bir işlemdir** ve #13'teki invariant'a tabidir. (§2.5, §3.1)

15. **Kaynak gizleme (resource hiding) varsayılan olsun: yetkin olmadığın kaynak listede görünmesin, 403 bile alma.** Keycloak Organizations FGAP'ın modeli: *"all other organizations are hidden entirely"* — hem konsolda hem **REST API'de**. 403 dönmek varlık ifşasıdır (enumeration). (§2.2)

16. **Kritik işlemler için re-authentication zorunlu kıl — ama bunu yetkilendirmenin YERİNE değil, ÜSTÜNE koy.** Entra Protected Actions'ın modeli: policy **sign-in'de değil, eylem anında** enforce ediliyor (*"users are prompted only when needed"*). Microsoft'un kendi uyarısını da uygula: *"Don't use protected actions to block access based on identity or group membership… Who has access to specific permissions is an authorization decision and should be controlled by role assignment."* Aday işlemler: hard-delete, izin/policy değişikliği, cross-tenant ayarları, signing key rotasyonu, impersonation başlatma, IdP/LDAP bağlantı ayarları (Zitadel CVE-2025-27507'nin hedefi tam olarak buydu). **Break-glass hesabını policy'den hariç tut** — Microsoft'un açık tavsiyesi. (§2.4, §2.6)

17. **Admin session politikası merkezî olsun ve tüm admin yüzeylerini kapsasın.** Okta'nın 12 saat lifetime + 15 dk idle (NIST'e dayalı) + **ASN session binding** (23 Eki 2023'ten beri varsayılan açık; 3 ayda 9.000+ org benimsedi) + opsiyonel IP binding modelini benimse. Ama Okta'nın **hatasını yapma**: *"Administrative sessions in other Okta applications are unaffected, including Okta Workflows, Okta Access Gateway, and Advanced Server Access."* Bir admin session policy'si sadece konsolu koruyorsa, diğer yüzeyler açık kapıdır. (§3.4)

18. **Admin API token'ları kısa ömürlü VE iptal edilebilir olsun.** Auth0'ın karşı örneği: Management API token'ı **24 saat** ve Auth0'ın kendi ifadesiyle *"Once issued, an access token cannot be revoked."* Keycloak'ın `admin-cli` token'ı **1 dakika** — bu tarafta doğru. Argus: kısa ömür + sunucu tarafı iptal listesi/introspection, admin token'ları için zorunlu. (§1.4, §1.6)

**Çok kiracılık**

19. **Platform-admin API'si ile tenant-admin API'sini AYRI yüzeyler yap** — ayrı audience, ayrı scope namespace'i, ayrı rate limit bütçesi. Auth0 bunu 21 Nis 2026'da yapmak zorunda kaldı: Management API *"is intended to configure tenants globally and is not designed for frequent, granular calls… can quickly become a bottleneck"*, ve müşteriler *"hit a wall with rate limits."* Çözümleri: `my-org/` audience'ı + `read:my_org:details` gibi scope'lar. Argus bunu **1. günde** yapsın. (§5.1)

20. **Tenant bağlamını istemciden ALMA — doğrulanmış token'dan türet.** Auth0 My Organization API'de org bağlamı *"the authenticated user's organization membership"*ten geliyor; istemci hiçbir yerde org ID'si göndermiyor. Bu, IDOR sınıfını **yapısal olarak** ortadan kaldırıyor. Path/subdomain'de tenant görünüyorsa bile, token claim'iyle eşleşme **her istekte** doğrulansın. (§5.2)

21. **"Master tenant'tan her şeyi yönet" modelinden kaçın.** Keycloak: *"The access token must come from the master realm regardless of which realm you're administering"* — master realm hem tek-arıza hem tek-ele-geçirme noktası. Argus'ta tenant admin'i **kendi tenant'ının issuer'ından** aldığı token'la yönetsin; platform admin'i ayrı, dar bir kontrol düzleminden. (§1.4, §5.3)

22. **"Platform admin'i bile göremesin" seçeneğini ürünleştir** — Entra'nın Restricted Management Administrative Unit'i gibi (*"this restriction applies to all other administrators, including Global Administrators"*). Ama Entra'nın tuzağına düşme: RMAU, **PIM ve Entitlement Management ile çalışmıyor.** Argus'ta izolasyon mekanizması, governance mekanizmasıyla aynı gün tasarlansın — sonradan birleştirilemiyor. (§2.4)

**Konfigürasyon**

23. **Export deterministik ve diff'lenebilir olsun: sıralı array'ler, üretilmiş ID'ler ve timestamp'ler opsiyonel olarak çıkarılabilir.** Keycloak'ın export'u deterministik değil; düzeltme core'da değil, [config-cli #799](https://github.com/adorsys/keycloak-config-cli/issues/799)'da client tarafında yapıldı. Bu, her üçüncü-parti aracın aynı işi tekrar çözmesi demek. (§4.1, §4.6)

24. **Secret'ları deklaratif dokümandan referansla ayır** (env var / secret-manager pointer) — asla gömülü, asla maskeli. Keycloak partial export secret'ları `*` ile maskeliyor → doküman ne diff edilebiliyor ne yeniden uygulanabiliyor; Terraform provider'ı ise secret'ları **state'e cache'liyor** ([#1058](https://github.com/keycloak/terraform-provider-keycloak/issues/1058)); Auth0'da `ignore_changes` credential'ları korumuyor ([#1291](https://github.com/auth0/terraform-provider-auth0/issues/1291)). Üçü de aynı kök nedenden: secret, config dokümanının bir alanı olarak modellenmiş. (§4.1, §4.3, §4.6)

25. **Tam CRUD + drift reconciliation ver, "create-only" import verme.** Keycloak'ın `KeycloakRealmImport` CRD'si *"only supports creation… changes performed directly on Keycloak are not synced back"* — o kadar yetersiz ki Keycloak **ayrı bir `keycloak-realm-operator` projesini "temporary workaround" olarak** yayınlamak zorunda kaldı. (§4.4)

26. **"Desired state" ile "runtime state"i API seviyesinde ayır.** vmuzikar'ın [#33049](https://github.com/keycloak/keycloak/discussions/33049)'daki önerisi; sunucu tarafı default'ların drift olarak görünmesini engelleyen tek yapısal çözüm. Auth0 ve Okta Terraform provider'larındaki kalıcı sahte drift ([Auth0 #1312](https://github.com/auth0/terraform-provider-auth0/issues/1312), [Okta #2254](https://github.com/okta/terraform-provider-okta/issues/2254)) bu ayrımın yokluğundan. Somut kural: bir GET, kullanıcının set etmediği alanları **set edilmiş gibi göstermesin** — stianst'in *"I create a client with a couple fields, and get back a client with 50 fields"* şikayeti. (§1.1, §4.6)

27. **Sıralamaya bağlı yapılandırmayı (auth flow execution'ları) deklaratif olarak ifade edilebilir yap.** Keycloak Terraform provider'ında bu, **API sınırlaması nedeniyle explicit `depends_on`** gerektiriyor ([#890](https://github.com/keycloak/terraform-provider-keycloak/issues/890)) — yani deklaratif araca imperative bir kaçış deliği açılmış. Sıra, kaynağın kendi alanı olsun (`order: 10`), ayrı bir API çağrısı değil. (§4.3, §4.6)

**Bulk ve rate limit**

28. **Bulk için async job API'si yap; SCIM `/Bulk`'a yatırım yapma.** RFC 7644 §3.7 iyi spec'lenmiş ama incelenen **her** büyük satıcı (Keycloak, Entra, Okta, PingFederate) `bulk.supported: false` diyor veya hiç yönlendirmiyor; hepsi kendi async job API'sini yazmış. Argus'un modeli: `POST /jobs/...` → **202** + job kaynağı → poll. AIP-151'in eşiğini benimse: **~10 saniyeden uzun her işlem** LRO olsun. AIP-151'in `metadata`/`response` ayrımını al: ilerleme ve kısmî hatalar terminal sonuçtan ayrı tiplerde. (§6.1, §6.2, §6.5)

29. **Job sonuçlarını yeterince uzun sakla ve yapılandırılmış per-item hata dosyası ver.** Auth0'ın hata formatı doğru (kayıt başına makine kodu + insan mesajı, ~19 kod) ama **24 saatte silmesi ve 2 saatte timeout etmesi** kısıtlayıcı. Ayrıca Auth0'ın **tenant başına 2 eşzamanlı iş** limiti o kadar dar ki enterprise müşterilere dokümante API çözümü yerine *"Technical Account Manager'a başvurun"* deniyor — bunu tekrarlama. (§6.2)

30. **Rate limit'i üç bağımsız katman olarak tasarla** (Okta'nın modeli): (a) **bucket bazlı zaman-penceresi** — method + en-uzun-önek eşleşmesiyle endpoint grupları; (b) **eşzamanlılık semaforu** — *"how many requests processing at the same time, not over time"*, Okta'da org başına 75; (c) **aktör bazlı koruma** — kullanıcı başına endpoint başına 10 sn'de 40 istek, tek aktörün tenant kotasını yemesini engellemek için. Microsoft bu üçüncü katmanı **30 Eyl 2025'te sonradan eklemek zorunda kaldı** (per-app/per-user limitini tenant limitinin yarısına düşürdü) — baştan yap. (§1.5, §1.7)

31. **Batch'i zarf olarak rate-limit et ama zarf boyutunu sınırla.** İki meşru model var: Graph **N sayıyor** (alt-istek başına, `x-ms-resource-unit` ile maliyet açık), Entra **1 sayıyor** ama çağrı başına ≤50 op + günde 2.000–6.000 çağrı ile sınırlıyor. Argus: Entra modelini seç (zarf sayılır, boyut sınırlı) — client'ın bütçe hesabı basitleşir. **Ama Graph'ın hatasını yapma:** batch envelope'u 200 dönerken içindeki her şey 429 olursa, client'lar sessizce veri kaybeder. Argus'un batch yanıtı, herhangi bir alt-işlem başarısızsa bunu **zarf seviyesinde de** sinyallesin. (§6.7, §1.7)

32. **`dependsOn` benzeri bağımlılık desteği verirsen, Microsoft'un tavsiyesini kurala çevir: batch ya tamamen sıralı ya tamamen paralel.** Karışık bağımlılık grafiği hem client'ta hem server'da hata kaynağı; başarısız bağımlılık için **424 Failed Dependency** semantiği net. (§1.7)

33. **`Idempotency-Key` header'ını 1. günden, tüm mutating endpoint'lerde destekle** — `draft-ietf-httpapi-idempotency-key-header-07` (15 Eki 2025, hâlâ Internet-Draft) semantiğiyle: RFC 8941 String, **payload fingerprint** ile key-reuse-farklı-payload tespiti, 400/422/409 kod ayrımı. Stripe'ın v2 davranışını al: **başarılı ilk deneme kısa devre yapar, başarısız olan yeniden çalıştırılır**; ve sonucu **sadece çalıştırma başladıktan sonra** kalıcılaştır (validation hataları ve in-flight çakışmalar saklanmasın ki güvenle retry edilebilsinler). Saklama penceresini **açıkça yayınla** (draft bunu API'ye bırakıyor); Stripe v2'nin 30 günü iyi bir referans. Key ≤255 karakter, PII yasak. **Bu bir farklılaşma noktası:** Okta, Auth0, Entra'nın hiçbiri bunu yapmıyor; WorkOS sadece tek bir endpoint'te ve diğerlerinde **header'ı sessizce yutup dedup yapmıyor** — sessiz yutma en kötü seçenek, ya destekle ya reddet. (§6.6)

**Admin UI ve gözlemlenebilirlik**

34. **Admin konsolunu ayrı bir origin'de çalıştır ve tenant-kontrollü her string'i güvenilmez kabul et.** Keycloak'ın stored XSS'leri (CVE-2024-4028 permission adında, GHSA-755v-r4x4-qf7m grup adında) ve HOST-header reflected XSS'i hep **"privileged attacker"** senaryosu: düşük yetkili admin, yüksek yetkili admin'in tarayıcısında kod çalıştırıyor. Delege yönetimde bu, tenant izolasyonunu tek hamlede çökertir. CSRF token'ı **session'a bağlansın** — Keycloak'ın hatası tam olarak buydu (*"not unique to each session"*). Sıkı CSP + `Host` header'ına asla güvenmeyen URL üretimi. (§3.3)

35. **Rate limit gözlemlenebilirliğini ürün özelliği yap.** Okta'nın Rate Limit Dashboard'u referans: bucket başına anlık yüzde, 24 saatlik/1 saatlik ortalama, **top-10 offender** kırılımı (IP / API token / OAuth app), 4 ayrı System Log event tipi (`violation`, `burst`, `warning`, `concurrency violation`) ve yapılandırılabilir eşikte e-posta uyarısı. Bir admin API, kotasının nerede tükendiğini gösteremiyorsa operasyonel olarak kullanılamaz. **Uyarı:** metrik etiketlerini istekten türetme — GHSA-3692-rrj9-24qw (6 Ağu 2026) tam olarak *"unbounded metric cardinality via request-controlled error text"*. (§1.5, §3.1)

36. **Impersonation'ı ayrı bir explicit scope yap ve her kullanımını denetlenebilir kıl.** Keycloak FGAP V2 `impersonate`'i explicit scope yaptı — doğru karar; ama dönen token hedef kullanıcının kendi token'ından **ayırt edilemiyor.** Argus: impersonation token'ı `act` (actor) claim'i taşısın ki downstream servisler ayırt edebilsin, ömrü normal token'dan **kısa** olsun, ve #16'daki re-auth kapısının arkasında dursun. (§3.5, §2.2)

37. **Rust'ın bellek güvenliğine güvenip yetkilendirme testlerinden kısma.** Keycloak advisory'lerinin ilk sayfasında (10 kayıt, 2026) **7'si "bypass"** sınıfı — authorization bypass, signature validation bypass, restriction bypass, boundary bypass. **Sıfır** memory-safety, **sıfır** injection. Özellikle iki tanesi (GHSA-2888-g6qc-w4mj "unnormalized URI matching", GHSA-f5p5-6xmx-p252 "incorrect URI comparison") **URI normalizasyonu** — path tabanlı yetkilendirme yapıyorsan, karşılaştırmadan önce tek bir kanonikleştirme fonksiyonundan geç ve bunu property test'le doğrula. (§3.1)

38. **FGAP'ı "bitmiş özellik" sanma — kademeli açılabilir ve kapatılabilir olsun.** Keycloak FGAP V2'yi Nisan 2025'te yayınladı ve **ilk ~14 ayda en az 5 ayrıcalık yükseltme CVE'si aldı** (CVE-2025-7784, CVE-2026-9099, CVE-2026-3121, CVE-2026-9795, CVE-2026-9796). Keycloak'ın doğru yaptığı şey: **realm başına bağımsız etkinleştirme** — sorun çıkan tenant'ta kapatılabiliyor. Argus'ta da delege yönetim tenant başına flag'lensin ve **V1'den V2'ye otomatik migrasyon vaat etme** (Keycloak da veremedi). (§2.2, §2.5)

---

## 8. Doğrulanamayanlar

1. **Keycloak `realm-management` rollerinin tam resmî listesi ve açıklamaları** — Red Hat 26.2 Server Admin Guide Chapter 11 ve keycloak.org karşılığı, fetch sırasında "Full list of permissions" bölümünden önce kesildi. Rol isimleri ekosistemde tutarlı ama **resmî tablo doğrulanmadı.**
2. **Keycloak'ın toplam GHSA advisory sayısı ve tam sınıf dağılımı** — sadece ilk sayfa (10 kayıt, hepsi 2026) çekilebildi; arama bütçesi tükendi.
3. **CVE-2026-3121, CVE-2026-9795, CVE-2026-9796 için CVSS skorları, tam saldırı yolu ve kesin düzeltme sürümleri** — GitHub issue'ları advisory placeholder'ı niteliğinde, teknik detay içermiyor.
4. **Auth0 ve Microsoft Graph'ın OpenAPI spec'i üretip üretmediği / elle mi yazdığı** — arama bütçesi tükendiği için hiç araştırılamadı.
5. **Auth0 Management API'nin güncel rps/rpm rakamları** — topluluk kaynakları ~50 rps / 1000 rpm diyor ama resmî sayfada tier bazlı tablo bulunamadı; Auth0 bu sayıları geçmişte değiştirdi. **Gösterge niteliğinde, bugün için otoriter değil.**
6. **Okta'nın `/api/v1/users` gibi spesifik endpoint'ler için sayısal rate limit tavanları ve abonelik tier'ına göre farkları** — Okta bunları dokümanda vermiyor, org içindeki Rate Limit Dashboard'a yönlendiriyor.
7. **PingFederate'in `bulk.supported: false` değeri** — birincil PingFederate doc sayfası fetch edilemedi; arama özeti üzerinden. **Muhtemelen doğru ama bağımsız doğrulanmadı.**
8. **Salesforce, OneLogin, Google Workspace'in SCIM `ServiceProviderConfig.bulk.supported` değerleri** — hiç araştırılmadı.
9. **AIP-151'in `WaitOperation` semantiği ve polling-vs-notification tradeoff'unun resmî ele alınışı** — çekilen AIP-151 sayfası bunları içermiyordu; ayrı `operations.proto`/linter dokümanlarında.
10. **keycloak-config-cli ve terraform-provider-keycloak release'lerinin gün-seviyesi tarihleri** — GitHub API rate-limit'lendiği için WebFetch özetlerinden alındı, ham JSON'dan değil. **Sürüm sırası ve "aktif bakımda" durumu sağlam; kesin tarihler yaklaşık.**
11. **`keycloak/keycloak-realm-operator`'ın güncel star/issue sayıları ve olgunluk değerlendirmesi** — tek fetch'ten, ikinci kaynakla çapraz kontrol edilmedi.
12. **authentik'in resmî Kubernetes operator konusundaki en güncel duruşu** — sadece 2023 tarihli, uygulanmamış [#5675](https://github.com/goauthentik/authentik/issues/5675) ve topluluk alternatifleri bulundu; çok yeni bir değişiklik olmuş olabilir.
13. **Keycloak impersonation "best practice"leri** (5 dk token ömrü, secrets manager kullanımı) — kaynak Medium/blog yazıları, **birincil kaynak değil.**
14. **Çok kiracılıkta tenant bağlamı taşıma konusunda birincil spec/standart kaynağı** — bulunanlar ağırlıklı blog; §5.2'deki sonuç Auth0'ın somut tasarımı ve Zitadel CVE'sinden **çıkarım** yoluyla desteklendi, normatif bir dokümandan değil.
15. **CVE-2024-3656'nın hangi spesifik admin REST endpoint'lerinin korumasız olduğu** — advisory endpoint isimlerini, kök nedeni ve CVSS'i vermiyor.
16. **Okta Workflows Bulk User Import'un "10.000 vs 50 kayıt" tutarsızlığının çözümü** — Okta'nın kendi destek yanıtı da açıklayamadı, resmî destek kaydına yönlendirdi.


---

# KISIM VII — İŞLETİM

*Gözlemlenebilirlik, dağıtım ve test — ürünü çalışır ve doğrulanabilir tutan katman.*
