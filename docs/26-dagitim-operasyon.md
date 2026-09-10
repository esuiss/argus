# 26. Dağıtım ve operatör deneyimi

> `ARGUS.md` §26'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§26 §X` referansları aynı anlamda.



---

## 1. Kurulum ve İlk Çalıştırma Deneyimi

### 1.1 Keycloak'ın `build` / `start` ikiliği — neden var, ne acıtıyor

Keycloak, Quarkus **augmentation** modeli üzerine kurulu. Resmî doküman ayrımı net biçimde tanımlıyor: **build options** imaja kalıcı olarak gömülür, **configuration options** çalışma anında uygulanır ([keycloak.org/server/configuration](https://www.keycloak.org/server/configuration)).

> "This `build` command performs a set of optimizations for the startup and runtime behavior."
> "The `--optimized` parameter tells Keycloak to assume a pre-built, already optimized Keycloak image is used. As a result, Keycloak avoids checking for and running a build directly at startup."

Build adımının yaptıkları: kurulu provider'lar hakkında **closed-world assumption**, konfigürasyon dosyalarının önceden parse edilmesi (I/O azaltma), veritabanına özgü kaynakların önceden yapılandırılması.

**Production mode "secure by default"**:
> "Production mode expects a hostname to be set up and an HTTPS/TLS setup to be available when started."
> "HTTP is disabled as transport layer security (HTTPS) is essential"

**Operatörlerin şikayeti — somut kanıt:** [keycloak/keycloak#30460](https://github.com/keycloak/keycloak/issues/30460) — `start-dev` ile bir kez çalıştırdıktan sonra `start` şu hatayla patlıyordu:

> "You can not 'start' the server in development mode. Please re-build the server first, using 'kc.sh build' for the default production mode."

Bug/regression olarak etiketlendi, `@ahus1` tarafından PR #30461 ile kapatıldı. Ders: **iki modlu tasarım, mod geçişlerinde sessiz/kafa karıştırıcı hata sınıfları üretiyor.** Kullanıcı "aynı komutu çalıştırdım, biri oldu biri olmadı" durumuna düşüyor.

**Dev veritabanı:** Keycloak'ın varsayılanı `dev-file` (H2) ve doküman açıkça "unsuitable for production and must be replaced" diyor ([keycloak.org/server/db](https://www.keycloak.org/server/db)). Getting-started sayfası tek komut veriyor ([keycloak.org/getting-started/getting-started-docker](https://www.keycloak.org/getting-started/getting-started-docker)):

```
docker run -p 127.0.0.1:8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.7.3 start-dev
```

Yani "5 dakikada IdP" hedefine Keycloak *ulaşıyor* — ama dev'den prod'a geçiş **uçurum**: farklı DB, farklı komut, zorunlu hostname + TLS, ayrı build adımı.

### 1.2 Rakiplerin kurulum modelleri (2026 durumu)

| Ürün | Süreç modeli | DB | Lisans | İlk çalıştırma |
|---|---|---|---|---|
| **Keycloak** | Tek JVM süreci (+ Operator) | PG 14–18, MySQL, MariaDB, Oracle, MSSQL, Aurora ([db docs](https://www.keycloak.org/server/db)) | Apache 2.0 | tek `docker run`, H2 |
| **Zitadel** | 4 konteyner: Traefik + API (Go) + Login (Next.js) + Postgres ([compose docs](https://zitadel.com/docs/self-hosting/deploy/compose)) | PostgreSQL (CockroachDB v3'te düştü) | AGPL-3.0 (v3'ten beri) | "2 minutes", `docker compose up -d --wait` |
| **authentik** | server + worker + PostgreSQL ([install docs](https://docs.goauthentik.io/install-config/install/docker-compose/)) | PostgreSQL 14–18 ([config docs](https://docs.goauthentik.io/install-config/configuration/)) | ⚠️ doğrulanmadı | compose, min **2 CPU / 2 GB RAM** |
| **Ory** | Ayrı ayrı Kratos/Hydra/Keto/Oathkeeper | PG, MySQL, CockroachDB; **SQLite "must not be used in a production deployment"** ([self-hosted deployment](https://www.ory.com/docs/self-hosted/deployment)) | Apache 2.0 + OEL | binary 5–15 MB, "without system dependencies" ([hydra](https://github.com/ory/hydra)) |
| **SuperTokens** | Core (:3567) + Backend SDK ([self-host docs](https://supertokens.com/docs/deployment/self-host-supertokens)) | **Sadece PostgreSQL** (Core 11.0.0 MySQL/MongoDB'yi düşürdü) | Core Apache 2.0 + lisans anahtarlı premium | tek `docker run` |
| **Casdoor** | Tek Go binary + React SPA ([github](https://github.com/casdoor/casdoor)) | MySQL/PG/**SQLite**/MSSQL (XORM) | Apache 2.0 | `docker run -p 8000:8000 casbin/casdoor-all-in-one` → SQLite, admin/123 |
| **Kanidm** | **Tek konteyner**, kendi DB'si ve replikasyonu ([github](https://github.com/kanidm/kanidm)) | Kendi "high-performance database and replication system" | MPL-2.0 | tek konteyner, 2-node HA replikasyon |
| **Pocket ID** | Tek binary veya Docker ([github](https://github.com/pocket-id/pocket-id)) | SQLite/Postgres | BSD-2-Clause | passkey-only |

### 1.3 Gömülü veritabanı ile başlamak — bir IdP için mantıklı mı?

Sektörde **üç farklı duruş** var:

1. **Yasak (Ory):** "SQLite is supported (in-memory and persistent) but **must not be used in a production deployment**". Sadece dev.
2. **Meşru (Casdoor, Pocket ID):** `casdoor-all-in-one` SQLite ile çalışır; Pocket ID SQLite'ı gerçek dağıtım seçeneği olarak sunar.
3. **Kendi motorunu yaz (Kanidm):** "its own high-performance database and replication system, developed based on enterprise LDAP server experience" — 3.000 kullanıcıda FreeIPA'ya göre "approximately three times faster search operations".
4. **Sahte gömülü (Keycloak):** H2 `dev-file`, prod'da açıkça yasaklı — ve bu, dev/prod uçurumunun ana kaynağı.

**Argus için çıkarım:** Keycloak modelinin en büyük operasyonel bedeli, dev-mode'un prod'la **aynı kod yolunu kullanmaması**. Casdoor/Pocket ID modeli (aynı binary, aynı şema, sadece farklı DSN) daha az sürpriz üretiyor. Ancak PostgreSQL'e özgü özellikler (`ANY k` quorum sync commit, `NOT VALID` constraint, advisory lock) kullanılacaksa SQLite ile şema paritesi maliyetli olur.

### 1.4 "5 dakikada çalışan IdP" — kim en yakın?

Ölçülebilir iddialar:
- **Zitadel: "2 minutes"** (resmî compose dokümanı), varsayılan admin `zitadel-admin@zitadel.localhost` / `Password1!`
- **Casdoor:** tek `docker run`, SQLite, demo kimlik bilgileri hazır
- **Keycloak:** tek `docker run start-dev`
- **authentik:** 4 adım (wget compose.yml → openssl ile parola üret → compose up → akadmin parolası ayarla)

Gerçekçi. Ama **hepsinin ortak kusuru:** "5 dakikada çalışan" şey, "5 dakikada production" değil. Zitadel'in masterkey uyarısı bunun tipik örneği — aşağıda (§5.2).

---

## 2. Konteyner ve Kubernetes

### 2.1 Distroless / scratch imajlar — Rust için gerçek rakamlar

[GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless) resmî rakamları (tümü Debian 13 tabanlı):

| İmaj | Boyut | İçerik |
|---|---|---|
| `gcr.io/distroless/static-debian13` | **~2 MiB** | statik binary'ler için, shell/paket yöneticisi yok |
| `gcr.io/distroless/cc-debian13` | — | C/C++ runtime kütüphaneleri (glibc) |
| `gcr.io/distroless/base-debian13` | — | libc + **CA certificates + tzdata** |
| `base-nossl-debian13` | — | SSL sertifika demeti olmadan |

> "the smallest distroless image...is around 2 MiB. That's about 50% of the size of `alpine` (~5 MiB), and less than 2% the size of `debian` (124 MiB)."

`:debug` varyantları busybox shell içerir; `nonroot` tag'leri düşük ayrıcalıkla çalışır. Mimariler: amd64, arm64, arm, s390x, ppc64le, riscv64.

**Rust için özel rakamlar:** cargo-chef + distroless ≈ **26.2 MB**, musl + scratch ≈ **8.38 MB** — ⚠️ bu rakamlar ikincil kaynaktan ([cloudnativefolks blog](https://blog.cloudnativefolks.org/cargo-chef-speed-up-your-docker-builds-reduce-image-size-of-your-rust-project)), doğrulanmadı. [Rust Project Primer](https://rustprojectprimer.com/releasing/containers.html) sadece "a Rust binary on `debian:bookworm-slim` or `alpine` is typically under 50 MB" diyor.

**⚠️ musl tuzağı (kritik):** [andygrove.io, Mayıs 2020](https://andygrove.io/2020/05/why-musl-extremely-slow/) — musl ile derlenen Rust kodu çok-thread'li benchmark'ta **~30x yavaş** çalıştı. Önerilen çözüm jemalloc'a geçmek (ripgrep'in aynı sorunu böyle çözdüğü belirtiliyor), ama yazar segfault aldı ve musl'u tamamen bırakıp `debian:buster-slim`e (89 MB) döndü. Yazarın sonucu: sorun sadece allocator değil, "fundamental issues with threading in musl".
⚠️ **DOĞRULANMADI:** Bu 2020 tarihli; musl 1.2.x sonrası mallocng iyileştirmeleri var. 2026 için yeniden ölçülmeli. Ama **Argus gibi Argon2 ağırlıklı, çok-thread'li, yoğun allocation yapan bir iş yükü için musl'a körlemesine geçmek riskli.**

### 2.2 cargo-chef ile build cache

[cargo-chef](https://github.com/LukeMathWalker/cargo-chef) üç aşama: **planner** (`Cargo.toml`/`Cargo.lock` iskeletinden recipe üretir) → **cook** (`cargo chef cook` sadece bağımlılıkları derler, bu katman cache'lenir) → **builder** (uygulama kodu). "up to 5x" hızlanma iddiası.

**README'nin iki uyarısı:**
1. "cargo chef cook and cargo build must be executed from the same working directory" — cargo mutlak yol metadata'sı kullandığı için.
2. "cargo build will build local dependencies (outside of the current project) from scratch, even if they are unchanged" — timestamp tabanlı fingerprint mantığı yüzünden. **Workspace dışı path dependency kullanıyorsanız cache tutmaz.**

### 2.3 Keycloak Operator (CRD modeli) — sınırlar ve gerçek arızalar

**CRD olgunluğu:** [keycloak/keycloak#45795](https://github.com/keycloak/keycloak/issues/45795) — `Keycloak` ve `KeycloakRealmImport` CRD'leri **yıllarca v2alpha1'de kaldı**; 26.6.0'da v2beta1'e terfi ettirildi (PR #45840). Gerekçe: "the CRDs are more mature and to differentiate the versioning from new CRDs, such as those needed for Clients".

**KeycloakRealmImport'un yapısal sınırı:** Realm Import CR sadece **yeni realm oluşturur** — güncellemez, silmez; Keycloak üzerinde doğrudan yapılan değişiklikler CR'a geri senkronlanmaz. Yani GitOps illüzyonu: CR'ınız gerçeğin kaynağı *değil*.

**Gerçek arızalar:**
- [#45966](https://github.com/keycloak/keycloak/issues/45966) (3 Şubat 2026, KC 26.5 / Operator 26.5.1 / K8s 1.34.2 / PostgreSQL 17): İçe aktarılan realm DB'ye yazılıyor ama Admin Console'da **StatefulSet restart edilene kadar görünmüyor**. Kök neden raportörün ifadesiyle: "the running Keycloak nodes ... do not receive an invalidation event via Infinispan/JGroups" — geçici Import Job ile çalışan pod'lar arasında cache invalidation kanalı yok. PR #46019 ile kapatıldı.
- [#24526](https://github.com/keycloak/keycloak/issues/24526): CR'lar GitOps pipeline'ında art arda uygulandığında realm import Job'ı **operand hazır olmadan** başlıyor, backoff limiti 6'ya kadar pod başarısız oluyor.

**Ders:** CRD'lerle yönetilen bir IdP'de, *veritabanına yazan yan süreçler* (import job'ları, CLI'lar) ile *çalışan node'ların cache'i* arasındaki invalidation, tasarımın birinci sınıf parçası olmak zorunda. Keycloak bunu 26.7'de **DB-backed outbox pattern**'e taşıdı (§4.4).

### 2.4 Helm chart vs Operator — ve Bitnami felaketi

**Keycloak'ın resmî Helm chart'ı yok.** [Kurulum dokümanı](https://www.keycloak.org/operator/installation) sadece OLM veya:
```
kubectl apply -k 'github.com/keycloak/keycloak-k8s-resources/kubernetes?ref=26.7.3'
```
Ve güçlü bir uyarı: "strongly recommend using manual approval mode" — otomatik operator güncellemesi istenmeyen Keycloak upgrade'i tetiklemesin diye.

**Bitnami'nin 2025 değişikliği** ([bitnami/charts#35164](https://github.com/bitnami/charts/issues/35164), 28 Ağustos 2025 yürürlük):
- `docker.io/bitnami` → sadece "limited community-tier subset", yalnızca **latest** tag, dev kullanımı için
- Sürümlü/eski imajlar → `docker.io/bitnamilegacy` — "will receive no further updates or support and should only be used for temporary migration purposes"
- `docker.io/bitnamicharts` OCI Helm artifact'leri **güncelleme almıyor**; bundle edilen imajlar override edilmezse deploy'lar patlıyor
- Public katalog silinmesi 29 Eylül 2025'e ertelendi; brownout'lar 28–29 Ağu, 2–3 Eyl, 17–19 Eyl 2025
- GitHub'daki chart ve container kaynak kodu Apache 2.0 altında kaldı

Doğrulama: [hub.docker.com/r/bitnamilegacy/keycloak](https://hub.docker.com/r/bitnamilegacy/keycloak) — "This repository is **no longer updated**... this repository may be removed in the future".

**Argus için ders:** Üçüncü taraf chart/imaj dağıtım kanalına bağımlılık, tek bir kurumsal karar ile gecede kırılabilir. **Kendi Helm chart'ınızı kendi OCI registry'nizde yayınlayın ve chart'ın imaj referansını kendi imajınıza sabitleyin.**

**Helm mi Operator mı?** Gözlem: Operator, *ancak* CRD'lerin çözdüğü gerçek bir problem varsa (rolling update uygunluk kararı, realm reconciliation, DB migration orkestrasyonu) değer üretiyor. Keycloak Operator'ün en çok değer kattığı yer bu üçüncüsü:

### 2.5 Rolling update ve oturum kaybı

Keycloak Operator'ün `spec.update.strategy` seçenekleri ([rolling-updates](https://www.keycloak.org/operator/rolling-updates)):
- **`RecreateOnImageChange`** (varsayılan): imaj değişince StatefulSet'i **scale down** eder → **downtime**
- **`Auto`**: rolling mi recreate mi gerektiğini kendisi tespit eder; bunun için geçici bir **Job** başlatır
- **`Explicit`**: sadece `spec.update.revision` değişince rolling yapar

Karar mekanizması `update-compatibility` komutu ([docs](https://www.keycloak.org/server/update-compatibility)):
```
bin/kc.sh update-compatibility metadata --file=/path/to/file.json   # eski sürümle
bin/kc.sh update-compatibility check --file=/path/to/file.json      # yeni sürümle
```
Exit code'ları: **0** = rolling mümkün, **3** = rolling imkânsız (shutdown gerek), **4** = rolling-updates feature kapalı.

Recreate gerektiren değişiklikler: sürüm farkı, `multi-site` / `persistent-user-sessions` / `stateless` feature toggle'ları, **db vendor / cache type / cache stack / connection parametreleri** değişimi.

**Uyarı:** Desteklenmeyen `podTemplate` alanı kullanılıyorsa Operator, podTemplate veya ConfigMap/Volume'dan gelen secret değişikliklerinden **yanlış sonuç çıkarabilir**.

**Stateless tasarımda oturum kaybı:** Keycloak 26.7'nin `stateless` preview'u ile authentication session'ları, action token'ları ve brute-force sayaçları DB'ye taşındı ([Multi-Cluster v2 and Stateless Mode, Temmuz 2026](https://www.keycloak.org/2026/07/multi-cluster-v2-and-stateless-mode)) — sonuç: **"Full cluster restarts no longer reset volatile state during upgrades."** Bedeli: auth etkileşimi başına **+8-10 ms** gecikme, **DB CPU ve IOPS'un kabaca 2 katına çıkması**.

### 2.6 Graceful shutdown — SIGTERM sonrası ne kadar beklemeli

**Keycloak'ın somut değerleri** ([all-config](https://www.keycloak.org/server/all-config)):

| Seçenek | Varsayılan | Açıklama |
|---|---|---|
| `shutdown-delay` (`KC_SHUTDOWN_DELAY`) | **1s** | "Length of the pre-shutdown phase during which the server prepares for shutdown" — LB reconfig + TLS/HTTP keepalive drain |
| `shutdown-timeout` (`KC_SHUTDOWN_TIMEOUT`) | **10s** | "The shutdown period waiting for currently running HTTP requests to finish and distributed caches to settle" |

26.6 ile geldi: "graceful shutdown of the HTTP stack, which includes delaying a shutdown after receiving a termination signal, connection draining for HTTP/1.1 and HTTP/2 connections" ([26.6.0 release notes](https://www.keycloak.org/2026/04/keycloak-2660-released)).

**Kubernetes'teki asıl yarış koşulu** — bu ürüne özgü değil, Kubernetes'in kendi tasarımı: Pod `Terminating` işaretlenir, control plane EndpointSlice'tan çıkarır, kubelet `preStop` çalıştırır, dönünce **SIGTERM** gönderir, `terminationGracePeriodSeconds` (varsayılan **30s**) sonunda SIGKILL. Kritik nokta:

> "endpoint removal and SIGTERM are not sequenced against each other. Endpoint removal has to reach every kube-proxy, every ingress controller, and every sidecar proxy in the mesh. That propagation is eventually consistent and takes real time, often a second or more on a busy cluster, while signal delivery to a local process takes microseconds."
> — [blog.codercops.com, 2026](https://blog.codercops.com/blog/graceful-shutdown-containers-sigterm-drain-guide-2026)

Yani `preStop sleep` **uygulamanın drain mantığı için değil**, endpoint propagasyon boşluğunu kapatmak için var.

**In-flight OAuth akışları için özel durum:** Authorization Code akışı **tek bir HTTP isteğinden uzun**. Kullanıcı `/authorize`'a gelir, login formunu doldurur, `/login-actions/authenticate`'e POST eder, sonra `/token`'a gider. Bu adımlar arası dakikalar geçebilir. Stateless olmayan tasarımda node ölürse akış kaybolur; **Keycloak'ın çözümü tam olarak auth session'ları DB'ye taşımak oldu.** Argus için aynı sonuç: **in-flight OAuth akışlarını graceful shutdown süresiyle korumaya çalışmayın — DB'ye yazın.**

### 2.7 Probe tasarımı

Keycloak dört endpoint sunuyor, **9000 numaralı management portunda** ([observability/health](https://www.keycloak.org/observability/health)):
- `/health/started` — "Startup probe used for initial startup of Keycloak before the liveness probe takes over"
- `/health/live` — başarısızsa restart gerekir
- `/health/ready` — "Checks if Keycloak is ready to process requests or not"
- `/health` — hepsinin toplamı

Kontrol edilenler: **DB connection pool durumu, cluster network partition durumu, graceful shutdown hazırlığı, server initialization**. Doküman `exec` liveness yerine **HTTP Probe** öneriyor; mTLS varsa `https-management-client-auth`'u `request` veya `none` yapın ki probe istekleri client sertifikası istemesin.

26.6'da eklenen kritik detay: **"Startup and liveness probes return UP status during migrations"** — yani şema göçü sırasında pod öldürülmüyor. Bu, uzun süren migration'ın restart döngüsüne girmesini önleyen zorunlu bir davranış.

### 2.8 PDB, topology spread, anti-affinity

**PodDisruptionBudget** ([k8s docs](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)):
- Sadece **gönüllü** kesintileri (node drain) korur; donanım arızası, kaynak baskısı kaynaklı eviction ve uygulama çökmesi **kapsam dışı**
- `minAvailable` veya `maxUnavailable` — ikisi birden **değil**
- Stateless frontend için önerilen: `minAvailable: 90%`
- `minAvailable: 100%` / `maxUnavailable: 0` → **node drain sonsuza kadar asılı kalır**
- Sadece **healthy** pod'lar sayılır (Running + readiness geçmiş)
- `.spec.unhealthyPodEvictionPolicy`: varsayılan `AlwaysAllow`; `IfHealthyBudget` bütçeyi ihlal etmiyorsa evict eder

**Topology spread** ([k8s docs](https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/)) — IdP için doğru desen:
```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule     # AZ dağılımı SERT kısıt
    minDomains: 3
    labelSelector: { matchLabels: { app: argus } }
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway    # node dağılımı YUMUŞAK
    matchLabelKeys: [pod-template-hash]
```
`matchLabelKeys: [pod-template-hash]` rolling update sırasında eski ve yeni ReplicaSet'in pod'larının birbirini saymasını engeller — Deployment'larda kritik.

Topology spread vs anti-affinity farkı: spread `maxSkew` ile **dengeleyici**, anti-affinity ikili (evet/hayır) **ayırıcı**; spread çok domain için tasarlanmış, anti-affinity küçük kısıtlar için daha iyi.

**Keycloak Operator varsayılanı:** "By default, pods receive automatic spread constraints across zones and nodes" ve CR "affinity, tolerations, topology spread constraints, and the priority class name" alanlarını expose ediyor. Varsayılan kaynak: **memory request 1700 MiB, limit 2 GiB** ([advanced-configuration](https://www.keycloak.org/operator/advanced-configuration)). PDB **native CR alanı değil** — kendiniz yazmalısınız.

**Veritabanı katmanı için:** [CloudNativePG](https://cloudnative-pg.io/docs/devel/architecture) net:
> "The multi-availability zone Kubernetes architecture with three (3) or more zones is the one that we recommend for PostgreSQL usage."
> "Deploy Postgres nodes in multiples of three—ideally with one node per availability zone."

Shared-nothing: farklı worker node, farklı AZ, **her node'da yerel disk** (paylaşımlı volume değil). Storage-level replikasyona açıkça karşı çıkıyor. Ve kritik sınır: **"CloudNativePG cannot perform any cross-cluster automated failover"** — replica cluster promote'u manuel/harici orkestrasyon gerektirir. Bu, sizin "tek bölge, 3 AZ" tercihinizi doğrudan destekliyor.

---

## 3. Konfigürasyon Yönetimi

### 3.1 Sır yönetimi

**External Secrets Operator** ([overview](https://external-secrets.io/latest/introduction/overview/)): `SecretStore` (namespace'li, *nasıl* erişilir) / `ClusterSecretStore` (küme geneli) / `ExternalSecret` (*ne* çekilir) / `PushSecret`. 40+ provider (AWS SM, Azure KV, Vault, GCP SM, 1Password, Bitwarden...).

⚠️ **ESO'nun kapsam dışı bıraktığı şey kritik:** "there is no Secret Operator that handles the lifecycle of the secret" — **secret döndüğünde pod'ları yeniden başlatmak ESO'nun işi değil.** Rotation'ı gerçekten çalıştırmak için Reloader tarzı ayrı bir mekanizma veya uygulamanın kendisinin dosyayı yeniden okuması gerekir.

**Vault PostgreSQL secrets engine** ([docs](https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql)): dinamik kimlik bilgisi, lease TTL (ör. 1h), `creation_statements` ile rol tanımı:
```sql
CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
```
**Static Roles** `rotation_period` ile root credential olmadan parola döndürür. Uygulamaya yüklediği yük: **lease süresi dolmadan yenileme + TTL bitince yeniden bağlanma mantığı.** Bu, connection pool'lu bir Rust servisinde önemsiz değildir — pool'daki mevcut bağlantılar geçerli kalır ama yeni bağlantılar yeni parolayı kullanmalıdır.

**Rust'ta bellek hijyeni:**
- [`secrecy`](https://docs.rs/secrecy/latest/secrecy/): drop'ta zeroize eder, ama açıkça — "does not provide more advanced memory protection mechanisms like those based on mlock(2)/mprotect(2)". Yani **swap'a ve core dump'a karşı koruma yok.**
- [`zeroize`](https://docs.rs/zeroize/latest/zeroize/): derleyicinin optimize edip atmasını engelleyen taşınabilir sıfırlama. **Sınırları net:** `Vec`/`String`/`CString` implementasyonları backing buffer'ın tüm kapasitesini sıfırlar, ama **buffer reallocation ile daha önce kopya çıkarılmadığını garanti edemez** → buffer'ları doğru kapasiteyle initialize edip realloc'u engellemek gerekir. Ayrıca Spectre/Meltdown sınıfı mikromimari sızıntılara karşı **hiçbir garanti vermiyor**.
- [`memsafe`](https://crates.io/crates/memsafe): `mmap` + `mlock`/`VirtualLock`, Linux'ta ek olarak `MADV_DONTDUMP` ve `MADV_WIPEONFORK`. **İmzalama anahtarları için doğru katman bu.**

### 3.2 Konfigürasyon doğrulama: fail-fast

En iyi örnek Keycloak'ın production mode'u: hostname ve TLS yoksa **başlamayı reddediyor** ("startup will fail intentionally with an error message, preventing insecure deployments"). Bu doğru desen: *güvensiz konfigürasyon çalışmamalı, uyarı vermemeli.*

Zitadel'in karşıt örneği: masterkey **üretilmezse de başlar**, ama sonradan değiştirilemez (§5.2). Bu, "sessizce yanlış" kategorisinin ders kitabı örneği.

### 3.3 Yanlış yapılandırma tuzakları — sessizce güvensiz hale gelen ayarlar

**(a) redirect_uri eşleştirme — kanıtlanmış ATO vektörü**

[CVE-2024-52289 / authentik](https://securityblog.omegapoint.se/en/writeup-authentik-cve-2024-52289/): authentik redirect URI'yi **regex ile** eşleştiriyordu ve nokta karakterini escape etmiyordu. `https://app.example.com/oauth2/callback` konfigürasyonu, `https://app0example.com/oauth2/callback` ile **eşleşiyordu**. Sonuç:

> "If the victim is already authenticated with the IdP, they are not prompted to authenticate and are directly redirected to the attacker without further user interaction."

Zaman çizelgesi: bildirim 8 Ekim 2024 → authentik'in kendi müşteri portalında PoC 31 Ekim 2024 → yama 21 Kasım 2024 (2024.10.3 ve 2024.8.5). Düzeltme: **varsayılan strict string matching**, regex ancak yönetici açıkça açarsa.

RFC 9700 (OAuth 2.0 Security BCP) confidential ve public client'lar için **exact match** zorunlu kılıyor ve wildcard'ları yasaklıyor. ⚠️ Yayın ayı doğrulanmadı (arama sonucu "March 2025" dedi).

**(b) issuer / hostname — token sahteciliği**

Keycloak dokümanı ([hostname v2](https://www.keycloak.org/server/hostname)):
> "If the hostname was dynamically interpreted from a hostname header, an attacker could manipulate a URL in an email, redirect a user to a fake domain, and steal sensitive data. By explicitly setting the hostname option, we avoid a situation where tokens could be issued by a fraudulent issuer."

**(c) Proxy header güveni — IP allowlist'i çökerten sessiz hata**

[keycloak.org/server/reverseproxy](https://www.keycloak.org/server/reverseproxy) uyarıları aynen:
> "If these headers are incorrectly configured, rogue clients can inject false values and trick Keycloak into thinking the client is connecting from a different IP address than the actual one." — "especially critical if you do any deny or allow listing of IP addresses."
> "Ensure the proxy overwrites (not just appends to) forwarded headers to prevent clients from injecting false values."
> "Do not use `forwarded` or `xforwarded` with TLS passthrough. Misconfiguration will leave Keycloak exposed to security vulnerabilities."
> "Restrict network access so that Keycloak accepts connections only from the proxy"

Bu, brute-force sayaçları ve rate limit'i **sessizce işe yaramaz** hale getiren tuzağın ta kendisi.

**(d) Admin konsolunun internete açık olması:** Keycloak, admin API ve UI'nin **farklı hostname/path** üzerinde sunulmasını öneriyor ("reduce the attack surface"); `KC_HOSTNAME_ADMIN` ile ayrılıyor.

### 3.4 Keycloak "production mode" kontrol listesi — ne zorluyor, ne zorlamıyor

[configuration-production](https://www.keycloak.org/server/configuration-production):

| Madde | Durum |
|---|---|
| TLS/HTTPS | **Zorunlu** (HTTP prod'da kapalı) |
| Hostname | **Zorunlu** (`--hostname` veya `--hostname-strict false`) |
| Production DB | Belgelenmiş, teknik olarak **zorlanmıyor** |
| Reverse proxy | "recommended" |
| `/health/ready` probe | önerilir |
| Admin/public hostname ayrımı | **sadece öneri** |
| Load shedding, `http-max-queued-requests` | **sadece öneri** |
| ≥2 instance | **sadece öneri** |

**Bu tablo Argus için bir fırsat listesi:** "sadece öneri" satırlarının çoğu, ölümcül yanlış yapılandırmalar. Argus bunları başlangıçta zorlayabilir veya en azından "insecure" bayrağı olmadan başlatmayı reddedebilir.

---

## 4. Yükseltme ve Şema Göçü

### 4.1 PostgreSQL'de hangi işlem kilitliyor

[PostgreSQL ALTER TABLE dokümanı, Notes bölümü](https://www.postgresql.org/docs/current/sql-altertable.html):

**Kilit seviyeleri:**
- **ACCESS EXCLUSIVE** — varsayılan, aksi belirtilmedikçe her ALTER TABLE alt komutu
- **SHARE UPDATE EXCLUSIVE** — `SET STATISTICS`, `CLUSTER ON` / `SET WITHOUT CLUSTER`, per-attribute options, **`VALIDATE CONSTRAINT`**, `ATTACH PARTITION`
- **SHARE ROW EXCLUSIVE** — `ADD FOREIGN KEY` (referans edilen tabloda da), trigger enable/disable

**Rewrite gerektirmeyen (metadata-only) işlemler:**
> "When a column is added with `ADD COLUMN` and a non-volatile `DEFAULT` is specified, the default value is evaluated at the time of the statement and the result stored in the table's metadata... making the `ALTER TABLE` very fast even on large tables."

- Non-volatile default ile `ADD COLUMN` → rewrite **yok** (PG 11+)
- Volatile default (`clock_timestamp()`) → **tam rewrite**
- Stored generated column, identity column → **rewrite**
- **Virtual generated column → asla rewrite yok**
- `ALTER TYPE`: "if the `USING` clause does not change the column contents and the old type is either binary coercible to the new type or an unconstrained domain over the new type, a table rewrite is not needed" — aksi halde tablo *ve tüm index'leri* yeniden yazılır

**Expand-contract'ın PostgreSQL'deki altın kuralı:**
> "The main purpose of the `NOT VALID` constraint option is to reduce the impact of adding a constraint on concurrent updates. With `NOT VALID`, the `ADD CONSTRAINT` command does not scan the table and can be committed immediately."

İki adımlı desen:
```sql
ALTER TABLE distributors ADD CONSTRAINT distfk FOREIGN KEY (address)
    REFERENCES addresses (address) NOT VALID;     -- anında commit
ALTER TABLE distributors VALIDATE CONSTRAINT distfk;  -- SHARE UPDATE EXCLUSIVE
```

**İki tehlikeli detay:**
1. **Rewrite eden formlar MVCC-safe değil:** "After a table rewrite, the table will appear empty to concurrent transactions, if they are using a snapshot taken before the rewrite occurred."
2. Rewrite "will temporarily require as much as double the disk space".

**PostgreSQL 18'in getirdiği (zero-downtime için en önemli değişiklik):**
- NOT NULL constraint'leri artık gerçek `pg_constraint` kayıtları, isimlendirilebiliyor
- **`ALTER TABLE ... ALTER COLUMN ... SET NOT NULL NOT VALID`** destekleniyor → sonra `VALIDATE CONSTRAINT` ile SHARE UPDATE EXCLUSIVE altında doğrula. Daha önce `SET NOT NULL` tüm tabloyu ACCESS EXCLUSIVE altında tarıyordu. ([PG18 release notes](https://www.postgresql.org/docs/release/18.0/))
- Geçerli bir `CHECK` constraint NULL olmadığını kanıtlıyorsa tablo taraması atlanabilir

**PostgreSQL 18 pg_upgrade:** planner istatistiklerini koruyor (upgrade sonrası uzun `ANALYZE` yok), `--jobs` ile paralel kontroller, `--swap` modu (dizin takası, en hızlı), `--set-char-signedness`.

### 4.2 Rust migration araçları — olgunluk ve rollback

| Araç | Reversible | Notlar |
|---|---|---|
| **sqlx** | ✅ `sqlx migrate add -r <name>` → `.up.sql` / `.down.sql`; "All the subsequent migrations will be reversible as well". `sqlx migrate run` / `revert` / `info`, `--source` ile dizin ([sqlx-cli README](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md)) | Dosya adı `<VERSION>_<DESCRIPTION>.sql`, VERSION i64 > 0 |
| **refinery** | ❌ "Refinery's design was based on flyway and shares its earlier philosophy on undo/rollback migrations—to undo/rollback a migration, you have to generate a new one" ([github](https://github.com/rust-db/refinery)) | postgres, tokio-postgres, mysql, mysql_async, rusqlite, tiberius; **sqlx ile de `Config` üzerinden çalışır** |
| **diesel_migrations** | ✅ up/down | Diesel DSL'ine bağlı |

⚠️ sqlx'in advisory-lock ile eşzamanlı migration koruması ve checksum/dirty-state davranışı **doküman üzerinden doğrulanamadı** — kaynak koddan teyit edilmeli.

**Pratik gerçek:** Down migration'lar production'da nadiren çalıştırılır. Zero-downtime'ın gerçek cevabı rollback değil, **expand-contract**. Martin Fowler'ın [Evolutionary Database Design](https://martinfowler.com/articles/evodb.html) tanımı:

> "A transition phase is a period of time when the database supports both the old access pattern and the new ones simultaneously."

Örnek: tablo yeniden adlandırma → tabloyu yeniden adlandır + **eski adla bir VIEW oluştur** → tüketiciler kendi hızlarında geçsin → view'ı düşür.

### 4.3 Keycloak'ın yükseltme deneyimi

- **Major/minor upgrade → offline zorunlu.** [HA upgrades](https://www.keycloak.org/high-availability/multi-cluster/upgrades): "the Keycloak deployment on each site is taken offline during the upgrade procedure" ve "Deploying different Keycloak major/minor versions on each of the sites is not supported."
- **Patch upgrade → zero-downtime**, 26.6'da "Zero-Downtime Patch Releases" *supported* seviyesine terfi etti ve **varsayılan açık** ([26.6.0 release notes](https://www.keycloak.org/2026/04/keycloak-2660-released)).
- Manuel migration mümkün: `--spi-connections-jpa--quarkus--migration-strategy=manual` ile SQL dosyası üretilebilir ([upgrading guide](https://www.keycloak.org/docs/latest/upgrading/index.html)); `migration-strategy` değerleri `manual` / `update` / `validate`, ayrıca `initialize-empty` ve `migration-export` ([db docs](https://www.keycloak.org/server/db)).
- **Etki büyüklüğü:** [#43252](https://github.com/keycloak/keycloak/issues/43252) — bu özelliğin hedefi "reduce annual Keycloak downtimes from approximately **20 to 4** for community users". Yılda **20 planlı kesinti**, Keycloak operatörünün 2025 öncesi gerçeğiydi.
- Aynı issue'da belirtilen iki engel: **Infinispan 15.x zero-downtime upgrade yapamıyor** (JGroups protokolü + serialization backward-compat gerekiyor) ve **"Incompatible migrations and index creation locks can prevent old instances from joining clusters during rolling updates."**

⚠️ "Keycloak'ın Liquibase migration'ları forward-only, geri alınamaz, restore gerekir" iddiası ikincil kaynaktan (skycloak blog) — resmî dokümanda doğrulanamadı, ama `migration-strategy` seçeneklerinde down migration olmaması bunu destekliyor.

### 4.4 N-1 uyumluluğu: iki sürüm aynı DB'ye yazarken

Keycloak'ın 26.6/26.7'de vardığı çözüm üç parçalı:

1. **Uyumluluk metadata'sı ile önceden karar:** `update-compatibility metadata` (eski konfig) → `check` (yeni konfig) → exit code. Rolling ancak sürüm aynıysa, feature toggle değişmemişse ve clustering/veri bütünlüğünü etkileyen konfig değişmemişse mümkün ([update-compatibility](https://www.keycloak.org/server/update-compatibility)).

2. **Volatile state'i DB'ye taşı** — 26.7 `stateless` preview: auth session'ları, action token'ları, brute-force sayaçları DB'de ([Temmuz 2026 duyurusu](https://www.keycloak.org/2026/07/multi-cluster-v2-and-stateless-mode)).

3. **DB-backed outbox ile cache invalidation:** "The system employs a database queuing table with polling. Cross-cluster invalidation messages propagate through this outbox pattern with a default **100-millisecond** interval, eliminating direct network dependencies between clusters."

Multi-cluster ön koşulları: **senkron replike edilmiş veritabanı ve site'lar arası <10 ms latency**; duyuru açıkça "prioritizes consistency over availability" diyor.

**Benchmark'tan latency kanıtı** ([Keycloak Performance Benchmarks 26.4, 1 Ekim 2025](https://www.keycloak.org/2025/10/keycloak-benchmark)): 20 ms RTT eklenince yanıt süresi 26.3'te **51 ms → 1076 ms**'ye fırladı; 26.4'te 130 ms'ye düşürüldü. Ağ latency'si çok-AZ IdP'de birinci sınıf tasarım kısıtı.

### 4.5 Sürüm politikaları

| Proje | Politika | Kaynak |
|---|---|---|
| **Keycloak** | "Fixes are applied to the current `major.minor` release for high-severity issues, or the following release for lower-severity vulnerabilities." LTS istiyorsanız **Red Hat build of Keycloak**. Güncel: 26.7.3 | [security policy](https://github.com/keycloak/keycloak/security/policy), [documentation](https://www.keycloak.org/documentation) |
| **Zitadel** | Major her **3 ay**, minor her **2 hafta**, patch gerektikçe; major öncesi RC; **minor sürümler arası backward compatibility**. Downgrade "will always logout all users that obtained a token after the upgrade" | [v3 announcement](https://zitadel.com/blog/zitadel-v3-announcement), [configure docs](https://zitadel.com/docs/self-hosting/manage/configure/configure) |
| **Ory** | OSS "free to use for experimentation and non-critical workloads"; **"security releases with SLAs"** ve CVE yamaları **Ory Enterprise License** ile | [ory/hydra](https://github.com/ory/hydra) |

⚠️ Keycloak/Zitadel için formel LTS + destek penceresi sayfaları bulunamadı (keycloak.org/support ve zitadel.com/docs/support/version-policy → 404). **DOĞRULANMADI.**

---

## 5. Yedekleme ve Felaket Kurtarma

### 5.1 PostgreSQL yedekleme

**pgBackRest** ([user guide](https://pgbackrest.org/user-guide.html)):
- Full / differential / incremental yedek
- WAL archiving (asenkron batch upload ile uzak repo throughput'u)
- **PITR**: timestamp, LSN, transaction ID veya named recovery point ile
- **Delta restore**: SHA-1 hash karşılaştırması ile değişmemiş dosyaları koruyor — "very efficient when combined with the process-max option" → **RTO'yu en çok düşüren tek özellik**
- Repository encryption: client-side **AES-256-CBC**
- Çoklu repo: yerel + S3/Azure/GCS/SFTP eşzamanlı → coğrafi yedeklilik
- `verify` komutu ile repo bütünlüğü
- Doküman kendi tavsiyesi: **"Only restore testing can determine which repository will be most efficient"**

**wal-g** ([github](https://github.com/wal-g/wal-g), Apache 2.0, ~4.2k star, aktif): LZ4/LZMA/ZSTD/Brotli, delta backup, libsodium/PGP/Yandex KMS şifreleme, rate limiting, statsd metrikleri. PG dışında MySQL/MariaDB/MSSQL/Mongo/Redis/Greenplum.

**`pg_dump` vs PITR:** `pg_dump` mantıksal, taşınabilir, seçici — ama **RPO = son dump'a kadar** (saatler). PITR ile RPO = son arşivlenen WAL segmenti (saniyeler–dakikalar). Bir IdP için `pg_dump` **tek başına yeterli değil**: kimlik verisi kaybı hesap kaybıdır.

### 5.2 İmzalama anahtarlarının yedeklenmesi — sektörün en zayıf noktası

**Keycloak** ([Server Admin Guide, Realm Keys](https://www.keycloak.org/docs/latest/server_admin/index.html)):
- Anahtar durumları: **Active** (yeni imza üretir) / **Passive** (mevcut imzaları doğrular) / **Disabled**
- Rotation önerisi: her **3–6 ayda bir** yeni anahtar, eskisini **1–2 ay sonra** kaldır
- Provider'lar: `rsa-generated` (otomatik üretim), `rsa` (PEM import), `java-keystore` (host üzerindeki JKS/PKCS12/BCFKS dosyasından)
- **Yedekleme prosedürü dokümante edilmemiş.** Sadece "compromise durumunda yeni anahtar üret + revocation policy push et" deniyor.

Yani `rsa-generated` kullanan bir Keycloak'ta imzalama anahtarları **veritabanının içindedir** — DB yedeği kaybolursa anahtarlar da kaybolur. `java-keystore` kullanılırsa anahtar **DB dışındadır ama pod'un dosya sistemindedir** ve DB yedeğiyle senkron değildir. Her iki seçenek de operatöre tuzak kuruyor.

**Zitadel'in daha keskin tuzağı** ([compose docs](https://zitadel.com/docs/self-hosting/deploy/compose)):
> masterkey "encrypts sensitive data at rest" ve **"cannot be changed" after initial setup.**

Şifrelediği alanlar ([configure docs](https://zitadel.com/docs/self-hosting/manage/configure/configure)): domain verification token'ları, IdP konfigürasyonları, OIDC token ve session'ları, SAML assertion'ları, OTP secret'ları, SMS/SMTP kimlik bilgileri, kullanıcı verisi, CSRF cookie'leri. **Masterkey kaybı = DB yedeği elinizde olsa bile kurtarılamaz veri.** Ve masterkey `docker compose up`'ta sessizce üretiliyor.

**HSM/KMS seçeneği — AWS KMS** ([asymmetric key specs](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html)):
- İmzalama için: RSA_2048/3072/4096, ECC_NIST_P256/P384/P521, **ECC_NIST_EDWARDS25519 (Ed25519, sadece sign/verify)**, ECC_SECG_P256K1, ve post-quantum **ML_DSA_44/65/87** (FIPS 204)
- "The private key never leaves AWS KMS unencrypted"
- Public key indirilip KMS dışında doğrulama yapılabilir → **JWKS endpoint'i KMS'e her istekte gitmez**
- ⚠️ Ters yüz: private key **hiç export edilemez** → DR planınız KMS multi-Region key veya import edilmiş key material ile yapılmalı; yoksa bölge kaybı = anahtar kaybı

**Anahtar kaybının etkisi asimetrik:** DB kaybı → kullanıcı kaybı (kötü). İmzalama anahtarı kaybı → **tüm çıkarılmış token'lar, refresh token'lar ve oturumlar ölür, ayrıca hiçbir RP eski JWT'leri doğrulayamaz** (felaket). Bu yüzden anahtarların yedekleme yaşam döngüsü DB'den **ayrı** olmalı.

### 5.3 Kurtarma tatbikatı — neyi test etmek gerekir

pgBackRest'in kendi ifadesi tatbikatı zorunlu kılıyor. Bir IdP için test edilmesi gerekenler:
1. PITR ile belirli bir zamana restore (sadece full restore değil)
2. **Restore edilen DB ile birlikte imzalama anahtarlarının da geri gelmesi** — anahtar ayrı sistemdeyse iki restore'un tutarlı bir noktada birleşmesi
3. Restore sonrası **JWKS'in aynı `kid`'leri sunması** (aksi halde RP'ler cache'lerindeki key ile doğrulayamaz)
4. Migration versiyonunun binary sürümüyle uyumu (eski DB + yeni binary)
5. Delta restore ile RTO ölçümü (`process-max` ayarlı ve ayarsız)
6. `pgbackrest verify` ile repo bütünlüğü

### 5.4 Kiracı bazında geri yükleme — dürüst cevap

[`pg_restore` dokümanı](https://www.postgresql.org/docs/current/app-pgrestore.html) seçici restore araçlarını veriyor: `-t table`, `-n schema`, `-N exclude-schema`, `-a data-only`, `-L list-file`, `--filter`.

**Ama uyarılar ölümcül:**
> "When `-t` is specified, pg_restore makes no attempt to restore any other database objects that the selected table(s) might depend upon. Therefore, **there is no guarantee that a specific-table restore into a clean database will succeed**."

> "While pg_dump's `-t` flag will also dump subsidiary objects (such as indexes) of the selected table(s), pg_restore's `-t` flag **does not include such subsidiary objects**."

> "pg_restore cannot restore large objects selectively... **all large objects will be restored, or none of them**."

`--data-only` ile FK/trigger sorunları için `--disable-triggers` gerekiyor.

**Sonuç:** Tek şemada, `tenant_id` kolonuyla çok-kiracılı bir tasarımda **satır seviyesinde tek kiracıyı geri almak `pg_restore` ile mümkün değil.** Gerçekçi yollar:
- **(a) Şema-per-tenant** → `pg_restore -n tenant_x` gerçekten çalışır, ama binlerce kiracıda katalog şişer
- **(b) Yan restore + mantıksal kopyalama:** yedeği ayrı bir instance'a restore et, oradan `tenant_id = ?` ile satırları hedef DB'ye kopyala. Bağımlılık sırasını ve FK'ları kendin yönetmelisin. **En yaygın ve en gerçekçi yol.**
- **(c) Uygulama seviyesinde soft-delete + audit log** — "restore" ihtiyacını en baştan azaltır

---

## 6. Kaynak Gereksinimleri ve Boyutlandırma

### 6.1 Keycloak'ın kapasite formülleri (birincil kaynak)

[Concepts for sizing CPU and memory resources](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing):

| Metrik | Formül | Test edilen üst sınır |
|---|---|---|
| **Parola ile login** | "For each **15 password-based user logins per second**, allocate 1 vCPU to the cluster" | 300/s'ye kadar |
| **Client credential grant** | "For each **120 client credential grants per second**, 1 vCPU to the cluster" | 2000/s'ye kadar |
| **Refresh token** | "For each **120 refresh token requests per second**, 1 vCPU" | 435/s'ye kadar |
| **Bellek/pod** | "base memory usage for a Pod including caches of Realm data and 10,000 cached sessions is **1250 MB of RAM**" | — |
| **Heap** | "Keycloak allocates **70% of the memory limit** for heap-based memory. It will also use approximately **300 MB of non-heap-based memory**" | — |
| **Headroom** | "Leave **150% extra head-room** for CPU usage to handle spikes" | — |
| **DB** | "For every 100 login/logout/refresh requests per second: Budget for **1400 Write IOPS**. Allocate between **0.35 and 0.7 vCPU**" | — |

Test ortamı: **c7g.2xlarge** makine havuzu, ROSA/OpenShift 4.21.x, Amazon Aurora PostgreSQL multi-AZ, OpenJDK 21.

**En önemli sayı: 15 vs 120.** Parola login'i, client credentials grant'ten **8 kat pahalı**. Fark neredeyse tamamen **parola hash'leme**. Bu, Argus'un boyutlandırma modelinin merkezine Argon2'yi koyması gerektiğini kanıtlıyor.

**Benchmark rakamları** ([1 Ekim 2025](https://www.keycloak.org/2025/10/keycloak-benchmark)): 3 pod, 24–74 vCPU, 4–8 GB, OpenShift 4.17, Aurora PostgreSQL 17.5 → **12.000 req/s** (2.000 login/s + 10.000 refresh/s). "Keycloak scales vertically almost linearly in the tested range." Cache 10.000 → 200.000 entry: Aurora peak CPU **%77.77 → %63.77**.

### 6.2 Argon2 ve worker havuzu boyutlandırması

**OWASP'ın eşdeğer parametre setleri** ([Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)) — hepsi p=1:

| m (KiB) | m (MiB) | t |
|---|---|---|
| 47104 | 46 | 1 |
| 19456 | 19 | 2 |
| 12288 | 12 | 3 |
| 9216 | 9 | 4 |
| **7168** | **7** | **5** |

OWASP hedefi: "calculating a hash should take less than one second".

**Keycloak'ın seçimi:** 25.0.0'dan (Haziran 2024) beri varsayılan Argon2 ve **hash isteği başına 7 MB** ([Keycloak 25.0.0 released](https://www.keycloak.org/2024/06/keycloak-2500-released)) — yani OWASP'ın son satırı (m=7168, t=5). Ayrıca: "the parallel computation of hashes by Argon2 is by default **limited to the number of cores available to the JVM**". Keycloak 24'te PBKDF2 iterasyonu 27.5K → 210K çıkarılmış, CPU zamanı 10 kattan fazla artmıştı; Argon2 ile "better security, with almost the same CPU time".

**OWASP'ın açık DoS uyarısı:** work factor aşırıysa saldırgan "a denial of service attack by exhausting the server's CPU with a large number of login attempts" yapabilir.

**Zitadel'in aynı gerçeği kabul edişi** ([production docs](https://zitadel.com/docs/self-hosting/manage/production)): "password hashing can cause CPU spikes — **reserve 4 CPU cores** for this".

**Argus için türetme (m=7168, t=5, p=1):**
- Eşzamanlı N hash → **N × 7 MB** tepe bellek. 64 eşzamanlı = 448 MB, sadece hash arenaları için.
- Argon2 **CPU-bound ve bloklayıcı**; tokio async runtime'ında **asla** doğrudan çalıştırılmamalı → ayrı bir bounded thread pool (`spawn_blocking` veya rayon), semaphore ile sınırlı.
- Havuz boyutu ≈ fiziksel çekirdek sayısı; kuyruk derinliği pod belleğine göre sınırlı; kuyruk dolunca **429 ile load-shed** (Keycloak'ın `http-max-queued-requests` mantığı).
- Pod bellek limiti = baseline + (max_concurrent_hashes × 7 MB) + connection pool + cache. **Bu, Rust'ta JVM'siz olarak Keycloak'ın 1250 MB'ının çok altında tutulabilir** — asıl kazanç burada.

### 6.3 PgBouncer + prepared statement — 2026'da çözüldü mü?

**Evet, 1.21.0'dan beri** ([PgBouncer FAQ](https://www.pgbouncer.org/faq.html), [config](https://www.pgbouncer.org/config.html)):
> "Since version 1.21.0 PgBouncer can track prepared statements in transaction pooling mode and make sure they get prepared on-the-fly on the linked server connection. To enable this feature, `max_prepared_statements` needs to be set to a non-zero value."

- `max_prepared_statements` = tek bir server bağlantısında aktif tutulan prepared statement sayısı (LRU cache). 0 = kapalı.
- **1.22.0**: transaction pooling'de prepared statement desteği açıkken `DISCARD ALL` ve `DEALLOCATE ALL` desteği eklendi ([1.22.0 duyurusu](https://postgresql.org/about/news/pgbouncer-1220-released-2802))
- **Kritik sınır:** "This only works for prepared statements managed via the database protocol... It **cannot handle SQL `PREPARE <statement_name> AS …` commands** sent as simple text queries."

sqlx extended query protocol kullandığı için bu uyumlu. ⚠️ sqlx + PgBouncer transaction mode kombinasyonunun 2026'daki pratik durumu birincil kaynaktan doğrulanmadı.

### 6.4 Küçükten büyüğe topoloji

| Ölçek | Öneri | Dayanak |
|---|---|---|
| **~100 kullanıcı** (homelab, iç araç) | Tek node, tek Postgres, günlük `pg_dump` + WAL arşivi. Kanidm/Casdoor modeli: tek konteyner. Zitadel'in referansı: app "1 CPU and 512MB memory are more than enough" | [Zitadel deploy overview](https://zitadel.com/docs/self-hosting/deploy/overview) |
| **~100K kullanıcı** | 3 stateless node (3 AZ), Postgres primary + 2 senkron standby (`ANY 1 (s1,s2)`), PgBouncer transaction mode, pgBackRest → S3. Zitadel referansı: DB ~1 core / 100 req/s, 4 GB RAM per core; 3-node HA'da node başına 4 core + 16 GB | [Zitadel production](https://zitadel.com/docs/self-hosting/manage/production) |
| **~10M kullanıcı** | Keycloak'ın gerçek verisi: 3 pod / 24–74 vCPU ile 12.000 req/s. Argon2 iş yükü için ayrı node pool + `http-max-queued-requests` ile load shed; read replica'lar; cache boyutunu büyüt (10K→200K cache girdisi DB CPU'sunu %14 düşürdü). Aurora multi-AZ veya CloudNativePG 3 AZ | [Keycloak benchmark](https://www.keycloak.org/2025/10/keycloak-benchmark), [sizing](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing) |

**Senkron quorum commit** ([PostgreSQL replication config](https://www.postgresql.org/docs/current/runtime-config-replication.html)):
> "The keyword `ANY`, coupled with `num_sync`, specifies a quorum-based synchronous replication and makes transaction commits wait until their WAL records are replicated to **at least** `num_sync` listed standbys."
> Örnek: `ANY 3 (s1, s2, s3, s4)`

`FIRST k (...)` öncelik tabanlı; bir standby düşerse listedeki bir sonraki en yüksek öncelikli ile **anında** değiştirilir.

> "Even when synchronous replication is enabled, individual transactions can be configured not to wait for replication by setting the `synchronous_commit` parameter to `local` or `off`."

**Bu, Argus için önemli bir kaldıraç:** `synchronous_commit` **transaction bazında** ayarlanabilir. Kullanıcı kaydı / parola değişikliği / anahtar rotasyonu → `on` (quorum). Brute-force sayacı / son-giriş-zamanı / telemetri → `local`. Böylece senkron replikasyonun latency bedelini sadece gerçekten dayanıklılık gereken yazmalar öder.

---

## 7. Açık Kaynak Proje Operasyonu

### 7.1 Lisans seçimi — IdP alanında kim ne yaptı

| Proje | Lisans | Hareket |
|---|---|---|
| **Keycloak** | Apache 2.0 | Değişmedi; LTS Red Hat build üzerinden ticarileşiyor |
| **Zitadel** | **Apache 2.0 → AGPL-3.0**, v3 ile **31 Mart 2025** yürürlük ([blog](https://zitadel.com/blog/apache-to-agpl), [PR #9597](https://github.com/zitadel/zitadel/pull/9597)) | "any modifications to Zitadel used to provide a service need to be made available to the community". **Kademeli:** sadece yeni katkılar AGPL; önceki sürümler eski lisansta kalıyor; SDK/kütüphaneler mevcut lisansını koruyor; ticari lisans mevcut |
| **Ory** | Apache 2.0 + **OEL (Ory Enterprise License)** | Open-core: "security releases with SLAs", high-performance pooling, YugabyteDB desteği OEL'e ait. "if you run Hydra as part of a business-critical system" ticari lisans öneriliyor |
| **SuperTokens** | Core Apache 2.0 + lisans anahtarlı premium | — |
| **Casdoor** | Apache 2.0 | — |
| **Kanidm** | MPL-2.0 | Dosya-bazlı copyleft — AGPL'den ılımlı, Apache'den korumalı |
| **Pocket ID** | BSD-2-Clause | — |

**Gözlem:** IdP alanında **saf permissive lisans azınlıkta ve azalıyor.** İki baskın strateji: (a) AGPL + ticari çift lisans (Zitadel), (b) Apache 2.0 + kapalı "enterprise" katman (Ory, SuperTokens). Keycloak'ın Apache 2.0 kalabilmesinin nedeni, ticarileşmenin **ayrı bir üründe** (RHBK) olması.

**Argus için pratik sonuç:** Apache 2.0, RP/SDK ekosisteminin benimsemesi için en düşük sürtünme; ama **IdP sunucusu için AGPL + SDK'lar için Apache 2.0** (Zitadel'in yaptığı ayrım) hem benimsenmeyi korur hem SaaS free-riding'i sınırlar. MPL-2.0 (Kanidm) ara yol: dosya bazlı, ağ üzerinden kullanımı tetiklemez.

### 7.2 EU Cyber Resilience Act — tarihler ve gerçek yükümlülük

**⚠️ Görev tanımındaki bir varsayımı düzeltmem gerekiyor.** "11 Eylül 2026 raporlama yükümlülüğü" **açık kaynak steward'ları için o tarihte başlamıyor.**

**CRA Madde 71 (Entry into force and application)** ([tam metin](https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_71.html)):
- **11 Haziran 2026** — Chapter IV (Madde 35–51) uygulanmaya başlar
- **11 Eylül 2026** — **Madde 14** yürürlüğe girer
- **11 Aralık 2027** — Regülasyonun tamamı uygulanır

**ENISA Single Reporting Platform FAQ** ([enisa.europa.eu](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions)) bunu netleştiriyor:
> **Manufacturers** — 11 Eylül 2026'dan itibaren raporlar.
> **Open-source software stewards** — raporlama yükümlülüklerine **11 Aralık 2027'de** katılır.

Bunun nedeni yapısal: Madde 14 manufacturer'lara doğrudan uygulanır; steward'ları Madde 14'e bağlayan hüküm **Madde 24(3)**'tür ve Madde 24 ancak 11 Aralık 2027'de uygulanmaya başlar.

**Raporlama süreleri** (her iki grup için aynı):
- **24 saat** — early warning (farkına varıldığında)
- **72 saat** — vulnerability notification / incident notification
- **Final report** — düzeltici önlem hazır olduktan sonra **14 gün** (zafiyet) veya 72 saatlik bildirimden sonra **1 ay** (severe incident)
- Portal: `portal.cra-srp.enisa.europa.eu`, EU Login hesabı ile atanmış bir **Assigned Representative** üzerinden. AB genelinde şube yapısı ne olursa olsun **olay başına tek bildirim**.
- Bildirim, üreticinin ana AB yerleşiminin ulusal CSIRT'ine gider, oradan diğer üye devletlere dağıtılır.

**"Actively exploited vulnerability"** tanımı: "reliable evidence that they have been exploited by a malicious actor".

**Kapsam dışı kalmak** ([EC cra-open-source sayfası](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source)):
> "products with digital elements qualifying as free and open-source software that are **not monetised by their manufacturers**" kapsam dışı. Kontrol etmedikleri projelere kaynak kodu katkısı yapan bireysel geliştiriciler de muaf.

**Steward tanımı ve Madde 24 yükümlülükleri** ([Article 24 metni](https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_24.html)):
- Steward = "legal persons that systematically provide support on a sustained basis for the development of specific free and open-source software **intended for commercial activities**, and that ensure the viability of those software products"
- **§1** — belgelenmiş, doğrulanabilir bir **cybersecurity policy**: zafiyetlerin belgelenmesi, ele alınması, giderilmesi; topluluk içinde bilgi paylaşımı; gönüllü zafiyet bildiriminin teşviki
- **§2** — pazar gözetim otoriteleriyle işbirliği; talep halinde politikayı "in a language which can be easily understood by that authority" sunmak
- **§3** — geliştirmede rol alıyorsa Madde 14(1) (aktif istismar edilen zafiyet), geliştirme altyapısını etkileyen severe incident'lar için 14(3) ve (8)
- **Yok olanlar:** CE marking yok, conformity assessment yok, teknik dokümantasyon saklama zorunluluğu yok, ve **Madde 64(10) uyarınca idari para cezası yok**

**ORC WG whitepaper'ın pratik rehberi** ([orcwg/orcwg stewards-and-cra.md](https://github.com/orcwg/orcwg/blob/main/cyber-resilience-sig/whitepapers/stewards-and-cra.md)):
- Steward, projeden ayrı **tescilli bir tüzel kişi** olmalı (şirket, vakıf vs.)
- "most Open Source projects today, especially small ones, **do not have a steward**" — steward'ı olmayan küçük projelerin CRA yükümlülüğü yok
- Yapılacaklar: güvenlik politikasını `SECURITY.md`'de yayınla; zafiyet bildirim ve triage sürecini tanımla; **atanmış CSIRT'i belgele** (merkez yeri veya kullanıcı yoğunluğuna göre); olay bildirimlerini kimin yapacağını belirle
- Kullanıcıları "in a timely manner", tercihen makine-okunabilir formatta bilgilendir

### 7.3 Zafiyet bildirimi ve CVE

**GitHub CNA yolu** ([GitHub docs](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories)):
- GitHub bir **CNA**'dır; draft advisory oluştururken CVE talep edilebilir, "GitHub usually reviews the request within **72 hours**"
- CVE talebi advisory'yi public yapmaz — yayınlanana kadar gizli
- Private fork'ta gizli düzeltme + private vulnerability reporting akışı
- Yayınlanan advisory GitHub Advisory Database'e girer ve **Dependabot alert**'lerini tetikler
- ⚠️ **Kısıt:** "GitHub cannot assign CVEs to your project if it is covered by another CNA"

**Argus için pratik:** Kendi CNA'nız olmasına gerek yok. GitHub CNA + `SECURITY.md` + private vulnerability reporting, hem CRA Madde 24 §1'in "documenting, addressing and remediating vulnerabilities" gereksinimini hem CVE numaralandırmayı karşılar.

**Örnek olarak Keycloak'ın politikası** ([security policy](https://github.com/keycloak/keycloak/security/policy)):
- `keycloak-security@googlegroups.com`, **7 iş günü** içinde ack
- Talep edilen: PoC (sadece scanner çıktısı değil), minimal reproducible example, düz metin gövde, bulgu başına ayrı rapor
- Experimental feature'lar genellikle CVE almaz, normal public bug olarak yönetilir
- Üçüncü taraf kütüphane CVE'leri → GitHub issue
- Araştırmacıya kredi: isim/alias/şirket/GitHub kullanıcı adı — e-posta ve link değil

### 7.4 Sürüm imzalama, SLSA, reproducible builds

**Sigstore / cosign** ([docs](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)):
- Keyless: OIDC → **Fulcio** kısa ömürlü sertifika verir → imza **Rekor** transparency log'una yazılır. Komut basit: `cosign sign $IMAGE`
- KMS URI'leri: `awskms://`, `gcpkms://`, `azurekms://`, `k8s://<ns>/<key>`, `env://`
- İmzalar **OCI 1.1 referrers** spesifikasyonuna göre eklenir; `cosign tree` ile bulunur, `cosign clean` ile silinir
- Tek konteynere birden çok imza eklenebilir

**SLSA v1.1 build seviyeleri** ([slsa.dev](https://slsa.dev/spec/v1.1/levels)):
- **L1** — provenance var, ama "may be incomplete and/or unsigned at L1"
- **L2** — hosted build platform, provenance **dijital olarak imzalanır**, tüketici doğrular → "Prevents tampering after the build"
- **L3** — hardened: "strong controls to prevent runs from influencing one another, even within the same project" + "secret material used to sign the provenance" build adımlarından erişilemez

⚠️ **Önemli:** SLSA v1.1 seviye tanımları **hermetic/reproducible build'i gerektirmiyor.** GitHub Actions + OIDC + cosign keyless ile **L2 makul erişilebilir**; L3 için izole runner gerekir.

**Rust'ta reproducible build gerçekçi mi?**
- Rust/cargo, [reproducible-builds.org CI test listesinde **yok**](https://reproducible-builds.org/citests/) (listede coreboot, Debian, FreeBSD, NetBSD, Arch, Guix, Go, NixOS, openSUSE, openEuler, Qubes, Yocto, Trisquel, rattler-build var)
- [Cargo Book Build Cache bölümü](https://doc.rust-lang.org/cargo/reference/build-cache.html) reproducibility'den **hiç bahsetmiyor**
- ⚠️ **Sonuç: Rust'ta bit-for-bit reproducible build 2026'da resmî olarak garantilenmiş bir özellik değil.** Argus'un gerçekçi hedefi: `Cargo.lock` commit + `cargo build --locked` + pinlenmiş toolchain + `--remap-path-prefix` + SLSA L2 provenance + cosign. Bit-for-bit reproducibility'yi **taahhüt etmeyin.**

**Tedarik zinciri gerçekliği — Rust ekosisteminde 2025-2026:**
- [**arrayref saldırısı, 20 Ağustos 2026**](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/): Maintainer kimlik bilgileri/bilgisayarı ele geçirildi; `arrayref` kötü amaçlı `proc-macro1` bağımlılığıyla yeniden yayınlandı — "a build script that was downloading a malicious payload". `arrayref@0.3.10` **86 dakika**, `internment@0.8.7` 90 dakika, `append-only-vec@0.1.9` 107 dakika yayında kaldı. Nextron Systems GmbH Research Team tespit etti.
- [crates.io phishing kampanyası, 12 Eylül 2025](https://blog.rust-lang.org/2025/09/12/crates-io-phishing-campaign/)
- Kötü amaçlı crate'ler: `faster_log`/`async_println` (24 Eyl 2025), `evm-units`/`uniswap-utils` (3 Ara 2025), `finch-rust`/`sha-rust` (5 Ara 2025)
- [crates.io session cookie güvenlik olayı, 11 Nis 2025](https://blog.rust-lang.org/2025/04/11/crates-io-security-session-cookies/)

**Argus için doğrudan sonuç:** `build.rs` çalıştıran bir bağımlılık, build makinenizde keyfi kod çalıştırır. Bir IdP'nin build pipeline'ı için: `cargo-deny` ile lisans+advisory taraması, `cargo-vet`/`cargo-crev` ile bağımlılık denetimi, `cargo-auditable` ile binary'ye SBOM gömme, **vendored + pinned** bağımlılıklar ve **build.rs içeren yeni bağımlılıkların manuel incelemesi**.

---

## Argus için Dağıtım ve Operasyon Kararları

**1. `build` adımı olmasın; tek komut, tek mod.**
Keycloak'ın `kc.sh build` / `start-dev` / `start --optimized` üçlemesi bir Quarkus augmentation artefaktıdır ve mod geçişlerinde regression üretmiştir ([#30460](https://github.com/keycloak/keycloak/issues/30460)). Rust'ta bu bedel yok — derleme zaten AOT. Argus tek binary, tek `argus serve` komutu olmalı; "dev" ile "prod" arasındaki fark yalnızca konfigürasyon değerleri olmalı, **farklı bir kod yolu değil.**

**2. Güvensiz konfigürasyonla başlamayı reddet (fail-fast), uyarma.**
Keycloak production mode'un doğru yaptığı tek şey bu: hostname ve TLS yoksa "startup will fail intentionally with an error message, preventing insecure deployments" ([configuration](https://www.keycloak.org/server/configuration)). Argus da issuer URL'i, TLS'i ve admin arayüzü bind adresini başlangıçta doğrulamalı; eksikse `--i-know-this-is-insecure` gibi açık bir bayrak olmadan başlamamalı.

**3. Dev veritabanı H2/dev-file tuzağına düşme — ama SQLite'ı prod'da yasaklama konusunda Ory'yi taklit et.**
Keycloak'ın `dev-file` (H2) varsayılanı "unsuitable for production" ([db docs](https://www.keycloak.org/server/db)) ve dev/prod uçurumunun kökeni. Ory'nin duruşu daha dürüst: "SQLite is supported (in-memory and persistent) but must not be used in a production deployment" ([Ory deployment](https://www.ory.com/docs/self-hosted/deployment)). Argus için: **tek node / <1000 kullanıcı senaryosu için SQLite'ı resmen destekle** (Casdoor all-in-one modeli), ama HA topolojisinde başlatılırsa reddet.

**4. `redirect_uri` eşleştirmesi yalnızca exact string olsun; regex ve wildcard hiçbir koşulda olmasın.**
authentik CVE-2024-52289'da escape edilmemiş regex noktası hesap devralmaya yol açtı; düzeltme "strict string matching as the default" oldu ([Omegapoint writeup](https://securityblog.omegapoint.se/en/writeup-authentik-cve-2024-52289/)). RFC 9700 zaten exact match zorunlu kılıyor. Argus'ta regex desteği **hiç implemente edilmemeli** — "opt-in tehlikeli özellik" bile olmamalı.

**5. Proxy header güvenini varsayılan olarak KAPALI tut ve açıkken trusted-proxy CIDR listesi zorunlu olsun.**
Keycloak'ın uyarısı: "rogue clients can inject false values"; "especially critical if you do any deny or allow listing of IP addresses"; proxy header'ları "overwrites (not just appends to)" etmeli ([reverseproxy](https://www.keycloak.org/server/reverseproxy)). Brute-force sayaçları ve rate limit doğrudan buna dayandığı için, Argus `trust_proxy_headers=true` iken `trusted_proxies` listesi boşsa **başlamamalı**.

**6. Volatile state'i (auth session, action token, brute-force sayacı) DB'ye yaz; in-flight akışları graceful shutdown'a emanet etme.**
Keycloak 26.7 stateless mode tam olarak bunu yaptı: "Full cluster restarts no longer reset volatile state during upgrades" ([Temmuz 2026](https://www.keycloak.org/2026/07/multi-cluster-v2-and-stateless-mode)). Bedeli auth başına +8-10 ms ve DB CPU/IOPS'un ~2 katı. Rust'ta bu bedel JVM'sizken daha da kabul edilebilir; Argus için **varsayılan** olmalı, opsiyon değil.

**7. Cache invalidation'ı ağ protokolüyle değil, DB-backed outbox ile yap.**
Keycloak'ın Infinispan/JGroups invalidation'ı, DB'ye yazan yan süreçlerle (realm import job'ı) senkronize olamadı — [#45966](https://github.com/keycloak/keycloak/issues/45966) (Şubat 2026): realm DB'de var, konsolda yok, restart gerekiyor. 26.7'nin çözümü DB kuyruğu + polling, varsayılan **100 ms** aralık. Argus: **outbox tablosu + polling** — ya da §1 §10.2'de seçilecek diğer kalıcı mekanizma. `LISTEN/NOTIFY` iptal yayınında **kullanılmaz** (§6 §4.5: PgBouncer transaction mode + dolu kuyrukta commit hatası). **Hiçbir durumda node-to-node cluster protokolü değil.**

**8. Graceful shutdown: `preStop sleep` + drain delay + request timeout üçlüsünü ayrı ayrı yapılandırılabilir yap.**
Keycloak'ın somut değerleri referans: `shutdown-delay` = 1s (LB reconfig + keepalive drain), `shutdown-timeout` = 10s (in-flight istekler) ([all-config](https://www.keycloak.org/server/all-config)). Kubernetes'te endpoint kaldırma ile SIGTERM sıralı değildir ve propagasyon "often a second or more on a busy cluster" sürer. Argus önerisi: `preStop: sleep 5` + `shutdown_delay=2s` + `shutdown_timeout=15s` + `terminationGracePeriodSeconds=45`.

**9. Startup/liveness probe migration sırasında UP dönsün.**
Keycloak 26.6 bunu düzeltti: "Startup and liveness probes return UP status during migrations" ([26.6.0](https://www.keycloak.org/2026/04/keycloak-2660-released)). Aksi halde uzun bir şema göçü sonsuz restart döngüsüne girer. Argus'ta migration durumu `/health/live` için UP, `/health/ready` için DOWN olmalı; ayrı `/health/started` startup probe'a hizmet etmeli — Keycloak'ın 9000 management portu modeli gibi **ayrı porttan** ([health docs](https://www.keycloak.org/observability/health)).

**10. Rolling update uygunluğunu makine tarafından karar verilebilir hale getir (`argus update-check`).**
Keycloak'ın `update-compatibility metadata` / `check` komutu ve exit code'ları (0 = rolling mümkün, 3 = shutdown gerekli) operatöre deterministik bir karar veriyor ([docs](https://www.keycloak.org/server/update-compatibility)). Argus, migration'ının **backward-compatible (expand) mi yoksa breaking (contract) mi** olduğunu binary'nin kendisi rapor edebilmeli — böylece CI/CD ve operator otomatik karar verir.

**11. Şema göçünde expand-contract zorunlu; her release yalnızca expand veya yalnızca contract içersin, ikisi birden değil.**
Fowler'ın transition phase tanımı ("the database supports both the old access pattern and the new ones simultaneously") N-1 uyumluluğunun tek güvenli yolu. PostgreSQL desteği: `ADD CONSTRAINT ... NOT VALID` anında commit eder ve `VALIDATE CONSTRAINT` yalnızca SHARE UPDATE EXCLUSIVE alır ([ALTER TABLE Notes](https://www.postgresql.org/docs/current/sql-altertable.html)). PG18 ile aynı desen artık **NOT NULL için de** geçerli (`SET NOT NULL NOT VALID`) → Argus'un minimum PostgreSQL hedefi **18** olmalı.

**12. Migration aracı olarak `sqlx migrate` seç, ama down migration'ları operasyonel kurtarma planı sayma.**
sqlx `-r` ile `.up.sql`/`.down.sql` üretir ve `migrate revert` sunar ([sqlx-cli](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md)); refinery ise Flyway felsefesiyle undo'yu reddediyor ("you have to generate a new one"). Down migration'ları test için tut; **production geri alma planı = PITR restore**, revert değil.

**13. Rolling update sırasında DDL'i uygulama başlatmasına bırakma — ayrı, tekil bir migration job'ı olsun.**
Keycloak [#43252](https://github.com/keycloak/keycloak/issues/43252) engelleri açıkça listeliyor: "Incompatible migrations and index creation locks can prevent old instances from joining clusters during rolling updates." Argus: `argus migrate` ayrı komut/Job; uygulama süreci başlangıçta yalnızca `validate` yapsın (Keycloak'ın `migration-strategy=validate` seçeneği gibi) ve şema uyumsuzsa hızlıca ölsün.

**14. Index'leri her zaman `CREATE INDEX CONCURRENTLY` ile ekle ve migration transaction'ının dışında tut.**
`ALTER TABLE` varsayılanı ACCESS EXCLUSIVE'dir; rewrite eden formlar ayrıca **MVCC-safe değildir** ("the table will appear empty to concurrent transactions") ve **2 katına kadar disk** ister ([PG docs](https://www.postgresql.org/docs/current/sql-altertable.html)). Bu, kimlik verisi taşıyan bir tabloda kabul edilemez.

**15. İmzalama anahtarlarını veritabanının dışına çıkar ve DB yedeğinden bağımsız yedekle.**
Keycloak `rsa-generated` kullanınca anahtarlar DB'dedir ve doküman yedekleme prosedürü **vermiyor**; `java-keystore` ise host dosya sisteminden okur ([Realm Keys](https://www.keycloak.org/docs/latest/server_admin/index.html)). Zitadel'in masterkey'i "cannot be changed" ve `docker compose up` sırasında sessizce üretiliyor ([compose docs](https://zitadel.com/docs/self-hosting/deploy/compose)). **Anahtar kaybı DB kaybından daha yıkıcıdır** (tüm token'lar + tüm RP doğrulamaları ölür). Argus: anahtar materyali için pluggable backend (dosya / KMS / PKCS#11), varsayılan olarak DB'den ayrı, ve **başlangıçta "anahtarınızı yedeklediniz mi" onayı olmadan üretilmemeli.**

**16. KMS/HSM entegrasyonu birinci sınıf olsun — ama JWKS'i KMS'e bağlama.**
AWS KMS asimetrik imzalama RSA 2048/3072/4096, ECC P-256/384/521, **Ed25519** ve post-quantum **ML-DSA-44/65/87** (FIPS 204) destekliyor; "The private key never leaves AWS KMS unencrypted" ve public key indirilebiliyor ([KMS key specs](https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html)). Argus: imzalama KMS'e delege edilebilmeli, ama **JWKS endpoint'i lokal public key cache'inden servis edilmeli** (her istekte KMS çağrısı yok). DR uyarısı: KMS anahtarı export edilemez → multi-Region key veya import edilmiş key material şart.

**17. Anahtar rotasyonu active/passive/disabled modeliyle, ve retire penceresi token ömründen uzun olsun.**
Keycloak'ın modeli ve önerisi doğrudan alınabilir: 3–6 ayda bir yeni anahtar, eskisini 1–2 ay sonra kaldır ([Realm Keys](https://www.keycloak.org/docs/latest/server_admin/index.html)). Kritik nokta: passive anahtar, en uzun refresh token ömrü + RP JWKS cache TTL'i kadar yaşamalı.

**18. Argon2 için ayrı, sınırlı bir blocking worker havuzu ve kuyruk dolunca 429.**
Kanıt zinciri: Keycloak sizing'de parola login'i **15/s/vCPU**, client credentials **120/s/vCPU** — 8x fark hash'lemeden ([sizing](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing)). Keycloak Argon2 varsayılanı **istek başına 7 MB** ve paralelliği JVM çekirdek sayısıyla sınırlıyor ([25.0.0](https://www.keycloak.org/2024/06/keycloak-2500-released)). Zitadel "reserve 4 CPU cores" diyor ([production](https://zitadel.com/docs/self-hosting/manage/production)). OWASP DoS uyarısı açık. Argus: `max_concurrent_hashes` semaphore + pod bellek limiti = baseline + (N × m_cost) formülüyle hesaplanmış; kuyruk dolunca **429 + Retry-After**, kuyruğa alıp bekletme yok.

**19. Argon2 parametreleri OWASP setlerinden seçilebilir olsun; m=19456/t=2 varsayılan, m=7168/t=5 "yüksek eşzamanlılık" profili.**
OWASP beş seti eşdeğer sayıyor (m=47104/t=1 … m=7168/t=5, hepsi p=1) ve hedefi "less than one second" ([cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)). Keycloak m=7168/t=5'i seçmiş — bellek-verimli uç. Argus, deployment profiline göre seçtirmeli ve **seçilen profilin bellek bütçesini başlangıçta hesaplayıp loglamalı.**

**20. PgBouncer transaction mode'u destekle: `max_prepared_statements` > 0 gerektir, protokol seviyesi prepare kullan.**
PgBouncer 1.21.0+ transaction pooling'de prepared statement'ları takip ediyor; 1.22.0 `DISCARD ALL`/`DEALLOCATE ALL` desteği ekledi ([FAQ](https://www.pgbouncer.org/faq.html)). Kısıt: yalnızca extended query protocol — "cannot handle SQL `PREPARE <statement_name> AS …`". Argus sqlx'in extended protokolünü kullandığı için uyumlu; ama dokümanda `max_prepared_statements=0` ile çalıştırmanın performans çöküşü uyarısı olmalı.

**21. `synchronous_commit`'i transaction sınıfına göre ayarla.**
PostgreSQL "individual transactions can be configured not to wait for replication by setting the `synchronous_commit` parameter to `local` or `off`" ([replication config](https://www.postgresql.org/docs/current/runtime-config-replication.html)). Argus: kullanıcı/kimlik/anahtar yazmaları `on` + `ANY 1 (az2, az3)` quorum; brute-force sayaçları, son-giriş zamanı, telemetri `local`. Böylece 3-AZ senkron quorum'un latency bedeli sadece dayanıklılık gerektiren yazmalara yansır.

**22. Kendi konteyner imajını distroless üzerine kur, ama musl'a körlemesine geçme.**
`gcr.io/distroless/static-debian13` ~2 MiB, alpine'ın %50'si, debian'ın %2'sinden az ([distroless](https://github.com/GoogleContainerTools/distroless)); `base` varyantı CA certs + tzdata içeriyor. ⚠️ Ama musl allocator/threading'in çok-thread'li Rust'ta ciddi yavaşlama ürettiği raporlanmış ([andygrove, 2020](https://andygrove.io/2020/05/why-musl-extremely-slow/)) — Argon2 + tokio iş yükünde **kendi benchmark'ınızı yapmadan** `x86_64-unknown-linux-musl`'a geçmeyin. Güvenli varsayılan: **glibc + `distroless/cc`**; musl+scratch opsiyonel.

**23. Build'i cargo-chef ile katmanla, ama workspace-dışı path dependency kullanma.**
cargo-chef planner/cook/builder ile "up to 5x"; iki katı kural: cook ve build **aynı working directory**'den çalışmalı, ve "cargo build will build local dependencies (outside of the current project) from scratch, even if they are unchanged" ([cargo-chef](https://github.com/LukeMathWalker/cargo-chef)). Argus'un repo düzeni tek workspace olmalı.

**24. Dağıtım kanalı bağımsızlığı: kendi Helm chart'ını kendi OCI registry'nde yayınla, imaj referanslarını kendi imajına sabitle.**
Bitnami 28 Ağustos 2025'te sürümlü imajları `bitnamilegacy`'ye taşıdı ("no further updates or support") ve `bitnamicharts` OCI artefaktları güncellenmiyor; bundled imajlar override edilmezse deploy'lar patlıyor ([bitnami/charts#35164](https://github.com/bitnami/charts/issues/35164), [bitnamilegacy/keycloak](https://hub.docker.com/r/bitnamilegacy/keycloak)). Argus'un chart'ı **hiçbir üçüncü taraf imaj kataloğuna** (özellikle PostgreSQL subchart'ına) bağımlı olmamalı — DB'yi harici bir gereksinim olarak belge, kendi chart'ına gömme.

**25. Operator'ü Helm'in üstüne değil, Helm'in yanına koy — ve sadece CRD'nin gerçekten çözdüğü sorunlar için.**
Keycloak'ın resmî Helm chart'ı yok; sadece Operator var ve kurulum "strongly recommend using manual approval mode" uyarısıyla geliyor ([installation](https://www.keycloak.org/operator/installation)). CRD'ler yıllarca v2alpha1'de kaldı ([#45795](https://github.com/keycloak/keycloak/issues/45795)) ve RealmImport CR yalnızca oluşturuyor, güncellemiyor/silmiyor, geri senkronlamıyor ([realm-import docs](https://www.keycloak.org/operator/realm-import)). **Argus için Helm chart birinci sınıf olmalı**; Operator'ün gerekçesi yalnızca (a) rolling-update uygunluk kararı ve (b) migration job orkestrasyonu olmalı — realm/client reconciliation'ı Terraform provider'a bırakın.

**26. PDB `maxUnavailable: 1`, topology spread zone'da `DoNotSchedule` + hostname'de `ScheduleAnyway`, `matchLabelKeys: [pod-template-hash]`.**
PDB yalnızca gönüllü kesintileri korur ve `minAvailable: 100%` node drain'i sonsuza kadar askıya alır ([PDB docs](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)). `matchLabelKeys: [pod-template-hash]` rolling update sırasında eski/yeni ReplicaSet pod'larının birbirini saymasını önler ([topology spread docs](https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/)). `unhealthyPodEvictionPolicy: AlwaysAllow` (varsayılan) bırakılmalı — aksi halde sağlıksız pod'lar drain'i kilitler.

**27. Veritabanı topolojisi: tek Kubernetes kümesi, 3+ AZ, shared-nothing, 3'ün katı node.**
CloudNativePG'nin resmî tavsiyesi ([architecture](https://cloudnative-pg.io/docs/devel/architecture)): "The multi-availability zone Kubernetes architecture with three (3) or more zones is the one that we recommend"; "Deploy Postgres nodes in multiples of three—ideally with one node per availability zone"; her node'da yerel disk, storage-level replikasyona hayır. Ve sınır: **"CloudNativePG cannot perform any cross-cluster automated failover"** — bu, sizin tek-bölge kararınızın doğruluğunu operatör tarafından da onaylıyor.

**28. RPO/RTO'yu pgBackRest ile hedefle; `pg_dump`'ı tek yedek stratejisi yapma.**
pgBackRest: PITR (time/LSN/xid/name), delta restore (SHA-1 karşılaştırma + `process-max`), AES-256-CBC repo şifreleme, çoklu repo (yerel + S3), `verify` komutu ([user guide](https://pgbackrest.org/user-guide.html)). Dokümanın kendi uyarısı: **"Only restore testing can determine which repository will be most efficient"** → restore tatbikatı Argus'un ops dokümantasyonunda zorunlu bir bölüm olmalı.

**29. Kiracı bazında geri yüklemeyi ürün özelliği olarak vaat etme; şema-per-tenant veya yan-restore desenini belgele.**
`pg_restore -t` için doküman açık: "makes no attempt to restore any other database objects that the selected table(s) might depend upon" ve subsidiary objects (index'ler) dahil edilmez; large object'ler ya hep ya hiç ([pg_restore](https://www.postgresql.org/docs/current/app-pgrestore.html)). Tek şema + `tenant_id` tasarımında satır-seviyesi restore **mümkün değil**. Argus'un dürüst duruşu: yedekten ayrı instance'a restore → `tenant_id` filtreli mantıksal kopyalama runbook'u yayınla; ve uygulama katmanında soft-delete + audit log ile restore ihtiyacını azalt.

**30. Lisans: sunucu için AGPL-3.0 (veya MPL-2.0), SDK/client kütüphaneleri için Apache 2.0.**
Zitadel v3 ile Apache 2.0 → AGPL-3.0'a geçti (31 Mart 2025), sadece yeni katkılar AGPL, SDK'lar mevcut lisansını korudu, ticari lisans sunuldu ([blog](https://zitadel.com/blog/apache-to-agpl)). Alternatif model Ory'nin open-core'u: OSS "non-critical workloads" için, **CVE yamaları ve SLA'lı güvenlik release'leri OEL'de** ([hydra](https://github.com/ory/hydra)) — bu bir IdP için etik olarak tartışmalı. Kanidm'in MPL-2.0'ı (dosya bazlı copyleft, ağ kullanımını tetiklemez) ılımlı ara yol. **Argus için tavsiye: sunucu AGPL-3.0 veya MPL-2.0, SDK'lar Apache 2.0, güvenlik yamaları asla ticari katmana kilitlenmesin.**

**31. CRA hazırlığını 11 Aralık 2027'ye göre planla, ama `SECURITY.md`'yi bugün yaz.**
CRA Madde 71: Chapter IV 11 Haziran 2026, **Madde 14** 11 Eylül 2026, regülasyonun tamamı 11 Aralık 2027 ([Article 71](https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_71.html)). ENISA açıkça belirtiyor: **manufacturer'lar 11 Eylül 2026'dan, açık kaynak steward'ları 11 Aralık 2027'den** itibaren raporlar ([ENISA SRP FAQ](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions)). Argus'un arkasında tüzel kişi yoksa steward yükümlülüğü **hiç** doğmaz ([ORC WG whitepaper](https://github.com/orcwg/orcwg/blob/main/cyber-resilience-sig/whitepapers/stewards-and-cra.md)); monetize edilmeyen FOSS zaten kapsam dışı ([EC](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source)). Ama Madde 24 §1'in istediği "documented in a verifiable manner" cybersecurity policy zaten iyi mühendislik — şimdi yazın.

**32. GitHub CNA + private vulnerability reporting kullan; kendi CNA'nızı kurmayın.**
GitHub CNA'dır, draft advisory'den CVE talep edilebilir ve ~72 saatte incelenir; yayınlanan advisory Advisory Database'e ve Dependabot alert'lerine akar ([GitHub docs](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories)). Keycloak'ın politikası şablon olarak alınabilir: 7 iş günü ack, PoC zorunlu (scanner çıktısı kabul edilmez), bulgu başına ayrı rapor, araştırmacıya kredi ([policy](https://github.com/keycloak/keycloak/security/policy)).

**33. Sürüm imzalama: cosign keyless + SLSA L2 hedefle; reproducible build TAAHHÜT ETME.**
cosign keyless OIDC → Fulcio → Rekor zinciri ve `cosign sign $IMAGE` kadar basit ([sigstore docs](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)). SLSA L2 = hosted platform + imzalı provenance; L3 = build run izolasyonu + imzalama anahtarının build adımlarından erişilemezliği ([SLSA v1.1](https://slsa.dev/spec/v1.1/levels)) — ve **hiçbiri reproducible build gerektirmiyor.** Rust/cargo reproducible-builds.org CI listesinde yok ve Cargo Book reproducibility'den bahsetmiyor. Argus'un taahhüdü: `--locked` + pinned toolchain + SLSA L2 provenance + cosign; bit-for-bit reproducibility "best effort".

**34. Tedarik zinciri: `build.rs` içeren her yeni bağımlılık manuel incelensin.**
20 Ağustos 2026 arrayref saldırısında maintainer hesabı ele geçirildi ve kötü amaçlı `proc-macro1` bağımlılığı "a build script that was downloading a malicious payload" içeriyordu; zararlı sürümler 86–107 dakika yayında kaldı ([Rust blog](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/)). 2025'te ayrıca phishing kampanyası ve dört ayrı kötü amaçlı crate olayı yaşandı. Bir IdP için: `cargo-deny` + `cargo-vet` + `cargo-auditable` + vendored bağımlılıklar + build.rs incelemesi **isteğe bağlı değil.**

**35. Sır yönetimi: dosya tabanlı secret + `secrecy`/`zeroize`, imzalama anahtarları için `memsafe`/mlock, rotation'da pod reload'u kendin çöz.**
`secrecy` açıkça mlock/mprotect sunmuyor; `zeroize` buffer realloc'undan önceki kopyaları garanti edemiyor ve Spectre sınıfı sızıntılara karşı garanti vermiyor ([docs.rs/secrecy](https://docs.rs/secrecy/latest/secrecy/), [docs.rs/zeroize](https://docs.rs/zeroize/latest/zeroize/)); `memsafe` mmap+mlock+`MADV_DONTDUMP`+`MADV_WIPEONFORK` yapıyor ([crates.io/memsafe](https://crates.io/crates/memsafe)). External Secrets Operator ise "there is no Secret Operator that handles the lifecycle of the secret" — **rotation sonrası pod reload ESO'nun işi değil** ([ESO overview](https://external-secrets.io/latest/introduction/overview/)). Argus: secret dosyalarını **inotify ile izleyip yeniden yüklesin**, restart gerektirmesin.

**36. Vault dinamik DB kimlik bilgilerini destekle: lease yenileme + TTL bitiminde yeniden bağlanma pool'da ele alınsın.**
Vault PostgreSQL secrets engine dinamik kullanıcıları `VALID UNTIL '{{expiration}}'` ile üretir ve static role'lerde `rotation_period` ile parola döndürür ([Vault docs](https://developer.hashicorp.com/vault/docs/secrets/databases/postgresql)). Argus'un connection pool'u, parola değiştiğinde **yeni bağlantıların yeni parolayı** kullanmasını sağlamalı ve mevcut bağlantıları gereksiz yere kapatmamalı.

---

## Doğrulanamayanlar (⚠️)

1. **Rust distroless/scratch imajlarının kesin boyutları** (26.2 MB distroless-chef, 8.38 MB musl+scratch) — yalnızca ikincil blog kaynağı ([cloudnativefolks](https://blog.cloudnativefolks.org/cargo-chef-speed-up-your-docker-builds-reduce-image-size-of-your-rust-project)). Kendi ölçümünüzü yapın.
2. **musl allocator/threading performansının 2026'daki durumu** — tek kaynak 2020 tarihli ([andygrove.io](https://andygrove.io/2020/05/why-musl-extremely-slow/)); musl 1.2.x mallocng sonrası yeniden ölçülmeli.
3. **RFC 9700'ün (OAuth 2.0 Security BCP) tam yayın tarihi** — arama sonucu "March 2025" dedi; RFC metninden doğrulanmadı.
4. **Keycloak'ın Liquibase migration'larının forward-only olduğu ve rollback için DB restore gerektiği** — yalnızca ikincil kaynak (skycloak blog); resmî dokümanda açık ifade bulunamadı (ancak `migration-strategy` seçeneklerinde down yok).
5. **Keycloak ve Zitadel için formel LTS / destek penceresi sayfaları** — `keycloak.org/support` ve `zitadel.com/docs/support/version-policy` 404 döndü.
6. **Red Hat build of Keycloak yaşam döngüsü tarihleri** — `access.redhat.com/support/policy/updates/rhbk` 404.
7. **authentik'in lisansı** (core MIT + enterprise?) — doğrulanmadı.
8. **sqlx migration'larının advisory lock ile eşzamanlılık koruması ve checksum/dirty-state davranışı** — docs.rs ve sqlx-cli README'de belgelenmemiş; kaynak koddan teyit gerekir.
9. **crates.io Trusted Publishing'in mevcut durumu ve provenance/attestation desteği** — `crates.io/docs/trusted-publishing` içerik döndürmedi; Rust blog arşivinde konuya özel yazı yok.
10. **Keycloak'ın büyük kurulumlarda major upgrade DB migration süresi** (saatler mi?) — resmî dokümanda somut rakam yok; yalnızca ikincil kaynaklardan "migration can take significant time on large databases".
11. **Kanidm'in veritabanı motorunun SQLite tabanlı olup olmadığı** — README "its own high-performance database" diyor, SQLite'tan bahsetmiyor.
12. **Zitadel masterkey'in kaybı durumunda kurtarma prosedürü olup olmadığı** — "cannot be changed" ifadesi doğrulandı, ancak kayıp senaryosu için resmî prosedür bulunamadı.
13. **Keycloak'ın imzalama anahtarları için PKCS#11/HSM desteği** — `java-keystore` provider'ı (JKS/PKCS12/BCFKS) doğrulandı; doğrudan PKCS#11/HSM desteği doğrulanamadı.
14. **`ANY k` quorum commit ile 3-AZ arasında gerçek latency maliyeti** — PostgreSQL dokümanı sözdizimini veriyor, sayısal etki vermiyor. Keycloak benchmark'ındaki 20 ms RTT verisi dolaylı bir gösterge.
