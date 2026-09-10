# 25. Gözlemlenebilirlik ve ölçekte denetim

> `ARGUS.md` §25'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§25 §X` referansları aynı anlamda.


Tarih: 8 Eylül 2026. Toplam ~55 arama/fetch (22 WebSearch + ~33 WebFetch/doğrudan indirme). Tüm iddialar kaynaklıdır; doğrulanamayanlar sonda listelenmiştir.

---

## 0. En kritik bulgu: Ön ölçümünüz literatürle birebir örtüşüyor

Per-event hash-chained audit log ölçümündeki **8 bağlantı = 1 bağlantı** eşitliği tesadüf değil. ⚠️ *Yapısal olan yalnızca şudur: **tek bir doğrusal zincirde ardışık zincir hash'lerinin hesaplanması arasında seri bağımlılık vardır.** Ölçülen ~5.900/s değeri bu uygulamaya ve donanıma özgüdür, evrensel bir tavan değildir (§6 §4.4).* İki bağımsız kaynak seri bağımlılığı doğruluyor:

**Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging", USENIX Security 2009** (PDF: https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf — indirildi ve metin çıkarıldı). Tablo 2, tek çekirdek Intel Core2 Duo 2.4GHz, SHA-1 + 1024-bit DSA:

| Adım | CPU payı | İzole hız |
|---|---|---|
| A — syslog mesajını parse et | 2,4 % | 81.000 ev/s |
| B — olayı log'a insert et | 2,6 % | 66.000 ev/s |
| C — commitment üret (Merkle root) | 11,8 % | 15.000 ev/s |
| D — commitment'ı imzala | **83,3 %** | **2.100 ev/s** |
| Membership proof (locality ile) | — | 8.600 /s |
| Membership proof (locality yok) | — | **32 /s** |

Uçtan uca: **1.750 olay/s** (her olayda imza), imzalar başka çekirdeğe/HSM'e offload edilirse **10.500 olay/s** (= 1,9 MB/s, 1,1 TB/hafta). Kâğıttan doğrudan alıntı: *"signatures account for over 80% of the runtime cost of an insert"* ve *"inserting events into the log is twenty times faster than generating and signing commitments"*.

Ve tam olarak sizin kararınızı öneriyorlar: *"The logger may amortize the costs of generating a signed commitment over many inserted events... Under light load, the logger could sign every commitment and insert 1,750 events per second. With increasing load, the logger might sign one in every 16 commitments to obtain an estimated insert rate of 17,000 events per second. Clients will still receive signed commitments within a fraction of a second, but several clients can now receive the same commitment."*

→ **~10x throughput artışı, karşılığında yalnızca "birden fazla istemci aynı commitment'ı alır" takası.** Ölçülen düz append-only değeri (⚠️ *ölçüm etiketi: §6 §4.4, [YENİDEN ÜRETİM BEKLİYOR] — çıplak insert, ürün throughput'u değil*) bu tabloya oturuyor (adım A+B ≈ 66.000/s teorik tavan, gerçek DB fsync maliyetiyle 22k makul).

**Agent Flight Recorder** (arXiv:2609.01931, 1 Eylül 2026, https://arxiv.org/html/2609.01931) — 5 kademeli ablation, N=10.000 olay:

| Konfigürasyon | Medyan gecikme | P95 | P99 | Bayt/olay |
|---|---|---|---|---|
| Baseline (düz JSON) | 20,3 µs | 26,2 µs | 30,7 µs | 272 |
| Schema (deterministik CBOR) | **6,0 µs** | 8,2 µs | 10,0 µs | 476 |
| **+ Chain (SHA-256 hash chain)** | **48,2 µs** | 57,2 µs | 76,8 µs | 477 |
| + Merkle (100-olay epoch) | 48,8 µs | 60,8 µs | ~4,1 ms | 512 |
| + Full (on-chain anchoring) | 47,6 µs | 60,2 µs | ~30 ms | 512 |

→ Hash chain tek başına medyan gecikmeyi **6 µs → 48 µs (8x)** çıkarıyor. Merkle batching *üstüne* neredeyse hiç medyan maliyet eklemiyor (48,2 → 48,8 µs); sadece P99'da epoch sınırında ~4 ms tepe var. Bu, "hash chain pahalı, Merkle checkpoint bedava" tezinizin bağımsız doğrulaması.

**Kritik ek bulgu — hash chain'in asıl maliyeti insert değil, DOĞRULAMA:** Crosby & Wallach: *"where a classic hash chain might require an 800MB trace to prove that a randomly chosen event is in a log with 80 million events, our prototype returns a 3KB proof with the same semantics."* Karşılaştırma tablosu:

| | Hash chain | Skiplist | History tree |
|---|---|---|---|
| ADD | O(1) | O(1) | O(log²n) |
| Incremental proof boyutu | O(n−k) | O(n) | **O(log²n)** |
| Membership proof boyutu | O(n−k) | O(n) | **O(log²n)** |

→ Hash chain'in O(1) insert'i cazip görünür ama denetçi her iki snapshot arasındaki **her ara olayı** taramak zorundadır. Merkle/history tree yapısı hem insert'i batch'lenebilir kılar hem proof'u logaritmik yapar. **Hash chain, ölçekte iki kere kaybediyor.**

---

## 1. Denetim logu standartları ve şemaları

### 1.1 RFC 8417 Security Event Token (SET) — denetim formatı olarak?

https://www.rfc-editor.org/rfc/rfc8417.html — Standards Track, Temmuz 2018.

Claim'ler: `iss` (REQUIRED), `iat` (REQUIRED), `jti` (REQUIRED, *"MAY be used by clients to track whether a particular SET has already been received"*), `events` (REQUIRED — URI → JSON payload map), `aud` (RECOMMENDED), `sub`/`sub_id`, `txn` (korelasyon), `toe` (olayın gerçekleşme zamanı — `iat`'ten farklı!).

**Kritik semantik sınır:** *"Security events are not commands issued between parties."* SET bir *olgu bildirimidir*, komut değil. Bu denetim logu semantiğiyle mükemmel uyumlu.

**Denetim için doğrudan destek:** *"If a SET needs to be retained for audit purposes, the signature can be used to provide verification of its authenticity."* İmza JWS ile; gizlilik gerekiyorsa JWE.

**Değerlendirme:** SET, Argus'un **dışa yayın (egress) formatı** olarak mükemmel — çünkü SSF/CAEP/RISC/SCIM ekosisteminin tamamı bunu konuşuyor. Ama **dahili depolama formatı** olarak kötü: JWT/JWS her kayda ~700+ bayt base64 overhead ve per-event imza (= Crosby'nin %83'lük D adımı) getirir. **Depola canonical binary olarak, yayınla SET olarak.**

### 1.2 RFC 9967 — SCIM SET profili

https://www.rfc-editor.org/rfc/rfc9967.html — Standards Track, **Mayıs 2026** (çok yeni). RFC 7643 ve 7644'ü günceller.

12 event URI'si, 3 sınıfta:
- **Feed:** `urn:ietf:params:scim:event:feed:add` / `:remove`
- **Provisioning:** `prov:create:{notice|full}`, `prov:patch:{notice|full}`, `prov:put:{notice|full}`, `prov:delete`, `prov:activate`, `prov:deactivate`
- **Misc:** `misc:asyncresp`

`notice` vs `full` ayrımı önemli: `notice` sadece "değişti" der (PII yaymaz), `full` veriyi taşır. **Argus'un denetim yayınında `notice` varyantı varsayılan olmalı.**

Durability şartı: *"Event Receivers MUST ensure events are persisted directly or indirectly to meet local recovery needs before acknowledging the SET Events were received."*

`sub_id` kullanımı zorunlu (`sub` değil) — format tipi + resource URI + external ID + unique id.

### 1.3 OpenTelemetry semantic conventions — kimlik/auth durumu

**Güncel sürüm: 1.44.0** (https://opentelemetry.io/docs/specs/semconv/).

Kapsanan alanlar: General, CI/CD, Cloud Providers, CloudEvents, Database, Exceptions, FaaS, Feature Flags, GenAI, GraphQL, HTTP, Messaging, Object Stores, RPC, System, .NET, Apps, Azure, Browser, CLI, DNS, Hardware, Mobile, NFS, OTel SDK, Runtime, URL.

**→ Authentication / identity / IAM / security events için ADANMIŞ SEMANTIC CONVENTION YOK.** Bu Argus için önemli: OTel'in kimlik olayları için hazır bir taksonomisi yok, kendi taksonomiinizi kurmalısınız (ve OCSF'e maplemelisiniz).

**`enduser.*` hikâyesi — kesin durum:**

| Attribute | Durum (semconv 1.44) | Kaynak |
|---|---|---|
| `enduser.id` | **AKTİF**, Development stability. "Contains sensitive PII" notu | https://opentelemetry.io/docs/specs/semconv/registry/attributes/enduser/ |
| `enduser.pseudo.id` | AKTİF, Development. "Pseudonymous identifier, random non-linked value" | aynı |
| `enduser.role` | **DEPRECATED** → `user.roles` | aynı |
| `enduser.scope` | **DEPRECATED**, yerine geçen yok | aynı |
| `user.id`, `user.name`, `user.email`, `user.full_name`, `user.roles`, `user.hash` | Hepsi **Development** (stable değil) | https://opentelemetry.io/docs/specs/semconv/registry/attributes/user/ |

Tarihçe (GitHub issue #1104, https://github.com/open-telemetry/semantic-conventions/issues/1104): `enduser.id` PR #731 ile deprecate edilip `user.id`'ye taşındı; ancak `user.id`'nin "authenticated mı anonymous mı" belirsizliği şikâyet konusu oldu; issue PR #1456 ile kapandı ve `enduser.id` **geri getirildi** — şimdi `enduser.id` (authenticated end-user, PII) ile `enduser.pseudo.id` (pseudonymous) ayrımı var.

→ **Pratik sonuç:** `enduser.pseudo.id`'yi trace/metrik yolunda, gerçek `user.id`'yi yalnızca audit log yolunda kullanın. Ve *hiçbiri stable değil* — semconv'a hard-code bağımlılık kurmayın, bir mapping katmanı koyun.

**OTel Events modeli** (https://opentelemetry.io/docs/specs/semconv/general/events/): Event = `EventRecord` = "`event.name` taşıyan bir `LogRecord`". Kural: *"Event names MUST NOT include dynamic values. Use attributes for identifiers, names, or other values that vary per occurrence."* Durum: **Development**.

### 1.4 OCSF — en güçlü aday, ve büyük bir sürpriz

**Güncel sürüm: 1.9.0, 3 Ağustos 2026** (https://github.com/ocsf/ocsf-schema/releases). Sürüm geçmişi: 1.5.0 (28 Nis 2025), 1.6.0 (1 Ağu 2025), 1.7.0 (14 Kas 2025), 1.8.0 (18 Mar 2026), 1.9.0 (3 Ağu 2026) — yılda ~3 sürüm, hızlı hareket eden bir standart.

**IAM kategorisi (category_uid = 3), OCSF 1.9.0** (https://schema.ocsf.io/1.9.0/categories):

| Sınıf | UID |
|---|---|
| Account Change | 3001 |
| **Authentication** | **3002** |
| Authorize Session | 3003 |
| Entity Management | 3004 |
| User Access Management | 3005 |
| Group Management | 3006 |
| **User Management** | **3007** (1.9.0'da yeni) |
| **Role Management** | **3008** (1.9.0'da yeni) |

**Authentication [3002] detayı** (https://schema.ocsf.io/1.7.0/classes/authentication): zorunlu alanlar `category_uid`, `class_uid`, `severity_id`, `time`, `metadata`, `user`; ayrıca `dst_endpoint` veya `service`'ten biri. `activity_id`: 1=Logon, 2=Logoff, 3=Authentication Ticket, 4=Service Ticket Request, 5=Service Ticket Renew, 7=Account Switch. Anahtar alanlar: `auth_protocol_id` (NTLM, Kerberos, OAUTH 2.0, SAML...), `logon_type_id`, `is_mfa`, `session`, `actor`, `src_endpoint`, `status_id` (0=Unknown, 1=Success, 2=Failure).

**🔥 SÜRPRİZ — OCSF 1.9.0 "Record Integrity" profili.** Argus'un tam olarak yaptığı şeyi standartlaştırmış:

https://schema.ocsf.io/1.9.0/profiles/record_integrity — *"adds one or more cryptographic attestations over the event itself, providing integrity, authenticity, and non-repudiation independent of any domain-specific content."* 80+ event class'a uygulanabilir. Tek attribute: `attestation_list`.

`attestation` nesnesi (https://raw.githubusercontent.com/ocsf/ocsf-schema/main/objects/attestation.json):
- `authority_uid` — attestation'ı üreten otorite
- **`chain_uid`** — *"Identifier of the append-only chain, such as a forensic or audit log"*
- **`fingerprint`** — *"The fingerprint of this event's canonical serialization"*
- **`prev_event`** — *"Reference to the previous event in a tamper-evident chain"*
- `signatures` — fingerprint üzerinden hesaplanan bir veya daha fazla dijital imza
- `uid`

Ve çoklu attestation destekleniyor: *"a producer at write time and a downstream processor at ingest"* bağımsız attestation ekleyebilir.

→ **Argus'un Merkle checkpoint modeli, OCSF `record_integrity` profiliyle wire-uyumlu olarak ifade edilebilir.** Her olayda `prev_event` doldurmak zorunda değilsiniz (bu opsiyonel); checkpoint'i ayrı bir attestation olarak yayınlayabilirsiniz. Bu, Argus'un denetim çıktısını *doğrudan* SIEM'lerin anlayabileceği hale getirir.

**Benimseme:** AWS Security Lake OCSF'i native olarak kullanıyor; custom source'lar **OCSF + Apache Parquet** formatına uymak zorunda (https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html). CloudTrail Management Events → `API Activity`, `Authentication` veya `Account Change` sınıflarına maplenıyor. Security Lake şu an `metadata.version` 1.0.0-rc.2 (v1 kaynak) ve 1.1.0 (v2 kaynak) kullanıyor — yani **AWS, OCSF'in en son sürümünün epey gerisinde**; bu, sürüm uyumluluğunu Argus'ta konfigüre edilebilir yapmanız gerektiği anlamına geliyor.

### 1.5 CADF / CEF / LEEF — hâlâ alakalı mı?

- **CADF** (DMTF, https://www.dmtf.org/standards/cadf): DMTF Cloud Management Initiative altında aktif standart. Pratik kullanımı esas olarak **OpenStack Keystone** ile sınırlı (pyCADF kütüphanesi, https://docs.openstack.org/mitaka/config-reference/identity/auditing.html). DSP2038 "OpenStack Profile" mevcut. → **Argus için niş; OpenStack ekosistemine satmıyorsanız görmezden gelin.**
- **CEF** (ArcSight) / **LEEF** (IBM QRadar) / SEF (McAfee): Query.ai'nin standartlar evrimi analizi (https://www.query.ai/resources/blogs/cybersecurity-event-data-normalization-standards/) — CEF *"was widely adopted... because of its simplicity, readability, log categorization, and easy transferability over syslog"*, ama *"the schema was network security centric and extension mechanism to non-network data was a force-fit. Also, the focus on serialized representation was still on single-line syslog, whereas the rest of the world was moving to JSON."*
- Vendor şemaları: CIM (Splunk), ECS (Elastic), UDM (Chronicle), ASIM (Microsoft) — hepsi vendor lock-in.
- **OCSF**, v1.0 BlackHat 2023'te çıktı, topluluk güdümlü halef olarak konumlanmış durumda.

→ **Karar: OCSF birincil, CEF/LEEF yalnızca opsiyonel çıktı adaptörü (legacy SIEM müşterileri için, 200 satırlık bir formatter).**

### 1.6 NIST SP 800-53 Rev.5 AU ailesi — IdP için hangileri bağlayıcı

(https://csf.tools/reference/nist-sp-800-53/r5/au/)

| Kontrol | İçerik | Baseline | Argus'a etkisi |
|---|---|---|---|
| **AU-2** Event Logging | Loglama yeteneklerini belirle, hangi olayların loglanacağını *ve sıklığını* tanımla, gerekçelendir, periyodik gözden geçir. Örnek olaylar: *"password changes, failed logons or failed accesses..., security or privacy attribute changes, administrative privilege usage, PIV credential usage, data action changes, query parameters, or external credential usage"* | Low+ | Event tipi kataloğu **konfigüre edilebilir** olmalı; sabit değil |
| **AU-3** Content | 6 zorunlu eleman: event type, when, where, source, outcome, *"identity of any individuals, subjects, or objects/entities associated with the event"*. AU-3(1) ek bilgi (Moderate+). **AU-3(3) PII sınırlama** (privacy baseline) | Low+ | Şema tasarımının minimum kontratı |
| **AU-9** Protection | Yetkisiz erişim/değiştirme/silmeden koru; Rev.5'te **tamper olunca alarm** eklendi. AU-9(2) ayrı fiziksel sistem, AU-9(3) **kriptografik bütünlük koruması**, AU-9(4) yetkili alt küme | **Moderate**+ | Merkle/imza tam olarak AU-9(3); ayrık depolama AU-9(2) |
| **AU-10** Non-repudiation | *"irrefutable evidence that a specific individual or process performed defined actions"* | **YALNIZCA High** | Merkle checkpoint + imza bunu karşılar |
| **AU-12** Audit Record Generation | Sistemin AU-2'deki olayları üretme yeteneği | Low+ | — |

→ **Bağlayıcılık analizi:** Genel amaçlı bir IdP çoğu müşteride Moderate baseline'a düşer → **AU-9(3) kriptografik bütünlük zaten Moderate'ta**. AU-10 sadece High'da, ama IdP tanım gereği kimlik iddialarının kaynağı olduğu için müşterilerin High sistemleri sizin logunuza dayanacak. **Argus AU-10'u varsayılan olarak karşılamalı** — bu, Merkle checkpoint'in imzalanması gerektiği anlamına gelir (sadece hash yeterli değil, non-repudiation imza ister).

### 1.7 PCI DSS v4.0 Requirement 10

(https://pcidssguide.com/pci-dss-requirement-10/, https://www.zengrc.com/blog/what-are-the-pci-audit-log-retention-requirements/)

- **Loglanacaklar:** tüm CHD erişimi, root/admin ile yapılan tüm işlemler, **audit trail'lere erişim**, geçersiz mantıksal erişim denemeleri, kimlik doğrulama mekanizmalarının kullanımı, audit log'un başlatılması, sistem seviyesi nesne oluşturma/silme.
- **Her kayıt en az 6 eleman:** User ID, event type, date & time, success/failure, event source, etkilenen veri/sistem bileşeni/kaynak kimliği. (AU-3 ile neredeyse birebir.)
- **Koruma:** görüntülemeyi iş ihtiyacıyla sınırla, dosyaları yetkisiz değişiklikten koru, değiştirilmesi zor merkezî sunucuya yedekle, **file integrity monitoring / change-detection yazılımı ile değişiklikte alarm ver**.
- **Saklama: en az 12 ay, son 3 ay hemen analize hazır (immediately available).** v4.0.1'de saklama ve gözden geçirme sıklığı hedefli risk analizi ile özelleştirilebilir.

→ **"Audit trail'lere erişimin kendisi loglanmalı"** maddesi çok kritik ve sıkça atlanıyor: Argus'ta audit log okuma API'si de audit event üretmelidir (meta-audit). Sonsuz döngüye girmemek için: meta-audit olayları ayrı bir chain/stream'de tutulmalı veya rate-limited/coalesced olmalı.

---

## 2. Bütünlük (tamper-evidence) — ölçekte

### 2.1 Hash chain vs Merkle tree vs transparency log

**RFC 9162 Certificate Transparency v2.0** (https://www.rfc-editor.org/rfc/rfc9162.html) — **Experimental**, Aralık 2021. (Not: "Experimental" statüsü kafa karıştırıcı; ekosistemde fiilen RFC 6962 v1 ve onun halefi **Static CT API** kullanılıyor.)

Teknik özet:
- Merkle Tree Hash: boş liste → `HASH()`; tek yaprak → `HASH(0x00 || d[0])`; iç düğüm → `HASH(0x01 || left || right)`. **Domain separation (0x00/0x01) second-preimage resistance için zorunlu** — bunu atlamak klasik bir hatadır.
- Inclusion proof: **O(log n)** düğüm.
- Consistency proof: **≤ ⌈log₂(n)⌉ + 1** düğüm.
- **Signed Tree Head (STH):** timestamp + tree size + root hash + extensions, imzalı. *"Each subsequent timestamp MUST be more recent than the timestamp of the previous update."*
- **Maximum Merge Delay (MMD):** SCT verildikten sonra log'un girdiyi ağaca dahil etme taahhüdü (index tahsis + root hesap + tree head imzala).

→ **MMD kavramı, Argus'un "1 saniyede bir checkpoint" kararının standart karşılığıdır.** Argus için MMD ≈ 1s ilan edilebilir ve bu bir SLA olarak yayınlanabilir.

### 2.2 Tiled logs (tlog) — 2024-2026'nın gerçek dersi

CT ekosistemi RFC 6962 tarzı "canlı DB + API" modelinden **statik dosya tile'larına** geçti. Bu Argus için doğrudan mimari ders.

**Sunlight / Static CT API** (https://sunlight.dev/, https://words.filippo.io/run-sunlight/):
- Log'lar *"simple collections of flat files called 'tiles'"* olarak temsil ediliyor.
- Filippo Valsorda **tek bir sunucuda** bir Sunlight log çalıştırıyor, **yıllık ~$10.000** toplam maliyet.
- Bant genişliği: Tuscolo log 400-800 Mbps üretiyor; RFC 6962 log'ları 1-2 Gbps. **Static CT bant genişliğini ~%80 azaltıyor.**

**Let's Encrypt, "Reflections on a Year of Sunlight"** (11 Haziran 2025, https://letsencrypt.org/2025/06/11/reflections-on-a-year-of-sunlight):
- *"each log's write side was handled comfortably by just a"* tek makine.
- **Merge delay fiilen sıfır:** log'lar *"always completely incorporate newly-submitted certificates before returning an SCT to the submitter."* — yani MMD'yi 0'a indirmek mümkün ve tercih edilir.
- Let's Encrypt'in *kendi ürettiği tüm sertifikaları* (tüm public-trusted hacmin çoğunluğu) işledi.
- Static CT API log'ları *"substantially lower resource requirements than first-generation CT logs"*.

**Sigstore Rekor v2** (GA 10 Ekim 2025, https://blog.sigstore.dev/rekor-v2-ga/):
- Trillian → **Trillian-Tessera** (tile-backed, C2SP tlog-tiles layout).
- *"Rekor v2 batches requests, which enables the higher QPS and witnessing."* Takas: yanıt *"take a few seconds to return"*.
- Tile'lar immutable, content-addressed, **CDN'den servis edilebilir**.
- **Yıllık shard:** `log2025-1`, `log2026-1`... Eski shard'lar dondurulup statik tile olarak arşivleniyor.
- Trillian log server + log signer instance'ları tamamen kapatıldı → altyapı maliyeti ve karmaşıklığı düştü.
- Basitleştirme: intoto/rekord/helm/tuf/rfc3161/jar/rpm/cose/alpine entry tipleri kaldırıldı, sadece `hashedrekord` + DSSE kaldı.

**Trillian Tessera benchmark'ları** (https://github.com/transparency-dev/tessera/blob/main/docs/performance.md) — **Argus için en değerli sayılar**:

| Backend | Throughput |
|---|---|
| **POSIX / yerel NVMe** | *"sustain around 10,000 write qps, using up to 7 cores for the server"* (antispam açık) |
| POSIX / yerel SAS HDD | ~2.900 w/s (antispam kapalı), ~1.600 w/s (antispam açık) |
| GCP Spanner, 100 PU + 1 frontend | >3.000 QPS (antispam yok), >800 QPS (antispam var) |
| GCP Spanner, 300 PU + 2 frontend | >5.000 QPS (antispam var) |
| CephFS ağ depolama, 4 node | >1.000 QPS |
| GCP `e2-micro` free tier + PersistentDisk | >1.500 w/s |

Mimari: **sequencing** (durable index atama, sıra garantisi yok) ile **integration** (arka planda Merkle ağacına birleştirme) ayrılmış. `WithBatching`, `WithCheckpointInterval`, `WithCheckpointRepublishInterval` konfigürasyonları var. Batch size = 1 mümkün ama *"this will make sequencing expensive"* (https://github.com/transparency-dev/tessera/blob/main/README.md).

→ ⚠️ **Bu karşılaştırma kaldırıldı (düzeltme, 2. inceleme turu).** Önceden burada "Argus'un 22.440 tps'si Tessera'nın 2 katı" yazıyordu. Bu elmayla armut karşılaştırmasıdır: Tessera'nın 10.000 QPS'i sequencing + integration yapan **tam bir transparency log**'un değeridir; 22.440 ise Merkle'sız, imzasız, uygulama mantığı olmayan **çıplak insert** ölçümüdür (§6 §4.4, 12 sn pgbench). Ayakta kalan sonuç, sayılardan değil yapıdan geliyor: **per-event hash chain seri bağımlılık yaratır, Merkle checkpoint yaratmaz.** Karar bu gerekçeyle doğru.

### 2.3 AWS QLDB — ⚠️ EMEKLİ

**QLDB 31 Temmuz 2025'te tamamen destek dışı kaldı.** (https://www.infoq.com/news/2024/07/aws-kill-qldb, https://techcommunity.microsoft.com/blog/azuresqlblog/moving-from-amazon-quantum-ledger-database-qldb/4246237)

- Resmî duyuru yapılmadı; sadece dokümantasyon güncellendi ve müşterilere e-posta gönderildi (Temmuz 2024).
- AWS'in önerdiği göç yolu: **Amazon Aurora PostgreSQL** (ledger benzeri yetenekler extension'larla) — **ancak bu göç kriptografik doğrulanabilirliği kaybettiriyor.**
- 2018 re:Invent'te duyuruldu, 2019'da GA oldu, ~6 yıl yaşadı.

→ **Ders (Argus için stratejik):** "Kriptografik olarak doğrulanabilir ledger" bir *managed service kategorisi* olarak ticari başarısızlığa uğradı — çünkü müşteriler ayrı bir veritabanı istemedi, **var olan veritabanlarında bütünlük özelliği** istedi. Bu, Argus'un "Postgres içinde append-only + Merkle checkpoint" kararını doğruluyor: ayrı bir ledger sistemi kurmak yerine, mevcut store'un üzerine ince bir bütünlük katmanı. Ayrıca **QLDB'ye veya benzeri managed ledger'lara bağımlılık kurmayın.**

### 2.4 Postgres'te append-only zorlama

Katman katman savunma (kaynaklar: https://heypinchy.com/blog/day-143-the-hole-in-append-only [10 Tem 2026], https://www.cybertec-postgresql.com/en/row-change-auditing-options-for-postgresql/, https://wiki.postgresql.org/wiki/Audit_trigger_91plus):

1. **`REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC`** ve uygulama rolüne yalnızca `INSERT` (+ gerekiyorsa `SELECT`). Compliance rejimi DB seviyesinde append-only istiyorsa **her rolden** revoke edin.
2. **BEFORE UPDATE/DELETE trigger** → `RAISE EXCEPTION`. Ama:
3. **🔴 TRUNCATE DELİĞİ.** *"TRUNCATE in Postgres is a statement-level operation, not a row-level one, and row-level triggers simply never fire for it."* Row-level trigger'larla korunan bir tablo TRUNCATE ile tamamen boşaltılabilir. **Çözüm: ayrıca bir `BEFORE TRUNCATE` statement-level trigger.** Bu, "append-only" iddiasında en sık kaçırılan açık.
4. **RLS**: okuma tarafında kiracı izolasyonu için; yazma korumasının yerini tutmaz.
5. **Temel gerçek:** *"blocking edits is not the same as making edits detectable. While you can reduce changes with permissions, anyone with enough access can still alter history. Tamper-evidence accepts that reality by making changes leave an obvious fingerprint."* → Superuser her zaman kazanır. **Bu yüzden Merkle checkpoint'ler dış tanıklara (witness) yayınlanmalıdır.**

**pgaudit** (https://github.com/pgaudit/pgaudit) — Argus için **uygun değil**:
- Session audit logging (READ/WRITE/FUNCTION/ROLE/DDL/MISC) ve object audit logging.
- *"Depending on settings, it is possible for pgAudit to generate an enormous volume of logging."* — OLAP fact table insert'lerinde disk hızla dolar; loglar metin ve gerçek veriden çok daha büyük.
- **⚠️ `TRUNCATE` object audit logging'de desteklenmiyor** (sadece SELECT/INSERT/UPDATE/DELETE).
- **⚠️ *"Audit logging is best-effort and not transactional"*** — crash'te kayıt kaybolabilir. **Bu tek başına pgaudit'i compliance-grade audit için diskalifiye eder.**
- Superuser auditing güvenilir değil.
- Çıktı standart Postgres log tesisine gider (CSV satırları) — yapılandırılmış sorgu için elverişsiz.

→ pgaudit **DB-seviyesi ikincil kontrol** olarak (Argus DB'sine dışarıdan yapılan doğrudan erişimi yakalamak için, AU-9 destekleyici) değerli; **birincil audit kaynağı olarak değil.**

**Retention için partitioning** (https://www.postgresql.org/docs/current/ddl-partitioning.html):
- `DROP TABLE partition` → milyonlarca kaydı anında siler, `VACUUM` yükü yok, ama `ACCESS EXCLUSIVE` lock ister.
- `DETACH PARTITION ... CONCURRENTLY` → sadece `SHARE UPDATE EXCLUSIVE` lock; üretimde tercih edilmeli. Veriyi bağımsız tablo olarak korur (arşiv/S3'e taşımadan önce).
- `ATTACH PARTITION` → `SHARE UPDATE EXCLUSIVE`; önceden `CHECK` constraint konursa full-table scan'den kaçınılır.
- Partition pruning plan-time + execution-time; örnekte maliyet 188,76 → 37,75.
- **Kısıt:** UNIQUE/PK constraint'ler partition key'i içermek zorunda. FK'lar partition hiyerarşisinde çalışmaz.

→ Bu, Keycloak'ın bulk-DELETE ile purge yaparken DB'yi kilitleme problemine (aşağıda) yapısal çözümdür.

### 2.5 Merkle checkpoint sıklığı vs doğrulanabilirlik takası — literatürdeki ölçümler

Bu, sorunuzun en spesifik kısmıydı. Bulunan ölçümler:

| Kaynak | Checkpoint/epoch | Sonuç |
|---|---|---|
| Crosby & Wallach 2009, §6 | Her commitment imzalanır | 1.750 ev/s |
| Crosby & Wallach 2009, §6 | **16 commitment'ta 1 imza** | **~17.000 ev/s (~10x)** |
| Agent Flight Recorder 2026 | 100-olay epoch | Medyan +0,6 µs, **P99 ~4,1 ms** (epoch sınırı tepesi) |
| Agent Flight Recorder 2026 | 100-olay epoch + L2 anchoring | **compromise window = 100 saniye**, maliyet **$2,30 / 100K olay** (L2) vs **$6.885 / 100K olay** (L1); anchor başına 91.800 gas (Base Sepolia) |
| Let's Encrypt Sunlight 2025 | Etkin sıfır merge delay | Tek makine tüm LE hacmini kaldırdı |
| Rekor v2 2025 | Batch + witnessing | Yanıt "birkaç saniye" |

**Takas yasası:** checkpoint aralığı = **compromise window** = "log operatörü tespit edilmeden ne kadar geçmişi yeniden yazabilir". 1 saniyelik checkpoint → 1 saniyelik pencere. Bu, Okta/Auth0/Keycloak'ın *hiç* sunmadığı bir garantidir (onlar 0 garanti sunuyor). 

**Ancak dikkat:** checkpoint yayınlanmadıkça (dış tanığa/istemciye) pencere sonsuzdur. Crosby: *"an untrusted logger is free to have different snapshots make inconsistent claims about the past"* — bunun tespiti için **consistency proof denetimi** (gossip/witness) şart. Checkpoint'i sadece kendi DB'nizde tutmak bütünlük sağlamaz.

### 2.6 Crypto-shredding + bütünlük zinciri bir arada

Desen (tüm kaynaklarda aynı): **hash'i ciphertext üzerinden al.** Böylece anahtar imha edildiğinde satır yerinde kalır, hash değişmez, zincir kırılmaz, ama içerik geri döndürülemez.

Kaynaklar:
- https://www.tdcommons.org/dpubs_series/10873/ — "Atomic Crypto-Shred with Trigger-Immutable Audit-Ledger Preservation": per-subject key satırının key material'ı NULL'a çekilir, **keyref tombstone hayatta kalır**, manifest-güdümlü plaintext PII purge, ve **tek bir immutable "erasure fact" satırı append edilir**. Ledger'a hiç dokunulmaz.
- https://veritaschain.org/blog/posts/2026-01-18-crypto-shredding-gdpr-mifid-ii-reconciliation/ (18 Oca 2026) — GDPR Art.17 ile MiFID II / Dodd-Frank / MAR kayıt tutma yükümlülüklerinin uzlaştırılması.
- https://www.conduktor.io/glossary/crypto-shredding-for-kafka — Kafka'da aynı desen (immutable log + per-subject key).
- https://granit-fx.dev/blog/crypto-shredding-gdpr-erasure-without-deleting-rows/ — .NET implementasyonu.

**⚠️ HUKUKİ UYARI — çok önemli.** EDPB **Guidelines 01/2025 on Pseudonymisation** (16 Ocak 2025 kabul, https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf): *"Even if all additional information retained by the pseudonymising controller has been erased, the pseudonymised data can be considered anonymous only if the conditions for anonymity are met."*

→ **Anahtar silmek otomatik olarak anonimleştirme değildir.** Crypto-shredding, GDPR Art.17 uyumu için "yeterli" diye pazarlanamaz; risk-bazlı bir argümandır (anahtar gerçekten yok edildi mi, backup'larda kaldı mı, ciphertext kırılabilir mi — kuantum sonrası dahil). **Argus dokümantasyonunda bunu "erasure" değil "irreversible de-identification of log content, subject to controller's own DPIA" olarak konumlandırın.** Gerçek uygulamalar var (yukarıdaki kaynaklar) ama düzenleyici kesinlik yok.

---

## 3. Ölçekte log hacmi ve maliyet

### 3.1 Gerçek IdP'lerin saklama süreleri — çarpıcı tablo

| Sağlayıcı | Sıcak saklama | Kaynak |
|---|---|---|
| **Okta System Log** | **90 gün** (Customer Data Retention Policy) | https://support.okta.com/help/Documentation/Knowledge_Article/Exporting-Okta-Log-Data |
| **Auth0** Starter | **1 gün** | https://auth0.com/docs/deploy-monitor/logs/log-data-retention |
| Auth0 B2C/B2B Essentials | 5 gün | aynı |
| Auth0 B2C/B2B Professional | 10 gün | aynı |
| Auth0 Enterprise | **30 gün** | aynı |
| **Entra ID Free** — audit + sign-in | **7 gün** | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention (güncelleme 25 Mar 2026) |
| **Entra ID P1 / P2** — audit + sign-in | **30 gün** | aynı |
| Entra ID P2 — riskli oturum açmalar | 90 gün | aynı |
| Entra External ID Basic | 7 gün | aynı |

**→ Sektör deseni açık ve şaşırtıcı: Hiçbir büyük IdP PCI DSS'in 12 aylık saklama gereksinimini kendi içinde karşılamıyor.** Hepsi "kısa sıcak pencere + streaming export" modeline geçmiş. Müşteri kendi SIEM'inde/arşivinde uzun saklamayı yapıyor.

Ek: Auth0 *"does not provide real-time logs for your tenant. While we do our best to index events as they arrive, you may see some delays."* Okta EventBridge streaming'de ~30 saniye gecikme. Auth0'da tenant başına varsayılan **2 log stream** (Enterprise'da talep üzerine 3).

Okta log streaming: yalnızca **Amazon EventBridge** ve **Splunk Cloud (HEC)**; *"Okta sends all System Log events to a configured log stream target. No event filtering is supported."* (https://help.okta.com/oie/en-us/content/topics/reports/log-streaming/about-log-streams.htm)

**⚠️ Event/saniye ve GB/gün rakamları:** Okta, Auth0 veya Keycloak için kamuya açık, birincil kaynaklı event/s veya GB/gün rakamı **bulunamadı**. Sektör dolaylı olarak yalnızca saklama süreleri ve rate limit'lerle konuşuyor. (Doğrulanamayanlar listesinde.)

Kıyaslanabilir tek somut hacim ölçüsü: Crosby & Wallach 2009 — 10.500 ev/s = 1,9 MB/s ham syslog = **1,1 TB/hafta**. ⚠️ *Buradaki ~2,3 TB/hafta tahmini 22.440 tps'yi sürekli hacim saymaktan çıkıyordu; o sayı 12 sn'lik çıplak-insert ölçümüdür (§6 §4.4) ve 7/24 tepe yük varsayımıyla çarpılamaz. Hacim planı, gerçek olay hızı ölçüldükten sonra yeniden yapılmalı.* Yapısal sonuç değişmiyor: bu büyüklük sınıfında ham olaylar sıkıştırmasız Postgres'te tutulamaz.

### 3.2 Sampling: audit'te KABUL EDİLEBİLİR Mİ?

**Hayır.** Bulunan tüm kaynaklar hemfikir:
- *"For high-volume, low-impact application metrics, consider sampling, but **audit trails should remain complete to preserve forensic value**."* (https://airbyte.com/data-engineering-resources/audit-logging-compliance)
- *"operations involving sensitive data, privileged actions, or regulated processes should always be traced to ensure complete audit trails, using trace attributes to mark these critical operations and **exempt them from sampling**"* (https://tetrate.io/learn/ai/mcp/mcp-audit-logging)
- PCI DSS 10.2: "**all** individual access", "**all** transactions performed by any person with root or administrative privileges" — "all" kelimesi sampling'i yasaklıyor.
- NIST AU-2: hangi olayların loglanacağı seçilir (**event selection**), ama seçilen olay tipinin *örneklenmesi* değil.

→ **Doğru ayrım: audit'te "sampling" değil "event selection" vardır.** AU-2'nin izin verdiği şey "bu olay tipini hiç loglama" (politika kararı, dokümante edilmiş gerekçeyle), "bu olay tipinin %10'unu logla" değil. Bu ikisini karıştırmak denetimde başarısızlıktır.

**Trace tarafında ise sampling zorunlu:** OTel'in kendi performans benchmark standardı varsayılan olarak 10.000 span/s ölçüyor (https://opentelemetry.io/docs/specs/otel/performance-benchmark/) — 22k tps'lik bir IdP'de %100 trace sampling ekonomik değil.

→ **Argus'ta iki ayrı yol (dual-path) olmalı: audit path (%100, durable, tamper-evident) ve telemetry path (sampled, best-effort, drop edilebilir). Bunları aynı pipeline'a koymak en yaygın mimari hatadır.**

### 3.3 Sıcak/soğuk katman ayrımı — gerçek üretim deseni

**Phase Two, "How We Scaled Keycloak Event Storage with Logs, S3, and ClickHouse"** (6 Temmuz 2026, https://phasetwo.io/blog/scaling-keycloak-event-storage/) — Argus için doğrudan uygulanabilir referans mimari.

Keycloak'ın JPA event store'unun 4 temel arızası:
1. **Request path tax:** event yazımı authentication ile *aynı transaction*'da; login isteği DB insert'ini beklemek zorunda.
2. **Operational fragility:** `EVENT_ENTITY` "tens or hundreds of millions of rows"a ulaşınca DDL riskli — aktif isteklerin bağlı olduğu tabloyu kilitliyor.
3. **Expiry contention:** bulk-delete expiration write-hot tabloya karşı çalışıyor → lock contention ve I/O spike.
4. **Analytics impossibility:** "90 gündeki başarısız login'ler" sorgusu üretim tablosunda full-table scan.

Boru hattı:
1. `ext-event-mdc-logger-store` provider → olayları **JSON log satırı** olarak emit ediyor (MDC alanları: `event_type`, `user_id`, `client_id`, `ip_address`, `event.realmName`). JPA ile dual-write yapılabilir, doğrulandıktan sonra tek başına.
2. **Fluent Bit** yönlendirme: tüm loglar → Loki (S3'te 90 gün); sadece event satırları → **S3 (PII redacted, cluster/tarih ile partition'lı)**.
3. **ClickHouse `S3Queue` table engine** bucket'ı sürekli izliyor; ClickHouse Keeper işlenen dosyaları takip ediyor → exactly-once benzeri teslimat. **Kafka yok, scheduled batch job yok.**
   - ⚠️ Öğrenilen ders: S3-backed table storage merge'ler sırasında **cluster başına 150 request/s** üretti → **yerel NVMe'ye geçildi.**
4. **Query gateway:** API Gateway arkasında Lambda, parametrik REST endpoint'ler (`/insights/user-events`, `/insights/metrics`), JWT ile tenant izolasyonu, **free-form SQL yok**.
5. Dashboard: metrikler rollup tablolarından, event search typed tablolardan.

Sonuçlar: ham olaylar **S3'te süresiz**; rollup granülaritesi **5 dakika** (15dk/saatlik/günlük zoom); *"a year of login trends"* sorgusu **onlarca milisaniyede** dönüyor. Her katman bağımsız değiştirilebilir çünkü kontrat *"just structured JSON log lines"*.

ClickHouse'un kendi observability kılavuzu: *"ClickHouse compresses logs and traces on average up to 14x"* (https://clickhouse.com/docs/en/use-cases/observability/introduction).

→ **Argus'un katman planı: Postgres (sıcak, 30-90 gün, partition'lı, append-only, Merkle chain'in kaynağı) → Parquet/S3 (soğuk, süresiz, OCSF şemalı) → ClickHouse (analitik, opsiyonel).** AWS Security Lake'in custom source kontratı da tam olarak **OCSF + Parquet**, bu yüzden soğuk katmanı bu formatta yazmak Argus'u ücretsiz olarak Security Lake uyumlu yapar.

### 3.4 Çelişen saklama gereksinimleri nasıl uzlaştırılıyor

| Rejim | Gereksinim | Kaynak |
|---|---|---|
| **PCI DSS v4.0** 10.5.1 | **En az 12 ay**, son 3 ay hemen erişilebilir | Bölüm 1.7 |
| **CNIL** (Délibération n° 2021-122, 14 Ekim 2021) | Genel: **6 ay – 1 yıl**; iç kontrollerle **6 ay – 3 yıl** (dokümante gerekçeyle); 3 yıl üstü sadece yasal yükümlülük/özel tehdit | https://www.cnil.fr/fr/la-cnil-publie-une-recommandation-relative-aux-mesures-de-journalisation |
| CNIL — log içeriği | En az: kullanıcı kimliği, erişim tarih/saati, kullanılan ekipman kimliği; ayrıca **otomatik analiz sistemi** kurulmalı (pasif saklama yetmez) | aynı |
| **GDPR Art. 5(1)(e)** | Storage limitation — amaç için gerekli süreden fazla tutma | https://gdpr-info.eu/art-5-gdpr/ |
| **NIST AU-11** | Organization-defined | csf.tools |
| **SOC 2** | Sabit sayı yok; genellikle 1 yıl gözlem penceresi pratikte | ⚠️ Birincil kaynak bulunamadı |

**Uzlaşma deseni (sektörde fiilen uygulanan):**
1. **Saklama süresi Argus'un kararı değil, kiracının konfigürasyonudur.** Hukuki çelişki müşterinin sorumluluğunda; Argus mekanizmayı sunar (per-tenant, per-event-class TTL).
2. **PII ile olay iskeletini ayır.** Olayın *varlığı* (kim/ne/ne zaman/sonuç, pseudonymous ID ile) 12+ ay tutulabilir; IP, user-agent, e-posta gibi PII alanları 6 ayda crypto-shred edilir. CNIL'in "6 ay" endişesi PII'ye yönelik; PCI'nin "12 ay"ı olay izine yönelik. **Bunlar aynı satırda olmak zorunda değil.**
3. Sıcak katman (Postgres) kısa, soğuk katman (S3/Parquet, şifreli, per-subject key) uzun.

---

## 4. Rust gözlemlenebilirlik yığını — 2026 üretim gerçeği

### 4.1 opentelemetry-rust — stability tablosu (Eylül 2026)

https://github.com/open-telemetry/opentelemetry-rust:

| Bileşen | Durum |
|---|---|
| **Logs API** | **Stable** |
| **Logs SDK** | **Stable** |
| Logs OTLP Exporter | RC |
| **Metrics API** | **Stable** |
| **Metrics SDK** | **Stable** |
| Metrics OTLP Exporter | RC |
| **Traces API** | **Beta** |
| **Traces SDK** | **Beta** |
| Traces OTLP Exporter | **Beta** |
| Context | Beta |
| Baggage | RC |
| Propagators | Beta |

MSRV: **1.75**; "current stable + son 3 minor" politikası.

**🔴 En kritik operasyonel gerçek:** Her crate hâlâ **pre-1.0**. Stable işaretli sinyaller bile 0.x sürümünde yaşıyor; **breaking change'ler minor release'lerde geliyor** ve tüm first-party crate'ler lockstep versiyonlanıyor. 0.32 hattındayız. GitHub issue #3376 "Graduate stable spec features out of experimental feature flags before 1.0" hâlâ açık.

→ **Rust'ta OTel, diğer dillerin tersine: logs ve metrics traces'ten ÖNCE stable oldu.** Bu Argus için aslında iyi haber — audit/log yolu stable API üzerinde, trace yolu (daha az kritik) beta'da.

→ **Ama:** lockstep 0.x versiyonlama, Argus'un doğrudan `opentelemetry` API'sine kod boyunca bağımlı olmasını riskli kılar. **Kendi ince facade'ınızı yazın**, OTel'i sadece exporter kenarında kullanın.

### 4.2 `tracing` ekosistemi

`tracing` **0.1.44** (6 Eylül 2026, https://docs.rs/tracing/latest/tracing/). Performansla ilgili tek resmî iddia: *"For performance reasons, if no currently active subscribers express interest in a given set of metadata by returning true, then the corresponding Span or Event will never be constructed."*

Compile-time filtreleme: `max_level_*` / `release_max_level_*` feature'ları — release build'de belirli seviyelerin altındaki makroların tamamen derlenmemesini sağlar.

Pratik kılavuz (https://rustify.rs/articles/rust-tracing-vs-log-crates-2026, https://oneuptime.com/blog/post/2026-02-06-tracing-subscriber-opentelemetry-layer-rust/view):
- Disabled olduğunda `log` ve `tracing` zero-cost; enabled olduğunda span başına küçük overhead (span record = küçük allocation).
- **Her zaman batch span processor** kullanın (simple değil) — batching network overhead'ini büyük ölçüde azaltır.
- Pahalı layer'lara filter uygulayın veya global filter kullanın ki disabled span'ler o layer'lardan geçmesin.
- Batch processor ayrı bir background thread'de çalışır; instrument'lar lock-light; GC yok.

**⚠️ `tracing`/`tracing-opentelemetry` için nanosaniye seviyesinde bağımsız yayınlanmış benchmark bulunamadı.** Sizin kendi ölçümünüzü almanız gerekecek — özellikle 22k tps'de `#[instrument]` makrosunun span-per-request maliyeti.

### 4.3 `metrics` crate vs OpenTelemetry metrics

| | `metrics` crate | opentelemetry metrics |
|---|---|---|
| Model | Facade (log/tracing gibi), backend takılabilir | Tam SDK |
| Exporter'lar | `metrics-exporter-prometheus`, `metrics-exporter-statsd`, custom — **instrumentation kodunu değiştirmeden** | `opentelemetry-prometheus`, OTLP |
| Olgunluk | Ekosistemde yaygın, "standard choice for most applications" | API+SDK **Stable**, ama crate 0.x |
| Trace/log korelasyonu | Yok | Var (tek OTLP hattı) |

Kaynaklar: https://crates.io/crates/metrics-prometheus, https://rust-exercises.com/telemetry/03_metrics/04_prometheus, https://www.rustfaq.org/en/how-to-add-metrics-to-a-rust-application-prometheus-metrics-crate/

→ **Argus için: OpenTelemetry metrics.** Gerekçe: (a) metrics API/SDK zaten **Stable**, (b) OTLP tek hatta metrik+log+trace korelasyonu, (c) kiracılara "OTLP endpoint'inize gönderelim" demek satılabilir bir özellik, (d) `metrics` crate'in backend-agnostisizmi Argus'un tek OTLP hedefi olan senaryosunda değer üretmiyor. `metrics`'in tek avantajı (backend swap) OTel Collector ile zaten çözülüyor.

### 4.4 Yüksek kardinalite — kiracı/client başına etiket

Sayısal gerçek: *"a Prometheus instance with 1 million active time series will typically consume 4–6 GB of RAM just for the head block"* (https://systeminternals.dev/observability/cardinality/, https://alexandre-vazquez.com/prometheus-scalability/).

Argus için hesap: 1.000 kiracı × 50 client × 20 event tipi × 5 sonuç durumu = **5.000.000 seri** → ~20-30 GB RAM. **Tek başına yıkıcı.**

Çözümler (https://oneuptime.com/blog/post/2025-12-05-prometheus-label-best-practices/view, https://last9.io/blog/how-to-manage-high-cardinality-metrics-in-prometheus/, https://www.sawmills.ai/blog/metric-cardinality-explained-sre-fixes):
1. **Label disiplini:** *"never use identifiers (user_id, request_id, IP, full URL) as labels."* `tenant_id` bile tehlikeli sınırda.
2. **Exemplars:** *"Exemplars attach a trace ID to a histogram bucket, providing aggregate metrics and a way to drill into a specific slow request without paying the cardinality cost of a per-request label."* → **Argus'un doğru cevabı bu.**
3. **Native histograms:** Prometheus v2.40'tan beri experimental, 3.x hattında olgun tooling. *"if histograms dominate your series count, they are the structural fix"* — klasik histogram bucket'ları seri sayısını bucket sayısıyla çarpar; native histogram bunu tek seriye indirir.
4. **Per-tenant isolation:** Grafana Mimir / Cortex / Thanos ile tenant başına max series, ingest rate, query limit'leri. *"runaway labels stay inside that tenant"*.

→ **Argus deseni: metrikte kiracı yok, audit log'da kiracı var.** Kiracı-kırılımlı sayılar Prometheus'tan değil, ClickHouse/rollup tablolarından (Phase Two'nun 5 dakikalık rollup'ları gibi) gelmelidir. İstisna: en fazla ~50 "top tenant" için allowlist'li düşük kardinaliteli metrik seti.

### 4.5 Structured logging'de PII/sır sızıntısı

**`secrecy` v0.10.3** (https://docs.rs/secrecy/latest/secrecy/):
- `SecretBox<T>`, `SecretString`, `SecretSlice` — `Display`/`Debug` **implement etmez**.
- Erişim için `ExposeSecret` / `ExposeSecretMut` trait'i üzerinden **açık** çağrı gerekir (`expose_secret()`).
- Drop'ta `zeroize` ile bellekten silinir.
- **Serde:** `SecretBox` **varsayılan olarak serialize edilemez** (veri sızıntısını engellemek için); deserialize desteklenir; serialize için `SerializableSecret`'ı elle implement etmek gerekir. — Bu, JSON logging'de kazara sızıntıyı yapısal olarak engeller.
- `no_std` uyumlu, `forbid(unsafe_code)`.
- `mlock(2)` gibi ileri bellek korumaları **kastî olarak yok**; onlar için `secrets` crate'i öneriliyor.
- Alternatifler: `redact`, `sec`, `secret-box` (hepsi Debug redaction + zeroize).

**Rust'a özgü tuzak:** `#[derive(Debug)]` bir struct'ta *bütün alanları* basar. `tracing`'in `field::debug()` / `?value` sözdizimi bu `Debug`'ı çağırır. Bir struct'a sonradan bir `password_hash` veya `refresh_token` alanı eklendiğinde, hiçbir log satırını değiştirmeseniz bile o an sızıntı başlar. Derive'ın sessiz genişlemesi = zamanla artan risk.

→ **Argus kuralı: PII/secret taşıyan hiçbir tipte `#[derive(Debug)]` olmayacak.** Elle yazılmış `Debug`, ya da `secrecy` sarmalayıcıları. Bunu CI'da `clippy` lint'i / custom lint ile zorunlu kılın (`missing_debug_implementations` ters yönde çalışır, kendi kuralınızı yazmanız gerekir).

**Zeroize'ın sınırı:** RUSTSEC-2024-0342 (vodozemac, https://osv.dev/vulnerability/RUSTSEC-2024-0342) — bir dependency değişikliği "more memory copies of encryption secrets" yarattı. Advisory'nin kendi notu: *"inherent limitations of Rust regarding absolute zeroization reduce the practical severity."* → Zeroize best-effort'tur, garanti değil (move semantics, optimizer, swap).

---

## 5. Denetim logu bir güvenlik ürünü olarak

### 5.1 SSF/CAEP transmitter — Argus'un asıl farklılaştırıcısı

**CAEP 1.0 ve SSF 1.0, Final Specification olarak onaylandı ve 2 Eylül 2025'te yayımlandı** (oylama: 85 kabul, 1 ret, 25 çekimser; 433 üyeden 111 oy, %20 kuorumun üstünde). https://openid.net/three-shared-signals-final-specifications-approved/

**CAEP 1.0'ın 8 event tipi** (https://openid.net/specs/openid-caep-1_0-final.html, 29 Ağu 2025 tarihli, base URI `https://schemas.openid.net/secevent/caep/event-type/`):

| # | Event | Argus'un iç denetim olayı karşılığı |
|---|---|---|
| 1 | `session-established` | Login başarılı → oturum oluşturuldu |
| 2 | `session-presented` | *"Confirms the session was actively observed at the Transmitter"* — token yenileme / SSO re-use |
| 3 | `session-revoked` | Logout, admin session kill, global sign-out |
| 4 | `credential-change` | Şifre değişimi, MFA enroll/unenroll, passkey ekleme/silme, recovery code üretimi |
| 5 | `assurance-level-change` | Step-up auth, AAL/ACR değişimi |
| 6 | `token-claims-change` | Rol/grup/claim değişimi (SCIM patch sonrası) |
| 7 | `device-compliance-change` | Cihaz posture entegrasyonu (varsa) |
| 8 | `risk-level-change` | Risk motoru skoru değişimi |

**Eşleme analizi:** Argus'un iç denetim olay evreninin **büyük çoğunluğu bu 8 tipe düşmüyor.** CAEP olayları *durum değişikliği bildirimleridir* (relying party'nin aksiyon alması için); denetim olayları *olgu kayıtlarıdır*. Örnek: "başarısız login denemesi" CAEP'te karşılığı yok (session kurulmadı, credential değişmedi). "Admin bir client secret'ı rotate etti" karşılığı yok.

→ **Doğru mimari: iki ayrı yayın kanalı, tek kaynaktan.**
- **CAEP stream** (8 tip): gerçek zamanlı, relying party'lere, aksiyon odaklı, düşük hacim.
- **Audit stream** (tam taksonomi, OCSF/SET): SIEM'lere, arşive, yüksek hacim.
- İkisi de aynı iç event bus'tan beslenir, aynı `txn` ile korele edilir.

**SSF 1.0 stream yönetimi** (https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html, 29 Ağu 2025):
- **Push delivery (RFC 8935):** Receiver `endpoint_url` verir, Transmitter POST eder; Receiver authorization header sağlayabilir.
- **Poll delivery (RFC 8936):** Transmitter `endpoint_url` verir; **delivery method belirtilmezse varsayılan budur.**
- **Configuration Endpoint:** POST (stream oluştur, `events_requested`/`delivery`/`description`), GET, PATCH (kısmi), PUT (tam replace), DELETE. Başarılı oluşturma → `201 Created` + `stream_id`, `iss`, `aud`, `events_delivered`.
- **Subject management:** Add/Remove Subject endpoint'leri; `verified` boolean'ı receiver'ın subject sahipliğini doğruladığını belirtir. Simple Subject → tam eşleşme; Complex Subject → wildcard semantiği (tanımsız alan = joker).
- **Verification events:** heartbeat + uçtan uca doğrulama; `https://schemas.openid.net/secevent/ssf/event-type/verification`, opak `state` echo edilir. *"The `id` of the value MUST be the `stream_id`"*; stream'i tanımlayan subject **implicitly eklenir ve kaldırılamaz**.
- **Sıralama ve dayanıklılık — Argus için kritik normatif metin:** Pause durumunda *"The Transmitter SHOULD hold any events it would have transmitted while paused, and SHOULD transmit them when the stream's status becomes 'enabled'."* Ve: *"If a Transmitter holds successive events that affect the same Subject Principal, then the Transmitter MUST make sure that those events are transmitted in the order of time that they were generated OR the Transmitter MUST send only the last events that do not require the previous events affecting the same Subject Principal to be processed."*
  - → **Per-subject sıralama garantisi ZORUNLU.** Global sıralama değil. Bu, Argus'un yayın kuyruğunu **subject ID ile partition'lamasını** gerektirir (Kafka-benzeri key-based partitioning).
- `inactivity_timeout`: receiver aktivitesi yoksa stream pause/disable/delete edilebilir.
- **Genel sıralama garantisi yok:** *"Event Receivers MUST NOT depend on the Verification Event being transmitted synchronously or in any particular order relative to the current queue of events."*

### 5.2 SIEM entegrasyonu — IdP'ler ne gönderiyor

| Hedef | Format / mekanizma | Kaynak |
|---|---|---|
| Okta → Splunk Cloud | HTTP Event Collector (HEC), ham System Log JSON | help.okta.com log-streaming |
| Okta → AWS | Amazon EventBridge, ~30 sn gecikme, **filtreleme yok** | aynı |
| AWS Security Lake | **OCSF + Apache Parquet** (custom source için zorunlu) | docs.aws.amazon.com/security-lake |
| Auth0 | Log Streams (tenant başına 2-3), Marketplace connector'ları | auth0.com/docs |
| Entra ID | Azure Monitor / Log Analytics / Event Hub / Storage Account | learn.microsoft.com |
| Legacy | CEF (ArcSight), LEEF (QRadar), syslog | query.ai analizi |

Vendor normalize şemaları: **CIM** (Splunk), **ECS** (Elastic), **UDM** (Chronicle), **ASIM** (Microsoft Sentinel) — hepsi vendor-specific, lock-in yaratıyor.

→ **Argus'un çıktı stratejisi:** 1 canonical iç format (OCSF-uyumlu) + adaptörler: OCSF/Parquet→S3, SET/JWS→SSF push/poll, OTLP logs, HEC, syslog+CEF. Her adaptör < 500 satır. **Canonical formatı OCSF yapmak, adaptör sayısını minimize eder** çünkü hem Security Lake hem Sentinel hem Splunk OCSF ingest'i destekliyor.

### 5.3 Okta System Log API ve taksonomisi

**1.178 event tipi** (https://developer.okta.com/docs/reference/api/event-types/ — katalog sayısı doğrudan sayfadan).

Naming: hiyerarşik, nokta ayrık `parent.sublevel.action`:
- `access.request.*`, `access.review.*`
- `user.lifecycle.*`, `user.account.*`, `user.authentication.*`, `user.session.*`
- `app.oauth2.*`, `app.saml.*`, `application.lifecycle.*`
- `policy.sign_on.*`, `policy.rule.*`
- `device.enrollment.*`, `device.lifecycle.*`
- `system.*`, `account.org.*`

Event'lerde metadata tag'leri: `event-hook-eligible` (event hook uyumlu), `changeDetails` (değişiklik takibi içerir), `oie-only` (yalnızca Okta Identity Engine).

Tam katalog CSV olarak indirilebilir. System Log tablosu UI'dan CSV export edilebilir (https://help.okta.com/en-us/content/topics/reports/reports_syslog.htm).

→ **Argus için ders:** 1.178 sayısı, olgun bir IdP'nin denetim taksonomisinin gerçek büyüklüğüdür. Ama bu sayı **20 yıllık organik büyümenin** ürünü. Argus sıfırdan yazıldığı için: (a) `<parent>.<sublevel>.<action>` hiyerarşisini benimseyin (sorgu ve okunabilirlik için), (b) **her event tipini bir enum + registry'de tanımlayın** ve OCSF class'ına + CAEP tipine (varsa) statik olarak mapleyin, (c) `event-hook-eligible` benzeri **capability tag'leri** ekleyin — hangi event'in webhook/SSF'e uygun olduğunu şemadan okuyun, (d) katalogu **makine okunabilir olarak yayınlayın** (Okta'nın CSV'si gibi) — bu bir uyum artefaktıdır ve AU-2'nin "hangi olayları logluyoruz" gerekçelendirmesini otomatikleştirir.

### 5.4 Keycloak Event SPI — bilinen sınırlamalar

Keycloak resmî dokümantasyonu (https://www.keycloak.org/docs/latest/server_admin/, "Configuring auditing to track events"): user events + admin events, `EventListenerProvider` SPI, DB'de saklama, konfigüre edilebilir expiration.

**Evet — DB'ye yazma bir performans sorunu.** Kanıtlar:

Phase Two (6 Tem 2026): *"Event writes ride the request transaction"* — event yazımı authentication ile aynı transaction'da, login isteği insert'i bekliyor. `EVENT_ENTITY` "tens or hundreds of millions of rows"da DDL riskli. Expiry bulk-delete write-hot tabloya karşı → lock contention + I/O spike. Analytics için full-table scan.

Phase Two, "User Events in Keycloak" (1 Ağu 2025, https://phasetwo.io/blog/user-events-in-keycloak/): purge sırasında büyük hacimlerin aynı anda silinmesi *"can cause performance issues or even downtime"* ve *"effectively locks up the database and can lead to massive latency issues."* Önerilen: küçük batch'lerle manuel purge scripti veya retention penceresini yavaşça daraltma.

Diğer bulgular (skycloak.io, docs.redhat.com):
- `EVENT_ENTITY` tablosunda **sınırlı indeksleme**; uzun zaman aralığı veya karmaşık filtre kombinasyonlarında sorgu performansı tablo büyüdükçe bozuluyor.
- **Bütünlük yok:** *"Anyone with database access can modify or delete rows, which is not acceptable for compliance evidence."*
- Öneri: DB event store'u **7-30 günlük operasyonel lookup** için kullan, uzun saklama/compliance için harici sistem.

→ **Bu, Argus'un en somut rekabet avantajı.** Keycloak'ın audit'i: (a) request path'te senkron, (b) tamper-evident değil, (c) purge'ü DB'yi kilitliyor, (d) analitik yapılamıyor. Argus dördünü de yapısal olarak çözebilir.

---

## 6. Kullanıcıya görünen denetim (user-facing audit)

### 6.1 Büyük sağlayıcıların yaklaşımı

**Google** (https://support.google.com/accounts/answer/3067630): "Devices" sayfası *"computers, phones, and other devices where you are or were signed in to your Google Account recently"* — **"son birkaç hafta"**. Gösterilen alanlar: cihaz tipi/adı, oturum bilgisi, son iletişim zaman damgası (*"the last time there was communication between the device or session and Google's systems"* — dikkat: bu login zamanı DEĞİL), oturum durumu (Signed out), yaklaşık konum. Aksiyonlar: cihaz detayı görüntüle, **sign out**, aynı cihazdaki birden fazla oturumu ayrı yönet.

**GitHub** (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events): kullanıcı hesabı **security log**'u — login/logout, başarısız kimlik doğrulama, şifre ve SSH key değişiklikleri, 2FA olayları, OAuth token grant/revoke. Naming: `<category>.<operation>` (örn. `repo.create`). Kategoriler: authentication & access, account management, repository operations, collaboration, security features, GitHub Actions, billing & sponsors, apps & integrations, gists/pages/codespaces/projects. Organizasyon/enterprise **audit log** ayrı bir şey (kim ayarları/izinleri/üyelikleri değiştirdi).
- ⚠️ Kullanıcı security log'unun **retention süresi ve export seçeneği dokümante edilmemiş.**

**Apple:** ⚠️ Kullanıcıya gösterilen giriş geçmişi için birincil kaynak **doğrulanamadı**.

**Ortak desen (Google + GitHub):**
1. **Aksiyon odaklı, arşiv değil.** Google "son birkaç hafta" gösteriyor ve yanına "Sign out" butonu koyuyor. Amaç adli değil, **hesap kurtarma/tepki**.
2. Alan seti minimal: ne / ne zaman / nereden (yaklaşık) / hangi cihaz.
3. **Konum yaklaşık** — tam IP gösterilmiyor (Google'da); GitHub gösteriyor.
4. Ayrı iki sistem: kullanıcı security log ≠ org audit log.

### 6.2 GDPR Md. 15 / Md. 20 ile ilişkisi — önemli bir düzeltme

**Art. 15 (erişim hakkı)** (https://gdpr-info.eu/art-15-gdpr/): işleme amaçları, **ilgili kişisel veri kategorileri**, alıcılar/alıcı kategorileri (özellikle üçüncü ülkeler), saklama süresi, haklar, şikâyet yolu, verinin kaynağı, otomatik karar verme. Elektronik talepte *"the information shall be provided in a commonly used electronic form."*
- Giriş geçmişi Art. 15'te ayrı bir kategori olarak sayılmıyor, ama işleniyorsa **"ilgili kişisel veri kategorileri"** altına girer.

**Art. 20 (taşınabilirlik)** (https://gdpr-info.eu/art-20-gdpr/): kapsam *"personal data concerning him or her, which he or she has **provided to** a controller"*, koşullar: (a) rıza veya sözleşme temelli, (b) otomatik araçlarla. Format: **structured, commonly used, machine-readable**. Teknik olarak mümkünse doğrudan controller-to-controller transfer.

**🔴 Kritik nüans — "provided by" observed data'yı KAPSAR.** WP29 **WP251rev.01** "Guidelines on Automated individual decision-making and Profiling" (3 Ekim 2017 kabul, 6 Şubat 2018 revize; PDF indirilip metin çıkarıldı, https://ec.europa.eu/newsroom/article29/items/612053/en) açıkça diyor:

> *"This differs from the right to data portability under Article 20 where the controller only needs to communicate the data **provided by the data subject or observed by the controller** and not the profile itself."*

Aynı belge veri kategorilerini üçe ayırıyor: (1) *"data provided directly by the individuals concerned (such as responses to a questionnaire)"*, (2) *"data observed about the individuals (such as location data collected via an application)"*, (3) *"derived or inferred data such as a profile of the individual that has already been created (e.g. a credit score)"*.

→ **Giriş geçmişi = observed data = Art. 20 kapsamında.** Sizin daha önceki tespitiniz doğru ve şimdi birincil (WP29/EDPB) kaynakla desteklendi. **Türetilmiş veri (risk skoru, davranışsal profil) kapsam dışı.**

→ **Argus'ta bunun karşılığı:** ham denetim olayları (login zamanı, IP, cihaz, sonuç) taşınabilir; **risk skorları ve anomali sinyalleri taşınabilir DEĞİL** ve kullanıcıya da gösterilmemeli (tersine mühendislik riski). Bu ayrımı şemada `portability: included|excluded` bayrağıyla kodlayın.

### 6.3 Kullanıcıya gösterilen vs SOC'a gösterilen — fark tablosu

| Boyut | Kullanıcıya (self-service) | SOC/SIEM'e |
|---|---|---|
| Zaman penceresi | Son 30-90 gün (Google: "birkaç hafta") | Tam retention (12+ ay) |
| Olay kapsamı | Kendi hesabı; başarılı + başarısız kimlik doğrulama, credential değişimi, oturum | Tüm kiracı; ayrıca admin, config, policy, token, meta-audit |
| Konum | Şehir/ülke düzeyi (Google) | Tam IP, ASN, geo, TOR/proxy sinyalleri |
| Risk sinyalleri | **Gösterilme** (tersine mühendislik) | Tam |
| Diğer kullanıcılar | Asla | Kiracı kapsamında hepsi |
| Aksiyon | Sign out, credential revoke, "bu ben değildim" | Sorgulama, korelasyon, export |
| Format | İnsan okunabilir UI + Art.20 export (JSON) | OCSF/SET/Parquet |
| Rate limit | Sıkı (enumeration/scraping) | Gevşek, API key ile |
| Gecikme | Yakın-gerçek-zaman kabul edilebilir | Yakın-gerçek-zaman istenir |
| Erişimin kendisi loglanır mı | **Evet** (PCI 10.2: audit trail'lere erişim) | **Evet** |

**Ek güvenlik notu:** kullanıcı-görünür audit'in kendisi bir saldırı yüzeyidir. IP/konum göstermek, hesabı ele geçirmiş saldırgana kurbanın hareketlerini gösterir. Google'ın yaklaşık konum kullanması muhtemelen bilinçli. **Argus: kullanıcı görünümünde IP'yi maskele (/24 veya sadece şehir), tam IP'yi yalnızca Art.15 SAR export'unda ver.**

---

## 7. Argus için somut tasarım kararları

**K1 — Düz append-only + ~1 sn Merkle checkpoint kararı DOĞRU; per-event hash chain'i tamamen bırakın.** Crosby & Wallach Tablo 2: commitment imzalama insert maliyetinin **%83,3**'ü, tek başına 2.100 ev/s tavanı; 16'da 1 imza ile 1.750 → ~17.000 ev/s (**~10x**). Agent Flight Recorder: hash chain medyan gecikmeyi 6 µs → 48 µs (8x) çıkarıyor, Merkle batching üstüne sadece +0,6 µs ekliyor. *(https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf; https://arxiv.org/html/2609.01931)*

**K2 — Checkpoint aralığını "Maximum Merge Delay" olarak ilan edin ve SLA yapın.** RFC 9162'nin MMD kavramı: log, SCT verdikten sonra girdiyi ağaca dahil etmeyi taahhüt eder. Argus: "MMD ≤ 1s". Let's Encrypt Sunlight bunu fiilen 0'a indirdi (*"always completely incorporate newly-submitted certificates before returning an SCT"*) — Argus da yüksek değerli olaylar (admin, credential change) için sync-checkpoint modu sunabilir. *(https://www.rfc-editor.org/rfc/rfc9162.html; https://letsencrypt.org/2025/06/11/reflections-on-a-year-of-sunlight)*

**K3 — Hash chain yerine history tree / tlog yapısı: proof boyutu için.** Hash chain'de incremental ve membership proof O(n−k); history tree'de O(log²n). 80M olaylı log'da rastgele bir olayın kanıtı: hash chain **800 MB**, history tree **3 KB**. Argus'un doğrulama API'si (`GET /audit/{id}/proof`) ancak logaritmik yapıyla kullanılabilir. *(Crosby & Wallach §3.4)*

**K4 — Sequencing ile integration'ı ayırın (Tessera modeli).** Sequencing durable index atar (batch içinde sıra garantisi yok), integration arka planda Merkle'a birleştirir. `WithBatching` + `WithCheckpointInterval` eşdeğeri konfigürasyonlar. Tessera POSIX/NVMe **10.000 write QPS @ 7 çekirdek** — bu, sequencing + integration yapan tam bir tlog'un değeri ve Argus için gerçekçi bir hedef büyüklüğü. ⚠️ *Önceden burada 22.440 ile karşılaştırma yapılıyordu; o çıplak-insert ölçümü bu rakamla kıyaslanabilir değil (§6 §4.4).* Taşınan sonuç: sequencing/integration ayrımı checkpoint eklemenin throughput'u öldürmediğini gösteriyor. *(https://github.com/transparency-dev/tessera/blob/main/docs/performance.md)*

**K5 — İmzalamayı ayrı çekirdeğe/HSM'e offload edin, insert path'inden çıkarın.** Crosby: imza offload edilince 1.750 → 10.500 ev/s. Argus: checkpoint imzalama ayrı bir task/thread'de; insert path'i asla imza beklemez. *(aynı)*

**K6 — Checkpoint'leri DIŞARI yayınlayın (witness/gossip), yoksa bütünlük iddiası boştur.** *"an untrusted logger is free to have different snapshots make inconsistent claims about the past"* (Crosby §2). Ayrıca Postgres superuser her koruma katmanını aşabilir (*"anyone with enough access can still alter history"*). Yayın hedefleri: müşteri webhook'u, S3 WORM/Object Lock, opsiyonel public transparency log. **Bu, Keycloak'ın "anyone with database access can modify or delete rows" zaafına verilen doğrudan cevaptır.** *(https://heypinchy.com/blog/day-143-the-hole-in-append-only; https://phasetwo.io/blog/scaling-keycloak-event-storage/)*

**K7 — Postgres append-only'yi 3 katmanda zorlayın; `BEFORE TRUNCATE` trigger'ı UNUTMAYIN.** (a) `REVOKE UPDATE, DELETE` her rolden, (b) `BEFORE UPDATE OR DELETE` row-level trigger, (c) **`BEFORE TRUNCATE` statement-level trigger** — row-level trigger'lar TRUNCATE'te ateşlenmez, bu "append-only" iddiasındaki en yaygın sessiz delik. *(https://heypinchy.com/blog/day-143-the-hole-in-append-only, 10 Tem 2026)*

**K8 — Audit'in PAHALI İŞİNİ request transaction'ından çıkarın; KABULÜNÜ çıkarmayın.** Keycloak'ın 1 numaralı arızası doğru teşhis: *"Event writes ride the request transaction"* — login isteği DB insert'ini bekliyor.

> ⚠️ **Düzeltme (2. inceleme turu) — bu maddenin önceki hâli yanlıştı.** Önceden şöyle diyordu: *"audit olayı bounded, backpressure'lı bir in-memory kuyruğa yazılır; kuyruk dolarsa isteği reddet."* Kuyruğu sınırlamak taşmayı önler ama **süreç çökmesini karşılamaz:** iş değişikliği commit olur, kullanıcı başarılı yanıt alır, olay bellekte beklerken süreç ölürse **değişiklik kalıcıdır ama denetim kaydı yoktur.** AU-12/PCI 10.2'nin "all" gereği tam olarak bunu yasaklar. Ayrıca bu, hemen üstteki **K4** ile çelişiyordu: K4 Tessera modelini benimserken *"sequencing **durable** index atar"* diyor.
>
> **Doğrusu — iki aşamayı ayır:**
> 1. **Kalıcı kabul (aynı transaction).** İş değişikliğiyle **atomik** olarak minimal bir `audit_outbox` satırı yazılır. Ya ikisi de olur ya hiçbiri. Maliyeti tek bir küçük insert'tir, Merkle veya imza değil.
> 2. **Pahalı işleme (arka plan).** Merkle birleştirme, checkpoint imzalama ve dışa yayın kuyruk üzerinden, request path'in dışında yürür. Bu kuyruk bellekte olabilir — çünkü kaybı yalnızca *gecikme* yaratır, kayıt kaybı yaratmaz.
>
> **Ayrıca tanımlanması gereken:** başarısız giriş gibi **commit edilmiş bir iş değişikliği bulunmayan** olayların kalıcılığı ayrı bir kuraldır — atomik bağlanacağı bir transaction yoktur. Bu olaylar için kabul noktası açıkça seçilmeli.

*(https://phasetwo.io/blog/scaling-keycloak-event-storage/; karar satırı: §1 §1 madde 23; statü: §1 §10.3 A1)*

**K9 — Retention'ı partition DROP/DETACH ile yapın, asla bulk DELETE ile değil.** Keycloak'ın purge'ü *"effectively locks up the database and can lead to massive latency issues."* Argus: günlük/haftalık range partition; `DETACH PARTITION ... CONCURRENTLY` (yalnızca `SHARE UPDATE EXCLUSIVE`) → S3'e arşivle → `DROP`. *(https://phasetwo.io/blog/user-events-in-keycloak/; https://www.postgresql.org/docs/current/ddl-partitioning.html)*

**K10 — Katmanlama: Postgres (sıcak 30-90 gün) → OCSF+Parquet/S3 (soğuk, süresiz) → ClickHouse (analitik, opsiyonel).** Phase Two'nun kanıtlanmış boru hattı; ClickHouse ~14x sıkıştırma; "bir yıllık login trendi" sorgusu **onlarca ms**. ⚠️ Onların öğrendiği ders: ClickHouse tablo depolamasını S3'te tutmayın (merge'ler cluster başına 150 req/s üretti) — **yerel NVMe**. *(https://phasetwo.io/blog/scaling-keycloak-event-storage/; https://clickhouse.com/docs/en/use-cases/observability/introduction)*

**K11 — Soğuk katmanı OCSF + Parquet yazın; bedavaya AWS Security Lake uyumu kazanın.** Security Lake custom source kontratı tam olarak bu. Ayrıca OCSF, Splunk/Sentinel/Query gibi platformlarda ingest ediliyor. ⚠️ Sürüm uyumluluğunu konfigüre edilebilir yapın: Security Lake hâlâ 1.0.0-rc.2 / 1.1.0 kullanıyor, OCSF ise 1.9.0'da. *(https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)*

**K12 — OCSF `record_integrity` profilini (1.9.0) benimseyin — Merkle modeliniz için hazır wire format.** `attestation` nesnesi: `chain_uid` (*"Identifier of the append-only chain, such as a forensic or audit log"*), `fingerprint` (*"fingerprint of this event's canonical serialization"*), `prev_event`, `signatures`, `authority_uid`. Çoklu attestation destekleniyor (write-time producer + ingest-time processor). **Argus'un checkpoint'i, olayın kendisine gömülü per-event chain yerine ayrı bir attestation olarak ifade edilebilir.** *(https://schema.ocsf.io/1.9.0/profiles/record_integrity; https://raw.githubusercontent.com/ocsf/ocsf-schema/main/objects/attestation.json)*

**K13 — Canonical iç şema = OCSF IAM sınıfları (3001-3008); SET yalnızca egress.** Authentication [3002] zorunlu alanları (`time`, `metadata`, `severity_id`, `user`, + `dst_endpoint`|`service`) minimum kontrat; `activity_id`, `auth_protocol_id`, `is_mfa`, `logon_type_id`, `status_id` doğrudan Argus alanlarına maplenir. **SET'i depolama formatı yapmayın** — JWT/JWS base64 overhead'i ve per-event imzası (K1'in reddettiği şey) getirir. *(https://schema.ocsf.io/1.7.0/classes/authentication; https://www.rfc-editor.org/rfc/rfc8417.html)*

**K14 — `jti` + `txn` + `toe` üçlüsünü şemada birinci sınıf yapın.** RFC 8417: `jti` idempotency/dedup (*"MAY be used by clients to track whether a particular SET has already been received"*), `txn` korelasyon, **`toe` olayın gerçekleşme zamanı — `iat` (kayıt zamanı) ile karıştırılmamalı**. Argus'ta üç farklı zaman damgası olmalı: `occurred_at` (toe), `recorded_at` (iat), `checkpoint_at`. Adli analizde bu ayrım kritiktir. *(https://www.rfc-editor.org/rfc/rfc8417.html)*

**K15 — SET yayınında per-subject sıralama garantisi ZORUNLU.** SSF 1.0: *"the Transmitter MUST make sure that those events are transmitted in the order of time that they were generated OR the Transmitter MUST send only the last events..."* → Yayın kuyruğunu **subject ID ile partition'layın**; global sıralama gerekmez (ve maliyetlidir). *(https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)*

**K16 — İki ayrı yayın kanalı: CAEP stream (8 tip, aksiyon) + Audit stream (tam taksonomi, kayıt).** CAEP 1.0 Final'in 8 tipi (`session-established/presented/revoked`, `credential-change`, `assurance-level-change`, `token-claims-change`, `device-compliance-change`, `risk-level-change`) Argus'un iç olay evreninin küçük bir alt kümesini kapsar — "başarısız login" veya "admin client secret rotate etti" karşılığı yok. Aynı bus, iki adaptör, ortak `txn`. Poll delivery (RFC 8936) varsayılan olmalı (SSF'in kendi varsayılanı). *(https://openid.net/specs/openid-caep-1_0-final.html; 2 Eyl 2025 Final)*

**K17 — Audit'te SAMPLING YASAK; yalnızca EVENT SELECTION var.** PCI DSS 10.2 "**all** individual access", "**all** transactions... with root or administrative privileges". NIST AU-2 olay tipi *seçimine* izin verir (gerekçelendirilmiş, periyodik gözden geçirilen), olay tipinin örneklenmesine değil. Telemetry path'te sampling serbest ve zorunlu. **İki path'i asla aynı pipeline'a koymayın.** *(https://pcidssguide.com/pci-dss-requirement-10/; https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/)*

**K18 — Audit log'a ERİŞİM de audit event üretmeli (meta-audit).** PCI DSS 10.2: "Access to all audit trails" loglanmalı. Sonsuz döngü riskine karşı: meta-audit ayrı bir chain_uid'de, coalesced (sorgu başına 1 kayıt, sonuç satırı başına değil). En sık atlanan gereksinim. *(aynı)*

**K19 — Kriptografik bütünlük Moderate baseline'da zaten zorunlu; AU-10'u varsayılan yapın.** AU-9(3) (kriptografik bütünlük koruması) Moderate+ baseline'da; AU-9 Rev.5 tamper alarmı ekledi; AU-10 (non-repudiation) High'da. IdP tanım gereği High sistemlerin kimlik kaynağıdır → **checkpoint'ler yalnızca hash'lenmemeli, İMZALANMALI** (non-repudiation imza gerektirir). *(https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/, .../au-10/)*

**K20 — AU-3 + PCI 10.3 birleşik minimum alan seti şemanın değişmez çekirdeği olsun.** event type, when, where (event location), source, outcome (success/failure), identity of subject/object, affected resource id. AU-3(3) (privacy baseline) PII'yi sınırlamayı emrediyor → **her alanı `pii: yes|no` + `retention_class` ile etiketleyin**, K22'yi mümkün kılmak için. *(https://csf.tools/reference/nist-sp-800-53/r5/au/au-3/)*

**K21 — Saklama süresi Argus'un değil, kiracının kararı; mekanizmayı per-tenant + per-event-class sunun.** Çelişki gerçek: PCI 12 ay (son 3 ay hemen erişilebilir) vs CNIL 6 ay-1 yıl (iç kontrolle 3 yıla kadar, Délibération 2021-122, 14 Eki 2021) vs GDPR Art.5(1)(e) storage limitation. Sektör deseni: Okta 90 gün, Entra P1/P2 30 gün, Auth0 1-30 gün — **hiçbir büyük IdP PCI'ın 12 ayını kendi içinde karşılamıyor**, hepsi streaming export'a devrediyor. Argus da bu modeli benimsemeli ama daha uzun sıcak pencere sunarak farklılaşabilir. *(https://www.cnil.fr/fr/la-cnil-publie-une-recommandation-relative-aux-mesures-de-journalisation; sağlayıcı retention tablosu §3.1)*

**K22 — Olay iskeletini PII'den ayırın: iskelet uzun, PII kısa yaşasın.** PCI'ın 12 ayı olay *izine*, CNIL'in 6 ayı *PII'ye* yönelik. Argus: `audit_event` (pseudonymous subject id, event type, outcome, timestamp — 12+ ay) + `audit_event_pii` (IP, UA, e-posta — per-subject key ile şifreli, 6 ayda crypto-shred). **İkisi de aynı Merkle ağacında, hash ciphertext üzerinden.** Bu, K23'ün ön şartıdır.

**K23 — Crypto-shredding: hash ciphertext üzerinden; ama "GDPR erasure" diye PAZARLAMAYIN.** Desen doğru ve uygulanıyor: per-subject key, key material NULL'a çekilir, keyref tombstone kalır, tek bir immutable "erasure fact" satırı append edilir, ledger'a dokunulmaz. **⚠️ Ama EDPB Guidelines 01/2025 (16 Oca 2025): *"the pseudonymised data can be considered anonymous only if the conditions for anonymity are met"* — anahtar silmek otomatik anonimleştirme değildir.** Dokümantasyonda "irreversible de-identification of log content, subject to the controller's own DPIA" olarak konumlandırın. *(https://www.tdcommons.org/dpubs_series/10873/; https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf)*

**K24 — Rust yığını: `tracing` (0.1.44) facade + opentelemetry-rust logs/metrics (Stable) + traces (Beta, dikkatli).** Logs API/SDK ve Metrics API/SDK **Stable**; Traces API/SDK **Beta**; OTLP exporter'lar RC (logs/metrics) ve Beta (traces). MSRV 1.75. **🔴 Hepsi pre-1.0, lockstep versiyonlanıyor, breaking change'ler minor'da geliyor → OTel'i kod tabanına yaymayın, kendi ince facade'ınızın arkasına koyun.** *(https://github.com/open-telemetry/opentelemetry-rust)*

**K25 — Metrik için OpenTelemetry metrics seçin (`metrics` crate'i değil).** Metrics API/SDK zaten Stable; OTLP tek hatta log/metrik/trace korelasyonu; kiracıya "kendi OTLP endpoint'inize gönderelim" demek satılabilir bir özellik. `metrics` crate'in tek avantajı olan backend-swap, OTel Collector ile zaten çözülüyor. *(aynı; https://crates.io/crates/metrics-prometheus)*

**K26 — Metrikte kiracı etiketi YOK; kiracı kırılımı ClickHouse rollup'larından.** 1M aktif seri ≈ **4-6 GB RAM sadece head block için**. 1.000 kiracı × 50 client × 20 event × 5 durum = 5M seri = 20-30 GB → yıkıcı. Çözüm: (a) **exemplars** ile histogram bucket'ına trace ID iliştir (per-request label maliyeti ödemeden drill-down), (b) **native histograms** (Prometheus 3.x'te olgun) seri sayısını yapısal olarak düşürür, (c) kiracı kırılımı 5 dakikalık rollup tablolarından, (d) en fazla ~50 "top tenant" için allowlist'li metrik. *(https://systeminternals.dev/observability/cardinality/; https://last9.io/blog/how-to-manage-high-cardinality-metrics-in-prometheus/)*

**K27 — PII/secret taşıyan hiçbir tipte `#[derive(Debug)]` olmayacak; CI'da zorunlu kılın.** `secrecy` v0.10.3: `SecretBox`/`SecretString`, `Display`/`Debug` yok, `expose_secret()` zorunlu, drop'ta zeroize, **serde ile varsayılan olarak serialize edilemez**. Rust'a özgü tuzak: derive'lı `Debug`, struct'a sonradan eklenen bir `refresh_token` alanını hiçbir log satırı değişmeden sızdırır. ⚠️ Zeroize best-effort'tur, garanti değil (RUSTSEC-2024-0342: *"inherent limitations of Rust regarding absolute zeroization"*). *(https://docs.rs/secrecy/latest/secrecy/; https://osv.dev/vulnerability/RUSTSEC-2024-0342)*

**K28 — Telemetride `enduser.pseudo.id`, audit'te gerçek `user.id`.** OTel semconv 1.44: `enduser.id` (aktif, Development, "contains sensitive PII"), `enduser.pseudo.id` (aktif, Development, "random non-linked"), `enduser.role`→`user.roles` deprecated, `enduser.scope` deprecated (yerine geçen yok). Tüm `user.*` alanları Development. **Semconv'a hard bağımlılık kurmayın — mapping katmanı koyun.** *(https://opentelemetry.io/docs/specs/semconv/registry/attributes/enduser/, .../user/)*

**K29 — Kendi event taksonomisini kurun; OTel'de kimlik/auth convention YOK.** Semconv 1.44'te HTTP, DB, messaging, GenAI, CI/CD, FaaS var; **authentication/identity/IAM/security yok.** Argus: Okta'nın `<parent>.<sublevel>.<action>` hiyerarşisini benimseyin (Okta'da **1.178 event tipi** var — olgun bir IdP'nin gerçek büyüklüğü), her tipi enum+registry'de tanımlayıp OCSF class'ı ve (varsa) CAEP tipiyle statik mapleyin, `event-hook-eligible` benzeri capability tag'leri ekleyin, ve **katalogu makine okunabilir yayınlayın** — bu AU-2'nin "hangi olayları logluyoruz ve neden" gerekçelendirmesini otomatikleştiren bir uyum artefaktıdır. OTel Event kuralı: *"Event names MUST NOT include dynamic values."* *(https://opentelemetry.io/docs/specs/semconv/; https://developer.okta.com/docs/reference/api/event-types/)*

**K30 — Kullanıcı-görünür audit: aksiyon odaklı, 30-90 gün, IP maskeli, risk sinyali yok.** Google "son birkaç hafta" + "Sign out" butonu; GitHub `<category>.<operation>` ile login/2FA/key/OAuth olayları. Kullanıcı görünümünde IP'yi maskeleyin (/24 veya şehir) — hesabı ele geçirmiş saldırgana kurbanın hareketlerini göstermeyin. Risk skorları hiç gösterilmez (tersine mühendislik). *(https://support.google.com/accounts/answer/3067630; https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events)*

**K31 — Art. 20 export'unda observed data DAHİL, derived data HARİÇ; şemada bayrakla kodlayın.** WP29 WP251rev.01 (3 Eki 2017 / 6 Şub 2018): *"the right to data portability under Article 20 where the controller only needs to communicate the data provided by the data subject **or observed by the controller** and not the profile itself."* → Giriş geçmişi (observed) taşınabilir; risk skoru/profil (derived) taşınabilir değil. Format: structured + commonly used + machine-readable (Art. 20(1)) → JSON, tercihen OCSF. Her audit alanına `portability: included|excluded` bayrağı koyun. *(https://ec.europa.eu/newsroom/article29/items/612053/en; https://gdpr-info.eu/art-20-gdpr/)*

**K32 — pgaudit'i birincil audit kaynağı YAPMAYIN; ikincil DB-seviyesi kontrol olarak kullanın.** *"Audit logging is best-effort and not transactional"* — crash'te kayıt kaybolur, bu tek başına compliance-grade audit için diskalifiye edicidir. Ayrıca: object audit logging'de **TRUNCATE desteklenmiyor**, superuser auditing güvenilmez, *"possible for pgAudit to generate an enormous volume of logging"*. Değeri: Argus DB'sine **uygulama dışından** yapılan doğrudan erişimi yakalamak (AU-9 destekleyici kontrol). *(https://github.com/pgaudit/pgaudit)*

**K33 — Managed ledger servislerine bağımlılık kurmayın.** AWS QLDB **31 Temmuz 2025'te destek dışı**, resmî duyuru bile yapılmadan (dokümantasyon güncellemesi + müşteri e-postası, Temmuz 2024). AWS'in önerdiği Aurora PostgreSQL göçü **kriptografik doğrulanabilirliği kaybettiriyor**. Ders: "kriptografik ledger" ayrı bir ürün kategorisi olarak ticari başarısızlık; müşteriler ayrı DB değil, **mevcut DB'de bütünlük özelliği** istiyor. Argus'un "Postgres + ince Merkle katmanı" kararı bu dersle uyumlu. *(https://www.infoq.com/news/2024/07/aws-kill-qldb; https://techcommunity.microsoft.com/blog/azuresqlblog/moving-from-amazon-quantum-ledger-database-qldb/4246237)*

**K34 — Yıllık log shard'ları + statik tile arşivi (Rekor v2 deseni).** Rekor v2 (GA 10 Eki 2025): yıl başına yeni shard (`log2025-1`), eski shard dondurulup statik tile olarak arşivleniyor, tile'lar immutable + content-addressed + **CDN-cacheable**. Bu, hem Merkle ağacının sınırsız büyümesini hem doğrulama maliyetini sınırlar. Argus: kiracı × yıl shard'ı; dondurulmuş shard'ın son checkpoint'i sonsuza dek doğrulanabilir kalır. *(https://blog.sigstore.dev/rekor-v2-ga/)*

**K35 — Tek canonical format + ince adaptörler; her adaptör < 500 satır.** Hedefler: OCSF/Parquet→S3, SET/JWS→SSF push (RFC 8935) & poll (RFC 8936), OTLP logs, Splunk HEC, syslog+CEF (legacy). CEF/LEEF ölmedi ama *"network security centric... force-fit"* ve single-line syslog odaklı; OCSF halef. **Canonical'ı OCSF yapmak adaptör sayısını ve dönüşüm kaybını minimize eder.** ⚠️ Okta'nın "no event filtering is supported" kısıtını tekrarlamayın — Argus stream'lerinde event tipi filtresi olsun. *(https://www.query.ai/resources/blogs/cybersecurity-event-data-normalization-standards/; https://help.okta.com/oie/en-us/content/topics/reports/log-streaming/about-log-streams.htm)*

**K36 — Merkle domain separation'ı doğru yapın: leaf `0x00`, node `0x01`.** RFC 9162: `MTH({d})= HASH(0x00 || d)`, iç düğüm `HASH(0x01 || left || right)`. Bu prefix'ler second-preimage resistance için **zorunlu**; atlamak leaf/node karıştırma saldırısına açar. Ayrıca STH kuralı: *"Each subsequent timestamp MUST be more recent than the timestamp of the previous update."* *(https://www.rfc-editor.org/rfc/rfc9162.html)*

**K37 — Proof üretiminde locality'yi mimarinin merkezine koyun.** Crosby Tablo 2: membership proof **8.600/s (locality ile) vs 32/s (locality yok)** — **269x fark**. Bu, Merkle düğümlerinin disk yerleşiminin (post-order traversal, sabit boyutlu düğüm, direct access) proof API'sinin kullanılabilirliğini tek başına belirlediği anlamına gelir. Değişken boyutlu olay içeriği ayrı bir write-once append-only value store'da, ağaç yaprakları offset tutar. *(Crosby & Wallach §3.3, §5)*

**K38 — Bütünlük anchor'ı için blockchain'e GEREK YOK; witness yeterli.** Agent Flight Recorder ölçümü: L2 anchoring **$2,30/100K olay**, L1 **$6.885/100K olay**, anchor başına 91.800 gas. ⚠️ *Önceki hesap 22.440 tps'yi sürekli hacim sayıp ≈1,94 milyar olay/gün türetiyordu; o sayı 12 sn'lik çıplak-insert ölçümüdür (§6 §4.4) ve böyle çarpılamaz.* Yön yine de sağlam: olay başına on-chain anchoring maliyeti, herhangi bir ciddi IdP hacminde witness/S3 Object Lock alternatifinin yanında kabul edilemez kalır. **Alternatif: checkpoint'i müşteri webhook'una + S3 Object Lock'a + opsiyonel üçüncü taraf witness'a yayınlayın.** Compromise window aynı, maliyet ~sıfır. *(https://arxiv.org/html/2609.01931)*

---

## 8. ⚠️ DOĞRULANAMAYANLAR

1. **⚠️ DOĞRULANMADI — Büyük IdP'lerin gerçek log hacimleri.** Okta, Auth0, Keycloak veya Entra ID için kamuya açık, birincil kaynaklı **event/saniye veya GB/gün** rakamı bulunamadı. Sektör yalnızca saklama süreleri üzerinden konuşuyor. Tek somut kıyas Crosby & Wallach 2009 (10.500 ev/s = 1,9 MB/s = 1,1 TB/hafta) ve o da 2009 syslog'u.

2. **⚠️ DOĞRULANMADI — Okta System Log API (`/api/v1/logs`) rate limit'leri.** Okta dokümantasyonu bunları "Rate Limit Dashboard"a havale ediyor; sayısal RPM değerleri kamuya açık sayfalarda bulunamadı.

3. **⚠️ DOĞRULANMADI — GitHub kullanıcı security log'unun retention süresi ve export seçeneği.** Dokümantasyon event kategorilerini listeliyor ama saklama süresi veya kişisel hesap için export yolu belirtmiyor.

4. **⚠️ DOĞRULANMADI — Apple'ın kullanıcıya gösterdiği giriş/hesap etkinliği geçmişi.** Birincil Apple Support kaynağı bu oturumda getirilemedi. Google ve GitHub deseni üzerinden genelleme yapıldı.

5. **⚠️ DOĞRULANMADI — Splunk CIM Authentication data model'in tam alan listesi ve tag'leri.** docs.splunk.com iki farklı URL'de HTTP 403 döndürdü.

6. **⚠️ DOĞRULANMADI — SOC 2'nin sayısal log saklama gereksinimi.** Birincil AICPA kaynağı bulunamadı. Pratikte "1 yıl gözlem penceresi" yaygın ama bu bir denetim uygulaması, normatif bir eşik değil.

7. **⚠️ DOĞRULANMADI — `tracing` / `tracing-opentelemetry` için nanosaniye seviyesinde yayınlanmış bağımsız benchmark.** Yalnızca niteliksel iddialar var ("zero-cost when disabled", "small overhead per span"). Argus'un 22k tps'sinde `#[instrument]` maliyeti **kendiniz ölçmelisiniz**.

8. **⚠️ DOĞRULANMADI — Tessera'nın varsayılan batch size ve checkpoint interval değerleri.** README ve performance.md konfigürasyon adlarını (`WithBatching`, `WithCheckpointInterval`, `WithCheckpointRepublishInterval`) veriyor ama varsayılanları belirtmiyor.

9. **⚠️ DOĞRULANMADI — Rekor v2'nin somut maliyet düşüş yüzdesi ve QPS rakamları.** GA blog'u yalnızca niteliksel ("cheaper to run", "higher QPS") ifadeler kullanıyor; sayı vermiyor.

10. **⚠️ DOĞRULANMADI — OCSF v1.9.0'ın tam release notes'u.** GitHub `releases/tag/v1.9.0` sayfası 404 döndü; bilgi releases liste sayfası ve şema/profil dosyalarından (`record_integrity.json`, `attestation.json`, schema.ocsf.io 1.9.0) derlendi. Sürüm ve tarih (3 Ağustos 2026) releases listesinden doğrulandı.

11. **⚠️ KISMEN DOĞRULANMADI — WP242rev.01'in (portability guidelines) doğrudan metni.** İndirme denemesi başka bir belgeye (WP251rev.01) yönlendi. Ancak WP251rev.01 aynı hukuki noktayı açıkça ifade ediyor (*"data provided by the data subject or observed by the controller"*), bu yüzden K31'in dayanağı birincil ve geçerlidir — sadece WP242'nin "activity logs / search history" örneklerini içeren spesifik paragrafı alıntılanamadı.

12. **⚠️ DOĞRULANMADI — CNIL Délibération 2021-122'nin tam metni.** CNIL'in resmî duyuru sayfası (tarih, 6 ay–1 yıl / 3 yıl kademeleri, minimum log içeriği, otomatik analiz zorunluluğu, 8 haftalık istişare / 43 katkı) doğrulandı; délibération PDF'inin kendisi getirilmedi.

13. **⚠️ DOĞRULANMADI — PCI DSS v4.0.1'in resmî metni.** PCI SSC'nin kendi PDF'i (kayıt gerektirir) getirilemedi; 10.2/10.3/10.5/10.7 içeriği ikincil ama tutarlı kaynaklardan (pcidssguide, ZenGRC, KirkpatrickPrice) derlendi. Sayısal eşikler (12 ay / 3 ay) birden fazla bağımsız kaynakta tutarlı.

14. **⚠️ DOĞRULANMADI — CADF'in 2025-2026'daki güncel benimseme durumu.** DMTF sayfaları standardın varlığını gösteriyor; OpenStack dışında güncel bir kullanıcı veya son yıllara ait bir güncelleme kanıtı bulunamadı.

---

## Kaynaklar

**Standartlar / RFC'ler**
- [RFC 8417 — Security Event Token (SET)](https://www.rfc-editor.org/rfc/rfc8417.html)
- [RFC 9967 — SCIM Profile for Security Event Tokens](https://www.rfc-editor.org/rfc/rfc9967.html)
- [RFC 9162 — Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html)
- [OpenID CAEP 1.0 (Final)](https://openid.net/specs/openid-caep-1_0-final.html)
- [OpenID Shared Signals Framework 1.0 (Final)](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
- [Three Shared Signals Final Specifications Approved — OpenID Foundation](https://openid.net/three-shared-signals-final-specifications-approved/)

**OCSF**
- [OCSF Schema 1.9.0 — Categories](https://schema.ocsf.io/1.9.0/categories?extensions=)
- [OCSF Authentication [3002]](https://schema.ocsf.io/1.7.0/classes/authentication)
- [OCSF record_integrity profile](https://schema.ocsf.io/1.9.0/profiles/record_integrity?extensions=)
- [OCSF attestation object (raw)](https://raw.githubusercontent.com/ocsf/ocsf-schema/main/objects/attestation.json)
- [OCSF releases](https://github.com/ocsf/ocsf-schema/releases)
- [OCSF in AWS Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)

**Uyum / regülasyon**
- [NIST SP 800-53 Rev.5 — AU-2](https://csf.tools/reference/nist-sp-800-53/r5/au/au-2/), [AU-3](https://csf.tools/reference/nist-sp-800-53/r5/au/au-3/), [AU-9](https://csf.tools/reference/nist-sp-800-53/r5/au/au-9/), [AU-10](https://csf.tools/reference/nist-sp-800-53/r5/au/au-10/)
- [PCI DSS Requirement 10](https://pcidssguide.com/pci-dss-requirement-10/), [PCI log retention](https://www.zengrc.com/blog/what-are-the-pci-audit-log-retention-requirements/)
- [CNIL — Recommandation journalisation (Délibération 2021-122)](https://www.cnil.fr/fr/la-cnil-publie-une-recommandation-relative-aux-mesures-de-journalisation)
- [EDPB Guidelines 01/2025 on Pseudonymisation (PDF)](https://www.edpb.europa.eu/system/files/2025-01/edpb_guidelines_202501_pseudonymisation_en.pdf)
- [GDPR Art. 15](https://gdpr-info.eu/art-15-gdpr/), [Art. 20](https://gdpr-info.eu/art-20-gdpr/)
- [WP29 WP251rev.01 — Automated decision-making & Profiling](https://ec.europa.eu/newsroom/article29/items/612053/en)

**Bütünlük / transparency log**
- [Crosby & Wallach, Efficient Data Structures for Tamper-Evident Logging (USENIX Sec 2009, PDF)](https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf)
- [Agent Flight Recorder (arXiv:2609.01931)](https://arxiv.org/html/2609.01931)
- [Trillian Tessera — performance](https://github.com/transparency-dev/tessera/blob/main/docs/performance.md), [README](https://github.com/transparency-dev/tessera/blob/main/README.md)
- [Sigstore Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- [Let's Encrypt — Reflections on a Year of Sunlight](https://letsencrypt.org/2025/06/11/reflections-on-a-year-of-sunlight)
- [Filippo Valsorda — You Should Run a Certificate Transparency Log](https://words.filippo.io/run-sunlight/)
- [AWS kills QLDB (InfoQ)](https://www.infoq.com/news/2024/07/aws-kill-qldb), [Microsoft — Moving from QLDB](https://techcommunity.microsoft.com/blog/azuresqlblog/moving-from-amazon-quantum-ledger-database-qldb/4246237)
- [The Hole in Append-Only (TRUNCATE)](https://heypinchy.com/blog/day-143-the-hole-in-append-only)
- [pgaudit](https://github.com/pgaudit/pgaudit), [PostgreSQL — Table Partitioning](https://www.postgresql.org/docs/current/ddl-partitioning.html)
- [Atomic Crypto-Shred with Immutable Audit-Ledger Preservation](https://www.tdcommons.org/dpubs_series/10873/), [Crypto-Shredding: GDPR & MiFID II](https://veritaschain.org/blog/posts/2026-01-18-crypto-shredding-gdpr-mifid-ii-reconciliation/)

**IdP / ölçek / SIEM**
- [Phase Two — Scaling Keycloak Event Storage](https://phasetwo.io/blog/scaling-keycloak-event-storage/), [User Events in Keycloak](https://phasetwo.io/blog/user-events-in-keycloak/)
- [Keycloak Server Admin Guide](https://www.keycloak.org/docs/latest/server_admin/index.html)
- [Okta Event Types catalog](https://developer.okta.com/docs/reference/api/event-types/), [Okta System Log retention](https://support.okta.com/help/Documentation/Knowledge_Article/Exporting-Okta-Log-Data), [Okta Log Streaming](https://help.okta.com/oie/en-us/content/topics/reports/log-streaming/about-log-streams.htm)
- [Auth0 Log Data Retention](https://auth0.com/docs/deploy-monitor/logs/log-data-retention)
- [Microsoft Entra data retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)
- [Query.ai — Cybersecurity Event Data Normalization Standards](https://www.query.ai/resources/blogs/cybersecurity-event-data-normalization-standards/)
- [DMTF CADF](https://www.dmtf.org/standards/cadf), [OpenStack — Auditing with CADF](https://docs.openstack.org/mitaka/config-reference/identity/auditing.html)
- [ClickHouse — Observability](https://clickhouse.com/docs/en/use-cases/observability/introduction)
- [Airbyte — Audit Logging Compliance](https://airbyte.com/data-engineering-resources/audit-logging-compliance), [Tetrate — MCP Audit Logging](https://tetrate.io/learn/ai/mcp/mcp-audit-logging)

**Rust / OpenTelemetry**
- [opentelemetry-rust](https://github.com/open-telemetry/opentelemetry-rust), [issue #3376](https://github.com/open-telemetry/opentelemetry-rust/issues/3376)
- [OTel Semantic Conventions 1.44.0](https://opentelemetry.io/docs/specs/semconv/), [enduser attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/enduser/), [user attributes](https://opentelemetry.io/docs/specs/semconv/registry/attributes/user/), [Events](https://opentelemetry.io/docs/specs/semconv/general/events/), [semconv issue #1104](https://github.com/open-telemetry/semantic-conventions/issues/1104)
- [OTel Performance Benchmark spec](https://opentelemetry.io/docs/specs/otel/performance-benchmark/)
- [tracing 0.1.44](https://docs.rs/tracing/latest/tracing/), [secrecy 0.10.3](https://docs.rs/secrecy/latest/secrecy/), [RUSTSEC-2024-0342](https://osv.dev/vulnerability/RUSTSEC-2024-0342)
- [metrics-prometheus](https://crates.io/crates/metrics-prometheus), [Rust telemetry workshop — Prometheus](https://rust-exercises.com/telemetry/03_metrics/04_prometheus)
- [High-Cardinality Metrics — The TSDB Killer](https://systeminternals.dev/observability/cardinality/), [Last9 — High cardinality in Prometheus](https://last9.io/blog/how-to-manage-high-cardinality-metrics-in-prometheus/), [Prometheus label best practices](https://oneuptime.com/blog/post/2025-12-05-prometheus-label-best-practices/view)

**Kullanıcıya görünen audit**
- [Google — Devices & recent security activity](https://support.google.com/accounts/answer/3067630)
- [GitHub — Security log events](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events)
