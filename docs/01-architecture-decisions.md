# 1. Mimari kararlar

> `ARGUS.md` §1'den taşındı. Projeye hakim olmak için bölüm bölüm
> incelenip düzeltiliyor. Ana dosya bu belgeye işaret ediyor.


**Girdi:** 15 araştırma dosyası, ~1,9 MB, yaklaşık 600 birincil kaynak.
**Bu dosyanın işi:** Araştırmayı karara çevirmek. Her karar (a) tek cümlede ifade edilir, (b) gerekçesi bir ölçüme veya birincil kaynağa dayanır, (c) geri alınabilir mi geri alınamaz mı işaretlenir.

> **Okuma sırası:** Bu dosya özet ve karardır. Gerekçenin tamamı ilgili araştırma dosyasındadır — her satırda bağlantı var. Çelişen tavsiyeler 02-contradictions-and-resolutions.md (§2)'de çözülmüştür.

---

## 0. Ürünün tek cümlelik tanımı

> **Argus, Keycloak'ın kapsamına sahip, MCP ve ajan kimliğini birinci sınıf vatandaş yapan, sender-constrained token'ı varsayılan kabul eden, çok kiracılığı gün-1'de doğru modelleyen, Rust ile yazılmış genel amaçlı bir Identity Provider'dır.**

**Ne değildir:** sektöre özgü bir ürün, bir uyum (compliance) ürünü, bir "hafif" IdP.

**Hedef karşılaştırma:** Keycloak'ın referans rakamları **2.000 login/sn ve 10.000 token yenileme/sn**. Argus bunu **aynı Argon2 parametreleriyle, daha az donanımla** aşmayı hedefler.

---

## 1. Gün-1 kararları ve statüleri

Bu tablodaki kararlar **gün-1'de verilmek zorunda olanlardır** — sonradan değiştirmenin maliyeti ya imkânsız ya da "dünyayı durduran" bir göçtür.

⚠️ **Statü sütunu (3. inceleme turu).** Önceden bu tablonun başlığı "Geri alınamaz kararlar" idi ve 27 maddenin hepsine aynı kesinlik veriliyordu. Bu yanlıştı: issuer'daki kiracı slug'ı ile minimum PostgreSQL sürümü aynı sınıfta değil, ve hepsine aynı kesinliği vermek yanlış olduğu sonradan görülen bir tercihi değiştirmeyi zorlaştırır. Statüler §10.4'te tanımlıdır:
**KŞS** = kalıcı şema sözleşmesi · **KKS** = kalıcı kimlik sözleşmesi (dış dünyaya yerleşir) · **MT** = kabul edilmiş mimari tercih · **DH** = doğrulanacak hipotez.

| # | Karar | Statü | Sonradan değiştirmenin maliyeti | Kaynak |
|---|---|---|---|---|
| 1 | **`tenant_id` her tabloda VE her birincil anahtarda** | KŞS | Tüm PK'ları düşürüp yeniden kurmak = çevrimdışı migration. SuperTokens: 33 tablo, tüm PK'lar CASCADE | 18-multi-tenancy.md (§18) |
| 2 | **Her yabancı anahtar composite (`tenant_id` dahil)** | KŞS | Tek kolonlu FK'lar çapraz-kiracı referansa izin verir; RLS sonradan okumayı bozar | Logto PR #7596 |
| 3 | **RLS + `FORCE` + non-owner rol, İSTİSNASIZ tüm tablolarda** | KŞS | Sonradan eklemek "ya hep ya hiç"tir; atlanan tek tablo = sessiz sızıntı | Logto #7685 |
| 4 | **Kiracı başına imzalama anahtarı** (ES256 varsayılan) | KKS | Paylaşımlıdan kiracı-başınaya geçiş = tüm RP'lerin JWKS cache invalidasyonu + koordineli kesinti | Storm-0558, CVE-2026-23552 |
| 5 | **`client_id` global benzersiz** (Keycloak'ın aksine) | KKS | Sonradan globalleştirmek = müşteri `client_id`'lerini yeniden adlandırmak = her RP config'i kırılır | RFC 6749 §2.2 |
| 6 | **Kullanıcı benzersizliği kiracı-yerel** (`UNIQUE(tenant_id, …)`), asla global | KŞS | Global→kiracı-yerel geçiş veri göçü + güvenlik incelemesi; tersi imkânsız | Zitadel: *"not possible to move users between organizations"* |
| 7 | **Değişmez kiracı slug'ı** | KKS | Slug issuer URL'indedir → değişirse her RP'nin discovery'si kırılır | Keycloak: *"alias cannot be changed afterwards"* |
| 8 | **Issuer stratejisi: subdomain birincil** + RFC 9207 `iss` gün-1'de | KKS | Issuer değişimi = tüm RP yeniden yapılandırması | RFC 8414 / OIDC Discovery çelişkisi |
| 9 | **`placement_id` silo-kaçış kolonu gün-1'de** (kullanılmasa bile) | KŞS | Yoksa bir kiracıyı ayrı kümeye taşımak mimari yeniden yazımdır | AWS silo/pool/bridge |
| 10 | **Denetim logu kiracı + zaman partition'lı** | KŞS | Milyarlarca satırlı tabloyu sonradan partition'lamak pratikte imkânsızdır | GDPR Md. 17 |
| 11 | **İsim değil, opak-ID/tam-yol tabanlı yetkilendirme** | MT | Token'da isim taşıyan her şey yeniden yazılır | CVE-2026-19608 |
| 12 | **WebAuthn RP ID = apex alan adı** (login alt alan adı DEĞİL, satıcı alan adı KESİNLİKLE değil). **Çok kiracılıkta: her kiracı KENDİ RP ID'sini alır.** ⚠️ *Bu bir **ürün tercihidir**, standart zorunluluğu değil — spec, origin'in effective domain'ini de geçerli RP ID sayar (§23 §5.3).* | KKS | **Geri alınamayan tek WebAuthn kararı.** RP ID değişirse Okta'nın ifadesiyle *"the browser doesn't present them at sign-in"* — kayıtlar silinmez ama kullanılamaz. ROR (`/.well-known/webauthn`) pratikte **5 label** ile sınırlı → paylaşımlı RP ID çok kiracılıkta ölçeklenmiyor | 22-account-lifecycle.md (§22) §39.1, 23-login-flows.md (§23) §5.3 |
| 13 | **WebAuthn `user.id` = 64 rastgele bayt**, asla e-posta veya hash'i | KKS | **İki ayrı derece — önceden tek `MUST NOT` etiketiyle birleştirilmişti:** user handle'a PII (e-posta, kullanıcı adı, salt'sız hash'i) koymak **`MUST NOT`**; **64 bayt ise `RECOMMENDED`** — spec 1–64 bayt aralığına izin verir, 64 bayt **Argus'un tercihidir**. Değiştirmek tüm credential'ları geçersiz kılar | WebAuthn L3 §5.4.3 (1–64 bayt), §14.6.1 (PII yasağı + 64 bayt önerisi) |
| 14 | **Kullanıcı ID'si asla yeniden kullanılmaz; e-posta varsayılan olarak asla** | KŞS | Tombstone tekillik kısıtını sonradan eklemek çakışan kayıtları çözemez | RFC 9967, Gmail, GitHub |
| 15 | **`argus-core` I/O yapmaz** — `async fn`, `tokio::`, `sqlx::`, `reqwest::` yasak, CI'da zorlanır | MT | Formel doğrulamanın tek girebileceği yer burasıdır; sonradan I/O'yu sökemezsin | 02-contradictions-and-resolutions.md (§2) §5 |
| 16 | **Kimlik doğrulama akışı bir "flow" konfigürasyonu değil, tipli bir durum makinesi** | MT | Keycloak #40744: akıştan adım silmek auth bypass üretiyor. Genel amaçlı flow motoru bunu yapısal olarak engelleyemez | 22-account-lifecycle.md (§22) §10.3 |
| 17 | **Her PII alanı kullanıcı başına DEK ile şifreli** (envelope encryption) | KŞS | Crypto-shredding'i sonradan eklemek tüm veriyi yeniden yazmaktır | ICO "put beyond use", EDPB CEF 2026 |
| 18 | **Üç ayrı epoch:** `session_epoch` (kullanıcı) · `authz_epoch` (kiracı) · `key_epoch` (kiracı) | MT ⚠️ *doldurma sözleşmesi §10.3 A6* | Tek sayaca sıkıştırılırsa her izin değişimi tüm oturumları düşürür | 02-contradictions-and-resolutions.md (§2) §4 |
| 19 | **Kiracıya server-side template execution VERİLMEZ** — Keycloak'ın FreeMarker modeli kopyalanmaz | MT | Keycloak kendi dokümanında: *"a malicious template can run code as the Keycloak process."* Çok kiracılı bir üründe bu, **kiracının RCE alması** demektir. Sonradan script-siz templating'e geçmek her kiracı temasını yeniden yazdırmaktır | 23-login-flows.md (§23) §5.2 |
| 20 | **Argus'un kendi admin konsolu ve hosted login'i OAuth kullanmaz — doğrudan session cookie** | MT | RFC 10017 §7.1: *"Simple applications are made needlessly complex by using OAuth to replace the concept of session management."* Sonradan sökmek tüm UI auth katmanını yeniden yazmaktır | 23-login-flows.md (§23) §4.2 |
| 21 | **Platform-admin API'si ile kiracı-admin API'si AYRI yüzeyler** — ayrı audience, ayrı scope namespace'i, ayrı rate limit bütçesi | KKS | Auth0 bunu **21 Nisan 2026'da yapmak zorunda kaldı**: Management API *"is not designed for frequent, granular calls… can quickly become a bottleneck"* ve müşteriler *"hit a wall with rate limits."* Sonradan ikinci bir API yüzeyi eklemek her entegrasyonu kırar | 24-admin-api.md (§24) §5.1 |
| 22 | **Yetkilendirme filtresi veri erişim katmanında, handler'da değil** — tipte kodlanır: filtrelenmemiş koleksiyon serileştirilemez | MT | CVE-2026-17059 tam olarak bunun yokluğu: `/users` doğru filtreliyordu ama `role-members` aynı token'a tam PII veriyordu. Handler-başına yetkilendirme, N endpoint × M kaynak kombinasyonunda **kaçınılmaz olarak** atlanır | 24-admin-api.md (§24) §3.2 |
| 23 | **Denetim olayı, iş değişikliğiyle AYNI transaction'da minimal bir audit outbox satırı olarak kalıcılaşır**; Merkle birleştirme, imzalama ve dışa yayın arka planda yürür | MT ✅ *kabul edilmiş yön §10.3 A1* | Keycloak'ın 1 numaralı arızası: *"Event writes ride the request transaction"* — login isteği DB insert'ini bekliyor; ayrıştırma doğru. ⚠️ **Ama çözüm bellek kuyruğu değil (düzeltme, 2. inceleme turu):** bounded in-memory kuyruk, iş değişikliği commit olduktan sonra süreç ölürse kaydı kaybeder — rol değişikliği kalıcı, denetim kaydı yok. Bu satır, §25 §7 K4'ün (Tessera: *durable* sequencing + arka planda integration) doğru okunuşudur; K8'in bellek kuyruğu K4 ile çelişiyordu | 25-observability.md (§25) §5.4, §7 K4/K8 |
| 24 | **`redirect_uri` eşleştirmesi YALNIZCA exact string** — regex ve wildcard hiç implemente edilmez, "opt-in tehlikeli özellik" olarak bile | MT | authentik **CVE-2024-52289**: escape edilmemiş regex noktası yüzünden `app.example.com` konfigürasyonu `app0example.com` ile eşleşti → *"the victim… are directly redirected to the attacker without further user interaction."* Düzeltme "strict string matching as the default" oldu. RFC 9700 zaten exact match zorunlu kılıyor. **Tek istisna — loopback:** RFC 8252 §7.3 gereği native uygulamaların `127.0.0.1`/`localhost` redirect'lerinde **port bileşeni yok sayılarak** eşleştirilir (§14 §9.4'te ayrıntılı). Bu bir wildcard değil, standardın kendi kuralıdır; karar satırında taşınması gerekiyordu | 26-deployment-operations.md (§26) §3.3, 14-mcp-authorization.md (§14) §9.4 |
| 25 | **İmzalama anahtarları veritabanının DIŞINDA**, pluggable backend (dosya/KMS/PKCS#11), DB yedeğinden bağımsız yedekleme | MT | **Anahtar kaybı DB kaybından yıkıcıdır**: tüm token'lar, refresh token'lar, oturumlar ölür ve hiçbir RP eski JWT'leri doğrulayamaz. Keycloak `rsa-generated` anahtarları DB'ye koyuyor ve **yedekleme prosedürü dokümante etmiyor**; Zitadel'in masterkey'i `docker compose up`'ta sessizce üretiliyor ve *"cannot be changed"* | 26-deployment-operations.md (§26) §5.2 |
| 26 | **Şema göçü ayrı bir job; uygulama başlangıçta yalnızca `validate` yapar ve uyumsuzsa ölür** | MT | Keycloak #43252: *"Incompatible migrations and index creation locks can prevent old instances from joining clusters during rolling updates."* Uygulama başlangıcına DDL bırakmak N-1 uyumluluğunu yapısal olarak imkânsız kılar | 26-deployment-operations.md (§26) §4.4 |
| 27 | **Minimum PostgreSQL 18** | **DH** ⚠️ *gerekçesi bir kez düzeltildi* | ⚠️ **Gerekçe düzeltildi (2. inceleme turu).** Eski gerekçe ("expand-contract'ı NOT NULL için mümkün kılan tek sürüm") **olgu olarak yanlıştı:** PG12'den beri `ADD CONSTRAINT ... CHECK (col IS NOT NULL) NOT VALID` → `VALIDATE CONSTRAINT` (SHARE UPDATE EXCLUSIVE) → `SET NOT NULL` dizisi tam tablo taraması olmadan çalışır. **Geçerli gerekçeler:** (a) yerleşik `uuidv7()` — [ÖLÇÜM] insert 1,67x hızlı, indeks %26 küçük (§6 §4.2); (b) fast-path kilit düzeltmesi (commit `c4d5cb71d`) çok-partition'lı iş yükündeki kilit uçurumunu kaldırıyor (§18 §2.2); (c) PG18'in `SET NOT NULL NOT VALID`'i aynı deseni sadeleştirir. Karar ayakta, gerekçe değişti | 26-deployment-operations.md (§26) §4.1, §6 §4.2, §18 §2.2 |

> **Bu yirmi yedi maddenin hepsi şemayı, crate sınırlarını, UI mimarisini, API yüzeyini veya dağıtım modelini etkiliyor. Hiçbiri "sonra bakarız" değil.**

### 1.1 Sonradan verilen kararlar

Gün-1 tablosundan sonra verilen mimari kararlar burada, CLAUDE.md §8'in
zorunlu alanlarıyla birlikte.

---

**K28 — Kiracı giriş sayfası: script çalıştırmayan şablon (Liquid), giriş kutusu derlenmiş**

| Alan | İçerik |
|---|---|
| **Kimlik** | K28 |
| **Statü** | **MT** — kabul edilmiş mimari tercih |
| **Karar** | Kiracı, giriş sayfasının **kabuğunu** Liquid ile yazabilir. **Giriş kutusu derlenmiş kodda kalır** ve kiracı onu yalnızca `argus_login_box` yer tutucusuyla YERLEŞTİRİR. Sunucuda kod çalıştıran şablon (FreeMarker sınıfı) hiç implemente edilmez. |
| **Gerekçe** | §23 §8 #18'in orijinal gerekçesi "kiracı düşman olabilir" idi ve Argus'ta kiracılar birinci taraf olduğu için **bu gerekçe geçerli değil**. Karar yine de ayakta, ama iki farklı ve daha dar sebeple: (a) bu oturumda gerçek bir yönetim API'si yazıldı ve **yönetim yüzeyini ele geçiren kişi birinci taraf değildir**; sunucuda çalışan bir şablon motoru tenant-admin yetkisini RCE'ye çevirir. (b) Kazanç sıfıra yakın: §9.5 #1 tek binary tek komut diyor, her değişiklikte zaten dağıtım yapılıyor. **Performans bu kararı belirlemiyor** — ölçüm: aynı istekteki Argon2 bu donanımda ~11 ms, şablon render'ı mikrosaniyeler. |
| **Neden kutu kiracıya açılmıyor** | Alan adları, alan sıralaması, neyin gönderildiği ve identifier adımının sabit biçimli cevabı (§23 §8 #2) güvenlik garantileridir. Auth0 Universal Login de aynı sınırı çiziyor: Liquid **prompt'un etrafını** kontrol eder, prompt'un kendisini değil. |
| **Geçerlilik koşulu** | Liquid'in iki ölçülmüş özelliği: (1) fonksiyon çağırma sözdizimi yok ve şablon kendisine elden verilmeyen hiçbir şeye ulaşamıyor — nesne grafiği, metot, ortam adı yok; (2) verilmemiş bir ada başvurmak boş dizge değil **hata** üretiyor. Bir sürüm yükseltmesi bu ikisini değiştirirse karar yeniden değerlendirilmeli. |
| **Kabul testi** | `crates/argus-http/tests/theme_shell.rs`. İkisi de sabitlenmiş: şablonun verilmeyene ulaşamadığı, ve istek verisinin kabuğa hiç girmediği. Ayrıca: kutuyu yerleştirmeyen kabuk saklanmadan reddediliyor, bozuk kabuk derlenmiş olana düşüyor, `javascript:` bir logo alanından geçemiyor (kontrol söküldüğünde iki test düşüyor), ve CSP hiçbir script kaynağına izin vermiyor. |
| **Hangi karşı örnek bu kararı geçersiz kılar** | Kiracıların giriş **kutusunun içini** — alan sırası, alan ekleme, adımlar arası içerik — dağıtım yapmadan değiştirmesinin ürün gereksinimi hâline gelmesi. Yalnızca kabuk yetmediğinde. Kabuğun yetmediği tek başına yeterli değildir; kabuk zaten Liquid'e açık. |
| **Kalan risk ve kontrolü** | FreeMarker'ın RCE'si yok, ama iki risk kalıyor: **XSS** — kiracı kabuğuna script yazabilir, kontrolü CSP (`default-src 'none'`, hiçbir script kaynağı yok, satır içi stil yok); **kaynak tüketimi** — Liquid döngü kurabilir, kontrolü kabuk boyutu, render süresi ve çıktı boyutu sınırları. |
| **Kaynak satır** | §23 §5.1 (üç ürünün yaklaşımı), §23 §5.2 (özelleştirmenin güvenlik maliyeti), §23 §8 #14/#16/#18/#19, §1 #19, §1 #20, §9.5 #1 |

**K29 — Tema verisi kayıt defterinde tutulur, istek başına veritabanına gidilmez**

| Alan | İçerik |
|---|---|
| **Kimlik** | K29 |
| **Statü** | **MT** |
| **Karar** | Tema `(kiracı, istemci)` ile anahtarlanmış bir veri kaydıdır; istemciye özel yoksa kiracıya, o da yoksa derlenmiş varsayılana düşülür. Veritabanında saklanır ama **başlangıçta kiracı kayıt defterine yüklenir**; render başına yapılan iş bir map aramasıdır, sorgu değil. Değişiklikten sonra yönetim ucu o kiracının girdisini tazeler; süreç yeniden başlatılmaz. |
| **Gerekçe** | Bir kiracının logosu yılda bir değişir, istek başına okunacak bir şey değil. Keycloak'ın modeli de fiilen budur: tema JAR'ı bir dağıtım artefaktıdır ve üretimde şablonlar bellekte cache'lenir. Fark, cache'te ne durduğu: Keycloak yorumlanacak bir şablon ağacı tutar, burada derlenmiş kod ve veri durur. |
| **Granülerlik gerekçesi** | Keycloak realm ve client düzeyinde tema seçimine izin veriyor; aynı granülerlik veri modelinde yalnızca bir anahtar meselesi ve ek maliyeti yok. |
| **Kabul testi** | Tema değişikliğinden sonra tazeleme ucu çağrılınca yeni tema sunuluyor; tazeleme çağrılmadan eski tema sunuluyor. |
| **Hangi karşı örnek bu kararı geçersiz kılar** | Tema sayısının bellekte tutulamayacak kadar büyümesi — kiracı başına birden çok istemci temasının toplam boyutunun süreç bellek bütçesini zorlaması. O noktada doğru cevap veritabanına dönmek değil, sınırlı bir LRU. |
| **Kaynak satır** | §23 §5.1, §18, §9.5 boyutlandırma |

---

## 2. Teknoloji yığını

### 2.1 Dil seçimi — dürüst gerekçe

**Rust seçilmiştir, ama "en performanslı" olduğu için değil.**

Ölçüm: bir login'in CPU'sunun **~%97'si Argon2 + imzalamadır** ve ikisi de dilden bağımsızdır. Argon2 kasıtlı olarak yavaştır ve hızlandırılamaz.

**Doğru üç gerekçe:**
1. **Kripto/TLS katmanı üstünlüğü** — rustls'te post-quantum varsayılan açık; aws-lc-rs FIPS modu + ML-DSA; s2n-bignum'un HOL Light ile makine-kontrollü ispatları.
2. **Güvenlik değişmezlerinin tip sistemine kodlanması** — branded lifetime ile **A kiracısından okunan bir varlığı B kiracısının yazma yoluna sokmanın** derleme hatası olması; bunun yayımlanmış bir emsali yok, Argus ilk olur. ⚠️ **Sınırları (§18 §6.3'teki "Kazanmaz" tablosu buraya taşınmalıydı):** yanlış kiracıyı `begin()`'e vermeyi *engellemez* (istek sınırındaki extractor invariantının işi); ham SQL'de `AND tenant_id = ?` unutmayı *engellemez* (RLS'in işi); `Scoped::get()` ham `&T` döndürdüğü için `T: Clone` olan veri brand'in dışına kopyalanabilir. **Söylenebilecek cümle:** "belirli yanlış kullanımlar derleme aşamasında engellenir." **Söylenemeyecek cümle:** "tenant izolasyonunu bütünüyle derleyici garanti eder."
3. **`webauthn-rs`'in kalitesi** — ekosistemdeki en iyi konumlanmış parça.

**Kazanç nerede:** Argon2'yi hızlandırmakta değil, **hash dışındaki %85'i silmekte.** Aynı Argon2 parametresiyle çekirdek başına 15 yerine **40-60 login/sn** gerçekçidir — 3-4× kazanç, tamamen overhead silme işi.

**Maliyet, açıkça:** ~46-73 geliştirici-ayı (Rust) vs ~31-49 (Go) — **~1,5× çarpan.** Kanidm 224.718 satır, Rauthy 84.242 satır (ölçüldü).

### 2.2 Bağımlılıklar

```toml
[dependencies]
axum        = "0.8"
tokio       = { version = "1.53", features = ["full"] }
rustls      = { version = "0.23", features = ["fips"] }
jsonwebtoken = { version = "11", default-features = false,
                 features = ["use_pem", "aws_lc_rs"] }   # rust_crypto ASLA
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
argon2      = { version = "0.6", features = ["parallel"] }
sqlx        = { version = "0.9", features = ["postgres", "runtime-tokio-rustls"] }
ldap3_proto = "0.8"
cedar-policy = "4"          # politika değerlendirme — Lean 4 ile doğrulanmış
bergshamra  = "0.9"          # XMLDSig/XMLEnc/C14N — saf Rust
generativity = "1"           # branded lifetimes — kiracı izolasyonu
```

**Yasaklar ve gerekçeleri:**

| Yasak | Gerekçe |
|---|---|
| `jsonwebtoken` + `rust_crypto` özelliği | `rsa` crate'i Marvin saldırısına açık — 08-side-channels.md (§8) |
| Dağıtık cache doğruluk kaynağı olarak (Redis/Infinispan) | Endüstri PostgreSQL'e yakınsadı: Keycloak Tem 2026, Zitadel Şub 2026, authentik 2025.8 — 19-high-availability.md (§19) |
| Postgres `LISTEN/NOTIFY` | PgBouncer transaction modunda çalışmıyor; kuyruk dolunca **yazmalar commit'te başarısız** |
| Olay başına hash-chained audit log | Ölçüldü: 8 bağlantı = 1 bağlantı throughput'u — tek doğrusal zincirde ardışık zincir hash'leri arasında seri bağımlılık. ⚠️ Sayı ölçüme özgüdür, evrensel tavan değildir |
| `gamlastan` (SAML domain modeli) | SAML iş mantığı dışarıdan gelmemeli; XSW savunması tam olarak orada yaşar |
| Verus | `serde::Serialize` ve `Mutex` desteklemiyor — gerçek kod tabanına uymuyor |

### 2.3 Crate topolojisi

```
argus-core/      #![forbid(unsafe_code)]  — I/O YOK, async YOK. Durum makineleri,
                                            politika değerlendirme, delegasyon
                                            değişmezleri, epoch mantığı. Kani hedefi.
argus-proto/     #![forbid(unsafe_code)]  — OIDC/OAuth2/SCIM/SAML tipleri
argus-parse/     #![forbid(unsafe_code)]  — TÜM parser'lar. Derinlik sınırları burada.
argus-http/      #![forbid(unsafe_code)]  — axum handler'ları
argus-store/     #![forbid(unsafe_code)]  — sqlx, RLS, SET LOCAL
argus-crypto/    (FFI izinli)             — aws-lc-rs sarmalayıcısı. Tek istisna #1.
argus-sandbox/   #![deny(unsafe_code)]+   — seccomp/landlock/prctl. Tek istisna #2.
argus-saml/                               — AYRI SÜREÇ. RLIMIT_AS/STACK + timeout.
```

**CI gate'leri:** `cargo geiger --forbid-only` · `argus-core`'da `async fn`/`tokio::`/`sqlx::` grep yasağı · `cargo-vet` · `cargo-deny` · `cargo-auditable`.

---

## 3. Protokol kapsamı ve öncelik

### 3.1 Faz 1 — çekirdek (bunlarsız ürün yok)

| Protokol | Neden faz 1 | Tahminî efor |
|---|---|---|
| **OAuth 2.1 AS durum makinesi** | **Tek en büyük risk.** Rust'ta Fosite eşdeğeri yok — iki bağımsız ajan doğruladı | **12-18 geliştirici-ayı** |
| **OIDC Core + Discovery + JWKS** | Her şeyin tabanı | dahil |
| **RFC 8414 + OIDC Discovery — İKİSİ BİRDEN** | MCP `MUST` | küçük |
| **RFC 9728 PRM · RFC 8707 `resource` · RFC 9207 `iss`** | MCP `MUST` üçlüsü | küçük |
| **RFC 9449 DPoP + RFC 8705 mTLS-bound** | 3 Ağu 2026 ölçümü: 15 halka açık issuer'dan **0'ı DPoP ilan ediyor**. Farklılaşma noktası | orta |
| **CIMD** (`client_id_metadata_document_supported: true`) | MCP DCR'ı deprecate etti | orta |
| **RFC 8693 Token Exchange** + `act`/`may_act` | Delegasyonun tabanı | orta |
| **ID-JAG üretimi VE tüketimi** | **Keycloak üretemiyor.** MCP Enterprise-Managed Authorization **Stable** ve doğrudan ID-JAG'ı profilliyor | orta |
| **WebAuthn / passkey** (`webauthn-rs`) | Ekosistemin en iyi parçası | orta |
| **SCIM 2.0 sunucu** | En büyük iş kalemi; PATCH motoru hiçbir crate'te yok | **büyük** |

### 3.2 Faz 2 — kurumsal

**Sıra:** SCIM → SAML → LDAP → OpenID Federation → Kerberos
**Efor:** Faz 1 = 61-68 hafta; hepsi ≈ 95 hafta ≈ **1,8 mühendis-yılı** + **%30-40 sürekli interop bakımı.**

| Protokol | Kritik bulgu |
|---|---|
| **SCIM** | **En büyük iş kalemi.** PATCH motorunu veren crate yok. **Entra ve Okta çelişkili member-list davranışı istiyor** → 17 maddelik istemci-başına tolerans katmanı gerekiyor |
| **SAML** | `bergshamra` saf Rust'ta XMLDSig veriyor ve **xmlsec1'in kendi süitini 1148/1151 geçiyor.** Domain modeli kendimiz yazarız. Ayrı süreç — bellek güvenliği için değil, **kaynak sınırı** için |
| **LDAP** | **Rust'ın en iyi konumlandığı protokol.** `ldap3_proto` tam op seti + paged results/sorting/sync |
| **OpenID Federation** | **Rust'ta tamamen boş — en büyük farklılaşma fırsatı** |
| **Kerberos** | **C FFI'dan kaçış yok.** Microsoft kendi Kerberos SSO'sunu PRT lehine terk etti. **En düşük öncelik** |

> ⚠️ Salesforce/ServiceNow/Workday/AWS/Slack/Zoom/Atlassian'ın SAML gereksinimleri **doğrulanmadı.** Faz 2 planlaması bunları doğrulamadan kesinleşemez.

### 3.3 Faz 3 — ajan kimliği ileri seviye

`delegation_chain` (imzalı, per-hop) · `sub_profile`/`agent_instance_id` · attestation-based client auth · transaction tokens · mid-execution HITL soyutlaması · AuthZEN PDP · SCIM `/Agents` · **A2A Agent Card imzalama servisi (hiçbir mainstream IdP yapmıyor)** · federated credential vault.

---

## 4. Güvenlik mimarisi

### 4.1 Oturum modeli

**Katmanlı, ağ turu olmadan doğrulanabilir:**
```
JWT imza doğrulama          → public key bellekte
exp/nbf                     → token'ın içinde
session_epoch karşılaştırma → node-yerel cache
────────────────────────────────────────────────
Sonuç: DB tamamen düşse bile kaynak sunucular etkilenmez.
```

**Epoch yayılımı:** transactional outbox + **100-250 ms polling** (Keycloak'ın deseni). `LISTEN/NOTIFY` değil.

**⚠️ AÇIK KARAR — access token ömrü ve iptal sözleşmesi (bkz. §1 §10.1).** Bu satır önceden "uzun ömürlü access token + sinyal güdümlü iptal, kısa TTL değil" diye kesin bir karar bildiriyordu. Ancak §19 §7.2 degraded mode'u anlatırken şunu diyor: *"degraded mode'un gerçek güvenlik sınırı access token ömrüdür… **bu, kısa token ömrünün en güçlü tek gerekçesidir** ve degraded mode tasarımının önkoşuludur."* Yani özetin "en değerli farklılaştırıcı" diye sattığı özellik, mimari bölümünün ifadesiyle özetin reddettiği token politikasını önkoşul kabul ediyor. İkisi aynı anda savunulamaz → karar §10.1'de açık bırakıldı. Uzun ömür lehine kanıt — Microsoft'un kendi bulgusu (birebir): *"Microsoft experimented with the 'blunt object' approach of reduced token lifetimes but found they **degrade user experiences and reliability without eliminating risks**."* Entra CAE 28 saatlik token + ~15 dk yayılım kullanıyor.

**Bearer varsayılan değildir.** DPoP + mTLS-bound + JWT-SVID kabulü birinci sınıftır. WIMSE'nin yönü net: WIT spec'i *"MUST NOT be used as a bearer token"* diyor.

**DBSC:** arayüz hazırlanır, implemente edilmez. Windows'ta GA (28 May 2026) ama Firefox'un **olumsuz standart pozisyonu** var ve Rust crate'i yok.

### 4.2 Yetkilendirme

- **Cedar embed edilir, yeniden yazılmaz** — Lean 4 ile doğrulanmış bir motoru atmak kazanılmış tek ücretsiz güvenceyi atmaktır.
- **ReBAC graf katmanı kendimiz yazarız** (Zanzibar tarzı), Cedar'ın üstünde.
- **`authz_epoch` karar cache anahtarının parçasıdır** — cache temizlenmez, adreslenemez olur.
- **İzin *kaldırma* read replica'dan okunmaz.** Replikasyon gecikmesi = new-enemy penceresi.
- ⚠️ Literatürdeki "2,6 µs/karar" rakamı **160 satırlık Python'da HMAC caveat doğrulamasıdır**, ReBAC graf çözümlemesi değil. Hedef olarak kullanılamaz.

### 4.3 Çok kiracılık

**Satır bazlı + RLS FORCE + `SET LOCAL` + branded lifetimes.**

- Schema-per-tenant **reddedildi**: 1.200 şemada 383 ms katalog taraması, 2 saatlik migration.
- `SET` değil **`SET LOCAL`** — `SET` transaction pooling'de sızar.
- Düz kiracı listesi; hiyerarşi kiracı **içinde** gruplarla. **Zitadel, Auth0, Okta, Entra, WorkOS — hepsi iç içe kiracıyı reddetti.** Frontegg yaptı ve miras JWT'ye sığmıyor.

### 4.4 Kimlik doğrulama ve kurtarma

- **Kurtarma güvencesi kısıtı** — "kurtarma korunan şeyden zayıf olamaz" ilkesinin şema kısıtına çevrilmiş hâli; **duruma koşullu** yazılır (koşulsuz hâli NULL'da sessizce geçerdi — §22 §10.2). Tek başına yetmez: yetki açan geçiş, kanıt doğrulama **ve kanıt tüketimi** ile aynı atomik işlemde olmalı.
- **`independence_group`** — aynı sync fabric'teki iki passkey **tek authenticator** sayılır.
- Hesabın efektif güvenliği = **`min(tüm kurtarma yollarının AAL'i)`**, admin konsolunda gösterilir.
- **Enumeration savunması:** dummy-Argon2 **değil** — Rauthy'nin çalışan-ortalama padding'i + **sabit yanıt süresi tabanı**. Gerekçe: dummy hash 100 eşzamanlı istekte **6,4 GB** tahsis ettirir ve NIST'in hesap-kapsamlı throttling'i bunu yapısal olarak yakalamaz.
- **Kayıt:** hesap, bant dışı onay kodu dönmeden **yaratılmaz** (WebAuthn §14.6.2). Tek kontrol, dört gereksinim.

### 4.5 Kripto

- **aws-lc-rs birincil** — FIPS modu, ML-DSA, s2n-bignum ispatları.
- **JWS `alg` beyaz listesinde `EdDSA` KABUL EDİLMEZ** — yalnızca `Ed25519`. ⚠️ *Bu bir **Argus uyumluluk politikasıdır**, standart zorunluluğu değil (düzeltme, 2. inceleme turu):* RFC 9864 `EdDSA`'yı **deprecate** eder, **yasaklamaz** — deprecated ≠ prohibited. **Bedeli açıkça:** yaygın JOSE kütüphanelerinin çoğu hâlâ `EdDSA` üretir, dolayısıyla bu politika `private_key_jwt` client assertion'larını, DPoP proof'larını ve request object'leri kırabilir. Güvenlik gerekçesi de zayıf: doğrulamada anahtarın `crv`'si zaten bilinir, `alg` anahtarın eğrisine bağlanırsa belirsizlik kalmaz. `ES256` doğrudur ve deprecate edilmemiştir.
- **WebAuthn `pubKeyCredParams`'a COSE tarafında `ESP256` + `Ed25519` eklenir.**
- Veri modelinde **`algorithm` alanı + rotasyon yolu gün-1'de** — ML-DSA geldiğinde şema değiştirmek istemezsin.
- **Argon2: `m=7168, t=5, p=1`.** Ölçüldü: `m=19456, t=2`'den **%16 ucuz** ve daha iyi ölçekleniyor (4 iş parçacığında %87 vs %69 verim). Keycloak zaten bunu kullanıyor ve haklı.
- **Argon2 `spawn_blocking` + çekirdek sayısı civarında semafor.** Bu ayar bedavaya hem daha yüksek throughput hem **25× daha iyi p99** veriyor. Kuyruk üst sınırı + timeout → aşınca **503 (yük atma)**.

### 4.6 Denetim logu

**Düz append-only + ~1 saniyede bir Merkle checkpoint.** Olay başına zincir, aynı koşullarda **3,8× yavaş** ve 8 bağlantı ile 1 bağlantı aynı throughput'u veriyor — tek doğrusal zincirde seri bağımlılık var.

> ⚠️ **[YENİDEN ÜRETİM BEKLİYOR]** — bu bölümün dayandığı ölçüm: 12 sn pgbench, Apple M4 / Docker PostgreSQL 18.6, 8 bağlantı. **Mutlak tps değerleri ürün iddiası değildir** ve kapasite, maliyet veya rakip karşılaştırması için kullanılmamalıdır (§6 §4.4). Taşınabilir olan karşılaştırmalı orandır, o da aynı etiketle.
**Bütünlük hash'i şifreli metin üzerinden hesaplanır** — böylece crypto-shred sonrası zincir doğrulanabilir kalır. Bütünlük ve gizlilik ayrışır.

---

## 5. Formel doğrulama kapsamı — ve ne İDDİA EDİLMEZ

**Kani'nin hedefi dört şeydir:** OAuth durum makinesi geçişleri · delegasyon zinciri değişmezleri · epoch karşılaştırma mantığı · parser derinlik invariant'ları.

**Async katmanda formel iddia yoktur.** Orada: `cargo-fuzz`, **Shuttle** (deterministik concurrency), `proptest`, interop conformance süitleri.

> **Söylenebilecek cümle:** *"Argus'un yetkilendirme çekirdeği ve protokol durum makinesi sınırlı model kontrolünden geçirilmiştir; kripto katmanı makine-kontrollü ispatları olan implementasyonlar kullanır; HTTP ve depolama katmanları fuzz ve deterministik concurrency testine tabidir."*
> **Söylenemeyecek cümle:** "Argus formel olarak doğrulanmıştır."

---

## 6. Acil ve tarihli maddeler

| Tarih | Ne | Etki |
|---|---|---|
| **11 Aralık 2027** | **EU Cyber Resilience Act — açık kaynak steward raporlaması** | ENISA'nın ayrımı: *"Open-source software stewards join the reporting obligations on **11 December 2027**."* (11 Eylül 2026 **manufacturer**'lar için Madde 14'ün yürürlük tarihidir.) Yapısal neden: steward'ları Madde 14'e bağlayan hüküm **Madde 24(3)** ve Madde 24 ancak 11 Ara 2027'de uygulanmaya başlıyor. Ayrıca **arkasında tüzel kişi yoksa steward yükümlülüğü hiç doğmaz** ve monetize edilmeyen FOSS zaten kapsam dışı |
| **Şimdi** | **Android attestation kök rotasyonu** | Android key attestation doğrulaması yapan kod **şu anda kırılıyor olabilir** — 21-session-security.md (§21) §E.1 |
| **Şimdi** | **Apple `private.icloud.com`** | Haziran 2026 öncesi kurulmuş e-posta allowlist'i **yeni Sign in with Apple kullanıcılarını sessizce reddediyor** |
| **Aralık 2026** | OAuth 2.1 IESG'ye | MCP hâlâ `draft-13`'e referans veriyor; güncel **-16** |
| **2 Aralık 2027** | EU AI Act yüksek risk (ertelendi, Reg. EU 2026/1744) | Dolaylı |

---

## 7. Farklılaşma — Argus'un neyi ilk yapacağı

Bu liste, araştırmanın en değerli çıktısıdır: **hiçbir mevcut ürünün yapmadığı, ama yapılabilir olan şeyler.**

| # | Farklılaşma | Kimse yapmıyor çünkü |
|---|---|---|
| 1 | **ID-JAG üretimi** | Keycloak sadece tüketiyor, o da preview. MCP EMA **Stable** ve tam olarak bu |
| 2 | **DPoP + mTLS-bound + JWT-SVID birinci sınıf** | 15 halka açık issuer'dan **0'ı** DPoP ilan ediyor |
| 3 | **OpenID Federation** | Rust'ta tamamen boş |
| 4 | **A2A Agent Card imzalama servisi** (RFC 8785 JCS + JWS) | Hiçbir mainstream IdP yapmıyor; A2A↔SPIFFE boşluğunu doldurur |
| 5 | **Branded lifetime ile derleme-zamanı kiracı izolasyonu** | Mekanizma olgun (3,99M indirme) ama çok kiracılığa uygulanmış yayımlanmış örnek yok |
| 6 | **`achieved_aal >= required_aal` şema kısıtı** | Hiçbir IdP kurtarma yolunun AAL'ini modellemiyor, dolayısıyla karşılaştıramıyor |
| 7 | **`independence_group`** — sync fabric farkındalığı | NIST "bind multiple authenticators" diyor, kimse bağımsızlığı ölçmüyor |
| 8 | **Delege oturumda ayrıcalık kesişimi + 12 invariant** | En yakın olanlar WorkOS (4/12) ve ServiceNow (2/12) |
| 9 | **Hash + TOTP sırlarının self-servis dışa aktarımı** | Yalnızca Keycloak TOTP'yi veriyor; kimse ikisini birden self-servis vermiyor. **Dürüstlük iddiası budur** |
| 10 | **Ön-hash ve pepper eklenebilir içe aktarım** | `bcrypt(sha256(pw))` ve peppered hash'ler başka türlü göç edemiyor |
| 11 | **`is_breakglass` birinci sınıf, izinli, alarmlı alan** | Yalnızca Stytch'te var, o da B2B'ye özgü |
| 12 | **Son kimlik doğrulama yöntemi koruması şemada** | Dört üründe de uygulama katmanı sorumluluğu |
| 13 | **Kurtarma/onboarding yeniden tetikleme oranı bir güvenlik metriği** | Unit 42'nin doğrudan tavsiyesi; hiçbir üründe yok |
| 14 | **Tamper-evident denetim logu** (Merkle checkpoint + imza + dış tanığa yayın) | Keycloak: *"Anyone with database access can modify or delete rows, which is not acceptable for compliance evidence."* Okta/Auth0/Entra **sıfır** bütünlük garantisi sunuyor |
| 15 | **`Idempotency-Key` tüm mutating endpoint'lerde** | Okta, Auth0, Entra'nın **hiçbiri** yapmıyor. WorkOS tek endpoint'te yapıyor, diğerlerinde **header'ı sessizce yutup dedup yapmıyor** — en kötü seçenek |
| 16 | **Uzun sıcak denetim penceresi** | Hiçbir büyük IdP PCI'ın 12 ayını kendi içinde karşılamıyor: Okta 90 gün, Entra P1/P2 **30 gün**, Auth0 Starter **1 gün** |
| 17 | **Denetim logu request path'inde değil** | Keycloak'ta login isteği event insert'ini bekliyor |

---

## 8. Bilinen boşluklar — dürüst liste

**Bu doküman şunları çözmüyor:**

1. **Salesforce/ServiceNow/Workday/AWS/Slack/Zoom/Atlassian SAML gereksinimleri doğrulanmadı** — Faz 2 planı bunlarsız kesinleşemez.
2. **x86-64'te Argon2:** `argon2` crate'i ile `libargon2` (AVX2/AVX-512, `-march=native`) farkı ölçülmedi. Fark %20'yi geçerse FFI'ye geçmeye değer. **Argus'un ilk performans işlerinden biri bu olmalı.**
3. **34 maddelik ölçüm boşluğu listesi** — allocator/PGO/io_uring, Postgres bağlantı eğrisi, PgBouncer prepared statement, ML-DSA hızları.
4. **`bergshamra` tek geliştiricili, 0.9.0.** Sürüm/doküman tutarsızlığı var. Test süitinin kopyası bizim CI'ımızda koşmalı.
5. **IdP tarafı SAML doğruluğunu ölçecek olgun bir kamu süiti YOK.** `italia/spid-saml-check` SP'leri test eder; IdP karşılığı (`AgID/spid-saml-check-idp`) 4 star / 51 commit / Docker'sız. Kapanmamış boşluk.
6. **Altı boyutun hepsi tamamlandı.** Kalan boşluklar bu listenin 1-5 maddeleridir.

---

## 9. Faz planı

Çıkış kriterleri artık **koşulabilir süitlere** bağlı — "bitti" bir görüş değil, bir exit code.

| Faz | Kapsam | Tahminî süre | **Çıkış kriteri (ölçülebilir)** |
|---|---|---|---|
| **0 — Temel** | Şema (27 gün-1 kararı), crate topolojisi, CI gate'leri, `argus-core` iskeleti, `nextest` + partitioning, `insta` snapshot altyapısı | 4-6 hafta | RLS testleri geçiyor · `cargo geiger --forbid-only` yeşil · `argus-core`'da async/IO grep'i temiz |
| **1 — OAuth/OIDC çekirdeği** | AS durum makinesi, Discovery, JWKS, PKCE, token endpoint, DPoP | **12-18 ay-adam** | **OIDF conformance suite** (self-hosted Docker) `oidcc-basic/config/dynamic-certification-test-plan` → `run-test-plan.py` exit 0 · **OAuch 195 testi** baseline'lı geçiyor · `oidcc-server-rotate-keys` modülü yük altında 0 adet 401 |
| **2 — MCP + ajan** | PRM, `resource`, `iss`, CIMD, Token Exchange, **ID-JAG üretimi**, CIBA | 3-4 ay | **MCP conformance suite** `authorization-server` senaryoları (per-check baseline) geçiyor · Claude Code ile uçtan uca çalışıyor |
| **3 — Kimlik doğrulama** | WebAuthn, Argon2, kurtarma durum makinesi, kayıt akışı, enumeration savunması | 3-4 ay | CDP Virtual Authenticator ile RP akışı yeşil · `achieved_aal >= required_aal` şemada zorlanıyor · timeless-timing testleri geçiyor · `criterion` Argon2 regresyon eşiği |
| **4 — Kurumsal** | SCIM → SAML → LDAP | 12-15 ay | **`scim2-tester`** RFC 7643/7644 geçiyor · Entra SCIM Validator (discover-schema) + Okta Runscope 13-adım yeşil · **"The Fragile Lock" 3 saldırı sınıfı + XSW1-8 regresyon corpus'u** geçiyor · LDAP: SSSD/JNDI/`ldap3` interop |
| **5 — Farklılaşma** | OpenID Federation, delegation chain, Agent Card imzalama, federated vault | 6-9 ay | FAPI 2.0 Security Profile Final planı · OIDF federation planları (⚠️ OIDF: *"early stage"*) |

**Toplam kaba tahmin: faz tablosunun toplamı ~37–51 geliştirici-ayı** (§2 §1'deki bağımsız tahmin: **46–73 geliştirici-ayı**) **+ %30-40 sürekli interop bakımı.**

> ⚠️ **Düzeltme (2. inceleme turu).** Burada önceden "~1,8 mühendis-yılı çekirdek" (≈21,6 ay) yazıyordu. O rakam §3.2'de **yalnızca kurumsal protokol paketi** için hesaplanmıştı (95 hafta / 1 mühendis) ve sehven projenin tamamına genellenmişti; üç ayrı toplam (21,6 / 37–51 / 46–73) birbirini tutmuyordu. **Birim uyarısı:** yukarıdaki tabloda Faz 1 *geliştirici-ayı*, diğer fazlar *takvim ayı* cinsinden yazılmıştı; toplam geliştirici-ayına çevrildi. **Ad çakışması uyarısı:** "Faz 1/Faz 2" §16 ve §22'de **protokol içi zorunlu/opsiyonel katman** anlamında kullanılıyor, buradaki global faz numaralarıyla aynı şey değil — SCIM'in iki yerde birden görünmesinin sebebi budur.

### 9.1 CI zaman bütçesi

| Aşama | Hedef | İçerik |
|---|---|---|
| Pre-commit | < 2 dk | fmt, clippy, unit, `insta` |
| **PR (blocking)** | **< 15 dk** | `nextest` 4-8 shard · testcontainers · proptest · Shuttle (kısa) · kaydedilmiş Okta/Entra trafiği replay · SAML/JWT saldırı corpus'u |
| Merge/main | ~45 dk | + OIDF conformance · MCP conformance · `scim2-tester` · OAuch |
| Nightly | 2-4 saat | + FAPI 2.0 · madsim DST (yüksek seed) · fuzzing · Keycloak differential **raporu** · gerçek sandbox koşumu |
| Haftalık | uzun | Yük (k6 `constant-arrival-rate`) · kaos (Chaos Mesh split-brain matrisi) · uzun fuzz kampanyaları |

**Conformance'ı PR'dan uzak tutmanın anahtarı expected-failures baseline'ıdır** — hem OIDF `run-test-plan.py` hem MCP conformance destekliyor: bilinen eksikler CI'yı kırmaz ama regresyon **ve bayat baseline** yakalanır.

### 9.2 Test stratejisinden çıkan üç zorlayıcı bulgu

**1. Read replica'dan yetkilendirme kararı vermek artık ölçülmüş bir risk.**
Jepsen'in **Amazon RDS for PostgreSQL 17.4** analizi (29 Nisan 2025): **fault injection olmadan**, ~150 write/sn + 1600 read/sn gibi mütevazı yükte **Snapshot Isolation ihlalleri** (G-nonadjacent, Long Fork) *"every few minutes"* gerçekleşiyor. RDS muhtemelen standart SI yerine **Parallel Snapshot Isolation** sağlıyor ve Jepsen'in ifadesiyle *"this behavior should not occur in standard PostgreSQL."*
→ 02-contradictions-and-resolutions.md §4 (§2)'teki "izin *kaldırma* ve `session_epoch` replica'dan okunmaz" kuralı **teorik bir ihtiyat değil, ölçülmüş bir gereklilik.**

**2. HA konfigürasyonunun iki parametresi veri kaybının %80'ini belirliyor.**
Coroot'un CloudNativePG 1.30.0 + PostgreSQL 18.4 üzerinde Chaos Mesh ile ürettiği split-brain (29 Tem 2026): primary izole edildi, isolation check ~34. saniyede doğru tetiklendi — **ama primary 177 saniye daha yazmaya devam etti** çünkü `smartShutdownTimeout` varsayılanı 180. Sonuç **~99 saniyelik çift-primary penceresi**: ACK'lenmiş 1.472 yazımdan **562'si başka client'lara reassign edildi, 291'i tamamen kayboldu** — sadece 619'u sağlam kaldı. **Cluster kendini mükemmel sağlıklı raporladı.**
**Düzeltme:** `smartShutdownTimeout: 0` **+** `failoverDelay: 30` birlikte → overlap tamamen kayboldu, bozulma **%80** azaldı.
→ Bir IdP için bu, "iptal edilmiş token geri geldi" veya "kullanıcı yanlış kiracıya atandı" demektir. **Bu iki parametre için açık bir kaos testi zorunlu.**

**3. SAML'da üç yeni saldırı sınıfı var ve biri tamamen yeni.**
PortSwigger "The Fragile Lock" (10 Ara 2025, güncelleme 21 Oca 2026): **Attribute Pollution** (parser'lar arası namespace tutarsızlığı) · **Namespace Confusion** (imza elementini bazı parser'lara görünmez yapmak) · **Void Canonicalization** — *yeni sınıf*: canonicalization çözülemeyen relative URI ile karşılaşınca güvenli şekilde fail etmek yerine **boş string** döndürüyor ve boş içeriğin geçerli hash'i üretiliyor.
Etkilenenler: Ruby-SAML, PHP-SAML, xmlseclibs, libxml2 tabanlı implementasyonlar. **Etkilenmeyenler: XMLSec Library, Shibboleth xmlsectool.**
→ **Argus'un canonicalization'ı çözülemeyen URI'de hard fail etmeli** ve bu üç sınıf, XSW1-8 ile birlikte **PR'da koşan regresyon corpus'unun çekirdeği** olmalı.

### 9.3 Denetim mimarisi — ölçüm bağımsız olarak doğrulandı

Daha önce kendi ölçümümüzle verdiğimiz "olay başına hash zinciri değil, düz append-only + ~1 sn Merkle checkpoint" kararı **iki bağımsız kaynakla doğrulandı** ve bir noktada **güçlendirildi.**

**Crosby & Wallach, USENIX Security 2009** — imzalama insert maliyetinin **%83,3'ü**; her commitment imzalanınca tavan **1.750 olay/s**, 16 commitment'ta 1 imza ile **~17.000 olay/s (10×)**. Kendi ifadeleri: *"signatures account for over 80% of the runtime cost of an insert."*

**Agent Flight Recorder (arXiv:2609.01931, Eylül 2026)** — hash chain medyan gecikmeyi **6 µs → 48 µs (8×)** çıkarıyor; Merkle batching üstüne **yalnızca +0,6 µs** ekliyor (48,2 → 48,8 µs), sadece epoch sınırında P99 ~4,1 ms tepe.

> **Ve bilmediğimiz bir şey: hash zinciri iki kere kaybediyor.**
> Insert maliyeti bir yana, **doğrulama maliyeti** asıl felaket. Crosby & Wallach: 80 milyon olaylı bir logda rastgele bir olayın kanıtı **hash chain'de 800 MB, history tree'de 3 KB.** Proof boyutu O(n−k) vs **O(log²n)**.
> → Argus'un `GET /audit/{id}/proof` API'si **ancak logaritmik yapıyla kullanılabilir.** Bu, kararı sadece performans değil, **ürün yeteneği** meselesi yapıyor.

**Üç somut ek karar:**

1. **OCSF 1.9.0'ın `record_integrity` profili tam olarak bu modelin wire formatı.** `attestation` nesnesi `chain_uid` (*"Identifier of the append-only chain, such as a forensic or audit log"*), `fingerprint` (*"fingerprint of this event's canonical serialization"*), `prev_event` ve `signatures` taşıyor; çoklu attestation destekleniyor. **Checkpoint'i ayrı bir attestation olarak yayınlayabiliriz** — her olaya `prev_event` gömmek zorunda değiliz. Bu, denetim çıktısını doğrudan SIEM'lerin anlayacağı hâle getirir.
2. **Postgres append-only'de `BEFORE TRUNCATE` trigger'ı zorunlu.** Row-level trigger'lar TRUNCATE'te **hiç ateşlenmez** — `REVOKE` + row trigger ile korunan bir tablo tek komutla boşaltılabilir. Bu, "append-only" iddiasındaki en yaygın sessiz delik.
3. **Checkpoint dışarı yayınlanmazsa bütünlük iddiası boştur.** Superuser her koruma katmanını aşar. Hedefler: müşteri webhook'u + S3 Object Lock + opsiyonel üçüncü taraf tanık. **Blockchain gerekmiyor** — ölçülen maliyet L2'de $2,30/100K olay. ⚠️ *Buradaki günlük maliyet tahmini önceden 22.440 tps'yi Argus'un sürekli hacmi sayıyordu; o sayı 12 sn'lik bir çıplak-insert ölçümüdür (§6 §4.4) ve 7/24 tepe yük varsayımıyla çarpılamaz. Sonuç yönü (blockchain gereksiz) hacim varsayımına duyarlı değil; rakam kaldırıldı.*

⚠️ **Ve bir uyarı: crypto-shredding'i "GDPR erasure" diye pazarlama.** EDPB Guidelines 01/2025 (16 Ocak 2025): *"the pseudonymised data can be considered anonymous only if the conditions for anonymity are met."* Anahtar silmek otomatik anonimleştirme değildir. Doğru konumlandırma: *"irreversible de-identification of log content, subject to the controller's own DPIA."*

### 9.4 Delege yönetimin gerçek maliyeti

**Keycloak, Fine-Grained Admin Permissions V2'yi Nisan 2025'te yayınladı ve ilk ~14 ayda en az beş ayrıcalık yükseltme CVE'si aldı:** CVE-2025-7784 (`manage-users` → kendine `realm-admin`), CVE-2026-9099 (CVSS 7.7 — `addChild()` yetkilendirme kontrolü yok, grup reparent ile **tam realm devralma**), CVE-2026-3121, CVE-2026-9795, CVE-2026-9796 (TOCTOU).

**Bu bir uygulama kalitesi sorunu değil — teorik bir sınır.** Ayrıcalık yükseltmenin formal adı **HRU safety problem** (Harrison, Ruzzo, Ullman, CACM 19(8), 1976) ve genel halde **karar verilemezdir**; create operasyonları olmadan bile PSPACE-complete. Yani *"bu izin seti güvenli mi?"* sorusuna genel bir statik analizle cevap verilemez.

**Uygulanabilir tek strateji — çalışma zamanı invariant'ı:**
> **Hiçbir aktör, kendi efektif izin kümesinin üstünde bir izni hiçbir yolla veremez.**
> Ve bu kontrol **tek bir merkezî fonksiyondan** geçmelidir: rol atama · grup üyeliği · **hiyerarşi taşıma** · scope mapping · protocol mapper · token exchange. Keycloak bu prensibi *beyan etti* ama kontrol her yolda uygulanmadığı için beş CVE aldı.

**İki alt kural:**
- **Hiyerarşi mutasyonu hem kaynak hem hedef üzerinde izin gerektirir** ve taşıyanın efektif iznini **artıramaz.** CVE-2026-9099 ve GitLab CVE-2026-35595 (`parent_project_id: 0`) aynı sınıf.
- **Token'a claim yazabilen her mekanizma yetki-verendir.** Keycloak'ta sınırlı yetkili geliştiriciler protocol mapper yöneterek admin rollerini token'a map edip Admin API'ye erişebiliyordu.

> **Ayrıca Rust'ın bellek güvenliğine güvenip yetkilendirme testinden kısma:** Keycloak advisory'lerinin son sayfasındaki 10 kayıttan **7'si "bypass" sınıfı** (authorization, signature validation, restriction, boundary, ticket). **Sıfır** memory-safety, **sıfır** injection. Rust bu kategoriye **hiçbir** katkı sağlamıyor.

### 9.5 Dağıtım — üç yapısal karar

**1. `build`/`start` ayrımı olmayacak; tek binary, tek komut.**
Keycloak'ın `kc.sh build` / `start-dev` / `start --optimized` üçlemesi bir **Quarkus augmentation artefaktıdır** ve mod geçişlerinde gerçek regresyon üretmiştir (#30460: `start-dev`'den sonra `start` patlıyordu). Rust'ta bu bedel yok — derleme zaten AOT. **Dev ile prod arasındaki fark yalnızca konfigürasyon değerleri olmalı, farklı bir kod yolu değil.** Keycloak'ın dev/prod uçurumunun kökeni tam olarak budur: farklı DB (H2), farklı komut, zorunlu hostname+TLS, ayrı build adımı.

**2. Güvensiz konfigürasyonla başlamayı reddet — uyarma.**
Keycloak production mode'un doğru yaptığı tek şey bu: hostname ve TLS yoksa *"startup will fail intentionally with an error message, preventing insecure deployments."*
Ama Keycloak'ın kendi kontrol listesinde **"sadece öneri"** kalan satırlar ölümcül yanlış yapılandırmalardır ve Argus bunları zorlayabilir:
- **Proxy header güveni varsayılan KAPALI**; açıkken `trusted_proxies` CIDR listesi boşsa **başlama**. Keycloak'ın kendi uyarısı: *"rogue clients can inject false values… especially critical if you do any deny or allow listing of IP addresses."* Bu, **brute-force sayaçlarını ve rate limit'i sessizce işe yaramaz hâle getiren** tuzaktır.
- **Admin arayüzü ayrı hostname/bind adresi** — Keycloak bunu öneri olarak bırakıyor.
- Issuer URL'i açıkça ayarlanmamışsa başlama: *"an attacker could manipulate a URL… tokens could be issued by a fraudulent issuer."*

**3. Volatile state DB'de — in-flight OAuth akışlarını graceful shutdown'a emanet etme.**
Authorization Code akışı **tek bir HTTP isteğinden uzundur**: `/authorize` → login formu → `/login-actions/authenticate` → `/token`, aralarda dakikalar geçebilir. Hiçbir `terminationGracePeriodSeconds` bunu korumaz.
Keycloak 26.7 stateless preview'u tam olarak bunu yaptı — auth session'ları, action token'ları ve brute-force sayaçları DB'ye taşındı: *"Full cluster restarts no longer reset volatile state during upgrades."* Bedeli auth etkileşimi başına **+8-10 ms** ve DB CPU/IOPS'un ~2 katı. **Rust'ta JVM'siz olarak bu bedel daha kabul edilebilir; Argus'ta varsayılan olmalı, opsiyon değil.**

**Boyutlandırmanın çapası — Keycloak'ın kendi formülleri:**

| Metrik | Formül |
|---|---|
| **Parola ile login** | **15/s başına 1 vCPU** |
| Client credential grant | 120/s başına 1 vCPU |
| Refresh token | 120/s başına 1 vCPU |
| DB | 100 istek/s başına **1.400 write IOPS** + 0,35-0,7 vCPU |
| Headroom | **%150** |

> **15 vs 120 — parola login'i client credentials'tan 8 kat pahalı ve fark neredeyse tamamen Argon2.** Bu, boyutlandırma modelinin merkezine hash'lemeyi koymayı zorunlu kılıyor: pod bellek limiti = baseline + (`max_concurrent_hashes` × 7 MB) + pool + cache. Kuyruk dolunca **429 + Retry-After**, bekletme yok.
> Ve Keycloak'ın pod başına **1250 MB** baseline'ı JVM'in bedeli — **asıl kazanç burada.**

**İki ek uyarı:**
- ⚠️ **musl'a körlemesine geçme.** Çok-thread'li Rust'ta musl allocator'ının ~30× yavaşlama ürettiği raporlanmış (2020; musl 1.2.x sonrası yeniden ölçülmeli). Argon2 + tokio iş yükü için **kendi benchmark'ın olmadan** geçme. Güvenli varsayılan: **glibc + `distroless/cc`**.
- ⚠️ **Üçüncü taraf imaj kataloğuna bağımlı olma.** Bitnami 28 Ağustos 2025'te sürümlü imajları `bitnamilegacy`'ye taşıdı (*"no further updates or support"*) ve `bitnamicharts` OCI artefaktları güncellenmiyor — bundled imajlar override edilmezse deploy'lar patlıyor. **Argus'un chart'ı hiçbir üçüncü taraf PostgreSQL subchart'ına bağımlı olmamalı.**

---

## 10. Açık kararlar — kapatılmadan ilgili bileşenin implementasyonuna başlanmaz

İki bağımsız inceleme turu sonunda aşağıdaki kararlar **kasıtlı olarak açık** bırakıldı.
"Açık" burada "sonra bakarız" değil, **"kanıtı henüz yok, uygulanabilir algoritması henüz
yazılmadı"** demektir. Bu bölümdeki hiçbir madde kapatılmadan **ilgili bileşenin implementasyonuna
başlanmaz** — crate iskeleti ve I/O içermeyen çekirdek bundan bağımsız ilerleyebilir.

**Karar kaydı alanları — her karar satırı bunları taşır:**

`kimlik · statü · gerekçe · geçerlilik koşulu · kabul testi · **hangi karşı örnek veya test
sonucu bu kararı geçersiz kılar** · kaynak satır`

Son alan bu turun ürünüdür: iki tarafın da yanıldığı yerler tam olarak bu alanın boş
olduğu yerlerdi.

**Statüler:** `kalıcı kimlik sözleşmesi` · `kabul edilmiş yön` · `doğrulanacak hipotez` ·
`ertelenmiş karar`

### 10.1 AÇIK — iptal / bayatlık sözleşmesi

**Neden açık:** §1 §4.1 uzun ömürlü access token + sinyal güdümlü iptal seçiyordu; §19 §7.2
ise degraded mode'un *"gerçek güvenlik sınırı access token ömrüdür"* diyerek kısa ömrü
önkoşul yapıyor. İkisi aynı anda savunulamaz.

**Terminoloji:** aşağıdakiler *profil* değil **doğrulama yollarıdır**; izin verilen bayatlık
her yol için tanımlanan bir **koşuldur**.

**Bu tablo boş bir alan değil, bir birleştirme işidir.** Hücrelerin çoğunun karşılığı belgede
zaten var — §19 §4.5 (negatif cache kuralı), §19 §7.1 (kesinti matrisi), §19 §7.2 (degraded
mode pencereleri), §26 (operatör davranışı). Sorun bunların **eksik veya çelişkili** olması ve
**tek, tutarlı bir sözleşmede birleştirilmemiş** olmasıdır. Mevcut bilgi yok sayılmadan
birleştirilecek; `—` işareti "bu yol için **uygulanamaz**" demektir, "bilinmiyor" değil.

| Doğrulama yolu | İptal bilgisi cache miss | Partition | Restart | Azami bayatlık |
|---|---|---|---|---|
| **Argus içi — login** | *birleştirilecek* (§19 §7.1: DB düştüğünde 503) | *birleştirilecek* | *birleştirilecek* | *birleştirilecek* |
| **Argus içi — refresh** | *birleştirilecek* (§19 §7.1: 503 + `Retry-After`, asla `invalid_grant`) | *birleştirilecek* | *birleştirilecek* | *birleştirilecek* |
| **Argus içi — introspection** | *birleştirilecek* (§19 §4.5 "mutlaka DB'ye sor" ↔ §19 §7.2 cache-only çatışıyor) | *birleştirilecek* | *birleştirilecek* | *birleştirilecek* |
| **Salt-JWT doğrulayan RS** (sinyal tüketmez) | **—** iptal bilgisi cache'i **yok**; RS'in tuttuğu şey **JWKS anahtar cache'idir**, iptal durumu değil | *birleştirilecek* | *birleştirilecek* | ≈ access token ömrü (§19 §7.2) |
| **Sinyal tüketen RS** (SSF/CAEP) | *birleştirilecek* | *birleştirilecek* | *birleştirilecek* | *birleştirilecek* |

⚠️ **Ayrım notu (3. tur):** login / refresh / introspection aynı Argus yüzeyinde bulunmaları
nedeniyle tek satır sayılmıştı; **aynı kesinti davranışına sahip değiller** ve §19 §7.1 zaten
üçünü farklı sütunlarda gösteriyor. Ayrıca salt-JWT doğrulayan RS'de "epoch cache miss"
uygulanabilir bir kavram değil — **anahtar cache'i ile iptal bilgisi ayrı tutulmalı**, aksi
hâlde JWKS tazeliği iptal tazeliğiyle karıştırılır.

**Kapatılması gereken bilinen boşluk:** §19 §4.5'in *"cache miss → **mutlaka** DB'ye sor"*
kuralı ile §19 §7.2'nin degraded mode'u doğrudan çatışıyor — DB erişilemezken cache'te
**hiç bulunmayan** bir kullanıcı için 60/300 sn'lik zaman penceresi anlamsızdır; o kullanıcı
için derhal fail-closed olmak gerekir. Zaman tabanlı pencere "cache bayat" ile "cache bu
kullanıcıyı hiç görmedi" durumlarını ayırmıyor.

**Geçersiz kılma koşulu:** *"DB düşse bile doğrulama sürer"* ile *"iptal en geç 250 ms'de
uygulanır"* aynı yolda birlikte vaat edilirse bu karar geçersizdir.

### 10.2 AÇIK — outbox teslimat algoritması

**Neden açık:** §19 §4.3'ün seçtiği "son 5 saniyeyi yeniden tara" çözümü doğruluk
sağlamıyor, ve önerilen iki alternatif de henüz tamamlanmış algoritma değil.

**Kaldırılan:** 5 saniyelik pencere **doğruluk mekanizması olmaktan çıkarıldı.** PostgreSQL'de
`now()` transaction *başlangıç* zamanını döndürdüğü için pencerenin azami transaction
süresinden büyük olması gerekir — o süre sınırsızdır. Pencere en fazla bir *hızlandırıcı*
olabilir, doğruluk kaynağı olamaz.

**Aday A — xid watermark üzerinden ilerleme (polling). `[ADAY — DOĞRULUK İDDİASI YOK]`**
Taslak: her turda `pg_snapshot_xmin(pg_current_snapshot())` alınır; transaction kimliği
`[önceki_watermark, yeni_xmin)` aralığında olan satırlar işlenir; watermark yeni xmin'e taşınır.

⚠️ **Neden `seq` cursor'u değil (bu kısım kesindir):** MVCC altında commit etmemiş bir
transaction'ın outbox satırı görünmez, dolayısıyla *"uçuştaki xid'e ait en düşük seq"* tablodan
**hesaplanamaz**. Sequence tabanlı cursor kuralları — 5 sn penceresi dahil — bu yüzden
uygulanabilir değil. Bu, adayın kendisini doğrulamaz; yalnızca terk edilen yolu kapatır.

⚠️ **Doğruluk iddiası kurulmadan önce değerlendirilecekler.** Bu liste kapanmadan A, B ile
karşılaştırılamaz:
- **Kimlik alanı: açık `xid8` kolonu öne çıkıyor.** İki seçenek var — satırın sistem sütunu
  `xmin`, ya da şemaya eklenen **açık bir transaction kimliği kolonu** (`pg_current_xact_id()`
  ile yazılan `xid8`). ⚠️ *Değerlendirme (3. tur, bu belgenin kendi çıkarımı — dış incelemede
  yer almadı): kanıt tek yönü gösteriyor.* Sistem sütunları **indekslenemez**; `xmin` üzerinden
  aralık taraması planlayıcı için seq scan demektir ve bu, 20 node'dan 100–250 ms'de koşan bir
  sorguda kabul edilemez (§19 §4.3 maliyet notu). Açık `xid8` kolonu indekslenebilir ve
  aşağıdaki sarma/subtransaction maddelerini de düşürür — **ama yalnızca üst-seviye (top-level)
  transaction kimliği tutulursa**, yani:
  ```sql
  producer_xid xid8 NOT NULL DEFAULT pg_current_xact_id()
  ```
  **`xid8` önde gelen adaydır; seçilmiş algoritma değildir.** Karar öncesinde şu dördü kalıyor:
  (a) aynı transaction'daki birden fazla olayın aynı `xid8`'i taşıması — sıralama ve idempotency
  buna göre tanımlanmalı; (b) watermark aralığının **yarı açık sınır semantiği**
  (`[önceki, yeni)`) — sınırda çift işleme veya atlama olmadığı ispatlanmalı; (c) uzun
  transaction'ın ilerlemeyi durdurması — §10.1'in azami bayatlık hücresine yazılır;
  (d) watermark ve retention durumunun **her tüketici için kalıcılaştırılması** — bellekte
  tutulursa restart'ta tüketici ilerlemesi ile yeniden üretilebilir durum arasında boşluk doğar.
- **Subtransaction'lar.** Savepoint/`EXCEPTION` bloğu içinde yazılan satır bir **subxid** taşır;
  subxid ile üst transaction'ın xid'i arasındaki ilişki ve `xmin` sınırına göre görünürlüğü
  ayrıca tanımlanmalı.
- **Satır güncellemesi — bu bir şema kısıtına çevrilir, açık soru değildir.** Sistem sütunu
  `xmin` satırı **en son yazan** transaction'ı gösterir; outbox satırı `UPDATE` edilirse ekleme
  sırası kaybolur. Çözüm zaten belgede: §25 §7 K7'nin append-only deseni (`REVOKE UPDATE, DELETE`
  + `BEFORE UPDATE OR DELETE` + `BEFORE TRUNCATE` trigger'ları) outbox tablosuna da uygulanır.
  Bu maddeyi "değerlendirilecek" değil, **"şemada zorlanacak"** olarak işaretliyoruz.
- **Snapshot tutarlılığı.** Watermark ilerletme ile satır okuma aynı snapshot'ta yapılmazsa
  aralık kayabilir; `REPEATABLE READ` veya tek sorgu gerekir.
- **Sorgulama maliyeti.** Sistem sütunları indekslenemez; `xmin` üzerinden aralık taraması
  planlayıcı için seq scan demektir. 100–250 ms'de bir, 20 node'dan koşan bir sorgu için bunun
  maliyeti ölçülmeden kabul edilemez.
- **Sarma.** 4 baytlık `xmin` ile 8 baytlık `xid8` arasında epoch dönüşümü gerekir.
- **Bilinen ve kaçınılmaz bedel:** tek bir uzun transaction watermark'ı dondurur ve bu
  **doğrudan iptal gecikmesine yazılır** — §10.1'deki azami bayatlık hücresini etkiler.

**Aday B — logical decoding (replication slot).** Akış tanım gereği **commit sırasındadır**,
dolayısıyla sequence/commit uyumsuzluğu yapısal olarak ortadan kalkar; cursor dayanıklıdır
(`confirmed_flush_lsn`), node belleğinde değil. ⚠️ **Dayanıklı slot, dayanıklı cache demek
değildir:** tüketici olayı alıp yalnızca bellekteki cache'e uygular, ilerlemeyi bildirir ve
çökerse, slot ilerlemiş ama cache boştur.

⚠️ **Restart prosedürü `[KISMEN AÇIK]`.** İlk kurulumda çözüm bilinir: slot oluşturulurken
**dışa aktarılan tutarlı snapshot**'tan başlangıç durumu kurulur ve akış tam oradan devralınır.
**Mevcut bir slot üzerinden yeniden başlamak ise aynı operasyon değildir** — var olan bir slota
yeniden bağlanmak yeni bir snapshot vermez, yalnızca bildirilen konumdan akışı sürdürür.

> ⚠️ *Daraltma (3. tur, bu belgenin kendi çıkarımı — dış incelemede yer almadı): bu boşluk
> göründüğünden dar.* Argus'un iptal cache'i **saf türetilmiş bir cache**'tir ve §19 §4.5 soğuk
> başlangıcı zaten tanımlar: cache boşaltılır, "cache miss → mutlaka DB'ye sor" moduyla ısınır.
> Yani durum kaybolduğunda onu **yeniden kurmanın yolu vardır ve slot'tan bağımsızdır** —
> snapshot/slot dansı doğruluk için değil, yalnızca *ısınma maliyetinden kaçınmak* için gerekir.
> ⚠️ **Ama bu daraltma koşulsuz değil.** Cache ancak aşağıdaki **dört koşul birlikte**
> sağlandığında saf türetilmiş veri olur; sağlanmazsa eski slot konumunun öncesindeki olaylara
> gerçekten ihtiyaç doğar ve boşluk yeniden açılır:
> 1. **Cache miss primary DB'ye gider** — replica'ya değil (§19 §4.5 negatif cache kuralı).
> 2. **DB erişilemiyorsa fail-closed olunur** — bilinmeyen için "iptal edilmemiş" varsayılmaz.
> 3. **Cache hazırmış gibi trafik alınmaz** — node, readiness'ini ilan etmeden isteğe cevap vermez.
> 4. **Epoch uygulaması monotondur** — yeniden teslimat veya sıra dışı olay değeri geri almaz.
>
> Bu dört koşul sağlandığında eksik değer her zaman DB'den çekilebilir ve restart prosedürünün
> açık kısmı gerçekten §10.1'e taşınır. **Geriye kalan tek açık:** restart, DB erişilemezliğiyle
> **çakışırsa** ne olur — o durumda 1. koşulun dayandığı fallback de yoktur. Bu, §10.1'in
> cache-miss × partition hücresidir, §10.2'nin konusu değil.

Yine de yeni bir snapshot/slot kurulacaksa şunlar tarif edilmeli ve hiçbiri henüz yazılmadı:
- eski slotun **devreden çıkarılma** noktası ve sırası (önce yeni slot mu, önce eski mi),
- iki slot arasındaki **aradaki değişikliklerin kapsanması** — hangi tarafın örttüğü,
- tüketicinin **hazır (readiness) koşulu**: hangi anda "durumum güncel" sayılır ve o ana kadar
  iptal kontrolü nasıl davranır (fail-closed mu, DB'ye mi sorar),
- eski slotun WAL biriktirmesinin sınırı (`idle_replication_slot_timeout`, §19 kaynak 19).

**Diğer bedelleri:** tek slot tek tüketiciye hizmet eder (N node = N slot veya ayrı dağıtıcı);
failover'da slot senkronizasyonu gerekir; `streaming` açıksa commit etmemiş parçalar gelir ve
tüketici `stream_abort` semantiğini doğru işlemelidir.

**Her iki aday da aynı arıza matrisinde sınanacak — karşılaştırma bundan önce yapılmaz:**

| # | Senaryo |
|---|---|
| 1 | Ters commit sırası (geç açılan transaction erken commit eder) |
| 2 | Uzun süren tek transaction — ilerleme durur, iptal gecikmesine etkisi ölçülür |
| 3 | Tüketici retention penceresinden (24 sa) uzun süre düşer → yeniden senkronizasyon |
| 4 | Tüketici restart — ilerleme ile yeniden üretilebilir durum arasında boşluk var mı |
| 5 | Failover — slot/cursor durumu hayatta kalıyor mu |
| 6 | Çoklu tüketici / çok node yayılımı |

**Sınanacak değişmez:** *Tüketici ilerlemesi ile tüketicinin yeniden oluşturabildiği durum
arasında boşluk bulunmamalı.*

**Geçersiz kılma koşulu:** yukarıdaki altı senaryodan herhangi birinde kaçırılmış iptal
üretilebiliyorsa aday elenir.

> **Bu bölümün statüsü.** §10, **mimari yönleri** kayda geçirir; outbox'ın doğruluğunu veya
> iptal sürelerini **kanıtlamaz**. İki aday da bugün *aday*dır ve aralarında seçim yapılmamıştır.
> Sıradaki teknik iş ikidir ve sırayla yapılır: (1) §10.1'deki doğrulama yollarının arıza
> sözleşmesini mevcut bölümlerden **birleştirerek** doldurmak, (2) iki outbox adayını yukarıdaki
> ortak matriste sınamak. Bu ikisi bitmeden §10.2'de karar satırı yazılmaz.

### 10.3 Kabul edilmiş yönler

| # | Karar | Statü | Kabul testi |
|---|---|---|---|
| A1 | Denetim olayı iş değişikliğiyle **atomik** minimal kayıt; Merkle/imza/egress arkada (§1 karar 23) | kabul edilmiş yön | Commit sonrası `SIGKILL` → kayıt yeniden işlenebiliyor |
| A2 | **Kurtarma iptali ile oturum iptali ayrı eylemler** (§22 §10.1) | kabul edilmiş yön | `DENIED` geçişi tek başına oturum düşürmüyor |
| A3 | Yetki açan geçiş: durum + kanıt doğrulama + **kanıt tüketimi** aynı atomik işlemde (§22 §10.2) | kabul edilmiş yön | Aynı kanıtla paralel iki `REBIND_OPEN` denemesi başarısız |
| A4 | **Origin / issuer / RP ID yaşam döngüleri ayrı modellenir** (§23 §5.3) | kabul edilmiş yön | Custom domain eklendi, eski RP ID + ROR ile giriş sürüyor |
| A5 | Benchmark sayılarına **[YENİDEN ÜRETİM BEKLİYOR]** etiketi; mutlak sayılar ürün iddiası değil (§6 §4.4) | kabul | Kod + ham çıktı + komut repoda |
| A6 | Yetkilendirme v1: primary'de **tek tutarlı snapshot** (`REPEATABLE READ` veya tek sorgu) + aynı transaction'da epoch artışı + sonucun snapshot epoch'uyla etiketlenmesi | kabul edilmiş başlangıç modeli | Yeni epoch altında eski veriyle karar cache'lenemiyor |

⚠️ **A6'nın açık kalan parçası:** `READ COMMITTED` altında ardışık sorgular farklı snapshot
görür — "aynı transaction" demek tek başına yetmez. Ayrıca **uçuşta olan kararın hangi anda
geçerli sayıldığı** tanımlı değil: cache'e hiç yazılmadan doğrudan çağırana dönen bir karar,
epoch anahtar karşılaştırmasının kapsamı dışında kalır. *"İptal commit olduktan sonra hiçbir
eski karar kullanılamaz"* garantisi yalnızca cache karşılaştırmasından çıkmaz. Replica'ya
çıkıldığında sürüm/LSN bariyeri gerekecek; v1'de gerekmiyor.

### 10.4 "Geri alınamaz" listesinin statü ayrımı

§1 §1'deki 27 maddenin hepsi aynı sınıfta değil ve hepsine aynı kesinliği vermek, yanlış
olduğu sonradan görülen bir tercihi değiştirmeyi zorlaştırıyor:

**Dağılım (§1 §1 tablosuyla birebir sayılmıştır):** KŞS 8 · KKS 7 · MT 11 · DH 1 = 27.

- **KŞS — kalıcı şema sözleşmesi (8)** — veritabanının içinde; değiştirmek çevrimdışı göç:
  `tenant_id` her PK'da (1), composite FK (2), RLS `FORCE` (3), kiracı-yerel kullanıcı
  benzersizliği (6), `placement_id` (9), denetim partition'ları (10), ID yeniden kullanılmaması
  (14), kullanıcı başına DEK (17).
- **KKS — kalıcı kimlik sözleşmesi (7)** — dış dünyaya yerleşir, göç maliyeti gerçekten yıkıcı:
  kiracı başına imzalama anahtarı (4), global `client_id` (5), değişmez kiracı slug'ı (7),
  issuer stratejisi (8), WebAuthn RP ID (12), `user.id` (13), platform/kiracı admin API
  ayrımı (21 — audience ve scope namespace'i token'larda görünür).
- **MT — kabul edilmiş mimari tercih (11)** — değiştirmesi pahalı ama mümkün: opak-ID
  yetkilendirme (11), `argus-core` I/O yasağı (15), tipli durum makinesi (16), üç epoch (18),
  server-side template yasağı (19), admin konsolu session cookie (20), veri katmanı filtresi
  (22), audit outbox (23), `redirect_uri` exact match (24), **imzalama anahtarlarının DB
  dışında olması (25)**, migration job modeli (26).
- **DH — doğrulanacak hipotez (1)**: minimum PostgreSQL 18 (27) — gerekçesi bu turda bir kez
  zaten düzeltildi.

⚠️ *Düzeltme (4. inceleme turu): bu liste önceden 25'i (imzalama anahtarlarının konumu) KKS
sayıyordu ve ana tabloyla çelişiyordu. **Doğrusu MT'dir:** geri alınamaz olan şey anahtarın
**kaybı**dır, **konumu** değil — depolama arkası (dosya/KMS/PKCS#11) pluggable tasarlandığı için
zaten değiştirilebilir. Ayrıca bu bölümün önceki hâli 27 maddenin yalnızca 8'ini sınıflandırıp
gerisini boşta bırakıyordu; şimdi hepsi sayılı.*

- **Bu tablonun dışında kalan, ertelenmiş/açık kararlar:** iptal sözleşmesi → §10.1;
  outbox teslimatı → §10.2. Denetim kuyruğu (23) §10.3 A1 ile kapandı ve tabloya MT olarak girdi.

> **Kural:** *"Henüz yayımlanmış bir örnek bulamadık"* ifadesi **"Argus dünyada ilk olacak"**
> sonucuna dönüştürülmez. İkincisi ayrı bir iddiadır ve ayrı kanıt ister.

---

## 11. Doküman haritası

| Dosya | Satır | İçerik |
|---|---|---|
| 01-architecture-decisions.md (§1) | bu dosya | **Karar** |
| 02-contradictions-and-resolutions.md (§2) | 225 | Raporlar arası beş çelişkinin çözümü |
| P0-kritik-bulgular.md (§3) | 376 | Acil ve öncelikli bulgular |
| 05-rust-ecosystem.md (§5) | 391 | Rust fizibilitesi, crate envanteri, efor tahmini |
| 14-mcp-authorization.md (§14) | 1.145 | MCP authorization tam referansı |
| 15-agent-identity.md (§15) | 1.016 | AI ajan kimliği — IETF, MCP, endüstri, düzenleme |
| 21-session-security.md (§21) | 1.229 | DBSC, SSF/CAEP, DPoP, AiTM, donanım attestation |
| 17-future-standards.md (§17) | 1.597 | PQC, WebAuthn L3, CTAP 2.3, TLS |
| 20-authorization-engine.md (§20) | 1.598 | Zanzibar, Cedar, OpenFGA, ReBAC |
| 19-high-availability.md (§19) | 1.277 | HA topolojisi, epoch, PostgreSQL, kademeli bozulma |
| 18-multi-tenancy.md (§18) | 1.299 | RLS, izolasyon, 14 gün-1 kararı |
| 06-performance.md (§6) | 724 | Ölçümler, Argon2, audit log, darboğazlar |
| 16-enterprise-protocols.md (§16) | 2.016 | SAML, SCIM, LDAP, Kerberos, OpenID Federation |
| 22-account-lifecycle.md (§22) | 2.998 | Kurtarma, bağlama, impersonation, silme, kayıt, göç, B2B |
| 23-login-flows.md (§23) | 632 | Identifier-first, passkey UX, MFA, hosted vs embedded, markalama, erişilebilirlik |
| 27-test-strategy.md (§27) | 669 | Conformance süitleri, interop, yük, kaos/DST, güvenlik testi, CI bütçesi |
| 24-admin-api.md (§24) | 664 | Admin API tasarımı, delege yönetim, ayrıcalık yükseltme CVE'leri, GitOps, bulk |
| 25-observability.md (§25) | 787 | OCSF, tamper-evidence, katmanlama, Rust OTel yığını, SSF/CAEP yayını |
| 26-deployment-operations.md (§26) | 773 | Kurulum, konteyner/K8s, şema göçü, yedekleme, boyutlandırma, lisans, CRA |
| guvenlik-muhendisligi.md | dizin | Aşağıdaki altı dosyaya giriş |
| 10-formal-verification.md (§10) | 1.371 | Kani, Verus, Cedar+Lean 4 |
| 07-verified-cryptography.md (§7) | 874 | HACL*, fiat-crypto, s2n-bignum |
| 08-side-channels.md (§8) | 799 | Sabit zaman, Marvin, timeless timing |
| 12-supply-chain.md (§12) | 1.484 | cargo-vet/deny/audit, SBOM |
| 11-runtime-hardening.md (§11) | 1.923 | Binary hardening, izolasyon, fuzzing |
| 09-key-management.md (§9) | 1.293 | PKCS#11/HSM, KMS, rotasyon |
| 13-security-process.md (§13) | 179 | Tehdit modelleme, VDP, CVE süreci |
