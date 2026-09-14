# §1 — Mimari kararlar

Argus, MCP ve ajan kimliğini birinci sınıf vatandaş olarak modelleyen, sender-constrained token'ı varsayılan kabul eden ve çok kiracılığı gün-1'de doğru kuran, Rust ile yazılmış genel amaçlı bir Identity Provider'dır.

**Kapsam sınıfı.** Hedeflenen kapsam, protokol yüzeyinin tamamını tek üründe veren genel amaçlı IdP sınıfıdır. Bu sınıfın referansları Keycloak, Janssen, WSO2 Identity Server ve Ping'in birleşik platformudur; tek bir ürün ölçüt alınmaz. Gerekçe manzara taramasıdır: karşılaştırmayı tek ürüne dayandırmak, farklılaşma iddialarının en az birini olgusal olarak yanlışlamıştı (bkz. 8).

Kapsam dışı: sektöre özgü dikey ürünler, uyum (compliance) ürünleri ve azaltılmış özellik setine sahip "hafif" IdP konumlandırması.

**Performans ölçütü.** Keycloak'ın yayımlanmış referans değerleri 2.000 login/sn ve 10.000 token yenileme/sn'dir. Argus bu değerleri aynı Argon2 parametreleriyle ve daha az donanımla aşmayı hedefler. Keycloak'ın ölçüt olmasının sebebi kapsam eşitliği değil, yeniden üretilebilir rakam ve koşum yöntemi yayımlayan tek IdP olmasıdır; incelenen hiçbir sağlayıcı üretim login/refresh/introspection oranı yayımlamamaktadır (§27 §3.2). Oranın kendisi de bir benchmark seçimidir: 1:5 login:refresh profili Keycloak'ın kıyaslama tercihidir, ölçülmüş bir üretim oranı değildir. Hedef bu yüzden "Keycloak'ı geçmek" değil, **aynı donanım bütçesinde aynı Argon2 maliyetiyle daha yüksek login/sn taşımaktır**; karışık profilde login'in refresh'i aç bırakmaması ayrı bir kabul kriteridir (§27 §3.4).

**Numaralandırma kuralı.** `§N` biçimindeki referanslar dizindeki diğer dosyalara işaret eder (doküman haritası için bkz. bölüm 11). Bu dosyanın kendi bölümleri `§` işareti olmadan, yalnızca numarayla anılır (ör. "bkz. 9.1"). Diğer dosyaların iç bölümleri `§23 §5.3` biçiminde yazılır.

---

## 1. Gün-1 kararları

Bu bölümdeki kararların gün-1'de verilmesi zorunludur. Sonradan değiştirme maliyeti ya uygulanabilir değildir ya da tüm kurulumu durduran bir göç gerektirir. Tercih sebebi sütunu seçimin gerekçesini taşır; gerekçe sonradan değiştirmenin bedelinden ayrılamıyorsa o bedel de aynı hücrededir.

| # | Karar | Tercih sebebi | Kaynak |
|---|---|---|---|
| 1 | `tenant_id` her tabloda ve her birincil anahtarda | Kiracı, satırın kimliğinin parçası olur; ona işaret eden her FK de kiracıyı taşımak zorunda kalır ve çapraz kiracı referans ifade edilemez hâle gelir. Sonradan: tüm PK'ları düşürüp yeniden kurmak, çevrimdışı göç. SuperTokens örneğinde 33 tablo ve tüm PK'lar CASCADE ile etkilendi | §18 |
| 2 | Her yabancı anahtar composite (`tenant_id` dahil) | Tek kolonlu FK'lar çapraz-kiracı referansa izin verir; RLS sonradan eklendiğinde okuma yollarını bozar | Logto PR #7596 |
| 3 | RLS + `FORCE` + non-owner rol, istisnasız tüm tablolarda | Atlanan tek bir tablo sessiz veri sızıntısı üretir; kısıt ya hep ya hiç niteliğindedir ve sonradan eklenmesi bunu değiştirmez | Logto #7685 |
| 4 | Kiracı başına imzalama anahtarı, varsayılan ES256 | Anahtar paylaşımlıysa kiracı A'nın verdiği token kiracı B'nin JWKS'iyle de doğrulanır; `client_id` kiracılar arası çakışabildiği için `aud` kontrolü de geçer. Storm-0558 tam olarak bu zincirdir. Sonradan geçiş, tüm RP'lerde JWKS cache invalidasyonu ve koordineli kesinti demektir | Storm-0558, CVE-2026-23552 |
| 5 | `client_id` global benzersiz (Keycloak'ın aksine) | RFC 6749 §2.2'ye göre `client_id` yalnızca AS içinde benzersiz olmak zorundadır; çok kiracılıkta bu, kiracılar arası çakışmanın spesifikasyona uygun olması ve `aud` karışıklığını mümkün kılması demektir. Global benzersizlik, kiracı başına anahtarın yanında ikinci bağımsız savunma katmanıdır. Sonradan globalleştirme her RP konfigürasyonunu kırar | RFC 6749 §2.2 |
| 6 | Kullanıcı benzersizliği kiracı-yerel: `UNIQUE(tenant_id, …)`, global değil | Kimlik bilgisini kiracı sahiplenir; aynı e-posta iki kiracıda iki ayrı kullanıcıdır. Global'den kiracı-yerele geçiş veri göçü ve güvenlik incelemesi gerektirir, ters yön ise uygulanabilir değildir | Zitadel: kullanıcıların organizasyonlar arası taşınması desteklenmiyor |
| 7 | Kiracı slug'ı değişmez | Slug issuer URL'inin parçasıdır; değişimi her RP'nin discovery akışını kırar | Keycloak: realm alias sonradan değiştirilemiyor |
| 8 | Issuer stratejisi: subdomain birincil, RFC 9207 `iss` gün-1'de | Alt alan adı, RFC 8414 ile OIDC Discovery arasındaki well-known yolu çelişkisine girmez; yol tabanlı issuer girer. Tek joker sertifika sınırsız kiracıya ölçeklenir, kiracı başına sertifika ellinci kiracıda duvara çarpar. Issuer değişimi tüm RP'lerin yeniden yapılandırılması demektir | RFC 8414 ile OIDC Discovery arasındaki çelişki |
| 9 | `placement_id` silo-kaçış kolonu gün-1'de, kullanılmasa dahi | Düzenlemeye tabi bir kiracı kendi kümesini isteyebilir; kolon varsa bu bir yerleştirme değişikliği, yoksa mimari yeniden yazımdır | AWS silo/pool/bridge modeli |
| 10 | Denetim logu kiracı ve zaman bazlı partition'lı | Ölçekte silme hakkı ancak partition düşürerek karşılanır; satır bazlı silme milyarlarca satırda uygulanabilir değildir. Sonradan partition'lamak da uygulanabilir değildir | GDPR Md. 17 |
| 11 | Yetkilendirme isim tabanlı değil, opak kimlik veya tam yol tabanlı | Token'da ve politikada isim taşınırsa yeniden adlandırma her bileşeni kırar; opak kimlik bunu yapısal olarak önler | CVE-2026-19608 |
| 12 | WebAuthn RP ID apex alan adıdır; login alt alan adı veya satıcı alan adı kullanılmaz. Çok kiracılıkta her kiracı kendi RP ID'sini alır | WebAuthn tarafındaki tek geri alınamaz karardır. RP ID değiştiğinde kayıtlar silinmez ancak kullanılamaz hâle gelir; Okta'nın ifadesiyle tarayıcı bunları girişte sunmaz. ROR (`/.well-known/webauthn`) pratikte beş label ile sınırlıdır, dolayısıyla paylaşımlı RP ID çok kiracılıkta ölçeklenmez | §22 §39.1, §23 §5.3 |
| 13 | WebAuthn `user.id` 64 rastgele bayttır; e-posta veya türevi kullanılmaz | `user.id` authenticator'da saklanır ve sonradan değiştirilemez; e-posta türevi kullanılırsa hem kişisel veri authenticator'a yazılır hem de e-posta değişimi tüm credential'ları geçersiz kılar | WebAuthn L3 §5.4.3, §14.6.1 |
| 14 | Kullanıcı kimliği yeniden kullanılmaz; e-posta varsayılan olarak hiçbir zaman kimlik değildir | Geri dönüştürülen bir tanımlayıcı, yeni sahibine eski hesabın erişimini devreder. Tombstone tekillik kısıtının sonradan eklenmesi mevcut çakışan kayıtları çözemez | RFC 9967, Gmail, GitHub |
| 15 | `argus-core` I/O yapmaz: `async fn`, `tokio::`, `sqlx::`, `reqwest::` yasaktır ve CI'da zorlanır | Formel doğrulamanın uygulanabileceği tek katman budur; I/O sonradan sökülemez | §2 §5 |
| 16 | Kimlik doğrulama akışı konfigüre edilebilir bir "flow" değil, tipli bir durum makinesidir | Keycloak #40744: akıştan adım silmek auth bypass üretiyor; kök neden akışın çalışma zamanında yorumlanan bir konfigürasyon olmasıdır. Agama sınıfı bir akış dili bu hatayı derleme zamanına taşıyabilir; Argus ikinci bir dili ve derleyicisini bakım yüzeyi olarak kabul etmediği için reddeder. Reddedilen **kompozisyondur**; askıya alınabilirlik reddedilmemiştir (§23 §8 #30) | §22 §10.3, §23 §8 #33 |
| 17 | Her PII alanı kullanıcı başına DEK ile şifrelenir (envelope encryption) | Kullanıcı başına DEK, silme hakkını veriyi yeniden yazmadan anahtarı imha ederek karşılar; sonradan eklenmesi tüm verinin yeniden yazılmasını gerektirir | ICO "put beyond use", EDPB CEF 2026 |
| 18 | Üç ayrı epoch: `session_epoch` (kullanıcı), `authz_epoch` (kiracı), `key_epoch` (kiracı) | Tek sayaca indirgenirse her izin değişikliği tüm oturumları düşürür | §2 §4, 9.3 A6 |
| 19 | Kiracıya sunucu tarafında kod çalıştırma verilmez; şablon, betik, kural ve kanca aynı yasağa tabidir. Keycloak'ın FreeMarker modeli benimsenmez | Keycloak dokümantasyonuna göre kötü niyetli bir şablon Keycloak süreci yetkisiyle kod çalıştırabilir; çok kiracılı bir üründe bu, kiracının RCE elde etmesi demektir. Aynı risk şablon dışı üç yüzeyde de vardır: WSO2'nun adaptive auth betikleri, Zitadel'in actions'ı ve authentik'in expression policy'leri. Sonradan script'siz templating'e geçiş her kiracı temasının yeniden yazılmasını gerektirir; script'siz mekanizma §23 §5.5'tedir | §23 §5.2, §23 §5.5 |
| 20 | Argus'un kendi admin konsolu ve hosted login'i OAuth kullanmaz; doğrudan session cookie kullanır | RFC 10017 §7.1, oturum yönetimini OAuth ile ikame etmenin basit uygulamaları gereksiz yere karmaşıklaştırdığını belirtir. Sonradan sökme tüm UI auth katmanının yeniden yazılması demektir | §23 §4.2 |
| 21 | Platform-admin API'si ile kiracı-admin API'si ayrı yüzeylerdir: ayrı audience, ayrı scope namespace'i, ayrı rate limit bütçesi | Auth0 bu ayrımı 21 Nisan 2026'da yapmak zorunda kaldı; Management API sık ve granüler çağrılar için tasarlanmadığından darboğaz hâline geliyor ve müşteriler rate limit sınırına çarpıyordu. Sonradan ikinci bir API yüzeyi eklemek mevcut tüm entegrasyonları kırar | §24 §5.1 |
| 22 | Yetkilendirme filtresi veri erişim katmanındadır, handler'da değil; tipte kodlanır ve filtrelenmemiş koleksiyon serileştirilemez | CVE-2026-17059 bu yapının yokluğundan doğdu: `/users` doğru filtreliyor, `role-members` aynı token'a tam PII döndürüyordu. Handler başına yetkilendirme, N endpoint × M kaynak kombinasyonunda kaçınılmaz olarak atlanır | §24 §3.2 |
| 23 | Denetim olayı, iş değişikliğiyle aynı transaction'da minimal bir audit outbox satırı olarak kalıcılaşır; Merkle birleştirme, imzalama ve dışa yayın arka planda yürür | Keycloak'ın birincil arızası olay yazımlarının istek transaction'ına binmesidir; ayrıştırma doğru yaklaşımdır. Çözüm bellek kuyruğu değildir: bounded in-memory kuyruk, iş değişikliği commit olduktan sonra süreç sonlanırsa kaydı kaybeder ve rol değişikliği kalıcı olurken denetim kaydı oluşmaz | §25 §5.4, §25 §7 K4/K8, 9.3 A1 |
| 24 | `redirect_uri` eşleştirmesi yalnızca tam dizge eşleşmesidir; regex ve wildcard opt-in tehlikeli özellik olarak dahi implemente edilmez | authentik CVE-2024-52289: escape edilmemiş regex noktası nedeniyle `app.example.com` konfigürasyonu `app0example.com` ile eşleşti ve kurban ek etkileşim olmadan saldırgana yönlendirildi. Düzeltme varsayılan olarak tam dizge eşleşmesi oldu. RFC 9700 zaten tam eşleşme zorunlu kılar. Tek istisna loopback'tir: RFC 8252 §7.3 gereği native uygulamaların `127.0.0.1` ve `localhost` redirect'lerinde port bileşeni yok sayılır | §26 §3.3, §14 §9.4 |
| 25 | İmzalama anahtarları veritabanı dışında tutulur; pluggable backend (dosya/KMS/PKCS#11) ve DB yedeğinden bağımsız yedekleme | Anahtar kaybı veritabanı kaybından daha yıkıcıdır: tüm token'lar, refresh token'lar ve oturumlar geçersizleşir, hiçbir RP mevcut JWT'leri doğrulayamaz. Keycloak `rsa-generated` anahtarları veritabanında tutar ve yedekleme prosedürünü dokümante etmez; Zitadel'in masterkey'i `docker compose up` sırasında sessizce üretilir ve sonradan değiştirilemez | §26 §5.2 |
| 26 | Şema göçü ayrı bir job'dır; uygulama başlangıçta yalnızca `validate` yapar ve uyumsuzlukta sonlanır | Keycloak #43252: uyumsuz göçler ve indeks oluşturma kilitleri, rolling update sırasında eski instance'ların kümeye katılmasını engelleyebiliyor. Başlangıca DDL bırakmak N-1 uyumluluğunu yapısal olarak imkânsız kılar | §26 §4.4 |
| 27 | Minimum PostgreSQL 18 | Yerleşik `uuidv7()` insert'te 1,67× hız ve %26 daha küçük indeks veriyor (§6 §4.2); fast-path kilit düzeltmesi (commit `c4d5cb71d`) çok partition'lı iş yükündeki kilit uçurumunu kaldırıyor (§18 §2.2); `SET NOT NULL NOT VALID` expand-contract desenini sadeleştiriyor. Expand-contract'ın kendisi PG12'den beri mümkündür, PG18 gerekçesi değildir | §26 §4.1, §6 §4.2, §18 §2.2 |
| 28 | Kiracı giriş sayfasının kabuğu script çalıştırmayan bir şablonla yazılır; giriş kutusu derlenmiş kodda kalır ve kiracı onu yalnızca konumlandırır | Yönetim yüzeyini ele geçiren aktör birinci taraf değildir; sunucuda kod çalıştıran bir şablon motoru tenant-admin yetkisini RCE'ye çevirir. Kazanç ihmal edilebilir: §26 tek binary modelini belirlediğinden her değişiklikte zaten dağıtım yapılır. Tam kayıt bölüm 2'dedir | §23 §5.1, §23 §5.2, karar 19, karar 20, §26 |
| 29 | Tema verisi `(kiracı, istemci)` ile anahtarlanır ve başlangıçta kiracı kayıt defterine yüklenir | Kiracı logosu yıllık mertebede değişir ve istek başına okunmayı gerektirmez; render başına yapılan iş bir map aramasıdır, sorgu değil. Tam kayıt bölüm 2'dedir | §23 §5.1, §18, §26 |
| 30 | `client_id` yönetici tarafından seçilmez; yerel kayıtta Argus üretir, CIMD yolunda istemcinin kendi URL'idir. İnsanın gördüğü ad ayrı bir `display_name` alanındadır ve kiracıya yereldir | Karar 5 `client_id`'yi küresel benzersiz yapıyor. Değer seçilebilir kaldığı sürece ilk gelen `webapp` adını alıyor ve ikinci kiracı bir benzersizlik ihlaline çarpıyor; yani karar 5 bir ürün hatasına dönüşüyor. Kimliği üretilen bir değer yapmak çakışmayı kaynağında bitiriyor. Sonradan geçiş mevcut istemci kimliklerinin yeniden adlandırılması, yani her RP konfigürasyonunun kırılması demektir. Tam kayıt bölüm 2'dedir | karar 5, §24, §14 |

Otuz maddenin tamamı şemayı, crate sınırlarını, UI mimarisini, API yüzeyini veya dağıtım modelini belirler. Hiçbiri implementasyon sonrasına ertelenebilir nitelikte değildir.

---

## 2. Karar kayıtları

28, 29 ve 30 numaralı kararlar, bölüm 9'da tanımlanan zorunlu karar kaydı alanlarının tamamıyla aşağıda kayıtlıdır.

### Karar 28 — Kiracı giriş sayfası: script çalıştırmayan şablon, derlenmiş giriş kutusu

| Alan | İçerik |
|---|---|
| Kimlik | 28 |
| Karar | Kiracı, giriş sayfasının kabuğunu Liquid ile yazabilir. Giriş kutusu derlenmiş kodda kalır; kiracı onu yalnızca `argus_login_box` yer tutucusuyla konumlandırır. Sunucuda kod çalıştıran şablon motorları (FreeMarker sınıfı) implemente edilmez. |
| Gerekçe | §23 §8 #18'in özgün gerekçesi kiracının düşman kabul edilmesiydi; Argus'ta kiracılar birinci taraf olduğundan bu gerekçe geçerli değildir. Karar iki daha dar sebeple korunmuştur. (a) Bu turda gerçek bir yönetim API'si tanımlandı ve yönetim yüzeyini ele geçiren aktör birinci taraf değildir; sunucuda çalışan bir şablon motoru tenant-admin yetkisini RCE'ye dönüştürür. (b) Kazanç ihmal edilebilir düzeydedir: §26 tek binary ve tek komut modelini belirler, dolayısıyla her değişiklikte zaten dağıtım yapılır. Performans bu kararı belirlemez; ölçümde aynı istekteki Argon2 bu donanımda yaklaşık 11 ms, şablon render'ı mikrosaniye mertebesindedir. |
| Kutunun kiracıya açılmama gerekçesi | Alan adları, alan sıralaması, gönderilen veri kümesi ve identifier adımının sabit biçimli cevabı (§23 §8 #2) güvenlik garantileridir. Auth0 Universal Login aynı sınırı çizer: Liquid prompt'un çevresini kontrol eder, prompt'un kendisini değil. |
| Geçerlilik koşulu | Liquid'in iki ölçülmüş özelliği: (1) fonksiyon çağırma sözdizimi yoktur ve şablon kendisine açıkça verilmeyen hiçbir nesneye, metoda veya ortam değişkenine erişemez; (2) tanımlanmamış bir ada başvuru boş dizge değil hata üretir. Bir sürüm yükseltmesi bu iki özellikten birini değiştirirse karar yeniden değerlendirilir. |
| Kabul testi | `crates/argus-http/tests/theme_shell.rs`. Sabitlenen davranışlar: şablonun kendisine verilmeyene erişememesi ve istek verisinin kabuğa hiç girmemesi. Ayrıca kutuyu konumlandırmayan kabuk saklanmadan reddedilir, bozuk kabuk derlenmiş varsayılana düşer, `javascript:` şeması logo alanından geçemez (kontrol kaldırıldığında iki test başarısız olur) ve CSP hiçbir script kaynağına izin vermez. |
| Geçersiz kılacak karşı örnek | Kiracıların giriş kutusunun içeriğini — alan sırası, alan ekleme, adımlar arası içerik — dağıtım yapmadan değiştirmesinin ürün gereksinimi hâline gelmesi. Kabuğun yetersiz kalması tek başına yeterli değildir; kabuk zaten Liquid'e açıktır. |
| Kalan risk ve kontrolü | FreeMarker sınıfı RCE riski ortadan kalkar, iki risk kalır. XSS: kiracı kabuğa script yazabilir; kontrolü CSP'dir (`default-src 'none'`, script kaynağı yok, satır içi stil yok). Kaynak tüketimi: Liquid döngü kurabilir; kontrolü kabuk boyutu, render süresi ve çıktı boyutu sınırlarıdır. |
| Kaynak | §23 §5.1, §23 §5.2, §23 §8 #14/#16/#18/#19, karar 19, karar 20, §26 |

### Karar 29 — Tema verisi kayıt defterinde tutulur

| Alan | İçerik |
|---|---|
| Kimlik | 29 |
| Karar | Tema, `(kiracı, istemci)` ile anahtarlanmış bir veri kaydıdır; istemciye özel tema yoksa kiracı temasına, o da yoksa derlenmiş varsayılana düşülür. Veri veritabanında saklanır ancak başlangıçta kiracı kayıt defterine yüklenir; render başına yapılan iş bir map aramasıdır, sorgu değil. Değişiklik sonrası yönetim ucu ilgili kiracının girdisini tazeler; süreç yeniden başlatılmaz. |
| Gerekçe | Kiracı logosu yıllık mertebede değişen bir veridir ve istek başına okunmayı gerektirmez. Keycloak'ın modeli de fiilen budur: tema JAR'ı bir dağıtım artefaktıdır ve üretimde şablonlar bellekte cache'lenir. Fark cache'in içeriğindedir: Keycloak yorumlanacak bir şablon ağacı tutar, Argus derlenmiş kod ve veri tutar. |
| Granülerlik gerekçesi | Keycloak realm ve client düzeyinde tema seçimine izin verir. Aynı granülerlik veri modelinde yalnızca bir anahtar meselesidir ve ek maliyet doğurmaz. |
| Kabul testi | Tema değişikliğinden sonra tazeleme ucu çağrıldığında yeni tema sunulur; tazeleme çağrılmadan eski tema sunulur. |
| Geçersiz kılacak karşı örnek | Toplam tema hacminin süreç bellek bütçesini zorlaması; kiracı başına birden çok istemci temasının bellekte tutulamaz hâle gelmesi. Bu noktada doğru cevap veritabanına dönmek değil, sınırlı bir LRU uygulamaktır. |
| Kaynak | §23 §5.1, §18, §26 |

### Karar 30 — `client_id` üretilir, insanın gördüğü ad ayrı bir alandır

| Alan | İçerik |
|---|---|
| Kimlik | 30 |
| Karar | `POST /admin/api/clients/v1` gövdede `clientId` kabul etmez; gönderilirse 400 döner. Kimliği sunucu üretir ve yanıtta bildirir. `PUT /admin/api/clients/v1/{id}` kaynak yaratamaz, yalnızca günceller; olmayan bir kimlikte 404 döner. Toplu iş yolu aynı kurala tabidir. İnsanın gördüğü ad `display_name` kolonundadır, kiracıya yereldir ve üzerinde benzersizlik kısıtı yoktur. CIMD yolundan gelen istemcilerde kimlik istemcinin kendi URL'idir ve adını metadata dokümanından alır. |
| Gerekçe | Karar 5 `client_id`'yi küresel benzersiz yapmaktadır ve gerekçesi sağlamdır: RFC 6749 §2.2 kiracılar arası çakışmaya izin verir, çakışma da karar 4'ün kestiği saldırı zincirinin `aud` halkasını yeniden açar. Ancak değer seçilebilir kaldığı sürece bu güvenlik kararı doğrudan kullanıcının gördüğü isme çarpar: ilk gelen `webapp` adını alır, ikinci kiracı bir benzersizlik ihlali görür ve söyleyecek bir şey yoktur, çünkü istemcinin başka bir adı yoktur. Sektörün cevabı üretilen kimliktir; Auth0, Okta, Entra ve Google'ın dördü de `client_id`'yi üretir, seçtiren tek ürün Keycloak'tır. |
| Geçerlilik koşulu | `client_id`'nin insan tarafından okunabilir olmasının bir ürün gereksinimi olmaması. Kimliğin göründüğü yerler yetkilendirme adresi, token istekleri ile günlüklerdir; üçünde de okunabilirlik gerekmez. |
| Kabul testi | `crates/argus-http/tests/admin_api.rs`. Sabitlenen davranışlar: gövdede `clientId` gönderen istek 400 alır; yaratma yanıtı üretilmiş bir `clientId` taşır ve bu değer etiketten farklıdır; aynı etiketle açılan iki istemci farklı kimlik alır ve ikisi de 201 döner; uydurulmuş bir kimliğe yapılan `PUT` 404 alır; toplu iş içinde `clientId` taşıyan öğe reddedilir. |
| Geçersiz kılacak karşı örnek | Bir müşterinin, istemci kimliğini kendi kurumsal envanterindeki bir değere eşitlemesinin sözleşme gereği olması. Bu durumda doğru cevap seçilebilir `client_id` değil, kimliğe eşlik eden ve kiracıya yerel bir dış referans alanıdır. |
| Kalan risk ve kontrolü | Üretilen kimlik UUIDv4'tür ve günlükte okunması zordur; kontrolü `display_name`'in listeleme yanıtlarında bulunmasıdır. Sürümün v7 değil v4 olması bilinçlidir: §1 §2'nin UUIDv7 kuralı birincil anahtarlar içindir ve gerekçesi indeks yerelliğidir. `client_id` ise yetkilendirme adresinde görünen açık bir tanımlayıcıdır; v7'nin gömdüğü zaman damgası istemcinin ne zaman yaratıldığını sızdırır ve kimlikleri sıralanabilir kılar. Aynı gerekçe §18'in `kid` değerinin opak olması kuralındadır. Ayrıca `clients` tablosunda karar 5 gereği tek kolonlu bir benzersizlik vardır, yani karar 2'nin uyardığı kaçış kapısı bu tabloda açıktır; bugün ona bakan yedi yabancı anahtarın hepsi bileşiktir. Bunu artık disiplin değil `rls_isolation.sql` içindeki `every_fk_carries_the_tenant` taraması sağlamaktadır: `tenant_id` taşıyan bir tablodan yine `tenant_id` taşıyan bir tabloya giden her yabancı anahtar, kiracıyı iki tarafta da aynı konumda taşımak zorundadır. |
| Kaynak | karar 5, karar 2, §24 §2.7, §14, `crates/argus-store/migrations/0025_client_display_name.sql` |

---

## 3. Teknoloji yığını

### 3.1 Dil seçimi

Rust performans gerekçesiyle seçilmemiştir.

Ölçüme göre bir login'in CPU maliyetinin yaklaşık %97'si Argon2 ve imzalamadan oluşur; her ikisi de dilden bağımsızdır. Argon2 tasarım gereği yavaştır ve hızlandırılamaz.

Seçimin üç gerekçesi vardır.

**Kripto ve TLS katmanı.** rustls'te post-quantum varsayılan olarak açıktır; aws-lc-rs FIPS modu ve ML-DSA sunar; s2n-bignum HOL Light ile makine-kontrollü ispatlara sahiptir.

**Güvenlik değişmezlerinin tip sistemine kodlanması.** Branded lifetime ile, A kiracısından okunan bir varlığın B kiracısının yazma yoluna verilmesi derleme hatası hâline gelir. Bu mekanizmanın çok kiracılığa uygulanmış yayımlanmış bir örneği bulunamamıştır.

Mekanizmanın sınırları (§18 §6.3): yanlış kiracının `begin()`'e verilmesini engellemez — bu istek sınırındaki extractor invariantının işidir; ham SQL'de `AND tenant_id = ?` unutulmasını engellemez — bu RLS'in işidir; `Scoped::get()` ham `&T` döndürdüğünden `T: Clone` olan veri brand'in dışına kopyalanabilir.

| | İfade |
|---|---|
| İzin verilen | Belirli yanlış kullanımlar derleme aşamasında engellenir. |
| İzin verilmeyen | Kiracı izolasyonunu bütünüyle derleyici garanti eder. |

**`webauthn-rs` kalitesi.** Ekosistemdeki en iyi konumlanmış bileşendir.

**Kazancın kaynağı.** Argon2'nin hızlandırılması değil, hash dışındaki maliyetin azaltılmasıdır. Aynı Argon2 parametreleriyle çekirdek başına 15 yerine 40-60 login/sn hedeflenmektedir.

**Maliyet.** Yaklaşık 46-73 geliştirici-ayı (Rust), buna karşılık 31-49 geliştirici-ayı (Go); yaklaşık 1,5× çarpan. Referans ölçümler: Kanidm 224.718 satır, Rauthy 84.242 satır.

### 3.2 Bağımlılıklar

```toml
[dependencies]
axum         = "0.8"
tokio        = { version = "1.53", features = ["full"] }
rustls       = { version = "0.23", features = ["fips"] }
jsonwebtoken = { version = "11", default-features = false,
                 features = ["use_pem", "aws_lc_rs"] }
webauthn-rs  = { version = "0.5", features = ["danger-allow-state-serialisation"] }
argon2       = { version = "0.6", features = ["parallel"] }
sqlx         = { version = "0.9", features = ["postgres", "runtime-tokio-rustls"] }
ldap3_proto  = "0.8"
cedar-policy = "4"            # politika değerlendirme, Lean 4 ile doğrulanmış
bergshamra   = "0.9"          # XMLDSig/XMLEnc/C14N, saf Rust
generativity = "1"            # branded lifetimes, kiracı izolasyonu
```

| Yasak | Gerekçe |
|---|---|
| `jsonwebtoken` + `rust_crypto` özelliği | `rsa` crate'i Marvin saldırısına açıktır — §8 |
| Dağıtık cache'in doğruluk kaynağı olarak kullanılması (Redis/Infinispan) | Endüstri PostgreSQL'e yakınsadı: Keycloak Temmuz 2026, Zitadel Şubat 2026, authentik 2025.8 — §19 |
| Postgres `LISTEN/NOTIFY` | PgBouncer transaction modunda çalışmaz; kuyruk dolduğunda yazmalar commit aşamasında başarısız olur |
| Olay başına hash-chained audit log | Ölçümde 8 bağlantı, 1 bağlantı ile aynı throughput'u verdi; tek doğrusal zincirde ardışık zincir hash'leri arasında seri bağımlılık bulunuyor. Değer ölçüme özgüdür, evrensel bir tavan değildir |
| `gamlastan` (SAML domain modeli) | SAML iş mantığı dış bağımlılıktan gelmemelidir; XSW savunması tam olarak bu katmanda yaşar |
| Verus | `serde::Serialize` ve `Mutex` desteklemiyor; mevcut kod tabanına uymuyor |

### 3.3 Crate topolojisi

```
argus-core/      #![forbid(unsafe_code)]  I/O yok, async yok. Durum makineleri,
                                          politika değerlendirme, delegasyon
                                          değişmezleri, epoch mantığı. Kani hedefi.
argus-proto/     #![forbid(unsafe_code)]  OIDC/OAuth2/SCIM/SAML tipleri
argus-parse/     #![forbid(unsafe_code)]  Tüm parser'lar. Derinlik sınırları burada.
argus-http/      #![forbid(unsafe_code)]  axum handler'ları
argus-store/     #![forbid(unsafe_code)]  sqlx, RLS, SET LOCAL
argus-crypto/    (FFI izinli)             aws-lc-rs sarmalayıcısı. İstisna 1.
argus-sandbox/   #![deny(unsafe_code)]+   seccomp/landlock/prctl. İstisna 2.
argus-saml/                               Ayrı süreç. RLIMIT_AS/STACK + timeout.
```

CI gate'leri: `cargo geiger --forbid-only`; `argus-core` içinde `async fn`, `tokio::` ve `sqlx::` için grep yasağı; `cargo-vet`; `cargo-deny`; `cargo-auditable`.

---

## 4. Protokol kapsamı ve öncelik

### 4.1 Faz 1 — çekirdek

| Protokol | Gerekçe | Tahminî efor |
|---|---|---|
| OAuth 2.1 AS durum makinesi | Projenin tek en büyük riski. Rust'ta Fosite eşdeğeri bulunmuyor; iki bağımsız inceleme bunu doğruladı | 12-18 geliştirici-ayı |
| OIDC Core + Discovery + JWKS | Diğer tüm bileşenlerin tabanı | Dahil |
| RFC 8414 ve OIDC Discovery, birlikte | MCP `MUST` | Küçük |
| RFC 9728 PRM, RFC 8707 `resource`, RFC 9207 `iss` | MCP `MUST` üçlüsü | Küçük |
| RFC 9449 DPoP + RFC 8705 mTLS-bound | 3 Ağustos 2026 ölçümü: incelenen 15 halka açık issuer'ın hiçbiri DPoP ilan etmiyor | Orta |
| CIMD (`client_id_metadata_document_supported: true`) | MCP, DCR'ı deprecate etti | Orta |
| RFC 8693 Token Exchange, `act` ve `may_act` | Delegasyonun tabanı | Orta |
| ID-JAG üretimi ve tüketimi | Artık farklılaşma değil, pariteyi koruma kalemidir: Okta Agent SSO 24 Ağustos 2026'da GA oldu ve IdP AS'in ID-JAG'ı *ürettiği* modu çekirdek SSO'ya dâhil etti. Keycloak hâlâ yalnızca tüketiyor. MCP Enterprise-Managed Authorization Stable statüsünde ve doğrudan ID-JAG'ı profilliyor | Orta |
| WebAuthn / passkey (`webauthn-rs`) | Ekosistemin en olgun bileşeni | Orta |
| SCIM 2.0 sunucu | En büyük iş kalemi; PATCH motorunu sağlayan crate bulunmuyor | Büyük |

### 4.2 Faz 2 — kurumsal

Sıra: SCIM → SAML → LDAP → OpenID Federation → Kerberos.

Efor: Faz 1 için 61-68 hafta; kurumsal paketin tamamı için yaklaşık 95 hafta. Her iki kalem de %30-40 sürekli interop bakımı gerektirir.

| Protokol | Kritik bulgu |
|---|---|
| SCIM | En büyük iş kalemi. PATCH motorunu sağlayan crate yok. Entra ve Okta çelişkili member-list davranışı bekliyor; 17 maddelik istemci başına tolerans katmanı gerekiyor |
| SAML | `bergshamra` saf Rust'ta XMLDSig sağlıyor ve xmlsec1'in kendi süitinden 1148/1151 geçiyor. Domain modeli kendimiz yazılır. Ayrı süreçte çalışır; gerekçe bellek güvenliği değil kaynak sınırlamasıdır |
| LDAP | Rust'ın en iyi konumlandığı protokol. `ldap3_proto` tam operasyon setini, paged results, sorting ve sync desteğini sağlıyor |
| OpenID Federation | Rust'ta mevcut bir implementasyon yok; en geniş farklılaşma alanı |
| Kerberos | C FFI kaçınılmaz. Microsoft kendi Kerberos SSO'sunu PRT lehine terk etti. En düşük öncelik |

> **Açık konu.** Salesforce, ServiceNow, Workday, AWS, Slack, Zoom ve Atlassian'ın SAML gereksinimleri doğrulanmamıştır. Faz 2 planlaması bu doğrulama yapılmadan kesinleştirilemez.

### 4.3 Faz 3 — ileri seviye ajan kimliği

İmzalı ve hop başına `delegation_chain`; `sub_profile` ve `agent_instance_id`; attestation tabanlı client auth; transaction token'ları; yürütme ortasında HITL soyutlaması; AuthZEN PDP; SCIM `/Agents`; A2A Agent Card imzalama servisi; federated credential vault.

---

## 5. Güvenlik mimarisi

### 5.1 Oturum modeli

Doğrulama katmanlıdır ve ağ turu gerektirmez:

```
JWT imza doğrulama          → public key bellekte
exp/nbf                     → token'ın içinde
session_epoch karşılaştırma → node-yerel cache
```

Sonuç: veritabanı tamamen erişilemez olsa dahi kaynak sunucuların mevcut token doğrulaması etkilenmez.

Epoch yayılımı transactional outbox ve 100-250 ms polling ile yapılır; `LISTEN/NOTIFY` kullanılmaz.

> **Açık karar — access token ömrü ve iptal sözleşmesi (bkz. 9.1).** Bu bölüm önceden uzun ömürlü access token ve sinyal güdümlü iptali kesin karar olarak bildiriyordu. §19 §7.2 ise degraded mode'un gerçek güvenlik sınırının access token ömrü olduğunu, bunun kısa token ömrünün en güçlü tek gerekçesi ve degraded mode tasarımının önkoşulu olduğunu belirtiyor. İki konum aynı anda savunulamaz; karar 9.1'de açık bırakılmıştır.
>
> Uzun ömür lehine kanıt: Microsoft, azaltılmış token ömürlerinin kullanıcı deneyimini ve güvenilirliği bozduğunu, buna karşılık riskleri ortadan kaldırmadığını raporlamıştır. Entra CAE 28 saatlik token ve yaklaşık 15 dakikalık yayılım kullanmaktadır.

Bearer varsayılan değildir. DPoP, mTLS-bound ve JWT-SVID kabulü birinci sınıftır. WIMSE'nin yönü açıktır: WIT spesifikasyonu ilgili token'ın bearer token olarak kullanılmamasını zorunlu kılar.

DBSC için arayüz hazırlanır, implementasyon yapılmaz. Windows'ta 28 Mayıs 2026 itibarıyla GA'dır ancak Firefox olumsuz standart pozisyonu bildirmiştir ve Rust crate'i bulunmamaktadır.

**Kimlik doğrulama sonucu tipli bir sözleşmedir.** Durum makinesi (karar 16) ile token üretimi arasındaki arayüz serbest bir claim haritası değil, tek bir tipli değerdir: hangi yöntem kullanıldı, hangi AAL'e ulaşıldı, hangi authenticator bağlandı, hangi kiracı bağlamı geçerli. Token üretimi yalnızca bu değeri okur ve kimlik doğrulama yolunun kendisine erişemez. İki kazanç vardır: §8 madde 6'daki `achieved_aal >= required_aal` kontrolü şema kısıtı olmanın yanında tip sistemine de girer, ve yol bağımlı claim sızıntısı yapısal olarak imkânsızlaşır. Desen yeni değildir — PingFederate'in adapter'dan token generator'a giden **policy contract**'ı ve AD FS'in üç aşamalı claims pipeline'ı (kabul, issuance authorization, issuance transform) aynı ayrımı yapar; ikisinin de ayrıntıları birincil kaynaktan doğrulanmamıştır.

**Sunucu tarafı oturum, browser akışları için varsayılandır.** Duende'nin modelinde çerez yalnızca bir oturum kimliği taşır; access ve refresh token sunucuda kalır, tarayıcıya hiç inmez. Argus'un hosted login'i ve admin konsolu karar 20 gereği zaten doğrudan session cookie kullanmaktadır; bu, aynı modelin Argus'un kendi yüzeyindeki hâlidir. Üçüncü taraf SPA'lar için önerilen desen BFF'tir (§4 §5, §21). Karar 20'nin gerekçesi RFC 10017 §7.1'dir; Duende'nin multi-frontend modeli aynı barındırıcıda frontend başına ayrı OIDC ve çerez ayarı tuttuğu için Argus'un kiracı başına upstream federation tasarımıyla birebir örtüşür.

**Kiracının token içeriğine müdahale sınırı tanımlıdır.** Clerk'in session JWT template'leri ve Kinde'nin feature flag claim'leri, kiracının token gövdesini şekillendirmesine izin verir; ikisi de birincil kaynaktan doğrulanmamıştır. Argus'ta sınır şudur: kiracı yalnızca **önceden tanımlı bir claim kümesinden seçim yapar**, serbest ifade veya şablon giremez. Gerekçe karar 19 ile aynıdır; token gövdesi de bir kod çalıştırma yüzeyidir ve claim adı çakışması protokol claim'lerini gölgeleyebilir. Rezerve claim adları (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `nbf`, `act`, `may_act`, `cnf`, `scope`, `client_id`) kiracıya kapalıdır.

### 5.2 Yetkilendirme

Cedar embed edilir, yeniden yazılmaz. Lean 4 ile doğrulanmış bir motorun terk edilmesi, kazanılmış tek maliyetsiz güvencenin terk edilmesi anlamına gelir.

ReBAC graf katmanı Cedar'ın üstünde, Zanzibar modeline göre kendimiz tarafından yazılır.

`authz_epoch` karar cache anahtarının parçasıdır; cache temizlenmez, adreslenemez hâle gelir.

İzin kaldırma işlemleri read replica'dan okunmaz. Replikasyon gecikmesi new-enemy penceresi üretir.

> **Not.** Literatürdeki 2,6 µs/karar değeri, 160 satırlık bir Python implementasyonunda HMAC caveat doğrulamasına aittir; ReBAC graf çözümlemesi değildir ve hedef olarak kullanılamaz.

### 5.3 Çok kiracılık

Model: satır bazlı izolasyon, RLS `FORCE`, `SET LOCAL` ve branded lifetimes.

Schema-per-tenant reddedilmiştir: 1.200 şemada 383 ms katalog taraması ve 2 saatlik göç ölçülmüştür.

`SET` değil `SET LOCAL` kullanılır; `SET` transaction pooling altında sızar.

Kiracı listesi düzdür; hiyerarşi kiracı içinde gruplarla kurulur. Zitadel, Auth0, Okta, Entra ve WorkOS iç içe kiracı modelini reddetmiştir. Frontegg uygulamış, miras yapısı JWT'ye sığmamıştır.

### 5.4 Kimlik doğrulama ve kurtarma

Kurtarma güvencesi kısıtı, "kurtarma yolu koruduğu şeyden zayıf olamaz" ilkesinin şema kısıtına çevrilmiş hâlidir ve duruma koşullu yazılır; koşulsuz hâli NULL değerlerde sessizce geçer (§22 §10.2). Kısıt tek başına yeterli değildir: yetki açan geçiş, kanıt doğrulama ve kanıt tüketimi ile aynı atomik işlemde gerçekleşmelidir.

`independence_group` alanı, aynı sync fabric üzerindeki iki passkey'in tek authenticator sayılmasını sağlar.

Hesabın efektif güvenliği tüm kurtarma yollarının AAL değerlerinin minimumudur ve admin konsolunda gösterilir.

Enumeration savunması dummy-Argon2 ile değil, Rauthy'nin çalışan ortalama padding'i ve sabit yanıt süresi tabanı ile yapılır. Dummy hash, 100 eşzamanlı istekte 6,4 GB tahsis ettirir ve NIST'in hesap kapsamlı throttling'i bu durumu yapısal olarak yakalamaz.

Kayıt akışında hesap, bant dışı onay kodu dönmeden yaratılmaz (WebAuthn §14.6.2). Tek kontrol dört gereksinimi birden karşılar.

**Admin bir kullanıcının credential'ını asla kendisi belirlemez.** Kurtarma yolundaki yönetici yetkisinin tavanı, Kanidm'in modelinden alınmıştır: yönetici yalnızca tek kullanımlık, kısa ömürlü bir **intent token** üretebilir; kullanıcı kendi credential'ını etkileşimli olarak kendisi kurar. Kanidm'de token varsayılan 1 saat, azami 24 saat geçerlidir ve reset commit edildiği anda kalıcı olarak geçersizleşir. Argus'ta bu bir ayrıcalık tavanıdır ve admin API yüzeyinde zorlanır (§24): `POST .../credential/reset-intent` vardır, credential'ı doğrudan yazan bir endpoint yoktur. Kazanç şudur — servis masasının ele geçirilmesi hesabın ele geçirilmesine dönüşmez, çünkü servis masası hiçbir noktada kullanıcının authenticator'ını seçemez. Ayrıntı ve state machine §22'dedir.

### 5.5 Kripto

Birincil kütüphane aws-lc-rs'tir: FIPS modu, ML-DSA ve s2n-bignum ispatları.

JWS `alg` beyaz listesinde `EdDSA` kabul edilmez; yalnızca `Ed25519` kabul edilir.

> **Bu bir Argus uyumluluk politikasıdır, standart zorunluluğu değildir.** RFC 9864 `EdDSA`'yı deprecate eder, yasaklamaz. Politikanın bedeli açıktır: yaygın JOSE kütüphanelerinin çoğu hâlâ `EdDSA` üretir, dolayısıyla politika `private_key_jwt` client assertion'larını, DPoP proof'larını ve request object'leri kırabilir. Güvenlik gerekçesi de zayıftır: doğrulamada anahtarın `crv` değeri zaten bilinir ve `alg` anahtarın eğrisine bağlanırsa belirsizlik kalmaz. `ES256` doğrudur ve deprecate edilmemiştir.

WebAuthn `pubKeyCredParams` listesine COSE tarafında `ESP256` ve `Ed25519` eklenir.

Veri modelinde `algorithm` alanı ve rotasyon yolu gün-1'de bulunur; ML-DSA geçişinde şema değişikliği gerekmemelidir.

Argon2 parametreleri: `m=7168, t=5, p=1`. Ölçümde `m=19456, t=2` konfigürasyonundan %16 daha ucuz ve daha iyi ölçeklenir durumdadır (dört iş parçacığında %87'ye karşı %69 verim). Keycloak aynı parametreleri kullanmaktadır.

Argon2 `spawn_blocking` içinde ve çekirdek sayısı mertebesinde bir semafor ile çalıştırılır. Bu konfigürasyon ek maliyet olmadan hem daha yüksek throughput hem 25× daha iyi p99 vermektedir. Kuyruk üst sınırı ve timeout aşıldığında 503 ile yük atma uygulanır.

### 5.6 Denetim logu

Model: düz append-only ve yaklaşık saniyede bir Merkle checkpoint. Olay başına zincir aynı koşullarda 3,8× yavaştır ve 8 bağlantı ile 1 bağlantı aynı throughput'u vermektedir; tek doğrusal zincirde seri bağımlılık bulunur.

> **Ölçüm statüsü: yeniden üretim bekliyor.** Bu bölümün dayandığı ölçüm 12 saniyelik pgbench koşumudur (Apple M4, Docker PostgreSQL 18.6, 8 bağlantı). Mutlak tps değerleri ürün iddiası değildir ve kapasite, maliyet veya rakip karşılaştırması için kullanılamaz (§6 §4.4). Taşınabilir olan yalnızca karşılaştırmalı orandır ve o da aynı etiketi taşır.

Bütünlük hash'i şifreli metin üzerinden hesaplanır; böylece crypto-shred sonrasında zincir doğrulanabilir kalır. Bütünlük ve gizlilik garantileri birbirinden ayrışır.

---

## 6. Formel doğrulama kapsamı

Kani'nin hedefi dört alandır: OAuth durum makinesi geçişleri, delegasyon zinciri değişmezleri, epoch karşılaştırma mantığı ve parser derinlik invariantları.

Async katman için formel bir iddia bulunmamaktadır. Bu katmanda `cargo-fuzz`, Shuttle (deterministik concurrency), `proptest` ve interop conformance süitleri kullanılır.

| | İfade |
|---|---|
| İzin verilen | Argus'un yetkilendirme çekirdeği ve protokol durum makinesi sınırlı model kontrolünden geçirilmiştir; kripto katmanı makine-kontrollü ispatlara sahip implementasyonlar kullanır; HTTP ve depolama katmanları fuzz ve deterministik concurrency testine tabidir. |
| İzin verilmeyen | Argus formel olarak doğrulanmıştır. |

---

## 7. Tarihli maddeler

| Tarih | Konu | Etki |
|---|---|---|
| 11 Aralık 2027 | EU Cyber Resilience Act, açık kaynak steward raporlaması | ENISA'nın ayrımına göre açık kaynak steward'ları raporlama yükümlülüklerine 11 Aralık 2027'de dahil olur. 11 Eylül 2026 tarihi manufacturer'lar için Madde 14'ün yürürlük tarihidir. Yapısal neden: steward'ları Madde 14'e bağlayan hüküm Madde 24(3)'tür ve Madde 24 ancak 11 Aralık 2027'de uygulanmaya başlar. Ayrıca arkasında tüzel kişi bulunmayan projelerde steward yükümlülüğü doğmaz ve monetize edilmeyen FOSS kapsam dışıdır |
| Açık | Android attestation kök rotasyonu | Android key attestation doğrulaması yapan kod hâlihazırda kırılmış olabilir — §21 §E.1 |
| Açık | Apple `private.icloud.com` | Haziran 2026 öncesinde kurulmuş e-posta allowlist'leri yeni Sign in with Apple kullanıcılarını sessizce reddediyor |
| Aralık 2026 | OAuth 2.1 IESG'ye sunuluyor | MCP hâlâ `draft-13`'e referans veriyor; güncel taslak `-16` |
| 2 Aralık 2027 | EU AI Act yüksek risk hükümleri (ertelendi, Reg. EU 2026/1744) | Dolaylı |

---

## 8. Farklılaşma alanları

Aşağıdaki liste, uygulanabilir olduğu değerlendirilen ve karşılaştırma kümesinde bulunmayan özellikleri içerir.

**Karşılaştırma kümesi.** Maddeler altı ürüne karşı sınanmıştır: Keycloak, Okta, Auth0, Entra ID, WorkOS ve Stytch. "Hiçbir üründe yok" ifadesi bu altı ürün için doğrulanmış, sektörün tamamı için doğrulanmamıştır. Ping ile ForgeRock, WSO2, Janssen, Kanidm, Duende, authentik, Zitadel, FusionAuth ve midPoint bu maddelerin 2-13 aralığına karşı **hâlâ sınanmamıştır**.

**Zorunlu alan.** Her maddenin, bölüm 9'un karar kaydı formatındaki gibi bir **hangi karşı örnek onu geçersiz kılar** alanı olmalıdır. Madde 1 bu alan doldurulmadığı için geçersizleşmesinden aylar sonra tabloda kalmıştır. Alan kalan 16 madde için doldurulmamıştır; 10. bölümdeki dokuzuncu açık iş budur.

| # | Farklılaşma | Mevcut durum |
|---|---|---|
| 1 | ID-JAG üretimi | **Farklılaşma düşmüştür.** Okta Agent SSO 24 Ağustos 2026'da GA oldu; Okta'nın IdP AS'i ID-JAG'ı kendisi üretiyor ve bu çekirdek SSO'ya dâhil, ek ücretsiz. Auth0 aynı yeteneği Temmuz 2026 sonunda erken erişime aldı. Keycloak'a göre üstünlük sürüyor, sektöre göre parite kalemi |
| 2 | DPoP, mTLS-bound ve JWT-SVID'in birinci sınıf desteği | İncelenen 15 halka açık issuer'ın hiçbiri DPoP ilan etmiyor |
| 3 | OpenID Federation | Rust'ta mevcut implementasyon yok |
| 4 | A2A Agent Card imzalama servisi (RFC 8785 JCS + JWS) | Hiçbir mainstream IdP sunmuyor; A2A ile SPIFFE arasındaki boşluğu dolduruyor |
| 5 | Branded lifetime ile derleme zamanı kiracı izolasyonu | Mekanizma olgun (3,99M indirme), çok kiracılığa uygulanmış yayımlanmış örnek bulunamadı |
| 6 | `achieved_aal >= required_aal` şema kısıtı | Hiçbir IdP kurtarma yolunun AAL değerini modellemiyor, dolayısıyla karşılaştırma da yapamıyor |
| 7 | `independence_group` ile sync fabric farkındalığı | NIST birden çok authenticator bağlanmasını öneriyor, bağımsızlığı ölçen bir ürün yok |
| 8 | Delege oturumda ayrıcalık kesişimi ve 12 invariant | En yakın örnekler WorkOS (4/12) ve ServiceNow (2/12) |
| 9 | Hash ve TOTP sırlarının self-servis dışa aktarımı | Yalnızca Keycloak TOTP sırlarını veriyor; her ikisini birden self-servis sunan ürün yok |
| 10 | Ön-hash ve pepper eklenebilir içe aktarım | `bcrypt(sha256(pw))` ve peppered hash'ler başka yolla göç edemiyor |
| 11 | `is_breakglass` alanının birinci sınıf, izinli ve alarmlı olması | Yalnızca Stytch'te mevcut, o da B2B'ye özgü |
| 12 | Son kimlik doğrulama yöntemi korumasının şemada olması | İncelenen dört üründe de uygulama katmanı sorumluluğunda |
| 13 | Kurtarma ve onboarding yeniden tetikleme oranının güvenlik metriği olarak izlenmesi | Unit 42'nin doğrudan tavsiyesi; hiçbir üründe uygulanmıyor |
| 14 | Tamper-evident denetim logu (Merkle checkpoint, imza, dış tanığa yayın) | Keycloak, veritabanı erişimi olan herkesin satırları değiştirebildiğini ve bunun uyum kanıtı için kabul edilemez olduğunu belirtiyor. Okta, Auth0 ve Entra bütünlük garantisi sunmuyor |
| 15 | `Idempotency-Key` desteğinin tüm mutating endpoint'lerde bulunması | Okta, Auth0 ve Entra desteklemiyor. WorkOS tek endpoint'te destekliyor, diğerlerinde header'ı sessizce yutup dedup yapmıyor |
| 16 | Uzun sıcak denetim penceresi | Hiçbir büyük IdP PCI'ın 12 aylık gereksinimini kendi içinde karşılamıyor: Okta 90 gün, Entra P1/P2 30 gün, Auth0 Starter 1 gün |
| 17 | Denetim logunun request path'inde bulunmaması | Keycloak'ta login isteği event insert'ini bekliyor |


---

## 9. Açık kararlar

Bu bölümdeki kararlar iki bağımsız inceleme turu sonunda açık bırakılmıştır. Buradaki "açık", ertelenmiş değil, kanıtı henüz bulunmayan ve uygulanabilir algoritması henüz yazılmamış anlamındadır. Bu bölümdeki maddeler kapatılmadan ilgili bileşenin implementasyonuna başlanmaz; crate iskeleti ve I/O içermeyen çekirdek bundan bağımsız ilerleyebilir.

**Karar kaydı alanları.** Her karar satırı şunları taşır: kimlik, statü, gerekçe, geçerlilik koşulu, kabul testi, kararı geçersiz kılacak karşı örnek veya test sonucu, kaynak bölüm.

Son alan bu turun çıktısıdır; her iki incelemenin de yanıldığı noktalar tam olarak bu alanın boş olduğu yerlerdi.

**Statüler:** kalıcı kimlik sözleşmesi, kabul edilmiş yön, doğrulanacak hipotez, ertelenmiş karar.

### 9.1 Açık — iptal ve bayatlık sözleşmesi

**Açık kalma nedeni.** 5.1 uzun ömürlü access token ve sinyal güdümlü iptali seçiyordu; §19 §7.2 ise degraded mode'un gerçek güvenlik sınırının access token ömrü olduğunu belirterek kısa ömrü önkoşul hâline getiriyor. İki konum aynı anda savunulamaz.

**Terminoloji.** Aşağıdakiler profil değil doğrulama yollarıdır. İzin verilen bayatlık, her yol için ayrı tanımlanan bir koşuldur.

Tablo boş bir alan değil, bir birleştirme işidir. Hücrelerin çoğunun karşılığı belgede mevcuttur: §19 §4.5 (negatif cache kuralı), §19 §7.1 (kesinti matrisi), §19 §7.2 (degraded mode pencereleri), §26 (operatör davranışı). Sorun bu bilgilerin eksik veya çelişkili olması ve tek tutarlı bir sözleşmede birleştirilmemiş olmasıdır. Birleştirme mevcut bilgi yok sayılmadan yapılacaktır. `—` işareti ilgili yol için uygulanamaz anlamına gelir, bilinmiyor anlamına gelmez.

| Doğrulama yolu | İptal bilgisi cache miss | Partition | Restart | Azami bayatlık |
|---|---|---|---|---|
| Argus içi — login | Birleştirilecek (§19 §7.1: DB düştüğünde 503) | Birleştirilecek | Birleştirilecek | Birleştirilecek |
| Argus içi — refresh | Birleştirilecek (§19 §7.1: 503 + `Retry-After`, `invalid_grant` değil) | Birleştirilecek | Birleştirilecek | Birleştirilecek |
| Argus içi — introspection | Birleştirilecek (§19 §4.5 ile §19 §7.2 çatışıyor) | Birleştirilecek | Birleştirilecek | Birleştirilecek |
| Salt-JWT doğrulayan RS (sinyal tüketmez) | — İptal bilgisi cache'i yoktur; RS'in tuttuğu JWKS anahtar cache'idir, iptal durumu değil | Birleştirilecek | Birleştirilecek | ≈ access token ömrü (§19 §7.2) |
| Sinyal tüketen RS (SSF/CAEP) | Birleştirilecek | Birleştirilecek | Birleştirilecek | Birleştirilecek |

> **Neden üç ayrı satır.** Login, refresh ve introspection aynı Argus yüzeyindedir ancak aynı kesinti davranışına sahip değildir; §19 §7.1 üçünü zaten farklı sütunlarda gösterir. Ayrıca salt-JWT doğrulayan RS'de epoch cache miss uygulanabilir bir kavram değildir; anahtar cache'i ile iptal bilgisi ayrı tutulmalıdır, aksi hâlde JWKS tazeliği iptal tazeliğiyle karıştırılır.

**Kapatılması gereken bilinen boşluk.** §19 §4.5'in "cache miss durumunda mutlaka veritabanına sorulur" kuralı ile §19 §7.2'nin degraded mode'u doğrudan çatışmaktadır. Veritabanı erişilemezken cache'te hiç bulunmayan bir kullanıcı için 60/300 saniyelik zaman penceresi anlamsızdır; bu kullanıcı için derhal fail-closed davranılmalıdır. Zaman tabanlı pencere, "cache bayat" ile "cache bu kullanıcıyı hiç görmedi" durumlarını ayırmamaktadır.

**Geçersiz kılma koşulu.** "Veritabanı düşse dahi doğrulama sürer" ile "iptal en geç 250 ms içinde uygulanır" garantilerinin aynı yolda birlikte verilmesi.

### 9.2 Açık — outbox teslimat algoritması

**Açık kalma nedeni.** §19 §4.3'ün seçtiği "son 5 saniyeyi yeniden tara" çözümü doğruluk sağlamamaktadır ve önerilen iki alternatif henüz tamamlanmış algoritma değildir.

**Kaldırılan yaklaşım.** Beş saniyelik pencere doğruluk mekanizması olmaktan çıkarılmıştır. PostgreSQL'de `now()` transaction başlangıç zamanını döndürdüğünden pencerenin azami transaction süresinden büyük olması gerekir; bu süre sınırsızdır. Pencere en fazla bir hızlandırıcı olabilir, doğruluk kaynağı olamaz.

#### Aday A — xid watermark üzerinden ilerleme (polling)

Statü: aday, doğruluk iddiası yok.

Taslak: her turda `pg_snapshot_xmin(pg_current_snapshot())` alınır; transaction kimliği `[önceki_watermark, yeni_xmin)` aralığında olan satırlar işlenir; watermark yeni xmin'e taşınır.

**Sequence cursor'unun neden kullanılamadığı.** Bu kısım kesindir. MVCC altında commit etmemiş bir transaction'ın outbox satırı görünmez, dolayısıyla uçuştaki xid'e ait en düşük seq değeri tablodan hesaplanamaz. Sequence tabanlı cursor kuralları — beş saniyelik pencere dahil — bu nedenle uygulanabilir değildir. Bu tespit adayın kendisini doğrulamaz, yalnızca terk edilen yolu kapatır.

**Doğruluk iddiası kurulmadan önce kapatılması gerekenler.** Bu liste kapanmadan A ile B karşılaştırılamaz.

*Kimlik alanı.* İki seçenek bulunmaktadır: satırın sistem sütunu `xmin`, veya şemaya eklenen açık bir transaction kimliği kolonu (`pg_current_xact_id()` ile yazılan `xid8`).

> **Değerlendirme (3. tur, bu belgenin kendi çıkarımı; dış incelemede yer almadı).** Kanıt tek yönü göstermektedir. Sistem sütunları indekslenemez; `xmin` üzerinden aralık taraması planlayıcı için seq scan anlamına gelir ve bu, 20 node'dan 100-250 ms aralıklarla koşan bir sorguda kabul edilemez (§19 §4.3). Açık `xid8` kolonu indekslenebilir ve aşağıdaki sarma ile subtransaction maddelerini de düşürür; ancak yalnızca üst seviye transaction kimliği tutulursa:
>
> ```sql
> producer_xid xid8 NOT NULL DEFAULT pg_current_xact_id()
> ```
>
> `xid8` önde gelen adaydır, seçilmiş algoritma değildir.

Karar öncesinde şu dört konu açıktır:

1. Aynı transaction'daki birden fazla olayın aynı `xid8` değerini taşıması; sıralama ve idempotency buna göre tanımlanmalıdır.
2. Watermark aralığının yarı açık sınır semantiği (`[önceki, yeni)`); sınırda çift işleme veya atlama olmadığı ispatlanmalıdır.
3. Uzun transaction'ın ilerlemeyi durdurması; sonuç 9.1'in azami bayatlık hücresine yazılır.
4. Watermark ve retention durumunun her tüketici için kalıcılaştırılması; bellekte tutulursa restart'ta tüketici ilerlemesi ile yeniden üretilebilir durum arasında boşluk doğar.

*Subtransaction'lar.* Savepoint veya `EXCEPTION` bloğu içinde yazılan satır bir subxid taşır. Subxid ile üst transaction'ın xid'i arasındaki ilişki ve `xmin` sınırına göre görünürlüğü ayrıca tanımlanmalıdır.

*Satır güncellemesi.* Bu madde açık soru değil, şema kısıtıdır. Sistem sütunu `xmin` satırı en son yazan transaction'ı gösterir; outbox satırı `UPDATE` edilirse ekleme sırası kaybolur. Çözüm belgede mevcuttur: §25 §7 K7'nin append-only deseni (`REVOKE UPDATE, DELETE` ile `BEFORE UPDATE OR DELETE` ve `BEFORE TRUNCATE` trigger'ları) outbox tablosuna da uygulanır. Madde "değerlendirilecek" değil "şemada zorlanacak" olarak işaretlenmiştir.

*Snapshot tutarlılığı.* Watermark ilerletme ile satır okuma aynı snapshot'ta yapılmazsa aralık kayabilir; `REPEATABLE READ` veya tek sorgu gerekir.

*Sorgulama maliyeti.* 100-250 ms aralıklarla ve 20 node'dan koşan bir sorgunun maliyeti ölçülmeden kabul edilemez.

*Sarma.* 4 baytlık `xmin` ile 8 baytlık `xid8` arasında epoch dönüşümü gerekir.

*Bilinen ve kaçınılmaz bedel.* Tek bir uzun transaction watermark'ı dondurur ve bu doğrudan iptal gecikmesine yazılır; 9.1'deki azami bayatlık hücresini etkiler.

#### Aday B — logical decoding (replication slot)

Akış tanım gereği commit sırasındadır, dolayısıyla sequence ile commit arasındaki uyumsuzluk yapısal olarak ortadan kalkar. Cursor dayanıklıdır (`confirmed_flush_lsn`) ve node belleğinde tutulmaz.

Dayanıklı slot, dayanıklı cache anlamına gelmez: tüketici olayı alıp yalnızca bellekteki cache'e uygular, ilerlemeyi bildirir ve ardından sonlanırsa slot ilerlemiş ancak cache boş kalır.

**Restart prosedürü: kısmen açık.** İlk kurulumda çözüm bilinmektedir; slot oluşturulurken dışa aktarılan tutarlı snapshot'tan başlangıç durumu kurulur ve akış tam o noktadan devralınır. Mevcut bir slot üzerinden yeniden başlamak aynı operasyon değildir: var olan bir slota yeniden bağlanmak yeni bir snapshot vermez, yalnızca bildirilen konumdan akışı sürdürür.

> **Daraltma (3. tur, bu belgenin kendi çıkarımı; dış incelemede yer almadı).** Bu boşluk göründüğünden dardır. Argus'un iptal cache'i saf türetilmiş bir cache'tir ve §19 §4.5 soğuk başlangıcı zaten tanımlar: cache boşaltılır ve "cache miss durumunda mutlaka veritabanına sorulur" moduyla ısınır. Durum kaybolduğunda yeniden kurulma yolu mevcuttur ve slot'tan bağımsızdır; snapshot ve slot koordinasyonu doğruluk için değil, yalnızca ısınma maliyetinden kaçınmak için gereklidir.
>
> Daraltma koşulsuz değildir. Cache ancak aşağıdaki dört koşul birlikte sağlandığında saf türetilmiş veri olur; sağlanmazsa eski slot konumunun öncesindeki olaylara gerçekten ihtiyaç doğar ve boşluk yeniden açılır.
>
> 1. Cache miss primary veritabanına gider, replica'ya değil (§19 §4.5 negatif cache kuralı).
> 2. Veritabanı erişilemiyorsa fail-closed davranılır; bilinmeyen için "iptal edilmemiş" varsayılmaz.
> 3. Node, readiness ilan etmeden istek almaz.
> 4. Epoch uygulaması monotondur; yeniden teslimat veya sıra dışı olay değeri geri almaz.
>
> Bu dört koşul sağlandığında eksik değer her zaman veritabanından çekilebilir ve restart prosedürünün açık kısmı 9.1'e taşınır. Geriye kalan tek açık konu, restart'ın veritabanı erişilemezliğiyle çakışmasıdır; bu durumda birinci koşulun dayandığı fallback de bulunmaz. Bu, 9.1'in cache miss × partition hücresidir, 9.2'nin konusu değildir.

Yeni bir snapshot ve slot kurulacaksa aşağıdakiler tarif edilmelidir; hiçbiri henüz yazılmamıştır:

- Eski slotun devreden çıkarılma noktası ve sırası: önce yeni slot mu, önce eski mi.
- İki slot arasındaki değişikliklerin hangi tarafça kapsandığı.
- Tüketicinin readiness koşulu: hangi anda durumun güncel sayılacağı ve o ana kadar iptal kontrolünün nasıl davranacağı (fail-closed veya veritabanına sorma).
- Eski slotun WAL biriktirme sınırı (`idle_replication_slot_timeout`, §19 kaynak 19).

Diğer bedeller: tek slot tek tüketiciye hizmet eder (N node için N slot veya ayrı bir dağıtıcı gerekir); failover'da slot senkronizasyonu gerekir; `streaming` açıkken commit etmemiş parçalar gelir ve tüketici `stream_abort` semantiğini doğru işlemelidir.

#### Ortak arıza matrisi

Her iki aday aynı matriste sınanacaktır; karşılaştırma bundan önce yapılmaz.

| # | Senaryo |
|---|---|
| 1 | Ters commit sırası: geç açılan transaction erken commit eder |
| 2 | Uzun süren tek transaction: ilerleme durur, iptal gecikmesine etkisi ölçülür |
| 3 | Tüketici retention penceresinden (24 saat) uzun süre düşer, yeniden senkronizasyon gerekir |
| 4 | Tüketici restart: ilerleme ile yeniden üretilebilir durum arasında boşluk oluşuyor mu |
| 5 | Failover: slot veya cursor durumu hayatta kalıyor mu |
| 6 | Çoklu tüketici ve çok node yayılımı |

**Sınanacak değişmez.** Tüketici ilerlemesi ile tüketicinin yeniden oluşturabildiği durum arasında boşluk bulunmamalıdır.

**Geçersiz kılma koşulu.** Altı senaryodan herhangi birinde kaçırılmış iptal üretilebiliyorsa aday elenir.

> **Bölümün statüsü.** Bölüm 9 mimari yönleri kayda geçirir; outbox'ın doğruluğunu veya iptal sürelerini kanıtlamaz. Her iki aday da bugün aday statüsündedir ve aralarında seçim yapılmamıştır. Sıradaki teknik iş iki adımdır ve sırayla yürütülür: (1) 9.1'deki doğrulama yollarının arıza sözleşmesini mevcut bölümlerden birleştirerek doldurmak, (2) iki outbox adayını ortak matriste sınamak. Bu ikisi tamamlanmadan 9.2'de karar satırı yazılmaz.

### 9.3 Kabul edilmiş yönler

| # | Karar | Statü | Kabul testi |
|---|---|---|---|
| A1 | Denetim olayı iş değişikliğiyle atomik minimal kayıt olarak yazılır; Merkle, imza ve egress arka planda yürür (1.1 #23) | Kabul edilmiş yön | Commit sonrası `SIGKILL` verildiğinde kayıt yeniden işlenebiliyor |
| A2 | Kurtarma iptali ile oturum iptali ayrı eylemlerdir (§22 §10.1) | Kabul edilmiş yön | `DENIED` geçişi tek başına oturum düşürmüyor |
| A3 | Yetki açan geçişte durum, kanıt doğrulama ve kanıt tüketimi aynı atomik işlemdedir (§22 §10.2) | Kabul edilmiş yön | Aynı kanıtla paralel iki `REBIND_OPEN` denemesi başarısız oluyor |
| A4 | Origin, issuer ve RP ID yaşam döngüleri ayrı modellenir (§23 §5.3) | Kabul edilmiş yön | Custom domain eklendiğinde eski RP ID ve ROR ile giriş sürüyor |
| A5 | Benchmark değerleri yeniden üretim bekliyor etiketi taşır; mutlak sayılar ürün iddiası değildir (§6 §4.4) | Kabul | Kod, ham çıktı ve komut repoda mevcut |
| A6 | Yetkilendirme v1: primary üzerinde tek tutarlı snapshot (`REPEATABLE READ` veya tek sorgu), aynı transaction'da epoch artışı ve sonucun snapshot epoch'uyla etiketlenmesi | Kabul edilmiş başlangıç modeli | Yeni epoch altında eski veriyle karar cache'lenemiyor |

> **A6'nın açık kalan parçası.** `READ COMMITTED` altında ardışık sorgular farklı snapshot görür; "aynı transaction" ifadesi tek başına yeterli değildir. Ayrıca uçuşta olan bir kararın hangi anda geçerli sayıldığı tanımlı değildir: cache'e hiç yazılmadan doğrudan çağırana dönen bir karar, epoch anahtar karşılaştırmasının kapsamı dışında kalır. "İptal commit olduktan sonra hiçbir eski karar kullanılamaz" garantisi yalnızca cache karşılaştırmasından türetilemez. Replica'ya çıkıldığında sürüm veya LSN bariyeri gerekecektir; v1'de gerekmemektedir.

Bölüm 9'un dışında kalan ertelenmiş ve açık kararlar: iptal sözleşmesi 9.1'dedir, outbox teslimatı 9.2'dedir. Denetim kuyruğu (karar 23) 9.3 A1 ile kapanmış ve bölüm 1'in tablosuna girmiştir.

> **Kural.** "Yayımlanmış bir örnek bulunamadı" ifadesi "Argus bunu ilk yapan olacak" sonucuna dönüştürülmez. İkincisi ayrı bir iddiadır ve ayrı kanıt gerektirir.

---

## 10. Çözülmemiş konular

Bu doküman aşağıdaki konuları kapatmamaktadır.

1. **SAML gereksinim doğrulaması.** Salesforce, ServiceNow, Workday, AWS, Slack, Zoom ve Atlassian'ın SAML gereksinimleri doğrulanmamıştır. Faz 2 planı bu doğrulama olmadan kesinleştirilemez.
2. **x86-64'te Argon2.** `argon2` crate'i ile `libargon2` (AVX2/AVX-512, `-march=native`) arasındaki fark ölçülmemiştir. Fark %20'yi geçerse FFI'ye geçiş değerlendirilmelidir. Bu, ilk performans işlerinden biri olmalıdır.
3. **Ölçüm boşlukları.** 34 maddelik liste: allocator, PGO ve io_uring; Postgres bağlantı eğrisi; PgBouncer prepared statement davranışı; ML-DSA hızları.
4. **`bergshamra` bağımlılık riski.** Tek geliştiricili, 0.9.0 sürümünde ve sürüm ile dokümantasyon arasında tutarsızlık bulunuyor. Test süitinin bir kopyası kendi CI'ımızda koşmalıdır.
5. **IdP tarafı SAML doğruluk süiti.** Olgun bir kamu süiti bulunmamaktadır. `italia/spid-saml-check` SP'leri test eder; IdP karşılığı olan `AgID/spid-saml-check-idp` 4 yıldız ve 51 commit'e sahiptir, Docker desteği yoktur.
6. **Ajanın veri modelindeki yeri.** Ajan, `users` tablosunun bir varyantı mı yoksa ayrı bir birinci sınıf varlık mıdır? FusionAuth'un entity/grant grafiği ikincisini yapar ve tip listesinde "AI agent" açıkça geçer; bu model §20'nin ilişki demeti modeliyle de tutarlıdır. Soru bir **kalıcı kimlik sözleşmesidir** ve bu nedenle gün-1'e aittir, ancak §1'de karara bağlanmamıştır. Analiz §15'tedir.
7. **Kiracı konfigürasyonunun kod olarak yönetilmesi.** Şema göçü karar 26 ile çözülmüştür; kiracı konfigürasyonunun (client, redirect_uri, upstream IdP bağlantısı, politika) bildirimsel bir kaynaktan uzlaştırılması çözülmemiştir. authentik'in blueprint modeli çalışan bir örnektir ancak 60 dakikalık yeniden uygulama döngüsü, admin UI'dan yapılan bir değişikliği sessizce geri alır; bir IdP'de bu güvenlik sonucu olan bir davranıştır. Çakışma semantiği tanımlanmadan benimsenemez. Analiz §24 ve §26'dadır.
8. **Journey modelinin güvenlik kaydı.** Karar 16'nın gerekçesi tek bir Keycloak hatasına (#40744) dayanmaktadır. Ping ile ForgeRock'un on yıllık journey ürününün aynı hata sınıfını üretip üretmediği incelenmemiştir. Bu, kararın bilinen en güçlü karşı örneğidir ve araştırılmadan karar "doğrulanmış" sayılamaz.
9. **§8 maddelerinin geniş ürün kümesine karşı sınanması.** Farklılaşma tablosunun 2-13 aralığı yalnızca altı ürüne karşı test edilmiştir. Madde 1 bu darlık yüzünden yanlış işaretlenmişti (§8'deki 5. tur notu). Kalan maddeler için aynı hatanın tekrarlanmadığı gösterilmemiştir.

Araştırmanın altı boyutu tamamlanmıştır; yukarıdaki dokuz madde kapanmamış konuların tamamını oluşturur. Maddeler 6-9, 13 Eylül 2026 tarihli IdP manzara taramasından gelmektedir.

---

## 11. Doküman haritası

Dizinin tamamı ve taşıma kuralları için `README.md` dosyasına bakınız.

| § | Dosya | Satır | İçerik |
|---|---|---|---|
| §1 | `01-architecture-decisions.md` | — | Mimari kararlar (bu dosya) |
| §2 | `02-contradictions-and-resolutions.md` | 236 | Raporlar arası beş çelişkinin çözümü |
| §3 | `03-p0-critical-findings.md` | 387 | Acil ve öncelikli bulgular |
| §4 | `04-identity-authentication-reference.md` | 1.597 | Kimlik ve kimlik doğrulama alan referansı |
| §5 | `05-rust-ecosystem.md` | 394 | Rust fizibilitesi, crate envanteri, efor tahmini |
| §6 | `06-performance.md` | 732 | Ölçümler, Argon2, audit log, darboğazlar |
| §7 | `07-verified-cryptography.md` | 879 | HACL*, fiat-crypto, s2n-bignum |
| §8 | `08-side-channels.md` | 804 | Sabit zaman, Marvin, timeless timing |
| §9 | `09-key-management.md` | 1.297 | PKCS#11/HSM, KMS, rotasyon |
| §10 | `10-formal-verification.md` | 1.375 | Kani, Verus, Cedar + Lean 4 |
| §11 | `11-runtime-hardening.md` | 1.926 | Binary hardening, izolasyon, fuzzing |
| §12 | `12-supply-chain.md` | 1.490 | cargo-vet, cargo-deny, cargo-audit, SBOM |
| §13 | `13-security-process.md` | 192 | Tehdit modelleme, VDP, CVE süreci |
| §14 | `14-mcp-authorization.md` | 1.148 | MCP authorization referansı |
| §15 | `15-agent-identity.md` | 1.017 | Ajan kimliği: IETF, MCP, endüstri, düzenleme |
| §16 | `16-enterprise-protocols.md` | 2.019 | SAML, SCIM, LDAP, Kerberos, OpenID Federation |
| §17 | `17-future-standards.md` | 1.607 | PQC, WebAuthn L3, CTAP 2.3, TLS |
| §18 | `18-multi-tenancy.md` | 1.304 | RLS, izolasyon, 14 gün-1 kararı |
| §19 | `19-high-availability.md` | 1.304 | HA topolojisi, epoch, PostgreSQL, kademeli bozulma |
| §20 | `20-authorization-engine.md` | 1.603 | Zanzibar, Cedar, OpenFGA, ReBAC |
| §21 | `21-session-security.md` | 1.242 | DBSC, SSF/CAEP, DPoP, AiTM, donanım attestation |
| §22 | `22-account-lifecycle.md` | 3.031 | Kurtarma, bağlama, impersonation, silme, kayıt, göç, B2B |
| §23 | `23-login-flows.md` | 636 | Identifier-first, passkey UX, MFA, hosted ve embedded, markalama, erişilebilirlik |
| §24 | `24-admin-api.md` | 675 | Admin API tasarımı, delege yönetim, ayrıcalık yükseltme CVE'leri, GitOps, bulk |
| §25 | `25-observability.md` | 801 | OCSF, tamper-evidence, katmanlama, Rust OTel yığını, SSF/CAEP yayını |
| §26 | `26-deployment-operations.md` | 777 | Kurulum, konteyner ve K8s, şema göçü, yedekleme, boyutlandırma, lisans, CRA |
| §27 | `27-test-strategy.md` | 673 | Conformance süitleri, interop, yük, kaos ve DST, güvenlik testi, CI bütçesi |

§7 ile §13 arası birlikte güvenlik mühendisliği kümesini oluşturur: doğrulanmış kripto, yan kanal, anahtar yönetimi, formel doğrulama, sertleştirme, tedarik zinciri ve güvenlik süreci. Bu küme için ayrı bir giriş dosyası bulunmamaktadır.