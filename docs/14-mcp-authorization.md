# §14 — MCP yetkilendirme

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

**Kapsam.** Argus'un MCP ekosisteminde hem Authorization Server hem Resource Server olarak çalışması için gereken her şey.

**Yöntem.** Spesifikasyon metinleri modelcontextprotocol.io üzerinden ham markdown olarak okunmuş, RFC'ler rfc-editor.org'dan alınmış, IETF durumları Datatracker'dan doğrulanmış ve sağlayıcı CIMD dokümanları canlı çekilmiştir. Blog özetleriyle yetinilmemiştir.

> **Doğrulama notu.** Bu dosyadaki her iddia bir birincil kaynağa dayanmaktadır. Doğrulanamayan noktalar 17. bölümde açıkça listelenmiştir. Rakam veya iddia uydurulmamıştır.

---

## 1. Yönetici özeti, on kritik bulgu

1. **Yürürlükteki revizyon 2026-07-28'dir.** Eylül 2026 itibarıyla daha yenisi yoktur. `/specification/draft/` sayfası mevcuttur ancak normalize edilmiş diff sonucunda 2026-07-28 ile birebir aynıdır; yalnızca URL yolları farklıdır. `/specification/latest` adresi 2026-07-28'e yönlenmektedir.

2. **DCR resmen kullanımdan kaldırılmıştır** (PR #2858) ve yerine CIMD gelmiştir. Geriye uyumluluk penceresi 2027-07-28 veya sonrasında yayımlanacak ilk revizyona kadardır; SEP-2596 uyarınca en az 12 aydır.

3. **Kritik uyumsuzluk.** MCP spesifikasyonu CIMD taslağının -00 revizyonuna atıf yapmaktadır. IETF'te güncel revizyon -02'dir (6 Temmuz 2026) ve -02, -00'da olmayan normatif MUST'lar getirmiştir. -02 uygulanmalıdır; 5.2'ye bakınız.

4. **RFC 9207 `iss` parametresi** AS için hâlâ SHOULD seviyesindedir, ancak spesifikasyon açıkça gelecek revizyonda MUST'a yükseltilmesinin beklendiğini söylemektedir. Bugünden MUST gibi uygulanmalıdır.

5. **`cacheScope` gizlenmiş bir yetkilendirme kararıdır.** Yalnızca `"public"` ve `"private"` değerlerini alır. Token'a göre filtrelenen bir liste `"public"` işaretlenirse, spesifikasyonun kendi ifadesiyle protokolce onaylanmış bir çapraz kiracı sızıntısı oluşur; 10. bölüme bakınız.

6. **Stateless çekirdek**, token doğrulamayı her POST isteğinde zorunlu kılmaktadır. `Mcp-Session-Id` kaldırılmış ve aynı mantıksal oturum muafiyeti spesifikasyon metninden silinmiştir. Principal'ı asacak bir oturum nesnesi yoktur.

7. **`requestState` saldırgan kontrollü bir girdidir** ve spesifikasyon bunu MUST seviyesinde söylemektedir: bütünlük koruması (HMAC veya AEAD) ile kimliği doğrulanmış principal'a bağlama zorunludur.

8. **Rust'ta büyük bir boşluk vardır.** Resmî `rmcp` v3.2.0'ın OAuth desteği yalnızca istemci tarafındadır. Rust'ta olgun ve genel amaçlı bir OAuth 2.1 Authorization Server crate'i yoktur. Argus'un en güçlü gerekçesi budur.

9. **Onay problemi RFC 8707 ile çözülmemektedir.** Confused deputy'nin çözümü istemci başına onay kaydıdır. Gerçek dünyada en çok istismar edilen açık budur.

10. **Resmî bir conformance çatısı vardır ve `auth` süiti içermektedir:** github.com/modelcontextprotocol/conformance. Kabul testi harness'ımız bu olmalıdır.

**Stratejik sinyal.** TypeScript SDK'sının `main` dalında tüm Authorization Server implementasyonu, yani `mcpAuthRouter`, authorize, token, register ile revoke handler'ları, `middleware/{bearerAuth,clientAuth}` ve `providers/proxyProvider.ts`, `packages/server-legacy/` paketine taşınmıştır. Yeni `packages/server/` paketi yalnızca `middleware/oauthMetadata.ts` dosyasını tutmaktadır.

> SDK, authorization server işinden çıkmakta ve yalnızca resource server metadata'sını tutmaktadır. Argus gibi ayrı bir AS ürünü doğru bahistir.

---

## 2. Spesifikasyon durumu ve kapsam

| Öğe | Değer |
|---|---|
| Yürürlükteki revizyon | 2026-07-28 |
| Bir önceki | 2025-11-25; CIMD bu revizyonda gelmiştir, SEP-991 |
| Yetkilendirme | MCP için OPTIONAL'dır |
| HTTP transport | Bu spesifikasyona SHOULD uymalıdır |
| STDIO transport | Bu spesifikasyonu SHOULD NOT takip etmelidir; kimlik bilgilerini ortamdan almalıdır |
| Diğer transport'lar | Kendi protokollerinin güvenlik en iyi uygulamalarını MUST takip etmelidir |

**Referans standartlar.** OAuth 2.1 (`draft-ietf-oauth-v2-1-13`), RFC 6750, RFC 8414, RFC 7591 (kullanımdan kaldırılmıştır), RFC 8707, RFC 9728, RFC 9207, CIMD (-00), OIDC Discovery 1.0 ile OIDC Dynamic Client Registration 1.0.

> **Spesifikasyon gecikmesi uyarısı.** MCP, `draft-ietf-oauth-v2-1-13` (Ekim 2025) ile `client-id-metadata-document-00` belgelerine referans vermektedir. Güncel sürümler -16 ve -02'dir. MCP, OAuth'u üç revizyon geriden takip etmektedir.

---

## 3. Authorization Server için normatif gereksinimler

### 3.1 MUST

| # | Gereksinim | Kaynak bölüm |
|---|---|---|
| AS-M1 | OAuth 2.1'i hem confidential hem public istemciler için uygun güvenlik önlemleriyle implemente etmelidir | Overview §1 |
| AS-M2 | Şu keşif mekanizmalarından en az birini sağlamalıdır: RFC 8414 AS Metadata veya OIDC Discovery 1.0 | Overview §5 |
| AS-M3 | `iss` yayınlıyorsa metadata'sında `authorization_response_iss_parameter_supported: true` ilan etmelidir | Authorization Response Validation |
| AS-M4 | Tüm AS endpoint'leri HTTPS üzerinden sunulmalıdır | Communication Security |
| AS-M5 | Tüm redirect URI'ler ya `localhost` ya HTTPS olmalıdır | Communication Security |
| AS-M6 | Redirect URI'leri ön kayıtlı değerlerle tam eşleşme ile doğrulamalıdır | Open Redirection |
| AS-M7 | Kullanıcı aracısını güvenilmeyen URI'lere yönlendirmemek için önlem almalıdır, OAuth 2.1 §7.12.2 | Open Redirection |
| AS-M8 | Public istemciler için refresh token'ları rotate etmelidir | Token Theft |
| AS-M9 | OIDC Discovery sunuyorsa `code_challenge_methods_supported` alanını metadata'ya dahil etmelidir | Authorization Code Protection |
| AS-M10 | CIMD destekliyorsa CIMD §6 güvenlik implikasyonlarını dikkate almalıdır | CIMD Security |
| AS-M11 | CIMD'de getirilen dokümanın `client_id` değeri URL ile tam eşleşmelidir | Client Registration |
| AS-M12 | CIMD'de authorization isteğindeki `redirect_uri` değerini metadata dokümanındakilere karşı doğrulamalıdır | Client Registration |
| AS-M13 | CIMD'de doküman yapısının geçerli JSON olduğunu ve zorunlu alanları içerdiğini doğrulamalıdır | Client Registration |
| AS-M14 | CIMD'de yetkilendirme sırasında redirect URI hostname'ini açıkça göstermelidir | Localhost Redirect URI Risks |
| AS-M15 | Proxy AS'ler için: statik istemci kimliği kullanan MCP proxy sunucuları, üçüncü taraf AS'e yönlendirmeden önce her dinamik kayıtlı istemci için kullanıcı onayı almalıdır | Confused Deputy |

### 3.2 SHOULD ve MAY

| # | Seviye | Gereksinim |
|---|---|---|
| AS-S1 | SHOULD | CIMD desteklemelidir |
| AS-S2 | SHOULD | Authorization yanıtlarında, hata yanıtları dahil, `iss` içermelidir, RFC 9207 §2 |
| AS-S3 | SHOULD | Kısa ömürlü access token üretmelidir |
| AS-S4 | SHOULD | URL formatlı `client_id` gördüğünde metadata dokümanını getirmelidir |
| AS-S5 | SHOULD | Metadata'yı HTTP cache başlıklarına saygı göstererek önbelleklemelidir |
| AS-S6 | SHOULD | CIMD §6 güvenlik değerlendirmelerini takip etmelidir |
| AS-S7 | SHOULD | Metadata getirirken SSRF risklerini dikkate almalıdır |
| AS-S8 | SHOULD | Yalnızca `localhost` redirect URI'si olan istemciler için ek uyarı göstermelidir |
| AS-S9 | SHOULD | Yalnızca güvendiği redirect URI'lerine otomatik yönlendirme yapmalıdır |
| AS-A1 | MAY | DCR, yani RFC 7591; kullanımdan kaldırılmıştır, yalnızca geriye uyumluluk içindir |
| AS-A2 | MAY | CIMD kabulü için alan adı tabanlı bir güven politikası uygulayabilir |
| AS-A3 | MAY | Ek attestation mekanizmaları isteyebilir |

### 3.3 RFC 8707 hakkında önemli nüans

Spesifikasyon, AS'in RFC 8707'yi desteklemesini hiçbir yerde MUST yapmamaktadır. MUST'lar istemciye (`resource` gönder) ve RS'e (audience doğrula) düşmektedir. Metin "when the Authorization Server supports the capability" demektedir.

Ancak RS audience doğrulamak zorunda olduğu için, pratikte AS'in RFC 8707 desteği fiilen zorunludur; desteklemezseniz ekosistemde çalışmazsınız.

> Sınıflandırma şudur: bu bir spesifikasyon MUST'ı değil, bir pazar MUST'ıdır.

---

## 4. Resource Server için normatif gereksinimler

### 4.1 MUST

| # | Gereksinim |
|---|---|
| RS-M1 | RFC 9728 Protected Resource Metadata implemente etmelidir |
| RS-M2 | PRM dokümanı en az bir AS içeren `authorization_servers` alanını içermelidir |
| RS-M3 | Keşif mekanizmalarından birini implemente etmelidir: 401 yanıtında `WWW-Authenticate: Bearer resource_metadata="…"` ya da well-known URI'de metadata |
| RS-M4 | Access token'ları OAuth 2.1 §5.2'ye göre doğrulamalıdır |
| RS-M5 | Token'ların kendisi için üretildiğini doğrulamalıdır, RFC 8707 §2 |
| RS-M6 | Geçersiz veya süresi dolmuş token'lara HTTP 401 dönmelidir |
| RS-M7 | Yalnızca kendi kaynakları için geçerli token'ları kabul etmelidir |
| RS-M8 | Başka hiçbir token'ı kabul etmemeli veya transit ettirmemelidir |
| RS-M9 | İsteği işlemeden önce token doğrulamalıdır |
| RS-M10 | Upstream API çağırıyorsa istemcinin token'ını olduğu gibi geçirmemelidir |
| RS-M11 | Scope hiyerarşilerini hesaba katmalıdır; geniş scope dar olanı kapsar |
| RS-M12 | Tüm gelen istekleri doğrulamalıdır; bir state handle'a sahip olmayı kimlik doğrulaması saymamalıdır |
| RS-M13 | `requestState` saldırgan kontrollü girdi olarak ele alınmalıdır; yetkilendirmeyi etkiliyorsa bütünlüğü korunmalı (HMAC veya AEAD) ve doğrulaması başarısız olan state reddedilmelidir |
| RS-M14 | Başlık değerleri gövdedeki karşılıklarıyla uyuşmuyorsa reddedilmelidir: 400 ile `-32020 HeaderMismatch` |
| RS-M15 | `Origin` başlığı mevcut ve geçersizse 403 Forbidden dönmelidir |
| RS-M16 | Sayfalı listelerde tüm sayfalara aynı `cacheScope` uygulanmalıdır |
| RS-M17 | Primitif başına erişim kontrolü uygulanmalıdır; `cacheScope`'a tek başına güvenilmemelidir |
| RS-M18 | `ttlMs` değeri sıfır veya daha büyük olmalıdır |
| RS-M19 | Bir sonraki istek için önceki isteklere dayalı bağlam çıkarılmamalıdır |

### 4.2 SHOULD

`WWW-Authenticate` başlığında `scope` parametresiyle gerekli scope'lar belirtilmelidir, RFC 6750 §3.

Yetersiz scope durumunda 403 Forbidden ile birlikte `error="insufficient_scope"`, `scope="…"` ve `resource_metadata` dönülmelidir.

Bir operasyon için gereken tüm scope'lar tek bir challenge'da verilmelidir; artımlı challenge kullanıcı deneyimini bozar.

Scope dahil etme stratejisinde tutarlı olunmalıdır.

`offline_access` değeri `WWW-Authenticate` scope'una veya PRM `scopes_supported` alanına dahil edilmemelidir (SHOULD NOT); refresh token bir kaynak gereksinimi değildir.

State handle'lar kriptografik olarak güvenli bir rastgele üreteçle üretilmeli ve sunucu tarafında kimliği doğrulanmış kullanıcıya bağlanmalıdır; biçim `<user_id>:<handle>` olur ve kullanıcı kimliği doğrulanmış token'dan türetilmelidir.

Tool'lar deterministik sırada döndürülmelidir; bu önbellek verimliliği içindir.

---

## 5. Client ID Metadata Documents

### 5.1 IETF durumu

| Öğe | Değer |
|---|---|
| Güncel revizyon | draft-ietf-oauth-client-id-metadata-document-02 |
| Yayın | 6 Temmuz 2026; sona erme 7 Ocak 2027; 20 sayfa |
| Yazarlar | Aaron Parecki (Okta), Emelia Smith |
| Çalışma grubu durumu | WG Document, kabul edilmiştir; WGLC'de değildir, IESG'de değildir |
| RFC numarası | Yoktur |

Geçmişi şöyledir: bireysel `draft-parecki-*` -00 ile -03 arası (Temmuz 2024'ten Temmuz 2025'e), 8 Ekim 2025'te çalışma grubu kabulü, WG -00 (12 sayfa), -01 (1 Mart 2026, 14 sayfa) ve -02 (6 Temmuz 2026, 20 sayfa).

### 5.2 -00 ile -02 farkı, bu dosyanın en operasyonel bulgusu

MCP 2026-07-28 normatif olarak -00'a atıf yapmaktadır. -02'nin getirdiği ve -00'da bulunmayan normatif kurallar şunlardır.

| -02'deki yeni kural | Seviye |
|---|---|
| Özel amaçlı IP adreslerine (RFC 6890) getirme yasaktır | MUST NOT |
| HTTP yönlendirmeleri otomatik takip edilmez | MUST NOT |
| Yanıt 200 OK olmalıdır; diğer tüm durum kodları hatadır | MUST |
| Simetrik sır tabanlı `token_endpoint_auth_method` yasaktır | MUST NOT |
| `client_secret` ile `client_secret_expires_at` yasaktır | MUST NOT |
| Özel anahtar materyali yasaktır; yalnızca public key olur | MUST NOT |
| Basit string karşılaştırması yapılır, port normalizasyonu yoktur | MUST |
| Privacy Considerations bölümü (§9) | Yenidir |

Bölüm numaraları da kaymıştır: MCP'nin -00 §6 ile -00 §6.2 atıfları -02'de §8 ve §8.2'ye karşılık gelmektedir.

Uçuşta olan düzeltmeler PR #3235 "Use updated OAuth Client ID Metadata Document RFC" (12 Ağustos 2026, açık) ile SEP-3149 "Require Token Endpoint Auth Methods Supported in CIMD"dir (28 Temmuz 2026, açık).

> **Karar.** -02 implemente edilir ve -00 uyumluluğu belgelenir. -02'nin MUST'ları katı bir üst kümedir; -00'a göre daha güvenlidir ve gelecekteki MCP revizyonuyla uyumlu olacaktır.

### 5.3 Client Identifier URL kuralları

`https` şeması MUST'tır. userinfo bileşeni MUST NOT'tur. Port MAY'dir. Path bileşeni MUST'tır: `https://example.com` geçersiz, `https://example.com/client.json` geçerlidir. Tek nokta ve çift nokta path bileşenleri MUST NOT'tur. Query bileşeni SHOULD NOT'tur. Fragment MUST NOT'tur.

Karşılaştırma basit string karşılaştırmasıdır (RFC 3986 §6.2.1): `https://example.com/client` ile `https://example.com:443/client` eşdeğer değildir.

Ek rehberlik şöyledir: kısa URL önerilir, çünkü kullanıcıya gösterilebilir; kararlı URL önerilir; URL kısaltıcılar uygun değildir, çünkü yönlendirme kullanırlar; `https://example.com/` gibi çıplak bir eğik çizgi path'i önerilmez.

`localhost` bir Client Identifier URL'i olarak kullanılamaz; https zorunluluğu ile §8.6'daki özel amaçlı IP yasağı bunu engeller. Asimetriye dikkat edilmelidir: `redirect_uris` içinde `http://localhost:3000/callback` sorunsuzdur, yasak olan `client_id` URL'inin kendisidir.

### 5.4 Metadata doküman şeması

Taslak bir alan listesi vermemekte, toptan RFC 7591'e devretmektedir: "The client metadata values are the values defined in the OAuth Dynamic Client Registration Metadata OAuth Parameters registry … as established by [RFC7591]."

Tek açıkça zorunlu alan §4'te tanımlanmıştır: "The Client ID Metadata Document MUST contain a `client_id` property whose value MUST match the Client Identifier URL, which MUST also match the URL that the authorization server used to fetch the document; comparisons MUST be made using simple string comparison."

`redirect_uris` dolaylı olarak zorunludur; §4.2 üzerinden RFC 9700'e dayanır. Yönlendirme içermeyen grant'lar, yani client_credentials ile token exchange, muaftır.

MCP'nin ek şartı şudur: doküman en az `client_id`, `client_name` ve `redirect_uris` içermelidir.

AS metadata alanı `client_id_metadata_document_supported`'tır ve boolean'dır.

> **Editoryal tutarsızlık.** -02'de §6 "AS MUST include" derken IANA kaydı alanı OPTIONAL tanımlamaktadır. Alanın yokluğu "bilinmiyor" olarak değil "desteklenmiyor" olarak yorumlanmalıdır.

Açık bir TBD maddesi vardır: "We may want a property such as `client_id_expires_at` for indicating that the client is ephemeral."

### 5.5 AS doğrulama gereksinimleri

**Getirme.** AS metadata dokümanını otomatik getirmeli ve periyodik olarak yeniden getirmelidir (SHOULD). Doküman 200 OK ile sunulmalıdır; diğer tüm HTTP durum kodları hata sayılmalıdır (MUST). AS, HTTP yönlendirmelerini otomatik takip etmemelidir (MUST NOT).

**Doğrulama sırası.** Önce HTTP 200 kontrol edilir. Sonra yönlendirmenin takip edilmediği doğrulanır. Sonra dokümandaki `client_id` değerinin Client Identifier URL'ine ve fiilen getirilen URL'e basit string karşılaştırmasıyla eşit olduğu doğrulanır. Son olarak authorization isteğindeki `redirect_uri`, dokümandaki kayıtlı yönlendirme URL'lerinden biriyle tam string eşleşmesi yapmalıdır.

Getirme başarısız olursa §5.1 uyarınca AS authorization isteğini iptal etmelidir; bu SHOULD seviyesindedir, MUST değildir.

> **En büyük interop tuzağı.** Origin veya önek eşleştirmesi açıkça zorunlu değildir. §8.1, AS'in `redirect_uri` değerini CIMD ile aynı origin'e kısıtlayabileceğini söylemektedir, ancak bu opsiyoneldir ve Solid-OIDC geriye uyumluluğu içindir. Aynı doküman bir AS'te çalışıp diğerinde reddedilebilir.

Taslakta açıkça bulunmayanlar, yani varsayılmaması gerekenler şunlardır: HTTP metodu (GET ima edilmekte ancak yazılmamaktadır), Accept başlığı şartı, TLS sürümü ile sertifika doğrulama şartı, zaman aşımı, hız sınırlama ve User-Agent rehberliği. İçerik türü ifadesi muğlaktır; taban çizgisi olarak `application/json` şartı hiç belirtilmemiştir.

### 5.6 Önbellekleme

§5.2'nin tam metni şudur:

> "The authorization server MAY cache the client metadata it discovers at the Client ID Metadata Document URL.
> The authorization server SHOULD respect HTTP cache headers [RFC9111] when caching client metadata, but MAY define its own upper and/or lower bounds on an acceptable cache lifetime as well.
> The authorization server MUST NOT cache error responses. The authorization server also MUST NOT cache documents which are invalid or malformed."

Varsayılan TTL yoktur, ETag ile yeniden doğrulama rehberliği yoktur, stale-while-revalidate yoktur. §8.8 `logo_uri` içeriğinin önceden getirilip önbelleklenmesini önermektedir. §9.1 her istekte getirmenin kullanıcı aktivite zamanlamasını istemcinin sunucusuna sızdırdığını belirtmektedir.

### 5.7 Güvenlik, SSRF ve hizmet reddi

§8.6 SSRF bölümün en güçlü normatif metnidir:

> "Authorization servers MUST NOT fetch a Client ID Metadata Document URL or any URLs contained within a Client ID Metadata Document that resolve to special-use IP addresses as defined in [RFC6890]."
>
> "Authorization servers deployed for development or testing purposes MAY relax this restriction to allow fetching from loopback addresses when the authorization server itself is also running on a loopback address … Authorization servers MUST NOT apply this exception in production deployments…"
>
> "Authorization servers SHOULD ensure they only fetch or parse URLs with known and supported URI schemes … if a client uses a URI scheme such as `javascript:` in a metadata property."

Kritik nokta şudur: RFC 6890 kuralı yalnızca `client_id` URL'ini değil, doküman içindeki URL'leri de kapsar; `jwks_uri`, `logo_uri`, `policy_uri` ve `tos_uri` dahildir.

§8.7 azami yanıt boyutunu düzenler: "authorization servers SHOULD limit the amount of data they read and process … The recommended maximum size to read is 5 kilobytes." -02 changelog notuna göre sınır dosya boyutuna değil okunan veri miktarına uygulanır; yani `Content-Length` değerine güvenilmez, okuma kesilir.

Diğer §8 maddeleri şunlardır. §8.1, `redirect_uri` ile `client_id` ilişkisini ele alır: kısıtlama opsiyoneldir ve kısıtlama olmadan bir istemcinin daha tanınmış bir istemciyi taklit etmesi mümkündür. §8.2 istemci kimlik doğrulamasını ele alır: simetrik sır imkânsızdır; `private_key_jwt` bildirilirse AS, RFC 7523 §2.2 uyarınca istemci kimlik doğrulamasını zorunlu kılmalıdır; attestation tabanlı istemci kimlik doğrulaması ile SPIFFE istemci kimlik doğrulaması taslaklarına referans verilmektedir. §8.3 Client Identifier URL değişimini ele alır: değişen URL tamamen yeni bir istemcidir ve "loss of control over the URL — for example through domain expiry or reassignment — would allow a third party to assume the client's identity" denmektedir. §8.4 metadata değişimini ele alır: dokümanlar istemci kontrolündedir ve değişebilir; AS, `redirect_uris`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks`, `client_name` veya `logo_uri` değiştiğinde mevcut grant'ları geçersiz kılmayı ya da yeniden onay istemeyi seçebilir. §8.5 oltalamayı ele alır: AS, `client_id` hostname'ini authorization arayüzünde göstermelidir. §8.9 alan adı güvenini ele alır: ilk 100 kullanıcı için ek uyarı ekranı, alan adı itibarı ile yaş kontrolleri ve `*.example.com` biçiminde allowlist'ler önerilir. §8.10 CIMD servislerini ele alır: barındırılan bir CIMD servisi statik istemci kaydı vekili gibi davranır ve bu tür istemciler kullanıcıya görsel olarak ayırt ettirilmelidir. §9 gizlilik bölümü -02'de yenidir: AS getirmeleri kullanıcı aktivitesini sızdıran bir yan kanaldır ve `logo_uri` ile `jwks_uri` çapraz alan adı izleme fırsatı yaratır.

§8'de hiç ele alınmayanlar şunlardır: AS'in istemci sunucusuna karşı hizmet reddi ve amplifikasyon, getirme hız sınırı, zaman aşımı, eşzamanlılık sınırı ve metadata önbellek zehirlenmesi. Bunlar tamamen implementasyon sorumluluğundadır.

### 5.8 MCP'nin CIMD için ek SSRF rehberliği

MCP güvenlik en iyi uygulamaları taslağın boşluklarını kapatmaktadır.

HTTPS zorunludur; loopback yalnızca geliştirmede ve açık bir devre dışı bırakmayla kullanılır. Engellenecek aralıklar `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, bulut metadata'sı için `169.254.0.0/16`, `fc00::/7` ve `fe80::/10`'dur. Spesifikasyonun kendi uyarısı şudur: "Avoid implementing IP validation manually. Attackers exploit encoding tricks (octal, hex, IPv4-mapped IPv6) that custom parsers often miss." Yönlendirme hedefleri aynı doğrulamaya tabidir. Çıkış vekili kullanılmalıdır; Stripe'ın Smokescreen'i isim olarak verilmektedir. DNS için kontrol ile kullanım arası zaman farkı sorunu şöyle ifade edilmektedir: "An attacker's domain may resolve to a safe IP during validation but to an internal IP during the actual request. Consider pinning DNS resolution results between check and use."

### 5.9 CIMD ile DCR karşılaştırması

**CIMD'nin çözdükleri.** Sınırsız istemci kaydı yoktur; AS hiçbir şey yazmaz ve kimlik bir URL'dir. Kayıt endpoint'i kaynaklı hizmet reddi yüzeyi yoktur. Kimlik AS'ler arasında taşınabilirdir: "No re-registration is needed when the authorization server changes." Kimlik alan adı kontrolüne demirlenmiştir, dolayısıyla denetlenebilirdir ve itibar anlamlıdır. Paylaşılan sır yoktur; confidential istemci yolu `private_key_jwt` ile yayımlanmış JWKS'tir.

**CIMD'nin getirdiği yeni problemler.** Dışa doğru getirme AS'te bir SSRF yüzeyidir; DCR'da dışa doğru getirme yoktur. Kimlik değişkendir, çünkü metadata istemci kontrolündedir ve onaydan sonra değişebilir. Erişilebilirlik bağımlılığı vardır: her yetkilendirme üçüncü taraf bir HTTPS sunucusunun ayakta olmasına bağlı olabilir. Alan adı ömrü riski vardır: alan adı süresi dolarsa istemci kimliği onu satın alana geçer. Taklit ve oltalama çözülmemiştir, çünkü aynı origin `redirect_uri` zorunluluğu opsiyoneldir. Bir gizlilik yan kanalı vardır. Yerel geliştirmeye düşmandır, çünkü localhost `client_id` olamaz. İstemci sunucusuna okuma amplifikasyonu taslakta hiç ele alınmamıştır.

### 5.10 DCR neden terk edildi

Kaynak blog.modelcontextprotocol.io/posts/client_registration/ adresindeki 22 Ağustos 2025 tarihli yazıdır; yazarı çekirdek bakımcı Paul Carleton'dır.

AS'ler için gerekçeler şunlardır. Sınırsız veritabanı büyümesi vardır, çünkü kayıtlar taşınabilir değildir; Claude Desktop'ı önce Windows'ta sonra macOS'ta kullanmak iki ayrı kayıt yaratır. İstemcinin süresinin dolması bir kara deliktir: bir istemciye kimliğinin geçersiz olduğunu açık yönlendirme açığı yaratmadan söylemenin yolu yoktur. Örnek başına karmaşa vardır: aynı uygulama için hiçbir mantıklı sebep olmadan yüzlerce hatta binlerce kayıt oluşur. Hizmet reddi vardır, çünkü kimlik doğrulamasız bir `/register` endpoint'i AS veritabanına yazar.

Sayısal gerçeklik ikincil bir kaynaktandır ve doğrulanmamıştır: Obsidian Security taramasında 660 AS'ten yalnızca 27'si, yani %4'ü, DCR desteklemekteydi; 78'den yalnızca üçü CIMD desteklemekteydi.

### 5.11 İstemci kayıt öncelik sırası

1. Sunucu için ön kayıtlı istemci bilgisi varsa o kullanılır.
2. AS metadata'sında `client_id_metadata_document_supported: true` varsa CIMD kullanılır.
3. AS'te `registration_endpoint` varsa DCR yedek olarak kullanılır.
4. Başka seçenek yoksa kullanıcıya sorulur.

---

## 6. RFC 9728, Protected Resource Metadata

### 6.1 Alanların tamamı

| Alan | RFC seviyesi | MCP notu |
|---|---|---|
| `resource` | REQUIRED | Kanonik MCP sunucu URI'sidir; RFC 8707 `resource` ile hizalı olmalıdır |
| `authorization_servers` | RFC'de OPTIONAL | MCP'de MUST'tır ve en az bir eleman içermelidir |
| `jwks_uri` | OPTIONAL | RS'in kendi imza anahtarlarıdır, yani yanıt imzalama içindir; token doğrulama anahtarları değildir. HTTPS zorunludur |
| `scopes_supported` | RECOMMENDED | MCP'ye göre temel işlevsellik için gereken minimal scope kümesidir, tüm katalog değildir |
| `bearer_methods_supported` | OPTIONAL | `["header"]`, `["body"]` veya `["query"]` olabilir. MCP query'yi yasakladığı için pratikte `["header"]` olur |
| `resource_signing_alg_values_supported` | OPTIONAL | `none` değeri MUST NOT'tur |
| `resource_name` | RECOMMENDED | Son kullanıcıya gösterilecek isimdir |
| `resource_documentation` | OPTIONAL | — |
| `resource_policy_uri` | OPTIONAL | — |
| `resource_tos_uri` | OPTIONAL | — |
| `tls_client_certificate_bound_access_tokens` | OPTIONAL, varsayılan `false` | mTLS'e bağlı token, RFC 8705 |
| `authorization_details_types_supported` | OPTIONAL | Zengin yetkilendirme istekleri, RFC 9396 |
| `dpop_signing_alg_values_supported` | OPTIONAL | Yol haritasında DPoP vardır, planlanmalıdır |
| `dpop_bound_access_tokens_required` | OPTIONAL, varsayılan `false` | — |
| `signed_metadata` | OPTIONAL, §2.2 | JWS ile imzalı metadata |

`resource_name`, `resource_documentation`, `resource_policy_uri` ve `resource_tos_uri` alanları BCP 47 dil etiketiyle çoğullanabilir; örneğin `resource_name#tr-TR`.

### 6.2 Well-known URI oluşturma

Well-known string'i host bileşeni ile path ve query arasına eklenir.

| Kaynak tanımlayıcısı | Metadata URL'i |
|---|---|
| `https://mcp.example.com` | `https://mcp.example.com/.well-known/oauth-protected-resource` |
| `https://mcp.example.com/mcp` | `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` |
| `https://example.com/public/mcp` | `https://example.com/.well-known/oauth-protected-resource/public/mcp` |

Host'tan sonraki sonlandırıcı eğik çizgi, ekleme yapılmadan önce kaldırılmalıdır (MUST). Sorgu HTTP GET ile yapılmalıdır (MUST). Başarılı yanıt 200 OK ve `application/json` olmalıdır.

Bu `.well-known` kullanımı RFC 8615'ten farklıdır: host hakkında genel bilgi vermez, host başına birden fazla kaynağı desteklemek içindir, yani çok kiracılıdır.

İstemcinin yedekleme sırası şudur: önce `WWW-Authenticate` başlığındaki `resource_metadata`, sonra alt path well-known, en son kök well-known.

### 6.3 RFC 9728 güvenlik notları

§7.3 taklit konusunda şunu söyler: istemci, metadata'daki `resource` değerinin kullandığı kaynak tanımlayıcısıyla tam eşleştiğini doğrulamalıdır (MUST).

§7.4 audience kısıtlı token'lar ile RFC 8707'yi önermektedir. Aksi hâlde kötü niyetli bir RS1, istemciyi RS2'nin scope'uyla token almaya ikna edip o token'ı RS2'de yeniden kullanabilir.

§7.6 PRM'deki `authorization_servers` listesi ile AS metadata'sındaki kaynak listesinin çapraz kontrol edilmesini ister.

§7.7 SSRF için istemcilerin iç IP aralıklarına istek göndermeyi engellemesini önerir.

§7.10 `Cache-Control: max-age` kullanımını önerir.

---

## 7. RFC 8707, Resource Indicators

### 7.1 `resource` parametresi kuralları

Değer mutlak bir URI olmalıdır (RFC 3986 §4.3). Fragment bileşeni içermemelidir (MUST NOT). Query bileşeni içermemelidir (SHOULD NOT), ancak uygulamayı kapsamlandırmak için gerekli olabileceği kabul edilmektedir. Birden fazla `resource` parametresi kullanılabilir. Hata kodu `invalid_target`'tır.

### 7.2 AS'in yükümlülüğü

Spesifikasyon şunu söyler: "The authorization server SHOULD audience-restrict issued access tokens to the resource(s) indicated by the `resource` parameter."

Bu bilgi JWT'de `aud` claim'iyle, introspection'da (RFC 7662) aynı isimli üst düzey üyeyle iletilir. AS, `resource` değerini aynen audience olarak kullanabilir veya daha genel bir URI'ye eşleyebilir. İstemci `resource` göndermezse AS belirli bir kaynak olmadan veya varsayılan bir kaynakla işleyebilir; alternatif olarak zorunlu kılabilir.

### 7.3 MCP kanonik URI kuralları

Geçerli olanlar `https://mcp.example.com/mcp`, `https://mcp.example.com`, `https://mcp.example.com:8443` ile `https://mcp.example.com/server/mcp`'tir. Geçersiz olanlar şema içermeyen `mcp.example.com` ile fragment içeren `https://mcp.example.com#fragment`'tir.

İstemci mümkün olan en spesifik URI'yi vermelidir (SHOULD). Kanonik biçim küçük harfli şema ve host kullanır, ancak implementasyonlar sağlamlık için büyük harf kabul etmelidir (SHOULD). Sonlandırıcı eğik çizgisiz biçim tercih edilmelidir (SHOULD).

> **Tasarım kararı.** AS'te `resource` değerleri kayıtlı korunan kaynaklara karşı doğrulanır ve bilinmeyenler için `invalid_target` dönülür. Aksi hâlde AS, keyfi audience'lı token üreten bir oracle'a dönüşür.

---

## 8. RFC 9207 ve `iss` doğrulaması, SEP-2468

Kısa cevap şudur: AS için SHOULD, istemci için MUST.

SEP-2468 "Recommend Issuer (iss) Parameter in MCP Auth Responses" Final statüsünde ve Standards Track'tedir; 25 Mart 2026, yazarı @EmLauber, sponsoru @pcarleton, PR numarası 2468'dir.

AS için ifade şudur: "MCP authorization servers SHOULD include the `iss` parameter in authorization responses, including error responses." AS, `iss` yayınlıyorsa `authorization_response_iss_parameter_supported: true` ilan etmelidir (MUST). İstemci RFC 9207 §2.4 doğrulamasını uygulamalıdır (MUST).

**İstemci karar tablosu.**

| `authorization_response_iss_parameter_supported` | Yanıtta `iss` | İstemci davranışı |
|---|---|---|
| `true` | Vardır | Kaydedilen issuer ile basit string karşılaştırması yapar, RFC 3986 §6.2.1 |
| `true` | Yoktur | Reddeder |
| `false` veya yok | Vardır | Kaydedilen issuer ile karşılaştırır, yerel politikaya göre |
| `false` veya yok | Yoktur | Devam eder |

Kritik karşılaştırma kuralı şudur: istemciler `iss` değerini çözdükten sonra şema ile host için büyük küçük harf katlaması, varsayılan port atlaması, sonlandırıcı eğik çizgi veya yüzde kodlama normalizasyonu uygulamamalıdır (MUST NOT).

> **Sonuç.** AS'imiz metadata'daki `issuer` ile bayt bayt özdeş bir `iss` yayınlamalıdır. `https://as.example.com` ile `https://as.example.com/` farklı sayılır.

Spesifikasyonun mix-up saldırıları hakkındaki dürüst uyarısı şudur: "PKCE alone does not prevent this attack because the client transmits the `code_verifier` to the attacker's token endpoint. Resource indicators do not help when the attacker's authorization server is intercepting requests before they hit the honest authorization server. This mitigation depends on honest authorization servers emitting `iss`; it provides no protection against an honest server that does not."

> `iss` yayınlamazsak bizimle konuşan her istemci mix-up saldırısına açık kalır.

Gelecek için spesifikasyon şunu söylemektedir: "A future revision of this specification is expected to upgrade authorization server inclusion of `iss` from SHOULD to MUST."

Neden issuer başına redirect URI değil de `iss` seçildiği sorusuna SEP-2468'in gerekçesi cevap vermektedir: benzersiz redirect URI'ler CIMD ile mümkün değildir ve DCR ile operasyonel olarak pahalıdır.

---

## 9. `application_type` ve loopback yönlendirmesi, SEP-837

SEP-837 "Update authorization spec to clarify client type requirements", @localden, PR #837, 24 Haziran 2025'te açılmış ve 28 Temmuz 2026'da inmiştir. SEP-1850 öncesi olduğu için ayrı bir SEP sayfası yoktur; statüsü merged'dır.

### 9.1 Sorun

OIDC DCR'da `application_type` atlanırsa varsayılan `"web"`tir. OIDC, `"web"` istemcileri için yönlendirme URI'lerinin HTTPS olmasını ve localhost olmamasını şart koşar. MCP istemcilerinin çoğu yerel veya komut satırı uygulaması olduğu ve `http://localhost:PORT/callback` kullandığı için kayıt sessizce reddedilir.

### 9.2 Çözüm

İstemciler DCR sırasında uygun `application_type` değerini belirtmelidir (MUST). Yerel uygulamalar, yani masaüstü, mobil, komut satırı ve localhost üzerinden erişilen yerel web uygulamaları, `"native"` kullanmalıdır (SHOULD). Uzak tarayıcı tabanlı olanlar `"web"` kullanmalıdır (SHOULD). İstemciler yönlendirme URI kısıtlarından kaynaklanan kayıt hatalarını ele alabilmelidir (MUST) ve anlamlı hata yüzeye çıkarılmalıdır (SHOULD). OIDC olmayan sunucular parametreyi güvenle yok sayar.

### 9.3 Kapsam sınırı ve gerçek dünya

`application_type` gereksinimi spesifikasyonda yalnızca DCR bölümünün altındadır ve CIMD için bir zorunluluk yoktur. Ancak pratikte gerekmektedir:

```json
// https://vscode.dev/oauth/client-metadata.json (8 Eylül 2026'da çekildi)
{
  "client_name": "Visual Studio Code",
  "application_type": "native",
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code","refresh_token",
                  "urn:ietf:params:oauth:grant-type:device_code"],
  "redirect_uris": ["http://127.0.0.1:33418/", "https://vscode.dev/redirect"],
  "client_id": "https://vscode.dev/oauth/client-metadata.json"
}
```

> AS'imiz CIMD dokümanlarında da `application_type` alanını okuyup dikkate almalıdır.

### 9.4 Loopback port eşleştirmesi, kritik interop kuralı

```json
// https://claude.ai/oauth/claude-code-client-metadata (8 Eylül 2026'da çekildi)
{
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "client_name": "Claude Code",
  "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
  "grant_types": ["authorization_code","refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

Claude Code yönlendirme URI'lerini portsuz bildirmekte ve çalışma zamanında `http://localhost:3118/callback` gibi geçici bir porta bağlanmaktadır. Anthropic dokümantasyonunun ifadesi şudur: "your authorization server must accept both with the port component ignored. RFC 8252 section 7.3 requires this for the IP-literal form (`127.0.0.1`); apply the same port-agnostic match to `localhost` so Claude Code works, even though RFC 8252 section 8.3 discourages `localhost`."

Bu, CIMD -02'nin basit string karşılaştırması ve tam eşleşme kuralıyla doğrudan çelişmektedir.

> **Karar: loopback yönlendirme URI'leri için özel eşleştirme kuralı.** Şema, host ve path tam eşleşmelidir. Host `localhost`, `127.0.0.1` veya `[::1]` ise port bileşeni yok sayılmalıdır. Loopback olmayan URI'lerde hiçbir gevşetme yapılmamalıdır.

---

## 10. Stateless çekirdek ve `cacheScope`

### 10.1 Ne değişti, SEP-2575 ile SEP-2567

`initialize` ile `notifications/initialized` kaldırılmıştır.

`Mcp-Session-Id` başlığı kaldırılmıştır. Modern sunucu eski trafiğe şöyle davranmalıdır: "ignore it, and do not mint or echo session IDs." HTTP GET ile DELETE isteklerine 405 dönülür. `Last-Event-ID` yok sayılır ve stream'ler devam ettirilebilir değildir.

Her istek `_meta` içinde protokol sürümünü ve istemci yeteneklerini taşır: `io.modelcontextprotocol/protocolVersion` (zorunlu), `io.modelcontextprotocol/clientCapabilities` (zorunlu) ve `io.modelcontextprotocol/clientInfo` (opsiyonel).

`server/discover` eklenmiştir ve sunucular bunu implemente etmelidir (MUST).

Spesifikasyon metni şunu söyler: "Servers MUST NOT rely on prior requests over the same connection to establish context (e.g., capabilities, protocol version, client identity)."

### 10.2 Yetkilendirmeye doğrudan etkisi

2025-11-25 metni şöyleydi: "authorization MUST be included in every HTTP request from client to server, even if they are part of the same logical session."

2026-07-28 metni şöyledir: "authorization MUST be included in every HTTP request from client to server."

Aynı mantıksal oturum kaçış kapısı silinmiştir, çünkü artık oturum yoktur.

> **Pratik sonuç.** Principal'ı asacak bir oturum nesnesi kalmamıştır. Her POST bağımsız, kendi kendini tanımlayan ve bağımsız yetkilendirilebilir bir birimdir.

`clientInfo` ile `serverInfo` güvenlik için kullanılamaz: "self-reported by the sender and are not verified by the protocol… SHOULD NOT rely on them for security decisions." Aynı şekilde `clientCapabilities` her istekte istemci tarafından iddia edilir; bu bir özellik pazarlığı girdisidir, kimlik doğrulama girdisi değildir.

### 10.3 State Handle Hijacking, yeni saldırı sınıfı

Bu başlık Session Hijacking bölümünün yerini almıştır. Saldırı şöyle işler. Sunucu kimliği doğrulanmış bir kullanıcı için state handle üretir ve tool sonucunda döner. Saldırgan handle'ı ele geçirir veya tahmin eder. Saldırgan handle'ı tool argümanı olarak geçer. Sunucu handle'ın çağırana ait olup olmadığını kontrol etmezse yetkisiz erişim doğar.

Azaltmaları şunlardır. Sunucular tüm gelen istekleri doğrulamalıdır (MUST). Bir state handle'a sahip olmak kimlik doğrulaması sayılmamalıdır (MUST NOT). Handle'lar kriptografik olarak güvenli rastgele üreteçle, deterministik olmayan biçimde üretilmelidir (SHOULD). Handle'lar sunucu tarafında kimliği doğrulanmış kullanıcıya bağlanmalıdır; biçim `<user_id>:<handle>` olur ve kullanıcı kimliği doğrulanmış token'dan türetilmelidir.

Tools sayfasının özlü ifadesi şudur: "a handle is a name, not a capability."

Bu vahşi doğada gerçekleşmiştir: CVE-2026-67431 (MCP Ruby SDK, "session poisoning with missing session owner binding") ile CVE-2026-67430 (sınırsız oturum saklamadan kaynaklanan hizmet reddi). İkisi de toplayıcı kaynaklıdır ve NVD'de doğrulanmamıştır.

### 10.4 `ttlMs` ile `cacheScope`, SEP-2549, gizli yetkilendirme kararı

SEP-2549 "TTL for List Results" Final ve Standards Track'tir; 9 Nisan 2026, @CaitieM20, PR numarası 2549'dur.

**Kapsam.** `CacheableResult` arayüzü şu sonuçlarda zorunludur: `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` ve `resources/read`. MRTR yeniden denemeleri önbelleklenmemelidir (MUST NOT).

**`ttlMs`.** Milisaniye cinsinden tamsayıdır ve `Cache-Control: max-age` benzeridir. Sıfır değeri hemen bayat demektir. Yoksa sıfır varsayılır. Negatifse sıfır sayılır. Sunucular sıfır veya daha büyük bir değer vermelidir (MUST).

> `no-store` ile `must-revalidate` karşılığı yoktur. Önbelleklenmesin demenin tek yolu `ttlMs: 0`'dır ve o da SHOULD seviyesinde bir ipucudur, yasak değildir.

**`cacheScope`, yalnızca iki değer.**

| Değer | Spesifikasyon metni |
|---|---|
| `"public"` | "The response does not contain user-specific data. Any client, shared gateway, or caching proxy MAY store and serve the cached response to any user." |
| `"private"` | "Cached responses MAY be reused for the same authorization context. Caches MUST NOT be shared across authorization contexts (e.g. a different access token requires a different cache)." |

Kullanıcı başına, token başına veya oturum başına bir enum değeri yoktur. İzolasyon birimi yetkilendirme bağlamı, yani access token'dır.

Spesifikasyonun kendi açık uyarısı şudur: "Servers MUST be aware that responses with a `"public"` `cacheScope` may be shared between callers even if the Result is coming from an authenticated endpoint. For example, the Result from an authenticated `tools/list` call with a `"public"` `cacheScope` may be cached by a client and may be shared outside of the initial request's authorization context." Devamında sunucuların "MUST apply appropriate per-primitive access controls, and MUST NOT rely on `cacheScope` alone" denmektedir.

Ek bir tuzak vardır: "Servers MUST apply the same `cacheScope` to all response pages for a given list request."

`tools/list` yetkilendirmeye göre değişebilir; `server/tools` spesifikasyonu şöyle der: "The set MAY vary by the authorization presented on the request … since credentials are per-request input, not connection state." Ancak "MUST NOT vary per-connection" da denmektedir.

> **Kesin kural.** `tools/list` veya herhangi bir liste scope, hak veya kiracıya göre filtreleniyorsa, ki stateless ve token başına modelde tam olarak öyle olur, `cacheScope: "private"` yayınlamak zorunludur. Tek bir yanlış etiketlenmiş `"public"`, tool yüzeyimizin protokolce onaylanmış çapraz kiracı ifşasıdır. Dikkat edilmelidir ki `server/discover` de önbelleklenebilir ve spesifikasyonun kendi örneği onu `"public"` işaretlemektedir; yetenek ilanımız token'a göre değişiyorsa o örnek bizim için yanlıştır.

### 10.5 `server/discover` için yetkilendirme muafiyeti var mıdır

Hayır, ve bu bir belirsizliktir. `server/discover.md` içinde yetkilendirme veya 401 ile ilgili hiçbir normatif ifade yoktur. Sıradan bir JSON-RPC metodudur ve "authorization MUST be included in every HTTP request" kuralına tabidir. Spesifikasyon onu kimlik doğrulamasız bir bootstrap endpoint'i olarak muaf tutmamaktadır.

Pratik bootstrap akışı şöyledir:

```
kimlik doğrulamasız server/discover (veya herhangi bir RPC)
  → 401 + WWW-Authenticate: Bearer resource_metadata="…"
  → RFC 9728 PRM
  → AS keşfi
```

Kimlik doğrulamasız bir yetenek yoklaması isteniyorsa bu karar kendimizce verilmeli ve `server/discover` sonucunun token'a göre değişmediğinden emin olunmalıdır.

### 10.6 Çözülmemiş boşluk: uzun ömürlü stream'de token süresi

`subscriptions/listen`, yanıtı açık bir sunucu gönderimli olay stream'i olan tek uzun ömürlü istektir. `basic/patterns/subscriptions.md` dosyasında token, auth, expire ve 401 kelimelerinin hiçbiri geçmemektedir; sıfır eşleşme ile doğrulanmıştır.

Spesifikasyon tamamen sessizdir. Öneri şudur: token süresi dolduğunda stream kapatılır ve istemci yeniden bağlanır; spesifikasyon zaten "the server holds no subscription state across reconnections" demektedir.

---

## 11. MRTR ve `requestState`

SEP-2322 Final statüsündedir ve 3 Şubat 2026 tarihlidir.

Sunucular artık istemciye JSON-RPC isteği gönderemez: "Servers MUST send server-to-client requests (such as `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the MRTR pattern. The previous pattern of server-initiated requests is no longer supported. This is a breaking change."

Bunun yerine sunucu `resultType: "input_required"` ile bir `InputRequiredResult` döner; bu, sunucu tarafından atanan anahtardan `ElicitRequest`, `CreateMessageRequest` veya `ListRootsRequest` değerine giden `inputRequests` alanını ve opak `requestState` alanını taşır. İstemci girdiyi toplar ve orijinal isteği yeni bir JSON-RPC kimliğiyle yeniden POST eder; `inputResponses` ile `requestState` ekler.

Bu yalnızca `prompts/get`, `resources/read` ve `tools/call` üzerinde izinlidir.

`requestState` güvenlik kritiktir: "servers MUST treat `requestState` as an attacker-controlled input. If `requestState` influences authorization, resource access, or business logic, servers MUST protect its integrity (e.g. HMAC or AEAD) and MUST reject state that fails verification."

> **Karar.** `requestState` imzalı veya AEAD ile korunur, `(sub, client_id, resource, original_request_hash)` değerine bağlanır, kısa bir TTL taşır ve tek kullanımlık olarak takip edilir.

---

## 12. Güvenlik tuzakları, öncelik sırasına göre

Sıralama gerçek dünyada insanları en çok ele geçiren tuzaklara göredir.

### 12.1 Onay, bir numaralı gerçek başarısızlık

1. Sunucu tarafında bir onay kaydı tutulur: `(user_id, client_id, resource, scopes)`. Bu, herhangi bir upstream yönlendirmesinden önce kontrol edilir.
2. Onay çerezi veya oturumu, kullanıcı onaya tıklamadan önce asla kurulmaz. Bu tek sıralama hatası confused deputy saldırısının tamamıdır.
3. `state` değeri kriptografik olarak güvenli bir rastgele üreteçle üretilir, yalnızca onay sonrası sunucu tarafında saklanır, callback'te tam eşleşme doğrulanır, doğrulamadan sonra silinir ve TTL'i en fazla on dakikadır.
4. Onay çerezi `__Host-` önekli, `Secure`, `HttpOnly` ve `SameSite=Lax` olur; imzalanır ve belirli bir `client_id` değerine bağlanır.
5. Onay, anonim tarayıcı oturumuna değil kimliği doğrulanmış kullanıcı kimliğine bağlanır; Obsidian'ın çerez enjeksiyonu atlatması bu yüzden mümkün olmuştur.

### 12.2 İstemci kimliği

8. `redirect_uri` hem `/authorize` hem token takasında, yalnızca tam string eşleşmesiyle doğrulanır; CVE-2025-4143 yalnızca takasta doğruluyordu. Tek istisna loopback portudur.
9. Yönlendirme URI politikasının sıkılaştırılması önceden var olan kayıtları geriye dönük geçersiz kılmalıdır; bu Square dersidir.
10. CIMD'de `client_id` https şemalı ve path içermelidir; dokümandaki `client_id` URL ile tam eşleşmelidir; `redirect_uri` dokümanda bulunmalıdır; HTTP cache başlıklarına saygı gösterilmelidir.
11. CIMD getiricisi SSRF'e karşı sertleştirilir: yalnızca HTTPS, engellenmiş özel, bağlantı yerel ve loopback aralıkları (IPv4 ve IPv6), otomatik yönlendirme takibi yok, kontrol ile kullanım arasında DNS pinleme, zaman aşımı, 5 KB okuma sınırı, istemci başına hız sınırı ve tercihen bir çıkış vekili. İncelenmiş bir crate kullanılır, IP ayrıştırması elle yazılmaz.
12. CIMD için alan adı güven politikası kurulur: allowlist, itibar ve alan adı yaşı katmanları. CIMD hostname'i belirgin gösterilir.
13. Yalnızca loopback yönlendirmeli istemciler için ek uyarı gösterilir, asla sessiz onay verilmez.
14. DCR endpoint'i tutuluyorsa sıkı hız sınırı (IP ve kiracı bazında), kayıt üst sınırı, kullanılmayanların temizliği ve wildcard veya desen içeren `redirect_uri` reddi uygulanır.

### 12.3 Token'lar

15. `resource` parametresi onurlandırılır, tek ve doğru bir `aud` damgalanır, kayıtsız `resource` değerleri reddedilir.
16. Asla audience'sız veya çoklu audience'lı token verilmez. Asla upstream token'ı kendi token'ımız gibi kabul edilmez.
17. RFC 9207 `iss` yayınlanır.
18. PKCE S256 zorunlu tutulur, `code_challenge_methods_supported` ilan edilir ve PKCE kod yolu seviyesinde atlanamaz yapılır; CVE-2025-4144 bir atlamaydı.
19. Kısa ömürlü access token verilir; public istemciler için refresh token rotasyonu uygulanır.
20. Authorization code'un tek kullanımlık takası atomik yapılır; karşılaştır ve değiştir kullanılır, önce oku sonra yaz değil. Stateless yeniden denemeler çift takası rutin hâline getirmektedir ve oradaki bir yarış kod yeniden oynatma açığıdır.

### 12.4 Stateless dönem

21. Bir state handle veya `requestState` asla kimlik doğrulaması sayılmaz. Sunucu tarafında token'dan türetilen `user_id` değerine bağlanır; handle'lar kriptografik olarak güvenli rastgele üretilir ve süre sınırı konur.
22. Yetkilendirme kararını etkileyebilen her `requestState` imzalanır ve audience'a bağlanır.
23. Bir ağ geçidinin arkasındaysak gövde otoritedir: başlık ile gövde uyuşmazlığı reddedilir, protokol sürüm başlığı istenir ve doğrulanır, `Mcp-Param-*` içinde sır tutulmaz, başlık değerlerinde satır başı ile satır sonu karakterleri yasaklanır ve base64 sentinel karşılaştırmadan önce çözülür.
24. `cacheScope` bir yetkilendirme kararı olarak ele alınır.
25. Çok kiracılıkta Asana olayı egzotik bir saldırı değil düz bir izolasyon mantık hatasıydı. Çapraz kiracı okumaları açıkça test edilir.

### 12.5 Vahşi doğadaki CVE'ler

> Aşağıdaki tablo toplayıcı kaynaklıdır. NVD ile CVE.org detay sayfaları JavaScript tek sayfa uygulaması olduğu için doğrudan doğrulanamamıştır. Alıntılamadan önce NVD JSON API ile teyit edilmelidir: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`

| CVE | Bileşen | Kusur |
|---|---|---|
| CVE-2026-27124 | `fastmcp < 3.2.0` | OAuth vekil callback'inde onay doğrulaması eksiktir ve confused deputy doğar, CWE-441 |
| CVE-2026-31944 | LibreChat | MCP OAuth callback ile hesap ele geçirme |
| CVE-2026-42073 | OpenClaude | OAuth callback'te CSRF ile `state` atlatması |
| CVE-2026-62800 | FastMCP | OAuth callback'te yansıtılmış XSS |
| CVE-2026-42230 | n8n | MCP OAuth açık yönlendirme |
| CVE-2026-46549 | NocoDB MCP | OAuth token scope atlatması |
| CVE-2026-49291 | mcp-memory-service | OAuth okuma scope'uyla `tools/call` atlatması |
| CVE-2026-25536 | MCP TypeScript SDK | Paylaşılan sunucu ile transport yeniden kullanımından çapraz istemci veri sızıntısı |
| CVE-2026-67430 ve -67431 | MCP Ruby SDK | Sınırsız oturum tutmadan hizmet reddi; oturum sahibi bağlaması eksikliğiyle oturum zehirlenmesi |
| CVE-2026-12112 | foreman-mcp-server | Gizli olmayan oturum kimliğiyle oturum ele geçirme |
| CVE-2026-77822 ve -18905 | IBM ContextForge MCP Gateway | DNS rebinding |
| CVE-2026-81315 | ash_ai MCP HTTP transport | DNS rebinding; `X-Forwarded-Proto` origin doğrulaması eksiktir |
| CVE-2026-24052 | `@anthropic-ai/claude-code` | WebFetch'te güvenilir alan adı doğrulamasının atlatılması |
| CVE-2026-32625 | LibreChat | MCP sunucu URL değişken interpolasyonu `JWT_SECRET`, `CREDS_KEY` ile `MONGO_URI` değerlerini sızdırmaktadır |

Toplu istatistikler toplayıcı kaynaklıdır ve doğrulanmamıştır: `mcp-security-project/mcp-cve-project` indeksi 570'ten fazla MCP CVE'si iddia etmektedir. Temmuz 2025 taramasında 1.862 herkese açık MCP örneği kimlik doğrulamasız yanıt vermekteydi ve yalnızca %8,5'i OAuth kullanmaktaydı.

Bir ölçüm çalışması (arXiv 2605.22333, 21 Mayıs 2026, Fudan) 7.973 canlı uzak MCP sunucusu incelemiştir: %40,55'i hiçbir kimlik doğrulaması olmadan tool açmaktadır; OAuth kullanan 119 sunucunun %100'ünde en az bir kusur vardır ve toplam 325 kusur bulunmuştur; %96,6'sında DCR kusuru vardır.

CVE olmayan bir olay olarak Asana çapraz kiracı veri ifşası önemlidir. Özellik 1 Mayıs 2025'te yayımlanmış, hata 4 Haziran 2025'te bulunmuş ve erişim 17 Haziran 2025'te geri verilmiştir. Deneysel MCP sunucusundaki bir kiracı izolasyon mantık hatası yaklaşık 1.000 organizasyon arasında görev verisini, proje metadata'sını, ekip detaylarını, yorumları ve dosyaları ifşa etmiştir. Bu bir ihlal değildi, prompt enjeksiyonu da değildi; düz bir çok kiracılık yetkilendirme hatasıydı.

### 12.6 Güvenlik araştırması yapanlar

**Doyensec**, "The MCP AuthN/Z Nightmare" (5 Mart 2026), en iyi yetkilendirmeye özgü eleştiridir. ID-JAG ile kurumsal model analizinde dört nokta öne çıkar. Erişim geçersizleştirme veya token iptal mekanizması yoktur. "The IdP issues an ID Token with no scopes embedded" denmektedir, dolayısıyla yüksek riskli scope'lar için hiçbir onay penceresi tetiklenmemektedir. `audience` değerinin `resource` tanımlayıcısına bağlandığının doğrulanması eksiktir, bu da scope isim alanı çakışması ile kaynak tanımlayıcısı enjeksiyonuna yol açar. ID-JAG yeniden oynatma amplifikasyonu vardır: tek bir JAG ile birçok access token alınabilir, dolayısıyla tek kullanımlık `jti` zorunlu kılınmalıdır.

**Trail of Bits** line jumping saldırısını (21 Nisan 2025) ve `mcp-context-protector` aracını üretmiştir.

**Invariant Labs** tool zehirlenmesi kavram kanıtını, GitHub MCP istismarını, tek tek yetkili tool çağrılarının kompozisyonu üzerine akıl yürüten ilk ilkeli yaklaşım olan Toxic Flow Analysis'i ve `mcp-scan` aracını üretmiştir.

**Obsidian Security** Square'deki tek tıkla hesap ele geçirmeyi, token geçirmeyi, anonim oturumun state'e bağlanmasını ve çerez enjeksiyonunu göstermiştir.

**Cloudflare** 14 Ağustos 2026'da `MCP-Protocol-Version` başlığıyla protokol tespitini ve gölge MCP tespitini yayımlamıştır. DCR kullanımdan kaldırıldığı için MCP Portals'a ön kayıtlı OAuth istemcisi desteği eklemişlerdir.

**NSA ve CISA'nın** "Model Context Protocol (MCP): Security Design" siber güvenlik bilgi sayfası PDF'i media.defense.gov'da 2 Haziran 2026 tarihli görünmüş ancak açılamamıştır. Okumaya değerdir.

---

## 13. Ekosistem

### 13.1 Resmî SDK'lar

**TypeScript.** npm üzerinde `@modelcontextprotocol/sdk` 1.30.0'dır ve `LATEST_PROTOCOL_VERSION = '2025-11-25'` tanımlamaktadır. `main` dalı 2.0.0-alpha.0'dır.

Tüm AS implementasyonu `packages/server-legacy/` paketine taşınmıştır; birinci bölümdeki stratejik sinyale bakınız. `protocolEras.ts` ile `'legacy'` (2025-11-25 ve öncesi) ile `'modern'` (2026-07-28 ve sonrası) arasında ikili bir çekirdek vardır. RFC 9207 istemci tarafında tam implemente edilmiştir; `packages/client/src/client/auth.ts` 2.527 satırdır, spesifikasyonun karar tablosu birebir kodlanmıştır ve ayrı bir `IssuerMismatchError` sınıfı vardır. CIMD için `OAuthClientProvider.clientMetadataUrl` alanı vardır ve `metadata.client_id_metadata_document_supported === true` koşuluna bağlıdır.

**Python.** PyPI üzerinde `mcp` 2.2.0'dır. TypeScript'in aksine AS implementasyonunu korumaktadır; `src/mcp/server/auth/handlers/*` altındadır.

`TokenVerifier` çıplak bir `Protocol`'dür:

```python
class TokenVerifier(Protocol):
    async def verify_token(self, token: str) -> AccessToken | None: ...
```

Yerleşik bir JWT veya introspection doğrulayıcısı yoktur. Audience zorlaması `AuthSettings.validate_token_resource` ile isteğe bağlı olarak açılır. DPoP yalnızca bildirimsel AS metadata alanları olarak vardır ve hiçbir şey zorlanmamaktadır.

> Her iki resmî SDK da PAR (RFC 9126) implemente etmemekte ve DPoP (RFC 9449) zorlamamaktadır.

### 13.2 Rust durumu, Argus için en kritik bölüm

**`rmcp`, resmî SDK, v3.2.0, 31 Ağustos 2026.** 24,9 milyon indirmesi vardır. v3.0.0, spesifikasyon revizyonuyla aynı gün, yani 28 Temmuz 2026'da çıkmıştır.

Yetkilendirme feature bayrakları `auth`, `auth-client-credentials-jwt` ve `auth-enterprise-managed`'dır. `oauth2` crate'inin v5.0 sürümü üzerine kuruludur. Desteklenenler RFC 8707, RFC 9728, RFC 8414 ile OIDC keşfi, RFC 7591, RFC 7636 (S256 zorunludur), SEP-991 yani CIMD, SEP-835 scope yükseltmesi, SEP-837 `application_type` ve RFC 9207'dir. Implemente edilmeyenler PAR, DPoP ve RAR'dır.

> **Belirleyici gerçek.** Bunların hepsi `src/transport/auth.rs` altındadır ve yalnızca istemci tarafıdır. Crate'te `TokenVerifier` yoktur, bearer middleware yoktur, PRM sunumu yoktur ve `WWW-Authenticate` yayını yoktur; ilgili tüm kod yalnızca ayrıştırma yapar. Dokümanlar bunu doğrulamaktadır: "Client-only implementation. The documentation describes no server-side (resource server) OAuth support."

Referans materyali `examples/servers/src/` altındaki üç elle yazılmış oyuncak axum AS'idir: `cimd_auth_streamhttp.rs` (514 satır), `complex_auth_streamhttp.rs` (691 satır) ile `simple_auth_streamhttp.rs` (173 satır). Bellek içidir ve demo kalitesindedir.

**`rust-mcp-sdk`, üçüncü taraf, `rust-mcp-stack`, v2.0.0, 27 Ağustos 2026.** 262 bin indirmesi vardır ve bizim için en yakın referans implementasyondur. `rmcp`'nin aksine tam kaynak sunucusu desteği vardır:

```
src/auth/
  auth_info.rs          AuthInfo
  auth_provider.rs      trait AuthProvider
  token_verifier.rs     trait OauthTokenVerifier
  metadata.rs           AuthMetadataBuilder, OauthMetadata, OauthEndpoint
  spec/{audience,claims,discovery,jwk}.rs
  client_auth/{client,discovery,pkce,registration,scope,store,token,www_authenticate}.rs
  auth_provider/remote_auth_provider.rs
```

Kodda RFC 9728 103 kez, token doğrulama 70 kez, CIMD 16 kez ve DPoP 17 kez geçmektedir. DCR'ın üzerinde gerçek bir `#[deprecated]` niteliği vardır. `rust-mcp-extra` içinde çalışan Keycloak, WorkOS AuthKit ile Scalekit sağlayıcıları bulunmaktadır. Yüzde yüz conformance iddiası kendi beyanıdır ve süiti kendimiz çalıştırana kadar doğrulanmamış sayılmalıdır.

> **Keycloak sağlayıcısı tasarımımız için en öğretici artefakttır.** MCP sunucusu kendi RFC 9728 PRM'sini `AuthMetadataBuilder` ile inşa edip sunmakta ve `aud` değerini kendisi doğrulamaktadır; `resolve_audience` beklenen audience'ı MCP sunucu URL'i varsaymakta ve açıkça "strongly discouraged" işaretli bir `disable_audience_validation` kaçış kapısı sunmaktadır. Keycloak yalnızca token üreticisi olarak kullanılmaktadır. Bu ayrımı biz de tekrarlamalıyız.

Ölü veya durgun Rust MCP crate'leri `mcp-core` (0.1.50, Mayıs 2025), `mcpr` (0.2.3, Mart 2025) ile `poem-mcpserver`'dır (0.3.1, Ekim 2025).

**Rust OAuth sunucu yapı taşları, dürüst değerlendirme.**

| Crate | Sürüm | Son yayın | Değerlendirme |
|---|---|---|---|
| `oxide-auth` | 0.6.1 | 2 Haziran 2024 | Rust'taki tek yerleşik AS çatısıdır ve yaklaşık iki buçuk yıl bayattır. OAuth 2.0 dönemindendir; RFC 9728, 8707, 9207, CIMD, PAR ile DPoP yoktur. Üzerine inşa edilmez |
| `oauth2` | 5.0.0 | 21 Ocak 2025 | 48,9 milyon indirme. Sağlamdır ancak yalnızca istemci tarafıdır |
| `openidconnect` | 4.0.1 | 6 Temmuz 2025 | 12,9 milyon indirme. Yalnızca RP ile istemci tarafıdır |
| `jsonwebtoken` | 11.0.0 | 24 Temmuz 2026 | 183 milyon indirme, aktiftir |
| `josekit` | 0.10.3 | 20 Mayıs 2025 | Daha geniş JOSE kapsamı ancak daha sessiz; C OpenSSL bağımlılığı vardır |
| `aws-lc-rs` | 1.18.1 | 1 Eylül 2026 | 214 milyon indirme, çok aktiftir, FIPS'e uygundur |
| `jwt-authorizer` | 0.15.0 | 27 Ağustos 2024 | Axum JWKS middleware'idir ve iki yıl bayattır |
| `axum` | 0.8.9 | 14 Nisan 2026 | 458 milyon indirme |

> **Rust'ta olgun ve genel amaçlı bir OAuth 2.1 Authorization Server crate'i yoktur. Bu boşluk gerçektir ve Argus'un en güçlü gerekçesidir.**

Niş crate'ler farkındalık içindir, benimseme için değildir: `oauth-as` 0.9.4 (8 Ağustos 2026, 2.342 indirme; gömülebilir bir OAuth 2.1 AS kütüphanesi olduğunu söylemektedir ancak kapsamı RFC 6749, 8628 ile 7636'dır ve RFC 9728, 8707, 9207 ile CIMD yoktur); `dpop-verifier` 4.4.0 (12.460 indirme, en inandırıcı DPoP yapı taşıdır); `turbomcp-dpop` 3.2.0; `nest-rs-oauth-resource`, `skyauth`, `turul-mcp-oauth`, `mcp-oauth`, `ferro-mcp-oauth` ile `auth-framework`; hepsi küçüktür.

Hiçbir sağlayıcı Rust SDK'sı sunmamaktadır. Bulunan tüm MCP yetkilendirme SDK'ları TypeScript veya Python'dur.

### 13.3 Conformance test aracı

`github.com/modelcontextprotocol/conformance` resmî conformance çatısıdır. Hem istemciyi hem sunucuyu kapsar. Açık yetkilendirme senaryoları `auth/basic-dcr`, `auth/basic-metadata-var1` ile `auth/basic-cimd`'dir. Revizyon başına gereksinim setleriyle her spesifikasyon sürümünün ne talep ettiğini dondurmaktadır. `--spec-version` bayrağıyla 2025-11-25 ile 2026-07-28 desteklenmektedir. SEP-1730 SDK katmanlaması ile `tier-check` alt komutu vardır.

```bash
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
npx @modelcontextprotocol/conformance client --command "…" --suite auth
npx @modelcontextprotocol/conformance list
```

> **Karar.** Bu, kabul testi harness'ımızdır ve birinci günden itibaren CI'dadır. Hem `rmcp` hem `rust-mcp-sdk`, `conformance-client` crate'leri taşımaktadır; kablolamayı oradan kopyalayabiliriz. GitHub API hız sınırı nedeniyle senaryo listesinin tamamı sayılamamıştır; yukarıdaki üç senaryo adı doğrulanmıştır, tam liste doğrulanmamıştır.

### 13.4 Sağlayıcılar

| Sağlayıcı | CIMD | DCR | RFC 9728 | RFC 8707 | Not |
|---|---|---|---|---|---|
| WorkOS AuthKit | Vardır; panelden açılır, varsayılan kapalıdır | Vardır | Vardır | Vardır, yapılandırılabilir | Doğrulanabilen en güçlü MCP hikâyesidir. Cross App Access erken erişimdedir |
| Cloudflare `workers-oauth-provider` | Vardır, `clientIdMetadataDocumentEnabled` | Vardır | Her zaman vardır | Vardır | Bir sağlayıcı değildir ancak amaca özel en eksiksiz açık kaynak MCP AS'idir. 1,9 bin yıldızlıdır ve API şekli ilhamı için okunmalıdır |
| Keycloak | Deneyseldir, 26.6.0, 8 Nisan 2026 | Vardır | Muhtemelen yoktur | Bilinmemektedir | Son sürüm 26.7.3'tür. 26.6.0 sürüm notları CIMD'yi MCP için eklediğini yazmakta ancak RFC 9728 ile 8707'den hiç bahsetmemektedir |
| Clerk | Beta olarak vardır, 5 Ağustos 2026 | Bilinmemektedir | Bilinmemektedir | Bilinmemektedir | Changelog taslak revizyonunu belirtmemektedir |
| Auth0 | Yakında denmektedir | Bilinmemektedir | Bilinmemektedir | Bilinmemektedir | Özel sayfalar erişilemedi, 405 ve 404 döndü. Mayıs 2026'da MCP için yetkilendirmenin genel kullanıma açıldığı iddiası doğrulanamamıştır |
| Stytch, Descope ve Scalekit | oauth.net listesine göre vardır | Bilinmemektedir | Bilinmemektedir | Bilinmemektedir | Genel bakış sayfaları MCP, DCR, CIMD, 9728 ile 8707'den bahsetmemektedir; doğrulanmamıştır |
| Okta ve Entra ID | Kanıt yoktur | Vardır | Bilinmemektedir | Entra `resource` desteklemektedir ancak MCP sunucu URL'i Application ID URI olarak kayıtlı olmalıdır, yoksa `AADSTS9010010` hatası döner | Okta hakkında veri toplanamamıştır |

Değerlendirilmeyenler Ory Hydra, Zitadel, Logto, Authentik, SuperTokens, node `oidc-provider` ile MCP ağ geçitleridir (Docker, Kong, Envoy AI Gateway, Pomerium).

---

## 14. İstemci interop gerçekleri

### 14.1 Anthropic ve Claude

Kaynağı claude.com/docs/connectors/building/authentication'dır.

| Tür | Durum |
|---|---|
| `oauth_dcr` | Hazır desteklidir |
| `oauth_cimd` | Hazır desteklidir |
| `oauth_anthropic_creds` | `mcp-review@anthropic.com` adresinden istenir |
| `custom_connection` | `mcp-review@anthropic.com` adresinden istenir |
| `static_headers` | Betadır |
| `none` | Desteklidir |

Kritik detaylar şunlardır. Saf makineden makineye `client_credentials` desteklenmemektedir: "Every connection requires user consent." Claude her authorization isteğinde `code_challenge_method=S256` göndermektedir. CIMD seçimi iki koşula birden bağlıdır: `client_id_metadata_document_supported: true` olmalı ve `token_endpoint_auth_methods_supported` içinde `"none"` bulunmalıdır; biri eksikse DCR'a düşer. Yüksek trafik bekleyen sunucular için DCR yerine CIMD veya `oauth_anthropic_creds` kullanılmalıdır, çünkü DCR her yeni bağlantıda yeni bir istemci kaydı yaratmaktadır. Scope kontrolü için 401 yanıtının `WWW-Authenticate` başlığında `scope` verilmelidir; verilmezse Claude PRM'nin `scopes_supported` alanını ister. AS metadata'sında `offline_access` varsa Claude onu da ekler. 401 şarttır: "Claude does not honor a `WWW-Authenticate` header on a `200` response." `authorization_servers` çoklu ise Claude yalnızca ilkini kullanır ve yedeğe geçmez. Zaman aşımları keşif, kayıt ve token için 10 saniye, yenileme için 30 saniyedir. Token endpoint'i `application/x-www-form-urlencoded`, `/register` ise `application/json` kullanır; yani farklı ayrıştırıcılar gerekir. Yenileme 401 üzerine tepkisel, süre dolmasından beş dakika önce öngörücü yapılır; geçersiz refresh token'da `invalid_grant` dönülür. Anthropic çıkış aralığı `160.79.104.0/21`'dir; AS'imiz bu aralıktan erişilebilir olmalıdır ve bir web uygulaması güvenlik duvarı akışı bozabilir.

Callback URL'leri şöyledir: barındırılan yüzeyler, yani Claude.ai web, Desktop, mobil ile Cowork, `https://claude.ai/api/mcp/auth_callback` kullanır; Claude Code ise RFC 8252 loopback ile geçici bir port kullanır ve port yok sayılarak eşleştirilmelidir, 9.4'e bakınız.

Not olarak Anthropic dokümantasyonu hâlâ MCP spesifikasyonunun 2025-11-25 sayfalarına bağlantı vermektedir; hangi revizyonu implemente ettikleri açıkça yazılmamıştır.

### 14.2 OpenAI Apps SDK

Kaynağı developers.openai.com/apps-sdk/build/auth'tur.

PKCE S256 zorunludur: "MCP servers are unsupported when their authorization server metadata omits this field", yani `code_challenge_methods_supported` alanı eksikse sunucu desteklenmez. CIMD tercih edilen yöntemdir ve `client_id_metadata_document_supported: true` gereklidir; desteklenen token kimlik doğrulaması `none` veya `private_key_jwt`'dir, DCR ise yedektir. ChatGPT `resource=https%3A%2F%2Fyour-mcp.example.com` parametresini eklemektedir ve AS bunu access token'a `aud` olarak kopyalamalıdır.

RFC 9207 sert bir gereksinimdir: `authorization_response_iss_parameter_supported: true` ilan edilmeli ve her başarılı ile hatalı yanıtta `iss` bulunmalıdır. "Clients use exact string comparison and do not normalize trailing slashes, paths, ports, or casing." ChatGPT ile Codex uyuşmazlıkları veya eksik `iss` değerlerini reddetmektedir.

ChatGPT OpenAI tarafından yönetilen bir mTLS sertifikası sunmaktadır ve yayımlanan CA zincirine karşı doğrulanabilir; alternatifi yayımlanan çıkış IP aralıklarıdır. Dokümantasyon şunu söyler: "ChatGPT does not support machine-to-machine OAuth grants such as client credentials." Yeniden yetkilendirme için AS, `id_token_hint` parametresini onurlandırmalıdır. Kurumsal alan adı kısıtlaması için OIDC metadata'sı, `openid` ile `email` scope'ları ve bir UserInfo endpoint'i gereklidir.

Gerçek ChatGPT CIMD dokümanı, 8 Eylül 2026'da çekilmiştir:

```json
{
  "client_id": "https://chatgpt.com/oauth/client.json",
  "client_uri": "https://chatgpt.com/",
  "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_name": "ChatGPT",
  "logo_uri": "https://persistent.oaistatic.com/sonic/misc/openai-logo.png",
  "token_endpoint_auth_signing_alg": "RS256",
  "jwks_uri": "https://chatgpt.com/oauth/jwks.json"
}
```

> Dikkat edilmelidir ki `token_endpoint_auth_methods_supported` bir RFC 7591 istemci metadata alanı değildir; bu, bir AS metadata alan adının yeniden kullanımıdır. AS'imiz bilinmeyen alanlara toleranslı olmalıdır.

OpenAI'nin tool başına `securitySchemes` dizisi MCP çekirdeğinde yoktur; `schema.ts` dosyasında `securityScheme` hiç geçmemektedir. Bu, OpenAI'ye özgü bir uzantıdır.

### 14.3 A2A, Agent2Agent

Linux Foundation yönetimindedir. v1.0 tarihi çelişkilidir: site Ağustos 2026, blog duyurusu 12 Mart 2026 demektedir, dolayısıyla kesin genel kullanım tarihi doğrulanamamıştır.

Yetkilendirme modeli `AgentCard.securitySchemes` üzerinden ve OpenAPI 3.0 desenleriyle kuruludur. Tipleri `apiKey`, `http`, `oauth2`, `openIdConnect` ile `mutualTls`'tir. OAuth akışları `authorizationCode`, `clientCredentials` ile `deviceCode`'dur; `implicit` ile `password` yoktur, yani OAuth 2.1 uyumludur. RFC 9728, RFC 8707 veya OAuth metadata keşfinden bahsetmemektedir. AgentCardSignature kartın kanonikleştirilmiş biçimi üzerinde bir JWS'tir (RFC 7515). Normatif ifadesi şudur: "Servers MUST reject requests with invalid or missing authentication credentials".

MCP ile temel farkı şudur: A2A yetkilendirme şemasını agent'ın kendi kartında bildirimsel olarak tanımlar, yani OpenAPI tarzıdır; MCP ise OAuth keşif zincirini (PRM'den AS metadata'sına) zorunlu kılar ve kaynak göstergesi ile audience bağlamayı normatif yapar. MCP'nin modeli daha katı ve daha OAuth yerlisidir. Yakınsama sinyali yoktur.

---

## 15. Yol haritası, yakın gelecek

Kaynağı blog.modelcontextprotocol.io/posts/mcp-roadmap adresindeki 22 Ağustos 2026 tarihli yazıdır; yazarları David Soria Parra ile Den Delimarsky'dir.

Üçüncü öncelik alanı ajan kimliği ve kurumsal hazır güvenliktir: "MCP authorization today is built around a person approving access in a browser… more and more of the callers are agents running as cloud workloads with their own identity."

İş akışları DPoP'un sonlandırılması ve benimsetilmesi, Workload Identity Federation, Enterprise-Managed Authorization'ın arkasındaki ID-JAG grant'ı ile standart token takasıdır. IETF'in OAuth ile WIMSE çalışma gruplarıyla etkileşim hedeflenmektedir. Ayrıca bir Server Card Working Group vardır: "so a server can be discovered and reasoned over without connecting to it."

Uçuşta olan yetkilendirme SEP'leri, 8 Eylül 2026 itibarıyla:

| SEP veya PR | Başlık | Son güncelleme |
|---|---|---|
| SEP-1932 | DPoP Profile for MCP | 7 Eylül 2026 |
| SEP-1933 | Workload Identity Federation | 7 Eylül 2026 |
| SEP-2752 | HTTP Message Signing for MCP Client Authentication | 7 Eylül 2026 |
| SEP-2643 | Structured Authorization Denials | 6 Eylül 2026 |
| SEP-2848 | Asynchronous Approval for Tool Calls | 7 Eylül 2026 |
| SEP-2817 | AI Invocation Audit Context in Request `_meta` | 24 Ağustos 2026 |
| SEP-3149 | Require Token Endpoint Auth Methods Supported in CIMD | 17 Ağustos 2026 |
| PR #3235 | Use updated OAuth Client ID Metadata Document RFC | 12 Ağustos 2026 |
| PR #3191 | docs: rework the authorization guide around CIMD | 3 Ağustos 2026 |

> **Karar.** DPoP ile RFC 8693 token takası için mimaride bugünden yer bırakılır. DPoP yol haritasında açıkça birinci sıradadır; `dpop_signing_alg_values_supported` alanı metadata şemasına şimdiden eklenir.

Enterprise-Managed Authorization stabildir ve MCP'nin kurumsal yetkilendirmesi ID-JAG'ı profillemektedir. Detayları §15'e aittir; buradaki bağlantı noktası şudur: IdP'nin AS rolü Argus'tur.

---

## 16. Argus için somut yapılacaklar

### 16.1 AS endpoint'leri

| Endpoint | Zorunluluk | Notlar |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | MUST, bu veya OIDC | RFC 8414. Path içeren issuer için `/.well-known/oauth-authorization-server/{path}` |
| `GET /.well-known/openid-configuration` | Alternatif veya ek | Path içeren issuer için hem `/.well-known/openid-configuration/{path}` hem `/{path}/.well-known/openid-configuration` sunulur; istemciler üçünü de dener |
| `GET /authorize` | MUST | PKCE S256 zorunludur, `resource` kabul edilir, `iss` yayınlanır, onay ekranı gösterilir |
| `POST /token` | MUST | `application/x-www-form-urlencoded` zorunludur. Yalnızca JSON ayrıştıran bir endpoint yaygın bir hatadır; 415 dönerseniz Claude bağlanamaz |
| `GET /jwks.json` | Pratikte zorunludur | — |
| `POST /register` | MAY, kullanımdan kaldırılmıştır | Hız sınırı, kayıt üst sınırı ve TTL temizliği şarttır |
| `POST /revoke` | Önerilir | RFC 7009 |
| `POST /introspect` | Opsiyonel | RFC 7662. Opak token kullanılırsa gereklidir |
| `GET /userinfo` | Opsiyonel | OpenAI'nin kurumsal alan adı kısıtlamaları için gereklidir |
| `GET` ve `POST /consent` | Proxy senaryosunda MUST | — |

### 16.2 AS metadata dokümanı

```json
{
  "issuer": "https://as.example.com",
  "authorization_endpoint": "https://as.example.com/authorize",
  "token_endpoint": "https://as.example.com/token",
  "jwks_uri": "https://as.example.com/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "private_key_jwt", "client_secret_basic"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
  "scopes_supported": ["..."],
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,
  "registration_endpoint": "https://as.example.com/register",
  "revocation_endpoint": "https://as.example.com/revoke"
}
```

Her alanın gerekçesi şudur. `code_challenge_methods_supported: ["S256"]` yoksa MCP istemcileri devam etmeyi reddetmek zorundadır; tek bir eksiklik tüm ekosistemden dışlar ve OIDC keşfi sunuyorsak da bu alan dahil edilmelidir. `authorization_response_iss_parameter_supported: true` olmazsa ChatGPT ile Codex uyuşmazlığı veya eksik `iss` değerini reddeder. `client_id_metadata_document_supported: true` CIMD desteğinin tek interop sinyalidir. `token_endpoint_auth_methods_supported` içindeki `"none"` değeri kritiktir, çünkü Claude CIMD'yi ancak bu ikisi birlikte varsa seçer, aksi hâlde DCR'a düşer. `offline_access` değeri `scopes_supported` alanına eklenirse Claude refresh token için onu ister. İleride `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]` ile `dpop_signing_alg_values_supported` eklenecektir.

### 16.3 AS davranış listesi

**Authorization endpoint.**

1. PKCE zorunlu kılınır, `S256` dışına izin verilmez ve PKCE'nin atlanabildiği hiçbir kod yolu bırakılmaz.
2. `redirect_uri` hem `/authorize` içinde hem token takasında doğrulanır.
3. Yönlendirme URI eşleştirmesi tam stringdir; wildcard ve desen yoktur. Tek istisna loopback host'larda portun yok sayılmasıdır.
4. `resource` parametresi kabul edilir, kayıtlı korunan kaynaklara karşı doğrulanır ve bilinmeyene `invalid_target` dönülür.
5. Onay ekranı gösterilir; CIMD istemcileri için varsayılan olarak gösterilir.
6. Onay verilene kadar state çerezi kurulmaz.
7. Başarılı ve hatalı yanıtlarda `iss` yayınlanır; metadata'daki `issuer` ile bayt bayt özdeş olmalıdır.
8. `application_type` değeri, CIMD dokümanından ya da DCR kaydından alınarak dikkate alınır.
9. Yalnızca loopback yönlendirmesi olan istemciler için ek uyarı gösterilir; yönlendirme hostname'i her zaman gösterilir.

**CIMD işleyicisi.**

10. URL formatlı `client_id` tespit edilir: `https` şeması, path bileşeni, fragment yokluğu ve userinfo yokluğu aranır.
11. Getirmede yönlendirme takip edilmez, yalnızca 200 kabul edilir, 5 KB'ta okuma kesilir, zaman aşımı konur ve istemci başına hız sınırı uygulanır.
12. SSRF savunması olarak RFC 6890 özel amaçlı adresleri engellenir; hem `client_id` URL'i hem doküman içindeki tüm URL'ler için geçerlidir. IP doğrulaması elle yazılmaz. DNS kontrol ile kullanım arasında pinlenir. Mümkünse bir çıkış vekili kullanılır.
13. Dokümandaki `client_id` değerinin getirilen URL ile basit string karşılaştırmasıyla eşleştiği doğrulanır.
14. `token_endpoint_auth_method` simetrik bir sır ise reddedilir; `client_secret` alanı varsa reddedilir.
15. HTTP cache başlıklarına saygı gösterilir; hata veya bozuk dokümanlar önbelleklenmez; kendi üst ve alt TTL sınırlarımız konur.
16. `logo_uri` önceden getirilir ve sunucu tarafında önbelleklenir.
17. Doküman hash'inin anlık görüntüsü alınır; değişirse yeniden onay zorlanır.
18. Alan adı güven politikası uygulanır.

**Token endpoint.**

19. `application/x-www-form-urlencoded` kabul edilir; `/register` için `application/json` kullanılır.
20. Authorization code takası atomik ve tek kullanımlık yapılır; karşılaştır ve değiştir kullanılır, önce oku sonra yaz değil.
21. `resource` değerine göre audience kısıtlı token verilir. Asla audience'sız veya çoklu audience'lı token verilmez.
22. Public istemciler için refresh token rotate edilir.
23. Geçersiz refresh token'da `invalid_grant` dönülür.
24. Kısa ömürlü access token verilir.
25. Yanıt süresi on saniyenin altında tutulur; Anthropic keşif, kayıt ve token için 10 saniye, yenileme için 30 saniye beklemektedir. Ters vekilin veya web uygulaması güvenlik duvarının yanıtı tutmadığından emin olunur.

**Onay ve iptal.**

26. Sunucu tarafında bir onay kaydı tutulur: `(user_id, client_id, resource, scopes, source, metadata_hash)`.
27. Onay çerezi `__Host-` önekli, `Secure`, `HttpOnly` ve `SameSite=Lax` olur; imzalanır ve `client_id` değerine bağlanır.
28. Onay sayfasında `frame-ancestors 'none'` veya `X-Frame-Options: DENY` ile bir CSRF token'ı bulunur.
29. Onay iptali canlı access ile refresh token'larını da geçersiz kılar.
30. Onay, anonim tarayıcı oturumuna değil kimliği doğrulanmış kullanıcı kimliğine bağlanır.

**DCR, geriye uyumluluk.**

31. IP ile kiracı bazında hız sınırı, kayıt üst sınırı ve kullanılmayan kayıtlarda TTL uygulanır.
32. Wildcard ve desen içeren `redirect_uri` reddedilir.
33. DCR kimlik bilgilerine kendi `issuer` değerimiz damgalanır; çapraz issuer sunumu sert reddedilir.
34. `application_type` onurlandırılır; sessizce reddetmek yerine açık hata dönülür.
35. Yönlendirme URI politikası sıkılaştırıldığında önceden var olan kayıtlar geriye dönük geçersiz kılınır.

**Çok kiracılık.**

36. Çapraz kiracı okumaları açıkça test edilir. Asana olayı egzotik bir saldırı değil düz bir izolasyon mantık hatasıydı.

### 16.4 Resource Server tarafı, referans implementasyon

| Endpoint | Zorunluluk |
|---|---|
| `POST /mcp` | MUST; POST desteklenmelidir |
| `GET /.well-known/oauth-protected-resource` ve varsa `/{path}` | MUST, ya da `WWW-Authenticate` yolu |

Yalnızca modern protokolü destekleyen bir sunucuda MCP endpoint'ine gelen `GET` veya `DELETE` istekleri 405 döner.

**PRM dokümanı, asgari biçim.**

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://as.example.com"],
  "scopes_supported": ["mcp:tools-basic"],
  "bearer_methods_supported": ["header"],
  "resource_name": "Example MCP Server"
}
```

`resource` değeri kullanıcının girdiği MCP sunucu URL'iyle path dahil tam eşleşmelidir. `authorization_servers` çoklu ise Claude yalnızca ilkini kullanır. `scopes_supported` minimal olmalıdır. `offline_access` buraya konmaz.

**Davranış.**

1. Token yoksa veya geçersizse 401 ile `WWW-Authenticate: Bearer resource_metadata="…"` dönülür; mümkünse `scope="…"` eklenir.
2. 200 yanıtında `WWW-Authenticate` işe yaramaz, çünkü Claude onu onurlandırmaz.
3. `resource_metadata` URL'i MCP sunucusunun origin'inde olmak zorunda değildir; `/.well-known/*` sunamayan platformlar için, yani Supabase Edge Functions, Cloudflare Workers ve Lambda URL için en güvenilir yoldur.
4. İmza ile `iss` JWKS üzerinden doğrulanır.
5. `exp` ile `nbf` doğrulanır.
6. `aud` veya `resource` claim'inin bizi işaret ettiği doğrulanır; etmiyorsa 401 dönülür.
7. Scope yetersizse 403 ile `insufficient_scope`, `scope` ve `resource_metadata` dönülür.
8. Scope hiyerarşisi uygulanır.
9. Bir operasyon için gereken tüm scope'lar tek bir challenge'da verilir.
10. Upstream API çağrılıyorsa ayrı bir token kullanılır; istemcinin token'ı asla iletilmez.
11. Önceki isteklerden bağlam çıkarılmaz; `Mcp-Session-Id` gelirse yok sayılır.
12. `clientInfo` ile `clientCapabilities` güvenlik kararında kullanılmaz.
13. State handle'lar kriptografik olarak güvenli rastgele, opak ve sınırlı ömürlü olur ve `<user_id>:<handle>` ile bağlanır.
14. `requestState` imzalı veya AEAD korumalı, kısa TTL'li ve tek kullanımlık olur.
15. Liste sonuçları token'a göre değişiyorsa `cacheScope: "private"` kullanılır.
16. `server/discover` sonucumuz token'a göre değişiyorsa o da `"private"` yapılır.
17. Sayfalı listede tüm sayfalara aynı `cacheScope` uygulanır.
18. `ttlMs` sıfır veya daha büyük olur.
19. `cacheScope`'a güvenilmez; primitif başına erişim kontrolü ayrıca uygulanır.
20. `Origin` başlığı varsa ve geçersizse 403 dönülür; bu DNS rebinding savunmasıdır.
21. Yerelde çalışıyorsa yalnızca `127.0.0.1` adresine bağlanılır.
22. Başlık ile gövde uyuşmazlığında 400 ile `-32020` dönülür; base64 sentinel çözülüp karşılaştırılır.
23. Başlık değerlerinde satır başı ile satır sonu karakterleri yasaktır.
24. `Mcp-Param-*` alanlarına sır düşürülmez.
25. Metadata endpoint yanıtları beş saniyenin altında verilir.
26. Sunucu gönderimli olay yanıtlarında `X-Accel-Buffering: no` kullanılır.
27. `subscriptions/listen` için token süresi dolma davranışına kendimiz karar veririz, çünkü spesifikasyon sessizdir.

---

## 17. Doğrulanamayanlar

Dürüstlük için açıkça işaretlenmiştir; kendi kararımızı vermeden önce teyit edilmelidir.

**Spesifikasyon ve standart.**

1. MCP'nin CIMD -00 atfı ile IETF -02 arasındaki fark doğrulanmıştır ve gerçektir. PR #3235'in ne zaman merge olacağı bilinmemektedir.
2. CIMD -02 §6'daki `client_id_metadata_document_supported` için MUST include ile OPTIONAL çelişkisi muhtemelen editoryal bir hatadır; taslak yazarlarına doğrulatılmamıştır.
3. CIMD -02'de içerik türü gereksinimi muğlaktır; taban çizgisi olarak `application/json` şartı hiç belirtilmemiştir.
4. `server/discover` endpoint'inin kimlik doğrulamasız olup olamayacağı spesifikasyonda tanımlanmamıştır; 10.5'teki yorum bir çıkarımdır.
5. `subscriptions/listen` için token süresi dolma davranışı spesifikasyonda tamamen tanımsızdır; sıfır kelime eşleşmesi vardır.
6. SEP-837'nin resmî statüsünün Final mi merged mi olduğu doğrulanamamıştır.

**Güvenlik.**

7. 2026 CVE tablosundaki tüm girdiler toplayıcı kaynaklıdır ve NVD JSON API ile teyit edilmelidir.
8. CVE-2025-54136'nın CVSS skoru kaynaklar arasında çelişmektedir: 7,2 ile 8,8.
9. CVE-2026-24052 ile CVE-2026-25536 birincil advisory'lere karşı doğrulanamamıştır.
10. `mcp-cve-project` 570'ten fazla CVE iddiası ile toplu istatistikler doğrulanmamıştır.
11. NSA ile CISA'nın "MCP: Security Design" siber güvenlik bilgi sayfası PDF'i açılamamıştır.
12. arXiv 2605.22333'ün tam PDF'i ayrıştırılamamış ve özeti kullanılmıştır. Dokuz kusur tipli taksonomisi tehdit modelimiz için en iyi yapılandırılmış girdi olurdu.

**Ekosistem.**

13. Keycloak'ın RFC 9728, 8707, 9207, PAR ile DPoP durumu doğrudan doğrulanmamıştır. RFC 9728 boşluğu için güçlü dolaylı kanıt vardır ancak olumsuzluk doğrudan kanıtlanamamıştır.
14. Auth0'ın MCP teklifi doğrulanamamıştır; özel sayfalar erişilemezdir, 405 ve 404 dönmektedir.
15. Clerk ile Okta hakkında veri toplanamamıştır.
16. Stytch ile Descope yalnızca genel bakış düzeyindedir.
17. `rust-mcp-sdk`'nın yüzde yüz conformance iddiası kendi beyanıdır.
18. Conformance çatısının tam yetkilendirme senaryo listesi sayılamamıştır; üç senaryo adı doğrulanmıştır.
19. Değerlendirilmeyenler Ory Hydra, Zitadel, Logto, Authentik, SuperTokens, node `oidc-provider` ile MCP ağ geçitleridir.
20. A2A v1.0'ın kesin genel kullanım tarihi belirsizdir: Mart mı Ağustos 2026 mı.

---

## 18. Kaynaklar

**Spesifikasyon**, 8 Eylül 2026'da ham markdown olarak okunmuştur.

`https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization` ve altındaki `authorization/authorization-server-discovery`, `authorization/client-registration` ile `authorization/security-considerations` sayfaları; `basic/security_best_practices`; `server/utilities/caching`; `basic/patterns/mrtr`; `basic/transports/streamable-http`; `changelog`; `deprecated`.

**RFC ve IETF.** RFC 9728, RFC 8707, RFC 8414, RFC 9207, RFC 6750, RFC 7591, RFC 8252, RFC 8693 ile RFC 7523. `https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.txt` ve `https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/` (draft-16, 3 Eylül 2026).

**MCP projesi.** `https://blog.modelcontextprotocol.io/posts/client_registration/` (22 Ağustos 2025); `https://blog.modelcontextprotocol.io/posts/mcp-roadmap` (22 Ağustos 2026); `https://github.com/modelcontextprotocol/ext-auth`; `https://github.com/modelcontextprotocol/conformance`; `https://modelcontextprotocol.io/seps`.

**Güvenlik araştırması.** Doyensec, `https://blog.doyensec.com/2026/03/05/mcp-nightmare.html`. Obsidian Security, `https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover`. Trail of Bits, `https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/`. Invariant Labs, `https://invariantlabs.ai/blog/mcp-github-vulnerability`. Equixly, `https://equixly.com/blog/2026/08/05/stateless-mcp/`. arXiv, `https://arxiv.org/abs/2605.22333`.

**Platform dokümanları.** `https://developers.openai.com/apps-sdk/build/auth`; `https://claude.com/docs/connectors/building/authentication`; `https://a2a-protocol.org/latest/specification/`; `https://oauth.net/2/client-id-metadata-document/`.
