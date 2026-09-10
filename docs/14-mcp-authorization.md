# 14. MCP yetkilendirme

> `ARGUS.md` §14'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§14 §X` referansları aynı anlamda.


**Kapsam:** Argus'un MCP ekosisteminde hem Authorization Server hem Resource Server olarak çalışması için gereken her şey.
**Yöntem:** Spec metinleri `modelcontextprotocol.io` üzerinden ham markdown olarak okundu; RFC'ler `rfc-editor.org`'dan; IETF durumları Datatracker'dan; sağlayıcı CIMD dokümanları canlı çekildi. Blog özetleriyle yetinilmedi.

> **Doğrulama notu:** Bu dosyadaki her iddia bir birincil kaynağa dayanıyor. Doğrulanamayan noktalar §14'te açıkça listelenmiştir. Rakam veya iddia uydurulmamıştır.

---

## 1. Yönetici özeti — on kritik bulgu

1. **Yürürlükteki revizyon `2026-07-28`.** Eylül 2026 itibarıyla daha yenisi yok. `/specification/draft/` sayfası mevcut ama normalize edilmiş diff sonucu `2026-07-28` ile **birebir aynı** (yalnızca URL yolları farklı). `/specification/latest` → `2026-07-28`'e yönleniyor.

2. **DCR resmen deprecate edildi** (PR #2858), yerine **CIMD**. Geriye uyumluluk penceresi: **2027-07-28 veya sonrasında yayımlanacak ilk revizyona kadar** kaldırılamaz (SEP-2596, minimum 12 ay).

3. **KRİTİK UYUMSUZLUK:** MCP spec'i CIMD taslağının **-00** revizyonuna atıf yapıyor. IETF'te güncel revizyon **-02** (2026-07-06) ve -02, -00'da olmayan **normatif MUST'lar** getirdi. → **-02'yi uygula** (§5.2).

4. **RFC 9207 `iss`** AS için hâlâ SHOULD, ama spec açıkça "gelecek revizyonda MUST'a yükseltilmesi bekleniyor" diyor. **Bugünden MUST gibi uygula.**

5. **`cacheScope` gizlenmiş bir yetkilendirme kararıdır.** Yalnızca `"public"` / `"private"`. Token'a göre filtrelenen bir liste `"public"` işaretlenirse spec'in kendi ifadesiyle **protokolce onaylanmış cross-tenant sızıntı** olur (§10).

6. **Stateless çekirdek**, token doğrulamayı her POST'ta zorunlu kılıyor. `Mcp-Session-Id` kaldırıldı; "aynı mantıksal oturum" muafiyeti spec metninden **silindi**. Principal'ı asacak oturum nesnesi yok.

7. **`requestState` saldırgan kontrollü girdidir** ve spec bunu MUST seviyesinde söylüyor: bütünlük koruması (HMAC/AEAD) + authenticated principal'a bağlama zorunlu.

8. **Rust'ta büyük boşluk var.** Resmî `rmcp` v3.2.0'ın OAuth desteği **yalnızca client tarafı**. Rust'ta olgun genel amaçlı OAuth 2.1 AS crate'i yok. **Argus'un en güçlü gerekçesi budur.**

9. **Consent problemi RFC 8707 ile çözülmüyor.** Confused deputy'nin çözümü per-client consent registry'dir. Gerçek dünyada en çok istismar edilen açık budur.

10. **Resmî conformance framework'ü var ve `auth` süiti içeriyor:** `github.com/modelcontextprotocol/conformance`. Kabul testi harness'ımız bu olmalı.

### Stratejik sinyal

TypeScript SDK'sının `main` branch'inde **tüm AS implementasyonu** — `mcpAuthRouter`, authorize/token/register/revoke handler'ları, `middleware/{bearerAuth,clientAuth}`, `providers/proxyProvider.ts` — **`packages/server-legacy/`** paketine taşındı. Yeni `packages/server/` yalnızca `middleware/oauthMetadata.ts` tutuyor.

> **SDK, authorization server işinden çıkıyor ve yalnızca resource server metadata'sını tutuyor. Argus gibi ayrı bir AS ürünü doğru bahis.**

---

## 2. Spec durumu ve kapsam

| Öğe | Değer |
|---|---|
| Yürürlükteki revizyon | **2026-07-28** |
| Bir önceki | 2025-11-25 (CIMD bu revizyonda geldi, SEP-991) |
| Yetkilendirme | MCP için **OPTIONAL** |
| HTTP transport | Bu spec'e **SHOULD** uymalı |
| STDIO transport | Bu spec'i **SHOULD NOT** takip etmeli — kimlik bilgilerini ortamdan almalı |
| Diğer transport'lar | Kendi protokollerinin güvenlik best practice'lerini **MUST** takip etmeli |

**Referans standartlar:** OAuth 2.1 (`draft-ietf-oauth-v2-1-13`), RFC 6750, RFC 8414, RFC 7591 (deprecated), RFC 8707, RFC 9728, RFC 9207, CIMD (-00), OIDC Discovery 1.0, OIDC Dynamic Client Registration 1.0.

> **Spec-lag uyarısı:** MCP `draft-ietf-oauth-v2-1-13` (Ekim 2025) ve `client-id-metadata-document-00`'a referans veriyor. Güncel sürümler **-16** ve **-02**. MCP, OAuth'un 3 revizyon gerisinden takip ediyor.

---

## 3. Authorization Server — normatif gereksinimler

### 3.1 MUST

| # | Gereksinim | Kaynak bölüm |
|---|---|---|
| AS-M1 | OAuth 2.1'i hem confidential hem public client'lar için uygun güvenlik önlemleriyle implemente etmeli | Overview §1 |
| AS-M2 | Şu keşif mekanizmalarından **en az birini** sağlamalı: RFC 8414 AS Metadata **veya** OIDC Discovery 1.0 | Overview §5 |
| AS-M3 | `iss` emit ediyorsa metadata'sında `authorization_response_iss_parameter_supported: true` ilan etmeli | Authorization Response Validation |
| AS-M4 | Tüm AS endpoint'leri **HTTPS** üzerinden sunulmalı | Communication Security |
| AS-M5 | Tüm redirect URI'ler ya `localhost` ya HTTPS olmalı | Communication Security |
| AS-M6 | Redirect URI'leri ön-kayıtlı değerlerle **tam eşleşme** ile doğrulamalı | Open Redirection |
| AS-M7 | User agent'ı güvenilmeyen URI'lere yönlendirmemek için önlem almalı (OAuth 2.1 §7.12.2) | Open Redirection |
| AS-M8 | Public client'lar için refresh token'ları **rotate etmeli** | Token Theft |
| AS-M9 | OIDC Discovery sunuyorsa `code_challenge_methods_supported` alanını metadata'ya **dahil etmeli** | Authorization Code Protection |
| AS-M10 | CIMD destekliyorsa CIMD §6 güvenlik implikasyonlarını dikkate almalı | CIMD Security |
| AS-M11 | CIMD: getirilen dokümanın `client_id`'si URL ile **tam eşleşmeli** | Client Registration |
| AS-M12 | CIMD: authorization request'teki `redirect_uri`'yi metadata dokümanındakilere karşı **doğrulamalı** | Client Registration |
| AS-M13 | CIMD: doküman yapısının geçerli JSON olduğunu ve zorunlu alanları içerdiğini doğrulamalı | Client Registration |
| AS-M14 | CIMD: yetkilendirme sırasında **redirect URI hostname'ini açıkça göstermeli** | Localhost Redirect URI Risks |
| AS-M15 | (Proxy AS'ler) Statik client ID kullanan MCP proxy sunucuları, üçüncü taraf AS'e yönlendirmeden **önce her dinamik kayıtlı client için kullanıcı onayı almalı** | Confused Deputy |

### 3.2 SHOULD / MAY

| # | Seviye | Gereksinim |
|---|---|---|
| AS-S1 | SHOULD | CIMD desteklemeli |
| AS-S2 | SHOULD | Authorization response'larında **hata response'ları dahil** `iss` içermeli (RFC 9207 §2) |
| AS-S3 | SHOULD | Kısa ömürlü access token issue etmeli |
| AS-S4 | SHOULD | URL formatlı `client_id` gördüğünde metadata dokümanını fetch etmeli |
| AS-S5 | SHOULD | Metadata'yı HTTP cache header'larına saygı göstererek cache'lemeli |
| AS-S6 | SHOULD | CIMD §6 güvenlik değerlendirmelerini takip etmeli |
| AS-S7 | SHOULD | Metadata fetch ederken **SSRF** risklerini dikkate almalı |
| AS-S8 | SHOULD | Yalnızca `localhost` redirect URI'si olan client'lar için **ek uyarı** göstermeli |
| AS-S9 | SHOULD | Yalnızca güvendiği redirect URI'lerine otomatik yönlendirme yapmalı |
| AS-A1 | MAY | DCR (RFC 7591) — *deprecated, yalnızca geriye uyumluluk* |
| AS-A2 | MAY | CIMD kabulü için domain tabanlı trust policy uygulayabilir |
| AS-A3 | MAY | Ek attestation mekanizmaları isteyebilir |

### 3.3 RFC 8707 hakkında önemli nüans

Spec, AS'in RFC 8707'yi desteklemesini **hiçbir yerde MUST yapmıyor**. MUST'lar client'a (`resource` gönder) ve RS'e (audience doğrula) düşüyor. Metin *"when the Authorization Server supports the capability"* diyor.

Ancak RS audience doğrulamak zorunda olduğu için, pratikte **AS'in RFC 8707 desteği fiilen zorunludur** — desteklemezseniz ekosistemde çalışmazsınız.

> **Sınıflandırma: "spec MUST'ı değil ama pazar MUST'ı".**

---

## 4. Resource Server — normatif gereksinimler

### 4.1 MUST

| # | Gereksinim |
|---|---|
| RS-M1 | **RFC 9728 Protected Resource Metadata implemente etmeli** |
| RS-M2 | PRM dokümanı **en az bir AS içeren `authorization_servers` alanını** içermeli |
| RS-M3 | Keşif mekanizmalarından birini implemente etmeli: (a) 401'de `WWW-Authenticate: Bearer resource_metadata="…"`, (b) well-known URI'de metadata |
| RS-M4 | Access token'ları OAuth 2.1 §5.2'ye göre doğrulamalı |
| RS-M5 | Token'ların **kendisi için** issue edildiğini doğrulamalı (RFC 8707 §2) |
| RS-M6 | Geçersiz/süresi dolmuş token'lara **HTTP 401** dönmeli |
| RS-M7 | **Yalnızca kendi kaynakları için geçerli** token'ları kabul etmeli |
| RS-M8 | Başka hiçbir token'ı **kabul etmemeli veya transit ettirmemeli** |
| RS-M9 | Request'i **işlemeden önce** token doğrulamalı |
| RS-M10 | Upstream API çağırıyorsa client'ın token'ını **pass-through yapmamalı** |
| RS-M11 | Scope hiyerarşilerini (geniş scope dar olanı kapsar) hesaba katmalı |
| RS-M12 | Tüm gelen request'leri doğrulamalı; **bir state handle'a sahip olmayı authentication saymamalı** |
| RS-M13 | `requestState` **saldırgan kontrollü girdi** olarak ele alınmalı; yetkilendirmeyi etkiliyorsa bütünlüğü korunmalı (HMAC/AEAD), doğrulaması başarısız state reddedilmeli |
| RS-M14 | Header değerleri body'deki karşılıklarıyla uyuşmuyorsa reddedilmeli (400 / `-32020 HeaderMismatch`) |
| RS-M15 | `Origin` header'ı mevcut ve geçersizse **403 Forbidden** dönmeli |
| RS-M16 | Sayfalı listelerde **tüm sayfalara aynı `cacheScope`** uygulanmalı |
| RS-M17 | Per-primitive erişim kontrolü uygulanmalı; **`cacheScope`'a tek başına güvenilmemeli** |
| RS-M18 | `ttlMs` değeri `>= 0` olmalı |
| RS-M19 | Bir sonraki istek için önceki isteklere dayalı bağlam çıkarılmamalı |

### 4.2 SHOULD

- `WWW-Authenticate`'te `scope` parametresi ile gerekli scope'ları belirtmeli (RFC 6750 §3)
- Yetersiz scope: **403 Forbidden** + `error="insufficient_scope"` + `scope="…"` + `resource_metadata`
- Bir operasyon için gereken **tüm scope'ları tek challenge'da** vermeli (artımlı challenge UX'i bozar)
- Scope dahil etme stratejisinde tutarlı olmalı
- `offline_access`'i `WWW-Authenticate` scope'una veya PRM `scopes_supported`'a **dahil ETMEMELİ** (SHOULD NOT) — refresh token bir kaynak gereksinimi değildir
- State handle'ları CSPRNG ile üretmeli ve sunucu tarafında authenticated user'a bağlamalı (`<user_id>:<handle>`; user ID **doğrulanmış token'dan** türetilmeli)
- Deterministik sırada tool döndürmeli (cache verimliliği)

---

## 5. Client ID Metadata Documents (CIMD)

### 5.1 IETF durumu

| Öğe | Değer |
|---|---|
| Güncel revizyon | **draft-ietf-oauth-client-id-metadata-document-02** |
| Yayın | **2026-07-06** · Sona erme 2027-01-07 · 20 sayfa |
| Yazarlar | Aaron Parecki (Okta), Emelia Smith |
| WG durumu | **WG Document (adopted)** — WGLC'de değil, IESG'de değil |
| RFC numarası | **YOK** |

Geçmiş: bireysel `draft-parecki-*` -00…-03 (2024-07 → 2025-07) → WG kabulü 2025-10-08 → WG -00 (12 s.) → -01 (2026-03-01, 14 s.) → **-02 (2026-07-06, 20 s.)**

### 5.2 -00 ↔ -02 farkı (bu dosyanın en operasyonel bulgusu)

MCP 2026-07-28 normatif olarak **-00**'a atıf yapıyor. -02'nin getirdiği, -00'da **bulunmayan** normatif kurallar:

| -02'deki yeni kural | Seviye |
|---|---|
| Özel amaçlı IP adreslerine (RFC 6890) fetch **yasak** | **MUST NOT** |
| HTTP redirect'leri **otomatik takip etme** | **MUST NOT** |
| Yanıt **200 OK olmalı**; diğer tüm status kodları hata | **MUST** |
| Simetrik secret tabanlı `token_endpoint_auth_method` **yasak** | **MUST NOT** |
| `client_secret` / `client_secret_expires_at` **yasak** | **MUST NOT** |
| Özel anahtar materyali **yasak** (yalnızca public key) | **MUST NOT** |
| Simple string comparison, **port normalizasyonu yok** | **MUST** |
| Privacy Considerations bölümü (§9) | yeni |

Bölüm numaraları da kaydı: MCP'nin "-00 §6" ve "-00 §6.2" atıfları -02'de **§8** ve **§8.2**.

**Uçuşta olan düzeltmeler:** PR #3235 "Use updated OAuth Client ID Metadata Document RFC" (2026-08-12, açık); SEP-3149 "Require Token Endpoint Auth Methods Supported in CIMD" (2026-07-28, açık).

> ### KARAR: -02'yi implemente et, -00 uyumluluğunu belgele.
> -02'nin MUST'ları katı bir üst kümedir; -00'a göre daha güvenlidir ve gelecekteki MCP revizyonuyla uyumlu olacaktır.

### 5.3 Client Identifier URL kuralları (§3)

- `https` scheme **MUST**
- userinfo bileşeni **MUST NOT**
- port **MAY**
- **path bileşeni MUST** — `https://example.com` geçersiz, `https://example.com/client.json` geçerli
- tek nokta / çift nokta path bileşenleri **MUST NOT**
- query bileşeni **SHOULD NOT**
- fragment **MUST NOT**

Karşılaştırma **basit string** (RFC 3986 §6.2.1): `https://example.com/client` ile `https://example.com:443/client` **eşdeğer değil**.

Ek rehberlik: kısa URL RECOMMENDED (kullanıcıya gösterilebilir); kararlı URL RECOMMENDED; URL kısaltıcılar **uygun değil** (redirect kullanırlar); `https://example.com/` gibi çıplak `/` path'i NOT RECOMMENDED.

**localhost, Client Identifier URL olarak kullanılamaz** (https zorunlu + §8.6 special-use IP yasağı). Asimetriye dikkat: `redirect_uris` içinde `http://localhost:3000/callback` sorunsuz; yasak olan **client_id URL'inin kendisi**.

### 5.4 Metadata doküman şeması

Taslak alan listesi vermiyor, toptan RFC 7591'e devrediyor:

> *"The client metadata values are the values defined in the OAuth Dynamic Client Registration Metadata OAuth Parameters registry … as established by [RFC7591]."*

**Tek açıkça REQUIRED alan (§4):**

> *"The Client ID Metadata Document **MUST contain a `client_id` property whose value MUST match the Client Identifier URL, which MUST also match the URL that the authorization server used to fetch the document**; comparisons MUST be made using simple string comparison."*

`redirect_uris` dolaylı olarak zorunlu (§4.2, RFC 9700 üzerinden). Redirect içermeyen grant'lar (client_credentials, token exchange) muaf.

**MCP'nin ek şartı:** doküman en az `client_id`, `client_name`, `redirect_uris` içermeli (MUST).

**AS metadata alanı:** `client_id_metadata_document_supported` (boolean).

> ⚠️ -02'de editoryal tutarsızlık: §6 "AS **MUST** include" derken IANA kaydı alanı "OPTIONAL" tanımlıyor. **Alan yokluğunu "desteklenmiyor" olarak yorumla**, "bilinmiyor" olarak değil.

**Açık TBD (-02):** *"We may want a property such as `client_id_expires_at` for indicating that the client is ephemeral."*

### 5.5 AS doğrulama gereksinimleri

**Fetch:**
- AS metadata dokümanını SHOULD otomatik fetch etsin, periyodik olarak SHOULD yeniden fetch etsin
- Doküman **200 OK ile sunulmalı**; diğer tüm HTTP status kodları **MUST** hata sayılmalı
- AS **HTTP redirect'leri otomatik takip ETMEMELİ** (MUST NOT)

**Doğrulama sırası:**
1. HTTP 200
2. Redirect takip edilmedi
3. Doküman `client_id` == Client Identifier URL == fiilen fetch edilen URL (simple string comparison)
4. Authorization request'teki `redirect_uri`, dokümandaki kayıtlı redirect URL'lerden biriyle **exact string match**

**Fetch başarısız olursa (§5.1):** AS authorization request'i **SHOULD abort** etsin (MUST değil).

> **En büyük interop tuzağı:** Origin/prefix eşleştirme **açıkça zorunlu değil.** §8.1 AS'in `redirect_uri`'yi CIMD ile aynı origin'e kısıtlayabileceğini söylüyor ama bu **opsiyonel** (Solid-OIDC geriye uyumluluğu için). Aynı doküman bir AS'te çalışıp diğerinde reddedilebilir.

**Taslakta AÇIKÇA BULUNMAYANLAR (varsayma):** HTTP metodu (GET ima ediliyor ama yazılmamış), Accept header şartı, TLS sürümü/sertifika doğrulama şartı, timeout, rate limiting, User-Agent rehberliği. Content-type ifadesi muğlak — baseline `application/json` şartı hiç belirtilmemiş.

### 5.6 Caching (§5.2, tam metin)

> *"The authorization server MAY cache the client metadata it discovers at the Client ID Metadata Document URL.*
> *The authorization server SHOULD respect HTTP cache headers [RFC9111] when caching client metadata, but MAY define its own upper and/or lower bounds on an acceptable cache lifetime as well.*
> *The authorization server MUST NOT cache error responses. The authorization server also MUST NOT cache documents which are invalid or malformed."*

Varsayılan TTL yok, ETag/revalidation rehberliği yok, stale-while-revalidate yok. §8.8: `logo_uri` içeriği SHOULD prefetch edilip cache'lenmeli. §9.1: her istekte fetch etmek kullanıcı aktivite zamanlamasını client'ın host'una sızdırır.

### 5.7 Güvenlik — SSRF ve DoS (§8)

**§8.6 SSRF — bölümün en güçlü normatif metni:**

> *"Authorization servers **MUST NOT fetch a Client ID Metadata Document URL or any URLs contained within a Client ID Metadata Document that resolve to special-use IP addresses as defined in [RFC6890]**."*
>
> *"Authorization servers deployed for development or testing purposes MAY relax this restriction to allow fetching from loopback addresses when the authorization server itself is also running on a loopback address … Authorization servers **MUST NOT apply this exception in production deployments**…"*
>
> *"Authorization servers SHOULD ensure they only fetch or parse URLs with known and supported URI schemes … if a client uses a URI scheme such as `javascript:` in a metadata property."*

**Kritik:** RFC 6890 kuralı **doküman içindeki URL'leri de kapsar** (`jwks_uri`, `logo_uri`, `policy_uri`, `tos_uri`) — sadece client_id URL'ini değil.

**§8.7 Maximum Response Size:**

> *"authorization servers **SHOULD limit the amount of data they read and process** … **The recommended maximum size to read is 5 kilobytes.**"*

-02 changelog notu: sınır **okunan veri miktarına** uygulanır, dosya boyutuna değil → **`Content-Length`'e güvenme, okumayı kes.**

**Diğer §8 maddeleri:**
- **§8.1** redirect_uri ↔ client_id ilişkisi: kısıtlama opsiyonel. Kısıtlama olmadan client'ın daha tanınmış bir client'ı taklit etmesi mümkün
- **§8.2** Client Authentication: simetrik secret imkânsız. `private_key_jwt` bildirilirse AS **MUST** RFC 7523 §2.2 uyarınca client auth zorunlu kılsın. Attestation-based client auth ve SPIFFE client auth draft'ları referans veriliyor
- **§8.3** Client Identifier URL değişimi: değişen URL **tamamen yeni bir client**'tır. *"loss of control over the URL — for example through domain expiry or reassignment — would allow a third party to assume the client's identity."*
- **§8.4** Metadata değişimi: dokümanlar client kontrolünde ve değişebilir. AS `redirect_uris`, `token_endpoint_auth_method`, `scope`, `grant_types`, `jwks`, `client_name`, `logo_uri` değişiminde mevcut grant'ları geçersiz kılmayı veya yeniden onay istemeyi seçebilir
- **§8.5** Phishing: AS **SHOULD** `client_id` **hostname'ini** authorization arayüzünde göstersin
- **§8.9** Domain Trust: ilk 100 kullanıcı için ek uyarı ekranı; domain reputation/yaş kontrolleri; `*.example.com` allowlist'leri
- **§8.10** CIMD Services: barındırılan CIMD servisi statik client kaydı proxy'si gibi davranır; bu tür client'lar kullanıcıya **görsel olarak ayırt ettirilmeli**
- **§9 Privacy** (-02'de yeni): AS fetch'leri kullanıcı aktivitesini sızdıran yan kanaldır; `logo_uri`/`jwks_uri` cross-domain tracking fırsatı yaratır

**§8'de HİÇ ele alınmayanlar:** AS'in client host'una karşı DoS/amplification, fetch rate limit, timeout, eşzamanlılık sınırı, metadata cache poisoning. **Tamamen implementer sorumluluğu.**

### 5.8 MCP'nin CIMD SSRF ek rehberliği

MCP security best practices, taslağın boşluklarını kapatıyor:

- **HTTPS zorunlu** (loopback yalnızca geliştirmede, açık opt-out ile)
- **Engellenecek aralıklar:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `169.254.0.0/16` (bulut metadata), `fc00::/7`, `fe80::/10`
- **Spec'in kendi uyarısı:** *"Avoid implementing IP validation manually. Attackers exploit encoding tricks (octal, hex, IPv4-mapped IPv6) that custom parsers often miss."*
- **Redirect hedefleri** aynı doğrulamaya tabi
- **Egress proxy** kullan — Stripe'ın `Smokescreen`'i isim olarak veriliyor
- **DNS TOCTOU:** *"An attacker's domain may resolve to a safe IP during validation but to an internal IP during the actual request. Consider pinning DNS resolution results between check and use."*

### 5.9 CIMD vs DCR — karşılaştırma

**CIMD'nin çözdükleri:**
- Sınırsız client kaydı yok — AS hiçbir şey yazmaz, kimlik bir URL'dir
- Kayıt endpoint'i DoS yüzeyi yok
- **AS'ler arası taşınabilir kimlik** — *"No re-registration is needed when the authorization server changes."*
- Kimlik **domain kontrolüne** demirlenmiş → denetlenebilir, reputation anlamlı
- **Paylaşılan secret yok** — confidential client yolu `private_key_jwt` + yayımlanmış JWKS

**CIMD'nin getirdiği yeni problemler:**
- **Outbound fetch = AS'te SSRF yüzeyi.** DCR'da outbound fetch yok
- **Değişken kimlik** — metadata client kontrolünde, onaydan sonra değişebilir
- **Erişilebilirlik bağımlılığı** — her authorization üçüncü taraf bir HTTPS host'un ayakta olmasına bağlı olabilir
- **Domain ömrü riski** — domain süresi dolarsa client kimliği onu satın alana geçer
- **Impersonation/phishing çözülmedi** — same-origin redirect_uri zorunluluğu opsiyonel olduğu için
- **Privacy yan kanalı**
- **Yerel geliştirmeye düşman** — localhost client_id yok
- **Client host'una okuma amplifikasyonu** — taslakta hiç ele alınmamış

### 5.10 DCR neden terk edildi

Kaynak: `blog.modelcontextprotocol.io/posts/client_registration/` (22 Ağustos 2025, Paul Carleton, Core Maintainer)

**AS'ler için:**
- **Sınırsız veritabanı büyümesi** — kayıtlar taşınabilir değil; Claude Desktop'ı Windows'ta sonra macOS'ta kullanmak **iki ayrı kayıt** yaratır
- **Client expiry "kara deliği"** — bir client'a ID'sinin geçersiz olduğunu **open redirect açığı yaratmadan** söylemenin yolu yok
- **Instance başına karmaşa** — aynı uygulama için "rhyme or reason olmadan yüzlerce, hatta binlerce kayıt"
- **DoS** — kimlik doğrulamasız `/register` endpoint'i AS veritabanına **yazar**

**Sayısal gerçeklik** *(ikincil kaynak, doğrulanmadı)*: Obsidian Security taramasında 660 AS'ten yalnızca **27'si (%4)** DCR destekliyordu; 78'den yalnızca **3'ü** CIMD.

### 5.11 Client kayıt öncelik sırası (SHOULD)

1. Sunucu için **ön-kayıtlı** client bilgisi varsa onu kullan
2. AS metadata'sında `client_id_metadata_document_supported: true` varsa **CIMD**
3. AS'te `registration_endpoint` varsa **DCR** (fallback)
4. Başka seçenek yoksa **kullanıcıya sor**

---

## 6. RFC 9728 — Protected Resource Metadata

### 6.1 Alanların tamamı

| Alan | RFC seviyesi | MCP notu |
|---|---|---|
| `resource` | **REQUIRED** | Canonical MCP server URI'si. RFC 8707 `resource` ile hizalı olmalı |
| `authorization_servers` | OPTIONAL (RFC) | **MCP'de MUST** ve **en az bir eleman** |
| `jwks_uri` | OPTIONAL | RS'in kendi imza anahtarları (response imzalama). Token doğrulama anahtarları **değil**. HTTPS zorunlu |
| `scopes_supported` | RECOMMENDED | MCP: *"temel işlevsellik için gereken minimal scope kümesi"*. Tüm katalog değil |
| `bearer_methods_supported` | OPTIONAL | `["header"]` / `["body"]` / `["query"]`. MCP query'yi yasakladığı için pratikte `["header"]` |
| `resource_signing_alg_values_supported` | OPTIONAL | `none` **MUST NOT** |
| `resource_name` | RECOMMENDED | Son kullanıcıya gösterilecek isim |
| `resource_documentation` | OPTIONAL | |
| `resource_policy_uri` | OPTIONAL | |
| `resource_tos_uri` | OPTIONAL | |
| `tls_client_certificate_bound_access_tokens` | OPTIONAL, default `false` | mTLS bound token (RFC 8705) |
| `authorization_details_types_supported` | OPTIONAL | RAR (RFC 9396) |
| `dpop_signing_alg_values_supported` | OPTIONAL | **Yol haritasında DPoP var — planla** |
| `dpop_bound_access_tokens_required` | OPTIONAL, default `false` | |
| `signed_metadata` | OPTIONAL (§2.2) | JWS ile imzalı metadata |

`resource_name`, `resource_documentation`, `resource_policy_uri`, `resource_tos_uri` **BCP47 dil etiketiyle çoğullanabilir**: `resource_name#tr-TR`.

### 6.2 Well-known URI oluşturma (§3, §3.1)

Well-known string **host bileşeni ile path/query arasına** eklenir:

| Resource identifier | Metadata URL |
|---|---|
| `https://mcp.example.com` | `https://mcp.example.com/.well-known/oauth-protected-resource` |
| `https://mcp.example.com/mcp` | `https://mcp.example.com/.well-known/oauth-protected-resource/mcp` |
| `https://example.com/public/mcp` | `https://example.com/.well-known/oauth-protected-resource/public/mcp` |

- Host'tan sonraki **sonlandırıcı slash kaldırılmalı** (MUST) ekleme yapılmadan önce
- **HTTP GET** ile sorgulanmalı (MUST)
- Başarılı yanıt: **200 OK**, `application/json`
- Bu `.well-known` kullanımı RFC 8615'ten farklıdır: host hakkında genel bilgi vermez, **host başına birden fazla kaynağı desteklemek içindir** (multi-tenant)

Client'ın fallback sırası: (1) `WWW-Authenticate`'teki `resource_metadata`, (2) alt-path well-known, (3) kök well-known.

### 6.3 RFC 9728 güvenlik notları

- **§7.3 Impersonation:** Client, metadata'daki `resource` değerinin kullandığı resource identifier ile **tam eşleştiğini doğrulamalı** (MUST)
- **§7.4:** Audience-restricted token'lar ve RFC 8707 RECOMMENDED. Aksi halde kötü niyetli RS1, client'ı RS2'nin scope'uyla token almaya ikna edip o token'ı RS2'de yeniden kullanabilir
- **§7.6:** PRM'deki `authorization_servers` ile AS metadata'sındaki kaynak listesi çapraz kontrol edilmeli
- **§7.7 SSRF:** Client'lar iç IP aralıklarına isteği SHOULD engellemeli
- **§7.10:** `Cache-Control: max-age` önerilir

---

## 7. RFC 8707 — Resource Indicators

### 7.1 `resource` parametresi kuralları

- Değer **mutlak URI** olmalı (RFC 3986 §4.3)
- **Fragment bileşeni içermemeli** (MUST NOT)
- Query bileşeni içermemeli (SHOULD NOT) — ama uygulamayı kapsamlandırmak için gerekli olabileceği kabul ediliyor
- **Birden fazla `resource` parametresi** kullanılabilir
- Hata kodu: **`invalid_target`**

### 7.2 AS'in yükümlülüğü

> *"The authorization server **SHOULD** audience-restrict issued access tokens to the resource(s) indicated by the `resource` parameter."*

- JWT'de `aud` claim'i ile, introspection'da (RFC 7662) aynı isimli top-level member ile iletilir
- AS, `resource` değerini aynen audience olarak kullanabilir **veya** daha genel bir URI'ye map'leyebilir
- Client `resource` göndermezse AS belirli bir kaynak olmadan veya varsayılan bir kaynakla işleyebilir — alternatif olarak zorunlu kılabilir

### 7.3 MCP canonical URI kuralları

**Geçerli:** `https://mcp.example.com/mcp` · `https://mcp.example.com` · `https://mcp.example.com:8443` · `https://mcp.example.com/server/mcp`
**Geçersiz:** `mcp.example.com` (scheme yok) · `https://mcp.example.com#fragment`

- Client mümkün olan **en spesifik URI'yi** vermeli (SHOULD)
- Canonical form lowercase scheme/host kullanır, ancak implementasyonlar sağlamlık için **uppercase kabul etmeli** (SHOULD)
- Trailing slash'siz form tercih edilmeli (SHOULD)

> **Tasarım kararı:** AS'te `resource` değerlerini **kayıtlı protected resource'lara karşı doğrula** ve bilinmeyenler için `invalid_target` dön. Aksi halde AS keyfi audience'lı token üreten bir oracle'a dönüşür.

---

## 8. RFC 9207 — `iss` doğrulaması (SEP-2468)

**Cevap: AS için SHOULD, client için MUST.**

SEP-2468 "Recommend Issuer (iss) Parameter in MCP Auth Responses" — **Final**, Standards Track, 2026-03-25, yazar @EmLauber, sponsor @pcarleton, PR #2468.

- AS: *"MCP authorization servers **SHOULD** include the `iss` parameter in authorization responses, **including error responses**."*
- AS: `iss` emit ediyorsa `authorization_response_iss_parameter_supported: true` ilanı **MUST**
- Client: RFC 9207 §2.4 doğrulamasını **MUST** uygular

**Client karar tablosu:**

| `authorization_response_iss_parameter_supported` | Response'ta `iss` | Client davranışı |
|---|---|---|
| `true` | var | Kaydedilen issuer ile **basit string karşılaştırması** (RFC 3986 §6.2.1) |
| `true` | yok | **Reddet** |
| `false` / yok | var | Kaydedilen issuer ile karşılaştır (yerel politika) |
| `false` / yok | yok | Devam et |

**Kritik karşılaştırma kuralı:** Client'lar `iss` değerini decode ettikten sonra **scheme/host case folding, default-port elision, trailing-slash veya percent-encoding normalizasyonu UYGULAMAMALI** (MUST NOT).

> **Sonuç: AS'imiz metadata'daki `issuer` ile byte-identical bir `iss` emit etmeli.** `https://as.example.com` ile `https://as.example.com/` farklı sayılır.

**Spec'in dürüst uyarısı (Mix-Up Attacks):**

> *"PKCE alone does not prevent this attack because the client transmits the `code_verifier` to the attacker's token endpoint. **Resource indicators do not help** when the attacker's authorization server is intercepting requests before they hit the honest authorization server. This mitigation depends on honest authorization servers emitting `iss`; it provides no protection against an honest server that does not."*

> **`iss` emit etmezsek, bizimle konuşan HER client mix-up saldırısına açık kalır.**

**Gelecek:** *"A future revision of this specification is expected to upgrade authorization server inclusion of `iss` from **SHOULD** to **MUST**."*

**Neden `iss`, per-issuer redirect URI değil?** SEP-2468 gerekçesi: benzersiz redirect URI'ler *"CIMD ile mümkün değil ve DCR ile operasyonel olarak pahalı."*

---

## 9. `application_type` ve loopback redirect (SEP-837)

**SEP-837:** "Update authorization spec to clarify client type requirements", @localden, PR #837 (2025-06-24 açıldı, 2026-07-28'de indi). *SEP-1850 öncesi olduğu için ayrı SEP sayfası yok; statü "merged".*

### 9.1 Sorun

OIDC DCR'da `application_type` atlanırsa varsayılan **`"web"`**'dir. OIDC `"web"` client'ları için redirect URI'lerin HTTPS olmasını ve **localhost OLMAMASINI** şart koşar. MCP client'larının çoğu native/CLI olduğu ve `http://localhost:PORT/callback` kullandığı için kayıt **sessizce reddedilir**.

### 9.2 Çözüm

- Client'lar DCR sırasında uygun `application_type` **MUST** belirtmeli
- Native (masaüstü, mobil, CLI, localhost üzerinden erişilen yerel web uygulamaları) → `"native"` (SHOULD)
- Uzak tarayıcı tabanlı → `"web"` (SHOULD)
- Client'lar redirect URI kısıtlarından kaynaklanan kayıt hatalarını MUST ele alabilmeli; anlamlı hata yüzeye çıkarılmalı (SHOULD)
- Non-OIDC sunucular parametreyi güvenle yok sayar

### 9.3 Kapsam sınırı ve gerçek dünya

`application_type` gereksinimi spec'te **yalnızca DCR bölümünün altındadır. CIMD için zorunluluk YOKTUR.** Ama pratikte gerekiyor:

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

> **AS'imiz CIMD dokümanlarında da `application_type` alanını okuyup dikkate almalı.**

### 9.4 Loopback port eşleştirme — kritik interop kuralı

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

Claude Code redirect URI'lerini **portsuz** bildiriyor ve çalışma zamanında `http://localhost:3118/callback` gibi geçici bir porta bağlanıyor. Anthropic dokümantasyonu (`claude.com/docs/connectors/building/authentication`):

> *"your authorization server must accept both with the **port component ignored**. RFC 8252 section 7.3 requires this for the IP-literal form (`127.0.0.1`); apply the same port-agnostic match to `localhost` so Claude Code works, even though RFC 8252 section 8.3 discourages `localhost`."*

**Bu, CIMD -02'nin "simple string comparison / exact match" kuralıyla doğrudan çelişir.**

> ### KARAR: Loopback redirect URI'ler için özel eşleştirme kuralı
> - Scheme, host ve path **tam eşleşmeli**
> - Host `localhost` / `127.0.0.1` / `[::1]` ise **port bileşeni yok sayılmalı**
> - Loopback olmayan URI'lerde **hiçbir gevşetme yapılmamalı**

---

## 10. Stateless çekirdek ve `cacheScope`

### 10.1 Ne değişti (SEP-2575, SEP-2567)

- `initialize` / `notifications/initialized` **kaldırıldı**
- **`Mcp-Session-Id` header'ı kaldırıldı.** Modern sunucu legacy trafiğe: *"ignore it, and do not mint or echo session IDs."* HTTP GET/DELETE → **405**. `Last-Event-ID` yok sayılır, stream'ler resumable değil
- Her request `_meta` içinde protokol sürümünü ve client capability'lerini taşır: `io.modelcontextprotocol/protocolVersion` (zorunlu), `io.modelcontextprotocol/clientCapabilities` (zorunlu), `io.modelcontextprotocol/clientInfo` (opsiyonel)
- **`server/discover`** eklendi: sunucular MUST implemente etsin

Spec metni (`basic/index` §Statelessness):
> *"Servers **MUST NOT** rely on prior requests over the same connection to establish context (e.g., capabilities, protocol version, client identity)."*

### 10.2 Auth'a doğrudan etkisi

`2025-11-25` metni:
> *"authorization **MUST** be included in every HTTP request from client to server, **even if they are part of the same logical session**."*

`2026-07-28` metni:
> *"authorization **MUST** be included in every HTTP request from client to server."*

"Aynı mantıksal oturum" kaçış kapısı **silindi**, çünkü artık oturum yok.

> **Pratik sonuç: principal'ı asacak bir oturum nesnesi kalmadı. Her POST bağımsız, kendi kendini tanımlayan, bağımsız yetkilendirilebilir bir birimdir.**

**`clientInfo` / `serverInfo` güvenlik için kullanılamaz:**
> *"self-reported by the sender and are not verified by the protocol… **SHOULD NOT** rely on them for security decisions."*

Aynı şekilde `clientCapabilities` her istekte client tarafından iddia edilir — **feature negotiation girdisidir, authentication girdisi değildir**.

### 10.3 State Handle Hijacking — yeni saldırı sınıfı

`Session Hijacking` bölümünün yerini aldı. Saldırı:
1. Sunucu authenticated bir kullanıcı için state handle üretir ve tool sonucunda döner
2. Saldırgan handle'ı ele geçirir veya tahmin eder
3. Saldırgan handle'ı tool argümanı olarak geçer
4. Sunucu handle'ın çağırana ait olup olmadığını kontrol etmez → yetkisiz erişim

**Azaltmalar:**
- Sunucular tüm gelen istekleri **MUST** doğrulasın
- Bir state handle'a sahip olmayı **authentication saymamalı** (MUST NOT)
- CSPRNG ile güvenli, deterministik olmayan handle'lar (SHOULD)
- Handle'ları sunucu tarafında authenticated user'a bağlasın: `<user_id>:<handle>`, user ID **doğrulanmış token'dan** türetilmeli

`tools` sayfası: *"a handle is a name, not a capability."*

Vahşi doğada gerçekleşti: **CVE-2026-67431** (MCP Ruby SDK, "session poisoning with missing session owner binding") ve **CVE-2026-67430** (unbounded session retention DoS). *(Aggregator kaynaklı, NVD'de doğrulanmadı.)*

### 10.4 `ttlMs` / `cacheScope` (SEP-2549) — gizli yetkilendirme kararı

SEP-2549 "TTL for List Results" — Final, Standards Track, 2026-04-09, @CaitieM20, PR #2549.

**Kapsam:** `CacheableResult` arayüzü şu sonuçlarda zorunlu: `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `resources/read`. MRTR retry'ları **MUST NOT** cache'lensin.

**`ttlMs`:** milisaniye tamsayı, `Cache-Control: max-age` benzeri. `0` = hemen bayat. Yoksa `0` varsayılır. Negatifse `0` sayılır. Sunucular `>= 0` **MUST** versin.

> **`no-store` / `must-revalidate` karşılığı YOK.** "Cache'leme" demenin tek yolu `ttlMs: 0` ve o da **SHOULD seviyesinde bir ipucudur**, yasak değil.

**`cacheScope` — yalnızca iki değer var:**

| Değer | Spec metni |
|---|---|
| `"public"` | *"The response does not contain user-specific data. Any client, shared gateway, or caching proxy **MAY** store and serve the cached response to any user."* |
| `"private"` | *"Cached responses **MAY** be reused for the same authorization context. **Caches MUST NOT be shared across authorization contexts (e.g. a different access token requires a different cache).**"* |

**Per-user / per-token / per-session enum değeri YOKTUR.** İzolasyon birimi **authorization context / access token**.

**Spec'in kendi açık uyarısı:**

> *"Servers MUST be aware that responses with a `"public"` `cacheScope` may be shared between callers **even if the Result is coming from an authenticated endpoint**. For example, the Result from an authenticated `tools/list` call with a `"public"` `cacheScope` may be cached by a client and may be shared outside of the initial request's authorization context."*
>
> Sunucular *"**MUST** apply appropriate per-primitive access controls, and **MUST NOT** rely on `cacheScope` alone."*

Ek tuzak: *"Servers **MUST** apply the same `cacheScope` to all response pages for a given list request."*

**`tools/list` yetkilendirmeye göre değişebilir** (`server/tools` spec'i):
> *"The set **MAY** vary by the authorization presented on the request … since credentials are per-request input, not connection state."* (Ama *"**MUST NOT** vary per-connection."*)

> ### KESİN KURAL
> **`tools/list` (veya herhangi bir liste) scope/entitlement/tenant'a göre filtreleniyorsa — ki stateless per-token modelde tam olarak öyle olur — `cacheScope: "private"` emit ETMEK ZORUNDAYIZ.**
>
> Tek bir yanlış etiketlenmiş `"public"`, tool yüzeyimizin **protokolce onaylanmış cross-tenant ifşasıdır.**
>
> Dikkat: `server/discover` de cache'lenebilir ve **spec'in kendi örneği onu `"public"` işaretliyor**. Capability ilanımız token'a göre değişiyorsa o örnek bizim için yanlıştır.

### 10.5 `server/discover` auth muafiyeti var mı?

**Hayır — ve bu bir belirsizlik.** `server/discover.md` içinde auth/401 ile ilgili hiçbir normatif ifade yok. Sıradan bir JSON-RPC metodudur ve "authorization MUST be included in every HTTP request" kuralına tabidir. Spec onu kimlik doğrulamasız bootstrap endpoint'i olarak **muaf tutmuyor**.

Pratik bootstrap akışı:
```
kimlik doğrulamasız server/discover (veya herhangi bir RPC)
  → 401 + WWW-Authenticate: Bearer resource_metadata="…"
  → RFC 9728 PRM
  → AS keşfi
```

Kimlik doğrulamasız bir capability probe istiyorsak bu kararı kendimiz vermeliyiz ve `server/discover` sonucunun token'a göre değişmediğinden emin olmalıyız.

### 10.6 Çözülmemiş boşluk: uzun ömürlü stream'de token süresi

`subscriptions/listen`, yanıtı açık SSE stream'i olan tek uzun ömürlü istektir. `basic/patterns/subscriptions.md` dosyasında **"token", "auth", "expire", "401" kelimelerinin hiçbiri geçmiyor** (0 eşleşme ile doğrulandı).

**Spec tamamen sessiz.** Öneri: token süresi dolduğunda stream'i kapat, client yeniden bağlansın — spec zaten *"the server holds no subscription state across reconnections"* diyor.

---

## 11. MRTR ve `requestState`

**SEP-2322**, Final, 2026-02-03.

Sunucular artık client'a JSON-RPC **isteği** gönderemez:
> *"Servers **MUST** send server-to-client requests (such as `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the MRTR pattern. The previous pattern of server-initiated requests is no longer supported. This is a breaking change."*

Bunun yerine sunucu `resultType: "input_required"` ile `InputRequiredResult` döner: `inputRequests` (sunucu tarafından atanan anahtar → `ElicitRequest` | `CreateMessageRequest` | `ListRootsRequest`) ve/veya opak `requestState`. Client girdiyi toplayıp **orijinal isteği yeni bir JSON-RPC id ile yeniden POST eder**, `inputResponses` + `requestState` ekleyerek.

Yalnızca `prompts/get`, `resources/read`, `tools/call` üzerinde izinli.

**`requestState` — güvenlik kritik:**
> *"servers **MUST** treat `requestState` as an attacker-controlled input. If `requestState` influences authorization, resource access, or business logic, servers **MUST** protect its integrity (e.g. HMAC or AEAD) and **MUST** reject state that fails verification."*

> ### KARAR: `requestState` imzalı/AEAD, `(sub, client_id, resource, original_request_hash)`'e bağlı, kısa TTL, tek kullanımlık takip.

---

## 12. Güvenlik tuzakları — öncelik sırasına göre

Gerçek dünyada insanları en çok ele geçiren sıraya göre.

### 12.1 Consent (1 numaralı gerçek başarısızlık)

1. Sunucu tarafı consent registry, `(user_id, client_id, resource, scopes)` — **herhangi bir upstream redirect'ten ÖNCE** kontrol edilir
2. **Consent cookie'sini/oturumunu kullanıcı onaya tıklamadan ÖNCE ASLA set etme.** Bu tek sıralama hatası, confused deputy saldırısının tamamıdır
3. `state`: CSPRNG, yalnızca consent sonrası sunucu tarafında saklanır, callback'te tam eşleşme doğrulanır, doğrulamadan sonra silinir, ≤10 dk TTL
4. Consent cookie: `__Host-` + `Secure` + `HttpOnly` + `SameSite=Lax` + imzalı + **belirli `client_id`'ye bağlı**
5. Consent'i **authenticated user identity'ye** bağla, anonim tarayıcı oturumuna değil (Obsidian cookie-injection bypass'ı)
6. Consent sayfası: client adı, tam scope'lar, `redirect_uri` hostname'i, CSRF token, `frame-ancestors 'none'`
7. Scope farkı → yeniden consent. Consent iptali → **canlı access ve refresh token'lar** geçersiz

### 12.2 Client kimliği

8. `redirect_uri` **hem `/authorize` hem token exchange'de**, **yalnızca tam string eşleşme** (CVE-2025-4143 yalnızca exchange'de doğruluyordu). Loopback port'u tek istisna
9. Redirect_uri politikası sıkılaştırması **önceden var olan kayıtları geriye dönük geçersiz kılmalı** (Square dersi)
10. CIMD: `client_id` https + path; doküman `client_id`'si URL ile tam eşleşmeli; redirect_uri dokümanda olmalı; HTTP cache header'a saygı
11. **CIMD fetcher'ını SSRF'e karşı sertleştir:** yalnızca HTTPS, engellenmiş private/link-local/loopback aralıklar (v4+v6), otomatik redirect takibi yok, **check ile use arasında DNS pinleme**, timeout, 5 KB okuma sınırı, per-client rate limit, tercihen egress proxy. **Vetted bir crate kullan; IP parsing'i elle yazma**
12. CIMD için domain trust policy: allowlist / reputation / domain yaşı katmanları; **CIMD hostname'ini belirgin göster**
13. Yalnızca loopback redirect'li client'lar için ek uyarı, asla sessiz onay
14. DCR endpoint'i tutuyorsak: sıkı rate limit (IP + tenant), kayıt üst sınırı, kullanılmayanların temizliği, wildcard/pattern redirect_uri reddi

### 12.3 Token'lar

15. `resource`'ı onurlandır; tek ve doğru `aud` damgala; kayıtsız `resource` değerlerini reddet
16. **Asla audience'sız veya çoklu-audience token verme. Asla upstream token'ı kendi token'ın gibi kabul etme**
17. **RFC 9207 `iss` emit et**
18. PKCE S256 zorunlu; `code_challenge_methods_supported` ilan et; PKCE'yi kod yolu seviyesinde **atlanamaz** yap (CVE-2025-4144 bir atlama idi)
19. Kısa ömürlü access token; public client'lar için refresh token rotasyonu
20. **Atomik tek kullanımlık authorization code redemption** (CAS, read-then-write değil). Stateless retry'lar çift-redemption'ı rutin yapıyor; oradaki bir race code-replay açığıdır

### 12.4 Stateless dönem

21. Bir state handle'ı / `requestState`'i asla authentication sayma. Sunucu tarafında token'dan türetilen `user_id`'ye bağla; CSPRNG handle'lar; süre sınırı
22. Yetkilendirme kararını etkileyebilen her `requestState`'i **imzala ve audience'a bağla**
23. Gateway arkasındaysak: **body otoritedir**; header/body uyuşmazlığını reddet; protokol sürüm header'ını iste ve doğrula; `Mcp-Param-*`'da sır tutma; header değerlerinde CR/LF yasak; **base64 sentinel'i karşılaştırmadan önce decode et**
24. **`cacheScope`'u bir yetkilendirme kararı olarak ele al**
25. **Multi-tenancy:** Asana olayı egzotik bir saldırı değil, düz bir izolasyon mantık hatasıydı. Cross-tenant okumaları açıkça test et

### 12.5 Vahşi doğadaki CVE'ler

> ⚠️ Aşağıdaki tablo **aggregator kaynaklıdır**. NVD ve CVE.org detay sayfaları JS SPA olduğu için doğrudan doğrulanamadı. Alıntılamadan önce NVD JSON API ile teyit edin: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`

| CVE | Bileşen | Kusur |
|---|---|---|
| CVE-2026-27124 | `fastmcp < 3.2.0` | OAuth proxy callback'te consent doğrulaması eksik → confused deputy (CWE-441) |
| CVE-2026-31944 | LibreChat | MCP OAuth callback hesap ele geçirme |
| CVE-2026-42073 | OpenClaude | OAuth callback CSRF `state` bypass |
| CVE-2026-62800 | FastMCP | OAuth callback'te reflected XSS |
| CVE-2026-42230 | n8n | MCP OAuth open redirect |
| CVE-2026-46549 | NocoDB MCP | OAuth token scope bypass |
| CVE-2026-49291 | mcp-memory-service | OAuth read-scope `tools/call` bypass |
| CVE-2026-25536 | **MCP TypeScript SDK** | Paylaşılan server/transport yeniden kullanımı ile cross-client veri sızıntısı |
| CVE-2026-67430 / -67431 | **MCP Ruby SDK** | Sınırsız oturum tutma DoS; session owner binding eksikliğiyle session poisoning |
| CVE-2026-12112 | foreman-mcp-server | Gizli olmayan session ID ile session hijacking |
| CVE-2026-77822 / -18905 | IBM ContextForge MCP Gateway | DNS rebinding |
| CVE-2026-81315 | ash_ai MCP HTTP transport | DNS rebinding, `X-Forwarded-Proto` origin doğrulaması eksik |
| CVE-2026-24052 | `@anthropic-ai/claude-code` | WebFetch güvenilir domain doğrulama bypass'ı |
| CVE-2026-32625 | LibreChat | MCP sunucu URL değişken interpolasyonu `JWT_SECRET`, `CREDS_KEY`, `MONGO_URI` sızdırıyor |

**Toplu istatistikler** *(aggregator, doğrulanmadı)*: `mcp-security-project/mcp-cve-project` indeksi 570+ MCP CVE'si iddia ediyor. Temmuz 2025 taraması: **1.862 herkese açık MCP instance'ı kimlik doğrulamasız yanıt veriyordu**, yalnızca **%8,5'i OAuth kullanıyordu**.

**Ölçüm çalışması** (arXiv:2605.22333, 21 Mayıs 2026, Fudan): 7.973 canlı uzak MCP sunucusu → **%40,55'i hiçbir auth olmadan tool açıyor**; OAuth'lu 119 sunucunun **%100'ünde en az bir kusur** (toplam 325); **%96,6 DCR kusuru**.

**CVE olmayan olay — Asana cross-tenant veri ifşası:** Özellik 2025-05-01'de yayınlandı, bug 2025-06-04'te bulundu, erişim 2025-06-17'de geri verildi. **Deneysel MCP sunucusundaki bir tenant izolasyon mantık hatası** ~1.000 organizasyon arasında görev verisi, proje metadata'sı, ekip detayları, yorumlar ve dosyaları ifşa etti. İhlal değil, prompt injection değil — **düz bir multi-tenancy authorization bug'ı.**

### 12.6 Güvenlik araştırması yapanlar

- **Doyensec, "The MCP AuthN/Z Nightmare" (2026-03-05)** — en iyi auth-spesifik eleştiri. ID-JAG/kurumsal model analizi: (1) erişim geçersizleştirme veya token iptal mekanizması yok; (2) *"The IdP issues an ID Token with no scopes embedded"* → yüksek riskli scope'lar için **hiçbir consent pop-up tetiklenmiyor**; (3) `audience`'ın `resource` tanımlayıcısına bağlandığının doğrulanması eksik → **scope namespace collision** ve **resource identifier injection**; (4) **ID-JAG replay amplification** — tek bir JAG ile birçok access token; **tek kullanımlık `jti` zorla**
- **Trail of Bits** — line jumping (2025-04-21), `mcp-context-protector`
- **Invariant Labs** — tool poisoning PoC, GitHub MCP exploit, **Toxic Flow Analysis** (tek tek yetkili tool çağrılarının kompozisyonu üzerine akıl yürüten ilk ilkeli yaklaşım), `mcp-scan`
- **Obsidian Security** — Square one-click ATO, token passthrough, anonim oturum state binding, cookie injection
- **Cloudflare** (2026-08-14) — `MCP-Protocol-Version` header'ı ile protokol tespiti; "shadow MCP" tespiti. **DCR deprecate edildiği için MCP Portals'a ön-kayıtlı OAuth client desteği eklediler**
- ⚠️ **NSA/CISA** — "Model Context Protocol (MCP): Security Design" CSI PDF'i `media.defense.gov`'da 2026-06-02 tarihli göründü ama **açılamadı**. Okumaya değer

---

## 13. Ekosistem

### 13.1 Resmî SDK'lar

**TypeScript** — npm `@modelcontextprotocol/sdk` **1.30.0** (`LATEST_PROTOCOL_VERSION = '2025-11-25'`). `main` branch'i **2.0.0-alpha.0**.

- **Tüm AS implementasyonu `packages/server-legacy/`'ye taşındı** (§1 stratejik sinyal)
- `protocolEras.ts` ile `'legacy'` (≤2025-11-25) vs `'modern'` (2026-07-28+) ikili çekirdek
- RFC 9207 client tarafında **tam implemente edilmiş** (`packages/client/src/client/auth.ts`, 2.527 satır); spec'in karar tablosu birebir kodlanmış, ayrı `IssuerMismatchError` sınıfı var
- CIMD: `OAuthClientProvider.clientMetadataUrl`, `metadata.client_id_metadata_document_supported === true` koşuluna bağlı

**Python** — PyPI `mcp` **2.2.0**. TS'in aksine **AS implementasyonunu koruyor** (`src/mcp/server/auth/handlers/*`).

`TokenVerifier` çıplak bir `Protocol`:
```python
class TokenVerifier(Protocol):
    async def verify_token(self, token: str) -> AccessToken | None: ...
```
**Yerleşik JWT veya introspection doğrulayıcısı YOK.** Audience zorlaması `AuthSettings.validate_token_resource` ile opt-in. DPoP yalnızca **bildirimsel AS-metadata alanları** olarak var — hiçbir şey zorlamıyor.

> **Her iki resmî SDK da PAR (RFC 9126) implemente etmiyor ve DPoP (RFC 9449) zorlamıyor.**

### 13.2 Rust durumu — Argus için en kritik bölüm

**`rmcp` (resmî) — v3.2.0, 2026-08-31.** 24,9M indirme. v3.0.0 spec revizyonuyla aynı gün (2026-07-28) çıktı.

Auth feature flag'leri: `auth`, `auth-client-credentials-jwt`, `auth-enterprise-managed`. `oauth2` crate v5.0 üzerine kurulu. Desteklenenler: RFC 8707, RFC 9728, RFC 8414+OIDC keşif, RFC 7591, RFC 7636 (S256 zorunlu), SEP-991/CIMD, SEP-835 scope step-up, SEP-837 `application_type`, RFC 9207. **Implemente edilmeyenler: PAR, DPoP, RAR.**

> **Belirleyici gerçek:** Bunların hepsi `src/transport/auth.rs` altında — **yalnızca client tarafı.** Crate'te `TokenVerifier` yok, bearer middleware yok, PRM sunumu yok, `WWW-Authenticate` **emisyonu** yok (tüm ilgili kod parse-only). Dokümanlar doğruluyor: *"Client-only implementation. The documentation describes no server-side (resource server) OAuth support."*

Referans materyali: `examples/servers/src/` altında üç elle yazılmış oyuncak axum AS'i — `cimd_auth_streamhttp.rs` (514 satır), `complex_auth_streamhttp.rs` (691), `simple_auth_streamhttp.rs` (173). In-memory, demo kalitesinde.

**`rust-mcp-sdk` (üçüncü taraf, `rust-mcp-stack`) — v2.0.0, 2026-08-27.** 262k indirme. **Bizim için en yakın referans implementasyon.** `rmcp`'nin aksine **tam resource-server desteği** var:

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

RFC 9728 kodda 103 kez, token doğrulama 70, CIMD 16, DPoP 17 kez geçiyor. DCR'ın üzerinde gerçek bir `#[deprecated]` attribute var. `rust-mcp-extra` içinde çalışan **Keycloak, WorkOS AuthKit ve Scalekit** provider'ları var. %100 conformance iddiası **kendi beyanıdır** — kendimiz süiti çalıştırana kadar doğrulanmamış sayılmalı.

> **Keycloak provider'ı, tasarımımız için en öğretici artefakt:** MCP sunucusu **kendi RFC 9728 PRM'sini `AuthMetadataBuilder` ile inşa edip sunuyor** ve `aud`'u kendisi doğruluyor (`resolve_audience` beklenen audience'ı MCP sunucu URL'ine varsayıyor, açıkça "strongly discouraged" işaretli bir `disable_audience_validation` kaçış kapısıyla). Keycloak yalnızca token issuer olarak kullanılıyor. **Bu ayrımı biz de tekrarlamalıyız.**

**Ölü/durgun Rust MCP crate'leri:** `mcp-core` (0.1.50, Mayıs 2025), `mcpr` (0.2.3, Mart 2025), `poem-mcpserver` (0.3.1, Ekim 2025).

**Rust OAuth server yapı taşları — dürüst değerlendirme:**

| Crate | Sürüm | Son yayın | Değerlendirme |
|---|---|---|---|
| `oxide-auth` | 0.6.1 | **2024-06-02** | Rust'taki tek yerleşik AS framework'ü ve **~2¼ yıl bayat**. OAuth 2.0 dönemi; 9728/8707/9207/CIMD/PAR/DPoP yok. **Üzerine inşa etme** |
| `oauth2` | 5.0.0 | 2025-01-21 | 48,9M indirme. Sağlam ama **yalnızca client tarafı** |
| `openidconnect` | 4.0.1 | 2025-07-06 | 12,9M indirme. **Yalnızca RP/client tarafı** |
| `jsonwebtoken` | 11.0.0 | 2026-07-24 | 183M indirme, aktif |
| `josekit` | 0.10.3 | 2025-05-20 | Daha geniş JOSE ama daha sessiz (C OpenSSL bağımlılığı) |
| `aws-lc-rs` | 1.18.1 | **2026-09-01** | 214M indirme, çok aktif, FIPS-capable |
| `jwt-authorizer` | 0.15.0 | 2024-08-27 | Axum JWKS middleware — **2 yıl bayat** |
| `axum` | 0.8.9 | 2026-04-14 | 458M indirme |

> ### **Rust'ta olgun, genel amaçlı bir OAuth 2.1 Authorization Server crate'i YOK. Bu boşluk gerçek ve Argus'un en güçlü gerekçesidir.**

Niş crate'ler (farkındalık için, benimseme için değil): `oauth-as` 0.9.4 (2026-08-08, 2.342 indirme — "embeddable OAuth 2.1 AS library" ama kapsamı RFC 6749/8628/7636, **9728/8707/9207/CIMD yok**); `dpop-verifier` 4.4.0 (12.460 indirme — **en inandırıcı DPoP yapı taşı**); `turbomcp-dpop` 3.2.0; `nest-rs-oauth-resource`, `skyauth`, `turul-mcp-oauth`, `mcp-oauth`, `ferro-mcp-oauth`, `auth-framework` — hepsi küçük.

**Hiçbir sağlayıcı Rust SDK sunmuyor.** Bulunan tüm MCP auth SDK'ları TypeScript veya Python.

### 13.3 Conformance test aracı

**`github.com/modelcontextprotocol/conformance`** — resmî conformance framework'ü. Hem client hem server kapsıyor. **Açık auth senaryoları:** `auth/basic-dcr`, `auth/basic-metadata-var1`, `auth/basic-cimd`. Revizyon başına gereksinim setleriyle her spec sürümünün ne talep ettiğini donduruyor. `--spec-version` ile 2025-11-25 ve 2026-07-28 destekliyor. SEP-1730 SDK tiering ve `tier-check` alt komutu var.

```bash
npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
npx @modelcontextprotocol/conformance client --command "…" --suite auth
npx @modelcontextprotocol/conformance list
```

> ### KARAR: Bu, kabul testi harness'ımız. Gün-1'den CI'da.
> Hem `rmcp` hem `rust-mcp-sdk` `conformance-client` crate'leri taşıyor — kablolamayı oradan kopyalayabiliriz.
>
> ⚠️ GitHub API rate limit'i nedeniyle senaryo listesinin tamamı sayılamadı; yukarıdaki üç senaryo adı doğrulandı, tam liste değil.

### 13.4 Sağlayıcılar

| Sağlayıcı | CIMD | DCR | RFC 9728 | RFC 8707 | Not |
|---|---|---|---|---|---|
| **WorkOS AuthKit** | ✅ (dashboard'dan, varsayılan kapalı) | ✅ | ✅ | ✅ (yapılandırılabilir) | **Doğrulanabilen en güçlü MCP hikâyesi.** Cross App Access early access |
| **Cloudflare `workers-oauth-provider`** | ✅ (`clientIdMetadataDocumentEnabled`) | ✅ | ✅ **her zaman** | ✅ | Sağlayıcı değil ama **amaca özel en eksiksiz açık kaynak MCP AS'i.** 1,9k yıldız. **API şekli ilhamı için okunmalı** |
| **Keycloak** | ⚠️ **Deneysel**, 26.6.0 (2026-04-08) | ✅ | ❓ **Muhtemelen YOK** | ❓ | Son sürüm 26.7.3. 26.6.0 release notes CIMD'yi MCP için eklediğini yazıyor ama **RFC 9728/8707'den hiç bahsetmiyor** |
| **Clerk** | ✅ beta (2026-08-05) | ? | ? | ? | Changelog draft revizyonunu belirtmiyor |
| **Auth0** | "coming soon" | ? | ? | ? | ⚠️ Özel sayfalar erişilemedi (405/404). **"Auth for MCP GA Mayıs 2026" iddiası doğrulanamadı** |
| **Stytch / Descope / Scalekit** | ✅ (oauth.net listesi) | ? | ? | ? | Genel bakış sayfaları MCP/DCR/CIMD/9728/8707'den bahsetmiyor — doğrulanmadı |
| **Okta, Entra ID** | ❌ kanıt yok | ✅ | ? | Entra: `resource` destekliyor ama MCP sunucu URL'i **Application ID URI olarak kayıtlı olmalı**, yoksa `AADSTS9010010` | Okta hakkında veri toplanamadı |

**Değerlendirilmedi:** Ory Hydra, Zitadel, Logto, Authentik, SuperTokens, node `oidc-provider`, MCP gateway'leri (Docker, Kong, Envoy AI Gateway, Pomerium).

---

## 14. İstemci interop gerçekleri

### 14.1 Anthropic / Claude

Kaynak: `claude.com/docs/connectors/building/authentication`

| Tür | Durum |
|---|---|
| `oauth_dcr` | Hazır destekli |
| `oauth_cimd` | Hazır destekli |
| `oauth_anthropic_creds` | `mcp-review@anthropic.com` |
| `custom_connection` | `mcp-review@anthropic.com` |
| `static_headers` | Beta |
| `none` | Destekli |

**Kritik detaylar:**
- **Saf M2M `client_credentials` DESTEKLENMİYOR.** *"Every connection requires user consent."*
- Claude **her** authorization isteğinde `code_challenge_method=S256` gönderiyor
- **CIMD seçimi iki koşula birden bağlı:** `client_id_metadata_document_supported: true` **ve** `token_endpoint_auth_methods_supported` içinde `"none"`. Biri eksikse **DCR'a düşer**
- **Yüksek trafik bekleyen sunucular için DCR yerine CIMD veya `oauth_anthropic_creds`** — DCR her yeni bağlantıda yeni client kaydı yaratıyor
- Scope kontrolü: 401'in `WWW-Authenticate`'inde `scope` ver; vermezsen Claude PRM'nin `scopes_supported`'ını ister. AS metadata'da `offline_access` varsa Claude onu da ekler
- **`401` şart** — *"Claude does not honor a `WWW-Authenticate` header on a `200` response."*
- `authorization_servers` çoklu ise **Claude sadece ilkini kullanır**, fallback yapmaz
- **Timeout'lar:** discovery/register/token **10 sn**, refresh **30 sn**
- Token endpoint `application/x-www-form-urlencoded`; `/register` `application/json` — **farklı parser'lar**
- Refresh: 401'de reaktif, expiry'den 5 dk önce proaktif. Geçersiz refresh token'da **`invalid_grant`**
- **Anthropic egress: `160.79.104.0/21`** — AS'imiz bu aralıktan erişilebilir olmalı; WAF akışı bozabilir

**Callback URL'leri:**
- Hosted yüzeyler (Claude.ai web, Desktop, mobil, Cowork): `https://claude.ai/api/mcp/auth_callback`
- Claude Code: RFC 8252 loopback, geçici port → **port yok sayılarak eşleştirilmeli** (§9.4)

> Not: Anthropic dokümantasyonu hâlâ MCP spec'inin **2025-11-25** sayfalarına link veriyor. Hangi revizyonu implemente ettikleri açıkça yazılmamış.

### 14.2 OpenAI Apps SDK

Kaynak: `developers.openai.com/apps-sdk/build/auth`

- **PKCE zorunlu S256.** *"MCP servers are unsupported when their authorization server metadata omits this field"* (`code_challenge_methods_supported`)
- **CIMD tercih edilen yöntem.** `client_id_metadata_document_supported: true` gerekli. Desteklenen token auth: `none` veya `private_key_jwt`. DCR fallback
- ChatGPT `resource=https%3A%2F%2Fyour-mcp.example.com` parametresini **ekliyor**. AS bunu access token'a (`aud`) **kopyalamalı**
- **RFC 9207 sert gereksinim:** `authorization_response_iss_parameter_supported: true` + **her başarılı ve hata yanıtında** `iss`. *"Clients use exact string comparison and do not normalize trailing slashes, paths, ports, or casing."* **ChatGPT/Codex uyuşmazlıkları veya eksik `iss` değerlerini reddeder**
- ChatGPT **OpenAI-yönetimli mTLS sertifikası** sunuyor; yayımlanan CA zincirine karşı doğrulanabilir. Alternatif: yayımlanan egress IP aralıkları
- *"ChatGPT does **not** support machine-to-machine OAuth grants such as client credentials."*
- **Reauthorization:** AS `id_token_hint` parametresini onurlandırmalı
- Kurumsal domain kısıtlaması: OIDC metadata + `openid`/`email` scope'ları + **UserInfo endpoint gerekli**

Gerçek ChatGPT CIMD dokümanı (8 Eylül 2026'da çekildi):
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

> Dikkat: `token_endpoint_auth_methods_supported` **RFC 7591 client metadata alanı değildir** — bu bir AS metadata alan adının yeniden kullanımı. **AS'imiz bilinmeyen alanlara toleranslı olmalı.**

⚠️ OpenAI'nin per-tool `securitySchemes` dizisi **MCP çekirdeğinde YOK** (`schema.ts`'te `securityScheme` hiç geçmiyor). OpenAI'ye özgü uzantı.

### 14.3 A2A (Agent2Agent)

- Linux Foundation yönetiminde. **v1.0 tarihi çelişkili:** site "August 2026", blog duyurusu "12 Mart 2026" → **kesin GA tarihi doğrulanamadı**
- Auth modeli **AgentCard.securitySchemes** üzerinden, **OpenAPI 3.0 desenleri**. Tipler: `apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTls`
- OAuth flow'ları: `authorizationCode`, `clientCredentials`, `deviceCode`. **`implicit` ve `password` YOK** — OAuth 2.1 uyumlu
- **RFC 9728, RFC 8707 veya OAuth metadata keşfinden bahsetmiyor**
- **AgentCardSignature** — JWS (RFC 7515), kartın canonicalized formu üzerinde
- Normatif: *"Servers MUST reject requests with invalid or missing authentication credentials"*

**MCP ile temel fark:** A2A auth şemasını **agent'ın kendi kartında bildirimsel olarak** tanımlar (OpenAPI tarzı); MCP ise **OAuth keşif zincirini** (PRM → AS metadata) zorunlu kılar ve resource indicator/audience binding'i normatif yapar. **MCP'nin modeli daha katı ve daha OAuth-yerlisidir.** Yakınsama sinyali yok.

---

## 15. Yol haritası — yakın gelecek

Kaynak: `blog.modelcontextprotocol.io/posts/mcp-roadmap` (22 Ağustos 2026, David Soria Parra ve Den Delimarsky)

Öncelik alanı 3 — **"Agent identity and enterprise-ready security"**:

> *"MCP authorization today is built around a person approving access in a browser… more and more of the callers are agents running as cloud workloads with their own identity."*

İş akışları: **DPoP'un finalize edilmesi ve benimsetilmesi**, **Workload Identity Federation**, Enterprise-Managed Authorization'ın arkasındaki **ID-JAG grant'ı**, ve **standart token exchange**. IETF **OAuth** ve **WIMSE** WG'leriyle etkileşim.

Ayrıca: **Server Card Working Group** — *"so a server can be discovered and reasoned over without connecting to it."*

**Uçuşta olan auth SEP'leri (8 Eylül 2026):**

| SEP/PR | Başlık | Son güncelleme |
|---|---|---|
| **SEP-1932** | DPoP Profile for MCP | 2026-09-07 |
| **SEP-1933** | Workload Identity Federation | 2026-09-07 |
| SEP-2752 | HTTP Message Signing for MCP Client Authentication | 2026-09-07 |
| SEP-2643 | Structured Authorization Denials | 2026-09-06 |
| SEP-2848 | Asynchronous Approval for Tool Calls | 2026-09-07 |
| SEP-2817 | AI Invocation Audit Context in Request `_meta` | 2026-08-24 |
| SEP-3149 | Require Token Endpoint Auth Methods Supported in CIMD | 2026-08-17 |
| PR #3235 | Use updated OAuth Client ID Metadata Document RFC | 2026-08-12 |
| PR #3191 | docs: rework the authorization guide around CIMD | 2026-08-03 |

> ### KARAR: DPoP ve RFC 8693 token exchange için mimaride **bugünden yer bırak.**
> DPoP yol haritasında açıkça birinci sırada. `dpop_signing_alg_values_supported` alanını metadata şemasına şimdiden ekle.

**Enterprise-Managed Authorization (EMA) — Stable:** MCP'nin kurumsal auth'u ID-JAG'ı profilliyor. Detaylar `docs/15-agent-identity.md`'ye (yazılacak) ait; buradaki bağlantı noktası: **IdP AS rolü = Argus.**

---

## 16. Argus için somut yapılacaklar

### 16.1 AS endpoint'leri

| Endpoint | Zorunluluk | Notlar |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | **MUST** (bu veya OIDC) | RFC 8414. Path'li issuer: `/.well-known/oauth-authorization-server/{path}` |
| `GET /.well-known/openid-configuration` | Alternatif veya ek | Path'li issuer için **hem** `/.well-known/openid-configuration/{path}` **hem** `/{path}/.well-known/openid-configuration` sun (client'lar üçünü de dener) |
| `GET /authorize` | **MUST** | PKCE S256 zorunlu, `resource` kabul, `iss` emit, consent ekranı |
| `POST /token` | **MUST** | `application/x-www-form-urlencoded` **zorunlu** (JSON-only parser yaygın hata; 415 dönersen Claude bağlanamaz) |
| `GET /jwks.json` | Pratikte zorunlu | |
| `POST /register` | **MAY**, deprecated | Rate limit + kayıt üst sınırı + TTL temizliği şart |
| `POST /revoke` | Önerilir | RFC 7009 |
| `POST /introspect` | Opsiyonel | RFC 7662. Opak token kullanırsak gerekli |
| `GET /userinfo` | Opsiyonel | **OpenAI kurumsal domain kısıtlamaları için gerekiyor** |
| `GET/POST /consent` | **MUST** (proxy senaryosunda) | |

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

**Neden her biri:**
- `code_challenge_methods_supported: ["S256"]` — **yoksa MCP client'ları devam etmeyi reddetmek ZORUNDA.** Tek eksiklik tüm ekosistemden dışlar. OIDC discovery sunuyorsak da **MUST** dahil et
- `authorization_response_iss_parameter_supported: true` — ChatGPT ve Codex uyuşmazlığı veya eksik `iss`'i **reddeder**
- `client_id_metadata_document_supported: true` — CIMD desteğinin **tek interop sinyali**
- **`token_endpoint_auth_methods_supported` içinde `"none"`** — Claude CIMD'yi ancak bu ikisi birlikte varsa seçer, yoksa DCR'a düşer
- `offline_access` — `scopes_supported`'a eklersek Claude refresh token için onu ister
- (İleride) `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]`
- (İleride) `dpop_signing_alg_values_supported`

### 16.3 AS davranış listesi

**Authorization endpoint:**
1. PKCE'yi **zorunlu** kıl, `S256` dışına izin verme; PKCE'nin atlanabildiği hiçbir kod yolu bırakma
2. `redirect_uri`'yi **hem `/authorize`'da hem token exchange'de** doğrula
3. Redirect URI eşleştirmesi **tam string** — wildcard/pattern yok. **Tek istisna:** loopback host'larda port yok sayılır
4. `resource` parametresini kabul et, **kayıtlı protected resource'lara karşı doğrula**, bilinmeyene `invalid_target`
5. **Consent ekranını göster.** CIMD client'ları için varsayılan olarak göster
6. Consent onaylanana kadar **state cookie'sini set etme**
7. Başarılı **ve hata** yanıtlarında **`iss` emit et**, metadata'daki `issuer` ile byte-identical
8. `application_type`'ı (CIMD dokümanından veya DCR kaydından) dikkate al
9. Yalnızca loopback redirect'i olan client'lar için **ek uyarı**; redirect hostname'ini **her zaman** göster

**CIMD işleyicisi:**
10. URL formatlı `client_id` tespit et: `https` + path bileşeni + fragment yok + userinfo yok
11. Fetch: **redirect takip etme**, **yalnızca 200 kabul et**, **5 KB'da okumayı kes**, timeout, per-client rate limit
12. **SSRF savunması:** RFC 6890 special-use adreslerini engelle (client_id URL'i **ve** doküman içindeki tüm URL'ler). IP doğrulamasını elle yazma. **DNS'i check ile use arasında pinle.** Mümkünse egress proxy
13. Doküman `client_id`'sinin fetch edilen URL ile **simple string comparison** ile eşleştiğini doğrula
14. `token_endpoint_auth_method` simetrik secret ise **reddet**; `client_secret` alanı varsa **reddet**
15. HTTP cache header'a saygı; **hata veya bozuk dokümanları cache'leme**; kendi üst/alt TTL sınırlarını koy
16. `logo_uri`'yi prefetch et ve sunucu tarafında cache'le
17. **Doküman hash'ini snapshot'la** — değişirse yeniden consent zorla
18. Domain trust policy uygula

**Token endpoint:**
19. `application/x-www-form-urlencoded` kabul et (`/register` ise `application/json`)
20. Authorization code redemption'ı **atomik tek kullanımlık** yap (CAS, read-then-write değil)
21. `resource`'a göre **audience-restricted token** ver. Asla audience'sız veya çoklu-audience token verme
22. Public client'lar için **refresh token rotate et**
23. Geçersiz refresh token'da **`invalid_grant`** dön
24. Kısa ömürlü access token
25. Yanıt süresi **10 saniyenin altında** (Anthropic: discovery/register/token 10 sn, refresh 30 sn). Ters proxy/WAF'ın yanıtı tutmadığından emin ol

**Consent ve iptal:**
26. Sunucu tarafı consent registry: `(user_id, client_id, resource, scopes, source, metadata_hash)`
27. Consent cookie: `__Host-` + `Secure` + `HttpOnly` + `SameSite=Lax` + imzalı + **client_id'ye bağlı**
28. Consent sayfası: `frame-ancestors 'none'` / `X-Frame-Options: DENY`, CSRF token
29. Consent iptali **canlı access ve refresh token'ları da** geçersiz kılsın
30. Consent'i **authenticated user identity'ye** bağla, anonim tarayıcı oturumuna değil

**DCR (geriye uyumluluk):**
31. IP + tenant bazlı rate limit, kayıt üst sınırı, kullanılmayan kayıtlarda TTL
32. Wildcard/pattern redirect_uri **reddet**
33. DCR credential'larına **kendi `issuer`'ımızı damgala**; cross-issuer sunumu sert reddet
34. `application_type`'ı onurlandır; sessizce reddetmek yerine **açık hata** dön
35. Redirect_uri politikasını sıkılaştırdığımızda **önceden var olan kayıtları geriye dönük geçersiz kıl**

**Multi-tenancy:**
36. Cross-tenant okumaları **açıkça test et.** Asana olayı egzotik bir saldırı değil, düz bir izolasyon mantık hatasıydı

### 16.4 RS tarafı (referans implementasyon)

**Endpoint'ler:**

| Endpoint | Zorunluluk |
|---|---|
| `POST /mcp` | **MUST** — POST desteklemeli |
| `GET /.well-known/oauth-protected-resource` ve/veya `/{path}` | **MUST** (veya `WWW-Authenticate` yolu) |

Modern-only sunucu: MCP endpoint'ine `GET` veya `DELETE` → **405**.

**PRM dokümanı (minimum):**
```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://as.example.com"],
  "scopes_supported": ["mcp:tools-basic"],
  "bearer_methods_supported": ["header"],
  "resource_name": "Example MCP Server"
}
```
- `resource` **kullanıcının girdiği MCP sunucu URL'iyle path dahil tam eşleşmeli**
- `authorization_servers` çoklu ise **Claude yalnızca ilkini kullanır**
- `scopes_supported` **minimal** olmalı
- `offline_access`'i buraya **koyma**

**Davranış:**
1. Token yoksa/geçersizse **401** + `WWW-Authenticate: Bearer resource_metadata="…"` (+ mümkünse `scope="…"`)
2. **200 yanıtında `WWW-Authenticate` işe yaramaz** — Claude onurlandırmıyor
3. `resource_metadata` URL'i MCP sunucusunun origin'inde olmak **zorunda değil** — `/.well-known/*` sunamayan platformlar (Supabase Edge Functions, Cloudflare Workers, Lambda URL) için en güvenilir yol
4. İmza ve `iss` doğrula (JWKS)
5. `exp` ve `nbf` doğrula
6. **`aud` / `resource` claim'inin bizi işaret ettiğini doğrula.** Etmiyorsa 401
7. Scope yetersizse **403** + `insufficient_scope` + `scope` + `resource_metadata`
8. Scope hiyerarşisi
9. Bir operasyon için **tüm scope'ları tek challenge'da**
10. Upstream API çağırıyorsak **ayrı token kullan** — client'ın token'ını asla iletme
11. Önceki isteklerden bağlam çıkarma; `Mcp-Session-Id` gelirse **yok say**
12. `clientInfo` / `clientCapabilities`'i **güvenlik kararında kullanma**
13. State handle'ları: CSPRNG, opak, sınırlı ömür, **`<user_id>:<handle>`** ile bağlanmış
14. `requestState`: **imzalı/AEAD**, kısa TTL, tek kullanımlık
15. Liste sonuçları token'a göre değişiyorsa **`cacheScope: "private"`**
16. `server/discover` sonucumuz token'a göre değişiyorsa onu da `"private"` yap
17. Sayfalı listede **tüm sayfalara aynı `cacheScope`**
18. `ttlMs >= 0`
19. **`cacheScope`'a güvenme** — per-primitive erişim kontrolünü ayrıca uygula
20. `Origin` header'ı varsa ve geçersizse **403** (DNS rebinding)
21. Yerelde çalışıyorsa yalnızca `127.0.0.1`'e bind et
22. Header ↔ body uyuşmazlığında **400 / `-32020`**; base64 sentinel'i **decode edip** karşılaştır
23. Header değerlerinde **CR/LF yasak**
24. `Mcp-Param-*`'a sır düşürme
25. Metadata endpoint yanıtları **5 saniyenin altında**
26. SSE yanıtlarında `X-Accel-Buffering: no`
27. `subscriptions/listen` token expiry davranışına **kendimiz karar vereceğiz** — spec sessiz

---

## 17. Doğrulanamayanlar

Dürüstlük için açıkça işaretlenmiştir. Kendi kararımızı vermeden önce teyit edilmeli.

**Spec ve standart:**
1. MCP'nin CIMD -00 atfı ile IETF -02 arasındaki fark **doğrulandı ve gerçektir**. PR #3235'in ne zaman merge olacağı **bilinmiyor**
2. CIMD -02 §6'daki `client_id_metadata_document_supported` "MUST include" vs "OPTIONAL" çelişkisi muhtemelen editoryal hata — **taslak yazarlarına doğrulatılmadı**
3. CIMD -02'de content-type gereksinimi muğlak; baseline `application/json` şartı **hiç belirtilmemiş**
4. `server/discover`'ın kimlik doğrulamasız olup olamayacağı **spec'te tanımlanmamış**. §10.5'teki yorum çıkarımdır
5. `subscriptions/listen` token expiry davranışı **spec'te tamamen tanımsız** (0 kelime eşleşmesi)
6. SEP-837'nin resmî statüsü ("Final" mi "merged" mi) **doğrulanamadı**

**Güvenlik:**
7. **2026 CVE tablosundaki tüm girdiler aggregator kaynaklıdır.** NVD JSON API ile teyit edilmeli
8. CVE-2025-54136 CVSS skoru kaynaklar arasında çelişiyor (7.2 vs 8.8)
9. CVE-2026-24052 ve CVE-2026-25536 birincil advisory'lere karşı doğrulanamadı
10. `mcp-cve-project` "570+ CVE" iddiası ve toplu istatistikler **doğrulanmadı**
11. NSA/CISA "MCP: Security Design" CSI PDF'i **açılamadı**
12. arXiv 2605.22333'ün tam PDF'i parse edilemedi; abstract kullanıldı. **9 kusur tipli taksonomisi tehdit modelimiz için en iyi yapılandırılmış girdi olurdu**

**Ekosistem:**
13. **Keycloak'ın RFC 9728 / 8707 / 9207 / PAR / DPoP durumu doğrudan doğrulanmadı.** RFC 9728 boşluğu için güçlü dolaylı kanıt var ama negatif doğrudan kanıtlanamadı
14. **Auth0'ın MCP teklifi doğrulanamadı** — özel sayfalar erişilemez (405/404)
15. **Clerk ve Okta hakkında veri toplanamadı**
16. Stytch ve Descope yalnızca genel bakış düzeyinde
17. `rust-mcp-sdk`'nın "%100 conformance" iddiası **kendi beyanıdır**
18. Conformance framework'ünün tam auth senaryo listesi sayılamadı (üç senaryo adı doğrulandı)
19. **Değerlendirilmedi:** Ory Hydra, Zitadel, Logto, Authentik, SuperTokens, node `oidc-provider`, MCP gateway'leri
20. A2A v1.0'ın kesin GA tarihi (Mart vs. Ağustos 2026)

---

## 18. Kaynaklar

**Spec (8 Eylül 2026'da ham markdown olarak okundu):**
- `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization`
- `.../authorization/authorization-server-discovery`
- `.../authorization/client-registration`
- `.../authorization/security-considerations`
- `https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices`
- `https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching`
- `https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr`
- `https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http`
- `https://modelcontextprotocol.io/specification/2026-07-28/changelog`
- `https://modelcontextprotocol.io/specification/2026-07-28/deprecated`

**RFC / IETF:**
- RFC 9728 · RFC 8707 · RFC 8414 · RFC 9207 · RFC 6750 · RFC 7591 · RFC 8252 · RFC 8693 · RFC 7523
- `https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.txt`
- `https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/` (draft-16, 2026-09-03)

**MCP proje:**
- `https://blog.modelcontextprotocol.io/posts/client_registration/` (2025-08-22)
- `https://blog.modelcontextprotocol.io/posts/mcp-roadmap` (2026-08-22)
- `https://github.com/modelcontextprotocol/ext-auth`
- `https://github.com/modelcontextprotocol/conformance`
- `https://modelcontextprotocol.io/seps`

**Güvenlik araştırması:**
- Doyensec `https://blog.doyensec.com/2026/03/05/mcp-nightmare.html`
- Obsidian Security `https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover`
- Trail of Bits `https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/`
- Invariant Labs `https://invariantlabs.ai/blog/mcp-github-vulnerability`
- Equixly `https://equixly.com/blog/2026/08/05/stateless-mcp/`
- arXiv `https://arxiv.org/abs/2605.22333`

**Platform dokümanları:**
- `https://developers.openai.com/apps-sdk/build/auth`
- `https://claude.com/docs/connectors/building/authentication`
- `https://a2a-protocol.org/latest/specification/`
- `https://oauth.net/2/client-id-metadata-document/`
