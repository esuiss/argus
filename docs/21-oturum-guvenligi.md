# 21. Oturum güvenliği ve hırsızlığa karşı savunmalar

> `ARGUS.md` §21'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§21 §X` referansları aynı anlamda.



---

### 0. Yönetici Özeti — Ne Zaman Ne Yapılmalı

| Teknoloji | Sınıflandırma | Gerekçe |
|---|---|---|
| **DPoP (RFC 9449)** | **BUGÜN İMPLEMENTE ET** | Final RFC, olgun, tarayıcı dışı tüm istemciler için çalışır, karşı taraf desteği gerçek |
| **SSF/CAEP Transmitter** | **BUGÜN İMPLEMENTE ET** | Final spec (Eyl 2025), Okta üretimde, interop profili Ekim 2026'da final olacak |
| **RFC 9470 step-up challenge** | **BUGÜN İMPLEMENTE ET** | Final RFC, ucuz, CAEP'in aksiyon tarafını kapatır |
| **mTLS bağlama (RFC 8705)** | **BUGÜN — opsiyonel yol olarak** | Final RFC, FAPI 2.0'ın ana yolu, B2B/yüksek güvence için |
| **SSF/CAEP Receiver** | **ARAYÜZ HAZIRLA** | Karşı taraf sayısı az; Google hâlâ pre-standart, Microsoft yok |
| **DBSC sunucu tarafı** | **ARAYÜZ HAZIRLA** (şema + endpoint iskeleti) | Spec Editor's Draft, tek tarayıcı, tek platform, Mozilla **negatif** |
| **DBSC federated/SSO (provider_key)** | **ERKEN** | Chrome'da "Proposed", spec'te SLO semantiği tanımsız |
| **DBSC(E) enterprise** | **ERKEN** | Ayrı overview dokümanı, W3C ana spec'e girmemiş |
| **Davranışsal biyometri** | **YAPMA** | Cross-session HTER ≈ 0.19; GDPR Art.9 + KVKK açık rıza + alternatif sunma yükümlülüğü |

**Tek cümlelik strateji:** *Bearer token modelinden çıkın (DPoP + mTLS bugün, DBSC yarın), iptali standart bir olay kanalına taşıyın (SSF/CAEP transmitter), heuristik risk skorunu asla terminal karar verici yapmayın.*

---

## 1. DBSC — Device Bound Session Credentials

### 1.1 Spec durumu (doğrulanmış)

- **W3C Editor's Draft, 27 Ağustos 2026** — https://w3c.github.io/webappsec-dbsc/
- Editör: Daniel Rubery (Google). **Former Editor: Kristian Monsen (Apple)** — Apple bir dönem editörlük yapmış, şu an pozisyon almamış.
- Spec'in kendi ifadesi: *"Note this is a very early drafting for writing collaboration only"* ve Changelog bölümü boş (*"This is an early draft of the spec"*). **Yani W3C süreci açısından CR'ye yakın değil.**

### 1.2 Tarayıcı desteği — gerçek durum

| Tarayıcı | Durum | Kaynak |
|---|---|---|
| **Chrome** | Windows'ta GA — Chrome 146 (stable 10 Mart 2026), duyuru 9 Nisan 2026 | blog.google, chromestatus |
| **Chrome macOS** | "Yaklaşan bir sürümde" duyuruldu; **bugüne kadar doğrulayamadım** | ⚠️ aşağıya bak |
| **Chrome Linux/Android/iOS** | Yok | chromestatus: `android: null, ios: null` |
| **Firefox** | **NEGATİF standart pozisyonu** (issue #912) | mozilla/standards-positions merged-data.json |
| **Safari/WebKit** | **Pozisyon yok** ("No signal"), issue #281, etiket: `concerns: usability` | WebKit/standards-positions summary.json |
| **Edge** | Origin Trial Ekim 2025'te bitti; GA duyurusu yok | ikincil kaynak |

> **⚠️ macOS hakkında doğrulanmış bulgu:** Bugün Chrome Enterprise policy template'ini indirdim. Tek DBSC ilgili politika `BoundSessionCredentialsEnabled` ve `supported_on` alanı **`["chrome.win:124-"]`** — yani **yalnızca Windows**. Chrome stable şu an 152. Bazı ikincil kaynaklar "Chrome 147'de macOS" diyor; **ben bunu doğrulayamadım ve politika verisi aksini ima ediyor.** Ayrıca bu politikanın açıklaması özellikle *"Google authentication cookies"* diyor — bu, Chrome'un kendi Google-hesabı çerez bağlama özelliği; genel web API'si için ayrı bir enterprise politika **yok**.

**Mozilla'nın negatif pozisyonu, bunun bir web standardı olarak yakın vadede yaygınlaşmayacağının en güçlü işareti.**

### 1.3 Protokol — SUNUCU TARAFINDA TAM İMPLEMENTASYON

#### Header isimleri değişti (kritik)

İkinci origin trial'da (Ekim 2025) header prefix'i **`Sec-Session-*` → `Secure-Session-*`** olarak değişti ve challenge için HTTP durum kodu **401 → 403** oldu. İnternetteki eski örneklerin çoğu yanlış.

| Header | Yön | Tip (RFC 9651) |
|---|---|---|
| `Secure-Session-Registration` | Response | sf-list (inner-list + params) |
| `Secure-Session-Challenge` | Response | sf-string + `id` param |
| `Secure-Session-Response` | Request | sf-string (JWT) |
| `Sec-Secure-Session-Id` | Request | sf-string |
| `Secure-Session-Skipped` | Request | sf-list of sf-token |

#### Adım 1 — Login yanıtında kayıt tetikle

```http
HTTP/1.1 200 OK
Set-Cookie: auth_cookie=<uzun-ömürlü-grant>; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=2592000
Secure-Session-Registration: (ES256 RS256);path="/dbsc/register";challenge="<cv>";authorization="<ac>"
```

Parametreler:
- `path` (**zorunlu**, yoksa entry yok sayılır) — relatif veya tam URL
- `challenge` (opsiyonel) — JWT'de `jti` olarak geri gelir
- `authorization` (opsiyonel) — JWT'de `authorization` claim'i **ve** `Authorization:` header'ı olarak gelir. Kullanıcıyı kayıt isteğine bağlamak için bunu kullanın.
- `provider_key` / `provider_session_id` / `provider_url` — federated key sharing (§1.6)

Desteklenen algoritmalar: **ES256, RS256, none** — başka yok.

Aynı response'ta birden fazla `Secure-Session-Registration` header'ı veya inner-list gönderilebilir (çoklu oturum).

#### Adım 2 — Registration endpoint

Gelen istek:
```http
POST /dbsc/register HTTP/1.1
Secure-Session-Response: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRic2Mrand0IiwiandrIjp7...}}.eyJqdGkiOiJjdiIsImF1dGhvcml6YXRpb24iOiJhYyJ9.<sig>"
Authorization: <ac>
```

**JWT (`typ: "dbsc+jwt"`) doğrulama algoritması:**

1. `typ == "dbsc+jwt"` — aksi halde reddet
2. `alg ∈ {ES256, RS256}` — **`none` gelirse `jwk` bulunmamalı** (spec: alg "none" ise jwk MUST NOT be present)
3. `jwk` header parametresi **kayıtta zorunlu** (ES256/RS256 için). Private key alanı içermemeli (`d` yoksa kontrol et).
4. İmzayı `jwk`'daki public key ile doğrula
5. `jti` == senin verdiğin `challenge`. **Challenge'ı tek kullanımlık + kısa ömürlü tut.**
6. `authorization` claim'i, header'da gönderdiğinle bit-bit aynı mı?
7. JWK thumbprint'i (RFC 7638, SHA-256, base64url-unpadded) hesapla → oturum kaydına yaz

> **🔴 En kritik interop tuzağı:** Spec'in normatif payload gereksinimi **yalnızca `jti`** (+ varsa `authorization`). Spec'in örneğindeki base64 decode edildiğinde `aud` ve `iat` de var, ama bunlar **normatif değil**. Üretimdeki bir DBSC server kütüphanesinin (dbsc-server, W3C issue #267, 4 Eyl 2026) implementasyon raporu net: *"Chrome's shipping implementation sends minimal proof payloads (`jti` and little else)"* → **`aud`/`iat`/`sub` zorunlu tutarsanız Chrome ile çalışmaz.** Ayrıca TLS-sonlandıran proxy arkasında `aud`'u iç URL'e karşı doğrulamak **her zaman** başarısız olur; `aud` kontrolü opt-in ve public origin'e karşı olmalı.

Yanıt — **JSON Session Instructions**:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Set-Cookie: auth_cookie=<kısa-ömürlü>; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=600
```

```jsonc
{
  "session_identifier": "s_9f3...",       // ZORUNLU (continue:false değilse)
  "refresh_url": "/dbsc/refresh",         // opsiyonel; yoksa registration URL kullanılır
  "continue": true,                        // opsiyonel, default true
  "scope": {                               // ZORUNLU
    "origin": "https://example.com",       // opsiyonel; yoksa instruction veren URL'in origin'i
    "include_site": false,                 // ZORUNLU (true/false açıkça yazılmalı)
    "scope_specification": [               // opsiyonel
      { "type": "include", "domain": "api.example.com", "path": "/v1" },
      { "type": "exclude", "domain": "*.example.com",   "path": "/static" }
    ]
  },
  "credentials": [{                        // ZORUNLU
    "type": "cookie",                      // yalnızca "cookie" geçerli
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None"
  }],
  "allowed_refresh_initiators": ["example.com", "*.example.com"]  // opsiyonel, default []
}
```

**Sunucu tarafında uyulması gereken kısıtlar (aksi halde tarayıcı oturumu sonlandırır):**
- `refresh_url` **HTTPS veya localhost** olmalı ve destination ile **same-site**
- `scope.origin` destination ile **same-site** olmalı
- Hiçbir credential `Partitioned` attribute'u taşıyamaz
- `include_site: true` ise `origin`'in host'u **eTLD+1** olmalı; ayrıca ilk kayıtta `https://<eTLD+1>/.well-known/device-bound-sessions` **200** dönmeli ve `registering_origins` içinde kayıt endpoint'inin origin'i olmalı
- `Max-Age`/`Expires` cookie eşleştirmesine **dahil değil**; eşleşen attribute'lar: **Domain, Path, Secure, HttpOnly, SameSite**

Kayıt reddi:
```http
HTTP/1.1 403
Secure-Session-Registration: (ES256 RS256);path="/dbsc/register";challenge="<yeni-cv>"
```

#### Adım 3 — Refresh endpoint (kritik yol)

Tarayıcı, bağlı cookie eksik/expired olduğunda **isteği bloklar** ve refresh'i çağırır:

```http
POST /dbsc/refresh HTTP/1.1
Sec-Secure-Session-Id: "s_9f3..."
Cookie: <bu isteğe uygulanan diğer çerezler>
```

Sunucu challenge ister:
```http
HTTP/1.1 403
Secure-Session-Challenge: "<yeni-challenge>";id="s_9f3..."
```

Tarayıcı imzalı proof ile döner (**`jwk` YOK, yalnızca `jti`**):
```http
POST /dbsc/refresh HTTP/1.1
Sec-Secure-Session-Id: "s_9f3..."
Secure-Session-Response: "<dbsc+jwt>"
```

Sunucu doğrulaması:
1. `Sec-Secure-Session-Id` → oturumu ve **kayıtlı public key**'i bul
2. `typ == dbsc+jwt`, `jwk` **bulunmamalı** (refresh'te MUST NOT)
3. İmzayı **kayıtlı** public key ile doğrula (proof'taki key ile değil!)
4. `jti` ∈ *bu oturum için son N challenge* — **tek bir challenge değil.** Spec açıkça uyarıyor: *"due to network latency and race conditions, it's possible to receive a signature for an old challenge after issuing a new challenge."* Pratik: son 2-3 challenge'ı ~60-120 sn pencerede kabul et, kullanılanı yak.
5. Yeni bağlı çerezi `Set-Cookie` ile ver, opsiyonel olarak yeni JSON instructions gönder

Optimizasyon: challenge'ı **herhangi bir 200 yanıtına** iliştirebilirsiniz — bu 403 round-trip'ini ortadan kaldırır:
```http
HTTP/1.1 200 OK
Secure-Session-Challenge: "c1";id="s_1", "c2";id="s_2"
```

Oturumu sonlandırma: `{"continue": false}` → tarayıcı oturum state'ini ve **private key'i siler**.

#### Adım 4 — Tarayıcının HTTP durum kodu semantiği (sunucunun bilmesi ZORUNLU)

| Durum | Tarayıcı davranışı |
|---|---|
| **403** | Cache'lenmiş challenge ile **tekrar dener** |
| **4xx (403 hariç)** | **OTURUMU SİLER** — 401, 404, 400 hepsi ölümcül |
| **5xx** | Ertelenir; tarayıcı backoff uygulayabilir |
| **407, 429** | İstek atlanır (skip) |
| **3xx** | Return (refresh yok) |
| **Boş body + session_id var** | Return (config değişmedi kabul edilir) |
| Network error | `Secure-Session-Skipped: unreachable;session_identifier="..."` |

> **🔴 Bir yanlış 404 = oturum kaybı.** Refresh endpoint'iniz deploy sırasında 404 dönerse tüm bağlı oturumlar silinir. Routing'i, rate-limiter'ı ve WAF'ı buna göre ayarlayın — 429 güvenli, 4xx değil.

#### Adım 5 — Güvenlik sertleştirmesi (spec'in kendi önerileri)

- Refresh endpoint **login state timing side-channel'ı sızdırır**. Geçerli `Sec-Secure-Session-Id` header'ı yoksa reddet.
- Refresh endpoint **asla** `Access-Control-Allow-Credentials` dönmesin. DBSC refresh'i credential'ları örtük olarak ekler; bu sayede cross-site fetch ile login state sızdırılamaz.
- `X-Frame-Options` / `Cross-Origin-Resource-Policy` ile embed'i reddet.
- **Point-in-time challenge deseni:** Hassas bir işlemden önce cihaz kanıtı istemek için, aynı endpoint'e **307** + bağlı çerezi expire eden `Set-Cookie` dön → tarayıcı önce refresh yapar, sonra redirect'i tamamlar.
- Federated oturumlarda RP **yalnızca** SP'den aldığı public key ile kayıtlı oturumları kabul etmeli.
- Challenge'lar **kısa ömürlü** olmalı, bayat challenge reddedilmeli.

#### `/.well-known/device-bound-sessions`

```json
{
  "registering_origins": ["https://login.example.com", "https://sso.example.com:8443"],
  "relying_origins":     ["https://example.co.uk", "https://partner.example"],
  "provider_origin":     "https://idp.example.com"
}
```
- `registering_origins` — site-scoped (`include_site: true`) oturum kaydedebilecek origin'ler. **Kayıt endpoint'i eTLD+1 host'undaysa gerekmiyor.**
- `relying_origins` + `provider_origin` — federated key sharing için **çift taraflı opt-in**

### 1.4 Güvenli donanımı olmayan cihazlar

Spec **hiçbir donanım gereksinimi dayatmıyor**: *"browser implementers are free to choose other key storage technologies, such as VBS keys."*

Chrome'un yayımlanmış ölçümleri (README):
- **Windows kullanıcılarının ~%60'ı** (ve artıyor) TPM'e sahip → koruma sunulabiliyor
- TPM imzalama gecikmesi: **P50 200 ms / P95 600 ms**, hata oranı **~%0.001**, ECDSA_P256

Google'ın resmi yol haritası (blog.google, 9 Nisan 2026) üçüncü maddesi: *"Actively exploring the potential addition of **software-based keys** to extend protections to devices without dedicated secure hardware."* — yani **henüz yok**.

**Sunucu tarafı sonucu:** DBSC oturumu olan/olmayan kullanıcılar arasında **yetki farkı** tasarlayın. Yazılım anahtarı geldiğinde "bu oturum donanım destekli mi" bilgisi **protokolde taşınmıyor** — TPM sertifika zinciri kasıtlı olarak sunucuya gönderilmiyor (fingerprinting karşıtı gizlilik hedefi). Yani sunucu **donanım vs yazılım ayrımını yapamaz**. Bu, DBSC(E)'nin (attestation'lı enterprise varyantı) var olma sebebi.

### 1.5 Performans — gerçek üretim verisi

W3C issue **#265 (25 Ağustos 2026)**, üretimde DBSC çalıştıran bir ekipten:

| İşlem | Medyan | P90 |
|---|---|---|
| **Registration** (challenge→yanıt) | **~3.0 s** | **~15.0 s** |
| **Refresh** | **~0.3 s** | **~0.6 s** |

Ayrıca *"a small number of registrations complete minutes after the challenge was issued"* — dağılım ağır sağa çarpık.

**Mimari sonuçlar:**
1. **Registration challenge'ları dakikalarca geçerli tutmanız gerekir.** 30 saniyelik TTL koyarsanız P90'ı kaybedersiniz.
2. **Kayıt penceresi bir güvenlik boşluğudur.** Chrome'un kanonik deseni: login'de **30 günlük unbound grant cookie**, kayıttan sonra **10 dakikalık bound cookie**. Chrome dokümanı açık: *"Chrome falls back to using the long-lived cookie if one is still present."* Yani 3-15 saniyelik kayıt penceresinde (ve kayıt hiç tamamlanmazsa süresiz) oturumu koruyan şey **bağsız bir bearer cookie**'dir. Bu cookie'ye tam yetki vermeyin.
3. Bu boşluk tam olarak Google'ın **"DBSC JavaScript API"** önerisinin (chromestatus, 9 Temmuz 2026 oluşturuldu, **"Proposed"**) sebebi: *"Premature Cookie Issuance"* ve *"SSO Handoff Vulnerabilities"*.

**Sunucu yükü hesabı:** Refresh sıklığı = bağlı cookie'nin `Max-Age`'i. 1M aktif oturum × 600 sn cookie → **~1.667 refresh/sn**, her biri 1 ECDSA-P256 doğrulama + challenge lookup. Rust'ta imza doğrulama maliyeti ihmal edilebilir (~20-50 µs); **darboğaz challenge store'un I/O'sudur.** Cookie ömrünü uzatmak yükü doğrusal azaltır ama çalınmış cookie'nin geçerlilik penceresini uzatır — doğrudan bir trade-off.

### 1.6 Federated / cross-origin SSO

**Spec'te tanımlı olan (§3.3, §8.11):** RP, kayıt header'ına `provider_key` (SP anahtarının base64url JWK thumbprint'i), `provider_session_id`, `provider_url` ekler. Tarayıcı SP'nin mevcut **private key'ini yeniden kullanır** — yeni anahtar üretmez. Çift taraflı `.well-known` opt-in şart, ayrıca `device-bound-session-key-sharing` permission prompt'u var.

**Chrome'daki durumu:** Ayrı bir feature — *"Device Bound Session Credentials for SSO"* (chromestatus 6051103412191232, crbug 485514814, oluşturma 18 Şub 2026, güncelleme 27 May 2026). **Status: "Proposed", spec: null, milestone yok.**

**Açık tasarım boşluğu:** W3C issue **#259 (5 Mayıs 2026)** — *"What should happen to RPs DBSC sessions when the SP session is terminated?"* — **cevapsız, konsensüs yok.** DBSC'de single-logout semantiği tanımlı değil. Bu boşluğu **SSF/CAEP `session-revoked` olayı** doldurur; ikisinin birlikte tasarlanması gerekiyor.

### 1.7 Gerçek dünya implementasyonları

| Kim | Ne |
|---|---|
| **Google** | Kendi hesap altyapısı; Workspace'te 25 Mayıs 2026'dan itibaren varsayılan açık, **yönetici kapatamıyor** |
| **Okta** | Origin trial'a katıldı, Google dışı bir auth ortamında test etti (ikincil kaynak) |
| `dbsc-server` | TypeScript (Node/Bun/Deno), MIT, sıfır bağımlılık — W3C issue #267, 4 Eyl 2026 |
| `dbsc-toolkit` | Node.js, Express/Fastify/Hono/Next.js + Redis/Postgres adapter — issue #260, 24 May 2026 |
| `dbsc-php` | Test vektörlerini paylaşıyor |
| **Rust** | **crates.io'da hiçbir şey yok.** `dbsc`/`device-bound-session` araması boş. Sıfırdan yazacaksınız. |

---

## 2. SSF / CAEP / RISC

### 2.1 Standart durumu (doğrulanmış)

| Spec | Durum | Tarih |
|---|---|---|
| **OpenID SSF 1.0** | **FINAL** | Doküman 29 Ağu 2025; onay 2 Eyl 2025 (85 kabul / 1 ret / 25 çekimser, 111 oy, %25.6 katılım) |
| **OpenID CAEP 1.0** | **FINAL** | 29 Ağu 2025 |
| **OpenID RISC 1.0** | **FINAL** | 29 Ağu 2025 |
| **CAEP Interoperability Profile 1.0** | **Implementer's Draft** — public review **27 Tem – 25 Eyl 2026**, oylama **26 Eyl – 10 Eki 2026** | Taslak footer: Eylül 2026 |

WG çalışma taslağı hâlâ 29 Ağu 2025 tarihli — **SSF 1.1 yolda değil.**

### 2.2 TRANSMITTER implementasyonu — tam liste

#### A) Discovery
```
GET /.well-known/ssf-configuration                    (issuer path'siz)
GET /.well-known/ssf-configuration/{path}             (multi-tenant için)
```
Content-Type: `application/json`. Yanıt:
```json
{
  "spec_version": "1_0",
  "issuer": "https://idp.example.com",
  "jwks_uri": "https://idp.example.com/jwks.json",
  "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
  "configuration_endpoint": "https://idp.example.com/ssf/streams",
  "status_endpoint":        "https://idp.example.com/ssf/status",
  "add_subject_endpoint":   "https://idp.example.com/ssf/subjects:add",
  "remove_subject_endpoint":"https://idp.example.com/ssf/subjects:remove",
  "verification_endpoint":  "https://idp.example.com/ssf/verify",
  "critical_subject_members": ["tenant", "user"],
  "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}],
  "default_subjects": "NONE"
}
```
- `issuer` **REQUIRED**, `iss` claim'i ile birebir aynı olmalı, discovery URL ile de aynı olmalı
- `spec_version` yoksa alıcı **`1_0-ID1`** varsayar → mutlaka yazın
- **Interop profili için ZORUNLU:** `spec_version ≥ 1_0`, `delivery_methods_supported`, `jwks_uri`, `configuration_endpoint`, `status_endpoint`, `verification_endpoint`, `authorization_schemes` ⊇ `{"spec_urn":"urn:ietf:rfc:6749"}`
- `authorization_schemes` **kimlik doğrulamasız erişilebilir olmalı** (SHOULD)

#### B) Stream Management API (5 endpoint)

**Configuration Endpoint** — `POST` (create), `GET` (read, `?stream_id=` opsiyonel; yoksa liste), `PATCH`/`PUT` (update), `DELETE`

Create isteği (Receiver-supplied alanlar: `events_requested`, `delivery`, `description`):
```http
POST /ssf/streams HTTP/1.1
Authorization: Bearer <at>
Content-Type: application/json

{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rp.example/events",
             "authorization_header":"Bearer rp-supplied-secret"},
 "events_requested":["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
 "description":"RP A"}
```
Yanıt **201 Created**, tam config:
```json
{"stream_id":"f67e...","iss":"https://idp.example.com","aud":["https://rp.example"],
 "delivery":{...},"events_supported":[...],"events_requested":[...],"events_delivered":[...],
 "min_verification_interval":60,"inactivity_timeout":2592000}
```
- `events_delivered` = `events_supported` ∩ `events_requested` — **Receiver buna göre davranır**
- `delivery` yoksa → **poll (RFC 8936) varsayılır**, Transmitter `endpoint_url`'i kendisi üretir
- Çoklu stream desteklemiyorsanız ikinci create'e **409 Conflict**
- Hata kodları: 400 parse, 401 authz yok, 403 izin yok, 409 çoklu stream yok

**Status Endpoint** — `GET ?stream_id=` → `{"stream_id","status","reason"}`; status ∈ `enabled|paused|disabled`. `POST` ile güncelleme.
- `paused`: olayları **tut** (SHOULD), enabled olunca gönder. Aynı subject için sıralı ya da yalnızca son olay.
- `disabled`: tutma yok.
- Transmitter kendi kararıyla değiştirirse **`stream-updated` olayı göndermek ZORUNLU** (enabled→paused/disabled: durdurmadan **önce**).

**Add/Remove Subject Endpoints** — `POST`. Complex subject eşleştirmesinde **tanımsız alanlar wildcard**: Receiver `{tenant: X}` eklerse, `{tenant: X, user: Y}` subject'li olay da gönderilir.

**Verification Endpoint** — `POST {"stream_id":"...","state":"opaque"}` → **204 No Content**. Sonra async olarak SET gönderilir. Hatalar: 400, 401, 404, **429** (`min_verification_interval` aşımı).

#### C) SET formatı — tuzaklar

```json
{
  "typ": "secevent+jwt",       // JOSE header — explicit typing ZORUNLU
  "alg": "RS256"               // Interop profili: RS256 ≥2048-bit ZORUNLU
}
{
  "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
  "iss": "https://idp.example.com",
  "aud": "https://rp.example/caep",
  "iat": 1615305159,
  "txn": "8675309",
  "sub_id": { "format": "iss_sub", "iss": "...", "sub": "jane@example.com" },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1615304991,
      "initiating_entity": "policy",
      "reason_admin": {"en": "Landspeed Policy Violation: C076E82F"},
      "reason_user":  {"en": "Access attempt from multiple regions."}
    }
  }
}
```

> **🔴 Üç MUST NOT:** `sub` claim'i **yasak**. `exp` claim'i **yasak**. `events` içinde **birden fazla olay yasak** (interop profili MUST).
> Subject **her zaman top-level `sub_id`** ile taşınır — CAEP/RISC'in eski `subject` alanı kullanılsa bile `sub_id` **zorunlu**.
> `txn` — aynı kök nedenden doğan farklı SET'lerde (session-revoked + credential-change) **aynı değer** kullanılmalı; korelasyon için kritik.

#### D) Delivery

**Push (RFC 8935):**
```http
POST /events HTTP/1.1
Host: rp.example
Content-Type: application/secevent+jwt      ← ZORUNLU
Accept: application/json                     ← ZORUNLU
Authorization: <stream config'teki authorization_header>

<JWT>
```
Başarı: **202 Accepted**, boş body. Hata: **400** + `{"err":"...","description":"..."}` + `Content-Language`.
Hata kodları: `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, `authentication_failed`, `access_denied`.

> SSF profili `delivery.authorization_header` alanını tanımlar — **Receiver verir, Transmitter her istekte aynen gönderir**. Bu, sizin tarafınızda saklanan bir 3. taraf statik credential'ıdır; şifreli saklayın ve rotasyon yolu bırakın.

**Poll (RFC 8936):** `POST` `application/json`
- İstek: `maxEvents` (0 = yalnızca ack), `returnImmediately` (default **false** = long-poll), `ack: [jti...]`, `setErrs: {jti: {err, description}}`
- Yanıt: `{"sets": {"<jti>": "<jwt>", ...}, "moreAvailable": true}`
- Ack'lenene kadar SET'i saklayın; ack sonrası saklama yükümlülüğü kalkar; tekrar teslim edilebilir (Receiver idempotent olmalı)

#### E) OAuth yetkilendirmesi (Interop Profili — zorunlu)

- Roller: **Resource Server = Transmitter**, **Client = Receiver**, AS ayrı bir varlık olabilir
- AS `client_credentials` **veya** `authorization_code` desteklemeli
- **Kısa ömürlü token = ≤ 60 dakika** (FAPI güvenlik değerlendirmelerine atıf)
- Token **`Authorization` header'ında** (RFC 6750 §2.1); **URI query parametresi YASAK** (§2.3)
- Transmitter: token geçerlilik/bütünlük/expiry/**revocation** kontrolü + yetki yeterliliği; yetersizse RFC 6750 §3.1 hataları
- **Scope'lar (ZORUNLU):**
  - `ssf.read` → Read Stream Configuration + Get Stream Status
  - `ssf.manage` → `ssf.read` + Create Stream + Delete Stream + Stream Verification
  - `ssf.` ile başlayan scope'lar **rezerve**, yalnızca SSF spec'leri tanımlayabilir

#### F) Interop profili — uçtan uca zorunluluklar
- TLS ≥ 1.2, RFC 9325 uyumlu
- Subject identifier formatları (RFC 9493): **`email`**, **`iss_sub`**, **`opaque`** (yalnızca verification için) — Transmitter en az birini üretebilmeli, Receiver hepsini kabul etmeli
- Transmitter zorunlu operasyonlar: Create, Read Config, Read Status, Verification, Delete
- **En az bir use case** desteklenmeli: session-revoked / credential-change / device-compliance-change / risk-level-change — hepsinde `reason_admin` **boş olmayan bir nesne olmalı**

### 2.3 CAEP olay tipleri — TAM LİSTE ve şemalar

Base URI: `https://schemas.openid.net/secevent/caep/event-type/`

Tüm olaylarda opsiyonel ortak claim'ler: `event_timestamp`, `initiating_entity` ∈ `{admin, user, policy, system}`, `reason_admin` (BCP47 dil→mesaj), `reason_user` (BCP47 dil→mesaj).

| # | Olay | Zorunlu alanlar | Opsiyonel |
|---|---|---|---|
| 1 | `session-revoked` | *(yok)* | — |
| 2 | `token-claims-change` | `claims` (yeni değerlerle nesne) | — |
| 3 | `credential-change` | `credential_type`, `change_type` | `friendly_name`, `x509_issuer`, `x509_serial`, `fido2_aaguid` |
| 4 | `assurance-level-change` | `namespace`, `current_level` | `previous_level`, `change_direction` ∈ `{increase, decrease}` |
| 5 | `device-compliance-change` | `previous_status`, `current_status` ∈ `{compliant, not-compliant}` | — |
| 6 | `session-established` | *(yok)* | `fp_ua`, `acr`, `amr[]`, `ext_id` |
| 7 | `session-presented` | *(yok)* | `fp_ua`, `ext_id` |
| 8 | `risk-level-change` | `principal`, `current_level` ∈ `{LOW, MEDIUM, HIGH}` | `previous_level`, `risk_reason` |

Detaylar:
- `credential_type` ∈ `password, pin, x509, fido2-platform, fido2-roaming, fido-u2f, verifiable-credential, phone-voice, phone-sms, app` (+ karşılıklı anlaşılan)
- `change_type` ∈ `create, revoke, update, delete`
- `namespace` ∈ `RFC8176, RFC6711, ISO-IEC-29115, NIST-IAL, NIST-AAL, NIST-FAL` (+ özel)
- `principal` ∈ `USER, DEVICE, SESSION, TENANT, ORG_UNIT, GROUP` (+ SSF §2'deki diğer varlıklar)
- SSF çerçeve olayları: `.../ssf/event-type/verification` (`state`), `.../ssf/event-type/stream-updated` (`status`, `reason`) — bunlar `events_delivered`'da olmasa da gönderilebilir

**RISC 1.0 olayları** (base: `https://schemas.openid.net/secevent/risc/event-type/`):
`account-credential-change-required`, `account-disabled`, `account-enabled`, `account-purged`, `credential-compromise` (`credential_type` zorunlu), `identifier-changed`, `identifier-recycled`, `opt-in`, `opt-out-initiated`, `opt-out-cancelled`, `opt-out-effective`, `recovery-activated`, `recovery-information-changed`, `sessions-revoked`

### 2.4 Karşı taraf desteği — GERÇEK durum

Bugün canlı olarak sorguladığım sonuçlar:

**Google — hâlâ pre-standart.** `https://accounts.google.com/.well-known/ssf-configuration` → **404**. Çalışan tek şey `risc-configuration`:
```json
{"issuer":"https://accounts.google.com",
 "jwks_uri":"https://www.googleapis.com/oauth2/v3/certs",
 "delivery_methods_supported":["http://schemas.openid.net/secevent/risc/delivery-method/push"],
 "add_subject_endpoint":"https://risc.googleapis.com/v1beta/subjects:add",
 "get_status_endpoint":"https://risc.googleapis.com/v1beta/stream/status",
 "get_configuration_endpoint":"https://risc.googleapis.com/v1beta/v1beta/stream",
 "update_configuration_endpoint":"https://risc.googleapis.com/v1beta/stream:update",
 "verification_endpoint":"https://risc.googleapis.com/v1beta/stream:verify"}
```
Dikkat: alan adları **standart dışı** (`get_status_endpoint` ≠ `status_endpoint`, `get_configuration_endpoint` ≠ `configuration_endpoint`), delivery method URN'i **eski** (`urn:ietf:rfc:8935` değil), endpoint'ler **`v1beta`** (üstelik bir tanesinde `v1beta/v1beta` çift path bug'ı var). **Receiver yazarken Google'a özel bir adaptör şart.**

**Test altyapısı — çalışıyor:** `https://ssf.caep.dev/.well-known/ssf-configuration` canlı, ancak `spec_version: "1_0-ID2"` (final değil). Interop testleriniz için kullanılabilir.

| Sağlayıcı | Transmitter | Receiver | Not |
|---|---|---|---|
| **Okta** | ✅ Üretimde (CAEP + RISC) | ✅ Üretimde (ITP) | Standart SSF'e en yakın ticari implementasyon |
| **Google** | ⚠️ RISC, pre-standart şekilde | ⚠️ Workspace SSF receiver **closed beta** (ikincil kaynak, doğrulanmadı) | |
| **Microsoft Entra** | ❌ Standart SSF transmitter **yok** | ❌ Standart SSF receiver endpoint'i **yok** | Kendi CAE'si var ama RFC 9470 değil, `insufficient_claims` + base64 `claims` kullanıyor |
| **Keycloak** | ⚠️ Transmitter merge edildi (Tem 2026), **experimental flag arkasında** | ❌ | Transactional outbox deseni kopyalanmaya değer |
| **SailPoint, Cisco, IBM, Omnissa, Thales, CrowdStrike, Zscaler, Jamf** | Interop etkinliklerinde gösterildi | | Üretim durumu vaka bazında |

**Sertifikasyon programı:** OpenID Foundation'ın sertifikasyon sayfasında SSF/CAEP profili **bulamadım**. Yani "SSF certified" diye bir rozet henüz yok.

**Rust ekosistemi:** `sigshare` 0.1.0-alpha.2 (24 Şub 2026, **47 indirme**) — tek SSF/CAEP/RISC crate'i, alpha. Pratikte kendiniz yazacaksınız.

---

## 3. DPoP (RFC 9449) — İmplementasyon Derinliği

### 3.1 Sunucu doğrulama algoritması (RFC 9449 §4.3, birebir)

1. **Tam olarak bir** `DPoP` header'ı olmalı
2. Değer tek ve iyi biçimli bir JWT
3. §4.2'deki tüm zorunlu claim'ler var
4. `typ == "dpop+jwt"`
5. `alg` kayıtlı asimetrik imza algoritması, **`none` değil**, desteklenen ve politikaca kabul edilebilir
6. İmza, header'daki `jwk` ile doğrulanıyor
7. `jwk` **private key içermiyor**
8. `htm` == isteğin HTTP metodu
9. `htu` == isteğin URI'si, **query ve fragment yok sayılarak**
10. Nonce verdiyseniz, `nonce` claim'i eşleşiyor
11. JWT oluşturma zamanı (`iat` **veya** nonce'a gömülü sunucu zamanı) kabul edilebilir pencerede
12. Access token ile birlikte sunulduysa: `ath` == access token'ın hash'i **ve** access token'ın bağlı olduğu public key == proof'taki key

**Normalizasyon (SHOULD):** `htu` karşılaştırmasından önce RFC 3986 §6.2.2 (syntax-based) ve §6.2.3 (scheme-based) normalizasyonu uygulayın.

### 3.2 Nonce mekanizması

**AS tarafı (§8):** Nonce yoksa/uyuşmuyorsa → **400 Bad Request**
```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}
```

**RS tarafı (§9):** → **401 Unauthorized**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
```

- Nonce'lar **öngörülemez** olmalı; birden fazla kez kullanılabilir (kriptografik nonce değil)
- **AS nonce'ı ile RS nonce'ı farklıdır** — birbirinin yerine kabul edilmemeli
- **§11.3 (MUST):** Client'a nonce verdiyseniz, nonce'suz proof'u **asla kabul etmeyin** (downgrade koruması)
- **Birden fazla `DPoP-Nonce` header'ı YASAK**

**Neden nonce şart (§11.2):** Nonce olmadan, client'ı kontrol eden bir saldırgan (meşru kullanıcı dahil) `iat`'i geleceğe ayarlayarak **önceden proof üretip dışarı sızdırabilir**. O zaman kanıtlanan şey anahtar sahipliği değil, "bir proof'a sahip olmak"tır. **`ath` claim'i** bunu access token ömrüyle sınırlar; nonce kullanmıyorsanız **uzun ömürlü DPoP access token vermeyin** (SHOULD NOT).

### 3.3 jti replay cache stratejisi

RFC'nin doğrudan söyledikleri (§11.1):
- Sunucular proof'ları **yalnızca kısa bir süre** kabul etmeli — *"preferably only for a relatively brief period on the order of seconds or minutes"*
- Cache anahtarı **hedef URI bağlamında `jti`** olmalı — sadece `jti` değil, `(htu, htm, jti)` üçlüsü
- Tek-kullanım zorunluluğu *"may not always be feasible in practice, e.g., when multiple servers behind a single endpoint have no shared state"* — dağıtık ortamda RFC bunun zor olduğunu **kabul ediyor**
- **Bellek tükenmesi saldırısına karşı:** aşırı büyük `jti` değerlerini reddedin **veya yalnızca hash'ini saklayın**
- `iat` saat kayması: yakın gelecekteki `iat`'ler kabul edilebilir (MAY). **Ama:** saat kayması büyükse, `iat` yerine **nonce'a gömülü sunucu zamanını** kullanın — bu, keyfi saat kaymasında bile aynı sonucu verir

**Argus için pratik reçete:**
```
Anahtar:  BLAKE3(htm ‖ htu_normalized ‖ jti)  → 128 bit
TTL:      nonce ömrü (örn. 60 sn) veya iat penceresi (±30 sn) — hangisi kısaysa
Store:    tek-node → moka/dashmap; çok-node → Redis SETNX + EX
Kapasite: peak_rps × TTL × 16 byte
```
1000 rps ve 60 sn TTL → 60.000 girdi × ~32 byte ≈ **2 MB**. Redis round-trip'i eklemek istemiyorsanız: **nonce'ı node-affinity taşıyıcısı yapın** (nonce'a node ID gömün), böylece aynı proof aynı node'a gelir ve lokal cache yeter.

### 3.4 Performans

- Rust'ta **ES256 doğrulama ~20-50 µs** (`p256`/`ring`/`aws-lc-rs`). 10.000 rps → **0.2-0.5 CPU-core**. İhmal edilebilir.
- **RS256 doğrulama ES256'dan hızlıdır** (küçük public exponent), ama proof üretimi client'ta çok daha yavaştır — client donanım anahtarı kullanıyorsa ES256 tercih edin.
- **Asıl maliyet imza değil:** (a) JWT parse + base64 decode + JSON deserialize, (b) jti cache I/O, (c) nonce round-trip'inin eklediği **ekstra HTTP isteği**.
- **Nonce round-trip'i gizleyin:** her başarılı yanıtta `DPoP-Nonce` header'ı ile **proaktif olarak yeni nonce verin**; böylece client hiçbir zaman 400/401 yemez. Nonce'ları kayan pencerede (örn. mevcut + önceki) kabul edin.
- ⚠️ Bağımsız, hakemli DPoP benchmark'ı **bulamadım**. Yukarıdaki rakamlar genel ECDSA ölçümlerinden çıkarımdır — kendi ortamınızda ölçün.

### 3.5 DPoP + refresh token rotation

RFC §5'in normatif kuralları:

- **Public client'a** DPoP proof ile refresh token verildiyse → refresh token o public key'e **bağlanmak ZORUNDA (MUST)**, ve her kullanımda bağ **doğrulanmak ZORUNDA**. Client, refresh token'ı kullandığı **her seferde aynı key ile** proof sunmak zorunda.
- **Confidential client'ın** refresh token'ı DPoP key'e **bağlanmaz** — zaten client authentication ile sender-constrained. RFC gerekçesi: mevcut mekanizma daha esnek, *"credential rotation for the client without invalidating refresh tokens"* mümkün.
- AS, `token_type: "Bearer"` dönerek **yalnızca refresh token'ı DPoP'a bağlayabilir** — RS'ler DPoP desteklemiyorsa bile güvenlik kazancı sağlar. Kademeli geçiş için doğru yol budur.
- **Anahtar rotasyonu:** RFC'de public client için key rotation mekanizması **yok**. Anahtar değişirse refresh token ölür → yeniden authorization gerekir. Bunu bilinçli tasarlayın (cihaz anahtarı kaybı = yeniden login).

**`dpop_jkt` ile authorization code bağlama (§10):** Authorization request'e `dpop_jkt=<JWK thumbprint SHA-256>` ekleyin. Token endpoint'te proof'un thumbprint'i ile karşılaştırın; eşleşmiyorsa **MUST reject**. PKCE ile birlikte kullanılabilir; ancak koruma yalnızca **her authorization request için ayrı DPoP key** kullanılıyorsa PKCE'ye benzer düzeye çıkar. PAR ile de kullanılabilir.

### 3.6 IETF taslakları — 2026 durumu (datatracker'dan doğrulandı)

| Taslak | Rev | Tarih | Durum |
|---|---|---|---|
| `draft-parecki-oauth-dpop-device-flow` | **00** | 20 Eyl 2025 (süresi 24 Mar 2026'da doldu) | Bireysel, WG adopte etmedi. Parecki (Okta) + Campbell (Ping) |
| `draft-rosomakho-oauth-dpop-rt` | **00** | 14 Eki 2025 (süresi doldu) | Bireysel, **Informational**. Zscaler |
| `draft-parecki-oauth-jwt-dpop-grant` | 01 | 3 Ağu 2026 | Bireysel |
| `draft-ritz-idpop` ("Interactive DPoP") | 01 | 6 Tem 2026 | Bireysel |
| `draft-nandakumar-oauth-dpop-proof` | 00 | 19 Mar 2026 | Bireysel, uygulama-agnostik DPoP çerçevesi |

**`draft-parecki-oauth-dpop-device-flow` neden önemli:** Device Authorization Grant'e DPoP eklendiğinde `device_code` **belirli bir public key'e bağlanır** — *"preventing a stolen device_code from being redeemed by a malicious actor."* Bu, §5'te göreceğiniz **device code phishing** salgınına doğrudan yapısal cevaptır. Ama taslak rev 00 ve süresi dolmuş; **WG'ye taşınması için itmeye değer.**

**`draft-rosomakho-oauth-dpop-rt`:** `DPoP-RT` ve `DPoP-RT-Nonce` header'ları ile access ve refresh token'ları **farklı anahtarlara** bağlar. Motivasyon: refresh token backend/HSM'de, access token kısa ömürlü frontend'de. **Rev 00, süresi dolmuş — implemente etmeyin, haberdar olun.**

### 3.7 Bilinen tuzaklar (implementasyon raporlarından ve RFC'den)

1. **`htu` normalizasyonu** — trailing slash, port, case, percent-encoding. RFC 3986 §6.2.2/§6.2.3 uygulayın.
2. **TLS-sonlandıran proxy `Host`'u yeniden yazıyorsa** `htu` asla eşleşmez. `X-Forwarded-Host`/`Forwarded` header'ından **yapılandırılmış bir public origin** kullanın, asla istemciden gelen değere körü körüne güvenmeyin.
3. **`htm` case** — RFC "matches" diyor; HTTP metodları case-sensitive'dir, `POST` ≠ `post`. Sıkı karşılaştırın.
4. **`ath` yalnızca RS'te** — token endpoint'inde `ath` beklemeyin.
5. **Introspection ile RS:** RS, access token'ın `cnf.jkt` değerini introspection yanıtından almalı ve proof'un thumbprint'i ile karşılaştırmalı.
6. **Nonce karışıklığı** — AS nonce'ı, RS nonce'ı ve OIDC ID Token `nonce`'ı üç ayrı şeydir. RFC bunu açıkça uyarıyor.
7. **`alg: none` ve `jwk`'da private key** — ikisini de reddedin (§4.3 madde 5 ve 7).
8. **`dpop_signing_alg_values_supported`** metadata alanını AS metadata'sında yayınlayın (RFC §5.1).

---

## 4. Token Binding Alternatifleri

### 4.1 mTLS (RFC 8705) vs DPoP — hangisi ne zaman

| | **mTLS (RFC 8705)** | **DPoP (RFC 9449)** |
|---|---|---|
| Katman | TLS | Uygulama |
| Bağlama | `cnf.x5t#S256` = client sertifikasının DER'inin base64url SHA-256'sı | `cnf.jkt` = JWK thumbprint |
| Client auth metotları | `tls_client_auth` (PKI; `tls_client_auth_subject_dn` / `san_dns` / `san_uri` / `san_ip` / `san_email` — **tam olarak biri**), `self_signed_tls_client_auth` | — |
| Altyapı gereksinimi | TLS sonlandırma noktasında client cert erişimi; **CDN/proxy sorunlu** | Yok — saf HTTP header |
| Per-request maliyet | ~0 (TLS handshake'te bir kez, session resumption ile amortize) | Her istekte 1 imza doğrulama + jti cache |
| Tarayıcı desteği | Zayıf/UX kötü | JS'ten kullanılabilir ama key non-extractable olmalı (WebCrypto) |
| Uygun olduğu yer | **B2B, sunucu-sunucu, FAPI, yüksek güvence, sabit altyapı** | **Mobil/SPA/CLI/public client, dinamik istemci tabanı** |

**FAPI 2.0** her ikisini de kabul eder ve **sender-constraining'i zorunlu kılar** — bearer token'a izin vermez. Bir IdP'nin ikisini de desteklemesi doğru karardır; `cnf` claim'i her iki durumda da doğrulama noktasını tekilleştirir.

### 4.2 Token Binding (RFC 8471/8472/8473) neden öldü

- TLS katmanına **derin** müdahale gerektiriyordu (TLS extension + exported keying material).
- TLS 1.3 ile birlikte yeniden tasarım gerekti; ekosistem takip etmedi.
- **Terminatör problemi:** CDN, load balancer, TLS-inspection middlebox'ların hepsi Token Binding'i kırıyordu — mTLS'in yaşadığı sorunun daha ağır hâli.
- Chrome desteği kaldırdı; Edge (Legacy) ile birlikte pratik olarak yok oldu; server tarafı destek (IIS/ADFS) izole kaldı.
- **Ders:** TLS katmanında çalışan bağlama mekanizmaları modern web altyapısıyla uyumsuzdur. **DPoP'un uygulama katmanında olması bir tesadüf değil, Token Binding'in ölümünden çıkarılan derstir.** DBSC de aynı sebeple HTTP header + JWT üzerine kuruldu.

### 4.3 Cihaz donanım anahtarına bağlama — sunucu tarafında ne doğrulanır

#### Android Keystore / StrongBox key attestation

**⚠️ 2026 kritik değişikliği: Google attestation root'u değişti.**
- Eski root: `SERIALNUMBER=f92009e853b6b045` — **1 Şubat 2026'ya kadar** geçerli
- Yeni root: **`CN=Key Attestation CA1`**, **EC P-384** — **1 Şubat 2026'dan itibaren**
- Root listesi: `https://android.googleapis.com/attestation/root` (JSON)

Sunucu doğrulama sırası:
1. `KeyStore.getCertificateChain()` ile gelen X.509 zincirini al
2. Her sertifikanın bir sonrakini imzaladığını doğrula
3. Root'un Google'ın yayınladığı listede olduğunu doğrula
4. **CRL kontrolü:** `https://android.googleapis.com/attestation/status` → `{"entries": {"<serial-hex>": {"status":"REVOKED","reason":"KEY_COMPROMISE",...}}}`. `REVOKED` veya `SUSPENDED` → reddet. `Cache-Control` header'ına göre önbellekle. **2021 öncesi cihazlarda fabrika anahtarları expired olabilir ama CRL'de yoksa güvenilir** — expiry kontrolünü bu durumda uygulamayın.
5. **Attestation extension'ı bul — root'a EN YAKIN sertifikada.** 🔴 *"Only trust the FIRST occurrence"* — zincirde ikinci bir attestation extension varsa bu **forgery göstergesidir**, reddedin.
6. ASN.1 ile `KeyDescription` parse et: `attestationVersion`, `attestationSecurityLevel`, `keymasterSecurityLevel`, `attestationChallenge`, `softwareEnforced`, `teeEnforced` (AuthorizationList)
7. **`attestationChallenge` == senin gönderdiğin nonce** — tazelik kanıtı
8. `attestationSecurityLevel ∈ {TrustedEnvironment, StrongBox}` — **`Software` ise donanım garantisi yok**
9. Kritik özellikleri **`teeEnforced`** listesinden oku (softwareEnforced'a güvenme): `purpose`, `algorithm`, `noAuthRequired`, `userAuthType`, `origin`
10. Doğrulamayı **asla cihazda yapma** — ele geçirilmiş Android sistemi attestation forge edebilir

Google resmi Kotlin kütüphanesi: `github.com/android/keyattestation`

#### Apple — Secure Enclave

- **App Attest** (iOS/iPadOS uygulamaları): `attest` çağrısı → CBOR attestation object; sunucu Apple App Attest root CA'ya kadar zinciri, `clientDataHash` (nonce) eşleşmesini, `appId` hash'ini, counter'ı ve `credCert`'teki public key'i doğrular. Sonraki istekler için `assert` → counter monoton artmalı.
- **DeviceCheck** — cihaz başına 2 bit + risk metriği; kimlik doğrulama bağlamak için uygun **değil**.
- **Web tarafında Secure Enclave'e doğrudan erişim yok** — yalnızca WebAuthn platform authenticator üzerinden dolaylı (Touch ID / Face ID).
- **DBSC macOS**'ta Secure Enclave kullanacağı duyuruldu ama sertifika zinciri **sunucuya gönderilmiyor** (fingerprinting karşıtı tasarım) → sunucu donanım garantisini **doğrulayamaz**.

#### TPM 2.0 / Windows Hello

- **WebAuthn `tpm` attestation format**: `ver: "2.0"`, `alg`, `x5c` (AIK sertifika zinciri), `sig`, `certInfo` (TPMS_ATTEST), `pubArea` (TPMT_PUBLIC). Sunucu: `certInfo.extraData == authenticatorData ‖ clientDataHash` özeti, `certInfo.attested.name` == `pubArea`'nın name'i, AIK sertifikasının TPM üreticisi CA'sına zincirlenmesi, EKU `2.23.133.8.3` (`tcg-kp-AIKCertificate`), Subject Alternative Name'de TPM manufacturer/model/version.
- **Windows Hello for Business**: Entra ID'ye karşı FIDO2 kimlik bilgisi olarak sunulur.
- ⚠️ **2026 uyarısı:** Dirk-jan Mollema (Ağu 2026) — ele geçirilmiş bir kullanıcı oturumundaki düşük yetkili process'ler, Windows kripto arayüzlerini çağırarak WHfB anahtarlarını **PIN/biyometrik yeniden doğrulama olmadan** kullanabiliyor. Ayrıca **Entra'nın 5 dakikalık WebAuthn challenge'ları oturuma bağlı değil.** Yani "TPM'de anahtar var" ≠ "kullanıcı orada".
- ⚠️ **CVE-2026-34348** (SpecterOps, Black Hat USA, 5 Ağu 2026): Windows Event Logging Service, WebAuthn assertion imzalarını **düz metin** olarak yetkisiz okunabilir loglara yazıyordu → Entra'daki bir zayıflıkla zincirlenerek phishing-dirençli MFA atlatıldı. Microsoft **14 Tem 2026** yamasıyla imza alanlarını 6 bayta kısalttı; **SpecterOps 10 Ağu 2026 itibarıyla Entra tarafında değişiklik gözlemlemediğini bildirdi.**

#### WebAuthn `devicePubKey` (Device-Bound Public Key) uzantısı

Synced passkey'lerin yanında cihaza özgü, **senkronize olmayan** ikinci bir anahtar sunar — "bu assertion hangi fiziksel cihazdan geldi" sorusuna cevap verir. **Yaygın platform desteği hâlâ yok** (Eylül 2026 itibarıyla doğrulayamadım). İzlemeye değer; bugün üzerine mimari kurmayın.

---

## 5. AiTM ve Oturum Hırsızlığı — 2026 Tehdit Verisi

### 5.1 PhaaS piyasası: Tycoon takedown'ı ve dersi

- **Zirve (2025):** CrowdStrike — Microsoft'un engellediği phishing girişimlerinin **%62'si** Tycoon 2FA; tek ayda **30M+** kötü amaçlı e-posta. Okta — yalnızca Temmuz 2025'te **11.199 tespit**.
- **Takedown: 4 Mart 2026** — Europol EC3 koordinasyonu, 6 ülke, **330 domain**.
- **Sonuç:** CrowdStrike, hacmin 4-5 Mart'ta ¼'e düştüğünü ama **günler içinde eski seviyeye döndüğünü** raporladı. Okta, altyapının **1-2 gün içinde** dört yeni sağlayıcıya taşındığını gözlemledi.
- **Barracuda (16 Nis 2026):** Mamba 2FA, EvilProxy, Sneaky 2FA, Whisper 2FA boşluğu doldurdu; **dört büyük platformun toplam hacmi takedown SONRASI arttı** (~20M → 23M+). Barracuda, Tycoon'un imza yorum satırlarını taşıyan **%99 kod benzerlikli bir device code phishing kampanyası** tespit etti.

> **Ders: Arz tarafına yönelik en büyük müdahale bile toplam hacmi düşürmedi, yeniden dağıttı. Savunma kit markasına değil tekniğe göre tasarlanmalı.**

### 5.2 2026'da teknik olarak ne değişti

1. **Anti-bot kapıları standart.** Cloudflare **Turnstile** neredeyse her ciddi kitte — hem kötü amaçlı kaynak yüklemesini geciktiriyor hem otomatik analizi engelliyor.
2. **Reverse proxy'den uzaklaşma.** İki yönde:
   - **Whisper 2FA** (Barracuda, 15 Eki 2025) — proxy yok, **AJAX tabanlı gerçek zamanlı exfiltration döngüsü**; credential'ı **birden çok kez** çalıyor; çok katmanlı Base64+XOR; **agresif anti-debug** (devtools açılırsa tarayıcıyı çökertiyor). Bir ayda ~1M saldırı.
   - **Starkiller** (CSA Labs, 2026) — **Docker içinde headless Chrome** gerçek login sayfasını proxy'liyor; kurban **otantik sayfanın kendisiyle** etkileşiyor. Keystroke logging, canlı ekran akışı, parola yöneticisi modülleri (1Password), **OAuth device flow modülü**. Aylık 200-350 USD.
3. **OS-duyarlı dinamik DOM.** Sneaky2FA (Kas 2025) **BitB** ekledi: sahte tarayıcı penceresi kurbanın **OS+tarayıcısına göre** boyutlandırılıp stillendiriliyor (Windows→Edge, macOS→Safari görünümü).
4. **Residential proxy katmanlaması.** Elastic'in Tycoon analizi: otomatik relay katmanı bulut VPS'lerde (`axios`, `undici` user-agent'ları), **operatör konsolu ise residential proxy'den** — coğrafi/ASN tespitini kasten etkisizleştiriyor.
5. **WebSocket/Socket.IO relay** klasik akışta hâlâ baskın (bazı kitler Socket.IO 4.7.5'i CDN'den yüklüyor — ironik bir tespit fırsatı).

**Tespit için en değerli iki davranışsal imza (Elastic):**
- Google Workspace: **aynı kullanıcı için ~1 saniye içinde birden fazla IP'den kimlik doğrulama** (coğrafyaya değil, **zamansal imkânsızlığa** dayanıyor)
- M365: Node.js user-agent'ları (`axios`, `undici`) ile otomatik relay

**🔴 Elastic'in en operasyonel bulgusu:** Kit, **cihaz tabanlı PRT kalıcılığı** kuruyor ve bu **oturum iptalinden sağ çıkıyor**. Doğru müdahale sırası: **önce kayıtlı device principal'ı sil, SONRA oturumları iptal et.** Ters sıra kalıcılığı kırmıyor. Kit→operatör devir penceresi **10-20 dakika**; otomasyonla **<10 sn** konteynman mümkün.

### 5.3 BitM (Browser-in-the-Middle) — DBSC'yi neden yenebilir

**Mandiant / Google Cloud, 17 Mart 2025.** Kurban sahte siteye bakmıyor; saldırganın sunucusunda çalışan **gerçek bir tarayıcıyı** uzaktan kontrol ediyor (noVNC veya WebRTC).

| | AiTM (Evilginx, Tycoon) | **BitM** (Delusion, CuddlePhish, EvilnoVNC) |
|---|---|---|
| Kurulum | Hedef başına **phishlet** yazımı (saatler) | **Herhangi bir siteye saniyeler içinde** |
| Çalınan | Oturum çerezi + credential | **Tüm tarayıcı profili** — çerez, localStorage, IndexedDB, service worker |
| Görsel | Fark olabilir | Birebir gerçek sayfa |

**🔴 Kritik ve zor nokta:** BitM'de oturum **en baştan saldırganın tarayıcısında** oluşuyor. Bu, çerezin başka makineye taşınması **değil**. Dolayısıyla saldırganın tarayıcısı kendi TPM'iyle **DBSC kaydını meşru şekilde tamamlayabilir** — oturum saldırganın cihazına *doğru şekilde* bağlanmış olur. Aynı mantık Entra Token Protection için de geçerli.

> ⚠️ **Belirsizlik:** Bu, Google veya Mandiant tarafından bu ifadeyle yayımlanmış bir tespit **değil**; DBSC spec'inin *"DBSC will also not prevent an attack if the attacker is replacing or injecting into the user agent at the time of session registration"* ifadesinden ve BitM mimarisinden çıkan **analitik bir sonuçtur**.

**BitM'i durduran şey: FIDO2/WebAuthn origin binding.** Mandiant bunu açıkça belirtiyor — kurbanın platform authenticator'ı uzaktan çağrılamaz, video akışı kriptografik imza üretemez. Tek teorik istisna **caBLE/hybrid QR relay**'dir, ama caBLE tasarımı **BLE yakınlık doğrulaması** gerektirir. *Bu konuda doğrulanmış 2026 araştırması bulunamadı — teorik risk, gözlemlenmemiş.*

### 5.4 Passkey'lere saldırılar — kesin sınıflandırma

**2026 itibarıyla WebAuthn kriptografisinin kırıldığına dair kanıt YOK.** Bilinen tüm "bypass"lar beş kategoriden birinde:

| Saldırı | Durum | Ön koşul |
|---|---|---|
| **FIDO downgrade** (Proofpoint, Ağu 2025) — Evilginx phishlet'i **Windows'ta Safari** UA'sı spoofluyor; Entra FIDO'yu kapatıp OTP/push fallback'ine düşüyor | **PoC — vahşi doğada gözlemlenmedi** | AiTM proxy + fallback açık |
| **Zayıf hesap kurtarma** — Netcraft (7 Nis 2026) bunun **en çok kullanılacak yol** olacağını öngörüyor | **Gerçek ve yaygın** | Zayıf recovery |
| **Golden Pass-ta-key** (Unit 42, 3 Ağu 2026) — Chrome'un **Security Domain Secret**'ı (32-byte simetrik master key) FIDO diagnostic loglarında açıkta ve Chrome process belleğinde düz metin; tüm senkronize passkey private key'leri açılıyor. **Google'ın implementasyonunda bu sırrı rotate/revoke etme yolu YOK.** | **PoC — gözlemlenmedi** | Uç noktada çalışan malware |
| **CVE-2026-34348 / Pass-the-Passkey** (SpecterOps, 5 Ağu 2026) | **PoC — Windows yamalı (14 Tem 2026), Entra tarafı açık** | Yerel log okuma |
| **Windows Hello in-session abuse** (Mollema, Ağu 2026) | **PoC** | Ele geçirilmiş oturum |
| **caBLE/hybrid QR relay** | **Bilinmiyor — araştırma bulunamadı** | — |
| **PRF/largeBlob istismarı** | **Bilinmiyor — araştırma bulunamadı** | — |
| **Device code phishing ile passkey'i tamamen atlama** | **GERÇEK, AKTİF, YAYGIN** | Yok |

> **En önemli çıkarım: Passkey'lerin 2026'daki en büyük düşmanı bir passkey saldırısı değil — device code phishing'dir. Çünkü passkey akışını hiç devreye sokmadan geçerli token verir.**
>
> **İkinci çıkarım: Golden Pass-ta-key, "device-bound vs synced passkey" ayrımının gerçek bir güvenlik sınırı olduğunun somut kanıtıdır.** Donanım anahtarında (YubiKey) bu saldırı sınıfı uygulanamaz.

### 5.5 Device code phishing — 2026'nın ana hikâyesi

Push Security'nin özeti: *"Device code authorization, etkin biçimde kimlik doğrulama SONRASINDA gerçekleştirilir."* → **Tüm MFA ve passkey kontrollerini atlar**, sahte login sayfası yok, yamalanacak zafiyet yok (RFC 8628 tasarımı gereği).

| Veri | Kaynak |
|---|---|
| 2026'da device code phishing sayfalarında **37,5 kat artış** | Push Security, 4 Nis 2026 |
| Dolaşımda **14+** toolkit; **EvilTokens** lider | Push Security |
| Tek bir EvilTokens kampanyası (Şub-Mar 2026) **340+ M365 organizasyonu** ele geçirdi | CSA Labs, 4 Nis 2026 |
| **Storm-2372** (Rusya bağlantılı, orta güven) Ağu 2024'ten beri aktif | Microsoft, 13 Şub 2025 |
| Storm-2372 **Microsoft Authentication Broker** client ID'sine geçti → saldırgan kontrollü **cihaz kaydı** → **PRT** | Microsoft |
| Refresh token'lar **90 güne kadar** geçerli, **her kullanımda yenileniyor**; PRT **parola sıfırlamalarından sağ çıkıyor** | Microsoft |
| Scattered Lapsus$ Hunters: vishing + Salesforce device code → **1000+ organizasyon** | Push Security |

**Savunma:** Microsoft'un önerisi — 25 günden az kullanım geçmişi olan tenant'larda Conditional Access ile device code akışını **bloklamak**. Push Security uyarısı: tam koruma değil, `ConsentFix` gibi teknikler alternatif OAuth akışlarını istismar ediyor.

**Argus için doğrudan tasarım kararı:** Device Authorization Grant'i **varsayılan olarak kapalı** yapın; açıksa `draft-parecki-oauth-dpop-device-flow` mantığını uygulayın (device_code'u DPoP key'e bağlayın) ve `user_code` girişini **ayrı bir onay ekranında client adı + scope + IP göstererek** yapın.

### 5.6 Infostealer ölçek verisi 2026

**SpyCloud 2026 Annual Identity Exposure Report (19 Mart 2026):**

| Metrik | Değer |
|---|---|
| Datalake toplam kimlik kaydı | **65,7 milyar** (+%23 YoY) |
| **2025'te ele geçirilen oturum çerezi** | **8,6 milyar** |
| Infostealer enfeksiyonu (2025) | **13,2 milyon** |
| Enfeksiyon başına ortalama credential | ~50 |
| **EDR/AV korumalı uç noktalardaki enfeksiyon oranı** | **%40** |
| Parola yöneticisi ana parolası | **1,1 milyon** |
| AI aracı credential/cookie'si | **6,2 milyon** |
| Açığa çıkan API anahtarı/token (NHI) | 18,1 milyon |
| Parola tekrar kullanımı | Bireysel %65, kurumsal %42 |

**Flashpoint 2026:** 2025 tam yıl 11,1M+ enfekte cihaz, 3,3 milyar+ çalınmış credential/çerez/token. **H1 2026: 7,4M host (+%27 dönemsel), 1,7 milyar credential.**

**Verizon DBIR 2026 (20 Mayıs 2026):**
- Zafiyet istismarı ilk erişim vektörü lideri oldu (~%31), **ama credential kötüye kullanımı tüm ihlallerin %39'unda** var (herhangi bir aşamada)
- 🔴 **Ransomware kurbanlarının %73'ünde önceki yıl içinde ilişkili infostealer enfeksiyonu/credential sızıntısı var; %50'sinde ransomware'den 95 gün önce**
- IAB loglarındaki cihazların %54'ünde en az bir infostealer
- Kurumsal e-posta domain'lerinden **aylık ortalama 2.362** ihlal edilmiş credential
- **RMM aracı kötüye kullanımı +%240 YoY**
- Vishing tıklama oranı %2 vs e-posta phishing %1,4

**IBM X-Force 2026:** 2025'te **300.000+ ChatGPT credential seti** dark web'de; suçlular arasında veri hırsızlığı (%18) şifrelemeyi (%11) geçti.

**Aileler:** Lumma (Mayıs 2025 takedown'ından sağ çıktı — Bitdefender 11 Şub 2026 aktif C2 doğruladı; Microsoft 5 Mar 2026 yeni Windows Terminal varyantı); Rhadamanthys (13 Kas 2025 Operation Endgame, Tor fallback ile hayatta); **Vidar** (Kas 2025'ten beri baskın; Telegram ve Steam profillerini dead-drop resolver olarak kullanıyor); StealC (EDR'li ortamlarda tercih — düşük telemetri ayak izi); **VoidStealer** (Ara 2025'te MaaS, **v2.0 13 Mar 2026**); **AMOS/macOS** (Jamf Ağu 2025 %300 sıçrama; Sophos: macOS malware koruma güncellemelerinin %40'ı).

**Chrome App-Bound Encryption bypass durumu:**
- ABE Temmuz 2024'te Chrome 127 ile geldi; **Eylül-Ekim 2024'te** MeduzaStealer, Whitesnake, Lumma, Vidar, StealC bypass geliştirdi. Rhadamanthys geliştiricileri *"10 dakikamızı aldı"* dedi.
- Elastic "Katz and Mouse Game" (Eki 2024): STEALC/VIDAR **ChromeKatz** ile network service process belleğinden `CookieMonster` yapılarını okuyor; METASTEALER COM ile **SYSTEM token'ı taklit edip** `GoogleChromeElevationService`'i çağırıyor; PHEMEDRONE **remote debugging port 9222** + `Network.getAllCookies`.
- 🔴 **VoidStealer v2.0 (13 Mar 2026), en gelişmiş bypass:** **Donanım kesme noktaları.** `DebugActiveProcess` + `SetThreadContext` ile tarayıcıya debugger olarak bağlanıp `v20_master_key`'i çıkarıyor. **Tarayıcı belleğini değiştirmiyor** (software breakpoint'ten gizli) ve **yetki yükseltme gerektirmiyor** — önceki tüm yöntemler admin istiyordu.
- Google'ın 2024'teki kendi öngörüsü doğru çıktı: *"saldırgan davranışını injection veya memory scraping gibi daha gözlemlenebilir tekniklere kaydırmasını bekliyoruz."*

> **ABE bir güvenlik sınırı değil, maliyet artırıcıdır. Halefi DBSC'dir — çünkü çerezi korumak yerine çalınmış çerezi işe yaramaz kılar.**

**Infostealer'lar DBSC'yi hedefliyor mu?** Doğrudan bir "DBSC bypass" özelliği **belgelenmemiş** (mimari olarak bypass edilemez). Gözlenen adaptasyon **yön değiştirme**: çerez exfiltration yerine **canlı oturumu yerinde kötüye kullanma**, **refresh token / PRT / OAuth token** hedefleme, ve **parola** hedefleme (Constella: infostealer paketlerinin **%98,6'sı aktif parola**, **%99,54'ü kullanım URL'leri** içeriyor).

### 5.7 DBSC'nin gerçek dünya etkinliği

**🔴 Eylül 2026 itibarıyla kamuya açık, sayısallaştırılmış bir DBSC etkinlik ölçümü YOK.**
- Google (blog.google, 9 Nis 2026): *"we have observed a significant reduction in session theft since its launch"* — **metrik yok**
- Workspace duyurusu (28 May 2026): *"anlamlı ölçüde zorlaştırdı"* — **sayı yok**
- Okta ile yapılan testler: *"anlamlı azalma"* — **sayı yok**

**DBSC'nin kapsamadıkları (SpyCloud + Constella):** refresh token hırsızlığı, device code phishing, yerel malware'in canlı oturumu yerinde kötüye kullanması, PRT ve Kerberos TGT, localStorage'daki OAuth token'ları, BitM, dolaşımdaki mevcut credential'lar, ve **tüm parola vektörü**.

---

## 6. Oturum İçi Anomali Tespiti

### 6.1 Sinyal kanıt tablosu

| Sinyal | Kanıt gücü | Not |
|---|---|---|
| Kriptografik bağlama (DBSC/DPoP/mTLS) | **Yüksek — deterministik** | Anomali tespiti değil, kanıt |
| Refresh token / oturum ID **reuse detection** | **Yüksek — deterministik, FP'siz** | En yüksek getirili tek kontrol |
| WebAuthn re-assertion | **Yüksek** | Olay tetiklemeli olmalı, periyodik değil |
| Cihaz duruşu (MDM/EDR attestation) | **Orta-Yüksek** | Kriptografik doğrulanabilir; BYOD'da kapsama yok |
| IP / ASN değişimi | **Orta** | Tek başına aksiyon için zayıf |
| **Zamansal imkânsızlık** (~1 sn içinde farklı IP'ler) | **Yüksek** | Coğrafyaya değil fiziğe dayanıyor |
| JA4 TLS fingerprint | **Orta** | Yalnızca **sınıf değişimi** dedektörü olarak |
| JA3 | **Düşük — pratikte ölü** | Chrome extension sırası rastgeleleştirme + GREASE |
| HTTP/2 frame fingerprint | **Orta** | Reverse proxy arkasında bilgi kayboluyor; mimari maliyet yüksek |
| User-Agent tutarlılığı | **Düşük** | Taklit trivial |
| "Impossible travel" | **Düşük-Orta, yüksek FP** | **Microsoft'ta bile OFFLINE tespit** |
| Klavye/fare biyometrisi | **Düşük — pratikte kanıtsız** | Cross-session **HTER ≈ 0.19** |

**Microsoft'un kendi sınıflandırması öğretici:** Anonymous IP, Unfamiliar sign-in properties, Verified threat actor IP, Suspicious MFA approval → **real-time**. **Atypical travel, Impossible travel, AiTM, Malicious IP, Suspicious browser, Leaked credentials → OFFLINE** (raporlara 48 saate kadar). *Dünyanın en büyük IdP'sinde bile impossible travel gerçek zamanlı bir oturum içi kontrol değildir.*

**JA3'ün ölümü:** GREASE (RFC 8701) her bağlantıda değişiyor + **Chrome ClientHello extension sırasını rastgeleleştiriyor** → tek tarayıcı binlerce JA3 hash'i üretiyor. **JA4** GREASE'i eliyor ve extension'ları sıralıyor, ama **kullanıcıyı değil istemci sınıfını** ayırt ediyor. Doğru kullanım: *oturum başında JA4'ü kaydet; ortada **sınıf değişirse** (tarayıcı→HTTP kütüphanesi) güçlü sinyal. Aynı kalırsa hiçbir şey kanıtlamaz.* Düşük FP, çok düşük duyarlılık — iyi bir "AND" koşulu, kötü bir birincil sinyal.

**Davranışsal biyometri — neden hayır:** Yayınlanan iyi rakamlar (EER %2.48-3.60) **oturum-içi/cross-validation** ölçümlerinden. Model ve eşik Oturum 1'de sabitlenip Oturum 2'ye **değiştirilmeden** uygulandığında: sabit metin AUC 0.895, **HTER ≈ 0.19** — her 5 kararda ~1 hata. Fare dinamiklerinde durum daha kötü (*"önceki çalışmaların sonuçları tekrarlanabilir değil"*). Akademik eleştiri: *"Sözde sürekli kimlik doğrulama üzerine yapılan araştırmaların çoğu aslında periyodik kimlik doğrulamadır."*

### 6.2 Risk-Based Authentication — gerçek akademik kanıt

Wiefling ve ekibinin çalışmaları (okumaya değer):
- **arXiv:2101.10681** — 780 kullanıcı, 247 özellik, 1.8 yıl. Ana bulgu: *"RBA her online servise dikkatlice uyarlanmalıdır; küçük konfigürasyon ayarlamaları bile güvenlik ve kullanılabilirlik özelliklerini büyük ölçüde etkileyebilir."* → **Taşınabilir "doğru eşik" yok.**
- **arXiv:2206.15139** — **3,3 milyon kullanıcı, 31,3 milyon login.** ML tabanlı RBA parametre optimizasyonu + IP yerine **RTT** kullanımının gizlilik değerlendirmesi. **Veri seti kamuya açık** — kendi modelinizi kalibre etmek için gerçek başlangıç noktası.
- **arXiv:2308.15156** — Google/Amazon/Facebook yeniden test. **Birçok test senaryosu RBA'yı nadiren tetikliyor** — büyük sağlayıcılar bile "az tetikle" tarafında hata yapıyor.

### 6.3 Sinyalden aksiyona: katmanlı tasarım

```
KATMAN 0 — Kriptografik gerçekler (deterministik, itiraz kabul etmez)
  • revocation_epoch aşıldı mı?  • DBSC/DPoP proof geçerli mi?  • RT reuse?
  → BLOK / oturum iptali. Skor yok.

KATMAN 1 — Deterministik politika (yönetici yazmış, açıklanabilir, denetlenebilir)
  • IP named location dışında mı?  • Cihaz uyumlu mu?  • acr/auth_time yeterli mi?
  → RFC 9470 step-up challenge veya blok.

KATMAN 2 — Risk skoru (olasılıksal)
  • Unfamiliar sign-in props, ASN anomalisi, JA4 sınıf değişimi, TI eşleşmesi
  → Step-up TALEBİ + CAEP risk-level-change yayını + insan inceleme kuyruğu
  → ASLA otomatik kalıcı kilit YOK
```

**Katman 2'nin asla terminal karar vermemesinin hukuki gerekçesi — SCHUFA (CJEU C-634/21, 7 Ara 2023):** Mahkeme, otomatik skorlamanın sonraki kararda *"belirleyici rol oynadığı"* için **Art. 22 anlamında otomatik karar** olduğuna hükmetti. *"Skor sadece bir girdi"* savunması SCHUFA sonrası zayıf. **"Lastik damga" insan onayı zinciri kırmıyor.** Kullanıcıyı otomatik kalıcı kilitlemek muhtemelen Art. 22 kapsamında; **step-up talep etmek çok daha savunulabilir.**

**RFC 9470 step-up akışı:**
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A different authentication level is required",
  acr_values="urn:argus:acr:webauthn-uv", max_age="300"
```
Client bunları authorization request'e taşır; AS `acr` ve `auth_time`'ı access token'a (RFC 9068) veya introspection yanıtına koyar. AS metadata'sında `acr_values_supported` yayınlayın.

> ⚠️ **Microsoft CAE, RFC 9470 KULLANMIYOR.** Kendi mekanizması: `error="insufficient_claims"` + base64 kodlu `claims` (örn. `{"access_token":{"nbf":{"essential":true,"value":"1604106651"}}}`), istemci yeteneği MSAL `clientCapabilities: ["cp1"]` → token'da `xms_cc`. Argus'ta **RFC 9470'i birincil** yapın; Microsoft tarzını yalnızca "belirli bir andan sonra düzenlenmiş token" semantiği gerekirse ek olarak destekleyin. İkisi aynı 401'de birlikte yaşayabilir.

### 6.4 İptal yayılım gecikmesi — gerçekçi bütçeler

| Sistem | Yayılım |
|---|---|
| Entra CAE kritik olay | Hedef "gerçek zamanlıya yakın", **15 dk'ya kadar** gözlenebilir |
| Entra CAE IP konum politikası | **Anlık** (kaynağa replike edilmiş politika) |
| Entra CA politikası / grup üyeliği değişikliği | **2 saat – 1 gün** |
| Entra ID Protection offline tespit → rapor | **48 saate kadar** |
| Cloudflare Gateway device posture | **Yalnızca oturum başında** — devam eden oturumlar kesilmiyor |

Ayrıca Entra CAE'nin dokümante sınırları: yalnızca **IP tabanlı** named location'ları görebiliyor (ülke/bölge → CAE yok, 1 saatlik token); IP aralıkları toplamı **5.000'i aşarsa** gerçek zamanlı uygulayamıyor; **guest kullanıcılar desteklenmiyor**. CAE-aware oturumlarda token **28 saate kadar** uzuyor ve Configurable Token Lifetime politikası **onurlandırılmıyor**.

> **Bunun anlattığı ders: "Sürekli değerlendirme" pratikte "her istekte tam politika değerlendirmesi" değil; kaynağa replike edilmiş politika alt kümesi + asenkron iptal olayları demektir. Replikasyon gecikmesi mimarinin ana zorluğudur, algoritma değil.**

### 6.5 Yanlış-pozitif kilitlenmelerinden kaçınma

1. **Shadow mode zorunlu** — yeni her kural önce sadece loglasın
2. **"IdP'nin gördüğü IP" ve "RP'nin gördüğü IP" ayrı alanlar olarak loglansın** — Microsoft'un strict enforcement rollout'unun ilk adımı tam olarak bu. Bu ayrımı yapmayan sistem strict moda hiç geçemez.
3. **Öğrenme dönemi** — Entra: unfamiliar sign-in props min. 5 gün, atypical travel 14 gün/10 login
4. **Blok yerine step-up'a düş** (fail-open-to-friction)
5. **Break-glass yolu** her risk kuralı için
6. **FP bütçesini SLO gibi yönet** — eşik aşılırsa kural otomatik shadow'a dönsün
7. **Kademeli çıkış:** salt-okunur → karantina → iptal
8. **Acil "şimdi zorla" yolu** (Entra'nın `Revoke-MgUserSignInSession` muadili)

### 6.6 Latency bütçesi — üç katman

| Katman | Ne | Bütçe |
|---|---|---|
| **A — Her istekte** | JWT imza (in-process JWKS cache), `token.iat < user.revocation_epoch` kontrolü, önceden derlenmiş IP trie lookup, `acr`/`auth_time` aritmetiği, DPoP/DBSC proof | **p99 < 1 ms** — allocation'sız, ağ çağrısız |
| **B — Token yenilemede** | Tam politika değerlendirmesi, geolocation/ASN, threat intel, cihaz duruşu, risk skoru, grup üyeliği taze okuma | **50-200 ms kabul edilebilir** |
| **C — Asenkron** | Davranışsal baseline, atypical travel, ML çıkarımı, cross-tenant korelasyon → **CAEP olayı yayınla** | saniyeler-dakikalar |

**Her istekte tam risk değerlendirmesi neden yanlış hedef:** (a) sektörde kimse yapmıyor — Entra IP politikasını **replike ediyor**, DBSC proof'ları **cookie refresh'te**, Cloudflare Gateway **oturum başında**; (b) sinyaller saniyede bir değişmiyor; (c) 10.000 rps'te her isteğe 50 ms eklemek 500 eşzamanlı in-flight istek demek; (d) girdi aynıyken ML modeli ek bilgi üretmiyor, yalnızca skor gürültüsü ekliyor.

**Rust'a özgü öneriler:**
- Politikaları başlangıçta **karar ağacına/bit maskesine derleyin**; sıcak yolda string karşılaştırması olmasın
- IP eşleştirme için **patricia trie** (`ipnet` + özel) — Entra'nın 5.000 aralık sınırını siz yaşamayın
- `revocation_epoch`, JWKS ve politika snapshot'ları için **`arc-swap`** — sıcak yolda `RwLock` yok
- SSF için **transactional outbox** (`sqlx` + tokio worker) — olayı iş transaction'ı içinde yaz, dışarıda teslim et. Keycloak'ın (3 Tem 2026, experimental) yaptığı bu.
- Karar loglaması sıcak yoldan çıksın (bounded channel), ama **backpressure/drop politikasını bilinçli seçin** — denetim logu kaybetmek uyum sorunudur

### 6.7 Hukuki çerçeve — kısa

- **GDPR Art. 22 / SCHUFA:** yukarıda (§6.3)
- **GDPR Art. 9 / KVKK:** Davranışsal biyometri, kişiyi **benzersiz tanımlamak amacıyla** işlendiğinde özel nitelikli veri. KVKK'da **açık rıza** kural; KVKK rehberi veri sorumlularının **alternatif doğrulama yöntemi sunmasını** istiyor (**Haziran 2026'da mesai takibi biyometrisi için yeni ilke kararı**). → **Zorunlu kılamazsanız saldırgan da opt-out eder; kontrolün güvenlik değeri yapısal olarak sıfırlanır.**
- **EU AI Act:**
  - **Yasaklar (Art. 5), 2 Şubat 2025'ten beri yürürlükte:** işyerinde **duygu çıkarımı** (5(1)(f)) ve biyometriden **korunan özellik çıkarsama** (5(1)(g)) — **kurumsal bir IdP'de "stres tespiti" gibi bir şey düşünmeyin.**
  - **Kritik muafiyet:** Annex III, madde 1, *"tek amacı belirli bir gerçek kişinin iddia ettiği kişi olduğunu doğrulamak olan doğrulama sistemlerini hariç tutuyor"* → **1:1 biyometrik verification (WebAuthn dahil) Annex III yüksek risk kapsamı DIŞINDA.**
  - ⚠️ **Takvim uyarısı:** artificialintelligenceact.eu implementation timeline (son güncelleme 31 Ağu 2026) **Annex III yüksek risk için 2 Aralık 2027** diyor; birçok 2025-2026 makalesi hâlâ "2 Ağustos 2026" yazıyor. **Hangi hukuki araçla değiştiğini doğrulayamadım — hukuk ekibinize Official Journal'dan teyit ettirin.**

---

## 7. Argus için Sentez ve Öncelik Sırası

#### Faz 1 — Deterministik temel (heuristik yok)
1. **Refresh token rotation + reuse detection** — klasik, FP'siz, en yüksek getirili tek kontrol
2. **Kullanıcı başına `revocation_epoch`** — `token.iat < revocation_epoch` ⇒ ölü. O(1), tüm iptal tiplerini kapsar, RP'de tek cache lookup
3. **RFC 9470 step-up** — `acr`/`auth_time` claim'leri, `insufficient_user_authentication`, `acr_values_supported`
4. **DPoP (RFC 9449)** — nonce **açık**, jti cache `(htm, htu, jti)` + kısa TTL, public client refresh token binding
5. **mTLS (RFC 8705)** ikinci yol olarak — `cnf.x5t#S256`, FAPI 2.0 uyumu için
6. **WebAuthn** — ACR seviyelerine bağlı; yüksek değerli hesaplarda **donanım anahtarı** (Golden Pass-ta-key sync riskini somutlaştırdı)
7. **Device Authorization Grant varsayılan KAPALI**; açıksa device_code'u DPoP key'e bağla

#### Faz 2 — Standart sinyal yayını (SSF transmitter)
8. `/.well-known/ssf-configuration` + 5 endpoint + push (RFC 8935) & poll (RFC 8936)
9. CAEP olayları: `session-revoked`, `credential-change`, `token-claims-change`, `assurance-level-change`, `risk-level-change` — **`reason_admin` boş olmayan nesne** (interop profili MUST), `reason_user` dolu, `txn` ile korelasyon
10. **Transactional outbox** (Keycloak deseni)
11. CAEP Interoperability Profile'ı takip et — **10 Ekim 2026'da final olması bekleniyor**
12. `ssf.read` / `ssf.manage` scope'ları, ≤60 dk access token

#### Faz 3 — DBSC arayüzü (implementasyon değil, iskele)
13. Session store şeması: `session_id`, `public_key_jwk`, `jkt`, `scope`, `credentials`, `challenge_ring[3]`, `last_refresh`
14. `/dbsc/register`, `/dbsc/refresh`, `/.well-known/device-bound-sessions` endpoint'leri — feature flag arkasında
15. **`aud`/`iat` doğrulamasını opt-in yap** (Chrome minimal payload gönderiyor)
16. **4xx = oturum ölümü** kuralını routing/WAF/rate-limiter'a işle; 429 kullan, 404 kullanma
17. Kayıt penceresindeki unbound grant cookie'ye **tam yetki verme** — ayrı bir düşük-yetki durumu tanımla
18. Challenge TTL'i **dakikalar** düzeyinde (P90 registration 15 sn, kuyruk dakikalara uzuyor)

#### Faz 4 — Receiver ve politika
19. **SSF receiver** — `device-compliance-change` tüketimi (CrowdStrike/Jamf/Zscaler). **Google için özel adaptör** yaz (`risc-configuration`, `v1beta`, standart dışı alan adları)
20. **SCIM Events (RFC 9967, Mayıs 2026)** — lifecycle olayları; Entra'nın 1 günlük grup gecikmesini baştan tasarımdan çıkarın
21. IP named location'lar (patricia trie), **"IdP'nin gördüğü IP" ≠ "RP'nin gördüğü IP"** ayrı alanlar, zorunlu shadow mode

#### Faz 5 — Olasılıksal katman (dikkatli)
22. Unfamiliar sign-in properties — Wiefling'in **kamuya açık 3,3M kullanıcılık veri setiyle** kalibre et
23. **Zamansal imkânsızlık** (aynı kullanıcı, ~1 sn, farklı IP'ler) — coğrafyadan çok daha güvenilir
24. JA4 yalnızca **sınıf-değişimi dedektörü**, tek başına aksiyonsuz
25. Çıktı: step-up + CAEP `risk-level-change`. **Asla otomatik kalıcı kilit.**

#### YAPMA
- Davranışsal biyometri (HTER ≈ 0.19, GDPR Art.9 + KVKK açık rıza + alternatif sunma yükümlülüğü)
- İşyerinde duygu çıkarımı (**AI Act yasağı, Şubat 2025'ten beri**)
- Ham impossible travel'ı gerçek zamanlı blok tetikleyicisi yapmak (Microsoft bile offline)
- Kendi ITDR platformunu yazmak — **iyi bir SSF transmitter olun**; pazar IdP'nin sinyal üretip XDR/ITDR'ın tüketmesi yönünde gidiyor

#### Olay müdahalesi — doğru sıra (Elastic)
> **1) Kayıtlı device principal'ı sil → 2) Oturumları iptal et → 3) Token'ları iptal et.**
> Ters sıra cihaz tabanlı PRT kalıcılığını **kırmaz**. Saldırganın devir penceresi 10-20 dk; otomasyonla <10 sn konteynman mümkün.

---

## 8. Belirsizlikler ve Doğrulanamayanlar

1. **DBSC macOS durumu** — "yaklaşan sürümde" duyuruldu (Nis 2026). Bugün indirdiğim Chrome Enterprise policy template'inde tek DBSC politikası `chrome.win:124-` (**Windows only**). Bazı ikincil kaynaklar "Chrome 147 macOS" diyor; **doğrulayamadım, politika verisi aksini ima ediyor.**
2. **DBSC'nin sayısal etkinliği** — Google ve Constella yalnızca niteliksel ifadeler kullanıyor. **Kamuya açık metrik yok.**
3. **BitM'in DBSC'yi yendiği iddiası** — spec'in kendi non-goal'ünden ve BitM mimarisinden çıkardığım analitik sonuç. Google/Mandiant tarafından bu ifadeyle yayımlanmış tespit bulamadım.
4. **caBLE/hybrid QR relay araştırması (2026)** — bulunamadı. BLE yakınlık gereksinimi tasarım savunmasıdır; implementasyon sıkılığı doğrulanmadı.
5. **PRF/largeBlob istismar araştırması (2026)** — bulunamadı. "Golden Pass-ta-key PRF çıktılarını da açar mı?" sorusu **spekülatiftir**, kaynağa dayanmıyor.
6. **Google Workspace SSF receiver** — "closed beta" ikincil kaynaktan; doğrulayamadım. `accounts.google.com/.well-known/ssf-configuration` **404**.
7. **DPoP performans rakamları** — bağımsız, hakemli benchmark bulunamadı. Verdiğim 20-50 µs genel ECDSA ölçümlerinden çıkarımdır.
8. **EU AI Act Annex III tarihi** — timeline sayfası 2 Aralık 2027 diyor, birçok makale 2 Ağustos 2026. Değişikliğin hukuki aracını doğrulayamadım.
9. **CISA / NCSC / FIDO Alliance orijinal dokümanları** — HTTP 403 ve arama bütçesi nedeniyle birinci elden okunamadı; ikincil kaynaklar üzerinden.
10. **Microsoft'un "phishing-dirençli MFA %99+ engelliyor"** — bu rakam orijinalinde MFA geneli için üretilmiş bir istatistiktir; phishing-dirençli MFA'ya atfedilmesi ikincil kaynak aktarımıdır.
11. **SSF sertifikasyon programı** — OpenID Foundation sertifikasyon sayfasında SSF/CAEP profili bulamadım.

---

### Ekler

**Rust ekosistemi gerçeği (crates.io, bugün sorgulandı):**
| Alan | Durum |
|---|---|
| **DBSC** | **Hiçbir crate yok.** Sıfırdan yazacaksınız. |
| **SSF/CAEP/RISC** | `sigshare` 0.1.0-alpha.2 (24 Şub 2026, **47 indirme**) — alpha, tek seçenek |
| **DPoP** | `dpop-verifier` 4.4.0 (12k indirme), `turbomcp-dpop` 3.2.0 (Ağu 2026), `skyauth` 0.3.2 (8 Eyl 2026) |

**Test altyapısı:** `https://ssf.caep.dev/.well-known/ssf-configuration` — canlı SSF transmitter, `spec_version: "1_0-ID2"`. Interop testleri için kullanılabilir (final spec değil, dikkat).

**Referans implementasyonlar:** `github.com/CloudNua/dbsc-server` (TS, MIT, sıfır bağımlılık), `github.com/SulimanAbdulrazzaq/dbsc-toolkit` (Node), `github.com/android/keyattestation` (Kotlin, resmi Google).

**Ana spec URL'leri:**
- DBSC: https://w3c.github.io/webappsec-dbsc/ (ED, 27 Ağu 2026)
- SSF 1.0 Final: https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html
- CAEP 1.0 Final: https://openid.net/specs/openid-caep-1_0-final.html
- RISC 1.0 Final: https://openid.net/specs/openid-risc-1_0-final.html
- CAEP Interop 1.0 draft: https://openid.github.io/sharedsignals/openid-caep-interoperability-profile-1_0.txt
- RFC 9449 (DPoP), RFC 9470 (step-up), RFC 8705 (mTLS), RFC 8935/8936 (SET delivery), RFC 9493 (subject identifiers), RFC 9967 (SCIM Events)

## EK — DPoP, Token Binding ve Donanım Attestation (Derinleştirme)

### E.1 🔴 ACİL AKSİYON: Android attestation kök rotasyonu

Bu, raporun tamamındaki **tek "şu anda kırılıyor olabilir"** maddesi. Android key attestation doğrulaması yapan herhangi bir kodunuz varsa:

| Kök | Konu / Algoritma | Geçerlilik |
|---|---|---|
| **Yeni kök** | `CN=Key Attestation CA 1, OU=Android, O=Google LLC, C=US`, **ECDSA P-384** | 2025-07-17 → 2035-07-15, **1 Şub 2026'dan itibaren geçerli** |
| Mevcut kök | `SERIALNUMBER=f92009e853b6b045`, RSA-2048 | 2022-03-20 → 2042-03-15 |
| **Eski kök** | 2016 kökü | **24 Mayıs 2026'da süresi doldu** |

Ayrıca **Remote Key Provisioning (RKP)** geçişi: Android 16+ standardı, **fabrika toplu (batch) anahtarları 1 Şubat 2026'da sona erdi**. Sonuçları:
- Yeni `provisioning info` uzantısı: **OID `1.3.6.1.4.1.11129.2.1.16`** (CBOR), köke en yakın sertifikada: `remotely_provisioned`, `provisioning_method` (0=Factory, 1=RKP), `provisioning_state`, `time_since_provisioning`, `time_until_expiration`
- RKP sertifikaları **kısa ömürlü** → artık `notAfter` **gerçekten kontrol edilmeli** (eski fabrika anahtarları için kontrol edilmiyordu)
- Cihaz başına iptal mümkün — bir batch key sızıntısının binlerce cihazı etkilemesi sorunu çözüldü

> **Aksiyon:** Kök trust store'unu statik gömmeyin, `https://android.googleapis.com/attestation/root`'tan **dinamik besleyin**; `github.com/android/keyattestation` (resmi Kotlin) kütüphanesinin mantığını port edin.

### E.2 🔴 DÜZELTME: WebAuthn `devicePubKey` standartlaşmadı — L3'ten çıkarıldı

Ana raporda "yaygın platform desteği yok, izlemeye değer" demiştim. **Doğrusu daha kesin:** uzantı **standartlaşmadı ve WebAuthn Level 3'ten çıkarıldı**. Üç bağımsız doğrulama:

1. **W3C WebAuthn Level 3 (Recommendation, 25 Ağu 2026):** "devicePubKey"/"device-bound" ifadesi **yok**
2. **Editor's Draft (3 Eyl 2026):** tanımlı uzantı listesi = `appid`, `appidExclude`, `credProps`, `prf`, `largeBlob`, `remoteClientDataJSON` — **`devicePubKey` yok**
3. **IANA WebAuthn Registries:** 16 kayıtlı uzantı arasında **yok**

⚠️ Kaldırma kararının gerekçesi birincil kaynaktan doğrulanamadı.

**Bunun sizin için anlamı önemli:** "Senkronize passkey mi, cihaza bağlı mı?" sorusunu WebAuthn katmanında **çözemezsiniz**. İhtiyaç ortadan kalkmadı, **katman değiştirdi**:
- Tarayıcı oturumu için → **DBSC**
- OAuth token'ı için → **DPoP + platform attestation**
- Kurumsal WebAuthn için → **enterprise attestation** (politika ile kapılı, genel web'de kullanılamaz)

Bu, Golden Pass-ta-key riskini (§5.4) mimari olarak yönetmenin tek yolunun **yüksek değerli hesaplarda donanım anahtarı** olduğunu pekiştiriyor.

### E.3 🟢 YENİ: Standartlaşma enerjisinin gerçekte olduğu yer

**`draft-ietf-oauth-attestation-based-client-auth-11` — 3 Eylül 2026, AKTİF WG DOKÜMANI** (shepherd: Hannes Tschofenig). DPoP çevresindeki bireysel taslakların neredeyse hepsi expired iken **tek canlı standartlaşma çalışması budur.**

- `OAuth-Client-Attestation` ve `OAuth-Client-Attestation-PoP` başlıkları
- 🔑 **"DPoP combined mode":** *"the Client Instance Key and the DPoP Key are the same asymmetric key pair"* — tek bir DPoP proof'u hem attestation hem sender-constraint görevi görüyor
- Donanım destekli anahtarları taşıyabiliyor, ama kanıt toplama kapsam dışı

**Doğru mimari desen:** donanım attestation **kayıt anında bir kez** anahtarın donanımda yaşadığını kanıtlar; sonra **her istekte DPoP proof'u** o anahtarın kullanıldığını kanıtlar. Bu taslak tam olarak bu iki katmanı birleştiriyor. **Argus'un anahtar kayıt akışını buna göre şekillendirin.**

Diğer aktif: `draft-ietf-oauth-security-topics-update-03` (5 Tem 2026). Bireysel/aktif: `draft-mw-oauth-tls-session-bound-tokens-07` (JPMorgan/Oracle/Telefónica, 20 Haz 2026 — Token Binding'in EKM fikrini **TLS uzantısı olmadan** diriltiyor, (token, bağlantı) başına **tek proof**), `draft-winmagic-oauth-condition-bound-keys-00` (12 Ağu 2026), `draft-chu-oauth-subject-key-binding-00` (1 Eyl 2026).

**Süresi dolmuş/benimsenmemiş:** `dpop-device-flow` (24 Mar 2026), `dpop-rt` (14 Eki 2025), `jwt-dpop-grant` (30 Oca 2026), `app-agnostic-dpop` (19 Mar 2026). **RFC 9449'u güncelleyen resmî bir şey yok — DPoP stabil.**

### E.4 DPoP performansı — ölçülmüş sayılar ve sezgiye aykırı sonuç

Bağımsız ölçüm (Apple M4, Node v24.20.0, tek çekirdek, 5.000 iterasyon):

| Algoritma | **Verify** (sunucu) | Sign (istemci) |
|---|---|---|
| **RS256 (RSA-2048)** | **10,3 µs** ⚡ | 321,1 µs 🐌 |
| PS256 (RSA-2048) | 17,4 µs | 328,3 µs |
| EdDSA (Ed25519) | 35,3 µs | 14,8 µs |
| **ES256 (P-256)** | **49,0 µs** | 28,3 µs |

> **Sezgiye aykırı ama doğru: doğrulamada RSA-2048, ECDSA P-256'dan ~4,7 kat HIZLI.** ECDSA'nın hızlı olduğu taraf *imzalama*dır ve imzalayan istemcidir. Sunucu yalnızca doğrular.

**Ama gerçek DPoP maliyeti imza değil.** Anahtar her proof'un `jwk` header'ında geldiği için — `kid` ile cache edilemez, çünkü anahtar istemci ve oturum başına değişir — doğrulayıcı **her istekte JWK import etmek zorunda**:

```
ES256 JWK-import + verify : 71,5 µs   ← gerçek per-request maliyet
ES256 JWK import ALONE    : 23,5 µs   ← toplamın ~%33'ü
RFC 7638 jkt thumbprint   :  0,95 µs  ← tamamen ihmal edilebilir
```

**Çıkarımlar:**
- Tek çekirdekte **~14.000 DPoP doğrulama/sn**; 8 çekirdek ≈ 110.000/sn. **DPoP'un CPU maliyeti çoğu dağıtım için sorun değil.**
- `cnf.jkt` karşılaştırması **hiçbir zaman darboğaz değil** (~1 µs)
- Rust'ta JWK import maliyetini düşürmek için: JWK'yı parse ettikten sonra `(jkt, VerifyingKey)` çiftini **kısa ömürlü bir cache'te** tutun (aynı oturum ardışık istekler yapıyor). Bu, maliyetin üçte birini siler.
- RS256'ya geçmek doğrulamayı ~%40 düşürür ama istemci imzalamayı 20 kat yavaşlatır (mobil/pil için kötü). **ES256 doğru varsayılan olmaya devam ediyor.**

⚠️ Yayımlanmış bağımsız DPoP benchmark'ı **yok**; bu sayılar tek bir ölçümdür, dil/runtime'a göre değişir.

### E.5 `jti` replay cache — somut boyutlandırma

**Duende (.NET JwtBearer Extensions v1.0.0, 2 Şub 2026)** — bulunan en somut sayısal veri:

- **TTL formülü: proof ömrü + 2 × clock skew.** Varsayılan 5 sn ömür + 5 sn skew → **15 saniye**
- `jti` **hash'lenerek** saklanır → sabit **67 karakterlik** anahtar + bir boolean (cache flooding'e karşı kritik)
- **Kapasite: 1.000 req/sn × 15 sn = ~15.000 kayıt**
- Varsayılanlar: `ProofTokenLifetime = 5 sn`, `EnableReplayDetection = true`, `ProofTokenExpirationMode = Nonce`
- Dağıtık: `HybridCache` + `AddStackExchangeRedisCache`

> **Bu, "DPoP replay cache ölçeklenmez" korkusuna karşı iyi bir gerçeklik kontrolü.** 10.000 rps'te bile ~150.000 kayıt × ~80 byte ≈ **12 MB**. Darboğaz boyut değil, **dağıtık senkronizasyon gecikmesidir** (Curity: *"a cache could easily become a bottleneck"*).

**Nonce stratejisi — dağıtım karşılaştırması (tasarım kararının kalbi):**

| Dağıtım | Nonce | Rotasyon | Sonuç |
|---|---|---|---|
| **Okta** | Zorunlu | **24 saat ömür + 3 gün grace** | Round-trip maliyeti pratikte **sıfır** |
| **ATProto/Bluesky** | Zorunlu (tüm client tipleri) | **Maks. 5 dakika** + bayat nonce toleransı | Yüksek tazelik, yarış koşulları yumuşatılmış |
| Auth0 | Sadece **public** client | Belirtilmemiş | Confidential'da round-trip yok |
| Duende | Opsiyonel | Yapılandırılabilir | Varsayılan `iat` + 5 sn |
| Keycloak | ⚠️ Dokümante edilmemiş | — | — |

**Bluesky/ATProto — DPoP'un en agresif büyük dağıtımı, kopyalanmaya değer kararlar:**
- DPoP **tüm client tipleri için zorunlu**, AS ve RS isteklerinde
- **Sunucu nonce'ları zorunlu**, maks. **5 dakika** ömür
- 🔑 *"Servers **may use the same nonce across all client sessions**"* → nonce üretimi **durumsuz ve ucuz**
- 🔑 *"Servers should accept recently-stale (old) nonces to make rotation smoother for clients with multiple concurrent requests in-flight"* → **sliding window**, uçuşta yarış koşullarına karşı
- İstemci `DPoP-Nonce` başlığı eksikse yanıtı **reddetmeli** (case-insensitive)
- **ES256 zorunlu taban**, PAR zorunlu, PKCE zorunlu
- Token ömürleri: access **maks. 30 dk**; refresh **public 2 hafta / confidential 180 gün**

**Argus için öneri:** Okta modeli + ATProto'nun bayat-nonce toleransı. Yani: uzun ömürlü (saatler), tüm oturumlarda paylaşılan, durumsuz üretilen nonce + kayan pencerede eski nonce kabulü + her 200 yanıtında proaktif `DPoP-Nonce`. Bu kombinasyon **hem round-trip maliyetini sıfırlar hem saat kayması sorununu tamamen ortadan kaldırır.**

**Satıcı gerçeği — dikkat:** Auth0 dokümantasyonu açıkça itiraf ediyor: *"not all Auth0 SDKs enforce `jti` replay protection out of the box."* Okta da replay tespitini **kaynak sunucuya devrediyor**. Yani "DPoP kullanıyoruz" demek replay korumasının var olduğu anlamına gelmiyor — RS tarafını siz yazmalısınız.

### E.6 mTLS — dağıtımın gerçek acıları

**`mtls_endpoint_aliases` neden zorunlu (ana raporda eksikti):** TLS'te client certificate request **handshake seviyesinde ve host bazında** yapılır. Aynı host'ta hem mTLS hem normal istemci varsa sunucu ya herkesten sertifika ister (tarayıcıda sertifika seçim penceresi açılır / bağlantı kırılır) ya da kimseden istemez. Çözüm: mTLS'i **ayrı host/port**'a taşımak ve `mtls_endpoint_aliases` ile ilan etmek.
> **HTTP/2 bunu zorunlu kılıyor:** TLS renegotiation HTTP/2'de **yasak** (RFC 9113). "Önce anonim bağlan, gerekince sertifika iste" modeli çalışmaz — sertifika **baştan** istenmelidir.

**🔴 mTLS dağıtımlarındaki en ciddi güvenlik hatası:** TLS-terminating proxy sertifikayı bir başlıkta iletir (`X-Forwarded-Client-Cert`/XFCC, `X-SSL-Client-Cert`, `ssl-client-cert`). **Bu başlıklar dış dünyadan spoof edilebilir.** Proxy bunları gelen isteklerden **mutlaka sıyırmalı (strip)**. Yapılmazsa mTLS bağlaması **tamamen baypas edilir.** Ayrıca format proxy'ye özgüdür (Envoy XFCC URL-encoded PEM, nginx farklı, HAProxy farklı) → parse mantığınız proxy'ye bağımlı olur.

**`tls_client_auth` "exactly one" kuralı:** İstemci `tls_client_auth_subject_dn`, `_san_dns`, `_san_uri`, `_san_ip`, `_san_email` parametrelerinden **tam olarak birini** kullanmak zorunda. Birden fazla kaydetmek belirsizlik ve **kimlik doğrulama baypası** riski yaratır.

**RS maliyeti karşılaştırması:** mTLS'te RS sadece TLS katmanından sertifikayı alır, SHA-256'sını hesaplar, `cnf.x5t#S256` ile karşılaştırır. **İmza doğrulama yok, replay cache yok, saat kayması yok, nonce yok.** DPoP'un ~71 µs'ine karşı ~sıfır. mTLS'in en büyük operasyonel avantajı budur.

**Sertifika rotasyonu:** RFC 8705 §6.3 — sertifika değişince access token'lar geçersiz olur. Ama refresh token da aynı sertifikaya bağlıysa **o da ölür** → tam yeniden yetkilendirme. DPoP'un anahtar rotasyon sorununun birebir aynısı. Pratikte sertifika ömürleri token ömürlerinden çok uzun tutularak (1-2 yıl) ertelenir.

### E.7 FAPI 2.0 — sender-constraining zorunlu, mekanizma serbest

**FAPI 2.0 Security Profile — Final, 22 Şubat 2025.** Stuttgart Üniversitesi tarafından **formal güvenlik analizi** yapıldı. Authlete ilk sertifikayı aldı (11 Tem 2025).

| Gereksinim | Normatif |
|---|---|
| **Sender-constraining** | AS *"shall use one of the following: MTLS (RFC 8705) [or] DPoP (RFC 9449)"* — **mekanizma serbest, kendisi zorunlu** |
| **PAR** | *"shall support ... RFC 9126"* ve *"**shall reject** authorization requests sent without RFC 9126"* |
| **PKCE** | *"shall require PKCE RFC 7636 with **S256**"* |
| **`iss` parametresi** | RFC 9207 (mix-up saldırısına karşı) |
| **Refresh token** | *"shall support refresh tokens and their **rotation**"* |

> **Tarihsel not:** FAPI 1.0 Advanced **"mTLS veya Token Binding"** diyordu. Token Binding öldüğü için FAPI 2.0 onu **DPoP ile değiştirdi.** Bu tek başına, DPoP'un Token Binding'in bıraktığı boşluğu doldurduğunun en net kurumsal kanıtıdır.

**Boşluk:** Sender-constraining **access token'lar için** zorunlu; **refresh token'lar için açık gereksinim yok** — FAPI 2.0 bunun yerine rotation zorunlu kılıyor. DPoP yolunu seçerseniz RFC 9449 zaten public client refresh binding'i MUST yapar, yani dolaylı olarak elde edersiniz. **mTLS yolunu seçerseniz RFC 8705 sadece SHOULD diyor** — bunu kendiniz MUST'a çevirin.

### E.8 Token Binding'in ölümü — birincil kaynak

**Chrome "Intent to Remove: Token Binding" — Nick Harper, 1 Ağustos 2018, blink-dev.** Tam alıntılar:

> *"After weighing the security benefit of Token Binding against the engineering costs, maintenance costs, web compatibility risk, and adoption, it does not make sense to ship this feature."*

> *"less than **00.01%** of HTTPS requests on Stable had Token Binding attempted."*

> *"for most features that we implement in Chrome, there are lots of third parties coming to us wanting to use the new features, which is something I've seen **very little of** with Token Binding."*

Harper ayrıca **Chrome extensions platformu ve DevTools ile uyumluluk riskini** özellikle sorun olarak andı — sebep: Token Binding TLS katmanındaydı, uzantıların ve DevTools'un gördüğü HTTP soyutlamasıyla uyuşmuyordu.

**Edge (EdgeHTML) shipledi, tek tarayıcıydı** — Chromium'a geçince (2020) destek kayboldu. Firefox ve Safari hiç uygulamadı.

⚠️ **Not:** "Middlebox/TLS-inspection uyumsuzluğu" gerekçesini Chrome'un Intent-to-Remove metninde **açıkça bulamadım** — metin mühendislik maliyeti, uyumluluk riski ve benimsenme üzerine yoğunlaşıyor. Bu, genel kabul gören teknik değerlendirmedir, doğrudan alıntı değildir. Ana raporda bunu daha kesin ifade etmiştim; burada düzeltiyorum.

**RFC durumu:** RFC 8471 hâlâ **Proposed Standard**, Historic'e taşınmadı, obsolete edilmedi. Kağıt üzerinde yaşıyor, uygulamada ölü.

### E.9 Donanım attestation — sunucu doğrulama listeleri

#### Apple App Attest (Secure Enclave)

**Attestation (kayıt, bir kez):**
1. `x5c` → `credCert` (leaf) + ara; **Apple App Attest root** ile doğrula
2. `clientDataHash` = SHA-256(challenge); `authData`'nın sonuna ekle
3. Birleşiğin SHA-256'sı → **`nonce`**
4. 🔑 `credCert`'in **OID `1.2.840.113635.100.8.2`** uzantısındaki OCTET STRING == `nonce` ← *challenge bağlaması burada*
5. `credCert` public key'in X9.62 uncompressed point SHA-256'sı == key identifier
6. App ID SHA-256 == `authData` RP ID hash
7. `authData.counter == 0`
8. `authData.aaguid` == `appattestdevelop` (dev) veya `appattest` + 7×`0x00` (prod)
9. `authData.credentialId` == key identifier
10-11. CBOR `extensions`: `apple_validation_category_01`, `apple_bundle_version_01`
> **macOS'a özel (4↔5 arası):** `aclBlob`'u **OID `1.2.840.113635.100.8.6`**'dan al, sabit bir base64 değerle karşılaştır

**Assertion (sonraki her istek):** `nonce` = SHA-256(`authenticatorData` ‖ SHA-256(`clientData`)); saklanan public key ile `signature` doğrula; RP ID eşleşmesi; 🔑 **`counter` bir öncekinden büyük** (klonlama tespiti); gömülü challenge eşleşmesi; `validationCategory` + `bundleVersion`

**Saklama kuralları:** public key'i kullanıcı + **belirli cihaz** ile ilişkilendir; **receipt**'i sakla (sonradan Apple'dan sunucu-sunucu risk metrikleri istemek için); dev/prod ayrı; kullanıcı başına birden fazla çift; 🔑 **public key başka bir kullanıcıyla ilişkili olmasın** (replay önleme).

> **Sınır:** App Attest **kullanıcıyı değil uygulama örneğini** doğrular. Kimlik doğrulamanın yerine geçmez. Rate limit'i vardır → **bir kez attestation + sonra assertion** modeli.

#### Android Key Attestation — OID `1.3.6.1.4.1.11129.2.1.17`

```asn1
KeyDescription ::= SEQUENCE {
  attestationVersion INTEGER,           -- 1..6
  attestationSecurityLevel SecurityLevel,   -- Software(0)|TrustedEnvironment(1)|StrongBox(2)
  keyMintVersion INTEGER, keymasterVersion INTEGER,
  attestationChallenge OCTET STRING,    -- ← SUNUCU NONCE'U
  uniqueId OCTET STRING,
  softwareEnforced AuthorizationList, teeEnforced AuthorizationList }

RootOfTrust ::= SEQUENCE {
  verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
  verifiedBootState ENUMERATED { Verified(0), SelfSigned(1), Unverified(2), Failed(3) },
  verifiedBootHash OCTET STRING }   -- deprecated
```
AuthorizationList tag'leri: `purpose[1] algorithm[2] keySize[3] digest[4] padding[5] ecCurve[6] rsaPublicExponent[7] ... origin[11] rollbackResistant[12] rootOfTrust[14] osVersion[15] osPatchLevel[16] ... attestationApplicationId[25](CBOR) creationDateTime[26]`; `Origin ::= { Generated(0), Imported(1), Unknown(2) }`

**Doğrulama:** zincir → kök (dinamik) → **CRL** (`/attestation/status`, anahtar = seri numarasının küçük harf hex'i, `REVOKED`/`SUSPENDED`, `Cache-Control`'a saygı) → (v6+) provisioning info → 🔑 uzantıyı **leaf'e en yakın ilk oluşumdan** oku, başkasına güvenme → `attestationChallenge` == nonce → `attestationSecurityLevel ∈ {TEE, StrongBox}` (`Software` reddet) → 🔑 **`teeEnforced`'dan** (asla `softwareEnforced`'dan) `verifiedBootState == Verified` **ve** `deviceLocked == true` → `origin == Generated` (import değil) → `attestationApplicationId` ile paket adı + imza hash'i → RKP ise `notAfter` kontrol et.

> **Android, bu dört mekanizma arasında sunucunun en zengin bilgiyi doğrulayabildiği olanıdır** — anahtarın nerede yaşadığından bootloader'ın kilitli olup olmadığına kadar. **Doğrulamayı asla cihazda yapmayın.**

#### TPM 2.0 — WebAuthn `tpm` (tek gerçek standart)

`tpmStmtFormat = { ver:"2.0", alg, x5c:[aikCert,...], sig, certInfo, pubArea }`

1. `pubArea` (TPMT_PUBLIC) → içindeki public key `credentialPublicKey` ile eşleşmeli
2. `certInfo` (TPMS_ATTEST) parse
3. 🔑 `magic == TPM_GENERATED_VALUE (0xFF544347)` ← *TPM bu magic ile başlayan dışarıdan gelen veriyi imzalamayı reddeder*
4. `type == TPM_ST_ATTEST_CERTIFY`
5. `extraData` == hash(`authenticatorData` ‖ `clientDataHash`) ← *challenge bağlaması*
6. 🔑 `attested.name` == `pubArea`'nın `nameAlg` ile hesaplanan Name'i ← *certInfo'nun gerçekten o anahtarı sertifikaladığını kanıtlar*
7-8. `sig`'i `x5c[0]` ile doğrula; zinciri doğrula

**AIK sertifika gereksinimleri (§8.3.1):** X.509 v3; **Subject BOŞ**; SAN'da `2.23.133.2.1` (Manufacturer), `2.23.133.2.2` (Model), `2.23.133.2.3` (Version); **EKU `2.23.133.8.3`** (`tcg-kp-AIKCertificate`); `basicConstraints CA=false`.

**EK/AIK ayrımı:** EK üretimde gömülür, değiştirilemez, ama gizlilik nedeniyle doğrudan imzalamaz (küresel izlenebilirlik). AIK'lar EK'ya bağlı türetilir. **`TPM2_ActivateCredential`** — bir AIK'nın gerçekten belirli EK'li TPM'de yaşadığını kanıtlar: doğrulayıcı EKpub ile şifrelenmiş sır gönderir, yalnızca o TPM çözebilir. **AIK'yı bir cihaza ilk bağlarken gereklidir.**

#### Microsoft AD CS TPM Key Attestation — üç güven modeli

| OID | Model | CA ne doğrular | Güvence |
|---|---|---|---|
| `1.3.6.1.4.1.311.21.30` | **Endorsement Key** | EKPub, yöneticinin listesinde (dosya adı = EKPub'un SHA-2 hash'i) | **Yüksek** |
| `1.3.6.1.4.1.311.21.31` | **Endorsement Certificate** | EKCert zinciri EKCA/EKROOT depolarına | **Orta** |
| `1.3.6.1.4.1.311.21.32` | **User credentials** | Hiçbir şey — sadece domain kimlik bilgileri | **Düşük** |

Sınırlar: **yalnızca RSA**; **Microsoft Platform Crypto Provider KSP** zorunlu; standalone CA'da çalışmaz; EKCert modeli **o üreticinin TÜM TPM'lerine** güvenmek demek; EKPub modeli en güvenli ama her cihazı manuel listelemek gerekir (ölçeklenmiyor).

> Bu mekanizmanın var olma sebebi, dokümanın kendi ifadesi: *"someone can easily spoof a software KSP as a TPM KSP with local administrator credentials"* — **attestation olmadan "bu anahtar TPM'de" iddiası hiçbir şey ifade etmez.**

**Windows Hello / WebAuthn:** ⚠️ Pratikte tarayıcılar çoğu zaman **`none` attestation** döner (RP `attestation: "none"` varsayılanı). Anlamlı attestation için `"direct"` veya `"enterprise"` istemek gerekir; enterprise attestation tarayıcı/OS politikasıyla kapılı, **yalnızca izinli kurumsal RP ID'ler için**. Ayrıca **passkey senkronizasyonu devreye girince anahtar cihaza bağlı olmayabilir** — devicePubKey probleminin ta kendisi.

---

### E.10 Ana rapordaki maddelerde değişen bir şey var mı?

| Madde | Durum |
|---|---|
| Sınıflandırma tablosu (Faz 1-5) | **Değişmedi** |
| DBSC sunucu implementasyon adımları | **Değişmedi** — header isimleri ve akış doğrulandı |
| SSF/CAEP implementasyon adımları | **Değişmedi** |
| Token Binding ölüm gerekçesi | **Nüanslandı** — middlebox gerekçesi Chrome'un metninde yok, genel değerlendirme |
| `devicePubKey` | **Düzeltildi** — "yaygın destek yok" değil, **standartlaşmadı, L3'ten çıkarıldı** |
| ES256 vs RS256 | **Eklendi** — doğrulamada RS256 daha hızlı; ama ES256 doğru varsayılan |
| Android attestation | **ACİL madde eklendi** — kök rotasyonu + RKP, dinamik trust store şart |
| Standartlaşma yol haritası | **Eklendi** — `draft-ietf-oauth-attestation-based-client-auth` tek aktif WG dokümanı, "DPoP combined mode" |

**Faz 1'e eklenecek tek somut madde:** DPoP nonce tasarımını **Okta modeli (uzun ömür + grace) + ATProto'nun bayat-nonce toleransı + tüm oturumlarda paylaşılan durumsuz nonce** olarak kurgulayın. Bu üçlü, `iat`/saat kayması sorununu tamamen ortadan kaldırır ve nonce round-trip maliyetini pratikte sıfırlar.

**Doğrulanamayanlar (ek):** Keycloak'ın replay cache iç yapısı ve ±15 sn skew değeri; Auth0 GA tarihi ve `iat` penceresi; API gateway'lerin (Kong/Envoy/Apigee) 2026 DPoP desteği; FAPI 2.0 Message Signing'in Final statüsü; `devicePubKey` kaldırma gerekçesi; Microsoft attestation CA köklerinin dağıtım kanalı; Apple App Attest rate limit sayıları; WebAuthn L3'ün 25 Ağu 2026 REC tarihi (tek kaynak).


---

# KISIM VI — ÜRÜN AKIŞLARI

*Kullanıcının ve yöneticinin gördüğü akışlar: hesap yaşam döngüsü, giriş deneyimi, yönetim API'si.*
