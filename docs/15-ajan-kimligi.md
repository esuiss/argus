# 15. AI ajan kimliği

> `ARGUS.md` §15'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§15 §X` referansları aynı anlamda.


**Kapsam:** ~60 birincil kaynak — IETF Datatracker API, spec ham metinleri, IETF 126 (Viyana) slaytları ve tutanakları, MCP `ext-auth` repo dosyaları, AuthZEN taslakları, Entra Agent ID docs.

---

## 0. Yönetici özeti — beş cümlelik gerçek

1. **IETF OAuth WG Haziran 2026'da yeniden charter'landı ve "Complex Delegation" resmen çalışma programına girdi** — ama Eylül 2026 itibarıyla **hiçbir ajan-özel doküman WG tarafından adopte edilmedi.**
2. Buna karşılık **200'den fazla ajan-ilgili I-D** IETF'e akmış; chairs bunu işleyemediklerini açıkça söylüyor.
3. **Bugün gerçekten implemente edilmesi gereken tek ajan-özel şey ID-JAG'dır** — MCP'nin `Enterprise-Managed Authorization` uzantısı **STABLE** ve doğrudan onu profilliyor. **Keycloak'ta ID-JAG *üretme* yeteneği yok** — en net rekabet açığı.
4. Geri kalan her şey (delegation_chain, attenuation, agent registry, agent claims) **yakınsamamış**; en az 6 rakip yaklaşım var.
5. **Hiçbir düzenleme bugün bir IdP'yi ajan kimliğine zorlamıyor** — baskı tedarik/ihale ve OWASP/CSA baseline'ından geliyor.

### Argus için beş kritik karar

| # | Karar | Gerekçe |
|---|---|---|
| 1 | ID-JAG'ı **hem üret hem tüket** | Keycloak sadece tüketiyor (preview); MCP EMA stable |
| 2 | CIMD'yi birinci sınıf yap, DCR'ı legacy tut | MCP 2026-07-28 DCR'ı deprecate etti |
| 3 | Token'da `sub` (insan) + `act` (ajan) **ayrı** olsun | Dual-identity, RFC 8693'te zaten var |
| 4 | Bearer'ı varsayılan yapma: DPoP + mTLS-bound birinci sınıf | WIMSE WIT: `MUST NOT be used as a bearer token` |
| 5 | Delegasyon zinciri için **kendi imzalı yapını** kur, `act`'e güvenme | `act` spec gereği yetki kararı için kullanılamaz |

---

## 1. IETF OAuth WG — süreç ve durum

### 1.0 Charter: ajan işi ARTIK kapsam içinde

`charter-ietf-oauth-06`, **Onaylandı, 2026-06-04**

Charter metninden birebir:
> *"As automated agents increasingly act on behalf of users, organizations, or both, these delegation patterns become increasingly involved and complex."*

Work Program maddesi:
> ***"Complex Delegation:** Developing new mechanisms or/and extensions for authorization of automated agents working on behalf of users, including addressing scenarios where automated agents act across multiple administrative domains."*

Koordinasyon maddesi WIMSE'yi açıkça sayıyor.

**→ Ajan işi OAuth WG'de meşru. Ama charter ≠ adopte edilmiş doküman.**

### 1.0.1 Chairs'in gerçek durumu — IETF 126 (Viyana, 23-24 Temmuz 2026)

Chairs Update slaytlarından (PDF'ten çıkarıldı):
> *"We received a very large number of requests for presentation. We expect this to be the case for a few more meetings. To give your request a better chance at getting WG time: We need to see discussion on the mailing list."*

Aaron Parecki + George Fletcher'ın **"Clustering of OAuth WG Work"** sunumu:
> *"Large numbers of new individual drafts are being submitted to the working group. **More than can reasonably be processed.**"*

Önerilen 9 cluster: Client/Server API · Client Identity, Authentication, and Registration · Token Formats/Types · Token Lifecycle · Security · Discovery · Proof of Possession · Same-Domain Chaining · Cross-Domain Chaining.

Slayt 9: *"Where does the new work land? ... May need to create a new one? **Complex-Delegation??**"*

### 1.0.2 Ölçek: 200+ ajan draft'ı

IETF 126 agentproto BoF'unda sunulan "IETF agent landscape" 160+ → **200+ ajan-ilgili draft** sayıyor. Datatracker API taraması: **60+ aktif ajan-kimlik/delegasyon draft'ı**.

---

## 2. Aktif OAuth WG dokümanları (Eylül 2026)

| Draft | Rev | Tarih | WG Durumu |
|---|---|---|---|
| `draft-ietf-oauth-v2-1` | **16** | 2026-09-03 | **Milestone: Ara 2026'da IESG'ye** |
| `draft-ietf-oauth-attestation-based-client-auth` | **11** | 2026-09-03 | WG Doc (New) |
| `draft-ietf-oauth-transaction-tokens` | **11** | 2026-07-30 | **WG Consensus: Waiting for Write-Up** |
| `draft-ietf-oauth-first-party-apps` | **04** | 2026-07-01 | **WG Consensus: Waiting for Write-Up** |
| `draft-ietf-oauth-client-id-metadata-document` | **02** | 2026-07-06 | WG Doc |
| `draft-ietf-oauth-identity-assertion-authz-grant` | **04** | 2026-05-21 | WG Doc |
| `draft-ietf-oauth-spiffe-client-auth` | **02** | 2026-06-15 | WG Doc |
| `draft-ietf-oauth-security-topics-update` | 03 | 2026-07-05 | WG Doc |
| `draft-ietf-oauth-refresh-token-expiration` | 03 | 2026-07-06 | WG Doc |
| `draft-ietf-oauth-rar-metadata-remediation` | **00** | 2026-08-23 | WG Doc (yeni adopte) |

**RFC kuyruğunda:** `identity-chaining-17`, `rfc7523bis-11`, `sd-jwt-vc-19` (Last Call 15 Eyl 2026'da bitiyor), `status-list-21`.
**Yeni RFC'ler:** RFC 10017 (Browser-Based Apps BCP, Ağu 2026), RFC 10027 (Cross-Device Flows BCP, Ağu 2026).

---

### 2.1 ⭐ ID-JAG — `draft-ietf-oauth-identity-assertion-authz-grant-04`

**Identity Assertion JWT Authorization Grant** · Rev 04 · 21 Mayıs 2026 · Süre bitişi 22 Kasım 2026
**Yazarlar:** A. Parecki (Okta), K. McGuinness, B. Campbell (Ping)

**Ne çözüyor:** Kurumsal IdP'nin, A uygulamasının B uygulamasının API'sine kullanıcı adına erişmesini merkezî politikayla yönetmesi. `draft-ietf-oauth-identity-chaining`'in bir profili.

**Token yapısı (birincil metinden doğrulandı):**
```
Header: { "typ": "oauth-id-jag+jwt" }        ← ZORUNLU, tip karışıklığına karşı
Payload:
  iss        IdP AS'in issuer identifier'ı            ZORUNLU
  sub        Kullanıcının IdP namespace'indeki id'si  ZORUNLU
  aud        Resource AS'in issuer identifier'ı        ZORUNLU
  client_id  Resource AS'teki client identifier'ı      ZORUNLU
  jti        Benzersiz id (replay)                     ZORUNLU
  exp, iat                                             ZORUNLU
  resource   RFC 8707 Resource Identifier              OPSİYONEL (MCP profilinde MUST)
  scope                                                OPSİYONEL
  email / aud_sub  JIT provisioning için               ÖNERİLEN
```

**Akış:**
1. `POST /token` @ IdP: `grant_type=...token-exchange`, `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, `audience=<Resource AS issuer>`, `subject_token=<ID Token|SAML|Refresh Token>`
2. Yanıt: `{"issued_token_type":"...id-jag","access_token":"<JWT>","token_type":"N_A","expires_in":300}` — `token_type: N_A` çünkü bu bir bearer token değil, bir **grant**
3. `POST /token` @ Resource AS: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<ID-JAG>`
4. Resource AS audience-kısıtlı access token verir

**Discovery metadata:**
- IdP AS: `identity_chaining_requested_token_types_supported` içinde `urn:ietf:params:oauth:token-type:id-jag`
- Resource AS: `authorization_grant_profiles_supported` içinde `urn:ietf:params:oauth:grant-profile:id-jag`

**Önemli sınırlama:** Spec, Token Exchange isteğinde opsiyonel `actor_token` parametresine izin veriyor ama **"this specification does not define normative processing requirements"** diyor. Güvenlik bölümü, geçerli bir `subject_token`'ı alakasız bir `actor_token` ile eşleyerek abartılı yetki elde etme riskini uyarıyor.

> **ID-JAG bugün ajan delegasyonunu ÇÖZMÜYOR; kullanıcı SSO'sunun cross-app taşınmasını çözüyor. Ajan bağlantısı MCP EMA profili üzerinden geliyor.**

**IdP'de implemente edilmesi gerekenler:**
- Token endpoint'te `requested_token_type=...id-jag` desteği + ID-JAG minting (`typ` header dahil)
- Cross-app connection policy: `(requesting_client_id, resource_as_issuer, resource_identifier, allowed_scopes, subject_policy)` — admin-yönetimli
- Per-connection `sub` mapper
- Resource AS rolü: `jwt-bearer` grant ile ID-JAG kabulü + 5 adımlı doğrulama
- **Client continuity kontrolü:** ID-JAG içindeki `client_id`, token endpoint'te kimlik doğrulanan client ile eşleşmeli (**bunu atlayan implementasyonlar var**)
- `jti` replay cache (TTL = exp)

**Sınıflandırma: 🟢 BUGÜN İMPLEMENTE EDİLMELİ.**

**Ekosistem kanıtı:** IdP tarafı Okta, Ping, Descope, Keycloak (in progress); istemciler Claude, VS Code, WorkOS; resource app'ler Slack, Notion, Figma, Linear, Asana, Datadog, Atlassian.

**Keycloak açığı:** Keycloak 26.5 ID-JAG'ı **tüketebiliyor** (preview) ama **üretemiyor**; issuance önerisi keycloak#43971, hedef 26.7.0. *(İkincil kaynak — GitHub'da doğrulanmadı.)*

---

### 2.2 ⭐ MCP Enterprise-Managed Authorization — ID-JAG'ın gerçek ajan uygulaması

**Statü: STABLE** (MCP `ext-auth` repo'sunda)

Spec'in kendi ifadesi:
> *"This document defines an application of the 'Identity Assertion JWT Authorization Grant' for use within enterprise deployments of the Model Context Protocol (MCP)."*

Rol eşlemesi:
- **Client** = MCP Client
- **Resource Server** = MCP Server
- **Resource Authorization Server** = MCP Server'ın PRM'de (RFC 9728) ilan ettiği AS
- **IdP Authorization Server** = kurumsal SSO IdP'si → **bu biziz**

Profil kısıtları:
- `audience` **MUST** = Resource AS'in issuer identifier'ı
- `resource` verilirse **MUST** = MCP Server'ın RFC 9728 Resource Identifier'ı
- IdP, token exchange'te client auth'u SSO'daki kadar sıkı uygulamalı
- Pre-registered değilse client, **CIMD**'sini client_id olarak kullanabilir

Örnek payload (spec'ten birebir):
```json
{ "jti":"9e43f81b64a33f20116179", "iss":"https://acme.idp.example",
  "sub":"U019488227", "email":"user@example.com",
  "aud":"https://auth.chat.example/", "resource":"https://mcp.chat.example/",
  "client_id":"f53f191f9311af35", "exp":1311281970, "iat":1311280970,
  "scope":"chat.read chat.history" }
```

> **Bu, "IdP'nin bugün ne implemente etmesi gerektiği" sorusunun en net cevabı: MCP dünyasının kurumsal auth'u = ID-JAG. Stable statüde. Şimdi.**

---

### 2.3 Identity Chaining — `draft-ietf-oauth-identity-chaining-17`

**Durum: IESG'ye gönderildi, RFC Editor kuyruğunda** · Proposed Standard · 19 Temmuz 2026

RFC 8693 + RFC 7523'ü birleştirerek trust domain'ler arası kimlik/yetki taşıyor. ID-JAG'ın üst kümesi. Yeni metadata: `identity_chaining_requested_token_types_supported`.

**🟢 BUGÜN İMPLEMENTE EDİLMELİ** — RFC olmak üzere, ID-JAG'ın temeli.

---

### 2.4 CIMD — `draft-ietf-oauth-client-id-metadata-document-02`

Detaylar için bkz. mcp-yetkilendirme.md §5 (§14).

**Not:** CIMD-02 metninde **AI agent veya MCP'den hiç bahis yok** — genel amaçlı bir spec. Ajan ekosisteminin ona bağımlılığı MCP tarafından geliyor.

**🟢 BUGÜN İMPLEMENTE EDİLMELİ.**

---

### 2.5 FiPA — `draft-ietf-oauth-first-party-apps-04`

**Durum: WG Consensus: Waiting for Write-Up** — WGLC geçmiş. **En olgun ajan-alakalı WG dokümanı.**
**Yazarlar:** Parecki (Okta), Fletcher (Practical Identity), Kasselman (Defakto)

**Ne getiriyor:** **Authorization Challenge Endpoint** — native uygulamanın tarayıcıya gitmeden kullanıcı auth'unu kendi UI'ında yürütmesi.
- HTTP POST, form-encoded; authorization code veya hata döner
- **`auth_session`**: aynı client instance'ından gelen ardışık istekleri bağlayan opak değer; **device-bound olmalı**, DPoP ile bağlanabilir
- Hata kodları: `invalid_session`, `insufficient_authorization`, `redirect_to_web` (HTTP 403)

**Ajan alakası:** Doğrudan ajan spec'i değil — ama **tarayıcısız/headless client** için resmî OAuth deseni. SPA'larda kullanımı **NOT RECOMMENDED** (XSS).

**🟡 ARAYÜZÜ HAZIRLANMALI.**

---

### 2.6 Token Exchange (RFC 8693) + `act` — DELEGASYONUN ZAYIF HALKASI

**Yapısal zaaf (spec'in kendi ifadesi, §4.1):** Tüketiciler yalnızca top-level claim'lere ve `act` ile tanımlanan **mevcut** aktöre bakmalı; önceki aktörler **sadece bilgilendirici**, erişim kontrolü kararlarında dikkate alınmamalı.

> **`act` bir audit izidir, yetki kanıtı DEĞİLDİR. Bu tasarım gereğidir.**

#### Delegation Chain Splicing saldırısı

IETF OAuth mailing list, thread doğrulandı: *"Security Consideration: Delegation Chain Splicing in RFC 8693 Token Exchange"*, başlatan `cbchhaya`, **27 Şubat 2026**; tartışma Mart 2026 boyunca.

Mekanizma: Ele geçirilmiş bir aracı, **farklı delegasyon bağlamlarından** `subject_token` ve `actor_token` sunar. STS her ikisini **bağımsız** doğrular, geçerli bulur ve **hiç gerçekleşmemiş bir zinciri iddia eden, usulüne uygun imzalanmış** token üretir.

**Kök neden: RFC 8693 iki token arasında çapraz doğrulama zorunlu kılmıyor.**

Önerilen mitigasyon (mailing list, **spec değil**): `aud[N] == sub[N+1]` kriptografik eşleşmesi + kısa TTL + back-channel revocation.

⚠️ Birincil mesaj gövdesine erişilemedi (mail-archive.com bloke). Mekanizma açıklaması ikincil kaynaktan (WorkOS, 27 Nisan 2026). **DOĞRULAMA: KISMÎ.**

#### Çözüm draft'ları — hepsi bireysel, hiçbiri adopte değil

| Draft | Rev/Tarih | Yaklaşım |
|---|---|---|
| `draft-liu-oauth-chain-delegation` | 00 / 8 Haz 2026 | `delegation_chain` claim'i; **çift imza** (`as_signature` + `delegator_signature`), detached JWS + JCS (RFC 8785); `record[i].delegator_id == record[i-1].delegatee_id`; max 5 hop. Yazarlar: Dapeng Liu, Judy Zhu, Suresh Krishnan, **Aaron Parecki** |
| `draft-mcguinness-oauth-actor-profile` | 00 / 30 Nis 2026 | `act` için **tutarlı profil**: `sub`=yetkilendiren, en dıştaki `act.sub`=doğrudan aktör, kanonik aktör kimliği = `(act.iss, act.sub)`. **Minimum depth 4**. İki presenter-geçiş modu: **continuation** ve **rebind** |
| `draft-asor-wimse-agent-delegation-chain` | 01 / 3 Eyl 2026 | Ed25519/ES256/**ML-DSA**; `del_depth`, `del_max_depth`, `par_hash` (ebeveynin SHA-256'sı), `cnf`. **8 adımlı offline doğrulama**, AS'e temas yok |
| `draft-niyikiza-oauth-attenuating-agent-tokens` | 01 / 15 Haz 2026 | Macaroon/biscuit ilhamlı ama **asimetrik**. 6 değişmez (I1-I6), 8 kısıt tipi, **closed-world mode** |
| `draft-hamr-oauth-agent-delegation` | 01 / 2 Eyl 2026 | **`Agent-Delegation` HTTP header'ı**. Scope containment, floor non-relaxation, expiry non-extension. **RFC 9421 HTTP Message Signatures zorunlu** |
| `draft-li-oauth-delegated-authorization` | 03 / 24 Tem 2026 | `cnf.jkt` key binding; client **kendi private key'iyle** çocuk token imzalar (AS'e gitmeden); DPoP zorunlu (Huawei) |
| `draft-mcguinness-oauth-mission` | 00 / 6 Tem 2026 | **Mission**: onaylanmış göreve bağlı dayanıklı yetkilendirme artefaktı. `intent_hash` + `authority_hash` |

**Yorum:** Bu, sağlıklı bir standartlaşma değil — **aynı problemin 7 rakip çözümü**. En güçlü adaylar: `draft-mcguinness-oauth-actor-profile` ve `draft-liu-oauth-chain-delegation` (yazar ağırlığı + `act` uyumu).

**🟡 ARAYÜZÜ HAZIRLANMALI + kendi güvenli üst kümeni kur.**

Somut öneri: `act`'i RFC 8693 uyumlu üret (interop), **ek olarak** `delegation_chain`'i `draft-liu`'nun şeklinde imzalı üret. `draft-mcguinness-oauth-actor-profile`'ın üç değişmezini bugünden benimse.

---

### 2.7 Transaction Tokens — `draft-ietf-oauth-transaction-tokens-11`

**Durum: WG Consensus, Waiting for Write-Up** (3. WGLC planlı)

- Header `typ: txntoken+jwt`
- Claim'ler: `txn`, `sub`, `aud` (**Trust Domain identifier** — cross-domain kullanımı engeller), `scope`, **`tctx`** (immutable transaction context), **`rctx`** (request context), **`req_wl`** (requesting workload id)
- **Transaction Token Service (TTS)**, RFC 8693 ile: `requested_token_type=urn:ietf:params:oauth:token-type:txn_token`
- HTTP taşıma: **`Txn-Token` özel header'ı**

**Ajan alakası:** Bir ajan görevinin mikroservis zinciri boyunca **daralmış, göreve bağlı** yetkiyi taşıması.

**🟡 ARAYÜZÜ HAZIRLANMALI.**

---

### 2.8 Attestation-Based Client Auth — rev 11, 3 Eylül 2026

- **Client Attestation JWT**: Client Attester'dan gelen, instance'ın anahtarına bağlı imzalı beyan
- **Client Attestation PoP JWT**: Instance'ın o anahtarla ürettiği sahiplik kanıtı
- Header'lar: `OAuth-Client-Attestation`, `OAuth-Client-Attestation-PoP`, `OAuth-Client-Attestation-Challenge`
- Claim'ler: `cnf`, `sub`, `aud`, opsiyonel `challenge`

🔑 **"DPoP combined mode":** *"the Client Instance Key and the DPoP Key are the same asymmetric key pair"* — tek DPoP proof'u hem attestation hem sender-constraint görevi görüyor.

> **Doğru mimari desen: donanım attestation kayıt anında bir kez anahtarın donanımda yaşadığını kanıtlar; sonra her istekte DPoP proof'u o anahtarın kullanıldığını kanıtlar.**

DPoP çevresindeki bireysel taslakların neredeyse hepsi expired iken **tek canlı standartlaşma çalışması budur.**

**🟡 ARAYÜZÜ HAZIRLANMALI.**

---

### 2.9 ⭐ SPIFFE Client Auth — `draft-ietf-oauth-spiffe-client-auth-02`

**Yazarlar:** Arndt Schwenkschuster, Pieter Kasselman, **Scott Rose (NIST)**, **Stian Thorgersen (IBM — Keycloak kurucusu)**, Nancy Cam-Winget (Cisco)

**Üç SVID auth yöntemi:**
1. **JWT-SVID**: `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`
2. **X.509-SVID**: mTLS, SPIFFE ID sertifikanın **SAN URI**'sinde
3. **WIT-SVID**: WIMSE Workload Identity Token + Client Attestation PoP JWT

**Anahtar dağıtımı: SPIFFE Bundle Endpoint zorunlu** (JWKS over HTTPS, WebPKI).

**Implementation Status: Keycloak** listeleniyor.

**🟢 BUGÜN İMPLEMENTE EDİLMELİ.** Stian Thorgersen'ın yazar olması, Keycloak'ın bunu ciddiye aldığının kanıtı.

---

### 2.10 Diğer WG dokümanları

**`draft-ietf-oauth-refresh-token-expiration-03`** (Nick Watson/Google): `refresh_token_timeout` ve `authorization_expires_in`. *"The refresh token MUST NOT expire later than the user authorization expires."* **Uzun süren ajan görevleri için doğrudan alakalı.** 🟡

**`draft-ietf-oauth-rar-metadata-remediation-00`** (Yaron Zehavi/RBI): `authorization_details_types_metadata_endpoint` + `insufficient_authorization` hata kodu + `authorization_remediation`. **Ajanın "hangi authorization_details'i istemeliyim"i keşfetmesi için.** 🟡

**`draft-ietf-oauth-v2-1-16`:** Milestone Aralık 2026'da IESG'ye. ⚠️ **MCP spec'i hâlâ `draft-13`'e referans veriyor — 3 revizyon geride.**

---

## 3. Ajan-özel bireysel draft'lar — zoo haritası

Hiçbiri WG dokümanı değil. **Ajan kimliği/yetkilendirmesiyle doğrudan ilgili en az 30 aktif draft var.**

### 3.1 ⭐⭐ `draft-klrc-aiagent-auth-03` — AIMS

**6 Temmuz 2026** · Bireysel I-D
**Yazarlar:** Pieter Kasselman (Defakto), **Jeff Lombardo (AWS)**, Yaroslav Rosomakho (Zscaler), **Brian Campbell (Ping)**, **Nick Steele (OpenAI)**, **Aaron Parecki (Okta)**

Bu, **endüstri konsensüsünün nereye gittiğinin en güçlü göstergesi.** Yeni protokol icat etmiyor; WIMSE + OAuth + SPIFFE'i kompoze ediyor.

**AIMS (Agent Identity Management System)** = *"bir ajan workload'unun kimliğini ve izinlerini tesis etmek, sürdürmek ve değerlendirmek için gereken fonksiyonlar kümesini tanımlayan kavramsal model."* Yedi bileşen: agent identifiers, credentials, provisioning, authentication, authorization, observability/remediation, compliance measurement.

**Ham metinden birebir alıntılar:**

> *"The Large Language Model **MUST NOT** have access to an agent's credentials or to credentials that may be needed to access tools and services. This prevents the Large Language Model from using, exposing, or being manipulated via prompt injection into disclosing the credentials."* (§8, satır 540)

> *"An identifier alone is insufficient unless it can be verified to be controlled by the communicating agent through a cryptographic binding."*

**Human-in-the-Loop bölümü (§10.7) — bizim için en değerli kısım:**

> *"An Agent, acting as an OAuth client, can use the OpenID Client Initiated Backchannel Authentication (CIBA) protocol. This triggers an out-of-band interaction allowing the user to approve or deny the requested operation without exposing credentials to the agent."*

> *"Such interactions do not by themselves constitute authorization and **MUST** be bound to a verifiable authorization grant issued by the authorization server... the agent **MUST NOT** treat local UI confirmation alone as sufficient authorization."*

> ***"Note:*** Additional specification or design work may be needed... **CIBA itself only accounts for client initiation, which doesn't map well to cases that envision the need for User confirmation to occur mid-execution.**"

> **Bu, "ajan görevinin ortasında insan onayı" probleminin resmî kabulü. CIBA yetmiyor. Bu AÇIK bir problem.**

**Agent Mission (§10.1):** Ajan bir Mission alır, genelde doğal dilde. Mission'ın yetkilendirme gereksinimlerine çevrilmesi **spec kapsamı dışı**.

**Yetkilendirme senaryoları (§10.4):** (1) User Delegates Authorization — phishing-dirençli auth ile authorization code grant; (2) Agent Obtains Own Authorization — client credentials / JWT grant; (3) Agents Accessed by Systems or Other Agents.

⚠️ **Önemli düzeltme:** "Çift kimlik credential'ı" ve "üç delegasyon akışı" bu belgede **DEĞİL** (grep ile doğrulandı). Bunlar ayrı bir belgeye ait — aşağıda.

### 3.2 `draft-ni-wimse-ai-agent-identity-02` — Dual-Identity

**28 Şubat 2026** · Huawei · ⚠️ Süre bitişi **1 Eylül 2026 → ŞU AN SÜRESİ DOLMUŞ**

**Dual-Identity Credential:** Ajanın kimliğini sahibinin kimliğine kriptografik olarak bağlayan credential.

**Üç bağlama modeli:**

| Model | Mekanizma | Saldırı yüzeyi |
|---|---|---|
| **Agent-Mediated** (Owner-Pre-Signed) | Sahip, ajanın credential isteğini **gönderilmeden önce yerel olarak** imzalar. Offline onay, FIDO/HSM | Ele geçirilmiş imzalama anahtarları |
| **Owner-Mediated** (Gateway Mode) | Sahip, proxy ile sunucu arasında denetleyici aracı | **Tek hata noktası**, DoS |
| **Server-Mediated** (Challenge-Response) | Identity server, sahibi **out-of-band kanalla doğrudan arayarak** bağlamayı orkestre eder | Out-of-band kanal güvenliği, replay |

> **Argus için doğrudan eşleme:** Agent-Mediated = "owner assertion" (sahip anahtarıyla imzalı JWT / WebAuthn). Owner-Mediated = admin konsolu + policy engine. **Server-Mediated = tam olarak CIBA'dır.** Bu üçünü ayrı akışlar olarak destekle ve böyle konumlandır.

Akademik eleştiri: *"WIMSE Dual-Identity Credential'ı tanıtıyor, iki-taraflı etkileşimleri çözüyor ama **multi-hop delegasyonu çözmüyor**."*

### 3.3 McGuinness serisi — en tutarlı tasarım kümesi

Karl McGuinness (bağımsız, eski Okta CTO'su) tek başına bir spec ailesi yazıyor:

| Draft | Rev/Tarih | İçerik |
|---|---|---|
| `draft-mora-oauth-entity-profiles` | 01 / 15 Nis 2026 | **`client_profile` ve `sub_profile` claim'leri.** 7 kayıtlı değer: `user`, `device`, `native_app`, `web_app`, `browser_app`, `service`, **`ai_agent`**. AS metadata: `entity_profiles_supported`. Yazarlar: Mora, **Pamela Dingle (Microsoft)**, McGuinness |
| `draft-mcguinness-oauth-actor-profile` | 00 / 30 Nis 2026 | §2.6'da |
| `draft-mcguinness-oauth-client-instance-assertion` | 01 / 23 Haz 2026 | **Client Instance Assertion**: bir OAuth client'ın somut runtime instance'ını tanımlayan imzalı JWT |
| `draft-mcguinness-oauth-ai-agent-instance` | 00 / 4 Tem 2026 | **AI Agent Instance Profile.** Problem: *"every agent session collapses into one identity, defeating per-agent authorization, audit attribution, incident response, and abuse containment."* Claim'ler: **`agent_instance_id`** (zorunlu), `agent_platform`, `agent_model`, `agent_runtime` (EAT). **`sub_profile` her zaman `["ai_agent","client_instance"]`** |
| `draft-mcguinness-oauth-mission` | 00 / 6 Tem 2026 | Mission claim'i, `intent_hash` |
| `draft-mcguinness-oauth-id-continuation-assertion` | 01 / 26 Ağu 2026 | **Identity Continuation Assertion**: kullanıcı gittikten sonra kimlik yayılımı. Kısa ömürlü (**max 300s**), **sender-constrained (DPoP)**, **tek kullanımlık + replay tespiti** |
| `draft-mcguinness-oauth-token-exchange-cnf` | 00 / 19 Tem 2026 | Token Exchange için `cnf` yanıt parametresi |
| `draft-mcguinness-oauth-rfc9728bis` | 01 / 28 Ağu 2026 | PRM resource identifier doğrulaması |

> **Bu set, ajan kimliğinin "doğru" tasarımı hakkında en tutarlı görüşü sunuyor: sub=insan, act=ajan, agent_instance_id=çalışan kopya, mission=görev sınırı, sub_profile=varlık tipi.**

**🟡 `sub_profile: "ai_agent"` ve `agent_instance_id`'yi bugünden token'a koy — maliyeti sıfıra yakın.**

### 3.4 Diğer notable draft'lar

| Draft | Rev/Tarih | Özet |
|---|---|---|
| `draft-chen-oauth-agent-authz-use-cases` | 03 / 25 Ağu 2026 | **Gap analysis, adoption istendi ama chairs erken buldu.** 11 use case. Üç boşluk: **Authorization Context Gap** (kullanıcının talimatı ile ajanın izin isteği arasındaki zamansal kopukluk), **Delegation Chain Gap**, **Mass Revocation Gap** |
| `draft-carleton-workload-authz-grant` | 00 / 3 Ağu 2026 | **Paul Carleton (Anthropic).** AIMS profili: müşteri başına birden çok ajan instance'ı barındıran platformlar için. *"Trust in the platform's issuer is established once, by reference, and thereafter agents are accepted on first presentation with **no per-agent registration step**."* |
| `draft-liu-ai-agent-authorization-integration` | 00 / 6 Tem 2026 | **Alibaba + Cisco + Okta (Parecki).** Altı uzantıyı entegre ediyor: SPIFFE client auth + ID-JAG + JWT Grant Interaction Response + Rego policy via RAR + Authorization Evidence + Delegation Chain |
| `draft-parecki-oauth-jwt-grant-interaction-response` | 00 / 25 Mar 2026 | **HITL için en temiz mekanizma.** `{"error":"interaction_required","interaction_uri":"https://...","interval":5,"expires_in":600}`. İki tamamlama: polling veya **sinyal redirect'i** (*"No authorization code or other parameters are included"*) |
| `draft-rosomakho-oauth-txn-challenge` | 00 / 25 Haz 2026 | **OAuth Transaction Authorization Challenge.** Korunan kaynak imzalı JWT challenge üretir → client AS'e taşır → AS onay alıp o işleme bağlı scoped token verir. *"useful when requests are mediated by agents, automated workflows, or delegated services"* |
| `draft-gerber-oauth-deferred-token-response` | 00 / 23 Haz 2026 | **Deferred Token Response.** `completion_mode=deferred` → `400 authorization_pending` + `deferral_code` + `expires_in` (saatler/günler). **Deferral code sender-constrained olmalı** |
| `draft-zhu-oauth-async-delegation` | 05 / 3 Ağu 2026 | **Delegated Refresh Tokens** (Atlassian). Mutlak delegation deadline, **task-scoped revocation** |
| `draft-jia-oauth-scope-aggregation` | 01 / 14 Ağu 2026 | Multi-step ajan iş akışlarında scope'ları önden toplama. Riskler: **residual privilege** ve **user blind signing** |
| `draft-gazitt-oauth-authzen-token-exchange` | 01 / 2 Eyl 2026 | AuthZEN'i RFC 8693'e bağlıyor. **İki ayrı değerlendirme:** Subject Gate + **Requesting Party Gate** |
| `draft-abbey-scim-agent-extension` | 00 / 16 Eki 2025 | **SCIM Agents Extension.** Macy Abbey, Rafael S. Cohen (Okta). `/Agents` ve `/AgenticApplications`. Attribute'lar: `agentType`, **`owners`**, `roles`, **`protocols`** (OpenAPI/A2A/MCP-Server), `x509Certificates`, **`subject`** (OIDC `sub` korelasyonu) |
| `draft-sharif-openid-agent-identity` | 01 / 27 Ağu 2026 | 10 ajan claim'i: `agent_trust_score` (0-100), `agent_trust_level` (L0-L4), `agent_spend_limit`... **Tek yazarlı, spekülatif** |
| `draft-drake-agent-identity-registry` | 03 / 22 May 2026 | Federated registry; **donanım-çapalı** (TPM 2.0/PIV/enclave, 5 trust tier). Kimlik **kalıcı ve iptal edilemez**. Tek yazarlı, **spekülatif** |
| `draft-mishra-oauth-agent-grants` (DAAP) | 02 / 30 Ağu 2026 | PAR zorunlu, PKCE S256, kimliği doğrulanmış insan consent'i (**policy engine ile ikame edilemez**), DPoP/mTLS |

---

## 4. IETF WIMSE WG

| Draft | Rev | Tarih | Durum |
|---|---|---|---|
| `draft-ietf-wimse-arch` | **08** | 2026-07-06 | WG Doc, 33 sayfa |
| `draft-ietf-wimse-http-signature` | **06** | 2026-08-04 | WG Doc |
| `draft-ietf-wimse-identifier` | **03** | 2026-07-06 | WG Doc |
| `draft-ietf-wimse-mutual-tls` | **02** | 2026-07-06 | WG Doc |
| `draft-ietf-wimse-workload-creds` | **02** | 2026-07-02 | WG Doc, 27 sayfa |
| `draft-ietf-wimse-wpt` | **02** | 2026-08-27 | WG Doc (New) |
| `draft-ietf-wimse-workload-identity-practices` | **06** | 2026-08-11 | **AD Evaluation** → Informational RFC |

**→ WIMSE'den henüz HİÇ RFC çıkmadı.**

### 4.1 WIT — Workload Identity Token

Ham metinden birebir:
> *"The workload MUST prove possession of the corresponding private key when presenting the WIT to another party. **As such, it MUST NOT be used as a bearer token** and is not intended for use in the Authorization header."*

- JOSE header: `alg` asimetrik (asla `none`), **`typ: wit+jwt`**
- Claim'ler: `sub` (WIMSE Workload Identifier URI), `exp`, **`cnf`** (public key, `jwk`; `jwk` içinde `alg` **MUST**), `iss`, `jti`
- Ayrı HTTP header'lar (Authorization değil)

**Bearer geçiş stratejisi (§5.3):** WIT yeni header'lar tanımladığı için bearer JWT header'larıyla **birlikte** sunulabilir. Uyarı: *"the decision which token to prefer is made when the caller's identity has still not been authenticated, and needs to be revalidated following the authentication step."*

### 4.2 WPT — Workload Proof Token

**27 Ağustos 2026** · Brian Campbell (Ping), Arndt Schwenkschuster (Defakto)

- `typ: application/wpt+jwt`, `alg` WIT'in `cnf` anahtarıyla eşleşmeli
- Claim'ler: `aud` (HTTP hedef URI), `exp`, `jti`, **`wth`** (WIT'in base64url SHA-256'sı), **`tth`** (Transaction Token hash'i), **`oth`**
- Taşıma: yeni **`WPT` authentication scheme**'i. Hata: `401` + `WWW-Authenticate: WPT`

### 4.3 Workload Identifier

- URI tabanlı: `spiffe://trust-domain/service` ve yeni kaydedilen **`wimse://<trust-domain>/<path>`**
- **Yasaklar:** query string, fragment, userinfo, port yok
- 2048 bayta kadar; **tam URI karşılaştırması**
- *"Identifiers require cryptographic credential context to be considered authenticated"*

### 4.4 WIMSE Architecture — AI ajanları açıkça ele alınıyor

**§3.4.11'de AI aracıları "delegated workload'ların özel bir hali" olarak konumlandırıyor:**
- Açıkça yetkilendirilmedikçe upstream güvenlik bağlamını **yaymalı**
- Otonom eylemleri delegasyonlu olanlardan **ayrı kimliklerle** ayırmalı
- **"cryptographic binding of delegation tokens or attestation"**
- Multi-agent zincirlerinde **her hop'ta güvenlik bağlamını yeniden bağlamalı**

**Sınıflandırma:**
- WIT/WPT: 🟡 **ARAYÜZÜ HAZIRLANMALI** (RFC yok ama yön net: bearer ölüyor)
- Workload Identifier şeması: 🟢 **BUGÜN BENİMSE** — ajanlara `spiffe://` veya `wimse://` tarzı hiyerarşik URI kimlikler ver, opak UUID değil. Policy yazımı (`spiffe://acme.example/agent/finance/*`) muazzam kolaylaşır
- SPIFFE client auth: 🟢 **BUGÜN**

### 4.5 WIMSE'deki ajan delegasyon draft'ları

| Draft | Rev/Tarih | İçerik |
|---|---|---|
| `draft-reece-wimse-cross-org-delegation` | 02 / 31 Ağu 2026 | **Problem statement + requirements.** 7 problem: recursive delegation, org sınırları, **offline doğrulama**, principal binding, revocation/freshness, composable audit, **execution-time human authorization**. 10 gereksinim |
| `draft-asor-wimse-agent-delegation-chain` | 01 / 3 Eyl 2026 | §2.6'da |
| `draft-sweeney-wimse-credential-delegation` | 00 / 3 Eyl 2026 | **İçeriği incelenmedi — DOĞRULANMADI** |
| `draft-rampalli-cross-org-delegation-mapping` | 05 / 6 Tem 2026 | Layered requirements mapping |

IETF 126 WIMSE oturumu: **AIMS**, "Heterogeneous Credential Verification", "PEDIGREE: per-hop delegation", "Offline workload access for user-owned resources without refresh tokens", "SOOS: Mandate JWT & Cross-Principal Transaction ID (XPID)".

---

## 5. agentproto BoF — yeni bir WG doğuyor (ama henüz yok)

**IETF 126, Viyana, 23 Temmuz 2026 — WG-forming BoF**

**Oda anketi sonuçları:**

| Soru | Evet | Hayır |
|---|---|---|
| IETF doğru mekân mı | 158 | — |
| Net interop ihtiyacı var mı | 155 | — |
| WG kurulsun mu | **154** | **51** |
| Mevcut kapsam doğru mu | **38** | **124** ⚠️ |

**Kimlik/yetkilendirme tartışması** çekişmeli geçmiş. Öne çıkan endişeler:
- **Durable Ownership Problem:** Credential'lar runtime tabanlıyken ve oturumlar sona ererken, ajan eylemlerinden sorumlu tarafın nasıl tanımlanacağı
- **Authorization Attenuation**
- **Delegation Mechanisms**

**Sonuç:** Grup kimlik/yetkilendirmeyi **mevcut çalışmalara (WIMSE, OAuth) yönlendirdi**, yeni iş yaratmadı.

**Eylül 2026: Henüz chartered DEĞİL.**

**Ayrıca reddedilen bir BoF:** `bofreq-kuhlewind-agent-use-of-delegation-and-interaction-traceability-audit` — **AUDIT**. Önericiler: **Mirja Kühlewind, Henk Birkholz, Pam Dingle**. Kapsam: dağıtık audit için interoperable protokol mekanizmaları; RATS/SCITT profilleme. **Durum: DECLINED.**

> **Ajan denetlenebilirliği (non-repudiation) IETF'te henüz mekân bulamadı.**

---

## 6. MCP ve A2A

### 6.1 MCP Authorization — revizyon 2026-07-28

Detaylar için bkz. mcp-yetkilendirme.md (§14).

**🟢 TAMAMEN BUGÜN.** MCP-native olmak, bu IdP'nin pazara giriş kancası.

### 6.2 A2A Protokolü

- Linux Foundation yönetiminde. ⚠️ **v1.0 tarihi ÇELİŞKİLİ:** site "August 2026", blog duyurusu "12 Mart 2026". **Kesin GA tarihi DOĞRULANAMADI.** 27 Ağustos 2026'da Agentic AI Foundation'a katıldığı bilgisi var
- **Agent Card (`/.well-known/agent-card.json`):** Zorunlu `id`, `name`, `interfaces[]`; **`securitySchemes`**: `map<string, SecurityScheme>` — OpenAPI 3 ile birebir aynı şekil; **`security`**: skill bazında granülerlik; **`signature`**: `AgentCardSignature`
- **SecurityScheme tipleri:** `apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTls`
- **OAuth flow'ları:** `authorizationCode`, `clientCredentials`, **`deviceCode`**. **`implicit` ve `password` YOK** — OAuth 2.1 uyumlu
- **Signed Agent Cards:** **RFC 8785 JCS** ile kanonikleştirilip **JWS** ile imzalanır
- **HITL:** `TASK_STATE_INPUT_REQUIRED` ve `TASK_STATE_AUTH_REQUIRED` — **ama onayın nasıl toplanacağı, işleme nasıl kriptografik bağlanacağı TANIMSIZ**

⚠️ **Kritik boşluk:** A2A spec'inde **SPIFFE/SPIRE geçmiyor.** `mutualTls` var ama sertifikadaki SPIFFE ID'nin ajan kimliğine nasıl bağlanacağına dair **normatif kural yok.**

**MCP ile temel fark:** A2A auth şemasını **agent'ın kendi kartında bildirimsel** tanımlar; MCP **OAuth keşif zincirini** zorunlu kılar. **MCP'nin modeli daha katı ve daha OAuth-yerlisidir.**

**🟡 A2A bir IdP protokolü değil — bizim işimiz onun `securitySchemes`'inde görünmek.** Somut: `openIdConnectUrl` discovery + `deviceCode` + `clientCredentials` + `authorizationCode` + **RFC 8705 mTLS-bound token (SAN URI'den SPIFFE ID çıkarımı)** → bu son madde A2A↔SPIFFE boşluğunu doldurur ve **kimsenin yapmadığı bir şey**.

---

## 7. Endüstri — teknik karşılaştırma

### 7.1 Microsoft Entra Agent ID

**GA: Nisan 2026**

| Kavram | Tanım |
|---|---|
| **Agent identity** | Özel bir **service principal**. Kendi credential'ı **YOK** |
| **Agent identity blueprint** | Yeniden kullanılabilir şablon; **credential'ları BLUEPRINT tutar** |
| **Blueprint principal** | Blueprint tenant'a eklendiğinde oluşan Entra nesnesi; **asıl token alan ve audit log'da görünen** |
| **Sponsor** | Ajandan sorumlu insan kullanıcı/grup |
| **Agent's user account** | Opsiyonel, **1:1**, gerçek user object gerektiren sistemler için |

**Token davranışı (docs'tan birebir):**
> *"Request agent tokens... **The subject of the access token is the agent identity.**"*
> *"Request user tokens for an authenticated user. **The subject of the token is a user, while the actor is the agent identity.**"*

> **Microsoft, `sub`=kullanıcı + `actor`=ajan modelini üretimde kullanıyor. RFC 8693 `act` semantiğiyle örtüşüyor.**

**Design pattern derslerinden — doğrudan uygulanabilir:**
- **Scale-out replikalar ayrı agent identity GEREKTİRMEZ** — *"Creating a separate agent identity per replica adds directory objects and management overhead without any audit, access control, or accountability benefit."*
- **Memory/context yönetimi ayrı kimlik gerektirmez** — session id ile filtreleme yeterli
- **Yüksek-hacimli per-object agent identity pratik değil** — *"use shared agent identities and rely on session or context identifiers at the application layer"*
- **Ephemeral agent identity** varyantı var ama "nondeterministic latency" uyarısı

⚠️ **Standartlaşma: SIFIR.** Entra Agent ID tamamen proprietary Graph modeli. ID-JAG, MCP EMA veya WIMSE desteği **docs'ta bulunamadı — DOĞRULANAMADI.**

### 7.2 Okta

- **Okta for AI Agents GA: 30 Nisan 2026** (ayrı ücretli ürün) — ajan keşfi/kaydı Universal Directory'de, Privileged Credential Management, **Universal Logout for AI Agents**
- **Agent SSO GA: 24 Ağustos 2026**, **çekirdek SSO planlarına dahil, ek ücretsiz**

**Üretim kanıtı:** Atlassian Rovo MCP, XAA/ID-JAG ile canlı (29 Haziran 2026). Doğrulama adımları: (1) imza+issuer JWKS'ten, (2) `typ`=`oauth-id-jag+jwt`, (3) `aud` bizi göstermeli, (4) **client continuity**, (5) `exp`/`iat`/`jti` tekilliği.

### 7.3 Auth0

- **Auth0 for AI Agents GA: 19 Kasım 2025**; **Auth for MCP GA: 6 Mayıs 2026**
- Dört bileşen: User Authentication, **Token Vault**, **Asynchronous Authorization (CIBA)**, FGA for RAG

**Token Vault — RFC 8693 tabanlı ama proprietary URN'ler:**
```
grant_type=urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token
subject_token=<AUTH0_REFRESH_TOKEN>
requested_token_type=http://auth0.com/oauth/token-type/federated-connection-access-token
connection=google-oauth2
```
Saklama: **"tokenset"** — her (kullanıcı × connection) için konteyner. Ajan hiçbir zaman 3. parti refresh token'a dokunmaz. 35+ sağlayıcı.

**CIBA + RAR kombinasyonu (en öğretici kısım):**
```
POST /bc-authorize
login_hint={"format":"iss_sub","iss":"https://{tenant}/","sub":"{USER_ID}"}
binding_message=Confirm payment of 2500
authorization_details=[{"type":"money_transfer","instructedAmount":{"amount":2500,"currency":"USD"},
  "sourceAccount":"...1234","destinationAccount":"...9876","beneficiary":"Hanna Herwitz"}]
```
**Kritik:** Onay verilince **`authorization_details` dizisi access token içinde aynen taşınıyor** — RS "ne onaylandı"yı token'dan doğrulayabiliyor.

### 7.4 Descope Agentic Identity Hub

**Hub 2.0: Ocak 2026.** Veri modeli en kopyalanmaya değer olan — **iki eksenli:**
- **Resources (inbound):** korunan API'ler/MCP sunucuları; `audience URL` + `scopes`; kısa ömürlü scope-sınırlı token **verir**
- **Connections (outbound):** downstream servisler için credential vault; uzun ömürlü 3. parti credential'ları **yönetir**
- **Önerilen desen:** ajan → Resource → Connection vault. **Ajan asla vault'a doğrudan erişmez.**

Client registration dört yol: pre-registered, **cloud workload OIDC token'ları (AWS/GCP)**, DCR, CIMD.

### 7.5 SPIFFE/SPIRE — mevcut durum ve sınırlar

**JWT-SVID kuralları:**
- `sub` = workload'un SPIFFE ID'si (**MUST**)
- `aud` **MUST** bulunsun; doğrulayıcı kendi identifier'ı yoksa **reddeder**
- `exp` **MUST**; `exp`'siz token **reddedilmeli**
- Anahtar keşfi: SPIFFE bundle'da RFC 7517 JWK; **`use` = `jwt-svid`**

**WIT-SVID** (SPIFFE spec setinde **"Incubating"**) — JWT-SVID'in adayı halefi:

| | JWT-SVID | WIT-SVID |
|---|---|---|
| Tip | **Bearer** | **Proof-of-Possession** |
| `cnf` | yok | **ZORUNLU** |
| `aud` | zorunlu | **yasak** |

**SPIFFE'in ajanlar için sınırları:**
1. SPIRE **adanmış altyapı** ister — çoğu ajan dağıtımı için ağır
2. **X.509 issuance gecikmesi, efemer ajan yaratımıyla uyumsuz**
3. **Cross-protocol identity flow yok**
4. **Delegasyonu hiç modellemez** — "bu process nedir"i çözer, "kimin adına"yı çözmez

> **Doğru mimari: SPIFFE = L1 (bu process kim). Argus = L2 (kimin adına, ne yetkiyle). SVID → token exchange → delegasyon taşıyan access token.**

### 7.6 OpenID Foundation

**AIIM CG** — OIDF board Nisan 2025'te görevlendirdi. Ekim 2025'te whitepaper (arXiv:2510.25819, Tobin South + 20 yazar). Eş başkanlar: Atul Tulshibagwale (CrowdStrike), Jeff Lombardo (AWS). **Mart 2026'da NIST RFI'ye resmî yanıt verdi.** Kapsam dışı: protokol standardı geliştirmek.

**AuthZEN WG — 15 Haziran 2026'da iki WG Draft onaylandı:**

**AARP (Access Request and Approval Profile)** — Draft 1, Eylül 2026
- **Requestable denial context:** PDP, reddederken `access_request` nesnesi ekleyerek reddin talebe uygun olduğunu bildirir
- **Access request endpoint** + **task handle** (opak, asenkron; *"survives PEP restart, replacement, or handoff"*)
- **Re-evaluation mode:** onay sonrası PEP taze AuthZEN değerlendirmesi yapar — **PDP enforcement anında otoriter kalır**
- Reddedilmiş karar **reddedilmiş kalır (MUST NOT)**

**COAZ-MCP Binding** — Draft 1, Şubat 2026
- MCP JSON-RPC mesajlarını **AuthZEN SARC** modeline eşliyor
- `x-authzen-mapping`, **CEL** ifadeleri (`$params.arguments.id`, `$token.sub`)
- **Subject identity trust modeli:** *"The human user is represented as the AuthZEN Subject; the AI agent appears in the Context."*
- **Sadece doğrulanmış `subject.id` güvenilir**

**Shared Signals — SSF 1.0 + CAEP 1.0 Final, 29 Ağustos 2025**
CAEP 1.0 Final **8 event type**. **Ajan-spesifik event tipi YOK** — bu bir boşluk.

⚠️ **Tuzak:** `openid.net/specs/openid-caep-specification-1_0.html` hâlâ **2021 draft-02**'yi döndürüyor. Final: `openid-caep-1_0-final.html`.

---

## 8. Açık problemler — ne çözüldü, ne çözülmedi

| Problem | Durum | Kanıt |
|---|---|---|
| Cross-domain kimlik zinciri | 🟢 **Neredeyse çözüldü** | identity-chaining-17 RFC kuyruğunda |
| Cross-app kullanıcı SSO taşıma | 🟢 **Çözüldü** | ID-JAG-04 + MCP EMA Stable + üretim |
| Sender-constrained token | 🟢 **Çözüldü** | DPoP RFC 9449, mTLS RFC 8705 |
| Sinyal/olay dağıtımı | 🟢 **Çözüldü** | SSF 1.0 + CAEP 1.0 Final |
| Out-of-band kullanıcı onayı | 🟡 **Kısmen** | CIBA Final ama **mid-execution'a uymuyor** (AIMS §10.7 itirafı) |
| Ölçeklenebilir revocation | 🟡 **Neredeyse** | status-list-21 RFC kuyruğunda (`VALID`/`INVALID`/**`SUSPENDED`**) |
| **Delegasyon zinciri kriptografik doğrulanabilirliği** | 🔴 **AÇIK** | `act` yetki için kullanılamaz; **7 rakip draft, hiçbiri WG'de** |
| **Ajan kaydı / keşfi** | 🔴 **AÇIK** | A2A registry tartışması **1+ yıldır** sonuçsuz (#741, 80+ yorum); MCP Registry **preview** |
| **Attenuation'ın OAuth'a entegrasyonu** | 🔴 **AÇIK** | Biscuit v3.3 / UCAN 1.0 olgun ama **OAuth'la konuşmuyor**. OAuth scope'u **operatör** düzeyinde ("TRANSFER"), **operand** düzeyinde değil ("Bob'a 100$") — arXiv:2603.17170 |
| **Mid-execution HITL, işleme kriptografik bağlı** | 🔴 **AÇIK** | CIBA `binding_message` sadece serbest metin. **Dört aday, hepsi bireysel** |
| **Ajan-spesifik CAEP event'leri** | 🔴 **AÇIK** | CAEP 1.0'da yok |
| **Toplu/kitlesel iptal** | 🔴 **AÇIK** | `draft-chen`'in "Mass Revocation Gap"i |
| **Ajan denetlenebilirliği** | 🔴 **AÇIK** | AUDIT BoF **DECLINED** |
| **Workload kimliği standardı** | 🔴 **AÇIK** | WIMSE'den **hiç RFC yok** |
| **Prompt injection'ın yetkilendirmeye etkisi** | 🔴 **YETKİLENDİRME KATMANINDA ÇÖZÜLEMEZ** | Güçlü konsensüs |

### 8.1 Prompt injection — dürüst değerlendirme

**Lethal trifecta** (Simon Willison, 16 Haziran 2025): özel veriye erişim + güvenilmeyen içeriğe maruziyet + dışarı iletişim. *"we still don't know how to 100% reliably prevent this from happening."*

**AIMS'in normatif cevabı (§8):** *"The Large Language Model MUST NOT have access to an agent's credentials..."*

**Ekosistemin gerçek durumu (arXiv:2605.22333, 21 Mayıs 2026, Fudan):** 7.973 canlı uzak MCP sunucusu → **%40,55'i hiçbir auth olmadan tool açıyor**; OAuth'lu 119 sunucunun **%100'ünde en az bir kusur** (toplam 325); **%96,6 DCR kusuru**.

**Yetkilendirme katmanının yapabildikleri (ölçülmüş)** — arXiv:2609.00267 (31 Ağu 2026): LangGraph/CrewAI/AutoGen/MCP değerlendirmesi: **üçü hiçbir yerleşik confinement sağlamıyor.** Yazarların **authorization broker**'ı 4 tehdidi de engelliyor ve ele geçirilmiş alt-ajanın erişimini **8.100 olası eylemden ortalama 1,5'e** düşürüyor. Makalede geçen "karar başına ~2,6 µs" rakamı **160 satırlık Python'da HMAC caveat doğrulamasıdır**, ReBAC graph çözümlemesi değil — Argus'un yetkilendirme hedefi olarak alınamaz (bkz. yetkilendirme-motoru.md (§20) §0). Doğru okuma: *yetki token'a gömülüyse doğrulama neredeyse bedavadır.*

> **Argus'un tez cümlesi: yetkilendirmeyi modelden çıkar, deterministik bir broker'a koy.**

---

## 9. Düzenleyici durum

**Net cevap: Bugün bir IdP'yi "AI ajanlarına ayrı kimlik ver" diye hukuken ZORLAYAN bağlayıcı düzenleme YOK.**

| Kaynak | Bağlayıcı? | Ajan kimliği gerektiriyor mu? | Ne zaman ısırır |
|---|---|---|---|
| **EU AI Act Md. 50** | ✅ Yürürlükte (2 Ağu 2026) | ❌ Sadece "AI'yım" ifşası | Şimdi |
| **EU AI Act yüksek risk** | ✅ ama **2 Ara 2027'ye ertelendi** (Reg. EU 2026/1744, 27 Tem 2026) | Dolaylı | 2027-12 |
| **Singapur CSA Securing Agentic AI Addendum** (17 Haz 2026) | ❌ *"not mandatory, prescriptive nor exhaustive"* | ✅ **Çok spesifik** | Tedarik/denetim baskısı |
| **NIST NCCoE "Software and AI Agent Identity and Authorization"** (5 Şub 2026) | ❌ | ✅ **En teknik** — MCP, OAuth 2.0/2.1, OIDC, **SPIFFE/SPIRE, SCIM, NGAC** | 2027 federal tedarik |
| **OWASP Agentic Top 10 (2026)** | ❌ | ✅ **ASI03 Identity & Privilege Abuse** | Şimdi (fiili baseline) |
| **FIDO Agentic Authentication WG** (28 Nis 2026) | ❌ | ✅ Verifiable User Instructions, Trusted Delegation for Commerce | 2027+ |

**Singapur CSA'nın somut kontrolleri:**
- *"Maintain **trusted registry of agents** and authenticate agents using **strong, verifiable credentials**"*
- *"Ensure **fine-grained, scoped tokens**"*; *"**time-bound or one-time-use credentials**"*
- *"**Validate permissions on every request to each agent in the workflow**"*
- *"**Prevent cross-agent privilege delegation**"*
- *"**Do not share credentials with the agent**"*

**WEF "AI Agents in Action" (Mayıs 2026) — ACAP çerçevesi.** En aksiyona dönüştürülebilir kuralı:
> *"a downstream agent operates under the **intersection** of its own ACAP permissions and those of the agent that invoked it. **An orchestrating agent cannot delegate authority it does not itself hold.**"*

**Dört kaynağın (CSA + NIST + OWASP + WEF) ortak paydası = bir IdP'nin roadmap'i:**
1. Her ajana benzersiz, ayrı kimlik (service account paylaşımı yok)
2. Kısa ömürlü, scoped, zaman-sınırlı credential
3. Güvenilir ajan kaydı + doğrulanabilir credential
4. Delegasyonda **kesişim, toplama değil**
5. **Her adımda yeniden yetkilendirme** — bir kez token alıp zincir boyunca kullanmak açık anti-pattern
6. Non-repudiation / denetlenebilirlik
7. Merkezî enforcement plane
8. Kullanıcı-başlatılan vs. ajan-başlatılan eylem ayrımı

---

## 10. Sınıflandırma

### 🟢 BUGÜN İMPLEMENTE EDİLMELİ

| # | Öğe | Neden |
|---|---|---|
| 1 | **OAuth 2.1 çekirdeği** (PKCE S256 zorunlu, `plain` reddi; implicit/password YOK) | Her şeyin tabanı |
| 2 | **RFC 8414 + OIDC Discovery** — **ikisi birden** | MCP MUST |
| 3 | **RFC 9728 PRM** | MCP MUST |
| 4 | **RFC 8707 `resource`** + canonical URI validasyonu + `aud`'a yansıtma | MCP MUST |
| 5 | **RFC 9207 `iss`** (hata dahil), normalizasyon YOK | MCP MUST, yakında MUST'a yükselecek |
| 6 | **CIMD tam implementasyonu** + `client_id_metadata_document_supported: true` | DCR deprecated |
| 7 | **RFC 7591 DCR** (legacy, `application_type`, issuer-bound credential) | 12+ ay geriye uyum |
| 8 | **RFC 8693 Token Exchange** — standart URN'lerle, `act` + `may_act` | Delegasyonun tabanı |
| 9 | **ID-JAG issuance + consumption** + metadata + `jti` replay cache + **client continuity** | **Keycloak'ta issuance YOK** |
| 10 | **SPIFFE client auth** (JWT-SVID, X.509-SVID, Bundle Endpoint) | Keycloak implemente ediyor |
| 11 | **DPoP (RFC 9449)** `cnf.jkt` + **mTLS-bound (RFC 8705)** `cnf.x5t#S256` | 3 Ağu 2026 ölçümünde 15 issuer'dan **0'ı DPoP** ilan ediyordu |
| 12 | **RAR (RFC 9396)** — istekte VE token claim'inde, per-type JSON Schema, consent'te insan-okunur render | Ajanlar için scope'tan kat kat önemli |
| 13 | **CIBA** (`/bc-authorize`, `binding_message`, `authorization_pending`/`slow_down`) | Server-Mediated bağlama modelinin ta kendisi |
| 14 | **Scope challenge motoru:** 403 + `insufficient_scope` + `scope` + `resource_metadata` | MCP MUST/SHOULD |
| 15 | **Workload-tarzı hiyerarşik identifier'lar** (`spiffe://` / `wimse://`) | Policy wildcard'ları |
| 16 | **RFC 7009 revocation + RFC 7662 introspection + JWKS rotation** | Temel hijyen |
| 17 | **SSF/CAEP transmitter — Final spec (8 event)** | ⚠️ 2021 draft-02 URL tuzağı |

### 🟡 ARAYÜZÜ HAZIRLANMALI

18. **`delegation_chain` claim'i** — per-hop imza, detached JWS + JCS
19. **Actor Profile değişmezleri:** `sub`=yetkilendiren, en dıştaki `act.sub`=doğrudan aktör, kanonik id=`(act.iss, act.sub)`; min depth 4
20. **`sub_profile` / `client_profile`** claim'leri, `ai_agent` değeri
21. **`agent_instance_id`** + `agent_platform`/`agent_model`/`agent_runtime`
22. **Attestation-based client auth** (`OAuth-Client-Attestation` header'ları)
23. **Transaction Tokens** (`typ: txntoken+jwt`, `Txn-Token` header'ı, TTS)
24. **Mid-execution HITL uzantı noktası** — üç adaydan birini seç, üçünü de destekleyebilecek soyutlama kur
25. **AuthZEN PDP entegrasyonu** — SARC, `x-authzen-mapping`, CEL; AARP'ın task handle modeli
26. **Delegated Refresh Token profili** — mutlak deadline, **task-scoped revocation**
27. **`refresh_token_timeout` + `authorization_expires_in`**
28. **RAR metadata discovery + remediation**
29. **First-Party Apps** Authorization Challenge Endpoint + `auth_session`
30. **SCIM `/Agents` + `/AgenticApplications`** — `owners`, `protocols`, `subject`
31. **Üç bağlama modeli** olarak akışlar: Agent-Mediated / Owner-Mediated / **Server-Mediated (=CIBA)**
32. **WIT/WPT desteği**
33. **Agent Card imzalama servisi** (RFC 8785 JCS + JWS + JWKS) — **hiçbir mainstream IdP yapmıyor**
34. **Federated credential vault ("Connection")** — envelope encryption, otomatik refresh worker
35. **Cloud workload federasyonu** (AWS/GCP OIDC → `jwt-bearer`)

### 🔴 HENÜZ ERKEN

Attenuating tokens (4 rakip draft) · Agent registry protokolleri (NANDA, ANS, AgentDNS, `agent://`, `urn:aid:`) · Donanım-çapalı ajan kimliği · `agent_trust_score` tarzı claim'ler · Rego/policy language OAuth binding · Mission-bound authorization · Ajan-spesifik CAEP event tipleri · Global/mass revocation standardı · SD-JWT ile Agent Card selective disclosure · agentproto'nun getireceği her şey

---

## 11. Somut teknik gereksinim listesi

### 11.1 Endpoint'ler

**Standart:**
```
GET  /.well-known/openid-configuration          OIDC Discovery (MUST — MCP)
GET  /.well-known/oauth-authorization-server    RFC 8414 (MUST — MCP)
GET  /.well-known/jwks.json                     JWKS
GET  /authorize                                 + iss in response (RFC 9207)
POST /token                                     tüm grant'lar
POST /par                                        RFC 9126
POST /revoke                                     RFC 7009
POST /introspect                                 RFC 7662
POST /register                                   RFC 7591 (legacy)
GET  /userinfo
```

**Ajan için ek:**
```
POST /bc-authorize                              CIBA backchannel
POST /token  (grant_type=...:ciba)              CIBA polling
POST /authorize-challenge                       FiPA (🟡)
GET  /.well-known/authorization-details-types   RAR metadata (🟡)
POST /access-requests                           AuthZEN AARP (🟡)
GET  /access-requests/{task_handle}             AARP task status (🟡)
POST /agents/{id}/revoke-all                    toplu iptal (standart yok)
GET  /ssf/.well-known/sse-configuration         SSF transmitter
POST /agent-cards/sign                          A2A Agent Card imzalama (🟡, farklılaşma)
SCIM /Agents, /AgenticApplications              (🟡)
```

**Grant type'lar:**
```
authorization_code                                          (PKCE S256 zorunlu)
refresh_token
client_credentials
urn:ietf:params:oauth:grant-type:token-exchange             RFC 8693
urn:ietf:params:oauth:grant-type:jwt-bearer                 RFC 7523 → ID-JAG tüketimi
urn:openid:params:grant-type:ciba                           CIBA
urn:ietf:params:oauth:grant-type:device_code                RFC 8628 (A2A deviceCode)
```

**`requested_token_type` değerleri:**
```
urn:ietf:params:oauth:token-type:access_token
urn:ietf:params:oauth:token-type:id_token
urn:ietf:params:oauth:token-type:refresh_token
urn:ietf:params:oauth:token-type:jwt
urn:ietf:params:oauth:token-type:id-jag                     ⭐ ID-JAG üretimi
urn:ietf:params:oauth:token-type:txn_token                  🟡
```

**Client auth metotları:**
```
private_key_jwt                                            (CIMD ile önerilen)
tls_client_auth / self_signed_tls_client_auth              RFC 8705
client_secret_basic / client_secret_post                   (legacy)
urn:ietf:params:oauth:client-assertion-type:jwt-spiffe     ⭐ JWT-SVID
attest_jwt_client_auth                                     🟡
```

### 11.2 Token tipleri (`typ` header'ları)

| `typ` | Ne | Öncelik |
|---|---|---|
| `at+jwt` | Access token (RFC 9068) | 🟢 |
| `oauth-id-jag+jwt` | **ID-JAG** | 🟢 |
| `dpop+jwt` | DPoP proof | 🟢 |
| `txntoken+jwt` | Transaction Token | 🟡 |
| `wit+jwt` | WIMSE Workload Identity Token | 🟡 |
| `application/wpt+jwt` | WIMSE Workload Proof Token | 🟡 |
| `oauth-client-attestation+jwt` / `-pop+jwt` | Client attestation | 🟡 |

### 11.3 Claim seti — ajan access token'ı hedef şekli

```jsonc
{
  // — Kimlik —
  "iss": "https://idp.acme.example/",
  "sub": "user:alice@acme.example",              // YETKİLENDİREN (insan)
  "sub_profile": "user",                          // 🟡
  "aud": "https://mcp.chat.example/",             // RFC 8707 resource
  "client_id": "https://app.example.com/client.json",  // CIMD URL-form
  "jti": "...", "iat": ..., "exp": ...,

  // — AKTÖR (ajan) — RFC 8693, iç içe olabilir —
  "act": {
    "sub": "spiffe://acme.example/agent/invoice-bot/i-7f3a",
    "iss": "https://idp.acme.example/",
    "sub_profile": ["ai_agent", "client_instance"],   // 🟡
    "agent_instance_id": "aai-...",                    // 🟡
    "agent_platform": "...", "agent_model": {"id":"...","version":"..."},
    "act": { /* bir üst hop — min depth 4 */ }
  },

  // — DELEGASYON ZİNCİRİ (imzalı) — 🟡 —
  "delegation_chain": [
    { "delegator_id":"...", "delegatee_id":"...", "iat":..., "exp":...,
      "policy": {...}, "as_signature":"<detached JWS>", "delegator_signature":"<detached JWS>" }
  ],
  "del_depth": 2, "del_max_depth": 4,

  // — YETKİ —
  "scope": "chat.read chat.history",
  "authorization_details": [ /* RFC 9396 — operand seviyesi */ ],

  // — SAHİPLİK KANITI —
  "cnf": { "jkt": "<DPoP thumbprint>" },
  "txn": "...",                                      // 🟡
  "tenant": "acme"
}
```

**Kural:** `sub` = insan, `act` = ajan. **Otonom (kullanıcısız) ajan durumunda `sub` = ajan, `act` yok.**

### 11.4 Veri modeli

```rust
enum Principal { User(User), ServiceAccount(SA), Agent(AgentIdentity) }

struct AgentIdentity {
    id: Uuid,
    identifier: WorkloadUri,          // spiffe:// veya wimse:// — opak UUID DEĞİL
    blueprint_id: Option<Uuid>,       // Entra "blueprint" modeli
    owner_user_id: Option<Uuid>,      // OBO ajanlar var, otonom ajanlar var
    sponsor_user_id: Option<Uuid>,    // Entra "sponsor": olayda aranacak insan
    tenant_id: Uuid,
    display_name: String,
    agent_type: AgentType,            // assistant | bot | orchestrator | worker
    protocols: Vec<Protocol>,         // MCP-Server | A2A | OpenAPI
    status: Active | Suspended | Disabled,
    trusted_instance_issuers: Vec<Url>,
    x509_spiffe_ids: Vec<SpiffeId>,
    jwks_uri: Option<Url>,
    inheritable_scopes: Vec<Scope>,   // blueprint'ten miras
    direct_scopes: Vec<Scope>,
    authorization_details: Vec<RarObject>,
    max_delegation_depth: u8,         // varsayılan 4
    default_token_ttl: Duration,      // insan token'larından ÇOK kısa
}

// Descope'un iki eksenli modeli
struct Resource {                     // inbound: bizim koruduğumuz
    id: Uuid, audience_uri: Url, scopes: Vec<Scope>,
    allowed_clients: Vec<ClientRef>, policy_ref: PolicyId,
    prm_document: ProtectedResourceMetadata,   // RFC 9728
}
struct Connection {                   // outbound: 3. parti credential vault
    id: Uuid, tenant_id: Uuid, provider: ProviderId,
    oauth_config: OAuthClientConfig,
    scope_mapping: HashMap<Scope, Vec<Scope>>,
}
struct TokenSet {                     // (user × connection) → şifreli credential
    user_id: Uuid, connection_id: Uuid,
    access_token_enc: Vec<u8>,        // envelope encryption: per-tenant DEK
    refresh_token_enc: Vec<u8>,
    issued_scopes: Vec<Scope>, expires_at: DateTime,
}

struct CrossAppConnection {           // ID-JAG
    requesting_client_id: ClientId,
    resource_as_issuer: Url,
    resource_identifier: Option<Url>,
    allowed_scopes: Vec<Scope>,
    subject_mapper: SubjectMapper,    // idp_user_id → resource app'in beklediği sub
    subject_policy: PolicyId,
}

struct DelegationRecord {
    delegator_id: PrincipalRef, delegatee_id: PrincipalRef,
    iat: i64, exp: i64,
    granted_scopes: Vec<Scope>,        // KESİŞİM kuralı (WEF ACAP)
    authorization_details: Vec<RarObject>,
    as_signature: DetachedJws,         // JCS (RFC 8785) üzerinden
    delegator_signature: Option<DetachedJws>,
}
```

**Zorunlu değişmezler (kod seviyesinde enforce et):**
1. **Monotonic attenuation:** `child.scopes ⊆ parent.scopes`
2. **TTL monotonluğu:** `child.exp ≤ parent.exp`
3. **Depth monotonluğu:** `child.del_depth = parent.del_depth + 1 ≤ max_depth`
4. **Zincir sürekliliği:** `record[i].delegator_id == record[i-1].delegatee_id`
5. **Kesişim semantiği:** downstream ajan, kendi izinleri ∩ çağıranın izinleri
6. **PoP:** leaf token'ın sunucusu özel anahtarı kontrol ediyor olmalı

### 11.5 AS Metadata

```json
{
  "authorization_response_iss_parameter_supported": true,
  "client_id_metadata_document_supported": true,
  "identity_chaining_requested_token_types_supported": ["urn:ietf:params:oauth:token-type:id-jag"],
  "authorization_grant_profiles_supported": ["urn:ietf:params:oauth:grant-profile:id-jag"],
  "grant_types_supported": ["authorization_code","refresh_token","client_credentials",
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:openid:params:grant-type:ciba",
    "urn:ietf:params:oauth:grant-type:device_code"],
  "token_endpoint_auth_methods_supported": ["private_key_jwt","tls_client_auth",
    "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe","client_secret_basic"],
  "dpop_signing_alg_values_supported": ["ES256","EdDSA"],
  "authorization_details_types_supported": [...],
  "entity_profiles_supported": ["user","service","ai_agent"],
  "backchannel_token_delivery_modes_supported": ["poll","ping","push"],
  "backchannel_authentication_endpoint": "https://.../bc-authorize",
  "authorization_challenge_endpoint": "https://.../authorize-challenge"
}
```

---

## 12. Çelişkili / yakınsamamış noktalar

1. **Mid-execution HITL: dört rakip mekanizma.** `interaction_required` + `interaction_uri` (Parecki/Campbell/Liu) · `completion_mode=deferred` + `deferral_code` (Gerber) · `transaction_challenge` (Rosomakho/Campbell/McGuinness/Kasselman) · AuthZEN AARP. **Üçü de aynı IETF 126 oturumunda sunuldu.**
   → **Öneri:** İç mimaride tek bir "pending authorization" soyutlaması kur; dört yüzeyi de ona bağla.

2. **Delegasyon zinciri: 7 rakip yaklaşım.** JWT claim vs HTTP header vs offline-doğrulanabilir capability chain vs sadece `act` profili. **Kriptografi de farklı:** çift-imza vs parent-hash zinciri vs HTTP Message Signatures.

3. **Bearer mi PoP mu:** WIMSE WIT `MUST NOT be used as a bearer token` diyor; MCP hâlâ `Authorization: Bearer` üzerine kurulu. SPIFFE JWT-SVID bearer, halefi WIT-SVID PoP. **Ekosistem ikiye bölünmüş.**

4. **`act` yetki için kullanılabilir mi:** RFC 8693 açıkça hayır diyor; ama neredeyse tüm ajan draft'ları `act`'i delegasyon kanıtı gibi kullanıyor. **Bu bir standart ihlali riski.**

5. **A2A v1.0 tarihi çelişkili.**

6. **Spec-lag:** MCP `draft-ietf-oauth-v2-1-13` ve `client-id-metadata-document-00`'a referans veriyor; güncel **-16** ve **-02**.

7. **ID-JAG'ın intended status'u:** Datatracker "None" gösteriyor, draft metni "Standards Track" diyor. **Metadata tutarsızlığı.**

8. **`draft-parecki-oauth-global-token-revocation-06`:** API "2026-08-28, rev 06" gösteriyor, doküman sayfası "expired, 24 Şubat 2026" diyor. **Çelişki çözülemedi.**

9. **Entra Agent ID ile açık standartlar:** Microsoft üretimde `sub`/`actor` ayrımını yapıyor ama ID-JAG/MCP EMA/WIMSE desteği docs'ta **bulunamadı**.

10. **"Ajan kaydı" konusunda tam kaos:** A2A registry (tartışma), MCP Registry (preview), SCIM `/Agents` (draft), Entra/Agent 365 (proprietary), `urn:aid:` (spekülatif), AgentDNS/ANS/NANDA (akademik). **Hiçbiri diğeriyle uyumlu değil.**

---

## 13. Doğrulanamayanlar

1. OAuth WG chairs'in "ajan dokümanlarının adopsiyonu için erken" ifadesinin **tam metni**
2. Delegation chain splicing saldırısının **birincil mesaj gövdesi**
3. `draft-ni-wimse-ai-agent-identity`'nin **-03 revizyonu** var mı (-02 süresi 1 Eyl 2026'da doldu)
4. AIMS'in "8 katmanlı yapısı" — ham metinde 7 bileşen sayıldı
5. **A2A v1.0'ın kesin GA tarihi**
6. Keycloak'ın ID-JAG issuance issue'su (keycloak#43971)
7. Singapur CSA Addendum'un **nihai (17 Haz 2026)** metnindeki kimlik kontrolleri
8. PSD3/PSR'de agentic AI'ya özgü hüküm — **bulunamadı**
9. NIST SP 800-63'ün NHI güncellemesi için resmî takvim
10. Entra Agent ID'nin açık standart desteği
11. Auth0'da ajana özel application type; Auth for MCP'nin RFC 9728 implementasyonu
12. Okta Agent SSO'nun GA tarihi (24 Ağu 2026 birincil; "Mayıs 2026" ikincil, çelişkili)
13. `github.com/nomoticai/ietf-agent-landscape` içeriği (URL 404)
14. `draft-sweeney-wimse-credential-delegation-00` içeriği
15. UCAN 1.0'ın kesin yayın tarihi; zcap-ld'nin 2026 durumu; KERI'nin ajan bağlamındaki benimsenmesi
16. Ping Identity, Astrix, Oasis Security'nin agentic **ürün** yaklaşımları

---

## 14. Argus için üç stratejik hamle

**1. ID-JAG'ı gün bir tam yap (issue + consume).** Keycloak sadece tüketiyor, o da preview. MCP Enterprise-Managed Authorization **Stable** ve ID-JAG'ın ta kendisi. **"MCP-native kurumsal IdP" konumlandırması bugün boş.**

**2. Bearer'ı varsayılan yapma.** 3 Ağustos 2026 ölçümünde discovery yanıtı veren 15 halka açık issuer'dan **10'u sadece shared-secret client auth, 3'ü private_key_jwt, 1'i mTLS, 0'ı DPoP** ilan ediyordu. DPoP + mTLS-bound + JWT-SVID kabulünü birinci sınıf yapan ilk ciddi IdP olmak, hem WIMSE'nin gittiği yön hem somut farklılaşma.

**3. Delegasyon zincirini kendi imzalı yapınla çöz, `act`'i uyumluluk için üret.** Standart yakınsamadı ve en az 2 yıl daha yakınsamayacak. `draft-liu-oauth-chain-delegation`'ın şeklini + `draft-mcguinness-oauth-actor-profile`'ın üç değişmezini + WEF ACAP'ın kesişim kuralını + attenuation değişmezlerini (I1-I6) bugün implemente et. Hangisi standartlaşırsa geçiş ucuz; hiçbiri olmazsa zaten `act`'in güvenli üst kümesine sahip olursun.

**Ve deterministik yetkilendirme broker'ını modelin dışında, Rust'ta tut.**
