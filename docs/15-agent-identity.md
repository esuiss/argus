# §15 — AI ajan kimliği

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

**Kapsam.** Yaklaşık 60 birincil kaynak kullanılmıştır: IETF Datatracker API'si, spesifikasyon ham metinleri, IETF 126 Viyana slaytları ile tutanakları, MCP `ext-auth` depo dosyaları, AuthZEN taslakları ve Entra Agent ID dokümanları.

---

## 0. Yönetici özeti, beş cümlelik gerçek

1. **IETF OAuth çalışma grubu Haziran 2026'da yeniden charter'lanmış ve karmaşık delegasyon resmen çalışma programına girmiştir.** Ancak Eylül 2026 itibarıyla hiçbir ajana özgü doküman çalışma grubu tarafından kabul edilmemiştir.
2. Buna karşılık 200'den fazla ajanla ilgili internet taslağı IETF'e akmıştır ve başkanlar bunu işleyemediklerini açıkça söylemektedir.
3. **Bugün gerçekten implemente edilmesi gereken tek ajana özgü şey ID-JAG'dır.** MCP'nin Enterprise-Managed Authorization uzantısı stabildir ve doğrudan onu profillemektedir. Keycloak'ta ID-JAG üretme yeteneği yoktur; bu en net rekabet açığıdır.
4. Geri kalan her şey, yani delegasyon zinciri, yetki daraltma, ajan kaydı ve ajan claim'leri, yakınsamamıştır; en az altı rakip yaklaşım vardır.
5. **Hiçbir düzenleme bugün bir IdP'yi ajan kimliğine zorlamamaktadır.** Baskı tedarik ile ihaleden ve OWASP ile CSA taban çizgisinden gelmektedir.

### Argus için beş kritik karar

| # | Karar | Gerekçe |
|---|---|---|
| 1 | ID-JAG hem üretilir hem tüketilir | Keycloak yalnızca tüketmektedir, o da önizleme olarak; MCP EMA stabildir |
| 2 | CIMD birinci sınıf yapılır, DCR eski olarak tutulur | MCP 2026-07-28 DCR'ı kullanımdan kaldırmıştır |
| 3 | Token'da insan için `sub`, ajan için `act` ayrı olur | İkili kimlik RFC 8693'te zaten vardır |
| 4 | Bearer varsayılan yapılmaz; DPoP ile mTLS'e bağlı token birinci sınıftır | WIMSE WIT şöyle der: "MUST NOT be used as a bearer token" |
| 5 | Delegasyon zinciri için kendi imzalı yapımız kurulur, `act`'e güvenilmez | `act`, spesifikasyon gereği yetki kararı için kullanılamaz |

---

## 1. IETF OAuth çalışma grubu, süreç ve durum

### 1.0 Charter: ajan işi artık kapsam içindedir

`charter-ietf-oauth-06` 4 Haziran 2026'da onaylanmıştır.

Charter metninden birebir alıntı: "As automated agents increasingly act on behalf of users, organizations, or both, these delegation patterns become increasingly involved and complex."

Çalışma programı maddesi şudur: "Complex Delegation: Developing new mechanisms or/and extensions for authorization of automated agents working on behalf of users, including addressing scenarios where automated agents act across multiple administrative domains."

Koordinasyon maddesi WIMSE'yi açıkça saymaktadır.

Yani ajan işi OAuth çalışma grubunda meşrudur, ancak charter kabul edilmiş doküman demek değildir.

### 1.0.1 Başkanların gerçek durumu, IETF 126, Viyana, 23 ile 24 Temmuz 2026

Başkanların güncelleme slaytlarından: "We received a very large number of requests for presentation. We expect this to be the case for a few more meetings. To give your request a better chance at getting WG time: We need to see discussion on the mailing list."

Aaron Parecki ile George Fletcher'ın "Clustering of OAuth WG Work" sunumundan: "Large numbers of new individual drafts are being submitted to the working group. More than can reasonably be processed."

Önerilen dokuz küme şunlardır: Client ile Server API; Client Identity, Authentication, and Registration; Token Formats ile Types; Token Lifecycle; Security; Discovery; Proof of Possession; Same-Domain Chaining; Cross-Domain Chaining.

Dokuzuncu slayt şunu sormaktadır: "Where does the new work land? ... May need to create a new one? Complex-Delegation??"

### 1.0.2 Ölçek: 200'den fazla ajan taslağı

IETF 126'daki agentproto BoF oturumunda sunulan IETF ajan manzarası 160'tan 200'ün üzerine çıkan ajanla ilgili taslak saymaktadır. Datatracker API taramasında 60'tan fazla aktif ajan kimliği ve delegasyon taslağı bulunmuştur.

---

## 2. Aktif OAuth çalışma grubu dokümanları, Eylül 2026

| Taslak | Revizyon | Tarih | Çalışma grubu durumu |
|---|---|---|---|
| `draft-ietf-oauth-v2-1` | 16 | 3 Eylül 2026 | Kilometre taşı: Aralık 2026'da IESG'ye |
| `draft-ietf-oauth-attestation-based-client-auth` | 11 | 3 Eylül 2026 | WG Doc, yeni |
| `draft-ietf-oauth-transaction-tokens` | 11 | 30 Temmuz 2026 | WG uzlaşısı, yazım bekliyor |
| `draft-ietf-oauth-first-party-apps` | 04 | 1 Temmuz 2026 | WG uzlaşısı, yazım bekliyor |
| `draft-ietf-oauth-client-id-metadata-document` | 02 | 6 Temmuz 2026 | WG Doc |
| `draft-ietf-oauth-identity-assertion-authz-grant` | 04 | 21 Mayıs 2026 | WG Doc |
| `draft-ietf-oauth-spiffe-client-auth` | 02 | 15 Haziran 2026 | WG Doc |
| `draft-ietf-oauth-security-topics-update` | 03 | 5 Temmuz 2026 | WG Doc |
| `draft-ietf-oauth-refresh-token-expiration` | 03 | 6 Temmuz 2026 | WG Doc |
| `draft-ietf-oauth-rar-metadata-remediation` | 00 | 23 Ağustos 2026 | WG Doc, yeni kabul edilmiştir |

RFC kuyruğunda `identity-chaining-17`, `rfc7523bis-11`, `sd-jwt-vc-19` (son çağrısı 15 Eylül 2026'da bitmektedir) ile `status-list-21` bulunmaktadır. Yeni RFC'ler RFC 10017 (Browser-Based Apps BCP, Ağustos 2026) ile RFC 10027'dir (Cross-Device Flows BCP, Ağustos 2026).

### 2.1 ID-JAG, `draft-ietf-oauth-identity-assertion-authz-grant-04`

Identity Assertion JWT Authorization Grant, revizyon 04, 21 Mayıs 2026, süre bitişi 22 Kasım 2026. Yazarları A. Parecki (Okta), K. McGuinness ile B. Campbell'dır (Ping).

**Ne çözer.** Kurumsal IdP'nin, A uygulamasının B uygulamasının API'sine kullanıcı adına erişmesini merkezî politikayla yönetmesini sağlar. `draft-ietf-oauth-identity-chaining` belgesinin bir profilidir.

**Token yapısı**, birincil metinden doğrulanmıştır:

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

**Akış.** Önce IdP'nin token endpoint'ine `POST /token` yapılır; `grant_type=...token-exchange`, `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, `audience=<Resource AS issuer>` ile `subject_token=<ID Token, SAML veya Refresh Token>` gönderilir. Yanıt `{"issued_token_type":"...id-jag","access_token":"<JWT>","token_type":"N_A","expires_in":300}` biçimindedir; `token_type` değeri `N_A`'dır, çünkü bu bir bearer token değil bir grant'tır. Sonra Resource AS'in token endpoint'ine `POST /token` yapılır; `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` ile `assertion=<ID-JAG>` gönderilir. Resource AS audience kısıtlı bir access token verir.

**Keşif metadata'sı.** IdP AS tarafında `identity_chaining_requested_token_types_supported` içinde `urn:ietf:params:oauth:token-type:id-jag` bulunur. Resource AS tarafında `authorization_grant_profiles_supported` içinde `urn:ietf:params:oauth:grant-profile:id-jag` bulunur.

**Önemli sınırlama.** Spesifikasyon, token takası isteğinde opsiyonel bir `actor_token` parametresine izin vermekte ancak "this specification does not define normative processing requirements" demektedir. Güvenlik bölümü, geçerli bir `subject_token`'ı alakasız bir `actor_token` ile eşleyerek abartılı yetki elde etme riskini uyarmaktadır.

> ID-JAG bugün ajan delegasyonunu çözmemektedir; kullanıcı çoklu oturum açmasının uygulamalar arası taşınmasını çözmektedir. Ajan bağlantısı MCP EMA profili üzerinden gelmektedir.

**IdP'de implemente edilmesi gerekenler.** Token endpoint'inde `requested_token_type=...id-jag` desteği ile ID-JAG üretimi, `typ` başlığı dahil. Uygulamalar arası bağlantı politikası: `(requesting_client_id, resource_as_issuer, resource_identifier, allowed_scopes, subject_policy)`, yönetici tarafından yönetilir. Bağlantı başına `sub` eşleyicisi. Resource AS rolü: `jwt-bearer` grant'ıyla ID-JAG kabulü ve beş adımlı doğrulama. İstemci sürekliliği kontrolü: ID-JAG içindeki `client_id`, token endpoint'inde kimliği doğrulanan istemciyle eşleşmelidir; bunu atlayan implementasyonlar vardır. `jti` yeniden oynatma önbelleği, TTL'i `exp` değerine eşit olur.

Sınıflandırması bugün implemente edilmelidir.

**Ekosistem kanıtı.** IdP tarafında Okta, Ping, Descope ile Keycloak (devam etmektedir) vardır; istemcilerde Claude, VS Code ile WorkOS; kaynak uygulamalarda Slack, Notion, Figma, Linear, Asana, Datadog ile Atlassian bulunmaktadır.

**Keycloak açığı.** Keycloak 26.5 ID-JAG'ı önizleme olarak tüketebilmekte ancak üretememektedir; üretim önerisi keycloak#43971 numaralı issue'dur ve hedefi 26.7.0'dır. Bu ikincil bir kaynaktır ve GitHub'da doğrulanmamıştır.

### 2.2 MCP Enterprise-Managed Authorization, ID-JAG'ın gerçek ajan uygulaması

Statüsü stabildir ve MCP `ext-auth` deposundadır.

Spesifikasyonun kendi ifadesi şudur: "This document defines an application of the 'Identity Assertion JWT Authorization Grant' for use within enterprise deployments of the Model Context Protocol (MCP)."

Rol eşlemesi şöyledir: Client MCP istemcisidir; Resource Server MCP sunucusudur; Resource Authorization Server, MCP sunucusunun RFC 9728 PRM'sinde ilan ettiği AS'tir; IdP Authorization Server kurumsal çoklu oturum açma IdP'sidir, yani biziz.

Profil kısıtları şunlardır. `audience` değeri Resource AS'in issuer tanımlayıcısı olmalıdır (MUST). `resource` verilirse MCP sunucusunun RFC 9728 kaynak tanımlayıcısı olmalıdır (MUST). IdP, token takasında istemci kimlik doğrulamasını çoklu oturum açmadaki kadar sıkı uygulamalıdır. Ön kayıtlı değilse istemci, CIMD'sini `client_id` olarak kullanabilir.

Spesifikasyondan birebir örnek payload:

```json
{ "jti":"9e43f81b64a33f20116179", "iss":"https://acme.idp.example",
  "sub":"U019488227", "email":"user@example.com",
  "aud":"https://auth.chat.example/", "resource":"https://mcp.chat.example/",
  "client_id":"f53f191f9311af35", "exp":1311281970, "iat":1311280970,
  "scope":"chat.read chat.history" }
```

> Bu, IdP'nin bugün ne implemente etmesi gerektiği sorusunun en net cevabıdır: MCP dünyasının kurumsal yetkilendirmesi ID-JAG'dır, stabil statüdedir ve şimdi gereklidir.

### 2.3 Identity Chaining, `draft-ietf-oauth-identity-chaining-17`

Durumu IESG'ye gönderilmiş ve RFC Editor kuyruğundadır; Proposed Standard, 19 Temmuz 2026.

RFC 8693 ile RFC 7523'ü birleştirerek güven alanları arasında kimlik ve yetki taşır. ID-JAG'ın üst kümesidir. Yeni metadata alanı `identity_chaining_requested_token_types_supported`'tır.

Bugün implemente edilmelidir, çünkü RFC olmak üzeredir ve ID-JAG'ın temelidir.

### 2.4 CIMD, `draft-ietf-oauth-client-id-metadata-document-02`

Detaylar için §14'ün beşinci bölümüne bakınız.

Not olarak CIMD -02 metninde AI ajanından veya MCP'den hiç bahis yoktur; genel amaçlı bir spesifikasyondur. Ajan ekosisteminin ona bağımlılığı MCP tarafından gelmektedir.

Bugün implemente edilmelidir.

### 2.5 FiPA, `draft-ietf-oauth-first-party-apps-04`

Durumu WG uzlaşısıdır ve yazım beklemektedir; çalışma grubu son çağrısı geçilmiştir. Ajanla ilgili en olgun çalışma grubu dokümanıdır. Yazarları Parecki (Okta), Fletcher (Practical Identity) ile Kasselman'dır (Defakto).

**Ne getirir.** Authorization Challenge Endpoint'i getirir; yerel bir uygulamanın tarayıcıya gitmeden kullanıcı kimlik doğrulamasını kendi arayüzünde yürütmesini sağlar. HTTP POST ile form kodlaması kullanır ve authorization code veya hata döner. `auth_session` aynı istemci örneğinden gelen ardışık istekleri bağlayan opak bir değerdir; cihaza bağlı olmalıdır ve DPoP ile bağlanabilir. Hata kodları `invalid_session`, `insufficient_authorization` ile `redirect_to_web`'dir (HTTP 403).

**Ajan alakası.** Doğrudan bir ajan spesifikasyonu değildir, ancak tarayıcısız ve başsız istemci için resmî OAuth desenidir. Tek sayfa uygulamalarında kullanımı XSS nedeniyle önerilmemektedir.

Arayüzü hazırlanmalıdır.

### 2.6 Token Exchange (RFC 8693) ile `act`, delegasyonun zayıf halkası

Yapısal zaaf spesifikasyonun kendi ifadesindedir, §4.1: tüketiciler yalnızca üst düzey claim'lere ve `act` ile tanımlanan mevcut aktöre bakmalıdır; önceki aktörler yalnızca bilgilendiricidir ve erişim kontrolü kararlarında dikkate alınmamalıdır.

> `act` bir denetim izidir, yetki kanıtı değildir. Bu tasarım gereğidir.

**Delegation Chain Splicing saldırısı.** IETF OAuth posta listesindeki "Security Consideration: Delegation Chain Splicing in RFC 8693 Token Exchange" başlıklı konu doğrulanmıştır; başlatan `cbchhaya`, 27 Şubat 2026, tartışma Mart 2026 boyunca sürmüştür.

Mekanizması şöyledir: ele geçirilmiş bir aracı, farklı delegasyon bağlamlarından bir `subject_token` ile bir `actor_token` sunar. Güvenlik token servisi her ikisini bağımsız doğrular, geçerli bulur ve hiç gerçekleşmemiş bir zinciri iddia eden, usulüne uygun imzalanmış bir token üretir.

Kök neden şudur: RFC 8693 iki token arasında çapraz doğrulama zorunlu kılmamaktadır.

Önerilen azaltma posta listesindendir, spesifikasyondan değildir: `aud[N] == sub[N+1]` kriptografik eşleşmesi, kısa TTL ve arka kanal iptali.

Birincil mesaj gövdesine erişilememiştir, çünkü mail-archive.com bloke olmuştur. Mekanizma açıklaması ikincil bir kaynaktandır; WorkOS, 27 Nisan 2026. Doğrulama kısmidir.

**Çözüm taslakları**, hepsi bireyseldir ve hiçbiri kabul edilmemiştir.

| Taslak | Revizyon ve tarih | Yaklaşım |
|---|---|---|
| `draft-liu-oauth-chain-delegation` | 00, 8 Haziran 2026 | `delegation_chain` claim'i; çift imza (`as_signature` ile `delegator_signature`), ayrık JWS ile JCS (RFC 8785); `record[i].delegator_id == record[i-1].delegatee_id`; en fazla beş sıçrama. Yazarları Dapeng Liu, Judy Zhu, Suresh Krishnan ile Aaron Parecki'dir |
| `draft-mcguinness-oauth-actor-profile` | 00, 30 Nisan 2026 | `act` için tutarlı bir profil: `sub` yetkilendirendir, en dıştaki `act.sub` doğrudan aktördür, kanonik aktör kimliği `(act.iss, act.sub)` ikilisidir. Asgari derinlik dörttür. İki sunucu geçiş modu vardır: continuation ile rebind |
| `draft-asor-wimse-agent-delegation-chain` | 01, 3 Eylül 2026 | Ed25519, ES256 ile ML-DSA; `del_depth`, `del_max_depth`, ebeveynin SHA-256'sı olan `par_hash` ve `cnf`. Sekiz adımlı çevrimdışı doğrulama yapılır, AS'e temas edilmez |
| `draft-niyikiza-oauth-attenuating-agent-tokens` | 01, 15 Haziran 2026 | Macaroon ile biscuit ilhamlıdır ancak asimetriktir. Altı değişmez (I1 ile I6 arası), sekiz kısıt tipi ve kapalı dünya modu vardır |
| `draft-hamr-oauth-agent-delegation` | 01, 2 Eylül 2026 | `Agent-Delegation` HTTP başlığı kullanır. Scope kapsaması, taban gevşetmeme ve süre uzatmama kuralları vardır. RFC 9421 HTTP Message Signatures zorunludur |
| `draft-li-oauth-delegated-authorization` | 03, 24 Temmuz 2026 | `cnf.jkt` ile anahtar bağlama; istemci kendi özel anahtarıyla çocuk token imzalar ve AS'e gitmez; DPoP zorunludur. Huawei kaynaklıdır |
| `draft-mcguinness-oauth-mission` | 00, 6 Temmuz 2026 | Mission, onaylanmış göreve bağlı dayanıklı bir yetkilendirme artefaktıdır; `intent_hash` ile `authority_hash` taşır |

**Yorum.** Bu, sağlıklı bir standartlaşma değildir; aynı problemin yedi rakip çözümüdür. En güçlü adaylar `draft-mcguinness-oauth-actor-profile` ile `draft-liu-oauth-chain-delegation`'dır; yazar ağırlığı ve `act` uyumu bunu getirmektedir.

Arayüzü hazırlanmalı ve kendi güvenli üst kümemiz kurulmalıdır. Somut öneri şudur: `act` RFC 8693 uyumlu üretilir, bu interop içindir; ek olarak `delegation_chain` alanı `draft-liu` biçiminde imzalı üretilir. `draft-mcguinness-oauth-actor-profile`'ın üç değişmezi bugünden benimsenir.

### 2.7 Transaction Tokens, `draft-ietf-oauth-transaction-tokens-11`

Durumu WG uzlaşısıdır ve yazım beklemektedir; üçüncü bir çalışma grubu son çağrısı planlanmıştır.

Başlığı `typ: txntoken+jwt`'dir. Claim'leri `txn`, `sub`, `aud` (güven alanı tanımlayıcısıdır ve alanlar arası kullanımı engeller), `scope`, değişmez işlem bağlamı olan `tctx`, istek bağlamı olan `rctx` ile isteyen iş yükünün kimliği olan `req_wl`'dir. Transaction Token Service, RFC 8693 ile `requested_token_type=urn:ietf:params:oauth:token-type:txn_token` kullanır. HTTP taşımasında `Txn-Token` adlı özel bir başlık kullanılır.

Ajan alakası şudur: bir ajan görevinin mikroservis zinciri boyunca daraltılmış ve göreve bağlı yetkiyi taşımasını sağlar.

Arayüzü hazırlanmalıdır.

### 2.8 Attestation tabanlı istemci kimlik doğrulaması, revizyon 11, 3 Eylül 2026

Client Attestation JWT, Client Attester'dan gelen ve örneğin anahtarına bağlı imzalı bir beyandır. Client Attestation PoP JWT, örneğin o anahtarla ürettiği sahiplik kanıtıdır. Başlıkları `OAuth-Client-Attestation`, `OAuth-Client-Attestation-PoP` ile `OAuth-Client-Attestation-Challenge`'tır. Claim'leri `cnf`, `sub`, `aud` ile opsiyonel `challenge`'tır.

DPoP birleşik modu şöyle tanımlanmıştır: "the Client Instance Key and the DPoP Key are the same asymmetric key pair". Yani tek bir DPoP kanıtı hem attestation hem gönderici kısıtlaması görevi görür.

> **Doğru mimari desen.** Donanım attestation'ı kayıt anında bir kez anahtarın donanımda yaşadığını kanıtlar; sonra her istekte DPoP kanıtı o anahtarın kullanıldığını kanıtlar.

DPoP çevresindeki bireysel taslakların neredeyse hepsi süresi dolmuş durumdayken tek canlı standartlaşma çalışması budur.

Arayüzü hazırlanmalıdır.

### 2.9 SPIFFE istemci kimlik doğrulaması, `draft-ietf-oauth-spiffe-client-auth-02`

Yazarları Arndt Schwenkschuster, Pieter Kasselman, Scott Rose (NIST), Stian Thorgersen (IBM, Keycloak kurucusu) ile Nancy Cam-Winget'tir (Cisco).

Üç SVID kimlik doğrulama yöntemi vardır. JWT-SVID, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` kullanır. X.509-SVID mTLS kullanır ve SPIFFE kimliği sertifikanın SAN URI alanındadır. WIT-SVID, WIMSE Workload Identity Token ile Client Attestation PoP JWT kullanır.

Anahtar dağıtımında SPIFFE Bundle Endpoint zorunludur; HTTPS üzerinden JWKS ve WebPKI kullanılır.

Implementasyon durumunda Keycloak listelenmektedir.

Bugün implemente edilmelidir. Stian Thorgersen'ın yazar olması, Keycloak'ın bunu ciddiye aldığının kanıtıdır.

### 2.10 Diğer çalışma grubu dokümanları

`draft-ietf-oauth-refresh-token-expiration-03` (Nick Watson, Google) `refresh_token_timeout` ile `authorization_expires_in` alanlarını getirir: "The refresh token MUST NOT expire later than the user authorization expires." Uzun süren ajan görevleri için doğrudan alakalıdır ve arayüzü hazırlanmalıdır.

`draft-ietf-oauth-rar-metadata-remediation-00` (Yaron Zehavi, RBI) `authorization_details_types_metadata_endpoint` alanını, `insufficient_authorization` hata kodunu ve `authorization_remediation` mekanizmasını getirir. Ajanın hangi `authorization_details` değerini istemesi gerektiğini keşfetmesi içindir ve arayüzü hazırlanmalıdır.

`draft-ietf-oauth-v2-1-16`'nın kilometre taşı Aralık 2026'da IESG'ye gitmektir. MCP spesifikasyonu hâlâ `draft-13`'e referans vermektedir, yani üç revizyon geridedir.

---

## 3. Ajana özgü bireysel taslaklar, zoo haritası

Hiçbiri çalışma grubu dokümanı değildir. Ajan kimliği ve yetkilendirmesiyle doğrudan ilgili en az 30 aktif taslak vardır.

### 3.1 `draft-klrc-aiagent-auth-03`, AIMS

6 Temmuz 2026 tarihli bireysel bir internet taslağıdır. Yazarları Pieter Kasselman (Defakto), Jeff Lombardo (AWS), Yaroslav Rosomakho (Zscaler), Brian Campbell (Ping), Nick Steele (OpenAI) ile Aaron Parecki'dir (Okta).

Bu, endüstri uzlaşısının nereye gittiğinin en güçlü göstergesidir. Yeni bir protokol icat etmemekte, WIMSE ile OAuth ve SPIFFE'i birleştirmektedir.

AIMS, yani Agent Identity Management System, bir ajan iş yükünün kimliğini ve izinlerini tesis etmek, sürdürmek ve değerlendirmek için gereken fonksiyonlar kümesini tanımlayan kavramsal modeldir. Yedi bileşeni vardır: ajan tanımlayıcıları, kimlik bilgileri, sağlama, kimlik doğrulama, yetkilendirme, gözlemlenebilirlik ile düzeltme ve uyum ölçümü.

Ham metinden birebir alıntılar şunlardır.

> "The Large Language Model MUST NOT have access to an agent's credentials or to credentials that may be needed to access tools and services. This prevents the Large Language Model from using, exposing, or being manipulated via prompt injection into disclosing the credentials." (§8, satır 540)

> "An identifier alone is insufficient unless it can be verified to be controlled by the communicating agent through a cryptographic binding."

Döngüde insan bölümü, yani §10.7, bizim için en değerli kısımdır.

> "An Agent, acting as an OAuth client, can use the OpenID Client Initiated Backchannel Authentication (CIBA) protocol. This triggers an out-of-band interaction allowing the user to approve or deny the requested operation without exposing credentials to the agent."

> "Such interactions do not by themselves constitute authorization and MUST be bound to a verifiable authorization grant issued by the authorization server... the agent MUST NOT treat local UI confirmation alone as sufficient authorization."

> "Note: Additional specification or design work may be needed... CIBA itself only accounts for client initiation, which doesn't map well to cases that envision the need for User confirmation to occur mid-execution."

> Bu, ajan görevinin ortasında insan onayı probleminin resmî kabulüdür. CIBA yetmemektedir ve bu açık bir problemdir.

Agent Mission, yani §10.1, şunu söyler: ajan bir Mission alır ve bu genelde doğal dildedir. Mission'ın yetkilendirme gereksinimlerine çevrilmesi spesifikasyon kapsamı dışındadır.

Yetkilendirme senaryoları, yani §10.4, üç tanedir: kullanıcının yetkilendirmeyi devretmesi, oltalamaya dirençli kimlik doğrulamayla authorization code grant'ı kullanılarak; ajanın kendi yetkilendirmesini alması, client credentials veya JWT grant'ıyla; ajanlara sistemler veya diğer ajanlar tarafından erişilmesi.

> **Önemli düzeltme.** Çift kimlik kimlik bilgisi ile üç delegasyon akışı bu belgede değildir; grep ile doğrulanmıştır. Bunlar ayrı bir belgeye aittir ve aşağıda ele alınmaktadır.

### 3.2 `draft-ni-wimse-ai-agent-identity-02`, ikili kimlik

28 Şubat 2026 tarihli ve Huawei kaynaklıdır. Süre bitişi 1 Eylül 2026'dır, yani şu an süresi dolmuştur.

Dual-Identity Credential, ajanın kimliğini sahibinin kimliğine kriptografik olarak bağlayan bir kimlik bilgisidir.

Üç bağlama modeli vardır.

| Model | Mekanizma | Saldırı yüzeyi |
|---|---|---|
| Ajan aracılı, sahip tarafından önceden imzalı | Sahip, ajanın kimlik bilgisi isteğini gönderilmeden önce yerel olarak imzalar. Çevrimdışı onay, FIDO veya HSM kullanılır | Ele geçirilmiş imzalama anahtarları |
| Sahip aracılı, ağ geçidi modu | Sahip, vekil ile sunucu arasında denetleyici bir aracıdır | Tek hata noktasıdır; hizmet reddine açıktır |
| Sunucu aracılı, meydan okuma ve yanıt | Kimlik sunucusu, sahibi bant dışı bir kanalla doğrudan arayarak bağlamayı orkestre eder | Bant dışı kanal güvenliği ile yeniden oynatma |

> **Argus için doğrudan eşleme.** Ajan aracılı model sahip beyanıdır, yani sahip anahtarıyla imzalı JWT veya WebAuthn. Sahip aracılı model yönetim konsolu ile politika motorudur. Sunucu aracılı model tam olarak CIBA'dır. Bu üçü ayrı akışlar olarak desteklenmeli ve böyle konumlandırılmalıdır.

Akademik eleştiri şudur: WIMSE Dual-Identity Credential'ı tanıtmakta, iki taraflı etkileşimleri çözmekte ancak çok sıçramalı delegasyonu çözmemektedir.

### 3.3 McGuinness serisi, en tutarlı tasarım kümesi

Karl McGuinness, bağımsız olarak ve Okta'nın eski teknoloji direktörü sıfatıyla tek başına bir spesifikasyon ailesi yazmaktadır.

| Taslak | Revizyon ve tarih | İçerik |
|---|---|---|
| `draft-mora-oauth-entity-profiles` | 01, 15 Nisan 2026 | `client_profile` ile `sub_profile` claim'leri. Yedi kayıtlı değer: `user`, `device`, `native_app`, `web_app`, `browser_app`, `service` ile `ai_agent`. AS metadata alanı `entity_profiles_supported`'tır. Yazarları Mora, Pamela Dingle (Microsoft) ile McGuinness'tir |
| `draft-mcguinness-oauth-actor-profile` | 00, 30 Nisan 2026 | 2.6'da ele alınmıştır |
| `draft-mcguinness-oauth-client-instance-assertion` | 01, 23 Haziran 2026 | Client Instance Assertion, bir OAuth istemcisinin somut çalışma zamanı örneğini tanımlayan imzalı bir JWT'dir |
| `draft-mcguinness-oauth-ai-agent-instance` | 00, 4 Temmuz 2026 | AI Agent Instance Profile. Problem şöyle konmuştur: "every agent session collapses into one identity, defeating per-agent authorization, audit attribution, incident response, and abuse containment." Claim'leri zorunlu `agent_instance_id`, `agent_platform`, `agent_model` ile EAT biçiminde `agent_runtime`'dır. `sub_profile` her zaman `["ai_agent","client_instance"]` olur |
| `draft-mcguinness-oauth-mission` | 00, 6 Temmuz 2026 | Mission claim'i ile `intent_hash` |
| `draft-mcguinness-oauth-id-continuation-assertion` | 01, 26 Ağustos 2026 | Identity Continuation Assertion, kullanıcı gittikten sonra kimlik yayılımını sağlar. Kısa ömürlüdür, en fazla 300 saniyedir; göndericiye kısıtlıdır, yani DPoP kullanır; tek kullanımlıktır ve yeniden oynatma tespiti vardır |
| `draft-mcguinness-oauth-token-exchange-cnf` | 00, 19 Temmuz 2026 | Token takası için `cnf` yanıt parametresi |
| `draft-mcguinness-oauth-rfc9728bis` | 01, 28 Ağustos 2026 | PRM kaynak tanımlayıcısı doğrulaması |

> Bu set, ajan kimliğinin doğru tasarımı hakkında en tutarlı görüşü sunmaktadır: `sub` insandır, `act` ajandır, `agent_instance_id` çalışan kopyadır, mission görev sınırıdır ve `sub_profile` varlık tipidir.

`sub_profile: "ai_agent"` ile `agent_instance_id` bugünden token'a konur; maliyeti sıfıra yakındır ve arayüzü hazırlanmalıdır.

### 3.4 Diğer dikkat çeken taslaklar

| Taslak | Revizyon ve tarih | Özet |
|---|---|---|
| `draft-chen-oauth-agent-authz-use-cases` | 03, 25 Ağustos 2026 | Boşluk analizidir; kabul istenmiş ancak başkanlar erken bulmuştur. On bir kullanım senaryosu vardır. Üç boşluk tanımlar: yetkilendirme bağlamı boşluğu, yani kullanıcının talimatı ile ajanın izin isteği arasındaki zamansal kopukluk; delegasyon zinciri boşluğu; toplu iptal boşluğu |
| `draft-carleton-workload-authz-grant` | 00, 3 Ağustos 2026 | Paul Carleton, Anthropic. AIMS profilidir ve müşteri başına birden çok ajan örneği barındıran platformlar içindir: "Trust in the platform's issuer is established once, by reference, and thereafter agents are accepted on first presentation with no per-agent registration step." |
| `draft-liu-ai-agent-authorization-integration` | 00, 6 Temmuz 2026 | Alibaba, Cisco ile Okta'dan Parecki. Altı uzantıyı entegre eder: SPIFFE istemci kimlik doğrulaması, ID-JAG, JWT Grant Interaction Response, RAR üzerinden Rego politikası, Authorization Evidence ile Delegation Chain |
| `draft-parecki-oauth-jwt-grant-interaction-response` | 00, 25 Mart 2026 | Döngüde insan için en temiz mekanizmadır: `{"error":"interaction_required","interaction_uri":"https://...","interval":5,"expires_in":600}`. İki tamamlama yolu vardır: yoklama veya sinyal yönlendirmesi ("No authorization code or other parameters are included") |
| `draft-rosomakho-oauth-txn-challenge` | 00, 25 Haziran 2026 | OAuth Transaction Authorization Challenge. Korunan kaynak imzalı bir JWT challenge üretir, istemci bunu AS'e taşır ve AS onay alıp o işleme bağlı kapsamlı bir token verir: "useful when requests are mediated by agents, automated workflows, or delegated services" |
| `draft-gerber-oauth-deferred-token-response` | 00, 23 Haziran 2026 | Deferred Token Response. `completion_mode=deferred` gönderildiğinde `400 authorization_pending` ile `deferral_code` ve saatler veya günler süren `expires_in` dönülür. Erteleme kodu göndericiye kısıtlı olmalıdır |
| `draft-zhu-oauth-async-delegation` | 05, 3 Ağustos 2026 | Delegated Refresh Tokens, Atlassian kaynaklıdır. Mutlak delegasyon son tarihi ile göreve kapsamlı iptal getirir |
| `draft-jia-oauth-scope-aggregation` | 01, 14 Ağustos 2026 | Çok adımlı ajan iş akışlarında scope'ları önden toplamayı ele alır. Riskleri artık ayrıcalık ile kullanıcının kör imzalamasıdır |
| `draft-gazitt-oauth-authzen-token-exchange` | 01, 2 Eylül 2026 | AuthZEN'i RFC 8693'e bağlar. İki ayrı değerlendirme yapar: özne kapısı ile isteyen taraf kapısı |
| `draft-abbey-scim-agent-extension` | 00, 16 Ekim 2025 | SCIM Agents Extension. Macy Abbey ile Rafael S. Cohen (Okta). `/Agents` ile `/AgenticApplications` uç noktalarını getirir. Nitelikleri `agentType`, `owners`, `roles`, `protocols` (OpenAPI, A2A, MCP-Server), `x509Certificates` ile OIDC `sub` korelasyonu sağlayan `subject`'tir |
| `draft-sharif-openid-agent-identity` | 01, 27 Ağustos 2026 | On ajan claim'i tanımlar: `agent_trust_score` (0 ile 100 arası), `agent_trust_level` (L0 ile L4 arası), `agent_spend_limit` ve diğerleri. Tek yazarlıdır ve spekülatiftir |
| `draft-drake-agent-identity-registry` | 03, 22 Mayıs 2026 | Federe bir kayıt defteridir ve donanıma çapalıdır: TPM 2.0, PIV veya enclave ile beş güven katmanı. Kimlik kalıcıdır ve iptal edilemez. Tek yazarlıdır ve spekülatiftir |
| `draft-mishra-oauth-agent-grants`, yani DAAP | 02, 30 Ağustos 2026 | PAR zorunludur, PKCE S256 kullanılır, kimliği doğrulanmış insan onayı gerekir ve bu bir politika motoruyla ikame edilemez; DPoP veya mTLS kullanılır |

---

## 4. IETF WIMSE çalışma grubu

| Taslak | Revizyon | Tarih | Durum |
|---|---|---|---|
| `draft-ietf-wimse-arch` | 08 | 6 Temmuz 2026 | WG Doc, 33 sayfa |
| `draft-ietf-wimse-http-signature` | 06 | 4 Ağustos 2026 | WG Doc |
| `draft-ietf-wimse-identifier` | 03 | 6 Temmuz 2026 | WG Doc |
| `draft-ietf-wimse-mutual-tls` | 02 | 6 Temmuz 2026 | WG Doc |
| `draft-ietf-wimse-workload-creds` | 02 | 2 Temmuz 2026 | WG Doc, 27 sayfa |
| `draft-ietf-wimse-wpt` | 02 | 27 Ağustos 2026 | WG Doc, yeni |
| `draft-ietf-wimse-workload-identity-practices` | 06 | 11 Ağustos 2026 | Alan direktörü değerlendirmesinde; Informational RFC olacaktır |

WIMSE'den henüz hiç RFC çıkmamıştır.

### 4.1 WIT, Workload Identity Token

Ham metinden birebir: "The workload MUST prove possession of the corresponding private key when presenting the WIT to another party. As such, it MUST NOT be used as a bearer token and is not intended for use in the Authorization header."

JOSE başlığında `alg` asimetriktir ve asla `none` olmaz; `typ` değeri `wit+jwt`'dir. Claim'leri `sub` (WIMSE iş yükü tanımlayıcısı URI'si), `exp`, `cnf` (public key, `jwk` biçiminde; `jwk` içinde `alg` zorunludur), `iss` ile `jti`'dir. Ayrı HTTP başlıkları kullanılır, `Authorization` kullanılmaz.

Bearer geçiş stratejisi §5.3'tedir: WIT yeni başlıklar tanımladığı için bearer JWT başlıklarıyla birlikte sunulabilir. Uyarısı şudur: "the decision which token to prefer is made when the caller's identity has still not been authenticated, and needs to be revalidated following the authentication step."

### 4.2 WPT, Workload Proof Token

27 Ağustos 2026 tarihlidir; yazarları Brian Campbell (Ping) ile Arndt Schwenkschuster'dır (Defakto).

`typ` değeri `application/wpt+jwt`'dir ve `alg`, WIT'in `cnf` anahtarıyla eşleşmelidir. Claim'leri `aud` (HTTP hedef URI'si), `exp`, `jti`, WIT'in base64url SHA-256'sı olan `wth`, işlem token'ının hash'i olan `tth` ile `oth`'tur. Taşımada yeni bir `WPT` kimlik doğrulama şeması kullanılır; hata durumunda 401 ile `WWW-Authenticate: WPT` dönülür.

### 4.3 İş yükü tanımlayıcısı

URI tabanlıdır: `spiffe://trust-domain/service` ile yeni kaydedilen `wimse://<trust-domain>/<path>`. Yasaklar sorgu dizesi, fragment, userinfo ile porttur. 2048 bayta kadar olabilir ve tam URI karşılaştırması yapılır. Spesifikasyon şunu söyler: "Identifiers require cryptographic credential context to be considered authenticated".

### 4.4 WIMSE mimarisi, AI ajanları açıkça ele alınmaktadır

§3.4.11 AI aracılarını delegasyonlu iş yüklerinin özel bir hâli olarak konumlandırmaktadır. Açıkça yetkilendirilmedikçe upstream güvenlik bağlamı yayılmalıdır. Otonom eylemler delegasyonlu olanlardan ayrı kimliklerle ayrılmalıdır. Metin "cryptographic binding of delegation tokens or attestation" demektedir. Çok ajanlı zincirlerde her sıçramada güvenlik bağlamı yeniden bağlanmalıdır.

Sınıflandırma şöyledir. WIT ile WPT için arayüz hazırlanmalıdır; henüz RFC yoktur ancak yön nettir, bearer ölmektedir. İş yükü tanımlayıcısı şeması bugün benimsenmelidir: ajanlara opak UUID yerine `spiffe://` veya `wimse://` tarzı hiyerarşik URI kimlikler verilir, çünkü politika yazımı, örneğin `spiffe://acme.example/agent/finance/*`, muazzam kolaylaşır. SPIFFE istemci kimlik doğrulaması bugün yapılmalıdır.

### 4.5 WIMSE'deki ajan delegasyon taslakları

| Taslak | Revizyon ve tarih | İçerik |
|---|---|---|
| `draft-reece-wimse-cross-org-delegation` | 02, 31 Ağustos 2026 | Problem tanımı ile gereksinimler. Yedi problem sayar: özyinelemeli delegasyon, organizasyon sınırları, çevrimdışı doğrulama, principal bağlama, iptal ile tazelik, birleştirilebilir denetim ve çalıştırma anında insan yetkilendirmesi. On gereksinim tanımlar |
| `draft-asor-wimse-agent-delegation-chain` | 01, 3 Eylül 2026 | 2.6'da ele alınmıştır |
| `draft-sweeney-wimse-credential-delegation` | 00, 3 Eylül 2026 | İçeriği incelenmemiştir ve doğrulanmamıştır |
| `draft-rampalli-cross-org-delegation-mapping` | 05, 6 Temmuz 2026 | Katmanlı gereksinim eşlemesi |

IETF 126 WIMSE oturumunda AIMS, "Heterogeneous Credential Verification", "PEDIGREE: per-hop delegation", "Offline workload access for user-owned resources without refresh tokens" ile "SOOS: Mandate JWT & Cross-Principal Transaction ID (XPID)" sunulmuştur.

---

## 5. agentproto BoF, yeni bir çalışma grubu doğuyor ancak henüz yok

IETF 126, Viyana, 23 Temmuz 2026'da çalışma grubu kurmaya yönelik bir BoF oturumu yapılmıştır.

Oda anketi sonuçları şöyledir.

| Soru | Evet | Hayır |
|---|---|---|
| IETF doğru mekân mıdır | 158 | — |
| Net bir interop ihtiyacı var mıdır | 155 | — |
| Çalışma grubu kurulsun mu | 154 | 51 |
| Mevcut kapsam doğru mudur | 38 | 124 |

Kimlik ve yetkilendirme tartışması çekişmeli geçmiştir. Öne çıkan endişeler dayanıklı sahiplik problemi (kimlik bilgileri çalışma zamanı tabanlıyken ve oturumlar sona ererken ajan eylemlerinden sorumlu tarafın nasıl tanımlanacağı), yetki daraltma ile delegasyon mekanizmalarıdır.

Sonuç olarak grup kimlik ile yetkilendirmeyi mevcut çalışmalara, yani WIMSE ile OAuth'a yönlendirmiş ve yeni iş yaratmamıştır. Eylül 2026 itibarıyla henüz charter'lanmamıştır.

Ayrıca reddedilen bir BoF vardır: `bofreq-kuhlewind-agent-use-of-delegation-and-interaction-traceability-audit`, yani AUDIT. Önericileri Mirja Kühlewind, Henk Birkholz ile Pam Dingle'dır. Kapsamı dağıtık denetim için birlikte çalışabilir protokol mekanizmaları ile RATS ve SCITT profillemesidir. Durumu reddedilmiştir.

> Ajan denetlenebilirliği, yani inkâr edilemezlik, IETF'te henüz mekân bulamamıştır.

---

## 6. MCP ve A2A

### 6.1 MCP yetkilendirmesi, revizyon 2026-07-28

Detaylar için §14'e bakınız. Bu tamamen bugünkü iştir; MCP yerlisi olmak bu IdP'nin pazara giriş kancasıdır.

### 6.2 A2A protokolü

Linux Foundation yönetimindedir. v1.0 tarihi çelişkilidir: site Ağustos 2026, blog duyurusu 12 Mart 2026 demektedir ve kesin genel kullanım tarihi doğrulanamamıştır. 27 Ağustos 2026'da Agentic AI Foundation'a katıldığı bilgisi vardır.

Agent Card, yani `/.well-known/agent-card.json`, zorunlu `id`, `name` ile `interfaces[]` alanlarını taşır. `securitySchemes` alanı `map<string, SecurityScheme>` tipindedir ve OpenAPI 3 ile birebir aynı şekildedir. `security` alanı beceri bazında granülerlik sağlar. `signature` alanı bir `AgentCardSignature` taşır.

SecurityScheme tipleri `apiKey`, `http`, `oauth2`, `openIdConnect` ile `mutualTls`'tir. OAuth akışları `authorizationCode`, `clientCredentials` ile `deviceCode`'dur; `implicit` ile `password` yoktur, yani OAuth 2.1 uyumludur. İmzalı ajan kartları RFC 8785 JCS ile kanonikleştirilip JWS ile imzalanır. Döngüde insan için `TASK_STATE_INPUT_REQUIRED` ile `TASK_STATE_AUTH_REQUIRED` durumları vardır, ancak onayın nasıl toplanacağı ve işleme nasıl kriptografik bağlanacağı tanımsızdır.

> **Kritik boşluk.** A2A spesifikasyonunda SPIFFE ile SPIRE geçmemektedir. `mutualTls` vardır ancak sertifikadaki SPIFFE kimliğinin ajan kimliğine nasıl bağlanacağına dair normatif bir kural yoktur.

MCP ile temel fark şudur: A2A yetkilendirme şemasını ajanın kendi kartında bildirimsel olarak tanımlar; MCP ise OAuth keşif zincirini zorunlu kılar. MCP'nin modeli daha katı ve daha OAuth yerlisidir.

A2A bir IdP protokolü değildir; bizim işimiz onun `securitySchemes` alanında görünmektir ve arayüzü hazırlanmalıdır. Somut olarak `openIdConnectUrl` keşfi, `deviceCode`, `clientCredentials`, `authorizationCode` ile RFC 8705 mTLS'e bağlı token desteklenir; sonuncusunda SAN URI'sinden SPIFFE kimliği çıkarılır. Bu son madde A2A ile SPIFFE arasındaki boşluğu doldurur ve kimsenin yapmadığı bir şeydir.

---

## 7. Endüstri, teknik karşılaştırma

### 7.1 Microsoft Entra Agent ID

Nisan 2026'da genel kullanıma açılmıştır.

| Kavram | Tanım |
|---|---|
| Agent identity | Özel bir service principal'dır ve kendi kimlik bilgisi yoktur |
| Agent identity blueprint | Yeniden kullanılabilir bir şablondur; kimlik bilgilerini blueprint tutar |
| Blueprint principal | Blueprint kiracıya eklendiğinde oluşan Entra nesnesidir; asıl token alan ve denetim kaydında görünen odur |
| Sponsor | Ajandan sorumlu insan kullanıcı veya gruptur |
| Ajanın kullanıcı hesabı | Opsiyoneldir, birebirdir ve gerçek bir kullanıcı nesnesi gerektiren sistemler içindir |

Token davranışı dokümanlardan birebir şöyledir: "Request agent tokens... The subject of the access token is the agent identity." ve "Request user tokens for an authenticated user. The subject of the token is a user, while the actor is the agent identity."

> Microsoft, `sub` kullanıcı ile `actor` ajan modelini üretimde kullanmaktadır ve bu RFC 8693 `act` semantiğiyle örtüşmektedir.

Tasarım deseni derslerinden doğrudan uygulanabilir olanlar şunlardır. Ölçeklenen replikalar ayrı bir ajan kimliği gerektirmez: "Creating a separate agent identity per replica adds directory objects and management overhead without any audit, access control, or accountability benefit." Bellek ile bağlam yönetimi ayrı kimlik gerektirmez; oturum kimliğiyle filtreleme yeterlidir. Yüksek hacimli ve nesne başına ajan kimliği pratik değildir: "use shared agent identities and rely on session or context identifiers at the application layer". Geçici ajan kimliği varyantı vardır ancak deterministik olmayan gecikme uyarısı taşır.

Standartlaşma tarafında durum sıfırdır: Entra Agent ID tamamen tescilli bir Graph modelidir. ID-JAG, MCP EMA veya WIMSE desteği dokümanlarda bulunamamış ve doğrulanamamıştır.

### 7.2 Okta

Okta for AI Agents 30 Nisan 2026'da genel kullanıma açılmıştır ve ayrı ücretli bir üründür; ajan keşfi ile kaydı Universal Directory'de yapılır, Privileged Credential Management ile Universal Logout for AI Agents sunulur. Agent SSO 24 Ağustos 2026'da genel kullanıma açılmıştır ve çekirdek SSO planlarına dahildir, ek ücret alınmaz.

Üretim kanıtı olarak Atlassian Rovo MCP, XAA ile ID-JAG üzerinden 29 Haziran 2026'da canlıya çıkmıştır. Doğrulama adımları şunlardır: imza ile issuer JWKS'ten doğrulanır; `typ` değerinin `oauth-id-jag+jwt` olduğu kontrol edilir; `aud` bizi göstermelidir; istemci sürekliliği doğrulanır; `exp`, `iat` ile `jti` tekilliği kontrol edilir.

### 7.3 Auth0

Auth0 for AI Agents 19 Kasım 2025'te, Auth for MCP 6 Mayıs 2026'da genel kullanıma açılmıştır. Dört bileşeni vardır: kullanıcı kimlik doğrulaması, Token Vault, CIBA tabanlı asenkron yetkilendirme ile RAG için ince taneli yetkilendirme.

Token Vault RFC 8693 tabanlıdır ancak tescilli URN'ler kullanır:

```
grant_type=urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token
subject_token=<AUTH0_REFRESH_TOKEN>
requested_token_type=http://auth0.com/oauth/token-type/federated-connection-access-token
connection=google-oauth2
```

Saklama birimi tokenset'tir; her kullanıcı ve bağlantı çifti için bir konteynerdir. Ajan hiçbir zaman üçüncü taraf refresh token'a dokunmaz. Otuz beşten fazla sağlayıcı desteklenir.

CIBA ile RAR kombinasyonu en öğretici kısımdır:

```
POST /bc-authorize
login_hint={"format":"iss_sub","iss":"https://{tenant}/","sub":"{USER_ID}"}
binding_message=Confirm payment of 2500
authorization_details=[{"type":"money_transfer","instructedAmount":{"amount":2500,"currency":"USD"},
  "sourceAccount":"...1234","destinationAccount":"...9876","beneficiary":"Hanna Herwitz"}]
```

Kritik nokta şudur: onay verilince `authorization_details` dizisi access token içinde aynen taşınır ve kaynak sunucusu neyin onaylandığını token'dan doğrulayabilir.

### 7.4 Descope Agentic Identity Hub

Hub 2.0 Ocak 2026'da çıkmıştır. Veri modeli en kopyalanmaya değer olandır ve iki eksenlidir.

Resources, yani gelen yön, korunan API'ler ile MCP sunucularıdır; audience URL'i ile scope'lar taşır ve kısa ömürlü, scope sınırlı token verir. Connections, yani giden yön, downstream servisler için bir kimlik bilgisi kasasıdır ve uzun ömürlü üçüncü taraf kimlik bilgilerini yönetir. Önerilen desen ajandan Resource'a, oradan Connection kasasına gitmektir; ajan asla kasaya doğrudan erişmez.

İstemci kaydı dört yolla yapılır: ön kayıt, bulut iş yükü OIDC token'ları (AWS ile GCP), DCR ile CIMD.

### 7.5 SPIFFE ve SPIRE, mevcut durum ve sınırlar

JWT-SVID kuralları şunlardır: `sub` iş yükünün SPIFFE kimliği olmalıdır; `aud` bulunmalıdır ve doğrulayıcı kendi tanımlayıcısını bulamazsa reddeder; `exp` zorunludur ve `exp` içermeyen token reddedilmelidir; anahtar keşfi SPIFFE bundle'ındaki RFC 7517 JWK ile yapılır ve `use` değeri `jwt-svid` olur.

WIT-SVID, SPIFFE spesifikasyon setinde kuluçka aşamasındadır ve JWT-SVID'in aday halefidir.

| | JWT-SVID | WIT-SVID |
|---|---|---|
| Tip | Bearer | Sahiplik kanıtı |
| `cnf` | Yoktur | Zorunludur |
| `aud` | Zorunludur | Yasaktır |

SPIFFE'in ajanlar için sınırları dörttür. SPIRE adanmış altyapı ister ve çoğu ajan dağıtımı için ağırdır. X.509 üretim gecikmesi geçici ajan yaratımıyla uyumsuzdur. Protokoller arası kimlik akışı yoktur. Delegasyonu hiç modellemez; bu süreç nedir sorusunu çözer, kimin adına sorusunu çözmez.

> **Doğru mimari.** SPIFFE birinci katmandır ve bu sürecin kim olduğunu söyler. Argus ikinci katmandır ve kimin adına, ne yetkiyle sorusunu cevaplar. Akış SVID'den token takasına, oradan delegasyon taşıyan access token'a gider.

### 7.6 OpenID Foundation

AIIM topluluk grubunu OIDF yönetim kurulu Nisan 2025'te görevlendirmiştir. Ekim 2025'te bir teknik rapor yayımlanmıştır (arXiv 2510.25819, Tobin South ve 20 yazar). Eş başkanları Atul Tulshibagwale (CrowdStrike) ile Jeff Lombardo'dur (AWS). Mart 2026'da NIST'in bilgi talebine resmî yanıt verilmiştir. Kapsam dışı olan şey protokol standardı geliştirmektir.

AuthZEN çalışma grubunda 15 Haziran 2026'da iki çalışma grubu taslağı onaylanmıştır.

**AARP**, yani Access Request and Approval Profile, Draft 1, Eylül 2026. Talep edilebilir ret bağlamı sunar: politika karar noktası reddederken bir `access_request` nesnesi ekleyerek reddin talebe uygun olduğunu bildirir. Bir erişim talebi endpoint'i ile opak ve asenkron bir görev tutamağı vardır: "survives PEP restart, replacement, or handoff". Yeniden değerlendirme modunda onay sonrası politika uygulama noktası taze bir AuthZEN değerlendirmesi yapar, böylece karar noktası uygulama anında otoriter kalır. Reddedilmiş bir karar reddedilmiş kalmalıdır (MUST NOT değiştirilmelidir).

**COAZ-MCP Binding**, Draft 1, Şubat 2026. MCP JSON-RPC mesajlarını AuthZEN SARC modeline eşler. `x-authzen-mapping` ile CEL ifadeleri kullanır; örneğin `$params.arguments.id` ve `$token.sub`. Özne kimliği güven modeli şöyledir: "The human user is represented as the AuthZEN Subject; the AI agent appears in the Context." Yalnızca doğrulanmış `subject.id` güvenilirdir.

**Shared Signals.** SSF 1.0 ile CAEP 1.0 Final 29 Ağustos 2025'te yayımlanmıştır. CAEP 1.0 Final sekiz olay tipi tanımlar. Ajana özgü bir olay tipi yoktur ve bu bir boşluktur.

> **Tuzak.** `openid.net/specs/openid-caep-specification-1_0.html` adresi hâlâ 2021 tarihli draft-02'yi döndürmektedir. Final sürüm `openid-caep-1_0-final.html` adresindedir.

### 7.7 Teleport, attestation'ı kim yapar sorusu

Teleport bir IdP değildir, ancak 2.8 ve 2.9'daki attestation tasarımına doğrudan bir sınır sorusu koyduğu için buradadır. Kaynak Teleport'un Machine & Workload Identity dokümanıdır, erişim 13 Eylül 2026.

**Modeli.** Teleport kümesi içinde bir kök CA kurulur ve iş yüklerine kısa ömürlü JWT'ler ile X.509 sertifikaları verir. Kimlikler SPIFFE uyumludur ve SVID olarak adlandırılır. İş yüklerinin yakınında `tbot` adlı bir ajan çalışır; kimlik talebini ve yenilemesini o yönetir. Bir uygulama SVID istediğinde `tbot` **workload attestation** yapar: container image'ı, Kubernetes pod etiketleri gibi bilgileri keşfeder. Kimlikler dosya sistemiyle veya SPIFFE Workload API'siyle teslim edilir.

**Argus için sorduğu soru.** 2.8'in mimari deseni "donanım attestation'ı kayıt anında bir kez kanıtlar, sonra DPoP her istekte kullanımı kanıtlar" der. Söylemediği şey, o ilk kanıtın kim tarafından toplandığıdır. İki cevap vardır ve ikisi farklı güven modelleri üretir:

1. **Argus delili kendisi toplar.** İstemci ham attestation belgesini (TPM quote, Android KeyDescription, Apple App Attest) gönderir, Argus doğrular. Güven kökü donanım üreticisidir. Argus her platformun attestation formatını bilmek zorundadır; §21'deki `KeyDescription` ASN.1 bloğu bu maliyetin bir örneğidir.
2. **Argus bir attester'ın imzaladığı iddiaya güvenir.** `tbot` modeli budur; kanıtı toplayan ve normalize eden taraf iş yükünün yanındaki ajandır, Argus yalnızca o ajanın imzasını doğrular. Argus platform çeşitliliğinden korunur, ama güven kökü artık donanım değil **attester'ın kendisidir**; attester ele geçirilirse her iş yükü taklit edilebilir.

Bu soru dokümanda sorulmamıştır ve 2.8'in "arayüzü hazırlanmalıdır" kararı ikisi arasında seçim yapmadan verilemez. Seçim veri modelini de değiştirmektedir: ikinci modelde `AgentIdentity` içinde `trusted_instance_issuers` alanı yeterli değildir, ayrıca hangi attester'ın hangi iddia tipini imzalamaya yetkili olduğu modellenmelidir.

**Ek bir gözlem.** Teleport'un değer önerisi, uzun ömürlü paylaşılan sırların altyapıdan kaldırılmasıdır. Argus'un ajan token'larının "insan token'larından çok kısa" olması kararı (11.4) aynı hedefin token tarafındaki hâlidir; ikisi birlikte tasarlanmalıdır, çünkü çok kısa ömür yenileme trafiğini ve dolayısıyla §27'deki yük profilini belirler.

---

## 8. Açık problemler, ne çözüldü ve ne çözülmedi

| Problem | Durum | Kanıt |
|---|---|---|
| Alanlar arası kimlik zinciri | Neredeyse çözülmüştür | identity-chaining-17 RFC kuyruğundadır |
| Uygulamalar arası kullanıcı çoklu oturum açması taşıma | Çözülmüştür | ID-JAG-04 ile MCP EMA stabildir ve üretimdedir |
| Göndericiye kısıtlı token | Çözülmüştür | DPoP RFC 9449 ile mTLS RFC 8705 |
| Sinyal ile olay dağıtımı | Çözülmüştür | SSF 1.0 ile CAEP 1.0 Final |
| Bant dışı kullanıcı onayı | Kısmen çözülmüştür | CIBA Final'dır ancak çalıştırma ortasına uymamaktadır; AIMS §10.7 itirafı |
| Ölçeklenebilir iptal | Neredeyse çözülmüştür | status-list-21 RFC kuyruğundadır; `VALID`, `INVALID` ile `SUSPENDED` durumları vardır |
| Delegasyon zincirinin kriptografik doğrulanabilirliği | Açıktır | `act` yetki için kullanılamaz; yedi rakip taslak vardır ve hiçbiri çalışma grubunda değildir |
| Ajan kaydı ile keşfi | Açıktır | A2A kayıt defteri tartışması bir yıldan uzun süredir sonuçsuzdur, issue #741 ve 80'den fazla yorum; MCP Registry önizlemededir |
| Yetki daraltmanın OAuth'a entegrasyonu | Açıktır | Biscuit v3.3 ile UCAN 1.0 olgundur ancak OAuth'la konuşmamaktadır. OAuth scope'u operatör düzeyindedir, örneğin TRANSFER, operand düzeyinde değildir, örneğin Bob'a 100 dolar; arXiv 2603.17170 |
| Çalıştırma ortasında ve işleme kriptografik bağlı insan onayı | Açıktır | CIBA `binding_message` yalnızca serbest metindir. Dört aday vardır ve hepsi bireyseldir |
| Ajana özgü CAEP olayları | Açıktır | CAEP 1.0'da yoktur |
| Toplu ve kitlesel iptal | Açıktır | `draft-chen`'in toplu iptal boşluğu |
| Ajan denetlenebilirliği | Açıktır | AUDIT BoF reddedilmiştir |
| İş yükü kimliği standardı | Açıktır | WIMSE'den hiç RFC çıkmamıştır |
| Prompt enjeksiyonunun yetkilendirmeye etkisi | Yetkilendirme katmanında çözülemez | Güçlü bir uzlaşı vardır |

### 8.1 Prompt enjeksiyonu, dürüst değerlendirme

Ölümcül üçlü (Simon Willison, 16 Haziran 2025) özel veriye erişim, güvenilmeyen içeriğe maruziyet ile dışarı iletişimden oluşur: "we still don't know how to 100% reliably prevent this from happening."

AIMS'in normatif cevabı §8'dedir: "The Large Language Model MUST NOT have access to an agent's credentials..."

Ekosistemin gerçek durumu için arXiv 2605.22333 (21 Mayıs 2026, Fudan) 7.973 canlı uzak MCP sunucusu incelemiştir: %40,55'i hiçbir kimlik doğrulaması olmadan tool açmakta; OAuth kullanan 119 sunucunun %100'ünde en az bir kusur, toplam 325 kusur bulunmakta; %96,6'sında DCR kusuru bulunmaktadır.

Yetkilendirme katmanının yapabildikleri ölçülmüştür; arXiv 2609.00267, 31 Ağustos 2026. LangGraph, CrewAI, AutoGen ile MCP değerlendirilmiş ve üçünün hiçbir yerleşik sınırlama sağlamadığı görülmüştür. Yazarların yetkilendirme aracısı dört tehdidi de engellemekte ve ele geçirilmiş bir alt ajanın erişimini 8.100 olası eylemden ortalama 1,5'e düşürmektedir. Makalede geçen karar başına yaklaşık 2,6 mikrosaniye rakamı 160 satırlık Python'da HMAC caveat doğrulamasıdır, ilişki tabanlı erişim kontrolü graf çözümlemesi değildir; Argus'un yetkilendirme hedefi olarak alınamaz, §20'nin sıfırıncı bölümüne bakınız. Doğru okuma şudur: yetki token'a gömülüyse doğrulama neredeyse bedavadır.

> **Argus'un tez cümlesi.** Yetkilendirmeyi modelden çıkar, deterministik bir aracıya koy.

---

## 9. Düzenleyici durum

Net cevap şudur: bugün bir IdP'yi AI ajanlarına ayrı kimlik vermeye hukuken zorlayan bağlayıcı bir düzenleme yoktur.

| Kaynak | Bağlayıcı mıdır | Ajan kimliği gerektiriyor mu | Ne zaman ısırır |
|---|---|---|---|
| AB Yapay Zekâ Yasası madde 50 | Evet, 2 Ağustos 2026'da yürürlüktedir | Hayır; yalnızca yapay zekâ olduğunun ifşasını ister | Şimdi |
| AB Yapay Zekâ Yasası yüksek risk | Evet ancak 2 Aralık 2027'ye ertelenmiştir, Reg. EU 2026/1744, 27 Temmuz 2026 | Dolaylı olarak | Aralık 2027 |
| Singapur CSA Securing Agentic AI eki, 17 Haziran 2026 | Hayır: "not mandatory, prescriptive nor exhaustive" | Evet, çok spesifiktir | Tedarik ile denetim baskısı olarak |
| NIST NCCoE "Software and AI Agent Identity and Authorization", 5 Şubat 2026 | Hayır | Evet, en teknik olanıdır: MCP, OAuth 2.0 ile 2.1, OIDC, SPIFFE ile SPIRE, SCIM ve NGAC | 2027 federal tedariki |
| OWASP Agentic Top 10, 2026 | Hayır | Evet; ASI03 kimlik ile ayrıcalık istismarı | Şimdi, fiilî taban çizgisidir |
| FIDO Agentic Authentication çalışma grubu, 28 Nisan 2026 | Hayır | Evet; doğrulanabilir kullanıcı talimatları ile ticarette güvenilir delegasyon | 2027 ve sonrası |

Singapur CSA'nın somut kontrolleri şunlardır: "Maintain trusted registry of agents and authenticate agents using strong, verifiable credentials"; "Ensure fine-grained, scoped tokens"; "time-bound or one-time-use credentials"; "Validate permissions on every request to each agent in the workflow"; "Prevent cross-agent privilege delegation"; "Do not share credentials with the agent".

Dünya Ekonomik Forumu'nun "AI Agents in Action" raporu (Mayıs 2026) ACAP çerçevesini getirmektedir. En aksiyona dönüştürülebilir kuralı şudur: "a downstream agent operates under the intersection of its own ACAP permissions and those of the agent that invoked it. An orchestrating agent cannot delegate authority it does not itself hold."

Dört kaynağın, yani CSA, NIST, OWASP ile WEF'in ortak paydası bir IdP'nin yol haritasıdır.

1. Her ajana benzersiz ve ayrı bir kimlik verilir; servis hesabı paylaşımı yapılmaz.
2. Kısa ömürlü, kapsamlı ve zaman sınırlı kimlik bilgisi kullanılır.
3. Güvenilir bir ajan kaydı ile doğrulanabilir kimlik bilgisi tutulur.
4. Delegasyonda kesişim alınır, toplama yapılmaz.
5. Her adımda yeniden yetkilendirme yapılır; bir kez token alıp zincir boyunca kullanmak açık bir anti-desendir.
6. İnkâr edilemezlik ile denetlenebilirlik sağlanır.
7. Merkezî bir uygulama düzlemi kurulur.
8. Kullanıcı başlatmalı eylemler ile ajan başlatmalı eylemler ayrılır.

---

## 10. Sınıflandırma

### Bugün implemente edilmeli

| # | Öğe | Neden |
|---|---|---|
| 1 | OAuth 2.1 çekirdeği: PKCE S256 zorunludur, `plain` reddedilir, implicit ile password yoktur | Her şeyin tabanıdır |
| 2 | RFC 8414 ile OIDC Discovery, ikisi birden | MCP MUST'ıdır |
| 3 | RFC 9728 PRM | MCP MUST'ıdır |
| 4 | RFC 8707 `resource`, kanonik URI doğrulaması ile `aud` alanına yansıtma | MCP MUST'ıdır |
| 5 | RFC 9207 `iss`, hata yanıtları dahil ve normalizasyon yapılmadan | MCP MUST'ıdır ve yakında MUST'a yükselecektir |
| 6 | CIMD tam implementasyonu ile `client_id_metadata_document_supported: true` | DCR kullanımdan kaldırılmıştır |
| 7 | RFC 7591 DCR, eski uyumluluk için; `application_type` ile issuer'a bağlı kimlik bilgisi | On iki aydan uzun geriye uyumluluk penceresi vardır |
| 8 | RFC 8693 Token Exchange, standart URN'lerle, `act` ile `may_act` | Delegasyonun tabanıdır |
| 9 | ID-JAG üretimi ile tüketimi, metadata, `jti` yeniden oynatma önbelleği ve istemci sürekliliği | Keycloak'ta üretim yoktur |
| 10 | SPIFFE istemci kimlik doğrulaması: JWT-SVID, X.509-SVID ile Bundle Endpoint | Keycloak implemente etmektedir |
| 11 | DPoP (RFC 9449) `cnf.jkt` ile mTLS'e bağlı (RFC 8705) `cnf.x5t#S256` | 3 Ağustos 2026 ölçümünde 15 issuer'dan hiçbiri DPoP ilan etmemekteydi |
| 12 | RAR (RFC 9396), hem istekte hem token claim'inde; tip başına JSON şeması ve onayda insan okunur gösterim | Ajanlar için scope'tan kat kat önemlidir |
| 13 | CIBA: `/bc-authorize`, `binding_message`, `authorization_pending` ile `slow_down` | Sunucu aracılı bağlama modelinin ta kendisidir |
| 14 | Scope challenge motoru: 403 ile `insufficient_scope`, `scope` ve `resource_metadata` | MCP MUST ile SHOULD'udur |
| 15 | İş yükü tarzı hiyerarşik tanımlayıcılar: `spiffe://` ile `wimse://` | Politika joker karakterleri içindir |
| 16 | RFC 7009 iptali, RFC 7662 introspection'ı ile JWKS rotasyonu | Temel hijyendir |
| 17 | SSF ile CAEP vericisi, Final spesifikasyonunun sekiz olayıyla | 2021 draft-02 URL tuzağına dikkat edilmelidir |

### Arayüzü hazırlanmalı

18. `delegation_chain` claim'i: sıçrama başına imza, ayrık JWS ile JCS.
19. Actor Profile değişmezleri: `sub` yetkilendirendir, en dıştaki `act.sub` doğrudan aktördür, kanonik kimlik `(act.iss, act.sub)` ikilisidir ve asgari derinlik dörttür.
20. `sub_profile` ile `client_profile` claim'leri ve `ai_agent` değeri.
21. `agent_instance_id` ile `agent_platform`, `agent_model` ve `agent_runtime`.
22. Attestation tabanlı istemci kimlik doğrulaması, yani `OAuth-Client-Attestation` başlıkları.
23. Transaction Tokens: `typ: txntoken+jwt`, `Txn-Token` başlığı ile token servisi.
24. Çalıştırma ortasında insan onayı için bir uzantı noktası: üç adaydan biri seçilir ve üçünü de destekleyebilecek bir soyutlama kurulur.
25. AuthZEN politika karar noktası entegrasyonu: SARC, `x-authzen-mapping`, CEL ile AARP'ın görev tutamağı modeli.
26. Delegasyonlu refresh token profili: mutlak son tarih ile göreve kapsamlı iptal.
27. `refresh_token_timeout` ile `authorization_expires_in`.
28. RAR metadata keşfi ile düzeltme akışı.
29. First-Party Apps Authorization Challenge Endpoint'i ile `auth_session`.
30. SCIM `/Agents` ile `/AgenticApplications`; `owners`, `protocols` ve `subject` nitelikleri.
31. Üç bağlama modeli akış olarak sunulur: ajan aracılı, sahip aracılı ile sunucu aracılı, yani CIBA.
32. WIT ile WPT desteği.
33. Agent Card imzalama servisi: RFC 8785 JCS, JWS ile JWKS. Hiçbir yaygın IdP bunu yapmamaktadır.
34. Federe kimlik bilgisi kasası, yani Connection: zarf şifrelemesi ile otomatik yenileme işçisi.
35. Bulut iş yükü federasyonu: AWS ile GCP OIDC'den `jwt-bearer` grant'ına.

### Henüz erken

Yetki daraltan token'lar, dört rakip taslak vardır. Ajan kayıt protokolleri: NANDA, ANS, AgentDNS, `agent://` ile `urn:aid:`. Donanıma çapalı ajan kimliği. `agent_trust_score` tarzı claim'ler. Rego ile politika dilinin OAuth'a bağlanması. Göreve bağlı yetkilendirme. Ajana özgü CAEP olay tipleri. Küresel ve toplu iptal standardı. SD-JWT ile Agent Card seçici ifşası. agentproto'nun getireceği her şey.

---

## 11. Somut teknik gereksinim listesi

### 11.1 Endpoint'ler

**Standart olanlar.**

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

**Ajan için ek olanlar.**

```
POST /bc-authorize                              CIBA backchannel
POST /token  (grant_type=...:ciba)              CIBA polling
POST /authorize-challenge                       FiPA
GET  /.well-known/authorization-details-types   RAR metadata
POST /access-requests                           AuthZEN AARP
GET  /access-requests/{task_handle}             AARP task status
POST /agents/{id}/revoke-all                    toplu iptal (standart yok)
GET  /ssf/.well-known/sse-configuration         SSF transmitter
POST /agent-cards/sign                          A2A Agent Card imzalama
SCIM /Agents, /AgenticApplications
```

**Grant tipleri.**

```
authorization_code                                          (PKCE S256 zorunlu)
refresh_token
client_credentials
urn:ietf:params:oauth:grant-type:token-exchange             RFC 8693
urn:ietf:params:oauth:grant-type:jwt-bearer                 RFC 7523 → ID-JAG tüketimi
urn:openid:params:grant-type:ciba                           CIBA
urn:ietf:params:oauth:grant-type:device_code                RFC 8628 (A2A deviceCode)
```

**`requested_token_type` değerleri.**

```
urn:ietf:params:oauth:token-type:access_token
urn:ietf:params:oauth:token-type:id_token
urn:ietf:params:oauth:token-type:refresh_token
urn:ietf:params:oauth:token-type:jwt
urn:ietf:params:oauth:token-type:id-jag                     ID-JAG üretimi
urn:ietf:params:oauth:token-type:txn_token
```

**İstemci kimlik doğrulama metotları.**

```
private_key_jwt                                            (CIMD ile önerilen)
tls_client_auth / self_signed_tls_client_auth              RFC 8705
client_secret_basic / client_secret_post                   (legacy)
urn:ietf:params:oauth:client-assertion-type:jwt-spiffe     JWT-SVID
attest_jwt_client_auth
```

### 11.2 Token tipleri, yani `typ` başlıkları

| `typ` | Ne olduğu | Öncelik |
|---|---|---|
| `at+jwt` | Access token, RFC 9068 | Bugün |
| `oauth-id-jag+jwt` | ID-JAG | Bugün |
| `dpop+jwt` | DPoP kanıtı | Bugün |
| `txntoken+jwt` | Transaction Token | Arayüz hazırlanır |
| `wit+jwt` | WIMSE Workload Identity Token | Arayüz hazırlanır |
| `application/wpt+jwt` | WIMSE Workload Proof Token | Arayüz hazırlanır |
| `oauth-client-attestation+jwt` ile `-pop+jwt` | İstemci attestation'ı | Arayüz hazırlanır |

### 11.3 Claim seti, ajan access token'ının hedef şekli

```jsonc
{
  // — Kimlik —
  "iss": "https://idp.acme.example/",
  "sub": "user:alice@acme.example",              // YETKİLENDİREN (insan)
  "sub_profile": "user",
  "aud": "https://mcp.chat.example/",             // RFC 8707 resource
  "client_id": "https://app.example.com/client.json",  // CIMD URL-form
  "jti": "...", "iat": ..., "exp": ...,

  // — AKTÖR (ajan) — RFC 8693, iç içe olabilir —
  "act": {
    "sub": "spiffe://acme.example/agent/invoice-bot/i-7f3a",
    "iss": "https://idp.acme.example/",
    "sub_profile": ["ai_agent", "client_instance"],
    "agent_instance_id": "aai-...",
    "agent_platform": "...", "agent_model": {"id":"...","version":"..."},
    "act": { /* bir üst hop — min depth 4 */ }
  },

  // — DELEGASYON ZİNCİRİ (imzalı) —
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
  "txn": "...",
  "tenant": "acme"
}
```

Kural şudur: `sub` insandır, `act` ajandır. Otonom, yani kullanıcısız ajan durumunda `sub` ajandır ve `act` yoktur.

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

Kod seviyesinde zorlanması gereken değişmezler şunlardır.

1. Tek yönlü daraltma: `child.scopes ⊆ parent.scopes`.
2. TTL monotonluğu: `child.exp ≤ parent.exp`.
3. Derinlik monotonluğu: `child.del_depth = parent.del_depth + 1 ≤ max_depth`.
4. Zincir sürekliliği: `record[i].delegator_id == record[i-1].delegatee_id`.
5. Kesişim semantiği: downstream ajan, kendi izinleriyle çağıranın izinlerinin kesişimine sahiptir.
6. Sahiplik kanıtı: yaprak token'ı sunan taraf özel anahtarı kontrol ediyor olmalıdır.

**Ajanın veri modelindeki yeri bir gün-1 sözleşmesidir ve §1'e taşınmalıdır.** Yukarıdaki `Principal` enum'u sessizce bir karar vermektedir: ajan, `User`'ın bir varyantı ya da bir bayrağı değil, ayrı bir varyanttır. Bu doğru karardır ancak §1'in kalıcı kimlik sözleşmeleri arasında kayıtlı değildir; `sub` değerinin uzayını ve her FK'nin şeklini belirlediği için sonradan değiştirilemez.

Karşılaştırma noktası FusionAuth'un **Entity Management**'ıdır (erişim 13 Eylül 2026). Orada model daha geneldir: bir entity'nin bir tipi vardır — ürün dokümanının saydığı örnekler arasında kilit, araba, şirket, bölüm, bilgisayar, **AI agent** ve API bulunur. **Grant**, bir hedef entity ile bir alıcı entity veya kullanıcı arasındaki ilişkidir ve sıfır ya da daha fazla permission taşır. Entity'ler birbirlerine client credentials grant'ıyla erişir.

İki model arasındaki gerçek fark şudur ve bir tercihtir:

| | Argus'un `Principal` enum'u | FusionAuth'un entity/grant grafiği |
|---|---|---|
| Yeni aktör tipi eklemek | Şema ve kod değişikliği | Veri; yeni bir entity type satırı |
| Ajana özgü değişmezler | Tipte taşınır; yukarıdaki altı kural derleme zamanında zorlanabilir | Genel grafikte ifade edilemez; uygulama katmanına düşer |
| §20 ile ilişki | `Principal` bir tuple öznesi olarak eşlenir | Grant grafiği zaten bir tuple deposudur |

Argus'un altı değişmezi — özellikle kesişim semantiği ve derinlik monotonluğu — genel bir grant grafiğinde ifade edilemez. Bu yüzden tipli model korunmalıdır. Ancak FusionAuth'un gösterdiği bir şey alınmalıdır: ajan, kullanıcıya *benzetilerek* modellenmemelidir. `AgentIdentity` bugün `owner_user_id` ve `sponsor_user_id` ile kullanıcıya bağlıdır; bu bağlar ilişki olarak modellenmelidir, kolon olarak değil, aksi hâlde çok sahipli ve devredilen ajanlar şema değişikliği gerektirir.

### 11.5 AS metadata'sı

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

## 12. Çelişkili ve yakınsamamış noktalar

1. **Çalıştırma ortasında insan onayı: dört rakip mekanizma.** `interaction_required` ile `interaction_uri` (Parecki, Campbell, Liu); `completion_mode=deferred` ile `deferral_code` (Gerber); `transaction_challenge` (Rosomakho, Campbell, McGuinness, Kasselman); AuthZEN AARP. Üçü de aynı IETF 126 oturumunda sunulmuştur. Öneri şudur: iç mimaride tek bir bekleyen yetkilendirme soyutlaması kurulur ve dört yüzey de ona bağlanır.
2. **Delegasyon zinciri: yedi rakip yaklaşım.** JWT claim'i, HTTP başlığı, çevrimdışı doğrulanabilir yetenek zinciri ve yalnızca `act` profili birbiriyle yarışmaktadır. Kriptografi de farklıdır: çift imza, ebeveyn hash zinciri ve HTTP Message Signatures.
3. **Bearer mi sahiplik kanıtı mı.** WIMSE WIT "MUST NOT be used as a bearer token" demektedir; MCP hâlâ `Authorization: Bearer` üzerine kuruludur. SPIFFE JWT-SVID bearer'dır, halefi WIT-SVID sahiplik kanıtıdır. Ekosistem ikiye bölünmüştür.
4. **`act` yetki için kullanılabilir mi.** RFC 8693 açıkça hayır demektedir, ancak neredeyse tüm ajan taslakları `act`'i delegasyon kanıtı gibi kullanmaktadır. Bu bir standart ihlali riskidir.
5. **A2A v1.0 tarihi çelişkilidir.**
6. **Spesifikasyon gecikmesi.** MCP `draft-ietf-oauth-v2-1-13` ile `client-id-metadata-document-00` belgelerine referans vermektedir; güncelleri -16 ile -02'dir.
7. **ID-JAG'ın hedeflenen statüsü.** Datatracker None göstermekte, taslak metni Standards Track demektedir; bir metadata tutarsızlığıdır.
8. **`draft-parecki-oauth-global-token-revocation-06`.** API 28 Ağustos 2026 ve revizyon 06 göstermekte, doküman sayfası 24 Şubat 2026'da süresinin dolduğunu söylemektedir. Çelişki çözülememiştir.
9. **Entra Agent ID ile açık standartlar.** Microsoft üretimde `sub` ile `actor` ayrımını yapmaktadır ancak ID-JAG, MCP EMA veya WIMSE desteği dokümanlarda bulunamamıştır.
10. **Ajan kaydı konusunda tam kaos vardır.** A2A kayıt defteri tartışma aşamasındadır, MCP Registry önizlemededir, SCIM `/Agents` taslaktır, Entra ile Agent 365 tescillidir, `urn:aid:` spekülatiftir, AgentDNS, ANS ile NANDA akademiktir. Hiçbiri diğeriyle uyumlu değildir.

---

## 13. Doğrulanamayanlar

1. OAuth çalışma grubu başkanlarının ajan dokümanlarının kabulü için erken olduğunu söyleyen ifadesinin tam metni.
2. Delegation chain splicing saldırısının birincil mesaj gövdesi.
3. `draft-ni-wimse-ai-agent-identity` için bir -03 revizyonu olup olmadığı; -02'nin süresi 1 Eylül 2026'da dolmuştur.
4. AIMS'in sekiz katmanlı yapısı; ham metinde yedi bileşen sayılmıştır.
5. A2A v1.0'ın kesin genel kullanım tarihi.
6. Keycloak'ın ID-JAG üretimi issue'su, keycloak#43971.
7. Singapur CSA ekinin 17 Haziran 2026 tarihli nihai metnindeki kimlik kontrolleri.
8. PSD3 ile PSR'de ajansal yapay zekâya özgü hüküm; bulunamamıştır.
9. NIST SP 800-63'ün insan olmayan kimlik güncellemesi için resmî takvim.
10. Entra Agent ID'nin açık standart desteği.
11. Auth0'da ajana özel uygulama tipi ile Auth for MCP'nin RFC 9728 implementasyonu.
12. Okta Agent SSO'nun genel kullanım tarihi; 24 Ağustos 2026 birincil kaynaktır, Mayıs 2026 ikincil ve çelişkilidir.
13. `github.com/nomoticai/ietf-agent-landscape` içeriği; URL 404 dönmektedir.
14. `draft-sweeney-wimse-credential-delegation-00` içeriği.
15. UCAN 1.0'ın kesin yayın tarihi; zcap-ld'nin 2026 durumu; KERI'nin ajan bağlamındaki benimsenmesi.
16. Ping Identity, Astrix ile Oasis Security'nin ajansal ürün yaklaşımları.

---

## 14. Argus için üç stratejik hamle

**1. ID-JAG birinci günde tam yapılır, yani hem üretilir hem tüketilir.** Keycloak yalnızca tüketmektedir, o da önizlemededir. MCP Enterprise-Managed Authorization stabildir ve ID-JAG'ın ta kendisidir. MCP yerlisi kurumsal IdP konumlandırması bugün boştur.

**2. Bearer varsayılan yapılmaz.** 3 Ağustos 2026 ölçümünde keşif yanıtı veren 15 halka açık issuer'dan onu yalnızca paylaşılan sır tabanlı istemci kimlik doğrulaması, üçü `private_key_jwt`, biri mTLS ilan etmekteydi ve hiçbiri DPoP ilan etmemekteydi. DPoP, mTLS'e bağlı token ile JWT-SVID kabulünü birinci sınıf yapan ilk ciddi IdP olmak hem WIMSE'nin gittiği yöndür hem somut bir farklılaşmadır.

**3. Delegasyon zinciri kendi imzalı yapımızla çözülür, `act` yalnızca uyumluluk için üretilir.** Standart yakınsamamıştır ve en az iki yıl daha yakınsamayacaktır. `draft-liu-oauth-chain-delegation`'ın şekli, `draft-mcguinness-oauth-actor-profile`'ın üç değişmezi, WEF ACAP'ın kesişim kuralı ile daraltma değişmezleri bugün implemente edilir. Hangisi standartlaşırsa geçiş ucuzdur; hiçbiri olmazsa zaten `act`'in güvenli bir üst kümesine sahip olunur.

Ve deterministik yetkilendirme aracısı modelin dışında, Rust'ta tutulur.
