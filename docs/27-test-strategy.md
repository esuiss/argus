# 27. Test stratejisi

> `ARGUS.md` §27'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§27 §X` referansları aynı anlamda.


Tarih: 8 Eylül 2026. Tüm iddialar kaynaklandırılmıştır; doğrulayamadıklarım "⚠️ DOĞRULANMADI" ile işaretlidir.

---

## 1. Uyum (Conformance) Test Süitleri

### 1.1 OpenID Foundation Conformance Suite

**Self-hosted çalıştırılabilir — evet, Docker ile.** Suite açık kaynak, `gitlab.com/openid/conformance-suite` üzerinde. OIDF'nin resmî sayfası: "The conformance suite supports local Docker installation for developers wanting to run tests independently" ve tüm testler "can be run locally or via OpenID Foundation servers — whichever the implementer prefers" ([openid.net/certification/about-conformance-suite](https://openid.net/certification/about-conformance-suite/)).

`docker-compose.yml` içeriği (birincil kaynak, [master raw](https://gitlab.com/openid/conformance-suite/-/raw/master/docker-compose.yml)):
- `mongodb` — `mongo:6.0.13`, port yok (internal), `./mongo/data:/data/db`
- `nginx` — `./nginx` context'ten build, **8443:8443** (HTTPS)
- `server` — `./server-dev` context, Java `fapi-test-suite.jar`, nginx arkasında

Yani: MongoDB + Java app + nginx TLS terminasyonu. Kayda değer: jar adı hâlâ `fapi-test-suite.jar` — suite'in kökeni OpenBanking Ltd'nin bağışladığı FAPI framework'ü ([README](https://gitlab.com/openid/conformance-suite/-/raw/master/README.md); katkı verenler arasında OpenBanking Ltd, ONC for Health IT, Authlete).

**Kapsanan spesifikasyonlar** (README'den): OpenID Connect, FAPI1-Advanced, FAPI2, FAPI-CIBA, OpenID for Identity Assurance (eKYC). Buna federation ve OpenID4VP/VCI de eklenmiş durumda (aşağıda).

**OP profilleri — 7 adet, doğrulandı** ([openid.net/certification/connect_op_testing](https://openid.net/certification/connect_op_testing/)):

| Profil | Ne test eder |
|---|---|
| Basic OP | `response_type=code` temel akış |
| Implicit OP | implicit response type'lar |
| Hybrid OP | hibrit akışlar |
| Config OP | `.well-known/openid-configuration` discovery |
| Dynamic OP | Dynamic Client Registration |
| Form Post OP | `response_mode=form_post` |
| 3rd Party-Init Login OP | third-party initiated login |

Aynı sayfadan doğrulanan operasyonel detaylar:
- Test için `certification.openid.net`'e Google veya GitLab ile giriş
- DCR desteklenmiyorsa **3 client** elle kaydedilmeli: 2 adet `client_secret_basic`, 1 adet `client_secret_post` (ilkiyle çakışabilir)
- Redirect URI: `https://www.certification.openid.net/test/a/<ALIAS>/callback`
- Sertifikasyon kriteri: tüm testler PASSED / REVIEW / WARNING / SKIPPED olmalı; **FAILED veya INTERRUPTED olmamalı**

**Logout profilleri — 4 adet** ([logout_op_testing](https://openid.net/certification/logout_op_testing/)): RP-Initiated Logout OP, Session Management OP, Front-Channel Logout OP, Back-Channel Logout OP. Sertifikasyon için RP-Initiated **+ diğer üçünden en az biri** gerekli. Test id konvansiyonu: `OP-RpInitLogout-*`, `OP-Session-*`, `OP-FrontChannel-*`, `OP-BackChannel-*`. ⚠️ Not: bu sayfa kendini "historical page relating to the now-decommissioned old test suite" olarak tanımlıyor — yeni suite'te plan adları farklı olabilir.

**Test planı adları (birincil doğrulama — Ory Hydra'nın CI kodu).** Hydra'nın [`test/conformance/run_test.go`](https://raw.githubusercontent.com/ory/hydra/master/test/conformance/run_test.go) dosyası gerçek plan adlarını içeriyor:

```
oidcc-basic-certification-test-plan          (⚠️ dosyada "oidcc-test-plan" olarak da geçiyor)
oidcc-implicit-certification-test-plan
oidcc-hybrid-certification-test-plan
oidcc-config-certification-test-plan
oidcc-dynamic-certification-test-plan
oidcc-formpost-basic-certification-test-plan
oidcc-formpost-implicit-certification-test-plan
oidcc-formpost-hybrid-certification-test-plan
oidcc-test-plan
```

Aynı dosya suite'in **REST API'sini** de açığa çıkarıyor — Argus için kritik:
- `POST /api/plan` → plan adı + variant, plan id döner
- Plan içinde N adet **module** var (örn. `oidcc-server-rotate-keys`)
- `POST /api/runner` → module id + plan id + variant ile test instance
- `GET /api/info` → exponential backoff ile poll; status `FINISHED`, result `PASSED`/`WARNING`/`FAILED`
- Hydra başarısız/interrupted testleri **max 5 kez** retry ediyor (flakiness gerçek bir problem)

Hydra'nın kurulumu: `test/conformance/` altında `docker-compose.yml`, `Dockerfile`, `config.json`, `start.sh`, `test.sh`, `publish.sh`, `purge.sh`, `run_test.go`, ayrıca `httpd/` ve `ssl/` dizinleri. `test.sh` sadece `go test -tags conformity -test.timeout 60m -failfast .` çalıştırıyor — **60 dakikalık timeout**, tam OIDC plan setinin CI süresi hakkında iyi bir sinyal.

**Resmî CI aracı: `scripts/run-test-plan.py`** ([raw kaynak](https://gitlab.com/openid/conformance-suite/blob/master/scripts/run-test-plan.py)). OIDF "highly recommended that authorization server developers integrate this into their development pipeline" diyor. Doğrulanan arayüz:

- Argümanlar: `<test-plan-name> <config-file>` çiftleri (birden fazla), `--export-dir`, `--no-parallel`, `--expected-failures-file`, `--expected-skips-file`, `--rerun 2:6`, `--list`, `--verbose`
- Env: `CONFORMANCE_SERVER` (zorunlu), `CONFORMANCE_TOKEN`, `CONFORMANCE_SERVER_MTLS`, `CONFORMANCE_SERVER_LOCAL`, `EXTERNAL_URL`, `CONFORMANCE_MAX_CONSECUTIVE_FAILURES` (default 3), `CONFORMANCE_RESTART_RETRIES` (default 2)
- Exit 1: modül tamamlanmadı, beklenmeyen failure/warning, **beklenen failure listede olup gerçekleşmedi** (stale baseline tespiti), sunucu sağlıksız
- Exit 0: hepsi tamam ve expected-failures ile eşleşti

Bu **tam olarak Argus'un istediği model**: baseline'lı, CI-dostu, exit-code'lu.

**Test sayıları:** ⚠️ DOĞRULANMADI — hiçbir birincil kaynakta "Basic OP planı N test içerir" gibi bir sayı bulamadım. Sayı, plan oluşturulduğunda dinamik olarak variant'lara göre belirleniyor (Hydra kodu "plan contains multiple modules, iterate over them" mantığıyla çalışıyor). Kesin sayı ancak `POST /api/plan` sonrası dönen module listesinden öğrenilir.

**Ücret:** Testleri çalıştırmak ücretsiz; sertifikasyon ücretli ([openid.net/certification/fees](https://openid.net/certification/fees/)):

| Kategori | Üye | Üye değil |
|---|---|---|
| OpenID Connect, OpenID4VCI/VP | $700 / deployment | $3,500 / deployment |
| FAPI 1 / FAPI 2 / FAPI-CIBA | $1,000 / deployment | $5,000 / deployment |

Açık kaynak projeler için fee waiver politikası var. **Argus sertifika hedeflemiyor → maliyet sıfır.**

### 1.2 FAPI 2.0

- **FAPI 2.0 Security Profile Final onaylandı: Şubat 2025.** Final conformance testleri **9 Temmuz 2025**'te duyuruldu — authorization server *ve* OAuth client için ([openid.net/fapi2-0-final-conformance-tests-available](https://openid.net/fapi2-0-final-conformance-tests-available/)). FAPI 2.0 Message Signing "Proposed Final", yayını Ağustos 2025 bekleniyordu.
- Desteklenen spesifikasyonlar ([certification-fapi_op_testing](https://openid.net/certification/certification-fapi_op_testing/)): FAPI 1.0 Part 2 Advanced Final, **FAPI 2.0 Security Profile Final**, FAPI 2.0 Security Profile ID2, FAPI 2.0 Message Signing ID1.
- Client auth varyantları: `oauth-mtls` ve `private_key_jwt`. Ekosistem varyantları: OpenBanking UK, Australian CDR, Brazil, KSA/SAMA.
- Önemli: "for certification purposes it is now only necessary to run one test with each option" — kombinatoryal patlama sınırlanmış.
- DPoP (RFC 9449) desteği FAPI 2.0 conformance testlerine eklendi (OIDF duyurusu). ⚠️ Tam plan adı (`fapi2-security-profile-final-test-plan` gibi) hiçbir sayfada açıkça yazılı değil — DOĞRULANMADI.

### 1.3 FAPI-CIBA

[fapi_ciba_op_testing](https://openid.net/certification/fapi_ciba_op_testing/): plan adı "FAPI-CIBA: test plan". Variant örneği `poll-mtls`. **Poll modu zorunlu**, ping opsiyonel. OpenBanking UK için `openbankinguk-` prefix'li varyantlar. Uyarı: adında "client" geçen planlar OP testi için kullanılmaz.

### 1.4 OpenID Federation

[federation_testing](https://openid.net/certification/federation_testing/) — **3 test planı**:
1. Deployed Federation Entity Test (leaf/intermediate/trust anchor, metadata + federation endpoint yanıt yapısı)
2. Entity Joined to Test Federation — OP Test (suite RP + trust anchor rolü oynar, OP suite'i `authority_hints`'e eklemeli)
3. Entity Joined to Test Federation — RP Test (suite OP + trust anchor rolü)

Olgunluk uyarısı doğrudan sayfadan: **"the set of tests currently available in production are in an early stage."** Argus için düşük öncelik.

### 1.5 OpenID4VP / OpenID4VCI (bonus — Argus roadmap'i için)

Self-certification **26 Şubat 2026**'da açıldı: OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0 kapsamda; 38 yargı bölgesi bu spesifikasyonları seçmiş durumda ([openid.net](https://openid.net/openid-for-verifiable-credential-self-certification-to-launch-feb-2026/)).

### 1.6 MCP Conformance Suite

`github.com/modelcontextprotocol/conformance` — birincil README doğrulandı:

- **Ne test eder:** client tarafı (initialize handshake, tool invocation, OAuth akışları, metadata) ve server tarafı (initialize, capabilities, tools list/call, resources, prompts)
- **Nasıl çalışır:**
  ```
  npx @modelcontextprotocol/conformance server --url http://localhost:3000/mcp
  npx @modelcontextprotocol/conformance client --command "<cmd>" --scenario initialize
  ```
- **Spec versiyonları:** tarihli sürümler (2025-11-25'e kadar) ve draft (2026-07-28); iki lifecycle: stateful (initialize handshake) ve stateless (per-request metadata)
- **Expected-failures baseline:** YAML dosyasında bilinen hatalar baseline'lanabilir → CI yeşil kalırken regresyon yakalanır. **Per-check baselining** (`scenario:check-id`) var — tüm senaryoyu değil tek check'i muaf tutabilirsiniz. Stale baseline'lar da raporlanır.
- **Çıktı:** conformance check'ler (pass/fail) + **wire-schema validation** (JSON Schema'ya karşı, hem implementasyonun hem harness'ın gönderdiği mesajlar için sentetik check üretir)
- **CI:** repo bir GitHub Action (`action.yml`) içeriyor; `tier-check` subcommand'ı SEP-1730 tiering'e göre SDK değerlendiriyor

**Senaryo sayısı (repo ağacından sayıldı):** `src/scenarios/` altında 3 kategori:
- `authorization-server/` — **2 ana senaryo**: `authorization-code-grant`, `authorization-server-metadata` (+ bir `auth/` alt dizini) ⚠️ alt dizin içeriği sayılmadı
- `server/` — **~17 senaryo**: caching, dns-rebinding, elicitation-defaults, elicitation-enums, http-standard-headers, input-required-result, json-schema-2020-12, lifecycle, negative-mrtr, negative, prompts, resources, session-lifecycle, sse-multiple-streams, sse-polling, stateless, tools (+ `tasks/` alt dizini, `utils`)
- `client/` — sayılmadı ⚠️

Argus için en değerli kısım **`authorization-server` senaryoları**: Argus bir MCP server'ın koruduğu kaynak için authorization server rolü oynayacaksa, `authorization-server-metadata` (RFC 8414 / RFC 9728 protected resource metadata) ve `authorization-code-grant` doğrudan Argus'u test eder. Ayrıca `dns-rebinding` ve `http-standard-headers` senaryoları güvenlik açısından ilgili.

Tek scenario (`server-stateless`) içinde "over twenty" check olduğu README'de belirtiliyor — yani senaryo sayısı ≠ check sayısı; toplam check sayısı birkaç yüz mertebesinde. ⚠️ Kesin toplam DOĞRULANMADI.

### 1.7 SCIM

**Resmî bir OASIS/IETF conformance süiti YOK.** RFC 7643/7644 için IETF conformance programı yok; ekosistem satıcı araçlarıyla yürüyor. Bulunan araçlar:

| Araç | Ne yapar | Erişim | Not |
|---|---|---|---|
| **Microsoft Entra SCIM Validator** ([scimvalidator.microsoft.com](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/scim-validator-tutorial)) | Entra provisioning service ile uyumu doğrular. 3 mod: default attributes / **discover schema** (`/Schemas` üzerinden, önerilen) / upload Entra schema. Attribute değerleri için expression desteği (`{% generateRandomString 6 %}@contoso.com`) | Web, ücretsiz | Entra app store'a yayınlanacak connector'lar için **daha katı** kurallar uygular. Bilinen sorun: PATCH testlerinin farklı payload formatı yüzünden fail etmesi (Microsoft Q&A'da rapor edilmiş) |
| **Okta Runscope SCIM test suite** ([test guide](https://developer.okta.com/docs/guides/scim-provisioning-integration-test/main/)) | **13 ardışık işlem**: user create, assign, attribute update, deactivate, reactivate, remove | Runscope'a JSON import; değişkenler: `oktaAppId`, `oktaOrgUrl`, `oktaToken`, `SCIMUrl`, `SCIMAuth` | OIN yayını için ayrıca **manuel OIN test plan** gerekli. Kritik davranış: "Okta doesn't delete user profiles in your app, but instead marks the user record with `active=false`" |
| **scim2-tester** (python-scim, [GitHub](https://github.com/python-scim/scim2-tester)) | Discovery (`/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas`), CRUD, **PATCH add/remove/replace** (simple/complex/extension attribute), RFC7643+7644 | pip, kütüphane; CLI için `scim2-cli` | **CI için tasarlanmış**, tag-based filtering. 210 commit. Argus için en pratik programatik seçenek |
| **WSO2 scim2-compliance-test-suite** ([GitHub](https://github.com/wso2-incubator/scim2-compliance-test-suite)) | Users, Groups, Me, EnterpriseUser, ServiceProviderConfig/ResourceType/Schemas, **Bulk** | `scimproxycompliance.war` deploy | Apache-2.0, 43 commit, "ongoing project" — düşük aktivite ⚠️ |
| **SCIM Sandbox** ([scimsandbox.net](https://scimsandbox.net/)) | SCIM Server Manager + SCIM Compliance + SCIM Playground; herhangi bir SCIM 2.0 base URL'e pass/fail raporu | ⚠️ Site 403 döndü, doğrudan doğrulanamadı | Açık kaynak olduğu iddia ediliyor — DOĞRULANMADI |

**Test sayıları:** hiçbiri için resmî sayı yok (Okta'nın 13 operasyonu hariç). ⚠️

### 1.8 SAML

**Resmî conformance:** OASIS'in [saml-conformance-2.0-os](https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf) belgesi *conformance requirements*'ı tanımlar ama **çalıştırılabilir bir test süiti değildir**. Liberty Alliance interop testleri tarihsel: GSA E-Authentication programı 2007'de Liberty Alliance SAML 2.0 interop testini zorunlu kılmıştı; Liberty'nin sertifikasyon işlevi **Kantara Initiative**'e geçti ([Kantara SAML IOP snapshot](https://kantarainitiative.org/snapshot-saml-iop/)). Kantara'nın bugünkü çıktısı **normatif profil**: [SAML V2.0 Implementation Profile for Federation Interoperability](https://docs.kantarainitiative.org/fi/rec-saml2-implementation-profile-for-fedinterop.html) ve [saml2int Deployment Profile v2.0](https://kantarainitiative.github.io/SAMLprofiles/saml2int.html). Bunlar bir çek-listesi; otomatik koşan bir suite değil. ⚠️ Kantara'nın halen aktif bir SAML sertifikasyon programı işletip işletmediği DOĞRULANMADI.

**Pratikte çalıştırılabilir tek büyük SAML süiti: İtalyan SPID.**

Burada bir **düzeltme** yapmam gerekiyor. `italia/spid-saml-check` ([README](https://github.com/italia/spid-saml-check/blob/master/README.md), [README.it](https://github.com/italia/spid-saml-check/blob/master/README.it.md)):
- **"più di 300 controlli individuali, divisi in 7 famiglie"** — 300+ kontrol, 7 aile: 4 aile SP metadata formal validasyonu, 3 aile SP SAML request validasyonu, 1 aile (**111 kontrol**) IdP yanıtlarına karşı SP davranışının interaktif validasyonu
- **Bu süit Service Provider'ları test eder, Identity Provider'ları değil.** Araç bir test IdP'si gibi davranarak SP'yi sınar.
- Çalıştırma: `docker run -t -i -p 8443:8443 italia/spid-saml-check` → `https://localhost:8443`, giriş `validator/validator`
- Bileşenler: `spid-sp-test` (CLI), `spid-validator` (web UI), `spid-demo` (test IdP)

⚠️ **"263 test" rakamı doğrulanamadı** — birincil kaynakta geçen sayılar "300+" ve "111". 263 muhtemelen belirli bir profil/varyant için filtrelenmiş bir alt küme veya eski bir sürümün rakamı. Bu iddiayı düzeltmenizi öneririm.

**IdP tarafı için:** ayrı bir repo var — [`AgID/spid-saml-check-idp`](https://github.com/AgID/spid-saml-check-idp), "SPID SAML Conformance Test Tool for IdP", Apache-2.0. **Ancak olgunluk çok düşük: 4 star, 1 fork, 51 commit.** Docker yok; Node.js v22 + libxml2-utils gerektiriyor, elle sertifika üretimi, `node server/spid-saml-check-idp`. README test aileleri veya sayı belirtmiyor. ⚠️ IdP tarafında ne test ettiği DOĞRULANMADI — Argus için ancak keşif amaçlı denenebilir, güvenilir bir doğruluk ölçütü değil.

`italia/spid-sp-test` (EUPL-1.2): CLI, **13 profil** (saml2-sp, spid-sp-public, spid-sp-private, CIE/eIDAS varyantları). "Send a huge number of fake SAML Response" modu var — yani SP'nin kötü niyetli IdP yanıtlarına dayanıklılığını test ediyor. Argus **IdP olduğu için** bu araç doğrudan Argus'u test etmez; ama Argus'un SP entegrasyonlarını (SAML federation/broker rolü) test etmek için kullanılabilir.

### 1.9 LDAP

Resmî bir RFC 4511 conformance süiti **yok**. Mevcut olanlar:
- **OpenLDAP kendi test süiti:** kaynak ağacında `make test`; backend başına testler (`test000-rootdse` gibi numaralı testler). Bu OpenLDAP'ın *kendi* regresyon süiti — üçüncü taraf sunucuya kolayca yöneltilemez ⚠️ (harici sunucuya karşı çalıştırılabilirliği DOĞRULANMADI).
- `slaptest(8)` — sadece slapd konfigürasyonunu doğrular, protokol conformance ile ilgisi yok.
- Pratik yaklaşım: `ldapsearch`/`ldapmodify`/`ldapwhoami` ile davranışsal doğrulama + gerçek istemcilerle interop (SSSD, nslcd, Apache Directory Studio, JNDI, `ldap3` Python, .NET `System.DirectoryServices`).
- Yük testi: **`ldclt`** (389-ds-base ile gelir; async ops, çok thread, search/add/delete/bind) ve **SLAMD** (Neil Wilson/Sun kökenli, LDAP'a özel benchmark tezgâhı). Docker test hedefi: `rroemhild/docker-test-openldap`.

### 1.10 WebAuthn / FIDO

**RP (server) tarafı test edilebiliyor — evet.** FIDO Conformance Tools masaüstü uygulaması "Server Tests" çalıştırıyor.

- **Erişim:** FIDO Alliance'a **Test Tool Access Request formu** doldurup indirme talebi gönderilir; spesifikasyon dropdown'ından FIDO2 seçilir. Onay sonrası e-postayla kimlik bilgileri + indirme linki gelir ([SimpleWebAuthn FIDO Conformance rehberi](https://simplewebauthn.dev/docs/advanced/fido-conformance)). **Üyelik gerekliliği açıkça belirtilmiyor** ⚠️ — sadece formal talep + onay süreci var. Sertifikasyon ücretleri ayrı ve ödeme yapılana kadar işlenmiyor ([FIDO certification submission](https://fidoalliance.org/certification/functional-certification/certification-submission/)); ücret tutarları sayfada yayımlanmamış ⚠️.
- **Sunucunun sunması gereken 4 REST endpoint'i** ([FIDO Conformance Test API](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Server/Conformance-Test-API.md)): `POST /attestation/options`, `POST /attestation/result`, `POST /assertion/options`, `POST /assertion/result`. Bu, conformance testi *için* tanımlanmış non-normatif bir API — yani Argus'un üretim API'sinden farklı; **test-only adapter yazmak gerekir.**
- **Test sayısı:** SimpleWebAuthn dokümanındaki örnek çıktı **160 test pass** gösteriyor. ⚠️ Bu resmî bir "160 test" beyanı değil, bir örnek koşu çıktısı — FIDO'nun kendi dokümanında sayı belirtilmiyor.
- Sertifikasyon yolu: conformance self-validation **+ interoperability testing event** → submission. Argus sertifika hedeflemediği için sadece self-validation kısmı ilgili.
- **Ücretsiz alternatif — CI için asıl pratik yol:** Chrome DevTools Protocol **Virtual Authenticator** ([CDP WebAuthn domain](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/), [Chrome docs](https://developer.chrome.com/docs/devtools/webauthn/)). CTAP2/USB + resident key emülasyonu, WebAuthn UI kapatılabilir. Playwright/Puppeteer üzerinden sürülür. **Sınır: yalnızca Chromium** — Safari/WebKit ve Firefox desteklemiyor. ⚠️ Rust'ta bir `softauthn` benzeri authenticator kütüphanesi araştırmamda doğrulanamadı.

### 1.11 OAuth genel

- **OAuch** ([DistriNet/OAuch](https://github.com/DistriNet/OAuch), [oauch.io](https://oauch.io/)) — açık kaynak OAuth 2.0 authorization server güvenlik/threat-model uyum analizörü. **195 test case, 13 kategori** ([oauch.io/Tests](https://oauch.io/Tests)): Document Support (10), Feature Support (19), Token Endpoint (30), Device Authorization Endpoint (5), Access & Refresh Tokens (9), Identity Tokens (15), JWTs (11), PKCE (8), Revocation (8), Concurrency (5), Authorization Endpoint (26), API Endpoint (8). OIDC provider'ları da destekliyor. Akademik temel: RAID 2022 makalesi "OAuch: Exploring Security Compliance in the OAuth 2.0 Ecosystem" — 100 kamuya açık IdP taranmış; ortalama IdP güvenlik şartlarının **%34'ünü** (zorunluların %20'sini) uygulamıyor, **97 IdP'de en az bir tehdit tamamen azaltılmamış**, IdP başına ortalama 4 azaltılmamış tehdit. **Argus için OIDF suite'inden sonraki en yüksek değerli araç budur** — çünkü OIDF suite'i "spec'e uyuyor mu"yu, OAuch "BCP/threat model'i karşılıyor mu"yu ölçer.
- **OSBT** (OIDC Scenario-Based Tester, [GitHub](https://github.com/oidc-scenario-based-tester/osbt), CODE BLUE 2023) — Python'da esnek OAuth/OIDC senaryoları; mitmproxy eklentisiyle HTTP trace manipülasyonu; **kötü niyetli OP** simülasyonu ("Attacker OP"); GitHub Actions entegrasyonu. Argus **IdP** olduğu için "attacker OP" kısmı doğrudan uygulanmaz — ama Argus'un upstream IdP broker'ı (social login / federation) için **birebir** uygun.
- **oauth.tools** (Curity) — ücretsiz online debugger; JWT decode/create, token alma, revocation, external API çağrılarına token ekleme; paylaşılabilir/import-export edilebilir workspace. Gereklilik: **OAuth servisleri internetten erişilebilir olmalı** — yani lokal Argus için tünel gerekir. Manuel keşif aracı, CI aracı değil.
- **Authlete** — OIDF conformance suite'e test ortamı ve PAR/FAPI/DPoP kod katkısı yapmış; suite wiki'sinde "Authlete Automated Example Configuration" sayfası var (otomasyon için referans config örneği).
- ⚠️ `mod_auth_openidc` test setleri — özel bir conformance test seti olarak DOĞRULANMADI; bilinen kullanımı bir RP implementasyonu olması.

---

## 2. Interop Testi — Gerçek Karşı Taraflarla

### 2.1 Ücretsiz/sandbox erişimi olan SP'ler

| Karşı taraf | Erişim | Doğrulama durumu |
|---|---|---|
| **Okta** | Integrator Free Plan org ücretsiz oluşturulabilir; **SCIM provisioning free tier'da etkinleştirilebilir** (Provisioning tab → SCIM → Configure API integration). Private SCIM integration instance'ı sadece oluşturulduğu org'da kullanılabilir. | Doğrulandı ([Okta devforum](https://devforum.okta.com/t/scim-provisioning-support-in-free-tier/35338), [Okta docs](https://developer.okta.com/docs/guides/scim-provisioning-integration-connect/main/)) |
| **Microsoft Entra ID** | Ücretsiz tenant + custom SCIM endpoint desteği; SCIM Validator ayrıca ücretsiz web aracı | Doğrulandı; ⚠️ hangi Entra SKU'sunun outbound app provisioning'i içerdiği (P1 gerekiyor mu) DOĞRULANMADI — bu **önemli bir maliyet riski** |
| **Salesforce** | Developer Edition org'lar ücretsiz; SAML SP olarak konfigüre edilebilir. **Uyarı: Summer '26 sürümü tek-konfigürasyonlu SAML SSO framework'ünü kaldırıyor**, tüm müşteriler multi-configuration SAML'a geçmeli (sandbox preview 8 Mayıs 2026, production 15 Mayıs / 5 Haziran / 12-13 Haziran 2026) | Doğrulandı ([Salesforce Ben](https://www.salesforceben.com/salesforce-summer-26-release-everything-you-need-to-know-before-go-live/), [Salesforce Help](https://help.salesforce.com/s/articleView?id=release-notes.rn_security_verify_saml_integrations.htm)) — Argus SAML çıktısının bu yeni framework'le test edilmesi gerek |
| **ServiceNow** | Personal Developer Instance (PDI) ücretsiz | ⚠️ DOĞRULANMADI — arama sonuçlarında PDI'nin SAML SSO'yu desteklediğine dair birincil kaynak bulamadım |
| **Workday, Slack, Zoom, Atlassian, AWS IAM Identity Center, Google Workspace** | — | ⚠️ DOĞRULANMADI — hiçbiri için ücretsiz developer/sandbox tier'ın SAML/SCIM içerdiğini birincil kaynaktan doğrulayamadım. Google Workspace özelinde: WorkOS'a göre **"Google does not support SCIM publicly"** — sadece veri çekilebilir, push edilemez ([WorkOS, 15 Kasım 2024](https://workos.com/blog/scim-challenges)) |

**Pratik sonuç:** Ücretsiz ve güvenilir şekilde erişilebilen gerçek karşı taraflar **Okta + Entra + Salesforce DE** üçlüsü. Diğerleri için ya ücretli tier ya da partner programı gerekiyor. Kalan SP'ler için **davranış emülasyonu** (aşağıya bakın) tek gerçekçi yol.

### 2.2 SCIM istemcilerinin çelişkili davranışları — doğrulanmış liste

[WorkOS "SCIM challenges", 15 Kasım 2024](https://workos.com/blog/scim-challenges) birincil olarak en zengin kaynak. Doğrulanan farklar:

| Konu | Okta | Entra ID |
|---|---|---|
| **Deprovisioning** | `PUT`/`PATCH` ile `active=false` — DELETE kullanmaz | **`DELETE` endpoint'ini kullanır** (ayrıca `PATCH /Users/{id}` + `active:false`) |
| **Group membership** | PATCH ve PUT ikisini de destekler; OIN template'lerinde default PATCH | **Sadece PATCH add/remove gönderir; 200 OK aldıktan sonra üyeleri bir daha doğrulamaz** — kendini source of truth kabul eder, full reconciliation yapmaz |
| **Senkron sıklığı** | Gerçek zamanlı | Default **40 dakika** (veya on-demand) |
| **Suspended user** | Kullanıcı suspend edildiyse grup üyelik değişikliklerini bildirmez | Hâlâ provisioned bir grupta olan kullanıcıyı suspend etmez |
| **Custom attribute** | `urn:ietf:params:scim:schemas:core:2.0:User` prefix'li custom attribute'ları **top-level** olarak işler | Schema extension prefix'i ve **nested** yapı bekler |
| **Filtreleme** | `meta.lastModified` ile filtrelemeyi desteklemez | Cloud-managed vs synchronized kullanıcılar için e-posta alımı farklı |
| **Group push** | Destekler; push için assignment'tan ayrı gruplar gerekir | — |

Diğerleri: **OneLogin** kullanıcıyı suspend etmek yerine siler, sadece grup üyeliğiyle provision eder. **JumpCloud** grup silindiğinde başka aktif grupta olmayan tüm üyeleri disable eder. Genel: `externalId` tutarlı biçimde benzersiz kimlik olarak kabul edilmiyor; bulk operations opsiyonel ve desteği tutarsız; e-posta çoğu yerde zorunlu değil → geçersiz event üretiyor.

**Ek doğrulanmış tehlike (Argus tasarımı için):** Entra 2000 üyeli bir grup güncellemesi gönderdiğinde, sunucu her PATCH'te tüm `members` dizisini replace ediyorsa ve request timeout olursa **kısmi state** (2000 yerine 1200 üye) kalır ve Entra bunu hiç doğrulamaz. Yani Argus'un SCIM group PATCH'i **atomik ve idempotent** olmalı, `replace` semantiği asla kısmi uygulanmamalı.

Microsoft Q&A'da rapor edilmiş iki gerçek dünya sorunu: (a) SCIM Validator PATCH testlerinin farklı payload formatı yüzünden fail etmesi, (b) başarılı üye eklemesinden sonra **tekrarlayan PATCH /Groups çağrıları**.

### 2.3 Sandbox kurulumu — pratik reçete

1. **Okta Integrator Free Plan** org aç → private SCIM integration ekle → Argus'un SCIM base URL'i + bearer token → **Runscope 13-adımlı CRUD suite**'ini koştur.
2. **Entra ücretsiz tenant** → Enterprise application → non-gallery app → Provisioning → SCIM. Ayrıca `scimvalidator.microsoft.com`'u "Discover schema" modunda Argus'a yönelt.
3. Argus lokal olduğu için her ikisi de **public erişilebilir URL** ister → ngrok/cloudflared tüneli veya ephemeral preview environment gerekir. Bu, bu katmanın **CI'da her PR'da koşamayacağı** anlamına gelir (aşağıdaki tabloda nightly).
4. Yakalanan gerçek trafiği **kaydet** (HAR/JSON) ve bir **"IdP client emulator"** test fixture'ına dönüştür — böylece Okta/Entra davranışları hermetik olarak, tünelsiz, her PR'da replay edilebilir. Bu, ücretsiz tier'ı olmayan SP'ler (Workday, ServiceNow, Slack) için de tek ölçeklenebilir yaklaşım.

### 2.4 Test matrisi ne kadar büyür

Naif çarpım:
- Protokoller (N): OIDC, OAuth 2.1, SAML 2.0, SCIM 2.0, LDAP, WebAuthn, MCP = **7**
- Karşı taraflar (M): protokol başına gerçekçi olarak 3–8 (SCIM: Okta/Entra/OneLogin/JumpCloud/Google = 5; SAML: Salesforce/ServiceNow/AWS/Slack/Atlassian/Zoom/Workday = 7; OIDC RP: 5+)
- Senaryolar (K): happy path, hata yolları, çok kiracılık izolasyonu, token/session lifecycle, anahtar rotasyonu, deprovisioning ≈ 10–20

7 × 6 × 15 ≈ **~630 interop kombinasyonu**. Bu, tam kombinatoryal koşumun **imkânsız** olduğu anlamına gelir.

Matrisi kırmanın yolu — üç eksende ayrıştırma:
1. **Protokol doğruluğu** (karşı taraftan bağımsız): conformance süitleri. N × K, M yok. ~7 × 15 = 105.
2. **Karşı taraf tuhaflıkları** (protokolden bağımsız değil ama senaryodan büyük ölçüde bağımsız): her karşı taraf için **davranış profili** olarak kodlanır (deprovisioning yöntemi, PATCH semantiği, filtre desteği, sync sıklığı). M × (küçük profil kontratı) ≈ 5–8 profil × ~10 assertion = 60–80.
3. **Gerçek uçtan uca smoke**: sadece kritik çiftler için, nightly/haftalık. ~10 kombinasyon.

Toplam ~200 anlamlı test, 630 yerine. **Pairwise/combinatorial test tasarımı** burada doğal yaklaşım.

---

## 3. Yük Testi — IdP'ye Özgü

### 3.1 keycloak-benchmark — birincil sayılar

Proje: [keycloak/keycloak-benchmark](https://github.com/keycloak/keycloak-benchmark). **Gatling tabanlı** (doğrulandı). Üç modül:
- **benchmark** — Gatling load testleri
- **provisioning** — minikube (Grafana observability ile) + docker-compose
- **dataset** — "a Keycloak add-on that can create entities in a Keycloak data store to prepare it for a load test" ← **Argus için doğrudan kopyalanabilir fikir**

Senaryolar (repo ağacından, [scenario/](https://github.com/keycloak/keycloak-benchmark/tree/main/benchmark/src/main/scala/keycloak/scenario)): paketler `_private`, `admin`, `authentication`, `basic`; ortak sınıflar `CommonSimulation.scala`, `KeycloakScenarioBuilder.scala`. `authentication/` altında: **`AuthorizationCode.scala`, `ClientSecret.scala`, `LoginUserPassword.scala`**. `basic/` altında `Get.scala`. Ayrıca dokümantasyonda `ListSessions`, `CreateRealms` geçiyor.

Konfigürasyon ([benchmark guide](https://www.keycloak.org/keycloak-benchmark/benchmark-guide/latest/configuration)) — **açık ve kapalı model ikisi de var**:
- `--users-per-sec` (default 1) → **open workload model**
- `--concurrent-users` → closed workload model
- `--ramp-up` (default 5s), `--measurement` (default 30s), `--user-think-time` (default 0)
- `--realms`, `--users-per-realm`, `--clients-per-realm` ← **çok kiracılık ölçekleme parametreleri, Argus için birebir**
- `--sla-error-percentage` (default 0), `--log-http-on-failure`

### 3.2 Yayımlanmış Keycloak 26.4 sonuçları — en değerli veri

[keycloak.org/2025/10/keycloak-benchmark](https://www.keycloak.org/2025/10/keycloak-benchmark) (Ekim 2025):

| Logins/sn | Token refresh/sn | Pod CPU | Pod RAM | DB instance |
|---|---|---|---|---|
| 500 | 2,500 | 24 | 4 GB | db.r8g.2xlarge |
| 1,000 | 5,000 | 40 | 8 GB | db.r8g.4xlarge |
| 2,000 | 10,000 | 74 | 8 GB | db.r8g.16xlarge |

**Sizing formülleri (birincil):**
- **1 vCPU ≈ 15 login/sn**
- **1 vCPU ≈ 120 refresh token request/sn**
- Trafik sıçramaları için **%150 headroom** önerisi

**Darboğaz cevabı net: login, refresh'ten ~8× pahalı.** Kapasite planlaması login/sn üzerinden yapılır.

Diğer doğrulanmış bulgular:
- **Ağ gecikmesine aşırı hassasiyet:** multi-zone deployment'ta **10 ms** gecikme p99 yanıt süresini **47 ms → 84 ms** yaptı. Argus çok-bölgeli olacaksa bu tek başına tasarım kısıtı.
- **DB CPU:** Aurora %77'de tepe yaptı; Keycloak cache 10K→200K entry çıkarılınca DB yükü **%63**'e düştü.
- **Login/refresh oranı 1:5** — bu, benchmark'ın seçtiği profil; yayımlanmış *üretim* oranı değil.

**Yük profili — yayımlanmış üretim verisi:** ⚠️ **DOĞRULANMADI.** Auth0/Okta'nın gerçek login:refresh:introspection oranlarını yayımladığına dair birincil kaynak bulamadım. Bulunabilenler sadece rate limit'ler (Okta Identity Engine: kullanıcı başına 5 saniyede 20 istek; Google: OAuth client ID başına hesap başına 100 refresh token). Keycloak'ın 1:5 login:refresh oranı elimizdeki **tek gerekçelendirilebilir başlangıç noktası**. Introspection oranı için hiçbir yayımlanmış veri yok — ancak mimari olarak: JWT access token kullanılırsa introspection ≈ 0; opaque token kullanılırsa introspection **her API çağrısı** demektir, yani login'den **2-3 kat büyüklük** fazla olabilir. Argus opaque token destekleyecekse introspection'ın en yüksek hacimli endpoint olacağını varsaymak güvenli.

Gatling raporlamasında Keycloak p99'u alıyor ([standard report guide](https://www.keycloak.org/keycloak-benchmark/benchmark-guide/latest/report/standard-report)).

⚠️ Keycloak ekibi Gatling'den memnun değil: [issue #1087 "Evaluate potential Gatling successors"](https://github.com/keycloak/keycloak-benchmark/issues/1087) açık.

### 3.3 Coordinated omission — hangi araç doğru ölçer

**Problem:** load generator, SUT yavaşladığında istek gönderimini istemeden yavaşlatır → tail latency spike'ları ölçümden düşer. Klasik generator'lar latency'yi "gönderim → yanıt" arası ölçer; bu model yüksek gecikme artefaktlarının çoğunu göz ardı eder.

**Doğru ölçen araçlar:**

| Araç | CO durumu | Detay |
|---|---|---|
| **wrk2** | ✅ Doğru | Gil Tene'nin wrk fork'u. `-R` sabit hız bayrağı + **HdrHistogram**. Latency'yi *gerçekte gönderildiği an*dan değil, **konfigüre edilen throughput'a göre gönderilmesi gereken an**dan ölçer ([giltene/wrk2](https://github.com/giltene/wrk2)) |
| **k6** | ✅ Şartlı | **`constant-arrival-rate` executor** ile doğru; **default executor'lar (`shared-iterations`, `constant-vus`) CO'ya açık.** Doğrulanmış opsiyonlar: `rate` (zorunlu), `timeUnit` (default `1s`), `duration` (zorunlu), `preAllocatedVUs` (zorunlu), `maxVUs`. Iteration'lar "start independently of system response", 10/sn'de ~100 ms aralıkla. **Kritik uyarı (dokümandan):** "Using too low of a `preAllocatedVUs` setting will reduce the test duration at the desired rate" — VU havuzu yetersizse hedef hız tutturulamaz ve **CO sessizce geri gelir** ([k6 docs](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/)) |
| **Gatling** | ✅ Şartlı | `--users-per-sec` (open model) mevcut. ⚠️ Gatling'in CO'yu spesifik olarak nasıl ele aldığına dair birincil kaynak bulamadım — DOĞRULANMADI |
| **Locust** | ⚠️ | Open/closed model ayrımını dokümante ediyor; her user bir greenlet → tek-node throughput'u k6'dan düşük |
| **Vegeta, autocannon** | ✅ | wrk2'nin open-loop yaklaşımını benimsemişler |
| **oha** | ❌/⚠️ | Rust, TUI'li hey/wrk alternatifi. **CO açısından doğruluğu doğrulanmadı** — smoke test için uygun, kapasite ölçümü için değil |

**Argus için sonuç:** kapasite sayıları **k6 `constant-arrival-rate`** veya **wrk2** ile üretilmeli; `preAllocatedVUs`/`maxVUs` mutlaka bilinçli ayarlanmalı ve k6'nın "dropped_iterations" metriği fail koşulu yapılmalı.

### 3.4 Argon2 yük testini nasıl bozar — ve istemci tarafında ne gerekir

Doğrulanmış gerçekler:
- Keycloak'ta Argon2'ye geçiş **JVM'de Major GC artışı ve yüksek CPU** yarattı, "applications behave abnormally during medium to high load" ([keycloak issue #29033](https://github.com/keycloak/keycloak/issues/29033))
- Argon2/scrypt **memory-hard** → GPU/ASIC direnci yüksek ama **bu bellek maliyeti eşzamanlılığı (concurrency) düşürür** ([MojoAuth](https://mojoauth.com/blog/password-hashing-performance-cpu-bottlenecks-high-traffic))
- **Aritmetik:** 200 eşzamanlı login × 64 MiB = **12.8 GiB RAM** talebi. `memoryCost` **ortalamaya değil, tepe eşzamanlılığa** göre boyutlandırılmalı
- Öneri: **lanes (parallelism) = 1** tutun ki bir hash bir core'a eşlensin, birkaç core'a değil; worker pool'u hem CPU hem RAM bütçesine göre sınırlayın
- Hedef: verification **300 ms altında** kalırken sunucunun sürdürebileceği bellek maliyetini maksimize edin; **üretime denk donanımda** benchmark edin

**İstemci tarafında CPU-bound endpoint'i test etmek için gerekenler:**

1. **Kapalı model (concurrent-users) kullanmayın** — SUT yavaşladıkça istemci de yavaşlar, gerçek doygunluk noktası hiç görünmez. **Open model / constant arrival rate zorunlu.**
2. **Load generator ayrı makinede olmalı.** Argon2 memory-hard olduğu için aynı makinedeki generator, SUT'un cache'ini ve bellek bant genişliğini çalar → ölçüm kirlenir. Bu, HTTP-bound endpoint'lerde önemsiz, Argon2'de belirleyici.
3. **Kuyruk derinliğini ve reddedilen istekleri ayrı ölç.** Argon2 doyduğunda sistem latency artışı yerine **kuyrukta biriktirme** yapar; sadece p99 latency'ye bakan bir test doygunluğu geç fark eder. `dropped_iterations` (k6) / admission control reddi metrik olmalı.
4. **Ayrı bir "hash-only" mikro-benchmark** tutun (Rust `criterion`), böylece Argon2 parametre değişikliğinin etkisi HTTP gürültüsünden bağımsız görünür.
5. **Login yükünü refresh/introspection yükünden ayrı senaryolarda çalıştırın**, sonra karışık profilde. Keycloak'ın 15 vs 120 req/vCPU farkı, karışık profilde login'in kaynak açlığına yol açacağını gösteriyor — **bulkhead/ayrı thread pool** tasarımının test edilmesi gereken bir davranış olduğu anlamına gelir.
6. **Boyut için formül:** hedef login/sn × Argon2 verification süresi = gerekli eşzamanlı hash sayısı; × memoryCost = gerekli RAM. 500 login/sn × 300 ms = 150 eşzamanlı hash × 64 MiB ≈ **9.6 GiB** sadece hashing için.

---

## 4. Kaos ve Dayanıklılık Testi

### 4.1 Deterministic Simulation Testing (DST) — genel

**FoundationDB modeli** ([apple.github.io/foundationdb/testing.html](https://apple.github.io/foundationdb/testing.html), [Pierre Zemb analizi](https://pierrezemb.fr/posts/diving-into-foundationdb-simulation/)):
- Tüm bir cluster'ı **tek thread'li tek process** içinde deterministik simüle eder
- Anahtar fikir: **aynı kod hem production hem simülasyonda çalışır**, sadece interface implementasyonları takas edilir. Nondeterminizmin tüm kaynakları soyutlanır: network, disk, zaman, PRNG
- `deterministicRandom()` — seeded PRNG tüm rastgeleliği değiştirir
- Flow (actor-based concurrency dili) ile sıkı entegre
- Ölçek: her gece on binlerce simülasyon; toplamda ~**1 trilyon CPU-saat** eşdeğeri
- FDB ekibi diske gerçek veri yazmadan **18 ay** simülasyon framework'ü inşa etti

**TigerBeetle VOPR** ([docs/internals/vopr.md](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/internals/vopr.md)):
- Viewstamped Replication protokolünü, network simülatörü + in-memory storage fault simülatörüyle tek process'te fuzz'lar
- **Zamanı istediği kadar hızlandırır** — "one minute of VOPR time ≈ days of real-world testing"
- **State checker**: tüm replica'lara hook, her state transition anında doğrulanır, **kriptografik hash chaining** ile nedensellik kanıtlanır
- Determinizm **seed + git commit** ile → bug'lar birebir reproduce edilir
- İlham kaynakları: WarGames filmi, Dropbox Nucleus, FoundationDB
- Devam eden çalışma: ["Protocol-Aware Deterministic Simulation Testing" (20 Ağustos 2026)](https://tigerbeetle.com/blog/2026-08-20-protocol-aware-dst/) ve ["A Tale Of Four Fuzzers" (28 Kasım 2025)](https://tigerbeetle.com/blog/2025-11-28-tale-of-four-fuzzers/)

**Antithesis** ([antithesis.com/docs](https://antithesis.com/docs/resources/deterministic_simulation_testing/)):
- **Deterministik hypervisor** içinde normal, non-deterministik yazılımı çalıştırır → **sistemi yeniden tasarlamadan** DST. Container image yüklenir, üretim replikası deterministik hypervisor'da boot edilir.
- Ele aldıkları nondeterminizm: clock, thread interleaving, sistem randomness'ı
- Tradeoff'lar (dokümandan): "Setting up a deterministic simulation environment is a complex, resource-intensive undertaking", "Not every system can be designed in a way that enables DST", harici bağımlılıklar mock'lanmalı
- **Fiyat:** CPU-hour bazlı; enterprise müşteriler tipik olarak **yıllık $20K–$100K+** ([Sacra](https://sacra.com/c/antithesis/)). Aralık 2025'te Jane Street liderliğinde **$105M Series A** ([PRNewswire](https://www.prnewswire.com/news-releases/jane-street-leads-antithesiss-105m-series-a-to-make-deterministic-simulation-testing-the-new-standard-302631076.html))
- **Argus için:** fiyat prohibitif; ancak "sistemi yeniden tasarlamadan" özelliği, library-level DST'ye göre entegrasyon maliyetini sıfırlıyor. **Erken aşamada hayır, ürün olgunlaştığında yeniden değerlendir.**

### 4.2 Rust'ta uygulanabilirlik

| Araç | Ne yapar | Olgunluk | Argus'a uygunluk |
|---|---|---|---|
| **turmoil** ([tokio-rs/turmoil](https://github.com/tokio-rs/turmoil)) | Tek thread'de birden fazla eşzamanlı host; network ve filesystem'e latency, drop, partition, crash, **torn write** enjekte eder; manuel kontrol veya seeded RNG. Crate ailesi: `turmoil`, `turmoil-net` (`tokio::net` yerine), `turmoil-fs` (`std::fs`/`tokio::fs` yerine), `turmoil-io-uring` | **1.3k star**, aktif geliştirme, MIT. Tokio ekibi 2023'te duyurdu ve "**the crate is still experimental**" dedi ([tokio.rs duyurusu](https://tokio.rs/blog/2023-01-03-announcing-turmoil)). ⚠️ TLS desteği, tokio versiyon kısıtları ve desteklenmeyen özellikler README'de açıkça yazılı **değil** — DOĞRULANMADI | **Orta.** Argus'un Postgres'e gerçek TCP ile bağlanması turmoil altında `turmoil-net`e taşınmayı gerektirir; `tokio-postgres` doğrudan çalışmayabilir. En pratik kullanım: **Argus node'ları arası** (epoch/cache invalidation propagation) simülasyonu — DB'yi mock'layarak |
| **madsim** ([madsim-rs/madsim](https://github.com/madsim-rs/madsim)) | tokio-benzeri ama deterministik runtime. `madsim-tokio` ile bağımlılık takası, `RUSTFLAGS="--cfg madsim" cargo test`. **Simülatör paketleri: tokio, tonic (gRPC), etcd-client, rdkafka, aws-sdk-s3.** Ayrıca yamalı `quanta`, `getrandom`, `tokio-retry`, **`tokio-postgres`**, `tokio-stream` | 1.2k star, 343 commit, Apache-2.0. **RisingWave (dağıtık stream-processing SQL DB) production'da kullanıyor** — bu en güçlü olgunluk sinyali | **Yüksek.** `tokio-postgres` yaması olması Argus için belirleyici — Postgres istemcisi simülasyon altında çalışabilir. ⚠️ API kapsama yüzdesi ve performans overhead'i dokümante değil |
| **mad-turmoil** | madsim'in libc symbol override yaklaşımıyla turmoil-tabanlı DST'yi birleştirir; CI'da "meta test" aynı seed'i yeniden koşup TRACE seviye logları byte-byte karşılaştırıyor | Yeni, düşük olgunluk ⚠️ | Deneysel |
| **Shuttle** ([awslabs/shuttle](https://github.com/awslabs/shuttle)) | **Randomized concurrency testing.** Thread scheduling'i kontrol eder, heuristik'li rastgele scheduling. `tokio` ve `rand` wrapper'ları + `std::sync`/`std::collections` primitifleri. **Async destekli** | 1.1k star, 319 commit, crates.io'da yayımlı | **Yüksek — dar kapsamda.** Açık tradeoff (repo'dan): "**not sound** (a passing Shuttle test does not prove the code is correct), but it scales to much larger test cases than **Loom**". Argus'ta hedef: session store, cache invalidation, connection pool, rate limiter gibi paylaşımlı-durum bileşenleri |
| **stateright** ([stateright/stateright](https://github.com/stateright/stateright)) | **Model checker** — rastgele alt küme değil, spesifikasyon içindeki **tüm gözlemlenebilir davranışları** test eder. Actor modeli + gömülü model checker + keşif UI + hafif actor runtime. **Linearizability tester** içerir ("more exhaustive coverage than similar solutions such as Jepsen"). `always` (safety/invariant) ve `sometimes` (erişilebilirlik) property'leri. Örnekler: Single Decree Paxos, two-phase commit | Kitap var ([stateright.rs](https://www.stateright.rs/getting-started.html)); ⚠️ 2025-2026 aktivitesi doğrulanmadı | **Orta.** Argus'un tam sistemini modellemek pahalı; **protokol state machine'lerini** (OAuth authorization code lifecycle, DPoP nonce, CIBA poll, session/logout propagation) modellemek için ideal |

### 4.3 Jepsen — bir IdP'ye uygulanabilir mi?

**Kısmen — ama doğrudan değil.** Jepsen linearizability/isolation ihlallerini arar; bunun için sistemin **okuma/yazma geçmişi** üretmesi gerekir. Bir IdP'nin çoğu endpoint'i bu kalıba oturmaz; ancak şunlar oturur:
- Session store (create/read/revoke) — linearizability sorusu anlamlı
- Refresh token rotation — **çift kullanım tespiti** (reuse detection) tam olarak bir concurrency/isolation problemi
- Consent/grant kayıtları
- Multi-tenant konfigürasyon (epoch) propagasyonu

**Jepsen'in PostgreSQL analizleri var — ve doğrudan Argus'u ilgilendiriyor:**

[Jepsen: Amazon RDS for PostgreSQL 17.4, 29 Nisan 2025](https://jepsen.io/analyses/amazon-rds-for-postgresql-17.4):
- Test edilen: RDS multi-AZ cluster'lar (13.15–17.4), primary **ve read-only** endpoint'lere karşı
- Workload: benzersiz integer listeleri üzerinde read/append transaction'ları; Elle checker
- **Bulgular: Snapshot Isolation ihlalleri — G-nonadjacent cycle'lar ve Long Fork.** ~150 write/sn + 1600 read/sn gibi mütevazı eşzamanlılıkta **"every few minutes"** gerçekleşiyor. **Fault injection yok** — yani normal çalışmada
- Sonuç: RDS muhtemelen standart SI yerine **Parallel Snapshot Isolation** sağlıyor; "**this behavior should not occur in standard PostgreSQL**"

**Argus için doğrudan çıkarım:** Read replica'lardan okuma yapan bir IdP, RDS/Aurora üzerinde **tek-node Postgres'ten zayıf** izolasyon garantileri alır. Epoch/revocation propagasyonu "read-your-writes" varsayımına dayanıyorsa bu **güvenlik açığıdır** (revoke edilmiş bir token'ın replica'da hâlâ geçerli görünmesi). Bu, Argus'un test etmesi gereken **birinci sınıf bir senaryo**.

[Jepsen 18: "Serializable Mom" (20 Haziran 2025)](https://jepsen.io/blog) — Bufstream 0.1.0, Amazon RDS for PostgreSQL 17.4, TigerBeetle 0.16.1 kapsıyor.

**Patroni:** resmî bir Jepsen analizi **yok**; ancak bağımsız bir çalışma var — [Bin Wang, 2 Aralık 2024](https://www.binwang.me/2024-12-02-PostgreSQL-High-Availability-Solutions-Part-1.html): Patroni üzerinde Jepsen testi **read committed isolation ihlali** olan bilinen bir sorunu reproduce etti ve 3 node'dan 1'i kaybedildiğinde cluster'ın **toparlanamadığını** gözlemledi. ⚠️ Bu birincil Jepsen raporu değil, bağımsız blog — ihtiyatla kullanılmalı.

### 4.4 Postgres failover / split-brain — somut kaos senaryoları

**CloudNativePG split-brain reprodüksiyonu — en değerli somut veri.** [Coroot, 29 Temmuz 2026](https://coroot.com/blog/reproducing-split-brain-on-cloudnativepg/):
- Kurulum: 5-node k3s (v1.34.5+k3s1), CloudNativePG **1.30.0**, PostgreSQL **18.4**, **Chaos Mesh 2.7.2** NetworkChaos; 3 client sürekli yazıyor
- Deney: primary pod'u replica'lardan, operator'dan ve API server'dan izole et
- **Ne oldu:** isolation check doğru çalıştı ve ~34. saniyede pod termination tetikledi — **ama primary 177 saniye daha yazmaya devam etti**, çünkü default `smartShutdownTimeout: 180`. Promote edilen replica bu sırada yazmaya başladı → **~99 saniyelik çift-primary penceresi**, her ikisi de commit ACK'liyor
- **Hasar:** partition iyileştikten ve `pg_rewind` bir survivor seçtikten sonra: **562 write farklı client'lara ID reassign edildi**, **291 write tamamen kayboldu**; ACK'lenmiş 1,472 write'ın sadece **619'u bozulmadan kaldı**. **Cluster mükemmel sağlıklı raporladı, constraint ihlali yok.**
- **Mitigasyon:** `smartShutdownTimeout: 0` **+** `failoverDelay: 30` birlikte → overlap tamamen ortadan kalktı, default'a kıyasla data corruption **%80** azaldı

**Argus için çıkarım:** "DB HA çözümüm var" ≠ "veri kaybım yok". ACK'lenmiş yazımların **%58'i** default konfigürasyonda kayboldu veya bozuldu. Bir IdP için bu, "revoke edilmiş token geri geldi" veya "kullanıcı yanlış tenant'a atandı" demektir. **Argus'un HA konfigürasyonu bu iki parametre için explicit test'e sahip olmalı.**

**Diğer CloudNativePG kaos verileri** ([Coroot, 16 Ocak 2025](https://coroot.com/blog/chaos-testing-a-postgres-cluster-managed-by-cloudnativepg/)):
- Üç deney: (1) `stress-ng` ile 300 sn CPU contention (noisy neighbor), (2) 10M satırlık tabloya `ALTER TABLE ... NOT NULL` ile lock contention, (3) `kubectl delete pod` ile primary failure
- **Ölçülen failover: primary pod silindikten sonra sorgu işlemenin geri gelmesi ~3 dakika**
- Gözlem: eBPF (Coroot) + `pg_stat_statements`/`pg_stat_activity`

**CloudNativePG'nin 2025 iyileştirmeleri** ([Gabriele Bartolini, Aralık 2025](https://www.gabrielebartolini.it/articles/2025/12/cloudnativepg-in-2025-cncf-sandbox-postgresql-18-and-a-new-era-for-extensions/)): primary'de network isolation tespiti için deneysel liveness probe (self-demotion), **primary isolation check / self-fencing**, ve failover'ın ancak node çoğunluğu hemfikirse gerçekleşmesini sağlayan **quorum tabanlı mekanizma**. Ayrıca proje **CNCF Sandbox**'a kabul edildi. Bir LFX mentorship projesi CloudNativePG için **kaos testi framework'ü** teslim etti — CI/CD'ye entegre, failover süresi ve data consistency metrikleri topluyor ([cloudnative-pg.io blog](https://cloudnative-pg.io/blog/lfx-chaos-testing-yash-agarwal/)).

### 4.5 Argus'ta ne test edilmeli — somut liste

| Senaryo | Beklenen davranış | Nasıl test edilir |
|---|---|---|
| **DB tamamen kayıp** | Yeni token yok; **mevcut JWT'ler doğrulanmaya devam eder** (stateless doğrulama); introspection 503 (asla "active:false" değil — fail-closed vs fail-open kararı açıkça verilmiş olmalı) | testcontainers'ta Postgres'i durdur |
| **Replica lag** | Revocation/logout **asla** stale replica'dan okunmaz; epoch okumaları primary'den veya monotonic read garantili | `pg_sleep` ile yapay lag; Jepsen RDS bulgusu ışığında **read replica'dan yetkilendirme kararı verilmemeli** |
| **Epoch propagation gecikmesi** | Tenant config değişikliği (örn. bir client'ın devre dışı bırakılması) sınırlı ve **ölçülen** bir süre içinde tüm node'lara ulaşır; süre aşımında fail-closed | turmoil/madsim ile node'lar arası partition; "revoke → N ms içinde tüm node'lar reddediyor" invariant'ı |
| **JWKS rotasyonu sırasında kesinti** | Eski kid ile imzalanmış token'lar overlap penceresi boyunca doğrulanır; yeni kid RP'ler tarafından fetch edilebilir; **rotation sırasında hiçbir istek 401 almaz** | Rotation'ı yük altında tetikle; k6 senaryosunda 401 sayısı = 0 threshold'u. OIDF suite'inde `oidcc-server-rotate-keys` modülü tam olarak bunu test ediyor |
| **Split-brain** | ACK'lenmiş hiçbir grant/token kaybolmaz | Chaos Mesh NetworkChaos + `smartShutdownTimeout`/`failoverDelay` matrisi; Coroot metodolojisi |
| **Refresh token reuse yarışı** | Aynı refresh token'ın iki eşzamanlı kullanımı → biri başarılı, diğeri **tüm aileyi iptal eder** | Shuttle (in-process) + gerçek eşzamanlı HTTP (interleaving) |
| **Connection pool tükenmesi** | Argon2 kuyruğu DB pool'unu aç bırakmamalı (bulkhead) | Karışık yük profili + pool metrikleri |

---

## 5. Güvenlik Testi

### 5.1 Protokol-özgü saldırı test setleri

**SAML:**
- **SAML Raider** ([CompassSecurity/SAMLRaider](https://github.com/CompassSecurity/SAMLRaider), [BApp Store](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)) — Burp eklentisi; SAML mesaj manipülasyonu + X.509 sertifika yönetimi. Repeater'a bir panel ekleyip **XSW saldırılarını tek tıkla** uygular. **8 yaygın XML Signature Wrapping varyantı (XSW1–XSW8)** — XSW1 örneğin Response mesajına, mevcut imzadan sonra imzasız bir klon ekler
- **d0ge/XSW** ([GitHub](https://github.com/d0ge/XSW)) — SAML endpoint'lerini XSW için otomatik prob'lar, çoklu crafted XML payload üretir
- **PortSwigger "The Fragile Lock"** ([10 Aralık 2025, güncelleme 21 Ocak 2026](https://portswigger.net/research/the-fragile-lock), Zakhar Fedotkin) — **üç yeni saldırı sınıfı**, Argus için doğrudan test vektörü:
  1. **Attribute Pollution** — parser'lar arası (libxml2 vs REXML) tutarsız namespace işleme; attribute sırasına ve parser'a göre farklı attribute'lar resolve oluyor
  2. **Namespace Confusion** — rezerve XML namespace bildirimlerini manipüle ederek signature element'lerini bazı parser'lara görünür, bazılarına görünmez yapmak → validation logic'i ikiye bölmek
  3. **Void Canonicalization** — **yeni bir saldırı sınıfı**: canonicalization çözülemeyen relative URI'lerle karşılaşınca güvenli şekilde fail etmek yerine **boş string** döndürüyor → boş içeriğin geçerli hash'i üretiliyor
  - Etkilenen: Ruby-SAML (<1.18.0, yamalı 1.12.4 dahil), PHP-SAML, xmlseclibs (v3.1.4'te düzeltildi), libxml2 tabanlı implementasyonlar. **Etkilenmeyen: XMLSec Library, Shibboleth xmlsectool**
  - Yayımlanan: GitHub samples'ta "Golden SAML Response" XML payload'ları + otomatik Burp eklentisi; SAML Raider'a entegre edilmesi planlanmış
  - Implementer önerileri: **kısıtlayıcı XML şeması, minimum extension point**; **yalnızca imzalanmış element'lerin downstream işlenmesi**; kütüphaneleri güncel tutmak; erişim kontrolünde e-posta domain suffix'ine güvenmemek

  **Argus için:** Rust'ta sıfırdan SAML yazarken bu üç sınıf **regression test corpus'unun çekirdeği** olmalı. Özellikle "Void Canonicalization" — Argus'un canonicalization'ı çözülemeyen URI'de **hard fail** etmeli.

**JWT:**
- **jwt_tool** ([ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)) — Python, **12+ attack mode**: alg confusion (RS256→HS256, RSA public key'i HMAC secret olarak), `none` bypass, `kid` injection (path traversal / SQLi), claim tampering, weak secret brute-force
- Bağlam: **2025'te yalnız başına 6 kritik CVE** yaygın kullanılan JWT kütüphanelerini etkiledi, birkaçı tek forged token ile tam hesap devralmaya izin veriyordu ([IntelligenceX](https://blog.intelligencex.org/jwt-vulnerabilities-testing-guide-2025-algorithm-confusion))
- JKU/X5U injection ve `kid` SQLi ayrı vektörler ([jsmon.sh](https://blogs.jsmon.sh/jwt-algorithm-confusion-to-account-takeover-rs256-hs256-jku-injection-kid-sqli/))

**OAuth/OIDC:**
- **OAuch** — 195 test, yukarıda detaylandırıldı. Argus için **en yüksek ROI'li güvenlik aracı**: threat model'e karşı otomatik uyum
- **OSBT** — attacker-OP senaryoları (Argus'un federation/broker rolü için)

### 5.2 Burp / OWASP ZAP ile OIDC otomasyonu

**Kısmen otomatikleştirilebilir — ama sürtünmeli.**
- ZAP **Automation Framework** YAML dosyalarıyla scan konfigüre ediyor; spider, active scan, API definition import job'ları var
- **OAuth için script-based authentication öneriliyor** — token'ı alan ve isteklere ekleyen custom script yazılır. Azure AD/OIDC SSO ile kullanım hâlâ community'de tartışılan, tam çözülmemiş bir konu ([zaproxy-users grubu](https://groups.google.com/g/zaproxy-users/c/2-Z7vNMUr2U))
- Gerçekçi değerlendirme: **ZAP/Burp bir IdP'nin *protokol* mantığını test etmez** — web katmanı (XSS, header'lar, CSRF, injection) için iyidir. Protokol seviyesi için OIDF suite + OAuch + OSBT gerekir.
- **Argus için tavsiye:** ZAP'ı **admin console ve consent/login UI** için kullanın (klasik web açıkları), protokol endpoint'leri için değil.

### 5.3 IdP-özgü fuzz hedefleri

(Genel fuzzing yöntemleri 11-runtime-hardening.md'de araştırıldı — burada yalnızca **IdP-özgü hedefler**:)

| Hedef | Neden | Corpus kaynağı |
|---|---|---|
| **XML parser + canonicalization (C14N)** | En yüksek riskli yüzey. PortSwigger'ın 3 saldırı sınıfı doğrudan burada | "The Fragile Lock" Golden SAML samples; XSW1–XSW8 varyantları; SPID test response'ları |
| **XML DSig verification** | İmzalanmış vs işlenen element ayrışması | SAML Raider çıktıları |
| **SAML metadata parser** | Güvenilmeyen federation metadata'sı | Kantara/eduGAIN metadata örnekleri |
| **JOSE: JWS/JWE header + compact/JSON serialization** | alg confusion, kid injection, crit header, zip bombası (JWE `zip:DEF`) | jwt_tool üretimleri |
| **JWKS parser** | Uzaktan çekilen güvenilmeyen JWK set'leri; dev boyut, garip curve, duplicate kid | — |
| **LDAP BER/ASN.1 decoder** | Ham bayt protokolü, klasik memory-safety yüzeyi (Rust'ta panic/DoS'a dönüşür) | RFC 4511 mesaj yapıları; `ldclt` trafiği |
| **LDAP search filter parser** | RFC 4515 filter string'leri; iç içe geçme derinliği → stack overflow | — |
| **SCIM filter parser** | RFC 7644 filter grameri — `and`/`or`/`not`, complex attribute path'leri | scim2-tester payload'ları |
| **SCIM PATCH path parser** | `members[value eq "x"].display` gibi ifadeler | — |
| **CBOR / COSE (WebAuthn attestation)** | attestationObject, authenticatorData; CBOR derinlik/boyut saldırıları | FIDO conformance tool trafiği |
| **CTAP2 attestation formatı** | packed, tpm, android-key, apple, fido-u2f varyantları | — |
| **URI/redirect_uri matcher** | Açık redirect; normalizasyon farkları | OAuch redirect testleri |
| **Deflate/inflate (SAML HTTP-Redirect binding)** | Zip bomb / decompression DoS | — |
| **MCP JSON-RPC mesaj parser** | MCP conformance'ın wire-schema validation'ı bunu kısmen kapsıyor | conformance harness trafiği |

**Öncelik sırası:** XML C14N/DSig > JOSE > LDAP BER > SCIM filter > CBOR/COSE.

### 5.4 Differential testing (Keycloak vs Argus)

**Pratik mi? — Kısmen. Şu koşullarda evet:**

**Uygun olduğu yerler:**
- **Saf fonksiyonlar / parser'lar**: aynı JWT'yi, aynı SAML assertion'ı, aynı SCIM filter'ı ikisine verip **kabul/red kararını** karşılaştırmak. Karar bir bit — karşılaştırması kolay, oracle sorunu yok. Bu klasik differential fuzzing ve **çok değerli**: Argus kabul edip Keycloak reddediyorsa muhtemelen Argus'ta güvenlik açığı var.
- **Discovery dokümanları**: `.well-known/openid-configuration`, `/Schemas`, `/ServiceProviderConfig` — yapısal diff.
- **Hata kodları**: aynı bozuk istek → `error` + `error_description` alanları. RP'ler bunlara bağımlıdır.

**Uygun olmadığı yerler:**
- Token içerikleri (nonce, jti, iat, imza) — nondeterministik
- Session/cookie davranışı, HTML login sayfaları
- Keycloak'ın spec'ten sapan davranışları — Keycloak **oracle değil**, referans implementasyon değil. Keycloak'a uymak spec'e uymak demek değil.

**Argus için önerilen konumlandırma:** Differential testing'i **birincil doğruluk ölçütü değil, bug bulucu** olarak kullanın. Birincil ölçüt conformance suite'leri. Fark bulunduğunda **spec metni hakem olur**, Keycloak değil. Pratik uygulama: `insta` snapshot'ları + Keycloak'ın testcontainer'ı ile nightly bir "divergence report" — fail etmeyen, sadece raporlayan bir job.

⚠️ OIDC/SAML implementasyonlarının otomatik differential testing'i üzerine akademik literatür bu araştırmada doğrulanamadı (arama bütçesi doldu).

---

## 6. Test Altyapısı

### 6.1 Rust entegrasyon testi

**testcontainers-rs** ([GitHub](https://github.com/testcontainers/testcontainers-rs), [rust.testcontainers.org](https://rust.testcontainers.org/)):
- İki crate: `testcontainers` (çekirdek) + `testcontainers-modules` (community-maintained hazır image'lar)
- **Async API** birinci sınıf; `blocking` feature'ı senkron testler için
- `GenericImage` ile keyfi Docker image
- Olgunluk: 1.1k star, 195 fork, 839 commit, Apache-2.0/MIT dual. ⚠️ Kesin sürüm ve son release tarihi doğrulanmadı

**Mevcut modüller** ([testcontainers-rs-modules-community](https://github.com/testcontainers/testcontainers-rs-modules-community)): anvil, azurite, fakecloud, localstack, mongo, mssql_server, nats, neo4j, **openldap**, **postgres**, rqlite, selenium, surrealdb, **zitadel**.

**Argus için sonuç:**
- ✅ **Postgres** — hazır
- ✅ **OpenLDAP** — hazır (Argus'un LDAP client tarafı veya migration senaryoları için)
- ❌ **Keycloak modülü Rust'ta YOK** (Java/Go'da var) → differential testing için `GenericImage` ile elle sarmalamak gerekir
- ❌ **SAML SP container'ı yok** → `GenericImage` ile SimpleSAMLphp veya Shibboleth SP image'ı sarmalanmalı; `italia/spid-saml-check` Docker image'ı (`docker run -p 8443:8443 italia/spid-saml-check`) hazır bir SAML test partneri olarak `GenericImage`'a takılabilir
- OIDF conformance suite'in kendisi de docker-compose ile ayağa kalktığı için CI'da `GenericImage`/compose olarak sürülebilir (Hydra'nın yaptığı gibi)

### 6.2 Snapshot testi — `insta`

[insta.rs](https://insta.rs/), [mitsuhiko/insta](https://github.com/mitsuhiko/insta):
- `assert_json_snapshot!` ile `serde::Serialize` çıktısı JSON olarak snapshot'lanır; format seçenekleri JSON/YAML/TOML/CSV
- **Redaction** — protokol yanıtları için kritik özellik: "permits replacing values with hardcoded other values to make snapshots stable when otherwise random or otherwise changing values are involved". Sözdizimi: `{ selector => replacement }` veya `match .. { selector => replacement }`
- `cargo-insta` ile inceleme; VS Code eklentisi; terminalde `similar` crate'i ile diff

**Argus'ta nereye:**
- `.well-known/openid-configuration`, `/jwks.json` (kid redact), OAuth error yanıtları
- SCIM `/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig`
- Decode edilmiş JWT **claim set'i** (imza değil; `jti`, `iat`, `exp`, `nonce` redact)
- SAML metadata (sertifika ve `ID` redact); assertion'ın **canonicalize edilmiş** hâli
- LDAP root DSE

Bu, "protokol yanıtımı yanlışlıkla değiştirdim" regresyonunu **çok ucuza** yakalar ve conformance suite'in çalışmadığı PR'larda ilk savunma hattıdır.

### 6.3 Test verisi üretimi

Keycloak'ın **dataset modülü** doğrudan model alınmalı: "a Keycloak add-on that can create entities in a Keycloak data store to prepare it for a load test". Keycloak benchmark'ın ölçeklendirme parametreleri (`--realms`, `--users-per-realm`, `--clients-per-realm`) gerçekçi bir çok-kiracılı grafiğin hangi eksenlerde büyüdüğünü gösteriyor.

Argus için gerçekçi kiracı/kullanıcı/rol grafiği eksenleri:
- Tenant sayısı × tenant başına kullanıcı (Zipf dağılımı — birkaç dev tenant, uzun kuyruk küçük tenant)
- Kullanıcı başına grup üyeliği (LDAP/SCIM'de **memberOf** patlaması; 389-ds dokümanlarında "large groups and memberOf tuning" ayrı bir başlık — [golinuxcloud](https://www.golinuxcloud.com/389-directory-server-large-group-performance/))
- Rol/scope grafiği derinliği (nested group resolution maliyeti)
- Client sayısı, redirect_uri sayısı, aktif session/refresh token sayısı
- **Sınır vakaları zorunlu**: 2000 üyeli grup (Entra'nın gerçek davranışı), Unicode/homoglyph kullanıcı adları, çok uzun DN'ler

Üretim: deterministik seed'li generator (aynı seed → aynı veri seti), böylece benchmark sonuçları karşılaştırılabilir olur.

### 6.4 CI süresi bütçesi

**cargo-nextest** ([nexte.st](https://nexte.st/book/partitioning.html)) — Argus'un ölçeğinde zorunlu:
- **Process-per-test** modeli: her test kendi process'inde → gerçek izolasyon (bir panic/segfault diğerlerini düşürmez) ve daha iyi scheduling
- Hız: kaynaklara göre `cargo test`'e kıyasla **2–5×** (bazı ölçümlerde "up to 60% faster", "up to 3x")
- **Partitioning/sharding** — CI matrisi için:
  ```
  cargo nextest run --partition count:1/3   # job 1
  cargo nextest run --partition count:2/3   # job 2
  cargo nextest run --partition count:3/3   # job 3
  ```
  İki mod: `count` (sayı tabanlı) ve `hash` (hash tabanlı)
- **Flaky test retry:** `--retries 2`
- **JUnit XML** çıktısı

**Referans süreler:**
- Ory Hydra'nın tam OIDC conformance koşumu için ayrılan timeout: **60 dakika** (`go test -tags conformity -test.timeout 60m -failfast`)
- OIDF `run-test-plan.py` **paralel çalışır** (`--no-parallel` ile kapatılabilir) — yani conformance kendi içinde paralelleşebilir

**Argus için realist bütçe:**

| Aşama | Hedef süre | İçerik |
|---|---|---|
| Pre-commit / hızlı | < 2 dk | fmt, clippy, unit + `insta` snapshot |
| PR (blocking) | **< 15 dk** | nextest 4-8 shard: unit + testcontainers entegrasyon + property/proptest + Shuttle (sabit seed, kısa) + kaydedilmiş IdP-emulator replay |
| Merge/main | ~45 dk | + OIDF conformance (Basic/Config/Dynamic + logout), MCP conformance, scim2-tester, OAuch |
| Nightly | 2-4 saat | + FAPI 2.0 planları, madsim/turmoil DST (yüksek seed sayısı), fuzzing (kısa), Keycloak differential raporu, gerçek Okta/Entra sandbox koşumu (tünelli) |
| Haftalık | uzun | Yük testleri (k6 constant-arrival-rate), kaos (Chaos Mesh split-brain matrisi), uzun fuzzing kampanyaları, FIDO conformance tools (manuel/yarı-otomatik) |

Conformance'ı PR'da tutmanın anahtarı: **expected-failures baseline'ı** (hem OIDF `run-test-plan.py` hem MCP conformance bunu destekliyor) — böylece bilinen eksikler CI'yı kırmaz ama **regresyon ve stale baseline** yakalanır.

---

## 7. Argus İçin Test Stratejisi — Somut Tablo

### 7.1 Ana matris

| # | Katman | Araç | Ne ölçer | Sıklık | CI aşaması | Blocking? |
|---|---|---|---|---|---|---|
| 1 | Unit | `cargo nextest` | Fonksiyon doğruluğu | Her commit | pre-commit + PR | ✅ |
| 2 | Property | `proptest` | Parser/serializer round-trip, filter grameri invariant'ları | Her PR | PR | ✅ |
| 3 | Snapshot | **`insta`** (redactions) | Protokol yanıt yapıları: discovery, JWKS, SCIM Schemas, error kodları, SAML metadata | Her PR | PR | ✅ |
| 4 | Concurrency | **Shuttle** (AWS) | Session store, refresh-token rotation yarışı, cache invalidation, pool | Her PR (kısa) + nightly (uzun) | PR + nightly | ✅ (kısa) |
| 5 | Entegrasyon | **testcontainers-rs** (postgres, openldap, GenericImage) | Gerçek DB/LDAP ile uçtan uca | Her PR | PR (nextest shard'lı) | ✅ |
| 6 | IdP-client emulator | Kaydedilmiş Okta/Entra trafiği replay | SCIM istemci tuhaflıkları (PATCH semantiği, `active=false`, DELETE, nested extension) | Her PR | PR | ✅ |
| 7 | **OIDC conformance** | **OIDF suite** (self-hosted Docker) + `run-test-plan.py` | `oidcc-basic/config/dynamic/implicit/hybrid/formpost-*-certification-test-plan` | Merge | main | ✅ (baseline'lı) |
| 8 | **Logout conformance** | OIDF suite | RP-Initiated + Back-Channel (+ Front-Channel) | Merge | main | ✅ (baseline'lı) |
| 9 | **OAuth güvenlik uyumu** | **OAuch** (self-hosted) | 195 test / 13 kategori — threat model + BCP | Merge | main | ✅ (baseline'lı) |
| 10 | **MCP conformance** | `npx @modelcontextprotocol/conformance` + GitHub Action | `authorization-server` senaryoları (authorization-code-grant, AS metadata) + server senaryoları | Merge | main | ✅ (per-check baseline) |
| 11 | **SCIM conformance** | **`scim2-tester`** (pytest/CI) | RFC 7643/7644: discovery, CRUD, PATCH add/remove/replace | Merge | main | ✅ |
| 12 | SCIM vendor uyumu | Entra SCIM Validator (discover-schema modu), Okta Runscope (13 op) | Gerçek istemci uyumu | Haftalık / release öncesi | manuel + nightly | ❌ rapor |
| 13 | **FAPI 2.0** | OIDF suite, FAPI 2.0 Security Profile Final planı | Yüksek güvenlik profili doğruluğu | Nightly | nightly | ❌ rapor → sonra ✅ |
| 14 | SAML doğruluğu | `italia/spid-saml-check` (Docker) — Argus'un **SP entegrasyonları** için; `AgID/spid-saml-check-idp` — deneysel IdP tarafı | 300+ kontrol / 7 aile (SP tarafı) | Nightly | nightly | ❌ rapor |
| 15 | SAML güvenliği | **SAML Raider XSW1–XSW8** + **"The Fragile Lock"** 3 saldırı sınıfı (Golden SAML samples) → **regression corpus** | Attribute Pollution, Namespace Confusion, Void Canonicalization | Her PR (corpus olarak) | PR | ✅ |
| 16 | JWT güvenliği | **`jwt_tool`** vektörleri → regression corpus | alg confusion, none, kid injection, jku/x5u | Her PR (corpus) | PR | ✅ |
| 17 | WebAuthn (ucuz) | **CDP Virtual Authenticator** + Playwright | RP akışı uçtan uca (Chromium-only) | Her PR | PR | ✅ |
| 18 | WebAuthn (resmî) | **FIDO Conformance Tools** (talep formu ile edinilir; 4 test endpoint'i için adapter gerekir) | FIDO2 server conformance (~160 test örnek koşum) | Release öncesi | manuel | ❌ |
| 19 | LDAP doğruluğu | `ldapsearch`/`ldapmodify` senaryoları + gerçek istemciler (SSSD, JNDI, `ldap3`, Apache DS) | Davranışsal interop | Nightly | nightly | ❌ rapor |
| 20 | LDAP yükü | **`ldclt`** (389-ds) veya SLAMD | bind/search/modify hızı, büyük grup + memberOf | Haftalık | perf job | ❌ |
| 21 | Fuzzing | `cargo-fuzz` — hedefler §5.3 önceliğine göre | Bellek/panic/DoS | Nightly (kısa) + haftalık (uzun) | nightly | ❌ (crash → issue) |
| 22 | **DST — node arası** | **madsim** (`tokio-postgres` yaması var) — birincil; **turmoil** — alternatif | Epoch propagasyonu, JWKS rotasyonu, partition altında revocation | Nightly (yüksek seed) | nightly | ❌ (seed kaydedilir) |
| 23 | Model checking | **stateright** | OAuth code lifecycle, refresh rotation, CIBA poll, logout propagation state machine'leri — `always`/`sometimes` property'leri | Haftalık | perf/verify job | ❌ |
| 24 | **Yük** | **k6 `constant-arrival-rate`** (birincil) veya **wrk2**; ayrı makinede | login/sn, refresh/sn, introspection/sn, p99 | Haftalık + release | perf job | ✅ threshold |
| 25 | Argon2 mikro-benchmark | `criterion` | Hash süresi + bellek, parametre değişimi regresyonu | Her PR | PR | ✅ (regresyon eşiği) |
| 26 | **Kaos — DB** | **Chaos Mesh** (NetworkChaos) + CloudNativePG; Coroot metodolojisi | Split-brain veri kaybı; failover süresi | Haftalık | chaos job | ❌ → ✅ |
| 27 | Differential | Keycloak `GenericImage` + `insta` diff | Parser kabul/red farkları, discovery farkları | Nightly | nightly | ❌ **rapor** (asla blocking değil) |
| 28 | Web güvenliği | **OWASP ZAP** Automation Framework | Admin console + login/consent UI (XSS, header, CSRF) — protokol için DEĞİL | Nightly | nightly | ❌ rapor |
| 29 | Federation broker | **OSBT** (attacker-OP) | Argus upstream IdP'ye bağlanırken kötü niyetli OP'ye dayanıklılık | Nightly | nightly | ❌ rapor |

### 7.2 Uygulama sırası (öncelik)

**Faz 1 — temel (hemen):** #1–5, #25. `nextest` + partitioning'i baştan kur; `insta` snapshot'larını protokol yanıtları yazılırken beraber yaz (sonradan eklemek 5× daha pahalı).

**Faz 2 — doğruluğu ölçmeye başla:** #7, #9, #11, #15, #16. **OIDF suite self-hosted + `run-test-plan.py` + expected-failures baseline** Argus'un tek en yüksek getirili yatırımıdır: Ory Hydra'nın `run_test.go`'su hazır bir referans implementasyon. **OAuch'u hemen yanına koyun** — spec uyumu ile güvenlik uyumu farklı şeyler ve OAuch'un 100-IdP çalışması bu farkın ne kadar büyük olduğunu gösteriyor.

**Faz 3 — interop:** #6, #10, #12, #17. Gerçek Okta/Entra sandbox koşumunu **bir kez** yapıp trafiği kaydedin, sonra replay ile her PR'da koşun.

**Faz 4 — dayanıklılık:** #22, #24, #26. Postgres izolasyon garantilerini (Jepsen RDS bulgusu) ve split-brain penceresini (Coroot bulgusu) **açıkça** test edin.

**Faz 5 — derinlik:** #13, #14, #18, #21, #23, #27.

### 7.3 Üç stratejik karar

1. **Sertifikasyon hedeflenmiyor ama süitler koşulacak** → Argus, tüm conformance süitlerini **ücretsiz self-hosted** çalıştırabilir. Ödenecek tek maliyet mühendislik zamanı. Yine de **certification.openid.net'e API token alıp** OIDF'nin sunucusunu kullanmak, kendi suite'inizi güncel tutma yükünü ortadan kaldırır — ama CI'yı harici servise bağımlı kılar. **Öneri: self-hosted Docker (Hydra modeli), nightly'de OIDF sunucusuna karşı çapraz doğrulama.**

2. **Keycloak oracle değil.** Differential testing bug bulucudur, doğruluk ölçütü değil. Spec metni tek hakem.

3. **Matris patlamasını tasarımla çözün** (§2.4): protokol doğruluğu (conformance) × karşı taraf profili (kodlanmış davranış kontratı) × az sayıda gerçek E2E smoke. 630 kombinasyon yerine ~200 anlamlı test.

---

## 8. ⚠️ DOĞRULANMAYANLAR

1. **SPID "263 test"** — birincil kaynaklarda geçen sayılar **"300+ kontrol, 7 aile"** ve **"111 kontrol"** (interaktif SP davranış ailesi). 263 rakamını hiçbir yerde doğrulayamadım. Ayrıca **önemli düzeltme:** `italia/spid-saml-check` **SP'leri** test eder, IdP'leri değil. IdP tarafı için ayrı ve çok olgunlaşmamış (**4 star, 51 commit**) `AgID/spid-saml-check-idp` var; onun test aileleri/sayısı dokümante değil.
2. **OIDF conformance planlarındaki test sayıları** — hiçbir plan için (Basic OP, FAPI 2.0, CIBA) resmî test sayısı bulunamadı. Sayı variant seçimine göre dinamik; ancak `POST /api/plan` yanıtından öğrenilebilir.
3. **FAPI 2.0 test planının tam adı** (`fapi2-security-profile-final-test-plan` vb.) — hiçbir OIDF sayfasında açıkça yazılı değil.
4. **FIDO "160 test"** — bu SimpleWebAuthn dokümanındaki bir **örnek koşum çıktısı**, FIDO Alliance'ın resmî beyanı değil.
5. **FIDO Conformance Tools için üyelik gerekliliği ve ücretler** — form + onay süreci doğrulandı; üyelik zorunluluğu ve fiyat tutarları hiçbir sayfada yayımlanmamış.
6. **Kantara'nın aktif SAML sertifikasyon programı** — saml2int/FedInterop profilleri doğrulandı (bunlar **normatif profil**, çalıştırılabilir süit değil); bugün işleyen bir sertifikasyon programı olup olmadığı doğrulanmadı.
7. **OASIS SAML conformance programının durumu** — `saml-conformance-2.0-os` belgesi mevcut, ancak programın devam edip etmediği doğrulanmadı.
8. **OpenLDAP `make test`'in harici sunucuya yöneltilebilirliği** — kendi regresyon süiti olduğu doğrulandı; üçüncü taraf LDAP sunucusuna karşı çalıştırılabildiğine dair kanıt yok.
9. **turmoil'in desteklemediği özellikler** — TLS desteği, tokio versiyon kısıtları, `tokio-postgres` uyumluluğu README'de yazılı değil. "Still experimental" ifadesi 2023 duyurusundan; 2026 itibarıyla güncel olgunluk seviyesi doğrulanmadı.
10. **madsim'in API kapsama yüzdesi, performans overhead'i ve bilinen sınırları** — dokümante edilmemiş. RisingWave kullanımı doğrulandı ancak kapsam derinliği bilinmiyor.
11. **Gatling'in coordinated omission davranışı** — open model (`--users-per-sec`) desteği doğrulandı, ancak latency'yi intended-send-time'a göre mi ölçtüğü doğrulanmadı.
12. **`oha`'nın coordinated omission doğruluğu** — doğrulanmadı; smoke test için uygun, kapasite ölçümü için güvenilmemeli.
13. **Üretim IdP trafik oranları (login : refresh : introspection)** — Auth0/Okta'dan yayımlanmış veri bulunamadı. Elimizdeki tek referans Keycloak benchmark'ın **1:5** login:refresh profili; bu bir benchmark seçimi, üretim ölçümü değil. Introspection için hiçbir veri yok.
14. **ServiceNow PDI'nin SAML SSO desteği**, ve **Workday / Slack / Zoom / Atlassian / AWS / Google Workspace** için ücretsiz developer tier'da SAML/SCIM erişimi — hiçbiri birincil kaynaktan doğrulanmadı. (Google Workspace için **negatif** doğrulama var: WorkOS'a göre SCIM push desteklenmiyor.)
15. **Entra ID'nin hangi SKU'sunun outbound app provisioning içerdiği** (P1 gerekiyor mu) — doğrulanmadı; Argus'un interop bütçesi için maliyet riski.
16. **SCIM Sandbox (scimsandbox.net)** — site 403 döndürdü; açık kaynak/self-hostable olduğu ve kaç check koştuğu doğrulanmadı.
17. **MCP conformance toplam check sayısı** — senaryo dizinleri sayıldı (`server/` ~17, `authorization-server/` 2 + `auth/` alt dizini, `client/` sayılmadı) ama toplam check sayısı doğrulanmadı. Tek senaryoda "over twenty" check olduğu README'de belirtiliyor.
18. **Patroni'nin resmî Jepsen analizi** — **yok**. Bulunan çalışma bağımsız bir blog (Bin Wang, Aralık 2024); ihtiyatla değerlendirin.
19. **`mod_auth_openidc` test setleri** — bir conformance test seti olarak varlığı doğrulanamadı.
20. **Rust'ta softauthn benzeri yazılım WebAuthn authenticator kütüphanesi** — doğrulanamadı; CDP Virtual Authenticator tek doğrulanmış ücretsiz yol (Chromium-only).
21. **OIDC/SAML implementasyonlarının otomatik differential testing'i üzerine akademik literatür** — arama bütçesi (200/200 WebSearch) dolduğu için araştırılamadı.
22. **Keycloak testsuite'inin toplam test sayısı** — Arquillian tabanlı mimarisi doğrulandı, sayı bulunamadı.
23. **`stateright`'ın 2025-2026 bakım durumu** — doğrulanmadı.

**Not:** Bu oturumda WebSearch bütçesi (200/200) tükendi; kalan doğrulamalar WebFetch ile doğrudan URL üzerinden yapıldı. Yukarıdaki 21. madde ve madsim/turmoil olgunluk detayları için ek bir oturum gerekir.
