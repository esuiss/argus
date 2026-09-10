# 16. Kurumsal protokoller — SAML, SCIM, LDAP, Kerberos, Federation

> `ARGUS.md` §16'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§16 §X` referansları aynı anlamda.


**Kapsam:** Argus'un SAML 2.0 (IdP tarafı), SCIM 2.0 (sunucu tarafı), LDAP (sunucu tarafı), Kerberos/AD entegrasyonu ve OpenID Federation 1.0/1.1 desteklemesi için gereken her şey — implementasyon seviyesinde.
**Yöntem:** RFC'ler `rfc-editor.org`'dan ham metin olarak okundu; errata `rfc-editor.org/errata/`'dan; IETF durumları Datatracker API'sinden; OASIS SAML spec'leri `docs.oasis-open.org`'dan; OpenID spec'leri `openid.net`'ten; satıcı gereksinimleri Microsoft Learn / Okta Developer / GitLab / Grafana / Kanidm resmi dokümanlarından; Rust crate verileri **crates.io JSON API'sinden canlı çekildi**. Blog özetleriyle yetinilmedi.

> **Doğrulama notu:** Her sürüm numarası, tarih ve indirme sayısı birincil kaynaktan alınmıştır. Doğrulanamayan noktalar açıkça **DOĞRULANMADI** olarak işaretlenmiştir ve §7'de toplanmıştır. Rakam uydurulmamıştır.


**İçindekiler**

| Bölüm | Konu |
|---|---|
| 0 | Yönetici özeti (12 kritik bulgu) ve sınıflandırma özet tablosu |
| 1 | **SAML 2.0 — IdP tarafı**: artefaktlar, XML imzalama, exc-c14n, şifreleme, NameID, binding'ler, SLO, metadata, saldırılar, SP gereksinimleri, Rust |
| 2 | **SCIM 2.0 — sunucu tarafı**: altı RFC, endpoint'ler, veri modeli, PATCH motoru, filtre dili, sayfalama, Entra/Okta interop, RFC 9967 olayları, Rust |
| 3 | **LDAP — sunucu tarafı**: operasyonlar, RootDSE, DIT projeksiyonu, filtre çevirisi, kontroller, SASL/TLS, istemci gerçeği, Kanidm dersleri, Rust |
| 4 | **Kerberos / AD**: SPNEGO acceptor, keytab, AD senkronizasyon kalıpları, 2026'da gereklilik, Rust |
| 5 | **OpenID Federation 1.0/1.1**: spec durumu, entity statement, trust chain, policy motoru, client resolution katmanı, ekosistem, Rust |
| 6 | Toplam efor tahmini ve önerilen sıralama |
| 7 | Doğrulanamayanlar ve dokümanın sınırları |

---

### 0. Yönetici özeti — on iki kritik bulgu

1. **Rust'ta saf XML imzalama artık mümkün.** `bergshamra` (kushaldas) XMLDSig/XMLEnc/C14N'i saf Rust'ta veriyor ve **xmlsec1'in kendi interop test süitini 1148/1151 geçiyor**. Üstündeki `gamlastan` SAML 2.0 kütüphanesinin SPID uyum iddiası ise kanıt sayılmaz: rakam kütüphanenin kendi README'sinden geliyor ve `italia/spid-saml-check` **Service Provider'ları test eder, Identity Provider'ları değil** (süitin birincil kaynaklarındaki sayılar 300+ kontrol / 7 aile). Buna karşılık `bergshamra`'nın xmlsec1 sonucu bağımsız bir süite karşıdır ve geçerlidir. Bu, "SAML için libxmlsec1'e mecbursun" varsayımını 2026'da geçersiz kılıyor — ama her ikisi de tek geliştiricili, 0.9.0 ve düşük benimseme (§1.13.2).

2. **SCIM artık üç RFC değil, altı RFC.** Brief'teki "RFC 9967 SCIM Events" adı yanlış: gerçek başlık **"SCIM Profile for Security Event Tokens (SETs)"** (Mayıs 2026). Ayrıca **RFC 9865** (cursor sayfalama, Ekim 2025) ve **RFC 9944** (cihaz şeması, Mayıs 2026) var ve ikisi de 7643/7644'ü **günceller** (§2.1).

3. **SCIM'in en büyük tek iş kalemi PATCH motorudur ve hiçbir Rust crate'i vermiyor.** `scim_v2` yalnızca yol AST'sini veriyor. Uygulama mantığı, atomiklik, `primary` düşürme kuralı ve 17 maddelik satıcı toleransı tamamen bize ait (§2.4, §2.11).

4. **Entra ve Okta birbiriyle çelişen şeyler şart koşuyor.** Okta: *"çıplak `GET /Groups/{id}` üyeleri döndürmek ZORUNDA"*. Entra: *"tüm üyeleri döndürmek tavsiye edilmez"*. Tek çözüm: istemci başına açılabilen bir hoşgörü katmanı (§2.8).

5. **Entra kendi uyumsuzluğunu belgeliyor ve düzeltme tarihi vermiyor:** *"Update PATCH behavior to ensure compliance — Fixed? **No** — Fix date **TBD**"*. `aadOptscim062020` bayrağı uyumlu moda geçiriyor, ama bayraklı modda bile **düz noktalı JSON anahtarları** (`"name.givenName"`) gönderiyor (§2.8).

6. **LDAP, Rust ekosisteminin en iyi durumda olduğu protokol.** `ldap3_proto` 0.8.1 (Kanidm, 2026-08-14) RFC 4511'in tam operasyon setini, `SimplePagedResults`/`ServerSort`/`SyncRequest` kontrollerini, `PasswordModify` ve `WhoAmI` extended op'larını wire seviyesinde veriyor. Yazılacak olan protokol değil, **semantik** (§3.10).

7. **Kanidm'in "LDAP bind'ı düşürülmüş yetki verir" kararı kopyalanmalı.** LDAP kanalı tam hesap yetkisini taşımamalı; ayrı bir kimlik bilgisi sınıfı gerekiyor. MFA'lı bir dünyada LDAP bind zaten tek faktörlüdür (§3.9).

8. **Sadece-okuma LDAP %95 senaryoyu kapatıyor.** Grafana dokümanı açıkça "no write is needed" diyor; GitLab salt-okunur erişim istiyor. Tek gerçek istisna **RFC 3062 Password Modify** (Linux `passwd`) — tek bir extended op (§3.8).

9. **Kerberos'ta Argus KDC olmamalı; sadece SPNEGO acceptor olmalı.** Microsoft kendi Kerberos tabanlı Seamless SSO'sunu modern Windows'ta **PRT lehine terk etti** (doküman güncellemesi 26 Şub 2026). Kerberos artık ürün genişliği değil, **belirli RFP'lerde satış kapısı** (§4.5).

10. **Kerberos, C bağımlılığından kaçamayacağımız tek protokol.** `libgssapi` 0.11.0 MIT krb5/Heimdal'a linklenir. Saf Rust GSSAPI iddiasında olan `krb5-rs` 0.1.0'ın **tek sürümü ve 80 indirmesi var** — kullanılamaz (§4.6).

11. **OpenID Federation'da Rust tamamen boş ve bu bizim en büyük farklılaşma fırsatımız.** Tek crate (`openid-federation` 0.1.0) **Final'den önceki draft 43'e** göre yazılmış, 0 yıldız, 4 commit, son 90 günde 8 indirme. oidfed.com'un ekosistem listesinde **Rust hiç geçmiyor.** Doğrudan rakip Kanidm de bu alanda henüz karar vermemiş (Discussion #4154, Şubat 2026) (§5.6, §5.7).

12. **crates.io'da SAML/SCIM isim işgali var.** `opensaml`, `samlify`, `samlet`, `rustsaml` crate'lerinin **dördü de aynı sahibin** (`salasebas`) `saml-rs` paketinin "compatibility re-export"ları. Aynı sahip `scim-rs`'i de yayınlamış. **Bu isimlere güvenip bağımlılık alma** (§1.13.3).

#### Stratejik sinyal

Beş protokolün Rust ekosistemindeki durumu ters sıralı: **LDAP hazır → SCIM kısmen → SAML yeni ve umut verici ama tek kişilik → Kerberos C'ye mahkûm → OpenID Federation sıfır.** En büyük teknik risk SAML'in kripto katmanında; en büyük fırsat OpenID Federation'da; en büyük **iş hacmi** SCIM PATCH motorunda.

---

### 0.1 Sınıflandırma özeti — tek tablo

| Protokol | ZORUNLU (Faz 1) | OPSİYONEL (Faz 2) | ATLANABİLİR |
|---|---|---|---|
| **SAML 2.0** | SP-initiated Web Browser SSO, HTTP-POST + HTTP-Redirect binding, Response/Assertion imzalama (RSA-SHA-256 + exc-c14n), IdP metadata yayını, SP metadata tüketimi, persistent/transient NameID, attribute statement, replay cache | EncryptedAssertion, IdP-initiated, imzalı metadata + MDQ, ECDSA imzalar, pairwise identifier, SLO (back-channel) | HTTP-Artifact binding, ECP/PAOS, front-channel SLO garantisi, SAML 1.1, WS-Federation, holder-of-key |
| **SCIM 2.0** | /Users, /Groups, /ServiceProviderConfig(+s), /ResourceTypes, /Schemas, PATCH motoru, `eq`+`and`, indeks sayfalaması, projeksiyon, satıcı tolerans katmanı | Tam filtre grameri, sıralama, ETag, /.search, RFC 9865 cursor, RFC 9967 SET (`:notice`), /Me | /Bulk, `Prefer: respond-async`, `:full` replikasyon, OpenID SSF akış yönetimi, RFC 9944 cihaz şeması |
| **LDAP** | Bind(simple)+TLS, Search, Unbind, Abandon, RootDSE, subschema, filtre çevirisi, paged results, LDAPS | StartTLS, RFC 3062 Password Modify, WhoAmI, Compare, server-side sorting, SASL EXTERNAL, matching-rule-in-chain | Add/Delete/ModifyDN, SASL GSSAPI/SCRAM/DIGEST-MD5, VLV, referral, RFC 4533 sync |
| **Kerberos** | SPNEGO/Negotiate acceptor, keytab yönetimi, AD LDAP sync, AD'ye bind delegasyonu | Cross-realm güven, S4U2Proxy delegasyon, PKINIT | KDC olmak, principal veritabanı, NTLM |
| **OpenID Federation** | Entity Configuration (leaf OP), entity statement doğrulama (§3.2, 25 adım), trust chain çözümleme, metadata policy motoru (7 operatör), automatic registration | Explicit registration, trust mark doğrulama, resolve endpoint, historical keys | Intermediate/Trust Anchor rolü (fetch/list endpoint'leri), trust mark **ihraç** etmek, federation'a özgü profiller |

---

## BÖLÜM 1 — SAML 2.0, IdP TARAFI

**Kaynak temeli:** Beş OASIS Standard dokümanının tamamı (`saml-core`, `saml-bindings`, `saml-profiles`, `saml-metadata`, `saml-sec-consider`, hepsi 15 Mart 2005, `docs.oasis-open.org/security/saml/v2.0/`) PDF olarak indirilip metne çevrildi; aşağıdaki tüm bölüm numaraları ve alıntılar bu birincil metinlerden çıkarıldı. Ek: W3C `xml-exc-c14n` REC, W3C XML Encryption 1.1 REC, RFC 9231, OASIS Metadata Interoperability Profile v1.0, NVD REST API, crates.io REST API.

### 1.1 IdP'nin üretmesi gereken artefaktlar

#### 1.1.1 `<AuthnRequest>` işleme — SAMLCore §3.4.1

Şema sırası bir `sequence`'tir, sıra önemlidir:
`saml:Subject?` → `samlp:NameIDPolicy?` → `saml:Conditions?` → `samlp:RequestedAuthnContext?` → `samlp:Scoping?`

| Attribute | Tip | IdP davranışı |
|---|---|---|
| `ForceAuthn` | boolean, default **false** | `true` ise IdP **MUST** kullanıcıyı yeniden authenticate etsin, mevcut security context'e güvenmesin |
| `IsPassive` | boolean, default **false** | `true` ise IdP ve user agent **MUST NOT** kullanıcı arayüzünü görünür şekilde ele geçirsin |
| `AssertionConsumerServiceIndex` | unsignedShort | `AssertionConsumerServiceURL` ve `ProtocolBinding` ile **karşılıklı dışlayan** |
| `AssertionConsumerServiceURL` | anyURI | `Index` ile karşılıklı dışlayan |
| `ProtocolBinding` | anyURI | `Index` ile karşılıklı dışlayan |
| `AttributeConsumingServiceIndex` | unsignedShort | SP metadata'sındaki `<md:AttributeConsumingService>`'e index; IdP **MAY ignore** |
| `ProviderName` | string | Yalnızca insan-okunur |

**ForceAuthn + IsPassive ikisi de true ise** — SAMLCore §3.4.1: *"if both ForceAuthn and IsPassive are 'true', the identity provider MUST NOT freshly authenticate the presenter unless the constraints of IsPassive can be met."* → IsPassive kazanır; karşılanamazsa `urn:oasis:names:tc:SAML:2.0:status:NoPassive` dönülmeli.

> ### 🔴 IdP tarafındaki 1 numaralı güvenlik kuralı — SAMLProf §4.1.4.1
> *"Whether the request is signed or not, the identity provider MUST ensure that any `<AssertionConsumerServiceURL>` or `<AssertionConsumerServiceIndex>` elements in the request are verified as belonging to the service provider to whom the response will be sent. **Failure to do so can result in a man-in-the-middle attack.**"*
>
> **İmzasız AuthnRequest'te bile ACS URL'ini asla doğrudan kullanma.** Her zaman SP metadata'sındaki kayıtlı `<md:AssertionConsumerService>` listesine karşı **tam eşleşme** doğrula. Bu, IdP'nin açık-yönlendirme ve assertion sızdırma vektörüdür.

**`<NameIDPolicy>` (§3.4.1.1):** `Format?`, `SPNameQualifier?`, **`AllowCreate` (default `"false"`!)**. Anlaşılmayan politika → `urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy`. `AllowCreate="false"` varsayılanı, persistent NameID kullanan kurulumlarda tuzaktır: IdP yalnızca **önceden kurulmuş** bir identifier varsa assertion verebilir.

**`<Scoping>` (§3.4.1.2-3):** `ProxyCount` (0 = proxying yasak), `<IDPList>`/`<IDPEntry>`/`<GetComplete>`, `<RequesterID>*`. Desteklenmeyen IdP → `NoAvailableIDP` / `NoSupportedIDP`.
→ **Argus v1: parse et, `ProxyCount`'u sakla, `RequesterID`'yi denetim kaydına yaz, proxying implemente etme.**

#### 1.1.2 `<Response>` — SAMLProf §4.1.4.2 normatif listesi

1. Hata dönerken **MUST NOT** assertion içersin.
2. `<Issuer>` **MAY** omit; varsa IdP'nin unique id'si, `Format` omit veya `...nameid-format:entity`.
3. **MUST** en az bir `<Assertion>` içersin.
4. Assertion kümesi **MUST** en az bir `<AuthnStatement>` içersin.
5. En az bir assertion **MUST** `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"` olan `<SubjectConfirmation>` içersin.
6. **SLO destekliyorsan:** *"any such authentication statements MUST include a `SessionIndex` attribute"*.
7. Bearer `<SubjectConfirmationData>` **MUST** `Recipient` (= SP'nin ACS URL'i) ve `NotOnOrAfter` içersin; **MUST NOT** `NotBefore` içersin; solicited ise `InResponseTo` = request'in `ID`'si; `Address` **MAY**.
8. Bearer assertion **MUST** `<AudienceRestriction>` içersin, `<Audience>` = SP'nin unique identifier'ı.
9. `<AttributeStatement>` **MAY**; `AttributeConsumingServiceIndex` **MAY ignore** edilir.
10. IdP, request'teki `<Conditions>`'ı onurlandırmak **zorunda değildir**.

#### 1.1.3 Üretilecek iskelet ve şema sırası

```
samlp:Response  @ID @Version="2.0" @IssueInstant @Destination @InResponseTo
├── saml:Issuer                       (entity format)
├── ds:Signature                      (önerilen)
├── samlp:Status → samlp:StatusCode @Value=".:status:Success"
└── saml:Assertion  @ID @Version="2.0" @IssueInstant
    ├── saml:Issuer
    ├── ds:Signature                  ← POST binding'de ZORUNLU
    ├── saml:Subject
    │   ├── saml:NameID @Format [@NameQualifier @SPNameQualifier]
    │   └── saml:SubjectConfirmation @Method="...cm:bearer"
    │       └── saml:SubjectConfirmationData
    │             @Recipient @NotOnOrAfter @InResponseTo   ← NotBefore YOK
    ├── saml:Conditions @NotBefore @NotOnOrAfter
    │   └── saml:AudienceRestriction → saml:Audience
    ├── saml:AuthnStatement @AuthnInstant @SessionIndex [@SessionNotOnOrAfter]
    │   └── saml:AuthnContext → saml:AuthnContextClassRef
    └── saml:AttributeStatement → saml:Attribute @Name @NameFormat [@FriendlyName]
```

> **Assertion şema sırası (SAMLCore §2.3.3) bir `sequence`'tir ve bozulamaz:**
> `Issuer → ds:Signature? → Subject? → Conditions? → Advice? → Statement*`
> **`ds:Signature`, `Issuer`'dan hemen sonra gelmek zorundadır.** Rust'ta serializer yazarken en sık kırılan nokta budur.

#### 1.1.4 `<Conditions>` (§2.5.1) incelikleri

- `NotBefore` < `NotOnOrAfter` olmalı; `NotOnOrAfter` **dışlayıcıdır** (o an dahil değil).
- §2.5.1.4: Bir `<AudienceRestriction>` içindeki çoklu `<Audience>` = **VEYA**; çoklu `<AudienceRestriction>` = **VE**. Çoklu audience istiyorsan **tek** `AudienceRestriction` içinde çoklu `Audience` yaz.
- `<OneTimeUse>` ve `<ProxyRestriction>`: şema çoklu izin verse de **MUST** en fazla birer tane olsun.

#### 1.1.5 `SessionIndex` üretimi — SAMLCore §2.7.2

Spec gizlilik uyarısı: *"the value SHOULD NOT be usable to correlate activity by a principal across different session participants."* İki **RECOMMENDED** yol: (a) rastgele aralıktan küçük tamsayılar, (b) **kapsayan assertion'ın `ID`'sini kullan.**

Microsoft'un kendi örneği (b)'yi kullanıyor (`SessionIndex` = assertion ID). **Argus önerisi: (b), ama gerçek SLO istiyorsan IdP tarafında `SessionIndex → (SP entityID, kullanıcı oturumu)` eşleme tablosu tutmak zorundasın** — aynı kullanıcının aynı SP'ye ikinci SSO'sunda eski index'i geçersizleştirme mantığı gerekir.

#### 1.1.6 Metadata dokümanı — SAMLMeta §2.4.1-2.4.3

`RoleDescriptorType` attribute'ları: `ID?`, `validUntil?`, `cacheDuration?`, **`protocolSupportEnumeration` (REQUIRED — `urn:oasis:names:tc:SAML:2.0:protocol` içermeli)**, `errorURL?`.

`SSODescriptorType` alt eleman sırası: `ArtifactResolutionService*` → `SingleLogoutService*` → `ManageNameIDService*` → `NameIDFormat*`.

`IDPSSODescriptorType` ek: `WantAuthnRequestsSigned` (default false), **`<SingleSignOnService>` [bir veya daha fazla]** — bu elemanda `ResponseLocation` attribute'u **MUST be omitted**; ayrıca `<NameIDMappingService>*`, `<AssertionIDRequestService>*`, `<AttributeProfile>*`, `<saml:Attribute>*`.

`<KeyDescriptor>` (§2.4.1.1): `ds:KeyInfo` **REQUIRED**, `md:EncryptionMethod*`, `use` **optional** — omit edilirse anahtar **her iki amaç için** geçerlidir.

### 1.2 XML imzalama

#### 1.2.1 SAMLCore §5.4 — XML Signature Profile

| § | Kural |
|---|---|
| §5 | *"any XML Digital Signatures MUST be **enveloped**"* |
| §5.4.2 | *"Signatures MUST contain a **single** `<ds:Reference>` containing a **same-document reference** to the ID attribute value... if the ID attribute value is 'foo', then the URI attribute MUST be '#foo'."* → **`URI=""` SAML'da yanlıştır.** Tam olarak **bir** Reference |
| §5.4.3 | *"SAML implementations **SHOULD use Exclusive Canonicalization**, with or without comments, both in `<ds:CanonicalizationMethod>` and as a `<ds:Transform>` algorithm."* |
| §5.4.4 | *"Signatures SHOULD NOT contain transforms other than the **enveloped signature transform** or the **exclusive canonicalization transforms**. Verifiers MAY reject signatures that contain other transform algorithms as invalid."* |
| §5.4.5 | `<ds:KeyInfo>` **MAY be absent** — SAML kısıt getirmez |
| §5.4.1 | 2005 metni `rsa-sha1`'i SHOULD der. **Bu bugün geçersizdir** (§1.2.4) |

#### 1.2.2 Exclusive C14N — implementasyonun zor kısmı

URI'ler: `http://www.w3.org/2001/10/xml-exc-c14n#` ve `...#WithComments`.

Inclusive C14N'den iki temel fark (W3C REC §3):
1. **`xml:` namespace attribute'ları** (`xml:lang`, `xml:space`, `xml:base`) ata düğümlerden **kopyalanmaz**.
2. Yalnızca **"visibly utilized"** namespace bildirimleri çıktılanır.

**"Visibly utilizes" tanımı (§1.1):** *"An element E in a document subset visibly utilizes a namespace declaration... if E or an attribute node in the document subset with parent E has a **qualified name** in which P is the namespace prefix."*

> 🔴 **Kritik:** Prefix yalnızca bir attribute **değerinin içinde** string olarak geçiyorsa (`xsi:type="xsd:decimal"`, XPath ifadeleri, QName-tipli içerik) bu "visible utilization" **sayılmaz** ve namespace bildirimi çıktılanmaz → imza doğrulanamaz. `InclusiveNamespaces PrefixList` tam olarak bunu telafi etmek için vardır:
> ```xml
> <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
>    <ec:InclusiveNamespaces PrefixList="dsig soap #default"
>        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
> </ds:Transform>
> ```
> `#default` token'ı default namespace'i işaret eder; listedeki prefix'ler inclusive muamele görür.

**Saf Rust'ta yazmak ne kadar zor?** Algoritmanın kendisi (~500-800 satır) yapılabilir. Asıl zorluk **document-subset / node-set semantiğidir**: enveloped-signature transform'u `ds:Signature` alt ağacını node-set'ten çıkarır ve bunu doğru modellemek gerekir. Burada yapılan hata ya sessiz imza uyumsuzluğu ya da (daha kötüsü) XSW'ye açık bir doğrulayıcı üretir. **Yazma — 2026'da hazır bir çözüm var (§1.13).**

#### 1.2.3 Response mu, Assertion mı, ikisi birden mi?

| Kaynak | Kural |
|---|---|
| SAMLCore §5.1/§5.2 | İkisi de **MAY** — zorunlu değil |
| SAMLCore §5.3 | İmza kalıtımı: assertion imzasızsa ve kapsayan imzalı element onu kapsıyorsa, *"the resulting interpretation should be equivalent to the case where the assertion itself was signed"* |
| **SAMLProf §4.1.4.5** | **"If the HTTP POST binding is used to deliver the `<Response>`, the enclosed assertion(s) MUST be signed."** |
| SAMLProf §4.1.6 | SP metadata'daki `WantAssertionsSigned`: *"the identity provider is not obligated by this, but is being made aware of the likelihood that an unsigned assertion will be insufficient"* |

**Argus kararı:**
- **HTTP-POST'ta Assertion imzası ZORUNLUDUR** — bu, tarayıcı SSO'sunun %99'u demektir.
- **Varsayılan: HER İKİSİNİ DE imzala** (Response + Assertion), SP başına `sign_response` / `sign_assertion` bayrakları sun. İkisini imzalamak hiçbir SP'yi kırmaz; tek imzalamak bazılarını kırar.
- **Sıra kısıtı:** Önce **Assertion**'ı imzala, sonra **Response**'u. Ters sıra Response imzasını geçersiz kılar, çünkü Response imzası Assertion'ı (imzası dahil) kapsar.
- **Şifreleme varsa (SAMLCore §6.2):** önce **imzala**, sonra **şifrele**.

#### 1.2.4 2026'da kabul edilebilir algoritmalar

Otoriter kayıt: **RFC 9231, "Additional XML Security URIs", Temmuz 2022, Standards Track, RFC 6931'i geçersiz kılar.**

**Digest:**
| Algoritma | URI |
|---|---|
| SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
| SHA-384 | `http://www.w3.org/2001/04/xmldsig-more#sha384` |
| SHA-512 | `http://www.w3.org/2001/04/xmlenc#sha512` |

> ⚠️ **Asimetrik namespace tuzağı: SHA-256 ve SHA-512 `xmlenc#` altında, SHA-384 ise `xmldsig-more#` altındadır.** Tarihsel bir tutarsızlıktır ve elle URI yazan implementasyonlarda sık hata kaynağıdır. Argus'ta `const &str` sabitleri olarak tanımlanmalı.

**İmza:** `xmldsig-more#rsa-sha256` / `-sha384` / `-sha512`; RSASSA-PSS `http://www.w3.org/2007/05/xmldsig-more#rsa-pss` ve `#sha256-rsa-MGF1` ailesi; ECDSA `xmldsig-more#ecdsa-sha256/384/512`; **EdDSA (RFC 9231'in yeni getirdiği)** `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` ve `-ed448`.

**SHA-1'in 2026 durumu:**
- RFC 9231 bir URI kaydıdır, politika dokümanı değildir; SHA-1 için RFC 6194 değerlendirmesine yönlendirir, formel "MUST NOT" demez.
- **NIST SP 800-131A:** yürürlükteki sürüm **Revision 2, Mart 2019**. **Revision 3 hâlâ TASLAK** — ilk kamuya açık taslak, yorum süresi 4 Aralık 2024'te kapandı, 8 Eylül 2026 itibarıyla final yayımlanmamış. Rev 3'ün SHA-1 için kesin tarihli yasak metni **DOĞRULANMADI**.
- **Microsoft, aynı doküman sayfasında hem `rsa-sha1` zorunlu diyor hem SHA-1'i deprecated ilan ediyor** — gerçek bir çelişki (§1.11.2).

**Argus politikası:** Üretim varsayılanı **`rsa-sha256` + `sha256`**. Konfigürasyonla `rsa-sha384/512`, `ecdsa-sha256/384`. **SHA-1 üretimini kod tabanına koyma** — istisna: M365 gibi legacy hedefler için açıkça opt-in edilen, uyarı loglayan bir uyumluluk bayrağı. RSASSA-PSS ve Ed25519'un SP tarafı desteği pratikte yoktur; emit etme, yalnızca tip sisteminde tanımla.

#### 1.2.5 `<ds:KeyInfo>` içeriği

Spec opsiyonel bıraksa da pratikte **her zaman `<ds:X509Data><ds:X509Certificate>` yaz** (base64 DER). Çoğu SP kütüphanesi bunu bekler.

- **Zincir ekleme** — Metadata Interoperability Profile PKIX path validation'ı yasakladığı için (§1.10.3) gereksizdir; leaf sertifika yeterli.
- **`<ds:KeyValue>` ekleme** — gereksiz ve bazı SP'lerde "metadata yerine KeyInfo'daki ham anahtara güven" hatasını tetikleyebilir.
- **Güvenlik notu:** SP'ler imzayı **metadata'daki** sertifikaya karşı doğrulamalıdır, KeyInfo'dakine karşı değil. Argus bunu değiştiremez ama dokümantasyonunda belirtmelidir: **KeyInfo bir ipucudur, güven kaynağı değildir.**

### 1.3 EncryptedAssertion

#### 1.3.1 Yapı — SAMLCore §2.3.4

```
<EncryptedAssertion>
├── xenc:EncryptedData   [REQUIRED]  @Type SHOULD = ...xmlenc#Element
└── xenc:EncryptedKey    [sıfır veya daha fazla]  @Recipient SHOULD (SAML entity URI)
```

> **En sık interop kırılma noktası:** Şema `<EncryptedKey>`'in `<EncryptedData>`'nın **kardeşi** olmasına izin verir; XMLEnc ise `<EncryptedData>/<ds:KeyInfo>` **içinde** olmasına izin verir. **Her iki yerleşim de gerçek dünyada kullanılıyor.** Argus varsayılan olarak **iç yerleşimi** (`EncryptedData/KeyInfo/EncryptedKey`) üretmeli ve SP başına dışa taşıma seçeneği sunmalı.

#### 1.3.2 Algoritmalar — W3C XML Encryption 1.1

| Kategori | URI |
|---|---|
| AES-128/192/256-CBC | `http://www.w3.org/2001/04/xmlenc#aes{128,192,256}-cbc` |
| **AES-128/192/256-GCM** | `http://www.w3.org/2009/xmlenc11#aes{128,192,256}-gcm` |
| RSA v1.5 ❌ | `http://www.w3.org/2001/04/xmlenc#rsa-1_5` |
| RSA-OAEP (legacy, MGF1-SHA1) | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` |
| **RSA-OAEP (1.1, açık MGF)** | `http://www.w3.org/2009/xmlenc11#rsa-oaep` |
| ECDH-ES | `http://www.w3.org/2009/xmlenc11#ECDH-ES` |
| ConcatKDF | `http://www.w3.org/2009/xmlenc11#ConcatKDF` |
| AES-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes{128,192,256}` |

**Spec'in kendi uyarısı (XMLEnc 1.1 §5.1.1), birebir:**
> *"Use of AES GCM is **strongly recommended** over any CBC block encryption algorithms as recent advances in cryptanalysis have cast doubt on the ability of CBC block encryption algorithms to protect plain text when used with XML Encryption."*

İlgili güvenlik bölümleri: **§6.9 "CBC Block Encryption Vulnerability"**, **§6.1.2** (PKCS#1 v1.5 üzerine Bleichenbacher chosen-ciphertext). Arka plan: Jager & Somorovsky, *"How to Break XML Encryption"* (ACM CCS 2011) — XMLEnc 1.1'e GCM eklenmesinin doğrudan nedeni. *(Makalenin tam metnine erişilemedi — **kısmen DOĞRULANMADI**; ancak W3C REC metni iddiayı birincil kaynak olarak destekliyor.)*

**Argus politikası:**
- Varsayılan emit: **`aes256-gcm` + `xmlenc11#rsa-oaep` (MGF1-SHA256)**.
- Uyumluluk fallback'i: `aes256-cbc` + `rsa-oaep-mgf1p` — çok sayıda eski SP kütüphanesi GCM ve XMLEnc11 OAEP'i tanımaz.
- **`rsa-1_5`'i asla emit etme.** Kod tabanında bulunmasın.
- Algoritma seçimi SP metadata'sındaki `<md:KeyDescriptor use="encryption"><md:EncryptionMethod>` üzerinden yapılmalı — SAMLMeta §2.4.1.1 bu elemanı tam olarak bunun için tanımlar.
- ECDH-ES/ConcatKDF: gerçek dünya SAML SP desteği pratikte yok. **Implemente etme.**

#### 1.3.3 Ne zaman gerekir?

Spec zorunlu kılmaz. Gerekçeler: SAMLCore §2.3.4 "intermediary" senaryosu; SAMLSec §6.4.4 "Browser State Exposure" (HTTP-POST'ta assertion tarayıcı geçmişinde/diskte korumasız kalır); `<NameIDPolicy Format="...nameid-format:encrypted">` talebi. Ayrıca §3.4.1.1: IdP, politikası gerektiriyorsa Format'tan bağımsız olarak `<EncryptedID>` dönebilir (**MAY**).

**Hangi SP'ler şifreli assertion ŞART koşuyor: DOĞRULANMADI.** Bu araştırmada hiçbir satıcı dokümanında "encrypted assertion required" ifadesi doğrulanamadı. AWS şifrelemeyi opsiyonel bir yapılandırma olarak konumlandırır ve etkinleştirilirse ACS URL'inin `https://{region}.signin.aws.amazon.com/saml/acs/{IdP-ID}` biçimine dönüştüğünü belirtir.

### 1.4 NameID formatları — SAMLCore §8.3

| § | Format | URI |
|---|---|---|
| 8.3.1 | Unspecified | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` |
| 8.3.2 | Email Address | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| 8.3.3 | X.509 Subject Name | `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName` |
| 8.3.4 | Windows Domain Qualified Name | `urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName` |
| 8.3.5 | Kerberos Principal | `urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos` |
| 8.3.6 | Entity Identifier | `urn:oasis:names:tc:SAML:2.0:nameid-format:entity` |
| 8.3.7 | Persistent | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| 8.3.8 | Transient | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` |
| §3.4.1.1 | Encrypted (yalnızca NameIDPolicy'de) | `urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted` |

> ⚠️ **Prefix tuzağı:** unspecified / emailAddress / X509SubjectName / WindowsDomainQualifiedName **`SAML:1.1:`** kullanır; kerberos / entity / persistent / transient **`SAML:2.0:`** kullanır. Elle URI yazan implementasyonlarda en sık yapılan hatadır. **Enum + `const &str` olarak sabitlenmeli.**

`entity` formatı: URI, **max 1024 karakter**, ve *"NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted."*

#### 1.4.1 Persistent identifier — §8.3.7 (en detaylı bölüm)

> *"Persistent name identifiers generated by identity providers MUST be constructed using **pseudo-random values that have no discernible correspondence with the subject's actual identifier** (for example, username). The intent is to create a **non-public, pair-wise pseudonym** to prevent the discovery of the subject's identity or activities."*
> *"Persistent name identifier values MUST NOT exceed a length of **256 characters**."*
> *"they MUST NOT be shared in clear text with providers other than the providers that have established the shared identifier. Furthermore, they **MUST NOT appear in log files** or similar locations without appropriate controls and protections."*
> *"Deployments without such requirements are free to use other kinds of identifiers... but **MUST NOT overload this format with persistent but non-opaque values**."*

**Qualifier semantiği:**
- `NameQualifier` — identifier'ı **üreten** IdP'nin unique id'si. Bağlamdan türetilebiliyorsa omit edilebilir. **Ama identifier başka bir entity tarafından yeniden yayımlanırsa değişmez ve o durumda omit EDİLEMEZ.**
- `SPNameQualifier` — kimin için üretildiği (SP veya affiliation).
- `SPProvidedID` — SP'nin `ManageNameID` (§3.6) ile belirlediği alternatif id; yoksa **MUST omit**.

**Pairwise identifier hesaplama:**

**(a) Saklanan rastgele değer — spec'e en uygun, ÖNERİLEN:**
```
pid = base64url(CSPRNG(32 byte))        # 43 karakter, 256 limitinin altında
DB: (user_id, sp_entity_id) → pid       # UNIQUE index
```
Gerçekten rastgele; kullanıcı silinince silinebilir (KVKK/GDPR); IdP entity id değişse bile stabil.

**(b) Türetilmiş / anahtarlı — durumsuz, dikkatli kullan:**
```
pid = base64url(HMAC-SHA256(idp_secret, idp_entity_id ‖ sp_entity_id ‖ user_id))
```
`idp_secret` **gizli olmalı** — aksi halde "no discernible correspondence" ihlal edilir (SP, user_id tahmin ederek pid'i doğrulayabilir). Shibboleth'in "computed ID" yaklaşımının modern hâli. Dezavantaj: anahtar rotasyonu tüm pairwise id'leri kırar ve `AllowCreate="false"` semantiği anlamsızlaşır.

→ **Argus: (a) varsayılan, (b) opsiyonel durumsuz mod (rotasyon uyarısıyla).** Affiliation gerekiyorsa anahtarı `sp_entity_id` yerine `affiliation_id` üzerinden hesapla (`<md:AffiliationDescriptor>`, SAMLMeta §2.5).

> 🔴 **`persistent` NameID'yi asla e-posta veya kullanıcı adıyla doldurma.** Bu bir spec ihlalidir. Kalıcı ama opak olmayan değer istiyorsan `unspecified` veya `emailAddress` kullan.

#### 1.4.2 Transient identifier — §8.3.8

*"SHOULD be treated as an opaque and temporary value... MUST be generated in accordance with the rules for SAML identifiers (§1.3.4), and MUST NOT exceed a length of 256 characters."* → §1.3.4 entropi kuralları geçerlidir. Her SSO'da değişir; SLO için IdP'nin `SessionIndex` ↔ transient NameID eşlemesini oturum boyunca saklaması gerekir.

#### 1.4.3 ID üretimi — SAMLCore §1.3.4

> *"the probability of two randomly chosen identifiers being identical MUST be less than or equal to 2^-128 and SHOULD be less than or equal to 2^-160."*
> *"Where a data object declares that it has a particular identifier, there MUST be **exactly one** such declaration."*

Ayrıca `SubjectConfirmationData/@InResponseTo` tipi **`xs:NCName`**'dir → **ID'ler rakamla başlayamaz.**

**Argus kuralı: ID = `_` + 160 bit (20 byte) CSPRNG çıktısının hex kodu = `_` + 40 hex karakter.** Hem `NCName` kısıtını hem 2^-160 SHOULD'unu karşılar. UUIDv4 (122 bit) MUST'ı karşılar ama SHOULD'u karşılamaz.

> Spec, `xml:id` standartlaşınca ona geçilmesini planlıyordu — **bu geçiş hiç olmadı.** SAML-özel `ID` attribute'larının DTD'siz belgelerde "ID-typed" olarak tanınmaması, XSW saldırılarının teknik zeminidir (§1.11.3).

### 1.5 AttributeStatement ve NameFormat

`<Attribute>` (§2.7.3.1): `Name` (**REQUIRED**), `NameFormat?` (yoksa `...attrname-format:unspecified` yürürlükte), `FriendlyName?` — ⚠️ *"This attribute's value MUST NOT be used as a basis for formally identifying SAML attributes."*

| § | NameFormat | URI | Kısıt |
|---|---|---|---|
| 8.2.1 | Unspecified | `urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified` | Yorum implementasyona bırakılmış |
| 8.2.2 | URI Reference | `urn:oasis:names:tc:SAML:2.0:attrname-format:uri` | RFC 2396 URI reference |
| 8.2.3 | Basic | `urn:oasis:names:tc:SAML:2.0:attrname-format:basic` | `Name` **MUST** `xs:Name` tipinden olsun |

**Argus:** Varsayılan `attrname-format:uri` + OID/URN tabanlı `Name` (federasyon/eduPerson uyumu). **SP başına override zorunlu** — birçok ticari SP `basic` veya hiç NameFormat beklemez (Microsoft: `Name="IDPEmail"`, NameFormat **yok**). `FriendlyName`'i her zaman doldur (hata ayıklama) ama SP eşleştirmesinde **asla kullanma**.

#### Çok değerli attribute'lar ve boş/null semantiği (§2.7.3.1, §2.7.3.1.1)

- Her değer kendi `<AttributeValue>`'sunda olmalı (RECOMMENDED). Birden fazla değerde `xsi:type` varsa **hepsi aynı tipte olmalı**.
- **Attribute var ama hiç değeri yok** → `<AttributeValue>` **MUST omitted** (`<Attribute>` boş kalır).
- **Değer boş string** → `<AttributeValue/>`. Bu, §1.3.1'deki "en az bir non-whitespace karakter" kuralını **override eder**.
- **Değer "null"** → boş element **VE** `xsi:nil="true"`.

#### AttributeConsumingService (SAMLMeta §2.4.4.1-2)

`index` (required), `isDefault?`, `<ServiceName>` [1+] (`xml:lang` gerekir), `<ServiceDescription>*`, `<RequestedAttribute>` [1+] (`isRequired?`).
SAMLProf §4.1.4.2 açıkça izin verir: *"The identity provider MAY ignore this, or send other attributes at its discretion."* → Doğru davranış: index'i çöz, `isRequired="true"` olanları karşılayamıyorsan hata dön veya logla. **Attribute release politikası her zaman IdP'nin kontrolünde kalmalı.**

#### OID vs WS-* — iki ayrı dünya

AWS dokümanından doğrulanan eduPerson OID'leri: `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` (`eduPersonAffiliation`), `.6` (`eduPersonPrincipalName`), `.9` (`eduPersonScopedAffiliation`), `.10` (`eduPersonTargetedID`), `.11` (`eduPersonAssurance`), `urn:oid:2.5.4.3` (`cn`).

AD/WS-* claim URI'leri: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/{name,givenname,surname,emailaddress}`, `http://schemas.xmlsoap.org/claims/CommonName`, `http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid`.

> **Argus attribute kataloğunda her iki aileyi de hazır sun.** SP'ler ikiye bölünmüş durumda: araştırma/eğitim federasyonları OID kullanıyor, kurumsal SaaS ise WS-* veya düz isim.

### 1.6 SP-initiated vs IdP-initiated

#### Spec konumu — SAMLProf §4.1.5 "Unsolicited Responses"

> *"An unsolicited `<Response>` **MUST NOT** contain an `InResponseTo` attribute, nor should any bearer `<SubjectConfirmationData>` elements contain one."*
> *"the `<Response>` or artifact SHOULD be delivered to the `<md:AssertionConsumerService>` endpoint of the service provider designated as the **default**."*
> RelayState: *"the identity provider MAY include a binding-specific 'RelayState' parameter that indicates, **based on mutual agreement with the service provider**, how to handle subsequent interactions... This MAY be the URL of a resource at the service provider."*

#### IdP-initiated neden zayıf?

1. **`InResponseTo` yok → request/response bağı yok.** SP, bu assertion'ın kendi başlattığı bir akışa ait olduğunu doğrulayamaz.
2. **Login CSRF.** Saldırgan, kurbanın tarayıcısına *kendi* geçerli IdP-initiated Response'unu POST ettirebilir → kurban saldırganın hesabına giriş yapar. Sonrasında kurbanın yaptığı her şey (kart ekleme, doküman yükleme) saldırganın hesabına gider. SP'de CSRF token/state yoktur, çünkü akışı SP başlatmamıştır.
3. **RelayState → open redirect.** IdP-initiated'da RelayState "SP'de gidilecek URL" olarak yorumlanır. SP allow-list'lemezse `RelayState=https://evil.com` klasik open redirect verir. SAMLSec §6.4.6 bunu "Relay state tampering or fabrication" olarak sayar ve *"Because the value of this element is both produced and consumed by the same system entity, symmetric cryptographic primitives could be utilized"* der.
4. **Varsayılan ACS'e teslim** — SP'nin birden çok ACS'i varsa yanlış olana gidebilir.
5. **`ForceAuthn`/`RequestedAuthnContext` yok** — SP kimlik doğrulama gücünü talep edemez.

#### Kim zorunlu tutuyor?

- **AWS Management Console SSO'su fiilen IdP-initiated'dır.** AWS dokümanı akışı "IdP sends an authentication response to the AWS sign-in endpoint URL" olarak tarif eder, AuthnRequest'ten söz etmez.
- **Microsoft Entra/M365 SP-initiated'dır** — Entra AuthnRequest gönderir (§1.11.2).
- Diğer büyük SP'lerin IdP-initiated zorunluluğu: **DOĞRULANMADI.**

**Argus:** SP-initiated varsayılan. Her SP config'inde `allow_idp_initiated: bool` (**varsayılan false**). Açıkken: RelayState'i **HMAC'le veya opak handle yap**; yalnızca `isDefault="true"` ACS'e gönder; assertion ömrünü daha da kısalt; `InResponseTo`'yu **hiçbir yere yazma** (§4.1.5 MUST NOT).

### 1.7 Binding'ler

#### 1.7.1 HTTP-Redirect (§3.4)

Encoding identifier: `urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE`.

**DEFLATE prosedürü (§3.4.4.1):**
1. Mesaj üzerindeki her imza, **`<ds:Signature>` elementinin kendisi dahil, MUST kaldırılsın.** Spec ekler: *"the length of such a message after encoding essentially precludes using this mechanism. Thus SAML protocol messages that contain signed content SHOULD NOT be encoded using this mechanism."*
2. **RFC 1951 DEFLATE** — ⚠️ **raw deflate, zlib header/checksum YOK.** (Rust: `flate2::write::DeflateEncoder`, **`ZlibEncoder` değil**.)
3. RFC 2045 base64; **linefeed ve whitespace MUST kaldırılsın.**
4. URL-encode → `SAMLRequest` / `SAMLResponse`.
5. RelayState varsa URL-encode → `RelayState`.
6. Orijinal mesaj imzalıydıysa, kodlanmış veriyi kapsayan **yeni** imza eklenir.

> ### 🔑 İmzalanan octet string'in kurulumu (§3.4.4.1) — Argus için en kritik detay
> `SigAlg` parametresi eklenir; sonra **şu SIRAYLA, her biri URL-ENCODED hâlde** birleştirilir:
> ```
> SAMLRequest=value&RelayState=value&SigAlg=value
> SAMLResponse=value&RelayState=value&SigAlg=value
> ```
> *"Any other content in the original query string is not included and not signed."*
>
> **Üç hayati incelik:**
> 1. **İmzalama sırası sabittir** (`SAMLRequest|SAMLResponse` → `RelayState` → `SigAlg`), ama URL'deki gerçek parametre sırası serbesttir: *"The parameters may appear in any order. Before verifying a signature... the relying party MUST ensure that the parameter values to be verified are ordered as required by the signing rules above."*
> 2. **Değerler imzalanmadan ÖNCE URL-encode edilir.** Doğrulama tarafı için: *"URL-encoding is not canonical... The relying party MUST therefore perform the verification step using the **original URL-encoded values it received** on the query string. It is not sufficient to re-encode the parameters after they have been processed by software."*
> 3. **RelayState yoksa parametre tamamen atlanır** — *"if there is no RelayState value, the entire parameter should be omitted from the signature computation (and not included as an empty parameter name)."* Yani `SAMLResponse=x&SigAlg=y`, boş `RelayState=` **değil**.

**Diğer kurallar:**
- §3.4.5.2: *"If the message is signed, the `Destination` XML attribute in the root SAML element MUST contain the URL to which the sender has instructed the user agent to deliver the message."* → **İmzalı redirect üretirken `Destination` zorunludur.**
- HTTP status **MUST** 302 veya 303 (§3.4.5).
- §3.4.5.1: `Cache-Control: no-cache, no-store` ve `Pragma: no-cache` **SHOULD**.
- §3.4.3 RelayState: **MUST NOT exceed 80 bytes**; bütünlük koruması SHOULD. *"Signing is not realistic given the space limitation."* Request'e eşlik eden RelayState response'ta **MUST** birebir geri konsun.
- §3.4.6: SAML işleme hataları HTTP error status ile bildirilemez; `urn:oasis:names:tc:SAML:2.0:status:RequestDenied` kullanılır.
- §3.4.4.1 madde 5 yalnızca `dsa-sha1`/`rsa-sha1`'i MUST-support sayar (2005). 2026'da `rsa-sha256`.

#### 1.7.2 HTTP-POST (§3.5)

Base64 (DEFLATE **yok**), gizli form kontrolü `SAMLRequest`/`SAMLResponse` + `RelayState`. İmza **belgenin içindedir** (XMLDSig), query imzası yoktur. **Tarayıcı SSO'sunun ana yolu budur.**

#### 1.7.3 HTTP-Artifact

Response yerine kısa bir artifact taşınır; SP `ArtifactResolve` ile SOAP back-channel üzerinden gerçek mesajı çeker. Avantajı: assertion tarayıcıdan hiç geçmez. Dezavantajı: SOAP endpoint'i, karşılıklı kimlik doğrulama, ve IdP tarafında artifact→mesaj durumu.

**2026'da gerekli mi? Hayır.** Ticari SP'lerin ezici çoğunluğu HTTP-POST kullanır. **ATLANABİLİR (Faz 3+).**

#### Argus'un binding kararı
**ZORUNLU:** HTTP-POST (Response teslimi) + HTTP-Redirect (AuthnRequest alımı, SLO).
**ATLANABİLİR:** HTTP-Artifact, SOAP, PAOS/ECP — ECP istisnası: Microsoft'un rich client'ları (Outlook, IMAP/POP/ActiveSync) için `$ecpUrl` gerekir; ECP desteklenmezse yalnızca web istemcileri çalışır.

### 1.8 Single Logout (SLO)

#### Yapısal olarak neden kırık

⚠️ *Aşağıdakiler spec metninden çıkarılan yapısal nedenlerdir; satıcı beyanı değildir. Shibboleth'in bu konudaki meşhur resmî ifadesine bu araştırmada erişilemedi — **DOĞRULANMADI**.*

1. **Front-channel + üçüncü taraf çerez engellemesi.** Front-channel SLO, IdP'nin her SP'ye tarayıcı üzerinden (redirect zinciri veya gizli iframe) LogoutRequest ulaştırmasını gerektirir. 2026'da Safari ITP, Firefox TCP ve Chrome'un üçüncü taraf çerez kısıtları, iframe içindeki SP'nin **kendi oturum çerezini görememesine** yol açar → SP oturumu silemez ama `Success` dönebilir. **Sessiz başarısızlık.**
2. **Seri redirect zinciri kırılgandır.** N SP için N redirect; biri yavaş/ölü ise kullanıcı takılır. Spec'in `PartialLogout` status'u tam da bunu itiraf eder.
3. **SP'lerde oturum durumu yok/uyumsuz.** Birçok SaaS, SAML oturumunu kendi uzun ömürlü uygulama çerezine çevirir ve `SessionIndex`'i saklamaz → eşleşme yapamaz.
4. **Back-channel (SOAP) çerezi çözemez.** IdP SP'ye SOAP ile LogoutRequest gönderse bile, SP'nin **kullanıcının tarayıcısındaki çerezi** geçersizleştirmesi gerekir; bu ancak SP sunucu tarafında oturum kaydı tutuyorsa mümkündür. Ayrıca mTLS altyapısı gerekir.
5. **IdP'de durum yükü.** Argus'un her kullanıcı oturumu için `{SP entityID, NameID(Format+Qualifiers), SessionIndex, SLO endpoint, binding}` listesi tutması ve logout anında yürütmesi gerekir. **Bu, IdP'yi durumsuz olmaktan çıkarır.**

#### Kim destekliyor?

**Doğrulanan — Microsoft Entra / M365:** *"Microsoft Entra ID uses HTTP POST for the authentication request to the identity provider and **REDIRECT for the sign out message** to the identity provider."* Yapılandırmada `SignOutUri` (`$LogOffUrl`) `New-MgDomainFederationConfiguration` ile zorunlu verilir. → **Entra, IdP'den HTTP-Redirect binding'inde SLO endpoint'i bekler.**

**DOĞRULANMADI:** Salesforce, ServiceNow, Workday, AWS IAM Identity Center, Google Workspace, Slack, Zoom, Atlassian.
> AWS notu: IAM SAML assertion dokümanında SLO'dan hiç söz edilmez; AWS Console oturumu `SessionDuration`/`SessionNotOnOrAfter` ile **süre bazlı** sonlanır. Bu, AWS'nin SLO yerine oturum süresine dayandığına dair güçlü bir işarettir, ancak "desteklenmiyor" ifadesi **doğrulanmadı**.

#### Argus önerisi
- SLO'yu implemente et ama **"best-effort" olarak konumlandır** ve bunu dokümante et.
- `SessionIndex`'i **her zaman** üret — sonradan eklemek şema değişikliğidir.
- Oturum tablosu: `(user_session_id) → [{sp_entity_id, name_id{value,format,nq,spnq}, session_index, slo_url, slo_binding}]`
- Front-channel varsayılan; `PartialLogout` status'unu doğru dön.
- **IdP-local logout her zaman başarılı olsun** — SP propagasyonu başarısız olsa bile kullanıcının IdP oturumu kapansın.

### 1.9 Zaman, saat kayması, replay

#### Spec zemini ve SAMLSec §6.4.1 önerileri

> *"The Identity Provider and Service Provider sites SHOULD make some reasonable effort to ensure that clock settings at both sites differ by at most **a few minutes**."*
> *"Values for NotBefore and NotOnOrAfter attributes of SSO assertions SHOULD have the **shortest possible validity period**... typically **on the order of a few minutes**."*

**Replay — kimin işi?** SAMLProf §4.1.4.5: *"**The service provider MUST ensure** that bearer assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid."*

> ⚠️ **Bu bir SP yükümlülüğüdür, IdP'nin değil.** Argus kendi ürettiği assertion ID'lerini replay için cache'lemek **zorunda değildir**. Argus'un sorumluluğu: ID'lerin çakışmaması (§1.3.4 entropisi) ve pencerelerin kısa olması.
> **Argus'un kendi replay koruması gereken yer farklıdır: gelen `AuthnRequest` ve `LogoutRequest` ID'leri.**

#### Önerilen pencere değerleri

| Alan | Değer | Gerekçe |
|---|---|---|
| `Response/@IssueInstant`, `Assertion/@IssueInstant` | now | — |
| `AuthnStatement/@AuthnInstant` | **gerçek auth anı** (SSO yeniden kullanımında ≠ now) | Spec semantiği |
| `Conditions/@NotBefore` | **now − 60 sn** | Karşı tarafın saat sapması payı |
| `Conditions/@NotOnOrAfter` | **now + 5 dk** | SAMLSec "a few minutes" |
| `SubjectConfirmationData/@NotOnOrAfter` | **now + 5 dk** | Conditions penceresinin içinde kalmalı (§2.4.1.2 SHOULD) |
| `SubjectConfirmationData/@NotBefore` | **YAZMA** | SAMLProf §4.1.4.2 **MUST NOT** |
| `AuthnStatement/@SessionNotOnOrAfter` | now + oturum ömrü (ör. 8 sa) | SP'nin oturum sonlandırması |
| Kabul edilen saat kayması (gelen mesajlarda) | **±3 dk**, konfigüre edilebilir | — |

**`<OneTimeUse>`:** SAMLSec §6.4.4 SHOULD der. Ancak SAMLCore §2.5.1.1 madde 3 gereği **anlaşılmayan condition → `Indeterminate` → MUST rejected**; bazı SP'ler `<OneTimeUse>`'u anlamayıp assertion'ı reddeder. ⚠️ **Gerçek bir risktir. Argus'ta varsayılan kapalı, SP başına opt-in.**

**Format (SAMLCore §1.3.3):** UTC. **`YYYY-MM-DDTHH:MM:SSZ` üret; timezone offset (`+03:00`) kullanma** — bazı SP parser'ları kırılır.

### 1.10 Metadata yönetimi — "en çok kırılan yer"

#### 1.10.1 validUntil / cacheDuration

Bu iki attribute `<EntitiesDescriptor>`, `<EntityDescriptor>` ve `RoleDescriptorType` seviyelerinde bulunur.
- `validUntil`: *"the expiration time of the metadata contained in the element **and any contained elements**"*
- `cacheDuration`: tüketicinin önbellekte tutabileceği azami süre
- **§2.2.1:** *"When used as the root element of a metadata instance, this element MUST contain either a validUntil or cacheDuration attribute."*

**Neden en çok kırılan yer:**
1. `validUntil` geçince tüketici metadata'yı **reddeder → federasyon aniden çöker**, ve hata mesajı genellikle anlaşılmazdır.
2. `validUntil` **iç içe elemanlara yayılır** — `EntitiesDescriptor` seviyesindeki kısa bir değer içindeki tüm entity'leri düşürür.
3. `cacheDuration` bir `xs:duration`'dır; tüketiciler farklı yorumlar (bazıları `validUntil` ile min alır, bazıları yok sayar).
4. **Sertifika rotasyonuyla etkileşim:** yeni sertifika metadata'ya konduktan sonra tüketicilerin `cacheDuration`/`validUntil` kadar beklemesi gerekir; buna uyulmadan geçiş yapılırsa imzalar reddedilir.

**Argus önerisi:** `validUntil` = now + 14 gün, `cacheDuration` = `PT6H`; metadata'yı otomatik yeniden imzalayıp yayınlayan bir zamanlanmış görev.

#### 1.10.2 İmzalı metadata — SAMLMeta §3

§3.1 "XML Signature Profile", SAMLCore §5.4'ün metadata karşılığıdır (aynı kısıtlar: enveloped, tek Reference, exc-c14n, sınırlı transform'lar). `<ds:Signature>`, `<EntityDescriptor>` veya `<EntitiesDescriptor>` üzerine atılır.

#### 1.10.3 🔑 Metadata Interoperability Profile — güven modelinin kalbi

**"SAML V2.0 Metadata Interoperability Profile Version 1.0", OASIS Standard, 24 Ekim 2019** (`docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop.html`)

Bu, çoğu geliştiricinin bilmediği ama Argus'un implemente etmesi gereken güven modelidir:

> **§2.6.1 — PKIX YOK:** *"consumers SHALL NOT apply any online or offline techniques including, but not limited to, X.509 path validation or revocation lists, OCSP responders, etc."*
> **§2.5.1 — Sertifika geçerliliği önemsiz:** *"the certificate may be **expired**, **not yet valid**, carry critical or non-critical extensions or usage flags, and contain any subject or issuer."*
> **§2.5.1 — Her anahtar kendi KeyDescriptor'ında:** *"Each key included in a metadata role MUST be placed within its own `<md:KeyDescriptor>` element, with the appropriate use attribute."*

**Anlamı:** Metadata'daki sertifika bir **çıplak açık anahtar taşıyıcısıdır.** Güven, sertifika zincirinden değil, **metadata'nın kendisinin güvenilir şekilde elde edilmiş olmasından** gelir.

Bunun iki somut sonucu var:
- Argus'un imza sertifikasının **süresi dolabilir ve IOP-uyumlu SP'lerde hiçbir şey kırılmaz.** Ama IOP-uyumsuz SP'ler CA doğrulaması yapar ve kırılır — **bu, "SSO bir sabah aniden bozuldu" vakalarının en yaygın nedenidir.**
- Self-signed, uzun ömürlü (ör. 10 yıl) sertifika kullanmak SAML'da **doğru pratiktir**, kötü pratik değil.

#### 1.10.4 Sertifika rotasyonu — doğru prosedür

`<KeyDescriptor use="signing">` **çoklu olabilir** (SAMLMeta §2.4.1.1, `maxOccurs="unbounded"`):

```
T0    : Metadata'ya YENİ sertifikayı EKLE (eski kalsın → iki adet use="signing").
        İmzalamaya hâlâ ESKİ anahtarla devam et.
T0+Δ  : Δ ≥ max(cacheDuration, tüm tüketicilerin yenileme periyodu). 14 gün güvenli.
T1    : İmzalamayı YENİ anahtara geçir. Metadata'da ikisi de durmaya devam etsin.
T1+Δ  : ESKİ sertifikayı metadata'dan kaldır.
```

> **Bir anda hem imzalama anahtarını değiştirip hem metadata'yı güncellemek garantili kesintidir**, çünkü tüketiciler metadata'yı önbelleğe almıştır. **İki fazlı geçiş zorunludur.**

**Encryption anahtarında sıra terstir:** Argus decrypt etmez, encrypt eder → **SP'nin** encryption sertifikası rotasyonunu Argus takip etmelidir (metadata'yı düzenli yeniden çekerek ve her iki `use="encryption"` anahtarını da kabul ederek).

#### 1.10.5 MDQ — Metadata Query Protocol

- Doküman: **draft-young-md-query**, Ian A. Young (ed.). Bu araştırmada görülen sürüm **-18, 6 Ocak 2023**; sayfa "latest is **-25**, Active" diyor.
- **Status: Internet-Draft — IETF standartlar sürecinin parçası DEĞİL.** *"product of REFEDS Working Group"*.
- URL yapısı: `<base URL '/' ile biter>` + `"entities/"` + percent-encoded identifier. `'/'` **MUST** percent-encoded, boşluk **MUST** `%20`.
- ⚠️ **Yaygın bilinen `entities/{sha1}<hex>` biçimi bu temel protokolde TANIMLI DEĞİLDİR** — *"reserved for profile specifications"*. Ayrı bir SAML profil dokümanında tanımlıdır; o dokümanın tam adı/sürümü **DOĞRULANMADI**.
- Önbellek: **`ETag` MUST**; değişmemişse sunucular **SHOULD 304**; `Cache-Control: max-age` hem 200 hem 404 için önerilir.
- İmzalama protokol seviyesinde tanımlı değildir.
- Kullanıcılar: InCommon, eduGAIN gibi araştırma/eğitim federasyonları. **Ticari SaaS'ta MDQ kullanımı DOĞRULANMADI.**

**Argus:** MDQ **tüketicisi** olmak v1 için gereksiz (ticari SP'ler dosya/URL ile metadata verir). MDQ **sunucusu** olmak yalnızca akademik federasyona girilecekse anlamlı. **P3.**

### 1.11 Saldırılar — hangileri IdP'yi ilgilendiriyor?

#### 1.11.1 Etki tablosu

| Saldırı | Etkilenen taraf | Argus (IdP) için anlamı |
|---|---|---|
| XML Signature Wrapping (XSW1-8) | **SP (doğrulayıcı)** | Doğrudan etkilemez; ama ürettiğimiz belge yapısı SP'nin direncini etkiler (§1.11.3) |
| Parser differential (CVE-2025-25291/25292) | **SP** | Argus SP-tarafı doğrulama yaparsa (AuthnRequest imza kontrolü) **aynı sınıf hata Argus'ta da olabilir** |
| Comment truncation (CVE-2017-11427/11428) | **SP** | Dolaylı: NameID değerlerinde yorum/özel karakter üretme |
| **XXE / DTD entity expansion** | **HER İKİSİ** | **Argus doğrudan etkilenir** — gelen AuthnRequest/LogoutRequest parse edilir |
| **Decompression bomb** (CVE-2025-25293, CVE-2023-28119) | **HER İKİSİ** | **Argus doğrudan etkilenir** — HTTP-Redirect DEFLATE açar |
| **RelayState open redirect** | **HER İKİSİ** | **Argus doğrudan etkilenir** |
| **ACS URL manipülasyonu** | **IdP** | **Argus'un birincil riski** (SAMLProf §4.1.4.1) |
| **Golden SAML** (anahtar hırsızlığı) | **IdP** | **Argus'un varoluşsal riski** — §1.11.4 |
| XML Encryption CBC padding oracle | SP (çözücü) | Argus GCM seçerek SP'yi korur |
| Bleichenbacher (RSA-1.5) | SP (çözücü) | Argus `rsa-1_5` emit etmeyerek önler |

#### 1.11.2 Doğrulanan CVE'ler (NVD REST API'den birebir)

| CVE | Ürün | Yayın | CVSS | Öz |
|---|---|---|---|---|
| **CVE-2025-25291 / 25292** | ruby-saml < 1.12.4 / 1.18.0 | 2025-03-12 | **9.8 CRITICAL** | *"authentication bypass... due to a **parser differential**. ReXML and Nokogiri parse XML differently; the parsers can generate entirely different document structures from the same XML input. That allows an attacker to be able to execute a Signature Wrapping attack."* |
| **CVE-2025-25293** | ruby-saml | 2025-03-12 | 7.5 HIGH | *"the **message size is checked before inflation and not after**"* → DoS |
| **CVE-2024-45409** | ruby-saml ≤1.16.0 | 2024-09-10 | **10.0 CRITICAL** | *"An unauthenticated attacker with access to **any signed saml document (by the IdP)** can thus forge a SAML Response/Assertion with arbitrary contents."* |
| **CVE-2025-29774 / 29775** ("SAMLStorm") | xml-crypto < 6.0.1/3.2.1/2.1.6 | 2025-03-14 | **9.3** | *"modify a valid signed XML message in a way that still passes signature verification checks"* |
| **CVE-2017-11427 / 11428** | python-saml ≤2.3.0 / ruby-saml ≤1.6.0 | 2019-04-17 | 7.7 HIGH | *"may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature"* (US-CERT VU#475445) |
| **CVE-2022-39299** | passport-saml | 2022-10-12 | 7.4 | *"requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, **fully unauthenticated attacks might also be feasible if generation of a signed message can be triggered**."* |
| **CVE-2023-28119** | crewjam/saml (Go) < 0.4.13 | 2023-03-22 | 7.5 | `flate.NewReader` girdi sınırı yok → decompression DoS |
| **CVE-2018-0489** | Shibboleth XMLTooling-C < 1.6.4 | 2018-02-27 | 6.5 | CVE-2018-0486'nın eksik düzeltmesi |
| **CVE-2025-23369** | GitHub Enterprise Server | 2025-01-21 | 8.8 | İmza spoofing; SAML SSO kullanmayanlar etkilenmedi |
| **CVE-2025-54419** | Node-SAML ≤5.0.1 | — | — | *"loads the assertion from the unsigned original document rather than the verified signed portion"* |
| **CVE-2025-66578** | xmlseclibs (PHP) < 3.1.4 | — | — | libxml2 canonicalization kusuru: geçersiz XML işlenirken **boş string üzerine digest** hesaplanıyor ve geçerli sayılıyor |

> 🔴 **CVE-2022-39299'un cümlesi Argus'u doğrudan ilgilendirir:** *"if generation of a signed message can be triggered"*. Argus, kimliği doğrulanmamış bir istekle imzalı bir artefakt üretmeye ikna edilebiliyorsa (imzalı hata Response'ları, imzalı metadata), zayıf SP'ler için saldırı yüzeyi sağlamış olur. **İmzalı çıktı üretimini kimlik doğrulamasına bağla.**
> Aynı şekilde **CVE-2024-45409**: "IdP tarafından imzalanmış **herhangi** bir belge" ile sömürülebiliyordu — yani Argus'un ürettiği her imzalı artefakt (metadata dahil) bir saldırı girdisidir.

**Comment truncation mekanizması** *(KISMEN DOĞRULANMADI — Duo'nun orijinal teknik yazısı 2026-09-08 itibarıyla erişilemez durumda; aşağıdaki açıklama CVE metni temellidir):* Yorumsuz C14N varyantı XML yorumlarını **çıkarır**, imza geçerli kalır. Ama DOM'dan metin çıkaran bazı API'ler yalnızca **ilk text node**'u döner. `<NameID>admin@example.com<!----> .evil.com</NameID>` yapısında doğrulayıcı tam string'i görür, kimlik çıkaran kod `admin@example.com` alır. Düzeltme: tüm text node'ları birleştirmek (`textContent` semantiği).

#### 1.11.3 XSW — IdP ne yapabilir?

XSW'nin kök nedeni SAMLCore §5.4'te gizlidir: imza `ID` attribute'una **same-document reference** ile bağlanır. DTD/şema olmadan XML parser'lar bir attribute'un "ID-typed" olduğunu bilmez; belgede **aynı ID'ye sahip iki element** varsa hangisinin referans edildiği implementasyona bağlıdır. SAMLCore §1.3.4 bunu yasaklar (*"there MUST be exactly one such declaration"*) ama **doğrulayıcının bunu zorlaması gerekir** — çoğu zorlamadı.

*XSW1-8 taksonomisinin birebir tanımları bu araştırmada birincil kaynaktan doğrulanamadı — **DOĞRULANMADI**. Referans: Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be", USENIX Security 2012.*

**IdP tarafında yapılabilecekler:**
1. **Basit, tek-assertion, tek-imza belgeler üret.** `<Advice>`, `<Extensions>`, gereksiz `<Object>` kullanma. Belge ne kadar düzse SP'nin yanlış element seçme ihtimali o kadar düşük.
2. **Assertion + Response'u birlikte imzala** — saldırganın iki imzayı birden atlatması gerekir.
3. **ID'ler yüksek entropili** (§1.4.3) — tahmin/çakışma yoluyla wrapping'i zorlaştırır.
4. **Argus'un KENDİ doğrulayıcısı için** (AuthnRequest/LogoutRequest imza kontrolü): **tek parser** kullan (parser differential yok), **yinelenen ID'yi reddet**, **DTD'yi tamamen kapat**, ve **imzalanan element ile veriyi okuduğun elementin aynı nesne olduğunu referans eşitliğiyle doğrula** (XPath ile ikinci kez arama yapma). Bu tam olarak CVE-2025-25291'in dersidir.

#### 1.11.4 Golden SAML — IdP'nin varoluşsal riski

SolarWinds/Solorigate saldırısında kullanılan teknik: saldırgan ADFS sunucusunu ele geçirip **assertion imzalama özel anahtarını çaldı** ve istediği kullanıcı olarak istediği federe servise (AWS, Office 365) kendi "altın" SAML token'larını üretti. (CISA Alert AA20-352A)

> **Bu, Argus'un tek gerçek varoluşsal riskidir.** İmzalama anahtarı çalınırsa tüm federasyon çöker ve **hiçbir SP bunu tespit edemez** — imza geçerlidir. Savunma:
> - İmzalama anahtarı **HSM/KMS'te** dursun, süreç belleğinde uzun süre kalmasın (§1.13.2'de `kryptering`'in PKCS#11 desteği bu yüzden stratejiktir).
> - Her imzalama işlemi **denetim kaydına** girsin; anormal hacim alarm üretsin.
> - Anahtar rotasyonu **rutin** olsun (§1.10.4), böylece rotasyon bir acil durum prosedürü değil, test edilmiş bir işlem olsun.

#### 1.11.5 XXE ve DoS — Argus'un doğrudan sorumluluğu

Zorunlu sertleştirmeler:
- **DTD işlemeyi tamamen kapat** (`<!DOCTYPE` reddi). XXE, billion laughs, external entity — hepsi burada biter.
- **External entity resolution kapalı**, ağ erişimi yok.
- **Inflate limiti:** sıkıştırılmış boyut kontrolü **YETMEZ** (CVE-2025-25293'ün tam dersi). Açılmış byte sayısını **akış hâlinde** sınırla (ör. 1 MB sert tavan). Rust'ta: `flate2::read::DeflateDecoder` üzerine `std::io::Read::take(limit)`.
- **Sıkıştırma oranı kontrolü:** açılan/sıkışık > 100 ise reddet.
- **Azami XML derinliği ve element sayısı** limitleri.
- `quick-xml` gibi pull parser'lar bu limitleri uygulamak için doğru araçtır.

#### 1.11.6 "SAML is insecure by design" tartışması

Argümanın özü: XMLDSig **belgenin bir alt kümesini** imzalar ve "hangi alt küme" sorusunu belgenin kendisi (ID referansıyla) belirler. Bu, **imza doğrulama ile veri okuma arasında bir ayrışma** yaratır. Güvenli tasarım, imzanın *tüm* mesajı kapsaması ve doğrulanan baytların doğrudan tüketilmesidir — JWS/JWT'nin yaptığı budur.

**Argus için pratik sonuç:** Bu yapısal zafiyeti IdP olarak ortadan kaldıramazsın. Yapabileceğin: (a) kendi doğrulayıcını doğru yaz, (b) basit belgeler üret, (c) mümkün olan yerde OIDC'yi tercih ettir.

### 1.12 Büyük SP'lerin gereksinimleri

#### 1.12.1 AWS (IAM SAML federation) — TAM DOĞRULANDI
`docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html`

> *"The response must include **exactly one** `SubjectConfirmation` element with a `SubjectConfirmationData` element that includes **both** the `NotOnOrAfter` attribute **and** a `Recipient` attribute. The Recipient attribute must include a value that matches the AWS sign-in endpoint URL."*

**Desteklenen NameID formatları:** persistent, transient, emailAddress, unspecified, X509SubjectName, WindowsDomainQualifiedName, kerberos, entity (tam liste).

**Endpoint'ler:** global `https://signin.aws.amazon.com/saml`; bölgesel `https://{region-code}.signin.aws.amazon.com/saml`; **şifreleme varsa** `https://{region-code}.signin.aws.amazon.com/saml/acs/{IdP-ID}`; `SessionDuration` için `https://signin.aws.amazon.com/static/saml` de kullanılabilir.

**Attribute'lar — `Name` değerleri BÜYÜK-KÜÇÜK HARFE DUYARLI ve birebir olmalı:**

| Attribute Name | Zorunlu | Değer |
|---|---|---|
| `https://aws.amazon.com/SAML/Attributes/Role` | Evet | `arn:aws:iam::<acct>:role/<role>,arn:aws:iam::<acct>:saml-provider/<provider>` — virgülle ayrılmış ARN çifti; çoklu değer → kullanıcıya rol seçtirilir |
| `https://aws.amazon.com/SAML/Attributes/RoleSessionName` | Evet | 2-64 karakter; alfanumerik + `_ . , + = @ -`. **Boşluk YASAK** |
| `.../SessionDuration` | Hayır | Saniye, **900-43200**. Yoksa 1 saat |
| `.../SourceIdentity` | Hayır | 2-256 karakter; rol trust policy'sinde `sts:SetSourceIdentity` yoksa **AssumeRole başarısız olur** |
| `.../PrincipalTag:{TagKey}` | Hayır | Her tag için ayrı `<Attribute>` |
| `.../TransitiveTagKeys` | Hayır | Transitive yapılacak tag key'leri |

**Tuhaflıklar:**
- *"The value of the `Name` attribute... is **case-sensitive**. It must be set to... **exactly**."* (dokümanda üç kez tekrarlanır)
- `SessionDuration` **ve** `SessionNotOnOrAfter` birlikte varsa **küçük olan kazanır**.
- 🔑 **`saml:aud` IAM condition key'i SAML `Recipient` attribute'undan gelir, `Audience`'tan DEĞİL.** IAM trust policy yazanlar için kritik incelik.
- Konsol SSO'su **IdP-initiated**'dır.
- SLO dokümanda hiç geçmiyor → **DOĞRULANMADI**.

#### 1.12.2 Microsoft Entra ID / M365 (SP rolünde) — TAM DOĞRULANDI
`learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp` (sayfa `ms.date: 2025-04-09`, güncelleme 2026-02-26)

**SAML 2.0 SP-Lite profili** senaryosu (üçüncü taraf IdP → M365).

- **NameID Format:** *"Microsoft Entra ID currently supports the following NameID Format URI for SAML 2.0: **`urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`**"* — **yalnızca persistent.**
- **NameID değeri:** *"must be the same as the Microsoft Entra user's **ImmutableID**. It can be up to **64 alpha numeric characters**. Any non-html safe characters must be encoded, for example a '+' character is shown as '.2B'."*
- **UPN taşıyıcısı:** *"The User Principal Name (UPN) is listed in the SAML response as an element with the name **IDPEmail**"*
  ```xml
  <Attribute Name="IDPEmail"><AttributeValue>administrator@contoso.com</AttributeValue></Attribute>
  ```
  ⚠️ **`NameFormat` attribute'u YOK; `Name` düz bir string.** URI değil. `attrname-format:uri` varsayan IdP'leri kırar.
- **Audience:** `urn:federation:MicrosoftOnline` · **Destination/Recipient:** `https://login.microsoftonline.com/login.srf` · **Entra'nın Issuer'ı:** `urn:federation:MicrosoftOnline`
- **İmza — dokümanın normatif listesi:** (1) *"The **assertion node itself must be signed**"*; (2) *"The RSA-sha1 algorithm must be used as the DigestMethod. **Other digital signature algorithms aren't accepted.**"*; (3) *"You **can also** sign the XML document"* (Response imzası opsiyonel); (4) Transform'lar enveloped-signature + exc-c14n olmalı; (5) SignatureMethod `rsa-sha1`.
- 🔴 **Ve aynı sayfada:** *"Note: In order to improve the security SHA-1 algorithm is deprecated. Ensure to use a more secure algorithm like SHA-256."* → **Doküman kendi içinde çelişkilidir.** Argus yaklaşımı: SHA-256 ile başla; M365 federasyonu başarısız olursa SHA-1'e düşen SP-özel bir bayrak bulundur. **Canlı test yapılmadan kesin karara bağlanmamalı.**
- **Binding'ler:** *"HTTPS is the required transport... Microsoft Entra ID requires **HTTP POST** for token submission... uses **HTTP POST for the authentication request** and **REDIRECT for the sign out message**."*
- **SessionIndex** örnekte assertion ID'siyle aynı. **AuthnContext:** `...ac:classes:PasswordProtectedTransport`.
- Entra'nın AuthnRequest'i minimaldir: yalnızca `Issuer` + `NameIDPolicy Format="...persistent"`. `Destination`, `AssertionConsumerServiceURL`, `ForceAuthn`, `IsPassive` **yok**. İmzalı varyantta KeyInfo'da `<ds:X509SKI>` + `<ds:KeyName>MicrosoftOnline</ds:KeyName>` kullanılır (**X509Certificate değil**).
- 🔴 ***"Microsoft Entra ID does not read metadata from the identity provider."*** → **Argus'un metadata'sı Entra'ya işe yaramaz**; sertifika elle (`New-MgDomainFederationConfiguration -SigningCertificate`) verilir. **Sertifika rotasyonu manuel ve kırılgandır** — §1.10.4'teki otomatik prosedür Entra için geçersizdir.
- *"Verify the clock on your SAML 2.0 identity provider server is synchronized to an accurate time source. An inaccurate clock time can cause federated logins to fail."*
- **ECP/PAOS endpoint'i (`$ecpUrl`)** rich client'lar (Outlook, IMAP/POP/ActiveSync) için gerekir — desteklenmezse yalnızca web istemcileri çalışır.

#### 1.12.3 Google Workspace — KISMEN DOĞRULANDI
`knowledge.workspace.google.com/admin/apps/sso-assertion-requirements`

- **NameID Format:** `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- **NameID değeri:** kullanıcının birincil e-posta adresi, **büyük-küçük harfe duyarlı**
- **ACS URL (SSO profile):** `https://accounts.google.com/samlrp/<id>/acs`; **legacy profile:** `https://www.google.com/a/<domain>/acs` veya `https://accounts.google.com/a/<domain>/acs`
- **Entity ID (legacy):** `google.com` veya `google.com/a/<domain>`
- **Destination:** opsiyonel; set edilirse ACS URL ile eşleşmeli
- 🔴 **Attribute veri limiti: *"You can only pass a maximum of 2kB of attribute data in your assertions."*** — attribute release politikasında sert sınır.

**DOĞRULANMADI (bu sayfada yok):** imza algoritması gereksinimi, sertifika/anahtar boyutu, Response vs Assertion imzalama, şifreli assertion, SLO.

#### 1.12.4 Diğerleri — DOĞRULANMADI

**Salesforce, ServiceNow, Workday, AWS IAM Identity Center (klasik IAM SAML'dan ayrı ürün), Slack, Zoom, Atlassian Cloud** için bu araştırmada **hiçbir** NameID formatı, attribute adı, imza yeri veya SLO desteği doğrulanamadı. Salesforce'un yardım sitesi bir SPA'dır ve `articleView` URL'leri içerik döndürmedi; diğerleri erişilemedi veya müşteri girişi arkasındadır.

> ⚠️ **Bu yedi satıcı için gereksinim yazarken kendi bilginizden doldurmayın.** Uydurulmuş bir attribute adı, sessizce başarısız olan bir entegrasyon demektir. Ayrı bir doğrulama turu gerekir.

#### 1.12.5 Doğrulanabilenlerin karşılaştırması

| | NameID Format | NameID değeri | İmza yeri | Şifreleme | SLO | SHA-1? |
|---|---|---|---|---|---|---|
| **AWS (IAM SAML)** | 8 format kabul | Serbest | POST → assertion imzalı | Opsiyonel (ACS URL değişir) | Doküman değinmiyor | Belirtilmemiş |
| **Entra / M365** | **yalnızca persistent** | **ImmutableID**, ≤64 alfanumerik | **Assertion MUST**; Response opsiyonel | Belirtilmemiş | **Evet — HTTP-Redirect** | Doküman `rsa-sha1` diyor ama SHA-1'i deprecated ilan ediyor (çelişki) |
| **Google Workspace** | **emailAddress** | Birincil e-posta (harf duyarlı) | Belirtilmemiş | Belirtilmemiş | Belirtilmemiş | Belirtilmemiş |

### 1.13 Rust ekosistemi — 2026'nın en önemli bulgusu

Tüm veriler **crates.io REST API**'sinden 8 Eylül 2026'da çekildi.

#### 1.13.1 `samael` — mevcut fiili standart

| | |
|---|---|
| Sürüm | **0.0.22**, 2026-07-07 |
| İndirme | **689.252** toplam / **222.678** son 90 gün |
| Repo / lisans | `github.com/njaremko/samael` (branch `master`) / MIT |
| Oluşturma | 2020-02-23 |

README'den doğrulanan yetenekler: SAML mesajlarını serileştirme/ayrıştırma; **IdP-initiated SSO**; SP-initiated SSO Redirect-POST binding; assertion doğrulama yardımcıları; **AuthnRequest imza doğrulama**; **imzalı Response üretme**.

> *"The `xmlsec` feature flag adds basic support for verifying and signing SAML messages. We're using a **modified copy of rust-xmlsec** library (bindings to xmlsec1 library)."*

**Gereken C kütüphaneleri:** `libiconv`, `libtool`, `libxml2`, `libxslt`, `libclang`, `openssl`, `pkg-config`, `xmlsec1`. Bağımlılık listesi doğruluyor: `bindgen ^0.72.1` (build, **opsiyonel değil**), `pkg-config`, `openssl`/`openssl-sys`, **`libxml =0.3.3` (tam sürüm sabitlenmiş)**.

**Değerlendirme:**
- ❌ **Saf Rust değil.** `xmlsec` feature'ı olmadan imzalama yok; feature ile 8 C kütüphanesi build zinciri gelir → Docker imajı şişer, cross-compile ve `musl` statik binary zorlaşır, tedarik zinciri yüzeyi büyür. (Proje `nix flake` ile build ediliyor — bu, zincirin ne kadar can sıkıcı olduğunun itirafı.)
- ❌ **Şifreleme desteği zayıf:** yalnızca `aes128-cbc` ve `aes128-gcm` — **AES-256 yok**; ve `rsa-1_5` destekleniyor (bugün emit edilmemeli).
- ⚠️ README: *"This is a work in progress."*
- ✅ Ekosistemin en çok indirilen ve en olgun seçeneği.

#### 1.13.2 `bergshamra` + `gamlastan` — saf Rust XML Security ve SAML yığını

Yazar: **Kushal Das** (`github.com/kushaldas/`). Lisans: **BSD-2-Clause**.

**`bergshamra` — xmlsec1'in saf Rust muadili**

| | |
|---|---|
| Sürüm | **0.9.0**, 2026-09-02 |
| İndirme | 62.096 toplam / 50.910 son 90 gün (`bergshamra-core` alt crate'i: 164.393 / 149.626) |
| Oluşturma | 2026-02-22 |
| Sürüm temposu | 0.3.1 (03-06) → 0.4.0 (04-02) → 0.5.x (06-07) → 0.6.x (06-27…07-03) → 0.7.0 (07-06) → 0.8.0 (08-01) → 0.9.0 (09-02) — **çok aktif** |

Workspace: `bergshamra-{core,xml,c14n,crypto,keys,transforms,dsig,enc}`, hepsi v0.9.0. Alt bağımlılıklar: **`uppsala ^0.10`** (saf Rust XML parser/DOM/XPath/XSD) ve **`kryptering ^0.5.0`**.

Doğrulanan yetenekler:
- **C14N:** *"all 6 W3C C14N variants (inclusive/exclusive, with/without comments, 1.0/1.1) with **document-subset filtering via XPath**"* → **exc-c14n dahil ve node-set semantiği var** — §1.2.2'de zor olduğunu söylediğim tam olarak bu kısım.
- **XML Signature:** enveloped, enveloping, detached — hem imzalama hem doğrulama.
- **Algoritmalar:** RSA PKCS#1 v1.5, RSA-PSS, ECDSA (P-256/384/521), DSA, Ed25519, HMAC, ve **post-quantum ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)**.
- **XML Encryption:** element/content, key wrapping, key transport, multi-recipient; AES-CBC/GCM, AES-KW, RSA-OAEP, **ECDH-ES**, X25519.
- **Crypto provider seçilebilir:** *"Exactly one of `rustcrypto` or `aws-lc` is required."* `fips` feature'ı AWS-LC seçer.
- **Saf Rust** — libxml2/xmlsec1 C bağımlılığı **yok**.
- **`#![forbid(unsafe_code)]`** her workspace crate'inde.
- **XSW savunması: "Duplicate ID rejection (always on)"** — tam olarak §1.11.3'te istediğimiz şey.
- 🔑 **Interop kanıtı:** *"passes the full xmlsec interoperability test suite"* — **Enc 701/0, DSig 447/0, toplam 1148 geçti, 0 başarısız, 3 atlandı** (atlananlar GOST imzaları). W3C, Merlin, Aleksey, IAIK, NIST ve Phaos test vektörlerini kapsıyor. Bir Python shim'i, değiştirilmemiş xmlsec test script'lerini doğrudan bergshamra'ya karşı çalıştırıyor.
- Rust 1.88 gerektiriyor.

> ⚠️ **Sürüm tutarsızlığı:** README *"Version 0.10.1 was released on August 02, 2026"* diyor, ama crates.io'da `bergshamra` azami sürümü **0.9.0**'dır (0.10.x hiç yok; tam sürüm listesi doğrulandı). **0.10.1 muhtemelen `uppsala`'nın sürümüdür** (uppsala v0.10.1, 2026-09-02 — doğrulandı). **crates.io'yu esas al.** Bu tutarsızlık projenin sürüm/doküman disiplini hakkında bir uyarıdır.

**`gamlastan` — saf Rust SAML 2.0**

| | |
|---|---|
| Sürüm | **0.9.0**, 2026-09-03 |
| İndirme | 15.518 toplam / 15.408 son 90 gün |
| Oluşturma | **2026-06-08** (yani **3 aylık**) |
| GitHub | 6 yıldız, ~138 commit |
| Lisans | BSD-2-Clause |

Bağımlılıklar: `bergshamra` + 7 alt crate'i, `uppsala`, `kryptering`, `chrono`, `flate2`, `rand`, `regex`, `md-5`, `bytes`, `thiserror`, `base64`. **`libxml`/`xmlsec`/`openssl-sys` YOK** → saf Rust zinciri doğrulandı.

Yetenekler: *"the full SAML 2.0 specification with **errata corrections**"*; **IdP tarafı Response ve hata üretimi**; SP tarafı AuthnRequest kurma ve Response işleme; **binding'ler: HTTP Redirect, POST, Artifact, SOAP, PAOS**; **SLO**; metadata (SPID uzantıları, önbellek, doğrulama); 35 kontrollü assertion doğrulayıcı, replay cache, saat kayması yönetimi; ulusal profiller (İtalyan SPID, İsveç Sweden Connect).
⚠️ **Uyum iddiası kanıt değil:** README *"passes the Italian SPID conformance test suite"* diyor ama bu **kendi beyanıdır** ve `italia/spid-saml-check` **SP'leri test eder, IdP'leri değil** — Argus bir IdP olduğu için bu süit Argus'un ürettiği assertion'ları hiç doğrulamaz. IdP tarafı için ayrı repo (`AgID/spid-saml-check-idp`) var ama olgunluğu çok düşük (4 star, 51 commit, Docker yok). Ayrı bir `gamlastan-mdq` crate'i MDQ istemcisi sunuyor.

**Uyarılar:** 3 aylık crate, 0.9.0 (1.0 öncesi), **6 GitHub yıldızı** (çok düşük benimseme), bağımsız güvenlik denetimi beyanı **yok**, ve ulusal profillere (SPID/Sweden Connect) odaklı — **genel ticari SP interop'u (Salesforce/AWS/Entra tuhaflıkları) DOĞRULANMADI.**

**Destek crate'leri:** `uppsala` **0.10.1** (2026-09-02, 176.007 indirme) — saf Rust XML parser/DOM/namespace/XPath/XSD; `kryptering` **0.5.0** (2026-07-23, 145.067 indirme) — *"Cryptographic operations library with software (RustCrypto) and **HSM (PKCS#11)** backends"*.

> 🔑 **`kryptering`'in PKCS#11 desteği stratejik olarak önemlidir** — üretim IdP'sinin imzalama anahtarı HSM/KMS'te durmalıdır (§1.11.4 Golden SAML) ve bu, saf Rust yığınında bunu destekleyen görünürdeki tek yoldur.

#### 1.13.3 Diğer crate'ler ve ekosistem hijyeni

| Crate | Sürüm | Tarih | Toplam | 90 gün | Not |
|---|---|---|---|---|---|
| `quick-xml` | **0.42.0** | 2026-08-22 | 402.585.436 | 104.519.059 | Pull parser. **Sağlam seçim** |
| `libxml` | 0.3.21 | 2026-08-02 | 2.159.264 | 494.908 | libxml2 wrapper; 0.3.18 **yanked**; C bağımlılığı |
| `xmlsec` (voipir) | 0.3.0 | 2026-02-12 | 88.659 | **1.584** | xmlsec1 binding. **90 günlük indirme çok düşük — fiilen terk edilmiş.** 0.2.3'ten (2023) 0.3.0'a 2,5 yıl |
| `rust-xmlsec` (as207960) | 1.0.0 | **2021-10-19** | 27.906 | 5.722 | "Pure rust XMLSec" iddiası ama **5 yıldır tek sürüm.** **Kullanma** |
| `xml_c14n` | 0.3.0 | 2023-11-29 | 88.632 | 48.315 | **libxml2 üzerine** → saf Rust değil; 3 yıldır güncelleme yok |
| `sxd-document` | 0.3.2 | **2019-05-26** | 2.771.111 | 570.314 | 7 yıldır güncelleme yok. **Yeni proje için kullanma** |
| `saml` (danielkov) | 0.0.1-alpha.2 | 2026-08-08 | **1.132** | 995 | *"no libxml2/xmlsec C build chain"* iddiası; **çok erken alpha.** İzle, kullanma |
| `oxixml-c14n` | 0.1.2 | 2026-08-10 | 412 | 412 | Yeni, düşük benimseme |
| `rsa` (RustCrypto) | **0.10.0-rc.18** | 2026-04-27 | 215.298.115 | 49.432.738 | ⚠️ **Hâlâ release candidate**; 0.10 stabil değil |
| `saml2` | — | — | — | — | **crates.io'da YOK** |

> ### 🔴 Ekosistem hijyeni uyarısı — isim işgali
> crates.io'da `opensaml` (0.5.0), `samlify` (0.5.0), `samlet` (0.5.0), `rustsaml` (0.5.0) crate'lerinin **dördü de** aynı sahibin (`salasebas`) `saml-rs` paketinin *"Maintained compatibility re-export"*larıdır — hepsi `github.com/salasebas/saml-rs` reposunu gösteriyor. Aynı sahip `scim-rs`'i de yayınlamış.
> **Tanıdık gelen bir isim gördün diye bağımlılık alma.** crates.io'da `repository` alanını ve sahibini her zaman kontrol et.

#### 1.13.4 Saf Rust'ta imza üretmek mümkün mü?

**Evet — ve 2026'da artık sıfırdan yazmaya gerek yok.**

| Seçenek | Artılar | Eksiler |
|---|---|---|
| **(A) `gamlastan` üzerine kur** | Saf Rust, tüm binding'ler, SLO, metadata, IdP-side Response üretimi, XSW savunması yerleşik, SPID uyum kanıtı | 3 aylık crate, 6 yıldız, denetim yok, ticari SP interop'u kanıtlanmamış, API kararlılık riski (haftalık minor sürümler) |
| **(B) `bergshamra` + kendi SAML katmanın — ÖNERİLEN** | Zor ve tehlikeli kısmı (exc-c14n + XMLDSig + XMLEnc) devret; SAML domain modelini (Response/Assertion/NameID politikaları/attribute release) kendin yaz — **bu iş mantığıdır, dışarıdan gelmemeli.** Saf Rust avantajı korunur; xmlsec interop suite'ini tam geçmesi güçlü olgunluk sinyali | `bergshamra` da genç (Şubat 2026); XML serileştirme için ayrıca `quick-xml` gerekir |
| **(C) `samael` + `xmlsec` feature** | 689K indirme, 2020'den beri, savaşta test edilmiş | 8 C kütüphanesi, nix gerektiren build, **AES-256 şifreleme yok**, `rsa-1_5` var; statik binary/konteyner hedefleri için ciddi yük |

> **Tavsiye: (B).** Ve geçiş sigortası olarak: imzalama çağrılarını **tek bir trait arkasına** koy —
> `trait XmlSigner { fn sign(&self, doc: &mut Document, ref_id: &str, key: &SigningKey) -> Result<()>; }`
> Böylece `bergshamra` beklentiyi karşılamazsa `samael`/`xmlsec1`'e düşmek **tek modül değişikliği** olur. Bu, genç bir bağımlılığa girmenin bedelini sınırlar.

**exc-c14n'i sıfırdan yazmak?** Algoritma ~500-800 satır, yapılabilir. Asıl zorluk document-subset/node-set semantiğidir; buradaki hata ya sessiz imza uyumsuzluğu ya da XSW'ye açık bir doğrulayıcı üretir. **Yazma.**

### 1.14 SAML sınıflandırma ve aksiyon listesi

**ZORUNLU (Faz 1):** SP-initiated Web Browser SSO; HTTP-POST + HTTP-Redirect binding; Assertion imzalama (`rsa-sha256` + exc-c14n + enveloped, tek Reference); IdP metadata yayını; SP metadata tüketimi ve ACS doğrulaması; persistent + transient + emailAddress NameID; AttributeStatement; `SessionIndex` üretimi; DTD-kapalı sertleştirilmiş XML ayrıştırma; inflate limiti.

**OPSİYONEL (Faz 2):** EncryptedAssertion (AES-256-GCM + RSA-OAEP); IdP-initiated (varsayılan kapalı, HMAC'li RelayState); imzalı metadata; SLO (front-channel, best-effort); ECDSA imzalar; pairwise identifier durumsuz modu; `<OneTimeUse>` (SP başına opt-in).

**ATLANABİLİR:** HTTP-Artifact binding; ArtifactResolve/SOAP; MDQ sunucusu; ECP/PAOS (Microsoft rich client'ları gerekmiyorsa); holder-of-key; NameIDMapping; SAML proxying; SAML 1.1; WS-Federation.

#### P0 aksiyonlar — yapılmazsa güvenlik açığı

1. `AssertionConsumerServiceURL`/`Index`'i **her zaman** SP metadata'sına karşı doğrula (SAMLProf §4.1.4.1).
2. ID üretimi: `_` + 160-bit CSPRNG hex (SAMLCore §1.3.4 + NCName kısıtı).
3. Gelen XML'de **DTD tamamen kapalı**; inflate için **akış hâlinde** boyut limiti (CVE-2025-25293).
4. Kendi doğrulayıcında: **tek parser**, **yinelenen ID reddi**, imzalanan element ile okunan elementin **referans eşitliği** (CVE-2025-25291 dersi).
5. RelayState'i HMAC'le veya opak handle yap; IdP-initiated'da allow-list.
6. `SubjectConfirmationData`'ya **`NotBefore` yazma**.
7. İmzalama anahtarını **HSM/KMS'te** tut; her imzalamayı denetim kaydına yaz (Golden SAML).
8. İmzalı çıktı üretimini kimlik doğrulamasına bağla (CVE-2022-39299).

#### P0 aksiyonlar — interop

9. Assertion şema sırası: `Issuer → Signature → Subject → Conditions → Advice → Statements`.
10. **Önce Assertion'ı, sonra Response'u imzala.** İkisini de imzala (varsayılan).
11. `rsa-sha256` + `sha256`; SHA-1 yalnızca açık legacy bayrağıyla.
12. exc-c14n + enveloped-signature transform; **tek** `<ds:Reference URI="#id">`.
13. HTTP-Redirect imza string'i: `SAMLRequest|SAMLResponse` → `RelayState` (varsa) → `SigAlg`, her biri URL-encoded; **RelayState yoksa tamamen atla**.
14. İmzalı redirect mesajlarında `Destination` zorunlu.
15. `SessionIndex`'i her zaman üret.
16. Zaman damgaları `Z` sonekli UTC; `Conditions` −60 sn / +5 dk.

#### P1

17. Metadata `validUntil` + `cacheDuration`; **iki fazlı** sertifika rotasyonu (çoklu `KeyDescriptor use="signing"`). **Entra için bu geçersizdir — manuel prosedür yaz.**
18. `aes256-gcm` + `xmlenc11#rsa-oaep`; `rsa-1_5` asla.
19. `<OneTimeUse>` varsayılan kapalı.
20. SLO best-effort + `PartialLogout` status'u.
21. `XmlSigner` trait'i ile kripto arka ucunu soyutla.

### 1.15 SAML efor tahmini

| İş kalemi | Tahmin |
|---|---|
| Kripto arka ucu spike'ı (bergshamra vs samael kararı) + `XmlSigner` soyutlaması | 2 hafta |
| SAML domain modeli + serileştirme (şema sırası, namespace'ler) | 2,5 hafta |
| AuthnRequest işleme + ACS doğrulama + NameIDPolicy/Scoping | 1,5 hafta |
| Response/Assertion üretimi + imzalama sırası | 2 hafta |
| NameID politikaları (persistent/transient/pairwise) + attribute release motoru | 2 hafta |
| HTTP-Redirect binding (DEFLATE + imza string'i) + HTTP-POST | 1,5 hafta |
| Metadata üretimi/tüketimi + sertifika rotasyonu prosedürü | 2 hafta |
| Sertleştirme (DTD, inflate limiti, RelayState HMAC, denetim) | 1 hafta |
| Gerçek SP interop testleri (AWS, Entra, Google + 2 tanesi) | **2-3 hafta** |
| **Faz 1 toplam** | **~14-16 hafta / 1 mühendis** |
| Faz 2 (EncryptedAssertion, SLO, imzalı metadata, IdP-initiated) | +8 hafta |

---

## BÖLÜM 2 — SCIM 2.0 (SUNUCU TARAFI)

### 2.1 İlk düzeltme: SCIM artık üç RFC değil, altı RFC

Brief'teki "RFC 9967 SCIM Events" ifadesi **kısmen yanlış.** Doğrulanan gerçek:

| RFC | Tam başlık | Tarih | Durum |
|---|---|---|---|
| **7642** | SCIM: Definitions, Overview, Concepts, and Requirements | Eylül 2015 | Informational |
| **7643** | SCIM: Core Schema | Eylül 2015 | Standards Track — **9865 ve 9967 ile güncellendi** |
| **7644** | SCIM: Protocol | Eylül 2015 | Standards Track — **9865 ve 9967 ile güncellendi** |
| **9865** | **Cursor-Based Pagination of SCIM Resources** | **Ekim 2025** | Standards Track. 7643+7644'ü günceller |
| **9944** | **Device Schema Extensions to the SCIM Model** | **Mayıs 2026** | Standards Track |
| **9967** | **SCIM Profile for Security Event Tokens (SETs)** | **Mayıs 2026** | Standards Track. 7643+7644'ü günceller. Yazarlar: P. Hunt (Ed.), N. Cam-Winget (Cisco), M. Kiser (SailPoint), J. Schreiber (Workday) |

> **Düzeltme:** RFC 9967'nin adı "SCIM Events" değil, **"SCIM Profile for Security Event Tokens (SETs)"**tir. Olay *sözlüğünü* tanımlar; olay *akışı yönetimini* tanımlamaz — o iş OpenID SSF'e bırakılmıştır (§2.9).
> Kaynak: rfc-editor.org/rfc/rfc9967.txt, datatracker.ietf.org/wg/scim/documents/ (erişim 8 Eylül 2026)

**Argus için anlamı: 2015 SCIM'i implemente etmek artık yetersiz.** Sayfalama (9865) ve olay yayını (9967) yeni taban çizgisidir.

### 2.2 Endpoint ve metot matrisi (RFC 7644 §3.2, Tablo 2)

| Kaynak | Endpoint | Metotlar | Argus sınıflandırması |
|---|---|---|---|
| User | `/Users` | GET, POST, PUT, PATCH, DELETE | **ZORUNLU** |
| Group | `/Groups` | GET, POST, PUT, PATCH, DELETE | **ZORUNLU** |
| ServiceProviderConfig | `/ServiceProviderConfig` | GET | **ZORUNLU** (+ `/ServiceProviderConfigs` alias'ı — §2.10) |
| ResourceType | `/ResourceTypes` | GET | **ZORUNLU** (Entra provisioning yapılandırmasında okur) |
| Schema | `/Schemas` | GET | **ZORUNLU** (Entra açıkça şart koşuyor) |
| Self | `/Me` | GET, POST, PUT, PATCH, DELETE (§3.11) | **OPSİYONEL** — üç meşru davranış var: `501`, gerçek kaynağa `308`, veya doğrudan işle |
| Bulk | `/Bulk` | POST | **ATLANABİLİR (Faz 1)** — Entra açıkça *"we don't support the /Bulk endpoint today"* diyor |
| Search | `[prefix]/.search` | POST | **OPSİYONEL** — uzun filtreleri URL'e sığdırma sorununu çözer; PII'yi URL'den çıkarır |

**Normatif seviyeler — sürpriz burada:**
- **PUT = MUST.** §3.5: *"Implementers MUST support HTTP PUT"*.
- **PATCH = SHOULD.** *"Resources such as Groups may be very large; hence, implementers SHOULD support HTTP PATCH"*.
- Filtreleme, sıralama, bulk, ETag, `/Me` → **OPSİYONEL/MAY**.
- `attributes` / `excludedAttributes` → §3.4.2.5: *"OPTIONAL parameters, which MUST be supported by SCIM service providers"* — yani **istemci için opsiyonel, sunucu için zorunlu.**

> **Ama gerçek dünya spec'i ezer: Entra ve Okta pratikte PATCH'i zorunlu kılıyor.** PATCH'i sona bırakma, **ilk yaz.**

**PUT asla kaynak yaratmaz.** (§3.2)

### 2.3 Veri modeli — RFC 7643 çekirdek şeması

#### Attribute karakteristikleri (§2.2) ve belirtilmediğindeki varsayılanlar
`required`=false · `canonicalValues`=yok · `caseExact`=false · `mutability`=`readWrite` · `returned`=`default` · `uniqueness`=`none` · `type`=`string`

Tam küme: `required`, `canonicalValues`, `caseExact`, `mutability`, `returned`, `uniqueness`, `referenceTypes`.

#### Rust veri modelini belirleyen tek kural
**§2.3.8: Bir complex attribute, kendisi complex olan alt-attribute içeremez.** Yalnızca tek seviye. Bu, `enum ScimValue` tasarımının tamamını sabitler — özyinelemeli iç içe geçme yoktur.

Veri tipleri (§2.3): `string`, `boolean`, `decimal`, `integer`, `dateTime` (xsd:dateTime, tarih **ve** saat zorunlu), `binary` (base64, **case exact**), `reference` (**case exact**, `referenceTypes` taşır), `complex`.

#### Çok değerli attribute'lar (§2.4-2.5)
Varsayılan alt-attribute'lar: `type`, `primary` (boolean; **`true` en fazla bir kez görünebilir**), `display` (**mutability = immutable**), `value`, `$ref`.
**§2.5: atanmamış / `null` / `[]` durum olarak eşdeğerdir.**

#### Ortak attribute'lar (§3.1)

| Attribute | caseExact | mutability | returned | Kritik not |
|---|---|---|---|---|
| `id` | true | readOnly | **always** | Sunucu atar; **kararlı ve yeniden atanamaz olmalı**; TÜM kaynak tipleri arasında benzersiz; istemci göndermemeli; `"bulkId"` string'i rezerve, hiçbir id'de geçemez |
| `externalId` | true | readWrite | default | İstemci atar; **sunucu benzersizlik dayatmaz** |
| `meta` | — | readOnly | default | **İstemci gönderirse yok sayılmalı** |

`meta` alt-attribute'ları: `resourceType`, `created`, `lastModified` (hiç değişmediyse `created` ile aynı), `location` (**`Content-Location` başlığına eşit olmalı**), `version` (**ETag başlığına eşit olmalı**; güçlü validator değilse **`W/` ön eki zorunlu**, büyük-küçük harfe duyarlı).

#### Uygulanması ZORUNLU errata (rfc-editor.org/errata/rfc7643)

RFC'nin §8.7.1'deki normatif JSON şeması hatalıdır. Argus'un şema kaydına **düzeltilmiş** hâli girmelidir:

| Errata | Durum | Düzeltme |
|---|---|---|
| **5368** | Verified | `Group.displayName` `required` = **true** olmalı (RFC'de yanlışlıkla false) |
| **5606** | Verified | `Schema.attributes.type` canonicalValues'a **`binary`** eklenmeli |
| **5607** | Verified | `Schema.attributes.referenceTypes` **`multiValued: true`** olmalı |
| **6004** | Verified | `name`, `emails`, `addresses` complex attribute'ları **`uniqueness` taşımamalı** (§2.3.8 ile çelişiyor) |
| **7522** | Verified | `ResourceType.schemaExtensions` **`multiValued: true`** olmalı |
| **8415** | Verified | `subAttributes.type` canonicalValues'a da `binary` |
| **8361** | Verified | §3.1 metni `/ServiceProviderConfig` ve `/ResourceTypes` demeli |

Ayrıca normatif JSON'daki **sessiz eksikler** (errata'ya girmemiş ama gerçek):
- `ims.type` canonicalValues'ta **`other` yok** (§4.1.2 düzyazısı listeliyor).
- `addresses`'ta **`.primary` alt-attribute'u yok** (diğer tüm çok değerli attribute'larda var).
- `Group.members`'ta **`.display` yok** — ama RFC 7644 §3.5.2'nin kendi PATCH örnekleri `display` gönderiyor. **Kabul et, reddetme.**
- `Group.members` alt-attribute'ları `value`, `$ref`, `type` **mutability = immutable**.

### 2.4 PATCH semantiği (§3.5.2) — işin en zor %40'ı

#### Zarf
`schemas` = `["urn:ietf:params:scim:api:messages:2.0:PatchOp"]`. `Operations` dizisi ≥1. Her op **tam olarak bir** `op` üyesi: `add` / `remove` / `replace`.
`path`: **add/replace için OPSİYONEL, remove için ZORUNLU.**

```
PATH = attrPath / valuePath [subAttr]          (Şekil 7)
```

Geçerli yol örnekleri (Şekil 8): `members` · `name.familyName` · `addresses[type eq "work"]` · `members[value eq "…"]` · `members[value eq "…"].displayName`

#### Sıra, atomiklik, schemas
- Operasyonlar **sırayla** uygulanır; her op'un çıktısı bir sonrakinin girdisidir.
- **"A PATCH request, regardless of the number of operations, SHALL be treated as atomic."** Herhangi bir hatada orijinal kaynak geri yüklenmeli. → Rust'ta: klon üzerine uygula veya transaction içinde çalış, sonda commit et.
- Bir op `schemas`'ı değiştirirse sonraki op'lar değişmiş durumu görür. **Tam nitelikli bir uzantı attribute'u eklemek (`urn:…:enterprise:2.0:User:employeeNumber`) uzantı URN'ini `schemas`'a örtük olarak ekler.**
- İstemci `readOnly` veya `immutable`'ı değiştiremez; **ama önceki değeri olmayan `immutable` bir attribute'a `add` YAPABİLİR.**
- **`primary` kuralı:** bir değerin `primary`'sini `true` yapmak, sunucunun aynı dizideki **diğer tüm değerlerin `primary`'sini otomatik `false` yapmasına** sebep OLMALIDIR.
- Yanıt: `200` + tam kaynak, veya `204`. **İstekte `attributes` varsa sunucu `200` dönmek ZORUNDA.**

#### `add` (§3.5.2.1) — sıralı kural listesi
1. `path` yoksa → hedef kaynağın kendisi; `value` eklenecek attribute'lar nesnesi.
2. Hedef yoksa → attribute ve değer eklenir.
3. Hedef complex ise → `value` alt-attribute kümesi olmalı.
4. Hedef çok değerli ise → **yeni değer eklenir (append)**.
5. Hedef tek değerli ise → **mevcut değer değiştirilir**.
6. Hedef varsa → değer değiştirilir.
7. **Hedef zaten bu değeri içeriyorsa → değişiklik YAPILMAMALI, başarı dönmeli ve `lastModified` DEĞİŞMEMELİ.**

> Kural 7 sıradan görünür ama **kritiktir**: Entra ve Okta grup üyeliğini periyodik olarak yeniden gönderir. `lastModified`'ı her seferinde güncellersen sonsuz senkron döngüsü ve gereksiz olay fırtınası üretirsin.

#### `remove` (§3.5.2.2)
- **`path` yoksa → `400` + `scimType: noTarget`** (dikkat: `invalidPath` değil).
- Tek değerli → attribute kaldırılır.
- Çok değerli, filtresiz → **attribute ve TÜM değerleri kaldırılır**.
- Çok değerli + değer filtresi → eşleşenler kaldırılır; hiç kalmazsa attribute atanmamış olur.
- **`required` veya `readOnly` bir attribute atanmamış hâle gelirse → `scimType: mutability` hatası.**
- **Grupta olmayan bir üyeyi kaldırmak BAŞARIDIR**, hata değil: *"If the user was not a member of this group, no changes should be made to the resource, and a success response should be returned."*

#### `replace` (§3.5.2.3)
- `path` yoksa → hedef kaynak; `value` değiştirilecek attribute listesi.
- Tek değerli → değiştirilir.
- Çok değerli, filtresiz → **attribute ve tüm değerleri toptan değiştirilir**.
- **Hedef yol yoksa → sunucu bunu `add` olarak İŞLEMELİDİR.**
- Complex hedef → `value`'daki alt-attribute'lar değiştirilir/eklenir; **belirtilmeyen alt-attribute'lar DEĞİŞMEDEN kalır** (merge, toptan replace değil).
- Çok değerli + valuePath ≥1 eşleşme → **eşleşen tüm kayıtlar değiştirilir**.
- **Çok değerli + valuePath HİÇ eşleşmiyorsa → `400` + `scimType: noTarget`.**

> **Asimetriyi ezberle:** filtresi hiçbir şeyle eşleşmeyen `replace` **hatadır**; olmayan bir üyeyi silen `remove` **başarıdır**.

#### RFC'nin gerçekten belirsiz bıraktığı yerler

1. **valuePath filtresiyle `add`** (`"op":"add","path":"emails[type eq \"work\"].value"`). §3.5.2.1'in kural listesinde **hiç yok.** Errata **8097** (Held for Document Update, 2024-09-08, Siqing Zheng) tam olarak bunu belgeliyor: *"Looks Microsoft Azure had a different understanding about the patch 'add' operation… Microsoft Azure expects to add a new email with value 'example@email.com' and type 'work'."* AD bunu gelecek çalışma için kabul etti.
   → **Argus bunu implemente etmeli:** valuePath + subAttr ile `add`, hiçbir şey eşleşmiyorsa **filtrenin `eq` yan tümcelerinden tohumlanmış yeni bir complex değer yaratmalı.**
2. **Filtresiz çok değerli `replace`** — spec "hepsini değiştir" der, birçok istemci "type'a göre upsert" kasteder. **Spec'e uy, ama gürültülü logla.**
3. **Hem `path` hem `value` içeren `remove`** — ABNF'te hiç yok; Entra'nın uyumsuz modu bunu üretiyor (§2.8).
4. **PATH ABNF'i basit çok değerli bir attribute üzerinde filtre ifade edemiyor.** Errata **7122** (Held) `PATH = attrPath / valuePath [subAttr] / attrExp` önerisiyle bunu düzeltmeye çalışıyor. **Hoşgörülü kabul et.**

### 2.5 Filtre dili (§3.4.2.2)

#### Yayımlanan ABNF
```
FILTER    = attrExp / logExp / valuePath / *1"not" "(" FILTER ")"
valuePath = attrPath "[" valFilter "]"
valFilter = attrExp / logExp / *1"not" "(" valFilter ")"
attrExp   = (attrPath SP "pr") / (attrPath SP compareOp SP compValue)
logExp    = FILTER SP ("and" / "or") SP FILTER
compValue = false / null / true / number / string
compareOp = "eq" / "ne" / "co" / "sw" / "ew" / "gt" / "lt" / "ge" / "le"
attrPath  = [URI ":"] ATTRNAME *1subAttr
ATTRNAME  = ALPHA *(nameChar)
nameChar  = "-" / "_" / DIGIT / ALPHA           ; DİKKAT: burada "$" YOK
subAttr   = "." ATTRNAME
```

> **Tutarsızlık:** RFC 7643 §2.1'in `nameChar`'ı **`$` içerir** (bu yüzden `$ref` yazılabilir), RFC 7644 §3.4.2.2'ninki **içermez**. Gerçek bir tutarsızlık; parser'ın `$`'ı kabul etmesi gerekir.

#### Düzeltilmesi gereken ABNF kusurları (hepsi belgeli errata)

| Errata | Durum | Sorun ve doğru kural |
|---|---|---|
| **7319** | Reported | `*1"not" "(" FILTER ")"` `not (…)` içindeki boşluğu yasaklıyor — ama RFC'nin **kendi örneği** boşluk kullanıyor. Düzelt: `*1("not" SP) "(" FILTER ")"` |
| **4690** | Held | `valFilter`'ın `logExp`'e referansı `FILTER`'a geri özyineliyor ve istenmeden iç içe valuePath'e izin veriyor |
| **7322** | Reported | **4690'ı düzeltiyor** — 4690'ın önerisi meşru `emails[type eq "work" or (type eq "home" and value ew "@example.com")]` ifadesini reddediyor. Doğru kural: `valLogExp = valFilter SP ("and" / "or") SP valFilter`. **7322'yi uygula** |
| **4670** | Held | Belirtilen öncelik sırası ters. `title sw "M" and userType eq "Employee"` → `(title sw "M") and (userType eq "Employee")` olmalı. **Öncelik: attribute operatörleri > `not` > `and` > `or`** |

#### Semantik
- **Attribute adları VE operatörler büyük-küçük harfe duyarsız** (`userName Eq "john"` ≡ `Username eq "john"`).
- Çok değerli attribute → **herhangi bir** değer eşleşirse eşleşir.
- Complex attribute tam nitelikli alt-attribute ister (`name.givenName`).
- **String karşılaştırmasının harf duyarlılığı filtrede değil, attribute'un `caseExact` karakteristiğinde belirlenir.** `userName` duyarsız; `id`, `externalId`, `meta.version`, `x509Certificates` duyarlı.
- **Boolean veya Binary üzerinde `gt`/`ge`/`lt`/`le` → `400` + `invalidFilter`** (spec bunu 4 kez tekrarlıyor).
- Tanınmayan operatör → `400 + invalidFilter` + insan-okunur `detail`. **MUST.**
- Şemaya göre filtreleme yasal: `filter=schemas eq "urn:…:enterprise:2.0:User"`.
- **Kök seviye sorgu** (`GET /`): tüm kaynak tiplerini döner. Bir kaynak tipinde tanımsız attribute'lar **değersiz sayılmalı** (presence/equality → false).

#### DoS
RFC `scimType: tooMany` ve SPC'de `filter.maxResults` verir, ama **sözdizimsel karmaşıklık limiti tanımlamaz.** Argus:
- İç içe geçme derinliği, toplam token sayısı, `and`/`or` terim sayısı için tavan koy (`scim_v2` crate'i `MAX_FILTER_DEPTH` sabitiyle emsal oluşturuyor).
- Büyük koleksiyonlarda salt-`pr` filtrelerini `tooMany` ile reddet.
- **`co` operatörü doğal DoS vektörüdür** — indekssiz `LIKE '%…%'`'e çevirme.
- Önce AST'ye parse et, şemaya karşı doğrula (bilinmeyen attribute → `invalidFilter`), **sonra** sorgu planla. **Asla string birleştirmeyle SQL üretme.**

### 2.6 Durum kodları ve hata sözlüğü

**Başarı:** `201` create (+ `Location` başlığı + `meta.location`) · `200` GET/PUT/PATCH-gövdeli · `204` PATCH-gövdesiz ve DELETE · `304` `If-None-Match` ile koşullu GET.

**Hata (§3.12, Tablo 8):** `307`/`308` · `400` · `401` · `403` · `404` · `409` (sürüm uyuşmazlığı **veya** yinelenen kaynak) · `412` (precondition) · `413` (payload — gövdede `maxOperations`/`maxPayloadSize` belirtilmeli) · `500` · `501`.

> **409 vs 412 ayrımı:** yinelenen `userName` → **`409` + `scimType: uniqueness`**; `If-Match` uyuşmazlığı → **`412`**.

Hata gövdesi: `urn:ietf:params:scim:api:messages:2.0:Error`, alanlar `status` (**JSON string**, zorunlu), `scimType`, `detail`.

**scimType anahtar kelimeleri (Tablo 9 + RFC 9865):** `invalidFilter`, `tooMany`, `uniqueness`, `mutability`, `invalidSyntax`, `invalidPath` (yalnızca PATCH), `noTarget` (yalnızca PATCH), `invalidValue`, `invalidVers`, `sensitive`, **`invalidCursor`**, **`expiredCursor`**, **`invalidCount`** (üçü RFC 9865 §2.1).

**Diğer normatif ayrıntılar:**
- **§3.3 create:** gövdedeki `readOnly` attribute'lar **yok sayılmalı** (hata değil).
- **§3.5.1 PUT mutability:** `readWrite`/`writeOnly` → değiştir; **`immutable`** → değer varsa girdi **eşleşmeli** yoksa `400 + mutability`, değer yoksa yeni değer geçerli; `readOnly` → yok say. Zorunlu attribute'lar PUT gövdesinde bulunmalı.
- **§3.6 DELETE:** `204`. Sonraki tüm işlemler `404`. **Silinen kaynaklar çakışma hesabına girmemeli** — aynı `userName` ile yeniden yaratma `409` vermemeli.
- **§3.8:** `Accept: application/scim+json` MUST; `application/json` SHOULD. Yanıtlar UTF-8.
- **§3.10:** `{urn}:{attr}.{subattr}` — **tüm bileşenler büyük-küçük harfe duyarsız.**
- **§4 keşif endpoint'leri:** `/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig` üzerinde filtreleme/sıralama/sayfalama **yok sayılmalı**; `filter` verilirse **`403 Forbidden` dönmek SHOULD** — böylece istemci filtrenin uygulandığını varsayamaz.

### 2.7 Sayfalama, sıralama, projeksiyon

#### İndeks sayfalaması (§3.4.2.4) — klasik tuzak
- **`startIndex` 1-TABANLIDIR.** Varsayılan 1. **1'den küçük değer 1 olarak yorumlanmalı.**
- `count`: negatif değer **0 olarak yorumlanmalı**. `count=0` → yalnızca `totalResults`.
- `ListResponse`: `totalResults` (zorunlu), `Resources` (totalResults≠0 ise zorunlu), kısmi sonuçta `startIndex` ve `itemsPerPage` zorunlu.
- **Sayfalama açıkça durumsuzdur; istemciler tutarsız sonuca hazırlıklı olmalı** — ama Okta bunun tersini şart koşuyor (§2.8).
- Sıfır eşleşme → **`200` + `totalResults: 0`**, asla 404.

#### Cursor sayfalaması — RFC 9865 (Ekim 2025)
- Yeni sorgu parametresi **`cursor`** (ilk sayfada boş/yok; **yalnızca RFC 3986 unreserved karakterler**).
- Yeni yanıt attribute'ları: **`nextCursor`** (son sayfa hariç her sayfada bulunmalı; **yokluğu tek bitiş sinyalidir**), **`previousCursor`** (opsiyonel, ilk sayfada bulunmamalı).
- İstemci diğer tüm parametreleri aynen tekrarlamalı; yalnızca `cursor` değişir.
- Sağlayıcı tahmin edemiyorsa `totalResults`'ı atlayabilir.
- `POST /.search` üzerinden de çalışır.
- Yeni SPC bloğu:
```json
"pagination": { "cursor": true, "index": true,
  "defaultPaginationMethod": "cursor",
  "defaultPageSize": 100, "maxPageSize": 250, "cursorTimeout": 3600 }
```
- İkisini de destekliyorsan bir varsayılan seçmek **MUST**; mevcut indeks tabanlı sağlayıcılar indeksi varsayılan tutmalı.

**Argus önerisi: ikisini de destekle, varsayılan `index`** (Entra/Okta indeks bekliyor), ama cursor'u sun — büyük kiracılarda indeks sayfalaması O(n²) tarama demektir.

#### Sıralama (§3.4.2.3)
`sortBy` + `sortOrder` (`ascending` varsayılan). Çok değerli `sortBy` → varsa **`primary`** değerine göre, yoksa ilk değere göre. **Eksik değerler artan sıralamada sona, azalanda başa gider.** `caseExact=false` attribute'lar **locale ima etmeyen** harf-duyarsız Unicode sıralamasıyla.

#### attributes / excludedAttributes (§3.4.2.5, §3.9) × `returned` etkileşimi
- Varsayılan yanıt kümesi = `returned:"always"` ∪ `returned:"default"`.
- `attributes` → varsayılan kümeyi **ezer**: yanıt = `always` (minimum küme) ∪ açıkça istenenler.
- `excludedAttributes` → yanıt = minimum küme ∪ (varsayılan − hariç tutulanlar). **`always` üzerinde etkisi YOK.**
- İkisi **birlikte kullanılamaz.**
- **`returned:"never"` (örn. `password`) açıkça istense bile ASLA dönmez.**
- `returned:"request"` yalnızca `attributes`'ta adı geçerse döner.
- `id` `always` olduğu için `?attributes=userName` sorgusu bile `id` döndürür.

Projektör kuralı: `always` koşulsuz çıktıda → `attributes` VEYA `excludedAttributes`'ı `default` katmanına uygula → `never` olan her şeyi düşür. **Alt-attribute yolları (`name.givenName`) desteklenmeli** ve istenen alt-attribute, yalnızca onu içeren ebeveyn nesnesini üretmeli.

### 2.8 Gerçek dünya interop — sunucunun tolere etmesi gerekenler

#### Microsoft Entra ID

Kaynaklar: learn.microsoft.com `use-scim-to-provision-users-and-groups` (doc tarihi 2026-08-28), `application-provisioning-config-problem-scim-compatibility` (2025-08-25), `how-provisioning-works`, `scim-validator-tutorial`; araç: **scimvalidator.microsoft.com** (erişim 8 Eylül 2026)

**Entra'nın belgelenmiş talepleri (alıntı seviyesinde):**

| Talep | Sonuç |
|---|---|
| *"Microsoft Entra-only uses the following operators: **eq, and**"* | Diğer operatörler Entra için gereksiz — ama Okta için değil |
| *"Don't require a case-sensitive match on structural elements… Microsoft Entra ID emits the values of op as **Add, Replace, and Remove**"* | **`op` karşılaştırması harf-duyarsız olmalı** |
| *"It isn't necessary to include the entire resource in the PATCH response"* + grup PATCH'i *"should yield an HTTP 204 No Content"* | `204` tercih ediliyor |
| *"**Values sent should be stored in the same format they were sent**"* | **RFC 7643 §4.1.2'nin "SHOULD canonicalize" tavsiyesiyle ÇELİŞİYOR. Kanonikleştirme yapma.** |
| *"The 'type' subattribute values of multivalued complex attributes must be unique"* | İki `work` e-posta olamaz |
| *"`id` is a required property for all resources… except for ListResponse with zero elements"* | |
| *"Response to a query/filter request should always be a ListResponse"* | |
| *"The entitlements attribute isn't supported"* | |
| Gruplar boş `members` listesiyle yaratılır; `displayName` benzersiz olmalı | **Bu bir Entra şartı, SCIM şartı değil** |
| `/Schemas`: ListResponse olmalı; *"If a value isn't present, don't send null values"*; *"Property values should be camel cased"* | |
| Özel complex attribute'lar **3+ alt-attribute** ile desteklenmiyor | |
| *"we don't support the /Bulk endpoint today"* | Bulk'u ertele |

**Entra'nın gönderdiği tam istek şekilleri:**
```
GET /Users?filter=userName eq "Test_User_00aa…"
GET /Groups?excludedAttributes=members&filter=displayName eq "displayName"
GET /Groups/{id}?excludedAttributes=members
DELETE /Users/{id}                      → 204 bekler
POST /Users (yinelenen)                 → önce 201 sonra 409 bekler
```
Grup yaratmada **Microsoft'a özel ekstra şema URN'i** gönderir:
`"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"]` — **reddedilmemeli.**

Microsoft'un kendi doküman örneğinde `"resourceType": "Users"` (çoğul) geçiyor — uyumsuz; `meta.resourceType`'ı doğrulamadıklarının kanıtı.

**Uyumluluk bayrağı:** kiracı URL'ine eklenen **`aadOptscim062020`** uyumlu PATCH davranışını açar. Geri düşürme bayrağı: **`AzureAdScimPatch2017`**. İş şablonları: `scim` (güncel) ve `customappsso` (Aralık 2018 öncesi legacy).

Entra'nın kendi uyumluluk tablosunda **hâlâ düzeltilmemiş** bir madde var: *"Update PATCH behavior to ensure compliance (such as active as boolean and proper group membership removals) — Fixed? **No** — Fix date **TBD** — use feature flag."*

**Bayrak OLMADAN (yani varsayılan) Entra'nın gönderdiği:**
```json
{"Operations":[{"op":"Replace","path":"active","value":"False"}]}          // string boolean + büyük harf op
{"Operations":[{"op":"Add","path":"nickName","value":"Babs"}]}
{"Operations":[{"op":"Remove","path":"members","value":[{"value":"u1091"}]}]}   // UYUMSUZ: path + value dizisi
```
Grup üyesi ekleme/çıkarma varsayılan biçimi **`"$ref": null`** içerir:
```json
{"Operations":[{"op":"Add","path":"members","value":[{"$ref":null,"value":"f648…"}]}]}
```

**Bayrak İLE** uyumlu hâle gelir (`"op":"replace"`, `"value":false`, `"path":"members[value eq \"…\"]"`), **ama** yolsuz bir `replace` üretir ve `value` nesnesinde **düz noktalı anahtarlar** kullanır:
```json
{"op":"replace","value":{"displayName":"Bjfe","name.givenName":"Kkom",
 "name.familyName":"Unua",
 "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber":"Aklq"}}
```
`"name.givenName"` **iç içe nesne değil, düz noktalı JSON anahtarıdır.** RFC'nin yolsuz biçimi gerçek attribute nesneleri bekler. **Argus bunu kabul etmeli.**

**Hız sınırlama / yeniden deneme:** Microsoft **açık 429 semantiği, istek zaman aşımı veya deneme sayısı belgelemiyor.** Belgelenen: başarısız nesne işlemleri sonraki senkron döngüsünde *"gradually scaling back the frequency of retries"* ile tekrarlanır; kalıcı yaygın hatalar işi **karantinaya** alır (döngü sıklığı **günde bire** düşer) ve **dört hafta** karantinadan sonra iş **otomatik devre dışı bırakılır**. Silme: varsayılan soft-delete (`active=false`); Entra'da soft-delete'ten **30 gün** sonra veya elle kalıcı silmede **hard DELETE** gönderilir. Microsoft'un tavsiyesi: *"always support both soft-deletes and hard-deletes."*
→ **Kesin 429/timeout değerleri: DOĞRULANMADI** — Microsoft'un kamuya açık dokümanlarında yok.

#### Okta

Kaynaklar: developer.okta.com `/docs/concepts/scim/`, `/docs/api/openapi/okta-scim/guides/scim-20/`, `/docs/guides/scim-provisioning-integration-prepare/main/` (erişim 8 Eylül 2026)

- Gereken endpoint'ler: `GET/POST /Users`, `GET/PUT/PATCH /Users/{id}`, `GET/POST /Groups`, `GET/PUT/PATCH/DELETE /Groups/{id}`.
- **"Okta doesn't perform DELETE operations on user objects in your SCIM app."** Kullanıcı kaldırma her zaman `active: false`. **Gruplar DELETE edilir.**
- Filtreler: `filter=userName eq "…"` ve `filter=displayName eq "…"`. *"Your SCIM server must support this query parameter to provision users with Okta successfully."*
- **Sayfalama değerleri string değil INTEGER olarak alışverilmeli.** Ve: *"The SCIM server must consistently return the same **ordering of results**… regardless of which values are provided for `count` and `startIndex`."* → **Okta kararlı toplam sıralama şart koşuyor, RFC §3.4.2.4 ise tutarsızlığa açıkça izin veriyor.**
- **PUT vs PATCH entegrasyon tipine bağlı:** yeni OIN entegrasyonları genel kullanıcı güncellemesi için **PUT**, aktivasyon/deaktivasyon/parola senkronu için **PATCH** kullanır; AIW/özel uygulamalar **her şey için PUT**. Gruplarda OIN **PATCH**, AIW **PUT** tercih ediyor. → **PUT'u ikinci sınıf vatandaş olarak yazma.**
- **"You must return the `members` list payload when `GET /Groups/{groupID}` is requested without any query parameters."** → **Entra'nın "üyeleri döndürmeye gerek yok" tavsiyesinin tam tersi.** Argus varsayılanda üyeleri döndürmeli **ve** `excludedAttributes=members`'a uymalı.
- Base URL **alt çizgi içermemeli**; Okta `/scim/v2/` öneriyor. TLS zorunlu. Auth: OAuth 2.0 authorization code, Basic veya bearer.
- Minimum şema: `userName`, `name.givenName`, `name.familyName`, `emails`, kararlı harf-duyarlı readOnly `id`, `active`.
- Test süiti: **"Okta SCIM 2.0 Spec Test JSON"**, Runscope'a import edilir. (Runscope BlazeMeter tarafından kapatıldı; 2026'da hâlâ çalışır durumda mı **DOĞRULANMADI**.)

#### Google Workspace, OneLogin, JumpCloud, Ping, SailPoint
**DOĞRULANMADI.** Bu oturumda birincil kaynaktan doğrulanamadı (arama bütçesi tükendi). Bu satıcılar hakkında spesifik iddia kurma; ayrı bir doğrulama turu gerekir.

#### Argus'un tolerans kontrol listesi (17 madde)

Her madde yukarıdaki doğrulanmış kaynaklara veya errata'ya dayanıyor:

1. `op` değeri **harf-duyarsız** (`Add`/`add`/`ADD`) — Entra
2. `"value": "False"` / `"True"` — **string boolean coercion** — Entra
3. `remove` hem `path:"members"` hem `value:[{value: id}]` ile — Entra varsayılanı
4. Üye nesnelerinde **`"$ref": null`** — Entra
5. Yolsuz `replace`/`add` gövdesinde **noktalı anahtarlar** ve **tam nitelikli URN anahtarları** — Entra (bayraklı)
6. Bilinmeyen/tescilli şema URN'leri — **yok say, reddetme**
7. valuePath+subAttr ile `add`, eşleşme yoksa → **yeni eleman yarat** — Errata 8097 / Entra
8. `Group.members`'ta `display` alt-attribute'u — normatif şemada yok ama kabul et
9. PatchOp gövdesinde `schemas` eksik → hoşgörülü ol
10. Boşluklu `not (…)`; valuePath içinde iç içe parantez — Errata 7319/7322
11. **Hem `/ServiceProviderConfig` hem `/ServiceProviderConfigs`** sun — Errata 4978 (Facebook/Salesforce/Slack çoğul kullanıyor)
12. `Accept: application/json`'ı da kabul et
13. Grup PATCH'inde `204` dön (Entra tercihi) **ama** `attributes` varsa `200` (RFC MUST)
14. Çıplak `GET /Groups/{id}`'de üyeleri dön (Okta MUST) **ve** `excludedAttributes=members`'a uy (Entra MUST)
15. Sayfalar arası **kararlı toplam sıralama** (Okta MUST), RFC izin verse de
16. Yinelenen `POST /Users` → `409`
17. **Saklanan değerleri asla kanonikleştirme** (Entra MUST), RFC SHOULD dese de

> **Tasarım kararı: bu 17 maddeyi "hoşgörü katmanı" olarak, katı parser'ın ÖNÜNE koy ve istemci başına açılıp kapanabilir yap.** Böylece uyumlu istemciler katı davranışı görür, Entra kendi lehçesini konuşur, ve hangi istemcinin hangi sapmayı kullandığını ölçebilirsin.

### 2.9 RFC 9967 — SCIM olayları ve Argus'un yapması gerekenler

**Kapsam:** SCIM güvenlik olaylarını SET (RFC 8417) olarak tanımlar — asenkron istek tamamlama, kaynak replikasyonu ve provisioning koordinasyonu için. RFC 7644'e `Prefer: respond-async` yeteneğini, RFC 7643'e `securityEvents` SPC bloğunu ekler.

**İlişkili standartlar:** RFC 8417 (SET), 7519 (JWT), **9493 (Subject Identifiers)**, 8935 (push), 8936 (poll), 7240 (Prefer). **Akış kaydı ve yapılandırması kapsam dışıdır** — *"Stream registration and configuration are out of scope of this specification"*. Orayı **OpenID SSF** doldurur.

> **OpenID Shared Signals Framework 1.0**, yayın **29 Ağustos 2025**, final (openid.net/specs/openid-sharedsignals-framework-1_0.html). RFC 8417/8935/8936'yı profilize eder, CAEP ve RISC olay tipleriyle geriye uyumluluk sağlar. Beş yönetim endpoint'i: Configuration, Status, Add Subject, Remove Subject, Verification.
> **Özet: RFC 9967 olay sözlüğünü verir, SSF boru tesisatını verir. Gerçek olay yayını isteyen bir IdP'nin İKİSİNE de ihtiyacı var.**

#### Subject tanımlama (§2.1)
- **`sub_id` claim'i (RFC 9493) ZORUNLU**, JWT'nin **üst seviye gövdesinde** — `events` içinde değil.
- **JWT `sub` claim'i KULLANILMAMALI** (yetkilendirme token'larıyla karışmasın diye).
- `sub_id.format` = `"scim"`. Alt claim'ler: **`uri`** (ZORUNLU — SCIM göreli yolu, örn. `/Users/2b2f880af…`), `externalId` (ops.), `id` (ops., geriye uyum).
- Ek olarak `uniqueness` değeri `server` veya `global` olan herhangi bir attribute taşınabilir.

#### Ortak olay attribute'ları (§2.2)
- **`txn`** — transaction id, SET seviyesi claim. `jti`'nin aksine yeniden iletimlerde ve birden çok alıcıda **sabit kalır**. Asenkron istekler, Koordineli Provisioning ve replikasyon için ZORUNLU.
- **`version`** — olaydan sonraki kaynağın ETag'i.
- **`data`** — tam yük, Bulk `data` attribute'u şeklinde.
- **`attributes`** — değişen attribute adları dizisi, PATCH `path` ABNF'ine uygun (`["userName","emails","name.familyName"]`).
- **`data` veya `attributes`'tan tam olarak biri bulunmalı. İkisi birden BULUNMAMALI.**

#### Olay URI'leri — IANA "SCIM Event URIs" kaydının tamamı (§7.4)
```
urn:ietf:params:scim:event:feed:add            Kaynak feed'e eklendi
urn:ietf:params:scim:event:feed:remove         Kaynak feed'den çıkarıldı
urn:ietf:params:scim:event:prov:create:notice  Yeni kaynak (yalnızca bildirim)
urn:ietf:params:scim:event:prov:create:full    Yeni kaynak (tam veri)
urn:ietf:params:scim:event:prov:patch:notice
urn:ietf:params:scim:event:prov:patch:full
urn:ietf:params:scim:event:prov:put:notice
urn:ietf:params:scim:event:prov:put:full
urn:ietf:params:scim:event:prov:delete         (full/notice ayrımı yok — yük yok)
urn:ietf:params:scim:event:prov:activate
urn:ietf:params:scim:event:prov:deactivate
urn:ietf:params:scim:event:misc:asyncresp      Asenkron istek tamamlanması
```
`:full` → `data` taşır. `:notice` → `attributes` taşır, alıcı SCIM GET ile geri çağırır.
İki çalışma modu: **DBR** (Domain-Based Replication — `:full`, geri çağrı yok) ve **CP** (Coordinated Provisioning — `:notice` + geri çağrı).
`prov:delete` kaynağı feed'den de çıkarır; ayrıca `feed:remove` **YAYINLANMAMALI**.
`feed:add`/`feed:remove` **feed üyeliği** sinyalidir, create/delete sinyali değil.

#### Asenkron istekler (§2.5.1, §3)
- İstemci `Prefer: respond-async` gönderir (`wait` tercihini de desteklemeli SHOULD).
- **`Accept` başlığı asenkron amaçlı YOK SAYILMALI.**
- Sunucu **`202 Accepted`, gövdesiz**, artı:
  - **`Set-Txn: <benzersiz string>`** — bu RFC'nin tanımladığı **yeni HTTP yanıt başlığı** (§3). Gövdesiz 202'de bulunmak ZORUNLU. Değeri, nihai SET'in `txn` claim'iyle eşleşmeli. Ara katmanlar değiştirmemeli.
  - `Preference-Applied: respond-async`
  - `Location:` — ya tamamlanma SET'inin GET edilebileceği URI ya da normal SCIM kaynak konumu.
- **Bulk + async:** **operasyon başına bir** `asyncresp` olayı. `txn` = `<orijinal txn>:<sıfır tabanlı indeks>` (`2d80e537…:0`, `:1`). **`bulkId` bu amaçla KULLANILMAMALI.** Sunucu sırayı değiştirse bile indeks **orijinal istek sırasını** yansıtmalı.

#### SPC uzantısı (§4)
```json
"securityEvents": {
  "asyncRequest": "none" | "long" | "request",
  "eventUris": [ "urn:ietf:params:scim:event:prov:create:full", "…" ]
}
```
Yoksa desteklenmiyor demektir. `eventUris` yalnızca bilgilendirmedir.

#### Argus'un uygulama sırası
1. Durum değiştiren her SCIM işleminde iç değişiklik olayı üret: `txn`, kaynak URI, `externalId`, sonuç ETag, değişen attribute listesi.
2. §2.1-2.4'e göre SET olarak serileştir. `sub_id` + `format:"scim"` + `uri`. **`sub` kullanma.**
3. `/ServiceProviderConfig`'te `securityEvents` yayınla. `asyncRequest: "none"` ile başla, `eventUris`'i doldur.
4. Teslimat: **RFC 8935 (push) önce** — 8936 (poll) daha karmaşık. Akış yönetimini **icat etme, OpenID SSF 1.0'ı izle.**
5. **`:notice` modunu önce yap** (olayda PII yok, alıcı geri çağırır). `:full`'ü yalnızca güvenilir replikasyon eşleri için ekle — tam kullanıcı kaydını tele koyar.
6. `Prefer: respond-async` + `202` + `Set-Txn` en sona — istek boru hattındaki en invaziv değişiklik budur.

> **Gizlilik uyarısı:** RFC'nin kendi Şekil 5'inde `prov:create:full` olayının değişen attribute'ları arasında **`"password"` listeleniyor.** Argus feed başına attribute filtrelemesi uygulamalı ve **`returned:"never"` attribute'ların DEĞERİNİ asla bir SET'e koymamalı.**

### 2.10 SCIM WG'nin güncel durumu (Eylül 2026)

datatracker.ietf.org/wg/scim/documents/ (erişim 8 Eylül 2026):

**Süresi dolmuş WG taslakları — aktif sanma:**
- `draft-ietf-scim-roles-entitlements-01` — "SCIM Roles and Entitlements Extension", rev 01, **2025-10-16**, **Expired**
- `draft-ietf-scim-use-cases-reloaded-02` — 7642-bis, rev 02, **2026-01-19**, **Expired**

**Brief'teki tahminlerin gerçek karşılıkları:**
- `draft-ietf-scim-events` / `-event-notification` → **RFC 9967 oldu**
- `draft-ietf-scim-device-model` → **RFC 9944 oldu**
- `draft-ietf-scim-cursor-pagination` → **RFC 9865 oldu**
- `draft-ietf-scim-profile-*` → **WG sayfasında böyle bir doküman YOK. DOĞRULANMADI.**
- Bir PATCH-netleştirme taslağı veya 7644bis → **listede YOK. DOĞRULANMADI.** PATCH netleştirmesi yalnızca errata 7122 ve 8097 olarak var (ikisi de Held for Document Update; AD notu: *"any future update work in this space should consider this erratum"*).

**RFC 9944 (cihaz şeması)** — Argus ileride cihaz provisioning yaparsa: `urn:ietf:params:scim:schemas:core:2.0:Device`, `…core:2.0:EndpointApp`, artı `ble`, `dpp` (Wi-Fi Easy Connect), `ethernet-mab`, `fido-device-onboard`, `zigbee`, `endpointAppsExt` uzantıları.

### 2.11 Rust ekosistemi — SCIM

crates.io JSON API'sinden doğrulanmış (8 Eylül 2026). "scim" araması **94 crate** döndürüyor; aşağıdakiler dışındakiler onlarca-yüzlerce indirmeli ve ciddiye alınamaz.

| Crate | Sürüm | Yayın | Toplam / son 90 gün | Lisans | Repo |
|---|---|---|---|---|---|
| **`scim_v2`** | **0.5.0** | **2026-09-07** | 75.483 / 47.320 | MIT | ShiftControl-io/scim-v2-rust |
| **`scim_proto`** | **1.11.1** | 2026-08-14 | 119.338 / 11.676 | **MPL-2.0** | kanidm/kanidm |
| **`scim-server`** | **0.5.3** | **2025-09-21** | 152.900 / 140.186 | MIT | pukeko37/scim-server |
| `scim-filter` | 0.2.3 | **2024-01-12** | 238.870 / 6.428 | MIT | matteosister/scim-filter |
| `scim-rs` | 0.1.0 | 2026-06-29 | 113 | MIT | salasebas/scim-rs |

`scim2`, `scim2-rs`, `scim-core` → **crates.io'da yok.**

#### Yetenek denetimi

**`scim_v2` 0.5.0** — modüller: `filter`, `models`, `schema_urns`, `utils`
- **Filtre parser: VAR.** `filter` modülü açıkça hem RFC 7644 §3.4.2.2 filtrelerini **hem de §3.5.2 PATCH yollarını** kapsıyor. Genel tipler: `Filter` (And/Or/Not/Attr), `AttrExp`, `CompValue`, `CompareOp`, `AttrPath`, `ValuePath`, `ValFilter`, `PatchPath`, `PatchValuePath`, `MaybeFilter`, `InvalidFilterError`, `FilterActionError` ve bir **`MAX_FILTER_DEPTH`** sabiti.
- **PATCH: KISMİ.** Yalnızca yol *ayrıştırma*. **Uygulama mantığı YOK.**
- **Değerlendirici/eşleştirici: YOK** (dokümanlarda elle yazılmış özyinelemeli örnek var).
- **Şema doğrulama: HAFİF.** Açıkça: *"Validation is light because the schema is specifically flexible. We only validate required fields."* Mutability/returned/uniqueness/caseExact dayatması yok.
- **HTTP yönlendirme: YOK.**
- **Argus için en kullanışlı crate** — ve bu araştırmadan bir gün önce (2026-09-07) güncellenmiş, yani filtre/PATCH-yol çalışması yepyeni.

**`scim_proto` 1.11.1** (Kanidm) — `user`, `group`, `filter`, `constants`, `prelude`. `peg ^0.8`'e bağımlı ⇒ gerçek PEG tabanlı filtre parser'ı. **PATCH desteği yok, HTTP sunucu kodu yok.** **MPL-2.0** — Argus'a vendor etmeden önce lisans uyumunu kontrol et.

**`scim-server` 0.5.3** — *"Complete implementation of RFC 7643 and RFC 7644"* iddiası, çok kiracılı, framework-bağımsız. Doğrulanan: şema doğrulama VAR, ETag VAR, sayfalama VAR, bulk kısmi. **Ama filtre parser'ı ve PATCH desteği genel API'de belgelenmemiş** — yani "tam implementasyon" iddiası tam olarak **en zor iki parça için desteklenmiyor.** Son yayın **2025-09-21**, yani ~1 yıl bayat; pre-1.0 ve README *"Minor version increments signal breaking changes until v1.0"* diyor.

**SET / SSF / CAEP için Rust crate'i: YOK.** Argus SET üretimini kendi yazmalı — RFC 9967 SET'leri `events`, `txn`, `sub_id` claim'li JWT'lerden ibaret olduğu için bu **mütevazı** bir iş (`jsonwebtoken` / `josekit` üzerine).

#### Argus'un sıfırdan yazması gerekenler

Hiçbir crate uyumlu bir sunucu vermiyor. Sahiplenilmesi gerekenler:

1. **Şema kaydı** — tam attribute karakteristikleriyle (mutability/returned/uniqueness/caseExact/canonicalValues/referenceTypes), **errata uygulanmış** hâlde. Hiçbir crate bunu doğru modellemiyor.
2. **Mutability/returned dayatma katmanı** — POST, PUT, PATCH ve yanıt projeksiyonu için **farklı** uygulanır. Kimsede yok.
3. **PATCH motoru** — yol ayrıştır → hedef çöz → §3.5.2.1-3 kural listelerini uygula → `primary` otomatik düşürme → işlemsel geri alma → artı §2.8'deki 17 tolerans. **En büyük tek iş kalemi ve hiçbir crate vermiyor.**
4. **Filtre değerlendirici + sorgu planlayıcı** — errata 7322'nin `valLogExp`'i, 7319'un `not (`'ı, caseExact'e göre karşılaştırma, boolean/binary üzerinde gt/lt → `invalidFilter`, derinlik/karmaşıklık limitleri.
5. **Projeksiyon** (`attributes`/`excludedAttributes` × `returned` katmanları, alt-attribute yolları).
6. **Sayfalama** — hem indeks (1-tabanlı!) hem RFC 9865 cursor'ları, Okta'nın istediği kararlı sıralama garantisiyle.
7. **ETag üretimi + If-Match/If-None-Match + 412/304.** İpucu: `meta.location`/`meta.version` yanıtın parçası olduğu için **hash'i saklanan durumdan al, render edilmiş yanıttan değil.**
8. **`/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig`** — doğrulamayı yapan **aynı kayıttan** üretilmeli (tek doğruluk kaynağı), RFC 9865 `pagination` ve RFC 9967 `securityEvents` blokları dahil.
9. **Bulk** — bulkId çözümleme, döngüsel referans, `failOnErrors`, 413.
10. **RFC 9967 SET üretimi** ve opsiyonel OpenID SSF akış yönetimi.
11. **Satıcı uyumluluk şimi** — 17 tolerans, istemci başına açılıp kapanabilir.

> **Tavsiye: `scim_v2` 0.5.0'ı filtre/PATCH-yol AST'leri ve model struct'ları için al; 2-11 katmanlarını kendin yaz. `scim-server`'ı temel alma** — bir yıl bayat, pre-1.0, ve en önemli iki iddiası belgelenmemiş.

### 2.12 SCIM sınıflandırma özeti

**ZORUNLU:** `/Users`, `/Groups` (GET/POST/PUT/PATCH/DELETE), `/ServiceProviderConfig` (+ çoğul alias), `/ResourceTypes`, `/Schemas`, `eq`+`and` filtreleri, indeks sayfalaması, `attributes`/`excludedAttributes`, PATCH motoru, errata uygulanmış şema kaydı, 17 maddelik tolerans katmanı, soft-delete (`active=false`) **ve** hard DELETE.

**OPSİYONEL (Faz 2):** Tam filtre gramer (`co`/`sw`/`ew`/`pr`/`ne`/karşılaştırma), sıralama, ETag/If-Match, `POST /.search`, RFC 9865 cursor sayfalaması, RFC 9967 SET yayını (`:notice` modu), `/Me`.

**ATLANABİLİR (Faz 3+):** `/Bulk` (Entra desteklemiyor), `Prefer: respond-async` + `Set-Txn`, `:full` replikasyon olayları, OpenID SSF akış yönetimi, RFC 9944 cihaz şemaları, `returned:"request"` uzantıları.

### 2.13 SCIM efor tahmini

| İş kalemi | Tahmin |
|---|---|
| Şema kaydı + errata + karakteristik motoru | 2 hafta |
| Kaynak CRUD + mutability dayatma (POST/PUT ayrı) | 2 hafta |
| **PATCH motoru** (kural listeleri + atomiklik + primary + tolerans) | **3-4 hafta** |
| Filtre parser (errata düzeltmeli) + değerlendirici + SQL planlayıcı | 2-3 hafta |
| Projeksiyon + sayfalama (indeks + cursor) + sıralama | 2 hafta |
| Keşif endpoint'leri (tek kaynaktan üretim) | 1 hafta |
| ETag/eşzamanlılık | 0,5 hafta |
| Satıcı tolerans şimi + Entra SCIM Validator'dan geçme | **2 hafta** |
| RFC 9967 SET üretimi (`:notice`, push) | 1,5 hafta |
| **Toplam** | **~16-18 hafta / 1 mühendis** |

---

## BÖLÜM 3 — LDAP (SUNUCU TARAFI)

### 3.1 Stratejik çerçeve: LDAP bir protokol değil, bir *uyumluluk yüzeyi*

Argus'un LDAP yazma sebebi dizin ürünü olmak değil. Sebep şu: kurumsal alıcının envanterinde OIDC konuşmayan 10-30 arası cihaz/uygulama var — VPN concentrator'ları, NAS'lar, hypervisor konsolları, izleme sistemleri, eski Java uygulamaları. Bunlar OIDC'ye asla geçmeyecek. LDAP arayüzü, bu kuyruk için bir **gateway**'dir.

Bu, tasarım kararının tamamını belirler: **Argus bir DIT (Directory Information Tree) ürünü değil, iç veri modelinin LDAP projeksiyonudur.** Kanidm tam olarak bu kararı verdi ve dokümantasyonunda açıkça yazıyor: *"The LDAP server in Kanidm is not a complete LDAP implementation."* (kanidm.github.io/kanidm/stable/integrations/ldap.html, erişim 8 Eylül 2026)

### 3.2 RFC 4511 operasyonları — üçlü sınıflandırma

| Operasyon | ASN.1 tag | Argus için | Gerekçe |
|---|---|---|---|
| **BindRequest/Response** (simple) | 0/1 | **ZORUNLU** | Her istemcinin ilk işlemi. RFC 4513 §2: anonim dışında herhangi bir mekanizma destekleyen implementasyon name/password simple bind'ı **MUST** destekler ve bunu TLS ile korumaya **MUST** muktedir olmalı |
| **SearchRequest / SearchResultEntry / SearchResultDone** | 3/4/5 | **ZORUNLU** | Tüm okuma trafiği |
| **UnbindRequest** | 2 | **ZORUNLU** | Tek yönlü, yanıtsız; bağlantı kapatma |
| **AbandonRequest** | 16 | **ZORUNLU (kabul et)** | Yanıtsız. En azından parse edip aramayı iptal etmelisin, yoksa kaynak sızdırırsın |
| **ExtendedRequest/Response** | 23/24 | **ZORUNLU (kısmi)** | StartTLS (1.3.6.1.4.1.1466.20037) ve Who Am I (RFC 4532, 1.3.6.1.4.1.4203.1.11.3) |
| **SearchResultReference** | 19 | **OPSİYONEL** | Referral yoksa hiç üretme. Ürettiğin an SSRF yüzeyi açarsın |
| **CompareRequest/Response** | 14/15 | **OPSİYONEL** | Bazı eski istemciler grup üyeliğini `compare` ile sorar. Ucuz, ekle |
| **ModifyRequest/Response** | 6/7 | **KOŞULLU** | Sadece parola değiştirme senaryosu için (§3.7) |
| **AddRequest / DelRequest / ModifyDNRequest** | 8/10/12 | **ATLANABİLİR** | Hiçbir gerçek istemci bunları IdP gateway'inden istemiyor. `unwillingToPerform` (53) döndür |
| **IntermediateResponse** | 25 | **ATLANABİLİR** | Sadece RFC 4533 content sync için gerekir |

**Karar:** Faz 1 = Bind(simple) + Search + Unbind + Abandon + StartTLS + WhoAmI. Bu, aşağıdaki istemci listesinin **tamamını** karşılar.

### 3.3 RootDSE — ilk kırılma noktası

İstemcilerin çoğu bağlanır bağlanmaz `baseObject` scope, `(objectClass=*)` filtresi, boş base DN ile arama yapar. Bu RootDSE'dir ve **doğru cevap vermezsen istemci daha ilk adımda vazgeçer.**

Zorunlu operasyonel attribute'lar:

| Attribute | Değer | Not |
|---|---|---|
| `namingContexts` | `dc=idm,dc=example,dc=com` | İstemciler base DN'i buradan keşfeder |
| `supportedLDAPVersion` | `3` | |
| `subschemaSubentry` | `cn=Subschema` | Şema keşfi buraya yönlenir |
| `supportedExtension` | StartTLS + WhoAmI (+ PasswordModify varsa) OID'leri | |
| `supportedControl` | En azından `1.2.840.113556.1.4.319` (paged) | |
| `supportedSASLMechanisms` | Boş veya `EXTERNAL` | Boş bırakmak meşru |
| `vendorName` / `vendorVersion` | `Argus` / sürüm | Bazı istemciler AD/OpenLDAP ayrımı için buna bakar |
| `objectClass` | `top`, `OpenLDAProotDSE` (uyumluluk için) | |

**`cn=Subschema` gerçekten dolu olmalı.** Apache Directory Studio, phpLDAPadmin ve bazı Java istemcileri `objectClasses` / `attributeTypes` listesini okumadan çalışmaz. Bu, "sadece okuma gateway'i" iddiasının en can sıkıcı maliyetidir: RFC 4512 formatında şema string'leri üretmek zorundasın.

### 3.4 DIT ve şema modellemesi — OIDC modelini LDAP'a projekte etmek

İki geçerli yaklaşım var:

**(a) Düz model (Kanidm'in seçimi).** Ağaç yok; tüm entry'ler base DN'in hemen altında. DN, `spn`/`name`/`uuid`'den türetilir: `spn=test1@idm.example.com,dc=idm,dc=example,dc=com`. Kanidm bind sırasında `name=test1`, `test1@idm.example.com` veya ham UUID formatlarını kabul ediyor. (Kaynak: Kanidm LDAP dokümanı, erişim 8 Eylül 2026)

**(b) Sahte OU modeli.** `ou=people,dc=…` ve `ou=groups,dc=…`. Gerçek bir ağaç değil, iki sabit konteyner. **Argus için bunu öneriyorum**, çünkü istemci konfigürasyonlarının ezici çoğunluğu `user_base` / `group_base` ayrımı bekliyor (GitLab `group_base`, Grafana `search_base_dns`, Jenkins `userSearchBase`). Düz modelde bu alanlar aynı değeri alır ve grup/kullanıcı ayrımı filtreye kalır — çalışır ama her müşteri kurulumunda ek destek bileti demektir.

#### Zorunlu objectClass/attribute matrisi

| Katman | objectClass | Attribute'lar | Kim istiyor |
|---|---|---|---|
| Temel kimlik | `top`, `person`, `organizationalPerson`, `inetOrgPerson` | `uid`, `cn`, `sn`, `givenName`, `displayName`, `mail`, `userPassword` (asla döndürme) | Herkes |
| POSIX | `posixAccount` | `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell` | sssd, nslcd, NAS, Synology, Proxmox |
| Grup (isimli) | `groupOfNames` | `member` (tam DN) | Jenkins, GitLab, Nextcloud |
| Grup (POSIX) | `posixGroup` | `gidNumber`, `memberUid` (sadece uid, DN değil) | sssd, nslcd |
| Ters üyelik | — | `memberOf` (operasyonel) | Grafana, GitLab, AD alışkanlığı olan her şey |
| AD taklidi | — | `sAMAccountName`, `userPrincipalName`, `userAccountControl` | AD varsayan istemciler |

**Kritik ayrıntı:** `groupOfNames` ve `posixGroup` **aynı entry'de** verilmelidir ki hem DN tabanlı (`member`) hem uid tabanlı (`memberUid`) istemciler çalışsın. Standart şemada bu bir çakışmadır (`groupOfNames` `member` için MUST der); gerçek dünyada herkes RFC 2307bis benzeri gevşetmeyle bunu yapar. Argus şema doğrulaması yapmadığı için (projeksiyon, depo değil) bedava.

**`memberOf` operasyonel bir attribute'tur:** `*` ile gelen aramada dönmemeli, ancak açıkça istenirse veya `+` ile istenirse dönmeli. Ama gerçek dünyada Grafana `member_of` istiyor ve bazı istemciler açıkça istemiyor — pratik karar: `memberOf`'u **açıkça istendiğinde** döndür, `*`'ta döndürme, ve dokümantasyonda bunu yaz.

**uidNumber/gidNumber üretimi:** UUID'den deterministik türetme (örn. UUID'nin belirli bitlerini bir aralığa map'lemek) tek makul yol; sayaç tabanlı üretim çok-yazarlı dağıtık kurulumda çakışır. Kanidm bu alanda dikkat çekici bir sınırlamaya sahip: dokümanı yalnızca `gidnumber` map'lediğini, `uid` map'lemesi olmadığını söylüyor.

### 3.5 Filtre çevirisi — asıl mühendislik işi

RFC 4515 filtre grameri iç sorgu diline çevrilmeli. Desteklenmesi gereken düğümler:

| Filtre | Öncelik | Not |
|---|---|---|
| `(attr=value)` equalityMatch | ZORUNLU | |
| `(&...)` `(\|...)` `(!...)` | ZORUNLU | İç içe geçme derinliğine **sınır koy** (öneri: 16) |
| `(attr=*)` present | ZORUNLU | `(objectClass=*)` her yerde |
| `(attr=a*b*c)` substring | ZORUNLU | Sadece `initial`/`final`/`any`; indeksiz `any` sorgusu DoS vektörüdür |
| `(attr>=v)` `(attr<=v)` | OPSİYONEL | Nadiren kullanılır |
| `(attr~=v)` approxMatch | ATLANABİLİR | Equality'ye düşür |
| `extensibleMatch` genel | OPSİYONEL | |
| `(memberOf:1.2.840.113556.1.4.1941:=CN=...)` | **ÖZEL DURUM** | AD'nin iç-içe-grup kuralı. GitLab dokümanı bunu açıkça örnekliyor, Grafana "sunucu LDAP_MATCHING_RULE_IN_CHAIN desteklemeli" diyor. Argus'ta grup hiyerarşisi zaten iç modelde var → **transitif üyelik sorgusu olarak implemente et.** Bu, AD'den geçen müşterilerde tek satırlık konfigürasyon farkı yaratır |

Matching rule semantiği: `caseIgnoreMatch` (çoğu string), `caseExactMatch`, `caseIgnoreIA5Match` (mail), `distinguishedNameMatch` (DN normalizasyonu — boşluk/kaçış/case), `integerMatch` (uidNumber). DN karşılaştırması RFC 4514 normalizasyonu gerektirir ve **naif string karşılaştırması hatalıdır.**

**Güvenlik:** Filtre değerleri iç sorguya geçerken kaçışlanmalı (LDAP injection'ın tersi: LDAP'tan SQL'e injection). Ayrıca sunucu tarafı **sonuç limiti** (`sizeLimit`) ve **süre limiti** (`timeLimit`) zorunlu — istemci vermezse kendi tavanını uygula.

### 3.6 Kontroller

| Kontrol | OID | Sınıflandırma |
|---|---|---|
| Simple Paged Results (RFC 2696) | `1.2.840.113556.1.4.319` | **ZORUNLU.** Kritiklik varsayılanı FALSE, yani teknik olarak yok sayabilirsin — ama 1000+ kullanıcılı dizinlerde AD alışkanlığıyla gelen istemciler sayfalama yapar ve `size`/`cookie` çiftini yok sayarsan sonsuz döngüye girerler. Cookie **opak** olmalı; sunucu tarafında imzalı/HMAC'li bir opak token öneriyorum (durum tutmamak için) |
| Server-Side Sorting (RFC 2891) | `1.2.840.113556.1.4.473` | OPSİYONEL. `ldap3_proto` destekliyor |
| VLV | `2.16.840.1.113730.3.4.9` | ATLANABİLİR |
| ManageDsaIT | `2.16.840.1.113730.3.4.2` | ATLANABİLİR (referral yoksa anlamsız) |
| Password Policy | `1.3.6.1.4.1.42.2.27.8.5.1` | OPSİYONEL — parola süresi/kilit bilgisini istemciye taşımanın tek standart yolu |
| AD DirSync / ShowDeleted / ExtendedDn | AD OID'leri | ATLANABİLİR |
| Content Sync (RFC 4533) | `1.3.6.1.4.1.4203.1.9.1.1` | ATLANABİLİR — ama `ldap3_proto` destekliyor; ileride replikasyon isteyen müşteri çıkarsa hazır |

### 3.7 SASL, StartTLS, LDAPS — ne kadarı gerçekten gerekli

**Şaşırtıcı sonuç: hiçbir SASL mekanizması zorunlu değil.** RFC 4513 §B.2.1 bunu açıkça söylüyor: TLS ile korunan name/password simple bind, **SASL DIGEST-MD5'in yerine LDAP'ın mandatory-to-implement parola mekanizması oldu.** DIGEST-MD5 ayrıca RFC 6331 ile tarihsel/deprecated ilan edildi.

| Mekanizma | Argus | Gerekçe |
|---|---|---|
| simple bind + TLS | **ZORUNLU** | RFC 4513 §2 MUST; ve pratikte tüm istemcilerin kullandığı tek şey |
| SASL EXTERNAL | OPSİYONEL | RFC 4513 §2 "SHOULD support". mTLS/ldapi senaryosu için; ucuz |
| SASL PLAIN | ATLANABİLİR | simple bind'ın gereksiz tekrarı |
| SCRAM-SHA-256 (RFC 5802/7677) | ATLANABİLİR | Argus parolaları Argon2 ile saklıyorsa SCRAM zaten **implemente edilemez** — SCRAM sunucunun PBKDF2 tabanlı `StoredKey`/`ServerKey` tutmasını gerektirir. Ayrı bir kimlik bilgisi tipi demektir |
| GSSAPI / GSS-SPNEGO | ATLANABİLİR (LDAP'ta) | Kerberos'u HTTP tarafında çözmek daha değerli (§4) |
| DIGEST-MD5 | **ASLA** | RFC 6331 |

**StartTLS vs LDAPS:** RFC 4513 §3.1.1 "istemci hem Bind hem StartTLS yapacaksa **önce StartTLS yapmalı (SHOULD)**" der. Ama Kanidm StartTLS'i **kasıtlı olarak reddediyor** ve yalnızca LDAPS (636) sunuyor, gerekçe olarak güvenlik riskini gösteriyor (downgrade/stripping saldırıları; istemcinin StartTLS'i atlaması sessizce düz metin bind'a yol açar).

**Argus için karar:** LDAPS zorunlu ve varsayılan; StartTLS **desteklenir ama varsayılan kapalı** ve açıldığında düz-metin bind reddedilir (`confidentialityRequired`, kod 13). Böylece hem Kanidm'in güvenlik pozisyonunu hem de StartTLS'ten başkasını konuşamayan eski istemcileri karşılarsın. StartTLS'i tamamen reddetmek, alan tecrübesinde bazı VPN/NAS ürünlerini dışarıda bırakır.

**Anonymous ve unauthenticated bind:** RFC 4513 §6.3.1 net: *"Servers SHOULD by default fail Unauthenticated Bind requests with a resultCode of unwillingToPerform."* Yani `name` dolu + `password` boş → **reddet**. Bu, LDAP'ın en eski ve en sık istismar edilen tuzağıdır: naif implementasyonlar boş parolayı "başarılı bind" sayar ve tüm kimlik doğrulaması çöker. Anonim bind (her ikisi de boş) ise RootDSE için gerekli olabilir — ayrı bir yetki seviyesi olarak ele al, varsayılan olarak yalnızca RootDSE'ye izin ver.

### 3.8 Sadece-okuma yeterli mi? — istemci gerçeği

| İstemci | Ne yapıyor | Yazma istiyor mu | Doğrulama |
|---|---|---|---|
| **Grafana** | Service account ile arama veya `bind_dn` içinde `%s`; `member_of` veya `group_search_filter`; iç-içe grup için LDAP_MATCHING_RULE_IN_CHAIN | **Hayır** — dokümanı açıkça "no write is needed" diyor | grafana.com/docs/.../ldap/ (8 Eyl 2026) |
| **GitLab** | `bind_dn`+password; `uid` (varsayılan `sAMAccountName`/`uid`/`userPrincipalName`), `mail`, `cn`, `givenName`, `sn`; grup senkronu `group_base`/`admin_group` (Premium+); AD'de `userAccountControl` bit 2 ile devre dışı kullanıcı tespiti; `(memberOf:1.2.840.113556.1.4.1941:=...)` | **Hayır** (salt-okunur erişim) | docs.gitlab.com/administration/auth/ldap/ (8 Eyl 2026) |
| **Jenkins**, **Nextcloud** | Kullanıcı arama + grup üyeliği | Hayır (Nextcloud opsiyonel yazma modülü var, nadir) | — |
| **sssd / nslcd** | `posixAccount` + `posixGroup` tam seti; `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`, `memberUid` | Hayır (ama parola değiştirme için ext-op ister) | — |
| **VPN'ler (OpenVPN/strongSwan/FortiGate/Cisco ASA)** | Bind + grup kontrolü | Hayır | — |
| **NAS/hypervisor (Synology, Proxmox, Zabbix, pfSense)** | Bind + POSIX attribute'ları | Hayır | — |

**Sonuç: sadece-okuma %95 senaryoyu kapatıyor.** Tek gerçek istisna **parola değiştirme**: masaüstü Linux'ta `passwd`, sssd üzerinden LDAP Password Modify Extended Operation (RFC 3062, OID `1.3.6.1.4.1.4203.1.11.1`) çağırır. Bu tek bir extended op ve Argus'un iç parola değiştirme API'sine bağlanabilir. **Öneri: RFC 3062'yi destekle, ModifyRequest'i desteklemeyi reddet.** `userPassword` üzerinde `ModifyRequest` yapan istemci pratikte yok denecek kadar azdır.

### 3.9 Kanidm'den çıkarılacak dersler

Kanidm'in LDAP dokümanından (erişim 8 Eylül 2026) doğrulanan davranışlar ve bunların Argus için anlamı:

1. **Sadece simple bind + search.** Tüm yazmalar reddediliyor. Gerekçe: "Kanidm'in iç veri yapıları basit LDAP anahtar-değer formatına map'lenemiyor." — **Argus da aynı gerekçeye sahip.** Bunu bir kusur değil, tasarım kararı olarak dokümante et.
2. **Yetki düşürme:** İnsan hesapları POSIX parolasıyla bind ettiğinde **anonim seviye** yetki alıyorlar, kendi hesap yetkilerini değil. Yükseltilmiş okuma için `dn=token` DN'i ve API token'ı ile bind eden **service account** gerekiyor (`ldapwhoami -D "dn=token" -w "TOKEN"`).
   → **Bu, kopyalanması gereken en önemli fikirdir.** LDAP kanalı, tam hesap yetkisini taşımamalı: LDAP'ta parola çalınması tüm hesabı vermemeli. Argus'ta karşılığı: LDAP bind için ayrı bir credential sınıfı ("uygulama parolası"/"LDAP token") ve okuma kapsamı kısıtlı bir servis kimliği.
3. **Ayrı POSIX parolası:** LDAP bind'ı ancak hesap POSIX hesabı olarak yapılandırılmış ve geçerli POSIX parolası varsa çalışıyor; `set-ldap-allow-unix-password-bind false` ile kapatılabiliyor. → MFA'lı bir dünyada LDAP bind zaten tek faktörlüdür; **ayrı, kapsamı dar bir kimlik bilgisi** doğru cevaptır.
4. **StartTLS yok, LDAPS zorunlu**, web TLS sertifikasını yeniden kullanıyor.
5. **Ağaç yok, düz model**; `uid` map'lemesi yok, yalnızca `gidnumber`. → Argus bu iki noktada Kanidm'den **daha iyi** yapmalı (§3.4).
6. `+` ile genişletilmiş map'lemeler sorgulanabiliyor; map'lenen attribute'lar: `objectClass, name, spn, displayname, gidnumber, memberof, entryuuid`.

### 3.10 Rust ekosistemi — LDAP

| Crate | Sürüm | Son yayın | İndirme | Rol |
|---|---|---|---|---|
| `ldap3_proto` | **0.8.1** | 2026-08-14 | 273.468 (son 90 gün ~59.040) | **Sunucu tarafı protokol bağlayıcıları.** Kanidm ekibi (github.com/kanidm/ldap3) |
| `ldap3` | — | — | — | **İstemci** kütüphanesi; sunucu yazmak için değil |
| `rasn` / `der-parser` / `asn1-rs` | — | — | — | `ldap3_proto` yetersiz kalırsa ham BER için |

`ldap3_proto` 0.8.1'in docs.rs API yüzeyinden **doğrulanan** kapsam (erişim 8 Eylül 2026):

- **`LdapOp` varyantları:** `BindRequest/Response`, `UnbindRequest`, `SearchRequest`, `SearchResultEntry`, `SearchResultReference`, `SearchResultDone`, `ModifyRequest/Response`, `AddRequest/Response`, `DelRequest/Response`, `ModifyDNRequest/Response`, `CompareRequest`, `CompareResult`, `AbandonRequest`, `ExtendedRequest/Response`, `IntermediateResponse` → **RFC 4511'in tam operasyon seti wire seviyesinde mevcut.**
- **Hazır yapılar:** `LdapPasswordModifyRequest/Response` (RFC 3062), `LdapWhoamiRequest/Response` (RFC 4532) ve sabitleri `OID_PASSWORD_MODIFY`, `OID_WHOAMI`; `LdapMatchingRuleAssertion` (extensibleMatch); `LdapSubstringFilter`; `SaslCredentials`; `LdapDerefAliases`; `LdapSearchScope`; `LdapResultCode`.
- **`LdapControl` varyantları:** `SimplePagedResults`, `ServerSort`, `ServerSortResult`, `ManageDsaIT`, `PasswordPolicyRequest`, `SyncRequest`, `SyncState`, `SyncDone` (RFC 4533), `AdDirsync`, `ExtendedDn`, `ShowDeleted`, `SearchOptions`, `SdFlags`, `Unknown`.
- **`LdapCodec`** — tokio-util tabanlı framing.
- Ayrıca bir filtre parser fonksiyonu ihraç ediyor (RFC 4515 string → `LdapFilter`).

**Değerlendirme: LDAP, beş protokol içinde Rust ekosisteminin en iyi durumda olduğu alandır.** Codec, ASN.1, kontroller ve extended op'lar hazır. Argus'un yazması gereken şey protokol değil, **semantik**: DIT projeksiyonu, filtre→sorgu çevirisi, şema üretimi, sayfalama cookie'si, yetki modeli, TLS terminasyonu.

**Eksik olan:** `ldap3_proto` bir framework değil, sadece protokol. Bağlantı yaşam döngüsü, eşzamanlı istek yönetimi (bir bağlantıda çoklu messageID), abandon semantiği, TLS geçişi (StartTLS sonrası aynı soket üzerinde TLS'e yükseltme) senin işin.

### 3.11 LDAP efor tahmini

| İş kalemi | Tahmin |
|---|---|
| Bağlantı/codec/TLS/StartTLS yaşam döngüsü | 1-1,5 hafta |
| RootDSE + subschema üretimi | 1 hafta |
| DIT projeksiyonu + attribute map'leme motoru (yapılandırılabilir) | 2 hafta |
| Filtre parser → iç sorgu çevirisi + DN normalizasyonu | 2 hafta |
| Sayfalama (opak imzalı cookie), sizeLimit/timeLimit | 1 hafta |
| Bind yetki modeli (ayrı LDAP credential, service token) | 1 hafta |
| RFC 3062 password modify + WhoAmI | 0,5 hafta |
| Gerçek istemci uyum testleri (sssd, Grafana, GitLab, Jenkins, bir VPN) | 2 hafta |
| **Toplam** | **~10-11 hafta / 1 mühendis** |

---

## BÖLÜM 4 — KERBEROS / ACTIVE DIRECTORY ENTEGRASYONU

### 4.1 Doğru soru: "Kerberos implemente etmeli miyiz?" değil, "Kerberos'un neresinde durmalıyız?"

Modern bir IdP'nin Kerberos ile üç olası ilişkisi var. Bunları karıştırmak, bu konudaki en yaygın planlama hatasıdır:

| Rol | Ne demek | Argus için |
|---|---|---|
| **KDC olmak** | Kendi realm'ini işletmek, TGT/TGS vermek, AS-REQ/TGS-REQ işlemek, principal veritabanı tutmak | **ASLA.** Bu ayrı bir üründür (FreeIPA/Samba AD/MIT KDC). Ölçülemez risk, sıfır ticari getiri |
| **Kerberos SP/acceptor (SPNEGO)** | Tarayıcıdan gelen `Authorization: Negotiate` başlığını kabul edip, keytab ile GSSAPI üzerinden kullanıcı kimliğini çıkarmak | **HEDEF BU.** Argus'un login sayfasında "kurumsal ağdan gelen kullanıcı parola girmez" deneyimi |
| **Kerberos istemcisi** | Downstream servislere kullanıcı adına bilet almak (constrained delegation, S4U2Proxy) | **OPSİYONEL/İLERİ.** Nadir ama yüksek değerli; PAM/eski uygulama senaryoları |

Yani Argus'un yapması gereken: **HTTP Negotiate (SPNEGO) acceptor'ı + AD'den kullanıcı senkronizasyonu.** Bu, Keycloak'ın "Kerberos bridge" olarak adlandırdığı şeyle aynı kapsamdır: *"Kerberos bridge — Automatically authenticate users that are logged-in to a Kerberos server."* (keycloak.org/docs/latest/server_admin/, erişim 8 Eylül 2026)

### 4.2 SPNEGO/Negotiate protokol mekaniği (RFC 4559)

RFC 4559 metninden doğrulanan akış (rfc-editor.org/rfc/rfc4559.txt, erişim 8 Eylül 2026):

1. İstemci korumalı kaynağı `Authorization` başlığı olmadan ister.
2. Sunucu **401** döner, `WWW-Authenticate: Negotiate` (ilk challenge **token taşımaz**).
3. İstemci SPNEGO mekanizmasıyla GSSAPI token'ı üretir, base64 kodlar: `Authorization: Negotiate <base64-gssapi-data>`. Spec: *"gssapi-data contains the base64 encoding of an initialContextToken"* (RFC 2743).
4. Sunucu token'ı `gss_accept_sec_context`'e verir. Context tamamlanmadıysa **401 + `WWW-Authenticate: Negotiate <token>`** ile devam eder — **çok turlu olabilir.**
5. Context tamamlandığında sunucu **200** döner ve isteğe bağlı olarak `WWW-Authenticate: Negotiate <final-token>` ile **karşılıklı kimlik doğrulama** sağlar; istemci bunu `gss_init_security_context`'e vererek sunucuyu doğrular.

**Implementasyon açısından kritik noktalar:**

- **Çok turlu olması durum yönetimi gerektirir.** HTTP stateless; ama GSSAPI context turlar arası yaşamalı. Bunu bağlantıya bağlamak gerekir (HTTP/1.1 keep-alive) — bu yüzden `axum-negotiate-layer` gibi kütüphaneler `into_make_service_with_connect_info` ile bağlantı bilgisini taşır. **HTTP/2 ve reverse proxy arkasında bu kırılır**; Negotiate connection-oriented bir kimlik doğrulamadır ve HTTP semantiğine aykırıdır.
- RFC 4559 güvenlik değerlendirmesi: HTTP başlıkları korunmuyor, **kanal güvenliği (TLS) şart**; proxy arkasında istemci `Proxy-support: Session-Based-Authentication` başlığını doğrulamadan kimlik doğrulamamalı — aksi halde güvenlik context'i karışır.
- **Tarayıcı tarafı yapılandırma zorunlu.** Hiçbir tarayıcı rastgele bir siteye Kerberos bileti vermez. Chrome/Edge'de `AuthServerAllowlist`, Firefox'ta `network.negotiate-auth.trusted-uris` politikası gerekir. Microsoft'un Seamless SSO dokümanı bunu tabloda açıkça işaretliyor: Firefox ve macOS'ta Chrome "additional configuration" gerektiriyor. (learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso, sayfa güncellemesi 26 Şub 2026, erişim 8 Eylül 2026)
- **Fallback zorunlu.** Negotiate başarısız olursa (bilet yok, SPN yanlış, ağ dışı) kullanıcı normal login formuna düşmeli. Microsoft bunu "opportunistic feature" olarak tanımlıyor: *"If it fails for any reason, the user sign-in experience goes back to its regular behavior."*

### 4.3 Keytab ve SPN yönetimi — operasyonel gerçek

| Konu | Gereksinim |
|---|---|
| SPN formatı | `HTTP/idp.example.com@EXAMPLE.COM` — DNS adıyla **birebir** eşleşmeli. Load balancer arkasındaki farklı isim = sessiz başarısızlık |
| Keytab dosyası | AD'de `ktpass` veya `setspn` + `ktpass` ile üretilir; enctype seçimi kritik (`AES256-SHA1`; RC4 artık devre dışı bırakılıyor) |
| Anahtar rotasyonu | Keytab'ın `kvno`'su AD'deki ile eşleşmeli. Parola değişince eski keytab bozulur — **en sık üretim arızası budur** |
| Çoklu instance | Aynı keytab tüm Argus düğümlerinde olmalı (paylaşılan sır). Sır yönetimine (Vault/KMS) girmeli, konteyner imajına gömülmemeli |
| Cross-realm | Birden çok orman/realm varsa realm başına güven ve muhtemelen ayrı SPN |
| Delegation | RFC 4559 delegation'ı destekler ama Keycloak dokümanı da bunu sınırlamalar arasında sayıyor; **varsayılan kapalı tut** |

**Karar önerisi:** Keytab'ı Argus'un birincil sır deposunda tut, dosya sisteminden değil bellekten yükle, `kvno` uyuşmazlığında **açık ve okunabilir hata** üret. Bu son madde bir özellik değil, satış sonrası destek maliyetinin yarısıdır.

### 4.4 AD'den kullanıcı senkronizasyonu — üç kalıp

| Kalıp | Nasıl | Artı | Eksi | Ne zaman |
|---|---|---|---|---|
| **LDAP sync (pull)** | Argus, AD'ye LDAP istemcisi olarak bağlanır, periyodik veya `uSNChanged`/DirSync ile artımlı çeker | Ek bileşen yok; Keycloak'ın "LDAP user federation" modeli; herkes tanıyor | Ağ erişimi gerekir (AD genelde iç ağda), parola doğrulaması ya AD'ye delege edilir ya senkronlanmaz, silme tespiti zor (tombstone) | **Varsayılan. Faz 1.** |
| **SCIM (push)** | AD tarafındaki bir ajan/Entra, Argus'a SCIM ile push eder | Argus'un ağ erişimine ihtiyacı yok; olay tabanlı, gecikme düşük; **SCIM sunucusunu zaten yazıyoruz** | Karşı tarafta provisioning yapılandırması gerekir; saf on-prem AD'de yerleşik SCIM istemcisi yok | **Entra ID kaynaklıysa en iyi seçenek** |
| **Ajan (outbound connector)** | Müşteri ağında çalışan hafif Argus ajanı, dışa doğru bağlantı kurar | Firewall dostu; AD'ye içeriden erişir; parola doğrulamasını da proxy'leyebilir (Entra "Pass-through Authentication" modeli) | **Ayrı bir ürün.** Dağıtım, güncelleme, gözetim, güvenlik yüzeyi | Faz 3+, kurumsal satış zorlarsa |

**Kritik alt karar — parola:** AD kullanıcılarının parolası Argus'ta nasıl doğrulanacak?
- (a) **Delegasyon:** her login'de AD'ye LDAP simple bind → basit, doğru, ama AD'ye çevrimiçi bağımlılık.
- (b) **Hash senkronu:** AD parola hash'lerini çekmek (Entra Connect'in Password Hash Sync yaptığı şey) → yüksek ayrıcalık (DCSync) gerektirir, güvenlik incelemesinden zor geçer.
- (c) **Kerberos/SPNEGO:** parola hiç görülmez.
→ **Öneri: (a) + (c). (b)'yi yapma.**

### 4.5 2026'da hâlâ gerekli mi? — dürüst cevap

**Sinyal 1 — Microsoft kendi Kerberos tabanlı çözümünden uzaklaşıyor.** Entra Seamless SSO dokümanı (güncelleme 26 Şub 2026) açıkça: *"For Windows 10, Windows Server 2016, and later versions, it's recommended to use SSO via primary refresh token (PRT). For Windows 7 and Windows 8.1, it's recommended to use Seamless SSO."* Seamless SSO ayrıca Entra-joined ve hybrid-joined cihazlarda **kullanılmıyor**. Yani Microsoft, modern Windows filosunda Kerberos-tabanlı tarayıcı SSO'sunu terk etmiş, PRT'ye geçmiştir.

**Sinyal 2 — Ama Kerberos ölmedi, sadece yer değiştirdi.** Hâlâ zorunlu olduğu yerler:
- On-prem AD'ye bağlı **Linux masaüstü/sunucu** filoları (sssd + GSSAPI).
- **Domain-joined Windows** makinelerden iç web uygulamalarına SSO (klasik intranet).
- **Kamu, savunma, sağlık, üniversite** segmentleri — hava boşluklu veya hibrit ağlar.
- Ülke/kurum politikası gereği "bulut IdP yok" diyen alıcılar. **Argus'un hedef segmenti tam olarak burası olabilir.**

**Sonuç:** Kerberos, Argus için **ürün genişliği değil, satış kapısı** meselesidir. Rakip Keycloak bunu destekliyor; desteklemezsen belirli RFP'lerde elenirsin. Ama kullanım oranı düşüktür.

**Sınıflandırma:**
- **ZORUNLU (kurumsal segmente satış yapılacaksa):** HTTP Negotiate/SPNEGO acceptor + keytab yönetimi + AD LDAP sync + AD'ye bind delegasyonu.
- **OPSİYONEL:** Cross-realm güven, S4U2Proxy ile constrained delegation, PKINIT.
- **ATLANABİLİR:** KDC olmak, kendi principal veritabanı, ticket cache yönetimi, NTLM (kesinlikle hayır — Microsoft NTLM'i emekliye ayırıyor).

### 4.6 Rust ekosistemi — Kerberos/GSSAPI

crates.io API'sinden **doğrulanmış** veriler (8 Eylül 2026):

| Crate | Sürüm | Son yayın | Toplam indirme | Son 90 gün | Değerlendirme |
|---|---|---|---|---|---|
| **`libgssapi`** | **0.11.0** | 2026-05-30 | 1.203.363 | 571.340 | **Ana seçenek.** MIT lisanslı güvenli GSSAPI (RFC 2744) bağlayıcısı. MIT krb5, Heimdal ve Apple GSS framework'üne karşı entegrasyon test süiti var. `gss_accept_sec_context` dahil **acceptor tarafını destekliyor** — SPNEGO sunucusu için gereken tam olarak budur. `s4u` feature'ı ile constrained delegation (yalnızca MIT) |
| **`cross-krb5`** | **0.5.0** | 2026-05-31 | 949.875 | 497.685 | Basitleştirilmiş çapraz platform Kerberos 5 arayüzü; Windows'ta SSPI'ye, POSIX'te GSSAPI'ye map'ler. libgssapi'nin yazarı (estokes) tarafından |
| **`axum-negotiate-layer`** | **0.3.1** | 2026-04-28 | 4.453 | 96 | **Hazır axum tower layer'ı:** `NegotiateLayer::new(Some("HTTP/example.com"))`, `Authenticated` extension'ı ile client principal. Bağlantı bilgisini `into_make_service_with_connect_info::<NegotiateInfo>()` ile taşıyor — yani connection-bound context sorununu çözmüş. Ama **kullanım hacmi çok düşük** (son 90 günde 96 indirme); referans olarak oku, doğrudan bağımlılık yapmadan önce denetle |
| `synta-krb5` | 0.3.3 | 2026-08-01 | 1.064 | Kerberos V5 + GSSAPI ASN.1 yapıları (codeberg.org/abbra/synta). Saf Rust ASN.1 katmanı; FreeIPA ekosisteminden Alexander Bokovoy'un projesi. Düşük olgunluk ama gerçek |
| `krb5-rs` | 0.1.0 | 2026-03-15 | 80 | *"Pure Rust Kerberos V5: GSSAPI, SPNEGO, PKINIT. No C FFI"* iddiasında. **Tek sürüm, 80 indirme, hiç güncellenmemiş.** İddia büyük, kanıt yok — **kullanma.** |
| `sspi` (Devolutions) | — | — | — | Windows tarafı için alternatif; DOĞRULANMADI (bu araştırmada sürüm çekilmedi) |

**Sonuç: Argus C bağımlılığından kaçamaz.** `libgssapi` MIT krb5 veya Heimdal'a linklenir; bu, konteyner imajına `libkrb5` ve `/etc/krb5.conf` girmesi demektir. Saf Rust bir GSSAPI/SPNEGO acceptor'ı 2026'da **üretime hazır değildir**. Bu, Kerberos özelliğinin bir **feature flag** arkasında ve ayrı bir imaj varyantında olmasını gerektirir.

### 4.7 Kerberos efor tahmini

| İş kalemi | Tahmin |
|---|---|
| SPNEGO acceptor (libgssapi entegrasyonu, çok turlu context, connection-bound state) | 2 hafta |
| Keytab yükleme/rotasyon/sır entegrasyonu + teşhis mesajları | 1 hafta |
| Login akışına Negotiate adımının entegrasyonu + fallback | 1 hafta |
| AD LDAP sync (artımlı, DirSync/uSNChanged, silme tespiti, attribute mapper) | 3 hafta |
| AD'ye bind delegasyonu | 0,5 hafta |
| Gerçek AD ortamında test (kurulum dahil) | 1,5 hafta |
| **Toplam** | **~9 hafta / 1 mühendis** (AD test ortamı kurmanın gizli maliyeti yüksek) |

---

## BÖLÜM 5 — OPENID FEDERATION 1.0 / 1.1

### 5.1 Spec durumu — kullanıcının verdiği tarihler doğrulandı

| Öğe | Durum | Kaynak |
|---|---|---|
| **OpenID Federation 1.0** | **Final Specification, 17 Şubat 2026'da onaylandı.** Oylama: 85 kabul / 0 itiraz / 20 çekimser; 105 oy = 425 üyenin %24,7'si (%20 yeter sayısının üzerinde) | openid.net/openid-federation-1-0-final-specification-approved/ (8 Eyl 2026) |
| **OpenID Federation 1.1** | **Final, 6 Mayıs 2026'da onaylandı.** Oylama: 83 / 0 / 21; 104 oy = 418 üyenin %24,9'u | openid.net/openid-federation-1-1-final-specifications-approved/ (8 Eyl 2026) |
| **OpenID Federation for OpenID Connect 1.1** | Aynı oylamada Final onaylandı | aynı |
| Yayın tarihi tutarsızlığı | OIDF duyurusu "publication date May 6, 2026" derken Mike Jones'un yazısı "published May 11, 2026" diyor. **Küçük tutarsızlık — normatif önemi yok** | self-issued.info/?p=2849 |

**1.1 ne değiştirdi?** Mike Jones (spec editörlerinden) net: **hiçbir işlevsellik eklenmedi veya çıkarılmadı.** *"Together, they are equivalent to OpenID Federation 1.0, by design."* Yapılan iş bir **ayrıştırma**dır:

- **OpenID Federation 1.1** → protokolden bağımsız kısım: Entity Statement, Trust Chain, Metadata, Policy, Trust Mark, Federation Endpoints.
- **OpenID Federation for OpenID Connect 1.1** → OIDC/OAuth 2.0'a özgü kısım: entity type'lar, client registration akışları.
- **Bölüm numaraları 1.0 ile hizalı tutuldu**, iki sürüm birbirinin yerine kullanılabilsin diye.
- Ayrıştırma kararı **Nisan 2025'te SUNET'teki Federation Interop etkinliğinde** alındı.

**Argus için pratik sonuç:** 1.1 çiftini hedefle. Protokolden bağımsız çekirdeği (entity statement, trust chain, policy motoru) ayrı bir modül olarak yaz — çünkü spec de tam olarak bu ayrımı yaptı ve gelecekte OIDC dışı profiller (EUDI Wallet, agentic identity) aynı çekirdeği kullanacak.

### 5.2 "Dokuz ülkenin interop testi" — doğrulandı, ama içeriği abartılmamalı

| Öğe | Doğrulanan |
|---|---|
| Etkinlik | **TIIME (Trust and Internet Identity Meeting Europe) unconference**, Amsterdam |
| Tarih | **13 Şubat 2026** (OIDFed 1.0'ın Final olmasıyla aynı haftaya denk geldi) |
| Katılım | *"Twelve participants representing nine implementations and nine countries"* |
| Ülkeler | Hırvatistan, Finlandiya, Yunanistan, İtalya, Hollanda, Polonya, Sırbistan, İsveç, ABD |
| Organizatörler | Niels van Dijk (SURFnet), Davide Vaghetti (GARR), Giuseppe De Marco (İtalya Dijital Dönüşüm Dairesi — OpenID Federation Browser aracının yazarı) |
| Süreklilik | Etkinlik için kurulan test federasyonu sonrasında **aktif kalmaya devam etti** |

**NE KANITLANMADI:** OIDF'in duyuru metni **hangi endpoint'lerin, hangi akışların test edildiğini belirtmiyor** ve **hiçbir sınırlama/sorun raporlamıyor.** Bu, "dokuz bağımsız implementasyon aynı trust chain'i çözebildi" demektir — güçlü bir sinyal, ama bir uyum sertifikasyon programı değildir. **Bunu bir conformance suite'i olarak sunma.**

Önceki etkinlik karşılaştırma için: **Stockholm, 28-30 Nisan 2025** — 30 delege, 14 implementasyon, 15 ülke (oidfed.com/ecosystem/, 8 Eyl 2026). Yani katılım Amsterdam'da **daralmış** görünüyor; muhtemelen unconference formatının doğal sonucu.

### 5.3 Normatif gereksinim listesi (Federation 1.1)

#### 5.3.1 Entity Statement claim'leri

**Entity Configuration ve Subordinate Statement'ta ortak (§3.1.1):**

| Claim | Durum |
|---|---|
| `iss` | REQUIRED — issuer Entity Identifier |
| `sub` | REQUIRED — subject Entity Identifier (Entity Configuration'da `iss == sub`) |
| `iat` | REQUIRED |
| `exp` | REQUIRED |
| `jwks` | REQUIRED (çoğu durumda) — federation anahtarları |
| `metadata` | OPTIONAL |
| `crit` | OPTIONAL |

**Yalnızca Entity Configuration (§3.1.2):** `authority_hints` (üst otoriteler), `trust_anchor_hints`, `trust_marks`, `trust_mark_issuers`, `trust_mark_owners` — hepsi OPTIONAL.

**Yalnızca Subordinate Statement (§3.1.3):** `constraints` (§6.2), `metadata_policy`, `metadata_policy_crit`, `source_endpoint` — hepsi OPTIONAL.

Entity Statement doğrulaması spec'te **§3.2'de 25 adımlık bir süreç** olarak tanımlı. Bunu bir checklist olarak koda dökmek gerekir; "JWT doğrula, bitti" değildir.

**Keşif:** `https://<entity-identifier>/.well-known/openid-federation` — Entity Identifier bir HTTPS URL'dir ve well-known yolu **path'in sonuna eklenir** (path-suffix semantiği; RFC 8615'in klasik ana-dizin varsayımından farklı). Bu, çok kiracılı Argus'ta her kiracının kendi entity identifier'ı olabilmesi demektir.

#### 5.3.2 Federation endpoint'leri (§8) — rol bazlı zorunluluk

| Endpoint | Metadata parametresi | Leaf OP (Argus) | Intermediate | Trust Anchor |
|---|---|---|---|---|
| Fetch (§8.1) | `federation_fetch_endpoint` | **MUST NOT** | **MUST** | **MUST** |
| Subordinate Listing (§8.2) | `federation_list_endpoint` | **MUST NOT** | **MUST** | **MUST** |
| Resolve (§8.3) | `federation_resolve_endpoint` | MAY | MAY | MAY |
| Trust Mark Status (§8.4) | `federation_trust_mark_status_endpoint` | — | — | Trust Mark Issuer ise SHOULD |
| Trust Mark List (§8.5) | `federation_trust_mark_list_endpoint` | — | — | MAY |
| Trust Mark (§8.6) | `federation_trust_mark_endpoint` | — | — | MAY |
| Historical Keys (§8.7) | `federation_historical_keys_endpoint` | MAY | MAY | MAY |

**Dikkat: Leaf için Fetch/List MUST NOT'tur.** Yani "her ihtimale karşı hepsini açalım" yaklaşımı **spec ihlalidir.** Argus'un rolü çalışma zamanında yapılandırılabilir olmalı ve rol değiştiğinde entity configuration'daki metadata otomatik değişmeli.

#### 5.3.3 Metadata policy operatörleri (§6.1.3.1)

| Operatör | Etki | Uygulama sırası | Birleştirme (üst→alt) |
|---|---|---|---|
| `value` | Parametreyi ata/kaldır | 1 | Yalnızca değerler eşitse |
| `add` | Değer ekle | 2 | Birleşim |
| `default` | Yoksa ata | 3 | Değerler eşleşmeli |
| `one_of` | Sayılan değerlerle sınırla | 4 | Kesişim |
| `subset_of` | Dizi altküme olmalı | 5 | Kesişim |
| `superset_of` | Dizi üstküme olmalı | 5 (one_of sonrası) | Birleşim |
| `essential` | Parametre zorunlu | son | Yalnızca ikisi de true ise |

Politika ilkeleri (§6.1.1): **Hierarchy, Equal Opportunity, Specificity, Operation, Integral Enforcement, Determinism.** Pratikte bunun anlamı: **üstteki otorite alttakinin politikasını gevşetemez, sadece daraltabilir; ve birleştirme sonucu deterministik olmalı — çelişki varsa trust chain reddedilir.**

Bu, implementasyonun en hatalı yazılan parçasıdır. Politika birleştirme **saf, test edilebilir bir fonksiyon** olarak yazılmalı ve spec'in örnekleri birim testine dönüştürülmeli.

#### 5.3.4 Trust chain çözümleme (§10.2)

1. Subject'in (genelde leaf) Entity Configuration'ını çek.
2. `authority_hints`'ten üst otoritelerin Entity Configuration'larını al.
3. Her üstten, subject hakkındaki Subordinate Statement'ı çek (`fetch` endpoint'i).
4. Her adımda imzayı bir üstteki statement'ın `jwks`'i ile doğrula.
5. Yapılandırılmış Trust Anchor'a ulaşana kadar yukarı çık.
6. Trust Anchor'ın kendi Entity Configuration imzasını doğrula.
7. Zincirdeki tüm Subordinate Statement'ların metadata policy'lerini uygula.
8. Çözülmüş metadata'nın tüm politikalara uyduğunu doğrula.

**Zincir geçerliliği = tüm statement'ların `exp` değerlerinin minimumu (§10.4).** Önbellek TTL'i buna bağlanmalı, HTTP `Cache-Control`'e değil.

#### 5.3.5 Trust Mark (§7)

```
{ "trust_mark_type": "<identifier>", "trust_mark": "<signed JWT>" }
```
Trust Mark JWT'si: `iss` (issuer), `sub` (sahip entity), `trust_mark_type`, `iat`, `exp`.
**Trust Mark Delegation (§7.2.1):** Trust Mark Owner tarafından imzalanmış ayrı bir JWT, ihraç yetkisini başkasına devreder.

> **Sürüm tuzağı:** 1.1'de claim adı **`trust_mark_type`**. Eski taslaklarda `id` / `trust_mark_id` görülür. İtalyan SPID gibi eski taslaklara göre yazılmış implementasyonlarla interop yaparken bu isim farkı ilk kırılma noktasıdır.

#### 5.3.6 Entity type'lar

`federation_entity` (§5.1.1) protokolden bağımsız kısımda tanımlı: endpoint'ler + `organization_name`, `logo_uri` gibi bilgisel parametreler. `openid_provider`, `openid_relying_party`, `oauth_authorization_server`, `oauth_resource`, `oauth_client` gibi tipler **profillerde/Connect spec'inde** tanımlı.

### 5.4 Client registration — Argus'un OP olarak yapması gereken

**Automatic registration (Connect 1.1 §12.1):**
- RP **önceden kayıt olmaz.** RP, kendi **Entity Identifier'ını `client_id` olarak kullanır.**
- Kimlik doğrulama **asimetrik kripto ile MUST**; client secret yoktur.
- Request Object zorunlu alanları (§12.1.1.1): `aud` = OP'nin Entity Identifier'ı, `client_id` = `iss` = RP'nin Entity Identifier'ı, `jti` (tekrar kullanımı engellemek için), `exp`.
- OP tarafında akış: `client_id`'yi URL olarak al → RP'nin Entity Configuration'ını çek → trust chain'i çöz → metadata policy uygula → **çözülmüş RP metadata'sını o istek için client kaydı gibi kullan.**

**Explicit registration (§12.2):**
- RP, OP'nin `federation_registration_endpoint`'ine POST eder.
- Gövde: Entity Configuration (`application/entity-statement+jwt`) veya tam trust chain (`application/trust-chain+json`).
- OP doğrular, trust chain çözer, metadata'yı uyum için **değiştirebilir**, ve **trust chain'in `exp`'ini aşmayan** bir geçerlilik süresi atar.
- Yanıt: Entity Statement, content type `application/explicit-registration-response+jwt`, içinde atanan `client_id`.
- OP, **Entity Identifier'dan farklı bir `client_id` verebilir (MAY)** — bu, mevcut DCR altyapısının üzerine inşa etmeyi mümkün kılar.

**Metadata parametreleri:** OP'de `client_registration_types_supported` (`automatic` ve/veya `explicit`) ve explicit destekleniyorsa `federation_registration_endpoint`. RP'de `client_registration_types`.

### 5.5 Client resolution katmanı — üç kaynaktan gelen kimlik

Argus'ta bir `client_id` üç farklı anlama gelebilir. Bu, tasarımın en kritik mimari kararıdır.

| Yol | `client_id` nedir | Güven kaynağı | Metadata kaynağı | İptal/rotasyon |
|---|---|---|---|---|
| **DCR (RFC 7591)** | Argus'un ürettiği opak string | **Argus'un kendi kaydı** | Yerel veritabanı | Yerel silme |
| **CIMD** (`draft-ietf-oauth-client-id-metadata-document`, **rev -02, 6 Tem 2026** — datatracker ile doğrulandı) | İstemcinin barındırdığı HTTPS URL | **Yok — sadece alan adı kontrolü (TOFU benzeri)** | URL'den canlı çekilir | URL'i kaldırmak |
| **OpenID Federation** | RP'nin Entity Identifier'ı (HTTPS URL) | **Trust Anchor'a kadar imza zinciri** | Trust chain + metadata policy ile çözülür | Subordinate statement'ı çekmek / trust mark iptali |

**Tasarım kuralları:**

1. **Tek bir `ClientResolver` soyutlaması yaz.** Girdi: `client_id` + istek bağlamı. Çıktı: `ResolvedClient { metadata, trust_level, source, expires_at, policy_applied }`. Protokol katmanı bu üç yolu ayırt etmemeli.
2. **`trust_level` birinci sınıf alan olmalı.** Federation ile gelen istemci, CIMD ile gelenden farklı yetkilere sahip olmalı. Örnek politika: CIMD istemcileri hassas scope'ları isteyemez, consent ekranı her zaman gösterilir ve "bu uygulama doğrulanmamış" uyarısı çıkar; Federation istemcilerinde trust mark varsa consent atlanabilir.
3. **Çakışma çözümü — sıra sabit ve deterministik olmalı:** `client_id` bir HTTPS URL ise → önce Federation dene (entity configuration çekilebiliyor ve trust chain çözülüyorsa), sonra CIMD; URL değilse → yerel DCR kaydı. **URL biçimindeki bir `client_id`'nin yerel kayda düşmesine asla izin verme** (kayıt kaçırma/karıştırma saldırısı).
4. **Kiracı başına hangi yolların açık olduğu yapılandırılabilir olmalı.** Çoğu kiracı yalnızca DCR isteyecek; federation'ı açan az sayıdaki kiracı için ekstra ağ trafiği ve gecikme kabul edilebilir olacak.
5. **Önbellek ve tazelik ayrı ayrı yönetilmeli:** Federation'da TTL = trust chain'in min `exp`'i; CIMD'de HTTP cache başlıkları + kendi tavanın. Her ikisinde de **SSRF savunması zorunlu** (özel IP aralıklarını engelle, yönlendirme sayısını sınırla, boyut sınırı koy, DNS rebinding'e karşı bağlantı-zamanı IP kontrolü).
6. Argus'un MCP dokümanındaki uyarıyla tutarlı ol: `docs/14-mcp-authorization.md` §5.2, MCP spec'inin CIMD **-00**'a atıf yaptığını ama **-02**'nin yeni normatif MUST'lar getirdiğini ve -02'nin uygulanması gerektiğini söylüyor. Aynı resolver bu farkı taşımalı.

### 5.6 Kim implemente etti — ekosistem

oidfed.com/ecosystem/ (8 Eylül 2026) ve OIDF kaynaklarından:

| Alan | Uygulama |
|---|---|
| **İtalya** | SPID/CIE OIDC Federation; teknik kurallar Ocak 2023'te yayımlandı. Ulusal eID (2022) IdP federasyonu için OpenID Federation'ı seçti |
| **İsveç** | Sweden Connect teknik çerçevesi 2025 içinde OpenID Federation desteği ekliyor |
| **AB** | EUDI Wallet / eIDAS 2.0, sınır ötesi cüzdan güveni için OpenID Federation'a atıf yapıyor |
| **GÉANT / eduGAIN** | Temmuz 2025'te başlayan **12 aylık pilot**, SAML ile paralel |
| **SUNET** | `satosa-idpy` — OpenID Federation yetenekli OP frontend'i olarak referans implementasyon |
| **Ticari** | Authlete, Connect2id, Raidiam Connect |

**Kütüphaneler (dil bazında):** Go — `zachmann/go-oidfed`; Java — Nimbus OAuth 2.0 SDK, `italia/spid-cie-oidc-java`; Kotlin — Sphereon; Python — `rohe/fedservice`, `italia/spid-cie-oidc-django`; PHP — `simplesamlphp/openid`; Node.js — `italia/spid-cie-oidc-nodejs`; TypeScript — `@oidfed/*` (Apache 2.0).

**Rust listede yok.**

**Keycloak:** OpenID Federation eklentisi olduğuna dair topluluk yazıları var (bucchi.medium.com, trust chain ile özelleştirilmiş DCR endpoint'i). **Resmî Keycloak dokümanından DOĞRULANMADI** — çekirdek özellik mi eklenti mi belirsiz.

**Kanidm:** GitHub Discussion #4154 (Şubat 2026) — OpenID Federation'ın SAML yerine "modern, OIDC-yerlisi bir yol" olarak değerlendirildiği tartışma. Bakımcı Firstyear (20 Şub 2026): *"We need to understand the protocol and problem space first before we make choices."* Taahhüt yok. **Yani doğrudan rakip konumdaki Rust IdP'si bu alanda henüz boş.**

### 5.7 Rust ekosistemi — OpenID Federation

crates.io API'sinden doğrulanmış (8 Eylül 2026):

| Crate | Sürüm | Yayın | İndirme | Değerlendirme |
|---|---|---|---|---|
| `openid-federation` (impierce) | **0.1.0** | **2025-10-02** (tek sürüm) | **283 toplam / son 90 gün 8** | GitHub'da **0 yıldız, 0 fork, 4 commit**, Apache-2.0. **OpenID Federation 1.0 draft 43**'e göre yazılmış — yani **Final'den önceki bir taslak.** Kapsam iddiası geniş (entity configuration, trust chain, policy operatörleri) ama olgunluk göstergeleri sıfır. **Üretimde kullanılamaz; en fazla referans** |

**Sonuç: OpenID Federation'da Rust'ta hiçbir şey yok. Sıfırdan yazılacak.** Ama iyi haber şu: gereken alt yapı taşları (JWS imzalama/doğrulama, JWK Set yönetimi, HTTPS istemcisi, JSON) Argus'ta OIDC için zaten olacak. Federation, bunların üzerine oturan **saf mantık** katmanıdır — XML gibi bir yabancı teknoloji stack'i getirmez. Bu, beş protokol içinde **Rust ekosistemi boşluğunun en az acı verdiği** alandır.

Yazılacaklar: Entity Statement modeli + §3.2'nin 25 adımlık doğrulaması, trust chain çözümleyici (döngü tespiti, derinlik sınırı), metadata policy motoru (7 operatör + birleştirme + çelişki tespiti), federation endpoint'leri, trust mark doğrulama/delegasyon, önbellek katmanı, historical keys, automatic/explicit registration akışları.

### 5.8 Gerçek dünya tuzakları

1. **Önbellek olmadan ölçeklenmez.** Her authorize isteğinde trust chain çözmek, N adet HTTPS çağrısı demektir. Çözülmüş metadata'yı `exp` minimumuna kadar önbelleğe al; negatif sonuçları da (kısa TTL ile) önbelleğe al.
2. **Trust anchor'ın yükü.** Büyük federasyonlarda trust anchor'ın fetch endpoint'i tek darboğaz. Statement'lar imzalı olduğu için **CDN'lenebilir** — bunu tasarıma yaz.
3. **Zincir uzunluğu ve döngü.** `constraints` (§6.2) `max_path_length` verir, ama sen kendi mutlak tavanını da koy. Döngü tespiti zorunlu.
4. **Anahtar rotasyonu iki katmanlı:** federation imzalama anahtarları (`jwks`, entity statement'ları imzalar) ile OP'nin token imzalama anahtarları **ayrıdır ve ayrı rotate edilir.** Karıştırmak yaygın hatadır. `federation_historical_keys_endpoint` eski anahtarlarla imzalanmış hâlâ geçerli statement'ların doğrulanabilmesi içindir.
5. **Saat kayması.** `exp`/`iat` kontrollerinde tolerans gerekir; ama federasyonda tolerans **küçük** tutulmalı (öneri: 60 sn).
6. **Offline doğrulama.** Trust chain, `application/trust-chain+json` olarak taşınabildiği için istemci zinciri **kendi getirebilir** — bu durumda Argus ağ çağrısı yapmadan doğrular. Explicit registration'ın bu seçeneği sunması tesadüf değil; kapalı ağlar için tek yol budur.

---

## BÖLÜM 6 — TOPLAM EFOR VE SIRALAMA

### 6.1 Efor tahmini — protokol bazında

Tahminler **tek bir deneyimli Rust mühendisi**, tam zamanlı, mevcut Argus çekirdeği (kullanıcı deposu, oturum, kripto, HTTP katmanı) hazır varsayımıyla. Test, dokümantasyon ve interop çalışması dahildir; **satış öncesi destek ve müşteriye özel hata ayıklama dahil değildir.**

| Protokol | Faz 1 (zorunlu) | Faz 2 (opsiyonel) | Toplam |
|---|---|---|---|
| **SCIM 2.0** | 16-18 hafta | +6 hafta (cursor, SET, /.search, ETag) | **~24 hafta** |
| **SAML 2.0 (IdP)** | 14-16 hafta | +8 hafta (SLO, MDQ, şifreleme, artifact) | **~24 hafta** |
| **LDAP** | 10-11 hafta | +3 hafta (StartTLS, password modify, sorting) | **~14 hafta** |
| **Kerberos/AD** | 9 hafta | +4 hafta (cross-realm, delegasyon) | **~13 hafta** |
| **OpenID Federation** | 12-14 hafta | +6 hafta (intermediate rolü, trust mark ihracı) | **~20 hafta** |
| **TOPLAM** | **61-68 hafta** | +27 hafta | **~95 hafta ≈ 1,8 mühendis-yılı** |

**Bu rakam yanıltıcıdır ve tek başına kullanılmamalıdır.** Üç düzeltme faktörü:

1. **Interop kuyruğu tahminlerin dışındadır.** SAML'de her yeni büyük SP, SCIM'de her yeni büyük istemci bir hafta yiyebilir. Gerçekçi çarpan: Faz 1 üzerine **%30-40 sürekli bakım.**
2. **Paralelleştirilebilirlik sınırlı.** SCIM ve LDAP aynı iç veri modelini ve yetki katmanını kullanır; iki mühendis aynı anda çalışırsa çakışırlar. SAML ve OpenID Federation birbirinden bağımsızdır ve gerçekten paralelleşir.
3. **Test ortamı kurulumu gizli maliyettir.** Bir AD ormanı, bir Entra kiracısı, bir Okta developer hesabı, bir SPID test federasyonu kurmak ve **canlı tutmak** kendi başına 3-4 hafta ve kalıcı bir bakım yüküdür.

### 6.2 Sıralama — ve gerekçesi

#### Faz 1: SCIM 2.0 (aylar 0-5)

**Neden ilk:**
- **Kurumsal alıcının en sık sorduğu şey budur.** README §7'nin kendi ifadesiyle: "Kurumsal alıcının en sık sorduğu şey."
- **Ağ etkisi yok, tek taraflı.** Kimseyle federe olman gerekmiyor; kendi endpoint'ini yazıp Entra SCIM Validator'a tutuyorsun.
- **Ölçülebilir bitiş çizgisi var:** scimvalidator.microsoft.com'dan geçmek. Diğer dört protokolün böyle bir kapısı yok.
- İç veri modelini (attribute karakteristikleri, mutability, projeksiyon) **doğru kurmaya zorluyor** — ve bu model LDAP ile Federation'da yeniden kullanılıyor.
- Teknolojik risk düşük: XML yok, ASN.1 yok, GSSAPI yok. Saf JSON + HTTP.

**Bitiş kriteri:** Entra SCIM Validator'dan tam geçiş + Okta ile canlı bir OIN entegrasyonu + 17 maddelik tolerans katmanı testli.

#### Faz 2: SAML 2.0 IdP (aylar 4-10, SCIM ile kısmen örtüşür)

**Neden ikinci:**
- **B2B satışta kapı bekçisi.** README §7: "B2B satışta kapı bekçisi. Ory'nin desteklememesi ciddi boşluk." Rakip analizinde bu, Argus'un Ory karşısındaki en net avantajı.
- Ama **en yüksek teknik riski taşıyor**: XML kripto. Bu yüzden SCIM'in ardından, ekip Argus'un iç modelini oturttuktan sonra.
- **Erken karar noktası:** `bergshamra`/`gamlastan` mı, `xmlsec` FFI mi? Bu kararı **fazın ilk iki haftasında bir spike ile** ver, sonra dönme.

**Bitiş kriteri:** Salesforce, AWS IAM Identity Center, Google Workspace ve M365'e canlı SSO; sertifika rotasyonu prosedürü belgeli ve test edilmiş.

#### Faz 3: LDAP (aylar 9-12)

**Neden üçüncü:**
- Kapsam iyi tanımlı, ekosistem hazır, sürpriz düşük — yani **öngörülebilir bir faz**, ve SAML'in belirsizliğinden sonra buna ihtiyaç olacak.
- SCIM'de kurulan veri modelinin ikinci tüketicisi; model hataları burada ortaya çıkar ve **ucuza** düzeltilir.
- Tek başına satış kapatmaz ama **RFP checkbox'ıdır** ve eksikliği eleme sebebidir.

**Bitiş kriteri:** sssd ile Linux login, Grafana + GitLab + Jenkins ile grup senkronu, bir VPN cihazıyla bind.

#### Faz 4: OpenID Federation (aylar 12-17)

**Neden dördüncü ama atlanmamalı:**
- **Bugün müşteri talebi yok.** Ama üç şey aynı anda oluyor: spec Final oldu (Şub/May 2026), eduGAIN pilotu çalışıyor, EUDI Wallet buna atıf yapıyor.
- **Rust'ta hiç yok** ve doğrudan rakip Kanidm henüz karar vermemiş. Bu, "Rust'ta OpenID Federation'ı olan tek IdP" konumu için **12-18 aylık bir pencere** demektir.
- Teknolojik olarak **en temiz** faz: JWS/JWK altyapısı zaten var, XML yok, C bağımlılığı yok, saf mantık.
- Ama **gelir getirmesi en uzak** olan; bu yüzden dördüncü.

**Bitiş kriteri:** Bir test federasyonunda (SPID test ortamı veya kendi kurduğumuz trust anchor) leaf OP olarak automatic registration ile çalışan uçtan uca akış.

#### Faz 5: Kerberos/AD (aylar 16-20)

**Neden son:**
- **Değer/efor oranı en düşük olanı.** Microsoft kendi Kerberos tabanlı çözümünden uzaklaşıyor (§4.5).
- Tek C bağımlılığını getiriyor → dağıtım hikâyesini bozuyor (ayrı imaj varyantı, `/etc/krb5.conf`, keytab sır yönetimi).
- **AD LDAP sync kısmı ise erken gerekebilir** — ve o kısım Kerberos'a bağımlı değildir. **Ayır:** "AD'den kullanıcı senkronizasyonu" Faz 3'ün (LDAP) yanına kaydırılabilir, SPNEGO Faz 5'te kalır.

**Bitiş kriteri:** Domain-joined bir Windows makineden tarayıcıyla parolasız login + bir AD ormanından artımlı kullanıcı senkronu.

### 6.3 Alternatif sıralama: "satış odaklı" senaryo

Eğer somut bir kurumsal anlaşma SAML'i şart koşuyorsa sıra **SAML → SCIM → LDAP → Federation → Kerberos** olur. Bu durumda kabul edilen risk: iç veri modeli SAML'in attribute ihtiyaçlarına göre şekillenir ve SCIM'in `mutability`/`returned` katmanı sonradan zorla takılır. **Bu, ileride ödenecek bir borçtur ama meşru bir ticari karardır.**

**Hiçbir koşulda önerilmeyen sıra:** Kerberos veya OpenID Federation ile başlamak. Birincisi C bağımlılığını ve dağıtım karmaşıklığını en başa taşır; ikincisi henüz alıcısı olmayan bir yatırımı öne alır.

### 6.4 Ortak altyapı — beş protokolün paylaştığı katmanlar

Bunlar **protokol fazlarından önce** veya ilk fazla birlikte inşa edilmeli; her birini beş kez yazmak en pahalı hatadır:

| Katman | Kim kullanıyor |
|---|---|
| **Attribute/claim map'leme motoru** (iç model → dış temsil, dönüşüm fonksiyonlarıyla) | SAML attribute statement, SCIM projeksiyonu, LDAP attribute map'i, OIDC claim'leri |
| **Anahtar ve sertifika yaşam döngüsü** (üretim, rotasyon, çoklu aktif anahtar, HSM/KMS) | SAML imzalama, Federation entity anahtarları, OIDC JWKS, LDAPS/TLS, Kerberos keytab |
| **Güvenli dış HTTP istemcisi** (SSRF savunması, boyut/yönlendirme limitleri, önbellek) | SAML metadata çekme, Federation entity statement, CIMD, SCIM webhook teslimatı |
| **Replay/nonce cache** (TTL'li, dağıtık) | SAML assertion ID, Federation `jti`, DPoP, OIDC nonce |
| **Denetim olayı boru hattı** | Hepsi — ve RFC 9967 SET yayını buradan beslenir |
| **Çok kiracılılık ve kiracı başına yapılandırma** | Hepsi |
| **Kabul/uyum test harness'ı** | Entra SCIM Validator, SAML SP simülatörleri, LDAP istemci matrisi, Federation test federasyonu |

### 6.5 Karar önerisi — tek paragraf

**SCIM ile başla, SAML ile devam et, LDAP ile sağlamlaştır, OpenID Federation ile farklılaş, Kerberos'u en sona bırak ve AD senkronizasyonunu Kerberos'tan ayırarak öne al.** Beş protokolün tamamı ~1,8 mühendis-yılı çekirdek iş, artı sürekli %30-40 interop bakımı. İki mühendisle 12-14 ayda Faz 1-3 (SCIM+SAML+LDAP) tamamlanabilir ve bu, kurumsal RFP'lerin ezici çoğunluğunu karşılar. OpenID Federation ve Kerberos ikinci yıla bırakılabilir — ama Federation'ın penceresi kapanmadan girilmeli.

---

## BÖLÜM 7 — DOĞRULANAMAYANLAR VE SINIRLAR

Bu dokümandaki her sürüm numarası, tarih, oy sayısı ve indirme rakamı birincil kaynaktan alınmıştır. Aşağıdakiler **doğrulanamamıştır** ve iddia olarak kullanılmamalıdır:

| # | Konu | Durum |
|---|---|---|
| 1 | **Google Workspace, OneLogin, JumpCloud, Ping, SailPoint SCIM istemci davranışları** | DOĞRULANMADI. Birincil kaynaktan teyit edilemedi (arama bütçesi tükendi). Ayrı bir doğrulama turu gerekiyor |
| 2 | **Entra ID'nin kesin 429 / zaman aşımı / yeniden deneme sayısı değerleri** | DOĞRULANMADI. Microsoft'un kamuya açık dokümanlarında yok. Yalnızca "karantina → günde bir → dört hafta sonra devre dışı" akışı belgeli |
| 3 | **Okta'nın Runscope tabanlı SCIM test süitinin 2026'da çalışır durumda olup olmadığı** | DOĞRULANMADI. Runscope BlazeMeter tarafından kapatıldı; Okta'nın yerine ne koyduğu teyit edilmedi |
| 4 | **`draft-ietf-scim-profile-*` veya bir 7644bis dokümanının varlığı** | DOĞRULANMADI — SCIM WG doküman listesinde böyle bir şey yok. PATCH netleştirmesi yalnızca errata 7122/8097 olarak mevcut |
| 5 | **Keycloak'ın OpenID Federation desteğinin resmî durumu** | DOĞRULANMADI. Topluluk yazıları bir eklentiden söz ediyor; resmî Keycloak dokümanından çekirdek özellik olduğu teyit edilemedi |
| 6 | **Amsterdam interop etkinliğinde tam olarak hangi endpoint ve akışların test edildiği** | DOĞRULANMADI. OIDF duyurusu bunu belirtmiyor ve hiçbir sınırlama raporlamıyor. "Dokuz implementasyon birbirine karşı test etti" ifadesinin ötesine geçme |
| 7 | **OpenID Federation 1.1'in kesin yayın tarihi** | Çelişkili: OIDF duyurusu "6 Mayıs 2026", Mike Jones "11 Mayıs 2026" diyor. Onay tarihi (6 Mayıs 2026) kesin; yayın tarihi tartışmalı. Normatif önemi yok |
| 8 | **`sspi` (Devolutions) crate'inin güncel sürümü ve Windows tarafı kapsamı** | DOĞRULANMADI — bu araştırmada crates.io verisi çekilmedi |
| 9 | **`bergshamra`'nın README'sindeki sürüm iddiası** | **ÇÖZÜLDÜ ama tutarsız.** README "Version 0.10.1 was released on August 02, 2026" diyor; crates.io'da `bergshamra` azami sürümü **0.9.0 (2026-09-02)** ve 0.10.x hiç yok. 0.10.1 büyük olasılıkla alt bağımlılık **`uppsala`**'nın sürümüdür (uppsala 0.10.1, 2026-09-02 — doğrulandı). **crates.io'yu esas al.** Bu tutarsızlık projenin doküman disiplini hakkında bir uyarıdır |
| 10 | **Salesforce, ServiceNow, Workday, AWS IAM Identity Center, Slack, Zoom, Atlassian SAML gereksinimleri** | DOĞRULANMADI. Hiçbiri birincil kaynaktan teyit edilemedi (Salesforce yardım sitesi SPA, diğerleri erişilemedi veya müşteri girişi arkasında). **Bu satıcılar için NameID formatı, attribute adı veya imza yeri iddiası bu dokümanda ÜRETİLMEDİ ve üretilmemelidir** — uydurulmuş bir attribute adı sessizce başarısız olan bir entegrasyon demektir |
| 11 | **Google Workspace'in imza algoritması, sertifika gereksinimi, Response vs Assertion imzalama ve SLO politikası** | DOĞRULANMADI — resmî gereksinim sayfasında yer almıyor |
| 12 | **NIST SP 800-131A Rev 3'ün SHA-1 için kesin ifadesi** | DOĞRULANMADI. Yürürlükteki sürüm **Rev 2 (Mart 2019)**; Rev 3 hâlâ **taslak** (yorum süresi 4 Aralık 2024'te kapandı), 8 Eylül 2026 itibarıyla final değil. PDF içeriğine erişilemedi |
| 13 | **XSW1-8 taksonomisinin birebir tanımları** | DOĞRULANMADI. Referans: Somorovsky et al., *"On Breaking SAML: Be Whoever You Want to Be"*, USENIX Security 2012 |
| 14 | **Jager & Somorovsky, "How to Break XML Encryption" (ACM CCS 2011) tam metni** | KISMEN DOĞRULANMADI — W3C XMLEnc 1.1 REC'in §5.1.1/§6.9 metni iddiayı birincil kaynak olarak destekliyor, ama makalenin kendisine erişilemedi |
| 15 | **MDQ'nun `{sha1}` transform'unu tanımlayan SAML profil dokümanının tam adı/sürümü** | DOĞRULANMADI. Temel `draft-young-md-query` bu transform'u tanımlamıyor, *"reserved for profile specifications"* diyor |
| 16 | **Comment truncation (CVE-2017-11427/11428) mekanizmasının teknik ayrıntısı** | KISMEN DOĞRULANMADI. Duo'nun orijinal teknik yazısı 8 Eylül 2026 itibarıyla erişilemez (Cisco Duo pazarlama sayfasına yönleniyor); açıklama CVE metni temellidir |
| 17 | **Shibboleth'in SLO hakkındaki resmî ifadesi** | DOĞRULANMADI — wiki sayfasına erişilemedi. §1.8'deki gerekçeler spec metninden çıkarılan yapısal nedenlerdir, satıcı beyanı değildir |
| 18 | **Microsoft Entra'nın SHA-1/SHA-256 çelişkisinin pratikte hangi tarafa düştüğü** | ÇÖZÜLMEDİ — doküman kendi içinde çelişkili. **Canlı test gerektirir** |
| 19 | **Efor tahminleri** | Bunlar **muhakeme ürünüdür, ölçüm değildir.** Hiçbir birincil kaynağa dayanmaz. ±%40 bant kabul et |

### 7.1 Bu dokümanın kapsamadıkları

- **SP tarafı SAML** — Argus'un başka bir IdP'ye SP olarak bağlanması (kimlik brokerliği) ayrı bir konudur ve tamamen farklı bir tehdit modeli taşır (bu dokümandaki tüm imza *doğrulama* CVE'leri oraya uygulanır).
- **RADIUS** — README §7'de listelenmiş ama bu araştırmanın kapsamı dışında bırakıldı.
- **WS-Federation** — legacy; kasıtlı olarak kapsam dışı.
- **SAML 1.1 / Shibboleth'e özgü uzantılar** — kapsam dışı.
- **Performans ve ölçek rakamları** — hiçbir protokol için ölçüm yapılmadı.
- **Lisans analizi** — `scim_proto` MPL-2.0, `gamlastan`/`bergshamra` BSD-2-Clause, `ldap3_proto` (Kanidm) ve `libgssapi` (MIT) farklı lisanslar taşıyor. **Argus'un lisans modeliyle uyum ayrıca incelenmelidir.**
