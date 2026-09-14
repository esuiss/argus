# §16 — Kurumsal protokoller: SAML, SCIM, LDAP, Kerberos ve federasyon

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

**Kapsam.** Argus'un SAML 2.0'ı IdP tarafında, SCIM 2.0'ı sunucu tarafında, LDAP'ı sunucu tarafında, Kerberos ile Active Directory entegrasyonunu ve OpenID Federation 1.0 ile 1.1'i desteklemesi için gereken her şey, implementasyon seviyesinde.

**Yöntem.** RFC'ler rfc-editor.org'dan ham metin olarak okunmuş, errata rfc-editor.org/errata adresinden alınmış, IETF durumları Datatracker API'sinden, OASIS SAML spesifikasyonları docs.oasis-open.org'dan, OpenID spesifikasyonları openid.net'ten, satıcı gereksinimleri Microsoft Learn, Okta Developer, GitLab, Grafana ile Kanidm resmî dokümanlarından alınmıştır. Rust crate verileri crates.io JSON API'sinden canlı çekilmiştir. Blog özetleriyle yetinilmemiştir.

> **Doğrulama notu.** Her sürüm numarası, tarih ve indirme sayısı birincil kaynaktan alınmıştır. Doğrulanamayan noktalar açıkça işaretlenmiş ve yedinci bölümde toplanmıştır. Rakam uydurulmamıştır.

**İçindekiler.**

| Bölüm | Konu |
|---|---|
| 0 | Yönetici özeti, on iki kritik bulgu ve sınıflandırma özet tablosu |
| 1 | SAML 2.0, IdP tarafı: artefaktlar, XML imzalama, exc-c14n, şifreleme, NameID, binding'ler, SLO, metadata, saldırılar, SP gereksinimleri ve Rust |
| 2 | SCIM 2.0, sunucu tarafı: altı RFC, endpoint'ler, veri modeli, PATCH motoru, filtre dili, sayfalama, Entra ile Okta interop'u, RFC 9967 olayları ve Rust |
| 3 | LDAP, sunucu tarafı: operasyonlar, RootDSE, DIT izdüşümü, filtre çevirisi, kontroller, SASL ile TLS, istemci gerçeği, Kanidm dersleri ve Rust |
| 4 | Kerberos ile Active Directory: SPNEGO kabul edicisi, keytab, senkronizasyon kalıpları, 2026'da gereklilik ve Rust |
| 5 | OpenID Federation 1.0 ile 1.1: spesifikasyon durumu, entity statement, güven zinciri, politika motoru, istemci çözümleme katmanı, ekosistem ve Rust |
| 6 | Toplam efor tahmini ve önerilen sıralama |
| 7 | Doğrulanamayanlar ve dokümanın sınırları |

---

## 0. Yönetici özeti, on iki kritik bulgu

1. **Rust'ta saf XML imzalama artık mümkündür.** `bergshamra` (kushaldas) XMLDSig, XMLEnc ile C14N'i saf Rust'ta vermekte ve xmlsec1'in kendi interop test süitini 1148/1151 geçmektedir. Üstündeki `gamlastan` SAML 2.0 kütüphanesinin SPID uyum iddiası ise kanıt sayılmaz: rakam kütüphanenin kendi README dosyasından gelmektedir ve `italia/spid-saml-check` servis sağlayıcılarını test eder, kimlik sağlayıcılarını değil; süitin birincil kaynaklarındaki sayılar 300'den fazla kontrol ve yedi ailedir. Buna karşılık `bergshamra`'nın xmlsec1 sonucu bağımsız bir süite karşıdır ve geçerlidir. Bu, SAML için libxmlsec1'e mecbur olma varsayımını 2026'da geçersiz kılmaktadır; ancak her ikisi de tek geliştiricilidir, 0.9.0 sürümündedir ve benimsenmeleri düşüktür, 1.13.2'ye bakınız.

2. **SCIM artık üç RFC değil altı RFC'dir.** Brief'teki "RFC 9967 SCIM Events" adı yanlıştır; gerçek başlık "SCIM Profile for Security Event Tokens (SETs)"tir ve Mayıs 2026 tarihlidir. Ayrıca RFC 9865 (imleç sayfalaması, Ekim 2025) ile RFC 9944 (cihaz şeması, Mayıs 2026) vardır ve ikisi de 7643 ile 7644'ü günceller, 2.1'e bakınız.

3. **SCIM'in en büyük tek iş kalemi PATCH motorudur ve hiçbir Rust crate'i bunu vermemektedir.** `scim_v2` yalnızca yol soyut sözdizim ağacını vermektedir. Uygulama mantığı, atomiklik, `primary` düşürme kuralı ve 17 maddelik satıcı toleransı tamamen bize aittir; 2.4 ile 2.11'e bakınız.

4. **Entra ile Okta birbiriyle çelişen şeyler şart koşmaktadır.** Okta çıplak `GET /Groups/{id}` isteğinin üyeleri döndürmesi zorunlu demektedir. Entra ise tüm üyeleri döndürmenin tavsiye edilmediğini söylemektedir. Tek çözüm istemci başına açılabilen bir hoşgörü katmanıdır, 2.8'e bakınız.

5. **Entra kendi uyumsuzluğunu belgelemekte ve düzeltme tarihi vermemektedir:** "Update PATCH behavior to ensure compliance — Fixed? No — Fix date TBD". `aadOptscim062020` bayrağı uyumlu moda geçirmektedir, ancak bayraklı modda bile düz noktalı JSON anahtarları göndermektedir, örneğin `"name.givenName"`; 2.8'e bakınız.

6. **LDAP, Rust ekosisteminin en iyi durumda olduğu protokoldür.** `ldap3_proto` 0.8.1 (Kanidm, 14 Ağustos 2026) RFC 4511'in tam operasyon setini, `SimplePagedResults`, `ServerSort` ile `SyncRequest` kontrollerini ve `PasswordModify` ile `WhoAmI` genişletilmiş operasyonlarını kablo seviyesinde vermektedir. Yazılacak olan protokol değil semantiktir, 3.10'a bakınız.

7. **Kanidm'in LDAP bind'ının düşürülmüş yetki verdiği kararı kopyalanmalıdır.** LDAP kanalı tam hesap yetkisini taşımamalıdır; ayrı bir kimlik bilgisi sınıfı gerekmektedir. Çok adımlı doğrulamanın olduğu bir dünyada LDAP bind zaten tek faktörlüdür, 3.9'a bakınız.

8. **Yalnızca okuma yapan LDAP senaryoların %95'ini kapatmaktadır.** Grafana dokümanı açıkça yazma gerekmediğini söylemektedir; GitLab salt okunur erişim istemektedir. Tek gerçek istisna RFC 3062 Password Modify'dır, yani Linux `passwd` komutu, ve bu tek bir genişletilmiş operasyondur; 3.8'e bakınız.

9. **Kerberos'ta Argus KDC olmamalı, yalnızca SPNEGO kabul edicisi olmalıdır.** Microsoft kendi Kerberos tabanlı Seamless SSO'sunu modern Windows'ta birincil yenileme token'ı lehine terk etmiştir; doküman güncellemesi 26 Şubat 2026 tarihlidir. Kerberos artık ürün genişliği değil, belirli ihalelerde bir satış kapısıdır; 4.5'e bakınız.

10. **Kerberos, C bağımlılığından kaçamayacağımız tek protokoldür.** `libgssapi` 0.11.0 MIT krb5 veya Heimdal'a linklenmektedir. Saf Rust GSSAPI iddiasındaki `krb5-rs` 0.1.0'ın tek sürümü ve 80 indirmesi vardır, kullanılamaz; 4.6'ya bakınız.

11. **OpenID Federation'da Rust tamamen boştur ve bu bizim en büyük farklılaşma fırsatımızdır.** Tek crate olan `openid-federation` 0.1.0, Final'den önceki draft 43'e göre yazılmıştır; sıfır yıldızı, dört commit'i ve son 90 günde sekiz indirmesi vardır. oidfed.com'un ekosistem listesinde Rust hiç geçmemektedir. Doğrudan rakip Kanidm de bu alanda henüz karar vermemiştir; Discussion #4154, Şubat 2026. 5.6 ile 5.7'ye bakınız.

12. **crates.io'da SAML ile SCIM isim işgali vardır.** `opensaml`, `samlify`, `samlet` ile `rustsaml` crate'lerinin dördü de aynı sahibin (`salasebas`) `saml-rs` paketinin uyumluluk yeniden dışa aktarımlarıdır. Aynı sahip `scim-rs`'i de yayımlamıştır. Bu isimlere güvenip bağımlılık alınmamalıdır; 1.13.3'e bakınız.

**Stratejik sinyal.** Beş protokolün Rust ekosistemindeki durumu ters sıralıdır: LDAP hazırdır, SCIM kısmen hazırdır, SAML yeni ve umut vericidir ancak tek kişiliktir, Kerberos C'ye mahkûmdur ve OpenID Federation sıfırdır. En büyük teknik risk SAML'in kripto katmanındadır; en büyük fırsat OpenID Federation'dadır; en büyük iş hacmi SCIM PATCH motorundadır.

### 0.1 Sınıflandırma özeti

| Protokol | Zorunlu, faz 1 | Opsiyonel, faz 2 | Atlanabilir |
|---|---|---|---|
| SAML 2.0 | SP başlatmalı tarayıcı çoklu oturum açması, HTTP-POST ile HTTP-Redirect binding'i, Response ile Assertion imzalama (RSA-SHA-256 ve exc-c14n), IdP metadata yayını, SP metadata tüketimi, kalıcı ile geçici NameID, attribute statement, yeniden oynatma önbelleği | EncryptedAssertion, IdP başlatmalı akış, imzalı metadata ile MDQ, ECDSA imzalar, çift taraflı tanımlayıcı, arka kanal tek noktadan çıkış | HTTP-Artifact binding'i, ECP ile PAOS, ön kanal tek noktadan çıkış garantisi, SAML 1.1, WS-Federation, holder-of-key |
| SCIM 2.0 | `/Users`, `/Groups`, `/ServiceProviderConfig` ve çoğulu, `/ResourceTypes`, `/Schemas`, PATCH motoru, `eq` ile `and`, indeks sayfalaması, izdüşüm, satıcı tolerans katmanı | Tam filtre grameri, sıralama, ETag, `/.search`, RFC 9865 imleci, RFC 9967 güvenlik olayı token'ı `:notice` profili, `/Me` | `/Bulk`, `Prefer: respond-async`, `:full` replikasyonu, OpenID SSF akış yönetimi, RFC 9944 cihaz şeması |
| LDAP | Basit bind ile TLS, Search, Unbind, Abandon, RootDSE, alt şema, filtre çevirisi, sayfalı sonuçlar, LDAPS | StartTLS, RFC 3062 Password Modify, WhoAmI, Compare, sunucu tarafı sıralama, SASL EXTERNAL, zincirde eşleşme kuralı | Add, Delete ile ModifyDN, SASL GSSAPI, SCRAM ile DIGEST-MD5, sanal liste görünümü, yönlendirme, RFC 4533 senkronizasyonu |
| Kerberos | SPNEGO ile Negotiate kabul edicisi, keytab yönetimi, Active Directory LDAP senkronizasyonu, Active Directory'ye bind delegasyonu | Alanlar arası güven, S4U2Proxy delegasyonu, PKINIT | KDC olmak, principal veritabanı, NTLM |
| OpenID Federation | Entity Configuration (yaprak OP), entity statement doğrulaması (§3.2, 25 adım), güven zinciri çözümleme, metadata politika motoru (yedi operatör), otomatik kayıt | Açık kayıt, güven işareti doğrulama, resolve endpoint'i, tarihsel anahtarlar | Ara düğüm veya güven çıpası rolü (fetch ile list endpoint'leri), güven işareti ihraç etmek, federasyona özgü profiller |

---

## Bölüm 1 — SAML 2.0, IdP tarafı

**Kaynak temeli.** Beş OASIS standardının tamamı (`saml-core`, `saml-bindings`, `saml-profiles`, `saml-metadata`, `saml-sec-consider`; hepsi 15 Mart 2005, docs.oasis-open.org/security/saml/v2.0/) PDF olarak indirilip metne çevrilmiştir; aşağıdaki tüm bölüm numaraları ve alıntılar bu birincil metinlerden çıkarılmıştır. Ek kaynaklar W3C `xml-exc-c14n` önerisi, W3C XML Encryption 1.1 önerisi, RFC 9231, OASIS Metadata Interoperability Profile v1.0, NVD REST API ile crates.io REST API'sidir.

### 1.1 IdP'nin üretmesi gereken artefaktlar

#### 1.1.1 `<AuthnRequest>` işleme, SAMLCore §3.4.1

Şema sırası bir `sequence`'tir ve sıra önemlidir: önce `saml:Subject?`, sonra `samlp:NameIDPolicy?`, sonra `saml:Conditions?`, sonra `samlp:RequestedAuthnContext?`, en son `samlp:Scoping?`.

| Nitelik | Tip | IdP davranışı |
|---|---|---|
| `ForceAuthn` | boolean, varsayılan false | `true` ise IdP kullanıcıyı yeniden kimlik doğrulamalıdır ve mevcut güvenlik bağlamına güvenmemelidir |
| `IsPassive` | boolean, varsayılan false | `true` ise IdP ile kullanıcı aracısı kullanıcı arayüzünü görünür şekilde ele geçirmemelidir |
| `AssertionConsumerServiceIndex` | unsignedShort | `AssertionConsumerServiceURL` ile `ProtocolBinding` ile karşılıklı dışlayandır |
| `AssertionConsumerServiceURL` | anyURI | `Index` ile karşılıklı dışlayandır |
| `ProtocolBinding` | anyURI | `Index` ile karşılıklı dışlayandır |
| `AttributeConsumingServiceIndex` | unsignedShort | SP metadata'sındaki `<md:AttributeConsumingService>` öğesine bir indekstir; IdP yok sayabilir |
| `ProviderName` | string | Yalnızca insan okunurdur |

`ForceAuthn` ile `IsPassive` ikisi de `true` ise SAMLCore §3.4.1 şunu söyler: "if both ForceAuthn and IsPassive are 'true', the identity provider MUST NOT freshly authenticate the presenter unless the constraints of IsPassive can be met." Yani `IsPassive` kazanır; karşılanamazsa `urn:oasis:names:tc:SAML:2.0:status:NoPassive` dönülmelidir.

> **IdP tarafındaki bir numaralı güvenlik kuralı, SAMLProf §4.1.4.1.** "Whether the request is signed or not, the identity provider MUST ensure that any `<AssertionConsumerServiceURL>` or `<AssertionConsumerServiceIndex>` elements in the request are verified as belonging to the service provider to whom the response will be sent. Failure to do so can result in a man-in-the-middle attack."
>
> İmzasız bir `AuthnRequest`'te bile ACS URL'i asla doğrudan kullanılmaz. Her zaman SP metadata'sındaki kayıtlı `<md:AssertionConsumerService>` listesine karşı tam eşleşme doğrulanır. Bu, IdP'nin açık yönlendirme ve assertion sızdırma vektörüdür.

`<NameIDPolicy>` (§3.4.1.1) alanları `Format?`, `SPNameQualifier?` ile `AllowCreate`'tir; sonuncunun varsayılanı `"false"`tur. Anlaşılmayan politika `urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy` döndürür. `AllowCreate="false"` varsayılanı, kalıcı NameID kullanan kurulumlarda bir tuzaktır: IdP yalnızca önceden kurulmuş bir tanımlayıcı varsa assertion verebilir.

`<Scoping>` (§3.4.1.2 ile 3) alanları `ProxyCount` (sıfır proxy'lemenin yasak olduğu anlamına gelir), `<IDPList>` ile `<IDPEntry>` ve `<GetComplete>`, ayrıca `<RequesterID>*`'tır. Desteklenmeyen IdP için `NoAvailableIDP` veya `NoSupportedIDP` dönülür. Argus'un birinci sürümünde bu ayrıştırılır, `ProxyCount` saklanır, `RequesterID` denetim kaydına yazılır ve proxy'leme implemente edilmez.

#### 1.1.2 `<Response>`, SAMLProf §4.1.4.2 normatif listesi

1. Hata dönerken assertion içermemelidir.
2. `<Issuer>` atlanabilir; varsa IdP'nin benzersiz kimliğidir ve `Format` atlanır veya `...nameid-format:entity` olur.
3. En az bir `<Assertion>` içermelidir.
4. Assertion kümesi en az bir `<AuthnStatement>` içermelidir.
5. En az bir assertion, `Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"` olan bir `<SubjectConfirmation>` içermelidir.
6. Tek noktadan çıkış destekleniyorsa: "any such authentication statements MUST include a `SessionIndex` attribute".
7. Bearer `<SubjectConfirmationData>` öğesi `Recipient` (SP'nin ACS URL'i) ile `NotOnOrAfter` içermelidir; `NotBefore` içermemelidir; istek üzerine üretilmişse `InResponseTo` değeri isteğin `ID` değerine eşit olur; `Address` opsiyoneldir.
8. Bearer assertion bir `<AudienceRestriction>` içermelidir ve `<Audience>` değeri SP'nin benzersiz tanımlayıcısı olur.
9. `<AttributeStatement>` opsiyoneldir; `AttributeConsumingServiceIndex` yok sayılabilir.
10. IdP, istekteki `<Conditions>` öğesini onurlandırmak zorunda değildir.

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

> **Assertion şema sırası (SAMLCore §2.3.3) bir `sequence`'tir ve bozulamaz:** `Issuer`, sonra opsiyonel `ds:Signature`, sonra opsiyonel `Subject`, sonra opsiyonel `Conditions`, sonra opsiyonel `Advice`, sonra sıfır veya daha fazla `Statement`. `ds:Signature`, `Issuer`'dan hemen sonra gelmek zorundadır. Rust'ta serileştirici yazarken en sık kırılan nokta budur.

#### 1.1.4 `<Conditions>` (§2.5.1) incelikleri

`NotBefore` değeri `NotOnOrAfter` değerinden küçük olmalıdır ve `NotOnOrAfter` dışlayıcıdır, yani o an dahil değildir.

§2.5.1.4'e göre bir `<AudienceRestriction>` içindeki çoklu `<Audience>` öğeleri arasında VEYA, çoklu `<AudienceRestriction>` öğeleri arasında VE ilişkisi vardır. Çoklu audience isteniyorsa tek bir `AudienceRestriction` içinde çoklu `Audience` yazılır.

`<OneTimeUse>` ile `<ProxyRestriction>` öğeleri, şema çoklu izin verse de en fazla birer tane olmalıdır.

#### 1.1.5 `SessionIndex` üretimi, SAMLCore §2.7.2

Spesifikasyonun gizlilik uyarısı şudur: "the value SHOULD NOT be usable to correlate activity by a principal across different session participants." İki önerilen yol vardır: rastgele bir aralıktan küçük tamsayılar kullanmak, ya da kapsayan assertion'ın `ID` değerini kullanmak.

Microsoft'un kendi örneği ikinci yolu kullanmaktadır, yani `SessionIndex` değeri assertion kimliğidir. Argus önerisi de ikinci yoldur; ancak gerçek bir tek noktadan çıkış isteniyorsa IdP tarafında `SessionIndex` değerinden SP entity kimliği ile kullanıcı oturumuna giden bir eşleme tablosu tutmak zorunludur. Aynı kullanıcının aynı SP'ye ikinci kez oturum açmasında eski indeksi geçersizleştirme mantığı gerekir.

#### 1.1.6 Metadata dokümanı, SAMLMeta §2.4.1 ile 2.4.3

`RoleDescriptorType` nitelikleri `ID?`, `validUntil?`, `cacheDuration?`, zorunlu olan ve `urn:oasis:names:tc:SAML:2.0:protocol` içermesi gereken `protocolSupportEnumeration` ile `errorURL?`'dir.

`SSODescriptorType` alt eleman sırası `ArtifactResolutionService*`, `SingleLogoutService*`, `ManageNameIDService*` ile `NameIDFormat*`'tır.

`IDPSSODescriptorType` ek olarak varsayılanı false olan `WantAuthnRequestsSigned` niteliğini ve bir veya daha fazla `<SingleSignOnService>` öğesini taşır; bu öğede `ResponseLocation` niteliği atlanmalıdır. Ayrıca `<NameIDMappingService>*`, `<AssertionIDRequestService>*`, `<AttributeProfile>*` ile `<saml:Attribute>*` bulunur.

`<KeyDescriptor>` (§2.4.1.1) içinde `ds:KeyInfo` zorunludur, `md:EncryptionMethod*` ile opsiyonel `use` bulunur; `use` atlanırsa anahtar her iki amaç için de geçerlidir.

### 1.2 XML imzalama

#### 1.2.1 SAMLCore §5.4, XML Signature Profile

| Bölüm | Kural |
|---|---|
| §5 | "any XML Digital Signatures MUST be enveloped" |
| §5.4.2 | "Signatures MUST contain a single `<ds:Reference>` containing a same-document reference to the ID attribute value... if the ID attribute value is 'foo', then the URI attribute MUST be '#foo'." Yani `URI=""` SAML'da yanlıştır ve tam olarak bir `Reference` olmalıdır |
| §5.4.3 | "SAML implementations SHOULD use Exclusive Canonicalization, with or without comments, both in `<ds:CanonicalizationMethod>` and as a `<ds:Transform>` algorithm." |
| §5.4.4 | "Signatures SHOULD NOT contain transforms other than the enveloped signature transform or the exclusive canonicalization transforms. Verifiers MAY reject signatures that contain other transform algorithms as invalid." |
| §5.4.5 | `<ds:KeyInfo>` bulunmayabilir; SAML kısıt getirmez |
| §5.4.1 | 2005 metni `rsa-sha1` için SHOULD demektedir. Bu bugün geçersizdir, 1.2.4'e bakınız |

#### 1.2.2 Exclusive C14N, implementasyonun zor kısmı

URI'ler `http://www.w3.org/2001/10/xml-exc-c14n#` ile `...#WithComments`'tir.

Inclusive C14N'den iki temel farkı vardır (W3C önerisi §3). Birincisi `xml:` isim alanı nitelikleri, yani `xml:lang`, `xml:space` ile `xml:base`, ata düğümlerden kopyalanmaz. İkincisi yalnızca görünür biçimde kullanılan isim alanı bildirimleri çıktılanır.

Görünür biçimde kullanma tanımı §1.1'dedir: "An element E in a document subset visibly utilizes a namespace declaration... if E or an attribute node in the document subset with parent E has a qualified name in which P is the namespace prefix."

> **Kritik nokta.** Bir önek yalnızca bir nitelik değerinin içinde string olarak geçiyorsa, örneğin `xsi:type="xsd:decimal"` içinde, XPath ifadelerinde veya QName tipli içerikte, bu görünür kullanım sayılmaz ve isim alanı bildirimi çıktılanmaz; sonuç olarak imza doğrulanamaz. `InclusiveNamespaces PrefixList` tam olarak bunu telafi etmek için vardır:
>
> ```xml
> <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
>    <ec:InclusiveNamespaces PrefixList="dsig soap #default"
>        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
> </ds:Transform>
> ```
>
> `#default` token'ı varsayılan isim alanını işaret eder ve listedeki önekler kapsayıcı muamele görür.

Saf Rust'ta yazmanın zorluğu şudur: algoritmanın kendisi yaklaşık 500 ile 800 satırdır ve yapılabilir. Asıl zorluk doküman alt kümesi ile düğüm kümesi semantiğidir; enveloped-signature dönüşümü `ds:Signature` alt ağacını düğüm kümesinden çıkarır ve bunu doğru modellemek gerekir. Burada yapılan hata ya sessiz bir imza uyumsuzluğu ya da daha kötüsü XSW'ye açık bir doğrulayıcı üretir. Yazılmamalıdır; 2026'da hazır bir çözüm vardır, 1.13'e bakınız.

#### 1.2.3 Response mu, Assertion mı, ikisi birden mi

| Kaynak | Kural |
|---|---|
| SAMLCore §5.1 ile §5.2 | İkisi de opsiyoneldir, zorunlu değildir |
| SAMLCore §5.3 | İmza kalıtımı: assertion imzasızsa ve kapsayan imzalı eleman onu kapsıyorsa, "the resulting interpretation should be equivalent to the case where the assertion itself was signed" |
| SAMLProf §4.1.4.5 | "If the HTTP POST binding is used to deliver the `<Response>`, the enclosed assertion(s) MUST be signed." |
| SAMLProf §4.1.6 | SP metadata'sındaki `WantAssertionsSigned` için: "the identity provider is not obligated by this, but is being made aware of the likelihood that an unsigned assertion will be insufficient" |

**Argus kararı.** HTTP-POST'ta assertion imzası zorunludur ve bu, tarayıcı çoklu oturum açmasının %99'u demektir. Varsayılan olarak hem Response hem Assertion imzalanır ve SP başına `sign_response` ile `sign_assertion` bayrakları sunulur; ikisini imzalamak hiçbir SP'yi kırmaz, tek imzalamak bazılarını kırar. Sıra kısıtı şudur: önce Assertion, sonra Response imzalanır; ters sıra Response imzasını geçersiz kılar, çünkü Response imzası Assertion'ı imzası dahil kapsar. Şifreleme varsa (SAMLCore §6.2) önce imzalanır sonra şifrelenir.

#### 1.2.4 2026'da kabul edilebilir algoritmalar

Otoriter kayıt RFC 9231'dir: "Additional XML Security URIs", Temmuz 2022, Standards Track, RFC 6931'i geçersiz kılar.

Özet algoritmaları şunlardır.

| Algoritma | URI |
|---|---|
| SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
| SHA-384 | `http://www.w3.org/2001/04/xmldsig-more#sha384` |
| SHA-512 | `http://www.w3.org/2001/04/xmlenc#sha512` |

> **Asimetrik isim alanı tuzağı.** SHA-256 ile SHA-512 `xmlenc#` altında, SHA-384 ise `xmldsig-more#` altındadır. Bu tarihsel bir tutarsızlıktır ve URI'yi elle yazan implementasyonlarda sık bir hata kaynağıdır. Argus'ta `const &str` sabitleri olarak tanımlanmalıdır.

İmza algoritmaları `xmldsig-more#rsa-sha256`, `-sha384` ile `-sha512`; RSASSA-PSS için `http://www.w3.org/2007/05/xmldsig-more#rsa-pss` ve `#sha256-rsa-MGF1` ailesi; ECDSA için `xmldsig-more#ecdsa-sha256`, `384` ile `512`; RFC 9231'in yeni getirdiği EdDSA için `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` ile `-ed448`'dir.

SHA-1'in 2026 durumu şöyledir. RFC 9231 bir URI kaydıdır, politika dokümanı değildir; SHA-1 için RFC 6194 değerlendirmesine yönlendirir ve formel bir yasak koymaz. NIST SP 800-131A'nın yürürlükteki sürümü Revision 2'dir ve Mart 2019 tarihlidir; Revision 3 hâlâ taslaktır, ilk kamuya açık taslağın yorum süresi 4 Aralık 2024'te kapanmıştır ve 8 Eylül 2026 itibarıyla final yayımlanmamıştır. Revision 3'ün SHA-1 için kesin tarihli yasak metni doğrulanamamıştır. Microsoft aynı doküman sayfasında hem `rsa-sha1`'in zorunlu olduğunu söylemekte hem SHA-1'i kullanımdan kaldırılmış ilan etmektedir; bu gerçek bir çelişkidir, 1.11.2'ye bakınız.

**Argus politikası.** Üretim varsayılanı `rsa-sha256` ile `sha256`'dır. Yapılandırmayla `rsa-sha384` ile `512` ve `ecdsa-sha256` ile `384` açılabilir. SHA-1 üretimi kod tabanına konmaz; istisnası M365 gibi eski hedefler için açıkça etkinleştirilen ve uyarı loglayan bir uyumluluk bayrağıdır. RSASSA-PSS ile Ed25519'un SP tarafı desteği pratikte yoktur; üretilmez, yalnızca tip sisteminde tanımlanır.

#### 1.2.5 `<ds:KeyInfo>` içeriği

Spesifikasyon opsiyonel bıraksa da pratikte her zaman `<ds:X509Data><ds:X509Certificate>` yazılır ve base64 DER kullanılır; çoğu SP kütüphanesi bunu bekler.

Zincir eklemek gereksizdir, çünkü Metadata Interoperability Profile PKIX yol doğrulamasını yasaklamaktadır, 1.10.3'e bakınız; yaprak sertifika yeterlidir. `<ds:KeyValue>` eklemek gereksizdir ve bazı SP'lerde metadata yerine KeyInfo'daki ham anahtara güvenme hatasını tetikleyebilir.

Güvenlik notu şudur: SP'ler imzayı metadata'daki sertifikaya karşı doğrulamalıdır, KeyInfo'dakine karşı değil. Argus bunu değiştiremez ancak dokümantasyonunda belirtmelidir: KeyInfo bir ipucudur, güven kaynağı değildir.

### 1.3 EncryptedAssertion

#### 1.3.1 Yapı, SAMLCore §2.3.4

```
<EncryptedAssertion>
├── xenc:EncryptedData   [REQUIRED]  @Type SHOULD = ...xmlenc#Element
└── xenc:EncryptedKey    [sıfır veya daha fazla]  @Recipient SHOULD (SAML entity URI)
```

> **En sık interop kırılma noktası.** Şema `<EncryptedKey>` öğesinin `<EncryptedData>` öğesinin kardeşi olmasına izin verir; XMLEnc ise `<EncryptedData>/<ds:KeyInfo>` içinde olmasına izin verir. Her iki yerleşim de gerçek dünyada kullanılmaktadır. Argus varsayılan olarak iç yerleşimi üretmeli, yani `EncryptedData/KeyInfo/EncryptedKey`, ve SP başına dışa taşıma seçeneği sunmalıdır.

#### 1.3.2 Algoritmalar, W3C XML Encryption 1.1

| Kategori | URI |
|---|---|
| AES-128, 192 ile 256 CBC | `http://www.w3.org/2001/04/xmlenc#aes{128,192,256}-cbc` |
| AES-128, 192 ile 256 GCM | `http://www.w3.org/2009/xmlenc11#aes{128,192,256}-gcm` |
| RSA v1.5, kullanılmaz | `http://www.w3.org/2001/04/xmlenc#rsa-1_5` |
| RSA-OAEP, eski, MGF1-SHA1 | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` |
| RSA-OAEP 1.1, açık MGF | `http://www.w3.org/2009/xmlenc11#rsa-oaep` |
| ECDH-ES | `http://www.w3.org/2009/xmlenc11#ECDH-ES` |
| ConcatKDF | `http://www.w3.org/2009/xmlenc11#ConcatKDF` |
| AES-KW | `http://www.w3.org/2001/04/xmlenc#kw-aes{128,192,256}` |

Spesifikasyonun kendi uyarısı XMLEnc 1.1 §5.1.1'dedir: "Use of AES GCM is strongly recommended over any CBC block encryption algorithms as recent advances in cryptanalysis have cast doubt on the ability of CBC block encryption algorithms to protect plain text when used with XML Encryption."

İlgili güvenlik bölümleri §6.9 "CBC Block Encryption Vulnerability" ile PKCS#1 v1.5 üzerine Bleichenbacher seçilmiş şifreli metin saldırısını anlatan §6.1.2'dir. Arka planı Jager ile Somorovsky'nin "How to Break XML Encryption" çalışmasıdır (ACM CCS 2011) ve XMLEnc 1.1'e GCM eklenmesinin doğrudan nedenidir. Makalenin tam metnine erişilememiştir, dolayısıyla kısmen doğrulanmamıştır; ancak W3C öneri metni iddiayı birincil kaynak olarak desteklemektedir.

**Argus politikası.** Varsayılan üretim `aes256-gcm` ile `xmlenc11#rsa-oaep` (MGF1-SHA256) olur. Uyumluluk yedeği `aes256-cbc` ile `rsa-oaep-mgf1p`'tir, çünkü çok sayıda eski SP kütüphanesi GCM ile XMLEnc11 OAEP'i tanımaz. `rsa-1_5` asla üretilmez ve kod tabanında bulunmaz. Algoritma seçimi SP metadata'sındaki `<md:KeyDescriptor use="encryption"><md:EncryptionMethod>` üzerinden yapılır; SAMLMeta §2.4.1.1 bu elemanı tam olarak bunun için tanımlar. ECDH-ES ile ConcatKDF'in gerçek dünyada SAML SP desteği pratikte yoktur ve implemente edilmez.

#### 1.3.3 Ne zaman gerekir

Spesifikasyon zorunlu kılmaz. Gerekçeleri SAMLCore §2.3.4'teki aracı senaryosu, SAMLSec §6.4.4'teki tarayıcı durumu ifşası (HTTP-POST'ta assertion tarayıcı geçmişinde veya diskte korumasız kalır) ile `<NameIDPolicy Format="...nameid-format:encrypted">` talebidir. Ayrıca §3.4.1.1 uyarınca IdP, politikası gerektiriyorsa formattan bağımsız olarak `<EncryptedID>` dönebilir.

Hangi SP'lerin şifreli assertion şart koştuğu doğrulanamamıştır. Bu araştırmada hiçbir satıcı dokümanında şifreli assertion zorunludur ifadesi doğrulanamamıştır. AWS şifrelemeyi opsiyonel bir yapılandırma olarak konumlandırmakta ve etkinleştirilirse ACS URL'inin `https://{region}.signin.aws.amazon.com/saml/acs/{IdP-ID}` biçimine dönüştüğünü belirtmektedir.

### 1.4 NameID formatları, SAMLCore §8.3

| Bölüm | Format | URI |
|---|---|---|
| 8.3.1 | Unspecified | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` |
| 8.3.2 | Email Address | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| 8.3.3 | X.509 Subject Name | `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName` |
| 8.3.4 | Windows Domain Qualified Name | `urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName` |
| 8.3.5 | Kerberos Principal | `urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos` |
| 8.3.6 | Entity Identifier | `urn:oasis:names:tc:SAML:2.0:nameid-format:entity` |
| 8.3.7 | Persistent | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| 8.3.8 | Transient | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` |
| §3.4.1.1 | Encrypted, yalnızca NameIDPolicy içinde | `urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted` |

> **Önek tuzağı.** unspecified, emailAddress, X509SubjectName ile WindowsDomainQualifiedName `SAML:1.1:` kullanır; kerberos, entity, persistent ile transient `SAML:2.0:` kullanır. URI'yi elle yazan implementasyonlarda en sık yapılan hatadır ve enum ile `const &str` olarak sabitlenmelidir.

`entity` formatı bir URI'dir, en fazla 1024 karakterdir ve "NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted" kuralına tabidir.

#### 1.4.1 Kalıcı tanımlayıcı, §8.3.7, en detaylı bölüm

> "Persistent name identifiers generated by identity providers MUST be constructed using pseudo-random values that have no discernible correspondence with the subject's actual identifier (for example, username). The intent is to create a non-public, pair-wise pseudonym to prevent the discovery of the subject's identity or activities."
>
> "Persistent name identifier values MUST NOT exceed a length of 256 characters."
>
> "they MUST NOT be shared in clear text with providers other than the providers that have established the shared identifier. Furthermore, they MUST NOT appear in log files or similar locations without appropriate controls and protections."
>
> "Deployments without such requirements are free to use other kinds of identifiers... but MUST NOT overload this format with persistent but non-opaque values."

Niteleyici semantiği şöyledir. `NameQualifier` tanımlayıcıyı üreten IdP'nin benzersiz kimliğidir ve bağlamdan türetilebiliyorsa atlanabilir; ancak tanımlayıcı başka bir varlık tarafından yeniden yayımlanırsa değişmez ve o durumda atlanamaz. `SPNameQualifier` kimin için üretildiğidir, yani SP veya bir birliktelik. `SPProvidedID`, SP'nin `ManageNameID` (§3.6) ile belirlediği alternatif kimliktir ve yoksa atlanmalıdır.

Çift taraflı tanımlayıcı hesaplamanın iki yolu vardır.

Birincisi saklanan rastgele değerdir; spesifikasyona en uygun olan ve önerilen budur:

```
pid = base64url(CSPRNG(32 byte))        # 43 karakter, 256 limitinin altında
DB: (user_id, sp_entity_id) → pid       # UNIQUE index
```

Gerçekten rastgeledir, kullanıcı silinince silinebilir, yani kişisel veri mevzuatına uygundur, ve IdP entity kimliği değişse bile stabil kalır.

İkincisi türetilmiş veya anahtarlı yoldur; durumsuzdur ancak dikkatli kullanılmalıdır:

```
pid = base64url(HMAC-SHA256(idp_secret, idp_entity_id ‖ sp_entity_id ‖ user_id))
```

`idp_secret` gizli olmalıdır, aksi hâlde ayırt edilebilir karşılık bulunmaması kuralı ihlal edilir, çünkü SP kullanıcı kimliğini tahmin ederek tanımlayıcıyı doğrulayabilir. Bu, Shibboleth'in hesaplanmış kimlik yaklaşımının modern hâlidir. Dezavantajı anahtar rotasyonunun tüm çift taraflı kimlikleri kırması ve `AllowCreate="false"` semantiğinin anlamsızlaşmasıdır.

Argus'ta birinci yol varsayılan, ikinci yol rotasyon uyarısıyla opsiyonel durumsuz moddur. Birliktelik gerekiyorsa anahtar `sp_entity_id` yerine `affiliation_id` üzerinden hesaplanır; `<md:AffiliationDescriptor>`, SAMLMeta §2.5.

> **Kalıcı NameID asla e-posta veya kullanıcı adıyla doldurulmaz.** Bu bir spesifikasyon ihlalidir. Kalıcı ama opak olmayan bir değer isteniyorsa `unspecified` veya `emailAddress` kullanılır.

#### 1.4.2 Geçici tanımlayıcı, §8.3.8

"SHOULD be treated as an opaque and temporary value... MUST be generated in accordance with the rules for SAML identifiers (§1.3.4), and MUST NOT exceed a length of 256 characters." Yani §1.3.4 entropi kuralları geçerlidir. Her oturum açmada değişir; tek noktadan çıkış için IdP'nin `SessionIndex` ile geçici NameID eşlemesini oturum boyunca saklaması gerekir.

#### 1.4.3 Kimlik üretimi, SAMLCore §1.3.4

> "the probability of two randomly chosen identifiers being identical MUST be less than or equal to 2^-128 and SHOULD be less than or equal to 2^-160."
>
> "Where a data object declares that it has a particular identifier, there MUST be exactly one such declaration."

Ayrıca `SubjectConfirmationData/@InResponseTo` tipi `xs:NCName`'dir, dolayısıyla kimlikler rakamla başlayamaz.

Argus kuralı şudur: kimlik, alt çizgi ile 160 bitlik, yani 20 baytlık, kriptografik rastgele çıktının onaltılık kodundan oluşur, yani alt çizgi artı 40 onaltılık karakter. Bu hem `NCName` kısıtını hem 2^-160 önerisini karşılar. UUIDv4 122 bittir ve zorunluluğu karşılar ancak öneriyi karşılamaz.

> Spesifikasyon, `xml:id` standartlaşınca ona geçilmesini planlamıştı; bu geçiş hiç olmamıştır. SAML'e özgü `ID` niteliklerinin DTD'siz belgelerde kimlik tipli olarak tanınmaması, XSW saldırılarının teknik zeminidir, 1.11.3'e bakınız.

### 1.5 AttributeStatement ve NameFormat

`<Attribute>` (§2.7.3.1) nitelikleri zorunlu `Name`, opsiyonel `NameFormat` (yoksa `...attrname-format:unspecified` yürürlüktedir) ile opsiyonel `FriendlyName`'dir. Spesifikasyon `FriendlyName` için şunu söyler: "This attribute's value MUST NOT be used as a basis for formally identifying SAML attributes."

| Bölüm | NameFormat | URI | Kısıt |
|---|---|---|---|
| 8.2.1 | Unspecified | `urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified` | Yorum implementasyona bırakılmıştır |
| 8.2.2 | URI Reference | `urn:oasis:names:tc:SAML:2.0:attrname-format:uri` | RFC 2396 URI referansıdır |
| 8.2.3 | Basic | `urn:oasis:names:tc:SAML:2.0:attrname-format:basic` | `Name` değeri `xs:Name` tipinden olmalıdır |

Argus'ta varsayılan `attrname-format:uri` ile OID veya URN tabanlı `Name`'dir; bu federasyon ile eduPerson uyumu içindir. SP başına geçersiz kılma zorunludur, çünkü birçok ticari SP `basic` bekler veya hiç NameFormat beklemez; Microsoft `Name="IDPEmail"` kullanır ve NameFormat vermez. `FriendlyName` her zaman doldurulur, bu hata ayıklama içindir, ancak SP eşleştirmesinde asla kullanılmaz.

**Çok değerli nitelikler ile boş ve null semantiği (§2.7.3.1, §2.7.3.1.1).** Her değer kendi `<AttributeValue>` öğesinde olmalıdır ve bu önerilir; birden fazla değerde `xsi:type` varsa hepsi aynı tipte olmalıdır. Nitelik var ancak hiç değeri yoksa `<AttributeValue>` atlanmalıdır ve `<Attribute>` boş kalır. Değer boş string ise `<AttributeValue/>` yazılır; bu, §1.3.1'deki en az bir boşluk olmayan karakter kuralını geçersiz kılar. Değer null ise hem boş eleman yazılır hem `xsi:nil="true"` konur.

**AttributeConsumingService (SAMLMeta §2.4.4.1 ile 2).** Zorunlu `index`, opsiyonel `isDefault`, bir veya daha fazla `<ServiceName>` (`xml:lang` gerekir), sıfır veya daha fazla `<ServiceDescription>` ile bir veya daha fazla `<RequestedAttribute>` (opsiyonel `isRequired`) taşır. SAMLProf §4.1.4.2 açıkça izin verir: "The identity provider MAY ignore this, or send other attributes at its discretion." Doğru davranış indeksi çözmek, `isRequired="true"` olanları karşılayamıyorsan hata dönmek veya loglamaktır. Nitelik paylaşım politikası her zaman IdP'nin kontrolünde kalmalıdır.

**OID ile WS-* iki ayrı dünyadır.** AWS dokümanından doğrulanan eduPerson OID'leri `urn:oid:1.3.6.1.4.1.5923.1.1.1.1` (`eduPersonAffiliation`), `.6` (`eduPersonPrincipalName`), `.9` (`eduPersonScopedAffiliation`), `.10` (`eduPersonTargetedID`), `.11` (`eduPersonAssurance`) ile `urn:oid:2.5.4.3` (`cn`) şeklindedir. Active Directory ile WS-* claim URI'leri `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/` altında `name`, `givenname`, `surname` ile `emailaddress`, ayrıca `http://schemas.xmlsoap.org/claims/CommonName` ile `http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid`'dir.

> Argus nitelik kataloğunda her iki aile de hazır sunulmalıdır. SP'ler ikiye bölünmüş durumdadır: araştırma ile eğitim federasyonları OID kullanmakta, kurumsal bulut yazılımları ise WS-* veya düz isim kullanmaktadır.

### 1.6 SP başlatmalı ile IdP başlatmalı akış

**Spesifikasyon konumu, SAMLProf §4.1.5 "Unsolicited Responses".**

> "An unsolicited `<Response>` MUST NOT contain an `InResponseTo` attribute, nor should any bearer `<SubjectConfirmationData>` elements contain one."
>
> "the `<Response>` or artifact SHOULD be delivered to the `<md:AssertionConsumerService>` endpoint of the service provider designated as the default."
>
> RelayState için: "the identity provider MAY include a binding-specific 'RelayState' parameter that indicates, based on mutual agreement with the service provider, how to handle subsequent interactions... This MAY be the URL of a resource at the service provider."

**IdP başlatmalı akış neden zayıftır.**

Birincisi `InResponseTo` olmadığı için istek ile yanıt arasında bağ yoktur; SP, bu assertion'ın kendi başlattığı bir akışa ait olduğunu doğrulayamaz.

İkincisi oturum açma CSRF'i mümkündür. Saldırgan, kurbanın tarayıcısına kendi geçerli IdP başlatmalı yanıtını POST ettirebilir ve kurban saldırganın hesabına giriş yapar. Sonrasında kurbanın yaptığı her şey, yani kart eklemesi veya doküman yüklemesi, saldırganın hesabına gider. SP'de CSRF token'ı veya state yoktur, çünkü akışı SP başlatmamıştır.

Üçüncüsü RelayState bir açık yönlendirmeye dönüşür. IdP başlatmalı akışta RelayState, SP'de gidilecek URL olarak yorumlanır. SP izin listesi uygulamazsa `RelayState=https://evil.com` klasik bir açık yönlendirme verir. SAMLSec §6.4.6 bunu RelayState kurcalama veya uydurma olarak saymakta ve şöyle demektedir: "Because the value of this element is both produced and consumed by the same system entity, symmetric cryptographic primitives could be utilized".

Dördüncüsü varsayılan ACS'e teslimdir; SP'nin birden çok ACS'i varsa yanlış olana gidebilir.

Beşincisi `ForceAuthn` ile `RequestedAuthnContext` olmamasıdır; SP kimlik doğrulama gücünü talep edemez.

**Kim zorunlu tutmaktadır.** AWS yönetim konsolu çoklu oturum açması fiilen IdP başlatmalıdır; AWS dokümanı akışı "IdP sends an authentication response to the AWS sign-in endpoint URL" olarak tarif etmekte ve `AuthnRequest`'ten söz etmemektedir. Microsoft Entra ile M365 SP başlatmalıdır; Entra `AuthnRequest` göndermektedir, 1.11.2'ye bakınız. Diğer büyük SP'lerin IdP başlatmalı zorunluluğu doğrulanamamıştır.

**Argus.** SP başlatmalı akış varsayılandır. Her SP yapılandırmasında `allow_idp_initiated: bool` bulunur ve varsayılanı false'tur. Açıkken RelayState HMAC'lenir veya opak bir tutamak yapılır; yalnızca `isDefault="true"` olan ACS'e gönderilir; assertion ömrü daha da kısaltılır; `InResponseTo` hiçbir yere yazılmaz, §4.1.5 bunu yasaklamaktadır.

### 1.7 Binding'ler

#### 1.7.1 HTTP-Redirect, §3.4

Kodlama tanımlayıcısı `urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE`'tir.

DEFLATE prosedürü §3.4.4.1'dedir.

1. Mesaj üzerindeki her imza, `<ds:Signature>` elemanının kendisi dahil, kaldırılmalıdır. Spesifikasyon ekler: "the length of such a message after encoding essentially precludes using this mechanism. Thus SAML protocol messages that contain signed content SHOULD NOT be encoded using this mechanism."
2. RFC 1951 DEFLATE kullanılır; bu ham deflate'tir ve zlib başlığı ile sağlama toplamı yoktur. Rust'ta `flate2::write::DeflateEncoder` kullanılır, `ZlibEncoder` kullanılmaz.
3. RFC 2045 base64 uygulanır ve satır sonu ile boşluk karakterleri kaldırılmalıdır.
4. URL kodlaması yapılır ve `SAMLRequest` ya da `SAMLResponse` parametresine konur.
5. RelayState varsa URL kodlanır ve `RelayState` parametresine konur.
6. Orijinal mesaj imzalıysa, kodlanmış veriyi kapsayan yeni bir imza eklenir.

> **İmzalanan sekizli dizisinin kurulumu (§3.4.4.1), Argus için en kritik detay.** `SigAlg` parametresi eklenir; sonra şu sırayla, her biri URL kodlanmış hâlde birleştirilir:
>
> ```
> SAMLRequest=value&RelayState=value&SigAlg=value
> SAMLResponse=value&RelayState=value&SigAlg=value
> ```
>
> "Any other content in the original query string is not included and not signed."
>
> Üç hayati incelik vardır. Birincisi imzalama sırası sabittir, yani önce `SAMLRequest` veya `SAMLResponse`, sonra `RelayState`, sonra `SigAlg`; ancak URL'deki gerçek parametre sırası serbesttir: "The parameters may appear in any order. Before verifying a signature... the relying party MUST ensure that the parameter values to be verified are ordered as required by the signing rules above." İkincisi değerler imzalanmadan önce URL kodlanır; doğrulama tarafı için spesifikasyon şunu söyler: "URL-encoding is not canonical... The relying party MUST therefore perform the verification step using the original URL-encoded values it received on the query string. It is not sufficient to re-encode the parameters after they have been processed by software." Üçüncüsü RelayState yoksa parametre tamamen atlanır: "if there is no RelayState value, the entire parameter should be omitted from the signature computation (and not included as an empty parameter name)." Yani `SAMLResponse=x&SigAlg=y` yazılır, boş `RelayState=` yazılmaz.

Diğer kurallar şunlardır. §3.4.5.2 der ki: "If the message is signed, the `Destination` XML attribute in the root SAML element MUST contain the URL to which the sender has instructed the user agent to deliver the message." Yani imzalı bir yönlendirme üretirken `Destination` zorunludur. HTTP durum kodu 302 veya 303 olmalıdır (§3.4.5). §3.4.5.1 uyarınca `Cache-Control: no-cache, no-store` ile `Pragma: no-cache` önerilir. §3.4.3 uyarınca RelayState 80 baytı aşmamalıdır ve bütünlük koruması önerilir: "Signing is not realistic given the space limitation." İsteğe eşlik eden RelayState yanıtta birebir geri konmalıdır. §3.4.6 uyarınca SAML işleme hataları HTTP hata durumuyla bildirilemez; `urn:oasis:names:tc:SAML:2.0:status:RequestDenied` kullanılır. §3.4.4.1'in beşinci maddesi 2005'te yalnızca `dsa-sha1` ile `rsa-sha1`'i zorunlu destek saymaktadır; 2026'da `rsa-sha256` kullanılır.

#### 1.7.2 HTTP-POST, §3.5

Base64 kullanılır ve DEFLATE uygulanmaz; gizli form kontrolleri `SAMLRequest` veya `SAMLResponse` ile `RelayState`'tir. İmza belgenin içindedir, yani XMLDSig'dir ve sorgu imzası yoktur. Tarayıcı çoklu oturum açmasının ana yolu budur.

#### 1.7.3 HTTP-Artifact

Yanıt yerine kısa bir artifact taşınır; SP `ArtifactResolve` ile SOAP arka kanalı üzerinden gerçek mesajı çeker. Avantajı assertion'ın tarayıcıdan hiç geçmemesidir. Dezavantajları bir SOAP endpoint'i, karşılıklı kimlik doğrulama ve IdP tarafında artifact'ten mesaja giden bir durum tutma gereğidir.

2026'da gerekli değildir; ticari SP'lerin ezici çoğunluğu HTTP-POST kullanmaktadır. Atlanabilirdir ve üçüncü faz ya da sonrasına bırakılır.

**Argus'un binding kararı.** Zorunlu olanlar yanıt teslimi için HTTP-POST ile `AuthnRequest` alımı ve tek noktadan çıkış için HTTP-Redirect'tir. Atlanabilir olanlar HTTP-Artifact, SOAP ile PAOS ve ECP'dir; ECP'nin istisnası şudur: Microsoft'un zengin istemcileri, yani Outlook ile IMAP, POP ve ActiveSync, için `$ecpUrl` gerekir ve ECP desteklenmezse yalnızca web istemcileri çalışır.

### 1.8 Tek noktadan çıkış

**Yapısal olarak neden kırıktır.** Aşağıdakiler spesifikasyon metninden çıkarılan yapısal nedenlerdir, satıcı beyanı değildir. Shibboleth'in bu konudaki meşhur resmî ifadesine bu araştırmada erişilememiştir ve doğrulanmamıştır.

Birincisi ön kanal ile üçüncü taraf çerez engellemesidir. Ön kanal tek noktadan çıkış, IdP'nin her SP'ye tarayıcı üzerinden, yani bir yönlendirme zinciri veya gizli çerçeveyle, `LogoutRequest` ulaştırmasını gerektirir. 2026'da Safari'nin izleme önleme mekanizması, Firefox'un toplam çerez koruması ile Chrome'un üçüncü taraf çerez kısıtları, çerçeve içindeki SP'nin kendi oturum çerezini görememesine yol açar; SP oturumu silemez ancak `Success` dönebilir. Bu sessiz bir başarısızlıktır.

İkincisi seri yönlendirme zincirinin kırılgan olmasıdır. N adet SP için N yönlendirme gerekir; biri yavaş veya ölü ise kullanıcı takılır. Spesifikasyonun `PartialLogout` durumu tam da bunu itiraf etmektedir.

Üçüncüsü SP'lerde oturum durumunun olmaması veya uyumsuz olmasıdır. Birçok bulut yazılımı SAML oturumunu kendi uzun ömürlü uygulama çerezine çevirir ve `SessionIndex` değerini saklamaz, dolayısıyla eşleşme yapamaz.

Dördüncüsü arka kanalın, yani SOAP'ın, çerezi çözememesidir. IdP, SP'ye SOAP ile `LogoutRequest` gönderse bile SP'nin kullanıcının tarayıcısındaki çerezi geçersizleştirmesi gerekir; bu ancak SP sunucu tarafında bir oturum kaydı tutuyorsa mümkündür. Ayrıca mTLS altyapısı gerekir.

Beşincisi IdP'deki durum yüküdür. Argus'un her kullanıcı oturumu için SP entity kimliği, NameID (formatı ve niteleyicileriyle), `SessionIndex`, tek noktadan çıkış endpoint'i ile binding'den oluşan bir liste tutması ve çıkış anında yürütmesi gerekir. Bu, IdP'yi durumsuz olmaktan çıkarır.

**Kim desteklemektedir.** Doğrulanan tek satıcı Microsoft Entra ile M365'tir: "Microsoft Entra ID uses HTTP POST for the authentication request to the identity provider and REDIRECT for the sign out message to the identity provider." Yapılandırmada `SignOutUri`, yani `$LogOffUrl`, `New-MgDomainFederationConfiguration` ile zorunlu verilir. Yani Entra, IdP'den HTTP-Redirect binding'inde bir tek noktadan çıkış endpoint'i beklemektedir.

Salesforce, ServiceNow, Workday, AWS IAM Identity Center, Google Workspace, Slack, Zoom ile Atlassian için durum doğrulanamamıştır. AWS notu şudur: IAM SAML assertion dokümanında tek noktadan çıkıştan hiç söz edilmemektedir ve AWS konsol oturumu `SessionDuration` ile `SessionNotOnOrAfter` üzerinden süre bazlı sonlanmaktadır. Bu, AWS'nin tek noktadan çıkış yerine oturum süresine dayandığına dair güçlü bir işarettir, ancak desteklenmediği ifadesi doğrulanmamıştır.

**Argus önerisi.** Tek noktadan çıkış implemente edilir ancak elden gelenin en iyisi olarak konumlandırılır ve bu dokümante edilir. `SessionIndex` her zaman üretilir, çünkü sonradan eklemek bir şema değişikliğidir. Oturum tablosu kullanıcı oturum kimliğinden SP entity kimliği, NameID (değeri, formatı ile niteleyicileri), `SessionIndex`, tek noktadan çıkış URL'i ve binding'inden oluşan bir listeye gider. Ön kanal varsayılandır ve `PartialLogout` durumu doğru dönülür. IdP'nin yerel çıkışı her zaman başarılı olmalıdır; SP'ye yayılım başarısız olsa bile kullanıcının IdP oturumu kapanır.

### 1.9 Zaman, saat kayması ve yeniden oynatma

**Spesifikasyon zemini ve SAMLSec §6.4.1 önerileri.**

> "The Identity Provider and Service Provider sites SHOULD make some reasonable effort to ensure that clock settings at both sites differ by at most a few minutes."
>
> "Values for NotBefore and NotOnOrAfter attributes of SSO assertions SHOULD have the shortest possible validity period... typically on the order of a few minutes."

**Yeniden oynatma kimin işidir.** SAMLProf §4.1.4.5 şöyle der: "The service provider MUST ensure that bearer assertions are not replayed, by maintaining the set of used ID values for the length of time for which the assertion would be considered valid."

> Bu bir SP yükümlülüğüdür, IdP'nin değil. Argus kendi ürettiği assertion kimliklerini yeniden oynatma için önbelleklemek zorunda değildir. Argus'un sorumluluğu kimliklerin çakışmaması (§1.3.4 entropisi) ile pencerelerin kısa olmasıdır. Argus'un kendi yeniden oynatma koruması gereken yer farklıdır: gelen `AuthnRequest` ile `LogoutRequest` kimlikleri.

**Önerilen pencere değerleri.**

| Alan | Değer | Gerekçe |
|---|---|---|
| `Response/@IssueInstant` ile `Assertion/@IssueInstant` | Şu an | — |
| `AuthnStatement/@AuthnInstant` | Gerçek kimlik doğrulama anı; oturum yeniden kullanımında şu andan farklıdır | Spesifikasyon semantiğidir |
| `Conditions/@NotBefore` | Şu an eksi 60 saniye | Karşı tarafın saat sapması payıdır |
| `Conditions/@NotOnOrAfter` | Şu an artı beş dakika | SAMLSec'in birkaç dakika ifadesidir |
| `SubjectConfirmationData/@NotOnOrAfter` | Şu an artı beş dakika | `Conditions` penceresinin içinde kalmalıdır, §2.4.1.2 önerisi |
| `SubjectConfirmationData/@NotBefore` | Yazılmaz | SAMLProf §4.1.4.2 bunu yasaklar |
| `AuthnStatement/@SessionNotOnOrAfter` | Şu an artı oturum ömrü, örneğin sekiz saat | SP'nin oturum sonlandırması içindir |
| Gelen mesajlarda kabul edilen saat kayması | Artı eksi üç dakika, yapılandırılabilir | — |

`<OneTimeUse>` için SAMLSec §6.4.4 önerir. Ancak SAMLCore §2.5.1.1'in üçüncü maddesi uyarınca anlaşılmayan bir koşul `Indeterminate` üretir ve reddedilmelidir; bazı SP'ler `<OneTimeUse>` öğesini anlamayıp assertion'ı reddeder. Bu gerçek bir risktir ve Argus'ta varsayılan kapalı, SP başına açılabilir olmalıdır.

Biçim SAMLCore §1.3.3'tedir ve UTC'dir. `YYYY-MM-DDTHH:MM:SSZ` üretilir; saat dilimi kayması, örneğin `+03:00`, kullanılmaz, çünkü bazı SP ayrıştırıcıları kırılır.

### 1.10 Metadata yönetimi, en çok kırılan yer

#### 1.10.1 `validUntil` ile `cacheDuration`

Bu iki nitelik `<EntitiesDescriptor>`, `<EntityDescriptor>` ile `RoleDescriptorType` seviyelerinde bulunur. `validUntil` "the expiration time of the metadata contained in the element and any contained elements" anlamına gelir. `cacheDuration` tüketicinin önbellekte tutabileceği azami süredir. §2.2.1 şunu söyler: "When used as the root element of a metadata instance, this element MUST contain either a validUntil or cacheDuration attribute."

Neden en çok kırılan yer olduğu dört başlıkta toplanır. `validUntil` geçince tüketici metadata'yı reddeder, federasyon aniden çöker ve hata mesajı genellikle anlaşılmazdır. `validUntil` iç içe elemanlara yayılır; `EntitiesDescriptor` seviyesindeki kısa bir değer içindeki tüm varlıkları düşürür. `cacheDuration` bir `xs:duration`'dır ve tüketiciler farklı yorumlar; bazıları `validUntil` ile asgarisini alır, bazıları yok sayar. Sertifika rotasyonuyla etkileşimi vardır: yeni sertifika metadata'ya konduktan sonra tüketicilerin `cacheDuration` veya `validUntil` kadar beklemesi gerekir, buna uyulmadan geçiş yapılırsa imzalar reddedilir.

Argus önerisi `validUntil` değerini şu an artı 14 gün, `cacheDuration` değerini `PT6H` yapmak ve metadata'yı otomatik yeniden imzalayıp yayımlayan bir zamanlanmış görev kurmaktır.

#### 1.10.2 İmzalı metadata, SAMLMeta §3

§3.1 "XML Signature Profile", SAMLCore §5.4'ün metadata karşılığıdır; aynı kısıtlar geçerlidir, yani enveloped imza, tek `Reference`, exc-c14n ile sınırlı dönüşümler. `<ds:Signature>` öğesi `<EntityDescriptor>` veya `<EntitiesDescriptor>` üzerine atılır.

#### 1.10.3 Metadata Interoperability Profile, güven modelinin kalbi

"SAML V2.0 Metadata Interoperability Profile Version 1.0", OASIS Standard, 24 Ekim 2019, docs.oasis-open.org/security/saml/Post2.0/sstc-metadata-iop.html.

Bu, çoğu geliştiricinin bilmediği ancak Argus'un implemente etmesi gereken güven modelidir.

> §2.6.1, PKIX yoktur: "consumers SHALL NOT apply any online or offline techniques including, but not limited to, X.509 path validation or revocation lists, OCSP responders, etc."
>
> §2.5.1, sertifika geçerliliği önemsizdir: "the certificate may be expired, not yet valid, carry critical or non-critical extensions or usage flags, and contain any subject or issuer."
>
> §2.5.1, her anahtar kendi tanımlayıcısında olur: "Each key included in a metadata role MUST be placed within its own `<md:KeyDescriptor>` element, with the appropriate use attribute."

Anlamı şudur: metadata'daki sertifika bir çıplak açık anahtar taşıyıcısıdır. Güven, sertifika zincirinden değil metadata'nın kendisinin güvenilir şekilde elde edilmiş olmasından gelir.

Bunun iki somut sonucu vardır. Argus'un imza sertifikasının süresi dolabilir ve bu profile uyan SP'lerde hiçbir şey kırılmaz; ancak uymayan SP'ler sertifika otoritesi doğrulaması yapar ve kırılır, ki bu "çoklu oturum açma bir sabah aniden bozuldu" vakalarının en yaygın nedenidir. Kendinden imzalı ve uzun ömürlü, örneğin on yıllık bir sertifika kullanmak SAML'da doğru pratiktir, kötü pratik değildir.

#### 1.10.4 Sertifika rotasyonu, doğru prosedür

`<KeyDescriptor use="signing">` çoklu olabilir; SAMLMeta §2.4.1.1 `maxOccurs="unbounded"` demektedir.

```
T0    : Metadata'ya YENİ sertifikayı EKLE (eski kalsın → iki adet use="signing").
        İmzalamaya hâlâ ESKİ anahtarla devam et.
T0+Δ  : Δ ≥ max(cacheDuration, tüm tüketicilerin yenileme periyodu). 14 gün güvenli.
T1    : İmzalamayı YENİ anahtara geçir. Metadata'da ikisi de durmaya devam etsin.
T1+Δ  : ESKİ sertifikayı metadata'dan kaldır.
```

> Bir anda hem imzalama anahtarını değiştirip hem metadata'yı güncellemek garantili bir kesintidir, çünkü tüketiciler metadata'yı önbelleğe almıştır. İki fazlı geçiş zorunludur.

Şifreleme anahtarında sıra terstir: Argus şifre çözmez, şifreler; dolayısıyla SP'nin şifreleme sertifikası rotasyonunu Argus takip etmelidir. Bu, metadata'yı düzenli yeniden çekerek ve her iki `use="encryption"` anahtarını da kabul ederek yapılır.

#### 1.10.5 MDQ, Metadata Query Protocol

Doküman `draft-young-md-query`'dir; editörü Ian A. Young'dır. Bu araştırmada görülen sürüm -18'dir ve 6 Ocak 2023 tarihlidir; sayfa en güncelinin -25 ve aktif olduğunu söylemektedir.

Statüsü internet taslağıdır ve IETF standartlar sürecinin parçası değildir; "product of REFEDS Working Group" olarak tanımlanmıştır.

URL yapısı eğik çizgiyle biten bir taban URL'e `"entities/"` ve yüzde kodlanmış tanımlayıcının eklenmesiyle oluşur. Eğik çizgi yüzde kodlanmalıdır ve boşluk `%20` olmalıdır.

Yaygın bilinen `entities/{sha1}<hex>` biçimi bu temel protokolde tanımlı değildir; "reserved for profile specifications" denmektedir. Ayrı bir SAML profil dokümanında tanımlıdır ve o dokümanın tam adı ile sürümü doğrulanamamıştır.

Önbellek için `ETag` zorunludur; değişmemişse sunucular 304 dönmelidir ve `Cache-Control: max-age` hem 200 hem 404 için önerilir. İmzalama protokol seviyesinde tanımlı değildir.

Kullanıcıları InCommon ile eduGAIN gibi araştırma ve eğitim federasyonlarıdır. Ticari bulut yazılımlarında MDQ kullanımı doğrulanamamıştır.

Argus için MDQ tüketicisi olmak birinci sürümde gereksizdir, çünkü ticari SP'ler metadata'yı dosya veya URL ile verir. MDQ sunucusu olmak yalnızca akademik bir federasyona girilecekse anlamlıdır ve üçüncü öncelik seviyesindedir.

### 1.11 Saldırılar, hangileri IdP'yi ilgilendirir

#### 1.11.1 Etki tablosu

| Saldırı | Etkilenen taraf | Argus için anlamı |
|---|---|---|
| XML Signature Wrapping, XSW1 ile XSW8 arası | SP, yani doğrulayıcı | Doğrudan etkilemez; ancak ürettiğimiz belge yapısı SP'nin direncini etkiler, 1.11.3'e bakınız |
| Ayrıştırıcı farkı, CVE-2025-25291 ile 25292 | SP | Argus SP tarafı doğrulama yaparsa, yani `AuthnRequest` imza kontrolünde, aynı sınıf hata Argus'ta da olabilir |
| Yorum kesme, CVE-2017-11427 ile 11428 | SP | Dolaylıdır; NameID değerlerinde yorum veya özel karakter üretmekle ilgilidir |
| XXE ile DTD varlık genişletmesi | Her ikisi | Argus doğrudan etkilenir, çünkü gelen `AuthnRequest` ile `LogoutRequest` ayrıştırılır |
| Açma bombası, CVE-2025-25293 ile CVE-2023-28119 | Her ikisi | Argus doğrudan etkilenir, çünkü HTTP-Redirect DEFLATE açar |
| RelayState açık yönlendirmesi | Her ikisi | Argus doğrudan etkilenir |
| ACS URL manipülasyonu | IdP | Argus'un birincil riskidir, SAMLProf §4.1.4.1 |
| Golden SAML, yani anahtar hırsızlığı | IdP | Argus'un varoluşsal riskidir, 1.11.4'e bakınız |
| XML şifrelemede CBC dolgu oracle'ı | SP, yani çözücü | Argus GCM seçerek SP'yi korur |
| Bleichenbacher, RSA 1.5 | SP, yani çözücü | Argus `rsa-1_5` üretmeyerek önler |

#### 1.11.2 Doğrulanan CVE'ler, NVD REST API'sinden birebir

| CVE | Ürün | Yayın | CVSS | Öz |
|---|---|---|---|---|
| CVE-2025-25291 ile 25292 | ruby-saml 1.12.4 ile 1.18.0 altı | 12 Mart 2025 | 9,8 kritik | "authentication bypass... due to a parser differential. ReXML and Nokogiri parse XML differently; the parsers can generate entirely different document structures from the same XML input. That allows an attacker to be able to execute a Signature Wrapping attack." |
| CVE-2025-25293 | ruby-saml | 12 Mart 2025 | 7,5 yüksek | "the message size is checked before inflation and not after", yani hizmet reddi |
| CVE-2024-45409 | ruby-saml 1.16.0 ve altı | 10 Eylül 2024 | 10,0 kritik | "An unauthenticated attacker with access to any signed saml document (by the IdP) can thus forge a SAML Response/Assertion with arbitrary contents." |
| CVE-2025-29774 ile 29775, SAMLStorm | xml-crypto 6.0.1, 3.2.1 ile 2.1.6 altı | 14 Mart 2025 | 9,3 | "modify a valid signed XML message in a way that still passes signature verification checks" |
| CVE-2017-11427 ile 11428 | python-saml 2.3.0 ve altı, ruby-saml 1.6.0 ve altı | 17 Nisan 2019 | 7,7 yüksek | "may incorrectly utilize the results of XML DOM traversal and canonicalization APIs in such a way that an attacker may be able to manipulate the SAML data without invalidating the cryptographic signature", US-CERT VU#475445 |
| CVE-2022-39299 | passport-saml | 12 Ekim 2022 | 7,4 | "requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks might also be feasible if generation of a signed message can be triggered." |
| CVE-2023-28119 | crewjam/saml, Go, 0.4.13 altı | 22 Mart 2023 | 7,5 | `flate.NewReader` girdi sınırı yoktur ve açma kaynaklı hizmet reddi doğar |
| CVE-2018-0489 | Shibboleth XMLTooling-C 1.6.4 altı | 27 Şubat 2018 | 6,5 | CVE-2018-0486'nın eksik düzeltmesidir |
| CVE-2025-23369 | GitHub Enterprise Server | 21 Ocak 2025 | 8,8 | İmza sahteciliğidir; SAML çoklu oturum açması kullanmayanlar etkilenmemiştir |
| CVE-2025-54419 | Node-SAML 5.0.1 ve altı | — | — | "loads the assertion from the unsigned original document rather than the verified signed portion" |
| CVE-2025-66578 | xmlseclibs, PHP, 3.1.4 altı | — | — | libxml2 kanonikleştirme kusurudur: geçersiz XML işlenirken boş string üzerine özet hesaplanmakta ve geçerli sayılmaktadır |

> **CVE-2022-39299'un cümlesi Argus'u doğrudan ilgilendirir:** "if generation of a signed message can be triggered". Argus, kimliği doğrulanmamış bir istekle imzalı bir artefakt üretmeye ikna edilebiliyorsa, yani imzalı hata yanıtları veya imzalı metadata üretiyorsa, zayıf SP'ler için saldırı yüzeyi sağlamış olur. İmzalı çıktı üretimi kimlik doğrulamasına bağlanmalıdır. Aynı şekilde CVE-2024-45409, IdP tarafından imzalanmış herhangi bir belgeyle sömürülebiliyordu; yani Argus'un ürettiği her imzalı artefakt, metadata dahil, bir saldırı girdisidir.

**Yorum kesme mekanizması.** Bu kısmen doğrulanmamıştır; Duo'nun orijinal teknik yazısı 8 Eylül 2026 itibarıyla erişilemez durumdadır ve aşağıdaki açıklama CVE metni temellidir. Yorumsuz C14N varyantı XML yorumlarını çıkarır ve imza geçerli kalır. Ancak DOM'dan metin çıkaran bazı API'ler yalnızca ilk metin düğümünü döner. `<NameID>admin@example.com<!----> .evil.com</NameID>` yapısında doğrulayıcı tam dizeyi görür, kimlik çıkaran kod ise `admin@example.com` alır. Düzeltmesi tüm metin düğümlerini birleştirmektir, yani `textContent` semantiğidir.

#### 1.11.3 XSW, IdP ne yapabilir

XSW'nin kök nedeni SAMLCore §5.4'te gizlidir: imza, `ID` niteliğine aynı belge içi referansla bağlanır. DTD veya şema olmadan XML ayrıştırıcıları bir niteliğin kimlik tipli olduğunu bilmez; belgede aynı kimliğe sahip iki eleman varsa hangisinin referans edildiği implementasyona bağlıdır. SAMLCore §1.3.4 bunu yasaklar ("there MUST be exactly one such declaration") ancak doğrulayıcının bunu zorlaması gerekir ve çoğu zorlamamıştır.

XSW1 ile XSW8 arası taksonominin birebir tanımları bu araştırmada birincil kaynaktan doğrulanamamıştır. Referansı Somorovsky ve arkadaşlarının "On Breaking SAML: Be Whoever You Want to Be" çalışmasıdır, USENIX Security 2012.

IdP tarafında yapılabilecekler dörttür.

1. Basit, tek assertion'lı ve tek imzalı belgeler üretilir. `<Advice>`, `<Extensions>` ile gereksiz `<Object>` kullanılmaz. Belge ne kadar düzse SP'nin yanlış eleman seçme ihtimali o kadar düşüktür.
2. Assertion ile Response birlikte imzalanır; saldırganın iki imzayı birden atlatması gerekir.
3. Kimlikler yüksek entropili olur (§1.4.3); tahmin veya çakışma yoluyla sarmalamayı zorlaştırır.
4. Argus'un kendi doğrulayıcısı için, yani `AuthnRequest` ile `LogoutRequest` imza kontrolünde, tek bir ayrıştırıcı kullanılır (ayrıştırıcı farkı olmaz), yinelenen kimlik reddedilir, DTD tamamen kapatılır ve imzalanan eleman ile veriyi okuduğun elemanın aynı nesne olduğu referans eşitliğiyle doğrulanır, yani XPath ile ikinci kez arama yapılmaz. Bu tam olarak CVE-2025-25291'in dersidir.

#### 1.11.4 Golden SAML, IdP'nin varoluşsal riski

SolarWinds ile Solorigate saldırısında kullanılan teknikte saldırgan ADFS sunucusunu ele geçirip assertion imzalama özel anahtarını çalmış ve istediği kullanıcı olarak istediği federe servise, yani AWS ile Office 365'e, kendi altın SAML token'larını üretmiştir. Kaynağı CISA Alert AA20-352A'dır.

> Bu, Argus'un tek gerçek varoluşsal riskidir. İmzalama anahtarı çalınırsa tüm federasyon çöker ve hiçbir SP bunu tespit edemez, çünkü imza geçerlidir. Savunması üç maddedir. İmzalama anahtarı HSM veya KMS'te durur ve süreç belleğinde uzun süre kalmaz; 1.13.2'de `kryptering`'in PKCS#11 desteğinin stratejik olmasının nedeni budur. Her imzalama işlemi denetim kaydına girer ve anormal hacim alarm üretir. Anahtar rotasyonu rutin olur (§1.10.4), böylece rotasyon bir acil durum prosedürü değil test edilmiş bir işlem olur.

#### 1.11.5 XXE ile hizmet reddi, Argus'un doğrudan sorumluluğu

Zorunlu sertleştirmeler şunlardır. DTD işleme tamamen kapatılır, yani `<!DOCTYPE` reddedilir; XXE, milyar kahkaha ile dış varlık saldırılarının hepsi burada biter. Dış varlık çözümlemesi kapalıdır ve ağ erişimi yoktur. Açma limiti konur: sıkıştırılmış boyut kontrolü yetmez, ki bu CVE-2025-25293'ün tam dersidir; açılmış bayt sayısı akış hâlinde sınırlanır, örneğin 1 MB sert tavan konur. Rust'ta bu `flate2::read::DeflateDecoder` üzerine `std::io::Read::take(limit)` uygulanarak yapılır. Sıkıştırma oranı kontrol edilir; açılan bölü sıkışık oranı 100'ü aşıyorsa reddedilir. Azami XML derinliği ile eleman sayısı sınırlanır. `quick-xml` gibi çekme ayrıştırıcıları bu limitleri uygulamak için doğru araçtır.

#### 1.11.6 SAML tasarım gereği güvensizdir tartışması

Argümanın özü şudur: XMLDSig belgenin bir alt kümesini imzalar ve hangi alt küme olduğunu belgenin kendisi, kimlik referansıyla, belirler. Bu, imza doğrulama ile veri okuma arasında bir ayrışma yaratır. Güvenli tasarım, imzanın tüm mesajı kapsaması ve doğrulanan baytların doğrudan tüketilmesidir; JWS ile JWT'nin yaptığı budur.

Argus için pratik sonuç şudur: bu yapısal zafiyet IdP olarak ortadan kaldırılamaz. Yapılabilecekler kendi doğrulayıcını doğru yazmak, basit belgeler üretmek ve mümkün olan yerde OIDC'yi tercih ettirmektir.

### 1.12 Büyük SP'lerin gereksinimleri

#### 1.12.1 AWS, IAM SAML federasyonu, tam doğrulanmıştır

Kaynağı docs.aws.amazon.com'daki `id_roles_providers_create_saml_assertions.html` sayfasıdır.

> "The response must include exactly one `SubjectConfirmation` element with a `SubjectConfirmationData` element that includes both the `NotOnOrAfter` attribute and a `Recipient` attribute. The Recipient attribute must include a value that matches the AWS sign-in endpoint URL."

Desteklenen NameID formatları persistent, transient, emailAddress, unspecified, X509SubjectName, WindowsDomainQualifiedName, kerberos ile entity'dir; bu tam listedir.

Endpoint'ler şöyledir: global olan `https://signin.aws.amazon.com/saml`; bölgesel olan `https://{region-code}.signin.aws.amazon.com/saml`; şifreleme varsa `https://{region-code}.signin.aws.amazon.com/saml/acs/{IdP-ID}`; `SessionDuration` için `https://signin.aws.amazon.com/static/saml` de kullanılabilir.

Nitelikler için `Name` değerleri büyük küçük harfe duyarlıdır ve birebir olmalıdır.

| Nitelik adı | Zorunlu | Değer |
|---|---|---|
| `https://aws.amazon.com/SAML/Attributes/Role` | Evet | `arn:aws:iam::<acct>:role/<role>,arn:aws:iam::<acct>:saml-provider/<provider>` biçiminde virgülle ayrılmış ARN çiftidir; çoklu değer verilirse kullanıcıya rol seçtirilir |
| `https://aws.amazon.com/SAML/Attributes/RoleSessionName` | Evet | 2 ile 64 karakter arası; alfanümerik ile `_ . , + = @ -` karakterleri. Boşluk yasaktır |
| `.../SessionDuration` | Hayır | Saniye cinsindendir, 900 ile 43200 arası. Yoksa bir saattir |
| `.../SourceIdentity` | Hayır | 2 ile 256 karakter arası; rol güven politikasında `sts:SetSourceIdentity` yoksa `AssumeRole` başarısız olur |
| `.../PrincipalTag:{TagKey}` | Hayır | Her etiket için ayrı bir `<Attribute>` verilir |
| `.../TransitiveTagKeys` | Hayır | Geçişli yapılacak etiket anahtarlarıdır |

Tuhaflıkları şunlardır. Doküman `Name` niteliğinin büyük küçük harfe duyarlı olduğunu ve tam olarak belirtilen değere ayarlanması gerektiğini üç kez tekrarlamaktadır. `SessionDuration` ile `SessionNotOnOrAfter` birlikte varsa küçük olan kazanır. `saml:aud` IAM koşul anahtarı SAML `Recipient` niteliğinden gelir, `Audience`'tan değil; IAM güven politikası yazanlar için kritik bir inceliktir. Konsol çoklu oturum açması IdP başlatmalıdır. Tek noktadan çıkış dokümanda hiç geçmemektedir ve doğrulanamamıştır.

#### 1.12.2 Microsoft Entra ID ile M365, SP rolünde, tam doğrulanmıştır

Kaynağı learn.microsoft.com'daki `how-to-connect-fed-saml-idp` sayfasıdır; sayfa tarihi 9 Nisan 2025, güncellemesi 26 Şubat 2026'dır. Senaryosu SAML 2.0 SP-Lite profilidir, yani üçüncü taraf IdP'den M365'e.

NameID formatı için doküman şöyle der: "Microsoft Entra ID currently supports the following NameID Format URI for SAML 2.0: `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`". Yani yalnızca kalıcı format desteklenmektedir.

NameID değeri için: "must be the same as the Microsoft Entra user's ImmutableID. It can be up to 64 alpha numeric characters. Any non-html safe characters must be encoded, for example a '+' character is shown as '.2B'."

Kullanıcı asıl adı taşıyıcısı için: "The User Principal Name (UPN) is listed in the SAML response as an element with the name IDPEmail".

```xml
<Attribute Name="IDPEmail"><AttributeValue>administrator@contoso.com</AttributeValue></Attribute>
```

Dikkat edilmelidir ki burada `NameFormat` niteliği yoktur ve `Name` düz bir dizedir, URI değildir. Bu, `attrname-format:uri` varsayan IdP'leri kırar.

Audience `urn:federation:MicrosoftOnline`, hedef ile alıcı `https://login.microsoftonline.com/login.srf`, Entra'nın issuer'ı ise yine `urn:federation:MicrosoftOnline`'dır.

İmza için dokümanın normatif listesi şudur: assertion düğümünün kendisi imzalanmalıdır; "The RSA-sha1 algorithm must be used as the DigestMethod. Other digital signature algorithms aren't accepted."; XML belgesi de imzalanabilir, yani Response imzası opsiyoneldir; dönüşümler enveloped-signature ile exc-c14n olmalıdır; `SignatureMethod` değeri `rsa-sha1` olmalıdır.

> Aynı sayfada şu da yazmaktadır: "Note: In order to improve the security SHA-1 algorithm is deprecated. Ensure to use a more secure algorithm like SHA-256." Doküman kendi içinde çelişkilidir. Argus yaklaşımı SHA-256 ile başlamak ve M365 federasyonu başarısız olursa SHA-1'e düşen SP'ye özel bir bayrak bulundurmaktır. Canlı test yapılmadan kesin karara bağlanmamalıdır.

Binding'ler için: "HTTPS is the required transport... Microsoft Entra ID requires HTTP POST for token submission... uses HTTP POST for the authentication request and REDIRECT for the sign out message."

`SessionIndex` örnekte assertion kimliğiyle aynıdır ve `AuthnContext` değeri `...ac:classes:PasswordProtectedTransport`'tur.

Entra'nın `AuthnRequest` mesajı minimaldir: yalnızca `Issuer` ile `NameIDPolicy Format="...persistent"` içerir. `Destination`, `AssertionConsumerServiceURL`, `ForceAuthn` ile `IsPassive` yoktur. İmzalı varyantta KeyInfo içinde `<ds:X509SKI>` ile `<ds:KeyName>MicrosoftOnline</ds:KeyName>` kullanılır, `X509Certificate` kullanılmaz.

> Doküman şunu söyler: "Microsoft Entra ID does not read metadata from the identity provider." Yani Argus'un metadata'sı Entra'ya işe yaramaz; sertifika elle verilir, `New-MgDomainFederationConfiguration -SigningCertificate` ile. Sertifika rotasyonu manuel ve kırılgandır; 1.10.4'teki otomatik prosedür Entra için geçersizdir.

Ayrıca: "Verify the clock on your SAML 2.0 identity provider server is synchronized to an accurate time source. An inaccurate clock time can cause federated logins to fail."

ECP ile PAOS endpoint'i, yani `$ecpUrl`, zengin istemciler için gereklidir; Outlook ile IMAP, POP ve ActiveSync bunlardandır. Desteklenmezse yalnızca web istemcileri çalışır.

#### 1.12.3 Google Workspace, kısmen doğrulanmıştır

Kaynağı knowledge.workspace.google.com'daki SSO assertion gereksinimleri sayfasıdır.

NameID formatı `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`'tir. NameID değeri kullanıcının birincil e-posta adresidir ve büyük küçük harfe duyarlıdır. ACS URL'i çoklu oturum açma profilinde `https://accounts.google.com/samlrp/<id>/acs`, eski profilde `https://www.google.com/a/<domain>/acs` veya `https://accounts.google.com/a/<domain>/acs`'tir. Eski profildeki entity kimliği `google.com` veya `google.com/a/<domain>`'dir. `Destination` opsiyoneldir ve ayarlanırsa ACS URL'iyle eşleşmelidir.

> Nitelik veri limiti serttir: "You can only pass a maximum of 2kB of attribute data in your assertions." Bu, nitelik paylaşım politikasında sert bir sınırdır.

Bu sayfada bulunmayan ve doğrulanamayan konular imza algoritması gereksinimi, sertifika ile anahtar boyutu, Response ile Assertion imzalama karşılaştırması, şifreli assertion ve tek noktadan çıkıştır.

#### 1.12.4 Diğerleri, doğrulanamamıştır

Salesforce, ServiceNow, Workday, AWS IAM Identity Center (klasik IAM SAML'dan ayrı bir üründür), Slack, Zoom ile Atlassian Cloud için bu araştırmada hiçbir NameID formatı, nitelik adı, imza yeri veya tek noktadan çıkış desteği doğrulanamamıştır. Salesforce'un yardım sitesi bir tek sayfa uygulamasıdır ve `articleView` URL'leri içerik döndürmemiştir; diğerleri erişilememiş veya müşteri girişinin arkasındadır.

> Bu yedi satıcı için gereksinim yazarken kendi bilginizden doldurmayın. Uydurulmuş bir nitelik adı, sessizce başarısız olan bir entegrasyon demektir. Ayrı bir doğrulama turu gerekir.

#### 1.12.5 Doğrulanabilenlerin karşılaştırması

| | NameID formatı | NameID değeri | İmza yeri | Şifreleme | Tek noktadan çıkış | SHA-1 |
|---|---|---|---|---|---|---|
| AWS, IAM SAML | Sekiz format kabul edilir | Serbesttir | POST kullanılırsa assertion imzalıdır | Opsiyoneldir ve ACS URL'i değişir | Doküman değinmemektedir | Belirtilmemiştir |
| Entra ile M365 | Yalnızca kalıcı | ImmutableID, en fazla 64 alfanümerik karakter | Assertion zorunludur, Response opsiyoneldir | Belirtilmemiştir | Evet, HTTP-Redirect ile | Doküman `rsa-sha1` demekte ancak SHA-1'i kullanımdan kaldırılmış ilan etmektedir, bu bir çelişkidir |
| Google Workspace | emailAddress | Birincil e-posta, harf duyarlıdır | Belirtilmemiştir | Belirtilmemiştir | Belirtilmemiştir | Belirtilmemiştir |

### 1.13 Rust ekosistemi, 2026'nın en önemli bulgusu

Tüm veriler crates.io REST API'sinden 8 Eylül 2026'da çekilmiştir.

#### 1.13.1 `samael`, mevcut fiilî standart

| | |
|---|---|
| Sürüm | 0.0.22, 7 Temmuz 2026 |
| İndirme | 689.252 toplam, 222.678 son 90 gün |
| Depo ile lisans | `github.com/njaremko/samael`, `master` dalı, MIT |
| Oluşturma | 23 Şubat 2020 |

README'den doğrulanan yetenekleri SAML mesajlarını serileştirme ile ayrıştırma, IdP başlatmalı çoklu oturum açma, SP başlatmalı akışta Redirect ile POST binding'i, assertion doğrulama yardımcıları, `AuthnRequest` imza doğrulaması ile imzalı Response üretimidir.

> "The `xmlsec` feature flag adds basic support for verifying and signing SAML messages. We're using a modified copy of rust-xmlsec library (bindings to xmlsec1 library)."

Gereken C kütüphaneleri `libiconv`, `libtool`, `libxml2`, `libxslt`, `libclang`, `openssl`, `pkg-config` ile `xmlsec1`'dir. Bağımlılık listesi bunu doğrulamaktadır: `bindgen ^0.72.1` derleme bağımlılığıdır ve opsiyonel değildir, ayrıca `pkg-config`, `openssl` ile `openssl-sys` ve tam sürümü sabitlenmiş `libxml =0.3.3` vardır.

Değerlendirmesi şudur. Saf Rust değildir; `xmlsec` özelliği olmadan imzalama yoktur, özellikle birlikte sekiz C kütüphanesinden oluşan bir derleme zinciri gelir, Docker imajı şişer, çapraz derleme ile `musl` statik binary zorlaşır ve tedarik zinciri yüzeyi büyür. Projenin `nix flake` ile derlenmesi, zincirin ne kadar can sıkıcı olduğunun itirafıdır. Şifreleme desteği zayıftır: yalnızca `aes128-cbc` ile `aes128-gcm` vardır, AES-256 yoktur ve bugün üretilmemesi gereken `rsa-1_5` desteklenmektedir. README "This is a work in progress" demektedir. Buna karşılık ekosistemin en çok indirilen ve en olgun seçeneğidir.

#### 1.13.2 `bergshamra` ile `gamlastan`, saf Rust XML güvenliği ve SAML yığını

Yazarı Kushal Das'tır (`github.com/kushaldas/`) ve lisansı BSD-2-Clause'tur.

**`bergshamra`, xmlsec1'in saf Rust muadili.**

| | |
|---|---|
| Sürüm | 0.9.0, 2 Eylül 2026 |
| İndirme | 62.096 toplam, 50.910 son 90 gün; `bergshamra-core` alt crate'i 164.393 ile 149.626 |
| Oluşturma | 22 Şubat 2026 |
| Sürüm temposu | 0.3.1 (Mart 6), 0.4.0 (Nisan 2), 0.5.x (Haziran 7), 0.6.x (Haziran 27 ile Temmuz 3), 0.7.0 (Temmuz 6), 0.8.0 (Ağustos 1), 0.9.0 (Eylül 2); çok aktiftir |

Workspace'i `bergshamra-core`, `-xml`, `-c14n`, `-crypto`, `-keys`, `-transforms`, `-dsig` ile `-enc` crate'lerinden oluşur ve hepsi v0.9.0'dır. Alt bağımlılıkları saf Rust XML ayrıştırıcısı, DOM'u, XPath'i ile XSD'si olan `uppsala ^0.10` ve `kryptering ^0.5.0`'dır.

Doğrulanan yetenekleri şunlardır. C14N tarafında "all 6 W3C C14N variants (inclusive/exclusive, with/without comments, 1.0/1.1) with document-subset filtering via XPath" denmektedir; yani exc-c14n dahildir ve düğüm kümesi semantiği vardır, ki 1.2.2'de zor olduğu söylenen tam olarak bu kısımdır. XML imzasında enveloped, enveloping ile detached biçimlerin hem imzalaması hem doğrulaması vardır. Algoritmaları RSA PKCS#1 v1.5, RSA-PSS, ECDSA (P-256, P-384 ile P-521), DSA, Ed25519, HMAC ile post kuantum ML-DSA (FIPS 204) ve SLH-DSA'dır (FIPS 205). XML şifrelemesinde eleman ile içerik şifrelemesi, anahtar sarmalama, anahtar taşıma ve çoklu alıcı desteklenir; AES-CBC ile GCM, AES-KW, RSA-OAEP, ECDH-ES ile X25519 vardır. Kripto sağlayıcısı seçilebilir: "Exactly one of `rustcrypto` or `aws-lc` is required" denmekte ve `fips` özelliği AWS-LC'yi seçmektedir. Saf Rust'tır, libxml2 ile xmlsec1 C bağımlılığı yoktur. Her workspace crate'inde `#![forbid(unsafe_code)]` vardır. XSW savunması olarak yinelenen kimlik reddi her zaman açıktır, ki 1.11.3'te istenen tam olarak budur.

> **Interop kanıtı.** "passes the full xmlsec interoperability test suite" denmektedir: şifrelemede 701 geçiş ve sıfır başarısızlık, imzada 447 geçiş ve sıfır başarısızlık, toplam 1148 geçiş, sıfır başarısızlık ve üç atlama vardır; atlananlar GOST imzalarıdır. W3C, Merlin, Aleksey, IAIK, NIST ile Phaos test vektörlerini kapsamaktadır. Bir Python ara katmanı, değiştirilmemiş xmlsec test betiklerini doğrudan `bergshamra`'ya karşı çalıştırmaktadır. Rust 1.88 gerekmektedir.

> **Sürüm tutarsızlığı.** README "Version 0.10.1 was released on August 02, 2026" demektedir, ancak crates.io'da `bergshamra` azami sürümü 0.9.0'dır; 0.10.x hiç yoktur ve tam sürüm listesi doğrulanmıştır. 0.10.1 muhtemelen `uppsala`'nın sürümüdür; uppsala v0.10.1, 2 Eylül 2026, doğrulanmıştır. crates.io esas alınmalıdır. Bu tutarsızlık projenin sürüm ve doküman disiplini hakkında bir uyarıdır.

**`gamlastan`, saf Rust SAML 2.0.**

| | |
|---|---|
| Sürüm | 0.9.0, 3 Eylül 2026 |
| İndirme | 15.518 toplam, 15.408 son 90 gün |
| Oluşturma | 8 Haziran 2026, yani üç aylıktır |
| GitHub | 6 yıldız, yaklaşık 138 commit |
| Lisans | BSD-2-Clause |

Bağımlılıkları `bergshamra` ile yedi alt crate'i, `uppsala`, `kryptering`, `chrono`, `flate2`, `rand`, `regex`, `md-5`, `bytes`, `thiserror` ile `base64`'tür. `libxml`, `xmlsec` ile `openssl-sys` yoktur; saf Rust zinciri doğrulanmıştır.

Yetenekleri "the full SAML 2.0 specification with errata corrections" ifadesiyle özetlenmektedir. IdP tarafında Response ile hata üretimi, SP tarafında `AuthnRequest` kurma ile Response işleme vardır. Binding'leri HTTP Redirect, POST, Artifact, SOAP ile PAOS'tur. Tek noktadan çıkış desteklenir. Metadata tarafında SPID uzantıları, önbellekleme ile doğrulama vardır. 35 kontrollü bir assertion doğrulayıcısı, yeniden oynatma önbelleği ile saat kayması yönetimi bulunur. Ulusal profillerden İtalyan SPID ile İsveç Sweden Connect desteklenir.

> **Uyum iddiası kanıt değildir.** README "passes the Italian SPID conformance test suite" demektedir, ancak bu kendi beyanıdır ve `italia/spid-saml-check` servis sağlayıcıları test eder, kimlik sağlayıcıları değil. Argus bir IdP olduğu için bu süit Argus'un ürettiği assertion'ları hiç doğrulamaz. IdP tarafı için ayrı bir depo vardır (`AgID/spid-saml-check-idp`) ancak olgunluğu çok düşüktür: dört yıldız, 51 commit ve Docker desteği yoktur. Ayrı bir `gamlastan-mdq` crate'i MDQ istemcisi sunmaktadır.

Uyarıları şunlardır: üç aylık bir crate'tir, 0.9.0 sürümündedir yani 1.0 öncesidir, altı GitHub yıldızı vardır yani benimsenmesi çok düşüktür, bağımsız bir güvenlik denetimi beyanı yoktur ve SPID ile Sweden Connect gibi ulusal profillere odaklıdır; genel ticari SP interop'u, yani Salesforce, AWS ile Entra tuhaflıkları, doğrulanmamıştır.

Destek crate'leri `uppsala` 0.10.1 (2 Eylül 2026, 176.007 indirme; saf Rust XML ayrıştırıcısı, DOM'u, isim alanı yönetimi, XPath'i ile XSD'si) ve `kryptering` 0.5.0'dır (23 Temmuz 2026, 145.067 indirme; "Cryptographic operations library with software (RustCrypto) and HSM (PKCS#11) backends").

> **`kryptering`'in PKCS#11 desteği stratejik olarak önemlidir.** Üretim IdP'sinin imzalama anahtarı HSM veya KMS'te durmalıdır (1.11.4'teki Golden SAML) ve bu, saf Rust yığınında bunu destekleyen görünürdeki tek yoldur.

#### 1.13.3 Diğer crate'ler ve ekosistem hijyeni

| Crate | Sürüm | Tarih | Toplam | 90 gün | Not |
|---|---|---|---|---|---|
| `quick-xml` | 0.42.0 | 22 Ağustos 2026 | 402.585.436 | 104.519.059 | Çekme ayrıştırıcısıdır ve sağlam bir seçimdir |
| `libxml` | 0.3.21 | 2 Ağustos 2026 | 2.159.264 | 494.908 | libxml2 sarmalayıcısıdır; 0.3.18 yanklanmıştır; C bağımlılığı vardır |
| `xmlsec` (voipir) | 0.3.0 | 12 Şubat 2026 | 88.659 | 1.584 | xmlsec1 bağlayıcısıdır. 90 günlük indirme çok düşüktür ve fiilen terk edilmiştir; 0.2.3'ten (2023) 0.3.0'a iki buçuk yıl geçmiştir |
| `rust-xmlsec` (as207960) | 1.0.0 | 19 Ekim 2021 | 27.906 | 5.722 | Saf Rust XMLSec iddiasındadır ancak beş yıldır tek sürümdedir; kullanılmaz |
| `xml_c14n` | 0.3.0 | 29 Kasım 2023 | 88.632 | 48.315 | libxml2 üzerine kuruludur, yani saf Rust değildir; üç yıldır güncelleme yoktur |
| `sxd-document` | 0.3.2 | 26 Mayıs 2019 | 2.771.111 | 570.314 | Yedi yıldır güncelleme yoktur; yeni proje için kullanılmaz |
| `saml` (danielkov) | 0.0.1-alpha.2 | 8 Ağustos 2026 | 1.132 | 995 | "no libxml2/xmlsec C build chain" iddiasındadır; çok erken alfadır, izlenir ancak kullanılmaz |
| `oxixml-c14n` | 0.1.2 | 10 Ağustos 2026 | 412 | 412 | Yenidir ve benimsenmesi düşüktür |
| `rsa` (RustCrypto) | 0.10.0-rc.18 | 27 Nisan 2026 | 215.298.115 | 49.432.738 | Hâlâ sürüm adayıdır; 0.10 stabil değildir |
| `saml2` | — | — | — | — | crates.io'da yoktur |

> **Ekosistem hijyeni uyarısı, isim işgali.** crates.io'da `opensaml` (0.5.0), `samlify` (0.5.0), `samlet` (0.5.0) ile `rustsaml` (0.5.0) crate'lerinin dördü de aynı sahibin (`salasebas`) `saml-rs` paketinin bakımlı uyumluluk yeniden dışa aktarımlarıdır ve hepsi `github.com/salasebas/saml-rs` deposunu göstermektedir. Aynı sahip `scim-rs`'i de yayımlamıştır. Tanıdık gelen bir isim görüldü diye bağımlılık alınmaz; crates.io'da `repository` alanı ile sahip her zaman kontrol edilir.

#### 1.13.4 Saf Rust'ta imza üretmek mümkün müdür

Evet, ve 2026'da artık sıfırdan yazmaya gerek yoktur.

| Seçenek | Artılar | Eksiler |
|---|---|---|
| A: `gamlastan` üzerine kurmak | Saf Rust'tır, tüm binding'ler, tek noktadan çıkış, metadata ile IdP tarafı Response üretimi vardır, XSW savunması yerleşiktir ve SPID uyum kanıtı sunulmaktadır | Üç aylık bir crate'tir, altı yıldızı vardır, denetimi yoktur, ticari SP interop'u kanıtlanmamıştır ve haftalık minor sürümler nedeniyle API kararlılık riski taşır |
| B: `bergshamra` üzerine kendi SAML katmanını yazmak, önerilen | Zor ve tehlikeli kısım, yani exc-c14n ile XMLDSig ve XMLEnc, devredilir; SAML alan modelini, yani Response, Assertion, NameID politikaları ile nitelik paylaşımını kendin yazarsın ve bu iş mantığıdır, dışarıdan gelmemelidir. Saf Rust avantajı korunur ve xmlsec interop süitini tam geçmesi güçlü bir olgunluk sinyalidir | `bergshamra` da gençtir, Şubat 2026'dandır; XML serileştirme için ayrıca `quick-xml` gerekir |
| C: `samael` ile `xmlsec` özelliği | 689 bin indirmesi vardır, 2020'den beri kullanılmaktadır ve savaşta test edilmiştir | Sekiz C kütüphanesi ve nix gerektiren bir derleme zinciri gelir, AES-256 şifrelemesi yoktur, `rsa-1_5` vardır; statik binary ile konteyner hedefleri için ciddi bir yüktür |

> **Tavsiye B seçeneğidir.** Geçiş sigortası olarak imzalama çağrıları tek bir trait arkasına konur:
>
> `trait XmlSigner { fn sign(&self, doc: &mut Document, ref_id: &str, key: &SigningKey) -> Result<()>; }`
>
> Böylece `bergshamra` beklentiyi karşılamazsa `samael` veya `xmlsec1`'e düşmek tek bir modül değişikliği olur. Bu, genç bir bağımlılığa girmenin bedelini sınırlar.

exc-c14n'i sıfırdan yazmak sorusuna cevap şudur: algoritma yaklaşık 500 ile 800 satırdır ve yapılabilir, ancak asıl zorluk doküman alt kümesi ile düğüm kümesi semantiğidir; buradaki hata ya sessiz bir imza uyumsuzluğu ya da XSW'ye açık bir doğrulayıcı üretir. Yazılmamalıdır.

### 1.14 SAML sınıflandırması ve aksiyon listesi

**Zorunlu, faz 1.** SP başlatmalı tarayıcı çoklu oturum açması; HTTP-POST ile HTTP-Redirect binding'i; assertion imzalama (`rsa-sha256`, exc-c14n, enveloped ve tek `Reference`); IdP metadata yayını; SP metadata tüketimi ile ACS doğrulaması; kalıcı, geçici ile e-posta adresi NameID formatları; `AttributeStatement`; `SessionIndex` üretimi; DTD kapalı ve sertleştirilmiş XML ayrıştırma; açma limiti.

**Opsiyonel, faz 2.** EncryptedAssertion (AES-256-GCM ile RSA-OAEP); IdP başlatmalı akış, varsayılan kapalı ve HMAC'li RelayState ile; imzalı metadata; tek noktadan çıkış, ön kanal ve elden gelenin en iyisi olarak; ECDSA imzalar; çift taraflı tanımlayıcının durumsuz modu; SP başına açılan `<OneTimeUse>`.

**Atlanabilir.** HTTP-Artifact binding'i; ArtifactResolve ile SOAP; MDQ sunucusu; Microsoft zengin istemcileri gerekmiyorsa ECP ile PAOS; holder-of-key; NameIDMapping; SAML proxy'leme; SAML 1.1; WS-Federation.

**Yapılmazsa güvenlik açığı doğuran sıfırıncı öncelikli aksiyonlar.**

1. `AssertionConsumerServiceURL` ile `Index` her zaman SP metadata'sına karşı doğrulanır, SAMLProf §4.1.4.1.
2. Kimlik üretimi alt çizgi artı 160 bitlik kriptografik rastgele onaltılık değerdir; SAMLCore §1.3.4 ile `NCName` kısıtı içindir.
3. Gelen XML'de DTD tamamen kapalıdır ve açma için akış hâlinde boyut limiti konur, CVE-2025-25293.
4. Kendi doğrulayıcında tek ayrıştırıcı kullanılır, yinelenen kimlik reddedilir ve imzalanan eleman ile okunan elemanın referans eşitliği doğrulanır; CVE-2025-25291 dersidir.
5. RelayState HMAC'lenir veya opak bir tutamak yapılır; IdP başlatmalı akışta izin listesi uygulanır.
6. `SubjectConfirmationData` öğesine `NotBefore` yazılmaz.
7. İmzalama anahtarı HSM veya KMS'te tutulur ve her imzalama denetim kaydına yazılır; Golden SAML içindir.
8. İmzalı çıktı üretimi kimlik doğrulamasına bağlanır, CVE-2022-39299.

**Interop için sıfırıncı öncelikli aksiyonlar.**

9. Assertion şema sırası `Issuer`, `Signature`, `Subject`, `Conditions`, `Advice` ile ifadeler şeklindedir.
10. Önce Assertion, sonra Response imzalanır ve varsayılan olarak ikisi de imzalanır.
11. `rsa-sha256` ile `sha256` kullanılır; SHA-1 yalnızca açık bir eski uyumluluk bayrağıyla kullanılır.
12. exc-c14n ile enveloped-signature dönüşümü kullanılır ve tek bir `<ds:Reference URI="#id">` bulunur.
13. HTTP-Redirect imza dizesi `SAMLRequest` veya `SAMLResponse`, sonra varsa `RelayState`, sonra `SigAlg` sırasındadır ve her biri URL kodludur; RelayState yoksa tamamen atlanır.
14. İmzalı yönlendirme mesajlarında `Destination` zorunludur.
15. `SessionIndex` her zaman üretilir.
16. Zaman damgaları `Z` sonekli UTC'dir ve `Conditions` penceresi eksi 60 saniye ile artı beş dakikadır.

**Birinci öncelikli aksiyonlar.**

17. Metadata'da `validUntil` ile `cacheDuration` kullanılır ve sertifika rotasyonu iki fazlı yapılır, yani çoklu `KeyDescriptor use="signing"` ile. Entra için bu geçersizdir ve manuel bir prosedür yazılmalıdır.
18. `aes256-gcm` ile `xmlenc11#rsa-oaep` kullanılır; `rsa-1_5` asla kullanılmaz.
19. `<OneTimeUse>` varsayılan olarak kapalıdır.
20. Tek noktadan çıkış elden gelenin en iyisi olarak yapılır ve `PartialLogout` durumu dönülür.
21. Kripto arka ucu `XmlSigner` trait'iyle soyutlanır.

### 1.15 SAML efor tahmini

| İş kalemi | Tahmin |
|---|---|
| Kripto arka ucu araştırması (bergshamra ile samael kararı) ve `XmlSigner` soyutlaması | 2 hafta |
| SAML alan modeli ile serileştirme (şema sırası, isim alanları) | 2,5 hafta |
| `AuthnRequest` işleme, ACS doğrulaması, NameIDPolicy ile Scoping | 1,5 hafta |
| Response ile Assertion üretimi ve imzalama sırası | 2 hafta |
| NameID politikaları (kalıcı, geçici, çift taraflı) ile nitelik paylaşım motoru | 2 hafta |
| HTTP-Redirect binding'i (DEFLATE ile imza dizesi) ve HTTP-POST | 1,5 hafta |
| Metadata üretimi ile tüketimi ve sertifika rotasyonu prosedürü | 2 hafta |
| Sertleştirme (DTD, açma limiti, RelayState HMAC'i, denetim) | 1 hafta |
| Gerçek SP interop testleri (AWS, Entra, Google ve iki tanesi daha) | 2 ile 3 hafta |
| Faz 1 toplamı | Yaklaşık 14 ile 16 hafta, tek mühendis |
| Faz 2 (EncryptedAssertion, tek noktadan çıkış, imzalı metadata, IdP başlatmalı akış) | Ek 8 hafta |

---

## Bölüm 2 — SCIM 2.0, sunucu tarafı

### 2.1 İlk düzeltme: SCIM artık üç RFC değil altı RFC'dir

Brief'teki "RFC 9967 SCIM Events" ifadesi kısmen yanlıştır. Doğrulanan gerçek şudur.

| RFC | Tam başlık | Tarih | Durum |
|---|---|---|---|
| 7642 | SCIM: Definitions, Overview, Concepts, and Requirements | Eylül 2015 | Informational |
| 7643 | SCIM: Core Schema | Eylül 2015 | Standards Track; 9865 ile 9967 tarafından güncellenmiştir |
| 7644 | SCIM: Protocol | Eylül 2015 | Standards Track; 9865 ile 9967 tarafından güncellenmiştir |
| 9865 | Cursor-Based Pagination of SCIM Resources | Ekim 2025 | Standards Track; 7643 ile 7644'ü günceller |
| 9944 | Device Schema Extensions to the SCIM Model | Mayıs 2026 | Standards Track |
| 9967 | SCIM Profile for Security Event Tokens (SETs) | Mayıs 2026 | Standards Track; 7643 ile 7644'ü günceller. Yazarları P. Hunt (editör), N. Cam-Winget (Cisco), M. Kiser (SailPoint) ile J. Schreiber'dır (Workday) |

> **Düzeltme.** RFC 9967'nin adı SCIM Events değil "SCIM Profile for Security Event Tokens (SETs)"tir. Olay sözlüğünü tanımlar, olay akışı yönetimini tanımlamaz; o iş OpenID SSF'e bırakılmıştır, 2.9'a bakınız. Kaynakları rfc-editor.org/rfc/rfc9967.txt ile datatracker.ietf.org/wg/scim/documents'tır, erişim 8 Eylül 2026.

Argus için anlamı şudur: 2015 SCIM'ini implemente etmek artık yetersizdir. Sayfalama (9865) ile olay yayını (9967) yeni taban çizgisidir.

### 2.2 Endpoint ve metot matrisi, RFC 7644 §3.2, tablo 2

| Kaynak | Endpoint | Metotlar | Argus sınıflandırması |
|---|---|---|---|
| User | `/Users` | GET, POST, PUT, PATCH, DELETE | Zorunludur |
| Group | `/Groups` | GET, POST, PUT, PATCH, DELETE | Zorunludur |
| ServiceProviderConfig | `/ServiceProviderConfig` | GET | Zorunludur; `/ServiceProviderConfigs` takma adıyla birlikte, 2.10'a bakınız |
| ResourceType | `/ResourceTypes` | GET | Zorunludur; Entra sağlama yapılandırmasında okur |
| Schema | `/Schemas` | GET | Zorunludur; Entra açıkça şart koşmaktadır |
| Self | `/Me` | GET, POST, PUT, PATCH, DELETE, §3.11 | Opsiyoneldir; üç meşru davranış vardır: 501 dönmek, gerçek kaynağa 308 ile yönlendirmek veya doğrudan işlemek |
| Bulk | `/Bulk` | POST | Birinci fazda atlanabilir; Entra açıkça "we don't support the /Bulk endpoint today" demektedir |
| Search | `[prefix]/.search` | POST | Opsiyoneldir; uzun filtreleri URL'e sığdırma sorununu çözer ve kişisel veriyi URL'den çıkarır |

Normatif seviyelerde sürpriz şudur: PUT zorunludur, §3.5 "Implementers MUST support HTTP PUT" der; PATCH ise önerilir, "Resources such as Groups may be very large; hence, implementers SHOULD support HTTP PATCH" denmektedir. Filtreleme, sıralama, toplu işlem, ETag ile `/Me` opsiyoneldir. `attributes` ile `excludedAttributes` için §3.4.2.5 şöyle der: "OPTIONAL parameters, which MUST be supported by SCIM service providers"; yani istemci için opsiyonel, sunucu için zorunludur.

> Ancak gerçek dünya spesifikasyonu ezmektedir: Entra ile Okta pratikte PATCH'i zorunlu kılmaktadır. PATCH sona bırakılmaz, ilk yazılır.

PUT asla kaynak yaratmaz, §3.2.

### 2.3 Veri modeli, RFC 7643 çekirdek şeması

**Nitelik karakteristikleri (§2.2) ve belirtilmediğindeki varsayılanları.** `required` false, `canonicalValues` yok, `caseExact` false, `mutability` `readWrite`, `returned` `default`, `uniqueness` `none` ile `type` `string`'dir. Tam küme `required`, `canonicalValues`, `caseExact`, `mutability`, `returned`, `uniqueness` ile `referenceTypes`'tır.

**Rust veri modelini belirleyen tek kural** §2.3.8'dedir: bir karmaşık nitelik, kendisi karmaşık olan bir alt nitelik içeremez; yalnızca tek seviye vardır. Bu, `enum ScimValue` tasarımının tamamını sabitler ve özyinelemeli iç içe geçme yoktur.

Veri tipleri (§2.3) `string`, `boolean`, `decimal`, `integer`, `dateTime` (xsd:dateTime; tarih ve saat zorunludur), `binary` (base64 ve harf duyarlıdır), `reference` (harf duyarlıdır ve `referenceTypes` taşır) ile `complex`'tir.

**Çok değerli nitelikler (§2.4 ile 2.5).** Varsayılan alt nitelikleri `type`, `primary` (boolean; `true` en fazla bir kez görünebilir), `display` (değişmezdir), `value` ile `$ref`'tir. §2.5 uyarınca atanmamış, `null` ve boş dizi durum olarak eşdeğerdir.

**Ortak nitelikler (§3.1).**

| Nitelik | caseExact | mutability | returned | Kritik not |
|---|---|---|---|---|
| `id` | true | readOnly | always | Sunucu atar; kararlı ve yeniden atanamaz olmalıdır; tüm kaynak tipleri arasında benzersizdir; istemci göndermemelidir; `"bulkId"` dizesi rezervedir ve hiçbir kimlikte geçemez |
| `externalId` | true | readWrite | default | İstemci atar; sunucu benzersizlik dayatmaz |
| `meta` | — | readOnly | default | İstemci gönderirse yok sayılmalıdır |

`meta` alt nitelikleri `resourceType`, `created`, `lastModified` (hiç değişmediyse `created` ile aynıdır), `location` (`Content-Location` başlığına eşit olmalıdır) ile `version`'dır (ETag başlığına eşit olmalıdır; güçlü doğrulayıcı değilse `W/` öneki zorunludur ve büyük küçük harfe duyarlıdır).

**Uygulanması zorunlu errata.** RFC'nin §8.7.1'deki normatif JSON şeması hatalıdır ve Argus'un şema kaydına düzeltilmiş hâli girmelidir.

| Errata | Durum | Düzeltme |
|---|---|---|
| 5368 | Doğrulanmıştır | `Group.displayName` için `required` true olmalıdır; RFC'de yanlışlıkla false'tur |
| 5606 | Doğrulanmıştır | `Schema.attributes.type` kanonik değerlerine `binary` eklenmelidir |
| 5607 | Doğrulanmıştır | `Schema.attributes.referenceTypes` için `multiValued: true` olmalıdır |
| 6004 | Doğrulanmıştır | `name`, `emails` ile `addresses` karmaşık nitelikleri `uniqueness` taşımamalıdır; §2.3.8 ile çelişmektedir |
| 7522 | Doğrulanmıştır | `ResourceType.schemaExtensions` için `multiValued: true` olmalıdır |
| 8415 | Doğrulanmıştır | `subAttributes.type` kanonik değerlerine de `binary` eklenmelidir |
| 8361 | Doğrulanmıştır | §3.1 metni `/ServiceProviderConfig` ile `/ResourceTypes` demelidir |

Normatif JSON'daki sessiz eksikler, yani errataya girmemiş ancak gerçek olanlar şunlardır. `ims.type` kanonik değerlerinde `other` yoktur, oysa §4.1.2 düzyazısı listelemektedir. `addresses` içinde `.primary` alt niteliği yoktur, oysa diğer tüm çok değerli niteliklerde vardır. `Group.members` içinde `.display` yoktur, ancak RFC 7644 §3.5.2'nin kendi PATCH örnekleri `display` göndermektedir; kabul edilir, reddedilmez. `Group.members` alt niteliklerinden `value`, `$ref` ile `type` değişmezdir.

### 2.4 PATCH semantiği, §3.5.2, işin en zor %40'ı

**Zarf.** `schemas` değeri `["urn:ietf:params:scim:api:messages:2.0:PatchOp"]`'tur. `Operations` dizisi en az bir eleman içerir. Her operasyon tam olarak bir `op` üyesi taşır: `add`, `remove` veya `replace`. `path` alanı add ile replace için opsiyonel, remove için zorunludur.

```
PATH = attrPath / valuePath [subAttr]          (Şekil 7)
```

Geçerli yol örnekleri (şekil 8) `members`, `name.familyName`, `addresses[type eq "work"]`, `members[value eq "…"]` ile `members[value eq "…"].displayName`'dir.

**Sıra, atomiklik ve `schemas`.** Operasyonlar sırayla uygulanır ve her operasyonun çıktısı bir sonrakinin girdisidir. "A PATCH request, regardless of the number of operations, SHALL be treated as atomic." Herhangi bir hatada orijinal kaynak geri yüklenmelidir; Rust'ta bu, bir klon üzerine uygulamak veya bir işlem içinde çalışıp sonda kesinleştirmekle yapılır. Bir operasyon `schemas` değerini değiştirirse sonraki operasyonlar değişmiş durumu görür. Tam nitelikli bir uzantı niteliği eklemek, örneğin `urn:…:enterprise:2.0:User:employeeNumber`, uzantı URN'ini `schemas` listesine örtük olarak ekler. İstemci `readOnly` veya `immutable` bir niteliği değiştiremez, ancak önceki değeri olmayan bir `immutable` niteliğe ekleme yapabilir. `primary` kuralı şudur: bir değerin `primary` alanını `true` yapmak, sunucunun aynı dizideki diğer tüm değerlerin `primary` alanını otomatik olarak `false` yapmasına sebep olmalıdır. Yanıt 200 ile tam kaynak veya 204 olur; istekte `attributes` varsa sunucu 200 dönmek zorundadır.

**`add` (§3.5.2.1) sıralı kural listesi.**

1. `path` yoksa hedef kaynağın kendisidir ve `value` eklenecek nitelikler nesnesidir.
2. Hedef yoksa nitelik ile değer eklenir.
3. Hedef karmaşıksa `value` bir alt nitelik kümesi olmalıdır.
4. Hedef çok değerliyse yeni değer eklenir, yani sona iliştirilir.
5. Hedef tek değerliyse mevcut değer değiştirilir.
6. Hedef varsa değer değiştirilir.
7. Hedef zaten bu değeri içeriyorsa değişiklik yapılmamalı, başarı dönmeli ve `lastModified` değişmemelidir.

> Yedinci kural sıradan görünür ancak kritiktir: Entra ile Okta grup üyeliğini periyodik olarak yeniden gönderir. `lastModified` her seferinde güncellenirse sonsuz bir senkronizasyon döngüsü ve gereksiz bir olay fırtınası üretilir.

**`remove` (§3.5.2.2).** `path` yoksa 400 ile `scimType: noTarget` dönülür; dikkat edilmelidir ki bu `invalidPath` değildir. Tek değerliyse nitelik kaldırılır. Çok değerli ve filtresizse nitelik ile tüm değerleri kaldırılır. Çok değerli ve değer filtresi varsa eşleşenler kaldırılır; hiç değer kalmazsa nitelik atanmamış olur. `required` veya `readOnly` bir nitelik atanmamış hâle gelirse `scimType: mutability` hatası dönülür. Grupta olmayan bir üyeyi kaldırmak bir başarıdır, hata değildir: "If the user was not a member of this group, no changes should be made to the resource, and a success response should be returned."

**`replace` (§3.5.2.3).** `path` yoksa hedef kaynaktır ve `value` değiştirilecek nitelik listesidir. Tek değerliyse değiştirilir. Çok değerli ve filtresizse nitelik ile tüm değerleri toptan değiştirilir. Hedef yol yoksa sunucu bunu bir ekleme olarak işlemelidir. Karmaşık hedefte `value` içindeki alt nitelikler değiştirilir veya eklenir ve belirtilmeyen alt nitelikler değişmeden kalır; bu bir birleştirmedir, toptan değiştirme değildir. Çok değerli ve değer yolu en az bir eşleşme veriyorsa eşleşen tüm kayıtlar değiştirilir. Çok değerli ve değer yolu hiç eşleşmiyorsa 400 ile `scimType: noTarget` dönülür.

> **Asimetri ezberlenmelidir:** filtresi hiçbir şeyle eşleşmeyen bir `replace` hatadır; olmayan bir üyeyi silen bir `remove` başarıdır.

**RFC'nin gerçekten belirsiz bıraktığı yerler.**

Birincisi değer yolu filtresiyle ekleme yapmaktır, örneğin `"op":"add","path":"emails[type eq \"work\"].value"`. §3.5.2.1'in kural listesinde bu hiç yoktur. Errata 8097 (doküman güncellemesi için beklemede, 8 Eylül 2024, Siqing Zheng) tam olarak bunu belgelemektedir: "Looks Microsoft Azure had a different understanding about the patch 'add' operation… Microsoft Azure expects to add a new email with value 'example@email.com' and type 'work'." Alan direktörü bunu gelecek çalışma için kabul etmiştir. Argus bunu implemente etmelidir: değer yolu ile alt nitelik kullanan bir eklemede hiçbir şey eşleşmiyorsa, filtrenin `eq` yan tümcelerinden tohumlanmış yeni bir karmaşık değer yaratılmalıdır.

İkincisi filtresiz çok değerli `replace`'tir; spesifikasyon hepsini değiştir der, birçok istemci ise tipe göre ekle veya güncelle kasteder. Spesifikasyona uyulur ancak gürültülü loglanır.

Üçüncüsü hem `path` hem `value` içeren `remove`'dur; ABNF'te hiç yoktur ve Entra'nın uyumsuz modu bunu üretmektedir, 2.8'e bakınız.

Dördüncüsü yol ABNF'inin basit çok değerli bir nitelik üzerinde filtre ifade edememesidir. Errata 7122 (beklemede) `PATH = attrPath / valuePath [subAttr] / attrExp` önerisiyle bunu düzeltmeye çalışmaktadır; hoşgörülü kabul edilmelidir.

### 2.5 Filtre dili, §3.4.2.2

**Yayımlanan ABNF.**

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

> **Tutarsızlık.** RFC 7643 §2.1'in `nameChar` tanımı dolar işaretini içerir, bu yüzden `$ref` yazılabilir; RFC 7644 §3.4.2.2'ninki içermez. Bu gerçek bir tutarsızlıktır ve ayrıştırıcının dolar işaretini kabul etmesi gerekir.

**Düzeltilmesi gereken ABNF kusurları**, hepsi belgeli erratadır.

| Errata | Durum | Sorun ve doğru kural |
|---|---|---|
| 7319 | Bildirilmiştir | `*1"not" "(" FILTER ")"` kuralı `not (…)` içindeki boşluğu yasaklamaktadır, oysa RFC'nin kendi örneği boşluk kullanmaktadır. Doğrusu `*1("not" SP) "(" FILTER ")"` olmalıdır |
| 4690 | Beklemededir | `valFilter` içindeki `logExp` referansı `FILTER`'a geri özyinelemekte ve istenmeden iç içe değer yoluna izin vermektedir |
| 7322 | Bildirilmiştir | 4690'ı düzeltmektedir; 4690'ın önerisi meşru olan `emails[type eq "work" or (type eq "home" and value ew "@example.com")]` ifadesini reddetmektedir. Doğru kural `valLogExp = valFilter SP ("and" / "or") SP valFilter`'dır ve 7322 uygulanmalıdır |
| 4670 | Beklemededir | Belirtilen öncelik sırası terstir. `title sw "M" and userType eq "Employee"` ifadesi `(title sw "M") and (userType eq "Employee")` olarak ayrıştırılmalıdır. Öncelik sırası nitelik operatörleri, sonra `not`, sonra `and`, sonra `or` şeklindedir |

**Semantik.** Nitelik adları ile operatörler büyük küçük harfe duyarsızdır; `userName Eq "john"` ile `Username eq "john"` aynıdır. Çok değerli bir nitelikte herhangi bir değer eşleşirse nitelik eşleşir. Karmaşık nitelik tam nitelikli alt nitelik ister, örneğin `name.givenName`. Dize karşılaştırmasının harf duyarlılığı filtrede değil niteliğin `caseExact` karakteristiğinde belirlenir; `userName` duyarsız, `id`, `externalId`, `meta.version` ile `x509Certificates` duyarlıdır. Boolean veya ikili değer üzerinde `gt`, `ge`, `lt` ile `le` kullanmak 400 ile `invalidFilter` döndürür ve spesifikasyon bunu dört kez tekrarlar. Tanınmayan operatör 400 ile `invalidFilter` ve insan okunur bir `detail` döndürmelidir. Şemaya göre filtreleme yasaldır: `filter=schemas eq "urn:…:enterprise:2.0:User"`. Kök seviye sorgu, yani `GET /`, tüm kaynak tiplerini döner ve bir kaynak tipinde tanımsız olan nitelikler değersiz sayılmalıdır, yani varlık ile eşitlik sınamaları false verir.

**Hizmet reddi.** RFC `scimType: tooMany` ile servis sağlayıcı yapılandırmasında `filter.maxResults` verir, ancak sözdizimsel bir karmaşıklık limiti tanımlamaz. Argus'ta iç içe geçme derinliği, toplam token sayısı ile `and` ve `or` terim sayısı için tavan konur; `scim_v2` crate'i `MAX_FILTER_DEPTH` sabitiyle emsal oluşturmaktadır. Büyük koleksiyonlarda yalnızca varlık sınayan filtreler `tooMany` ile reddedilir. `co` operatörü doğal bir hizmet reddi vektörüdür ve indekssiz bir `LIKE '%…%'` ifadesine çevrilmez. Önce soyut sözdizim ağacına ayrıştırılır, şemaya karşı doğrulanır, yani bilinmeyen nitelik `invalidFilter` verir, sonra sorgu planlanır. Asla dize birleştirmesiyle SQL üretilmez.

### 2.6 Durum kodları ve hata sözlüğü

**Başarı kodları.** 201 oluşturma (`Location` başlığı ile `meta.location` eşlik eder), 200 GET ile gövdeli PUT ve PATCH, 204 gövdesiz PATCH ile DELETE, 304 `If-None-Match` ile koşullu GET.

**Hata kodları (§3.12, tablo 8).** 307 ile 308, 400, 401, 403, 404, 409 (sürüm uyuşmazlığı veya yinelenen kaynak), 412 (ön koşul), 413 (yük; gövdede `maxOperations` veya `maxPayloadSize` belirtilmelidir), 500 ile 501.

> **409 ile 412 ayrımı.** Yinelenen `userName` için 409 ile `scimType: uniqueness` dönülür; `If-Match` uyuşmazlığı için 412 dönülür.

Hata gövdesi `urn:ietf:params:scim:api:messages:2.0:Error` şemasındadır; alanları zorunlu olan ve JSON dizesi olarak verilen `status`, ayrıca `scimType` ile `detail`'dir.

`scimType` anahtar kelimeleri tablo 9 ile RFC 9865'ten gelir: `invalidFilter`, `tooMany`, `uniqueness`, `mutability`, `invalidSyntax`, yalnızca PATCH'te kullanılan `invalidPath` ile `noTarget`, `invalidValue`, `invalidVers`, `sensitive`, ayrıca RFC 9865 §2.1'den gelen `invalidCursor`, `expiredCursor` ile `invalidCount`.

Diğer normatif ayrıntılar şunlardır. §3.3 uyarınca oluşturmada gövdedeki `readOnly` nitelikler yok sayılmalıdır, hata verilmez. §3.5.1 uyarınca PUT'ta değiştirilebilirlik şöyledir: `readWrite` ile `writeOnly` değiştirilir; `immutable` için değer varsa girdi eşleşmeli, eşleşmezse 400 ile `mutability` dönülmeli, değer yoksa yeni değer geçerli sayılmalıdır; `readOnly` yok sayılır. Zorunlu nitelikler PUT gövdesinde bulunmalıdır. §3.6 uyarınca DELETE 204 döner, sonraki tüm işlemler 404 verir ve silinen kaynaklar çakışma hesabına girmemelidir, yani aynı `userName` ile yeniden yaratma 409 vermemelidir. §3.8 uyarınca `Accept: application/scim+json` zorunlu, `application/json` önerilirdir ve yanıtlar UTF-8'dir. §3.10 uyarınca `{urn}:{attr}.{subattr}` biçiminde tüm bileşenler büyük küçük harfe duyarsızdır. §4 uyarınca keşif endpoint'lerinde, yani `/Schemas`, `/ResourceTypes` ile `/ServiceProviderConfig` üzerinde filtreleme, sıralama ve sayfalama yok sayılmalıdır; `filter` verilirse 403 dönmek önerilir, böylece istemci filtrenin uygulandığını varsayamaz.

### 2.7 Sayfalama, sıralama ve izdüşüm

**İndeks sayfalaması (§3.4.2.4), klasik tuzak.** `startIndex` birden başlar ve varsayılanı birdir; birden küçük bir değer bir olarak yorumlanmalıdır. `count` için negatif değer sıfır olarak yorumlanmalıdır ve `count=0` yalnızca `totalResults` döndürür. `ListResponse` içinde `totalResults` zorunludur, `totalResults` sıfırdan farklıysa `Resources` zorunludur ve kısmi sonuçta `startIndex` ile `itemsPerPage` zorunludur. Sayfalama açıkça durumsuzdur ve istemciler tutarsız sonuca hazırlıklı olmalıdır, ancak Okta bunun tersini şart koşmaktadır, 2.8'e bakınız. Sıfır eşleşme 200 ile `totalResults: 0` döndürür, asla 404 dönmez.

**İmleç sayfalaması, RFC 9865, Ekim 2025.** Yeni sorgu parametresi `cursor`'dır; ilk sayfada boştur veya yoktur ve yalnızca RFC 3986'nın ayrılmamış karakterlerini içerir. Yeni yanıt nitelikleri `nextCursor` (son sayfa hariç her sayfada bulunmalıdır ve yokluğu tek bitiş sinyalidir) ile `previousCursor`'dır (opsiyoneldir ve ilk sayfada bulunmamalıdır). İstemci diğer tüm parametreleri aynen tekrarlar ve yalnızca `cursor` değişir. Sağlayıcı tahmin edemiyorsa `totalResults` alanını atlayabilir. `POST /.search` üzerinden de çalışır.

Yeni servis sağlayıcı yapılandırma bloğu şöyledir:

```json
"pagination": { "cursor": true, "index": true,
  "defaultPaginationMethod": "cursor",
  "defaultPageSize": 100, "maxPageSize": 250, "cursorTimeout": 3600 }
```

İkisi de destekleniyorsa bir varsayılan seçmek zorunludur; mevcut indeks tabanlı sağlayıcılar indeksi varsayılan tutmalıdır.

Argus önerisi ikisini de desteklemek ve varsayılanı indeks yapmaktır, çünkü Entra ile Okta indeks beklemektedir; ancak imleç de sunulmalıdır, çünkü büyük kiracılarda indeks sayfalaması O(n²) tarama demektir.

**Sıralama (§3.4.2.3).** `sortBy` ile `sortOrder` kullanılır ve varsayılan `ascending`'tir. Çok değerli bir `sortBy` için varsa `primary` değerine, yoksa ilk değere göre sıralanır. Eksik değerler artan sıralamada sona, azalanda başa gider. `caseExact=false` olan nitelikler yerel ayar ima etmeyen harf duyarsız bir Unicode sıralamasıyla sıralanır.

**`attributes` ile `excludedAttributes` (§3.4.2.5, §3.9) ve `returned` etkileşimi.** Varsayılan yanıt kümesi `returned:"always"` ile `returned:"default"` birleşimidir. `attributes` varsayılan kümeyi ezer ve yanıt asgari küme olan `always` ile açıkça istenenlerden oluşur. `excludedAttributes` kullanıldığında yanıt asgari küme ile varsayılan kümeden hariç tutulanların çıkarılmasıyla oluşur ve `always` üzerinde etkisi yoktur. İkisi birlikte kullanılamaz. `returned:"never"` olan nitelikler, örneğin `password`, açıkça istense bile asla dönmez. `returned:"request"` yalnızca `attributes` içinde adı geçerse döner. `id` değeri `always` olduğu için `?attributes=userName` sorgusu bile `id` döndürür.

İzdüşüm kuralı şudur: `always` olanlar koşulsuz çıktıya konur, sonra `attributes` veya `excludedAttributes` `default` katmanına uygulanır, sonra `never` olan her şey düşürülür. Alt nitelik yolları, örneğin `name.givenName`, desteklenmelidir ve istenen alt nitelik yalnızca onu içeren ebeveyn nesnesini üretmelidir.

### 2.8 Gerçek dünya interop'u, sunucunun tolere etmesi gerekenler

#### Microsoft Entra ID

Kaynakları learn.microsoft.com'daki `use-scim-to-provision-users-and-groups` (doküman tarihi 28 Ağustos 2026), `application-provisioning-config-problem-scim-compatibility` (25 Ağustos 2025), `how-provisioning-works` ile `scim-validator-tutorial` sayfalarıdır; aracı scimvalidator.microsoft.com'dur, erişim 8 Eylül 2026.

Entra'nın belgelenmiş talepleri alıntı seviyesinde şunlardır.

| Talep | Sonuç |
|---|---|
| "Microsoft Entra-only uses the following operators: eq, and" | Diğer operatörler Entra için gereksizdir, ancak Okta için değildir |
| "Don't require a case-sensitive match on structural elements… Microsoft Entra ID emits the values of op as Add, Replace, and Remove" | `op` karşılaştırması harf duyarsız olmalıdır |
| "It isn't necessary to include the entire resource in the PATCH response" ile grup PATCH'inin "should yield an HTTP 204 No Content" olması | 204 tercih edilmektedir |
| "Values sent should be stored in the same format they were sent" | RFC 7643 §4.1.2'nin kanonikleştirme tavsiyesiyle çelişmektedir; kanonikleştirme yapılmaz |
| "The 'type' subattribute values of multivalued complex attributes must be unique" | İki `work` e-postası olamaz |
| "`id` is a required property for all resources… except for ListResponse with zero elements" | — |
| "Response to a query/filter request should always be a ListResponse" | — |
| "The entitlements attribute isn't supported" | — |
| Gruplar boş `members` listesiyle yaratılır ve `displayName` benzersiz olmalıdır | Bu bir Entra şartıdır, SCIM şartı değildir |
| `/Schemas` bir ListResponse olmalıdır; "If a value isn't present, don't send null values"; "Property values should be camel cased" | — |
| Özel karmaşık nitelikler üç veya daha fazla alt nitelikle desteklenmemektedir | — |
| "we don't support the /Bulk endpoint today" | Toplu işlem ertelenir |

Entra'nın gönderdiği tam istek şekilleri şunlardır:

```
GET /Users?filter=userName eq "Test_User_00aa…"
GET /Groups?excludedAttributes=members&filter=displayName eq "displayName"
GET /Groups/{id}?excludedAttributes=members
DELETE /Users/{id}                      → 204 bekler
POST /Users (yinelenen)                 → önce 201 sonra 409 bekler
```

Grup yaratmada Microsoft'a özel ekstra bir şema URN'i gönderir: `"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group","http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group"]`. Bu reddedilmemelidir.

Microsoft'un kendi doküman örneğinde `"resourceType": "Users"` çoğul olarak geçmektedir; bu uyumsuzdur ve `meta.resourceType` alanını doğrulamadıklarının kanıtıdır.

Uyumluluk bayrağı kiracı URL'ine eklenen `aadOptscim062020`'dir ve uyumlu PATCH davranışını açar. Geri düşürme bayrağı `AzureAdScimPatch2017`'dir. İş şablonları güncel olan `scim` ile Aralık 2018 öncesi eski olan `customappsso`'dur.

Entra'nın kendi uyumluluk tablosunda hâlâ düzeltilmemiş bir madde vardır: "Update PATCH behavior to ensure compliance (such as active as boolean and proper group membership removals) — Fixed? No — Fix date TBD — use feature flag."

Bayrak olmadan, yani varsayılan durumda, Entra'nın gönderdikleri şunlardır:

```json
{"Operations":[{"op":"Replace","path":"active","value":"False"}]}          // string boolean + büyük harf op
{"Operations":[{"op":"Add","path":"nickName","value":"Babs"}]}
{"Operations":[{"op":"Remove","path":"members","value":[{"value":"u1091"}]}]}   // UYUMSUZ: path + value dizisi
```

Grup üyesi ekleme ile çıkarmanın varsayılan biçimi `"$ref": null` içerir:

```json
{"Operations":[{"op":"Add","path":"members","value":[{"$ref":null,"value":"f648…"}]}]}
```

Bayrakla uyumlu hâle gelir, yani `"op":"replace"`, `"value":false` ile `"path":"members[value eq \"…\"]"` üretir; ancak yolsuz bir `replace` de üretir ve `value` nesnesinde düz noktalı anahtarlar kullanır:

```json
{"op":"replace","value":{"displayName":"Bjfe","name.givenName":"Kkom",
 "name.familyName":"Unua",
 "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber":"Aklq"}}
```

Buradaki `"name.givenName"` iç içe bir nesne değil düz noktalı bir JSON anahtarıdır. RFC'nin yolsuz biçimi gerçek nitelik nesneleri bekler ve Argus bunu kabul etmelidir.

Hız sınırlama ile yeniden deneme konusunda Microsoft açık 429 semantiği, istek zaman aşımı veya deneme sayısı belgelememektedir. Belgelenen şudur: başarısız nesne işlemleri sonraki senkronizasyon döngüsünde "gradually scaling back the frequency of retries" ile tekrarlanır; kalıcı ve yaygın hatalar işi karantinaya alır, döngü sıklığı günde bire düşer ve dört hafta karantinadan sonra iş otomatik devre dışı bırakılır. Silmede varsayılan yumuşak silmedir, yani `active=false`; Entra'da yumuşak silmeden 30 gün sonra veya elle kalıcı silmede sert DELETE gönderilir. Microsoft'un tavsiyesi şudur: "always support both soft-deletes and hard-deletes." Kesin 429 ile zaman aşımı değerleri doğrulanamamıştır; Microsoft'un kamuya açık dokümanlarında yoktur.

#### Okta

Kaynakları developer.okta.com'daki `/docs/concepts/scim/`, `/docs/api/openapi/okta-scim/guides/scim-20/` ile `/docs/guides/scim-provisioning-integration-prepare/main/` sayfalarıdır, erişim 8 Eylül 2026.

Gereken endpoint'ler `GET` ile `POST /Users`, `GET`, `PUT` ile `PATCH /Users/{id}`, `GET` ile `POST /Groups`, ayrıca `GET`, `PUT`, `PATCH` ile `DELETE /Groups/{id}`'dir.

"Okta doesn't perform DELETE operations on user objects in your SCIM app." Kullanıcı kaldırma her zaman `active: false` iledir. Gruplar ise silinir.

Filtreler `filter=userName eq "…"` ile `filter=displayName eq "…"`'dir: "Your SCIM server must support this query parameter to provision users with Okta successfully."

Sayfalama değerleri dize değil tamsayı olarak alışverilmelidir. Ayrıca: "The SCIM server must consistently return the same ordering of results… regardless of which values are provided for `count` and `startIndex`." Yani Okta kararlı bir toplam sıralama şart koşmaktadır, oysa RFC §3.4.2.4 tutarsızlığa açıkça izin vermektedir.

PUT ile PATCH tercihi entegrasyon tipine bağlıdır: yeni OIN entegrasyonları genel kullanıcı güncellemesi için PUT, etkinleştirme, devre dışı bırakma ile parola senkronizasyonu için PATCH kullanır; uygulama entegrasyon sihirbazıyla kurulan ve özel uygulamalar her şey için PUT kullanır. Gruplarda OIN PATCH, sihirbaz PUT tercih etmektedir. Dolayısıyla PUT ikinci sınıf bir vatandaş olarak yazılmamalıdır.

"You must return the `members` list payload when `GET /Groups/{groupID}` is requested without any query parameters." Bu, Entra'nın üyeleri döndürmeye gerek olmadığı tavsiyesinin tam tersidir. Argus varsayılanda üyeleri döndürmeli ve `excludedAttributes=members` isteğine de uymalıdır.

Temel URL alt çizgi içermemelidir ve Okta `/scim/v2/` önermektedir. TLS zorunludur. Kimlik doğrulama OAuth 2.0 authorization code, Basic veya bearer olabilir.

Asgari şema `userName`, `name.givenName`, `name.familyName`, `emails`, kararlı ve harf duyarlı salt okunur `id` ile `active`'tir.

Test süiti "Okta SCIM 2.0 Spec Test JSON"dur ve Runscope'a aktarılır. Runscope BlazeMeter tarafından kapatılmıştır ve 2026'da hâlâ çalışır durumda olup olmadığı doğrulanamamıştır.

#### Google Workspace, OneLogin, JumpCloud, Ping ile SailPoint

Bu oturumda birincil kaynaktan doğrulanamamıştır, çünkü arama bütçesi tükenmiştir. Bu satıcılar hakkında spesifik bir iddia kurulmamalıdır; ayrı bir doğrulama turu gerekir.

#### Argus'un tolerans kontrol listesi, 17 madde

Her madde yukarıdaki doğrulanmış kaynaklara veya errataya dayanmaktadır.

1. `op` değeri harf duyarsız kabul edilir; `Add`, `add` ile `ADD` aynıdır. Entra kaynaklıdır.
2. `"value": "False"` ile `"True"` dizeleri boolean'a zorlanır. Entra kaynaklıdır.
3. `remove` hem `path:"members"` hem `value:[{value: id}]` ile gelebilir. Entra varsayılanıdır.
4. Üye nesnelerinde `"$ref": null` bulunabilir. Entra kaynaklıdır.
5. Yolsuz `replace` veya `add` gövdesinde noktalı anahtarlar ile tam nitelikli URN anahtarları bulunabilir. Bayraklı Entra kaynaklıdır.
6. Bilinmeyen ve tescilli şema URN'leri yok sayılır, reddedilmez.
7. Değer yolu ile alt nitelik kullanan bir `add` işleminde eşleşme yoksa yeni bir eleman yaratılır. Errata 8097 ile Entra kaynaklıdır.
8. `Group.members` içinde `display` alt niteliği normatif şemada yoktur ancak kabul edilir.
9. PatchOp gövdesinde `schemas` eksikse hoşgörülü olunur.
10. Boşluklu `not (…)` ile değer yolu içinde iç içe parantez kabul edilir. Errata 7319 ile 7322 kaynaklıdır.
11. Hem `/ServiceProviderConfig` hem `/ServiceProviderConfigs` sunulur. Errata 4978 kaynaklıdır; Facebook, Salesforce ile Slack çoğul kullanmaktadır.
12. `Accept: application/json` da kabul edilir.
13. Grup PATCH'inde 204 dönülür, ki bu Entra tercihidir, ancak `attributes` varsa 200 dönülür, ki bu RFC zorunluluğudur.
14. Çıplak `GET /Groups/{id}` isteğinde üyeler dönülür, ki bu Okta zorunluluğudur, ve `excludedAttributes=members` isteğine uyulur, ki bu Entra zorunluluğudur.
15. Sayfalar arasında kararlı bir toplam sıralama sağlanır; Okta zorunluluğudur, RFC izin verse de.
16. Yinelenen `POST /Users` isteğine 409 dönülür.
17. Saklanan değerler asla kanonikleştirilmez; Entra zorunluluğudur, RFC öneri seviyesinde tersini söylese de.

> **Tasarım kararı.** Bu 17 madde bir hoşgörü katmanı olarak katı ayrıştırıcının önüne konur ve istemci başına açılıp kapanabilir yapılır. Böylece uyumlu istemciler katı davranışı görür, Entra kendi lehçesini konuşur ve hangi istemcinin hangi sapmayı kullandığı ölçülebilir.

### 2.9 RFC 9967, SCIM olayları ve Argus'un yapması gerekenler

**Kapsam.** SCIM güvenlik olaylarını güvenlik olayı token'ı, yani RFC 8417 SET'i olarak tanımlar; asenkron istek tamamlama, kaynak replikasyonu ile sağlama koordinasyonu içindir. RFC 7644'e `Prefer: respond-async` yeteneğini, RFC 7643'e `securityEvents` yapılandırma bloğunu ekler.

**İlişkili standartlar.** RFC 8417 (SET), 7519 (JWT), 9493 (özne tanımlayıcıları), 8935 (itme), 8936 (çekme) ile 7240 (Prefer). Akış kaydı ile yapılandırması kapsam dışıdır: "Stream registration and configuration are out of scope of this specification". Orayı OpenID SSF doldurur.

> OpenID Shared Signals Framework 1.0, 29 Ağustos 2025'te final olarak yayımlanmıştır; adresi openid.net/specs/openid-sharedsignals-framework-1_0.html'dir. RFC 8417, 8935 ile 8936'yı profiller ve CAEP ile RISC olay tipleriyle geriye uyumluluk sağlar. Beş yönetim endpoint'i vardır: yapılandırma, durum, özne ekleme, özne çıkarma ile doğrulama. Özeti şudur: RFC 9967 olay sözlüğünü verir, SSF boru tesisatını verir ve gerçek olay yayını isteyen bir IdP'nin ikisine de ihtiyacı vardır.

**Özne tanımlama (§2.1).** RFC 9493'teki `sub_id` claim'i zorunludur ve JWT'nin üst seviye gövdesinde bulunur, `events` içinde değil. JWT'nin `sub` claim'i kullanılmamalıdır, böylece yetkilendirme token'larıyla karışmaz. `sub_id.format` değeri `"scim"`tir. Alt claim'leri zorunlu olan `uri` (SCIM göreli yoludur, örneğin `/Users/2b2f880af…`), opsiyonel `externalId` ile geriye uyumluluk için opsiyonel `id`'dir. Ek olarak `uniqueness` değeri `server` veya `global` olan herhangi bir nitelik taşınabilir.

**Ortak olay nitelikleri (§2.2).** `txn` bir işlem kimliğidir ve SET seviyesinde bir claim'dir; `jti`'nin aksine yeniden iletimlerde ve birden çok alıcıda sabit kalır. Asenkron istekler, koordineli sağlama ile replikasyon için zorunludur. `version` olaydan sonraki kaynağın ETag değeridir. `data` tam yüktür ve toplu işlem `data` niteliği şeklindedir. `attributes` değişen nitelik adlarının dizisidir ve PATCH `path` ABNF'ine uygundur, örneğin `["userName","emails","name.familyName"]`. `data` ile `attributes` alanlarından tam olarak biri bulunmalıdır; ikisi birden bulunmamalıdır.

**Olay URI'leri, IANA SCIM Event URIs kaydının tamamı (§7.4).**

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

`:full` sonekli olaylar `data` taşır. `:notice` sonekliler `attributes` taşır ve alıcı bir SCIM GET ile geri çağırır. İki çalışma modu vardır: alan tabanlı replikasyon `:full` kullanır ve geri çağrı yoktur; koordineli sağlama `:notice` ile geri çağrı kullanır. `prov:delete` kaynağı feed'den de çıkarır ve ayrıca `feed:remove` yayınlanmamalıdır. `feed:add` ile `feed:remove` feed üyeliği sinyalidir, oluşturma veya silme sinyali değildir.

**Asenkron istekler (§2.5.1, §3).** İstemci `Prefer: respond-async` gönderir ve `wait` tercihini de desteklemesi önerilir. `Accept` başlığı asenkron amaçla yok sayılmalıdır. Sunucu gövdesiz bir 202 Accepted döner ve buna şunlar eşlik eder: bu RFC'nin tanımladığı yeni HTTP yanıt başlığı olan `Set-Txn` (§3; gövdesiz 202'de bulunması zorunludur, değeri nihai SET'in `txn` claim'iyle eşleşmelidir ve ara katmanlar değiştirmemelidir), `Preference-Applied: respond-async` ile `Location` (ya tamamlanma SET'inin alınabileceği URI ya da normal SCIM kaynak konumudur).

Toplu işlem ile asenkron birleşimi için operasyon başına bir `asyncresp` olayı üretilir. `txn` değeri orijinal işlem kimliğine iki nokta üst üste ve sıfır tabanlı indeks eklenerek oluşur, örneğin `2d80e537…:0` ile `:1`. `bulkId` bu amaçla kullanılmamalıdır. Sunucu sırayı değiştirse bile indeks orijinal istek sırasını yansıtmalıdır.

**Servis sağlayıcı yapılandırma uzantısı (§4).**

```json
"securityEvents": {
  "asyncRequest": "none" | "long" | "request",
  "eventUris": [ "urn:ietf:params:scim:event:prov:create:full", "…" ]
}
```

Bu blok yoksa desteklenmiyor demektir ve `eventUris` yalnızca bilgilendirmedir.

**Argus'un uygulama sırası.**

1. Durum değiştiren her SCIM işleminde bir iç değişiklik olayı üretilir: `txn`, kaynak URI'si, `externalId`, sonuç ETag'i ile değişen nitelik listesi taşınır.
2. §2.1 ile §2.4 arasına göre SET olarak serileştirilir; `sub_id`, `format:"scim"` ile `uri` kullanılır ve `sub` kullanılmaz.
3. `/ServiceProviderConfig` üzerinde `securityEvents` yayımlanır; `asyncRequest: "none"` ile başlanır ve `eventUris` doldurulur.
4. Teslimatta önce RFC 8935 itme yapılır, çünkü RFC 8936 çekme daha karmaşıktır. Akış yönetimi icat edilmez, OpenID SSF 1.0 izlenir.
5. Önce `:notice` modu yapılır, çünkü olayda kişisel veri yoktur ve alıcı geri çağırır. `:full` yalnızca güvenilir replikasyon eşleri için eklenir, çünkü tam kullanıcı kaydını tele koyar.
6. `Prefer: respond-async` ile 202 ve `Set-Txn` en sona bırakılır; istek boru hattındaki en invaziv değişiklik budur.

> **Gizlilik uyarısı.** RFC'nin kendi beşinci şeklinde `prov:create:full` olayının değişen nitelikleri arasında `"password"` listelenmektedir. Argus feed başına nitelik filtrelemesi uygulamalı ve `returned:"never"` olan niteliklerin değerini asla bir SET'e koymamalıdır.

### 2.10 SCIM çalışma grubunun güncel durumu, Eylül 2026

Kaynağı datatracker.ietf.org/wg/scim/documents'tır, erişim 8 Eylül 2026.

Süresi dolmuş çalışma grubu taslakları aktif sanılmamalıdır: `draft-ietf-scim-roles-entitlements-01` ("SCIM Roles and Entitlements Extension", revizyon 01, 16 Ekim 2025, süresi dolmuştur) ile `draft-ietf-scim-use-cases-reloaded-02` (7642-bis, revizyon 02, 19 Ocak 2026, süresi dolmuştur).

Brief'teki tahminlerin gerçek karşılıkları şöyledir: `draft-ietf-scim-events` veya `-event-notification` RFC 9967 olmuştur; `draft-ietf-scim-device-model` RFC 9944 olmuştur; `draft-ietf-scim-cursor-pagination` RFC 9865 olmuştur; `draft-ietf-scim-profile-*` için çalışma grubu sayfasında böyle bir doküman yoktur ve doğrulanamamıştır; bir PATCH netleştirme taslağı veya 7644bis listede yoktur ve doğrulanamamıştır. PATCH netleştirmesi yalnızca errata 7122 ile 8097 olarak vardır; ikisi de doküman güncellemesi için beklemededir ve alan direktörü notu şöyledir: "any future update work in this space should consider this erratum".

RFC 9944, yani cihaz şeması, Argus ileride cihaz sağlaması yaparsa gerekecektir: `urn:ietf:params:scim:schemas:core:2.0:Device` ile `…core:2.0:EndpointApp` şemalarını, ayrıca `ble`, Wi-Fi Easy Connect için `dpp`, `ethernet-mab`, `fido-device-onboard`, `zigbee` ile `endpointAppsExt` uzantılarını getirir.

### 2.11 Rust ekosistemi, SCIM

crates.io JSON API'sinden doğrulanmıştır, 8 Eylül 2026. "scim" araması 94 crate döndürmektedir; aşağıdakiler dışındakiler onlarca ile yüzlerce indirmelidir ve ciddiye alınamaz.

| Crate | Sürüm | Yayın | Toplam ile son 90 gün | Lisans | Depo |
|---|---|---|---|---|---|
| `scim_v2` | 0.5.0 | 7 Eylül 2026 | 75.483 ile 47.320 | MIT | ShiftControl-io/scim-v2-rust |
| `scim_proto` | 1.11.1 | 14 Ağustos 2026 | 119.338 ile 11.676 | MPL-2.0 | kanidm/kanidm |
| `scim-server` | 0.5.3 | 21 Eylül 2025 | 152.900 ile 140.186 | MIT | pukeko37/scim-server |
| `scim-filter` | 0.2.3 | 12 Ocak 2024 | 238.870 ile 6.428 | MIT | matteosister/scim-filter |
| `scim-rs` | 0.1.0 | 29 Haziran 2026 | 113 | MIT | salasebas/scim-rs |

`scim2`, `scim2-rs` ile `scim-core` crates.io'da yoktur.

**Yetenek denetimi.**

`scim_v2` 0.5.0'ın modülleri `filter`, `models`, `schema_urns` ile `utils`'tir. Filtre ayrıştırıcısı vardır; `filter` modülü açıkça hem RFC 7644 §3.4.2.2 filtrelerini hem §3.5.2 PATCH yollarını kapsamaktadır. Genel tipleri `Filter` (And, Or, Not ile Attr), `AttrExp`, `CompValue`, `CompareOp`, `AttrPath`, `ValuePath`, `ValFilter`, `PatchPath`, `PatchValuePath`, `MaybeFilter`, `InvalidFilterError`, `FilterActionError` ile bir `MAX_FILTER_DEPTH` sabitidir. PATCH desteği kısmidir: yalnızca yol ayrıştırması vardır, uygulama mantığı yoktur. Değerlendirici veya eşleştirici yoktur; dokümanlarda elle yazılmış özyinelemeli bir örnek bulunmaktadır. Şema doğrulaması hafiftir; açıkça şöyle denmektedir: "Validation is light because the schema is specifically flexible. We only validate required fields." Değiştirilebilirlik, döndürülme, benzersizlik ile harf duyarlılığı dayatması yoktur. HTTP yönlendirmesi yoktur. Argus için en kullanışlı crate budur ve bu araştırmadan bir gün önce, yani 7 Eylül 2026'da güncellenmiştir; yani filtre ile PATCH yolu çalışması yepyenidir.

`scim_proto` 1.11.1 Kanidm'dendir ve `user`, `group`, `filter`, `constants` ile `prelude` modüllerine sahiptir. `peg ^0.8` bağımlılığı gerçek bir PEG tabanlı filtre ayrıştırıcısı olduğunu gösterir. PATCH desteği ile HTTP sunucu kodu yoktur. Lisansı MPL-2.0'dır ve Argus'a dahil etmeden önce lisans uyumu kontrol edilmelidir.

`scim-server` 0.5.3 "Complete implementation of RFC 7643 and RFC 7644" iddiasındadır; çok kiracılı ve çatı bağımsızdır. Doğrulananlar şema doğrulaması, ETag desteği ile sayfalamadır ve toplu işlem kısmidir. Ancak filtre ayrıştırıcısı ile PATCH desteği genel API'de belgelenmemiştir; yani tam implementasyon iddiası tam olarak en zor iki parça için desteklenmemektedir. Son yayını 21 Eylül 2025'tir, yani yaklaşık bir yıl bayattır; 1.0 öncesidir ve README "Minor version increments signal breaking changes until v1.0" demektedir.

SET, SSF ile CAEP için bir Rust crate'i yoktur. Argus SET üretimini kendisi yazmalıdır; RFC 9967 SET'leri `events`, `txn` ile `sub_id` claim'li JWT'lerden ibaret olduğu için bu mütevazı bir iştir ve `jsonwebtoken` veya `josekit` üzerine kurulabilir.

**Argus'un sıfırdan yazması gerekenler.** Hiçbir crate uyumlu bir sunucu vermemektedir; sahiplenilmesi gerekenler şunlardır.

1. Şema kaydı: tam nitelik karakteristikleriyle, yani değiştirilebilirlik, döndürülme, benzersizlik, harf duyarlılığı, kanonik değerler ile referans tipleriyle, ve errata uygulanmış hâlde. Hiçbir crate bunu doğru modellememektedir.
2. Değiştirilebilirlik ile döndürülme dayatma katmanı: POST, PUT, PATCH ile yanıt izdüşümü için farklı uygulanır. Kimsede yoktur.
3. PATCH motoru: yolu ayrıştır, hedefi çöz, §3.5.2.1 ile 3 arasındaki kural listelerini uygula, `primary` alanını otomatik düşür, işlemsel geri alma yap ve 2.8'deki 17 toleransı ekle. En büyük tek iş kalemidir ve hiçbir crate vermemektedir.
4. Filtre değerlendiricisi ile sorgu planlayıcısı: errata 7322'nin `valLogExp` kuralı, 7319'un boşluklu `not (` kuralı, harf duyarlılığına göre karşılaştırma, boolean ile ikili değer üzerinde `gt` ve `lt` için `invalidFilter` ve derinlik ile karmaşıklık limitleri.
5. İzdüşüm: `attributes` ile `excludedAttributes` katmanlarının `returned` ile etkileşimi ve alt nitelik yolları.
6. Sayfalama: hem birden başlayan indeks hem RFC 9865 imleçleri, Okta'nın istediği kararlı sıralama garantisiyle.
7. ETag üretimi ile `If-Match` ve `If-None-Match` işleme, 412 ile 304. İpucu şudur: `meta.location` ile `meta.version` yanıtın parçası olduğu için hash saklanan durumdan alınır, oluşturulan yanıttan değil.
8. `/Schemas`, `/ResourceTypes` ile `/ServiceProviderConfig`: doğrulamayı yapan aynı kayıttan üretilmelidir, yani tek doğruluk kaynağı olmalıdır; RFC 9865 `pagination` ile RFC 9967 `securityEvents` blokları dahildir.
9. Toplu işlem: `bulkId` çözümleme, döngüsel referans, `failOnErrors` ile 413.
10. RFC 9967 SET üretimi ve opsiyonel OpenID SSF akış yönetimi.
11. Satıcı uyumluluk ara katmanı: 17 tolerans, istemci başına açılıp kapanabilir.

> **Tavsiye.** `scim_v2` 0.5.0 filtre ile PATCH yolu soyut sözdizim ağaçları ve model yapıları için alınır; ikinciden on birinciye kadarki katmanlar kendimiz yazılır. `scim-server` temel alınmaz, çünkü bir yıl bayattır, 1.0 öncesidir ve en önemli iki iddiası belgelenmemiştir.

### 2.12 SCIM sınıflandırma özeti

**Zorunlu.** `/Users` ile `/Groups` üzerinde GET, POST, PUT, PATCH ile DELETE; `/ServiceProviderConfig` ve çoğul takma adı; `/ResourceTypes`; `/Schemas`; `eq` ile `and` filtreleri; indeks sayfalaması; `attributes` ile `excludedAttributes`; PATCH motoru; errata uygulanmış şema kaydı; 17 maddelik tolerans katmanı; yumuşak silme (`active=false`) ile sert silme.

**Opsiyonel, faz 2.** Tam filtre grameri (`co`, `sw`, `ew`, `pr`, `ne` ile karşılaştırma operatörleri); sıralama; ETag ile `If-Match`; `POST /.search`; RFC 9865 imleç sayfalaması; RFC 9967 SET yayını, `:notice` modunda; `/Me`.

**Atlanabilir, faz 3 ve sonrası.** `/Bulk`, çünkü Entra desteklememektedir; `Prefer: respond-async` ile `Set-Txn`; `:full` replikasyon olayları; OpenID SSF akış yönetimi; RFC 9944 cihaz şemaları; `returned:"request"` uzantıları.

### 2.13 SCIM efor tahmini

| İş kalemi | Tahmin |
|---|---|
| Şema kaydı, errata ile karakteristik motoru | 2 hafta |
| Kaynak CRUD ile değiştirilebilirlik dayatması, POST ile PUT ayrı | 2 hafta |
| PATCH motoru: kural listeleri, atomiklik, `primary` ile tolerans | 3 ile 4 hafta |
| Errata düzeltmeli filtre ayrıştırıcısı, değerlendirici ile SQL planlayıcısı | 2 ile 3 hafta |
| İzdüşüm, sayfalama (indeks ile imleç) ve sıralama | 2 hafta |
| Keşif endpoint'leri, tek kaynaktan üretim | 1 hafta |
| ETag ile eşzamanlılık | 0,5 hafta |
| Satıcı tolerans katmanı ile Entra SCIM Validator'dan geçmek | 2 hafta |
| RFC 9967 SET üretimi, `:notice` ile itme | 1,5 hafta |
| Toplam | Yaklaşık 16 ile 18 hafta, tek mühendis |

---

## Bölüm 3 — LDAP, sunucu tarafı

### 3.1 Stratejik çerçeve: LDAP bir protokol değil bir uyumluluk yüzeyidir

Argus'un LDAP yazma sebebi dizin ürünü olmak değildir. Sebep şudur: kurumsal alıcının envanterinde OIDC konuşmayan 10 ile 30 arası cihaz veya uygulama vardır; VPN yoğunlaştırıcıları, ağa bağlı depolama birimleri, hipervizör konsolları, izleme sistemleri ile eski Java uygulamaları bunlardandır. Bunlar OIDC'ye asla geçmeyecektir ve LDAP arayüzü bu kuyruk için bir ağ geçididir.

Bu, tasarım kararının tamamını belirler: Argus bir dizin bilgi ağacı ürünü değil, iç veri modelinin LDAP izdüşümüdür. Kanidm tam olarak bu kararı vermiş ve dokümantasyonunda açıkça yazmıştır: "The LDAP server in Kanidm is not a complete LDAP implementation." Kaynağı kanidm.github.io/kanidm/stable/integrations/ldap.html'dir, erişim 8 Eylül 2026.

### 3.2 RFC 4511 operasyonları, üçlü sınıflandırma

| Operasyon | ASN.1 etiketi | Argus için | Gerekçe |
|---|---|---|---|
| Basit `BindRequest` ile `BindResponse` | 0 ile 1 | Zorunludur | Her istemcinin ilk işlemidir. RFC 4513 §2: anonim dışında herhangi bir mekanizma destekleyen bir implementasyon ad ile parola kullanan basit bind'ı desteklemeli ve bunu TLS ile korumaya muktedir olmalıdır |
| `SearchRequest`, `SearchResultEntry` ile `SearchResultDone` | 3, 4 ile 5 | Zorunludur | Tüm okuma trafiğidir |
| `UnbindRequest` | 2 | Zorunludur | Tek yönlüdür ve yanıtsızdır; bağlantıyı kapatır |
| `AbandonRequest` | 16 | Zorunludur, en azından kabul edilmelidir | Yanıtsızdır. En azından ayrıştırılıp arama iptal edilmelidir, yoksa kaynak sızdırılır |
| `ExtendedRequest` ile `ExtendedResponse` | 23 ile 24 | Kısmen zorunludur | StartTLS (1.3.6.1.4.1.1466.20037) ile Who Am I (RFC 4532, 1.3.6.1.4.1.4203.1.11.3) içindir |
| `SearchResultReference` | 19 | Opsiyoneldir | Yönlendirme yoksa hiç üretilmez; üretildiği anda bir SSRF yüzeyi açılır |
| `CompareRequest` ile `CompareResponse` | 14 ile 15 | Opsiyoneldir | Bazı eski istemciler grup üyeliğini karşılaştırmayla sorar. Ucuzdur, eklenir |
| `ModifyRequest` ile `ModifyResponse` | 6 ile 7 | Koşulludur | Yalnızca parola değiştirme senaryosu içindir, 3.7'ye bakınız |
| `AddRequest`, `DelRequest` ile `ModifyDNRequest` | 8, 10 ile 12 | Atlanabilir | Hiçbir gerçek istemci bunları bir IdP ağ geçidinden istememektedir; `unwillingToPerform` yani 53 dönülür |
| `IntermediateResponse` | 25 | Atlanabilir | Yalnızca RFC 4533 içerik senkronizasyonu için gerekir |

Karar şudur: faz 1'de basit bind, arama, unbind, abandon, StartTLS ile WhoAmI yapılır. Bu, aşağıdaki istemci listesinin tamamını karşılar.

### 3.3 RootDSE, ilk kırılma noktası

İstemcilerin çoğu bağlanır bağlanmaz `baseObject` kapsamı, `(objectClass=*)` filtresi ile boş bir temel ayırt edici adla arama yapar. Bu RootDSE'dir ve doğru cevap verilmezse istemci daha ilk adımda vazgeçer.

Zorunlu operasyonel nitelikler şunlardır.

| Nitelik | Değer | Not |
|---|---|---|
| `namingContexts` | `dc=idm,dc=example,dc=com` | İstemciler temel ayırt edici adı buradan keşfeder |
| `supportedLDAPVersion` | `3` | — |
| `subschemaSubentry` | `cn=Subschema` | Şema keşfi buraya yönlenir |
| `supportedExtension` | StartTLS ile WhoAmI, varsa PasswordModify OID'leri | — |
| `supportedControl` | En azından `1.2.840.113556.1.4.319`, yani sayfalı sonuçlar | — |
| `supportedSASLMechanisms` | Boş veya `EXTERNAL` | Boş bırakmak meşrudur |
| `vendorName` ile `vendorVersion` | `Argus` ile sürüm | Bazı istemciler Active Directory ile OpenLDAP ayrımı için buna bakar |
| `objectClass` | `top` ile uyumluluk için `OpenLDAProotDSE` | — |

`cn=Subschema` gerçekten dolu olmalıdır. Apache Directory Studio, phpLDAPadmin ile bazı Java istemcileri `objectClasses` ve `attributeTypes` listesini okumadan çalışmaz. Bu, yalnızca okuma yapan bir ağ geçidi iddiasının en can sıkıcı maliyetidir: RFC 4512 biçiminde şema dizeleri üretmek zorunludur.

### 3.4 Dizin ağacı ve şema modellemesi: OIDC modelini LDAP'a izdüşürmek

İki geçerli yaklaşım vardır.

**Düz model, Kanidm'in seçimi.** Ağaç yoktur ve tüm girdiler temel ayırt edici adın hemen altındadır. Ayırt edici ad `spn`, `name` veya `uuid` değerinden türetilir: `spn=test1@idm.example.com,dc=idm,dc=example,dc=com`. Kanidm bind sırasında `name=test1`, `test1@idm.example.com` veya ham UUID biçimlerini kabul etmektedir; kaynağı Kanidm LDAP dokümanıdır, erişim 8 Eylül 2026.

**Sahte organizasyon birimi modeli.** `ou=people,dc=…` ile `ou=groups,dc=…` kullanılır. Gerçek bir ağaç değil, iki sabit konteynerdir. Argus için bu önerilir, çünkü istemci yapılandırmalarının ezici çoğunluğu kullanıcı tabanı ile grup tabanı ayrımı beklemektedir; GitLab `group_base`, Grafana `search_base_dns`, Jenkins ise `userSearchBase` kullanır. Düz modelde bu alanlar aynı değeri alır ve grup ile kullanıcı ayrımı filtreye kalır; bu çalışır ancak her müşteri kurulumunda ek bir destek bileti demektir.

**Zorunlu nesne sınıfı ile nitelik matrisi.**

| Katman | objectClass | Nitelikler | Kim ister |
|---|---|---|---|
| Temel kimlik | `top`, `person`, `organizationalPerson`, `inetOrgPerson` | `uid`, `cn`, `sn`, `givenName`, `displayName`, `mail`, asla döndürülmeyecek `userPassword` | Herkes |
| POSIX | `posixAccount` | `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell` | sssd, nslcd, ağa bağlı depolama, Synology, Proxmox |
| İsimli grup | `groupOfNames` | Tam ayırt edici ad taşıyan `member` | Jenkins, GitLab, Nextcloud |
| POSIX grubu | `posixGroup` | `gidNumber` ile yalnızca kullanıcı adı taşıyan `memberUid` | sssd, nslcd |
| Ters üyelik | — | Operasyonel `memberOf` | Grafana, GitLab ile Active Directory alışkanlığı olan her şey |
| Active Directory taklidi | — | `sAMAccountName`, `userPrincipalName`, `userAccountControl` | Active Directory varsayan istemciler |

Kritik ayrıntı şudur: `groupOfNames` ile `posixGroup` aynı girdide verilmelidir ki hem ayırt edici ad tabanlı `member` hem kullanıcı adı tabanlı `memberUid` istemcileri çalışsın. Standart şemada bu bir çakışmadır, çünkü `groupOfNames` `member` alanını zorunlu kılar; gerçek dünyada herkes RFC 2307bis benzeri bir gevşetmeyle bunu yapmaktadır. Argus şema doğrulaması yapmadığı için, çünkü bir izdüşümdür ve depo değildir, bu bedavadır.

`memberOf` operasyonel bir niteliktir: yıldız ile gelen aramada dönmemeli, ancak açıkça veya artı işaretiyle istenirse dönmelidir. Gerçek dünyada Grafana `member_of` istemekte ve bazı istemciler açıkça istememektedir; pratik karar `memberOf` değerini açıkça istendiğinde döndürmek, yıldızda döndürmemek ve bunu dokümantasyonda yazmaktır.

`uidNumber` ile `gidNumber` üretimi için UUID'den deterministik türetme, örneğin UUID'nin belirli bitlerini bir aralığa eşlemek, tek makul yoldur; sayaç tabanlı üretim çok yazarlı dağıtık bir kurulumda çakışır. Kanidm bu alanda dikkat çekici bir sınırlamaya sahiptir: dokümanı yalnızca `gidnumber` eşlediğini, `uid` eşlemesi olmadığını söylemektedir.

### 3.5 Filtre çevirisi, asıl mühendislik işi

RFC 4515 filtre grameri iç sorgu diline çevrilmelidir. Desteklenmesi gereken düğümler şunlardır.

| Filtre | Öncelik | Not |
|---|---|---|
| `(attr=value)` eşitlik eşleşmesi | Zorunludur | — |
| `(&...)`, `(\|...)` ile `(!...)` | Zorunludur | İç içe geçme derinliğine sınır konur, önerisi 16'dır |
| `(attr=*)` varlık | Zorunludur | `(objectClass=*)` her yerdedir |
| `(attr=a*b*c)` alt dize | Zorunludur | Yalnızca baş, son ile herhangi bir yer; indekssiz herhangi bir yer sorgusu bir hizmet reddi vektörüdür |
| `(attr>=v)` ile `(attr<=v)` | Opsiyoneldir | Nadiren kullanılır |
| `(attr~=v)` yaklaşık eşleşme | Atlanabilir | Eşitliğe düşürülür |
| Genel `extensibleMatch` | Opsiyoneldir | — |
| `(memberOf:1.2.840.113556.1.4.1941:=CN=...)` | Özel durumdur | Active Directory'nin iç içe grup kuralıdır. GitLab dokümanı bunu açıkça örneklemekte, Grafana sunucunun zincirde eşleşme kuralını desteklemesi gerektiğini söylemektedir. Argus'ta grup hiyerarşisi zaten iç modelde vardır ve geçişli üyelik sorgusu olarak implemente edilir. Bu, Active Directory'den geçen müşterilerde tek satırlık bir yapılandırma farkı yaratır |

Eşleşme kuralı semantiği şöyledir: çoğu dize için `caseIgnoreMatch`, `caseExactMatch`, posta için `caseIgnoreIA5Match`, ayırt edici ad normalizasyonu, yani boşluk, kaçış ile harf durumu için `distinguishedNameMatch` ve `uidNumber` için `integerMatch`. Ayırt edici ad karşılaştırması RFC 4514 normalizasyonu gerektirir ve naif dize karşılaştırması hatalıdır.

Güvenlik açısından filtre değerleri iç sorguya geçerken kaçışlanmalıdır; bu, LDAP enjeksiyonunun tersidir, yani LDAP'tan SQL'e enjeksiyondur. Ayrıca sunucu tarafında sonuç limiti ile süre limiti zorunludur; istemci vermezse kendi tavanımız uygulanır.

### 3.6 Kontroller

| Kontrol | OID | Sınıflandırma |
|---|---|---|
| Sayfalı sonuçlar, RFC 2696 | `1.2.840.113556.1.4.319` | Zorunludur. Kritiklik varsayılanı yanlıştır, yani teknik olarak yok sayılabilir; ancak 1000'den fazla kullanıcılı dizinlerde Active Directory alışkanlığıyla gelen istemciler sayfalama yapar ve boyut ile çerez çifti yok sayılırsa sonsuz döngüye girerler. Çerez opak olmalıdır; durum tutmamak için sunucu tarafında imzalı veya HMAC'li bir opak token önerilir |
| Sunucu tarafı sıralama, RFC 2891 | `1.2.840.113556.1.4.473` | Opsiyoneldir; `ldap3_proto` desteklemektedir |
| Sanal liste görünümü | `2.16.840.1.113730.3.4.9` | Atlanabilir |
| ManageDsaIT | `2.16.840.1.113730.3.4.2` | Atlanabilir; yönlendirme yoksa anlamsızdır |
| Parola politikası | `1.3.6.1.4.1.42.2.27.8.5.1` | Opsiyoneldir; parola süresi ile kilit bilgisini istemciye taşımanın tek standart yoludur |
| Active Directory DirSync, ShowDeleted ile ExtendedDn | Active Directory OID'leri | Atlanabilir |
| İçerik senkronizasyonu, RFC 4533 | `1.3.6.1.4.1.4203.1.9.1.1` | Atlanabilir; ancak `ldap3_proto` desteklemektedir ve ileride replikasyon isteyen bir müşteri çıkarsa hazırdır |

### 3.7 SASL, StartTLS ile LDAPS, ne kadarı gerçekten gerekir

Şaşırtıcı sonuç şudur: hiçbir SASL mekanizması zorunlu değildir. RFC 4513 §B.2.1 bunu açıkça söyler: TLS ile korunan ad ile parola kullanan basit bind, SASL DIGEST-MD5'in yerine LDAP'ın implemente edilmesi zorunlu parola mekanizması olmuştur. DIGEST-MD5 ayrıca RFC 6331 ile tarihsel ve kullanımdan kaldırılmış ilan edilmiştir.

| Mekanizma | Argus | Gerekçe |
|---|---|---|
| Basit bind ile TLS | Zorunludur | RFC 4513 §2 bunu zorunlu kılar ve pratikte tüm istemcilerin kullandığı tek şeydir |
| SASL EXTERNAL | Opsiyoneldir | RFC 4513 §2 desteklenmesini önerir; mTLS ile yerel soket senaryosu içindir ve ucuzdur |
| SASL PLAIN | Atlanabilir | Basit bind'ın gereksiz tekrarıdır |
| SCRAM-SHA-256, RFC 5802 ile 7677 | Atlanabilir | Argus parolaları Argon2 ile sakladığı için SCRAM zaten implemente edilemez; SCRAM sunucunun PBKDF2 tabanlı saklanan anahtar ile sunucu anahtarı tutmasını gerektirir ve bu ayrı bir kimlik bilgisi tipi demektir |
| GSSAPI ile GSS-SPNEGO | LDAP'ta atlanabilir | Kerberos'u HTTP tarafında çözmek daha değerlidir, dördüncü bölüme bakınız |
| DIGEST-MD5 | Asla | RFC 6331 |

**StartTLS ile LDAPS.** RFC 4513 §3.1.1 istemcinin hem bind hem StartTLS yapacaksa önce StartTLS yapmasını önerir. Ancak Kanidm StartTLS'i kasıtlı olarak reddetmekte ve yalnızca 636 portunda LDAPS sunmaktadır; gerekçesi güvenlik riskidir, yani indirgeme ile soyma saldırıları ve istemcinin StartTLS'i atlamasının sessizce düz metin bind'a yol açmasıdır.

Argus için karar şudur: LDAPS zorunlu ve varsayılandır; StartTLS desteklenir ancak varsayılan kapalıdır ve açıldığında düz metin bind reddedilir, yani `confidentialityRequired` ile kod 13 dönülür. Böylece hem Kanidm'in güvenlik pozisyonu hem StartTLS'ten başkasını konuşamayan eski istemciler karşılanır. StartTLS'i tamamen reddetmek, saha tecrübesinde bazı VPN ile ağa bağlı depolama ürünlerini dışarıda bırakır.

**Anonim ile kimliği doğrulanmamış bind.** RFC 4513 §6.3.1 nettir: "Servers SHOULD by default fail Unauthenticated Bind requests with a resultCode of unwillingToPerform." Yani adın dolu, parolanın boş olduğu bir istek reddedilir. Bu, LDAP'ın en eski ve en sık istismar edilen tuzağıdır: naif implementasyonlar boş parolayı başarılı bir bind sayar ve tüm kimlik doğrulaması çöker. Anonim bind, yani her ikisinin de boş olması, RootDSE için gerekli olabilir; ayrı bir yetki seviyesi olarak ele alınır ve varsayılan olarak yalnızca RootDSE'ye izin verilir.

### 3.8 Yalnızca okuma yeterli midir, istemci gerçeği

| İstemci | Ne yapar | Yazma ister mi | Doğrulama |
|---|---|---|---|
| Grafana | Servis hesabıyla arama yapar veya `bind_dn` içinde yer tutucu kullanır; `member_of` veya grup arama filtresi kullanır; iç içe grup için zincirde eşleşme kuralını ister | Hayır; dokümanı açıkça yazma gerekmediğini söyler | grafana.com/docs LDAP sayfası, 8 Eylül 2026 |
| GitLab | Bağlanma ayırt edici adı ile parola kullanır; `uid` (varsayılanı `sAMAccountName`, `uid` veya `userPrincipalName`), `mail`, `cn`, `givenName` ile `sn` okur; grup senkronizasyonu için `group_base` ile `admin_group` kullanır, bu Premium ve üstündedir; Active Directory'de `userAccountControl` ikinci bitiyle devre dışı kullanıcıyı tespit eder; `(memberOf:1.2.840.113556.1.4.1941:=...)` kullanır | Hayır, salt okunur erişim ister | docs.gitlab.com LDAP sayfası, 8 Eylül 2026 |
| Jenkins ile Nextcloud | Kullanıcı araması ile grup üyeliği sorgular | Hayır; Nextcloud'un opsiyonel bir yazma modülü vardır ancak nadirdir | — |
| sssd ile nslcd | `posixAccount` ile `posixGroup` tam setini okur: `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell` ile `memberUid` | Hayır; ancak parola değiştirme için genişletilmiş operasyon ister | — |
| VPN'ler: OpenVPN, strongSwan, FortiGate ile Cisco ASA | Bind ile grup kontrolü yapar | Hayır | — |
| Ağa bağlı depolama ile hipervizörler: Synology, Proxmox, Zabbix ile pfSense | Bind ile POSIX nitelikleri okur | Hayır | — |

Sonuç şudur: yalnızca okuma senaryoların %95'ini kapatmaktadır. Tek gerçek istisna parola değiştirmedir: masaüstü Linux'ta `passwd` komutu sssd üzerinden LDAP Password Modify genişletilmiş operasyonunu çağırır, yani RFC 3062, OID `1.3.6.1.4.1.4203.1.11.1`. Bu tek bir genişletilmiş operasyondur ve Argus'un iç parola değiştirme API'sine bağlanabilir. Öneri RFC 3062'yi desteklemek ve `ModifyRequest`'i desteklemeyi reddetmektir; `userPassword` üzerinde `ModifyRequest` yapan istemci pratikte yok denecek kadar azdır.

### 3.9 Kanidm'den çıkarılacak dersler

Kanidm'in LDAP dokümanından doğrulanan davranışlar ile bunların Argus için anlamı şöyledir; erişim 8 Eylül 2026.

1. Yalnızca basit bind ile arama desteklenmektedir ve tüm yazmalar reddedilmektedir. Gerekçesi Kanidm'in iç veri yapılarının basit LDAP anahtar değer biçimine eşlenememesidir. Argus da aynı gerekçeye sahiptir ve bu bir kusur değil bir tasarım kararı olarak dokümante edilmelidir.
2. Yetki düşürme uygulanmaktadır: insan hesapları POSIX parolasıyla bind ettiğinde kendi hesap yetkilerini değil anonim seviye yetki alırlar. Yükseltilmiş okuma için `dn=token` ayırt edici adı ile API token'ı kullanan bir servis hesabı gerekir: `ldapwhoami -D "dn=token" -w "TOKEN"`. Bu, kopyalanması gereken en önemli fikirdir: LDAP kanalı tam hesap yetkisini taşımamalıdır ve LDAP'ta parola çalınması tüm hesabı vermemelidir. Argus'taki karşılığı LDAP bind için ayrı bir kimlik bilgisi sınıfı, yani bir uygulama parolası veya LDAP token'ı, ile okuma kapsamı kısıtlı bir servis kimliğidir.
3. Ayrı bir POSIX parolası vardır: LDAP bind'ı ancak hesap POSIX hesabı olarak yapılandırılmışsa ve geçerli bir POSIX parolası varsa çalışır; `set-ldap-allow-unix-password-bind false` ile kapatılabilir. Çok adımlı doğrulamanın olduğu bir dünyada LDAP bind zaten tek faktörlüdür ve ayrı, kapsamı dar bir kimlik bilgisi doğru cevaptır.
4. StartTLS yoktur, LDAPS zorunludur ve web TLS sertifikası yeniden kullanılmaktadır.
5. Ağaç yoktur, düz model vardır; `uid` eşlemesi yoktur, yalnızca `gidnumber` vardır. Argus bu iki noktada Kanidm'den daha iyisini yapmalıdır, 3.4'e bakınız.
6. Artı işaretiyle genişletilmiş eşlemeler sorgulanabilmektedir; eşlenen nitelikler `objectClass`, `name`, `spn`, `displayname`, `gidnumber`, `memberof` ile `entryuuid`'dir.

### 3.10 Rust ekosistemi, LDAP

| Crate | Sürüm | Son yayın | İndirme | Rol |
|---|---|---|---|---|
| `ldap3_proto` | 0.8.1 | 14 Ağustos 2026 | 273.468; son 90 günde yaklaşık 59.040 | Sunucu tarafı protokol bağlayıcılarıdır; Kanidm ekibindendir, github.com/kanidm/ldap3 |
| `ldap3` | — | — | — | İstemci kütüphanesidir, sunucu yazmak için değildir |
| `rasn`, `der-parser` ile `asn1-rs` | — | — | — | `ldap3_proto` yetersiz kalırsa ham BER içindir |

`ldap3_proto` 0.8.1'in docs.rs API yüzeyinden doğrulanan kapsamı şöyledir, erişim 8 Eylül 2026.

`LdapOp` varyantları `BindRequest` ile `BindResponse`, `UnbindRequest`, `SearchRequest`, `SearchResultEntry`, `SearchResultReference`, `SearchResultDone`, `ModifyRequest` ile `ModifyResponse`, `AddRequest` ile `AddResponse`, `DelRequest` ile `DelResponse`, `ModifyDNRequest` ile `ModifyDNResponse`, `CompareRequest`, `CompareResult`, `AbandonRequest`, `ExtendedRequest` ile `ExtendedResponse` ve `IntermediateResponse`'tur; yani RFC 4511'in tam operasyon seti kablo seviyesinde mevcuttur.

Hazır yapılar RFC 3062 için `LdapPasswordModifyRequest` ile `LdapPasswordModifyResponse`, RFC 4532 için `LdapWhoamiRequest` ile `LdapWhoamiResponse` ve bunların `OID_PASSWORD_MODIFY` ile `OID_WHOAMI` sabitleri, genişletilebilir eşleşme için `LdapMatchingRuleAssertion`, ayrıca `LdapSubstringFilter`, `SaslCredentials`, `LdapDerefAliases`, `LdapSearchScope` ile `LdapResultCode`'dur.

`LdapControl` varyantları `SimplePagedResults`, `ServerSort`, `ServerSortResult`, `ManageDsaIT`, `PasswordPolicyRequest`, RFC 4533 için `SyncRequest`, `SyncState` ile `SyncDone`, ayrıca `AdDirsync`, `ExtendedDn`, `ShowDeleted`, `SearchOptions`, `SdFlags` ile `Unknown`'dır.

`LdapCodec` tokio-util tabanlı çerçevelemeyi sağlar. Ayrıca RFC 4515 dizesini `LdapFilter` yapısına çeviren bir filtre ayrıştırma fonksiyonu dışa aktarılmaktadır.

Değerlendirme şudur: LDAP, beş protokol içinde Rust ekosisteminin en iyi durumda olduğu alandır. Codec, ASN.1, kontroller ile genişletilmiş operasyonlar hazırdır. Argus'un yazması gereken şey protokol değil semantiktir: dizin ağacı izdüşümü, filtreden sorguya çeviri, şema üretimi, sayfalama çerezi, yetki modeli ile TLS sonlandırması.

Eksik olan şudur: `ldap3_proto` bir çatı değil yalnızca protokoldür. Bağlantı yaşam döngüsü, eşzamanlı istek yönetimi (bir bağlantıda çoklu mesaj kimliği), abandon semantiği ile TLS geçişi (StartTLS sonrası aynı soket üzerinde TLS'e yükseltme) bizim işimizdir.

### 3.11 LDAP efor tahmini

| İş kalemi | Tahmin |
|---|---|
| Bağlantı, codec, TLS ile StartTLS yaşam döngüsü | 1 ile 1,5 hafta |
| RootDSE ile alt şema üretimi | 1 hafta |
| Dizin ağacı izdüşümü ve yapılandırılabilir nitelik eşleme motoru | 2 hafta |
| Filtre ayrıştırıcısından iç sorguya çeviri ile ayırt edici ad normalizasyonu | 2 hafta |
| Sayfalama (opak imzalı çerez), boyut ile süre limiti | 1 hafta |
| Bind yetki modeli: ayrı LDAP kimlik bilgisi ile servis token'ı | 1 hafta |
| RFC 3062 parola değiştirme ile WhoAmI | 0,5 hafta |
| Gerçek istemci uyum testleri: sssd, Grafana, GitLab, Jenkins ile bir VPN | 2 hafta |
| Toplam | Yaklaşık 10 ile 11 hafta, tek mühendis |

---

## Bölüm 4 — Kerberos ve Active Directory entegrasyonu

### 4.1 Doğru soru Kerberos implemente etmeli miyiz değil, Kerberos'un neresinde durmalıyız

Modern bir IdP'nin Kerberos ile üç olası ilişkisi vardır ve bunları karıştırmak bu konudaki en yaygın planlama hatasıdır.

| Rol | Ne demek | Argus için |
|---|---|---|
| KDC olmak | Kendi alanını işletmek, bilet vermek, kimlik doğrulama ile bilet verme isteklerini işlemek, principal veritabanı tutmak | Asla. Bu ayrı bir üründür: FreeIPA, Samba AD veya MIT KDC. Ölçülemez risk ve sıfır ticari getiri vardır |
| Kerberos servis sağlayıcısı, yani SPNEGO kabul edicisi | Tarayıcıdan gelen `Authorization: Negotiate` başlığını kabul edip keytab ile GSSAPI üzerinden kullanıcı kimliğini çıkarmak | Hedef budur. Argus'un giriş sayfasında kurumsal ağdan gelen kullanıcının parola girmediği deneyimi sağlar |
| Kerberos istemcisi | Downstream servislere kullanıcı adına bilet almak, yani kısıtlı delegasyon ile S4U2Proxy | Opsiyonel ve ileri seviyedir. Nadirdir ancak yüksek değerlidir; PAM ile eski uygulama senaryoları içindir |

Yani Argus'un yapması gereken HTTP Negotiate kabul edicisi ile Active Directory'den kullanıcı senkronizasyonudur. Bu, Keycloak'ın Kerberos köprüsü dediği şeyle aynı kapsamdadır: "Kerberos bridge — Automatically authenticate users that are logged-in to a Kerberos server." Kaynağı keycloak.org/docs/latest/server_admin'dir, erişim 8 Eylül 2026.

### 4.2 SPNEGO ile Negotiate protokol mekaniği, RFC 4559

RFC 4559 metninden doğrulanan akış şöyledir; kaynağı rfc-editor.org/rfc/rfc4559.txt'tir, erişim 8 Eylül 2026.

1. İstemci korumalı kaynağı `Authorization` başlığı olmadan ister.
2. Sunucu 401 döner ve `WWW-Authenticate: Negotiate` verir; ilk meydan okuma token taşımaz.
3. İstemci SPNEGO mekanizmasıyla bir GSSAPI token'ı üretir ve base64 kodlar: `Authorization: Negotiate <base64-gssapi-data>`. Spesifikasyon şöyle der: "gssapi-data contains the base64 encoding of an initialContextToken", RFC 2743.
4. Sunucu token'ı `gss_accept_sec_context` fonksiyonuna verir. Bağlam tamamlanmadıysa 401 ile `WWW-Authenticate: Negotiate <token>` dönerek devam eder; bu çok turlu olabilir.
5. Bağlam tamamlandığında sunucu 200 döner ve isteğe bağlı olarak `WWW-Authenticate: Negotiate <final-token>` ile karşılıklı kimlik doğrulama sağlar; istemci bunu `gss_init_security_context` fonksiyonuna vererek sunucuyu doğrular.

Implementasyon açısından kritik noktalar şunlardır.

Çok turlu olması bir durum yönetimi gerektirir. HTTP durumsuzdur, ancak GSSAPI bağlamı turlar arasında yaşamalıdır. Bunu bağlantıya bağlamak gerekir, yani HTTP/1.1 kalıcı bağlantısına; bu yüzden `axum-negotiate-layer` gibi kütüphaneler `into_make_service_with_connect_info` ile bağlantı bilgisini taşımaktadır. HTTP/2 ile ters vekil arkasında bu kırılır; Negotiate bağlantı yönelimli bir kimlik doğrulamadır ve HTTP semantiğine aykırıdır.

RFC 4559 güvenlik değerlendirmesi şunu söyler: HTTP başlıkları korunmamaktadır, dolayısıyla kanal güvenliği yani TLS şarttır; vekil arkasında istemci `Proxy-support: Session-Based-Authentication` başlığını doğrulamadan kimlik doğrulamamalıdır, aksi hâlde güvenlik bağlamı karışır.

Tarayıcı tarafında yapılandırma zorunludur. Hiçbir tarayıcı rastgele bir siteye Kerberos bileti vermez. Chrome ile Edge'de `AuthServerAllowlist`, Firefox'ta `network.negotiate-auth.trusted-uris` politikası gerekir. Microsoft'un Seamless SSO dokümanı bunu tabloda açıkça işaretlemektedir: Firefox ile macOS'taki Chrome ek yapılandırma gerektirmektedir; kaynağı learn.microsoft.com'un `how-to-connect-sso` sayfasıdır, güncellemesi 26 Şubat 2026, erişim 8 Eylül 2026.

Yedek yol zorunludur. Negotiate başarısız olursa, yani bilet yoksa, servis principal adı yanlışsa veya kullanıcı ağ dışındaysa, kullanıcı normal giriş formuna düşmelidir. Microsoft bunu fırsatçı bir özellik olarak tanımlamaktadır: "If it fails for any reason, the user sign-in experience goes back to its regular behavior."

### 4.3 Keytab ve servis principal adı yönetimi, operasyonel gerçek

| Konu | Gereksinim |
|---|---|
| Servis principal adı biçimi | `HTTP/idp.example.com@EXAMPLE.COM` biçimindedir ve DNS adıyla birebir eşleşmelidir. Yük dengeleyici arkasındaki farklı bir ad sessiz bir başarısızlık demektir |
| Keytab dosyası | Active Directory'de `ktpass` veya `setspn` ile `ktpass` kullanılarak üretilir; şifreleme tipi seçimi kritiktir, `AES256-SHA1` kullanılır ve RC4 artık devre dışı bırakılmaktadır |
| Anahtar rotasyonu | Keytab'ın anahtar sürüm numarası Active Directory'dekiyle eşleşmelidir. Parola değişince eski keytab bozulur ve en sık üretim arızası budur |
| Çoklu örnek | Aynı keytab tüm Argus düğümlerinde bulunmalıdır, yani paylaşılan bir sırdır. Sır yönetimine, yani bir kasa veya anahtar yönetim servisine girmeli, konteyner imajına gömülmemelidir |
| Alanlar arası | Birden çok orman veya alan varsa alan başına güven ve muhtemelen ayrı bir servis principal adı gerekir |
| Delegasyon | RFC 4559 delegasyonu desteklemektedir ancak Keycloak dokümanı da bunu sınırlamalar arasında saymaktadır; varsayılan kapalı tutulur |

Karar önerisi şudur: keytab Argus'un birincil sır deposunda tutulur, dosya sisteminden değil bellekten yüklenir ve anahtar sürüm numarası uyuşmazlığında açık ve okunabilir bir hata üretilir. Bu son madde bir özellik değildir, satış sonrası destek maliyetinin yarısıdır.

### 4.4 Active Directory'den kullanıcı senkronizasyonu, üç kalıp

| Kalıp | Nasıl | Artı | Eksi | Ne zaman |
|---|---|---|---|---|
| LDAP ile çekme | Argus, Active Directory'ye LDAP istemcisi olarak bağlanır ve periyodik olarak ya da `uSNChanged` veya DirSync ile artımlı çeker | Ek bileşen yoktur; Keycloak'ın LDAP kullanıcı federasyonu modelidir ve herkes tanır | Ağ erişimi gerekir, çünkü Active Directory genelde iç ağdadır; parola doğrulaması ya Active Directory'ye devredilir ya senkronlanmaz; silme tespiti mezar taşı kayıtları nedeniyle zordur | Varsayılandır ve faz 1'dedir |
| SCIM ile itme | Active Directory tarafındaki bir ajan veya Entra, Argus'a SCIM ile iter | Argus'un ağ erişimine ihtiyacı yoktur; olay tabanlıdır ve gecikme düşüktür; SCIM sunucusu zaten yazılmaktadır | Karşı tarafta sağlama yapılandırması gerekir; saf yerinde Active Directory'de yerleşik bir SCIM istemcisi yoktur | Kaynak Entra ID ise en iyi seçenektir |
| Ajan, yani dışa dönük bağlayıcı | Müşteri ağında çalışan hafif bir Argus ajanı dışa doğru bağlantı kurar | Güvenlik duvarı dostudur; Active Directory'ye içeriden erişir; parola doğrulamasını da vekilleyebilir, ki bu Entra'nın geçişli kimlik doğrulama modelidir | Ayrı bir üründür: dağıtım, güncelleme, gözetim ile güvenlik yüzeyi getirir | Faz 3 ve sonrası; kurumsal satış zorlarsa |

Kritik alt karar paroladır: Active Directory kullanıcılarının parolası Argus'ta nasıl doğrulanacaktır. Birinci seçenek delegasyondur, yani her girişte Active Directory'ye LDAP basit bind yapmaktır; basit ve doğrudur ancak Active Directory'ye çevrimiçi bir bağımlılık yaratır. İkinci seçenek hash senkronizasyonudur, yani Active Directory parola hash'lerini çekmektir, ki Entra Connect'in parola hash senkronizasyonu budur; yüksek ayrıcalık, yani DCSync, gerektirir ve güvenlik incelemesinden zor geçer. Üçüncü seçenek Kerberos ile SPNEGO'dur ve parola hiç görülmez. Öneri birinci ile üçüncü seçenektir; ikincisi yapılmaz.

### 4.5 2026'da hâlâ gerekli midir, dürüst cevap

**Birinci sinyal: Microsoft kendi Kerberos tabanlı çözümünden uzaklaşmaktadır.** Entra Seamless SSO dokümanı, 26 Şubat 2026 güncellemesiyle şöyle demektedir: "For Windows 10, Windows Server 2016, and later versions, it's recommended to use SSO via primary refresh token (PRT). For Windows 7 and Windows 8.1, it's recommended to use Seamless SSO." Seamless SSO ayrıca Entra'ya katılmış ile hibrit katılmış cihazlarda kullanılmamaktadır. Yani Microsoft, modern Windows filosunda Kerberos tabanlı tarayıcı çoklu oturum açmasını terk etmiş ve birincil yenileme token'ına geçmiştir.

**İkinci sinyal: ancak Kerberos ölmemiş, yalnızca yer değiştirmiştir.** Hâlâ zorunlu olduğu yerler yerinde Active Directory'ye bağlı Linux masaüstü ile sunucu filoları (sssd ile GSSAPI), alana katılmış Windows makinelerinden iç web uygulamalarına çoklu oturum açma yani klasik intranet, kamu, savunma, sağlık ile üniversite segmentleri yani hava boşluklu veya hibrit ağlar, ve ülke ya da kurum politikası gereği bulut IdP istemeyen alıcılardır. Argus'un hedef segmenti tam olarak burası olabilir.

Sonuç şudur: Kerberos Argus için bir ürün genişliği değil bir satış kapısı meselesidir. Rakip Keycloak bunu desteklemektedir; desteklenmezse belirli ihalelerde elenilir. Ancak kullanım oranı düşüktür.

Sınıflandırması şöyledir. Kurumsal segmente satış yapılacaksa zorunlu olanlar HTTP Negotiate kabul edicisi, keytab yönetimi, Active Directory LDAP senkronizasyonu ile Active Directory'ye bind delegasyonudur. Opsiyonel olanlar alanlar arası güven, S4U2Proxy ile kısıtlı delegasyon ve PKINIT'tir. Atlanabilir olanlar KDC olmak, kendi principal veritabanını tutmak, bilet önbelleği yönetimi ile NTLM'dir; NTLM kesinlikle yapılmaz, çünkü Microsoft onu emekliye ayırmaktadır.

### 4.6 Rust ekosistemi, Kerberos ile GSSAPI

crates.io API'sinden doğrulanmış veriler, 8 Eylül 2026:

| Crate | Sürüm | Son yayın | Toplam indirme | Son 90 gün | Değerlendirme |
|---|---|---|---|---|---|
| `libgssapi` | 0.11.0 | 30 Mayıs 2026 | 1.203.363 | 571.340 | Ana seçenektir. MIT lisanslı, güvenli bir GSSAPI (RFC 2744) bağlayıcısıdır. MIT krb5, Heimdal ile Apple GSS çatısına karşı bir entegrasyon test süiti vardır. `gss_accept_sec_context` dahil kabul edici tarafını desteklemektedir, ki SPNEGO sunucusu için gereken tam olarak budur. `s4u` özelliğiyle kısıtlı delegasyon sunar, yalnızca MIT'te |
| `cross-krb5` | 0.5.0 | 31 Mayıs 2026 | 949.875 | 497.685 | Basitleştirilmiş çapraz platform Kerberos 5 arayüzüdür; Windows'ta SSPI'ye, POSIX'te GSSAPI'ye eşler. `libgssapi`'nin yazarı estokes tarafından yazılmıştır |
| `axum-negotiate-layer` | 0.3.1 | 28 Nisan 2026 | 4.453 | 96 | Hazır bir axum tower katmanıdır: `NegotiateLayer::new(Some("HTTP/example.com"))` ile kullanılır ve `Authenticated` uzantısıyla istemci principal'ını verir. Bağlantı bilgisini `into_make_service_with_connect_info::<NegotiateInfo>()` ile taşır, yani bağlantıya bağlı bağlam sorununu çözmüştür. Ancak kullanım hacmi çok düşüktür, son 90 günde 96 indirme; referans olarak okunur, doğrudan bağımlılık yapmadan önce denetlenir |
| `synta-krb5` | 0.3.3 | 1 Ağustos 2026 | 1.064 | — | Kerberos V5 ile GSSAPI ASN.1 yapılarıdır, codeberg.org/abbra/synta. Saf Rust ASN.1 katmanıdır ve FreeIPA ekosisteminden Alexander Bokovoy'un projesidir. Olgunluğu düşüktür ancak gerçektir |
| `krb5-rs` | 0.1.0 | 15 Mart 2026 | 80 | — | "Pure Rust Kerberos V5: GSSAPI, SPNEGO, PKINIT. No C FFI" iddiasındadır. Tek sürümü ile 80 indirmesi vardır ve hiç güncellenmemiştir. İddia büyüktür, kanıt yoktur; kullanılmaz |
| `sspi` (Devolutions) | — | — | — | — | Windows tarafı için bir alternatiftir; doğrulanmamıştır, bu araştırmada sürümü çekilmemiştir |

Sonuç şudur: Argus C bağımlılığından kaçamaz. `libgssapi` MIT krb5 veya Heimdal'a linklenir; bu, konteyner imajına `libkrb5` ile `/etc/krb5.conf` girmesi demektir. Saf Rust bir GSSAPI ile SPNEGO kabul edicisi 2026'da üretime hazır değildir. Bu, Kerberos özelliğinin bir feature bayrağı arkasında ve ayrı bir imaj varyantında olmasını gerektirir.

### 4.7 Kerberos efor tahmini

| İş kalemi | Tahmin |
|---|---|
| SPNEGO kabul edicisi: `libgssapi` entegrasyonu, çok turlu bağlam ile bağlantıya bağlı durum | 2 hafta |
| Keytab yükleme, rotasyon ile sır entegrasyonu ve teşhis mesajları | 1 hafta |
| Giriş akışına Negotiate adımının entegrasyonu ile yedek yol | 1 hafta |
| Active Directory LDAP senkronizasyonu: artımlı, DirSync veya `uSNChanged`, silme tespiti ile nitelik eşleyici | 3 hafta |
| Active Directory'ye bind delegasyonu | 0,5 hafta |
| Gerçek Active Directory ortamında test, kurulum dahil | 1,5 hafta |
| Toplam | Yaklaşık 9 hafta, tek mühendis; Active Directory test ortamı kurmanın gizli maliyeti yüksektir |

---

## Bölüm 5 — OpenID Federation 1.0 ile 1.1

### 5.1 Spesifikasyon durumu, verilen tarihler doğrulanmıştır

| Öğe | Durum | Kaynak |
|---|---|---|
| OpenID Federation 1.0 | Final spesifikasyon olarak 17 Şubat 2026'da onaylanmıştır. Oylama 85 kabul, sıfır itiraz ile 20 çekimserdir; 105 oy, 425 üyenin %24,7'sidir ve %20 yeter sayısının üzerindedir | openid.net'in ilgili duyurusu, 8 Eylül 2026 |
| OpenID Federation 1.1 | Final olarak 6 Mayıs 2026'da onaylanmıştır. Oylama 83, sıfır ile 21'dir; 104 oy, 418 üyenin %24,9'udur | openid.net'in ilgili duyurusu, 8 Eylül 2026 |
| OpenID Federation for OpenID Connect 1.1 | Aynı oylamada final onaylanmıştır | Aynı |
| Yayın tarihi tutarsızlığı | OIDF duyurusu yayın tarihini 6 Mayıs 2026 derken Mike Jones'un yazısı 11 Mayıs 2026 demektedir. Küçük bir tutarsızlıktır ve normatif önemi yoktur | self-issued.info |

**1.1 ne değiştirmiştir.** Spesifikasyon editörlerinden Mike Jones nettir: hiçbir işlevsellik eklenmemiş veya çıkarılmamıştır. "Together, they are equivalent to OpenID Federation 1.0, by design." Yapılan iş bir ayrıştırmadır.

OpenID Federation 1.1 protokolden bağımsız kısımdır: entity statement, güven zinciri, metadata, politika, güven işareti ile federasyon endpoint'leri. OpenID Federation for OpenID Connect 1.1 ise OIDC ile OAuth 2.0'a özgü kısımdır: varlık tipleri ile istemci kayıt akışları. Bölüm numaraları 1.0 ile hizalı tutulmuştur, böylece iki sürüm birbirinin yerine kullanılabilir. Ayrıştırma kararı Nisan 2025'te SUNET'teki Federation Interop etkinliğinde alınmıştır.

Argus için pratik sonuç şudur: 1.1 çifti hedeflenir. Protokolden bağımsız çekirdek, yani entity statement, güven zinciri ile politika motoru, ayrı bir modül olarak yazılır, çünkü spesifikasyon da tam olarak bu ayrımı yapmıştır ve gelecekte OIDC dışı profiller, örneğin Avrupa dijital kimlik cüzdanı ile ajansal kimlik, aynı çekirdeği kullanacaktır.

### 5.2 Dokuz ülkenin interop testi doğrulanmıştır ancak içeriği abartılmamalıdır

| Öğe | Doğrulanan |
|---|---|
| Etkinlik | TIIME, yani Trust and Internet Identity Meeting Europe, konferans dışı formatta, Amsterdam |
| Tarih | 13 Şubat 2026; OIDFed 1.0'ın final olmasıyla aynı haftaya denk gelmiştir |
| Katılım | "Twelve participants representing nine implementations and nine countries" |
| Ülkeler | Hırvatistan, Finlandiya, Yunanistan, İtalya, Hollanda, Polonya, Sırbistan, İsveç ile ABD |
| Organizatörler | Niels van Dijk (SURFnet), Davide Vaghetti (GARR) ile Giuseppe De Marco (İtalya Dijital Dönüşüm Dairesi, OpenID Federation Browser aracının yazarı) |
| Süreklilik | Etkinlik için kurulan test federasyonu sonrasında aktif kalmaya devam etmiştir |

Ne kanıtlanmadığı da önemlidir: OIDF'in duyuru metni hangi endpoint'lerin ve hangi akışların test edildiğini belirtmemekte ve hiçbir sınırlama veya sorun raporlamamaktadır. Bu, dokuz bağımsız implementasyonun aynı güven zincirini çözebildiği anlamına gelir; güçlü bir sinyaldir ancak bir uyum sertifikasyon programı değildir. Bu bir uygunluk süiti olarak sunulmamalıdır.

Karşılaştırma için önceki etkinlik Stockholm'de 28 ile 30 Nisan 2025 arasında yapılmış ve 30 delege, 14 implementasyon ile 15 ülke katılmıştır; kaynağı oidfed.com/ecosystem'dir, 8 Eylül 2026. Yani katılım Amsterdam'da daralmış görünmektedir ve bu muhtemelen konferans dışı formatın doğal sonucudur.

### 5.3 Normatif gereksinim listesi, Federation 1.1

#### 5.3.1 Entity statement claim'leri

Entity Configuration ile Subordinate Statement'ta ortak olanlar §3.1.1'dedir.

| Claim | Durum |
|---|---|
| `iss` | Zorunludur; issuer varlık tanımlayıcısıdır |
| `sub` | Zorunludur; özne varlık tanımlayıcısıdır ve Entity Configuration'da `iss` ile `sub` eşittir |
| `iat` | Zorunludur |
| `exp` | Zorunludur |
| `jwks` | Çoğu durumda zorunludur; federasyon anahtarlarıdır |
| `metadata` | Opsiyoneldir |
| `crit` | Opsiyoneldir |

Yalnızca Entity Configuration'da bulunanlar (§3.1.2) üst otoriteleri gösteren `authority_hints`, ayrıca `trust_anchor_hints`, `trust_marks`, `trust_mark_issuers` ile `trust_mark_owners`'tır; hepsi opsiyoneldir.

Yalnızca Subordinate Statement'ta bulunanlar (§3.1.3) `constraints` (§6.2), `metadata_policy`, `metadata_policy_crit` ile `source_endpoint`'tir; hepsi opsiyoneldir.

Entity statement doğrulaması spesifikasyonda §3.2'de 25 adımlık bir süreç olarak tanımlıdır. Bunu bir kontrol listesi olarak koda dökmek gerekir; JWT'yi doğrula ve bitir değildir.

Keşif adresi `https://<entity-identifier>/.well-known/openid-federation` biçimindedir. Varlık tanımlayıcısı bir HTTPS URL'idir ve well-known yolu path'in sonuna eklenir; bu bir path soneki semantiğidir ve RFC 8615'in klasik ana dizin varsayımından farklıdır. Bu, çok kiracılı Argus'ta her kiracının kendi varlık tanımlayıcısı olabilmesi demektir.

#### 5.3.2 Federasyon endpoint'leri (§8), rol bazlı zorunluluk

| Endpoint | Metadata parametresi | Yaprak OP, yani Argus | Ara düğüm | Güven çıpası |
|---|---|---|---|---|
| Fetch (§8.1) | `federation_fetch_endpoint` | Bulunmamalıdır | Zorunludur | Zorunludur |
| Alt liste (§8.2) | `federation_list_endpoint` | Bulunmamalıdır | Zorunludur | Zorunludur |
| Resolve (§8.3) | `federation_resolve_endpoint` | Olabilir | Olabilir | Olabilir |
| Güven işareti durumu (§8.4) | `federation_trust_mark_status_endpoint` | — | — | Güven işareti verenler için önerilir |
| Güven işareti listesi (§8.5) | `federation_trust_mark_list_endpoint` | — | — | Olabilir |
| Güven işareti (§8.6) | `federation_trust_mark_endpoint` | — | — | Olabilir |
| Tarihsel anahtarlar (§8.7) | `federation_historical_keys_endpoint` | Olabilir | Olabilir | Olabilir |

Dikkat edilmelidir ki yaprak için fetch ile listeleme endpoint'leri bulunmamalıdır. Yani her ihtimale karşı hepsini açalım yaklaşımı bir spesifikasyon ihlalidir. Argus'un rolü çalışma zamanında yapılandırılabilir olmalı ve rol değiştiğinde entity configuration'daki metadata otomatik değişmelidir.

#### 5.3.3 Metadata politika operatörleri (§6.1.3.1)

| Operatör | Etki | Uygulama sırası | Üstten alta birleştirme |
|---|---|---|---|
| `value` | Parametreyi atar veya kaldırır | 1 | Yalnızca değerler eşitse |
| `add` | Değer ekler | 2 | Birleşim alınır |
| `default` | Yoksa atar | 3 | Değerler eşleşmelidir |
| `one_of` | Sayılan değerlerle sınırlar | 4 | Kesişim alınır |
| `subset_of` | Dizinin alt küme olmasını ister | 5 | Kesişim alınır |
| `superset_of` | Dizinin üst küme olmasını ister | 5, `one_of` sonrası | Birleşim alınır |
| `essential` | Parametreyi zorunlu kılar | Son | Yalnızca ikisi de doğruysa |

Politika ilkeleri §6.1.1'dedir: hiyerarşi, eşit fırsat, özgüllük, işlem, bütünsel uygulama ile determinizm. Pratikte bunun anlamı şudur: üstteki otorite alttakinin politikasını gevşetemez, yalnızca daraltabilir; ve birleştirme sonucu deterministik olmalıdır, çelişki varsa güven zinciri reddedilir.

Bu, implementasyonun en hatalı yazılan parçasıdır. Politika birleştirme saf ve test edilebilir bir fonksiyon olarak yazılmalı ve spesifikasyonun örnekleri birim testine dönüştürülmelidir.

#### 5.3.4 Güven zinciri çözümleme (§10.2)

1. Öznenin, genelde yaprağın, entity configuration'ı çekilir.
2. `authority_hints` üzerinden üst otoritelerin entity configuration'ları alınır.
3. Her üstten, özne hakkındaki subordinate statement fetch endpoint'iyle çekilir.
4. Her adımda imza bir üstteki statement'ın `jwks` değeriyle doğrulanır.
5. Yapılandırılmış güven çıpasına ulaşana kadar yukarı çıkılır.
6. Güven çıpasının kendi entity configuration imzası doğrulanır.
7. Zincirdeki tüm subordinate statement'ların metadata politikaları uygulanır.
8. Çözülmüş metadata'nın tüm politikalara uyduğu doğrulanır.

Zincir geçerliliği tüm statement'ların `exp` değerlerinin asgarisidir (§10.4). Önbellek yaşam süresi buna bağlanmalıdır, HTTP `Cache-Control` değerine değil.

#### 5.3.5 Güven işareti (§7)

```
{ "trust_mark_type": "<identifier>", "trust_mark": "<signed JWT>" }
```

Güven işareti JWT'si `iss` (veren), `sub` (sahip varlık), `trust_mark_type`, `iat` ile `exp` taşır. Güven işareti delegasyonu (§7.2.1), güven işareti sahibi tarafından imzalanmış ayrı bir JWT'dir ve verme yetkisini başkasına devreder.

> **Sürüm tuzağı.** 1.1'de claim adı `trust_mark_type`'tır. Eski taslaklarda `id` veya `trust_mark_id` görülür. İtalyan SPID gibi eski taslaklara göre yazılmış implementasyonlarla interop yaparken bu isim farkı ilk kırılma noktasıdır.

#### 5.3.6 Varlık tipleri

`federation_entity` (§5.1.1) protokolden bağımsız kısımda tanımlıdır: endpoint'ler ile `organization_name` ve `logo_uri` gibi bilgisel parametreler içerir. `openid_provider`, `openid_relying_party`, `oauth_authorization_server`, `oauth_resource` ile `oauth_client` gibi tipler profillerde veya Connect spesifikasyonunda tanımlıdır.

### 5.4 İstemci kaydı, Argus'un OP olarak yapması gereken

**Otomatik kayıt, Connect 1.1 §12.1.** İlgili taraf önceden kayıt olmaz ve kendi varlık tanımlayıcısını `client_id` olarak kullanır. Kimlik doğrulama asimetrik kriptoyla zorunludur ve istemci sırrı yoktur. İstek nesnesinin zorunlu alanları (§12.1.1.1) `aud` (OP'nin varlık tanımlayıcısı), `client_id` ile `iss` (ilgili tarafın varlık tanımlayıcısı), tekrar kullanımı engellemek için `jti` ve `exp`'tir. OP tarafındaki akış şöyledir: `client_id` bir URL olarak alınır, ilgili tarafın entity configuration'ı çekilir, güven zinciri çözülür, metadata politikası uygulanır ve çözülmüş ilgili taraf metadata'sı o istek için bir istemci kaydı gibi kullanılır.

**Açık kayıt (§12.2).** İlgili taraf, OP'nin `federation_registration_endpoint` adresine POST eder. Gövde ya bir entity configuration'dır, içerik tipi `application/entity-statement+jwt`, ya tam güven zinciridir, içerik tipi `application/trust-chain+json`. OP doğrular, güven zincirini çözer, metadata'yı uyum için değiştirebilir ve güven zincirinin `exp` değerini aşmayan bir geçerlilik süresi atar. Yanıt bir entity statement'tır, içerik tipi `application/explicit-registration-response+jwt`'tir ve içinde atanan `client_id` bulunur. OP, varlık tanımlayıcısından farklı bir `client_id` verebilir; bu, mevcut dinamik istemci kaydı altyapısının üzerine inşa etmeyi mümkün kılar.

Metadata parametreleri OP tarafında `client_registration_types_supported` (`automatic` ve ya da `explicit`) ile açık kayıt destekleniyorsa `federation_registration_endpoint`'tir; ilgili taraf tarafında `client_registration_types`'tır.

### 5.5 İstemci çözümleme katmanı, üç kaynaktan gelen kimlik

Argus'ta bir `client_id` üç farklı anlama gelebilir ve bu, tasarımın en kritik mimari kararıdır.

| Yol | `client_id` nedir | Güven kaynağı | Metadata kaynağı | İptal ile rotasyon |
|---|---|---|---|---|
| Dinamik istemci kaydı, RFC 7591 | Argus'un ürettiği opak bir dizedir | Argus'un kendi kaydıdır | Yerel veritabanıdır | Yerel silmedir |
| CIMD, `draft-ietf-oauth-client-id-metadata-document`, revizyon -02, 6 Temmuz 2026, Datatracker ile doğrulanmıştır | İstemcinin barındırdığı bir HTTPS URL'idir | Yoktur; yalnızca alan adı kontrolüdür, ilk kullanımda güven benzeridir | URL'den canlı çekilir | URL'i kaldırmaktır |
| OpenID Federation | İlgili tarafın varlık tanımlayıcısıdır, bir HTTPS URL'idir | Güven çıpasına kadar uzanan imza zinciridir | Güven zinciri ile metadata politikasıyla çözülür | Subordinate statement'ı çekmek veya güven işaretini iptal etmektir |

Tasarım kuralları şunlardır.

1. Tek bir istemci çözümleyici soyutlaması yazılır. Girdisi `client_id` ile istek bağlamı, çıktısı metadata, güven seviyesi, kaynak, sona erme zamanı ile uygulanan politikayı taşıyan çözülmüş bir istemcidir. Protokol katmanı bu üç yolu ayırt etmemelidir.
2. Güven seviyesi birinci sınıf bir alan olmalıdır. Federasyonla gelen bir istemci, CIMD ile gelenden farklı yetkilere sahip olmalıdır. Örnek politika şudur: CIMD istemcileri hassas scope'ları isteyemez, onay ekranı her zaman gösterilir ve bu uygulamanın doğrulanmadığı uyarısı çıkar; federasyon istemcilerinde güven işareti varsa onay atlanabilir.
3. Çakışma çözümünde sıra sabit ve deterministik olmalıdır: `client_id` bir HTTPS URL'i ise önce federasyon denenir, yani entity configuration çekilebiliyor ve güven zinciri çözülüyorsa, sonra CIMD denenir; URL değilse yerel dinamik kayıt kullanılır. URL biçimindeki bir `client_id`'nin yerel kayda düşmesine asla izin verilmez, çünkü bu bir kayıt kaçırma veya karıştırma saldırısıdır.
4. Kiracı başına hangi yolların açık olduğu yapılandırılabilir olmalıdır. Çoğu kiracı yalnızca dinamik kayıt isteyecektir; federasyonu açan az sayıdaki kiracı için ekstra ağ trafiği ile gecikme kabul edilebilir olacaktır.
5. Önbellek ile tazelik ayrı ayrı yönetilmelidir: federasyonda yaşam süresi güven zincirinin asgari `exp` değeridir, CIMD'de HTTP önbellek başlıkları ile kendi tavanımızdır. Her ikisinde de SSRF savunması zorunludur: özel IP aralıkları engellenir, yönlendirme sayısı sınırlanır, boyut sınırı konur ve DNS yeniden bağlamasına karşı bağlantı anındaki IP kontrol edilir.
6. Argus'un MCP dokümanındaki uyarıyla tutarlı olunmalıdır: §14'ün 5.2 bölümü, MCP spesifikasyonunun CIMD -00'a atıf yaptığını ancak -02'nin yeni normatif zorunluluklar getirdiğini ve -02'nin uygulanması gerektiğini söylemektedir. Aynı çözümleyici bu farkı taşımalıdır.

### 5.6 Kim implemente etti, ekosistem

Kaynakları oidfed.com/ecosystem, 8 Eylül 2026, ile OIDF kaynaklarıdır.

| Alan | Uygulama |
|---|---|
| İtalya | SPID ile CIE OIDC Federation; teknik kurallar Ocak 2023'te yayımlanmıştır. Ulusal elektronik kimlik, 2022'de IdP federasyonu için OpenID Federation'ı seçmiştir |
| İsveç | Sweden Connect teknik çerçevesi 2025 içinde OpenID Federation desteği eklemektedir |
| Avrupa Birliği | Avrupa dijital kimlik cüzdanı ile eIDAS 2.0, sınır ötesi cüzdan güveni için OpenID Federation'a atıf yapmaktadır |
| GÉANT ile eduGAIN | Temmuz 2025'te başlayan on iki aylık bir pilot, SAML ile paralel yürümektedir |
| SUNET | `satosa-idpy`, OpenID Federation yetenekli bir OP ön yüzü olarak referans implementasyondur |
| Ticari | Authlete, Connect2id ile Raidiam Connect |

Kütüphaneler dil bazında şöyledir: Go'da `zachmann/go-oidfed`; Java'da Nimbus OAuth 2.0 SDK ile `italia/spid-cie-oidc-java`; Kotlin'de Sphereon; Python'da `rohe/fedservice` ile `italia/spid-cie-oidc-django`; PHP'de `simplesamlphp/openid`; Node.js'te `italia/spid-cie-oidc-nodejs`; TypeScript'te Apache 2.0 lisanslı `@oidfed/*`. Rust listede yoktur.

Keycloak için OpenID Federation eklentisi olduğuna dair topluluk yazıları vardır; bucchi.medium.com'da güven zinciriyle özelleştirilmiş bir dinamik kayıt endpoint'i anlatılmaktadır. Resmî Keycloak dokümanından doğrulanamamıştır; çekirdek bir özellik mi eklenti mi olduğu belirsizdir.

Kanidm'de GitHub Discussion #4154 (Şubat 2026) OpenID Federation'ın SAML yerine modern ve OIDC yerlisi bir yol olarak değerlendirildiği bir tartışmadır. Bakımcı Firstyear 20 Şubat 2026'da şöyle demiştir: "We need to understand the protocol and problem space first before we make choices." Bir taahhüt yoktur. Yani doğrudan rakip konumdaki Rust IdP'si bu alanda henüz boştur.

### 5.7 Rust ekosistemi, OpenID Federation

crates.io API'sinden doğrulanmıştır, 8 Eylül 2026.

| Crate | Sürüm | Yayın | İndirme | Değerlendirme |
|---|---|---|---|---|
| `openid-federation` (impierce) | 0.1.0 | 2 Ekim 2025, tek sürüm | 283 toplam, son 90 günde 8 | GitHub'da sıfır yıldız, sıfır fork ile dört commit'i vardır; Apache-2.0'dır. OpenID Federation 1.0 draft 43'e göre yazılmıştır, yani final'den önceki bir taslağa. Kapsam iddiası geniştir, yani entity configuration, güven zinciri ile politika operatörleri, ancak olgunluk göstergeleri sıfırdır. Üretimde kullanılamaz, en fazla referans olur |

Sonuç şudur: OpenID Federation'da Rust'ta hiçbir şey yoktur ve sıfırdan yazılacaktır. İyi haber şudur: gereken alt yapı taşları, yani JWS imzalama ile doğrulama, JWK set yönetimi, HTTPS istemcisi ile JSON, Argus'ta OIDC için zaten bulunacaktır. Federasyon, bunların üzerine oturan saf bir mantık katmanıdır ve XML gibi yabancı bir teknoloji yığını getirmez. Bu, beş protokol içinde Rust ekosistemi boşluğunun en az acı verdiği alandır.

Yazılacaklar şunlardır: entity statement modeli ile §3.2'nin 25 adımlık doğrulaması, döngü tespiti ve derinlik sınırı içeren güven zinciri çözümleyicisi, yedi operatörlü metadata politika motoru ile birleştirme ve çelişki tespiti, federasyon endpoint'leri, güven işareti doğrulaması ile delegasyonu, önbellek katmanı, tarihsel anahtarlar ve otomatik ile açık kayıt akışları.

### 5.8 Gerçek dünya tuzakları

1. Önbellek olmadan ölçeklenmez. Her yetkilendirme isteğinde güven zinciri çözmek N adet HTTPS çağrısı demektir. Çözülmüş metadata asgari `exp` değerine kadar önbelleğe alınır ve olumsuz sonuçlar da kısa bir yaşam süresiyle önbelleğe alınır.
2. Güven çıpasının yükü vardır. Büyük federasyonlarda güven çıpasının fetch endpoint'i tek darboğazdır. Statement'lar imzalı olduğu için içerik dağıtım ağına konabilir ve bu tasarıma yazılmalıdır.
3. Zincir uzunluğu ile döngü. `constraints` (§6.2) azami yol uzunluğu verir, ancak kendi mutlak tavanımız da konmalıdır. Döngü tespiti zorunludur.
4. Anahtar rotasyonu iki katmanlıdır: entity statement'ları imzalayan federasyon imzalama anahtarları ile OP'nin token imzalama anahtarları ayrıdır ve ayrı rotate edilir. Karıştırmak yaygın bir hatadır. `federation_historical_keys_endpoint`, eski anahtarlarla imzalanmış ve hâlâ geçerli olan statement'ların doğrulanabilmesi içindir.
5. Saat kayması. `exp` ile `iat` kontrollerinde bir tolerans gerekir, ancak federasyonda tolerans küçük tutulmalıdır; önerisi 60 saniyedir.
6. Çevrimdışı doğrulama. Güven zinciri `application/trust-chain+json` olarak taşınabildiği için istemci zinciri kendisi getirebilir; bu durumda Argus ağ çağrısı yapmadan doğrular. Açık kaydın bu seçeneği sunması tesadüf değildir; kapalı ağlar için tek yol budur.

---

## Bölüm 6 — Toplam efor ve sıralama

### 6.1 Efor tahmini, protokol bazında

Tahminler tek bir deneyimli Rust mühendisinin tam zamanlı çalıştığı ve mevcut Argus çekirdeğinin, yani kullanıcı deposu, oturum, kripto ile HTTP katmanının hazır olduğu varsayımıyla yapılmıştır. Test, dokümantasyon ile interop çalışması dahildir; satış öncesi destek ile müşteriye özel hata ayıklama dahil değildir.

| Protokol | Faz 1, zorunlu | Faz 2, opsiyonel | Toplam |
|---|---|---|---|
| SCIM 2.0 | 16 ile 18 hafta | Ek 6 hafta: imleç, güvenlik olayı token'ı, `/.search` ile ETag | Yaklaşık 24 hafta |
| SAML 2.0, IdP tarafı | 14 ile 16 hafta | Ek 8 hafta: tek noktadan çıkış, MDQ, şifreleme ile artifact | Yaklaşık 24 hafta |
| LDAP | 10 ile 11 hafta | Ek 3 hafta: StartTLS, parola değiştirme ile sıralama | Yaklaşık 14 hafta |
| Kerberos ile Active Directory | 9 hafta | Ek 4 hafta: alanlar arası güven ile delegasyon | Yaklaşık 13 hafta |
| OpenID Federation | 12 ile 14 hafta | Ek 6 hafta: ara düğüm rolü ile güven işareti verme | Yaklaşık 20 hafta |
| Toplam | 61 ile 68 hafta | Ek 27 hafta | Yaklaşık 95 hafta, yani 1,8 mühendis yılı |

Bu rakam yanıltıcıdır ve tek başına kullanılmamalıdır. Üç düzeltme faktörü vardır.

Birincisi interop kuyruğu tahminlerin dışındadır. SAML'de her yeni büyük servis sağlayıcı, SCIM'de her yeni büyük istemci bir hafta yiyebilir. Gerçekçi çarpan faz 1 üzerine %30 ile %40 arası sürekli bakımdır.

İkincisi paralelleştirilebilirlik sınırlıdır. SCIM ile LDAP aynı iç veri modelini ve yetki katmanını kullanır; iki mühendis aynı anda çalışırsa çakışırlar. SAML ile OpenID Federation birbirinden bağımsızdır ve gerçekten paralelleşir.

Üçüncüsü test ortamı kurulumu gizli bir maliyettir. Bir Active Directory ormanı, bir Entra kiracısı, bir Okta geliştirici hesabı ile bir SPID test federasyonu kurmak ve canlı tutmak kendi başına üç ile dört hafta ve kalıcı bir bakım yüküdür.

### 6.2 Sıralama ve gerekçesi

**Faz 1: SCIM 2.0, aylar 0 ile 5.** Neden ilk olduğu şöyledir. Kurumsal alıcının en sık sorduğu şey budur. Ağ etkisi yoktur ve tek taraflıdır: kimseyle federe olmak gerekmez, kendi endpoint'i yazılıp Entra SCIM Validator'a tutulur. Ölçülebilir bir bitiş çizgisi vardır, yani scimvalidator.microsoft.com'dan geçmek; diğer dört protokolün böyle bir kapısı yoktur. İç veri modelini, yani nitelik karakteristiklerini, değiştirilebilirliği ile izdüşümü, doğru kurmaya zorlar ve bu model LDAP ile federasyonda yeniden kullanılır. Teknolojik riski düşüktür: XML yoktur, ASN.1 yoktur, GSSAPI yoktur, saf JSON ile HTTP vardır. Bitiş kriteri Entra SCIM Validator'dan tam geçiş, Okta ile canlı bir OIN entegrasyonu ve 17 maddelik tolerans katmanının test edilmiş olmasıdır.

**Faz 2: SAML 2.0 IdP, aylar 4 ile 10, SCIM ile kısmen örtüşür.** Neden ikinci olduğu şöyledir. İşletmeler arası satışta bir kapı bekçisidir ve Ory'nin desteklememesi ciddi bir boşluktur; rakip analizinde bu, Argus'un Ory karşısındaki en net avantajıdır. Ancak en yüksek teknik riski taşır, yani XML kriptoyu; bu yüzden SCIM'in ardından, ekip Argus'un iç modelini oturttuktan sonra yapılır. Erken bir karar noktası vardır: `bergshamra` ile `gamlastan` mı yoksa `xmlsec` yabancı fonksiyon arayüzü mü. Bu karar fazın ilk iki haftasında bir araştırmayla verilir ve sonra dönülmez. Bitiş kriteri Salesforce, AWS IAM Identity Center, Google Workspace ile M365'e canlı çoklu oturum açma ve sertifika rotasyonu prosedürünün belgelenmiş ve test edilmiş olmasıdır.

**Faz 3: LDAP, aylar 9 ile 12.** Neden üçüncü olduğu şöyledir. Kapsamı iyi tanımlıdır, ekosistem hazırdır ve sürpriz düşüktür; yani öngörülebilir bir fazdır ve SAML'in belirsizliğinden sonra buna ihtiyaç olacaktır. SCIM'de kurulan veri modelinin ikinci tüketicisidir; model hataları burada ortaya çıkar ve ucuza düzeltilir. Tek başına satış kapatmaz ancak bir ihale kutucuğudur ve eksikliği eleme sebebidir. Bitiş kriteri sssd ile Linux girişi, Grafana, GitLab ile Jenkins'te grup senkronizasyonu ve bir VPN cihazıyla bind'dır.

**Faz 4: OpenID Federation, aylar 12 ile 17.** Neden dördüncü olduğu ancak atlanmaması gerektiği şöyledir. Bugün müşteri talebi yoktur, ancak üç şey aynı anda olmaktadır: spesifikasyon final olmuştur (Şubat ile Mayıs 2026), eduGAIN pilotu çalışmaktadır ve Avrupa dijital kimlik cüzdanı buna atıf yapmaktadır. Rust'ta hiç yoktur ve doğrudan rakip Kanidm henüz karar vermemiştir; bu, Rust'ta OpenID Federation'ı olan tek IdP konumu için 12 ile 18 aylık bir pencere demektir. Teknolojik olarak en temiz fazdır: JWS ile JWK altyapısı zaten vardır, XML yoktur, C bağımlılığı yoktur ve saf mantıktır. Ancak geliri en uzak olandır ve bu yüzden dördüncüdür. Bitiş kriteri bir test federasyonunda, yani SPID test ortamında veya kendi kurduğumuz güven çıpasında, yaprak OP olarak otomatik kayıtla çalışan uçtan uca bir akıştır.

**Faz 5: Kerberos ile Active Directory, aylar 16 ile 20.** Neden son olduğu şöyledir. Değerin efora oranı en düşük olanıdır; Microsoft kendi Kerberos tabanlı çözümünden uzaklaşmaktadır, 4.5'e bakınız. Tek C bağımlılığını getirir ve dağıtım hikâyesini bozar: ayrı bir imaj varyantı, `/etc/krb5.conf` ile keytab sır yönetimi gerekir. Active Directory LDAP senkronizasyonu kısmı ise erken gerekebilir ve o kısım Kerberos'a bağımlı değildir; ayrılmalıdır: Active Directory'den kullanıcı senkronizasyonu üçüncü fazın, yani LDAP'ın yanına kaydırılabilir, SPNEGO beşinci fazda kalır. Bitiş kriteri alana katılmış bir Windows makinesinden tarayıcıyla parolasız giriş ile bir Active Directory ormanından artımlı kullanıcı senkronizasyonudur.

### 6.3 Alternatif sıralama, satış odaklı senaryo

Somut bir kurumsal anlaşma SAML'i şart koşuyorsa sıra SAML, SCIM, LDAP, federasyon ile Kerberos olur. Bu durumda kabul edilen risk şudur: iç veri modeli SAML'in nitelik ihtiyaçlarına göre şekillenir ve SCIM'in değiştirilebilirlik ile döndürülme katmanı sonradan zorla takılır. Bu, ileride ödenecek bir borçtur ancak meşru bir ticari karardır.

Hiçbir koşulda önerilmeyen sıra Kerberos veya OpenID Federation ile başlamaktır. Birincisi C bağımlılığını ve dağıtım karmaşıklığını en başa taşır; ikincisi henüz alıcısı olmayan bir yatırımı öne alır.

### 6.4 Ortak altyapı, beş protokolün paylaştığı katmanlar

Bunlar protokol fazlarından önce veya ilk fazla birlikte inşa edilmelidir; her birini beş kez yazmak en pahalı hatadır.

| Katman | Kim kullanır |
|---|---|
| Nitelik ile claim eşleme motoru: iç modelden dış temsile, dönüşüm fonksiyonlarıyla | SAML nitelik ifadesi, SCIM izdüşümü, LDAP nitelik eşlemesi ile OIDC claim'leri |
| Anahtar ile sertifika yaşam döngüsü: üretim, rotasyon, çoklu aktif anahtar ile HSM veya anahtar yönetim servisi | SAML imzalama, federasyon varlık anahtarları, OIDC JWKS, LDAPS ile TLS ve Kerberos keytab'ı |
| Güvenli dış HTTP istemcisi: SSRF savunması, boyut ile yönlendirme limitleri ve önbellek | SAML metadata çekme, federasyon entity statement'ı, CIMD ile SCIM web kancası teslimatı |
| Yeniden oynatma ile nonce önbelleği: yaşam süreli ve dağıtık | SAML assertion kimliği, federasyon `jti` değeri, DPoP ile OIDC nonce'u |
| Denetim olayı boru hattı | Hepsi; RFC 9967 SET yayını buradan beslenir |
| Çok kiracılık ile kiracı başına yapılandırma | Hepsi |
| Kabul ile uyum test harness'ı | Entra SCIM Validator, SAML servis sağlayıcı simülatörleri, LDAP istemci matrisi ile federasyon test federasyonu |

### 6.5 Karar önerisi

SCIM ile başlanır, SAML ile devam edilir, LDAP ile sağlamlaştırılır, OpenID Federation ile farklılaşılır, Kerberos en sona bırakılır ve Active Directory senkronizasyonu Kerberos'tan ayrılarak öne alınır. Beş protokolün tamamı yaklaşık 1,8 mühendis yılı çekirdek iş, artı sürekli %30 ile %40 arası interop bakımıdır. İki mühendisle 12 ile 14 ayda birinci ile üçüncü fazlar, yani SCIM, SAML ile LDAP, tamamlanabilir ve bu, kurumsal ihalelerin ezici çoğunluğunu karşılar. OpenID Federation ile Kerberos ikinci yıla bırakılabilir, ancak federasyonun penceresi kapanmadan girilmelidir.

---

## Bölüm 7 — Doğrulanamayanlar ve sınırlar

Bu dokümandaki her sürüm numarası, tarih, oy sayısı ile indirme rakamı birincil kaynaktan alınmıştır. Aşağıdakiler doğrulanamamıştır ve iddia olarak kullanılmamalıdır.

| # | Konu | Durum |
|---|---|---|
| 1 | Google Workspace, OneLogin, JumpCloud, Ping ile SailPoint SCIM istemci davranışları | Doğrulanamamıştır; birincil kaynaktan teyit edilememiştir, çünkü arama bütçesi tükenmiştir. Ayrı bir doğrulama turu gerekir |
| 2 | Entra ID'nin kesin 429, zaman aşımı ile yeniden deneme sayısı değerleri | Doğrulanamamıştır; Microsoft'un kamuya açık dokümanlarında yoktur. Yalnızca karantinadan günde bire, dört hafta sonra devre dışı bırakmaya giden akış belgelidir |
| 3 | Okta'nın Runscope tabanlı SCIM test süitinin 2026'da çalışır durumda olup olmadığı | Doğrulanamamıştır; Runscope BlazeMeter tarafından kapatılmıştır ve Okta'nın yerine ne koyduğu teyit edilememiştir |
| 4 | `draft-ietf-scim-profile-*` veya bir 7644bis dokümanının varlığı | Doğrulanamamıştır; SCIM çalışma grubu doküman listesinde böyle bir şey yoktur. PATCH netleştirmesi yalnızca errata 7122 ile 8097 olarak mevcuttur |
| 5 | Keycloak'ın OpenID Federation desteğinin resmî durumu | Doğrulanamamıştır; topluluk yazıları bir eklentiden söz etmektedir ancak resmî Keycloak dokümanından çekirdek bir özellik olduğu teyit edilememiştir |
| 6 | Amsterdam interop etkinliğinde tam olarak hangi endpoint ile akışların test edildiği | Doğrulanamamıştır; OIDF duyurusu bunu belirtmemekte ve hiçbir sınırlama raporlamamaktadır. Dokuz implementasyonun birbirine karşı test ettiği ifadesinin ötesine geçilmemelidir |
| 7 | OpenID Federation 1.1'in kesin yayın tarihi | Çelişkilidir: OIDF duyurusu 6 Mayıs 2026, Mike Jones 11 Mayıs 2026 demektedir. Onay tarihi olan 6 Mayıs 2026 kesindir, yayın tarihi tartışmalıdır ve normatif önemi yoktur |
| 8 | `sspi` (Devolutions) crate'inin güncel sürümü ile Windows tarafı kapsamı | Doğrulanamamıştır; bu araştırmada crates.io verisi çekilmemiştir |
| 9 | `bergshamra`'nın README dosyasındaki sürüm iddiası | Çözülmüştür ancak tutarsızdır. README "Version 0.10.1 was released on August 02, 2026" demektedir; crates.io'da `bergshamra` azami sürümü 0.9.0'dır, 2 Eylül 2026 tarihlidir ve 0.10.x hiç yoktur. 0.10.1 büyük olasılıkla alt bağımlılık `uppsala`'nın sürümüdür; uppsala 0.10.1, 2 Eylül 2026, doğrulanmıştır. crates.io esas alınmalıdır ve bu tutarsızlık projenin doküman disiplini hakkında bir uyarıdır |
| 10 | Salesforce, ServiceNow, Workday, AWS IAM Identity Center, Slack, Zoom ile Atlassian SAML gereksinimleri | Doğrulanamamıştır; hiçbiri birincil kaynaktan teyit edilememiştir, çünkü Salesforce yardım sitesi bir tek sayfa uygulamasıdır ve diğerleri erişilemez veya müşteri girişinin arkasındadır. Bu satıcılar için NameID formatı, nitelik adı veya imza yeri iddiası bu dokümanda üretilmemiştir ve üretilmemelidir; uydurulmuş bir nitelik adı sessizce başarısız olan bir entegrasyon demektir |
| 11 | Google Workspace'in imza algoritması, sertifika gereksinimi, Response ile Assertion imzalama tercihi ve tek noktadan çıkış politikası | Doğrulanamamıştır; resmî gereksinim sayfasında yer almamaktadır |
| 12 | NIST SP 800-131A Revision 3'ün SHA-1 için kesin ifadesi | Doğrulanamamıştır. Yürürlükteki sürüm Revision 2'dir, Mart 2019 tarihlidir; Revision 3 hâlâ taslaktır, yorum süresi 4 Aralık 2024'te kapanmıştır ve 8 Eylül 2026 itibarıyla final değildir. PDF içeriğine erişilememiştir |
| 13 | XSW1 ile XSW8 arası taksonominin birebir tanımları | Doğrulanamamıştır. Referansı Somorovsky ve arkadaşlarının "On Breaking SAML: Be Whoever You Want to Be" çalışmasıdır, USENIX Security 2012 |
| 14 | Jager ile Somorovsky'nin "How to Break XML Encryption" (ACM CCS 2011) tam metni | Kısmen doğrulanamamıştır; W3C XMLEnc 1.1 önerisinin §5.1.1 ile §6.9 metni iddiayı birincil kaynak olarak desteklemektedir, ancak makalenin kendisine erişilememiştir |
| 15 | MDQ'nun `{sha1}` dönüşümünü tanımlayan SAML profil dokümanının tam adı ile sürümü | Doğrulanamamıştır; temel `draft-young-md-query` bu dönüşümü tanımlamamakta ve "reserved for profile specifications" demektedir |
| 16 | Yorum kesme (CVE-2017-11427 ile 11428) mekanizmasının teknik ayrıntısı | Kısmen doğrulanamamıştır; Duo'nun orijinal teknik yazısı 8 Eylül 2026 itibarıyla erişilemezdir ve Cisco Duo pazarlama sayfasına yönlenmektedir, açıklama CVE metni temellidir |
| 17 | Shibboleth'in tek noktadan çıkış hakkındaki resmî ifadesi | Doğrulanamamıştır; wiki sayfasına erişilememiştir. 1.8'deki gerekçeler spesifikasyon metninden çıkarılan yapısal nedenlerdir, satıcı beyanı değildir |
| 18 | Microsoft Entra'nın SHA-1 ile SHA-256 çelişkisinin pratikte hangi tarafa düştüğü | Çözülmemiştir; doküman kendi içinde çelişkilidir ve canlı test gerektirir |
| 19 | Efor tahminleri | Bunlar muhakeme ürünüdür, ölçüm değildir. Hiçbir birincil kaynağa dayanmazlar ve artı eksi %40 bant kabul edilmelidir |

### 7.1 Bu dokümanın kapsamadıkları

Servis sağlayıcı tarafı SAML, yani Argus'un başka bir IdP'ye servis sağlayıcı olarak bağlanması, ki buna kimlik brokerliği denir, ayrı bir konudur ve tamamen farklı bir tehdit modeli taşır; bu dokümandaki tüm imza doğrulama CVE'leri oraya uygulanır.

RADIUS README'nin yedinci bölümünde listelenmiştir ancak bu araştırmanın kapsamı dışında bırakılmıştır.

WS-Federation eski bir teknolojidir ve kasıtlı olarak kapsam dışıdır. SAML 1.1 ile Shibboleth'e özgü uzantılar da kapsam dışıdır.

Performans ile ölçek rakamları için hiçbir protokolde ölçüm yapılmamıştır.

Lisans analizi yapılmamıştır: `scim_proto` MPL-2.0, `gamlastan` ile `bergshamra` BSD-2-Clause, `ldap3_proto` (Kanidm) ile `libgssapi` (MIT) farklı lisanslar taşımaktadır. Argus'un lisans modeliyle uyumu ayrıca incelenmelidir.
