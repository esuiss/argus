# §17 — Gelecek standartları: PQC, WebAuthn L3, CTAP ve TLS

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

**Soru.** Beş ile on yıl yaşayacak bir IdP mimarisinde, bugün ucuz olan ancak sonradan çok pahalıya patlayacak kararlar hangileridir.

Bu dosya dört ayrı araştırma hattının ham raporlarını birleştirir. Sentez ile karar tablosu için §3'e bakınız.

---

## Hat 1 — Post kuantum kriptografi ve kimlik

Bu, 8 Eylül 2026 tarihli bir post kuantum kriptografi durum raporudur ve Rust ile kimlik sağlayıcı geliştiren bir ekip içindir.

**Yöntem notu.** Bulgular birincil kaynaklardan doğrudan çekilmiştir: csrc.nist.gov, datatracker.ietf.org, rfc-editor.org, iana.org, w3.org, fidoalliance.org, cabforum.org, crates.io ile docs.rs ve whitehouse.gov. Erişilemeyen kaynaklar ile doğrulanamayan noktalar açıkça işaretlenmiştir.

### 0. Yönetici özeti, bir IdP için tek cümlelik durum

İmza tarafı, yani JWS ile JWT, hazırdır; şifreleme tarafı, yani JWE, hazır değildir; sertifika tarafı kamuya açık güvende hâlâ kapalıdır; FIDO donanımı yoktur ve Rust'ta RFC 9964 implementasyonu yoktur.

| Katman | Durum | Aksiyon |
|---|---|---|
| TLS anahtar değişimi | Üretimdedir, RFC olmuştur ve trafiğin yaklaşık üçte ikisini kapsamaktadır | Bugün açılır |
| JWS imzası, ML-DSA | RFC 9964 ile hazırdır, Mayıs 2026 | Spesifikasyon hazırdır ancak Rust kütüphanesi yoktur |
| JWE şifrelemesi, ML-KEM | Yalnızca taslaktır ve JOSE için yoktur | Beklenir |
| X.509 sertifikası, özel PKI | RFC 9881 ile 9935 hazırdır | Kullanılabilir |
| X.509 sertifikası, kamuya açık güven | CA ile tarayıcı forumu oylaması geçmemiştir | 2027 ve sonrası |
| FIDO2 ile WebAuthn PQC | Spesifikasyonda bile yoktur ve donanım yoktur | 2028 ve sonrası |
| FIPS 140-3 validasyonlu PQC | Kuyruktadır | Beklenir |

### 1. NIST PQC standartları

#### 1.1 Yayımlanmış FIPS'ler, hepsi 13 Ağustos 2024

| Standart | Tam ad | Durum | Not |
|---|---|---|---|
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard, yani ML-KEM | Final, 13 Ağustos 2024 | 17 Kasım 2025 tarihli errata notu gelecek bir güncellemede düzeltilecek bir sorundan söz etmektedir |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard, yani ML-DSA | Final, 13 Ağustos 2024 | 31 Temmuz 2026 tarihli errata notu birkaç küçük sorunun gelecek revizyonda düzeltileceğini söylemektedir |
| FIPS 205 | Stateless Hash-Based Digital Signature Standard, yani SLH-DSA | Final, 13 Ağustos 2024 | Sayfada errata notu yoktur |

Hiçbirinin birinci revizyonu yoktur; ikisinde bir errata elektronik tablosu vardır ve revizyon tarihi ilan edilmemiştir, yani belirsizdir.

Kaynakları csrc.nist.gov/pubs/fips/203/final, /204/final ile /205/final'dir.

#### 1.2 FIPS 206, yani FN-DSA veya Falcon, 8 Eylül 2026 itibarıyla yayımlanmamıştır

NIST PQC standardizasyon sayfasında hâlâ yalnızca geliştirme aşamasında olduğu yazmakta ve tarih verilmemektedir.

NIST'in yoruma açık taslaklar listesinde FIPS 206 yoktur, yani ilk kamuya açık taslak bile çıkmamıştır. Bu doğrudan doğrulanmıştır; 8 Eylül 2026 listesi SP 800-73-6, SP 800-78-6, SP 800-209r1, SP 800-239, IR 8613, SP 1353, SP 800-213A r1 ile SP 800-38E r1'den oluşmaktadır.

IETF tarafındaki `draft-ietf-cose-falcon-04` özeti "expected to be published in late 2026 early 2027" demektedir ve bu şu an en güvenilir kamuya açık beklentidir.

İkincil kaynaklar NIST'in taslağı 28 Ağustos 2025'te onaya gönderdiğini söylemektedir; bu birincil kaynakta doğrulanamamıştır ve belirsizdir.

Kaynağı csrc.nist.gov'un post kuantum kriptografi standardizasyon sayfasıdır.

#### 1.3 HQC seçilmiştir ancak taslak gecikmiştir

Seçim 11 Mart 2025'te yapılmıştır. Gerekçe belgesi NIST IR 8545'tir, yani "Status Report on the Fourth Round of the NIST PQC Standardization Process", Mart 2025. Metni şöyledir: "The only key-establishment algorithm that will be standardized is HQC."

FIPS numarası atanmamıştır. Ne IR 8545'te ne proje sayfasında bir numara vardır. Yaygın olarak dolaşan FIPS 207 iddiası hiçbir NIST kaynağında bulunamamıştır ve uydurma saymak gerekir.

NIST'in ilan ettiği takvim, Mart 2025 tarihli nist.gov haber bülteninde şöyledir: "NIST plans to release a draft standard built around HQC for public comment in about a year" ve "finalize the standard for release in 2027."

Gerçekleşmeye bakıldığında yaklaşık bir yıl Mart 2026 demekti. 8 Eylül 2026 itibarıyla HQC taslağı yayımlanmamıştır; yoruma açık taslaklar listesinde yoktur. Yani takvimin yaklaşık altı ay gerisindedir. 2027 finali bu gidişle riskli görünmektedir; bu bir yorumdur ve belirsizdir.

Kaynakları csrc.nist.gov/pubs/ir/8545/final ile nist.gov'un Mart 2025 haber sayfasıdır.

#### 1.4 Yan gelişmeler

NIST IR 8610, final, Mayıs 2026: "Status Report on the Second Round of the Additional Digital Signature Schemes". Üçüncü tura kalan dokuz aday FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign ile UOV'dur. Standardizasyon takvimi verilmemiştir.

SP 800-227, final, Eylül 2025: "Recommendations for Key-Encapsulation Mechanisms". Anahtar kapsülleme mekanizmalarının doğru kullanımını anlatır ve ML-KEM entegrasyonu için başvuru dokümanıdır.

SP 800-230'un ilk kamuya açık taslağı 13 Nisan 2026 tarihlidir ve yorum süresi 12 Haziran 2026'da kapanmıştır: "Additional SLH-DSA Parameter Sets for Limited Signature Use Cases". Birinci, üçüncü ile beşinci seviye için altı ek parametre seti getirir; daha küçük imza ile hızlı doğrulama sağlar, ancak anahtar başına iki üzeri yirmi dört imza sınırı vardır ve "not approved for general-purpose use" denmektedir.

### 2. NIST SP 800-208, durumlu hash tabanlı imzalar, LMS ile XMSS

Tam adı "Recommendation for Stateful Hash-Based Signature Schemes"tir. Durumu finaldir ve Ekim 2020 tarihlidir; kesinleşmesi 29 Ekim 2020'dir. Geri çekilme veya yerine geçme notu yoktur ve hâlâ yürürlüktedir. Kapsamı LMS, çok ağaçlı LMS olan HSS, XMSS ile XMSS^MT'dir.

IdP açısından bu şemalar durum tutar: aynı tek kullanımlık imza anahtarı iki kez kullanılırsa imza sahteciliği mümkün olur. Bu yüzden yalnızca donanım güvenlik modülü destekli, merkezî ve düşük hacimli senaryolar, örneğin ürün yazılımı veya yazılım imzalama, için uygundur. Token imzalama için kesinlikle uygun değildir, çünkü yüksek hacim, yatay ölçekleme ile durum senkronizasyonu birleşimi bir felakettir.

CNSA 2.0 yazılım ile ürün yazılımı imzalama için bunları zorunlu kılmaktadır; aşağıya bakınız.

IETF tarafında `draft-ietf-pquip-hbs-state-04`, yani "Hash-based Signatures: State and Backup Management", RFC Editor kuyruğundadır. Durum yönetimi ile yedekleme tuzaklarını anlatır ve LMS ya da XMSS'e girilecekse okunması şarttır.

Kaynağı csrc.nist.gov/pubs/sp/800/208/final'dir. COSE tarafında HSS ile LMS zaten kayıtlıdır: algoritma değeri eksi 46'dır, RFC 8778 ile RFC 9053'te tanımlıdır, anahtar tipi beştir.

### 3. Geçiş takvimleri: IR 8547, EO 14412 ile CNSA 2.0

#### 3.1 NIST IR 8547 hâlâ taslaktır, final değildir

Bu, raporun en çok yanlış bilinen maddesidir. İnternette dolaşan 2025'te final olduğu iddiası yanlıştır.

Tam adı "Transition to Post-Quantum Cryptography Standards"tır. Durumu ilk kamuya açık taslaktır; 12 Kasım 2024'te yayımlanmış, yorumlar 10 Ocak 2025'te kapanmış ve gelen yorumlar 21 Ocak 2025'te yayımlanmıştır.

8 Eylül 2026 itibarıyla final sürüm yoktur, ikinci taslak da yoktur. Bu üç ayrı yerden doğrulanmıştır: `csrc.nist.gov/pubs/ir/8547/final` adresi HTTP 404 dönmektedir; `csrc.nist.gov/pubs/ir/8547/ipd` sayfasında final veya güncelleme notu yoktur; NIST PQC haber akışında IR 8547 ile ilgili son kayıt 12 Kasım 2024 tarihli taslak duyurusudur.

Taslaktaki hedefler şunlardır: kuantuma açık açık anahtarlı algoritmalar, yani RSA, ECDSA, ECDH ile sonlu cisim Diffie-Hellman, 2030'dan sonra kullanımdan kaldırılmış, 2035'ten sonra ise yasaklanmış sayılacaktır.

Pratik sonuç şudur: 2030 ile 2035 tarihleri yaygın olarak alıntılansa da hâlâ resmî olarak taslak statüsündedir. Bağlayıcı olan şey artık IR 8547 değil aşağıdaki başkanlık kararnamesidir.

İlgili olarak SP 800-131A Revision 3 de hâlâ ilk kamuya açık taslaktır, 21 Ekim 2024 tarihlidir. Yani NIST'in resmî algoritma geçiş rehberliğinin ikisi de taslaktır. Kaynakları csrc.nist.gov/pubs/ir/8547/ipd ile csrc.nist.gov/pubs/sp/800/131/a/r3/ipd'dir.

#### 3.2 Executive Order 14412, asıl bağlayıcı belge

Bu, ekibin takvimini belirleyen belgedir ve whitehouse.gov'dan doğrudan doğrulanmıştır.

Tam adı Executive Order 14412, "Securing the Nation Against Advanced Cryptographic Attacks"tır ve imza tarihi 22 Haziran 2026'dır.

| Tarih | Yükümlülük |
|---|---|
| Otuz gün, yani Temmuz 2026 | Kurumlar PQC geçiş sorumlusunu OMB ile Ulusal Siber Direktör'e bildirir |
| Doksan gün, yani Eylül 2026 | OMB rehberlik yayımlar; kurumlar yüksek değerli ile yüksek etkili sistemleri gözden geçirip geçiş planı hazırlar |
| Yüz seksen gün | NIST bir PQC pilot projesi başlatır, bitişi 2027 sonudur; CISA kriptografik malzeme listesi rehberliği yayımlar; Federal Satın Alma Yönetmeliği Konseyi bir sözleşme kuralı önerir |
| İki yüz yetmiş gün | Aynı konsey zafiyet açıklama gereksinimlerini önerir |
| 31 Aralık 2030 | Yüksek değerli ile yüksek etkili sistemler anahtar tesisi için PQC'ye geçer; yükleniciler NIST PQC FIPS'lerine uyar |
| 31 Aralık 2031 | Yüksek değerli ile yüksek etkili sistemler dijital imza ile kimlik doğrulama için PQC'ye geçer |

> **IdP ekibi için kritik nokta.** Kararname anahtar tesisi ile imza ve kimlik doğrulama arasına bir yıl fark koymaktadır: birincisi 2030, ikincisi 2031'dir. Bir IdP'nin ürettiği JWT imzaları ile mTLS ve FIDO kimlik doğrulaması 2031 kovasına düşer; TLS anahtar değişimi 2030 kovasına düşer. ABD federal bir müşteri veya federal bir yüklenici varsa bu tarihler sözleşmesel hâle gelir.

Kaynağı whitehouse.gov'un 2026/06 tarihli başkanlık eylemleri sayfasıdır.

#### 3.3 CNSA 2.0, NSA, ikincil kaynak uyarısıyla

Uyarı şudur: `media.defense.gov` üzerindeki CNSA 2.0 algoritmaları PDF'i ile nsa.gov'un post kuantum siber güvenlik kaynakları sayfası HTTP 403 döndürmüştür; birincil PDF'e erişilememiştir. Aşağıdaki tablo ikincil kaynaktandır ve doğrulanması gerekir.

Algoritma paketi, Wikipedia ile Encryption Consulting kaynaklarının uyumlu verdiği hâliyle şöyledir.

| Amaç | Algoritma | Standart |
|---|---|---|
| Anahtar tesisi | ML-KEM-1024, yalnızca beşinci kategori | FIPS 203 |
| Genel dijital imza | ML-DSA-87, yalnızca beşinci kategori | FIPS 204 |
| Yazılım ile ürün yazılımı imzalama | LMS veya XMSS, asgari SHA-256 ile 192 | SP 800-208 |
| Simetrik | AES-256 | FIPS 197 |
| Özet | SHA-384 ile SHA-512 | FIPS 180-4 |
| Güvenli açılış özeti | SHA3-384 ile SHA3-512 | FIPS 202 |

Geçiş takvimi ikincildir ve belirsizdir.

| Kategori | Destekle veya tercih et | Yalnızca CNSA 2.0 |
|---|---|---|
| Yazılım ile ürün yazılımı imzalama | 2025 | 2030 |
| Geleneksel ağ ekipmanı, yani VPN ile yönlendirici | 2026 | 2030 |
| Web tarayıcısı ile sunucusu ve bulut servisleri | 2025 | 2033 |
| İşletim sistemleri | 2027 | 2033 |

Ayrıca 1 Ocak 2027'den itibaren yeni ulusal güvenlik sistemi alımlarının varsayılan olarak CNSA 2.0 uyumlu olması gerekmektedir. NSA'nın 2025 veya 2026'da takvimi revize edip etmediği doğrulanamamıştır ve belirsizdir.

> **Dikkat.** CNSA 2.0 yalnızca beşinci kategori parametrelerine izin verir, yani ML-DSA-87 ile ML-KEM-1024'e. Bu, aşağıda görülecek web ile IETF ekosisteminin varsayılanı olan ML-DSA-44 ile ML-KEM-768'le çelişmektedir. Ulusal güvenlik sistemi müşterisi varsa iki ayrı profil desteklenmesi gerekir.

### 4. IETF JOSE ile COSE PQC, IdP'nin kalbi

#### 4.1 RFC 9964, JOSE ile COSE için ML-DSA, yayımlanmıştır

Bu, ekip için en önemli tek belgedir.

Tam adı "ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)"tır. Durumu RFC 9964, Standards Track, Mayıs 2026'dır ve öncülü `draft-ietf-cose-dilithium`'dur. Kaynağı rfc-editor.org/rfc/rfc9964.html'dir.

JWS `alg` değerleri IANA'nın JSON Web Signature and Encryption Algorithms kaydında kayıtlıdır ve implementasyon gereksinimleri opsiyoneldir.

| `alg` | Açıklama | Referans |
|---|---|---|
| `ML-DSA-44` | ML-DSA-44 as described in US NIST FIPS 204 | RFC 9964, FIPS 204 |
| `ML-DSA-65` | ML-DSA-65 as described in US NIST FIPS 204 | RFC 9964, FIPS 204 |
| `ML-DSA-87` | ML-DSA-87 as described in US NIST FIPS 204 | RFC 9964, FIPS 204 |

COSE algoritma kimlikleri IANA'nın COSE Algorithms kaydında kayıtlıdır.

| Değer | İsim | Referans |
|---|---|---|
| Eksi 48 | ML-DSA-44 | RFC 9964 |
| Eksi 49 | ML-DSA-65 | RFC 9964 |
| Eksi 50 | ML-DSA-87 | RFC 9964 |

Yeni anahtar tipi `AKP`'dir, yani algoritma anahtar çifti.

| Katman | Değer |
|---|---|
| JWK `kty` | `"AKP"`, RFC 9964 |
| COSE `kty` | 7, "COSE Key Type for Algorithm Key Pairs", RFC 9964 |
| Açık anahtar parametresi | JWK'da base64url kodlu `pub`, COSE'da bayt dizisi olarak eksi 1 etiketi |
| Özel anahtar parametresi | JWK'da base64url kodlu `priv`, COSE'da bayt dizisi olarak eksi 2 etiketi |

Örnek bir JWK şöyledir:

```json
{
  "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
  "kty": "AKP",
  "alg": "ML-DSA-44",
  "pub": "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMc...",
  "priv": "<32-byte seed, base64url>"
}
```

İmplementasyonda tuzak olan üç kritik tasarım kararı vardır.

1. `priv` mutlaka 32 baytlık bir tohum olmalıdır. RFC metni şöyledir: "the `priv` parameter MUST be the seed and MUST have a length of 32 bytes." Genişletilmiş özel anahtar biçimi JOSE ile COSE'de yasaktır ve bu, ikisi arasında tutarlılık için seçilmiştir.
2. Ön özetli ML-DSA, yani HashML-DSA, desteklenmemektedir. RFC metni şöyledir: "This document does not specify algorithms for use with HashML-DSA as described in Section 5.4 of FIPS-204." Yalnızca saf ML-DSA vardır.
3. `alg` parametresi tüm AKP anahtarlarında zorunludur, çünkü anahtar tipi tek başına algoritmayı belirlememektedir.

> **X.509 ile interop tuzağı.** RFC 9881, yani X.509 tarafı, özel anahtar için tohum, genişletilmiş ile her ikisi seçeneklerinin üçünü de kabul etmektedir. RFC 9964, yani JOSE ile COSE tarafı, yalnızca tohumu kabul etmektedir. Donanım güvenlik modülünüz veya PKI aracınız yalnızca genişletilmiş anahtar veriyorsa JWK'ya doğrudan aktaramazsınız; tohumu saklamanız şarttır. Bu, anahtar üretim akışında baştan kurgulanmalıdır.

#### 4.2 JOSE ile COSE için SLH-DSA, IESG'dedir

`draft-ietf-cose-sphincs-plus-10`, revizyon tarihi 28 Temmuz 2026, Datatracker güncellemesi 23 Ağustos 2026'dır. Durumu yayın için IESG'ye sunulmuştur ve hedefi Proposed Standard'dır; sorumlu alan direktörü Christopher Inacio'dur. Öncülü `draft-ietf-cose-post-quantum-signatures`'tır.

FIPS 205'teki on ikisinin değil yalnızca iki parametre setinin kaydını talep etmektedir.

| İsim | COSE değeri | Durum |
|---|---|---|
| `SLH-DSA-SHA2-128s` | Belirlenecek, eksi 51 istenmektedir | IANA'da henüz kayıtlı değildir |
| `SLH-DSA-SHAKE-128s` | Belirlenecek, eksi 52 istenmektedir | IANA'da henüz kayıtlı değildir |

IANA COSE kaydında bugün SLH-DSA girdisi yoktur ve bu doğrudan doğrulanmıştır. JOSE kaydında da yoktur. Kaynağı datatracker.ietf.org'daki taslak sayfasıdır.

#### 4.3 JOSE ile COSE için FN-DSA, FIPS 206'ya bağımlıdır ve süresi dolmaktadır

`draft-ietf-cose-falcon-04`, 15 Mart 2026 tarihlidir ve süresi 16 Eylül 2026'da dolacaktır, yani sekiz gün içinde.

İstenen değerler `FN-DSA-512` için eksi 54 ile `FN-DSA-1024` için eksi 55'tir; ikisi de belirlenecek durumdadır. FIPS 206 yayımlanmadan ilerleyemez.

> **Olası kod noktası çakışması.** `draft-ietf-jose-pq-composite-sigs-03` de eksi 54 ile eksi 59 arasını istemektedir. İkisi de belirlenecek durumda olduğu için IANA tahsis sırasında çözülecektir ve hangisinin alacağı belirsizdir. Bu değerler koda sabit yazılmamalıdır.

#### 4.4 JOSE ile COSE için ML-KEM, JOSE için yoktur

Bu, IdP'ler için en büyük boşluktur.

`draft-ietf-jose-pqc-kem-06`, 6 Temmuz 2026 tarihli, JOSE çalışma grubunun aktif bir internet taslağıdır. Başlığı "Post-Quantum Key Encapsulation Mechanisms (PQ KEMs) for COSE"dur.

Dosya adında JOSE geçmesine rağmen kapsamı yalnızca COSE'dur. Metin açıkça JOSE ile hibrit yaklaşımları "outside the scope of this document" olarak nitelemektedir.

Tanımlanan altı algoritma doğrudan anahtar anlaşması için `ML-KEM-512`, `ML-KEM-768` ile `ML-KEM-1024` ve anahtar sarmalamalı `ML-KEM-512+A128KW`, `ML-KEM-768+A192KW` ile `ML-KEM-1024+A256KW`'dir. Kod noktalarının hepsi belirlenecek durumdadır ve IANA'da hiçbiri kayıtlı değildir.

Sonuç şudur: JWE için standartlaşmış post kuantum şifreleme 8 Eylül 2026 itibarıyla yoktur. Şifreli kimlik token'ı, şifreli kullanıcı bilgisi veya JARM kullanılıyorsa kuantuma dayanıklı bir seçenek mevcut değildir.

#### 4.5 HPKE, JOSE ile COSE

| Taslak | Revizyon | Tarih | Durum | Post kuantum var mı |
|---|---|---|---|---|
| `draft-ietf-jose-hpke-encrypt` | 22 | 6 Temmuz 2026 | Alan direktörü onayı beklemektedir, hedefi Proposed Standard'dır | Yoktur; yalnızca P-256 ile X25519 tabanlı DHKEM vardır, ML-KEM yoktur |
| `draft-ietf-cose-hpke` | 26 | 4 Temmuz 2026 | Alan direktörü değerlendirmesi ile takibindedir | Yoktur |
| `draft-ietf-jose-hpke-pq-pqt` | 01 | 6 Temmuz 2026 | Çalışma grubu dokümanı olarak mevcuttur | Vardır; post kuantum kayıtları buradadır |
| `draft-ietf-cose-hpke-pq-pqt` | 01 | 2026 | Çalışma grubu dokümanı olarak mevcuttur | Vardır |

`draft-ietf-jose-hpke-pq-pqt-01` şunları kaydetmektedir ve hepsi SHAKE256 anahtar türetme fonksiyonu ile AES-256-GCM kullanır. Post kuantum ile geleneksel hibritler `HPKE-8` (ML-KEM-768 ile P-256), `HPKE-9` (ML-KEM-768 ile X25519) ve `HPKE-10`'dur (ML-KEM-1024 ile P-384). Saf post kuantum olanlar `HPKE-12` (ML-KEM-768) ile `HPKE-13`'tür (ML-KEM-1024). Her birinin anahtar şifreleme varyantı da vardır.

JOSE için HPKE henüz RFC değildir ve IANA JOSE kaydında HPKE girdisi bulunamamıştır.

#### 4.6 Hibrit ile bileşik imzalar

`draft-ietf-jose-pq-composite-sigs-03`, 20 Temmuz 2026 tarihli, JOSE çalışma grubunun aktif bir taslağıdır ve altı kombinasyon tanımlar.

| JOSE `alg` | COSE, belirlenecek |
|---|---|
| `ML-DSA-44-ES256` | Eksi 54 |
| `ML-DSA-65-ES256` | Eksi 55 |
| `ML-DSA-87-ES384` | Eksi 56 |
| `ML-DSA-44-Ed25519` | Eksi 57 |
| `ML-DSA-65-Ed25519` | Eksi 58 |
| `ML-DSA-87-Ed448` | Eksi 59 |

Serileştirme için `draft-ietf-lamps-pq-composite-sigs` belgesine bağımlıdır, ancak kritik bir sapma vardır: ECDSA imzası ile anahtarı, X.509'un ASN.1 yapıları olan `Ecdsa-Sig-Value` ile `ECPrivateKey` yerine JOSE ile COSE'nin ham sabit uzunluklu kodlamasını kullanmak zorundadır. Yani bileşik imzalar X.509 ile bit uyumlu değildir.

`draft-ietf-lamps-pq-composite-sigs-19`, yani X.509 tarafı, 21 Nisan 2026 tarihlidir ve RFC Editor kuyruğunda ilk düzenleme aşamasındadır; RFC numarası henüz atanmamıştır. On sekiz kombinasyon tanımlar: ML-DSA ile RSA-PSS, PKCS#1 v1.5, ECDSA, Ed25519 ile Ed448 çarpımı, brainpool eğrileri dahil.

`draft-ietf-lamps-pq-composite-kem-21`, 1 Eylül 2026 tarihlidir ve IESG değerlendirmesindedir; revize edilmiş bir taslak gerekmektedir ve iki tartışma kaydı vardır. On iki kombinasyon tanımlar: ML-KEM-768 ile 1024'ün RSA-OAEP, X25519, X448 ile ECDH çarpımı, hepsi SHA3-256 anahtar türetme fonksiyonuyla.

Okunması önerilen referans dokümanlar şunlardır. RFC 9794, Haziran 2025, "Terminology for Post-Quantum Traditional Hybrid Schemes". RFC 9955, Temmuz 2026, "Hybrid Signature Spectrums"; kritik uyarısı şudur: geriye dönük uyumluluk ile güçlü ayrılamazlık karşılıklı olarak dışlayıcıdır, yani eski istemcilerin tek bileşeni doğrulayabilmesi istenirse imza soyma saldırısına açık kalınır. RFC 9958, Haziran 2026, "Post-Quantum Cryptography for Engineers", bilgilendirici, 42 sayfa; ekibin başlangıç okumasıdır.

#### 4.7 IANA kayıt özeti, 8 Eylül 2026 kesin durumu

JSON Web Signature and Encryption Algorithms kaydında `ML-DSA-44`, `ML-DSA-65` ile `ML-DSA-87` kayıtlıdır, RFC 9964 ile opsiyonel olarak. SLH-DSA, ML-KEM, FN-DSA ile HPKE yoktur.

JSON Web Key Types kaydında `AKP`, yani algoritma anahtar çifti, kayıtlıdır; RFC 9964 ile opsiyoneldir.

COSE Algorithms kaydında şunlar vardır.

| Değer | İsim | Referans |
|---|---|---|
| Eksi 46 | HSS-LMS | RFC 8778, RFC 9053 |
| Eksi 48 | ML-DSA-44 | RFC 9964 |
| Eksi 49 | ML-DSA-65 | RFC 9964 |
| Eksi 50 | ML-DSA-87 | RFC 9964 |

SLH-DSA, ML-KEM ile FN-DSA'nın hiçbiri kayıtlı değildir.

COSE Key Types kaydında `AKP` 7'dir, RFC 9964; `HSS-LMS` 5, `WalnutDSA` 6'dır.

#### 4.8 JOSE'deki diğer ilgili değişiklikler

RFC 9864, Ekim 2025, Standards Track: "Fully-Specified Algorithms for JOSE and COSE". `EdDSA` değerini kullanımdan kaldırmakta ve yerine `Ed25519` ile `Ed448` getirmektedir; COSE'da `ESP256`, `ESP384` ile `ESP512` kullanılır. §4.3 IANA talimatlarını güncellemektedir: artık yalnızca tam belirtilmiş algoritma tanımlayıcıları kaydedilebilir. ML-DSA-44, 65 ile 87'nin baştan parametreli isimlendirilmesinin sebebi budur.

`draft-ietf-jose-deprecate-none-rsa15-05`, 23 Haziran 2026: yayın talep edilmiştir ve hedefi Proposed Standard'dır. `none` ile `RSA1_5` kullanımdan kaldırılmaktadır.

`draft-ietf-oauth-rfc8725bis-10`, 21 Ağustos 2026: JWT en iyi uygulama güncellemesidir, RFC Editor kuyruğundadır ve referans alınamadığı için bloke durumdadır, yukarıdaki kullanımdan kaldırma taslağını beklemektedir. Bu güncelleme post kuantumdan, ML-DSA'dan veya RFC 9964'ten hiç bahsetmemektedir. OAuth çalışma grubunda PQC ile ilgili hiçbir çalışma yoktur ve bu doğrudan doğrulanmıştır.

### 5. X.509 ile PKI

#### 5.1 Yayımlanmış RFC'ler

| RFC | Tarih | Konu |
|---|---|---|
| RFC 9881 | Ekim 2025 | ML-DSA için X.509 algoritma tanımlayıcıları; öncülü `draft-ietf-lamps-dilithium-certificates` |
| RFC 9882 | Ekim 2025 | CMS içinde ML-DSA |
| RFC 9814 | Temmuz 2025 | CMS içinde SLH-DSA |
| RFC 9909 | Aralık 2025 | SLH-DSA için X.509 algoritma tanımlayıcıları |
| RFC 9935 | Mart 2026 | ML-KEM için X.509 algoritma tanımlayıcıları |
| RFC 9936 | Mart 2026 | CMS içinde ML-KEM |

RFC 9881'deki ML-DSA nesne tanımlayıcıları `2.16.840.1.101.3.4.3.x` altındadır.

| Algoritma | OID | Açık anahtar | İmza | Genişletilmiş özel anahtar |
|---|---|---|---|---|
| ML-DSA-44 | sigAlgs 17 | 1.312 bayt | 2.420 bayt | 2.560 bayt |
| ML-DSA-65 | sigAlgs 18 | 1.952 bayt | 3.309 bayt | 4.032 bayt |
| ML-DSA-87 | sigAlgs 19 | 2.592 bayt | 4.627 bayt | 4.896 bayt |

Açık anahtar `SubjectPublicKeyInfo` içinde ham bayt dizisi olarak taşınır ve ASN.1 sarmalaması yoktur. Özel anahtar `OneAsymmetricKey` içinde üç seçenekle taşınır: önerilen olan 32 baytlık tohum (`[0]` etiketli), genişletilmiş biçim, veya bir SEQUENCE içinde her ikisi. Her ikisi seçeneği tam da interop kaygısı yüzünden eklenmiştir: "some may want to use and retain the seed and others may only support expanded private keys."

RFC 9909, yani SLH-DSA, 24 nesne tanımlayıcısı içerir: 12 saf biçim `sigAlgs 20` ile `31` arasında, 12 ön özetli biçim `sigAlgs 35` ile `46` arasındadır. İmza boyutları 7.856 ile 49.856 bayt arasındadır. Açık anahtar 32, 48 veya 64 bayttır. RFC'nin uyarısı şudur: "The entire certificate or CRL needs to be held in memory during SLH-DSA signature verification"; ayrıca büyük iptal listeleri donanım güvenlik modülü sınırlarını aşabilir.

RFC 9935'teki ML-KEM nesne tanımlayıcıları `id-alg-ml-kem-512` için 2.16.840.1.101.3.4.4.1, 768 için ...4.2 ile 1024 için ...4.3'tür.

`draft-ietf-lamps-fn-dsa-certificates-00`, 20 Mayıs 2026, bir çalışma grubu dokümanıdır ve FIPS 206'yı beklemektedir.

#### 5.2 CA ile tarayıcı forumu: PQC sertifikaları kamuya açık güvende henüz izinli değildir

Geçmiş bir oylama yoktur. Temel gereksinimlerde ML-DSA veya SLH-DSA'ya izin veren onaylanmış hiçbir oylama bulunamamıştır.

Devam eden çalışma `cabforum/servercert` deposundadır. PR #679, yani "SC-106: Enable Post-Quantum Cryptography (PQ) Key Pairs in TLS Server Certificates", 26 Ağustos 2026'da açılmıştır ve hâlâ taslak ile açık durumdadır. PR #662, yani "SC-XXX: Permit ML-DSA public keys and signatures in certificates", 11 Ağustos 2026'da kapatılmıştır. PR #624, yani CBonnell'in ML-DSA-87 ekleme taslağı, 29 Haziran 2026'da kapatılmıştır.

13 Ağustos 2026 tarihli sunucu sertifikası çalışma grubu tutanaklarına göre Stephen Davidson ile Gurleen Grewal birleşik bir oylama üzerinde çalışmaktadır ve tamamlanmaya yaklaşmaktadır. Yürürlük tarihi önerilmemiştir.

SC-106'nın içeriği şudur: ML-DSA-44, 65 ile 87'ye izin verilir; saf post kuantum zincir zorunluluğu getirilir, yani bir ML-DSA açık anahtarı yalnızca bir ML-DSA imzasıyla sertifikalanabilir; iptal listeleri ile OCSP'ye muafiyet tanınır.

Henüz çözülmemiş tartışma noktaları şunlardır: Mozilla ile Chrome temsilcileri geçiş ve çapraz imzalama için karışık zincirlere izin verilmesini savunmaktadır; Chrome, tarayıcı dışı PKI kullanım senaryolarının çalışma grubu kapsamında olup olmadığını sorgulamaktadır; sertifika şeffaflığı günlüklerine ML-DSA sertifika boyutunun getireceği yük tartışılmaktadır.

Kaynakları github.com/cabforum/servercert/pull/679 ile cabforum.org'un 13 Ağustos 2026 tutanaklarıdır.

#### 5.3 Chrome Quantum-resistant Root Program, X.509 PQC'yi reddetmektedir

Bu, planlama açısından çok önemli ve az bilinen bir gelişmedir.

Chrome, standart kök programının yanına ayrı bir kuantuma dayanıklı kök programı kurmuştur. Taslak politikası v0.3.0'dır ve son güncellemesi 14 Ağustos 2026'dır; birçok bölüm hâlâ yapılacak durumdadır ve v1.0.0 beklenen spesifikasyonlara bağlıdır.

Politika metnine göre Chrome, post kuantum içeren geleneksel X.509 sertifikalarını kök deposuna eklemeyecektir. Yerine Merkle ağacı sertifikaları kullanılacaktır.

Gerekçesi sıkça sorulan sorular sayfasında şöyledir: "sending heavy, serialized chains of post-quantum signatures and Certificate Transparency proofs during every TLS handshake creates severe bandwidth penalties and increases connection latency." Merkle ağacı sertifikalarında sertifika otoritesi milyonlarca sertifikayı temsil eden tek bir ağaç başlığı imzalamakta, sunucu tam zincir yerine kompakt bir kanıt göndermekte ve sertifika şeffaflığı ek yükü ortadan kalkmaktadır.

Algoritma zorunlulukları şunlardır: sertifika otoritesi ile aynalama ortak imzalayıcı anahtarları yalnızca ML-DSA-44 olabilir; abone sertifikaları ML-DSA-44, 65 veya 87 olabilir; ön özetli ML-DSA yasaktır; ML-DSA anahtarlarında `parameters` alanı bulunmamalıdır; FIPS 140-3 üçüncü seviye donanım güvenlik modülü zorunludur; sertifika otoritesi ortak imzalayıcı anahtarı için azami altı yıl güven süresi vardır.

Takvimi şöyledir. Birinci faz şu andadır: Cloudflare ile bir fizibilite çalışması ile X.509 yedekli bağlantı testleri yapılmaktadır. İkinci fazın hedefi 2027'nin ilk çeyreğidir: ilk kamusal Merkle ağacı sertifikası başlatması yapılacak ve kriterleri karşılayan sertifika şeffaflığı günlüğü operatörleri davet edilecektir; uygunluk için 1 Şubat 2026'dan önce çalışan bir günlük işletiyor olmak gerekmektedir. Üçüncü fazın hedefi 2027'nin üçüncü çeyreğidir: kuantuma dayanıklı kök deposunun açılışı ile sertifika otoritesi kayıtları yapılacaktır.

Chrome 150 ve üstü zaten özel ile kurumsal ortamlarda Merkle ağacı sertifikası olmayan post kuantum X.509 sertifikalarını desteklemektedir; yani özel PKI'da bugün test edilebilir.

Kaynakları googlechrome.github.io'daki taslak politika ile sıkça sorulan sorular sayfaları ve chromium.org'un 27 Şubat 2026 tarihli post kuantum kimlik doğrulama yol haritasıdır; yol haritası dört aşamalıdır ve tarih vermemektedir.

Mozilla tarafında blog.mozilla.org/security üzerinde PQC, ML-DSA veya kök deposu ile ilgili hiçbir gönderi bulunamamıştır ve Mozilla'nın PQC kök politikası belirsizdir.

Cloudflare'in beklentisi şudur: web PKI'da ML-DSA sertifikaları 2027 başında, Merkle ağacı sertifikası tabanlı post kuantum kimlik doğrulama 2027 ortasında ve tam post kuantum 2029'da gelecektir.

### 6. TLS

#### 6.1 RFC 10024, hibrit anahtar değişimi artık bir RFC'dir

Tam adı "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3"tür. RFC 10024, Ağustos 2026, Standards Track'tir ve öncülü `draft-ietf-tls-ecdhe-mlkem-05`'tir, 10 Ağustos 2026. Yazarları Kwiatkowski (PQShield), Kampanakis (AWS), Westerbaan (Cloudflare) ile Stebila'dır (Waterloo).

IANA TLS desteklenen gruplar kaydındaki gerçek kayıtlı değerler şunlardır.

| Değer | Onaltılık | İsim | Önerilen | Referans |
|---|---|---|---|---|
| 4587 | 0x11EB | SecP256r1MLKEM768 | Hayır | RFC 10024 |
| 4588 | 0x11EC | X25519MLKEM768 | Evet | RFC 10024 |
| 4589 | 0x11ED | SecP384r1MLKEM1024 | Hayır | RFC 10024 |
| 512 | 0x0200 | MLKEM512 | Hayır | `draft-connolly-tls-mlkem-key-agreement-05` |
| 513 | 0x0201 | MLKEM768 | Hayır | Aynı |
| 514 | 0x0202 | MLKEM1024 | Hayır | Aynı |
| 25497 | 0x63A5 | X25519Kyber768Draft00 | Önerilmez | RFC 10024 ile geçersiz kılınmıştır |
| 25498 | 0x63A6 | SecP256r1Kyber768Draft00 | Önerilmez | RFC 10024 ile geçersiz kılınmıştır |

X25519MLKEM768, önerilen olarak işaretli tek post kuantum gruptur.

Tel üzerindeki boyutlar RFC 10024 §3'tedir: X25519MLKEM768 için istemci anahtar payı 1.216 bayttır, yani 1.184 baytlık ML-KEM eklentisi ile 32 baytlık X25519; sunucu payı 1.120 bayttır; paylaşılan sır 64 bayttır.

Yan not olarak TLS 1.3 yeniden yayımlanmıştır: RFC 9846, Temmuz 2026, RFC 8446'yı geçersiz kılmaktadır ve RFC 10024 artık 9846'ya atıf yapmaktadır.

Saf ML-KEM için `draft-ietf-tls-mlkem-10`, 2 Eylül 2026, onay duyurusu gönderilmiş durumdadır, yani RFC Editor kuyruğundadır, ve hedefi bilgilendiricidir.

#### 6.2 Benimseme oranı, Eylül 2026

radar.cloudflare.com bot koruması nedeniyle HTTP 403 döndürmüştür ve canlı Eylül 2026 rakamı çekilememiştir; uydurulmamıştır. Canlı rakam bir tarayıcıyla radar.cloudflare.com/post-quantum adresinden görülebilir.

Cloudflare'in birincil kaynaklarındaki belgelenmiş seyir şöyledir.

| Tarih | Rakam | Kaynak |
|---|---|---|
| 2024 başı | Yüzde üçün altı | blog.cloudflare.com'un radar yazısı |
| Eylül 2025 | En büyük 100 bin alan adının %39'u post kuantum anahtar değişimini desteklemektedir | blog.cloudflare.com/pq-2025 |
| Ekim 2025 | İnsan kaynaklı trafiğin yarısından fazlası | Aynı yazı, 28 Ekim 2025 |
| Şubat 2026 | Yüzde altmışın üzerinde | Radar yazısı, 27 Şubat 2026 |
| 7 Nisan 2026 | İnsan trafiğinin %65'inin üzerinde | blog.cloudflare.com/post-quantum-roadmap |
| 23 Haziran 2026 | Tarayıcı trafiğinin üçte ikisinden fazlası | blog.cloudflare.com/post-quantum-eo-2026 |

Kaynak sunucu tarafı çok geridedir: Cloudflare'den müşteri kaynak sunucusuna giden bağlantılarda kaynakların yalnızca yaklaşık %10'u post kuantum anahtar değişimini desteklemektedir, Şubat 2026 itibarıyla; bu, 2025 başındaki yüzde birin altındaki orandan yaklaşık on kat artıştır.

Metrik uyarısı şudur: Cloudflare'in manşet rakamı insan veya tarayıcı kaynaklı trafiktir. Bot ile API istemcileri dahil tüm trafik rakamı daha düşüktür ve o rakam bulunamamıştır.

#### 6.3 İstemci ile kütüphane durumu

| Ürün | Durum | Sürüm ile tarih |
|---|---|---|
| Chrome | M124'te, yani Nisan 2024'te, X25519Kyber768 varsayılan olmuştur; M131'de ML-KEM'e geçilmiştir, 6 Kasım 2024. Politika metni şöyledir: "Prior to Google Chrome 131, the algorithm was Kyber." | M131 |
| Chrome kapatma anahtarı | `PostQuantumKeyAgreementEnabled` kaldırılmıştır, `chrome.*:116-146` aralığında geçerliydi. M147 kararlı sürümü 7 Nisan 2026'da çıkmıştır ve artık kapatmanın desteklenen bir yolu yoktur | M147 ve üstü |
| Chrome kararlı sürüm, bugün | 152.0.7977.83; M152 kararlı sürümü 25 Ağustos 2026'dadır | — |
| Firefox | 132'de, yani 29 Ekim 2024'te, TLS 1.3 için `mlkem768x25519` gelmiştir. 135'te, yani 4 Şubat 2025'te, HTTP/3 ile QUIC desteği gelmiştir | 132 ile 135 |
| Apple | Apple platform güvenliği dokümanı şöyle demektedir: "On devices with iOS 26, iPadOS 26, or later, TLS 1.3 with quantum-secure encryption (X25519MLKEM768) is enabled by default for URLSession and Network APIs" | iOS, iPadOS ile macOS 26, Eylül ile Ekim 2025 |
| OpenSSL | 3.5.0, 8 Nisan 2025, ilk uzun destekli sürümdür ve desteği 8 Nisan 2030'a kadardır. ML-KEM, ML-DSA ile SLH-DSA içerir. Varsayılan anahtar payı X25519MLKEM768 ile X25519'dur. OpenSSL 3.0 uzun destekli sürümünün desteği 7 Eylül 2026'da, yani dün, bitmiştir | 3.5 uzun destekli |
| BoringSSL | `SSL_GROUP_X25519_MLKEM768` 0x11ec'tir; `SSL_SIGN_ML_DSA_44`, `65` ile `87` sırasıyla 0x0904, 0x0905 ile 0x0906'dır | Ana dal |
| Go | 1.24'te, yani Şubat 2025'te, X25519MLKEM768 varsayılan olmuştur; `GODEBUG=tlsmlkem=0` ile geri alınır | 1.24 |
| rustls | 0.23.16'da Kyber'den ML-KEM'e geçilmiştir; 0.23.22'de, 30 Ocak 2025, X25519MLKEM768 gelmiştir; 0.23.27'de, 5 Mayıs 2025, `prefer-post-quantum` varsayılan bir özellik olmuştur; 0.23.37'de, 24 Şubat 2026, ML-KEM-1024 gelmiştir | 0.23.27 ve üstü |

#### 6.4 TLS'te ML-DSA ile kimlik doğrulama

`draft-ietf-tls-mldsa-05`, 6 Temmuz 2026 tarihlidir. IESG durumu onay duyurusunun gönderileceği ile alan direktörü takibi aşamasındadır; yani IESG onaylamıştır ancak henüz RFC değildir. Hedef statüsü bilgilendiricidir ve sorumlu alan direktörü Deb Cooley'dir.

IANA TLS imza şeması kaydındaki değerler şunlardır.

| Onaltılık | İsim | Önerilen | Referans |
|---|---|---|---|
| 0x0904 | mldsa44 | Hayır | `draft-ietf-tls-mldsa-00` |
| 0x0905 | mldsa65 | Hayır | `draft-ietf-tls-mldsa-00` |
| 0x0906 | mldsa87 | Hayır | `draft-ietf-tls-mldsa-00` |
| 0x0911 ile 0x091C arası | `slhdsa_sha2_128s`'ten `slhdsa_shake_256f`'e kadar 12 adet | Hayır | `draft-reddy-tls-slhdsa-01` |

Kayıt hâlâ sıfırıncı revizyona atıf yapmaktadır ve RFC çıkınca güncellenecektir. Tüm post kuantum imza şemaları önerilmeyen olarak işaretlidir.

Gerçekten ML-DSA ile TLS kimlik doğrulaması yapanlar şunlardır. Cloudflare 29 Temmuz 2026'da kaynak sunuculara post kuantum kimlik doğrulamasının desteklendiğini duyurmuştur: ML-DSA-44, 65 ile 87 desteklenmektedir; tüm planlarda ücretsiz olan doğrulanmış kaynak çekmeleri ile sertifika yönetimi gerektiren özel kaynak güven deposu bunu kullanmaktadır. Cloudflare ML-DSA-44'ü önermektedir. Özellik Haziran 2026'da başlatılmış ve 10 Haziran 2026'da bir BoringSSL güncellemesi kesintiye yol açmıştır. rustls 0.23.44, 7 Eylül 2026, yani dün, şöyle demektedir: "Support for post-quantum secure ML-DSA certificates is now enabled by default in the aws-lc-rs crypto provider." Öncesinde rustls-post-quantum 0.2.3, 16 Temmuz 2025, doğrulama getirmiş; 0.2.4, 23 Eylül 2025, imzalamayı `aws-lc-rs-unstable` altında getirmiştir.

Hiçbir kamuya açık web PKI sertifika otoritesi tarayıcıya dönük TLS için ML-DSA sertifikası vermemektedir. Bugün bu tamamen özel PKI ile kaynak sunucuya dönük bir hikâyedir.

#### 6.5 Bilinen sorunlar

**İstemci merhabası boyutu, azami iletim birimi ile kemikleşme.** X25519MLKEM768 istemci anahtar payını 1.216 bayta çıkarmaktadır ve tipik bir istemci merhabası artık tek bir TCP segmentine ya da QUIC ilk paketine sığmamaktadır. Chrome politika metni şöyledir: "devices that do not correctly implement TLS may malfunction when offered the new option… Such devices are not post-quantum-ready and will interfere with an enterprise's post-quantum transition." Go 1.24 notları doğrudan tldr.fail adresine yönlendirmektedir; istemci merhabasını segmentler arasında birleştiremeyen sunucular el sıkışmayı zaman aşımına uğratmaktadır. RFC 10024'ün kendisinde azami iletim birimi, ara kutu veya parçalanma rehberliği yoktur; metin bu terimler için taranmış ve hiçbiri bulunamamıştır. Bu tartışma implementasyon dokümanlarındadır.

**Ölçülmüş ara kutu kırılması.** Cloudflare'in kaynak sunuculara yönelik pq-2025 ölçümüne göre hızlı yaklaşım, yani post kuantum anahtar payını iyimser göndermek, bağlantıların %0,05'ini kırmaktadır; güvenli yaklaşım, yani grubu ilan edip anahtar payı göndermemek ve bir yeniden merhaba turunu kabul etmek, evrensel olarak tolere edilmektedir.

**Sertifika ile imza boyutu.** Cloudflare'in duruşu 9 Temmuz 2026 tarihli yazısında şudur: daha iyisi zamanında gelmemektedir, çünkü FN-DSA yaklaşık 2033'te, çok değişkenli şemalar 2034'ten önce değil ve SQIsign 2035'ten önce olası değildir; 2030 ile 2035 arasındaki düzenleme tarihlerine karşı ML-DSA idare etmek zorundadır.

**Güven çıpası kimlikleri.** `draft-ietf-tls-trust-anchor-ids-04`, 1 Mayıs 2026, aktif bir TLS çalışma grubu dokümanıdır ve IESG'de işlem yoktur. Chrome'da özellik numarası 5132064512540672'dir, durumu önerilmiştir ve kilometre taşı atanmamıştır; yani sevk edilmemektedir.

**Merkle ağacı sertifikaları.** Çalışma grubu değişmiştir: `draft-davidben-tls-merkle-tree-certs` süresi dolmuş ve yeni PLANTS çalışma grubuna, yani PKI, günlükler ile ağaç imzaları grubuna, kabul edilmiştir; sonucu `draft-ietf-plants-merkle-tree-certs-05`'tir, 6 Temmuz 2026, mevcut bir internet taslağıdır.

### 7. FIDO2 ile WebAuthn PQC, ekosistemin en geri kalmış alanı

#### 7.1 WebAuthn Level 3 W3C önerisi olmuştur ancak PQC yoktur

Durumu W3C önerisidir ve 25 Ağustos 2026 tarihlidir, yani çok yenidir.

Doküman post kuantum kriptografiden, ML-DSA'dan veya kuantum kelimesinden hiç bahsetmemektedir. Spesifikasyon EdDSA, ES256 ile RS256 gibi mevcut eğri ile RSA algoritmalarına odaklıdır.

Level 4 diye bir halef yoktur; doküman kendini 2021 tarihli Level 2'nin halefi olarak tanımlamakta ve ileriye dönük bir referans içermemektedir. Kaynağı w3.org/TR/webauthn-3'tür.

#### 7.2 CTAP'ta PQC yoktur

| Sürüm | Durum | Tarih |
|---|---|---|
| CTAP 2.3.1 | Çalışma taslağı | 29 Mayıs 2026 |
| CTAP 2.3 | Önerilen standart | 26 Şubat 2026 |
| CTAP 2.2 | Önerilen standart | 14 Temmuz 2025 |
| CTAP 2.1 | Önerilen standart | 15 Haziran 2021; errata 21 Haziran 2022 |

CTAP 2.3 spesifikasyon metni doğrudan çekilmiştir: post kuantum, kuantum, ML-DSA ile Dilithium kelimeleri ve eksi 48, 49 ile 50 kod noktaları geçmemektedir. Spesifikasyon algoritma seçimini IANA COSE kaydına ile WebAuthn'a devretmektedir: "PublicKeyCredentialParameters' algorithm identifiers are values that SHOULD be registered in the IANA COSE Algorithms registry."

Teorik olarak iyi haber şudur: COSE ML-DSA kod noktaları, yani eksi 48, 49 ile 50, RFC 9964 ile IANA'ya kayıtlı olduğu için CTAP ile WebAuthn'ın spesifikasyon değişikliği gerektirmeden ML-DSA'yı taşıyabilmesi mimari olarak mümkündür. Engel spesifikasyon değil donanımdır.

#### 7.3 Donanımda hiçbir ürün yoktur ve yeni donanım gerekmektedir

Yubico'nun 21 Ekim 2025 tarihli "Future-proofing authentication: A look at the future of post-quantum cryptography" başlıklı blog yazısı nettir:

> "Prototype ≠ product: The PQ demo shows feasibility and performance direction, not a shipment announcement."
>
> "New hardware is required: PQ algorithms have bigger footprints; they don't fit on today's keys."

FIDO Authenticate konferansında bir donanım güvenlik anahtarında post kuantum imza prototipi gösterilmiştir. Beta yetenekler sınırlı sayıda nitelikli test kullanıcısına açıktır.

Yubico ayrıca standartların olgunlaşması gerektiğini vurgulamaktadır: yalnızca imza üretimi değil, PIN protokolleri, attestation, kayıt kullanıcı deneyimi ile kriptografik çeviklik altyapısı da gerekmektedir.

Yubico'nun 26 Haziran 2026 tarihli EO 14412 yazısında hiçbir ürün veya takvim güncellemesi yoktur; yalnızca kurumlara şu tavsiye verilmektedir: "Hardware security keys, smart cards, and tokens used in your authentication stack need to support PQC algorithms ML-KEM and ML-DSA". Kendi ürünleri hakkında bir beyan yoktur.

Yubico'nun mevcut blog akışında, yani Ağustos ile Eylül 2026'da, bir PQC gönderisi yoktur. HyperCloud entegrasyonunda hibrit post kuantum, yani RSA ile ML-KEM, duran veri şifrelemesi geçmektedir; ancak bu bir veri şifrelemesidir, FIDO kimlik bilgisi değildir.

Sonuç şudur: 8 Eylül 2026 itibarıyla ML-DSA destekleyen ve sevk edilen hiçbir FIDO2 donanım kimlik doğrulayıcısı bulunamamıştır.

#### 7.4 FIDO Alliance'ın normatif çıktısı yoktur

fidoalliance.org üzerinde PQC ile ilgili bulunanlar yalnızca etkinlik ile web semineri düzeyindedir: "How Passkeys and Post-Quantum Cryptography Are Reshaping the Future of Security" (web semineri, 1 Temmuz 2026); "Member Event: Future-Proofing Authentication: FIDO, PKI, and the Path to Post-Quantum Security" (11 Ağustos 2025); "IEEE Spectrum: Google Develops Quantum-Safe Security Keys" (haber alıntısı, 1 Eylül 2023; Google'ın OpenSK'daki Dilithium ile ECDSA hibrit denemesi).

Bulunamayanlar şunlardır: FIDO Alliance'ın yayımlanmış bir PQC yol haritası, beyaz kâğıdı, PQC sertifikasyon programı veya PQC algoritması ekleyen bir CTAP taslağı. PQC'yi ele alan resmî bir FIDO Alliance normatif dokümanı yoktur.

Not olarak bu bölümde arama bütçesi tükendiği için yalnızca doğrudan site çekimleriyle çalışılmıştır. Duyurulmuş ancak bu sayfalarda listelenmemiş bir çalışma olabilir; kısmen belirsizdir.

### 8. Rust ekosistemi

#### 8.1 Saf Rust, RustCrypto

| Crate | Sürüm | Tarih | İndirme | Depo |
|---|---|---|---|---|
| `ml-kem` | 0.3.2 | 10 Mayıs 2026 | 2.464.049 | RustCrypto/KEMs |
| `ml-dsa` | 0.1.1 | 5 Haziran 2026 | 770.685 | RustCrypto/signatures |
| `slh-dsa` | 0.2.0-rc.5 | 28 Nisan 2026 | 876.336 | RustCrypto/signatures |

Her üçünün README dosyasında da aynı uyarı vardır: "Security Warning — The implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!"

Ek olarak sabit zaman garantisi veya yan kanal direnci hakkında hiçbir beyan yoktur; ACVP test vektörü uyumu belirtilmemiştir. `ml-kem` crate'inde `zeroize` opsiyonel bir özelliktir ve varsayılan değildir. Hepsi hâlâ 1.0 öncesidir ve `slh-dsa` bir sürüm adayıdır.

Bir IdP'nin imza yolunda bunların kullanılması önerilmez: denetlenmemişlerdir, 1.0 öncesidirler ve yan kanal beyanları yoktur.

#### 8.2 aws-lc-rs, üretim için en olgun seçenek

Sürümü 1.18.1'dir, 1 Eylül 2026 tarihlidir ve 214,9 milyondan fazla toplam indirmesi vardır; yakın dönemde 78,8 milyon indirilmiştir. AWS-LC bağlamasıdır, yani saf Rust değildir, ve `ring` ile API uyumludur.

ML-KEM tarafında `aws_lc_rs::kem` modülünde `ML_KEM_512`, `ML_KEM_768` ile `ML_KEM_1024` vardır; NIST FIPS 203 olarak belgelenmiştir ve kararsız işaretli değildir.

ML-DSA tarafında `aws_lc_rs::signature` modülünde doğrulama için `ML_DSA_44`, `ML_DSA_65` ile `ML_DSA_87`, imzalama için `ML_DSA_44_SIGNING`, `ML_DSA_65_SIGNING` ile `ML_DSA_87_SIGNING` vardır. Dokümantasyon şöyle demektedir: "The signature is the raw ML-DSA signature encoding described in FIPS 204." Kararsız işaretli değildir.

SLH-DSA için dokümantasyonda desteğe dair bir kanıt yoktur.

#### 8.3 FIPS 140-3 validasyonu PQC için henüz yoktur

Bu, FIPS zorunluluğu olan bir IdP için kritik bir bulgudur.

CMVP'de aktif sertifika araması, yani algoritma ML-KEM ile durum aktif filtresi, sıfır sonuç vermekte ve arama kriterlerine uyan sertifika bulunmadığını söylemektedir.

AWS-LC'nin en yeni validasyonu 5429 numaralı sertifikadır: "AWS-LC Cryptographic Module (dynamic)", 20 Temmuz 2026, FIPS 140-3 genel birinci seviye, batımı 13 Ağustos 2029. Onaylı algoritmaları AES (CBC, CCM, CMAC, CTR, ECB, GCM, GMAC, KW, KWP ile XTS modlarında), SHA-1, SHA-2, ECDSA, RSA, HKDF ile SSH, TLS ve PBKDF türetmeleri, KAS-ECC-SSC ile sayaç tabanlı deterministik rastgele bit üretecidir. ML-KEM ile ML-DSA bu listede yoktur.

Aktif AWS-LC sertifikaları 5429 (20 Temmuz 2026), 5314 (5 Haziran 2026), 5298 (3 Haziran 2026), 5146 (26 Ocak 2026), 4816 (1 Ekim 2024) ile 4631'dir (6 Ekim 2023).

İşlemdeki modüller listesinde, ki 201 modül vardır, `AWS-LC 4 Cryptographic Module` dinamik ile statik biçimlerde yer almakta ve laboratuvar yorum çözümü aşamasındadır, 14 Ağustos 2026. Ayrıca kuyrukta Code Siren PQC Library'nin masaüstü ile mobil sürümleri, CryptoComply 140-3 FIPS Provider with PQC (4 Eylül 2026) ile PQCryptoLib-Core (25 Ağustos 2026) bulunmaktadır.

> **Sonuç.** `aws-lc-rs`'i `fips` özelliğiyle derlemek size FIPS validasyonlu ML-KEM veya ML-DSA vermez. PQC algoritmaları validasyon sınırının dışındadır. FIPS 140-3 zorunluluğunuz varsa PQC'yi bugün FIPS modunda kullanamazsınız ve AWS-LC 4 validasyonunu beklemeniz gerekir.
>
> Belirsizlik şudur: CMVP arama arayüzünün algoritma filtresinin tam eşleşme yapıp yapmadığı doğrulanamamıştır; ancak 5429 numaralı sertifikanın detay sayfasında ML-KEM ile ML-DSA'nın bulunmaması bulguyu bağımsız olarak desteklemektedir.

#### 8.4 Diğer crate'ler

| Crate | Sürüm | Tarih | Not |
|---|---|---|---|
| `oqs`, yani liboqs-rust | 0.11.0 | 1 Mayıs 2025 | liboqs bağlamasıdır; OQS projesi genel olarak üretim için uygun olmadığı uyarısını taşımaktadır. Bir buçuk yıldır güncellenmemiştir |
| `pqcrypto` | 0.18.1 | 11 Aralık 2024 | Thom Wiggers'ındır. ML-KEM, McEliece, HQC, ML-DSA, Falcon ile SPHINCS+ içerir. Yaklaşık iki yıldır güncellenmemiştir |
| `fips204` | 0.4.6 | 22 Aralık 2024 | integritychain'indir, yaklaşık 1.714 satırdır. Yaklaşık iki yıldır güncellenmemiştir |
| `rustls` | 0.23.44 | 7 Eylül 2026 | Aşağıya bakınız |

#### 8.5 rustls

Sürümü 0.23.44'tür ve 7 Eylül 2026, yani dün, çıkmıştır.

aws-lc-rs sağlayıcısıyla desteklenen anahtar değişim grupları SECP256R1, SECP384R1, X25519, MLKEM768, MLKEM1024, X25519MLKEM768 ile SECP256R1MLKEM768'dir.

0.23.27'den, yani 5 Mayıs 2025'ten itibaren `prefer-post-quantum` varsayılan bir özelliktir ve post kuantum anahtar değişimi varsayılan olarak tercih edilmektedir. 0.23.44 ile aws-lc-rs sağlayıcısında ML-DSA sertifikaları varsayılan olarak etkindir.

Rust tarafında TLS için durum iyidir; sorun JOSE tarafındadır.

#### 8.6 Rust JOSE ile JWT tarafında RFC 9964 implementasyonu yoktur

| Crate | Sürüm | Tarih | ML-DSA var mı |
|---|---|---|---|
| `josekit` | 0.10.3 | 20 Mayıs 2025 | Yoktur; RFC 9964'ten, yani Mayıs 2026'dan bir yıl öncedir ve PQC olması mümkün değildir |
| `jsonwebtoken` | 11.0.0 | 24 Temmuz 2026 | Yoktur; `Algorithm` enum'u HS256, HS384, HS512, ES256, ES384, RS256, RS384, RS512, PS256, PS384, PS512 ile EdDSA içerir ve post kuantum varyant yoktur |

Bulunamayan şey şudur: RFC 9964'ü, yani `ML-DSA-44`, `ML-DSA-65` ile `ML-DSA-87` algoritmalarını ve `AKP` anahtar tipini uygulayan hiçbir Rust crate'i yoktur.

> **Bu, ekip için en somut boşluktur.** JWS ile JWT tarafında ML-DSA'yı bugün kullanmak isteniyorsa kendimiz yazmamız gerekecektir: `aws-lc-rs`'in ML-DSA imzalama API'si alınıp üzerine RFC 9964'ün JWS serileştirmesi ile AKP JWK tipi, yani yalnızca tohum içeren `priv` ile base64url kodlu `pub`, inşa edilir. İyi haber iş yükünün küçük olmasıdır: ML-DSA'nın JWS entegrasyonu düz bir imzala ve doğrula işidir ve RSA-PSS'teki gibi bir parametre karmaşası yoktur.

Rust OIDC ile IdP çatılarında, yani `openidconnect`, `rauthy` ile `oxide-auth`'ta PQC desteği araştırılamamıştır ve belirsizdir; arama bütçesi tükenmiştir.

### 9. Bir IdP ekibi için pratik çıkarımlar

**Bugün yapılabilecekler.**

1. TLS sonlandırmasında X25519MLKEM768 açılır. RFC 10024 ile standarttır, önerilen olarak işaretlidir ve trafiğin yaklaşık üçte ikisi zaten kullanmaktadır. rustls 0.23.27 ve üstü ile OpenSSL 3.5 uzun destekli sürümünde bedava gelir. Şimdi topla sonra çöz riskini bugün kapatır.
2. Kaynak sunucu ile servis içi mTLS'te ML-DSA'ya geçilir. Özel PKI kontrol ediliyorsa engel yoktur: RFC 9881, rustls 0.23.44 varsayılan açık hâliyle ve aws-lc-rs yeterlidir. Cloudflare bunu Temmuz 2026'dan beri üretimde yapmaktadır.
3. Kriptografik çeviklik borcu şimdi ödenir. JWKS'in `kty: "AKP"` taşıyabilmesi, `alg` izin listesinin veri odaklı olması ve anahtar rotasyonunun algoritma değişimini destekleyebilmesi gerekir. En pahalı iş budur ve şimdi yapılabilir.
4. Kriptografik malzeme listesi çıkarılır. EO 14412 uyarınca CISA rehberliği gelmektedir; federal bir müşteri varsa zaten isteyecektir.
5. Anahtar üretimi tohum tabanlı kurgulanır. RFC 9964 `priv` için 32 baytlık tohumu zorunlu kılmaktadır. Donanım güvenlik modülü yalnızca genişletilmiş anahtar veriyorsa bu şimdi öğrenilmelidir.

**Şimdi başlatılabilecek işler.**

6. RFC 9964 JWS desteği kendimiz yazılır, çünkü Rust'ta yoktur. `aws-lc-rs` üzerine ince bir katmandır. JWKS'te AKP anahtarları yayımlamaya başlanır; istemciler algoritmayı tanımıyorsa yok sayacaktır.
7. Token boyutu bütçesi test edilir. ML-DSA-44 imzası 2.420 bayttır ve base64url ile yaklaşık 3.227 karakter eder. Ed25519 ile karşılaştırıldığında, ki 64 bayt ve 86 karakterdir, fark büyüktür. Çerez boyut limitleri 4 KB, HTTP başlık limitleri nginx'te varsayılan 8 KB ve yük dengeleyicide 16 KB, ayrıca URL fragment akışları kırılabilir. Bu bugün ölçülmelidir.

**Beklenmesi gerekenler.**

8. JWE için post kuantum şifreleme yoktur. `draft-ietf-jose-pqc-kem-06` yalnızca COSE'u kapsamaktadır ve `draft-ietf-jose-hpke-encrypt-22` ML-KEM içermemektedir. Şifreli kimlik token'ı veya JARM kullanılıyorsa bugün kuantum güvenli bir seçenek yoktur.
9. Kamuya açık güvende PQC sertifikaları beklemektedir. CA ile tarayıcı forumundaki SC-106 hâlâ taslak bir PR'dır. Chrome ise X.509 PQC'yi kök deposuna almayacağını ilan etmiş ve Merkle ağacı sertifikalarına yönelmiştir; ikinci fazı 2027'nin ilk çeyreği, üçüncü fazı üçüncü çeyreğidir. Cloudflare beklentisi web PKI'da ML-DSA için 2027 başıdır.
10. FIDO2 PQC beklemektedir. WebAuthn Level 3'te bahsi bile yoktur, CTAP 2.3'te yoktur ve donanım yoktur; Yubico yeni donanım gerektiğini söylemektedir. Bu, 2028 ve sonrasının konusudur. Passkey stratejisi buna göre planlanmalıdır; passkey'ler kuantum geçişinde en geç kalan halka olacaktır.
11. FIPS 140-3 validasyonlu PQC kuyruktadır ve henüz yoktur. AWS-LC 4 yorum çözümü aşamasındadır.
12. JOSE ile COSE için SLH-DSA IESG'dedir ancak kod noktaları henüz IANA'da yoktur; ayrıca yalnızca iki parametre seti, yani 128s varyantları, tanımlanmaktadır.

**Takvim çıpaları.**

| Tarih | Olay |
|---|---|
| 2027 birinci çeyrek | Chrome kuantuma dayanıklı kök programının ikinci fazı, yani Merkle ağacı sertifikası başlatması |
| Yaklaşık 2027 | Aynı programın üçüncü fazı; Cloudflare beklentisiyle web PKI'da ML-DSA; NIST hedefiyle HQC finali |
| 2026 sonu ile 2027 başı | FIPS 206 ile FN-DSA; `draft-ietf-cose-falcon` beklentisidir |
| 2029 | Cloudflare'in tam post kuantum hedefi |
| 31 Aralık 2030 | EO 14412 ile anahtar tesisinin PQC'ye geçmesi ve yüklenicilerin uyumu; CNSA 2.0 ile yazılım imzalama ve ağ ekipmanı |
| 31 Aralık 2031 | EO 14412 ile imza ve kimlik doğrulamanın PQC'ye geçmesi; bu, IdP'nin asıl tarihidir |
| 2033 | CNSA 2.0 ile web, bulut ve işletim sistemleri |
| 2035 | IR 8547 taslağındaki yasaklama tarihi |

**Parametre seti çelişkisine dikkat.** Web ile IETF ekosistemi ML-DSA-44 ile ML-KEM-768 etrafında toplanmaktadır: Chrome kuantuma dayanıklı kök programı sertifika otoritesi ortak imzalayıcıları için ML-DSA-44'ü zorunlu kılmakta, Cloudflare ML-DSA-44 önermekte ve X25519MLKEM768 önerilen olarak işaretli tek grup olmaktadır. CNSA 2.0 ise yalnızca ML-DSA-87 ile ML-KEM-1024'e izin vermektedir. Ulusal güvenlik sistemi müşterisi varsa iki ayrı profil desteklenmesi gerekecektir.

### 10. Belirsizlikler ve bulunamayanlar, dürüst liste

**Bulunamayan veya doğrulanamayanlar.**

1. Cloudflare Radar'ın canlı Eylül 2026 yüzdesi: radar.cloudflare.com bot koruması nedeniyle 403 döndürmüş ve Radar API'si bir jeton istemiştir. Rakam uydurulmamıştır. Alıntılanabilir en güncel rakam 23 Haziran 2026 tarihli üçte ikiden fazla ifadesidir. Bot dahil tüm trafik rakamı hiç bulunamamıştır.
2. NSA'nın CNSA 2.0 birincil PDF'i: media.defense.gov ile nsa.gov 403 döndürmüştür. Takvim tablosu ikincil kaynaktandır ve doğrulanması gerekir. NSA'nın 2025 veya 2026'da takvimi revize edip etmediği belirsizdir.
3. HQC'nin FIPS numarası: hiçbir NIST kaynağında atanmış bir numara yoktur ve dolaşan FIPS 207 iddiası doğrulanamamıştır.
4. FIPS 206 taslağının 28 Ağustos 2025'te onaya gönderildiği iddiası: yalnızca ikincil kaynaklardadır ve NIST'te doğrulanamamıştır.
5. Federal Register'da EO 14412'nin resmî sitesi veya atfı: federalregister.gov erişimi engellemiştir. Ancak whitehouse.gov'dan doğrudan doğrulanmıştır.
6. Rust OIDC ile IdP çatılarında PQC desteği, yani `openidconnect`, `rauthy` ile `oxide-auth`: araştırılamamıştır, arama bütçesi tükenmiştir.
7. Mozilla kök deposunun PQC politikası: blog.mozilla.org/security'de hiçbir PQC gönderisi yoktur.
8. FIDO Alliance'ın duyurulmuş ancak site listelerinde görünmeyen bir PQC çalışması olabilir; bu bölüm yalnızca doğrudan site çekimiyle yapılmıştır ve kısmen belirsizdir.

**Çelişkili veya dikkat gerektirenler.**

9. Firefox'ta varsayılan açık olan sürüm: Firefox 132 notu destek eklendiğini söylemekte, Cloudflare Kasım 2024'te varsayılan olduğunu söylemektedir. Mozilla'nın birincil kaynağından tercih varsayılanı doğrulanamamıştır; muhtemelen 132'dir ancak belirsizdir.
10. Chrome 131'in ML-KEM geçiş noktası bir kurumsal politika açıklamasından çıkarılmıştır; otoriterdir ancak bir sürüm notu değildir.
11. `draft-ietf-tls-mldsa` ile `draft-ietf-tls-mlkem` ikisi de bilgilendiricidir; kod noktası kaydı için alışılmadıktır. Datatracker API'sinden doğrulanmıştır ancak çalışma grubu gerekçesi bulunamamıştır.
12. COSE kod noktası çakışması riski: `cose-falcon` eksi 54 ile 55'i, `jose-pq-composite-sigs` eksi 54 ile 59 arasını istemektedir. İkisi de belirlenecek durumdadır ve bu değerler koda sabit yazılmamalıdır.
13. CMVP'de algoritma ML-KEM aramasının sıfır sonuç vermesi filtre davranışından da kaynaklanabilir; ancak AWS-LC 5429 numaralı sertifikanın detayında ML-KEM ile ML-DSA'nın olmaması bulguyu desteklemektedir.

### Kaynak adresleri

**NIST.** csrc.nist.gov/pubs/fips/203/final; /204/final; /205/final; post kuantum kriptografi standardizasyon sayfası; PQC haber sayfası; /pubs/ir/8545/final; /pubs/ir/8547/ipd; /pubs/ir/8610/final; /pubs/sp/800/208/final; /pubs/sp/800/227/final; /pubs/sp/800/230/ipd; /pubs/sp/800/131/a/r3/ipd; nist.gov'un Mart 2025 HQC duyurusu; CMVP 5429 numaralı sertifika sayfası; CMVP işlemdeki modüller listesi.

**Beyaz Saray.** whitehouse.gov'un 2026/06 tarihli EO 14412 sayfası.

**IETF ile IANA.** RFC 9964, 9881, 9909, 9935, 10024, 9864, 9958 ile 9955; IANA COSE, JOSE ile TLS parametre kayıtları; COSE, JOSE, LAMPS ile PQUIP çalışma grubu doküman listeleri; `draft-ietf-cose-sphincs-plus`, `draft-ietf-cose-falcon`, `draft-ietf-jose-pqc-kem`, `draft-ietf-jose-hpke-encrypt`, `draft-ietf-jose-pq-composite-sigs`, `draft-ietf-lamps-pq-composite-sigs`, `draft-ietf-lamps-pq-composite-kem`, `draft-ietf-tls-mldsa`, `draft-ietf-tls-mlkem`, `draft-ietf-tls-trust-anchor-ids`, `draft-ietf-plants-merkle-tree-certs` ile `draft-ietf-oauth-rfc8725bis` sayfaları.

**PKI ile tarayıcı.** github.com/cabforum/servercert/pull/679; cabforum.org'un 13 Ağustos 2026 tutanağı; googlechrome.github.io'daki kuantuma dayanıklı kök programı politikası ile sıkça sorulan sorular; chromium.org'un post kuantum kimlik doğrulama yol haritası.

**FIDO ile W3C.** w3.org/TR/webauthn-3; fidoalliance.org'un spesifikasyon indirme sayfası; Yubico'nun post kuantum kriptografi yazısı.

**Cloudflare.** blog.cloudflare.com'un pq-2025, post-quantum-roadmap, ml-dsa-will-have-to-do, post-quantum-authentication-to-origins, radar-origin-pq-key-transparency-aspa ile post-quantum-eo-2026 yazıları.

**Rust.** RustCrypto'nun ml-dsa ile ml-kem depoları; docs.rs'te aws-lc-rs'in kem ile signature modülleri; AWS-LC'nin PQREADME dosyası; docs.rs'te rustls'in anahtar değişim grubu modülü; docs.rs'te jsonwebtoken'ın `Algorithm` enum'u.

**Diğer.** openssl-library.org'un 3.5 sürüm notları; go.dev'in Go 1.24 dokümanı; support.apple.com'un TLS güvenlik sayfası; tldr.fail.

---

## Hat 2 — WebAuthn Level 3, CTAP 2.3 ile passkey ekosistemi

Bu, 8 Eylül 2026 tarihli bir WebAuthn ile passkey durum raporudur ve Rust tabanlı, sunucu tarafı bir kimlik sağlayıcı, yani ilgili taraf, ekibi içindir.

**Metodoloji notu.** Aşağıdaki bulguların büyük kısmı birincil kaynaklardan doğrulanmıştır: w3.org/TR, fidoalliance.org'un spesifikasyon dizin listeleri, github.com/w3c/webauthn, crates.io API'si ile ham GitHub kaynak dosyaları. Doğrulanamayan noktalar açıkça işaretlenmiştir. Bu oturumda web arama kotası dolmuştur ve son bölümdeki bazı boşluklar bu yüzden kapatılamamıştır.

### 1. WebAuthn Level 3 spesifikasyon durumu

| Öğe | Değer |
|---|---|
| Tam ad | Web Authentication: An API for accessing Public Key Credentials, Level 3 |
| Durum | W3C önerisidir, yani tamamlanmıştır |
| Öneri tarihi | 25 Ağustos 2026 |
| Sabit adres | w3.org/TR/2026/REC-webauthn-3-20260825 |
| Canlı adres | w3.org/TR/webauthn-3 |
| Aday öneri anlık görüntüsü | 26 Mayıs 2026 |
| Önerilen öneri duyurusu | 20 Temmuz 2026 |

Spesifikasyon metni şöyle demektedir: "There have been no substantive changes since the Candidate Recommendation Snapshot of 26 May 2026." Yani Mayıs 2026'dan beri normatif bir değişiklik yoktur ve Level 3'e karşı kodlamak artık güvenlidir.

Kaynakları w3.org/TR/webauthn-3 ile w3.org'un 2026 tarihli iki haber sayfasıdır.

**Level 4 başlamış mıdır.** Evet, tam şu anda başlamaktadır.

W3C Web Authentication çalışma grubunun 2026 taslak charter'ı tek normatif çıktı olarak WebAuthn Level 4'ü listelemektedir. Charter iki yıllıktır ve Level 4 için hedef tamamlanma 2028'in dördüncü çeyreğidir. Önceki charter 30 Nisan 2024 ile 30 Nisan 2026 arasındaydı. Kaynağı w3c.github.io'daki charter taslağıdır.

GitHub'daki "L4 (First Published Working Draft)" kilometre taşının son tarihi 9 Eylül 2026'dır, yani yarındır; %81 tamamlanmıştır ve 11 açık ile 47 kapalı issue vardır. Kaynağı github.com/w3c/webauthn/milestone/27'dir.

Level 4 kapsamına giren açık issue'lar şunlardır; ilgili taraf tarafını ilgilendirenler öne çıkmaktadır. #2291 anlık kullanıcı arayüzü modunu eklemektedir, 2.8'e bakınız. #2078 ham imzalama için bir `sign` uzantısı eklemektedir; dijital cüzdan, belge imzalama ile AI ajanları içindir. #2437 algoritma göçünü desteklemektedir ve post kuantum geçişi için kritiktir. #2393 ML-DSA test vektörleri eklemektedir. #2377 kimlik bilgisi yöneticisi güven grubu anahtarı uzantısını eklemektedir. #2150 kendinden attestation'lı platform kimlik doğrulayıcılarını dışlamaktadır. #2095 alternatif hata kodları getirmektedir. #2072 WebDriver BiDi desteği eklemektedir. #2404 sanal kimlik doğrulayıcılar için CTAP 2.3 sürüm dizesi eklemektedir.

Charter'ın kapsama eklediği yeni başlıklar uzak masaüstü ile kalıcı olmayan arayüz, kimlik bilgisi yedekleme ile kurtarma seçenekleri, taşıma ile dayanıklılık sinyalleri, AI ajanları dahil WebAuthn aracılı ham imzalama, kimlik doğrulayıcı hakkında gizlilik korumalı güven sinyalleri ile gizlilik için genişletilmiş WebAuthn uzantılarıdır.

IdP ekibi için çıkarım şudur: Level 3 hedeflenir ve Level 4 izlenir. Level 4'teki dayanıklılık ile güven sinyalleri doğrudan cihaza bağlı ile senkronize passkey politikasını etkileyecektir.

### 2. Level 3 özellikleri ve sunucu tarafı etkileri

#### 2.1 PRF uzantısı, yani hmac-secret

**Ne yapar.** Kimlik doğrulayıcı içinde kimlik bilgisine bağlı bir gizli anahtardan, ilgili tarafın verdiği tuzla deterministik 32 baytlık bir çıktı türetir. Uçtan uca şifreleme anahtarı için kullanılır.

**CTAP eşlemesi.** Tarayıcıdaki `prf`, CTAP2'deki `hmac-secret` uzantısıdır.

**Kritik tuz türetmesi**, ki bunu tarayıcı yapar, siz değil:

```
actualSalt = SHA-256( UTF8("WebAuthn PRF") || 0x00 || developerSalt )
```

Bu, web bağlamında türetilen sırların yerel ile CTAP bağlamından kriptografik olarak izole olmasını sağlar. Yerel uygulama SDK'ları, yani YubiKit ile libfido2, bu öneki uygulamaz; yerel ile web aynı sırrı istiyorsa alan ayrımını kendiniz yapmanız gerekir.

API şekilleri şunlardır:

```js
// Kayıt (create) — sadece yetenek sorgusu / etkinleştirme
extensions: { prf: {} }
// çıktı: getClientExtensionResults().prf.enabled === true

// Kayıtta doğrudan sonuç almak (CTAP 2.2 hmac-secret-mc gerekir)
extensions: { prf: { eval: { first: salt } } }

// Doğrulama (get) — tek salt
extensions: { prf: { eval: { first: salt1, second: salt2 } } }

// Doğrulama — credential başına farklı salt
extensions: { prf: { evalByCredential: {
    "<base64url-credentialId>": { first: saltA },
    "<base64url-credentialId2>": { first: saltB }
} } }
```

`evalByCredential`, W3C spesifikasyonunda kimlik bilgisi kimliğinin base64url dizesiyle anahtarlanır, ham baytlarla değil. Rust tarafında serileştirirken buna dikkat edilmelidir.

**Sunucu ne saklamalı ve ne saklamamalıdır.** Saklanacaklar: kimlik bilgisi kimliğiyle birlikte kimlik bilgisi başına rastgele bir tuz, ki kayıt sırasında üretilir ve gizli değildir ancak benzersiz olmalıdır; ayrıca `prf.enabled` bayrağı, yani bu kimlik bilgisinin PRF destekleyip desteklemediği, ki arayüzde bu cihazla şifreli veriye erişilebileceğini söylemek içindir. Asla saklanmayacak şey PRF çıktısının kendisidir; türetilmiş anahtar tarayıcıda kalır ve sunucu yalnızca şifreli metni görür.

Anahtar rotasyonu için `first` ile `second` ikilisi kullanılır: eski tuz `first`, yeni tuz `second` olur ve tek işlemde iki sır alınarak geçiş yapılabilir. Pratik desen `HKDF(prf.results.first, info="enc")` ile bir AES-GCM anahtarı ve `HKDF(prf.results.second, info="mac")` ile bir HMAC anahtarı türetmektir; ayrık bilgi dizeleriyle.

Platform destek uyarıları Yubico rehberindendir ve yaklaşık 2025 ortası verisidir; 2026 için kısmen doğrulanmıştır.

| Platform | Platform passkey'i | Harici anahtar, yani YubiKey |
|---|---|---|
| Windows 11 | Hayır; Windows Hello hmac-secret desteklememektedir | Evet; Chrome, Edge ile Firefox'ta |
| macOS 15 ve üstü | Evet; iCloud Anahtar Zinciri, Safari 18 ve üstü | Chrome'da evet, Safari'de hayır |
| iOS ile iPadOS 18 ve üstü | Evet; iCloud Anahtar Zinciri | Hayır; iOS harici kimlik doğrulayıcıya uzantı verisi geçirmemektedir |
| Android | Evet; Google Parola Yöneticisi | USB'de evet, NFC'de hayır |

En önemli sonuç şudur: PRF tabanlı uçtan uca şifreleme tek kimlik doğrulama yöntemi yapılmamalıdır. Windows Hello platform passkey'leri ile iOS ve YubiKey kombinasyonu çalışmamaktadır. Mutlaka bir yedek yol, yani parola tabanlı anahtar türetme veya kurtarma kodu, tasarlanmalıdır.

Kaynakları developers.yubico.com'un PRF uzantısı geliştirici rehberi ile CTAP2 hmac-secret derin incelemesi, github.com/w3c/webauthn wiki'sindeki PRF açıklayıcısı ve bitwarden.com'un PRF yazısıdır.

#### 2.2 largeBlob durumu

Level 3 önerisinde hâlâ mevcuttur; §10.1.5'te büyük ikili veri depolama uzantısı olarak tanımlıdır.

w3c/webauthn issue taramasında kullanımdan kaldırma, riskli işaretleme veya kaldırma tartışması bulunamamıştır; yani spesifikasyon seviyesinde sağlıklıdır.

Bilinen kısıt issue #1622'de netleştirilmiştir: CTAP kimlik doğrulayıcılarında keşfedilebilir kimlik bilgisi zorunludur.

Pratik gerçek şudur: destek dardır ve PRF çoğu kullanım senaryosunda yerini almıştır. 2026 için güncel tarayıcı ile platform destek matrisi bulunamamıştır; passkeys.dev destek matrisi largeBlob'u listelememektedir.

IdP tavsiyesi largeBlob'a bağımlılık kurmamaktır. Küçük sırlar için PRF ile sunucuda şifreli metin saklama modeli çok daha taşınabilirdir.

#### 2.3 İlişkili köken istekleri

Dosya adresi `https://<RP ID>/.well-known/webauthn`'dur.

```json
{
  "origins": [
    "https://example.co.uk",
    "https://example.de",
    "https://myshoppingrewards.com"
  ]
}
```

Sunucu tarafı gereksinimleri kesindir: HTTPS üzerinden servis edilmelidir; `Content-Type: application/json` zorunludur; HTTP 200 dönmelidir; tarayıcı bu dosyayı kimlik bilgisi olmadan ve Referer başlığı olmadan çeker, yani kimlik doğrulamanın arkasına konmamalıdır ve içerik dağıtım ağında önbelleklenebilir olmalıdır; ilgili taraf kimliğinin kendisiyle eşleşen kökenleri listelemeye gerek yoktur.

Etiket limiti beştir. Etiket, etkin en üst düzey alan adı artı birin soldaki etiketidir; örneğin `shopping.com` ile `shopping.co.uk` ikisi de shopping etiketine sahiptir ve tek sayılır. Spesifikasyon istemcilerin en az beş desteklemesini şart koşmaktadır; beşten fazlasını destekleyen bilinen bir istemci yoktur ve beş tavan kabul edilmelidir.

Tarayıcı desteği passkeys.dev cihaz destek matrisine göre, son güncellemesi 20 Mayıs 2026, şöyledir: Chrome 128 ve üstü ile Edge 128 ve üstü çoğu platformda, Firefox 152 ve üstü. Safari için matris macOS Safari 15 ve üstü demektedir; bu büyük olasılıkla hatalı veya bozuk bir satırdır, çünkü Safari 15 WebAuthn Level 3 öncesidir. Safari'nin ilişkili köken desteği kesinleştirilememiştir.

Çalışma zamanı tespiti `PublicKeyCredential.getClientCapabilities()` çağrısının `relatedOrigins` alanıyla yapılır.

Mimari uyarı şudur: passkeys.dev açıkça ilişkili köken isteklerinin federasyon mümkün değilken kullanılması gerektiğini söylemektedir. Siz zaten bir kimlik sağlayıcı yazmaktasınız, yani OIDC ile SAML federasyonu zaten elinizdedir. İlişkili köken isteklerini yalnızca IdP'nin kendi çok markalı veya çok ülkeli alan adları için düşünün, müşteri ilgili tarafları için değil. Ayrıca desteklemeyen istemciler için önce tanımlayıcı akışı ile arka uçta arama yedeği şarttır.

Kaynakları passkeys.dev'in ilişkili kökenler sayfası, github.com/w3c/webauthn'daki açıklayıcı, ki artık bakımda değildir ve passkeys.dev'e yönlendirmektedir, ile w3.org/TR/webauthn-3'ün ilgili bölümüdür.

#### 2.4 Signal API

`PublicKeyCredential` üzerinde üç statik metot vardır.

| Metot | Ne zaman çağrılır | Sunucu tarafı sorumluluğu |
|---|---|---|
| `signalUnknownCredential()` | Bilinmeyen bir kimlik bilgisi kimliğiyle başarısız bir giriş denemesinden sonra; kullanıcı kimliği doğrulanmamışken de çağrılabilir | Sunucu bu kimlik bilgisinin kendisinde olmadığı cevabını dönmeli, ön yüz bu sinyali göndermelidir. Sağlayıcı yetim passkey'i siler |
| `signalAllAcceptedCredentials()` | Yalnızca kimliği doğrulanmış kullanıcı için; her başarılı girişte ve kimlik bilgisi yönetimi değişikliğinden sonra | Sunucu kullanıcının tüm geçerli kimlik bilgisi kimliklerini ve kullanıcı tutamağını döndürmelidir |
| `signalCurrentUserDetails()` | Kullanıcı adı ya da görünen ad güncellendiğinde ve her girişte | Sunucu güncel `name` ile `displayName` değerlerini döndürmelidir |

> **Kritik tehlike.** `signalAllAcceptedCredentials()` çağrısında listede eksik bırakılan her geçerli kimlik bilgisi sağlayıcı tarafından gizlenir. Boş bir liste gönderilirse kullanıcının tüm passkey'leri gizlenir. Sayfalama uygulanmış bir kimlik bilgisi listesi endpoint'i asla doğrudan bu API'ye bağlanmamalıdır; tam liste dönülmelidir. Bazı sağlayıcılar sonraki çağrıyla geri getirebilir ancak bu garanti değildir.

Tarayıcı desteği şöyledir: Chrome ile Edge masaüstünde 132 ve üstü, Ocak 2025; Chrome Android'de 144, 5 Aralık 2025; Safari Temmuz 2026 itibarıyla sevk etmemiştir, Safari 26 hedef olarak gösterilmişti; Firefox sevk etmemiştir ve resmî bir tutumu yoktur.

Sağlayıcı davranışında Google Parola Yöneticisi sinyalleri aktif olarak işlemektedir. Chrome eklenti tabanlı sağlayıcılar kendi kararlarını vermektedir.

Kaynakları developer.chrome.com'un Signal API dokümanı, MDN'in ilgili sayfası ile w3.org/TR/webauthn-3'ün sinyal metotları bölümüdür.

Sunucu tarafı iş listesi şudur. Birincisi kimliği doğrulanmış kullanıcı için `{ rpId, userId, allAcceptedCredentialIds: [...] }` döndüren, sayfalama içermeyen bir endpoint yazmaktır. İkincisi başarısız doğrulamada kimlik bilgisi kimliğini ön yüze geri verip `signalUnknownCredential` çağrısının tetiklenmesini sağlamaktır. Üçüncüsü profil güncelleme akışına `signalCurrentUserDetails` kancası eklemektir.

#### 2.5 Koşullu aracılık ile koşullu oluşturma

**Koşullu alma, yani otomatik doldurma arayüzü**, `mediation: 'conditional'` ile `autocomplete="username webauthn"` kullanır. Desteği şöyledir: Android'de Chrome 108 ve üstü, Edge 122 ve üstü ile Firefox; iOS ile iPadOS'ta Safari 16.1 ve üstü, Chrome 108 ve üstü, Firefox 122 ve üstü ile Edge 122 ve üstü; macOS'ta Safari 16.1 ve üstü, Chrome 108 ve üstü, Firefox 122 ve üstü ile Edge 122 ve üstü; Windows'ta Chrome 108 ve üstü, Edge 122 ve üstü ile Firefox 122 ve üstü.

**Koşullu oluşturma**, yani otomatik passkey yükseltmesi, parolayla girişten sonra sessizce bir passkey oluşturur. Desteği şöyledir: macOS'ta Safari 18 ve üstü ile Chrome 136 ve üstü; Windows'ta Chrome 136 ve üstü; iOS ile iPadOS'ta iOS 18 ve üstü, yani Safari, diğer tarayıcılar ile Apple Passwords; Android'de Chrome 142 ve üstü, Google Parola Yöneticisiyle. Firefox desteklememektedir ve üçüncü taraf parola yöneticisi kapsamı düzensizdir.

Sunucu tarafı etkileri önemlidir. Chrome, parola doldurulmasından sonra beş dakikalık katı bir pencere uygulamakta ve nihai kararı Google Parola Yöneticisi vermektedir; Apple'da karar mercii Authentication Services'tır ve yayımlanmış kesin bir pencere yoktur. Kimlik bilgisi arayüz gösterilmeden oluşmakta ve kullanıcı bunu bilmemektedir; kullanıcıya sonradan hesabına bir passkey eklendiği bildirimi gönderilmeli ve kimlik bilgisi yönetim ekranında görünür yapılmalıdır. `excludeCredentials` listesi doğru doldurulmalıdır, yoksa aynı sağlayıcıda mükerrer passkey birikir. `credProps.rk` çıktısı kontrol edilmelidir; keşfedilebilir olmayan bir kimlik bilgisi oluşmuşsa passkey kullanıcı deneyimi çalışmaz. Bu akışta attestation istenmemelidir, çünkü sessiz akışı bozar.

Kaynakları developer.chrome.com'un koşullu oluşturma dokümanı, passkeys.dev cihaz destek sayfası ile chromestatus.com'daki ilgili özellik kaydıdır.

#### 2.6 Cihazlar arası kimlik doğrulama, hibrit taşıma

Hibrit taşıma, yani QR kodu ile Bluetooth yakınlığı, artık CTAP spesifikasyonunun normal bir parçasıdır; gezici güvenlik anahtarları değil, platform kimlik doğrulayıcıları ile istemciler tarafından uygulanmaktadır. Platform desteği Android 9 ve üstü, iOS 16 ve üstü ile macOS 13 ve üstüdür.

CTAP 2.3, yani Şubat 2026, hibrit için birden fazla veri aktarım kanalı eklemiştir: mevcut WebSocket'e ek olarak düşük enerjili Bluetooth veri kanalı gelmiştir. Bu, internet bağlantısının zayıf olduğu senaryolarda güvenilirliği artırır.

İlgili taraf tarafında etkisi neredeyse yoktur. Yalnızca `transports` alanında `"hybrid"` değerini tanıyıp saklamak yeterlidir; `AuthenticatorTransport` enum'unuzda bilinmeyen değerleri hata vermeden kabul etmelisiniz, çünkü bu ileride yeni taşımalar eklendiğinde kırılmamak için kritiktir.

#### 2.7 credProps, credProtect, minPinLength ile devicePubKey

| Uzantı | Durum | İlgili taraf tarafı |
|---|---|---|
| credProps | Level 3'te tanımlıdır ve yaygın desteklenmektedir. Issue #1988 ile doğrulama sırasında da kullanımına izin verilmiştir, 29 Kasım 2023 | `rk` değeri saklanır; kimlik bilgisinin gerçekten keşfedilebilir olup olmadığını bilmenin tek yoludur. Keşfedilebilir değilse kullanıcı adsız akışa sokulmaz |
| credProtect | CTAP 2.1 uzantısıdır ve WebAuthn uzantı kaydında kayıtlıdır; çekirdek spesifikasyonun içindekiler listesinde yoktur ve bu normaldir | Üçüncü seviye, yani kullanıcı doğrulaması zorunlu, istenebilir; ancak zorlanırsa desteklemeyen kimlik doğrulayıcılar reddeder. Genelde ikinci seviye, yani kimlik bilgisi listesiyle opsiyonel kullanıcı doğrulaması, makuldür |
| minPinLength | CTAP 2.1 uzantısıdır ve kayıtlıdır | Yalnızca attestation ile anlamlıdır ve kurumsal senaryolar içindir. Tüketici IdP'sinde gereksizdir |
| devicePubKey, yani cihaza bağlı anahtar | Level 3'ten çıkarılmıştır ve bu üç yönlü doğrulanmıştır: 25 Ağustos 2026 tarihli Level 3 önerisinde `devicePubKey` ile cihaza bağlı ifadesi geçmemektedir; 3 Eylül 2026 tarihli editör taslağının tanımlı uzantı listesi `appid`, `appidExclude`, `credProps`, `prf`, `largeBlob` ile `remoteClientDataJSON`'dan ibarettir; ilgili tüm issue'lar, yani #1691, #1658, #1846, #1817, #1922 ile #1739, kapalıdır | Üzerine mimari kurulmaz. Cihaza bağlılık garantisi isteniyorsa ayrı bir cihaza bağlı kimlik bilgisi, yani bir güvenlik anahtarı veya attestation'lı platform kimlik doğrulayıcısı, kaydettirilir |

#### 2.8 Anlık aracılık, yani varsa al

Önemli bir API değişikliği vardır: `mediation: 'immediate'` artık çalışmamaktadır. Spesifikasyon 5 Kasım 2025'te güncellenmiştir ve doğru alan artık `uiMode: 'immediate'`'tır.

```js
const cred = await navigator.credentials.get({
  publicKey: { challenge, rpId, allowCredentials: [] },  // allowlist BOŞ olmalı
  uiMode: 'immediate'
});
```

Davranışı şöyledir: yerelde kimlik bilgisi varsa anında sunar, yoksa hiç arayüz göstermeden `NotAllowedError` istisnasıyla reddeder. Öncesinde bir kullanıcı jesti zorunludur. Tarayıcı ardışık çağrıları hız sınırlamasına tabi tutar. Gizli modda her zaman `NotAllowedError` fırlatır. İzleme önlemi olarak `allowCredentials` dolu istekler reddedilir. `signal` parametresi, yani iptal denetleyicisi, kullanılamaz.

Tespiti `getClientCapabilities()` çağrısının `immediateGet` alanıyla yapılır.

Durumu şudur: Chrome 149'da genel kullanıma açılmıştır ve Mayıs 2026 itibarıyla anlık arayüz modunu destekleyen tek tarayıcı Chrome'dur. Safari ile Firefox değerlendirmektedir ancak kamuya açık bir taahhütleri yoktur.

Spesifikasyon seviyesinde bu özellik Credential Management API'sini genişletmektedir ve w3c/webauthn'da Level 4 kilometre taşındadır, issue #2291. Yani Level 3 önerisinin parçası değildir.

Gizlilik notu bir IdP olarak sizi ilgilendirir: bu API siteye bu kullanıcıda kimlik bilgisi olup olmadığını zamanlama farkıyla sızdırır. Yukarıdaki kısıtlar bu yüzden vardır. Kullanımınızı tek bir giriş düğmesine bağlayın ve sayfa yüklenmesinde otomatik tetiklemeyin.

Kaynakları github.com/w3c/webauthn'daki anlık aracılık açıklayıcısı ile developer.chrome.com'un iki yazısıdır.

### 3. CTAP durumu

| Spesifikasyon | Sürüm | Durum | Tarih |
|---|---|---|---|
| CTAP | 2.1 | Önerilen standart | 15 Haziran 2021 |
| CTAP | 2.2 | Önerilen standart | 14 Temmuz 2025 |
| CTAP | 2.3 | Önerilen standart | 26 Şubat 2026 |
| CTAP | 2.3.1 | Çalışma taslağı | 29 Mayıs 2026 |
| FIDO Server Requirements | 2.3 | İnceleme taslağı | 26 Şubat 2026 |

Kaynakları fidoalliance.org'daki CTAP 2.3 önerilen standart sayfası, sunucu gereksinimleri inceleme taslağı ile spesifikasyon dizinidir.

**CTAP 2.2 ne getirmiştir.** `hmac-secret-mc`, hmac-secret'ı `authenticatorMakeCredential` sırasında da çalıştırır, yani kayıt anında PRF çıktısı alınabilir ve ikinci bir doğrulama turu gerekmez; uçtan uca şifrelemeli katılım akışı için büyük bir kullanıcı deneyimi kazancıdır. Kalıcı PIN ile kullanıcı doğrulama yetkilendirme token'ları güç döngüsüne dayanır ve yalnızca okuma amaçlı, dar kapsamlı token'lardır; ilgili taraf etkisi yoktur, yerel kimlik bilgisi yönetim araçlarını ilgilendirir. PIN karmaşıklık politikası `getInfo` içinde `pinComplexityPolicy` ile `pinComplexityPolicyURL` olarak gelir; ilgili taraf etkisi yoktur. Üçüncü taraf ödeme uzantısı, işlem başlatanın ilgili taraftan farklı olduğu senaryolar içindir, yani PSD2 güçlü müşteri kimlik doğrulaması ile güvenli ödeme onayı; ödeme akışı olan IdP'ler için ilgilidir. Hibrit taşıma normatifleşmiştir. `getInfo` zenginleşmiştir: `attestationFormats` ile ilgili taraf tercih ettiği formatı seçebilir, ayrıca `maxPINLength` ile `uvCountSinceLastPinEntry` gelmiştir. CTAP üzerinden JSON, dijital kimlik bilgisi API'si isteklerini hibrit taşıma üzerinden JSON olarak taşır ve geleneksel ilgili taraf sunucularını etkilemez.

**CTAP 2.3 ne getirmiştir, 26 Şubat 2026.** Kırıcı bir değişiklik yoktur; CTAP 2.2 uyumlu her implementasyon otomatik olarak 2.3 uyumludur. FIDO, 2.2 için ayrı bir sertifikasyon kategorisi açmamıştır ve 2.3 artık tüm FIDO2 sertifikasyonlarının temelidir. Hibrit için çoklu veri aktarım kanalı, yani düşük enerjili Bluetooth, eklenmiştir. Sıfırlama için uzun dokunuş gelmiştir. `authenticatorGetInfo` sürüm listesine `FIDO_2_3` eklenmiştir. NFC, yani ISO 7816 ile ISO 14443, kullanıcı etkileşim gereksinimleri netleştirilmiştir. `setMinPINLength` ile `pinComplexityPolicy` etkileşimleri geliştirilmiştir. `authenticatorReset` veya eşdeğer bir fabrika sıfırlaması zorunlu hâle gelmiştir. Akıllı kart arayüzü desteklenen FIDO arayüzleri listesine eklenmiştir.

**FIDO Server Requirements v2.3 sizi doğrudan ilgilendirir.** Post kuantum ML-DSA algoritmaları önerilen listeye eklenmiştir: ML-DSA-44, ML-DSA-65 ile ML-DSA-87. Tam belirtilmiş algoritmalar da eklenmiştir: ESP256, ESP384, ESP512 ile Ed25519.

Rust IdP için aksiyon şudur: COSE algoritma tablosu genişletilmeye hazırlanır. `pubKeyCredParams` listesine ESP256 ile Ed25519 eklemek ve doğrulama tarafında ML-DSA'ya yer bırakmak planlanır. Level 4'teki #2437 numaralı algoritma göçü issue'su mevcut kimlik bilgilerinin algoritma geçişini konuşmaktadır; bu, veri modelinde algoritma alanının ve rotasyon yolunun şimdiden düşünülmesini gerektirir.

### 4. Credential Exchange Format ile Protocol

Dizini fidoalliance.org/specs/cx'tir.

**CXF, yani değişim formatı.**

| Sürüm | Durum | Tarih |
|---|---|---|
| 1.0 | Çalışma taslağı | 22 Mayıs 2024 |
| 1.0 | Çalışma taslağı | 3 Ekim 2024 |
| 1.0 | İnceleme taslağı | 13 Mart 2025 |
| 1.0 | Önerilen standart | 14 Ağustos 2025 |
| 1.0 | Önerilen standart artı errata | Errata 9 Mart 2026, yayın 22 Nisan 2026 |

Kapsamı 17 kimlik bilgisi tipidir: adresler, API anahtarları, temel kimlik doğrulama, kredi kartları, özel alanlar, ehliyet, dosyalar, üretilmiş parolalar, kimlik belgeleri, öğe referansları, notlar, passkey'ler, pasaportlar, kişi adları, SSH anahtarları, tek kullanımlık zaman tabanlı parolalar ile Wi-Fi parolaları.

Passkey veri modelinin zorunlu alanları `credentialId`, `rpId`, `username`, `userDisplayName`, `userHandle` ile `key`'dir; opsiyonel olarak `fido2Extensions` bulunur ve hmac kimlik bilgileri, kimlik bilgisi ikili verileri ile büyük ikili verileri içerir.

İlgili taraf tarafını ilgilendiren iki kritik nokta vardır.

Birincisi özel anahtarın gerçekten dışa aktarılmasıdır. `key` alanı PKCS#8 ASN.1 DER biçimindedir ve base64url kodludur. Yani passkey taşınabilirliği anahtarın kendisinin taşınması demektir; kimlik bilgisi kimliği ile açık anahtar değişmez, dolayısıyla sizin veritabanınızda hiçbir şey değişmez ve taşımayı göremezsiniz.

İkincisi imza sayacı kuralıdır: sıfırdan farklı imza sayacına sahip passkey'ler dışa aktarımdan hariç tutulmalı ve içe aktaran taraf sayaçları sıfırlamalıdır. Sunucunuzda katı imza sayacı kontrolü yapıyorsanız, taşınmış bir kimlik bilgisi sayacı sıfırlanmış olarak geri gelir ve kullanıcıyı kilitlersiniz.

Aksiyon şudur: senkronize veya yedeklemeye uygun kimlik bilgileri için, yani BE değeri bir olanlar için, imza sayacı kontrolü devre dışı bırakılır veya yalnızca loglanır. Sıkı sayaç kontrolü yalnızca BE değeri sıfır olan, yani cihaza bağlı kimlik bilgilerine uygulanır. Bu zaten önceki en iyi uygulamaydı; CXF bunu zorunlu hâle getirmektedir.

AAGUID etkisi şudur: CXF veri modelinde AAGUID passkey'in zorunlu alanları arasında listelenmemektedir. Dolayısıyla bir passkey 1Password'den Bitwarden'a taşındığında kayıt anında sakladığınız AAGUID artık gerçeği yansıtmaz. AAGUID kaydolduğu andaki sağlayıcı olarak yorumlanmalı, şu anki sağlayıcı olarak yorumlanmamalıdır. Arayüzde gösteriliyorsa bir ipucu olarak sunulmalı, kesin bilgi olarak sunulmamalıdır.

**CXP, yani değişim protokolü.**

| Sürüm | Durum | Tarih |
|---|---|---|
| 1.0 | Çalışma taslağı | 22 Mayıs 2024 |
| 1.0 | Çalışma taslağı | 3 Ekim 2024, en yenisidir |

CXP hâlâ yalnızca bir çalışma taslağıdır. Dizinde hiçbir inceleme taslağı veya önerilen standart sürümü yoktur. Belgenin kendi ifadesi şudur: "This is a Working Draft Specification and is not intended to be a basis for any implementations as the Specification may change."

Bu dikkat çekici bir ayrışmadır: CXF, yani format, önerilen standarda ulaşıp errata alırken CXP, yani aktarım protokolü, iki yıldır çalışma taslağında takılıdır. Yani ekosistem formatta anlaşmıştır ancak sağlayıcılar arası canlı ve doğrudan aktarım protokolü henüz standartlaşmamıştır. Pratikte taşımalar dosya tabanlı, yani şifrelenmiş bir CXF arşiviyle yapılmaktadır.

CXP'nin çalışma taslağındaki teknik özeti şöyledir. Beş adımı vardır: içe aktaran taraf bir dışa aktarma isteği ile şifreleme parametreleri oluşturur; dışa aktaran taraf yetkilendirme sonrası göç anahtarını belirler; veri şifrelenir; dışa aktarma yanıtı iletilir; içe aktaran taraf çözer ve saklar. HPKE, yani RFC 9180, kullanılmaktadır ve anahtar kapsülleme, anahtar türetme ile kimlik doğrulamalı şifreleme taraflar arasında müzakere edilmekte, bir varsayılan dayatılmamaktadır; modları temel, ön paylaşımlı anahtarlı, kimlik doğrulamalı ile ikisinin birleşimidir. Kimlik bilgileri DEFLATE ile sıkıştırılıp bir JWE dosyası olarak şifrelenmektedir. Rolleri dışa aktaran, içe aktaran, kimlik bilgisi sahibi ile opsiyonel yetkilendiren taraftır.

**Hangi platformlar ile parola yöneticileri sevk etmiştir.** Bu soru güvenilir şekilde cevaplanamamıştır. Web arama kotası dolduğu için satıcı duyuruları taranamamıştır. 1Password blogunun son yazıları, yani Temmuz ile Eylül 2026 arası, tarandığında kimlik bilgisi değişimi veya passkey taşınabilirliğiyle ilgili hiçbir yazı bulunamamıştır. Apple, Google, Bitwarden ile Dashlane için sürüm veya tarih doğrulaması yapılamamıştır.

Uydurma yapılmamaktadır: bu konuda ekibinize kesin bir sevk edildi bilgisi verilemez. Ancak yukarıdaki spesifikasyon durumu, yani CXP'nin çalışma taslağında takılı olması, ekosistem genelinde tam otomatik sağlayıcıdan sağlayıcıya taşımanın Eylül 2026'da henüz olgunlaşmadığına işaret etmektedir.

### 5. Cihaza bağlı ile senkronize passkey: BE ile BS bayrakları

**Bayraklar.** `authenticatorData` bayrak baytında BE, yani yedekleme uygunluğu, üçüncü bittir ve kimlik bilgisinin yedeklenebilir veya senkronize edilebilir olup olmadığını söyler; kimlik bilgisinin ömrü boyunca değişmez. BS, yani yedekleme durumu, dördüncü bittir ve kimlik bilgisinin şu anda yedeklenmiş veya senkronize durumda olup olmadığını söyler; zamanla değişir.

Geçerli kombinasyonlar BE sıfır ile BS sıfır, yani cihaza bağlı; BE bir ile BS sıfır, yani senkronize edilebilir ancak henüz değil; ve BE bir ile BS bir, yani senkronize durumdur. BE sıfır ile BS bir geçersizdir ve reddedilmelidir.

**Sunucunun yapması gerekenler.**

1. Kayıtta BE saklanır ve bir daha değiştirilmez. Sonraki doğrulamalarda gelen BE saklanandan farklıysa bu bir protokol ihlalidir; loglanır ve reddedilir.
2. BS her doğrulamada güncellenir. BS'nin sıfırdan bire geçmesi kullanıcının yedeklemeyi etkinleştirdiği anlamına gelir; birden sıfıra geçmesi yedeklemenin devre dışı bırakıldığı ve kurtarma riski oluştuğu anlamına gelir ve kullanıcıya uyarı göstermek için iyi bir tetikleyicidir.
3. İmza sayacı politikası BE'ye bağlanır: BE sıfırsa sayaç monoton artmalıdır ve ihlal bir klonlama şüphesidir, reddedilir; BE birse sayaç genellikle hep sıfır gelir ve kontrol edilmez, çünkü CXF taşımaları da sayacı sıfırlamaktadır.
4. Hesap kurtarma politikası şöyledir: BE bir ile BS bir olan bir passkey tek başına önyükleme için yeterli sayılabilir, ki passkeys.dev'in senkronize passkey tanımı tam olarak budur, yani başka bir giriş meydan okuması gerektirmeden oturum açmayı önyükleyebilen kimlik bilgisi. BE sıfır olan bir passkey tek kimlik doğrulama faktörünüz olmamalıdır, çünkü cihaz kaybı hesap kaybı demektir. Kullanıcı yalnızca cihaza bağlı kimlik bilgisi kaydettiyse ikinci bir kimlik bilgisi veya kurtarma kodu istenmelidir.
5. Kurumsal veya yüksek güvenlik politikası: cihazdan çıkmama garantisi isteniyorsa BE sıfır şartı konabilir; ancak bu, tüm modern platform passkey'lerini, yani iCloud Anahtar Zinciri ile Google Parola Yöneticisi'ni dışlar ve pratikte kullanıcıları güvenlik anahtarlarına zorlar. Bu bilinçli yapılmalıdır.

**AAGUID kullanımı.** AAGUID yalnızca attestation `none` dışında anlamlı bir değer taşır. `attestation: "none"` istendiğinde tarayıcılar AAGUID'i sıfırlar, yani 16 bayt sıfır yapar; bu gizlilik amaçlıdır ve kasıtlıdır. Sağlayıcı adı gösterilmek isteniyorsa `attestation: "direct"` veya `"indirect"` istenmesi gerekir. Apple ile Google'ın 2026'da hangi iletim ayarında sıfır olmayan AAGUID döndürdüğü kesin olarak doğrulanamamıştır. AAGUID bir arayüz ipucu olarak kullanılmalıdır, örneğin 1Password'de kayıtlı demek için, bir güvenlik kararı olarak değil; yukarıda anlatıldığı gibi CXF taşımaları AAGUID'i eskitmektedir.

Topluluk listesi github.com/passkeydeveloper/passkey-authenticator-aaguids adresindedir. Topluluk tarafından yürütülmekte ve sağlayıcılar GitHub profil doğrulaması şartıyla PR ile eklenmektedir. JSON şeması şöyledir: AAGUID'ler küçük harfli üst düzey anahtarlardır, `name` zorunludur, `icon_dark` ile `icon_light` opsiyoneldir ve base64 SVG veri URI'si taşır. Deponun kendisi uyarmaktadır: başka hiçbir amaç için kullanılmak üzere tasarlanmamıştır ve emekliye ayrılabilir; o durumda JSON dosyaları boş bir nesneye indirgenecektir. Depo, otoriter güvenlik bilgisi için FIDO metadata servisini önermekte ve bu listedeki bazı AAGUID'lerin orada bulunmayabileceğini söylemektedir. Listedeki sağlayıcı sayısı ile son güncelleme tarihi tespit edilememiştir.

Pratik gerçek şudur: senkronize passkey sağlayıcıları, yani Apple iCloud Anahtar Zinciri, Google Parola Yöneticisi, 1Password, Bitwarden, Dashlane ile Windows Hello, genel olarak metadata servisine metadata yayımlamamaktadır; bu yüzden topluluk listesi vardır. 2026 için sağlayıcı bazında metadata servisindeki varlık tek tek doğrulanamamıştır.

**FIDO metadata servisi durumu.** Dizini fidoalliance.org/specs/mds'tir.

| Belge | Sürüm | Durum | Tarih |
|---|---|---|---|
| FIDO Metadata Service | 3.0 | Önerilen standart | 18 Mayıs 2021 |
| FIDO Metadata Service | 3.1 | Önerilen standart | 21 Mayıs 2025 |
| FIDO Metadata Service | 3.1.1 | Önerilen standart | 5 Ocak 2026, yayın 12 Mayıs 2026 |
| FIDO Metadata Statement | 3.0 | Önerilen standart | 18 Mayıs 2021 |
| FIDO Metadata Statement | 3.1 | Önerilen standart | 21 Mayıs 2025 |
| FIDO Metadata Statement | 3.1.1 | Önerilen standart | 5 Ocak 2026, yayın 12 Mayıs 2026 |
| Convenience Metadata Service | 1.0 | Önerilen standart | 21 Mayıs 2025 |

Metadata servisinin dördüncü sürümü yoktur; üçüncü hat devam etmekte ve güncel nokta sürümü 3.1.1'dir. Ayrıca 2025'te eklenen birinci sürüm kolaylık metadata servisi ilginçtir; muhtemelen metadata servisi veri bloğunu tüketmeyi kolaylaştıran bir katmandır. İçeriği incelenmemiştir ve ekibin bakması önerilir.

Metadata servisi veri bloğu endpoint adresi ile imza doğrulama zinciri detayları, yani JWT, `x5c` ile kök sertifika, bu oturumda doğrulanamamıştır. Adresin `https://mds3.fidoalliance.org/` civarında olduğu bilinmekte ancak teyit edilmemiştir; spesifikasyondan okunmalıdır.

### 6. Attestation gerçekliği

**Level 3'ün getirdikleri**, değişiklik günlüğüne göre: Apple anonim attestation'ı ile bileşik attestation formatları eklenmiştir. Ayrıca CTAP 2.2 ile `getInfo.attestationFormats` sayesinde istemci tercih ettiği formatı müzakere edebilmektedir.

**Kurumsal attestation, CTAP 2.1 ve üstü.** Kimlik doğrulayıcı, önceden yapılandırılmış bir ilgili taraf kimliği listesine karşı seri numarası gibi benzersiz bir tanımlayıcı döndürebilir. İki tipi vardır: platform yönetimli, ki istemci ilgili taraf kimliği listesini tutar, ile satıcı kolaylaştırmalı, ki kimlik doğrulayıcı kendi listesini tutar. Yalnızca mobil cihaz yönetimiyle yönetilen kurumsal ortamlarda anlamlıdır.

**Ne zaman anlamlıdır.** Kurumsal veya düzenlenmiş bir ortamda, belirli sertifikalı kimlik doğrulayıcı modellerini, yani FIPS veya belirli bir güvence seviyesini, zorunlu kılmanız gerektiğinde ve cihaz envanteriyle eşleştirme yaptığınızda anlamlıdır. Metadata servisiyle birlikte kullanılır: AAGUID'den metadata beyanına, oradan sertifikasyon seviyesi ile bilinen güvenlik açıklarına, yani durum raporuna gidilir.

**Ne zaman anlamsız veya zararlıdır**, yani tüketici IdP'sinde. Senkronize passkey'lerde attestation zaten yoktur veya anonimdir ve hangi cihazda sorusuna cevap vermez, çünkü anahtar zaten senkronizedir. Attestation istemek Apple ile Google'da ek kullanıcı onay ekranları ve dönüşüm kaybı yaratır. Koşullu oluşturma, yani sessiz passkey yükseltmesi, akışını bozar. Bir izin listesi uygulanırsa kullanıcı tabanının bir kısmı kaydolamaz hâle gelir.

Tavsiye şudur: tüketici IdP'si için `attestation: "none"` kullanılır. Kurumsal kiracılar için kiracı bazlı bir politika bayrağıyla `"direct"`, metadata servisi doğrulaması ile AAGUID izin listesi kullanılır. İki akış kod düzeyinde ayrılır; webauthn-rs bunu zaten `Passkey` ile `AttestedPasskey` ayrımıyla modellemektedir, aşağıya bakınız.

Tarayıcıların 2026'da dolaylı iletimi pratikte nasıl ele aldığı, yani anonimleştirme sertifika otoritesi kullanıp kullanmadığı konusunda güncel bir kaynak doğrulanamamıştır.

### 7. Passkey benimseme istatistikleri, Eylül 2026

Bu bölüm zayıftır; dürüst olmak gerekirse 2026 tarihli birincil FIDO raporu bulunamamıştır.

Doğrulanabilenler şunlardır.

FIDO Alliance'ın passkeys sayfasındaki 2024 tarihli bağımsız ankete göre insanların %53'ü en az bir hesapta passkey etkinleştirmiş, %22'si etkinleştirebildiği her hesapta etkinleştirmiştir. Kaynağı "2024 Consumer Password & Passkey Trends"tir.

FIDO'nun aynı sayfada alıntıladığı kurumsal metrikler şunlardır: Yubico'da oltalama ile kimlik bilgisi hırsızlığına maruziyette %99,99 azalma; Amazon'da altı kat daha hızlı oturum açma süresi; Google'da parolalara kıyasla dört kat daha iyi oturum açma başarı oranı.

Chrome for Developers'ın 21 Mayıs 2026 tarihli yazısına göre Pixiv'de passkey sonrası giriş başarı oranı %99 olmuş ve parolalara göre %29 iyileşme sağlanmıştır; Adidas'ta sıfır istemli koşullu oluşturma stratejisiyle passkey oluşturmalarında %8 artış olmuştur.

FIDO Alliance ana sayfasındaki 2026 haberleri benimseme sayısı içermemektedir: 14 Ağustos 2026'da OpenAI ile Yubico ortaklığı duyurulmuştur ve OpenAI'nin gelişmiş hesap güvenliği programı kapsamında özel oltalamaya dirençli YubiKey'ler verilmektedir; 17 Temmuz 2026'da RSA Security ile FIDO Alliance ortak brifingi yapılmıştır; 27 Mayıs 2026'da Authenticate APAC 2026 duyurulmuştur, 2 ile 3 Haziran tarihlidir.

Kapatılamayan boşluklar şunlardır: 2025 veya 2026 tarihli çevrimiçi kimlik doğrulama barometresi ya da passkey durum raporu, çünkü fidoalliance.org'un araştırma sayfaları çekimde gezinme iskeletinden fazlasını vermemiştir; Google, Microsoft, Apple, Amazon ile PayPal'ın 2026 passkey kullanıcı sayıları; senkronize ile cihaza bağlı passkey oranı, ki hiçbir kamuya açık veri bulunamamıştır; cihazlar arası, yani hibrit ve QR kodu, kullanım oranları, ki veri bulunamamıştır.

Ekibiniz bu bölümü kendi tarafında fidoalliance.org'un araştırma sayfasını tarayarak tamamlamalıdır.

### 8. Rust ekosistemi: webauthn-rs

Deposu github.com/kanidm/webauthn-rs, paketi crates.io/crates/webauthn-rs'tir.

| Sürüm | Tarih | Not |
|---|---|---|
| 0.5.5 | 30 Nisan 2026 | En güncel kararlı sürümdür |
| 0.6.1-dev | 30 Nisan 2026 | Ön sürümdür |
| 0.6.0-dev | 20 Mart 2026 | Ön sürümdür |
| 0.5.4 | 10 Aralık 2025 | — |
| 0.5.3 | 23 Ekim 2025 | — |

Crate'in güncellenme tarihi 30 Nisan 2026'dır, yani aktif bakımdadır. Yakın dönem indirmesi yaklaşık 2,47 milyondur, yani ekosistemde baskın konumdadır. SUSE ürün güvenliği tarafından bir güvenlik denetiminden geçmiştir.

**Workspace yapısı.** `webauthn-rs` güvenli ve yüksek seviyeli API'dir ve önerilendir. `webauthn-rs-core` düşük seviyeli protokoldür. `webauthn-rs-proto` protokol tipleri ile bağlayıcılarıdır. `fido-mds` bir kimlik doğrulayıcı şeffaflık ayrıştırıcısıdır, yani FIDO metadata servisi ayrıştırması için hazır bir crate vardır ve kendiniz yazmamalısınız. `webauthn-authenticator-rs` ayrı bir depo ile crate'tir ve istemci tarafıdır.

**Özellik bayrakları**, `webauthn-rs/Cargo.toml` dosyasından:

```
default                                    = ["attestation"]
preview-features                           = ["conditional-ui"]
resident-key-support
conditional-ui
attestation
workaround-google-passkey-specific-issues
danger-allow-state-serialisation
danger-credential-internals
danger-user-presence-only-security-keys
```

**Level 3 özellik desteğinin gerçek durumu**, `webauthn-rs-proto/src/extensions.rs` kaynak kodundan doğrulanmıştır:

```rust
pub struct RequestRegistrationExtensions {
    pub cred_protect:        Option<CredProtect>,
    pub uvm:                 Option<bool>,
    pub cred_props:          Option<bool>,
    pub min_pin_length:      Option<bool>,
    pub hmac_create_secret:  Option<bool>,
}

pub struct RequestAuthenticationExtensions {
    pub appid:           Option<String>,
    pub uvm:             Option<bool>,
    pub hmac_get_secret: Option<HmacGetSecretInput>,
}
```

| Özellik | webauthn-rs desteği |
|---|---|
| credProps | Vardır, `cred_props` alanıyla |
| credProtect | Vardır, `cred_protect` alanıyla |
| minPinLength | Vardır, `min_pin_length` alanıyla |
| uvm | Vardır |
| appid, yani U2F geçişi | Vardır |
| hmac-secret, ham CTAP | Vardır, `hmac_create_secret` ile `hmac_get_secret` alanlarıyla |
| PRF uzantısı, WebAuthn seviyesinde | Yoktur |
| largeBlob | Yoktur |
| devicePubKey | Yoktur |
| Koşullu arayüz | Vardır ancak `preview-features` ile `conditional-ui` bayrakları arkasındadır |
| Koşullu oluşturma | Doğrulanamamıştır; açık bir API bulunamamıştır |
| Signal API | Yoktur ve olması da gerekmez; bu tamamen istemci tarafı bir API'dir ve sizin yalnızca bir yük endpoint'i yazmanız gerekir |
| İlişkili köken istekleri | Yoktur ve gerekmez; bu bir tarayıcı özelliğidir ve sizin yalnızca `.well-known/webauthn` servis etmeniz gerekir |
| BE ile BS bayrakları | Kısmen vardır; `allow_backup_eligible_upgrade` adlı bir iç yapılandırma bulunmaktadır, passkey akışında doğru ile güvenlik anahtarı ve attestation'lı passkey akışında yanlış değerindedir, ancak `backup_eligible` ile `backup_state` genel API'de ilgili tarafa açılmamaktadır |
| Attestation ile metadata servisi | Vardır; `attestation` varsayılan bir özelliktir, `AttestationCaList` bulunmaktadır ve ayrı bir `fido-mds` crate'i vardır |

**En kritik iki boşluk.**

Birincisi PRF'in olmamasıdır ve bu, uçtan uca şifreleme planı için doğrudan bir engeldir. Elde `hmac_get_secret` vardır ancak bu ham CTAP hmac-secret'tır; WebAuthn `prf` uzantısının `SHA-256("WebAuthn PRF" || 0x00 || salt)` alan ayrımını ile `evalByCredential` yapısını içermez. PRF isteniyorsa ya `webauthn-rs-proto` içindeki uzantı yapıları genişletilmeli, yani fork alınmalı veya yukarı akışa bir PR açılmalı, ya uzantı girdisi ile çıktısı kendi katmanınızda JSON seviyesinde ele alınmalıdır. `danger-credential-internals` özelliği `Credential` tipine dönüşüm trait'leriyle erişim vermektedir ve bir kaçış kapısı olarak kullanılabilir.

İkincisi BE ile BS'nin ilgili tarafa açılmamasıdır. Beşinci bölümdeki politikaları, yani sayaç kontrolünü BE'ye bağlamayı, BS geçişlerinde uyarmayı ile kurtarma politikasını, uygulamak için bu bayraklara erişim şarttır. Çözümü `danger-credential-internals` ile `Credential` iç yapısına inmek veya yukarı akışa bir erişimci PR'ı açmaktır. Bu, projede erken çözülmesi gereken bir mimari karardır.

**Alternatifler.** `passkey-rs`, yani github.com/1Password/passkey-rs, için sürüm ile durum doğrulanamamıştır; not olarak ağırlıklı olarak istemci ile kimlik doğrulayıcı tarafı içindir, yani 1Password'ün kendi kimlik doğrulayıcı implementasyonudur, sunucu ilgili tarafı için değildir ve sizin kullanım senaryonuza uygun değildir. `webauthn-authenticator-rs` kanidm ekosistemindedir ve istemci ile kimlik doğrulayıcı tarafıdır; test ile sanal kimlik doğrulayıcı için kullanışlıdır. `fido-mds` kanidm workspace'indedir ve metadata servisi ayrıştırması yapar; sunucu tarafı için kullanışlıdır.

### Özet: IdP ekibi için aksiyon listesi

**Hemen yapılacaklar.**

1. BE ile BS bayraklarına erişim çözülür; webauthn-rs'te bu genel değildir ve beşinci bölümdeki tüm politikaların ön koşuludur. `danger-credential-internals` kullanılır veya yukarı akışa PR açılır.
2. İmza sayacı politikası BE'ye bağlanır: BE bir ise kontrol yapılmaz. Bu, CXF passkey taşımalarında kullanıcı kilitlenmesini önler, çünkü CXF sayacı sıfırlamaktadır.
3. AAGUID kayıt anındaki sağlayıcı ipucu olarak modellenir, bir güvenlik kararı olarak değil; CXF taşımaları AAGUID'i eskitmektedir.
4. `attestation: "none"` varsayılan yapılır; kurumsal kiracılar için ayrı bir attestation'lı akış kurulur, yani webauthn-rs'in `AttestedPasskey` tipi ile `fido-mds` kullanılır.
5. `transports` alanında bilinmeyen değerler hata vermeden kabul edilir; `"hybrid"` ile gelecekteki değerler içindir.

**Kısa vadede, yani Level 3 özelliklerini benimseme.**

6. Signal API yük endpoint'i yazılır; tam kimlik bilgisi listesi verilir ve sayfalama yapılmaz. Yanlış yapılırsa kullanıcıların passkey'leri gizlenir. Chrome 132 ve üstü ile Android 144 ve üstü kullanıcılarınızın önemli bir kısmını kapsamaktadır.
7. Koşullu oluşturma akışı eklenir; Chrome 136 ile 142 ve üstü, Safari 18 ve üstü ile iOS 18 ve üstünde çalışır ve parola girişinden sonra sessiz bir passkey yükseltmesidir. `excludeCredentials` doğru doldurulur, attestation istenmez ve kullanıcıya sonradan bildirim gönderilir.
8. PRF için webauthn-rs genişletilmelidir. Kayıtta kimlik bilgisi başına tuz üretilip saklanır, `prf.enabled` saklanır ve PRF çıktısı asla saklanmaz. Windows Hello ile iOS artı harici anahtar senaryoları için bir yedek yol şarttır.
9. İlişkili köken istekleri yalnızca kendi çok alan adlı markanız için düşünülür; müşteri ilgili tarafları için OIDC federasyonu zaten elinizdedir. Kullanılırsa `application/json` içerik tipi, HTTP 200, kimlik doğrulaması olmaması ile en fazla beş etiket kuralına uyulur.

**İzlenecekler.**

10. Level 4'ün ilk kamuya açık çalışma taslağı 9 Eylül 2026'dadır, yani yarındır. Özellikle `uiMode: 'immediate'` (#2291), `sign` uzantısı (#2078) ile algoritma göçü (#2437) izlenmelidir.
11. Post kuantum tarafında FIDO Server Requirements v2.3, 26 Şubat 2026, ML-DSA-44, 65 ile 87'yi ve ESP256, ESP384, ESP512 ile Ed25519'u önerilen listeye almıştır. COSE algoritma tablosu ile kimlik bilgisi veri modelindeki algoritma ve rotasyon alanı buna göre tasarlanmalıdır.
12. CXP hâlâ bir çalışma taslağıdır, 3 Ekim 2024. Sağlayıcıdan sağlayıcıya canlı taşıma standartlaşmamıştır. CXF ise önerilen standarttır, 14 Ağustos 2025 ve 9 Mart 2026 errata'sıyla. Taşınabilirlik gelmektedir ancak henüz tam değildir.

**Kapatılamayan boşluklar**, ekibin doğrulaması gerekenler: 2025 ile 2026 FIDO benimseme raporlarının gerçek sayıları; CXF ile CXP'yi hangi satıcıların gerçekten sevk ettiği, ki 1Password blogunda Temmuz ile Eylül 2026 arasında ilgili bir yazı yoktur; Safari'nin ilişkili köken istekleri ile Signal API destek durumu ve kesin sürümü; largeBlob'un 2026 tarayıcı destek matrisi; metadata servisi veri bloğu endpoint adresi ile imza zinciri detayları.

---

## Hat 3 — PQC ile kimlik doğrulamanın kesişimi

Bu, 8 Eylül 2026 tarihli bir araştırma raporudur: FIDO2 ile WebAuthn post kuantum donanımı ve Rust JOSE PQC durumu.

Yöntem uyarısı şudur: oturumun web arama bütçesi başlamadan önce, yani 200 üzerinden 200 olarak, tükenmiştir; dolayısıyla buradaki her şey doğrudan API sorgularından, yani crates.io, GitHub ile chromestatus'tan, ve hedefli sayfa çekimlerinden gelmektedir. Bu, satıcı duyuruları için olumsuz bulguların hedefli çekimle bulunamadı anlamına geldiğini, kapsamlı bir tarama olmadığını gösterir. Her biri ayrıca işaretlenmiştir.

### A. FIDO2 ile WebAuthn post kuantum donanımı ve ekosistemi

#### A1. Spesifikasyon durumu: PQC yalnızca issue aşamasındadır, henüz spesifikasyon metni değildir

Canlı WebAuthn editör taslağı çekilmiş ve tam oluşturulmuş metin, yani 1,53 milyon karakter, taranmıştır.

`https://w3c.github.io/webauthn/` başlığı "Web Authentication: An API for accessing Public Key Credentials Level 3"tür ve editör taslağı 3 Eylül 2026 tarihlidir. Geçiş sayıları şöyledir: `ML-DSA` sıfır, `post-quantum` sıfır, `quantum` sıfır, `Dilithium` sıfır, `AKP` sıfır ve COSE kimlikleri eksi 49 ile eksi 50 sıfırdır. Sağlama kontrolü olarak `ES256` 162, `EdDSA` 21 ve `COSEAlgorithmIdentifier` 43 kez geçmektedir, yani bu gerçek spesifikasyon gövdesidir.

Sonuç şudur: 8 Eylül 2026 itibarıyla yayımlanmış veya taslak hâlindeki hiçbir WebAuthn spesifikasyon metni ML-DSA'dan bahsetmemektedir. Bu, 25 Ağustos 2026 tarihli Level 3 önerisinde PQC bulunmaması gerçeğiyle tutarlıdır. Editör taslağının hâlâ Level 3 olarak markalandığına dikkat edilmelidir; Level 4 yalnızca GitHub kilometre taşları olarak, yani ilk yayımlanan çalışma taslağı ile ikinci çalışma taslağı olarak, vardır, henüz editör taslağı metni olarak yoktur.

#### A2. W3C WebAuthn GitHub'ında aktif bir post kuantum iş kolu vardır ve asıl sinyal budur

`repo:w3c/webauthn ML-DSA OR "post-quantum" OR PQ` araması 15 sonuç vermektedir. 2026 kümesi şöyledir.

| Numara | Tür | Açılış | Durum | Başlık ve özü |
|---|---|---|---|---|
| 2475 | PR | 2 Eylül 2026 | Açık | Geçersiz kılınan kimlik bilgilerini yedekleme ile geri yükleme |
| 2471 | Issue | 26 Ağustos 2026 | Açık | SHA-256 kullanımı: istemci veri özeti ile ilgili taraf kimliği özeti SHA-256'ya çivilenmiştir ve çeviklik yoktur; SHA-256 CNSA 2.0 altında genel özetleme için onaylı değildir. Önerilen seçenekler resmî bir CNSA istisnası veya SHA-384 ya da SHA-512 taşıyan imzalı bir uzantıdır |
| 2462 | Issue | 6 Ağustos 2026 | Kapalı | `pkOptions.pubKeyCredParams` varsayılanı kuantum gününden sonra güvensiz olacaktır; nsatragno (Google ile Chrome) açmıştır. Varsayılan algoritma setinin kullanımdan kaldırıldığının belgelenmesini, kullanıcı aracısı uyarılarını ile bir kaldırma takvimini önermektedir |
| 2456 | Issue | 29 Temmuz 2026 | Açık | Merkle ağacı sertifikaları için yeni bir toplu attestation tipi eklemek; ve7jtb, yani John Bradley, Yubico. Post kuantum attestation boyutu azaltmasıdır |
| 2448 | Issue | 16 Temmuz 2026 | Açık | Kimlik doğrulayıcılar için varsayılan algoritmaların güncellenmesi gerekebilir; ve7jtb. Şimdi P-384'ün ile post kuantum seçeneği olarak ML-DSA-44'ün eklenmesini önermektedir |
| 2437 | PR | 30 Haziran 2026 | Açık | Algoritma göçünü desteklemek; akshayku, Microsoft. Bir `algPolicy` uzantısı ile doğrulama isteği seçeneklerine `acceptedAlgs` eklemektedir; ek arayüz olmadan sessiz göç hedeflenmektedir. Son hareketi 26 Ağustos 2026'dır ve nsatragno tek bir tercih listesi ile mevcut sinyal API'sine doğru itmektedir |
| 2417 | Issue | 22 Nisan 2026 | Açık | İlgili taraf için post kuantum kripto ile WebAuthn geçişi; akshayku, kilometre taşı Level 4 ikinci çalışma taslağı. IANA COSE kimlikleri eksi 48, 49 ile 50'ye açıkça atıf yapmaktadır. Üç talebi vardır: aynı kullanıcı ile ilgili taraf kimliği için farklı algoritmalı bir kimlik bilgisinin üzerine yazılmaması; ilgili tarafların doğrulama anında algoritma tercihi belirtebilmesi; doğrulama sırasında sessiz kimlik bilgisi oluşturma |
| 2393 | Issue | 26 Şubat 2026 | Açık | ML-DSA test vektörleri eklemek; emlun, yani Emil Lundberg, Yubico; kilometre taşı Level 4 ilk yayımlanan çalışma taslağı. Gerekçesi ML-DSA'nın artık IANA COSE kimliklerine sahip olması, kimlik doğrulayıcı üreticilerinin desteği uygulamaya başlaması ile ilgili tarafların ilgilenmesidir |

Adı geçen dört katılımcı Yubico'yu (ve7jtb ile emlun), Microsoft'u (akshayku) ile Google ve Chrome'u (nsatragno) temsil etmektedir; yani çalışma grubu post kuantum geçişini aktif olarak tasarlamaktadır ancak tamamen algoritma çevikliği ile göç katmanında çalışmaktadır ve henüz birleştirilmiş bir ML-DSA kaydı yoktur.

Belirsizlik şudur: web çekimi GitHub yorum akışlarını oluşturamamış, yalnızca issue gövdelerini verebilmiştir ve GitHub API'si kimlik doğrulamasız hız sınırına takılmıştır. Dolayısıyla 2462 ile 2471 numaralı issue'ların altındaki tartışma okunamamıştır ve satıcı taahhütleri büyük olasılıkla oradadır. Kimliği doğrulanmış bir `gh` istemcisiyle yeniden kontrol edilmeye değer.

#### A3. Donanım kimlik doğrulayıcıları

**Yubico en somut veri noktasıdır ve açıkça ürün değildir.** Christopher Harrell'in 21 Ekim 2025 tarihli "Future-proofing authentication: A look at the future of post-quantum cryptography" yazısı şunları söylemektedir: "Prototype ≠ product: The PQ demo shows feasibility and performance direction, not a shipment announcement."; "New hardware is required: PQ algorithms have bigger footprints; they don't fit on today's keys."; "Standards progress is underway: FIDO, IETF, and other standards work is progressing, but there's more to do beyond 'make a signature'…". Beta yetenekler sınırlı sayıda nitelikli test kullanıcısına açık olarak tanımlanmakta ve post kuantum çalışması prototip seviyesi ile ürüne hazır değil olarak nitelenmektedir.

Yubico'nun sonraki PQC yazısı, yani Joe Scalone'un 26 Haziran 2026 tarihli "Post-quantum cryptography is now a federal mandate" yazısı, hiçbir YubiKey ürünü, ürün yazılımı veya yol haritası taahhüdü içermemekte, yalnızca anahtarların ML-KEM ile ML-DSA desteklemesi gerektiğine dair genel rehberlik vermektedir. Yubico site aramasında post kuantum sorgusu dokuz sayfada 76 sonuç döndürmektedir, ancak 2026 kalemleri web seminerleri, federal zorunluluk yazısı ile ilgisiz bir ortak anmasıdır; HyperCloud'daki hibrit RSA ile ML-KEM duran veri şifrelemesi YubiKey imzalaması değildir.

Sevk edilen bir ML-DSA YubiKey ürünü bulunamamıştır. Harrell'in yeni donanım gerekiyor ifadesi göz önüne alındığında, bir PQC YubiKey'i 5.x hattına bir ürün yazılımı güncellemesini değil yeni bir donanım kuşağını ima etmektedir.

**Google ile OpenSK.** github.com/google/OpenSK aktif bakımdadır; en son commit 4 Eylül 2026'dır ve bir ile dört haftalık bir kadans vardır. Ancak son çalışmalar Wasefire çatısına göç, bağımlılık yükseltmeleri, CTAPHID zaman aşımı düzeltmeleri ile biyometrik kayıttır. PQC, Dilithium veya ML-DSA commit'i bulunamamıştır. Google Güvenlik Blogu'nun kuantum yazıları listesinde 15 Ağustos 2023 tarihli "Toward Quantum Resilient Security Keys" yazısı vardır ve 2026'ya kadar güvenlik anahtarıyla ilgili bir devam yazısı yoktur; 2026 yazıları 27 Şubat 2026 tarihli kuantuma dayanıklı HTTPS yazısı ile aşağıdaki Android yazısıdır. Yani 2023'teki Dilithium ile ECDSA hibriti kamuya açık bir devam almamış görünmektedir.

**Google Android**, komşu bir alandır ve sevk edilen en güçlü PQC sinyalidir. 25 Mart 2026 tarihli "Security for the Quantum Era: Implementing Post-Quantum Cryptography in Android" yazısı şöyle demektedir: "Android 17 updates Android Keystore to natively support ML-DSA. This allows applications to leverage quantum-safe signatures entirely within the device's secure hardware." Ayrıca doğrulanmış açılışta ML-DSA entegrasyonu ile Play hibrit imzalama blokları vardır. Yazı FIDO2, WebAuthn, passkey, güvenlik anahtarı veya Titan'dan bahsetmemektedir; ML-DSA platform bütünlüğü ile uygulama imzalaması için kullanılmaktadır, kimlik bilgileri için değil. Yine de anahtar deposunda donanım destekli ML-DSA, gelecekteki bir Android post kuantum passkey'inin ihtiyaç duyacağı alt yapıdır.

**Feitian.** ftsafe.com'un FIDO ürünleri sayfasında ePass FIDO, ePass FIDO-NFC, BioPass FIDO, iePass FIDO ile MultiPass FIDO vardır. PQC veya ML-DSA iddiası yoktur ve bulunamamıştır.

**SoloKeys.** Organizasyon depoları Ağustos 2026'ya kadar aktiftir: solo2 20 Ağustos 2026, fido-authenticator 17 Ağustos 2026, ctap-types 10 Ağustos 2026 ile trussed 9 Ağustos 2026'da güncellenmiştir. libcrux'un bir fork'unu taşımaktadırlar, 9 Ağustos 2026'da güncellenmiştir; libcrux yukarı akışta formel olarak doğrulanmış ML-KEM ile ML-DSA kütüphanesidir, yani ilkel erişilebilir durumdadır. Ancak FIDO ürün yazılımı depolarında görünür bir PQC çalışması yoktur ve bulunamamıştır.

**Nitrokey.** nitrokey.com/news sayfasında 2025 ile 2026'da PQC kalemi yoktur; NetHSM, NitroPhone ile fiyatlandırma vardır. Bulunamamıştır.

**TPM 2.0 ile TCG doğrulanmamıştır.** trustedcomputinggroup.org hem web çekimine hem tarayıcı kullanıcı aracısıyla curl'e HTTP 403 döndürmüştür; post kuantum araması ile TPM 2.0 kütüphane spesifikasyonu kaynak sayfası için denenmiştir. ML-DSA veya ML-KEM ekleyen bir TPM 2.0 revizyonu hakkında iki yönde de kanıt yoktur. Bu, A bölümündeki en büyük çözülmemiş boşluktur.

**Google Titan özelinde** ayrı bir PQC duyurusu bulunamamıştır; Titan ürün yazılımı OpenSK'ya komşudur ancak aynı değildir.

#### A4. Passkey sağlayıcıları

**Google ile Chrome.** chromestatus'ta WebAuthn PQC özelliği yoktur. chromestatus API'sinde ML-DSA, post kuantum ile webauthn sorguları 15 WebAuthn özelliği döndürmekte ve hiçbiri PQC değildir. Tek ML-DSA eşleşmesi 5198951632470016 numaralı "Algorithm Updates in WebCrypto" özelliğidir; durumu önerilmiştir ve masaüstü kilometre taşı 154'tür: "Add post-quantum cryptography and a common symmetric AEAD… ML-KEM - 768, 1024; ML-DSA - 44, 65, 87; ChaCha20-Poly1305; X-Wing." Bu WebCrypto'dur, WebAuthn değildir.

**Microsoft.** Güvenlik blogundaki PQC yazıları 20 Ağustos 2025 tarihli kuantum güvenli güvenlik ilerlemesi, 16 Nisan 2026 tarihli kriptografik envanter oluşturma, 30 Haziran 2026 tarihli kuantum güvenli takvimi hızlandırma ile 10 Temmuz 2026 tarihli güvenli gelecek girişimi ilerleme raporudur. Hiçbiri listede passkey, FIDO2, WebAuthn veya Entra PQC içeriği yüzeye çıkarmamıştır; kuantum güvenli takvimi hızlandırma yazısı açılamamış ve tahmin edilen adres 404 dönmüştür. Microsoft'un asıl WebAuthn PQC katılımı bunun yerine W3C'deki 2417 ile 2437 numaralı issue'larda, yani akshayku üzerinden, görünmektedir.

**Apple.** Bulunamamıştır; bir Apple PQC passkey beyanını bulacak arama yeteneği olmamış ve bir Apple sayfası çekilmemiştir. Olumsuz değil doğrulanmamış olarak ele alınmalıdır.

**1Password.** 1password.com/blog listesinde PQC veya kuantum güvenli yazı yoktur; `blog.1password.com/?s=post-quantum` adresi filtresiz bloga yönlenmektedir. Bulunamamıştır. 1Password'ten Nick Steele listelenmiş bir WebAuthn katkıcısıdır ancak bir PQC beyanı bulunamamıştır.

#### A5. FIDO Alliance'ın PQC programı

`fidoalliance.org/?s=post-quantum` toplam on sonuç döndürmektedir ve hepsi sayılmıştır. Etkinlikler: 1 Temmuz 2026 tarihli passkey'ler ile post kuantum kriptografinin güvenliğin geleceğini nasıl yeniden şekillendirdiği; 11 Ağustos 2025 tarihli üye etkinliği. Bölgesel atölye özetleri: Ağustos 2026 Hindistan, Aralık 2025 Taipei ile Aralık 2025 Kore. Seminer sunumları: Haziran 2025 ile Mart 2025. Ayrıca 2024 APAC zirvesi vardır. Haber olarak 1 Eylül 2023 tarihli IEEE Spectrum alıntısı bulunmaktadır. Bir de üye profili vardır.

FIDO Alliance'ın bir PQC beyaz kâğıdı, bir PQC çalışma grubu ile bir PQC sertifikasyon programı bulunamamıştır. `fidoalliance.org/specifications/` sayfası PQC veya ML-DSA'dan hiç bahsetmemektedir. Beyaz kâğıt dizin sayfaları JavaScript ile oluşturulmakta ve curl'e Cloudflare tarafından bloke edilmektedir, dolayısıyla site aramasında listelenmeyen bir kâğıt var olabilir; ancak iki bağımsız yol da bir şey bulamamıştır.

#### A6. A bölümünün sonucu

FIDO2 ile WebAuthn'da PQC bugün standart komitesi çalışması artı kabul edilmiş tek bir prototipten ibarettir. Hiç kimse bir ML-DSA FIDO2 kimlik doğrulayıcısı sevk etmemektedir. Kayıtta görünen üç somut engel şunlardır: kimlik bilgisi ile attestation boyutu, ki Merkle ağacı attestation'ına, yani 2456 numaralı issue'ya işaret etmektedir; göç için algoritma çevikliğinin olmaması, ki 2417 ile 2437 numaralı kayıtlara işaret etmektedir; ve çivilenmiş SHA-256 özetleri, ki 2471 numaralı issue'ya işaret etmektedir. Yubico açıkça post kuantumun bugünün anahtarlarına sığmadığını söylemektedir.

### B. PQC destekli Rust JOSE ile JWT kütüphaneleri

#### B1. Adı geçen kütüphaneler, çoğunlukla hayır

| Crate | Son sürüm | Tarih | ML-DSA veya RFC 9964 var mı |
|---|---|---|---|
| josekit | 0.10.3 | 20 Mayıs 2025 | Yoktur. README'deki desteklenen imzalama listesi HS, RS, PS ile ES'in 256, 384 ve 512 varyantları, ES256K ile EdDSA'dan ibarettir. `AKP` yoktur, ML-DSA yoktur, RFC 9964 yoktur. GitHub'da ML-DSA, post kuantum, PQC, Dilithium ile AKP araması sıfır sonuç vermektedir. Depoda bir değişiklik günlüğü dosyası yoktur |
| jsonwebtoken | 11.0.0 | 24 Temmuz 2026 | Henüz yoktur ancak uçuştadır; aşağıya bakınız |
| biscuit-auth | 6.0.0 | 16 Temmuz 2025 | Kanıt bulunamamıştır; GitHub sorgusu 422 döndürmüş ve yeniden denenmemiştir. Crate bir yıldan fazladır bayattır. Bulunamadı olarak, düşük güvenle ele alınmalıdır |
| jwt, yani rust-jwt, mikkyang | 0.16.0 | 9 Ocak 2022 | Yoktur; 2022'den beri bakımsızdır |
| jose-jwt | — | — | Crate crates.io'da yoktur, 404 döndürmektedir |
| openidconnect | 4.0.1 | 6 Temmuz 2025 | Yoktur; depo issue aramasında ML-DSA, post kuantum ile PQC sıfır sonuç vermektedir |
| oxide-auth | 0.6.1 | 2 Haziran 2024 | Yoktur; Haziran 2024'ten beri bayattır |
| rauthy | crates.io'da yoktur | — | Yoktur; aşağıya bakınız |

**jsonwebtoken'da aktif ancak birleştirilmemiş bir ML-DSA çalışması vardır.** 534 numaralı issue, yani "Support for ML-DSA signed JWTs", 12 Ağustos 2026'da PhilSchmieder tarafından açılmış, RFC 9964 JOSE bağlamalarına atıf yapmış ve aws-lc-rs ile RustCrypto'nun ikisinde de implementasyon olduğunu belirtmiştir. 535 numaralı PR, yani "Add support for ML-DSA signatures", 17 Ağustos 2026'da açılmış, son hareketi 3 Eylül 2026'dır ve durumu açık ile değişiklik istendi şeklindedir. ML-DSA-44, 65 ile 87'yi RFC 9964 kablo adlarıyla eklemekte, yani Rust enum'unda `Algorithm::MLDSA44` olarak; RFC 9964 uyarınca `kty: "AKP"` JWK içe ile dışa aktarımı ve parmak izlerini; PKCS#8 DER ile PEM özel anahtarlarını; ham ile SPKI açık anahtarlarını; ve parametre seti uzunluk doğrulamasını getirmektedir. İki arka ucu vardır: `aws_lc_rs`, ki 1.15'ten 1.18'e yükseltilmiştir, ile `rust_crypto`, ki `signature` 3.x üzerinden `ml-dsa` crate'ini kullanmaktadır. Katkıcı arckoor JWK serileştirme karmaşıklığı, test makroları, genel API yüzeyi ile algoritma ailesi isimlendirmesi konusunda değişiklik istemiştir. Bir birleştirme takvimi verilmemiştir. Bu, 24 Temmuz 2026 tarihli 11.0.0 sürümünün `CryptoProvider` soyutlamasını getirmesiyle mümkün olmuştur.

**rauthy bunu istemektedir ancak sevk etmemiştir.** 857 numaralı issue, yani "Feat: FIPS 204", 18 Nisan 2025'te açılmıştır, hâlâ açıktır, etiketleri iyileştirme ile gelecek şeklindedir ve bakımcı sebadob'a atanmıştır. Bakımcı, yukarı akıştaki JWT crate'inin FIPS 204 önerisini reddettiğini, bu yüzden rauthy'nin kendi JWT yığınını inşa ettiğini belirtmektedir. rauthy'nin değişiklik günlüğünde tam olarak bir PQC eşleşmesi vardır; 3654 numaralı satırda, v0.30.0 bölümünde, 14 Mayıs 2025'te kapanan 941 numaralı PR şöyle demektedir: "…makes Rauthy independent for things like PQC algorithms / FIPS 204 in the future." Yani yalnızca zemin hazırlığıdır ve sevk edilen rauthy'de ML-DSA yoktur.

#### B2. Sorulmayan ancak ML-DSA JWS uygulayan crate'ler, asıl cevap

crates.io araması üç tane yüzeye çıkarmıştır ve ikisi RFC 9964 semantiğini açıkça uygulamaktadır.

**`jwt-simple` 0.13.1, 19 Ağustos 2026, açık ara en çok kullanılan ve bugün sevk edilendir.** Toplam 6.157.377 indirmesi ile 994.638 yakın dönem indirmesi vardır; deposu jedisct1/rust-jwt-simple'dır. ML-DSA 30 Temmuz 2026'da çıkan 0.13.0 sürümünde gelmiştir ve sürüm notu "ML-DSA is now supported" demektedir. README algoritma tablosu `ML-DSA-44`, `ML-DSA-65` ile `ML-DSA-87`'yi FIPS 204 post kuantum olarak listelemekte ve `MLDSA44KeyPair`, `MLDSA65KeyPair` ile `MLDSA87KeyPair` tiplerini sunmaktadır; README ML-DSA-44'ü önermektedir. Arka ucu saf Rust olan `superboring` 0.1.14'tür ve Cargo.toml yorumu şöyledir: mevcut `boring` crate'i henüz ML-DSA uygulamadığı için ML-DSA imzaları crate'in yeni bir sürümü çıkana kadar her zaman bir Rust implementasyonu kullanmaktadır. Uyarı şudur: algoritma adları RFC 9964 kablo adlarıyla eşleşmektedir ancak README'de `AKP` veya RFC 9964 referansı bulunamamıştır; JWK ile `kty: "AKP"` desteği doğrulanmamıştır ve muhtemelen yoktur. Özellikle RFC 9964 JWK birlikte çalışabilirliği gerekiyorsa güvenmeden önce doğrulanmalıdır.

**`jose-rs` 0.7.0, 5 Ağustos 2026, bulunan en standartlara uygun PQC JOSE crate'idir.** Deposu kushaldas/jose-rs'tir; 2 Nisan 2026'da oluşturulmuştur ve 1.300 indirmesi vardır, yani yeni ile küçüktür. README'deki desteklenen algoritmalar bölümü şöyle demektedir: isteğe bağlı JWS post kuantum imzaları olarak ML-DSA-44, ML-DSA-65 ile ML-DSA-87, yani FIPS 204, artı `draft-ietf-jose-pq-composite-sigs-03` belgesindeki altı bileşik algoritma, yani ML-DSA-44-ES256, ML-DSA-65-ES256, ML-DSA-87-ES384, ML-DSA-44-Ed25519, ML-DSA-65-Ed25519 ile ML-DSA-87-Ed448. JWK satırı RSA, EC, oct, OKP ile AKP anahtar tiplerini listelemektedir. README'nin AKP kablo biçimi bölümü şöyle demektedir: `draft-ietf-cose-dilithium` uyarınca ML-DSA anahtarları yeni `AKP` tipini kullanmaktadır; dikkat edilmelidir ki numarasıyla RFC 9964'e değil COSE taslağına atıf yapmaktadır. Bileşik algoritmalar AKP üyelerini ham birleştirilmiş anahtarlarla yeniden kullanmaktadır. Özellik bayrağı `post-quantum`'dur ve varsayılan kapalıdır. Arka ucu yazarın `kryptering` crate'i üzerinden RustCrypto'nun `ml-dsa ^0.1.0` crate'idir; `kryptering`'in 145 bin indirmesi vardır. `jwt_ml_dsa` ile `jwt_composite` örnekleri dahildir. Bu, hibrit ile bileşik ML-DSA artı klasik JWS'i de yapan bulunan tek crate'tir.

**`jose4rs` 0.5.0, 5 Eylül 2026, yepyeni ve küçüktür.** Deposu ogital-net/jose4rs'tir; 24 Ağustos 2026'da oluşturulmuştur, 79 indirmesi vardır ve 12 günde beş sürüm çıkarmıştır. Java jose4j'nin bir portudur. README'ye göre ML-DSA-44, 65 ile 87 opsiyonel bir `pq-ml-dsa` özelliği altındadır ve bu özellik `aws-lc` kullanımını ima etmektedir; RFC 9964 uyarınca ML-DSA için opsiyonel `AKP` anahtarlarını desteklemektedir. Bağımlılık alınamayacak kadar olgunlaşmamıştır, çünkü sürüm çalkantısı vardır ve benimsenmesi sıfıra yakındır; ancak RFC 9964 deseninin bağımsız olarak uygulandığını doğrulamaktadır.

Bilgi amaçlı olarak `pq-algorithm-id` 0.0.1, 26 Ocak 2026, "Algorithm identifier mappings (JOSE, COSE, X.509)", 25 indirme ile deposuz, ve `pq-oid` 1.0.3, 20 Şubat 2026, da yüzeye çıkmıştır. crates.io'da `rfc9964` araması sıfır crate döndürmektedir.

İlkel katman referans olarak şöyledir: `ml-dsa` 0.1.1, RustCrypto/signatures, 5 Haziran 2026; ilk kararlı sürümü 0.1.0, 17 Mayıs 2026'dır; saf Rust'tır ve FIPS 204 final sürümünü uygulamaktadır. `fips204` 0.4.6, 22 Aralık 2024, integritychain'indir ve yaklaşık 21 aydır bayattır.

#### B3. Rust'tan erişilebilir FIPS 140-3 validasyonlu ML-DSA, kilit olumsuz sonuç

Kontrol edilen hiçbir CMVP validasyonlu modülün onaylı algoritma listesinde ML-DSA yoktur.

AWS-LC'nin FIPS dokümanına göre verilmiş sertifikalar şunlardır.

| Modül | Sertifika |
|---|---|
| AWS-LC-FIPS v1.0 | 4631 |
| AWS-LC Cryptographic Module, dinamik, NetOS | 5146 |
| AWS-LC-FIPS v2.0, dinamik | 5429 |
| AWS-LC-FIPS v2.0, statik | 4816 |
| AWS-LC-FIPS v3.1, dinamik | 5298 |
| AWS-LC-FIPS v3.1, statik | 5314 |

Güncel iki tanesi csrc.nist.gov'da açılmıştır. 5298 numaralı sertifika "AWS-LC 3 Cryptographic Module (dynamic)" içindir, 3 Haziran 2026'da validasyondan geçmiştir, aktiftir ve batımı 2 Haziran 2031'dir; onaylı algoritmaları ML-KEM anahtar üretimi ile kapsülleme ve çözme işlemlerini içermektedir, CAVP numaraları A6176 ile A6180, A6184 ve A6278 ile A6279'dur; ML-DSA bulunmamaktadır. 5314 numaralı sertifika "AWS-LC 3 Cryptographic Module (static)" içindir, 5 Haziran 2026'da validasyondan geçmiştir, aktiftir ve batımı 4 Haziran 2031'dir; ML-KEM bulunmaktadır, CAVP numaraları A6288 ile A6315 arasıdır; ML-DSA bulunmamaktadır.

AWS-LC-FIPS v4.0'ın statik ile dinamik biçimleri CMVP'nin işlemdeki modüller listesindedir; akredite bir laboratuvar tarafından test edilmiş ve NIST'e sunulmuştur ancak henüz sertifikalanmamıştır. ML-DSA'yı ekleyen modül FIPS 4.0'dır.

Bu doğrudan Rust'la ilgilidir: aws-lc-rs 1.18.0, crates.io yayın tarihi 7 Ağustos 2026, ML-DSA API'lerini kararlı hâle getirmiştir. `aws-lc-rs/src/unstable/signature.rs` dosyası artık ML-DSA imza API'lerinin kararlı hâle geldiğini ve bunun yerine `crate::signature` kullanılması gerektiğini söylemekte, `PqdsaKeyPair`, `PqdsaPrivateKey` ile `PqdsaPublicKey` için kullanımdan kaldırılmış takma adlar sunmaktadır. `signature.rs` dosyası `ML_DSA_44`, `ML_DSA_65` ile `ML_DSA_87` ve imzalama varyantlarını açmakta, bunları boş bağlam dizesiyle saf ML-DSA olarak belgelemekte ve ön özetli ML-DSA'nın desteklenmediğini belirtmektedir. Sürüm notları şöyledir: ML-DSA artık `unstable` özelliğini gerektirmemektedir ve `fips` altında kullanılabilirdir, çünkü FIPS 4.0 modülü ML-DSA sağlamaktadır ve bu API'leri kararsız tutan şey buydu; ayrıca 1.18.0, aws-lc-fips-sys'i FIPS 3.x'ten 4.x'e yükseltmektedir ve bu modül validasyon testini tamamlamış ile sertifikasyon için NIST'e sunulmuştur.

> **Tarih tutarsızlığı işaretlenmiştir.** GitHub sürüm sayfası özetleyicisi v1.18.0'ı 7 Ağustos 2024 olarak raporlamıştır. crates.io otoriterdir ve 7 Ağustos 2026 demektedir; aws-lc-rs 1.18.1 ile 1.17.4'ün ikisi de 1 Eylül 2026'da yayımlanmıştır. 2024 bir özetleyici hatası olarak ele alınmalıdır.

Dolayısıyla tuzak şudur: FIPS modunda ML-DSA almak için aws-lc-rs 1.18'e yükseltmek sizi sertifikalı bir modülden, yani 3.x ile 5298 ve 5314'ten, sertifikasız ve işlemdeki bir modüle, yani 4.0'a taşır. 3.x'te kalmak sertifikayı korur ancak ML-DSA vermez. Şu anda aws-lc-rs üzerinden validasyonlu ML-DSA almanın bir yolu yoktur.

**wolfSSL.** wolfssl.com/license/fips sayfasına göre aktif sertifikalar 5041 ile 4718'dir ve ikisi de 17 Temmuz 2030'a kadar geçerlidir; tarihsel FIPS 140-2 sertifikaları 3389 ile 2425'tir. Hiçbir aktif sertifika ML-DSA veya ML-KEM içermemektedir. wolfCrypt v7.0.0 erken geliştirme aşamasındadır, sunum beklemektedir ve planlanan FIPS 203 ML-KEM ile FIPS 204 ML-DSA desteğini içermektedir. Sayfa, FIPS 140-2'nin Eylül 2026'dan sonra yeni federal alımlar için kabul edilmeyi bırakacağını belirtmektedir.

**BoringCrypto** kontrol edilmemiştir; kullanılabilir bir arama yolu kalmamıştır ve doğrulanmamıştır.

#### B4. B bölümünün sonucu

Rust'ta bugün ML-DSA JWS isteniyorsa iki seçenek vardır: `jwt-simple` 0.13.1, ki olgundur, benimsenmesi yüksektir ve saf Rust superboring arka ucunu kullanır ancak AKP ile JWK birlikte çalışabilirliği doğrulanmamıştır; ya da `jose-rs` 0.7.0, ki düzgün bir `AKP` JWK'sı ile bileşik hibrit algoritmalar sunar ancak 1,3 bin indirmelidir ve beş aylıktır. `jsonwebtoken`'ın 535 numaralı PR'ı, ana akım crate'te aws-lc-rs ile RustCrypto arka uçları arasında seçim yaparak ML-DSA isteniyorsa izlenmesi gereken çalışmadır. Rust'ta hiçbir şey size FIPS 140-3 validasyonlu ML-DSA vermemektedir; bu, AWS-LC-FIPS 4.0'ın CMVP'yi geçmesini veya wolfCrypt 7.0.0'ın sunulmasını beklemektedir.

### Açık belirsizlik ile bulunamayanlar defteri

Doğrulanmayan ve bloke olan: TCG ile TPM 2.0 PQC durumu; trustedcomputinggroup.org denenen her çekim yoluna 403 döndürmektedir ve iki yönde de bir sonuç yoktur.

Doğrulanmayan ve arama yapılamayan: Apple'ın PQC passkey beyanları. Buradaki yokluk araç eksikliğidir, kanıt değildir.

Okunamayan ve hız sınırına takılan: W3C'deki 2462, 2471, 2448 ile 2456 numaralı issue'ların yorum akışları; web çekimi yalnızca issue gövdelerini oluşturmakta ve GitHub API'si saatte 60 isteklik kimlik doğrulamasız sınıra takılmaktadır. Satıcı taahhütleri en makul olarak orada bulunur ve kimliği doğrulanmış bir `gh` istemcisiyle yeniden çalıştırılmalıdır.

Düşük güvenli olumsuz: biscuit-auth'un PQC durumu; bir sorgu 422 döndürmüş ve yeniden denenmemiştir.

Kontrol edilmeyen: BoringCrypto'nun CMVP durumu; Microsoft'un 30 Haziran 2026 tarihli kuantum güvenli takvimi hızlandırma yazısının gövdesi; Cloudflare ile JavaScript arkasındaki FIDO beyaz kâğıt dizini.

Uydurma koruması: yukarıdaki her sürüm numarası ile tarih crates.io API'sinden, ham GitHub dosyalarından, csrc.nist.gov sertifika sayfalarından veya chromestatus API'sinden gelmektedir; tek istisna işaretlenen aws-lc-rs 2024 özetleyici hatasıdır ve crates.io'ya karşı düzeltilmiştir.

---

## Hat 4 — TLS'te post kuantum, gerçek dağıtım verisi

Bu, 8 Eylül 2026 itibarıyla TLS'te post kuantum kriptografinin durumudur.

Yöntem notu ile sınırlama baştan verilmiştir: bu oturumun web arama bütçesi başlamadan önce zaten tükenmişti, dolayısıyla aşağıdaki her şey birincil kaynakların doğrudan çekiminden gelmektedir; IANA CSV dosyaları, IETF Datatracker ile RFC Editor, chromestatus ile chromiumdash API'leri, Chrome politika şablonu JSON'ları, openssl-library.org, go.dev, Firefox sürüm notları, support.apple.com, BoringSSL git deposu, crates.io ile blog.cloudflare.com kullanılmıştır. radar.cloudflare.com bir Cloudflare bot meydan okumasının arkasındadır ve hem web çekimine hem curl'e her denemede HTTP 403 döndürmüştür; sayfa HTML'i, `/post-quantum`, `/adoption-and-usage` ile iç API yolları denenmiştir. `api.cloudflare.com/client/v4/radar/*` bir API jetonu gerektirmektedir. Dolayısıyla canlı Eylül 2026 Radar rakamı okunamamıştır ve bir rakam uydurulmamıştır.

### 1. X25519MLKEM768 benimsenmesi

**Alınamayan.** Eylül 2026 için tam güncel Cloudflare Radar yüzdesi alınamamıştır. Radar bir tarayıcı veya jeton olmadan erişilemezdir. Bilinmiyor olarak işaretlenmiştir ve tahmin edilmemiştir.

**Cloudflare'in birincil kaynaklarında belgelenenler.**

| Tarih | Rakam | Kaynak |
|---|---|---|
| 2024 başı | Yüzde üçün altı | 27 Şubat 2026 tarihli radar yazısı |
| Eylül 2025 | En büyük 100 bin alan adının %39'u post kuantum anahtar anlaşmasını desteklemektedir | pq-2025 |
| Ekim 2025 | Cloudflare ile insan kaynaklı trafiğin yarısından fazlası post kuantum şifrelemeyle korunmaktadır | pq-2025, 28 Ekim 2025 |
| Şubat 2026 | Yüzde altmışın üzerinde | Radar yazısı |
| 7 Nisan 2026 | Cloudflare'e gelen insan trafiğinin %65'inden fazlası post kuantum şifrelidir | post-quantum-roadmap |
| 23 Haziran 2026 | Cloudflare'e gelen tarayıcı trafiğinin üçte ikisinden fazlası | post-quantum-eo-2026 |

Kaynak sunucu tarafı, yani Cloudflare'den müşteri kaynak sunucusuna giden yön, çok geridedir: Şubat 2026 itibarıyla kaynakların yaklaşık %10'u post kuantum tercihli anahtar anlaşmasını desteklemektedir ve bu, 2025 başındaki yüzde birin altından yaklaşık on kat artıştır.

Metrik uyarısı şudur: Cloudflare'in manşet rakamı insan ile tarayıcı kaynaklı trafiktir. Botlar ile API istemcilerini de içeren tüm trafik rakamı daha düşüktür ve alınamamıştır.

Kanonik adres `https://radar.cloudflare.com/post-quantum`'dur; adanmış bir post kuantum bölümü ile Şubat 2026'da duyurulan, bir sitenin post kuantumu destekleyip desteklemediğini sorgulayan bir denetleyici içermektedir.

### 2. `draft-ietf-tls-ecdhe-mlkem` artık RFC 10024'tür

RFC 10024 olarak Ağustos 2026'da Standards Track, yani önerilen standart olarak yayımlanmıştır. Başlığı "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3"tür. Yazarları K. Kwiatkowski (PQShield), P. Kampanakis (AWS), B. E. Westerbaan (Cloudflare) ile D. Stebila'dır (Waterloo); sorumlu alan direktörü Paul Wouters'tır. Son internet taslağı revizyonu `draft-ietf-tls-ecdhe-mlkem-05`'tir ve Datatracker damgası 10 Ağustos 2026'dır. Kaynakları rfc-editor.org/rfc/rfc10024.txt ile datatracker.ietf.org/doc/rfc10024'tür.

**IANA TLS desteklenen gruplar kaydı**, hem kayıt CSV dosyasına hem RFC 10024'ün IANA bölümüne karşı doğrulanmıştır. Kaynağı `https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv`'dir.

| Değer | Onaltılık | İsim | DTLS uygun | Önerilen | Referans |
|---|---|---|---|---|---|
| 4587 | 0x11EB | SecP256r1MLKEM768 | Evet | Hayır | RFC 10024 |
| 4588 | 0x11EC | X25519MLKEM768 | Evet | Evet | RFC 10024 |
| 4589 | 0x11ED | SecP384r1MLKEM1024 | Evet | Hayır | RFC 10024 |
| 512 | 0x0200 | MLKEM512 | Evet | Hayır | `draft-connolly-tls-mlkem-key-agreement-05` |
| 513 | 0x0201 | MLKEM768 | Evet | Hayır | Aynı |
| 514 | 0x0202 | MLKEM1024 | Evet | Hayır | Aynı |
| 4585 | 0x11E9 | SecP256r1MLKEM512 | Evet | Hayır | `draft-rosomakho-tls-ecdhe-mlkem512-00` |
| 4586 | 0x11EA | MLKEM512X25519 | Evet | Hayır | Aynı |
| 4590 | 0x11EE | curveSM2MLKEM768 | Hayır | Hayır | `draft-yang-tls-hybrid-sm2-mlkem-03` |
| 25497 | 0x63A5 | X25519Kyber768Draft00, eskimiştir | Evet | Önerilmez | RFC 10024 ile geçersiz kılınmıştır |
| 25498 | 0x63A6 | SecP256r1Kyber768Draft00, eskimiştir | Evet | Önerilmez | RFC 10024 ile geçersiz kılınmıştır |

X25519MLKEM768, önerilen olarak işaretli tek post kuantum gruptur. RFC 10024 iki Kyber taslağı kod noktasını açıkça önerilmez durumuna çevirmiştir.

0x11EC değerinin bağımsız doğrulaması BoringSSL'in `include/openssl/ssl.h` dosyasının 2699. satırındadır: `#define SSL_GROUP_X25519_MLKEM768 0x11ec`.

**Tel üzerindeki boyutlar**, RFC 10024 §3'ten birebir: X25519MLKEM768 için istemci payı 1216 bayttır, yani 1184 baytlık ML-KEM kapsülü ile 32 baytlık X25519; sunucu payı 1120 bayttır, yani 1088 baytlık şifreli metin ile 32; paylaşılan sır 64 bayttır. SecP256r1MLKEM768 için istemci payı 1249, sunucu payı 1153 bayttır ve paylaşılan sır 64 bayttır. SecP384r1MLKEM1024 için istemci ile sunucu payı 1665 bayttır ve paylaşılan sır 80 bayttır.

**Saf ML-KEM, yani hibrit olmayan.** `draft-ietf-tls-mlkem-10`, 2 Eylül 2026 tarihlidir; Datatracker zamanı 3 Eylül 2026'dır. IESG durumu onay duyurusu gönderildi şeklindedir, yani RFC Editor kuyruğundadır ve henüz bir RFC değildir. Hedeflenen statüsü bilgilendiricidir. MLKEM512, 768 ile 1024'ü, yani 512, 513 ile 514 değerlerini kaydetmektedir. IANA kaydı hâlâ öncülü olan bireysel taslağa, yani süresi dolmuş ve çalışma grubu taslağıyla değiştirilmiş `draft-connolly-tls-mlkem-key-agreement-05`'e atıf yapmaktadır; referans RFC yayımlandığında güncellenecektir.

**Ayrıca işaretlenmeye değer: TLS 1.3'ün kendisi yeniden yayımlanmıştır.** RFC 9846, Temmuz 2026, "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446'yı ve 5077, 5246, 6961, 7627 ile 8422'yi geçersiz kılmaktadır. RFC 10024, 8446'ya değil 9846'ya atıf yapmaktadır.

### 3. Tarayıcı ile kütüphane durumu

| Implementasyon | X25519MLKEM768 durumu | Sürüm ile tarih | Kaynak |
|---|---|---|---|
| Chrome | M124'ten beri masaüstünde varsayılan olarak post kuantum kullanılmaktadır, Nisan 2024, X25519Kyber768 ile; Chrome 131'de ML-KEM'e, yani X25519MLKEM768'e geçilmiştir, kararlı sürüm 6 Kasım 2024. Android varsayılanı Kasım 2024'tür | M131 | Chrome politika şablonu JSON'u birebir şöyle demektedir: "Prior to Google Chrome 131, the algorithm was Kyber, an earlier draft iteration of the standard." |
| Chrome kaçış kapısı | `PostQuantumKeyAgreementEnabled` kullanımdan kaldırılmış ve gitmiştir: desteklenen aralıklar `chrome.*:116-146`, `chrome_os:116-146` ile `android:116-146`'dır. M147 kararlı sürümü 7 Nisan 2026'da çıkmıştır, dolayısıyla post kuantum anahtar anlaşmasını kapatmanın desteklenen bir yolu artık yoktur. ChromeOS cihaz düzeyindeki `DevicePostQuantumKeyAgreementEnabled` de aynı şekilde `chrome_os:128-146` aralığındadır | M147 itibarıyla kaldırılmıştır | chromeenterprise.google politika şablonları JSON'u |
| Chrome güncel kararlı sürüm | 152.0.7977.83; M152 kararlı sürümü 25 Ağustos 2026'dır | — | chromiumdash `fetch_releases` |
| Firefox | Sürüm notu şöyledir: "Added support for a post-quantum key exchange mechanism for TLS 1.3 (mlkem768x25519)", Firefox 132, 29 Ekim 2024. HTTP/3 ile QUIC desteği Firefox 135'te eklenmiştir, 4 Şubat 2025: "Added support for a post-quantum key exchange mechanism (mlkem768x25519) for HTTP/3." | 132 ile 135 | firefox.com sürüm notları |
| Safari ile Apple | Apple platform güvenliği rehberi birebir şöyledir: "On devices with iOS 26, iPadOS 26, or later, TLS 1.3 with quantum-secure encryption (with the X25519MLKEM768 key exchange algorithm) is enabled by default for `URLSession` framework and the `Network` APIs." iOS, iPadOS ile macOS 26 ile Eylül ve Ekim 2025'te sevk edilmiştir | iOS, iPadOS ile macOS 26 | support.apple.com'un TLS güvenliği sayfası |
| OpenSSL | 3.5.0, 8 Nisan 2025, yeni politika altındaki ilk uzun destekli sürümdür ve desteği 8 Nisan 2030'a kadardır. ML-KEM, ML-DSA ile SLH-DSA eklemektedir. Sürüm notları şöyledir: "The default TLS keyshares have been changed to offer X25519MLKEM768 and X25519" ve "The default TLS supported groups list has been changed to include and prefer hybrid PQC KEM groups." Not olarak OpenSSL 3.0 uzun destekli sürümünün desteği 7 Eylül 2026'da, yani dün, bitmiştir | 3.5 uzun destekli | openssl-library.org'un 3.5 notları ile sürüm stratejisi sayfası |
| BoringSSL | Güncel `include/openssl/ssl.h` dosyasında `SSL_GROUP_X25519_MLKEM768` 0x11ec, `SSL_GROUP_MLKEM1024` 0x0202 ile `SSL_SIGN_ML_DSA_44`, `65` ve `87` sırasıyla 0x0904, 0x0905 ile 0x0906'dır | Ana dal | boringssl.googlesource.com |
| Go | Go 1.24, Şubat 2025: "The new post-quantum X25519MLKEM768 key exchange mechanism is now supported and is enabled by default when Config.CurvePreferences is nil. GODEBUG setting `tlsmlkem=0` reverts the default." `X25519Kyber768Draft00` kaldırılmıştır. Go 1.23, Ağustos 2024, Kyber taslağını varsayılan açık tutuyordu | 1.24 | go.dev/doc/go1.24 |
| rustls | 0.23.16, 28 Ekim 2024, kyber768'den ML-KEM-768'e geçmiştir. 0.23.22, 30 Ocak 2025, aws-lc-rs sağlayıcısıyla X25519MLKEM768 ile yeni `prefer-post-quantum` crate özelliğini getirmiştir. 0.23.27, 5 Mayıs 2025, post kuantum anahtar değişim algoritmalarını varsayılan olarak tercih etmekte ve `prefer-post-quantum` varsayılan özelliklere eklenmektedir. 0.23.28, 16 Haziran 2025, `secp256r1mlkem768` eklemiştir. 0.23.37, 24 Şubat 2026, ML-KEM-1024 eklemiştir | 0.23.27 varsayılanı | GitHub sürümleri ile crates.io sürüm tarihleri |

### 4. TLS'te ML-DSA kimlik doğrulaması

`draft-ietf-tls-mldsa-05`, 6 Temmuz 2026 tarihlidir; Datatracker zamanı 8 Temmuz 2026'dır. IESG durumu onay duyurusunun gönderileceği ile alan direktörü takibi şeklindedir, yani IESG onaylamıştır ancak henüz bir RFC değildir. Hedeflenen statüsü bilgilendiricidir. Sorumlu alan direktörü Deb Cooley, çoban Sean Turner'dır. `draft-tls-westerbaan-mldsa` belgesinin yerini almıştır. IETF son çağrısı Mayıs 2026'daydı ve IANA işlemi şu anda beklemede ile inceleme gerekiyor durumundadır.

**IANA TLS imza şeması kod noktaları**, `tls-signaturescheme.csv` dosyasından doğrulanmıştır.

| Onaltılık | İsim | Önerilen | Referans |
|---|---|---|---|
| 0x0904 | mldsa44 | Hayır | `draft-ietf-tls-mldsa-00` |
| 0x0905 | mldsa65 | Hayır | `draft-ietf-tls-mldsa-00` |
| 0x0906 | mldsa87 | Hayır | `draft-ietf-tls-mldsa-00` |
| 0x0907 ile 0x0910 arası | Atanmamıştır | | |
| 0x0911 ile 0x091C arası | `slhdsa_sha2_128s`'ten `slhdsa_shake_256f`'e 12 girdi | Hayır | `draft-reddy-tls-slhdsa-01` |

Kayıt hâlâ sıfırıncı revizyona işaret etmektedir ve RFC'ye yeniden yönlendirilecektir. Tüm post kuantum imza şemaları önerilmeyen olarak işaretlidir.

**TLS'te post kuantum sertifika kimlik doğrulamasını gerçekten sevk edenler.** Cloudflare 29 Temmuz 2026'da kaynak sunuculara post kuantum kimlik doğrulamasının desteklendiğini duyurmuştur. FIPS 204'ün tüm parametre setleri, yani ML-DSA-44, 65 ile 87, doğrulanmış kaynak çekmelerinde, ki ücretsizdir, tüm planlarda ve bölge ile hostname bazında kullanılabilir, ve özel kaynak güven deposunda, ki gelişmiş sertifika yöneticisi gerektirir ve kendi ML-DSA sertifika otoritenizi yüklemenize izin verir, desteklenmektedir. Anahtar anlaşması için X25519MLKEM768 ile eşleştirilmektedir ve Cloudflare ML-DSA-44'ü önermektedir. Haziran 2026'da başlatılmış ve 10 Haziran 2026'da bir BoringSSL güncellemesi bir servis olayına yol açmıştır.

rustls 0.23.44, 7 Eylül 2026, yani dün, şöyle demektedir: "Support for post-quantum secure ML-DSA certificates is now enabled by default in the aws-lc-rs crypto provider." Öncesinde rustls-post-quantum 0.2.3, 16 Temmuz 2025, ML-DSA doğrulaması getirmiş; 0.2.4, 23 Eylül 2025, ML-DSA imzalamasını `aws-lc-rs-unstable` altında getirmiştir.

BoringSSL, ML-DSA imza şeması sabitlerini genel başlık dosyasında taşımaktadır.

Hiçbir kamuya açık web PKI sertifika otoritesi tarayıcıya dönük TLS için ML-DSA sertifikası vermemektedir. Cloudflare'in yol haritası 2025 sonundan itibaren pilot bir yıllık ML-DSA-87 verme sürecini ve donanım güvenlik modülü denetimlerinden sonra yaklaşık 2027'de geniş kullanılabilirliği tarif etmektedir. Tarayıcılar post kuantum sertifika kimlik doğrulaması için hiçbir şey sevk etmemiştir. Bu, bugün tamamen özel PKI ile kaynak sunucuya dönük bir konudur.

### 5. Açık problemler

**İstemci merhabası boyutu, azami iletim birimi ile kemikleşme.** X25519MLKEM768, istemci anahtar payını 1216 bayta çıkarmaktadır, dolayısıyla tipik bir istemci merhabası artık tek bir TCP segmentine ya da QUIC ilk paketine sığmamaktadır. Chrome'un kendi politika metni şöyledir: "devices that do not correctly implement TLS may malfunction when offered the new option. For example, they may disconnect in response to unrecognized options or the resulting larger messages. Such devices are not post-quantum-ready and will interfere with an enterprise's post-quantum transition." Go'nun 1.24 notları doğrudan tldr.fail adresine işaret etmektedir; TCP segmentleri arasına bölünmüş bir istemci merhabasını yeniden birleştiremeyen sunucular el sıkışmanın zaman aşımına uğramasına yol açmaktadır ve Go geçici çözüm olarak `GODEBUG=tlsmlkem=0` sunmaktadır. Cloudflare'in tarihsel çerçevelemesi pq-2025'te şöyledir: bazı ara kutular, yük dengeleyiciler ile diğer yazılımlar istemci merhabasının her zaman tek bir pakete sığdığını zımnen varsaymaktadır; bu, daha önceki NTRU-HRSS denemesini öldüren aynı kemikleşmedir. RFC 10024'ün kendisinde azami iletim birimi, ara kutu veya parçalanma rehberliği yoktur; tam metin bu terimler ile yeniden merhaba için taranmış ve hiçbiri bulunamamıştır. Bu tartışma RFC'de değil implementasyon dokümanlarındadır.

**Ölçülmüş ara kutu kırılması.** pq-2025'ten, Ekim 2025, Cloudflare'den kaynak sunucuya giden bağlantılarda: hızlı yaklaşım, yani post kuantum anahtar payını iyimser sunmak, bağlantıların %0,05'ini kırmaktadır; güvenli yaklaşım, yani grubu ilan edip post kuantum anahtar payı göndermemek ve bir yeniden merhaba turunu kabul etmek, evrensel olarak tolere edilmektedir. Cloudflare uyumluluğun önemli olduğu yerlerde güvenli yöntemi kullanmaktadır.

**Sertifika ile imza boyutu.** ML-DSA-44 imzası 2.420 bayttır, Ed25519'un 64 baytına karşılık; kaynağı Cloudflare'in 9 Temmuz 2026 tarihli yazısıdır. Tam bir post kuantum zinciri bunu yaprak, ara sertifikalar, sertifika şeffaflığı imzalı zaman damgaları ile OCSP boyunca çarpmaktadır. Cloudflare'in aynı yazıdaki pozisyonu şudur: daha iyisi zamanında gelmemektedir, çünkü FN-DSA yaklaşık 2033'te, çok değişkenli şemalar 2034'ten önce değil ve SQIsign 2035'ten önce olası değildir; 2030 ile 2035 arasındaki düzenleyici son tarihlere karşı ML-DSA idare etmek zorundadır. EO 14412, 22 Haziran 2026'da imzalanmıştır ve şunları belirlemektedir: yüksek değerli varlıklar ile yüksek etkili sistemler için post kuantum anahtar tesisi 31 Aralık 2030'a kadar, post kuantum kimlik doğrulaması 31 Aralık 2031'e kadar ve federal yüklenicilerin NIST PQC FIPS'lerine uyumu 31 Aralık 2030'a kadar. Bu, Cloudflare'in post-quantum-eo-2026 yazısındandır; kararnamenin metni çekilmemiştir.

**`draft-ietf-tls-trust-anchor-ids`.** Dördüncü revizyonu 1 Mayıs 2026 tarihlidir. Aktif bir TLS çalışma grubu dokümanıdır ve IESG durumu internet taslağı mevcut şeklindedir, yani henüz son çağrı veya IESG işlemi yoktur. Yazarları Bob Beck (OpenSSL), David Benjamin (Google), Devon O'Brien ile Kyle Nekritz'tir (Meta). Kısa, nesne tanımlayıcısı tabanlı güven çıpası kimlikleri, bir `trust_anchors` uzantısı, yani istemci merhabasında, şifreli uzantılarda, sertifika isteğinde ile sertifikada, bir yeniden deneme mekanizması ile sunucuların güven çıpalarını bant dışı ilan edebilmesi için bir HTTPS ve SVCB DNS servis parametresi tanımlamaktadır. Amacı verimli çoklu sertifika müzakeresi, ara sertifika elemesi, ki yüzlerce ile binlerce bayt tasarruf ettirir, ve daha yumuşak bir post kuantum kök geçişidir. Chrome'da chromestatus özelliği 5132064512540672 numaralı "Trust Anchor Identifiers"tır; durumu önerilmiştir, kilometre taşı atanmamıştır, sahibi dadrian@google.com'dur ve son güncellemesi 8 Mayıs 2025'tir. Sevk edilmemektedir.

**Merkle ağacı sertifikaları.** Çalışma grubu değişmiştir: `draft-davidben-tls-merkle-tree-certs` süresi dolmuştur, son bireysel revizyonu onuncudur ve 22 Ocak 2026 tarihlidir; yeni PLANTS çalışma grubu tarafından, yani PKI, günlükler ile ağaç imzaları grubu tarafından, kabul edilmiştir. Güncel belge `draft-ietf-plants-merkle-tree-certs-05`'tir, 6 Temmuz 2026 tarihlidir ve IESG durumu internet taslağı mevcut şeklindedir. Yazarları David Benjamin, Devon O'Brien, Bas Westerbaan, Luke Valenta ile Filippo Valsorda'dır. Fikri günlüklemenin içine gömüldüğü bir X.509 profilidir: sertifika otoritesi önce günlüğe yazar, sonra ortak imzalar toplar ve sertifika bir dahil edilme kanıtı taşır. Günlük girdileri tam post kuantum anahtarlar ile imzalar yerine özetler tutar ve yer imine göreli sertifikalar güncel istemciler için imzaları tamamen düşürebilir. Cloudflare'in başlatma yazısı blog.cloudflare.com/bootstrap-mtc'dir, 28 Ekim 2025. Cloudflare'in yol haritası ziyaretçiden Cloudflare'e bağlantılarda Merkle ağacı sertifikası tabanlı post kuantum kimlik doğrulamasını 2027 ortasına, Cloudflare One'ı 2028 başına ve tam post kuantumu 2029'a hedeflemektedir.

### Açıkça belirsiz ve çözülmemiş olanlar

1. Canlı Cloudflare Radar Eylül 2026 yüzdesi alınamamıştır. Radar tarayıcı olmayan istemcileri engellemektedir, yani 403 ile bir JavaScript meydan okuması dönmektedir, ve Radar API'si bir jeton gerektirmektedir. Alıntılanabilir en güncel rakam 23 Haziran 2026 tarihli üçte ikiden fazla ifadesidir. Tarayıcısı olan herkes güncel rakamı radar.cloudflare.com/post-quantum adresinden okuyabilir.
2. Firefox'ta varsayılan açık olan sürüm belirsizdir. Firefox 132'nin sürüm notu destek eklendiğini söylemekte, Cloudflare'in zaman çizelgesi Firefox'un Kasım 2024'te varsayılan açık olduğunu söylemektedir. Firefox 132, 29 Ekim 2024'te ve 133, 26 Kasım 2024'te çıkmıştır; Firefox 133 notları post kuantum hakkında bir şey söylememektedir. Varsayılan açık hâlin 132'de geldiğine inanılmaktadır ancak arama olmadan bir Mozilla birincil kaynağından tercih varsayılanı teyit edilememiştir.
3. Chrome 131'in ML-KEM geçiş noktası olduğu, Chrome kurumsal politika açıklamasından çıkarılmıştır; bu açıklama sürüm konusunda otoriterdir ancak bir sürüm notu değildir. chromestatus'ta ayrı bir X25519MLKEM768 girdisi yoktur; eski "X25519Kyber768 key encapsulation for TLS" girdisi, yani 5257822742249472 numaralı M124 kaydı, hiç değiştirilmemiştir.
4. `draft-ietf-tls-mldsa` ile `draft-ietf-tls-mlkem` ikisi de bilgilendiricidir ve bu, protokol kod noktası kayıtları için alışılmadıktır. Bu, ikisi için de Datatracker API'sinden, yani hedeflenen standart seviyesi alanından, doğrulanmıştır, dolayısıyla bir yanlış okuma değildir; ancak çalışma grubu gerekçesi bulunamamıştır.
5. Apple platform güvenliği rehberindeki iOS 26 ile iPadOS 26 veya üstü ifadesinin ötesinde kesin Safari ya da iOS sürümünü adlandıran bir Apple sürüm notu veya güvenlik blogu bulunamamıştır; macOS 26 okunan Apple sayfası tarafından değil Cloudflare tarafından iddia edilmektedir.

Kaynakları IANA TLS parametreleri, RFC 10024, RFC 9846, `draft-ietf-tls-mldsa`, `draft-ietf-tls-mlkem`, `draft-ietf-tls-trust-anchor-ids`, `draft-ietf-plants-merkle-tree-certs`, OpenSSL 3.5 notları ile sürüm stratejisi, Go 1.24 dokümanı, Firefox 132 ile 135 sürüm notları, Apple TLS güvenliği sayfası, Chrome politika listesi, chromestatus, Cloudflare'in pq-2025, post kuantum yol haritası, ML-DSA, kaynak kimlik doğrulaması, radar ile başkanlık kararnamesi ve Merkle ağacı sertifikası yazıları, rustls sürümleri ile BoringSSL'in `ssl.h` dosyasıdır.

---

# Kısım V — Mimari

Çok kiracılık, yüksek erişilebilirlik, yetkilendirme ile oturum mimarisi.
