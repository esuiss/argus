# 9. Anahtar ve sır yönetimi

> `ARGUS.md` §9'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§9 §X` referansları aynı anlamda.



---

### ÖZET — Tek Cümlelik Sonuç

**Her JWT imzası için bir KMS/HSM çağrısı yapan bir IdP, hesap/bölge başına ~1.000 token/sn tavanına çarpar ve aylık ~39.000 USD öder.** Argus'un istediği ölçekte tek çalışan mimari, C bölümünde anlatılan **hibrit (envelope) model**dir: kök anahtar KMS/HSM'de, kısa ömürlü ara imzalama anahtarı bellekte. Bunun kanıtı aşağıdaki gerçek sayılarda.

---

## A) PKCS#11 / HSM — Rust Tarafı

### A.1 `cryptoki` crate — olgunluk ve durum (2026)

crates.io API'sinden bugün çekilen kesin veriler:

| Crate | Sürüm | Son güncelleme | Toplam indirme | Son 90 gün |
|---|---|---|---|---|
| `cryptoki` | **0.12.0** | 2026-01-22 | 2.554.577 | 1.225.938 |
| `cryptoki-sys` | 0.5.0 | 2025-12-19 | 2.875.734 | 1.454.145 |
| `pkcs11` (eski) | 0.5.0 | **2020-04-20** | 760.201 | 49.567 |
| `r2d2-cryptoki` | 0.5.0 | 2026-08-14 | 136.646 | 28.305 |
| `yubihsm` | 0.42.1 | **2023-08-15** | 1.277.973 | 137.886 |

Kaynak: `https://crates.io/api/v1/crates/{cryptoki,cryptoki-sys,pkcs11,r2d2-cryptoki,yubihsm}` (2026-09-08 çekildi). Crate 2021-03-18'de yayınlanmış, 18 sürüm, Apache-2.0.

**Değerlendirme:** `cryptoki` gerçek ve canlı bir projedir. Çeyrek yılda bir sürüm ritmi var, 3 ayda 1,2 milyon indirme. Parsec topluluğu (Arm kökenli) tarafından sürdürülüyor. README'de üretim-hazırlığı beyanı yok ama sürüm/indirme profili olgun.
Kaynak: https://github.com/parallaxsecond/rust-cryptoki (README), https://crates.io/crates/cryptoki

#### CHANGELOG'dan kritik noktalar
Kaynak: https://github.com/parallaxsecond/rust-cryptoki/blob/main/CHANGELOG.md

- **v0.12.0 (Ocak 2026): "Make Session Send"** — oturumlar artık thread sınırlarını geçebiliyor. Argus için doğrudan ilgili: bundan önce oturumu bir tokio task'ına taşımak sorunluydu.
- **v0.11.0 (Aralık 2025):** `Session`'ın ömrü `Pkcs11` nesnesinden ayrıldı. Bu, havuzlama (pooling) yapmayı çok kolaylaştıran bir değişiklik.
- **PKCS#11 3.0 desteği:** "Add support for message-based encryption and decryption (PKCS#11 3.0)" — mesaj tabanlı API ve çok-parçalı (multi-part) işlemler eklendi.
- **PKCS#11 3.2:** profile objects ve validation objects desteği; SLH-DSA mekanizmaları (post-kuantum).
- NIST SP800-108 KDF, HKDF, SHA key generation, vendor-defined mechanisms/attributes.
- `paste` bağımlılığı kaldırıldı (RUSTSEC-2024-0436 nedeniyle) — güvenlik hijyeni açısından iyi sinyal.
- `get_attribute_info_map` artık slice alıyor (kırıcı değişiklik).

**PKCS#11 3.0 durumu (Rust):** Destekleniyor ve aktif genişletiliyor. Bu, Rust ekosisteminde PKCS#11 3.x için pratikte tek ciddi seçenek.

#### Önemli detay: `cryptoki` PIN için `secrecy` kullanıyor
crates.io feature listesinde `"serde": ["secrecy/serde"]` görünüyor — yani crate, PIN'i `secrecy::SecretString` içinde tutuyor. PIN handling tartışması: https://github.com/parallaxsecond/rust-cryptoki/issues/50

#### `cryptoki-rustcrypto` — **[DOĞRULANMADI / MUHTEMELEN YOK]**
- crates.io API'sinde `cryptoki-rustcrypto` / `cryptoki_rustcrypto` **bulunamadı**.
- `https://raw.githubusercontent.com/parallaxsecond/rust-cryptoki/main/Cargo.toml` workspace üyeleri: **sadece `cryptoki` ve `cryptoki-sys`**.
- crates.io'da "cryptoki" araması sonuçları: `cryptoki`, `cryptoki-sys`, `r2d2-cryptoki`, `sequoia-cryptoki` (0.1.1, 2026-07-05), `sequoia-keystore-cryptoki` (0.1.0, 2026-07-05), `sq-cryptoki`, `esteid-cryptoki`, `oxicrypto-adapter-pkcs11`, `oxitls-adapter-pkcs11`.

**Sonuç:** Yayınlanmış bir `cryptoki-rustcrypto` crate'i yok. RustCrypto `signature::Signer` trait köprüsünü Argus'un kendisi yazmalı (zaten ~200 satırlık iş).

#### Alternatif: `kryptering` (Kushal Das)
Signer/Verifier/Decryptor/Encryptor/KeyWrapper/KeyAgreement trait'leri ile hem yazılım (RustCrypto) hem PKCS#11 (SoftHSM2, Kryoptic, gerçek HSM) arka ucu sunuyor. Argus'un istediği soyutlamanın referans tasarımı.
Kaynak: https://github.com/kushaldas/kryptering

### A.2 Pratik entegrasyon zorlukları

#### Oturum yönetimi ve thread güvenliği — çözülmüş problem
**`r2d2-cryptoki` (spruceid, v0.5.0, 2026-08-14)** — r2d2 bağlantı havuzu adaptörü. PIN doğrulaması ve thread-safe oturum yönetimi hazır geliyor. 90 günde 28.305 indirme.
Kaynak: https://github.com/spruceid/r2d2-cryptoki , https://docs.rs/r2d2-cryptoki/latest/r2d2_cryptoki/

`CInitializeFlags::OS_LOCKING_OK` bayrağı ile PKCS#11 kütüphanesinin kendi kilitlemesini OS'a devretmesi sağlanıyor.

**Argus için mimari kural:** HSM oturumu asla `async fn` içinde doğrudan tutulmamalı. Ayrı bir blocking thread pool (`tokio::task::spawn_blocking` veya adanmış bir signer thread) + r2d2 havuzu. `Session: Send` (v0.12.0) bunu mümkün kılıyor ama `Sync` değil — her thread kendi oturumunu almalı.

#### Mekanizma desteği — algoritma matrisi
| Sağlayıcı | ECDSA P-256 | Ed25519/EdDSA | RSA-PSS |
|---|---|---|---|
| SoftHSMv2 | Evet | Evet (derleme sırasında `--enable-eddsa`) | **[DOĞRULANMADI]** |
| YubiHSM 2 | Evet | Evet (EdDSA-25519) | Evet |
| AWS CloudHSM | Evet | HashEdDSA sadece `hsm2m.medium` ve **non-FIPS** modda | Evet |
| Azure Managed HSM | P-256/P-256K/P-384/P-521 | **Listede yok** | Evet |
| AWS KMS | Evet | **Evet** (ECC_NIST_EDWARDS25519) | Evet |

SoftHSMv2: OpenDNSSEC kökenli, Botan 2.0+ veya OpenSSL 1.0+ gerektiriyor, ECC/EdDSA/SHA3 derleme opsiyonlu. Sadece test için değil, üretimde de kullanılıyor (OpenDNSSEC).
Kaynak: https://github.com/softhsm/SoftHSMv2

**AWS CloudHSM HashEdDSA kısıtı çok önemli:** FIPS modunda EdDSA yok. Argus "en güvenli" iddiasındaysa FIPS 140-3 Level 3 + EdDSA aynı anda olmuyor — ES256'ya (P-256) düşmek zorundasınız.
Kaynak: https://docs.aws.amazon.com/cloudhsm/latest/userguide/cloudhsm_cli-crypto-sign-ed25519ph.html

#### Test altyapısı
- **SoftHSMv2** — CI için standart. https://github.com/softhsm/SoftHSMv2
- **Kryoptic** — daha yeni, Rust-tabanlı PKCS#11 token (kryptering tarafından destekleniyor)
- **MockHSM** — `yubihsm` crate'inde donanımsız test için. Uyarı: gerçek YubiHSM2'ye karşı testler **YIKICI** ("DO NOT RUN THEM AGAINST A YUBIHSM2 WHICH CONTAINS KEYS YOU CARE ABOUT"). Kaynak: https://lib.rs/crates/yubihsm

#### `yubihsm` crate riski
Son sürüm **2023-08-15** — 3 yıldır sürüm yok. Yubico'nun resmi projesi değil ("This is NOT an official Yubico project"). Tony Arcieri (iqlusion) sürdürüyor, MSRV 1.67. 90 günde 138k indirme var ama bakımsız. **Argus için tavsiye: `yubihsm` crate yerine `cryptoki` + YubiHSM'in PKCS#11 modülü kullanın.**

#### Nesne handle'ları ve yeniden bağlanma
PKCS#11'de `CK_OBJECT_HANDLE` **oturuma özeldir ve oturum kapandığında geçersizleşir**. Argus tasarımında: anahtarları her zaman `CKA_LABEL` / `CKA_ID` ile arayın, handle'ı önbelleklemeyin ya da önbelleklerseniz oturum yeniden kurulduğunda tam geçersizleştirme yapın. `C_FindObjects` maliyeti her imzaya eklenmemeli — bu yüzden havuzdaki her oturum, kendi handle'ını oturum ömrü boyunca cache'lemeli.

#### HSM'ler arası failover
PKCS#11 standardı failover tanımlamaz. AWS CloudHSM istemcisi kümeyi kendi yönetir (yük dengeleme + yeniden deneme). Thales Luna ve Utimaco için HA grupları sağlayıcı kütüphanesinde. **Argus, kendi failover'ını yazarsa: her HSM için ayrı `Pkcs11` instance + ayrı havuz + circuit breaker.**

### A.3 HSM İMZALAMA PERFORMANSI — GERÇEK SAYILAR

#### YubiHSM 2 (Yubico resmi dokümantasyonu)
Boştaki bir cihazda ortalama gecikmeler:

| İşlem | Süre | İmza/sn |
|---|---|---|
| **ECDSA-P256-SHA256** | **~73 ms** | **~13,7** |
| ECDSA-P384-SHA384 | ~120 ms | ~8,3 |
| ECDSA-P521-SHA512 | ~210 ms | ~4,8 |
| **EdDSA-25519 (32 B)** | **~105 ms** | **~9,5** |
| EdDSA-25519 (64 B) | ~121 ms | ~8,3 |
| EdDSA-25519 (128 B) | ~137 ms | ~7,3 |
| EdDSA-25519 (256 B) | ~168 ms | ~6,0 |
| EdDSA-25519 (512 B) | ~229 ms | ~4,4 |
| EdDSA-25519 (1024 B) | ~353 ms | ~2,8 |
| **RSA-2048** | **~139 ms** | **~7** |

**Kritik mimari kısıt:** Cihaz en fazla **16 eşzamanlı oturum** destekler, ancak **tek thread'lidir** — oturumlar arasında işlemleri **seri** yürütür. Yani 16 oturum açmak throughput'u artırmaz.

Kaynak: https://support.yubico.com/hc/en-us/articles/360021202780-YubiHSM-2-A-load-balanced-design-for-heavy-traffic-environments (doğrudan fetch Yubico portalının CSS hatası nedeniyle başarısız oldu; sayılar Yubico'nun bu resmi destek makalesinin arama indeksinden alındı — **teyit için sayfayı bir tarayıcıda açıp doğrulayın**). Ayrıca teknik veri sayfası: https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf

**Argus için anlamı:** Bir YubiHSM 2, saniyede **~14 JWT** imzalayabilir. Bu bir IdP için tamamen yetersizdir. YubiHSM 2 sadece **kök/ara anahtar** rolü için uygundur (hibrit model).

#### AWS CloudHSM (AWS resmi performans sayfası)
Kaynak: https://docs.aws.amazon.com/cloudhsm/latest/userguide/performance.html

**hsm1.medium:**
| İşlem | 2 HSM | 3 HSM | 6 HSM |
|---|---|---|---|
| RSA-2048 sign | 2.000/sn | 3.000/sn | 5.000/sn |
| EC P-256 sign | 500/sn | 750/sn | 1.500/sn |

**hsm2m.medium:**
| İşlem | 2 HSM | 3 HSM | 6 HSM |
|---|---|---|---|
| RSA-2048 sign | 2.000/sn | 3.000/sn | 5.000/sn |
| **EC P-256 sign** | **3.000/sn** | **4.500/sn** | **7.000/sn** |

Ölçüm koşulu: Java çok-thread'li uygulama, tek `c4.large` EC2 instance üzerinde. AWS "kümenizi yük testine tabi tutun ve bir HSM daha ekleyin" diyor. Aşıldığında "HSMs are busy or throttled" hatası.

**hsm2m.medium ile P-256'da 6× iyileşme (500→3.000)** — yeni nesil donanım. Bu, gerçekten HSM'de imzalamak isteyen bir IdP için tek makul on-prem/bulut-HSM seçeneği.

**hsm2m.medium bilinen sorun:** FIPS 140-3 Level 3 uyumu nedeniyle **login gecikmesi arttı**. Kaynak: https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-hsm2m-medium.html — Argus'un HSM'e yeniden bağlanma senaryolarında bu ciddi bir tail-latency kaynağı.

#### Azure Managed HSM (Microsoft resmi ölçekleme kılavuzu)
Kaynak: https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/scaling-guidance (ms.date: 2025-12-03, güncelleme: 2026-06-12)

Ölçüm yöntemi: "tek partition'lı Managed HSM havuzuna karşı, her istekte aynı anahtar, 5 dakika boyunca sürdürülen ortalama ops/sn."

**RSA (işlem/sn, HSM instance başına, 1 partition):**
| İşlem | 2048 | 3072 | 4096 |
|---|---|---|---|
| **Sign** | **900** | **340** | **150** |
| Verify | 3400 | 3400 | 3700 |
| Decrypt | 1100 | 360 | 160 |
| **Create Key** | **1** | **1** | **1** |

**EC (işlem/sn):**
| İşlem | P-256 | P-256K | P-384 | P-521 |
|---|---|---|---|---|
| **Sign** | **330** | **330** | **160** | **200** |
| Verify | 130 | 130 | 82 | 28 |
| Create Key | 1 | 1 | 1 | 1 |

**Mimari:** Her Managed HSM instance **3 yük-dengeli partition**tan oluşur. Tablodaki sayılar **en az 1 partition** varsayımıyla. Hepsi ayaktaysa **3×'e kadar** çıkabilir. Microsoft "kapasite planlamasında 2 partition varsayın; garanti gerekiyorsa 1 partition ile planlayın" diyor. Abonelik/bölge başına **max 5 HSM instance**, instance başına **5000 anahtar**, anahtar başına **100 versiyon**.

**Dikkat çekici:** Managed HSM kripto işlemlerinde **throttle etmiyor** — donanımın doğal limitine kadar çalışıyor. Ama `Create Key = 1/sn` — **anahtar rotasyonu için ciddi bir darboğaz**.

#### Azure Key Vault (standart vault, Managed HSM DEĞİL) — kötü şöhretli limitler
Kaynak: https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits (ms.date: 2025-07-20, güncelleme: 2026-06-12)

**10 saniyede, vault başına, bölge başına:**

| Anahtar tipi | HSM: CREATE/RELEASE | HSM: diğer tüm işlemler | Yazılım: CREATE | Yazılım: diğer |
|---|---|---|---|---|
| RSA-2048 | 10 | **2.000** (=200 TPS) | 20 | 4.000 (=400 TPS) |
| RSA-3072 | 10 | **500** (=50 TPS) | 20 | 1.000 |
| RSA-4096 | 10 | **250** (=25 TPS) | 20 | 500 |
| ECC P-256 | 10 | **2.000** (=200 TPS) | 20 | 4.000 |
| ECC P-384/P-521/secp256k1 | 10 | 2.000 | 20 | 4.000 |

Kotalar **ağırlıklıdır ve toplamları üzerinden uygulanır**: "RSA-4096 HSM anahtarı kullanmak RSA-2048'e göre 8 kat pahalıdır (2000/250 = 8)". Aşınca **HTTP 429**.

**Abonelik geneli limit = vault limitinin 5 katı.**
**Secret CREATE / Certificate IMPORT / Key IMPORT: birlikte 300 / 10 sn.**

**Argus için:** Azure Key Vault (standart) HSM anahtarıyla en fazla **200 imza/sn per vault**, abonelik genelinde **1.000/sn** (5 vault). Kesinlikle yetersiz.

#### Karşılaştırma noktası: YAZILIMDA imzalama (Cloudflare'in yayınlanmış ölçümü)
Kaynak: https://developers.cloudflare.com/ssl/keyless-ssl/reference/scaling-and-benchmarking/

Donanım: **AWS c5.xlarge** (4 vCPU, 3.0 GHz Intel Xeon Platinum)

| Algoritma | Çekirdek başına | 4 çekirdek toplam (60 sn) | Ortalama işlem süresi |
|---|---|---|---|
| **ECDSA** | **>10.000 imza/sn** | 2.661.570 işlem ≈ **44.359/sn** | **22,543 µs** |
| RSA | ~200 imza/sn | 46.560 işlem ≈ 776/sn | 1,288659 ms |

Cloudflare tavsiyesi: beklenen yükün **2 katını** karşılayacak kadar key server dağıtın.

### A.4 Karşılaştırma Tablosu — İMZA/SN

| Yöntem | ECDSA P-256 imza/sn | Kaynak |
|---|---|---|
| **Rust/Go bellek içi (c5.xlarge, 4 vCPU)** | **~44.000** | Cloudflare |
| AWS CloudHSM hsm2m 6-HSM | 7.000 | AWS |
| AWS CloudHSM hsm2m 2-HSM | 3.000 | AWS |
| Azure Managed HSM (3 partition) | ~990 | Microsoft (330×3) |
| AWS KMS (ECC kotası) | 1.000 (hesap+bölge) | AWS |
| Azure Key Vault HSM (vault başına) | 200 | Microsoft |
| GCP Cloud KMS HSM asimetrik | 50 (bölge başına, eski model) | Google |
| **YubiHSM 2** | **~14** | Yubico |

**Fark: 3 büyüklük mertebesi (1000×).** Bu tablo tek başına Argus'un mimari kararını belirler.

### A.5 Alternatifler: KMIP, Tink, yerel SDK'lar
- **KMIP:** Rust'ta olgun bir KMIP istemcisi bulamadım. **[DOĞRULANMADI]** — KMIP zaten anahtar *yönetimi* protokolü, yüksek hacimli imzalama için tasarlanmadı. Argus için uygun değil.
- **Tink:** Google'ın kütüphanesi; Rust portu (`rust-tink`) topluluk çabası ve bakımı zayıf **[DOĞRULANMADI]**. Tink'in KMS envelope soyutlaması iyi bir *tasarım referansı* ama Rust'ta bağımlılık olarak almayın.
- **Yerel vendor SDK'ları:** Thales Luna, Utimaco'nun C SDK'ları PKCS#11'den daha hızlı olabilir ama Rust FFI + vendor kilidi. `cryptoki` üzerinden PKCS#11 doğru seçim.

---

## B) BULUT KMS ile İMZALAMA — Kotalar, Fiyat, Gecikme

### B.1 AWS KMS — Kotalar (kesin sayılar)
Kaynak: https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html

| Kota | Varsayılan (istek/sn) |
|---|---|
| Simetrik kripto işlemleri | 10.000 (paylaşımlı); **20.000**: us-east-2, ap-southeast-1/2, ap-northeast-1, eu-central-1, eu-west-2; **100.000**: us-east-1, us-west-2, eu-west-1 |
| **RSA kripto işlemleri (Sign/Verify dahil)** | **1.000 (paylaşımlı)** |
| **ECC ve SM2 (Sign/Verify dahil)** | **1.000 (paylaşımlı)** |
| ML-DSA (Sign/Verify) | 1.000 (paylaşımlı) |
| CloudHSM key store | **1.800 — AYARLANAMAZ** |
| External key store | **1.800 — AYARLANAMAZ** |
| GenerateDataKeyPair ECC_NIST_P256 | 100 |
| GenerateDataKeyPair ECC_NIST_EDWARDS25519 | 100 |
| GenerateDataKeyPair RSA_2048 | 20 |
| GenerateDataKeyPair RSA_3072 | 4 |
| GenerateDataKeyPair RSA_4096 | **1** |
| GetPublicKey | 2.000 |
| DescribeKey | 2.000 |
| CreateKey | 5 |
| EnableKeyRotation | 15 |

**Kritik notlar:**
1. **Kota hesap + bölge genelindedir**, tüm principal'lar ve AWS servislerinin sizin adınıza yaptığı çağrılar dahil.
2. **Sign ve Verify aynı kotayı paylaşır.** Argus hem imzalar hem doğrularsa aynı 1.000'i böler.
3. **CloudHSM key store'un 1.800 kotası ayarlanamaz** — "en güvenli" için CloudHSM-backed KMS key seçerseniz, tavan sabittir.
4. Tüm diğer kotalar Service Quotas ile artırılabilir ama AWS üst sınırı yayınlamıyor.
5. **AWS'nin kendi dokümanında tutarsızlık var:** Tablo ECC için 1.000 derken, Singapur örnek paragrafında "up to 500 additional calls per second with RSA asymmetric... plus up to 300 additional with ECC" diyor. Argus planlamasında **muhafazakâr olan (300-500)** rakamı varsayın veya AWS'ye teyit ettirin.

### B.2 AWS KMS — Desteklenen imza algoritmaları
Kaynak: https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html

| Key spec | İmza algoritması |
|---|---|
| RSA_2048/3072/4096 | RSASSA_PSS_SHA_256/384/512 (**tercih edilen**), RSASSA_PKCS1_V1_5_SHA_256/384/512 |
| ECC_NIST_P256 | ECDSA_SHA_256 |
| ECC_NIST_P384 | ECDSA_SHA_384 |
| ECC_NIST_P521 | ECDSA_SHA_512 |
| ECC_SECG_P256K1 | ECDSA_SHA_256 |
| **ECC_NIST_EDWARDS25519** | **ED25519_SHA_512** (MessageType:**RAW**), ED25519_PH_SHA_512 (MessageType:DIGEST) |
| ML_DSA_44/65/87 | ML_DSA_SHAKE_256 (post-kuantum, FIPS 204) |

**Argus için iki önemli sonuç:**
1. **AWS KMS artık Ed25519/EdDSA destekliyor** (RFC 8037 `EdDSA` JWS alg'i). Modern bir IdP için doğru seçim.
2. **ED25519_SHA_512 `MessageType:RAW` gerektiriyor** — yani ön-hash yapamazsınız, **tüm JWT signing input'unu (header.payload)** ağ üzerinden KMS'e göndermek zorundasınız. Büyük claim setlerinde bu, hem gecikme hem bant genişliği maliyeti. ECDSA'da ise digest gönderebilirsiniz (32 bayt). Bu, **EdDSA'yı KMS-per-signature modelinde ECDSA'dan daha pahalı yapar.**
3. ED25519_PH_SHA_512 + DIGEST kullanırsanız **girdi iki kez hash'lenir** (siz bir kez, KMS bir kez) — AWS bunu açıkça uyarıyor.

### B.3 AWS KMS — Fiyatlandırma
Kaynak: https://aws.amazon.com/kms/pricing/

- Her KMS anahtarı: **$1/ay** (saatlik orantılı)
- Standart işlemler: **$0,03 / 10.000 istek**
- **Asimetrik imzalama: $0,15 / 10.000 istek**

**[KISMEN DOĞRULANDI]** — Fiyat sayfasının tam per-key-spec tablosunu çıkaramadım; yukarıdaki iki rakam sayfadaki örneklerden alındı (S3 örneği $0,03; dosya imzalama örneği $0,15). RSA-2048 ile diğer asimetrik spec'ler arasında fiyat farkı olabilir — **satın alma öncesi Pricing Calculator ile teyit edin.**

#### Maliyet matematiği (Argus senaryosu)
Her JWT = 1 KMS Sign çağrısı, $0,15/10.000:

| Token/sn | Günlük istek | Günlük maliyet | Aylık maliyet |
|---|---|---|---|
| 100 | 8.640.000 | $129,60 | **~$3.888** |
| 500 | 43.200.000 | $648 | **~$19.440** |
| **1.000 (AWS ECC kota tavanı)** | **86.400.000** | **$1.296** | **~$38.880** |

Karşılaştırma: **Hibrit modelde** 15 dakikalık ara anahtar ömrü ile günde 96 KMS Sign çağrısı → **ayda ~$0,004**. Yani **10 milyon kat** daha ucuz.

### B.4 GCP Cloud KMS — Kotalar (2026'da model değişti!)
Kaynak: https://docs.cloud.google.com/kms/quotas

**16 Şubat 2026 ÖNCESİ (eski model):**
| Koruma seviyesi | Kota |
|---|---|
| Software-backed | 60.000 QPM = **1.000 QPS** (çağıran proje) |
| HSM simetrik | **500 QPS** / bölge (barındıran proje) |
| **HSM asimetrik** | **50 QPS** / bölge |
| External (Cloud EKM) | 100 QPS / bölge |

**16 Şubat 2026 SONRASI (token tabanlı model):**
| Kota | Değer | Uygulama |
|---|---|---|
| Software usage | 6.000.000 TPM | **soft** |
| HSM usage | 3.000.000 TPM | **soft** |
| External KMS usage | 10.000 TPS | **hard** |

**Asimetrik imzalama token maliyeti (HSM anahtarları):**
| Anahtar tipi | HSM token / işlem |
|---|---|
| RSA-2048 | 1.500 |
| RSA-3072 | 3.500 |
| RSA-4096 | 14.000 |
| **EC P-224 / P-256 / secp256k1** | **4.500** |
| EC P-384 / P-521 | 7.000 |

**Benim türetmem [HESAPLAMA — Google'ın yayınladığı ops/sn rakamı değil]:**
- EC P-256: 3.000.000 TPM ÷ 4.500 = **666 imza/dakika ≈ 11 imza/sn**
- RSA-2048: 3.000.000 ÷ 1.500 = **2.000/dakika ≈ 33 imza/sn**
- RSA-4096: 3.000.000 ÷ 14.000 = **214/dakika ≈ 3,6 imza/sn**

Bu kota **soft-enforced** (yumuşak uygulanır) ve artırılabilir. Ama sıfır noktası korkunç derecede düşük.

**GCP fiyatlandırması: [DOĞRULANAMADI]** — `cloud.google.com/kms/pricing` sayfası fetch sırasında kesildi. Manuel kontrol gerekiyor.

**GCP Cloud HSM vs Software:** Software koruma seviyesi 6× daha yüksek token bütçesi ve zaten 1.000 QPS eski limit. HSM'e geçmek Argus için throughput'u ~20× düşürür.

### B.5 Azure — B.A.3'te verildi
Özet: Key Vault (vault) HSM ECC = **200 TPS/vault**, abonelik geneli 1.000 TPS. Managed HSM P-256 = **330/sn/partition**, gerçekçi olarak 660-990/sn per instance, max 5 instance = ~3.300-4.950/sn.

### B.6 GECİKME (LATENCY) — p50/p99

#### **[BULUNAMADI — UYDURMUYORUM]**
AWS, GCP veya Azure'un asimetrik `Sign` API'si için **yayınlanmış p50/p99 gecikme rakamı bulamadım.** Yaptığım aramalar:
- AWS Security Blog "How to verify AWS KMS signatures in decoupled architectures at scale" (**2021-05-19**, https://aws.amazon.com/blogs/security/how-to-verify-aws-kms-signatures-in-decoupled-architectures-at-scale/) — **hiçbir gecikme/throughput sayısı vermiyor.**
- AWS re:Post sorusu "KMS Signing performance with Asymmetric ECC_NIST_P256 key is slow" (https://repost.aws/questions/QUPEubdAqrSnSLm-38Vjyqpw/) — sayfa HTTP 403 döndü, içerik alınamadı. **Başlık kendi başına bir sinyal: müşteriler ECC_NIST_P256 imzalamayı yavaş buluyor.**

#### Ne söyleyebilirim (kaynaklı)
1. **AWS'nin kendi argümanı:** Yukarıdaki blog, KMS API'sinin şu durumlarda pratik olmadığını açıkça söylüyor: "Your system has low latency or high throughput requirements for signature verification, exceeding AWS KMS API request quotas" ve "You want to optimize costs by minimizing AWS KMS API calls." Önerdiği çözüm: **bir kez KMS'te imzala, public key'i dağıt, yerelde doğrula.**
2. **Cloudflare'in uzak anahtar sunucusu argümanı:** "the additional latency cost corresponds to the round-trip time from the server to the key server, which can be as much as a second if the key server is on the other side of the world." Kaynak: https://blog.cloudflare.com/keyless-delegation/
3. **Bilinen alt sınır:** KMS Sign en iyi ihtimalle bir VPC-içi HTTPS RPC + HSM işlem süresidir. Azure MHSM'in P-256 için 330 ops/sn/partition'ı, tam boru hatlı çalışmada ~3 ms HSM-tarafı servis süresi ima eder (**bu throughput'tan türetilmiş bir alt sınır, gecikme ölçümü DEĞİL** — ikisini karıştırmayın).

**Argus için eylem maddesi:** Kendi bölgenizde, kendi VPC'nizde, `hey`/`vegeta`/`k6` ile 60 saniyelik bir KMS Sign yükü koşturup p50/p95/p99'u ölçün. Bu, mimari kararı vermeden önce yapılacak ilk iştir.

### B.7 SONUÇ: KMS-Per-Signature ile Ulaşılabilir Token Hızı

#### Gerçek matematik

**Senaryo A — Her JWT için bir AWS KMS Sign (ECC P-256):**
- Tavan: **1.000 token/sn** (hesap+bölge, Sign+Verify+DeriveSharedSecret paylaşımlı, ayarlanabilir)
- Bu 1.000/sn, aynı hesaptaki **tüm** ECC KMS anahtar kullanımıyla paylaşılır.
- Maliyet: **~$38.880/ay**
- Token endpoint p99'una **bir tam ağ RTT + HSM süresi** eklenir (ölçülmemiş).
- KMS bölge-içi bir bağımlılıktır → Argus'un availability'si KMS'in availability'sinin altına düşer.

**Senaryo B — GCP Cloud KMS HSM:**
- **~11-50 token/sn** (yeni token modelinden türetildi / eski model). Kota artırımı gerekir.
- Software koruma seviyesinde: 1.000 QPS.

**Senaryo C — Azure Managed HSM:**
- **~660-990 token/sn** per instance (P-256, 2-3 partition), max 5 instance → ~3.300-4.950/sn.
- En iyi bulut-KMS seçeneği ama 5-instance limitinde sabit tavan.

**Senaryo D — AWS CloudHSM hsm2m.medium doğrudan (KMS değil):**
- 6-HSM küme: **7.000 token/sn** (EC P-256). Maliyet: 6 × hsm2m.medium saatlik ücreti — **[fiyat DOĞRULANMADI]**.
- Ama: FIPS modda EdDSA yok, login gecikmesi yüksek.

**Senaryo E — HİBRİT (Argus'un yapması gereken):**
- İmzalama CPU'da: Cloudflare'in ölçümüne göre **~44.000 ECDSA imza/sn / c5.xlarge (4 vCPU)**, ortalama 22,5 µs.
- Gerçekçi JWT serileştirme + tahsis yükü ile bunun **%10-20'si** → düğüm başına **4.000-9.000 token/sn**, yatay ölçeklenebilir.
- KMS çağrısı: sadece ara anahtar rotasyonunda (günde ~100). Kota sorunu yok, maliyet sıfır.
- Token endpoint p99'undan ağ RTT'si **tamamen kalkar**.

**Karar: Hibrit model, 40-4.000× throughput avantajı ve 10⁶× maliyet avantajı sağlar. Tartışma yok.**

---

## C) HİBRİT MODEL — Kim Gerçekten Yapıyor?

Bu, Argus'un en kritik mimari sorusu. İyi haber: bu tam olarak **yerleşik bir endüstri kalıbı**.

### C.1 Cloudflare Delegated Credentials for TLS — En Yakın Analog
Kaynak: https://blog.cloudflare.com/keyless-delegation/

**Bu, Argus'un yapmak istediği şeyin birebir aynısı, TLS bağlamında.**

- Sertifika sahibi **kısa ömürlü bir anahtar** üretir ve onu bir servise **delege eder** ("vekaletname" metaforu): "your server authorizes our server to terminate TLS for a limited time."
- **Maksimum geçerlilik: 24 saat.** Gerekçe açıkça belirtilmiş: "temporary access to a key can enable signing lots of delegated credentials which start far in the future."
- **Tasarım motivasyonu doğrudan gecikmedir:** Keyless SSL'in pull-tabanlı modeli her handshake'te uzak key server'a RPC gerektiriyordu. Delegated Credentials **push-tabanlı**: "periodically push a short-lived authorization key to the server and use that for handshakes."
- X.509 uzantısı ile **opt-in** — kısa süreli anahtar erişimi olan bir saldırganın kötüye kullanmasını engelliyor.
- Standart: `draft-ietf-tls-subcerts-04` (blog yazıldığında).

**Argus'a doğrudan uyarlama:**
| Cloudflare DC | Argus karşılığı |
|---|---|
| Uzun ömürlü sertifika anahtarı (HSM'de) | Kök imzalama anahtarı (KMS/HSM'de) |
| Delegated Credential (≤24 saat) | Ara JWT imzalama anahtarı (bellekte) |
| DC'yi imzalayan long-term key | KMS Sign ile ara anahtarı imzalama/attest etme |
| Edge sunucusu handshake'i yerel yapar | Argus düğümü JWT'yi yerel imzalar |
| Max 24 saat kuralı | Ara anahtar TTL üst sınırı |

### C.2 HashiCorp Vault Seal/Unseal — Envelope Kalıbının Referans Uygulaması
Kaynak: https://developer.hashicorp.com/vault/docs/concepts/seal

Üç katmanlı hiyerarşi:
1. **Encryption Key (keyring)** — storage'daki verinin çoğunu şifreler
2. **Root Key** — keyring'i şifreler
3. **Unseal Key** — root key'i şifreler

**Auto-unseal ile KMS:** KMS **root key'i şifreler ve saklar**. Vault başlarken **bir kez** KMS'e bağlanıp root key'i çözer. Sonrasında tüm kripto işlemleri **yerel keyring** ile yapılır.

> "KMS performs decryption during server startup and when operations requiring recovery key authorization occur (like generating root tokens)."

**Bu tam olarak Argus'un istediği desendir:** KMS başlangıçta/rotasyonda çağrılır, istek başına değil.

Shamir seal (varsayılan): unseal key Shamir Secret Sharing ile paylaşılır; operatörler threshold'a kadar pay girer. Auto-unseal'de operatörler **recovery key** alır.

**Seal Wrap** (Enterprise): hassas değerler için ek şifreleme katmanı — storage kompromizasyonuna karşı derinlemesine savunma.

### C.3 SPIFFE/SPIRE KeyManager — Karşı Örnek (Argus bunu YAPMAMALI)
Kaynak: https://github.com/spiffe/spire/tree/main/doc

Mevcut plugin'ler:
- `plugin_server_keymanager_disk.md` — yerel disk
- `plugin_server_keymanager_memory.md` — bellek
- `plugin_server_keymanager_aws_kms.md`
- `plugin_server_keymanager_gcp_kms.md`
- `plugin_server_keymanager_azure_key_vault.md`
- `plugin_server_keymanager_hashicorp_vault.md`

**aws_kms plugin tasarımı** (https://github.com/spiffe/spire/blob/main/doc/plugin_server_keymanager_aws_kms.md):
- Anahtar çiftleri KMS'te CMK olarak yaratılır ve tutulur; "the private key never leaving KMS"
- **"sign SVIDs as needed"** → **her SVID için bir KMS Sign çağrısı**
- Desteklenen tipler: `rsa-2048`, `rsa-4096`, `ec-p256`, `ec-p384`
- Anahtar hijyeni: Description formatı `SPIRE_SERVER/{TRUST_DOMAIN}`; alias'sız ve **48 saatten eski** anahtarlar silinir; `LastUpdatedDate`'i **2 haftadan eski** alias'lar anahtarlarıyla birlikte budanır; aktif anahtarlarda **6 saatte bir** liveness sinyali yenilenir.

**Ders:** SPIRE, KMS-per-operation seçti. SVID üretim hızında (workload attestation başına, dakikalar/saatler ölçeğinde) bu kabul edilebilir. **JWT issuance hızında değil.** Argus, SPIRE'ın bu kararını kopyalarsa B bölümündeki duvara çarpar.

Ancak SPIRE'ın **anahtar budama disiplinini** (48 saat orphan cleanup, 6 saatlik liveness, 2 haftalık alias budama) doğrudan kopyalayın — üretim-kalitesi anahtar yaşam döngüsü yönetimi.

### C.4 Sigstore Fulcio — Ara CA Kalıbı
Kaynaklar: https://github.com/sigstore/fulcio/blob/main/docs/setup.md , https://docs.sigstore.dev/about/security/

- Fulcio, **offline bir root CA'ya zincirlenen ara CA** olarak çalışır. "The KMS signing backend is primarily meant to be used as an intermediate CA."
- Ara sertifika: **pathlen:0** Basic Constraints (sadece end-entity sertifika verebilir), **~3 yıl ömür** (sık rotasyon gerektirmesin diye).
- Kısa ömürlü code-signing sertifikaları verir, efemer anahtarı OIDC kimliğine bağlar.
- Root anahtar materyali TUF deposu üzerinden yönetilir (`sigstore-root-signing`); GCP KMS timestamping anahtarı: `projects/sigstore-root-signing/locations/global/keyRings/root/cryptoKeys/timestamp`
- "Since the key is short-lived, something is needed to attest that the key and the certificate associated with it was valid at the time the artifact was signed" → **transparency log** (Rekor).

**Argus'a ders:** Kısa ömürlü anahtar kullanıyorsanız, **"o anda geçerliydi" kanıtına** ihtiyacınız var. JWKS'te geçmiş `kid`'leri tutmak + isteğe bağlı bir transparency log bunu sağlar.

### C.5 Let's Encrypt / Boulder — Anahtar Töreni (Key Ceremony)
Kaynak: https://github.com/letsencrypt/boulder/tree/main/cmd/ceremony , https://github.com/letsencrypt/boulder/blob/main/cmd/ceremony/README.md

- `ceremony` aracı sertifikaları ve anahtarlarını üretir.
- Anahtarlar **HSM içinde** üretilir; PKCS#11 modülü + slot ile erişilir; **object label** ile tanımlanır (ör. `"intermediate signing key"` — hem public hem private nesne bu label'la saklanır).
- CSR, HSM'deki anahtarla imzalanır.
- Anahtar tipi: RSA (exponent 65537, `rsa-mod-length` ile modül uzunluğu) veya ECDSA (`ecdsa-curve`).
- Fiziksel erişim ve tüm HSM yönetim işlemleri **çok kişili kontrol** gerektirir. Kaynak: https://jhalderm.com/pub/papers/letsencrypt-ccs19.pdf (CCS 2019 makalesi)

**Argus'a ders:** Kök anahtar töreni için `boulder/cmd/ceremony`'nin config formatını referans alın — yıllardır bir kamu CA'sında üretimde çalışan tek açık kaynak tören aracı.

### C.6 Cloudflare Keyless SSL — Pull Modelinin Maliyeti
Kaynaklar: https://developers.cloudflare.com/ssl/keyless-ssl/reference/scaling-and-benchmarking/ , https://blog.cloudflare.com/geo-key-manager-how-it-works/

- Key server: worker pool modeli — her istemci bağlantısı kendi reader/writer goroutine çiftine sahip, kripto iş global havuzdan çekilen ayrı worker goroutine'lerde. Hedef: "minimize latency while maximizing signing operations per second."
- ECDSA ve RSA için **ayrı worker havuzları** (RSA bir mertebe daha pahalı olduğu için).
- ECDSA **önceden hesaplanmış rastgele değerler** kullanıyor (gecikmeyi düşürmek için).
- Gecikme maliyeti **sadece ilk handshake'te**; TLS Session Resumption private key gerektirmiyor.

**Argus'a ders:** Eğer bir "signing service" ayırırsanız (Argus düğümleri → imza servisi), Cloudflare'in worker-pool + algoritma-başına-havuz + önceden-hesaplama desenini kopyalayın. Ama **JWT'lerde session resumption analoğu yok** — her token yeni imza. Bu yüzden uzak imza servisi TLS'ten daha kötü bir uyum.

### C.7 AWS Encryption SDK — Data Key Caching (Standart Envelope Kalıbı)
Kaynak: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html

- **Caching CMM** (cryptographic materials manager) + local cache, **güvenlik eşikleri** (security thresholds) uygular.
- AWS'nin açık uyarısı: *"Data key caching is an optional feature of the AWS Encryption SDK that you should use cautiously. By default, the AWS Encryption SDK generates a new data key for every encryption operation... In general, use data key caching only when it is required to meet your performance goals. Then, use the data key caching security thresholds to ensure that you use the minimum amount of caching required to meet your cost and performance goals."*
- Güvenlik eşikleri (https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/thresholds.html): **max age**, **max messages encrypted**, **max bytes encrypted**.
- Modern alternatif: **AWS KMS Hierarchical keyring** — ve **AWS Encryption SDK for Rust 1.x** bunu destekliyor. Rust ekosisteminde referans implementasyon olarak incelemeye değer.
- Derin tartışma: https://aws.amazon.com/blogs/security/aws-encryption-sdk-how-to-decide-if-data-key-caching-is-right-for-your-application/

**Argus'a doğrudan uyarlama:** Ara imzalama anahtarınıza **üç eşik birden** koyun:
1. `max_age` — ör. 15 dakika
2. `max_signatures` — ör. 5.000.000 imza
3. Herhangi biri aşılırsa **zorunlu rotasyon**

Bu, AWS'nin tam olarak önerdiği disiplindir ve "sadece zaman tabanlı rotasyon"dan daha güvenlidir.

### C.8 Argus için Somut Hibrit Tasarım

#### Anahtar hiyerarşisi
```
[Kök Anahtar]  — KMS / HSM'de, ASLA dışarı çıkmaz
      │              (ECC_NIST_P256 veya ECC_NIST_EDWARDS25519)
      │  KMS Sign  (günde ~96 çağrı)
      ▼
[Ara İmzalama Anahtarı]  — bellekte üretilir, 15 dk ömür
      │                     kök tarafından imzalanmış bir "attestation" ile
      │  yerel imza (22,5 µs)
      ▼
[JWT'ler]  — saniyede binlerce
```

#### Ne kadar kısa yaşamalı?

Karar için üç girdi:
1. **Bellekten anahtar çalma riski penceresi** — kısa iyi
2. **KMS bağımlılığı / kesinti toleransı** — uzun iyi (KMS 30 dk down olursa Argus çalışmaya devam etmeli)
3. **JWKS yayın gecikmesi** — E bölümündeki matematik

**Önerim: 15 dakika üretim ömrü, 60 dakika hard cap.**
- 15 dk × 4 rotasyon/saat × 24 = 96 KMS çağrısı/gün/lineage
- Cloudflare'in 24 saatlik DC üst sınırından çok daha muhafazakâr
- KMS 45 dakika kesinti yaşasa bile (mevcut anahtarın hard cap'ine kadar) Argus token vermeye devam eder
- **Kritik kural:** Ara anahtar TTL'i **her zaman** verilen access token TTL'inden uzun olmalı, yoksa henüz geçerli tokenlar için doğrulama anahtarı JWKS'ten kalkar.

#### JWKS'te nasıl yayınlanır / attest edilir?

**Seçenek 1 (basit, önerilen):** Ara anahtarın public kısmı doğrudan JWKS'e `kid` ile eklenir. Kök anahtar JWKS'te **görünmez** — sadece bir out-of-band trust anchor.
- Artı: standart OIDC, hiçbir istemci değişikliği gerekmez
- Eksi: kök anahtarın delegasyonu doğrulanamaz; JWKS endpoint'i kompromize olursa saldırgan kendi anahtarını ekleyebilir

**Seçenek 2 (Cloudflare DC benzeri, "en güvenli"):** JWKS girdisine, kök anahtarla imzalanmış bir delegation attestation eklenir (`x5c` zinciri veya özel bir `x-argus-delegation` alanı):
```
attestation = KMS.Sign(root_key, CBOR{ kid, jwk_thumbprint, not_before, not_after, issuer })
```
- Artı: JWKS endpoint kompromizasyonu tek başına yetmez; istemci kök anahtara pin'lenebilir
- Eksi: standart-dışı; genel istemciler yok sayar. **Ama zarar vermez** ve yüksek-güvenlikli istemciler (kendi SDK'nız) doğrulayabilir.

**Argus "en güvenli" iddiasındaysa Seçenek 2'yi ekleyin — Seçenek 1'in üstüne, kırıcı olmayan bir alan olarak.**

#### Anahtar töreni (key ceremony)
- Kök anahtar KMS/HSM içinde üretilir, asla export edilmez (`boulder/cmd/ceremony` deseni)
- Çok kişili kontrol (AWS: KMS key policy + MFA'lı ayrı IAM principal'lar; HSM: M-of-N kartlar)
- Töreni videoya kaydedin, tanık imzalı tutanak tutun (Let's Encrypt/WebTrust pratiği)
- Kök anahtar rotasyonu: yılda 1 veya hiç (Fulcio ara CA'sı 3 yıl)

#### Hata modları ve karşılıkları

| Hata modu | Sonuç | Karşılık |
|---|---|---|
| **KMS erişilemez, rotasyon zamanı geldi** | Yeni ara anahtar üretilemez | Hard cap'e kadar mevcut anahtarla devam; hard cap yaklaşırken alarm; degraded mode'da uzatılmış TTL ile ikinci bir önceden-imzalanmış anahtar hazır tut |
| **Argus düğümü çöker, ara anahtar kaybolur** | Bellekteki anahtar gider | Sorun değil — yeniden başlarken yeni anahtar üretir. **Ama** düğümler arası anahtar paylaşımı yapıyorsanız (aynı kid), koordinasyon gerekir |
| **Her düğüm kendi ara anahtarını üretir** | JWKS'te N × anahtar | Kabul edilebilir ve aslında **daha güvenli** (blast radius küçülür). JWKS boyutunu izleyin; 50+ anahtar olmasın |
| **Ara anahtar bellekten çalınır** | Saldırgan TTL boyunca sahte token üretir | TTL'i kısaltmak tek savunma. + F/G bölümü |
| **Saat kayması** | `not_before`/`not_after` hataları | NTP zorunlu; attestation'da ±5 dk tolerans |
| **Split-brain: iki düğüm aynı kid'i üretir** | Doğrulama kaosu | `kid` = JWK thumbprint (RFC 7638) → çakışma matematiksel olarak imkânsız |
| **JWKS yayını yeni anahtardan geç kalır** | `kid` bilinmiyor → doğrulama hatası | **Publish-before-use kuralı** (E bölümü) |
| **Rotasyon fırtınası** (tüm düğümler aynı anda) | KMS throttle | Rotasyon zamanına jitter ekleyin (±%20) |

---

## D) HashiCorp Vault Transit Engine

### D.1 IdP için uygun mu?

**Kısa cevap: Ara anahtar sarmalayıcı (wrapper) olarak evet, per-JWT imzalayıcı olarak hayır.**

### D.2 Yetenekler
Kaynak: https://developer.hashicorp.com/vault/docs/secrets/transit , https://developer.hashicorp.com/vault/api-docs/secret/transit

**Desteklenen imza anahtarı tipleri:**
- **Ed25519** ("supports signing, signature verification, and key derivation")
- **ECDSA P-256, P-384, P-521**
- **RSA-2048, RSA-3072, RSA-4096**
- ML-DSA, hibrit algoritmalar, SLH-DSA (**sadece Enterprise**)

**`batch_input` desteği — kritik throughput kaldıracı:**
```json
{ "batch_input": [
    {"input": "adba32==", "context": "abcd", "reference": "jwt-1"},
    {"input": "aGVsbG8=", "context": "efgh", "reference": "jwt-2"}
]}
```
Sonuçlar `batch_results` dizisinde **giriş sırası korunarak** döner. `reference` alanı ile eşleme yapılır. Bu, HTTP + auth overhead'ini N imzaya amorti eder — Argus bir token-endpoint batch'i topluyorsa gerçek bir kazanç.

**Versiyonlama / rotasyon yerleşik:**
- `key_version` (int, 0 = latest); `>= min_encryption_version` olmalı
- `min_encryption_version` / `min_decryption_version` key config endpoint'inde
- Vault uyarısı: *"frequent rotation may lead to a storage entry size for the archive that is larger than the storage backend can handle"* (Raft/Paxos gibi backend'lerde) — çözüm olarak **zaman-tabanlı anahtar isimlendirme** öneriliyor.

**Diğer limitler:** Max HTTP request boyutu **32 MB** (DoS önlemi).

### D.3 Gerçek benchmark sayıları

#### HashiCorp'un resmi benchmark blogu (2026-07-16)
Kaynak: https://www.hashicorp.com/en/blog/understanding-vault-performance-benchmarks-from-real-world-workloads

**Ortam:** AWS us-west-2, **Vault Enterprise v1.17.3+ent**, integrated Raft storage, yük aracı **k6**, metrikler **Datadog**.

| Bulgu | Sayı |
|---|---|
| PKI sertifika verme, tek kullanıcı baseline | **~560 ms** |
| PKI knee point | ~25 eşzamanlı kullanıcı |
| PKI revocation timeout başlangıcı | 100+ eşzamanlı kullanıcı |
| SSH-CA **RSA-2048** knee point | ~100 sanal kullanıcı (VU) |
| SSH-CA RSA-2048 doygunlukta CPU | **%92-96** |
| SSH-CA RSA-2048 doygunluk | ~250 VU |
| SSH-CA **ED25519** knee point | **~200 VU** |
| SSH-CA ED25519 doygunlukta CPU | **%40-42** |
| PKI algoritma karşılaştırması | "minimal performance differences across RSA, ED25519, and ECDSA" |

**HashiCorp bu blogda transit sign için ops/sn YAYINLAMIYOR.** Bunu açıkça belirtiyorum.

**Ama PKI'nin 560 ms'lik tek-kullanıcı baseline'ı çok şey söylüyor:** Vault'un HTTP + policy + audit + storage yolu ağır. Transit sign daha hafif olsa da, **22,5 µs'lik yerel ECDSA imzayla kıyaslanamaz** — en az 3 büyüklük mertebesi fark.

**ED25519'un RSA'ya göre 2× concurrency ve yarı CPU avantajı** — Argus Vault kullanacaksa Ed25519 seçmeli.

#### "37k ops/sn" iddiası — **[DOĞRULANMADI]**
Bu rakam Stenio Ferreira'nın (HashiCorp Solutions Engineer) Medium yazısında geçiyor: https://medium.com/hashicorp-engineering/hashicorp-vault-performance-benchmark-13d0ea7b703f — **sayfa fetch sırasında HTTP 403 döndürdü, doğrulayamadım.** Ayrıca arama snippet'ine göre bu "highly favorable test environment"da transit **genel** (muhtemelen encrypt/decrypt) içindi, **sign değil.** Argus planlamasında bu sayıyı kullanmayın.

#### Benchmark araçları
- **`vault-benchmark`** (HashiCorp resmi, açık kaynak): auth method'ları ve secrets engine'leri yükler; HTTP isteklerini **Vegeta** kütüphanesiyle üretir; throughput/latency/success rate ölçer.
  - Repo: https://github.com/hashicorp/vault-benchmark , DeepWiki: https://deepwiki.com/hashicorp/vault-benchmark
  - Tutorial: https://developer.hashicorp.com/vault/tutorials/operations/benchmark-vault
- Topluluk: `wrk` tabanlı transit throughput testi — https://github.com/jdfriedma/Vault-Transit-Load-Testing
- HashiCorp Raft tuning: https://support.hashicorp.com/hc/en-us/articles/4406933742099-Initial-Research-for-Vault-Integrated-Storage-Performance-Tuning

**Vault dokümanının kendi uyarısı:** *"The transit secret engine (encryption as a service) is one of the most taxing operations on a Vault server, since it requires the server to run the encryption algorithm."*

### D.4 HA
Vault HA: aktif/standby (integrated Raft). Performance Standby (Enterprise) okuma ölçekler. **Transit sign bir yazma değil ama aktif node'a gider** [DOĞRULANMADI — Performance Standby'ların transit sign'ı servis edip edemediğini teyit edemedim]. Argus için: tek aktif node darboğazı riski var.

### D.5 Lisans değişimi ve OpenBao

**Vault → BUSL 1.1, Ağustos 2023.** OpenBao, Vault'un OSS sürümünün topluluk fork'u olarak 2023'te yaratıldı ve **Linux Foundation'a bağışlandı** (açık yönetişim). **Haziran 2025'te OpenSSF sandbox projesi** oldu.

#### OpenBao 2026 durumu — gerçek sürüm verisi
Kaynak: https://github.com/openbao/openbao/releases

| Sürüm | Tarih |
|---|---|
| **v2.6.2** | **2026-08-18** (güvenlik düzeltmeleri + hata düzeltmeleri) |
| v2.6.1 | 2026-07-22 |
| v2.6.0 | 2026-07-14 (namespace sealing, workflow desteği) |
| v2.6.0-beta | 2026-06-22 |
| v2.5.5 | 2026-06-17 (çoklu güvenlik açığı düzeltmesi) |

- 2.0 "production-ready" sürümü: **Eylül 2024**
- **Namespaces** ve **horizontal read scalability** eklendi — Vault Enterprise'ın ücretli özelliklerini açık kaynağa taşıyor
- **8 şirket** ticari destek sunuyor (ControlPlane dahil)
- **NVIDIA OpenBao'yu benimsedi** — Kaynak: https://www.techtarget.com/searchitoperations/news/366644831/Nvidia-adopts-OpenBao-open-source-fork-of-HashiCorps-Vault

**Değerlendirme:** OpenBao 2026'da **canlı ve ciddi** bir proje. Aylık sürüm ritmi, LF yönetişimi, NVIDIA gibi bir referans, Vault'un kapalı özelliklerini açıyor. Argus için Vault yerine OpenBao makul — özellikle Argus kendisi açık kaynaksa BUSL bulaşmasından kaçınmak için.

**Ama:** Üçüncü parti araç ekosistemi hâlâ Vault'un gerisinde. Ve Argus'un asıl ihtiyacı ara anahtar sarmalama olduğu için **her ikisi de opsiyonel bir bileşen** — bulut KMS zaten yeter.

### D.6 Argus'ta Vault/OpenBao'nun yeri

| Kullanım | Uygun mu? |
|---|---|
| Her JWT için transit sign | **HAYIR** — 3 mertebe yavaş, tek node darboğazı |
| Ara anahtarı sarmalama/açma (envelope) | **EVET** — dakikada birkaç çağrı |
| DB şifreleri, OAuth client secret'ları saklama | **EVET** — klasik kullanım |
| Argus'un TLS sertifikaları (PKI engine) | **EVET** ama 560 ms baseline'a dikkat, önceden verin |
| Argus düğümlerinin kimlik doğrulaması (AppRole/K8s auth) | **EVET** |

---

## E) ANAHTAR ROTASYONU (JWKS)

### E.1 Standart dayanağı

**RFC 7517 (JWK) §4.5 — `kid` parametresi:**
> "The 'kid' (key ID) parameter is used to match a specific key. This is used, for instance, **to choose among a set of keys within a JWK Set during key rollover**."

> "When 'kid' values are used within a JWK Set, **different keys within the JWK Set SHOULD use distinct 'kid' values**."

`kid` büyük/küçük harf duyarlıdır ve **opsiyoneldir** (ama Argus için zorunlu yapın). JWS/JWE'deki `kid` header parametresiyle eşleşir.
Kaynak: https://datatracker.ietf.org/doc/html/rfc7517

**Öneri:** `kid` = **RFC 7638 JWK Thumbprint** (SHA-256). Böylece çakışma imkânsız, deterministik, ve anahtar materyalinden türetildiği için ayrı bir kayıt tutmaya gerek yok.

**OpenID Connect Core §10.1.1 "Rotation of Asymmetric Signing Keys":** RP, ID Token doğrularken `kid` header'ına bakar; anahtar yerel cache'de yoksa `jwks_uri`'yi **yeniden çeker**. Bu, kesintisiz rotasyonun temel mekanizmasıdır.
Kaynak: https://openid.net/specs/openid-connect-core-1_0.html **[Bu bölümün tam metnini fetch edemedim — sayfa kesildi. Yukarıdaki, ikincil kaynaklardan yapılmış bir özettir; spec metnini doğrudan doğrulayın.]**

### E.2 Gerçek sağlayıcılar ne yapıyor?

#### Okta — yayınlanmış rotasyon periyodu
Kaynak: https://developer.okta.com/docs/concepts/key-rotation/

> **"The current Okta key rotation schedule is four times a year, but can change without notice."** (üç ayda bir)

> **"New keys are normally generated a few weeks before the rotation occurs to ensure that downstream customer caching mechanisms are updated."**

> İstemciler `jwks_uri` yanıtını **"following the directives in the standard HTTP Cache-Control headers"** cache'lemeli.

Okta cache süresini rotasyona olan yakınlığa göre **dinamik olarak ayarlıyor**. Anahtarların JWKS'te rotasyondan sonra tam olarak ne kadar kaldığını yayınlamıyor.

**Öne çıkan:** Okta, yeni anahtarı kullanmadan **haftalar önce** yayınlıyor. Bu, "publish-before-use" kuralının en muhafazakâr uygulaması.

#### Auth0 — 3-anahtar modeli
Kaynak: https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys

> "The OIDC discovery document will always include both the **current key** and the **next key**, and it may also include the **previous key** if the previous key has not yet been revoked."

- Aynı anda **tek anahtarla** imzalanır
- Önceki anahtarla imzalanmış tüm token'lar, **siz onu açıkça revoke edene kadar** geçerli kalır
- Otomatik rotasyon aralığı belirtilmemiş; manuel rotasyon vurgulanmış

**Bu, Argus için doğrudan kopyalanabilir bir model:** JWKS = `{previous?, current, next}`.

#### Keycloak — active/passive
Kaynak: https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/realms/keys.adoc

- **Bir anda tek aktif** anahtar çifti, **birden çok pasif** anahtar
- Aktif anahtar yeni imzalar üretir; pasif anahtar önceki imzaları doğrular → **kesintisiz rotasyon**
- Provider'lar **Priority** alanıyla sıralanır; en yüksek öncelikli, aktif anahtar sağlayabilen provider seçilir
- Eski anahtarlar süreleri dolana kadar JWKS endpoint'inde kalır
- **Varsayılan anahtar ömrü: [DOĞRULANMADI]** — eriştiğim kaynaklarda `rsa-generated` provider'ın varsayılan lifespan'ı yoktu

#### Google — canlı kanıt
Bugün (2026-09-08) `https://www.googleapis.com/oauth2/v3/certs` çekildi: **4 anahtar**, hepsi RSA / RS256:
```
a8f80b512469959cdc1eeba44b066c2f79944779
ca622895d4d408c1b1089f874a0fa07bbc04b55e
943a3a5d7d919625a454e489b75c29adab57acba
f10f87405a979c1df36df26606734f33cd85c271
```
Google aynı anda **4 anahtar** yayınlıyor — geniş bir overlap penceresi tutuyorlar. (Google'ın rotasyon periyodunu yayınlamadığını not edeyim; bu sadece anlık gözlem.)

#### Duende IdentityServer — timing önerisi
Kaynak: https://duendesoftware.com/blog/20260113-why-signing-key-rotation-matters-in-openid-connect-and-duende-identityserver (2026-01-13)

Yeni anahtar JWKS'e eklenir ama **henüz imzalamada kullanılmaz** → istemciler keşfedip cache'ler → **duyuru periyodu (genelde 24-48 saat)** sonra yeni anahtarla imzalamaya başlanır → eski anahtar doğrulama için kalır.

#### Zalando — rotasyon formülü
Kaynak: https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html

> **"Time of key retirement + Maximum token lifespan + Extra safety time = Time to drop the public key"**

Süreç:
1. Yeni anahtar çifti üret
2. Public key'i JWK endpoint'inde yayınla
3. İstemci cache yenilemesi için **grace period**
4. Yeni anahtarı **aktif imzalayıcı** yap
5. Önceki aktif anahtarı **emekliye ayır** (yayında kalır)
6. **Max token ömrü** kadar sonra JWKS'ten kaldır

Vurgu: **"cache control headers matter!"** ve JWT'lerde `kid` ile hangi anahtarın kullanıldığı takip ediliyor.

### E.3 Kesin Zamanlama Matematiği (Argus için)

#### Tanımlar
- `T_token` = verilen en uzun token TTL'i (access token; ID token dahil)
- `T_cache` = `jwks_uri` üzerindeki `Cache-Control: max-age` değeri
- `T_client` = en yavaş istemcinin JWKS yenileme periyodu (kontrolünüz dışında!)
- `T_safety` = güvenlik marjı
- `T_sign` = bir anahtarın aktif imzalama süresi (Argus'ta ara anahtar TTL'i)

#### Kural 1 — PUBLISH-BEFORE-USE (yayınla, sonra kullan)
```
T_publish_lead ≥ T_cache + T_client + T_safety
```
Yeni `kid` ile **ilk token imzalanmadan önce**, o anahtarın JWKS'te bu kadar süre bulunmuş olması gerekir.

**Ama Argus'ta ara anahtar 15 dakikada bir dönüyor.** Bu, klasik "48 saat önce yayınla" yaklaşımıyla **uyumsuz**. Çözüm iki katmanlı:

#### Argus'un iki katmanlı rotasyon şeması

**Katman 1 — Ara anahtarlar (hızlı, 15 dk):**
`T_publish_lead`'i sağlamak imkânsız (15 dk < tipik cache TTL'leri). Bu yüzden:
- `jwks_uri` üzerinde **`Cache-Control: max-age=300, must-revalidate`** (5 dk) — kısa tutun
- **`ETag`** verin, `If-None-Match` ile 304 dönün (bant genişliği maliyeti neredeyse sıfır)
- İstemcilere **"unknown kid → refetch"** davranışını zorunlu kılın (OIDC §10.1.1 zaten bunu söylüyor). Argus kendi SDK'sını yayınlıyorsa bunu SDK'da uygulayın.
- **Yeni ara anahtarı, kullanmaya başlamadan `T_cache + T_safety` = 5 + 5 = 10 dakika önce JWKS'e ekleyin.** Yani anahtar üretimi ile ilk kullanım arasında 10 dakikalık bir "warm-up" penceresi olur. 15 dakikalık rotasyon periyoduyla bu, **her zaman 2-3 anahtarın JWKS'te olduğu** anlamına gelir.
- **Kaldırma zamanı:** `T_sign_end + T_token + T_safety`. `T_token` = 15 dk (kısa access token) ise: son imzadan 15 + 5 = **20 dakika sonra** JWKS'ten çıkar.
- **JWKS'teki toplam anahtar sayısı ≈ (10 dk warm-up + 15 dk aktif + 20 dk drain) / 15 dk ≈ 3 anahtar** — makul.

**Katman 2 — Kök anahtar (yavaş, yıllık):**
- Okta/Duende modeli: yeni kök anahtarı **haftalar önce** yayınla (delegation attestation'ı doğrulayan istemciler için)
- Fulcio deseni: 3 yıl ömür, sık rotasyon gerektirmeyen

#### Kural 2 — Kaldırma (drop) zamanı
```
T_drop = T_last_signature_with_key + T_token_max + T_safety
```
Zalando'nun formülü. **`T_token_max`'ı kesinlikle bilmeniz gerekir** — Argus'ta refresh token'lar imzalıysa onlar da sayılır!

#### Kural 3 — En yavaş doğrulayıcıya göre planla
> "If one service refreshes every 5 minutes, another every hour, and a mobile client every app launch, the grace period has to reflect the slowest verifier."

**Argus için:** `T_client`'ı bilemezsiniz. Bu yüzden **"unknown kid → refetch"** davranışını zorunlu kılan negatif-cache'li bir tasarım şart. Ayrıca `jwks_uri`'ye **rate limit** koyun (kötü niyetli refetch fırtınası DoS'a döner) ama 429 yerine stale-while-revalidate verin.

#### Kural 4 — Token TTL'i, ara anahtar TTL'inden KISA olmalı
```
T_token < T_sign
```
Aksi halde bir token, imzalandığı anahtar JWKS'ten kalkmadan önce süresi dolmaz. Argus'ta: 15 dk anahtar → access token **≤ 10 dakika** olmalı (marjla).

#### Cache-Control önerisi (Argus)
```
Cache-Control: public, max-age=300, stale-while-revalidate=600, stale-if-error=86400
ETag: "<jwks-set-hash>"
```
- `stale-if-error=86400`: Argus'un JWKS endpoint'i çökerse istemciler 24 saat eski setle çalışır → **availability kazancı**
- `stale-while-revalidate`: arka planda yenileme, istemci gecikmesi yok

### E.4 Otomatik Rotasyon Tasarımı — Argus State Machine

Her ara anahtar için durum makinesi:
```
PENDING ──(JWKS'e eklendi)──► PUBLISHED ──(warm-up 10dk doldu)──► ACTIVE
                                                                     │
                                                          (15 dk veya 5M imza)
                                                                     ▼
                                                                 RETIRING
                                                                     │
                                                     (T_token + safety = 20 dk)
                                                                     ▼
                                                                  DROPPED
```

- **Aynı anda tam 1 ACTIVE anahtar** (düğüm başına veya küme başına — karar verin)
- **PUBLISHED ve RETIRING anahtarlar JWKS'te**, ACTIVE olan da
- **DROPPED anahtar materyali `zeroize` edilir** (F bölümü)
- Geçişler bir **audit log**'a yazılır (kid, thumbprint, timestamps, KMS attestation id)
- Her geçişte metrik: `argus_jwks_keys{state="active|published|retiring"}`

**Küme-genelinde tek anahtar mı, düğüm başına mı?**

| | Küme-geneli tek anahtar | Düğüm başına anahtar |
|---|---|---|
| JWKS boyutu | 3 anahtar | 3 × N düğüm |
| Koordinasyon | Gerekli (leader election / etcd) | **Yok** |
| Blast radius | Tüm küme | **Tek düğüm** |
| KMS çağrısı | 96/gün | 96 × N/gün |
| Karmaşıklık | Yüksek | **Düşük** |

**Önerim: Düğüm başına anahtar.** N=10 düğümde JWKS'te ~30 anahtar olur; bu bir sorun değil (JWKS ~10 KB). Koordinasyon yokluğu ve küçük blast radius, "en güvenli" hedefiyle uyumlu. N büyürse (>30 düğüm) shard başına anahtara geçin.

---

## F) RUST'TA BELLEK-İÇİ SIR HİJYENİ

### F.1 `zeroize` — mekanizma ve GERÇEK garantiler

**Sürüm: 1.9.0**, crates.io `updated_at: 2026-06-12`. **672.831.052 toplam indirme, son 90 günde 168.883.175.** (Not: docs.rs sayfası "released September 3, 2026" gösteriyor — crates.io API'siyle çelişiyor; crates.io'yu esas alın.) `zeroize_derive` 1.5.0, 90 günde 64.227.400 indirme.
Kaynaklar: https://docs.rs/zeroize/latest/zeroize/ , https://crates.io/api/v1/crates/zeroize , https://github.com/RustCrypto/utils/tree/master/zeroize

#### Nasıl çalışır
- `core::ptr::write_volatile` + `core::sync::atomic` bellek bariyerleri
- **Saf Rust** — FFI yok, assembly yok
- Tüm core sayı tiplerinde ve slice'larında

#### NE GARANTİ EDER
> "the zeroing operation **can't be 'optimized away' by the compiler**, as ensured by LLVM's volatile semantics."

Volatile ve non-volatile erişimleri karıştırmanın UB olup olmadığı endişesi **Unsafe Code Guidelines Working Group** içinde tartışıldı ve bu crate'teki kullanım deseni **well-defined** kabul edildi.

#### NE GARANTİ ETMEZ (docs.rs'deki açık ifadeler)
1. **Mikromimari saldırılar:** "There is still potential for microarchitectural attacks (ala Spectre/Meltdown) to leak 'zeroized' secrets through covert channels... this crate makes no guarantees that zeroized values cannot be leaked through such channels, as they represent flaws in the underlying hardware."
2. **`Vec`/`String`/`CString`:** Backing buffer'ın **tüm kapasitesini** sıfırlar, **ama önceki yeniden-tahsislerin (reallocation) kopyalarını garanti edemez.** → **Doğru kapasiteyle initialize edin ve sonradan realloc'u engelleyin.**
3. **Stack spilling:** "heap data may leave temporary copies on stack via Rust move semantics"
4. **Register temizleme:** **Kapsam dışı** — "requires inline ASM or rustc support"

#### `Zeroizing<Z>`
`Deref`/`DerefMut` implement eden generic wrapper; drop'ta `zeroize()` çağırır. İçinde sır tutan **rastgele tipler** için.

#### `#[derive(ZeroizeOnDrop)]`
Marker trait + custom derive. "Recommended for types always containing secrets that need complex invariant maintenance."

### F.2 Assembly-seviyesinde doğrulama — somut kanıt

CipherStash blog yazısı, **2024-01-09**: "Verifying Rust Zeroize with Assembly...including portable SIMD"
Kaynak: https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd

**Bulgular:**
1. `#[derive(Zeroize, ZeroizeOnDrop)]` ile ARM64 disassembly'de `strb wzr` (sıfır yazma) komutları **doğrulandı** — zeroize gerçekten çalışıyor.
2. **Elle yazılmış naif `Drop` implementasyonu:** `[u8; 4]` için derleyici **sıfırlama kodunu tamamen sildi** ("For some reason the compiler decided that our code to zeroize was irrelevant and optimized it away"). **Aynı kod `[u32; 4]` için çalıştı.** → Tip değişikliği optimizasyon davranışını değiştiriyor; elle zeroization öngörülemez.
3. **Portable SIMD (`Simd<u16, 8>`):** Durum daha kötü — derleyici Drop implementasyonunu **tamamen yok saydı**. zeroize crate'inin (o tarihte) portable SIMD desteği yoktu.
4. Çözüm: `ptr::write_volatile()` + `compiler_fence()`. İronik olarak "bellek güvenliği için `unsafe` gerekiyor".

**Argus için ders:** **Asla elle zeroization yazmayın.** `zeroize` kullanın ve SIMD tipleri içeren yapılarda ekstra dikkatli olun.

### F.3 `secrecy` — ne yapar, ne yapmaz

**Sürüm: 0.10.3**, crates.io `updated_at: 2024-10-09`. **156.698.098 toplam, 37.989.495 son 90 gün.**
Kaynak: https://docs.rs/secrecy/latest/secrecy/

#### Sağladıkları
- **`SecretBox<T>`** — çekirdek wrapper (parolalar, kripto anahtarlar, access token'lar)
- **`SecretString`** = `SecretBox<str>` type alias
- **`SecretSlice<T>`**
- **`ExposeSecret` / `ExposeSecretMut`** trait'leri — "make secret access explicit and easy-to-audit"
- **Redakte eden `Debug` impl** — kazara debug loglamayı engeller

#### AÇIKÇA YAPMADIKLARI
> "this crate favors a simple, `no_std`-friendly, safe i.e. **`forbid(unsafe_code)`**-based implementation and **does not provide more advanced memory protection mechanisms e.g. ones based on `mlock(2)`/`mprotect(2)`**."

Dokümanı gelişmiş koruma için **`secrets` crate'ine** yönlendiriyor.

`zeroize ^1.6`'ya bağımlı; opsiyonel `serde` desteği (sır deserialization için).

#### 0.10.0 kırıcı değişiklikleri (2024-09-17) — 0.9.0 atlandı
Kaynak: https://github.com/iqlusioninc/crates/blob/main/secrecy/CHANGELOG.md

**Kaldırılanlar:**
- **Generic `Secret<T>` kaldırıldı** → `SecretBox<T>` kullanın
- `alloc` feature'ı kaldırıldı (artık zorunlu bağımlılık)
- `bytes` crate entegrasyonu kaldırıldı
- **`DebugSecret` trait'i kaldırıldı**
- **`SecretVec` kaldırıldı** (stack-tabanlı depolamanın kaldırılmasının sonucu)

**Eklenenler:**
- `SecretBox` artık **type alias değil, newtype**
- `SecretSlice<T>`
- `SecretBox::init_with`, `try_init_with`, `init_with_mut`
- MSRV 1.60, Rust 2021 edition
- `SecretString` = `SecretBox<str>` type alias

**En önemli mimari değişiklik:** Sırlar artık **stack'te değil heap'te** saklanıyor → heapless `no_std` desteği bitti. Ama bu aslında **güvenlik açısından iyi**: heap'teki sır, move semantiği ile stack'te kopya bırakmaz (sadece pointer taşınır).

**Argus için:** `secrecy 0.10.x` kullanın. `cryptoki`'nin de PIN için bunu kullandığını unutmayın — sürüm çakışması olmasın.

### F.4 GERÇEK LİMİTLER — Neden `zeroize` + `secrecy` Yeterli Değil

Bu, Argus'un "en güvenli" iddiası için en dürüst bölüm.

| # | Sızıntı vektörü | Neden zeroize çözmez | Gerçek karşılık |
|---|---|---|---|
| 1 | **Derleyici optimizasyonu değeri kopyalar/taşır** | Volatile write sadece **son** yazmayı korur; ara kopyalar korunmaz | Heap'te tut (`SecretBox`), `Copy` implement etme, fonksiyonlar arası referansla geçir |
| 2 | **Rust move semantiği kopya bırakır** | `let b = a;` byte-wise kopyadır; derleyici eski konumu temizlemez | Heap indirection — move sadece pointer'ı taşır. **`SecretBox`'ın 0.10'daki heap-only kararının gerçek gerekçesi budur** |
| 3 | **`Vec` yeniden tahsisi eski buffer'ı bırakır** | zeroize dokümanında açıkça belirtilmiş | `Vec::with_capacity(exact)` + asla `push` etme, veya sabit boyutlu array |
| 4 | **`String` büyümesi** | Aynı — realloc eski byte'ları arkada bırakır | Aynı; `SecretString` ile `str` (büyüyemez) kullanın |
| 5 | **`mem::forget` / kasıtlı leak** | `Drop` çalışmaz → zeroize çalışmaz | Kod incelemesi; `#[deny]` lint'i (**[araç DOĞRULANMADI]**) |
| 6 | **Panic / unwinding** | Unwind sırasında Drop **çalışır** (iyi haber) — ama `panic = "abort"` ile **ÇALIŞMAZ** | Argus'ta `panic = "unwind"` bırakın veya abort öncesi signal handler'da temizleyin (güvenilmez) |
| 7 | **Process kill (SIGKILL) / abort** | Hiçbir Drop çalışmaz | Sadece OS-seviyesi koruma (mlock + memfd_secret) |
| 8 | **Core dump'lar** | Heap tamamen diske yazılır | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `MADV_DONTDUMP` (G bölümü) |
| 9 | **Swap** | Sayfa diske yazılır, zeroize sonrası bile eski kopya swap'te kalır | `mlock` / `memfd_secret` |
| 10 | **Hibernation (S4)** | Tüm RAM diske yazılır | `memfd_secret` aktif kullanıcı varken **hibernation engellenir** (G bölümü) |
| 11 | **DMA / cold boot** | RAM'e doğrudan erişim | IOMMU, memory encryption (AMD SME/SEV, Intel TME/TDX) |
| 12 | **Hypervisor snapshot / live migration** | Tüm bellek imajı kopyalanır | Confidential computing (SEV-SNP, TDX, Nitro Enclaves). **Bulutta çalışıyorsanız bu gerçek bir tehdittir ve zeroize'ın hiçbir katkısı yoktur** |
| 13 | **Mikromimari (Spectre/Meltdown)** | zeroize dokümanında **açıkça kapsam dışı** | Mikrokod + kernel mitigations |
| 14 | **CPU register'ları** | zeroize **kapsam dışı** — "requires inline ASM or rustc support" | Yok. Kabul edilmiş risk |

### F.5 Derleyici desteği var mı?

- **Bugün: HAYIR.** zeroize dokümanı register temizliğinin "inline ASM or rustc support" gerektirdiğini ve kapsam dışı olduğunu söylüyor.
- `#[no_sanitize]`: sanitizer'lar için, sır tipleri için değil.
- **Rust'ta "secret types" için kabul edilmiş bir RFC bulamadım — [DOĞRULANMADI].** Arama bütçem tükendiği için bu konuda kesin konuşamıyorum; `rust-lang/rfcs` deposunda "secret" araması yapmanızı öneririm. Bildiğim kadarıyla konu tartışılmış ama stabil bir özellik yok.
- İlgili literatür: "constant-time" / "secret-independent" tip sistemleri akademik olarak var (FaCT, Jasmin, HACL*) ama Rust'ta değil.

**Argus'un pozisyonu:** Kritik sabit-zaman kodu (imza, karşılaştırma) için `subtle` crate'ini ve zaten sabit-zaman garantisi veren kütüphaneleri (ed25519-dalek, p256) kullanın. Kendi kripto ilkelinizi yazmayın.

### F.6 Crate karşılaştırması — Argus için karar

| Crate | Sürüm | Son güncelleme | 90g indirme | Ne yapar | Argus'ta yeri |
|---|---|---|---|---|---|
| **`zeroize`** | 1.9.0 | 2026-06-12 | **168.883.175** | Volatile sıfırlama | **ZORUNLU** — her sır tipinde |
| **`secrecy`** | 0.10.3 | 2024-10-09 | **37.989.495** | Tip-seviyesi kapsülleme + redakte Debug | **ZORUNLU** — API sınırlarında |
| `secrets` | 1.3.0 | 2026-04-13 | 9.661 | mlock + guard pages + canary + core dump kapatma | **Sadece ara imzalama anahtarı için** |
| `memsec` | 0.7.0 | 2024-06-06 | 542.675 | libsodium/utils portu; `memfd_secret` dahil | Alternatif düşük seviye |
| `memsafe` | 1.0.2 | 2026-07-05 | 1.847 | Cross-platform güvenli wrapper | Çok yeni, adoption düşük |
| `memsecurity` | 3.5.2 | 2024-01-05 | 4.958 | Cross-protection-boundary koruma | Bakımsız görünüyor |
| `region` | 4.0.0 | 2026-08-07 | 2.410.207 | Cross-platform sanal bellek API | mprotect için low-level |

**Adoption uyarısı:** `zeroize` ve `secrecy` fiilen standarttır (yüz milyonlarca indirme). `secrets`/`memsafe`/`memsecurity` **çok düşük adoption**'a sahip (10k altı) — bu, az gözden geçirilmiş kod anlamına gelir. **"En güvenli" hedefi ile "az denenmiş bağımlılık" arasında bir gerilim var.** `secrets` crate'ini kullanacaksanız kaynağını okuyun (1.3.0, 2026-04-13'te güncellenmiş — en azından bakımlı).

---

## G) MLOCK / MEMFD_SECRET / CORE DUMP

### G.1 `memfd_secret(2)` — En güçlü Linux mekanizması

Kaynaklar: https://www.man7.org/linux/man-pages//man2/memfd_secret.2.html , https://lwn.net/Articles/865256/ , https://www.phoronix.com/news/Linux-5.14-memfd_secret , https://cateee.net/lkddb/web-lkddb/SECRETMEM.html

#### Ne garanti eder
- Bellek alanları **sadece FD'ye sahip proseslerin sayfa tablosunda** map'lenir
- **Kernel direct map'ten kaldırılır** → kernel'in kendisi bile normal yoldan erişemez
- **`mlock` gibi davranır**: bellekte kalır, **asla swap'e gitmez**
- **`RLIMIT_MEMLOCK`'a tabidir**
- Sayfalar `mmap()` sırasında değil, **fault'ta talep üzerine** tahsis edilir
- **`FD_CLOEXEC`**: `execve(2)`'de bölge prosesten kaldırılır
- **Hibernation, aktif `memfd_secret()` kullanıcısı varken ENGELLENIR** — hibernation imajı üzerinden sızıntıyı önlemek için

#### DÜRÜST UYARI (man sayfasından, birebir)
> **"There is no 100% guarantee that kernel won't be able to access memory ranges backed by memfd_secret() in any circumstances."**

Kanıt: https://github.com/JonathonReinhart/nosecmem — "Demonstrate ability to read memfd_secret() data from the kernel"

#### Varsayılan olarak açık mı? **HAYIR (çoğu sistemde)**
- **Linux 5.14**'te eklendi
- **Linux 6.5'ten ÖNCE varsayılan KAPALI** — `secretmem.enable=y` kernel cmdline parametresi gerekli
- Aksi halde **`ENOSYS`** (ya mimari desteklemiyor ya da kernel cmdline'da açılmamış)
- `CONFIG_SECRETMEM` derleme opsiyonu
- Kapalı olma gerekçesi: direct map'i parçalamanın sistem performansını düşüreceği ve secret memory'yi RAM'e kilitlemenin sorun yaratacağı korkusu

#### Rust desteği
**Adanmış, yaygın bir `memfd-secret` crate'i bulamadım.** Mevcut yol:
- **`memsec`** crate'i: Linux'ta **`alloc_memfd_secret` / `free_memfd_secret`** fonksiyonları — "implementations similar to alloc/free but backed by memfd_secret"
  Kaynak: https://docs.rs/memsec/ , https://github.com/quininer/memsec
- Alternatif: `libc::syscall(SYS_memfd_secret, 0)` ile doğrudan çağrı + `mmap`

#### Pratik kullanılabilirlik — Argus için gerçekçi değerlendirme
| Ortam | memfd_secret çalışır mı? |
|---|---|
| Kendi bare-metal sunucunuz (kernel cmdline kontrolü var) | **Evet** — `secretmem.enable=y` ekleyin |
| Kendi kernel'inizi seçtiğiniz VM | **Evet** |
| Managed Kubernetes (EKS/GKE/AKS) | **Muhtemelen hayır** — node kernel cmdline'ına erişemezsiniz **[DOĞRULANMADI]** |
| Linux 6.5+ node | Varsayılan açık olmalı |

**Tavsiye:** `memfd_secret`'i **opsiyonel bir sertleştirme (hardening) katmanı** olarak uygulayın. Başlangıçta deneyin; `ENOSYS` gelirse `mlock`'a düşün ve **bunu bir startup log satırı + metrik olarak raporlayın** (`argus_secret_memory_backend{type="memfd_secret|mlock|none"}`). Argus'un güvenlik duruşu şeffaf olmalı.

### G.2 `mlock` / `mlockall`

#### Rust'tan
- **`memsec::mlock` / `memsec::munlock`** — cross-platform
- **`region`** crate (4.0.0, 90 günde 2.410.207 indirme) — cross-platform sanal bellek API
- Ham `libc::mlock` / `libc::mlockall`
- **`secrets`** crate mlock'u zaten içinde yapıyor

#### `RLIMIT_MEMLOCK`
`memsafe` dokümantasyonundan (https://lib.rs/crates/memsafe):
> "Each secret occupies a full page (typically 4 KiB) and counts against `RLIMIT_MEMLOCK`, so **the number of live secrets is bounded**."
> "Construction requires about **five syscalls** and every guard cycle uses **two mprotect calls**."

**Argus için önemli:** Her ara anahtar 4 KiB sayfa tüketir. 3-anahtar overlap × N düğüm başına, sorun değil. Ama sırları gelişigüzel `secrets::SecretBox` içine sararsanız `RLIMIT_MEMLOCK`'a çarparsınız.

#### Container etkileri — **[DOĞRULANMADI]**
Docker/Kubernetes varsayılan `RLIMIT_MEMLOCK` değerini yetkili bir kaynakla doğrulayamadım (arama bütçesi tükendi). Bildiğim genel durum:
- Container'larda `memlock` limiti çoğu zaman düşüktür (tarihsel olarak 64 KB) ve **`CAP_IPC_LOCK`** yeteneği veya yükseltilmiş `ulimit -l` gerektirir
- Docker: `--ulimit memlock=-1:-1`
- Kubernetes: `securityContext.capabilities.add: ["IPC_LOCK"]` ve/veya node-level ulimit

**Eylem:** Argus'un başlangıç kodunda `getrlimit(RLIMIT_MEMLOCK)` okuyup loglayın ve yetersizse **açıkça uyarın**. Bunu belgeleyin — deployment dokümanında "IPC_LOCK gerekiyor" yazın.

### G.3 Guard pages / libsodium tarzı koruma

**`secrets` crate 1.3.0** (crates.io: 2026-04-13, 9.661 dl/90g)
Kaynak: https://docs.rs/secrets/latest/secrets/

Sağladıkları:
- **Tahsisin öncesinde ve sonrasında guard pages** (buffer overflow/underflow yakalar)
- **Underflow canary** (guard page'e ulaşmadan önce underflow tespiti)
- **Free'de otomatik sıfırlama**
- **`mlock(2)`** entegrasyonu
- **UNIX release build'lerinde core dump'lar varsayılan olarak KAPALI** (`allow-coredumps` feature ile açılabilir)
- Tipler: `Secret` (stack, sabit uzunluk), `SecretBox` (heap, sabit), `SecretVec` (heap, değişken)
- Erişim **closure'lar** üzerinden — sırın görünürlüğü dar bir kapsama kısıtlanır

Bu, libsodium'un `sodium_malloc`/`sodium_mprotect_noaccess` deseninin Rust karşılığıdır.

**`memsafe` alternatifi:** `MADV_DONTDUMP` de kullanıyor — core dump'tan sadece o sayfaları çıkarır (tüm core dump'ı kapatmadan). Bu **daha iyi bir denge** olabilir.

### G.4 Core dump'ları kapatma

#### `prctl(PR_SET_DUMPABLE, 0)`
Kaynak: https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html

> "Set the state of the 'dumpable' attribute, which determines whether core dumps are produced for the calling process upon delivery of a signal whose default behavior is to produce a core dump."

**`SUID_DUMP_DISABLE` (değer `0L`)** ayarlandığında:
1. Proses **core dump üretmez**
2. **`/proc/[pid]` dizinindeki dosyaların sahipliği değişir** → `root:root` (kısıtlı erişim)
3. **`ptrace(2)` `PTRACE_ATTACH` ile bağlanılamaz**

Bu üçü birden Argus için **çok değerli**: `/proc/<pid>/environ`, `/proc/<pid>/maps`, `/proc/<pid>/mem` aynı-UID saldırgana kapanır ve debugger attach engellenir.

#### Diğer katmanlar
- **`RLIMIT_CORE = 0`** — `setrlimit(RLIMIT_CORE, {0,0})`
- **`/proc/sys/kernel/core_pattern`** — sistem geneli; core'u bir pipe'a yönlendiriyorsa (systemd-coredump, apport) `RLIMIT_CORE` bazı durumlarda **bypass edilebilir** → bu yüzden `PR_SET_DUMPABLE` daha güvenilirdir
- **`madvise(MADV_DONTDUMP)`** — sadece belirli sayfaları core dump'tan çıkarır (`memsafe` bunu yapıyor)

#### Debuggability maliyeti — dürüst muhasebe

| Kaybedilen | Etki | Telafi |
|---|---|---|
| Core dump / post-mortem analiz | Prod crash'ini offline inceleyemezsiniz | Yapılandırılmış panic handler + backtrace log'u (`std::backtrace`), sırlar HARİÇ |
| `gdb` / `lldb` attach | Canlı debug imkânsız | `tokio-console`, metrics, tracing spans |
| `perf` / profiler'lar | Bazıları ptrace kullanır | eBPF tabanlı profiler'lar (`parca`, `pyroscope`) `PTRACE_ATTACH` gerektirmeyebilir **[DOĞRULANMADI]** |
| Sentry/minidump crash reporting | Heap dump gitmez (bu **iyi**) | Sadece stack trace + mesaj gönderin |
| `strace` | Çalışmaz | Uygulama-seviyesi audit log |

**Argus için önerim — kademeli yaklaşım:**
```
ARGUS_HARDENING=paranoid   → PR_SET_DUMPABLE=0 + RLIMIT_CORE=0 + mlock + memfd_secret
ARGUS_HARDENING=balanced   → MADV_DONTDUMP (sadece sır sayfaları) + RLIMIT_CORE=0 + mlock
ARGUS_HARDENING=dev        → hiçbiri, uyarı logla
```
Varsayılan **`balanced`**; prod deployment dokümanında `paranoid` önerin. `MADV_DONTDUMP` sayesinde `balanced` modda core dump alabilirsiniz ama sır sayfaları içinde olmaz — en iyi denge budur.

---

## H) SIR SIZINTI VEKTÖRLERİ

### H.1 Loglama — `tracing` ile kazara sır kaydı

Kaynak: https://docs.rs/tracing/latest/tracing/

**Mekanizma:**
- **`?field` sigil'i** → alanı **`fmt::Debug`** implementasyonuyla kaydeder
- **`%field` sigil'i** → **`fmt::Display`** implementasyonuyla kaydeder
- **Struct alanları nokta notasyonuyla otomatik kaydedilir**: `User { name, email }` → `user.name` ve `user.email` ayrı span alanları olarak

**Sonuç:** `tracing` makrosuna `?` ile giren **her tip** kendi `Debug`'ını sızdırır. `#[derive(Debug)]` olan bir struct'ın içindeki bir `Vec<u8>` anahtar, log satırına düz metin olarak yazılır.

#### En tehlikeli desenler (Argus'ta yasaklanmalı)
```rust
// TEHLİKELİ
#[derive(Debug)]                  // ← anahtar materyalini içeren tipte ASLA
struct SigningKey { d: Vec<u8>, kid: String }

tracing::debug!(?signing_key);    // ← tüm private key log'a
tracing::error!(?err);            // ← err içinde key materyali olabilir
tracing::info!(?request);         // ← request.client_secret
anyhow::anyhow!("failed for {:?}", key)  // ← hata mesajında sır
```

#### Savunma katmanları (Argus için somut)

**1. Tip seviyesinde — birincil savunma**
```rust
// secrecy::SecretBox'ın Debug'ı redakte eder
struct SigningKey {
    d: SecretBox<[u8; 32]>,   // Debug: "SecretBox<[u8; 32]>([REDACTED])"
    kid: String,
}
```

**2. `Debug` derive'ını yasaklayan newtype**
```rust
pub struct KeyMaterial(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyMaterial([REDACTED])")
    }
}
// Display implement ETMEYİN — %field'i imkânsız kılın
// Serialize implement ETMEYİN — JSON'a kaçamasın
```

**3. Clippy lint'i var mı? — [DOĞRULANMADI]**
Bu konuda standart bir clippy lint'i bulup doğrulayamadım (arama bütçesi tükendi). Bildiğim seçenekler:
- **`dylint`** ile özel lint yazmak — Argus'un ölçeğinde buna değer. Bir `#[argus::secret]` attribute'u tanımlayıp, o tiple işaretli her şeyin `Debug`/`Display`/`Serialize` implement etmediğini ve tracing makrolarına geçmediğini denetleyin.
- **`cargo-semver-checks` benzeri CI kontrolü:** `grep -r "derive(.*Debug" src/crypto/` ile bir CI guard
- **`#[deny(missing_debug_implementations)]`'ın TERSİ** gerekiyor — böyle bir lint yok

**4. Log pipeline'ında son savunma**
- Bir `tracing_subscriber::Layer` yazın: alan değerlerinde yüksek-entropi base64/hex desenleri arayıp redakte etsin. Bu **son çare** — tip sistemine güvenin, buna değil.
- Log toplama katmanında (Vector/Fluent Bit) redaksiyon kuralları.

**5. Test**
Argus'un test suite'ine bir test ekleyin: bir signing key üretin, tüm log seviyelerinde tüm public API'yi çağırın, log çıktısını yakalayın, anahtar byte'larının hex/base64 gösterimlerini **grep'leyin**. Bulursa fail.

**6. Gerçek CVE'ler — [DOĞRULANMADI]**
Rust'ta `Debug`/loglama üzerinden sır sızdıran spesifik bir CVE bulup doğrulayamadım. Genel olarak bu sınıfın (CWE-532: Insertion of Sensitive Information into Log File) çok yaygın olduğunu biliyorum ama Argus dokümanında **isim vererek bir vaka aktarmayın** — ben doğrulayamadım.

### H.2 `/proc/<pid>/environ` ve `/proc/<pid>/cmdline`

**Mekanizma (genel OS bilgisi, bu görevde ayrıca kaynaklandırılmadı):**
- `/proc/<pid>/environ` — prosesin **başlangıç** ortam değişkenlerini içerir; aynı UID'deki her proses okuyabilir
- `/proc/<pid>/cmdline` — komut satırı argümanları; **tüm kullanıcılar** tarafından okunabilir (`ps aux`)
- **`prctl(PR_SET_DUMPABLE, 0)` bunları `root:root` yapar** (G.4) → aynı-UID saldırganı engeller

#### Sır teslim yöntemleri — karşılaştırma

| Yöntem | Sızıntı riski | Argus'ta |
|---|---|---|
| **Komut satırı argümanı** | **En kötü** — `ps` ile herkese açık | **ASLA** |
| **Ortam değişkeni** | `/proc/pid/environ`; child proseslere miras; crash reporter'lar toplar; `docker inspect` gösterir | Sadece düşük-hassasiyetli config |
| **Dosya (0600, tmpfs)** | Disk (tmpfs ise RAM), okuduktan sonra kapatılabilir | **İyi** — bootstrap credential için |
| **Unix domain socket** | Dosya sistemi izinleri + `SO_PEERCRED` ile peer doğrulama | **En iyi** — Vault Agent / SPIRE Workload API deseni |
| **KMS/IMDS ile runtime çekme** | Diskte/env'de hiç yok | **En iyi** — IAM rolü ile |

**Argus önerisi:** Bootstrap kimliği (KMS'e erişim) **workload identity** ile (IRSA/Workload Identity/Managed Identity) — hiç sır dosyası olmasın. Statik sır gerekiyorsa **Unix socket üzerinden Vault Agent / SPIFFE Workload API**.

### H.3 Kubernetes Secrets

Kaynak: https://kubernetes.io/docs/concepts/configuration/secret/

**Kubernetes'in kendi uyarısı (birebir):**
> "Kubernetes Secrets are, **by default, stored unencrypted in the API server's underlying data store (etcd)**. Anyone with API access can retrieve or modify a Secret, and so can anyone with access to etcd."

**Erişim riski:**
> Bir namespace'te Pod yaratma yetkisi olan **herkes o namespace'teki HERHANGİ bir Secret'ı okuyabilir** — doğrudan API ile veya Deployment yaratma yetkisi üzerinden dolaylı olarak.

**Kubernetes'in önerdiği minimum önlemler:**
1. **Encryption at Rest'i etkinleştir** (https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
2. **En az yetki ilkesiyle RBAC** yapılandır
3. **Container erişimini kısıtla** — Secret'ı sadece ihtiyacı olan container'a ver
4. **Harici secret store sağlayıcıları düşün** — https://secrets-store-csi-driver.sigs.k8s.io/

Ayrıca: https://kubernetes.io/docs/concepts/security/secrets-good-practices/

#### Karşılaştırma — Argus için
| Yaklaşım | Değerlendirme |
|---|---|
| **K8s Secret → env var** | **En kötü**: etcd'de şifresiz + `/proc/pid/environ` + child prosesler + `kubectl describe` |
| **K8s Secret → volume mount** | Daha iyi: tmpfs'te, env'de değil. Ama etcd hâlâ şifresiz (encryption-at-rest yoksa) |
| **K8s Secret + KMS encryption provider** | İyi: etcd'de şifreli |
| **Secrets Store CSI Driver** | Daha iyi: etcd'ye hiç girmez, doğrudan Vault/KMS'ten tmpfs'e |
| **Vault Agent sidecar / injector** | Çok iyi: kısa ömürlü token, otomatik yenileme |
| **Workload Identity (IRSA/GKE WI) + doğrudan KMS** | **En iyi**: hiçbir yerde statik sır yok |

**Argus'un dokümante etmesi gereken:** "Argus, KMS'e workload identity ile erişir. Kubernetes Secret kullanmaz. Eğer kullanmak zorundaysanız, encryption-at-rest'i etkinleştirin ve volume mount kullanın, env var değil."

### H.4 Core dump'lar ve crash reporter'lar

- **G.4**'te ele alındı. Ek olarak:
- **Sentry / minidump / Crashpad:** Minidump'lar **heap segmentlerini içerebilir**. Argus Sentry kullanacaksa `before_send` hook'unda tüm binary payload'ları sıfırlayın ve **sadece** stack trace + mesaj gönderin.
- **`secrets` crate zaten UNIX release build'lerinde core dump'ı kapatıyor** — bu ücretsiz bir kazanç.
- **systemd-coredump:** `/etc/systemd/coredump.conf` → `Storage=none`. Ama `PR_SET_DUMPABLE=0` daha güvenilir çünkü uygulama kontrolünde.

### H.5 Yedekler, DB dump'ları, replikasyon

Argus için:
- **Ara imzalama anahtarları hiçbir zaman DB'ye yazılmamalı** — bu, hibrit modelin bir yan faydası. Bellekte doğar, bellekte ölür.
- Kök anahtar zaten KMS/HSM'de — DB'de yok.
- **DB'de ne var:** JWKS geçmişi (sadece **public** anahtarlar), client secret hash'leri (Argon2id), refresh token hash'leri, kullanıcı kimlik bilgileri.
- **Client secret'ları asla düz metin saklamayın** — hash'leyin (Argon2id). Keycloak'ın client secret'ı geri gösterebilmesi bir zayıflıktır; Argus bunu yapmamalı.
- **Replikasyon:** WAL/binlog kanalları TLS + at-rest şifreli olmalı.
- **Yedek:** `pg_dump` çıktısı client secret hash'lerini ve refresh token hash'lerini içerir — bu dump'lar KMS ile şifrelenmeli.
- **Test/staging'e prod dump kopyalama** — en yaygın gerçek sızıntı yolu. CI'da yasaklayın.

### H.6 Zamanlama / hata mesajı farkları (yan kanallar)

- **Client secret doğrulama:** `subtle::ConstantTimeEq` kullanın, `==` değil.
- **Hata mesajı ayrımı:** "unknown client" vs "invalid secret" **aynı** hata dönmeli (OAuth 2.0 `invalid_client`). Farklı mesaj = client enumeration.
- **Zamanlama ayrımı:** Var olmayan client için Argon2 çalıştırmazsanız, cevap süresi farkından client varlığı anlaşılır. **Dummy hash ile sabit-zamanlı yol** izleyin.
- **JWKS `kid` lookup:** Bilinmeyen `kid` için sabit zamanlı yanıt (bu düşük riskli ama tutarlılık iyi).
- **Rate limiting'in kendisi bir yan kanaldır:** "bu client throttle'landı" bilgisi client varlığını sızdırır.

---

## ARGUS İÇİN ÖZET KARAR TABLOSU

| Araç / Teknik | Olgunluk | Maliyet | Ne kazandırır | Argus'ta nerede |
|---|---|---|---|---|
| **`zeroize` 1.9.0** | **Çok yüksek** (169M/90g) | Sıfır | Derleyicinin sıfırlamayı silmemesi | **Her sır tipinde — ZORUNLU** |
| **`secrecy` 0.10.3** | **Çok yüksek** (38M/90g) | Sıfır | Redakte Debug + explicit exposure | **API sınırlarında — ZORUNLU** |
| **`cryptoki` 0.12.0** | Yüksek (1.2M/90g) | Sıfır (+HSM donanımı) | PKCS#11 3.x, Session: Send | Kök anahtar HSM'de ise |
| **`r2d2-cryptoki` 0.5.0** | Orta (28k/90g) | Sıfır | HSM oturum havuzu | cryptoki ile birlikte |
| **`secrets` 1.3.0** | **Düşük** (9,6k/90g) | Sayfa başına 4 KiB memlock | mlock + guard page + core dump kapatma | **Sadece ara imzalama anahtarı** |
| **`memsec` 0.7.0** | Orta (543k/90g) | Sıfır | `memfd_secret` erişimi | Opsiyonel sertleştirme |
| **`memfd_secret(2)`** | Kernel 5.14+, **çoğu yerde kapalı** | Kernel cmdline erişimi | Direct map'ten çıkarma, swap yok, hibernation bloğu | Best-effort, fallback'li |
| **`PR_SET_DUMPABLE=0`** | Olgun | Debuggability | Core dump + ptrace + /proc kapanışı | Prod'da `paranoid` mod |
| **AWS KMS (Ed25519/P-256)** | Çok yüksek | $1/ay/anahtar + $0,15/10k | Kök anahtar hiç çıkmaz | **Sadece ara anahtar sarma** |
| **AWS CloudHSM hsm2m** | Yüksek | Saatlik HSM | 3.000-7.000 P-256/sn, FIPS L3 | Kök anahtar, düzenleyici zorunluluk varsa |
| **Azure Managed HSM** | Yüksek | Instance saatlik | 330 P-256/sn/partition | Azure'daysanız kök anahtar |
| **YubiHSM 2** | Yüksek | ~$650 donanım | ~14 P-256/sn, tek thread | **Sadece kök anahtar / dev** |
| **Vault/OpenBao transit** | Yüksek | Ops yükü | Ed25519 + batch_input + versiyonlama | Ara anahtar sarma (KMS alternatifi) |
| **OpenBao v2.6.2** | Orta-yüksek, hızlı büyüyor | Ops yükü | BUSL'dan kaçınma, LF yönetişimi | Vault yerine, açık kaynak Argus için |
| **Delegated-credential tarzı attestation** | Standart-dışı ama kanıtlanmış (Cloudflare) | Az kod | JWKS kompromizasyonuna karşı savunma | JWKS'e ek alan olarak |

---

## EYLEM PLANI (öncelik sırasıyla)

1. **Hibrit modeli tasarım kararı olarak kilitleyin.** Kök → KMS/HSM. Ara anahtar (15 dk / 5M imza, hangisi önce) → bellek. Gerekçe: B bölümündeki 1.000 TPS tavanı ve $39k/ay maliyeti.
2. **`zeroize` + `secrecy` 0.10.x'i baştan uygulayın.** Sonradan eklemek çok daha zor. `SecretBox`'ın heap-only olmasının move-semantiği gerekçesini kod yorumlarında belgeleyin.
3. **Kendi bölgenizde KMS Sign p50/p99'unu ölçün.** Yayınlanmış sayı yok; bu ölçüm mimari kararı doğrulayacak (veya çürütecek).
4. **JWKS rotasyon state machine'ini E.4'teki gibi kurun.** Warm-up 10 dk, aktif 15 dk, drain 20 dk. `kid` = RFC 7638 thumbprint. `Cache-Control: max-age=300, stale-if-error=86400`.
5. **`ARGUS_HARDENING` kademeli sertleştirme modunu ekleyin** ve hangi katmanın aktif olduğunu startup'ta loglayın + metrik olarak yayınlayın.
6. **Sır sızıntısı testini CI'ya koyun** (log çıktısında anahtar byte'larını grep'leyen test). Uzun vadede `dylint` özel lint'i.
7. **HSM entegrasyonunu `cryptoki` 0.12+ ve `r2d2-cryptoki` ile, ayrı bir blocking thread pool'da yapın.** Handle'ları label ile çözün, oturum ömrüne bağlayın.
8. **Kök anahtar töreni için `boulder/cmd/ceremony`'yi referans alın**, çok kişili kontrol + video kayıt.

---

### Açıkça doğrulanamayan maddeler (özet)

1. **AWS/GCP/Azure KMS Sign p50/p99 gecikmesi** — hiçbir sağlayıcı yayınlamıyor; bulamadım.
2. **Vault transit sign ops/sn** — HashiCorp yayınlamıyor; "37k ops/sn" Medium kaynağı fetch edilemedi (403).
3. **YubiHSM 2 performans tablosu** — Yubico destek makalesinden arama indeksi üzerinden alındı; sayfanın doğrudan fetch'i CSS hatası verdi. **Tarayıcıda teyit edin.**
4. **AWS KMS asimetrik fiyatlandırmanın tam per-key-spec tablosu** — sadece $0,15/10k örneği çıkarılabildi.
5. **GCP Cloud KMS fiyatlandırması** — sayfa içeriği kesildi.
6. **Keycloak varsayılan anahtar rotasyon ömrü** — kaynaklarda yoktu.
7. **OIDC Core §10.1.1'in birebir metni** — spec sayfası kesildi; özet ikincil kaynaklardan.
8. **Docker/K8s varsayılan `RLIMIT_MEMLOCK`** — yetkili kaynakla doğrulanamadı.
9. **Rust'ta secret-type RFC'si** — bulamadım; yok olduğunu iddia etmiyorum.
10. **Rust `Debug`/log sır sızıntısı için clippy lint'i** — bulamadım.
11. **Rust'ta `Debug` üzerinden sır sızdıran spesifik CVE** — doğrulanmış bir örnek bulamadım.
12. **`cryptoki-rustcrypto`** — crates.io'da ve repo workspace'inde **yok**; yayınlanmış bir crate olarak mevcut değil.

*Not: Bu oturumda WebSearch bütçesi (200/200) tükendiği için son birkaç madde yalnızca doğrudan URL fetch'i ile araştırılabildi.*

**Kaynaklar (ana):**
- https://github.com/parallaxsecond/rust-cryptoki · https://github.com/parallaxsecond/rust-cryptoki/blob/main/CHANGELOG.md · https://crates.io/crates/cryptoki
- https://github.com/spruceid/r2d2-cryptoki · https://lib.rs/crates/yubihsm · https://github.com/softhsm/SoftHSMv2 · https://github.com/kushaldas/kryptering
- https://support.yubico.com/hc/en-us/articles/360021202780-YubiHSM-2-A-load-balanced-design-for-heavy-traffic-environments · https://docs.yubico.com/hardware/yubihsm-2/datasheet/_static/YubiHSM_2_Technical_Data_Sheet.pdf
- https://docs.aws.amazon.com/cloudhsm/latest/userguide/performance.html · https://docs.aws.amazon.com/cloudhsm/latest/userguide/ki-hsm2m-medium.html
- https://docs.aws.amazon.com/kms/latest/developerguide/requests-per-second.html · https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html · https://aws.amazon.com/kms/pricing/
- https://docs.cloud.google.com/kms/quotas
- https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits · https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/scaling-guidance
- https://blog.cloudflare.com/keyless-delegation/ · https://developers.cloudflare.com/ssl/keyless-ssl/reference/scaling-and-benchmarking/ · https://blog.cloudflare.com/geo-key-manager-how-it-works/
- https://developer.hashicorp.com/vault/docs/concepts/seal · https://developer.hashicorp.com/vault/docs/secrets/transit · https://developer.hashicorp.com/vault/api-docs/secret/transit · https://www.hashicorp.com/en/blog/understanding-vault-performance-benchmarks-from-real-world-workloads · https://developer.hashicorp.com/vault/tutorials/operations/benchmark-vault
- https://github.com/openbao/openbao/releases · https://www.techtarget.com/searchitoperations/news/366644831/Nvidia-adopts-OpenBao-open-source-fork-of-HashiCorps-Vault
- https://github.com/spiffe/spire/blob/main/doc/plugin_server_keymanager_aws_kms.md · https://github.com/sigstore/fulcio/blob/main/docs/setup.md · https://github.com/letsencrypt/boulder/tree/main/cmd/ceremony · https://jhalderm.com/pub/papers/letsencrypt-ccs19.pdf
- https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html · https://aws.amazon.com/blogs/security/how-to-verify-aws-kms-signatures-in-decoupled-architectures-at-scale/
- https://datatracker.ietf.org/doc/html/rfc7517 · https://developer.okta.com/docs/concepts/key-rotation/ · https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys · https://github.com/keycloak/keycloak/blob/main/docs/documentation/server_admin/topics/realms/keys.adoc · https://engineering.zalando.com/posts/2025/01/automated-json-web-key-rotation.html · https://duendesoftware.com/blog/20260113-why-signing-key-rotation-matters-in-openid-connect-and-duende-identityserver
- https://docs.rs/zeroize/latest/zeroize/ · https://cipherstash.com/blog/verifying-rust-zeroize-with-assembly-including-portable-simd · https://docs.rs/secrecy/latest/secrecy/ · https://github.com/iqlusioninc/crates/blob/main/secrecy/CHANGELOG.md · https://docs.rs/secrets/latest/secrets/ · https://docs.rs/memsec/ · https://lib.rs/crates/memsafe
- https://www.man7.org/linux/man-pages//man2/memfd_secret.2.html · https://lwn.net/Articles/865256/ · https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html · https://github.com/JonathonReinhart/nosecmem
- https://docs.rs/tracing/latest/tracing/ · https://kubernetes.io/docs/concepts/configuration/secret/
