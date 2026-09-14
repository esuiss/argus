# §9 — Anahtar ve sır yönetimi

## Özet

Her JWT imzası için bir KMS veya HSM çağrısı yapan bir IdP, hesap ve bölge başına yaklaşık 1.000 token/sn tavanına çarpar ve aylık yaklaşık 39.000 USD öder. Argus'un hedeflediği ölçekte çalışan tek mimari, C bölümünde anlatılan hibrit envelope modelidir: kök anahtar KMS veya HSM'de, kısa ömürlü ara imzalama anahtarı bellekte. Bunun kanıtı aşağıdaki gerçek sayılardadır.

---

## A. PKCS#11 ve HSM: Rust tarafı

### A.1 `cryptoki` crate'inin olgunluğu ve durumu

crates.io API'sinden 8 Eylül 2026'da çekilen veriler:

| Crate | Sürüm | Son güncelleme | Toplam indirme | Son 90 gün |
|---|---|---|---|---|
| `cryptoki` | 0.12.0 | 22 Ocak 2026 | 2.554.577 | 1.225.938 |
| `cryptoki-sys` | 0.5.0 | 19 Aralık 2025 | 2.875.734 | 1.454.145 |
| `pkcs11` (eski) | 0.5.0 | 20 Nisan 2020 | 760.201 | 49.567 |
| `r2d2-cryptoki` | 0.5.0 | 14 Ağustos 2026 | 136.646 | 28.305 |
| `yubihsm` | 0.42.1 | 15 Ağustos 2023 | 1.277.973 | 137.886 |

Crate 18 Mart 2021'de yayımlanmıştır, 18 sürümü vardır ve Apache-2.0 lisanslıdır.

**Değerlendirme.** `cryptoki` gerçek ve canlı bir projedir. Çeyrek yılda bir sürüm ritmi vardır ve üç ayda 1,2 milyon indirme almaktadır. Arm kökenli Parsec topluluğu tarafından sürdürülmektedir. README'de üretim hazırlığı beyanı yoktur ancak sürüm ve indirme profili olgundur.

**CHANGELOG'dan kritik noktalar.** v0.12.0 (Ocak 2026) ile oturumlar `Send` hâline gelmiş ve thread sınırlarını geçebilmeye başlamıştır; bu Argus için doğrudan ilgilidir, çünkü öncesinde oturumu bir tokio task'ına taşımak sorunluydu. v0.11.0 (Aralık 2025) ile `Session`'ın ömrü `Pkcs11` nesnesinden ayrılmıştır; bu havuzlamayı çok kolaylaştıran bir değişikliktir. PKCS#11 3.0 desteği kapsamında mesaj tabanlı şifreleme ile şifre çözme ve çok parçalı işlemler eklenmiştir. PKCS#11 3.2 kapsamında profile ve validation objeleri ile SLH-DSA post-quantum mekanizmaları desteklenmektedir. Ayrıca NIST SP800-108 KDF, HKDF, SHA anahtar üretimi ile vendor tanımlı mekanizma ve öznitelikler eklenmiştir. `paste` bağımlılığı RUSTSEC-2024-0436 nedeniyle kaldırılmıştır; bu güvenlik hijyeni açısından iyi bir sinyaldir. `get_attribute_info_map` artık slice almaktadır ve bu kırıcı bir değişikliktir.

PKCS#11 3.0 Rust'ta desteklenmekte ve aktif olarak genişletilmektedir. Bu, Rust ekosisteminde PKCS#11 3.x için pratikte tek ciddi seçenektir.

**PIN yönetimi.** crates.io feature listesinde `"serde": ["secrecy/serde"]` görünmektedir; crate PIN'i `secrecy::SecretString` içinde tutmaktadır. Tartışma github.com/parallaxsecond/rust-cryptoki/issues/50 adresindedir.

**`cryptoki-rustcrypto` mevcut değildir.** crates.io API'sinde `cryptoki-rustcrypto` veya `cryptoki_rustcrypto` bulunamamıştır. Workspace üyeleri yalnızca `cryptoki` ve `cryptoki-sys`'tir. crates.io'da "cryptoki" araması `cryptoki`, `cryptoki-sys`, `r2d2-cryptoki`, `sequoia-cryptoki` (0.1.1, 5 Temmuz 2026), `sequoia-keystore-cryptoki` (0.1.0, 5 Temmuz 2026), `sq-cryptoki`, `esteid-cryptoki`, `oxicrypto-adapter-pkcs11` ve `oxitls-adapter-pkcs11` döndürmektedir. Sonuç olarak yayımlanmış bir `cryptoki-rustcrypto` crate'i yoktur; RustCrypto `signature::Signer` trait köprüsünü Argus'un kendisi yazmalıdır ve bu yaklaşık 200 satırlık bir iştir.

**Alternatif: `kryptering` (Kushal Das).** Signer, Verifier, Decryptor, Encryptor, KeyWrapper ve KeyAgreement trait'leriyle hem yazılım (RustCrypto) hem PKCS#11 (SoftHSM2, Kryoptic, gerçek HSM) arka ucu sunar. Argus'un istediği soyutlamanın referans tasarımıdır (github.com/kushaldas/kryptering).

### A.2 Pratik entegrasyon zorlukları

**Oturum yönetimi ve thread güvenliği çözülmüş bir problemdir.** `r2d2-cryptoki` (spruceid, v0.5.0, 14 Ağustos 2026) bir r2d2 bağlantı havuzu adaptörüdür; PIN doğrulaması ve thread güvenli oturum yönetimi hazır gelir ve 90 günde 28.305 indirme almıştır. `CInitializeFlags::OS_LOCKING_OK` bayrağı ile PKCS#11 kütüphanesinin kendi kilitlemesini işletim sistemine devretmesi sağlanır.

**Argus için mimari kural.** HSM oturumu asla `async fn` içinde doğrudan tutulmaz. Ayrı bir blocking thread havuzu (`tokio::task::spawn_blocking` veya adanmış bir signer thread) ile r2d2 havuzu kullanılır. `Session: Send` (v0.12.0) bunu mümkün kılar ancak `Sync` değildir; her thread kendi oturumunu almalıdır.

**Mekanizma desteği.**

| Sağlayıcı | ECDSA P-256 | Ed25519 ve EdDSA | RSA-PSS |
|---|---|---|---|
| SoftHSMv2 | Evet | Evet; derleme sırasında `--enable-eddsa` | Doğrulanamamıştır |
| YubiHSM 2 | Evet | Evet; EdDSA-25519 | Evet |
| AWS CloudHSM | Evet | HashEdDSA yalnızca `hsm2m.medium` ve FIPS dışı modda | Evet |
| Azure Managed HSM | P-256, P-256K, P-384, P-521 | Listede yoktur | Evet |
| AWS KMS | Evet | Evet; ECC_NIST_EDWARDS25519 | Evet |

SoftHSMv2 OpenDNSSEC kökenlidir, Botan 2.0 ve üstü veya OpenSSL 1.0 ve üstü gerektirir ve ECC, EdDSA ile SHA3 derleme opsiyonludur. Yalnızca test için değil, üretimde de kullanılmaktadır; OpenDNSSEC örneğidir.

> **AWS CloudHSM HashEdDSA kısıtı önemlidir.** FIPS modunda EdDSA yoktur. Argus en güvenli iddiasındaysa FIPS 140-3 Level 3 ile EdDSA aynı anda mümkün değildir; ES256'ya, yani P-256'ya düşmek gerekir.

**Test altyapısı.** SoftHSMv2 CI için standarttır. Kryoptic daha yenidir ve Rust tabanlı bir PKCS#11 token'ıdır; `kryptering` tarafından desteklenir. MockHSM `yubihsm` crate'inde donanımsız test için bulunur; uyarısı gerçek bir YubiHSM2'ye karşı çalıştırılan testlerin yıkıcı olduğu ve önem verilen anahtarlar içeren bir cihazda koşulmaması gerektiğidir.

**`yubihsm` crate'i riskleri.** Son sürüm 15 Ağustos 2023 tarihlidir; üç yıldır sürüm çıkmamıştır. Yubico'nun resmî projesi değildir; Tony Arcieri (iqlusion) sürdürmektedir ve MSRV 1.67'dir. 90 günde 138.000 indirme almaktadır ancak bakımsızdır. Argus için tavsiye `yubihsm` crate'i yerine `cryptoki` ile YubiHSM'in PKCS#11 modülünün kullanılmasıdır.

**Nesne handle'ları ve yeniden bağlanma.** PKCS#11'de `CK_OBJECT_HANDLE` oturuma özeldir ve oturum kapandığında geçersizleşir. Argus tasarımında anahtarlar her zaman `CKA_LABEL` veya `CKA_ID` ile aranır; handle önbelleklenmez veya önbelleklenirse oturum yeniden kurulduğunda tam geçersizleştirme yapılır. `C_FindObjects` maliyeti her imzaya eklenmemelidir; bu nedenle havuzdaki her oturum kendi handle'ını oturum ömrü boyunca önbellekler.

**HSM'ler arası failover.** PKCS#11 standardı failover tanımlamaz. AWS CloudHSM istemcisi kümeyi kendisi yönetir ve yük dengeleme ile yeniden deneme sağlar. Thales Luna ve Utimaco için HA grupları sağlayıcı kütüphanesindedir. Argus kendi failover'ını yazarsa her HSM için ayrı bir `Pkcs11` instance'ı, ayrı havuz ve circuit breaker kullanır.

### A.3 HSM imzalama performansı

**YubiHSM 2** (Yubico resmî dokümantasyonu). Boştaki bir cihazda ortalama gecikmeler:

| İşlem | Süre | İmza/sn |
|---|---|---|
| ECDSA-P256-SHA256 | Yaklaşık 73 ms | Yaklaşık 13,7 |
| ECDSA-P384-SHA384 | Yaklaşık 120 ms | Yaklaşık 8,3 |
| ECDSA-P521-SHA512 | Yaklaşık 210 ms | Yaklaşık 4,8 |
| EdDSA-25519 (32 B) | Yaklaşık 105 ms | Yaklaşık 9,5 |
| EdDSA-25519 (64 B) | Yaklaşık 121 ms | Yaklaşık 8,3 |
| EdDSA-25519 (128 B) | Yaklaşık 137 ms | Yaklaşık 7,3 |
| EdDSA-25519 (256 B) | Yaklaşık 168 ms | Yaklaşık 6,0 |
| EdDSA-25519 (512 B) | Yaklaşık 229 ms | Yaklaşık 4,4 |
| EdDSA-25519 (1024 B) | Yaklaşık 353 ms | Yaklaşık 2,8 |
| RSA-2048 | Yaklaşık 139 ms | Yaklaşık 7 |

**Kritik mimari kısıt.** Cihaz en fazla 16 eşzamanlı oturum destekler ancak tek thread'lidir ve oturumlar arasında işlemleri seri yürütür. 16 oturum açmak throughput'u artırmaz.

> **Kaynak notu.** Yubico'nun ilgili destek makalesinin doğrudan çekilmesi portalın CSS hatası nedeniyle başarısız olmuştur; sayılar bu resmî destek makalesinin arama indeksinden alınmıştır ve sayfanın bir tarayıcıda açılarak teyit edilmesi gerekir. Teknik veri sayfası docs.yubico.com üzerindedir.

Argus için anlamı şudur: bir YubiHSM 2 saniyede yaklaşık 14 JWT imzalayabilir. Bu bir IdP için tamamen yetersizdir. YubiHSM 2 yalnızca kök veya ara anahtar rolü için, yani hibrit modelde uygundur.

**AWS CloudHSM** (AWS resmî performans sayfası).

hsm1.medium:

| İşlem | 2 HSM | 3 HSM | 6 HSM |
|---|---|---|---|
| RSA-2048 sign | 2.000/sn | 3.000/sn | 5.000/sn |
| EC P-256 sign | 500/sn | 750/sn | 1.500/sn |

hsm2m.medium:

| İşlem | 2 HSM | 3 HSM | 6 HSM |
|---|---|---|---|
| RSA-2048 sign | 2.000/sn | 3.000/sn | 5.000/sn |
| EC P-256 sign | 3.000/sn | 4.500/sn | 7.000/sn |

Ölçüm koşulu tek bir `c4.large` EC2 instance'ı üzerinde çalışan çok thread'li bir Java uygulamasıdır. AWS kümenin yük testine tabi tutulmasını ve bir HSM daha eklenmesini önermektedir. Kapasite aşıldığında HSM'lerin meşgul veya throttle edilmiş olduğu hatası döner.

hsm2m.medium ile P-256'da 500'den 3.000'e altı kat iyileşme vardır; bu yeni nesil donanımdır. Gerçekten HSM'de imzalamak isteyen bir IdP için tek makul on-prem veya bulut HSM seçeneğidir.

> **hsm2m.medium bilinen sorunu.** FIPS 140-3 Level 3 uyumu nedeniyle login gecikmesi artmıştır. Argus'un HSM'e yeniden bağlanma senaryolarında bu ciddi bir tail latency kaynağıdır.

**Azure Managed HSM** (Microsoft resmî ölçekleme kılavuzu; ms.date 3 Aralık 2025, güncelleme 12 Haziran 2026). Ölçüm yöntemi tek partition'lı bir Managed HSM havuzuna karşı, her istekte aynı anahtar kullanılarak beş dakika boyunca sürdürülen ortalama işlem/sn'dir.

RSA (işlem/sn, HSM instance başına, bir partition):

| İşlem | 2048 | 3072 | 4096 |
|---|---|---|---|
| Sign | 900 | 340 | 150 |
| Verify | 3400 | 3400 | 3700 |
| Decrypt | 1100 | 360 | 160 |
| Create Key | 1 | 1 | 1 |

EC (işlem/sn):

| İşlem | P-256 | P-256K | P-384 | P-521 |
|---|---|---|---|---|
| Sign | 330 | 330 | 160 | 200 |
| Verify | 130 | 130 | 82 | 28 |
| Create Key | 1 | 1 | 1 | 1 |

Her Managed HSM instance'ı üç yük dengeli partition'dan oluşur. Tablodaki sayılar en az bir partition varsayımıyladır; hepsi ayaktaysa üç katına kadar çıkabilir. Microsoft kapasite planlamasında iki partition varsayılmasını, garanti gerekiyorsa bir partition ile planlanmasını önermektedir. Abonelik ve bölge başına en fazla beş HSM instance'ı, instance başına 5.000 anahtar ve anahtar başına 100 versiyon sınırı vardır.

Dikkat çekici nokta şudur: Managed HSM kripto işlemlerinde throttle uygulamaz ve donanımın doğal limitine kadar çalışır. Ancak `Create Key` saniyede bir işlemdir ve bu anahtar rotasyonu için ciddi bir darboğazdır.

**Azure Key Vault** (standart vault, Managed HSM değil). Limitler 10 saniyede, vault başına ve bölge başınadır:

| Anahtar tipi | HSM: CREATE ve RELEASE | HSM: diğer tüm işlemler | Yazılım: CREATE | Yazılım: diğer |
|---|---|---|---|---|
| RSA-2048 | 10 | 2.000 (200 TPS) | 20 | 4.000 (400 TPS) |
| RSA-3072 | 10 | 500 (50 TPS) | 20 | 1.000 |
| RSA-4096 | 10 | 250 (25 TPS) | 20 | 500 |
| ECC P-256 | 10 | 2.000 (200 TPS) | 20 | 4.000 |
| ECC P-384, P-521, secp256k1 | 10 | 2.000 | 20 | 4.000 |

Kotalar ağırlıklıdır ve toplamları üzerinden uygulanır: RSA-4096 HSM anahtarı kullanmak RSA-2048'e göre sekiz kat pahalıdır (2000 bölü 250). Aşıldığında HTTP 429 döner. Abonelik geneli limit vault limitinin beş katıdır. Secret CREATE, Certificate IMPORT ve Key IMPORT birlikte 10 saniyede 300 ile sınırlıdır.

Argus için sonuç: Azure Key Vault standart sürümü HSM anahtarıyla vault başına en fazla 200 imza/sn, abonelik genelinde beş vault ile 1.000 imza/sn verir. Bu kesinlikle yetersizdir.

**Karşılaştırma noktası: yazılımda imzalama.** Cloudflare'in yayımlanmış ölçümü AWS c5.xlarge (4 vCPU, 3,0 GHz Intel Xeon Platinum) üzerinde alınmıştır:

| Algoritma | Çekirdek başına | Dört çekirdek toplam (60 sn) | Ortalama işlem süresi |
|---|---|---|---|
| ECDSA | 10.000'den fazla imza/sn | 2.661.570 işlem, yaklaşık 44.359/sn | 22,543 µs |
| RSA | Yaklaşık 200 imza/sn | 46.560 işlem, yaklaşık 776/sn | 1,288659 ms |

Cloudflare beklenen yükün iki katını karşılayacak kadar key server dağıtılmasını önermektedir.

### A.4 Karşılaştırma tablosu

| Yöntem | ECDSA P-256 imza/sn | Kaynak |
|---|---|---|
| Rust veya Go bellek içi (c5.xlarge, 4 vCPU) | Yaklaşık 44.000 | Cloudflare |
| AWS CloudHSM hsm2m, altı HSM | 7.000 | AWS |
| AWS CloudHSM hsm2m, iki HSM | 3.000 | AWS |
| Azure Managed HSM (üç partition) | Yaklaşık 990 | Microsoft; 330 × 3 |
| AWS KMS (ECC kotası) | 1.000; hesap ve bölge başına | AWS |
| Azure Key Vault HSM (vault başına) | 200 | Microsoft |
| GCP Cloud KMS HSM asimetrik | 50; bölge başına, eski model | Google |
| YubiHSM 2 | Yaklaşık 14 | Yubico |

Fark üç büyüklük mertebesidir, yani bin kattır. Bu tablo tek başına Argus'un mimari kararını belirler.

### A.5 Alternatifler: KMIP, Tink, yerel SDK'lar

KMIP için Rust'ta olgun bir istemci bulunamamıştır. KMIP zaten bir anahtar yönetimi protokolüdür ve yüksek hacimli imzalama için tasarlanmamıştır; Argus için uygun değildir.

Tink Google'ın kütüphanesidir; Rust portu (`rust-tink`) topluluk çabasıdır ve bakımı zayıftır, bu doğrulanamamıştır. Tink'in KMS envelope soyutlaması iyi bir tasarım referansıdır ancak Rust'ta bağımlılık olarak alınmamalıdır.

Yerel vendor SDK'ları — Thales Luna ve Utimaco'nun C SDK'ları — PKCS#11'den daha hızlı olabilir ancak Rust FFI ve vendor kilidi getirir. `cryptoki` üzerinden PKCS#11 doğru seçimdir.

---

## B. Bulut KMS ile imzalama: kotalar, fiyat, gecikme

### B.1 AWS KMS kotaları

| Kota | Varsayılan (istek/sn) |
|---|---|
| Simetrik kripto işlemleri | 10.000 (paylaşımlı); us-east-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1 ve eu-west-2'de 20.000; us-east-1, us-west-2 ve eu-west-1'de 100.000 |
| RSA kripto işlemleri (Sign ve Verify dahil) | 1.000 (paylaşımlı) |
| ECC ve SM2 (Sign ve Verify dahil) | 1.000 (paylaşımlı) |
| ML-DSA (Sign ve Verify) | 1.000 (paylaşımlı) |
| CloudHSM key store | 1.800; ayarlanamaz |
| External key store | 1.800; ayarlanamaz |
| GenerateDataKeyPair ECC_NIST_P256 | 100 |
| GenerateDataKeyPair ECC_NIST_EDWARDS25519 | 100 |
| GenerateDataKeyPair RSA_2048 | 20 |
| GenerateDataKeyPair RSA_3072 | 4 |
| GenerateDataKeyPair RSA_4096 | 1 |
| GetPublicKey | 2.000 |
| DescribeKey | 2.000 |
| CreateKey | 5 |
| EnableKeyRotation | 15 |

Kritik notlar şunlardır. Kota hesap ve bölge genelindedir; tüm principal'lar ve AWS servislerinin sizin adınıza yaptığı çağrılar dahildir. Sign ve Verify aynı kotayı paylaşır; Argus hem imzalar hem doğrularsa aynı 1.000'i böler. CloudHSM key store'un 1.800'lük kotası ayarlanamaz; en güvenli seçenek için CloudHSM destekli KMS anahtarı seçilirse tavan sabittir. Diğer tüm kotalar Service Quotas ile artırılabilir ancak AWS üst sınırı yayımlamamaktadır.

> **AWS dokümantasyonundaki tutarsızlık.** Tablo ECC için 1.000 derken Singapur örnek paragrafında RSA asimetrik ile saniyede 500'e kadar ek çağrı ve ECC ile 300'e kadar ek çağrıdan söz edilmektedir. Argus planlamasında muhafazakâr olan 300-500 rakamı varsayılmalı veya AWS'ye teyit ettirilmelidir.

### B.2 AWS KMS'in desteklediği imza algoritmaları

| Key spec | İmza algoritması |
|---|---|
| RSA_2048, RSA_3072, RSA_4096 | RSASSA_PSS_SHA_256/384/512 (tercih edilen), RSASSA_PKCS1_V1_5_SHA_256/384/512 |
| ECC_NIST_P256 | ECDSA_SHA_256 |
| ECC_NIST_P384 | ECDSA_SHA_384 |
| ECC_NIST_P521 | ECDSA_SHA_512 |
| ECC_SECG_P256K1 | ECDSA_SHA_256 |
| ECC_NIST_EDWARDS25519 | ED25519_SHA_512 (MessageType RAW), ED25519_PH_SHA_512 (MessageType DIGEST) |
| ML_DSA_44, ML_DSA_65, ML_DSA_87 | ML_DSA_SHAKE_256; post-quantum, FIPS 204 |

Argus için üç sonuç çıkar. AWS KMS artık Ed25519 ve EdDSA desteklemektedir, yani RFC 8037'deki `EdDSA` JWS algoritması kullanılabilir; modern bir IdP için doğru seçimdir. ED25519_SHA_512 `MessageType: RAW` gerektirir, yani ön hash yapılamaz ve tüm JWT imzalama girdisi (header ve payload) ağ üzerinden KMS'e gönderilmek zorundadır; büyük claim setlerinde bu hem gecikme hem bant genişliği maliyetidir. ECDSA'da ise 32 baytlık digest gönderilebilir, dolayısıyla EdDSA imza başına KMS modelinde ECDSA'dan daha pahalıdır. ED25519_PH_SHA_512 ile DIGEST kullanılırsa girdi iki kez hash'lenir; AWS bunu açıkça uyarmaktadır.

### B.3 AWS KMS fiyatlandırması

Her KMS anahtarı ayda 1 USD'dir ve saatlik orantılanır. Standart işlemler 10.000 istek başına 0,03 USD'dir. Asimetrik imzalama 10.000 istek başına 0,15 USD'dir.

> **Kısmen doğrulanmıştır.** Fiyat sayfasının key spec başına tam tablosu çıkarılamamıştır; yukarıdaki iki rakam sayfadaki örneklerden alınmıştır (S3 örneği 0,03 USD, dosya imzalama örneği 0,15 USD). RSA-2048 ile diğer asimetrik spec'ler arasında fiyat farkı olabilir; satın alma öncesi Pricing Calculator ile teyit edilmelidir.

Maliyet matematiği: her JWT bir KMS Sign çağrısı ve 10.000 istek başına 0,15 USD varsayımıyla:

| Token/sn | Günlük istek | Günlük maliyet | Aylık maliyet |
|---|---|---|---|
| 100 | 8.640.000 | 129,60 USD | Yaklaşık 3.888 USD |
| 500 | 43.200.000 | 648 USD | Yaklaşık 19.440 USD |
| 1.000 (AWS ECC kota tavanı) | 86.400.000 | 1.296 USD | Yaklaşık 38.880 USD |

Karşılaştırma: hibrit modelde 15 dakikalık ara anahtar ömrüyle günde 96 KMS Sign çağrısı yapılır ve aylık maliyet yaklaşık 0,004 USD'dir, yani on milyon kat daha ucuzdur.

### B.4 GCP Cloud KMS kotaları

16 Şubat 2026 öncesindeki eski model:

| Koruma seviyesi | Kota |
|---|---|
| Software-backed | 60.000 QPM, yani 1.000 QPS; çağıran proje |
| HSM simetrik | Bölge başına 500 QPS; barındıran proje |
| HSM asimetrik | Bölge başına 50 QPS |
| External (Cloud EKM) | Bölge başına 100 QPS |

16 Şubat 2026 sonrasındaki token tabanlı model:

| Kota | Değer | Uygulama |
|---|---|---|
| Software kullanımı | 6.000.000 TPM | Yumuşak |
| HSM kullanımı | 3.000.000 TPM | Yumuşak |
| External KMS kullanımı | 10.000 TPS | Katı |

HSM anahtarlarında asimetrik imzalama token maliyetleri:

| Anahtar tipi | HSM token / işlem |
|---|---|
| RSA-2048 | 1.500 |
| RSA-3072 | 3.500 |
| RSA-4096 | 14.000 |
| EC P-224, P-256, secp256k1 | 4.500 |
| EC P-384, P-521 | 7.000 |

Bu değerlerden türetilen hesaplama şudur; bunlar Google'ın yayımladığı işlem/sn rakamları değildir. EC P-256 için 3.000.000 bölü 4.500 dakikada 666 imza, yani saniyede yaklaşık 11 imza eder. RSA-2048 için 3.000.000 bölü 1.500 dakikada 2.000 imza, yani saniyede yaklaşık 33 imza eder. RSA-4096 için 3.000.000 bölü 14.000 dakikada 214 imza, yani saniyede yaklaşık 3,6 imza eder.

Bu kota yumuşak uygulanır ve artırılabilir; ancak başlangıç noktası çok düşüktür.

GCP fiyatlandırması doğrulanamamıştır; `cloud.google.com/kms/pricing` sayfası çekilirken kesilmiştir ve manuel kontrol gerekmektedir.

Cloud HSM ile software karşılaştırması: software koruma seviyesi altı kat daha yüksek token bütçesine sahiptir ve eski modelde zaten 1.000 QPS limiti vardı. HSM'e geçmek Argus için throughput'u yaklaşık yirmi kat düşürür.

### B.5 Azure

Özet A.3'te verilmiştir: Key Vault'ta HSM ECC vault başına 200 TPS, abonelik genelinde 1.000 TPS'tir. Managed HSM'de P-256 partition başına 330/sn, gerçekçi olarak instance başına 660-990/sn, en fazla beş instance ile yaklaşık 3.300-4.950/sn'dir.

### B.6 Gecikme

AWS, GCP ve Azure'un asimetrik `Sign` API'si için yayımlanmış p50 veya p99 gecikme rakamı bulunamamıştır. Yapılan aramalar şunlardır: AWS Security Blog'un "How to verify AWS KMS signatures in decoupled architectures at scale" yazısı (19 Mayıs 2021) hiçbir gecikme veya throughput sayısı vermemektedir. AWS re:Post'taki "KMS Signing performance with Asymmetric ECC_NIST_P256 key is slow" başlıklı soru sayfası HTTP 403 döndürmüş ve içerik alınamamıştır; başlığın kendisi bir sinyaldir, müşteriler ECC_NIST_P256 imzalamayı yavaş bulmaktadır.

Kaynaklı olarak söylenebilecekler şunlardır. AWS'nin kendi argümanına göre KMS API'si imza doğrulama için düşük gecikme veya yüksek throughput gereksinimi olan ve AWS KMS API istek kotalarını aşan sistemlerde ve AWS KMS API çağrılarını en aza indirerek maliyet optimize etmek isteyenlerde pratik değildir; önerilen çözüm bir kez KMS'te imzalamak, public key'i dağıtmak ve yerelde doğrulamaktır. Cloudflare'in uzak anahtar sunucusu argümanına göre ek gecikme maliyeti sunucudan key server'a gidiş dönüş süresine karşılık gelir ve key server dünyanın diğer ucundaysa bir saniyeye kadar çıkabilir. Bilinen alt sınır şudur: KMS Sign en iyi ihtimalle bir VPC içi HTTPS RPC ile HSM işlem süresidir. Azure Managed HSM'in P-256 için partition başına 330 işlem/sn değeri, tam boru hatlı çalışmada yaklaşık 3 ms'lik HSM tarafı servis süresi ima eder; bu throughput'tan türetilmiş bir alt sınırdır, gecikme ölçümü değildir ve ikisi karıştırılmamalıdır.

**Argus için eylem maddesi.** Kendi bölgemizde, kendi VPC'mizde `hey`, `vegeta` veya `k6` ile 60 saniyelik bir KMS Sign yükü koşturulup p50, p95 ve p99 ölçülür. Bu, mimari karar verilmeden önce yapılacak ilk iştir.

### B.7 Sonuç: imza başına KMS ile ulaşılabilir token hızı

**Senaryo A: her JWT için bir AWS KMS Sign (ECC P-256).** Tavan 1.000 token/sn'dir; hesap ve bölge başınadır, Sign, Verify ve DeriveSharedSecret ile paylaşılır ve ayarlanabilir. Bu 1.000/sn aynı hesaptaki tüm ECC KMS anahtar kullanımıyla paylaşılır. Maliyet aylık yaklaşık 38.880 USD'dir. Token endpoint'inin p99'una bir tam ağ gidiş dönüşü ve HSM süresi eklenir; bu ölçülmemiştir. KMS bölge içi bir bağımlılıktır, dolayısıyla Argus'un erişilebilirliği KMS'in erişilebilirliğinin altına düşer.

**Senaryo B: GCP Cloud KMS HSM.** Yeni token modelinden türetildiğinde yaklaşık 11 token/sn, eski modelde 50 token/sn'dir ve kota artırımı gerekir. Software koruma seviyesinde 1.000 QPS'tir.

**Senaryo C: Azure Managed HSM.** P-256 ile iki veya üç partition'da instance başına yaklaşık 660-990 token/sn, en fazla beş instance ile yaklaşık 3.300-4.950 token/sn'dir. En iyi bulut KMS seçeneğidir ancak beş instance limitinde sabit bir tavanı vardır.

**Senaryo D: AWS CloudHSM hsm2m.medium doğrudan, KMS olmadan.** Altı HSM'lik küme EC P-256 ile 7.000 token/sn verir. Maliyet altı adet hsm2m.medium'un saatlik ücretidir ve bu fiyat doğrulanmamıştır. Ancak FIPS modunda EdDSA yoktur ve login gecikmesi yüksektir.

**Senaryo E: hibrit model, Argus'un yapması gereken.** İmzalama CPU'da yapılır; Cloudflare'in ölçümüne göre c5.xlarge (4 vCPU) üzerinde yaklaşık 44.000 ECDSA imza/sn ve ortalama 22,5 µs'dir. Gerçekçi JWT serileştirme ve tahsis yüküyle bunun %10-20'si alınır, yani düğüm başına 4.000-9.000 token/sn elde edilir ve yatay ölçeklenir. KMS çağrısı yalnızca ara anahtar rotasyonunda yapılır, günde yaklaşık 100 çağrıdır; kota sorunu yoktur ve maliyet sıfıra yakındır. Token endpoint'inin p99'undan ağ gidiş dönüşü tamamen kalkar.

Karar şudur: hibrit model 40 ile 4.000 kat arası throughput avantajı ve milyon kat maliyet avantajı sağlar.

---
## C. Hibrit model: kim gerçekten yapıyor

Bu, Argus'un en kritik mimari sorusudur. İyi haber şudur: bu tam olarak yerleşik bir endüstri kalıbıdır.

### C.1 Cloudflare Delegated Credentials for TLS

Bu, Argus'un yapmak istediğinin TLS bağlamındaki birebir karşılığıdır.

Sertifika sahibi kısa ömürlü bir anahtar üretir ve onu bir servise delege eder; Cloudflare bunu bir vekaletname metaforuyla anlatır ve sunucunun kendi sunucularına sınırlı bir süre için TLS sonlandırma yetkisi verdiğini söyler. Azami geçerlilik 24 saattir; gerekçe açıkça belirtilmiştir, bir anahtara geçici erişim, çok ileri tarihte başlayan çok sayıda delegated credential imzalanmasına imkân verebilir. Tasarım motivasyonu doğrudan gecikmedir: Keyless SSL'in pull tabanlı modeli her handshake'te uzak key server'a RPC gerektiriyordu; Delegated Credentials push tabanlıdır ve kısa ömürlü bir yetkilendirme anahtarı periyodik olarak sunucuya gönderilip handshake'ler için kullanılır. Mekanizma bir X.509 uzantısıyla opt-in'dir; bu, kısa süreli anahtar erişimi olan bir saldırganın kötüye kullanmasını engeller. Standart, blog yazıldığında `draft-ietf-tls-subcerts-04` idi.

| Cloudflare Delegated Credentials | Argus karşılığı |
|---|---|
| Uzun ömürlü sertifika anahtarı, HSM'de | Kök imzalama anahtarı, KMS veya HSM'de |
| Delegated Credential, 24 saat veya daha kısa | Ara JWT imzalama anahtarı, bellekte |
| Delegated Credential'ı imzalayan uzun ömürlü anahtar | KMS Sign ile ara anahtarın imzalanması ve attest edilmesi |
| Edge sunucusunun handshake'i yerel yapması | Argus düğümünün JWT'yi yerel imzalaması |
| Azami 24 saat kuralı | Ara anahtar TTL üst sınırı |

### C.2 HashiCorp Vault seal ve unseal: envelope kalıbının referans uygulaması

Üç katmanlı bir hiyerarşi vardır. Encryption key, yani keyring, storage'daki verinin çoğunu şifreler. Root key keyring'i şifreler. Unseal key root key'i şifreler.

Auto-unseal ile KMS root key'i şifreler ve saklar. Vault başlarken bir kez KMS'e bağlanıp root key'i çözer; sonrasında tüm kripto işlemleri yerel keyring ile yapılır. Dokümantasyona göre KMS, şifre çözmeyi sunucu başlangıcında ve recovery key yetkilendirmesi gerektiren işlemler sırasında (örneğin root token üretiminde) gerçekleştirir.

Bu tam olarak Argus'un istediği desendir: KMS başlangıçta ve rotasyonda çağrılır, istek başına değil.

Shamir seal varsayılandır; unseal key Shamir Secret Sharing ile paylaşılır ve operatörler eşik değere kadar pay girer. Auto-unseal'de operatörler recovery key alır. Seal Wrap (Enterprise) hassas değerler için ek bir şifreleme katmanıdır ve storage kompromizasyonuna karşı derinlemesine savunma sağlar.

### C.3 SPIFFE ve SPIRE KeyManager: karşı örnek

Argus bu deseni uygulamamalıdır.

Mevcut plugin'ler şunlardır: yerel disk, bellek, AWS KMS, GCP KMS, Azure Key Vault ve HashiCorp Vault.

aws_kms plugin tasarımında anahtar çiftleri KMS'te CMK olarak yaratılır ve tutulur; özel anahtar KMS'ten hiç çıkmaz. SVID'ler ihtiyaç oldukça imzalanır, yani her SVID için bir KMS Sign çağrısı yapılır. Desteklenen tipler `rsa-2048`, `rsa-4096`, `ec-p256` ve `ec-p384`'tür. Anahtar hijyeni disiplini şöyledir: açıklama formatı `SPIRE_SERVER/{TRUST_DOMAIN}`'dir; alias'sız ve 48 saatten eski anahtarlar silinir; `LastUpdatedDate` değeri iki haftadan eski alias'lar anahtarlarıyla birlikte budanır; aktif anahtarlarda altı saatte bir liveness sinyali yenilenir.

Ders şudur: SPIRE işlem başına KMS modelini seçmiştir. SVID üretim hızında, yani workload attestation başına dakikalar veya saatler ölçeğinde, bu kabul edilebilirdir. JWT issuance hızında değildir. Argus SPIRE'ın bu kararını kopyalarsa B bölümündeki duvara çarpar.

Buna karşılık SPIRE'ın anahtar budama disiplini — 48 saatlik orphan temizliği, altı saatlik liveness ve iki haftalık alias budaması — doğrudan kopyalanmalıdır; üretim kalitesinde bir anahtar yaşam döngüsü yönetimidir.

### C.4 Sigstore Fulcio: ara CA kalıbı

Fulcio, offline bir root CA'ya zincirlenen bir ara CA olarak çalışır; dokümantasyona göre KMS imzalama arka ucu öncelikle ara CA olarak kullanılmak üzere tasarlanmıştır. Ara sertifika `pathlen:0` Basic Constraints taşır, yani yalnızca end-entity sertifika verebilir ve sık rotasyon gerektirmemesi için yaklaşık üç yıl ömürlüdür. Fulcio kısa ömürlü kod imzalama sertifikaları verir ve efemer anahtarı OIDC kimliğine bağlar. Root anahtar materyali TUF deposu üzerinden yönetilir (`sigstore-root-signing`); GCP KMS timestamping anahtarı `projects/sigstore-root-signing/locations/global/keyRings/root/cryptoKeys/timestamp` yolundadır. Anahtar kısa ömürlü olduğu için, anahtarın ve onunla ilişkili sertifikanın artefakt imzalandığı anda geçerli olduğunu attest edecek bir mekanizma gerekir; bu mekanizma transparency log'dur, yani Rekor'dur.

Argus'a dersi şudur: kısa ömürlü anahtar kullanılıyorsa o anda geçerli olduğuna dair bir kanıt gerekir. JWKS'te geçmiş `kid` değerlerinin tutulması ve isteğe bağlı bir transparency log bunu sağlar.

### C.5 Let's Encrypt ve Boulder: anahtar töreni

`ceremony` aracı sertifikaları ve anahtarlarını üretir. Anahtarlar HSM içinde üretilir; PKCS#11 modülü ve slot ile erişilir ve object label ile tanımlanır, örneğin "intermediate signing key"; hem public hem private nesne bu label ile saklanır. CSR, HSM'deki anahtarla imzalanır. Anahtar tipi RSA (exponent 65537, `rsa-mod-length` ile modül uzunluğu) veya ECDSA'dır (`ecdsa-curve`). Fiziksel erişim ve tüm HSM yönetim işlemleri çok kişili kontrol gerektirir; ayrıntı CCS 2019 makalesindedir.

Argus'a dersi şudur: kök anahtar töreni için `boulder/cmd/ceremony`'nin config formatı referans alınır; yıllardır bir kamu CA'sında üretimde çalışan tek açık kaynak tören aracıdır.

### C.6 Cloudflare Keyless SSL: pull modelinin maliyeti

Key server bir worker havuzu modeli kullanır: her istemci bağlantısının kendi reader ve writer goroutine çifti vardır, kripto iş ise global havuzdan çekilen ayrı worker goroutine'lerde yapılır. Hedef gecikmeyi en aza indirirken saniyedeki imzalama işlemini azamiye çıkarmaktır. ECDSA ve RSA için ayrı worker havuzları bulunur, çünkü RSA bir mertebe daha pahalıdır. ECDSA gecikmeyi düşürmek için önceden hesaplanmış rastgele değerler kullanır. Gecikme maliyeti yalnızca ilk handshake'tedir; TLS Session Resumption özel anahtar gerektirmez.

Argus'a dersi şudur: ayrı bir imzalama servisi kurulursa Cloudflare'in worker havuzu, algoritma başına havuz ve önceden hesaplama deseni kopyalanır. Ancak JWT'lerde session resumption analoğu yoktur; her token yeni bir imzadır. Bu nedenle uzak imza servisi TLS'ten daha kötü bir uyumdur.

### C.7 AWS Encryption SDK: data key caching

Caching CMM (cryptographic materials manager) ile yerel bir cache birlikte çalışır ve güvenlik eşikleri uygular.

AWS'nin açık uyarısı şudur: data key caching, AWS Encryption SDK'nın dikkatle kullanılması gereken opsiyonel bir özelliğidir. Varsayılan olarak SDK her şifreleme işlemi için yeni bir data key üretir. Genel olarak data key caching yalnızca performans hedeflerini karşılamak için gerektiğinde kullanılmalı ve maliyet ile performans hedeflerini karşılayacak asgari miktarda caching yapıldığından emin olmak için güvenlik eşikleri kullanılmalıdır.

Güvenlik eşikleri azami yaş, şifrelenen azami mesaj sayısı ve şifrelenen azami bayttır. Modern alternatif AWS KMS Hierarchical keyring'dir ve AWS Encryption SDK for Rust 1.x bunu desteklemektedir; Rust ekosisteminde referans implementasyon olarak incelemeye değerdir.

Argus'a doğrudan uyarlaması şudur: ara imzalama anahtarına üç eşik birden konur. `max_age` örneğin 15 dakikadır. `max_signatures` örneğin 5.000.000 imzadır. Herhangi biri aşılırsa rotasyon zorunlu olur. Bu, AWS'nin tam olarak önerdiği disiplindir ve yalnızca zaman tabanlı rotasyondan daha güvenlidir.

### C.8 Argus için somut hibrit tasarım

**Anahtar hiyerarşisi.**

```
[Kök Anahtar]  — KMS / HSM'de, dışarı çıkmaz
      │              (ECC_NIST_P256 veya ECC_NIST_EDWARDS25519)
      │  KMS Sign  (günde ~96 çağrı)
      ▼
[Ara İmzalama Anahtarı]  — bellekte üretilir, 15 dk ömür
      │                     kök tarafından imzalanmış bir attestation ile
      │  yerel imza (22,5 µs)
      ▼
[JWT'ler]  — saniyede binlerce
```

**Ne kadar kısa yaşamalı.** Karar için üç girdi vardır: bellekten anahtar çalma riski penceresi için kısa olması iyidir; KMS bağımlılığı ve kesinti toleransı için uzun olması iyidir, çünkü KMS 30 dakika down olursa Argus çalışmaya devam etmelidir; JWKS yayın gecikmesi E bölümündeki matematiğe bağlıdır.

Öneri 15 dakika üretim ömrü ve 60 dakika hard cap'tir. On beş dakika, saatte dört rotasyon ve günde 24 saat ile lineage başına 96 KMS çağrısı eder. Bu, Cloudflare'in 24 saatlik delegated credential üst sınırından çok daha muhafazakârdır. KMS 45 dakika kesinti yaşasa bile mevcut anahtarın hard cap'ine kadar Argus token vermeye devam eder.

> **Kritik kural.** Ara anahtar TTL'i her zaman verilen access token TTL'inden uzun olmalıdır; aksi hâlde hâlâ geçerli token'lar için doğrulama anahtarı JWKS'ten kalkar.

**JWKS'te nasıl yayınlanır ve attest edilir.**

Birinci seçenek basittir ve önerilir: ara anahtarın public kısmı doğrudan JWKS'e bir `kid` ile eklenir. Kök anahtar JWKS'te görünmez; yalnızca bant dışı bir güven çıpasıdır. Artısı standart OIDC olması ve hiçbir istemci değişikliği gerektirmemesidir. Eksisi kök anahtarın delegasyonunun doğrulanamamasıdır; JWKS endpoint'i kompromize olursa saldırgan kendi anahtarını ekleyebilir.

İkinci seçenek Cloudflare delegated credentials benzeridir ve en güvenli olandır: JWKS girdisine kök anahtarla imzalanmış bir delegation attestation eklenir; bu bir `x5c` zinciri veya `x-argus-delegation` gibi özel bir alan olabilir.

```
attestation = KMS.Sign(root_key, CBOR{ kid, jwk_thumbprint, not_before, not_after, issuer })
```

Artısı JWKS endpoint kompromizasyonunun tek başına yetmemesi ve istemcinin kök anahtara pinlenebilmesidir. Eksisi standart dışı olmasıdır; genel istemciler yok sayar, ancak bu zarar vermez ve yüksek güvenlikli istemciler, örneğin Argus'un kendi SDK'sı, doğrulayabilir.

Argus en güvenli iddiasındaysa ikinci seçenek birincinin üstüne, kırıcı olmayan bir alan olarak eklenir.

**Anahtar töreni.** Kök anahtar KMS veya HSM içinde üretilir ve asla export edilmez; `boulder/cmd/ceremony` deseni izlenir. Çok kişili kontrol uygulanır; AWS'de KMS key policy ile MFA'lı ayrı IAM principal'ları, HSM'de M-of-N kartlar kullanılır. Tören videoya kaydedilir ve tanık imzalı tutanak tutulur; bu Let's Encrypt ve WebTrust pratiğidir. Kök anahtar rotasyonu yılda bir kez yapılır veya hiç yapılmaz; Fulcio ara CA'sı üç yıl ömürlüdür.

**Hata modları ve karşılıkları.**

| Hata modu | Sonuç | Karşılık |
|---|---|---|
| KMS erişilemez ve rotasyon zamanı gelmiştir | Yeni ara anahtar üretilemez | Hard cap'e kadar mevcut anahtarla devam edilir; hard cap yaklaşırken alarm üretilir; degraded mode için uzatılmış TTL'li ikinci bir önceden imzalanmış anahtar hazır tutulur |
| Argus düğümü çöker ve ara anahtar kaybolur | Bellekteki anahtar gider | Sorun değildir; yeniden başlarken yeni anahtar üretilir. Ancak düğümler arası anahtar paylaşımı yapılıyorsa, yani aynı `kid` kullanılıyorsa, koordinasyon gerekir |
| Her düğüm kendi ara anahtarını üretir | JWKS'te N kat anahtar bulunur | Kabul edilebilirdir ve aslında daha güvenlidir, çünkü blast radius küçülür. JWKS boyutu izlenir; 50'den fazla anahtar olmamalıdır |
| Ara anahtar bellekten çalınır | Saldırgan TTL boyunca sahte token üretir | Tek savunma TTL'i kısaltmaktır; ayrıca F ve G bölümleri uygulanır |
| Saat kayması | `not_before` ve `not_after` hataları | NTP zorunludur; attestation'da artı eksi beş dakika tolerans tanınır |
| Split-brain: iki düğüm aynı `kid`'i üretir | Doğrulama tutarsızlığı | `kid` değeri JWK thumbprint'tir (RFC 7638) ve çakışma matematiksel olarak imkânsızdır |
| JWKS yayını yeni anahtardan geç kalır | `kid` bilinmez ve doğrulama hatası oluşur | Publish-before-use kuralı uygulanır; E bölümü |
| Rotasyon fırtınası, tüm düğümler aynı anda | KMS throttle eder | Rotasyon zamanına artı eksi %20 jitter eklenir |

---

## D. HashiCorp Vault Transit engine

### D.1 IdP için uygun mu

Kısa cevap şudur: ara anahtar sarmalayıcı olarak evet, JWT başına imzalayıcı olarak hayır.

### D.2 Yetenekler

Desteklenen imza anahtarı tipleri Ed25519 (imzalama, imza doğrulama ve anahtar türetme destekler), ECDSA P-256, P-384 ve P-521, RSA-2048, RSA-3072 ve RSA-4096'dır. ML-DSA, hibrit algoritmalar ve SLH-DSA yalnızca Enterprise sürümündedir.

`batch_input` desteği kritik bir throughput kaldıracıdır:

```json
{ "batch_input": [
    {"input": "adba32==", "context": "abcd", "reference": "jwt-1"},
    {"input": "aGVsbG8=", "context": "efgh", "reference": "jwt-2"}
]}
```

Sonuçlar `batch_results` dizisinde giriş sırası korunarak döner ve `reference` alanıyla eşleme yapılır. Bu, HTTP ve auth overhead'ini N imzaya amorti eder; Argus bir token endpoint batch'i topluyorsa gerçek bir kazançtır.

Versiyonlama ve rotasyon yerleşiktir: `key_version` tamsayıdır ve 0 en güncel anlamına gelir, değer `min_encryption_version` değerinden büyük veya ona eşit olmalıdır; `min_encryption_version` ve `min_decryption_version` key config endpoint'indedir. Vault'un uyarısına göre sık rotasyon, arşiv için storage backend'in kaldıramayacağı kadar büyük bir storage girdisi boyutuna yol açabilir; bu Raft ve Paxos gibi backend'lerde geçerlidir ve çözüm olarak zaman tabanlı anahtar isimlendirme önerilir.

Azami HTTP istek boyutu DoS önlemi olarak 32 MB'dir.

### D.3 Gerçek benchmark sayıları

**HashiCorp'un resmî benchmark blogu (16 Temmuz 2026).** Ortam AWS us-west-2, Vault Enterprise v1.17.3+ent, integrated Raft storage, yük aracı k6 ve metrikler Datadog'dur.

| Bulgu | Sayı |
|---|---|
| PKI sertifika verme, tek kullanıcı baseline'ı | Yaklaşık 560 ms |
| PKI knee point | Yaklaşık 25 eşzamanlı kullanıcı |
| PKI revocation timeout başlangıcı | 100'den fazla eşzamanlı kullanıcı |
| SSH-CA RSA-2048 knee point | Yaklaşık 100 sanal kullanıcı |
| SSH-CA RSA-2048 doygunlukta CPU | %92-96 |
| SSH-CA RSA-2048 doygunluk | Yaklaşık 250 sanal kullanıcı |
| SSH-CA Ed25519 knee point | Yaklaşık 200 sanal kullanıcı |
| SSH-CA Ed25519 doygunlukta CPU | %40-42 |
| PKI algoritma karşılaştırması | RSA, Ed25519 ve ECDSA arasında asgari performans farkı |

HashiCorp bu blogda transit sign için işlem/sn yayımlamamaktadır ve bu açıkça belirtilmelidir.

Ancak PKI'nin 560 ms'lik tek kullanıcı baseline'ı çok şey söyler: Vault'un HTTP, policy, audit ve storage yolu ağırdır. Transit sign daha hafif olsa da 22,5 µs'lik yerel ECDSA imzayla kıyaslanamaz; en az üç büyüklük mertebesi fark vardır.

Ed25519'un RSA'ya göre iki kat eşzamanlılık ve yarı CPU avantajı vardır; Argus Vault kullanacaksa Ed25519 seçmelidir.

**37.000 işlem/sn iddiası doğrulanamamıştır.** Bu rakam Stenio Ferreira'nın (HashiCorp Solutions Engineer) Medium yazısında geçmektedir; sayfa çekilirken HTTP 403 dönmüş ve doğrulanamamıştır. Ayrıca arama snippet'ine göre bu, çok elverişli bir test ortamında transit'in genel kullanımı içindi, muhtemelen encrypt ve decrypt için, sign için değil. Argus planlamasında bu sayı kullanılmamalıdır.

**Benchmark araçları.** `vault-benchmark` HashiCorp'un resmî ve açık kaynak aracıdır; auth metotlarını ve secrets engine'leri yükler, HTTP isteklerini Vegeta kütüphanesiyle üretir ve throughput, gecikme ile başarı oranını ölçer. Topluluk tarafında `wrk` tabanlı bir transit throughput testi mevcuttur. HashiCorp'un Raft tuning notları destek portalındadır.

Vault dokümantasyonunun kendi uyarısı şudur: transit secret engine, yani şifreleme servisi, Vault sunucusundaki en yorucu işlemlerden biridir, çünkü sunucunun şifreleme algoritmasını çalıştırmasını gerektirir.

### D.4 Yüksek erişilebilirlik

Vault HA aktif ve standby düğümlerden oluşur; integrated Raft kullanılır. Performance Standby (Enterprise) okumayı ölçekler. Transit sign bir yazma değildir ancak aktif node'a gider; Performance Standby'ların transit sign'ı servis edip edemediği doğrulanamamıştır. Argus için tek aktif node darboğazı riski vardır.

### D.5 Lisans değişimi ve OpenBao

Vault Ağustos 2023'te BUSL 1.1'e geçmiştir. OpenBao, Vault'un açık kaynak sürümünün topluluk fork'u olarak 2023'te yaratılmış ve Linux Foundation'a bağışlanmıştır, yani açık yönetişim altındadır. Haziran 2025'te OpenSSF sandbox projesi olmuştur.

OpenBao'nun 2026 sürüm verisi:

| Sürüm | Tarih |
|---|---|
| v2.6.2 | 18 Ağustos 2026; güvenlik ve hata düzeltmeleri |
| v2.6.1 | 22 Temmuz 2026 |
| v2.6.0 | 14 Temmuz 2026; namespace sealing ve workflow desteği |
| v2.6.0-beta | 22 Haziran 2026 |
| v2.5.5 | 17 Haziran 2026; çoklu güvenlik açığı düzeltmesi |

2.0 üretime hazır sürümü Eylül 2024'te çıkmıştır. Namespaces ve yatay okuma ölçeklenebilirliği eklenmiş, yani Vault Enterprise'ın ücretli özellikleri açık kaynağa taşınmıştır. Sekiz şirket ticari destek sunmaktadır, aralarında ControlPlane bulunur. NVIDIA OpenBao'yu benimsemiştir.

**Değerlendirme.** OpenBao 2026'da canlı ve ciddi bir projedir: aylık sürüm ritmi, Linux Foundation yönetişimi, NVIDIA gibi bir referans ve Vault'un kapalı özelliklerini açması. Argus için Vault yerine OpenBao makuldür, özellikle Argus kendisi açık kaynaksa BUSL bulaşmasından kaçınmak için. Ancak üçüncü taraf araç ekosistemi hâlâ Vault'un gerisindedir. Ayrıca Argus'un asıl ihtiyacı ara anahtar sarmalama olduğu için her ikisi de opsiyonel bir bileşendir; bulut KMS zaten yeterlidir.

### D.6 Argus'ta Vault ve OpenBao'nun yeri

| Kullanım | Uygun mu |
|---|---|
| Her JWT için transit sign | Hayır; üç mertebe yavaştır ve tek node darboğazı vardır |
| Ara anahtarı sarmalama ve açma (envelope) | Evet; dakikada birkaç çağrıdır |
| Veritabanı şifreleri ve OAuth client secret'larını saklama | Evet; klasik kullanımdır |
| Argus'un TLS sertifikaları (PKI engine) | Evet, ancak 560 ms baseline'a dikkat edilir ve sertifikalar önceden verilir |
| Argus düğümlerinin kimlik doğrulaması (AppRole veya K8s auth) | Evet |

---

## E. Anahtar rotasyonu (JWKS)

### E.1 Standart dayanağı

**RFC 7517 (JWK) §4.5, `kid` parametresi.** `kid` parametresi belirli bir anahtarı eşleştirmek için kullanılır; örneğin anahtar geçişi sırasında bir JWK Set içindeki anahtarlar arasından seçim yapmak için. Bir JWK Set içinde `kid` değerleri kullanıldığında, set içindeki farklı anahtarların farklı `kid` değerleri kullanması önerilir. `kid` büyük küçük harf duyarlıdır ve opsiyoneldir; Argus için zorunlu yapılmalıdır. JWS ve JWE'deki `kid` header parametresiyle eşleşir.

Öneri şudur: `kid` değeri RFC 7638 JWK Thumbprint (SHA-256) olur. Böylece çakışma imkânsızdır, değer deterministiktir ve anahtar materyalinden türetildiği için ayrı bir kayıt tutmaya gerek kalmaz.

**OpenID Connect Core §10.1.1, asimetrik imzalama anahtarlarının rotasyonu.** RP, ID Token doğrularken `kid` header'ına bakar; anahtar yerel önbellekte yoksa `jwks_uri` yeniden çekilir. Bu, kesintisiz rotasyonun temel mekanizmasıdır.

> **Kaynak notu.** Bu bölümün tam metni çekilememiştir; sayfa kesilmiştir. Yukarıdaki, ikincil kaynaklardan yapılmış bir özettir ve spec metni doğrudan doğrulanmalıdır.

### E.2 Gerçek sağlayıcılar ne yapıyor

**Okta.** Yayımlanmış rotasyon periyodu yılda dört kez, yani üç ayda birdir ve bildirimsiz değişebilir. Yeni anahtarlar normalde rotasyondan birkaç hafta önce üretilir; böylece downstream müşteri önbellekleme mekanizmalarının güncellenmesi sağlanır. İstemciler `jwks_uri` yanıtını standart HTTP Cache-Control header'larındaki yönergelere göre önbelleklemelidir. Okta önbellek süresini rotasyona olan yakınlığa göre dinamik olarak ayarlamaktadır. Anahtarların rotasyondan sonra JWKS'te tam olarak ne kadar kaldığını yayımlamamaktadır.

Öne çıkan nokta şudur: Okta yeni anahtarı kullanmadan haftalar önce yayımlamaktadır; bu publish-before-use kuralının en muhafazakâr uygulamasıdır.

**Auth0: üç anahtar modeli.** OIDC discovery dokümanı her zaman hem geçerli anahtarı hem sonraki anahtarı içerir; önceki anahtar henüz iptal edilmemişse onu da içerebilir. Aynı anda tek anahtarla imzalanır. Önceki anahtarla imzalanmış tüm token'lar, o anahtar açıkça iptal edilene kadar geçerli kalır. Otomatik rotasyon aralığı belirtilmemiştir; manuel rotasyon vurgulanmaktadır.

Bu model Argus için doğrudan kopyalanabilir: JWKS içeriği önceki (opsiyonel), geçerli ve sonraki anahtardan oluşur.

**Keycloak: aktif ve pasif.** Bir anda tek bir aktif anahtar çifti ve birden çok pasif anahtar bulunur. Aktif anahtar yeni imzalar üretir, pasif anahtar önceki imzaları doğrular ve rotasyon kesintisiz olur. Provider'lar Priority alanıyla sıralanır; aktif anahtar sağlayabilen en yüksek öncelikli provider seçilir. Eski anahtarlar süreleri dolana kadar JWKS endpoint'inde kalır. Varsayılan anahtar ömrü doğrulanamamıştır; erişilen kaynaklarda `rsa-generated` provider'ının varsayılan lifespan değeri bulunmamaktadır.

**Google: canlı gözlem.** 8 Eylül 2026'da `googleapis.com/oauth2/v3/certs` çekilmiştir; hepsi RSA ve RS256 olmak üzere dört anahtar bulunmuştur:

```
a8f80b512469959cdc1eeba44b066c2f79944779
ca622895d4d408c1b1089f874a0fa07bbc04b55e
943a3a5d7d919625a454e489b75c29adab57acba
f10f87405a979c1df36df26606734f33cd85c271
```

Google aynı anda dört anahtar yayımlamaktadır ve geniş bir overlap penceresi tutmaktadır. Google rotasyon periyodunu yayımlamamaktadır; bu yalnızca anlık bir gözlemdir.

**Duende IdentityServer: zamanlama önerisi.** Yeni anahtar JWKS'e eklenir ancak henüz imzalamada kullanılmaz; istemciler onu keşfedip önbelleğe alır; genellikle 24-48 saatlik bir duyuru periyodundan sonra yeni anahtarla imzalamaya başlanır ve eski anahtar doğrulama için kalır.

**Zalando: rotasyon formülü.** Anahtarın emekliye ayrılma zamanına azami token ömrü ve ek güvenlik süresi eklenerek public key'in düşürüleceği zaman bulunur. Süreç şudur: yeni anahtar çifti üretilir, public key JWK endpoint'inde yayımlanır, istemci önbellek yenilemesi için bir grace period beklenir, yeni anahtar aktif imzalayıcı yapılır, önceki aktif anahtar emekliye ayrılır ancak yayında kalır ve azami token ömrü kadar sonra JWKS'ten kaldırılır. Vurgu cache control header'larının önemli olduğu ve JWT'lerde `kid` ile hangi anahtarın kullanıldığının takip edildiğidir.

### E.3 Zamanlama matematiği

**Tanımlar.** `T_token` verilen en uzun token TTL'idir; access token ve ID token dahildir. `T_cache` `jwks_uri` üzerindeki `Cache-Control: max-age` değeridir. `T_client` en yavaş istemcinin JWKS yenileme periyodudur ve kontrolümüz dışındadır. `T_safety` güvenlik marjıdır. `T_sign` bir anahtarın aktif imzalama süresidir, Argus'ta ara anahtar TTL'idir.

**Kural 1: publish-before-use.**

```
T_publish_lead ≥ T_cache + T_client + T_safety
```

Yeni `kid` ile ilk token imzalanmadan önce, o anahtarın JWKS'te bu kadar süre bulunmuş olması gerekir.

Ancak Argus'ta ara anahtar 15 dakikada bir döner ve bu, klasik "48 saat önce yayınla" yaklaşımıyla uyumsuzdur. Çözüm iki katmanlıdır.

**Katman 1: ara anahtarlar, 15 dakikalık hızlı döngü.** `T_publish_lead` sağlanamaz, çünkü 15 dakika tipik önbellek TTL'lerinden kısadır. Bu nedenle `jwks_uri` üzerinde `Cache-Control: max-age=300, must-revalidate` kullanılır, yani beş dakika, kısa tutulur. `ETag` verilir ve `If-None-Match` ile 304 dönülür; bant genişliği maliyeti neredeyse sıfırdır. İstemcilere bilinmeyen `kid` görüldüğünde yeniden çekme davranışı zorunlu kılınır; OIDC §10.1.1 zaten bunu söyler ve Argus kendi SDK'sını yayımlıyorsa bunu SDK'da uygular. Yeni ara anahtar, kullanılmaya başlanmadan `T_cache + T_safety` kadar, yani 5 artı 5 eşittir 10 dakika önce JWKS'e eklenir; anahtar üretimi ile ilk kullanım arasında 10 dakikalık bir ısınma penceresi olur. On beş dakikalık rotasyon periyoduyla bu, her zaman iki veya üç anahtarın JWKS'te bulunduğu anlamına gelir. Kaldırma zamanı son imzadan sonra `T_token + T_safety` kadardır; `T_token` 15 dakika ise son imzadan 20 dakika sonra JWKS'ten çıkarılır. JWKS'teki toplam anahtar sayısı 10 dakika ısınma, 15 dakika aktif ve 20 dakika drenaj toplamının 15 dakikaya bölümüdür, yani yaklaşık üç anahtardır; bu makuldür.

**Katman 2: kök anahtar, yıllık yavaş döngü.** Okta ve Duende modeli izlenerek yeni kök anahtar haftalar önce yayımlanır; bu, delegation attestation'ı doğrulayan istemciler içindir. Fulcio deseni izlenerek üç yıllık ömür verilir ve sık rotasyon gerekmez.

**Kural 2: kaldırma zamanı.**

```
T_drop = T_last_signature_with_key + T_token_max + T_safety
```

Bu Zalando'nun formülüdür. `T_token_max` değeri kesinlikle bilinmelidir; Argus'ta refresh token'lar imzalıysa onlar da sayılır.

**Kural 3: en yavaş doğrulayıcıya göre planlama.** Bir servis beş dakikada bir, diğeri saatte bir ve bir mobil istemci her uygulama açılışında yeniliyorsa, grace period en yavaş doğrulayıcıyı yansıtmalıdır. Argus için `T_client` bilinemez; bu nedenle bilinmeyen `kid` görüldüğünde yeniden çekme davranışını zorunlu kılan, negatif önbellekli bir tasarım şarttır. Ayrıca `jwks_uri` üzerine rate limit konur, çünkü kötü niyetli bir yeniden çekme fırtınası DoS'a döner; ancak 429 yerine stale-while-revalidate verilir.

**Kural 4: token TTL'i ara anahtar TTL'inden kısa olmalıdır.**

```
T_token < T_sign
```

Aksi hâlde bir token, imzalandığı anahtar JWKS'ten kalkmadan önce süresi dolmaz. Argus'ta 15 dakikalık anahtar için access token marjla birlikte 10 dakika veya daha kısa olmalıdır.

**Cache-Control önerisi.**

```
Cache-Control: public, max-age=300, stale-while-revalidate=600, stale-if-error=86400
ETag: "<jwks-set-hash>"
```

`stale-if-error=86400` ile Argus'un JWKS endpoint'i çökerse istemciler 24 saat eski setle çalışır ve erişilebilirlik kazancı sağlanır. `stale-while-revalidate` arka planda yenileme yapar ve istemci gecikmesi oluşmaz.

### E.4 Otomatik rotasyon tasarımı

Her ara anahtar için durum makinesi şudur:

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

Aynı anda tam olarak bir ACTIVE anahtar bulunur; bunun düğüm başına mı küme başına mı olduğu karara bağlanır. PUBLISHED ve RETIRING anahtarlar da ACTIVE ile birlikte JWKS'tedir. DROPPED anahtar materyali `zeroize` edilir (F bölümü). Geçişler bir denetim kaydına yazılır: `kid`, thumbprint, zaman damgaları ve KMS attestation kimliği. Her geçişte `argus_jwks_keys{state="active|published|retiring"}` metriği güncellenir.

**Küme geneli tek anahtar mı, düğüm başına mı.**

| | Küme geneli tek anahtar | Düğüm başına anahtar |
|---|---|---|
| JWKS boyutu | Üç anahtar | Düğüm sayısı çarpı üç |
| Koordinasyon | Gereklidir; leader election veya etcd | Gerekmez |
| Blast radius | Tüm küme | Tek düğüm |
| KMS çağrısı | Günde 96 | Düğüm başına günde 96 |
| Karmaşıklık | Yüksek | Düşük |

Öneri düğüm başına anahtardır. On düğümde JWKS'te yaklaşık 30 anahtar olur ve bu bir sorun değildir; JWKS yaklaşık 10 KB'dir. Koordinasyon yokluğu ve küçük blast radius en güvenli hedefiyle uyumludur. Düğüm sayısı 30'u aşarsa shard başına anahtara geçilir.

---
## F. Rust'ta bellek içi sır hijyeni

### F.1 `zeroize`: mekanizma ve gerçek garantiler

Sürüm 1.9.0'dır; crates.io `updated_at` değeri 12 Haziran 2026'dır. Toplam 672.831.052 indirme, son 90 günde 168.883.175 indirme almıştır. docs.rs sayfası 3 Eylül 2026'da yayımlandığını göstermektedir ve bu crates.io API'siyle çelişmektedir; crates.io esas alınır. `zeroize_derive` 1.5.0 sürümündedir ve 90 günde 64.227.400 indirme almıştır.

**Nasıl çalışır.** `core::ptr::write_volatile` ve `core::sync::atomic` bellek bariyerleri kullanılır. Saf Rust'tır; FFI ve assembly yoktur. Tüm çekirdek sayı tiplerinde ve bunların slice'larında çalışır.

**Ne garanti eder.** Sıfırlama işleminin derleyici tarafından optimize edilip kaldırılamayacağı garanti edilir; bu LLVM'in volatile semantiğiyle sağlanır. Volatile ve volatile olmayan erişimleri karıştırmanın tanımsız davranış olup olmadığı endişesi Unsafe Code Guidelines Working Group içinde tartışılmış ve bu crate'teki kullanım deseni iyi tanımlanmış kabul edilmiştir.

**Ne garanti etmez.** docs.rs'deki açık ifadeler şunlardır. Mikromimari saldırılarda Spectre ve Meltdown benzeri saldırıların sıfırlanmış sırları örtülü kanallar üzerinden sızdırma potansiyeli hâlâ vardır; crate bu kanallar üzerinden sızıntı olmayacağına dair garanti vermez, çünkü bunlar altta yatan donanımın kusurlarıdır. `Vec`, `String` ve `CString` için backing buffer'ın tüm kapasitesi sıfırlanır, ancak önceki yeniden tahsislerin bıraktığı kopyalar garanti edilemez; bu nedenle doğru kapasiteyle initialize edilmeli ve sonradan yeniden tahsis engellenmelidir. Stack spilling söz konusudur: heap verisi Rust move semantiği üzerinden stack'te geçici kopyalar bırakabilir. Register temizleme kapsam dışıdır ve inline assembly veya rustc desteği gerektirir.

`Zeroizing<Z>` `Deref` ve `DerefMut` implement eden generic bir sarmalayıcıdır ve drop anında `zeroize()` çağırır; içinde sır tutan rastgele tipler için kullanılır.

`#[derive(ZeroizeOnDrop)]` bir marker trait ve custom derive'dır; her zaman sır içeren ve karmaşık invariant bakımı gerektiren tipler için önerilir.

### F.2 Assembly seviyesinde doğrulama

CipherStash'in 9 Ocak 2024 tarihli blog yazısı Rust zeroize'ın assembly ile, portable SIMD dahil, doğrulanmasını anlatır.

Bulguları şunlardır. `#[derive(Zeroize, ZeroizeOnDrop)]` ile ARM64 disassembly'sinde `strb wzr`, yani sıfır yazma komutları doğrulanmıştır; zeroize gerçekten çalışmaktadır. Elle yazılmış naif bir `Drop` implementasyonunda `[u8; 4]` için derleyici sıfırlama kodunu tamamen silmiştir; yazarın ifadesiyle derleyici bir nedenle sıfırlama kodunu gereksiz bulup optimize etmiştir. Aynı kod `[u32; 4]` için çalışmıştır; yani tip değişikliği optimizasyon davranışını değiştirmekte ve elle sıfırlama öngörülemez olmaktadır. Portable SIMD'de (`Simd<u16, 8>`) durum daha kötüdür: derleyici Drop implementasyonunu tamamen yok saymıştır ve zeroize crate'inin o tarihte portable SIMD desteği yoktu. Çözüm `ptr::write_volatile()` ile `compiler_fence()` kullanmaktır; ironik biçimde bellek güvenliği için `unsafe` gerekmektedir.

Argus için ders şudur: elle sıfırlama asla yazılmaz. `zeroize` kullanılır ve SIMD tipleri içeren yapılarda ekstra dikkat gösterilir.

### F.3 `secrecy`: ne yapar, ne yapmaz

Sürüm 0.10.3'tür; crates.io `updated_at` değeri 9 Ekim 2024'tür. Toplam 156.698.098, son 90 günde 37.989.495 indirme almıştır.

**Sağladıkları.** `SecretBox<T>` çekirdek sarmalayıcıdır ve parolalar, kripto anahtarlar ile access token'lar için kullanılır. `SecretString` `SecretBox<str>` için bir type alias'tır. `SecretSlice<T>` bulunur. `ExposeSecret` ve `ExposeSecretMut` trait'leri sır erişimini açık ve kolay denetlenebilir kılar. Redakte eden bir `Debug` implementasyonu kazara debug loglamayı engeller.

**Açıkça yapmadıkları.** Crate basit, `no_std` dostu ve `forbid(unsafe_code)` temelli güvenli bir implementasyonu tercih ettiğini ve `mlock(2)` ile `mprotect(2)` gibi daha gelişmiş bellek koruma mekanizmalarını sağlamadığını belirtir. Dokümantasyon gelişmiş koruma için `secrets` crate'ine yönlendirir.

Crate `zeroize ^1.6`'ya bağımlıdır ve opsiyonel `serde` desteği sunar; bu sır deserialization içindir.

**0.10.0 kırıcı değişiklikleri** (17 Eylül 2024; 0.9.0 atlanmıştır). Kaldırılanlar: generic `Secret<T>` kaldırılmış ve yerine `SecretBox<T>` gelmiştir; `alloc` özelliği kaldırılmış ve zorunlu bağımlılık hâline gelmiştir; `bytes` crate entegrasyonu kaldırılmıştır; `DebugSecret` trait'i kaldırılmıştır; stack tabanlı depolamanın kaldırılmasının sonucu olarak `SecretVec` kaldırılmıştır. Eklenenler: `SecretBox` artık type alias değil bir newtype'tır; `SecretSlice<T>` eklenmiştir; `SecretBox::init_with`, `try_init_with` ve `init_with_mut` eklenmiştir; MSRV 1.60 ve Rust 2021 edition'a geçilmiştir; `SecretString` `SecretBox<str>` type alias'ı olmuştur.

En önemli mimari değişiklik sırların artık stack'te değil heap'te saklanmasıdır; bu heapless `no_std` desteğini sonlandırmıştır. Ancak bu güvenlik açısından iyidir: heap'teki sır, move semantiğiyle stack'te kopya bırakmaz, yalnızca pointer taşınır.

Argus için `secrecy 0.10.x` kullanılır. `cryptoki`'nin de PIN için bunu kullandığı unutulmamalı ve sürüm çakışması yaşanmamalıdır.

### F.4 Gerçek limitler: neden `zeroize` ve `secrecy` yeterli değil

Bu, Argus'un en güvenli iddiası için en dürüst bölümdür.

| # | Sızıntı vektörü | Neden zeroize çözmez | Gerçek karşılık |
|---|---|---|---|
| 1 | Derleyici optimizasyonu değeri kopyalar veya taşır | Volatile write yalnızca son yazmayı korur, ara kopyalar korunmaz | Heap'te tutulur (`SecretBox`), `Copy` implement edilmez ve fonksiyonlar arası referansla geçirilir |
| 2 | Rust move semantiği kopya bırakır | `let b = a;` bayt düzeyinde bir kopyadır ve derleyici eski konumu temizlemez | Heap indirection kullanılır; move yalnızca pointer'ı taşır. `SecretBox`'ın 0.10'daki heap-only kararının gerçek gerekçesi budur |
| 3 | `Vec` yeniden tahsisi eski buffer'ı bırakır | zeroize dokümantasyonunda açıkça belirtilmiştir | `Vec::with_capacity(exact)` kullanılır ve hiç `push` edilmez, veya sabit boyutlu dizi tercih edilir |
| 4 | `String` büyümesi | Aynı; yeniden tahsis eski baytları arkada bırakır | Aynı; `SecretString` ile büyüyemeyen `str` kullanılır |
| 5 | `mem::forget` veya kasıtlı leak | `Drop` çalışmaz, dolayısıyla zeroize çalışmaz | Kod incelemesi yapılır; `#[deny]` lint'i düşünülür ancak araç doğrulanmamıştır |
| 6 | Panic ve unwinding | Unwind sırasında Drop çalışır, bu iyi haberdir; ancak `panic = "abort"` ile çalışmaz | Argus'ta `panic = "unwind"` bırakılır veya abort öncesi signal handler'da temizlenir, bu güvenilmezdir |
| 7 | Süreç öldürme (SIGKILL) veya abort | Hiçbir Drop çalışmaz | Yalnızca işletim sistemi seviyesi koruma: mlock ve memfd_secret |
| 8 | Core dump'lar | Heap tamamen diske yazılır | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` ve `MADV_DONTDUMP`; G bölümü |
| 9 | Swap | Sayfa diske yazılır ve zeroize sonrasında bile eski kopya swap'te kalır | `mlock` veya `memfd_secret` |
| 10 | Hibernation (S4) | Tüm RAM diske yazılır | `memfd_secret` aktif kullanıcı varken hibernation engellenir; G bölümü |
| 11 | DMA ve cold boot | RAM'e doğrudan erişim sağlanır | IOMMU ve bellek şifrelemesi: AMD SME ve SEV, Intel TME ve TDX |
| 12 | Hipervizör snapshot'ı ve canlı göç | Tüm bellek imajı kopyalanır | Confidential computing: SEV-SNP, TDX, Nitro Enclaves. Bulutta çalışılıyorsa bu gerçek bir tehdittir ve zeroize'ın hiçbir katkısı yoktur |
| 13 | Mikromimari saldırılar (Spectre ve Meltdown) | zeroize dokümantasyonunda açıkça kapsam dışıdır | Mikrokod ve kernel azaltmaları |
| 14 | CPU register'ları | zeroize kapsamı dışındadır; inline assembly veya rustc desteği gerekir | Yoktur; kabul edilmiş risktir |

### F.5 Derleyici desteği

Bugün için derleyici desteği yoktur. zeroize dokümantasyonu register temizliğinin inline assembly veya rustc desteği gerektirdiğini ve kapsam dışı olduğunu söyler. `#[no_sanitize]` sanitizer'lar içindir, sır tipleri için değildir. Rust'ta secret types için kabul edilmiş bir RFC bulunamamıştır; arama bütçesi tükendiği için bu konuda kesin konuşulamaz ve `rust-lang/rfcs` deposunda arama yapılması önerilir. Bilinen kadarıyla konu tartışılmıştır ancak stabil bir özellik yoktur. İlgili literatürde sabit zamanlı ve gizli bağımsız tip sistemleri akademik olarak mevcuttur (FaCT, Jasmin, HACL*) ancak Rust'ta değildir.

Argus'un pozisyonu şudur: kritik sabit zaman kodu için, yani imza ve karşılaştırma için, `subtle` crate'i ve zaten sabit zaman garantisi veren kütüphaneler (ed25519-dalek, p256) kullanılır. Kendi kripto ilkeli yazılmaz.

### F.6 Crate karşılaştırması

| Crate | Sürüm | Son güncelleme | 90 gün indirme | Ne yapar | Argus'taki yeri |
|---|---|---|---|---|---|
| `zeroize` | 1.9.0 | 12 Haziran 2026 | 168.883.175 | Volatile sıfırlama | Zorunludur; her sır tipinde |
| `secrecy` | 0.10.3 | 9 Ekim 2024 | 37.989.495 | Tip seviyesi kapsülleme ve redakte Debug | Zorunludur; API sınırlarında |
| `secrets` | 1.3.0 | 13 Nisan 2026 | 9.661 | mlock, guard page, canary ve core dump kapatma | Yalnızca ara imzalama anahtarı için |
| `memsec` | 0.7.0 | 6 Haziran 2024 | 542.675 | libsodium utils portu; `memfd_secret` dahil | Alternatif düşük seviye |
| `memsafe` | 1.0.2 | 5 Temmuz 2026 | 1.847 | Cross-platform güvenli sarmalayıcı | Çok yenidir, benimsenmesi düşüktür |
| `memsecurity` | 3.5.2 | 5 Ocak 2024 | 4.958 | Koruma sınırları arası koruma | Bakımsız görünmektedir |
| `region` | 4.0.0 | 7 Ağustos 2026 | 2.410.207 | Cross-platform sanal bellek API'si | mprotect için düşük seviye |

> **Benimsenme uyarısı.** `zeroize` ve `secrecy` fiilen standarttır; yüz milyonlarca indirme almışlardır. `secrets`, `memsafe` ve `memsecurity` çok düşük benimsenmeye sahiptir (10.000 altı) ve bu, az gözden geçirilmiş kod anlamına gelir. En güvenli hedefi ile az denenmiş bağımlılık arasında bir gerilim vardır. `secrets` crate'i kullanılacaksa kaynağı okunmalıdır; 1.3.0 sürümü 13 Nisan 2026'da güncellenmiştir, yani en azından bakımlıdır.

---

## G. mlock, memfd_secret ve core dump

### G.1 `memfd_secret(2)`: en güçlü Linux mekanizması

**Ne garanti eder.** Bellek alanları yalnızca dosya tanıtıcısına sahip süreçlerin sayfa tablosunda eşlenir. Alan kernel direct map'ten kaldırılır, yani kernel'in kendisi bile normal yoldan erişemez. `mlock` gibi davranır: bellekte kalır ve asla swap'e gitmez. `RLIMIT_MEMLOCK`'a tabidir. Sayfalar `mmap()` sırasında değil, fault anında talep üzerine tahsis edilir. `FD_CLOEXEC` davranışı gereği `execve(2)` çağrısında bölge süreçten kaldırılır. Aktif bir `memfd_secret()` kullanıcısı varken hibernation engellenir; bu, hibernation imajı üzerinden sızıntıyı önlemek içindir.

> **Dürüst uyarı.** Man sayfasının kendi ifadesine göre, kernel'in `memfd_secret()` ile desteklenen bellek alanlarına hiçbir koşulda erişemeyeceğine dair yüzde yüz bir garanti yoktur. Kanıt github.com/JonathonReinhart/nosecmem deposudur; `memfd_secret()` verisinin kernel'den okunabildiğini göstermektedir.

**Varsayılan olarak açık mı.** Çoğu sistemde değildir. Özellik Linux 5.14'te eklenmiştir. Linux 6.5'ten önce varsayılan olarak kapalıdır ve `secretmem.enable=y` kernel komut satırı parametresi gerekir; aksi hâlde `ENOSYS` döner, yani ya mimari desteklememektedir ya da kernel komut satırında açılmamıştır. `CONFIG_SECRETMEM` bir derleme seçeneğidir. Kapalı olma gerekçesi direct map'in parçalanmasının sistem performansını düşüreceği ve gizli belleği RAM'e kilitlemenin sorun yaratacağı endişesidir.

**Rust desteği.** Adanmış ve yaygın bir `memfd-secret` crate'i bulunamamıştır. Mevcut yol `memsec` crate'idir; Linux'ta `alloc_memfd_secret` ve `free_memfd_secret` fonksiyonları sunar ve bunlar alloc ile free'ye benzer ancak memfd_secret ile desteklenir. Alternatif `libc::syscall(SYS_memfd_secret, 0)` ile doğrudan çağrı ve ardından `mmap`'tir.

**Pratik kullanılabilirlik.**

| Ortam | memfd_secret çalışır mı |
|---|---|
| Kendi bare-metal sunucumuz; kernel komut satırı kontrolü var | Evet; `secretmem.enable=y` eklenir |
| Kendi kernel'imizi seçtiğimiz VM | Evet |
| Yönetilen Kubernetes (EKS, GKE, AKS) | Muhtemelen hayır; node kernel komut satırına erişilemez, bu doğrulanmamıştır |
| Linux 6.5 ve üstü node | Varsayılan açık olmalıdır |

**Tavsiye.** `memfd_secret` opsiyonel bir sertleştirme katmanı olarak uygulanır. Başlangıçta denenir; `ENOSYS` gelirse `mlock`'a düşülür ve bu bir başlangıç log satırı ile metrik olarak raporlanır (`argus_secret_memory_backend{type="memfd_secret|mlock|none"}`). Argus'un güvenlik duruşu şeffaf olmalıdır.

### G.2 `mlock` ve `mlockall`

Rust'tan erişim yolları `memsec::mlock` ile `memsec::munlock` (cross-platform), `region` crate'i (4.0.0, 90 günde 2.410.207 indirme; cross-platform sanal bellek API'si), ham `libc::mlock` ile `libc::mlockall` ve mlock'u zaten içinde yapan `secrets` crate'idir.

**`RLIMIT_MEMLOCK`.** `memsafe` dokümantasyonuna göre her sır tam bir sayfa, tipik olarak 4 KiB, kaplar ve `RLIMIT_MEMLOCK`'a sayılır; dolayısıyla canlı sırların sayısı sınırlıdır. Yapılandırma yaklaşık beş syscall gerektirir ve her guard döngüsü iki `mprotect` çağrısı kullanır.

Argus için önemi şudur: her ara anahtar 4 KiB sayfa tüketir. Düğüm başına üç anahtarlık overlap ile bu sorun değildir. Ancak sırlar gelişigüzel `secrets::SecretBox` içine sarılırsa `RLIMIT_MEMLOCK`'a çarpılır.

**Container etkileri doğrulanamamıştır.** Docker ve Kubernetes'in varsayılan `RLIMIT_MEMLOCK` değeri yetkili bir kaynakla doğrulanamamıştır; arama bütçesi tükenmiştir. Bilinen genel durum şudur: container'larda memlock limiti çoğu zaman düşüktür, tarihsel olarak 64 KB'dir ve `CAP_IPC_LOCK` yeteneği veya yükseltilmiş `ulimit -l` gerektirir. Docker'da `--ulimit memlock=-1:-1`, Kubernetes'te `securityContext.capabilities.add: ["IPC_LOCK"]` ve node seviyesinde ulimit kullanılır.

**Eylem.** Argus'un başlangıç kodunda `getrlimit(RLIMIT_MEMLOCK)` okunup loglanır ve yetersizse açıkça uyarı verilir. Bu belgelenir; dağıtım dokümanında IPC_LOCK gerektiği yazılır.

### G.3 Guard page'ler ve libsodium tarzı koruma

`secrets` crate'i 1.3.0 (crates.io: 13 Nisan 2026, 90 günde 9.661 indirme) şunları sağlar: tahsisin öncesinde ve sonrasında guard page'ler, yani buffer overflow ve underflow yakalama; underflow canary'si, yani guard page'e ulaşmadan önce underflow tespiti; free anında otomatik sıfırlama; `mlock(2)` entegrasyonu; UNIX release build'lerinde varsayılan olarak kapalı core dump'lar, `allow-coredumps` özelliğiyle açılabilir. Tipleri `Secret` (stack, sabit uzunluk), `SecretBox` (heap, sabit) ve `SecretVec`'tir (heap, değişken). Erişim closure'lar üzerinden yapılır ve sırın görünürlüğü dar bir kapsama kısıtlanır.

Bu, libsodium'un `sodium_malloc` ve `sodium_mprotect_noaccess` deseninin Rust karşılığıdır.

`memsafe` alternatifi `MADV_DONTDUMP` de kullanır ve core dump'tan yalnızca ilgili sayfaları çıkarır, tüm core dump'ı kapatmadan. Bu daha iyi bir denge olabilir.

### G.4 Core dump'ları kapatma

**`prctl(PR_SET_DUMPABLE, 0)`.** Man sayfasına göre bu çağrı dumpable özniteliğinin durumunu ayarlar; öznitelik, varsayılan davranışı core dump üretmek olan bir sinyal teslim edildiğinde çağıran süreç için core dump üretilip üretilmeyeceğini belirler.

`SUID_DUMP_DISABLE` (değer 0) ayarlandığında üç şey olur: süreç core dump üretmez; `/proc/[pid]` dizinindeki dosyaların sahipliği `root:root` olarak değişir ve erişim kısıtlanır; sürece `ptrace(2)` ile `PTRACE_ATTACH` yapılamaz.

Bu üçü birlikte Argus için çok değerlidir: `/proc/<pid>/environ`, `/proc/<pid>/maps` ve `/proc/<pid>/mem` aynı UID'deki saldırgana kapanır ve debugger attach engellenir.

**Diğer katmanlar.** `RLIMIT_CORE = 0` için `setrlimit(RLIMIT_CORE, {0,0})` kullanılır. `/proc/sys/kernel/core_pattern` sistem genelindedir; core'u bir pipe'a yönlendiriyorsa (systemd-coredump, apport) `RLIMIT_CORE` bazı durumlarda bypass edilebilir, bu nedenle `PR_SET_DUMPABLE` daha güvenilirdir. `madvise(MADV_DONTDUMP)` yalnızca belirli sayfaları core dump'tan çıkarır; `memsafe` bunu yapmaktadır.

**Debuggability maliyeti.**

| Kaybedilen | Etki | Telafi |
|---|---|---|
| Core dump ve post-mortem analiz | Üretim çökmesi offline incelenemez | Yapılandırılmış panic handler ve `std::backtrace` ile backtrace log'u; sırlar hariç tutulur |
| `gdb` ve `lldb` attach | Canlı debug imkânsızdır | `tokio-console`, metrikler ve tracing span'leri |
| `perf` ve profiler'lar | Bazıları ptrace kullanır | eBPF tabanlı profiler'lar (`parca`, `pyroscope`) `PTRACE_ATTACH` gerektirmeyebilir; doğrulanmamıştır |
| Sentry ve minidump crash reporting | Heap dump gitmez; bu iyidir | Yalnızca stack trace ve mesaj gönderilir |
| `strace` | Çalışmaz | Uygulama seviyesi denetim kaydı |

**Argus için kademeli yaklaşım.**

```
ARGUS_HARDENING=paranoid   → PR_SET_DUMPABLE=0 + RLIMIT_CORE=0 + mlock + memfd_secret
ARGUS_HARDENING=balanced   → MADV_DONTDUMP (yalnızca sır sayfaları) + RLIMIT_CORE=0 + mlock
ARGUS_HARDENING=dev        → hiçbiri; uyarı loglanır
```

Varsayılan `balanced`'tır; üretim dağıtım dokümanında `paranoid` önerilir. `MADV_DONTDUMP` sayesinde `balanced` modda core dump alınabilir ancak sır sayfaları içinde olmaz; en iyi denge budur.

---

## H. Sır sızıntı vektörleri

### H.1 Loglama: `tracing` ile kazara sır kaydı

**Mekanizma.** `?field` sigil'i alanı `fmt::Debug` implementasyonuyla kaydeder. `%field` sigil'i `fmt::Display` implementasyonuyla kaydeder. Struct alanları nokta notasyonuyla otomatik kaydedilir; `User { name, email }` yapısı `user.name` ve `user.email` olarak ayrı span alanlarına yazılır.

Sonuç şudur: `tracing` makrosuna `?` ile giren her tip kendi `Debug` çıktısını sızdırır. `#[derive(Debug)]` taşıyan bir struct'ın içindeki `Vec<u8>` bir anahtar, log satırına düz metin olarak yazılır.

**En tehlikeli desenler.** Argus'ta yasaklanmalıdır.

```rust
// Tehlikeli
#[derive(Debug)]                  // anahtar materyali içeren tipte kullanılmaz
struct SigningKey { d: Vec<u8>, kid: String }

tracing::debug!(?signing_key);    // tüm private key log'a gider
tracing::error!(?err);            // err içinde key materyali olabilir
tracing::info!(?request);         // request.client_secret sızabilir
anyhow::anyhow!("failed for {:?}", key)  // hata mesajında sır
```

**Savunma katmanları.**

Birinci ve birincil savunma tip seviyesindedir:

```rust
// secrecy::SecretBox'ın Debug'ı redakte eder
struct SigningKey {
    d: SecretBox<[u8; 32]>,   // Debug: "SecretBox<[u8; 32]>([REDACTED])"
    kid: String,
}
```

İkinci savunma `Debug` derive'ını yasaklayan bir newtype'tır:

```rust
pub struct KeyMaterial(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyMaterial([REDACTED])")
    }
}
// Display implement edilmez — %field imkânsız kılınır
// Serialize implement edilmez — JSON'a kaçamaz
```

Üçüncü savunma bir clippy lint'idir ancak bu konuda standart bir lint bulunup doğrulanamamıştır; arama bütçesi tükenmiştir. Bilinen seçenekler `dylint` ile özel bir lint yazmaktır ve Argus'un ölçeğinde buna değer: bir `#[argus::secret]` attribute'u tanımlanır ve o tiple işaretli her şeyin `Debug`, `Display` ve `Serialize` implement etmediği ile tracing makrolarına geçmediği denetlenir. Alternatif olarak CI'da `grep -r "derive(.*Debug" src/crypto/` benzeri bir guard konur. `#[deny(missing_debug_implementations)]` lint'inin tersi gerekmektedir ve böyle bir lint yoktur.

Dördüncü savunma log hattındaki son savunmadır: bir `tracing_subscriber::Layer` yazılır ve alan değerlerinde yüksek entropili base64 veya hex desenleri aranarak redakte edilir. Bu son çaredir; tip sistemine güvenilmeli, buna değil. Log toplama katmanında (Vector, Fluent Bit) redaksiyon kuralları eklenir.

Beşinci savunma testtir. Argus'un test süitine bir test eklenir: bir imzalama anahtarı üretilir, tüm log seviyelerinde tüm public API çağrılır, log çıktısı yakalanır ve anahtar baytlarının hex ile base64 gösterimleri aranır. Bulunursa test başarısız olur.

Rust'ta `Debug` veya loglama üzerinden sır sızdıran spesifik bir CVE bulunup doğrulanamamıştır. Genel olarak bu sınıfın (CWE-532, hassas bilginin log dosyasına eklenmesi) çok yaygın olduğu bilinmektedir; ancak Argus dokümanında isim vererek bir vaka aktarılmamalıdır.

### H.2 `/proc/<pid>/environ` ve `/proc/<pid>/cmdline`

`/proc/<pid>/environ` sürecin başlangıç ortam değişkenlerini içerir ve aynı UID'deki her süreç okuyabilir. `/proc/<pid>/cmdline` komut satırı argümanlarını içerir ve tüm kullanıcılar tarafından okunabilir (`ps aux`). `prctl(PR_SET_DUMPABLE, 0)` bunları `root:root` yapar (G.4) ve aynı UID'deki saldırganı engeller.

| Yöntem | Sızıntı riski | Argus'ta |
|---|---|---|
| Komut satırı argümanı | En kötüsü; `ps` ile herkese açıktır | Kullanılmaz |
| Ortam değişkeni | `/proc/pid/environ`'da görünür, child süreçlere miras kalır, crash reporter'lar toplar ve `docker inspect` gösterir | Yalnızca düşük hassasiyetli yapılandırma için |
| Dosya (0600, tmpfs) | Disk; tmpfs ise RAM. Okuduktan sonra kapatılabilir | İyi; bootstrap credential için |
| Unix domain socket | Dosya sistemi izinleri ve `SO_PEERCRED` ile peer doğrulaması | En iyi; Vault Agent ve SPIRE Workload API deseni |
| KMS veya IMDS ile çalışma zamanında çekme | Diskte ve ortam değişkeninde hiç bulunmaz | En iyi; IAM rolü ile |

**Argus önerisi.** Bootstrap kimliği, yani KMS'e erişim, workload identity ile sağlanır (IRSA, Workload Identity, Managed Identity) ve hiç sır dosyası olmaz. Statik sır gerekiyorsa Unix socket üzerinden Vault Agent veya SPIFFE Workload API kullanılır.

### H.3 Kubernetes Secrets

Kubernetes'in kendi uyarısı şudur: Kubernetes Secret'ları varsayılan olarak API sunucusunun altındaki veri deposunda, yani etcd'de şifrelenmemiş olarak saklanır. API erişimi olan herkes bir Secret'ı alabilir veya değiştirebilir; etcd'ye erişimi olan herkes de aynısını yapabilir.

Erişim riski şudur: bir namespace'te Pod yaratma yetkisi olan herkes o namespace'teki herhangi bir Secret'ı okuyabilir; bu doğrudan API ile veya Deployment yaratma yetkisi üzerinden dolaylı olarak mümkündür.

Kubernetes'in önerdiği asgari önlemler encryption at rest'i etkinleştirmek, en az yetki ilkesiyle RBAC yapılandırmak, container erişimini kısıtlayarak Secret'ı yalnızca ihtiyacı olan container'a vermek ve harici secret store sağlayıcılarını değerlendirmektir.

| Yaklaşım | Değerlendirme |
|---|---|
| K8s Secret'tan ortam değişkenine | En kötüsü: etcd'de şifresizdir, `/proc/pid/environ`'da görünür, child süreçlere geçer ve `kubectl describe` gösterir |
| K8s Secret'tan volume mount'a | Daha iyidir: tmpfs'tedir, ortam değişkeninde değildir. Ancak encryption at rest yoksa etcd hâlâ şifresizdir |
| K8s Secret ile KMS encryption provider | İyidir: etcd'de şifrelidir |
| Secrets Store CSI Driver | Daha iyidir: etcd'ye hiç girmez, doğrudan Vault veya KMS'ten tmpfs'e iner |
| Vault Agent sidecar veya injector | Çok iyidir: kısa ömürlü token ve otomatik yenileme sağlar |
| Workload Identity (IRSA, GKE Workload Identity) ile doğrudan KMS | En iyisidir: hiçbir yerde statik sır yoktur |

Argus'un dokümante etmesi gereken ifade şudur: Argus KMS'e workload identity ile erişir ve Kubernetes Secret kullanmaz; kullanılması zorunluysa encryption at rest etkinleştirilmeli ve ortam değişkeni yerine volume mount tercih edilmelidir.

### H.4 Core dump'lar ve crash reporter'lar

Konu G.4'te ele alınmıştır. Ek noktalar şunlardır. Sentry, minidump ve Crashpad'in ürettiği minidump'lar heap segmentlerini içerebilir; Argus Sentry kullanacaksa `before_send` hook'unda tüm ikili payload'lar sıfırlanır ve yalnızca stack trace ile mesaj gönderilir. `secrets` crate'i UNIX release build'lerinde core dump'ı zaten kapatır; bu maliyetsiz bir kazançtır. systemd-coredump için `/etc/systemd/coredump.conf` dosyasında `Storage=none` ayarlanır; ancak `PR_SET_DUMPABLE=0` daha güvenilirdir, çünkü uygulama kontrolündedir.

### H.5 Yedekler, veritabanı dump'ları ve replikasyon

Ara imzalama anahtarları hiçbir zaman veritabanına yazılmaz; bu, hibrit modelin bir yan faydasıdır. Anahtar bellekte doğar, bellekte ölür. Kök anahtar zaten KMS veya HSM'dedir ve veritabanında bulunmaz.

Veritabanında bulunanlar JWKS geçmişi (yalnızca public anahtarlar), client secret hash'leri (Argon2id), refresh token hash'leri ve kullanıcı kimlik bilgileridir.

Client secret'ları asla düz metin saklanmaz, Argon2id ile hash'lenir. Keycloak'ın client secret'ı geri gösterebilmesi bir zayıflıktır ve Argus bunu yapmamalıdır.

Replikasyonda WAL ve binlog kanalları TLS ile korunmalı ve at-rest şifreli olmalıdır. Yedeklerde `pg_dump` çıktısı client secret hash'lerini ve refresh token hash'lerini içerir; bu dump'lar KMS ile şifrelenmelidir. Üretim dump'ının test veya staging ortamına kopyalanması en yaygın gerçek sızıntı yoludur ve CI'da yasaklanmalıdır.

### H.6 Zamanlama ve hata mesajı farkları

Client secret doğrulamasında `subtle::ConstantTimeEq` kullanılır, `==` kullanılmaz. Hata mesajı ayrımı yapılmaz; bilinmeyen client ile geçersiz secret için aynı hata dönmelidir, yani OAuth 2.0'ın `invalid_client` hatası; farklı mesaj client enumeration üretir. Zamanlama ayrımı da yapılmaz: var olmayan client için Argon2 çalıştırılmazsa cevap süresi farkından client varlığı anlaşılır, bu nedenle dummy hash ile sabit zamanlı bir yol izlenir. JWKS `kid` aramasında bilinmeyen `kid` için sabit zamanlı yanıt verilir; risk düşüktür ancak tutarlılık iyidir. Rate limiting'in kendisi de bir yan kanaldır; bir client'ın throttle edildiği bilgisi o client'ın varlığını sızdırır.

---

## Argus için özet karar tablosu

| Araç veya teknik | Olgunluk | Maliyet | Ne kazandırır | Argus'ta nerede |
|---|---|---|---|---|
| `zeroize` 1.9.0 | Çok yüksek; 90 günde 169 milyon indirme | Sıfır | Derleyicinin sıfırlamayı silmemesi | Her sır tipinde; zorunludur |
| `secrecy` 0.10.3 | Çok yüksek; 90 günde 38 milyon indirme | Sıfır | Redakte Debug ve açık exposure | API sınırlarında; zorunludur |
| `cryptoki` 0.12.0 | Yüksek; 90 günde 1,2 milyon indirme | Sıfır, HSM donanımı hariç | PKCS#11 3.x ve `Session: Send` | Kök anahtar HSM'deyse |
| `r2d2-cryptoki` 0.5.0 | Orta; 90 günde 28.000 indirme | Sıfır | HSM oturum havuzu | `cryptoki` ile birlikte |
| `secrets` 1.3.0 | Düşük; 90 günde 9.600 indirme | Sayfa başına 4 KiB memlock | mlock, guard page ve core dump kapatma | Yalnızca ara imzalama anahtarı |
| `memsec` 0.7.0 | Orta; 90 günde 543.000 indirme | Sıfır | `memfd_secret` erişimi | Opsiyonel sertleştirme |
| `memfd_secret(2)` | Kernel 5.14 ve üstü; çoğu yerde kapalıdır | Kernel komut satırı erişimi | Direct map'ten çıkarma, swap yokluğu, hibernation bloğu | Best-effort, fallback'li |
| `PR_SET_DUMPABLE=0` | Olgun | Debuggability kaybı | Core dump, ptrace ve `/proc` kapanışı | Üretimde `paranoid` modda |
| AWS KMS (Ed25519, P-256) | Çok yüksek | Anahtar başına aylık 1 USD ve 10.000 istek başına 0,15 USD | Kök anahtar hiç çıkmaz | Yalnızca ara anahtar sarmalama |
| AWS CloudHSM hsm2m | Yüksek | Saatlik HSM ücreti | 3.000-7.000 P-256 imza/sn, FIPS Level 3 | Kök anahtar; düzenleyici zorunluluk varsa |
| Azure Managed HSM | Yüksek | Instance saatlik ücreti | Partition başına 330 P-256 imza/sn | Azure'da kök anahtar |
| YubiHSM 2 | Yüksek | Yaklaşık 650 USD donanım | Yaklaşık 14 P-256 imza/sn, tek thread | Yalnızca kök anahtar ve geliştirme |
| Vault veya OpenBao transit | Yüksek | Operasyon yükü | Ed25519, `batch_input` ve versiyonlama | Ara anahtar sarmalama; KMS alternatifi |
| OpenBao v2.6.2 | Orta ile yüksek arası; hızlı büyümekte | Operasyon yükü | BUSL'dan kaçınma ve Linux Foundation yönetişimi | Vault yerine; açık kaynak Argus için |
| Delegated credential tarzı attestation | Standart dışı ancak kanıtlanmış (Cloudflare) | Az kod | JWKS kompromizasyonuna karşı savunma | JWKS'e ek alan olarak |

---

## Eylem planı

1. Hibrit model bir tasarım kararı olarak kilitlenir: kök anahtar KMS veya HSM'de, ara anahtar bellekte, 15 dakika veya 5 milyon imzadan hangisi önce gelirse rotasyon. Gerekçe B bölümündeki 1.000 TPS tavanı ve aylık 39.000 USD maliyettir.
2. `zeroize` ile `secrecy` 0.10.x baştan uygulanır; sonradan eklemek çok daha zordur. `SecretBox`'ın heap-only olmasının move semantiği gerekçesi kod yorumlarında belgelenir.
3. Kendi bölgemizde KMS Sign p50 ve p99 değerleri ölçülür. Yayımlanmış sayı yoktur ve bu ölçüm mimari kararı doğrulayacak veya çürütecektir.
4. JWKS rotasyon durum makinesi E.4'teki gibi kurulur: 10 dakika ısınma, 15 dakika aktif, 20 dakika drenaj. `kid` değeri RFC 7638 thumbprint'tir. `Cache-Control: max-age=300, stale-if-error=86400` kullanılır.
5. `ARGUS_HARDENING` kademeli sertleştirme modu eklenir ve hangi katmanın aktif olduğu başlangıçta loglanıp metrik olarak yayımlanır.
6. Sır sızıntısı testi CI'ya konur; log çıktısında anahtar baytlarını arayan bir test yazılır. Uzun vadede `dylint` ile özel bir lint geliştirilir.
7. HSM entegrasyonu `cryptoki` 0.12 ve üstü ile `r2d2-cryptoki` kullanılarak ayrı bir blocking thread havuzunda yapılır. Handle'lar label ile çözülür ve oturum ömrüne bağlanır.
8. Kök anahtar töreni için `boulder/cmd/ceremony` referans alınır; çok kişili kontrol ve video kayıt uygulanır.

---

## Doğrulanamayan maddeler

1. AWS, GCP ve Azure KMS Sign p50 ile p99 gecikmesi; hiçbir sağlayıcı yayımlamamaktadır ve bulunamamıştır.
2. Vault transit sign işlem/sn değeri; HashiCorp yayımlamamaktadır ve 37.000 işlem/sn iddiasının Medium kaynağı çekilememiştir (HTTP 403).
3. YubiHSM 2 performans tablosu; Yubico destek makalesinden arama indeksi üzerinden alınmıştır, sayfanın doğrudan çekilmesi CSS hatası vermiştir ve tarayıcıda teyit edilmelidir.
4. AWS KMS asimetrik fiyatlandırmasının key spec başına tam tablosu; yalnızca 10.000 istek başına 0,15 USD örneği çıkarılabilmiştir.
5. GCP Cloud KMS fiyatlandırması; sayfa içeriği kesilmiştir.
6. Keycloak varsayılan anahtar rotasyon ömrü; kaynaklarda bulunmamaktadır.
7. OIDC Core §10.1.1'in birebir metni; spec sayfası kesilmiştir ve özet ikincil kaynaklardandır.
8. Docker ve Kubernetes varsayılan `RLIMIT_MEMLOCK` değeri; yetkili kaynakla doğrulanamamıştır.
9. Rust'ta secret type RFC'si; bulunamamıştır, yok olduğu iddia edilmemektedir.
10. Rust'ta `Debug` ve log üzerinden sır sızıntısı için clippy lint'i; bulunamamıştır.
11. Rust'ta `Debug` üzerinden sır sızdıran spesifik bir CVE; doğrulanmış bir örnek bulunamamıştır.
12. `cryptoki-rustcrypto`; crates.io'da ve repo workspace'inde yoktur, yayımlanmış bir crate olarak mevcut değildir.

Bu oturumda WebSearch bütçesi tükendiği için son birkaç madde yalnızca doğrudan URL çekimiyle araştırılabilmiştir.

---

## Kaynaklar

github.com/parallaxsecond/rust-cryptoki ve CHANGELOG.md; crates.io/crates/cryptoki. github.com/spruceid/r2d2-cryptoki; lib.rs/crates/yubihsm; github.com/softhsm/SoftHSMv2; github.com/kushaldas/kryptering. Yubico'nun YubiHSM 2 yük dengeli tasarım destek makalesi ve docs.yubico.com üzerindeki teknik veri sayfası. AWS CloudHSM performans ve hsm2m.medium bilinen sorunlar sayfaları. AWS KMS saniyedeki istek, asimetrik key spec ve fiyatlandırma sayfaları. docs.cloud.google.com/kms/quotas. Azure Key Vault servis limitleri ve Managed HSM ölçekleme kılavuzu. Cloudflare keyless delegation blogu, Keyless SSL ölçekleme ve benchmark sayfası ile Geo Key Manager yazısı. HashiCorp Vault seal kavramları, transit secrets engine, transit API dokümantasyonu, Vault performans benchmark blogu ve benchmark tutorial'ı. github.com/openbao/openbao/releases ve NVIDIA'nın OpenBao'yu benimsemesine dair haber. SPIRE aws_kms keymanager plugin dokümanı; Sigstore Fulcio setup dokümanı; Let's Encrypt boulder ceremony dizini ve CCS 2019 makalesi. AWS Encryption SDK data key caching sayfası ve KMS imzalarının ölçekte doğrulanmasına dair AWS güvenlik blogu. RFC 7517; Okta anahtar rotasyonu dokümanı; Auth0 imzalama anahtarı rotasyonu; Keycloak keys.adoc; Zalando otomatik JWK rotasyonu yazısı; Duende'nin imzalama anahtarı rotasyonu blogu. docs.rs/zeroize; CipherStash'in zeroize assembly doğrulama yazısı; docs.rs/secrecy ve secrecy CHANGELOG; docs.rs/secrets; docs.rs/memsec; lib.rs/crates/memsafe. man7.org memfd_secret ve PR_SET_DUMPABLE sayfaları; lwn.net/Articles/865256/; github.com/JonathonReinhart/nosecmem. docs.rs/tracing; kubernetes.io Secret dokümantasyonu.
