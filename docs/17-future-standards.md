# 17. Gelecek standartları — PQC, WebAuthn L3, CTAP, TLS

> `ARGUS.md` §17'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§17 §X` referansları aynı anlamda.


**Soru:** 5-10 yıl yaşayacak bir IdP mimarisinde, bugün ucuz olan ama sonradan çok pahalıya patlayacak kararlar hangileri?

Bu dosya dört ayrı araştırma hattının ham raporlarını birleştirir. Sentez ve karar tablosu için bkz. [§3 — P0 kritik bulgular](#3-p0-kritik-bulgular).


---

## HAT 1 — Post-Quantum Kriptografi ve Kimlik

## Post-Quantum Kriptografi Durum Raporu — 8 Eylül 2026
#### Rust ile Identity Provider geliştiren ekip için

**Yöntem notu:** Bulgular birincil kaynaklardan (csrc.nist.gov, datatracker.ietf.org, rfc-editor.org, iana.org, w3.org, fidoalliance.org, cabforum.org, crates.io/docs.rs, whitehouse.gov) doğrudan çekildi. Erişilemeyen kaynaklar ve doğrulanamayan noktalar açıkça işaretlendi.

---

### 0. Yönetici Özeti — Bir IdP için tek cümlelik durum

**İmza tarafı (JWS/JWT) hazır, şifreleme tarafı (JWE) hazır değil, sertifika tarafı public trust'ta hâlâ kapalı, FIDO donanımı yok, Rust'ta RFC 9964 implementasyonu yok.**

| Katman | Durum | Aksiyon |
|---|---|---|
| TLS anahtar değişimi | ✅ Üretimde, RFC oldu, trafiğin ~2/3'ü | Bugün aç |
| JWS imza (ML-DSA) | ✅ RFC 9964 (Mayıs 2026) | Spec hazır, Rust kütüphanesi yok |
| JWE şifreleme (ML-KEM) | ❌ Sadece taslak, JOSE için yok | Bekle |
| X.509 sertifika (private PKI) | ✅ RFC 9881/9935 | Kullanılabilir |
| X.509 sertifika (public trust) | ❌ CA/B Forum oylaması geçmedi | 2027+ |
| FIDO2/WebAuthn PQC | ❌ Spec'te bile yok, donanım yok | 2028+ |
| FIPS 140-3 validasyonlu PQC | ❌ Kuyrukta | Bekle |

---

### 1. NIST PQC Standartları

#### 1.1 Yayınlanmış FIPS'ler — hepsi 13 Ağustos 2024

| Standart | Tam ad | Durum | Not |
|---|---|---|---|
| **FIPS 203** | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | Final, 13.08.2024 | Errata notu **17.11.2025**: "gelecek bir güncellemede düzeltilecek bir sorun" |
| **FIPS 204** | Module-Lattice-Based Digital Signature Standard (ML-DSA) | Final, 13.08.2024 | Errata notu **31.07.2026**: "birkaç küçük sorun gelecek revizyonda düzeltilecek" |
| **FIPS 205** | Stateless Hash-Based Digital Signature Standard (SLH-DSA) | Final, 13.08.2024 | Sayfada errata notu yok |

Hiçbirinin **Rev 1'i yok**; ikisinde errata elektronik tablosu var, revizyon tarihi ilan edilmemiş (**belirsiz**).

- https://csrc.nist.gov/pubs/fips/203/final
- https://csrc.nist.gov/pubs/fips/204/final
- https://csrc.nist.gov/pubs/fips/205/final

#### 1.2 FIPS 206 (FN-DSA / Falcon) — **8 Eylül 2026 itibarıyla YAYINLANMADI**

- NIST PQC standardizasyon sayfasında hâlâ yalnızca **"FIPS 206 (in development)"** yazıyor; tarih verilmiyor.
- **NIST'in "drafts open for comment" listesinde FIPS 206 YOK** — yani initial public draft bile çıkmamış. Doğrudan doğruladım (08.09.2026 listesi: SP 800-73-6, SP 800-78-6, SP 800-209r1, SP 800-239, IR 8613, SP 1353, SP 800-213A r1, SP 800-38E r1).
- IETF tarafındaki `draft-ietf-cose-falcon-04` abstract'ı **"expected to be published in late 2026 early 2027"** diyor — bu şu an en güvenilir kamuya açık beklenti.
- İkincil kaynaklar "NIST taslağı 28 Ağustos 2025'te onaya gönderdi" diyor — **birincil kaynakta doğrulayamadım, belirsiz.**

https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization

#### 1.3 HQC — seçildi, taslak gecikti

- **Seçim: 11 Mart 2025.** Gerekçe belgesi: **NIST IR 8545**, "Status Report on the Fourth Round of the NIST PQC Standardization Process", Mart 2025. Metin: *"The only key-establishment algorithm that will be standardized is HQC."*
- **FIPS numarası atanmadı.** Ne IR 8545'te ne de proje sayfasında bir numara var. (Yaygın olarak dolaşan "FIPS 207" iddiasını **hiçbir NIST kaynağında bulamadım — uydurma saymak gerekir.**)
- **NIST'in ilan ettiği takvim** (nist.gov haber bülteni, Mart 2025): *"NIST plans to release a draft standard built around HQC for public comment in about a year"* + *"finalize the standard for release in 2027."*
- **Gerçekleşme:** "yaklaşık bir yıl" ≈ Mart 2026 idi. **8 Eylül 2026 itibarıyla HQC taslağı yayınlanmadı** (drafts-open-for-comment listesinde yok). Yani **takvimin ~6 ay gerisinde.** 2027 finali bu gidişle riskli görünüyor (**yorum, belirsiz**).

- https://csrc.nist.gov/pubs/ir/8545/final
- https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption

#### 1.4 Yan gelişmeler

- **NIST IR 8610** (Final, **Mayıs 2026**) — "Status Report on the Second Round of the Additional Digital Signature Schemes". Üçüncü tura kalan 9 aday: **FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV.** Standardizasyon takvimi verilmemiş.
- **SP 800-227** (Final, **Eylül 2025**) — "Recommendations for Key-Encapsulation Mechanisms". KEM'lerin doğru kullanımı; ML-KEM entegrasyonu için başvuru dokümanı.
- **SP 800-230 ipd** (**13 Nisan 2026**, yorum süresi 12 Haziran 2026'da kapandı) — "Additional SLH-DSA Parameter Sets for Limited Signature Use Cases". Seviye 1/3/5 için **6 ek "SLHsig" parametre seti**; daha küçük imza + hızlı doğrulama, ama **anahtar başına 2²⁴ imza sınırı** ve *"not approved for general-purpose use"*.

---

### 2. NIST SP 800-208 — Stateful Hash-Based İmzalar (LMS/XMSS)

- **Tam ad:** "Recommendation for Stateful Hash-Based Signature Schemes"
- **Durum:** **Final, Ekim 2020** (kesinleşme 29.10.2020). Geri çekilme/supersede notu **yok**; hâlâ yürürlükte.
- **Kapsam:** LMS, HSS (LMS çok-ağaçlı), XMSS, XMSS^MT.
- **IdP açısından:** Bu şemalar **durum (state) tutar** — aynı OTS anahtarı iki kez kullanılırsa imza sahteciliği mümkün olur. Bu yüzden yalnızca **firmware/yazılım imzalama** gibi merkezi, düşük hacimli, HSM destekli senaryolar için uygundur. **Token imzalama için kesinlikle uygun değildir** (yüksek hacim + yatay ölçekleme + state senkronizasyonu = felaket).
- **CNSA 2.0 yazılım/firmware imzalama için bunları zorunlu kılıyor** (aşağıda).
- IETF tarafı: **draft-ietf-pquip-hbs-state-04**, "Hash-based Signatures: State and Backup Management" — RFC Editor kuyruğunda. Durum yönetimi ve yedekleme tuzaklarını anlatıyor; LMS/XMSS'e girecekseniz okunması şart.

- https://csrc.nist.gov/pubs/sp/800/208/final
- COSE tarafında HSS-LMS zaten kayıtlı: **alg = -46** (RFC 8778, RFC 9053), **kty = 5**.

---

### 3. Geçiş Takvimleri: IR 8547, EO 14412, CNSA 2.0

#### 3.1 NIST IR 8547 — **HÂLÂ TASLAK, FİNAL DEĞİL** ⚠️

Bu, raporun en çok yanlış bilinen maddesi. İnternette dolaşan "2025'te final oldu" iddiası **yanlış**.

- **Tam ad:** "Transition to Post-Quantum Cryptography Standards"
- **Durum: Initial Public Draft (ipd)** — 12 Kasım 2024 yayınlandı, yorumlar 10 Ocak 2025'te kapandı, gelen yorumlar 21 Ocak 2025'te yayınlandı.
- **8 Eylül 2026 itibarıyla final sürüm YOK, ikinci taslak da YOK.** Bunu üç ayrı yerden doğruladım: (a) `csrc.nist.gov/pubs/ir/8547/final` → **HTTP 404**; (b) `csrc.nist.gov/pubs/ir/8547/ipd` sayfasında final/güncelleme notu yok; (c) NIST PQC haber akışında IR 8547 ile ilgili son kayıt 12.11.2024 tarihli taslak duyurusu.
- **Taslaktaki hedefler:** kuantuma açık açık anahtarlı algoritmalar (RSA, ECDSA, ECDH, sonlu cisim DH) **2030'dan sonra deprecated**, **2035'ten sonra disallowed**.
- **Pratik sonuç:** 2030/2035 tarihleri yaygın olarak alıntılansa da **hâlâ resmî olarak taslak statüsünde**. Bağlayıcı olan şey artık IR 8547 değil, aşağıdaki EO.

https://csrc.nist.gov/pubs/ir/8547/ipd

**İlgili:** **SP 800-131A Rev. 3** de hâlâ **Initial Public Draft** (21 Ekim 2024). Yani NIST'in resmî algoritma geçiş rehberliğinin **ikisi de taslak**.
https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd

#### 3.2 ⭐ Executive Order 14412 — asıl bağlayıcı belge (YENİ)

Bu, ekibinizin takvimini belirleyen belgedir. whitehouse.gov'dan doğrudan doğrulandı.

- **Tam ad:** Executive Order 14412, **"Securing the Nation Against Advanced Cryptographic Attacks"**
- **İmza tarihi: 22 Haziran 2026**

| Tarih | Yükümlülük |
|---|---|
| +30 gün (Tem 2026) | Kurumlar PQC geçiş sorumlusunu OMB ve Ulusal Siber Direktör'e bildirir |
| +90 gün (Eyl 2026) | OMB rehberliği yayınlar; kurumlar HVA/yüksek etkili sistemleri gözden geçirip geçiş planı hazırlar |
| +180 gün | NIST PQC pilot projesi başlatır (bitiş 2027 sonu); CISA **cryptographic bill of materials (CBOM)** rehberliği yayınlar; FAR Council sözleşme kuralı önerir |
| +270 gün | FAR Council zafiyet açıklama gereksinimlerini önerir |
| **31 Aralık 2030** | HVA/yüksek etkili sistemler **anahtar tesisi (key establishment)** için PQC'ye geçer; **yükleniciler** NIST PQC FIPS'lerine uyar |
| **31 Aralık 2031** | HVA/yüksek etkili sistemler **dijital imza / kimlik doğrulama** için PQC'ye geçer |

> **IdP ekibi için kritik:** EO, **anahtar tesisi (2030)** ile **imza/kimlik doğrulama (2031)** arasında bir yıl fark koyuyor. Bir IdP'nin ürettiği JWT imzaları ve mTLS/FIDO kimlik doğrulaması **2031 kovasına** düşer; TLS anahtar değişimi **2030 kovasına**. ABD federal müşteriniz veya federal yükleniciniz varsa bu tarihler sözleşmesel hale gelir.

https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/

#### 3.3 CNSA 2.0 (NSA) — ⚠️ ikincil kaynak

**Uyarı:** `media.defense.gov` (CSA_CNSA_2.0_ALGORITHMS_.PDF) ve `nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/` **HTTP 403** döndü — birincil PDF'e erişemedim. Aşağıdaki tablo ikincil kaynaktan; **doğrulanması gerekir.**

**Algoritma paketi** (Wikipedia + Encryption Consulting, uyumlu):
| Amaç | Algoritma | Standart |
|---|---|---|
| Anahtar tesisi | **ML-KEM-1024** (yalnızca Kategori 5) | FIPS 203 |
| Dijital imza (genel) | **ML-DSA-87** (yalnızca Kategori 5) | FIPS 204 |
| Yazılım/firmware imzalama | **LMS veya XMSS** (SHA-256/192 asgari) | SP 800-208 |
| Simetrik | AES-256 | FIPS 197 |
| Özet | SHA-384 / SHA-512 | FIPS 180-4 |
| Secure boot özeti | SHA3-384 / SHA3-512 | FIPS 202 |

**Geçiş takvimi (ikincil, belirsiz):**
| Kategori | Destekle/Tercih et | Yalnızca CNSA 2.0 |
|---|---|---|
| Yazılım ve firmware imzalama | 2025 | 2030 |
| Geleneksel ağ ekipmanı (VPN, router) | 2026 | 2030 |
| Web tarayıcı/sunucu, bulut servisleri | 2025 | **2033** |
| İşletim sistemleri | 2027 | 2033 |

Ayrıca: **1 Ocak 2027'den itibaren yeni NSS alımları varsayılan olarak CNSA 2.0 uyumlu olmalı.**

**2025/2026'da NSA'nın takvimi revize edip etmediğini doğrulayamadım — belirsiz.**

> Dikkat: CNSA 2.0 **yalnızca Kategori 5** parametrelerine izin verir (ML-DSA-87, ML-KEM-1024). Bu, aşağıda göreceğiniz web/IETF ekosisteminin varsayılanı olan ML-DSA-44 ve ML-KEM-768 ile **çelişir**. NSS müşteriniz varsa iki ayrı profil desteklemeniz gerekir.

---

### 4. IETF JOSE/COSE PQC — IdP'nin kalbi

#### 4.1 ⭐ RFC 9964 — ML-DSA for JOSE and COSE (YAYINLANDI)

**Bu, ekibiniz için en önemli tek belge.**

- **Tam ad:** "ML-DSA for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)"
- **Durum: RFC 9964, Standards Track, Mayıs 2026.** (Öncülü `draft-ietf-cose-dilithium`.)
- https://www.rfc-editor.org/rfc/rfc9964.html

**JWS `alg` değerleri** (IANA "JSON Web Signature and Encryption Algorithms" registry'de **kayıtlı**, Implementation Requirements: **Optional**):

| `alg` | Açıklama | Referans |
|---|---|---|
| `ML-DSA-44` | ML-DSA-44 as described in US NIST FIPS 204 | RFC 9964, FIPS-204 |
| `ML-DSA-65` | ML-DSA-65 as described in US NIST FIPS 204 | RFC 9964, FIPS-204 |
| `ML-DSA-87` | ML-DSA-87 as described in US NIST FIPS 204 | RFC 9964, FIPS-204 |

**COSE algoritma ID'leri** (IANA "COSE Algorithms" registry'de **kayıtlı**):

| Değer | İsim | Referans |
|---|---|---|
| **-48** | ML-DSA-44 | RFC 9964 |
| **-49** | ML-DSA-65 | RFC 9964 |
| **-50** | ML-DSA-87 | RFC 9964 |

**Yeni anahtar tipi: `AKP` (Algorithm Key Pair)**

| Katman | Değer |
|---|---|
| JWK `kty` | `"AKP"` (RFC 9964) |
| COSE `kty` | **7** ("COSE Key Type for Algorithm Key Pairs", RFC 9964) |
| Public key param | JWK `pub` (base64url) / COSE label **-1** (bstr) |
| Private key param | JWK `priv` (base64url) / COSE label **-2** (bstr) |

Örnek JWK:
```json
{
  "kid": "T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o",
  "kty": "AKP",
  "alg": "ML-DSA-44",
  "pub": "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMc...",
  "priv": "<32-byte seed, base64url>"
}
```

**İki kritik tasarım kararı — implementasyonda tuzak:**

1. **`priv` MUTLAKA 32 baytlık seed olmalıdır.** RFC metni: *"the `priv` parameter MUST be the seed and MUST have a length of 32 bytes."* Genişletilmiş (expanded) private key formatı JOSE/COSE'de **yasak**. Bu, JOSE ile COSE arasında tutarlılık için seçilmiş.
2. **HashML-DSA (pre-hash) desteklenmiyor.** RFC metni: *"This document does not specify algorithms for use with HashML-DSA as described in Section 5.4 of FIPS-204."* Yalnızca pure ML-DSA.
3. `alg` parametresi tüm AKP anahtarlarında **zorunlu** (anahtar tipi tek başına algoritmayı belirlemiyor).

> ⚠️ **X.509 ile interop tuzağı:** RFC 9881 (X.509) private key için **seed / expanded / both** üçünü de kabul ediyor. RFC 9964 (JOSE/COSE) **yalnızca seed** kabul ediyor. HSM'iniz veya PKI aracınız yalnızca expanded key veriyorsa JWK'ya doğrudan aktaramazsınız — seed'i saklamanız şart. Bunu anahtar üretim akışında baştan kurgulayın.

#### 4.2 SLH-DSA for JOSE and COSE — IESG'de

- **`draft-ietf-cose-sphincs-plus-10`**, revizyon tarihi **28 Temmuz 2026** (datatracker güncelleme 23.08.2026)
- **Durum: "Submitted to IESG for Publication"**, hedef Proposed Standard. Sorumlu AD: Christopher Inacio. (Öncülü `draft-ietf-cose-post-quantum-signatures`.)
- **Yalnızca İKİ parametre seti** talep ediyor (FIPS 205'teki 12'nin değil):

| İsim | COSE değeri | Durum |
|---|---|---|
| `SLH-DSA-SHA2-128s` | **TBD1 (-51 isteniyor)** | ❌ IANA'da HENÜZ KAYITLI DEĞİL |
| `SLH-DSA-SHAKE-128s` | **TBD2 (-52 isteniyor)** | ❌ IANA'da HENÜZ KAYITLI DEĞİL |

IANA COSE registry'sinde bugün **SLH-DSA girdisi yok** — doğrudan doğrulandı. JOSE registry'sinde de yok.

https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/

#### 4.3 FN-DSA for JOSE and COSE — FIPS 206'ya bağımlı, süresi doluyor

- **`draft-ietf-cose-falcon-04`**, **15 Mart 2026**, **süre sonu 16 Eylül 2026** (yani 8 gün içinde expire olacak)
- İstenen: `FN-DSA-512` (**TBD1, -54**), `FN-DSA-1024` (**TBD2, -55**)
- **FIPS 206 yayınlanmadan ilerleyemez.**
- ⚠️ **Olası codepoint çakışması:** `draft-ietf-jose-pq-composite-sigs-03` de **-54..-59** aralığını istiyor. İkisi de TBD olduğu için IANA tahsis sırasında çözülecek; **hangisinin alacağı belirsiz.** Kodunuzda bu değerleri sabit yazmayın.

#### 4.4 ML-KEM for JOSE/COSE — ⚠️ JOSE için YOK

Bu, IdP'ler için en büyük boşluk.

- **`draft-ietf-jose-pqc-kem-06`**, **6 Temmuz 2026**, aktif I-D (JOSE WG)
- **Başlık:** "Post-Quantum Key Encapsulation Mechanisms (PQ KEMs) for **COSE**"
- ⚠️ **Dosya adında "jose" geçmesine rağmen kapsam yalnızca COSE'dir.** Metin açıkça JOSE ile hibrit yaklaşımları *"outside the scope of this document"* diyor.
- Tanımlanan 6 algoritma: `ML-KEM-512/768/1024` (Direct Key Agreement) ve `ML-KEM-512+A128KW`, `ML-KEM-768+A192KW`, `ML-KEM-1024+A256KW`
- **Codepoint'ler TBD1–TBD6 — IANA'da hiçbiri kayıtlı değil.**

**Sonuç: JWE için standartlaşmış post-quantum şifreleme 8 Eylül 2026 itibarıyla YOKTUR.** Şifreli ID token / şifreli userinfo / JARM kullanıyorsanız kuantum-güvenli seçenek mevcut değil.

https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/

#### 4.5 HPKE — JOSE ve COSE

| Taslak | Rev | Tarih | Durum | PQ? |
|---|---|---|---|---|
| `draft-ietf-jose-hpke-encrypt` | **22** | 06.07.2026 | **Waiting for AD Go-Ahead** (Proposed Std) | ❌ Yalnızca DHKEM(P-256/X25519), ML-KEM **yok** |
| `draft-ietf-cose-hpke` | **26** | 04.07.2026 | **AD Evaluation::AD Followup** | ❌ |
| `draft-ietf-jose-hpke-pq-pqt` | **01** | 06.07.2026 | I-D Exists (WG doc) | ✅ PQ kayıtları burada |
| `draft-ietf-cose-hpke-pq-pqt` | **01** | 2026 | I-D Exists (WG doc) | ✅ |

**`draft-ietf-jose-hpke-pq-pqt-01`** kaydettiği algoritmalar (hepsi SHAKE256 KDF + AES-256-GCM AEAD):
- **PQ/T hibrit:** `HPKE-8` (ML-KEM-768 + P-256), `HPKE-9` (ML-KEM-768 + X25519), `HPKE-10` (ML-KEM-1024 + P-384)
- **Saf PQ:** `HPKE-12` (ML-KEM-768), `HPKE-13` (ML-KEM-1024)
- Her birinin `-KE` (key encryption) varyantı da var.

**HPKE for JOSE henüz RFC DEĞİL.** IANA JOSE registry'sinde HPKE girdisi bulunamadı.

#### 4.6 Hibrit / Composite imzalar

**`draft-ietf-jose-pq-composite-sigs-03`**, **20 Temmuz 2026**, aktif I-D (JOSE WG). 6 kombinasyon:

| JOSE `alg` | COSE (TBD) |
|---|---|
| `ML-DSA-44-ES256` | -54 |
| `ML-DSA-65-ES256` | -55 |
| `ML-DSA-87-ES384` | -56 |
| `ML-DSA-44-Ed25519` | -57 |
| `ML-DSA-65-Ed25519` | -58 |
| `ML-DSA-87-Ed448` | -59 |

`draft-ietf-lamps-pq-composite-sigs`'e serileştirme için bağımlı, ama **kritik bir sapma var:** ECDSA imzası/anahtarı X.509'un ASN.1 yapıları (`Ecdsa-Sig-Value`, `ECPrivateKey`) yerine **JOSE/COSE'nin ham sabit uzunluklu kodlamasını** kullanmak ZORUNDA. Yani composite imzalar X.509 ile bit-uyumlu değil.

**`draft-ietf-lamps-pq-composite-sigs-19`** (X.509 tarafı), **21 Nisan 2026**, **RFC Editor kuyruğunda ("In Progress — First Edit")**, RFC numarası henüz atanmadı. 18 kombinasyon (ML-DSA × RSA-PSS/PKCS#1v1.5/ECDSA/Ed25519/Ed448, brainpool dahil).

**`draft-ietf-lamps-pq-composite-kem-21`**, **1 Eylül 2026**, **IESG Evaluation — "Revised I-D Needed", 2 DISCUSS var.** 12 kombinasyon (ML-KEM-768/1024 × RSA-OAEP/X25519/X448/ECDH), hepsi SHA3-256 KDF.

**Referans dokümanlar (okunması önerilir):**
- **RFC 9794** (Haziran 2025) — "Terminology for Post-Quantum Traditional Hybrid Schemes"
- **RFC 9955** (Temmuz 2026) — "Hybrid Signature Spectrums". Kritik uyarı: **geriye dönük uyumluluk ile Strong Non-Separability karşılıklı olarak dışlayıcıdır.** Yani "eski istemciler tek bileşeni doğrulayabilsin" isterseniz imza-soyma (stripping) saldırısına açık kalırsınız.
- **RFC 9958** (Haziran 2026) — "Post-Quantum Cryptography for Engineers", Informational, 42 sayfa. Ekibin başlangıç okuması.

#### 4.7 IANA registry özeti — 8 Eylül 2026 kesin durum

**JOSE (JSON Web Signature and Encryption Algorithms):**
| Girdi | Durum |
|---|---|
| `ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87` | ✅ Kayıtlı (RFC 9964, Optional) |
| SLH-DSA | ❌ Yok |
| ML-KEM | ❌ Yok |
| FN-DSA / Falcon | ❌ Yok |
| HPKE | ❌ Yok |

**JOSE (JSON Web Key Types):** `AKP` = "Algorithm Key Pair" ✅ (RFC 9964, Optional)

**COSE Algorithms:**
| Değer | İsim | Referans |
|---|---|---|
| **-46** | HSS-LMS | RFC 8778, RFC 9053 |
| **-48** | ML-DSA-44 | RFC 9964 |
| **-49** | ML-DSA-65 | RFC 9964 |
| **-50** | ML-DSA-87 | RFC 9964 |

SLH-DSA, ML-KEM, FN-DSA: ❌ hiçbiri kayıtlı değil.

**COSE Key Types:** `AKP` = **7** ✅ (RFC 9964); `HSS-LMS` = 5; `WalnutDSA` = 6.

#### 4.8 JOSE'de ilgili diğer değişiklikler

- **RFC 9864** (Ekim 2025, Standards Track) — "Fully-Specified Algorithms for JOSE and COSE". **`EdDSA`'yı deprecate ediyor**, yerine `Ed25519` / `Ed448` geliyor; COSE'de `ESP256/ESP384/ESP512`. §4.3 IANA talimatlarını güncelliyor: **artık yalnızca fully-specified algoritma tanımlayıcıları kaydedilebilir.** ML-DSA-44/65/87'nin baştan parametreli isimlendirilmesinin sebebi bu.
- **`draft-ietf-jose-deprecate-none-rsa15-05`** (23 Haziran 2026) — "Publication Requested", Proposed Standard. `none` ve `RSA1_5` deprecate ediliyor.
- **`draft-ietf-oauth-rfc8725bis-10`** (21 Ağustos 2026) — JWT BCP güncellemesi, RFC Editor kuyruğunda, **"blocked: Reference Not Received"** (yukarıdaki deprecate taslağını bekliyor). ⚠️ **Bu güncelleme post-quantum'dan, ML-DSA'dan veya RFC 9964'ten hiç bahsetmiyor.** OAuth WG'de PQC ile ilgili **hiçbir çalışma yok** — doğrudan doğrulandı.

---

### 5. X.509 / PKI

#### 5.1 Yayınlanmış RFC'ler ✅

| RFC | Tarih | Konu |
|---|---|---|
| **RFC 9881** | Ekim 2025 | **ML-DSA için X.509 algoritma tanımlayıcıları** (← `draft-ietf-lamps-dilithium-certificates`) |
| **RFC 9882** | Ekim 2025 | ML-DSA in CMS |
| **RFC 9814** | Temmuz 2025 | SLH-DSA in CMS |
| **RFC 9909** | Aralık 2025 | SLH-DSA için X.509 algoritma tanımlayıcıları |
| **RFC 9935** | Mart 2026 | **ML-KEM için X.509 algoritma tanımlayıcıları** |
| **RFC 9936** | Mart 2026 | ML-KEM in CMS |

**RFC 9881 — ML-DSA OID'leri** (`2.16.840.1.101.3.4.3.x`):
| Algoritma | OID | Public key | İmza | Expanded private key |
|---|---|---|---|---|
| ML-DSA-44 | ...sigAlgs **17** | 1.312 B | **2.420 B** | 2.560 B |
| ML-DSA-65 | ...sigAlgs **18** | 1.952 B | **3.309 B** | 4.032 B |
| ML-DSA-87 | ...sigAlgs **19** | 2.592 B | **4.627 B** | 4.896 B |

Public key `SubjectPublicKeyInfo` içinde **ham byte string** olarak (ASN.1 sarmalama yok). Private key `OneAsymmetricKey` içinde üç seçenek: **seed (32 B, `[0]` tagged, RECOMMENDED)**, expanded, veya **both** (SEQUENCE). "both" seçeneği tam da interop kaygısı yüzünden eklenmiş: *"some may want to use and retain the seed and others may only support expanded private keys."*

**RFC 9909 — SLH-DSA:** 24 OID (12 Pure `sigAlgs 20–31`, 12 HashSLH-DSA `sigAlgs 35–46`). İmza boyutları **7.856 – 49.856 bayt** (!). Public key 32/48/64 B. RFC uyarısı: *"The entire certificate or CRL needs to be held in memory during SLH-DSA signature verification"*, ve büyük CRL'ler HSM sınırlarını aşabilir.

**RFC 9935 — ML-KEM OID'leri:** `id-alg-ml-kem-512` = 2.16.840.1.101.3.4.4.1, `-768` = ...4.2, `-1024` = ...4.3.

**`draft-ietf-lamps-fn-dsa-certificates-00`** (20 Mayıs 2026) — WG dokümanı, FIPS 206 bekliyor.

#### 5.2 ⚠️ CA/Browser Forum — PQC sertifikaları public trust'ta HENÜZ İZİNLİ DEĞİL

- **Geçmiş bir ballot YOK.** Baseline Requirements'ta ML-DSA veya SLH-DSA'ya izin veren onaylanmış hiçbir oylama bulunamadı.
- **Devam eden çalışma:** `cabforum/servercert` reposunda:
  - **PR #679 — "SC-106: Enable Post-Quantum Cryptography (PQ) Key Pairs in TLS Server Certificates"**, açılış **26 Ağustos 2026**, **hâlâ Draft/Open**
  - PR #662 — "SC-XXX: Permit ML-DSA public keys and signatures in certificates" — **kapatıldı** 11.08.2026
  - PR #624 — "Draft SC-XX: Add MLDSA-87" (CBonnell) — **kapatıldı** 29.06.2026
- **13 Ağustos 2026 SCWG tutanakları:** Stephen Davidson ve Gurleen Grewal birleşik ballot üzerinde çalışıyor, *"getting close to completion"*. **Yürürlük tarihi önerilmemiş.**

**SC-106'nın içeriği:** ML-DSA-44/65/87'ye izin; **"pure post-quantum chain"** zorunluluğu (ML-DSA public key yalnızca ML-DSA imzasıyla sertifikalanabilir); CRL/OCSP'ye muafiyet.

**Tartışma noktaları (henüz çözülmedi):** Mozilla ve Chrome temsilcileri geçiş ve cross-signing için **karışık zincirlere izin verilmesini** savunuyor; Chrome tarayıcı dışı PKI kullanım senaryolarının SCWG kapsamında olup olmadığını sorguluyor; CT log'larına ML-DSA sertifika boyutunun getireceği yük tartışılıyor.

- https://github.com/cabforum/servercert/pull/679
- https://cabforum.org/2026/08/13/2026-08-13-minutes-of-the-server-certificate-working-group/

#### 5.3 ⭐ Chrome Quantum-resistant Root Program (CQRP) — X.509 PQC'yi REDDEDİYOR

Bu, planlama açısından çok önemli ve az bilinen bir gelişme.

- Chrome, standart Chrome Root Program'ın yanına **ayrı bir "Chrome Quantum-resistant Root Program"** kurdu.
- **Draft Policy v0.3.0, son güncelleme 14 Ağustos 2026** (birçok bölüm hâlâ `[TODO]`, v1.0.0 beklenen spec'lere bağlı)
- **Politika metni: Chrome, post-quantum içeren geleneksel X.509 sertifikalarını Chrome Root Store'a EKLEMEYECEK.** Yerine **Merkle Tree Certificates (MTC)** kullanılacak.
- **Gerekçe (CQRP FAQ):** *"sending heavy, serialized chains of post-quantum signatures and Certificate Transparency proofs during every TLS handshake creates severe bandwidth penalties and increases connection latency."* MTC'de CA milyonlarca sertifikayı temsil eden tek bir "Tree Head" imzalıyor; sunucu tam zincir yerine kompakt bir kanıt gönderiyor ve CT ek yükü ortadan kalkıyor.
- **Algoritma zorunlulukları:** CA Cosigner ve Mirroring Cosigner anahtarları **yalnızca ML-DSA-44**; abone sertifikaları ML-DSA-44/65/87. **HashML-DSA yasak.** ML-DSA anahtarlarında `parameters` alanı **absent** olmalı. **FIPS 140-3 Level 3 HSM zorunlu.** CA Cosigner anahtarı için azami 6 yıl güven süresi.
- **Takvim (CQRP FAQ):**
  - **Faz 1 (şu an):** Cloudflare ile fizibilite çalışması, X.509 yedekli MTC bağlantı testleri
  - **Faz 2 — hedef Q1 2027:** ilk kamusal MTC bootstrapping; kriterleri karşılayan CT log operatörleri davet edilecek (uygunluk için **1 Şubat 2026'dan önce** çalışan CT log işletiyor olmak gerekiyor)
  - **Faz 3 — hedef Q3 2027:** Chrome Quantum-resistant Root Store'un açılışı ve CA kayıtları
- **Chrome 150+ zaten özel/kurumsal ortamlarda MTC olmayan post-quantum X.509 sertifikalarını destekliyor** — yani private PKI'da bugün test edebilirsiniz.

- https://googlechrome.github.io/chromerootprogram/cqrp/draft-policy
- https://googlechrome.github.io/chromerootprogram/cqrp/faq
- https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/ (27.02.2026, 4 aşama, **tarih verilmemiş**)

**Mozilla:** blog.mozilla.org/security üzerinde PQC / ML-DSA / root store ile ilgili **hiçbir gönderi bulunamadı**. Mozilla'nın PQC root politikası **belirsiz**.

**Cloudflare'in beklentisi:** WebPKI'da ML-DSA sertifikaları **2027 başı**; MTC tabanlı PQ kimlik doğrulama **2027 ortası**; tam PQ **2029**.

---

### 6. TLS

#### 6.1 ⭐ RFC 10024 — hibrit anahtar değişimi artık RFC

- **Tam ad:** "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3"
- **RFC 10024, Ağustos 2026, Standards Track.** (← `draft-ietf-tls-ecdhe-mlkem-05`, 10.08.2026)
- Yazarlar: Kwiatkowski (PQShield), Kampanakis (AWS), Westerbaan (Cloudflare), Stebila (Waterloo)

**IANA TLS Supported Groups — gerçek kayıtlı değerler:**

| Değer | Hex | İsim | Recommended | Referans |
|---|---|---|---|---|
| 4587 | **0x11EB** | SecP256r1MLKEM768 | N | RFC 10024 |
| **4588** | **0x11EC** | **X25519MLKEM768** | **Y** ⭐ | RFC 10024 |
| 4589 | **0x11ED** | SecP384r1MLKEM1024 | N | RFC 10024 |
| 512 | 0x0200 | MLKEM512 | N | draft-connolly-tls-mlkem-key-agreement-05 |
| 513 | 0x0201 | MLKEM768 | N | aynı |
| 514 | 0x0202 | MLKEM1024 | N | aynı |
| 25497 | 0x63A5 | X25519Kyber768Draft00 | **D** (discouraged) | RFC 10024 ile obsolete |
| 25498 | 0x63A6 | SecP256r1Kyber768Draft00 | **D** | RFC 10024 ile obsolete |

**X25519MLKEM768, Recommended=Y işaretli TEK post-quantum gruptur.**

**Tel üzerindeki boyutlar (RFC 10024 §3):** X25519MLKEM768 → istemci key_share **1.216 B** (1.184 ML-KEM ek + 32 X25519), sunucu **1.120 B**, paylaşılan sır 64 B.

**Yan not:** TLS 1.3 yeniden yayınlandı — **RFC 9846, Temmuz 2026**, RFC 8446'yı obsolete ediyor. RFC 10024 artık 9846'ya atıf yapıyor.

**Saf ML-KEM:** `draft-ietf-tls-mlkem-10` (2 Eylül 2026), **"Approved-announcement sent"** (RFC Editor kuyruğunda), hedef **Informational**.

#### 6.2 Benimseme oranı — Eylül 2026

⚠️ **radar.cloudflare.com bot koruması nedeniyle HTTP 403 döndü; canlı Eylül 2026 rakamını çekemedim. Uydurmadım.** Canlı rakam tarayıcıyla https://radar.cloudflare.com/post-quantum adresinden görülebilir.

**Cloudflare birincil kaynaklarındaki belgelenmiş seyir:**

| Tarih | Rakam | Kaynak |
|---|---|---|
| 2024 başı | %3'ün altı | blog.cloudflare.com/radar-origin-pq-key-transparency-aspa |
| Eyl 2025 | Top 100k alan adının **%39'u** PQ anahtar değişimini destekliyor | blog.cloudflare.com/pq-2025 |
| Eki 2025 | İnsan kaynaklı trafiğin **yarısından fazlası** | pq-2025 (28.10.2025) |
| Şub 2026 | **%60'ın üzerinde** | radar-origin-pq-key-transparency-aspa (27.02.2026) |
| **7 Nis 2026** | **%65'in üzerinde** insan trafiği | blog.cloudflare.com/post-quantum-roadmap |
| **23 Haz 2026** | **"üçte ikiden fazla"** tarayıcı trafiği | blog.cloudflare.com/post-quantum-eo-2026 |

**Origin tarafı çok geride:** Cloudflare→müşteri origin bağlantılarında origin'lerin **yalnızca ~%10'u** PQ anahtar değişimini destekliyor (Şub 2026), 2025 başındaki <%1'den ~10 kat artış.

⚠️ Metrik uyarısı: Cloudflare'in manşet rakamı **"insan/tarayıcı kaynaklı"** trafik. Bot/API istemcileri dahil tüm trafik rakamı daha düşük; o rakamı bulamadım.

#### 6.3 İstemci / kütüphane durumu

| Ürün | Durum | Sürüm / Tarih |
|---|---|---|
| **Chrome** | M124 (Nis 2024) X25519Kyber768 varsayılan; **M131'de ML-KEM'e geçiş** (6 Kas 2024). Politika metni: *"Prior to Google Chrome 131, the algorithm was Kyber."* | M131 |
| Chrome kapatma anahtarı | `PostQuantumKeyAgreementEnabled` **kaldırıldı**: `chrome.*:116-146`. M147 stable 7 Nis 2026 → **artık kapatmanın desteklenen yolu yok** | M147+ |
| Chrome stable (bugün) | 152.0.7977.83 (M152 stable 25.08.2026) | |
| **Firefox** | **132** (29 Eki 2024): TLS 1.3 için `mlkem768x25519`. **135** (4 Şub 2025): HTTP/3 + QUIC | 132 / 135 |
| **Apple** | Apple Platform Security: *"On devices with iOS 26, iPadOS 26, or later, TLS 1.3 with quantum-secure encryption (X25519MLKEM768) is enabled by default for URLSession and Network APIs"* | iOS/iPadOS/macOS 26 (Eyl-Eki 2025) |
| **OpenSSL** | **3.5.0 (8 Nis 2025), ilk LTS** — destek 8 Nis 2030'a kadar. ML-KEM + ML-DSA + SLH-DSA. Varsayılan keyshare X25519MLKEM768 + X25519. ⚠️ **OpenSSL 3.0 LTS desteği 7 Eylül 2026'da (dün) bitti** | 3.5 LTS |
| **BoringSSL** | `SSL_GROUP_X25519_MLKEM768 0x11ec`, `SSL_SIGN_ML_DSA_44/65/87 = 0x0904/0905/0906` | main |
| **Go** | **1.24** (Şub 2025): X25519MLKEM768 varsayılan; `GODEBUG=tlsmlkem=0` ile geri alınır | 1.24 |
| **rustls** | 0.23.16 Kyber→ML-KEM; **0.23.22** (30.01.2025) X25519MLKEM768; **0.23.27** (05.05.2025) `prefer-post-quantum` **varsayılan feature**; 0.23.37 (24.02.2026) ML-KEM-1024 | 0.23.27+ |

#### 6.4 ML-DSA ile TLS kimlik doğrulama

- **`draft-ietf-tls-mldsa-05`**, **6 Temmuz 2026**. IESG durumu: **"Approved-announcement to be sent :: AD Followup"** — IESG onayladı, **henüz RFC değil**. Hedef statü: **Informational**. Sorumlu AD: Deb Cooley.

**IANA TLS SignatureScheme — kayıtlı değerler:**
| Hex | İsim | Recommended | Referans |
|---|---|---|---|
| **0x0904** | mldsa44 | N | draft-ietf-tls-mldsa-00 |
| **0x0905** | mldsa65 | N | draft-ietf-tls-mldsa-00 |
| **0x0906** | mldsa87 | N | draft-ietf-tls-mldsa-00 |
| 0x0911–0x091C | slhdsa_sha2_128s … slhdsa_shake_256f (12 adet) | N | draft-reddy-tls-slhdsa-01 |

(Registry hâlâ `-00`'a atıf yapıyor; RFC çıkınca güncellenecek. Tüm PQ imza şemaları Recommended=N.)

**Kim gerçekten ML-DSA ile TLS kimlik doğrulaması yapıyor:**
- **Cloudflare, 29 Temmuz 2026** — "Post-quantum authentication to origins is now supported". ML-DSA-44/65/87, **Authenticated Origin Pulls** (tüm planlarda ücretsiz) ve **Custom Origin Trust Store** (ACM gerekli). Cloudflare **ML-DSA-44** öneriyor. Haziran 2026'da başlatıldı; 10 Haziran 2026'da bir BoringSSL güncellemesi kesintiye yol açtı.
- **rustls 0.23.44 (7 Eylül 2026 — dün):** *"Support for post-quantum secure ML-DSA certificates is now enabled by default in the aws-lc-rs crypto provider."* Öncesinde rustls-post-quantum 0.2.3 (16.07.2025, doğrulama) ve 0.2.4 (23.09.2025, imzalama, `aws-lc-rs-unstable` altında).
- **Hiçbir public WebPKI CA'sı tarayıcıya dönük TLS için ML-DSA sertifikası vermiyor.** Bugün bu tamamen private PKI / origin'e dönük bir hikâye.

#### 6.5 Bilinen sorunlar

**ClientHello boyutu / MTU / ossification.** X25519MLKEM768 istemci key_share'i **1.216 bayta** çıkarıyor; tipik ClientHello artık tek TCP segmentine / QUIC Initial'a sığmıyor.
- Chrome politika metni: *"devices that do not correctly implement TLS may malfunction when offered the new option… Such devices are not post-quantum-ready and will interfere with an enterprise's post-quantum transition."*
- Go 1.24 notları doğrudan **https://tldr.fail/** adresine yönlendiriyor — ClientHello'yu segmentler arasında birleştiremeyen sunucular el sıkışmayı zaman aşımına uğratıyor.
- ⚠️ **RFC 10024'ün kendisinde MTU/middlebox/parçalanma rehberliği YOK** (metin MTU/fragment/middlebox/ossif için tarandı — hiçbiri geçmiyor). Bu tartışma implementasyon dokümanlarında.

**Ölçülmüş middlebox kırılması** (pq-2025, Cloudflare→origin): "hızlı" yaklaşım (PQ key share'i iyimser gönder) bağlantıların **%0,05'ini** kırıyor; "güvenli" yaklaşım (grubu ilan et ama key share gönderme, HelloRetryRequest turunu kabul et) evrensel olarak tolere ediliyor.

**Sertifika/imza boyutu.** Cloudflare'in duruşu (blog.cloudflare.com/ml-dsa-will-have-to-do, 9 Temmuz 2026): daha iyisi zamanında gelmiyor — **FN-DSA ~2033, çok değişkenli şemalar 2034 öncesi değil, SQIsign 2035 öncesi olası değil** — 2030-2035 regülasyon tarihlerine karşı, dolayısıyla *"ML-DSA will have to do."*

**Trust Anchor IDs:** `draft-ietf-tls-trust-anchor-ids-04` (1 Mayıs 2026), aktif TLS WG dokümanı, IESG'de işlem yok. Chrome'da chromestatus özelliği **5132064512540672**, durum **Proposed**, milestone atanmamış — **shipping değil**.

**Merkle Tree Certificates:** çalışma grubu değişti. `draft-davidben-tls-merkle-tree-certs` expire oldu; **yeni PLANTS WG'ye** (PKI, Logs, And Tree Signatures) adopte edildi → **`draft-ietf-plants-merkle-tree-certs-05`**, 6 Temmuz 2026, "I-D Exists".

---

### 7. FIDO2 / WebAuthn PQC — ⚠️ Ekosistemin en geri kalmış alanı

#### 7.1 WebAuthn Level 3 — **W3C Recommendation oldu, ama PQC yok**

- **Durum: W3C Recommendation, 25 Ağustos 2026** (çok yeni!)
- ⚠️ **Doküman post-quantum kriptografiden, ML-DSA'dan veya "quantum" kelimesinden hiç bahsetmiyor.** Spec EdDSA, ES256, RS256 gibi mevcut eğri/RSA algoritmalarına odaklı.
- **Level 4 diye bir halef yok** — doküman kendini Level 2'nin (2021) halefi olarak tanımlıyor, ileriye dönük referans içermiyor.
- https://www.w3.org/TR/webauthn-3/

#### 7.2 CTAP — PQC yok

| Sürüm | Durum | Tarih |
|---|---|---|
| CTAP 2.3.1 | Working Draft | **29 Mayıs 2026** |
| CTAP 2.3 | Proposed Standard | **26 Şubat 2026** |
| CTAP 2.2 | Proposed Standard | 14 Temmuz 2025 |
| CTAP 2.1 | Proposed Standard | 15 Haziran 2021 (errata 21.06.2022) |

**CTAP 2.3 spec metnini doğrudan çektim: "post-quantum", "quantum", "ML-DSA", "Dilithium" veya -48/-49/-50 codepoint'leri geçmiyor.** Spec algoritma seçimini IANA COSE registry'sine ve WebAuthn'a devrediyor: *"PublicKeyCredentialParameters' algorithm identifiers are values that SHOULD be registered in the IANA COSE Algorithms registry."*

**Teorik olarak iyi haber:** COSE ML-DSA codepoint'leri (-48/-49/-50) RFC 9964 ile IANA'ya kayıtlı olduğu için, **CTAP/WebAuthn'ın spec değişikliği gerektirmeden ML-DSA'yı taşıyabilmesi mimari olarak mümkün.** Engel spec değil, **donanım**.

#### 7.3 Donanım — **hiçbir ürün yok, yeni donanım gerekiyor**

Yubico'nun kendi blog yazısı (21 Ekim 2025, "Future-proofing authentication: A look at the future of post-quantum cryptography") net:

> *"Prototype ≠ product: The PQ demo shows feasibility and performance direction, not a shipment announcement."*
> *"New hardware is required: PQ algorithms have bigger footprints; they don't fit on today's keys."*

- FIDO Authenticate konferansında bir donanım güvenlik anahtarında post-quantum imza **prototipi** gösterildi. Beta yetenekler "sınırlı sayıda nitelikli test kullanıcısına" açık.
- Yubico ayrıca standartların olgunlaşması gerektiğini vurguluyor: yalnızca imza üretimi değil, **PIN protokolleri, attestation, kayıt UX'i ve kripto-çevik altyapı** da gerekiyor.
- Yubico'nun **26 Haziran 2026** tarihli EO 14412 yazısında **hiçbir ürün/takvim güncellemesi yok** — yalnızca kurumlara *"Hardware security keys, smart cards, and tokens used in your authentication stack need to support PQC algorithms ML-KEM and ML-DSA"* tavsiyesi veriliyor. Kendi ürünleri hakkında beyan yok.
- Yubico'nun mevcut blog akışında (Ağu-Eyl 2026) PQC gönderisi yok. HyperCloud entegrasyonunda "hybrid post-quantum (RSA+ML-KEM) data-at-rest encryption" geçiyor — ama bu **veri şifreleme**, FIDO kimlik bilgisi değil.

**Sonuç: 8 Eylül 2026 itibarıyla ML-DSA destekleyen sevk edilen hiçbir FIDO2 donanım authenticator'ı bulunamadı.**

#### 7.4 FIDO Alliance — normatif çıktı yok

fidoalliance.org üzerinde PQC ile ilgili bulunanlar yalnızca **etkinlik/webinar** düzeyinde:
- "How Passkeys and Post-Quantum Cryptography Are Reshaping the Future of Security" (webinar, 1 Temmuz 2026)
- "Member Event: Future-Proofing Authentication: FIDO, PKI, and the Path to Post-Quantum Security" (11 Ağustos 2025)
- "IEEE Spectrum: Google Develops Quantum-Safe Security Keys" (haber alıntısı, 1 Eylül 2023 — Google'ın OpenSK'daki Dilithium+ECDSA hibrit denemesi)

**Bulunamadı:** FIDO Alliance'ın yayınlanmış bir PQC yol haritası, beyaz kâğıdı, PQC sertifikasyon programı veya PQC algoritması ekleyen bir CTAP taslağı. **PQC'yi ele alan resmî bir FIDO Alliance normatif dokümanı yok.**

⚠️ Not: Bu bölümde arama bütçesi tükendiği için yalnızca doğrudan site çekimleriyle çalıştım. Duyurulmuş ama bu sayfalarda listelenmemiş bir çalışma olabilir — **kısmen belirsiz.**

---

### 8. Rust Ekosistemi

#### 8.1 Saf Rust — RustCrypto ⚠️

| Crate | Sürüm | Tarih | İndirme | Repo |
|---|---|---|---|---|
| `ml-kem` | **0.3.2** | 10.05.2026 | 2.464.049 | RustCrypto/KEMs |
| `ml-dsa` | **0.1.1** | 05.06.2026 | 770.685 | RustCrypto/signatures |
| `slh-dsa` | **0.2.0-rc.5** | 28.04.2026 | 876.336 | RustCrypto/signatures |

⚠️ **Her üçünün README'sinde de aynı uyarı var:**
> *"⚠️ Security Warning — The implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!"*

Ek olarak: sabit zaman (constant-time) garantisi veya yan kanal direnci hakkında **hiçbir beyan yok**; ACVP test vektörü uyumu belirtilmemiş. `ml-kem`'de `zeroize` bir **opsiyonel feature** (varsayılan değil). Hepsi hâlâ **pre-1.0**, `slh-dsa` ise **release candidate**.

**Bir IdP'nin imza yolunda bunları kullanmasını önermem** — denetlenmemiş, pre-1.0 ve yan kanal beyanı yok.

#### 8.2 aws-lc-rs — üretim için en olgun seçenek ✅

- **Sürüm 1.18.1, 1 Eylül 2026.** 214.900.000+ toplam indirme (78,8M yakın dönem). AWS-LC bağlaması (saf Rust değil), `ring` ile API-uyumlu.
- **ML-KEM:** `aws_lc_rs::kem` modülünde `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024` — "NIST FIPS 203" olarak belgelenmiş, **unstable işaretli değil**.
- **ML-DSA:** `aws_lc_rs::signature` modülünde `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87` (doğrulama) ve `ML_DSA_44_SIGNING`, `ML_DSA_65_SIGNING`, `ML_DSA_87_SIGNING` (imzalama). *"The signature is the raw ML-DSA signature encoding described in FIPS 204."* **unstable işaretli değil.**
- **SLH-DSA:** dokümantasyonda desteğe dair kanıt yok.

#### 8.3 ⚠️ FIPS 140-3 validasyonu — PQC İÇİN HENÜZ YOK

Bu, FIPS zorunluluğu olan bir IdP için **kritik** bir bulgu.

- **CMVP aktif sertifika araması (`Algorithm=ML-KEM`, `CertificateStatus=Active`) → "No certificates match the search criteria" (0 sonuç).**
- **AWS-LC'nin en yeni validasyonu — Sertifika #5429**, "AWS-LC Cryptographic Module (dynamic)", **20 Temmuz 2026**, FIPS 140-3 **Overall Level 1**, sunset 13.08.2029. Onaylı algoritmalar: AES (CBC/CCM/CMAC/CTR/ECB/GCM/GMAC/KW/KWP/XTS), SHA-1, SHA-2, ECDSA, RSA, HKDF/SSH/TLS/PBKDF, KAS-ECC-SSC, Counter DRBG. **ML-KEM ve ML-DSA bu listede YOK.**
- Aktif AWS-LC sertifikaları: #5429 (20.07.2026), #5314 (05.06.2026), #5298 (03.06.2026), #5146 (26.01.2026), #4816 (01.10.2024), #4631 (06.10.2023).
- **Modules In Process (MIP) listesi** (201 modül): `AWS-LC 4 Cryptographic Module` (dynamic ve static) — **"Comment Resolution - Lab"**, 14.08.2026. Ayrıca kuyrukta: Code Siren PQC Library (Desktop/Mobile), CryptoComply 140-3 FIPS Provider with PQC (04.09.2026), PQCryptoLib-Core (25.08.2026).

> **Sonuç: `aws-lc-rs`'i `fips` feature'ı ile derlemek size FIPS-validasyonlu ML-KEM/ML-DSA VERMEZ.** PQC algoritmaları validasyon sınırının dışında. FIPS 140-3 zorunluluğunuz varsa PQC'yi bugün "FIPS modunda" kullanamazsınız. AWS-LC 4 validasyonunu bekleyin.
>
> ⚠️ *Belirsizlik: CMVP arama arayüzünün "Algorithm" filtresi tam eşleşme mi yapıyor doğrulayamadım; ancak #5429 sertifika detay sayfasında ML-KEM/ML-DSA'nın bulunmaması bulguyu bağımsız olarak destekliyor.*

#### 8.4 Diğer crate'ler

| Crate | Sürüm | Tarih | Not |
|---|---|---|---|
| `oqs` (liboqs-rust) | **0.11.0** | 01.05.2025 | liboqs bağlaması; OQS projesi genel olarak üretim için uygun olmadığı uyarısını taşır. **1,5 yıldır güncellenmemiş.** |
| `pqcrypto` | **0.18.1** | 11.12.2024 | Thom Wiggers. ML-KEM, McEliece, HQC, ML-DSA, Falcon, SPHINCS+. **~2 yıldır güncellenmemiş.** |
| `fips204` | **0.4.6** | 22.12.2024 | integritychain, ~1.714 satır. **~2 yıldır güncellenmemiş.** |
| `rustls` | **0.23.44** | 07.09.2026 | Aşağıya bakınız |

#### 8.5 rustls ✅

- **Sürüm 0.23.44, 7 Eylül 2026 (dün).**
- aws-lc-rs sağlayıcısıyla desteklenen anahtar değişim grupları: SECP256R1, SECP384R1, X25519, **MLKEM768, MLKEM1024, X25519MLKEM768, SECP256R1MLKEM768**.
- **0.23.27'den (05.05.2025) itibaren `prefer-post-quantum` varsayılan feature** — PQ anahtar değişimi varsayılan olarak tercih ediliyor.
- **0.23.44 ile: aws-lc-rs sağlayıcısında ML-DSA sertifikaları varsayılan olarak etkin.**

**Rust tarafında TLS için durum iyi. Sorun JOSE tarafında.**

#### 8.6 ⚠️ Rust JOSE/JWT — RFC 9964 implementasyonu YOK

| Crate | Sürüm | Tarih | ML-DSA? |
|---|---|---|---|
| `josekit` | 0.10.3 | **20 Mayıs 2025** | ❌ RFC 9964'ten (Mayıs 2026) **bir yıl önce**; PQC olması mümkün değil |
| `jsonwebtoken` | **11.0.0** | 24 Temmuz 2026 | ❌ `Algorithm` enum'u: HS256/384/512, ES256/384, RS256/384/512, PS256/384/512, EdDSA. **Post-quantum varyant yok.** |

**Bulunamadı:** RFC 9964'ü (alg `ML-DSA-44/65/87`, kty `AKP`) uygulayan hiçbir Rust crate'i.

> **Bu, ekibiniz için en somut boşluk.** JWS/JWT tarafında ML-DSA'yı bugün kullanmak istiyorsanız **kendiniz yazmanız gerekecek**: `aws-lc-rs`'in `ML_DSA_*_SIGNING` API'sini alıp üzerine RFC 9964'ün JWS serileştirmesini + AKP JWK tipini (seed-only `priv`, base64url `pub`) inşa etmek. İyi haber: iş yükü küçük — ML-DSA'nın JWS entegrasyonu düz bir "imzala/doğrula", RSA-PSS gibi parametre karmaşası yok.

⚠️ Rust OIDC/IdP framework'lerinde (`openidconnect`, `rauthy`, `oxide-auth`) PQC desteğini araştıramadım — **belirsiz** (arama bütçesi tükendi).

---

### 9. Bir IdP Ekibi İçin Pratik Çıkarımlar

#### Bugün yapılabilecekler ✅
1. **TLS terminasyonunda X25519MLKEM768'i açın.** RFC 10024 ile standart, Recommended=Y, trafiğin ~2/3'ü zaten kullanıyor. rustls 0.23.27+ / OpenSSL 3.5 LTS ile bedava geliyor. "Harvest now, decrypt later" riskini bugün kapatır.
2. **Origin/servis-içi mTLS'te ML-DSA'ya geçin.** Private PKI'nızı kontrol ediyorsanız engel yok: RFC 9881 (X.509) + rustls 0.23.44 (varsayılan açık) + aws-lc-rs. Cloudflare bunu Temmuz 2026'dan beri üretimde yapıyor.
3. **Kripto-çeviklik (crypto-agility) borcunu şimdi ödeyin.** JWKS'inizin `kty: "AKP"` taşıyabilmesi, `alg` allowlist'inizin veri odaklı olması, anahtar rotasyonunun algoritma değişimini destekleyebilmesi. **En pahalı iş bu, ve şimdi yapılabilir.**
4. **CBOM (cryptographic bill of materials) çıkarın.** EO 14412 uyarınca CISA rehberliği geliyor; federal müşteriniz varsa zaten isteyecekler.
5. **Anahtar üretimini seed-tabanlı kurgulayın.** RFC 9964 `priv` için 32 baytlık seed'i **zorunlu** kılıyor. HSM'iniz sadece expanded key veriyorsa şimdi öğrenin.

#### Şimdi başlatılabilecek işler 🔨
6. **RFC 9964 JWS desteğini kendiniz yazın** (Rust'ta yok). `aws-lc-rs` üzerine ince bir katman. JWKS'te AKP anahtarlarını yayınlamaya başlayın — istemciler `alg`'ı tanımıyorsa yok sayacaktır.
7. **Token boyutu bütçenizi test edin.** ML-DSA-44 imzası **2.420 bayt** → base64url ≈ **3.227 karakter**. Ed25519 (64 B → 86 karakter) ile karşılaştırın. Cookie boyut limitleri (4 KB), HTTP header limitleri (nginx varsayılan 8 KB, ALB 16 KB), URL fragment akışları — hepsi kırılabilir. **Bunu bugün ölçün.**

#### Bekleyin ⏸️
8. **JWE için PQ şifreleme:** yok. `draft-ietf-jose-pqc-kem-06` yalnızca COSE kapsıyor; `draft-ietf-jose-hpke-encrypt-22` ML-KEM içermiyor. Şifreli ID token / JARM kullanıyorsanız bugün kuantum-güvenli seçenek yok.
9. **Public trust PQC sertifikaları:** CA/B Forum SC-106 hâlâ draft PR. Chrome ise X.509 PQC'yi root store'a **almayacağını** ilan etti — MTC'ye gidiyor (Faz 2 Q1 2027, Faz 3 Q3 2027). Cloudflare beklentisi WebPKI'da ML-DSA "2027 başı".
10. **FIDO2 PQC:** WebAuthn L3'te bahsi bile yok, CTAP 2.3'te yok, donanım yok (Yubico: "yeni donanım gerekiyor"). **2028+ konusu.** Passkey stratejinizi buna göre planlayın — passkey'ler kuantum geçişinde en geç kalan halka olacak.
11. **FIPS 140-3 validasyonlu PQC:** kuyrukta, henüz yok. AWS-LC 4 "Comment Resolution" aşamasında.
12. **SLH-DSA JOSE/COSE:** IESG'de ama codepoint'ler henüz IANA'da yok; ayrıca yalnızca 2 parametre seti (128s) tanımlanıyor.

#### Takvim çıpaları 📅
| Tarih | Olay |
|---|---|
| Q1 2027 | Chrome CQRP Faz 2 (MTC bootstrapping) |
| ~2027 | Chrome CQRP Faz 3; WebPKI'da ML-DSA (Cloudflare beklentisi); HQC finali (NIST hedefi) |
| geç 2026 – erken 2027 | FIPS 206 / FN-DSA (draft-ietf-cose-falcon beklentisi) |
| 2029 | Cloudflare tam PQ hedefi |
| **31 Ara 2030** | **EO 14412: anahtar tesisi PQC (+ yükleniciler)**; CNSA 2.0 yazılım imzalama & ağ ekipmanı |
| **31 Ara 2031** | **EO 14412: imza/kimlik doğrulama PQC** ← IdP'nin asıl tarihi |
| 2033 | CNSA 2.0 web/bulut ve işletim sistemleri |
| 2035 | IR 8547 (taslak) "disallowed" |

#### ⚠️ Parametre seti çelişkisine dikkat
Web/IETF ekosistemi **ML-DSA-44** ve **ML-KEM-768** etrafında toplanıyor (Chrome CQRP CA cosigner'ları için ML-DSA-44 **zorunlu**; Cloudflare ML-DSA-44 öneriyor; X25519MLKEM768 tek Recommended=Y grup). CNSA 2.0 ise **yalnızca ML-DSA-87 ve ML-KEM-1024**'e izin veriyor. NSS müşteriniz varsa **iki ayrı profil** desteklemeniz gerekecek.

---

### 10. Belirsizlikler ve Bulunamayanlar (dürüst liste)

**Bulunamadı / doğrulanamadı:**
1. **Cloudflare Radar'ın canlı Eylül 2026 yüzdesi** — radar.cloudflare.com bot koruması nedeniyle 403 döndü, Radar API token istiyor. **Rakam uydurulmadı.** Alıntılanabilir en güncel rakam: "üçte ikiden fazla" (23 Haziran 2026). Bot dahil tüm-trafik rakamı hiç bulunamadı.
2. **NSA CNSA 2.0 birincil PDF'i** — media.defense.gov ve nsa.gov 403 döndü. Takvim tablosu **ikincil kaynaktan**; doğrulanması gerekir. NSA'nın 2025/2026'da takvimi revize edip etmediği **belirsiz**.
3. **HQC'nin FIPS numarası** — hiçbir NIST kaynağında atanmış numara yok. Dolaşan "FIPS 207" iddiası doğrulanamadı.
4. **FIPS 206 taslağının 28 Ağustos 2025'te onaya gönderildiği** iddiası — yalnızca ikincil kaynaklarda, NIST'te doğrulanamadı.
5. **Federal Register'da EO 14412'nin resmî sitesi/atıfı** — federalregister.gov erişimi engelledi. Ancak **whitehouse.gov'dan doğrudan doğrulandı**.
6. **Rust OIDC/IdP framework'lerinde PQC desteği** (`openidconnect`, `rauthy`, `oxide-auth`) — araştırılamadı, arama bütçesi tükendi.
7. **Mozilla root store'un PQC politikası** — blog.mozilla.org/security'de hiçbir PQC gönderisi yok.
8. **FIDO Alliance'ın duyurulmuş ama site listelerinde görünmeyen PQC çalışması** olabilir — bu bölüm yalnızca doğrudan site çekimiyle yapıldı, kısmen belirsiz.

**Çelişkili / dikkat gerektiren:**
9. **Firefox'ta "varsayılan açık" sürümü:** FF 132 notu "Added support for" diyor; Cloudflare Kasım 2024'te varsayılan olduğunu söylüyor. Mozilla birincil kaynağından pref varsayılanı doğrulanamadı — **muhtemelen 132, belirsiz**.
10. **Chrome 131'in ML-KEM geçiş noktası** kurumsal politika açıklamasından çıkarıldı (otoriter ama release note değil).
11. **`draft-ietf-tls-mldsa` ve `draft-ietf-tls-mlkem` ikisi de Informational** — codepoint kaydı için alışılmadık. Datatracker API'sinden doğrulandı, ama WG gerekçesi bulunamadı.
12. **COSE codepoint çakışması riski:** `cose-falcon` -54/-55 istiyor, `jose-pq-composite-sigs` -54..-59 istiyor. İkisi de TBD. **Bu değerleri koda sabit yazmayın.**
13. **CMVP "Algorithm=ML-KEM" aramasının 0 sonuç vermesi** filtre davranışından da kaynaklanabilir; ancak AWS-LC #5429 sertifika detayında ML-KEM/ML-DSA'nın olmaması bulguyu destekliyor.

---

### Kaynak URL'leri

**NIST:** [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) · [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) · [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) · [PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization) · [PQC News](https://csrc.nist.gov/Projects/post-quantum-cryptography/news) · [IR 8545](https://csrc.nist.gov/pubs/ir/8545/final) · [IR 8547 ipd](https://csrc.nist.gov/pubs/ir/8547/ipd) · [IR 8610](https://csrc.nist.gov/pubs/ir/8610/final) · [SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) · [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final) · [SP 800-230 ipd](https://csrc.nist.gov/pubs/sp/800/230/ipd) · [SP 800-131A r3 ipd](https://csrc.nist.gov/pubs/sp/800/131/a/r3/ipd) · [HQC duyurusu](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption) · [CMVP cert 5429](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5429) · [CMVP MIP](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list)

**Beyaz Saray:** [EO 14412](https://www.whitehouse.gov/presidential-actions/2026/06/securing-the-nation-against-advanced-cryptographic-attacks/)

**IETF/IANA:** [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) · [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) · [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909.html) · [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html) · [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) · [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) · [RFC 9958](https://datatracker.ietf.org/doc/rfc9958/) · [RFC 9955](https://datatracker.ietf.org/doc/rfc9955/) · [IANA COSE](https://www.iana.org/assignments/cose/cose.xhtml) · [IANA JOSE](https://www.iana.org/assignments/jose/jose.xhtml) · [IANA TLS](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml) · [COSE WG](https://datatracker.ietf.org/wg/cose/documents/) · [JOSE WG](https://datatracker.ietf.org/wg/jose/documents/) · [LAMPS WG](https://datatracker.ietf.org/wg/lamps/documents/) · [PQUIP WG](https://datatracker.ietf.org/wg/pquip/documents/) · [draft-ietf-cose-sphincs-plus](https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/) · [draft-ietf-cose-falcon](https://datatracker.ietf.org/doc/draft-ietf-cose-falcon/) · [draft-ietf-jose-pqc-kem](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/) · [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/) · [draft-ietf-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) · [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) · [draft-ietf-lamps-pq-composite-kem](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/) · [draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/) · [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) · [draft-ietf-tls-trust-anchor-ids](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/) · [draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/) · [draft-ietf-oauth-rfc8725bis](https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/)

**PKI/Tarayıcı:** [CA/B Forum SC-106 PR](https://github.com/cabforum/servercert/pull/679) · [SCWG 13.08.2026 tutanak](https://cabforum.org/2026/08/13/2026-08-13-minutes-of-the-server-certificate-working-group/) · [Chrome CQRP policy](https://googlechrome.github.io/chromerootprogram/cqrp/draft-policy) · [Chrome CQRP FAQ](https://googlechrome.github.io/chromerootprogram/cqrp/faq) · [Chromium PQ auth roadmap](https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/)

**FIDO/W3C:** [WebAuthn L3](https://www.w3.org/TR/webauthn-3/) · [FIDO spec indirme](https://fidoalliance.org/specifications/download/) · [Yubico PQC yazısı](https://www.yubico.com/blog/future-proofing-authentication-a-look-at-the-future-of-post-quantum-cryptography/)

**Cloudflare:** [pq-2025](https://blog.cloudflare.com/pq-2025/) · [PQ roadmap](https://blog.cloudflare.com/post-quantum-roadmap/) · [ML-DSA will have to do](https://blog.cloudflare.com/ml-dsa-will-have-to-do/) · [PQ origin auth](https://blog.cloudflare.com/post-quantum-authentication-to-origins/) · [Radar PQ transparency](https://blog.cloudflare.com/radar-origin-pq-key-transparency-aspa/) · [EO yazısı](https://blog.cloudflare.com/post-quantum-eo-2026/)

**Rust:** [ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa) · [ml-kem](https://github.com/RustCrypto/KEMs/tree/master/ml-kem) · [aws-lc-rs kem](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/kem/index.html) · [aws-lc-rs signature](https://docs.rs/aws-lc-rs/latest/aws_lc_rs/signature/index.html) · [AWS-LC PQREADME](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/PQREADME.md) · [rustls kx_group](https://docs.rs/rustls/latest/rustls/crypto/aws_lc_rs/kx_group/index.html) · [jsonwebtoken Algorithm](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/enum.Algorithm.html)

**Diğer:** [OpenSSL 3.5 notları](https://openssl-library.org/news/openssl-3.5-notes/) · [Go 1.24](https://go.dev/doc/go1.24) · [Apple TLS security](https://support.apple.com/guide/security/tls-security-sec100a75d12/web) · [tldr.fail](https://tldr.fail/)

---

## HAT 2 — WebAuthn Level 3 / CTAP 2.3 / Passkey Ekosistemi

## WebAuthn / Passkey Durum Raporu — 8 Eylül 2026
### Rust tabanlı sunucu taraflı Identity Provider (RP) ekibi için

**Metodoloji notu:** Aşağıdaki bulguların büyük kısmı birincil kaynaklardan (w3.org/TR, fidoalliance.org/specs dizin listeleri, github.com/w3c/webauthn, crates.io API, raw GitHub kaynak dosyaları) doğrulandı. Doğrulayamadığım noktalar **[DOĞRULANMADI]** olarak işaretlendi. Bu oturumda WebSearch kotası doldu; son bölümdeki bazı boşluklar bu yüzden kapatılamadı.

---

### 1. WebAuthn Level 3 spec durumu

| Öğe | Değer |
|---|---|
| Tam ad | Web Authentication: An API for accessing Public Key Credentials — Level 3 |
| Durum | **W3C Recommendation (REC)** — yani tamamlandı |
| REC tarihi | **25 Ağustos 2026** |
| Sabit URL | https://www.w3.org/TR/2026/REC-webauthn-3-20260825/ |
| Canlı URL | https://www.w3.org/TR/webauthn-3/ |
| CR Snapshot | 26 Mayıs 2026 |
| PR (Proposed Rec) duyurusu | 20 Temmuz 2026 |

Spec metni: "There have been no substantive changes since the Candidate Recommendation Snapshot of 26 May 2026." Yani Mayıs 2026'dan beri normatif değişiklik yok — **L3'e karşı kodlamak artık güvenli**.

Kaynaklar:
- https://www.w3.org/TR/webauthn-3/
- https://www.w3.org/news/2026/proposed-advancement-of-webauthn-3-to-w3c-recommendation/
- https://www.w3.org/news/2026/w3c-invites-implementations-of-web-authentication-an-api-for-accessing-public-key-credentials-level-3/

#### Level 4 başladı mı? — Evet, tam şu anda

- W3C Web Authentication WG taslak charter'ı (2026) **tek normatif deliverable olarak "WebAuthn Level 4"** listeliyor. Charter 2 yıllık; **L4 için hedef tamamlanma Q4 2028**. Önceki charter 30 Nisan 2024 – 30 Nisan 2026 arasıydı.
  - https://w3c.github.io/charter-drafts/2026/charter-wg-webauthn-2026.html
- GitHub milestone **"L4 (First Published Working Draft)"**: **due date 9 Eylül 2026** (yani yarın), %81 tamamlanmış, 11 açık / 47 kapalı issue.
  - https://github.com/w3c/webauthn/milestone/27

**L4 kapsamına giren açık issue'lar (RP tarafını ilgilendirenler kalın):**
- #2291 — **Add Immediate uiMode** (aşağıda 2.8)
- #2078 — **Add "sign" extension** (ham imzalama; dijital cüzdan / belge imzalama / AI ajanları)
- #2437 — **Support Algorithm Migration** (post-quantum geçişi için kritik)
- #2393 — **Add ML-DSA test vectors** (post-quantum)
- #2377 — Add "Credential Manager Trust Group (CMTG) Key" extension
- #2150 — Exclude platform authenticators with self-attestation
- #2095 — Alternative error codes
- #2072 — WebDriver BiDi desteği
- #2404 — CTAP 2.3 version string for virtual authenticators

Charter'ın kapsama eklediği yeni başlıklar: remote desktop / non-modal UI, credential backup & recovery seçenekleri, transport ve "durability" sinyalleri, **WebAuthn aracılı ham imzalama (AI ajanları dahil)**, authenticator hakkında gizlilik korumalı güven sinyalleri, gizlilik için genişletilmiş WebAuthn Extensions.

**IdP ekibi için çıkarım:** L3 hedefleyin, L4'ü izleyin. L4'teki "durability signals" ve "trust signals" doğrudan sizin device-bound vs synced politikanızı etkileyecek.

---

### 2. L3 özellikleri ve SUNUCU TARAFI etkileri

#### 2.1 PRF extension (hmac-secret)

**Ne yapar:** Authenticator içinde credential'a bağlı bir gizli anahtardan, RP'nin verdiği salt ile deterministik 32 baytlık çıktı türetir. E2E şifreleme anahtarı için kullanılır.

**CTAP eşlemesi:** Tarayıcıdaki `prf` = CTAP2'deki `hmac-secret` eklentisi.

**Kritik salt türetmesi (tarayıcı yapar, siz değil):**
```
actualSalt = SHA-256( UTF8("WebAuthn PRF") || 0x00 || developerSalt )
```
Bu, web bağlamında türetilen sırların native/CTAP bağlamından kriptografik olarak izole olmasını sağlar. **Native uygulama SDK'ları (YubiKit, libfido2) bu prefix'i uygulamaz** — native ve web aynı sırrı istiyorsa domain separation'ı kendiniz yapmalısınız.

**API şekilleri:**
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
`evalByCredential`, W3C spec'inde **credential ID'nin base64url string hali** ile anahtarlanır (raw bytes değil). Rust tarafında serileştirirken buna dikkat.

**Sunucu ne saklamalı / ne saklamamalı:**
- **SAKLA:** credential ID ile birlikte **credential başına rastgele bir salt** (kayıt sırasında üretilir). Bu salt gizli değil, ama benzersiz olmalı.
- **SAKLA:** `prf.enabled` bayrağı (bu credential PRF destekliyor mu) — UI'da "bu cihazla şifreli veriye erişebilirsiniz" demek için.
- **ASLA SAKLAMA:** PRF çıktısının kendisi. Türetilmiş anahtar tarayıcıda kalır; sunucu **sadece ciphertext** görür.
- Anahtar rotasyonu için `first`/`second` ikilisini kullanın: eski salt `first`, yeni salt `second` → tek işlemde iki sır, geçiş yapabilirsiniz.
- Pratik desen: `HKDF(prf.results.first, info="enc")` → AES-GCM anahtarı, `HKDF(prf.results.second, info="mac")` → HMAC anahtarı; ayrık `info` string'leri ile.

**Platform destek uyarıları (Yubico rehberi, ~2025 ortası verisi — 2026 için [KISMEN DOĞRULANDI]):**
| Platform | Platform passkey | Harici anahtar (YubiKey) |
|---|---|---|
| Windows 11 | **Hayır** — Windows Hello hmac-secret desteklemiyor | Evet (Chrome/Edge/Firefox) |
| macOS 15+ | Evet (iCloud Keychain, Safari 18+) | Chrome: evet, **Safari: hayır** |
| iOS/iPadOS 18+ | Evet (iCloud Keychain) | **Hayır** — iOS harici authenticator'a extension verisi geçirmiyor |
| Android | Evet (Google Password Manager) | USB: evet, **NFC: hayır** |

**En önemli sonuç:** PRF tabanlı E2E şifrelemeyi tek kimlik doğrulama yöntemi yapmayın. Windows Hello platform passkey'leri ve iOS+YubiKey kombinasyonu çalışmaz. Mutlaka fallback (parola tabanlı KDF veya kurtarma kodu) tasarlayın.

Kaynaklar:
- https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html
- https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html
- https://github.com/w3c/webauthn/wiki/Explainer:-PRF-extension
- https://bitwarden.com/blog/prf-webauthn-and-its-role-in-passkeys/

#### 2.2 largeBlob durumu

- L3 REC'te **hâlâ mevcut**: §10.1.5 "Large blob storage extension (largeBlob)".
- w3c/webauthn issue taramasında **deprecation, at-risk veya kaldırma tartışması bulunamadı**. Yani spec seviyesinde sağlıklı.
- Bilinen kısıt (issue #1622'de netleştirilmiş): **CTAP authenticator'larda discoverable credential zorunlu**.
- Pratik gerçek: destek dar ve PRF çoğu kullanım senaryosunda yerini aldı. **[DOĞRULANMADI]** — 2026 için güncel tarayıcı/platform destek matrisini bulamadım; passkeys.dev destek matrisi largeBlob'u listelemiyor.

**IdP tavsiyesi:** largeBlob'a bağımlılık kurmayın. Küçük sırlar için PRF + sunucuda ciphertext saklama modeli çok daha taşınabilir.

#### 2.3 Related Origin Requests (ROR)

**Dosya:** `https://<RP ID>/.well-known/webauthn`
```json
{
  "origins": [
    "https://example.co.uk",
    "https://example.de",
    "https://myshoppingrewards.com"
  ]
}
```

**Sunucu tarafı gereksinimleri (kesin):**
- HTTPS üzerinden servis edilmeli
- `Content-Type: application/json` **zorunlu**
- HTTP **200** dönmeli
- Tarayıcı bu dosyayı **credentials olmadan ve Referer başlığı olmadan** çeker — yani auth arkasına koymayın, CDN/edge'de cache'lenebilir olmalı
- RP ID'nin kendisiyle eşleşen origin'leri listelemeye gerek yok

**Label limiti:** `maxLabels` = **5**. "Label", eTLD+1'in soldaki etiketi (örn. `shopping.com` ve `shopping.co.uk` → ikisi de "shopping" label'ı, **tek** sayılır). Spec istemcilerin en az 5 desteklemesini şart koşuyor; **5'ten fazlasını destekleyen bilinen istemci yok, 5'i tavan kabul edin.**

**Tarayıcı desteği (passkeys.dev device-support matrisi, son güncelleme 20 Mayıs 2026):**
- Chrome 128+, Edge 128+ (çoğu platform)
- Firefox 152+
- Safari: matris "macOS Safari 15+" diyor — bu **büyük olasılıkla hatalı/bozuk bir satır** (Safari 15 WebAuthn L3 öncesi). **[DOĞRULANMADI]** — Safari'nin ROR desteğini kesinleştiremedim.

**Runtime tespiti:** `PublicKeyCredential.getClientCapabilities()` → `relatedOrigins` alanı.

**Mimari uyarı:** passkeys.dev açıkça diyor ki *ROR, federation mümkün DEĞİLKEN kullanılmalıdır*. Siz zaten bir **Identity Provider** yazıyorsunuz — yani OIDC/SAML federation'ı zaten elinizde. ROR'u sadece IdP'nin kendi çoklu markalı/çoklu ülkeli domainleri için düşünün, müşteri RP'leri için değil. Ayrıca ROR desteklemeyen istemciler için identifier-first akışı + backend lookup fallback'i şart.

Kaynaklar:
- https://passkeys.dev/docs/advanced/related-origins/
- https://github.com/w3c/webauthn/blob/main/explainers/related-origin-requests.md (artık bakımda değil, passkeys.dev'e yönlendiriyor)
- https://www.w3.org/TR/webauthn-3/#sctn-related-origins

#### 2.4 Signal API

Üç statik metot (`PublicKeyCredential.` üzerinde):

| Metot | Ne zaman çağrılır | Sunucu tarafı sorumluluğu |
|---|---|---|
| `signalUnknownCredential()` | Bilinmeyen credential ID ile başarısız bir sign-in girişiminden **sonra** — kullanıcı authenticated DEĞİLKEN çağrılabilir | Sunucu "bu credential ID bende yok" cevabını dönmeli; frontend bu sinyali gönderir. Provider yetim passkey'i siler. |
| `signalAllAcceptedCredentials()` | **Sadece authenticated kullanıcı için**. Her başarılı girişte ve credential yönetimi değişikliğinden sonra | Sunucu, kullanıcının **TÜM** geçerli credential ID'lerini + `userId` (userHandle) döndürmeli |
| `signalCurrentUserDetails()` | Kullanıcı adı/görünen ad güncellendiğinde **ve her girişte** | Sunucu güncel `name` ve `displayName` döndürmeli |

**KRİTİK TEHLİKE:** `signalAllAcceptedCredentials()` çağrısında listeden **eksik bıraktığınız her geçerli credential provider tarafından gizlenir**. Boş liste gönderirseniz kullanıcının tüm passkey'leri gizlenir. Sayfalama (pagination) uygulanmış bir credential listesi endpoint'ini asla doğrudan bu API'ye bağlamayın — tam liste dönmelisiniz. Bazı provider'lar sonraki çağrıyla geri getirebilir, ama garanti değil.

**Tarayıcı desteği:**
- Chrome / Edge **132+** masaüstü — Ocak 2025
- Chrome Android **144** — 5 Aralık 2025
- Safari: Temmuz 2026 itibarıyla **shipped değil** (Safari 26 hedef olarak gösterilmişti)
- Firefox: **shipped değil**, resmi tutum yok

**Provider davranışı:** Google Password Manager sinyalleri aktif olarak işliyor. Chrome eklenti tabanlı provider'lar kendi kararlarını veriyor.

Kaynaklar:
- https://developer.chrome.com/docs/identity/webauthn-signal-api
- https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/signalAllAcceptedCredentials_static
- https://www.w3.org/TR/webauthn-3/#sctn-signal-methods

**Sunucu tarafı iş listesi:**
1. `GET /credentials/signal-payload` gibi bir endpoint: authenticated kullanıcı için `{ rpId, userId, allAcceptedCredentialIds: [...] }` (tam liste, sayfalama yok)
2. Başarısız doğrulamada credential ID'yi frontend'e geri verip `signalUnknownCredential` tetiklenmesini sağlayın
3. Profil güncelleme akışına `signalCurrentUserDetails` hook'u

#### 2.5 Conditional mediation / conditional create

**Conditional get (autofill UI)** — `mediation: 'conditional'` + `autocomplete="username webauthn"`:
- Android: Chrome 108+, Edge 122+, Firefox
- iOS/iPadOS: Safari 16.1+, Chrome 108+, Firefox 122+, Edge 122+
- macOS: Safari 16.1+, Chrome 108+, Firefox 122+, Edge 122+
- Windows: Chrome 108+, Edge 122+, Firefox 122+

**Conditional create (otomatik passkey yükseltmesi / "passkey upgrades")** — parola ile girişten sonra sessizce passkey oluşturur:
- macOS: Safari 18+, Chrome 136+
- Windows: Chrome 136+
- iOS/iPadOS: iOS 18+ (Safari ve diğer tarayıcılar, Apple Passwords)
- **Android: Chrome 142+** (Google Password Manager ile)
- Firefox: **desteklemiyor**
- Üçüncü parti parola yöneticisi kapsamı düzensiz

**Sunucu tarafı etkileri (önemli):**
- Chrome **parola doldurulmasından sonra 5 dakikalık katı bir pencere** uyguluyor; nihai kararı Google Password Manager veriyor. Apple'da karar mercii Authentication Services; yayınlanmış kesin pencere yok.
- **UI göstermeden credential oluşur** → kullanıcı bunu bilmez. Kullanıcıya sonradan "hesabınıza bir passkey eklendi" bildirimi gönderin ve credential yönetim ekranınızda görünür yapın.
- `excludeCredentials` listesini doğru doldurun — yoksa aynı provider'da mükerrer passkey birikir.
- `credProps.rk` çıktısını kontrol edin: discoverable olmayan bir credential oluşmuşsa passkey UX'i çalışmaz.
- Bu akışta **attestation isteme** — sessiz akışı bozar.

Kaynaklar:
- https://developer.chrome.com/docs/identity/webauthn-conditional-create
- https://passkeys.dev/device-support/
- https://chromestatus.com/feature/5135710007590912

#### 2.6 Cross-device authentication (hybrid transport)

- Hybrid transport (QR + BLE yakınlık) artık CTAP spec'inin normal parçası; roaming security key'ler değil, **platform authenticator'lar ve istemciler** tarafından uygulanıyor.
- Platform desteği: Android 9+, iOS 16+, macOS 13+.
- **CTAP 2.3 (Şubat 2026) hybrid için birden fazla veri aktarım kanalı ekledi** — mevcut WebSocket'e ek olarak **Bluetooth Low Energy** veri kanalı. Bu, internet bağlantısı zayıf senaryolarda güvenilirliği artırır.
- **RP tarafı etkisi neredeyse yok.** Sadece `transports` alanında `"hybrid"` değerini tanıyıp saklamanız yeterli (`AuthenticatorTransport` enum'unuzda bilinmeyen değerleri hata vermeden kabul edin — bu ileride yeni transport'lar eklendiğinde kırılmamanız için kritik).

#### 2.7 credProps, credProtect, minPinLength, devicePubKey

| Extension | Durum | RP tarafı |
|---|---|---|
| **credProps** | L3'te tanımlı, yaygın destekleniyor. Issue #1988 ile **doğrulama (assertion) sırasında da kullanımına** izin verildi (29 Kas 2023) | `rk: true/false` sakla — credential'ın gerçekten discoverable olup olmadığını bilmenin tek yolu. Discoverable değilse usernameless akışa sokmayın. |
| **credProtect** | CTAP 2.1 eklentisi, WebAuthn Extension Registry'de kayıtlı (WebAuthn core spec TOC'unda yok — bu normal) | `userVerificationRequired` (level 3) isteyebilirsiniz; ancak zorlarsanız desteklemeyen authenticator'lar reddeder. Genelde `userVerificationOptionalWithCredentialIDList` (level 2) makul. |
| **minPinLength** | CTAP 2.1 eklentisi, kayıtlı | Sadece attestation ile anlamlı; kurumsal senaryolar. Tüketici IdP'sinde gereksiz. |
| **devicePubKey** (device-bound key) | **L3'ten çıkarıldı.** Üç yönlü doğrulandı: L3 REC'te (25 Ağu 2026) "devicePubKey"/"device-bound" ifadesi yok; Editor's Draft'ın (3 Eyl 2026) tanımlı uzantı listesi `appid`, `appidExclude`, `credProps`, `prf`, `largeBlob`, `remoteClientDataJSON`'dan ibaret; ilgili tüm issue'lar (#1691, #1658, #1846, #1817, #1922, #1739) kapalı. | **Üzerine mimari kurmayın.** Device-bound garanti istiyorsanız ayrı bir device-bound credential (security key veya attested platform authenticator) kaydettirin. |

#### 2.8 Immediate mediation / "get if available"

**ÖNEMLİ API DEĞİŞİKLİĞİ:** `mediation: 'immediate'` **artık çalışmıyor**. Spec 5 Kasım 2025'te güncellendi; doğru alan artık **`uiMode: 'immediate'`**.

```js
const cred = await navigator.credentials.get({
  publicKey: { challenge, rpId, allowCredentials: [] },  // allowlist BOŞ olmalı
  uiMode: 'immediate'
});
```

**Davranış:**
- Yerelde credential varsa anında sunar; yoksa **hiç UI göstermeden** `NotAllowedError` DOMException ile reddeder.
- Öncesinde **user gesture** zorunlu
- Tarayıcı ardışık çağrıları **rate-limit** eder
- **Gizli/private modda her zaman `NotAllowedError`** fırlatır
- **`allowCredentials` dolu istekler reddedilir** (tracking önlemi)
- `signal` (AbortController) parametresi kullanılamaz

**Tespit:** `getClientCapabilities()` → `immediateGet`

**Durum:** Chrome **149**'da genel kullanıma açıldı. Mayıs 2026 itibarıyla **immediate UI mode'u destekleyen tek tarayıcı Chrome**. Safari ve Firefox: değerlendiriyor, kamuya açık taahhüt yok.

**Spec seviyesi:** Bu özellik **Credential Management API'yi genişletiyor** ve w3c/webauthn'da **L4 milestone'unda (issue #2291)**. Yani **L3 REC'in parçası DEĞİL.**

**Gizlilik notu (IdP olarak sizi ilgilendirir):** Bu API, siteye "bu kullanıcıda credential var mı" bilgisini zamanlama farkıyla sızdırır. Yukarıdaki kısıtlar bu yüzden var. Kullanımınızı tek bir "Sign in" butonuna bağlayın, sayfa yüklenmesinde otomatik tetiklemeyin.

Kaynaklar:
- https://github.com/w3c/webauthn/blob/main/explainers/immediate-mediation.md
- https://developer.chrome.com/blog/webauthn-immediate-ui
- https://developer.chrome.com/docs/identity/immediate-ui-mode

---

### 3. CTAP durumu

| Spec | Sürüm | Durum | Tarih |
|---|---|---|---|
| CTAP | 2.1 | Proposed Standard | 15 Haz 2021 |
| CTAP | **2.2** | **Proposed Standard** | **14 Tem 2025** |
| CTAP | **2.3** | **Proposed Standard** | **26 Şub 2026** |
| CTAP | **2.3.1** | **Working Draft** | **29 May 2026** |
| FIDO Server Requirements | **2.3** | **Review Draft** | **26 Şub 2026** |

- CTAP 2.3 URL: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html
- Server Requirements URL: https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html
- Dizin: https://fidoalliance.org/specs/

#### CTAP 2.2 ne getirdi
- **hmac-secret-mc**: hmac-secret'ı `authenticatorMakeCredential` sırasında da çalıştırır → **kayıt anında PRF çıktısı alabilirsiniz**, ikinci bir doğrulama turu gerekmez. E2E şifrelemeli onboarding için büyük UX kazancı.
- **Persistent PIN/UV Auth Tokens (PPUAT)**: power cycle'a dayanan, sadece okuma amaçlı (`enumerateRPs`, `enumerateCredentials`, `getCredentialMetadata`) dar kapsamlı token. RP etkisi yok, native credential yönetim araçlarını ilgilendirir.
- **PIN complexity policy**: `getInfo`'da `pinComplexityPolicy` ve `pinComplexityPolicyURL`. RP etkisi yok.
- **thirdPartyPayment extension**: işlem başlatanın RP'den farklı olduğu senaryolar (PSD2 SCA / Secure Payment Confirmation). **Ödeme akışı olan IdP'ler için ilgili.**
- **Hybrid transport** normatifleşti.
- **Zenginleşen getInfo**: `attestationFormats` (RP tercih ettiği formatı seçebilir), `maxPINLength`, `uvCountSinceLastPinEntry`.
- **JSON-over-CTAP**: Digital Credentials API isteklerini hybrid transport üzerinden JSON olarak taşır. Geleneksel RP sunucularını **etkilemez**.

#### CTAP 2.3 ne getirdi (26 Şub 2026)
- **Breaking change YOK** — CTAP 2.2 uyumlu her implementasyon otomatik olarak 2.3 uyumlu. FIDO, 2.2 için ayrı sertifikasyon kategorisi açmadı; **2.3 artık tüm FIDO2 sertifikasyonlarının temeli**.
- Hybrid için **çoklu veri aktarım kanalı → BLE** eklendi
- **Long Touch for Reset**
- `authenticatorGetInfo` versions listesine `FIDO_2_3`
- NFC (ISO7816/ISO14443) kullanıcı etkileşim gereksinimleri netleştirildi
- `setMinPINLength` ve `pinComplexityPolicy` etkileşimleri geliştirildi
- `authenticatorReset` veya eşdeğer fabrika sıfırlama zorunlu hale geldi
- Smart Card arayüzü desteklenen FIDO arayüzleri listesine eklendi

#### FIDO Server Requirements v2.3 — SİZİ DOĞRUDAN İLGİLENDİRİR
- **Post-quantum ML-DSA algoritmaları önerilen listeye eklendi: ML-DSA-44, ML-DSA-65, ML-DSA-87**
- **Fully-specified algoritmalar eklendi: ESP256, ESP384, ESP512, Ed25519**

**Rust IdP için aksiyon:** COSE algoritma tablonuzu genişletmeye hazırlanın. `pubKeyCredParams` listenize ESP256/Ed25519'u eklemeyi ve doğrulama tarafında ML-DSA'ya yer bırakmayı planlayın. L4'teki #2437 "Support Algorithm Migration" issue'su, mevcut credential'ların algoritma geçişini konuşuyor — bu, veri modelinizde algoritma alanını ve rotasyon yolunu şimdiden düşünmenizi gerektirir.

---

### 4. Credential Exchange Format (CXF) ve Protocol (CXP)

Dizin: https://fidoalliance.org/specs/cx/

#### CXF — Credential Exchange Format
| Sürüm | Durum | Tarih |
|---|---|---|
| 1.0 | Working Draft | 2024-05-22 |
| 1.0 | Working Draft | 2024-10-03 |
| 1.0 | Review Draft | 2025-03-13 |
| **1.0** | **Proposed Standard** | **2025-08-14** |
| **1.0** | **PS + Errata** | **errata 2026-03-09** (yayın 22 Nis 2026) |

URL: https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html

**Kapsam:** 17 credential tipi — adresler, API anahtarları, basic auth, kredi kartları, custom fields, ehliyet, dosyalar, üretilmiş parolalar, kimlik belgeleri, item referansları, notlar, **passkey'ler**, pasaportlar, kişi adları, SSH anahtarları, TOTP, Wi-Fi passphrase'leri.

**Passkey veri modeli (zorunlu alanlar):** `credentialId`, `rpId`, `username`, `userDisplayName`, `userHandle`, `key`, ve opsiyonel `fido2Extensions` (hmac credentials, credential blobs, large blobs dahil).

**RP tarafını ilgilendiren KRİTİK iki nokta:**
1. **Özel anahtar gerçekten dışa aktarılıyor.** `key` alanı: PKCS#8 ASN.1 DER, Base64url kodlu. Yani passkey taşınabilirliği anahtarın kendisinin taşınması demek — credential ID ve public key **değişmez**, dolayısıyla **sizin veritabanınızda hiçbir şey değişmez ve siz taşımayı göremezsiniz**.
2. **Signature counter kuralı:** *"Sıfırdan farklı signature counter'a sahip passkey'ler dışa aktarımdan hariç tutulmalıdır; içe aktaran taraf counter'ları sıfırlamalıdır."* → **Sunucunuzda katı signature counter kontrolü yapıyorsanız, taşınmış bir credential counter'ı sıfırlanmış olarak geri gelir ve kullanıcıyı kilitlersiniz.**

**Aksiyon:** Synced/backup-eligible (BE=1) credential'lar için signature counter kontrolünü **devre dışı bırakın veya sadece loglayın**. Sıkı counter kontrolünü yalnızca BE=0 (device-bound) credential'lara uygulayın. Bu zaten önceki en iyi pratikti; CXF bunu zorunlu hale getiriyor.

**AAGUID etkisi:** CXF veri modelinde AAGUID passkey'in zorunlu alanları arasında listelenmiyor. Dolayısıyla bir passkey 1Password'den Bitwarden'a taşındığında, **sizin kayıt anında sakladığınız AAGUID artık gerçeği yansıtmaz.** AAGUID'i "kaydolduğu andaki provider" olarak yorumlayın, "şu anki provider" olarak değil. UI'da gösteriyorsanız bunu bir ipucu olarak sunun, kesin bilgi olarak değil.

#### CXP — Credential Exchange Protocol
| Sürüm | Durum | Tarih |
|---|---|---|
| 1.0 | Working Draft | 2024-05-22 |
| **1.0** | **Working Draft** | **2024-10-03** ← en yeni |

**CXP hâlâ sadece Working Draft.** Dizinde hiçbir RD veya PS sürümü yok. Belgenin kendi ifadesi: *"This is a Working Draft Specification and is not intended to be a basis for any implementations as the Specification may change."*

**Bu dikkat çekici bir ayrışma:** CXF (format) Proposed Standard'a ulaşıp errata almışken, CXP (aktarım protokolü) iki yıldır WD'de takılı. Yani ekosistem formatta anlaşmış, ancak provider'lar arası **canlı, doğrudan aktarım protokolü henüz standartlaşmamış**. Pratikte taşımalar dosya tabanlı (şifrelenmiş CXF arşivi) yapılıyor.

**CXP teknik özeti (WD):**
- 5 adım: importer export isteği + şifreleme parametreleri oluşturur → exporter yetkilendirme sonrası migration key belirler → veri şifrelenir → export response iletilir → importer çözer ve saklar
- **HPKE (RFC 9180)** kullanılıyor. KEM/KDF/AEAD taraflar arasında müzakere ediliyor, varsayılan dayatılmıyor. Modlar: base, psk, auth, auth-psk
- Credential'lar **DEFLATE** ile sıkıştırılıp **JWE** dosyası olarak şifreleniyor
- Roller: Exporter, Importer, Credential Owner, opsiyonel Authorizing Party

#### Hangi platformlar/parola yöneticileri shipledi?
**[DOĞRULANMADI]** — Bu soruyu güvenilir şekilde cevaplayamadım. WebSearch kotası dolduğu için vendor duyurularını tarayamadım. 1Password blogunun son yazıları (Tem–Eyl 2026) taradığımda credential exchange / passkey taşınabilirliği ile ilgili **hiçbir yazı bulamadım**. Apple, Google, Bitwarden, Dashlane için sürüm/tarih doğrulaması yapılamadı.

**Uydurma yapmıyorum:** Bu konuda ekibinize kesin bir "X shipledi" bilgisi veremem. Ancak yukarıdaki spec durumu (CXP'nin WD'de takılı olması) ekosistem genelinde **tam otomatik provider-to-provider taşımanın Eylül 2026'da henüz olgunlaşmadığına** işaret ediyor.

---

### 5. Device-bound vs synced passkey: BE / BS bayrakları

#### Bayraklar
`authenticatorData` flags baytında:
- **BE (Backup Eligibility, bit 3)**: Credential yedeklenebilir/senkronize edilebilir mi. **Credential'ın ömrü boyunca DEĞİŞMEZ.**
- **BS (Backup State, bit 4)**: Credential şu anda yedeklenmiş/senkronize durumda mı. **Zamanla DEĞİŞİR.**

Geçerli kombinasyonlar: `BE=0,BS=0` (device-bound), `BE=1,BS=0` (senkronize edilebilir ama henüz değil), `BE=1,BS=1` (senkronize). **`BE=0,BS=1` geçersizdir — reddedin.**

#### Sunucunun yapması gerekenler
1. **Kayıtta BE'yi sakla ve bir daha değiştirme.** Sonraki doğrulamalarda gelen BE, saklanan BE'den farklıysa bu bir protokol ihlali — logla ve reddet.
2. **BS'yi her doğrulamada güncelle.** BS 0→1 geçişi "kullanıcı yedekleme etkinleştirdi" demektir; 1→0 geçişi "yedekleme devre dışı — kurtarma riski" demektir ve kullanıcıya uyarı göstermek için iyi bir tetikleyicidir.
3. **Signature counter politikasını BE'ye bağlayın:**
   - `BE=0` → counter monoton artmalı, ihlal = klonlama şüphesi, reddet
   - `BE=1` → counter genellikle hep 0 gelir; **kontrol etmeyin** (CXF taşımaları da counter'ı sıfırlıyor)
4. **Hesap kurtarma politikası:** `BE=1,BS=1` bir passkey tek başına bootstrap için yeterli sayılabilir (passkeys.dev'in "synced passkey" tanımı tam olarak bu: *"başka bir login challenge gerektirmeden oturum açmayı bootstrap edebilen credential"*). `BE=0` bir passkey **tek kimlik doğrulama faktörünüz olmamalı** — cihaz kaybı = hesap kaybı. Kullanıcı sadece device-bound credential kaydettiyse ikinci bir credential veya kurtarma kodu isteyin.
5. **Kurumsal / yüksek güvenlik politikası:** Cihazdan çıkmama garantisi istiyorsanız `BE=0` şartı koyabilirsiniz — ancak bu, tüm modern platform passkey'lerini (iCloud Keychain, GPM) dışlar ve pratikte kullanıcıları security key'lere zorlar. Bunu bilinçli yapın.

#### AAGUID kullanımı
- AAGUID sadece **attestation `none` DIŞINDA** anlamlı bir değer taşır. `attestation: "none"` istediğinizde tarayıcılar AAGUID'i **sıfırlar** (16 bayt 0x00) — bu gizlilik amaçlı ve kasıtlıdır.
- Provider adını göstermek istiyorsanız `attestation: "direct"` veya `"indirect"` istemeniz gerekir. **[DOĞRULANMADI]** — Apple ve Google'ın 2026'da hangi conveyance ayarında sıfır olmayan AAGUID döndürdüğünü kesin olarak doğrulayamadım.
- AAGUID'i **UI ipucu** olarak kullanın ("1Password'de kayıtlı"), güvenlik kararı olarak değil. Yukarıda anlattığım gibi CXF taşımaları AAGUID'i eskitir.

**Community listesi:** https://github.com/passkeydeveloper/passkey-authenticator-aaguids
- Topluluk tarafından yürütülüyor, provider'lar PR ile ekleniyor (GitHub profil doğrulaması şartıyla)
- JSON şeması: AAGUID'ler üst düzey anahtar (küçük harf), zorunlu `name`, opsiyonel `icon_dark` / `icon_light` (base64 SVG data URI)
- **Repo kendisi uyarıyor:** *"başka hiçbir amaç için kullanılmak üzere tasarlanmamıştır"* ve emekliye ayrılabilir — o durumda JSON dosyaları boş nesneye indirgenecek
- Repo, otoriter güvenlik bilgisi için **FIDO MDS'i** öneriyor ve *"bu listedeki bazı AAGUID'ler FIDO MDS'te bulunmayabilir"* diyor
- **[DOĞRULANMADI]** Listedeki provider sayısı ve son güncelleme tarihi tespit edilemedi.

**Pratik gerçek:** Synced passkey provider'ları (Apple iCloud Keychain, Google Password Manager, 1Password, Bitwarden, Dashlane, Windows Hello) genel olarak MDS'e metadata yayınlamıyor; bu yüzden community listesi var. **[DOĞRULANMADI]** — 2026 için provider bazında MDS varlığını tek tek doğrulayamadım.

#### FIDO MDS durumu
Dizin: https://fidoalliance.org/specs/mds/

| Belge | Sürüm | Durum | Tarih |
|---|---|---|---|
| FIDO Metadata Service | 3.0 | PS | 2021-05-18 |
| FIDO Metadata Service | 3.1 | PS | 2025-05-21 |
| FIDO Metadata Service | **3.1.1** | **PS** | **2026-01-05** (yayın 12 May 2026) |
| FIDO Metadata Statement | 3.0 | PS | 2021-05-18 |
| FIDO Metadata Statement | 3.1 | PS | 2025-05-21 |
| FIDO Metadata Statement | **3.1.1** | **PS** | **2026-01-05** (yayın 12 May 2026) |
| Convenience Metadata Service | 1.0 | PS | 2025-05-21 |

**MDS v4 YOK.** v3 hattı devam ediyor, güncel nokta sürüm **3.1.1**. Ayrıca 2025'te eklenen **"Convenience Metadata Service" v1.0** ilginç — muhtemelen MDS BLOB'unu tüketmeyi kolaylaştıran bir katman. **[DOĞRULANMADI]** — içeriğini incelemedim, ekibinize bakmasını öneririm.

**[DOĞRULANMADI]** — MDS BLOB endpoint URL'i ve imza doğrulama zinciri detaylarını (JWT + x5c + root cert) bu oturumda doğrulayamadım. `https://mds3.fidoalliance.org/` civarında olduğunu biliyorum ama teyit etmedim; spec'ten okuyun.

---

### 6. Attestation gerçekliği

**L3'ün getirdikleri (changelog'dan):** Apple Anonymous Attestation ve **Compound Attestation** formatları eklendi. Ayrıca CTAP 2.2 ile `getInfo.attestationFormats` sayesinde istemci tercih ettiği formatı müzakere edebiliyor.

**Enterprise attestation (CTAP 2.1+):** Authenticator, önceden yapılandırılmış bir RP ID listesine karşı benzersiz tanımlayıcı (seri numarası gibi) döndürebilir. İki tip: platform-managed (istemci RP ID listesini tutar) ve vendor-facilitated (authenticator kendi listesini tutar). **Yalnızca MDM ile yönetilen kurumsal ortamlarda anlamlıdır.**

**Ne zaman anlamlı:**
- **Anlamlı:** Kurumsal/regüle ortam; belirli sertifikalı authenticator modellerini (FIPS, belirli AAL seviyesi) zorunlu kılmanız gerekiyor; cihaz envanteri ile eşleştirme yapıyorsunuz. MDS ile birlikte kullanılır: AAGUID → metadata statement → sertifikasyon seviyesi + bilinen güvenlik açıkları (`StatusReport`).
- **Anlamsız / zararlı (tüketici IdP'si):** 
  - Synced passkey'lerde attestation zaten yok veya anonim — "hangi cihazda" sorusuna cevap vermez, çünkü anahtar zaten senkronize
  - Attestation istemek Apple/Google'da ek kullanıcı onay ekranları ve dönüşüm kaybı yaratır
  - Conditional create (sessiz passkey yükseltme) akışını **bozar**
  - Bir allowlist uygularsanız kullanıcı tabanınızın bir kısmını kaydolamaz hale getirirsiniz

**Tavsiye:** Tüketici IdP'si için `attestation: "none"`. Kurumsal tenant'lar için tenant bazlı bir politika bayrağıyla `"direct"` + MDS doğrulaması + AAGUID allowlist. İki akışı kod düzeyinde ayırın (webauthn-rs bunu zaten `Passkey` vs `AttestedPasskey` ayrımıyla modelliyor — aşağıya bakın).

**[DOĞRULANMADI]** — 2026'da tarayıcıların `indirect` conveyance'i pratikte nasıl ele aldığı (anonymization CA kullanıp kullanmadığı) konusunda güncel bir kaynak doğrulayamadım.

---

### 7. Passkey benimseme istatistikleri (Eylül 2026)

**Bu bölüm zayıf — dürüst olmam gerekirse 2026 tarihli birincil FIDO raporunu bulamadım.**

Doğrulayabildiklerim:

**FIDO Alliance (fidoalliance.org/passkeys, 2024 tarihli bağımsız anket):**
- İnsanların **%53'ü** en az bir hesapta passkey etkinleştirmiş
- **%22'si** etkinleştirebildiği her hesapta etkinleştirmiş
- Kaynak: "2024 Consumer Password & Passkey Trends" — https://fidoalliance.org/passkeys/

**FIDO'nun aynı sayfada alıntıladığı kurumsal metrikler:**
- Yubico: phishing ve credential hırsızlığına maruziyette **%99.99 azalma**
- Amazon: **6x daha hızlı** oturum açma süresi
- Google: parolalara kıyasla **4x daha iyi** oturum açma başarı oranı

**Chrome for Developers, "Modernize authentication with passkeys..." (21 Mayıs 2026) — https://developer.chrome.com/blog/io26-web-identity:**
- **Pixiv**: passkey sonrası **%99 giriş başarı oranı** — parolalara göre **%29 iyileşme**
- **Adidas**: zero-prompt conditional create stratejisiyle **passkey oluşturmalarında %8 artış**

**FIDO Alliance ana sayfasındaki 2026 haberleri (adoption sayısı içermiyor):**
- 14 Ağu 2026 — OpenAI + Yubico ortaklığı: OpenAI'nin Advanced Account Security programı kapsamında özel phishing-dirençli YubiKey'ler
- 17 Tem 2026 — RSA Security + FIDO Alliance ortak brifingi
- 27 May 2026 — Authenticate APAC 2026 (2–3 Haziran)

**[DOĞRULANMADI] / Kapatılamayan boşluklar:**
- 2025 veya 2026 tarihli "Online Authentication Barometer" / "State of Passkeys" raporu — fidoalliance.org/content/research/ ve /research-and-resources/ sayfaları fetch'te navigasyon iskeletinden fazlasını vermedi
- Google/Microsoft/Apple/Amazon/PayPal'ın 2026 passkey kullanıcı sayıları
- Synced vs device-bound passkey oranı — **hiçbir kamuya açık veri bulamadım**
- Cross-device (hybrid/QR) kullanım oranları — **veri bulamadım**

Ekibiniz bu bölümü kendi tarafında https://fidoalliance.org/content/research/ üzerinden tarayarak tamamlamalı.

---

### 8. Rust ekosistemi: webauthn-rs

**Repo:** https://github.com/kanidm/webauthn-rs
**crates.io:** https://crates.io/crates/webauthn-rs

| Sürüm | Tarih | Not |
|---|---|---|
| **0.5.5** | **2026-04-30** | **en güncel stabil** (`max_stable_version`) |
| 0.6.1-dev | 2026-04-30 | prerelease (`max_version` / `newest_version`) |
| 0.6.0-dev | 2026-03-20 | prerelease |
| 0.5.4 | 2025-12-10 | |
| 0.5.3 | 2025-10-23 | |

- crate `updated_at`: 2026-04-30 → **aktif bakımda**
- `recent_downloads`: ~2.47M → ekosistemde baskın konumda
- SUSE product security tarafından güvenlik denetiminden geçmiş

#### Workspace yapısı
- **webauthn-rs** — güvenli, yüksek seviye API (önerilen)
- **webauthn-rs-core** — düşük seviye protokol
- **webauthn-rs-proto** — protokol tipleri/bindings
- **fido-mds** — "Authenticator transparency parser" → **FIDO MDS ayrıştırma için hazır crate var, kendiniz yazmayın**
- (webauthn-authenticator-rs ayrı repo/crate, istemci tarafı)

#### Feature flag'ler (`webauthn-rs/Cargo.toml`)
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

#### L3 özellik desteği — GERÇEK DURUM

`webauthn-rs-proto/src/extensions.rs` kaynak kodundan doğrulanmış:

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
| credProps | **Var** (`cred_props`) |
| credProtect | **Var** (`cred_protect`) |
| minPinLength | **Var** (`min_pin_length`) |
| uvm | **Var** |
| appid (U2F geçiş) | **Var** |
| hmac-secret (ham CTAP) | **Var** (`hmac_create_secret` / `hmac_get_secret`) |
| **PRF extension (WebAuthn seviyesi)** | **YOK** |
| **largeBlob** | **YOK** |
| **devicePubKey** | **YOK** |
| Conditional UI | **Var** ama `preview-features` / `conditional-ui` flag'i arkasında |
| Conditional create | **[DOĞRULANMADI]** — açık bir API bulamadım |
| Signal API | **Yok — ve olması da gerekmez** (bu tamamen istemci tarafı API'si; sizin sadece payload endpoint'i yazmanız gerekiyor) |
| Related Origin Requests | **Yok — gerekmez** (tarayıcı özelliği; sizin sadece `.well-known/webauthn` servis etmeniz gerekiyor) |
| BE/BS bayrakları | **Kısmen** — `allow_backup_eligible_upgrade` iç konfigürasyonu var (passkey akışında `true`, security key ve attested passkey akışında `false`), ancak **`backup_eligible` / `backup_state` public API'de RP'ye açılmıyor** |
| Attestation + MDS | **Var** — `attestation` default feature; AttestationCaList; ayrı `fido-mds` crate'i |

#### En kritik iki boşluk

**1. PRF yok.** Bu, sizin E2E şifreleme planınız için doğrudan engel. Elde `hmac_get_secret` var ama bu **ham CTAP hmac-secret**'tır — WebAuthn `prf` eklentisinin `SHA-256("WebAuthn PRF" || 0x00 || salt)` domain separation'ını ve `evalByCredential` yapısını içermez. PRF istiyorsanız:
   - `webauthn-rs-proto`'daki extension struct'larını genişletmeniz (fork veya upstream PR), **veya**
   - Extension input/output'u kendi katmanınızda JSON seviyesinde ele almanız gerekir
   
   `danger-credential-internals` feature'ı `Credential` tipine `Into`/`From` ile erişim veriyor — kaçış kapısı olarak bunu kullanabilirsiniz.

**2. BE/BS RP'ye açılmıyor.** Bölüm 5'teki politikaları (counter kontrolünü BE'ye bağlama, BS geçişlerinde uyarı, kurtarma politikası) uygulamak için bu bayraklara erişmeniz **şart**. Çözüm: `danger-credential-internals` ile `Credential` iç yapısına inin veya upstream'e bir accessor PR'ı açın. Bu, projenizde erken çözmeniz gereken bir mimari karar.

#### Alternatifler
- **passkey-rs** (github.com/1Password/passkey-rs) — **[DOĞRULANMADI]** sürüm/durum doğrulayamadım. Not: ağırlıklı olarak **istemci/authenticator** tarafı içindir (1Password'ün kendi authenticator implementasyonu), sunucu RP'si için değil. Sizin kullanım senaryonuza uygun değil.
- **webauthn-authenticator-rs** — kanidm ekosisteminde, **istemci/authenticator** tarafı. Test/sanal authenticator için kullanışlı.
- **fido-mds** — kanidm workspace'inde, MDS ayrıştırma. Sunucu tarafı için kullanışlı.

---

### Özet: IdP ekibi için aksiyon listesi

**Hemen yapılacaklar**
1. **BE/BS bayraklarına erişimi çözün** — webauthn-rs'te bu public değil. Bu, bölüm 5'teki tüm politikaların ön koşulu. `danger-credential-internals` veya upstream PR.
2. **Signature counter politikasını BE'ye bağlayın.** BE=1 → kontrol yok. Bu, CXF passkey taşımalarında kullanıcı kilitlenmesini önler (CXF counter'ı sıfırlıyor).
3. **AAGUID'i "kayıt anındaki provider ipucu" olarak modelleyin**, güvenlik kararı olarak değil. CXF taşımaları AAGUID'i eskitiyor.
4. **`attestation: "none"` varsayılan yapın**; kurumsal tenant'lar için ayrı bir attested akış (webauthn-rs'in `AttestedPasskey` tipi + `fido-mds`).
5. **`transports` alanında bilinmeyen değerleri hata vermeden kabul edin** (`"hybrid"` ve gelecekteki değerler için).

**Kısa vadede (L3 özelliklerini benimseme)**
6. **Signal API payload endpoint'i** yazın — tam credential listesi, sayfalama YOK. Yanlış yaparsanız kullanıcıların passkey'lerini gizlersiniz. Chrome 132+/Android 144+ kullanıcılarınızın önemli kısmını kapsıyor.
7. **Conditional create** akışını ekleyin (Chrome 136+/142+, Safari 18+, iOS 18+): parola girişinden sonra sessiz passkey yükseltmesi. `excludeCredentials`'ı doğru doldurun, attestation istemeyin, kullanıcıya sonradan bildirim gönderin.
8. **PRF için:** webauthn-rs'i genişletmeniz gerekecek. Kayıtta credential başına salt üretip saklayın, `prf.enabled`'ı saklayın, PRF çıktısını **asla** saklamayın. Windows Hello ve iOS+harici anahtar senaryoları için fallback şart.
9. **ROR'u sadece kendi çoklu-domain markanız için** düşünün; müşteri RP'leri için OIDC federation zaten elinizde. Kullanırsanız: `application/json`, HTTP 200, auth yok, maksimum 5 label.

**İzlenecekler**
10. **L4 First Public Working Draft — 9 Eylül 2026 (yarın).** Özellikle `uiMode: 'immediate'` (#2291), `sign` extension (#2078), algorithm migration (#2437).
11. **Post-quantum:** FIDO Server Requirements v2.3 (26 Şub 2026) ML-DSA-44/65/87 ve ESP256/384/512, Ed25519'u önerilen listeye aldı. COSE algoritma tablonuzu ve credential veri modelinizdeki algoritma/rotasyon alanını buna göre tasarlayın.
12. **CXP hâlâ Working Draft (2024-10-03).** Provider-to-provider canlı taşıma standartlaşmadı. CXF ise PS (2025-08-14 + errata 2026-03-09). Taşınabilirlik geliyor ama henüz tam değil.

**Kapatamadığım boşluklar (ekibin doğrulaması gereken)**
- 2025/2026 FIDO adoption raporlarının gerçek sayıları
- CXF/CXP'yi hangi vendor'ların gerçekten shiplediği (1Password blogunda Tem–Eyl 2026'da ilgili yazı yok)
- Safari'nin ROR ve Signal API destek durumu (kesin sürüm)
- largeBlob'un 2026 tarayıcı destek matrisi
- MDS BLOB endpoint URL'i ve imza zinciri detayları

---

## HAT 3 — PQC ↔ Kimlik Doğrulama Kesişimi

## Research report — FIDO2/WebAuthn PQC hardware & Rust JOSE PQC (as of 8 Sep 2026)

**Method caveat:** the session's WebSearch budget (200/200) was exhausted before I started, so all of this comes from direct API queries (crates.io, GitHub, chromestatus) and targeted page fetches. That means **negative findings for vendor announcements are "not found by targeted fetch," not exhaustive**. I flag each one.

---

### A) FIDO2/WebAuthn post-quantum hardware & ecosystem

#### A1. Spec status: PQC is issue-stage only, not yet spec text

I fetched the live WebAuthn Editor's Draft and grepped the full rendered text (1.53M chars):

- `https://w3c.github.io/webauthn/` — title: *"Web Authentication: An API for accessing Public Key Credentials Level 3"*, **Editor's Draft, 3 September 2026**
- Occurrences: `ML-DSA` = **0**, `post-quantum` = **0**, `quantum` = **0**, `Dilithium` = **0**, `AKP` = **0**, COSE ids `-49`/`-50` = **0**. (Sanity check: `ES256` = 162, `EdDSA` = 21, `COSEAlgorithmIdentifier` = 43 — so it is the real spec body.)

**Conclusion: as of 8 Sep 2026 no published or draft WebAuthn spec text mentions ML-DSA.** This is consistent with your established fact that L3 REC (25 Aug 2026) has no PQC. Note the ED is still branded L3; L4 exists only as GitHub milestones ("L4 (First Published Working Draft)", "L4 WD02"), not yet as ED text.

#### A2. W3C WebAuthn GitHub: an active `[PQ]` workstream (this is the real signal)

GitHub search `repo:w3c/webauthn ML-DSA OR "post-quantum" OR PQ` → 15 results. The 2026 cluster:

| # | Type | Opened | State | Title / substance |
|---|---|---|---|---|
| [2475](https://github.com/w3c/webauthn/pull/2475) | PR | 2026-09-02 | open | `[PQ] Back up and restore overridden credentials` |
| [2471](https://github.com/w3c/webauthn/issues/2471) | issue | 2026-08-26 | open | `[PQ] SHA-256 usage` — clientDataHash/rpIdHash are hard-wired to SHA-256 with no agility; SHA-256 is not approved for general hashing under CNSA 2.0. Options floated: formal CNSA exception, or a signed extension carrying SHA-384/512 |
| [2462](https://github.com/w3c/webauthn/issues/2462) | issue | 2026-08-06 | **closed** | `pkOptions.pubKeyCredParams` default will be unsafe after Q-day — filed by **nsatragno (Google/Chrome)**; proposes documenting that the default alg set is deprecated, plus UA warnings and a removal timeline |
| [2456](https://github.com/w3c/webauthn/issues/2456) | issue | 2026-07-29 | open | `[PQ] Add new batch attestation type for Merkle tree certificates` — **ve7jtb (John Bradley, Yubico)**. PQ attestation-size mitigation |
| [2448](https://github.com/w3c/webauthn/issues/2448) | issue | 2026-07-16 | open | `[PQ] Default Algorithms for Authenticators perhaps need updating` — ve7jtb. Proposes adding **P-384** now and **ML-DSA-44** as the PQ option |
| [2437](https://github.com/w3c/webauthn/pull/2437) | PR | 2026-06-30 | open | `Support Algorithm Migration` — **akshayku (Microsoft)**. Adds an `algPolicy` extension + `acceptedAlgs` in GetAssertion options; "silent migration with no extra UI". Last activity 2026-08-26; nsatragno pushing back toward a single preference list / existing signal API |
| [2417](https://github.com/w3c/webauthn/issues/2417) | issue | 2026-04-22 | open | `[PQ] Post Quantum Crypto and WebAuthn Transition for RP` — akshayku, milestone **L4 WD02**. Explicitly cites the IANA COSE ids **-48, -49, -50**. Three asks: (1) don't overwrite a credential of a different alg for the same userID/rpID, (2) let RPs express alg preference at *authentication* time, (3) silent credential creation during authentication |
| [2393](https://github.com/w3c/webauthn/issues/2393) | issue | 2026-02-26 | open | `[PQ] Add ML-DSA test vectors` — **emlun (Emil Lundberg, Yubico)**, milestone L4 FPWD. Rationale states ML-DSA now has IANA COSE ids, **"authenticator manufacturers are beginning to implement support,"** and RPs are interested |

The four named participants map to Yubico (ve7jtb, emlun), Microsoft (akshayku) and Google/Chrome (nsatragno) — i.e. the WG *is* actively designing the PQC transition, but entirely at the algorithm-agility/migration layer, with no ML-DSA registration merged yet.

**Uncertainty:** WebFetch could not render GitHub comment threads (only issue bodies), and the GitHub API hit its unauthenticated rate limit. So I could not read the discussion under #2462/#2471, which is where vendor commitments would most likely appear. Worth a re-check with an authenticated `gh`.

#### A3. Hardware authenticators

**Yubico — the most concrete data point, and it is explicitly "not a product":**
[*Future-proofing authentication: A look at the future of post-quantum cryptography*](https://www.yubico.com/blog/future-proofing-authentication-a-look-at-the-future-of-post-quantum-cryptography/), Christopher Harrell, **21 Oct 2025**:
- *"Prototype ≠ product: The PQ demo shows feasibility and performance direction, not a shipment announcement."*
- *"New hardware is required: PQ algorithms have bigger footprints; they don't fit on today's keys."*
- *"Standards progress is underway: FIDO, IETF, and other standards work is progressing, but there's more to do beyond 'make a signature'…"*
- Beta capabilities described as available to "a limited set of qualified testers"; PQ work characterized as "prototype level," "not product-ready yet."

Yubico's later PQC post, [*Post-quantum cryptography is now a federal mandate*](https://www.yubico.com/blog/post-quantum-cryptography-is-now-a-federal-mandate-heres-what-it-means-and-what-your-agency-should-do-now/) (Joe Scalone, **26 Jun 2026**), contains **no** YubiKey product/firmware/roadmap commitment — only the generic guidance that keys "need to support PQC algorithms ML-KEM and ML-DSA." Yubico site search for "post-quantum" returns 76 results across 9 pages, but the 2026 items surfaced are webinars, the federal-mandate post, and an unrelated partner mention (HyperCloud: hybrid RSA+ML-KEM *data-at-rest*, not YubiKey signing).

**No shipping YubiKey ML-DSA product found.** Given Harrell's "new hardware is required," a PQC YubiKey implies a new hardware generation, not a firmware update to the 5.x line.

**Google / OpenSK:** [github.com/google/OpenSK](https://github.com/google/OpenSK) is actively maintained (most recent commit **4 Sep 2026**, ~1–4 week cadence), but recent work is Wasefire framework migration, dependency bumps, CTAPHID timeout fixes, BioEnrollment. **No PQC/Dilithium/ML-DSA commits found.** Google Security Blog's quantum post list shows [*Toward Quantum Resilient Security Keys*](https://security.googleblog.com/2023/08/toward-quantum-resilient-security-keys.html) (15 Aug 2023) with **no follow-up security-key post** through 2026 — the 2026 posts are *Cultivating a robust and efficient quantum-safe HTTPS* (27 Feb 2026) and the Android one below. So the 2023 Dilithium+ECDSA hybrid appears to have **no public follow-up**.

**Google Android (adjacent, and the strongest shipping PQC signal):** [*Security for the Quantum Era: Implementing Post-Quantum Cryptography in Android*](https://blog.google/security/security-for-the-quantum-era-implementing-post-quantum-cryptography-in-android/), **25 Mar 2026**: *"Android 17 updates Android Keystore to natively support ML-DSA. This allows applications to leverage quantum-safe signatures entirely within the device's secure hardware."* Also AVB verified boot integrating ML-DSA, and Play hybrid signing blocks. **The post does not mention FIDO2, WebAuthn, passkeys, security keys, or Titan** — ML-DSA is used for platform integrity and app signing, not credentials. Hardware-backed ML-DSA in Keystore is nonetheless the substrate a future Android PQC passkey would need.

**Feitian:** [ftsafe.com/Products/FIDO](https://www.ftsafe.com/Products/FIDO) — ePass FIDO, ePass FIDO-NFC, BioPass FIDO, iePass FIDO, MultiPass FIDO. **No PQC/ML-DSA claims. Not found.**

**SoloKeys:** org repos active through Aug 2026 (solo2 updated 2026-08-20, fido-authenticator 2026-08-17, ctap-types 2026-08-10, trussed 2026-08-09). They carry a fork of **libcrux** (updated 2026-08-09) — libcrux upstream is the formally-verified ML-KEM/ML-DSA library, so the primitive is in reach — but **no PQC work visible in the FIDO firmware repos. Not found.**

**Nitrokey:** [nitrokey.com/news](https://www.nitrokey.com/news) — no PQC items 2025–2026 (NetHSM, NitroPhone, pricing). **Not found.**

**TPM 2.0 / TCG: NOT VERIFIED.** trustedcomputinggroup.org returned **HTTP 403** to both WebFetch and curl-with-browser-UA on `/?s=post-quantum` and the TPM 2.0 Library Specification resource page. I have no evidence either way on a TPM 2.0 revision adding ML-DSA/ML-KEM. This is the biggest unresolved gap in part A.

**Google Titan specifically:** no dedicated PQC announcement found (Titan firmware is OpenSK-adjacent but not identical). **Not found.**

#### A4. Passkey providers

- **Google/Chrome:** no WebAuthn PQC feature on chromestatus. Querying the chromestatus API for `ML-DSA`, `post-quantum` and `webauthn` returns 15 WebAuthn features, **none PQC**. The only ML-DSA match is [**"Algorithm Updates in WebCrypto"** (id 5198951632470016), status **Proposed**, desktop milestone **154**]: *"Add post-quantum cryptography and a common symmetric AEAD… ML-KEM - 768, 1024; ML-DSA - 44, 65, 87; ChaCha20-Poly1305; X-Wing."* That's WebCrypto, not WebAuthn.
- **Microsoft:** Security Blog PQC posts — *Quantum-safe security: Progress towards next-generation cryptography* (20 Aug 2025), *Building your cryptographic inventory* (16 Apr 2026), *Accelerating the quantum-safe timeline* (30 Jun 2026), *SFI July 2026 progress report* (10 Jul 2026). **None surfaced passkey/FIDO2/WebAuthn/Entra PQC content** in the listing; I could not open *Accelerating the quantum-safe timeline* (my guessed URL 404'd). Microsoft's actual WebAuthn PQC engagement is visible instead in W3C issues #2417/#2437 (akshayku).
- **Apple:** **not found** — I had no search capability to locate an Apple PQC-passkey statement, and did not fetch an Apple page. Treat as unverified rather than negative.
- **1Password:** [1password.com/blog](https://1password.com/blog) — no PQC/quantum-safe posts in the listing. `blog.1password.com/?s=post-quantum` 301s to the unfiltered blog. **Not found.** (1Password's Nick Steele is a listed WebAuthn contributor, but no PQC statement located.)

#### A5. FIDO Alliance PQC program

`fidoalliance.org/?s=post-quantum` returns **10 total results**, all of which I enumerated:
- Events: *How Passkeys and Post-Quantum Cryptography Are Reshaping the Future of Security* (1 Jul 2026); *Member Event: Future-Proofing Authentication: FIDO, PKI, and the Path to Post-Quantum Security* (11 Aug 2025)
- Regional workshop recaps (India Aug 2026, Taipei Dec 2025, Korea Dec 2025), seminar decks (Jun 2025 / Mar 2025), APAC Summit 2024
- News: *IEEE Spectrum: Google Develops Quantum-Safe Security Keys* (1 Sep 2023)
- One member profile

**No FIDO Alliance PQC white paper, no PQC working group, and no PQC certification program found.** `fidoalliance.org/specifications/` contains no PQC/ML-DSA mention. The white-paper index pages are JS-rendered and Cloudflare-blocked to curl, so a paper could exist unlisted by site search — but two independent paths turned up nothing.

#### A6. Part A bottom line

PQC in FIDO2/WebAuthn is, today, **standards-committee work plus one admitted prototype**. Nobody ships an ML-DSA FIDO2 authenticator. The three concrete blockers visible in the record are: credential/attestation size (→ Merkle-tree attestation #2456), lack of algorithm agility for migration (→ #2417/#2437), and the hard-wired SHA-256 hashes (→ #2471). Yubico states plainly that PQ "doesn't fit on today's keys."

---

### B) Rust JOSE/JWT libraries with PQC support

#### B1. The libraries you named: mostly no

| Crate | Latest | Date | ML-DSA / RFC 9964? |
|---|---|---|---|
| **josekit** | 0.10.3 | 2025-05-20 | **No.** README supported-signing list is HS/RS/PS/ES256-384-512, ES256K, EdDSA only. No `AKP`, no ML-DSA, no RFC 9964. GitHub issue search for ML-DSA/post-quantum/PQC/Dilithium/AKP → **0 results**. No CHANGELOG.md in repo |
| **jsonwebtoken** | 11.0.0 | 2026-07-24 | **Not yet — but in flight.** See below |
| **biscuit-auth** | 6.0.0 | 2025-07-16 | No evidence found (my GitHub query 422'd; not retried). Crate is >1 yr stale. Treat as **not found**, low confidence |
| **jwt** (rust-jwt, mikkyang) | 0.16.0 | 2022-01-09 | **No.** Unmaintained since 2022 |
| **jose-jwt** | — | — | **Crate does not exist on crates.io (404)** |
| **openidconnect** | 4.0.1 | 2025-07-06 | **No.** Repo issue search for ML-DSA/post-quantum/PQC → **0 results** |
| **oxide-auth** | 0.6.1 | 2024-06-02 | **No.** Stale since Jun 2024 |
| **rauthy** | — (not on crates.io) | — | **No.** See below |

**jsonwebtoken — active ML-DSA work, unmerged:**
- Issue [#534](https://github.com/Keats/jsonwebtoken/issues/534) *"Support for ML-DSA signed JWTs"*, opened **12 Aug 2026** by PhilSchmieder, citing **RFC 9964** JOSE bindings and noting aws-lc-rs + RustCrypto both have implementations.
- PR [#535](https://github.com/Keats/jsonwebtoken/pull/535) *"Add support for ML-DSA signatures"*, opened **17 Aug 2026**, last activity **3 Sep 2026**, **status: open, changes requested**. Adds ML-DSA-44/65/87 using RFC 9964 wire names (Rust enum `Algorithm::MLDSA44`), **`kty: "AKP"`** JWK import/export + thumbprints per RFC 9964, PKCS#8 DER/PEM private keys, raw + SPKI public keys, parameter-set length validation. **Two backends: `aws_lc_rs` (bumped 1.15 → 1.18) and `rust_crypto` (the `ml-dsa` crate via `signature` 3.x).** Collaborator arckoor requested changes on JWK serde complexity, test macros, public API surface, alg-family naming. **No merge timeline given.**
- This is feasible now because 11.0.0 (2026-07-24) introduced the `CryptoProvider` abstraction.

**rauthy — wants it, has not shipped it:** issue [#857](https://github.com/sebadob/rauthy/issues/857) *"Feat: FIPS 204"* (opened **18 Apr 2025**, still open, labels `enhancement`/`future`, assigned to maintainer sebadob). Maintainer states the upstream JWT crate rejected the FIPS 204 proposal, so rauthy built its own JWT stack instead. The rauthy CHANGELOG has exactly **one** PQC hit (line 3654, in the **v0.30.0** section, PR [#941](https://github.com/sebadob/rauthy/pull/941) closed 2025-05-14): *"…makes Rauthy independent for things like PQC algorithms / FIPS 204 in the future."* — i.e. groundwork only. **No ML-DSA in shipped rauthy.**

#### B2. Crates you didn't ask about that *do* implement ML-DSA JWS — the actual answer

crates.io search surfaced three, two of which explicitly implement RFC 9964 semantics:

**`jwt-simple` 0.13.1 (2026-08-19) — by far the most-used, and it ships today.**
- 6,157,377 total downloads / 994,638 recent. Repo: [jedisct1/rust-jwt-simple](https://github.com/jedisct1/rust-jwt-simple)
- ML-DSA landed in **0.13.0, released 2026-07-30**; release note: *"ML-DSA is now supported."*
- README algorithm table lists `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` ("FIPS 204, post-quantum"), with `MLDSA44KeyPair`/`MLDSA65KeyPair`/`MLDSA87KeyPair`. README recommends ML-DSA-44.
- Backend: **`superboring` 0.1.14** (pure-Rust). Cargo.toml comment: *"the current `boring` crate does not implement ML-DSA yet, so ML-DSA signatures always use a Rust implementation until a new version of the crate is out."*
- **Caveat:** the `alg` names match RFC 9964 wire names, but I found **no `AKP` or RFC 9964 reference** in its README — JWK/`kty: "AKP"` support is **unverified/likely absent**. If you need RFC 9964 JWK interop specifically, verify before relying on it.

**`jose-rs` 0.7.0 (2026-08-05) — the most standards-complete PQC JOSE crate found.** Repo: [kushaldas/jose-rs](https://github.com/kushaldas/jose-rs). Created 2026-04-02; 1,300 downloads (new, small).
- README *Supported algorithms*: **"JWS post-quantum signatures (opt-in): ML-DSA-44 / ML-DSA-65 / ML-DSA-87 (FIPS 204), plus the six composite algorithms from `draft-ietf-jose-pq-composite-sigs-03`: ML-DSA-44-ES256, ML-DSA-65-ES256, ML-DSA-87-ES384, ML-DSA-44-Ed25519, ML-DSA-65-Ed25519, ML-DSA-87-Ed448."**
- JWK row: "RSA / EC / oct / OKP / **AKP** key types". README §"JWK wire format (`kty = "AKP"`)" says *"Per `draft-ietf-cose-dilithium`, ML-DSA keys use the new `"AKP"`…"* — note it cites the **COSE draft, not RFC 9964 by number**; composite algs reuse AKP members with raw concatenated keys.
- Feature flag `post-quantum` (off by default). Backend: `ml-dsa ^0.1.0` (RustCrypto) via the author's `kryptering` crate (145k downloads). Examples `jwt_ml_dsa` and `jwt_composite` included. **This is the only crate found that also does hybrid/composite ML-DSA+classical JWS.**

**`jose4rs` 0.5.0 (2026-09-05) — brand new, tiny.** Repo: [ogital-net/jose4rs](https://github.com/ogital-net/jose4rs). Created 2026-08-24, 79 downloads, 5 releases in 12 days. Port of Java jose4j. README: ML-DSA-44/65/87 under an optional **`pq-ml-dsa`** feature which "implies `aws-lc`"; supports "optional `AKP` keys for ML-DSA" per RFC 9964. **Too immature to depend on** (version churn, ~zero adoption), but confirms the RFC 9964 pattern is being implemented independently.

Also surfaced, informational: `pq-algorithm-id` 0.0.1 (2026-01-26, "Algorithm identifier mappings (JOSE, COSE, X.509)", 25 downloads, no repo) and `pq-oid` 1.0.3 (2026-02-20). A crates.io search for **`rfc9964` returns 0 crates**.

Primitive layer, for reference: **`ml-dsa` 0.1.1 (RustCrypto/signatures, 2026-06-05)**, first stable 0.1.0 on 2026-05-17 — pure Rust, FIPS-204 final. **`fips204` 0.4.6 (2024-12-22)** — integritychain, stale ~21 months.

#### B3. FIPS 140-3 validated ML-DSA reachable from Rust — the key negative result

**No CMVP-validated module I checked has ML-DSA in its approved algorithm list.**

**AWS-LC** ([crypto/fipsmodule/FIPS.md](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md)) — awarded certificates:

| Module | Cert |
|---|---|
| AWS-LC-FIPS v1.0 | [#4631](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4631) |
| AWS-LC Cryptographic Module (dynamic, NetOS) | [#5146](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5146) |
| AWS-LC-FIPS v2.0 (dynamic) | [#5429](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5429) |
| AWS-LC-FIPS v2.0 (static) | [#4816](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4816) |
| AWS-LC-FIPS v3.1 (dynamic) | [#5298](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298) |
| AWS-LC-FIPS v3.1 (static) | [#5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314) |

I opened the two current ones on csrc.nist.gov:
- **Cert #5298** — "AWS-LC 3 Cryptographic Module (dynamic)", **validated 2026-06-03**, active, sunset 2031-06-02. Approved algorithms include **ML-KEM KeyGen + EncapDecap** (CAVP A6176–A6180, A6184, A6278–A6279). **ML-DSA: not present.**
- **Cert #5314** — "AWS-LC 3 Cryptographic Module (static)", **validated 2026-06-05**, active, sunset 2031-06-04. **ML-KEM present** (CAVP A6288–A6315). **ML-DSA: not present.**

**AWS-LC-FIPS v4.0 (static and dynamic) is on the CMVP Modules-In-Process list — tested by an accredited lab, submitted to NIST, not yet certified.** FIPS 4.0 is the module that adds ML-DSA.

This ties directly to Rust: **aws-lc-rs 1.18.0 (crates.io publish date 2026-08-07)** stabilized the ML-DSA APIs. `aws-lc-rs/src/unstable/signature.rs` now reads *"The ML-DSA signature APIs have been stabilized; use `crate::signature` instead"*, with deprecated aliases for `PqdsaKeyPair`/`PqdsaPrivateKey`/`PqdsaPublicKey`. `signature.rs` exposes `ML_DSA_44`/`ML_DSA_65`/`ML_DSA_87` (+ `_SIGNING` variants), documented as **pure ML-DSA with an empty context string — HashML-DSA (pre-hash) is not supported**. Release notes: *"ML-DSA no longer requires the `unstable` feature, and is now available under `fips` — the FIPS 4.0 module provides ML-DSA, which is what had kept these APIs unstable"*, and 1.18.0 upgrades aws-lc-fips-sys from FIPS 3.x to 4.x, which *"has completed validation testing… and has been submitted to NIST for certification."*

> **Date discrepancy flagged:** the GitHub release page summarizer reported v1.18.0 as "August 7, **2024**." crates.io is authoritative and says **2026-08-07**; aws-lc-rs 1.18.1 and 1.17.4 both published 2026-09-01. Treat 2024 as a summarizer error.

**So the trap is:** upgrading to aws-lc-rs 1.18 to get FIPS-mode ML-DSA moves you from a **certified** module (3.x, #5298/#5314) to an **uncertified, in-process** one (4.0). Staying on 3.x keeps the certificate but has no ML-DSA. There is currently no way to get *validated* ML-DSA through aws-lc-rs.

**wolfSSL** ([wolfssl.com/license/fips](https://www.wolfssl.com/license/fips/)): active certs **#5041** and **#4718** (both valid through 2030-07-17); historical FIPS 140-2 **#3389**, **#2425**. **Neither active cert includes ML-DSA or ML-KEM.** wolfCrypt **v7.0.0** is "in early development," "pending submission," with planned FIPS 203 ML-KEM and FIPS 204 ML-DSA. The page notes FIPS 140-2 stops being accepted for new federal procurement after **September 2026**.

**BoringCrypto:** **not checked** — I ran out of a usable search path. Unverified.

#### B4. Part B bottom line

If you want ML-DSA JWS in Rust **today**: `jwt-simple` 0.13.1 (mature, high adoption, pure-Rust superboring backend, but AKP/JWK interop unverified) or `jose-rs` 0.7.0 (proper `AKP` JWK + composite hybrid algs, but 1.3k downloads and 5 months old). `jsonwebtoken` PR #535 is the one to watch if you want ML-DSA in the mainstream crate with a choice of aws-lc-rs or RustCrypto backends. **Nothing in Rust gives you FIPS-140-3-validated ML-DSA** — that waits on AWS-LC-FIPS 4.0 clearing CMVP or wolfCrypt 7.0.0 being submitted.

---

### Explicit uncertainty / not-found ledger

- **Not verified (blocked):** TCG / TPM 2.0 PQC status — trustedcomputinggroup.org returns 403 to every fetch path I tried. No conclusion either way.
- **Not verified (no search):** Apple PQC passkey statements. Absence here is my tooling, not evidence.
- **Not read (rate limit):** comment threads on W3C issues #2462, #2471, #2448, #2456 — WebFetch renders only issue bodies, and the GitHub API hit the 60/hr unauthenticated cap. Vendor commitments would most plausibly live there. Re-run with authenticated `gh`.
- **Low-confidence negative:** biscuit-auth PQC (one query 422'd, not retried).
- **Not checked:** BoringCrypto CMVP status; Microsoft *Accelerating the quantum-safe timeline* (30 Jun 2026) body; FIDO white-paper index behind Cloudflare/JS.
- **Fabrication guard:** every version number and date above came from crates.io API, raw GitHub files, csrc.nist.gov certificate pages, or chromestatus API — except the single flagged aws-lc-rs "2024" summarizer error, which I corrected against crates.io.

---

## HAT 4 — TLS'te Post-Quantum — Gerçek Dağıtım Verisi

### Post-Quantum Cryptography in TLS — state of play, 8 September 2026

**Method note / limitation up front:** the WebSearch budget for this session was already exhausted before I started, so everything below comes from direct fetches of primary sources (IANA CSVs, IETF Datatracker + RFC Editor, chromestatus/chromiumdash APIs, Chrome policy templates JSON, openssl-library.org, go.dev, firefox.com release notes, support.apple.com, BoringSSL git, crates.io, blog.cloudflare.com). **`radar.cloudflare.com` is behind a Cloudflare bot challenge and returned HTTP 403 to both WebFetch and curl on every attempt (page HTML, `/post-quantum`, `/adoption-and-usage`, and the internal API paths); `api.cloudflare.com/client/v4/radar/*` requires an API token.** So I could not read the live September 2026 Radar figure. I have not invented one.

---

### 1. X25519MLKEM768 adoption

#### What I could NOT get
The exact current Cloudflare Radar percentage for September 2026. Radar is inaccessible without a browser/token. **Marked unknown — not estimated.**

#### What is documented in primary Cloudflare sources
| Date | Figure | Source |
|---|---|---|
| Start of 2024 | "under 3%" | [radar-origin-pq-key-transparency-aspa](https://blog.cloudflare.com/radar-origin-pq-key-transparency-aspa/) (27 Feb 2026) |
| Sept 2025 | 39% of top 100k domains *support* PQ key agreement | [pq-2025](https://blog.cloudflare.com/pq-2025/) |
| Oct 2025 | "over half of human-initiated traffic with Cloudflare is protected … with post-quantum encryption" | [pq-2025](https://blog.cloudflare.com/pq-2025/) (28 Oct 2025) |
| Feb 2026 | "over 60%" | [radar-origin-pq-key-transparency-aspa](https://blog.cloudflare.com/radar-origin-pq-key-transparency-aspa/) |
| **7 Apr 2026** | **"over 65% of human traffic to Cloudflare is post-quantum encrypted"** | [post-quantum-roadmap](https://blog.cloudflare.com/post-quantum-roadmap/) |
| **23 Jun 2026** | **"over two-thirds" of browser traffic to Cloudflare** | [post-quantum-eo-2026](https://blog.cloudflare.com/post-quantum-eo-2026/) |

Origin-side (Cloudflare → customer origin) is far behind: **~10% of origins support PQ-preferred key agreement as of Feb 2026, up ~10x from <1% at the start of 2025.**

Caveat on the metric: Cloudflare's headline number is "human/browser-initiated" traffic. The all-traffic number (including bots/API clients) is lower; I could not retrieve it.

Canonical URL: `https://radar.cloudflare.com/post-quantum` (dedicated PQ section, plus a per-hostname "does this site support PQ" checker announced Feb 2026).

---

### 2. draft-ietf-tls-ecdhe-mlkem → **now RFC 10024**

- **Published as RFC 10024, August 2026, Standards Track (Proposed Standard).** Title: *Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3*. Authors: K. Kwiatkowski (PQShield), P. Kampanakis (AWS), B. E. Westerbaan (Cloudflare), D. Stebila (Waterloo). Responsible AD: Paul Wouters.
- Final I-D revision: **draft-ietf-tls-ecdhe-mlkem-05**, datatracker timestamp 2026-08-10.
- https://www.rfc-editor.org/rfc/rfc10024.txt · https://datatracker.ietf.org/doc/rfc10024/

#### IANA TLS Supported Groups — verified against the registry CSV *and* RFC 10024 §IANA
Source: `https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv`

| Value | Hex | Name | DTLS-OK | Recommended | Reference |
|---|---|---|---|---|---|
| 4587 | **0x11EB** | SecP256r1MLKEM768 | Y | N | RFC 10024 |
| 4588 | **0x11EC** | **X25519MLKEM768** | Y | **Y** | RFC 10024 |
| 4589 | **0x11ED** | SecP384r1MLKEM1024 | Y | N | RFC 10024 |
| 512 | 0x0200 | MLKEM512 | Y | N | draft-connolly-tls-mlkem-key-agreement-05 |
| 513 | 0x0201 | MLKEM768 | Y | N | draft-connolly-tls-mlkem-key-agreement-05 |
| 514 | 0x0202 | MLKEM1024 | Y | N | draft-connolly-tls-mlkem-key-agreement-05 |
| 4585 | 0x11E9 | SecP256r1MLKEM512 | Y | N | draft-rosomakho-tls-ecdhe-mlkem512-00 |
| 4586 | 0x11EA | MLKEM512X25519 | Y | N | draft-rosomakho-tls-ecdhe-mlkem512-00 |
| 4590 | 0x11EE | curveSM2MLKEM768 | N | N | draft-yang-tls-hybrid-sm2-mlkem-03 |
| 25497 | 0x63A5 | X25519Kyber768Draft00 **(OBSOLETE)** | Y | **D** (discouraged) | obsoleted by RFC 10024 |
| 25498 | 0x63A6 | SecP256r1Kyber768Draft00 **(OBSOLETE)** | Y | **D** | obsoleted by RFC 10024 |

X25519MLKEM768 is the **only** PQ group marked Recommended=Y. RFC 10024 explicitly flipped the two Kyber-draft codepoints to "D".

Independent confirmation of 0x11EC: BoringSSL `include/openssl/ssl.h` line 2699 — `#define SSL_GROUP_X25519_MLKEM768 0x11ec`.

#### Wire sizes (RFC 10024 §3, verbatim)
- X25519MLKEM768: client share **1216 bytes** (1184 ML-KEM ek + 32 X25519); server share **1120 bytes** (1088 ct + 32); shared secret 64 B.
- SecP256r1MLKEM768: client share 1249 B; server share 1153 B; shared secret 64 B.
- SecP384r1MLKEM1024: client share 1665 B; server share 1665 B; shared secret 80 B.

#### Pure ML-KEM (non-hybrid): draft-ietf-tls-mlkem
- **draft-ietf-tls-mlkem-10**, dated **2 Sept 2026** (datatracker `time` 2026-09-03). IESG state: **"Approved-announcement sent"** — i.e. in the RFC Editor queue, not yet an RFC. Intended status: **Informational**.
- Registers MLKEM512/768/1024 (512/513/514). The IANA registry still cites the predecessor individual draft `draft-connolly-tls-mlkem-key-agreement-05` (expired, replaced by the WG draft); the reference will be updated at RFC publication.
- https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/

#### Also worth flagging: TLS 1.3 itself was re-issued
**RFC 9846, July 2026** — *The Transport Layer Security (TLS) Protocol Version 1.3*, obsoleting RFC 8446 (and 5077, 5246, 6961, 7627, 8422). RFC 10024 references RFC 9846, not 8446. https://www.rfc-editor.org/rfc/rfc9846.txt

---

### 3. Browser and library status

| Implementation | X25519MLKEM768 status | Version / date | Source |
|---|---|---|---|
| **Chrome** | PQ by default since **M124** (desktop, Apr 2024) using X25519**Kyber**768; **switched to ML-KEM (X25519MLKEM768) in Chrome 131** (stable 6 Nov 2024). Android default Nov 2024. | M131 | Chrome policy templates JSON, verbatim: *"Prior to Google Chrome 131, the algorithm was Kyber, an earlier draft iteration of the standard."* |
| **Chrome escape hatch** | `PostQuantumKeyAgreementEnabled` is **deprecated and gone**: `supported_on: chrome.*:116-146`, `chrome_os:116-146`, `android:116-146`. M147 hit stable **7 Apr 2026**, so there is no longer any supported way to turn PQ key agreement off. ChromeOS device-level `DevicePostQuantumKeyAgreementEnabled` likewise `chrome_os:128-146`. | removed as of M147 | chromeenterprise.google policy templates JSON |
| Chrome current stable | **152.0.7977.83**; M152 stable 25 Aug 2026 | — | chromiumdash `fetch_releases` |
| **Firefox** | *"Added support for a post-quantum key exchange mechanism for TLS 1.3 (mlkem768x25519)"* — **Firefox 132, 29 Oct 2024**. HTTP/3/QUIC added in **Firefox 135, 4 Feb 2025**: *"Added support for a post-quantum key exchange mechanism (mlkem768x25519) for HTTP/3."* | 132 / 135 | firefox.com release notes |
| **Safari / Apple** | Apple Platform Security guide, verbatim: *"On devices with iOS 26, iPadOS 26, or later, TLS 1.3 with quantum-secure encryption (with the X25519MLKEM768 key exchange algorithm) is enabled by default for `URLSession` framework and the `Network` APIs."* Shipped Sept/Oct 2025 with iOS/iPadOS/macOS 26. | iOS/iPadOS/macOS 26 | support.apple.com/guide/security/tls-security-sec100a75d12/web |
| **OpenSSL** | **3.5.0, 8 Apr 2025** — first **LTS** under the new policy, supported to **8 Apr 2030**. Adds ML-KEM, ML-DSA, SLH-DSA. *"The default TLS keyshares have been changed to offer X25519MLKEM768 and X25519"* and *"The default TLS supported groups list has been changed to include and prefer hybrid PQC KEM groups."* Note: **OpenSSL 3.0 LTS support ended 2026-09-07 — yesterday.** | 3.5 LTS | openssl-library.org/news/openssl-3.5-notes/ + /policies/releasestrat/ |
| **BoringSSL** | `SSL_GROUP_X25519_MLKEM768 0x11ec`, `SSL_GROUP_MLKEM1024 0x0202`, plus `SSL_SIGN_ML_DSA_44/65/87 = 0x0904/0x0905/0x0906` in current `include/openssl/ssl.h`. | main | boringssl.googlesource.com |
| **Go** | **Go 1.24, Feb 2025**: *"The new post-quantum X25519MLKEM768 key exchange mechanism is now supported and is enabled by default when Config.CurvePreferences is nil. GODEBUG setting `tlsmlkem=0` reverts the default."* `X25519Kyber768Draft00` removed. (Go 1.23, Aug 2024, had the Kyber draft on by default.) | 1.24 | go.dev/doc/go1.24 |
| **rustls** | 0.23.16 (2024-10-28) moved kyber768 → ML-KEM-768. **0.23.22 (2025-01-30)**: X25519MLKEM768 with the aws-lc-rs provider + new `prefer-post-quantum` crate feature. **0.23.27 (2025-05-05)**: *"Prefer post-quantum key exchange algorithms by default"* and `prefer-post-quantum` added to default features. 0.23.28 (2025-06-16) added `secp256r1mlkem768`. 0.23.37 (2026-02-24) added ML-KEM-1024. | 0.23.27 default | GitHub releases + crates.io version dates |

---

### 4. ML-DSA authentication in TLS

- **draft-ietf-tls-mldsa-05**, dated **6 July 2026** (datatracker `time` 2026-07-08). IESG state: **"Approved-announcement to be sent :: AD Followup"** — approved by the IESG, **not yet an RFC**. Intended status: **Informational**. Responsible AD: Deb Cooley; shepherd Sean Turner. Replaces `draft-tls-westerbaan-mldsa`. IETF Last Call was May 2026; IANA action currently "On Hold / review needed."
- https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/

#### IANA TLS SignatureScheme codepoints (verified from `tls-signaturescheme.csv`)
| Hex | Name | Recommended | Reference |
|---|---|---|---|
| **0x0904** | mldsa44 | N | draft-ietf-tls-mldsa-00 |
| **0x0905** | mldsa65 | N | draft-ietf-tls-mldsa-00 |
| **0x0906** | mldsa87 | N | draft-ietf-tls-mldsa-00 |
| 0x0907–0x0910 | Unassigned | | |
| 0x0911–0x091C | slhdsa_sha2_128s … slhdsa_shake_256f (12 entries) | N | draft-reddy-tls-slhdsa-01 |

(Registry still points at `-00`; it'll be re-pointed at the RFC. All PQ signature schemes are Recommended=N.)

#### Who is actually shipping PQ certificate auth in TLS
- **Cloudflare, 29 July 2026** — *"Post-quantum authentication to origins is now supported."* ML-DSA-44/65/87 (all FIPS 204 parameter sets) in **Authenticated Origin Pulls** (free, all plans, per-zone and per-hostname) and **Custom Origin Trust Store** (requires Advanced Certificate Manager, upload your own ML-DSA CA). Paired with X25519MLKEM768 for key agreement. Cloudflare recommends **ML-DSA-44**. Launched June 2026; a BoringSSL update caused a service incident on **10 June 2026**. https://blog.cloudflare.com/post-quantum-authentication-to-origins/
- **rustls 0.23.44, released 2026-09-07 (yesterday)**: *"Support for post-quantum secure ML-DSA certificates is now enabled by default in the aws-lc-rs crypto provider."* Preceded by rustls-post-quantum 0.2.3 (2025-07-16, ML-DSA verification) and 0.2.4 (2025-09-23, ML-DSA signing under `aws-lc-rs-unstable`).
- **BoringSSL** has the ML-DSA signature scheme constants in its public header.
- **No public WebPKI CA is issuing ML-DSA certificates for browser-facing TLS.** Cloudflare's roadmap describes pilot one-year ML-DSA-87 issuance from late 2025 and broad availability ~2027 after HSM audits. Browsers have shipped **nothing** for PQ cert auth. This is entirely private-PKI / origin-facing today.

---

### 5. Open problems

#### ClientHello size, MTU, ossification
- X25519MLKEM768 pushes the client key_share to **1216 bytes**, so a typical ClientHello no longer fits in one TCP segment / QUIC Initial. Chrome's own policy text: *"devices that do not correctly implement TLS may malfunction when offered the new option. For example, they may disconnect in response to unrecognized options or the resulting larger messages. Such devices are not post-quantum-ready and will interfere with an enterprise's post-quantum transition."*
- Go's 1.24 notes point directly at **https://tldr.fail/** — servers that fail to reassemble a ClientHello split across TCP segments, causing handshake timeouts. Go ships `GODEBUG=tlsmlkem=0` as the workaround.
- Cloudflare's historical framing (pq-2025): *"some middleboxes, load-balancers, and other software tacitly assume the ClientHello always fits in a single packet"* — the same ossification that killed the earlier NTRU-HRSS experiment.
- RFC 10024 itself contains **no** MTU/middlebox/fragmentation guidance (I grepped the full text for MTU/fragment/middlebox/packet/ossif/HelloRetry — nothing). That discussion lives in implementation docs, not the RFC.

#### Middlebox breakage, measured
From pq-2025 (Oct 2025), on Cloudflare→origin connections: the "fast" approach (offer the PQ key share optimistically) breaks **0.05%** of connections; the "safe" approach (advertise the group but send no PQ key share, accept a HelloRetryRequest round trip) was universally tolerated. Cloudflare uses the safe method where compatibility matters.

#### Certificate / signature size
- ML-DSA-44 signature is **2,420 bytes** vs 64 bytes for Ed25519 (Cloudflare, [ml-dsa-will-have-to-do](https://blog.cloudflare.com/ml-dsa-will-have-to-do/), 9 July 2026). A full PQ chain multiplies this across leaf + intermediates + CT SCTs + OCSP.
- Cloudflare's position (same post): nothing better arrives in time — **FN-DSA ~2033, multivariate schemes not before 2034, SQIsign unlikely before 2035** — against regulatory deadlines of 2030–2035, so "ML-DSA will have to do."
- **EO 14412** (signed 22 June 2026) sets: PQ **key establishment** for High Value Assets / high-impact systems by **31 Dec 2030**; PQ **authentication** by **31 Dec 2031**; federal contractors to NIST PQC FIPS by 31 Dec 2030. (Per Cloudflare's [post-quantum-eo-2026](https://blog.cloudflare.com/post-quantum-eo-2026/); I did not fetch the EO text itself.)

#### draft-ietf-tls-trust-anchor-ids
- **draft-ietf-tls-trust-anchor-ids-04**, dated **1 May 2026**. Active TLS WG document, IESG state "I-D Exists" (no WGLC/IESG action yet). Authors: Bob Beck (OpenSSL), David Benjamin (Google), Devon O'Brien, Kyle Nekritz (Meta).
- Defines short OID-based trust anchor IDs, a `trust_anchors` extension (ClientHello / EncryptedExtensions / CertificateRequest / Certificate), a retry mechanism, and an HTTPS/SVCB DNS service parameter so servers can advertise trust anchors out-of-band. Purpose: efficient multi-certificate negotiation, intermediate elision (saves hundreds–thousands of bytes), and smoother PQ root rollout.
- Chrome: chromestatus feature **5132064512540672 "Trust Anchor Identifiers (TAI)"**, status **Proposed**, no milestone assigned, owner dadrian@google.com, last updated 8 May 2025. **Not shipping.**

#### Merkle Tree Certificates
- Moved working groups: `draft-davidben-tls-merkle-tree-certs` is expired (last individual rev -10, 22 Jan 2026) and was **adopted by the new PLANTS WG** (PKI, Logs, And Tree Signatures).
- Current: **draft-ietf-plants-merkle-tree-certs-05**, dated **6 July 2026**, IESG state "I-D Exists". Authors: David Benjamin, Devon O'Brien, Bas Westerbaan, Luke Valenta, Filippo Valsorda.
- Idea: an X.509 profile with logging baked in — CA logs first, then collects cosignatures; the cert carries an inclusion proof. Log entries hold hashes rather than full PQ keys/signatures, and "landmark-relative" certificates can drop signatures entirely for up-to-date clients. Cloudflare's bootstrap post: https://blog.cloudflare.com/bootstrap-mtc/ (28 Oct 2025).
- Cloudflare's roadmap targets **mid-2027** for MTC-based PQ authentication on visitor→Cloudflare connections, early 2028 for Cloudflare One, **full PQ by 2029**.

---

### Explicitly uncertain / unresolved

1. **The live Cloudflare Radar September 2026 percentage — not retrieved.** Radar blocks non-browser clients (403 + JS challenge) and the Radar API needs a token. Latest citable figure is "over two-thirds" (23 June 2026). Anyone with a browser can read the current number at https://radar.cloudflare.com/post-quantum.
2. **Firefox "enabled by default" version.** Firefox 132's release note says "Added support for"; Cloudflare's timeline says Firefox was default-on in November 2024. Firefox 132 shipped 29 Oct 2024 and 133 on 26 Nov 2024, and the Firefox 133 notes say nothing about PQ. I believe default-on landed in 132, but I could not confirm the pref default from a Mozilla primary source without search.
3. **Chrome 131 as the ML-KEM switch point** is inferred from the Chrome enterprise policy description ("Prior to Google Chrome 131, the algorithm was Kyber"), which is authoritative on the version but is not a release note. chromestatus has no separate X25519MLKEM768 entry — the old "X25519Kyber768 key encapsulation for TLS" entry (id 5257822742249472, M124) was never superseded.
4. **draft-ietf-tls-mldsa and draft-ietf-tls-mlkem are both Informational**, which is unusual for protocol codepoint registrations; I confirmed this from the Datatracker API (`intendedstdlevelname/inf/`) for both, so it is not a misreading, but I did not find the WG rationale.
5. I did not find an Apple release note or security blog naming the exact Safari/iOS build beyond "iOS 26 / iPadOS 26 or later" from the Apple Platform Security guide; macOS 26 is asserted by Cloudflare, not by the Apple page I read.

Sources: [IANA TLS parameters](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml), [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.txt), [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.txt), [draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/), [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/), [draft-ietf-tls-trust-anchor-ids](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/), [draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/), [OpenSSL 3.5 notes](https://openssl-library.org/news/openssl-3.5-notes/), [OpenSSL release strategy](https://openssl-library.org/policies/releasestrat/), [Go 1.24](https://go.dev/doc/go1.24), [Firefox 132](https://www.firefox.com/en-US/firefox/132.0/releasenotes/), [Firefox 135](https://www.firefox.com/en-US/firefox/135.0/releasenotes/), [Apple TLS security](https://support.apple.com/guide/security/tls-security-sec100a75d12/web), [Chrome policy list](https://chromeenterprise.google/policies/), [chromestatus](https://chromestatus.com/feature/5132064512540672), [Cloudflare pq-2025](https://blog.cloudflare.com/pq-2025/), [Cloudflare PQ roadmap](https://blog.cloudflare.com/post-quantum-roadmap/), [Cloudflare ML-DSA post](https://blog.cloudflare.com/ml-dsa-will-have-to-do/), [Cloudflare PQ origin auth](https://blog.cloudflare.com/post-quantum-authentication-to-origins/), [Cloudflare Radar PQ transparency](https://blog.cloudflare.com/radar-origin-pq-key-transparency-aspa/), [Cloudflare EO post](https://blog.cloudflare.com/post-quantum-eo-2026/), [Cloudflare MTC](https://blog.cloudflare.com/bootstrap-mtc/), [rustls releases](https://github.com/rustls/rustls/releases), [BoringSSL ssl.h](https://boringssl.googlesource.com/boringssl/+/refs/heads/main/include/openssl/ssl.h).


---

# KISIM V — MİMARİ

*Çok kiracılık, yüksek erişilebilirlik, yetkilendirme ve oturum mimarisi.*
