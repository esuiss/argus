# Argus — Tam Teknik Referans

**Sürüm 1.0 · 8 Eylül 2026**

Argus, sıfırdan yazılan genel amaçlı bir Identity Provider'dır: protokol yüzeyinin
tamamını tek üründe veren kapsama sahip, MCP ve ajan kimliğini birinci sınıf vatandaş
yapan, sender-constrained token'ı varsayılan kabul eden, çok kiracılığı gün-1'de doğru
modelleyen bir sistem. Dil: Rust. Kapsam sınıfının referansları ve karşılaştırma
kümesi §1'dedir; tek bir ürün ölçüt alınmaz.

Bu dosya, projenin tüm araştırma ve karar çıktısının tek ve eksiksiz hâlidir — yirmi yedi
ayrı araştırma dokümanı ile alan referansının birleşimi. Yaklaşık altı yüz birincil kaynağa
dayanır.

**Nasıl okunur.** Kısım I kararları ve gerekçelerini verir; acele eden oradan başlamalıdır.
Kısım II alanın genel referansıdır. Kısım III–VII kararların dayandığı araştırmanın tamamıdır.

**Kaynak ve şerh kuralı.** Her iddianın kaynağı yanındadır. Doğrulanamayan her nokta ⚠️ ile
satır içinde işaretlenmiştir; bu işaretler bir kusur değil, güven derecesinin göstergesidir.
Rakam, tarih veya URL uydurulmamıştır. Araştırma sırasında çürütülen iddialar metinden
çıkarılmış, yalnızca doğrulanmış hâlleri bırakılmıştır.

---

> **Bu dosya artık bir içindekiler.** 27 bölümün tamamı
> [`docs/`](docs/README.md) altına taşındı; her bölümün altında kendi dosyasına
> bir işaretçi var. Numaralandırma korundu, dolayısıyla `§20 §7.5` gibi
> referanslar ve koddaki `§1 #24` gibi karar kimlikleri aynen geçerli.

## İçindekiler

**KISIM I — KARARLAR**

- [1. Mimari kararlar](docs/01-architecture-decisions.md) — **ayrı dosya**
- [2. Çelişkiler ve çözümleri](#2-çelişkiler-ve-çözümleri)
  - [Çelişki 1 — İmza algoritması tanımlayıcısı: `ES256` mi `ESP256` mi?](#çelişki-1--imza-algoritması-tanımlayıcısı-es256-mi-esp256-mi)
  - [Çelişki 2 — `#![forbid(unsafe_code)]` ile aws-lc-rs bir arada durabilir mi?](#çelişki-2--forbidunsafecode-ile-aws-lc-rs-bir-arada-durabilir-mi)
  - [Çelişki 3 — SAML: saf Rust mı, süreç izolasyonu mu?](#çelişki-3--saml-saf-rust-mı-süreç-izolasyonu-mu)
  - [Çelişki 4 — `revocation_epoch` ile yetkilendirme karar cache'i nasıl etkileşiyor?](#çelişki-4--revocationepoch-ile-yetkilendirme-karar-cachei-nasıl-etkileşiyor)
  - [Çelişki 5 — Formel doğrulama: Argus tamamen async, araçlar async desteklemiyor](#çelişki-5--formel-doğrulama-argus-tamamen-async-araçlar-async-desteklemiyor)
  - [Özet — beş kararın tek tabloda hâli](#özet--beş-kararın-tek-tabloda-hâli)
- [3. P0 kritik bulgular](#3-p0-kritik-bulgular)
  - [0. CRA — kimlik yönetimi Sınıf I'de, steward raporlaması 11 Aralık 2027](#0-cra--kimlik-yönetimi-sınıf-ide-steward-raporlaması-11-aralık-2027)
  - [1. Parser derinlik sınırı — doğrudan rakipte iki High CVE](#1-parser-derinlik-sınırı--doğrudan-rakipte-iki-high-cve)
  - [2. Tedarik zinciri — `Cargo.lock` kullanıcıların %90'ını kurtardı](#2-tedarik-zinciri--cargolock-kullanıcıların-90ını-kurtardı)
  - [3. Doğrulanmış kripto — iki büyük boşluk ve bir uyarı](#3-doğrulanmış-kripto--iki-büyük-boşluk-ve-bir-uyarı)
  - [4. Sabit-zamanlı karşılaştırma — "ölçülemez" argümanı öldü](#4-sabit-zamanlı-karşılaştırma--ölçülemez-argümanı-öldü)
  - [5. `rsa` crate'i — Marvin hâlâ yamalı değil](#5-rsa-cratei--marvin-hâlâ-yamalı-değil)
  - [6. Kullanıcı sayımı — dummy Argon2 yanlış çözüm](#6-kullanıcı-sayımı--dummy-argon2-yanlış-çözüm)
  - [7. Formel doğrulama — nereye uygulanır, nereye uygulanmaz](#7-formel-doğrulama--nereye-uygulanır-nereye-uygulanmaz)
  - [8. Performans — en büyük kaldıraç kriptoda değil, sertifikada](#8-performans--en-büyük-kaldıraç-kriptoda-değil-sertifikada)
  - [9. İşletim — sessiz başarısızlıklar](#9-işletim--sessiz-başarısızlıklar)
  - [10. Öncelik sırası](#10-öncelik-sırası)
  - [Kapatılamayan boşluklar](#kapatılamayan-boşluklar)

**KISIM II — ALAN BİLGİSİ**

- [4. Kimlik ve kimlik doğrulama — alan referansı](#4-kimlik-ve-kimlik-doğrulama--alan-referansı)
  - [BÖLÜM I — TEMELLER](#bölüm-i--temeller)
  - [BÖLÜM II — PROTOKOLLER VE STANDARTLAR](#bölüm-ii--protokoller-ve-standartlar)
  - [BÖLÜM III — KİMLİK DOĞRULAMA YÖNTEMLERİ](#bölüm-iii--kimlik-doğrulama-yöntemleri)
  - [BÖLÜM IV — TEHDİT MODELİ](#bölüm-iv--tehdit-modeli)
  - [BÖLÜM V — ÜRÜN ENVANTERİ](#bölüm-v--ürün-envanteri)
  - [BÖLÜM VI — MİMARİ KALIPLARI](#bölüm-vi--mimari-kaliplari)
  - [BÖLÜM VII — KULLANICI DENEYİMİ VE DÖNÜŞÜM](#bölüm-vii--kullanici-deneyimi-ve-dönüşüm)
  - [BÖLÜM VIII — SENARYO OYUN KİTAPLARI](#bölüm-viii--senaryo-oyun-kitaplari)
  - [BÖLÜM IX — YENİ NESİL](#bölüm-ix--yeni-nesil)
  - [BÖLÜM X — UYUM VE MEVZUAT](#bölüm-x--uyum-ve-mevzuat)
  - [BÖLÜM XI — KOMŞU EKOSİSTEM](#bölüm-xi--komşu-ekosistem)
  - [BÖLÜM XII — ANTI-PATTERN KATALOĞU](#bölüm-xii--anti-pattern-kataloğu)
  - [BÖLÜM XIII — SEÇİM REHBERİ](#bölüm-xiii--seçim-rehberi)
  - [BÖLÜM XIV — SINIRLAR](#bölüm-xiv--sinirlar)
  - [BÖLÜM XV — KAPATILAN BOŞLUKLAR](#bölüm-xv--kapatilan-boşluklar)

**KISIM III — TEKNOLOJİ TEMELİ**

- [5. Rust ekosistemi fizibilitesi](#5-rust-ekosistemi-fizibilitesi)
- [6. Performans mühendisliği](#6-performans-mühendisliği)
  - [0. Metodoloji ve dürüstlük notu](#0-metodoloji-ve-dürüstlük-notu)
  - [1. Mevcut IdP'lerin gerçek performans verileri](#1-mevcut-idplerin-gerçek-performans-verileri)
  - [2. Parola hash kapasite planlaması — en kritik darboğaz](#2-parola-hash-kapasite-planlaması--en-kritik-darboğaz)
  - [3. Token imzalama ve doğrulama](#3-token-imzalama-ve-doğrulama)
  - [4. Postgres kimlik şeması ölçeklenmesi](#4-postgres-kimlik-şeması-ölçeklenmesi)
  - [5. Dağıtık mimari kararları](#5-dağıtık-mimari-kararları)
  - [6. Rust'ta yüksek performans](#6-rustta-yüksek-performans)
  - [7. Darboğaz sıralaması — bir IdP'de zaman gerçekte nereye gidiyor](#7-darboğaz-sıralaması--bir-idpde-zaman-gerçekte-nereye-gidiyor)
  - [8. Argus için kapasite hesabı ve mimari öneriler](#8-argus-için-kapasite-hesabı-ve-mimari-öneriler)
  - [9. Doğrulanamayanların listesi](#9-doğrulanamayanların-listesi)
  - [10. Kaynaklar](#10-kaynaklar)
- [7. Formel doğrulanmış kriptografi](#7-formel-doğrulanmış-kriptografi)
  - [0. YÖNETİCİ ÖZETİ (önce bunu oku)](#0-yönetici-özeti-önce-bunu-oku)
  - [1. HACL* / EverCrypt (Project Everest, F*)](#1-hacl--evercrypt-project-everest-f)
  - [2. HACL* RUST'TA — "hacl-rs", Eurydice, Charon, Scylla](#2-hacl-rustta--hacl-rs-eurydice-charon-scylla)
  - [3. LIBCRUX — 2026 DURUMU (EN ÖNEMLİ BÖLÜM)](#3-libcrux--2026-durumu-en-önemli-bölüm)
  - [4. HAX TOOLCHAIN (Cryspen/CE Labs)](#4-hax-toolchain-cryspence-labs)
  - [5. FIAT-CRYPTO (Coq, MIT PLV)](#5-fiat-crypto-coq-mit-plv)
  - [6. AWS-LC / s2n-bignum / SAW-Cryptol](#6-aws-lc--s2n-bignum--saw-cryptol)
  - [7. RUSTCRYPTO EKOSİSTEMİ / ring / aws-lc-rs / dalek](#7-rustcrypto-ekosistemi--ring--aws-lc-rs--dalek)
  - [8. CONSTANT-TIME DOĞRULAMA — RUST'TA 2026'DA NE MÜMKÜN?](#8-constant-time-doğrulama--rustta-2026da-ne-mümkün)
  - [9. ARGUS İÇİN PRATİK DEĞERLENDİRME VE ÖNERİ](#9-argus-için-pratik-değerlendirme-ve-öneri)
  - [10. KAYNAK LİSTESİ (erişim tarihleri ile)](#10-kaynak-listesi-erişim-tarihleri-ile)
- [8. Yan kanal ve zamanlama saldırıları](#8-yan-kanal-ve-zamanlama-saldırıları)
  - [A) RUST'TA SABİT-ZAMANLI KARŞILAŞTIRMA](#a-rustta-sabit-zamanli-karşilaştirma)
  - [B) DERLEYİCİ SABİT-ZAMANI BOZUYOR MU? — EVET, RUST'TA DA](#b-derleyici-sabit-zamani-bozuyor-mu--evet-rustta-da)
  - [C) ZAMANLAMA İLE KULLANICI SAYIMI (USER ENUMERATION)](#c-zamanlama-ile-kullanici-sayimi-user-enumeration)
  - [D) MARVIN SALDIRISI VE RSA](#d-marvin-saldirisi-ve-rsa)
  - [E) SPECTRE / MELTDOWN SINIFI — IdP İÇİN GERÇEKÇİ DEĞERLENDİRME](#e-spectre--meltdown-sinifi--idp-için-gerçekçi-değerlendirme)
  - [F) ARGUS İÇİN SOMUT YAPILACAKLAR LİSTESİ](#f-argus-için-somut-yapilacaklar-listesi)
  - [G) DOĞRULANMAMIŞ / ÇELİŞKİLİ MADDELER — AÇIKÇA İŞARETLİ](#g-doğrulanmamiş--çelişkili-maddeler--açikça-işaretli)
  - [KAYNAKLAR (erişim: 2026-09-08)](#kaynaklar-erişim-2026-09-08)
- [9. Anahtar ve sır yönetimi](#9-anahtar-ve-sır-yönetimi)
  - [A) PKCS#11 / HSM — Rust Tarafı](#a-pkcs11--hsm--rust-tarafı)
  - [B) BULUT KMS ile İMZALAMA — Kotalar, Fiyat, Gecikme](#b-bulut-kms-ile-imzalama--kotalar-fiyat-gecikme)
  - [C) HİBRİT MODEL — Kim Gerçekten Yapıyor?](#c-hibrit-model--kim-gerçekten-yapıyor)
  - [D) HashiCorp Vault Transit Engine](#d-hashicorp-vault-transit-engine)
  - [E) ANAHTAR ROTASYONU (JWKS)](#e-anahtar-rotasyonu-jwks)
  - [F) RUST'TA BELLEK-İÇİ SIR HİJYENİ](#f-rustta-bellek-içi-sir-hijyeni)
  - [G) MLOCK / MEMFD_SECRET / CORE DUMP](#g-mlock--memfdsecret--core-dump)
  - [H) SIR SIZINTI VEKTÖRLERİ](#h-sir-sizinti-vektörleri)
  - [ARGUS İÇİN ÖZET KARAR TABLOSU](#argus-için-özet-karar-tablosu)
  - [EYLEM PLANI (öncelik sırasıyla)](#eylem-plani-öncelik-sırasıyla)
- [10. Formel doğrulama ve model checking](#10-formel-doğrulama-ve-model-checking)
  - [AWS Cedar + Lean 4 "Verification-Guided Development" ve AWS Uygulamalı Formel Metotlar Portföyü](#aws-cedar--lean-4-verification-guided-development-ve-aws-uygulamalı-formel-metotlar-portföyü)
- [11. Runtime/binary sertleştirme ve izolasyon](#11-runtimebinary-sertleştirme-ve-izolasyon)
  - [Argus (Rust IdP) için Fuzzing & Property-Based Testing — Derin Araştırma Raporu](#argus-rust-idp-için-fuzzing--property-based-testing--derin-araştırma-raporu)
- [12. Yazılım tedarik zinciri güvenliği](#12-yazılım-tedarik-zinciri-güvenliği)
  - [A) BAĞIMLILIK DENETİM ARAÇLARI](#a-bağimlilik-denetim-araçlari)
  - [B) BAĞIMLILIK MİNİMİZASYONU](#b-bağimlilik-minimizasyonu)
  - [C) RUST'TA TEKRARLANABİLİR DERLEMELER (2026 DURUMU)](#c-rustta-tekrarlanabilir-derlemeler-2026-durumu)
  - [D) SBOM VE SLSA](#d-sbom-ve-slsa)
  - [E) İMZALAMA VE ATTESTATION](#e-imzalama-ve-attestation)
  - [F) RUST TEDARİK ZİNCİRİ SALDIRILARI](#f-rust-tedarik-zinciri-saldirilari)
  - [G) CRATES.IO GÜVENLİK ÖNLEMLERİ](#g-cratesio-güvenlik-önlemleri)
  - [H) ARGUS İÇİN SOMUT YOL HARİTASI](#h-argus-için-somut-yol-haritasi)
  - [I) DOĞRULANAMAYAN / EKSİK KALAN MADDELER](#i-doğrulanamayan--eksik-kalan-maddeler)
  - [J) EN KRİTİK ÜÇ MESAJ](#j-en-kritik-üç-mesaj)
- [13. Güvenlik süreci](#13-güvenlik-süreci)
  - [A) BİR IdP İÇİN TEHDİT MODELLEME (THREAT MODELING)](#a-bir-idp-için-tehdit-modelleme-threat-modeling)
  - [B) GÜVENLİK AÇIĞI AÇIKLAMA PROGRAMI (VDP)](#b-güvenlik-açiği-açiklama-programi-vdp)
  - [C) BAĞIMSIZ GÜVENLİK DENETİMİ (AUDIT)](#c-bağimsiz-güvenlik-denetimi-audit)
  - [D) RED TEAM / DÜŞMANCA TEST](#d-red-team--düşmanca-test)
  - [E) GÜVENLİK REGRESYON TESTİ](#e-güvenlik-regresyon-testi)
  - [Argus için önceliklendirilmiş özet öneri](#argus-için-önceliklendirilmiş-özet-öneri)

**KISIM IV — PROTOKOLLER**

- [14. MCP yetkilendirme](#14-mcp-yetkilendirme)
  - [1. Yönetici özeti — on kritik bulgu](#1-yönetici-özeti--on-kritik-bulgu)
  - [2. Spec durumu ve kapsam](#2-spec-durumu-ve-kapsam)
  - [3. Authorization Server — normatif gereksinimler](#3-authorization-server--normatif-gereksinimler)
  - [4. Resource Server — normatif gereksinimler](#4-resource-server--normatif-gereksinimler)
  - [5. Client ID Metadata Documents (CIMD)](#5-client-id-metadata-documents-cimd)
  - [6. RFC 9728 — Protected Resource Metadata](#6-rfc-9728--protected-resource-metadata)
  - [7. RFC 8707 — Resource Indicators](#7-rfc-8707--resource-indicators)
  - [8. RFC 9207 — `iss` doğrulaması (SEP-2468)](#8-rfc-9207--iss-doğrulaması-sep-2468)
  - [9. `application_type` ve loopback redirect (SEP-837)](#9-applicationtype-ve-loopback-redirect-sep-837)
  - [10. Stateless çekirdek ve `cacheScope`](#10-stateless-çekirdek-ve-cachescope)
  - [11. MRTR ve `requestState`](#11-mrtr-ve-requeststate)
  - [12. Güvenlik tuzakları — öncelik sırasına göre](#12-güvenlik-tuzakları--öncelik-sırasına-göre)
  - [13. Ekosistem](#13-ekosistem)
  - [14. İstemci interop gerçekleri](#14-istemci-interop-gerçekleri)
  - [15. Yol haritası — yakın gelecek](#15-yol-haritası--yakın-gelecek)
  - [16. Argus için somut yapılacaklar](#16-argus-için-somut-yapılacaklar)
  - [17. Doğrulanamayanlar](#17-doğrulanamayanlar)
  - [18. Kaynaklar](#18-kaynaklar)
- [15. AI ajan kimliği](#15-ai-ajan-kimliği)
  - [0. Yönetici özeti — beş cümlelik gerçek](#0-yönetici-özeti--beş-cümlelik-gerçek)
  - [1. IETF OAuth WG — süreç ve durum](#1-ietf-oauth-wg--süreç-ve-durum)
  - [2. Aktif OAuth WG dokümanları (Eylül 2026)](#2-aktif-oauth-wg-dokümanları-eylül-2026)
  - [3. Ajan-özel bireysel draft'lar — zoo haritası](#3-ajan-özel-bireysel-draftlar--zoo-haritası)
  - [4. IETF WIMSE WG](#4-ietf-wimse-wg)
  - [5. agentproto BoF — yeni bir WG doğuyor (ama henüz yok)](#5-agentproto-bof--yeni-bir-wg-doğuyor-ama-henüz-yok)
  - [6. MCP ve A2A](#6-mcp-ve-a2a)
  - [7. Endüstri — teknik karşılaştırma](#7-endüstri--teknik-karşılaştırma)
  - [8. Açık problemler — ne çözüldü, ne çözülmedi](#8-açık-problemler--ne-çözüldü-ne-çözülmedi)
  - [9. Düzenleyici durum](#9-düzenleyici-durum)
  - [10. Sınıflandırma](#10-sınıflandırma)
  - [11. Somut teknik gereksinim listesi](#11-somut-teknik-gereksinim-listesi)
  - [12. Çelişkili / yakınsamamış noktalar](#12-çelişkili--yakınsamamış-noktalar)
  - [13. Doğrulanamayanlar](#13-doğrulanamayanlar)
  - [14. Argus için üç stratejik hamle](#14-argus-için-üç-stratejik-hamle)
- [16. Kurumsal protokoller — SAML, SCIM, LDAP, Kerberos, Federation](#16-kurumsal-protokoller--saml-scim-ldap-kerberos-federation)
  - [BÖLÜM 1 — SAML 2.0, IdP TARAFI](#bölüm-1--saml-20-idp-tarafi)
  - [BÖLÜM 2 — SCIM 2.0 (SUNUCU TARAFI)](#bölüm-2--scim-20-sunucu-tarafi)
  - [BÖLÜM 3 — LDAP (SUNUCU TARAFI)](#bölüm-3--ldap-sunucu-tarafi)
  - [BÖLÜM 4 — KERBEROS / ACTIVE DIRECTORY ENTEGRASYONU](#bölüm-4--kerberos--active-directory-entegrasyonu)
  - [BÖLÜM 5 — OPENID FEDERATION 1.0 / 1.1](#bölüm-5--openid-federation-10--11)
  - [BÖLÜM 6 — TOPLAM EFOR VE SIRALAMA](#bölüm-6--toplam-efor-ve-siralama)
  - [BÖLÜM 7 — DOĞRULANAMAYANLAR VE SINIRLAR](#bölüm-7--doğrulanamayanlar-ve-sinirlar)
- [17. Gelecek standartları — PQC, WebAuthn L3, CTAP, TLS](#17-gelecek-standartları--pqc-webauthn-l3-ctap-tls)
  - [HAT 1 — Post-Quantum Kriptografi ve Kimlik](#hat-1--post-quantum-kriptografi-ve-kimlik)
  - [Post-Quantum Kriptografi Durum Raporu — 8 Eylül 2026](#post-quantum-kriptografi-durum-raporu--8-eylül-2026)
  - [HAT 2 — WebAuthn Level 3 / CTAP 2.3 / Passkey Ekosistemi](#hat-2--webauthn-level-3--ctap-23--passkey-ekosistemi)
  - [WebAuthn / Passkey Durum Raporu — 8 Eylül 2026](#webauthn--passkey-durum-raporu--8-eylül-2026)
  - [HAT 3 — PQC ↔ Kimlik Doğrulama Kesişimi](#hat-3--pqc--kimlik-doğrulama-kesişimi)
  - [Research report — FIDO2/WebAuthn PQC hardware & Rust JOSE PQC (as of 8 Sep 2026)](#research-report--fido2webauthn-pqc-hardware--rust-jose-pqc-as-of-8-sep-2026)
  - [HAT 4 — TLS'te Post-Quantum — Gerçek Dağıtım Verisi](#hat-4--tlste-post-quantum--gerçek-dağıtım-verisi)

**KISIM V — MİMARİ**

- [18. Çok kiracılık mimarisi](#18-çok-kiracılık-mimarisi)
  - [BÖLÜM I — MEVCUT IdP'LERİN ÇOK KİRACILIK MODELLERİ](#bölüm-i--mevcut-idplerin-çok-kiracilik-modelleri)
  - [BÖLÜM II — VERİTABANI İZOLASYON STRATEJİLERİ](#bölüm-ii--veritabani-izolasyon-stratejileri)
  - [BÖLÜM III — İZOLASYONUN VERİDEN ÖTESİ](#bölüm-iii--izolasyonun-veriden-ötesi)
  - [BÖLÜM IV — HİYERARŞİ VE KULLANICI KİMLİĞİ](#bölüm-iv--hiyerarşi-ve-kullanici-kimliği)
  - [BÖLÜM V — GÜVENLİK: CROSS-TENANT SIZINTI](#bölüm-v--güvenlik-cross-tenant-sizinti)
  - [BÖLÜM VI — RUST'A ÖZGÜ](#bölüm-vi--rusta-özgü)
  - [BÖLÜM VII — ARGUS İÇİN ÖNERİ](#bölüm-vii--argus-için-öneri)
  - [BÖLÜM VIII — DOĞRULANAMAYANLAR](#bölüm-viii--doğrulanamayanlar)
- [19. Yüksek erişilebilirlik ve dağıtık mimari](#19-yüksek-erişilebilirlik-ve-dağıtık-mimari)
  - [BÖLÜM 1 — MEVCUT IdP'LERİN HA MİMARİLERİ](#bölüm-1--mevcut-idplerin-ha-mimarileri)
  - [BÖLÜM 2 — POSTGRESQL İLE HA](#bölüm-2--postgresql-ile-ha)
  - [BÖLÜM 3 — ÇOK BÖLGELİ (MULTI-REGION) KİMLİK](#bölüm-3--çok-bölgeli-multi-region-kimlik)
  - [BÖLÜM 4 — DAĞITIK DURUM VE İPTAL YAYINI](#bölüm-4--dağitik-durum-ve-iptal-yayini)
  - [BÖLÜM 5 — DAĞITIK RATE LIMITING](#bölüm-5--dağitik-rate-limiting)
  - [BÖLÜM 6 — ÖLÇEKLENME VE KAPASİTE](#bölüm-6--ölçeklenme-ve-kapasite)
  - [BÖLÜM 7 — FELAKET SENARYOLARI VE KADEMELİ BOZULMA](#bölüm-7--felaket-senaryolari-ve-kademeli-bozulma)
  - [BÖLÜM 8 — ARGUS İÇİN NET TOPOLOJİ ÖNERİSİ](#bölüm-8--argus-için-net-topoloji-önerisi)
  - [BÖLÜM 9 — KAYNAKLAR](#bölüm-9--kaynaklar)
- [20. Yetkilendirme motoru](#20-yetkilendirme-motoru)
  - [BÖLÜM 1 — ZANZIBAR VE TÜREVLERİ](#bölüm-1--zanzibar-ve-türevleri)
  - [BÖLÜM 2 — RUST'TA YETKİLENDİRME](#bölüm-2--rustta-yetkilendirme)
  - [BÖLÜM 3 — AuthZEN](#bölüm-3--authzen)
  - [BÖLÜM 4 — SICAK YOL PERFORMANSI](#bölüm-4--sicak-yol-performansi)
  - [BÖLÜM 5 — VERİ MODELİ VE MİGRASYON](#bölüm-5--veri-modeli-ve-migrasyon)
  - [BÖLÜM 6 — GÜVENLİK](#bölüm-6--güvenlik)
  - [BÖLÜM 7 — ARGUS İÇİN KARAR VE MİMARİ](#bölüm-7--argus-için-karar-ve-mimari)
- [21. Oturum güvenliği ve hırsızlığa karşı savunmalar](#21-oturum-güvenliği-ve-hırsızlığa-karşı-savunmalar)
  - [1. DBSC — Device Bound Session Credentials](#1-dbsc--device-bound-session-credentials)
  - [2. SSF / CAEP / RISC](#2-ssf--caep--risc)
  - [3. DPoP (RFC 9449) — İmplementasyon Derinliği](#3-dpop-rfc-9449--implementasyon-derinliği)
  - [4. Token Binding Alternatifleri](#4-token-binding-alternatifleri)
  - [5. AiTM ve Oturum Hırsızlığı — 2026 Tehdit Verisi](#5-aitm-ve-oturum-hırsızlığı--2026-tehdit-verisi)
  - [6. Oturum İçi Anomali Tespiti](#6-oturum-içi-anomali-tespiti)
  - [7. Argus için Sentez ve Öncelik Sırası](#7-argus-için-sentez-ve-öncelik-sırası)
  - [8. Belirsizlikler ve Doğrulanamayanlar](#8-belirsizlikler-ve-doğrulanamayanlar)
  - [EK — DPoP, Token Binding ve Donanım Attestation (Derinleştirme)](#ek--dpop-token-binding-ve-donanım-attestation-derinleştirme)

**KISIM VI — ÜRÜN AKIŞLARI**

- [22. Hesap yaşam döngüsü](#22-hesap-yaşam-döngüsü)
  - [BÖLÜM I — HESAP KURTARMA](#bölüm-i--hesap-kurtarma)
  - [BÖLÜM II — HESAP BAĞLAMA VE BİRLEŞTİRME](#bölüm-ii--hesap-bağlama-ve-birleştirme)
  - [BÖLÜM III — IMPERSONATION ("KULLANICI OLARAK GİRİŞ")](#bölüm-iii--impersonation-kullanici-olarak-giriş)
  - [BÖLÜM IV — KULLANICI YAŞAM DÖNGÜSÜ, SİLME VE TOMBSTONE](#bölüm-iv--kullanici-yaşam-döngüsü-silme-ve-tombstone)
  - [BÖLÜM V — KAYIT VE ONBOARDING GÜVENLİĞİ](#bölüm-v--kayit-ve-onboarding-güvenliği)
  - [BÖLÜM VI — IdP GÖÇÜ](#bölüm-vi--idp-göçü)
  - [BÖLÜM VII — B2B ORGANİZASYON AKIŞLARI](#bölüm-vii--b2b-organizasyon-akişlari)
- [23. Giriş akışları ve UX](#23-giriş-akışları-ve-ux)
  - [1. IDENTIFIER-FIRST AKIŞI](#1-identifier-first-akişi)
  - [2. PASSKEY / WEBAUTHN UX — 2026 GERÇEĞİ](#2-passkey--webauthn-ux--2026-gerçeği)
  - [3. MFA UX VE GÜVENLİK TAKASLARI](#3-mfa-ux-ve-güvenlik-takaslari)
  - [4. HOSTED LOGIN vs EMBEDDED (SDK)](#4-hosted-login-vs-embedded-sdk)
  - [5. MARKALAMA, ÖZELLEŞTİRME VE ÇOK KİRACILIK](#5-markalama-özelleştirme-ve-çok-kiracilik)
  - [6. HATA MESAJLARI VE KURTARMA UX'İ](#6-hata-mesajlari-ve-kurtarma-uxi)
  - [7. ERİŞİLEBİLİRLİK](#7-erişilebilirlik)
  - [8. ARGUS İÇİN GİRİŞ AKIŞI TASARIM KARARLARI](#8-argus-için-giriş-akişi-tasarim-kararlari)
  - [9. DOĞRULANAMAYANLAR](#9-doğrulanamayanlar)
- [24. Admin API ve delege yönetim](#24-admin-api-ve-delege-yönetim)
  - [1. Mevcut IdP'lerin Admin API Tasarımı](#1-mevcut-idplerin-admin-api-tasarımı)
  - [2. Delege Yönetim — en zor kısım](#2-delege-yönetim--en-zor-kısım)
  - [3. Admin API Güvenliği](#3-admin-api-güvenliği)
  - [4. Konfigürasyon Yönetimi ve GitOps](#4-konfigürasyon-yönetimi-ve-gitops)
  - [5. Admin API × Çok Kiracılık Kesişimi](#5-admin-api-×-çok-kiracılık-kesişimi)
  - [6. Bulk / Batch İşlemler](#6-bulk--batch-işlemler)
  - [7. Argus için Somut Tasarım Kararları](#7-argus-için-somut-tasarım-kararları)
  - [8. Doğrulanamayanlar](#8-doğrulanamayanlar)

**KISIM VII — İŞLETİM**

- [25. Gözlemlenebilirlik ve ölçekte denetim](#25-gözlemlenebilirlik-ve-ölçekte-denetim)
  - [0. En kritik bulgu: Ön ölçümünüz literatürle birebir örtüşüyor](#0-en-kritik-bulgu-ön-ölçümünüz-literatürle-birebir-örtüşüyor)
  - [1. Denetim logu standartları ve şemaları](#1-denetim-logu-standartları-ve-şemaları)
  - [2. Bütünlük (tamper-evidence) — ölçekte](#2-bütünlük-tamper-evidence--ölçekte)
  - [3. Ölçekte log hacmi ve maliyet](#3-ölçekte-log-hacmi-ve-maliyet)
  - [4. Rust gözlemlenebilirlik yığını — 2026 üretim gerçeği](#4-rust-gözlemlenebilirlik-yığını--2026-üretim-gerçeği)
  - [5. Denetim logu bir güvenlik ürünü olarak](#5-denetim-logu-bir-güvenlik-ürünü-olarak)
  - [6. Kullanıcıya görünen denetim (user-facing audit)](#6-kullanıcıya-görünen-denetim-user-facing-audit)
  - [7. Argus için somut tasarım kararları](#7-argus-için-somut-tasarım-kararları)
  - [8. ⚠️ DOĞRULANAMAYANLAR](#8--doğrulanamayanlar)
  - [Kaynaklar](#kaynaklar)
- [26. Dağıtım ve operatör deneyimi](#26-dağıtım-ve-operatör-deneyimi)
  - [1. Kurulum ve İlk Çalıştırma Deneyimi](#1-kurulum-ve-ilk-çalıştırma-deneyimi)
  - [2. Konteyner ve Kubernetes](#2-konteyner-ve-kubernetes)
  - [3. Konfigürasyon Yönetimi](#3-konfigürasyon-yönetimi)
  - [4. Yükseltme ve Şema Göçü](#4-yükseltme-ve-şema-göçü)
  - [5. Yedekleme ve Felaket Kurtarma](#5-yedekleme-ve-felaket-kurtarma)
  - [6. Kaynak Gereksinimleri ve Boyutlandırma](#6-kaynak-gereksinimleri-ve-boyutlandırma)
  - [7. Açık Kaynak Proje Operasyonu](#7-açık-kaynak-proje-operasyonu)
  - [Argus için Dağıtım ve Operasyon Kararları](#argus-için-dağıtım-ve-operasyon-kararları)
  - [Doğrulanamayanlar (⚠️)](#doğrulanamayanlar)
- [27. Test stratejisi](#27-test-stratejisi)
  - [1. Uyum (Conformance) Test Süitleri](#1-uyum-conformance-test-süitleri)
  - [2. Interop Testi — Gerçek Karşı Taraflarla](#2-interop-testi--gerçek-karşı-taraflarla)
  - [3. Yük Testi — IdP'ye Özgü](#3-yük-testi--idpye-özgü)
  - [4. Kaos ve Dayanıklılık Testi](#4-kaos-ve-dayanıklılık-testi)
  - [5. Güvenlik Testi](#5-güvenlik-testi)
  - [6. Test Altyapısı](#6-test-altyapısı)
  - [7. Argus İçin Test Stratejisi — Somut Tablo](#7-argus-için-test-stratejisi--somut-tablo)
  - [8. ⚠️ DOĞRULANMAYANLAR](#8--doğrulanmayanlar)


---

# KISIM I — KARARLAR

*Argus'un ne yapacağına dair kararlar ve gerekçeleri. Geri kalan her kısım bu kararların dayanağıdır.*
## 1. Mimari kararlar

**Bu bölüm [`docs/01-architecture-decisions.md`](docs/01-architecture-decisions.md) dosyasına taşındı.**

30 gün-1 kararı, karar kayıtları, teknoloji yığını,
crate topolojisi, protokol kapsamı, güvenlik mimarisi ve
bölüm 9'daki açık kararlar orada.

Bu dosyanın başka yerlerinde geçen **`§1 §10.2` gibi referanslar** o dosyanın
ilgili bölümünü gösterir; numaralandırma korundu.

## 2. Çelişkiler ve çözümleri

**Bu bölüm [`docs/02-contradictions-and-resolutions.md`](docs/02-contradictions-and-resolutions.md) dosyasına taşındı.**

## 3. P0 kritik bulgular

**Bu bölüm [`docs/03-p0-critical-findings.md`](docs/03-p0-critical-findings.md) dosyasına taşındı.**

## 4. Kimlik ve kimlik doğrulama — alan referansı

**Bu bölüm [`docs/04-identity-authentication-reference.md`](docs/04-identity-authentication-reference.md) dosyasına taşındı.**

## 5. Rust ekosistemi fizibilitesi

**Bu bölüm [`docs/05-rust-ecosystem.md`](docs/05-rust-ecosystem.md) dosyasına taşındı.**

## 6. Performans mühendisliği

**Bu bölüm [`docs/06-performance.md`](docs/06-performance.md) dosyasına taşındı.**

## 7. Formel doğrulanmış kriptografi

**Bu bölüm [`docs/07-verified-cryptography.md`](docs/07-verified-cryptography.md) dosyasına taşındı.**

## 8. Yan kanal ve zamanlama saldırıları

**Bu bölüm [`docs/08-side-channels.md`](docs/08-side-channels.md) dosyasına taşındı.**

## 9. Anahtar ve sır yönetimi

**Bu bölüm [`docs/09-key-management.md`](docs/09-key-management.md) dosyasına taşındı.**

## 10. Formel doğrulama ve model checking

**Bu bölüm [`docs/10-formal-verification.md`](docs/10-formal-verification.md) dosyasına taşındı.**

## 11. Runtime/binary sertleştirme ve izolasyon

**Bu bölüm [`docs/11-runtime-hardening.md`](docs/11-runtime-hardening.md) dosyasına taşındı.**

## 12. Yazılım tedarik zinciri güvenliği

**Bu bölüm [`docs/12-supply-chain.md`](docs/12-supply-chain.md) dosyasına taşındı.**

## 13. Güvenlik süreci

**Bu bölüm [`docs/13-security-process.md`](docs/13-security-process.md) dosyasına taşındı.**

## 14. MCP yetkilendirme

**Bu bölüm [`docs/14-mcp-authorization.md`](docs/14-mcp-authorization.md) dosyasına taşındı.**

## 15. AI ajan kimliği

**Bu bölüm [`docs/15-agent-identity.md`](docs/15-agent-identity.md) dosyasına taşındı.**

## 16. Kurumsal protokoller — SAML, SCIM, LDAP, Kerberos, Federation

**Bu bölüm [`docs/16-enterprise-protocols.md`](docs/16-enterprise-protocols.md) dosyasına taşındı.**

## 17. Gelecek standartları — PQC, WebAuthn L3, CTAP, TLS

**Bu bölüm [`docs/17-future-standards.md`](docs/17-future-standards.md) dosyasına taşındı.**

## 18. Çok kiracılık mimarisi

**Bu bölüm [`docs/18-multi-tenancy.md`](docs/18-multi-tenancy.md) dosyasına taşındı.**

## 19. Yüksek erişilebilirlik ve dağıtık mimari

**Bu bölüm [`docs/19-high-availability.md`](docs/19-high-availability.md) dosyasına taşındı.**

## 20. Yetkilendirme motoru

**Bu bölüm [`docs/20-authorization-engine.md`](docs/20-authorization-engine.md) dosyasına taşındı.**

## 21. Oturum güvenliği ve hırsızlığa karşı savunmalar

**Bu bölüm [`docs/21-session-security.md`](docs/21-session-security.md) dosyasına taşındı.**

## 22. Hesap yaşam döngüsü

**Bu bölüm [`docs/22-account-lifecycle.md`](docs/22-account-lifecycle.md) dosyasına taşındı.**

## 23. Giriş akışları ve UX

**Bu bölüm [`docs/23-login-flows.md`](docs/23-login-flows.md) dosyasına taşındı.**

## 24. Admin API ve delege yönetim

**Bu bölüm [`docs/24-admin-api.md`](docs/24-admin-api.md) dosyasına taşındı.**

## 25. Gözlemlenebilirlik ve ölçekte denetim

**Bu bölüm [`docs/25-observability.md`](docs/25-observability.md) dosyasına taşındı.**

## 26. Dağıtım ve operatör deneyimi

**Bu bölüm [`docs/26-deployment-operations.md`](docs/26-deployment-operations.md) dosyasına taşındı.**

## 27. Test stratejisi

**Bu bölüm [`docs/27-test-strategy.md`](docs/27-test-strategy.md) dosyasına taşındı.**
