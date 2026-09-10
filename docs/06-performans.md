# 6. Performans mühendisliği

> `ARGUS.md` §6'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§6 §X` referansları aynı anlamda.



## 0. Metodoloji ve dürüstlük notu

İki tür veri var, karıştırmıyorum:

- **[YAYIN]** — üçüncü taraf kaynaktan, URL + tarih + donanım ile.
- **[ÖLÇÜM]** — bu araştırma sırasında **benim ölçtüğüm** rakamlar. Donanım: **Apple M4 (6 performans + 4 verimlilik çekirdeği, 16 GB), macOS**, Rust 1.98.1, `opt-level=3 + lto="fat" + codegen-units=1`. Postgres testleri: **PostgreSQL 18.6 (aarch64-alpine, Docker)**, `shared_buffers=2GB`, `synchronous_commit=on`.

M4 bir sunucu CPU'su değildir. Tek çekirdek performansı Graviton3/4'ten yüksek, bellek bant genişliği ve çekirdek sayısı ise bir EPYC/Xeon sunucudan çok düşüktür. **Mutlak rakamları değil, oranları ve eğilimleri** taşıyın. x86 sunucuda doğrulanması gereken yerleri işaretledim.

Web arama bütçesi bu oturumda tükendiği için arama motoru üzerinden keşif yapamadım; bilinen otoriter URL'leri doğrudan çektim. Bu nedenle 5. bölüm (dağıtık mimari) diğerlerinden zayıf — açıkça belirtiyorum.

---

## 1. Mevcut IdP'lerin gerçek performans verileri

### 1.1 Keycloak — resmî kapasite planlama rakamları

Kaynak: [keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing) (çekildi 8 Eyl 2026)

| Metrik | Resmî rakam | Test edilen üst sınır |
|---|---|---|
| Parola ile login | **1 vCPU / 15 login/sn** | 300 login/sn |
| Client credential grant | 1 vCPU / 120 grant/sn | 2.000/sn |
| Refresh token | 1 vCPU / 120 istek/sn | 435/sn |
| Pod taban bellek (10.000 oturum önbellekli) | 1.250 MB | — |
| Heap payı | Bellek limitinin %70'i + ~300 MB heap dışı | — |
| DB (100 login/logout/refresh/sn başına) | **1.400 write IOPS**, 0,35–0,7 vCPU | — |
| CPU başlık payı önerisi | **%150 fazladan** | — |

**Referans donanım:** OpenShift 4.21 / ROSA, `c7g.2xlarge` (Graviton3), Aurora PostgreSQL multi-AZ, 1M kullanıcı + 20.000 client, **OpenJDK 21**, parola hash: **Argon2, t=5, m=7 MiB**.

### 1.2 Keycloak 26.4 benchmark — sizin 2.000/10.000 rakamınızın kaynağı

Kaynak: [keycloak.org/2025/10/keycloak-benchmark](https://www.keycloak.org/2025/10/keycloak-benchmark) (Ekim 2025)

Bu, hedef olarak aldığınız rakamların kaynağı. **Ama asıl hikâye maliyet tarafında:**

| Senaryo | Pod | vCPU/pod | **Toplam vCPU** | Bellek/pod | Aurora | Aurora vCPU |
|---|---|---|---|---|---|---|
| 500 login + 2.500 refresh /sn | 3 | 24 | **72** | 4 GB | db.r8g.2xlarge | 8 |
| 1.000 login + 5.000 refresh /sn | 3 | 40 | **120** | 8 GB | db.r8g.4xlarge | 16 |
| **2.000 login + 10.000 refresh /sn** | 3 | 74 | **222** | 8 GB | db.r8g.16xlarge | **64** |

Ortam: OpenShift 4.17, `c8g.8xlarge`/`c8g.24xlarge`, eu-west-1 3 AZ, Aurora PostgreSQL 17.5, 100.000 kullanıcı, 20–50 adet `t4g.small` yük üreteci, `http-pool-max-threads=330`.

**Bu tablo raporun en önemli tek verisi.** Aşmanız gereken şey "2.000 login/sn" değil, **"286 vCPU ile 2.000 login/sn"**dir (222 uygulama + 64 veritabanı).

Doğrulama — resmî formül ölçümle tutarlı:
```
2.000 login / 15  = 133 vCPU
10.000 refresh / 120 =  83 vCPU
                     ─────────
                       216 vCPU   (ölçülen: 222) ✓
```

Diğer bulgular:
- **Sürüm farkı gerçek:** 20 ms gidiş-dönüş gecikmesinde p99 yanıt süresi KC 26.3'te **1.076 ms**, KC 26.4'te **130 ms** (8,3x iyileşme). 0 ms'de 51 → 47 ms. Yani Keycloak'ın gecikme davranışı ağ RTT'sine aşırı duyarlıydı.
- **Önbellek boyutu DB'yi doğrudan sürüyor:** oturum önbelleği 10.000 → 200.000 girdiye çıkarıldığında Aurora tepe CPU **%77,77 → %63,77**.
- Test edilen azami toplam: 12.000 istek/sn; "test edilen aralıkta neredeyse doğrusal" dikey ölçekleniyor.
- **"Farklı bölgelere yaymayı önermiyoruz."**

### 1.3 Keycloak'ın yapısal darboğazları

Kaynak: [keycloak.org/server/caching](https://www.keycloak.org/server/caching)

| Darboğaz | Mekanizma | Sonuç |
|---|---|---|
| Yerel önbellek varsayılanı | `realms`, `users`, `authorization` → **10.000 girdi**; `keys` → 1.000 girdi, 1 saat TTL | 1M kullanıcıda isabet oranı düşük → her login DB'ye gider |
| Oturum önbelleği | Node başına **10.000 girdi** | Yukarıdaki %77→%63 Aurora CPU etkisinin sebebi |
| `persistent-user-sessions` | Oturumlar varsayılan olarak **DB'de**, talep üzerine önbelleğe yüklenir | Login başına ek DB yazma/okuma |
| `work` önbelleği | Replicated cache ile **invalidation mesajı yayını** | Node sayısıyla mesaj trafiği artar |
| Session affinity | "Üretimde mutlaka değerlendirilmeli" | Yük dengeleme esnekliği kaybı; node kaybında state transfer |

**Argus için çıkarım:** Keycloak'ın mimarisi "durum node'da, DB'de de kopyası var, node'lar birbirini invalidate ediyor" üzerine kurulu. Bu, cluster büyüdükçe süperdoğrusal maliyet üretir. Durumsuz + tek doğruluk kaynağı (DB veya paylaşımlı önbellek) tasarımı burada yapısal avantaj sağlar.

### 1.4 Diğer IdP'ler

| Ürün | Yayımlanan performans verisi | Değerlendirme |
|---|---|---|
| **Zitadel** | Zitadel'in kendisi ~512 MB RAM, <1 CPU çekirdeği. **DB: ~100 istek/sn başına 1 CPU çekirdeği**, çekirdek başına 4 GB RAM. Üretim HA: min 3 node × 4 çekirdek/16 GB. "Parola hash'lemede CPU tepe yapar, 4 çekirdek önerilir." ([kaynak](https://zitadel.com/docs/self-hosting/manage/production), çekildi 8 Eyl 2026) | Bunlar **ölçüm değil, doküman tavsiyesi**. Bağımsız benchmark **DOĞRULANAMADI**. Event sourcing maliyetine dair sayısal veri **DOĞRULANAMADI**. DB'ye 100 req/sn/çekirdek yüklemesi Keycloak'tan (login için 15/vCPU ama uygulama tarafında) farklı bir profil gösteriyor |
| **Ory Hydra/Kratos** | `ory.sh/docs/hydra/benchmarks` ve `ory.com/docs/hydra/benchmarks` → **404**. `github.com/ory/hydra/.../BENCHMARKS.md` → **404** | Eskiden yayımlanan benchmark dokümanı **kaldırılmış**. Güncel sayısal veri **DOĞRULANAMADI** |
| **authentik** | Yalnızca asgari gereksinim: 2 CPU çekirdeği, 2 GB RAM ([kaynak](https://docs.goauthentik.io/install-config/install/docker-compose/)) | Throughput verisi **DOĞRULANAMADI** |
| **Logto, SuperTokens, Casdoor, Better Auth** | Bulunamadı | **DOĞRULANAMADI** |
| **Bağımsız karşılaştırmalı benchmark** | Bulunamadı | **DOĞRULANAMADI.** Hakemli çalışma bulamadım. Bu bir fırsat: alanda karşılaştırılabilir, tekrarlanabilir IdP benchmark'ı yok |

### 1.5 Ory / OpenAI ölçeği

Kaynak: [ory.com/case-studies/openai](https://www.ory.com/case-studies/openai) (yayın 6 Mar 2025, son güncelleme 1 Eyl 2026)

- **900M haftalık aktif kullanıcı** (Ekim 2025; Aralık 2024'te 400M)
- **Ory Hydra**, self-hosted Ory Enterprise License
- Veritabanı: **CockroachDB**
- Performans: *"unprecedented logins per second"* — **sayı verilmiyor**

**Throughput, gecikme veya donanım rakamı yayımlanmamış → DOĞRULANAMADI.** Teknik olarak çıkarılabilecek tek şey: bu ölçekte **CockroachDB** seçilmiş, yani çok bölgeli yatay ölçeklenen bir SQL katmanı tercih edilmiş.

Auth0/Okta/Google/Cloudflare Access için sayısal mimari yazısı bu oturumda **bulunamadı → DOĞRULANAMADI**.

---

## 2. Parola hash kapasite planlaması — en kritik darboğaz

### 2.1 Önce standartlar: "eşdeğer" parametreler eşdeğer maliyette değil

[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) beş Argon2id yapılandırmasını **eşdeğer güvenlik** sayar:

`m=47104,t=1` · `m=19456,t=2` · `m=12288,t=3` · `m=9216,t=4` · `m=7168,t=5` (hepsi p=1)

[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) §4 ayrı bir öneri seti verir: **1. öneri** t=1, p=4, m=2²¹ (2 GiB); **2. öneri** t=3, p=4, m=2¹⁶ (64 MiB). RFC benchmark rakamı **vermiyor** (yalnızca "x86 için optimize" ifadesi).

**Kritik gözlem:** Keycloak `m=7168, t=5, p=1` kullanıyor — bu OWASP'ın **en düşük bellekli eşdeğer** seçeneği. Yani Keycloak zayıf parametre kullanmıyor; bilinçli olarak bellek ayak izini minimize etmiş. Sizin hedeflediğiniz `m=19456, t=2` ile **aynı güvenlik sınıfında** ama **2,7 kat az bellek** tüketiyor.

### 2.2 [ÖLÇÜM] Tek çekirdek Argon2id gecikmesi

Apple M4, tek thread, `argon2` crate 0.5.3 (RustCrypto) ve `phc-winner-argon2` C kütüphanesi:

| Parametre | Rust ms/hash | Rust hash/sn/çekirdek | C ms/hash | Toplam iş (MiB-geçiş) |
|---|---|---|---|---|
| m=46 MiB, t=1 | 16,08 | 62,2 | 16,02 | 46 |
| **m=19 MiB, t=2** | **10,65** | **93,9** | 10,59 | 38 |
| m=12 MiB, t=3 | 9,19 | 108,8 | 9,93 | 36 |
| m=9 MiB, t=4 | 9,12 | 109,7 | 9,73 | 36 |
| **m=7 MiB, t=5 (Keycloak)** | **8,95** | **111,7** | 9,87 | 35 |
| m=64 MiB, t=3 (RFC9106 #2) | 66,11 | 15,1 | 68,92 | 192 |

**Bulgu 1 — "eşdeğer" seçenekler %80'e varan maliyet farkı taşıyor.** `m=46,t=1` (16,08 ms) ile `m=7,t=5` (8,95 ms) arasında **1,80x** fark var. OWASP'ın eşdeğerlik listesi güvenlik açısından doğru, **performans açısından yanıltıcı**. Yüksek bellek + düşük geçiş kombinasyonu, aynı güvenlik için daha fazla CPU harcıyor (bellek tahsis/ilklendirme maliyeti geçişlerle amorti edilemiyor).

**Bulgu 2 — RFC 9106'nın 2. önerisi (m=64 MiB, t=3) 66 ms.** Bu, çekirdek başına **15 login/sn** demektir. RFC'nin 1. önerisi (2 GiB) bir IdP için tamamen kullanılamaz.

### 2.3 [ÖLÇÜM] Bellek bant genişliği duvarı — asıl mesele

Aynı iş, artan thread sayısıyla (toplam hash/sn):

**m=19 MiB, t=2:**

| Thread | hash/sn | Hızlanma | Verim |
|---|---|---|---|
| 1 | 99,0 | 1,00x | 100% |
| 2 | 161,5 | 1,66x | 83% |
| **4** | **268,8** | **2,76x** | **69%** |
| 6 | 317,9 | 3,26x | 54% |
| 8 | 342,5 | 3,51x | 44% |
| 10 | 391,9 | 4,02x | **40%** |

**m=7 MiB, t=5:**

| Thread | hash/sn | Hızlanma | Verim |
|---|---|---|---|
| 1 | 109,2 | 1,00x | 100% |
| 2 | 215,2 | 2,03x | **102%** |
| **4** | **370,9** | **3,50x** | **87%** |
| 6 | 413,4 | 3,90x | 65% |
| 8 | 437,7 | 4,13x | 52% |
| 10 | 539,3 | 5,09x | 51% |

(C kütüphanesi ile aynı desen: 19 MiB'de 4 thread %70, 7 MiB'de %81.)

**Bu tablo raporun ikinci en önemli verisi.** Yorumu:

1. **Argon2 çekirdek sayısıyla ölçeklenmiyor.** 10 thread'de yalnızca 4,02x kazanç. Bu, "N çekirdek → N × hash/sn" varsayımıyla yapılan her kapasite planını **2,5 kat yanlış** kılar.
2. **Düşük bellekli parametre belirgin biçimde daha iyi ölçekleniyor.** 4 thread'de: m=7 MiB %87 verim, m=19 MiB %69. Sebep: 7 MiB'lik çalışma kümesi büyük L2/L3 önbelleklerine kısmen sığar, 19 MiB sığmaz ve her erişim DRAM'e iner. Toplam bellek trafiği neredeyse aynı olduğu halde (35 vs 38 MiB-geçiş) **konum (locality) farkı** ölçeklenmeyi belirliyor.
3. **Metodolojik uyarı:** M4'te 6 P + 4 E çekirdeği var; 6 thread'in üstündeki düşüşün bir kısmı E-çekirdeklerinin yavaşlığından. Ama **4 thread karşılaştırması tamamen P-çekirdekler üzerindedir** ve orada bile %87 vs %69 farkı net. Yani etki gerçek, yalnızca büyüklüğü x86 sunucuda doğrulanmalı.

### 2.4 Kapasite formülü ve bellek ayak izi

```
Eşzamanlı hash sayısı (Little yasası) = hedef_login/sn × hash_gecikmesi
Bellek ayak izi = eşzamanlı_hash × m
```

2.000 login/sn için:

| Parametre | Gecikme | Eşzamanlı hash | **Bellek** | M4-sınıfı çekirdek ihtiyacı (ölçülen ölçeklenmeyle) |
|---|---|---|---|---|
| m=19 MiB, t=2 | 10,65 ms | 21,3 | **405 MiB** | ~51 çekirdek (10 çekirdekte 391,9 h/sn) |
| m=7 MiB, t=5 | 8,95 ms | 17,9 | **125 MiB** | ~37 çekirdek (10 çekirdekte 539,3 h/sn) |

**Bulgu: bellek darboğaz değil.** 2.000 login/sn yalnızca ~400 MiB eşzamanlı hash belleği ister. Yaygın "Argon2 RAM'i patlatır" endişesi bu ölçekte yersizdir — **darboğaz CPU ve bellek bant genişliğidir**, kapasite değil. Bellek ancak *sınırsız eşzamanlılığa* izin verirseniz sorun olur (bkz. §6.2 kabul kontrolü).

### 2.5 Keycloak'ın CPU'su gerçekte nereye gidiyor? (türetilmiş analiz)

Keycloak dokümanı şunu iddia ediyor: *"Keycloak CPU zamanının çoğunu kullanıcının verdiği parolayı hash'lemekle geçirir."* **Kendi rakamları bunu desteklemiyor:**

- Resmî oran: 1 vCPU / 15 login/sn → login başına **66,7 ms CPU**
- Aynı parametrede (m=7 MiB, t=5) ölçülen hash maliyeti: **~9–10 ms**
- Hash payı: **~%15**

Yani **login CPU'sunun ~%85'i parola hash'leme değil** — JVM, Quarkus/JAX-RS katmanı, Infinispan, JPA/Hibernate, DB gidiş-dönüşleri, serileştirme.

**Uyarı:** M4 çekirdeği ile `c7g.2xlarge` (Graviton3) vCPU'su denk değildir; Graviton3 tek çekirdek performansı belirgin biçimde düşüktür. Graviton3'ün 2 kat yavaş olduğunu varsaysak bile hash payı ~%30'da kalır. **Bu bir tahmindir, x86/ARM sunucuda doğrulanmalıdır** — ama yönü sağlamdır.

> **Argus için stratejik sonuç:** Keycloak'ı yenmenin yolu Argon2'yi hızlandırmak değil. Argon2 kasıtlı olarak yavaştır ve onu hızlandıramazsınız. Kazanç, **hash dışındaki %85'i ortadan kaldırmakta**. Aynı Argon2 parametresiyle çekirdek başına 15 yerine 40–60 login/sn hedefi gerçekçidir; bu 3–4x'lik bir kazançtır ve tamamen "overhead silme" işidir.

### 2.6 SIMD ve implementasyon seçimi

**Yaygın iddia yanlış çıktı.** [RustCrypto/password-hashes#104](https://github.com/RustCrypto/password-hashes/issues/104) (açılış 29 Oca 2021, hâlâ **OPEN**) "argon2 crate'i optimize edilmemiş `ref.c` çevirisidir, `opt.c` gerekir" diyor. Ancak **kaynak kodu inceledim** — `argon2` 0.5.3 artık runtime AVX2 dispatch içeriyor:

```rust
// argon2-0.5.3/src/lib.rs:148
cpufeatures::new!(avx2_cpuid, "avx2");
// :463-470
#[target_feature(enable = "avx2")]
unsafe fn compress_avx2(rhs: &Block, lhs: &Block) -> Block { ... }
if self.cpu_feat_avx2.get() { return unsafe { compress_avx2(rhs, lhs) }; }
```

Yani issue metni güncel değil. x86-64'te crate AVX2 yolunu kullanır. **AVX-512 yolu yok.**

**Ölçümümdeki C ≈ Rust eşitliği neden aldatıcı:** `phc-winner-argon2` derlemesi `"Building without optimizations"` dedi ve `ref.c` kullandı — çünkü `opt.c` yalnızca SSE2/SSSE3/XOP/AVX2/AVX512F destekliyor, **ARM NEON yolu yok**. Dolayısıyla ARM'de her iki taraf da referans uygulamadır.

> **x86-64 sunucuda C `opt.c` (AVX2/AVX-512) ile Rust crate'i arasındaki farkı ölçemedim → DOĞRULANAMADI.** Argus'un ilk performans işlerinden biri bu olmalı: hedef sunucuda `argon2` crate'i ile `libargon2` (opt.c, `-march=native`) karşılaştırması. Fark %20'yi geçerse FFI'ye geçmeye değer.

### 2.7 Hash işini ayırma stratejileri

| Strateji | Değerlendirme |
|---|---|
| **Sınırlı worker havuzu (aynı süreç)** | **Önerilen.** §6.2'de ölçtüm: hem throughput'u hem p99'u iyileştiriyor. En düşük karmaşıklık |
| Ayrı hash mikroservisi | Ağ gidiş-dönüşü (~0,2–1 ms) 9–10 ms hash yanında önemsiz. **Gerçek fayda: izolasyon** — hash yükü API katmanının tail latency'sini bozamaz, ayrı ölçeklenir. Bedeli: parola ağdan geçer (mTLS zorunlu), operasyonel karmaşıklık |
| GPU/FPGA hızlandırma | **Savunmacıya yaramaz.** Argon2 zaten GPU'yu bellek bant genişliğinden boğmak için tasarlandı. Savunmacı tarafta tek hash gecikmesi düşmez |
| Intel QAT / donanım | Argon2 için QAT desteği **DOĞRULANAMADI** |
| Kabul kontrolü + kuyruk + yük atma | **Zorunlu.** Bkz. §6.2 |

**Büyük servisler ne yapıyor:** Bu oturumda Auth0/Okta/Dropbox/Facebook/Discord mühendislik yazılarına erişemedim → **DOĞRULANAMADI**. Bilinen genel kalıp (bellekten, doğrulanmadı): parola hash'i "pepper" ile HSM/KMS'te ikinci bir simetrik katmana sarılır (Dropbox'ın bcrypt+AES yaklaşımı) — bu performansı değiştirmez, DB sızıntısı senaryosunu değiştirir.

---

## 3. Token imzalama ve doğrulama

### 3.1 [ÖLÇÜM] Ham imza performansı — Apple M4, tek çekirdek

| İşlem | µs/op | ops/sn/çekirdek |
|---|---|---|
| **aws-lc-rs Ed25519 imzala** | **4,10** | **243.804** |
| ring Ed25519 imzala | 7,30 | 137.050 |
| RustCrypto ed25519-dalek imzala | 8,56 | 116.777 |
| ring Ed25519 doğrula | 19,72 | 50.704 |
| aws-lc-rs Ed25519 doğrula | 18,32 | 54.597 |
| RustCrypto ed25519-dalek doğrula | 18,03 | 55.475 |
| ring ES256 (P-256) imzala | 10,79 | 92.701 |
| aws-lc-rs ES256 imzala | 11,05 | 90.483 |
| aws-lc-rs ES256 doğrula | 27,30 | 36.632 |
| ring ES256 doğrula | 28,52 | 35.069 |
| **RustCrypto p256 imzala (saf Rust)** | **84,06** | 11.896 |
| **RustCrypto p256 doğrula (saf Rust)** | **134,52** | 7.434 |
| RustCrypto RSA-2048 imzala | 710,46 | 1.408 |
| RustCrypto RSA-2048 doğrula | 88,80 | 11.262 |
| HMAC-SHA256 (HS256) | 0,66 | 1.522.689 |

**Bulgular:**

1. **Ed25519 her yönden ES256'yı yener:** imzada 2,6x (aws-lc-rs), doğrulamada 1,5x hızlı. Ed25519'u seçin.
2. **Saf Rust P-256 felaket:** aws-lc-rs'e göre imzada **7,6x**, doğrulamada **4,9x** yavaş. `p256` crate'ini üretim yolunda kullanmayın.
3. **RSA-2048 imzalama 710 µs** — Ed25519'un (aws-lc-rs) **173 katı**. RS256 varsayılan yapmayın; yalnızca uyumluluk için tutun.
4. **İmzalama ≠ doğrulama.** Ed25519'da doğrulama imzalamadan **4,5x pahalı** (18,3 vs 4,1 µs). Bir IdP çoğunlukla *imzalar* (ucuz); doğrulama maliyeti resource server'lara ve DPoP'a düşer.
5. **HS256 27x ucuz** ama anahtar paylaşımı gerektirdiği için çok taraflı bir IdP'de kullanılamaz. Yalnızca dahili, tek taraflı token'lar için.

### 3.2 [ÖLÇÜM] Batch doğrulama (ed25519-dalek `verify_batch`)

| Batch boyutu | µs/imza | Tekile göre |
|---|---|---|
| 1 (tekil) | 18,03 | 1,00x |
| 8 | 10,08 | 1,79x |
| 64 | 8,63 | 2,09x |
| 256 | 7,48 | **2,41x** |

Gerçek ama sınırlı bir kazanç. **Bir IdP için pratik kullanımı dar:** batch doğrulama "hepsi geçerli mi?" sorusuna cevap verir; bir imza bozuksa hangisinin bozuk olduğunu söylemez, yeniden tekil doğrulama gerekir. Ayrıca istekleri batch'lemek gecikme ekler. **Öneri: kullanmayın**, çünkü IdP'nin doğrulama yükü zaten düşük.

### 3.3 [ÖLÇÜM] JWT uçtan uca — kripto dışı maliyet

`jsonwebtoken` 9.3.1 (ring backend), 296 baytlık claims, 534 baytlık token:

| İşlem | µs | ops/sn |
|---|---|---|
| EdDSA JWT encode | 15,20 | 65.802 |
| EdDSA JWT decode | 21,03 | 47.545 |
| ES256 JWT encode | 18,52 | 53.997 |
| ES256 JWT decode | 29,41 | 33.997 |
| HS256 JWT encode | 0,74 | 1.352.506 |
| HS256 JWT decode | 1,27 | 786.579 |
| **serde_json serialize** | **0,22** | 4.553.250 |
| **serde_json deserialize** | **0,31** | 3.244.833 |
| **base64url encode** | **0,08** | 11.775.015 |
| **base64url decode** | **0,09** | 11.135.971 |

**Bulgu: JSON ve base64 pratikte bedava.** İkisi birlikte encode'un %2'sinden az. simd-json/sonic-rs'e geçmenin JWT yolunda **kazancı sıfıra yakındır**. Maliyet ~%95 kriptodur.

### 3.4 [ÖLÇÜM] `jsonwebtoken` crate'inde 1,91x'lik kayıp — somut bulgu

Ham `ring` Ed25519 imzalama 7,30 µs, ama `jsonwebtoken::encode` 15,20 µs. Aradaki fark JSON/base64 değil (0,3 µs). **Kaynağı kodda buldum:**

```rust
// jsonwebtoken-9.3.1/src/crypto/eddsa.rs
pub fn sign(key: &[u8], message: &[u8]) -> Result<String> {
    let signing_key = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key)?;  // HER İMZADA!
    let out = signing_key.sign(message);
```

```rust
// crypto/ecdsa.rs — ES256 daha da kötü
    let rng = rand::SystemRandom::new();                        // her imzada
    let signing_key = signature::EcdsaKeyPair::from_pkcs8(alg, key, &rng)?;  // her imzada
```

Anahtar **her imzalama çağrısında PKCS#8'den yeniden parse ediliyor**. Ölçtüm:

| | µs | ops/sn |
|---|---|---|
| `jsonwebtoken::encode` | 15,01 | 66.623 |
| **Elle yazılmış, önbellekli KeyPair** | **7,84** | **127.570** |
| `Ed25519KeyPair::from_pkcs8` (tek başına) | 6,77 | 147.806 |
| `ring` sign (önbellekli anahtar) | 6,94 | 144.079 |

**Hızlanma: 1,91x.** Anahtar parse maliyeti (6,77 µs) imzanın kendisine (6,94 µs) neredeyse eşit.

> **Somut aksiyon:** Argus'ta JWT üretimini `jsonwebtoken` ile yapmayın. Header'ı önceden base64'leyip, `KeyPair`'i process ömrü boyunca önbellekte tutan ~40 satırlık bir encoder yazın. Bedava 1,9x. Aynı hata birçok Rust servisinde var.

### 3.5 [ÖLÇÜM] DPoP ve alternatifler

| İşlem | µs | ops/sn |
|---|---|---|
| JWK SHA-256 thumbprint (RFC 7638) | 0,21 | 4.795.069 |
| DPoP ≈ (EdDSA JWT decode + thumbprint) | **21,51** | 46.493 |
| Opak token: 32 bayt rastgele + SHA-256 | **0,75** | 1.337.186 |

**DPoP'un asıl maliyeti thumbprint değil (0,21 µs), ikinci bir imza doğrulamasıdır (~19–21 µs).** Yani DPoP'lu her istek, DPoP'suza göre **~21 µs ek CPU** ister. 10.000 istek/sn'de bu 0,21 çekirdek — kabul edilebilir.

**Ama gerçek DPoP maliyeti kriptoda değil, `jti` replay önbelleğinde.** Her proof'un `jti`'si tekrar kullanımı engellemek için saklanmalı ve bu **dağıtık, yazma-ağırlıklı bir durum**dur. Bu, §5'teki iptal yayını problemiyle aynı sınıftadır ve asıl mühendislik burasıdır. mTLS-bound token (RFC 8705) alternatifi bu durumu ortadan kaldırır çünkü bağlanma TLS katmanındadır — sayısal karşılaştırma **DOĞRULANAMADI**.

**Dikkat çekici:** Opak token (0,75 µs) JWT'den **20x ucuz**. Eğer introspection'ı hızlı bir önbellekten yapabiliyorsanız, opak token + merkezî doğrulama, JWT'den *CPU olarak* daha ucuzdur. JWT'nin avantajı CPU değil, **ağ gidiş-dönüşünden kaçınmaktır**.

### 3.6 Post-kuantum

ML-DSA (FIPS 204) imza boyutları ve hızlarına dair güvenilir ölçüm bu oturumda **bulunamadı → DOĞRULANAMADI**. Bilinen tek yapısal gerçek: ML-DSA-44 imzası ~2.420 bayt, Ed25519 ise 64 bayt. Bu, **JWT boyutunu ~40x büyütür** ve HTTP header limitlerini (8 KB) zorlar. Argus'un tasarımında `alg` alanının ve anahtar rotasyon mekanizmasının bunu kaldırabilmesi gerekir — ama bugün Ed25519 ile başlayın.

---

## 4. Postgres kimlik şeması ölçeklenmesi

Tüm ölçümler: PostgreSQL 18.6, Docker (aarch64-alpine), `shared_buffers=2GB`, `work_mem=64MB`, `synchronous_commit=on`, 8 eşzamanlı bağlantı.

### 4.1 [ÖLÇÜM] Birincil anahtar: UUIDv4 vs UUIDv7

3.000.000 satır insert:

| | Süre | Heap | **PK indeks** |
|---|---|---|---|
| UUIDv4 (`gen_random_uuid()`) | 9.366 ms | 219 MB | **122 MB** |
| **UUIDv7 (`uuidv7()`, PG18 yerleşik)** | **5.599 ms** | 219 MB | **90 MB** |

**UUIDv7 insert'te 1,67x hızlı, indeks %26 küçük.** Sebep: UUIDv7 zaman sıralıdır, B-tree'nin sağ ucuna sıralı yazar (sayfa bölünmesi az, önbellek isabeti yüksek). UUIDv4 rastgeledir ve indeksin her yerine dağılır.

> **Aksiyon: tüm tablolarda UUIDv7 kullanın.** PostgreSQL 18 `uuidv7()`'yi yerleşik sunuyor, ekstra eklenti gerekmiyor. Bu, 100M+ satırda hem yazma throughput'u hem indeks bellek ayak izi açısından bedava kazançtır.
>
> **Güvenlik uyarısı:** UUIDv7 zaman damgası sızdırır. Kullanıcıya görünen tanımlayıcılarda (public ID) kullanmayın; dahili PK olarak kullanın, dışa ayrı bir opak ID verin.

### 4.2 [ÖLÇÜM] Row-Level Security'nin gerçek maliyeti

3M satırlık `sess` tablosu, tekil oturum arama, pgbench 8 bağlantı / 12 sn:

| Senaryo | tps | Ortalama gecikme | **Maliyet** |
|---|---|---|---|
| RLS yok (temel) | 11.843,7 | 0,338 ms | — |
| **RLS var, basit indekslenebilir policy** | **11.324,2** | 0,353 ms | **%4,4** |
| **RLS var, `EXISTS` alt sorgulu policy** | **9.641,1** | 0,415 ms | **%18,6** |

Policy'ler:
```sql
-- Ucuz: predicate doğrudan indekse itiliyor
CREATE POLICY p_tenant ON sess USING (tenant_id = current_setting('app.tenant')::uuid);
-- Pahalı: satır başına ek indeks probe'u
CREATE POLICY p_sub ON sess USING (EXISTS (
  SELECT 1 FROM memberships m WHERE m.user_id=sess.user_id AND m.tenant_id=sess.tenant_id));
```

Plan farkı belirleyici. Basit policy'de predicate **Index Cond**'a giriyor:
```
Index Cond: (tenant_id = (current_setting('app.tenant'::text))::uuid)
```
Alt sorgulu policy'de ise **satır başına çalışan bir Filter**'a dönüşüyor:
```
Filter: EXISTS(SubPlan 2)
  ->  Index Only Scan using memberships_pkey  (loops = her satır)
```

**Bulgu: "RLS yavaştır" folkloru yanlış — RLS'in maliyeti tamamen policy'nin indekslenebilirliğine bağlı.**

- Policy predicate'i tablonun **lider indeks kolonuyla** eşleşiyorsa maliyet %5 civarı → **kabul edilebilir, kullanın**.
- Policy alt sorgu/JOIN içeriyorsa maliyet satır sayısıyla doğrusal büyür. Tekil aramada %19, N satır dönen bir taramada **N kat ek indeks probe'u** demektir — orada felakete döner.

> **Aksiyon:** RLS'i Argus'ta kullanın ama **tek kuralla**: her policy predicate'i tek bir indeksli kolon üzerinde eşitlik olmalı (`tenant_id = current_setting(...)`). Üyelik alt sorgusu gerekiyorsa, üyeliği isteğin başında bir kez çözüp `SET LOCAL app.tenant`'a yazın — policy'ye taşımayın.

### 4.3 [ÖLÇÜM] `last_seen` güncellemesi — kullanıcının sorduğu kritik soru

500.000 satırlık oturum tablosu, her istekte tek satır `UPDATE`, pgbench 8 bağlantı / 15 sn:

| Varyant | tps | **HOT %** | WAL (toplam) | **WAL/güncelleme** |
|---|---|---|---|---|
| `last_seen` **indeksli** (logged) | 26.266 | **0,0%** | 123 MB | **328 B** |
| İndekssiz (logged, fillfactor 100) | 25.984 | 97,0% | 74 MB | 199 B |
| **İndekssiz + fillfactor=70** | **27.856** | **100%** | 73 MB | **183 B** |
| **UNLOGGED + fillfactor=70** | **109.484** | **100%** | 62 MB | **38 B** |
| **Toplu: 1.000 satır / tek statement** | **~208.800 satır/sn** | — | — | — |

**Cevap: "Her istekte `last_seen` güncellemek kötü fikir mi?" → Nasıl yaptığınıza bağlı. Şu üç kural her şeyi değiştiriyor:**

1. **`last_seen` kolonunu ASLA indekslemeyin.** İndeks, HOT update'i **tamamen imkânsız** kılıyor (%97 → %0) ve WAL'ı **1,8x** artırıyor (183 → 328 B/güncelleme). Aynı işi yapmak için iki katına yakın disk ve replikasyon trafiği. "Son 5 dakikada aktif oturumlar" sorgusu için `last_seen` indeksi istiyorsanız — istemeyin; onun yerine `expires_at` indeksleyin (nadiren değişir).
2. **`fillfactor=70` verin.** %100 HOT ve ~%7 daha yüksek throughput. Bedeli %44 daha büyük heap (80 → 115 MB) — bu takas oturum tablosu için kesinlikle doğrudur.
3. **Toplu yazma 8x kazandırır.** Tek statement'ta 1.000 satır 4,79 ms'de güncelleniyor (~208.800 satır/sn), tekil güncelleme ise 27.856/sn.

**Ölçek hesabı:** 10.000 istek/sn'de her istekte `last_seen` güncellerseniz:
- İndeksli: 328 B × 10.000 = 3,28 MB/sn = **283 GB/gün WAL**
- İndekssiz + ff=70: 183 B × 10.000 = 1,83 MB/sn = **158 GB/gün WAL**
- Uygulama içinde 10 sn'lik pencerede birleştirip toplu yazarsanız: **~%90 azalma**

> **Önerilen mimari:** `last_seen`'i her istekte DB'ye yazmayın. Uygulama içinde (veya Redis'te) 10–30 saniyelik pencerede biriktirin, tek `UPDATE ... FROM (VALUES ...)` ile toplu yazın. Doğruluk kaybı 30 saniyedir — bir "son görülme" alanı için tamamen kabul edilebilir. Kazanç: WAL'da ~10x, tps'te ~8x.
>
> **UNLOGGED tablo (109.484 tps, 3,9x) cazip ama oturumlar için tehlikelidir:** crash'te tablo **boşalır**, yani tüm kullanıcılar çıkış yapar. Yalnızca gerçekten atılabilir durum için (rate limit sayaçları, geçici auth session) düşünün.

### 4.4 [ÖLÇÜM] Hash-zincirli denetim logu — en sert yapısal sınır

pgbench, 12 sn — ⚠️ **[YENİDEN ÜRETİM BEKLİYOR]**, donanım: Apple M4 / Docker PostgreSQL 18.6, 8 bağlantı (§5 ölçüm konvansiyonu). Aşağıdaki **mutlak** değerler Argus'un throughput'u değildir: çıplak insert ölçümüdür — Merkle yok, imza yok, uygulama mantığı yok, ağ yok. Bu bölümün başka yerlerinde bu sayının ürün throughput'u gibi kullanıldığı yerler düzeltilmiştir:

| Senaryo | tps | Ortalama gecikme |
|---|---|---|
| Düz append-only (zincirsiz), 8 bağlantı | **22.440,8** | 0,356 ms |
| Hash-zincirli, **8 bağlantı** | **5.898,1** | 1,356 ms |
| Hash-zincirli, **1 bağlantı** | **5.873,0** | 0,170 ms |

**Bu tablodaki asıl bulgu son iki satırın eşitliği.** 8 bağlantı (5.898 tps) ile 1 bağlantı (5.873 tps) **aynı throughput'u** veriyor. Yani:

> **Hash zinciri paralelliği tamamen yok ediyor.** Her kayıt bir öncekinin hash'ine bağlı olduğu için işlem seri olmak zorunda. Eşzamanlılık eklemek throughput'a **hiçbir şey katmıyor**, yalnızca gecikmeyi 0,170 ms'den 1,356 ms'ye (**8x**) çıkarıyor — çünkü bağlantılar kilit için sıraya giriyor.

Zincir maliyeti: **bu ölçüm koşullarında** düz log'a göre **3,8x throughput kaybı**.

> ⚠️ **Düzeltme (2. inceleme turu).** Burada önceden "donanımdan bağımsız ~5.900 olay/sn tavanı" yazıyordu. Bu iddia hem fazla geniş, hem de aşağıdaki çözüm tablosunun kendi *"Uygulama içi tek yazar — zinciri bellekte tutup batch commit"* satırıyla çelişiyor. **Savunulabilir ifade:** *tek bir doğrusal zincirde ardışık zincir hash'lerinin hesaplanması arasında seri bağımlılık vardır.* Payload hazırlama, bağımsız hash hesapları, batch yazma ve **farklı** zincirler paralel yürüyebilir; seri bağımlılık, olay başına ayrı bir veritabanı transaction'ını zorunlu kılmaz. Ölçülen şey belirli bir uygulamadır (olay başına transaction + her seferinde önceki hash'in okunması), yapısal bir tavan değil.

**Çözüm kalıpları:**

| Yaklaşım | Mekanizma | Değerlendirme |
|---|---|---|
| **Parçalı zincir (önerilen)** | Her shard/tenant kendi zincirini tutar; zincirler arası seri bağımlılık yoktur | Shard sayısıyla ölçeklenir, ⚠️ **ama doğrusal olmak zorunda değil** — ortak disk, WAL, checkpoint ve imza darboğazları paylaşılır; "N shard = N × ölçülen tps" **geçersiz bir ekstrapolasyondur**. Global sıralama kaybolur, ama denetim için genelde gerekmez |
| **Checkpoint / Merkle ağacı** | Olaylar zincirsiz yazılır; periyodik olarak (örn. saniyede bir) bir batch'in Merkle kökü zincire eklenir | Düz log hızıyla yazma + kanıtlanabilirlik (⚠️ *ölçüm etiketi: §6 §4.4, [YENİDEN ÜRETİM BEKLİYOR] — çıplak insert, ürün throughput'u değil*). **En iyi takas** |
| Certificate Transparency modeli | Merkle ağacı + imzalı ağaç başlığı (STH) | Aynı fikrin olgunlaşmış hali; Trillian/Rekor referans alınabilir |
| Uygulama içi tek yazar | Zinciri bellekte tutup batch commit | Yazar tek nokta hatası olur |

> **Aksiyon:** Olay başına zincir kurmayın. Olayları düz append-only yazın, her ~1 saniyede bir batch'in Merkle kökünü ayrı bir küçük "checkpoint" tablosuna zincirleyin. Kanıt gücü neredeyse aynı, throughput **3,8x** yüksek ve ölçeklenebilir.

### 4.5 LISTEN/NOTIFY'ın belgelenmiş sınırları

Kaynak: [postgresql.org/docs/current/sql-notify.html](https://www.postgresql.org/docs/current/sql-notify.html)

| Sınır | Değer/davranış |
|---|---|
| Payload | **< 8.000 bayt** |
| Kuyruk boyutu | Standart kurulumda **8 GB** (`max_notify_queue_pages`) |
| Kuyruk dolarsa | **`NOTIFY` çağıran transaction commit'te BAŞARISIZ olur** |
| Uzun transaction | `LISTEN` yapıp uzun transaction'a giren oturum **kuyruk temizliğini engeller**; %50'de log uyarısı |
| Teslimat | Yalnızca **commit sonrası**; dinleyici transaction içindeyse ertelenir |
| İki fazlı commit | `NOTIFY` yapmış transaction **prepare edilemez** |
| İzleme | `pg_notification_queue_usage()` |

**Ve kritik entegrasyon sorunu:** [PgBouncer](https://www.pgbouncer.org/features.html) dokümanına göre **transaction pooling modunda `LISTEN` desteklenmez** (SET/RESET, PREPARE, WITH HOLD cursor, session-level advisory lock ile birlikte).

> **Argus için sonuç: LISTEN/NOTIFY'ı iptal yayını için kullanmayın.** İki bağımsız sebep: (1) PgBouncer transaction mode ile uyumsuz — ve bağlantı ölçeklenmesi için transaction mode'a ihtiyacınız olacak; (2) tek bir uzun transaction tüm bildirim kuyruğunu tıkayabilir ve kuyruk dolduğunda **yazma işlemleriniz commit'te patlar**. Bu, iptal mekanizmasının veritabanının yazma yolunu düşürebilmesi demektir — kabul edilemez bir hata modu.

### 4.6 Bağlantı havuzlama

Belgelenmiş: PgBouncer bağlantı başına **~2 kB** bellek. Transaction mode'da kırılan özellikler yukarıda.

**Keycloak'ın rehberi** ([kaynak](https://www.keycloak.org/high-availability/multi-cluster/concepts-database-connections)): *"En iyi performans için initial, minimal ve maximum havuz boyutu eşit olmalı"* — dinamik bağlantı açmanın stampede etkisi ve sunucu tarafı prepared statement önbelleğinin kaybı nedeniyle. PostgreSQL'de prepared statement'ın devreye girmesi için sorgunun **en az 5 kez** çalışması gerekir. Sayısal havuz boyutu formülü **vermiyorlar**.

> "Postgres N bağlantının üstünde çöker" eğrisinin ölçülmüş hali bu oturumda **DOĞRULANAMADI**. Ancak yukarıdaki üç veri birleşince net bir tasarım çıkıyor: sabit boyutlu uygulama içi havuz + prepared statement kullanımı, transaction-mode PgBouncer ile **çelişir** (PREPARE desteklenmiyor). Ya PgBouncer'ı atlayıp uygulama havuzunda sabit, ölçülü sayıda bağlantı tutun, ya da PgBouncer kullanıp prepared statement'lardan vazgeçin. **İkisini birden alamazsınız** — bu, erken verilmesi gereken bir karardır.

### 4.7 Partitioning ve indeks stratejisi (kısmen doğrulanmamış)

Ölçemediğim ama yapısal olarak sağlam noktalar (**sayısal doğrulama yapılmadı → DOĞRULANAMADI**):

- Oturum, denetim logu ve token tablolarını **zamana göre range partition** edin. Asıl kazanç sorgu değil, **silme**: `DROP PARTITION` anında biterken `DELETE` milyonlarca satırda autovacuum kasırgası yaratır.
- Partition sayısını sınırlı tutun (haftalık/aylık). Çok sayıda partition **plan süresini** artırır.
- E-posta araması için `lower(email)` üzerinde functional unique index; `citext` yerine bunu tercih edin (daha öngörülebilir plan).
- Kapsayıcı indeks (`INCLUDE`) ile index-only scan hedefleyin — §4.2 ölçümlerinde `Heap Fetches: 0` gördük, doğru indekslemede tekil arama 0,3 ms'nin altında kalıyor.

---

## 5. Dağıtık mimari kararları

> **Bu bölüm raporun en zayıfı.** Web arama bütçesi tükendiği için Bloom/cuckoo filter'ın gerçek IdP kullanım örneklerini, dağıtık rate limiting benchmark'larını ve çok bölgeli kimlik replikasyonu ölçümlerini **bulamadım → DOĞRULANAMADI**. Aşağıdakiler belgelenmiş kısıtlardan çıkan **mühendislik muhakemesidir**, ölçüm değildir.

### 5.1 Oturum iptalinin yayılması

Belgelenmiş kısıtlardan çıkan tablo:

| Yöntem | Gecikme | Ölçek | Doğrulanmış kısıt |
|---|---|---|---|
| Postgres LISTEN/NOTIFY | Düşük | **Zayıf** | §4.5: PgBouncer transaction mode ile çalışmaz; kuyruk dolarsa yazmalar başarısız |
| Keycloak'ın `work` cache'i (replicated invalidation) | Düşük | Orta | §1.3: node sayısıyla mesaj trafiği artar, session affinity gerektirir |
| Harici pub/sub (Redis/NATS) | Düşük | İyi | Ölçüm **DOĞRULANAMADI** |
| Polling (kısa TTL + periyodik çekme) | TTL kadar | Çok iyi | — |

**Muhakeme:** Token TTL'ini kısa tutmak (örn. 60–120 sn access token) iptal yayınının çoğunu gereksiz kılar. "Anında iptal" gereksinimi genelde sanıldığından dardır ve yalnızca yüksek riskli olaylar (parola değişimi, oturum sonlandırma) için gerekir. Bu olaylar **seyrektir** — yani düşük hacimli bir pub/sub kanalı yeter, ve kaçırılan bir mesajın etkisi TTL ile sınırlıdır.

Bloom/cuckoo filter ile iptal listesi: yanlış pozitif, **geçerli bir kullanıcıyı reddetmek** demektir. Bu, "fail-open mu fail-closed mu" sorusunu doğurur ve güvenlik açısından tehlikelidir. Gerçek IdP'lerde kullanıldığına dair kanıt **bulamadım**.

### 5.2 Rate limiting

Doğruluk/performans takası ölçülmüş veriyle **DOĞRULANAMADI**. Yapısal not: §4.3'te ölçtüğüm UNLOGGED tablo performansı (109.484 tps, 38 B/güncelleme WAL) rate limit sayaçları için Postgres'in makul bir seçenek olabileceğini gösteriyor — ama sayaçlar için asıl doğru yer bellek içi/Redis'tir.

---

## 6. Rust'ta yüksek performans

### 6.1 Tokio varsayılanları (belgelenmiş)

Kaynak: [docs.rs/tokio/latest/tokio/runtime/struct.Builder.html](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html)

| Ayar | Varsayılan |
|---|---|
| `worker_threads` | Sistemdeki çekirdek sayısı |
| `max_blocking_threads` | **512** |
| Blocking thread keep-alive | 10 saniye |

Doküman `spawn_blocking`'i dosya IO, DNS, stdio için öneriyor; **CPU-yoğun iş için doğrudan rehberlik vermiyor** ve "bu limiti çok düşük ayarlamayın" diyor. Argon2 gibi CPU-yoğun iş için bu varsayılan (512) **fazlasıyla yanlıştır** — aşağıda ölçtüm.

### 6.2 [ÖLÇÜM] Argon2'yi nereye koymalı — raporun en uygulanabilir bulgusu

Argon2id m=19 MiB/t=2, 64 eşzamanlı login, 8 Tokio worker, 5 sn ölçüm. "Sağlık-ucu gecikmesi" = async runtime'ın duyarlılığı (küçük bir timer task'ının ne kadar geciktiği):

| Senaryo | hash/sn | p50 (ms) | **p99 (ms)** | max (ms) |
|---|---|---|---|---|
| **A) Hash doğrudan async worker'da** | 358,3 | 17,86 | **119,31** | 185,60 |
| B) `spawn_blocking` (sınırsız) | 370,9 | 1,07 | 29,64 | 86,95 |
| **C) `spawn_blocking` + semafor=6** | 323,9 | 1,07 | **2,34** | **3,91** |
| **D) `spawn_blocking` + semafor=10** | **403,9** | 1,08 | **4,77** | 8,22 |
| E) `spawn_blocking` + semafor=64 | 362,6 | 1,09 | 33,47 | 63,10 |

**Bulgular:**

1. **Async worker thread'inde hash'lemek runtime'ı öldürüyor.** p50 sağlık gecikmesi 17,86 ms, p99 **119 ms**. Üstelik throughput da daha iyi değil (358 vs 404). Bu senaryonun ilk denemesinde `yield_now()` olmadan test **tamamen kilitlendi** — 64 task 8 worker'ı süresiz işgal etti ve runtime hiçbir zaman timer'ı çalıştıramadı. Gerçek bir serviste bu, **sağlık kontrollerinin başarısız olması ve pod'un restart edilmesi** demektir.
2. **`spawn_blocking` tek başına yetmiyor.** p50 16,7x düzeliyor (17,86 → 1,07 ms) ama p99 hâlâ 29,64 ms — çünkü 512 blocking thread çekirdekleri aşırı abone ediyor ve bellek bant genişliğini doyuruyor.
3. **Sınırlı semafor hem throughput'u hem tail'i iyileştiriyor.** Semafor=10 en yüksek throughput'u (403,9 h/sn) **ve** p99'da senaryo A'ya göre **25x** iyileşmeyi (119,31 → 4,77 ms) birlikte veriyor. Semafor=6 en iyi tail'i (p99 2,34 ms, max 3,91 ms) biraz throughput karşılığında sunuyor.
4. **Sınırsıza yakın semafor (64) geriliyor** — p99 33,47 ms. Yani "daha fazla eşzamanlılık = daha fazla iş" burada yanlış.

> **Kesin öneri:** Argon2'yi `spawn_blocking` üzerine koyun **ve** eşzamanlılığı çekirdek sayısı civarında (çekirdek sayısı ± birkaç) bir semaforla sınırlayın. Kuyruk için bir üst sınır ve zaman aşımı ekleyip aşınca 503 dönün (yük atma). Bu ayar bedavaya **hem daha yüksek throughput hem 25x daha iyi p99** veriyor. Semafor değerini hedef donanımda kalibre edin — optimum, bellek bant genişliği duvarının dibindedir (§2.3).

### 6.3 Derleme optimizasyonları

Kaynak: [github.com/zamazan4ik/awesome-pgo](https://github.com/zamazan4ik/awesome-pgo)

| Proje | PGO kazancı |
|---|---|
| **ScyllaDB** | "%50'ye varan throughput, %33 daha düşük gecikme" |
| rustc | ~%10 derleme hızı |
| Genel (özel yazışmalar) | Tipik %5–7, bazen %10 |

Depo, kazancın iş yüküne çok bağlı olduğunu ve %20–50 aralığının da görüldüğünü belirtiyor. **Kendi ölçümüm yok → Argus için doğrulanmalı.**

Ölçümlerimin tamamını `opt-level=3 + lto="fat" + codegen-units=1` ile aldım; bu ayarların **ayrık katkısını ölçmedim → DOĞRULANAMADI**.

**Muhakeme:** Argus'un CPU profili ağırlıklı olarak Argon2 ve eğri kriptografisidir. Bunların ikisi de zaten elle optimize edilmiş, sıkı döngülü kodlardır — **PGO'nun bu kısımlara katkısı düşük olacaktır**. PGO asıl kazancı HTTP/serileştirme/yönlendirme katmanında verir; ama §3.3'te gördüğümüz gibi o katman zaten toplam maliyetin küçük bir yüzdesidir. **Önceliğiniz PGO olmasın.**

### 6.4 Ölçmediğim konular — dürüst boşluk listesi

| Konu | Durum |
|---|---|
| jemalloc / mimalloc / snmalloc vs sistem malloc | **DOĞRULANAMADI** — ölçmedim, kaynak bulamadım |
| `target-cpu=native` ayrık etkisi | **DOĞRULANAMADI** |
| TechEmpower güncel tur rakamları | **DOĞRULANAMADI** |
| rustls vs OpenSSL handshake/sn | **DOĞRULANAMADI** |
| io_uring (tokio-uring/monoio/glommio) kazancı | **DOĞRULANAMADI** |
| `tracing` span maliyeti | **DOĞRULANAMADI** |

Bunların hepsi Argus'un kendi ortamında ölçülebilir; hiçbiri için literatüre güvenmenize gerek yok.

---

## 7. Darboğaz sıralaması — bir IdP'de zaman gerçekte nereye gidiyor

Bir parola login'inin CPU bütçesi (M4 ölçümleri, Argus benzeri yalın bir yığın varsayımıyla):

| # | Bileşen | Maliyet | Toplam içindeki pay |
|---|---|---|---|
| **1** | **Argon2id (m=19 MiB, t=2)** | **10.650 µs** | **~%97** |
| 2 | Postgres: kullanıcı arama + oturum yazma (2–3 gidiş-dönüş) | ~200–400 µs | ~%2–3 |
| 3 | JWT üretimi (elle, önbellekli anahtar) | 7,8 µs | %0,07 |
| 4 | JWT üretimi (`jsonwebtoken` ile) | 15,0 µs | %0,14 |
| 5 | TLS, HTTP parse, yönlendirme | ölçülmedi | küçük |
| 6 | JSON + base64 | 0,3 µs | %0,003 |

Bir **refresh token** isteğinde:

| # | Bileşen | Maliyet |
|---|---|---|
| 1 | Postgres: token arama + rotasyon yazma | ~200–400 µs (**baskın**) |
| 2 | JWT doğrula + üret | ~29 µs |
| 3 | DPoP proof doğrulama (varsa) | +21,5 µs |

**Sıralamanın anlamı:**

1. **Login'de Argon2 mutlak baskındır (%97).** Onu optimize edemezsiniz — tasarımı gereği yavaştır. Yapabileceğiniz tek şey **doğru parametreyi seçmek** (m=7 MiB/t=5, m=19 MiB/t=2'den %16 ucuz ve %26 daha iyi ölçekleniyor) ve **doğru şekilde zamanlamaktır** (§6.2).
2. **Refresh'te darboğaz veritabanıdır**, kripto değil. 10.000 refresh/sn hedefi bir **Postgres yazma throughput'u problemidir**. Keycloak'ın bunun için 83 vCPU harcaması (120/sn/vCPU) tamamen framework overhead'idir.
3. **Kripto ve serileştirme gürültü seviyesindedir.** Buraya mühendislik yatırmak boşa emektir — tek istisna §3.4'teki 1,91x'lik bedava kazanç.

> **En büyük fırsat, listedeki hiçbir satır değil: Keycloak'ın login başına harcadığı 66,7 ms CPU'nun ~%85'ini oluşturan "diğer her şey" (JVM, ORM, Infinispan, katman geçişleri).** Argus'un rekabet avantajı burada. Argon2'yi hızlandıramazsınız ama onun etrafındaki 56 ms'yi 2 ms'ye indirebilirsiniz.

---

## 8. Argus için kapasite hesabı ve mimari öneriler

### 8.1 Hedef: Keycloak'ın 2.000 login + 10.000 refresh/sn senaryosunu yenmek

Keycloak'ın maliyeti: **222 uygulama vCPU + 64 DB vCPU = 286 vCPU**.

Argus için alt sınır hesabı (m=19 MiB/t=2, M4 ölçümleriyle, **sunucu CPU'sunda doğrulanmalı**):

```
Hash tarafı (kaçınılmaz fizik):
  10 çekirdekli düğümde ölçülen: 391,9 hash/sn
  2.000 login/sn → 2.000 / 39,2 hash/sn/çekirdek ≈ 51 çekirdek

  m=7 MiB/t=5 seçilirse: 539,3 hash/sn / 10 çekirdek
  2.000 / 53,9 ≈ 37 çekirdek

Token tarafı (neredeyse bedava):
  10.000 refresh/sn × 7,84 µs (elle JWT) = 0,078 çekirdek
  2.000 login/sn × 7,84 µs              = 0,016 çekirdek
  ────────────────────────────────────────────────────
  Toplam imzalama: 0,1 çekirdekten az

Bellek (eşzamanlı hash):
  m=19 MiB: 21,3 eşzamanlı × 19 MiB = 405 MiB
  m=7  MiB: 17,9 eşzamanlı × 7 MiB  = 125 MiB
```

| Konfigürasyon | Hash çekirdeği | Token çekirdeği | Hash belleği |
|---|---|---|---|
| Argus, m=19 MiB/t=2 | ~51 | <0,1 | 405 MiB |
| **Argus, m=7 MiB/t=5** | **~37** | **<0,1** | **125 MiB** |
| Keycloak (m=7 MiB/t=5, ölçülen) | — | — | — |
| **Keycloak toplam (ölçülen)** | **222 vCPU** | | 8 GB × 3 |

**Yorum:** Argon2 fiziği 37–51 çekirdek istiyor. Keycloak 222 vCPU harcıyor. **Aradaki ~4–6x, tamamen framework overhead'idir ve Argus'un alabileceği paydır.** Gerçekçi hedef: **60–80 çekirdekte 2.000 login + 10.000 refresh/sn** — yani Keycloak'ın ~3-4'te biri.

> **Uyarı: bu rakamlar M4 çekirdeği başınadır ve Graviton/EPYC vCPU'suna doğrudan çevrilemez.** Doğru okuma şudur: *Argus'un hash dışı overhead'i, Argon2 maliyetinin %10'unu geçmemelidir.* Keycloak'ta bu oran ~%570'tir. Ölçmeniz gereken metrik budur, mutlak çekirdek sayısı değil.

### 8.2 Somut mimari kararlar

**Parola hash'leme**
1. **`m=7168, t=5, p=1` seçin**, `m=19456, t=2` değil. OWASP eşdeğer sayıyor; ölçtüm: %16 daha ucuz, 4 thread'de %87 vs %69 ölçeklenme, 2,7x az bellek. **Keycloak'ın da seçtiği yapılandırma bu — ve bu konuda haklılar.**
2. Hash'i `spawn_blocking` + **çekirdek sayısı kadar semafor** ile çalıştırın. Kuyruk üst sınırı + zaman aşımı + 503 ile yük atma (§6.2).
3. Hedef sunucuda `argon2` crate'i (AVX2 dispatch'li) ile `libargon2 opt.c` (`-march=native`, AVX-512) karşılaştırmasını **yapın** — bu tek ölçüm ilk haftada yapılmalı.
4. Parametreleri veritabanında kayıt başına saklayın (algoritma + m/t/p), böylece geriye dönük migration mümkün olsun.

**Token**
5. **Ed25519 (EdDSA) varsayılan.** ES256'dan imzada 2,6x, doğrulamada 1,5x hızlı. RS256'yı yalnızca uyumluluk için tutun (173x yavaş).
6. **`jsonwebtoken` kullanmayın** — kendi encoder'ınızı yazın, `KeyPair`'i önbellekte tutun, header'ı önceden base64'leyin. **Bedava 1,91x.**
7. `aws-lc-rs`'i tercih edin (Ed25519 imzalamada `ring`'den 1,78x hızlı). Saf Rust `p256`/`rsa` crate'lerini üretim yolundan çıkarın (4,9–7,6x yavaş).
8. Batch doğrulama kullanmayın — 2,41x kazanç gerçek ama hata izolasyonu kaybı ve gecikme eklemesi buna değmez.

**Postgres**
9. **UUIDv7** her yerde (PG18 yerleşik `uuidv7()`): insert 1,67x hızlı, indeks %26 küçük. Dışa açık ID'ler için ayrı opak tanımlayıcı.
10. **`last_seen`'i indekslemeyin** (HOT'u %97'den %0'a düşürüyor, WAL'ı 1,8x artırıyor). Oturum tablosuna **`fillfactor=70`** verin (%100 HOT).
11. **`last_seen`'i her istekte yazmayın** — 10–30 sn pencerede birleştirip toplu `UPDATE` yapın (8x throughput, ~10x WAL azalması).
12. **RLS kullanın**, ama her policy tek indeksli kolonda eşitlik olsun (%4,4 maliyet). Alt sorgulu policy yazmayın (%18,6 ve satır sayısıyla büyür).
13. **Denetim logunu olay başına zincirlemeyin** — ölçülen koşullarda 3,8x throughput kaybı; tek doğrusal zincirde ardışık zincir hash'leri arasında seri bağımlılık var (⚠️ sayı ölçüme özgü, evrensel tavan değil — §6 §4.4). Düz append-only yazıp saniyede bir Merkle checkpoint zincirleyin.
14. **LISTEN/NOTIFY'ı iptal yayını için kullanmayın** — PgBouncer transaction mode'da çalışmaz ve dolu kuyruk yazmalarınızı commit'te düşürür.
15. **Erken karar verin:** PgBouncer transaction mode (prepared statement yok) **veya** uygulama içi sabit havuz (prepared statement var). İkisi birden olmaz.
16. Oturum/denetim/token tablolarını zamana göre partition edin — asıl kazanç `DROP PARTITION`.

**Ölçüm disiplini**
17. Tek anlamlı metrik: **login başına toplam CPU µs / Argon2 CPU µs**. Hedef < 1,10. Keycloak'ta bu oran ~6,7.
18. Kapasite planında **çekirdek sayısıyla doğrusal ölçeklenme varsaymayın** — 10 thread'de gerçek kazanç 4,02x (m=19 MiB) veya 5,09x (m=7 MiB).

---

## 9. Doğrulanamayanların listesi

Rakam uydurmadım. Şunlar bulunamadı veya ölçülemedi:

| Konu | Durum |
|---|---|
| Ory Hydra/Kratos güncel benchmark | Resmî sayfalar **404**; veri kaldırılmış |
| Ory/OpenAI throughput, gecikme, donanım | Yalnızca "unprecedented logins per second" pazarlama ifadesi |
| Zitadel bağımsız benchmark; event sourcing maliyeti | Yalnızca doküman tavsiyesi var, ölçüm yok |
| authentik / Logto / SuperTokens / Casdoor throughput | Hiç yayımlanmamış |
| Bağımsız karşılaştırmalı IdP benchmark'ı | Bulunamadı — alanda böyle bir çalışma yok görünüyor |
| Auth0 / Okta / Google / Cloudflare mimari yazıları | Erişilemedi |
| x86-64'te Argon2 AVX2/AVX-512 vs Rust crate farkı | ARM'de ölçülemez; **Argus ekibi ölçmeli** |
| Argon2 için Intel QAT / donanım hızlandırma | Kanıt yok |
| Bloom/cuckoo filter ile iptal listesinin gerçek kullanımı | Örnek bulunamadı |
| Dağıtık rate limiting doğruluk/performans ölçümleri | Bulunamadı |
| Çok bölgeli kimlik replikasyonu (CRDB/Vitess) ölçümleri | Bulunamadı |
| Allocator (jemalloc/mimalloc), PGO ayrık etkisi, rustls, io_uring, TechEmpower, tracing maliyeti | Ölçmedim, kaynak bulamadım |
| ML-DSA imza hız ölçümleri | Bulunamadı |
| "Postgres N bağlantı üstünde çöker" eğrisinin ölçümü | Bulunamadı |

---

## 10. Kaynaklar

- [Keycloak — Concepts for sizing CPU and memory resources](https://www.keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing) (çekildi 8 Eyl 2026)
- [Keycloak Performance Benchmarks: A Deep Dive into Scaling and Sizing (26.4)](https://www.keycloak.org/2025/10/keycloak-benchmark) (Ekim 2025)
- [Keycloak — Configuring distributed caches](https://www.keycloak.org/server/caching)
- [Keycloak — Concepts for database connection pools](https://www.keycloak.org/high-availability/multi-cluster/concepts-database-connections)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [P-H-C/phc-winner-argon2](https://github.com/P-H-C/phc-winner-argon2)
- [RustCrypto/password-hashes#104 — argon2: optimized implementation](https://github.com/RustCrypto/password-hashes/issues/104) (açık, 29 Oca 2021)
- [ZITADEL — Production setup](https://zitadel.com/docs/self-hosting/manage/production)
- [Ory — OpenAI case study](https://www.ory.com/case-studies/openai) (6 Mar 2025 / güncelleme 1 Eyl 2026)
- [authentik — Docker Compose installation](https://docs.goauthentik.io/install-config/install/docker-compose/)
- [PostgreSQL — NOTIFY](https://www.postgresql.org/docs/current/sql-notify.html)
- [PgBouncer — Features](https://www.pgbouncer.org/features.html)
- [Tokio — runtime::Builder](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html)
- [zamazan4ik/awesome-pgo](https://github.com/zamazan4ik/awesome-pgo)
- [MojoAuth — The Cost of Crypto: CPU Bottlenecks in Password Hashing](https://mojoauth.com/blog/password-hashing-performance-cpu-bottlenecks-high-traffic) (22 Haz 2026) — bcrypt cost 12 ≈ 249 ms, AWS c7i.xlarge

---

### Özet: en önemli beş bulgu

1. **Keycloak'ın 2.000 login/sn'i 286 vCPU'ya mal oluyor**, ve bunun ~%85'i parola hash'leme değil framework overhead'i. Rekabet alanınız burası.
2. **Argon2 çekirdek sayısıyla ölçeklenmiyor** — 10 thread'de 4,02x. Kapasite planlarının çoğu bu yüzden 2,5x yanlış.
3. **OWASP'ın "eşdeğer" Argon2 seçenekleri eşdeğer maliyette değil**; `m=7 MiB/t=5`, `m=46 MiB/t=1`'den 1,80x ucuz ve belirgin biçimde daha iyi ölçekleniyor.
4. **`spawn_blocking` + çekirdek-sayısı-kadar semafor** hem throughput'u hem p99'u aynı anda iyileştiriyor (p99'da 25x).
5. **Hash-zincirli denetim logu paralelliği sıfırlıyor** — 8 bağlantı ile 1 bağlantı aynı throughput'u veriyor. Merkle checkpoint'e geçin.
