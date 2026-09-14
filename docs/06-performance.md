# §6 — Performans mühendisliği

## 0. Metodoloji

Bu dosyada iki tür veri bulunur ve birbirine karıştırılmaz.

**Yayın verisi** üçüncü taraf kaynaktan gelir ve URL, tarih ile donanım bilgisiyle birlikte verilir.

**Ölçüm verisi** bu araştırma sırasında alınmıştır. Donanım Apple M4'tür (altı performans ve dört verimlilik çekirdeği, 16 GB, macOS), Rust sürümü 1.98.1'dir ve derleme ayarları `opt-level=3`, `lto="fat"`, `codegen-units=1`'dir. Postgres testleri PostgreSQL 18.6 (aarch64-alpine, Docker) üzerinde, `shared_buffers=2GB` ve `synchronous_commit=on` ile yapılmıştır.

M4 bir sunucu CPU'su değildir. Tek çekirdek performansı Graviton3 ve Graviton4'ten yüksektir; bellek bant genişliği ve çekirdek sayısı ise bir EPYC veya Xeon sunucudan çok düşüktür. Mutlak rakamlar değil, oranlar ve eğilimler taşınmalıdır. x86 sunucuda doğrulanması gereken yerler işaretlenmiştir.

Web arama bütçesi bu oturumda tükendiği için arama motoru üzerinden keşif yapılamamış, yalnızca bilinen otoriter URL'ler doğrudan çekilmiştir. Bu nedenle beşinci bölüm, yani dağıtık mimari, diğerlerinden zayıftır.

---

## 1. Mevcut IdP'lerin gerçek performans verileri

### 1.1 Keycloak resmî kapasite planlama rakamları

Kaynak: keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing, 8 Eylül 2026'da çekilmiştir.

| Metrik | Resmî rakam | Test edilen üst sınır |
|---|---|---|
| Parola ile login | 1 vCPU başına 15 login/sn | 300 login/sn |
| Client credential grant | 1 vCPU başına 120 grant/sn | 2.000/sn |
| Refresh token | 1 vCPU başına 120 istek/sn | 435/sn |
| Pod taban belleği (10.000 oturum önbellekli) | 1.250 MB | — |
| Heap payı | Bellek limitinin %70'i ve yaklaşık 300 MB heap dışı | — |
| Veritabanı (saniyede 100 login, logout ve refresh başına) | 1.400 write IOPS, 0,35-0,7 vCPU | — |
| CPU başlık payı önerisi | %150 fazladan | — |

**Referans donanım.** OpenShift 4.21 veya ROSA, `c7g.2xlarge` (Graviton3), Aurora PostgreSQL multi-AZ, 1 milyon kullanıcı ve 20.000 client, OpenJDK 21, parola hash'i Argon2 t=5 ve m=7 MiB.

### 1.2 Keycloak 26.4 benchmark'ı

Kaynak: keycloak.org/2025/10/keycloak-benchmark, Ekim 2025.

Bu, hedef olarak alınan 2.000 ile 10.000 rakamlarının kaynağıdır. Asıl hikâye ise maliyet tarafındadır.

| Senaryo | Pod | vCPU/pod | Toplam vCPU | Bellek/pod | Aurora | Aurora vCPU |
|---|---|---|---|---|---|---|
| Saniyede 500 login ve 2.500 refresh | 3 | 24 | 72 | 4 GB | db.r8g.2xlarge | 8 |
| Saniyede 1.000 login ve 5.000 refresh | 3 | 40 | 120 | 8 GB | db.r8g.4xlarge | 16 |
| Saniyede 2.000 login ve 10.000 refresh | 3 | 74 | 222 | 8 GB | db.r8g.16xlarge | 64 |

Ortam: OpenShift 4.17, `c8g.8xlarge` ve `c8g.24xlarge`, eu-west-1'de üç AZ, Aurora PostgreSQL 17.5, 100.000 kullanıcı, 20-50 adet `t4g.small` yük üreteci, `http-pool-max-threads=330`.

Bu tablo raporun en önemli tek verisidir. Aşılması gereken şey 2.000 login/sn değil, 286 vCPU ile 2.000 login/sn'dir; 222 vCPU uygulama, 64 vCPU veritabanı.

Resmî formül ölçümle tutarlıdır:

```
2.000 login / 15     = 133 vCPU
10.000 refresh / 120 =  83 vCPU
                     ─────────
                       216 vCPU   (ölçülen: 222)
```

Diğer bulgular şunlardır. Sürüm farkı gerçektir: 20 ms gidiş-dönüş gecikmesinde p99 yanıt süresi Keycloak 26.3'te 1.076 ms, 26.4'te 130 ms'dir, yani 8,3 kat iyileşme vardır; 0 ms'de 51 ms'den 47 ms'ye iner. Keycloak'ın gecikme davranışı ağ RTT'sine aşırı duyarlıydı. Önbellek boyutu veritabanını doğrudan sürmektedir: oturum önbelleği 10.000'den 200.000 girdiye çıkarıldığında Aurora tepe CPU'su %77,77'den %63,77'ye inmektedir. Test edilen azami toplam 12.000 istek/sn'dir ve dikey ölçekleme test edilen aralıkta neredeyse doğrusaldır. Keycloak ekibi kurulumun farklı bölgelere yayılmasını önermemektedir.

### 1.3 Keycloak'ın yapısal darboğazları

Kaynak: keycloak.org/server/caching.

| Darboğaz | Mekanizma | Sonuç |
|---|---|---|
| Yerel önbellek varsayılanı | `realms`, `users` ve `authorization` için 10.000 girdi; `keys` için 1.000 girdi ve bir saat TTL | 1 milyon kullanıcıda isabet oranı düşer ve her login veritabanına gider |
| Oturum önbelleği | Node başına 10.000 girdi | Aurora CPU'sundaki %77'den %63'e düşüşün sebebidir |
| `persistent-user-sessions` | Oturumlar varsayılan olarak veritabanındadır ve talep üzerine önbelleğe yüklenir | Login başına ek veritabanı yazma ve okuma |
| `work` önbelleği | Replicated cache ile invalidation mesajı yayını | Node sayısıyla mesaj trafiği artar |
| Session affinity | Üretimde mutlaka değerlendirilmesi önerilir | Yük dengeleme esnekliği kaybolur; node kaybında state transfer gerekir |

**Argus için çıkarım.** Keycloak'ın mimarisi durumun node'da bulunması, veritabanında da kopyasının olması ve node'ların birbirini invalidate etmesi üzerine kuruludur. Bu yapı cluster büyüdükçe süperdoğrusal maliyet üretir. Durumsuz ve tek doğruluk kaynaklı bir tasarım burada yapısal avantaj sağlar.

### 1.4 Diğer IdP'ler

| Ürün | Yayımlanan performans verisi | Değerlendirme |
|---|---|---|
| Zitadel | Zitadel'in kendisi yaklaşık 512 MB RAM ve bir çekirdeğin altında CPU kullanır. Veritabanı tarafında yaklaşık 100 istek/sn başına bir CPU çekirdeği ve çekirdek başına 4 GB RAM istenir. Üretim HA kurulumu için asgari üç node, dört çekirdek ve 16 GB önerilir. Dokümantasyon parola hash'lemede CPU'nun tepe yaptığını ve dört çekirdek önerildiğini belirtir (zitadel.com/docs/self-hosting/manage/production, 8 Eylül 2026'da çekilmiştir) | Bunlar ölçüm değil, doküman tavsiyesidir. Bağımsız benchmark doğrulanamamıştır. Event sourcing maliyetine dair sayısal veri doğrulanamamıştır. Veritabanına çekirdek başına 100 istek/sn yüklemesi Keycloak'tan farklı bir profil gösterir |
| Ory Hydra ve Kratos | `ory.sh/docs/hydra/benchmarks`, `ory.com/docs/hydra/benchmarks` ve `github.com/ory/hydra/.../BENCHMARKS.md` adreslerinin üçü de 404 vermektedir | Eskiden yayımlanan benchmark dokümanı kaldırılmıştır. Güncel sayısal veri doğrulanamamıştır |
| authentik | Yalnızca asgari gereksinim yayımlanmıştır: iki CPU çekirdeği ve 2 GB RAM (docs.goauthentik.io/install-config/install/docker-compose/) | Throughput verisi doğrulanamamıştır |
| Logto, SuperTokens, Casdoor, Better Auth | Bulunamamıştır | Doğrulanamamıştır |
| Bağımsız karşılaştırmalı benchmark | Bulunamamıştır | Doğrulanamamıştır. Hakemli bir çalışma bulunamamıştır. Bu bir fırsattır: alanda karşılaştırılabilir ve tekrarlanabilir bir IdP benchmark'ı yoktur |

### 1.5 Ory ve OpenAI ölçeği

Kaynak: ory.com/case-studies/openai, 6 Mart 2025'te yayımlanmış, 1 Eylül 2026'da güncellenmiştir.

Vaka çalışmasına göre sistem 900 milyon haftalık aktif kullanıcıya hizmet etmektedir; bu rakam Ekim 2025 tarihlidir ve Aralık 2024'te 400 milyondu. Kullanılan ürün Ory Hydra'dır ve self-hosted Ory Enterprise License ile çalışmaktadır. Veritabanı CockroachDB'dir. Performans için yalnızca nitel bir ifade verilmiştir ve sayı paylaşılmamıştır.

Throughput, gecikme ve donanım rakamı yayımlanmadığı için bu veri doğrulanamamıştır. Teknik olarak çıkarılabilecek tek şey, bu ölçekte CockroachDB'nin seçilmiş olması, yani çok bölgeli yatay ölçeklenen bir SQL katmanının tercih edilmesidir.

Auth0, Okta, Google ve Cloudflare Access için sayısal mimari yazısı bu oturumda bulunamamıştır.

---

## 2. Parola hash kapasite planlaması

Bu, sistemin en kritik darboğazıdır.

### 2.1 Standartlar: eşdeğer parametreler eşdeğer maliyette değil

OWASP Password Storage Cheat Sheet beş Argon2id yapılandırmasını eşdeğer güvenlikte sayar: `m=47104,t=1`, `m=19456,t=2`, `m=12288,t=3`, `m=9216,t=4` ve `m=7168,t=5`; hepsinde p=1'dir.

RFC 9106 §4 ayrı bir öneri seti verir. Birinci öneri t=1, p=4, m=2²¹ (2 GiB); ikinci öneri t=3, p=4, m=2¹⁶ (64 MiB) biçimindedir. RFC benchmark rakamı vermez, yalnızca x86 için optimize edildiğini belirtir.

**Kritik gözlem.** Keycloak `m=7168, t=5, p=1` kullanmaktadır; bu OWASP'ın en düşük bellekli eşdeğer seçeneğidir. Yani Keycloak zayıf parametre kullanmamakta, bilinçli olarak bellek ayak izini minimize etmektedir. Hedeflenen `m=19456, t=2` ile aynı güvenlik sınıfındadır ancak 2,7 kat az bellek tüketir.

### 2.2 Ölçüm: tek çekirdek Argon2id gecikmesi

Apple M4, tek thread, `argon2` crate 0.5.3 (RustCrypto) ve `phc-winner-argon2` C kütüphanesi:

| Parametre | Rust ms/hash | Rust hash/sn/çekirdek | C ms/hash | Toplam iş (MiB-geçiş) |
|---|---|---|---|---|
| m=46 MiB, t=1 | 16,08 | 62,2 | 16,02 | 46 |
| m=19 MiB, t=2 | 10,65 | 93,9 | 10,59 | 38 |
| m=12 MiB, t=3 | 9,19 | 108,8 | 9,93 | 36 |
| m=9 MiB, t=4 | 9,12 | 109,7 | 9,73 | 36 |
| m=7 MiB, t=5 (Keycloak) | 8,95 | 111,7 | 9,87 | 35 |
| m=64 MiB, t=3 (RFC 9106 ikinci öneri) | 66,11 | 15,1 | 68,92 | 192 |

**Birinci bulgu.** Eşdeğer seçenekler %80'e varan maliyet farkı taşımaktadır. `m=46,t=1` (16,08 ms) ile `m=7,t=5` (8,95 ms) arasında 1,80 kat fark vardır. OWASP'ın eşdeğerlik listesi güvenlik açısından doğru, performans açısından yanıltıcıdır. Yüksek bellek ve düşük geçiş kombinasyonu aynı güvenlik için daha fazla CPU harcar; bellek tahsis ve ilklendirme maliyeti geçişlerle amorti edilemez.

**İkinci bulgu.** RFC 9106'nın ikinci önerisi (m=64 MiB, t=3) 66 ms sürmektedir. Bu, çekirdek başına 15 login/sn demektir. RFC'nin birinci önerisi (2 GiB) bir IdP için tamamen kullanılamaz.

### 2.3 Ölçüm: bellek bant genişliği duvarı

Aynı iş, artan thread sayısıyla toplam hash/sn cinsinden ölçülmüştür.

m=19 MiB, t=2:

| Thread | hash/sn | Hızlanma | Verim |
|---|---|---|---|
| 1 | 99,0 | 1,00× | %100 |
| 2 | 161,5 | 1,66× | %83 |
| 4 | 268,8 | 2,76× | %69 |
| 6 | 317,9 | 3,26× | %54 |
| 8 | 342,5 | 3,51× | %44 |
| 10 | 391,9 | 4,02× | %40 |

m=7 MiB, t=5:

| Thread | hash/sn | Hızlanma | Verim |
|---|---|---|---|
| 1 | 109,2 | 1,00× | %100 |
| 2 | 215,2 | 2,03× | %102 |
| 4 | 370,9 | 3,50× | %87 |
| 6 | 413,4 | 3,90× | %65 |
| 8 | 437,7 | 4,13× | %52 |
| 10 | 539,3 | 5,09× | %51 |

C kütüphanesiyle desen aynıdır: 19 MiB'de dört thread %70, 7 MiB'de %81 verim vermektedir.

Bu tablo raporun ikinci en önemli verisidir. Yorumu üç maddededir.

Argon2 çekirdek sayısıyla ölçeklenmemektedir. On thread'de yalnızca 4,02 kat kazanç alınır. Bu, N çekirdeğin N kat hash/sn vereceği varsayımıyla yapılan her kapasite planını 2,5 kat yanlış kılar.

Düşük bellekli parametre belirgin biçimde daha iyi ölçeklenir. Dört thread'de m=7 MiB %87, m=19 MiB %69 verim verir. Sebep, 7 MiB'lik çalışma kümesinin büyük L2 ve L3 önbelleklerine kısmen sığması, 19 MiB'in sığmaması ve her erişimin DRAM'e inmesidir. Toplam bellek trafiği neredeyse aynı olduğu hâlde (35 ile 38 MiB-geçiş) ölçeklenmeyi konum belirlemektedir.

Metodolojik uyarı gereklidir: M4'te altı performans ve dört verimlilik çekirdeği vardır ve altı thread'in üstündeki düşüşün bir kısmı verimlilik çekirdeklerinin yavaşlığından kaynaklanır. Ancak dört thread karşılaştırması tamamen performans çekirdekleri üzerindedir ve orada bile %87 ile %69 farkı nettir. Etki gerçektir, yalnızca büyüklüğü x86 sunucuda doğrulanmalıdır.

### 2.4 Kapasite formülü ve bellek ayak izi

```
Eşzamanlı hash sayısı (Little yasası) = hedef_login/sn × hash_gecikmesi
Bellek ayak izi = eşzamanlı_hash × m
```

2.000 login/sn için:

| Parametre | Gecikme | Eşzamanlı hash | Bellek | M4 sınıfı çekirdek ihtiyacı |
|---|---|---|---|---|
| m=19 MiB, t=2 | 10,65 ms | 21,3 | 405 MiB | Yaklaşık 51 çekirdek; on çekirdekte 391,9 hash/sn |
| m=7 MiB, t=5 | 8,95 ms | 17,9 | 125 MiB | Yaklaşık 37 çekirdek; on çekirdekte 539,3 hash/sn |

**Bulgu: bellek darboğaz değildir.** 2.000 login/sn yalnızca yaklaşık 400 MiB eşzamanlı hash belleği ister. Argon2'nin RAM'i tükettiği yönündeki yaygın endişe bu ölçekte yersizdir; darboğaz CPU ve bellek bant genişliğidir, kapasite değildir. Bellek ancak sınırsız eşzamanlılığa izin verildiğinde sorun olur; kabul kontrolü için 6.2'ye bakınız.

### 2.5 Keycloak'ın CPU'su gerçekte nereye gidiyor

Keycloak dokümantasyonu CPU zamanının çoğunun kullanıcının verdiği parolayı hash'lemekle geçtiğini iddia eder. Kendi rakamları bunu desteklememektedir.

Resmî oran 1 vCPU başına 15 login/sn'dir, yani login başına 66,7 ms CPU. Aynı parametrede (m=7 MiB, t=5) ölçülen hash maliyeti 9-10 ms'dir. Hash payı yaklaşık %15'tir.

Yani login CPU'sunun yaklaşık %85'i parola hash'leme değildir; JVM, Quarkus ve JAX-RS katmanı, Infinispan, JPA ve Hibernate, veritabanı gidiş-dönüşleri ve serileştirmedir.

> **Uyarı.** M4 çekirdeği ile `c7g.2xlarge` (Graviton3) vCPU'su denk değildir; Graviton3'ün tek çekirdek performansı belirgin biçimde düşüktür. Graviton3'ün iki kat yavaş olduğu varsayılsa bile hash payı yaklaşık %30'da kalır. Bu bir tahmindir ve x86 veya ARM sunucuda doğrulanmalıdır, ancak yönü sağlamdır.

**Stratejik sonuç.** Keycloak'ı yenmenin yolu Argon2'yi hızlandırmak değildir. Argon2 kasıtlı olarak yavaştır ve hızlandırılamaz. Kazanç hash dışındaki %85'i ortadan kaldırmaktadır. Aynı Argon2 parametresiyle çekirdek başına 15 yerine 40-60 login/sn hedefi gerçekçidir; bu 3-4 katlık bir kazançtır ve tamamen overhead silme işidir.

### 2.6 SIMD ve implementasyon seçimi

Yaygın bir iddia yanlış çıkmıştır. RustCrypto/password-hashes #104 numaralı issue (29 Ocak 2021'de açılmış, hâlâ açık) `argon2` crate'inin optimize edilmemiş bir `ref.c` çevirisi olduğunu ve `opt.c` gerektiğini söyler. Ancak kaynak kodu incelendiğinde `argon2` 0.5.3'ün artık runtime AVX2 dispatch içerdiği görülmüştür:

```rust
// argon2-0.5.3/src/lib.rs:148
cpufeatures::new!(avx2_cpuid, "avx2");
// :463-470
#[target_feature(enable = "avx2")]
unsafe fn compress_avx2(rhs: &Block, lhs: &Block) -> Block { ... }
if self.cpu_feat_avx2.get() { return unsafe { compress_avx2(rhs, lhs) }; }
```

Issue metni güncel değildir. x86-64'te crate AVX2 yolunu kullanır. AVX-512 yolu yoktur.

Ölçümdeki C ile Rust eşitliği aldatıcıdır: `phc-winner-argon2` derlemesi optimizasyonsuz yapılmış ve `ref.c` kullanmıştır, çünkü `opt.c` yalnızca SSE2, SSSE3, XOP, AVX2 ve AVX512F destekler ve ARM NEON yolu yoktur. Dolayısıyla ARM'de her iki taraf da referans uygulamadır.

> **Doğrulanamayan konu.** x86-64 sunucuda C `opt.c` (AVX2 ve AVX-512) ile Rust crate'i arasındaki fark ölçülememiştir. Argus'un ilk performans işlerinden biri bu olmalıdır: hedef sunucuda `argon2` crate'i ile `libargon2` (opt.c, `-march=native`) karşılaştırması. Fark %20'yi geçerse FFI'ye geçmek gerekir.

### 2.7 Hash işini ayırma stratejileri

| Strateji | Değerlendirme |
|---|---|
| Sınırlı worker havuzu, aynı süreçte | Önerilen yaklaşımdır. 6.2'de ölçülmüştür: hem throughput'u hem p99'u iyileştirir ve karmaşıklığı en düşüktür |
| Ayrı hash mikroservisi | Ağ gidiş-dönüşü 0,2-1 ms'dir ve 9-10 ms'lik hash yanında önemsizdir. Gerçek fayda izolasyondur: hash yükü API katmanının tail latency'sini bozamaz ve ayrı ölçeklenir. Bedeli parolanın ağdan geçmesi (mTLS zorunludur) ve operasyonel karmaşıklıktır |
| GPU ve FPGA hızlandırma | Savunmacıya yaramaz. Argon2 zaten GPU'yu bellek bant genişliğinden boğmak için tasarlanmıştır. Savunmacı tarafta tek hash gecikmesi düşmez |
| Intel QAT ve donanım | Argon2 için QAT desteği doğrulanamamıştır |
| Kabul kontrolü, kuyruk ve yük atma | Zorunludur; 6.2'ye bakınız |

**Büyük servislerin yaklaşımı.** Bu oturumda Auth0, Okta, Dropbox, Facebook ve Discord mühendislik yazılarına erişilememiştir; dolayısıyla doğrulanamamıştır. Bilinen genel kalıp — bellekten aktarılmıştır ve doğrulanmamıştır — parola hash'inin pepper ile HSM veya KMS'te ikinci bir simetrik katmana sarılmasıdır; Dropbox'ın bcrypt ve AES yaklaşımı budur. Bu performansı değiştirmez, veritabanı sızıntısı senaryosunu değiştirir.

---

## 3. Token imzalama ve doğrulama

### 3.1 Ölçüm: ham imza performansı

Apple M4, tek çekirdek:

| İşlem | µs/işlem | işlem/sn/çekirdek |
|---|---|---|
| aws-lc-rs Ed25519 imzalama | 4,10 | 243.804 |
| ring Ed25519 imzalama | 7,30 | 137.050 |
| RustCrypto ed25519-dalek imzalama | 8,56 | 116.777 |
| ring Ed25519 doğrulama | 19,72 | 50.704 |
| aws-lc-rs Ed25519 doğrulama | 18,32 | 54.597 |
| RustCrypto ed25519-dalek doğrulama | 18,03 | 55.475 |
| ring ES256 (P-256) imzalama | 10,79 | 92.701 |
| aws-lc-rs ES256 imzalama | 11,05 | 90.483 |
| aws-lc-rs ES256 doğrulama | 27,30 | 36.632 |
| ring ES256 doğrulama | 28,52 | 35.069 |
| RustCrypto p256 imzalama (saf Rust) | 84,06 | 11.896 |
| RustCrypto p256 doğrulama (saf Rust) | 134,52 | 7.434 |
| RustCrypto RSA-2048 imzalama | 710,46 | 1.408 |
| RustCrypto RSA-2048 doğrulama | 88,80 | 11.262 |
| HMAC-SHA256 (HS256) | 0,66 | 1.522.689 |

Bulgular şunlardır.

Ed25519 her yönden ES256'yı yenmektedir: imzalamada 2,6 kat (aws-lc-rs ile), doğrulamada 1,5 kat hızlıdır. Ed25519 seçilir.

Saf Rust P-256 çok yavaştır: aws-lc-rs'e göre imzalamada 7,6 kat, doğrulamada 4,9 kat yavaştır. `p256` crate'i üretim yolunda kullanılmaz.

RSA-2048 imzalama 710 µs sürer; bu aws-lc-rs Ed25519'un 173 katıdır. RS256 varsayılan yapılmaz, yalnızca uyumluluk için tutulur.

İmzalama ile doğrulama aynı maliyette değildir. Ed25519'da doğrulama imzalamadan 4,5 kat pahalıdır (18,3 µs karşısında 4,1 µs). Bir IdP çoğunlukla imzalar ve bu ucuzdur; doğrulama maliyeti resource server'lara ve DPoP'a düşer.

HS256 27 kat ucuzdur ancak anahtar paylaşımı gerektirdiği için çok taraflı bir IdP'de kullanılamaz. Yalnızca dahili ve tek taraflı token'lar için uygundur.

### 3.2 Ölçüm: batch doğrulama

ed25519-dalek `verify_batch` ile:

| Batch boyutu | µs/imza | Tekile göre |
|---|---|---|
| 1 (tekil) | 18,03 | 1,00× |
| 8 | 10,08 | 1,79× |
| 64 | 8,63 | 2,09× |
| 256 | 7,48 | 2,41× |

Kazanç gerçektir ancak sınırlıdır. Bir IdP için pratik kullanımı dardır: batch doğrulama yalnızca hepsinin geçerli olup olmadığını söyler, bir imza bozuksa hangisinin bozuk olduğunu söylemez ve yeniden tekil doğrulama gerekir. Ayrıca istekleri batch'lemek gecikme ekler. Kullanılmaması önerilir, çünkü IdP'nin doğrulama yükü zaten düşüktür.

### 3.3 Ölçüm: JWT uçtan uca, kripto dışı maliyet

`jsonwebtoken` 9.3.1 (ring backend), 296 baytlık claims ve 534 baytlık token ile:

| İşlem | µs | işlem/sn |
|---|---|---|
| EdDSA JWT encode | 15,20 | 65.802 |
| EdDSA JWT decode | 21,03 | 47.545 |
| ES256 JWT encode | 18,52 | 53.997 |
| ES256 JWT decode | 29,41 | 33.997 |
| HS256 JWT encode | 0,74 | 1.352.506 |
| HS256 JWT decode | 1,27 | 786.579 |
| serde_json serialize | 0,22 | 4.553.250 |
| serde_json deserialize | 0,31 | 3.244.833 |
| base64url encode | 0,08 | 11.775.015 |
| base64url decode | 0,09 | 11.135.971 |

**Bulgu: JSON ve base64 pratikte bedavadır.** İkisi birlikte encode maliyetinin %2'sinden azdır. simd-json veya sonic-rs'e geçmenin JWT yolunda kazancı sıfıra yakındır. Maliyetin yaklaşık %95'i kriptodur.

### 3.4 Ölçüm: `jsonwebtoken` crate'inde 1,91 katlık kayıp

Ham `ring` Ed25519 imzalama 7,30 µs sürerken `jsonwebtoken::encode` 15,20 µs sürmektedir. Aradaki fark JSON ve base64 değildir; o toplam 0,3 µs'dir. Kaynağı koddadır:

```rust
// jsonwebtoken-9.3.1/src/crypto/eddsa.rs
pub fn sign(key: &[u8], message: &[u8]) -> Result<String> {
    let signing_key = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key)?;  // her imzada
    let out = signing_key.sign(message);
```

```rust
// crypto/ecdsa.rs — ES256 daha da maliyetli
    let rng = rand::SystemRandom::new();                        // her imzada
    let signing_key = signature::EcdsaKeyPair::from_pkcs8(alg, key, &rng)?;  // her imzada
```

Anahtar her imzalama çağrısında PKCS#8'den yeniden parse edilmektedir. Ölçüm sonuçları:

| | µs | işlem/sn |
|---|---|---|
| `jsonwebtoken::encode` | 15,01 | 66.623 |
| Elle yazılmış, önbellekli KeyPair | 7,84 | 127.570 |
| `Ed25519KeyPair::from_pkcs8` tek başına | 6,77 | 147.806 |
| `ring` sign, önbellekli anahtarla | 6,94 | 144.079 |

Hızlanma 1,91 kattır. Anahtar parse maliyeti (6,77 µs) imzanın kendisine (6,94 µs) neredeyse eşittir.

**Somut aksiyon.** Argus'ta JWT üretimi `jsonwebtoken` ile yapılmaz. Header'ı önceden base64'leyen ve `KeyPair`'i süreç ömrü boyunca önbellekte tutan yaklaşık 40 satırlık bir encoder yazılır. Kazanç maliyetsiz 1,9 kattır. Aynı hata birçok Rust servisinde bulunmaktadır.

### 3.5 Ölçüm: DPoP ve alternatifleri

| İşlem | µs | işlem/sn |
|---|---|---|
| JWK SHA-256 thumbprint (RFC 7638) | 0,21 | 4.795.069 |
| DPoP, yani EdDSA JWT decode ile thumbprint | 21,51 | 46.493 |
| Opak token: 32 bayt rastgele ve SHA-256 | 0,75 | 1.337.186 |

DPoP'un asıl maliyeti thumbprint değil (0,21 µs), ikinci bir imza doğrulamasıdır (19-21 µs). DPoP'lu her istek DPoP'suza göre yaklaşık 21 µs ek CPU ister. 10.000 istek/sn'de bu 0,21 çekirdektir ve kabul edilebilir.

Ancak gerçek DPoP maliyeti kriptoda değil, `jti` replay önbelleğindedir. Her proof'un `jti` değeri tekrar kullanımı engellemek için saklanmalıdır ve bu dağıtık, yazma ağırlıklı bir durumdur. Bu, beşinci bölümdeki iptal yayını problemiyle aynı sınıftadır ve asıl mühendislik burasıdır. mTLS-bound token (RFC 8705) alternatifi bu durumu ortadan kaldırır, çünkü bağlanma TLS katmanındadır; sayısal karşılaştırma doğrulanamamıştır.

Dikkat çekici bir nokta vardır: opak token (0,75 µs) JWT'den 20 kat ucuzdur. Introspection hızlı bir önbellekten yapılabiliyorsa opak token ile merkezî doğrulama, JWT'den CPU olarak daha ucuzdur. JWT'nin avantajı CPU değil, ağ gidiş-dönüşünden kaçınmaktır.

### 3.6 Post-quantum

ML-DSA (FIPS 204) imza boyutları ve hızlarına dair güvenilir ölçüm bu oturumda bulunamamıştır. Bilinen tek yapısal gerçek şudur: ML-DSA-44 imzası yaklaşık 2.420 bayt, Ed25519 imzası 64 bayttır. Bu, JWT boyutunu yaklaşık 40 kat büyütür ve 8 KB'lik HTTP header limitlerini zorlar. Argus'un tasarımında `alg` alanının ve anahtar rotasyon mekanizmasının bunu kaldırabilmesi gerekir; ancak bugün Ed25519 ile başlanmalıdır.

---
## 4. Postgres kimlik şeması ölçeklenmesi

Tüm ölçümler PostgreSQL 18.6 üzerinde, Docker (aarch64-alpine) ortamında, `shared_buffers=2GB`, `work_mem=64MB`, `synchronous_commit=on` ayarlarıyla ve sekiz eşzamanlı bağlantıyla alınmıştır.

### 4.1 Ölçüm: birincil anahtar, UUIDv4 ile UUIDv7

3.000.000 satır insert:

| | Süre | Heap | PK indeksi |
|---|---|---|---|
| UUIDv4 (`gen_random_uuid()`) | 9.366 ms | 219 MB | 122 MB |
| UUIDv7 (`uuidv7()`, PG18 yerleşik) | 5.599 ms | 219 MB | 90 MB |

UUIDv7 insert'te 1,67 kat hızlıdır ve indeksi %26 küçüktür. Sebep, UUIDv7'nin zaman sıralı olması ve B-tree'nin sağ ucuna sıralı yazmasıdır; sayfa bölünmesi az, önbellek isabeti yüksektir. UUIDv4 rastgeledir ve indeksin her yerine dağılır.

**Aksiyon.** Tüm tablolarda UUIDv7 kullanılır. PostgreSQL 18 `uuidv7()` fonksiyonunu yerleşik sunar ve ek eklenti gerekmez. Bu, 100 milyondan fazla satırda hem yazma throughput'u hem indeks bellek ayak izi açısından maliyetsiz bir kazançtır.

> **Güvenlik uyarısı.** UUIDv7 zaman damgası sızdırır. Kullanıcıya görünen tanımlayıcılarda kullanılmaz; dahili birincil anahtar olarak kullanılır ve dışa ayrı bir opak kimlik verilir.

### 4.2 Ölçüm: Row-Level Security'nin gerçek maliyeti

3 milyon satırlık `sess` tablosunda tekil oturum araması, pgbench ile sekiz bağlantı ve 12 saniye:

| Senaryo | tps | Ortalama gecikme | Maliyet |
|---|---|---|---|
| RLS yok, temel | 11.843,7 | 0,338 ms | — |
| RLS var, basit indekslenebilir policy | 11.324,2 | 0,353 ms | %4,4 |
| RLS var, `EXISTS` alt sorgulu policy | 9.641,1 | 0,415 ms | %18,6 |

Policy'ler şunlardır:

```sql
-- Ucuz: predicate doğrudan indekse itiliyor
CREATE POLICY p_tenant ON sess USING (tenant_id = current_setting('app.tenant')::uuid);
-- Pahalı: satır başına ek indeks probe'u
CREATE POLICY p_sub ON sess USING (EXISTS (
  SELECT 1 FROM memberships m WHERE m.user_id=sess.user_id AND m.tenant_id=sess.tenant_id));
```

Plan farkı belirleyicidir. Basit policy'de predicate Index Cond'a girer:

```
Index Cond: (tenant_id = (current_setting('app.tenant'::text))::uuid)
```

Alt sorgulu policy'de ise satır başına çalışan bir Filter'a dönüşür:

```
Filter: EXISTS(SubPlan 2)
  ->  Index Only Scan using memberships_pkey  (loops = her satır)
```

**Bulgu.** RLS'in yavaş olduğu yönündeki folklor yanlıştır; maliyeti tamamen policy'nin indekslenebilirliğine bağlıdır. Policy predicate'i tablonun lider indeks kolonuyla eşleşiyorsa maliyet %5 civarındadır ve kabul edilebilir. Policy alt sorgu veya JOIN içeriyorsa maliyet satır sayısıyla doğrusal büyür; tekil aramada %19, N satır dönen bir taramada N kat ek indeks probe'u demektir ve orada kullanılamaz hâle gelir.

**Aksiyon.** RLS Argus'ta kullanılır, ancak tek bir kuralla: her policy predicate'i tek bir indeksli kolon üzerinde eşitlik olmalıdır (`tenant_id = current_setting(...)`). Üyelik alt sorgusu gerekiyorsa üyelik isteğin başında bir kez çözülüp `SET LOCAL app.tenant` değerine yazılır ve policy'ye taşınmaz.

### 4.3 Ölçüm: `last_seen` güncellemesi

500.000 satırlık oturum tablosunda her istekte tek satır `UPDATE`, pgbench ile sekiz bağlantı ve 15 saniye:

| Varyant | tps | HOT oranı | WAL (toplam) | WAL/güncelleme |
|---|---|---|---|---|
| `last_seen` indeksli (logged) | 26.266 | %0,0 | 123 MB | 328 B |
| İndekssiz (logged, fillfactor 100) | 25.984 | %97,0 | 74 MB | 199 B |
| İndekssiz, fillfactor=70 | 27.856 | %100 | 73 MB | 183 B |
| UNLOGGED, fillfactor=70 | 109.484 | %100 | 62 MB | 38 B |
| Toplu: tek statement'ta 1.000 satır | Yaklaşık 208.800 satır/sn | — | — | — |

Her istekte `last_seen` güncellemenin kötü bir fikir olup olmadığı nasıl yapıldığına bağlıdır. Üç kural her şeyi değiştirmektedir.

Birincisi, `last_seen` kolonu indekslenmez. İndeks HOT update'i tamamen imkânsız kılar (%97'den %0'a) ve WAL'ı 1,8 kat artırır (183 B'den 328 B'ye). Aynı iş için yaklaşık iki katı disk ve replikasyon trafiği harcanır. Son beş dakikada aktif oturumlar sorgusu için `last_seen` indeksi istenmez; onun yerine nadiren değişen `expires_at` indekslenir.

İkincisi, `fillfactor=70` verilir. Bu %100 HOT ve yaklaşık %7 daha yüksek throughput sağlar. Bedeli %44 daha büyük heap'tir (80 MB'den 115 MB'ye) ve bu takas oturum tablosu için kesinlikle doğrudur.

Üçüncüsü, toplu yazma sekiz kat kazandırır. Tek statement'ta 1.000 satır 4,79 ms'de güncellenir (yaklaşık 208.800 satır/sn); tekil güncelleme 27.856/sn'de kalır.

**Ölçek hesabı.** 10.000 istek/sn'de her istekte `last_seen` güncellenirse indeksli varyantta 328 B × 10.000 = 3,28 MB/sn, yani günde 283 GB WAL üretilir. İndekssiz ve fillfactor=70 ile 183 B × 10.000 = 1,83 MB/sn, yani günde 158 GB olur. Uygulama içinde 10 saniyelik pencerede birleştirilip toplu yazılırsa yaklaşık %90 azalma sağlanır.

**Önerilen mimari.** `last_seen` her istekte veritabanına yazılmaz. Uygulama içinde veya Redis'te 10-30 saniyelik pencerede biriktirilir ve tek bir `UPDATE ... FROM (VALUES ...)` ile toplu yazılır. Doğruluk kaybı 30 saniyedir ve bir son görülme alanı için tamamen kabul edilebilirdir. Kazanç WAL'da yaklaşık 10 kat, tps'te yaklaşık sekiz kattır.

> **UNLOGGED tablo uyarısı.** 109.484 tps ile 3,9 kat kazanç cazip görünse de oturumlar için tehlikelidir: çökmede tablo boşalır ve tüm kullanıcılar çıkış yapar. Yalnızca gerçekten atılabilir durum için — rate limit sayaçları, geçici auth session'ları — düşünülür.

### 4.4 Ölçüm: hash zincirli denetim logu

pgbench ile 12 saniye ölçüm yapılmıştır.

> **Ölçüm statüsü: yeniden üretim bekliyor.** Donanım Apple M4 ve Docker PostgreSQL 18.6'dır, sekiz bağlantı kullanılmıştır. Aşağıdaki mutlak değerler Argus'un throughput'u değildir; çıplak insert ölçümüdür. Merkle, imza, uygulama mantığı ve ağ bulunmamaktadır. Bu bölümün başka yerlerinde bu sayının ürün throughput'u gibi kullanıldığı yerler düzeltilmiştir.

| Senaryo | tps | Ortalama gecikme |
|---|---|---|
| Düz append-only, zincirsiz, sekiz bağlantı | 22.440,8 | 0,356 ms |
| Hash zincirli, sekiz bağlantı | 5.898,1 | 1,356 ms |
| Hash zincirli, tek bağlantı | 5.873,0 | 0,170 ms |

Bu tablodaki asıl bulgu son iki satırın eşitliğidir. Sekiz bağlantı (5.898 tps) ile tek bağlantı (5.873 tps) aynı throughput'u vermektedir.

Hash zinciri paralelliği tamamen yok etmektedir. Her kayıt bir öncekinin hash'ine bağlı olduğu için işlem seri olmak zorundadır. Eşzamanlılık eklemek throughput'a hiçbir şey katmaz, yalnızca gecikmeyi 0,170 ms'den 1,356 ms'ye, yani sekiz kat artırır, çünkü bağlantılar kilit için sıraya girer.

Zincir maliyeti bu ölçüm koşullarında düz log'a göre 3,8 kat throughput kaybıdır.

> **Düzeltme (2. tur).** Burada önceden donanımdan bağımsız yaklaşık 5.900 olay/sn'lik bir tavan olduğu yazılıydı. Bu iddia hem fazla geniştir hem de aşağıdaki çözüm tablosunun zinciri bellekte tutup batch commit eden satırıyla çelişir. Savunulabilir ifade şudur: tek bir doğrusal zincirde ardışık zincir hash'lerinin hesaplanması arasında seri bağımlılık vardır. Payload hazırlama, bağımsız hash hesapları, batch yazma ve farklı zincirler paralel yürüyebilir; seri bağımlılık olay başına ayrı bir veritabanı transaction'ını zorunlu kılmaz. Ölçülen şey belirli bir uygulamadır — olay başına transaction ve her seferinde önceki hash'in okunması — yapısal bir tavan değildir.

| Yaklaşım | Mekanizma | Değerlendirme |
|---|---|---|
| Parçalı zincir (önerilen) | Her shard veya kiracı kendi zincirini tutar; zincirler arası seri bağımlılık yoktur | Shard sayısıyla ölçeklenir ancak doğrusal olmak zorunda değildir; ortak disk, WAL, checkpoint ve imza darboğazları paylaşılır, dolayısıyla N shard'ın N kat tps vereceği çıkarımı geçersizdir. Global sıralama kaybolur ancak denetim için genelde gerekmez |
| Checkpoint ve Merkle ağacı | Olaylar zincirsiz yazılır; periyodik olarak, örneğin saniyede bir, bir batch'in Merkle kökü zincire eklenir | Düz log hızıyla yazma ve kanıtlanabilirlik sağlar. Ölçüm etiketi §6 §4.4'tedir ve yeniden üretim beklemektedir; çıplak insert ölçümüdür, ürün throughput'u değildir. En iyi takastır |
| Certificate Transparency modeli | Merkle ağacı ve imzalı ağaç başlığı (STH) | Aynı fikrin olgunlaşmış hâlidir; Trillian ve Rekor referans alınabilir |
| Uygulama içi tek yazar | Zinciri bellekte tutup batch commit eder | Yazar tek nokta hatası hâline gelir |

**Aksiyon.** Olay başına zincir kurulmaz. Olaylar düz append-only yazılır ve yaklaşık saniyede bir batch'in Merkle kökü ayrı bir küçük checkpoint tablosuna zincirlenir. Kanıt gücü neredeyse aynıdır, throughput 3,8 kat yüksektir ve ölçeklenebilir.

### 4.5 LISTEN/NOTIFY'ın belgelenmiş sınırları

Kaynak: postgresql.org/docs/current/sql-notify.html.

| Sınır | Değer veya davranış |
|---|---|
| Payload | 8.000 bayttan küçük olmalıdır |
| Kuyruk boyutu | Standart kurulumda 8 GB (`max_notify_queue_pages`) |
| Kuyruk dolarsa | `NOTIFY` çağıran transaction commit aşamasında başarısız olur |
| Uzun transaction | `LISTEN` yapıp uzun transaction'a giren oturum kuyruk temizliğini engeller; %50 doluluğunda log uyarısı verilir |
| Teslimat | Yalnızca commit sonrasıdır; dinleyici transaction içindeyse ertelenir |
| İki fazlı commit | `NOTIFY` yapmış transaction prepare edilemez |
| İzleme | `pg_notification_queue_usage()` |

Kritik bir entegrasyon sorunu daha vardır: PgBouncer dokümantasyonuna göre transaction pooling modunda `LISTEN` desteklenmez; aynı kısıt SET ve RESET, PREPARE, WITH HOLD cursor ve session seviyesi advisory lock için de geçerlidir.

**Argus için sonuç.** LISTEN/NOTIFY iptal yayını için kullanılmaz. İki bağımsız sebep vardır. Birincisi PgBouncer transaction mode ile uyumsuz olmasıdır ve bağlantı ölçeklenmesi için transaction mode gerekecektir. İkincisi tek bir uzun transaction'ın tüm bildirim kuyruğunu tıkayabilmesi ve kuyruk dolduğunda yazma işlemlerinin commit aşamasında başarısız olmasıdır. Bu, iptal mekanizmasının veritabanının yazma yolunu düşürebilmesi demektir ve kabul edilemez bir hata modudur.

### 4.6 Bağlantı havuzlama

Belgelenmiş bilgi şudur: PgBouncer bağlantı başına yaklaşık 2 kB bellek kullanır. Transaction mode'da kırılan özellikler yukarıda listelenmiştir.

Keycloak'ın rehberine göre en iyi performans için initial, minimal ve maximum havuz boyutu eşit olmalıdır; gerekçe dinamik bağlantı açmanın stampede etkisi ve sunucu tarafı prepared statement önbelleğinin kaybıdır. PostgreSQL'de prepared statement'ın devreye girmesi için sorgunun en az beş kez çalışması gerekir. Sayısal bir havuz boyutu formülü verilmemektedir.

> **Doğrulanamayan konu.** Postgres'in belirli bir bağlantı sayısının üstünde çöktüğü eğrinin ölçülmüş hâli bu oturumda bulunamamıştır.

Yukarıdaki üç veri birleştiğinde net bir tasarım çıkar: sabit boyutlu uygulama içi havuz ile prepared statement kullanımı, transaction mode PgBouncer ile çelişir çünkü PREPARE desteklenmez. Ya PgBouncer atlanıp uygulama havuzunda sabit ve ölçülü sayıda bağlantı tutulur, ya da PgBouncer kullanılıp prepared statement'lardan vazgeçilir. İkisi birden alınamaz ve bu erken verilmesi gereken bir karardır.

### 4.7 Partitioning ve indeks stratejisi

Aşağıdaki noktalar yapısal olarak sağlamdır ancak sayısal doğrulama yapılmamıştır.

Oturum, denetim logu ve token tabloları zamana göre range partition edilir. Asıl kazanç sorgu değil silmedir: `DROP PARTITION` anında biterken `DELETE` milyonlarca satırda autovacuum kasırgası yaratır.

Partition sayısı sınırlı tutulur; haftalık veya aylık uygundur. Çok sayıda partition plan süresini artırır.

E-posta araması için `lower(email)` üzerinde functional unique index kullanılır; `citext` yerine bu tercih edilir, çünkü planı daha öngörülebilirdir.

Kapsayıcı indeks (`INCLUDE`) ile index-only scan hedeflenir. 4.2 ölçümlerinde `Heap Fetches: 0` görülmüştür ve doğru indekslemede tekil arama 0,3 ms'nin altında kalmaktadır.

---

## 5. Dağıtık mimari kararları

> **Bu bölüm raporun en zayıf bölümüdür.** Web arama bütçesi tükendiği için Bloom ve cuckoo filter'ın gerçek IdP kullanım örnekleri, dağıtık rate limiting benchmark'ları ve çok bölgeli kimlik replikasyonu ölçümleri bulunamamıştır. Aşağıdakiler belgelenmiş kısıtlardan çıkan mühendislik muhakemesidir, ölçüm değildir.

### 5.1 Oturum iptalinin yayılması

Belgelenmiş kısıtlardan çıkan tablo şudur:

| Yöntem | Gecikme | Ölçek | Doğrulanmış kısıt |
|---|---|---|---|
| Postgres LISTEN/NOTIFY | Düşük | Zayıf | 4.5: PgBouncer transaction mode ile çalışmaz; kuyruk dolarsa yazmalar başarısız olur |
| Keycloak'ın `work` cache'i, replicated invalidation | Düşük | Orta | 1.3: node sayısıyla mesaj trafiği artar ve session affinity gerekir |
| Harici pub/sub (Redis veya NATS) | Düşük | İyi | Ölçüm doğrulanamamıştır |
| Polling, kısa TTL ve periyodik çekme | TTL kadar | Çok iyi | — |

**Muhakeme.** Token TTL'ini kısa tutmak, örneğin 60-120 saniyelik access token, iptal yayınının çoğunu gereksiz kılar. Anında iptal gereksinimi genelde sanıldığından dardır ve yalnızca yüksek riskli olaylar için — parola değişimi, oturum sonlandırma — gereklidir. Bu olaylar seyrektir, dolayısıyla düşük hacimli bir pub/sub kanalı yeterlidir ve kaçırılan bir mesajın etkisi TTL ile sınırlı kalır.

Bloom veya cuckoo filter ile iptal listesi tutmakta yanlış pozitif, geçerli bir kullanıcıyı reddetmek anlamına gelir. Bu, fail-open mu fail-closed mu sorusunu doğurur ve güvenlik açısından tehlikelidir. Gerçek IdP'lerde kullanıldığına dair kanıt bulunamamıştır.

### 5.2 Rate limiting

Doğruluk ile performans arasındaki takas ölçülmüş veriyle doğrulanamamıştır. Yapısal not şudur: 4.3'te ölçülen UNLOGGED tablo performansı (109.484 tps, güncelleme başına 38 B WAL) rate limit sayaçları için Postgres'in makul bir seçenek olabileceğini göstermektedir; ancak sayaçlar için asıl doğru yer bellek içi bir yapı veya Redis'tir.

---

## 6. Rust'ta yüksek performans

### 6.1 Tokio varsayılanları

Kaynak: docs.rs/tokio/latest/tokio/runtime/struct.Builder.html.

| Ayar | Varsayılan |
|---|---|
| `worker_threads` | Sistemdeki çekirdek sayısı |
| `max_blocking_threads` | 512 |
| Blocking thread keep-alive | 10 saniye |

Dokümantasyon `spawn_blocking`'i dosya IO, DNS ve stdio için önerir; CPU yoğun iş için doğrudan rehberlik vermez ve bu limitin çok düşük ayarlanmamasını söyler. Argon2 gibi CPU yoğun bir iş için 512 varsayılanı fazlasıyla yanlıştır; aşağıda ölçülmüştür.

### 6.2 Ölçüm: Argon2 nereye konmalı

Argon2id m=19 MiB ve t=2 ile, 64 eşzamanlı login, sekiz Tokio worker ve beş saniyelik ölçüm. Sağlık ucu gecikmesi async runtime'ın duyarlılığını, yani küçük bir timer task'ının ne kadar geciktiğini ölçer.

| Senaryo | hash/sn | p50 (ms) | p99 (ms) | Azami (ms) |
|---|---|---|---|---|
| A: hash doğrudan async worker'da | 358,3 | 17,86 | 119,31 | 185,60 |
| B: `spawn_blocking`, sınırsız | 370,9 | 1,07 | 29,64 | 86,95 |
| C: `spawn_blocking` ve semafor=6 | 323,9 | 1,07 | 2,34 | 3,91 |
| D: `spawn_blocking` ve semafor=10 | 403,9 | 1,08 | 4,77 | 8,22 |
| E: `spawn_blocking` ve semafor=64 | 362,6 | 1,09 | 33,47 | 63,10 |

Bulgular şunlardır.

Async worker thread'inde hash'lemek runtime'ı çalışamaz hâle getirir. p50 sağlık gecikmesi 17,86 ms, p99 119 ms'dir. Üstelik throughput da daha iyi değildir (358'e karşı 404). Bu senaryonun ilk denemesinde `yield_now()` olmadan test tamamen kilitlenmiştir; 64 task sekiz worker'ı süresiz işgal etmiş ve runtime timer'ı hiç çalıştıramamıştır. Gerçek bir serviste bu, sağlık kontrollerinin başarısız olması ve pod'un yeniden başlatılması demektir.

`spawn_blocking` tek başına yetmemektedir. p50 16,7 kat düzelir (17,86 ms'den 1,07 ms'ye) ancak p99 hâlâ 29,64 ms'dir, çünkü 512 blocking thread çekirdekleri aşırı abone eder ve bellek bant genişliğini doyurur.

Sınırlı semafor hem throughput'u hem tail'i iyileştirmektedir. Semafor=10 en yüksek throughput'u (403,9 hash/sn) ve A senaryosuna göre p99'da 25 kat iyileşmeyi (119,31 ms'den 4,77 ms'ye) birlikte verir. Semafor=6 en iyi tail'i (p99 2,34 ms, azami 3,91 ms) biraz throughput karşılığında sunar.

Sınırsıza yakın semafor (64) geriye gider; p99 33,47 ms'dir. Daha fazla eşzamanlılığın daha fazla iş anlamına geldiği varsayımı burada yanlıştır.

**Kesin öneri.** Argon2 `spawn_blocking` üzerine konur ve eşzamanlılık çekirdek sayısı civarında, yani çekirdek sayısı artı eksi birkaç değerinde bir semaforla sınırlanır. Kuyruk için bir üst sınır ve zaman aşımı eklenir, aşıldığında 503 dönülür, yani yük atılır. Bu ayar maliyetsiz biçimde hem daha yüksek throughput hem 25 kat daha iyi p99 verir. Semafor değeri hedef donanımda kalibre edilir; optimum, bellek bant genişliği duvarının dibindedir (2.3).

### 6.3 Derleme optimizasyonları

Kaynak: github.com/zamazan4ik/awesome-pgo.

| Proje | PGO kazancı |
|---|---|
| ScyllaDB | Throughput'ta %50'ye varan artış, gecikmede %33 azalma |
| rustc | Derleme hızında yaklaşık %10 |
| Genel, özel yazışmalar | Tipik olarak %5-7, bazen %10 |

Depo, kazancın iş yüküne çok bağlı olduğunu ve %20-50 aralığının da görüldüğünü belirtir. Kendi ölçümümüz yoktur ve Argus için doğrulanmalıdır.

Ölçümlerin tamamı `opt-level=3`, `lto="fat"` ve `codegen-units=1` ile alınmıştır; bu ayarların ayrık katkısı ölçülmemiştir.

**Muhakeme.** Argus'un CPU profili ağırlıklı olarak Argon2 ve eğri kriptografisidir. Bunların ikisi de zaten elle optimize edilmiş, sıkı döngülü kodlardır ve PGO'nun bu kısımlara katkısı düşük olacaktır. PGO asıl kazancı HTTP, serileştirme ve yönlendirme katmanında verir; ancak 3.3'te görüldüğü gibi o katman zaten toplam maliyetin küçük bir yüzdesidir. PGO öncelik olmamalıdır.

### 6.4 Ölçülmeyen konular

| Konu | Durum |
|---|---|
| jemalloc, mimalloc ve snmalloc ile sistem malloc karşılaştırması | Doğrulanamamıştır; ölçülmemiş ve kaynak bulunamamıştır |
| `target-cpu=native` ayrık etkisi | Doğrulanamamıştır |
| TechEmpower güncel tur rakamları | Doğrulanamamıştır |
| rustls ile OpenSSL handshake/sn karşılaştırması | Doğrulanamamıştır |
| io_uring (tokio-uring, monoio, glommio) kazancı | Doğrulanamamıştır |
| `tracing` span maliyeti | Doğrulanamamıştır |

Bunların hepsi Argus'un kendi ortamında ölçülebilir; hiçbiri için literatüre güvenmek gerekmez.

---

## 7. Darboğaz sıralaması

Bir parola login'inin CPU bütçesi, M4 ölçümleriyle ve Argus benzeri yalın bir yığın varsayımıyla:

| # | Bileşen | Maliyet | Toplam içindeki pay |
|---|---|---|---|
| 1 | Argon2id (m=19 MiB, t=2) | 10.650 µs | Yaklaşık %97 |
| 2 | Postgres: kullanıcı arama ve oturum yazma, iki üç gidiş-dönüş | 200-400 µs | %2-3 |
| 3 | JWT üretimi, elle ve önbellekli anahtarla | 7,8 µs | %0,07 |
| 4 | JWT üretimi, `jsonwebtoken` ile | 15,0 µs | %0,14 |
| 5 | TLS, HTTP parse ve yönlendirme | Ölçülmemiştir | Küçük |
| 6 | JSON ve base64 | 0,3 µs | %0,003 |

Bir refresh token isteğinde:

| # | Bileşen | Maliyet |
|---|---|---|
| 1 | Postgres: token arama ve rotasyon yazma | 200-400 µs; baskın kalemdir |
| 2 | JWT doğrulama ve üretme | Yaklaşık 29 µs |
| 3 | DPoP proof doğrulaması, varsa | Ek 21,5 µs |

Sıralamanın anlamı şudur.

Login'de Argon2 mutlak baskındır (%97). Optimize edilemez, çünkü tasarımı gereği yavaştır. Yapılabilecek tek şey doğru parametreyi seçmek — m=7 MiB ve t=5, m=19 MiB ve t=2'den %16 ucuzdur ve %26 daha iyi ölçeklenir — ve doğru biçimde zamanlamaktır (6.2).

Refresh'te darboğaz veritabanıdır, kripto değildir. 10.000 refresh/sn hedefi bir Postgres yazma throughput'u problemidir. Keycloak'ın bunun için 83 vCPU harcaması (vCPU başına 120/sn) tamamen framework overhead'idir.

Kripto ve serileştirme gürültü seviyesindedir. Buraya mühendislik yatırmak boşa emektir; tek istisna 3.4'teki 1,91 katlık maliyetsiz kazançtır.

En büyük fırsat listedeki hiçbir satır değildir. Keycloak'ın login başına harcadığı 66,7 ms CPU'nun yaklaşık %85'ini oluşturan diğer her şey — JVM, ORM, Infinispan, katman geçişleri — asıl fırsattır. Argus'un rekabet avantajı buradadır: Argon2 hızlandırılamaz ama etrafındaki 56 ms 2 ms'ye indirilebilir.

---

## 8. Argus için kapasite hesabı ve mimari öneriler

### 8.1 Hedef

Keycloak'ın 2.000 login ve 10.000 refresh/sn senaryosunu yenmek hedeflenmektedir. Keycloak'ın maliyeti 222 uygulama vCPU'su ve 64 veritabanı vCPU'su, toplam 286 vCPU'dur.

Argus için alt sınır hesabı m=19 MiB ve t=2 ile, M4 ölçümleri temelinde yapılmıştır ve sunucu CPU'sunda doğrulanmalıdır.

```
Hash tarafı (kaçınılmaz fizik):
  10 çekirdekli düğümde ölçülen: 391,9 hash/sn
  2.000 login/sn → 2.000 / 39,2 hash/sn/çekirdek ≈ 51 çekirdek

  m=7 MiB/t=5 seçilirse: 10 çekirdekte 539,3 hash/sn
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
| Argus, m=19 MiB ve t=2 | Yaklaşık 51 | 0,1'den az | 405 MiB |
| Argus, m=7 MiB ve t=5 | Yaklaşık 37 | 0,1'den az | 125 MiB |
| Keycloak toplamı, ölçülen | 222 vCPU | — | Pod başına 8 GB, üç pod |

**Yorum.** Argon2 fiziği 37-51 çekirdek istemektedir. Keycloak 222 vCPU harcamaktadır. Aradaki 4-6 katlık fark tamamen framework overhead'idir ve Argus'un alabileceği paydır. Gerçekçi hedef 60-80 çekirdekte 2.000 login ve 10.000 refresh/sn'dir, yani Keycloak'ın yaklaşık üçte veya dörtte biri.

> **Uyarı.** Bu rakamlar M4 çekirdeği başınadır ve Graviton veya EPYC vCPU'suna doğrudan çevrilemez. Doğru okuma şudur: Argus'un hash dışı overhead'i Argon2 maliyetinin %10'unu geçmemelidir. Keycloak'ta bu oran yaklaşık %570'tir. Ölçülmesi gereken metrik budur, mutlak çekirdek sayısı değildir.

### 8.2 Somut mimari kararlar

**Parola hash'leme.**

1. `m=7168, t=5, p=1` seçilir, `m=19456, t=2` değil. OWASP ikisini eşdeğer sayar; ölçümde birincisi %16 daha ucuzdur, dört thread'de %87 ile %69 ölçeklenme farkı verir ve 2,7 kat az bellek kullanır. Keycloak'ın da seçtiği yapılandırma budur ve bu konuda haklıdır.
2. Hash `spawn_blocking` üzerinde ve çekirdek sayısı kadar semaforla çalıştırılır. Kuyruk üst sınırı, zaman aşımı ve 503 ile yük atma eklenir (6.2).
3. Hedef sunucuda `argon2` crate'i (AVX2 dispatch'li) ile `libargon2 opt.c` (`-march=native`, AVX-512) karşılaştırması yapılır. Bu tek ölçüm ilk haftada tamamlanmalıdır.
4. Parametreler veritabanında kayıt başına saklanır (algoritma ile m, t ve p), böylece geriye dönük migration mümkün olur.

**Token.**

5. Ed25519 (EdDSA) varsayılan olur. ES256'dan imzalamada 2,6 kat, doğrulamada 1,5 kat hızlıdır. RS256 yalnızca uyumluluk için tutulur; 173 kat yavaştır.
6. `jsonwebtoken` kullanılmaz; kendi encoder'ımız yazılır, `KeyPair` önbellekte tutulur ve header önceden base64'lenir. Kazanç maliyetsiz 1,91 kattır.
7. `aws-lc-rs` tercih edilir; Ed25519 imzalamada `ring`'den 1,78 kat hızlıdır. Saf Rust `p256` ve `rsa` crate'leri üretim yolundan çıkarılır; 4,9-7,6 kat yavaştırlar.
8. Batch doğrulama kullanılmaz. 2,41 katlık kazanç gerçektir ancak hata izolasyonu kaybı ve gecikme eklemesi buna değmez.

**Postgres.**

9. Her yerde UUIDv7 kullanılır; PG18 `uuidv7()` fonksiyonunu yerleşik sunar. Insert 1,67 kat hızlı, indeks %26 küçüktür. Dışa açık kimlikler için ayrı bir opak tanımlayıcı verilir.
10. `last_seen` indekslenmez; indeks HOT oranını %97'den %0'a düşürür ve WAL'ı 1,8 kat artırır. Oturum tablosuna `fillfactor=70` verilir ve %100 HOT elde edilir.
11. `last_seen` her istekte yazılmaz; 10-30 saniyelik pencerede birleştirilip toplu `UPDATE` yapılır. Kazanç throughput'ta sekiz kat, WAL'da yaklaşık 10 kattır.
12. RLS kullanılır ancak her policy tek indeksli kolonda eşitlik olur; maliyeti %4,4'tür. Alt sorgulu policy yazılmaz; maliyeti %18,6'dır ve satır sayısıyla büyür.
13. Denetim logu olay başına zincirlenmez. Ölçülen koşullarda 3,8 kat throughput kaybı vardır; tek doğrusal zincirde ardışık zincir hash'leri arasında seri bağımlılık bulunur. Sayı ölçüme özgüdür, evrensel bir tavan değildir (§6 §4.4). Düz append-only yazılır ve saniyede bir Merkle checkpoint zincirlenir.
14. LISTEN/NOTIFY iptal yayını için kullanılmaz; PgBouncer transaction mode'da çalışmaz ve dolu kuyruk yazmaları commit aşamasında düşürür.
15. Erken karar verilir: PgBouncer transaction mode (prepared statement yok) veya uygulama içi sabit havuz (prepared statement var). İkisi birden olmaz.
16. Oturum, denetim ve token tabloları zamana göre partition edilir; asıl kazanç `DROP PARTITION`'dır.

**Ölçüm disiplini.**

17. Tek anlamlı metrik login başına toplam CPU mikrosaniyesinin Argon2 CPU mikrosaniyesine oranıdır. Hedef 1,10'un altıdır; Keycloak'ta bu oran yaklaşık 6,7'dir.
18. Kapasite planında çekirdek sayısıyla doğrusal ölçeklenme varsayılmaz; on thread'de gerçek kazanç m=19 MiB'de 4,02 kat, m=7 MiB'de 5,09 kattır.

---

## 9. Doğrulanamayanlar

Rakam uydurulmamıştır. Aşağıdakiler bulunamamış veya ölçülememiştir.

| Konu | Durum |
|---|---|
| Ory Hydra ve Kratos güncel benchmark'ı | Resmî sayfalar 404 vermektedir; veri kaldırılmıştır |
| Ory ve OpenAI throughput, gecikme ve donanım verisi | Yalnızca nitel bir pazarlama ifadesi mevcuttur |
| Zitadel bağımsız benchmark'ı ve event sourcing maliyeti | Yalnızca doküman tavsiyesi vardır, ölçüm yoktur |
| authentik, Logto, SuperTokens ve Casdoor throughput'u | Hiç yayımlanmamıştır |
| Bağımsız karşılaştırmalı IdP benchmark'ı | Bulunamamıştır; alanda böyle bir çalışma görünmemektedir |
| Auth0, Okta, Google ve Cloudflare mimari yazıları | Erişilememiştir |
| x86-64'te Argon2 AVX2 ve AVX-512 ile Rust crate'i farkı | ARM'de ölçülemez; Argus ekibi ölçmelidir |
| Argon2 için Intel QAT ve donanım hızlandırma | Kanıt bulunmamaktadır |
| Bloom ve cuckoo filter ile iptal listesinin gerçek kullanımı | Örnek bulunamamıştır |
| Dağıtık rate limiting doğruluk ve performans ölçümleri | Bulunamamıştır |
| Çok bölgeli kimlik replikasyonu (CockroachDB, Vitess) ölçümleri | Bulunamamıştır |
| Allocator, PGO'nun ayrık etkisi, rustls, io_uring, TechEmpower ve tracing maliyeti | Ölçülmemiş ve kaynak bulunamamıştır |
| ML-DSA imza hız ölçümleri | Bulunamamıştır |
| Postgres'in bağlantı sayısına göre çökme eğrisinin ölçümü | Bulunamamıştır |

---

## 10. Kaynaklar

- Keycloak, Concepts for sizing CPU and memory resources — keycloak.org/high-availability/multi-cluster/concepts-memory-and-cpu-sizing (8 Eylül 2026'da çekilmiştir)
- Keycloak Performance Benchmarks: A Deep Dive into Scaling and Sizing (26.4) — keycloak.org/2025/10/keycloak-benchmark (Ekim 2025)
- Keycloak, Configuring distributed caches — keycloak.org/server/caching
- Keycloak, Concepts for database connection pools — keycloak.org/high-availability/multi-cluster/concepts-database-connections
- OWASP Password Storage Cheat Sheet — cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 9106, Argon2 — rfc-editor.org/rfc/rfc9106.html
- P-H-C/phc-winner-argon2 — github.com/P-H-C/phc-winner-argon2
- RustCrypto/password-hashes #104, argon2: optimized implementation — github.com/RustCrypto/password-hashes/issues/104 (açık, 29 Ocak 2021)
- ZITADEL, Production setup — zitadel.com/docs/self-hosting/manage/production
- Ory, OpenAI case study — ory.com/case-studies/openai (6 Mart 2025, güncelleme 1 Eylül 2026)
- authentik, Docker Compose installation — docs.goauthentik.io/install-config/install/docker-compose/
- PostgreSQL, NOTIFY — postgresql.org/docs/current/sql-notify.html
- PgBouncer, Features — pgbouncer.org/features.html
- Tokio, runtime::Builder — docs.rs/tokio/latest/tokio/runtime/struct.Builder.html
- zamazan4ik/awesome-pgo — github.com/zamazan4ik/awesome-pgo
- MojoAuth, The Cost of Crypto: CPU Bottlenecks in Password Hashing — mojoauth.com/blog/password-hashing-performance-cpu-bottlenecks-high-traffic (22 Haziran 2026); bcrypt cost 12 yaklaşık 249 ms, AWS c7i.xlarge

---

## Özet: en önemli beş bulgu

1. Keycloak'ın 2.000 login/sn'i 286 vCPU'ya mal olmaktadır ve bunun yaklaşık %85'i parola hash'leme değil framework overhead'idir. Rekabet alanı burasıdır.
2. Argon2 çekirdek sayısıyla ölçeklenmemektedir; on thread'de kazanç 4,02 kattır. Kapasite planlarının çoğu bu yüzden 2,5 kat yanlıştır.
3. OWASP'ın eşdeğer saydığı Argon2 seçenekleri eşdeğer maliyette değildir; `m=7 MiB` ve `t=5`, `m=46 MiB` ve `t=1`'den 1,80 kat ucuzdur ve belirgin biçimde daha iyi ölçeklenir.
4. `spawn_blocking` ile çekirdek sayısı kadar semafor hem throughput'u hem p99'u aynı anda iyileştirmektedir; p99'da 25 kat kazanç vardır.
5. Hash zincirli denetim logu paralelliği sıfırlamaktadır; sekiz bağlantı ile tek bağlantı aynı throughput'u vermektedir. Merkle checkpoint'e geçilmelidir.
