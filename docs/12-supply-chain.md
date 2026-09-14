# §12 — Yazılım tedarik zinciri güvenliği

Bu bölüm önceden ARGUS.md içindeydi; numaralandırma korunmuştur ve dosya içindeki §X referansları aynı anlamdadır.

## 0. Metodoloji ve dürüstlük notu

Bu raporda üç tip veri vardır ve ayırt edilerek okunmalıdır. Ölçüm olarak işaretlenenler bu oturumda kendi makinede birebir ölçülmüştür (rustc 1.98.1, cargo 1.98.1, aarch64-apple-darwin) ve tekrarlanabilirdir. Birincil olarak işaretlenenler resmî kaynaktan doğrulanmıştır: rust-lang.org, mozilla.github.io, slsa.dev ve Avrupa Komisyonu. Doğrulanamadı olarak işaretlenenler bulunmuş ancak teyit edilememiştir.

> **Yanlış bilgi tuzağı.** Arama sonuçlarında çıkan safeguard.sh, lightsquares.dev ve geekwala.com gibi siteler cargo-vet hakkında çok spesifik rakamlar vermektedir; örneğin Mozilla ile Google'ın ortak audit havuzunu 14.140 crate ve 58.900 crate sürümüne çıkardığı iddiası. Bu rakamlar doğrudan kaynaktan kontrol edilmiş ve gerçek olmadıkları görülmüştür. Beş büyük audit seti klonlanıp sayılmıştır ve gerçek rakamlar aşağıdadır; yaklaşık 1.815 crate. Bu siteler AI üretimi SEO içeriğidir; Argus'un tehdit modelinde dil modeline yanlış güvenlik verisi besleme diye bir madde açılması önerilir.

**Kapsam sınırı.** Oturumun web arama kotası (200 arama) dolmuştur; son bölümlerde yalnızca doğrudan URL çekimi kullanılabilmiştir. Bu yüzden cargo-crev'in güncel inceleme sayısı ve bazı 2026 haberleri eksik kalmıştır ve açıkça işaretlenmiştir.

---

## A. Bağımlılık denetim araçları

### A.1 Araç olgunluk tablosu

crates.io API'sinden 8 Eylül 2026'da çekilmiş gerçek veridir.

| Araç | Sürüm | Son güncelleme | Toplam indirme | Son 90 gün | Yorum |
|---|---|---|---|---|---|
| `cargo-audit` | 0.22.2 | 5 Haziran 2026 | 11.544.186 | 3.268.469 | Fiilî standarttır |
| `rustsec` (kütüphane) | 0.33.0 | 5 Haziran 2026 | 12.726.593 | 2.918.169 | cargo-audit ile cargo-deny'nin motorudur |
| `cargo-deny` | 0.20.2 | 9 Temmuz 2026 | 5.547.620 | 1.550.032 | Politika kapısıdır |
| `cargo-cyclonedx` | 0.5.9 | 19 Mart 2026 | 1.686.501 | 747.740 | SBOM lideridir |
| `cargo-machete` | 0.9.2 | 15 Nisan 2026 | 2.821.321 | 508.102 | Kullanılmayan bağımlılık bulur |
| `cargo-auditable` | 0.7.5 | 28 Haziran 2026 | 991.221 | 249.877 | Binary'e SBOM gömer |
| `cargo-about` | 0.9.2 | 18 Ağustos 2026 | 1.154.564 | 236.356 | Lisans raporu üretir |
| `cargo-udeps` | 0.1.61 | 29 Nisan 2026 | 1.455.555 | 137.735 | nightly gerektirir |
| `cargo-vet` | 0.10.2 | 13 Ocak 2026 | 619.642 | 98.004 | Yavaştır ancak canlıdır |
| `cargo-outdated` | 0.19.0 | 14 Nisan 2026 | 968.679 | 69.111 | — |
| `cargo-geiger` | 0.13.0 | 31 Ağustos 2025 | 233.931 | 51.010 | Bakımı yavaşlamıştır |
| `cargo-sbom` | 0.10.0 | 17 Haziran 2025 | 225.224 | 56.461 | SPDX ile CycloneDX üretir |
| `cargo-supply-chain` | 0.3.7 | 5 Şubat 2026 | 70.894 | 4.244 | Niştir |
| `cargo-crev` | 0.27.1 | 12 Nisan 2026 | 112.638 | 1.380 | Fiilen ölüdür |
| `cargo-spdx` | 0.1.0 | 10 Mayıs 2022 | 2.115 | 22 | Terk edilmiştir |

En çarpıcı sonuç şudur: cargo-crev'in son 90 günde 1.380 indirmesi vardır, cargo-audit'in 3.268.469. Yani yaklaşık 2400 kat fark vardır ve cargo-crev fiilen ölü bir teknolojidir.

### A.2 cargo-vet ve nasıl çalıştığı

**Yerleşik kriterler.** İki yerleşik kriter vardır ve tam metinleri şöyledir.

`safe-to-run`: "This crate can be compiled, run, and tested on a local workstation or in controlled automation without surprising consequences, such as: Reading or writing data from sensitive or unrelated parts of the filesystem; Installing software or reconfiguring the device; Connecting to untrusted network endpoints; Misuse of system resources (e.g. cryptocurrency mining)."

`safe-to-deploy`: "This crate will not introduce a serious security vulnerability to production software exposed to untrusted input." Devamı kritiktir: denetçinin tüm crate'in mantığını incelemesi gerekmez, ancak tüm `unsafe` bloklarını ve powerful imports kullanımını tam olarak muhakeme edebilecek kadar incelemesi gerekir. Ayrıca "For crates which generate deployed code (e.g. build dependencies or procedural macros), reasonable usage of the crate should output code which meets the above criteria" der; yani `build.rs` ve proc-macro'lar da kapsam içindedir.

`safe-to-deploy`, `safe-to-run`'ı kapsar.

**Özel kriterler.** `audits.toml` içinde kendi kriteriniz tanımlanır:

```toml
[criteria.crypto-reviewed]
description = '''
The cryptographic code in this crate has been reviewed for correctness by a
member of a designated set of cryptography experts within the project.
'''
```

Kritik tuzak şudur: audit'ler repolar arası birleştirilirken her repodaki `description` metni birebir aynı olmak zorundadır, yoksa birleştirme başarısız olur.

> **Argus için.** `crypto-reviewed`, `constant-time` (yan kanal), `no-network-egress` (build script ağa çıkmasın) ve `oidc-spec-conformant` gibi özel kriterler tanımlanır. Bu, en güvenli IdP iddiasının denetlenebilir hâle gelmesidir.

**Audit paylaşımı ve import mekanizması.** `config.toml` içinde `imports` direktifleriyle başka organizasyonların `audits.toml` URL'leri eklenir; cargo-vet çeker ve `imports.lock` dosyasına yazar. Mekanizma geçişli değildir: "you can't directly import someone else's list of imports". Güven ilişkisi doğrudandır ve bu kasıtlı bir tasarım kararıdır. Merkezî kayıt `https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml` adresindedir.

**Kayıttaki organizasyonlar.** 8 Eylül 2026 tarihli çekimde dokuz organizasyonun tam listesi şudur:

| Org | audits.toml URL |
|---|---|
| `actix` | `github.com/actix/supply-chain` |
| `ariel-os` | `github.com/ariel-os/ariel-os` |
| `bytecode-alliance` | `github.com/bytecodealliance/wasmtime` |
| `embark-studios` | `github.com/EmbarkStudios/rust-ecosystem` |
| `fermyon` | `github.com/fermyon/spin` |
| `google` | `github.com/google/supply-chain` |
| `isrg` | `github.com/divviup/libprio-rs`, Let's Encrypt'in kurumudur |
| `mozilla` | `github.com/mozilla/supply-chain` |
| `zcash` | `github.com/zcash/rust-ecosystem` |

ChromeOS ayrı bir giriş değildir, Google'ın seti altındadır. Fuchsia da ayrı değildir.

**Audit setlerinin gerçek büyüklüğü.** Beş büyük set 8 Eylül 2026'da klonlanıp `audits.toml` dosyaları ayrıştırılmıştır.

| Organizasyon | Denetlenmiş crate | Wildcard | Trusted | Toplam farklı crate |
|---|---|---|---|---|
| google | 948 | 0 | 0 | 948 |
| mozilla | 586 | 67 | 162 | 691 |
| bytecode-alliance | 298 | 118 | 153 | 476 |
| zcash | 376 | 0 | 62 | 416 |
| embark | 98 | 45 | 26 | 169 |
| Birleşim | | | | 1.815 farklı crate |

Toplam audit girdisi 5.576'dır. Bu, SEO bloglarının iddia ettiği 14.140 crate ve 58.900 sürümün yaklaşık sekizde biridir; planlama buna göre yapılmalıdır.

**Argus'un bağımlılık grafiğinin ne kadarı zaten denetlenmiştir.** Bu, raporun en operasyonel sayısıdır. Tipik bir IdP yığını kurulup (axum, tokio, sqlx, jsonwebtoken, argon2, webauthn-rs, redis, reqwest) beş audit setiyle kesiştirilmiştir.

Crate adı düzeyinde, yani aşırı iyimser üst sınır:

| Yığın | Bağımlılık | Herhangi bir audit setinde | `safe-to-deploy` ile | Hiç denetlenmemiş |
|---|---|---|---|---|
| Tam yığın | 231 farklı crate | 194, yani %84,0 | 186, yani %80,5 | 37 |
| Minimal yığın | 162 farklı crate | 148, yani %91,4 | 143, yani %88,3 | 14 |

Sürüm-tam düzeyinde, yani delta zincirlerini saymayan alt sınır, minimal yığının 170 crate sürümü için şöyledir. Tam sürüm eşleşen audit kaydı 39'dur (%22,9). Wildcard veya trusted yayıncı güvenceli olan 48'dir (%28,2). Toplam kapsanan 87'dir (%51,2) ve kalan 83 crate sürümü kayıtsızdır.

Gerçek cargo-vet kapsamı bu ikisinin arasındadır, yani yaklaşık %51 ile %91 arası, çünkü `0.4.1 -> 0.4.2` gibi delta audit zincirleri sürüm-tam eşleşmede görünmez ancak gerçekte kapsar. Kesin sayı için `cargo vet` çalıştırmak gerekir.

Hiç denetlenmemiş olanlar Argus için tam da en kritik olanlardır:

```
argon2, sqlx, sqlx-core, sqlx-macros, sqlx-macros-core, sqlx-postgres,
blake2, atoi, dotenvy, event-listener, futures-intrusive,
unicode-properties, untrusted
```

Tam yığında ayrıca `asn1-rs`, `der-parser`, `oid-registry`, `pem`, `simple_asn1`, `base64urlsafedata`, `redis`, `reqwest`, `arc-swap`, `axum-macros`, `rusticata-macros` ve `combine` vardır.

> **Yorum.** Parola hash'leme (`argon2`), veritabanı katmanı (`sqlx` ailesi) ile ASN.1 ve sertifika ayrıştırma (`asn1-rs`, `der-parser`, `simple_asn1`), yani bir IdP'nin en yüksek riskli üç bileşeni, hiçbir büyük organizasyon tarafından denetlenmemiştir. ASN.1 ayrıştırıcıları tarihsel olarak bellek güvenliği ve parser differential açıklarının klasik yuvasıdır. Argus'un ilk elle denetim bütçesi buraya gitmelidir.

**Wildcard audit ve trusted publisher.** Bir wildcard audit, belirli bir hesabın yayımladığı herhangi bir sürümün kriteri karşılayacağını sertifikalar; yani kodu değil, yayımcının sürüm çıkarma sürecinin bütünlüğünü onaylarsınız. Alanları `user-id` (crates.io kullanıcı kimliği, zorunludur), `start` ile `end` (UTC; `end` en fazla bir yıl ileri olabilir), `criteria`, `who`, `renew` (bool) ve `notes`'tur. Komutları `cargo vet certify --wildcard` (varsayılan bir yıl), `cargo vet renew` ve `cargo vet renew --expiring`'dir (altı hafta içinde dolacakları yeniler).

> **Risk uyarısı.** Ağustos 2026'daki `arrayref` saldırısı (F bölümüne bakınız) tam olarak wildcard audit modelinin kırıldığı senaryodur: yayımcı kötü niyetli değildi, kimlik bilgileri ve bilgisayarı ele geçirildi. Bir wildcard audit o saldırıyı durdurmazdı. Wildcard'lar yalnızca Trusted Publishing kullanan ve iki kişi onayı olan projeler için verilir.

**cargo-vet bakım durumu, 2026.** GitHub'daki son release v0.10.0 ve 3 Ekim 2024 tarihlidir. crates.io'daki son yayın 0.10.2 ve 13 Ocak 2026'dır; yayımlayan Nika Layzell'dir. Son 90 günde 98.004 indirme almıştır. Değerlendirme şudur: terk edilmemiştir ancak hızı belirgin şekilde düşmüştür, yaklaşık 15 ayda bir yama sürümü gelmektedir. Mozilla içinde hâlâ kullanılmakta ve `audits.toml` aktif güncellenmektedir. Argus için kullanılabilir, ancak araç üstünde bir bağımlılık riski olarak modellenmelidir; cargo-vet yarın dursa `audits.toml` verisi hâlâ okunabilir TOML'dur ve kaybolmaz.

### A.3 cargo-crev ve neden tutmadığı

**Model.** Dağıtık ve kriptografik olarak imzalanmış proof repoları ile web-of-trust kullanır. `crev` çekirdeği dil bağımsızdır, `cargo-crev` Rust uyarlamasıdır.

**Benimsenme.** Son 90 günde 1.380 indirme almıştır, toplam 112.638'dir. Depo yaklaşık 2,2 bin yıldızlıdır.

**Ek kanıt.** 8 Eylül 2026'da `https://web.crev.dev/rust-reviews/` ve `.../reviewers/` adreslerinin ikisi de HTTP 502 Bad Gateway döndürmüştür; ekosistemin merkezî keşif arayüzü çalışmamaktadır. Güncel inceleme sayısı bu yüzden doğrulanamamıştır.

**cargo-vet neden kazandı.** Mozilla'nın dev-platform duyurusundaki gerekçe şudur: audit'ler ayrı bir anahtar seti ve web-of-trust yerine, deponun mevcut erişim kontrollerine tabi olarak repoda saklanır. Bu üç şeyi çözer. Anahtar yönetimi yoktur, çünkü GitHub PR incelemesi zaten kimlik doğrulamasıdır. Güven kararı bireysel değil örgütseldir: "Google'a güveniyorum" denir, "kripto-twitter'da tanıdığım 12 kişiye güveniyorum" denmez. CI'ya sokmak tek satırdır: `cargo vet --locked`.

Web-of-trust'ın sosyal ölçekleme sorunu vardır: kime ve hangi derinlikte güvenileceğine dair karar yükü kullanıcıda kalır ve bu karar denetlenebilir veya kurumsallaştırılabilir değildir.

> **Argus kararı.** cargo-crev kullanılmaz; ölü teknolojidir.

### A.4 cargo-deny, zorunlu politika kapısı

Dört bağımsız kontrol vardır: advisories, bans, licenses ve sources.

`deny.toml` üst düzey bölümleri `[graph]`, `[advisories]`, `[bans]`, `[licenses]`, `[sources]` ve `[output]`'tur.

`[graph]` özellikle önemlidir: hedef platforma ve feature'lara göre filtreleyerek gerçekten derlediğiniz grafiği değerlendirmenizi sağlar; aksi hâlde Windows'a özgü bağımlılıklar için gereksiz alarm alınır.

**Argus için önerilen `deny.toml`.**

```toml
[graph]
targets = [
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
]
all-features = false

[advisories]
# unmaintained: sadece workspace ağacı için (transitive gürültüyü keser)
unmaintained = "workspace"
unsound = "all"
yanked = "deny"
ignore = []          # BOŞ TUTUN. Her istisna gerekçeli PR ile gelsin.

[licenses]
confidence-threshold = 0.93
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
         "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
# GPL/AGPL bir IdP ürününde lisans bulaşması riskidir -> allow listesinde YOK.

[bans]
multiple-versions = "warn"
wildcards = "deny"           # Cargo.toml'da "*" sürüm yasak
deny = [
  { name = "openssl-sys" },  # native OpenSSL: rustls kullanın (bkz. B.4)
  { name = "openssl" },
  { name = "git2" },
  { name = "time", version = "<0.2" },
]
# Aynı crate'in birden çok sürümüne izin verilen istisnalar:
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []               # BOŞ: git bağımlılığı yasak (checksum'suz koddur)
```

`[sources]` en az bilinen ancak Argus için en kritik kontroldür: `allow-git = []` ile hiçbir bağımlılığın doğrudan git'ten, yani checksum'suz, yanklanamaz ve mirror'lanamaz bir kaynaktan gelmemesi garanti edilir. Bir git bağımlılığı, tedarik zinciri güvencelerinin tamamını delen bir kaçış deliğidir.

**CI'da bloklayıcı hâle getirme.**

```yaml
- uses: EmbarkStudios/cargo-deny-action@v2
  with:
    command: check bans licenses sources advisories
    arguments: --all-features --locked
```

Çıkış kodu sıfırdan farklıysa job başarısız olur. `continue-on-error` kullanılmaz.

Advisories kontrolü için ayrı bir düşünce gerekir: bu kontrol dış veriye, yani RustSec veritabanına bağlı olduğu için, yeni bir advisory yayımlandığında kod değişmeden CI kırılır. Bu istenen davranıştır ancak release hattını kilitleyebilir. Çözüm `bans`, `licenses` ve `sources`'ı deterministik bir PR kapısı, `advisories`'i günlük zamanlanmış bir job ile release kapısı olarak ayırmaktır.

### A.5 cargo-audit ve RustSec advisory veritabanı

**Kapsam.** Veritabanı klonlanıp sayılmıştır; son commit 8 Eylül 2026 saat 11.58 CEST'tir.

Toplam advisory `crates/` altında 1.222, `rust/` altında 20'dir (std 18, cargo 1, rustdoc 1).

Yıllara göre dağılım:

| Yıl | Sayı | | Yıl | Sayı |
|---|---|---|---|---|
| 2016 | 6 | | 2022 | 104 |
| 2017 | 8 | | 2023 | 126 |
| 2018 | 22 | | 2024 | 139 |
| 2019 | 40 | | 2025 | 172 |
| 2020 | 168 | | 2026 | 281, 8 Eylül'e kadar |
| 2021 | 156 | | | |

2026, henüz sekiz ay geçmişken tüm zamanların rekorudur; yıllıklandırılmış yaklaşık 420 eder ve bu 2025'in 2,4 katıdır.

Tür dağılımı şöyledir: gerçek güvenlik açığı 741, `informational = "unmaintained"` 269, `informational = "unsound"` 206, `informational = "notice"` 6.

`unmaintained` advisory'leri Argus için özellikle değerlidir; CVE değildir ancak gelecekteki riskin göstergesidir, çünkü bakımsız bir crate'te bulunacak açık asla yamalanmayacaktır.

**Bakım ve yönetişim.** Veritabanı Rust Secure Code Working Group tarafından bakılmaktadır, Rust Foundation tarafından değil; Foundation ayrı olarak fonlama ve araç sağlamaktadır, G.3'e bakınız. Depo 3.192 commit, 1,2 bin yıldız ve 536 fork'a sahiptir. Güncelleme sıklığı günlüktür; klonlama anında son commit aynı gün atılmıştı. Veritabanı OSV formatında yayımlanmakta, osv.dev ile GitHub Advisory Database otomatik içe aktarmaktadır; yani Dependabot, Trivy, Grype ve osv-scanner hepsi aynı veriyi görmektedir.

**`rustsec` deposundaki crate'ler.** Tek workspace altında altı crate vardır: `cargo-audit`, `cargo-lock` (bağımsız Cargo.lock ayrıştırıcısı), `cvss`, `platforms`, `rustsec` (istemci kütüphanesi) ve `rustsec-admin`.

> **Argus için.** `rustsec` crate'i doğrudan kullanılarak yönetim paneline bir bağımlılık sağlığı widget'ı konabilir. Bir IdP'nin operatörüne "şu an çalışan sürümünüzde sıfır bilinen açık var" demesi güçlü bir ürün özelliğidir ve CRA madde 13 şeffaflık beklentisiyle örtüşür.

**Argus yığınının advisory maruziyeti.** Örnek yığınlar advisory veritabanıyla kesiştirilmiştir; eşleşme kabadır ve sürüm aralıklarını değil crate adını eşleştirir.

| | Tam yığın (231) | Minimal (162) |
|---|---|---|
| Advisory kaydı olan crate | 46 | 38 |
| Toplam advisory kaydı | 83 | 64 |

Şu an fiilen açık `unsound` işaretli ve her iki yığında ortak olan bağımlılıklar şunlardır:

```
crossbeam-queue 0.3.14   RUSTSEC-2022-0021
crossbeam-utils 0.8.23   RUSTSEC-2022-0041
event-listener  5.4.2    RUSTSEC-2026-0221  (yeni!)
futures-intrusive 0.5.0  RUSTSEC-2020-0072
hyper           1.11.1   RUSTSEC-2022-0022
lock_api        0.4.14   RUSTSEC-2020-0070
mio             1.2.3    RUSTSEC-2020-0081
rand            0.9.5    RUSTSEC-2026-0097
smallvec        1.16.0   RUSTSEC-2018-0018
socket2         0.6.5    RUSTSEC-2020-0079
tokio           1.53.1   RUSTSEC-2023-0005, RUSTSEC-2025-0023
tracing         0.1.44   RUSTSEC-2023-0078
```

> **`ring` hakkında düzeltme.** Kaba eşleştirici `ring 0.17.14`'ü unmaintained olarak işaretlemiştir (RUSTSEC-2025-0007, 20 Şubat 2025). Ancak advisory'nin TOML başlığında `withdrawn = "2025-02-22"` vardır; advisory iki gün sonra geri çekilmiştir. Advisory metnine göre yazar süresiz ara verdiğini duyurmuş, rustls ekibine erişim verilmiş ve durum şöyle özetlenmiştir: "Things are more-or-less back to how they were before, and in particular the situation isn't 'security maintenance only.'" Bu, raporun en öğretici anıdır: grep ile advisory taraması yapılmaz. `withdrawn`, `patched` ve `unaffected` alanlarını doğru yorumlayan gerçek araç, yani `cargo audit` veya `cargo deny`, kullanılır. Elle sayarken bu tuzağa düşülmüştür; CI düşmemelidir.

Bir IdP'yi doğrudan ilgilendiren 2026 advisory'leri şunlardır.

`bcrypt` RUSTSEC-2026-0199 (20 Haziran 2026, 0.19.2 ve üstünde yamalıdır): `bcrypt::verify(password, hash)` saldırgan kontrollü hash string'iyle panic etmektedir; 60 baytlık ve belirli konumlarda çok baytlı UTF-8 karakter içeren bir `&str` yeterlidir. Advisory'nin kendi tehdit senaryosu birebir Argus'tur: "Rust authentication services reading hashes from a database that was previously compromised via, e.g., SQL injection. The attacker can then crash the service on every login attempt against the tampered account." Crate `#![forbid(unsafe_code)]` olduğu için etki yalnızca hizmet reddidir.

`tokio-postgres` RUSTSEC-2026-0178 (12 Haziran 2026, 0.7.18 ve üstü): kötü niyetli veya ele geçirilmiş bir sunucu, satır tanımından az alan içeren bir `DataRow` gönderirse `Row::get` ve panic etmeyeceği varsayılan `try_get` bile aralık dışı indeksleme ile panic etmektedir.

Ayrıca `h2` RUSTSEC-2026-0258, `diesel` için 2026'da altı ayrı advisory (0111, 0134, 0135, 0136, 0137, 0172), `rand` RUSTSEC-2026-0097, `time` RUSTSEC-2026-0009 ve `lettre` RUSTSEC-2026-0141 vardır; sonuncusu e-posta içindir ve OTP ile magic link akışlarını ilgilendirir.

`rmcp` RUSTSEC-2026-0189 (29 Nisan 2026, CVE-2026-42559, 1.4.0 ve üstü): MCP Streamable HTTP transport'unda DNS rebinding vardır, çünkü `Host` başlığı doğrulanmamaktadır. Argus'a MCP veya AI entegrasyonu düşünülüyorsa doğrudan ilgilidir.

> **DNS rebinding kalıbı.** 2026'da RustSec'te en az iki ayrı DNS rebinding advisory'si vardır: `rmcp` ve `rojo` RUSTSEC-2026-0279. İkisinde de kök neden aynıdır: localhost'a bağlanan kimlik doğrulamasız HTTP API'de `Host` ve `Origin` doğrulaması yoktur. Argus'un geliştirme sunucusu, yönetim API'si ve device code akışı bu kalıba düşebilir. `Host` allowlist'i birinci günden uygulanır.

### A.6 Diğer araçlar, ne satın aldıkları ve Argus'ta nereye oturdukları

**`cargo-auditable`, güçlü tavsiye.** Bağımlılık ağacını derlenmiş binary'e gömer; Zlib ile sıkıştırılmış JSON'u `.dep-v0` adlı linker section'ına yazar. Maliyeti yoktur: "under 4kB even on large dependency trees with 400+ entries", yani binary boyutunun binde biri ile on binde biri kadardır. Çıkarma araçları `rust-audit-info`, `syft` (v1.15.0 ve üstü), `trivy` (v0.31.0 ve üstü), `auditable2cdx` (CycloneDX'e çevirir) ve `cargo audit`'tir (v0.17.3 ve üstü). Benimsenme olarak Alpine Linux, NixOS, openSUSE, Void Linux, Chimera Linux, Wolfi OS ve Ubuntu 26.04 (seçili paketler) bunu varsayılan olarak kullanmaktadır; Microsoft dahilî olarak kullanmaktadır.

> **Neden kritiktir.** SBOM dosyaları kaybolur, eşleşmez ve güncellenmez. Binary'nin içindeki SBOM her zaman doğru binary'ye aittir. Müşteri hangi sürümü çalıştırdığını ve açığı olup olmadığını sorduğunda cevap `rust-audit-info /usr/bin/argus | cargo audit --stdin` olur. Bu, CRA Ek I Bölüm II.1'deki bileşenleri tanımla ve belgele yükümlülüğünü çalışma zamanında karşılar. Yapılmalıdır.

**`cargo-machete` ile `cargo-udeps`.** `cargo-machete` (0.9.2, 15 Nisan 2026, 90 günde 508 bin) stable toolchain'de çalışır, hızlıdır çünkü kaynak metnini tarar, bazen yanlış pozitif verir ve CI'ya konur. `cargo-udeps` (0.1.61, 29 Nisan 2026, 90 günde 138 bin) nightly gerektirir, derleyici verisine bakar ve daha doğrudur; haftalık veya aylık bir job olarak konur. İkisi tamamlayıcıdır: Argus'ta machete PR kapısı, udeps zamanlanmış iş olur.

**`cargo-supply-chain`** (0.3.7, 5 Şubat 2026, 90 günde 4,2 bin) bağımlılıkların yayımcılarını ve sahiplerini listeler. Niştir ancak Argus için değerli tek bir soruyu cevaplar: bağımlılık grafiğim kaç farklı insana güvenmektedir. Bu, tedarik zinciri tehdit modelinin gerçek boyutudur. Yılda bir çalıştırılıp raporlanır; sayı büyüyorsa minimizasyon çalışması yapılır.

**`cargo-outdated` ve `cargo-semver-checks`.** `cargo-outdated` (0.19.0) güncellenebilir bağımlılıkları listeler; bilgilendiricidir, kapı değildir. `cargo-semver-checks` (0.50.0, 1 Ağustos 2026) Argus kendi crate'lerini, yani SDK ve istemci kütüphanelerini yayımlayacaksa semver ihlallerini yakalar ve downstream kırılmalarını önler.

**`cargo-geiger`** (0.13.0, 31 Ağustos 2025) `unsafe` kullanımını sayar. Faydalıdır ancak son sürümü bir yıldan eskidir ve bakımı yavaştır; aşağıdaki Cargo Scan alternatifine bakılmalıdır.

**Cargo Scan, yeni ve Argus için çok uygun.** "Auditing Rust Crates Effectively", Lydia Zoghbi, David Thien, Ranjit Jhala, Deian Stefan ve Caleb Stanford, arXiv 2602.06466, 6 Şubat 2026'da sunulmuştur. Rust'ın tip ve modül sistemini kullanarak yan etki analiziyle potansiyel olarak tehlikeli kodu işaretler. Sonuçları şöyledir: vakaların yaklaşık %69'unda geliştirici, işaretlenen etkiyi daha geniş bağlam analizi olmadan yerel olarak değerlendirebilmektedir; `hyper` HTTP crate'i ve bağımlılıklarına uygulandığında denetim yükünü kod satırlarının medyan %0,2'sine indirmiştir; crates.io'nun ilk 10.000 crate'inde yaklaşık 3.500 crate otomatik olarak güvenli sınıflandırılabilmiş, elle inceleme gerekenlerde tehlikeli yan etkiler crate'lerin yaklaşık %3'ünde yoğunlaşmıştır.

> **Argus'ta yeri.** cargo-vet ile birleştirilir. Yukarıda hiç denetlenmemiş bulunan 14 ile 37 arası crate elle denetlenmelidir; Cargo Scan bu işi crate başına tam okuma yerine satırların %0,2'sini okumaya indirger. `argon2`, `sqlx` ailesi ve ASN.1 ayrıştırıcıları için ilk uygulanacak araç budur.

---

## B. Bağımlılık minimizasyonu

### B.1 Gerçek şişkinlik verisi

Teorik tartışma yerine ölçüm yapılmıştır; cargo 1.98.1 ile iki gerçek proje kurulup `cargo vendor` ile kaynaklar çekilmiştir.

**Yığın A, makul ve sıradan bir IdP yığını.**

```toml
axum 0.8 (macros), tokio 1 (full), tower 0.5, tower-http 0.6 (trace,cors,compression-gzip),
sqlx 0.8 (runtime-tokio, tls-rustls, postgres, uuid, chrono, migrate),
serde, serde_json, tracing, tracing-subscriber (env-filter,json),
jsonwebtoken 9, argon2 0.5, rand 0.9, uuid 1, chrono 0.4,
reqwest 0.12 (default-features=false, json, rustls-tls), redis 0.27, webauthn-rs 0.5
```

| Metrik | Değer |
|---|---|
| `Cargo.lock` paket sayısı | 324, kendisi dahil |
| linux-x86_64 için gerçekten derlenen (normal ve build) | 243 crate sürümü, 231 farklı ad |
| Yalnızca runtime (normal) | 236 |
| `build.rs` içeren crate, yani derleme anında keyfi kod | 26 |
| proc-macro crate, yani derleme anında keyfi kod | 19 |
| Üçüncü taraf Rust satırı, test ile bench ve example hariç | 1.747.244 |
| C ve C++ kaynak dosyası taşıyan crate | 3: `cc`, `openssl-sys`, `ring` |
| Bağımlılık ağacı derinliği | Yaklaşık 19 seviye |
| Çoklu sürümü olan crate | 23 |

**Yığın B, minimize edilmiş.** `default-features = false` uygulanmış, webauthn-rs, redis, reqwest, chrono ve tower-http çıkarılmış, `tls-rustls-ring` seçilmiştir.

| Metrik | A, tam | B, minimal | Kazanç |
|---|---|---|---|
| linux-x86_64 crate | 243 | 170 | %30 azalma |
| `build.rs`, yani derleme anı kod çalıştırma yüzeyi | 26 | 20 | %23 azalma |
| proc-macro | 19 | 9 | %53 azalma |
| Üçüncü taraf satır | 1.747.244 | 1.311.921 | %25 azalma |
| OpenSSL, yani native C kripto | Vardır | Yoktur | Tamamen kalkar |
| Denetlenmemiş crate, vet setlerine göre | 37 | 14 | %62 azalma |

En değerli tek hamle `webauthn-rs`'i çıkarmaktır. `cargo tree -i cc` kanıtı şudur:

```
cc v1.4.5
[build-dependencies]
├── openssl-sys v0.9.117
│   ├── openssl v0.10.81
│   │   ├── webauthn-attestation-ca v0.5.5
│   │   │   └── webauthn-rs-core v0.5.5
│   │   │       └── webauthn-rs v0.5.5
```

`webauthn-rs 0.5` attestation CA doğrulaması için native OpenSSL'e bağımlıdır. Bir IdP için passkey desteği zorunludur; ancak bu bağımlılık ürüne şunları sokar: CVE akışı yüksek olan sistem OpenSSL'i; derleme anında `cc` çalıştıran ve sistemi tarayan `openssl-sys` build script'i; `openssl` crate'i için RustSec'te on advisory kaydı; statik ve tekrarlanabilir derlemenin zorlaşması; container imajının şişmesi.

> **Argus mimari kararı.** WebAuthn attestation doğrulaması ayrı bir sürece veya servise izole edilir, ya da saf Rust ASN.1 ile X.509 doğrulaması (`webpki`, `rustls-webpki`, `x509-cert`) kendimiz yazılır. Attestation, passkey akışının isteğe bağlı parçasıdır; çoğu CIAM senaryosunda `AttestationConveyancePreference::None` kullanılır ve o zaman bu bağımlılığa hiç gerek yoktur. Attestation yalnızca yüksek güvence gereken kurumsal profilde ve izole edilmiş şekilde açılır.

**En büyük 20 bağımlılık**, minimal yığında ve satır sayısıyla:

```
129.987  libc 0.2.189
 99.903  tokio 1.53.1
 65.894  regex-automata 0.4.18   ← tracing-subscriber/env-filter
 58.465  regex-syntax 0.8.11     ← tracing-subscriber/env-filter
 51.755  syn 3.0.5               ← ikinci syn sürümü!
 50.120  syn 2.0.119
 48.053  rustls 0.23.44
 28.541  zerocopy 0.8.56
 26.108  futures-util 0.3.34
 25.644  ring 0.17.14
 24.402  unicode-normalization 0.1.25
 23.720  hashbrown 0.17.1
 23.184  tracing-subscriber 0.3.23
 22.248  hyper 1.11.1
 22.213  hashbrown 0.15.5        ← ikinci hashbrown!
 19.841  sqlx-postgres 0.8.6
 19.354  typenum 1.20.1
 18.359  serde_json 1.0.151
 17.306  serde 1.0.229
 16.977  axum 0.8.9
```

İlk on crate toplam satırın %44,5'ini oluşturmaktadır. Denetim bütçesi buraya odaklanır; ancak dikkat edilmelidir ki bunların çoğu, yani tokio, rustls, serde ve hyper, zaten Google ile Mozilla tarafından `safe-to-deploy` denetlenmiştir. Gerçek iş denetlenmemiş küçük crate'lerdedir.

**İki somut şişkinlik zinciri.**

Birincisi `env-filter`'dan regex motoruna gider ve 124.359 satırdır:

```
regex-automata + regex-syntax
  └── matchers 0.2.0 → tracing-subscriber (env-filter feature)
```

`RUST_LOG=info,argus::oidc=debug` gibi filtrelere ihtiyaç yoksa `env-filter` kapatılır veya `tracing-subscriber`'ın regex kullanmayan `Targets` filtresi kullanılır; yaklaşık 124 bin satır ve tam bir regex motoru gider.

İkincisi `url`'den `idna`'ya, oradan ICU4X'e ve ikinci bir `syn`'e gider; iki syn yaklaşık 102 bin satırdır:

```
syn 3.0.5
└── displaydoc (proc-macro)
    └── icu_collections → icu_normalizer → idna_adapter → idna → url
        └── sqlx-core
```

Bu, Rust ekosisteminin en bilinen şişkinlik zinciridir: bir URL ayrıştırmak için Unicode IDNA gelir, o tam ICU4X normalizasyon veri yapılarını getirir, o da `yoke`, `zerocopy` ve `displaydoc` proc-macro'larını getirir. Argus URL ayrıştırmayı, yani `redirect_uri` doğrulamasını, kendisi yapmalıdır; zaten OAuth 2.1'de `redirect_uri` eşleşmesi birebir string karşılaştırması olmalıdır ve RFC 6749 ile OAuth 2.1 taslağı exact match zorunlu kılar. Genel amaçlı bir URL ayrıştırıcısının esnekliği burada bir özellik değil güvenlik açığıdır.

### B.2 Rust'ta left-pad riski ve küçük crate tartışması

**npm'e göre yapısal farklar.** Birincisi `cargo yank` silmez: yanklanan sürüm mevcut `Cargo.lock` dosyalarından çözülmeye devam eder, yalnızca yeni çözümleme onu seçmez. left-pad tipi "paket kayboldu, dünya durdu" olayı Rust'ta mimari olarak mümkün değildir. İkincisi gerçek silme yalnızca crates.io ekibi tarafından ve kötü amaçlı kod için yapılır; o zaman da bir RustSec advisory'si yayımlanır, F bölümündeki `expect-deleted = true` alanına bakınız. Üçüncüsü binary projelerde `Cargo.lock` ve checksum varsayılan olarak commit edilir.

**Ancak Rust'ın npm'den daha kötü olan bir yanı vardır: `build.rs` ve proc-macro.** npm'de `postinstall` script'i vardır ve `--ignore-scripts` ile kapatılabilir. Rust'ta `build.rs`'yi kapatmanın bir yolu yoktur ve JFrog'un araştırması bunu net söylemektedir: "In Rust, a `build.rs` script is compiled and executed automatically during `cargo build`, `cargo check`, and similar commands, including CI and rust-analyzer driven builds."

Yani editörde dosyayı açmak yeterlidir: rust-analyzer `cargo check` çalıştırır, `build.rs` çalışır ve payload iner. Ağustos 2026 saldırısı tam olarak böyle işlemiştir.

Ölçüme göre sıradan bir IdP yığınında 26 crate'in `build.rs` dosyası vardır ve 19 proc-macro crate'i derleme sırasında derleyici içinde keyfi kod çalıştırmaktadır. Bu 45 crate, CI runner'ında ve geliştirici dizüstünde kod çalıştırma hakkına sahip 45 ayrı taraftır.

**Argus için somut politika.** `deny.toml`'a bir `build.rs` allowlist mantığı eklenir; cargo-deny bunu doğrudan desteklemez, `cargo metadata` üzerinde küçük bir betik yazılır: yeni bir `build.rs` bağımlılığı grafiğe girdiğinde CI kırılır ve insan onayı gerekir. Ağustos 2026 saldırısında sinyal tam buydu; `arrayref`'in on yıllık geçmişinde hiç görülmemiş bir bağımlılık eklenmişti. CI derlemeleri ağ erişimi olmayan bir container'da, vendor edilmiş kaynaklarla ve `--offline` ile yapılır; `proc-macro1`'in payload indirmesi mümkün olmazdı. Geliştirici makinelerinde rust-analyzer için `cargo check` yerine izole devcontainer kullanmak değerlendirilir.

### B.3 `cargo vendor` ve vendoring politikası

`cargo vendor` tüm bağımlılık kaynaklarını repoya veya artifact'a indirir ve `.cargo/config.toml` dosyasına kaynak değiştirme yazar.

Ölçüme göre tam yığın için vendor dizini 342 MB'dir; Windows import kütüphaneleri baskındır, `windows-sys`'in üç sürümü 70 MB tutmaktadır. Yalnızca Linux hedeflenip `--versioned-dirs` kullanılınca çok daha küçük olur.

**Önerilen vendoring politikası.**

| Ne | Karar | Gerekçe |
|---|---|---|
| Kaynak vendoring'i repoya commit etmek | Hayır | 342 MB'dir, inceleme gürültüsü yaratır ve PR'ları öldürür |
| Release hattında vendor tarball'ı üretmek | Evet | Hermetik, ağsız ve tekrarlanabilir derleme sağlar |
| Vendor tarball'ını imzalamak ve arşivlemek | Evet | Kaynak crates.io'dan silinse bile derleme yapılabilir |
| Kritik crate'i forklamak | Seçici | Aşağıya bakınız |

**Fork kapasitesi konusunda gerçekçi olunmalıdır.** Minimal yığında 1.311.921 satır üçüncü taraf kod vardır; iki ile beş kişilik bir ekip bunu forklayamaz ve sürdüremez. Fork stratejisi yalnızca crate küçükse (5.000 satırın altında), güvenlik kritik yoldaysa ve upstream bakımsız veya yavaşsa anlamlıdır.

Argus için fork adayları `jsonwebtoken` (JWT doğrulama mantığıdır; algoritma karıştırma saldırıları için tam kontrol istenir), `argon2` parametreleri ve ASN.1 ayrıştırıcılarıdır. `tokio`, `rustls` ve `serde` asla forklanmaz.

Daha iyi alternatif vendor ile patch birleşimidir: `[patch.crates-io]` ile yalnızca ihtiyaç duyulan crate yerel bir kopyayla değiştirilir, geri kalanı upstream kalır. Tam fork'un bakım yükü olmadan kontrol sağlar.

### B.4 Somut minimizasyon teknikleri

**1. `default-features = false`, en yüksek getirili tek hamle.** Ölçüme göre crate sayısını %30 düşürür.

```toml
tokio = { version = "1", default-features = false,
          features = ["rt-multi-thread","net","time","macros","signal"] }
axum = { version = "0.8", default-features = false,
         features = ["http1","json","tokio"] }
sqlx = { version = "0.8", default-features = false,
         features = ["runtime-tokio","tls-rustls-ring","postgres","uuid","macros"] }
```

`tokio` için `"full"` yerine gerçek feature listesi kullanılır. `"full"`, `fs`, `process` ve `io-std` gibi Argus'un asla kullanmayacağı ve ambient capability yüzeyini genişleten modülleri açar.

Feature'lar aynı zamanda bir güvenlik kontrolüdür: `tokio/process` açık değilse ele geçirilmiş bir bağımlılık `tokio::process` üzerinden komut çalıştıramaz.

**2. `cargo tree -d` ile çoklu sürümler.** Ölçüme göre tam yığında 23 crate çifttir.

```bash
cargo tree -d --target x86_64-unknown-linux-gnu -e normal
```

Tam yığında `rand`, `rand_core` ve `getrandom` üçer sürümlüdür; `syn`, `thiserror`, `hashbrown`, `base64`, `socket2` ve `webpki-roots` ikişer sürümlüdür.

Bunun önemi şudur: her kopya ayrı denetlenmelidir; `rand` ile `getrandom`'ın üç farklı sürümü olması üç farklı entropi kaynağı kod yolu demektir ve bu bir IdP için kabul edilemez; ayrıca binary boyutunu büyütür. `cargo update -p <crate> --precise <ver>` ile birleştirilir veya bağımlılık sürümleri hizalanır.

**3. `no_std`, Argus için sınırlı fayda.** Argus bir ağ servisidir; tokio, TLS ve PostgreSQL istemcisi zaten `std` gerektirir, dolayısıyla `no_std` ana binary için uygulanamaz.

Ancak kripto ve protokol çekirdeği kendi crate'lerinde `#![no_std]` olarak yazılabilir. Token üretimi ve doğrulaması, PKCE hesabı, DPoP kanıt doğrulaması ile parola hash parametreleri `no_std` artı `alloc` ile yazılabilir. Kazanç şudur: bu modüller dosya sistemine, ağa ve saate erişemez, dolayısıyla denetimi radikal biçimde kolaylaşır ve cargo-vet `safe-to-deploy` incelemesi dakikalar sürer. Bu, en güvenli IdP iddiası için somut ve gösterilebilir bir mimari argümandır.

**4. Kendi kodda `#![forbid(unsafe_code)]` ve bir `unsafe` bütçesi.** Ölçüme göre tam yığında 193 crate en az bir `unsafe fn`, `impl` veya bloğu içermekte, toplam 22.595 oluşum bulunmaktadır. Bu sıfırlanamaz. Ancak Argus'un kendi crate'lerinde workspace lint'i olarak `#![forbid(unsafe_code)]` uygulanır ve bağımlılıklardaki `unsafe` sayısı zaman içinde izlenir; artıyorsa yeni ve denetlenmemiş bir bağımlılık girmiştir.

**5. Alternatif crate seçimleri.**

| Yerine | Kullanılır | Gerekçe |
|---|---|---|
| `openssl` ve `native-tls` | `rustls` ile `aws-lc-rs` veya `ring` | Native C kripto ve `build.rs` yoktur; FIPS için aws-lc-rs kullanılır |
| `chrono` | `time` veya `jiff` | chrono geçmişte `localtime_r` soundness sorunları yaşamıştır, RUSTSEC-2020-0159 |
| `webauthn-rs`, attestation ile | Attestation izole edilir veya saf Rust X.509 yazılır | OpenSSL zincirini keser; ölçümle kanıtlıdır |
| `tracing-subscriber` ile `env-filter` | `Targets` filtresi | 124 bin satırlık regex motoru gider |
| `url`, `redirect_uri` için | Birebir string eşleşmesi | OAuth 2.1 zaten exact match ister; ICU4X zinciri gider |
| `reqwest`, tam | `reqwest` ile `default-features=false` ve `rustls-tls` | Ya da doğrudan `hyper` istemcisi kullanılır |

---

## C. Rust'ta tekrarlanabilir derlemeler, 2026 durumu

### C.1 `cargo build` tekrarlanabilir midir

Bu bölüm teorik bırakılmamıştır; rustc 1.98.1 (48a229cea, 1 Eylül 2026) ile dört kontrollü deney yapılmıştır.

**Deney 1: aynı makine, farklı derleme dizini, `debug = false`.** İki özdeş proje, `.../scratchpad/rb1` ve `.../scratchpad/rb2`, aynı `Cargo.lock` ile derlenmiştir:

```
hash1 = 7c2e382ad80a0c00b44a3e6743c42c02b8fac31cb4d655039a97c770f7b044c9
hash2 = 7c2e382ad80a0c00b44a3e6743c42c02b8fac31cb4d655039a97c770f7b044c9
```

Sonuç bit düzeyinde aynıdır. Proje dizini yolu binary'e sızmamıştır; `strings | grep scratchpad/rb1` sıfır eşleşme vermiştir.

**Deney 2: `debug = 1`**, yani üretimde sembol isteniyorsa:

```
hash1 = 8ce8891f9196985af57e18525c9d0b45b9e9e0b417bbfca830fb88e2288df813
hash2 = 907451832bf2b624e7911e26e562274542e50ba46da11da49a683b33af74774a
```

Sonuç farklıdır; debuginfo derleme dizinini, yani DWARF `comp_dir` alanını sızdırmaktadır.

**Deney 3: farklı `CARGO_HOME`**, asıl tuzak budur. `debug = false` ile, ancak ikinci derleme farklı `CARGO_HOME` ile yapılmıştır:

```
varsayılan CARGO_HOME : 7c2e382ad80a0c00b44a3e6743c42c02b8fac31cb4d655039a97c770f7b044c9
alternatif CARGO_HOME : 5d71f9aeb24cbc6e213b4259b6229069ccf604dd0f181b98e99fd472a4a28718
```

Sonuç farklıdır. Sızan string şudur:

```
/Users/adem/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/itoa-1.0.18/src/lib.rs
```

Sebebi şudur: bağımlılık içindeki `panic!` ve `assert!` makroları `std::file!()` ile mutlak kaynak yolunu binary'e gömmektedir. Bu, farklı kullanıcı adına sahip iki makinede tekrarlanabilirliği kırar; CI ile geliştirici makinesi arasında veya iki farklı CI runner'ı arasında.

**Deney 4: düzeltme, `--remap-path-prefix`.** Hem proje dizini hem `CARGO_HOME/registry` remap edilmiştir:

```bash
RUSTFLAGS="--remap-path-prefix=$CARGO_HOME/registry=/cargo \
           --remap-path-prefix=$PWD=/build"
```

```
build1 (yol A, cargo home A) : 3cd7b02ce6de710cedea15b8c9503e7ab394994215a189219589283bfae7c3bb
build2 (yol B, cargo home B) : 3cd7b02ce6de710cedea15b8c9503e7ab394994215a189219589283bfae7c3bb
```

Sonuç bit düzeyinde aynıdır. Binary'deki string artık `/cargo/src/index.crates.io-.../itoa-1.0.18/src/lib.rs` biçimindedir.

**Deney 4b: üçüncü sızıntı kaynağı, rustup toolchain yolu.** Remap sonrası kalan mutlak yollar arandığında şu bulunmuştur:

```
/Users/adem/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/alloc/src/collections/btree/navigate.rs
```

Önceden derlenmiş `std` ve `alloc` içindeki panic konumları, `std`'nin derlendiği makinenin rustup yolunu taşımaktadır. İki derlemede aynı `RUSTUP_HOME` kullanıldığı için aynıydı, ancak farklı `$HOME` değerine sahip bir makinede bu değişir. Bu yüzden reçeteye üçüncü bir remap kuralı gerekir:

```bash
--remap-path-prefix=$RUSTUP_HOME=/rustup
```

Bu üçüncü kuralın farklı makinelerdeki etkinliği bu oturumda birebir doğrulanamamıştır; CI'da iki farklı kullanıcı adıyla test edilmelidir.

**Özet: tekrarlanabilirliği kıran şeyler.**

| Kırıcı | Durum | Çözüm |
|---|---|---|
| Proje dizini mutlak yolu | Ölçüldü: release'de sızmaz, `debug`'da sızar | `--remap-path-prefix=$PWD=/build` |
| `CARGO_HOME` registry yolu | Ölçüldü: sızar ve hash'i kırar | `--remap-path-prefix=$CARGO_HOME/registry=/cargo` |
| `RUSTUP_HOME` toolchain yolu | Ölçüldü: binary'de vardır | `--remap-path-prefix=$RUSTUP_HOME=/rustup` |
| Debug info, `comp_dir` | Ölçüldü: `debug=1` hash'i kırar | remap ile `--remap-path-scope` veya `strip="debuginfo"` |
| rustc sürümü | Kesin kırar | `rust-toolchain.toml` ile sabitlenir |
| `Cargo.lock` çözümlemesi | Kırar | `--locked` |
| Artımlı derleme | Kırar | Release'de zaten kapalıdır; `CARGO_INCREMENTAL=0` |
| `codegen-units` paralelliği | Genelde deterministiktir ancak risklidir | `codegen-units = 1`, hem tekrarlanabilirlik hem performans için |
| `build.rs` determinizmsizliği | Crate'e bağlıdır | `SOURCE_DATE_EPOCH`; vendor ile offline |
| Linker'ın gömdüğü yollar | rustc bunu remap etmez | Aşağıya bakınız |

> **Kritik uyarı.** rustc dokümanı şunu söylemektedir: "On Windows (`x86_64-pc-windows-msvc`) and Apple platforms, linkers embed absolute paths into debug info (`.pdb`, OSO entries) independently. These are not remapped by `--remap-path-prefix`." Dolayısıyla Argus tekrarlanabilir release'lerini Linux'ta üretmelidir; macOS ve Windows binary'leri için bit düzeyinde tekrarlanabilirlik pratik değildir.

### C.2 `--remap-path-prefix` ve `--remap-path-scope` stabilizasyon durumu

Kaynak rustc dokümanının 8 Eylül 2026 tarihli çekimidir.

`--remap-path-prefix` stabildir. Formatı `FROM=TO`'dur; `FROM` eşittir içerebilir, `TO` içeremez. Birden çok eşleşmede sonuncusu uygulanır. Tamamen metinsel bir değiştirmedir ve yol ayırıcı normalizasyonu yapmaz; Windows'ta `/` ile `\` ayrı karakterlerdir.

`--remap-path-scope` unstable'dır ve nightly gerektirir. Kapsamları `macro` (`std::file!()` ve gömülü panic mesajları), `diagnostics`, `debuginfo`, `coverage`, `object` (yani `macro,coverage,debuginfo` takma adı) ve `all`'dır (varsayılan). Dokümanın kendi uyarısı şudur: "The `all` scope may correspond to different scopes between releases."

rustc kendi ifadesiyle bunun best effort bir özellik olduğunu söylemektedir.

**Cargo tarafı: `trim-paths` hâlâ unstable'dır.** 8 Eylül 2026'da iki kaynaktan teyit edilmiştir. Birincisi `doc.rust-lang.org/cargo/reference/profiles.html` sayfasıdır ve `trim-paths` listede yoktur; listede yalnızca `opt-level`, `debug`, `split-debuginfo`, `strip`, `debug-assertions`, `overflow-checks`, `lto`, `panic`, `incremental`, `codegen-units` ve `rpath` vardır. İkincisi `doc.rust-lang.org/nightly/cargo/reference/unstable.html` sayfasıdır ve `trim-paths` unstable bölümündedir. Takip issue'ları rust-lang/cargo#12137 ile rust-lang/rust#111540'tır.

Nightly'de kullanımı şöyledir:

```toml
cargo-features = ["trim-paths"]
[profile.release]
trim-paths = "all"     # veya "object", "none"
```

Varsayılanlar dev için `"none"`, release için `"object"`'tir. Build script'lere geçen ortam değişkenleri `CARGO_TRIM_PATHS_SCOPE` ve `CARGO_TRIM_PATHS_REMAP`'tir; ikincisi C ve C++ derleyicilerine geçirmek içindir ve `cc` crate'i kullanan bağımlılıklar için gereklidir.

> **Argus kararı.** `trim-paths` beklenmez. Stabil `RUSTFLAGS` ile `--remap-path-prefix` kullanılarak bugün çözülür; Deney 4 bunu kanıtlamıştır. `trim-paths` stabilize olunca geçilir.

### C.3 Cargo'nun diğer ilgili unstable özellikleri, 2026

**`lockfile-publish-time`, Argus için en önemli gelecek özelliktir.**

```bash
cargo generate-lockfile -Zunstable-options --publish-time <time>
```

Belirtilen zamandan sonra yayımlanmış paketleri çözümlemeye almaz; yani bağımlılıklar için bir bekleme süresi, yani cooldown uygular. Issue'ları cargo#5221 (orijinal) ve cargo#16271'dir (takip).

Bunun neden hayati olduğu bir sayıyla gösterilebilir: Ağustos 2026 `arrayref` saldırısında kötü niyetli sürümler 86, 90 ve 107 dakika yayında kalmıştır. Yedi günlük bir cooldown politikası bu saldırıyı sıfır etkiyle geçiştirirdi. Aynısı Mart 2026'daki beş crate ve Aralık 2025 kampanyası için de geçerlidir.

Bu özelliği mümkün kılan altyapı Ocak 2026'da gelmiştir: crates.io index'ine `pubtime` alanı eklenmiştir.

> **Argus şimdi ne yapmalı.** Stable'da bu yoktur, ancak elle uygulanabilir: `Cargo.lock` dondurulur, bağımlılık güncellemeleri haftalık toplu grup hâlinde yapılır ve grup, içindeki en yeni crate'in yayın tarihinden en az yedi gün sonra merge edilir. Dependabot ve Renovate otomatik merge'den çıkarılır. Renovate'ta `minimumReleaseAge: "7 days"` ayarı bunu doğrudan destekler.

**`sbom`, Cargo'nun yerleşik SBOM'u.**

```toml
[unstable]
sbom = true
[build]
sbom = true
```

Ya da `CARGO_BUILD_SBOM=true cargo +nightly -Z sbom build` kullanılır.

Her derlenen artifact'ın yanına `<artifact>.cargo-sbom.json` üretir; crate kimlikleri, türleri, feature'lar, bağımlılıklar ve rustc bilgisi içerir. RFC numarası 3553, PR numarası cargo#13709'dur. Build script'lere `CARGO_SBOM_PATH` geçer. Durumu unstable'dır. Bunlar SBOM ön ürünü dosyalarıdır, CycloneDX veya SPDX değildir; bir SBOM aracının tüketmesi beklenir.

**`checksum-freshness`.**

```toml
[unstable]
checksum-freshness = true
[build]
fingerprint = "content"   # varsayılan "mtime"
```

Yeniden derleme kararını mtime yerine içerik checksum'ıyla verir; issue numarası cargo#14136'dır. CI'da mtime güvenilmez olduğu için faydalıdır. Not olarak build script'lerin okuduğu dosyalar hâlâ mtime kullanmaktadır.

**`build-std`.** `std`'yi kaynaktan derler. Tekrarlanabilir derleme için teorik olarak idealdir ve C.1 Deney 4b'deki rustup yolu sorununu kökten çözer, ancak "still in very early stages of development" durumundadır ve nightly gerektirir. Argus için 2026'da önerilmez.

### C.4 Reproducible Builds projesi ve Rust

Projenin kendi değerlendirmesi şudur: Rust programları, orijinal derleme zinciri sürüm eşleşmeli ve derleme yolları normalize edilmişse "often already reproducible by default" durumdadır. Rehberleri şöyledir.

`cargo build --release --locked` kullanılır; bu, cargo'nun semver uyumlu daha yeni sürümlere kaymasını engeller. Sorun ayıklamak için `target/` dizininde diffoscope çalıştırılır ve sorun tek bir crate'e indirgenir; `.rustc_info.json` ile `.fingerprint/` dosyaları yok sayılır. Zaman damgaları için "very uncommon for Rust programs to record the date and time the binary has been compiled" denmektedir, ancak `SOURCE_DATE_EPOCH` varsa ona saygı gösterilmelidir. `rust-embed` kullanılıyorsa `deterministic-timestamps` feature'ı açılmalıdır, aksi hâlde dosya sistemi metadata'sı binary'e girer; Argus login sayfasını ve statik varlıklarını gömecekse bu madde kaçırılmamalıdır.

Rust ve crates.io, Reproducible Builds projesinin sürekli test altyapısında ayrı bir proje olarak izlenmemektedir. İzlenenler coreboot, Debian, FreeBSD ve NetBSD (dahilî); Arch Linux, GNU Guix, Go, NixOS, openSUSE, openEuler, Qubes OS, Yocto, Trisquel ve rattler-build (harici); Alpine, Fedora ve OpenWrt (devre dışı) şeklindedir. Rust paketleri dolaylı olarak Debian, Arch ve NixOS üzerinden test edilmektedir. Rust'a özel bir yüzde metriği doğrulanamamıştır, çünkü arama kotası bittiği için 2025 ile 2026 aylık raporları taranamamıştır.

rustc'nin kendi tekrarlanabilirliği için rust-lang/rust#34902 numaralı izleme issue'su 18 Temmuz 2016'da açılmış ve kapatılmıştır. Orijinal bulguları build-id farkları, ELF section header konumu farkları (dört bayt) ve ortam varyasyonlarından kaynaklanan tutarsızlıklardır. Kapanma gerekçesi ile tarihi doğrulanamamıştır, çünkü GitHub sayfası yorumları yükleyememiştir.

### C.5 Argus için pratik tekrarlanabilir release reçetesi

Bunlar Deney 1 ile 4 arasından çıkan ve test edilmiş ayarlardır.

**1. `rust-toolchain.toml`**, repo kökünde, sürümü çiviler:

```toml
[toolchain]
channel = "1.98.1"
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
profile = "minimal"
```

**2. `Cargo.toml` release profili.**

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1        # determinizm + performans
panic = "abort"          # unwind yollarını kaldırır, yüzey küçültür
strip = "debuginfo"      # debuginfo'yu ayır (C.1 Deney 2!)
incremental = false
debug = false
overflow-checks = true   # GÜVENLİK: release'de de açık kalsın
```

`overflow-checks = true` bir IdP için önemlidir: token sayaçları, rate limit hesapları ve süre aritmetiği sessizce sarmamalıdır. Maliyeti ihmal edilebilirdir.

**3. `.cargo/config.toml`**, üç remap kuralı:

```toml
[build]
rustflags = [
  "--remap-path-prefix=/build=/b",
  "--remap-path-prefix=/cargo/registry=/c",
  "--remap-path-prefix=/rustup=/r",
]
```

Container içinde yollar sabitlenirse remap ihtiyacı azalır; aşağıya bakınız.

**4. Container içinde sabit yollar, en sağlam yaklaşımdır.** Remap ile uğraşmak yerine yollar determinize edilir:

```dockerfile
FROM rust:1.98.1-bookworm@sha256:<DIGEST>   # tag değil, DIGEST pinleyin
ENV CARGO_HOME=/cargo \
    RUSTUP_HOME=/rustup \
    CARGO_INCREMENTAL=0 \
    SOURCE_DATE_EPOCH=1700000000
WORKDIR /build
COPY . .
COPY vendor /build/vendor
RUN cargo build --release --locked --offline
```

Herkes `/build` ve `/cargo` kullanınca C.1'deki üç sızıntı kaynağı da ortadan kalkar. Temel imaj digest ile pinlenir; `rust:1.98.1` etiketi yeniden yayımlanabilir.

**5. Vendor edilmiş ve çevrimdışı derleme**, derleme anında ağ erişimini keser:

```bash
cargo vendor --versioned-dirs vendor
cargo build --release --locked --offline
```

Bu, Ağustos 2026 saldırısının payload indirme adımını engellerdi. Vendor tarball'ının SHA-256'sı release artifact'ı olarak yayımlanır.

**6. Doğrulama adımı**, CI'da iki kez derleyip karşılaştırmak:

```yaml
- name: Reproducibility gate
  run: |
    docker build -t argus:a -f Dockerfile.repro .
    docker run --rm argus:a cat /out/argus | sha256sum > a.txt
    docker build --no-cache -t argus:b -f Dockerfile.repro .
    docker run --rm argus:b cat /out/argus | sha256sum > b.txt
    diff a.txt b.txt || { echo "REPRODUCIBILITY BROKEN"; exit 1; }
```

Bu bloklayıcı yapılır. Tekrarlanabilirlik sessizce kaybedilir; kapı olmadan fark edilmez.

**7. Nix, opsiyonel ve güçlüdür.** `crane` veya `naersk` ile hermetik ve içerik adresli derleme sağlar. Ekipte Nix bilgisi yoksa maliyeti yüksektir; container, vendor ve pinlenmiş toolchain zaten bunun %90'ını verir. Nix ancak en güvenli iddiası bir denetçiye kanıtlanacaksa değerlendirilir.

**8. OCI imaj tekrarlanabilirliği.** Binary tekrarlanabilir olsa bile imaj olmayabilir; katman zaman damgaları, dosya sıralaması ve metadata buna neden olur. Çözümler `SOURCE_DATE_EPOCH` ile BuildKit'in `rewrite-timestamp` özelliği, `nix build` veya `ko` veya `apko` ile deterministik imaj üretimi, ya da en basiti olan imajı değil binary'yi imzalamaktır; imaj digest'i zaten değişmezdir ve tekrarlanabilirlik binary düzeyinde iddia edilir.

---

## D. SBOM ve SLSA

### D.1 Rust için SBOM araçları

crates.io API'sinden 8 Eylül 2026'da çekilmiştir.

| Araç | Sürüm | Son güncelleme | 90 gün | Format | Değerlendirme |
|---|---|---|---|---|---|
| `cargo-cyclonedx` | 0.5.9 | 19 Mart 2026 | 747.740 | CycloneDX | Açık ara liderdir |
| `cargo-sbom` | 0.10.0 | 17 Haziran 2025 | 56.461 | SPDX ile CycloneDX | Bakımı yavaşlamıştır |
| `cargo-auditable` | 0.7.5 | 28 Haziran 2026 | 249.877 | Gömülü JSON | Tamamlayıcıdır ve şarttır |
| `cargo-spdx` | 0.1.0 | 10 Mayıs 2022 | 22 | SPDX | Ölüdür, kullanılmaz |
| `syft` (Anchore) | — | Aktif | — | İkisi de | Container ve binary tarar |

`cargo-cyclonedx` iki bileşenden oluşur: `cyclonedx-bom` kütüphanesi ve `cargo-cyclonedx` uygulaması. 1.314 commit, 175 yıldız, 66 fork ve 38 açık issue'ya sahiptir. Deponun kendi güvenlik uyarısı şudur: "cargo-cyclonedx calls into Cargo internally"; yani güvenilmeyen bir proje üzerinde çalıştırılırsa keyfi kod çalıştırabilir, çünkü `build.rs` devreye girer. CI'da yalnızca kendi kod üzerinde çalıştırılır.

Desteklenen tam CycloneDX spesifikasyon sürümleri doğrulanamamıştır; depo sayfası listelememektedir.

### D.2 CycloneDX ile SPDX, Rust için hangisi

| Boyut | CycloneDX | SPDX |
|---|---|---|
| Rust araç desteği | Güçlüdür; `cargo-cyclonedx`, 90 günde 748 bin | Zayıftır; `cargo-spdx` ölüdür, `cargo-sbom` ile syft vardır |
| Yönetişim | OWASP | Linux Foundation ve ISO/IEC 5962:2021 |
| purl, `pkg:cargo/...` | Yerel destek vardır | ExternalRef ile desteklenir |
| VEX | Yerleşiktir, CycloneDX VEX | Ayrıdır; CSAF veya OpenVEX ile yapılır |
| Güvenlik odağı | Yüksektir | Lisans ve uyum odağı ağır basar |
| CRA ve EO uyumu | Kabul edilir | Kabul edilir |

**Argus tavsiyesi.** Birincil format CycloneDX'tir; Rust araçları olgundur, VEX yerleşiktir ve güvenlik odaklıdır. OWASP Dependency-Track ile doğrudan çalışır. İkincil format SPDX'tir; bazı kurumsal ve kamu alıcıları ISO standardı olduğu için SPDX ister, `syft` ile aynı artifact'tan üretilir ve ikinci bir doğruluk kaynağı yaratılmaz. Üçüncü değil temel olan ise `cargo-auditable`'dır; binary'nin içine gömülür, çünkü dosya tabanlı SBOM'lar birbirinden kopar, gömülü olan kopmaz.

> **VEX neden kritiktir.** A.5'te gösterildiği gibi minimal yığında bile 14 `unsound` işaretli bağımlılık vardır. Müşteri Grype veya Trivy çalıştırıp 60 bulguyla gelecektir. Bunların çoğu Argus'un kullandığı kod yolunda sömürülemez. VEX belgesi tam olarak bunu söylemek içindir: bu bileşen etkilenmemektedir, çünkü etkilenen fonksiyon çağrılmamaktadır. VEX üretilmezse destek ekibi bu soruyu her müşteriye elle cevaplar. VEX ürünün parçası yapılmalıdır.

Tüketiciler Dependency-Track (CycloneDX'i doğrudan alır ve sürekli izler), Grype, Trivy ile osv-scanner'dır. Argus müşterilerine SBOM yayımlarken Dependency-Track uyumluluğu hedeflenir.

### D.3 SLSA, 2026 durumu

Güncel sürüm v1.1 değil v1.2'dir; slsa.dev spesifikasyon sayfasında Approved olarak işaretlidir ve v1.1 retired durumundadır.

**Build track, v1.2.**

| Seviye | Ad | Gereksinim |
|---|---|---|
| L0 | Garanti yok | Hiçbir gereksinim yoktur. Tek makinede geliştirme ve testtir |
| L1 | Provenance Exists | Üretici tutarlı bir derleme süreci izler ve provenance'ı tüketicilere dağıtır. Platform, artifact'ı kriptografik digest ile tanımlayan provenance üretir |
| L2 | Hosted ve Authentic | L1'e ek olarak derleme kişisel iş istasyonunda değil barındırılan bir platformda çalışır. Platform provenance'ı kendisi imzalar ve imza anahtarı yalnızca platforma erişilebilirdir. "The build platform MUST have some security control to prevent tenants from tampering." Tüketici imzayı doğrular |
| L3 | Hardened ve Unforgeable | L2'ye ek olarak provenance "strongly resistant to forgery by tenants" olur. Kimlik doğrulama sır materyali güvenli saklanır ve kullanıcı tanımlı derleme adımlarına erişilemez. "Every field in the provenance MUST be generated or verified by the build platform in a trusted control plane." İzolasyon gereği derlemeler platform sırlarına erişemez, eşzamanlı derlemeler birbirini etkileyemez, "An ephemeral build environment MUST be provisioned for each build", cache zehirlenmesi önlenir ve dış servisler provenance parametrelerinde yakalanır |

L4 yoktur; SLSA v0.1'de vardı ve v1.0'da kaldırılmıştır.

**Source track, v1.2'de yenidir** ve v1.2'nin ana yeniliğidir. Dört seviyesi vardır.

| Seviye | Ad | Gereksinim |
|---|---|---|
| L1 | Version Controlled | Modern bir sürüm kontrol sistemi kullanılır ve ayrık kaynak revizyonları mümkündür |
| L2 | History and Provenance | Sürekli ve değişmez branch geçmişi ile her revizyon için provenance attestation'ı bulunur: "tamper-resistant evidence of when changes were made, who made them, and which technical controls were enforced" |
| L3 | Continuous Technical Controls | Korumalı branch'lerde teknik kontroller belgelenir ve uygulanır; doğrulayıcıya güçlü kanıt sunulur |
| L4 | Two-Party Review | "two or more trusted persons" değişiklikleri onaylamadan korumalı branch'e giremez. İçeriden tehdit ve tek taraflı kötü niyetli değişiklik riskini ciddi azaltır |

Ayrıca Source Verification Summary Attestation ile ulaşılan seviye downstream'e bildirilir.

> **Stratejik öneri.** En güvenli IdP iddiasını en ucuz ve en inandırıcı şekilde destekleyecek şey Source Track L4'tür: GitHub'da branch koruması, zorunlu iki onay, imzalı commit ve doğrusal geçmiş. Bu sıfır altyapı maliyetiyle elde edilir ve Ağustos 2026 `arrayref` saldırısının kök nedenine, yani tek bakımcının ele geçirilmesine, doğrudan cevaptır.

**SLSA Build L3'e GitHub Actions ile ulaşmak.**

Önemli bir 2026 güncellemesi vardır: `slsa-github-generator` artık bakılmamaktadır. Son sürümü v2.1.0 ve Şubat 2025 tarihlidir. Deponun ifadesi şudur: "provenance that has already been generated remains valid, and the reusable workflows here continue to work. They should not be assumed to receive updates." Resmî tavsiye "GitHub artifact attestations, a built-in solution for generating SLSA provenance on GitHub" kullanmaktır; doğrulama `slsa-verifier` yerine `gh attestation verify` ile yapılır.

Sunduğu builder'lar tarihsel olarak Go (stable v1.0.0), Node.js (beta v1.6.0), Maven ile Gradle (beta v1.9.0), Docker ve container (beta v1.7.0), Bazel (devam eden iş) ve dil bağımsız Generic generator'dır (stable v1.2.0). Rust'a özel bir builder hiç olmamıştır.

**Argus için doğru yol `actions/attest-build-provenance`'tır.** Artifact'ı, yani ad ile digest'i, in-toto formatlı bir SLSA build provenance predicate'ine bağlar. v4'ten itibaren `actions/attest` üzerine ince bir sarmalayıcıdır. Sigstore kullanır: "short-lived Sigstore-issued signing certificate". Public repo'lar public-good Sigstore instance'ını, private ve internal repo'lar GitHub'ın private Sigstore instance'ını kullanır. Doğrulama `gh attestation verify` ile yapılır. Erişim açısından public repo'lar tüm planlarda kullanabilir, private ve internal repo'lar GitHub Enterprise Cloud gerektirir; Argus kapalı kaynak geliştirilecekse bu bir maliyet kalemidir. Sayfada hangi SLSA seviyesine ulaşıldığı belirtilmemektedir ve doğrulanamamıştır: GitHub'ın barındırdığı runner, geçici sanal makine ve OIDC ile üretilen provenance L3 gereksinimlerini karşılamaya yakındır, ancak bu resmî bir GitHub beyanına dayandırılamamıştır. Pazarlamada SLSA L3 demeden önce doğrulanmalıdır.

```yaml
permissions:
  id-token: write
  contents: read
  attestations: write
steps:
  - uses: actions/attest-build-provenance@v4
    with:
      subject-path: 'target/release/argus'
```

**Küçük ekip için gerçekçi hedef.**

| Hedef | Efor | Argus için |
|---|---|---|
| Build L1 | Yaklaşık bir saat | Hemen |
| Build L2 | Yaklaşık bir gün | Hemen; GitHub'ın barındırdığı runner ve attest action ile |
| Build L3 | Yaklaşık bir hafta | Ulaşılabilirdir; self-hosted runner kullanılmaz, GitHub'ın barındırdığı runner'da kalınır |
| Source L4 | Yaklaşık iki saat | En yüksek getirili hamledir |

> **Self-hosted runner uyarısı.** Kendi runner'ınızı kullanırsanız L3'ün "ephemeral build environment MUST be provisioned for each build" ve "concurrent builds cannot influence each other" gereksinimlerini kendiniz kanıtlamak zorunda kalırsınız. İki ile beş kişilik bir ekip için bu gerçekçi değildir; GitHub'ın barındırdığı runner'da kalınır.

---

## E. İmzalama ve attestation

### E.1 Sigstore

Üç bileşeni vardır: imzalama ve doğrulama istemcisi Cosign, OIDC kimliğine bağlı kısa ömürlü sertifika üreten CA olan Fulcio ve değişmez, yalnızca ekleme yapılan şeffaflık günlüğü Rekor.

Temel fikir şudur: "Sigstore addresses these problems by helping users move away from a key-based signing approach to an identity-based one". Yani uzun ömürlü bir anahtar çifti yönetmek yerine OIDC kimliğiyle geçici anahtar alınır; buna keyless signing denir.

Yönetişim OpenSSF ve Linux Foundation altındadır; katkıcıları Google, Red Hat, Chainguard, GitHub ile Purdue University'dir. Public-good instance ücretsizdir.

Olgunluk açısından Cosign v2 uzun süredir genel kullanıma açıktır ve GitHub'ın yerleşik attestation'ları Sigstore üzerine kuruludur; bu, fiilî ekosistem standardı olduğunun en güçlü göstergesidir.

### E.2 Crate imzalama, crates.io'da var mıdır

Kısa cevap hayırdır.

Kasım 2014'te açılan TUF (The Update Framework) issue'su, yani rust-lang/crates.io#75, geliştiricilerin kendi imzalama anahtarlarını yönetmesini öneriyordu ve kapatılmıştır. Kapanma tarihi ile gerekçesi doğrulanamamıştır, çünkü GitHub sayfası yorumları yükleyememiştir.

crates.io'nun bütünlük modeli imza değil şunlardır. Birincisi SHA-256 checksum'larıdır; index'te ve `Cargo.lock`'ta bulunur ve model ilk kullanımda güven, yani TOFU'dur. İkincisi HTTPS üzerinden sparse index'tir; Ocak 2026'dan itibaren Fastly CDN üzerinden sunulmaktadır. Üçüncüsü Trusted Publishing'dir; bu bir imza değil yayımlama kimlik doğrulamasıdır, G.1'e bakınız. Dördüncüsü `.crate` dosyalarının değişmez olmasıdır; bir sürüm yayımlandıktan sonra üzerine yazılamaz.

`cargo-sigstore` veya crates.io'ya entegre bir crate imzalama çözümünün varlığı doğrulanamamıştır; arama kotası tükendiği için teyit edilememiştir. Bilindiği kadarıyla üretimde kullanılan böyle bir standart yoktur. Argus'un tehdit modelinde crates.io'ya güven, kriptografik yayımcı imzası olarak değil, TOFU ile checksum ve platform güvenliği olarak modellenmelidir.

> **Argus'un yapabileceği.** Kendi crate'lerini, yani SDK'ları, yayımlarken Trusted Publishing kullanılır ve ayrıca her release'in tarball'ı cosign ile imzalanıp GitHub Release'e eklenir. crates.io imza sunmuyorsa siz sunarsınız.

### E.3 in-toto ve SLSA provenance formatı

in-toto attestation bir zarf formatıdır: `subject` (artifact adı ve digest'i), `predicateType` ve `predicate` alanlarından oluşur. SLSA Provenance bir predicate türüdür (`https://slsa.dev/provenance/v1`) ve derlemeyi kimin, hangi kaynaktan, hangi derleme platformunda ve hangi parametrelerle yaptığını söyler. GitHub'ın `attest-build-provenance` eylemi tam olarak bu ikisini üretir ve Sigstore ile imzalar.

**Argus'un üretmesi gereken attestation seti.**

| Attestation | Ne söyler | Araç |
|---|---|---|
| SLSA Provenance | Bu binary bu commit'ten ve bu workflow ile üretilmiştir | `actions/attest-build-provenance` |
| SBOM attestation | Bu binary bu bileşenleri içermektedir | `actions/attest-sbom` veya `cosign attest --type cyclonedx` |
| VEX | Şu CVE bizi etkilememektedir, çünkü | Elle veya OpenVEX ile |
| Test ve tarama attestation'ı | cargo-deny ile cargo-audit temiz geçmiştir | `cosign attest` ile özel predicate |
| Tekrarlanabilirlik attestation'ı | İki bağımsız derleme aynı digest'i vermiştir | Özel predicate; farklılaştırıcıdır |

Son madde Argus'a özgü bir pazarlama ve güvenlik avantajıdır; çok az ürün bunu yapmaktadır.

### E.4 Dağıtımda doğrulama

**cosign ile:**

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/ORG/argus/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/org/argus:v1.2.3
```

Kritik nokta şudur: `--certificate-identity-regexp` ve `--certificate-oidc-issuer` zorunludur. Bunlar olmadan `cosign verify` yalnızca birisinin imzaladığını söyler, bizim imzaladığımızı söylemez. Dokümantasyonda müşterilere tam komut verilmelidir.

**GitHub attestation ile:**

```bash
gh attestation verify ./argus --repo ORG/argus
```

**Kubernetes admission.** Sigstore Policy Controller "can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from cosign" demektedir. Yetenekleri imza ile attestation doğrulama, tag'i digest'e çözme (admission ile runtime arasında tutarlılık sağlar), namespace bazlı politika ve çoklu anahtardır. Durumu 3.908 commit, 178 yıldız ve aylık minor release kadansıdır; son sürüm tarihi doğrulanamamıştır.

Alternatifleri Kyverno (`verifyImages` kuralı; daha geniş bir politika motorudur ve topluluğu daha büyüktür) ile OPA ve Gatekeeper artı ratify'dır.

> **Argus önerisi.** Kendi Kubernetes dağıtımında Kyverno kullanılır; genel amaçlı bir politika motoru olarak zaten işe yarar. Müşterilere ise doğrulama komutları ile public key ve kimlik bilgisi kurulum dokümanının ilk sayfasında verilir. Bir IdP'de imaj doğrulaması opsiyonel bir güzellik değil, kurulum adımıdır.

---

## F. Rust tedarik zinciri saldırıları

Bu bölüm raporun en güçlü kanıt tabanına sahip kısmıdır: RustSec advisory veritabanı klonlanmış ve kötü amaçlı kod advisory'lerinin tamamı çıkarılmıştır.

### F.1 Kötü amaçlı crate advisory'lerinin tam envanteri

`categories = ["malicious"]` içeren 75 advisory vardır. Yıllara göre dağılımı şöyledir.

| Yıl | Sayı |
|---|---|
| 2022 | 1 |
| 2023 | 28 |
| 2024 | 0 |
| 2025 | 14 |
| 2026 | 32, 8 Eylül'e kadar |

2024'te sıfır, 2026'da rekor vardır; trend açıkça kötüleşmektedir.

### F.2 `rustdecimal`, 2022, ilk vaka

RUSTSEC-2022-0042, 10 Mayıs 2022. Yaygın finansal ondalık sayı crate'i olan `rust_decimal`'ın tipo eşkıyalığıdır. Rust ekosisteminin ilk kamuya açık kötü amaçlı crate vakası ve `malicious` kategorisinin tek 2022 kaydıdır.

### F.3 2023, kitlesel tipo eşkıyalık kampanyaları

28 advisory iki dalga hâlinde gelmiştir.

Ağustos 2023 dalgası, 16 Ağustos: `envlogger`, `if-cfg`, `lazystatic`, `oncecell`, `postgress`, `serd`, `xrvrv` ve 18 Ağustos'ta `postgresderive`. Hedefleri `env_logger`, `cfg-if`, `lazy_static`, `once_cell`, `postgres` ve `serde`'dir; hepsi en popüler crate'lerin tipo varyantlarıdır.

Kasım 2023 dalgası, 6 ile 22 Kasım arası, Windows ve kripto odaklıdır: `windows-service-rs`, `windowsservice`, `win-crypto`, `win-base64-rs`, `win_run_rs`, `winx-rs`, `registry-win`, `libusb1-main`, `openvpn-plugin-rs`, `monero-api`, `monero-rpc-rs`, `acceptxmr-rs`, `lasso-rs`, `lfest-main`, `hann-rs-service`, `tiny-server`, `littest`, `bit-flags`, `tauri-winrt-notifications`, `tauri-win-rt-notification`. Kripto para (Monero, AcceptXMR) ve Windows sistem API'leri hedefi belirgindir.

### F.4 2025, kripto ile DeFi'ye ve altyapıya kayış

14 advisory vardır.

| Tarih | Crate | Not |
|---|---|---|
| 30 Ocak 2025 | `custom-req-on-workers`, `jfrog_quotes` | — |
| 10 Şubat 2025 | `rands` | `rand` tiposudur |
| 15 Şubat 2025 | `sophosfirewall-python` | Rust'ta Python adıdır; çapraz ekosistem kafa karıştırmadır |
| 10 Mart 2025 | `tree-sitter-pkl` | — |
| 26 Ağustos 2025 | `statsrelay-protobuf` | — |
| 4 Kasım 2025 | `replit_ruspty` | Replit'in gerçek paketinin tiposudur |
| 3 Aralık 2025 | `uniswap-utils`, `evm-units` | DeFi |
| 5 Aralık 2025 | `sha-rust`, `finch-rust` | — |
| 9 Aralık 2025 | `sha-rst`, `finch-rst`, `finch_cli_rust` | — |

Aralık 2025'teki `finch-*` ve `sha-*` kümesi tek bir koordineli kampanyadır; beş crate altı gün içinde yayımlanmıştır.

### F.5 2026, 32 advisory ve nitel bir sıçrama

**F.5.1 Şubat ile Mart 2026: Polymarket kümesi ve CI/CD sır hırsızlığı.**

Polymarket tipoları dört crate'tir: `polymarket-clients-sdk` (6 Şubat), `polymarket-client-sdks` (13 Şubat), `polymarkets-client-sdk` (19 Şubat), `polymarkets-rs-clob-client` (20 Şubat); ayrıca `clob-sdk` (20 Şubat) ile `rpc-check` (19 ve 24 Şubat, iki ayrı advisory).

Beş kötü amaçlı Rust crate'i kampanyası 11 Mart 2026'da The Hacker News tarafından yayımlanmıştır. Crate'ler `chrono_anchor`, `dnp3times`, `time_calibrator`, `time_calibrators` ve `time-sync`'tir; hepsi zamanla ilgili yardımcı program kılığındadır. Socket'ten Kirill Boychenko'nun ifadesi şudur: "Their core behavior is credential and secret theft." Hedefleri `.env` dosyaları, yani API anahtarları ile token'lardır. `chrono_anchor` en gelişmiş olanıdır; exfiltration mantığını `guard.rs` adlı bir dosyaya gömerek tespitten kaçınmaktadır. Kalıcılık kurmamakta, bunun yerine CI iş akışlarında her çağrıldığında `.env` çalmayı yeniden denemektedir. Yayın Şubat sonu ile Mart başı 2026'dır ve bulan Socket'tir.

RustSec kayıtları şöyledir: `chrono_anchor` RUSTSEC-2026-0039 (10 Mart), `dnp3times` RUSTSEC-2026-0032 (4 Mart), `time_calibrator` RUSTSEC-2026-0030 ile `time_calibrators` RUSTSEC-2026-0031 (3 Mart), `time-sync` RUSTSEC-2026-0036 (4 Mart). Ayrıca ilişkili olarak `tracing-check` RUSTSEC-2026-0019, `tracings` RUSTSEC-2026-0027, `tracing_checks` RUSTSEC-2026-0028 ("for transitively including malicious code") ve `tracing-ethers` RUSTSEC-2026-0040 vardır.

> **Doğrudan ders.** Bu kampanya CI'daki `.env` dosyalarını hedeflemiştir. Argus'un CI'sında hiçbir zaman `.env` dosyası bulunmamalıdır; sırlar OIDC ile kısa ömürlü token olarak alınmalı, dosyaya yazılmamalıdır.

**F.5.2 20 Ağustos 2026, `arrayref` saldırısı ve Rust ekosisteminin dönüm noktası.**

Bu, Rust'ın "npm'de olur bizde olmaz" dönemini bitiren olaydır. Tipo eşkıyalığı değil, gerçek ve popüler crate'lerin ele geçirilmesidir.

| Crate | Kötü sürüm | Toplam indirme, on yıl |
|---|---|---|
| `arrayref` | 0.3.10 | Yaklaşık 245.000.000 |
| `internment` | 0.8.7 | Yaklaşık 14.400.000 |
| `append-only-vec` | 0.1.9 | Yaklaşık 4.500.000 |

Zaman çizelgesi, tüm saatler UTC:

```
07:15  arrayref@0.3.10 yayımlandı  |  Güvenlik ekibine ilk rapor ulaştı (aynı dakika)
07:29:50  Socket'in AI tarayıcısı proc-macro1'i bağımsız tespit etti
07:34  internment@0.8.7 yayımlandı
07:37  append-only-vec@0.1.9 yayımlandı
08:41–09:25  Kötü amaçlı sürümler silindi
```

Yayında kalma süreleri `arrayref` için 86 dakika, `internment` için 90 dakika ve `append-only-vec` için 107 dakikadır.

Saldırı mekanizması üç aşamalıdır. Birinci aşama dropper enjeksiyonudur: saldırgan kötü kodu doğrudan gömmemiş, bunun yerine meşru crate'lere `proc-macro2`'nin tipo eşkıyası olan `proc-macro1` adlı yeni bir bağımlılık eklemiştir. RUSTSEC-2026-0260'ın ifadesi şudur: "That line added a dependency never seen before in a decade of the package's history." İkinci aşama dropper'ın kendisidir, yani `proc-macro1`'in `build.rs` dosyası. JFrog'un kritik notu şudur: "In Rust, a `build.rs` script is compiled and executed automatically during `cargo build`, `cargo check`, and similar commands, including CI and rust-analyzer driven builds." Yani crate'ten hiçbir fonksiyon çağırmak gerekmez, derlemek yeterlidir, hatta editörde açmak yeterlidir. Üçüncü aşama payload'dır: platforma özel payload indirilip C2 argümanlarıyla çalıştırılmıştır ve Linux, Windows ile macOS hedeflenmiştir.

JFrog'un bildirdiği teknik göstergeler şunlardır: C2 URL'leri bölünmüş Base64 parçalarıyla gizlenmiştir; TLS sertifika doğrulaması kasten kapatılmıştır; Unix'te `/tmp/rust-setup` dosyasına yazılmıştır; Windows'ta PowerShell execution policy bypass'ı kullanılmıştır; payload analiz için ele geçirilememiştir.

Erişimin nasıl sağlandığı konusunda Rust güvenlik ekibinin ifadesi şudur: "We do not believe the author of `arrayref` to be acting maliciously, but their computer or credentials are likely compromised." Yani bakımcının makinesi veya kimlik bilgileri ele geçirilmiştir, gönüllü bir işbirliği yoktur.

Etki açısından `arrayref` 0.3.10 yalnızca 2.285 kez indirilmiştir; bu, tüm sürümler arasındaki trafiğin %10'undan azıdır, çünkü çoğu kullanıcının `Cargo.lock` dosyasında eski sürüm sabitliydi.

> **Argus için en önemli tek çıkarım.** `Cargo.lock`'u commit etmek bu saldırıda kullanıcıların %90'ını kurtarmıştır.

crates.io müdahalesi şöyledir: kötü sürümler silinmiş, meşru olarak yanklanmış sürümler geri alınmış ve yazarın hesabı önlem olarak kilitlenmiştir. `proc-macro1` (iki sürüm) ile `proc-macro-en` (bir sürüm) tamamen silinmiş, ilgili hesaplar kilitlenmiştir.

Bildirenler RUSTSEC-2026-0265'e göre "the Research Team at Nextron Systems GmbH"tir; koordinasyon için "Emily Albini for coordinating with the crates.io and infra-admin teams" denmektedir. Bazı kaynaklar Kuzey Kore bağlantısı iddia etmektedir, ancak bu doğrulanamamıştır; resmî Rust blogu atıf yapmamaktadır.

**F.5.3 Mayıs 2026, TrapDoor ve çok ekosistemli kampanya.** Kaynak 25 Mayıs 2026 tarihli The Hacker News haberidir; keşfi Socket.dev yapmıştır. 34'ten fazla kötü amaçlı paket ve 384'ten fazla sürüm vardır. npm'de 20 paket bulunmaktadır: `async-pipeline-builder`, `crypto-credential-scanner`, `web3-secrets-detector` ve diğerleri. PyPI'da yedi paket vardır: `cryptowallet-safety`, `eth-security-auditor`, `solidity-build-guard` ve diğerleri. crates.io'da altı Rust crate'i vardır: `move-analyzer-build`, `sui-framework-helpers` ve diğerleri. Hedef kitle kripto, DeFi, Solana ve AI topluluklarıdır. Çalınanlar geliştirici sırları, kripto cüzdanlar, SSH anahtarları, bulut kimlik bilgileri, tarayıcı verisi ve ortam değişkenleridir. İlk aktivite 22 Mayıs 2026 saat 20.20 UTC'dir.

RustSec'te ilgili kayıtlar `sui-execution-cut` RUSTSEC-2026-0108 (23 Nisan) ile `mysten-metrics` RUSTSEC-2026-0107'dir (22 Nisan); hedef Sui ve Move ekosistemidir.

**F.5.4 Haziran 2026, `onering`.** RUSTSEC-2026-0175, 10 Haziran 2026, `onering` 1.4.1, kod exfiltration'ıdır. Aikido tarafından raporlanmıştır.

**F.5.5 6 ile 7 Eylül 2026, PolinRider crates.io'ya ulaştı.** Bu, raporun en taze bulgusudur; RUSTSEC-2026-0280, 7 Eylül 2026:

> "A new version of the `greentic-setup-dev` crate was published with a variant of the PolinRider malware included that would fire when a project depending on `greentic-setup-dev` was opened in Visual Studio Code."
>
> "One malicious version was published on 2026-09-06, approximately 27 hours before removal. This crate has no dependencies on crates.io. We have no evidence that this crate version was downloaded by any actual users."
>
> "Thanks to the Research Team at Nextron Systems GmbH for the report."

Kardeş advisory RUSTSEC-2026-0281, `greentic-setup` 1.3.1-dev.34027618345'tir.

PolinRider, Kuzey Kore bağlantılı (Lazarus Group ve APT37) çok ekosistemli bir kampanyadır. npm, Packagist, Go modülleri ve Chrome Web Store'da en az 108 kötü amaçlı paket ile tarayıcı eklentisi vardır. Tekniği gizlenmiş JavaScript'i ele geçirilmiş geliştiricilerin `.vscode/tasks.json` dosyalarında, sahte `.woff2` fontlarında ve `tailwind.config.js`, `postcss.config.mjs`, `eslint.config.mjs`, `App.js` ile `babel.config.cjs` gibi meşru yapılandırma dosyalarında saklamaktır. Payload'ları DEV#POPPER ile OmniStealer'dır ve keyfi komut çalıştırma, kimlik bilgisi toplama, tarayıcı verisi exfiltration'ı, kripto cüzdan hırsızlığı ile `socket.io-client` üzerinden C2 yaparlar. Kaynakları socket.dev'in PolinRider yazısı, rescana.com ve sonatype.com'dur.

> **Kritik ders.** Bu saldırı `build.rs` bile kullanmamaktadır; VS Code'un `tasks.json` mekanizmasını kullanmaktadır. Yani `cargo build`'i sandbox'lamak yetmez. Bir bağımlılığın kaynak ağacındaki `.vscode/` dizini bir saldırı vektörüdür. `cargo vendor` sonrası vendor edilmiş ağaçta `.vscode/`, `.devcontainer/` ve `.githooks/` dizinleri taranmalı ve CI'da reddedilmelidir.

### F.6 npm ile karşılaştırma ve Shai-Hulud

Shai-Hulud gerçektir ve iki dalga geçirmiştir.

**Birinci dalga, Eylül 2025.** ReversingLabs 15 Eylül 2025'te, Checkmarx 16 Eylül 2025 sabahı tespit etmiştir. Adı Frank Herbert'in Dune romanındaki kum solucanından gelmektedir. İlk kendini kopyalayan tedarik zinciri saldırısı olduğuna inanılmaktadır. Başlangıcı npm güvenlik uyarısı kılığında bir oltalama e-postasıyla bir geliştiricinin kimlik bilgilerinin çalınmasıdır. Mekanizması şöyledir: `postinstall` script'i GitHub token'ı, npm token'ı, AWS ile GCP kimlik bilgileri, Atlassian anahtarları ve Datadog API anahtarlarını toplar; çalınan GitHub token'ıyla erişilebilen repolara `shai-hulud-workflow.yml` adlı bir GitHub Actions workflow'u eklenip tetiklenir; çalınan npm token'ıyla o hesabın diğer paketlerine kod enjekte edilir. Etkisi ilk anda 180'den fazla paket, sonra 500'den fazladır. CISA 23 Eylül 2025'te resmî uyarı yayımlamıştır: "Widespread Supply Chain Compromise Impacting npm Ecosystem".

**İkinci dalga, Kasım 2025, Shai-Hulud 2.0 veya The Second Coming.** Unit 42'nin 26 Kasım 2025 güncellemesi ile SecurityWeek kaynaktır. Yaklaşık 350 farklı GitHub kullanıcısında 25.000'den fazla kötü amaçlı repo vardır; SecurityWeek 640 npm paketi bildirmiştir. Birinci değişiklik çalışmanın `postinstall`'dan `preinstall`'a taşınmasıdır: "execution on virtually every build server processing the infected package". İkinci ve yıkıcı değişiklik şudur: kimlik bilgisi hırsızlığı başarısız olursa malware kurbanın tüm home dizinini güvenli üzerine yazma ile yok etmeye çalışmaktadır. Üçüncü değişiklik yeni payload'lar olan `setup_bun.js` ile `bun_environment.js`'tir; ikincisi 10 MB'tan büyük ve aşırı gizlenmiştir. Dördüncü değişiklik GitHub Actions workflow dosyalarıyla self-hosted runner kaydı yaparak kalıcılık ve keyfi komut çalıştırma sağlamaktır.

npm ile GitHub'ın müdahalesi doğrulanamamıştır; arama kotası nedeniyle token politikası değişiklikleri teyit edilememiştir.

**Rust ile npm'in yapısal karşılaştırması.**

| Boyut | npm | Rust ve crates.io | Argus için anlamı |
|---|---|---|---|
| Kurulum anı kod | `postinstall` ile `preinstall`; `--ignore-scripts` ile kapatılabilir | `build.rs` ile proc-macro; kapatılamaz | Rust daha kötüdür |
| Kendini kopyalayan solucan | İki kez gerçekleşmiştir | Henüz yoktur | Rust daha iyidir |
| Ekosistem büyüklüğü | Yaklaşık 3 milyon paket | Yaklaşık 180 bin crate | Hedef yüzeyi küçüktür |
| Bağımlılık sayısı | Genelde çok daha fazladır | Ölçümde 243 | Rust daha iyidir |
| Lockfile normu | Vardır ancak tutarsızdır | `Cargo.lock` commit etmek standarttır | arrayref'te kullanıcıların %90'ını kurtarmıştır |
| Paket silme | Karmaşıktır, left-pad örneği | `yank` silmez; silme yalnızca malware içindir | Rust daha iyidir |
| Tespit süresi | Günler ile haftalar | arrayref'te 86 dakika | Rust çok daha iyidir |
| Yayımcı imzası | Yoktur; provenance vardır | Yoktur | İkisi de zayıftır |

> **Sonuç.** Rust'ın avantajı ekosistem olgunluğunda değil küçüklüğünde ve `Cargo.lock` normundadır. `build.rs` konusunda Rust npm'den daha savunmasızdır. "Rust yazdık, güvendeyiz" denmez.

### F.7 xz ve liblzma, CVE-2024-3094, bakımcı güveni dersleri

Bu bölüm genel bilinen olay bilgisidir; arama kotası bittiği için bu oturumda ayrıca doğrulanamamıştır.

Bilinen çerçeve şudur: "Jia Tan" kimliği, iki yıldan uzun süren bir sosyal mühendislik operasyonuyla `xz-utils`'te ortak bakımcı statüsü kazanmış, ardından test dosyalarına gizlenmiş ve derleme sistemi üzerinden, yani `configure` ile `m4` makroları üzerinden enjekte edilen bir sshd arka kapısı yerleştirmiştir. Mart 2024'te Andres Freund tarafından bir performans anomalisi sayesinde tesadüfen bulunmuştur.

**Argus için beş somut ders.**

Birincisi arka kapının kaynak repoda değil release tarball'ında olmasıdır. Argus asla el yapımı tarball yayımlamamalıdır; her artifact imzalı bir git etiketinden ve provenance ile üretilmelidir. SLSA Build L2 ile L3'ün var olma sebebi budur.

İkincisi derleme sisteminin bir saldırı yüzeyi olmasıdır. xz'de `m4` makroları, Rust'ta `build.rs` bunu sağlar; ölçüme göre yığında 26 tanesi vardır. Kod incelemesi `build.rs` değişikliklerini `src/` değişikliklerinden daha sıkı incelemelidir.

Üçüncüsü test verisi ikili dosyalarının payload taşımasıdır. Bağımlılıklarda ve kendi repoda `tests/fixtures/*.bin` benzeri sıkıştırılmış veya opak dosyalara dikkat edilmelidir; Argus'un CI'sı yeni ikili dosyaları işaretlemelidir.

Dördüncüsü tek bakımcılı kritik crate'lerin yapısal bir risk olmasıdır. `cargo-supply-chain` ile bağımlılıkların yayımcı sayısı çıkarılır; tek kişiye bağlı ve kritik yolda olanlar forklanacak veya değiştirilecek listesine alınır.

Beşincisi sosyal mühendisliğin uzun vadeli olmasıdır. Argus'un kendi projesinde yeni katkıcıya commit hakkı verme süreci yazılı olmalı, iki kişi onayı (SLSA Source L4) ve bir bekleme süresi bulunmalıdır. `arrayref` saldırısı da tek kişilik bir yayımlama sürecinin kırılmasıydı.

---

## G. crates.io güvenlik önlemleri

### G.1 Trusted Publishing

Lansmanı 11 Temmuz 2025'tir; RFC numarası 3691'dir.

**Nasıl çalışır.** crates.io'da güvenilir bir yayımcı yapılandırılır ve şu OIDC claim'leri eşleştirilir:

| Alan | Anlamı |
|---|---|
| `owner` | GitHub kullanıcı veya organizasyon adı |
| `repo` | Depo adı |
| `workflow` | `.github/workflows/` altındaki workflow dosya adı |
| `environment` | GitHub Actions ortam adı, opsiyoneldir |

crates.io, GitHub'ın verdiği kimlik token'ını geçici bir erişim token'ıyla takas eder. RFC'nin ifadesi şudur: "access tokens are used as if it was an API token and actually permits access to perform API actions." Başlangıçta "a long enough lifetime" verilir ve workflow bittiğinde iptal talep etmelidir. Kesin TTL değeri doğrulanamamıştır.

```yaml
permissions:
  id-token: write
steps:
  - uses: rust-lang/crates-io-auth-action@v1
    id: auth
  - run: cargo publish
    env:
      CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}
```

İlk sürümü elle yayımlamak gerekir; sonrasında trusted publishing açılabilir.

**Neyi önler ve neyi önlemez.** Önledikleri şunlardır: uzun ömürlü API token'larının CI secret'larında durması; token sızarsa herhangi bir yerden kullanılabilmesi; elle iptal gerekliliği. Önlemedikleri RFC'nin kendi ifadesiyle şunlardır: "Compromises of actions within the specified workflow" ve "Supply chain attacks if the workflow itself is malicious".

> **Argus için kritik nüans.** Trusted Publishing token hırsızlığını çözer, workflow'un içindeki bir action'ın ele geçirilmesini çözmez. Bu yüzden tüm GitHub Actions commit SHA'sıyla pinlenir (`uses: actions/checkout@8f4b7f8...` biçiminde, `@v4` değil); yayımlama workflow'u zorunlu inceleyicilerle korunan ayrı bir ortam altında çalıştırılır; yayımlama workflow'u en az sayıda action kullanır.

**2026 güncellemeleri.** 21 Ocak 2026 tarihli güncelleme Argus için doğrudan ilgili üç madde getirmiştir. Birincisi GitLab CI/CD desteğidir; GitHub Actions'a ek olarak gelmiştir ve GitLab.com ile sınırlıdır. İkincisi yalnızca Trusted Publishing modudur: crate sahipleri klasik API token'larını tamamen devre dışı bırakabilmektedir. Argus kendi crate'lerini yayımlıyorsa bu açılmalıdır, çünkü `arrayref` tipi "bakımcının token'ı çalındı" saldırısını yapısal olarak imkânsızlaştırır. Üçüncüsü tehlikeli GitHub Actions tetikleyicilerinin bloklanmasıdır: `pull_request_target` ile `workflow_run` artık kabul edilmemektedir; bunlar fork'tan gelen PR'ların yazma yetkili bağlamda kod çalıştırmasına izin veren klasik yetki yükseltme vektörleridir.

### G.2 Diğer crates.io güvenlik özellikleri, Ocak 2026 güncellemesi

Crate sayfasına RustSec advisory'lerini gösteren bir Security sekmesi eklenmiştir: "quickly see if a crate has known vulnerabilities before adding it as a dependency."

Index'e `pubtime` alanı eklenmiştir; bu, cooldown ile tarihsel bağımlılık çözümlemesinin, yani `lockfile-publish-time` özelliğinin altyapısıdır. C.3'teki en önemli gelecek özelliğini bu mümkün kılmıştır.

GitHub OAuth token'ları artık veritabanında şifreli saklanmaktadır.

`tokei` ile hesaplanan SLOC metrikleri crate sayfalarında gösterilmektedir; bir crate'in gerçek boyutu eklenmeden önce görülebilir ve minimizasyon için faydalıdır.

İndirme grafiklerinden bot, scraper ve mirror trafiği filtrelenmektedir; bu, bir crate'in gerçekte ne kadar kullanıldığı sorusuna daha dürüst cevap verir.

Sparse index'i Fastly CDN sunmaktadır. Frontend Svelte ile TypeScript'e taşınmakta ve OpenAPI'den tip güvenli istemciler üretilmektedir.

### G.3 Rust Foundation Security Initiative

Kaynak rustfoundation.org'un 12 Mayıs 2025 tarihli Alpha-Omega ilerleme güncellemesidir.

| Araç | Ne yapar | Durum |
|---|---|---|
| typomania | Tipo eşkıyalığı tespit eder; `typogard`'ın Rust portudur ve herhangi bir registry'ye uyarlanabilir bir kütüphanedir | Olgundur; Rust bakımcıları ve dış güvenlik araştırmacıları kullanmaktadır |
| painter | crates.io ekosistemindeki tüm crate'ler arası bağımlılık ve çağrı grafiğinin graph veritabanıdır; `unsafe` istatistikleri, çağrı grafiği budama ve FFI sınır haritalama sunar | Olgundur |
| Crate provenance tracking | crates.io'ya yayımlanan her crate'in provenance'ını izler | Devreye alınmıştır |
| Real-time crate scanning | Paketlerde açık ve malware tespiti yapar | Geliştirme aşamasındadır |
| cargo-cgsec | Google'ın Capslock'unun Rust'a uyarlanmış hâlidir; yetenek analizi yapar | Deneyseldir |
| Trusted Publishing | G.1'e bakınız | Uygulanmıştır |

Fonlama OpenSSF Alpha-Omega projesindendir; 2025'te Trusted Publishing ile Capslock uygulaması için ek 216.000 ABD doları hibe verilmiştir. Diğer bir çıktı olarak 2025 başında crates.io ekosistemi ile Rust çekirdek altyapısı için tehdit modelleri yayımlanmıştır.

**2026: AI Security Engineer in Residence.** Kaynak alpha-omega.dev'in 16 Haziran 2026 tarihli yazısıdır. Rust Foundation, Alpha-Omega fonuyla bir pozisyon açmıştır. Çözdüğü problem şudur: AI araçları hem gerçek bulgular hem devasa hacimde değersiz rapor üretmekte ve bakımcılar sinyal gürültü oranı altında ezilmektedir. Görevleri "use a mix of human-led and AI-assisted methods to proactively review Rust itself and the crates" biçiminde tanımlanmıştır; en çok güvenilen crate'leri proaktif incelemek, gerçek ve sömürülebilir sorunları yanlış pozitiflerden bakımcıya ulaşmadan önce ayırmak ve Project Glasswing gibi girişimlerden gelen raporlara temas noktası olmaktır. Başlangıçta altı ay fonlanmıştır ve uzatma opsiyonludur: "methods, playbooks, and prompts will be documented so the work doesn't end with the contract." Sonuç metrikleri henüz yoktur, çünkü bu bir duyurudur, rapor değildir.

> **Argus için anlamı.** Bir IdP olarak size de AI üretimi güvenlik raporları gelecektir. Şimdiden bir triyaj politikası yazılır: yeniden üretici olmayan, CVSS'i gerekçelendirilmemiş ve AI imzası taşıyan raporlar için ayrı bir kuyruk açılır.

### G.4 Index bütünlüğü ve TUF

SHA-256 checksum'ları index'te ve `Cargo.lock`'tadır; model ilk kullanımda güvendir, yani ilk indirmede checksum kabul edilir ve sonrasında değişiklik tespit edilir. Sparse index HTTPS üzerinden sunulmaktadır; Ocak 2026'dan beri Fastly CDN üzerindedir. `.crate` dosyaları değişmezdir ve yayımlandıktan sonra üzerine yazılamaz. TUF uygulanmamıştır; Kasım 2014 tarihli rust-lang/crates.io#75 issue'su kapatılmıştır ve aktif bir TUF planı doğrulanamamıştır.

**Boşluk analizi, Argus'un tehdit modeline yazılmalıdır.** crates.io'da yayımcı tarafında kriptografik imza yoktur. Güven zinciri HTTPS, crates.io platform güvenliği, checksum ve opsiyonel Trusted Publishing'den oluşur. crates.io altyapısı ele geçirilirse veya bir yayımcının hesabı ele geçirilirse, ki `arrayref`'te tam olarak bu olmuştur, checksum'lar korumaz, çünkü kötü amaçlı içeriğin checksum'ı da doğrudur.

Argus bu boşluğu şöyle kapatır. `Cargo.lock` commit edilir; arrayref'te %90 koruma sağladığı kanıtlıdır. `cargo vendor` yapılır ve imzalı vendor tarball'ı arşivlenir. Bağımlılık güncellemeleri en az yedi günlük bir cooldown ile toplu hâlde yapılır. `cargo-vet` ile denetim durumu takip edilir. Yeni bir `build.rs` bağımlılığı CI'da alarm üretir.

### G.5 Token yönetimi, iki adımlı doğrulama ve yanking

**API token'ları.** crates.io endpoint kapsamlı token'ları desteklemektedir; örneğin yalnızca `publish-update`. Kesin kapsam listesi doğrulanamamıştır, çünkü crates.io tek sayfa uygulaması olduğu için doküman sayfası çekilememiştir.

**Cargo tarafında credential provider'lar.**

```toml
[registry]
global-credential-providers = ["cargo:token", "cargo:libsecret",
                               "cargo:macos-keychain", "cargo:wincred"]
```

Sonraki girişler daha yüksek önceliklidir. `cargo:token` sağlayıcısı token'ı düz metin olarak cargo'nun credentials dosyasında veya `CARGO_REGISTRIES_<NAME>_TOKEN` ortam değişkeninde saklar.

> **Argus geliştirici politikası.** `cargo:token` kullanılmaz. macOS'ta `cargo:macos-keychain`, Linux'ta `cargo:libsecret` kullanılır. Bu, geliştirici makinesindeki bir bilgi hırsızının, yani PolinRider veya TrapDoor'un, crates.io token'ını düz metin okumasını engeller; `arrayref` saldırısının muhtemel giriş vektörü tam olarak buydu.

**İki adımlı doğrulama.** Yayımlama için zorunluluğun güncel durumu bu oturumda teyit edilememiştir. Ancak Ocak 2026'da gelen yalnızca Trusted Publishing modu iki adımlı doğrulamadan daha güçlü bir kontroldür ve mevcuttur; o kullanılır.

**Yanking ve silme politikası**, RustSec advisory'lerinden gözlemlenen davranışa göre şöyledir. `cargo yank` sonrası sürüm mevcut lockfile'lardan çözülmeye devam eder ve yeni çözümlemede seçilmez; bu bir silme değildir. Gerçek silme yalnızca crates.io ekibi tarafından ve kötü amaçlı kod için yapılır; advisory'de `expect-deleted = true` alanıyla işaretlenir, RUSTSEC-2026-0264 ile 0265 örnektir. Hesap kilitleme ele geçirme şüphesinde uygulanır; `arrayref` ile `proc-macro1` örnektir. Ad eşkıyalığı politikasının resmî metni doğrulanamamıştır.

---

## H. Argus için somut yol haritası

### H.1 Öncelik matrisi

| # | Aksiyon | Efor | Kazanç | Kanıt |
|---|---|---|---|---|
| 1 | `Cargo.lock` commit edilir ve her yerde `--locked` kullanılır | 5 dakika | Çok yüksek | arrayref'te kullanıcıların %90'ını kurtarmıştır |
| 2 | `cargo-deny` CI kapısı: `bans licenses sources` | 2 saat | Çok yüksek | `allow-git=[]` git kaçış deliğini kapatır |
| 3 | `cargo-audit` günlük iş ve release kapısı olarak | 1 saat | Çok yüksek | 1.222 advisory'lik veritabanı günlük günceldir |
| 4 | SLSA Source L4: branch koruması, iki onay ve imzalı commit | 2 saat | Çok yüksek | arrayref ile xz'nin kök nedenidir |
| 5 | Her bağımlılıkta `default-features = false` | 1 gün | Yüksek | Ölçümle %30 crate ve %53 proc-macro azalması |
| 6 | webauthn-rs ile OpenSSL zincirini kesmek | 3 gün | Yüksek | Ölçümle native C kripto sıfırlanır |
| 7 | `cargo-auditable` ile derlemek | 30 dakika | Yüksek | 4 KB'tan az maliyetle CRA Ek I Bölüm II.1 karşılanır |
| 8 | Bağımlılık cooldown'u en az yedi gün; Renovate `minimumReleaseAge` | 1 saat | Çok yüksek | 86 ile 107 dakikalık saldırı penceresini kapatır |
| 9 | `actions/attest-build-provenance` | 2 saat | Yüksek | SLSA Build L2 ile L3 |
| 10 | Actions'ları SHA ile pinlemek | 2 saat | Yüksek | Trusted Publishing'in kapatmadığı boşluktur |
| 11 | Tekrarlanabilir derleme ve CI kapısı | 1 hafta | Orta ile yüksek | Ölçümle üç remap kuralı yeterlidir |
| 12 | CycloneDX SBOM ile VEX yayını | 3 gün | Yüksek | CRA ile 11 Aralık 2027'de zorunludur |
| 13 | `cargo-vet` ve özel kriterler | 2 hafta | Orta ile yüksek | Ölçümle %51 ile %91 hazır kapsam |
| 14 | Denetlenmemiş 14 crate'i elle denetlemek | 3 hafta | Yüksek | `argon2`, `sqlx`, ASN.1 |
| 15 | Kripto ile protokol çekirdeğini `no_std` crate'lere ayırmak | 1 ay | Orta ile yüksek | Denetim maliyetini düşürür |
| 16 | CRA madde 14 raporlama süreci | 1 hafta | Yasal | Steward'lar için 11 Aralık 2027, üreticiler için 11 Eylül 2026 |

### H.2 Hemen bugün yapılacaklar, ilk hafta

```bash
# 1. Toolchain sabitle
cat > rust-toolchain.toml <<'EOF'
[toolchain]
channel = "1.98.1"
components = ["rustfmt", "clippy"]
profile = "minimal"
EOF

# 2. Araçları kur
cargo install cargo-deny cargo-audit cargo-auditable cargo-machete cargo-vet

# 3. cargo-vet başlat (mevcut durumu exemption olarak kaydeder)
cargo vet init

# 4. Beş büyük audit setini import et
# supply-chain/config.toml içine:
#   [imports.mozilla] url = "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml"
#   [imports.google]  url = "https://raw.githubusercontent.com/google/supply-chain/main/audits.toml"
#   [imports.bytecode-alliance] url = "https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml"
#   [imports.zcash] url = "https://raw.githubusercontent.com/zcash/rust-ecosystem/main/supply-chain/audits.toml"
#   [imports.isrg]  url = "https://raw.githubusercontent.com/divviup/libprio-rs/main/supply-chain/audits.toml"
cargo vet check      # gerçek kapsama oranınızı görün
```

### H.3 CI iskeleti

```yaml
name: supply-chain
on: [pull_request, push]
permissions: { contents: read }

jobs:
  gate:                       # deterministik — her PR'da bloklar
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>
      - uses: EmbarkStudios/cargo-deny-action@<SHA>
        with: { command: check bans licenses sources }
      - run: cargo vet --locked
      - run: cargo machete
      - name: build.rs sürprizi var mı?
        run: |
          cargo metadata --format-version 1 --locked \
            | jq -r '.packages[] | select(.build != null) | .name' | sort > /tmp/now.txt
          diff .supply-chain/buildrs-allowlist.txt /tmp/now.txt \
            || { echo "::error::Yeni build.rs bağımlılığı — insan onayı gerekli"; exit 1; }
      - name: vendored ağaçta gizli çalıştırma vektörü
        run: |
          cargo vendor --versioned-dirs /tmp/v >/dev/null
          find /tmp/v -maxdepth 2 \( -name '.vscode' -o -name '.devcontainer' -o -name '.githooks' \) \
            | tee /tmp/hits.txt
          [ ! -s /tmp/hits.txt ] || { echo "::error::PolinRider vektörü"; exit 1; }

  advisories:                 # dış veriye bağlı — ayrı job + günlük cron
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>
      - run: cargo audit --deny warnings
      - uses: EmbarkStudios/cargo-deny-action@<SHA>
        with: { command: check advisories }
```

---

## I. Doğrulanamayan ve eksik kalan maddeler

Dürüstlük için tam liste şudur.

1. cargo-crev'in güncel inceleme sayısı: `web.crev.dev` 8 Eylül 2026'da 502 döndürmüştür; yalnızca indirme verisi elde vardır, 90 günde 1.380.
2. crates.io'da yayımlama için iki adımlı doğrulama zorunluluğu: güncel durum teyit edilememiştir.
3. crates.io API token kapsamlarının tam listesi: tek sayfa uygulaması olduğu için doküman çekilememiştir.
4. crates.io ad eşkıyalığı ve namespace resmî politika metni: çekilememiştir.
5. `cargo-sigstore` veya crates.io için crate imzalama çözümü: varlığı doğrulanamamıştır; bilindiği kadarıyla üretim standardı yoktur.
6. `actions/attest-build-provenance`'ın resmî SLSA seviyesi: GitHub sayfası belirtmemektedir. SLSA L3 iddiası doğrulanmadan pazarlamada kullanılmaz.
7. CRA yürürlüğe giriş tarihi çelişkisi: Komisyon sayfası 10 Aralık 2024, Wikipedia 12 Kasım 2024 demektedir. Komisyon esas alınır; EUR-Lex bot koruması nedeniyle madde 71'in birebir metni alınamamıştır.
8. CRA Ek IV kritik ürünler tam listesi: çekilememiştir. Argus Ek III Sınıf I'de olduğu için pratikte etkisizdir ancak teyit edilmelidir.
9. CRA uyumlaştırılmış standartlarının, yani CEN ile CENELEC JTC13'ün, hazırlık durumu: araştırılamamıştır. Bu Argus için önemlidir: uyumlaştırılmış standart yoksa Sınıf I ürünler için üçüncü taraf uygunluk değerlendirmesi gerekebilir.
10. ABD EO 14028, EO 14144 ve Haziran 2025 EO değişikliklerinin güncel durumu: arama kotası nedeniyle araştırılamamıştır.
11. NIS2'nin kimlik yazılımı satıcılarına etkisi: araştırılamamıştır.
12. CISA SBOM minimum elements'in 2024 ile 2025 güncellemesi: araştırılamamıştır.
13. SPDX 3.0 durumu ve Rust desteği: araştırılamamıştır.
14. Reproducible Builds projesinin Rust'a özel 2025 ile 2026 metrikleri: aylık raporlar taranamamıştır.
15. rustc tekrarlanabilirlik issue'su rust-lang/rust#34902'nin kapanma tarihi ve gerekçesi: GitHub yorumları yüklenememiştir.
16. `arrayref` saldırısının Kuzey Kore'ye atfı: resmî Rust blogu atıf yapmamaktadır, üçüncü taraf iddiasıdır.
17. Shai-Hulud sonrası npm ile GitHub politika değişiklikleri: teyit edilememiştir.
18. xz ile CVE-2024-3094 detayları: bu oturumda ayrıca doğrulanmamıştır, genel bilinen olay bilgisidir.
19. `RUSTUP_HOME` remap kuralının farklı makinelerdeki etkinliği: tek makinede test edilmiştir, CI'da iki farklı kullanıcı adıyla doğrulanmalıdır.
20. cargo-cyclonedx'in desteklediği tam CycloneDX spesifikasyon sürümleri: belirtilmemiştir.

---

## J. En kritik üç mesaj

**1. CRA açısından Argus Sınıf I önemli ürün kategorisindedir.** Raporlama yükümlülüğü açık kaynak steward'ları için 11 Aralık 2027'de başlar; 11 Eylül 2026 üreticiler içindir ve ENISA bu ayrımı açıkça yapmaktadır. Argus CRA Ek III Sınıf I önemli ürün kategorisindedir: "Identity management systems and privileged access management software... including authentication and access control readers". Bu, varsayılan öz değerlendirme kategorisinden daha ağır bir uygunluk rejimi demektir. Aktif olarak sömürülen açıklar için ENISA ile CSIRT'e bildirim süreci ve iletişim adresi bu hafta kurulmalıdır. Tam yükümlülükler 11 Aralık 2027'de başlar: SBOM (Ek I Bölüm II.1, "covering at the very least the top-level dependencies"), koordineli açık bildirim politikası, destek süresi tanımı, teknik dokümantasyon (Ek VII) ve CE işareti.

**2. Ağustos 2026 `arrayref` saldırısı Argus'un tehdit modelini yeniden yazmalıdır.** 245 milyon indirmeli bir crate, tipo eşkıyalığıyla değil bakımcı ele geçirmesiyle, 86 dakikada ve `build.rs` üzerinden Linux, Windows ile macOS'a payload dağıtmıştır. Kullanıcıların %90'ını kurtaran tek şey `Cargo.lock` olmuştur. Buna karşı üç savunma vardır ve üçü de ucuzdur: lockfile, yedi günlük cooldown ve ağsız ile vendor edilmiş CI derlemesi. Ayrıca unutulmamalıdır ki 6 Eylül 2026'da PolinRider crates.io'ya ulaşmıştır; bu sefer `build.rs` bile kullanmadan, `.vscode/tasks.json` üzerinden.

**3. Sayılara güvenilir, bloglara değil.** Ölçülen gerçekler şunlardır: sıradan bir IdP yığını 243 crate, 1.747.244 satır üçüncü taraf kod, 26 `build.rs` ve 19 proc-macro getirmektedir. Basit feature hijyeniyle bu 170 crate, 1.311.921 satır, 20 `build.rs` ve 9 proc-macro'ya inmekte ve OpenSSL tamamen kaybolmaktadır; bir günlük iş, kalıcı kazançtır. cargo-vet'in beş büyük audit seti gerçekte 1.815 crate kapsamaktadır, SEO bloglarının iddia ettiği 14.140 değil, ve bu sizin grafiğinizin %51 ile %91'ine karşılık gelir. Denetlenmemiş kalanlar tam da en kritik olanlardır: `argon2`, `sqlx` ailesi ve ASN.1 ayrıştırıcıları. İlk denetim bütçesi oraya harcanır.
