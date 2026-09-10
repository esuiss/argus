# 12. Yazılım tedarik zinciri güvenliği

> `ARGUS.md` §12'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§12 §X` referansları aynı anlamda.



### 0. Metodoloji ve dürüstlük notu

Bu raporda üç tip veri var, ayırt ederek okuyun:

| İşaret | Anlamı |
|---|---|
| **[ÖLÇÜM]** | Bu oturumda kendi makinemde **birebir ölçtüğüm** veri (rustc 1.98.1, cargo 1.98.1, aarch64-apple-darwin). Tekrarlanabilir. |
| **[BİRİNCİL]** | Resmî kaynaktan (rust-lang.org, mozilla.github.io, slsa.dev, EU Komisyonu) doğrulanmış. |
| **[DOĞRULANAMADI]** | Bulundu ama teyit edilemedi. |

**Önemli uyarı — yanlış bilgi tuzağı:** Arama sonuçlarında çıkan `safeguard.sh`, `lightsquares.dev`, `geekwala.com` gibi siteler, cargo-vet hakkında *"Mozilla ve Google ortak audit havuzunu 14.140 crate / 58.900 crate-version'a çıkardı"* gibi çok spesifik rakamlar veriyor. **Bu rakamları doğrudan kaynaktan kontrol ettim ve gerçek değiller.** Beş büyük audit setini klonlayıp saydım — aşağıda gerçek rakamlar var (~1.815 crate). Bu siteler AI üretimi SEO içeriği; Argus'un tehdit modelinde "LLM'e yanlış güvenlik verisi besleme" diye bir madde açmanızı öneririm.

**Kapsam sınırı:** Oturumun web arama kotası (200 arama) doldu; son bölümlerde yalnızca doğrudan URL çekimi kullanabildim. Bu yüzden cargo-crev'in güncel inceleme sayısı ve bazı 2026 haberleri eksik kaldı — açıkça işaretledim.

---

## A) BAĞIMLILIK DENETİM ARAÇLARI

### A.1 Araç olgunluk tablosu [ÖLÇÜM — crates.io API, 8 Eylül 2026]

Her aracın crates.io API'sinden çekilmiş gerçek verisi:

| Araç | Sürüm | Son güncelleme | Toplam indirme | Son 90 gün | Yorum |
|---|---|---|---|---|---|
| `cargo-audit` | 0.22.2 | 2026-06-05 | 11.544.186 | **3.268.469** | Fiili standart |
| `rustsec` (kütüphane) | 0.33.0 | 2026-06-05 | 12.726.593 | 2.918.169 | cargo-audit/deny motoru |
| `cargo-deny` | 0.20.2 | 2026-07-09 | 5.547.620 | **1.550.032** | Politika kapısı |
| `cargo-cyclonedx` | 0.5.9 | 2026-03-19 | 1.686.501 | 747.740 | SBOM lideri |
| `cargo-machete` | 0.9.2 | 2026-04-15 | 2.821.321 | 508.102 | Kullanılmayan bağımlılık |
| `cargo-auditable` | 0.7.5 | 2026-06-28 | 991.221 | 249.877 | Binary'e SBOM gömme |
| `cargo-about` | 0.9.2 | 2026-08-18 | 1.154.564 | 236.356 | Lisans raporu |
| `cargo-udeps` | 0.1.61 | 2026-04-29 | 1.455.555 | 137.735 | nightly gerekir |
| `cargo-vet` | 0.10.2 | **2026-01-13** | 619.642 | **98.004** | Yavaş ama canlı |
| `cargo-outdated` | 0.19.0 | 2026-04-14 | 968.679 | 69.111 | |
| `cargo-geiger` | 0.13.0 | **2025-08-31** | 233.931 | 51.010 | Bakım yavaşlamış |
| `cargo-sbom` | 0.10.0 | **2025-06-17** | 225.224 | 56.461 | SPDX+CycloneDX |
| `cargo-supply-chain` | 0.3.7 | 2026-02-05 | 70.894 | 4.244 | Niş |
| `cargo-crev` | 0.27.1 | 2026-04-12 | 112.638 | **1.380** | **Fiilen ölü** |
| `cargo-spdx` | 0.1.0 | **2022-05-10** | 2.115 | **22** | **Terk edilmiş** |

**En çarpıcı sonuç:** cargo-crev'in son 90 günde **1.380** indirmesi var; cargo-audit'in **3.268.469**. Yani ~2400 kat fark. cargo-crev fiilen ölü bir teknolojidir.

### A.2 cargo-vet (Mozilla) — nasıl çalışır

#### Yerleşik kriterler [BİRİNCİL — https://mozilla.github.io/cargo-vet/built-in-criteria.html]

İki yerleşik kriter var, tam metinleri:

**`safe-to-run`:** "This crate can be compiled, run, and tested on a local workstation or in controlled automation without surprising consequences, such as: Reading or writing data from sensitive or unrelated parts of the filesystem; Installing software or reconfiguring the device; Connecting to untrusted network endpoints; Misuse of system resources (e.g. cryptocurrency mining)."

**`safe-to-deploy`:** "This crate will not introduce a serious security vulnerability to production software exposed to untrusted input." Devamı kritik: denetçinin **tüm crate'in mantığını incelemesi gerekmez**; ama **tüm `unsafe` bloklarını ve "powerful imports" kullanımını tam olarak muhakeme edebilecek kadar** incelemesi gerekir. Ayrıca: "For crates which generate deployed code (e.g. build dependencies or procedural macros), reasonable usage of the crate should output code which meets the above criteria." — yani **build.rs ve proc-macro'lar da kapsam içinde.**

`safe-to-deploy`, `safe-to-run`'ı kapsar (implies).

#### Özel kriterler [BİRİNCİL — audit-criteria.html]

`audits.toml` içinde kendi kriterinizi tanımlarsınız:

```toml
[criteria.crypto-reviewed]
description = '''
The cryptographic code in this crate has been reviewed for correctness by a
member of a designated set of cryptography experts within the project.
'''
```

**Kritik tuzak:** Audit'ler repolar arası birleştirilirken **her repodaki `description` metni birebir aynı olmak zorunda**, yoksa birleştirme başarısız olur.

→ **Argus için:** `crypto-reviewed`, `constant-time` (yan kanal), `no-network-egress` (build script ağa çıkmasın), `oidc-spec-conformant` gibi özel kriterler tanımlayın. Bu, "en güvenli IdP" iddiasının denetlenebilir hale gelmesidir.

#### Audit paylaşımı / import mekanizması [BİRİNCİL — importing-audits.html]

- `config.toml` içinde `imports` direktifleriyle başka organizasyonların `audits.toml` URL'lerini eklersiniz; cargo-vet çeker ve `imports.lock`'a yazar.
- **Geçişli (transitive) değildir**: "you can't directly import someone else's list of imports". Güven ilişkisi doğrudandır — bu kasıtlı bir tasarım kararıdır.
- Merkezî kayıt: `https://raw.githubusercontent.com/mozilla/cargo-vet/main/registry.toml`

#### Kayıttaki organizasyonlar [BİRİNCİL — registry.toml, 8 Eylül 2026 tarihli çekim]

Tam liste, dokuz organizasyon:

| Org | audits.toml URL |
|---|---|
| `actix` | `github.com/actix/supply-chain` |
| `ariel-os` | `github.com/ariel-os/ariel-os` |
| `bytecode-alliance` | `github.com/bytecodealliance/wasmtime` |
| `embark-studios` | `github.com/EmbarkStudios/rust-ecosystem` |
| `fermyon` | `github.com/fermyon/spin` |
| `google` | `github.com/google/supply-chain` |
| `isrg` | `github.com/divviup/libprio-rs` (Let's Encrypt'in kurumu) |
| `mozilla` | `github.com/mozilla/supply-chain` |
| `zcash` | `github.com/zcash/rust-ecosystem` |

Not: Kullanıcının sorduğu **ChromeOS ayrı bir giriş değil** — Google'ın seti altında. **Fuchsia da ayrı değil.**

#### Audit setlerinin GERÇEK büyüklüğü [ÖLÇÜM — 5 repo klonlandı, 8 Eylül 2026]

Beş büyük seti klonlayıp `audits.toml` dosyalarını ayrıştırdım:

| Organizasyon | Denetlenmiş crate | Wildcard | Trusted | **Toplam farklı crate** |
|---|---|---|---|---|
| google | 948 | 0 | 0 | **948** |
| mozilla | 586 | 67 | 162 | **691** |
| bytecode-alliance | 298 | 118 | 153 | **476** |
| zcash | 376 | 0 | 62 | **416** |
| embark | 98 | 45 | 26 | **169** |
| **BİRLEŞİM** | | | | **1.815 farklı crate** |

Toplam audit girdisi: **5.576**. 

Bu, SEO bloglarının iddia ettiği "14.140 crate / 58.900 versiyon"un **~1/8'i**. Gerçekçi planlama yapın.

#### **Argus'un bağımlılık grafiğinin ne kadarı zaten denetlenmiş?** [ÖLÇÜM]

Bu raporun en operasyonel sayısı. Tipik bir IdP yığını kurup (axum+tokio+sqlx+jsonwebtoken+argon2+webauthn-rs+redis+reqwest) beş audit setiyle kesiştirdim:

**Crate adı düzeyinde (ÜST SINIR — aşırı iyimser):**

| Yığın | Bağımlılık | Herhangi bir audit setinde | `safe-to-deploy` ile | Hiç denetlenmemiş |
|---|---|---|---|---|
| Tam yığın | 231 farklı crate | 194 (**%84,0**) | 186 (%80,5) | **37** |
| Minimal yığın | 162 farklı crate | 148 (**%91,4**) | 143 (%88,3) | **14** |

**Sürüm-tam düzeyinde (ALT SINIR — delta zincirlerini saymıyor):**

Minimal yığın, 170 crate-versiyon:
- Tam sürüm eşleşen audit kaydı: **39 (%22,9)**
- Wildcard/trusted yayıncı güvenceli: **48 (%28,2)**
- **Toplam kapsanan: 87 (%51,2)** — kalan **83 crate-versiyon kayıtsız**

**Gerçek cargo-vet kapsamı bu ikisinin arasındadır (~%51–%91)**, çünkü delta audit zincirleri (`0.4.1 -> 0.4.2` gibi) sürüm-tam eşleşmede görünmüyor ama gerçekte kapsıyor. Kesin sayı için `cargo vet` çalıştırmak gerekir.

**Hiç denetlenmemiş olanlar, Argus için tam da en kritik olanlar:**

```
argon2, sqlx, sqlx-core, sqlx-macros, sqlx-macros-core, sqlx-postgres,
blake2, atoi, dotenvy, event-listener, futures-intrusive,
unicode-properties, untrusted
```
Tam yığında ayrıca: `asn1-rs`, `der-parser`, `oid-registry`, `pem`, `simple_asn1`, `base64urlsafedata`, `redis`, `reqwest`, `arc-swap`, `axum-macros`, `rusticata-macros`, `combine`.

**Yorum:** Parola hash'leme (`argon2`), veritabanı katmanı (`sqlx` ailesi) ve ASN.1/sertifika ayrıştırma (`asn1-rs`, `der-parser`, `simple_asn1`) — bir IdP'nin en yüksek riskli üç bileşeni — **hiçbir büyük organizasyon tarafından denetlenmemiş**. ASN.1 ayrıştırıcıları tarihsel olarak bellek güvenliği ve ayrıştırma kafası karışıklığı (parser differential) açıklarının klasik yuvasıdır. Argus'un ilk elle denetim bütçesi buraya gitmeli.

#### Wildcard audit / trusted publisher [BİRİNCİL — wildcard-audit-entries.html]

Bir wildcard audit, "belirli bir hesabın yayımladığı **herhangi bir sürümün**" kriteri karşılayacağını sertifikalar. Yani **kodu değil, yayımcının sürüm çıkarma sürecinin bütünlüğünü** onaylarsınız.

Alanlar: `user-id` (crates.io kullanıcı ID'si, zorunlu), `start`/`end` (UTC, **end en fazla 1 yıl ileri**), `criteria`, `who`, `renew` (bool), `notes`.

Komutlar: `cargo vet certify --wildcard` (varsayılan 1 yıl), `cargo vet renew`, `cargo vet renew --expiring` (6 hafta içinde dolacakları yeniler).

**Argus için risk uyarısı:** Ağustos 2026 `arrayref` saldırısı (bkz. Bölüm F) tam olarak **wildcard audit modelinin kırıldığı** senaryodur: yayımcı kötü niyetli değildi, **kimlik bilgileri/bilgisayarı ele geçirildi**. Bir wildcard audit o saldırıyı durdurmazdı. Wildcard'ları yalnızca Trusted Publishing kullanan ve iki kişi onayı olan projeler için verin.

#### cargo-vet bakım durumu 2026

- GitHub'daki son **release**: v0.10.0, **3 Ekim 2024** [BİRİNCİL — github.com/mozilla/cargo-vet/releases]
- crates.io'daki son **yayın**: **0.10.2, 13 Ocak 2026** [ÖLÇÜM — crates.io API], yayımlayan: Nika Layzell
- Son 90 gün: 98.004 indirme

**Değerlendirme:** Terk edilmemiş ama **hızı belirgin şekilde düşmüş**. ~15 ayda bir yama sürümü. Mozilla içinde hâlâ kullanılıyor (audits.toml aktif güncelleniyor). Argus için: kullanılabilir, ancak **araç üstünde bir bağımlılık riski** olarak modelleyin — cargo-vet yarın dursa `audits.toml` verisi hâlâ okunabilir TOML'dur, kaybolmaz.

### A.3 cargo-crev — neden tutmadı

**Model:** Dağıtık, kriptografik olarak imzalanmış "proof" repoları + web-of-trust. Dil-bağımsız (`crev` çekirdeği), `cargo-crev` Rust uyarlaması.

**Benimsenme [ÖLÇÜM]:** Son 90 günde **1.380 indirme**. Toplam 112.638. Depo ~2,2k yıldız.

**Ek kanıt [ÖLÇÜM, 8 Eylül 2026]:** `https://web.crev.dev/rust-reviews/` ve `.../reviewers/` adreslerinin ikisi de **HTTP 502 Bad Gateway** döndü. Ekosistemin merkezî keşif arayüzü çalışmıyor. Güncel inceleme sayısını bu yüzden **[DOĞRULANAMADI]** olarak bırakıyorum.

**Neden cargo-vet kazandı:** Mozilla'nın kendi duyurusundaki gerekçe [dev-platform duyurusu]: audit'ler **ayrı bir anahtar seti ve web-of-trust yerine, deponun mevcut erişim kontrollerine tabi olarak repoda saklanır**. Bu üç şeyi çözer:
1. Anahtar yönetimi yok — GitHub PR review'ı zaten kimlik doğrulaması.
2. Güven kararı örgütsel, bireysel değil ("Google'a güveniyorum", "kripto-twitter'da tanıdığım 12 kişiye" değil).
3. CI'ya sokmak tek satır (`cargo vet --locked`).

Web-of-trust'ın sosyal ölçekleme sorunu var: kime, hangi derinlikte güveneceğinize dair karar yükü kullanıcıda kalıyor ve bu karar denetlenebilir/kurumsallaştırılabilir değil.

→ **Argus kararı: cargo-crev kullanmayın.** Ölü teknoloji.

### A.4 cargo-deny — politika kapısı (ZORUNLU)

[BİRİNCİL — embarkstudios.github.io/cargo-deny/checks/cfg.html]

Dört bağımsız kontrol: **advisories**, **bans**, **licenses**, **sources**.

`deny.toml` üst düzey bölümleri: `[graph]`, `[advisories]`, `[bans]`, `[licenses]`, `[sources]`, `[output]`.

`[graph]` özellikle önemli: hedef platforma, feature'lara göre filtreleyerek **gerçekten derlediğiniz** grafiği değerlendirmenizi sağlar — aksi halde Windows-only bağımlılıklar için gereksiz alarm alırsınız.

#### Argus için önerilen `deny.toml`

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

**`[sources]` en az bilinen ama Argus için en kritik kontroldür:** `allow-git = []` ile hiçbir bağımlılığın doğrudan git'ten (checksum'suz, yanklanamaz, mirror'lanamaz) gelmemesini garanti edersiniz. Bir git bağımlılığı, tedarik zinciri güvencelerinizin tamamını delen bir kaçış deliğidir.

#### CI'da bloklayıcı hale getirme

```yaml
- uses: EmbarkStudios/cargo-deny-action@v2
  with:
    command: check bans licenses sources advisories
    arguments: --all-features --locked
```
Çıkış kodu ≠ 0 → job fail. `continue-on-error` **kullanmayın**.

**Advisories kontrolü için ayrı bir düşünce:** `advisories` kontrolü dış veriye (RustSec DB) bağlı olduğu için, yeni bir advisory yayınlandığında **kodunuz değişmeden CI kırılır**. Bu istenen davranıştır ama release pipeline'ını kilitleyebilir. Çözüm: `bans/licenses/sources`'ı **PR kapısı** (deterministik), `advisories`'i **günlük zamanlanmış job + release kapısı** olarak ayırın.

### A.5 cargo-audit ve RustSec advisory veritabanı

#### Kapsam — GERÇEK sayılar [ÖLÇÜM — advisory-db klonlandı, son commit 2026-09-08 11:58 CEST]

Veritabanını klonlayıp saydım:

**Toplam advisory: 1.222** (`crates/` altında) + **20** (`rust/` altında: std 18, cargo 1, rustdoc 1)

**Yıllara göre dağılım:**

| Yıl | Sayı | | Yıl | Sayı |
|---|---|---|---|---|
| 2016 | 6 | | 2022 | 104 |
| 2017 | 8 | | 2023 | 126 |
| 2018 | 22 | | 2024 | 139 |
| 2019 | 40 | | 2025 | 172 |
| 2020 | 168 | | **2026** | **281** (8 Eylül'e kadar) |
| 2021 | 156 | | | |

2026, henüz 8 ay geçmişken tüm zamanların rekoru — yıllıklandırılmış ~420, 2025'in **2,4 katı**.

**Tür dağılımı:**
- Gerçek güvenlik açığı: **741**
- `informational = "unmaintained"`: **269**
- `informational = "unsound"`: **206**
- `informational = "notice"`: **6**

`unmaintained` advisory'leri Argus için özellikle değerlidir: CVE değil ama **gelecekteki risk göstergesidir** — bakımsız bir crate'te bulunacak açık asla yamalanmayacak demektir.

#### Bakım ve yönetişim [BİRİNCİL — rustsec.org]

- Veritabanı: **Rust Secure Code Working Group** tarafından bakılıyor ("maintained by the Rust Secure Code Working Group"). **Rust Foundation değil** — Foundation ayrı olarak fonlama ve araç sağlıyor (bkz. G.3).
- Depo: 3.192 commit, 1,2k yıldız, 536 fork.
- Güncelleme sıklığı: **günlük** — klonladığım anda son commit **aynı gün** (2026-09-08) atılmıştı.
- İhracat: **OSV formatında** yayınlanıyor → osv.dev ve GitHub Advisory Database otomatik içe aktarıyor. Yani Dependabot, Trivy, Grype, osv-scanner hepsi aynı veriyi görüyor.

#### `rustsec` deposundaki crate'ler [BİRİNCİL — github.com/rustsec/rustsec]

Tek workspace, altı crate: `cargo-audit`, `cargo-lock` (bağımsız Cargo.lock ayrıştırıcı), `cvss`, `platforms`, `rustsec` (istemci kütüphanesi), `rustsec-admin`.

→ **Argus için:** `rustsec` crate'ini doğrudan kullanarak **kendi admin panelinize "bağımlılık sağlığı" widget'ı** koyabilirsiniz. Bir IdP'nin operatörüne "şu an çalışan sürümünüzde 0 bilinen açık var" demesi güçlü bir ürün özelliğidir ve CRA Madde 13 şeffaflık beklentisiyle örtüşür.

#### Argus yığınının advisory maruziyeti [ÖLÇÜM]

Örnek yığınları advisory DB ile kesiştirdim (kaba eşleşme — sürüm aralıklarını değil crate adını eşleştirir):

| | Tam yığın (231) | Minimal (162) |
|---|---|---|
| Advisory kaydı olan crate | 46 | 38 |
| Toplam advisory kaydı | 83 | 64 |

**Şu an fiilen açık `unsound` işaretli bağımlılıklar (ikisinde de ortak):**

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

**ÖNEMLİ DÜZELTME — `ring` hakkında:** Kaba eşleştiricim `ring 0.17.14`'ü "unmaintained" olarak işaretledi (RUSTSEC-2025-0007, 20 Şubat 2025). **Ama advisory'nin TOML başlığında `withdrawn = "2025-02-22"` var — advisory iki gün sonra geri çekilmiş.** Advisory metni: yazar süresiz ara verdiğini duyurdu → rustls ekibine erişim verildi → *"Things are more-or-less back to how they were before, and in particular the situation isn't 'security maintenance only.'"*

Bu, raporun en öğretici anıdır: **grep ile advisory taraması yapmayın.** `withdrawn`, `patched`, `unaffected` alanlarını doğru yorumlayan gerçek araç (`cargo audit` / `cargo deny`) kullanın. Ben elle sayarken bu tuzağa düştüm; sizin CI'nız düşmesin.

**Bir IdP'yi doğrudan ilgilendiren 2026 advisory'leri [ÖLÇÜM]:**

- **`bcrypt` RUSTSEC-2026-0199** (20 Haziran 2026, `>= 0.19.2`'de yamalı): `bcrypt::verify(password, hash)` **saldırgan kontrollü hash string'iyle panic ediyor** — 60 baytlık, belirli konumlarda çok baytlı UTF-8 karakter içeren `&str`. Advisory'nin kendi tehdit senaryosu birebir Argus: *"Rust authentication services reading hashes from a database that was previously compromised via, e.g., SQL injection. The attacker can then crash the service on every login attempt against the tampered account."* Crate `#![forbid(unsafe_code)]` olduğu için sadece DoS.
- **`tokio-postgres` RUSTSEC-2026-0178** (12 Haziran 2026, `>= 0.7.18`): kötü niyetli/ele geçirilmiş sunucu, satır tanımından az alan içeren `DataRow` gönderirse `Row::get` **ve panic etmeyeceği varsayılan `try_get` bile** index-out-of-bounds panic ediyor.
- **`h2` RUSTSEC-2026-0258**, **`diesel`** için 2026'da altı ayrı advisory (0111, 0134, 0135, 0136, 0137, 0172), **`rand` RUSTSEC-2026-0097**, **`time` RUSTSEC-2026-0009**, **`lettre` RUSTSEC-2026-0141** (e-posta — OTP/magic link akışlarınız için).
- **`rmcp` RUSTSEC-2026-0189** (29 Nisan 2026, CVE-2026-42559, `>= 1.4.0`): MCP Streamable HTTP transport'unda **DNS rebinding** — `Host` başlığı doğrulanmıyordu. Argus'a MCP/AI entegrasyonu düşünüyorsanız doğrudan ilgili.

**Argus için genel ders — DNS rebinding kalıbı:** 2026'da RustSec'te en az iki ayrı DNS rebinding advisory'si var (`rmcp`, `rojo` RUSTSEC-2026-0279). İkisinde de kök neden aynı: **localhost'a bağlanan kimlik doğrulamasız HTTP API'de `Host`/`Origin` doğrulaması yok.** Argus'un geliştirme sunucusu, admin API'si ve device-code akışı bu kalıba düşebilir. `Host` allowlist'ini gün bir gün uygulayın.

### A.6 Diğer araçlar — ne satın alır, Argus'ta nereye oturur

#### `cargo-auditable` — **[GÜÇLÜ TAVSİYE]**
[BİRİNCİL — github.com/rust-secure-code/cargo-auditable]

Bağımlılık ağacını derlenmiş binary'e gömer: **Zlib-sıkıştırılmış JSON**, `.dep-v0` adlı linker section'ında.

- **Maliyet: yok.** *"under 4kB even on large dependency trees with 400+ entries"* — binary boyutunun 1/1.000 ila 1/10.000'i.
- **Çıkarma araçları:** `rust-audit-info`, `syft` (v1.15.0+), `trivy` (v0.31.0+), `auditable2cdx` (→ CycloneDX), `cargo audit` (v0.17.3+).
- **Benimsenme:** Alpine Linux, NixOS, openSUSE, Void Linux, Chimera Linux, Wolfi OS, Ubuntu 26.04 (seçili paketler) bunu **varsayılan olarak** kullanıyor. Microsoft dahilî kullanıyor.

**Argus'ta neden kritik:** SBOM dosyaları kaybolur, eşleşmez, güncellenmez. Binary'nin içindeki SBOM **her zaman doğru binary'ye aittir**. Müşteri "hangi sürümü çalıştırıyorum ve açığı var mı?" diye sorduğunda cevap `rust-audit-info /usr/bin/argus | cargo audit --stdin`. Bu, CRA Ek I Bölüm II.1'deki "bileşenleri tanımla ve belgele" yükümlülüğünü **çalışma zamanında** karşılar. Yapın.

#### `cargo-machete` vs `cargo-udeps`
- **`cargo-machete`** (0.9.2, 2026-04-15, 508k/90gün): stable toolchain, **hızlı** (kaynak metnini tarar), bazen yanlış pozitif. CI'ya koyun.
- **`cargo-udeps`** (0.1.61, 2026-04-29, 138k/90gün): **nightly gerektirir**, derleyici verisine bakar, daha doğru. Haftalık/aylık job olarak koyun.
- İkisi tamamlayıcıdır. Argus'ta: machete = PR kapısı, udeps = zamanlanmış.

#### `cargo-supply-chain` (0.3.7, 2026-02-05, 4.2k/90gün)
Bağımlılıklarınızın **yayımcılarını (publishers/owners)** listeler. Niş ama Argus için değerli tek bir soruyu cevaplar: **"Bağımlılık grafiğim kaç farklı insana güveniyor?"** — bu, tedarik zinciri tehdit modelinizin *gerçek* boyutudur. Yılda bir çalıştırıp raporlayın; sayı büyüyorsa minimizasyon çalışması yapın.

#### `cargo-outdated` (0.19.0) / `cargo-semver-checks` (0.50.0, 2026-08-01)
- `cargo-outdated`: güncellenebilir bağımlılıkları listeler. Bilgilendirici, kapı değil.
- `cargo-semver-checks`: **Argus kendi crate'lerini yayımlayacaksa** (SDK, client kütüphaneleri) semver ihlallerini yakalar. Downstream kırılmalarını önler.

#### `cargo-geiger` (0.13.0, **2025-08-31** — bakım yavaş)
`unsafe` kullanımını sayar. **[DİKKAT]** Faydalıdır ama son sürüm bir yıldan eski. Aşağıdaki `cargo scan` alternatifine bakın.

#### **Cargo Scan — yeni ve Argus için çok uygun** [BİRİNCİL — arXiv:2602.06466]

**"Auditing Rust Crates Effectively"**, Lydia Zoghbi, David Thien, Ranjit Jhala, Deian Stefan, Caleb Stanford — **6 Şubat 2026**'da sunuldu.

Rust'ın tip ve modül sistemini kullanarak yan-etki analiziyle "potansiyel olarak tehlikeli" kodu işaretler. Sonuçlar:

- Vakaların **~%69'unda** geliştirici, işaretlenen etkiyi **daha geniş bağlam analizi olmadan yerel olarak** değerlendirebiliyor.
- `hyper` HTTP crate'i ve bağımlılıklarına uygulandığında denetim yükünü **kod satırlarının medyan %0,2'sine** indirdi.
- crates.io'nun ilk 10.000 crate'inde: **~3.500 crate otomatik olarak güvenli sınıflandırılabildi**; elle inceleme gerekenlerde tehlikeli yan etkiler **crate'lerin ~%3'ünde yoğunlaştı**.

**Argus'ta yeri:** cargo-vet ile birleştirin. Yukarıda "hiç denetlenmemiş" bulduğum 14–37 crate'i elle denetlemeniz gerekiyor; Cargo Scan bu işi **crate başına tam okuma yerine %0,2 satır okuma**ya indirger. `argon2` + `sqlx` ailesi + ASN.1 ayrıştırıcıları için ilk uygulanacak araç budur.

---

## B) BAĞIMLILIK MİNİMİZASYONU

### B.1 Gerçek şişkinlik verisi [ÖLÇÜM — bu oturumda, cargo 1.98.1]

Teorik tartışma yerine ölçtüm. İki gerçek proje kurup `cargo vendor` ile kaynakları çektim.

#### Yığın A — "makul, sıradan" IdP yığını

```toml
axum 0.8 (macros), tokio 1 (full), tower 0.5, tower-http 0.6 (trace,cors,compression-gzip),
sqlx 0.8 (runtime-tokio, tls-rustls, postgres, uuid, chrono, migrate),
serde, serde_json, tracing, tracing-subscriber (env-filter,json),
jsonwebtoken 9, argon2 0.5, rand 0.9, uuid 1, chrono 0.4,
reqwest 0.12 (default-features=false, json, rustls-tls), redis 0.27, webauthn-rs 0.5
```

| Metrik | Değer |
|---|---|
| `Cargo.lock` paket sayısı | **324** (kendisi dahil) |
| **linux-x86_64 için gerçekten derlenen** (normal+build) | **243 crate-versiyon** / 231 farklı ad |
| Sadece runtime (normal) | 236 |
| **build.rs içeren crate** (derleme anında keyfi kod!) | **26** |
| **proc-macro crate** (derleme anında keyfi kod!) | **19** |
| **Üçüncü taraf Rust satırı** (test/bench/example hariç) | **1.747.244** |
| C/C++ kaynak dosyası taşıyan crate | 3 (`cc`, `openssl-sys`, `ring`) |
| Bağımlılık ağacı derinliği | ~19 seviye |
| Çoklu sürümü olan crate | 23 |

#### Yığın B — minimize edilmiş

`default-features = false` + webauthn-rs, redis, reqwest, chrono, tower-http çıkarıldı, `tls-rustls-ring` seçildi:

| Metrik | A (tam) | B (minimal) | Kazanç |
|---|---|---|---|
| linux-x86_64 crate | 243 | **170** | **−%30** |
| build.rs (derleme-anı RCE yüzeyi) | 26 | **20** | −%23 |
| proc-macro | 19 | **9** | **−%53** |
| Üçüncü taraf satır | 1.747.244 | **1.311.921** | **−%25** |
| OpenSSL (native C kripto) | **VAR** | **YOK** | ✅ |
| Denetlenmemiş crate (vet setlerine göre) | 37 | **14** | **−%62** |

**En değerli tek hamle:** `webauthn-rs`'i çıkarmak. Kanıt [ÖLÇÜM — `cargo tree -i cc`]:

```
cc v1.4.5
[build-dependencies]
├── openssl-sys v0.9.117
│   ├── openssl v0.10.81
│   │   ├── webauthn-attestation-ca v0.5.5
│   │   │   └── webauthn-rs-core v0.5.5
│   │   │       └── webauthn-rs v0.5.5
```

`webauthn-rs 0.5`, attestation CA doğrulaması için **native OpenSSL**'e bağımlı. Bir IdP için passkey desteği zorunlu; ama bu, ürününüze şunları sokar: (a) sistem OpenSSL'i (CVE akışı yüksek), (b) `openssl-sys` build script'i (derleme anında `cc` çalıştırır, sistem tarar), (c) `openssl` crate'i için RustSec'te **10 advisory** kaydı, (d) statik/reproducible build'i zorlaştırır, (e) container imajınızı şişirir.

→ **Argus mimari kararı:** WebAuthn attestation doğrulamasını **ayrı bir process/servise** izole edin veya saf-Rust ASN.1/X.509 doğrulaması (`webpki`, `rustls-webpki`, `x509-cert`) ile kendiniz yazın. Attestation, passkey akışının **isteğe bağlı** parçasıdır — çoğu CIAM senaryosunda `AttestationConveyancePreference::None` kullanılır ve o zaman bu bağımlılığa hiç gerek yoktur. Attestation'ı sadece yüksek güvence gereken kurumsal profilde, izole edilmiş şekilde açın.

#### En büyük 20 bağımlılık (minimal yığın, satır sayısıyla) [ÖLÇÜM]

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

**İlk 10 crate, toplam satırın %44,5'ini oluşturuyor.** Denetim bütçenizi buraya odaklayın — ama dikkat: bunların çoğu (tokio, rustls, serde, hyper) zaten Google/Mozilla tarafından `safe-to-deploy` denetlenmiş. Gerçek iş, **denetlenmemiş küçük crate'lerde**.

#### İki somut şişkinlik zinciri [ÖLÇÜM]

**1) `env-filter` → regex motoru (124.359 satır):**
```
regex-automata + regex-syntax
  └── matchers 0.2.0 → tracing-subscriber (env-filter feature)
```
`RUST_LOG=info,argus::oidc=debug` gibi filtrelere ihtiyacınız yoksa `env-filter`'ı kapatın veya `tracing-subscriber`'ın `Targets` filtresini (regex'siz) kullanın → ~124k satır ve tam bir regex motoru gider.

**2) `url` → `idna` → ICU4X → ikinci `syn` (~102k satır iki syn):**
```
syn 3.0.5
└── displaydoc (proc-macro)
    └── icu_collections → icu_normalizer → idna_adapter → idna → url
        └── sqlx-core
```
Bu, Rust ekosisteminin en bilinen şişkinlik zinciridir: bir URL ayrıştırmak için Unicode IDNA, o da tam ICU4X normalizasyon veri yapılarını, o da `yoke`/`zerocopy`/`displaydoc` proc-macro'larını getirir. Argus URL ayrıştırmayı (redirect_uri doğrulaması!) **kendisi yapmalı** — zaten OAuth 2.1 `redirect_uri` eşleşmesi **birebir string karşılaştırması** olmalıdır (RFC 6749 ve OAuth 2.1 taslağı exact match zorunlu kılar). Genel amaçlı bir URL ayrıştırıcısının esnekliği burada **güvenlik açığıdır**, özellik değil.

### B.2 Rust'ta "left-pad" riski ve küçük crate tartışması

**Yapısal fark npm'e göre:**
1. **`cargo yank` silmez.** Yanklanan sürüm mevcut `Cargo.lock`'lardan çözülmeye devam eder; sadece yeni çözümleme onu seçmez. left-pad tipi "paket kayboldu, dünya durdu" olayı Rust'ta mimari olarak mümkün değil.
2. **Gerçek silme sadece crates.io ekibi tarafından, kötü amaçlı kod için yapılır** — ve o zaman da RustSec advisory'si yayınlanır (bkz. F bölümü: `expect-deleted = true` alanı).
3. `Cargo.lock` + checksum varsayılan olarak commit edilir (binary projelerde).

**Ama Rust'ın kendine özgü, npm'den DAHA KÖTÜ olan bir yanı var: `build.rs` ve proc-macro.**

npm'de `postinstall` script'i vardır ve `--ignore-scripts` ile kapatılabilir. Rust'ta **`build.rs`'yi kapatmanın bir yolu yoktur** ve JFrog'un arayışı bunu net söylüyor: *"In Rust, a `build.rs` script is compiled and executed automatically during `cargo build`, `cargo check`, and similar commands, including CI and **rust-analyzer driven builds**."*

Yani: **editörünüzde dosyayı açmak yeterlidir.** rust-analyzer `cargo check` çalıştırır, `build.rs` çalışır, payload iner. Ağustos 2026 saldırısı tam olarak böyle işledi.

[ÖLÇÜM] Sıradan bir IdP yığınında **26 crate'in build.rs'i var** ve **19 proc-macro crate** derleme sırasında derleyici içinde keyfi kod çalıştırıyor. Bu 45 crate, sizin CI runner'ınızda ve geliştirici laptop'unuzda **kod çalıştırma hakkına sahip 45 ayrı taraftır.**

**Argus için somut politika:**
- `deny.toml`'a bir "build.rs allowlist" mantığı ekleyin (cargo-deny doğrudan desteklemez; `cargo metadata` üzerinde küçük bir script yazın): yeni bir build.rs bağımlılığı grafiğe girdiğinde CI kırılsın ve insan onayı gereksin. Ağustos 2026 saldırısında sinyal tam buydu — `arrayref`'in **10 yıllık geçmişinde hiç görülmemiş** bir bağımlılık eklendi.
- CI derlemelerini **ağ erişimi olmayan** (vendored kaynaklarla, `--offline`) container'da yapın. `proc-macro1`'in payload'u indirmesi mümkün olmazdı.
- Geliştirici makinelerinde rust-analyzer için `cargo check` yerine izole devcontainer kullanmayı değerlendirin.

### B.3 `cargo vendor` ve vendoring politikası

`cargo vendor` tüm bağımlılık kaynaklarını repoya/artifact'a indirir ve `.cargo/config.toml`'a kaynak değiştirme (source replacement) yazar.

[ÖLÇÜM] Tam yığın için vendor dizini **342 MB** (Windows import kütüphaneleri baskın: `windows-sys` üç sürümü 70 MB). Linux-only hedefleyip `--versioned-dirs` kullanınca çok daha küçük.

**Argus için önerilen vendoring politikası:**

| Ne | Karar | Gerekçe |
|---|---|---|
| Kaynak vendoring repoya commit | **HAYIR** | 342 MB, review gürültüsü, PR'ları öldürür |
| Release pipeline'ında vendor tarball | **EVET** | Hermetik, ağsız, reproducible build |
| Vendor tarball'ı imzala + arşivle | **EVET** | Kaynak crates.io'dan silinse bile derleyebilirsiniz |
| Kritik crate fork'lama | **SEÇİCİ** | Aşağıya bakın |

**Fork kapasitesi — gerçekçi olun.** [ÖLÇÜM] Minimal yığında 1.311.921 satır üçüncü taraf kod var. 2-5 kişilik bir ekip bunu forklayamaz, sürdüremez. Fork stratejisi **sadece** şu koşullarda anlamlıdır:
- Crate küçük (<5.000 satır),
- Güvenlik-kritik yolda,
- Upstream bakımsız veya yavaş.

Argus için fork adayları: `jsonwebtoken` (JWT doğrulama mantığı — algoritma karıştırma saldırıları için tam kontrol istersiniz), `argon2` parametreleri, ASN.1 ayrıştırıcıları. `tokio`/`rustls`/`serde` **asla** forklanmaz.

**Daha iyi alternatif — "vendor + patch":** `[patch.crates-io]` ile sadece ihtiyacınız olan crate'i yerel bir kopyayla değiştirin, geri kalanı upstream kalsın. Tam fork'un bakım yükü olmadan kontrol sağlar.

### B.4 Somut minimizasyon teknikleri

**1) `default-features = false` — en yüksek getirili tek hamle** [ÖLÇÜM: −%30 crate]

```toml
tokio = { version = "1", default-features = false,
          features = ["rt-multi-thread","net","time","macros","signal"] }
axum = { version = "0.8", default-features = false,
         features = ["http1","json","tokio"] }
sqlx = { version = "0.8", default-features = false,
         features = ["runtime-tokio","tls-rustls-ring","postgres","uuid","macros"] }
```
`tokio` `"full"` yerine gerçek feature listesi kullanın. `"full"` `fs`, `process`, `io-std` gibi Argus'un asla kullanmayacağı ve **ambient capability yüzeyini genişleten** modülleri açar.

**Feature'lar aynı zamanda bir güvenlik kontrolüdür:** `tokio/process` açık değilse, ele geçirilmiş bir bağımlılık `tokio::process` üzerinden komut çalıştıramaz.

**2) `cargo tree -d` — çoklu sürümler** [ÖLÇÜM: tam yığında 23 crate çift]

```bash
cargo tree -d --target x86_64-unknown-linux-gnu -e normal
```
Tam yığında: `rand`, `rand_core`, `getrandom` **üçer sürüm**; `syn`, `thiserror`, `hashbrown`, `base64`, `socket2`, `webpki-roots` ikişer sürüm.

Neden önemli: (a) her kopya ayrı denetlenmeli, (b) `rand`/`getrandom`'ın **üç farklı sürümü** demek üç farklı entropi kaynağı kod yolu demek — bir IdP için kabul edilemez, (c) binary boyutu.

`cargo update -p <crate> --precise <ver>` ile birleştirin veya bağımlılık sürümlerini hizalayın.

**3) `no_std` — Argus için sınırlı fayda [GERÇEKÇİ OLUN]**

Argus bir ağ servisidir; tokio, TLS, PostgreSQL istemcisi zaten `std` gerektirir. `no_std` **ana binary için uygulanamaz**.

Ancak: **kripto ve protokol çekirdeğinizi kendi crate'lerinizde `#![no_std]` yazın.** Token üretimi/doğrulaması, PKCE hesabı, DPoP kanıt doğrulaması, parola hash parametreleri — bunlar `no_std + alloc` ile yazılabilir. Kazanç: bu modüller dosya sistemine, ağa, saate erişemez → **denetimi radikal biçimde kolaylaşır** ve cargo-vet `safe-to-deploy` incelemesi dakikalar sürer. Bu, "en güvenli IdP" iddiası için somut, gösterilebilir bir mimari argümandır.

**4) `#![forbid(unsafe_code)]` kendi kodunuzda + `unsafe` bütçesi**

[ÖLÇÜM] Tam yığında **193 crate** en az bir `unsafe fn`/`impl`/blok içeriyor, toplam **22.595** oluşum. Bunu sıfırlayamazsınız. Ama:
- Argus'un kendi crate'lerinde `#![forbid(unsafe_code)]` (workspace lint olarak).
- Bağımlılıklardaki `unsafe` sayısını **zaman içinde izleyin** — artıyorsa yeni ve denetlenmemiş bir bağımlılık girmiştir.

**5) Alternatif crate seçimleri (Argus'a özel)**

| Yerine | Kullanın | Gerekçe |
|---|---|---|
| `openssl` / `native-tls` | `rustls` (+ `aws-lc-rs` veya `ring`) | Native C kripto yok, build.rs yok, FIPS için aws-lc-rs |
| `chrono` | `time` veya `jiff` | chrono geçmişte `localtime_r` soundness sorunları yaşadı (RUSTSEC-2020-0159) |
| `webauthn-rs` (attestation ile) | attestation'ı izole et / saf-Rust X.509 | OpenSSL zincirini keser [ÖLÇÜM ile kanıtlı] |
| `tracing-subscriber` + `env-filter` | `Targets` filtresi | −124k satır regex motoru [ÖLÇÜM] |
| `url` (redirect_uri için) | birebir string eşleşme | OAuth 2.1 zaten exact match ister; ICU4X zinciri gider |
| `reqwest` (tam) | `reqwest` `default-features=false` + `rustls-tls` | veya doğrudan `hyper` istemcisi |

---

## C) RUST'TA TEKRARLANABİLİR DERLEMELER (2026 DURUMU)

### C.1 `cargo build` tekrarlanabilir mi? — Kendi deneylerim [ÖLÇÜM]

Bu bölümü teorik bırakmadım; **rustc 1.98.1 (48a229cea, 2026-09-01)** ile dört kontrollü deney yaptım.

#### Deney 1: Aynı makine, farklı derleme dizini, `debug = false`

İki özdeş proje, `.../scratchpad/rb1` ve `.../scratchpad/rb2`, aynı `Cargo.lock`:

```
hash1 = 7c2e382ad80a0c00b44a3e6743c42c02b8fac31cb4d655039a97c770f7b044c9
hash2 = 7c2e382ad80a0c00b44a3e6743c42c02b8fac31cb4d655039a97c770f7b044c9
SONUÇ: BİT DÜZEYİNDE AYNI ✅
```
Proje dizini yolu binary'e sızmadı (`strings | grep scratchpad/rb1` → 0 eşleşme).

#### Deney 2: `debug = 1` (production'da sembol istiyorsanız)

```
hash1 = 8ce8891f9196985af57e18525c9d0b45b9e9e0b417bbfca830fb88e2288df813
hash2 = 907451832bf2b624e7911e26e562274542e50ba46da11da49a683b33af74774a
SONUÇ: FARKLI ❌ — debuginfo derleme dizinini (DWARF comp_dir) sızdırıyor
```

#### Deney 3: Farklı `CARGO_HOME` (asıl tuzak)

`debug = false` ile, ama ikinci derleme farklı `CARGO_HOME` ile:

```
varsayılan CARGO_HOME : 7c2e382ad80a0c00b44a3e6743c42c02b8fac31cb4d655039a97c770f7b044c9
alternatif CARGO_HOME : 5d71f9aeb24cbc6e213b4259b6229069ccf604dd0f181b98e99fd472a4a28718
SONUÇ: FARKLI ❌
```
Sızan string:
```
/Users/adem/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/itoa-1.0.18/src/lib.rs
```
Sebep: bağımlılık içindeki `panic!`/`assert!` makroları `std::file!()` ile **mutlak kaynak yolunu** binary'e gömüyor. **Bu, farklı kullanıcı adına sahip iki makinede tekrarlanabilirliği kırar** — CI ile geliştirici makinesi arasında, veya iki farklı CI runner arasında.

#### Deney 4: Düzeltme — `--remap-path-prefix`

Hem proje dizinini hem `CARGO_HOME/registry`'yi remap ettim:

```bash
RUSTFLAGS="--remap-path-prefix=$CARGO_HOME/registry=/cargo \
           --remap-path-prefix=$PWD=/build"
```

```
build1 (yol A, cargo home A) : 3cd7b02ce6de710cedea15b8c9503e7ab394994215a189219589283bfae7c3bb
build2 (yol B, cargo home B) : 3cd7b02ce6de710cedea15b8c9503e7ab394994215a189219589283bfae7c3bb
SONUÇ: BİT DÜZEYİNDE AYNI ✅
```
Binary'deki string artık: `/cargo/src/index.crates.io-.../itoa-1.0.18/src/lib.rs`

#### Deney 4b: ÜÇÜNCÜ sızıntı kaynağı — rustup toolchain yolu

Remap sonrası kalan mutlak yolları aradım:
```
/Users/adem/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/alloc/src/collections/btree/navigate.rs
```

**Önceden derlenmiş `std`/`alloc` içindeki panic konumları, `std`'nin derlendiği makinenin rustup yolunu taşıyor.** İki derlemede aynıydı (aynı `RUSTUP_HOME`), ama **farklı `$HOME`'a sahip bir makinede bu değişir**. Bu yüzden reçeteye **üçüncü bir remap kuralı** gerekir:
```bash
--remap-path-prefix=$RUSTUP_HOME=/rustup
```
[NOT: Bu üçüncü kuralın farklı makinelerde etkinliğini bu oturumda birebir doğrulayamadım — CI'nızda iki farklı kullanıcı adıyla test edin. **[KISMEN DOĞRULANAMADI]**]

#### Özet: tekrarlanabilirliği kıran şeyler (ölçüm + kaynak)

| Kırıcı | Durum | Çözüm |
|---|---|---|
| Proje dizini mutlak yolu | ✅ ÖLÇTÜM: release'de sızmıyor, `debug`'da sızıyor | `--remap-path-prefix=$PWD=/build` |
| **`CARGO_HOME` registry yolu** | ❌ **ÖLÇTÜM: sızıyor, hash'i kırıyor** | `--remap-path-prefix=$CARGO_HOME/registry=/cargo` |
| **`RUSTUP_HOME` toolchain yolu** | ⚠️ ÖLÇTÜM: binary'de var | `--remap-path-prefix=$RUSTUP_HOME=/rustup` |
| Debug info (`comp_dir`) | ❌ **ÖLÇTÜM: `debug=1` hash'i kırıyor** | remap + `--remap-path-scope` veya `strip="debuginfo"` |
| rustc sürümü | Kesin kırar | `rust-toolchain.toml` ile sabitle |
| `Cargo.lock` çözümlemesi | Kırar | `--locked` |
| Incremental derleme | Kırar | Release'de zaten kapalı; `CARGO_INCREMENTAL=0` |
| `codegen-units` paralelliği | Genelde deterministik ama riskli | `codegen-units = 1` (hem repro hem perf) |
| `build.rs` non-determinizmi | Crate'e bağlı | `SOURCE_DATE_EPOCH`; vendor+offline |
| Linker'ın gömdüğü yollar | **rustc bunu remap ETMEZ** | Aşağıya bakın |

**Kritik uyarı [BİRİNCİL — doc.rust-lang.org/rustc/remap-source-paths.html]:** *"On Windows (`x86_64-pc-windows-msvc`) and Apple platforms, linkers embed absolute paths into debug info (`.pdb`, OSO entries) independently. These are **not remapped** by `--remap-path-prefix`."*

→ **Argus, reproducible release'lerini Linux'ta üretmelidir.** macOS/Windows binary'leri için bit-düzeyi tekrarlanabilirlik pratik değildir.

### C.2 `--remap-path-prefix` ve `--remap-path-scope` — stabilizasyon durumu

[BİRİNCİL — doc.rust-lang.org/rustc/remap-source-paths.html, 2026-09-08 çekimi]

- **`--remap-path-prefix`: STABİL.** `FROM=TO` formatı. `FROM` `=` içerebilir, `TO` içeremez. Birden çok eşleşmede **sonuncusu** uygulanır. **Tamamen metinsel değiştirme** — yol ayırıcı normalizasyonu yok (Windows'ta `/` ve `\` ayrı karakterlerdir).
- **`--remap-path-scope`: UNSTABLE (nightly).** Kapsamlar: `macro` (`std::file!()`, gömülü panic mesajları), `diagnostics`, `debuginfo`, `coverage`, `object` (= `macro,coverage,debuginfo` takma adı), `all` (varsayılan). Dokümanın kendi uyarısı: *"The `all` scope may correspond to different scopes between releases."*
- rustc'nin kendi ifadesi: bu bir **"best effort"** özelliğidir.

**Cargo tarafı — `trim-paths`: HÂLÂ UNSTABLE** [BİRİNCİL — 2026-09-08'de doğruladım]

İki kaynaktan teyit ettim:
1. `doc.rust-lang.org/cargo/reference/profiles.html` — `trim-paths` **listede yok** (yalnızca `opt-level`, `debug`, `split-debuginfo`, `strip`, `debug-assertions`, `overflow-checks`, `lto`, `panic`, `incremental`, `codegen-units`, `rpath`).
2. `doc.rust-lang.org/nightly/cargo/reference/unstable.html` — `trim-paths` unstable bölümünde. Takip issue'ları: [rust-lang/cargo#12137](https://github.com/rust-lang/cargo/issues/12137), [rust-lang/rust#111540](https://github.com/rust-lang/rust/issues/111540).

Kullanımı (nightly):
```toml
cargo-features = ["trim-paths"]
[profile.release]
trim-paths = "all"     # veya "object", "none"
```
Varsayılanlar: dev → `"none"`, release → `"object"`.

Build script'lere geçen ortam değişkenleri: `CARGO_TRIM_PATHS_SCOPE`, `CARGO_TRIM_PATHS_REMAP` (C/C++ derleyicilerine geçirmek için — `cc` crate'i kullanan bağımlılıklar için gerekli).

→ **Argus kararı:** `trim-paths`'i beklemeyin. **Stable `RUSTFLAGS` + `--remap-path-prefix` ile bugün çözün** (Deney 4 kanıtladı). `trim-paths` stabilize olunca geçin.

### C.3 Cargo'nun diğer ilgili unstable özellikleri (2026)

[BİRİNCİL — doc.rust-lang.org/nightly/cargo/reference/unstable.html]

#### `lockfile-publish-time` — **Argus için EN ÖNEMLİ gelecek özellik**

```bash
cargo generate-lockfile -Zunstable-options --publish-time <time>
```
Belirtilen zamandan **sonra yayımlanmış paketleri çözümlemeye almaz** — yani bağımlılıklar için bir **"bekleme süresi" (cooldown)** uygular.

Issue'lar: [cargo#5221](https://github.com/rust-lang/cargo/issues/5221) (orijinal), [cargo#16271](https://github.com/rust-lang/cargo/issues/16271) (takip).

**Bunun neden hayati olduğunu bir sayıyla gösterelim:** Ağustos 2026 `arrayref` saldırısında kötü niyetli sürümler **86, 90 ve 107 dakika** yayında kaldı. **7 günlük bir cooldown politikası bu saldırıyı sıfır etkiyle geçiştirirdi.** Aynısı Mart 2026'daki beş crate ve Aralık 2025 kampanyası için de geçerli.

Bu özelliği mümkün kılan altyapı **Ocak 2026'da geldi**: crates.io index'ine `pubtime` alanı eklendi [BİRİNCİL — blog.rust-lang.org/2026/01/21/crates-io-development-update].

→ **Argus şimdi ne yapmalı:** Stable'da bu yok. Ama **elle uygulayabilirsiniz**: `Cargo.lock`'u dondurun, bağımlılık güncellemelerini **haftalık toplu batch** halinde yapın ve batch'i, içindeki en yeni crate'in yayın tarihinden **≥7 gün sonra** merge edin. Dependabot/Renovate'ı otomatik-merge'den çıkarın. Renovate'ta `minimumReleaseAge: "7 days"` ayarı bunu doğrudan destekler.

#### `sbom` — Cargo'nun yerleşik SBOM'u

```toml
[unstable]
sbom = true
[build]
sbom = true
```
veya `CARGO_BUILD_SBOM=true cargo +nightly -Z sbom build`

Her derlenen artifact'ın yanına `<artifact>.cargo-sbom.json` üretir: crate ID'leri, türleri, feature'lar, bağımlılıklar ve **rustc bilgisi**. RFC [#3553](https://github.com/rust-lang/rfcs/pull/3553), PR [#13709](https://github.com/rust-lang/cargo/pull/13709). Build script'lere `CARGO_SBOM_PATH` geçer.

**Durum: UNSTABLE.** Bunlar "SBOM ön-ürünü" (precursor) dosyalarıdır — CycloneDX/SPDX değil; bir SBOM aracının tüketmesi beklenir.

#### `checksum-freshness`
```toml
[unstable]
checksum-freshness = true
[build]
fingerprint = "content"   # varsayılan "mtime"
```
Yeniden derleme kararını mtime yerine içerik checksum'ıyla verir. [cargo#14136](https://github.com/rust-lang/cargo/issues/14136). CI'da mtime güvenilmez olduğu için faydalı. Not: **build script'lerin okuduğu dosyalar hâlâ mtime kullanıyor.**

#### `build-std`
`std`'yi kaynaktan derler. Reproducible build için teorik olarak ideal (C.1 Deney 4b'deki rustup yolu sorununu kökten çözer) ama *"still in very early stages of development"* ve nightly gerektirir. **Argus için 2026'da önerilmez.**

### C.4 Reproducible Builds projesi ve Rust

[BİRİNCİL — reproducible-builds.org/docs/rust/]

Projenin kendi değerlendirmesi: Rust programları, **orijinal derleme zinciri sürüm-eşleşmeli ve derleme yolları normalize edilmişse "often already reproducible by default"**. Rehberleri:

- `cargo build --release --locked` kullanın — cargo'nun semver-uyumlu daha yeni sürümlere kaymasını engeller.
- Sorun ayıklama: `target/` dizininde **diffoscope** çalıştırın, sorunu tek crate'e indirgeyin. `.rustc_info.json` ve `.fingerprint/` dosyalarını **yok sayın**.
- Zaman damgaları: *"very uncommon for Rust programs to record the date and time the binary has been compiled"* — ama `SOURCE_DATE_EPOCH` varsa saygı gösterilmeli.
- `rust-embed` kullanıyorsanız **`deterministic-timestamps`** feature'ını açın (aksi halde dosya sistemi metadata'sı binary'e girer). → Argus login sayfası/statik varlıkları gömecekse **bu maddeyi kaçırmayın.**

[BİRİNCİL — reproducible-builds.org/citests/] **Rust/crates.io, RB projesinin sürekli test altyapısında ayrı bir proje olarak izlenmiyor.** İzlenenler: coreboot, Debian, FreeBSD, NetBSD (dahilî); Arch Linux, GNU Guix, Go, NixOS, openSUSE, openEuler, Qubes OS, Yocto, Trisquel, rattler-build (harici); Alpine, Fedora, OpenWrt (devre dışı).

→ Rust paketleri **dolaylı olarak** Debian/Arch/NixOS üzerinden test ediliyor. Rust'a özel bir yüzde metriği **[DOĞRULANAMADI]** — arama kotası bittiği için 2025-2026 aylık raporlarını tarayamadım.

**rustc'nin kendi tekrarlanabilirliği:** [rust-lang/rust#34902](https://github.com/rust-lang/rust/issues/34902), 18 Temmuz 2016'da açılmış izleme issue'su, **kapatılmış**. Orijinal bulgular: build-id farkları, ELF section header konumu farkları (4 bayt), ortam varyasyonlarından kaynaklanan tutarsızlıklar. Kapanma gerekçesi ve tarihi **[DOĞRULANAMADI]** — GitHub sayfası yorumları yükleyemedi.

### C.5 Argus için pratik reproducible release reçetesi

Bunlar Deney 1-4'ten çıkan, **test edilmiş** ayarlardır.

**1) `rust-toolchain.toml` (repo kökü) — sürümü çiviler**
```toml
[toolchain]
channel = "1.98.1"
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
profile = "minimal"
```

**2) `Cargo.toml` release profili**
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
`overflow-checks = true` bir IdP için önemlidir: token sayaçları, rate-limit hesapları, süre aritmetiği sessizce sarmamalıdır. Maliyeti ihmal edilebilir.

**3) `.cargo/config.toml` — üç remap kuralı**
```toml
[build]
rustflags = [
  "--remap-path-prefix=/build=/b",
  "--remap-path-prefix=/cargo/registry=/c",
  "--remap-path-prefix=/rustup=/r",
]
```
(Container içinde yolları sabitlerseniz remap ihtiyacı azalır — aşağıya bakın.)

**4) Konteyner içinde sabit yollar — en sağlam yaklaşım**

Remap ile uğraşmak yerine **yolları determinize edin**:
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
Herkes `/build` ve `/cargo` kullanınca C.1'deki üç sızıntı kaynağı da ortadan kalkar. **Base imajı digest ile pinleyin** — `rust:1.98.1` etiketi yeniden yayımlanabilir.

**5) Vendored + offline — build-time ağ erişimini kes**
```bash
cargo vendor --versioned-dirs vendor
cargo build --release --locked --offline
```
Bu, Ağustos 2026 saldırısının **payload indirme adımını** engellerdi. Vendor tarball'ının SHA-256'sını release artifact'ı olarak yayınlayın.

**6) Doğrulama adımı — CI'da iki kez derleyip karşılaştırın**
```yaml
- name: Reproducibility gate
  run: |
    docker build -t argus:a -f Dockerfile.repro .
    docker run --rm argus:a cat /out/argus | sha256sum > a.txt
    docker build --no-cache -t argus:b -f Dockerfile.repro .
    docker run --rm argus:b cat /out/argus | sha256sum > b.txt
    diff a.txt b.txt || { echo "REPRODUCIBILITY BROKEN"; exit 1; }
```
Bunu **bloklayıcı** yapın. Tekrarlanabilirliği kaybetmek sessizce olur; kapı olmadan fark etmezsiniz.

**7) Nix (opsiyonel, güçlü)**
`crane` veya `naersk` ile hermetik, içerik-adresli derleme. Ekipte Nix bilgisi yoksa **maliyeti yüksektir** — container + vendor + pinned toolchain %90'ını zaten verir. Nix'i ancak "en güvenli" iddiasını denetçiye kanıtlamanız gerekiyorsa değerlendirin.

**8) OCI imaj tekrarlanabilirliği**
Binary reproducible olsa bile imaj olmayabilir: katman zaman damgaları, dosya sıralaması, metadata. Çözümler:
- `SOURCE_DATE_EPOCH` + BuildKit'in `rewrite-timestamp` özelliği,
- veya **`nix build` / `ko` / `apko`** ile deterministik imaj üretimi,
- veya en basit: **binary'yi imzalayın, imajı değil** — imaj digest'i zaten değişmezdir; tekrarlanabilirliği binary düzeyinde iddia edin.

---

## D) SBOM VE SLSA

### D.1 Rust için SBOM araçları

[ÖLÇÜM — crates.io API, 2026-09-08]

| Araç | Sürüm | Son güncelleme | 90 gün | Format | Değerlendirme |
|---|---|---|---|---|---|
| `cargo-cyclonedx` | 0.5.9 | 2026-03-19 | 747.740 | CycloneDX | **Açık ara lider** |
| `cargo-sbom` | 0.10.0 | 2025-06-17 | 56.461 | SPDX + CycloneDX | Bakım yavaşlamış |
| `cargo-auditable` | 0.7.5 | 2026-06-28 | 249.877 | gömülü JSON | **Tamamlayıcı, şart** |
| `cargo-spdx` | 0.1.0 | **2022-05-10** | **22** | SPDX | **ÖLÜ — kullanmayın** |
| `syft` (Anchore) | — | aktif | — | ikisi de | Container/binary tarama |

**`cargo-cyclonedx`** [BİRİNCİL — github.com/CycloneDX/cyclonedx-rust-cargo]: İki bileşen — `cyclonedx-bom` (kütüphane) ve `cargo-cyclonedx` (uygulama). 1.314 commit, 175 yıldız, 66 fork, 38 açık issue. Deponun kendi güvenlik uyarısı: *"cargo-cyclonedx calls into Cargo internally"* — güvenilmeyen bir proje üzerinde çalıştırırsanız **keyfi kod çalıştırabilir** (build.rs!). CI'da yalnızca kendi kodunuz üzerinde çalıştırın.

Desteklenen tam CycloneDX spec sürümleri **[DOĞRULANAMADI]** — depo sayfası listelemiyor.

### D.2 CycloneDX vs SPDX — Rust için hangisi?

| Boyut | CycloneDX | SPDX |
|---|---|---|
| Rust araç desteği | **Güçlü** (`cargo-cyclonedx`, 748k/90gün) | Zayıf (`cargo-spdx` ölü; `cargo-sbom` ve syft var) |
| Yönetişim | OWASP | Linux Foundation / ISO/IEC 5962:2021 |
| purl (`pkg:cargo/...`) | Yerel destek | Destekli (ExternalRef) |
| VEX | **Yerleşik** (CycloneDX VEX) | Ayrı (CSAF/OpenVEX ile) |
| Güvenlik odağı | Yüksek | Lisans/uyum odağı ağır basar |
| CRA/EO uyumu | Kabul edilir | Kabul edilir |

**Argus tavsiyesi:**
- **Birincil: CycloneDX** — Rust tooling'i olgun, VEX yerleşik, güvenlik odaklı. Dependency-Track (OWASP) ile doğrudan çalışır.
- **İkincil: SPDX** — bazı kurumsal/kamu alıcıları ISO standardı olduğu için SPDX ister. `syft` ile aynı artifact'tan üretin; ikinci bir doğruluk kaynağı yaratmayın.
- **Üçüncüsü değil, temeli: `cargo-auditable`** — binary'nin içine gömün. Dosya tabanlı SBOM'lar birbirinden kopar; gömülü olan kopmaz.

**VEX neden Argus için kritik:** Bölüm A.5'te gösterdim — minimal yığında bile 14 `unsound` işaretli bağımlılık var. Müşteriniz Grype/Trivy çalıştırıp size 60 bulgu ile gelecek. Bunların çoğu Argus'un kullandığı kod yolunda **sömürülemez**. VEX belgesi tam olarak bunu söylemek içindir: *"bu bileşen etkilenmiyor, çünkü etkilenen fonksiyonu çağırmıyoruz"*. VEX üretmezseniz, destek ekibiniz bu soruyu her müşteriye elle cevaplar. **VEX'i ürünün parçası yapın.**

**Tüketiciler:** Dependency-Track (CycloneDX'i doğrudan alır, sürekli izler), Grype, Trivy, osv-scanner. Argus müşterilerine SBOM'u yayınlarken Dependency-Track uyumluluğunu hedefleyin.

### D.3 SLSA — 2026 durumu

**⚠️ Güncel sürüm v1.1 DEĞİL, v1.2'dir.** [BİRİNCİL — slsa.dev/spec/, "Approved"]. v1.1 "retired" olarak işaretlenmiş.

#### Build track (v1.2)

[BİRİNCİL — slsa.dev/spec/v1.2/build-requirements]

| Seviye | Ad | Gereksinim |
|---|---|---|
| **L0** | Garanti yok | Hiçbir gereksinim. Tek makinede geliştirme/test. |
| **L1** | Provenance Exists | Üretici tutarlı bir derleme süreci izler ve provenance'ı tüketicilere dağıtır. Platform, artifact'ı **kriptografik digest** ile tanımlayan provenance üretir. |
| **L2** | Hosted / Authentic | L1 + derleme **barındırılan platformda** çalışır (kişisel iş istasyonunda değil). Platform provenance'ı **kendisi imzalar**; imza anahtarı yalnızca platforma erişilebilir. *"The build platform MUST have some security control to prevent tenants from tampering."* Tüketici imzayı doğrular. |
| **L3** | Hardened / Unforgeable | L2 + provenance *"strongly resistant to forgery by tenants"*. Kimlik doğrulama sır materyali güvenli saklanır ve **kullanıcı tanımlı derleme adımlarına erişilemez**. *"Every field in the provenance MUST be generated or verified by the build platform in a trusted control plane."* İzolasyon: derlemeler platform sırlarına erişemez, eşzamanlı derlemeler birbirini etkileyemez, *"An ephemeral build environment MUST be provisioned for each build"*, cache zehirlenmesi önlenir, dış servisler provenance parametrelerinde yakalanır. |

**L4 yoktur.** (SLSA v0.1'de vardı, v1.0'da kaldırıldı.)

#### Source track (v1.2'de YENİ) [BİRİNCİL — slsa.dev/spec/v1.2/source-requirements]

v1.2'nin ana yeniliği. Dört seviye:

| Seviye | Ad | Gereksinim |
|---|---|---|
| **L1** | Version Controlled | Modern bir VCS kullanılır; "discrete Source Revisions" mümkün. |
| **L2** | History & Provenance | Sürekli, değişmez branch geçmişi + her revizyon için provenance attestation'ı — *"tamper-resistant evidence of when changes were made, who made them, and which technical controls were enforced."* |
| **L3** | Continuous Technical Controls | Korumalı branch'lerde teknik kontroller belgelenir ve uygulanır; doğrulayıcıya güçlü kanıt sunulur. |
| **L4** | Two-Party Review | *"two or more trusted persons"* değişiklikleri onaylamadan korumalı branch'e giremez. İçeriden tehdit ve tek taraflı kötü niyetli değişiklik riskini ciddi azaltır. |

Ayrıca **Source Verification Summary Attestation (VSA)** ile ulaşılan seviye downstream'e bildirilir.

**→ Argus için stratejik öneri:** "En güvenli IdP" iddiasını en ucuz ve en inandırıcı şekilde destekleyecek şey **Source Track L4'tür**: GitHub'da branch protection + zorunlu 2 onay + imzalı commit + linear history. Bu, **sıfır altyapı maliyetiyle** elde edilir ve Ağustos 2026 `arrayref` saldırısının kök nedenine (tek maintainer'ın ele geçirilmesi) doğrudan cevaptır.

#### SLSA Build L3'e GitHub Actions ile ulaşmak

**⚠️ ÖNEMLİ 2026 GÜNCELLEMESİ:** [BİRİNCİL — github.com/slsa-framework/slsa-github-generator]

**`slsa-github-generator` ARTIK BAKILMIYOR.** Son sürüm **v2.1.0, Şubat 2025**. Depo ifadesi: *"provenance that has already been generated remains valid, and the reusable workflows here continue to work. They should not be assumed to receive updates."*

Resmî tavsiye: *"GitHub artifact attestations, a built-in solution for generating SLSA provenance on GitHub"* — doğrulama `slsa-verifier` yerine **`gh attestation verify`** ile.

Sunduğu builder'lar (tarihsel): Go (stable v1.0.0), Node.js (beta v1.6.0), Maven/Gradle (beta v1.9.0), Docker/container (beta v1.7.0), Bazel (WIP), **Generic generator** (stable v1.2.0 — dil bağımsız). **Rust'a özel builder hiç olmadı.**

**→ Argus doğru yol: `actions/attest-build-provenance`**

[BİRİNCİL — github.com/actions/attest-build-provenance]
- Artifact'ı (ad + digest) bir **in-toto** formatlı **SLSA build provenance predicate**'ine bağlar.
- **v4'ten itibaren `actions/attest` üzerine ince bir sarmalayıcı.**
- **Sigstore kullanır**: *"short-lived Sigstore-issued signing certificate"*. Public repo'lar **public-good Sigstore** instance'ını, private/internal repo'lar **GitHub'ın private Sigstore** instance'ını kullanır.
- Doğrulama: `gh attestation verify`.
- Erişim: public repo'lar tüm planlarda; **private/internal repo'lar GitHub Enterprise Cloud gerektirir**. ← Argus kapalı kaynak geliştirilecekse **bu bir maliyet kalemidir**.
- Sayfada **hangi SLSA seviyesine ulaştığı belirtilmiyor** [DOĞRULANAMADI]. GitHub-hosted runner + ephemeral VM + OIDC ile üretilen provenance L3 gereksinimlerini karşılamaya *yakındır*, ancak bunu resmî bir GitHub beyanına dayandıramadım. **Pazarlamada "SLSA L3" demeden önce doğrulayın.**

Örnek:
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

**Küçük ekip için gerçekçi hedef:**

| Hedef | Efor | Argus için |
|---|---|---|
| Build L1 | ~1 saat | Hemen |
| Build L2 | ~1 gün | Hemen (GitHub-hosted runner + attest action) |
| Build L3 | ~1 hafta | Ulaşılabilir — self-hosted runner **kullanmayın**, GitHub-hosted kalın |
| Source L4 | ~2 saat | **En yüksek getirili hamle** |

**Self-hosted runner uyarısı:** Kendi runner'ınızı kullanırsanız L3'ün "ephemeral build environment MUST be provisioned for each build" ve "concurrent builds cannot influence each other" gereksinimlerini **kendiniz kanıtlamak zorundasınız**. 2-5 kişilik ekip için bu gerçekçi değil. GitHub-hosted kalın.

---

## E) İMZALAMA VE ATTESTATION

### E.1 Sigstore [BİRİNCİL — docs.sigstore.dev/about/overview/]

Üç bileşen:
- **Cosign** — imzalama/doğrulama istemcisi
- **Fulcio** — OIDC kimliğine bağlı **kısa ömürlü** sertifika üreten CA
- **Rekor** — değişmez, yalnızca-ekleme şeffaflık günlüğü (transparency log)

Temel fikir: *"Sigstore addresses these problems by helping users move away from a key-based signing approach to an identity-based one"* — uzun ömürlü anahtar çifti yönetmek yerine, OIDC kimliğinizle geçici anahtar alırsınız ("keyless signing").

Yönetişim: **OpenSSF / Linux Foundation** altında; katkıcılar Google, Red Hat, Chainguard, GitHub, Purdue University. Public-good instance ücretsiz.

**Olgunluk 2026:** Cosign v2 uzun süredir GA; GitHub'ın yerleşik attestation'ları Sigstore üzerine kurulu (yukarıya bakın) — bu, **fiili ekosistem standardı** olduğunun en güçlü göstergesidir.

### E.2 Crate imzalama — crates.io'da var mı?

**KISA CEVAP: HAYIR.**

[BİRİNCİL — github.com/rust-lang/crates.io/issues/75] Kasım 2014'te açılan TUF (The Update Framework) issue'su — geliştiricilerin kendi imzalama anahtarlarını yönetmesini öneriyordu — **kapatılmış**. Kapanma tarihi ve gerekçesi **[DOĞRULANAMADI]** (GitHub sayfası yorumları yükleyemedi).

**crates.io'nun bütünlük modeli imza değil, şudur:**
1. **SHA-256 checksum'lar** — index'te ve `Cargo.lock`'ta. TOFU (trust-on-first-use) modeli.
2. **Sparse index** (HTTPS üzerinden) — Ocak 2026'dan itibaren **Fastly CDN** üzerinden [BİRİNCİL — blog.rust-lang.org/2026/01/21/crates-io-development-update].
3. **Trusted Publishing** (OIDC) — imza değil, **yayımlama kimlik doğrulaması** (bkz. G.1).
4. **`.crate` dosyaları değişmezdir** — bir sürüm yayımlandıktan sonra üzerine yazılamaz.

**`cargo-sigstore` veya crates.io'ya entegre bir crate imzalama çözümü: [DOĞRULANAMADI]** — arama kotası tükendiği için var olup olmadığını teyit edemedim. Bildiğim kadarıyla **üretimde kullanılan böyle bir standart yok**. Argus'un tehdit modelinde crates.io'ya güveni "TOFU + checksum + platform güvenliği" olarak modelleyin, "kriptografik yayımcı imzası" olarak değil.

→ **Argus'un yapabileceği:** Kendi crate'lerinizi (SDK'lar) yayımlarken Trusted Publishing kullanın **ve ayrıca** her release'in tarball'ını cosign ile imzalayıp GitHub Release'e ekleyin. crates.io imza sunmuyorsa siz sunun.

### E.3 in-toto ve SLSA provenance formatı

- **in-toto attestation** = zarf formatı: `subject` (artifact adı + digest) + `predicateType` + `predicate`.
- **SLSA Provenance** = bir predicate türü (`https://slsa.dev/provenance/v1`): derlemeyi kimin, hangi kaynaktan, hangi build platformunda, hangi parametrelerle yaptığı.
- GitHub `attest-build-provenance` tam olarak bu ikisini üretir ve Sigstore ile imzalar.

**Argus'un üretmesi gereken attestation seti:**

| Attestation | Ne söyler | Araç |
|---|---|---|
| SLSA Provenance | "bu binary bu commit'ten, bu workflow ile üretildi" | `actions/attest-build-provenance` |
| SBOM attestation | "bu binary bu bileşenleri içerir" | `actions/attest-sbom` veya `cosign attest --type cyclonedx` |
| VEX | "şu CVE bizi etkilemiyor, çünkü…" | elle/OpenVEX |
| Test/scan attestation | "cargo-deny + cargo-audit temiz geçti" | `cosign attest` özel predicate |
| **Reproducibility attestation** | "iki bağımsız derleme aynı digest'i verdi" | özel predicate — **farklılaştırıcı** |

Son madde Argus'a özgü bir pazarlama+güvenlik avantajıdır: çok az ürün bunu yapıyor.

### E.4 Dağıtımda doğrulama

**cosign ile:**
```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/ORG/argus/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/org/argus:v1.2.3
```
**Kritik:** `--certificate-identity-regexp` ve `--certificate-oidc-issuer` **zorunludur**. Bunlar olmadan `cosign verify` "birisi imzalamış" der, "biz imzalamışız" demez. Dokümantasyonunuzda müşterilere **tam komutu** verin.

**GitHub attestation ile:**
```bash
gh attestation verify ./argus --repo ORG/argus
```

**Kubernetes admission:**

[BİRİNCİL — github.com/sigstore/policy-controller] Sigstore Policy Controller: *"can be used to enforce policy on a Kubernetes cluster based on verifiable supply-chain metadata from cosign."* Yetenekleri: imza+attestation doğrulama, **tag→digest çözümleme** (admission ile runtime arasında tutarlılık), namespace bazlı politika, çoklu anahtar. Durum: 3.908 commit, 178 yıldız, **aylık minor release kadansı**. Son sürüm tarihi **[DOĞRULANAMADI]**.

**Alternatifler:** Kyverno (`verifyImages` kuralı — daha geniş politika motoru, daha büyük topluluk), OPA/Gatekeeper + ratify.

→ **Argus önerisi:** Kendi Kubernetes deployment'ınızda Kyverno kullanın (genel amaçlı politika motoru olarak zaten işinize yarar). **Müşterilerinize** ise doğrulama komutlarını ve public key/identity bilgisini **kurulum dokümanının ilk sayfasında** verin. Bir IdP'de imaj doğrulaması opsiyonel bir "nice to have" değil, kurulum adımıdır.

---

## F) RUST TEDARİK ZİNCİRİ SALDIRILARI

Bu bölüm raporun en güçlü kanıt tabanına sahip kısmı: RustSec advisory veritabanını klonlayıp **kötü amaçlı kod advisory'lerinin tamamını** çıkardım.

### F.1 Kötü amaçlı crate advisory'leri — tam envanter [ÖLÇÜM]

`categories = ["malicious"]` içeren **75 advisory**. Yıllara göre:

| Yıl | Sayı |
|---|---|
| 2022 | 1 |
| 2023 | 28 |
| **2024** | **0** |
| 2025 | 14 |
| **2026** | **32** (8 Eylül'e kadar) |

2024'te sıfır, 2026'da rekor. **Trend açıkça kötüleşiyor.**

### F.2 `rustdecimal` (2022) — ilk vaka

**RUSTSEC-2022-0042**, 10 Mayıs 2022. `rust_decimal`'ın (yaygın finansal ondalık sayı crate'i) tipo-eşkıyalığı. Rust ekosisteminin ilk kamuya açık kötü amaçlı crate vakası ve `malicious` kategorisinin tek 2022 kaydı.

### F.3 2023 — kitlesel tipo-eşkıyalık kampanyaları

28 advisory, iki dalga halinde:

**Ağustos 2023 (16 Ağustos):** `envlogger`, `if-cfg`, `lazystatic`, `oncecell`, `postgress`, `serd`, `xrvrv`, `postgresderive` (18 Ağustos). Hedef: `env_logger`, `cfg-if`, `lazy_static`, `once_cell`, `postgres`, `serde` — **hepsi en popüler crate'lerin tipo varyantları.**

**Kasım 2023 (6–22 Kasım):** Windows/kripto odaklı ikinci dalga — `windows-service-rs`, `windowsservice`, `win-crypto`, `win-base64-rs`, `win_run_rs`, `winx-rs`, `registry-win`, `libusb1-main`, `openvpn-plugin-rs`, `monero-api`, `monero-rpc-rs`, `acceptxmr-rs`, `lasso-rs`, `lfest-main`, `hann-rs-service`, `tiny-server`, `littest`, `bit-flags`, `tauri-winrt-notifications`, `tauri-win-rt-notification`.

Kripto para (Monero, AcceptXMR) ve Windows sistem API'leri hedefi belirgin.

### F.4 2025 — kripto/DeFi ve altyapıya kayış

14 advisory:

| Tarih | Crate | Not |
|---|---|---|
| 2025-01-30 | `custom-req-on-workers`, `jfrog_quotes` | |
| 2025-02-10 | `rands` | `rand` tiposu |
| 2025-02-15 | `sophosfirewall-python` | Rust'ta Python adı — çapraz-ekosistem kafa karıştırma |
| 2025-03-10 | `tree-sitter-pkl` | |
| 2025-08-26 | `statsrelay-protobuf` | |
| 2025-11-04 | `replit_ruspty` | **Replit'in gerçek paketinin tiposu** |
| 2025-12-03 | `uniswap-utils`, `evm-units` | DeFi |
| 2025-12-05 | `sha-rust`, `finch-rust` | |
| 2025-12-09 | `sha-rst`, `finch-rst`, `finch_cli_rust` | |

Aralık 2025'teki `finch-*`/`sha-*` kümesi tek bir koordineli kampanyadır (5 crate, 6 gün).

### F.5 2026 — **32 advisory, nitel bir sıçrama**

#### F.5.1 Şubat–Mart 2026: Polymarket kümesi + CI/CD sır hırsızlığı

**Polymarket tipoları** (4 crate): `polymarket-clients-sdk` (6 Şub), `polymarket-client-sdks` (13 Şub), `polymarkets-client-sdk` (19 Şub), `polymarkets-rs-clob-client` (20 Şub) + `clob-sdk` (20 Şub), `rpc-check` (19 ve 24 Şub — iki ayrı advisory).

**"Beş kötü amaçlı Rust crate'i" kampanyası** [BİRİNCİL — thehackernews.com, 11 Mart 2026]:

Crate'ler: **`chrono_anchor`, `dnp3times`, `time_calibrator`, `time_calibrators`, `time-sync`** — hepsi zaman ile ilgili yardımcı program kılığında.

- Socket'ten Kirill Boychenko: *"Their core behavior is credential and secret theft."*
- Hedef: **`.env` dosyaları** — API anahtarları, token'lar.
- `chrono_anchor` en gelişmişi: exfiltration mantığını **`guard.rs`** adlı dosyaya gömerek tespitten kaçınıyor.
- **Kalıcılık kurmuyor**; bunun yerine CI iş akışlarında her çağrıldığında `.env` çalmayı tekrar deniyor.
- Yayın: Şubat sonu – Mart başı 2026. Bulan: **Socket**.

RustSec kayıtları [ÖLÇÜM]: `chrono_anchor` RUSTSEC-2026-0039 (10 Mart), `dnp3times` RUSTSEC-2026-0032 (4 Mart), `time_calibrator` RUSTSEC-2026-0030, `time_calibrators` RUSTSEC-2026-0031 (3 Mart), `time-sync` RUSTSEC-2026-0036 (4 Mart). Ayrıca ilişkili: `tracing-check` RUSTSEC-2026-0019, `tracings` RUSTSEC-2026-0027, `tracing_checks` RUSTSEC-2026-0028 (*"for transitively including malicious code"*), `tracing-ethers` RUSTSEC-2026-0040.

**→ Argus için doğrudan ders:** Bu kampanya **CI'daki `.env` dosyalarını** hedefledi. Argus'un CI'sında **hiçbir zaman `.env` dosyası bulunmamalı**; sırlar OIDC/kısa ömürlü token ile alınmalı, dosyaya yazılmamalı.

#### F.5.2 **20 Ağustos 2026 — `arrayref` saldırısı: Rust ekosisteminin dönüm noktası**

Bu, Rust'ın "npm'de olur bizde olmaz" dönemini bitiren olaydır. **Tipo-eşkıyalık değil; gerçek, popüler crate'lerin ele geçirilmesi.**

**Etkilenen crate'ler ve indirme sayıları** [BİRİNCİL — research.jfrog.com/post/arrayref-proc-macro1-crates-io/]:

| Crate | Kötü sürüm | Toplam indirme (10 yıl) |
|---|---|---|
| `arrayref` | 0.3.10 | **~245.000.000** |
| `internment` | 0.8.7 | ~14.400.000 |
| `append-only-vec` | 0.1.9 | ~4.500.000 |

**Zaman çizelgesi** [BİRİNCİL — blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/, tüm saatler UTC]:

```
07:15  arrayref@0.3.10 yayımlandı  |  Güvenlik ekibine ilk rapor ulaştı (aynı dakika)
07:29:50  Socket'in AI tarayıcısı proc-macro1'i bağımsız tespit etti
07:34  internment@0.8.7 yayımlandı
07:37  append-only-vec@0.1.9 yayımlandı
08:41–09:25  Kötü amaçlı sürümler silindi
```
Yayında kalma süreleri: **arrayref 86 dk, internment 90 dk, append-only-vec 107 dk.**

**Saldırı mekanizması — üç aşamalı:**

1. **Aşama 1 (dropper enjeksiyonu):** Saldırgan kötü kodu doğrudan gömmedi; bunun yerine meşru crate'lere **`proc-macro1`** adlı yeni bir bağımlılık ekledi — `proc-macro2`'nin tipo-eşkıyası. RustSec'in ifadesi [ÖLÇÜM — RUSTSEC-2026-0260]: *"That line added a dependency never seen before in a decade of the package's history."*

2. **Aşama 2 (dropper):** `proc-macro1`'in **`build.rs`**'i. JFrog'un kritik notu: *"In Rust, a `build.rs` script is compiled and executed automatically during `cargo build`, `cargo check`, and similar commands, including CI and rust-analyzer driven builds."* — **Crate'ten hiçbir fonksiyon çağırmanız gerekmiyor. Derlemek yeterli. Hatta editörde açmak yeterli.**

3. **Aşama 3 (payload):** Platforma özel payload indirilip C2 argümanlarıyla çalıştırıldı. **Linux, Windows ve macOS** hedeflendi.

**Teknik IOC'ler** [BİRİNCİL — JFrog]:
- C2 URL'leri **bölünmüş Base64 parçalarıyla** gizlendi
- **TLS sertifika doğrulaması kasten kapatıldı**
- Unix'te `/tmp/rust-setup`'a yazıldı
- Windows'ta PowerShell execution policy bypass'ı
- Payload analiz için ele geçirilemedi

**Nasıl erişildi:** Rust güvenlik ekibinin ifadesi: *"We do not believe the author of `arrayref` to be acting maliciously, but their computer or credentials are likely compromised."* — yani **maintainer'ın makinesi veya kimlik bilgileri ele geçirildi**, gönüllü işbirliği değil.

**Etki:** `arrayref` 0.3.10 **2.285 kez indirildi** — tüm sürümler arasındaki trafiğin **%10'undan azı**, çünkü çoğu kullanıcının `Cargo.lock`'unda eski sürüm sabitliydi.

**→ Bu son cümle Argus için en önemli tek çıkarımdır: `Cargo.lock`'u commit etmek, bu saldırıda kullanıcıların %90'ını kurtardı.**

**crates.io müdahalesi:** Kötü sürümler silindi, meşru olarak yanklanmış sürümler geri alındı (unyank), yazarın hesabı **önlem olarak kilitlendi**. `proc-macro1` (2 sürüm) ve `proc-macro-en` (1 sürüm) tamamen silindi, ilgili hesaplar kilitlendi.

**Bildirenler** [ÖLÇÜM — RUSTSEC-2026-0265]: *"the Research Team at Nextron Systems GmbH"*; koordinasyon: *"Emily Albini for coordinating with the crates.io and infra-admin teams."*

**Atıf:** Bazı kaynaklar Kuzey Kore bağlantısı iddia ediyor [DOĞRULANAMADI — resmî Rust blogu atıf yapmıyor].

#### F.5.3 Mayıs 2026: "TrapDoor" — çok ekosistemli kampanya

[BİRİNCİL — thehackernews.com, 25 Mayıs 2026; keşif: Socket.dev]

- **34+ kötü amaçlı paket, 384+ sürüm**
- npm: 20 paket (`async-pipeline-builder`, `crypto-credential-scanner`, `web3-secrets-detector`…)
- PyPI: 7 paket (`cryptowallet-safety`, `eth-security-auditor`, `solidity-build-guard`…)
- **crates.io: 6 Rust crate'i** (`move-analyzer-build`, `sui-framework-helpers`…)
- Hedef kitle: kripto, DeFi, Solana, AI toplulukları
- Çalınanlar: geliştirici sırları, kripto cüzdanlar, **SSH anahtarları**, bulut kimlik bilgileri, tarayıcı verisi, ortam değişkenleri
- İlk aktivite: **22 Mayıs 2026, 20:20 UTC**

RustSec'te ilgili kayıtlar [ÖLÇÜM]: `sui-execution-cut` RUSTSEC-2026-0108 (23 Nis), `mysten-metrics` RUSTSEC-2026-0107 (22 Nis) — Sui/Move ekosistemi hedefi.

#### F.5.4 Haziran 2026: `onering`

**RUSTSEC-2026-0175**, 10 Haziran 2026, `onering` 1.4.1 — kod exfiltration'ı. Aikido tarafından raporlandı.

#### F.5.5 **6–7 Eylül 2026: PolinRider crates.io'ya ulaştı — DÜN**

Bu, raporun en taze bulgusudur. [ÖLÇÜM — RUSTSEC-2026-0280, 2026-09-07]:

> *"A new version of the `greentic-setup-dev` crate was published with a variant of the **PolinRider malware** included that would fire when a project depending on `greentic-setup-dev` was opened in **Visual Studio Code**."*
>
> *"One malicious version was published on 2026-09-06, approximately **27 hours** before removal. This crate has no dependencies on crates.io. We have no evidence that this crate version was downloaded by any actual users."*
>
> *"Thanks to the Research Team at Nextron Systems GmbH for the report."*

Kardeş advisory: **RUSTSEC-2026-0281**, `greentic-setup` 1.3.1-dev.34027618345.

**PolinRider nedir:** Kuzey Kore bağlantılı (Lazarus Group / APT37) çok ekosistemli kampanya. npm, Packagist, Go modülleri ve Chrome Web Store'da **en az 108 kötü amaçlı paket ve tarayıcı eklentisi**. Teknik: gizlenmiş JavaScript'i **ele geçirilmiş geliştiricilerin `.vscode/tasks.json` dosyalarında**, sahte `.woff2` fontlarında ve `tailwind.config.js`, `postcss.config.mjs`, `eslint.config.mjs`, `App.js`, `babel.config.cjs` gibi meşru config dosyalarında saklıyor. Payload'lar (DEV#POPPER, OmniStealer): keyfi komut çalıştırma, kimlik bilgisi toplama, tarayıcı verisi exfiltration, kripto cüzdan hırsızlığı, `socket.io-client` ile C2. [Kaynaklar: socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands; rescana.com; sonatype.com]

**→ Argus için kritik ders:** Bu saldırı **`build.rs` bile kullanmıyor** — VS Code'un `tasks.json` mekanizmasını kullanıyor. Yani `cargo build`'i sandbox'lamak yetmez. **Bir bağımlılığın kaynak ağacındaki `.vscode/` dizini bir saldırı vektörüdür.** `cargo vendor` sonrası vendored ağaçta `.vscode/`, `.devcontainer/`, `.githooks/` dizinlerini tarayın ve CI'da reddedin.

### F.6 npm ile karşılaştırma: Shai-Hulud **gerçektir** (doğrulandı)

Kullanıcı "if it exists" diye sormuş — **evet, var ve iki dalga geçirdi.**

**Birinci dalga: Eylül 2025** [BİRİNCİL — Checkmarx, ReversingLabs, Unit 42, CISA]
- ReversingLabs **15 Eylül 2025**'te, Checkmarx **16 Eylül 2025** sabahı tespit etti.
- Adı Frank Herbert'in *Dune*'undaki kum solucanından geliyor.
- **İlk kendini kopyalayan (self-replicating) tedarik zinciri saldırısı** olduğuna inanılıyor.
- Başlangıç: **npm güvenlik uyarısı kılığında phishing e-postası** ile bir geliştiricinin kimlik bilgileri çalındı.
- Mekanizma: `postinstall` script'i → GitHub token, npm token, AWS/GCP kimlik bilgileri, Atlassian anahtarları, Datadog API anahtarları toplandı → çalınan GitHub token'ıyla erişilebilen repolara **`shai-hulud-workflow.yml`** adlı GitHub Actions workflow'u eklendi ve tetiklendi → çalınan npm token'ıyla o hesabın diğer paketlerine kod enjekte edildi.
- Etki: 180+ paket (ilk), sonra **500+**.
- **CISA resmî uyarı yayınladı: 23 Eylül 2025** ("Widespread Supply Chain Compromise Impacting npm Ecosystem").

**İkinci dalga: Kasım 2025 — "Shai-Hulud 2.0" / "The Second Coming"** [BİRİNCİL — Unit 42, 26 Kasım 2025 güncellemesi; SecurityWeek]
- **~350 farklı GitHub kullanıcısında 25.000'den fazla kötü amaçlı repo.** SecurityWeek 640 npm paketi bildirdi.
- **Değişiklik 1:** Çalışma `postinstall`'dan **`preinstall`**'a taşındı — *"execution on virtually every build server processing the infected package"*.
- **Değişiklik 2 — YIKICI:** Kimlik bilgisi hırsızlığı başarısız olursa, malware **kurbanın tüm home dizinini güvenli üzerine-yazma ile yok etmeye** çalışıyor.
- **Değişiklik 3:** Yeni payload'lar `setup_bun.js` ve `bun_environment.js` (ikincisi **10 MB'tan büyük**, aşırı gizlenmiş).
- **Değişiklik 4:** GitHub Actions workflow dosyalarıyla **self-hosted runner kaydı** yaparak kalıcılık ve keyfi komut çalıştırma.

**npm/GitHub müdahalesi [DOĞRULANAMADI]** — arama kotası nedeniyle token politikası değişikliklerini teyit edemedim.

#### Rust vs npm — yapısal karşılaştırma

| Boyut | npm | Rust/crates.io | Argus için anlamı |
|---|---|---|---|
| Kurulum-anı kod | `postinstall`/`preinstall`, **`--ignore-scripts` ile kapatılabilir** | **`build.rs` + proc-macro, KAPATILAMAZ** | ❌ **Rust daha kötü** |
| Kendini kopyalayan solucan | ✅ İki kez gerçekleşti | ❌ Henüz yok | ✅ Rust daha iyi |
| Ekosistem büyüklüğü | ~3M paket | ~180k crate | ✅ Küçük hedef yüzeyi |
| Bağımlılık sayısı | Genelde çok daha fazla | 243 [ÖLÇÜM] | ✅ Rust daha iyi |
| Lockfile normu | Var ama tutarsız | **`Cargo.lock` commit standart** | ✅ **arrayref'te %90'ı kurtardı** |
| Paket silme | Karmaşık (left-pad) | `yank` silmez; silme sadece malware'de | ✅ Rust daha iyi |
| Tespit süresi | Günler–haftalar | **86 dakika (arrayref)** | ✅ Rust çok daha iyi |
| Yayımcı imzası | Yok (provenance var) | **Yok** | ❌ İkisi de zayıf |

**Sonuç: Rust'ın avantajı ekosistem olgunluğunda değil, KÜÇÜKLÜĞÜNDE ve `Cargo.lock` normundadır. `build.rs` konusunda Rust npm'den daha savunmasızdır.** "Rust yazdık, güvendeyiz" demeyin.

### F.7 xz/liblzma (CVE-2024-3094) — bakımcı güveni dersleri

[Bu bölüm genel bilinen olay bilgisidir; kotam bittiği için bu oturumda ayrıca doğrulayamadım — **[KISMEN DOĞRULANAMADI]**]

Bilinen çerçeve: "Jia Tan" kimliği, iki yıldan uzun süren bir sosyal mühendislik operasyonuyla `xz-utils`'te ortak-bakımcı statüsü kazandı; ardından test dosyalarına gizlenmiş, **build sistemi (`configure`/`m4` makroları) üzerinden** enjekte edilen bir sshd backdoor'u yerleştirdi. Mart 2024'te Andres Freund tarafından performans anomalisi sayesinde tesadüfen bulundu.

**Argus için beş somut ders:**

1. **Backdoor kaynak repoda değil, release tarball'ındaydı.** → **Argus asla el yapımı tarball yayınlamamalı.** Her artifact, imzalı bir git tag'inden, provenance ile üretilmeli. Bu, SLSA Build L2/L3'ün var olma sebebidir.

2. **Build sistemi saldırı yüzeyidir.** xz'de `m4` makroları, Rust'ta **`build.rs`**. [ÖLÇÜM: yığınınızda 26 tanesi var.] Kod review'unuz `build.rs` değişikliklerini `src/` değişikliklerinden **daha sıkı** incelemeli.

3. **Test verisi ikili dosyaları payload taşır.** → Bağımlılıklarda ve kendi reponuzda `tests/fixtures/*.bin` benzeri sıkıştırılmış/opak dosyalara dikkat. Argus'un CI'sı yeni binary dosyaları işaretlemeli.

4. **Tek bakımcılı kritik crate'ler yapısal risktir.** → `cargo-supply-chain` ile bağımlılıklarınızın yayımcı sayısını çıkarın; tek kişiye bağlı ve kritik yoldakileri **fork veya değiştir** listesine alın.

5. **Sosyal mühendislik uzun vadelidir.** → Argus'un kendi projesinde: yeni katkıcıya commit hakkı verme süreci yazılı olsun, **iki kişi onayı (SLSA Source L4)** ve bekleme süresi olsun. `arrayref` saldırısı da tek kişilik bir yayımlama sürecinin kırılmasıydı.

---

## G) CRATES.IO GÜVENLİK ÖNLEMLERİ

### G.1 Trusted Publishing

**Lansman: 11 Temmuz 2025** [BİRİNCİL — blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07]. RFC [#3691](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html).

**Nasıl çalışır** [BİRİNCİL — RFC 3691]:

crates.io'da güvenilir bir yayımcı yapılandırırsınız; şu OIDC claim'leri eşleştirilir:

| Alan | Anlamı |
|---|---|
| `owner` | GitHub kullanıcı/organizasyon adı |
| `repo` | Depo adı |
| `workflow` | `.github/workflows/` altındaki **workflow dosya adı** |
| `environment` | GitHub Actions environment adı (opsiyonel) |

crates.io, GitHub'ın verdiği ID token'ını **geçici bir erişim token'ıyla** takas eder. RFC: *"access tokens are used as if it was an API token and actually permits access to perform API actions."* Başlangıçta *"a long enough lifetime"* verilir ve workflow bittiğinde iptal talep etmelidir. **Kesin TTL değeri [DOĞRULANAMADI].**

Kullanımı:
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
Not: **İlk sürümü elle yayımlamanız gerekir**, sonra trusted publishing'i açabilirsiniz.

**Neyi önler / neyi ÖNLEMEZ** [BİRİNCİL — RFC 3691]:

✅ Önler: uzun ömürlü API token'larının CI secret'larında durması; token sızarsa **herhangi bir yerden kullanılabilmesi**; elle iptal gerekliliği.

❌ **ÖNLEMEZ:** *"Compromises of actions within the specified workflow"*, *"Supply chain attacks if the workflow itself is malicious"*.

**→ Bu, Argus için kritik bir nüanstır.** Trusted Publishing token hırsızlığını çözer; **workflow'un içindeki bir action'ın ele geçirilmesini çözmez.** Bu yüzden:
- Tüm GitHub Actions'ı **commit SHA ile pinleyin** (`uses: actions/checkout@8f4b7f8...`, `@v4` değil).
- Yayımlama workflow'unu **ayrı bir `environment`** altında koruma kuralları (required reviewers) ile çalıştırın.
- Yayımlama workflow'u **minimum** action kullansın.

#### 2026 güncellemeleri [BİRİNCİL — blog.rust-lang.org/2026/01/21/crates-io-development-update]

**21 Ocak 2026** tarihli güncelleme, Argus için doğrudan ilgili üç madde getirdi:

1. **GitLab CI/CD desteği** eklendi (GitHub Actions'a ek olarak; GitLab.com ile sınırlı).
2. **"Trusted Publishing-only" modu:** Crate sahipleri **klasik API token'larını tamamen devre dışı bırakabiliyor.** → **Argus kendi crate'lerini yayımlıyorsa bunu AÇIN.** Bu, `arrayref` tipi "maintainer'ın token'ı çalındı" saldırısını yapısal olarak imkânsızlaştırır.
3. **Tehlikeli GitHub Actions tetikleyicileri bloklandı:** `pull_request_target` ve `workflow_run` artık kabul edilmiyor. (Bunlar, fork'tan gelen PR'ların yazma yetkili bağlamda kod çalıştırmasına izin veren klasik privilege-escalation vektörleridir.)

### G.2 Diğer crates.io güvenlik özellikleri (Ocak 2026 güncellemesi)

[BİRİNCİL — blog.rust-lang.org/2026/01/21/crates-io-development-update]

- **Security tab:** Crate sayfasında RustSec advisory'lerini gösteren yeni sekme — *"quickly see if a crate has known vulnerabilities before adding it as a dependency."*
- **`pubtime` alanı** index'e eklendi → cooldown ve tarihsel bağımlılık çözümlemesi (`lockfile-publish-time`) için altyapı. **Bölüm C.3'teki en önemli gelecek özelliği bu mümkün kıldı.**
- **GitHub OAuth token'ları artık veritabanında şifreli** (at rest).
- **SLOC metrikleri** (`tokei` ile hesaplanıyor) crate sayfalarında. → Bir crate'in gerçek boyutunu eklemeden önce görebilirsiniz; minimizasyon için faydalı.
- İndirme grafiklerinden **bot/scraper/mirror trafiği filtreleniyor** → "bu crate gerçekten ne kadar kullanılıyor" sorusuna daha dürüst cevap.
- **Fastly CDN** sparse index'i sunuyor.
- Frontend Svelte+TypeScript'e taşınıyor; OpenAPI'den tip güvenli istemciler.

### G.3 Rust Foundation Security Initiative

[BİRİNCİL — rustfoundation.org/media/strengthening-rust-security-with-alpha-omega-a-progress-update/, **12 Mayıs 2025**]

**Çıkan araçlar:**

| Araç | Ne yapar | Durum |
|---|---|---|
| **typomania** | Tipo-eşkıyalık tespiti; `typogard`'ın Rust portu, **herhangi bir registry'ye uyarlanabilir kütüphane** | Olgun; Rust bakımcıları ve dış güvenlik araştırmacıları kullanıyor |
| **painter** | crates.io ekosistemindeki tüm crate'ler arası bağımlılık ve çağrı grafiğinin **graph veritabanı**; `unsafe` istatistikleri, çağrı grafiği budama, **FFI sınır haritalama** | Olgun |
| **Crate provenance tracking** | crates.io'ya yayımlanan **her crate'in provenance'ını izleyen** araç | Devreye alınmış |
| **Real-time crate scanning** | Paketlerde açık ve malware tespiti | Geliştirme aşamasında |
| **cargo-cgsec** | Google'ın **Capslock**'unun Rust'a uyarlanmış hali — **yetenek (capability) analizi** | Deneysel |
| **Trusted Publishing** | (bkz. G.1) | Uygulandı |

**Fonlama:** OpenSSF **Alpha-Omega** projesi. 2025'te Trusted Publishing ve Capslock uygulaması için **ek 216.000 USD** hibe.

**Diğer çıktı:** 2025 başında **crates.io ekosistemi ve Rust çekirdek altyapısı için tehdit modelleri** yayınlandı.

#### 2026: AI Security Engineer in Residence

[BİRİNCİL — alpha-omega.dev/blog/an-ai-security-engineer-in-residence-for-the-rust-ecosystem/, **16 Haziran 2026**]

Rust Foundation, Alpha-Omega fonuyla bir pozisyon açtı. Çözdüğü problem: **AI araçları hem gerçek bulgular hem de devasa hacimde değersiz rapor üretiyor**, bakımcılar sinyal/gürültü altında eziliyor.

Görevler: *"use a mix of human-led and AI-assisted methods to proactively review Rust itself and the crates"* — en çok güvenilen crate'leri proaktif incelemek; gerçek/sömürülebilir sorunları yanlış pozitiflerden **bakımcıya ulaşmadan önce** ayırmak; **Project Glasswing** gibi girişimlerden gelen raporlara temas noktası olmak.

Başlangıçta **altı ay** fonlandı, uzatma opsiyonlu. *"methods, playbooks, and prompts will be documented so the work doesn't end with the contract."* Sonuç metrikleri henüz yok (duyuru, rapor değil).

**→ Argus için anlamı:** Bir IdP olarak size de AI üretimi güvenlik raporları gelecek. Şimdiden bir **triage politikası** yazın: reproducer olmayan, CVSS'i gerekçelendirilmemiş, AI imzası taşıyan raporlar için ayrı kuyruk.

### G.4 Index bütünlüğü ve TUF

- **SHA-256 checksum'lar** index'te ve `Cargo.lock`'ta. Model **TOFU**'dur: ilk indirmede checksum'ı kabul edersiniz, sonrasında değişiklik tespit edilir.
- **Sparse index** HTTPS üzerinden (Fastly CDN, Ocak 2026).
- `.crate` dosyaları **değişmezdir** — yayımlandıktan sonra üzerine yazılamaz.
- **TUF: uygulanmadı.** Issue [#75](https://github.com/rust-lang/crates.io/issues/75) (Kasım 2014) kapatılmış. Aktif bir TUF planı **[DOĞRULANAMADI]**.

**Boşluk analizi — Argus'un tehdit modeline yazın:** crates.io'da **yayımcı-tarafı kriptografik imza yoktur.** Güven zinciri: `HTTPS + crates.io platform güvenliği + checksum + (opsiyonel) Trusted Publishing`. crates.io altyapısı ele geçirilirse veya bir yayımcının hesabı ele geçirilirse (**`arrayref`'te tam olarak bu oldu**), checksum'lar sizi korumaz — çünkü kötü amaçlı içeriğin checksum'ı da doğrudur.

**Bu boşluğu Argus şöyle kapatır:**
1. `Cargo.lock` commit edilir (arrayref'te %90 koruma sağladı — kanıtlı).
2. `cargo vendor` + imzalı vendor tarball'ı arşivlenir.
3. Bağımlılık güncellemeleri cooldown ile (≥7 gün) batch halinde.
4. `cargo-vet` ile denetim durumu takip edilir.
5. Yeni `build.rs` bağımlılığı CI'da alarm üretir.

### G.5 Token yönetimi, 2FA, yanking

**API token'ları:** crates.io endpoint-scoped token'ları destekler (yalnızca `publish-update` gibi). [Kesin scope listesi **[DOĞRULANAMADI]** — crates.io SPA olduğu için doküman sayfası çekilemedi.]

**Cargo tarafında credential provider'lar** [BİRİNCİL — doc.rust-lang.org/cargo/reference/registry-authentication.html]:
```toml
[registry]
global-credential-providers = ["cargo:token", "cargo:libsecret",
                               "cargo:macos-keychain", "cargo:wincred"]
```
Sonraki girişler daha yüksek önceliklidir. **`cargo:token` token'ı DÜZ METİN olarak** cargo'nun credentials dosyasında veya `CARGO_REGISTRIES_<NAME>_TOKEN` ortam değişkeninde saklar.

**→ Argus geliştirici politikası:** `cargo:token`'ı **kullanmayın**. macOS'ta `cargo:macos-keychain`, Linux'ta `cargo:libsecret`. Bu, geliştirici makinesindeki bir infostealer'ın (bkz. PolinRider, TrapDoor) crates.io token'ınızı düz metin okumasını engeller — `arrayref` saldırısının muhtemel giriş vektörü tam olarak buydu.

**2FA:** Yayımlama için 2FA zorunluluğunun güncel durumu **[DOĞRULANAMADI]** — bu oturumda teyit edemedim. Ancak **Trusted Publishing-only modu** (Ocak 2026) 2FA'dan daha güçlü bir kontroldür ve mevcuttur; onu kullanın.

**Yanking / silme politikası** [BİRİNCİL — RustSec advisory'lerinden gözlemlenen davranış]:
- `cargo yank`: sürüm mevcut lockfile'lardan çözülmeye devam eder, yeni çözümlemede seçilmez. **Silme değildir.**
- Gerçek silme: yalnızca crates.io ekibi, **kötü amaçlı kod** için. Advisory'de `expect-deleted = true` alanıyla işaretlenir [ÖLÇÜM — RUSTSEC-2026-0264/0265].
- Hesap kilitleme: ele geçirme şüphesinde uygulanır (arrayref, proc-macro1).
- Ad-eşkıyalığı politikası: crates.io'nun resmî politika metni **[DOĞRULANAMADI]**.

---

## H) ARGUS İÇİN SOMUT YOL HARİTASI

### H.1 Öncelik matrisi

| # | Aksiyon | Efor | Kazanç | Kanıt |
|---|---|---|---|---|
| 1 | **`Cargo.lock` commit + `--locked` her yerde** | 5 dk | **Çok yüksek** | arrayref'te kullanıcıların %90'ını kurtardı |
| 2 | **`cargo-deny` CI kapısı** (`bans licenses sources`) | 2 saat | Çok yüksek | `allow-git=[]` git kaçış deliğini kapatır |
| 3 | **`cargo-audit` günlük + release kapısı** | 1 saat | Çok yüksek | 1.222 advisory'lik DB, günlük güncel |
| 4 | **SLSA Source L4**: branch protection + 2 onay + imzalı commit | 2 saat | **Çok yüksek** | arrayref & xz'nin kök nedeni |
| 5 | **`default-features = false`** her bağımlılıkta | 1 gün | Yüksek | [ÖLÇÜM] −%30 crate, −%53 proc-macro |
| 6 | **webauthn-rs/OpenSSL zincirini kes** | 3 gün | Yüksek | [ÖLÇÜM] native C kripto sıfırlanır |
| 7 | **`cargo-auditable` ile derle** | 30 dk | Yüksek | <4 KB maliyet, CRA Ek I.II.1 karşılar |
| 8 | **Bağımlılık cooldown ≥7 gün** (Renovate `minimumReleaseAge`) | 1 saat | **Çok yüksek** | 86–107 dakikalık saldırı penceresini kapatır |
| 9 | **`actions/attest-build-provenance`** | 2 saat | Yüksek | SLSA Build L2/L3 |
| 10 | **Actions'ları SHA ile pinle** | 2 saat | Yüksek | Trusted Publishing'in kapatmadığı boşluk |
| 11 | **Reproducible build + CI kapısı** | 1 hafta | Orta-Yüksek | [ÖLÇÜM] 3 remap kuralı yeterli |
| 12 | **CycloneDX SBOM + VEX yayını** | 3 gün | Yüksek | CRA zorunlu (11 Aralık 2027) |
| 13 | **`cargo-vet` + özel kriterler** | 2 hafta | Orta-Yüksek | [ÖLÇÜM] %51–91 hazır kapsam |
| 14 | **Denetlenmemiş 14 crate'i elle denetle** | 3 hafta | Yüksek | `argon2`, `sqlx`, ASN.1 |
| 15 | **Kripto/protokol çekirdeğini `no_std` crate'lere ayır** | 1 ay | Orta-Yüksek | Denetim maliyetini düşürür |
| 16 | **CRA Madde 14 raporlama süreci** | 1 hafta | YASAL | Steward'lar için 11 Aralık 2027; manufacturer'lar için 11 Eylül 2026 |

### H.2 Hemen bugün yapılacaklar (ilk hafta)

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

## I) DOĞRULANAMAYAN / EKSİK KALAN MADDELER

Dürüstlük için tam liste:

1. **cargo-crev güncel inceleme sayısı** — `web.crev.dev` 502 döndü (8 Eyl 2026). Sadece indirme verisi (1.380/90gün) elimde.
2. **crates.io yayımlama için 2FA zorunluluğu** — güncel durum teyit edilemedi.
3. **crates.io API token scope'larının tam listesi** — SPA olduğu için doküman çekilemedi.
4. **crates.io ad-eşkıyalığı / namespace resmî politika metni** — çekilemedi.
5. **`cargo-sigstore` veya crates.io için crate imzalama çözümü** — varlığı doğrulanamadı; bildiğim kadarıyla üretim standardı yok.
6. **`actions/attest-build-provenance`'ın resmî SLSA seviyesi** — GitHub sayfası belirtmiyor. **"SLSA L3" iddiasını doğrulamadan pazarlamada kullanmayın.**
7. **CRA yürürlüğe giriş tarihi çelişkisi** — Komisyon sayfası **10 Aralık 2024**, Wikipedia **12 Kasım 2024** diyor. **Komisyon'u esas alın**; EUR-Lex bot koruması nedeniyle Madde 71'in birebir metnini alamadım.
8. **CRA Ek IV (kritik ürünler) tam listesi** — çekilemedi. Argus **Ek III Sınıf I**'de olduğu için pratikte etkisiz, ama teyit edin.
9. **CRA uyumlaştırılmış standartların (CEN/CENELEC JTC13) hazırlık durumu** — araştırılamadı. **Bu Argus için önemli**: harmonised standard yoksa Sınıf I ürünler için üçüncü taraf uygunluk değerlendirmesi gerekebilir.
10. **ABD EO 14028 / EO 14144 / Haziran 2025 EO değişikliklerinin güncel durumu** — arama kotası nedeniyle araştırılamadı.
11. **NIS2'nin kimlik yazılımı satıcılarına etkisi** — araştırılamadı.
12. **CISA SBOM minimum elements'in 2024/2025 güncellemesi** — araştırılamadı.
13. **SPDX 3.0 durumu ve Rust desteği** — araştırılamadı.
14. **Reproducible Builds projesinin Rust'a özel 2025-2026 metrikleri** — aylık raporlar taranamadı.
15. **rustc reproducibility issue #34902'nin kapanma tarihi/gerekçesi** — GitHub yorumları yüklenemedi.
16. **`arrayref` saldırısının Kuzey Kore atfı** — resmî Rust blogu atıf yapmıyor; üçüncü taraf iddiası.
17. **Shai-Hulud sonrası npm/GitHub politika değişiklikleri** — teyit edilemedi.
18. **xz/CVE-2024-3094 detayları** — bu oturumda ayrıca doğrulanmadı (genel bilinen olay bilgisi).
19. **`RUSTUP_HOME` remap kuralının farklı makinelerde etkinliği** — tek makinede test edildi; CI'da iki farklı kullanıcı adıyla doğrulayın.
20. **cargo-cyclonedx'in desteklediği tam CycloneDX spec sürümleri** — belirtilmemiş.

---

## J) EN KRİTİK ÜÇ MESAJ

**1. CRA — Argus Sınıf I "önemli ürün" kategorisinde.** Raporlama yükümlülüğü açık kaynak steward'ları için **11 Aralık 2027**'de başlar (11 Eylül 2026 manufacturer'lar içindir; ENISA bu ayrımı açıkça yapıyor). Argus, CRA Ek III **Sınıf I "önemli ürün"** kategorisindedir — *"Identity management systems and privileged access management software... including authentication and access control readers"*. Bu, varsayılan öz-değerlendirme kategorisinden daha ağır bir uygunluk rejimi demektir. Aktif olarak sömürülen açıklar için ENISA/CSIRT'e bildirim sürecinizi ve iletişim adresinizi bu hafta kurun. Tam yükümlülükler **11 Aralık 2027**'de başlıyor — SBOM (Ek I Bölüm II.1: *"covering at the very least the top-level dependencies"*), koordineli açık bildirim politikası, destek süresi tanımı, teknik dokümantasyon (Ek VII), CE işareti.

**2. Ağustos 2026 `arrayref` saldırısı Argus'un tehdit modelini yeniden yazmalı.** 245 milyon indirmeli bir crate, tipo-eşkıyalık değil **maintainer ele geçirmesi** yoluyla, **86 dakikada**, `build.rs` üzerinden Linux/Windows/macOS'a payload dağıttı. Kullanıcıların %90'ını kurtaran tek şey `Cargo.lock`'tu. Buna karşı üç savunmanız var ve üçü de ucuz: **lockfile + 7 günlük cooldown + ağsız/vendored CI derlemesi**. Ve unutmayın: 6 Eylül 2026'da PolinRider crates.io'ya ulaştı — bu sefer `build.rs` bile kullanmadan, `.vscode/tasks.json` üzerinden.

**3. Sayılara güvenin, bloglara değil.** Ölçtüğüm gerçekler: sıradan bir IdP yığını **243 crate, 1.747.244 satır üçüncü taraf kod, 26 build.rs, 19 proc-macro** getiriyor. Basit feature hijyeniyle bu **170 crate / 1.311.921 satır / 20 build.rs / 9 proc-macro**'ya iniyor ve OpenSSL tamamen kayboluyor — **bir günlük iş, kalıcı kazanç**. cargo-vet'in beş büyük audit seti gerçekte **1.815 crate** kapsıyor (SEO bloglarının iddia ettiği 14.140 değil), bu da sizin grafiğinizin **%51–91'ine** karşılık geliyor. Denetlenmemiş kalanlar tam da en kritik olanlar: `argon2`, `sqlx` ailesi ve ASN.1 ayrıştırıcıları. İlk denetim bütçenizi oraya harcayın.
