# 10. Formel doğrulama ve model checking

> `ARGUS.md` §10'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§10 §X` referansları aynı anlamda.


> **Metodoloji notu:** Aşağıdaki her olgusal iddianın yanında kaynak URL'i ve tarihi var. Kaynaklandırılamayan hiçbir şey iddia edilmedi; belirsiz kalanlar **[DOĞRULANAMADI]** ile işaretlendi. Efor tahminleri açıkça **[TAHMİN — kaynaklı değil]** olarak etiketlendi.

---

### 0. YÖNETİCİ ÖZETİ

2026'da Rust için "gerçekten kullanılabilir" araç seti üçe ayrılıyor:

| Katman | Araçlar | Argus için rol |
|---|---|---|
| **Ucuz, her gün çalışan** | Miri, proptest/bolero, cargo-fuzz, ASan/TSan, Loom/Shuttle | Zorunlu taban. Maliyet düşük, kapsam geniş, garanti yok |
| **Sınırlı ama otomatik ispat** | **Kani** (+ Flux) | Seçili "yaprak" fonksiyonlar: aritmetik, süre/saat, oran sınırlayıcı, sabit boyutlu decoder'lar |
| **Tam fonksiyonel ispat, pahalı** | **Verus**, Creusot, Aeneas/hax+Lean, VeriFast | Sadece 1-2 kritik çekirdek: politika değerlendirme motoru, token durum makinesi |

**En önemli tek gerçeklik kontrolü:** Rust ekosisteminin en güvenlik-kritik kütüphanesi olan `rustls`, formel doğrulama kullanmıyor — `forbid(unsafe_code)` + fuzzing + OSS-Fuzz ile yetiniyor ve SECURITY.md'sinde formel yöntemlere hiç atıf yok ([rustls SECURITY.md](https://github.com/rustls/rustls/blob/main/SECURITY.md), erişim 2026-09-08). Bir IdP'nin "en güvenli" olması, %100 ispatlanmış olmasından değil, doğru yerlere doğru aracı koymasından geçiyor.

---

### 1. KANI (AWS, CBMC tabanlı sınırlı model checker)

#### 1.1 Sürüm ve durum (2026)

- **Güncel sürüm: `kani-verifier` 0.67.0, yayın tarihi 2026-01-16** (crates.io API, `max_version: 0.67.0`, `created_at: 2026-01-16T17:11:13Z`, toplam ~566.000 indirme) — [crates.io/api/v1/crates/kani-verifier](https://crates.io/api/v1/crates/kani-verifier), erişim 2026-09-08.
- Sürüm geçmişi (GitHub releases atom, erişim 2026-09-08): 0.61.0 (2025-04-06), 0.62.0 (2025-05-08), 0.63.0 (2025-06-10), 0.64.0 (2025-07-03), 0.65.0 (2025-08-07), 0.66.0 (2025-11-06), 0.67.0 (2026-01-16) — [github.com/model-checking/kani/releases.atom](https://github.com/model-checking/kani/releases.atom).
- **Dikkat / risk sinyali:** 2026-01-16'dan bugüne (2026-09-08) yeni sürüm yok — yaklaşık **8 aylık sürüm boşluğu**, oysa proje daha önce aylık kadans tutuyordu. Kani blogu da 2024-12-10'dan beri yeni yazı yayınlamamış — [model-checking.github.io/kani-verifier-blog](https://model-checking.github.io/kani-verifier-blog/), erişim 2026-09-08. **[DOĞRULANAMADI]** Bu boşluğun nedeni (kadans değişikliği mi, kaynak azalması mı) kaynaklardan çıkarılamadı. Ancak aşağıdaki iki 2026 yayını projenin canlı olduğunu gösteriyor.
- **Akademik/endüstriyel yayın:** "Kani: A Model Checker for Rust", arXiv 2607.01504, **2026-07-01 gönderim**, ASE 2026 (Münih, 12–16 Ekim 2026) Industry Showcase Track, 12 yazar (Rémi Delmas, Zyad Hassan ve diğerleri) — [arxiv.org/abs/2607.01504](https://arxiv.org/abs/2607.01504).
- **Platform desteği:** `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`. **Windows desteklenmiyor.** — [Kani install guide](https://model-checking.github.io/kani/install-guide.html), erişim 2026-09-08. *(Not: aarch64 Linux bu listede yok; ARM CI runner kullanacaksanız kaynaktan derleme gerekebilir.)*

#### 1.2 Mimari

Kani bir `rustc` eklentisidir; kodu **MIR** seviyesinde yakalar (LLVM IR'in kaybettiği Rust tip değişmezlerini korumak için), GOTO programına çevirir ve **CBMC**'ye verir; CBMC de SAT/SMT çözücüye indirger.
Pipeline: `Rust kaynak → kani-compiler (MIR dönüşümleri) → codegen → GOTO → CBMC → SAT/SMT`.
Çözücüler: **SAT** — MiniSat (varsayılan), Kissat, CaDiCaL; **SMT** — Z3, cvc5, Bitwuzla (SMT desteği 0.65.0 ile geldi, 2025-08-07).
— [arxiv.org/html/2607.01504v1](https://arxiv.org/html/2607.01504v1), 2026-07-01.

#### 1.3 Kani NE doğrulayabilir

**Anotasyonsuz, otomatik kontrol edilenler** ([arXiv 2607.01504v1](https://arxiv.org/html/2607.01504v1), 2026-07-01):

1. **Tanımsız davranış (UB) yokluğu:** geçersiz/sarkan pointer dereference, hizasız (misaligned) cast, geçersiz enum discriminant.
2. **Runtime panic yokluğu:** aritmetik taşma, sıfıra bölme, tanımsız shift, dizi sınır aşımı, `unwrap()` başarısızlığı.
3. **Ek MIR geçişleri:** "valid-value pass" (unsafe tip dönüşümlerinin geçerli değer ürettiğini kontrol eder), "uninit-memory pass" (gölge bellek kullanarak tüm dereference'ların initialize edilmiş belleğe eriştiğini doğrular).
4. Float→integer cast sonluluğu.

**Spesifikasyon dili (sınırlıdan sınırsıza geçmek için):**

- **Fonksiyon kontratları:** `#[kani::requires(P)]`, `#[kani::ensures(|&result| Q)]`, `#[kani::modifies(e)]`, `old(e)`.
- **Döngü kontratları:** `#[kani::loop_invariant(I)]`, `#[kani::loop_modifies(W)]`, `#[kani::loop_decreases(d)]` (sonlandırma ölçütü — sadece tamsayı ifadeler).
- **Niceleyiciler (quantifiers):** `kani::forall!(|x: T in (lo,hi)| P(x))`, `kani::exists!(...)`. **SAT arka ucunda sınırlar derleme-zamanı sabiti olmalı** (aralık 1000 değeri aşarsa uyarı); SMT arka ucu çalışma-zamanı değerli sınırları destekler.
- **Stubbing:** `#[kani::stub(f, g)]` — desteklenmeyen özellikleri (inline assembly, FFI), pahalı implementasyonları veya ortamı (saat okuma, rastgele sayı) değiştirmek için. **Kritik ayrım:** düz stub'lar *doğrulanmamış varsayımdır*; `#[kani::stub_verified(f)]` makine-kontrollü kontrat soyutlaması kullanır.
— [arxiv.org/html/2607.01504v1](https://arxiv.org/html/2607.01504v1), 2026-07-01.

**Kontratların olgunluk durumu:** Kontratlar hâlâ **deneysel** — `-Z function-contracts` bayrağıyla açılıyor; özyinelemeli fonksiyonlarda `recursion` özniteliği zorunlu — [Kani contracts reference](https://model-checking.github.io/kani/reference/experimental/contracts.html), erişim 2026-09-08.

**Autoharness (otomatik harness üretimi):** `cargo kani autoharness -Z autoharness`. Tüm argümanları `kani::Arbitrary` implement eden fonksiyonlar için otomatik harness üretir. **Deneysel.** Sınırları: `Arbitrary` olmayan argümanlar (`--bounded-arguments` olmadan) desteklenmez; **generic fonksiyonlarda sadece tek bir monomorfik örnekleme doğrulanır — bu bir under-approximation'dır**; `usize` olmayan const generic parametreler desteklenmez; farklı pointer/reference argümanları arasında aliasing modellenmez — [Kani autoharness reference](https://model-checking.github.io/kani/reference/experimental/autoharness.html), erişim 2026-09-08.

#### 1.4 Kani NE doğrulayamaz (Argus için kritik)

Resmî "Rust feature support" tablosundan ([model-checking.github.io/kani/rust-feature-support.html](https://model-checking.github.io/kani/rust-feature-support.html), erişim 2026-09-08):

| Özellik | Destek | Not |
|---|---|---|
| **Await ifadeleri / async** | **Hayır** | "Concurrency out of scope" |
| **Veri yarışları (data races)** | **Hayır** | Eşzamanlılık kapsam dışı |
| **Inline assembly (`asm!`, `global_asm!`)** | **Hayır** | "Kani does not support assembly code for now" |
| Hizasız raw pointer dereference | Hayır | |
| Pointer aliasing kurallarını ihlal | Hayır | Stacked/Tree Borrows modellenmiyor |
| Immutable veriyi mutate etme | Hayır | |
| **Trait object types (`dyn`)** | **Kısmi** | "advanced features" sınırlamaları |
| **Closure types / function pointers / pointer types** | **Kısmi** | Aynı |
| `impl Trait` / tip parametreleri / inferred type / DST | Kısmi | |
| Destructors / `Drop` | Kısmi | |
| `UnsafeCell<T>`, `PhantomData<T>`, Operator Traits | Kısmi | |
| Compiler intrinsics | Kısmi | |
| Patterns | Kısmi | Issue #707 |

Ek olarak, aynı sayfadan:

- **Eşzamanlılık:** "Concurrent features are currently out of scope for Kani." Kani eşzamanlı kod görürse **uyarı verir ve sıralı (sequential) olarak işler** — yani sessizce yanlış bir modelle devam eder. Bu, bir IdP'nin oturum deposu / token cache'i gibi paylaşımlı durum içeren yerlerinde **tuzak**tır.
- **Kayan nokta:** `sin`, `cos`, `sqrt` **over-approximate** edilir — muhafazakâr aralıkta nondeterministik değer döndürür; bu **gerçekte imkânsız olan sahte hatalar (spurious errors)** üretebilir.
- **Stack unwinding desteklenmiyor** — sadece abort stratejisi. Panic sırasında temizlik mantığına (Drop) bağımlı kodda bellek güvenliği boşluğu doğabilir. *Argus için pratik sonuç: `panic = "abort"` profili ile çalışmak Kani ile daha tutarlı olur.*

UB dokümanı ([model-checking.github.io/kani/undefined-behaviour.html](https://model-checking.github.io/kani/undefined-behaviour.html), erişim 2026-09-08) şunu açıkça söylüyor: liste **tüketici değil**, çünkü "unsafe kodda neyin izinli olduğuna dair Rust semantiğinin formel bir modeli yok". Kani'nin **hiç kontrol etmediği** sınıflar: veri yarışları, inline assembly, initialize edilmemiş bellek (özellik dokümanına bakınız), yanlış call/unwind ABI'ları. "Best-effort" olanlar: pointer aliasing ihlalleri (yalnızca bellek güvenliğine yansıdığı ölçüde), immutable veri mutasyonu, intrinsic ön koşulları, geçersiz değer üretimi (`transmute`'u engellemez).

ASE 2026 makalesinin kendi sınırlar listesi ([arxiv.org/html/2607.01504v1](https://arxiv.org/html/2607.01504v1), 2026-07-01):
- Özyinelemeli fonksiyonların **sonlanması doğrulanmaz** (kullanıcı sorumluluğu).
- **Karşılıklı özyineleme (mutual recursion) desteklenmez** — tespit edilirse derleme hatası.
- `decreases` cümlelerinde struct alan projeksiyonları ve leksikografik tuple ölçütleri henüz yok.
- **Stacked Borrows / Tree Borrows modellenmiyor** — "unsafe Rust'ın birincil UB sınıfı".
- **FFI çağrıları CBMC'nin bellek modeli dışında çalışır** (stub'lanmadıkça).
- Spesifikasyonlar generic'ler için adreslenemez — her monomorfizasyon ayrı doğrulanır.
- Dinamik trait dispatch ve eşzamanlı yürütme ele alınmıyor.

**Döngü sınırları (unwinding) — parser'lar için en acı nokta:** `--default-unwind` tüm harness'lar için döngü açma üst sınırı koyar. Sınır yetersizse "unwinding assertion" hatası verir ve **diğer birçok sonuç "undetermined" hâline gelir**. Kani dokümanı bunu açıkça söylüyor: **"big string problems" — parser'lar gibi — genellikle hataları ortaya çıkarmak için 10-20+ karakterlik girdiye ihtiyaç duyar** ve bu ölçek verifikasyon süresini dramatik biçimde artırır — [Kani loop unwinding tutorial](https://model-checking.github.io/kani/tutorial-loop-unwinding.html), erişim 2026-09-08. *Bu, Argus'ta JWT/base64/CBOR decoder'ları Kani ile "tam" doğrulamanın neden gerçekçi olmadığının doğrudan kaynağıdır.*

Kani kendi karşılaştırma sayfasında **eşzamanlılık için Loom ve Shuttle'ı öneriyor** — [Kani tool comparison](https://model-checking.github.io/kani/tool-comparison.html), erişim 2026-09-08.

#### 1.5 Üretimde gerçek kullanım — somut kanıt

ASE 2026 makalesinden ([arxiv.org/html/2607.01504v1](https://arxiv.org/html/2607.01504v1), 2026-07-01):

| Proje | Ne | Sayılar |
|---|---|---|
| **AWS Firecracker** (Lambda + Fargate'in VMM'i) | Block device panic-freedom, rate limiter, VirtIO emülasyonu | **34 harness, 21 dakika CI çalışma süresi.** Rate limiter'da **nondeterministik saat değerleriyle** doğrulama yapıldı ve **%0.01 bütçe aşımına izin veren yuvarlama hatası** bulundu. VirtIO'da guest'in tetikleyebildiği panic bulundu (queue adreslerinin MMIO boşluğuna yerleştirilmesi) |
| **AWS s2n-quic** (Rust QUIC) | Protokol kodlama/çözme | **102 harness.** `try_fit` assertion hatası **20 saniyede** bulundu — oysa **16.7 milyon iterasyonluk fuzzing hiçbir şey bulamamıştı**. `decode_packet_number` taşması da bulundu |
| **Hifitime** (havacılık/uzay zaman kütüphanesi) | Faz I: 11 panic-freedom harness → Faz II: **153 fonksiyonel doğruluk ispatı** | Faz I'de **6 gerçek hata**: `total_nanoseconds()` işaret hatası; `i64::MIN.abs()` taşması; float çarpım döngüsünde NaN/sonsuz yayılımı; **`Epoch`'ta `PartialEq`/`Ord` tutarsızlığı**; **`Duration`'da sıfır geçişinde `a == b && a < b` aynı anda sağlanabiliyor**; `is_gregorian_valid` taşması (`year == i32::MAX`). Faz I'de **158 harness'ın 57'si 60 saniyelik CI bütçesini aştı**; Faz II'de kontratlarla çoğu ispat **5 saniye altında**, takvim geçerliliği 16.4 s, döngü sonlanması 13.6 s |
| **Rust std** | verify-rust-std kampanyası | **Her kod değişikliğinde 16.748 harness**, 69 dakika CI, paralelleştirmeyle **3.97× derleme hızlanması** |

s2n-quic, Kani'yi **Bolero** property-testing framework'üyle birlikte kullanıyor: tek bir öznitelikle aynı harness hem fuzz testi hem Kani ispatı olarak çalışıyor — [aws.github.io/s2n-quic/dev-guide/kani.html](https://aws.github.io/s2n-quic/dev-guide/kani.html) ve [Kani blog, 2023-05-30](https://model-checking.github.io/kani-verifier-blog/2023/05/30/how-s2n-quic-uses-kani-to-inspire-confidence.html). **Argus için doğrudan kopyalanabilir desen budur.**

**Tokio:** Kani blogunda "Using the Kani Rust Verifier on Tokio Bytes" (2022-08-17) var — [blog](https://model-checking.github.io/kani-verifier-blog/) — ancak bu bir **deneme/vaka çalışması**, Tokio'nun kendi CI'ında sürekli Kani çalıştırdığına dair kanıt **[DOĞRULANAMADI]**.

**CI entegrasyonu:** Resmî GitHub Action mevcut (`model-checking/kani-github-action`, v1); parametreler: `kani-version`, `command`, `working-directory`, `args`, `enable-propproof` — [github.com/model-checking/kani-github-action](https://github.com/model-checking/kani-github-action), erişim 2026-09-08.

#### 1.6 "Verify Rust Std Lib" mücadelesi — 2026 durumu

**Kuruluş:** Rust Foundation + AWS ortak duyurusu **2024-11-20**. Rust std'de ~35.000 fonksiyon, **~7.500'ü `unsafe`**; son üç yılda 57 "soundness issue" ve 20 CVE. Her mücadeleye bağlı bir finansal ödül var; bir "challenge rewards committee" ödülleri dağıtıyor. Duyuru anında "30+ öğrenci, akademisyen ve araştırmacı" katılmıştı — [Rust Foundation duyurusu, 2024-11-20](https://rustfoundation.org/media/rust-foundation-collaborates-with-aws-initiative-to-verify-rust-standard-libraries/); ayrıca [devclass, 2024-11-21](https://devclass.com/2024/11/21/aws-will-pay-devs-to-verify-rust-standard-library-because-of-7500-unsafe-functions-and-enormity-of-task/).

**AWS'in toplam taahhüt rakamı: [DOĞRULANAMADI]** — Rust Foundation duyurusu belirli bir toplam $ tutarı vermiyor, sadece "her mücadeleye bağlı ödül" diyor. Depo README'sindeki tablo mücadele başına tutarları listeliyor; birebir alıntılar: `"| [1: Verify core transmuting methods] | 10,000 USD | [Resolved]"`, `"| [2: Verify the memory safety of core intrinsics using raw pointers] | 10,000 USD | Open |"`, `"[20: Verify the safety of char-related functions in str::pattern] | 25,000 USD | Open |"`, `"[21: ... str::pattern] | 25,000 USD | Open |"` — [raw README](https://raw.githubusercontent.com/model-checking/verify-rust-std/main/README.md), erişim 2026-09-08. Yani **mücadele başına 10.000–25.000 USD** aralığı doğrulandı.

**Mücadele sayısı: 29** — SUMMARY.md'den birebir liste doğrulandı (1: core transmutation … 29: Safety of `boxed`) — [doc/src/SUMMARY.md](https://raw.githubusercontent.com/model-checking/verify-rust-std/main/doc/src/SUMMARY.md), erişim 2026-09-08. NFM 2026 makalesi de "29 published challenges" diyor.

**Çözülmüş/açık sayısı: [KISMEN DOĞRULANAMADI]** — Aynı README'yi iki kez çektiğimde çelişkili özetler geldi (bir seferinde "7 çözüldü / 22 açık, toplam $315.000+", diğerinde "9 çözüldü / 20 açık, toplam $285.000"). Bağımsız hakemli kaynak — Le Blanc & Lam, "Lessons Learned So Far…", arXiv 2510.01072 (gönderim 2025-10-01, revizyon 2025-10-26) — **"9 of 27 challenges completed"** diyor — [arxiv.org/abs/2510.01072](https://arxiv.org/abs/2510.01072). **Güvenli ifade: 29 mücadelenin yaklaşık 7–9'u çözülmüş, ~20–22'si açık.** Kesin güncel sayı için her mücadelenin tracking issue'suna bakmak gerekiyor (depo bunu kendisi söylüyor).

**Kampanyanın 2026 sonuçları** — "Verifying the Rust Standard Library", NFM 2026 (Los Angeles, 5–7 Mayıs 2026), arXiv 2606.17374, gönderim 2026-06-16 — [arxiv.org/html/2606.17374](https://arxiv.org/html/2606.17374):

- **450+ pull request**, en az **21 harici katkıcı**, 4 farklı kurum.
- **16.748 otomatik üretilmiş proof harness** (autoharness ile), bunların **11.970'i** Kani'nin desteklediği UB sınıflarına karşı doğrulandı.
- **989 fonksiyon tam kontratla doğrulandı** (295 otomatik + 694 manuel).
- Kapsam: core+alloc+std'de **33.955 fonksiyon**; **4.645 unsafe fonksiyon için harness**; unsafe üzerine **1.126 güvenli soyutlama** doğrulandı; **10.194 safe fonksiyon** doğrulandı.
- **Bulunan yeni bellek güvenliği açığı sayısı: SIFIR.** Bunun yerine **4 spesifikasyon/dokümantasyon hatası** upstream'e düzeltildi (yanlış SIMD shift'ler, eksik safety anotasyonları, hatalı SAFETY yorumları, dokümantasyon hataları).
- CI: paralelleştirme ve optimizasyonla **3.97× derleme hızlanması**.

**Rust Foundation'ın 2026-09-01 tarihli değerlendirmesi** — [rustfoundation.org, 2026-09-01](https://rustfoundation.org/media/how-the-rust-standard-library-verification-contest-scaled-past-manual-proof-engineering/):
- İlk yıl manuel: **725 Kani harness + 50+ VeriFast ispatı**; ancak **manuel kontrat büyümesi Ekim 2025 civarında platoya ulaştı** — bu, autoharness'a geçişin nedeni.
- VeriFast ile `LinkedList`'in **19 çekirdek fonksiyonu** separation logic ile doğrulandı (5 fonksiyon daha dolaylı olarak sağlam çıktı).
- Kalan boşluklar: **9.600 generic fonksiyon** autoharness tarafından atlanıyor (monomorfizasyon sorunu); **atomik tipler (Challenge 7) ve `Arc` (Challenge 27) çözülemedi** — gevşek bellek modeli altında lock-free yapılar gerçek bir teknik zorluk.

**Kapsama gerçeği (önemli):** Le Blanc & Lam (arXiv 2510.01072, Ekim 2025) manuel doğrulama kapsamını **`core` için %3.98, `std` için %1.4** olarak veriyor. Autoharness sonrası rakamlar daha yüksek ama **autoharness'ın verdiği garanti daha zayıf** (tam kontrat değil, yalnızca UB sınıfları).

**Entegre araçlar:** Kani, ESBMC (goto-transcoder üzerinden), VeriFast, Flux — CI'da. İnceleme aşamasında: Verus, Creusot, KRust, RAPx — [verify-rust-std README](https://raw.githubusercontent.com/model-checking/verify-rust-std/main/README.md) ve [Rust Foundation, 2026-09-01](https://rustfoundation.org/media/how-the-rust-standard-library-verification-contest-scaled-past-manual-proof-engineering/).

---

### 2. DİĞER RUST DOĞRULAMA ARAÇLARI

#### 2.1 Karşılaştırma tablosu

| Araç | Teknoloji | Kanıtladığı | Anotasyon yükü | 2026 durumu | Argus'ta yeri |
|---|---|---|---|---|---|
| **Kani** | CBMC / SAT+SMT, sınırlı model checking | Panic yok, UB alt kümesi, assertion'lar, kontratlar | **Düşük** (harness + isteğe bağlı kontrat) | Canlı ama sürüm kadansı yavaşladı (0.67.0, 2026-01-16) | **Birincil** |
| **Verus** | SMT (Z3), lineer ghost tipler | Tam fonksiyonel doğruluk, sahiplik disiplini, eşzamanlılık | **Yüksek** | **Çok canlı** — günde birden çok rolling release (0.2026.09.07, 2026-09-07) | Politika motoru, durum makinesi |
| **Creusot** | Why3 / Coma → SMT | Panic/taşma/UB yok + tam fonksiyonel doğruluk, sonlanma | **Yüksek** | **Canlı** — v0.13.0, 2026-07-30 | Alternatif; algoritma ispatı |
| **Prusti** | Viper / permission logic | Safe Rust fonksiyonel doğruluk | Orta | **ÖLÜ** — son commit 2024-03-26 | Kullanmayın |
| **Flux** | Refinement (liquid) types → SMT | Aritmetik taşma, sıfıra bölme, dizi sınırı, özel refinement'lar | **Düşük** (döngü invariant'ı çıkarımı otomatik) | **Çok canlı** — commit'ler 2026-09-08 | İndeks/uzunluk/aralık mantığı |
| **Aeneas + Charon** | Rust→LLBC→saf fonksiyonel Lean/F*/Coq/HOL4 | Kanıtlayıcıda ne ispatlarsanız | **Çok yüksek** (kanıtlayıcı bilgisi şart) | **Çok canlı** — commit'ler 2026-09-07 | Kripto çekirdeği |
| **hax (Cryspen)** | Rust→F*/Rocq/Lean/ProVerif/SSProve/EasyCrypt | Aynı; ayrıca protokol/kripto oyunları | Çok yüksek | Canlı (474 ★) | Protokol analizi |
| **MIRAI** | MIR soyut yorumlama | Taint analizi, panic tahmini | Düşük | **ÖLÜ (orijinal repo)** — son commit 2024-08-22; endorlabs fork'una taşındı | Kullanmayın |
| **VeriFast** | Separation logic, modüler sembolik yürütme | Unsafe kodda UB yokluğu, sınırsız (unbounded) doğrulama | **Çok yüksek** | Canlı, std kampanyasında CI'da | Yalnızca özel veri yapıları |
| **KMIR** (Runtime Verification) | K Framework, MIR semantiği, sembolik yürütme | Panic/UB yokluğu, eşdeğerlik | Düşük-orta | Aktif geliştirme | Henüz değil |
| **ESBMC / goto-transcoder** | Sınırlı model checking + k-induction | Kani'ye benzer | Düşük | CI'da ama **hiçbir challenge bu arka uçla çözülmedi** | Hayır |
| **Stateright** | Açık-durum model checking (actor) | Dağıtık protokol invariant'ları, linearizability | Orta (sistemi yeniden yazmak gerekir) | 1.9k ★, ~460 commit | Protokol akış modeli |

#### 2.2 Verus — detay

- **Rust lehçesi mi?** Teknik olarak hayır ama pratikte "evet gibi". Verus, `verus!{}` makrosu içinde yazılır; spesifikasyon ve ispatlar **Rust söz dizimiyle yazılır ve Rust'ın tip denetleyicisinden geçer** — ayrı bir DSL değil, Rust'ın makro yoluyla genişletilmesidir (`forall`, `exists`, `requires`, `ensures`) — [Verus guide overview](https://verus-lang.github.io/verus/guide/overview.html), erişim 2026-09-08. Ancak desteklenen alt küme dar olduğu için, **Verus'ta yazılan kod pratikte "Verus-uyumlu Rust"tır** ve normal Rust kütüphanelerini serbestçe kullanamazsınız.
- README'nin kendi ifadesi: *"Verus is under active development. Features may be broken and/or missing, and the documentation is still incomplete."* — 3.000+ ★, 4.628 commit — [github.com/verus-lang/verus](https://github.com/verus-lang/verus), erişim 2026-09-08.
- **Aktivite: son derece yüksek.** Rolling release'ler: `0.2026.09.07.f9e9452` (2026-09-07 17:42 UTC), aynı gün 3 sürüm daha, 2026-09-06'da 3, 2026-09-05, 2026-09-04… — [releases.atom](https://github.com/verus-lang/verus/releases.atom), erişim 2026-09-08. **2026'da Rust doğrulama araçları içinde en aktif olanı.**

**Desteklenen / desteklenmeyen özellikler** ([verus-lang.github.io/verus/guide/features.html](https://verus-lang.github.io/verus/guide/features.html), erişim 2026-09-08):

- **Tam destek:** fonksiyonlar, struct/enum, tip parametreleri, where cümleleri, lifetime'lar, pattern matching + match guard, `while`/`loop`, unsafe blokları, paylaşımlı ve mutable borrow, closure'lar, tamsayı tipleri, bitwise işlemler, `Vec`/`Option`/`Result`, slice'lar, `Box`/`Rc`/`Arc`, kullanıcı trait'leri + default impl, associated type'lar, HRTB, `Copy`/`Send`/`Sync`, `Deref`/`DerefMut`.
- **Kısmi:** associated const'lar, `const fn`, const generics, `for` döngüleri, `as` cast, pointer'lar, **kayan nokta**, function pointer tipleri, **closure tipleri (mutable capture yok)**, **trait object'ler (`dyn`)**, `impl Trait`, **iterator'lar**, çok-crate'li projeler, panic-unwinding.
- **DESTEKLENMİYOR:** **`async fn` / async bloklar, `await`**, destructuring assignment, `Pin`, donanım intrinsic'leri, **yazdırma/I/O**, **standart trait'ler (`Debug`, `serde::Serialize`)**, **kullanıcı tanımlı `Drop`**, **standart kütüphane kilitleri (`Mutex`, `RwLock`)**, `transmute`, çok-iş parçacıklı atomikler (ancak `vstd` alternatifleri var).

> **Argus için doğrudan sonuç:** Verus, `async`/tokio tabanlı bir HTTP sunucusunda **kullanılamaz**. `serde::Serialize` desteklenmediği için serileştirme katmanına da giremez. Verus'un yeri, **saf, senkron, I/O'suz bir çekirdek modül** — örneğin politika değerlendirme motoru veya token durum makinesi — ve bu modülün geri kalanla `external_body` sınırından konuşması.

**Eşzamanlılık:** Verus, "VerusSync framework"ü ile önemsiz olmayan sahiplik disiplini gerektiren çok-iş parçacıklı kodu destekler; konu ayrı bir kitapta ele alınıyor (`state_machines/intro.html`) — [Verus concurrency guide](https://verus-lang.github.io/verus/guide/concurrency.html), erişim 2026-09-08. Yani **Verus, Kani'nin yapamadığı eşzamanlılık ispatını yapabilir** — ama tokenized state machine / ghost permission tekniklerini öğrenmek gerekir.

**Garantiler ve TCB:** Verus kılavuzu açıkça "doğrulanmış kod boşlukta çalışmaz; genellikle doğrulanmamış kodla her iki yönde etkileşir" diyor ve `external_body`, `assume`, `admit` gibi kaçış kapıları ile "Trusted Code Base (TCB)" için ayrı bölümler ayırıyor — [Verus guarantees](https://verus-lang.github.io/verus/guide/guarantees.html), erişim 2026-09-08. **Bu, Argus'ta "%X doğrulandı" demenin neden dikkatli ifade edilmesi gerektiğinin kaynağıdır: `external_body` ile işaretlediğiniz her fonksiyon ispatsız bir aksiyomdur.**

**Verus ile doğrulanmış sistemler** ([verus-lang.github.io/verus/verus/publications-and-projects](https://verus-lang.github.io/verus/publications-and-projects/), erişim 2026-09-08):
- **IronKV** — IronFleet'ten Verus'a port edilmiş dağıtık key-value store.
- **Verified Storage Systems (Microsoft)** — persistent memory için doğrulanmış key-value store ve append-only log implementasyonları.
- **Concurrent Memory Allocator** — mimalloc tabanlı.
- **Node Replication Library** — sıralı veri yapılarından linearizable NUMA-farkında eşzamanlı yapılar.
- **OS Page Table Management** — donanım bellek çeviri modelleriyle sayfa tablosu kodu.
- **Asterinas OSTD (`vostd`)** — safe Rust'ta OS geliştirme standart kütüphanesinin formel doğrulanmış sürümü.
- **TLSF Memory Allocator**, **TLA+ kütüphanesi** (Anvil'den port edilmiş TLA+ temporal logic gömülmesi).
- Yayınlar: Verus/OOPSLA 2023, Leaf separation logic/OOPSLA 2023, **Anvil (OSDI 2024)** — küme yönetim controller'larının liveness doğrulaması, **VeriSMo (OSDI 2024)** — gizli VM'ler için doğrulanmış güvenlik modülü, Verus/SOSP 2024 ([DOI 10.1145/3694715.3695952](https://dl.acm.org/doi/10.1145/3694715.3695952)), CortenMM (SOSP 2025).
- **VerusBelt** (PLDI 2026) — Verus'un anlamlı bir alt kümesi için **ilk semantik sağlamlık (soundness) ispatı**; cell'ler, invariant'lar, resource algebra'lar, storage protokolleri, tam Rust lifetime'ları, eşzamanlılık ve mutable borrow'ları kapsıyor — [pldi26.sigplan.org](https://pldi26.sigplan.org/details/pldi-2026-papers/82/VerusBelt-A-Semantic-Foundation-for-Verus-s-Proof-Oriented-Extensions-to-the-Rust-Ty). *Bu, Verus'a güvenmek için güçlü bir argüman.*

**Verus'ta ispat/kod oranı: [DOĞRULANAMADI]** — SOSP 2024 PDF'i metin olarak ayrıştırılamadı ve güvenilir bir ikincil kaynakta somut oran bulunamadı. Bu tür sistem doğrulama projelerinde tipik oranlar literatürde yüksektir, ancak **Verus için spesifik bir sayı bu araştırmada doğrulanamadı** — bunu bütçelemede varsayım olarak kullanmayın.

> **Uyarı:** emergentmind.com/topics/verus sayfası "Verus uses Z3 via the Viper verification backend" diyor — **bu yanlıştır**; Viper'ı kullanan Prusti'dir, Verus doğrudan Z3'e SMT üretir. Bu sayfa AI ile üretilmiş bir agregatördür, birincil kaynak olarak kullanılmamalıdır.

#### 2.3 Creusot

- **Ne yapar:** Rust'ı **Coma** ara doğrulama diline derler, sonra **Why3** platformu doğrulama koşullarını üretip SMT çözücülere dağıtır — [creusot.rs](https://creusot.rs/), erişim 2026-09-08.
- **Spesifikasyon dili: Pearlite** — `#[requires]`, `#[ensures]`, `#[invariant]`, döngü variant'ları (sonlanma için). Pearlite fonksiyonları/predicate'leri tanımlanabilir, hatta **trait'lerde bildirilebilir**.
- **Ne ispatlar:** panic, taşma, tanımsız davranış yokluğu; anotasyonla tam fonksiyonel doğruluk ve **sonlanma**.
- **Unsafe kod:** "ghost ownership" tekniğiyle interior mutability, raw pointer'lar ve atomikler ele alınıyor.
- **Aktivite: canlı.** Sürümler: v0.6.0 (2025-10-09), v0.7.0 (2025-11-03), v0.8.0 (2025-12-10), v0.9.0 (2026-01-17), v0.10.0 (2026-02-24), v0.11.0 (2026-04-20), v0.12.0 (2026-06-12), **v0.13.0 (2026-07-30)** — [releases.atom](https://github.com/creusot-rs/creusot/releases.atom), erişim 2026-09-08.
- **POPL 2026'da (Ocak 2026) tutorial verildi** — [popl26.sigplan.org](https://popl26.sigplan.org/details/POPL-2026-tutorials/6/Creusot-Formal-verification-of-Rust-programs).
- **Doğrulanmış örnek:** **CreuSAT** — Creusot ile formel doğrulanmış bir SAT çözücü (tez çalışması). Başka büyük ölçekli üretim kullanımı **[DOĞRULANAMADI]**.
- verify-rust-std'de **hâlâ inceleme aşamasında**, CI'da değil.

#### 2.4 Prusti — ÖLÜ

- ETH Zürich, Viper altyapısı üzerine kurulu permission-logic tabanlı safe Rust doğrulayıcı — [pm.inf.ethz.ch/research/prusti.html](https://www.pm.inf.ethz.ch/research/prusti.html).
- **Son sürüm: "Nightly Release v-2024-03-26-1504", 2024-03-26.** Bundan sonra hiçbir sürüm yok — [releases.atom](https://github.com/viperproject/prusti-dev/releases.atom), erişim 2026-09-08.
- **Son commit: "Fix issue #1505 (#1511)", 2024-03-26** (fpoli). Master dalında 2025 veya 2026'da **hiçbir commit yok** — [commits/master.atom](https://github.com/viperproject/prusti-dev/commits/master.atom), erişim 2026-09-08.
- Ayrıca `nightly-2023-09-15` gibi 3 yıl önceki bir Rust nightly'sine sabitlenmiş durumda.

> **Karar: Argus'ta Prusti kullanmayın.** ~2.5 yıldır terkedilmiş; modern Rust'ta derlenmez.

#### 2.5 Flux (UCSD) — düşük maliyetli tatlı nokta

- **Ne:** Rust derleyicisine eklenti olarak çalışan **refinement (liquid) tip denetleyicisi**. "Refinements: derleme sırasında kontrol edilen mantıksal iddialar" — [flux-rs.github.io/flux](https://flux-rs.github.io/flux/index.html), erişim 2026-09-08.
- **Kutudan çıkan kontroller:** aritmetik taşma, sıfıra bölme, dizi sınır aşımı. Kullanıcı refinement kontratlarıyla (ön/son koşul olarak) özel özellikler tanımlayabilir — [verify-rust-std tools/flux](https://model-checking.github.io/verify-rust-std/tools/flux.html), erişim 2026-09-08.
- **Anotasyon yükü — en düşük olanlardan:** **döngü invariant'larını otomatik çıkarır** ve **sınırsız (unbounded) doğrulama** yapar (Kani'nin yapamadığı). Le Blanc & Lam: Flux "daha hafif olmayı amaçlıyor" — [arXiv 2510.01072](https://arxiv.org/html/2510.01072v2).
- **Sınırlar** ([verify-rust-std tools/flux](https://model-checking.github.io/verify-rust-std/tools/flux.html)):
  1. Mantık hatalarını (panic) UB'ye yol açan hatalardan **ayırt etmez**.
  2. Refinement predicate'leri **niceleyicisiz, karar verilebilir birinci-derece mantık fragmanı** ile sınırlı — bu yüzden "dizi sıralı mı" gibi özellikler ifade edilemez.
  3. **Unsafe kod desteği sınırlı** — pointer özelliklerini takip edebilir ama **pointer üzerinden yazılan verinin değerlerini takip edemez**.
  4. Birçok Rust özelliği desteklenmiyor ve **analiz sırasında çökmelere** sebep olabiliyor.
- **Aktivite: çok yüksek.** Commit'ler: 2026-09-08 (bağımlılık), 2026-09-03 ("Add specs for dangling pointer functions", "Update generic Iterator::next() specs"), 2026-09-01 (üç ayrı iterator state commit'i) — [commits/main.atom](https://github.com/flux-rs/flux/commits/main.atom), erişim 2026-09-08.
- **En güçlü referansı:** **Tock** mikrodenetleyici OS'unda **süreç izolasyonu (process isolation)** doğrulandı. Tock, **Google Security Chip (GSC)** ve **Microsoft Pluton** güvenlik işlemcisi gibi güvenlik-kritik sistemlerde kullanılıyor. Doğrulama çalışması "izolasyonu bozan, kötü niyetli uygulamaların OS'u ele geçirmesine izin veren birden fazla ince hata" ortaya çıkardı — Ranjit Jhala (UCSD) kolokyumu, **2025-11-19** — [events.ucsc.edu](https://events.ucsc.edu/event/cse-colloquium-flux-refinement-types-for-verified-rust-systems/). Temel makale: "Flux: Liquid Types for Rust", PACMPL/PLDI 2023 — [dl.acm.org/doi/10.1145/3591283](https://dl.acm.org/doi/10.1145/3591283), [arXiv 2207.04034](https://arxiv.org/abs/2207.04034).
- verify-rust-std CI'ında **entegre** (dört araçtan biri).

> **Argus için değerlendirme:** Flux, Kani'den **çok daha ucuz** ve **sınırsız** olduğu için, "bu indeks asla buffer'ı aşmaz", "bu TTL asla negatif olmaz", "bu sayaç asla taşmaz" gibi *aritmetik/uzunluk* invariant'ları için ilk tercih olmalı. Ama "bu JWT doğru parse edildi" diyemez.

#### 2.6 Aeneas + Charon + hax → Lean/F* (kripto için gerçek üretim kanıtı)

- **Charon:** safe Rust'ı **LLBC**'ye (MIR türevi tiplenmiş ara temsil) çevirir. **Aeneas:** LLBC'yi **saf fonksiyonel Lean 4** koduna çevirir. Arka uçlar: **F*, Coq/Rocq, HOL4, Lean** — [lean-lang.org/use-cases/aeneas](https://lean-lang.org/use-cases/aeneas/), [github.com/AeneasVerif/aeneas](https://github.com/AeneasVerif/aeneas).
- **Aktivite: çok yüksek.** Commit'ler 2026-09-07 (Charon güncellemeleri, PR #1336, #1334), 2026-09-06 ("Fix release"), 2026-09-03 ("Fix `Iterator` extraction (#1131)") — [commits/main.atom](https://github.com/AeneasVerif/aeneas/commits/main.atom), erişim 2026-09-08.
- **hax (Cryspen):** Rust'ın büyük bir alt kümesini formel dillere çevirir. Arka uçlar: **Lean (Aeneas üzerinden — önerilen), Lean (legacy), Rocq/Coq (deneysel), F* (stabil), ProVerif (deneysel), SSProve (deneysel), EasyCrypt (deneysel)**. Tek kasıtlı kısıt: **`&mut T` dönüş tiplerinde ve aliasing durumunda yasak** — [github.com/cryspen/hax](https://github.com/cryspen/hax), erişim 2026-09-08 (474 ★).

**En güçlü 2026 üretim kanıtı — Microsoft SymCrypt:**
- "Verifying Rust cryptography in SymCrypt, from standards to code", Microsoft Research blog, **2026-07-13** — [microsoft.com/en-us/research/blog/verifying-rust-cryptography-in-symcrypt-from-standards-to-code](https://www.microsoft.com/en-us/research/blog/verifying-rust-cryptography-in-symcrypt-from-standards-to-code/).
- **ML-KEM ve SHA-3** için tam formel ispatlar tamamlandı ve bu kod **Windows insider build'lerinde şu anda çalışıyor**. AES-GCM, FrodoKEM, ML-DSA'ya genişletiliyor.
- Yöntem: kriptografik standartları **çalıştırılabilir Lean spesifikasyonu** olarak formalize et → Rust kodunu **Aeneas** ile Lean modeline çevir → implementasyon ile spesifikasyon arasında **eşdeğerlik ispatı** yap. SIMD intrinsic'leri ve platform-özel dispatch içeren optimize edilmiş, çok-mimarili kodu destekliyor.
- **AI ajanları** standartları spesifikasyona çevirmede ve ispatları yazıp bakımını yapmada kullanılıyor; "daha önce aylarca uzman eforu gerektiren iş dramatik biçimde hızlanabiliyor".

**libcrux (Cryspen'in doğrulanmış kripto kütüphanesi):**
- HACL*'dan çıkarılan F*-doğrulanmış kodu (bellek güvenliği + fonksiyonel doğruluk + **secret independence**) hax ile doğrulanmış Rust koduyla birleştiriyor (panic-freedom + fonksiyonel doğruluk).
- Algoritmalar: ML-KEM, X25519, XWing, P256 DHKEM; AES-GCM/CCM, ChaCha20Poly1305, XChaCha20Poly1305; BLAKE2, SHA2, SHA3; P256 ECDSA, ML-DSA, Ed25519, RSA-PSS; HKDF, HMAC, Poly1305.
- **KRİTİK SINIRLAMA:** *"Compiled executables are not verified for side-channel resistance"* — yani derlenmiş ikili dosyalar için yan-kanal direnci **doğrulanmamıştır**.
- **ÜRETİM UYARISI:** Tüm crate'ler **0.1'in altında ön-yayın**. Doküman birebir: *"If you wish to use any of these crates in production, get in touch with the maintainers and we can advise you on whether libcrux is a good fit for your use-case."* — [github.com/cryspen/libcrux](https://github.com/cryspen/libcrux), erişim 2026-09-08.

**AWS-LC formel doğrulaması (C tarafı, ama `aws-lc-rs` altında):**
- `aws-lc-verification` deposu: **SAW + Cryptol** (C ve x86-64), **NSym** (AArch64 assembly), **Coq** (Cryptol spesifikasyon özellikleri), **s2n-bignum** (HOL Light), **CBMC** (C bileşenlerinin bellek/tip güvenliği).
- Doğrulanmış algoritmalar: SHA-384/512, HMAC-SHA384, AES-KW(P)-256, AES-GCM-256; ML-KEM ve ML-DSA ilgili depolarda.
- **Varsayımlar altında:** sınırlı girdi uzunlukları, null ENGINE pointer'ları, doğrulanmamış fonksiyonların (`malloc`, refcounting) doğru davrandığı varsayımı.
- **2026 aktivitesi düşük** — yeni çalışma `s2n-bignum`, `mlkem-native`, `mldsa-native` depolarına kaymış — [github.com/awslabs/aws-lc-verification](https://github.com/awslabs/aws-lc-verification), erişim 2026-09-08.

#### 2.7 MIRAI — ÖLÜ (orijinal repo)

- Rust MIR üzerinde soyut yorumlayıcı (abstract interpreter), Facebook/Meta kökenli.
- README birebir: proje *"started out as a Facebook project, but became orphaned when the sponsoring organization was disbanded"*; *"ongoing work to keep the project alive now happens at https://github.com/endorlabs/MIRAI"* — [raw README](https://raw.githubusercontent.com/facebookexperimental/MIRAI/main/README.md), erişim 2026-09-08.
- Orijinal repoda **son commit 2024-08-22** ("Update README to point to new home"); 2025 veya 2026'da hiçbir aktivite yok — [commits/main.atom](https://github.com/facebookexperimental/MIRAI/commits/main.atom), erişim 2026-09-08.
- Endor Labs fork'unun 2026 aktivite durumu **[DOĞRULANAMADI]** (bu araştırmada incelenmedi).

> **Karar: Argus'ta MIRAI'ye bel bağlamayın.**

#### 2.8 VeriFast

- Rust için separation logic tabanlı **modüler** doğrulayıcı; fonksiyonları tek tek spesifikasyonlarına karşı kontrol eder.
- **Ne ispatlar:** `unsafe` içeren fonksiyonların **UB üretmediğini** ve dönüş durumlarının son koşulları sağladığını. Safe fonksiyonlar için **RustBelt**'in Rust tip sistemi semantiğine dayalı spesifikasyonlar üreterek "semantik iyi-tiplilik" garanti eder.
- **Anotasyon yükü — çok yüksek:** her fonksiyon için ön/son koşul, **her döngü için invariant**, sembolik yürütme algoritmasına ipucu veren **ghost komut anotasyonları**, bellek ayak izini tanımlayan **separation logic predicate'leri**.
- Karşılığında: **sonlu zamanda sınırsız (unbounded) doğrulama** — Kani'nin unwind sınırı sorunu yok.
- std kampanyasında `LinkedList`'in **19 çekirdek fonksiyonu** doğrulandı — [verify-rust-std tools/verifast](https://model-checking.github.io/verify-rust-std/tools/verifast.html) ve [Rust Foundation, 2026-09-01](https://rustfoundation.org/media/how-the-rust-standard-library-verification-contest-scaled-past-manual-proof-engineering/).

#### 2.9 KMIR (Runtime Verification)

- **K Framework** üzerine kurulu, **MIR seviyesinde** rewrite tabanlı semantik; hem somut hem sembolik yürütme.
- Harness'lar **düz Rust** ile yazılır: son koşul için `assert!`, ön koşul için `assume` — özel doğrulama dili yok.
- "Refusal-to-execute" stratejisi: UB'ye yol açabilecek bir talimatla karşılaşınca UB-detected durumunda durur ve ispat başarısız olur.
- **Desteklenmeyenler:** kayan nokta (f16/f32/f64/f128), **heap ayıran tipler (String, Vec)**, **smart pointer'lar (Box, Rc, Arc)**, **async/await ve çok-iş parçacıklılık**, **dinamik trait object'ler**.
- Başarılar: Rust std'de tamsayı işlemleri; Solana P-Token ve SPL-Token programları için eşdeğerlik ispatları.
— [verify-rust-std tools/kmir](https://model-checking.github.io/verify-rust-std/tools/kmir.html), erişim 2026-09-08.

> `String`/`Vec` desteklenmediği için **bir IdP için 2026'da kullanılabilir değil**.

#### 2.10 ESBMC / goto-transcoder

- Kani'nin GOTO çıktısını ESBMC'ye besler; **k-induction** ve SMT çözücü desteği ekler. Teorik olarak "daha güçlü doğrulama" potansiyeli var **ama bu arka uçla hiçbir challenge çözülmedi** — [arXiv 2510.01072](https://arxiv.org/html/2510.01072v2), Ekim 2025.

#### 2.11 Gillian-Rust / Soteria-Rust, RefinedRust, coq-of-rust/rocq-of-rust

- **Soteria-Rust** — Rust Formal Methods Interest Group'un **Aralık 2025** toplantısında sunuldu: *"the first symbolic execution engine for Rust that fully supports reasoning about the language"* — [rust-formal-methods.github.io](https://rust-formal-methods.github.io/), erişim 2026-09-08. Depo URL'i doğrulanamadı (denenen iki URL 404 döndü) — **[DOĞRULANAMADI]**.
- **Gillian-Rust** — "hybrid approach to unsafe Rust verification"; RFMIG tool listesinde yer alıyor; survey'de "hybrid separation logic, safe ve unsafe entegrasyonu" olarak sınıflandırılmış — [arXiv 2410.01981v1](https://arxiv.org/html/2410.01981v1), 2024-10-02.
- **RefinedRust** — MPI-SWS, "foundational semi-automated functional correctness verification" (Coq/Iris tabanlı, foundational separation logic). GitLab deposu 1.642 commit, Apache 2.0, 2023-06-12'de oluşturulmuş — [gitlab.mpi-sws.org/lgaeher/refinedrust-dev](https://gitlab.mpi-sws.org/lgaeher/refinedrust-dev), erişim 2026-09-08. Güncel aktivite düzeyi **[DOĞRULANAMADI]**.
- **rocq-of-rust (Formal Land)** — Rust'ın THIR temsilini Rocq'a çevirir; 1.2k ★, 3.326 commit; Ethereum Foundation ve Aleph Zero Foundation fonlu — [github.com/formal-land/coq-of-rust](https://github.com/formal-land/coq-of-rust), erişim 2026-09-08. Sayfa tam yüklenmediği için güncel durum **[KISMEN DOĞRULANAMADI]**.

> Bu üçü **araştırma aşamasında**; Argus için 2026'da üretim seçeneği değil.

#### 2.12 Survey / karşılaştırma literatürü

- **"Surveying the Rust Verification Landscape"** — Alex Le Blanc, Patrick Lam (University of Waterloo), **2024-10-02**, arXiv 2410.01981 — [arxiv.org/html/2410.01981v1](https://arxiv.org/html/2410.01981v1). Taksonomi: Kani (bounded model checking, unsafe kod, bellek güvenliği), Prusti (deductive, safe Rust), Creusot (deductive, Pearlite), Aeneas (fonksiyonel çeviri), Verus (Rust-native ispatlar), Gillian-Rust (hibrit separation logic), RefinedRust (foundational separation logic). **Flux, MIRAI ve Miri'yi derinlemesine ele almıyor** — bu bir eksiklik, 2026 için güncelliğini kısmen yitirmiş.
- **"Lessons Learned So Far From a Community Effort to Verify the Rust Standard Library"** — aynı yazarlar, arXiv 2510.01072, **2025-10-01 / rev. 2025-10-26** — [arxiv.org/abs/2510.01072](https://arxiv.org/abs/2510.01072). En değerli kısmı **üç temel engel**:
  1. **Karmaşık çağıran gereksinimleri:** `MaybeUninit<T>`'nin initialize durumu veya pointer provenance gibi, tek bir ön koşulla ifade edilmesi zor koşullar.
  2. **Generic tipli girdiler:** Rust derleme zamanında monomorfize ettiği için her tip örneklemesi ayrı harness gerektiriyor → "bir yığın neredeyse-aynı harness".
  3. **Eşzamanlı kod:** Kani dokümanı eşzamanlılığı desteklemediğini söylüyor, ancak alttaki motorlar (CBMC/ESBMC) eşzamanlılığı destekliyor — yani teorik boşluk değil, mühendislik boşluğu.
- **ASE 2026 Kani makalesinin kendi karşılaştırması:** *"Verus is the closest tool to Kani in ambition"*; deductive araçlar (Prusti, Creusot, Verus) zengin fonksiyonel özellikleri ispatlayabilir ancak *"require substantial proof engineering (e.g., separation logic or ghost state) that limits adoption outside specialist teams"* — [arXiv 2607.01504](https://arxiv.org/html/2607.01504), 2026-07-01.
- NFM 2026 makalesinin gerekçesi: *"no single tool can discharge all verification conditions; architecture-specific intrinsics, pointer-heavy code, concurrency primitives, and loops with complex invariants require complementary reasoning techniques"* — [arXiv 2606.17374](https://arxiv.org/html/2606.17374), 2026-06-16.

---

### 3. UCUZ YARDIMCILAR: MIRI, LOOM, FUZZING, SANITIZER'LAR

#### 3.1 Miri — 2026'da olgun ve akademik olarak sağlamlaştırılmış

- **POPL 2026 makalesi:** "Miri: Practical Undefined Behavior Detection for Rust", Ralf Jung, Benjamin Kimock, Christian Poveda, Eduardo Sánchez Muñoz, Oli Scherer, Qian Wang — [plf.inf.ethz.ch/research/popl26-miri.html](https://plf.inf.ethz.ch/research/popl26-miri.html), [dl.acm.org/doi/10.1145/3776690](https://dl.acm.org/doi/10.1145/3776690).
- İddia: **"the first tool that can find all de-facto Undefined Behavior in deterministic Rust programs"**.
- **Değerlendirme:** 100.000'den fazla Rust kütüphanesi üzerinde test edildi; birleşik test suite'lerinin **%70'inden fazlası başarıyla çalıştırıldı**; **onlarca gerçek dünya hatası** bulundu; Rust std ve birçok önemli kütüphanenin CI'ına entegre.

**Miri'nin yakaladıkları** ([Miri README](https://raw.githubusercontent.com/rust-lang/miri/master/README.md), erişim 2026-09-08):
- Sınır dışı bellek erişimi ve use-after-free
- Initialize edilmemiş verinin geçersiz kullanımı
- Intrinsic ön koşul ihlalleri (`unreachable_unchecked`'a ulaşma, örtüşen aralıklarla `copy_nonoverlapping` çağırma)
- Yetersiz hizalanmış bellek erişimleri ve referanslar
- Temel tip değişmezi ihlalleri (0/1 olmayan `bool`, geçersiz enum discriminant)
- **Veri yarışları** ve *bazı* zayıf bellek (weak memory) etkilerinin emülasyonu
- **Stacked Borrows / Tree Borrows** aliasing ihlalleri (deneysel)
- Bellek sızıntıları (program sonunda ulaşılamayan ayrılmış bellek)

**Miri'nin yakalayamadıkları / sınırları** (aynı README):
- **"Does not catch every violation of the Rust specification"** — çünkü formel bir spesifikasyon yok.
- **Determinizm sorunu:** *"Miri tests one of many possible executions of your program, but it will miss bugs that only occur in a different possible execution."* — bellek yerleşimi ve iş parçacığı interleaving'i tek bir yürütmeyi test eder.
- **Platform API'leri ve FFI'ye erişimi yok**; **ağ (networking) desteklenmiyor**. → *Argus için: HTTP sunucusu tarafını Miri altında koşturamazsınız; sadece saf iş mantığı unit testlerini.*
- Zayıf bellek emülasyonu **tam değil** — Miri'nin asla üretmeyeceği yasal davranışlar var.
- **En önemli:** *"Miri fundamentally cannot ensure that your code is sound."* UB'yi belirli yürütmelerde bulur, keyfi safe kod kombinasyonlarıyla tüm olası çağrılarda değil.
- Ayrıca: integer→pointer cast yapan programlar **tam desteklenmiyor** ve kullanıcı uyarılır; Stacked/Tree Borrows aliasing kontrolü **veri yarışı dedektörünün yerini tutmaz**, model raw pointer'ları ve interior-mutable paylaşımlı referansları kasten kısıtlamaz — [POPL 2026 makalesi özeti üzerinden](https://plf.inf.ethz.ch/research/popl26-miri.html).

**CI maliyeti:** Miri bir yorumlayıcıdır; native yürütmeye göre **büyüklük mertebelerinde yavaştır**. **[TAHMİN — kaynaklı değil]** Pratikte tipik olarak 10–100× yavaşlama beklenmeli; kesin bir çarpan bu araştırmada doğrulanamadı. Pratik yaklaşım: Miri'yi her PR'da değil, **nightly** olarak ve **sadece saf/unsafe içeren crate'lerin unit testlerinde** koşturmak.

#### 3.2 Loom — güçlü ama bakım modunda

- **Ne:** *"runs tests many times, permuting the possible concurrent executions"*; **C11 bellek modelini** modeller; işletim sistemi zamanlayıcısını ve Rust bellek modelini simüle ederek *"all possible valid behaviors are explored and tested"* — [docs.rs/loom](https://docs.rs/loom/latest/loom/), erişim 2026-09-08.
- **Kapsam:** iş parçacığı zamanlama permütasyonları, çeşitli memory ordering'lerle atomik işlemler (SeqCst, Acquire/Release), mutex/rwlock/condvar/channel, `UnsafeCell`, kombinatoryal patlamayı azaltmak için durum indirgeme.
- **Sınırlar:**
  1. **Müdahaleci (intrusive):** yalnızca Loom'un replacement tiplerini kullanan kod modellenir; Loom'dan gizlenen işlemler izlenmez. → *Argus'ta `std::sync` yerine `loom::sync` kullanan `cfg(loom)` yolları yazmanız gerekir.*
  2. **Relaxed ordering'i tam modelleyemez** — tek iş parçacığı içindeki yeniden sıralamaları (B, A'dan önce çalışabilir) tam kapsamaz.
  3. **`MAX_THREADS` sınırı** — interleaving'ler üstel büyüdüğü için.
  4. **Kombinatoryal patlama** — `LOOM_MAX_PREEMPTIONS` genelde 2-3'e ayarlanır; bu **eksiksizliği (exhaustiveness) feda eder**.
  5. Büyük modellerde exhaustive kontrol çok uzun sürer.
- **BAKIM DURUMU — dikkat:** crates.io'ya göre **son sürüm 0.7.2, 2024-04-23**; öncekiler 0.7.1 (2023-10-02), 0.7.0 (2023-08-04). Toplam **62.875.383 indirme** — [crates.io/api/v1/crates/loom](https://crates.io/api/v1/crates/loom), erişim 2026-09-08.
  GitHub'da 2025-2026'da yalnızca **5 commit**: 2026-02-20 (typo düzeltmesi), 2026-01-12 (`RwLock`'a `?Sized` bound), 2025-04-17, 2025-04-14, 2025-02-11 — [commits/master.atom](https://github.com/tokio-rs/loom/commits/master.atom), erişim 2026-09-08.
  > *(Not: docs.rs özeti "0.7.2, 31 Ağustos 2026" dedi; bu muhtemelen doküman build tarihidir. crates.io API'sini otoriter kabul ediyorum: **2024-04-23**.)*
- **Sonuç:** Loom çalışır ve yaygın kullanılır ama **aktif geliştirilmiyor**; 2+ yıldır yeni sürüm yok.

#### 3.3 Shuttle (AWS) — Loom'un ölçeklenebilir alternatifi

- Randomize edilmiş eşzamanlılık testi; "A Randomized Scheduler with Probabilistic Guarantees of Finding Bugs" araştırmasına dayanıyor.
- Loom'dan farkı: **exhaustive değil, olasılıksal.** *"Not sound (a passing Shuttle test does not prove the code is correct)"* — ama **çok daha büyük test senaryolarını** kaldırabilir.
- `std::sync` (Arc, Mutex…), `std::collections` ve tokio/rand gibi popüler kütüphanelerin primitiflerini sarmalar.
- **Aktif:** `shuttle` 0.9.3, **2026-08-20**; 0.9.2 (2026-08-12), 0.9.1 (2026-04-21) — [crates.io/api/v1/crates/shuttle](https://crates.io/api/v1/crates/shuttle), erişim 2026-09-08. Repo: 319 commit, 1.1k ★, Apache-2.0 — [github.com/awslabs/shuttle](https://github.com/awslabs/shuttle).

> **Argus için: Loom (küçük, kritik primitifler için exhaustive) + Shuttle (büyük entegrasyon senaryoları için randomize).** Kani eşzamanlılığı desteklemediği için bu ikisi zorunlu.

#### 3.4 Fuzzing ve property testing

| Araç | Sürüm / tarih | İndirme | Not |
|---|---|---|---|
| `cargo-fuzz` (libFuzzer) | **0.13.2, 2026-06-09** | 4.482.797 | [crates.io](https://crates.io/api/v1/crates/cargo-fuzz), 2026-09-08 |
| `proptest` | **1.11.0, 2026-03-24** | 182.638.062 | [crates.io](https://crates.io/api/v1/crates/proptest), 2026-09-08 |
| `bolero` | **0.13.4, 2025-07-03** | 5.406.604 | "fuzz and property testing front-end" — [crates.io](https://crates.io/api/v1/crates/bolero), 2026-09-08 |

**Kani'nin bunlarla karşılaştırması** ([Kani tool comparison](https://model-checking.github.io/kani/tool-comparison.html), erişim 2026-09-08):
- **Fuzzing:** yönlendirilmemiş rastgele test; "çökmüyor mu, UB yapmıyor mu" gibi genel özellikler; evrimsel algoritmalar.
- **Property testing:** yönlendirilmiş rastgeleleştirme; ancak *"the engine can't fully prove the property: It can only sample randomly a few of those values to test."*
- **Model checking (Kani):** *"non-random and exhaustive (though often only up to some bound on input or problem size)"*; program izlerini sembolik SAT/SMT problemleri olarak kodlar.

**Kritik veri noktası:** s2n-quic'te `try_fit` hatası — **fuzzing 16.7 milyon iterasyonda bulamadı, Kani 20 saniyede buldu** ([arXiv 2607.01504](https://arxiv.org/html/2607.01504v1), 2026-07-01). Ama tersi de doğru: `decode_packet_number` taşmasını fuzzing de bağımsız olarak buldu. **Fuzzing ile model checking rakip değil, tamamlayıcıdır.**

**Bolero'nun köprü rolü:** s2n-quic'te tek bir öznitelikle aynı harness hem fuzz hedefi hem Kani ispatı olarak çalışıyor ([Kani blog, 2023-05-30](https://model-checking.github.io/kani-verifier-blog/2023/05/30/how-s2n-quic-uses-kani-to-inspire-confidence.html); [Kani blog, 2022-10-27 "From Fuzzing to Proof: Using Kani with Bolero"](https://model-checking.github.io/kani-verifier-blog/)). **Argus için önerilen omurga budur.**

#### 3.5 Sanitizer'lar (ASan/TSan/MSan/CFI)

[doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html), erişim 2026-09-08:

- **Hepsi nightly-only** (`-Zsanitizer=...`).
- Test/fuzzing için: **ASan, HWASan, LSan, MSan, RealtimeSanitizer, TSan**. Üretimde kullanılabilir olanlar: **CFI, KCFI, DataFlowSanitizer, MemTagSanitizer, SafeStack, ShadowCallStack**.
- Platformlar: ASan → x86_64/aarch64 Linux/macOS/FreeBSD/Fuchsia; TSan → x86_64/aarch64 Linux/macOS/FreeBSD; MSan → x86_64/aarch64 Linux/FreeBSD.
- **TSan uyarıları (Argus için kritik):** `std::sync::atomic::fence` **desteklenmiyor**; inline assembly ile senkronizasyon desteklenmiyor; kısmi enstrümantasyon **false positive** üretir; `-Zbuild-std` ile std'yi yeniden derlemek önerilir.
- **MSan:** tüm program kodunun enstrümante edilmesi **zorunlu**; C/C++ bağımlılıkları Clang `-fsanitize=memory` ile yeniden derlenmeli; aksi hâlde false positive.
- **CFI** için `-Clto` veya `-Clinker-plugin-lto` gerekir.

> **Argus için:** Eğer `forbid(unsafe_code)` politikası uygularsanız (rustls'in yaptığı gibi), ASan/MSan'ın marjinal değeri düşer. **TSan** yine de değerlidir çünkü safe Rust'ta bile FFI sınırlarında ve `unsafe` kripto bağımlılıklarında yarış olabilir. CFI ise **derleme sertleştirmesi** olarak üretimde açılmaya değer.

---

### 4. ARGUS (IdP) BİLEŞENLERİNE UYGULANABİLİRLİK

> Aşağıdaki efor tahminleri **[TAHMİN — kaynaklı değil]**, kaynaklarda bulunan analog projelerden (Hifitime 153 ispat, Firecracker 34 harness/21 dk, s2n-quic 102 harness) türetilmiş mühendislik yargılarıdır.

#### 4.1 Bileşen bazlı harita

| # | IdP bileşeni | En uygun araç | İfade edeceğiniz özellik | Efor [TAHMİN] | Gerekçe / kaynak |
|---|---|---|---|---|---|
| 1 | **JWT / JOSE parser** (compact serialization) | Kani (sınırlı) + **cargo-fuzz birincil** | "Herhangi bir ≤N baytlık girdi için parser panic etmez, UB yapmaz, ve `alg` alanı asla `none`'a düşmez" | Kani: 2–4 hafta, **sınırlı değer**; fuzz: 3–5 gün, yüksek değer | Kani dokümanı parser'lar için 10-20+ karakterlik girdilerin gerektiğini ve bunun ölçeklenmediğini açıkça söylüyor — [loop unwinding tutorial](https://model-checking.github.io/kani/tutorial-loop-unwinding.html) |
| 2 | **base64 / CBOR / ASN.1(DER) decoder** | **Kani** (sabit, küçük N için) + fuzz + Miri | "≤32 bayt girdi için: panic yok, sınır aşımı yok, `decode(encode(x)) == x` (round-trip)" | Kani: 1–2 hafta/decoder | Hifitime'da "encode-decode identity" ispatları böyle yapıldı — [arXiv 2607.01504](https://arxiv.org/html/2607.01504v1) |
| 3 | **Sabit zamanlı karşılaştırma** (HMAC/token eşitliği) | **HİÇBİRİ tam çözmez** — `subtle` crate + kod incelemesi + `dudect` tarzı istatistiksel test | "Karşılaştırma süresi girdi verisinden bağımsız" | — | Bu bir **zamanlama/yan-kanal** özelliğidir; Kani, Verus, Creusot, Flux'un hiçbiri zamanlamayı modellemez. libcrux bile *"compiled executables are not verified for side-channel resistance"* diyor — [github.com/cryspen/libcrux](https://github.com/cryspen/libcrux). `subtle` 2.6.1 (2024-06-24), 682M indirme — [crates.io](https://crates.io/api/v1/crates/subtle) |
| 4 | **Protokol durum makineleri** (OAuth2/OIDC akışları, device code, PKCE) | **Verus** (senkron çekirdek) veya **Stateright** (actor modeli) veya **TLA+/hax→ProVerif** (protokol seviyesi) | "Yetkilendirme kodu asla iki kez kullanılamaz"; "state parametresi eşleşmeden token verilmez"; "PKCE verifier olmadan kod değiştirilemez" | Verus: 4–8 hafta; Stateright: 2–3 hafta | Verus TLA+ gömülmesi mevcut ([Verus projects](https://verus-lang.github.io/verus/publications-and-projects/)); Stateright liveness için "experimental/incomplete" ([repo](https://github.com/stateright/stateright)). **Protokol seviyesi güvenlik için Fett/Küsters/Schmitz'in web modeli referans** — [arXiv 1601.01229](https://arxiv.org/abs/1601.01229), CCS 2016; OAuth 2.0'da 4 yeni saldırı buldular ve bunlar **OpenID Connect'te de mevcut** |
| 4b | **Kod→implementasyon köprüsü** | **Differential random testing (Cedar deseni)** | "Rust implementasyonu, Lean/Dafny referans modeliyle her girdide aynı kararı verir" | 3–6 hafta | Cedar tam olarak bunu yapıyor: Lean modeli ispatlanır, Rust implementasyonu **ispatlanmaz**, DRT ile karşılaştırılır; gecelik ~100 milyon test — [Amazon Science, 2023-05-10](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing) |
| 5 | **Erişim kontrolü / politika değerlendirme** | **Cedar'ı doğrudan kullanın**, ya da Cedar desenini kopyalayın (Lean model + DRT); alternatif Verus | "Yalnızca `permit` politikası izin verir, hata/varsayılan yoluyla izin doğmaz"; "`forbid`, `permit`'i her koşulda ezer"; "validator kabul ederse değerlendirme belirli hata sınıflarına düşmez" | Cedar kullanımı: günler. Kendi motorunu ispatlamak: **3–6 ay** | Bu üç özellik Cedar'da **fiilen ispatlanmış**: "Explicit Permit", "Forbid Overrides Permit", "Validator Soundness" — [Amazon Science, 2023-05-10](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing). Cedar, OOPSLA 2024'te yayınlandı — [amazon.science](https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization). Model artık **Lean 4**'te, `cedar-spec` deposu **2026-09-04'te hâlâ aktif** (batched evaluation, requestIsConsistent tutarlılık ispatları) — [commits/main.atom](https://github.com/cedar-policy/cedar-spec/commits/main.atom). **Ancak README açıkça: Rust kodu doğrulanmamıştır** — [cedar-spec README](https://raw.githubusercontent.com/cedar-policy/cedar-spec/main/README.md) |
| 6 | **Oturum ömrü / saat aritmetiği** (skew, expiry, `nbf`/`exp`/`iat`, leap second) | **KANI — EN İYİ UYUM** | "Herhangi bir `now`, `iat`, `exp`, `skew` için: taşma yok; `is_expired` monotondur; `exp < now - skew ⇒ reddedilir`; `PartialEq`/`Ord` tutarlıdır" | **1–3 hafta, çok yüksek getiri** | **Hifitime bunun kanıtı.** Kani orada tam bu sınıfta 6 gerçek hata buldu: işaret hatası, `i64::MIN.abs()` taşması, NaN yayılımı, **`Epoch`'ta `PartialEq`/`Ord` tutarsızlığı**, **`Duration`'da `a == b && a < b`**, `is_gregorian_valid` taşması — [arXiv 2607.01504](https://arxiv.org/html/2607.01504v1), 2026-07-01. Bir IdP'de `Ord` tutarsızlığı doğrudan **süresi dolmuş token'ın kabul edilmesi** demektir |
| 7 | **Kripto yapıştırma kodu** (nonce üretimi, key wrapping, KDF çağrıları, alg seçimi) | Kani (stub'lu) + `aws-lc-rs` gibi doğrulanmış altyapı; ileri seviye: hax/Aeneas→Lean | "Nonce asla tekrar kullanılmaz"; "anahtar materyali zeroize edilir"; "desteklenmeyen `alg` reddedilir" | Kani: 1–2 hafta. Aeneas/Lean: **6+ ay + Lean uzmanı** | Kani `#[kani::stub]` ile RNG ve saat okumayı nondeterministik değerlerle modelleyebilir — bu **tam olarak Firecracker rate limiter'da yapıldı** ([arXiv 2607.01504](https://arxiv.org/html/2607.01504v1)). Kripto primitiflerini kendiniz ispatlamayın: SymCrypt (Microsoft, 2026-07-13) ve AWS-LC bunu zaten yapmış |
| 8 | **Oran sınırlayıcı (rate limiter) / brute-force koruma** | **KANI — kanıtlanmış uyum** | "Herhangi bir istek dizisi ve saat değeri için, T penceresinde izin verilen istek sayısı ≤ bütçe" | **1 hafta, çok yüksek getiri** | Firecracker'ın rate limiter'ı Kani ile **nondeterministik saat değerleri** kullanılarak doğrulandı ve **%0.01 bütçe aşımına izin veren yuvarlama hatası** bulundu — [arXiv 2607.01504](https://arxiv.org/html/2607.01504v1), 2026-07-01 |
| 9 | **İndeks/uzunluk/tampon mantığı** (header parsing offset'leri, buffer slicing) | **FLUX** | "`i < buf.len()` her erişimde"; "taşma yok"; "kapasite ≥ uzunluk" | **3–7 gün, en ucuz kazanç** | Flux döngü invariant'larını otomatik çıkarır ve **sınırsız** doğrular; kutudan taşma/sıfıra bölme/dizi sınırı kontrolü verir — [verify-rust-std tools/flux](https://model-checking.github.io/verify-rust-std/tools/flux.html) |
| 10 | **Eşzamanlı oturum deposu / token cache / iptal listesi** | **LOOM** (küçük primitifler) + **SHUTTLE** (büyük senaryolar) + TSan | "Token iptali ile doğrulama arasında yarış yok"; "cache invalidation atomiktir" | Loom: 1–2 hafta | **Kani burada kullanılamaz** — eşzamanlı kodu sessizce sıralı işler ([rust-feature-support](https://model-checking.github.io/kani/rust-feature-support.html)). Kani dokümanı bizzat Loom ve Shuttle'ı öneriyor ([tool comparison](https://model-checking.github.io/kani/tool-comparison.html)). Verus VerusSync ile yapabilir ama `Mutex`/`RwLock` desteklemediği için `vstd` primitiflerine geçmek gerekir |
| 11 | **HTTP katmanı / async runtime (axum/tokio)** | **HİÇBİR formel araç değil** — sadece fuzz + entegrasyon testi + Shuttle | — | — | Kani: `await` = **Hayır**. Verus: `async fn`/`await` = **DESTEKLENMİYOR**. KMIR: async/await desteklenmiyor. Miri: **ağ desteklenmiyor**. Bu katman **formel doğrulama kapsamı dışıdır** |
| 12 | **Serileştirme (serde)** | Fuzz + proptest round-trip | "`deserialize(serialize(x)) == x`" | 3–5 gün | Verus `serde::Serialize`'i **desteklemiyor** ([Verus features](https://verus-lang.github.io/verus/guide/features.html)) |

#### 4.2 Argus için önerilen katmanlı strateji

**Katman 0 — Taban (hafta 1-2, zorunlu):**
- `#![forbid(unsafe_code)]` çekirdek crate'lerde (rustls deseni — [rustls SECURITY.md](https://github.com/rustls/rustls/blob/main/SECURITY.md)).
- `cargo-fuzz` + OSS-Fuzz kaydı: her parser (JWT, base64, CBOR, DER, form-encoding) için hedef.
- `proptest`/`bolero` round-trip ve invariant testleri.
- Nightly Miri koşusu (saf mantık testleri; ağ/FFI olan testler hariç).
- CI'da CFI ile sertleştirilmiş release build.

**Katman 1 — Ucuz formel (hafta 3-8):**
- **Flux**: indeks/uzunluk/taşma invariant'ları. En düşük anotasyon maliyeti, sınırsız garanti.
- **Kani (autoharness ile başla)**: `cargo kani autoharness -Z autoharness` ile tüm saf, `Arbitrary`-uyumlu fonksiyonlar için otomatik panic/UB taraması. Bu, std kampanyasında 16.748 harness üreten yaklaşımın aynısı ([arXiv 2606.17374](https://arxiv.org/html/2606.17374), 2026-06-16). **Generic fonksiyonlarda tek monomorfizasyon doğrulandığı için bunun bir under-approximation olduğunu unutmayın** ([autoharness docs](https://model-checking.github.io/kani/reference/experimental/autoharness.html)).
- **Kani elle harness**: saat/expiry aritmetiği (#6) ve rate limiter (#8). **En yüksek getiri/maliyet oranı buradadır.**

**Katman 2 — Eşzamanlılık (hafta 6-10):**
- `cfg(loom)` yolları ile oturum deposu ve iptal listesi primitifleri; `LOOM_MAX_PREEMPTIONS=3`.
- Shuttle ile daha büyük entegrasyon senaryoları.
- Nightly TSan (`-Zbuild-std` ile).

**Katman 3 — Ağır ispat (ay 3-9, sadece bir hedef seçin):**
- **Öneri: politika/erişim kararı motoru.** Ya doğrudan **Cedar**'ı kullanın (zaten Lean'de ispatlanmış model + gecelik 100M DRT), ya da kendi motorunuz için Cedar desenini kopyalayın: referans modeli Lean/Verus'ta yazıp ispatlayın, Rust implementasyonunu DRT ile bağlayın.
- Alternatif: token/oturum durum makinesini **Verus**'ta senkron, I/O'suz bir çekirdek olarak yazın.

**Yapmayın:**
- Kripto primitiflerini kendiniz ispatlamaya kalkmayın (SymCrypt/AWS-LC/libcrux var).
- Async HTTP katmanını formel doğrulamaya çalışmayın (hiçbir araç desteklemiyor).
- Prusti veya MIRAI'ye bel bağlamayın (ölü).
- libcrux'u üretimde bakımcılara danışmadan kullanmayın (0.1 altı sürümler).
- "Tam parser doğrulaması" hedeflemeyin — Kani'nin kendi dokümanı bunun ölçeklenmediğini söylüyor.

#### 4.3 CI maliyeti hakkında gerçekçi rakamlar

| Referans | Ölçek | Süre |
|---|---|---|
| Firecracker | 34 harness | **21 dakika** |
| Rust std kampanyası | 16.748 harness | **69 dakika** (paralelleştirme + cache ile, 3.97× hızlanma sonrası) |
| Hifitime Faz I | 158 harness | **57 tanesi 60 saniyelik bütçeyi aştı** |
| Hifitime Faz II (kontratlarla) | 153 ispat | çoğu **<5 s**; en yavaşları 16.4 s ve 13.6 s |

Kaynak: [arXiv 2607.01504](https://arxiv.org/html/2607.01504v1), 2026-07-01.

> **Ders:** Kontratlar (`requires`/`ensures`/`modifies`) sadece "daha güçlü özellik" değil, **CI süresini düşüren modülerleştirme aracıdır** — Hifitime'da harness sayısı 11'den 153'e çıkarken tek ispat süresi düştü. Argus'ta da kontrat tabanlı modüler doğrulama, monolitik harness'lardan daha sürdürülebilir olacaktır.

---

### 5. ÖNEMLİ UYARILAR VE DOĞRULANAMAYANLAR

1. **verify-rust-std çözülmüş/açık challenge sayısı** — aynı README'nin iki çekimi çelişkili sonuç verdi (7/22 vs 9/20; $315k vs $285k). Bağımsız hakemli kaynak (arXiv 2510.01072, Ekim 2025) "9/27" diyor. **Kesin güncel sayı doğrulanamadı.** Mücadele sayısının 29 olduğu ve ödüllerin 10.000–25.000 USD aralığında olduğu doğrulandı.
2. **AWS'in toplam $ taahhüdü** — Rust Foundation duyurusunda (2024-11-20) belirli bir toplam rakam yok. README'deki tablodan toplam çıkarılabilir ama iki çekim farklı toplam verdi. **Doğrulanamadı.**
3. **Kani'nin 8 aylık sürüm boşluğunun nedeni** — doğrulanamadı. Proje ASE 2026 makalesi (2026-07-01) ile canlı görünüyor ama sürüm ve blog kadansı durmuş.
4. **Verus'un ispat/kod oranı** — SOSP 2024 PDF'i ayrıştırılamadı; güvenilir sayı bulunamadı. Bütçelemede varsayım olarak kullanmayın.
5. **Miri'nin yavaşlama çarpanı** — kaynaklarda somut sayı bulunamadı; yukarıdaki 10–100× **tahmindir**.
6. **Tokio'nun Kani'yi sürekli CI'da kullanıp kullanmadığı** — sadece 2022 tarihli bir vaka çalışması blog yazısı bulundu; sürekli kullanım doğrulanamadı.
7. **Endor Labs'in MIRAI fork'unun 2026 durumu** — incelenmedi.
8. **Soteria-Rust / RefinedRust'ın güncel aktivite düzeyi** — depo URL'leri doğrulanamadı (404).
9. **emergentmind.com** AI-üretimi bir agregatördür ve Verus hakkında **yanlış** bilgi içeriyor ("Z3 via Viper backend"); birincil kaynak olarak kullanılmamalıdır.
10. **Loom'un son sürüm tarihi** — docs.rs özeti (2026-08-31) ile crates.io API'si (2024-04-23) çelişti; crates.io otoriter kabul edildi.
11. **Efor tahminlerinin tamamı (Bölüm 4.1)** mühendislik yargısıdır, hiçbir kaynakta yer almamaktadır.

---

### 6. KAYNAKLAR

**Kani**
- [github.com/model-checking/kani](https://github.com/model-checking/kani) — erişim 2026-09-08
- [github.com/model-checking/kani/releases.atom](https://github.com/model-checking/kani/releases.atom) — erişim 2026-09-08
- [crates.io/api/v1/crates/kani-verifier](https://crates.io/api/v1/crates/kani-verifier) — erişim 2026-09-08
- [arxiv.org/abs/2607.01504](https://arxiv.org/abs/2607.01504) / [html](https://arxiv.org/html/2607.01504v1) — "Kani: A Model Checker for Rust", ASE 2026, 2026-07-01
- [model-checking.github.io/kani/](https://model-checking.github.io/kani/) — erişim 2026-09-08
- [rust-feature-support.html](https://model-checking.github.io/kani/rust-feature-support.html) · [limitations.html](https://model-checking.github.io/kani/limitations.html) · [undefined-behaviour.html](https://model-checking.github.io/kani/undefined-behaviour.html) · [tool-comparison.html](https://model-checking.github.io/kani/tool-comparison.html) · [install-guide.html](https://model-checking.github.io/kani/install-guide.html) · [tutorial-loop-unwinding.html](https://model-checking.github.io/kani/tutorial-loop-unwinding.html) · [contracts](https://model-checking.github.io/kani/reference/experimental/contracts.html) · [autoharness](https://model-checking.github.io/kani/reference/experimental/autoharness.html) — erişim 2026-09-08
- [model-checking.github.io/kani-verifier-blog](https://model-checking.github.io/kani-verifier-blog/) — son yazı 2024-12-10
- [github.com/model-checking/kani-github-action](https://github.com/model-checking/kani-github-action) — erişim 2026-09-08
- [aws.github.io/s2n-quic/dev-guide/kani.html](https://aws.github.io/s2n-quic/dev-guide/kani.html)

**verify-rust-std**
- [github.com/model-checking/verify-rust-std](https://github.com/model-checking/verify-rust-std) · [raw README](https://raw.githubusercontent.com/model-checking/verify-rust-std/main/README.md) · [SUMMARY.md](https://raw.githubusercontent.com/model-checking/verify-rust-std/main/doc/src/SUMMARY.md) — erişim 2026-09-08
- [arxiv.org/html/2606.17374](https://arxiv.org/html/2606.17374) — "Verifying the Rust Standard Library", NFM 2026, 2026-06-16
- [arxiv.org/abs/2510.01072](https://arxiv.org/abs/2510.01072) — "Lessons Learned So Far…", 2025-10-01 / rev. 2025-10-26
- [rustfoundation.org — 2026-09-01](https://rustfoundation.org/media/how-the-rust-standard-library-verification-contest-scaled-past-manual-proof-engineering/)
- [rustfoundation.org — 2024-11-20 duyuru](https://rustfoundation.org/media/rust-foundation-collaborates-with-aws-initiative-to-verify-rust-standard-libraries/)
- [devclass.com, 2024-11-21](https://devclass.com/2024/11/21/aws-will-pay-devs-to-verify-rust-standard-library-because-of-7500-unsafe-functions-and-enormity-of-task/)
- [tools/verifast](https://model-checking.github.io/verify-rust-std/tools/verifast.html) · [tools/kmir](https://model-checking.github.io/verify-rust-std/tools/kmir.html) · [tools/flux](https://model-checking.github.io/verify-rust-std/tools/flux.html) — erişim 2026-09-08

**Verus / Creusot / Prusti / Flux / Aeneas / MIRAI**
- [github.com/verus-lang/verus](https://github.com/verus-lang/verus) · [releases.atom](https://github.com/verus-lang/verus/releases.atom) · [publications-and-projects](https://verus-lang.github.io/verus/publications-and-projects/) · [guide/overview](https://verus-lang.github.io/verus/guide/overview.html) · [guide/features](https://verus-lang.github.io/verus/guide/features.html) · [guide/guarantees](https://verus-lang.github.io/verus/guide/guarantees.html) · [guide/concurrency](https://verus-lang.github.io/verus/guide/concurrency.html) — erişim 2026-09-08
- [dl.acm.org/doi/10.1145/3694715.3695952](https://dl.acm.org/doi/10.1145/3694715.3695952) — Verus, SOSP 2024 · [dl.acm.org/doi/10.1145/3586037](https://dl.acm.org/doi/10.1145/3586037) — OOPSLA 2023
- [pldi26.sigplan.org — VerusBelt](https://pldi26.sigplan.org/details/pldi-2026-papers/82/VerusBelt-A-Semantic-Foundation-for-Verus-s-Proof-Oriented-Extensions-to-the-Rust-Ty)
- [creusot.rs](https://creusot.rs/) · [creusot releases.atom](https://github.com/creusot-rs/creusot/releases.atom) · [POPL 2026 tutorial](https://popl26.sigplan.org/details/POPL-2026-tutorials/6/Creusot-Formal-verification-of-Rust-programs) — erişim 2026-09-08
- [prusti-dev releases.atom](https://github.com/viperproject/prusti-dev/releases.atom) · [commits/master.atom](https://github.com/viperproject/prusti-dev/commits/master.atom) · [pm.inf.ethz.ch/research/prusti.html](https://www.pm.inf.ethz.ch/research/prusti.html) — erişim 2026-09-08
- [flux-rs.github.io/flux](https://flux-rs.github.io/flux/index.html) · [flux commits/main.atom](https://github.com/flux-rs/flux/commits/main.atom) · [arXiv 2207.04034](https://arxiv.org/abs/2207.04034) · [dl.acm.org/doi/10.1145/3591283](https://dl.acm.org/doi/10.1145/3591283) · [UCSC kolokyum, 2025-11-19](https://events.ucsc.edu/event/cse-colloquium-flux-refinement-types-for-verified-rust-systems/)
- [github.com/AeneasVerif/aeneas](https://github.com/AeneasVerif/aeneas) · [commits/main.atom](https://github.com/AeneasVerif/aeneas/commits/main.atom) · [lean-lang.org/use-cases/aeneas](https://lean-lang.org/use-cases/aeneas/) · [github.com/cryspen/hax](https://github.com/cryspen/hax) · [github.com/cryspen/libcrux](https://github.com/cryspen/libcrux) — erişim 2026-09-08
- [Microsoft Research, 2026-07-13 — SymCrypt](https://www.microsoft.com/en-us/research/blog/verifying-rust-cryptography-in-symcrypt-from-standards-to-code/)
- [github.com/facebookexperimental/MIRAI](https://github.com/facebookexperimental/MIRAI) · [raw README](https://raw.githubusercontent.com/facebookexperimental/MIRAI/main/README.md) · [commits/main.atom](https://github.com/facebookexperimental/MIRAI/commits/main.atom) — erişim 2026-09-08
- [arxiv.org/html/2410.01981v1](https://arxiv.org/html/2410.01981v1) — "Surveying the Rust Verification Landscape", 2024-10-02
- [rust-formal-methods.github.io](https://rust-formal-methods.github.io/) — erişim 2026-09-08
- [gitlab.mpi-sws.org/lgaeher/refinedrust-dev](https://gitlab.mpi-sws.org/lgaeher/refinedrust-dev) · [github.com/formal-land/coq-of-rust](https://github.com/formal-land/coq-of-rust)

**Miri / Loom / Shuttle / fuzzing / sanitizer**
- [research.ralfj.de/papers/2026-popl-miri.pdf](https://research.ralfj.de/papers/2026-popl-miri.pdf) · [plf.inf.ethz.ch/research/popl26-miri.html](https://plf.inf.ethz.ch/research/popl26-miri.html) · [dl.acm.org/doi/10.1145/3776690](https://dl.acm.org/doi/10.1145/3776690) — POPL 2026
- [Miri README](https://raw.githubusercontent.com/rust-lang/miri/master/README.md) — erişim 2026-09-08
- [docs.rs/loom](https://docs.rs/loom/latest/loom/) · [crates.io/api/v1/crates/loom](https://crates.io/api/v1/crates/loom) · [loom commits/master.atom](https://github.com/tokio-rs/loom/commits/master.atom) — erişim 2026-09-08
- [github.com/awslabs/shuttle](https://github.com/awslabs/shuttle) · [crates.io/api/v1/crates/shuttle](https://crates.io/api/v1/crates/shuttle) — erişim 2026-09-08
- [crates.io/api/v1/crates/cargo-fuzz](https://crates.io/api/v1/crates/cargo-fuzz) · [proptest](https://crates.io/api/v1/crates/proptest) · [bolero](https://crates.io/api/v1/crates/bolero) · [subtle](https://crates.io/api/v1/crates/subtle) — erişim 2026-09-08
- [doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html) — erişim 2026-09-08

**IdP'ye özgü**
- [github.com/cedar-policy/cedar-spec](https://github.com/cedar-policy/cedar-spec) · [raw README](https://raw.githubusercontent.com/cedar-policy/cedar-spec/main/README.md) · [commits/main.atom](https://github.com/cedar-policy/cedar-spec/commits/main.atom) — erişim 2026-09-08
- [amazon.science — Cedar, OOPSLA 2024](https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization) · [amazon.science blog, 2023-05-10](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [arxiv.org/abs/1601.01229](https://arxiv.org/abs/1601.01229) — Fett/Küsters/Schmitz, OAuth 2.0 formel analizi, CCS 2016
- [github.com/rustls/rustls SECURITY.md](https://github.com/rustls/rustls/blob/main/SECURITY.md) — erişim 2026-09-08
- [github.com/awslabs/aws-lc-verification](https://github.com/awslabs/aws-lc-verification) — erişim 2026-09-08
- [github.com/stateright/stateright](https://github.com/stateright/stateright) — erişim 2026-09-08


---

## AWS Cedar + Lean 4 "Verification-Guided Development" ve AWS Uygulamalı Formel Metotlar Portföyü

**Rapor tarihi:** 8 Eylül 2026
**Bağlam:** Rust ile sıfırdan yazılan, Keycloak sınıfı bir kimlik sağlayıcı (IdP) olan "Argus" için Cedar/Lean yaklaşımının tekrarlanabilirliği.

> **Metodoloji notu:** Aşağıdaki nicel verilerin bir kısmı yayınlardan, bir kısmı ise `cedar-spec` deposunun **4 Eylül 2026 tarihli commit'i `3a19359`** üzerinde tarafımca yapılan doğrudan ölçümlerden gelmektedir. Ölçümle elde edilenler açıkça "[ölçüm]" olarak işaretlenmiştir. Doğrulayamadığım her şey **"DOĞRULANAMADI"** etiketi taşır.

---

### BÖLÜM 1: CEDAR YETKİLENDİRME DİLİ

#### 1.1 OOPSLA 2024 Makalesi

**Künye:** "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization", *Proceedings of the ACM on Programming Languages*, Vol. 8, OOPSLA1, Article 118, Nisan 2024.
- arXiv (genişletilmiş sürüm): https://arxiv.org/abs/2403.04651 — v1: 7 Mart 2024, v2: 8 Mart 2024, CC-BY 4.0
- ACM DL: https://dl.acm.org/doi/10.1145/3649835

**Yazarlar (16 kişi):** Joseph W. Cutler, Craig Disselkoen, Aaron Eline, Shaobo He, Kyle Headley, Michael Hicks, Kesha Hietala, Eleftherios Ioannidis, John Kastner, Anwar Mamat, Darin McAdams, Matt McCutchen, Neha Rungta, Emina Torlak, Andrew Wells.
(Kaynak: https://arxiv.org/abs/2403.04651, erişim 8 Eylül 2026)

**Makalenin üç ana katkı iddiası (birebir):**
> "• Design, implementation, and evaluation of Cedar... • A verified validator for Cedar, designed to accept safe policies that are translatable to SMT. • A verified symbolic compiler for reducing Cedar to a decidable fragment of SMT."
(Kaynak: arXiv:2403.04651 PDF, tarafımca metin çıkarımı, 8 Eylül 2026)

#### 1.2 Tasarım Kararları — Neden Turing-Complete Değil?

Cedar bilinçli olarak ifade gücünü kısıtlar:
- **Genel özyineleme (recursion) ve sınırsız döngü yok.** Sadece doğrusal-zamanlı döngü yapıları.
- **Kullanıcı tanımlı fonksiyon yok.** Sadece yerleşik operatörler.
- **Yan etki yok.**

Makalenin birebir ifadesi:
> "The third aspect of safety is that Cedar's authorizer is deterministic: It is guaranteed to terminate and always produce the same authorization decision for a given request, hierarchy, and set of policies. Because Cedar policies are free of side effects and general loops, policy evaluation order doesn't matter."
(arXiv:2403.04651, metin çıkarımı, 8 Eylül 2026)

**Neden Datalog/Rego değil (birebir alıntı):**
> "Open Policy Agent (OPA) is an open source authorization system that uses a Datalog-based language called Rego. Rego, like other Datalog-based languages, is **more expressive than Cedar**, allowing users to define their own notions of evidence prioritization and combination, and data hierarchy."
(arXiv:2403.04651, metin çıkarımı, 8 Eylül 2026)

Yani AWS'nin argümanı "Rego yetersiz" değil, tam tersi: **Rego fazla ifade gücüne sahip olduğu için sağlam (sound) ve tam (complete) bir SMT kodlaması yapılamıyor.** Cedar bilinçli olarak ifade gücünü feda edip analiz edilebilirliği satın alıyor.

**XACML üzerine ilgili tespit:** Makale, Hughes ve Bultan'ın XACML alt kümesini SAT'a çeviren çalışması için "Their encoding is neither sound nor complete" diyor — Cedar'ın farkı tam da budur.

**Neden OpenFGA/Zanzibar değil:** Cedar RBAC + ABAC + ReBAC'ı birlikte ifade edebiliyor; makale OpenFGA'nın iki örnek uygulamasını Cedar'da yeniden modelliyor.

#### 1.3 Performans Sayıları (OOPSLA 2024)

| Karşılaştırma | Sonuç |
|---|---|
| Cedar vs OpenFGA | **28.7× – 35.2× daha hızlı** |
| Cedar vs Rego (OPA) | **42.8× – 80.8× daha hızlı** |
| Policy slicing kazancı | **10.0× – 18.0× ortalama** |
| SMT analiz sorgusu (kodlama+çözme) | ortalama **75.1 ms** |

(Kaynak: arXiv:2403.04651, metin çıkarımı, 8 Eylül 2026)

#### 1.4 "Analiz Edilebilir" Fragman ve SMT Kararverilebilirliği

- Cedar politikaları **SMT-LIB'in kararverilebilir (decidable) bir fragmanına** indirgenir.
- Kodlama hem **sound (aşırı-yaklaşım)** hem **complete (alt-yaklaşım)** — yani ne yanlış alarm ne kaçırılan ihlal.
- Entity store'lar **yorumlanmamış fonksiyonlar ve sabitler** (uninterpreted functions/constants) ile kodlanır; şemaya uyan *tüm* somut store'ları temsil eder.
- Nicelleyiciler (quantifiers) kullanılmaz — bunun yerine **sonlu, ground iyi-biçimlilik kısıtları** kullanılır. Nicelleyici kullanmak kararverilebilirliği kırardı.

**Tip sistemi iki yenilik kullanır:**
1. **Singleton tipler** (`True`/`False`): ulaşılamayan dalları budayarak yanlış alarmları önler.
2. **Statik yetenekler (static capabilities)**: `resource has f` doğruysa, `resource.f` erişiminin güvenli olduğu kaydedilir.

---

### BÖLÜM 2: `cedar-spec` DEPOSU VE LEAN 4 MODELİ

**Depo:** https://github.com/cedar-policy/cedar-spec — Lisans **Apache-2.0**

#### 2.1 Depo Yapısı [ölçüm, commit `3a19359`, 4 Eylül 2026]

| Dizin | İçerik |
|---|---|
| `cedar-lean/` | Lean 4 formalizasyonu ve ispatlar |
| `cedar-drt/` | Fuzzing, property-based testing, differential testing |
| `cedar-lean-ffi/` | **Rust ↔ Lean FFI köprüsü** |
| `cedar-lean-cli/` | Lean modeli üzerinde CLI |
| `cedar-policy-generators/` | `arbitrary` crate ile şema/entity/politika üreteçleri |
| `cedar-benchmarking/` | Performans ölçümü |

**Lean sürümü:** `leanprover/lean4:v4.33.1` (`lean-toolchain` dosyası, 4 Eylül 2026)

#### 2.2 GERÇEK KOD BÜYÜKLÜKLERİ [ölçüm, 4 Eylül 2026]

Bu, raporun en değerli kısmı — 2024 makalesindeki sayılar **artık ciddi ölçüde eskimiş**.

**Model (spesifikasyon) katmanı — `cedar-lean/Cedar/` altında `Thm` hariç:**

| Modül | Satır |
|---|---|
| `Cedar/Spec` (17 dosya) | 2,138 |
| `Cedar/Validation` (8 dosya) | 1,754 |
| `Cedar/Data` (6 dosya) | 994 |
| `Cedar/SymCC` (22 dosya) | 4,477 |
| `Cedar/SymCCOpt` | 999 |
| `Cedar/TPE` | 1,125 |
| `Cedar/Slice` | 73 |
| **MODEL TOPLAM** | **11,560** |

**İspat katmanı — `Cedar/Thm/` (198 dosya): 71,987 satır**

| Alt dizin | Satır |
|---|---|
| `Thm/SymCC` | 39,471 |
| `Thm/Validation` | 11,583 |
| `Thm/Data` | 7,481 |
| `Thm/TPE` | 5,555 |
| `Thm/WellTyped` | 3,413 |
| `Thm/Authorization` | 977 |
| `Thm/BatchedEvaluator` | 378 |

**Destek katmanı:** `CedarProto` + `Protobuf` 6,432 · `SymTest` 3,649 · `UnitTest` 2,481 · `CedarFFI` 1,151 · `DiffTest` 164
**`cedar-lean` altındaki tüm `.lean` dosyaları: 352 dosya, 98,549 satır**

**İspat sağlığı [ölçüm]:**
- **1,772 adet `theorem`** (+ 2 `lemma`)
- **`sorry` sayısı: 0** — yani hiçbir ispat boşluğu bırakılmamış
- **`axiom` sayısı: 0** — Lean çekirdeği dışında ek aksiyom yok

> Bu iki sıfır çok önemli: ispatlar gerçekten kapalı. Birçok akademik formalizasyonda `sorry`/`admit` kalıntıları olur; burada yok.

**Oranlar [hesaplama]:**
- **İspat : Model = 71,987 : 11,560 ≈ 6.2 : 1**
- 2024 makalesindeki oran: 5,714 : 1,673 ≈ **3.4 : 1**
- Yani iki yılda hem mutlak büyüklük ~7× arttı hem de ispat yoğunluğu neredeyse iki katına çıktı (SymCC/TPE gibi ağır meta-teori eklendiği için).

> ⚠️ Not: Bir kaynak özetinde bu oran "13.4:1" olarak geçti; makalenin kendi tablosundaki sayılardan (5,714/1,673) hesapladığımda **3.4:1** çıkıyor. Kendi hesabımı esas alıyorum.

#### 2.3 LEAN'DE GERÇEKTE NELER İSPATLANIYOR — Kesin Envanter

Aşağıdaki teorem adları `cedar-spec` kaynak kodundan **birebir** alınmıştır (4 Eylül 2026).

##### A) Yetkilendirme semantiği — `Cedar/Thm/Authorization.lean`

| Lean teorem adı | Anlamı |
|---|---|
| `forbid_trumps_permit` | Bir `forbid` sağlanıyorsa istek reddedilir |
| `allowed_only_if_explicitly_permitted` | İzin ancak açık bir `permit` ile verilir |
| `default_deny` | Açıkça izin verilmemişse reddedilir |
| `allowed_iff_explicitly_permitted_and_not_denied` | İzin ⟺ permit var ∧ forbid yok |
| `denied_iff_explicitly_denied_or_not_permitted` | Ret ⟺ forbid var ∨ permit yok |
| `order_and_dup_independent` | Politika **sırası ve tekrarları** kararı değiştirmez |
| `unchanged_allow_when_add_permit` | Yeni `permit` eklemek mevcut `allow`'u bozmaz |
| `unchanged_deny_when_add_forbid` | Yeni `forbid` eklemek mevcut `deny`'ı bozmaz |

##### B) Politika dilimleme (slicing) — `Cedar/Thm/PolicySlice.lean`

- `isAuthorized_eq_for_sound_policy_slice` — sağlam bir dilim, tam küme ile **aynı** kararı verir
- `sound_bound_analysis_produces_sound_slices`
- `scope_bound_is_sound`, `scope_analysis_is_sound`
- `isAuthorized_eq_for_scope_based_policy_slice`

Bu, Argus için doğrudan önemli: **indeksleme/önbellekleme optimizasyonunun kararı değiştirmediği ispatlanmış.**

##### C) Tip denetleyici sağlamlığı — `Cedar/Thm/Typechecking.lean`

**Burada çok kritik bir nüans var.** Teoremin doküman yorumu birebir şöyle:

> "If typechecking succeeds, then for any request consistent with the schema, either (1) evaluation produces a boolean or (2) it returns an error of type `entityDoesNotExist`, `extensionError`, or `arithBoundsError`. Both options are encoded in the `EvaluatesTo` predicate. **The type checker cannot protect against these errors** because it has no knowledge of the entities/context that will be provided at authorization time, and it does not reason about the semantics of arithmetic operators."

```lean
theorem typecheck_is_sound (policy : Policy) (env : TypeEnv) (t : CedarType)
    (request : Request) (entities : Entities) :
  InstanceOfWellFormedEnvironment request entities env →
  typecheck policy env = .ok t →
  (∃ (b : Bool), EvaluatesTo policy.toExpr request entities b)
```

> **Argus için uyarı:** "Validator geçtiyse hiç hata olmaz" **YANLIŞ** bir okumadır. Doğrusu: "tip hatası olmaz; ama `entityDoesNotExist`, `extensionError` (ör. hatalı IP/decimal), `arithBoundsError` (tamsayı taşması) hâlâ olabilir." Bu üç hata sınıfı runtime'da yönetilmek zorunda.

##### D) Seviye tabanlı entity dilimleme — `Cedar/Thm/Validation/Levels.lean`

> "If an expression is well-typed and does not exceed a maximum entity dereference level *n*, then, for any set of entities, the result of evaluating the expression with entities sliced at level *n* is the same as evaluating the expression with the original set of entities."

Pratik anlamı: bir IdP'de **veritabanından kaç seviye entity çekmeniz gerektiğini** statik olarak sınırlayabilir ve bunun kararı değiştirmediğini bilirsiniz. Argus için doğrudan uygulanabilir bir fikir.

##### E) Sembolik derleme — `Cedar/Thm/SymbolicCompilation.lean`

- `compile_is_sound`, `compile_is_complete`
- `isAuthorized_is_sound`, `isAuthorized_is_complete`
- `compile_well_typed` — iyi-tipli ifadeler daima başarıyla derlenir

##### F) Analiz doğruluğu — `Cedar/Thm/Verification.lean`

Her biri için **hem sound hem complete** teoremi mevcut:
`verifyNeverErrors`, `verifyAlwaysMatches`, `verifyNeverMatches` (+ `'` ile biten alternatif formülasyonlar)

##### G) Tip-farkında kısmi değerlendirme (TPE) — `Cedar/Thm/TPE.lean`

- `reauthorize_is_sound` — residual politikaların yeniden yetkilendirilmesi sağlam
- `partial_authorize_decision_is_sound`
- `partial_re_authorize_decision_eq`
- `partial_authorize_erroring_policies_is_sound`
- `partial_authorize_allow_determining_policies_is_sound`
- `partial_authorize_satisfied_permits_not_determining_if_deny`
- `partial_authorize_satisfied_forbid_is_determining`

TPE, RFC 0095 ile tanımlanmıştır: https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md

##### H) Sonlanma (Termination)

Lean'de tüm fonksiyonlar toplam (total) olmak zorundadır; dolayısıyla **sonlanma, modelin Lean'de tip denetiminden geçmesiyle otomatik olarak elde edilir** — ayrı bir teorem değildir. Bu, Lean seçiminin "bedava" kazanımlarından biridir.

##### 2024 makalesinin özetlediği 7 özellik

"How We Built Cedar" (https://arxiv.org/abs/2407.01688, 1 Temmuz 2024) şu 7'yi listeler: Forbid Trumps Permit, Default Deny, Explicit Allow, Order Independence, Sound Slicing, Validation Soundness, Termination. Makale, **validation soundness**'ı "şimdiye kadarki en zahmetli ispat" (*the most involved proof*) olarak niteler.

---

### BÖLÜM 3: DIFFERENTIAL RANDOM TESTING (DRT) — MİMARİ VE GERÇEK GARANTİ

#### 3.1 Rust, Lean'den ÜRETİLMİYOR

Bu sorunun net cevabı: **Rust kodu elle yazılmıştır, Lean'den extract edilmemiştir.**

Mike Hicks (AWS Senior Principal Scientist), Amazon Science blogu, **10 Mayıs 2023**:
> "the Dafny model for the authorizer has about one-sixth as many lines of code" — modeller **referans spesifikasyondur**, üretim kodu elle Rust'ta yazılmıştır.
(https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)

> ⚠️ Tarihsel not: Bu blog **Dafny** dönemine aittir (Mayıs 2023). Lean'e geçiş sonradan olmuştur (bkz. §3.4).

#### 3.2 FFI Köprüsü — Teknik Gerçek [ölçüm + depo dokümanı]

`cedar-lean-ffi/README.md` (4 Eylül 2026) birebir:
> "This directory contains Rust bindings for interacting with the Lean formalization of Cedar... This FFI makes use of Cedar's **Protobuf feature** to convert Cedar types in Rust to the corresponding type within the Lean formalization."

**Mekanizma zinciri:**

1. **Lean tarafı — `@[export]` ile C sembolleri.** `CedarFFI` modülü (1,151 satır Lean) fonksiyonları C ABI'ye açar. Ölçülen giriş noktaları:
   ```
   @[export isAuthorized]        unsafe def isAuthorizedFFI (req: ByteArray) : String
   @[export validate]            unsafe def validateReqFFI (req : ByteArray) : String
   @[export levelValidate]       unsafe def levelValidateFFI (req : ByteArray) : String
   @[export checkEvaluate]       unsafe def checkEvaluateFFI (req : ByteArray) : String
   @[export validateEntities]    unsafe def validateEntitiesFFI (req : ByteArray) : String
   @[export validateRequest]     unsafe def validateRequestFFI (req : ByteArray) : String
   @[export loadProtobufSchema]  unsafe def loadProtobufSchema (req: ByteArray) : Except String Schema
   @[export runCheckAsserts]     ...  @[export runCheckNeverErrors] ...
   ```
   İmza deseni dikkat çekici: **`ByteArray → String`**. Yani sınırdan zengin tip değil, **serileştirilmiş bayt** geçiyor.

2. **Lean statik kütüphane olarak derleniyor** — `cedar-lean-ffi/build_lean_lib.sh` birebir:
   ```bash
   cd ../cedar-lean/
   lake update
   lake build Cedar:static Protobuf:static CedarProto:static \
              Cedar.SymCC:static CedarFFI:static Batteries:static
   ```

3. **Rust tarafı — `unsafe extern "C"` + `libleanshared.so`.** Ölçülen dosyalar:
   - `cedar-lean-ffi/src/lean_ffi.rs:56` → `unsafe extern "C" { ... }`
   - `lean_ffi.rs:39-40` → `lean_initialize_runtime_module_locked`, `lean_initialize_thread`, `lean_io_mark_end_initialization`, `lean_io_mk_world`, `lean_dec`, `lean_finalize_thread`
   - `cedar-lean-ffi/build.rs:52-55` → `cargo:rustc-link-search=native=...` (Lean build dizini + Batteries paketi)
   - `lean_object.rs` → `lean_object` işaretçileri üzerinde tip-güvenli sarmalayıcılar

4. **Sınırdaki veri formatı: Protobuf.** `protoc` v29.3 ile test edilmiş. Rust `cedar-policy` crate'inin `protobufs` feature'ı kullanılıyor; `prost = "0.14"`.

5. **Çalışma zamanı:** `libleanshared.so` yüklenmeli (`source set_env_vars.sh`).

**Özet mimari:**
```
Rust fuzz target (libfuzzer)
   ├─→ cedar-policy (üretim Rust)             ─┐
   └─→ cedar-lean-ffi                          ├─→ çıktılar karşılaştırılır
         ├ Cedar tipleri → Protobuf (prost)    │
         ├ extern "C" → @[export] Lean fn      │
         ├ libleanshared.so + Lean statik libs │
         └ Lean modeli (referans semantik)    ─┘
```

#### 3.3 Fuzzing Altyapısı [ölçüm]

- **79 fuzz hedefi** (`cedar-drt/fuzz/fuzz_targets/`)
- Motor: **`libfuzzer-sys = "0.4"`** + `cargo-fuzz` (`[package.metadata] cargo-fuzz = true`)
- Girdi üretimi: **`arbitrary` crate** (`cedar-policy-core` `arbitrary` feature'ı ile)
- **`bolero` KULLANILMIYOR** — depoda hiçbir `Cargo.toml`'da `bolero` geçmiyor [ölçüm: 0 eşleşme]. Görevde geçen "bolero" varsayımı yanlıştır.

**Hedef kategorileri (örnekler):**
- *DRT (model ↔ Rust):* `abac-type-directed`, `rbac-authorizer`, `eval-type-directed`, `validation-drt`, `level-validation-drt`, `entity-slicing-drt-type-directed`, `batched-evaluation-drt`, `tpe-is-authorized-drt`, `tpe-residual-reauthorize-drt`
- *SymCC DRT (~20 hedef):* `symcc-term-drt-equivalent`, `symcc-term-drt-implies`, `symcc-term-drt-disjoint`, `symcc-term-drt-never-errors`, `symcc-cex-drt`, `symcc-smt-script-drt`, `symcc-check-*-ok`
- *Round-trip PBT:* `roundtrip`, `formatter`, `policy-set-roundtrip`, `schema-roundtrip`, `json-schema-roundtrip`, `protobuf-roundtrip`, `pst-ast-roundtrip`
- *Genel PBT:* `simple-parser`, `wildcard-matching`, `entity-validation`, `request-validation`, `input-generation`

**Çalıştırma ölçeği** (arXiv:2407.01688, 1 Temmuz 2024):
- AWS ECS üzerinde **günlük**, desteklenen tüm Cedar sürümleri için
- Hedef başına **4 vCPU, 8 GB bellek, 6 saat**
- Amazon Science blogu (10 Mayıs 2023): gecelik yaklaşık **100 milyon test**

**Performans:** Lean yetkilendiricinin medyan süresi **6 µs**, Rust'ın **10 µs** (arXiv:2407.01688). AWS blogu (8 Nisan 2024) 5 µs vs 7 µs veriyor. Lean modelinin **üretim kodundan hızlı** olması DRT'yi ekonomik kılan kritik faktördür.

#### 3.4 Dafny → Lean Göçü

**RFC 0032:** https://github.com/cedar-policy/rfcs/blob/main/text/0032-port-formalization-to-lean.md
- Başlangıç: 12 Ekim 2023 · Kabul: 24 Ekim 2023 · İniş: 26 Ekim 2023
- Dafny formalizasyonu **8 Mart 2024**'te `cedar-spec` v3.1.0 ile kullanımdan kaldırıldı
- Gerekçe (birebir): *"proving Cedar's meta-theoretic properties (such as validator soundness) is less suited for Dafny's automation"* — meta-teori için **etkileşimli** kanıtlayıcı gerekiyordu
- Kabul edilen bedel: *"We will need to support both Dafny and Lean proofs for a period of time"*

**Lean'in seçilme nedenleri** (AWS blogu, 8 Nisan 2024): (1) hızlı çalışma zamanı → DRT mümkün, (2) zengin kütüphaneler (Batteries/Mathlib), (3) **küçük güvenilir hesaplama tabanı (TCB)**.

#### 3.5 GERÇEK GARANTİ NEDİR? (Dürüst Değerlendirme)

Bu, Argus kararınız için en kritik paragraf.

**Kanıtlanan:** Lean modeli §2.3'teki özellikleri sağlar. Bu **matematiksel kesinliktir** (sorry=0, axiom=0).

**Kanıtlanmayan:** Rust üretim kodunun Lean modeline eşdeğerliği. Bu **yalnızca test edilir** — milyonlarca rastgele girdiyle, ama test testtir.

Yani zincir şudur:
```
[Lean modeli] --İSPAT (kesin)--> [güvenlik özellikleri]
      ↑
      | DRT (olasılıksal, ispat DEĞİL)
      ↓
[Rust üretim kodu] --> gerçekte çalışan şey
```

Makalenin kendi dürüst itirafı — **kaçırılan 10 hata** belgelenmiş (arXiv:2407.01688):
- Validator'da **sonlanmama (non-termination)** — tetiklenme olasılığı çok düşük olduğu için fuzzer bulamadı
- Bozuk girdide parser çökmeleri — üreteç sınırlaması
- Şema parser'ının geçersiz öznitelik kabul etmesi

Ayrıca kapsama tuzağı: ilk turda üretilen koşulların **%35.5'i önemsiz boolean sabitiydi**; makale *"complete line coverage alone does not guarantee effective testing"* diyor.

**Bulunan hatalar (toplam 25):** 4'ü ispat sırasında, 21'i DRT/PBT ile (6 authorizer parity, 4 validator parity, 6 parser roundtrip, 2 formatter roundtrip, 3 validation soundness).

> **Argus için çıkarım:** VGD, "kod doğrulanmıştır" demez. "**Tasarım** doğrulanmıştır, **uygulama** çok yoğun differential test edilmiştir" der. Bu, hiç yapmamaktan kat kat iyidir ama Verus/Kani ile Rust'ın *kendisini* doğrulamaktan farklıdır.

---

### BÖLÜM 4: SEMBOLİK DERLEYİCİ VE 2025-2026 TAKİPLERİ

#### 4.1 Cedar Analysis Açık Kaynak Sürümü

**AWS Open Source Blog, 16 Haziran 2025**, yazarlar Spencer Erickson ve Liana Hadarean:
https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/

- **Cedar Symbolic Compiler** + **Cedar Analysis CLI** yayımlandı
- SMT çözücü: **cvc5**
- Lean'de sound + complete ispatlı

#### 4.2 `cedar-policy-symcc` Crate'i (2026 durumu)

crates.io API'den (8 Eylül 2026):

| Alan | Değer |
|---|---|
| Açıklama | "Symbolic Cedar Compiler (SymCC): translates queries about Cedar policies to SMT" |
| Lisans | **Apache-2.0** |
| En yeni sürüm | **0.6.0** (28 Temmuz 2026) |
| İlk sürüm | 0.1.0 (10 Kasım 2025) |
| Toplam indirme | 97,864 |

**Sunulan analizler** (docs.rs, 8 Eylül 2026): `never errors`, `always allows`, `always denies`, `implies` (subsumption), `equivalent`, `disjoint` — her birinin **karşı-örnek (counterexample)** varyantı ile.
**Gereksinim:** `cvc5-1.3.1`, `CVC5` ortam değişkeni.

#### 4.3 SymCert — FMCAD 2026 (EN GÜNCEL VE EN ÖNEMLİ)

**Künye:** Emina Torlak (AWS), "SymCert: Verifying SMT-Based Policy Analyses", *Formal Methods in Computer-Aided Design (FMCAD) 2026*.
PDF: https://cdn.amazon.science/9f/c9/5d18658a41c48628b686493aa327/scipub-approval152134-46496997-symcert-verifying-smtbased-policy-analyses.pdf
Sayfa: https://www.amazon.science/publications/symcert-verifying-smt-based-policy-analyses
(Tam metin tarafımca çıkarıldı, 8 Eylül 2026)

**Problem (birebir):**
> "building these analyses is error-prone: subtle encoding mistakes can silently compromise soundness or completeness, and are hard to catch through testing alone."

**Dört doğrulanmış yapı taşı:** symbolic compiler · symbolic authorizer · hierarchy enforcer · **counterexample extractor** (sonsuz SMT modellerini sonlu Cedar girdilerine çevirir — *completeness* ispatı için şart).

**Modüler ispat yaklaşımı — Argus için en aktarılabilir fikir:**

Ana teorem (Theorem 1, derleyici doğruluğu) **iki genel özelliğe** ayrıştırılıyor:
- **Reducibility** (Theorem 2): derleyici literal girdileri kısmi değerlendirir
- **Interpretability** (Theorem 3): derleme, SMT değerlendirmesiyle **yer değiştirir** (commutes)

Sonuç (birebir):
> "Together, interpretability and reducibility give compiler correctness for free. **Our Lean proof of Theorem 1 is 4 lines of code.**"

Bu neden işe yarıyor:
> "Interpretability and reducibility both hold because all SymCert components build terms exclusively through **factory functions**, and each factory function is individually interpretable and reducible."

**Dafny'den alınan ders (birebir, çok değerli):**
> "We initially attempted this approach in Dafny, producing roughly **8,000 lines of proof** for a subset of Cedar. The resulting proof was **fragile, difficult to maintain**, and its lemmas **could not be reused**... because they were closely tied to the statement of Theorem 1."

**SymCert geliştirme metrikleri (TABLE I) — altın veri:**

| Bileşen | Model LOC | Model saat | İspat LOC | İspat saat |
|---|---|---|---|---|
| Terms & factories | 1,059 | — | 10,018 | — |
| Compiler | 318 | 81 | 6,520 | 327 |
| Authorizer | 16 | 1 | 411 | 11 |
| Enforcer | 69 | 16 | — | — |
| Extractor | 211 | 13 | 4,798 | 167 |
| Solver (**trusted**, ispatsız) | 566 | 47 | 0 | 0 |
| **TOPLAM** | **2,239** | **158** | **21,747** | **505** |

> ⚠️ Bazı satır-içi hücreler PDF metin çıkarımında birleşti; **toplamlar kesindir** ve alt bileşenlerle tutarlıdır.

**Hesaplanan oranlar:**
- İspat : Model **LOC** oranı = 21,747 / 2,239 ≈ **9.7 : 1**
- İspat : Model **saat** oranı = 505 / 158 ≈ **3.2 : 1**
- **Toplam çaba: 663 kişi-saat ≈ 83 kişi-gün ≈ 4 kişi-ay** (tek bir alt sistem için!)

**Bakım/genişletme maliyeti (TABLE II ve metin):**
- Beş analizi (`verifyDeniesAll`, `verifyAllowsAll`, `verifyImplies`, `verifyEquiv`, `verifyDisjoint`) modelleyip ispatlamak: model **39 LOC / <1 saat**, ispat **512 LOC / 7 saat** → *"took just one work day"*
- Üç büyük yeni Cedar özelliği için genişletme: **her biri 4–8 gün**

**Performans (TABLE III, 8 benchmark):** sorgu üretimi **<20 ms**, çözüm **<40 ms**; 8 benchmark'ın **3'ünde gerçek politika yazım hatası** bulundu (DocumentCloud 2, SalesOrgs 2, TinyTodo 2).

> **Argus için en önemli ders:** Modüler ispat mimarisi (factory functions + reducibility/interpretability) **ispat maliyetini 3-4 katına kadar düşürüyor** ve bakımı mümkün kılıyor. Dafny'deki monolitik deneme 8,000 satırda kırılgan kaldı; Lean'deki modüler yaklaşım 4 satırlık ana teoreme indi. Bu, "hangi araç" sorusundan çok **"ispatı nasıl ayrıştırdığınız"** sorusunun kritik olduğunu gösteriyor.

#### 4.4 Diğer 2026 AWS Automated Reasoning Yayınları

Amazon Science automated-reasoning etiketinden (erişim 8 Eylül 2026):
- **ControlsDSL: A Language for Verifiable Cloud Configuration Controls** — ASE 2026 (Basu, Delgado, Filieri, Gacek, Joosten, Porncharoenwase, Razavi, Rungta)
- **IAM Policy Autopilot: Static Analysis for Policy Generation from Application Code** — ASE 2026 (Filieri, Rungta, Schlaipfer, Tanuku)
- **Kani: A Model Checker for Rust** — ASE 2026 (Delmas, Hassan, Hu, Kumar, Monteiro, Tautschnig)
- **SymCert** — FMCAD 2026

> Dikkat: **ControlsDSL**, Cedar mantığının (analiz edilebilir DSL) IAM dışı alanlara yayıldığını gösteriyor — AWS'nin bunu tekrarlanabilir bir *desen* olarak gördüğünün kanıtı.

#### 4.5 Cedar'ın Kurumsal Durumu

**CNCF Sandbox'a kabul: 15 Aralık 2025**, Lara Langdon (AWS Applied Science Manager):
https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project/

- **Üretimdeki kullanıcılar:** Cloudflare, MongoDB, StrongDM, Cloudinary, AWS servisleri (Bedrock AgentCore Policy, Systems Manager)
- Linux Foundation **Janssen Project** entegrasyonu (⚠️ Janssen bir OpenID/IdP projesidir — Argus için doğrudan emsal!)
- Yol haritası: Sandbox → Incubation → Graduated

**cedar-policy org'daki 23 depo** arasında dikkat çekenler (erişim 8 Eylül 2026): `cedar` (Rust), `cedar-spec` (Lean), `cedar-go` (Go implementasyonu), `cedar-java`, `cedar-language-server`, `cedar-access-control-for-k8s`, `cedar-for-agents`, ve **`cedar-json-parser` — "A JSON parser verified in Verus"**.

> ⚠️ **DOĞRULANAMADI:** `cedar-json-parser` deposunun README'sini çekemedim (main ve master dallarında 404 döndü). Sadece organizasyon listesindeki açıklamayı gördüm. Ancak bu bile önemli bir sinyal: **AWS, Rust kodunun kendisini Verus ile doğrulamayı deniyor** — yani DRT'nin ötesine geçme girişimi var.

---

### BÖLÜM 5: MALİYET, ÇABA VE TEKRARLANABİLİRLİK

#### 5.1 Bilinen Çaba Rakamları

| Kalem | Değer | Kaynak |
|---|---|---|
| Validator soundness ispatı | **18 kişi-günü** | AWS blogu, 8 Nisan 2024 |
| SymCert toplam | **663 kişi-saat ≈ 4 kişi-ay** | FMCAD 2026, TABLE I |
| SymCert: 5 analizi ispatlama | **1 iş günü** | FMCAD 2026 |
| SymCert: yeni dil özelliği entegrasyonu | **4–8 gün / özellik** | FMCAD 2026 |
| Tüm ispatların doğrulanması (CI) | **~185 saniye** (Rust derlemesi 45 sn) | AWS blogu, 8 Nisan 2024 |
| Dafny'deki başarısız monolitik deneme | 8,000 satır, kırılgan | FMCAD 2026 |

**2024 makalesindeki kod büyüklükleri** (arXiv:2407.01688):

| Bileşen | Lean model | Lean ispat | Rust üretim | Rust test |
|---|---|---|---|---|
| Custom sets/maps | 244 | 681 | — | — |
| Parser | — | — | 4,114 | 3,599 |
| Evaluator/Authorizer | 897 | 347 | 4,877 | 7,061 |
| Validator | 532 | 4,686 | 6,702 | 9,798 |
| **Toplam** | **1,673** | **5,714** | **15,693** | **20,458** (+31,391 diğer) |

AWS blogu (8 Nisan 2024) üretim Rust'ı **24,915 satır** olarak veriyor — makale tablosuyla kapsam farkı var; ikisini de bilginize sunuyorum.

#### 5.2 DOĞRULANAMAYANLAR

- ❌ **Cedar ekibinin büyüklüğü ve toplam kişi-ay maliyeti.** arXiv:2407.01688 açıkça personel verisi vermiyor. OOPSLA makalesinin 16 yazarı olması bir üst sınır ipucu ama kanıt değil.
- ❌ **AWS'nin resmi "ispat:kod çaba oranı" açıklaması.** Böyle bir genel beyan bulamadım. Elimizdeki tek sağlam oran SymCert'in **3.2:1 saat** ve **9.7:1 LOC** oranı, ve validator için 18 kişi-günü.
- ❌ **IonSpec** — bu isimle bir AWS deposu/yayını bulamadım (`awslabs/ion-spec` ve `amazon-ion/ion-spec` 404). Yanlış isim olabilir veya dahili olabilir.

#### 5.3 Tekrarlanabilir mi? — Değerlendirmem

**EVET, ama koşullu.** Lehte kanıtlar:

1. **Tüm araç zinciri açık ve ücretsiz:** Lean 4 (Apache-2.0), cedar-spec (Apache-2.0), cvc5, cargo-fuzz, `arbitrary`. Hiçbir tescilli araç yok.
2. **Referans mimari kopyalanabilir durumda:** `cedar-lean-ffi` tam bir şablon — `@[export]` + Protobuf + `extern "C"` + statik linkleme. Bunu okuyup uyarlayabilirsiniz.
3. **Marjinal maliyet düşük:** SymCert kanıtlıyor ki *modüler kurulduktan sonra* yeni analiz **1 gün**, yeni dil özelliği **4-8 gün**.
4. **CI'da 3 dakika:** Sürdürülebilir; geliştirme hızını öldürmez.
5. **AWS bunu bir kez değil, tekrar tekrar yaptı:** Cedar → SymCC → SymCert → ControlsDSL. Desen olgunlaşmış.

**Aleyhte / maliyetli olan taraf:**

1. **Ana kurulum maliyeti yüksek.** SymCert tek başına 4 kişi-ay. Cedar'ın tamamı (11,560 model + 71,987 ispat satırı) muhtemelen **çok kişi-yılı**.
2. **Nadir beceri.** AWS blogu (8 Nisan 2024) birebir tavsiyesi: *"Lean into the curve"* — dik öğrenme eğrisini kabul edin. Emina Torlak (Rosette'in yaratıcısı) ve Michael Hicks sınıfında araştırmacılar bu işi yaptı.
3. **Dil tasarımı ispatı mümkün kılmak için kısıtlanmalı.** Cedar Turing-complete olmadığı için ispatlanabilir. Argus'un politika dili de **aynı feragatleri kabul etmeli**, yoksa ispat mümkün olmaz. Bu bir mühendislik detayı değil, **temel bir ürün kararıdır**.
4. **Süreç disiplini şart.** lean-lang.org Cedar vaka çalışması (erişim 8 Eylül 2026, https://lean-lang.org/use-cases/cedar/) birebir: *"No new Cedar version is released unless its model, proofs, and differential tests are current."* Bu kurala uymazsanız model çürür ve değersizleşir.

---

### BÖLÜM 6: AWS'NİN DİĞER FORMEL METOT ÇALIŞMALARI

#### 6.1 Zelkova — SMT ile IAM Politika Analizi

**Künye:** John Backes, Pauline Bolignano, Byron Cook, Catherine Dodge, Andrew Gacek, Kasper Luckow, Neha Rungta, Oksana Tkachuk, Carsten Varming (hepsi AWS), "Semantic-based Automated Reasoning for AWS Access Policies using SMT", **FMCAD 2018**.
PDF: https://www.cs.utexas.edu/~hunt/FMCAD/FMCAD18/papers/paper3.pdf (tam metin tarafımca çıkarıldı, 8 Eylül 2026)

**Ne yapar (birebir):**
> "ZELKOVA encodes the semantics of policies into SMT, compares behaviors, and verifies properties. It provides users a **sound mechanism** to detect misconfigurations of their policies. ZELKOVA solves a **PSPACE-complete** problem and is invoked many millions of times daily."

**SMT kodlaması:**
> "The SMT encoding uses the theory of **strings, regular expressions, bit vectors, and integer comparisons**. The use of the wildcards `*` (any number of characters) and `?` (exactly one character) in the string constraints makes the decision problem **PSPACE-complete**. However, our experience with real-world policies is that **99% of policy questions can be answered in less than 160 milliseconds**."

**Çözücü portföyü:** Z3, CVC4, ve AWS'nin kendi Z3 uzantısı **Z3AUTOMATA**. Makaledeki Fig. 8: 1 milyon UNSAT sorgusunda en hızlı olan — Z3: 965,092, CVC4: 34,908, Z3AUTOMATA: 0; 1 milyon SAT'ta — Z3: 959,543, CVC4: 39,932, Z3AUTOMATA: 525.

**Zarif tasarım kararı:**
> "The property to be verified is specified in **the policy language itself**, eliminating the need for a different specification or formalism for properties."

> **Argus için doğrudan alınabilir fikir:** Güvenlik özelliklerini ayrı bir spesifikasyon dilinde değil, **politika dilinin kendisinde** ifade ettirin. Kullanıcının öğrenmesi gereken tek dil olur.

**Dağıtım:** S3, AWS Config, Amazon Macie, Trusted Advisor, GuardDuty ve dahili AWS güvenlik denetim araçları.

**Ölçek:** "A Billion SMT Queries a Day", Neha Rungta, **CAV 2022** (davetli bildiri): beş yılda günde binlerce SMT çağrısından **günde bir milyara**.
https://www.amazon.science/publications/a-billion-smt-queries-a-day

**IAM Access Analyzer'ı nasıl besliyor:** AWS dokümanı (https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html, erişim 8 Eylül 2026) birebir: *"IAM Access Analyzer identifies resources shared with external principals by using **logic-based reasoning** to analyze the resource-based policies."*

Yetenekler: external access analyzer · internal access analyzer · unused access analyzer · policy validation · **custom policy checks** (yeni erişim veriliyor mu? belirli aksiyonlar yasak mı?) · CloudTrail'den politika üretimi.

**Zelkova NE İSPATLAMAZ:** Zelkova'nın *kendisi* bir teorem kanıtlayıcıda doğrulanmış değildir. Kodlamanın sağlamlığı makalede **argüman** edilir, makine-kontrollü değildir. İşte tam olarak bu boşluğu **SymCert 8 yıl sonra Cedar için kapatıyor** — SymCert'in var oluş sebebi budur (bkz. §4.3 giriş alıntısı: *"subtle encoding mistakes can silently compromise soundness"*).

#### 6.2 s2n / s2n-tls

**Künye:** Andrey Chudnov, Nathan Collins, Byron Cook, Joey Dodds, Brian Huffman, Colm MacCárthaigh, Stephen Magill, Eric Mertens, Eric Mullen, Serdar Tasiran, Aaron Tomb, Eddy Westbrook — **CAV 2018**, LNCS 10982, s. 430–446.
(Galois Inc. + AWS + University of Washington + UCL)
PDF: https://d1.awsstatic.com/Security/pdfs/Continuous_Formal_Verification_Of_Amazon_s2n.pdf (tam metin tarafımca çıkarıldı, 8 Eylül 2026)

**Tam olarak ne ispatlandı — üç parça:**

**1. HMAC** — katmanlı ispat mimarisi:
```
[Rastgeleden ayırt edilemezlik]  ← Coq (Beringer ve ark., FCF kütüphanesi)
          ↕ Coq ispatı (Cryptol operasyonel semantiği)
[Yüksek seviye HMAC spesifikasyonu (monolitik API)]
          ↕ Coq (manuel) + Cryptol (otomatik)
[Düşük seviye Cryptol spesifikasyonu (artımlı API)]
          ↕ SAW (çoğunlukla otomatik)
[s2n C kodu]
```
Galois'nın belirttiğine göre 103 satırlık HMAC C kodu hakkındaki akıl yürütme **3 satır Cryptol'e** indirgeniyor.

**2. DRBG** — aynı yaklaşım.

**3. TLS El Sıkışma Durum Makinesi** (birebir):
> "we have proved that (1) it implements a subset of **TLS 1.2** as defined in IETF **RFCs 5246, 5077 and 6066** and (2) the **socket corking API**, which optimizes how data is split into packets, is used correctly. Formally, we proved that the implementation **refines** a specification (conversely, the specification simulates the implementation)."

**Çaba (birebir):**
> "HMAC and DRBG each took roughly **3 months** of engineering effort. The TLS handshake verification took longer at **8 months**, though some of that time involved developing tool extensions."

**KRİTİK ÇEKİNCELER (birebir):**
- **Sınırlılık:** *"...for a set of samples, chosen to cover all branches in the code. This yields a result that is **short of full proof**, but still provides much higher state space coverage than testing methods."*
- **Derleyici bağımlılığı:** *"Internally SAW reasons about C programs by first translating them to LLVM... from a soundness perspective **the C code must be compiled through LLVM for the proofs to apply** to the compiled code."*
- **Protokol güvenliği ispatlanmadı:** RFC'lerin kendisinin güvenli olduğu **varsayılıyor**; miTLS gibi bir spesifikasyon-seviyesi güvenlik ispatıyla bağlantı gelecek çalışma olarak bırakılmış.
- s2n'in küçük olması işi mümkün kıldı: *"the implementation of s2n is small (less than 10k LOC), and most iteration is bounded."*

**Bugünkü durum [ölçüm, 8 Eylül 2026]:** `aws/s2n-tls` deposunda hem `tests/saw/` (HMAC ↔ Cryptol eşdeğerliği, Yices+Z3 ile) hem `tests/cbmc/` (**bellek güvenliği**, C Bounded Model Checker ile) mevcut ve **her pull request'te CI'da çalışıyor**.

> **Argus için ders:** Sürekli doğrulama (continuous verification) uygulanabilir — ama sadece **küçük, sınırlı-iterasyonlu, kritik** bileşenlerde. TLS el sıkışması **8 ay** aldı.

#### 6.3 AWS-LC (AWS libcrypto) Doğrulaması

**Depo:** https://github.com/awslabs/aws-lc-verification (`master` dalı, Apache-2.0)
README tam metin tarafımca çekildi, 8 Eylül 2026.

**Şu anda aktif doğrulanan algoritmalar:**

| Algoritma | Varyant | Platform | Araç | Çekinceler |
|---|---|---|---|---|
| SHA-2 | 384, 512 | SandyBridge+ | SAW | NoEngine, MemCorrect |
| SHA-2 | 384, 512 | neoverse-n1/v1 | SAW + NSym | +NoInline, ArmSpecGap, ToolGap, LaxPointer |
| HMAC | SHA-384 ile | SandyBridge+ | SAW | NoEngine, MemCorrect, InitZero, NoInline, CRYPTO_once_Correct |
| AES-KW(P) | 256 | SandyBridge+ | SAW | **InputLength**, MemCorrect, NoInline |
| AES-GCM | 256 | SandyBridge-Skylake | SAW | GcmSpecGap, **GcmMultipleOf16**, **GcmADNotVerified**, **GcmIV12Tag16**, GcmWellFoundedInduction |

> ⚠️ **ÇOK ÖNEMLİ BULGU:** README'de **ECDSA (P-384), ECDH (P-384), Elliptic Curve Keys, HKDF** satırları **HTML yorumu içine alınmış** (`<!--- ... --->`) — yani **şu anda aktif tabloda değiller**. Görevde sorulan "ECDSA/ECDH P-384 ispatlanmış mı?" sorusunun cevabı: *bir zamanlar tabloda vardı, şu anda yorum satırında.* Bunun sebebini README açıklamıyor (muhtemelen s2n-bignum'a geçişle ilgili).
>
> **Curve25519 ve RSA** bu depoda hiç listelenmiyor.

**Yeni teknik yön (README birebir):**
> "Recently, we have changed our technical approach for formal verification to use tools newer than SAW and NSym. For verification of assembly language (covering both x86_64 and AArch64 ISAs), we use the **s2n-bignum** infrastructure, which is built on the **HOL Light** theorem prover... Our production implementation of ML-KEM lies in the **mlkem-native** repository. This repo... adds proof of memory- and type-safety for the C components using the **CBMC** tool."

Yani post-kuantum (ML-KEM, ML-DSA) için: **s2n-bignum/HOL Light (assembly) + CBMC (C)**.

**Platform/derleyici bağımlılığı (birebir):**
> "In all cases, the actual verification is performed on code that is produced by **Clang**, but the verification results also apply to any compiler that produces semantically equivalent code."
Platformlar: SandyBridge+ (Clang 10), SandyBridge-Skylake (Clang 10, AVX-512 **hariç**), neoverse-n1/v1 (C için Clang 10, assembly için Clang 10/14).

**Çekince sözlüğü — Argus için "dürüst doğrulama" dersi.** README'nin bu tablosu, formel doğrulamada **ne ispatlanmadığını** açıkça listelemenin mükemmel bir örneğidir:

| Çekince | Anlamı |
|---|---|
| `InputLength` | Sadece **sınırlı sayıda girdi uzunluğu** için doğrulandı (tüm dalları kapsayacak şekilde seçildi); o uzunluklarda tüm değerler için geçerli |
| `MemCorrect` | `OPENSSL_malloc`/`free` **doğrulanmadı**, doğru varsayıldı |
| `NoEngine` | `ENGINE*` alan API'ler sadece **null** işaretçi için doğrulandı |
| `NoInline` | Belirli fonksiyonların **inline edilmediği** varsayıldı |
| `OptNone` | Belirli fonksiyonların **optimize edilmediği** varsayıldı |
| `GcmMultipleOf16` | AES-GCM sadece **16'nın katı uzunluklar** için doğrulandı |
| `GcmADNotVerified` | AES-GCM'e **ek veri (AD) verilmesi doğrulanmadı** |
| `GcmIV12Tag16` | Sadece **12 baytlık IV ve 16 baytlık tag** için |
| `GcmWellFoundedInduction` | Sınırsız döngüler için tümevarım hipotezleri **varsayıldı** (SAW iyi-temellilik denetimi yapmıyor) |
| `SAWBreakpoint` | Breakpoint özelliği iyi-temellilik denetimi **yapmıyor** |
| `ToolGap` | Bitişik bileşenler **farklı araçlarla** doğrulandı; birinin ispatının diğerinde geçerli olduğu varsayıldı |
| `ArmSpecGap` | NSym'deki Cryptol spesifikasyonu SAW'dakinden **farklı**; döngü gövdeleri doğrulandı ama **üst seviye döngü yapısı doğrulanmadı** |
| `SAWCore_Coq` | `saw-core-coq` kütüphanesinde bazı gerçekler **admit** edilmiş |
| `EC_Fiat_Crypto` | Fiat-Crypto spesifikasyonu kullanılıyor ama üretimde s2n-bignum kodu çalışıyor → **mekanizasyon boşluğu** |
| `LaxPointer` | Clang'ın ürettiği farklı allocation block'lar arası işaretçi karşılaştırmaları için SAW denetimi **kapatıldı** |

> **Argus için ders:** "Formally verified" etiketinin gerçek kıymeti, yanına konan bu tür bir çekince tablosuyla ölçülür. Argus'un güvenlik dokümanı bu README'yi model almalı.

#### 6.4 AWS Encryption SDK — Dafny Yaklaşımı

**Depolar:**
- https://github.com/aws/aws-encryption-sdk-dafny (`mainline` dalı)
- https://github.com/aws/aws-cryptographic-material-providers-library (`main` dalı)
(README'ler tarafımca çekildi, 8 Eylül 2026)

**Yaklaşım:** Kütüphane **bir kez Dafny'de yazılır ve doğrulanır**, sonra birden çok hedef dile **transpile edilir**.

Material Providers Library README birebir:
> "This library is written in **Dafny**, a formally verifiable programming language that can be compiled into different runtimes. This library is currently **ONLY** supported in **Java, .NET, Python, Rust and Go**."

Encryption SDK for Dafny README'den iş akışı:
- Doğrulama: `dotnet build -t:VerifyDafny test`
- Kod üretimi: **Smithy** modellerinden **Polymorph** / `smithy-dafny` ile
- Transpilasyon: `make transpile_net`, **`make transpile_rust`**
- Birebir: *"There is no Dafny runtime, so there is no concept of 'running the AWS Encryption SDK for Dafny'."*
- Kriptografik ilkeller **native** (Dafny'de değil) — yani doğrulama kapsamı dışında

**Dafny'nin Rust backend'i — doğrulandı [ölçüm]:** `dafny-lang/dafny` kaynağında `Source/DafnyCore/Backends/Rust/RustBackend.cs` mevcut:
```csharp
public class RustBackend : DafnyExecutableBackend {
  public override string TargetName => "Rust";
  public override bool IsStable => true;
  public override bool IsInternal => true;
  ...
}
```
`RELEASE_NOTES.md`'de "Experimental Dafny-to-Rust compiler development" ve sonrasında Rust backend iyileştirmeleri (PR #5643, #5647) görülüyor.

> ⚠️ **Tutarsızlık notu:** Çektiğim Dafny referans kılavuzu sayfası (https://dafny.org/latest/DafnyRef/DafnyRef#sec-target-backends) backend listesinde Rust'ı **saymıyor** (C#, Java, JavaScript, Go, C++ diyor). Kaynak kodu ve AWS'nin fiilen Rust'a transpile etmesi göz önüne alındığında **dokümanın eski olduğu** sonucuna varıyorum. Kaynak kodunu esas alıyorum, ama bunu bir belirsizlik olarak işaretliyorum.

> **Argus için:** Bu, Cedar'dan **tamamen farklı** bir stratejidir. Cedar: *model Lean'de + kod elle Rust'ta + DRT ile bağla.* Encryption SDK: *tek kaynak Dafny'de + Rust'a üret.* İkincisi model-kod uçurumunu **tamamen ortadan kaldırır** ama üretilen Rust'ın idiomatik olmaması ve performans bedeli vardır — Cedar ekibinin idiomatik/hızlı üretim kodu istemesi tam da bu yüzden DRT'yi seçmelerinin sebebidir.

#### 6.5 Kani — Rust Model Denetleyicisi (kısa)

**Depo:** https://github.com/model-checking/kani (erişim 8 Eylül 2026)
- **Bit-precise model checker for Rust**, CBMC tabanlı
- *Safety:* tanımsız davranış (UB) denetimi — özellikle `unsafe` bloklar için
- *Correctness:* panic, aritmetik taşma, `assert!`, **function contracts** (deneysel)
- Kurulum: `cargo install --locked kani-verifier && cargo kani setup`
- `#[kani::proof]` ile harness; `kani::any()` ile sembolik girdi
- GitHub Action mevcut: `model-checking/kani-github-action@VERSION`
- **ASE 2026 makalesi:** "Kani: A Model Checker for Rust" (Delmas, Hassan, Hu, Kumar, Monteiro, Tautschnig)

> Argus için Kani, **en düşük sürtünmeli giriş noktasıdır** — Lean öğrenmeden, mevcut Rust kodunuza `#[kani::proof]` ekleyerek başlayabilirsiniz.

#### 6.6 Bulunamayanlar

- ❌ **IonSpec** — bu isimde bir depo/yayın bulunamadı (bkz. §5.2).

---

### BÖLÜM 7: ARGUS'A AKTARILABİLİRLİK

#### 7.1 Cedar'ı Doğrudan Gömmek — Fizibilite: YÜKSEK

**`cedar-policy` crate durumu (crates.io API, 8 Eylül 2026):**

| Alan | Değer |
|---|---|
| En yeni sürüm | **4.12.0** (28 Temmuz 2026) |
| Lisans | **Apache-2.0** |
| İlk yayın | 10 Mayıs 2023 |
| Toplam indirme | **8,375,517** |
| Son dönem indirme | 2,698,101 |
| MSRV | **Rust 1.89** |
| Edition | 2021 |

**Sürüm geçmişi (son 12 ay):** 4.8.1 (25 Kas 2025) · 4.8.2 (9 Ara 2025) · 4.9.0 (9 Şub 2026) · 4.9.1 (27 Şub 2026) · 4.10.0 (23 Nis 2026) · 4.11.0 (18 May 2026) · 4.11.1 (9 Haz 2026) · 4.11.2 (22 Haz 2026) · 4.12.0 (28 Tem 2026). Ayrıca **3.4.3** (22 Haz 2026) — eski major hâlâ bakımda.

> **Olgunluk değerlendirmesi:** 3+ yıl, 8.3M indirme, ~aylık düzenli sürüm, **4.x içinde semver kararlılığı**, CNCF Sandbox, Cloudflare/MongoDB üretim kullanımı. Bir IdP'nin yetkilendirme motoru olarak gömülmesi için **fazlasıyla olgun**.

**API yüzeyi** (docs.rs, 8 Eylül 2026): `Authorizer`, `PolicySet`, `Entities`, `Request`, `Schema`, `Validator`, `Decision`, `Diagnostics`.

**Feature flag'ler:**
- Varsayılan: `ipaddr`, `decimal`, `datetime`
- Opsiyonel: `heap-profiling`, `corpus-timing`, `wasm`
- **Deneysel:** `tpe` (tip-farkında kısmi değerlendirme), `partial-eval`, `partial-validate`, `entity-manifest` (**kullanımdan kaldırıldı**, `tpe` lehine), `protobufs`, `tolerant-ast`, `extended-schema`

> ⚠️ `tolerant-ast` için doküman birebir uyarısı: *"This feature is intended only for use in language servers, and **should never be used on the authorization path**."* Argus'ta bunu asla etkinleştirmeyin.

**Lint disiplini** [ölçüm, `cedar-policy/src/lib.rs`]: `#![warn(clippy::pedantic, clippy::use_self, clippy::option_if_let_else)]` + `#![deny(missing_docs, ...)]`. Cedar dokümanı (https://docs.cedarpolicy.com/other/security.html) Rust uygulamasının **güvenli alt kümede** yazıldığını belirtiyor.
> ⚠️ **DOĞRULANAMADI:** `cedar-policy-core`'da açık bir `#![forbid(unsafe_code)]` bulamadım (grep 0 sonuç). "Sadece safe Rust" iddiası dokümantasyona dayanıyor, derleyici-zorlamalı bir bariyer olarak doğrulayamadım. Argus için: kendi kodunuzda `#![forbid(unsafe_code)]` kullanın ve bağımlılıkları `cargo-geiger` ile denetleyin.

**Cedar'ın kendi güvenlik modeli** (https://docs.cedarpolicy.com/other/security.html, erişim 8 Eylül 2026) — **paylaşılan sorumluluk**:
- ✅ Cedar sağlar: I/O yok (politikalar dosya/ağ okuyamaz), politika izolasyonu, sonlanma garantisi
- ⚠️ Argus'un sorumluluğu:
  - Politika doğruluğu (validator yardımcı olur, garanti etmez)
  - **Cedar sadece yetkilendirmedir, kimlik doğrulama DEĞİLDİR** ← bir IdP için tam olarak sizin işiniz
  - **String birleştirmeyle dinamik politika üretimi = enjeksiyon riski** ← Argus'ta politika şablonları (`Template`) kullanın, asla string concat yapmayın
  - **Değişebilir entity ID'leri (kullanıcı adı gibi) geri dönüştürülürse yetki sızıntısı** ← Argus'ta **değişmez, yeniden kullanılmayan UUID/ULID** kullanın, asla kullanıcı adı/e-posta değil
  - Girdi boyutu sınırları uygulama tarafından zorlanmalı (bellek tükenmesi)
  - Veri gizliliği/bütünlüğü uygulama katmanında

**Ek olarak alabileceğiniz:** `cedar-policy-symcc` 0.6.0 (Apache-2.0) ile Argus, yöneticilere **"bu politika değişikliği yeni erişim veriyor mu?"** sorusunu **ispatla** cevaplayan bir özellik sunabilir — Keycloak'ta karşılığı olmayan güçlü bir farklılaştırıcı. (cvc5-1.3.1 bağımlılığı gerekir.)

#### 7.2 Alternatiflerin Formel Temeli — Karşılaştırma

| Sistem | Model | Formel temel | Makine-kontrollü ispat? |
|---|---|---|---|
| **Cedar** | RBAC+ABAC+ReBAC | Lean 4 modeli, 1,772 teorem, sorry=0 · sound+complete SMT | ✅ **EVET** |
| **Zanzibar** (Google) | ReBAC | ATC 2019 makalesi; **external consistency** tanımlar | ❌ Makalede formel doğrulama/ispat yok |
| **OpenFGA** | ReBAC (Zanzibar) | Zanzibar'dan "ilham alınmış" | ❌ README'de formel/ispat iddiası yok [ölçüm] |
| **SpiceDB** | ReBAC (Zanzibar) | "en olgun açık kaynak Zanzibar" | ❌ README'de formel/ispat iddiası yok [ölçüm] |
| **OPA / Rego** | Datalog tabanlı | Cedar makalesi: Cedar'dan **daha ifadeli**, sound SMT kodlaması zor | ❌ Bilinen makine-kontrollü ispat yok |
| **Casbin** | PERM metamodeli | Konfigürasyon tabanlı model | ❌ README'de formel iddia yok [ölçüm] |
| **Oso / Polar** | Prolog benzeri | — | ⚠️ **DOĞRULANAMADI** (arama bütçesi tükendi) |

**Kanıtlar:**
- Zanzibar: https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/ (USENIX ATC 2019; Pang, Caceres, Burrows ve ark.). Özet birebir: *"Its authorization decisions respect causal ordering of user actions and thus provide **external consistency**"* — bu bir **dağıtık sistem tutarlılık** garantisidir, bir **yetkilendirme semantiği doğruluk ispatı** değildir. İkisi farklı şeylerdir.
- OpenFGA/SpiceDB/Casbin: README'lerini grep'ledim; "formal", "verif", "proof" için yetkilendirme-semantiği ispatına dair hiçbir iddia yok [ölçüm, 8 Eylül 2026].

> **Sonuç:** Yetkilendirme motoru pazarında **makine-kontrollü doğruluk ispatına sahip tek üretim-kalitesinde seçenek Cedar'dır.** Argus "en güvenli" iddiasında bulunacaksa, kendi motorunu yazmak bu iddiayı **zayıflatır** — Cedar'ı gömmek ise doğrudan güçlendirir.

#### 7.3 Bir IdP İçin "Verification-Guided Development" Oyun Kitabı

Argus'un bileşenlerini **ispat getirisi / maliyet** oranına göre sıralıyorum:

##### Katman 1 — Cedar'ı gömün, yeniden yazmayın (getiri: çok yüksek, maliyet: çok düşük)

`cedar-policy` 4.12 + `cedar-policy-symcc` 0.6 kullanın. **8.3M indirme ve 1,772 Lean teoremini bedavaya devralırsınız.** Kendi politika dilinizi yazmak, bu ispatları çöpe atmak demektir. Cedar'ın Janssen (bir OpenID projesi) tarafından entegre edilmiş olması emsal teşkil eder.

##### Katman 2 — Protokol katmanı: Cedar deseni DEĞİL, WIM deseni

Bir IdP'nin asıl saldırı yüzeyi yetkilendirme motoru değil, **OAuth 2.0 / OIDC protokol akışlarıdır.** Bu alanın kendi formel geleneği var:

- **"A Comprehensive Formal Security Analysis of OAuth 2.0"** — Daniel Fett, Ralf Küsters, Guido Schmitz. **CCS 2016**; arXiv: https://arxiv.org/abs/1601.01229 (6 Ocak 2016). Dört grant tipinin tamamı için **authorization, authentication, session integrity** ispatlanıyor. **OAuth'un güvenliğini kıran 4 saldırı** bulundu (OpenID Connect'te de mevcut).
- **"The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis and Security Guidelines"** — Fett, Küsters, Schmitz. **CSF 2017**; arXiv: https://arxiv.org/abs/1704.08539 (27 Nisan 2017). *"the first in-depth security analysis of OpenID Connect."* Aynı üç özellik ispatlanıyor + uygulayıcılar için güvenlik kılavuzu.
- **"An Extensive Formal Security Analysis of the OpenID Financial-grade API"** — Fett, Hosseyni, Küsters. **IEEE S&P 2019**; arXiv: https://arxiv.org/abs/1901.11520 (31 Ocak 2019). FAPI'de *"partly severe attacks, breaking authentication, authorization, and session integrity"* bulundu.

Hepsi **Web Infrastructure Model (WIM)** kullanıyor — DNS, HTTP(S), tarayıcı, script'ler, çerezler ve kötücül aktörleri modelleyen kapsamlı bir web modeli.

> ⚠️ **DOĞRULANAMADI:** Bu WIM ispatlarının makine-kontrollü mü yoksa elle mi yapıldığını çektiğim özetlerden **kesinleştiremedim** (özetler belirtmiyor). Genel kanaatim elle yapıldıkları yönünde ama bunu bu araştırmada doğrulayamadım — Argus için buna güveneceksiniz, tam metinlerden teyit edin.

> **Pratik tavsiye:** Bu üç makale Argus için **ispat hedefi değil, tasarım kısıtı listesi** olarak kullanılmalıdır. FAPI makalesinin bulduğu saldırılar → Argus'un regresyon test paketi. OIDC makalesinin "security guidelines for implementors" bölümü → Argus'un uygulama şartnamesi.

##### Katman 3 — Lean/Dafny modeli hak eden Argus bileşenleri

Cedar'ın *dışında* kalan, Argus'a özgü ve **durum makinesi** karakterli olan yerler:

| Bileşen | Neden modellenmeli | Önerilen araç |
|---|---|---|
| **Oturum/token yaşam döngüsü durum makinesi** (issue → refresh → rotate → revoke → expire) | s2n'in TLS durum makinesi ispatının birebir muadili. "İptal edilmiş token asla kabul edilmez", "refresh token yeniden kullanımı tüm aileyi iptal eder" gibi invaryantlar | **Lean 4** (Cedar deseni: model + DRT) |
| **Rol/grup hiyerarşisi geçişli kapanışı** | Döngü yok, ayrıcalık yükseltme yok, `in` semantiği. Cedar'ın `PolicySlice` teoremlerinin muadili | **Lean 4** |
| **Onay (consent) ve scope daraltma** | "Türetilmiş token asla ebeveyninden fazla scope içermez" — monotonluk teoremi | **Lean 4** |
| **Multi-tenant izolasyon** | "A kiracısının isteği asla B kiracısının entity'lerine erişemez" — Cedar'ın level-slicing teoreminin muadili | **Lean 4** |
| **JWT/JWS/JOSE ayrıştırıcı ve doğrulayıcı** | `alg:none`, algoritma karışıklığı, `kid` enjeksiyonu — tarihsel CVE yuvası. Cedar'ın `cedar-json-parser`'ı Verus'ta doğrulaması tam bu sebeple | **Verus** veya **Kani** (doğrudan Rust üzerinde) |
| **Parola hash'leme / sabit-zamanlı karşılaştırma** | AWS-LC deseni | **Kani** + hazır doğrulanmış kripto kütüphanesi kullan (kendin yazma) |
| **Kriptografi** | **Kendiniz yazmayın.** `aws-lc-rs` veya `ring` kullanın; AWS-LC çekince tablosunu okuyun | (dış bağımlılık) |

##### Katman 4 — Kademeli benimseme yol haritası

**Faz 0 (hafta 1-2, maliyet ~sıfır):** `cargo kani` ekleyin. Ayrıştırıcılara ve `unsafe` bloklara `#[kani::proof]` yazın. CI'a `model-checking/kani-github-action` ekleyin. Cedar'ı gömün. **Lean öğrenmeden ciddi kazanç.**

**Faz 1 (ay 1-3):** `cedar-lean-ffi`'yi şablon alarak **DRT altyapısını kurun**: `arbitrary` ile Argus'a özgü üreteçler (kullanıcı, oturum, token, kiracı) + `libfuzzer-sys` ile round-trip ve invaryant PBT hedefleri. **Henüz Lean modeli olmadan bile** bu, Cedar'ın 21 hatasının çoğunu bulan mekanizmadır.

**Faz 2 (ay 3-9):** **Tek bir** bileşeni Lean'de modelleyin — tavsiyem **token yaşam döngüsü durum makinesi** (en yüksek risk/satır oranı, en küçük model). SymCert dersini uygulayın: **factory function'lar üzerinden kurun**, ana teoremi reducibility/interpretability benzeri iki genel özelliğe ayrıştırın. Ölçek beklentisi: Cedar validator'ı **18 kişi-günü** aldı; sizin durum makineniz benzer büyüklükte olmalı.

**Faz 3 (ay 9+):** FFI köprüsünü kurun (Protobuf + `@[export]` + `extern "C"`), DRT'yi Lean modeline bağlayın, CI'a günlük fuzzing ekleyin. **Cedar'ın kuralını benimseyin:** model/ispat/DRT güncel değilse sürüm çıkmaz.

##### Katman 5 — Dürüstlük şartı

Argus "en güvenli" iddiasında bulunacaksa, AWS-LC README'sindeki gibi bir **çekince tablosu** yayımlamalıdır:
- Hangi bileşen, hangi araçla, hangi platformda/derleyiciyle doğrulandı
- Ne **varsayıldı** (bellek ayırıcısı? kripto kütüphanesi? inline edilmeme?)
- Doğrulama **sınırlı mı** (belirli girdi uzunlukları?)
- Model ↔ kod boşluğu nasıl kapatılıyor (ispat mı, DRT mi?)

Bu tablo olmadan "formally verified" pazarlama sözüdür; tabloyla birlikte mühendislik iddiasıdır. **Cedar'ın kendisi bile "shared responsibility" diyor.**

---

### BÖLÜM 8: ÖZET DEĞERLENDİRME

**Cedar/Lean yaklaşımı tekrarlanabilir mi? — Evet, ama tümüyle kopyalamayın.**

1. **Cedar'ı yeniden yazmayın, gömün.** Yetkilendirme motoru problemi çözülmüş; 1,772 makine-kontrollü teorem, Apache-2.0, 8.3M indirme. Kendi motorunuzu yazmak "en güvenli" iddianızı güçlendirmez, zayıflatır.

2. **VGD'nin gerçek garantisini doğru anlayın.** Model ispatlanır; **kod test edilir**. Cedar bile 10 hatayı DRT ile kaçırdı. Bu bir eksiklik değil, mühendislik gerçeğidir — ama pazarlamada abartılmamalıdır.

3. **En değerli aktarılabilir varlık ispatların kendisi değil, ispat mimarisidir.** SymCert'in dersi çarpıcı: Dafny'de monolitik 8,000 satır kırılgan ispat → Lean'de modüler yaklaşımla **4 satırlık** ana teorem, ve yeni özellik entegrasyonu **4-8 gün**. Factory function + iki genel özellik (reducibility/interpretability) deseni Argus'un durum makinelerine doğrudan uygulanabilir.

4. **Maliyeti gerçekçi tutun.** Validator soundness: 18 kişi-günü. SymCert: 4 kişi-ay. s2n TLS el sıkışması: 8 ay. Cedar'ın tamamı: çok kişi-yılı. Argus için **tek bir yüksek-değerli bileşenle** başlayın.

5. **Bir IdP'nin risk profili Cedar'ınkinden farklıdır.** Cedar'ın çözdüğü problem (politika değerlendirme semantiği) sizin için hazır. Sizin asıl riskiniz **OAuth/OIDC protokol akışları** ve **token yaşam döngüsüdür** — burada rehberiniz Cedar değil, Fett/Küsters/Schmitz'in WIM analizleri (CCS 2016, CSF 2017, IEEE S&P 2019) olmalıdır.

6. **En yüksek getirili ilk adım Lean değil, Kani + DRT'dir.** Cedar'ın 25 hatasının **21'i** differential/property-based testing ile bulundu, sadece 4'ü ispat sırasında. Test altyapısı, ispatlardan önce ve daha ucuza gelir.

---

#### Kaynak Listesi (erişim: 8 Eylül 2026)

**Cedar & Lean**
- https://arxiv.org/abs/2403.04651 — Cedar OOPSLA 2024 (7-8 Mart 2024)
- https://dl.acm.org/doi/10.1145/3649835 — PACMPL Vol.8 OOPSLA1 Art.118 (Nisan 2024)
- https://arxiv.org/abs/2407.01688 — How We Built Cedar: VGD (1 Temmuz 2024), FSE Companion '24
- https://github.com/cedar-policy/cedar-spec — commit `3a19359` (4 Eylül 2026), Apache-2.0
- https://github.com/cedar-policy/cedar — cedar-policy 4.12.0, MSRV 1.89, Apache-2.0
- https://github.com/cedar-policy/rfcs/blob/main/text/0032-port-formalization-to-lean.md — Dafny→Lean (Ekim 2023)
- https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md — TPE
- https://docs.cedarpolicy.com/other/security.html — güvenlik modeli
- https://docs.rs/cedar-policy/latest/cedar_policy/ · https://docs.rs/cedar-policy-symcc
- https://crates.io/api/v1/crates/cedar-policy · .../cedar-policy-symcc

**AWS blogları & Amazon Science**
- https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing — Mike Hicks (10 Mayıs 2023, Dafny dönemi)
- https://aws.amazon.com/blogs/opensource/lean-into-verified-software-development/ — Hietala & Torlak (8 Nisan 2024)
- https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/ — Erickson & Hadarean (16 Haziran 2025)
- https://aws.amazon.com/blogs/opensource/cedar-joins-cncf-as-a-sandbox-project/ — Lara Langdon (15 Aralık 2025)
- https://lean-lang.org/use-cases/cedar/ — Lean vaka çalışması
- https://www.amazon.science/tag/automated-reasoning — 2026 yayınları

**SymCert / Zelkova / s2n / AWS-LC / Dafny / Kani**
- https://cdn.amazon.science/9f/c9/5d18658a41c48628b686493aa327/scipub-approval152134-46496997-symcert-verifying-smtbased-policy-analyses.pdf — SymCert, FMCAD 2026, Torlak
- https://www.cs.utexas.edu/~hunt/FMCAD/FMCAD18/papers/paper3.pdf — Zelkova, FMCAD 2018
- https://www.amazon.science/publications/a-billion-smt-queries-a-day — Rungta, CAV 2022
- https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
- https://d1.awsstatic.com/Security/pdfs/Continuous_Formal_Verification_Of_Amazon_s2n.pdf — CAV 2018
- https://github.com/aws/s2n-tls — `tests/saw/`, `tests/cbmc/`
- https://github.com/awslabs/aws-lc-verification (`master`) — çekince tablosu
- https://github.com/aws/aws-encryption-sdk-dafny (`mainline`) · https://github.com/aws/aws-cryptographic-material-providers-library
- https://github.com/dafny-lang/dafny — `Source/DafnyCore/Backends/Rust/RustBackend.cs`
- https://github.com/model-checking/kani · https://github.com/verus-lang/verus

**IdP protokol formel analizi**
- https://arxiv.org/abs/1601.01229 — OAuth 2.0, CCS 2016 (6 Ocak 2016)
- https://arxiv.org/abs/1704.08539 — OpenID Connect, CSF 2017 (27 Nisan 2017)
- https://arxiv.org/abs/1901.11520 — FAPI, IEEE S&P 2019 (31 Ocak 2019)
- https://research.google/pubs/zanzibar-googles-consistent-global-authorization-system/ — USENIX ATC 2019
