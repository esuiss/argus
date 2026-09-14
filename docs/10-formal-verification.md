# §10 — Formel doğrulama ve model checking

Aşağıdaki her olgusal iddianın yanında kaynak ve tarih verilmiştir. Kaynaklandırılamayan hiçbir şey iddia edilmemiş, belirsiz kalanlar açıkça doğrulanamadı olarak işaretlenmiştir. Efor tahminleri de açıkça tahmin olarak etiketlenmiştir ve kaynaklı değildir.

---

## 0. Yönetici özeti

2026'da Rust için gerçekten kullanılabilir araç seti üçe ayrılmaktadır.

| Katman | Araçlar | Argus için rol |
|---|---|---|
| Ucuz, her gün çalışan | Miri, proptest ve bolero, cargo-fuzz, ASan ve TSan, Loom ve Shuttle | Zorunlu tabandır. Maliyeti düşük, kapsamı geniştir; garanti vermez |
| Sınırlı ancak otomatik ispat | Kani ve Flux | Seçili yaprak fonksiyonlar: aritmetik, süre ve saat, oran sınırlayıcı, sabit boyutlu decoder'lar |
| Tam fonksiyonel ispat, pahalı | Verus, Creusot, Aeneas ile hax ve Lean, VeriFast | Yalnızca bir veya iki kritik çekirdek: politika değerlendirme motoru, token durum makinesi |

En önemli gerçeklik kontrolü şudur: Rust ekosisteminin en güvenlik kritik kütüphanesi olan rustls formel doğrulama kullanmamaktadır. `forbid(unsafe_code)`, fuzzing ve OSS-Fuzz ile yetinmekte ve SECURITY.md dosyasında formel yöntemlere hiç atıf yapmamaktadır (8 Eylül 2026'da erişilmiştir). Bir IdP'nin en güvenli olması yüzde yüz ispatlanmış olmasından değil, doğru yerlere doğru aracı koymasından geçer.

---

## 1. Kani: AWS'nin CBMC tabanlı sınırlı model checker'ı

### 1.1 Sürüm ve durum

Güncel sürüm `kani-verifier` 0.67.0'dır ve 16 Ocak 2026'da yayımlanmıştır; toplam yaklaşık 566.000 indirme almıştır (crates.io API, 8 Eylül 2026).

Sürüm geçmişi şöyledir: 0.61.0 (6 Nisan 2025), 0.62.0 (8 Mayıs 2025), 0.63.0 (10 Haziran 2025), 0.64.0 (3 Temmuz 2025), 0.65.0 (7 Ağustos 2025), 0.66.0 (6 Kasım 2025) ve 0.67.0 (16 Ocak 2026).

> **Risk sinyali.** 16 Ocak 2026'dan 8 Eylül 2026'ya kadar yeni sürüm çıkmamıştır; yaklaşık sekiz aylık bir boşluk vardır, oysa proje daha önce aylık kadans tutuyordu. Kani blogu da 10 Aralık 2024'ten beri yeni yazı yayımlamamıştır. Bu boşluğun nedeni — kadans değişikliği mi kaynak azalması mı — kaynaklardan çıkarılamamıştır. Buna karşılık aşağıdaki iki 2026 yayını projenin canlı olduğunu göstermektedir.

Akademik ve endüstriyel yayın "Kani: A Model Checker for Rust" başlığıyla arXiv 2607.01504'te 1 Temmuz 2026'da yayımlanmıştır; ASE 2026 (Münih, 12-16 Ekim 2026) Industry Showcase Track'inde sunulacaktır ve 12 yazarı vardır (Rémi Delmas, Zyad Hassan ve diğerleri).

Platform desteği `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin` ve `aarch64-apple-darwin` ile sınırlıdır; Windows desteklenmez. aarch64 Linux bu listede yoktur, dolayısıyla ARM CI runner kullanılacaksa kaynaktan derleme gerekebilir.

### 1.2 Mimari

Kani bir `rustc` eklentisidir. Kodu MIR seviyesinde yakalar; bunun nedeni LLVM IR'in kaybettiği Rust tip değişmezlerini korumaktır. Ardından GOTO programına çevirir ve CBMC'ye verir; CBMC de SAT veya SMT çözücüye indirger.

Boru hattı şudur: Rust kaynağından kani-compiler ile MIR dönüşümleri, oradan codegen, GOTO, CBMC ve SAT veya SMT.

Çözücüler SAT tarafında MiniSat (varsayılan), Kissat ve CaDiCaL; SMT tarafında Z3, cvc5 ve Bitwuzla'dır. SMT desteği 0.65.0 ile 7 Ağustos 2025'te gelmiştir.

### 1.3 Kani ne doğrulayabilir

Anotasyonsuz ve otomatik kontrol edilenler şunlardır. Tanımsız davranış yokluğu: geçersiz veya sarkan pointer dereference, hizasız cast ve geçersiz enum discriminant. Çalışma zamanı panic yokluğu: aritmetik taşma, sıfıra bölme, tanımsız shift, dizi sınır aşımı ve `unwrap()` başarısızlığı. Ek MIR geçişleri: valid-value pass unsafe tip dönüşümlerinin geçerli değer ürettiğini kontrol eder, uninit-memory pass gölge bellek kullanarak tüm dereference'ların ilklendirilmiş belleğe eriştiğini doğrular. Ayrıca float'tan integer'a cast'in sonluluğu kontrol edilir.

Spesifikasyon dili sınırlıdan sınırsıza geçmek için kullanılır. Fonksiyon kontratları `#[kani::requires(P)]`, `#[kani::ensures(|&result| Q)]`, `#[kani::modifies(e)]` ve `old(e)`'dir. Döngü kontratları `#[kani::loop_invariant(I)]`, `#[kani::loop_modifies(W)]` ve `#[kani::loop_decreases(d)]`'dir; sonuncusu bir sonlandırma ölçütüdür ve yalnızca tamsayı ifadeleri alır. Niceleyiciler `kani::forall!(|x: T in (lo,hi)| P(x))` ve `kani::exists!(...)` biçimindedir; SAT arka ucunda sınırların derleme zamanı sabiti olması gerekir ve aralık 1000 değerini aşarsa uyarı verilir, SMT arka ucu çalışma zamanı değerli sınırları destekler. Stubbing `#[kani::stub(f, g)]` ile yapılır ve desteklenmeyen özellikleri (inline assembly, FFI), pahalı implementasyonları veya ortamı (saat okuma, rastgele sayı) değiştirmek için kullanılır. Kritik ayrım şudur: düz stub'lar doğrulanmamış varsayımlardır, `#[kani::stub_verified(f)]` ise makine kontrollü kontrat soyutlaması kullanır.

Kontratlar hâlâ deneyseldir ve `-Z function-contracts` bayrağıyla açılır; özyinelemeli fonksiyonlarda `recursion` özniteliği zorunludur.

Autoharness `cargo kani autoharness -Z autoharness` ile çalışır ve tüm argümanları `kani::Arbitrary` implement eden fonksiyonlar için otomatik harness üretir. Deneyseldir. Sınırları şunlardır: `Arbitrary` olmayan argümanlar `--bounded-arguments` olmadan desteklenmez; generic fonksiyonlarda yalnızca tek bir monomorfik örnekleme doğrulanır ve bu bir under-approximation'dır; `usize` olmayan const generic parametreler desteklenmez; farklı pointer ve referans argümanları arasında aliasing modellenmez.

### 1.4 Kani ne doğrulayamaz

Resmî Rust özellik destek tablosundan:

| Özellik | Destek | Not |
|---|---|---|
| Await ifadeleri ve async | Hayır | Eşzamanlılık kapsam dışıdır |
| Veri yarışları | Hayır | Eşzamanlılık kapsam dışıdır |
| Inline assembly (`asm!`, `global_asm!`) | Hayır | Kani şimdilik assembly kodunu desteklememektedir |
| Hizasız raw pointer dereference | Hayır | — |
| Pointer aliasing kurallarını ihlal | Hayır | Stacked ve Tree Borrows modellenmemektedir |
| Immutable veriyi mutate etme | Hayır | — |
| Trait object tipleri (`dyn`) | Kısmi | İleri özellik sınırlamaları vardır |
| Closure tipleri, function pointer'lar, pointer tipleri | Kısmi | Aynı |
| `impl Trait`, tip parametreleri, inferred type, DST | Kısmi | — |
| Destructor'lar ve `Drop` | Kısmi | — |
| `UnsafeCell<T>`, `PhantomData<T>`, operator trait'leri | Kısmi | — |
| Compiler intrinsic'leri | Kısmi | — |
| Pattern'ler | Kısmi | Issue #707 |

Eşzamanlılık konusunda dokümantasyon eşzamanlı özelliklerin şu anda Kani'nin kapsamı dışında olduğunu söyler. Kani eşzamanlı kod gördüğünde uyarı verir ve sıralı olarak işler; yani sessizce yanlış bir modelle devam eder. Bu, bir IdP'nin oturum deposu veya token cache'i gibi paylaşımlı durum içeren yerlerinde tuzaktır.

Kayan noktada `sin`, `cos` ve `sqrt` over-approximate edilir ve muhafazakâr bir aralıkta nondeterministik değer döndürür; bu, gerçekte imkânsız olan sahte hatalar üretebilir.

Stack unwinding desteklenmez; yalnızca abort stratejisi vardır. Panic sırasında temizlik mantığına, yani `Drop`'a bağımlı kodda bellek güvenliği boşluğu doğabilir. Argus için pratik sonuç `panic = "abort"` profiliyle çalışmanın Kani ile daha tutarlı olmasıdır.

Tanımsız davranış dokümanı listenin tüketici olmadığını açıkça söyler, çünkü unsafe kodda neyin izinli olduğuna dair Rust semantiğinin formel bir modeli yoktur. Kani'nin hiç kontrol etmediği sınıflar veri yarışları, inline assembly, ilklendirilmemiş bellek ve yanlış call veya unwind ABI'larıdır. Best-effort olanlar pointer aliasing ihlalleri (yalnızca bellek güvenliğine yansıdığı ölçüde), immutable veri mutasyonu, intrinsic ön koşulları ve geçersiz değer üretimidir; `transmute` engellenmez.

ASE 2026 makalesinin kendi sınırlar listesi şudur: özyinelemeli fonksiyonların sonlanması doğrulanmaz ve bu kullanıcı sorumluluğundadır; karşılıklı özyineleme desteklenmez ve tespit edilirse derleme hatası verir; `decreases` cümlelerinde struct alan projeksiyonları ve leksikografik tuple ölçütleri henüz yoktur; Stacked ve Tree Borrows modellenmemektedir ve bu unsafe Rust'ın birincil tanımsız davranış sınıfıdır; FFI çağrıları stub'lanmadıkça CBMC'nin bellek modeli dışında çalışır; spesifikasyonlar generic'ler için adreslenemez ve her monomorfizasyon ayrı doğrulanır; dinamik trait dispatch ve eşzamanlı yürütme ele alınmaz.

Döngü sınırları, yani unwinding, parser'lar için en acı noktadır. `--default-unwind` tüm harness'lar için bir döngü açma üst sınırı koyar. Sınır yetersizse unwinding assertion hatası verir ve diğer birçok sonuç belirsiz hâle gelir. Kani dokümantasyonu bunu açıkça söyler: parser'lar gibi büyük string problemleri hataları ortaya çıkarmak için genellikle 10-20 ve daha fazla karakterlik girdiye ihtiyaç duyar ve bu ölçek doğrulama süresini dramatik biçimde artırır. Bu, Argus'ta JWT, base64 ve CBOR decoder'larını Kani ile tam doğrulamanın neden gerçekçi olmadığının doğrudan kaynağıdır.

Kani kendi karşılaştırma sayfasında eşzamanlılık için Loom ve Shuttle'ı önerir.

### 1.5 Üretimde gerçek kullanım

ASE 2026 makalesinden:

| Proje | Ne doğrulanmış | Sayılar |
|---|---|---|
| AWS Firecracker; Lambda ve Fargate'in VMM'i | Block device panic yokluğu, rate limiter, VirtIO emülasyonu | 34 harness ve 21 dakika CI süresi. Rate limiter'da nondeterministik saat değerleriyle doğrulama yapılmış ve %0,01 bütçe aşımına izin veren bir yuvarlama hatası bulunmuştur. VirtIO'da guest'in tetikleyebildiği bir panic bulunmuştur; queue adreslerinin MMIO boşluğuna yerleştirilmesi |
| AWS s2n-quic; Rust QUIC implementasyonu | Protokol kodlama ve çözme | 102 harness. `try_fit` assertion hatası 20 saniyede bulunmuştur; oysa 16,7 milyon iterasyonluk fuzzing hiçbir şey bulamamıştı. `decode_packet_number` taşması da bulunmuştur |
| Hifitime; havacılık ve uzay zaman kütüphanesi | Faz I'de 11 panic yokluğu harness'ı, Faz II'de 153 fonksiyonel doğruluk ispatı | Faz I'de altı gerçek hata bulunmuştur: `total_nanoseconds()` işaret hatası, `i64::MIN.abs()` taşması, float çarpım döngüsünde NaN ve sonsuz yayılımı, `Epoch` tipinde `PartialEq` ile `Ord` tutarsızlığı, `Duration`'da sıfır geçişinde `a == b && a < b` koşulunun aynı anda sağlanabilmesi ve `is_gregorian_valid` taşması (`year == i32::MAX`). Faz I'de 158 harness'ın 57'si 60 saniyelik CI bütçesini aşmıştır; Faz II'de kontratlarla çoğu ispat beş saniyenin altına inmiş, takvim geçerliliği 16,4 saniye ve döngü sonlanması 13,6 saniye sürmüştür |
| Rust std; verify-rust-std kampanyası | Standart kütüphane | Her kod değişikliğinde 16.748 harness, 69 dakika CI ve paralelleştirmeyle 3,97 kat derleme hızlanması |

s2n-quic Kani'yi Bolero property testing framework'üyle birlikte kullanmaktadır: tek bir öznitelikle aynı harness hem fuzz testi hem Kani ispatı olarak çalışır. Argus için doğrudan kopyalanabilir desen budur.

Tokio için Kani blogunda 17 Ağustos 2022 tarihli "Using the Kani Rust Verifier on Tokio Bytes" yazısı bulunmaktadır; ancak bu bir deneme ve vaka çalışmasıdır, Tokio'nun kendi CI'ında sürekli Kani çalıştırdığına dair kanıt doğrulanamamıştır.

CI entegrasyonu için resmî bir GitHub Action mevcuttur (`model-checking/kani-github-action`, v1); parametreleri `kani-version`, `command`, `working-directory`, `args` ve `enable-propproof`'tur.

### 1.6 Verify Rust Std Lib mücadelesi

**Kuruluş.** Rust Foundation ve AWS ortak duyurusu 20 Kasım 2024 tarihlidir. Rust std'de yaklaşık 35.000 fonksiyon bulunmaktadır ve bunların yaklaşık 7.500'ü `unsafe`'tir; son üç yılda 57 soundness issue ve 20 CVE görülmüştür. Her mücadeleye bağlı bir finansal ödül vardır ve bir ödül komitesi ödülleri dağıtmaktadır. Duyuru anında 30'dan fazla öğrenci, akademisyen ve araştırmacı katılmıştı.

AWS'in toplam taahhüt rakamı doğrulanamamıştır; Rust Foundation duyurusu belirli bir toplam tutar vermemekte, yalnızca her mücadeleye bağlı ödülden söz etmektedir. Depo README'sindeki tablo mücadele başına tutarları listeler; doğrulanan aralık mücadele başına 10.000 ile 25.000 USD'dir.

Mücadele sayısı 29'dur ve SUMMARY.md dosyasından birebir doğrulanmıştır; birinci mücadele core transmutation, yirmi dokuzuncu mücadele `boxed` güvenliğidir. NFM 2026 makalesi de 29 yayımlanmış mücadeleden söz etmektedir.

Çözülmüş ve açık mücadele sayısı kısmen doğrulanamamıştır. Aynı README iki kez çekildiğinde çelişkili özetler gelmiştir; birinde yedi çözülmüş ve 22 açık ile 315.000 USD üstü toplam, diğerinde dokuz çözülmüş ve 20 açık ile 285.000 USD toplam görülmüştür. Bağımsız hakemli kaynak olan Le Blanc ve Lam'in "Lessons Learned So Far…" çalışması (arXiv 2510.01072, 1 Ekim 2025 gönderim, 26 Ekim 2025 revizyon) 27 mücadeleden dokuzunun tamamlandığını söylemektedir. Güvenli ifade şudur: 29 mücadelenin yaklaşık yedi ile dokuzu çözülmüş, yaklaşık 20 ile 22'si açıktır. Kesin güncel sayı için her mücadelenin tracking issue'suna bakmak gerekir; depo bunu kendisi söylemektedir.

**Kampanyanın 2026 sonuçları** ("Verifying the Rust Standard Library", NFM 2026, Los Angeles, 5-7 Mayıs 2026, arXiv 2606.17374, 16 Haziran 2026): 450'den fazla pull request, en az 21 harici katkıcı ve dört farklı kurum. Autoharness ile 16.748 otomatik üretilmiş proof harness oluşturulmuş, bunların 11.970'i Kani'nin desteklediği tanımsız davranış sınıflarına karşı doğrulanmıştır. 989 fonksiyon tam kontratla doğrulanmıştır; 295'i otomatik, 694'ü manueldir. Kapsam core, alloc ve std'de 33.955 fonksiyondur; 4.645 unsafe fonksiyon için harness yazılmış, unsafe üzerine 1.126 güvenli soyutlama doğrulanmış ve 10.194 safe fonksiyon doğrulanmıştır. Bulunan yeni bellek güvenliği açığı sayısı sıfırdır; bunun yerine dört spesifikasyon ve dokümantasyon hatası upstream'e düzeltilmiştir: yanlış SIMD shift'ler, eksik safety anotasyonları, hatalı SAFETY yorumları ve dokümantasyon hataları. CI'da paralelleştirme ve optimizasyonla 3,97 kat derleme hızlanması sağlanmıştır.

**Rust Foundation'ın 1 Eylül 2026 tarihli değerlendirmesi.** İlk yıl manuel olarak 725 Kani harness'ı ve 50'den fazla VeriFast ispatı üretilmiştir; ancak manuel kontrat büyümesi Ekim 2025 civarında platoya ulaşmıştır ve autoharness'a geçişin nedeni budur. VeriFast ile `LinkedList`'in 19 çekirdek fonksiyonu separation logic ile doğrulanmış, beş fonksiyon daha dolaylı olarak sağlam çıkmıştır. Kalan boşluklar şunlardır: 9.600 generic fonksiyon monomorfizasyon sorunu nedeniyle autoharness tarafından atlanmaktadır; atomik tipler (yedinci mücadele) ve `Arc` (yirmi yedinci mücadele) çözülememiştir, çünkü gevşek bellek modeli altında lock-free yapılar gerçek bir teknik zorluktur.

**Kapsama gerçeği.** Le Blanc ve Lam (arXiv 2510.01072, Ekim 2025) manuel doğrulama kapsamını `core` için %3,98 ve `std` için %1,4 olarak vermektedir. Autoharness sonrası rakamlar daha yüksektir ancak autoharness'ın verdiği garanti daha zayıftır; tam kontrat değil yalnızca tanımsız davranış sınıflarıdır.

Entegre araçlar Kani, goto-transcoder üzerinden ESBMC, VeriFast ve Flux'tur ve CI'dadır. İnceleme aşamasında Verus, Creusot, KRust ve RAPx bulunmaktadır.

---
## 2. Diğer Rust doğrulama araçları

### 2.1 Karşılaştırma tablosu

| Araç | Teknoloji | Kanıtladığı | Anotasyon yükü | 2026 durumu | Argus'taki yeri |
|---|---|---|---|---|---|
| Kani | CBMC ile SAT ve SMT; sınırlı model checking | Panic yokluğu, tanımsız davranış alt kümesi, assertion'lar, kontratlar | Düşük; harness ve isteğe bağlı kontrat | Canlı ancak sürüm kadansı yavaşlamıştır (0.67.0, 16 Ocak 2026) | Birincil araç |
| Verus | SMT (Z3) ve lineer ghost tipler | Tam fonksiyonel doğruluk, sahiplik disiplini, eşzamanlılık | Yüksek | Çok canlı; günde birden çok rolling release (0.2026.09.07) | Politika motoru ve durum makinesi |
| Creusot | Why3 ve Coma üzerinden SMT | Panic, taşma ve tanımsız davranış yokluğu ile tam fonksiyonel doğruluk ve sonlanma | Yüksek | Canlı; v0.13.0, 30 Temmuz 2026 | Alternatif; algoritma ispatı |
| Prusti | Viper ve permission logic | Safe Rust fonksiyonel doğruluğu | Orta | Ölü; son commit 26 Mart 2024 | Kullanılmaz |
| Flux | Refinement (liquid) tipleri üzerinden SMT | Aritmetik taşma, sıfıra bölme, dizi sınırı ve özel refinement'lar | Düşük; döngü invariantı çıkarımı otomatiktir | Çok canlı; commit'ler 8 Eylül 2026 | İndeks, uzunluk ve aralık mantığı |
| Aeneas ve Charon | Rust'tan LLBC'ye, oradan saf fonksiyonel Lean, F*, Coq veya HOL4 | Kanıtlayıcıda ne ispatlanırsa | Çok yüksek; kanıtlayıcı bilgisi şarttır | Çok canlı; commit'ler 7 Eylül 2026 | Kripto çekirdeği |
| hax (Cryspen) | Rust'tan F*, Rocq, Lean, ProVerif, SSProve veya EasyCrypt'e | Aynı; ayrıca protokol ve kripto oyunları | Çok yüksek | Canlı; 474 yıldız | Protokol analizi |
| MIRAI | MIR soyut yorumlama | Taint analizi ve panic tahmini | Düşük | Orijinal repo ölüdür; son commit 22 Ağustos 2024, endorlabs fork'una taşınmıştır | Kullanılmaz |
| VeriFast | Separation logic ve modüler sembolik yürütme | Unsafe kodda tanımsız davranış yokluğu; sınırsız doğrulama | Çok yüksek | Canlı; std kampanyasında CI'dadır | Yalnızca özel veri yapıları |
| KMIR (Runtime Verification) | K Framework, MIR semantiği, sembolik yürütme | Panic ve tanımsız davranış yokluğu, eşdeğerlik | Düşük ile orta arası | Aktif geliştirme | Henüz uygun değildir |
| ESBMC ve goto-transcoder | Sınırlı model checking ve k-induction | Kani'ye benzer | Düşük | CI'dadır ancak hiçbir mücadele bu arka uçla çözülmemiştir | Kullanılmaz |
| Stateright | Açık durum model checking (actor) | Dağıtık protokol invariantları ve linearizability | Orta; sistemi yeniden yazmak gerekir | 1.900 yıldız, yaklaşık 460 commit | Protokol akış modeli |

### 2.2 Verus

**Rust lehçesi mi.** Teknik olarak hayır, ancak pratikte evet gibidir. Verus `verus!{}` makrosu içinde yazılır; spesifikasyon ve ispatlar Rust söz dizimiyle yazılır ve Rust'ın tip denetleyicisinden geçer. Ayrı bir DSL değil, Rust'ın makro yoluyla genişletilmesidir; `forall`, `exists`, `requires` ve `ensures` bu yolla gelir. Ancak desteklenen alt küme dar olduğu için Verus'ta yazılan kod pratikte Verus uyumlu Rust'tır ve normal Rust kütüphaneleri serbestçe kullanılamaz.

README'nin kendi ifadesine göre Verus aktif geliştirme altındadır; özellikler bozuk veya eksik olabilir ve dokümantasyon hâlâ tamamlanmamıştır. Proje 3.000'den fazla yıldıza ve 4.628 commit'e sahiptir.

**Aktivite son derece yüksektir.** Rolling release'ler `0.2026.09.07.f9e9452` (7 Eylül 2026, 17.42 UTC) ve aynı gün üç sürüm daha, 6 Eylül 2026'da üç sürüm, 5 ve 4 Eylül 2026'da sürümler biçimindedir. 2026'da Rust doğrulama araçları içinde en aktif olanıdır.

**Desteklenen ve desteklenmeyen özellikler.** Tam destek: fonksiyonlar, struct ve enum, tip parametreleri, where cümleleri, lifetime'lar, pattern matching ve match guard, `while` ve `loop`, unsafe blokları, paylaşımlı ve mutable borrow, closure'lar, tamsayı tipleri, bitwise işlemler, `Vec`, `Option`, `Result`, slice'lar, `Box`, `Rc`, `Arc`, kullanıcı trait'leri ve default implementasyonlar, associated type'lar, HRTB, `Copy`, `Send`, `Sync`, `Deref` ve `DerefMut`. Kısmi destek: associated const'lar, `const fn`, const generic'ler, `for` döngüleri, `as` cast, pointer'lar, kayan nokta, function pointer tipleri, closure tipleri (mutable capture yoktur), trait object'ler (`dyn`), `impl Trait`, iterator'lar, çok crate'li projeler ve panic unwinding. Desteklenmeyenler: `async fn`, async bloklar ve `await`, destructuring assignment, `Pin`, donanım intrinsic'leri, yazdırma ve I/O, standart trait'ler (`Debug`, `serde::Serialize`), kullanıcı tanımlı `Drop`, standart kütüphane kilitleri (`Mutex`, `RwLock`), `transmute` ve çok iş parçacıklı atomikler; sonuncusu için `vstd` alternatifleri vardır.

> **Argus için doğrudan sonuç.** Verus, async ve tokio tabanlı bir HTTP sunucusunda kullanılamaz. `serde::Serialize` desteklenmediği için serileştirme katmanına da giremez. Verus'un yeri saf, senkron ve I/O içermeyen bir çekirdek modüldür — örneğin politika değerlendirme motoru veya token durum makinesi — ve bu modül geri kalanla `external_body` sınırından konuşur.

**Eşzamanlılık.** Verus, VerusSync framework'ü ile önemsiz olmayan sahiplik disiplini gerektiren çok iş parçacıklı kodu destekler; konu ayrı bir kitapta ele alınmaktadır. Yani Verus, Kani'nin yapamadığı eşzamanlılık ispatını yapabilir; ancak tokenized state machine ve ghost permission tekniklerini öğrenmek gerekir.

**Garantiler ve güvenilen hesaplama tabanı.** Verus kılavuzu doğrulanmış kodun boşlukta çalışmadığını ve genellikle doğrulanmamış kodla her iki yönde etkileştiğini açıkça söyler; `external_body`, `assume` ve `admit` gibi kaçış kapıları ile TCB için ayrı bölümler ayırır. Bu, Argus'ta belirli bir yüzdenin doğrulandığını söylemenin neden dikkatli ifade edilmesi gerektiğinin kaynağıdır: `external_body` ile işaretlenen her fonksiyon ispatsız bir aksiyomdur.

**Verus ile doğrulanmış sistemler.** IronKV, IronFleet'ten Verus'a port edilmiş dağıtık bir key-value store'dur. Verified Storage Systems (Microsoft) persistent memory için doğrulanmış key-value store ve append-only log implementasyonları sunar. Concurrent Memory Allocator mimalloc tabanlıdır. Node Replication Library sıralı veri yapılarından linearizable ve NUMA farkında eşzamanlı yapılar üretir. OS Page Table Management donanım bellek çeviri modelleriyle sayfa tablosu kodunu kapsar. Asterinas OSTD (`vostd`) safe Rust'ta OS geliştirme standart kütüphanesinin formel doğrulanmış sürümüdür. TLSF Memory Allocator ve Anvil'den port edilmiş TLA+ temporal logic gömülmesini sağlayan TLA+ kütüphanesi de listededir. Yayınlar Verus (OOPSLA 2023), Leaf separation logic (OOPSLA 2023), Anvil (OSDI 2024; küme yönetim controller'larının liveness doğrulaması), VeriSMo (OSDI 2024; gizli VM'ler için doğrulanmış güvenlik modülü), Verus (SOSP 2024) ve CortenMM (SOSP 2025)'tir. VerusBelt (PLDI 2026) Verus'un anlamlı bir alt kümesi için ilk semantik sağlamlık ispatıdır; cell'leri, invariantları, resource algebra'ları, storage protokollerini, tam Rust lifetime'larını, eşzamanlılığı ve mutable borrow'ları kapsar. Bu, Verus'a güvenmek için güçlü bir argümandır.

Verus'ta ispat ile kod oranı doğrulanamamıştır; SOSP 2024 PDF'i metin olarak ayrıştırılamamış ve güvenilir bir ikincil kaynakta somut oran bulunamamıştır. Bu tür sistem doğrulama projelerinde tipik oranlar literatürde yüksektir, ancak Verus için spesifik bir sayı bu araştırmada doğrulanamamıştır ve bütçelemede varsayım olarak kullanılmamalıdır.

> **Uyarı.** emergentmind.com/topics/verus sayfası Verus'un Viper doğrulama arka ucu üzerinden Z3 kullandığını söylemektedir; bu yanlıştır. Viper'ı kullanan Prusti'dir, Verus doğrudan Z3'e SMT üretir. Bu sayfa AI ile üretilmiş bir agregatördür ve birincil kaynak olarak kullanılmamalıdır.

### 2.3 Creusot

Creusot Rust'ı Coma ara doğrulama diline derler, ardından Why3 platformu doğrulama koşullarını üretip SMT çözücülere dağıtır.

Spesifikasyon dili Pearlite'tır ve `#[requires]`, `#[ensures]`, `#[invariant]` ile sonlanma için döngü variant'ları sunar. Pearlite fonksiyonları ve predicate'leri tanımlanabilir, hatta trait'lerde bildirilebilir.

Panic, taşma ve tanımsız davranış yokluğunu ispatlar; anotasyonla tam fonksiyonel doğruluk ve sonlanma da ispatlanır. Unsafe kod ghost ownership tekniğiyle ele alınır ve interior mutability, raw pointer'lar ile atomikler kapsanır.

Aktivite canlıdır. Sürümler v0.6.0 (9 Ekim 2025), v0.7.0 (3 Kasım 2025), v0.8.0 (10 Aralık 2025), v0.9.0 (17 Ocak 2026), v0.10.0 (24 Şubat 2026), v0.11.0 (20 Nisan 2026), v0.12.0 (12 Haziran 2026) ve v0.13.0'dır (30 Temmuz 2026). POPL 2026'da (Ocak 2026) tutorial verilmiştir.

Doğrulanmış örnek CreuSAT'tır; Creusot ile formel doğrulanmış bir SAT çözücüdür ve bir tez çalışmasıdır. Başka büyük ölçekli üretim kullanımı doğrulanamamıştır. verify-rust-std'de hâlâ inceleme aşamasındadır ve CI'da değildir.

### 2.4 Prusti

ETH Zürich'in Viper altyapısı üzerine kurulu, permission logic tabanlı bir safe Rust doğrulayıcısıdır.

Son sürüm "Nightly Release v-2024-03-26-1504" olup 26 Mart 2024 tarihlidir; bundan sonra hiçbir sürüm çıkmamıştır. Son commit 26 Mart 2024 tarihli "Fix issue #1505 (#1511)" commit'idir ve master dalında 2025 veya 2026'da hiçbir commit yoktur. Ayrıca proje `nightly-2023-09-15` gibi üç yıl önceki bir Rust nightly'sine sabitlenmiş durumdadır.

Karar şudur: Argus'ta Prusti kullanılmaz. Yaklaşık iki buçuk yıldır terk edilmiştir ve modern Rust'ta derlenmez.

### 2.5 Flux

Rust derleyicisine eklenti olarak çalışan bir refinement, yani liquid, tip denetleyicisidir. Refinement'lar derleme sırasında kontrol edilen mantıksal iddialardır.

Kutudan çıkan kontroller aritmetik taşma, sıfıra bölme ve dizi sınır aşımıdır. Kullanıcı refinement kontratlarıyla, yani ön ve son koşul olarak, özel özellikler tanımlayabilir.

Anotasyon yükü en düşük olanlardandır: döngü invariantlarını otomatik çıkarır ve sınırsız doğrulama yapar; bu, Kani'nin yapamadığı bir şeydir. Le Blanc ve Lam Flux'un daha hafif olmayı amaçladığını belirtir.

Sınırları şunlardır. Mantık hatalarını, yani panic'leri, tanımsız davranışa yol açan hatalardan ayırt etmez. Refinement predicate'leri niceleyicisiz ve karar verilebilir birinci derece mantık fragmanıyla sınırlıdır; bu nedenle bir dizinin sıralı olup olmadığı gibi özellikler ifade edilemez. Unsafe kod desteği sınırlıdır; pointer özelliklerini takip edebilir ancak pointer üzerinden yazılan verinin değerlerini takip edemez. Birçok Rust özelliği desteklenmemektedir ve analiz sırasında çökmelere sebep olabilir.

Aktivite çok yüksektir. Commit'ler 8 Eylül 2026 (bağımlılık), 3 Eylül 2026 (dangling pointer fonksiyonları için spec'ler, generic `Iterator::next()` spec'lerinin güncellenmesi) ve 1 Eylül 2026 (üç ayrı iterator state commit'i) tarihlidir.

En güçlü referansı Tock mikrodenetleyici işletim sisteminde süreç izolasyonunun doğrulanmasıdır. Tock, Google Security Chip ve Microsoft Pluton güvenlik işlemcisi gibi güvenlik kritik sistemlerde kullanılmaktadır. Doğrulama çalışması izolasyonu bozan ve kötü niyetli uygulamaların işletim sistemini ele geçirmesine izin veren birden fazla ince hata ortaya çıkarmıştır (Ranjit Jhala, UCSD kolokyumu, 19 Kasım 2025). Temel makale "Flux: Liquid Types for Rust", PACMPL ve PLDI 2023'tür.

Flux verify-rust-std CI'ına entegredir ve dört araçtan biridir.

> **Argus için değerlendirme.** Flux, Kani'den çok daha ucuz ve sınırsız olduğu için bir indeksin asla buffer'ı aşmayacağı, bir TTL'in asla negatif olmayacağı ve bir sayacın asla taşmayacağı gibi aritmetik ve uzunluk invariantları için ilk tercih olmalıdır. Ancak bir JWT'nin doğru ayrıştırıldığını söyleyemez.

### 2.6 Aeneas, Charon ve hax'tan Lean ile F*'a

Charon safe Rust'ı LLBC'ye, yani MIR türevi tiplenmiş bir ara temsile çevirir. Aeneas LLBC'yi saf fonksiyonel Lean 4 koduna çevirir. Arka uçlar F*, Coq ve Rocq, HOL4 ile Lean'dir.

Aktivite çok yüksektir. Commit'ler 7 Eylül 2026 (Charon güncellemeleri, PR #1336 ve #1334), 6 Eylül 2026 ("Fix release") ve 3 Eylül 2026 (`Iterator` çıkarımı düzeltmesi, #1131) tarihlidir.

hax (Cryspen) Rust'ın büyük bir alt kümesini formel dillere çevirir. Arka uçları Aeneas üzerinden Lean (önerilen), legacy Lean, deneysel Rocq ve Coq, stabil F*, deneysel ProVerif, deneysel SSProve ve deneysel EasyCrypt'tir. Tek kasıtlı kısıtı `&mut T` dönüş tiplerinde ve aliasing durumunda yasak olmasıdır. Proje 474 yıldıza sahiptir.

**En güçlü 2026 üretim kanıtı: Microsoft SymCrypt.** "Verifying Rust cryptography in SymCrypt, from standards to code" başlıklı Microsoft Research blog yazısı 13 Temmuz 2026 tarihlidir. ML-KEM ve SHA-3 için tam formel ispatlar tamamlanmıştır ve bu kod Windows insider build'lerinde şu anda çalışmaktadır. Çalışma AES-GCM, FrodoKEM ve ML-DSA'ya genişletilmektedir. Yöntem şudur: kriptografik standartlar çalıştırılabilir Lean spesifikasyonu olarak formalize edilir, Rust kodu Aeneas ile Lean modeline çevrilir ve implementasyon ile spesifikasyon arasında eşdeğerlik ispatı yapılır. SIMD intrinsic'leri ve platforma özel dispatch içeren optimize edilmiş, çok mimarili kod desteklenmektedir. AI ajanları standartları spesifikasyona çevirmede ve ispatları yazıp bakımını yapmada kullanılmakta, daha önce aylarca uzman eforu gerektiren iş dramatik biçimde hızlanabilmektedir.

**libcrux.** Cryspen'in doğrulanmış kripto kütüphanesidir. HACL*'tan çıkarılan F* doğrulanmış kodu (bellek güvenliği, fonksiyonel doğruluk ve gizli bağımsızlık) hax ile doğrulanmış Rust koduyla (panic yokluğu ve fonksiyonel doğruluk) birleştirir. Algoritmalar ML-KEM, X25519, XWing, P256 DHKEM; AES-GCM ve CCM, ChaCha20Poly1305, XChaCha20Poly1305; BLAKE2, SHA2, SHA3; P256 ECDSA, ML-DSA, Ed25519, RSA-PSS; HKDF, HMAC ve Poly1305'tir. Kritik sınırlama şudur: derlenmiş yürütülebilir dosyalar yan kanal direnci için doğrulanmamıştır. Üretim uyarısı da vardır: tüm crate'ler 0.1'in altında ön yayındadır ve dokümantasyon bu crate'lerin üretimde kullanılması düşünülüyorsa bakımcılarla iletişime geçilmesini istemektedir.

**AWS-LC formel doğrulaması.** C tarafındadır ancak `aws-lc-rs` altındadır. `aws-lc-verification` deposu SAW ve Cryptol (C ve x86-64), NSym (AArch64 assembly), Coq (Cryptol spesifikasyon özellikleri), s2n-bignum (HOL Light) ve CBMC (C bileşenlerinin bellek ve tip güvenliği) kullanır. Doğrulanmış algoritmalar SHA-384 ve SHA-512, HMAC-SHA384, AES-KW(P)-256 ile AES-GCM-256'dır; ML-KEM ve ML-DSA ilgili depolardadır. Varsayımlar sınırlı girdi uzunlukları, null ENGINE pointer'ları ve doğrulanmamış fonksiyonların (`malloc`, refcounting) doğru davrandığıdır. 2026 aktivitesi düşüktür; yeni çalışma s2n-bignum, mlkem-native ve mldsa-native depolarına kaymıştır.

### 2.7 MIRAI

Rust MIR üzerinde çalışan bir soyut yorumlayıcıdır ve Facebook ile Meta kökenlidir. README'ye göre proje bir Facebook projesi olarak başlamış, sponsor organizasyon dağıldığında sahipsiz kalmıştır; projeyi canlı tutmaya yönelik devam eden çalışma artık github.com/endorlabs/MIRAI adresinde yürütülmektedir.

Orijinal repoda son commit 22 Ağustos 2024 tarihli "Update README to point to new home" commit'idir; 2025 veya 2026'da hiçbir aktivite yoktur. Endor Labs fork'unun 2026 aktivite durumu bu araştırmada incelenmemiştir.

Karar şudur: Argus'ta MIRAI'ye bel bağlanmaz.

### 2.8 VeriFast

Rust için separation logic tabanlı modüler bir doğrulayıcıdır ve fonksiyonları tek tek spesifikasyonlarına karşı kontrol eder.

`unsafe` içeren fonksiyonların tanımsız davranış üretmediğini ve dönüş durumlarının son koşulları sağladığını ispatlar. Safe fonksiyonlar için RustBelt'in Rust tip sistemi semantiğine dayalı spesifikasyonlar üreterek semantik iyi tipliliği garanti eder.

Anotasyon yükü çok yüksektir: her fonksiyon için ön ve son koşul, her döngü için invariant, sembolik yürütme algoritmasına ipucu veren ghost komut anotasyonları ve bellek ayak izini tanımlayan separation logic predicate'leri gerekir. Karşılığında sonlu zamanda sınırsız doğrulama sağlar; Kani'nin unwind sınırı sorunu yoktur.

std kampanyasında `LinkedList`'in 19 çekirdek fonksiyonu doğrulanmıştır.

### 2.9 KMIR

K Framework üzerine kurulu, MIR seviyesinde rewrite tabanlı bir semantiktir; hem somut hem sembolik yürütme sunar.

Harness'lar düz Rust ile yazılır; son koşul için `assert!`, ön koşul için `assume` kullanılır ve özel bir doğrulama dili yoktur.

Refusal-to-execute stratejisi uygular: tanımsız davranışa yol açabilecek bir talimatla karşılaşınca UB-detected durumunda durur ve ispat başarısız olur.

Desteklenmeyenler kayan nokta (f16, f32, f64, f128), heap ayıran tipler (`String`, `Vec`), smart pointer'lar (`Box`, `Rc`, `Arc`), async ve await ile çok iş parçacıklılık ve dinamik trait object'lerdir.

Başarıları Rust std'de tamsayı işlemleri ile Solana P-Token ve SPL-Token programları için eşdeğerlik ispatlarıdır.

`String` ve `Vec` desteklenmediği için bir IdP için 2026'da kullanılabilir değildir.

### 2.10 ESBMC ve goto-transcoder

Kani'nin GOTO çıktısını ESBMC'ye besler; k-induction ve SMT çözücü desteği ekler. Teorik olarak daha güçlü doğrulama potansiyeli vardır, ancak bu arka uçla hiçbir mücadele çözülmemiştir.

### 2.11 Gillian-Rust, Soteria-Rust, RefinedRust ve rocq-of-rust

Soteria-Rust, Rust Formal Methods Interest Group'un Aralık 2025 toplantısında Rust hakkında akıl yürütmeyi tam olarak destekleyen ilk sembolik yürütme motoru olarak sunulmuştur. Depo URL'i doğrulanamamıştır; denenen iki URL 404 döndürmüştür.

Gillian-Rust unsafe Rust doğrulamasına hibrit bir yaklaşımdır; RFMIG araç listesinde yer alır ve survey'de hibrit separation logic ile safe ve unsafe entegrasyonu olarak sınıflandırılmıştır.

RefinedRust MPI-SWS'ün Coq ve Iris tabanlı, foundational separation logic kullanan yarı otomatik fonksiyonel doğruluk doğrulayıcısıdır. GitLab deposu 1.642 commit'e sahiptir, Apache 2.0 lisanslıdır ve 12 Haziran 2023'te oluşturulmuştur. Güncel aktivite düzeyi doğrulanamamıştır.

rocq-of-rust (Formal Land) Rust'ın THIR temsilini Rocq'a çevirir; 1.200 yıldız ve 3.326 commit'e sahiptir, Ethereum Foundation ve Aleph Zero Foundation tarafından fonlanmaktadır. Sayfa tam yüklenmediği için güncel durum kısmen doğrulanamamıştır.

Bu üçü araştırma aşamasındadır ve Argus için 2026'da üretim seçeneği değildir.

### 2.12 Survey ve karşılaştırma literatürü

"Surveying the Rust Verification Landscape", Alex Le Blanc ve Patrick Lam (University of Waterloo), 2 Ekim 2024, arXiv 2410.01981. Taksonomisi şudur: Kani (bounded model checking, unsafe kod, bellek güvenliği), Prusti (dedüktif, safe Rust), Creusot (dedüktif, Pearlite), Aeneas (fonksiyonel çeviri), Verus (Rust-native ispatlar), Gillian-Rust (hibrit separation logic) ve RefinedRust (foundational separation logic). Flux, MIRAI ve Miri derinlemesine ele alınmamıştır; bu bir eksikliktir ve 2026 için güncelliğini kısmen yitirmiştir.

"Lessons Learned So Far From a Community Effort to Verify the Rust Standard Library", aynı yazarlar, arXiv 2510.01072, 1 Ekim 2025 ve 26 Ekim 2025 revizyonu. En değerli kısmı üç temel engeldir. Karmaşık çağıran gereksinimleri: `MaybeUninit<T>`'nin ilklendirme durumu veya pointer provenance gibi, tek bir ön koşulla ifade edilmesi zor koşullar. Generic tipli girdiler: Rust derleme zamanında monomorfize ettiği için her tip örneklemesi ayrı harness gerektirir ve neredeyse aynı harness'lardan oluşan bir yığın ortaya çıkar. Eşzamanlı kod: Kani dokümantasyonu eşzamanlılığı desteklemediğini söyler, ancak alttaki motorlar CBMC ve ESBMC eşzamanlılığı destekler; yani bu teorik değil mühendislik boşluğudur.

ASE 2026 Kani makalesinin kendi karşılaştırması Verus'un hedef bakımından Kani'ye en yakın araç olduğunu söyler; dedüktif araçlar Prusti, Creusot ve Verus zengin fonksiyonel özellikleri ispatlayabilir ancak separation logic veya ghost state gibi kayda değer ispat mühendisliği gerektirir ve bu, uzman ekipler dışında benimsenmeyi sınırlar.

NFM 2026 makalesinin gerekçesi şudur: hiçbir araç tek başına tüm doğrulama koşullarını karşılayamaz; mimariye özgü intrinsic'ler, pointer ağırlıklı kod, eşzamanlılık primitifleri ve karmaşık invariantlı döngüler tamamlayıcı akıl yürütme teknikleri gerektirir.

---

## 3. Ucuz yardımcılar: Miri, Loom, fuzzing ve sanitizer'lar

### 3.1 Miri

POPL 2026 makalesi "Miri: Practical Undefined Behavior Detection for Rust" Ralf Jung, Benjamin Kimock, Christian Poveda, Eduardo Sánchez Muñoz, Oli Scherer ve Qian Wang tarafından yazılmıştır. İddiası deterministik Rust programlarındaki tüm fiili tanımsız davranışları bulabilen ilk araç olmasıdır. Değerlendirmede 100.000'den fazla Rust kütüphanesi üzerinde test edilmiş, birleşik test süitlerinin %70'inden fazlası başarıyla çalıştırılmış, onlarca gerçek dünya hatası bulunmuş ve araç Rust std ile birçok önemli kütüphanenin CI'ına entegre edilmiştir.

**Miri'nin yakaladıkları.** Sınır dışı bellek erişimi ve use-after-free; ilklendirilmemiş verinin geçersiz kullanımı; intrinsic ön koşul ihlalleri (`unreachable_unchecked`'a ulaşma, örtüşen aralıklarla `copy_nonoverlapping` çağırma); yetersiz hizalanmış bellek erişimleri ve referanslar; temel tip değişmezi ihlalleri (0 veya 1 olmayan `bool`, geçersiz enum discriminant); veri yarışları ve bazı zayıf bellek etkilerinin emülasyonu; Stacked ve Tree Borrows aliasing ihlalleri (deneysel); bellek sızıntıları, yani program sonunda ulaşılamayan ayrılmış bellek.

**Miri'nin yakalayamadıkları.** Rust spesifikasyonunun her ihlalini yakalayamaz, çünkü formel bir spesifikasyon yoktur. Determinizm sorunu vardır: Miri programın olası birçok yürütmesinden birini test eder ve yalnızca farklı bir olası yürütmede ortaya çıkan hataları kaçırır; bellek yerleşimi ve iş parçacığı interleaving'i tek bir yürütme üzerinde test edilir. Platform API'lerine ve FFI'ye erişimi yoktur ve ağ desteklenmez; Argus için bu, HTTP sunucusu tarafının Miri altında koşturulamayacağı, yalnızca saf iş mantığı birim testlerinin koşturulabileceği anlamına gelir. Zayıf bellek emülasyonu tam değildir ve Miri'nin asla üretmeyeceği yasal davranışlar vardır. En önemlisi Miri kodun sağlam olduğunu temelden garanti edemez; tanımsız davranışı belirli yürütmelerde bulur, keyfi safe kod kombinasyonlarıyla tüm olası çağrılarda değil. Ayrıca integer'dan pointer'a cast yapan programlar tam desteklenmez ve kullanıcı uyarılır; Stacked ve Tree Borrows aliasing kontrolü veri yarışı dedektörünün yerini tutmaz ve model raw pointer'ları ile interior-mutable paylaşımlı referansları kasten kısıtlamaz.

**CI maliyeti.** Miri bir yorumlayıcıdır ve native yürütmeye göre büyüklük mertebelerinde yavaştır. Pratikte tipik olarak 10-100 kat yavaşlama beklenmelidir; bu bir tahmindir ve kesin bir çarpan bu araştırmada doğrulanamamıştır. Pratik yaklaşım Miri'yi her PR'da değil, gecelik olarak ve yalnızca saf veya unsafe içeren crate'lerin birim testlerinde koşturmaktır.

### 3.2 Loom

Testleri birçok kez çalıştırır ve olası eşzamanlı yürütmeleri permüte eder; C11 bellek modelini modeller ve işletim sistemi zamanlayıcısı ile Rust bellek modelini simüle ederek tüm olası geçerli davranışların keşfedilip test edilmesini sağlar.

Kapsamı iş parçacığı zamanlama permütasyonları, çeşitli memory ordering'lerle atomik işlemler (SeqCst, Acquire ve Release), mutex, rwlock, condvar ve channel, `UnsafeCell` ile kombinatoryal patlamayı azaltmak için durum indirgemedir.

Sınırları şunlardır. Müdahalecidir: yalnızca Loom'un replacement tiplerini kullanan kod modellenir ve Loom'dan gizlenen işlemler izlenmez; Argus'ta `std::sync` yerine `loom::sync` kullanan `cfg(loom)` yolları yazmak gerekir. Relaxed ordering'i tam modelleyemez; tek iş parçacığı içindeki yeniden sıralamaları tam kapsamaz. `MAX_THREADS` sınırı vardır, çünkü interleaving'ler üstel büyür. Kombinatoryal patlama nedeniyle `LOOM_MAX_PREEMPTIONS` genelde 2 veya 3'e ayarlanır ve bu, eksiksizliği feda eder. Büyük modellerde exhaustive kontrol çok uzun sürer.

**Bakım durumu.** crates.io'ya göre son sürüm 0.7.2'dir ve 23 Nisan 2024 tarihlidir; öncekiler 0.7.1 (2 Ekim 2023) ve 0.7.0'dır (4 Ağustos 2023). Toplam 62.875.383 indirme almıştır. GitHub'da 2025 ve 2026'da yalnızca beş commit vardır: 20 Şubat 2026 (yazım düzeltmesi), 12 Ocak 2026 (`RwLock`'a `?Sized` bound), 17 Nisan 2025, 14 Nisan 2025 ve 11 Şubat 2025. docs.rs özeti 0.7.2 için 31 Ağustos 2026 tarihini göstermektedir; bu muhtemelen doküman build tarihidir ve crates.io API'si otoriter kabul edilmiştir.

Sonuç olarak Loom çalışmaktadır ve yaygın kullanılmaktadır, ancak aktif geliştirilmemektedir; iki yıldan uzun süredir yeni sürüm yoktur.

### 3.3 Shuttle

AWS'nin randomize eşzamanlılık testi aracıdır ve "A Randomized Scheduler with Probabilistic Guarantees of Finding Bugs" araştırmasına dayanır.

Loom'dan farkı exhaustive değil olasılıksal olmasıdır; sağlam değildir, yani geçen bir Shuttle testi kodun doğru olduğunu kanıtlamaz, ancak çok daha büyük test senaryolarını kaldırabilir.

`std::sync` (Arc, Mutex ve diğerleri), `std::collections` ile tokio ve rand gibi popüler kütüphanelerin primitiflerini sarmalar.

Aktiftir: `shuttle` 0.9.3 (20 Ağustos 2026), 0.9.2 (12 Ağustos 2026) ve 0.9.1 (21 Nisan 2026). Repo 319 commit ve 1.100 yıldıza sahiptir, Apache-2.0 lisanslıdır.

> **Argus için.** Küçük ve kritik primitifler için exhaustive olan Loom, büyük entegrasyon senaryoları için randomize olan Shuttle kullanılır. Kani eşzamanlılığı desteklemediği için bu ikisi zorunludur.

### 3.4 Fuzzing ve property testing

| Araç | Sürüm ve tarih | İndirme | Not |
|---|---|---|---|
| `cargo-fuzz` (libFuzzer) | 0.13.2, 9 Haziran 2026 | 4.482.797 | crates.io, 8 Eylül 2026 |
| `proptest` | 1.11.0, 24 Mart 2026 | 182.638.062 | crates.io, 8 Eylül 2026 |
| `bolero` | 0.13.4, 3 Temmuz 2025 | 5.406.604 | Fuzz ve property testing ön yüzüdür |

Kani'nin bunlarla karşılaştırması şudur. Fuzzing yönlendirilmemiş rastgele testtir; çökme veya tanımsız davranış gibi genel özellikleri arar ve evrimsel algoritmalar kullanır. Property testing yönlendirilmiş rastgeleleştirmedir; ancak motor özelliği tam olarak ispatlayamaz, yalnızca değerlerden birkaçını rastgele örnekleyerek test edebilir. Model checking, yani Kani, rastgele değildir ve exhaustive'dir, ancak genellikle girdi veya problem boyutunda bir sınıra kadar; program izlerini sembolik SAT veya SMT problemleri olarak kodlar.

**Kritik veri noktası.** s2n-quic'te `try_fit` hatasını fuzzing 16,7 milyon iterasyonda bulamamış, Kani 20 saniyede bulmuştur. Ancak tersi de doğrudur: `decode_packet_number` taşmasını fuzzing de bağımsız olarak bulmuştur. Fuzzing ile model checking rakip değil tamamlayıcıdır.

**Bolero'nun köprü rolü.** s2n-quic'te tek bir öznitelikle aynı harness hem fuzz hedefi hem Kani ispatı olarak çalışmaktadır. Argus için önerilen omurga budur.

### 3.5 Sanitizer'lar

Hepsi yalnızca nightly'de kullanılabilir (`-Zsanitizer=...`). Test ve fuzzing için ASan, HWASan, LSan, MSan, RealtimeSanitizer ve TSan bulunur. Üretimde kullanılabilir olanlar CFI, KCFI, DataFlowSanitizer, MemTagSanitizer, SafeStack ve ShadowCallStack'tir.

Platformlar şöyledir: ASan x86_64 ve aarch64 üzerinde Linux, macOS, FreeBSD ve Fuchsia'da; TSan x86_64 ve aarch64 üzerinde Linux, macOS ve FreeBSD'de; MSan x86_64 ve aarch64 üzerinde Linux ve FreeBSD'de.

TSan uyarıları Argus için kritiktir: `std::sync::atomic::fence` desteklenmez, inline assembly ile senkronizasyon desteklenmez, kısmi enstrümantasyon yanlış pozitif üretir ve std'nin `-Zbuild-std` ile yeniden derlenmesi önerilir.

MSan'da tüm program kodunun enstrümante edilmesi zorunludur; C ve C++ bağımlılıkları Clang `-fsanitize=memory` ile yeniden derlenmelidir, aksi hâlde yanlış pozitif oluşur. CFI için `-Clto` veya `-Clinker-plugin-lto` gerekir.

> **Argus için.** rustls'in yaptığı gibi `forbid(unsafe_code)` politikası uygulanırsa ASan ve MSan'ın marjinal değeri düşer. TSan yine de değerlidir, çünkü safe Rust'ta bile FFI sınırlarında ve unsafe kripto bağımlılıklarında yarış olabilir. CFI ise derleme sertleştirmesi olarak üretimde açılmaya değerdir.

---
## 4. Argus bileşenlerine uygulanabilirlik

Aşağıdaki efor tahminleri kaynaklı değildir; Hifitime'ın 153 ispatı, Firecracker'ın 34 harness'ı ve 21 dakikası ile s2n-quic'in 102 harness'ı gibi analog projelerden türetilmiş mühendislik yargılarıdır.

### 4.1 Bileşen bazlı harita

| # | IdP bileşeni | En uygun araç | İfade edilecek özellik | Efor (tahmin) | Gerekçe |
|---|---|---|---|---|---|
| 1 | JWT ve JOSE parser'ı (compact serialization) | Sınırlı ölçüde Kani; birincil araç cargo-fuzz | N bayta kadar herhangi bir girdi için parser panic etmez, tanımsız davranış üretmez ve `alg` alanı asla `none`'a düşmez | Kani ile 2-4 hafta ve sınırlı değer; fuzz ile 3-5 gün ve yüksek değer | Kani dokümantasyonu parser'lar için 10-20 ve daha fazla karakterlik girdi gerektiğini ve bunun ölçeklenmediğini açıkça söyler |
| 2 | base64, CBOR ve ASN.1 (DER) decoder'ları | Sabit ve küçük N için Kani, ayrıca fuzz ve Miri | 32 bayta kadar girdi için panic ve sınır aşımı yoktur, `decode(encode(x)) == x` sağlanır | Decoder başına Kani ile 1-2 hafta | Hifitime'da encode-decode özdeşlik ispatları böyle yapılmıştır |
| 3 | Sabit zamanlı karşılaştırma (HMAC ve token eşitliği) | Hiçbir araç tam çözmez; `subtle` crate'i, kod incelemesi ve dudect tarzı istatistiksel test | Karşılaştırma süresi girdi verisinden bağımsızdır | — | Bu bir zamanlama ve yan kanal özelliğidir; Kani, Verus, Creusot ve Flux'un hiçbiri zamanlamayı modellemez. libcrux bile derlenmiş yürütülebilir dosyaların yan kanal direnci için doğrulanmadığını söyler. `subtle` 2.6.1 (24 Haziran 2024), 682 milyon indirme |
| 4 | Protokol durum makineleri (OAuth2 ve OIDC akışları, device code, PKCE) | Senkron çekirdek için Verus, actor modeli için Stateright, protokol seviyesi için TLA+ veya hax ile ProVerif | Yetkilendirme kodu asla iki kez kullanılamaz; state parametresi eşleşmeden token verilmez; PKCE verifier olmadan kod değiştirilemez | Verus ile 4-8 hafta; Stateright ile 2-3 hafta | Verus'ta TLA+ gömülmesi mevcuttur; Stateright liveness için deneysel ve eksiktir. Protokol seviyesi güvenlik için Fett, Küsters ve Schmitz'in web modeli referanstır (arXiv 1601.01229, CCS 2016); OAuth 2.0'da dört yeni saldırı bulunmuştur ve bunlar OpenID Connect'te de mevcuttur |
| 4b | Koddan implementasyona köprü | Differential random testing; Cedar deseni | Rust implementasyonu, Lean veya Dafny referans modeliyle her girdide aynı kararı verir | 3-6 hafta | Cedar tam olarak bunu yapar: Lean modeli ispatlanır, Rust implementasyonu ispatlanmaz ve differential random testing ile karşılaştırılır; gecelik yaklaşık 100 milyon test koşulur |
| 5 | Erişim kontrolü ve politika değerlendirme | Cedar doğrudan kullanılır, ya da Cedar deseni kopyalanır (Lean modeli ve DRT); alternatif Verus'tur | Yalnızca `permit` politikası izin verir ve hata veya varsayılan yoluyla izin doğmaz; `forbid` her koşulda `permit`'i ezer; validator kabul ederse değerlendirme belirli hata sınıflarına düşmez | Cedar kullanımı günler alır; kendi motorunu ispatlamak 3-6 ay sürer | Bu üç özellik Cedar'da fiilen ispatlanmıştır: Explicit Permit, Forbid Overrides Permit ve Validator Soundness. Cedar OOPSLA 2024'te yayımlanmıştır. Model artık Lean 4'tedir ve `cedar-spec` deposu 4 Eylül 2026'da hâlâ aktiftir. Ancak README açıkça Rust kodunun doğrulanmadığını belirtir |
| 6 | Oturum ömrü ve saat aritmetiği (skew, expiry, `nbf`, `exp`, `iat`, leap second) | Kani; en iyi uyum | Herhangi bir `now`, `iat`, `exp` ve `skew` için taşma yoktur; `is_expired` monotondur; `exp < now - skew` ise reddedilir; `PartialEq` ve `Ord` tutarlıdır | 1-3 hafta ve çok yüksek getiri | Hifitime bunun kanıtıdır. Kani orada tam bu sınıfta altı gerçek hata bulmuştur. Bir IdP'de `Ord` tutarsızlığı doğrudan süresi dolmuş token'ın kabul edilmesi demektir |
| 7 | Kripto yapıştırma kodu (nonce üretimi, key wrapping, KDF çağrıları, algoritma seçimi) | Stub'lu Kani ve `aws-lc-rs` gibi doğrulanmış altyapı; ileri seviyede hax ile Aeneas ve Lean | Nonce asla tekrar kullanılmaz; anahtar materyali zeroize edilir; desteklenmeyen `alg` reddedilir | Kani ile 1-2 hafta; Aeneas ve Lean ile altı aydan fazla ve bir Lean uzmanı | Kani `#[kani::stub]` ile RNG ve saat okumayı nondeterministik değerlerle modelleyebilir; bu tam olarak Firecracker rate limiter'ında yapılmıştır. Kripto primitifleri kendimiz ispatlanmaz; SymCrypt ve AWS-LC bunu zaten yapmıştır |
| 8 | Oran sınırlayıcı ve brute-force koruması | Kani; kanıtlanmış uyum | Herhangi bir istek dizisi ve saat değeri için T penceresinde izin verilen istek sayısı bütçeyi aşmaz | 1 hafta ve çok yüksek getiri | Firecracker'ın rate limiter'ı Kani ile nondeterministik saat değerleri kullanılarak doğrulanmış ve %0,01 bütçe aşımına izin veren bir yuvarlama hatası bulunmuştur |
| 9 | İndeks, uzunluk ve tampon mantığı (header parsing offset'leri, buffer slicing) | Flux | Her erişimde `i < buf.len()` sağlanır; taşma yoktur; kapasite uzunluktan küçük değildir | 3-7 gün; en ucuz kazanç | Flux döngü invariantlarını otomatik çıkarır ve sınırsız doğrular; kutudan taşma, sıfıra bölme ve dizi sınırı kontrolü verir |
| 10 | Eşzamanlı oturum deposu, token cache'i ve iptal listesi | Küçük primitifler için Loom, büyük senaryolar için Shuttle, ayrıca TSan | Token iptali ile doğrulama arasında yarış yoktur; cache invalidation atomiktir | Loom ile 1-2 hafta | Kani burada kullanılamaz; eşzamanlı kodu sessizce sıralı işler. Kani dokümantasyonu bizzat Loom ve Shuttle'ı önerir. Verus VerusSync ile yapabilir ancak `Mutex` ve `RwLock` desteklemediği için `vstd` primitiflerine geçmek gerekir |
| 11 | HTTP katmanı ve async runtime (axum, tokio) | Hiçbir formel araç değil; yalnızca fuzz, entegrasyon testi ve Shuttle | — | — | Kani `await` desteklemez. Verus `async fn` ve `await` desteklemez. KMIR async ve await desteklemez. Miri'de ağ desteklenmez. Bu katman formel doğrulama kapsamı dışındadır |
| 12 | Serileştirme (serde) | Fuzz ve proptest ile round-trip | `deserialize(serialize(x)) == x` | 3-5 gün | Verus `serde::Serialize` desteklememektedir |

### 4.2 Önerilen katmanlı strateji

**Katman 0, taban, birinci ve ikinci hafta, zorunludur.** Çekirdek crate'lerde `#![forbid(unsafe_code)]` uygulanır; bu rustls desenidir. `cargo-fuzz` ve OSS-Fuzz kaydı yapılır; her parser için (JWT, base64, CBOR, DER, form-encoding) hedef yazılır. `proptest` ve `bolero` ile round-trip ve invariant testleri eklenir. Gecelik Miri koşusu yapılır; saf mantık testleri kapsanır, ağ ve FFI içeren testler hariç tutulur. CI'da CFI ile sertleştirilmiş release build alınır.

**Katman 1, ucuz formel, üçüncü ile sekizinci hafta.** Flux ile indeks, uzunluk ve taşma invariantları doğrulanır; en düşük anotasyon maliyetiyle sınırsız garanti verir. Kani autoharness ile başlanır: `cargo kani autoharness -Z autoharness` ile tüm saf ve `Arbitrary` uyumlu fonksiyonlar için otomatik panic ve tanımsız davranış taraması yapılır. Bu, std kampanyasında 16.748 harness üreten yaklaşımın aynısıdır. Generic fonksiyonlarda tek monomorfizasyon doğrulandığı için bunun bir under-approximation olduğu unutulmamalıdır. Ardından elle Kani harness'ları yazılır: saat ve expiry aritmetiği ile rate limiter. En yüksek getiri maliyet oranı buradadır.

**Katman 2, eşzamanlılık, altıncı ile onuncu hafta.** `cfg(loom)` yollarıyla oturum deposu ve iptal listesi primitifleri test edilir; `LOOM_MAX_PREEMPTIONS=3` kullanılır. Shuttle ile daha büyük entegrasyon senaryoları koşulur. Gecelik TSan `-Zbuild-std` ile çalıştırılır.

**Katman 3, ağır ispat, üçüncü ile dokuzuncu ay, yalnızca bir hedef seçilir.** Öneri politika ve erişim kararı motorudur. Ya doğrudan Cedar kullanılır — zaten Lean'de ispatlanmış model ve gecelik 100 milyon differential test vardır — ya da kendi motorumuz için Cedar deseni kopyalanır: referans model Lean veya Verus'ta yazılıp ispatlanır ve Rust implementasyonu differential random testing ile bağlanır. Alternatif olarak token ve oturum durum makinesi Verus'ta senkron ve I/O içermeyen bir çekirdek olarak yazılır.

**Yapılmayacaklar.** Kripto primitifleri kendimiz ispatlanmaya kalkışılmaz; SymCrypt, AWS-LC ve libcrux vardır. Async HTTP katmanı formel doğrulanmaya çalışılmaz; hiçbir araç desteklemez. Prusti veya MIRAI'ye bel bağlanmaz; ikisi de ölüdür. libcrux üretimde bakımcılara danışmadan kullanılmaz; sürümler 0.1'in altındadır. Tam parser doğrulaması hedeflenmez; Kani'nin kendi dokümantasyonu bunun ölçeklenmediğini söyler.

### 4.3 CI maliyeti

| Referans | Ölçek | Süre |
|---|---|---|
| Firecracker | 34 harness | 21 dakika |
| Rust std kampanyası | 16.748 harness | 69 dakika; paralelleştirme ve cache ile, 3,97 kat hızlanma sonrası |
| Hifitime Faz I | 158 harness | 57 tanesi 60 saniyelik bütçeyi aşmıştır |
| Hifitime Faz II, kontratlarla | 153 ispat | Çoğu beş saniyenin altında; en yavaşları 16,4 ve 13,6 saniye |

> **Ders.** Kontratlar (`requires`, `ensures`, `modifies`) yalnızca daha güçlü özellik değil, CI süresini düşüren bir modülerleştirme aracıdır. Hifitime'da harness sayısı 11'den 153'e çıkarken tek ispat süresi düşmüştür. Argus'ta da kontrat tabanlı modüler doğrulama monolitik harness'lardan daha sürdürülebilir olacaktır.

---

## 5. Uyarılar ve doğrulanamayanlar

1. verify-rust-std'de çözülmüş ve açık mücadele sayısı: aynı README'nin iki çekimi çelişkili sonuç vermiştir (7/22 ile 9/20; 315.000 USD ile 285.000 USD). Bağımsız hakemli kaynak (arXiv 2510.01072, Ekim 2025) 9/27 demektedir. Kesin güncel sayı doğrulanamamıştır. Mücadele sayısının 29 olduğu ve ödüllerin 10.000-25.000 USD aralığında bulunduğu doğrulanmıştır.
2. AWS'in toplam taahhüdü: Rust Foundation duyurusunda (20 Kasım 2024) belirli bir toplam rakam yoktur. README'deki tablodan toplam çıkarılabilir ancak iki çekim farklı toplam vermiştir; doğrulanamamıştır.
3. Kani'nin sekiz aylık sürüm boşluğunun nedeni doğrulanamamıştır. Proje ASE 2026 makalesiyle (1 Temmuz 2026) canlı görünmektedir ancak sürüm ve blog kadansı durmuştur.
4. Verus'un ispat ile kod oranı: SOSP 2024 PDF'i ayrıştırılamamış ve güvenilir sayı bulunamamıştır; bütçelemede varsayım olarak kullanılmamalıdır.
5. Miri'nin yavaşlama çarpanı: kaynaklarda somut sayı bulunamamıştır; 10-100 kat bir tahmindir.
6. Tokio'nun Kani'yi sürekli CI'da kullanıp kullanmadığı: yalnızca 2022 tarihli bir vaka çalışması blog yazısı bulunmuş, sürekli kullanım doğrulanamamıştır.
7. Endor Labs'in MIRAI fork'unun 2026 durumu incelenmemiştir.
8. Soteria-Rust ve RefinedRust'ın güncel aktivite düzeyi: depo URL'leri doğrulanamamıştır, 404 dönmüştür.
9. emergentmind.com AI üretimi bir agregatördür ve Verus hakkında yanlış bilgi içermektedir; birincil kaynak olarak kullanılmamalıdır.
10. Loom'un son sürüm tarihi: docs.rs özeti (31 Ağustos 2026) ile crates.io API'si (23 Nisan 2024) çelişmiştir; crates.io otoriter kabul edilmiştir.
11. Dördüncü bölümdeki efor tahminlerinin tamamı mühendislik yargısıdır ve hiçbir kaynakta yer almamaktadır.

---

## 6. Kaynaklar

**Kani.** github.com/model-checking/kani ve releases.atom; crates.io/api/v1/crates/kani-verifier; arXiv 2607.01504 ("Kani: A Model Checker for Rust", ASE 2026, 1 Temmuz 2026); model-checking.github.io/kani/ altındaki rust-feature-support, limitations, undefined-behaviour, tool-comparison, install-guide, tutorial-loop-unwinding, contracts ve autoharness sayfaları; model-checking.github.io/kani-verifier-blog (son yazı 10 Aralık 2024); github.com/model-checking/kani-github-action; aws.github.io/s2n-quic/dev-guide/kani.html. Hepsine 8 Eylül 2026'da erişilmiştir.

**verify-rust-std.** github.com/model-checking/verify-rust-std, README ve doc/src/SUMMARY.md; arXiv 2606.17374 ("Verifying the Rust Standard Library", NFM 2026, 16 Haziran 2026); arXiv 2510.01072 ("Lessons Learned So Far…", 1 Ekim 2025, revizyon 26 Ekim 2025); rustfoundation.org'un 1 Eylül 2026 ve 20 Kasım 2024 tarihli yazıları; devclass.com, 21 Kasım 2024; model-checking.github.io/verify-rust-std/tools/ altındaki verifast, kmir ve flux sayfaları.

**Verus, Creusot, Prusti, Flux, Aeneas ve MIRAI.** github.com/verus-lang/verus ve releases.atom, publications-and-projects, guide/overview, guide/features, guide/guarantees, guide/concurrency; Verus SOSP 2024 (DOI 10.1145/3694715.3695952) ve OOPSLA 2023 (DOI 10.1145/3586037); pldi26.sigplan.org'da VerusBelt; creusot.rs ve creusot releases.atom, POPL 2026 tutorial'ı; prusti-dev releases.atom ve commits/master.atom, pm.inf.ethz.ch/research/prusti.html; flux-rs.github.io/flux ve flux commits/main.atom, arXiv 2207.04034, DOI 10.1145/3591283, 19 Kasım 2025 tarihli UCSC kolokyumu; github.com/AeneasVerif/aeneas ve commits/main.atom, lean-lang.org/use-cases/aeneas, github.com/cryspen/hax, github.com/cryspen/libcrux; Microsoft Research'ün 13 Temmuz 2026 tarihli SymCrypt yazısı; github.com/facebookexperimental/MIRAI ile README ve commits/main.atom; arXiv 2410.01981 ("Surveying the Rust Verification Landscape", 2 Ekim 2024); rust-formal-methods.github.io; gitlab.mpi-sws.org/lgaeher/refinedrust-dev; github.com/formal-land/coq-of-rust.

**Miri, Loom, Shuttle, fuzzing ve sanitizer.** research.ralfj.de/papers/2026-popl-miri.pdf, plf.inf.ethz.ch/research/popl26-miri.html, DOI 10.1145/3776690 (POPL 2026); Miri README; docs.rs/loom, crates.io/api/v1/crates/loom, loom commits/master.atom; github.com/awslabs/shuttle ve crates.io/api/v1/crates/shuttle; crates.io API'sinde cargo-fuzz, proptest, bolero ve subtle; doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html.

**IdP'ye özgü.** github.com/cedar-policy/cedar-spec ile README ve commits/main.atom; amazon.science'ta Cedar OOPSLA 2024 yayını ve 10 Mayıs 2023 tarihli blog; arXiv 1601.01229 (Fett, Küsters ve Schmitz'in OAuth 2.0 formel analizi, CCS 2016); github.com/rustls/rustls SECURITY.md; github.com/awslabs/aws-lc-verification; github.com/stateright/stateright.

---
## AWS Cedar ile Lean 4 doğrulama güdümlü geliştirme ve AWS'nin uygulamalı formel metot portföyü

Rapor tarihi 8 Eylül 2026'dır. Bağlam, Rust ile sıfırdan yazılan ve Keycloak sınıfı bir IdP olan Argus için Cedar ve Lean yaklaşımının tekrarlanabilirliğidir.

Aşağıdaki nicel verilerin bir kısmı yayınlardan, bir kısmı `cedar-spec` deposunun 4 Eylül 2026 tarihli `3a19359` commit'i üzerinde yapılan doğrudan ölçümlerden gelmektedir. Ölçümle elde edilenler açıkça belirtilmiştir; doğrulanamayanlar da işaretlenmiştir.

### 1. Cedar yetkilendirme dili

#### 1.1 OOPSLA 2024 makalesi

Künye: "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization", Proceedings of the ACM on Programming Languages, Cilt 8, OOPSLA1, Makale 118, Nisan 2024. Genişletilmiş sürüm arXiv 2403.04651'dedir; v1 7 Mart 2024, v2 8 Mart 2024 tarihlidir ve CC-BY 4.0 lisanslıdır.

Yazarları on altı kişidir: Joseph W. Cutler, Craig Disselkoen, Aaron Eline, Shaobo He, Kyle Headley, Michael Hicks, Kesha Hietala, Eleftherios Ioannidis, John Kastner, Anwar Mamat, Darin McAdams, Matt McCutchen, Neha Rungta, Emina Torlak ve Andrew Wells.

Makalenin üç ana katkı iddiası şudur: Cedar'ın tasarımı, implementasyonu ve değerlendirmesi; SMT'ye çevrilebilen güvenli politikaları kabul etmek üzere tasarlanmış doğrulanmış bir validator; Cedar'ı SMT'nin karar verilebilir bir fragmanına indirgeyen doğrulanmış bir sembolik derleyici.

#### 1.2 Neden Turing complete değil

Cedar bilinçli olarak ifade gücünü kısıtlar. Genel özyineleme ve sınırsız döngü yoktur; yalnızca doğrusal zamanlı döngü yapıları bulunur. Kullanıcı tanımlı fonksiyon yoktur, yalnızca yerleşik operatörler vardır. Yan etki yoktur.

Makaleye göre güvenliğin üçüncü boyutu Cedar'ın yetkilendiricisinin deterministik olmasıdır: sonlanacağı garanti edilir ve belirli bir istek, hiyerarşi ile politika kümesi için her zaman aynı yetkilendirme kararını üretir. Cedar politikaları yan etkilerden ve genel döngülerden arınmış olduğu için politika değerlendirme sırası önemsizdir.

Datalog ve Rego'nun tercih edilmeme gerekçesi şudur. Open Policy Agent, Rego adlı Datalog tabanlı bir dil kullanan açık kaynak bir yetkilendirme sistemidir ve Rego, diğer Datalog tabanlı diller gibi Cedar'dan daha ifadelidir; kullanıcıların kendi kanıt önceliklendirme ve birleştirme kavramlarını ile veri hiyerarşilerini tanımlamalarına imkân verir.

Yani AWS'nin argümanı Rego'nun yetersiz olduğu değil, tam tersidir: Rego fazla ifade gücüne sahip olduğu için sağlam ve tam bir SMT kodlaması yapılamamaktadır. Cedar bilinçli olarak ifade gücünü feda edip analiz edilebilirliği satın almaktadır.

XACML üzerine ilgili tespit şudur: makale, Hughes ve Bultan'ın XACML alt kümesini SAT'a çeviren çalışması için kodlamalarının ne sağlam ne tam olduğunu söyler; Cedar'ın farkı tam da budur.

OpenFGA ve Zanzibar'ın tercih edilmeme gerekçesi Cedar'ın RBAC, ABAC ve ReBAC'ı birlikte ifade edebilmesidir; makale OpenFGA'nın iki örnek uygulamasını Cedar'da yeniden modellemektedir.

#### 1.3 Performans

| Karşılaştırma | Sonuç |
|---|---|
| Cedar ile OpenFGA | 28,7 ile 35,2 kat arası daha hızlı |
| Cedar ile Rego (OPA) | 42,8 ile 80,8 kat arası daha hızlı |
| Policy slicing kazancı | Ortalama 10,0 ile 18,0 kat arası |
| SMT analiz sorgusu (kodlama ve çözme) | Ortalama 75,1 ms |

#### 1.4 Analiz edilebilir fragman ve SMT karar verilebilirliği

Cedar politikaları SMT-LIB'in karar verilebilir bir fragmanına indirgenir. Kodlama hem sağlamdır, yani aşırı yaklaşımdır, hem tamdır, yani alt yaklaşımdır; dolayısıyla ne yanlış alarm ne kaçırılan ihlal oluşur. Entity store'lar yorumlanmamış fonksiyonlar ve sabitlerle kodlanır ve şemaya uyan tüm somut store'ları temsil eder. Niceleyiciler kullanılmaz; bunun yerine sonlu ve ground iyi biçimlilik kısıtları kullanılır, çünkü niceleyici kullanmak karar verilebilirliği kırardı.

Tip sistemi iki yenilik kullanır. Singleton tipler (`True` ve `False`) ulaşılamayan dalları budayarak yanlış alarmları önler. Statik yetenekler ise `resource has f` doğruysa `resource.f` erişiminin güvenli olduğunu kaydeder.

### 2. `cedar-spec` deposu ve Lean 4 modeli

Depo github.com/cedar-policy/cedar-spec adresindedir ve Apache-2.0 lisanslıdır.

#### 2.1 Depo yapısı

Ölçüm commit `3a19359` üzerinde, 4 Eylül 2026'da yapılmıştır.

| Dizin | İçerik |
|---|---|
| `cedar-lean/` | Lean 4 formalizasyonu ve ispatlar |
| `cedar-drt/` | Fuzzing, property-based testing ve differential testing |
| `cedar-lean-ffi/` | Rust ile Lean arasındaki FFI köprüsü |
| `cedar-lean-cli/` | Lean modeli üzerinde CLI |
| `cedar-policy-generators/` | `arbitrary` crate'i ile şema, entity ve politika üreteçleri |
| `cedar-benchmarking/` | Performans ölçümü |

Lean sürümü `leanprover/lean4:v4.33.1`'dir (`lean-toolchain` dosyası, 4 Eylül 2026).

#### 2.2 Gerçek kod büyüklükleri

Ölçüm 4 Eylül 2026 tarihlidir. Bu, raporun en değerli kısımlarından biridir, çünkü 2024 makalesindeki sayılar ciddi ölçüde eskimiştir.

Model, yani spesifikasyon katmanı, `cedar-lean/Cedar/` altında `Thm` hariç:

| Modül | Satır |
|---|---|
| `Cedar/Spec` (17 dosya) | 2.138 |
| `Cedar/Validation` (8 dosya) | 1.754 |
| `Cedar/Data` (6 dosya) | 994 |
| `Cedar/SymCC` (22 dosya) | 4.477 |
| `Cedar/SymCCOpt` | 999 |
| `Cedar/TPE` | 1.125 |
| `Cedar/Slice` | 73 |
| Model toplamı | 11.560 |

İspat katmanı `Cedar/Thm/` altında 198 dosya ve 71.987 satırdır:

| Alt dizin | Satır |
|---|---|
| `Thm/SymCC` | 39.471 |
| `Thm/Validation` | 11.583 |
| `Thm/Data` | 7.481 |
| `Thm/TPE` | 5.555 |
| `Thm/WellTyped` | 3.413 |
| `Thm/Authorization` | 977 |
| `Thm/BatchedEvaluator` | 378 |

Destek katmanında `CedarProto` ve `Protobuf` 6.432 satır, `SymTest` 3.649 satır, `UnitTest` 2.481 satır, `CedarFFI` 1.151 satır ve `DiffTest` 164 satırdır. `cedar-lean` altındaki tüm `.lean` dosyaları 352 dosya ve 98.549 satırdır.

İspat sağlığı ölçümü şudur: 1.772 `theorem` ve iki `lemma` bulunmaktadır; `sorry` sayısı sıfırdır, yani hiçbir ispat boşluğu bırakılmamıştır; `axiom` sayısı sıfırdır, yani Lean çekirdeği dışında ek aksiyom yoktur. Bu iki sıfır çok önemlidir: ispatlar gerçekten kapalıdır. Birçok akademik formalizasyonda `sorry` veya `admit` kalıntıları bulunur; burada yoktur.

Oranlar şöyledir. İspatın modele oranı 71.987 bölü 11.560, yani yaklaşık 6,2'ye 1'dir. 2024 makalesindeki oran 5.714 bölü 1.673, yani yaklaşık 3,4'e 1'dir. İki yılda hem mutlak büyüklük yaklaşık yedi kat artmış hem de ispat yoğunluğu neredeyse iki katına çıkmıştır; sebebi SymCC ve TPE gibi ağır meta-teorinin eklenmesidir.

> **Not.** Bir kaynak özetinde bu oran 13,4'e 1 olarak geçmiştir; makalenin kendi tablosundaki sayılardan (5.714 bölü 1.673) hesaplandığında 3,4'e 1 çıkmaktadır. Kendi hesabımız esas alınmıştır.

#### 2.3 Lean'de gerçekte neler ispatlanıyor

Aşağıdaki teorem adları `cedar-spec` kaynak kodundan birebir alınmıştır (4 Eylül 2026).

**Yetkilendirme semantiği, `Cedar/Thm/Authorization.lean`.**

| Lean teoremi | Anlamı |
|---|---|
| `forbid_trumps_permit` | Bir `forbid` sağlanıyorsa istek reddedilir |
| `allowed_only_if_explicitly_permitted` | İzin ancak açık bir `permit` ile verilir |
| `default_deny` | Açıkça izin verilmemişse reddedilir |
| `allowed_iff_explicitly_permitted_and_not_denied` | İzin, permit varlığı ve forbid yokluğuna denktir |
| `denied_iff_explicitly_denied_or_not_permitted` | Ret, forbid varlığı veya permit yokluğuna denktir |
| `order_and_dup_independent` | Politika sırası ve tekrarları kararı değiştirmez |
| `unchanged_allow_when_add_permit` | Yeni `permit` eklemek mevcut izni bozmaz |
| `unchanged_deny_when_add_forbid` | Yeni `forbid` eklemek mevcut reddi bozmaz |

**Politika dilimleme, `Cedar/Thm/PolicySlice.lean`.** Teoremler `isAuthorized_eq_for_sound_policy_slice` (sağlam bir dilim tam küme ile aynı kararı verir), `sound_bound_analysis_produces_sound_slices`, `scope_bound_is_sound`, `scope_analysis_is_sound` ve `isAuthorized_eq_for_scope_based_policy_slice`'tır. Bu, Argus için doğrudan önemlidir: indeksleme ve önbellekleme optimizasyonunun kararı değiştirmediği ispatlanmıştır.

**Tip denetleyici sağlamlığı, `Cedar/Thm/Typechecking.lean`.** Burada kritik bir nüans vardır. Teoremin doküman yorumuna göre tip denetimi başarılı olursa, şemayla tutarlı herhangi bir istek için ya değerlendirme bir boolean üretir ya da `entityDoesNotExist`, `extensionError` veya `arithBoundsError` tipinde bir hata döner. İki seçenek de `EvaluatesTo` predicate'inde kodlanmıştır. Tip denetleyici bu hatalara karşı koruyamaz, çünkü yetkilendirme anında sağlanacak entity'ler ve bağlam hakkında bilgisi yoktur ve aritmetik operatörlerin semantiği hakkında akıl yürütmez.

```lean
theorem typecheck_is_sound (policy : Policy) (env : TypeEnv) (t : CedarType)
    (request : Request) (entities : Entities) :
  InstanceOfWellFormedEnvironment request entities env →
  typecheck policy env = .ok t →
  (∃ (b : Bool), EvaluatesTo policy.toExpr request entities b)
```

> **Argus için uyarı.** Validator geçtiyse hiç hata olmayacağı okuması yanlıştır. Doğrusu şudur: tip hatası olmaz, ancak `entityDoesNotExist`, `extensionError` (örneğin hatalı IP veya decimal) ve `arithBoundsError` (tamsayı taşması) hâlâ olabilir. Bu üç hata sınıfı çalışma zamanında yönetilmek zorundadır.

**Seviye tabanlı entity dilimleme, `Cedar/Thm/Validation/Levels.lean`.** Bir ifade iyi tipliyse ve azami entity dereference seviyesi n'i aşmıyorsa, herhangi bir entity kümesi için ifadenin n seviyesinde dilimlenmiş entity'lerle değerlendirilmesinin sonucu, orijinal entity kümesiyle değerlendirilmesinin sonucuyla aynıdır. Pratik anlamı şudur: bir IdP'de veritabanından kaç seviye entity çekilmesi gerektiği statik olarak sınırlandırılabilir ve bunun kararı değiştirmediği bilinir. Argus için doğrudan uygulanabilir bir fikirdir.

**Sembolik derleme, `Cedar/Thm/SymbolicCompilation.lean`.** Teoremler `compile_is_sound`, `compile_is_complete`, `isAuthorized_is_sound`, `isAuthorized_is_complete` ve `compile_well_typed`'dır; sonuncusu iyi tipli ifadelerin daima başarıyla derlendiğini söyler.

**Analiz doğruluğu, `Cedar/Thm/Verification.lean`.** `verifyNeverErrors`, `verifyAlwaysMatches` ve `verifyNeverMatches` için hem sağlamlık hem tamlık teoremleri mevcuttur; ayrıca kesme işaretiyle biten alternatif formülasyonlar vardır.

**Tip farkında kısmi değerlendirme, `Cedar/Thm/TPE.lean`.** Teoremler `reauthorize_is_sound`, `partial_authorize_decision_is_sound`, `partial_re_authorize_decision_eq`, `partial_authorize_erroring_policies_is_sound`, `partial_authorize_allow_determining_policies_is_sound`, `partial_authorize_satisfied_permits_not_determining_if_deny` ve `partial_authorize_satisfied_forbid_is_determining`'dir. TPE, RFC 0095 ile tanımlanmıştır.

**Sonlanma.** Lean'de tüm fonksiyonlar toplam olmak zorundadır; dolayısıyla sonlanma, modelin Lean'de tip denetiminden geçmesiyle otomatik olarak elde edilir ve ayrı bir teorem değildir. Bu, Lean seçiminin maliyetsiz kazanımlarından biridir.

2024 makalesi ("How We Built Cedar", arXiv 2407.01688, 1 Temmuz 2024) yedi özelliği listeler: Forbid Trumps Permit, Default Deny, Explicit Allow, Order Independence, Sound Slicing, Validation Soundness ve Termination. Makale validation soundness'ı şimdiye kadarki en zahmetli ispat olarak niteler.

### 3. Differential random testing: mimari ve gerçek garanti

#### 3.1 Rust, Lean'den üretilmiyor

Net cevap şudur: Rust kodu elle yazılmıştır, Lean'den çıkarılmamıştır.

Mike Hicks (AWS Senior Principal Scientist), Amazon Science blogunda 10 Mayıs 2023'te yetkilendirici için Dafny modelinin kod satırı sayısının yaklaşık altıda bir olduğunu belirtmiştir; modeller referans spesifikasyondur ve üretim kodu elle Rust'ta yazılmıştır.

Tarihsel not: bu blog Dafny dönemine aittir; Lean'e geçiş sonradan olmuştur.

#### 3.2 FFI köprüsü

`cedar-lean-ffi/README.md` dosyasına göre (4 Eylül 2026) bu dizin Cedar'ın Lean formalizasyonuyla etkileşim için Rust binding'leri içerir; FFI, Rust'taki Cedar tiplerini Lean formalizasyonundaki karşılık gelen tiplere çevirmek için Cedar'ın Protobuf özelliğini kullanır.

Mekanizma zinciri şudur.

Lean tarafında `@[export]` ile C sembolleri açılır. `CedarFFI` modülü (1.151 satır Lean) fonksiyonları C ABI'ye açar. Ölçülen giriş noktaları şunlardır:

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

İmza deseni dikkat çekicidir: `ByteArray`'den `String`'e. Yani sınırdan zengin tip değil, serileştirilmiş bayt geçer.

Lean statik kütüphane olarak derlenir; `cedar-lean-ffi/build_lean_lib.sh` şunu yapar:

```bash
cd ../cedar-lean/
lake update
lake build Cedar:static Protobuf:static CedarProto:static \
           Cedar.SymCC:static CedarFFI:static Batteries:static
```

Rust tarafında `unsafe extern "C"` ve `libleanshared.so` kullanılır. Ölçülen dosyalar `cedar-lean-ffi/src/lean_ffi.rs:56` (`unsafe extern "C"` bloğu), `lean_ffi.rs:39-40` (`lean_initialize_runtime_module_locked`, `lean_initialize_thread`, `lean_io_mark_end_initialization`, `lean_io_mk_world`, `lean_dec`, `lean_finalize_thread`), `cedar-lean-ffi/build.rs:52-55` (`cargo:rustc-link-search=native=...` ile Lean build dizini ve Batteries paketi) ve `lean_object.rs`'tir (`lean_object` işaretçileri üzerinde tip güvenli sarmalayıcılar).

Sınırdaki veri formatı Protobuf'tur; `protoc` v29.3 ile test edilmiştir. Rust `cedar-policy` crate'inin `protobufs` özelliği kullanılır ve `prost = "0.14"` bağımlılığı vardır. Çalışma zamanında `libleanshared.so` yüklenmelidir (`source set_env_vars.sh`).

Özet mimari şudur:

```
Rust fuzz target (libfuzzer)
   ├─→ cedar-policy (üretim Rust)             ─┐
   └─→ cedar-lean-ffi                          ├─→ çıktılar karşılaştırılır
         ├ Cedar tipleri → Protobuf (prost)    │
         ├ extern "C" → @[export] Lean fn      │
         ├ libleanshared.so + Lean statik libs │
         └ Lean modeli (referans semantik)    ─┘
```

#### 3.3 Fuzzing altyapısı

Ölçüme göre 79 fuzz hedefi bulunmaktadır (`cedar-drt/fuzz/fuzz_targets/`). Motor `libfuzzer-sys = "0.4"` ve `cargo-fuzz`'dır. Girdi üretimi `arbitrary` crate'iyle yapılır; `cedar-policy-core`'un `arbitrary` özelliği kullanılır. `bolero` kullanılmamaktadır; depoda hiçbir `Cargo.toml` dosyasında `bolero` geçmemektedir.

Hedef kategorileri şunlardır. Model ile Rust arasındaki DRT hedefleri: `abac-type-directed`, `rbac-authorizer`, `eval-type-directed`, `validation-drt`, `level-validation-drt`, `entity-slicing-drt-type-directed`, `batched-evaluation-drt`, `tpe-is-authorized-drt`, `tpe-residual-reauthorize-drt`. SymCC DRT hedefleri yaklaşık yirmi tanedir: `symcc-term-drt-equivalent`, `symcc-term-drt-implies`, `symcc-term-drt-disjoint`, `symcc-term-drt-never-errors`, `symcc-cex-drt`, `symcc-smt-script-drt`, `symcc-check-*-ok`. Round-trip property based test hedefleri: `roundtrip`, `formatter`, `policy-set-roundtrip`, `schema-roundtrip`, `json-schema-roundtrip`, `protobuf-roundtrip`, `pst-ast-roundtrip`. Genel PBT hedefleri: `simple-parser`, `wildcard-matching`, `entity-validation`, `request-validation`, `input-generation`.

Çalıştırma ölçeği (arXiv 2407.01688, 1 Temmuz 2024): AWS ECS üzerinde günlük olarak, desteklenen tüm Cedar sürümleri için; hedef başına 4 vCPU, 8 GB bellek ve altı saat. Amazon Science blogu (10 Mayıs 2023) gecelik yaklaşık 100 milyon testten söz etmektedir.

Performans açısından Lean yetkilendiricinin medyan süresi 6 µs, Rust'ın 10 µs'dir (arXiv 2407.01688). AWS blogu (8 Nisan 2024) 5 µs ile 7 µs vermektedir. Lean modelinin üretim kodundan hızlı olması differential random testing'i ekonomik kılan kritik faktördür.

#### 3.4 Dafny'den Lean'e göç

RFC 0032 ile yapılmıştır: başlangıç 12 Ekim 2023, kabul 24 Ekim 2023, iniş 26 Ekim 2023. Dafny formalizasyonu 8 Mart 2024'te `cedar-spec` v3.1.0 ile kullanımdan kaldırılmıştır. Gerekçe, Cedar'ın meta-teorik özelliklerini, örneğin validator sağlamlığını, ispatlamanın Dafny'nin otomasyonuna daha az uygun olmasıdır; meta-teori için etkileşimli bir kanıtlayıcı gerekiyordu. Kabul edilen bedel bir süre hem Dafny hem Lean ispatlarının desteklenmesi olmuştur.

Lean'in seçilme nedenleri (AWS blogu, 8 Nisan 2024): hızlı çalışma zamanı sayesinde differential random testing'in mümkün olması, zengin kütüphaneler (Batteries ve Mathlib) ve küçük güvenilen hesaplama tabanı.

#### 3.5 Gerçek garanti

Bu, Argus kararı için en kritik paragraftır.

Kanıtlanan şudur: Lean modeli 2.3'teki özellikleri sağlar ve bu matematiksel kesinliktir; `sorry` ve `axiom` sayıları sıfırdır.

Kanıtlanmayan şudur: Rust üretim kodunun Lean modeline eşdeğerliği. Bu yalnızca test edilir; milyonlarca rastgele girdiyle, ancak test testtir.

Zincir şöyledir:

```
[Lean modeli] --İSPAT (kesin)--> [güvenlik özellikleri]
      ↑
      | DRT (olasılıksal, ispat değil)
      ↓
[Rust üretim kodu] --> gerçekte çalışan şey
```

Makalenin kendi dürüst itirafında kaçırılan on hata belgelenmiştir (arXiv 2407.01688): validator'da sonlanmama, tetiklenme olasılığı çok düşük olduğu için fuzzer bulamamıştır; bozuk girdide parser çökmeleri, üreteç sınırlaması nedeniyle; şema parser'ının geçersiz öznitelik kabul etmesi.

Ayrıca bir kapsama tuzağı vardır: ilk turda üretilen koşulların %35,5'i önemsiz boolean sabitiydi ve makale tam satır kapsamasının tek başına etkili testi garanti etmediğini söylemektedir.

Bulunan hatalar toplam 25'tir; dördü ispat sırasında, yirmi biri DRT ve PBT ile bulunmuştur (altı authorizer parity, dört validator parity, altı parser roundtrip, iki formatter roundtrip ve üç validation soundness).

> **Argus için çıkarım.** Doğrulama güdümlü geliştirme kodun doğrulandığını söylemez; tasarımın doğrulandığını ve uygulamanın çok yoğun differential test edildiğini söyler. Bu hiç yapmamaktan kat kat iyidir, ancak Verus veya Kani ile Rust'ın kendisini doğrulamaktan farklıdır.

### 4. Sembolik derleyici ve 2025-2026 takipleri

#### 4.1 Cedar Analysis açık kaynak sürümü

AWS Open Source Blog, 16 Haziran 2025, yazarlar Spencer Erickson ve Liana Hadarean. Cedar Symbolic Compiler ve Cedar Analysis CLI yayımlanmıştır. SMT çözücü cvc5'tir. Lean'de sağlamlık ve tamlık ispatlıdır.

#### 4.2 `cedar-policy-symcc` crate'i

crates.io API'sinden (8 Eylül 2026):

| Alan | Değer |
|---|---|
| Açıklama | Symbolic Cedar Compiler; Cedar politikaları hakkındaki sorguları SMT'ye çevirir |
| Lisans | Apache-2.0 |
| En yeni sürüm | 0.6.0 (28 Temmuz 2026) |
| İlk sürüm | 0.1.0 (10 Kasım 2025) |
| Toplam indirme | 97.864 |

Sunulan analizler `never errors`, `always allows`, `always denies`, `implies` (subsumption), `equivalent` ve `disjoint`'tir; her birinin karşı örnek varyantı vardır. Gereksinimi `cvc5-1.3.1` ve `CVC5` ortam değişkenidir.

#### 4.3 SymCert, FMCAD 2026

Künye: Emina Torlak (AWS), "SymCert: Verifying SMT-Based Policy Analyses", Formal Methods in Computer-Aided Design 2026. Tam metin çıkarılmıştır (8 Eylül 2026).

Problem şudur: bu analizleri inşa etmek hataya açıktır; ince kodlama hataları sağlamlığı veya tamlığı sessizce bozabilir ve yalnızca testle yakalanması zordur.

Dört doğrulanmış yapı taşı vardır: sembolik derleyici, sembolik yetkilendirici, hiyerarşi zorlayıcı ve karşı örnek çıkarıcı. Sonuncusu sonsuz SMT modellerini sonlu Cedar girdilerine çevirir ve tamlık ispatı için şarttır.

**Modüler ispat yaklaşımı Argus için en aktarılabilir fikirdir.** Ana teorem, yani derleyici doğruluğu, iki genel özelliğe ayrıştırılır: reducibility, derleyicinin literal girdileri kısmi değerlendirmesidir; interpretability, derlemenin SMT değerlendirmesiyle yer değiştirmesidir. Makalenin ifadesiyle interpretability ve reducibility birlikte derleyici doğruluğunu maliyetsiz verir ve birinci teoremin Lean ispatı dört satır koddur.

Bunun işe yaramasının nedeni şudur: interpretability ve reducibility geçerlidir, çünkü tüm SymCert bileşenleri terimleri yalnızca factory fonksiyonlar üzerinden inşa eder ve her factory fonksiyonu tek tek interpretable ve reducible'dır.

Dafny'den alınan ders çok değerlidir: bu yaklaşım önce Dafny'de denenmiş ve Cedar'ın bir alt kümesi için yaklaşık 8.000 satır ispat üretilmiştir. Ortaya çıkan ispat kırılgan ve bakımı zordu; lemmaları yeniden kullanılamıyordu, çünkü birinci teoremin ifadesine sıkı biçimde bağlıydılar.

SymCert geliştirme metrikleri (Tablo I):

| Bileşen | Model satırı | Model saati | İspat satırı | İspat saati |
|---|---|---|---|---|
| Terimler ve factory'ler | 1.059 | — | 10.018 | — |
| Derleyici | 318 | 81 | 6.520 | 327 |
| Yetkilendirici | 16 | 1 | 411 | 11 |
| Zorlayıcı | 69 | 16 | — | — |
| Çıkarıcı | 211 | 13 | 4.798 | 167 |
| Çözücü (güvenilen, ispatsız) | 566 | 47 | 0 | 0 |
| Toplam | 2.239 | 158 | 21.747 | 505 |

Bazı satır içi hücreler PDF metin çıkarımında birleşmiştir; toplamlar kesindir ve alt bileşenlerle tutarlıdır.

Hesaplanan oranlar şunlardır: ispatın modele satır oranı 21.747 bölü 2.239, yani yaklaşık 9,7'ye 1'dir; saat oranı 505 bölü 158, yani yaklaşık 3,2'ye 1'dir; toplam çaba 663 kişi-saat, yani yaklaşık 83 kişi-gün veya dört kişi-aydır ve bu yalnızca tek bir alt sistem içindir.

Bakım ve genişletme maliyeti (Tablo II ve metin): beş analizi (`verifyDeniesAll`, `verifyAllowsAll`, `verifyImplies`, `verifyEquiv`, `verifyDisjoint`) modelleyip ispatlamak model tarafında 39 satır ve bir saatten az, ispat tarafında 512 satır ve yedi saat sürmüştür; makale bunun yalnızca bir iş günü aldığını söyler. Üç büyük yeni Cedar özelliği için genişletme her biri dört ile sekiz gün almıştır.

Performans (Tablo III, sekiz benchmark): sorgu üretimi 20 ms'nin, çözüm 40 ms'nin altındadır; sekiz benchmark'ın üçünde gerçek politika yazım hatası bulunmuştur (DocumentCloud iki, SalesOrgs iki, TinyTodo iki).

> **Argus için en önemli ders.** Modüler ispat mimarisi — factory fonksiyonlar ile reducibility ve interpretability — ispat maliyetini üç ile dört katına kadar düşürmekte ve bakımı mümkün kılmaktadır. Dafny'deki monolitik deneme 8.000 satırda kırılgan kalmış, Lean'deki modüler yaklaşım dört satırlık ana teoreme inmiştir. Bu, hangi araç sorusundan çok ispatın nasıl ayrıştırıldığı sorusunun kritik olduğunu göstermektedir.

#### 4.4 Diğer 2026 AWS automated reasoning yayınları

Amazon Science automated-reasoning etiketinden (8 Eylül 2026): "ControlsDSL: A Language for Verifiable Cloud Configuration Controls" (ASE 2026; Basu, Delgado, Filieri, Gacek, Joosten, Porncharoenwase, Razavi, Rungta); "IAM Policy Autopilot: Static Analysis for Policy Generation from Application Code" (ASE 2026; Filieri, Rungta, Schlaipfer, Tanuku); "Kani: A Model Checker for Rust" (ASE 2026); "SymCert" (FMCAD 2026).

ControlsDSL, Cedar mantığının, yani analiz edilebilir bir DSL yaklaşımının, IAM dışı alanlara yayıldığını göstermektedir; bu, AWS'nin bunu tekrarlanabilir bir desen olarak gördüğünün kanıtıdır.

#### 4.5 Cedar'ın kurumsal durumu

CNCF Sandbox'a kabul 15 Aralık 2025'te gerçekleşmiştir; duyuruyu Lara Langdon (AWS Applied Science Manager) yapmıştır.

Üretimdeki kullanıcılar Cloudflare, MongoDB, StrongDM, Cloudinary ve AWS servisleridir (Bedrock AgentCore Policy, Systems Manager). Linux Foundation'ın Janssen Project'i ile entegrasyon bulunmaktadır; Janssen bir OpenID ve IdP projesidir ve Argus için doğrudan emsaldir. Yol haritası Sandbox'tan Incubation'a, oradan Graduated statüsüne uzanmaktadır.

cedar-policy organizasyonundaki 23 depo arasında dikkat çekenler `cedar` (Rust), `cedar-spec` (Lean), `cedar-go`, `cedar-java`, `cedar-language-server`, `cedar-access-control-for-k8s`, `cedar-for-agents` ve `cedar-json-parser`'dır; sonuncusu Verus'ta doğrulanmış bir JSON parser olarak tanımlanmaktadır.

> **Doğrulanamadı.** `cedar-json-parser` deposunun README'si çekilememiştir; main ve master dallarında 404 dönmüştür. Yalnızca organizasyon listesindeki açıklama görülmüştür. Ancak bu bile önemli bir sinyaldir: AWS, Rust kodunun kendisini Verus ile doğrulamayı denemekte, yani differential random testing'in ötesine geçme girişimi bulunmaktadır.

### 5. Maliyet, çaba ve tekrarlanabilirlik

#### 5.1 Bilinen çaba rakamları

| Kalem | Değer | Kaynak |
|---|---|---|
| Validator sağlamlık ispatı | 18 kişi-günü | AWS blogu, 8 Nisan 2024 |
| SymCert toplamı | 663 kişi-saat, yaklaşık dört kişi-ay | FMCAD 2026, Tablo I |
| SymCert'te beş analizin ispatlanması | Bir iş günü | FMCAD 2026 |
| SymCert'te yeni dil özelliği entegrasyonu | Özellik başına dört ile sekiz gün | FMCAD 2026 |
| Tüm ispatların CI'da doğrulanması | Yaklaşık 185 saniye; Rust derlemesi 45 saniye | AWS blogu, 8 Nisan 2024 |
| Dafny'deki başarısız monolitik deneme | 8.000 satır, kırılgan | FMCAD 2026 |

2024 makalesindeki kod büyüklükleri (arXiv 2407.01688):

| Bileşen | Lean modeli | Lean ispatı | Rust üretim | Rust test |
|---|---|---|---|---|
| Özel set ve map'ler | 244 | 681 | — | — |
| Parser | — | — | 4.114 | 3.599 |
| Evaluator ve authorizer | 897 | 347 | 4.877 | 7.061 |
| Validator | 532 | 4.686 | 6.702 | 9.798 |
| Toplam | 1.673 | 5.714 | 15.693 | 20.458, ayrıca 31.391 diğer |

AWS blogu (8 Nisan 2024) üretim Rust'ını 24.915 satır olarak vermektedir; makale tablosuyla kapsam farkı bulunmaktadır ve her ikisi de kayda geçirilmiştir.

#### 5.2 Doğrulanamayanlar

Cedar ekibinin büyüklüğü ve toplam kişi-ay maliyeti doğrulanamamıştır; arXiv 2407.01688 açıkça personel verisi vermemektedir. OOPSLA makalesinin on altı yazarı olması bir üst sınır ipucudur ancak kanıt değildir.

AWS'nin resmî ispat ile kod çaba oranı açıklaması bulunamamıştır. Elimizdeki tek sağlam oran SymCert'in 3,2'ye 1 saat ve 9,7'ye 1 satır oranları ile validator için 18 kişi-günüdür.

IonSpec adında bir AWS deposu veya yayını bulunamamıştır; `awslabs/ion-spec` ve `amazon-ion/ion-spec` 404 dönmüştür. Yanlış isim veya dahili bir kaynak olabilir.

#### 5.3 Tekrarlanabilirlik değerlendirmesi

Cevap evettir, ancak koşulludur.

Lehte kanıtlar şunlardır. Tüm araç zinciri açık ve ücretsizdir: Lean 4 (Apache-2.0), cedar-spec (Apache-2.0), cvc5, cargo-fuzz ve `arbitrary`; hiçbir tescilli araç yoktur. Referans mimari kopyalanabilir durumdadır: `cedar-lean-ffi` tam bir şablondur ve `@[export]`, Protobuf, `extern "C"` ile statik linkleme içerir. Marjinal maliyet düşüktür: SymCert modüler kurulduktan sonra yeni analizin bir gün, yeni dil özelliğinin dört ile sekiz gün sürdüğünü kanıtlamaktadır. CI'da üç dakika sürer, yani sürdürülebilirdir ve geliştirme hızını öldürmez. AWS bunu bir kez değil tekrar tekrar yapmıştır: Cedar, SymCC, SymCert ve ControlsDSL; desen olgunlaşmıştır.

Aleyhte ve maliyetli olan taraf şudur. Ana kurulum maliyeti yüksektir: SymCert tek başına dört kişi-aydır ve Cedar'ın tamamı (11.560 model ve 71.987 ispat satırı) muhtemelen çok kişi-yılıdır. Beceri nadirdir; AWS blogunun (8 Nisan 2024) tavsiyesi dik öğrenme eğrisini kabul etmektir ve bu işi Emina Torlak (Rosette'in yaratıcısı) ve Michael Hicks sınıfında araştırmacılar yapmıştır. Dil tasarımı ispatı mümkün kılmak için kısıtlanmalıdır; Cedar Turing complete olmadığı için ispatlanabilirdir ve Argus'un politika dili de aynı feragatleri kabul etmelidir, yoksa ispat mümkün olmaz. Bu bir mühendislik detayı değil, temel bir ürün kararıdır. Süreç disiplini şarttır; lean-lang.org'un Cedar vaka çalışmasına göre modeli, ispatları ve differential testleri güncel olmayan hiçbir Cedar sürümü yayımlanmamaktadır. Bu kurala uyulmazsa model çürür ve değersizleşir.

### 6. AWS'nin diğer formel metot çalışmaları

#### 6.1 Zelkova: SMT ile IAM politika analizi

Künye: John Backes, Pauline Bolignano, Byron Cook, Catherine Dodge, Andrew Gacek, Kasper Luckow, Neha Rungta, Oksana Tkachuk ve Carsten Varming (hepsi AWS), "Semantic-based Automated Reasoning for AWS Access Policies using SMT", FMCAD 2018.

Ne yaptığı şudur: Zelkova politikaların semantiğini SMT'ye kodlar, davranışları karşılaştırır ve özellikleri doğrular. Kullanıcılara politikalarındaki yanlış yapılandırmaları tespit etmek için sağlam bir mekanizma sunar. PSPACE-complete bir problemi çözer ve günde milyonlarca kez çağrılır.

SMT kodlaması string, düzenli ifade, bit vektör ve tamsayı karşılaştırma teorilerini kullanır. String kısıtlarında `*` (herhangi sayıda karakter) ve `?` (tam olarak bir karakter) joker karakterlerinin kullanılması karar problemini PSPACE-complete yapar. Ancak gerçek dünya politikalarındaki deneyime göre politika sorularının %99'u 160 milisaniyenin altında cevaplanabilmektedir.

Çözücü portföyü Z3, CVC4 ve AWS'nin kendi Z3 uzantısı Z3AUTOMATA'dır. Makaledeki sekizinci şekle göre bir milyon UNSAT sorgusunda Z3 965.092, CVC4 34.908 ve Z3AUTOMATA sıfır kez en hızlıdır; bir milyon SAT sorgusunda Z3 959.543, CVC4 39.932 ve Z3AUTOMATA 525 kez en hızlıdır.

Zarif tasarım kararı şudur: doğrulanacak özellik politika dilinin kendisinde belirtilir ve özellikler için farklı bir spesifikasyon veya formalizm gerekmez.

> **Argus için doğrudan alınabilir fikir.** Güvenlik özellikleri ayrı bir spesifikasyon dilinde değil, politika dilinin kendisinde ifade ettirilir. Böylece kullanıcının öğrenmesi gereken tek bir dil olur.

Dağıtım S3, AWS Config, Amazon Macie, Trusted Advisor, GuardDuty ve dahili AWS güvenlik denetim araçlarındadır.

Ölçek için Neha Rungta'nın CAV 2022 davetli bildirisi "A Billion SMT Queries a Day" beş yılda günde binlerce SMT çağrısından günde bir milyara çıkıldığını anlatmaktadır.

IAM Access Analyzer'ı nasıl beslediği AWS dokümantasyonunda açıklanmıştır: IAM Access Analyzer, kaynak tabanlı politikaları analiz etmek için mantık tabanlı akıl yürütme kullanarak harici principal'larla paylaşılan kaynakları tespit eder. Yetenekleri external access analyzer, internal access analyzer, unused access analyzer, policy validation, custom policy checks (yeni erişim veriliyor mu, belirli aksiyonlar yasak mı) ve CloudTrail'den politika üretimidir.

Zelkova'nın ispatlamadığı şey şudur: Zelkova'nın kendisi bir teorem kanıtlayıcıda doğrulanmış değildir. Kodlamanın sağlamlığı makalede argüman edilir, makine kontrollü değildir. SymCert tam olarak bu boşluğu sekiz yıl sonra Cedar için kapatmaktadır; var oluş sebebi budur.

#### 6.2 s2n ve s2n-tls

Künye: Andrey Chudnov, Nathan Collins, Byron Cook, Joey Dodds, Brian Huffman, Colm MacCárthaigh, Stephen Magill, Eric Mertens, Eric Mullen, Serdar Tasiran, Aaron Tomb ve Eddy Westbrook; CAV 2018, LNCS 10982, sayfa 430-446. Kurumlar Galois Inc., AWS, University of Washington ve UCL'dir.

Üç parça ispatlanmıştır.

**HMAC**, katmanlı ispat mimarisiyle:

```
[Rastgeleden ayırt edilemezlik]  ← Coq (Beringer ve ark., FCF kütüphanesi)
          ↕ Coq ispatı (Cryptol operasyonel semantiği)
[Yüksek seviye HMAC spesifikasyonu (monolitik API)]
          ↕ Coq (manuel) + Cryptol (otomatik)
[Düşük seviye Cryptol spesifikasyonu (artımlı API)]
          ↕ SAW (çoğunlukla otomatik)
[s2n C kodu]
```

Galois'nın belirttiğine göre 103 satırlık HMAC C kodu hakkındaki akıl yürütme üç satır Cryptol'e indirgenmektedir.

**DRBG** için aynı yaklaşım kullanılmıştır.

**TLS el sıkışma durum makinesi** için makale, implementasyonun IETF RFC 5246, 5077 ve 6066'da tanımlandığı biçimde TLS 1.2'nin bir alt kümesini gerçekleştirdiğini ve verinin paketlere nasıl bölündüğünü optimize eden socket corking API'sinin doğru kullanıldığını ispatladıklarını söyler. Formel olarak implementasyonun bir spesifikasyonu refine ettiği, yani spesifikasyonun implementasyonu simüle ettiği ispatlanmıştır.

Çaba şudur: HMAC ve DRBG'nin her biri yaklaşık üç ay mühendislik eforu almıştır; TLS el sıkışma doğrulaması sekiz ay sürmüştür, ancak bu sürenin bir kısmı araç uzantılarının geliştirilmesine gitmiştir.

Kritik çekinceler şunlardır. Sınırlılık: doğrulama, koddaki tüm dalları kapsayacak şekilde seçilmiş bir örnek kümesi için yapılmıştır; bu tam ispatın gerisinde kalan bir sonuçtur, ancak yine de test yöntemlerinden çok daha yüksek durum uzayı kapsaması sağlar. Derleyici bağımlılığı: SAW C programları hakkında akıl yürütürken önce onları LLVM'e çevirir ve sağlamlık açısından ispatların derlenmiş koda uygulanabilmesi için C kodunun LLVM üzerinden derlenmesi gerekir. Protokol güvenliği ispatlanmamıştır: RFC'lerin kendisinin güvenli olduğu varsayılmakta ve miTLS gibi bir spesifikasyon seviyesi güvenlik ispatıyla bağlantı gelecek çalışma olarak bırakılmaktadır. s2n'in küçük olması işi mümkün kılmıştır; implementasyon 10.000 satırın altındadır ve çoğu iterasyon sınırlıdır.

Bugünkü durum ölçümle doğrulanmıştır (8 Eylül 2026): `aws/s2n-tls` deposunda hem `tests/saw/` (HMAC ile Cryptol eşdeğerliği, Yices ve Z3 ile) hem `tests/cbmc/` (bellek güvenliği, C Bounded Model Checker ile) mevcuttur ve her pull request'te CI'da çalışmaktadır.

> **Argus için ders.** Sürekli doğrulama uygulanabilirdir, ancak yalnızca küçük, sınırlı iterasyonlu ve kritik bileşenlerde. TLS el sıkışması sekiz ay almıştır.

#### 6.3 AWS-LC doğrulaması

Depo github.com/awslabs/aws-lc-verification'dır (`master` dalı, Apache-2.0). README tam metni 8 Eylül 2026'da çekilmiştir.

Şu anda aktif doğrulanan algoritmalar:

| Algoritma | Varyant | Platform | Araç | Çekinceler |
|---|---|---|---|---|
| SHA-2 | 384, 512 | SandyBridge ve üstü | SAW | NoEngine, MemCorrect |
| SHA-2 | 384, 512 | neoverse-n1 ve v1 | SAW ve NSym | Ek olarak NoInline, ArmSpecGap, ToolGap, LaxPointer |
| HMAC | SHA-384 ile | SandyBridge ve üstü | SAW | NoEngine, MemCorrect, InitZero, NoInline, CRYPTO_once_Correct |
| AES-KW(P) | 256 | SandyBridge ve üstü | SAW | InputLength, MemCorrect, NoInline |
| AES-GCM | 256 | SandyBridge ile Skylake arası | SAW | GcmSpecGap, GcmMultipleOf16, GcmADNotVerified, GcmIV12Tag16, GcmWellFoundedInduction |

> **Önemli bulgu.** README'de ECDSA (P-384), ECDH (P-384), Elliptic Curve Keys ve HKDF satırları HTML yorumu içine alınmıştır (`<!--- ... --->`); yani şu anda aktif tabloda değildirler. ECDSA ve ECDH P-384'ün ispatlanıp ispatlanmadığı sorusunun cevabı şudur: bir zamanlar tabloda vardı, şu anda yorum satırındadır. README bunun sebebini açıklamamaktadır; muhtemelen s2n-bignum'a geçişle ilgilidir. Curve25519 ve RSA bu depoda hiç listelenmemektedir.

Yeni teknik yön README'de şöyle anlatılır: formel doğrulama için teknik yaklaşım SAW ve NSym'den daha yeni araçlara çevrilmiştir. Assembly dilinin doğrulanması için, hem x86_64 hem AArch64 komut setlerini kapsayacak biçimde, HOL Light teorem kanıtlayıcısı üzerine kurulu s2n-bignum altyapısı kullanılmaktadır. ML-KEM'in üretim implementasyonu mlkem-native deposundadır ve bu depo C bileşenleri için CBMC ile bellek ve tip güvenliği ispatı eklemektedir.

Yani post-quantum için (ML-KEM ve ML-DSA) assembly tarafında s2n-bignum ile HOL Light, C tarafında CBMC kullanılmaktadır.

Platform ve derleyici bağımlılığı şudur: doğrulama her durumda Clang tarafından üretilen kod üzerinde yapılmaktadır, ancak doğrulama sonuçları semantik olarak eşdeğer kod üreten her derleyici için de geçerlidir. Platformlar SandyBridge ve üstü (Clang 10), SandyBridge ile Skylake arası (Clang 10, AVX-512 hariç) ve neoverse-n1 ile v1'dir (C için Clang 10, assembly için Clang 10 ve 14).

Çekince sözlüğü, formel doğrulamada neyin ispatlanmadığını açıkça listelemenin mükemmel bir örneğidir:

| Çekince | Anlamı |
|---|---|
| `InputLength` | Yalnızca sınırlı sayıda girdi uzunluğu için doğrulanmıştır; uzunluklar tüm dalları kapsayacak biçimde seçilmiştir ve o uzunluklarda tüm değerler için geçerlidir |
| `MemCorrect` | `OPENSSL_malloc` ve `free` doğrulanmamış, doğru varsayılmıştır |
| `NoEngine` | `ENGINE*` alan API'ler yalnızca null işaretçi için doğrulanmıştır |
| `NoInline` | Belirli fonksiyonların inline edilmediği varsayılmıştır |
| `OptNone` | Belirli fonksiyonların optimize edilmediği varsayılmıştır |
| `GcmMultipleOf16` | AES-GCM yalnızca 16'nın katı uzunluklar için doğrulanmıştır |
| `GcmADNotVerified` | AES-GCM'e ek veri verilmesi doğrulanmamıştır |
| `GcmIV12Tag16` | Yalnızca 12 baytlık IV ve 16 baytlık tag için geçerlidir |
| `GcmWellFoundedInduction` | Sınırsız döngüler için tümevarım hipotezleri varsayılmıştır; SAW iyi temellilik denetimi yapmaz |
| `SAWBreakpoint` | Breakpoint özelliği iyi temellilik denetimi yapmaz |
| `ToolGap` | Bitişik bileşenler farklı araçlarla doğrulanmış ve birinin ispatının diğerinde geçerli olduğu varsayılmıştır |
| `ArmSpecGap` | NSym'deki Cryptol spesifikasyonu SAW'dakinden farklıdır; döngü gövdeleri doğrulanmış ancak üst seviye döngü yapısı doğrulanmamıştır |
| `SAWCore_Coq` | `saw-core-coq` kütüphanesinde bazı gerçekler admit edilmiştir |
| `EC_Fiat_Crypto` | Fiat-Crypto spesifikasyonu kullanılmakta ancak üretimde s2n-bignum kodu çalışmaktadır; bu bir mekanizasyon boşluğudur |
| `LaxPointer` | Clang'ın ürettiği farklı allocation block'lar arası işaretçi karşılaştırmaları için SAW denetimi kapatılmıştır |

> **Argus için ders.** Formally verified etiketinin gerçek kıymeti yanına konan bu tür bir çekince tablosuyla ölçülür. Argus'un güvenlik dokümanı bu README'yi model almalıdır.

#### 6.4 AWS Encryption SDK ve Dafny yaklaşımı

Depolar github.com/aws/aws-encryption-sdk-dafny (`mainline` dalı) ve github.com/aws/aws-cryptographic-material-providers-library'dir (`main` dalı). README'ler 8 Eylül 2026'da çekilmiştir.

Yaklaşım şudur: kütüphane bir kez Dafny'de yazılır ve doğrulanır, ardından birden çok hedef dile transpile edilir.

Material Providers Library README'sine göre kütüphane Dafny ile yazılmıştır; Dafny farklı runtime'lara derlenebilen formel olarak doğrulanabilir bir programlama dilidir ve kütüphane şu anda yalnızca Java, .NET, Python, Rust ve Go'da desteklenmektedir.

Encryption SDK for Dafny README'sindeki iş akışı şudur: doğrulama `dotnet build -t:VerifyDafny test` ile yapılır; kod üretimi Smithy modellerinden Polymorph veya `smithy-dafny` ile gerçekleştirilir; transpilasyon `make transpile_net` ve `make transpile_rust` ile yapılır. README, bir Dafny runtime'ı bulunmadığı için AWS Encryption SDK for Dafny'yi çalıştırma kavramının olmadığını belirtir. Kriptografik ilkeller native'dir, yani Dafny'de değildir ve doğrulama kapsamı dışındadır.

Dafny'nin Rust backend'i ölçümle doğrulanmıştır: `dafny-lang/dafny` kaynağında `Source/DafnyCore/Backends/Rust/RustBackend.cs` mevcuttur:

```csharp
public class RustBackend : DafnyExecutableBackend {
  public override string TargetName => "Rust";
  public override bool IsStable => true;
  public override bool IsInternal => true;
  ...
}
```

`RELEASE_NOTES.md` dosyasında deneysel Dafny'den Rust'a derleyici geliştirmesi ve sonrasında Rust backend iyileştirmeleri (PR #5643 ve #5647) görülmektedir.

> **Tutarsızlık notu.** Çekilen Dafny referans kılavuzu sayfası backend listesinde Rust'ı saymamaktadır; C#, Java, JavaScript, Go ve C++ demektedir. Kaynak kodu ve AWS'nin fiilen Rust'a transpile etmesi göz önüne alındığında dokümantasyonun eski olduğu sonucuna varılmıştır. Kaynak kodu esas alınmış, ancak bu bir belirsizlik olarak işaretlenmiştir.

Argus için bu, Cedar'dan tamamen farklı bir stratejidir. Cedar'da model Lean'de yazılır, kod elle Rust'ta yazılır ve ikisi differential random testing ile bağlanır. Encryption SDK'da tek kaynak Dafny'dedir ve Rust'a üretilir. İkincisi model ile kod arasındaki uçurumu tamamen ortadan kaldırır, ancak üretilen Rust'ın idiomatik olmaması ve performans bedeli vardır. Cedar ekibinin idiomatik ve hızlı üretim kodu istemesi tam da bu yüzden differential random testing'i seçmelerinin sebebidir.

#### 6.5 Kani

Depo github.com/model-checking/kani'dir. Bit hassas, CBMC tabanlı bir Rust model checker'ıdır. Güvenlik tarafında tanımsız davranış denetimi yapar, özellikle unsafe bloklar için. Doğruluk tarafında panic, aritmetik taşma, `assert!` ve deneysel fonksiyon kontratlarını kapsar. Kurulum `cargo install --locked kani-verifier && cargo kani setup` ile yapılır. Harness `#[kani::proof]` ile, sembolik girdi `kani::any()` ile tanımlanır. GitHub Action mevcuttur. ASE 2026 makalesi "Kani: A Model Checker for Rust"tır (Delmas, Hassan, Hu, Kumar, Monteiro, Tautschnig).

Argus için Kani en düşük sürtünmeli giriş noktasıdır; Lean öğrenmeden, mevcut Rust koduna `#[kani::proof]` eklenerek başlanabilir.

#### 6.6 Bulunamayanlar

IonSpec adında bir depo veya yayın bulunamamıştır.

### 7. Argus'a aktarılabilirlik

#### 7.1 Cedar'ı doğrudan gömmek

Fizibilite yüksektir.

`cedar-policy` crate durumu (crates.io API, 8 Eylül 2026):

| Alan | Değer |
|---|---|
| En yeni sürüm | 4.12.0 (28 Temmuz 2026) |
| Lisans | Apache-2.0 |
| İlk yayın | 10 Mayıs 2023 |
| Toplam indirme | 8.375.517 |
| Son dönem indirme | 2.698.101 |
| MSRV | Rust 1.89 |
| Edition | 2021 |

Son 12 ayın sürüm geçmişi: 4.8.1 (25 Kasım 2025), 4.8.2 (9 Aralık 2025), 4.9.0 (9 Şubat 2026), 4.9.1 (27 Şubat 2026), 4.10.0 (23 Nisan 2026), 4.11.0 (18 Mayıs 2026), 4.11.1 (9 Haziran 2026), 4.11.2 (22 Haziran 2026) ve 4.12.0 (28 Temmuz 2026). Ayrıca 3.4.3 (22 Haziran 2026) ile eski major sürüm hâlâ bakımdadır.

> **Olgunluk değerlendirmesi.** Üç yıldan fazla geçmiş, 8,3 milyon indirme, yaklaşık aylık düzenli sürüm, 4.x içinde semver kararlılığı, CNCF Sandbox statüsü ile Cloudflare ve MongoDB üretim kullanımı. Bir IdP'nin yetkilendirme motoru olarak gömülmesi için fazlasıyla olgundur.

API yüzeyi `Authorizer`, `PolicySet`, `Entities`, `Request`, `Schema`, `Validator`, `Decision` ve `Diagnostics`'tir.

Feature flag'ler şöyledir: varsayılanlar `ipaddr`, `decimal` ve `datetime`; opsiyoneller `heap-profiling`, `corpus-timing` ve `wasm`; deneyseller `tpe` (tip farkında kısmi değerlendirme), `partial-eval`, `partial-validate`, `entity-manifest` (kullanımdan kaldırılmıştır, `tpe` lehine), `protobufs`, `tolerant-ast` ve `extended-schema`.

> **Uyarı.** `tolerant-ast` için dokümantasyon bu özelliğin yalnızca dil sunucularında kullanılmak üzere tasarlandığını ve yetkilendirme yolunda asla kullanılmaması gerektiğini söyler. Argus'ta bu özellik asla etkinleştirilmez.

Lint disiplini `cedar-policy/src/lib.rs` ölçümüne göre `#![warn(clippy::pedantic, clippy::use_self, clippy::option_if_let_else)]` ve `#![deny(missing_docs, ...)]` biçimindedir. Cedar dokümantasyonu Rust uygulamasının güvenli alt kümede yazıldığını belirtir.

> **Doğrulanamadı.** `cedar-policy-core`'da açık bir `#![forbid(unsafe_code)]` bulunamamıştır; grep sıfır sonuç vermiştir. Yalnızca safe Rust iddiası dokümantasyona dayanmaktadır ve derleyici zorlamalı bir bariyer olarak doğrulanamamıştır. Argus için öneri kendi kodunda `#![forbid(unsafe_code)]` kullanmak ve bağımlılıkları `cargo-geiger` ile denetlemektir.

Cedar'ın kendi güvenlik modeli paylaşılan sorumluluk esasına dayanır. Cedar'ın sağladıkları: I/O yoktur, yani politikalar dosya veya ağ okuyamaz; politika izolasyonu ve sonlanma garantisi vardır. Argus'un sorumluluğunda olanlar: politika doğruluğu, çünkü validator yardımcı olur ancak garanti etmez; Cedar yalnızca yetkilendirmedir, kimlik doğrulama değildir ve bir IdP için bu tam olarak Argus'un işidir; string birleştirmeyle dinamik politika üretimi enjeksiyon riski taşır, dolayısıyla Argus'ta politika şablonları kullanılır ve asla string birleştirme yapılmaz; değişebilir entity kimlikleri, örneğin kullanıcı adları, geri dönüştürülürse yetki sızıntısı oluşur, bu nedenle Argus'ta değişmez ve yeniden kullanılmayan UUID veya ULID kullanılır, asla kullanıcı adı veya e-posta değil; girdi boyutu sınırları uygulama tarafından zorlanmalıdır, aksi hâlde bellek tükenebilir; veri gizliliği ve bütünlüğü uygulama katmanındadır.

Ek olarak `cedar-policy-symcc` 0.6.0 (Apache-2.0) ile Argus, yöneticilere bir politika değişikliğinin yeni erişim verip vermediğini ispatla cevaplayan bir özellik sunabilir; Keycloak'ta karşılığı olmayan güçlü bir farklılaştırıcıdır. `cvc5-1.3.1` bağımlılığı gerekir.

#### 7.2 Alternatiflerin formel temeli

| Sistem | Model | Formel temel | Makine kontrollü ispat |
|---|---|---|---|
| Cedar | RBAC, ABAC ve ReBAC | Lean 4 modeli, 1.772 teorem, sıfır `sorry`; sağlam ve tam SMT | Evet |
| Zanzibar (Google) | ReBAC | ATC 2019 makalesi; external consistency tanımlar | Hayır; makalede formel doğrulama veya ispat yoktur |
| OpenFGA | ReBAC, Zanzibar temelli | Zanzibar'dan ilham alınmıştır | Hayır; README'de formel veya ispat iddiası yoktur |
| SpiceDB | ReBAC, Zanzibar temelli | En olgun açık kaynak Zanzibar olarak tanımlanır | Hayır; README'de formel veya ispat iddiası yoktur |
| OPA ve Rego | Datalog tabanlı | Cedar makalesine göre Cedar'dan daha ifadelidir ve sağlam SMT kodlaması zordur | Hayır; bilinen makine kontrollü ispat yoktur |
| Casbin | PERM metamodeli | Konfigürasyon tabanlı model | Hayır; README'de formel iddia yoktur |
| Oso ve Polar | Prolog benzeri | — | Doğrulanamamıştır; arama bütçesi tükenmiştir |

Kanıtlar şunlardır. Zanzibar (USENIX ATC 2019; Pang, Caceres, Burrows ve diğerleri) özetinde yetkilendirme kararlarının kullanıcı eylemlerinin nedensel sıralamasına saygı gösterdiğini ve böylece external consistency sağladığını söyler; bu bir dağıtık sistem tutarlılık garantisidir, bir yetkilendirme semantiği doğruluk ispatı değildir ve ikisi farklı şeylerdir. OpenFGA, SpiceDB ve Casbin README'leri taranmış, formel, doğrulama veya ispat kelimeleri için yetkilendirme semantiği ispatına dair hiçbir iddia bulunamamıştır (8 Eylül 2026 ölçümü).

> **Sonuç.** Yetkilendirme motoru pazarında makine kontrollü doğruluk ispatına sahip tek üretim kalitesinde seçenek Cedar'dır. Argus en güvenli iddiasında bulunacaksa kendi motorunu yazmak bu iddiayı zayıflatır; Cedar'ı gömmek ise doğrudan güçlendirir.

#### 7.3 Bir IdP için doğrulama güdümlü geliştirme oyun kitabı

Argus'un bileşenleri ispat getirisi ile maliyet oranına göre sıralanmıştır.

**Katman 1: Cedar gömülür, yeniden yazılmaz.** Getiri çok yüksek, maliyet çok düşüktür. `cedar-policy` 4.12 ve `cedar-policy-symcc` 0.6 kullanılır; 8,3 milyon indirme ve 1.772 Lean teoremi maliyetsiz devralınır. Kendi politika dilini yazmak bu ispatları çöpe atmak demektir. Cedar'ın Janssen, yani bir OpenID projesi, tarafından entegre edilmiş olması emsal teşkil eder.

**Katman 2: protokol katmanında Cedar deseni değil, web modeli deseni.** Bir IdP'nin asıl saldırı yüzeyi yetkilendirme motoru değil, OAuth 2.0 ve OIDC protokol akışlarıdır. Bu alanın kendi formel geleneği vardır.

"A Comprehensive Formal Security Analysis of OAuth 2.0", Daniel Fett, Ralf Küsters ve Guido Schmitz; CCS 2016, arXiv 1601.01229 (6 Ocak 2016). Dört grant tipinin tamamı için yetkilendirme, kimlik doğrulama ve oturum bütünlüğü ispatlanmıştır. OAuth'un güvenliğini kıran dört saldırı bulunmuş ve bunlar OpenID Connect'te de mevcuttur.

"The Web SSO Standard OpenID Connect: In-Depth Formal Security Analysis and Security Guidelines", Fett, Küsters ve Schmitz; CSF 2017, arXiv 1704.08539 (27 Nisan 2017). OpenID Connect'in ilk derinlemesine güvenlik analizidir. Aynı üç özellik ispatlanmış ve uygulayıcılar için güvenlik kılavuzu verilmiştir.

"An Extensive Formal Security Analysis of the OpenID Financial-grade API", Fett, Hosseyni ve Küsters; IEEE S&P 2019, arXiv 1901.11520 (31 Ocak 2019). FAPI'de kimlik doğrulamayı, yetkilendirmeyi ve oturum bütünlüğünü kıran kısmen ciddi saldırılar bulunmuştur.

Hepsi Web Infrastructure Model kullanır; DNS, HTTP ve HTTPS, tarayıcı, script'ler, çerezler ve kötücül aktörleri modelleyen kapsamlı bir web modelidir.

> **Doğrulanamadı.** Bu web modeli ispatlarının makine kontrollü mü yoksa elle mi yapıldığı çekilen özetlerden kesinleştirilememiştir; özetler belirtmemektedir. Genel kanaat elle yapıldıkları yönündedir ancak bu araştırmada doğrulanamamıştır; Argus için buna güvenilecekse tam metinlerden teyit edilmelidir.

Pratik tavsiye şudur: bu üç makale Argus için ispat hedefi değil, tasarım kısıtı listesi olarak kullanılır. FAPI makalesinin bulduğu saldırılar Argus'un regresyon test paketine, OIDC makalesinin uygulayıcılar için güvenlik kılavuzu bölümü Argus'un uygulama şartnamesine dönüştürülür.

**Katman 3: Lean veya Dafny modeli hak eden Argus bileşenleri.** Cedar'ın dışında kalan, Argus'a özgü ve durum makinesi karakterli yerler şunlardır.

| Bileşen | Neden modellenmeli | Önerilen araç |
|---|---|---|
| Oturum ve token yaşam döngüsü durum makinesi (verme, yenileme, rotasyon, iptal, süre dolumu) | s2n'in TLS durum makinesi ispatının birebir muadilidir. İptal edilmiş token'ın asla kabul edilmemesi ve refresh token yeniden kullanımının tüm aileyi iptal etmesi gibi invariantlar taşır | Lean 4; Cedar deseni, yani model ve differential random testing |
| Rol ve grup hiyerarşisi geçişli kapanışı | Döngü olmaması, ayrıcalık yükseltmesi olmaması ve `in` semantiği; Cedar'ın `PolicySlice` teoremlerinin muadilidir | Lean 4 |
| Onay ve scope daraltma | Türetilmiş token'ın asla ebeveyninden fazla scope içermemesi, yani bir monotonluk teoremi | Lean 4 |
| Çok kiracılı izolasyon | Bir kiracının isteğinin asla başka bir kiracının entity'lerine erişememesi; Cedar'ın seviye dilimleme teoreminin muadilidir | Lean 4 |
| JWT, JWS ve JOSE ayrıştırıcısı ile doğrulayıcısı | `alg:none`, algoritma karışıklığı ve `kid` enjeksiyonu tarihsel bir CVE yuvasıdır. Cedar'ın `cedar-json-parser`'ı Verus'ta doğrulaması tam bu sebepledir | Doğrudan Rust üzerinde Verus veya Kani |
| Parola hash'leme ve sabit zamanlı karşılaştırma | AWS-LC desenidir | Kani ile birlikte hazır doğrulanmış kripto kütüphanesi; kendi yazılmaz |
| Kriptografi | Kendimiz yazmayız; `aws-lc-rs` veya `ring` kullanılır ve AWS-LC çekince tablosu okunur | Dış bağımlılık |

**Katman 4: kademeli benimseme yol haritası.**

Faz 0 (birinci ve ikinci hafta, maliyet neredeyse sıfır): `cargo kani` eklenir. Ayrıştırıcılara ve unsafe bloklara `#[kani::proof]` yazılır. CI'a `model-checking/kani-github-action` eklenir. Cedar gömülür. Lean öğrenmeden ciddi kazanç sağlanır.

Faz 1 (birinci ile üçüncü ay): `cedar-lean-ffi` şablon alınarak differential random testing altyapısı kurulur. `arbitrary` ile Argus'a özgü üreteçler (kullanıcı, oturum, token, kiracı) ve `libfuzzer-sys` ile round-trip ile invariant property based test hedefleri yazılır. Henüz Lean modeli olmadan bile bu, Cedar'ın 21 hatasının çoğunu bulan mekanizmadır.

Faz 2 (üçüncü ile dokuzuncu ay): tek bir bileşen Lean'de modellenir; tavsiye token yaşam döngüsü durum makinesidir, çünkü en yüksek risk ile satır oranına ve en küçük modele sahiptir. SymCert dersi uygulanır: yapı factory fonksiyonlar üzerinden kurulur ve ana teorem reducibility ile interpretability benzeri iki genel özelliğe ayrıştırılır. Ölçek beklentisi şudur: Cedar validator'ı 18 kişi-günü almıştır ve durum makinesi benzer büyüklükte olmalıdır.

Faz 3 (dokuzuncu ay ve sonrası): FFI köprüsü kurulur (Protobuf, `@[export]`, `extern "C"`), differential random testing Lean modeline bağlanır ve CI'a günlük fuzzing eklenir. Cedar'ın kuralı benimsenir: model, ispat ve differential testler güncel değilse sürüm çıkmaz.

**Katman 5: dürüstlük şartı.** Argus en güvenli iddiasında bulunacaksa AWS-LC README'sindeki gibi bir çekince tablosu yayımlamalıdır. Tabloda hangi bileşenin hangi araçla, hangi platform ve derleyiciyle doğrulandığı; neyin varsayıldığı (bellek ayırıcısı, kripto kütüphanesi, inline edilmeme); doğrulamanın sınırlı olup olmadığı (belirli girdi uzunlukları); model ile kod arasındaki boşluğun nasıl kapatıldığı (ispat mı, differential testing mi) yer almalıdır.

Bu tablo olmadan formally verified bir pazarlama sözüdür; tabloyla birlikte mühendislik iddiasıdır. Cedar'ın kendisi bile paylaşılan sorumluluktan söz etmektedir.

### 8. Özet değerlendirme

Cedar ve Lean yaklaşımı tekrarlanabilirdir, ancak tümüyle kopyalanmamalıdır.

1. Cedar yeniden yazılmaz, gömülür. Yetkilendirme motoru problemi çözülmüştür; 1.772 makine kontrollü teorem, Apache-2.0 lisansı ve 8,3 milyon indirme vardır. Kendi motorunu yazmak en güvenli iddiasını güçlendirmez, zayıflatır.
2. Doğrulama güdümlü geliştirmenin gerçek garantisi doğru anlaşılmalıdır: model ispatlanır, kod test edilir. Cedar bile on hatayı differential random testing ile kaçırmıştır. Bu bir eksiklik değil mühendislik gerçeğidir, ancak pazarlamada abartılmamalıdır.
3. En değerli aktarılabilir varlık ispatların kendisi değil, ispat mimarisidir. SymCert'in dersi çarpıcıdır: Dafny'de monolitik 8.000 satırlık kırılgan ispat, Lean'de modüler yaklaşımla dört satırlık ana teoreme inmiş ve yeni özellik entegrasyonu dört ile sekiz güne düşmüştür. Factory fonksiyon ile iki genel özellik deseni Argus'un durum makinelerine doğrudan uygulanabilir.
4. Maliyet gerçekçi tutulmalıdır. Validator sağlamlığı 18 kişi-günü, SymCert dört kişi-ay, s2n TLS el sıkışması sekiz ay ve Cedar'ın tamamı çok kişi-yılı sürmüştür. Argus için tek bir yüksek değerli bileşenle başlanmalıdır.
5. Bir IdP'nin risk profili Cedar'ınkinden farklıdır. Cedar'ın çözdüğü problem, yani politika değerlendirme semantiği, hazırdır. Asıl risk OAuth ve OIDC protokol akışları ile token yaşam döngüsüdür; burada rehber Cedar değil, Fett, Küsters ve Schmitz'in web modeli analizleridir (CCS 2016, CSF 2017, IEEE S&P 2019).
6. En yüksek getirili ilk adım Lean değil, Kani ile differential random testing'tir. Cedar'ın 25 hatasının 21'i differential ve property based testing ile bulunmuş, yalnızca dördü ispat sırasında ortaya çıkmıştır. Test altyapısı ispatlardan önce ve daha ucuza gelir.

### Kaynaklar

Erişim tarihi 8 Eylül 2026'dır.

**Cedar ve Lean.** arXiv 2403.04651 (Cedar, OOPSLA 2024, 7-8 Mart 2024); DOI 10.1145/3649835 (PACMPL Cilt 8, OOPSLA1, Makale 118, Nisan 2024); arXiv 2407.01688 ("How We Built Cedar", 1 Temmuz 2024, FSE Companion '24); github.com/cedar-policy/cedar-spec (commit `3a19359`, 4 Eylül 2026, Apache-2.0); github.com/cedar-policy/cedar (cedar-policy 4.12.0, MSRV 1.89, Apache-2.0); cedar-policy/rfcs'te 0032 (Dafny'den Lean'e, Ekim 2023) ve 0095 (TPE); docs.cedarpolicy.com/other/security.html; docs.rs/cedar-policy ve docs.rs/cedar-policy-symcc; crates.io API'sinde cedar-policy ve cedar-policy-symcc.

**AWS blogları ve Amazon Science.** amazon.science'ta Mike Hicks'in 10 Mayıs 2023 tarihli yazısı (Dafny dönemi); aws.amazon.com/blogs/opensource'ta Hietala ve Torlak'ın 8 Nisan 2024 tarihli yazısı, Erickson ve Hadarean'ın 16 Haziran 2025 tarihli Cedar Analysis duyurusu ve Lara Langdon'ın 15 Aralık 2025 tarihli CNCF yazısı; lean-lang.org/use-cases/cedar; amazon.science/tag/automated-reasoning.

**SymCert, Zelkova, s2n, AWS-LC, Dafny ve Kani.** cdn.amazon.science üzerindeki SymCert PDF'i (FMCAD 2026, Torlak); cs.utexas.edu üzerindeki Zelkova PDF'i (FMCAD 2018); amazon.science'ta Rungta'nın CAV 2022 bildirisi; docs.aws.amazon.com IAM Access Analyzer sayfası; d1.awsstatic.com üzerindeki s2n sürekli formel doğrulama PDF'i (CAV 2018); github.com/aws/s2n-tls (`tests/saw/` ve `tests/cbmc/`); github.com/awslabs/aws-lc-verification (`master`, çekince tablosu); github.com/aws/aws-encryption-sdk-dafny (`mainline`) ve github.com/aws/aws-cryptographic-material-providers-library; github.com/dafny-lang/dafny (`Source/DafnyCore/Backends/Rust/RustBackend.cs`); github.com/model-checking/kani ve github.com/verus-lang/verus.

**IdP protokol formel analizi.** arXiv 1601.01229 (OAuth 2.0, CCS 2016, 6 Ocak 2016); arXiv 1704.08539 (OpenID Connect, CSF 2017, 27 Nisan 2017); arXiv 1901.11520 (FAPI, IEEE S&P 2019, 31 Ocak 2019); research.google/pubs (Zanzibar, USENIX ATC 2019).
