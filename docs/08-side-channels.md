# §8 — Yan kanal ve zamanlama saldırıları

## 0. Yönetici özeti: gerçek risk sıralaması

| # | Konu | Gerçek risk | Argus'taki yeri |
|---|---|---|---|
| 1 | Kullanıcı sayımı (enumeration); zamanlama ile mesaj, status ve uzunluk farkı | Yüksek ve kesin sömürülebilir | Login, kayıt, şifre sıfırlama, MFA kaydı, SCIM |
| 2 | `rsa` crate'inin Marvin durumu | Yüksek; 2026'da hâlâ yamalı sürüm yoktur | JWE RSA1_5, RSA imzalama |
| 3 | JWE `RSA1_5` desteği | Yüksek; IETF varsayılan olarak kapatılmasını zorunlu kılar | JOSE katmanı |
| 4 | Sabit zamanlı karşılaştırma eksikliği (token, HMAC, TOTP, PKCE, client_secret) | Orta ile yüksek arası; HTTP/2 varsa yüksek | Tüm kimlik doğrulama yolları |
| 5 | Argon2 DoS'u; dummy hash veya yüksek parametre | Orta ile yüksek arası | Login endpoint'i |
| 6 | Derleyicinin sabit zamanı bozması | Orta; 2026'da Rust'ta gerçek CVE mevcuttur | Kripto yardımcı kodu |
| 7 | Spectre ve Meltdown sınıfı | Co-tenant yoksa düşük; plugin veya WASM varsa yüksek | Barındırma ve eklenti motoru |

---

## A. Rust'ta sabit zamanlı karşılaştırma

### A.1 `subtle` crate'inin 2026 durumu

**Sürüm ve bakım.** Son sürüm 2.6.1'dir ve 24 Haziran 2024 tarihlidir; toplam 682.501.354 indirme almıştır (crates.io API, 8 Eylül 2026). Son commit 19 Haziran 2024 tarihlidir (github.com/dalek-cryptography/subtle/commits/main.atom, 8 Eylül 2026), yani 26 aydır hiçbir commit yoktur. Bu, en güvenli IdP hedefi için dikkate alınması gereken bir bakım riskidir. 2.6.0 yanked'tır, 2.5.0 28 Şubat 2023 tarihlidir ve MSRV Rust 1.41'dir.

**Sunduğu API.** `Choice` (u8 sarmalayıcı, 0 veya 1), `CtOption<T>`, `ConstantTimeEq`, `ConstantTimeGreater`, `ConstantTimeLess`, `ConditionallySelectable`, `ConditionallyNegatable`.

**Dokümante edilmiş çekinceler.** README'ye göre crate bir en iyi çaba denemesini temsil eder, çünkü yan kanallar nihayetinde yalnızca yazılımın değil, üzerinde çalıştığı donanım dahil dağıtılmış kriptografik sistemin bir özelliğidir. Trait'ler bitwise işlemlerle implemente edilmiştir ve iki koşul sağlanırsa sabit zamanda çalışırlar: bitwise işlemlerin sabit zamanlı olması ve bu işlemlerin koşullu atama olarak tanınıp branch'e geri optimize edilmemesi. Bir derleyicinin bitwise işlemlerin koşullu atamayı temsil ettiğini anlaması için bitmask üretiminde kullanılan değerin `i8` bayt değeri değil gerçek bir boolean `i1` olduğunu bilmesi gerekir; crate bu daraltmayı engellemek için `Choice`'ın içindeki `u8` değerini volatile read ile gizlemeye çalışır. Ayrıca crate debug build'lerde invariant kontrolü için `debug_assert` içerir; bu kontroller gizliye bağımlı dallanma barındırır ve release modda bulunmaz, dolayısıyla crate release modda kullanılmak üzere tasarlanmıştır.

docs.rs özeti de aynı yöndedir: böyle bir çaba temelde sınırlıdır ve kullanım kullanıcının kendi riskindedir.

Kritik nokta şudur: `subtle` `black_box` kullanmaz, volatile read kullanır. Bu, LLVM'in `Choice`'ı `i1`'e daraltıp branch'e çevirmesini engelleme umududur, garanti değildir.

### A.2 Alternatifler

| Crate | Sürüm ve tarih | Ne sunuyor |
|---|---|---|
| `constant_time_eq` | 0.6.0, 30 Ağustos 2026; 307.711.245 indirme; codeberg.org/cesarb/constant_time_eq | Yalnızca eşit uzunluklu bayt dizisi karşılaştırması yapar. Aktif bakımdadır |
| `cmov` | 0.5.4, 28 Mayıs 2026; RustCrypto | x86 ve x86_64'te `CMOVZ` ve `CMOVNZ`, aarch64'te `CSEL` komutlarını inline `asm!` ile kullanır; sabit zamanda çalışmayı ve derleyici tarafından branch'e dönüştürülmemeyi garanti eder. LLVM'in `x86-cmov-conversion` pass'ini bypass eder |
| `ctutils` | 0.4.2, 2 Nisan 2026; RustCrypto | `cmov` üzerine kuruludur ve `subtle`'ın modern muadilidir: `Choice`, `CtOption`, `CtFind`, `CtLookup` ve `const fn` desteği sunar |
| `aarch64-dit` | 0.1.0, 6 Eylül 2024; RustCrypto | ARM DIT bitini RAII guard ile açıp kapatır |

`ctutils` README'sine göre crate x86, x86_64 ve aarch64'te `cmov` crate'indeki `asm!` implementasyonlarıyla garantili sabit zamanlı eşitlik testi ve koşullu seçim sağlar; diğer platformlarda bitwise aritmetik ve `black_box` ile taşınabilir bir en iyi çaba fallback'i kullanır. Crate kendisini `subtle`'dan esinlenmiş deneysel bir yeni nesil sabit zaman kütüphanesi olarak tanımlar ve şimdilik `subtle` kullanmaya devam edilmesini önerir. Ayrıca bu crate'teki implementasyonun hiç bağımsız denetimden geçmediğini ve kullanımın kullanıcının kendi riskinde olduğunu belirtir.

**Argus için öneri.** x86_64 ve aarch64 hedefleniyorsa basit bayt karşılaştırması için aktif bakımdaki `constant_time_eq` kullanılır; kripto seçim mantığı gerekiyorsa olgun olan `subtle` veya garantisi daha güçlü ancak denetlenmemiş olan `ctutils` tercih edilir. `subtle` seçilirse bakım durgunluğu risk kaydına yazılır.

### A.3 Sabit zamanlı karşılaştırmanın zorunlu olduğu yerler

Sıralama gerçek uzaktan sömürülebilirlik değerlendirmesine göredir.

| # | Yer | Zorunlu mu | Gerekçe |
|---|---|---|---|
| 1 | Opak session ve bearer token veritabanı araması | Evet; ancak asıl çözüm hash'lemektir | Token düz saklanırsa hem karşılaştırma hem veritabanı indeks karşılaştırması sızdırır, çünkü B-tree karşılaştırmaları prefix'e göre erken çıkar. Çözüm veritabanına `SHA-256(token)` yazmak, aramayı bu hash üzerinden yapmak ve dönen kaydı `constant_time_eq` ile doğrulamaktır |
| 2 | HMAC ve JWS imza doğrulama (HS256) | Evet | Klasik durumdur. Keyczar'ın 2009 zafiyeti tam olarak buydu |
| 3 | TOTP kodu karşılaştırma | Evet | Gerçek CVE mevcuttur: `totp-rs` için RUSTSEC-2022-0018 ve CVE-2022-29185, 9 Mayıs 2022; `TOTP::check` sabit zamanlı değildi ve 1.1.0'da `constant_time_eq` ile düzeltildi. Bugünkü kaynak (6.0.0) `Token::eq` içinde `constant_time_eq::constant_time_eq_n` kullanmaktadır. Altı haneli kodda arama uzayı 10⁶ olduğu için bayt bayt sızıntı gerçekten kritiktir |
| 4 | `client_secret` karşılaştırma | Evet | Rauthy sabit uzunluk zorlar ve `constant_time_eq_64` kullanır |
| 5 | API anahtarı | Evet, ayrıca hash'lenir | Rauthy `EncValue::encrypt(sha256!(secret))` saklar ve doğrulamada `constant_time_eq(self.secret, sha256!(secret))` kullanır |
| 6 | CSRF ve state token'ı | Evet | Rauthy `sessions.rs::validate_csrf` ve `magic_links.rs` içinde `constant_time_eq` kullanır |
| 7 | Şifre sıfırlama token'ı ve magic link | Evet, ayrıca hash'lenir ve tek kullanımlık yapılır | OWASP Forgot Password Cheat Sheet token'ların kriptografik olarak güvenli bir algoritmayla rastgele üretilmesini, yeterince uzun olmasını, güvenli saklanmasını, tek kullanımlık olmasını ve süresinin dolmasını ister |
| 8 | PKCE `code_verifier` ile `code_challenge` karşılaştırması | Evet; pratikte düşük risk | RFC 7636 sabit zaman zorunlu kılmaz; §4.6 yalnızca `BASE64URL-ENCODE(SHA256(...)) == code_challenge` der. §7.1 en az 256 bit entropi önerir; entropi yüksek olduğu için bayt bayt sızıntı bile pratikte sömürülemez, ancak maliyeti sıfır olduğundan yine de uygulanır. Rauthy uygulamaktadır (`login_finish.rs:60`) |
| 9 | Device code ve user code | Evet; düşük risk, ancak rate limit zorunludur | RFC 8628 §5.1 sunucunun user code denemelerini rate limit etmesini önerir; 8 karakterlik base-20 kod için (yaklaşık 34,5 bit) 2⁻³² başarı olasılığı ancak beş deneme izniyle sağlanır. §5.2 device code brute force'unu ele alır. Asıl savunma rate limit'tir, sabit zaman değildir |
| 10 | WebAuthn challenge karşılaştırma | Evet; risk düşüktür | Challenge en az 16 rastgele bayttır ve tek kullanımlıktır; asıl güvenlik imza doğrulamadadır. Yine de eşitlik kontrolü sabit zamanlı yapılır |

**Rauthy'nin karşı argümanı.** `src/service/src/oidc/grant_types/device_code.rs` dosyasında device code ve client secret için sabit zamanlı karşılaştırmanın güvenlik açısından anlam taşımadığı, ancak konu hakkında rapor almamak için yapıldığı belirtilir. Gerekçe device code'un çok kısa ömürlü, rate limit'li ve üç kez rate limit ihlalinden sonra silinmiş olması, karşılaştırmanın tek haneli nanosaniyelerde gerçekleşmesi ve bu API'de pratikte ölçülemez olmasıdır.

Bu argüman kısmen doğrudur; ancak aşağıdaki Timeless Timing Attacks çalışması tam olarak bu ölçülemezlik varsayımını yıkmaktadır.

### A.4 Uzaktan zamanlama saldırısının fizibilitesi

**Brumley ve Boneh, "Remote Timing Attacks are Practical" (2003).** Çalışma zamanlama saldırılarının genel yazılım sistemlerine uygulandığını gösterir; OpenSSL'e karşı bir zamanlama saldırısı tasarlanmış ve yerel ağdaki bir makinede çalışan OpenSSL tabanlı web sunucusundan özel anahtarlar çıkarılmıştır. Üç ortam denenmiştir: ağ (kampüs ağı, üç router arası), süreçler arası (aynı makinede iki süreç) ve sanal makineler (VMM izolasyonu delinerek diğer VM'den RSA anahtarı çıkarma).

**Crosby, Wallach ve Riedi, "Opportunities and Limits of Remote Timing Attacks" (ACM TISSEC, 2009).** Jitter filtreleriyle internet üzerinden 15-100 µs, LAN üzerinden 100 ns çözünürlük elde edilmiştir. Timeless makalesinin aktarımına göre Crosby ve arkadaşları Box Test'in en iyi performansı verdiğini bulmuş ve internet üzerinden 20 µs, LAN üzerinden 100 ns'lik bir zamanlama farkı ölçebilmiştir.

**Van Goethem, Pöpper, Joosen ve Vanhoef, "Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections", USENIX Security 2020.** Bu makale Argus'un tehdit modelini değiştirmektedir.

Bulguları şunlardır. Eşzamanlılık tabanlı zamanlama saldırıları yanıtların döndürülme sırasını analiz ederek göreli bir zamanlama farkı çıkarır ve hiçbir mutlak zamanlama bilgisine dayanmaz; 100 ns kadar küçük farkları, yerel bir sistemde yapılan saldırılara benzer doğrulukla tespit edebilir. HTTP/2 üzerinden sunulan web sunucularında 100 ns kadar küçük bir fark yaklaşık 40.000 istek çiftinin yanıt sırasından doğru biçimde çıkarılabilmektedir; internet üzerinden geleneksel bir zamanlama saldırısında gözlenebilen en küçük fark 10 µs'dir, yani 100 kat daha büyüktür. Yöntem ağ koşullarından tamamen bağımsızdır ve saldırgan ile kurban sunucu arasındaki mesafeden etkilenmez.

Mekanizma şudur: iki HTTP/2 isteği tek bir TCP paketinde birleşir, sunucuya aynı anda varır, eşzamanlı işlenir ve hangi yanıtın önce döndüğü ölçülür. Ağ jitter'ı hem yukarı hem aşağı yönde tamamen elenir. Tor onion servisleri ile VPN ve SOCKS tünelleri de aynı paket birleştirmeyi sağlar. HTTP/3 için makale bu protokolü değerlendirmediğini, çünkü henüz yaygın olarak dağıtılmadığını belirtir; multiplexing bulunduğu için aynı prensibin geçerli olması beklenir ancak bu kısmen doğrulanmamıştır.

**Argus için sonuç.** Argus HTTP/2 veya HTTP/3 sunduğu için — ki modern bir IdP sunar — Rauthy'nin tek haneli nanosaniyelerin ölçülemeyeceği argümanı artık geçerli değildir. 100 ns'lik fark 40.000 istek çiftiyle ölçülebilmektedir. 32 baytlık bir token'ın bayt bayt karşılaştırmasında ilk bayt farkı 1-2 ns'dir, ancak 16. bayta kadar birikirse fark 10-30 ns'ye çıkar; bayt başına 40.000 istek ve 256 tahmin ile brute force teorik olarak mümkündür. Sonuç kesindir: tüm sır karşılaştırmalarında sabit zaman kullanılır.

**Makalenin önerdiği savunmalar (§6.3).** Zamanlama saldırılarına karşı en etkili karşı önlem sabit zamanlı yürütmedir, ancak bu çok zor olabilir. Doğrudan bir savunma gelen isteklere rastgele gecikme eklemektir. Jitter'ın standart sapmasının 1 ms olduğu ağ koşullarını taklit etmek için bu gecikme [0, √12] ms aralığından tekdüze rastgele örneklenebilir ve istek başına yaklaşık 1,73 ms ortalama gecikme üretir. Ancak yalnızca sunucuya eşzamanlı ulaşan isteklerin doldurulması gerekir.

Yani eşzamanlı gelen istek çiftlerine rastgele gecikme eklenerek saldırı sıradan bir sıralı zamanlama saldırısı seviyesine indirilebilir, yok edilemez.

### A.5 Sabit zamanlı karşılaştırmaya alternatifler

**Hash'leyip karşılaştırma, yani veritabanında hash saklama. En iyi çözümdür.** Token veritabanına düz yazılmaz, `SHA-256(token)` yazılır. Karşılaştırma zamanlaması sızıntısı ortadan kalkar, çünkü hash çıktıları saldırganın kontrolünde değildir ve bayt bayt sızıntı işe yaramaz. Veritabanı indeks zamanlaması sızıntısı da ortadan kalkar, çünkü B-tree veya hash indeks araması hash üzerinde yapılır. Veritabanı dump'ı çalınırsa token'lar kullanılamaz; bu tek başına yeterli bir gerekçedir. Gerçek örnek Rauthy'dedir: `api_keys.rs:84,148,444` ve `pam/remote_password.rs:25,61` dosyalarında `sha256!` ile saklanır ve `constant_time_eq` ile doğrulanır. Token yüksek entropili olduğu için (en az 128 bit) SHA-256 yeterlidir ve Argon2 gerekmez.

**Double-HMAC, yani HMAC'leyip karşılaştırma.** `compare(HMAC(k, a), HMAC(k, b))` biçiminde çalışır; `k` her süreç başlangıcında üretilen rastgele bir anahtardır. Saldırgan karşılaştırılan değerleri tahmin edemediği için erken çıkışlı `memcmp` bile güvenli hâle gelir.

> **Ölü kaynak.** Orijinal NCC Group ve iSEC Partners "Double HMAC Verification" (Şubat 2011) blog yazısı artık erişilememektedir; hem `nccgroup.com/us/research-blog/...` hem `research.nccgroup.com/2011/02/07/...` 404 vermekte ve Wayback CDX'te snapshot bulunmamaktadır (8 Eylül 2026'da kontrol edilmiştir). Yerine kullanılabilecek kanonik kaynak Cryptography Coding Standard'ın "Compare secret strings in constant time" maddesidir (github.com/veorq/cryptocoding); bu kaynak Keyczar zafiyetine (Nate Lawson, 2009) ve OpenBSD `memcmp`'ın erken çıkışlı implementasyonuna atıf yapar.

**Uzunluk sızıntısı.** `constant_time_eq` eşit uzunluk gerektirir; uzunluk farkı zaten sızar. Token'lar sabit uzunluk yapılır; Rauthy `SECRET_LEN_CLIENTS = 64` sabitini `debug_assert_eq!` ile zorlar.

---

## B. Derleyici sabit zamanı bozuyor mu

Cevap evettir ve bu Rust'ta da geçerlidir.

### B.1 Rust standart kütüphanesinin kendi dokümantasyonu

`doc.rust-lang.org/std/hint/fn.black_box.html` (Rust 1.98.1, build `48a229cea`, 1 Eylül 2026; 8 Eylül 2026'da çekilmiştir) şunu belirtir.

`black_box` yalnızca en iyi çaba temelinde sağlanır ve yalnızca öyle sağlanabilir. Optimizasyonları ne ölçüde engelleyebileceği platforma ve kullanılan kod üretim arka ucuna göre değişir. Programlar, kimlik fonksiyonu gibi davranması dışında `black_box`'a doğruluk için güvenemez ve kritik program davranışını kontrol etmek için ona dayanılmamalıdır. Bu aynı zamanda fonksiyonun kriptografik veya güvenlik amaçları için hiçbir garanti sunmadığı anlamına gelir. Bu kısıt `black_box`'a özgü değildir; Rust dilinin tamamında sabit zamanlı kriptografinin gerektirdiği garantileri sağlayabilecek bir mekanizma yoktur. LLVM'de de böyle bir mekanizma bulunmadığı için aynı durum LLVM tabanlı her derleyici için geçerlidir.

Bu, resmî Rust dokümantasyonunun açık kabulüdür ve Argus'un tehdit modeli belgesine birebir alınmalıdır.

### B.2 Gerçek ve güncel Rust CVE'leri

RustSec advisory-db'nin ana dalı indirilip taranmıştır (8 Eylül 2026). Sabit zamanlılıkla ilgili advisory'ler şunlardır.

**RUSTSEC-2026-0003 ve CVE-2026-23519, `cmov`, 14 Ocak 2026.** En önemli kanıttır. Başlığı ARM32 hedeflerinde sabit zamanlı olmayan kod üretimidir. Advisory'ye göre implementasyon, optimizasyon aşamasından sabit zamanlı kod üretimini zorlamak için bitwise aritmetik ile `core::hint::black_box` kombinasyonunu kullanır, ancak v0.4.3 ve öncesindeki implementasyon bunu 32 bit ARM hedeflerinde başaramamıştır. Üretilen assembly şudur:

```asm
bne  .LBB0_2      ; Branch if Not Equal
mvns r3, r3
```

Advisory, LLVM optimizasyon aşamasının 32 bit hedeflerde eklediği branch komutlarının cache timing gibi çeşitli mikromimari yan kanallarla sömürülebileceğini belirtir. Çözüm olarak v0.4.4 taktiksel bir `black_box` yaması uygulamış, v0.4.5 ise `asm!` ile yeniden yazılmıştır. CVSS 4.0 vektörü AV:N/AC:H, VC:H/SC:H'dir.

Bunun anlamı şudur: RustCrypto ekibinin tam da bu iş için yazdığı ve `black_box`'ı bilinçli kullandığı crate'te bile LLVM branch üretmiştir. `black_box`'a güvenmek çalışmamakta, `asm!` çalışmaktadır.

**RUSTSEC-2025-0144 ve CVE-2026-22705, `ml-dsa`, 12 Aralık 2025.** Analiz, derlenmiş assembly kodunu veri bağımlı zamanlama davranışı olan komutlar için inceleyen bir sabit zaman analizöründe yapılmıştır. Analizör `UDIV` ve `SDIV` komutlarını işaretlemektedir; donanım bölme komutlarının erken sonlanma optimizasyonları vardır ve yürütme süresi operand değerlerine bağlıdır. Sorunlu satır `r1.0 /= TwoGamma2::U32;` biçimindedir ve gizli anahtardan türeyen veride donanım bölmesi yapar. Düzeltme Barrett reduction'dır; yamalı sürüm 0.1.0-rc.3 ve üstüdür.

**RUSTSEC-2026-0212, `libcrux-secrets`, 26 Mayıs 2026.** aarch64 inline `asm!` içinde `cmp` 32 bit register kullanmaktaydı ve 8 bitlik selector'ın üst 24 biti tanımsızdı; bu nedenle `Select::select` ve `Swap::swap` yanlış sonuç verebiliyordu. `tst` ve maske ile düzeltilmiştir; yamalı sürüm 0.0.6 ve üstüdür.

**RUSTSEC-2026-0211, `libcrux-aesgcm`, 14 Temmuz 2026.** AES-GCM şifre çözme, verilen kimlik doğrulama tag'ini kontrol etmek için sabit zamanlı olması amaçlanan ancak belirli koşullarda sabit zamanlı olmayan kod üreten bir implementasyon kullanmaktaydı. Advisory, `libcrux-aesgcm`'in sabit zamanlı kod üretimi hakkında garanti vermediğini ve olası azaltmaların en iyi çaba temelinde değerlendirilmesi gerektiğini belirtir. Advisory düzeyinde `versions.patched` boştur; gerçek düzeltme `libcrux-aes@v0.0.9`'dadır.

**RUSTSEC-2024-0354 ve CVE-2024-40640, `vodozemac`, 17 Temmuz 2024.** Sabit zamanlı olmayan bir base64 decoder gizli anahtar materyalini sızdırmaktaydı. Bu, yalnızca karşılaştırmanın değil, tüm sır işleme yolunun sabit zamanlı olması gerektiğinin dersidir.

**RUSTSEC-2022-0018 ve CVE-2022-29185, `totp-rs`.** A.3'te ele alınmıştır.

### B.3 Akademik literatür

**"What you get is what you C: Controlling side effects in mainstream C compilers".** Laurent Simon (Samsung Research America ve Cambridge), David Chisnall ve Ross Anderson; IEEE EuroS&P 2018. Özet şunu söyler: bir programcı kodun yan etkilerini kontrol etmeye çalıştığında, örneğin bir kriptografik algoritmayı sabit zamanda çalıştırmak istediğinde sorun devam eder. Programcılar niyetlerini gizlemek için karmaşık hileler geliştirir, derleyici yazarları ise kodu optimize etmenin gittikçe daha akıllı yollarını bulur. Bir derleyici yükseltmesi, daha önce güvenli olan kodda aniden ve uyarısız bir zamanlama kanalı açabilir. Bu silahlanma yarışı anlamsızdır ve sona ermelidir. Makalenin katkısı Clang ve LLVM'e sabit zamanlı seçim ile register ve stack silme için doğrudan derleyici desteği eklemektir.

**"Dude, is my code constant time?"** Oscar Reparaz, Josep Balasch ve Ingrid Verbauwhede; IACR ePrint 2016/1123 (Aralık 2016), DATE 2017. Yaklaşık 350 satır C'dir ve hedef platformda kara kutu istatistiksel sızıntı tespiti yapar (Welch t-testi). |t| değeri 5'i aşarsa sızıntı çok muhtemeldir. README'deki örnek çıktı memcmp tabanlı MAC karşılaştırması için `max t: +1271.13 ... Definitely not constant time.` biçimindedir.

**Cryptography Coding Standard** (github.com/veorq/cryptocoding), "Prevent compiler interference with security-critical operations" maddesi Tor'daki `memset` çağrısının MSVC 2010 tarafından silinmesini, `volatile` fonksiyon pointer hilesini ve Colin Percival'ın bu hilenin yeterli olmayabileceğini belirten errata'sını aktarır.

### B.4 Doğrulama araçları

| Araç | Tip | Kaynak | Notlar |
|---|---|---|---|
| dudect | Dinamik, istatistiksel, kara kutu | github.com/oreparaz/dudect | Donanım modeli gerektirmez |
| `dudect-bencher` (Rust) | Dinamik | 0.7.0, 23 Mart 2026, 191.096 indirme; github.com/rozbb/dudect-bencher/ | Rust portudur. README uyarısı şudur: genel olarak bir fonksiyonun her zaman sabit zamanda çalıştığını kanıtlamak mümkün değildir; aracın amacı sabit zamanlı olmama durumu varsa onu bulmaktır ve kullanıcının sabit zamanlı olmamanın nerede olabileceğini çok dikkatli düşünmesini gerektirir. Argus'un CI'ına eklenebilecek en pratik araçtır |
| ctgrind (Adam Langley, 1 Nisan 2010) | Valgrind ve memcheck | imperialviolet.org/2010/04/01/ctgrind.html | Gizli veri `ct_poison` ile uninitialised işaretlenir ve memcheck gizliye bağımlı branch ile bellek erişimini yakalar. Langley bu araçla OpenSSL'in `BN_mod_exp_mont_consttime` fonksiyonunun sabit zamanlı olmadığını bulmuştur |
| TIMECOP | Valgrind, SUPERCOP üzerinde | post-apocalyptic-crypto.org/timecop/ | 2.700'den fazla kripto implementasyonu tarar. Bilinen sınırı şudur: Valgrind, değişken zamanlı kodun değişken zamanlı CPU komutlarından kaynaklandığı durumları tespit edemez. Yani `ml-dsa`'daki UDIV'i yakalayamaz |
| ct-verif | Statik ve formel; LLVM, SMACK ve Boogie | Almeida, Barbosa, Barthe, Dupressoir, Emmi; USENIX Security 2016 | Ürün-program indirgemesi Coq'ta doğrulanmıştır |
| Binsec/Rel | İkili düzeyde ilişkisel sembolik yürütme | Daniel, Bardin, Rezk; IEEE S&P 2020, arXiv:1912.08788 | Derleyicinin ürettiği ikiliyi analiz eder, kaynak kodu değil |
| Microwalk | Dinamik ikili enstrümantasyon ve istatistik | github.com/microwalk-project/Microwalk | CI entegrasyonu vardır: GitHub Actions şablonları, hazır Docker imajları ve GitHub arayüzünde satır içi sızıntı raporu. C ve JavaScript örnek repoları mevcuttur; Rust için hazır şablon doğrulanmamıştır |
| cachegrind | Cache profili | Valgrind paketi | Yalnızca kaba sinyal verir |

### B.5 RustCrypto'nun politikası

`crypto-bigint` README'si şunu belirtir: crate'te bulunan tüm fonksiyonlar, aksi açıkça belirtilmedikçe (`*_vartime` isim soneki ile) sabit zamanda çalışacak biçimde tasarlanmıştır. Crate NCC Group tarafından denetlenmiş ve önemli bir bulgu çıkmamıştır; ancak implementasyon son denetimden bu yana belirgin biçimde değişmiştir. Kütüphane, değişken zamanlı çarpma işlemi olan işlemcilerde kullanıma uygun değildir; örneğin sıfırla veya birle çarpmada kısa devre yapan bazı 32 bit PowerPC CPU'lar ve ARM olmayan bazı mikrodenetleyiciler.

`*_vartime` isimlendirme kuralı Argus için doğrudan benimsenmelidir.

**CI'da ne yapıyorlar.** RustCrypto/utils'in `.github/workflows/` dizini indirilip taranmıştır (8 Eylül 2026): `aarch64-dit.yml`, `cmov.yml`, `ctutils.yml` ve `security-audit.yml` bulunmaktadır; dudect veya valgrind tabanlı otomatik sabit zaman testi yoktur. `cmov` CVE'si de harici bir raporla ortaya çıkmıştır. Yani RustCrypto bile CI'da sabit zaman doğrulaması yapmamaktadır; Argus bunu yaparsa ekosistemin önüne geçmiş olur.

**fiat-crypto** (github.com/mit-plv/fiat-crypto) Coq'ta formel olarak doğrulanmış bir alan aritmetiği üretecidir; Rust backend'i vardır ve `curve25519-dalek`, BoringSSL ile Firefox tarafından kullanılır. Bir IdP için doğrudan gerekli değildir, çünkü eğri aritmetiği yazılmaz; ancak doğru yapılmış bir referans olarak değerlidir.

### B.6 Donanım: yazılım tek başına yetmiyor

**Intel DOIT ve DOITM.** Kaynak intel.com üzerindeki data operand independent timing ISA rehberidir; belge güncelleme tarihi 10 Eylül 2025'tir. `IA32_UARCH_MISC_CTL` MSR'si (0x1B01) DOITM bitini taşır. Bit açıkken listelenen komutların zamanlaması kaynaklardaki veri değerlerinden bağımsızdır. Ice Lake ve sonrası Core ile Gracemont ve sonrası Atom işlemciler DOITM'i enumerate eder; daha eski işlemcilerde modun her zaman açık olduğu varsayılır.

> **Intel'in uyarısı.** Bu modun performans etkisi gelecekteki işlemcilerde belirgin biçimde daha yüksek olabilir ve Intel modun global olarak açılmasını önermemektedir; gelecekte uygulama başına ince taneli kontrol planlanmaktadır. Rust ekosisteminde DOITM'i açan yaygın bir crate bulunamamıştır; RustCrypto/utils dizininde `aarch64-dit` vardır ancak x86 muadili yoktur (8 Eylül 2026'da doğrulanmıştır).

**ARM DIT (FEAT_DIT, PSTATE.DIT).** ARM developer dokümantasyonu curl'e 403, WebFetch'e boş içerik döndürmüştür; doğrudan alıntı alınamamıştır. Ancak bilgi Linux kernel kaynağından doğrulanmıştır: `entry.S:199` satırında `alternative_insn nop, SET_PSTATE_DIT(1), ARM64_HAS_DIT` bulunur, yani kernel EL0'dan girişte DIT'i açar; `cpufeature.c:3057-3064` satırlarında `.desc = "Data independent timing control (DIT)"`, `ARM64_HAS_DIT` ve `ID_AA64PFR0_EL1.DIT` tanımlıdır. Rust tarafında `aarch64-dit` 0.1.0 (6 Eylül 2024) `cpufeatures::new!(dit_supported, "dit")` ile runtime tespiti ve RAII guard sağlar.

**GoFetch (USENIX Security 2024).** Sabit zamanlı kodun donanımda kırılmasıdır. Proje sayfasına göre GoFetch, veri bellek bağımlı prefetcher'lar (DMP) üzerinden sabit zamanlı kriptografik implementasyonlardan gizli anahtar çıkarabilen bir mikromimari yan kanal saldırısıdır. DMP, bellekten yüklenen ve pointer'a benzeyen veriyi etkinleştirir ve dereference etmeye çalışır; bu, veri ile bellek erişim örüntülerinin karıştırılmasını yasaklayan sabit zamanlı programlama paradigmasının bir gereksinimini açıkça ihlal eder. Uçtan uca anahtar çıkarma OpenSSL Diffie-Hellman, Go RSA-2048 şifre çözme, CRYSTALS-Kyber ve CRYSTALS-Dilithium için Apple M1'de gösterilmiş, M2 ve M3'te de benzer DMP davranışı görülmüştür. DMP kapatma konusunda M3 CPU'larda DIT bitinin ayarlanması DMP'yi etkili biçimde devre dışı bırakır; M1 ve M2'de bu geçerli değildir. Intel'in DOIT biti Raptor Lake'te DMP'yi kapatır. Nisan 2024 güncellemesinde Hector Martin M1 ve M2 için `SYS_APL_HID11_EL1[30]` chicken bitini bulmuştur; macOS'ta kernel desteği yoktur. Aralık 2024'teki devam çalışması "Peek-a-Walk: Leaking Secrets via Page Walk Side Channels" Intel DMP semantiğini tersine mühendislikle çözmüştür. Apple'a bildirim 5 Aralık 2023'te yapılmıştır; çalışma 2024 Pwnie Award'da en iyi kriptografik saldırı ödülünü almıştır.

**Argus için anlamı.** M serisi Mac üzerinde geliştirme ve test yapmak sorun değildir, çünkü yerel makinedir. Üretimde Apple Silicon sunucu kullanılmaz ve yan kanal kritik kod için x86_64 sunucu varsayılır. DMP tehdidi yerel kod yürütme gerektirir; çok kiracılı olunmadığı sürece doğrudan uygulanabilir değildir.

---
## C. Zamanlama ile kullanıcı sayımı

### C.1 Klasik problem

Kullanıcı yoksa parola hash'i hesaplanmaz ve cevap yaklaşık 1 ms'de döner; kullanıcı varsa Argon2 çalışır ve cevap 200-500 ms sürer. Fark beş büyüklük derecesindedir; bu, 100 ns inceliğindeki saldırılara gerek bırakmaz ve `curl -w '%{time_total}'` ile görülebilir.

OWASP Authentication Cheat Sheet'in sözde kodu şöyledir. Zafiyetli hâli hızlı çıkış yapar:

```
IF USER_EXISTS(username) THEN
    password_hash = HASH(password)
    IS_VALID = LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
    IF NOT IS_VALID THEN RETURN Error("Invalid Username or Password!")
ELSE
    RETURN Error("Invalid Username or Password!")   ← hızlı dönüş
ENDIF
```

Güvenli hâli şudur:

```
password_hash = HASH(password)
IS_VALID = LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
IF NOT IS_VALID THEN RETURN Error("Invalid Username or Password!")
```

### C.2 Kullanıcı yoksa dummy Argon2 çalıştırmak doğru çözüm değildir

Tek başına yeterli olmamasının iki nedeni vardır.

**Birinci sorun: DoS.** Memory-hard fonksiyon saldırgana ücretsiz verilmiş olur. OWASP'ın Argon2id önerisi m=19456 KiB (19 MiB) veya m=47104 KiB'dir (46 MiB). Yüz eşzamanlı sahte kullanıcı isteği 19 MiB ile çarpıldığında 1,9 GB RAM ve 100 çekirdek-saniye eder. Saldırgan hiçbir geçerli kullanıcı adı bilmeden IdP'yi düşürebilir. Rauthy varsayılanı daha da agresiftir: `argon2_m_cost = 131072` (128 MiB), `t_cost = 4`, `p_cost = 8`. İki eşzamanlı hash bile 256 MiB tüketir.

**İkinci sorun: doğruluk.** Dummy hash zamanı gerçekten eşitlemez ve bunun üç sebebi vardır.

Parametre göçü: kullanıcı A `m=19456,t=2` ile, kullanıcı B `m=47104,t=1` ile hash'lenmişse tek bir dummy parametre setiyle ikisi de taklit edilemez. Dummy'nin süresi A ile eşleşiyorsa B sızar, B ile eşleşiyorsa A sızar.

Algoritma göçü: legacy bcrypt (cost 10, yaklaşık 60 ms) ile yeni Argon2id (yaklaşık 300 ms) karışımı varsa dummy hangisini taklit edeceği belirsizdir.

Unusable password durumu: bu gerçek bir CVE'ye yol açmıştır. CVE-2024-39329, Django, 9 Temmuz 2024. `django.contrib.auth.backends.ModelBackend.authenticate()` metodu, kullanılamaz parolaya sahip kullanıcılar için yapılan login isteklerini içeren bir zamanlama saldırısıyla uzaktaki saldırganların kullanıcıları sayabilmesine izin veriyordu. Düzeltilen sürümler Django 5.0.7, 4.2.14 ve 5.1b'dir. Django 2013'te dummy hash eklemiş olmasına rağmen 11 yıl sonra aynı sınıfta yeni bir zafiyet çıkarmıştır.

Django'nun orijinal düzeltmesi ticket #20760 ile Django 1.6'da (Temmuz 2013) gelmiştir. Aymeric Augustin 20 Temmuz 2013'te şunu yazmıştır: Django artık varsayılan olarak güçlü hasher'larla geldiği için login view'ı zamanının çoğunu parolayı hash'lemekle geçirmektedir; kullanıcının var olup olmamasından bağımsız olarak hasher'ı çalıştırmanın, bir zamanlama saldırısını en azından önemsiz olmaktan çıkarma açısından değeri vardır.

İfadenin "önemsiz olmaktan çıkarmak" olduğuna, "imkânsız kılmak" olmadığına dikkat edilmelidir. Django ekibi bile bunu tam çözüm saymamıştır.

### C.3 Alternatifler

| Yaklaşım | Etkinlik | Maliyet | Değerlendirme |
|---|---|---|---|
| Dummy Argon2 | Orta | Çok yüksek; DoS üretir | Tek başına önerilmez |
| Sabit gecikme, örneğin her cevap 500 ms | İyi, ancak sınırlı | Throughput tavanı getirir; ayrıca gerçek işlem 500 ms'yi aşarsa sızıntı geri gelir | Uygulanabilir ancak kabadır |
| Rastgele gecikme | Zayıf | Düşük | Ortalamayla yenilir; N örnekte gürültü √N ile azalır. Timeless makalesi bunun saldırıyı sıralı seviyeye indirdiğini, yok etmediğini belirtir |
| Adaptif gecikme, koşan ortalamaya doldurma | İyi | Düşük | Rauthy'nin çözümüdür; aşağıdadır |
| Rate limiting ve IP kara listesi | Yüksek; ortogonaldir | Düşük | Zorunludur |
| Protokol düzeyinde kabullenme, yani enumeration'ı önlemeye çalışmayıp her yerde tutarlı olmak | Kanidm'in seçimidir | Sıfır | Aşağıdadır |
| Hash kuyruğu ve semafor | DoS'a karşı zorunludur | Düşük | Rauthy'de `max_hash_threads`, Keycloak'ta `cpu-cores` |

#### Rauthy'nin çözümü

Kaynak kodundan doğrulanmıştır: `src/service/src/login_delay.rs` (main dalı, 8 Eylül 2026'da indirilmiştir). Dosyanın açıklamasına göre modül login gecikmesini yönetir; her başarılı login'de başarılı bir login'in ne kadar sürdüğüne dair yeni bir ortalama hesaplanır ve bir login başarısız olduğunda cevap, kullanıcı sayımı gibi saldırıları önlemek için başarılı login'in güncel ortalaması kadar geciktirilir.

Mekanizma şudur. Parola gerçekten hash'lenerek başarılı olunduğunda `new_time = (success_time + delta) / 2` hesaplanır ve koşan ortalama cache'e yazılır; varsayılan başlangıç 2000 ms'dir. Başarısızlıkta `sleep_time_median = success_time - time_taken` hesaplanır, negatifse sıfır alınır ve hata cevabı ortalama başarı süresine kadar doldurulur. Üstüne IP başına başarısız giriş sayacıyla üstel ceza uygulanır: üç ve üzeri denemede ek 2 saniye, beş ve üzeri denemede ek 3 saniye, yedi denemede 60 saniye kara liste, on denemede 600 saniye, on beş denemede 900 saniye, yirmi denemede 3600 saniye, yirmi beş ve üzerinde 86.400 saniye.

`src/service/src/oidc/authorize.rs` dosyasında kullanıcı bulunamadığında şu not bulunur: arayüz henüz kullanıcı yokken parola giriş formunu göstermez, dolayısıyla kullanıcı sayımını önlemek için arayüzün parola istemediği bu aşamada kullanıcı hiç yoksa login gecikmesi eklenmemelidir.

Rauthy dummy Argon2 çalıştırmamaktadır; DoS'tan kaçınmakta ve bunun yerine yanıt süresini ortalamaya doldurmaktadır. Bu yaklaşımda hash çalıştırılmadığı için DoS yoktur ve parametre göçü sorunu bulunmaz. Buna karşılık ortalama istatistikseldir ve farklı parametreli kullanıcılar arasındaki varyans hâlâ sızabilir; ayrıca gerçek başarılı login ortalamadan uzunsa, örneğin veritabanı yavaşsa, sızıntı geri gelir.

Ayrıca `CredStuffDetect` mekanizması beş saniyelik pencerede üç başarısız `sha256(email/password)` denemesinde 86.400 saniyelik kara liste uygular.

#### Keycloak'ın çözümü

Keycloak'ın yaklaşımı DoS tarafına odaklanır. Varsayılan hash Argon2id'dir (FIPS dışı modda) ve parametreleri `memory = 7168` KB, `iterations = 5`, `parallelism = 1`, `version = 1.3`, `hash-length = 32`'dir. `spi-password-hashing--argon2--cpu-cores` ayarı hash'leme için kullanılacak azami paralel CPU çekirdeği sayısını belirler. Admin guide'a göre aşırı bellek ve CPU kullanımını önlemek için Argon2'nin paralel hash hesaplaması varsayılan olarak JVM'in erişebildiği çekirdek sayısıyla sınırlanmıştır.

Keycloak'ın `m=7168, t=5, p=1` değeri OWASP'ın listelediği eşdeğer seçeneklerden biriyle birebir aynıdır; düşük bellek ve yüksek iterasyon tercihi bilinçlidir ve DoS yüzeyini küçültür.

#### Kanidm'in çözümü

Kanidm enumeration'ı engellememeyi seçmiştir. Firstyear 14 Kasım 2021'de şunu yazmıştır: hesap sayımını etkili biçimde engellemenin teknik bariyerleri son derece yüksektir ve maliyeti elde edilecek kazanca göre olağanüstüdür. Hesap güvenliği adının veya varlığının gizliliğiyle değil, başka unsurlarla tanımlanır. Microsoft, Gmail, Google ve GitHub gibi büyük sağlayıcılar hesap ve kullanıcı adı sayımını engellemeye çalışmamaktadır.

Tartışılan ve reddedilen seçenek sahte hesap simülasyonudur; sahte bir kullanıcı hesabını simüle etmek rate limit ve kilitlemeyi de simüle etmeyi gerektirir ve bu sunucu belleği tüketir. Ayrıca bir akış sorunu tespit edilmiştir: kullanıcıdan MFA'ya, oradan parolaya giden sıra zorunlu olarak sızdırır; idealı kullanıcı ve parolanın birlikte alınıp ardından MFA'nın gelmesidir.

### C.4 Enumeration Keycloak'ta bile hâlâ çıkıyor

CVE-2026-4633 ve GHSA-rhgq-f8x5-j2jc, yayın 23 Mart 2026, şiddet düşük, CVSS 3.7 (AV:N/AC:H/PR:N/UI:N/C:L), CWE-209. Keycloak'ın identity-first login akışı kullanıcı bilgisi sızdırmaktadır; uzaktaki bir saldırgan, Organizations etkinken identity-first login akışı sırasındaki differential error message'ları sömürebilmektedir. Var olan kullanıcıda mesaj "Invalid Password", olmayan kullanıcıda "Invalid username or password" biçimindedir. Etkilenen sürümler 26.4.12'nin altı ile 26.5.0 ve üstü, 26.6.1'in altıdır; düzeltilen sürümler 26.6.1 ve 26.4.12'dir. İlgili issue github.com/keycloak/keycloak/issues/47619 ve Red Hat Bugzilla 2450247'dir. Ayrıca github.com/keycloak/keycloak/issues/26625 şifre sıfırlama endpoint'i üzerinden manuel kullanıcı sayımını açık bir konu olarak taşımaktadır. Tarihsel örnek CVE-2020-1717'dir; giriş yapmış kullanıcı e-posta sayımıdır.

Ders şudur: enumeration olgun bir IdP'de 2026'da hâlâ bulunmakta ve genellikle zamanlamadan değil, yeni eklenen bir özellikten sızmaktadır. Argus'ta her yeni akış için enumeration regresyon testi bulunmalıdır.

### C.5 Zamanlama dışı yan kanallar

Aşağıdaki liste WSTG-IDNT-04 ile IdP'ye özgü eklemelerden oluşur.

1. Hata mesajı metni: "Login for User foo: invalid password" ile "invalid Account" arasındaki fark.
2. HTTP status kodu: 401, 403 ve 200 arasındaki fark.
3. Content-Length ve cevap gövdesi uzunluğu: aynı metin bile olsa CSRF token uzunluğu veya HTML render farkı.
4. URL hata kodu parametresi: `err.jsp?User=gooduser&Error=2` ile `Error=0` arasındaki fark.
5. URI probing: `/account1` 403 dönerken `/account2` 404 dönmesi.
6. Redirect hedefi: var olan kullanıcının `/password` sayfasına, olmayanın `/error`'a yönlendirilmesi.
7. Rate limit davranış farkı: var olan kullanıcı için hesap kilidi devreye girip olmayan için girmiyorsa kilit mekanizması oracle hâline gelir. Bu Kanidm'in tespit ettiği sorundur.
8. Şifre sıfırlama akışı: "Invalid username" ile "Your password has been successfully sent" farkı ve e-postanın gerçekten gidip gitmediğinin zamanlaması.
9. Kayıt akışı: "email already in use" mesajı en sık kaçırılan sızıntıdır. Rauthy'de bunun için özel bir e-posta şablonu vardır (`email_registered_already.rs`); bilgi arayüzde gösterilmez, e-posta ile bildirilir.
10. MFA kayıt ve challenge akışı: WebAuthn `allowCredentials` listesinin dolu veya boş olması passkey'lerde kritiktir; `residentKey` veya discoverable credential kullanılmıyorsa kullanıcının kayıtlı authenticator'ı olup olmadığı sızar.
11. SCIM `/Users?filter=userName eq "x"` sorgusu: API tarafında yetkisiz sorgu.
12. OIDC hata kodları: `login_required` ile `interaction_required` farkı ve `error_description` farkları.
13. `prompt=none` davranışı: oturumun var olup olmadığını sızdırır.
14. Sosyal ve federe login: "Bu e-posta Google ile kayıtlı" mesajı.
15. Kullanıcı adı formatı: `jbloggs` veya `CN000100` ile `CN000101` gibi tahmin edilebilir şemalar.

**Argus önerisi.** Enumeration protokol seviyesinde çözülür: tüm bu akışlarda aynı cevap gövdesi, aynı status, aynı süre ve aynı yönlendirme kullanılır. Login akışı kullanıcı ve parolanın birlikte alınıp ardından MFA'nın geldiği biçimde kurulur; identity-first akışı kullanılmaz veya identity-first kullanılıyorsa parola formu her zaman gösterilir.

### C.6 NIST ve OWASP'ın resmî konumu

**NIST SP 800-63B-4** (final, 2025; pages.nist.gov/800-63-4/sp800-63b.html sayfası Revision 4, 26 Ağustos 2025 göstermektedir; tam tarih doğrulaması zayıftır). Tam metin taramasında hesap sayımı veya genel hata mesajı hakkında normatif bir gereksinim bulunmamıştır. Bu önemlidir: NIST bunu zorunlu kılmamaktadır. Bulunan ilgili normatif madde, doğrulayıcının tek bir abone hesabında belirli bir authenticator ile yapılan ardışık başarısız kimlik doğrulama denemelerini o authenticator'ı devre dışı bırakarak en fazla 100 ile sınırlaması gerektiğidir. Bölüm numarası kaynak sayfadan çıkarılmıştır ve kesin değildir.

**OWASP Forgot Password Cheat Sheet.** Var olan ve olmayan hesaplar için tutarlı bir mesaj döndürülmelidir. Kullanıcıya dönen mesajın süresi tekdüze olmalıdır. Yanıtların tutarlı bir sürede dönmesi sağlanmalı ve bu, senkron olmayan çağrılar kullanılarak veya hızlı çıkış yöntemi yerine aynı mantığın izlenmesi sağlanarak yapılabilir. Hesap bazında rate limiting veya CAPTCHA gibi aşırı otomatik gönderimlere karşı korumalar uygulanmalıdır. Geçerli bir token sunulmadan hesapta değişiklik yapılmamalıdır; örneğin hesap kilitlenmemelidir.

Son madde önemlidir: sıfırlama isteği hesabı kilitlerse bu da bir oracle olur.

### C.7 Argon2 parametreleri ve DoS matematiği

OWASP Password Storage Cheat Sheet'e göre (8 Eylül 2026'da çekilmiştir) Argon2id için eşdeğer güvenlikteki seçenekler şunlardır:

| m (KiB) | m (MiB) | t | p |
|---|---|---|---|
| 47104 | 46 | 1 | 1 |
| 19456 | 19 | 2 | 1 |
| 12288 | 12 | 3 | 1 |
| 9216 | 9 | 4 | 1 |
| 7168 | 7 | 5 | 1 |

Diğer seçenekler scrypt için `N=2^17` (128 MiB), `r=8`, `p=1`; yalnızca legacy için bcrypt cost 10 ve üstü ile 72 baytlık sınır; FIPS gereksinimi için PBKDF2-HMAC-SHA256 ile 600.000 iterasyondur. Genel kural bir hash hesaplamasının bir saniyeden kısa sürmesi gerektiğidir. bcrypt ile ön hash'leme tehlikelidir (null byte ve password shucking); gerekiyorsa `bcrypt(base64(hmac-sha384(password, pepper)), salt, cost)` kalıbı kullanılır.

**RFC 9106 §4** çok daha agresiftir: 2 GHz CPU'da dört çekirdek kullanarak 0,5 saniye süren arka uç sunucu kimlik doğrulaması için 8 lane ve 4 GiB RAM ile Argon2id; 2 GHz CPU'da iki çekirdek kullanarak 0,5 saniye süren ön uç sunucu kimlik doğrulaması için 4 lane ve 1 GiB RAM ile Argon2id önerilir.

> **Uyarı.** RFC 9106'nın 4 GiB önerisi bir IdP için DoS açısından kabul edilemez. OWASP, Keycloak ve Rauthy pratiği olan 7-128 MiB aralığı gerçek dünyayı yansıtmaktadır.

`argon2` crate'i (RustCrypto) 0.6.0 sürümündedir, 27 Ağustos 2026 tarihlidir ve 50.939.882 indirme almıştır. Rauthy hâlâ 0.5 kullanmaktadır (`Cargo.toml:73`).

DoS matematiği şudur:

```
Eşzamanlı hash sayısı N, bellek m MiB
Tepe RAM = N × m + baseline
Rauthy varsayılanı: max_hash_threads=2, m=128 MiB → 256 MiB tepe
OWASP m=19 MiB, N=32 → 608 MiB, 32 çekirdek-yarım saniye
```

Rauthy dokümantasyonuna göre `hashing.max_hash_threads` sistem belleğini aşmamak için tam olarak aynı anda çalışan azami paralel parola hash sayısını sınırlar ve varsayılan değeri 2'dir. Küçük kurulumlar için bu değerin 1 yapılması önerilir; bu teknik olarak aynı anda yalnızca bir kullanıcı girişine izin verir ve login için harici bir rate limiting'i gereksiz kılar, diğer uçlar için rate limiting eklenebilir. Ayrıca uygulama belleğin sınırlı olduğu bir ortamda çalışıyorsa, örneğin kaynak limitleri çok düşük ayarlanmış bir Kubernetes içinde, `hashing.argon2_m_cost` çok yüksek veya bellek limiti çok düşük ayarlanırsa uygulama çöker.

`config.toml` dosyasında `hash_await_warn_time = 500` ayarı bulunur; bir istek bu süreden uzun beklediyse bu, izin verilenden daha fazla eşzamanlı login olduğuna ve yapılandırmanın ayarlanması gerekebileceğine dair bir göstergedir.

**Argus için hash kuyruğu tasarımı.**

```rust
// Semafor + kuyruk + zaman aşımı
static HASH_SEM: Semaphore = Semaphore::new(max_hash_threads);
// 1. permit al (timeout ile) → alınamazsa 503 + Retry-After (kullanıcıdan bağımsız)
// 2. Argon2 çalıştır
// 3. permit'i bırak
// Kritik: kuyruk doluluğu kullanıcı varlığına göre değişmemeli,
//         yoksa yeni bir oracle yaratılır.
```

> **Uyarı.** Kuyruğun kendisi bir yan kanaldır. Hash yalnızca var olan kullanıcılar için çalıştırılırsa saldırgan kuyruğu doldurup gecikmeyi gözleyerek hangi kullanıcının var olduğunu anlayabilir. Rauthy'nin adaptif gecikme yaklaşımı bu tuzağa düşmez, çünkü gecikme kullanıcı varlığından bağımsız global bir ortalamadan gelir.

---

## D. Marvin saldırısı ve RSA

### D.1 Marvin nedir

"Everlasting ROBOT: the Marvin Attack", Hubert Kario (Red Hat). IACR ePrint 2023/1442, alınma 21 Eylül 2023, onay 24 Eylül 2023; ESORICS 2023. Proje sayfası people.redhat.com/~hkario/marvin/ (8 Eylül 2026'da çekilmiştir).

Özete göre çalışma, RSA şifre çözmeye yönelik Bleichenbacher tarzı saldırıların hâlâ mümkün olmakla kalmadığını, zafiyetli implementasyonların da yaygın olduğunu göstermektedir. Yalnızca şifre çözme işleminin zamanlaması kullanılarak birden çok implementasyona başarıyla saldırılmış ve daha birçoğunun zafiyetli olduğu gösterilmiştir. Saldırıyı gerçekleştirmek için sign test, Wilcoxon signed-rank test ve pairwise farkların medyanının bootstrap'ı gibi istatistiksel olarak daha titiz teknikler kullanılmıştır.

Proje sayfasındaki kritik noktalar şunlardır. Saldırı pratiktir: M2Crypto ve pyca/cryptography'ye karşı standart dizüstülerde birkaç saat içinde yürütülmüştür; TLS sunucularında saatler ile günler arası sürer. Ölçülemeyecek kadar küçük olduğu varsayılan zamanlama farklarının güvenli olduğu varsayımı yanlış çıkmıştır; araştırmacıların eşleştirilmiş fark yaklaşımı üretim ağlarında birkaç CPU saat döngüsü kadar küçük farkları tespit etmektedir. OAEP de güvende değildir: altındaki sayısal kütüphaneler zamanlama bilgisi sızdırıyorsa RSA-OAEP implementasyonları zafiyetli kalır ve koruma sabit zamanlı deblinding ile bayt dizisi dönüşümü gerektirir. Özel anahtar çalınmaz: saldırı tek tek şifreli metinleri çözer veya imza forge eder, ancak özel anahtarın kendisini açığa çıkarmaz, dolayısıyla sertifika yenilemeye gerek yoktur. Birincil öneri PKCS#1 v1.5 şifrelemenin tamamen deprecate edilip devre dışı bırakılmasıdır.

### D.2 Etkilenen kütüphaneler ve CVE listesi

Proje sayfasından, 8 Eylül 2026:

| Uygulama | CVE | Durum |
|---|---|---|
| OpenSSL (TLS) | CVE-2022-4304 | Düzeltildi |
| OpenSSL (API) | — | API iyileştirmeleri merge edildi |
| GnuTLS (TLS) | CVE-2023-0361, CVE-2023-5981, CVE-2024-0553 | Kısmî ve çoklu düzeltme |
| NSS (TLS) | CVE-2023-4421, CVE-2023-5388 | Kısmî düzeltme; hâlâ zafiyetlidir |
| pyca/cryptography | CVE-2020-25659, CVE-2023-50782 | Etkisiz azaltma |
| M2Crypto | CVE-2020-25657, CVE-2023-50781 | Etkisiz azaltma |
| python-rsa | CVE-2020-25658 | Kapsam dışı |
| Go | CVE-2023-45287 | Düzeltildi; v1.20 ve üstü |
| Java | CVE-2024-20952, CVE-2025-21587 | Düzeltildi |
| BouncyCastle | CVE-2024-30171 | Düzeltildi |
| Node.js | CVE-2023-46809 | Düzeltildi |
| .NET | — | Issue açıldı |
| Apple corecrypto | CVE-2024-23218 | Düzeltildi |
| Mbed TLS | CVE-2024-23170 | Düzeltildi |
| libgcrypt | CVE-2024-2236 | Düzeltildi |
| wolfSSL | CVE-2023-6935 | Düzeltildi |
| PyCryptodome | CVE-2023-52323 | Düzeltildi |
| jsrsasign | CVE-2024-21484 | Düzeltildi |
| cjose | — | PR merge edildi |
| Ruby | CVE-2025-0306 | Düzeltildi |
| Linux Kernel | CVE-2023-6240 | Düzeltildi |
| OpenSC | CVE-2023-5992, CVE-2024-29995 | Düzeltildi |
| Intel QuickAssist | CVE-2024-33617, CVE-2024-28885, CVE-2024-31074 | Düzeltildi |
| RustCrypto RSA | CVE-2023-49092 | Proje sayfasına göre düzeltildi; bu bilgi çelişkilidir, aşağıya bakınız |
| xmlsec | — | PKCS1.5 devre dışı bırakıldı |
| Erlang/OTP | — | Uyarı eklendi |

Etkilenmediği doğrulananlar: BearSSL 0.6, BoringSSL (TLS, Eylül 2023 itibarıyla) ve rustls 0.21.9 (RSA ciphersuite desteği yoktur).

**marvin-toolkit** (github.com/tomato42/marvin-toolkit, sürüm 0.3.5). Adım 0 venv ve tlsfuzzer kurulumudur. Adım 1 1024, 2048 ve 4096 bit RSA anahtar üretimidir (PEM, PKCS#8, PKCS#12). Adım 2 bilinen yapıda çok sayıda şifreli metin üretimidir: geçerli, bozuk header'lı, yanlış padding uzunluklu ve benzeri. İstatistik Friedman testidir; p değeri 0,05'in altındaysa muhtemel yan kanal, 1e-9'un altındaysa neredeyse kesin yan kanal vardır. Örneklem yerel test için şifreli metin başına 100.000 ile 1 milyon çağrıdır; hızlı kütüphaneler yaklaşık 10 milyon, yavaşlar 1 milyardan fazla gözlem gerektirebilir. TLS sunucusu testi `test-bleichenbacher-timing-pregenerate.py`, API testi `marvin-ciphertext-generator.py` ile yapılır.

**OpenSSL tarafındaki asıl azaltma: implicit rejection.** OpenSSL CHANGES.md dosyasında, 3.1 ile 3.2.0 (23 Kasım 2023) arasındaki değişiklikler başlığı altında şu yer alır: Bleichenbacher benzeri saldırılara karşı koruma olarak RSA PKCS#1 v1.5 şifre çözmede implicit rejection eklenmiş ve varsayılan olarak etkinleştirilmiştir. RSA şifre çözme API'si, padding kontrolünde hata tespit ettiğinde hata döndürmek yerine rastgele üretilmiş deterministik bir mesaj döndürecektir. Bu, CVE-2020-25659 ve CVE-2020-25657 gibi sorunlara karşı genel bir korumadır. Katkı Hubert Kario'ya aittir.

Ayrıca 3.0.9 ve 3.1.1 civarında RSA şifre çözmedeki zamanlama oracle'ı için düzeltme yeniden ele alınmıştır (CVE-2022-4304); önceki düzeltme 2-3 kat ciddi bir performans gerilemesine yol açmıştı ve yeni düzeltme mevcut sabit zamanlı kod yollarını kullanmaktadır.

Sonuç şudur: OpenSSL 3.2.0 ve üstü kullanılıyorsa PKCS#1 v1.5 şifre çözmede implicit rejection açıktır. Bu bir azaltmadır, kök çözüm değildir; Kario'nun önerisi hâlâ PKCS#1 v1.5 şifrelemenin tamamen kapatılmasıdır.

### D.3 IdP'de RSA PKCS#1 v1.5 şifre çözmenin kullanıldığı yerler

Tek büyük yer JWE `alg=RSA1_5` anahtar sarmalamadır. Bir IdP'de görülebilecek noktalar şunlardır: Request Object şifrelemesi (JAR ve JARM; `request` parametresi şifreli JWE olabilir), ID Token ve UserInfo şifrelemesi (`id_token_encrypted_response_alg`, `userinfo_encrypted_response_alg`), `private_key_jwt` istemci kimlik doğrulaması (imzadır, şifre çözme değildir ve Marvin kapsamı dışındadır), istemciden gelen şifreli JWT'ler ve SAML `EncryptedAssertion` ile `EncryptedKey`. Sonuncusu unutulmamalıdır; SAML tarafı `http://www.w3.org/2001/04/xmlenc#rsa-1_5` kullanır ve xmlsec bunu devre dışı bırakmıştır.

**RSASSA-PKCS1-v1_5 imzalama (RS256, RS384, RS512) etkilenir mi.** Doğrulama etkilenmez; yalnızca public key işlemidir ve sır yoktur. İmzalama Marvin'in decryption oracle'ı kapsamında değildir, ancak iki nokta vardır. IETF taslağı bunu açıkça ayırır: `draft-ietf-jose-deprecate-none-rsa15-05` §1'e göre PKCS#1 sürüm 1.5 padding kullanan RSA imzaları (RS256, RS384, RS512) bu spesifikasyonla değişmemiştir ve hâlâ kullanılabilir. Buna karşılık RustSec RUSTSEC-2023-0071 advisory'si `rsa` crate'i için her türlü private key işlemini kapsar ve özel anahtar hakkındaki bilginin ağ üzerinden gözlemlenebilen zamanlama bilgisiyle sızdığını belirtir; yani `rsa` crate'iyle RS256 imzalamak da advisory kapsamındadır. Bir IdP her token için imzalar, dolayısıyla çok sayıda ölçüm birikir ve risk gerçektir. Marvin SSS'inde de aynı anahtarla hem decryption oracle'ı hem imzalama varsa oracle üzerinden imza forge edilebileceği belirtilir.

**JOSE'de RSA1_5'in 2026 durumu.** `draft-ietf-jose-deprecate-none-rsa15-05` Haziran 2026 tarihlidir, son geçerlilik 25 Aralık 2026'dır; datatracker'da IESG durumu "Publication Requested"tır, son revizyon 23 Haziran 2026, son güncelleme 6 Eylül 2026'dır. Henüz RFC değildir. Yazarı Neil Madden'dır (Hazelcast).

§3'e göre `RSA1_5` algoritması PKCS#1 sürüm 1.5 padding kullanan RSA şifrelemesini implemente eder. Bu padding modunun en azından 1998'deki Bleichenbacher saldırısından beri güvenlik sorunları olduğu bilinmektedir. Algoritmanın JWE'de desteklenmesinin nedeni, özellikle legacy donanımdaki yaygın dağıtımıdır. Ancak OAEP veya eliptik eğri şifreleme algoritmaları gibi daha güvenli alternatifler artık yaygın biçimde mevcuttur. NIST bu şifreleme modunun federal kullanımını 2023 sonundan itibaren yasaklamıştır (NIST SP 800-131Ar2) ve bir CFRG taslağı da bu modu yeni protokoller ve dağıtımlar için deprecate etmektedir.

§4'e göre JOSE kütüphane geliştiricileri bu algoritmaların desteğini deprecate etmelidir; uygulama geliştiricileri bu algoritmaların desteğini varsayılan olarak devre dışı bırakmak zorundadır. Bu algoritmalardan birine özel ihtiyacı olan bir uygulama onu etkinleştirebilir, ancak yalnızca onu gerektiren belirli nesneler veya işlemler için, global düzeyde değil. JOSE üzerine kurulan yeni spesifikasyonlar bu algoritmaların kullanımına izin veremez. IANA'da "Deprecated" olarak işaretlenecektir, "Prohibited" değil.

**RFC 8725 §3.2** uygulamaların algoritmaya özgü tavsiyeleri izlemesini önerir: tüm RSA-PKCS1 v1.5 şifreleme algoritmalarından kaçınılmalı (RFC 8017 §7.2) ve RSAES-OAEP tercih edilmelidir (RFC 8017 §7.1).

**alg downgrade riski.** Sunucu JWE header'ındaki `alg` değerini allowlist olmadan kabul ediyorsa saldırgan RSA-OAEP'ten RSA1_5'e düşürüp Bleichenbacher saldırısı açabilir. Argus'ta `alg` değeri her zaman istemci kaydındaki beklenen değere karşı doğrulanır, JWE header'ından alınmaz.

### D.4 Rust `rsa` crate'i ve RUSTSEC-2023-0071'in 2026 durumu

RustSec advisory'sinin ana daldan alınan TOML'u şudur:

```toml
id = "RUSTSEC-2023-0071"
package = "rsa"
date = "2023-11-22"
url = "https://github.com/RustCrypto/RSA/issues/626"
cvss = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"   # 5.9 Medium
aliases = ["CVE-2023-49092", "GHSA-c38w-74pg-36hr", "GHSA-4grx-2x9w-596c"]
[versions]
patched = []          # boş
```

Advisory, hâlihazırda yamalı bir sürüm bulunmadığını ve bakımcıların tam sabit zamanlı bir implementasyona doğru çalıştığını belirtir. Geçici çözüm olarak kullanıcıların `rsa` crate'ini zamanlama gözlemlerinin fizibil olmadığı senaryolarla sınırlaması önerilir; örneğin izole ve ele geçirilmemiş sistemler.

**Sürüm durumu** (crates.io API, 8 Eylül 2026). Stabil varsayılan 0.9.10'dur (6 Ocak 2026). En yeni sürüm 0.10.0-rc.18'dir (27 Nisan 2026) ve 18 release candidate sonrasında hâlâ RC aşamasındadır. Toplam 215.298.115 indirme alınmıştır, MSRV Rust 1.85'tir.

**Düzeltme çalışmasının durumu.** Issue #390 ("Migrating from `num-bigint(-dig)` to `crypto-bigint`", açılış 28 Kasım 2023, tarcieri) kapalıdır; `BoxedUint`, Montgomery ve sabit zamanlı modexp'e geçiş yapılmıştır. Issue #626 ("Padding implementation is not constant-time", açılış 7 Ocak 2026) açıktır. Bakımcı notuna göre implementasyondaki kalan yan kanallar muhtemelen artık `crypto-bigint`'ten değil, bu crate'in RSA padding modlarına ait implementasyonundan gelmektedir. RustSec advisory'sinin `url` alanı artık bu issue'ya işaret etmektedir. README hâlâ implementasyonun Marvin saldırısına açık olduğunu ve azaltma çabalarının issue #390'da sürdüğünü belirtmektedir. docs.rs 0.9.10 güvenlik notlarına göre modüler üs alma implementasyonu sabit zamanlı değildir ancak zamanlama değişkenliği rastgele blinding ile maskelenmektedir; crate Include Security tarafından bir kez denetlenmiştir.

> **Çelişki.** Marvin proje sayfası tablosunda RustCrypto RSA için CVE-2023-49092 "Fixed" olarak işaretlidir. Ancak RustSec advisory-db ana dalında `patched = []`, GitHub Advisory GHSA-c38w-74pg-36hr'de "Patched versions: None" yazmakta, upstream issue #626 açık ve Ocak 2026'da açılmış durumdadır ve crate README'si hâlâ uyarı vermektedir. Değerlendirme şudur: Kario'nun tablosu muhtemelen modexp düzeltmesini (issue #390 ve crypto-bigint) gördüğü için "Fixed" işaretlemiştir; padding tarafı hâlâ açıktır. Argus için karar `rsa` crate'inin private key işlemleri için üretimde kullanılmamasıdır.

**Rust JOSE kütüphanelerinin durumu.** `jsonwebtoken` 11.0.0 (24 Temmuz 2026, 183.855.256 indirme) yalnızca JWS sağlar, JWE yoktur. Kripto backend'i takılabilirdir: `aws_lc_rs` (aws-lc-rs 1.18.1, 1 Eylül 2026) veya `rust_crypto`. `CryptoProvider` deseni rustls'ten alınmıştır. Argus için RS256 imzalamada `aws_lc_rs` backend'ini seçmek `rsa` crate'inden kaçınmanın en temiz yoludur. `josekit` 0.10.3 (20 Mayıs 2025, 3.747.971 indirme) JWE dahil tam JOSE sağlar. README algoritma tablosunda `RSA1_5` (RSAES-PKCS1-v1_5) RSA-OAEP, OAEP-256, OAEP-384 ve OAEP-512 ile birlikte desteklenmektedir. Backend'i `openssl = "0.10.68"`, yani native OpenSSL'dir; dolayısıyla Marvin durumu sistemdeki OpenSSL sürümüne bağlıdır ve 3.2.0 ve üstünde implicit rejection açıktır. Bakım açısından 16 aydır güncelleme yoktur. `rustls` RSA key exchange desteklemez ve Marvin'e karşı yapısal olarak bağışıktır; Kario'nun listesinde rustls 0.21.9 zafiyetsiz olarak yer alır.

**Argus için RSA kararları.**

1. JWE `RSA1_5` hiç implemente edilmez. IETF zaten varsayılan olarak devre dışı bırakılmasını zorunlu kılmaktadır; hiç desteklememek downgrade yüzeyini sıfırlar.
2. JWE için birincil `ECDH-ES` ve `A256GCM`, gerekirse ikincil olarak ve yalnızca legacy istemciler için açıkça opt-in `RSA-OAEP-256` kullanılır.
3. İmzalama için birincil `EdDSA` (Ed25519) veya `ES256`, uyumluluk için `RS256` ve yalnızca `aws-lc-rs` backend ile kullanılır.
4. `rsa` crate'i bağımlılık ağacından çıkarılır (`cargo tree -i rsa` ile kontrol edilir) veya yalnızca public key doğrulamayla sınırlanır.
5. `alg` allowlist'i istemci metadata'sından gelir, JWE veya JWS header'ından değil.
6. CI'da `cargo audit` ve `cargo deny` ile RUSTSEC-2023-0071 açıkça izlenir.

---

## E. Spectre ve Meltdown sınıfı

### E.1 Tehdit modeli

Geçici yürütme saldırıları yerel kod yürütme veya aynı fiziksel makinede co-tenant gerektirir. Bir IdP için senaryolar şunlardır.

| Senaryo | Risk | Gerekçe |
|---|---|---|
| Kendi donanımı veya dedicated instance; başka kiracı yok | Çok düşük | Saldırgan kod çalıştıramaz |
| Çok kiracılı bulut, paylaşımlı VM host | Orta | VMScape ve cross-VM saldırıları |
| Paylaşımlı çekirdek üzerinde container'lar; aynı node'da güvenilmeyen iş yükü | Orta ile yüksek arası | Kullanıcıdan kullanıcıya ve kullanıcıdan kernel'e saldırılar |
| Argus'ta WASM, script veya plugin eklenti noktası varsa | Yüksek | Süreç içi güvenilmeyen kod; Spectre'ın klasik senaryosudur |
| Tarayıcı tarafı | İlgisiz | Kernel dokümantasyonuna göre Linux'un azalttığı CPU zafiyetlerinin genel olarak tarayıcı tabanlı sandbox'lardan sömürülebilir olduğu gösterilmemiştir |

### E.2 Mevcut manzara, 2024-2026

Linux kernel dokümantasyon ağacındaki tam hw-vuln listesi şudur (docs sürümü 7.3.0-rc2, 8 Eylül 2026):

```
attack_vector_controls, spectre, l1tf, mds, tsx_async_abort, multihit,
special-register-buffer-data-sampling, core-scheduling, l1d_flush,
processor_mmio_stale_data, cross-thread-rsb, srso, gather_data_sampling,
reg-file-data-sampling, rsb, old_microcode, indirect-target-selection, vmscape
```

Bu listede `vmscape`'ten daha yeni isimli bir zafiyet dokümanı yoktur; Eylül 2026 itibarıyla kernel'e yeni bir isimlendirilmiş sınıf eklenmemiştir.

| Saldırı | CVE | Yıl | Etki | Kaynak |
|---|---|---|---|---|
| Downfall (GDS) | CVE-2022-40982 | 2023 | Intel Skylake (6. nesil) ile Tiger Lake (11. nesil) arasında `gather` komutu vektör register dosyasını sızdırır, SGX dahil. Azaltma maliyeti %50'ye kadar çıkar. Bildirim 24 Ağustos 2022, embargo yaklaşık bir yıl | downfall.page |
| Zenbleed | CVE-2023-20593 | 2023 | AMD Zen 2 (Ryzen 3000, 4000, 5000-G ve EPYC Rome); `vzeroupper` yanlış tahmin kurtarması register sızdırır | lock.cmpxchg8b.com/zenbleed.html (Tavis Ormandy) |
| Inception (SRSO) | CVE-2023-20569 | 2023 | AMD Zen 1 ile Zen 4 arası (family 0x17 ve 0x19); RAP zehirlenmesi ve mimari olmayan CALL | Kernel `srso.rst` |
| Reptar | CVE-2023-23583 | 2023 | Intel redundant prefix; DoS veya ayrıcalık yükseltme. Bu bir yan kanal değildir | Kısmen doğrulanmıştır; lock.cmpxchg8b.com/reptar.html HTTP 200 döndürmüş ancak içerik JavaScript ile yüklendiği için metin çıkarılamamıştır. CVE numarası ikincil kaynaklardandır |
| Breaking the Barrier ve PB-Inception | CVE-2024-10041 (PAM zafiyeti için) | IEEE S&P 2025 | IBPB bariyerini bypass eder. Intel Core 12-14. nesil ve Xeon 5-6. nesilde mikrokod hatası, AMD'de IBPB'nin return tahminlerini temizlememesi. İlk pratik uçtan uca cross-process Spectre'dır: SUID `sudo`'dan root parolası, PB-Inception ile page cache'ten root parola hash'i elde edilmiştir | comsec.ethz.ch/research/microarch/breaking-the-barrier/ |
| Training Solo | CVE-2024-28956 (ITS), CVE-2025-24495 (Lion Cove BPU) | 2025 | Domain izolasyonunu tasarım gereği kırar; saldırgan aynı domain içinde self-training yapar. eBPF gerekmez, cBPF ve SECCOMP yeterlidir ve bunlar tüm kullanıcılara varsayılan açıktır. Kernel bellek sızıntısı 17 KB/sn, hipervizör belleği 8,5 KB/sn'dir. Etkilenenler eIBRS'li tüm Intel CPU'lardır (BHI_NO'lu Lion Cove dahil); ITS için Core 9-11. nesil ve Xeon 2-3. nesil. Azaltma yeni IBHF komutu (mikrokod), yeni indirect branch thunk'ları (cache line üst yarısı) ve IBPB mikrokod güncellemesidir | vusec.net/projects/training-solo/ |
| VMScape | CVE-2025-40300 | IEEE S&P 2026 | Tüm AMD Zen CPU'ları (Zen 5 dahil); BTB host ile guest ayrımı yapmaz. Kötü niyetli bir KVM guest'i QEMU gibi userspace hipervizörden anahtar sızdırır. Intel eIBRS BTB'yi ayırır ancak branch history'yi ayırmaz, dolayısıyla vBHI potansiyeli vardır; Intel doğrulamıştır, PoC yoktur. Zen 5 BTB'sinde tek bitlik privilege tag bulunur ancak dört domain için yetersizdir | comsec.ethz.ch ve kernel `vmscape.rst` |
| Stack Engine Attacks | — | MICRO 2025 | x86 stack engine, 2000'lerin ortasından beri her x86'da bulunan bir frontend optimizasyonudur ve Intel MPK ile kurulan süreç içi izolasyonu kırar. Recursive descent JSON parser'ın derinliğinden FHIR veri setindeki 120 hastadan beşini ayırt edebilmektedir. Zen 5'te AGESA varsayılan olarak add ve sub desteğini kapatır; Intel Alder Lake ve sonrası P-core'larda benzeri bulunur. Azaltma olarak veri değişmez kontrol akışı ve diğer sabit zamanlı programlama tekniklerinin iyi bir savunma sağladığı açıkça belirtilir | comsec.ethz.ch |

VMScape makalesi IEEE S&P 2026'da sunulacaktır; kernel'de `vmscape` dokümanı ve `vmscape=` boot parametresi mevcuttur. Bunun ötesinde 2026'ya özgü yeni bir isimlendirilmiş geçici yürütme saldırısı doğrulanamamıştır.

### E.3 Azaltmalar ve maliyetleri

**Linux `attack_vector_controls`.** Yeni ve çok pratiktir. Dokümantasyona göre saldırı vektörü kontrolleri, bir sistemin amaçlanan kullanımı göz önüne alındığında yalnızca ilgili CPU zafiyeti azaltmalarını yapılandırmak için basit bir yöntem sunar. Yöneticilerin hangi saldırı vektörlerinin ilgili olduğunu değerlendirmesi ve sistem performansını geri kazanmak için diğerlerinin tamamını devre dışı bırakması önerilir. Yeni ilgili CPU zafiyetleri bulunduğunda bunlar bu saldırı vektörü kontrollerine eklenecektir, dolayısıyla yöneticilerin komut satırı parametrelerini yeniden yapılandırması gerekmeyecektir.

Beş vektör vardır: `user_kernel`, `user_user`, `guest_host`, `guest_guest` ve `smt` (cross-thread). Dokümantasyon, tek kullanıcılı sistemlerde olduğu gibi güvenilmeyen kullanıcı uygulaması çalıştırılmıyorsa kullanıcıdan kernel'e azaltmaların devre dışı bırakılmasının değerlendirilmesini önerir. Ayrıca Linux kernel'i tüm fiziksel belleğin bir eşlemesini içerdiği için, kötü niyetli bir kullanıcı programının başka bir kullanıcı programından veri sızdırmasını engellemek tam koruma açısından kullanıcıdan kernel'e saldırıların da azaltılmasını gerektirir. Cross-thread için `'auto,nosmt'` SMT'yi kapatabilir; `'auto'` SMT'yi açık tutar ancak diğer azaltmalar devrede kalır.

**Core scheduling.** Dokümantasyona göre cross-HT saldırılarının tek tam azaltması Hyper Threading'i kapatmaktır. Core scheduling, bazı cross-HT saldırılarını azaltabilen bir scheduler özelliğidir ve yalnızca kullanıcı tarafından belirlenmiş güvenilir bir gruptaki görevlerin bir çekirdeği paylaşmasını sağlayarak HT'nin güvenli biçimde açılmasına imkân verir. Teorik olarak core scheduling en az Hyper Threading kapalıyken olduğu kadar iyi performans göstermeyi hedefler; pratikte çoğunlukla böyledir ancak her zaman değildir ve iş yüklerinin performansı mutlaka ölçülmelidir. API `prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE/SHARE_TO/SHARE_FROM, pid, pid_type, &cookie)` biçimindedir; cookie fork ve exec'te miras alınır.

**VMScape azaltması.** Kernel bir CPU'nun potansiyel olarak kötü niyetli bir guest çalıştırdığı durumu takip eder ve VM-exit'ten sonra kullanıcı alanına ilk çıkıştan önce IBPB verir. VM-exit ile bir sonraki VM-entry arasında kullanıcı alanı çalışmadıysa IBPB verilmez. SMT etkinken hipervizörler cross-thread saldırılara açık olabilir; SMT ortamlarında VMSCAPE saldırılarına karşı tam koruma için STIBP etkinleştirilmelidir. sysfs yolu `/sys/devices/system/cpu/vulnerabilities/vmscape`, boot parametresi `vmscape=off|ibpb|force`'tur.

**Confidential computing.** AMD SEV-SNP ve Intel TDX hipervizörden bellek şifrelemesi ve bütünlük sağlar. Ancak VMScape gibi branch predictor saldırıları mimari olmayan durumu hedefler; SEV-SNP tek başına Spectre-BTI'ı çözmez. Bu konuda derin doğrulama yapılmamıştır.

### E.4 Argus için pratik öneri

**Gerçekten önemli olanlar.**

1. Eklenti veya script motoru varsa bu konu birinci önceliktir. Argus'ta WASM plugin, Keycloak'takine benzer JavaScript authenticator script'leri veya Lua ile Rhai policy engine varsa süreç içi izolasyon Spectre'a karşı yeterli değildir. Stack engine makalesi tam olarak MPK tabanlı süreç içi izolasyonun kırıldığını göstermektedir. Çözüm eklentileri ayrı süreçte, hatta ayrı kullanıcı veya cgroup'ta çalıştırmak ve ana IdP sürecinde asla güvenilmeyen kod yürütmemektir. Keycloak'ın script'leri preview olarak işaretlemesi tesadüf değildir.
2. Barındırma kararı dedicated instance veya bare-metal yönünde verilir. Bulutta genel amaçlı paylaşımlı instance kullanılmaz. Bu karar tüm saldırı sınıfını tek hamlede tehdit modelinden çıkarır.
3. `mitigations=auto` varsayılanı bozulmaz. Performans için `mitigations=off` yapmak, özellikle imza anahtarları RAM'de duran bir IdP'de kabul edilemez.
4. Mikrokod güncel tutulur. Training Solo, Breaking the Barrier, Downfall ve VMScape azaltmalarının hepsi mikrokoda bağlıdır. Kernel'de `old_microcode` dokümanı ve uyarısı bulunur ve izlenmelidir.
5. Kernel LTS sürümü kullanılır ve güncel tutulur. VMScape SSS'ine göre Linux sistemlerde en son sürüme veya bakımı sürdürülen herhangi bir LTS sürümüne güncellemek yeterlidir.
6. İmza anahtarları süreç dışına çıkarılır; HSM, KMS veya ayrı bir imzalama servisi kullanılır. Anahtar Argus'un adres uzayında hiç bulunmuyorsa hiçbir Spectre varyantı onu okuyamaz. En yüksek getirili tek kontrol budur.
7. `zeroize` kullanılarak sırlar kullanım sonrası temizlenir ve sızıntı penceresi daraltılır.

**Bu bağlamda gereksiz olanlar.**

Uygulama kodunda Spectre-v1 için `lfence` serpiştirmek gereksizdir; LLVM'in `-mspeculative-load-hardening` seçeneği bile IdP iş mantığı için anlamsızdır, çünkü darboğaz orada değildir. Co-tenant yokken SMT kapatmak yaklaşık %20-30 throughput kaybına karşılık sıfır kazanç verir. Rust'ta Spectre'a dayanıklı bounds check yazmaya çalışmak gereksizdir; Rust'ın bounds check'i zaten vardır ve spekülatif bypass uygulama katmanında çözülemez. Tarayıcı tarafı önlemler (COOP ve COEP) kullanıcı arayüzü için iyi hijyendir ancak Spectre ile ilgili değildir.

---

## F. Argus için yapılacaklar

### F.1 Sabit zamanlı karşılaştırma

1. `constant_time_eq = "0.6"` bağımlılığı eklenir; crate aktif bakımdadır (30 Ağustos 2026). Kripto seçim mantığı gerekirse `subtle 2.6.1` (bakım durgun) veya `ctutils 0.4.2` (denetlenmemiş) seçilir ve karar gerekçeleriyle karar kaydına yazılır.
2. Newtype tasarımı uygulanır: `struct Secret<const N: usize>([u8; N])` tanımlanır, `PartialEq` implementasyonu `constant_time_eq_n` kullanır, `Debug` maskeler ve `Drop` `zeroize` yapar. Böylece `==` yazan geliştirici otomatik olarak güvende olur; bu totp-rs'in `Token` desenidir.
3. Tüm token'lar veritabanına SHA-256 hash'i olarak yazılır: session, refresh token, API anahtarı, şifre sıfırlama, device code ve magic link. Arama hash üzerinden yapılır ve veritabanı indeks zamanlaması sızıntısı ortadan kalkar.
4. Token'lar sabit uzunluk yapılır; uzunluk kontrolü sabit zamanlı karşılaştırmadan önce yapılır, çünkü uzunluk zaten sır değildir.
5. Clippy lint, `cargo-deny` veya özel bir lint ile sır tiplerinde `==`, `memcmp` ve `String::eq` kullanımı yasaklanır.
6. `*_vartime` isimlendirme kuralı benimsenir; bu RustCrypto politikasıdır.

### F.2 Derleyici doğrulaması

1. CI'a `dudect-bencher 0.7` ile bir `ct-bench` binary'si eklenir; token karşılaştırma, TOTP kontrolü, PKCE doğrulama ve client_secret doğrulama fonksiyonları test edilir. |t| değeri 5'i aşarsa build başarısız olur.
2. Gecelik bir job ile ctgrind ve valgrind memcheck üzerinden `ct_poison` yaklaşımı bir Rust FFI shim'iyle uygulanır; alternatif olarak Microwalk Docker şablonu Rust için uyarlanır.
3. Release binary'de assembly denetimi yapılır: kritik sabit zaman fonksiyonları için `cargo asm` veya `objdump` çıktısında `jne`, `je`, `bne` ve `cmov` beklentisi bir snapshot testi olarak sabitlenir. `cmov` CVE'si tam olarak böyle yakalanabilirdi.
4. `aarch64-dit` crate'i ile aarch64 hedeflerinde kripto bölgelerinde DIT açılır; RAII guard kullanılır.
5. x86'da DOITM için hazır crate yoktur ve Intel global açmayı önermemektedir. Şimdilik aksiyon alınmaz, yalnızca risk kaydına yazılır.
6. Bağımlılıklar `cargo audit` ile günlük taranır; RUSTSEC-2026-0003 (cmov) ile RUSTSEC-2026-0211 ve 0212 (libcrux) sabit zaman advisory'lerinin sık geldiğini göstermektedir.

### F.3 Enumeration

1. Login akışı kullanıcı ve parolanın birlikte alınıp ardından MFA'nın geldiği biçimde kurulur. Identity-first akışı kullanılmaz; gerekçe Kanidm'in tespiti ve Keycloak CVE-2026-4633'tür.
2. Rauthy modeli uygulanır: koşan başarılı login ortalaması tutulur ve başarısızlıkta yanıt ortalamaya doldurulur. Dummy Argon2 çalıştırılmaz, çünkü DoS üretir.
3. `max_hash_threads` semaforu ve `hash_await_warn_time` metriği eklenir. Kuyruk doluluğunun kullanıcı varlığına bağlı olmadığından emin olunur.
4. IP başına başarısız giriş sayacı ve üstel kara liste uygulanır; Rauthy'nin değerleri yedi denemede 60 saniye, on denemede 600 saniye, on beş denemede 900 saniye, yirmi denemede 3600 saniye ve yirmi beş denemede 24 saattir.
5. Enumeration regresyon test süiti yazılır: her akış için (login, kayıt, sıfırlama, MFA enroll, SCIM, device flow, OIDC hata) var olan ve olmayan kullanıcı arasında status kodu, gövdenin baytı baytına içeriği, header seti, redirect hedefi ve p50 ile p95 süreleri karşılaştırılır. Rauthy'de örneği vardır: `handler_users.rs:156` satırında kullanıcı sayımını önlemek için her zaman HTTP 200 dönülmesi gerektiği belirtilir.
6. Kayıtta "email already in use" bilgisi arayüzde gösterilmez, e-posta ile bildirilir; Rauthy'nin `email_registered_already.rs` deseni izlenir.
7. Argon2 parametre göçünde eski ve yeni parametrelerin süre farkı ölçülür; fark ortalama doldurma penceresinden büyükse migration zorlanır, yani kullanıcı login olduğunda yeniden hash'lenir.
8. HTTP/2 kullanılıyorsa Timeless Timing savunması olarak eşzamanlı gelen istek çiftlerine ortalama yaklaşık 1,73 ms rastgele gecikme eklemek değerlendirilir; alternatif olarak kritik endpoint'lerde HTTP/2 multiplexing sınırlanır.

### F.4 RSA ve JOSE

1. `alg=RSA1_5` hiç desteklenmez; taslak bunu varsayılan olarak devre dışı bırakmayı zorunlu kılar.
2. `alg=none` desteklenmez; aynı taslak geçerlidir.
3. JWE'de birincil `ECDH-ES+A256KW` ve `A256GCM` kullanılır; `RSA-OAEP-256` yalnızca opt-in legacy seçenek olarak bulunur.
4. İmzalamada birincil `EdDSA` veya `ES256` kullanılır; `RS256` uyumluluk için ve `aws-lc-rs` backend ile (`jsonwebtoken 11` `CryptoProvider`) tutulur.
5. `cargo tree -i rsa` çalıştırılır; `rsa` crate'i ağaçtaysa neden orada olduğu belgelenir. Private key işlemi yapıyorsa kaldırılır.
6. `alg` allowlist'i istemci metadata'sından gelir, JWS veya JWE header'ından değil. Downgrade testi yazılır.
7. SAML tarafı varsa `xmlenc#rsa-1_5` devre dışı bırakılır; xmlsec'in yaptığı budur.
8. RUSTSEC-2023-0071 ve RustCrypto/RSA issue #626 izleme listesine alınır.

### F.5 Barındırma ve donanım

1. Dedicated instance veya bare-metal kullanılır; paylaşımlı genel amaçlı bulut instance'ı kullanılmaz.
2. `mitigations=auto` varsayılanı korunur. Co-tenant veya güvenilmeyen VM varsa `mitigations=auto,nosmt` kullanılır.
3. Yeni `attack_vector_controls` ile gereksiz vektörler kapatılıp performans geri kazanılır; ancak `user_kernel` ve `user_user` kapatılmadan önce bu makinede güvenilmeyen kod çalışmadığı iddiası ispatlanır.
4. Mikrokod ve kernel LTS güncel tutulur; `old_microcode` uyarısı izlenir.
5. `/sys/devices/system/cpu/vulnerabilities/*` çıktısı dağıtım sağlık kontrolüne eklenir.
6. İmza anahtarları HSM veya KMS'e taşınır; en yüksek getirili tek kontrol budur.
7. Eklenti veya script motoru varsa ayrı süreçte çalıştırılır. Süreç içi sandbox (WASM veya MPK) Spectre'a karşı yeterli değildir; MICRO 2025 stack engine çalışması bunu göstermektedir.
8. `zeroize` ile sırlar temizlenir.

---

## G. Doğrulanmamış ve çelişkili maddeler

1. **Çelişkili.** `rsa` crate'inin Marvin durumu: Kario'nun tablosu "Fixed" der, RustSec, GHSA ve upstream yamalı sürüm bulunmadığını ve issue #626'nın (7 Ocak 2026) açık olduğunu gösterir. Upstream esas alınır ve düzeltilmemiş kabul edilir.
2. **Ölü kaynak.** NCC Group ve iSEC Partners "Double HMAC Verification" (Şubat 2011) blog yazısı erişilemezdir; Wayback'te snapshot yoktur. Teknik doğrudur, ancak kanonik kaynak olarak github.com/veorq/cryptocoding kullanılır.
3. **Kaynağa erişilemedi.** ARM DIT resmî dokümantasyonu (developer.arm.com ve support.arm.com) 403 ve boş içerik döndürmüştür. DIT bilgisi Linux kernel kaynak kodundan ve GoFetch SSS'inden doğrulanmıştır; ARM ARM'dan birebir alıntı verilememiştir.
4. **Kısmen doğrulandı.** Reptar ve CVE-2023-23583: sayfa JavaScript ile yüklendiği için metin çıkarılamamıştır. CVE numarası ikincil kaynaklardandır. Ayrıca bu bir yan kanal değil, DoS ve ayrıcalık yükseltmedir.
5. **Kısmen doğrulandı.** NIST SP 800-63B-4'ün yayın tarihi (26 Ağustos 2025 mi Temmuz 2025 mi) ve rate limiting maddesinin bölüm numarası kesin değildir. Enumeration hakkında normatif gereksinim bulunmadığı bulgusu ise tam metin taramasıyla doğrulanmıştır.
6. **Doğrulanmadı.** Microwalk için hazır bir Rust CI şablonu olup olmadığı; C ve JavaScript örnekleri mevcuttur.
7. **Doğrulanmadı.** 2026'ya özgü yeni bir isimlendirilmiş geçici yürütme saldırısı bulunamamıştır. Linux 7.3-rc2 dokümantasyon ağacında `vmscape`'ten yenisi yoktur. Bu yok anlamına gelmez, doğrulanamadı anlamına gelir.
8. **Doğrulanmadı.** SEV-SNP ve TDX'in VMScape sınıfı branch predictor saldırılarına karşı ne ölçüde koruduğu; derin doğrulama yapılmamıştır.
9. **Doğrulanmadı.** HTTP/3 ve QUIC üzerinde Timeless Timing Attack'ın pratik uygulanabilirliği; makale bunu değerlendirmediğini açıkça söylemektedir.
10. **Düzeltme.** docs.rs'in `subtle` sayfası küçük bir modelce 2.6.1'in 1 Eylül 2026'da yayımlandığı biçiminde özetlenmiştir; bu yanlıştır. crates.io API'sine göre 2.6.1 24 Haziran 2024 tarihlidir. crates.io esas alınır.
11. Rauthy kaynak kodu alıntıları `main` dalından, 8 Eylül 2026 tarihli snapshot'tan alınmıştır. Sürüm etiketi sabitlenmemiştir.

---

## Kaynaklar

Erişim tarihi 8 Eylül 2026'dır.

**Rust ve crate'ler.** doc.rust-lang.org/std/hint/fn.black_box.html (Rust 1.98.1, build 1 Eylül 2026); raw.githubusercontent.com/dalek-cryptography/subtle/main/README.md, docs.rs/subtle/latest/subtle/, crates.io/api/v1/crates/subtle, github.com/dalek-cryptography/subtle/commits/main.atom; raw.githubusercontent.com/RustCrypto/utils/master/ctutils/README.md ile cmov ve aarch64-dit README'leri; raw.githubusercontent.com/RustCrypto/crypto-bigint/master/README.md; raw.githubusercontent.com/RustCrypto/RSA/master/README.md, CHANGELOG.md ve docs.rs/rsa/latest/rsa/index.html; github.com/RustCrypto/RSA/issues/390 (kapalı) ve issues/626 (açık, 7 Ocak 2026); crates.io API'sinde rsa, argon2, constant_time_eq, cmov, ctutils, dudect-bencher, jsonwebtoken, josekit, totp-rs, aws-lc-rs ve aarch64-dit; github.com/rozbb/dudect-bencher; raw.githubusercontent.com/constantoine/totp-rs/master/src/lib.rs ve token.rs; raw.githubusercontent.com/Keats/jsonwebtoken/master/src/crypto/mod.rs; raw.githubusercontent.com/hidekatsu-izuno/josekit-rs/master/README.md ve Cargo.toml.

**Güvenlik advisory'leri.** rustsec.org/advisories/RUSTSEC-2023-0071.html ve github.com/advisories/GHSA-c38w-74pg-36hr; rustsec/advisory-db ana dalından RUSTSEC-2026-0003 (cmov, CVE-2026-23519, 14 Ocak 2026), RUSTSEC-2025-0144 (ml-dsa, CVE-2026-22705, 12 Aralık 2025), RUSTSEC-2026-0212 (libcrux-secrets, 26 Mayıs 2026), RUSTSEC-2026-0211 (libcrux-aesgcm, 14 Temmuz 2026), RUSTSEC-2024-0354 (vodozemac, CVE-2024-40640) ve RUSTSEC-2022-0018 (totp-rs, CVE-2022-29185); github.com/advisories/GHSA-rhgq-f8x5-j2jc (Keycloak CVE-2026-4633, 23 Mart 2026), github.com/keycloak/keycloak/issues/47619 ve issues/26625; djangoproject.com/weblog/2024/jul/09/security-releases/ (CVE-2024-39329) ve code.djangoproject.com/ticket/20760.

**Akademik.** usenix.org/system/files/sec20-van_goethem.pdf (Timeless Timing Attacks, USENIX Security 2020); cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf ve dl.acm.org/doi/10.1145/1455526.1455530 (Crosby ve diğerleri, 2009); crypto.stanford.edu/~dabo/papers/ssl-timing.pdf (Brumley ve Boneh, 2003); cl.cam.ac.uk/~rja14/Papers/whatyouc.pdf (Simon, Chisnall, Anderson; EuroS&P 2018); eprint.iacr.org/2016/1123.pdf (dudect, DATE 2017) ve github.com/oreparaz/dudect; usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida (ct-verif); arXiv:1912.08788 (Binsec/Rel, IEEE S&P 2020); eprint.iacr.org/2023/1442 (Marvin, ESORICS 2023).

**Araçlar, donanım ve kernel.** imperialviolet.org/2010/04/01/ctgrind.html; post-apocalyptic-crypto.org/timecop/; github.com/microwalk-project/Microwalk; github.com/veorq/cryptocoding; gofetch.fail (USENIX Security 2024); downfall.page; lock.cmpxchg8b.com/zenbleed.html; comsec.ethz.ch/research/microarch/ altındaki vmscape, breaking-the-barrier, microarchitectural-attacks-on-the-stack-engine ve spring sayfaları; vusec.net/projects/training-solo/; git.kernel.org üzerinde Documentation/admin-guide/hw-vuln/ altındaki index, attack_vector_controls, core-scheduling, vmscape ve srso dosyaları ile arch/arm64/kernel/entry.S ve cpufeature.c; intel.com'daki data operand independent timing ISA rehberi (güncelleme 10 Eylül 2025); raw.githubusercontent.com/openssl/openssl/master/CHANGES.md; people.redhat.com/~hkario/marvin/ ve github.com/tomato42/marvin-toolkit.

**Standartlar ve rehberler.** rfc-editor.org üzerinde RFC 8725, RFC 7636, RFC 8628 ve RFC 9106; ietf.org/archive/id/draft-ietf-jose-deprecate-none-rsa15-05.txt ve datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/; cheatsheetseries.owasp.org üzerinde Authentication, Password Storage ve Forgot Password cheat sheet'leri; owasp.org WSTG'de hesap sayımı ve tahmin edilebilir kullanıcı hesabı testi; pages.nist.gov/800-63-4/sp800-63b.html.

**Referans implementasyonlar.** github.com/sebadob/rauthy (main dalı, 8 Eylül 2026 tarball'ı): `login_delay.rs`, `oidc/authorize.rs`, `oidc/grant_types/device_code.rs`, `entity/clients.rs`, `api_keys.rs`, `sessions.rs`, `magic_links.rs` ve `config.toml`; sebadob.github.io/rauthy/config/argon2.html; keycloak.org/server/all-provider-config ve keycloak.org/docs/latest/server_admin/index.html; github.com/kanidm/kanidm/discussions/610 (14 Kasım 2021).
