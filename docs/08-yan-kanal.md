# 8. Yan kanal ve zamanlama saldırıları

> `ARGUS.md` §8'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§8 §X` referansları aynı anlamda.



---

### 0. Yönetici özeti — gerçek risk sıralaması

| # | Konu | Gerçek risk | Argus'ta yeri |
|---|---|---|---|
| 1 | **Kullanıcı sayımı (enumeration)** — zamanlama + mesaj/status/uzunluk farkı | **Yüksek, kesin sömürülebilir** | Login, kayıt, şifre sıfırlama, MFA kaydı, SCIM |
| 2 | **`rsa` crate'inin Marvin durumu** | **Yüksek** — 2026'da hâlâ yamalı sürüm yok | JWE RSA1_5, RSA imzalama |
| 3 | **JWE `RSA1_5` desteği** | **Yüksek** — IETF varsayılan olarak kapatılmasını MUST diyor | JOSE katmanı |
| 4 | **Sabit-zamanlı karşılaştırma eksikliği** (token/HMAC/TOTP/PKCE/client_secret) | **Orta-Yüksek** (HTTP/2 varsa yüksek) | Tüm kimlik doğrulama yolları |
| 5 | **Argon2 DoS** (dummy hash veya yüksek parametre) | **Orta-Yüksek** | Login endpoint |
| 6 | **Derleyicinin sabit-zamanı bozması** | **Orta** — 2026'da Rust'ta gerçek CVE var | Kripto yardımcı kodu |
| 7 | **Spectre/Meltdown sınıfı** | **Düşük** (co-tenant yoksa) / **Yüksek** (plugin/WASM varsa) | Barındırma + eklenti motoru |

---

## A) RUST'TA SABİT-ZAMANLI KARŞILAŞTIRMA

### A.1 `subtle` crate — durum 2026

**Sürüm ve bakım (doğrulanmış):**
- Son sürüm **2.6.1, 24 Haziran 2024**; toplam 682.501.354 indirme. Kaynak: crates.io API — `https://crates.io/api/v1/crates/subtle` (2026-09-08 çekildi).
- **Son commit: 19 Haziran 2024.** Kaynak: `https://github.com/dalek-cryptography/subtle/commits/main.atom` (2026-09-08). Yani **26 aydır hiçbir commit yok.** Bu, "en güvenli IdP" hedefi için dikkate alınması gereken bir bakım riski.
- 2.6.0 yanked, 2.5.0 (2023-02-28), MSRV Rust 1.41.

**Sunduğu API:** `Choice` (u8 sarmalayıcı, 0/1), `CtOption<T>`, `ConstantTimeEq`, `ConstantTimeGreater`, `ConstantTimeLess`, `ConditionallySelectable`, `ConditionallyNegatable`.

**Dokümante edilmiş çekinceler — README'den birebir** (`https://raw.githubusercontent.com/dalek-cryptography/subtle/main/README.md`):

> "This crate represents a "best-effort" attempt, since side-channels are ultimately a property of a deployed cryptographic system including the hardware it runs on, not just of software."
>
> "The traits are implemented using bitwise operations, and should execute in constant time **provided that a) the bitwise operations are constant-time and b) the bitwise operations are not recognized as a conditional assignment and optimized back into a branch.**"
>
> "For a compiler to recognize that bitwise operations represent a conditional assignment, it needs to know that the value used to generate the bitmasks is really a boolean `i1` rather than an `i8` byte value. **In an attempt to prevent this refinement, the crate tries to hide the value of a `Choice`'s inner `u8` by passing it through a volatile read.**"
>
> "Note: the `subtle` crate contains `debug_assert`s to check invariants during debug builds. **These invariant checks involve secret-dependent branches**, and are not present when compiled in release mode. This crate is intended to be used in release mode."

docs.rs özetinde de aynı ifade: *"any such effort is fundamentally limited. **USE AT YOUR OWN RISK**"* (`https://docs.rs/subtle/latest/subtle/`).

**Kritik nokta:** `subtle` **`black_box` kullanmıyor** — volatile read kullanıyor. Bu, LLVM'in `Choice`'ı `i1`'e daraltıp branch'e çevirmesini engellemeye yönelik *bir umut*, garanti değil.

### A.2 Alternatifler — 2026'da daha iyi seçenekler var

| Crate | Sürüm / tarih | Ne sunuyor |
|---|---|---|
| **`constant_time_eq`** | **0.6.0, 2026-08-30**, 307.711.245 indirme, `codeberg.org/cesarb/constant_time_eq` | Sadece eşit uzunluklu byte dizisi karşılaştırma. Aktif bakımda. |
| **`cmov`** | **0.5.4, 2026-05-28**, RustCrypto | x86/x86_64 `CMOVZ/CMOVNZ`, aarch64 `CSEL` — **inline `asm!` ile**, "guaranteed ... to execute in constant-time and not be rewritten as branches by the compiler". LLVM'in `x86-cmov-conversion` pass'ini bypass eder. |
| **`ctutils`** | **0.4.2, 2026-04-02**, RustCrypto | `cmov` üstüne kurulu, `subtle`'ın modern muadili: `Choice`, `CtOption`, `CtFind`, `CtLookup`, `const fn` desteği. |
| **`aarch64-dit`** | 0.1.0, 2024-09-06, RustCrypto | ARM DIT bit'ini RAII guard ile açıp kapatır. |

`ctutils` README'sinden (`https://raw.githubusercontent.com/RustCrypto/utils/master/ctutils/README.md`):
> "**Guaranteed** constant-time equality testing and conditional selection on `x86(_64)` and `aarch64` using `asm!` implementations in the `cmov` crate ... with a portable "best effort" fallback on other platforms using bitwise arithmetic and `black_box`"
>
> "This is an **experimental next-generation** constant-time library inspired by `subtle`, but **for now we recommend you continue to stick with `subtle`**."
>
> "⚠️ **The implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!**"

**Argus için öneri:** x86_64/aarch64 hedefliyorsanız `constant_time_eq` (basit byte karşılaştırma için, aktif bakımda) + kripto seçim mantığı gerekiyorsa `subtle` (olgun) veya `ctutils` (garanti daha güçlü ama denetlenmemiş). `subtle`'ı seçerseniz **bakım durgunluğunu risk kaydına yazın**.

### A.3 Sabit-zamanlı karşılaştırmanın ZORUNLU olduğu yerler (IdP'ye özgü)

Sıralama: gerçek uzaktan sömürülebilirlik değerlendirmesiyle.

| # | Yer | Zorunlu mu | Gerekçe |
|---|---|---|---|
| 1 | **Opak session/bearer token DB araması** | **Evet — ama asıl çözüm hash'lemek** | Token'ı düz saklarsanız hem karşılaştırma hem **DB indeks karşılaştırması** sızdırır (B-tree karşılaştırmaları prefix'e göre erken çıkar). Çözüm: DB'ye `SHA-256(token)` yaz, araması bu hash üzerinden olsun, dönen kaydı `constant_time_eq` ile doğrula. |
| 2 | **HMAC / JWS imza doğrulama (HS256)** | **Evet** | Klasik. Keyczar 2009 zafiyeti tam olarak buydu (cryptocoding referansı, aşağıda). |
| 3 | **TOTP kodu karşılaştırma** | **Evet** | **Gerçek CVE var:** `totp-rs` — RUSTSEC-2022-0018 / CVE-2022-29185, 2022-05-09, `TOTP::check` sabit zamanlı değildi, 1.1.0'da `constant_time_eq` ile düzeltildi. Bugünkü kaynak (6.0.0) `Token::eq` içinde `constant_time_eq::constant_time_eq_n` kullanıyor — doğruladım. 6 haneli kodda arama uzayı 10⁶ olduğu için byte-byte sızıntı gerçekten kritik. |
| 4 | **client_secret karşılaştırma** | **Evet** | Rauthy sabit uzunluk zorlayıp `constant_time_eq_64` kullanıyor (kaynak doğrulandı). |
| 5 | **API anahtarı** | **Evet + hash'le** | Rauthy: `EncValue::encrypt(sha256!(secret))` saklıyor, doğrulamada `constant_time_eq(self.secret, sha256!(secret))`. |
| 6 | **CSRF / state token** | **Evet** | Rauthy `sessions.rs::validate_csrf` ve `magic_links.rs` içinde `constant_time_eq`. |
| 7 | **Şifre sıfırlama token'ı / magic link** | **Evet + hash'le + tek kullanımlık** | OWASP Forgot Password Cheat Sheet: token'lar "Randomly generated using a cryptographically safe algorithm, Sufficiently long, Stored securely, Single use and expire". |
| 8 | **PKCE `code_verifier` → `code_challenge`** | **Evet (pratikte düşük risk)** | **RFC 7636 sabit zaman ZORUNLU KILMIYOR** — §4.6 sadece `BASE64URL-ENCODE(SHA256(...)) == code_challenge` diyor (`https://www.rfc-editor.org/rfc/rfc7636.txt`). §7.1 en az 256 bit entropi öneriyor; entropi yüksek olduğu için byte-byte sızıntı bile pratikte sömürülemez ama maliyeti sıfır olduğundan yine de yapın. Rauthy yapıyor (`login_finish.rs:60`). |
| 9 | **Device code / user code** | **Evet (düşük risk) + rate limit ZORUNLU** | RFC 8628 §5.1: *"it is recommended that the server rate-limit user code attempts"*; 8 karakter base-20 (≈34.5 bit) için 2⁻³² başarı olasılığı ancak **5 deneme** izniyle sağlanır. §5.2 device code brute force. Asıl savunma rate-limit, sabit zaman değil. |
| 10 | **WebAuthn challenge karşılaştırma** | **Evet ama düşük** | Challenge ≥16 rastgele byte + tek kullanımlık; asıl güvenlik imza doğrulamada. Yine de eşitlik kontrolünü CT yapın. |

**Rauthy'nin ilginç karşı-argümanı** — `src/service/src/oidc/grant_types/device_code.rs` (kaynak birebir):
> "The constant time comparison for both the device code and the client secret don't make any sense in terms of security here, but I don't want any other brain-dead AI security report about it. The device code is very short-lived, rate-limited and even deleted after 3 times rate-limit abuse. ... this comparison happens in single digit nanoseconds and is practically impossible to measure in this API. Scheduling an async task that is ready for work takes even longer than that..."

Bu argüman **kısmen** doğru — ama Timeless Timing Attacks (aşağıda) tam olarak bu "ölçülemez" varsayımını yıkıyor.

### A.4 Uzaktan zamanlama saldırısı gerçekten fizibil mi? — Klasik literatür

**1) Brumley & Boneh, "Remote Timing Attacks are Practical" (2003)**
`https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf` (PDF çekilip metin çıkarıldı)
> "We show that timing attacks apply to general software systems. Specifically, we devise a timing attack against OpenSSL. ... we can extract private keys from an OpenSSL-based web server running on a machine in the local network."
> Üç ortam: **Network** (kampüs ağı, 3 router arası), **Interprocess** (aynı makinede iki süreç), **Virtual Machines** (VMM izolasyonunu delip diğer VM'den RSA anahtarı çıkarma).

**2) Crosby, Wallach & Riedi, "Opportunities and Limits of Remote Timing Attacks" (ACM TISSEC, 2009)**
`https://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf` · `https://dl.acm.org/doi/10.1145/1455526.1455530`
- Jitter filtreleriyle **İnternet üzerinden 15–100 µs**, **LAN üzerinden 100 ns** çözünürlük.
- Timeless makalesinin alıntısıyla: *"Crosby et al. found that the Box Test performs best, and were able to measure a timing difference of 20µs over the Internet and 100ns over the LAN"*.

**3) ⭐ Van Goethem, Pöpper, Joosen, Vanhoef — "Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections", USENIX Security 2020**
`https://www.usenix.org/system/files/sec20-van_goethem.pdf` (PDF çekilip metin çıkarıldı) · `https://www.usenix.org/conference/usenixsecurity20/presentation/van-goethem`

**Bu, IdP tehdit modelinizi değiştiren makale.** Birebir alıntılar:
> "These concurrency-based timing attacks infer a relative timing difference by analyzing **the order in which responses are returned**, and thus do not rely on any absolute timing information. ... can accurately detect timing differences as small as **100ns**, similar to attacks launched on a local system."
>
> "On web servers hosted over HTTP/2, we find that a timing difference as small as **100ns can be accurately inferred from the response order of approximately 40,000 request-pairs**. The smallest timing difference that we could observe in a traditional timing attack over the Internet was 10µs, **100 times higher**."
>
> "Our proposed concurrency-based timing attacks are **completely unaffected by network conditions, regardless of the distance** between the adversary and the victim server."

Mekanizma: İki HTTP/2 isteği **tek bir TCP paketinde** birleşir → sunucuya aynı anda varır → eşzamanlı işlenir → hangisinin cevabının önce döndüğü ölçülür. Ağ jitter'ı hem yukarı hem aşağı yönde tamamen elenir. Tor onion servisleri ve VPN/SOCKS tünelleri de aynı paket birleştirmeyi sağlıyor. HTTP/3 için: *"we did not evaluate this protocol as it is not yet widely deployed"* — yani **[KISMEN DOĞRULANMAMIŞ]** ama multiplexing olduğu için aynı prensip geçerli.

**Argus için sonuç:** Argus HTTP/2 (veya HTTP/3) sunuyorsa — ki modern bir IdP sunar — Rauthy'nin "tek haneli nanosaniye ölçülemez" argümanı **artık geçerli değil**. 100 ns'lik fark 40.000 istek çiftiyle ölçülebiliyor. 32 byte'lık bir token'ın byte-byte karşılaştırmasında ilk byte farkı ~1-2 ns, ama 16. byte'a kadar birikirse fark 10-30 ns'ye çıkar; 40k istek/byte × 256 tahmin ile brute force teorik olarak mümkün. **Kesin sonuç: tüm sır karşılaştırmalarında CT kullanın, tartışma yok.**

**Makalenin önerdiği savunmalar (§6.3):**
> "The most effective counter-measure against timing attacks is to ensure constant time execution. However, this can be very difficult ... A straightforward defense is **adding a random delay on incoming requests**. To mimic network conditions where the standard deviation of the jitter is 1ms, this delay can be sampled uniformly at random from the range [0, √12] ms, resulting in an average delay of ≈1.73ms for every request. However, **only requests that arrive simultaneously at the server need to be padded**."

Yani: eşzamanlı gelen istek çiftlerine rastgele gecikme ekleyerek saldırıyı "sıradan sıralı zamanlama saldırısı" seviyesine indirebilirsiniz — yok edemezsiniz.

### A.5 Sabit-zamanlı karşılaştırmaya alternatifler

**1) Hash-then-compare (DB'de hash saklama) — EN İYİ ÇÖZÜM**
Token'ı DB'ye düz yazmayın. `SHA-256(token)` yazın:
- Karşılaştırma zamanlaması sızıntısı: hash çıktıları saldırganın kontrolünde olmadığı için byte-byte sızıntı işe yaramaz.
- **DB indeks zamanlaması sızıntısı da ölür** — B-tree/hash-index araması hash üzerinde yapılır.
- DB dump'ı çalınırsa token'lar kullanılamaz (bu tek başına yeterli gerekçe).
- Gerçek örnek: Rauthy `api_keys.rs:84,148,444` ve `pam/remote_password.rs:25,61` — `sha256!` ile saklayıp `constant_time_eq` ile doğruluyor.
- **Not:** Token yüksek entropili (≥128 bit) olduğu için SHA-256 yeterli; Argon2 gerekmez.

**2) Double-HMAC / HMAC-then-compare**
`compare(HMAC(k, a), HMAC(k, b))` — `k` her süreç başlangıcında üretilen rastgele anahtar. Saldırgan karşılaştırılan değerleri tahmin edemediği için erken-çıkışlı `memcmp` bile güvenli hale gelir.
- ⚠️ Orijinal NCC Group / iSEC Partners "Double HMAC Verification" (Şubat 2011) blog yazısı **artık erişilemiyor** — hem `nccgroup.com/us/research-blog/...` (404) hem `research.nccgroup.com/2011/02/07/...` hem de Wayback CDX'te snapshot yok (2026-09-08 kontrol edildi). **[KAYNAK ÖLÜ]**
- Yerine kullanılabilir kanonik kaynak: **Cryptography Coding Standard**, "Compare secret strings in constant time" — `https://github.com/veorq/cryptocoding` — Keyczar zafiyetine (Nate Lawson, 2009) ve OpenBSD `memcmp` erken-çıkış implementasyonuna atıf yapıyor.

**3) Uzunluk sızıntısına dikkat**
`constant_time_eq` **eşit uzunluk gerektirir**; uzunluk farkı zaten sızar. Token'ları sabit uzunluk yapın (Rauthy `SECRET_LEN_CLIENTS = 64` sabitini `debug_assert_eq!` ile zorluyor).

---

## B) DERLEYİCİ SABİT-ZAMANI BOZUYOR MU? — EVET, RUST'TA DA

### B.1 ⭐ En güçlü kanıt: Rust standart kütüphanesinin kendi dokümantasyonu

`https://doc.rust-lang.org/std/hint/fn.black_box.html` (Rust **1.98.1**, build `48a229cea 2026-09-01`, 2026-09-08 çekildi) — **birebir**:

> "Note however, that `black_box` is only (and can only be) provided on a **"best-effort" basis**. The extent to which it can block optimisations may vary depending upon the platform and code-gen backend used. **Programs cannot rely on `black_box` for correctness**, beyond it behaving as the identity function. As such, it must not be relied upon to control critical program behavior.
>
> **This also means that this function does not offer any guarantees for cryptographic or security purposes.**
>
> **This limitation is not specific to `black_box`; there is no mechanism in the entire Rust language that can provide the guarantees required for constant-time cryptography. (There is also no such mechanism in LLVM, so the same is true for every other LLVM-based compiler.)**"

Bu, resmi Rust dokümantasyonunun açık kabulü. Argus'un tehdit modeli belgesine birebir alınmalı.

### B.2 ⭐⭐ Gerçek, güncel Rust CVE'leri — risk teorik değil

RustSec advisory-db'nin **ana dalını indirip taradım** (`https://codeload.github.com/rustsec/advisory-db/tar.gz/refs/heads/main`, 2026-09-08). Sabit-zamanlılıkla ilgili advisory'ler:

**① RUSTSEC-2026-0003 / CVE-2026-23519 — `cmov`, 14 Ocak 2026** ⭐ (en önemli kanıt)
`https://github.com/RustCrypto/utils/security/advisories/GHSA-2gqc-6j2q-83qp`
Başlık: *"Non-constant-time code generation on ARM32 targets"*
> "This implementation uses a combination of bitwise arithmetic and `core::hint::black_box` to attempt to coerce constant-time code generation out of the optimizer, but **the implementation in v0.4.3 and earlier failed to do this on 32-bit ARM targets.**"
>
> Üretilen assembly:
> ```asm
> bne  .LBB0_2      ; Branch if Not Equal  ← BRANCH!
> mvns r3, r3
> ```
> "Branch instructions inserted by the LLVM optimizer on 32-bit targets can be leveraged using various microarchitectural sidechannels like cache timing attacks..."
>
> Çözüm: v0.4.4 taktiksel `black_box` yamalı, **v0.4.5 `asm!` ile yeniden yazıldı**. CVSS 4.0 AV:N/AC:H, VC:H/SC:H.

**Anlam:** RustCrypto ekibinin, tam da bu iş için yazdığı, `black_box`'ı bilinçli kullanan crate'te bile LLVM branch üretti. `black_box`'a güvenmek çalışmıyor; `asm!` çalışıyor.

**② RUSTSEC-2025-0144 / CVE-2026-22705 — `ml-dsa`, 12 Aralık 2025**
> "The analysis was performed using **a constant-time analyzer that examines compiled assembly code** for instructions with data-dependent timing behavior. The analyzer flags: **UDIV/SDIV instructions**: Hardware division instructions have early termination optimizations where execution time depends on operand values."
> `r1.0 /= TwoGamma2::U32;` — gizli anahtardan türeyen veride donanım bölmesi. Düzeltme: **Barrett reduction**. Patched ≥ 0.1.0-rc.3.

**③ RUSTSEC-2026-0212 — `libcrux-secrets`, 26 Mayıs 2026**
aarch64 inline `asm!`'de `cmp` 32-bit register kullanıyordu, 8-bit selector'ın üst 24 biti tanımsızdı → `Select::select` ve `Swap::swap` yanlış sonuç verebiliyordu. `tst` + maske ile düzeltildi (≥0.0.6).

**④ RUSTSEC-2026-0211 — `libcrux-aesgcm`, 14 Temmuz 2026**
> "AES-GCM decryption used an implementation for checking the provided authentication tag ... that was **intended to be constant-time, but resulted in non-constant-time code generation in certain circumstances.** Note that `libcrux-aesgcm` **does not give guarantees on constant-time code generation** and possible mitigations must be considered on a best-effort basis."
> `versions.patched = []` (advisory düzeyinde), gerçek düzeltme `libcrux-aes@v0.0.9`.

**⑤ RUSTSEC-2024-0354 / CVE-2024-40640 — `vodozemac`, 17 Temmuz 2024**
Sabit-zamanlı olmayan **base64 decoder** gizli anahtar materyalini sızdırıyordu. Bu, "sadece karşılaştırma değil, tüm sır işleme yolu" dersidir.

**⑥ RUSTSEC-2022-0018 / CVE-2022-29185 — `totp-rs` (yukarıda, A.3).**

### B.3 Akademik literatür

**"What you get is what you C: Controlling side effects in mainstream C compilers"** — Laurent Simon (Samsung Research America / Cambridge), David Chisnall, Ross Anderson, **IEEE EuroS&P 2018**. PDF: `https://www.cl.cam.ac.uk/~rja14/Papers/whatyouc.pdf` (indirilip metin çıkarıldı). Abstract birebir:
> "But when a programmer tries to control side effects of code, such as to make a cryptographic algorithm execute in constant time, the problem remains. **Programmers devise complex tricks to obscure their intentions, but compiler writers find ever smarter ways to optimize code. A compiler upgrade can suddenly and without warning open a timing channel in previously secure code. This arms race is pointless and has to stop.**"
> Katkı: Clang/LLVM'e **constant-time selection** ve **register/stack erasure** için doğrudan derleyici desteği eklemişler.

**"Dude, is my code constant time?"** — Oscar Reparaz, Josep Balasch, Ingrid Verbauwhede. IACR ePrint 2016/1123 (Aralık 2016), **DATE 2017**. `https://eprint.iacr.org/2016/1123.pdf` · Kod: `https://github.com/oreparaz/dudect`
- ~350 satır C; hedef platformda kara-kutu istatistiksel sızıntı tespiti (Welch t-testi). |t| > 5 → sızıntı çok muhtemel.
- README'den örnek çıktı: `./dudect_cmpmemcmp_-O2` → `max t: +1271.13 ... Definitely not constant time.` (memcmp tabanlı MAC karşılaştırma).

**Cryptography Coding Standard** — `https://github.com/veorq/cryptocoding`, "Prevent compiler interference with security-critical operations": Tor'daki `memset`'in MSVC 2010 tarafından silinmesi; `volatile` fonksiyon pointer hilesi ve Colin Percival'ın *"may not be sufficient"* errata'sı (`https://www.daemonology.net/blog/2014-09-05-erratum.html`).

### B.4 Doğrulama araçları — ne kullanılabilir

| Araç | Tip | URL / Referans | Notlar |
|---|---|---|---|
| **dudect** | Dinamik, istatistiksel, kara kutu | `https://github.com/oreparaz/dudect` | Donanım modeli gerektirmez |
| **`dudect-bencher`** (Rust) | Dinamik | **0.7.0, 2026-03-23**, 191.096 indirme, `https://github.com/rozbb/dudect-bencher/` | Rust portu. README uyarısı: *"In general, it is not possible to prove that a function always runs in constant time. The purpose of this tool is to find non-constant-timeness when it exists ... it requires the user to think very hard about where the non-constant-timeness might be."* **Argus'un CI'ına eklenebilecek en pratik araç.** |
| **ctgrind** (Adam Langley, 1 Nisan 2010) | Valgrind/memcheck | `https://www.imperialviolet.org/2010/04/01/ctgrind.html` | Gizli veriyi "uninitialised" olarak işaretle (`ct_poison`), memcheck secret-dependent branch/memory-access'i yakalar. Langley bu araçla OpenSSL'in `BN_mod_exp_mont_consttime`'ının sabit zamanlı **olmadığını** bulmuş. |
| **TIMECOP** | Valgrind, SUPERCOP üzerinde | `https://post-apocalyptic-crypto.org/timecop/` | 2.700+ kripto implementasyonu tarıyor. **Bilinen sınırı (birebir): "Valgrind cannot spot cases where variable-time code is caused by variable-time CPU instructions."** — yani `ml-dsa`'daki UDIV'i yakalayamaz. |
| **ct-verif** | Statik/formal (LLVM, SMACK+Boogie) | Almeida, Barbosa, Barthe, Dupressoir, Emmi — USENIX Security 2016, `https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida` | Ürün-program indirgemesi Coq'ta doğrulanmış |
| **Binsec/Rel** | İkili düzey ilişkisel sembolik yürütme | Daniel, Bardin, Rezk — IEEE S&P 2020, arXiv:1912.08788 (`http://export.arxiv.org/api/query?id_list=1912.08788`, doğrulandı) | Derleyicinin ürettiği ikiliyi analiz eder — kaynak kodu değil |
| **Microwalk** | Dinamik ikili enstrümantasyon + istatistik | `https://github.com/microwalk-project/Microwalk` | **CI entegrasyonu var** (GitHub Actions şablonları, hazır Docker imajları, GitHub UI'da satır-içi sızıntı raporu). C ve JS örnek repoları mevcut. Rust için hazır şablon **[DOĞRULANMADI]**. |
| **cachegrind** | Cache profili | Valgrind paketi | Sadece kaba sinyal |

### B.5 RustCrypto'nun politikası

`crypto-bigint` README (`https://raw.githubusercontent.com/RustCrypto/crypto-bigint/master/README.md`) — birebir:
> "**All functions contained in the crate are designed to execute in constant time unless explicitly specified otherwise (via a `*_vartime` name suffix).**"
> "This crate has been **audited by NCC Group** with no significant findings. ... Note that **the implementation has diverged significantly since the last audit.**"
> "This library is **NOT suitable for use on processors with a variable-time multiplication operation** (e.g. short circuit on multiply-by-zero / multiply-by-one, such as certain 32-bit PowerPC CPUs and some non-ARM microcontrollers)."

**`*_vartime` isimlendirme kuralı Argus için doğrudan benimsenmeli.**

**CI'da ne yapıyorlar?** RustCrypto/utils'in `.github/workflows/` dizinini indirip taradım (2026-09-08): `aarch64-dit.yml`, `cmov.yml`, `ctutils.yml`, `security-audit.yml`... — **dudect/valgrind tabanlı otomatik sabit-zaman testi yok**. `cmov` CVE'si de zaten harici bir raporla ortaya çıktı. Yani **RustCrypto bile CI'da CT doğrulaması yapmıyor** — Argus bunu yaparsa ekosistemin önüne geçmiş olur.

**fiat-crypto** (`https://github.com/mit-plv/fiat-crypto`): Coq'ta formal olarak doğrulanmış alan aritmetiği üreteci; Rust backend'i var ve `curve25519-dalek`/BoringSSL/Firefox tarafından kullanılıyor. IdP için doğrudan gerekli değil (eğri aritmetiği yazmıyorsunuz), ama "doğru yapılmış" referansı olarak değerli.

### B.6 Donanım: yazılım tek başına yetmiyor

**Intel DOIT / DOITM**
`https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html` (belge güncelleme tarihi: **10 Eylül 2025**; not: intel.com curl'e 403 döndü, WebFetch ile alındı)
- `IA32_UARCH_MISC_CTL` MSR (0x1B01), DOITM bit'i. Açıkken listelenen komutlar "timing independent of the data values in the sources".
- **Ice Lake ve sonrası** Core, **Gracemont ve sonrası** Atom DOITM'i enumerate ediyor. Daha eski işlemcilerde mod "her zaman açık" varsayılıyor.
- ⚠️ Intel açıkça uyarıyor: *"the performance impact of this mode may be **significantly higher on future processors**"* ve **global olarak açılmasını önermiyor**; gelecekte uygulama-başına ince taneli kontrol planlıyor.
- **Rust ekosisteminde DOITM'i açan yaygın bir crate bulamadım** — RustCrypto/utils dizin listesinde `aarch64-dit` var ama x86 muadili yok (2026-09-08 doğrulandı). **[BOŞLUK]**

**ARM DIT (FEAT_DIT, PSTATE.DIT)**
- ARM developer dokümantasyonu curl'e 403, WebFetch'e boş içerik döndü — **doğrudan alıntı alınamadı [KAYNAK ERİŞİLEMEDİ]**.
- Ancak **Linux kernel kaynağından doğrulandı** (`https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/arch/arm64/kernel/`):
  - `entry.S:199` → `alternative_insn nop, SET_PSTATE_DIT(1), ARM64_HAS_DIT` — **kernel, EL0'dan girişte DIT'i açıyor.**
  - `cpufeature.c:3057-3064` → `.desc = "Data independent timing control (DIT)"`, `ARM64_HAS_DIT`, `ID_AA64PFR0_EL1.DIT`.
- Rust: `aarch64-dit` 0.1.0 (2024-09-06), `cpufeatures::new!(dit_supported, "dit")` ile runtime tespit + RAII guard.

**GoFetch (USENIX Security 2024) — sabit-zamanlı kodun donanımda kırılması**
`https://gofetch.fail/` (2026-09-08 çekildi)
> "GoFetch is a microarchitectural side-channel attack that can extract secret keys from **constant-time cryptographic implementations** via **data memory-dependent prefetchers (DMPs)**."
> "the DMP activates (and attempts to dereference) data loaded from memory that "looks like" a pointer. **This explicitly violates a requirement of the constant-time programming paradigm**, which forbids mixing data and memory access patterns."
> Uçtan uca anahtar çıkarma: **OpenSSL Diffie-Hellman, Go RSA-2048 decryption, CRYSTALS-Kyber, CRYSTALS-Dilithium** — Apple M1'de gösterildi, M2/M3'te de benzer DMP davranışı.
> DMP kapatma: **"the DIT bit set on m3 CPUs effectively disables the DMP. This is not the case for the m1 and m2."** Intel'in DOIT bit'i Raptor Lake'te DMP'yi kapatıyor.
> Nisan 2024 güncellemesi: Hector Martin (marcan) M1/M2 için `SYS_APL_HID11_EL1[30]` chicken bit'i buldu; macOS'ta kernel desteği yok.
> Aralık 2024 devamı: **"Peek-a-Walk: Leaking Secrets via Page Walk Side Channels"** — Intel DMP semantiği tersine mühendislikle çözüldü.
> Apple'a bildirim: 5 Aralık 2023. Pwnie Award 2024 "Best Cryptographic Attack".

**Argus için anlamı:** M-serisi Mac üzerinde geliştirme/test yapıyorsanız sorun yok (yerel makine). **Üretimde Apple Silicon sunucu kullanmayın** ve zaten yan-kanal kritik kod için x86_64 sunucu varsayın. DMP tehdidi lokal kod yürütme gerektiriyor — çok kiracılı değilseniz doğrudan uygulanabilir değil.

---

## C) ZAMANLAMA İLE KULLANICI SAYIMI (USER ENUMERATION)

### C.1 Klasik problem

Kullanıcı yoksa parola hash'i hesaplanmaz → cevap ~1 ms; kullanıcı varsa Argon2 çalışır → ~200-500 ms. Fark **beş kat büyüklük derecesinde** — bu, 100 ns'lik incelikli saldırılara gerek bırakmaz, `curl -w '%{time_total}'` ile görülür.

**OWASP Authentication Cheat Sheet** (`https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html`) — birebir sözde kod:

Zafiyetli ("quick exit"):
```
IF USER_EXISTS(username) THEN
    password_hash = HASH(password)
    IS_VALID = LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
    IF NOT IS_VALID THEN RETURN Error("Invalid Username or Password!")
ELSE
    RETURN Error("Invalid Username or Password!")   ← hızlı dönüş
ENDIF
```
Güvenli:
```
password_hash = HASH(password)
IS_VALID = LOOKUP_CREDENTIALS_IN_STORE(username, password_hash)
IF NOT IS_VALID THEN RETURN Error("Invalid Username or Password!")
```

### C.2 "Kullanıcı yoksa dummy Argon2 çalıştır" doğru çözüm mü? — HAYIR, tek başına değil

#### Sorun 1: DoS — memory-hard fonksiyonu saldırgana ücretsiz veriyorsunuz
- OWASP Argon2id önerisi m=19456 KiB (19 MiB) veya m=47104 KiB (46 MiB) (aşağıda). 100 eşzamanlı sahte kullanıcı isteği × 19 MiB = **1.9 GB RAM** + 100 çekirdek-saniye. Saldırgan hiç geçerli kullanıcı adı bilmeden IdP'nizi düşürür.
- Rauthy varsayılanı daha da agresif: `argon2_m_cost = 131072` (**128 MiB**), `t_cost = 4`, `p_cost = 8` (`https://raw.githubusercontent.com/sebadob/rauthy/main/config.toml`). 2 eşzamanlı hash bile 256 MiB.

#### Sorun 2: Doğruluk — dummy hash gerçekten zamanı eşitler mi?
Hayır, üç sebeple:
1. **Parametre göçü.** Kullanıcı A `m=19456,t=2` ile, kullanıcı B `m=47104,t=1` ile hash'lenmişse, tek bir dummy parametre setiyle ikisini de taklit edemezsiniz. Dummy'nin süresi A ile eşleşiyorsa B sızar, B ile eşleşiyorsa A sızar.
2. **Algoritma göçü.** Legacy bcrypt (cost 10, ~60 ms) + yeni Argon2id (~300 ms) karışımı varsa, dummy hangisini taklit edecek?
3. **"Unusable password" durumu.** ⭐ **Gerçek CVE:** **CVE-2024-39329** — Django, `https://www.djangoproject.com/weblog/2024/jul/09/security-releases/` (9 Temmuz 2024):
   > "The `django.contrib.auth.backends.ModelBackend.authenticate()` method allowed remote attackers to **enumerate users via a timing attack involving login requests for users with unusable passwords**."
   Düzeltilen sürümler: Django 5.0.7, 4.2.14, 5.1b.
   Yani Django, 2013'te dummy hash eklemiş olmasına rağmen (aşağıda) **11 yıl sonra aynı sınıfta yeni bir zafiyet çıkardı.**

**Django'nun orijinal düzeltmesi** — ticket #20760 (`https://code.djangoproject.com/ticket/20760`), Django 1.6 (Temmuz 2013). Aymeric Augustin, 20 Temmuz 2013:
> "Since Django now ships with strong hashers by default, the login view spends most of its time hashing the password; there's some value in **running the hasher regardless of whether the user exists or not**, in order to make a timing attack (at least) **non-trivial**."

Dikkat: "non-trivial", "impossible" değil. Django ekibi bile bunu tam çözüm saymamış.

### C.3 Alternatifler — karşılaştırmalı analiz

| Yaklaşım | Etkinlik | Maliyet | Değerlendirme |
|---|---|---|---|
| **Dummy Argon2** | Orta | **Çok yüksek (DoS)** | Tek başına önerilmez |
| **Sabit gecikme** (ör. her cevap 500 ms) | İyi ama... | Throughput tavanı; ayrıca gerçek işlem 500 ms'yi aşarsa sızıntı geri gelir | Uygulanabilir ama kaba |
| **Rastgele gecikme** | **Zayıf** | Düşük | Ortalamayla yenilir: N örnekte gürültü √N ile azalır. Timeless makalesi bunu "saldırıyı sıralı seviyeye indirir" diye tanımlıyor — **yok etmez** |
| **⭐ Adaptif gecikme (koşan ortalamaya doldurma)** | **İyi** | Düşük | Rauthy'nin çözümü — aşağıda |
| **Rate limiting + IP kara liste** | Yüksek (ortogonal) | Düşük | Zorunlu |
| **Protokol düzeyinde kabullenme** (enumeration'ı önlemeye çalışma, her yerde tutarlı ol) | Kanidm'in seçimi | Sıfır | Aşağıda |
| **Hash kuyruğu / semafor** | DoS'a karşı zorunlu | Düşük | Rauthy `max_hash_threads`, Keycloak `cpu-cores` |

#### ⭐ Rauthy'nin çözümü — kaynak kodundan doğrulandı

`src/service/src/login_delay.rs` (`https://github.com/sebadob/rauthy`, main branch, 2026-09-08 indirildi):
> "Handles the login delay. With every successful login, a new average login time is calculated for how long it took for a successful login. **If a login failed though, the answer will be delayed by the current average for a successful login, to prevent things like username enumeration.**"

Mekanizma:
- Başarılı ve **parola gerçekten hash'lendiyse**: `new_time = (success_time + delta) / 2` → koşan ortalama cache'e yazılır (varsayılan başlangıç 2000 ms).
- Başarısızlıkta: `sleep_time_median = success_time - time_taken` (negatifse 0) → hata cevabı ortalama başarı süresine kadar doldurulur.
- Üstüne **IP başına başarısız giriş sayacıyla üstel ceza**:
  `≥3 → +t×2s`, `≥5 → +t×3s`, `7 → 60 s kara liste`, `10 → 600 s`, `15 → 900 s`, `20 → 3600 s`, `≥25 → 86400 s`.

`src/service/src/oidc/authorize.rs` (kullanıcı bulunamadığında):
> "The UI does not show the password input form when there is no user yet. **To prevent username enumeration, we should not add a login delay if a user does not even exist** when the UI is in that phase where the user does not provide any password."

**Yani Rauthy dummy Argon2 ÇALIŞTIRMIYOR** — DoS'tan kaçınıyor, bunun yerine yanıt süresini ortalamaya dolduruyor. Bu yaklaşım:
- ✅ DoS yok (hash yok)
- ✅ Parametre göçü sorunu yok
- ⚠️ "Ortalama" istatistiksel; farklı parametreli kullanıcılar arası varyans hâlâ sızabilir
- ⚠️ Gerçek başarılı login ortalamadan uzunsa (ör. yavaş DB) sızıntı geri gelir

Ayrıca `CredStuffDetect` (config.toml): 5 saniyelik pencerede 3 başarısız `sha256(email/password)` → 86400 s kara liste.

#### Keycloak'ın çözümü — DoS tarafı
`https://www.keycloak.org/server/all-provider-config` (2026-09-08):
- Varsayılan hash: **Argon2id** (non-FIPS), `memory = 7168` KB, `iterations = 5`, `parallelism = 1`, `version = 1.3`, `hash-length = 32`
- `spi-password-hashing--argon2--cpu-cores` — *"Maximum parallel CPU cores to use for hashing"*
- Admin guide (`https://www.keycloak.org/docs/latest/server_admin/index.html`): *"**To prevent excessive memory and CPU usage, the parallel computation of hashes by Argon2 is by default limited to the number of cores available to the JVM.**"*

Not: Keycloak'ın `m=7168, t=5, p=1` değeri OWASP'ın listelediği eşdeğer seçeneklerden biriyle **birebir aynı** (aşağıya bakınız) — yani düşük bellek/yüksek iterasyon tercihi bilinçli, DoS yüzeyini küçültüyor.

#### Kanidm'in çözümü — "engellemiyoruz"
`https://github.com/kanidm/kanidm/discussions/610` — Firstyear, 14 Kasım 2021:
> "The technical barriers to effectively blocking account enumeration are extremely high ... the cost would be extraordinary for what gain?"
> "**Account security is not defined through obscurity of its name or existence but from other elements.**"
> "Major providers like microsoft, gmail/google, github ... do **NOT** try to prevent account/username enumeration."

Tartışılan ve reddedilen seçenek: sahte hesap simülasyonu — *"simulating a fake user account would require simulating rate limits and locking, which would consume server memory"*. Ayrıca akış sorunu tespiti: `user → MFA → password` sırası zorunlu olarak sızdırır; ideali `user + password → MFA`.

### C.4 Bu Keycloak'ta bile hâlâ çıkıyor — güncel CVE

**CVE-2026-4633 / GHSA-rhgq-f8x5-j2jc** — `https://github.com/advisories/GHSA-rhgq-f8x5-j2jc`
- Yayın: **23 Mart 2026**. Şiddet: Low, CVSS 3.7 (AV:N/AC:H/PR:N/UI:N/C:L). CWE-209.
- *"Keycloak's identity-first login flow exposes user information ... A remote attacker can exploit **differential error messages** during the identity-first login flow when **Organizations are enabled**."*
- Var olan kullanıcı: "Invalid Password"; olmayan kullanıcı: "Invalid username or password".
- Etkilenen: `< 26.4.12` ve `>= 26.5.0, < 26.6.1`. Düzeltilen: **26.6.1, 26.4.12**.
- İlgili issue: `https://github.com/keycloak/keycloak/issues/47619`; Red Hat Bugzilla 2450247.
- Ayrıca açık: `https://github.com/keycloak/keycloak/issues/26625` — *"Manual user enumeration via password reset endpoint"*.
- Tarihsel: CVE-2020-1717 (giriş yapmış kullanıcı e-posta enumeration'ı).

**Ders:** Enumeration, olgun bir IdP'de 2026'da hâlâ bulunuyor ve genellikle **zamanlamadan değil, yeni eklenen bir özellikten** (Organizations) sızıyor. Argus'ta her yeni akış için enumeration regresyon testi olmalı.

### C.5 Zamanlama dışı yan kanallar — tam liste

WSTG-IDNT-04 (`https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html`) + IdP'ye özgü eklemelerim:

1. **Hata mesajı metni** — "Login for User foo: invalid password" vs "invalid Account"
2. **HTTP status kodu** — 401 vs 403 vs 200
3. **Content-Length / cevap gövde uzunluğu** — aynı metin bile olsa CSRF token uzunluğu, HTML render farkı
4. **URL hata kodu parametresi** — `err.jsp?User=gooduser&Error=2` vs `Error=0`
5. **URI probing** — `/account1` → 403 (var), `/account2` → 404 (yok)
6. **Redirect hedefi** — var olan kullanıcı `/password` sayfasına, olmayan `/error`'a
7. **Rate-limit davranış farkı** ⚠️ — var olan kullanıcı için hesap kilidi devreye giriyor, olmayan için girmiyorsa **kilit mekanizmanız oracle olur**. (Kanidm'in tespit ettiği sorun.)
8. **Şifre sıfırlama akışı** — "Invalid username" vs "Your password has been successfully sent"; e-postanın gerçekten gidip gitmediği zamanlaması
9. **Kayıt akışı** — "email already in use" ⚠️ **En sık kaçırılan.** Rauthy'de bunun için özel bir e-posta şablonu var: `email_registered_already.rs` → *"show this information in the UI directly to prevent a username enumeration"* (yani UI'da göstermiyor, e-posta ile bildiriyor)
10. **MFA kayıt/challenge akışı** — WebAuthn `allowCredentials` listesi dolu mu boş mu (**passkey'lerde kritik**; `residentKey`/discoverable credential kullanmıyorsanız kullanıcının kayıtlı authenticator'ı olup olmadığı sızar)
11. **SCIM `/Users?filter=userName eq "x"`** — API tarafında yetkisiz sorgu
12. **OIDC hata kodları** — `login_required` vs `interaction_required`; `error_description` farkları
13. **`prompt=none` davranışı** — oturum var mı yok mu
14. **Sosyal/federe login** — "Bu e-posta Google ile kayıtlı" mesajı
15. **Kullanıcı adı formatı** — `jbloggs`, `CN000100/CN000101` gibi tahmin edilebilir şemalar (WSTG)

**Argus önerisi:** Enumeration'ı **protokol seviyesinde** çözün: tüm bu akışlarda **aynı cevap gövdesi, aynı status, aynı süre, aynı yönlendirme**. Login akışını `user+password birlikte → MFA` yapın (Kanidm'in tespiti), identity-first akışı kullanmayın veya identity-first'te **her zaman** parola formunu gösterin.

### C.6 NIST ve OWASP resmi konumu

**NIST SP 800-63B-4** (final, 2025; `https://pages.nist.gov/800-63-4/sp800-63b.html` — sayfa "Revision 4, 26 Ağustos 2025" gösteriyor **[TAM TARİH DOĞRULAMASI ZAYIF]**):
- **Tam metin taramamda account enumeration / generic error message hakkında normatif (SHALL/SHOULD) bir gereksinim BULUNMADI.** Bu önemli: NIST bunu zorunlu kılmıyor.
- Bulunan ilgili normatif madde (§3.2.2 civarı): *"the verifier **SHALL** limit consecutive failed authentication attempts using a specific authenticator on a single subscriber account to **no more than 100** by disabling that authenticator"*.
- ⚠️ Bölüm numarasını kaynak sayfadan çıkardım; **§ numarası kesin değil [KISMEN DOĞRULANDI]**.

**OWASP Forgot Password Cheat Sheet** (`https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html`) — birebir:
> "Return a consistent message for both existent and non-existent accounts."
> "**Ensure that the time taken for the user response message is uniform.**"
> "Ensure that responses return in a consistent amount of time to prevent an attacker enumerating which accounts exist. **This could be achieved by using asynchronous calls or by making sure that the same logic is followed, instead of using a quick exit method.**"
> "Implement protections against excessive automated submissions such as rate-limiting on a per-account basis, requiring a CAPTCHA..."
> "Do not make a change to the account until a valid token is presented, such as **locking out the account**."

Son madde önemli: sıfırlama isteği hesabı kilitlerse, bu da bir oracle olur.

### C.7 Argon2 parametreleri ve DoS matematiği — 2026

**OWASP Password Storage Cheat Sheet** (`https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html`, 2026-09-08 çekildi) — Argon2id için eşdeğer güvenlikte seçenekler:

| m (KiB) | m (MiB) | t | p |
|---|---|---|---|
| 47104 | 46 | 1 | 1 |
| 19456 | 19 | 2 | 1 |
| 12288 | 12 | 3 | 1 |
| 9216 | 9 | 4 | 1 |
| 7168 | 7 | 5 | 1 |

Diğer: scrypt `N=2^17 (128 MiB), r=8, p=1`; bcrypt cost ≥10 + 72 byte sınırı (yalnızca legacy); PBKDF2-HMAC-SHA256 **600.000** iterasyon (FIPS için). Genel kural: *"Calculating a hash should take less than one second."* bcrypt ile pre-hashing tehlikeli (null byte + password shucking); gerekiyorsa `bcrypt(base64(hmac-sha384(password, pepper)), salt, cost)`.

**RFC 9106 §4** (`https://www.rfc-editor.org/rfc/rfc9106.txt`) — çok daha agresif:
> "Backend server authentication, which takes 0.5 seconds on a 2 GHz CPU using 4 cores — **Argon2id with 8 lanes and 4 GiB of RAM**."
> "Frontend server authentication, which takes 0.5 seconds on a 2 GHz CPU using 2 cores — **Argon2id with 4 lanes and 1 GiB of RAM**."

⚠️ RFC 9106'nın 4 GiB önerisi bir IdP için **DoS açısından kabul edilemez**. OWASP/Keycloak/Rauthy pratiği (7–128 MiB) gerçek dünyayı yansıtıyor.

**`argon2` crate (RustCrypto):** **0.6.0, 27 Ağustos 2026**, 50.939.882 indirme, `https://github.com/RustCrypto/password-hashes`. (Rauthy hâlâ 0.5 kullanıyor — `Cargo.toml:73`.)

**DoS matematiği (Argus için):**
```
Eşzamanlı hash sayısı N, bellek m MiB
Tepe RAM = N × m + baseline
Rauthy varsayılanı: max_hash_threads=2, m=128 MiB → 256 MiB tepe
OWASP m=19 MiB, N=32 → 608 MiB, 32 çekirdek-yarım saniye
```

**Rauthy dokümantasyonu** (`https://sebadob.github.io/rauthy/config/argon2.html`) — birebir:
> "`hashing.max_hash_threads` limits the maximum number of parallel password hashes at the exact same time to never exceed system memory... The default value is **2**."
> "**For smaller deployments, set `hashing.max_hash_threads` [to 1], which will technically allow only one user login at the exact same time. This value makes an external rate limiting for the login obsolete** (while you may add some for the others)."
> "Keep in mind that if you run the application in a way where memory is limited, for instance inside Kubernetes with resource limits set too low, **it will crash** if either `hashing.argon2_m_cost` is set too high or the memory limit too low."

Ayrıca `config.toml`'da `hash_await_warn_time = 500` — *"If a request waited longer than this time... indicator that you have more concurrent logins than allowed and may need config adjustments"*.

**⭐ Argus için hash kuyruğu tasarımı:**
```rust
// Semafor + kuyruk + zaman aşımı
static HASH_SEM: Semaphore = Semaphore::new(max_hash_threads);
// 1. permit al (timeout ile) → alınamazsa 503 + Retry-After (kullanıcıdan bağımsız!)
// 2. Argon2 çalıştır
// 3. permit'i bırak
// Kritik: kuyruk doluluğu kullanıcı varlığına göre değişmemeli,
//         yoksa yeni bir oracle yaratırsınız.
```
⚠️ **Dikkat: kuyruk kendisi bir yan kanaldır.** Sadece var olan kullanıcılar için hash çalıştırırsanız, saldırgan kuyruğu doldurup gecikmeyi gözleyerek hangi kullanıcının var olduğunu anlayabilir. Rauthy'nin adaptif-gecikme yaklaşımı bu tuzağa düşmüyor çünkü gecikme kullanıcı varlığından bağımsız bir global ortalamadan geliyor.

---

## D) MARVIN SALDIRISI VE RSA

### D.1 Marvin nedir

**"Everlasting ROBOT: the Marvin Attack"** — Hubert Kario (Red Hat).
IACR ePrint 2023/1442 (`https://eprint.iacr.org/2023/1442`, alındı 21 Eylül 2023, onay 24 Eylül 2023), **ESORICS 2023** (`https://link.springer.com/chapter/10.1007/978-3-031-51479-1_13`).
Proje sayfası: `https://people.redhat.com/~hkario/marvin/` (2026-09-08 çekildi).

Abstract birebir:
> "In this paper we show that **Bleichenbacher-style attacks on RSA decryption are not only still possible, but also that vulnerable implementations are common.** We have successfully attacked multiple implementations using **only timing of decryption operation** and shown that many others are vulnerable. To perform the attack we used more statistically rigorous techniques like the **sign test, Wilcoxon signed-rank test, and bootstrapping of median of pairwise differences.**"

Proje sayfasından kritik noktalar:
- Pratiklik: *"executed the attack against M2Crypto and pyca/cryptography in just a couple of hours"* — standart dizüstülerde. TLS sunucularında saatler–günler.
- *"Previous assumptions that timing differences 'too small to detect' were safe proved wrong. The researchers' paired-difference statistical approach detects differences as small as **a few CPU clock cycles** across production networks."*
- **OAEP de güvende değil:** *"Even RSA-OAEP implementations remain vulnerable if underlying numerical libraries leak timing information. Protection requires constant-time deblinding and byte-string conversion."*
- **Özel anahtar çalınmaz:** *"The attack decrypts individual ciphertexts or forges signatures but does not expose the private key itself."* Sertifika yenilemeye gerek yok.
- Birincil öneri: **"Deprecate and disable PKCS#1 v1.5 encryption entirely."**

### D.2 Etkilenen kütüphaneler ve CVE listesi (proje sayfasından, 2026-09-08)

| Uygulama | CVE | Durum |
|---|---|---|
| OpenSSL (TLS) | **CVE-2022-4304** | Fixed |
| OpenSSL (API) | — | API iyileştirmeleri merge edildi |
| GnuTLS (TLS) | **CVE-2023-0361, CVE-2023-5981, CVE-2024-0553** | Kısmi / çoklu düzeltme |
| NSS (TLS) | **CVE-2023-4421, CVE-2023-5388** | **Kısmi düzeltme; hâlâ zafiyetli** |
| pyca/cryptography | **CVE-2020-25659, CVE-2023-50782** | **Etkisiz azaltma** |
| M2Crypto | **CVE-2020-25657, CVE-2023-50781** | **Etkisiz azaltma** |
| python-rsa | **CVE-2020-25658** | Kapsam dışı |
| Go | **CVE-2023-45287** | Fixed (v1.20+) |
| Java | **CVE-2024-20952, CVE-2025-21587** | Fixed |
| BouncyCastle | **CVE-2024-30171** | Fixed |
| Node.js | **CVE-2023-46809** | Fixed |
| .NET | — | Issue açıldı |
| Apple corecrypto | **CVE-2024-23218** | Fixed |
| Mbed TLS | **CVE-2024-23170** | Fixed |
| libgcrypt | **CVE-2024-2236** | Fixed |
| wolfSSL | **CVE-2023-6935** | Fixed |
| PyCryptodome | **CVE-2023-52323** | Fixed |
| jsrsasign | **CVE-2024-21484** | Fixed |
| cjose | — | PR merge edildi |
| Ruby | **CVE-2025-0306** | Fixed |
| Linux Kernel | **CVE-2023-6240** | Fixed |
| OpenSC | **CVE-2023-5992, CVE-2024-29995** | Fixed |
| Intel QuickAssist | **CVE-2024-33617, CVE-2024-28885, CVE-2024-31074** | Fixed |
| Rust OpenSSL | **CVE-2024-3296** | Fixed |
| **RustCrypto RSA** | **CVE-2023-49092** | **"Fixed" (proje sayfasına göre) — ÇELİŞKİLİ, aşağıya bakınız** |
| xmlsec | — | PKCS1.5 devre dışı bırakıldı |
| Erlang/OTP | — | Uyarı eklendi |

**Etkilenmediği doğrulananlar:** BearSSL 0.6, BoringSSL (TLS, Eylül 2023 itibarıyla), **rustls 0.21.9** (RSA ciphersuite desteği yok).

**marvin-toolkit** — `https://github.com/tomato42/marvin-toolkit` (sürüm 0.3.5)
- Step 0: venv + tlsfuzzer kurulumu. Step 1: 1024/2048/4096-bit RSA anahtar üretimi (PEM/PKCS#8/PKCS#12). Step 2: bilinen yapıda çok sayıda şifreli metin (geçerli, bozuk header, yanlış padding uzunluğu vb.).
- İstatistik: **Friedman testi.** p < 0.05 → muhtemel yan kanal; **p < 1e-9 → neredeyse kesin.**
- Örneklem: *"100k to a 1M calls per ciphertext"* yerel test için; hızlı kütüphaneler ~10M, yavaşlar 1G+ gözlem gerektirebiliyor.
- TLS sunucusu testi: `test-bleichenbacher-timing-pregenerate.py`; API testi: `marvin-ciphertext-generator.py`.

**OpenSSL tarafındaki asıl azaltma — "implicit rejection"**
`https://raw.githubusercontent.com/openssl/openssl/master/CHANGES.md` (satır 3935 civarı, **"Changes between 3.1 and 3.2.0 [23 Nov 2023]"** başlığı altında):
> "Added and **enabled by default implicit rejection in RSA PKCS#1 v1.5 decryption** as a protection against Bleichenbacher-like attacks. The RSA decryption API will now return a randomly generated **deterministic message** instead of an error in case it detects an error when checking padding... This is a general protection against issues like CVE-2020-25659 and CVE-2020-25657."
> *Katkı: Hubert Kario*

Ayrıca (3.0.9/3.1.1 civarı): *"Reworked the Fix for the Timing Oracle in RSA Decryption (CVE-2022-4304). The previous fix ... caused a severe 2-3x performance regression ... The new fix uses existing constant time code paths."*

**Sonuç:** OpenSSL ≥ 3.2.0 kullanıyorsanız PKCS#1 v1.5 decryption'da implicit rejection açık. Bu bir **azaltma**, kök çözüm değil — Kario'nun önerisi hâlâ "PKCS#1 v1.5 şifrelemeyi tamamen kapat".

### D.3 IdP'de RSA-PKCS#1 v1.5 decryption nerede kullanılır?

**⭐ Tek büyük yer: JWE `alg=RSA1_5` anahtar sarmalama.** IdP'de görülebilecek yerler:
- Request Object encryption (JAR/JARM — `request` parametresi şifreli JWE)
- ID Token / UserInfo encryption (`id_token_encrypted_response_alg`, `userinfo_encrypted_response_alg`)
- `private_key_jwt` istemci kimlik doğrulaması (imza — decryption değil, **Marvin kapsamı dışı**)
- Client'tan gelen şifreli JWT'ler
- SAML `EncryptedAssertion` / `EncryptedKey` (**bunu unutmayın** — SAML tarafı `http://www.w3.org/2001/04/xmlenc#rsa-1_5` kullanır; xmlsec bunu devre dışı bıraktı)

**RSASSA-PKCS1-v1_5 imzalama (RS256/384/512) etkilenir mi?**
- **Doğrulama (verify): HAYIR.** Yalnızca public key işlemi; sır yok.
- **İmzalama (sign): Marvin'in decryption oracle'ı kapsamında DEĞİL**, ama:
  - IETF draft'ı bunu açıkça ayırıyor (`draft-ietf-jose-deprecate-none-rsa15-05` §1, birebir): *"Note that **RSA signatures using PKCS#1 version 1.5 padding ("RS256", "RS384", and "RS512") are unchanged by this specification and can still be used.**"*
  - **AMA:** RustSec RUSTSEC-2023-0071 (`rsa` crate) **her türlü private-key işlemini** kapsıyor ve *"information about the private key is leaked through timing information which is observable over the network"* diyor — yani `rsa` crate'iyle RS256 **imzalamak** da advisory kapsamında. IdP her token için imzalar → çok sayıda ölçüm → risk gerçek.
  - Marvin FAQ'ında da: aynı anahtarla hem decryption oracle'ı hem imzalama varsa, oracle üzerinden **imza forge edilebilir**.

**JOSE'de RSA1_5'in durumu — 2026**

`draft-ietf-jose-deprecate-none-rsa15-05` (`https://www.ietf.org/archive/id/draft-ietf-jose-deprecate-none-rsa15-05.txt`, Haziran 2026, son geçerlilik 25 Aralık 2026; datatracker: **IESG state "Publication Requested"**, son revizyon 23 Haziran 2026, son güncelleme 6 Eylül 2026 — `https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/`). **Henüz RFC değil.** Yazar: Neil Madden (Hazelcast).

§3 birebir:
> "The "RSA1_5" algorithm implements RSA encryption using PKCS#1 version 1.5 padding... This padding mode has long been known to have security issues, since at least Bleichenbacher's attack in 1998. It was supported in JWE due to the wide deployment of this algorithm, especially in legacy hardware. However, more secure replacements such as OAEP or elliptic curve encryption algorithms are now widely available. **NIST has disallowed the use of this encryption mode for federal use since the end of 2023** [NIST.SP800-131Ar2] and a CFRG draft also deprecates this encryption mode for new protocols and deployments."

§4 birebir:
> "JOSE library developers **SHOULD** deprecate support for these algorithms. Application developers **MUST disable support for these algorithms by default.** ... an application that has a specific need for one of these algorithms MAY enable it, but **only for the specific objects or operations that require it and not at a global level.** **New specifications building on top of JOSE MUST NOT allow the use of either algorithm.**"
> IANA'da "Deprecated" olarak işaretlenecek (Prohibited değil).

**RFC 8725 §3.2** (`https://www.rfc-editor.org/rfc/rfc8725.txt`):
> "Applications SHOULD follow these algorithm-specific recommendations: **Avoid all RSA-PKCS1 v1.5 encryption algorithms ([RFC8017], Section 7.2), preferring RSAES-OAEP ([RFC8017], Section 7.1).**"

**alg downgrade riski:** Sunucu JWE header'ındaki `alg`'yi allowlist olmadan kabul ediyorsa, saldırgan RSA-OAEP'ten RSA1_5'e düşürüp Bleichenbacher açar. **Argus'ta `alg` değeri her zaman istemci kaydındaki (client metadata) beklenen değere karşı doğrulanmalı, JWE header'ından alınmamalı.**

### D.4 ⭐ Rust `rsa` crate — RUSTSEC-2023-0071 durumu 2026'da

**RustSec advisory (ana daldan birebir TOML, `https://raw.githubusercontent.com/rustsec/advisory-db/main/crates/rsa/RUSTSEC-2023-0071.md`, 2026-09-08):**
```toml
id = "RUSTSEC-2023-0071"
package = "rsa"
date = "2023-11-22"
url = "https://github.com/RustCrypto/RSA/issues/626"
cvss = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"   # 5.9 Medium
aliases = ["CVE-2023-49092", "GHSA-c38w-74pg-36hr", "GHSA-4grx-2x9w-596c"]
[versions]
patched = []          # ← BOŞ
```
> "### Patches — Currently, **no patched versions exist**. The maintainers are working toward a fully constant-time implementation."
> "### Workarounds — Users should **limit the RSA crate to scenarios where timing observations aren't feasible** — such as isolated, uncompromised systems."

**Sürüm durumu (crates.io API, 2026-09-08):**
- Stabil varsayılan: **0.9.10 (6 Ocak 2026)**
- En yeni: **0.10.0-rc.18 (27 Nisan 2026)** — hâlâ **release candidate**, 18 RC'den sonra
- Toplam 215.298.115 indirme, MSRV Rust 1.85

**Düzeltme çalışmasının durumu:**
- **Issue #390** "Migrating from `num-bigint(-dig)` to `crypto-bigint`" (açılış 28 Kasım 2023, tarcieri) → **KAPALI**. `BoxedUint` + Montgomery + sabit-zamanlı modexp'e geçiş.
- **⭐ Issue #626** "**Padding implementation is not constant-time**" (açılış **7 Ocak 2026**) → **AÇIK**. Maintainer notu (birebir):
  > "the remaining sidechannels in our implementation are probably no longer coming from `crypto-bigint`, but are instead **in this crate's implementation of RSA padding modes**."
  RustSec advisory'sinin `url` alanı artık **bu issue'ya** işaret ediyor.
- README (`https://raw.githubusercontent.com/RustCrypto/RSA/master/README.md`, 2026-09-08) hâlâ: *"The implementation is vulnerable to the Marvin Attack ... (RUSTSEC-2023-0071). Mitigation efforts are ongoing in issue #390."*
- docs.rs 0.9.10 Security Notes: *"The implementation of modular exponentiation is not constant time, but timing variability is masked using **random blinding**"* + Include Security tarafından tek denetim.

**⚠️ [ÇELİŞKİLİ]** Marvin proje sayfası (`people.redhat.com/~hkario/marvin/`) tablosunda **"RustCrypto RSA | CVE-2023-49092 | Fixed"** yazıyor. Ancak:
- RustSec advisory-db ana dalı: `patched = []`
- GitHub Advisory GHSA-c38w-74pg-36hr: "Patched versions: None"
- Upstream issue #626 açık ve **2026 Ocak'ta açılmış**
- Crate README'si hâlâ uyarıyor

**Değerlendirmem:** Kario'nun tablosu muhtemelen modexp düzeltmesini (issue #390 / crypto-bigint) gördüğü için "Fixed" işaretlemiş; padding tarafı hâlâ açık. **Argus için karar: `rsa` crate'ini private-key işlemleri için üretimde kullanmayın.**

**Rust JOSE kütüphaneleri ne yapıyor?**
- **`jsonwebtoken` 11.0.0 (24 Temmuz 2026)**, 183.855.256 indirme — **sadece JWS**, JWE yok. Kripto backend'i takılabilir: `aws_lc_rs` (aws-lc-rs 1.18.1, 1 Eylül 2026) veya `rust_crypto`. `CryptoProvider` deseni rustls'ten alınmış. **Argus için RS256 imzalamada `aws_lc_rs` backend'ini seçmek `rsa` crate'inden kaçınmanın en temiz yolu** (kaynak: `https://raw.githubusercontent.com/Keats/jsonwebtoken/master/src/crypto/mod.rs`).
- **`josekit` 0.10.3 (20 Mayıs 2025)**, 3.747.971 indirme — **tam JOSE, JWE dahil**. README algoritma tablosunda **`RSA1_5` (RSAES-PKCS1-v1_5) DESTEKLENİYOR**, RSA-OAEP/-256/-384/-512 ile birlikte. Backend: `openssl = "0.10.68"` (native OpenSSL) — yani Marvin durumu sistemdeki OpenSSL sürümüne bağlı (≥3.2.0 ise implicit rejection açık). ⚠️ **Bakım:** 16 aydır güncelleme yok.
- **`rustls`**: RSA key exchange desteklemiyor → Marvin'e karşı yapısal olarak bağışık (Kario'nun listesinde "not vulnerable, rustls 0.21.9").

**Argus için RSA kararları:**
1. **JWE `RSA1_5`'i hiç implemente etmeyin.** IETF zaten "MUST disable by default" diyor; hiç desteklemeyerek downgrade yüzeyini sıfırlarsınız.
2. JWE için: **ECDH-ES + A256GCM** (birincil), gerekirse **RSA-OAEP-256** (ikincil, sadece legacy istemciler için, açıkça opt-in).
3. İmzalama için: **EdDSA (Ed25519)** veya **ES256** birincil; RS256'yı sadece uyumluluk için ve `aws-lc-rs` backend ile.
4. `rsa` crate'ini bağımlılık ağacından çıkarın (`cargo tree -i rsa` ile kontrol edin) veya sadece public-key doğrulama için sınırlayın.
5. `alg` allowlist'i istemci metadata'sından gelsin, JWE/JWS header'ından değil.
6. CI'da `cargo audit` / `cargo deny` ile RUSTSEC-2023-0071'i explicit olarak izleyin.

---

## E) SPECTRE / MELTDOWN SINIFI — IdP İÇİN GERÇEKÇİ DEĞERLENDİRME

### E.1 Tehdit modeli — ne zaman önemli?

Geçici yürütme (transient execution) saldırıları **yerel kod yürütme veya aynı fiziksel makinede co-tenant** gerektirir. Bir IdP için üç senaryo:

| Senaryo | Risk | Gerekçe |
|---|---|---|
| Kendi donanımınız / dedicated instance, başka kiracı yok | **Çok düşük** | Saldırgan kod çalıştıramıyor |
| Çok kiracılı bulut (paylaşımlı VM host) | **Orta** | VMScape, cross-VM saldırılar |
| Paylaşımlı çekirdek üzerinde container'lar (aynı node'da güvenilmeyen iş yükü) | **Orta-Yüksek** | user↔user, user↔kernel |
| ⭐ **Argus'ta WASM/script/plugin eklenti noktası varsa** | **YÜKSEK** | Süreç-içi güvenilmeyen kod — Spectre'ın klasik senaryosu |
| Tarayıcı tarafı | **İlgisiz** | Kernel dokümanı: *"the CPU vulnerabilities mitigated by Linux have generally not been shown to be exploitable from browser-based sandboxes."* |

### E.2 Mevcut manzara 2024–2026 — DOĞRULANMIŞ liste

Linux kernel dokümantasyon ağacındaki **tam hw-vuln listesi** (`https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/Documentation/admin-guide/hw-vuln/index.rst`, 2026-09-08, docs sürümü **7.3.0-rc2**):

```
attack_vector_controls, spectre, l1tf, mds, tsx_async_abort, multihit,
special-register-buffer-data-sampling, core-scheduling, l1d_flush,
processor_mmio_stale_data, cross-thread-rsb, srso, gather_data_sampling,
reg-file-data-sampling, rsb, old_microcode, indirect-target-selection, vmscape
```

**Bu listede `vmscape`'ten daha yeni isimli bir zafiyet dokümanı YOK** — yani 2026-09 itibarıyla kernel'de yeni bir isimlendirilmiş sınıf eklenmemiş.

| Saldırı | CVE | Yıl | Etki | Kaynak (doğrulandı) |
|---|---|---|---|---|
| **Downfall / GDS** | **CVE-2022-40982** | 2023 | Intel Skylake(6.)–Tiger Lake(11.) `gather` komutu vektör register dosyasını sızdırıyor. SGX dahil. Mitigation overhead **%50'ye kadar**. Bildirim 24 Ağu 2022, embargo ~1 yıl. | `https://downfall.page/` |
| **Zenbleed** | **CVE-2023-20593** | 2023 | AMD **Zen 2** (Ryzen 3000/4000/5000-G, EPYC "Rome"); `vzeroupper` yanlış tahmin kurtarma → register sızıntısı | `https://lock.cmpxchg8b.com/zenbleed.html` (Tavis Ormandy) |
| **Inception / SRSO** | **CVE-2023-20569** | 2023 | AMD **Zen 1–4** (family 0x17, 0x19); RAP zehirlenmesi, non-architectural CALL | Kernel `srso.rst` |
| **Reptar** | **CVE-2023-23583** | 2023 | Intel redundant prefix — DoS / privilege escalation. **Bu bir yan kanal DEĞİL.** | ⚠️ **[KISMEN DOĞRULANDI]** — `lock.cmpxchg8b.com/reptar.html` HTTP 200 döndü ama içerik JS ile yükleniyor, metin çıkaramadım. CVE numarası arama sonuçlarından. |
| **Breaking the Barrier / PB-Inception** | **CVE-2024-10041** (PAM zafiyeti için) | IEEE S&P **2025** | IBPB bariyerini bypass. Intel Core 12–14. nesil, Xeon 5–6. nesil mikrokod hatası + AMD IBPB'nin return tahminlerini temizlememesi. **İlk pratik uçtan uca cross-process Spectre**: SUID `sudo`'dan root parolası; PB-Inception ile page cache'ten root parola hash'i. | `https://comsec.ethz.ch/research/microarch/breaking-the-barrier/` |
| **⭐ Training Solo** | **CVE-2024-28956** (ITS), **CVE-2025-24495** (Lion Cove BPU) | 2025 | Domain isolation'ı **tasarım gereği** kırar: saldırgan aynı domain içinde self-training yapıyor. eBPF gerekmiyor — **cBPF/SECCOMP yeterli (tüm kullanıcılara varsayılan açık)**. Kernel bellek sızıntısı **17 KB/s**; hipervizör belleği 8.5 KB/s. Etkilenen: eIBRS'li tüm Intel CPU'lar (BHI_NO'lu Lion Cove dahil), ITS için Core 9–11. nesil / Xeon 2–3. nesil. Azaltma: yeni **IBHF** komutu (mikrokod), yeni indirect branch thunk'ları (cache line üst yarısı), IBPB mikrokod güncellemesi. | `https://www.vusec.net/projects/training-solo/` |
| **⭐ VMScape** | **CVE-2025-40300** | IEEE S&P **2026** | **Tüm AMD Zen CPU'ları (Zen 5 dahil)** — BTB host/guest ayrımı yapmıyor. Kötü niyetli KVM guest'i, **QEMU** gibi userspace hipervizörden anahtar sızdırıyor. Intel eIBRS BTB'yi ayırıyor ama branch history'yi ayırmıyor → vBHI potansiyeli (Intel doğruladı, PoC yok). Zen 5 BTB'de tek-bit privilege tag var ama 4 domain için yetersiz. | `https://comsec.ethz.ch/research/microarch/vmscape-.../` + kernel `vmscape.rst` |
| **Stack Engine Attacks** | — | MICRO **2025** | x86 stack engine (2000'lerin ortasından beri her x86'da) frontend optimizasyonu → **Intel MPK ile süreç-içi izolasyonu kırıyor**. Recursive descent JSON parser'ın derinliğinden FHIR veri setindeki 120 hastadan 5'ini ayırt edebiliyor. Zen 5'te AGESA varsayılan olarak add/sub desteğini kapatıyor. Intel Alder Lake+ P-core'larda benzeri var. **Azaltma olarak açıkça: "data-invariant control flow and other constant-time programming techniques also provide a good defense"** | `https://comsec.ethz.ch/research/microarch/microarchitectural-attacks-on-the-stack-engine/` |

**2026 gelişmeleri:** VMScape makalesi IEEE S&P 2026'da sunulacak; kernel'de `vmscape` dokümanı ve `vmscape=` boot parametresi mevcut. **Bunun ötesinde 2026'ya özgü yeni bir isimlendirilmiş geçici-yürütme saldırısı doğrulayamadım [DOĞRULANMADI].**

### E.3 Azaltmalar ve maliyetleri

**⭐ Linux `attack_vector_controls` (yeni, çok pratik)** — `Documentation/admin-guide/hw-vuln/attack_vector_controls.rst`, birebir:
> "Attack vector controls provide a simple method to configure **only the mitigations for CPU vulnerabilities which are relevant given the intended use of a system.** Administrators are encouraged to consider which attack vectors are relevant and **disable all others in order to recoup system performance.**"
> "When new relevant CPU vulnerabilities are found, they will be added to these attack vector controls so administrators will likely not need to reconfigure their command line parameters."

5 vektör: `user_kernel`, `user_user`, `guest_host`, `guest_guest`, `smt` (cross-thread).
- *"If no untrusted userspace applications are being run, such as with single-user systems, consider disabling user-to-kernel mitigations."*
- *"Note that because the Linux kernel contains a mapping of all physical memory, preventing a malicious userspace program from leaking data from another userspace program requires mitigating user-to-kernel attacks as well for complete protection."*
- Cross-thread: `'auto,nosmt'` → SMT kapatılabilir; `'auto'` → SMT açık kalır ama diğer azaltmalar devrede.

**Core scheduling** (`core-scheduling.rst`), birebir:
> "**The only full mitigation of cross-HT attacks is to disable Hyper Threading (HT).** Core scheduling is a scheduler feature that can mitigate **some (not all)** cross-HT attacks. It allows HT to be turned on safely by ensuring that only tasks in a user-designated trusted group can share a core."
> "In theory, core scheduling aims to perform at least as good as when Hyper Threading is disabled. In practice, this is mostly the case though not always... **Please measure the performance of your workloads always.**"
API: `prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE/SHARE_TO/SHARE_FROM, pid, pid_type, &cookie)`; cookie fork/exec'te miras alınır.

**VMScape azaltması** (`vmscape.rst`), birebir:
> "Kernel tracks when a CPU has run a potentially malicious guest and issues an **IBPB before the first exit to userspace after VM-exit.** If userspace did not run between VM-exit and the next VM-entry, no IBPB is issued."
> "**When SMT is enabled, hypervisors can be vulnerable to cross-thread attacks. For complete protection against VMSCAPE attacks in SMT environments, STIBP should be enabled.**"
sysfs: `/sys/devices/system/cpu/vulnerabilities/vmscape`; boot: `vmscape=off|ibpb|force`.

**Confidential computing:** AMD SEV-SNP / Intel TDX — hipervizörden bellek şifrelemesi + bütünlük. ⚠️ Ama VMScape gibi branch predictor saldırıları **mimari olmayan** durumu hedefliyor; SEV-SNP tek başına Spectre-BTI'ı çözmez. **[BU KONUDA DERİN DOĞRULAMA YAPMADIM]**

### E.4 ⭐ Argus için pratik öneri: ne önemli, ne tiyatro

**GERÇEKTEN ÖNEMLİ:**
1. **Eklenti/script motoru varsa bu konu birinci öncelik.** Argus'ta WASM plugin, JS script (Keycloak'taki gibi authenticator script'leri), Lua/Rhai policy engine varsa: **süreç-içi izolasyon Spectre'a karşı yeterli değildir.** Stack engine makalesi tam olarak MPK tabanlı süreç-içi izolasyonu kırdığını gösteriyor. **Çözüm: eklentileri ayrı süreçte (hatta ayrı kullanıcı/cgroup'ta) çalıştırın**, ana IdP sürecinde asla güvenilmeyen kod yürütmeyin. Keycloak'ın script'leri "preview" olarak işaretlemesi tesadüf değil.
2. **Barındırma kararı:** Dedicated instance veya bare-metal. Bulutta genel amaçlı paylaşımlı instance kullanmayın. Bu, **tüm bu saldırı sınıfını tek hamlede** tehdit modelinden çıkarır.
3. **`mitigations=auto` varsayılanını bozmayın.** Performans için `mitigations=off` yapmak — özellikle imza anahtarları RAM'de duran bir IdP'de — kabul edilemez.
4. **Mikrokod güncel tut.** Training Solo, Breaking the Barrier, Downfall, VMScape'in azaltmalarının **hepsi** mikrokoda bağlı. Kernel'de `old_microcode` dokümanı ve uyarısı var — bunu izleyin.
5. **Kernel LTS + güncel.** VMScape FAQ: *"For Linux systems, updating to the latest version, or any maintained LTS release, is sufficient."*
6. **İmza anahtarlarını süreç dışına çıkarın** — HSM / KMS / ayrı imzalama servisi. Anahtar hiç Argus'un adres uzayında değilse hiçbir Spectre varyantı onu okuyamaz. **En yüksek getirili tek kontrol budur.**
7. **`zeroize`** kullanın (RustCrypto, `utils` repo'sunda) — sırları kullanım sonrası temizleyin; sızıntı penceresini daraltır.

**TİYATRO (bu bağlamda):**
- Uygulama kodunda Spectre-v1 `lfence` serpiştirmek — LLVM'in `-mspeculative-load-hardening`'i bile IdP iş mantığı için anlamsız; darboğaz orada değil.
- Co-tenant yokken SMT kapatmak (~%20-30 throughput kaybı, karşılığında sıfır kazanç).
- Rust'ta "Spectre-safe" bounds check yazmaya çalışmak — Rust'ın bounds check'i zaten var ve spekülatif bypass'ı uygulama katmanında çözemezsiniz.
- Tarayıcı tarafı önlemler (COOP/COEP) — kullanıcı arayüzü için iyi hijyen ama Spectre'la ilgili değil.

---

## F) ARGUS İÇİN SOMUT YAPILACAKLAR LİSTESİ

### F.1 Sabit-zamanlı karşılaştırma (A)
- [ ] `constant_time_eq = "0.6"` bağımlılığı ekle (aktif bakımda, 2026-08-30). Kripto seçim mantığı gerekirse `subtle 2.6.1` (bakım durgun) veya `ctutils 0.4.2` (denetlenmemiş) — kararı gerekçeleriyle ADR'ye yaz.
- [ ] **Newtype tasarımı:** `struct Secret<const N: usize>([u8; N])`, `PartialEq` implementasyonu `constant_time_eq_n` kullansın, `Debug` maskeleyecek, `Drop` ile `zeroize` yapacak. Böylece `==` yazan geliştirici otomatik güvende olur (totp-rs'in `Token` deseni).
- [ ] **Tüm token'ları DB'ye `SHA-256` hash'i olarak yaz** (session, refresh token, API key, password reset, device code, magic link). Arama hash üzerinden → DB indeks zamanlaması ölür.
- [ ] Token'ları **sabit uzunluk** yap; uzunluk kontrolünü CT karşılaştırmadan **önce** yap (uzunluk zaten sırdır değil).
- [ ] Clippy lint / `cargo-deny` / custom lint: sır tiplerinde `==`, `memcmp`, `String::eq` kullanımını yasakla.
- [ ] `*_vartime` isimlendirme kuralını benimse (RustCrypto politikası).

### F.2 Derleyici doğrulaması (B)
- [ ] CI'a **`dudect-bencher 0.7`** ile bir `ct-bench` binary'si ekle: token karşılaştırma, TOTP kontrolü, PKCE doğrulama, client_secret doğrulama fonksiyonlarını test et. |t| > 5 → build fail.
- [ ] Nightly job: **ctgrind/valgrind memcheck** ile `ct_poison` yaklaşımını Rust FFI shim'iyle uygula (veya **Microwalk** Docker şablonunu Rust için uyarla).
- [ ] **Release binary'de assembly denetimi:** kritik CT fonksiyonları için `cargo asm` / `objdump` çıktısında `jne/je/bne/cmov` beklentisini bir snapshot testi olarak sabitle. `cmov` CVE'si tam olarak böyle yakalanabilirdi.
- [ ] `aarch64-dit` crate'i ile aarch64 hedeflerinde kripto bölgelerinde DIT aç (RAII guard).
- [ ] x86'da DOITM: **hazır crate yok**; Intel global açmayı önermiyor. **Şu an aksiyon almayın**, sadece risk kaydına yazın.
- [ ] Bağımlılıkları `cargo audit` ile günlük tara — RUSTSEC-2026-0003 (cmov), RUSTSEC-2026-0211/0212 (libcrux) gösteriyor ki CT advisory'leri sık geliyor.

### F.3 Enumeration (C)
- [ ] **Login akışını `user+password birlikte → MFA` yap.** Identity-first akışı kullanma (Kanidm'in tespiti + Keycloak CVE-2026-4633).
- [ ] **Rauthy modelini uygula:** koşan başarılı-login ortalaması + başarısızlıkta ortalamaya doldurma. Dummy Argon2 **çalıştırma** (DoS).
- [ ] `max_hash_threads` semaforu + `hash_await_warn_time` metriği. Kuyruk doluluğunun kullanıcı varlığına bağlı olmadığından emin ol.
- [ ] IP başına başarısız giriş sayacı + üstel kara liste (Rauthy: 7→60s, 10→600s, 15→900s, 20→3600s, 25→24h).
- [ ] **Enumeration regresyon test suite'i:** her akış (login, register, reset, MFA enroll, SCIM, device flow, OIDC error) için var-olan vs olmayan kullanıcı arasında **status kodu, gövde byte'ı byte'ına, header seti, redirect hedefi, p50/p95 süre** karşılaştırması. Rauthy'de örneği var: `handler_users.rs:156` — *"we should always get back an HTTP 200 for username enumeration prevention"*.
- [ ] Kayıtta "email already in use" bilgisini UI'da gösterme; e-posta ile bildir (Rauthy `email_registered_already.rs`).
- [ ] Argon2 parametre göçünde **eski ve yeni parametrelerin süre farkını** ölç; fark ortalama-doldurma penceresinden büyükse migration'ı zorla (kullanıcı login olduğunda rehash).
- [ ] HTTP/2 kullanıyorsanız: Timeless Timing savunması olarak **eşzamanlı gelen istek çiftlerine** rastgele gecikme (~1.73 ms ortalama) eklemeyi değerlendirin — veya kritik endpoint'lerde HTTP/2 multiplexing'i sınırlayın.

### F.4 RSA / JOSE (D)
- [ ] **`alg=RSA1_5` desteklemeyin.** Hiç. (draft-ietf-jose-deprecate-none-rsa15: "MUST disable by default")
- [ ] `alg=none` desteklemeyin (aynı draft).
- [ ] JWE: `ECDH-ES+A256KW` / `A256GCM` birincil; `RSA-OAEP-256` sadece opt-in legacy.
- [ ] İmza: `EdDSA`/`ES256` birincil; `RS256` uyumluluk için, **`aws-lc-rs` backend ile** (`jsonwebtoken 11` `CryptoProvider`).
- [ ] `cargo tree -i rsa` çalıştır — `rsa` crate'i ağaçtaysa neden orada olduğunu belgele. Private-key işlemi yapıyorsa **kaldır**.
- [ ] `alg` allowlist'i **istemci metadata'sından** gelsin, JWS/JWE header'ından asla. Downgrade testi yaz.
- [ ] SAML tarafı varsa `xmlenc#rsa-1_5`'i devre dışı bırak (xmlsec'in yaptığı gibi).
- [ ] RUSTSEC-2023-0071 ve RustCrypto/RSA issue #626'yı izleme listesine al.

### F.5 Barındırma / donanım (E)
- [ ] Dedicated instance veya bare-metal. Paylaşımlı genel amaçlı bulut instance'ı kullanma.
- [ ] `mitigations=auto` (varsayılan). Co-tenant/untrusted VM varsa `mitigations=auto,nosmt`.
- [ ] Yeni `attack_vector_controls` ile gereksiz vektörleri kapatıp performans geri kazan — ama `user_kernel` ve `user_user`'ı kapatmadan önce "bu makinede güvenilmeyen kod çalışmıyor" iddiasını ispatla.
- [ ] Mikrokod + kernel LTS güncel; `old_microcode` uyarısını izle.
- [ ] `/sys/devices/system/cpu/vulnerabilities/*` çıktısını deployment health check'ine ekle.
- [ ] **İmza anahtarlarını HSM/KMS'e taşı** — en yüksek getirili tek kontrol.
- [ ] **Eklenti/script motoru varsa ayrı süreçte çalıştır.** Süreç-içi sandbox (WASM/MPK) Spectre'a karşı yeterli değil (MICRO 2025 stack engine).
- [ ] `zeroize` ile sırları temizle.

---

## G) DOĞRULANMAMIŞ / ÇELİŞKİLİ MADDELER — AÇIKÇA İŞARETLİ

1. **[ÇELİŞKİLİ]** `rsa` crate'inin Marvin durumu: Kario'nun tablosu "Fixed", RustSec/GHSA/upstream "patched yok + açık issue #626 (7 Ocak 2026)". Ben upstream'e güveniyorum → **düzeltilmemiş kabul edin.**
2. **[KAYNAK ÖLÜ]** NCC Group / iSEC Partners "Double HMAC Verification" (Şubat 2011) blog yazısı erişilemiyor; Wayback'te snapshot yok. Teknik doğru, ama kanonik kaynak olarak `github.com/veorq/cryptocoding` kullanın.
3. **[KAYNAK ERİŞİLEMEDİ]** ARM DIT resmi dokümantasyonu (developer.arm.com / support.arm.com) 403 ve boş içerik döndü. DIT bilgisi **Linux kernel kaynak kodundan** ve GoFetch FAQ'ından doğrulandı — ARM ARM'dan birebir alıntı veremedim.
4. **[KISMEN DOĞRULANDI]** Reptar / CVE-2023-23583: sayfa JS ile yükleniyor, metin çıkaramadım. CVE numarası ikincil kaynaklardan. Ayrıca bu bir yan kanal değil, DoS/privilege escalation.
5. **[KISMEN DOĞRULANDI]** NIST SP 800-63B-4'ün yayın tarihi (26 Ağustos 2025 mi, Temmuz 2025 mi) ve rate-limiting maddesinin bölüm numarası (§3.2.2) kesin değil. **Enumeration hakkında normatif gereksinim bulunmadığı** bulgusu ise tam metin taramasıyla doğrulandı.
6. **[DOĞRULANMADI]** Microwalk için hazır bir Rust CI şablonu olup olmadığı (C ve JS örnekleri var).
7. **[DOĞRULANMADI]** 2026'ya özgü yeni bir isimlendirilmiş geçici-yürütme saldırısı bulamadım. Linux 7.3-rc2 dokümantasyon ağacında `vmscape`'ten yenisi yok. Bu "yok" demek değil, "benim doğrulayamadığım" demek.
8. **[DOĞRULANMADI]** SEV-SNP/TDX'in VMScape sınıfı branch-predictor saldırılarına karşı ne ölçüde koruduğu — derin doğrulama yapmadım.
9. **[DOĞRULANMADI]** HTTP/3/QUIC üzerinde Timeless Timing Attack'ın pratik uygulanabilirliği — makale bunu değerlendirmediğini açıkça söylüyor.
10. **[DÜZELTME]** docs.rs'in `subtle` sayfası küçük bir modelce "2.6.1 released September 1, 2026" olarak özetlendi — **yanlış**. crates.io API'sine göre 2.6.1 **24 Haziran 2024**. crates.io'yu esas alın.
11. Rauthy kaynak kodu alıntıları `main` dalından, 2026-09-08 tarihli snapshot'tan. Sürüm etiketi sabitlemedim.

---

## KAYNAKLAR (erişim: 2026-09-08)

**Rust / crate'ler**
- https://doc.rust-lang.org/std/hint/fn.black_box.html (Rust 1.98.1, build 2026-09-01)
- https://raw.githubusercontent.com/dalek-cryptography/subtle/main/README.md · https://docs.rs/subtle/latest/subtle/ · https://crates.io/api/v1/crates/subtle · https://github.com/dalek-cryptography/subtle/commits/main.atom
- https://raw.githubusercontent.com/RustCrypto/utils/master/ctutils/README.md · .../cmov/README.md · .../aarch64-dit/README.md
- https://raw.githubusercontent.com/RustCrypto/crypto-bigint/master/README.md
- https://raw.githubusercontent.com/RustCrypto/RSA/master/README.md · .../CHANGELOG.md · https://docs.rs/rsa/latest/rsa/index.html
- https://github.com/RustCrypto/RSA/issues/390 (kapalı) · https://github.com/RustCrypto/RSA/issues/626 (açık, 2026-01-07)
- https://crates.io/api/v1/crates/{rsa,argon2,constant_time_eq,cmov,ctutils,dudect-bencher,jsonwebtoken,josekit,totp-rs,aws-lc-rs,aarch64-dit}
- https://github.com/rozbb/dudect-bencher
- https://raw.githubusercontent.com/constantoine/totp-rs/master/src/{lib.rs,token.rs}
- https://raw.githubusercontent.com/Keats/jsonwebtoken/master/src/crypto/mod.rs
- https://raw.githubusercontent.com/hidekatsu-izuno/josekit-rs/master/{README.md,Cargo.toml}

**Güvenlik advisory'leri**
- https://rustsec.org/advisories/RUSTSEC-2023-0071.html · https://github.com/advisories/GHSA-c38w-74pg-36hr
- https://codeload.github.com/rustsec/advisory-db/tar.gz/refs/heads/main → RUSTSEC-2026-0003 (cmov/CVE-2026-23519, 2026-01-14), RUSTSEC-2025-0144 (ml-dsa/CVE-2026-22705, 2025-12-12), RUSTSEC-2026-0212 (libcrux-secrets, 2026-05-26), RUSTSEC-2026-0211 (libcrux-aesgcm, 2026-07-14), RUSTSEC-2024-0354 (vodozemac/CVE-2024-40640), RUSTSEC-2022-0018 (totp-rs/CVE-2022-29185)
- https://github.com/advisories/GHSA-rhgq-f8x5-j2jc (Keycloak CVE-2026-4633, 2026-03-23) · https://github.com/keycloak/keycloak/issues/47619 · .../issues/26625
- https://www.djangoproject.com/weblog/2024/jul/09/security-releases/ (CVE-2024-39329) · https://code.djangoproject.com/ticket/20760

**Akademik**
- https://www.usenix.org/system/files/sec20-van_goethem.pdf (Timeless Timing Attacks, USENIX Sec 2020)
- https://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf · https://dl.acm.org/doi/10.1145/1455526.1455530 (Crosby et al. 2009)
- https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf (Brumley & Boneh 2003)
- https://www.cl.cam.ac.uk/~rja14/Papers/whatyouc.pdf (Simon/Chisnall/Anderson, EuroS&P 2018)
- https://eprint.iacr.org/2016/1123.pdf (dudect, DATE 2017) · https://github.com/oreparaz/dudect
- https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/almeida (ct-verif)
- arXiv:1912.08788 (Binsec/Rel, IEEE S&P 2020)
- https://eprint.iacr.org/2023/1442 (Marvin, ESORICS 2023)

**Araçlar / donanım / kernel**
- https://www.imperialviolet.org/2010/04/01/ctgrind.html · https://post-apocalyptic-crypto.org/timecop/ · https://github.com/microwalk-project/Microwalk · https://github.com/veorq/cryptocoding
- https://gofetch.fail/ (USENIX Sec 2024) · https://downfall.page/ · https://lock.cmpxchg8b.com/zenbleed.html
- https://comsec.ethz.ch/research/microarch/{vmscape-...,breaking-the-barrier,microarchitectural-attacks-on-the-stack-engine,spring}/ · https://www.vusec.net/projects/training-solo/
- https://git.kernel.org/.../Documentation/admin-guide/hw-vuln/{index,attack_vector_controls,core-scheduling,vmscape,srso}.rst · .../arch/arm64/kernel/{entry.S,cpufeature.c}
- https://www.intel.com/.../data-operand-independent-timing-isa-guidance.html (güncelleme 2025-09-10)
- https://raw.githubusercontent.com/openssl/openssl/master/CHANGES.md
- https://people.redhat.com/~hkario/marvin/ · https://github.com/tomato42/marvin-toolkit

**Standartlar / rehberler**
- https://www.rfc-editor.org/rfc/rfc8725.txt · rfc7636.txt · rfc8628.txt · rfc9106.txt
- https://www.ietf.org/archive/id/draft-ietf-jose-deprecate-none-rsa15-05.txt · https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/
- https://cheatsheetseries.owasp.org/cheatsheets/{Authentication,Password_Storage,Forgot_Password}_Cheat_Sheet.html
- https://owasp.org/www-project-web-security-testing-guide/latest/.../04-Testing_for_Account_Enumeration_and_Guessable_User_Account.html
- https://pages.nist.gov/800-63-4/sp800-63b.html

**Referans implementasyonlar**
- https://github.com/sebadob/rauthy (main, 2026-09-08 tarball) — `login_delay.rs`, `oidc/authorize.rs`, `oidc/grant_types/device_code.rs`, `entity/{clients,api_keys,sessions,magic_links}.rs`, `config.toml` · https://sebadob.github.io/rauthy/config/argon2.html
- https://www.keycloak.org/server/all-provider-config · https://www.keycloak.org/docs/latest/server_admin/index.html
- https://github.com/kanidm/kanidm/discussions/610 (2021-11-14)
