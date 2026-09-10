# 11. Runtime/binary sertleştirme ve izolasyon

> `ARGUS.md` §11'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§11 §X` referansları aynı anlamda.



---

### A) RUST BINARY HARDENING

#### A.1 Rust'ın varsayılan olarak verdikleri

rustc'nin resmî "Exploit Mitigations" tablosu ([doc.rust-lang.org/rustc/exploit-mitigations.html](https://doc.rust-lang.org/rustc/exploit-mitigations.html)):

| Mitigation | Destekli | Varsayılan açık | Rust sürümü |
|---|---|---|---|
| Position-independent executable (PIE) | Evet | **Evet** | 0.12.0 (2014-10-09) |
| Integer overflow checks | Evet | **Hayır** (sadece debug-assertions açıkken) | 1.1.0 (2015-06-25) |
| Non-executable memory (NX) | Evet | **Evet** | 1.8.0 (2016-04-14) |
| Stack clashing protection (stack probes) | Evet | **Evet** | 1.20.0 (2017-08-31) |
| Read-only relocations + immediate binding (Full RELRO / BIND_NOW) | Evet | **Evet** | 1.21.0 (2017-10-12) |
| Heap corruption protection | Evet | Evet (OS/allocator kaynaklı) | 1.32.0 (2019-01-17) |
| **Stack smashing protection (canary)** | Evet | **HAYIR** — `-Z stack-protector` | **Nightly** |
| **Forward-edge CFI** | Evet | **HAYIR** — `-Z sanitizer=cfi` | **Nightly** |
| **Backward-edge (shadow/safe stack)** | Evet | **HAYIR** — `-Z sanitizer=shadow-call-stack,safestack` | **Nightly** |

**Sonuç:** `cargo build --release` ile üretilen Linux binary'si zaten PIE + Full RELRO + NX + stack probes verir. `checksec` çıktısında "Full RELRO / NX enabled / PIE enabled" görürsünüz; **eksik olan tek klasik kalem stack canary'dir** (`No canary found`). Argus için bu, C/C++ dünyasına göre iyi bir başlangıç — ama "en güvenli" iddiası için yeterli değil.

> **Argus için aksiyon:** CI'da her release binary'sinde `checksec --file=target/release/argus` (veya `hardening-check`) çalıştırıp beklenen değerleri assert eden bir test yazın. Regresyon tespiti için kritik — özellikle bir gün `-C relocation-model=static` veya özel linker script eklerseniz sessizce PIE'yi kaybedersiniz.

#### A.2 Stack protector — 2026 durumu (SORULAN SORU)

**Hayır, 2026-09 itibarıyla stabilize DEĞİL.**

- Tracking issue: [rust-lang/rust#114903](https://github.com/rust-lang/rust/issues/114903)
- Stabilizasyon PR'ı: [rust-lang/rust#146369](https://github.com/rust-lang/rust/pull/146369) — `-Zstack-protector` → `-Cstack-protector` olarak stabilize etme önerisi. Açılış **2025-09-09**, son force-push **2026-06-15**, **2026-07-13** itibarıyla `S-blocked` (PR #157941'e — "target modifier" altyapısına — bağlı). FCP "merge-pending" ama tamamlanmamış. Compiler team üyelerinden onaylar var ama **merge edilmemiş**.
- Semantik: `-Cstack-protector=strong` Clang'in `-fstack-protector-strong` heuristiğini kullanır; PR notu bu heuristiklerin Rust için tasarlanmadığını ve bazı durumlarda aşırı-muhafazakâr olabileceğini söylüyor.

> **Argus için:** Stack canary'nin Rust'taki değeri sınırlı — çünkü canary'nin koruduğu şey stack buffer overflow'dur ve safe Rust'ta bu zaten yok. Değeri yalnızca (a) `unsafe` blokları, (b) FFI ile bağlanan C kütüphaneleri (PKCS#11 modülleri, aws-lc-rs'in C parçaları) için vardır. **Nightly'ye geçme maliyeti bunu haklı çıkarmaz.** Bunun yerine unsafe/FFI yüzeyini küçültün.

#### A.3 CFI (Control Flow Integrity) — 2026 durumu

Kaynak: [Rust Unstable Book — sanitizer](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html)

Birebir alıntı:
> "LLVM CFI can be enabled with `-Zsanitizer=cfi` and requires LTO (i.e., `-Clinker-plugin-lto` or `-Clto`). Cross-language LLVM CFI can be enabled with `-Zsanitizer=cfi`, and requires the `-Zsanitizer-cfi-normalize-integers` option to be used with Clang `-fsanitize-cfi-icall-experimental-normalize-integers` option for cross-language LLVM CFI support, and proper (i.e., non-rustc) LTO (i.e., `-Clinker-plugin-lto`). It is recommended to rebuild the standard library with CFI enabled by using the Cargo build-std feature (i.e., `-Zbuild-std`) when enabling CFI."

- **Nightly-only.** Evet, hâlâ.
- **LTO zorunlu**, `-Zbuild-std` şiddetle tavsiye ediliyor (yani std'yi de yeniden derliyorsunuz → build süresi ve reproducibility maliyeti).
- **KCFI** hedefleri: `aarch64-linux-android`, `aarch64-unknown-linux-gnu`, `x86_64-linux-android`, `x86_64-unknown-linux-gnu`.
- **ShadowCallStack** (backward-edge): aarch64'te `x18` register'ının ABI'de rezerve olmasını gerektirir. Desteklenen hedefler: `aarch64-linux-android` (bionic runtime var), `aarch64-unknown-fuchsia`, `aarch64-unknown-none` (`-Zfixed-x18` zorunlu) ve riscv64 bare-metal/Fuchsia hedefleri. **`aarch64-unknown-linux-gnu` listede YOK** — yani standart Linux sunucu hedefinde ShadowCallStack pratikte kullanılamaz (glibc x18'i rezerve etmiyor).
- **SafeStack**: yalnızca `x86_64-unknown-linux-gnu`.
- 2026'da yeni: **RealtimeSanitizer** (`-Zsanitizer=realtime`) tüm hedeflerde listelenmiş.

**2026 yol haritası:** [Rust Project Goals 2026 — Rust for Linux compiler features](https://goals.rust-lang.org/2026/rust-for-linux-compiler-features.html) — `-Zsanitizer=kcfi`, `-Zsanitizer-cfi-normalize-integers`, `-Zfixed-x18` stabilizasyon hedefleri arasında. Zaman aralığı **2026-2027**, durum "Accepted", champion Wesley Wiser. **Belirli bir stabilizasyon tarihi yok.** Not: bu hedef *kernel* ihtiyaçlarına odaklı; userspace `-Zsanitizer=cfi` doğrudan hedefte değil.

**Android:** [source.android.com/docs/security/test/cfi](https://source.android.com/docs/security/test/cfi) — LLVM CFI Android 8.1'den beri media stack'te, Android 9'da genişletildi, "System CFI is on by default". Performans: *"In testing on Android, the combination of LTO and CFI results in negligible overhead to code size and performance; in a few cases both improved."* **Ancak bu sayfa Rust kodu için CFI'dan hiç bahsetmiyor — Android'in Rust bileşenlerinde CFI'ın açık olup olmadığı bu kaynaktan [DOĞRULANMADI].**

> **Argus için karar:** CFI, Rust-only bir kod tabanında marjinal fayda sağlar (indirect call hedefleri zaten tip-güvenli). **Gerçek fayda cross-language CFI'dadır**: eğer Argus PKCS#11 (HSM) veya `aws-lc-rs` gibi C kodu link ediyorsa, C tarafındaki bir bug'ın Rust'taki fonksiyon pointer'larına sıçramasını engeller. Maliyet: nightly + LTO + build-std + clang ile eşleştirilmiş build → **CI karmaşıklığı yüksek, reproducible build zorlaşır**. Önerim: **v1'de kullanmayın**, ama "hardened build" adlı opsiyonel bir CI job olarak deneysel tutun ve HSM/FFI yüzeyi büyürse yeniden değerlendirin.

#### A.4 Sanitizer'lar (test/CI için)

Hedef desteği ([Unstable Book, aynı sayfa](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html)):

| Sanitizer | Linux x86_64 | Linux aarch64 | Not |
|---|---|---|---|
| AddressSanitizer | ✅ | ✅ | |
| LeakSanitizer | ✅ | ✅ | |
| ThreadSanitizer | ✅ | ✅ | Veri yarışı — tokio için değerli |
| MemorySanitizer | ✅ | ✅ | **`-Zbuild-std` zorunlu**, tüm kod instrumente olmalı |
| HWAddressSanitizer | ❌ | ✅ | Düşük bellek overhead'i |
| MemTagSanitizer | ❌ | ✅ | `-C target-feature=+mte` gerekli |
| DataFlowSanitizer | ✅ | ❌ | |

Hepsi **nightly-only**. Kullanım: `RUSTFLAGS=-Zsanitizer=<name> cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu`.

> **Argus için:** ASan + LSan + TSan'ı **haftalık nightly CI job** olarak test suite'i üzerinde çalıştırın. Maliyet: ~2-3x yavaşlık, nightly toolchain bakımı. Fayda: `unsafe`/FFI kodunda gerçek bellek hataları ve tokio kodunda veri yarışları. **MSan'ı atlayın** — `-Zbuild-std` + tüm bağımlılıkların instrumente edilmesi gereksinimi C kütüphaneleri (ring/aws-lc-rs) yüzünden pratikte kırılır.

#### A.5 `overflow-checks` ve `panic` — release profili

Cargo varsayılanları ([doc.rust-lang.org/cargo/reference/profiles.html](https://doc.rust-lang.org/cargo/reference/profiles.html)) — birebir:

```toml
[profile.release]
opt-level = 3
debug = false
split-debuginfo = '...'  # Platform-specific.
strip = "none"
debug-assertions = false
overflow-checks = false   # ← DİKKAT
lto = false
panic = 'unwind'
incremental = false
codegen-units = 16
rpath = false
```

**`overflow-checks = false`** demek: release'te `u32` taşması **panic etmez, sarmalanır (wrap)**. Bir IdP'de bu doğrudan güvenlik sorunudur: token sayaçları, session TTL aritmetiği, rate-limit sayaçları, `len - offset` hesapları, quota kontrolleri. Rust'ta wraparound *tanımlı davranıştır* (UB değil) ama **mantık hatası** üretir — ve bir IdP'de mantık hatası = yetki atlatma.

**Maliyet:** Genelde %1-5 arası CPU (iş yüküne bağlı; kripto hot-loop'larda daha fazla). Argus gibi I/O ve Argon2 baskın bir sistemde **ölçülemeyecek kadar küçük**.

**`panic` kararı:**
- `panic = "unwind"` (varsayılan): panic bir thread'i öldürür, tokio task'ı düşer, süreç yaşar. Ama `catch_unwind` ile yakalanmayan bir unwind, kilitlenmiş mutex'leri **zehirli (poisoned)** bırakır ve `unsafe` kodda yarım kalmış invariant'lar oluşturabilir.
- `panic = "abort"`: süreç ölür. **Güvenlik açısından daha temiz** (fail-closed, tutarsız state'te devam yok), binary daha küçük/hızlı, ama **DoS yüzeyini büyütür** — tek bir panic tüm süreci düşürür.

> **Argus için önerim:** `overflow-checks = true` **mutlaka açın**. `panic` için: `unwind` bırakın **ama** panic'i asla bir DoS vektörü yapmayın — yani panic'e giden yolları (unwrap/expect/index/slice) `clippy::unwrap_used`, `clippy::expect_used`, `clippy::indexing_slicing`, `clippy::panic`, `clippy::integer_arithmetic` lint'leriyle handler kodunda **yasaklayın**. Bir de tokio'nun `unhandled_panic = ShutdownRuntime` davranışını bilinçli seçin. `abort` seçerseniz, tek bir parser panic'i = tam DoS olur (bkz. F bölümü).

#### A.6 Intel CET (shadow stack / IBT)

Kaynak: [Linux kernel docs — x86 shadow stack](https://docs.kernel.org/arch/x86/shstk.html)

- 64-bit kernel'de **yalnızca userspace shadow stack ve kernel IBT** destekleniyor.
- Uygulama ELF note ile işaretlenir: `readelf -n <binary> | grep -a SHSTK` → `properties: x86 feature: SHSTK`. **Kernel bu işareti doğrudan işlemez**; loader (glibc ld.so veya static runtime) `arch_prctl` ile açar.
- `arch_prctl` arayüzü (yalnız 64-bit): `ARCH_SHSTK_ENABLE`, `ARCH_SHSTK_DISABLE`, `ARCH_SHSTK_LOCK`, `ARCH_SHSTK_UNLOCK` (yalnız ptrace), `ARCH_SHSTK_STATUS`. Özellikler: `ARCH_SHSTK_SHSTK`, `ARCH_SHSTK_WRSS`.
- Toolchain gereksinimi: Binutils v2.29+ veya LLVM v6+.

> **Argus için kritik nokta:** rustc'nin ürettiği object'lerin `GNU_PROPERTY_X86_FEATURE_1_SHSTK`/`IBT` property note'unu taşıyıp taşımadığını **bu araştırmada doğrulayamadım [DOĞRULANMADI]**. Pratikte: eğer binary'nizde bu note yoksa, glibc shadow stack'i **açmaz** ve CET koruması hiç devreye girmez. **Yapılacak yerel doğrulama:**
> ```bash
> readelf -n target/release/argus | grep -A2 'GNU_PROPERTY\|x86 feature'
> ```
> Note yoksa, linker'a `-Wl,-z,force-bti` benzeri bir zorlamayla veya tüm object'lerin property taşımasını sağlayarak eklenmeli. **Bunu Argus'ta ölçün ve raporlayın — çoğu Rust projesi bunu hiç kontrol etmiyor.** Aynı doğrulama aarch64 için BTI (`-Z branch-protection=bti,pac-ret`) tarafında da geçerli.

#### A.7 Önerilen `RUSTFLAGS` / build reçetesi

Kaynak: [Codegen Options](https://doc.rust-lang.org/rustc/codegen-options/index.html)

- `relocation-model` varsayılanı **`pic`**; "If relocation model is `pic` and the target supports PIE, the linker will be instructed (`-pie`)". → **Değiştirmeyin.**
- `control-flow-guard` yalnız Windows, varsayılan kapalı.
- `strip` hakkında dokümanın kendi uyarısı: *"Removing debuginfo only impacts 'friendly' introspection and should not be relied upon for security or obfuscation."* → strip'i güvenlik kontrolü sayma; sadece imaj boyutu için.

**Argus için önerilen `Cargo.toml` + `.cargo/config.toml`:**

```toml
# Cargo.toml
[profile.release]
overflow-checks = true      # ← IdP için zorunlu
debug-assertions = false
lto = "fat"                 # CFI'ye ileride geçerseniz zaten gerekli
codegen-units = 1           # LTO ile tutarlı, biraz daha iyi kod
panic = "unwind"            # bilinçli seçim, A.5'e bakın
strip = "debuginfo"         # symbols değil: panic backtrace'leri koruyun
```

```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = [
  "-C", "link-arg=-Wl,-z,relro",
  "-C", "link-arg=-Wl,-z,now",          # BIND_NOW — zaten varsayılan, açıkça pekiştir
  "-C", "link-arg=-Wl,-z,noexecstack",
  "-C", "link-arg=-Wl,-z,separate-code",
  "-C", "link-arg=-Wl,--as-needed",
  "-C", "force-frame-pointers=yes",     # profil/crash analizi + bazı CFI araçları
]
```

`-z,relro` ve `-z,now` Rust'ta zaten varsayılan (1.21.0'dan beri) ama **açıkça belirtmek regresyona karşı sigortadır** ve bazı custom linker'larda (mold, lld, wild) varsayılan farklılaşabilir.

---

### B) PROCESS ISOLATION

#### B.1 seccomp-bpf — Rust ekosistemi olgunluk karşılaştırması

| Crate | Son sürüm | Tarih | İndirme | Değerlendirme |
|---|---|---|---|---|
| **seccompiler** | 0.5.0 | **2025-03-07** | ~2.1M/ay, 229 crate | Sahibi **rust-vmm** org (Andreea Florescu, Alin Dima, petreeftime). Saf Rust, C bağımlılığı yok. Hedefler: LE x86_64, aarch64, riscv64. Bağımlılık: sadece `libc` (+opsiyonel serde/serde_json JSON için). **En olgun seçenek.** [lib.rs/crates/seccompiler](https://lib.rs/crates/seccompiler) |
| libseccomp | 0.4.0 | — | ~1.2M toplam | C `libseccomp` bindings — sisteme kütüphane kurmayı gerektirir; static/distroless imajda sorun. [libseccomp-rs](https://github.com/libseccomp-rs/libseccomp-rs) |
| syscallz | 0.17.0 | ~2 yıl önce | 100k toplam | Bakımsız görünüyor |
| **extrasafe** | 0.5.1 | **2024-04-16** | ~5.5k/ay | Harry Stern + 3 katkıcı. Seccomp + Landlock + user namespaces'i tek ergonomik API'de birleştirir (`SafetyContext`, `Isolate`, `RuleSet`'ler). **Ama: yalnızca x86_64, çok düşük kullanım, 2024'ten beri release yok.** [lib.rs/crates/extrasafe](https://lib.rs/crates/extrasafe) |

**Gerçek dünya örneği — Firecracker** ([docs/seccomp.md](https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md)):
- `seccompiler` kullanıyor.
- Filtreler **thread bazında** yükleniyor: VMM thread, API thread, VCPU thread'leri — her biri kendi ana işine başlamadan hemen önce.
- Filtreler `resources/seccomp` altında JSON, **build-time'da** derlenip binary'ye gömülüyor.
- Politika: *"the bare minimum set of system calls and parameters that Firecracker needs in order to function correctly"*.
- **Uyarı (alıntı):** thread-özel filtreleme yanlış yapılandırılırsa *"result in abruptly terminating the process or disabling the seccomp security boundary altogether"*. Debug binary'ler ve deneysel GNU hedefleri **varsayılan filtre olmadan** gelir.

#### B.2 Tokio tabanlı HTTP sunucusu için seccomp filtresi kurmanın zorlukları

Bu araştırmadan çıkan **en önemli operasyonel uyarı**:

**io_uring seccomp'u BYPASS eder.** ([blog.0x74696d.com/posts/iouring-and-seccomp/](https://blog.0x74696d.com/posts/iouring-and-seccomp/), **2022-11-27**) — Birebir mantık: *"we can't filter out syscalls we never make!"* io_uring, `connect()`, `openat()`, `read()` gibi işlemleri **opcode** olarak submission queue'ya yazar ve tek bir `io_uring_enter` ile gönderir. seccomp syscall numarasına baktığı için bu opcode'ları göremez.

Mitigasyonlar:
1. Uygulama kendi io_uring yeteneklerini `io_uring_register_restrictions` ile kısıtlar (untrusted input almadan önce).
2. Docker/containerd varsayılan seccomp profili `io_uring_setup`/`io_uring_enter`/`io_uring_register`'ı **zaten bloklar** — Docker dokümanı bunu açıkça *"blocked due to security vulnerabilities that can be exploited to break out of containers"* diye gerekçelendiriyor ([docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)).

> **Argus için mimari karar:** **io_uring KULLANMAYIN.** Standart tokio (epoll) backend'inde kalın. Nedenler: (a) seccomp politikanız anlamlı kalır, (b) container runtime'ları zaten io_uring'i bloklar → deployment kırılır, (c) io_uring'in kendi kernel CVE geçmişi bir IdP için kabul edilemez risk. Performans kaybı (tokio blog'unda ~%60 iyileşme iddiası, [tokio.rs/blog/2021-07-tokio-uring](https://tokio.rs/blog/2021-07-tokio-uring)) bir IdP'de zaten Argon2 ve kripto baskın olduğu için önemsizdir.

**Tokio+epoll için minimum syscall seti (allowlist yaklaşımı):** `epoll_create1`, `epoll_ctl`, `epoll_wait`/`epoll_pwait`, `accept4`, `read`/`recvfrom`, `write`/`sendto`/`writev`, `close`, `fcntl`, `mmap`/`munmap`/`mremap`/`brk` (allocator), `futex`, `clock_gettime`, `getrandom`, `sched_yield`, `madvise`, `rt_sigaction`/`rt_sigprocmask`/`rt_sigreturn`, `sigaltstack`, `exit_group`, `restart_syscall`, `eventfd2`, `timerfd_*`, `setsockopt`/`getsockopt`, `shutdown`. **[Bu liste literatürden derlenmiş genel bir çerçevedir; Argus'un tam seti ancak `strace -f -c` ile ölçülerek çıkarılır — DOĞRULANMADI olarak işaretleyin ve deneysel olarak üretin.]**

**Pratik strateji (iki fazlı):**
1. **Faz 1 (init):** Konfigürasyon oku, TLS sertifikalarını yükle, DB bağlantı havuzunu kur, portu bind et, key material'i belleğe al.
2. **Faz 2 (serve):** `no_new_privs` set et → capability'leri düşür → Landlock uygula → **sonra** seccomp filtresini yükle → tokio runtime'ı başlat.

Kritik: seccomp'u **tokio runtime thread'leri spawn edilmeden önce** yüklerseniz, `SECCOMP_FILTER_FLAG_TSYNC` bayrağıyla tüm thread'lere yayılır. `seccompiler`'ın `apply_filter` fonksiyonu TSYNC kullanır. Yükledikten sonra spawn edilen thread'ler filtreyi zaten miras alır.

#### B.3 Capability düşürme, no_new_privs, setuid drop

- **`caps` crate 0.5.6 (2025-10-17)** — Luca Bruno + 12 katkıcı, ~2.3M indirme/ay, 1182 crate kullanıyor, Unix API kategorisinde #20. Saf Rust, harici C kütüphanesi gerektirmez (**static/musl build için önemli**). Tüm setleri destekler: Effective, Permitted, Inheritable, **Ambient**, **Bounding**. ([lib.rs/crates/caps](https://lib.rs/crates/caps))
- **`no_new_privs`**: `nix` 0.31.3 `nix::sys::prctl` modülünde `set_no_new_privs()`, `get_no_new_privs()`, ayrıca `set_dumpable()`, `set_keepcaps()`, `set_pdeathsig()`, `set_name()`, `set_thp_disable()` mevcut ([docs.rs/nix/latest/nix/sys/prctl](https://docs.rs/nix/latest/nix/sys/prctl/index.html)). `process` feature'ı gerekli, Linux-only.

> **Argus sıralaması (bu sıra önemli!):**
> 1. `prctl(PR_SET_DUMPABLE, 0)` — core dump'ta private key sızmasın.
> 2. Port 443 bind (root veya `CAP_NET_BIND_SERVICE` ile) — ya da daha iyisi: **hiç root olmayın**, `net.ipv4.ip_unprivileged_port_start` veya socket activation kullanın.
> 3. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — **seccomp'tan önce zorunlu** (unprivileged seccomp bunu gerektirir) ve setuid binary'lerle privilege escalation'ı kapatır.
> 4. Bounding set'i **tamamen temizleyin** (`caps::clear(None, CapSet::Bounding)`), sonra Permitted/Effective/Inheritable/Ambient'ı sıfırlayın.
> 5. `setgroups([])` → `setgid` → `setuid` (bu sırayla; ters sıra klasik bir güvenlik hatasıdır).
> 6. Landlock.
> 7. seccomp.

#### B.4 Namespaces / unshare

- **`unshare` crate 0.7.0 — son release 2021-05-04**, ~2.1k indirme/ay, 5 crate kullanıyor. **Fiilen bakımsız** ([lib.rs/crates/unshare](https://lib.rs/crates/unshare)). Argus'ta kullanmayın.
- **`extrasafe`'in `Isolate`'i** unprivileged user namespace başlatır — ama extrasafe'in kendisi düşük olgunlukta (bkz. B.1).

> **Argus için:** Namespace izolasyonunu **uygulama içinde çözmeye çalışmayın**. Bu, container runtime'ının (containerd/CRI-O) ve Kubernetes'in işi. Uygulama katmanında Landlock + seccomp + capability drop yapın; namespace'i platforma bırakın. `unshare`'i kendiniz yapmak, PID 1 reaping, mount propagation, /proc yeniden mount gibi bir sürü ince hata kaynağı açar.

#### B.5 Privilege separation mimarisi — Argus için değer mi?

**Gerçek dünya kanıtı:**

**OpenSSH 9.8 (2024-07-01)** ([openssh.org/txt/release-9.8](https://www.openssh.org/txt/release-9.8)) — birebir:
> "the server has been split into a listener binary, sshd(8), and a per-session binary 'sshd-session'. This allows for a much smaller listener binary, as it no longer needs to support the SSH protocol."

Aynı release'te CVE-2024-6387 (regreSSHion): *"A critical vulnerability in sshd(8) was present in Portable OpenSSH versions between 8.5p1 and 9.7p1 (inclusive) that may allow arbitrary code execution with root privileges."* — 32-bit Linux/glibc + ASLR'de ortalama 6-8 saatlik sürekli bağlantıyla exploit edilebildi. **Bu split doğrudan bu sınıf bug'a mimari cevaptı.**

**Ayrıca** OpenSSH security sayfası ([openssh.org/security.html](https://www.openssh.org/security.html)), CVE-2023-38408 (ssh-agent PKCS#11 RCE, 2023-07-19) için: *"This is not believed to be exploitable, and it occurs in the unprivileged pre-auth process that is subject to chroot(2) and is further sandboxed on most major platforms."* — **privsep bir RCE'nin etkisini fiilen sıfırladı.**

> **Argus için değerlendirmem: EVET, değer — ama seçici olarak.**
>
> Rust'ta bellek güvenliği zaten var, dolayısıyla "buffer overflow'u hapset" argümanı OpenSSH'teki kadar güçlü değil. Ama **iki gerçek gerekçe kalıyor:**
>
> **1. Anahtar materyali süreç ayrımı (YÜKSEK DEĞER).** Signing key'ler HTTP sürecinin adres alanında **hiç bulunmasın**. Ayrı bir `argus-signer` süreci:
> - Unix domain socket üzerinden `SCM_CREDENTIALS` ile kimlik doğrulanmış istek alır ("bu claim set'i imzala").
> - Kendi Landlock domain'i: **hiçbir dosya yazamaz**, yalnızca key store'u okur.
> - Kendi seccomp filtresi: **network syscall'ları tamamen yasak** (`socket`, `connect`, `sendto` yok). Bu, bir key exfiltration'ı fiziksel olarak imkânsız kılar.
> - Bir Spectre/side-channel, bir `unsafe` bug'ı, bir FFI (PKCS#11) sorunu HTTP sürecini ele geçirse bile **anahtarlar okunamaz**.
> - Bonus: bu süreç Argon2 hesaplamasını da yapabilir → memory budget'ı ayrı sınırlanır (bkz. G bölümü).
>
> **2. Parser izolasyonu (ORTA DEĞER).** SAML/XML gibi tarihsel olarak felaket olan formatları ayrı, "yok edilebilir" bir worker sürecinde parse etmek. Bir stack exhaustion abort'u tüm IdP'yi değil, o worker'ı öldürür. **Bu, F bölümündeki Kanidm CVE'sinin tam olarak çözümüdür.** Chromium'un site isolation'ı ve Firefox'un RLBox'ı bu modeli izler.
>
> **Maliyet:** IPC latency (Unix socket ~10-50µs, imza başına kabul edilebilir), süreç yaşam döngüsü yönetimi, deployment karmaşıklığı (container'da 2 süreç → PID 1 reaping, supervisor gerekir veya sidecar pattern). **Kanidm ve Rauthy'nin ikisi de bunu yapmıyor** — Argus "en güvenli" iddiasındaysa burada gerçek bir diferansiyasyon var.

---

### C) LANDLOCK

#### C.1 ABI seviyeleri — 2026 durumu (SORULAN SORU: doğrulandı)

Kaynak: [man7.org/linux/man-pages/man7/landlock.7.html](https://man7.org/linux/man-pages/man7/landlock.7.html) + [docs.kernel.org/userspace-api/landlock.html](https://docs.kernel.org/userspace-api/landlock.html)

| ABI | Kernel | Eklenen |
|---|---|---|
| 1 | **5.13** | Temel FS: `EXECUTE`, `WRITE_FILE`, `READ_FILE`, `READ_DIR`, `REMOVE_DIR`, `REMOVE_FILE`, `MAKE_*` |
| 2 | **5.19** | `LANDLOCK_ACCESS_FS_REFER` (dizinler arası link/rename) |
| 3 | **6.2** | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 4 | **6.7** | **Ağ:** `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` |
| 5 | **6.10** | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| 6 | **6.12** | IPC scoping: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` |
| 7 | **6.15** | Logging bayrakları (exec tracking, subdomain kısıtlama) |
| 8 | **7.0** | **`LANDLOCK_RESTRICT_SELF_TSYNC`** — çok-thread'li enforcement |
| 9 | **7.1** | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (pathname socket) |
| 10 | (kernel docs) | **UDP** kısıtlamaları (`BIND_UDP`, `CONNECT_SEND_UDP`) + quiet rule bayrakları |
| 11 | (kernel docs) | `no_new_privs`'in ruleset enforcement'a entegrasyonu |

Not: man page 1-8'i listeliyor; kernel dokümanı 9, 10, 11'i de gösteriyor. **Soruda "ABI 5/6" tahmin ediliyordu — gerçek 2026 durumu çok daha ileri: ABI 11.**

#### C.2 Landlock'un yapamadıkları (kritik sınırlamalar)

Kernel dokümanından, birebir kapsam:
- **Kısıtlanamayan işlemler:** `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl`, `access`.
- **`mount` ve `pivot_root` sandbox'lı thread'ler için kısıtlanamaz.**
- `/proc` üzerinden erişilen özel dosya sistemleri (pipe, socket, nsfs) **açıkça kısıtlanamaz** — ptrace kısıtlamaları dolaylı koruma sağlar.
- **16 katman (layer) stack sınırı.**
- **Truncate ve ioctl hakları yalnızca yeni açılan FD'lere uygulanır** — mevcut stdin/stdout/stderr'e değil.
- OverlayFS katmanları bind mount'lardan bağımsız değerlendirilir.

#### C.3 `landlock` Rust crate'i

- **Resmî bindings**, Mickaël Salaün (Landlock'un kernel'daki yazarı) tarafından, `landlock-lsm/rust-landlock`.
- **Sürüm 0.4.7, yayın 2026-07-27.** ABI **v9**'a kadar destekliyor.
- Best-effort modeli (birebir): *"In the default best-effort mode, `Ruleset` will determine compatibility with the intersection of the currently running kernel's features and those required by the caller."*
- Sınırlama beyanı: *"This crate exposes the Landlock features available as of Linux 7.1 (Landlock ABI v9) and then inherits some kernel limitations that will be addressed with future kernel releases (e.g., arbitrary mounts are always denied)."*
- Forward-compat uyarısı: `BitFlags::all()` gibi hareketli hedeflere güvenmeyin, **hedef ABI'yi açıkça belirtin** — yoksa `cargo update` sessizce yeni access right'ları etkinleştirebilir.

#### C.4 ⚠️ TOKIO İÇİN KRİTİK: Landlock thread bazlıdır

Bu, raporun **en önemli operasyonel bulgularından biri** ([docs.rs/landlock](https://docs.rs/landlock/latest/landlock/)):

> *"By default `landlock_restrict_self()` only restricts the calling thread."*
>
> *"Landlock ABI v8 adds `all_threads()` to atomically enforce the configuration on every thread of the process."*
>
> *"On an older kernel this is silently dropped in the default best-effort mode, leaving sibling and parent threads unrestricted, so multithreaded programs that need this guarantee should require it."*

**Bunun Argus için anlamı:**
- Tokio multi-thread runtime'ında Landlock'u worker thread'lerden birinde uygularsanız, **diğer worker'lar kısıtlanmamış kalır** → sandbox tamamen anlamsızdır.
- ABI v8 (`all_threads()`) **Linux 7.0** gerektirir. 2026'da bu hâlâ çok yeni bir kernel — çoğu prod ortamı (RHEL 9/10, Ubuntu 24.04/26.04 LTS) daha eski kernel çalıştırıyor olabilir.
- **Best-effort modunda `all_threads()` eski kernel'de SESSİZCE düşürülür** → sandbox'ınız olduğunu sanırsınız, olmaz. **Sessiz güvenlik başarısızlığı.**

> **Argus için doğru çözüm (iki katmanlı):**
> 1. **Landlock'u tokio runtime başlatılmadan ÖNCE, ana thread'de uygulayın.** Landlock domain'i `fork`/`clone` ile miras alınır, dolayısıyla sonradan spawn edilen tüm tokio worker'ları kısıtlamayı devralır. Bu, ABI 8 gerektirmeyen ve tüm 5.13+ kernel'lerde çalışan yaklaşımdır.
> 2. Ek olarak, kernel destekliyorsa `all_threads()` isteyin; **ama `CompatLevel::HardRequirement` ile isteyin ve düşürülürse başlangıçta hata verin** (best-effort ile sessiz düşürmeye izin vermeyin). Minimum garanti seviyesini (örn. ABI ≥ 1 zorunlu, ağ kısıtlaması için ABI ≥ 4 opsiyonel) log'a yazdırın ve `/healthz`'da raporlayın.

#### C.5 Landlock kullanan gerçek projeler

Doğrulayabildiklerim:
- **Island** — Landlock projesinin kendi sandbox aracı, Firefox çalıştırabiliyor ([github.com/landlock-lsm/island](https://github.com/landlock-lsm/island)).
- **Landrun** — Go tabanlı CLI sandbox, systemd servisleri destekliyor ([Slashdot, 2025-04-05](https://linux.slashdot.org/story/25/04/05/217212/landrun-lightweight-linux-sandboxing-with-landlock-no-root-required)).
- **extrasafe** — opsiyonel Landlock feature'ı.
- Kernel dokümanında sistem-genelinde yönetim sayfası var ([docs.kernel.org/admin-guide/LSM/landlock.html](https://docs.kernel.org/admin-guide/LSM/landlock.html)), yani distro entegrasyonu olgunlaşmış.

**[DOĞRULANMADI]:** systemd, Docker, Firefox (doğrudan), sudo-rs'in Landlock kullandığını **bu araştırmada doğrulayamadım.** Soruda varsayılan bu adopsiyonlar için kesin kanıt bulamadım — iddia etmeyin.

#### C.6 Argus için pratik Landlock politikası

```
İzin verilen (read-only):
  /etc/argus/            → config, TLS cert/key (yalnız READ_FILE)
  /usr/share/argus/      → statik varlıklar, şablonlar
  /etc/ssl/certs/        → CA bundle (upstream OIDC/LDAP doğrulaması için)

İzin verilen (read-write):
  /var/lib/argus/db/     → yalnızca DB dosyaları (embedded DB kullanılıyorsa)
  /run/argus/            → Unix socket (signer sürecine)

Her şey başka yer: YASAK
  → /etc/shadow, /etc/passwd okunamaz
  → /proc/self/mem, /proc/*/environ okunamaz (ama /proc kısıtlaması sınırlı, bkz. C.2)
  → /tmp yazılamaz (memfd kullanın)
  → hiçbir yere yazma/exec

Ağ (ABI ≥ 4, kernel ≥ 6.7):
  BIND_TCP:    yalnızca 8443 (ve varsa metrics portu)
  CONNECT_TCP: yalnızca 5432 (Postgres), 636 (LDAPS), 443 (upstream OIDC)
  → Bu, bir SSRF'yi veya exfiltration'ı port düzeyinde keser.

IPC (ABI ≥ 6, kernel ≥ 6.12):
  LANDLOCK_SCOPE_SIGNAL          → başka süreçlere sinyal gönderemez
  LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET → abstract socket'lere bağlanamaz
```

**Maliyet:** Runtime overhead pratik olarak sıfır (path lookup'ta ek LSM hook). Geliştirme maliyeti: bir günlük iş + kernel matrisinde test. **Fayda/maliyet oranı bu raporda en yüksek olan tekniktir.**

**⚠️ Uyarı:** Landlock, `CONNECT_TCP` ile *TCP portlarını* kısıtlar, **IP adreslerini değil**. SSRF savunması için tek başına yeterli değil — uygulama katmanında da IP allowlist/DNS rebinding koruması gerekir.

---

### D) CONTAINER HARDENING

#### D.1 ⚠️ musl allocator problemi — GERÇEK ve ÖNEMLİ

Bu, "static musl binary + scratch image" reçetesinin en büyük tuzağıdır ve sorunuzda doğru tespit edilmiş.

**Ölçümler** ([nickb.dev, 2025-02-02](https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance/)):
- Gerçek uygulama benchmark'ı: **musl glibc'den 7x yavaş**.
- Sentetik çok-thread'li yük, 48 çekirdek: **~700x yavaş**.
- 8 çekirdekli sistem: 4x yavaş.
- Voluntary context switch: **199,786 vs 1,196 → 167x fazla**.
- Futex'te geçen süre: **6.7s vs 0.5s → 13x fazla**.

**Kök neden:** *"contention for a shared lock in musl when allocating or de-allocating memory from multiple threads."* Yavaşlama thread sayısı ve allocation sıklığıyla doğru orantılı.

**Kritik ek bulgu:** musl'un yeni **mallocng** allocator'ı (musl v1.2.1, Rust'ın Mayıs 2023'te benimsediği) **bu sorunu çözmedi**.

Daha eski, aynı yönde: [andygrove.io, 2020-05-05](https://andygrove.io/2020/05/why-musl-extremely-slow/) — ~30x yavaşlama, thread'ler CPU'nun yalnızca %20-40'ını kullanıyordu.

> **Argus için:** Bir IdP **tanım gereği çok-thread'li, yüksek-allocation'lı** bir servistir (her HTTP isteği JSON/JWT allocation'ı, her Argon2 hash'i büyük allocation). **musl'ı varsayılan allocator'ıyla kullanmak felakettir.**
>
> **Üç seçenek, tercih sırasıyla:**
> 1. **glibc + distroless `base-nossl` veya `cc`** — en basit, en hızlı, en az sürpriz. `gcr.io/distroless/cc-debian13:nonroot`.
> 2. **musl + mimalloc** (`#[global_allocator]` olarak) — static binary + ~2 MiB imaj istiyorsanız. Bu, blog yazısının önerdiği çözüm. `mimalloc`, `jemallocator` veya `snmalloc-rs`.
> 3. **glibc static** — mümkün ama NSS/DNS sorunları çıkarır, önermem.
>
> **Karar önerim: (1).** "Static musl + scratch" estetik olarak çekici ama Argus için yanlış trade-off. Distroless `cc` zaten shell'siz, paket yöneticisiz. `static-debian13` ~2 MiB (Alpine'ın ~%50'si, Debian'ın <%2'si) ([GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)) — ama bu `static` variant'ı ve glibc-static gerektiriyor. Eğer (2)'yi seçerseniz, **mimalloc'u kesinlikle ekleyin ve bunu bir CI benchmark'ıyla koruyun.**

#### D.2 Base image seçenekleri

**Distroless** ([GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)):
- İçerik: yalnızca uygulama + runtime bağımlılıkları. **Shell yok, paket yöneticisi yok, standart Linux araçları yok.**
- Variantlar: `static`, `base`, `base-nossl`, `cc`, + dil-özel (Java/Python/Node).
- `gcr.io/distroless/static-debian13` ≈ **2 MiB**.
- `:nonroot` tag'i non-root kullanıcıyla çalışır. `:debug` busybox shell ekler (`debug-nonroot` kombinasyonu var).
- Platform: amd64, arm64, arm, s390x, ppc64le, riscv64.
- Kullananlar: Kubernetes (v1.15'ten beri), Knative, Tekton.

**Chainguard Images** ([chainguard.dev/chainguard-images](https://www.chainguard.dev/chainguard-images)): "industry's largest zero-CVE, built-from-source container image catalog" iddiası. **Wolfi base, SBOM, sigstore imzalama, FIPS variantları ve fiyatlandırma detaylarını bu sayfadan doğrulayamadım [DOĞRULANMADI]** — pazarlama sayfası teknik detay içermiyordu. Ücretsiz `latest` tag'leri var ama sürüm-pinned imajlar ücretli — **bunu satın alma kararından önce doğrulayın.**

**cargo-chef** ([LukeMathWalker/cargo-chef](https://github.com/LukeMathWalker/cargo-chef)): 2.7k yıldız, 295 commit. `cargo chef prepare` → `recipe.json`; `cargo chef cook` bağımlılıkları ayrı Docker layer'da derler. *"up to 5x measured on some commercial projects"*. Caveat'lar: yalnızca container build için (local'de kullanmayın), working directory `cook` ve `build` arasında aynı kalmalı, local path bağımlılıkları cargo'nun timestamp fingerprinting'i yüzünden sıfırdan derlenir.

#### D.3 Container runtime hardening

**Docker varsayılan seccomp profili** ([docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)):
- *"disables around 44 system calls out of 300+. It is moderately protective while providing wide application compatibility."*
- Varsayılan action `SCMP_ACT_ERRNO` (Permission Denied), allowlist mantığı.
- Blokladıkları: `io_uring_enter`/`register`/`setup`, `clone`/`unshare`/`setns` (namespace), `create_module`/`delete_module`/`init_module`, `mount`/`umount`/`reboot`/`swapon`, `ptrace`/`perf_event_open`/`lookup_dcookie`.
- Doküman uyarısı: *"It is not recommended to change the default seccomp profile"* → `seccomp=unconfined` **kesinlikle kullanmayın**.

> **Argus için:** Docker varsayılanı **taban** olsun, ama uygulama içi `seccompiler` filtreniz (B.2) çok daha dar olacak. İkisi birleşiktir (en kısıtlayıcı kazanır). Ayrıca Kubernetes'te `seccompProfile: {type: Localhost, localhostProfile: argus.json}` ile özel profil dağıtabilirsiniz — ama uygulama-içi filtre daha iyidir çünkü init/serve fazlarını ayırabilir.

#### D.4 Kubernetes Pod Security Standards "restricted"

⚠️ **Yaygın bir yanlış bilgiyi düzeltiyorum:** Kubernetes web sitesinin kaynak markdown'ından doğruladım ([raw.githubusercontent.com/kubernetes/website/main/content/en/docs/concepts/security/pod-security-standards.md](https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/concepts/security/pod-security-standards.md)) — **`readOnlyRootFilesystem` PSS "Restricted" politikasının bir kontrolü DEĞİLDİR.** Ne Baseline'da ne Restricted'da yok.

**Restricted'ın Baseline'a EKLEDİĞİ 6 kontrol (tam liste, kaynak markdown'dan):**
1. Volume Types
2. Privilege Escalation (v1.8+)
3. Running as Non-root
4. Running as Non-root user (v1.23+)
5. Seccomp (v1.19+)
6. Capabilities (v1.22+)

Detaylar ([kubernetes.io/docs/concepts/security/pod-security-standards/](https://kubernetes.io/docs/concepts/security/pod-security-standards/)):
- **Capabilities:** *"ALL capabilities must be dropped, and only the NET_BIND_SERVICE capability may be added."* → `drop: ["ALL"]` zorunlu, `add` yalnız `nil` veya `NET_BIND_SERVICE`.
- **Seccomp:** *"Seccomp profile must be explicitly set to one of the allowed values. Both `RuntimeDefault` and `Localhost` are allowed."* → **açıkça set edilmeli**, `nil` kabul edilmez.
- **allowPrivilegeEscalation:** `false` **açıkça** set edilmeli.
- **runAsNonRoot:** `true`.
- **runAsUser:** sıfır olmayan değer.
- Volume types: yalnızca `configMap`, `secret`, `downwardAPI`, `projected`, `emptyDir`, `persistentVolumeClaim`, `ephemeral` gibi allowlist.

> **Argus için manifest (PSS Restricted + ötesi):**
> ```yaml
> spec:
>   automountServiceAccountToken: false   # PSS'te yok, ama önemli
>   securityContext:
>     runAsNonRoot: true
>     runAsUser: 65532                    # distroless nonroot UID
>     runAsGroup: 65532
>     fsGroup: 65532
>     seccompProfile:
>       type: RuntimeDefault              # veya Localhost + özel profil
>   containers:
>   - name: argus
>     securityContext:
>       allowPrivilegeEscalation: false
>       privileged: false
>       readOnlyRootFilesystem: true      # ← PSS'te YOK, elle ekleyin!
>       capabilities:
>         drop: ["ALL"]
>       # NET_BIND_SERVICE bile eklemeyin: >1024 port dinleyin, Service ile map edin
>     resources:
>       limits:
>         memory: "2Gi"                   # Argon2 OOM'una karşı sert tavan
>         cpu: "2"
>     volumeMounts:
>     - name: tmp
>       mountPath: /tmp                   # emptyDir, readOnlyRootFilesystem ile birlikte
>   volumes:
>   - name: tmp
>     emptyDir: { medium: Memory, sizeLimit: 64Mi }
> ```
> `readOnlyRootFilesystem: true`'yu **manuel ekleyin** — PSS sizi bu konuda zorlamayacak.

#### D.5 gVisor / Kata — güçlü izolasyon ve maliyeti

[gvisor.dev/docs/architecture_guide/performance/](https://gvisor.dev/docs/architecture_guide/performance/):
- İki maliyet sınıfı: **structural costs** (syscall interception, platform seçimine bağlı — ptrace *"the highest structural costs by far"*) ve **implementation costs**.
- **Ağ:** *"does not support all the advanced recovery mechanisms offered by other stacks and is less CPU efficient."*
- **Disk I/O:** *"the high overhead comes principally from the VFS implementation that needs improvement, with several internal serialization points."* Statik dosya sunumunda Apache benchmark'ları *"predictably poor results"*.
- **En kötü etkilenen:** syscall-bound uygulamalar (Redis, statik network servisleri, küçük işlemler). tmpfs sandbox-içi olduğu için ucuz. Bellek: *"a small, mostly fixed amount of memory overhead"* per container.
- **En az etkilenen:** CPU-bound ve I/O-bound iş yükleri.

> **Argus için:** Bir IdP **hem syscall-yoğun (her istek = socket I/O) hem CPU-yoğun (Argon2, imza)**. gVisor'un ağ stack'i darboğaz olur. **Önerim: gVisor'u varsayılan yapmayın.** Bunun yerine:
> - Multi-tenant/hostile ortamdaysanız veya "en güvenli" iddiasını mimari olarak desteklemek istiyorsanız: **Kata Containers** (donanım VM izolasyonu, ağ performansı gVisor'dan iyi, ama bellek overhead'i daha yüksek ve startup daha yavaş) tercih edin.
> - Ya da **dedicated node pool + node düzeyinde izolasyon** ile aynı güvenlik hedefine daha ucuz ulaşın.
> - gVisor'u yalnızca **privilege-separated signer sürecinin** kendisi için düşünün — o süreç düşük syscall hacimli ve yüksek değerli.

#### D.6 İmza + admission control

**sigstore policy-controller** ([docs.sigstore.dev/policy-controller/overview/](https://docs.sigstore.dev/policy-controller/overview/)):
- Kubernetes admission controller; imza ve attestation doğrular.
- *"can automatically validate signatures and attestations on container images as well as apply policies (using cue or rego) against attestations."*
- **Tag'i SHA256 digest'e resolve eder** → tag-switching saldırısını engeller. Bu tek başına büyük kazanç.
- `ClusterImagePolicy` CRD: image glob pattern'ları, authority'ler (key-based / **keyless (OIDC/Fulcio/Rekor)** / static), Cue veya Rego politikaları, namespace label ile opt-in/opt-out.
- Admission mantığı: image en az bir policy ile eşleşmeli; her eşleşen policy'de en az bir authority doğrulanmalı; **tüm eşleşen policy'ler geçmeli** (policy'ler arası AND, authority'ler arası OR).
- Durum uyarısı: *"This component is still actively under development!"*

> **Argus için:** Keyless (Fulcio/Rekor) imzalama + `ClusterImagePolicy` ile "yalnızca bizim GitHub Actions workflow'umuzun ürettiği imaj çalışır" kuralı. Bunu SLSA provenance attestation'ıyla birleştirin. Bu, "en güvenli IdP" iddiasının **supply chain ayağı** — ve doğrulanabilir olduğu için pazarlanabilir.

---

### E) UNSAFE CODE POLICY

#### E.1 `#![forbid(unsafe_code)]` — Argus için gerçekçi mi?

**Evet — ama workspace düzeyinde katmanlı olarak.**

**En güçlü emsal: rustls.** Güvenlik politikasından birebir ([github.com/rustls/rustls/blob/main/SECURITY.md](https://github.com/rustls/rustls/blob/main/SECURITY.md)):
> *"The entire crate which processes items on this trust boundary is `forbid(unsafe_code)`."*

Yani **dünyanın en çok kullanılan Rust TLS kütüphanesi, ağdan gelen veriyi işleyen tüm crate'inde unsafe'i tamamen yasaklamış.** Bu, bir IdP için ulaşılabilir bir çıta olduğunun kanıtıdır.

rustls ayrıca: OSS-Fuzz'a kayıtlı, mock crypto provider ile hem pre-auth hem post-auth kod yollarına fuzzing ulaşıyor. Tehdit modelinde açıkça: *"reachable loops with inappropriate and attacker-controlled complexity, with significant amplification"* — yani algoritmik karmaşıklık DoS'u **güvenlik açığı sayıyorlar**. Integer overflow'lar için: *"generally reduce[s] their impact to denial-of-service"*.

**Ne unsafe'i zorunlu kılar:**
| İhtiyaç | unsafe gerektirir mi? | Alternatif |
|---|---|---|
| PKCS#11 FFI (HSM) | **Evet** | İzole crate'e hapset (`argus-pkcs11`) |
| `mlock`/`memzero` | **Evet** | `memsec` (0.7.0, 2024-06-06) veya `zeroize` kullanın — kendi yazmayın |
| `memfd_secret` | **Evet** | `memsec::alloc_memfd_secret` (Linux-özel) |
| seccomp yükleme | Genelde hayır | `seccompiler` API'si safe |
| Landlock | Hayır | `landlock` crate'i safe abstraction |
| capability drop | Hayır | `caps` safe API |
| SIMD | Genelde hayır | `std::simd` (nightly) veya `wide`/`safe_arch` crate'leri |

**`memsec` 0.7.0** (2024-06-06, ~177k indirme/ay, 224 crate) ([lib.rs/crates/memsec](https://lib.rs/crates/memsec)): libsodium/utils'in Rust implementasyonu — `memeq`/`memcmp` (sabit zamanlı), `memzero`, `mlock`/`munlock`, `alloc`/`free`/`mprotect` (guard page'li allocation), ve **Linux'ta `alloc_memfd_secret`/`free_memfd_secret`** (kernel `memfd_secret` destekli — bellek kernel'dan bile gizli).

> **Argus workspace mimarisi önerisi:**
> ```
> argus/
> ├── argus-core/        #![forbid(unsafe_code)]  ← iş mantığı, politika
> ├── argus-proto/       #![forbid(unsafe_code)]  ← OIDC/OAuth2/SCIM tipleri
> ├── argus-parse/       #![forbid(unsafe_code)]  ← TÜM parser'lar (kritik!)
> ├── argus-http/        #![forbid(unsafe_code)]  ← axum handler'ları
> ├── argus-store/       #![forbid(unsafe_code)]  ← DB katmanı
> ├── argus-sandbox/     #![deny(unsafe_code)] + izinli istisnalar  ← seccomp/landlock/prctl
> └── argus-hsm/         unsafe İZİNLİ, ama her blok SAFETY: yorumlu + Miri/ASan testli
> ```
> CI kuralı: `argus-sandbox` ve `argus-hsm` dışındaki hiçbir crate'te `unsafe` kelimesi geçemez (grep + `cargo-geiger --forbid-only`). Bu iki crate toplamda **500 satırın altında** kalmalı ve ayrı güvenlik incelemesinden geçmeli.

#### E.2 `cargo-geiger` — 2026 olgunluk durumu (SORULAN SORU)

**Bakımda, ama sınırlı.** ([lib.rs/crates/cargo-geiger](https://lib.rs/crates/cargo-geiger))
- **Son sürüm 0.13.0, 2025-08-31.** ~19,117 indirme/ay. Cargo plugin'leri arasında #235.
- Yeni `--forbid-only` tarama modu: rustc çağrısı gerektirmez, yalnızca entry-point `.rs` dosyalarını parse eder → **çok hızlı**, ama yalnızca `#![forbid(unsafe_code)]` beyanını kontrol eder.
- Düzeltme: unsafe fonksiyon içindeki ve iç içe unsafe scope'lardaki tüm ifadeler artık sayılıyor ([issue #71](https://github.com/rust-secure-code/cargo-geiger/issues/71)).

**Sınırlamalar (dokümanın kendi ifadesi):**
> *"not meant to advise directly whether the code ultimately is truly insecure or not"* — istatistiksel girdi sağlar, denetim yerine geçmez. *"a quick and dirty investigation tool"*, *"partial information is better than no information"*.

Ek pratik sorunlar:
- **Makroların içini göremez** — `macro_rules!` veya proc-macro tarafından üretilen unsafe sayılmaz. Modern Rust'ta bu büyük bir kör nokta.
- **Build sorunları:** bir GitHub issue'da v0.13.0'ın *"crashes on complex workspaces — abort trap on unresolved packages"* olduğu raporlanmış ([terrylica/cc-skills#46](https://github.com/terrylica/cc-skills/issues/46)). Büyük workspace'lerde çalışmayabilir.
- **Unsafe ifadeleri sayar, kalitesini yargılamaz.** 1000 satır iyi denetlenmiş SIMD unsafe'i, 3 satır kötü FFI unsafe'inden daha güvenli olabilir.

> **Argus için:** `cargo-geiger`'ı **metrik olarak değil, gate olarak** kullanın: `cargo geiger --forbid-only` ile kendi crate'lerinizin `forbid(unsafe_code)` beyanını CI'da doğrulayın. Bağımlılık ağacındaki toplam unsafe sayısını bir KPI yapmayın — yanıltıcıdır.

#### E.3 Alternatifler

**`cackle` / `cargo-acl`** ([lib.rs/crates/cackle](https://lib.rs/crates/cackle), [github.com/davidlattimore/cackle](https://github.com/davidlattimore/cackle)):
- David Lattimore'un aracı. Transitive bağımlılıkların **hangi API'leri kullandığını** analiz eder. Örnek: bir veri işleme kütüphanesinin gizlice ağ API'lerine eriştiğini yakalar. `cackle.toml` ile crate başına izin beyanı, `cackle ui` ile interaktif kurulum.
- **⚠️ Son sürüm 0.2.0, 2023-09-07.** 285 yıldız, 638 commit. **Yaklaşık 3 yıldır release yok — fiilen durgun.** (Not: yazar o dönemden beri *Wild* linker projesine odaklandı — **bu bağlantıyı doğrulayamadım [DOĞRULANMADI]**, ama release boşluğu gerçek.)
- Sınırlamalar (kendi dokümanından): yalnızca Linux; proc-macro'lar Cackle altında çalıştıklarını **algılayıp farklı kod üretebilir**; crate analizi keyfi kod çalıştırabilir (bubblewrap sandbox'ı öneriliyor); *"Determined developers can likely circumvent detection"*; *"should not replace any manual code reviews"*.

> **Argus için:** Fikir mükemmel, **ama durgun bir araca güvenlik zinciri kurmayın.** Aynı garantiyi **Landlock + seccomp ile runtime'da** elde edin — bir bağımlılık gizlice ağa çıkmaya kalkarsa syscall filtresi durdurur. Bu, statik analizden daha güvenilir çünkü atlatılamaz.

**`cargo-vet`** (Mozilla) ([mozilla.github.io/cargo-vet/](https://mozilla.github.io/cargo-vet/)):
- Üçüncü parti bağımlılıkların **güvenilir denetimlerden geçtiğini** doğrular.
- Üç strateji: **sharing** (organizasyonlar denetim setlerini paylaşır — Mozilla, Google, Embark import edilebilir), **relative audits** (sürümler arası fark denetimi), **deferred audits** (istisna listesiyle kademeli benimseme).
- Kriter sistemi: `safe-to-deploy` / `safe-to-run`. Trusted publishers desteği.
- *"under active development"*.

> **Argus için: EN İYİ SEÇENEK.** `cargo-geiger`'dan daha anlamlı, `cackle`'dan daha canlı. Mozilla+Google denetim setlerini import ederek büyük bir kısmı bedava kapatırsınız, kalan istisnaları `exemptions` olarak listeleyip zamanla azaltırsınız. CI'da `cargo vet check` hard gate olsun.

**`cargo-crev`, `cargo-supply-chain`, `cargo-audit`, `cargo-deny`** — tamamlayıcı. `cargo-deny` ile lisans + duplicate + RUSTSEC advisory'lerini tek yerde gate'leyin.

#### E.4 Rust web stack'inde ne kadar unsafe var?

**Doğrulanmış tek veri noktası:** rustls, ağ verisi işleyen crate'inde `forbid(unsafe_code)` (yukarıda alıntılandı).

**`rasn`** (ASN.1) ([docs.rs/rasn](https://docs.rs/rasn/latest/rasn/)) birebir: *"The encoder and decoder have been written in 100% safe Rust and fuzzed with American Fuzzy Lop Plus Plus to ensure that the decoder correctly handles random input."* Ayrıca tamamen `#[no_std]` (alloc ile).

**tokio, hyper, h2, ring/aws-lc-rs için sayısal ölçüm bulamadım [DOĞRULANMADI].** Sorunuzda "yayımlanmış ölçümler" istendi — güvenilir, tarihli bir kaynak bulamadım. Genel bilinen: tokio ve hyper unsafe içerir (I/O primitive'leri, intrusive linked list'ler, `Bytes`), `ring` ve `aws-lc-rs` **C ve assembly** içerir (BoringSSL türevi) — bunlar `forbid(unsafe_code)` iddiasını crate düzeyinde imkânsız kılar.

> **Argus için:** Bu sayıyı kendiniz üretin ve **yayımlayın** — "en güvenli IdP" iddiasının somut kanıtı olur:
> ```bash
> cargo geiger --output-format GitHubMarkdown > docs/unsafe-report.md
> ```
> Ama yorumlayın: "toplam N unsafe ifadesi, bunların %X'i rustls/ring kripto katmanında, %Y'si tokio I/O'da, Argus'un kendi kodunda **0**."

#### E.5 Miri

[github.com/rust-lang/miri](https://github.com/rust-lang/miri) — tespit ettikleri: memory safety (OOB, UAF), uninitialized data, intrinsic precondition ihlalleri, alignment/type invariant ihlalleri, **data race'ler**, aliasing ihlalleri (Stacked/Tree Borrows), memory leak'ler.

**Sınırlamalar (birebir alıntılar):**
- FFI: *"experimental FFI support via `-Zmiri-native-lib`"* — ama yalnızca integer/pointer argümanlarla sınırlı ve *"stops tracking details such as initialization and provenance on memory shared with native code."*
- *"Miri runs the program as a platform-independent interpreter, so the program has no access to most platform-specific APIs or FFI."*
- **Ağ:** *"Miri currently does not support networking"*.
- **Tokio:** temel threading destekleniyor ama *"cannot run frameworks like Tokio"*.
- Determinizm: *"Miri tests one of many possible executions of your program, but it will miss bugs that only occur in a different possible execution."*
- Hız: interpreter olduğu için çok yavaş (tipik 50-500x).

> **Argus için:** Miri'yi **tüm test suite'ine değil**, `argus-hsm` ve `argus-sandbox` crate'lerinin **saf, I/O'suz unit testlerine** uygulayın. `cargo +nightly miri test -p argus-hsm --lib`. Bu, unsafe'in doğru olduğuna dair en güçlü otomatik kanıttır — ama FFI sınırından öteye geçemez, dolayısıyla PKCS#11 çağrılarını mock'layın.

---

### F) PARSER HARDENING — **EN KRİTİK BÖLÜM**

#### F.1 Rust'ta stack overflow'da tam olarak ne olur

Bu, Argus'un tehdit modelinin merkezinde durmalı. **Rust, stack overflow'u yakalanabilir bir hataya dönüştürmez.**

Mekanizma ([rust-lang/rust#31273](https://github.com/rust-lang/rust/issues/31273), [#43052](https://github.com/rust-lang/rust/issues/43052), [#69533](https://github.com/rust-lang/rust/issues/69533)):
1. Rust runtime'ı **her thread için** (main dahil) kendi userspace "stack guard"ını kurar.
2. Bir `SIGSEGV` handler'ı kurulur, **`sigaltstack` üzerinde** (varsayılan `SIGSTKSZ` boyutunda) — çünkü stack zaten dolmuşken normal stack'te handler çalıştırılamaz.
3. Handler, fault adresinin guard page aralığında olup olmadığına bakar. Unix hedeflerde guard bölgesi bir `Range<usize>` olarak raporlanır: *"Any fault therein will be called a stack overflow."*
4. Guard page'de fault ise: **"thread ... has overflowed its stack" mesajı basılır ve `abort()` çağrılır** — SIGSEGV yeniden raise edilmez.

**Kritik sonuçlar:**
- **`catch_unwind` bunu yakalayamaz** — bu bir panic değil, doğrudan abort'tur.
- **Bir tokio worker thread'inde olsa bile TÜM SÜREÇ ölür.** `abort()` süreç geneli.
- Main thread'in guard'ı `pthread_getattr_np` üzerinden hesaplanır ve bu POSIX'te tanımlı değil → bazı platform/page-size kombinasyonlarında hatalı davranabilir ([#43052](https://github.com/rust-lang/rust/issues/43052): 64KB page-size'lı Linux'ta neredeyse tüm Rust programlarını bozuyordu).

> **Yani: özyinelemeli bir parser'da derinlik sınırı yoksa, kimliği doğrulanmamış bir istekle tüm IdP'nizi kapatabilirim.** Bu, Rust'ın bellek güvenliğinin sizi korumadığı bir sınıftır ve `#![forbid(unsafe_code)]` hiçbir işe yaramaz.

#### F.2 Kanidm 2026 advisory'leri — **DOĞRULANDI, GERÇEK**

Sorunuzda bunları doğrulamam istendi. **İkisi de gerçek.**

##### (1) SCIM filter stack exhaustion — GHSA-r5fr-9gmv-jggh

- **GHSA:** `GHSA-r5fr-9gmv-jggh` — yayın **2026-05-06** ([advisories.gitlab.com/cargo/scim_proto/GHSA-r5fr-9gmv-jggh/](https://advisories.gitlab.com/cargo/scim_proto/GHSA-r5fr-9gmv-jggh/))
- **CVE:** CVE-2026-46689, **CVSS 8.7 HIGH** (GHSA sayfasında 7.5 HIGH olarak da geçiyor — iki farklı skorlama)
- **Etkilenen:** `scim_proto` ve `kanidm_proto`, < 1.9.3. **Düzeltilen:** 1.9.3+
- **CWE:** CWE-248 (Uncaught Exception), CWE-400 (Uncontrolled Resource Consumption), **CWE-674 (Uncontrolled Recursion)**
- **Açıklama (birebir):** *"a `?filter=` query string of a few thousand nested parentheses (≈ 4–12 KB) drives the recursive-descent PEG parser past the worker thread's stack guard page."* Sonuç: *"Rust responds to stack overflow with `std::process::abort()` — the entire kanidmd process exits."*
- **En can alıcı detay:** *"The parse runs inside axum's `Query<ScimEntryGetQuery>` extractor, before any handler body and therefore before any ACL check."*

**Bunun Argus için üç dersi:**
1. **4-12 KB'lık bir GET query string ile tüm süreç ölüyor.** Body limit'iniz 2 MB olsun ya da olmasın — bu bir *query string*, extractor'da parse ediliyor.
2. **Axum extractor'ları handler'dan ÖNCE, dolayısıyla auth/ACL middleware'inizden sonra ama iş mantığından önce çalışır.** Eğer `FromRequestParts` implementasyonunuzda parse yapıyorsanız, o parse **kimliği doğrulanmamış** girdiyi işliyor olabilir. Argus'ta **her custom extractor'ı ayrı bir tehdit yüzeyi olarak** ele alın.
3. **PEG parser (pest, peg crate) varsayılan olarak özyinelemelidir ve derinlik sınırı yoktur.** Grammar'ınız `expr = "(" expr ")"` içeriyorsa güvenlik açığınız var demektir.

##### (2) LDAP filter stack exhaustion — GHSA-qcxq-75wr-5cm8

- **GHSA:** `GHSA-qcxq-75wr-5cm8` — yayın **2026-04-30** ([github.com/kanidm/ldap3/security/advisories/GHSA-qcxq-75wr-5cm8](https://github.com/kanidm/ldap3/security/advisories/GHSA-qcxq-75wr-5cm8))
- **CVE:** atanmamış. **CVSS v4.0: 8.7 HIGH** — availability'ye tam etki, auth/UI/privilege gerektirmez, network üzerinden.
- **Etkilenen:** `ldap3_proto` < 0.7.0 → **düzeltilen 0.7.1**
- **CWE-674** (Uncontrolled Recursion). Credit: mbarbero.
- **Açıklama (birebir):** *"LDAP queries are not validated for depth, which can cause the parser (**both PEG and ASN**) to exhaust the stack."*

**Kritik nokta: hem PEG (string filter) hem ASN.1/BER (wire format) parser'ı etkilenmiş.** Yani sorun tek bir kütüphanede değil, **özyinelemeli parse eden her katmanda**.

##### Kanidm v1.9.3 release notları

[github.com/kanidm/kanidm/releases/tag/v1.9.3](https://github.com/kanidm/kanidm/releases/tag/v1.9.3) — **yayın 2026-04-30**, toplam **6 güvenlik sorunu** (2 High, 1 Moderate, 3 Low):
- *"SCIM Filters did not contain a bound on their parsing depth allowing stack exhaustion to occur leading to Denial of Service by an unauthenticated user"*
- *"LDAP Filters did not contain a bound on their parsing depth allowing stack exhaustion to occur leading to Denial of Service by an unauthenticated user"*
- Diğerleri: PNG image validation, passkey enrollment'ta HTML injection, OAuth2 client secret timing karşılaştırması, WebAuthn origin doğrulama.
- *"no evidence that these are in active exploitation or that user privacy or data was compromised."*

**Fix:** parse derinliğine sınır eklenmesi (explicit depth bound).

> **Argus'un konumu:** Kanidm, Rust'la yazılmış, güvenlik odaklı, olgun bir IdP — ve 2026'da bu sınıftan **iki High severity açık** aldı. Argus "en güvenli" olacaksa, bu **doğrudan rakip analizinden çıkan somut gereksinimdir**: her parser derinlik-sınırlı olmalı ve bu bir test suite ile kanıtlanmalı.

#### F.3 Aynı sınıftan diğer 2026 RUSTSEC advisory'leri (desen kanıtı)

| ID | Crate | Detay |
|---|---|---|
| **RUSTSEC-2026-0009** | `time` | CVE-2026-25727, **CVSS 6.8**. RFC 2822 parse'ında stack exhaustion. Etkilenen 0.3.6–0.3.46, **düzeltilen 0.3.47**. `Date::parse`, `Time::parse`, `OffsetDateTime::parse`, `UtcOffset::parse` etkilenmiş. Fix: *"a limit to the depth of recursion"*. Alternatif mitigasyon: girdi uzunluğunu sınırlamak (stack tüketimi girdi boyutuyla orantılı). ([rustsec.org/advisories/RUSTSEC-2026-0009.html](https://rustsec.org/advisories/RUSTSEC-2026-0009.html)) — **Cloudflare Pingora bile bundan etkilendi** ([cloudflare/pingora#807](https://github.com/cloudflare/pingora/issues/807)) |
| **RUSTSEC-2026-0195** | `quick-xml` | `NsReader`'da namespace bildirimi bellek tüketimi. *"a start tag with `N` namespace declarations drove roughly `3×` the tag's byte size in `NamespaceResolver` heap, allocated **inside** quick-xml"* → yani **caller'ın input size limit'i bunu kapsamıyor**. **Gerçek etki: NLnet Labs Routinator (RPKI validator) OOM-kill oldu.** Düzeltme **0.41.0**: element başına varsayılan **256 namespace bildirimi** sınırı, `NamespaceError::TooManyDeclarations`, ayarlanabilir `NamespaceResolver::set_max_declarations_per_element()`. **Düz `Reader` etkilenmiyor** (namespace resolution yapmıyor). ([rustsec.org/advisories/RUSTSEC-2026-0195.html](https://rustsec.org/advisories/RUSTSEC-2026-0195.html)) |
| **RUSTSEC-2026-0187** | `lopdf` | Derin iç içe PDF nesneleriyle stack overflow |
| **RUSTSEC-2024-0437** | `protobuf` | CVE-2025-53605, GHSA-2gh3-rmm4-6rq5. `CodedInputStream::skip_group`'ta kontrolsüz özyineleme — **bilinmeyen alanları parse ederken**. ≤3.4.0 etkilenmiş, **3.7.2**'de düzeltildi. Rapor 2024-12-12, yayın 2025-03-07. ([rustsec.org/advisories/RUSTSEC-2024-0437.html](https://rustsec.org/advisories/RUSTSEC-2024-0437.html)) |
| **RUSTSEC-2026-0185** | `quinn-proto` | Sırasız stream reassembly'de sınırsız bellek tüketimi — HTTP/3 kullanırsanız ilgili |

> **Desen:** 2026'da Rust ekosisteminde bu, **en yaygın açık sınıfı**. `quick-xml` örneği ayrıca **"input size limit'i koydum, güvendeyim" varsayımının yanlış olduğunu** gösteriyor — amplifikasyon parser'ın *içinde* oluyor.

#### F.4 Savunma teknikleri — Argus için reçete

##### (a) Explicit depth counter — **BİRİNCİL SAVUNMA**

Her özyinelemeli parse fonksiyonuna bir `depth: u32` parametresi ve giriş kontrolü. Kanidm'in ve `time` crate'inin uyguladığı fix budur.

```rust
const MAX_FILTER_DEPTH: u32 = 32;   // OIDC/SCIM için 32 fazlasıyla yeterli

fn parse_expr(input: &str, depth: u32) -> Result<Expr, ParseError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(ParseError::TooDeep);   // panic DEĞİL, Result
    }
    // ... parse_expr(inner, depth + 1)
}
```

**Maliyet:** ~sıfır. **Fayda:** tüm sınıfı kapatır. **Argus'ta bu, negotiable değil.**

##### (b) Recursion → iterative (explicit heap stack)

En güçlü ama en pahalı çözüm: özyinelemeyi bir `Vec<Frame>` üzerinde açık döngüye çevirmek. Stack tükenmez, yalnızca heap büyür — ve heap `cap` crate'i (aşağıda) veya cgroup limit'i ile sınırlanabilir.

> **Argus için:** Yalnızca **en sıcak, en düşmanca yüzeyde** yapın: SCIM filter parser'ı ve LDAP filter parser'ı. Diğerlerinde (a) yeterli.

##### (c) `stacker` — stack'i talep üzerine büyüt

[lib.rs/crates/stacker](https://lib.rs/crates/stacker) — **0.1.25, 2026-08-02**. Sahipler: **The Rust Programming Language** org + Simonas Kazlauskas (Alex Crichton + 38 katkıcı). **8.7M indirme/ay, 3,503 crate kullanıyor** — rustc'nin kendisi kullanıyor. `psm` crate'i üzerinden çalışır, Windows'ta Fiber tabanlı.

> **⚠️ Kritik caveat:** *"On unsupported platforms, it operates as a no-op—code compiles but won't actually prevent stack overflow."* → **Sessiz başarısızlık.** Argus'ta hedef platformunuzda gerçekten çalıştığını test edin.
>
> **Ayrıca:** `stacker` derinliği *sınırsız* yapar → stack overflow yerine **bellek tükenmesi** alırsınız. DoS'u ortadan kaldırmaz, sadece şeklini değiştirir. **Depth counter'ın yerine geçmez, yanına gelir.**

##### (d) `serde_json` recursion limit — **DOĞRULANDI: varsayılan 128**

[serde-rs/json src/de.rs](https://github.com/serde-rs/json/blob/master/src/de.rs) — `Deserializer::new` `remaining_depth`'i **128** ile başlatır.

- Bu koruma **varsayılan olarak açıktır** ve *"protect from malicious clients sending a deeply recursive structure and DOS-ing a server"* için tasarlanmıştır.
- `disable_recursion_limit()` yalnızca **`unbounded_depth` feature'ı** açıkken vardır. Dokümanın kendi uyarısı: bu feature kullanılırsa *"you will want to provide some other way to protect against stack overflows, such as by wrapping your Deserializer in the dynamically growing stack adapter provided by the `serde_stacker` crate."*

> **Argus için:** `unbounded_depth` feature'ının **hiçbir bağımlılık tarafından açılmadığını** doğrulayın — Cargo feature unification yüzünden bir transitive bağımlılık bunu açarsa **tüm build'de** korumanız kalkar. `cargo tree -f "{p} {f}"` ile kontrol edin ve CI'da assert edin. **Bu sinsi bir tuzaktır.**
>
> Ayrıca 128 bile bir IdP için fazla: OIDC/JWT/SCIM payload'ları 8-16 derinliği aşmamalı. **Kendi `Deserializer`'ınızı kurup daha sıkı bir sınır koyamazsınız** (API dışa açık değil) — bunun yerine deserialize *sonrası* bir derinlik doğrulaması veya şema doğrulaması (JSON Schema) ekleyin.

**`serde_stacker` 0.1.14 (2025-09-15)**, dtolnay, ~604k indirme/ay ([lib.rs/crates/serde_stacker](https://lib.rs/crates/serde_stacker)): `disable_recursion_limit()` çağırıp sonra deserializer'ı sarmalayın. **Argus için önermiyorum** — sınırsız derinlik bir IdP'de asla meşru değildir.

##### (e) XML — SAML'in mayın tarlası

**`quick-xml` davranışı** ([docs.rs/quick-xml Event enum](https://docs.rs/quick-xml/latest/quick_xml/events/enum.Event.html)):
- `Event::DocType` variant'ı var: *"Document type definition data (DTD) stored in `<!DOCTYPE ...>`"* — DTD **event olarak sunuluyor**, işlenmiyor.
- `Event::GeneralRef` variant'ı: *"General reference `&entity;` in the textual data. Can be either an entity reference, or a character reference."* — **entity'ler otomatik genişletilmiyor**, ayrı event olarak veriliyor.

> **Bunun anlamı: quick-xml yapısal olarak billion laughs ve XXE'ye karşı bağışıktır — ÇÜNKÜ entity genişletmesini hiç yapmaz.** Tehlike, uygulamanın kendi entity resolution'ını yazmasıdır.
>
> **Argus kuralı:** SAML/XML işleyen kodda `Event::GeneralRef` gördüğünüzde **yalnızca 5 built-in entity'yi** (`&lt; &gt; &amp; &quot; &apos;`) ve sayısal karakter referanslarını (sınırlı aralıkta) çözün. **`Event::DocType` gördüğünüzde belgeyi REDDEDIN.** Bu tek kural XXE ve billion laughs'ı kapatır.
>
> **Ama:** RUSTSEC-2026-0195 gösteriyor ki quick-xml'in kendi içinde de amplifikasyon olabilir → **0.41.0+ kullanın** ve `NsReader` kullanıyorsanız `set_max_declarations_per_element()`'i 256'dan da düşürün (SAML için 32 fazlasıyla yeterli).

**SAML Rust ekosistemi — durum raporu (crates.io API, 2026-09-08):**

| Crate | Sürüm | Güncelleme | İndirme | Not |
|---|---|---|---|---|
| **`gamlastan`** | 0.9.0 | 2026-09-03 | 15,408 | **Kushal Das** (tanınmış güvenlik geliştiricisi). "SAML 2.0 library - types, XML, crypto, metadata, bindings, security, profiles" |
| `saml-rs` | 0.5.0 | 2026-08-13 | 9,637 | 2026-06-14'te oluşturulmuş |
| `opensaml` / `samlify` / `samlet` / `rustsaml` / `rust-saml` / `open-saml` | 0.5.0 / 0.1.4 | 2026-06..08 | 112–6,793 | **"Maintained compatibility re-export of saml-rs"** — hepsi aynı crate'in yeniden export'u |
| `rustauth-saml`, `openauth-saml`, `nornir-auth-saml`, `rvoip-saml` | çeşitli | 2026 | 35–911 | Küçük, yeni |
| `saml` | 0.0.1-alpha.2 | 2026-08-08 | 995 | "Stateless, async-native SAML 2.0 toolkit with no libxml2/xmlsec C build chain" |

> **🚩 SUPPLY CHAIN UYARISI:** `saml-rs`'in **6 farklı isimle re-export edildiği** bir küme var (`opensaml`, `samlify`, `samlet`, `rustsaml`, `rust-saml`, `open-saml`) — hepsi 2026'da oluşturulmuş, hepsi popüler diğer-dil kütüphanelerinin isimlerini taklit ediyor (`samlify` bir Node.js kütüphanesi, `opensaml` Shibboleth'in C++/Java kütüphanesi). **Bu klasik bir isim-squatting / tipo-squatting desenidir.** Argus'ta bu crate'lerin **hiçbirini** kullanmayın ve `cargo-deny`'de `bans` bölümüne ekleyin.

**`gamlastan`** ([github.com/kushaldas/gamlastan](https://github.com/kushaldas/gamlastan)):
- **"35-check assertion validator"**, fail-closed tasarım.
- *"signature binding against XML Signature Wrapping, request correlation"* — XSW savunması açıkça belirtilmiş.
- SPID uyum iddiası kütüphanenin kendi beyanıdır ve **kanıt sayılmaz** — `italia/spid-saml-check` SP'leri test eder, IdP'leri değil. Sweden Connect ve SPID deployment profilleri var.
- XML için `uppsala` crate'i, kripto için `bergshamra` crate'i (aynı yazar). "zero-copy XML parsing".
- Hedef: *"the Rust equivalent of pysaml2 project"*. Rust 1.88+, 138 commit.

**`samlattacks.md`** dosyası, saldırı taksonomisi (Argus'un SAML test suite'i için doğrudan checklist):
| Saldırı | CVE |
|---|---|
| Golden SAML (SolarWinds/Solorigate) — ADFS'ten private key çalınması | — |
| **XML Signature Wrapping (XSW)** — orijinal imzayı korurken sahte assertion enjeksiyonu | — |
| SAMLResponse doğrulama eksikliği | CVE-2019-3731 |
| **XPath seçim hatası** imza doğrulamada | CVE-2024-45409 |
| **SAMLStorm** — DigestValue node'una comment injection | CVE-2025-29775 |
| Doğrulanmış kısım yerine imzasız assertion yüklenmesi | CVE-2025-54419 |
| **XXE** (xmlsec kullanımında) | CVE-2013-6440 |
| Geçersiz XML'den boş string üzerinden digest hesabı | CVE-2025-66578 |
| Yanlış XML node canonicalization | CVE-2017-11429 |
| **Comment/text node truncation** — doğrulama sırasında comment işleme | CVE-2017-11427, CVE-2017-11428 |
| XML tanım hatası | CVE-2018-0489 |

> **Argus için SAML kararı — açık sözlü olayım:**
>
> **SAML'i mümkünse hiç desteklemeyin.** XML-DSig + c14n + XSW, 20 yıldır çözülmemiş bir problem sınıfıdır ve "en güvenli IdP" hedefiyle temel bir gerilim içindedir. OIDC/OAuth2 + SCIM ile başlayın.
>
> **Zorundaysanız:**
> 1. **Kendi XML-DSig implementasyonunuzu yazmayın.** `gamlastan` en ciddi aday görünüyor (SPID conformance geçmiş, XSW savunması var, güvenilir yazar) — ama **0.9.0, 2026-06'da oluşturulmuş, henüz denetlenmemiş**. Bağımsız güvenlik denetimi yaptırmadan prod'a almayın.
> 2. **Mimari kural: "önce imzayı doğrula, SONRA parse et" değil — "canonicalize edilmiş baytları doğrula, ve YALNIZCA imzalanmış node'u işle".** XSW'nin kökeni, doğrulanan ağaç ile işlenen ağacın farklı olmasıdır. Argus, imza doğrulamasından **doğrulanan node'un kendisini** döndürmeli ve iş mantığı yalnızca ona dokunmalı — belgeyi yeniden XPath'lamak yasak olmalı.
> 3. **DOCTYPE içeren her belgeyi reddedin.** Entity genişletme yok.
> 4. SAML parse'ını **ayrı bir süreçte** çalıştırın (B.5).
> 5. Test suite'inize yukarıdaki CVE'lerin her biri için bir regresyon vektörü koyun.

##### (f) ASN.1/DER — ölçülmemiş risk

- **`der` 0.8.2** (RustCrypto): dokümanı *"The DER decoder in this crate performs checks to ensure that the input document is in canonical form"* diyor — **ama iç içe derinlik sınırı, özyineleme koruması veya DoS mitigasyonu belgelenmemiş.** `forbid(unsafe_code)` beyanı da dokümanda yok. ([docs.rs/der](https://docs.rs/der/latest/der/))
- **`rasn`**: 100% safe Rust, AFL++ ile fuzzlanmış, `#[no_std]` — **ama derinlik/özyineleme koruması hakkında hiçbir belge yok**, bağımsız denetim bilgisi yok. ([docs.rs/rasn](https://docs.rs/rasn/latest/rasn/))

> **[DOĞRULANMADI]:** Bu iki crate'in decoder'ının özyinelemeli olup olmadığını ve derinlik sınırı olup olmadığını doğrulayamadım. **Ama LDAP advisory'si (GHSA-qcxq-75wr-5cm8) açıkça "both PEG and ASN" parser'ının stack tükettiğini söylüyor** — yani bu risk gerçek.
>
> **Argus için zorunlu aksiyon:** X.509/PKCS#8/JWK-in-DER işleyen her yolda:
> 1. **Girdi boyutunu sert sınırlayın.** DER'de her iç içe seviye en az 2 bayt header tüketir → derinlik ≈ girdi_boyutu/2. **16 KB sertifika limiti → maksimum ~8000 derinlik → yine de stack overflow için yeterli.** Yani boyut limiti tek başına yetmez, ama 4 KB'a indirirseniz risk ciddi düşer.
> 2. **Kendi fuzz target'ınızı yazın:** `cargo-fuzz` ile `x509-cert::Certificate::from_der` üzerine derin iç içe DER besleyin ve **stack overflow'un gerçekleşip gerçekleşmediğini ölçün.** Bu, bu raporun size verdiği en somut test görevidir.
> 3. Sertifika parse'ını da izole süreçte yapmayı düşünün.

##### (g) CBOR — WebAuthn için kritik

**`ciborium` 0.2.2 (2026-08-29)** ([docs.rs/ciborium](https://docs.rs/ciborium/latest/ciborium/)): **derinlik sınırı belgelenmemiş [DOĞRULANMADI].**

> **Argus için:** WebAuthn/FIDO2 attestation object'leri CBOR'dur ve **kimliği doğrulanmamış kullanıcıdan gelir** (registration akışı). Bu, SCIM filter'la aynı risk profilinde. `ciborium` yerine **`minicbor`**'u değerlendirin (`minicbor` decoder'ında açık derinlik kontrolü olduğu bilinir — **ama bunu doğrulamadım [DOĞRULANMADI]**). Her hâlükârda: attestation object boyutunu sert sınırlayın (~8 KB) ve fuzz edin.

##### (h) Allocation limitleri

**Attacker-controlled length prefix problemi:** `Vec::with_capacity(n)` çağrısında `n` ağdan geliyorsa, tek bir 4 baytlık alan 4 GB allocation tetikler. Bu, binary protokollerde (LDAP BER, CBOR, protobuf) klasik bir açıktır.

**Savunmalar:**
1. **Asla ham length prefix ile `with_capacity` çağırmayın.** `min(n, MAX_REASONABLE)` veya hiç reserve etmeyip `Vec::new()` + incremental push kullanın (allocator zaten amortize eder).
2. **`bytes` crate'i** ile zero-copy dilimleme — kopya yok, allocation yok.
3. **Limited reader:** `std::io::Read::take(n)` ile stream'i sert kesin.

**`cap` crate 0.1.2 (2023-03-26)** ([lib.rs/crates/cap](https://lib.rs/crates/cap)) — ~77,580 indirme/ay, Alec Mocatta. Başka bir allocator'ı sarmalayıp bellek kullanımını izler ve tavan koyar:
```rust
#[global_allocator]
static ALLOCATOR: Cap<std::alloc::System> = Cap::new(std::alloc::System, usize::MAX);
ALLOCATOR.set_limit(30 * 1024 * 1024).unwrap();
```

> **Argus için değerlendirme:** `cap` çekici ama **iki problem var**: (1) 2023'ten beri güncellenmemiş, (2) global bir tavan aşıldığında allocation `null` döner → Rust'ta bu **`handle_alloc_error` → abort** demektir, yani yine süreç ölümü. **DoS'u önlemez, sadece OOM-killer yerine kendiniz ölürsünüz.**
>
> **Daha iyi yaklaşım:** Global tavan yerine **istek başına bütçe**. Her handler'ın işleyebileceği maksimum veri boyutunu tower layer'ında sınırlayın, ve **cgroup memory limit'i** (K8s `resources.limits.memory`) ile son savunma hattını kurun. `cap`'i yalnızca **gözlem** için (`ALLOCATOR.allocated()` metriği) kullanın — limit olarak değil.

#### F.5 Argus için parser hardening checklist

```
[ ] Her özyinelemeli parser'da explicit depth counter (MAX ≤ 32)
[ ] Derinlik aşımında Result::Err — asla panic, asla abort
[ ] Her parser için cargo-fuzz target'ı, CI'da nightly çalışan
[ ] Fuzz corpus'unda: 10k iç içe paren, 10k iç içe {}, 10k iç içe DER SEQUENCE
[ ] Bir integration test: 12 KB derin-iç-içe filter POST et → 400 dön, süreç YAŞASIN
[ ] serde_json unbounded_depth feature'ı hiçbir bağımlılıkta açık değil (CI assert)
[ ] quick-xml ≥ 0.41.0; DocType event → belgeyi reddet
[ ] Custom axum extractor'larının hepsi listelendi ve tehdit modellendi
[ ] Auth middleware, pahalı extractor'lardan ÖNCE çalışıyor (mümkünse)
[ ] Body/query/header boyut limitleri parser'a ULAŞMADAN uygulanıyor
[ ] x509/DER parse için boyut limiti ≤ 8 KB ve fuzz ile doğrulanmış
[ ] WebAuthn CBOR için boyut limiti ve derinlik kontrolü
```

---

### G) DOS SAVUNMASI

#### G.1 Boyut limitleri

**axum:** `DefaultBodyLimit` — **varsayılan 2 MB**, `Bytes`/`String`/`Json`/`Form` extractor'larını kapsar ([docs.rs/axum DefaultBodyLimit](https://docs.rs/axum/latest/axum/extract/struct.DefaultBodyLimit.html)). Güvenilmeyen kaynaklar için `DefaultBodyLimit::disable()` + `tower_http::limit::RequestBodyLimitLayer` ile farklı limit. axum 0.7'de `RequestBodyLimitLayer` düzeltildi: artık hangi middleware eklerseniz ekleyin `Request<Body>` extract edersiniz ([tokio.rs/blog/2023-11-27-announcing-axum-0-7-0](https://tokio.rs/blog/2023-11-27-announcing-axum-0-7-0)).

**hyper HTTP/1 Builder** ([docs.rs/hyper http1::Builder](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html)):
| Ayar | Varsayılan | Not |
|---|---|---|
| `max_buf_size` | **~400 KB** | Minimum 8192 |
| `max_headers` | **100** | Aşılırsa HTTP **431** döner |
| `header_read_timeout` | **30 sn** | ⚠️ **Timer gerektirir!** |
| `keep_alive` | `true` | |
| `half_close` | `false` | |

> ⚠️ **Slowloris tuzağı:** `header_read_timeout`'un çalışması için `Builder::timer()` ile bir Timer set edilmelidir. Doküman: *"calling `serve_connection` panics if a timeout is configured without a Timer"* — yani ya Timer verirsiniz ya panic alırsınız. **`hyper-util`'in `auto::Builder`'ını kullanıyorsanız `TokioTimer` set edildiğini doğrulayın**, yoksa slowloris'e açıksınız.

**hyper HTTP/2 Builder** ([docs.rs/hyper http2::Builder](https://docs.rs/hyper/latest/hyper/server/conn/http2/struct.Builder.html)):
| Ayar | Varsayılan |
|---|---|
| `max_concurrent_streams` | **200** ("not part of the stability of hyper") |
| `max_header_list_size` | **16 KB** |
| `max_send_buf_size` | **~400 KB** |
| `keep_alive_interval` | **disabled** |
| `keep_alive_timeout` | **20 sn** |
| `max_pending_accept_reset_streams` | **20** (h2 v0.4.0'dan itibaren) |
| `max_local_error_reset_streams` | **1024** |
| `initial_stream_window_size` / `initial_connection_window_size` / `max_frame_size` | "hyper will use a default" (belgelenmemiş) |

> **🚨 EN ÖNEMLİ UYARI (dokümanın kendi ifadesi):** *"default values of options are **not considered stable**. They are subject to change at any time."*
>
> **Argus için bu, tüm bu değerlerin AÇIKÇA set edilmesi gerektiği anlamına gelir.** Varsayılana güvenmek, bir hyper minor upgrade'inde sessizce DoS'a açılmak demektir. Bunu bir konfigürasyon struct'ında toplayın, değerleri log'layın, ve `/metrics`'te expose edin.

#### G.2 HTTP/2 saldırıları — 2026'da ne yapılmalı

**Rapid Reset (CVE-2023-44487)** — 2023 Ağustos-Ekim'de vahşi doğada exploit edildi. Saldırgan çok sayıda stream açıp her birini hemen `RST_STREAM` ile iptal eder → kaynak açlığı ([CISA alert, 2023-10-10](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487)).

**Rust ekosisteminde ilgili advisory'ler:**

| Advisory | Detay |
|---|---|
| **RUSTSEC-2023-0034** | *"If an attacker floods the network with pairs of HEADERS/RST_STREAM frames faster than the h2 application can accept them, the pending accept queue can grow in memory usage and eventually trigger Out Of Memory."* Fix: [hyperium/h2#668](https://github.com/hyperium/h2/pull/668) — remote reset stream sayısı varsayılan olarak sınırlandı. ([rustsec.org/advisories/RUSTSEC-2023-0034.html](https://rustsec.org/advisories/RUSTSEC-2023-0034.html)) |
| **RUSTSEC-2024-0003** | *"An attacker with an HTTP/2 connection can send a steady stream of invalid frames to force reset frame generation, and by closing their recv window, could force these resets to be queued unboundedly, resulting in Out Of Memory (OOM) and high CPU usage."* Fix: [hyperium/h2#737](https://github.com/hyperium/h2/pull/737) — internal error reset sayısına **varsayılan 1024** eşiği. ([rustsec.org/advisories/RUSTSEC-2024-0003](https://rustsec.org/advisories/RUSTSEC-2024-0003)) |

**CONTINUATION Flood** ([seanmonstar.com/blog/hyper-http2-continuation-flood/](https://seanmonstar.com/blog/hyper-http2-continuation-flood/), **2024-04-03**):
- Saldırı: sonsuz `CONTINUATION` frame'i gönderilir. hyper'da *"memory growth will cap"* (header limit'te) **ama sunucu frame'leri işlemeye devam eder → CPU tüketimi** → *"a degradation of service"*.
- **Düzeltme: h2 v0.4.4 ve v0.3.26.** `cargo update -p h2`.
- Düzeltmenin mantığı: sabit bir limit yerine, konfigüre edilmiş max frame size ve max header list size'a göre **meşru bir mesajın gerektirebileceği maksimum CONTINUATION frame sayısı hesaplanıyor** + padding.
- **CVE atanmadı**; RustSec advisory ile duyuruldu.
- **Kullanıcı sorumluluğu (birebir):** *"Users should set `SETTING_MAX_HEADER_LIST_SIZE` to a reasonable value for their use case. The library uses a high emergency default if unset."*

> **Argus için HTTP/2 konfigürasyonu (2026'da açıkça set edilmesi gerekenler):**
> ```rust
> builder
>     .max_concurrent_streams(100)                    // 200 fazla; IdP için 100 bol
>     .max_header_list_size(8 * 1024)                 // 16KB fazla; JWT header'ları için 8KB
>     .max_frame_size(16 * 1024)                      // minimum, açıkça
>     .initial_stream_window_size(64 * 1024)
>     .initial_connection_window_size(1024 * 1024)
>     .max_send_buf_size(256 * 1024)
>     .max_pending_accept_reset_streams(Some(20))
>     .max_local_error_reset_streams(Some(256))       // 1024 yerine daha sıkı
>     .keep_alive_interval(Some(Duration::from_secs(20)))
>     .keep_alive_timeout(Duration::from_secs(10))
>     .timer(TokioTimer::new())                       // ← ZORUNLU
> ```
> Ve HTTP/1 tarafında `header_read_timeout` + Timer. **HTTP/3 (quinn) eklerseniz RUSTSEC-2026-0185'e dikkat.**

#### G.3 Timeout, concurrency, load shedding

**tower 0.5.3** ([docs.rs/tower](https://docs.rs/tower/latest/tower/)):
- `timeout` — istek başına süre sınırı
- `limit::ConcurrencyLimit` — eşzamanlı istek sayısı
- `limit::RateLimit` — zaman içinde istek frekansı
- `load_shed` — *"Middleware for shedding load when inner services aren't ready"* → downstream hazır değilse **hemen reddet**, kuyruk büyütme
- `buffer` — *"Provides a buffered mpsc channel to a service"*
- `retry` — ⚠️ **retry, DoS'u AMPLIFY edebilir**; rate limit ile birlikte ve jitter'lı backoff ile kullanın

Feature flag'leri: `tower = { version = "0.5", features = ["timeout", "limit", "load_shed", "buffer"] }`.

> **Argus katman sırası (dıştan içe):**
> ```
> 1. ConnectionLimit (accept loop'ta semaphore — tower dışı, elle)
> 2. tower_governor (IP başına rate limit)  ← ucuz, erken
> 3. RequestBodyLimitLayer / DefaultBodyLimit
> 4. TimeoutLayer (toplam istek: 10 sn)
> 5. LoadShedLayer
> 6. ConcurrencyLimitLayer (global: ~2x çekirdek sayısı)
> 7. TraceLayer
> 8. Auth middleware
> 9. Handler
>    └─ Argon2 için AYRI semaphore (aşağıda)
> ```
> **Kural: pahalı olan her şey, ucuz olan her şeyin arkasında.** Kanidm CVE'sinin dersi tam olarak buydu — parse, ACL kontrolünden önce çalışıyordu.

#### G.4 Rate limiting

- **`governor` 0.10.4 (2026-09-05)** ([docs.rs/governor](https://docs.rs/governor/latest/governor/)) — GCRA (Generic Cell Rate Algorithm), yani leaky bucket'ın hassas varyantı. Keyed rate limiter (`DefaultKeyedRateLimiter`, `dashmap` ile). Async destekli (`RatelimitedSink`, `RatelimitedStream`). **Dağıtık senaryolar hakkında hiçbir rehberlik yok — tamamen in-process.**
- **`tower_governor` 0.8.0 (2025-08-14)** ([crates.io/crates/tower_governor](https://crates.io/api/v1/crates/tower_governor), [github.com/benwis/tower-governor](https://github.com/benwis/tower-governor)) — *"A rate-limiting middleware for Tower backed by the governor crate that allows configurable key based and global limits"*. Toplam 4,435,671 indirme, son dönem 1,654,323 → **iyi benimsenmiş**.

> **Argus için çok-instance rate limiting:**
> - **Yerel katman (governor):** her instance kendi in-memory limitini uygular. Ucuz, gecikmesiz, ve tek bir instance'ı korur. Limit = global_limit / instance_sayısı × güvenlik_payı.
> - **Global katman (Redis):** brute-force ve credential stuffing için **kesinlikle gerekli** — çünkü saldırgan load balancer'da farklı instance'lara dağılır. Redis'te `INCR` + `EXPIRE` veya sliding window script'i. Anahtar: hem `ip` hem `username` hem `ip+username` üçlüsü.
> - **⚠️ Proxy tuzağı:** `X-Forwarded-For`'a **asla körlemesine güvenmeyin**. Kaç proxy hop'u olduğunu konfigüre edin ve **sağdan sayarak** güvenilir IP'yi alın. Aksi halde saldırgan header enjekte ederek rate limit'i atlar VE meşru kullanıcıları bloklatır (limit poisoning).
> - Rate limit **fail-closed mi fail-open mi?** Redis düşerse: **login endpoint'i için fail-closed** (yerel governor devreye girer, sıkı limit), diğerleri için fail-open. Bunu bilinçli karar olarak dokümante edin.

#### G.5 Argon2 DoS — bellek × eşzamanlılık = OOM

Bu, bir IdP'ye özgü, **en çok gözden kaçan DoS vektörüdür.** Argon2 tanım gereği "memory-hard"dır. `m_cost = 64 MiB` ve 50 eşzamanlı login = **3.2 GB** anlık bellek → OOM-kill.

**`argon2` crate `Params`** ([docs.rs/argon2 Params](https://docs.rs/argon2/latest/argon2/struct.Params.html)):
- `DEFAULT_T_COST = 2`, `DEFAULT_P_COST = 1`, `DEFAULT_OUTPUT_LEN = 32`
- `MIN_T_COST = 1`, `MIN_P_COST = 1`, `MIN_OUTPUT_LEN = 4`
- `MAX_M_COST = u32::MAX`, `MAX_T_COST = u32::MAX`, `MAX_P_COST = 0xFFFFFF`, `MAX_OUTPUT_LEN = 0xFFFFFFFF`
- `m_cost` kısıtı: "memory size in 1 KiB blocks", `8*p_cost` ile `2^32-1` arasında.
- **`DEFAULT_M_COST`'un sayısal değerini doküman sayfasından çıkaramadım [DOĞRULANMADI]** — kodda doğrulayın.

**Gerçek dünya örneği — Rauthy** ([sebadob.github.io/rauthy/config/argon2.html](https://sebadob.github.io/rauthy/config/argon2.html), [github.com/sebadob/rauthy](https://github.com/sebadob/rauthy)):
- **`hashing.max_hash_threads`, varsayılan `2`.** Doküman: *"The application restricts parallel password hash operations to prevent exceeding system memory while maintaining adequate security margins."*
- Varsayılan 2 ile *"only one user login at the exact same time"* — küçük deployment'larda harici rate limiting'i gereksiz kılıyor.
- Admin UI'da `Config → Argon2 Parameters` altında bir tuning yardımcısı var: *"Allow as many resources as possible for hashing to have maximum security, while restricting it as necessary"*.
- Container ortamlarında bellek limitlerinin izlenmesi konusunda açık uyarı — yetersiz limit crash'e yol açar.
- Rauthy ayrıca: *"Login / Password hashing rate limiting"*, *"Brute-Force and Credential Stuffing detection"* + otomatik IP blacklisting, session peer IP binding, ed25519 token imzalama, DB içinde kritik alanların ek şifrelenmesi.
- **Bağımsız güvenlik denetimi: Radically Open Security, v0.32.1.** Güncel sürüm 0.36.2.
- **sudo-rs** de iki bağımsız denetim geçirmiş: 2023-08 (v0.2.0) ve **2025-08 (v0.2.8)** ([github.com/trifectatechfoundation/sudo-rs](https://github.com/trifectatechfoundation/sudo-rs)) — Rust güvenlik projelerinde denetim artık norm.

> **Argus için Argon2 mimarisi:**
> ```rust
> // Global, adil (fair) semaphore — bounded worker pool
> static HASH_PERMITS: Semaphore = Semaphore::const_new(N);
> // N = floor(available_memory_bytes * 0.5 / (m_cost_kib * 1024))
> // Örn: 2 GiB limit, m_cost = 64 MiB → N = floor(1024/64) = 16
>
> async fn verify_password(pw: &str, hash: &str) -> Result<bool> {
>     // 1. Semaphore'u ZAMAN AŞIMIYLA al — sonsuz kuyruk yok
>     let permit = timeout(Duration::from_millis(500), HASH_PERMITS.acquire())
>         .await
>         .map_err(|_| Error::Overloaded)?;   // → HTTP 503 + Retry-After
>
>     // 2. spawn_blocking — Argon2 CPU-bound, async worker'ı bloklamamalı
>     let r = tokio::task::spawn_blocking(move || argon2_verify(pw, hash)).await?;
>     drop(permit);
>     r
> }
> ```
> **Dört kritik nokta:**
> 1. **Semaphore boyutu bellek limitinden TÜRETİLMELİ**, elle sabit olmamalı. Container limit'ini `/sys/fs/cgroup/memory.max`'tan okuyun.
> 2. **`acquire()` timeout'lu olmalı.** Timeout'suz semaphore = sınırsız kuyruk = bellek DoS'unu latency DoS'una çevirmek.
> 3. **`spawn_blocking` zorunlu.** Argon2'yi async worker thread'inde çalıştırmak tüm runtime'ı dondurur. Ayrıca `tokio` blocking pool'unun kendi limitini (`max_blocking_threads`) semaphore ile uyumlu ayarlayın.
> 4. **Timing:** kullanıcı yoksa da hash hesaplayın (dummy hash) — yoksa user enumeration açığı. Ama bu, DoS bütçenizi ikiye katlar; semaphore hesabına dahil edin.
>
> **Ek:** Argon2'yi privilege-separated signer sürecine taşırsanız (B.5), bellek bütçesi tamamen ayrılır ve HTTP sürecinin OOM'u imkânsızlaşır.

#### G.6 ReDoS

**`regex` 1.13.1** ([docs.rs/regex](https://docs.rs/regex/latest/regex/)) — birebir:
> *"all regex searches in this crate have worst case `O(m * n)` time complexity, where `m` is proportional to the size of the regex and `n` is proportional to the size of the string being searched."*

**Doğrulandı: `regex` lineer zamanlıdır**, catastrophic backtracking yoktur. Backreference ve lookaround **desteklenmez** — çünkü *"lacks several features that are not known how to implement efficiently."*

**Ama bir uyarı var:** güvenilmeyen *pattern*'ler için (yani kullanıcı regex yazabiliyorsa) compile-time bellek patlaması mümkün: `a{5}{5}{5}{5}{5}{5}` gibi yığılmış tekrarlar. Doküman: *"limit the pattern length to something small and expand it as needed. Configure `RegexBuilder::size_limit` to something small and then expand it as needed."*

> **Argus için:**
> - **`regex` güvenli** — kullanmaya devam edin.
> - **`fancy-regex`, `onig`, `pcre2` gibi backtracking motorları ReDoS'a açıktır** ([bunu bu araştırmada doğrudan doğrulamadım — DOĞRULANMADI, ama fancy-regex'in lookaround/backreference desteği tanım gereği backtracking gerektirir]). `cargo-deny`'de bunları **bans** listesine ekleyin.
> - Eğer Argus'ta admin'ler regex yazabiliyorsa (örn. claim mapping, group matching kuralları): pattern uzunluğunu ≤256 karakter sınırlayın ve `RegexBuilder::size_limit(1MB)` set edin.

#### G.7 Slowloris ve TLS handshake DoS

- **Slowloris:** `header_read_timeout` (hyper HTTP/1, varsayılan 30 sn — **Timer set edilmişse!**) + connection limit + accept loop'ta semaphore. 30 sn hâlâ uzun; **5-10 sn'ye indirin.**
- **TLS handshake DoS:** Handshake, RSA/ECDHE ile CPU maliyetlidir. rustls'in tehdit modeli bunu kapsıyor: *"reachable loops with inappropriate and attacker-controlled complexity, with significant amplification"* ([rustls SECURITY.md](https://github.com/rustls/rustls/blob/main/SECURITY.md)).
  - **Savunma:** Accept'ten sonra, handshake'ten önce connection semaphore. Handshake'e ayrı bir timeout. IP başına eşzamanlı bağlantı sınırı.
  - **rustls'in modern özellikleri** ([rustls manual features](https://docs.rs/rustls/latest/rustls/manual/_04_features/index.html)): TLS 1.2/1.3, ECDHE forward secrecy, **X25519MLKEM768 post-quantum hybrid key exchange**, ECH (Encrypted Client Hello), OCSP stapling, session resumption. Renegotiation, SSL1/2/3, TLS1.0/1.1, RC4, DES, MAC-then-encrypt **desteklenmiyor** → bu iyi (renegotiation DoS vektörüdür).
  - **Crypto provider seçimi:** `rustls-aws-lc-rs` — *"excellent performance and a complete feature set (including post-quantum algorithms)"*, proje tarafından önerilen. `rustls-ring` daha kolay build ama sınırlı feature set. **Ama aws-lc-rs C/assembly içerir** → E bölümündeki unsafe politikanızı etkiler. ([github.com/rustls/rustls](https://github.com/rustls/rustls))
- **Session resumption dikkat:** resumption CPU'yu düşürür ama ticket key yönetimi ve replay riski getirir. TLS 1.3 0-RTT'yi **kapalı tutun** (replay).

---

### ÖZET: ARGUS İÇİN ÖNCELİKLENDİRİLMİŞ AKSİYON LİSTESİ

#### P0 — Yapılmazsa "en güvenli" iddiası geçersiz

| # | Aksiyon | Maliyet | Gerekçe |
|---|---|---|---|
| 1 | **Her özyinelemeli parser'a derinlik sınırı** (≤32) + fuzz target | 1 hafta | Kanidm GHSA-r5fr-9gmv-jggh & GHSA-qcxq-75wr-5cm8 (2026-04/05) — doğrudan rakip, aynı sorun |
| 2 | **`overflow-checks = true`** release profilinde | ~0 | Wraparound = IdP'de yetki mantığı hatası |
| 3 | **hyper HTTP/1+HTTP/2 tüm limitlerini açıkça set et** + `TokioTimer` | 1 gün | hyper: *"default values are not considered stable"* |
| 4 | **Argon2 bounded semaphore** (bellek limitinden türetilmiş) + timeout + `spawn_blocking` | 2 gün | Rauthy `max_hash_threads=2` emsali |
| 5 | **K8s: PSS restricted + `readOnlyRootFilesystem: true` (PSS'te YOK!) + `drop: ALL` + memory limit** | 1 gün | Doğrulandı: PSS restricted readOnlyRootFilesystem içermiyor |
| 6 | **`cargo-deny` + `cargo-vet` CI gate** (RUSTSEC + lisans + banned crates) | 2 gün | h2/quick-xml/time/protobuf advisory'leri |
| 7 | **`#![forbid(unsafe_code)]` tüm iş mantığı crate'lerinde** | 0 (baştan) | rustls emsali: trust boundary crate'i forbid ediyor |

#### P1 — Gerçek diferansiyasyon

| # | Aksiyon | Maliyet | Gerekçe |
|---|---|---|---|
| 8 | **Landlock** (ana thread'de, runtime'dan önce, `landlock` 0.4.7) | 2-3 gün | En yüksek fayda/maliyet oranı. **ABI ≥ 8 `all_threads()` best-effort'ta sessizce düşer — HardRequirement kullanın** |
| 9 | **seccomp-bpf** (`seccompiler` 0.5.0, iki fazlı: init → serve) | 1 hafta | Firecracker emsali |
| 10 | **capability drop + `no_new_privs` + `PR_SET_DUMPABLE=0`** (`caps` 0.5.6, `nix` prctl) | 1 gün | Doğru sırada: dumpable → bind → nnp → bounding → setgroups → setgid → setuid |
| 11 | **Privilege separation: `argus-signer` ayrı süreç** (ağ syscall'ları yasak) | 2-3 hafta | OpenSSH 9.8 sshd-session emsali; CVE-2023-38408'de privsep RCE'yi etkisizleştirdi |
| 12 | **glibc + distroless `cc:nonroot`** (musl seçilirse **mimalloc ZORUNLU**) | 1 gün | musl: 7x gerçek / ~700x sentetik yavaşlama, mallocng çözmedi |
| 13 | **sigstore keyless imzalama + policy-controller admission** | 3 gün | Tag→digest resolve tek başına büyük kazanç |
| 14 | **io_uring KULLANMA** kararını dokümante et | 0 | io_uring seccomp'u bypass eder; Docker zaten bloklar |

#### P2 — Değerlendirin

| # | Aksiyon | Not |
|---|---|---|
| 15 | Nightly CI: ASan + LSan + TSan (haftalık) | MSan'ı atlayın (build-std + C bağımlılıkları) |
| 16 | Miri: `argus-hsm` / `argus-sandbox` unit testleri | Ağ/tokio çalışmaz; FFI sınırlı |
| 17 | Bağımsız güvenlik denetimi | Rauthy (ROS) ve sudo-rs (2×) emsali; "en güvenli" iddiası için gerekli |
| 18 | CET/BTI ELF property note'unu `readelf -n` ile ölç | **[DOĞRULANMADI]** — rustc bunu emit ediyor mu bilinmiyor; ölçün ve raporlayın |
| 19 | SAML: mümkünse hiç desteklemeyin; zorundaysanız `gamlastan` + denetim + izole süreç | 6 kopya re-export crate'i var — supply chain riski |

#### ❌ Yapmayın

| Teknik | Neden |
|---|---|
| `-Zsanitizer=cfi` production'da | Nightly + LTO + build-std; Rust-only kodda marjinal; reproducible build'i bozar |
| `-Zstack-protector` | Hâlâ nightly (PR #146369 S-blocked, 2026-07-13); safe Rust'ta değeri sınırlı |
| `cackle` / `cargo-acl`'e güvenlik zinciri kurmak | Son release 2023-09-07; atlatılabilir; runtime seccomp/Landlock daha güvenilir |
| `unshare` crate | Son release 2021-05-04, bakımsız |
| `cap` crate'i **limit** olarak | Limit aşımı → `handle_alloc_error` → abort; DoS'u önlemez. Yalnızca metrik olarak kullanın |
| gVisor'u varsayılan runtime yapmak | IdP hem syscall- hem CPU-yoğun; gVisor'un ağ stack'i darboğaz |
| `serde_stacker` + `disable_recursion_limit` | Sınırsız derinlik bir IdP'de asla meşru değil |
| musl'ı varsayılan allocator'ıyla | 7x–700x yavaşlama |

---

### DOĞRULANAMAYAN / AÇIK KALAN NOKTALAR

Bunları Argus ekibinin kendi ölçmesi gerekiyor — **iddia etmeyin, ölçün:**

1. **rustc, x86-64'te `GNU_PROPERTY_X86_FEATURE_1_SHSTK`/`IBT` note'unu emit ediyor mu?** → `readelf -n target/release/argus`
2. **Android'in Rust bileşenlerinde LLVM CFI açık mı?** source.android.com CFI sayfası yalnızca C/C++'tan bahsediyor.
3. **`der` 0.8.2 ve `rasn` decoder'ları özyinelemeli mi, derinlik sınırı var mı?** → `cargo-fuzz` ile derin iç içe DER besleyerek ölçün.
4. **`ciborium` 0.2.2 derinlik sınırı var mı?** WebAuthn için kritik. `minicbor` alternatifinin derinlik kontrolü de doğrulanmadı.
5. **tokio/hyper/h2/ring için yayımlanmış unsafe ölçümü** bulunamadı — kendiniz `cargo geiger` ile üretin.
6. **`argon2` crate'inin `DEFAULT_M_COST` sayısal değeri** dokümandan çıkarılamadı.
7. **systemd / Docker / Firefox / sudo-rs'in Landlock kullandığı** doğrulanamadı — sorunuzda varsayılmıştı, kanıt bulamadım.
8. **Chainguard'ın FIPS variantları, Wolfi tabanı, fiyatlandırması** pazarlama sayfasından çıkarılamadı.
9. **`fancy-regex`'in ReDoS'a açık olduğu** doğrudan doğrulanmadı (tasarım gereği backtracking olduğu bilinir ama kaynakla teyit edilmedi).
10. **Cackle yazarının Wild linker'a geçtiği** doğrulanamadı — yalnızca release boşluğu gerçek.
11. **Tokio+epoll için tam syscall allowlist'i** literatürden derlenmiş genel bir çerçevedir; Argus'un gerçek seti `strace -f -c` ile ölçülmelidir.

---

### Kaynaklar

**Rust derleyici / hardening:** [rustc Exploit Mitigations](https://doc.rust-lang.org/rustc/exploit-mitigations.html) · [rust-lang/rust#146369](https://github.com/rust-lang/rust/pull/146369) · [rust-lang/rust#114903](https://github.com/rust-lang/rust/issues/114903) · [Unstable Book — sanitizer](https://doc.rust-lang.org/nightly/unstable-book/compiler-flags/sanitizer.html) · [Codegen Options](https://doc.rust-lang.org/rustc/codegen-options/index.html) · [Cargo Profiles](https://doc.rust-lang.org/cargo/reference/profiles.html) · [Rust Project Goals 2026 — Rust for Linux](https://goals.rust-lang.org/2026/rust-for-linux-compiler-features.html) · [Android CFI](https://source.android.com/docs/security/test/cfi) · [Linux x86 shadow stack](https://docs.kernel.org/arch/x86/shstk.html) · [rust-lang/rust#31273](https://github.com/rust-lang/rust/issues/31273) · [rust-lang/rust#43052](https://github.com/rust-lang/rust/issues/43052) · [rust-lang/rust#69533](https://github.com/rust-lang/rust/issues/69533)

**İzolasyon:** [seccompiler (lib.rs)](https://lib.rs/crates/seccompiler) · [rust-vmm/seccompiler](https://github.com/rust-vmm/seccompiler) · [Firecracker seccomp](https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md) · [extrasafe](https://lib.rs/crates/extrasafe) · [libseccomp-rs](https://github.com/libseccomp-rs/libseccomp-rs) · [io_uring & seccomp (2022-11-27)](https://blog.0x74696d.com/posts/iouring-and-seccomp/) · [caps](https://lib.rs/crates/caps) · [nix prctl](https://docs.rs/nix/latest/nix/sys/prctl/index.html) · [unshare](https://lib.rs/crates/unshare) · [OpenSSH 9.8 (2024-07-01)](https://www.openssh.org/txt/release-9.8) · [OpenSSH security](https://www.openssh.org/security.html)

**Landlock:** [landlock.io](https://landlock.io/) · [kernel userspace-api/landlock](https://docs.kernel.org/userspace-api/landlock.html) · [landlock(7)](https://man7.org/linux/man-pages/man7/landlock.7.html) · [docs.rs/landlock](https://docs.rs/landlock/latest/landlock/) · [ABI enum](https://docs.rs/landlock/latest/landlock/enum.ABI.html) · [rust-landlock](https://github.com/landlock-lsm/rust-landlock) · [island](https://github.com/landlock-lsm/island)

**Container:** [musl allocator harmful (2025-02-02)](https://nickb.dev/blog/default-musl-allocator-considered-harmful-to-performance/) · [andygrove musl (2020-05-05)](https://andygrove.io/2020/05/why-musl-extremely-slow/) · [distroless](https://github.com/GoogleContainerTools/distroless) · [cargo-chef](https://github.com/LukeMathWalker/cargo-chef) · [K8s PSS](https://kubernetes.io/docs/concepts/security/pod-security-standards/) · [PSS kaynak markdown](https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/concepts/security/pod-security-standards.md) · [gVisor performance](https://gvisor.dev/docs/architecture_guide/performance/) · [Docker seccomp](https://docs.docker.com/engine/security/seccomp/) · [sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/) · [Chainguard](https://www.chainguard.dev/chainguard-images)

**Unsafe / supply chain:** [cargo-geiger](https://lib.rs/crates/cargo-geiger) · [cargo-geiger CHANGELOG](https://github.com/geiger-rs/cargo-geiger/blob/master/CHANGELOG.md) · [cargo-geiger#71](https://github.com/rust-secure-code/cargo-geiger/issues/71) · [cackle](https://lib.rs/crates/cackle) · [davidlattimore/cackle](https://github.com/davidlattimore/cackle) · [cargo-vet](https://mozilla.github.io/cargo-vet/) · [Miri](https://github.com/rust-lang/miri) · [rustls SECURITY.md](https://github.com/rustls/rustls/blob/main/SECURITY.md) · [rustls](https://github.com/rustls/rustls) · [rustls features](https://docs.rs/rustls/latest/rustls/manual/_04_features/index.html) · [memsec](https://lib.rs/crates/memsec) · [sudo-rs](https://github.com/trifectatechfoundation/sudo-rs)

**Parser / advisory'ler:** [GHSA-r5fr-9gmv-jggh (2026-05-06)](https://advisories.gitlab.com/cargo/scim_proto/GHSA-r5fr-9gmv-jggh/) · [GHSA-qcxq-75wr-5cm8 (2026-04-30)](https://github.com/kanidm/ldap3/security/advisories/GHSA-qcxq-75wr-5cm8) · [Kanidm v1.9.3 (2026-04-30)](https://github.com/kanidm/kanidm/releases/tag/v1.9.3) · [RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009.html) · [RUSTSEC-2026-0195](https://rustsec.org/advisories/RUSTSEC-2026-0195.html) · [RUSTSEC-2024-0437](https://rustsec.org/advisories/RUSTSEC-2024-0437.html) · [RustSec advisories](https://rustsec.org/advisories/) · [cloudflare/pingora#807](https://github.com/cloudflare/pingora/issues/807) · [serde_json de.rs](https://github.com/serde-rs/json/blob/master/src/de.rs) · [serde_stacker](https://lib.rs/crates/serde_stacker) · [stacker](https://lib.rs/crates/stacker) · [quick-xml Event](https://docs.rs/quick-xml/latest/quick_xml/events/enum.Event.html) · [gamlastan](https://github.com/kushaldas/gamlastan) · [samlattacks.md](https://raw.githubusercontent.com/kushaldas/gamlastan/main/samlattacks.md) · [der](https://docs.rs/der/latest/der/) · [rasn](https://docs.rs/rasn/latest/rasn/) · [ciborium](https://docs.rs/ciborium/latest/ciborium/) · [cap](https://lib.rs/crates/cap)

**DoS:** [axum DefaultBodyLimit](https://docs.rs/axum/latest/axum/extract/struct.DefaultBodyLimit.html) · [axum 0.7 duyurusu (2023-11-27)](https://tokio.rs/blog/2023-11-27-announcing-axum-0-7-0) · [hyper http1::Builder](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html) · [hyper http2::Builder](https://docs.rs/hyper/latest/hyper/server/conn/http2/struct.Builder.html) · [hyper CONTINUATION flood (2024-04-03)](https://seanmonstar.com/blog/hyper-http2-continuation-flood/) · [RUSTSEC-2024-0003](https://rustsec.org/advisories/RUSTSEC-2024-0003) · [RUSTSEC-2023-0034](https://rustsec.org/advisories/RUSTSEC-2023-0034.html) · [hyperium/h2#737](https://github.com/hyperium/h2/pull/737) · [CISA CVE-2023-44487 (2023-10-10)](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487) · [tower](https://docs.rs/tower/latest/tower/) · [governor](https://docs.rs/governor/latest/governor/) · [tower_governor](https://github.com/benwis/tower-governor) · [Rauthy](https://github.com/sebadob/rauthy) · [Rauthy Argon2 config](https://sebadob.github.io/rauthy/config/argon2.html) · [argon2 Params](https://docs.rs/argon2/latest/argon2/struct.Params.html) · [regex](https://docs.rs/regex/latest/regex/) · [Kanidm security hardening](https://github.com/kanidm/kanidm/blob/master/book/src/security_hardening.md)


---

## Argus (Rust IdP) için Fuzzing & Property-Based Testing — Derin Araştırma Raporu

---

### A) RUST FUZZING EKOSİSTEMİ — 2026 DURUMU

#### A.1 libFuzzer'ın durumu: "maintenance mode", ölmüş değil ama gelişmiyor

LLVM'in kendi dokümantasyonu net: libFuzzer **2022 sonundan beri yalnızca bakım modunda**; yeni özellik gelmeyecek, orijinal yazarlar **Centipede**'e geçti. Önemli hatalar düzeltiliyor, ama major feature/code review beklenmemeli.
- https://llvm.org/docs/LibFuzzer.html (LLVM resmî dokümantasyon, "maintenance-only mode since late 2022")
- Trail of Bits teyidi (29 Nisan 2026): "LLVM's libFuzzer is now in maintenance mode" — https://blog.trailofbits.com/2026/04/29/extending-ruzzy-with-libafl/

#### A.2 cargo-fuzz: LibAFL'e geçiş RESMÎ OLARAK BAŞLADI (2026'nın en önemli haberi)

Bu, sorunuzun en kritik cevabı ve arama sonuçlarının yüzeyde göstermediği bir şey — **kaynak koddan doğruladım**:

**cargo-fuzz 0.13.2 (yayın: 9 Haziran 2026)** `cargo fuzz init` komutuna `--fuzz-engine` bayrağını ekledi.
- CHANGELOG: https://github.com/rust-fuzz/cargo-fuzz/blob/main/CHANGELOG.md

Kaynak kodda desteklenen motorlar (`src/options.rs`, satır 284-298):
```rust
pub enum FuzzEngine { LibFuzzer, LibAfl }
// "invalid fuzz engine: '{s}'. Must be one of: 'libfuzzer', 'libafl'"
```
`src/templates.rs` içindeki şablon, `--fuzz-engine libafl` seçildiğinde `fuzz/Cargo.toml`'a şunu yazıyor:
```toml
libfuzzer-sys = { version = "0.15.3", package = "libafl_libfuzzer" }
```
Yani **cargo-fuzz, libFuzzer'dan LibAFL'e geçişi resmî olarak destekliyor** ve mekanizma "libfuzzer-sys yerine libafl_libfuzzer'ı drop-in koy" şeklinde.
- https://raw.githubusercontent.com/rust-fuzz/cargo-fuzz/main/src/options.rs
- https://raw.githubusercontent.com/rust-fuzz/cargo-fuzz/main/src/templates.rs

Tarihçe: cargo-fuzz issue #330 "LibAFL support?" (20 Aralık 2022 açıldı, kapandı) — https://github.com/rust-fuzz/cargo-fuzz/issues/330

**Argus için tavsiye:** yeni fuzz projelerini `cargo fuzz init --fuzz-engine libafl` ile başlatın; harness kodu (`fuzz_target!`) aynı kalır, sadece runtime değişir. libFuzzer'a geri dönmek tek satırlık Cargo.toml değişikliği.

#### A.3 Sürüm/bakım tablosu (crates.io API'sinden doğrulanmış, 8 Eylül 2026)

| Araç | Son sürüm | Tarih | Durum | Argus'ta yeri |
|---|---|---|---|---|
| `cargo-fuzz` | 0.13.2 | 2026-06-09 | Aktif | Ana giriş noktası; OSS-Fuzz zorunluluğu |
| `libfuzzer-sys` | 0.4.13 | 2026-06-04 | Aktif (bağlayıcı) | Varsayılan runtime |
| `libafl` | 0.16.1 | 2026-08-11 | Çok aktif | Özel fuzzer yazımı |
| `libafl_libfuzzer` | 0.16.1 | 2026-08-11 | Aktif | libFuzzer drop-in replacement |
| `afl` / `cargo-afl` | 0.18.2 | 2026-05-11 | Aktif | AFL++ 4.40c; persistent mode |
| `honggfuzz` | 0.5.62 | 2026-08-04 | Aktif (düzenli) | Alternatif motor |
| `bolero` / `cargo-bolero` | 0.13.4 | **2025-07-03** | **Yavaşlamış** | Birleşik ön-yüz (aşağı bak) |
| `arbitrary` | 1.4.2 | 2025-08-14 | Stabil/olgun | Structure-aware üretim |
| `mutatis` | 0.5.3 | 2026-06-09 | Aktif | Structure-aware **mutasyon** |
| `proptest` | 1.11.0 | 2026-03-24 | Aktif | PBT |
| `proptest-state-machine` | 0.8.0 | 2026-03-24 (crate) / docs 2026-07-04 | Aktif | Stateful PBT |
| `quickcheck` | 1.1.0 | **2026-02-10** | 5 yıl sonra uyandı (önceki: 1.0.3, 2021-01-15) | Basit PBT |
| `stateright` | 0.31.0 | 2025-07-27 | Yavaş | Model checking |
| `kani-verifier` | 0.67.0 | 2026-01-16 | Aktif | Bounded model checking |

Kaynak: `https://crates.io/api/v1/crates/<isim>/versions` (8 Eylül 2026'da çekildi).

#### A.4 Araç araç değerlendirme

**cargo-fuzz + libFuzzer**
- Olgunluk: yüksek; fiilî standart. **Nightly toolchain zorunlu**, x86-64/aarch64 Unix. Windows desteği `--no-include-msvc` ile 0.13.0'dan (2025-06-25) beri "basic".
- Maliyet: ~sıfır (kendi CPU'nuz).
- Trail of Bits notu: unsafe içermeyen saf Rust kodda `--sanitizer none` ~2x hızlanma sağlar. https://appsec.guide/docs/fuzzing/rust/cargo-fuzz/
- Argus'ta: JOSE parser, SCIM filter parser, LDAP BER decoder, CBOR/WebAuthn attestation, OAuth query-string parser, redirect_uri matcher.

**LibAFL**
- Olgunluk: araştırma-sınıfı ama üretimde. CCS 2022 papers (Fioraldi et al., https://www.s3.eurecom.fr/docs/ccs22_fioraldi.pdf); 2026'da aktif kullanım: LibAFL-DiFuzz (Rust/Go directed fuzzing, arXiv:2601.22772, Ocak 2026), StorFuzz (ICSE 2026, LibAFL 0.13.1 tabanlı), Ruzzy (Trail of Bits, Nisan 2026).
- Kazandırdığı: çok-çekirdek/çok-makine ölçekleme, custom mutator/observer/feedback, stacktrace ile dedup, grimoire mutasyonu, TUI.
- Maliyet: öğrenme eğrisi dik. `libafl_libfuzzer` üzerinden kullanırsanız maliyet ~sıfır.
- Platform: Rust/C/C++ hedefleri Linux + macOS; Windows sadece standalone kütüphane olarak.
- https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_libfuzzer

**afl.rs / cargo-afl (AFL++)**
- Olgunluk: yüksek, aktif (0.18.2, 2026-05-11; AFL++ 4.40c). CMPLOG varsayılan açık.
- **Kritik uyarı (Argus için doğrudan geçerli):** AFL++ persistent mode hedefi bir döngüde çalıştırır; `lazy_static`/`OnceLock` gibi static init yalnız ilk iterasyonda çalışır → AFL'in "stability" metriği düşer, timeout'lar raporlanmaz. Çözüm: 0.18.0'da eklenen `fuzz_with_reset!` makrosu ile her iterasyondan sonra static state'i temizleyen closure verin. Ayrıca `rust-fuzz/resettable-lazy-static.rs`.
- https://github.com/rust-fuzz/afl.rs/blob/master/CHANGES.md
- Argus'ta: bir IdP'de global key cache, JWKS cache, session store, rate-limiter state hep static/lazy — persistent mode kullanacaksanız reset şart.

**honggfuzz-rs**
- Olgunluk: orta-yüksek, düzenli sürümler (0.5.62, 2026-08-04). ~7.8M toplam indirme.
- Farklılaştırıcı: hardware feedback (Intel PT/BTS), kolay crash triage, thread/signal-heavy kod.

**bolero / cargo-bolero**
- Ne yapar: **tek bir `bolero::check!` arayüzü** ile libFuzzer / AFL / honggfuzz / **Kani**'yi birleştirir; `--fuzzer` bayrağıyla motor değiştirilir. Sanitizer belirtilmediyse nightly gerekmez — cargo-fuzz'a göre büyük avantaj.
- **Olgunluk uyarısı:** son sürüm 0.13.4 → **3 Temmuz 2025**. 2026'da yeni sürüm yok. Repo'da 44 açık issue / 11 açık PR var. Yani "terk edilmiş" değil ama **momentum kaybetmiş**; ekosistemin geri kalanı (cargo-fuzz 0.13.2, LibAFL 0.16.1) 2026'da hareket ederken bolero durdu.
- https://github.com/camshaft/bolero · https://camshaft.github.io/bolero/
- **Argus için karar:** bolero'nun "aynı property'yi hem unit test hem fuzz hem Kani proof olarak çalıştır" modeli bir IdP için ideolojik olarak çok cazip. Ama tek noktadan bağımlılık riski var. Öneri: **property'lerinizi bolero'ya değil, kendi trait/fonksiyonlarınıza yazın**; bolero'yu ince bir adaptör katmanı olarak kullanın ki gerekirse cargo-fuzz+proptest'e düşebilesiniz.

#### A.5 Coverage-guided vs. structure-aware — ve 2026'nın önemli bulgusu

`arbitrary` crate'i ham byte dizisini "DNA string" gibi okuyup yapılandırılmış tipe çevirir; `#[derive(Arbitrary)]` bunu otomatik üretir.
- https://github.com/rust-fuzz/arbitrary
- https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html

**2026'nın önemli deneysel sonucu (Nick Fitzgerald, 1 Haziran 2026):** Wasmtime'da 4 yaklaşım karşılaştırıldı — `derive(Arbitrary)`+fixup, bottom-up generation, top-down generation, ve `derive(Mutate)` (mutatis crate) ile **mutasyon tabanlı**.
- 24 saatte: mutasyon diğerlerinden **%1–2 daha fazla coverage**.
- **5 dakikada: mutasyon %36–49 daha fazla coverage.**
- Generation yaklaşımları arasında top-down > bottom-up.
- Sonuç: "mutation-based fuzzing performs best"; structure-aware iş için `arbitrary` yerine **`mutatis`** önerilir.
- https://fitzgen.com/2026/06/01/structure-aware-fuzzing-experiment.html

**Argus'a çevirisi:** CI'da PR başına 5–10 dakikalık fuzz koşusu yapacaksanız (CIFuzz gibi), mutasyon tabanlı yaklaşımın avantajı devasa. Uzun gece koşularında fark küçülüyor. Yani: **CI = mutatis; nightly = her ikisi.**

Ayrıca `fuzz_mutator!` makrosu ile custom mutator yazılabiliyor — sıkıştırılmış veri (JWE `zip=DEF`!) için kanonik desen: decompress → mutate → recompress.

#### A.6 Argus'un protokol mesajları için gramer tasarımı (somut öneri)

| Yüzey | Yaklaşım | Notlar |
|---|---|---|
| **JWS/JWT compact** | `#[derive(Arbitrary)]` ile `struct Jws { header: JoseHeader, payload: Vec<u8>, sig: Vec<u8> }` + kanonik serializer | Header'ı **enum + open string** karışımı yapın: `alg` alanı `Known(Alg) \| Raw(String)` olmalı ki `none`, `NONE`, `nOnE`, `HS256 ` (trailing space), unicode homoglyph üretilebilsin |
| **JOSE header** | `crit`, `jku`, `jwk`, `x5u`, `x5c`, `kid`, `zip`, `p2c`, `p2s`, `epk`, `apu`, `apv` alanlarının hepsi opsiyonel + tip-karışık olmalı | **jsonwebtoken CVE-2026-25537 tam olarak tip karışıklığından çıktı** (aşağı bak) — `exp`/`nbf` için `Number \| String \| Bool \| Null \| Array` üretin |
| **JWS JSON serialization** | Ayrı hedef | "JWT Format Confusion" sınıfı buradan çıkıyor (NDSS 2026) |
| **OAuth request params** | `Vec<(String, String)>` + %-encoding mutatörü | Tekrarlanan parametreler (`scope=a&scope=b`), boş değer, `+` vs `%20`, aşırı uzun `state` |
| **redirect_uri** | Ayrı, yüksek öncelikli hedef | Diferansiyel test için ideal (aşağı bak) |
| **SAML XML** | quick-xml/roxmltree üstünde `arbitrary`-tabanlı XML AST + XSW mutatörü | Aşağıdaki quick-xml RUSTSEC'lerine dikkat |
| **CBOR/WebAuthn attestation** | `ciborium`/`coset` üstünde structure-aware; COSE_Key ve attStmt için ayrı grammar | |
| **SCIM JSON + SCIM filter** | **Filter parser'ı ayrı fuzz edin** | Kanidm'in 2026'daki en ciddi 2 açığı tam buradan (aşağı bak) |

#### A.7 Async Rust / tokio ve HTTP sunucusu fuzzing'i — pratik zorluklar

Bunlar Argus için gerçek engeller:

1. **Fuzz harness'ı senkron olmalı.** `fuzz_target!` bir `&[u8]` alır ve döner. tokio kodu için her iterasyonda `Runtime::new()` yaratmak çok pahalı — tek bir `current_thread` runtime'ı `OnceLock`'ta tutup `block_on` kullanmak gerekir, ama bu persistent-mode'da state sızıntısı yaratır.
2. **AFL persistent mode + lazy static çakışması** (yukarıda A.4).
3. **Coverage gürültüsü:** tokio scheduler'ı non-deterministik dallanma üretir; coverage feedback'i bozulur. Pratik çözüm: **runtime'ı harness'tan tamamen çıkarın** — parser/validator/state-machine katmanlarını `async` olmayan saf fonksiyonlar olarak tasarlayın ve *onları* fuzz edin.
4. **Timeout ve OOM:** OSS-Fuzz'da hedef başına ~25 saniye timeout ve 2.5 GB RAM sınırı var (https://google.github.io/oss-fuzz/faq/). `p2c` iterasyon DoS'u gibi CPU-bound bug'lar burada timeout olarak yakalanır — bu iyi haber.

> **Argus mimarî tavsiyesi:** "hexagonal" ayrım yapın — `argus-core` (saf, senkron, no-IO: token validate, policy decide, filter parse) + `argus-http` (axum/tokio). Fuzzing ve PBT'nin %90'ı `argus-core`'a uygulanır ve orada hem hızlı hem deterministiktir. Bu tek karar, fuzzing yatırımınızın getirisini katlar.

#### A.8 Snapshot / Nyx fuzzing

- **Nyx** (USENIX Security 2021, Schumilo et al.): KVM-PT + QEMU-PT ile tam-VM snapshot, saniyede binlerce restore. https://www.usenix.org/conference/usenixsecurity21/presentation/schumilo
- **Nyx-Net** (EuroSys 2022): stateful ağ servisleri için artımlı snapshot; "gürültüsüz" fuzzing ve temiz state'e hızlı dönüş. https://arxiv.org/pdf/2111.03013
- Harness framework: **HyperHook** (Neodyme) — https://neodyme.io/en/blog/hyperhook/
- **2026 durumu: [DOĞRULANMADI]** — Nyx için 2025-2026'ya ait yeni bir major sürüm/duyuru bulamadım; bulduğum tüm kaynaklar 2021-2022. LibAFL tarafında `libafl_qemu`/`libafl_nyx` entegrasyonu var ve LibAFL 0.16.1 (Ağustos 2026) aktif — snapshot fuzzing'in 2026'daki canlı yolu muhtemelen LibAFL üzerinden.
- **Argus için verdict:** Nyx aşırı ağır. Bir IdP'de kazanç/maliyet oranı düşük — çünkü asıl risk *bellek güvenliği* değil (Rust) *mantık* ve *kaynak tüketimi*. Snapshot yerine A.7'deki mimari ayrım + in-process HTTP harness (aşağı) çok daha verimli.

---

### B) DİFERANSİYEL FUZZING

#### B.1 Kavram ve klasik örnekler

**Frankencerts** (Brubaker et al., IEEE S&P 2014): gerçek sertifikaların parçalarını rastgele birleştirip "frankencert" üretip OpenSSL, NSS, CyaSSL, GnuTLS, PolarSSL, MatrixSSL'i diferansiyel test etti. **8.127.600 sertifika → 208 tutarsızlık → 9 farklı kök neden.**
- https://www.cs.columbia.edu/~suman/docs/frankencert.pdf

**NEZHA** (Petsios et al., IEEE S&P 2017): "domain-independent differential testing"; davranışsal asimetriyi feedback sinyali olarak kullanır. **10K iterasyonda ortalama sadece 98.3 sertifika üretip %81.74 çeşitlilik** — frankencert'ten kat kat verimli.
- https://wcventure.github.io/FuzzingPaper/Paper/SP17_NEZHA.pdf

**transcert** (TOSEM 2022, coverage-directed): 10.000 iterasyonda **71 benzersiz doğrulama farkı** — frankencert'in 12×'i, NEZHA'nın 1.4×'i, RFCcert'in 7×'i.
- https://dl.acm.org/doi/10.1145/3510416

**Project Wycheproof**: kripto kütüphanelerini bilinen saldırılara karşı test vektörleriyle sınar (AES, DH, DSA, ECDH, ECDSA, RSA); invalid curve attack, biased nonce, Bleichenbacher varyantları. **2025-2026'da C2SP çatısı altına taşındı ve yeniden canlandırılıyor**; öncelik tüm test vektörlerinin JSON şema tanımlarının tamamlanması. Son paket: `wycheproof-testvectors-20251219`.
- https://github.com/C2SP/wycheproof
- **Argus için:** JOSE imza/şifreleme katmanınızı Wycheproof vektörleriyle beslemek *zorunlu bir taban çizgisi*. Fuzzing'in bulamayacağı şeyleri (psychic signature, invalid curve) bunlar bulur.

**Cryptofuzz / Cryptofuzz++**: kripto kütüphanelerinin diferansiyel fuzzing'i; ICISC 2024'te hibrit fuzzing + kripto-özel mutasyonla genişletildi.
- https://link.springer.com/chapter/10.1007/978-981-96-5566-3_10

**Risk Estimation in Differential Fuzzing via Extreme Value Theory** (arXiv:2511.02927) — diferansiyel fuzzing'de "kaçırılan bug" riskini istatistiksel tahmin etme.

#### B.2 JWT kütüphanelerinin diferansiyel fuzzing'i — **EVET, YAPILDI** (2026'nın en önemli çalışması)

**"Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery"**, NDSS Symposium 2026, 23–27 Şubat 2026, San Diego. DOI: 10.14722/ndss.2026.240697
- Yazarlar: Jingcheng Yang, Enze Wang (eş-birinci), Jianjun Chen (sorumlu yazar, Tsinghua), Qi Wang, Yuheng Zhang, Haixin Duan (Tsinghua University); Wei Xie, Baosheng Wang (National University of Defense Technology).
- PDF: https://www.ndss-symposium.org/wp-content/uploads/2026-f697-paper.pdf · https://jianjunchen.com/p/jwt.NDSS26.pdf
- Sayfa: https://www.ndss-symposium.org/ndss-paper/token-time-bomb-evaluating-jwt-implementations-for-vulnerability-discovery/

**Metodoloji (JWTeemo):**
- **FBNF** (Function-extended Backus-Naur Form) — ABNF'i genişleterek JWT'yi RFC'lerden modelleyen yeni bir gramer dili. Semantik bağımlılıklar graf kenarları olarak modellenir (ör. `signature` düğümünden `alg_value` düğümüne yönlü kenar — imzanın üretimi `alg` değerine bağlı).
- **UCT-Rand** (Monte Carlo Tree Search / Upper Confidence bounds for Trees): gramer grafındaki düğüm seçimini MCTS olarak modelleyip hedef implementasyonun parse feedback'i ile ağırlıkları günceller. Örnek: "JWE → p2s → p2c" yolu başarılı parse ederken "JWE → p2s" tek başına başarısızsa, fuzzer `p2c`'nin `p2s` ile birlikte gerekliliğini **öğrenir**.
- **Differential Analyzer**: iki strateji — (a) *parsing discrepancy* (aynı token'ı farklı implementasyonlar farklı kabul/red ediyor mu?), (b) *resource exhaustion* (istatistiksel: `R > μ + k·σ`, Chebyshev eşitsizliği ile eşik).
- Ablation: "w/o Mutator" ve "w/o UCT" varyantlarına karşı edge coverage'da net üstünlük.

**Sonuçlar:** 10 dilde **43 JWT implementasyonu** → **17 kütüphanede 31 sıfır-gün**, **20 CVE**. Kubernetes'te authentication bypass, Apache James'te DoS. Apache, Connect2id, Kubernetes, Let's Encrypt ve RedHat'ten bug bounty. **IETF bulguları kabul etti ve mitigasyonları yeni bir RFC'ye alacağını belirtti.**

**Beş kök-neden kategorisi:**
1. **Sign/Encryption Confusion** (2 adet) — JWS doğrulama public key'i ile JWE üretip token'ı JWE zannettirmek. Saldırgan public key'i alır, normal login ile JWS alır, payload'daki `role`'ü `admin` yapar, public key ile şifreleyip sahte JWE üretir. Kurban implementasyon **noktaların sayısına bakarak** JWE olduğuna karar verip private key ile açar → yetki yükseltme.
2. **Algorithm Confusion** (2 adet)
3. **JWT Format Confusion** (4 implementasyon riskli) — JWS'in JSON serialization formatını parse etme
4. **Billion Hashes Attack** (10 adet) — PBES2 `p2c`. **PBES2 destekleyen implementasyonların %71.9'u savunmasız.**
5. **Compression DoS** (13 adet) — JWE `zip=DEF`. **JWE destekleyen implementasyonların %86.7'si savunmasız.**

**Tablo I — Bulunan yeni açıklar (makaleden birebir):**

| Dil | Kütüphane | Sürüm | Açık | CVE |
|---|---|---|---|---|
| Python | python-jose | 3.3.0 | Compression DoS | CVE-2024-29370 |
| Python | jwcrypto | 1.5.0 | Billion Hashes | CVE-2023-6681 |
| Python | jwcrypto | 1.5.0 | Compression DoS | CVE-2024-28102 |
| Python | jwcrypto | 1.5.0 | JWT Format Confusion | Fixed (CVE yok) |
| Python | authlib | 1.2.1 | Compression DoS | Unassigned |
| C | latchset/jose | 11 | Billion Hashes | CVE-2023-50967 |
| C | latchset/jose | 11 | JWT Format Confusion | Unassigned |
| C | libjwt | 1.15.3 | **Algorithm Confusion** | CVE-2024-57453 |
| C++ | cpp-jwt | 1.4 | **Algorithm Confusion** | CVE-2024-57454 |
| Java | jjwt | 0.12.3 | Billion Hashes | CVE-2024-39960 |
| Java | jjwt | 0.12.3 | Compression DoS (+ JWS'te) | Unassigned ×2 |
| Java | jose4j | 0.9.3 | Billion Hashes | CVE-2023-51775 |
| Java | jose4j | 0.9.3 | Compression DoS | CVE-2024-29371 |
| Java | nimbus-jose-jwt | 9.37.1 | Billion Hashes | CVE-2023-52428 |
| Java | nimbus-jose-jwt | 9.37.1 | Compression DoS | Unassigned |
| C# | jose-jwt | 4.1.0 | **Sign/Encrypt Confusion** | CVE-2024-24238 |
| C# | jose-jwt | 4.1.0 | Compression DoS | CVE-2024-27663 |
| JS | jose (panva) | 5.1.3 | Compression DoS | CVE-2024-28176 |
| JS | node-jose | 2.2.0 | Billion Hashes | CVE-2024-39960 |
| JS | node-jose | 2.2.0 | Compression DoS | Unassigned |
| PHP | jwt-framework | 3.2.8 | Billion Hashes | Fixed |
| PHP | jwt-framework | 3.2.8 | Compression DoS | Unassigned |
| Go | jose2go | 1.5.0 | Billion Hashes | CVE-2023-50658 |
| Go | jose2go | 1.5.0 | Compression DoS | **CVE-2025-63811** |
| Go | go-jose | 3.0.1 | Compression DoS | CVE-2024-28180 |
| Go | go-jose | 3.0.1 | JWT Format Confusion | Unassigned |
| Go | jwx (lestrrat) | 2.0.17 | Billion Hashes | CVE-2023-49290 |
| Go | jwx | 2.0.17 | Compression DoS | CVE-2024-28122 |
| Go | jwx | 2.0.17 | JWT Format Confusion | Fixed |
| Ruby | json-jwt | 1.16.3 | **Sign/Encrypt Confusion** | CVE-2023-51774 |

**🔴 ARGUS İÇİN KRİTİK BULGU:** Makale metninde "Rust" kelimesi **sıfır kez** geçiyor. Test edilen 10 dil: Python, C, C++, Java, C#, JavaScript, PHP, Go, Ruby, Swift. **Rust JOSE kütüphaneleri (jsonwebtoken, josekit, jwt-simple, biscuit) bu çalışmanın kapsamı DIŞINDA.** Bu, Argus için hem bir risk (bilmiyoruz) hem de bir fırsat (JWTeemo metodolojisini Rust ekosistemine ilk uygulayan siz olabilirsiniz — yayınlanabilir iş).

#### B.3 Chai — 2026, X.509 + JWT + SAML diferansiyel testi

**"Chai: Agentic Discovery of Cryptographic Misuse Vulnerabilities"** — arXiv:2606.26933
- Yaklaşım: kütüphane seviyesinde kusurları katalogla, sonra kriptografik bağımlılık grafında yay. İki aşama: (1) kütüphane içi gerçek güvenlik sorunlarını yüksek hassasiyetle bul, (2) tutarsızlıkları bağımlı uygulamalardaki açık göstergesi olarak kullan.
- Değerlendirme alanları: **X.509, JWT ve SAML**. "Chai'nin yaklaşımı önceki araçlardan daha az girdi ile daha fazla benzersiz differential buluyor."
- Sonuçlar: milyarlarca cihazda kullanılan bir SSL kütüphanesinde önceden bilinmeyen kritik açık; büyük bir web tarayıcısının kripto kütüphanesinde bug'lar; major Linux dağıtımlarıyla gelen kütüphanelerde açıklar; **toplam 100+ açık**.

#### B.4 Bir OAuth Authorization Server'ı diferansiyel test etmek — pratik tasarım

**Referans implementasyonlar (diff hedefi olarak):**

| Referans | Dil | Neden iyi bir oracle | Zorluk |
|---|---|---|---|
| **ory/hydra** | Go | OpenID Certified; headless; kullanıcı yönetimi yok → sadece protokol. **En iyi diff hedefi.** | Login/consent URL'leri konfigüre edilmeli |
| **node oidc-provider** (panva) | JS | Spec'e en sadık, in-process çalıştırılabilir, çok esnek | JS runtime bridge |
| **Keycloak** | Java | En yaygın, en çok özellik | Ağır, kendi login UI'ı, stateful |
| **Authlete** | SaaS | API tabanlı, sertifikalı | Ücretli, ağ bağımlı |
| **oauth2-server / fosite** | Go/JS | Kütüphane seviyesi, embed edilebilir | Tam AS değil |

**OpenID Conformance Suite** (OIDF, açık kaynak, https://openid.net/certification/about-conformance-suite/, üretim: https://www.certification.openid.net): AS ve RP için test planları; "sahte" OP/AS sağlar; master branch günde en az bir kez vendor cloud ortamlarına karşı regresyon testinden geçiyor; lokalde Docker ile kurulabilir. Argus için **birinci gün hedefi** olmalı.

**OAuch** (DistriNet/KU Leuven, https://github.com/DistriNet/OAuch, testler: https://oauch.io/Tests): AS implementasyonlarının OAuth standartlarına ve **tehdit modeline** uyumunu analiz eder. AS'in desteklediği özellikleri otomatik tespit edip yalnız ilgili testleri koşar. Kategoriler ve test sayıları:
- Document & Feature Support: 29 test (RFC6749, RFC7636 PKCE, RFC8705 mTLS, grant type'lar, OIDC)
- Token Security: 39 test (token endpoint doğrulama, client auth, code binding, refresh mekaniği, **access token / refresh token / authorization code entropi ölçümü**, timeout, rotasyon)
- Cryptography & Identity: 26 test (JWT imza/exp/aud doğrulama, ID token claim'leri, **PKCE downgrade koruması**)
- Endpoint Security: 39 test (HTTPS/TLS, sertifika doğrulama, cipher suite gücü, **redirect URI doğrulama**, güvenlik başlıkları)
- Token Management: 13 test (revocation, client binding, eşzamanlı token'lar, refresh token invalidation)

> **Gerçek dünya kanıtı:** Kanidm'e karşı OAuch koşuldu ve GHSA-hh34-7jqq-3f73 (23 Haziran 2026, Low) doğdu — 4 bulgu: (1) authorization code ilk kullanımdan sonra invalidate edilmiyor (RFC 9700 ihlali), (2) 34 karakterden kısa PKCE code_verifier reddedilmiyor (RFC 7636), (3) authorization sayfasında X-Frame-Options yok (clickjacking), (4) authorization akışında Referer başlığı bastırılmıyor (RFC 9700). Bildiren: oliverpool; araç: pieterphilippaerts (OAuch geliştiricisi).
> https://github.com/kanidm/kanidm/security/advisories/GHSA-hh34-7jqq-3f73

**Argus için somut diferansiyel test mimarisi:**

```
┌─────────────────┐
│ Fuzzer (LibAFL) │  structure-aware OAuth senaryo üreteci
└────────┬────────┘   (Arbitrary/Mutate ile: client kayıt + istek dizisi)
         │
    ┌────┴────┬──────────────┐
    ▼         ▼              ▼
 Argus AS   ory/hydra   node oidc-provider
    │         │              │
    └────┬────┴──────────────┘
         ▼
  Normalizer  →  aynı input için:
                 - HTTP status sınıfı (2xx/3xx/4xx)
                 - OAuth error code (invalid_request / invalid_grant / ...)
                 - redirect Location'ın host+path+query anahtarları
                 - token verildi mi? scope kümesi? aud? exp?
         ▼
  Differ  →  KABUL/RED ayrışması = yüksek öncelikli sinyal
```

**Diferansiyel testin en verimli 6 yüzeyi (öncelik sırasıyla):**

1. **`redirect_uri` eşleştirme.** Tarihsel olarak en bereketli alan. Üretin: trailing slash, `//`, `/../`, userinfo (`https://a@evil.com`), unicode host, IDN homoglyph, port varyasyonu, `?`/`#` fragment, encode edilmiş `%2e%2e`, boş path, wildcard subdomain, `localhost` vs `127.0.0.1` vs `[::1]`, path traversal. **Argus kabul edip hydra reddediyorsa → muhtemelen açık.**
2. **`scope` parse ve grant.** Boşluk-ayrımlı liste; tekrarlanan scope, boş scope, `scope=` (boş), tab/newline ayırıcı, aşırı uzun, unicode boşluklar. Verilen scope kümesi ⊆ istenen ∩ client'ın izinli kümesi mi?
3. **PKCE.** `code_challenge_method` yok/`plain`/`S256`/bilinmeyen; verifier uzunluğu 42 (sınır: 43-128); base64url padding'li/padlı olmayan; `+`/`/` vs `-`/`_`; code_challenge ile code_verifier eşleşmesi.
4. **Token endpoint client auth.** `client_secret_basic` vs `client_secret_post` **ikisi de gönderilmişse**? Basic auth'ta URL-encoding? `client_id` iki farklı yerde farklı değerlerle?
5. **`grant_type` / `response_type` kombinasyonları.** Bilinmeyen değerler, çoklu değerler, sıra permütasyonları.
6. **JWT doğrulama.** Burada asıl referanslar JOSE kütüphaneleri: `jsonwebtoken` (Rust) vs `panva/jose` (JS) vs `go-jose` (Go) vs `nimbus-jose-jwt` (Java) → aynı token'a farklı verdict veriyorlarsa, hangisi doğru?

**Oracle problemi ve çözümü:** Diferansiyel testte iki implementasyon ayrışınca "hangisi haklı?" sorusu çıkar. Cedar'ın çözümü şu: **bir tarafı kanıtlanmış bir model yapın.** Argus için uygulanabilir versiyon: `argus-core`'un token validation ve policy decision mantığı için ayrı, minimal, *aşikâr derecede doğru* bir referans model (executable spec) yazın; asıl implementasyon optimizasyonlarla dolu olsun. Model ile implementasyon arasında DRT koşun. Bu, Cedar'ın tam formülü (aşağı bak) ve dış kütüphanelere bağımlılığı ortadan kaldırır.

---

### C) ERİŞİM KONTROLÜNÜN PROPERTY-BASED TESTİ

#### C.1 proptest vs quickcheck — 2026

| | proptest | quickcheck |
|---|---|---|
| Üretim modeli | **Strategy** nesneleri (değer-başına) | Tip-başına `Arbitrary` |
| Esneklik | Kompozisyon kolay; aynı tip için farklı stratejiler | Tip başına tek generator; newtype sarmak gerekir |
| Shrinking | Gelişmiş, integrated | Basit |
| Hız | Karmaşık değerlerde **1 mertebe daha yavaş** olabilir | Hızlı |
| Sürüm/bakım | 1.11.0, 2026-03-24; **aktif** (1.6→1.11 arası 6 sürüm 2024-12'den beri) | 1.1.0, 2026-02-10 — **2021-01'den beri ilk sürüm** |
| Resmî not | "feature-complete'e yakın, mimari değişiklik yok, **passive maintenance**" | — |

- https://proptest-rs.github.io/proptest/proptest/vs-quickcheck.html
- https://github.com/proptest-rs/proptest · https://github.com/BurntSushi/quickcheck

**Argus kararı: proptest.** Bir IdP'de üretilen değerler (policy ağaçları, rol grafları, token dizileri) karmaşık ve bağlama duyarlı; quickcheck'in tip-başına modeli bunu taşımaz. proptest'in "passive maintenance" durumu bir risk değil — olgunluk göstergesi (2026'da hâlâ minor sürümler geliyor).

**`arbitrary` ile üretim:** proptest'in yanında `arbitrary` kullanın; aynı `#[derive(Arbitrary)]` tipleri hem proptest testlerini hem fuzz hedeflerini beslesin. Bu, "PBT'de bulduğunu fuzz corpus'una at, fuzz'da bulduğunu PBT regresyonuna al" döngüsünü kurar. (bolero bunu built-in yapar.)

#### C.2 GÜVENLİK INVARYANTLARINI PROPERTY OLARAK YAZMAK

##### C.2.1 Altın standart: AWS Cedar'ın Verification-Guided Development'ı

Bu, Argus'un doğrudan kopyalaması gereken model.

**Kaynaklar:**
- "How We Built Cedar: A Verification-Guided Approach", arXiv:2407.01688 (1 Temmuz 2024), 13 yazar, iletişim: Shaobo He — https://arxiv.org/abs/2407.01688
- Amazon Science blogu — https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing
- Lean'e taşınma RFC: https://cedar-policy.github.io/rfcs/0032-port-formalization-to-lean.html
- Kod: https://github.com/cedar-policy/cedar-spec
- Lean tarafı: https://lean-lang.org/use-cases/cedar/

**Üç ayak:**
1. **Executable formal model** yaz (önce Dafny, sonra **Lean 4**'e taşındı) ve model üzerinde teoremleri mekanik olarak kanıtla.
2. **DRT (Differential Random Testing)**: milyonlarca rastgele girdi üretip hem modele hem Rust üretim koduna ver; çıktılar aynı değilse bug.
3. **PBT**: modellenmemiş parçalar için QuickCheck tarzı doğrudan property testleri.

**Somut sayılar:**
- **Gecelik 6 saat DRT, ~100 milyon test/gün.**
- Lean modeli test başına **5 μs**, Rust üretim kodu **7 μs** → Lean modeli DRT için yeterince hızlı.
- Lean modelleri Rust muadillerinden **bir mertebe daha küçük**.
- **Toplam 25 bug:** 4'ü model kanıtlanırken, **21'i DRT + PBT ile**.
- Bulunan bug tipleri: harici bir Rust IP-adresi parse paketinde bug, Cedar policy parser'ında ince kusurlar, authorizer'ın eksik uygulama verisini ele alışında hatalar, namespace prefix yorumlamada hata.
- **Kanıtlanan iki temel property:**
  - *Explicit permit*: erişim yalnızca açık bir `permit` policy'si üzerinden verilir.
  - *Forbid overrides permit*: uygulanabilir herhangi bir `forbid` policy'si, tüm `permit`'lere rağmen erişimi reddeder.
- **Süreç kuralı:** "Modeli, kanıtları ve diferansiyel testleri güncel olmayan hiçbir Cedar sürümü yayınlanmaz."

**Teknik yığın:** `cedar-lean` (Lean 4 formalizasyon + kanıtlar), `cedar-drt` (test framework), `cedar-policy-generators` (**`arbitrary` crate'i ile** schema/entity/policy/request üretimi). Çalıştırma: `cargo fuzz run -s none <target>`.

**Kritik detay — "input generation" sorunu:** Amazon açıkça yazıyor: saf rastgele üretim işe yaramaz, çünkü *"rastgele üretilen policy'lerin, rastgele üretilen request ve verideki aynı grup ve attribute'lardan bahsetme olasılığı düşük."* Çözüm: **birbirleriyle tutarlı** policy + data + request üreten özel generator'lar yazdılar.

> **Argus için doğrudan uygulanabilir ders:** IdP'nizde rastgele bir `(user, role, resource, action)` üretirseniz %99.9 ihtimalle "deny" alırsınız ve hiçbir ilginç kod yolu çalışmaz. **Tutarlı dünya üreticileri** yazın: önce bir schema/tenant üret, ondan roller türet, rollerden kullanıcılar, kullanıcılardan istekler. Bu, PBT yatırımınızın tek en önemli teknik detayı.

##### C.2.2 Diğer authorization motorlarında test durumu

- **Cerbos:** repo'da "Fuzzing" issue'su (#149) — resmî bir fuzzer çıkınca motoru fuzz etme planı, nadir uç durumları yakalamak için. https://github.com/cerbos/cerbos/issues/149. Cerbos'un asıl test hikâyesi YAML policy test dosyaları + Cerbos Hub'da policy testing/versioning.
- **SpiceDB:** `internal/services/integrationtesting/` altında `consistencytestutil/`, `consistency_test.go`, `consistency_datastore_test.go`, `queryconsistency/` var — **sistematik consistency testing yapıyorlar**; ancak dizin listesinden metodolojinin property-based mi klasik assertion mı olduğu **çıkarılamıyor [KISMEN DOĞRULANDI]**. https://github.com/authzed/spicedb
- **OpenFGA:** `tests/` altında `authzen/`, `check/`, `listobjects/`, `listusers/`, `functional_test.go` — fuzzing/PBT'ye dair kanıt **[DOĞRULANMADI]**. https://github.com/openfga/openfga
- **Oso:** policy testing, decision tracing ve REPL sunuyor; PBT/fuzzing kanıtı **[DOĞRULANMADI]**.
- **Zanzibar tutarlılık:** SpiceDB "new enemy problem"a karşı ZedToken (zookie) ile snapshot consistency; OpenFGA yapılandırılabilir read modları + transactional timestamp. Bu, Argus'un session/permission cache'i için doğrudan bir invariant kaynağı.

> **Sonuç:** Cedar dışında, authorization dünyasında **ciddi, yayınlanmış property/differential testing pratiği yok**. Argus "en güvenli IdP" iddiasını Cedar'ın VGD modelini benimseyerek somut ve savunulabilir hale getirebilir — bu, pazarda gerçek bir farklılaştırıcı.

##### C.2.3 Model-based / stateful property testing araçları

**`proptest-state-machine` 0.8.0** (crate 2026-03-24, docs 2026-07-04; %95.65 doküman kapsamı; proptest ^1.10 gerektirir)
- https://docs.rs/proptest-state-machine · https://proptest-rs.github.io/proptest/proptest/state-machine.html

İki trait:
- **`ReferenceStateMachine`**: `State`, `Transition` (enum); `init_state()` (Strategy), `transitions(state)` (genelde `prop_oneof!`), `apply(state, transition)`, **`preconditions(state, transition)`** — geçişin geçerliliği state'e bağlıysa kritik.
- **`StateMachineTest`**: `SystemUnderTest`, `Reference`; `init_test(ref_state)`, `apply(...)` (post-condition assert'leri burada), **`check_invariants(state, ref_state)`** — *her geçişten sonra* koşar, `teardown()`.
- Makro: `prop_state_machine! { #[test] fn t(sequential 1..20 => MyTest); }`
- **Shrinking sırası:** sondan geçiş silme → baştan tek tek geçişleri küçültme → başlangıç state'ini küçültme. Bir güvenlik bug'ını "3 istek dizisi"ne indirger — triaj için paha biçilmez.
- Pratik: geliştirme sırasında `PROPTEST_CASES` yüksek tutun; `PROPTEST_VERBOSE=1` uygulanan geçişleri gösterir.

**`proptest-stateful`** (ReadySet) — alternatif; operasyon dizisi üretip tek tek çalıştırır ve her operasyondan sonra post-condition kontrol eder. https://github.com/readysettech/proptest-stateful

**`stateright` 0.31.0 (2025-07-27)** — dağıtık sistemler için model checker + actor runtime + gömülü UI + **linearizability tester**. TLA+/TLC'den farkı: Rust'ta yazdığınız sistemi hem model-check edip hem gerçek ağda çalıştırabilirsiniz (yeniden implementasyon yok). Örnekler: Single Decree Paxos, iki-fazlı commit. https://github.com/stateright/stateright · https://www.stateright.rs/
- **Uyarı:** 0.30.2 (2024-06) → 0.31.0 (2025-07) → sonrası yok. Gelişim yavaş.
- Argus'ta yeri: **çok-düğümlü Argus cluster'ında replikasyon/revocation yayılımı**. "Revoke edilmiş bir token, revocation'ı henüz görmemiş bir replikada kabul ediliyor mu?" tam bir stateright sorusu.

**`kani-verifier` 0.67.0 (2026-01-16)** — Rust MIR'ından CBMC'ye derleyen bounded model checker.
- "Kani: A Model Checker for Rust", arXiv:2607.01504 (2026, ASE'de) — https://arxiv.org/abs/2607.01504
- Otomatik kontroller: aritmetik taşma, sıfıra bölme, null deref, assertion ihlali — annotation gerekmeden.
- **Function contracts, loop contracts, quantifier'lar ve function stubbing** ile bounded'dan unbounded'a çıkıyor; contract'lar panic-freedom'dan **fonksiyonel doğruluğa** yükseltti ve **6 yeni bug** ortaya çıkardı.
- Ölçek: Rust standart kütüphanesi doğrulama kampanyasında **kod değişikliği başına 16.000+ harness** doğrulanıyor; Amazon'un kritik altyapısında kullanılıyor.
- Argus'ta yeri: `constant_time_eq`, base64url decode, varint/length parsing, `p2c` sınır kontrolü gibi **küçük ve kritik** fonksiyonlar. Tüm IdP'yi Kani ile doğrulamaya kalkmayın.

**TLA+ / P** — protokol state machine'leri için. OAuth/OIDC'nin akademik formal analizinde kullanılan araçlar aslında **Tamarin** ve **ProVerif**:
- "A Comprehensive Formal Security Analysis of OAuth 2.0" — https://arxiv.org/pdf/1601.01229
- OIDC Tamarin modeli (ETH Zürich BA tezi): ~50 multiset rewriting kuralı, 16 thread'de ~3.5 saatte otomatik kanıt — https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/information-security-group-dam/research/software/ba-19-hofmeier-oidc.pdf
- "Automatic Verification of Security of OpenID Connect Protocol with ProVerif" — https://link.springer.com/chapter/10.1007/978-3-319-49109-7_20
- 2026: "Unveiling Authentication Forgery in OpenID Connect under Web Frameworks: A Formal Analysis of CSRF-Based Attack Paths" — https://www.sciencedirect.com/org/science/article/pii/S1546221826004947

> Bunlar **protokol seviyesinde** (Dolev-Yao saldırgan) çalışır, implementasyonunuzu doğrulamaz. Argus için doğru kombinasyon: **Tamarin/ProVerif protokol tasarımı için → stateright/proptest-state-machine implementasyon state machine'i için → Kani kritik fonksiyonlar için → fuzzing parser'lar için.**

#### C.3 IdP'ye özgü SOMUT invaryantlar (property olarak yazılabilir haliyle)

Bunlar `check_invariants()` içine veya post-condition olarak girer. RFC 9700 (Best Current Practice for OAuth 2.0 Security, https://www.rfc-editor.org/rfc/rfc9700.html) referans alınmıştır.

**Token yaşam döngüsü:**
1. `revoke(t)` sonrası hiçbir `validate(t)` çağrısı `Valid` dönmez — hangi sırayla, kaç kez, hangi endpoint'ten sorulursa sorulsun. *(Monotonluk invaryantı: `revoked` kümesi asla küçülmez.)*
2. `introspect(t).active == true` ⟺ `t ∉ revoked ∧ now < t.exp ∧ now ≥ t.nbf ∧ t.client_id aktif`.
3. Bir access token'ın `scope`'u, onu doğuran authorization code'un scope'unun **alt kümesidir**; refresh ile *asla genişlemez* (RFC 6749 §6).
4. `exp - iat ≤ configured_max_lifetime` — her zaman, her grant tipinde.
5. Token'ın `aud`'u, istenen resource'un tescilli identifier'ı olmayan bir değer içeremez.

**Refresh token rotasyonu / replay tespiti** (RFC 9700 §4.14 — "public client'lar için refresh token'lar sender-constrained OLMALI ya da rotasyon kullanmalı"):
6. `RT_n` kullanıldığında `RT_{n+1}` üretilir ve `RT_n` invalidate olur.
7. **Replay tespiti:** `RT_n` ikinci kez sunulursa → *tüm zincir* (`RT_0..RT_n+k`) ve türetilmiş access token'lar iptal edilir. Bu bir *stateful* property: geçiş dizisi `[Use(RT0), Use(RT1), Use(RT0)]` üretilmeli ve sonrasında `Use(RT2)` başarısız olmalı.
8. Eşzamanlılık: `Use(RT_n)` iki kez paralel çağrılırsa **en fazla biri** başarılı olur (linearizability). → stateright/linearizability tester ya da `prop_state_machine!` concurrent modu.

**Yetki yükseltmesi / sıralama:**
9. **Rol atama sırasından bağımsızlık:** aynı rol atama kümesinin *herhangi bir permütasyonu* aynı efektif izin kümesini verir. `proptest`'te: `shuffle` stratejisi + sonuç eşitliği. *(Kanidm'in Critical GHSA-xxwr-vvr3-2g9f'i tam bu ailedendir — set modifikasyonlarının yanlış ele alınması.)*
10. **Monotonluk yok kuralı:** bir kullanıcıdan rol *çıkarmak* hiçbir zaman izin *eklememeli*. (`permissions(roles \ {r}) ⊆ permissions(roles)`)
11. **Deny üstünlüğü (Cedar'ın "forbid overrides permit"i):** herhangi bir uygulanabilir deny varsa sonuç Deny.
12. **Explicit permit:** hiçbir permit uygulanabilir değilse sonuç Deny (default-deny).

**Session:**
13. **Session downgrade imkânsızlığı:** bir session'ın AMR/ACR seviyesi (`pwd` → `mfa` → `hwk`) yalnızca *artabilir*; hiçbir istek dizisi onu düşüremez.
14. Session ID rotation: privilege escalation olayında (login, MFA yükseltme) session identifier değişir.
15. `logout(s)` sonrası `s` ile hiçbir kaynağa erişilemez ve türetilmiş tüm token'lar iptaldir.

**Consent:**
16. **Consent-before-grant:** `authorize` bir `scope` için code döndürüyorsa, ya (a) o scope için kayıtlı bir consent kaydı vardır, ya (b) client "trusted/first-party" olarak işaretlidir. Aksi hâlde consent ekranı gösterilmelidir. *(Bu bir "her yol için" property'sidir — state machine'de `Authorize` geçişinin post-condition'ı.)*
17. Consent geri çekildiğinde (`revoke_consent`), o consent'e dayanan tüm aktif refresh token'lar iptal edilir.

**PKCE / code:**
18. Authorization code **tam olarak bir kez** kullanılabilir; ikinci kullanımda code ve ondan doğan tüm token'lar iptal edilir (RFC 9700). *(Kanidm burada başarısız oldu — OAuch bulgusu.)*
19. `code_verifier`, code'u yaratan `code_challenge` ile eşleşmelidir; challenge yoksa ve client public ise → red.
20. Code, onu isteyen `client_id` ve `redirect_uri` ile bağlıdır; farklı client/redirect ile takas edilemez.

**Kripto/kodlama:**
21. **Round-trip:** `parse(serialize(x)) == x` her `x` için (JWT, SCIM filter, SAML assertion, CBOR attestation).
22. **Idempotent kanonikleştirme:** `canon(canon(x)) == canon(x)`.
23. **Sabit zaman:** `constant_time_eq(a,b)` çalışma süresi `a`/`b` içeriğinden bağımsız (Kani ile kanıtlanabilir kısmı: erken dönüş yok).

#### C.4 Metamorfik test — yetkilendirme için

**Metamorphic Testing (MT)**, oracle problemini çözer: mutlak doğru cevabı bilmek yerine, *girdi değişikliği ile çıktı değişikliği arasındaki ilişkiyi* (Metamorphic Relation, MR) doğrularsınız.

**"Metamorphic Testing for Web System Security"**, IEEE TSE 2023 (Bayati Chaleshtari, Pastore, Goknil, Briand) — OWASP kılavuzlarından ilham alan MR kümesi, MR'ları belirtmek için bir DSL, veri toplama ve otomatik test framework'ü.
- https://arxiv.org/pdf/2208.09505 · https://orbilu.uni.lu/bitstream/10993/54576/1/Nanazin_SecurityMetamorphicTesting_Journal.pdf · https://dl.acm.org/doi/abs/10.1109/TSE.2023.3256322
- Örnek OWASP kaynaklı MR: "bypass authorization schema" — admin arayüzündeki linkleri topla, aynı URL'lere *başka* kullanıcının kimlik bilgileriyle eriş; sonuç 403 olmalı.

**Access control policy mutation testing:** Martin ve ark. ilk olarak access control policy'lerini mutation testing ile test etmeyi önerdi; model-tabanlı testler access-control fault detection değerlendirmelerinde **mutant'ların %99.7'sini öldürdü**.
- Bkz. https://dl.acm.org/doi/abs/10.1145/2851613.2851829 ve "A Survey of Access Control Misconfiguration Detection Techniques" https://arxiv.org/pdf/2304.07704

**Argus için 8 somut metamorfik ilişki:**

| # | MR | Beklenen |
|---|---|---|
| MR1 | Aynı isteği farklı kullanıcının token'ı ile tekrarla | Yetkisiz ise 403/404, asla 200 |
| MR2 | Token'ın `scope`'unu daralt | İzin kümesi ⊆ önceki |
| MR3 | Kullanıcıya *ilgisiz* bir rol ekle | İlgili kaynaktaki karar değişmemeli |
| MR4 | Policy'lerin değerlendirme sırasını permüte et | Karar aynı |
| MR5 | Aynı JWT'yi başlıkta whitespace/alan sırası değiştirerek gönder | Aynı sonuç (veya *ikisi de* red — asla biri kabul biri red) |
| MR6 | `redirect_uri`'ye anlamsal olarak eşdeğer bir normalizasyon uygula (trailing slash yok) | Aynı karar |
| MR7 | Tenant A'daki bir işlem, Tenant B'nin herhangi bir kararını değiştirmemeli | **İzolasyon** — çok kiracılı IdP için en önemli MR |
| MR8 | Zamanı `exp`'in bir saniye ötesine ilerlet | Valid → Invalid, asla tersi |

MR7 özellikle güçlü: rastgele iki tenant üret, tenant A'da rastgele mutasyonlar uygula, B'nin karar vektörünün *bit-bit aynı* kaldığını doğrula.

---

### D) JWT/JOSE PARSER GÜVENLİĞİ

#### D.1 Zafiyet SINIFLARI (Argus'un tehdit modeli tablosu)

| Sınıf | Mekanizma | Kanonik örnek |
|---|---|---|
| **alg=none** | `{"alg":"none"}` ile imza atlanır; büyük/küçük harf varyantları (`NONE`, `nOnE`) filtreleri aşar | Auth0 2015 bültenİ; https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ |
| **Algorithm confusion (RS256→HS256)** | RSA public key'i HMAC secret'ı olarak kullandırma | CVE-2022-23541 (node jsonwebtoken); CVE-2024-33663 (python-jose, OpenSSH ECDSA anahtarları) |
| **Key confusion / DER-vs-PEM** | Farklı anahtar formatlarının yanlış yorumlanması | CVE-2024-33663 |
| **jwk header injection** | Header'daki `jwk` doğrulama adayı olarak kabul edilir → tam token forgery | **CVE-2026-27962** (Authlib, CVSS **9.1**), **CVE-2026-34240** (appsup-dart jose) |
| **jku / x5u injection + SSRF** | Sunucu, saldırgan URL'sinden anahtar çeker; hem forgery hem SSRF primitifi | https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection |
| **kid path traversal / SQLi** | `kid: "../../dev/null"` → boş anahtar; `kid: "' UNION SELECT ..."` | https://www.cerberauth.com/docs/jwtop/vulnerabilities/jwt-kid-injection/ |
| **Empty/nil HMAC key** | Boş secret ile HMAC hesaplanabiliyorsa forgery | **CVE-2026-45363** (ruby-jwt), **CVE-2026-44351**, **CVE-2026-49852** (joserfc) |
| **ECDSA psychic signatures** | `r=0, s=0` reddedilmiyor → her imza geçerli | **CVE-2022-21449** (Java 15-18) |
| **Invalid curve attack (ECDH-ES)** | `epk`'nin eğri üzerinde olduğu doğrulanmıyor → CRT ile private key kurtarma | **CVE-2017-16007** (node-jose <0.9.3) + go-jose, jose2go, Nimbus, jose4j |
| **Billion Hashes / p2c** | PBES2 `p2c` üst sınırsız → CPU tükenmesi | CVE-2023-51775 (jose4j), CVE-2023-52428 (Nimbus), CVE-2023-6681 (jwcrypto), CVE-2023-50658 (jose2go), CVE-2023-49290 (jwx), CVE-2023-50966 (erlang jose), **CVE-2026-27932 (joserfc)** |
| **Compression DoS / zip bomb (`zip=DEF`)** | JWE decompress sınırsız | CVE-2024-28176 (panva/jose), CVE-2024-28180 (go-jose), CVE-2024-29371 (jose4j), CVE-2024-33664 (python-jose "JWT bomb"), CVE-2024-29370 (python-jose), CVE-2024-27663 (jose-jwt), CVE-2024-28122 (jwx), **CVE-2025-63811 (jose2go)** |
| **Billion laughs / deeply nested JSON** | XML/JSON entity/derinlik | **CVE-2025-53864** (Nimbus JOSE+JWT, derin iç içe JSON DoS) |
| **`crit` header yanlış ele alma** | Anlaşılmayan `crit` uzantısı reddedilmeli, sessizce yoksayılmamalı (RFC 7515 §4.1.11) | Sınıf; spesifik CVE aramada çıkmadı **[DOĞRULANMADI]** |
| **JWE-wrapped PlainJWT** | JWE içinden çıkan `alg:none` JWT'nin imzası doğrulanmıyor | **CVE-2026-29000** (pac4j-jwt) |
| **Sign/Encrypt confusion** | Nokta sayısına bakıp JWS'i JWE sanma | CVE-2024-24238 (jose-jwt), CVE-2023-51774 (json-jwt) — NDSS 2026 |
| **JWT Format Confusion** | JWS'in JSON serialization'ını compact sanma | latchset/jose, go-jose, jwx, jwcrypto — NDSS 2026 |
| **Type confusion in claims** | `exp`/`nbf` yanlış tipte gelince "yok" sayılıyor | **CVE-2026-25537 (Rust `jsonwebtoken`!)** — aşağı bak |
| **Timing side-channel HMAC** | Non-constant-time karşılaştırma | GHSA-5vw4-v588-pgv8 (robbert229/jwt); Kanidm GHSA-53hj-r94p-8c8f |

**Not — CVE-2023-51767:** Kullanıcının notunda "Zip bomb / compressed JWE (CVE-2023-51767?)" olarak geçiyor. **Bu YANLIŞ.** CVE-2023-51767 aslında **OpenSSH ≤10.0'da row-hammer tabanlı auth bypass**'tır (`mm_answer_authpassword`'daki `authenticated` integer'ı tek-bit flip'e dayanıklı değil); üstelik satıcı tarafından itiraz edilmiştir ("platform mimari zayıflıklarına karşı savunma uygulamanın sorumluluğu değildir") ve gerçek bir konfigürasyonda sömürülebilirliği gösterilmemiştir.
- https://nvd.nist.gov/vuln/detail/cve-2023-51767 · https://access.redhat.com/security/cve/cve-2023-51767
- **Aradığınız JWE zip bomb CVE'leri yukarıdaki tabloda** (CVE-2024-28176 / 28180 / 29371 / 33664).

#### D.2 Rust crate'leri — RustSec/OSV taraması (8 Eylül 2026, OSV.dev API)

Bu taramayı doğrudan OSV API'sine sorgu atarak yaptım:

| Crate | Advisory | Sonuç |
|---|---|---|
| **`jsonwebtoken`** | **GHSA-h395-gr6q-cpjc / CVE-2026-25537** | ⚠️ **Bkz. D.3 — Argus için en önemli tek bulgu** |
| `josekit` | — | Advisory yok |
| `jwt` | — | Advisory yok |
| `jwt-simple` | — | Advisory yok |
| `jwtk` | — | Advisory yok |
| **`biscuit-auth`** | GHSA-75rw-34q6-72cr / CVE-2022-31053 | **İmza sahteciliği** (Γ-signature kriptanalizi, eprint 2020/1484). v1 → v2 zorunlu geçiş. CVSS 3.1 **9.8**. 17 Haz 2022 |
| **`biscuit-auth`** | GHSA-p9w4-585h-g3c7 / CVE-2024-41949 + CVE-2024-42350 | **Third-party block'ta public key confusion** — kötü niyetli holder `ThirdPartyBlockRequest`'in `publicKeys` alanını değiştirerek üçüncü tarafı yanlış keypair'e güvenen datalog üretmeye kandırır. 4.0.0 ≤ v < 5.0.0. 31 Tem 2024 |
| `openidconnect` | — | Advisory yok |
| `oauth2` | — | Advisory yok |
| `webauthn-rs` | — | Advisory yok |

**Yan ekosistem (IdP'nin bağımlılıkları — hepsi Argus için doğrudan risk):**

| Crate | Advisory | Tarih | Neden Argus'u ilgilendirir |
|---|---|---|---|
| **`quick-xml`** | **RUSTSEC-2026-0194** — start tag'de duplicate attribute kontrolü **O(N²)** | 2026-06-29 | **SAML.** 80.000 attribute ≈ 6 sn; 800.000 ≈ 10 dk. Saf hesaplama, `.await` yok → **I/O timeout'u kesemez.** Birkaç on MB'lık tek bir start tag bir parsing thread'ini saatlerce kilitler. |
| **`quick-xml`** | **RUSTSEC-2026-0195** — `NsReader`'da sınırsız namespace-declaration allocation | 2026-06-29 | **SAML.** `NamespaceResolver::push`, event caller'a *dönmeden önce* çalışır → M byte'lık start tag ≈ **3×M** byte resolver heap'i, caller görmeden. Girdi boyutunu sınırlamak yetmez. Gerçek dünyada NLnet Labs Routinator OOM-kill edildi. |
| **`time`** | **RUSTSEC-2026-0009** — RFC 2822 parse'ta stack exhaustion DoS | 2026-02-05 | JWT/HTTP tarih ayrıştırma. v0.3.47'de recursion depth limiti eklendi. |
| **`rsa`** | RUSTSEC-2023-0071 / CVE-2023-49092 — **Marvin Attack**, timing side-channel ile key recovery | 2023-11-22 | RSA imzalama/şifre çözme |
| **`rsa`** | GHSA-9c48-w39g-hm26 / CVE-2026-21895 — asal 1'e eşitken panic | 2026-01-06 | Anahtar import doğrulaması |
| **`ring`** | RUSTSEC-2025-0009 — overflow checking açıkken bazı AES fonksiyonları panic | 2025-03-06 | |
| **`ring`** | RUSTSEC-2025-0010 — <0.17 unmaintained | 2025-03-05 | |
| **`rustls`** | RUSTSEC-2024-0336 — `complete_io` ağ girdisine bağlı **sonsuz döngü** | 2024-04-19 | TLS terminasyonu |
| **`rustls`** | RUSTSEC-2024-0399 — fragmanlanmış ClientHello'da `Acceptor::accept` panic (0.23.13 regresyonu) | 2024-11-22 | `tokio-rustls` `LazyConfigAcceptor` etkilenir |
| **`openssl` (rust-openssl)** | GHSA-8c75-8mhr-p7r9 — AES key wrap'te hatalı bounds assertion | 2026-04-22 | JWE A128KW/A256KW |
| **`openssl`** | GHSA-4fcv-w3qc-ppgg — `Md::fetch`/`Cipher::fetch` **use-after-free** | 2025-04-04 | **`josekit` OpenSSL tabanlıdır** |
| `serde_cbor` | RUSTSEC-2019-0025 stack overflow; RUSTSEC-2021-0127 **unmaintained** | 2019/2021 | WebAuthn attestation — `ciborium`/`coset`'e geçin |

> **Argus için aksiyon:** `josekit` OpenSSL'e bağlı olduğu için rust-openssl'in tüm CVE yüzeyini miras alır. `jsonwebtoken` saf Rust ama D.3'teki mantık hatasına sahipti. `biscuit-auth`'un iki ayrı kripto-tasarım açığı geçmişi var. **Hiçbiri "güvenle bağımlılık olarak al ve unut" kategorisinde değil.**

#### D.3 🔴 `jsonwebtoken` CVE-2026-25537 — Argus için en öğretici vaka

**GHSA-h395-gr6q-cpjc / CVE-2026-25537**, yayın **3 Şubat 2026**, CVSS v4: `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N` (E:P — PoC mevcut). Etkilenen: `jsonwebtoken` **< 10.3.0** (yani *tüm* geçmiş sürümler). Düzeltme commit'i: `abbc3076742c4161347bc6b8bf4aa5eb86e1dc01`.
- https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc
- https://nvd.nist.gov/vuln/detail/CVE-2026-25537

**Mekanizma:**
```rust
enum TryParse<T> { Parsed(T), FailedToParse, NotPresent }
```
`src/validation.rs` (satır ~288):
```rust
if matches!(claims.nbf, TryParse::Parsed(nbf) if options.validate_nbf && nbf > now + options.leeway) {
    return Err(new_error(ErrorKind::ImmatureSignature));
}
```
`{"nbf": "99999999999"}` (sayı yerine **string**) gönderildiğinde serde `u64`'e parse edemez → `FailedToParse`. `matches!` yalnızca `Parsed(_)`'ı yakaladığı için **koşul false döner, blok atlanır, hata yok**. Yani `validate_nbf = true` olmasına rağmen "Not Before" kontrolü tamamen atlanır. Tek fallback `required_spec_claims` listesidir — ama yaygın kullanım deseni "validate_nbf'i aç, required listesine ekleme"dir. Test ortamı: jsonwebtoken 10.2.0, rustc 1.90.0.

**Neden bu vaka Argus'un tez cümlesi olmalı:**
- Bu bir **memory safety** bug'ı değil. Rust'ın tip sistemi, borrow checker'ı, `unsafe` yasağı — hiçbiri yardımcı olmadı.
- Bu bir **panic** değil. Klasik coverage-guided fuzzing (crash oracle'ı ile) bunu **asla bulamaz**.
- Bunu bulan şey: **tip-karışık claim üreten structure-aware bir generator + "validate_nbf açıksa geçersiz nbf'li token reddedilmeli" property'si**. Yani tam olarak bu raporun C bölümü.
- Diferansiyel test de bulurdu: `panva/jose` bu token'ı reddeder, `jsonwebtoken` kabul ederdi.

**Argus için doğrudan property:**
```
∀ token, ∀ claim c ∈ {exp, nbf, iat, aud, iss, sub, jti}:
  eğer c mevcut ama beklenen tipte değilse
  → validate() Err döner (asla "yok sayıldı" davranışı olmaz)
```

#### D.4 2025–2026 yeni JOSE açıkları (en güncel durum)

| CVE | Kütüphane | Sınıf | CVSS | Tarih | Not |
|---|---|---|---|---|---|
| **CVE-2026-27962** | Authlib (Python) | **jwk header injection → imza doğrulama bypass** | **9.1 Kritik** | 2026 | `key=None` geçildiğinde JWS deserialize, saldırgan kontrollü `jwk` header'ındaki anahtarı kullanıyor. Etkilenen yaygın desen: **JWKS lookup'ta bilinmeyen/rotate edilmiş `kid` için resolver'ın `None` dönmesi.** RFC 7515 §4.1.3 ve §5.2 ihlali. Düzeltme: ≥1.6.9. https://github.com/authlib/authlib/security/advisories/GHSA-wvwj-cvrp-7pv5 |
| **CVE-2026-34240** | appsup-dart `jose` | Aynı sınıf: header `jwk` trusted key store'da olmasa da doğrulama adayı | — | 2026 | Düzeltme: 0.3.5+1. Workaround: header `jwk` varsa ve trusted store'daki bir anahtarla eşleşmiyorsa token'ı reddet. https://www.tenable.com/cve/CVE-2026-34240 |
| **CVE-2026-49852** | joserfc (Python) | **Boş/None anahtar → tam auth bypass**; key finder boş string/None'a çözülürse sahte claim (sub, admin, scope, aud, exp) | 7.4 | 2026 | Sessiz misconfiguration: sunucu boot etmeyi başarır, sadece bir `SecurityWarning` verir. ≤1.6.7 etkilenir, **patch yok** (kaynak tarihinde). |
| **CVE-2026-45363** | ruby-jwt | **Boş anahtarla HMAC bypass** | 7.4 | 2026 | `JWT.decode(token, '', true, algorithm: 'HS256')` sahte token'ı kabul ediyor. `OpenSSL::HMAC.digest('SHA256','',payload)` boş anahtarla geçerli digest dönüyor; **OpenSSL ≥3.5'te artık raise etmediği için** eski rescue devreye girmiyor. HS256/384/512, hem `JWT.decode` hem `EncodedToken#verify_signature!`. Düzeltme: 2.10.3 / 3.2.0. https://github.com/jwt/ruby-jwt/security/advisories/GHSA-c32j-vqhx-rx3x |
| **CVE-2026-44351** | (cross-language sibling) | Aynı boş-anahtar ailesi | — | 2026 | |
| **CVE-2026-29000** | pac4j-jwt (Java) | **JWE-wrapped PlainJWT ile auth bypass** | — | 2026 | Sunucunun RSA **public** key'ini bilen saldırgan, keyfi `sub`/rol claim'leriyle bir PlainJWT'yi JWE'ye sarar; imza doğrulaması atlanır → admin dahil herkes olarak kimlik doğrulama. <4.5.9, <5.7.9, <6.3.3. https://github.com/advisories/GHSA-pm7g-w2cf-q238 |
| **CVE-2026-27932** | joserfc | **PBES2 `p2c` sınırsız** | 7.5 | Advisory 28 Şub 2026; NVD 6 Mar 2026 | `_rfc7518/jwe_algs.py` `PBES2HSAlgKeyEncryption.decrypt_cek()`, `p2c`'yi header'dan doğrudan okuyor, üst sınır yok. `2^31-1` verilebilir. **Claim/imza doğrulamasından ÖNCE** tetiklenir. Önerilen sınır: ~300.000. https://github.com/authlib/joserfc/security/advisories/GHSA-w5r5-m38g-f9f9 |
| **CVE-2025-63811** | jose2go (Go) | Compression DoS | — | 2025 | NDSS 2026 kaynaklı |
| **CVE-2025-53864** | Nimbus JOSE+JWT | Derin iç içe JSON ile DoS | — | 2025 | https://github.com/advisories/GHSA-xwmg-2g98-w7v9 |
| **CVE-2026-55040** | Microsoft SharePoint | JWT token auth bypass; PoC yayınlandıktan sonra **aktif sömürü** | — | 2026 | https://thehackernews.com/2026/08/attackers-exploit-sharepoint.html |

**2026 trendi net:** *header `jwk`/boş anahtar kaynaklı imza doğrulama bypass'ları* patlama yaptı (Authlib 9.1, dart-jose, joserfc, ruby-jwt, pac4j). Bunların ortak paydası: **anahtar seçimi (key resolution) mantığı**, kripto değil. Argus'un anahtar çözümleme katmanı ayrı bir tip olmalı ve şu invaryanta sahip olmalı:

```
∀ token: resolve_key(token) ∈ trusted_key_store
         ∧ resolve_key(token) ≠ ∅
         ∧ resolve_key(token).len() > 0
         ∧ resolve_key(token).alg_family == header.alg.family()
```
ve `Option<Key>` dönen bir resolver'ın `None`'ı **asla** "header'daki anahtarı kullan"a düşmemeli — tip seviyesinde: `resolve() -> Result<TrustedKey, KeyError>`, `Option` değil.

#### D.5 Bir JOSE parser'ını etkili fuzz etmek — somut reçete

**Harness ayrımı (her biri ayrı fuzz target):**
1. `fuzz_jws_compact_decode` — sadece parse, doğrulama yok. Panik/OOM/timeout arar.
2. `fuzz_jws_verify` — sabit, bilinen anahtar seti ile doğrulama. **Oracle: `verify()` `Ok` dönerse, imza gerçekten o anahtarla mı üretilmiş?** Fuzzer'ın anahtarı bilmediği için `Ok` dönmesi *kendi başına* bir bulgudur (`alg=none`, boş anahtar, psychic signature hepsini yakalar).
3. `fuzz_jwe_decrypt` — `p2c`, `zip`, `epk` alanları grammar'da.
4. `fuzz_jose_header_json` — JSON tip karışıklığı (CVE-2026-25537 sınıfı).
5. `fuzz_jwks_parse` — JWKS dokümanı.
6. `fuzz_differential_jose` — Argus vs. referans (aşağı).

**Kritik oracle'lar (sadece "panic yok" yetmez):**
```rust
fuzz_target!(|data: JoseInput| {
    // O1: Round-trip
    if let Ok(t) = parse(&data.bytes) { assert_eq!(parse(&serialize(&t)).unwrap(), t); }

    // O2: ANAHTAR YOKKEN ASLA KABUL ETME
    if verify_with_no_keys(&data.bytes).is_ok() { panic!("SECURITY: accepted with empty keyset"); }

    // O3: alg allowlist zorunlu
    let r = verify(&data.bytes, &KEYS, &Validation::new(&[Algorithm::ES256]));
    if let Ok(tok) = r { assert_eq!(tok.header.alg, Algorithm::ES256); }

    // O4: kaynak sınırı
    let t0 = Instant::now();
    let _ = decrypt(&data.bytes, &KEY);
    assert!(t0.elapsed() < Duration::from_millis(100), "resource DoS");

    // O5: decompress sınırı
    // (zip=DEF çıktısı yapılandırılmış limiti aşmamalı)
});
```

**Grammar/corpus tohumlaması:**
- Seed corpus: RFC 7515/7516/7517/7518/7519 örnekleri + Wycheproof vektörleri + `jwt_tool`/`JWTEditor` payload'ları.
- **Dictionary** (libFuzzer `-dict=`): `"alg"`, `"none"`, `"HS256"`, `"RS256"`, `"dir"`, `"ECDH-ES"`, `"PBES2-HS256+A128KW"`, `"crit"`, `"jku"`, `"jwk"`, `"x5u"`, `"x5c"`, `"kid"`, `"zip"`, `"DEF"`, `"p2c"`, `"p2s"`, `"epk"`, `"enc"`, `"typ"`, `"cty"`, `"nbf"`, `"exp"`.
- **Custom mutator** `zip=DEF` için: decompress → payload'ı mutate et → recompress (Rust Fuzz Book'un kanonik örneği).
- **NDSS 2026'nın FBNF+UCT-Rand yaklaşımını taklit edin:** `p2s` üretildiğinde `p2c`'nin de üretilmesi gerektiğini fuzzer'a *öğretin* — `Arbitrary` impl'inizde alan bağımlılıklarını kodlayın (ör. `enum JweAlg { Pbes2 { p2s: Vec<u8>, p2c: u32 }, EcdhEs { epk: Jwk }, Dir, ... }`). Bu, MCTS olmadan aynı etkinin %80'ini verir.

---

### E) OSS-FUZZ

#### E.1 Kabul kriterleri

Resmî ifade: *"To be accepted to OSS-Fuzz, an open-source project must have a significant user base and/or be critical to the global IT infrastructure."* FAQ ayrıca "critical impact on infrastructure and user security" olan **yerleşik (established)** projeleri kabul ettiklerini, seçim kriterlerinin **uzaktan saldırıya maruziyet** ve **downstream kullanıcı/bağımlı proje sayısı** olduğunu söylüyor.
- https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/ · https://google.github.io/oss-fuzz/faq/

Başvuru gereksinimleri: proje ana sayfası, ana repo URL'si, birincil dil, ve **Google Account ile ilişkili yerleşik bir proje committer'ının** iletişim e-postası.

> **Argus için gerçekçi değerlendirme:** Sıfırdan yazılmış, henüz kullanıcı tabanı olmayan bir IdP **muhtemelen ilk denemede reddedilir**. Strateji: (1) önce kendi CI'nızda ClusterFuzzLite/CIFuzz benzeri bir kurulum yapın, (2) benimsenmeyi büyütün, (3) *ya da* Argus'un kritik alt-crate'lerini (JOSE parser, SCIM filter parser) **ayrı, bağımsız crate'ler olarak** yayınlayın — bunlar başkaları tarafından da kullanılırsa OSS-Fuzz kriterini bağımsız olarak karşılayabilirler. Bu ikinci strateji hem mimari olarak (A.7) hem de OSS-Fuzz açısından doğru.

#### E.2 Rust entegrasyonu — teknik gereksinimler

- **`cargo fuzz` kullanımı beklenir** — doğru compiler flag'leri ve OSS-Fuzz'ın kendi libFuzzer'ına linkleme onunla yapılır.
- Yapı: `fuzz/` dizini, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/*.rs`.
- `project.yaml`: `language: rust`; **yalnızca libFuzzer + AddressSanitizer desteklenir.**
- `Dockerfile`: `FROM gcr.io/oss-fuzz-base/base-builder-rust` (Rust nightly + cargo-fuzz hazır gelir).
- `build.sh`: `cargo fuzz build -O` (release önerilir) → binary'leri `$OUT/`'a kopyala.
- **Zarif kalıp:** fuzzing mantığını `#[cfg(fuzzing)]` bloklarına sarın; test ve fuzz kodunu paylaşmak için `#[cfg(any(test, fuzzing))]`.
- https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/

**Doğrulanmış gerçek örnekler (`project.yaml` dosyalarını doğrudan çektim, 8 Eyl 2026):**
```yaml
# projects/rustls/project.yaml
homepage: "https://github.com/rustls/rustls"
sanitizers: [address]
fuzzing_engines: [libfuzzer]
language: rust
auto_ccs: ["david@adalogics.com", "dirkjan@ochtman.nl", "brian@briansmith.org", ...]
```

```yaml
# projects/ring/project.yaml
sanitizers: [address, memory, undefined]   # ring'de C var, o yüzden 3 sanitizer
```

#### E.3 Argus ile ilgili hangi Rust projeleri OSS-Fuzz'da? (doğrudan doğrulandı)

`https://raw.githubusercontent.com/google/oss-fuzz/master/projects/<isim>/project.yaml` HTTP durum kodları ile:

| Proje | OSS-Fuzz'da? |
|---|---|
| **rustls** | ✅ 200 |
| **ring** | ✅ 200 |
| **quick-xml** | ✅ 200 (SAML için önemli) |
| **serde_json** | ✅ 200 |
| **tokio** | ✅ 200 |
| **httparse** | ✅ 200 |
| **rust-regex** | ✅ 200 |
| **rust-lexical** | ✅ 200 |
| **trust-dns** | ✅ 200 |
| openssl / boringssl (C) | ✅ 200 |
| rust-openssl | ❌ 404 |
| **kanidm** | ❌ 404 |
| josekit / rust-jwt | ❌ 404 |
| rust-webpki | ❌ 404 |
| x509-parser / der-parser / asn1-rs | ❌ 404 |
| ciborium / rust-cbor | ❌ 404 |
| hyper / axum | ❌ 404 |

> **Boşluk analizi:** IdP yığınının tam kalbi — **JOSE, X.509 parse, CBOR/WebAuthn, ASN.1/LDAP BER** — OSS-Fuzz'da **yok**. Argus'un fuzzing yatırımı için en yüksek marjinal getiri tam burada.

#### E.4 Ne kazandırır

- **ClusterFuzz** üzerinde sürekli, ücretsiz fuzzing. Build makineleri: 32 CPU / 28.8 GB RAM. Fuzzing makineleri: **tek çekirdek, hedef başına 2.5 GB RAM sınırı**; ~25 sn timeout veya 2.5 GB → bug raporu.
- **CIFuzz**: OSS-Fuzz'a entegre olduktan sonra tek bir GitHub Actions workflow'u ile her commit ve her PR'da fuzzing.
  - Action'lar: `google/oss-fuzz/infra/cifuzz/actions/build_fuzzers@master` ve `.../run_fuzzers@master`; crash artifact'leri ve **SARIF** çıktısı upload edilir.
  - Varsayılan **10 dakika** toplam fuzzing süresi, tüm fuzzer'lara bölünür.
  - Proje code coverage destekliyorsa CIFuzz **sadece PR'dan etkilenen fuzzer'ları** koşar.
  - **30 günlük eski/public regresyon corpus'unu** OSS-Fuzz'dan yeniden kullanır — bu, sıfırdan başlamaya göre devasa avantaj.
  - Gereksinim: proje OSS-Fuzz'a entegre **ve** GitHub'da barındırılmalı.
  - https://google.github.io/oss-fuzz/getting-started/continuous-integration/
- Bug tracker: varsayılan olarak ayrı OSS-Fuzz tracker (Google hesabı gerekir); `project.yaml` ile GitHub issue'larına opt-in yapılabilir.

#### E.5 Açıklama (disclosure) takvimi

Google'ın standart politikası:
- Bug'lar **proje yazarlarına bildirimden 90 gün sonra** VEYA **fix yayınlandığında** — hangisi önce gelirse — **otomatik olarak public** olur.
- Son tarih hafta sonuna denk gelirse bir sonraki iş gününe kayar.
- Geliştiriciler ilk sürenin bitiminden sonraki 14 gün içinde yama çıkacağını teyit ederse **14 günlük ek süre**.
- https://google.github.io/oss-fuzz/getting-started/bug-disclosure-guidelines/

#### E.6 Ödüller — ÖNEMLİ DEĞİŞİKLİK

**OSS-Fuzz Reward Program 1 Mayıs 2026 itibarıyla SONLANDIRILDI (sunset).** Bu tarihten sonra başvuru kabul edilmiyor. Araştırmacılar **Patch Rewards Program** ve **OSS Vulnerability Rewards Program**'a yönlendiriliyor. Gerekçe olarak "güvenlik ortamının evrimi ve AI-güdümlü otomasyondaki ilerlemeler" gösterilmiş.
- Kaynak: Google Bug Hunters, OSS-Fuzz Reward Program Rules sayfası (arama sonucu snippet'i, Eylül 2026).
- ⚠️ **[KISMEN DOĞRULANDI]** — `https://bughunters.google.com/about/rules/open-source/oss-fuzz-reward-program-rules` şu an **404** dönüyor (bu da sunset ile tutarlı, ama sayfa artık erişilemez olduğu için birincil kaynaktan teyit edemedim). OSS-Fuzz FAQ ve dokümantasyonunda ödül programından hiç bahis yok. Bu maddeyi kritik bir karara dayanak yapmadan önce Google Bug Hunters'ın güncel program listesini kontrol edin.

#### E.7 OSS-Fuzz-Gen / AI ile fuzz hedefi üretimi — 2025-2026

- Framework: LLM'lerle gerçek dünya C/C++/Java/Python projeleri için fuzz target üretir ve OSS-Fuzz platformunda benchmark eder. Desteklenen modeller: Google Vertex AI (code-bison), Gemini serisi (Pro/Ultra/1.5), OpenAI GPT-3.5-turbo/4/4o/4o-mini/4-turbo (Azure varyantları dahil).
- https://github.com/google/oss-fuzz-gen · https://google.github.io/oss-fuzz/research/llms/target_generation/
- **Sonuçlar:** 297 açık kaynak projeden 1.300+ benchmark. **160 C/C++ projesinde** geçerli ve işlevsel fuzz target üretildi; insan yazımı target'lara göre **maksimum %29 satır kapsamı artışı** (phmap'te %205.75 göreli kazanç). **30 yeni zafiyet**, bunlardan biri **CVE-2024-9143 (OpenSSL, 20 yıldır var olan bir hata)**.
- Zaman çizelgesi: Ağustos 2023 framework kuruldu; Ocak 2024 açık kaynak; Kasım 2024 zafiyetler bildirildi; toplamda **26 zafiyet** medyaya duyuruldu. https://www.infosecurity-magazine.com/news/google-oss-fuzz-ai-expose-26/
- Yeni bileşenler: **LLM-driven Function Analyzer** Constraint Satisfaction Ratio'yu %38.9 → **%63.1**'e çıkardı; **Crash Validation Agent** spurious crash'lerin **%65'ini** filtreliyor.
- 2026: ICSE 2026 SEIP'te "Fixing Security Vulnerabilities with Agentic AI in OSS-Fuzz" — https://conf.researchr.org/details/icse-2026/icse-2026-software-engineering-in-practice/27/Fixing-Security-Vulnerabilities-with-Agentic-AI-in-OSS-Fuzz
- ⚠️ **Rust desteği:** OSS-Fuzz-Gen README'sinde belirtilen diller **C/C++, Java, Python**. **Rust listede yok [DOĞRULANDI — yokluğu].** Argus için doğrudan kullanılabilir değil; ama aynı fikri (LLM ile harness taslağı + derleme hatası düzeltme) kendi repo'nuzda uygulayabilirsiniz.

#### E.8 Tipik efor

- İlk entegrasyon: 3 dosya (`project.yaml`, `Dockerfile`, `build.sh`) + mevcut `fuzz/` dizini → **birkaç saat**, eğer `cargo fuzz` zaten kuruluysa.
- Asıl efor **harness yazımında ve oracle tasarımında**, altyapıda değil. Argus için realist tahmin: iyi tasarlanmış 8-12 fuzz target = **2-4 kişi-hafta**, artı sürekli triaj yükü.

---

### F) FUZZING GERÇEKTE NE BULUR — VE NE BULMAZ

#### F.1 Kanıt: Kanidm'in 2026 advisory serisi (hepsi doğrulandı)

Kanidm, Rust ile yazılmış üretim-kalitesinde bir IdP — Argus'un en yakın karşılaştırma noktası. GitHub Security Advisories sayfası (https://github.com/kanidm/kanidm/security/advisories) 10 advisory listeliyor. **Kullanıcının bahsettiği "3 parser stack exhaustion, non-constant-time comparison, XSS, Critical authenticated arbitrary write" tanımı DOĞRU ve teyit edildi.**

| GHSA | Başlık | Şiddet | Tarih | Detay |
|---|---|---|---|---|
| **GHSA-2pm5-6m23-h692** | Unauthenticated stack-overflow crash via SCIM filter parser | **High** | **2 Ağu 2026** | PEG grameri her parantez seviyesinde recurse ediyor. `SCIM_FILTER_MAX_DEPTH = 128` eklenmişti ama limit **kurallara indikten SONRA** kontrol ediliyordu → recursion sınırsız. **~10 KB / ~5000 iç içe parantez** fatal stack overflow. Daemon varsayılan worker stack'i **2 MiB** (8 MiB override'ı comment'li). Öneri: "kabul edilen ağaç derinliğini değil, **recursion'ın kendisini sınırla**" — ya limit'e ulaşınca recurse etmeden reddet, ya da iteratif parser yaz. Yamalı sürüm: yok (advisory tarihinde). |
| **GHSA-qcrp-p3rq-pffr** | Anonymous nested LDAP filter stack overflow aborts kanidmd | **High** (CVSS **7.5**) | **23 Haz 2026** | Kök neden: **`lber` 0.4.2**'de BER wire decoding'de kontrolsüz recursion, derinlik limiti yok. `FramedRead::new(r, LdapCodec::default())` — kanidm'in filter-depth doğrulaması **codec parse'ı bitirdikten SONRA** çalışıyor, çok geç. Anonim client `0xa0` tag'ini **~8.000 kez** iç içe koyan bir SearchRequest gönderiyor; **~32 KB** payload byte-size limitinin altında ama stack'i aşıyor. Etki: hem LDAPS (:3636) hem **HTTPS/OIDC API (:8443)** ölüyor — tüm proses. Etkilenen: ≤1.10.3, yama yok. Ön koşul: `ldapbindaddress` konfigüre edilmiş olmalı (varsayılan kapalı). |
| **GHSA-r5fr-9gmv-jggh** | SCIM filter stack exhaustion → process abort | **High** | 30 Nis 2026 (OSV: 6 May 2026) | **CVE-2026-46689.** Etkilenen crate'ler: `scim_proto`, `kanidm_proto`. Birkaç bin iç içe parantez (**≈4–12 KB**) recursive-descent PEG parser'ı stack guard page'in ötesine itiyor; Rust stack overflow'a `std::process::abort()` ile yanıt veriyor → tüm kanidmd çıkıyor. **Parse, axum'un `Query<ScimEntryGetQuery>` extractor'ında, handler body'sinden ve dolayısıyla her ACL kontrolünden ÖNCE çalışıyor.** Düzeltme: ≥1.9.3. |
| **GHSA-xxwr-vvr3-2g9f** | Incorrect handling of set modifications → authenticated arbitrary writes | **CRITICAL (CVSS 9.3)** | 14 May 2026 | *"A non exhaustive enumeration allowed `Modify::Set` to have its attributes excluded from the requested removed / present sets."* Boş küme her kümenin alt kümesi olduğu için **erişim kontrolü kontrolleri yanlışlıkla geçiyor.** Herhangi bir giriş yapmış kullanıcı, arayabildiği/okuyabildiği nesnelerin attribute'larını değiştirebiliyor. Tüm authenticated kullanıcılar gruplara erişebildiği için → grup üyeliği değiştirip **`system_admins` / `idm_admins`** ile tüm identity DB'sinin kontrolü. Etkilenen: <1.9.3 ve 1.10.1. Yama: ≥1.9.4, ≥1.10.2. **Workaround yok.** Bildiren: kmq. |
| **GHSA-84jc-3hj2-hwc7** | Image upload validators run before authorization; PNG validator panics | Moderate (CVSS **6.9**) | 30 Nis 2026 | İki ayrı hata: (1) `POST /v1/domain/_image` ve `POST /v1/oauth2/{rs_name}/_image` handler'ları, **admin yetkisi kontrolünden ÖNCE** görseli doğruluyor; `VerifiedClientInformation` extractor'ı unauthenticated istekleri kabul ediyor ve validation başarısız olursa authorization hiç çalışmıyor. (2) PNG validator **8 byte'tan kısa** girdide veya chunk-length alanı `u32::MAX`'a yaklaşınca (**integer wraparound**) panic ediyor. Varsayılan build'de sadece task-level panic; ama **`panic = "abort"`** ile build eden downstream'lerde tam unauthenticated proses çökmesi. Etkilenen: v1.1.0-rc.15 → master (edf50b9). Yama: ≥1.9.3. CVE yok. Bildiren: mbarbero. |
| **GHSA-53hj-r94p-8c8f** | Non-constant-time comparison of OAuth2 client_secret | Low (CVSS 3.7) | 30 Nis 2026 | `/oauth2/token` ve `/oauth2/token/introspect` Rust'ın standart `PartialEq` string karşılaştırmasını kullanıyor — **ilk eşleşmeyen byte'ta kısa devre**. Advisory dürüstçe "pratikte sömürülebilir bir zafiyetten çok **hardening** meselesi" diyor: secret'lar 48 karakter yüksek-entropili, karşılaştırma şifreli TLS içinde, ağ jitter'ı tek-byte zamanlamasını fazlasıyla aşıyor. Yama: ≥1.9.3 (constant-time). |
| **GHSA-gpxg-fx2g-qxj2** | Stored HTML injection in "passkey-enrolment" partial via displayname → htmx-driven authenticated request forgery | Moderate | 30 Nis 2026 | XSS/HTML injection |
| **GHSA-x8cg-3c8h-gw55** | OAuth2 trust login provider subject not validated | Low (CVSS v4 **2.3**) | 27 May 2026 | OIDC `login_hint` parametresi **kimlik kanıtı** gibi kullanılıyor — oysa yalnızca "provider UI'ına bir ipucu"dur, güvenlik garantisi yok. `validate_access_token_response`, upstream provider'ın gerçekten *aynı subject*'i doğrulayıp doğrulamadığını kontrol etmiyor. HTTP login view'ı OIDC `id_token`'ı hiç doğrulamıyor, UserInfo'yu çağırmıyor, dönen `sub` claim'ini beklenen değerle karşılaştırmıyor. Saldırı: upstream'de hesabı olan saldırgan, kurbana ait bir login oturumunu başlatır/ele geçirir; upstream'de kendisi olarak kimlik doğrular; client hâlâ kurbanın oturumunu işlerken **kurbanın yerel hesabı için bearer cookie** üretilir. Etkilenen: 1.10.2; yama: 1.11.0-dev. |
| **GHSA-j4gj-f54h-56j5** | Python RADIUS module logs RADIUS passwords and returns cleartext secrets | Low | 27 May 2026 | Sır sızıntısı |
| **GHSA-hh34-7jqq-3f73** | OAuth 2.0 Analysis with OAuch | Low | 23 Haz 2026 | Bkz. B.4 |

**🔍 Kritik gözlem:** Kanidm'in `Cargo.toml` workspace bağımlılıklarında **proptest, quickcheck, arbitrary, libfuzzer — hiçbiri yok**; workspace'te `fuzz/` dizini de yok (raw.githubusercontent 404). Test altyapısı `testkit` + `testkit-macros`.
- https://raw.githubusercontent.com/kanidm/kanidm/master/Cargo.toml
- Sonuç: **üretim-kalitesinde, güvenlik-odaklı bir Rust IdP, 2026'da fuzzing veya property-based testing kullanmıyor** — ve 2026'nın ilk 8 ayında 3 High-severity stack exhaustion + 1 Critical yetki yükseltmesi yedi. **Argus için bu, hem uyarı hem fırsattır.**

#### F.2 Bug sınıfları: fuzzing ne bulur?

**rust-fuzz/trophy-case** (https://github.com/rust-fuzz/trophy-case) — Rust kodunu fuzz ederek bulunan **600+ bug / 200+ crate**. Baskın kategoriler:
- Aritmetik hatalar (overflow/underflow)
- Aralık dışı erişim (index bounds)
- Mantık hataları (yanlış implementasyon)
- **Panic'ler** (unwrap failure, assertion)
- Bellek sorunları (**stack overflow**, OOM)
- UTF-8 işleme

Güvenlik olarak işaretli (❗️) olanlar küçük bir alt küme: capnproto-rust (memory safety), claxon (memory disclosure), lexical (unsafe kodda OOB read), lz4_flex (heap buffer overflow), sxd-document (**use-after-free**), symbolic-minidump (segfault), v_escape ve zune-jpeg (heap buffer overflow). Ana keşif araçları: libFuzzer ve AFL.

**Rust'a özgü gerçek:** Saf, `unsafe`'siz Rust'ta fuzzing'in bulduğu şeyler ezici çoğunlukla **panic = DoS**'tur: `unwrap()` başarısızlıkları, index out of bounds, debug'da aritmetik taşma, **recursion → stack exhaustion → `process::abort()`**. Kanidm'in 2026 tablosu tam olarak bunu gösteriyor: 3/10 advisory stack exhaustion.

**Argus'un kaçınılmaz bug sınıfları (Kanidm + quick-xml + time RUSTSEC'lerinden türetilmiş):**
1. **Recursive-descent parser + kullanıcı girdisi = stack overflow.** SCIM filter, LDAP BER, JSON, XML, JWT nested claims. Rust bunu `abort()` ile karşılar — recover edilemez. **Panik değil, proses ölümü.**
2. **Doğrulama sırası hatası:** parse/validate authorization'dan önce çalışıyor. Kanidm'de **iki kez** oldu (SCIM filter axum extractor'ında; image validator handler'da). Bu bir **mimari** hatadır, fuzzer bunu ancak "unauthenticated istek prosesi öldürüyor" olarak görür.
3. **Algoritmik karmaşıklık DoS:** quick-xml RUSTSEC-2026-0194'ün O(N²) attribute kontrolü. Crash yok, panic yok — sadece CPU. **Fuzzer'ın timeout oracle'ı olmadan bulunamaz.** OSS-Fuzz'ın 25 sn timeout'u bunu yakalar.
4. **Bellek amplifikasyonu:** quick-xml RUSTSEC-2026-0195 — M byte girdi → 3M byte iç heap. Girdi sınırı korumaz. OOM oracle'ı gerekir.
5. **Integer wraparound → panic:** Kanidm'in PNG chunk-length `u32::MAX` vakası.
6. **Tip karışıklığı → sessiz güvenlik atlaması:** `jsonwebtoken` CVE-2026-25537.

#### F.3 Fuzzing'in BULAMADIĞI şeyler

| Bulamaz | Neden | Kanidm'den örnek | Doğru araç |
|---|---|---|---|
| **Mantık hataları / yetki yükseltmesi** | Gözlemlenebilir sinyal (crash) üretmez; fuzzer arama uzayını crash sinyaliyle yönetir | **GHSA-xxwr-vvr3-2g9f (Critical 9.3)** — `Modify::Set`'te boş kümenin her kümenin altkümesi olması. Hiçbir şey çökmez, sadece yanlış "allow" döner | **Property-based / differential testing** (Cedar modeli) |
| **İş mantığı / protokol uyumsuzluğu** | Fuzzing "beklenen davranışı" bilmez | **GHSA-hh34** — authorization code invalidate edilmiyor, PKCE verifier uzunluğu kontrol edilmiyor | **Conformance suite (OpenID), OAuch, spec-based testing** |
| **Kimlik doğrulama mantığı** | Yine oracle yok | **GHSA-x8cg** — `login_hint`'in kimlik kanıtı sanılması, `sub` claim'inin karşılaştırılmaması | **Model checking (Tamarin/ProVerif), stateful PBT** |
| **Zamanlama yan kanalları** | Coverage feedback'i zamanı ölçmez | **GHSA-53hj** — non-constant-time `client_secret` | **`dudect`/`ctgrind` tarzı istatistiksel timing analizi; Kani ile erken-dönüş yokluğu kanıtı; kod review** |
| **XSS / injection (output-side)** | Sunucu çökmez, tarayıcı kurbandır | **GHSA-gpxg** — displayname üzerinden stored HTML injection | **Taint analysis, template auto-escaping (tip seviyesinde), DAST** |
| **Kriptografik tasarım hataları** | Fuzzer "bu imza şeması matematiksel olarak kırık" diyemez | `biscuit-auth` CVE-2022-31053 (Γ-signature) | **Kriptanaliz, Wycheproof vektörleri, formal analiz** |
| **Sır sızıntısı (loglama)** | Çıktı doğru, ama yanlış yere gidiyor | **GHSA-j4gj** — RADIUS parolalarının loglanması | **Tip seviyesinde `Secret<T>` wrapper'ı + `Debug`/`Display` yasağı, log denetimi** |
| **Kapsanmayan kod** | Fuzzer sadece çalıştırdığı yolları görebilir | — | **Coverage-guided harness genişletme, statik analiz** |
| **Multi-request / stateful akışlar** | Tek `&[u8]` girdisi bir OAuth akışını ifade edemez (harness özel tasarlanmazsa) | Refresh token replay | **`proptest-state-machine`, stateright** |

Akademik teyit:
- "Logic bugs do not necessarily exhibit observable signals such as crashes, and fuzzers rely on such signals to guide their search." — https://arxiv.org/pdf/2605.10074 (Agentic Fuzzing: Opportunities and Challenges)
- "Fuzz testing will not reason about business logic." — https://www.akamai.com/blog/security/why-fuzzing-isnt-enough-to-test-your-apis-for-security-issues
- "Fuzzers cannot find bugs in uncovered code." — https://arxiv.org/pdf/2505.22052

> **Sayısal özet, Kanidm 2026 verisiyle:** 10 advisory'nin **4'ünü** iyi kurulmuş bir fuzzing pipeline'ı bulabilirdi (3 stack exhaustion + PNG panic). **6'sını bulamazdı** — ve bunların içinde **tek Critical (9.3)** de var. Yani: *fuzzing, bir IdP'nin güvenlik bütçesinin yaklaşık %40'ını karşılar; kalan %60 property-based/differential/formal/conformance testing ve kod review'a aittir.*

---

### G) ARGUS İÇİN SENTEZ — ÖNCELİKLENDİRİLMİŞ PLAN

#### Katman 0 — Mimari (her şeyin ön koşulu, sıfır araç maliyeti)
- `argus-core`: saf, senkron, no-IO. Parser'lar, token validator, policy engine, state machine. Fuzzing ve PBT buraya uygulanır.
- `argus-http`: axum/tokio, sadece adaptör.
- **Her parser için AÇIK derinlik limiti — recursion'a girmeden ÖNCE kontrol edilerek** (Kanidm GHSA-2pm5'in tam olarak yaptığı hata). Tercihen iteratif/explicit-stack parser.
- **Authorization, parsing'den ÖNCE.** Extractor'larda parse yapmayın (Kanidm SCIM ve image vakaları).
- Anahtar çözümleme: `fn resolve(&self, hdr: &Header) -> Result<TrustedKey, KeyError>` — `Option` yok, `None`→fallback yok. (2026'nın Authlib/joserfc/ruby-jwt/dart-jose açık ailesinin tamamı burada durur.)
- `Secret<T>` tipi, `Debug`/`Display` implement etmez.
- **`panic = "abort"` KULLANMAYIN** üretim build'inde (Kanidm GHSA-84jc'nin downstream riski).

#### Katman 1 — Fuzzing (2-4 kişi-hafta, ~sıfır para)
- `cargo fuzz init --fuzz-engine libafl` (cargo-fuzz ≥0.13.2).
- 10-12 hedef: JWS compact parse, JWS verify (anahtarsız-kabul oracle'ı ile), JWE decrypt (p2c/zip oracle'ları ile), JOSE header JSON tip-karışıklığı, JWKS parse, SCIM filter, SCIM JSON, LDAP BER, SAML XML, CBOR attestation, OAuth query params, redirect_uri matcher.
- Structure-aware: **`mutatis`** (2026 kanıtı: kısa koşularda %36-49 daha iyi) + `arbitrary`.
- Oracle'lar: sadece panic değil — round-trip, anahtarsız-red, alg-allowlist, süre sınırı, bellek sınırı, decompress sınırı.
- Wycheproof vektörlerini seed corpus'a ekleyin.
- CI'da PR başına 10 dk (CIFuzz deseni), nightly'de 6 saat (Cedar deseni).

#### Katman 2 — Property-based testing (3-6 kişi-hafta)
- `proptest` 1.11 + `proptest-state-machine` 0.8.
- **Tutarlı dünya üreticileri** yazın (Cedar'ın en önemli dersi): schema → roller → kullanıcılar → istekler.
- C.3'teki 23 invaryantı `check_invariants()` ve post-condition olarak kodlayın.
- Metamorfik ilişkiler MR1-MR8, özellikle **MR7 (tenant izolasyonu)**.

#### Katman 3 — Differential (4-8 kişi-hafta, en yüksek getiri)
- **Kısa vade:** `ory/hydra` + `node oidc-provider`'a karşı normalize edilmiş diff. B.4'teki 6 yüzey.
- **Orta vade:** OpenID Conformance Suite lokal Docker + OAuch — bunlar zaten yazılmış oracle'lar, bedava.
- **Uzun vade (farklılaştırıcı):** Cedar'ın VGD modelini benimseyin — `argus-core`'un authorization ve token-validation semantiği için ayrı bir executable model (Lean 4 tercih; Cedar'ın Lean modeli test başına 5 μs ve Rust'tan bir mertebe küçük) + gecelik DRT + "modeli/kanıtları/DRT'si güncel olmayan sürüm yayınlanmaz" kuralı.
- **Yayınlanabilir iş:** JWTeemo (NDSS 2026) metodolojisini Rust JOSE ekosistemine uygulayın — 43 kütüphaneli çalışmada **hiç Rust yok**. `jsonwebtoken`, `josekit`, `jwt-simple`, `jose-jwt`, `biscuit` için FBNF-tarzı diferansiyel fuzzing.

#### Katman 4 — Formal (seçici, 2-4 kişi-hafta)
- **Kani** yalnızca küçük-kritik fonksiyonlar: constant-time eq, base64url, varint/length parsing, p2c sınır kontrolü, derinlik sayacı. (Kani contract'ları Rust std doğrulamasında 6 yeni bug buldu.)
- **stateright** çok-düğümlü revocation/session yayılımı için.
- **Tamarin/ProVerif** protokol tasarımı kararlarınız spec'ten sapıyorsa.

#### Katman 5 — OSS-Fuzz (uzun vade)
- Argus'un kritik alt-crate'lerini bağımsız crate olarak yayınlayın; benimseme büyüdükçe OSS-Fuzz başvurusu yapın.
- Boşluk: JOSE, X.509 parse, CBOR/WebAuthn, ASN.1/LDAP BER OSS-Fuzz'da **yok** — burası boş arazi.
- Ödül programı beklentisi kurmayın (OSS-Fuzz Rewards 1 Mayıs 2026'da sunset **[kısmen doğrulandı]**); asıl değer ClusterFuzz + CIFuzz + 30 günlük corpus.

---

### H) DOĞRULANMAMIŞ / DİKKAT EDİLECEK NOKTALAR

1. **OSS-Fuzz Rewards sunset (1 Mayıs 2026)** — kaynak sayfa artık 404. Tek dolaylı kanıt var. Karar öncesi teyit edin.
2. **Nyx'in 2026 durumu** — 2022 sonrası major gelişme kanıtı bulamadım.
3. **`crit` header'ının yanlış ele alınmasına** dair spesifik bir CVE bulamadım (sınıf gerçek, RFC 7515 §4.1.11 gereksinimi net, ama numaralı örnek yok).
4. **OpenFGA / Oso'da property-based/fuzz testing kanıtı yok.** SpiceDB'de consistency test dizinleri var ama metodoloji (PBT mi assertion mı) doğrulanmadı.
5. **`libafl_libfuzzer`'ın Windows desteği** yalnızca standalone kütüphane olarak — Argus Windows hedefliyorsa engel.
6. **Arama sonucu snippet'lerinde iki hata tespit ettim ve düzelttim:** (a) cargo-afl'in "0.15.17 / AFL++ 4.31c" olduğu iddiası yanlış — gerçek: 0.18.2 (2026-05-11) / AFL++ 4.40c. (b) LibAFL sürüm tarihleri GitHub sayfasından yanlış çıkarılmıştı — crates.io API ile doğrulandım (0.16.1 = 2026-08-11).
7. **CVE-2023-51767 JWE ile ilgili DEĞİLDİR** (OpenSSH row-hammer, üstelik satıcı tarafından itiraz edilmiş).
