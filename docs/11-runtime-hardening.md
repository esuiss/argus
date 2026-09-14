# §11 — Runtime ve binary sertleştirme ile izolasyon

## A. Rust binary sertleştirme

### A.1 Rust'ın varsayılan olarak verdikleri

rustc'nin resmî exploit mitigations tablosu şudur:

| Önlem | Destekli | Varsayılan açık | Rust sürümü |
|---|---|---|---|
| Position-independent executable (PIE) | Evet | Evet | 0.12.0 (9 Ekim 2014) |
| Integer overflow kontrolleri | Evet | Hayır; yalnızca debug-assertions açıkken | 1.1.0 (25 Haziran 2015) |
| Non-executable memory (NX) | Evet | Evet | 1.8.0 (14 Nisan 2016) |
| Stack clashing koruması (stack probe) | Evet | Evet | 1.20.0 (31 Ağustos 2017) |
| Read-only relocation ve immediate binding (Full RELRO, BIND_NOW) | Evet | Evet | 1.21.0 (12 Ekim 2017) |
| Heap bozulma koruması | Evet | Evet; işletim sistemi ve allocator kaynaklıdır | 1.32.0 (17 Ocak 2019) |
| Stack smashing koruması (canary) | Evet | Hayır; `-Z stack-protector` gerekir | Nightly |
| Forward-edge CFI | Evet | Hayır; `-Z sanitizer=cfi` gerekir | Nightly |
| Backward-edge (shadow veya safe stack) | Evet | Hayır; `-Z sanitizer=shadow-call-stack,safestack` gerekir | Nightly |

Sonuç şudur: `cargo build --release` ile üretilen Linux binary'si zaten PIE, Full RELRO, NX ve stack probe verir. `checksec` çıktısında Full RELRO, NX enabled ve PIE enabled görülür; eksik olan tek klasik kalem stack canary'dir. Argus için bu, C ve C++ dünyasına göre iyi bir başlangıçtır, ancak en güvenli iddiası için yeterli değildir.

> **Argus için aksiyon.** CI'da her release binary'sinde `checksec --file=target/release/argus` veya `hardening-check` çalıştırılıp beklenen değerleri assert eden bir test yazılır. Regresyon tespiti için kritiktir; özellikle bir gün `-C relocation-model=static` veya özel bir linker script eklenirse PIE sessizce kaybedilir.

### A.2 Stack protector

2026 Eylül itibarıyla stabilize değildir.

Tracking issue rust-lang/rust#114903'tür. Stabilizasyon PR'ı rust-lang/rust#146369'dur ve `-Zstack-protector` seçeneğini `-Cstack-protector` olarak stabilize etmeyi önerir. Açılış 9 Eylül 2025, son force-push 15 Haziran 2026 tarihlidir ve 13 Temmuz 2026 itibarıyla PR `S-blocked` durumundadır; target modifier altyapısına ilişkin PR #157941'e bağlıdır. FCP merge-pending durumundadır ancak tamamlanmamıştır. Compiler ekibi üyelerinden onaylar vardır ancak merge edilmemiştir.

Semantik olarak `-Cstack-protector=strong` Clang'in `-fstack-protector-strong` heuristiğini kullanır; PR notu bu heuristiklerin Rust için tasarlanmadığını ve bazı durumlarda aşırı muhafazakâr olabileceğini söyler.

> **Argus için.** Stack canary'nin Rust'taki değeri sınırlıdır, çünkü canary'nin koruduğu şey stack buffer overflow'dur ve safe Rust'ta bu zaten yoktur. Değeri yalnızca unsafe blokları ve FFI ile bağlanan C kütüphaneleri (PKCS#11 modülleri, aws-lc-rs'in C parçaları) için vardır. Nightly'ye geçme maliyeti bunu haklı çıkarmaz; bunun yerine unsafe ve FFI yüzeyi küçültülür.

### A.3 Control Flow Integrity

Rust Unstable Book'a göre LLVM CFI `-Zsanitizer=cfi` ile etkinleştirilir ve LTO gerektirir (`-Clinker-plugin-lto` veya `-Clto`). Diller arası LLVM CFI de `-Zsanitizer=cfi` ile etkinleştirilir; ancak `-Zsanitizer-cfi-normalize-integers` seçeneğinin Clang'in `-fsanitize-cfi-icall-experimental-normalize-integers` seçeneğiyle birlikte kullanılmasını ve rustc dışı düzgün bir LTO'yu (`-Clinker-plugin-lto`) gerektirir. CFI etkinleştirilirken standart kütüphanenin Cargo build-std özelliğiyle (`-Zbuild-std`) yeniden derlenmesi önerilir.

Özellik yalnızca nightly'dedir. LTO zorunludur ve `-Zbuild-std` şiddetle tavsiye edilir; yani std de yeniden derlenir ve bu, build süresi ile tekrarlanabilirlik maliyeti getirir.

KCFI hedefleri `aarch64-linux-android`, `aarch64-unknown-linux-gnu`, `x86_64-linux-android` ve `x86_64-unknown-linux-gnu`'dur.

ShadowCallStack, yani backward-edge koruması, aarch64'te `x18` register'ının ABI'de rezerve olmasını gerektirir. Desteklenen hedefler `aarch64-linux-android` (bionic runtime'ı vardır), `aarch64-unknown-fuchsia`, `aarch64-unknown-none` (`-Zfixed-x18` zorunludur) ile riscv64 bare-metal ve Fuchsia hedefleridir. `aarch64-unknown-linux-gnu` listede yoktur; yani standart Linux sunucu hedefinde ShadowCallStack pratikte kullanılamaz, çünkü glibc x18'i rezerve etmez.

SafeStack yalnızca `x86_64-unknown-linux-gnu` hedefindedir. 2026'da yeni olarak RealtimeSanitizer (`-Zsanitizer=realtime`) tüm hedeflerde listelenmektedir.

2026 yol haritasında Rust Project Goals kapsamında `-Zsanitizer=kcfi`, `-Zsanitizer-cfi-normalize-integers` ve `-Zfixed-x18` stabilizasyon hedefleri arasındadır. Zaman aralığı 2026-2027, durum kabul edilmiş, champion Wesley Wiser'dır. Belirli bir stabilizasyon tarihi yoktur. Bu hedef kernel ihtiyaçlarına odaklıdır; userspace `-Zsanitizer=cfi` doğrudan hedefte değildir.

Android tarafında LLVM CFI Android 8.1'den beri media stack'tedir, Android 9'da genişletilmiştir ve sistem CFI'sı varsayılan olarak açıktır. Performans açısından Android'de yapılan testlerde LTO ile CFI kombinasyonunun kod boyutuna ve performansa ihmal edilebilir düzeyde ek maliyet getirdiği, birkaç durumda her ikisinin de iyileştiği belirtilmektedir. Ancak bu sayfa Rust kodu için CFI'dan hiç bahsetmemektedir; Android'in Rust bileşenlerinde CFI'ın açık olup olmadığı bu kaynaktan doğrulanamamıştır.

> **Argus için karar.** CFI, yalnızca Rust içeren bir kod tabanında marjinal fayda sağlar, çünkü indirect call hedefleri zaten tip güvenlidir. Gerçek fayda diller arası CFI'dadır: Argus PKCS#11 (HSM) veya `aws-lc-rs` gibi C kodu link ediyorsa, C tarafındaki bir hatanın Rust'taki fonksiyon pointer'larına sıçramasını engeller. Maliyeti nightly, LTO, build-std ve Clang ile eşleştirilmiş bir build'dir; CI karmaşıklığı yüksektir ve tekrarlanabilir build zorlaşır. Öneri v1'de kullanmamak, ancak hardened build adlı opsiyonel bir CI job olarak deneysel tutmak ve HSM ile FFI yüzeyi büyürse yeniden değerlendirmektir.

### A.4 Sanitizer'lar

Hedef desteği şöyledir:

| Sanitizer | Linux x86_64 | Linux aarch64 | Not |
|---|---|---|---|
| AddressSanitizer | Var | Var | — |
| LeakSanitizer | Var | Var | — |
| ThreadSanitizer | Var | Var | Veri yarışı tespiti; tokio için değerlidir |
| MemorySanitizer | Var | Var | `-Zbuild-std` zorunludur ve tüm kod enstrümante edilmelidir |
| HWAddressSanitizer | Yok | Var | Düşük bellek ek maliyeti |
| MemTagSanitizer | Yok | Var | `-C target-feature=+mte` gerekir |
| DataFlowSanitizer | Var | Yok | — |

Hepsi yalnızca nightly'dedir. Kullanım `RUSTFLAGS=-Zsanitizer=<name> cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu` biçimindedir.

> **Argus için.** ASan, LSan ve TSan test süiti üzerinde haftalık bir gecelik CI job olarak çalıştırılır. Maliyeti yaklaşık 2-3 kat yavaşlık ve nightly toolchain bakımıdır. Faydası unsafe ve FFI kodunda gerçek bellek hataları ile tokio kodunda veri yarışlarını yakalamaktır. MSan atlanır; `-Zbuild-std` ile tüm bağımlılıkların enstrümante edilmesi gereksinimi ring ve aws-lc-rs gibi C kütüphaneleri yüzünden pratikte kırılır.

### A.5 `overflow-checks` ve `panic`

Cargo varsayılanları şunlardır:

```toml
[profile.release]
opt-level = 3
debug = false
split-debuginfo = '...'  # platforma özgüdür
strip = "none"
debug-assertions = false
overflow-checks = false   # dikkat
lto = false
panic = 'unwind'
incremental = false
codegen-units = 16
rpath = false
```

`overflow-checks = false` demek, release'te `u32` taşmasının panic etmeyip sarmalanması demektir. Bir IdP'de bu doğrudan güvenlik sorunudur: token sayaçları, oturum TTL aritmetiği, rate limit sayaçları, `len - offset` hesapları ve kota kontrolleri etkilenir. Rust'ta wraparound tanımlı davranıştır, tanımsız davranış değildir; ancak mantık hatası üretir ve bir IdP'de mantık hatası yetki atlatması demektir.

Maliyeti genelde %1-5 arası CPU'dur ve iş yüküne bağlıdır; kripto sıcak döngülerinde daha fazladır. Argus gibi I/O ve Argon2 baskın bir sistemde ölçülemeyecek kadar küçüktür.

`panic` kararı iki seçenek arasındadır. `panic = "unwind"` varsayılandır; panic bir thread'i öldürür, tokio task'ı düşer ve süreç yaşamaya devam eder. Ancak `catch_unwind` ile yakalanmayan bir unwind kilitlenmiş mutex'leri zehirli bırakır ve unsafe kodda yarım kalmış invariantlar oluşturabilir. `panic = "abort"` sürecin ölmesine yol açar; güvenlik açısından daha temizdir, çünkü fail-closed davranır ve tutarsız durumda devam edilmez, binary daha küçük ve hızlıdır, ancak DoS yüzeyini büyütür, çünkü tek bir panic tüm süreci düşürür.

> **Argus için öneri.** `overflow-checks = true` mutlaka açılır. `panic` için `unwind` bırakılır, ancak panic asla bir DoS vektörü hâline getirilmez; yani panic'e giden yollar (`unwrap`, `expect`, indexing, slicing) handler kodunda `clippy::unwrap_used`, `clippy::expect_used`, `clippy::indexing_slicing`, `clippy::panic` ve `clippy::integer_arithmetic` lint'leriyle yasaklanır. Ayrıca tokio'nun `unhandled_panic = ShutdownRuntime` davranışı bilinçli olarak seçilir. `abort` seçilirse tek bir parser panic'i tam DoS'a dönüşür; F bölümüne bakınız.

### A.6 Intel CET

64 bit kernel'de yalnızca userspace shadow stack ve kernel IBT desteklenmektedir.

Uygulama bir ELF note ile işaretlenir: `readelf -n <binary> | grep -a SHSTK` komutu `properties: x86 feature: SHSTK` çıktısını vermelidir. Kernel bu işareti doğrudan işlemez; loader, yani glibc ld.so veya statik runtime, `arch_prctl` ile açar.

`arch_prctl` arayüzü yalnızca 64 bittedir ve `ARCH_SHSTK_ENABLE`, `ARCH_SHSTK_DISABLE`, `ARCH_SHSTK_LOCK`, `ARCH_SHSTK_UNLOCK` (yalnızca ptrace ile) ve `ARCH_SHSTK_STATUS` çağrılarını içerir. Özellikler `ARCH_SHSTK_SHSTK` ve `ARCH_SHSTK_WRSS`'tir. Toolchain gereksinimi Binutils 2.29 ve üstü veya LLVM 6 ve üstüdür.

> **Argus için kritik nokta.** rustc'nin ürettiği object dosyalarının `GNU_PROPERTY_X86_FEATURE_1_SHSTK` ve IBT property note'unu taşıyıp taşımadığı bu araştırmada doğrulanamamıştır. Pratikte binary'de bu note yoksa glibc shadow stack'i açmaz ve CET koruması hiç devreye girmez. Yapılacak yerel doğrulama şudur:
>
> ```bash
> readelf -n target/release/argus | grep -A2 'GNU_PROPERTY\|x86 feature'
> ```
>
> Note yoksa linker'a `-Wl,-z,force-bti` benzeri bir zorlamayla veya tüm object'lerin property taşıması sağlanarak eklenmelidir. Bu Argus'ta ölçülmeli ve raporlanmalıdır; çoğu Rust projesi bunu hiç kontrol etmemektedir. Aynı doğrulama aarch64 için BTI tarafında da geçerlidir (`-Z branch-protection=bti,pac-ret`).

### A.7 Önerilen build reçetesi

`relocation-model` varsayılanı `pic`'tir; relocation modeli `pic` ise ve hedef PIE destekliyorsa linker'a `-pie` verilir. Bu değiştirilmez.

`control-flow-guard` yalnızca Windows'tadır ve varsayılan olarak kapalıdır.

`strip` hakkında dokümantasyonun kendi uyarısı şudur: debuginfo'nun kaldırılması yalnızca dostane introspection'ı etkiler ve güvenlik veya karartma için güvenilmemelidir. Yani strip bir güvenlik kontrolü sayılmaz, yalnızca imaj boyutu içindir.

```toml
# Cargo.toml
[profile.release]
overflow-checks = true      # IdP için zorunlu
debug-assertions = false
lto = "fat"                 # CFI'ye ileride geçilirse zaten gerekir
codegen-units = 1           # LTO ile tutarlı, biraz daha iyi kod
panic = "unwind"            # bilinçli seçim, A.5'e bakınız
strip = "debuginfo"         # sembolleri değil: panic backtrace'leri korunur
```

```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = [
  "-C", "link-arg=-Wl,-z,relro",
  "-C", "link-arg=-Wl,-z,now",          # BIND_NOW — zaten varsayılan, açıkça pekiştirilir
  "-C", "link-arg=-Wl,-z,noexecstack",
  "-C", "link-arg=-Wl,-z,separate-code",
  "-C", "link-arg=-Wl,--as-needed",
  "-C", "force-frame-pointers=yes",     # profil ve crash analizi, bazı CFI araçları
]
```

`-z,relro` ve `-z,now` Rust'ta 1.21.0'dan beri zaten varsayılandır, ancak açıkça belirtmek regresyona karşı bir sigortadır ve mold, lld ile wild gibi bazı özel linker'larda varsayılan farklılaşabilir.

---

## B. Süreç izolasyonu

### B.1 seccomp-bpf ve Rust ekosistemi

| Crate | Son sürüm | Tarih | İndirme | Değerlendirme |
|---|---|---|---|---|
| seccompiler | 0.5.0 | 7 Mart 2025 | Aylık yaklaşık 2,1 milyon; 229 crate kullanır | Sahibi rust-vmm organizasyonudur (Andreea Florescu, Alin Dima, petreeftime). Saf Rust'tır ve C bağımlılığı yoktur. Hedefleri little-endian x86_64, aarch64 ve riscv64'tür. Tek bağımlılığı `libc`'dir; JSON için opsiyonel serde ve serde_json eklenir. En olgun seçenektir |
| libseccomp | 0.4.0 | — | Toplam yaklaşık 1,2 milyon | C `libseccomp` binding'leridir; sisteme kütüphane kurmayı gerektirir ve statik veya distroless imajda sorun çıkarır |
| syscallz | 0.17.0 | Yaklaşık iki yıl önce | Toplam 100.000 | Bakımsız görünmektedir |
| extrasafe | 0.5.1 | 16 Nisan 2024 | Aylık yaklaşık 5.500 | Harry Stern ve üç katkıcı tarafından geliştirilmektedir. Seccomp, Landlock ve user namespace'leri tek bir ergonomik API'de birleştirir (`SafetyContext`, `Isolate`, `RuleSet`). Ancak yalnızca x86_64 destekler, kullanımı çok düşüktür ve 2024'ten beri release çıkmamıştır |

**Gerçek dünya örneği: Firecracker.** `seccompiler` kullanmaktadır. Filtreler thread bazında yüklenir: VMM thread'i, API thread'i ve VCPU thread'leri, her biri kendi ana işine başlamadan hemen önce. Filtreler `resources/seccomp` altında JSON olarak tutulur, build zamanında derlenip binary'ye gömülür. Politika, Firecracker'ın doğru çalışması için gereken asgari sistem çağrısı ve parametre kümesidir. Dokümantasyonun uyarısına göre thread'e özel filtreleme yanlış yapılandırılırsa süreç aniden sonlandırılabilir veya seccomp güvenlik sınırı tamamen devre dışı kalabilir. Debug binary'leri ve deneysel GNU hedefleri varsayılan filtre olmadan gelir.

### B.2 Tokio tabanlı HTTP sunucusunda seccomp

Bu araştırmadan çıkan en önemli operasyonel uyarı io_uring ile ilgilidir.

**io_uring seccomp'u bypass eder.** Yapılmayan sistem çağrıları filtrelenemez. io_uring, `connect()`, `openat()` ve `read()` gibi işlemleri opcode olarak submission queue'ya yazar ve tek bir `io_uring_enter` çağrısıyla gönderir. seccomp sistem çağrısı numarasına baktığı için bu opcode'ları göremez.

Azaltmalar şunlardır. Uygulama, güvenilmeyen girdi almadan önce kendi io_uring yeteneklerini `io_uring_register_restrictions` ile kısıtlar. Docker ve containerd varsayılan seccomp profili `io_uring_setup`, `io_uring_enter` ve `io_uring_register` çağrılarını zaten bloklar; Docker dokümantasyonu bunu container'dan kaçmak için sömürülebilecek güvenlik açıkları nedeniyle bloklandığı biçiminde gerekçelendirir.

> **Argus için mimari karar.** io_uring kullanılmaz. Standart tokio epoll backend'inde kalınır. Nedenleri şunlardır: seccomp politikası anlamlı kalır; container runtime'ları io_uring'i zaten bloklar ve dağıtım kırılır; io_uring'in kendi kernel CVE geçmişi bir IdP için kabul edilemez risktir. Tokio blogunda belirtilen yaklaşık %60'lık performans iyileşmesi bir IdP'de zaten Argon2 ve kripto baskın olduğu için önemsizdir.

Tokio ve epoll için asgari sistem çağrısı seti allowlist yaklaşımıyla şudur: `epoll_create1`, `epoll_ctl`, `epoll_wait` veya `epoll_pwait`, `accept4`, `read` veya `recvfrom`, `write`, `sendto` veya `writev`, `close`, `fcntl`, allocator için `mmap`, `munmap`, `mremap` ve `brk`, `futex`, `clock_gettime`, `getrandom`, `sched_yield`, `madvise`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `exit_group`, `restart_syscall`, `eventfd2`, `timerfd_*`, `setsockopt`, `getsockopt` ve `shutdown`. Bu liste literatürden derlenmiş genel bir çerçevedir; Argus'un tam seti ancak `strace -f -c` ile ölçülerek çıkarılır ve doğrulanmamış olarak işaretlenip deneysel olarak üretilmelidir.

Pratik strateji iki fazlıdır. Birinci faz başlatmadır: yapılandırma okunur, TLS sertifikaları yüklenir, veritabanı bağlantı havuzu kurulur, port bind edilir ve anahtar materyali belleğe alınır. İkinci faz servistir: `no_new_privs` ayarlanır, capability'ler düşürülür, Landlock uygulanır, ardından seccomp filtresi yüklenir ve tokio runtime'ı başlatılır.

Kritik nokta şudur: seccomp tokio runtime thread'leri spawn edilmeden önce yüklenirse `SECCOMP_FILTER_FLAG_TSYNC` bayrağıyla tüm thread'lere yayılır. `seccompiler`'ın `apply_filter` fonksiyonu TSYNC kullanır. Yükledikten sonra spawn edilen thread'ler filtreyi zaten miras alır.

### B.3 Capability düşürme, no_new_privs ve setuid

`caps` crate'i 0.5.6 sürümündedir (17 Ekim 2025). Luca Bruno ve 12 katkıcı tarafından geliştirilmektedir, aylık yaklaşık 2,3 milyon indirme alır ve 1.182 crate tarafından kullanılır; Unix API kategorisinde 20. sıradadır. Saf Rust'tır ve harici C kütüphanesi gerektirmez; bu, statik ve musl build için önemlidir. Effective, Permitted, Inheritable, Ambient ve Bounding setlerinin tamamını destekler.

`no_new_privs` için `nix` 0.31.3'ün `nix::sys::prctl` modülü `set_no_new_privs()`, `get_no_new_privs()` ile birlikte `set_dumpable()`, `set_keepcaps()`, `set_pdeathsig()`, `set_name()` ve `set_thp_disable()` sunar. `process` özelliği gerekir ve modül yalnızca Linux'tadır.

> **Argus sıralaması.** Sıra önemlidir.
>
> 1. `prctl(PR_SET_DUMPABLE, 0)` çağrılır; core dump'ta özel anahtar sızmaz.
> 2. 443 portu bind edilir (root veya `CAP_NET_BIND_SERVICE` ile); daha iyisi hiç root olmamak ve `net.ipv4.ip_unprivileged_port_start` veya socket activation kullanmaktır.
> 3. `prctl(PR_SET_NO_NEW_PRIVS, 1)` çağrılır; seccomp'tan önce zorunludur, çünkü ayrıcalıksız seccomp bunu gerektirir, ayrıca setuid binary'lerle ayrıcalık yükseltmesini kapatır.
> 4. Bounding set tamamen temizlenir (`caps::clear(None, CapSet::Bounding)`), ardından Permitted, Effective, Inheritable ve Ambient sıfırlanır.
> 5. `setgroups([])`, `setgid` ve `setuid` bu sırayla çağrılır; ters sıra klasik bir güvenlik hatasıdır.
> 6. Landlock uygulanır.
> 7. seccomp uygulanır.

### B.4 Namespace'ler ve unshare

`unshare` crate'i 0.7.0 sürümündedir ve son release 4 Mayıs 2021 tarihlidir; aylık yaklaşık 2.100 indirme alır ve beş crate tarafından kullanılır. Fiilen bakımsızdır ve Argus'ta kullanılmaz. `extrasafe`'in `Isolate` yapısı ayrıcalıksız bir user namespace başlatır, ancak extrasafe'in kendisi düşük olgunluktadır.

> **Argus için.** Namespace izolasyonu uygulama içinde çözülmeye çalışılmaz. Bu, container runtime'ının (containerd, CRI-O) ve Kubernetes'in işidir. Uygulama katmanında Landlock, seccomp ve capability drop yapılır; namespace platforma bırakılır. `unshare`'i kendimiz yapmak PID 1 reaping, mount propagation ve `/proc` yeniden mount gibi birçok ince hata kaynağı açar.

### B.5 Ayrıcalık ayrıştırma mimarisi

**Gerçek dünya kanıtı.** OpenSSH 9.8 (1 Temmuz 2024) release notuna göre sunucu bir dinleyici binary'si olan sshd ile oturum başına çalışan `sshd-session` binary'sine bölünmüştür; bu, dinleyici binary'nin çok daha küçük olmasını sağlar, çünkü artık SSH protokolünü desteklemesi gerekmez.

Aynı release'te CVE-2024-6387 (regreSSHion) ele alınmıştır: Portable OpenSSH'in 8.5p1 ile 9.7p1 arasındaki sürümlerinde sshd'de root ayrıcalıklarıyla keyfi kod çalıştırmaya imkân verebilecek kritik bir zafiyet bulunmaktaydı. 32 bit Linux ve glibc ile ASLR ortamında ortalama altı ile sekiz saatlik sürekli bağlantıyla sömürülebilmiştir. Bu bölünme doğrudan bu sınıf hataya mimari cevaptı.

Ayrıca OpenSSH güvenlik sayfası CVE-2023-38408 (ssh-agent PKCS#11 RCE, 19 Temmuz 2023) için bunun sömürülebilir olduğuna inanılmadığını ve zafiyetin `chroot(2)` uygulanan ve çoğu büyük platformda ayrıca sandbox'lanan ayrıcalıksız ön kimlik doğrulama sürecinde bulunduğunu belirtir. Ayrıcalık ayrıştırma bir RCE'nin etkisini fiilen sıfırlamıştır.

> **Argus için değerlendirme: evet, değerlidir, ancak seçici olarak.**
>
> Rust'ta bellek güvenliği zaten vardır, dolayısıyla buffer overflow'u hapsetme argümanı OpenSSH'teki kadar güçlü değildir. Ancak iki gerçek gerekçe kalmaktadır.
>
> **Anahtar materyali süreç ayrımı; yüksek değerlidir.** İmzalama anahtarları HTTP sürecinin adres alanında hiç bulunmaz. Ayrı bir `argus-signer` süreci Unix domain socket üzerinden `SCM_CREDENTIALS` ile kimliği doğrulanmış istek alır, yani bu claim setini imzala isteğini. Kendi Landlock domain'i vardır: hiçbir dosya yazamaz, yalnızca key store'u okur. Kendi seccomp filtresi vardır: ağ sistem çağrıları tamamen yasaktır (`socket`, `connect`, `sendto` yoktur) ve bu, anahtar sızdırmayı fiziksel olarak imkânsız kılar. Bir Spectre veya yan kanal, bir unsafe hatası ya da bir PKCS#11 FFI sorunu HTTP sürecini ele geçirse bile anahtarlar okunamaz. Bonus olarak bu süreç Argon2 hesaplamasını da yapabilir ve bellek bütçesi ayrı sınırlanır; G bölümüne bakınız.
>
> **Parser izolasyonu; orta değerlidir.** SAML ve XML gibi tarihsel olarak sorunlu formatlar ayrı ve yok edilebilir bir worker sürecinde ayrıştırılır. Bir stack exhaustion abort'u tüm IdP'yi değil, yalnızca o worker'ı öldürür. Bu, F bölümündeki Kanidm CVE'sinin tam çözümüdür. Chromium'un site isolation'ı ve Firefox'un RLBox'ı bu modeli izler.
>
> **Maliyeti** IPC gecikmesi (Unix socket yaklaşık 10-50 µs, imza başına kabul edilebilir), süreç yaşam döngüsü yönetimi ve dağıtım karmaşıklığıdır; container'da iki süreç PID 1 reaping ile bir supervisor veya sidecar deseni gerektirir. Kanidm ve Rauthy'nin ikisi de bunu yapmamaktadır; Argus en güvenli iddiasındaysa burada gerçek bir farklılaşma vardır.

---

## C. Landlock

### C.1 ABI seviyeleri

| ABI | Kernel | Eklenen |
|---|---|---|
| 1 | 5.13 | Temel dosya sistemi: `EXECUTE`, `WRITE_FILE`, `READ_FILE`, `READ_DIR`, `REMOVE_DIR`, `REMOVE_FILE`, `MAKE_*` |
| 2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER`; dizinler arası link ve rename |
| 3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 4 | 6.7 | Ağ: `LANDLOCK_ACCESS_NET_BIND_TCP`, `LANDLOCK_ACCESS_NET_CONNECT_TCP` |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| 6 | 6.12 | IPC kapsamlama: `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` |
| 7 | 6.15 | Logging bayrakları; exec takibi ve subdomain kısıtlaması |
| 8 | 7.0 | `LANDLOCK_RESTRICT_SELF_TSYNC`; çok thread'li zorlama |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`; pathname socket |
| 10 | Kernel dokümanı | UDP kısıtlamaları (`BIND_UDP`, `CONNECT_SEND_UDP`) ve quiet rule bayrakları |
| 11 | Kernel dokümanı | `no_new_privs`'in ruleset zorlamasına entegrasyonu |

Man sayfası 1 ile 8 arasını listelemekte, kernel dokümanı 9, 10 ve 11'i de göstermektedir. 2026 durumu ABI 11'dir.

### C.2 Landlock'un yapamadıkları

Kernel dokümanından kapsam şudur. Kısıtlanamayan işlemler `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl` ve `access`'tir. `mount` ve `pivot_root` sandbox'lı thread'ler için kısıtlanamaz. `/proc` üzerinden erişilen özel dosya sistemleri (pipe, socket, nsfs) açıkça kısıtlanamaz; ptrace kısıtlamaları dolaylı koruma sağlar. Katman yığını 16 ile sınırlıdır. Truncate ve ioctl hakları yalnızca yeni açılan dosya tanıtıcılarına uygulanır, mevcut stdin, stdout ve stderr'e uygulanmaz. OverlayFS katmanları bind mount'lardan bağımsız değerlendirilir.

### C.3 `landlock` Rust crate'i

Resmî binding'lerdir ve Landlock'un kernel'daki yazarı Mickaël Salaün tarafından `landlock-lsm/rust-landlock` deposunda geliştirilmektedir.

Sürüm 0.4.7'dir ve 27 Temmuz 2026'da yayımlanmıştır; ABI v9'a kadar destekler.

Best-effort modelinde `Ruleset`, çalışan kernel'in özellikleriyle çağıranın gerektirdiklerinin kesişimine göre uyumluluğu belirler.

Sınırlama beyanı şudur: crate, Linux 7.1 itibarıyla mevcut Landlock özelliklerini (ABI v9) açar ve gelecekteki kernel sürümleriyle giderilecek bazı kernel sınırlamalarını miras alır; örneğin keyfi mount'lar her zaman reddedilir.

İleriye dönük uyumluluk uyarısı şudur: `BitFlags::all()` gibi hareketli hedeflere güvenilmez, hedef ABI açıkça belirtilir; aksi hâlde `cargo update` sessizce yeni erişim haklarını etkinleştirebilir.

### C.4 Landlock thread bazlıdır

Bu, raporun en önemli operasyonel bulgularından biridir.

Dokümantasyona göre varsayılan olarak `landlock_restrict_self()` yalnızca çağıran thread'i kısıtlar. Landlock ABI v8, yapılandırmayı sürecin her thread'inde atomik olarak zorlamak için `all_threads()` eklemektedir. Daha eski bir kernel'de bu, varsayılan best-effort modunda sessizce düşürülür ve kardeş ile ebeveyn thread'ler kısıtlanmamış kalır; bu garantiye ihtiyaç duyan çok thread'li programlar bunu zorunlu kılmalıdır.

Argus için anlamı şudur. Tokio çok thread'li runtime'ında Landlock worker thread'lerden birinde uygulanırsa diğer worker'lar kısıtlanmamış kalır ve sandbox tamamen anlamsız olur. ABI v8, yani `all_threads()`, Linux 7.0 gerektirir ve 2026'da bu hâlâ çok yeni bir kernel'dir; çoğu üretim ortamı (RHEL 9 ve 10, Ubuntu 24.04 ve 26.04 LTS) daha eski kernel çalıştırıyor olabilir. Best-effort modunda `all_threads()` eski kernel'de sessizce düşürülür ve sandbox olduğu sanılırken olmaz; bu sessiz bir güvenlik başarısızlığıdır.

> **Argus için doğru çözüm iki katmanlıdır.**
>
> Landlock, tokio runtime'ı başlatılmadan önce ana thread'de uygulanır. Landlock domain'i `fork` ve `clone` ile miras alınır, dolayısıyla sonradan spawn edilen tüm tokio worker'ları kısıtlamayı devralır. Bu, ABI 8 gerektirmeyen ve 5.13 ve üstü tüm kernel'lerde çalışan yaklaşımdır.
>
> Ek olarak kernel destekliyorsa `all_threads()` istenir; ancak `CompatLevel::HardRequirement` ile istenir ve düşürülürse başlangıçta hata verilir, yani best-effort ile sessiz düşürmeye izin verilmez. Asgari garanti seviyesi — örneğin ABI 1 zorunlu, ağ kısıtlaması için ABI 4 opsiyonel — log'a yazılır ve `/healthz` üzerinden raporlanır.

### C.5 Landlock kullanan projeler

Doğrulanabilenler şunlardır. Island, Landlock projesinin kendi sandbox aracıdır ve Firefox çalıştırabilmektedir. Landrun, Go tabanlı bir CLI sandbox'tır ve systemd servislerini desteklemektedir. extrasafe opsiyonel bir Landlock özelliği sunar. Kernel dokümantasyonunda sistem genelinde yönetim sayfası bulunmaktadır, yani distro entegrasyonu olgunlaşmıştır.

> **Doğrulanamadı.** systemd, Docker, Firefox (doğrudan) ve sudo-rs'in Landlock kullandığı bu araştırmada doğrulanamamıştır. Bu benimsemeler için kesin kanıt bulunamamıştır ve iddia edilmemelidir.

### C.6 Argus için pratik Landlock politikası

```
İzin verilen (salt okunur):
  /etc/argus/            → yapılandırma, TLS sertifikası ve anahtarı (yalnızca READ_FILE)
  /usr/share/argus/      → statik varlıklar, şablonlar
  /etc/ssl/certs/        → CA bundle (upstream OIDC ve LDAP doğrulaması için)

İzin verilen (okuma ve yazma):
  /var/lib/argus/db/     → yalnızca veritabanı dosyaları (gömülü DB kullanılıyorsa)
  /run/argus/            → Unix socket (signer sürecine)

Başka her yer yasaktır:
  → /etc/shadow ve /etc/passwd okunamaz
  → /proc/self/mem ve /proc/*/environ okunamaz (ancak /proc kısıtlaması sınırlıdır, C.2)
  → /tmp yazılamaz (memfd kullanılır)
  → hiçbir yere yazma veya çalıştırma yoktur

Ağ (ABI 4 ve üstü, kernel 6.7 ve üstü):
  BIND_TCP:    yalnızca 8443 (ve varsa metrics portu)
  CONNECT_TCP: yalnızca 5432 (Postgres), 636 (LDAPS), 443 (upstream OIDC)
  → Bu, bir SSRF'yi veya veri sızdırmayı port düzeyinde keser.

IPC (ABI 6 ve üstü, kernel 6.12 ve üstü):
  LANDLOCK_SCOPE_SIGNAL               → başka süreçlere sinyal gönderilemez
  LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET → abstract socket'lere bağlanılamaz
```

Maliyeti çalışma zamanında pratik olarak sıfırdır; path lookup'ta ek bir LSM hook'u vardır. Geliştirme maliyeti bir günlük iş ve kernel matrisinde testtir. Fayda maliyet oranı bu raporda en yüksek olan tekniktir.

> **Uyarı.** Landlock `CONNECT_TCP` ile TCP portlarını kısıtlar, IP adreslerini değil. SSRF savunması için tek başına yeterli değildir; uygulama katmanında da IP allowlist ve DNS rebinding koruması gerekir.

---

## D. Container sertleştirme

### D.1 musl allocator problemi

Bu, statik musl binary ve scratch imaj reçetesinin en büyük tuzağıdır.

Ölçümler şöyledir. Gerçek uygulama benchmark'ında musl glibc'den yedi kat yavaştır. Sentetik çok thread'li yükte, 48 çekirdekte yaklaşık 700 kat yavaştır. Sekiz çekirdekli sistemde dört kat yavaştır. Voluntary context switch sayısı 199.786'ya karşı 1.196'dır, yani 167 kat fazladır. Futex'te geçen süre 6,7 saniyeye karşı 0,5 saniyedir, yani 13 kat fazladır.

Kök neden, birden çok thread'ten bellek ayırırken veya bırakırken musl'da paylaşılan bir kilit için yaşanan çekişmedir. Yavaşlama thread sayısı ve ayırma sıklığıyla doğru orantılıdır.

Kritik ek bulgu şudur: musl'un yeni mallocng allocator'ı (musl v1.2.1, Rust'ın Mayıs 2023'te benimsediği sürüm) bu sorunu çözmemiştir.

Daha eski ve aynı yöndeki bir ölçüm yaklaşık 30 kat yavaşlama göstermiş ve thread'lerin CPU'nun yalnızca %20-40'ını kullandığını tespit etmiştir.

> **Argus için.** Bir IdP tanım gereği çok thread'li ve yüksek ayırmalı bir servistir; her HTTP isteği JSON ve JWT ayırması, her Argon2 hash'i büyük ayırma yapar. musl'ı varsayılan allocator'ıyla kullanmak kabul edilemez.
>
> Üç seçenek tercih sırasıyla şudur. Birincisi glibc ile distroless `base-nossl` veya `cc`'dir; en basit, en hızlı ve en az sürprizli seçenektir (`gcr.io/distroless/cc-debian13:nonroot`). İkincisi musl ile mimalloc'tur; `#[global_allocator]` olarak mimalloc, jemallocator veya snmalloc-rs kullanılır ve statik binary ile yaklaşık 2 MiB imaj isteniyorsa tercih edilir. Üçüncüsü glibc statiktir; mümkündür ancak NSS ve DNS sorunları çıkarır ve önerilmez.
>
> Karar önerisi birinci seçenektir. Statik musl ile scratch estetik olarak çekicidir ancak Argus için yanlış takastır. Distroless `cc` zaten shell'siz ve paket yöneticisizdir. `static-debian13` yaklaşık 2 MiB'dir, yani Alpine'ın yaklaşık yarısı ve Debian'ın %2'sinden azıdır; ancak bu `static` variant'ıdır ve glibc-static gerektirir. İkinci seçenek tercih edilirse mimalloc kesinlikle eklenir ve bu bir CI benchmark'ıyla korunur.

### D.2 Base imaj seçenekleri

**Distroless.** İçeriği yalnızca uygulama ve çalışma zamanı bağımlılıklarıdır; shell, paket yöneticisi ve standart Linux araçları yoktur. Variantları `static`, `base`, `base-nossl`, `cc` ile dile özel Java, Python ve Node imajlarıdır. `gcr.io/distroless/static-debian13` yaklaşık 2 MiB'dir. `:nonroot` tag'i non-root kullanıcıyla çalışır; `:debug` busybox shell ekler ve `debug-nonroot` kombinasyonu bulunur. Platformları amd64, arm64, arm, s390x, ppc64le ve riscv64'tür. Kullananlar arasında Kubernetes (v1.15'ten beri), Knative ve Tekton vardır.

**Chainguard Images.** Sektörün en büyük sıfır CVE'li ve kaynaktan derlenmiş container imaj kataloğu olduğu iddia edilmektedir. Wolfi base, SBOM, sigstore imzalama, FIPS variantları ve fiyatlandırma detayları bu sayfadan doğrulanamamıştır; pazarlama sayfası teknik detay içermemektedir. Ücretsiz `latest` tag'leri vardır ancak sürüm pinlenmiş imajlar ücretlidir ve bu, satın alma kararından önce doğrulanmalıdır.

**cargo-chef.** 2.700 yıldız ve 295 commit'e sahiptir. `cargo chef prepare` bir `recipe.json` üretir; `cargo chef cook` bağımlılıkları ayrı bir Docker katmanında derler. Bazı ticari projelerde beş kata kadar hızlanma ölçülmüştür. Çekinceleri şunlardır: yalnızca container build için kullanılır, yerelde kullanılmaz; çalışma dizini `cook` ile `build` arasında aynı kalmalıdır; yerel path bağımlılıkları cargo'nun timestamp fingerprinting'i yüzünden sıfırdan derlenir.

### D.3 Container runtime sertleştirmesi

**Docker varsayılan seccomp profili.** 300'den fazla sistem çağrısından yaklaşık 44 tanesini devre dışı bırakır; geniş uygulama uyumluluğu sağlarken orta düzeyde koruyucudur. Varsayılan aksiyon `SCMP_ACT_ERRNO`'dur (Permission Denied) ve allowlist mantığı kullanılır. Blokladıkları arasında `io_uring_enter`, `io_uring_register` ve `io_uring_setup`; namespace için `clone`, `unshare` ve `setns`; `create_module`, `delete_module` ve `init_module`; `mount`, `umount`, `reboot` ve `swapon`; `ptrace`, `perf_event_open` ve `lookup_dcookie` bulunur. Dokümantasyonun uyarısı varsayılan seccomp profilinin değiştirilmesinin önerilmediğidir; `seccomp=unconfined` kesinlikle kullanılmaz.

> **Argus için.** Docker varsayılanı taban olur, ancak uygulama içi `seccompiler` filtremiz çok daha dar olacaktır. İkisi birleşiktir ve en kısıtlayıcı olan kazanır. Ayrıca Kubernetes'te `seccompProfile: {type: Localhost, localhostProfile: argus.json}` ile özel profil dağıtılabilir; ancak uygulama içi filtre daha iyidir, çünkü başlatma ve servis fazlarını ayırabilir.

### D.4 Kubernetes Pod Security Standards Restricted

> **Yaygın bir yanlış bilginin düzeltilmesi.** Kubernetes web sitesinin kaynak markdown dosyasından doğrulanmıştır: `readOnlyRootFilesystem` PSS Restricted politikasının bir kontrolü değildir. Ne Baseline'da ne Restricted'da yer alır.

Restricted'ın Baseline'a eklediği altı kontrol şunlardır: Volume Types; Privilege Escalation (v1.8 ve üstü); Running as Non-root; Running as Non-root user (v1.23 ve üstü); Seccomp (v1.19 ve üstü); Capabilities (v1.22 ve üstü).

Detaylar şöyledir. Capabilities için tüm capability'ler düşürülmeli ve yalnızca `NET_BIND_SERVICE` eklenebilir; yani `drop: ["ALL"]` zorunludur ve `add` ya `nil` ya `NET_BIND_SERVICE` olur. Seccomp için profil izin verilen değerlerden birine açıkça ayarlanmalıdır; hem `RuntimeDefault` hem `Localhost` kabul edilir ve `nil` kabul edilmez. `allowPrivilegeEscalation` açıkça `false` yapılmalıdır. `runAsNonRoot` `true` olmalıdır. `runAsUser` sıfır olmayan bir değer olmalıdır. Volume tipleri `configMap`, `secret`, `downwardAPI`, `projected`, `emptyDir`, `persistentVolumeClaim` ve `ephemeral` gibi bir allowlist ile sınırlıdır.

> **Argus için manifest; PSS Restricted ve ötesi.**
>
> ```yaml
> spec:
>   automountServiceAccountToken: false   # PSS'te yoktur, ancak önemlidir
>   securityContext:
>     runAsNonRoot: true
>     runAsUser: 65532                    # distroless nonroot UID'i
>     runAsGroup: 65532
>     fsGroup: 65532
>     seccompProfile:
>       type: RuntimeDefault              # veya Localhost ile özel profil
>   containers:
>   - name: argus
>     securityContext:
>       allowPrivilegeEscalation: false
>       privileged: false
>       readOnlyRootFilesystem: true      # PSS'te yoktur, elle eklenir
>       capabilities:
>         drop: ["ALL"]
>       # NET_BIND_SERVICE bile eklenmez: 1024 üstü port dinlenir ve Service ile map edilir
>     resources:
>       limits:
>         memory: "2Gi"                   # Argon2 OOM'una karşı sert tavan
>         cpu: "2"
>     volumeMounts:
>     - name: tmp
>       mountPath: /tmp                   # emptyDir; readOnlyRootFilesystem ile birlikte
>   volumes:
>   - name: tmp
>     emptyDir: { medium: Memory, sizeLimit: 64Mi }
> ```
>
> `readOnlyRootFilesystem: true` elle eklenir; PSS bu konuda zorlamaz.

### D.5 gVisor ve Kata

gVisor'un performans dokümantasyonuna göre iki maliyet sınıfı vardır: yapısal maliyetler (sistem çağrısı yakalama; platform seçimine bağlıdır ve ptrace açık ara en yüksek yapısal maliyete sahiptir) ve implementasyon maliyetleri.

Ağ tarafında gVisor diğer yığınların sunduğu tüm gelişmiş kurtarma mekanizmalarını desteklemez ve CPU açısından daha az verimlidir. Disk I/O tarafında yüksek ek maliyet temel olarak iyileştirilmesi gereken VFS implementasyonundan gelir ve birkaç dahili serileştirme noktası bulunur; statik dosya sunumunda Apache benchmark'ları öngörülebilir biçimde zayıf sonuçlar vermektedir.

En kötü etkilenenler sistem çağrısı bağımlı uygulamalardır: Redis, statik ağ servisleri ve küçük işlemler. tmpfs sandbox içinde olduğu için ucuzdur. Bellek tarafında container başına küçük ve çoğunlukla sabit bir ek maliyet vardır. En az etkilenenler CPU bağımlı ve I/O bağımlı iş yükleridir.

> **Argus için.** Bir IdP hem sistem çağrısı yoğundur, çünkü her istek socket I/O'sudur, hem CPU yoğundur, çünkü Argon2 ve imzalama vardır. gVisor'un ağ yığını darboğaz olur. Öneri gVisor'u varsayılan yapmamaktır. Bunun yerine çok kiracılı veya düşmanca bir ortamdaysanız ya da en güvenli iddiasını mimari olarak desteklemek istiyorsanız Kata Containers tercih edilir; donanım VM izolasyonu sunar, ağ performansı gVisor'dan iyidir ancak bellek ek maliyeti daha yüksek ve başlatma daha yavaştır. Alternatif olarak adanmış node havuzu ve node düzeyinde izolasyonla aynı güvenlik hedefine daha ucuza ulaşılır. gVisor yalnızca ayrıcalık ayrıştırılmış signer süreci için düşünülebilir; o süreç düşük sistem çağrısı hacimli ve yüksek değerlidir.

---

### D.6 İmza ve admission control

**sigstore policy-controller.** Kubernetes admission controller'ıdır; imza ve attestation doğrular. Container imajları üzerindeki imzaları ve attestation'ları otomatik doğrulayabilir, ayrıca attestation'lara karşı Cue veya Rego ile politika uygulayabilir. Tag'i SHA256 digest'e çözer ve bu, tag değiştirme saldırısını engeller; tek başına büyük bir kazançtır. `ClusterImagePolicy` CRD'si imaj glob desenleri, authority'ler (anahtar tabanlı, keyless yani OIDC, Fulcio ve Rekor, veya statik), Cue ile Rego politikaları ve namespace etiketiyle opt-in ile opt-out sunar. Admission mantığı şudur: imaj en az bir politikayla eşleşmeli, her eşleşen politikada en az bir authority doğrulanmalı ve tüm eşleşen politikalar geçmelidir; politikalar arasında VE, authority'ler arasında VEYA ilişkisi vardır. Durum uyarısı bileşenin hâlâ aktif geliştirme altında olduğudur.

> **Argus için.** Keyless imzalama (Fulcio ve Rekor) ile `ClusterImagePolicy` kullanılarak yalnızca bizim GitHub Actions workflow'umuzun ürettiği imajın çalışması kuralı konur. Bu, SLSA provenance attestation'ıyla birleştirilir. Bu, en güvenli IdP iddiasının tedarik zinciri ayağıdır ve doğrulanabilir olduğu için sunulabilir.

---

## E. Unsafe kod politikası

### E.1 `#![forbid(unsafe_code)]` Argus için gerçekçi mi

Evet, ancak workspace düzeyinde katmanlı olarak.

En güçlü emsal rustls'tir. Güvenlik politikasına göre bu güven sınırındaki öğeleri işleyen crate'in tamamı `forbid(unsafe_code)`'dur. Yani dünyanın en çok kullanılan Rust TLS kütüphanesi, ağdan gelen veriyi işleyen tüm crate'inde unsafe'i tamamen yasaklamıştır. Bu, bir IdP için ulaşılabilir bir çıta olduğunun kanıtıdır.

rustls ayrıca OSS-Fuzz'a kayıtlıdır ve mock crypto provider ile hem kimlik doğrulama öncesi hem sonrası kod yollarına fuzzing ulaşmaktadır. Tehdit modelinde uygunsuz ve saldırgan kontrolündeki karmaşıklığa sahip, kayda değer amplifikasyon üreten erişilebilir döngüler açıkça sayılmıştır; yani algoritmik karmaşıklık DoS'u bir güvenlik açığı sayılmaktadır. Integer overflow'lar için etkinin genel olarak hizmet reddine indirgendiği belirtilir.

| İhtiyaç | unsafe gerektirir mi | Alternatif |
|---|---|---|
| PKCS#11 FFI (HSM) | Evet | İzole bir crate'e hapsedilir (`argus-pkcs11`) |
| `mlock` ve `memzero` | Evet | `memsec` (0.7.0, 6 Haziran 2024) veya `zeroize` kullanılır; kendi yazılmaz |
| `memfd_secret` | Evet | `memsec::alloc_memfd_secret`; Linux'a özgüdür |
| seccomp yükleme | Genelde hayır | `seccompiler` API'si güvenlidir |
| Landlock | Hayır | `landlock` crate'i güvenli bir soyutlamadır |
| Capability düşürme | Hayır | `caps` güvenli API sunar |
| SIMD | Genelde hayır | `std::simd` (nightly) veya `wide` ile `safe_arch` crate'leri |

`memsec` 0.7.0 (6 Haziran 2024, aylık yaklaşık 177.000 indirme, 224 crate kullanır) libsodium utils'in Rust implementasyonudur: sabit zamanlı `memeq` ve `memcmp`, `memzero`, `mlock` ve `munlock`, guard page'li `alloc`, `free` ve `mprotect` ile Linux'ta `alloc_memfd_secret` ve `free_memfd_secret` sunar; sonuncusu kernel'ın `memfd_secret` desteğiyle belleği kernel'dan bile gizler.

> **Argus workspace mimarisi önerisi.**
>
> ```
> argus/
> ├── argus-core/        #![forbid(unsafe_code)]  ← iş mantığı, politika
> ├── argus-proto/       #![forbid(unsafe_code)]  ← OIDC/OAuth2/SCIM tipleri
> ├── argus-parse/       #![forbid(unsafe_code)]  ← tüm parser'lar
> ├── argus-http/        #![forbid(unsafe_code)]  ← axum handler'ları
> ├── argus-store/       #![forbid(unsafe_code)]  ← DB katmanı
> ├── argus-sandbox/     #![deny(unsafe_code)] + izinli istisnalar  ← seccomp/landlock/prctl
> └── argus-hsm/         unsafe izinli; her blok SAFETY yorumlu, Miri ve ASan testli
> ```
>
> CI kuralı şudur: `argus-sandbox` ve `argus-hsm` dışındaki hiçbir crate'te `unsafe` kelimesi geçemez; grep ve `cargo-geiger --forbid-only` ile kontrol edilir. Bu iki crate toplamda 500 satırın altında kalmalı ve ayrı bir güvenlik incelemesinden geçmelidir.

### E.2 `cargo-geiger`

Bakımdadır ancak sınırlıdır. Son sürüm 0.13.0'dır ve 31 Ağustos 2025 tarihlidir; aylık yaklaşık 19.117 indirme alır ve cargo eklentileri arasında 235. sıradadır. Yeni `--forbid-only` tarama modu rustc çağrısı gerektirmez ve yalnızca giriş noktası `.rs` dosyalarını ayrıştırır; çok hızlıdır ancak yalnızca `#![forbid(unsafe_code)]` beyanını kontrol eder. Bir düzeltmeyle unsafe fonksiyon içindeki ve iç içe unsafe scope'lardaki tüm ifadeler artık sayılmaktadır.

Sınırlamaları dokümantasyonun kendi ifadesiyle şudur: araç kodun nihai olarak gerçekten güvensiz olup olmadığını doğrudan söylemek üzere tasarlanmamıştır; istatistiksel girdi sağlar ve denetimin yerine geçmez. Kendisini hızlı ve kaba bir inceleme aracı olarak tanımlar ve kısmi bilginin hiç bilgi olmamasından iyi olduğunu söyler.

Ek pratik sorunlar şunlardır. Makroların içini göremez; `macro_rules!` veya proc-macro tarafından üretilen unsafe sayılmaz ve bu modern Rust'ta büyük bir kör noktadır. Build sorunları vardır; bir GitHub issue'da v0.13.0'ın karmaşık workspace'lerde çözümlenmemiş paketlerde abort trap ile çöktüğü raporlanmıştır. Unsafe ifadelerini sayar ancak kalitesini yargılamaz; bin satır iyi denetlenmiş SIMD unsafe'i, üç satır kötü FFI unsafe'inden daha güvenli olabilir.

> **Argus için.** `cargo-geiger` bir metrik olarak değil, bir gate olarak kullanılır: `cargo geiger --forbid-only` ile kendi crate'lerimizin `forbid(unsafe_code)` beyanı CI'da doğrulanır. Bağımlılık ağacındaki toplam unsafe sayısı bir KPI yapılmaz, çünkü yanıltıcıdır.

### E.3 Alternatifler

**`cackle` ve `cargo-acl`.** David Lattimore'un aracıdır. Transitive bağımlılıkların hangi API'leri kullandığını analiz eder; örneğin bir veri işleme kütüphanesinin gizlice ağ API'lerine eriştiğini yakalar. `cackle.toml` ile crate başına izin beyanı, `cackle ui` ile etkileşimli kurulum sunar. Son sürüm 0.2.0'dır ve 7 Eylül 2023 tarihlidir; 285 yıldız ve 638 commit'e sahiptir. Yaklaşık üç yıldır release çıkmamıştır ve fiilen durgundur. Yazarın o dönemden beri Wild linker projesine odaklandığı bilgisi doğrulanamamıştır, ancak release boşluğu gerçektir. Kendi dokümantasyonundaki sınırlamalar şunlardır: yalnızca Linux desteklenir; proc-macro'lar Cackle altında çalıştıklarını algılayıp farklı kod üretebilir; crate analizi keyfi kod çalıştırabilir ve bubblewrap sandbox'ı önerilir; kararlı geliştiriciler tespiti muhtemelen atlatabilir; araç hiçbir manuel kod incelemesinin yerine geçmemelidir.

> **Argus için.** Fikir mükemmeldir, ancak durgun bir araca güvenlik zinciri kurulmaz. Aynı garanti Landlock ve seccomp ile çalışma zamanında elde edilir: bir bağımlılık gizlice ağa çıkmaya kalkarsa sistem çağrısı filtresi durdurur. Bu, statik analizden daha güvenilirdir çünkü atlatılamaz.

**`cargo-vet` (Mozilla).** Üçüncü taraf bağımlılıkların güvenilir denetimlerden geçtiğini doğrular. Üç stratejisi vardır: paylaşım, yani organizasyonların denetim setlerini paylaşması (Mozilla, Google ve Embark import edilebilir); göreli denetimler, yani sürümler arası fark denetimi; ertelenmiş denetimler, yani istisna listesiyle kademeli benimseme. Kriter sistemi `safe-to-deploy` ve `safe-to-run`'dır. Trusted publishers desteklenir. Araç aktif geliştirme altındadır.

> **Argus için en iyi seçenektir.** `cargo-geiger`'dan daha anlamlı, `cackle`'dan daha canlıdır. Mozilla ve Google denetim setleri import edilerek büyük bir kısım maliyetsiz kapatılır, kalan istisnalar `exemptions` olarak listelenip zamanla azaltılır. CI'da `cargo vet check` sert bir gate olur.

`cargo-crev`, `cargo-supply-chain`, `cargo-audit` ve `cargo-deny` tamamlayıcıdır. `cargo-deny` ile lisans, duplicate ve RUSTSEC advisory'leri tek yerde gate'lenir.

### E.4 Rust web yığınında ne kadar unsafe var

Doğrulanmış tek veri noktası rustls'tir; ağ verisi işleyen crate'inde `forbid(unsafe_code)` bulunmaktadır.

`rasn` (ASN.1) dokümantasyonuna göre encoder ve decoder %100 güvenli Rust'ta yazılmıştır ve decoder'ın rastgele girdiyi doğru işlediğinden emin olmak için American Fuzzy Lop Plus Plus ile fuzzlanmıştır. Ayrıca crate tamamen `no_std`'dur (alloc ile).

tokio, hyper, h2, ring ve aws-lc-rs için sayısal ölçüm bulunamamıştır; güvenilir ve tarihli bir kaynak yoktur. Genel bilinen şudur: tokio ve hyper unsafe içerir (I/O primitifleri, intrusive linked list'ler, `Bytes`), `ring` ve `aws-lc-rs` C ve assembly içerir (BoringSSL türevidir) ve bunlar `forbid(unsafe_code)` iddiasını crate düzeyinde imkânsız kılar.

> **Argus için.** Bu sayı kendimiz üretilir ve yayımlanır; en güvenli IdP iddiasının somut kanıtı olur:
>
> ```bash
> cargo geiger --output-format GitHubMarkdown > docs/unsafe-report.md
> ```
>
> Ancak yorumlanır: toplam N unsafe ifadesi vardır, bunların yüzde şu kadarı rustls ve ring kripto katmanında, yüzde şu kadarı tokio I/O'sundadır ve Argus'un kendi kodunda sıfırdır.

### E.5 Miri

Miri'nin tespit ettikleri bellek güvenliği (sınır dışı erişim, use-after-free), ilklendirilmemiş veri, intrinsic ön koşul ihlalleri, hizalama ve tip invariantı ihlalleri, veri yarışları, aliasing ihlalleri (Stacked ve Tree Borrows) ile bellek sızıntılarıdır.

Sınırlamaları şunlardır. FFI desteği deneyseldir (`-Zmiri-native-lib`) ve yalnızca integer ile pointer argümanlarıyla sınırlıdır; native kodla paylaşılan bellekte ilklendirme ve provenance gibi ayrıntıların takibi bırakılır. Miri programı platformdan bağımsız bir yorumlayıcı olarak çalıştırır, dolayısıyla program çoğu platforma özgü API'ye ve FFI'ye erişemez. Ağ şu anda desteklenmemektedir. Temel threading desteklenir ancak tokio gibi framework'ler çalıştırılamaz. Determinizm açısından Miri programın olası birçok yürütmesinden birini test eder ve yalnızca farklı bir yürütmede ortaya çıkan hataları kaçırır. Yorumlayıcı olduğu için çok yavaştır; tipik olarak 50-500 kat.

> **Argus için.** Miri tüm test süitine değil, `argus-hsm` ve `argus-sandbox` crate'lerinin saf ve I/O içermeyen birim testlerine uygulanır: `cargo +nightly miri test -p argus-hsm --lib`. Bu, unsafe'in doğru olduğuna dair en güçlü otomatik kanıttır; ancak FFI sınırından öteye geçemez, dolayısıyla PKCS#11 çağrıları mock'lanır.

---

## F. Parser sertleştirme

Bu, dosyanın en kritik bölümüdür.

### F.1 Rust'ta stack overflow'da ne olur

Bu, Argus'un tehdit modelinin merkezinde durmalıdır. Rust, stack overflow'u yakalanabilir bir hataya dönüştürmez.

Mekanizma şudur. Rust runtime'ı her thread için, main dahil, kendi userspace stack guard'ını kurar. Bir `SIGSEGV` handler'ı `sigaltstack` üzerinde kurulur (varsayılan `SIGSTKSZ` boyutunda), çünkü stack zaten dolmuşken normal stack'te handler çalıştırılamaz. Handler, fault adresinin guard page aralığında olup olmadığına bakar; Unix hedeflerinde guard bölgesi bir `Range<usize>` olarak raporlanır ve bu aralıktaki herhangi bir fault stack overflow sayılır. Guard page'de fault varsa thread'in stack'ini taşırdığına dair mesaj basılır ve `abort()` çağrılır; SIGSEGV yeniden raise edilmez.

Kritik sonuçlar şunlardır. `catch_unwind` bunu yakalayamaz, çünkü bu bir panic değil doğrudan abort'tur. Bir tokio worker thread'inde gerçekleşse bile tüm süreç ölür, çünkü `abort()` süreç genelindedir. Main thread'in guard'ı `pthread_getattr_np` üzerinden hesaplanır ve bu POSIX'te tanımlı değildir; bazı platform ve sayfa boyutu kombinasyonlarında hatalı davranabilir. Bir issue'ya göre 64 KB sayfa boyutlu Linux'ta neredeyse tüm Rust programları bozulmuştur.

Yani özyinelemeli bir parser'da derinlik sınırı yoksa kimliği doğrulanmamış bir istekle tüm IdP kapatılabilir. Bu, Rust'ın bellek güvenliğinin koruma sağlamadığı bir sınıftır ve `#![forbid(unsafe_code)]` hiçbir işe yaramaz.

### F.2 Kanidm 2026 advisory'leri

İkisi de doğrulanmıştır ve gerçektir.

**SCIM filter stack exhaustion, GHSA-r5fr-9gmv-jggh.** Yayın 6 Mayıs 2026'dır. CVE-2026-46689'dur ve CVSS 8,7 HIGH'dır; GHSA sayfasında 7,5 HIGH olarak da geçmektedir, yani iki farklı skorlama vardır. Etkilenenler `scim_proto` ve `kanidm_proto`'nun 1.9.3'ten önceki sürümleridir; düzeltilen sürüm 1.9.3 ve üstüdür. CWE'leri CWE-248 (yakalanmamış istisna), CWE-400 (kontrolsüz kaynak tüketimi) ve CWE-674'tür (kontrolsüz özyineleme). Açıklamaya göre birkaç bin iç içe parantez içeren bir `?filter=` query string'i, yani yaklaşık 4-12 KB, özyinelemeli inişli PEG parser'ı worker thread'in stack guard page'inin ötesine iter. Sonuç şudur: Rust stack overflow'a `std::process::abort()` ile yanıt verir ve tüm kanidmd süreci sonlanır. En can alıcı detay şudur: ayrıştırma axum'un `Query<ScimEntryGetQuery>` extractor'ı içinde, herhangi bir handler gövdesinden ve dolayısıyla herhangi bir ACL kontrolünden önce koşar.

Bunun Argus için üç dersi vardır. 4-12 KB'lık bir GET query string'i ile tüm süreç ölmektedir; body limitiniz 2 MB olsun veya olmasın bu bir query string'tir ve extractor'da ayrıştırılır. Axum extractor'ları handler'dan önce çalışır; `FromRequestParts` implementasyonunda ayrıştırma yapılıyorsa o ayrıştırma kimliği doğrulanmamış girdiyi işliyor olabilir ve Argus'ta her custom extractor ayrı bir tehdit yüzeyi olarak ele alınmalıdır. PEG parser'lar (pest, peg crate'i) varsayılan olarak özyinelemelidir ve derinlik sınırı yoktur; grammar `expr = "(" expr ")"` içeriyorsa güvenlik açığı vardır.

**LDAP filter stack exhaustion, GHSA-qcxq-75wr-5cm8.** Yayın 30 Nisan 2026'dır. CVE atanmamıştır. CVSS v4.0 skoru 8,7 HIGH'dır; erişilebilirliğe tam etki eder, kimlik doğrulama, kullanıcı etkileşimi veya ayrıcalık gerektirmez ve ağ üzerinden sömürülebilir. Etkilenen `ldap3_proto`'nun 0.7.0'dan önceki sürümleridir; düzeltilen sürüm 0.7.1'dir. CWE-674'tür ve bulguyu mbarbero bildirmiştir. Açıklamaya göre LDAP sorguları derinlik için doğrulanmamaktadır ve bu, hem PEG hem ASN parser'ının stack'i tüketmesine yol açabilir.

Kritik nokta şudur: hem PEG (string filter) hem ASN.1 ile BER (wire format) parser'ı etkilenmiştir. Yani sorun tek bir kütüphanede değil, özyinelemeli ayrıştırma yapan her katmandadır.

**Kanidm v1.9.3 release notları.** Yayın 30 Nisan 2026'dır ve toplam altı güvenlik sorunu içerir: iki High, bir Moderate ve üç Low. SCIM filtrelerinin ayrıştırma derinliğinde bir sınır bulunmadığı ve bunun kimliği doğrulanmamış bir kullanıcı tarafından hizmet reddine yol açan stack tükenmesine imkân verdiği belirtilir. LDAP filtreleri için aynı ifade geçerlidir. Diğerleri PNG imaj doğrulaması, passkey kaydında HTML enjeksiyonu, OAuth2 client secret zamanlama karşılaştırması ve WebAuthn origin doğrulamasıdır. Release notu bunların aktif sömürüde olduğuna veya kullanıcı gizliliğinin ya da verisinin tehlikeye girdiğine dair bir kanıt bulunmadığını belirtir. Düzeltme ayrıştırma derinliğine açık bir sınır eklenmesidir.

> **Argus'un konumu.** Kanidm, Rust ile yazılmış, güvenlik odaklı ve olgun bir IdP'dir ve 2026'da bu sınıftan iki High severity açık almıştır. Argus en güvenli olacaksa bu, doğrudan rakip analizinden çıkan somut bir gereksinimdir: her parser derinlik sınırlı olmalı ve bu bir test süitiyle kanıtlanmalıdır.

### F.3 Aynı sınıftan diğer 2026 advisory'leri

| Kimlik | Crate | Detay |
|---|---|---|
| RUSTSEC-2026-0009 | `time` | CVE-2026-25727, CVSS 6,8. RFC 2822 ayrıştırmasında stack tükenmesi. Etkilenen 0.3.6 ile 0.3.46 arası, düzeltilen 0.3.47. `Date::parse`, `Time::parse`, `OffsetDateTime::parse` ve `UtcOffset::parse` etkilenmiştir. Düzeltme özyineleme derinliğine bir sınır getirmektir. Alternatif azaltma girdi uzunluğunu sınırlamaktır, çünkü stack tüketimi girdi boyutuyla orantılıdır. Cloudflare Pingora bile bundan etkilenmiştir |
| RUSTSEC-2026-0195 | `quick-xml` | `NsReader`'da namespace bildirimi bellek tüketimi. N namespace bildirimi içeren bir start tag, tag'in bayt boyutunun yaklaşık üç katı kadar `NamespaceResolver` heap'i tüketmekte ve bu quick-xml'in içinde ayrılmaktadır; yani çağıranın girdi boyutu limiti bunu kapsamaz. Gerçek etki NLnet Labs Routinator'ın (RPKI validator) OOM ile öldürülmesidir. Düzeltme 0.41.0'dadır: element başına varsayılan 256 namespace bildirimi sınırı, `NamespaceError::TooManyDeclarations` ve ayarlanabilir `NamespaceResolver::set_max_declarations_per_element()`. Düz `Reader` etkilenmez, çünkü namespace çözümlemesi yapmaz |
| RUSTSEC-2026-0187 | `lopdf` | Derin iç içe PDF nesneleriyle stack overflow |
| RUSTSEC-2024-0437 | `protobuf` | CVE-2025-53605, GHSA-2gh3-rmm4-6rq5. `CodedInputStream::skip_group` içinde kontrolsüz özyineleme; bilinmeyen alanlar ayrıştırılırken oluşur. 3.4.0 ve öncesi etkilenmiş, 3.7.2'de düzeltilmiştir. Rapor 12 Aralık 2024, yayın 7 Mart 2025 |
| RUSTSEC-2026-0185 | `quinn-proto` | Sırasız stream birleştirmede sınırsız bellek tüketimi; HTTP/3 kullanılıyorsa ilgilidir |

> **Desen.** 2026'da Rust ekosisteminde bu en yaygın açık sınıfıdır. `quick-xml` örneği ayrıca girdi boyutu limiti konulduğu için güvende olunduğu varsayımının yanlış olduğunu göstermektedir; amplifikasyon parser'ın içinde oluşmaktadır.

### F.4 Savunma teknikleri

**Açık derinlik sayacı, birincil savunma.** Her özyinelemeli ayrıştırma fonksiyonuna bir `depth: u32` parametresi ve giriş kontrolü eklenir. Kanidm'in ve `time` crate'inin uyguladığı düzeltme budur.

```rust
const MAX_FILTER_DEPTH: u32 = 32;   // OIDC ve SCIM için 32 fazlasıyla yeterlidir

fn parse_expr(input: &str, depth: u32) -> Result<Expr, ParseError> {
    if depth > MAX_FILTER_DEPTH {
        return Err(ParseError::TooDeep);   // panic değil, Result
    }
    // ... parse_expr(inner, depth + 1)
}
```

Maliyeti neredeyse sıfırdır ve tüm sınıfı kapatır. Argus'ta bu pazarlık konusu değildir.

**Özyinelemeyi döngüye çevirme.** En güçlü ancak en pahalı çözüm, özyinelemeyi bir `Vec<Frame>` üzerinde açık bir döngüye çevirmektir. Stack tükenmez, yalnızca heap büyür ve heap `cap` crate'i veya cgroup limitiyle sınırlanabilir. Argus için yalnızca en sıcak ve en düşmanca yüzeylerde yapılır: SCIM filter parser'ı ve LDAP filter parser'ı. Diğerlerinde derinlik sayacı yeterlidir.

**`stacker`.** 0.1.25 sürümündedir (2 Ağustos 2026). Sahipleri Rust Programming Language organizasyonu ve Simonas Kazlauskas'tır; Alex Crichton ile 38 katkıcı bulunmaktadır. Aylık 8,7 milyon indirme alır ve 3.503 crate kullanır; rustc'nin kendisi de kullanmaktadır. `psm` crate'i üzerinden çalışır ve Windows'ta Fiber tabanlıdır.

> **Kritik çekince.** Desteklenmeyen platformlarda no-op olarak çalışır; kod derlenir ancak stack overflow'u gerçekten engellemez. Bu sessiz bir başarısızlıktır ve Argus'ta hedef platformda gerçekten çalıştığı test edilmelidir. Ayrıca `stacker` derinliği sınırsız yapar ve stack overflow yerine bellek tükenmesi alınır; DoS'u ortadan kaldırmaz, yalnızca şeklini değiştirir. Derinlik sayacının yerine geçmez, yanına gelir.

**`serde_json` özyineleme sınırı.** `Deserializer::new` `remaining_depth` değerini 128 ile başlatır. Bu koruma varsayılan olarak açıktır ve kötü niyetli istemcilerin derin özyinelemeli yapı göndererek sunucuya hizmet reddi uygulamasını engellemek için tasarlanmıştır. `disable_recursion_limit()` yalnızca `unbounded_depth` özelliği açıkken vardır; dokümantasyonun uyarısına göre bu özellik kullanılırsa stack overflow'a karşı başka bir koruma sağlanmalıdır, örneğin Deserializer `serde_stacker` crate'inin dinamik büyüyen stack adaptörüyle sarmalanmalıdır.

> **Argus için.** `unbounded_depth` özelliğinin hiçbir bağımlılık tarafından açılmadığı doğrulanır; Cargo feature unification nedeniyle bir transitive bağımlılık bunu açarsa tüm build'de koruma kalkar. `cargo tree -f "{p} {f}"` ile kontrol edilir ve CI'da assert edilir. Bu sinsi bir tuzaktır. Ayrıca 128 bile bir IdP için fazladır; OIDC, JWT ve SCIM payload'ları 8-16 derinliği aşmamalıdır. Kendi `Deserializer`'ımızı kurup daha sıkı bir sınır koyamayız, çünkü API dışa açık değildir; bunun yerine deserialize sonrası bir derinlik doğrulaması veya JSON Schema ile şema doğrulaması eklenir.

`serde_stacker` 0.1.14 (15 Eylül 2025, dtolnay, aylık yaklaşık 604.000 indirme) `disable_recursion_limit()` çağırıp deserializer'ı sarmalamayı sağlar. Argus için önerilmez; sınırsız derinlik bir IdP'de asla meşru değildir.

**XML ve SAML.** `quick-xml` davranışına göre `Event::DocType` variant'ı `<!DOCTYPE ...>` içinde saklanan DTD verisini temsil eder; DTD bir event olarak sunulur, işlenmez. `Event::GeneralRef` variant'ı metin verisindeki `&entity;` genel referansını temsil eder ve bir entity referansı ya da karakter referansı olabilir; yani entity'ler otomatik genişletilmez, ayrı bir event olarak verilir.

Bunun anlamı şudur: quick-xml yapısal olarak billion laughs ve XXE'ye karşı bağışıktır, çünkü entity genişletmesini hiç yapmaz. Tehlike, uygulamanın kendi entity çözümlemesini yazmasıdır.

> **Argus kuralı.** SAML ve XML işleyen kodda `Event::GeneralRef` görüldüğünde yalnızca beş yerleşik entity (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;`) ve sınırlı bir aralıktaki sayısal karakter referansları çözülür. `Event::DocType` görüldüğünde belge reddedilir. Bu tek kural XXE ve billion laughs'ı kapatır. Ancak RUSTSEC-2026-0195 quick-xml'in kendi içinde de amplifikasyon olabileceğini göstermektedir; 0.41.0 ve üstü kullanılır ve `NsReader` kullanılıyorsa `set_max_declarations_per_element()` 256'dan da düşürülür, SAML için 32 fazlasıyla yeterlidir.

SAML Rust ekosisteminin durumu (crates.io API, 8 Eylül 2026):

| Crate | Sürüm | Güncelleme | İndirme | Not |
|---|---|---|---|---|
| `gamlastan` | 0.9.0 | 3 Eylül 2026 | 15.408 | Kushal Das tarafından geliştirilmektedir; SAML 2.0 kütüphanesi olarak tipler, XML, kripto, metadata, binding'ler, güvenlik ve profilleri kapsar |
| `saml-rs` | 0.5.0 | 13 Ağustos 2026 | 9.637 | 14 Haziran 2026'da oluşturulmuştur |
| `opensaml`, `samlify`, `samlet`, `rustsaml`, `rust-saml`, `open-saml` | 0.5.0 ve 0.1.4 | Haziran-Ağustos 2026 | 112-6.793 | `saml-rs`'in bakımlı uyumluluk yeniden export'u olarak tanımlanmışlardır; hepsi aynı crate'in yeniden export'udur |
| `rustauth-saml`, `openauth-saml`, `nornir-auth-saml`, `rvoip-saml` | Çeşitli | 2026 | 35-911 | Küçük ve yenidir |
| `saml` | 0.0.1-alpha.2 | 8 Ağustos 2026 | 995 | libxml2 ve xmlsec C build zinciri olmayan, durumsuz ve async-native SAML 2.0 araç seti |

> **Tedarik zinciri uyarısı.** `saml-rs`'in altı farklı isimle yeniden export edildiği bir küme vardır (`opensaml`, `samlify`, `samlet`, `rustsaml`, `rust-saml`, `open-saml`); hepsi 2026'da oluşturulmuştur ve hepsi başka dillerdeki popüler kütüphanelerin isimlerini taklit etmektedir. `samlify` bir Node.js kütüphanesi, `opensaml` Shibboleth'in C++ ve Java kütüphanesidir. Bu klasik bir isim ve tipo işgali desenidir. Argus'ta bu crate'lerin hiçbiri kullanılmaz ve `cargo-deny`'nin `bans` bölümüne eklenirler.

`gamlastan` 35 kontrollü bir assertion validator sunar ve fail-closed tasarlanmıştır. XML Signature Wrapping'e karşı imza bağlama ve istek korelasyonu açıkça belirtilmiştir. SPID uyum iddiası kütüphanenin kendi beyanıdır ve kanıt sayılmaz; `italia/spid-saml-check` SP'leri test eder, IdP'leri değil. Sweden Connect ve SPID dağıtım profilleri vardır. XML için `uppsala`, kripto için `bergshamra` crate'lerini kullanır; ikisi de aynı yazara aittir. Zero-copy XML ayrıştırma sunar. Hedefi pysaml2 projesinin Rust karşılığı olmaktır. Rust 1.88 ve üstünü gerektirir ve 138 commit'e sahiptir.

`samlattacks.md` dosyasındaki saldırı taksonomisi Argus'un SAML test süiti için doğrudan bir kontrol listesidir:

| Saldırı | CVE |
|---|---|
| Golden SAML (SolarWinds ve Solorigate); ADFS'ten özel anahtar çalınması | — |
| XML Signature Wrapping; orijinal imza korunurken sahte assertion enjeksiyonu | — |
| SAMLResponse doğrulama eksikliği | CVE-2019-3731 |
| İmza doğrulamada XPath seçim hatası | CVE-2024-45409 |
| SAMLStorm; DigestValue node'una comment enjeksiyonu | CVE-2025-29775 |
| Doğrulanmış kısım yerine imzasız assertion yüklenmesi | CVE-2025-54419 |
| XXE (xmlsec kullanımında) | CVE-2013-6440 |
| Geçersiz XML'den boş string üzerinden digest hesabı | CVE-2025-66578 |
| Yanlış XML node canonicalization | CVE-2017-11429 |
| Comment ve text node truncation; doğrulama sırasında comment işleme | CVE-2017-11427, CVE-2017-11428 |
| XML tanım hatası | CVE-2018-0489 |

> **Argus için SAML kararı.** SAML mümkünse hiç desteklenmez. XML-DSig, canonicalization ve XSW yirmi yıldır çözülmemiş bir problem sınıfıdır ve en güvenli IdP hedefiyle temel bir gerilim içindedir. OIDC, OAuth2 ve SCIM ile başlanır.
>
> Zorunluysa şunlar yapılır. Kendi XML-DSig implementasyonumuz yazılmaz; `gamlastan` en ciddi aday görünmektedir, ancak 0.9.0 sürümündedir, Haziran 2026'da oluşturulmuştur ve henüz denetlenmemiştir; bağımsız güvenlik denetimi yaptırılmadan üretime alınmaz. Mimari kural önce imzayı doğrulayıp sonra ayrıştırmak değil, canonicalize edilmiş baytları doğrulamak ve yalnızca imzalanmış node'u işlemektir; XSW'nin kökeni doğrulanan ağaç ile işlenen ağacın farklı olmasıdır, dolayısıyla Argus imza doğrulamasından doğrulanan node'un kendisini döndürmeli ve iş mantığı yalnızca ona dokunmalıdır, belgeyi yeniden XPath'lamak yasak olmalıdır. DOCTYPE içeren her belge reddedilir ve entity genişletme yapılmaz. SAML ayrıştırması ayrı bir süreçte çalıştırılır. Test süitine yukarıdaki CVE'lerin her biri için bir regresyon vektörü konur.

**ASN.1 ve DER.** `der` 0.8.2 (RustCrypto) dokümantasyonu bu crate'teki DER decoder'ının girdi belgesinin kanonik biçimde olduğundan emin olmak için kontroller yaptığını söyler; ancak iç içe derinlik sınırı, özyineleme koruması veya DoS azaltması belgelenmemiştir ve `forbid(unsafe_code)` beyanı dokümantasyonda yoktur. `rasn` %100 güvenli Rust'tır, AFL++ ile fuzzlanmıştır ve `no_std`'dur; ancak derinlik ve özyineleme koruması hakkında hiçbir belge yoktur ve bağımsız denetim bilgisi bulunmamaktadır.

> **Doğrulanamadı.** Bu iki crate'in decoder'ının özyinelemeli olup olmadığı ve derinlik sınırı bulunup bulunmadığı doğrulanamamıştır. Ancak LDAP advisory'si hem PEG hem ASN parser'ının stack tükettiğini açıkça söylemektedir; yani bu risk gerçektir.
>
> **Argus için zorunlu aksiyon.** X.509, PKCS#8 ve DER içindeki JWK'yı işleyen her yolda şunlar yapılır. Girdi boyutu sert sınırlanır; DER'de her iç içe seviye en az iki bayt header tüketir, dolayısıyla derinlik girdi boyutunun yarısı kadardır. 16 KB'lık bir sertifika limiti azami yaklaşık 8.000 derinlik demektir ve bu hâlâ stack overflow için yeterlidir; yani boyut limiti tek başına yetmez, ancak 4 KB'a indirilirse risk ciddi biçimde düşer. Kendi fuzz hedefimiz yazılır: `cargo-fuzz` ile `x509-cert::Certificate::from_der` üzerine derin iç içe DER beslenir ve stack overflow'un gerçekleşip gerçekleşmediği ölçülür; bu, bu raporun verdiği en somut test görevidir. Sertifika ayrıştırmasının da izole bir süreçte yapılması düşünülür.

**CBOR.** `ciborium` 0.2.2 (29 Ağustos 2026) için derinlik sınırı belgelenmemiştir ve doğrulanamamıştır.

> **Argus için.** WebAuthn ve FIDO2 attestation object'leri CBOR'dur ve kimliği doğrulanmamış kullanıcıdan gelir, yani kayıt akışındadır. Bu, SCIM filter ile aynı risk profilindedir. `ciborium` yerine `minicbor` değerlendirilir; `minicbor` decoder'ında açık derinlik kontrolü olduğu bilinmektedir ancak bu doğrulanmamıştır. Her hâlükârda attestation object boyutu sert sınırlanır (yaklaşık 8 KB) ve fuzz edilir.

**Ayırma limitleri.** Saldırgan kontrolündeki uzunluk öneki problemi şudur: `Vec::with_capacity(n)` çağrısında `n` ağdan geliyorsa tek bir dört baytlık alan 4 GB ayırma tetikler. Bu, LDAP BER, CBOR ve protobuf gibi ikili protokollerde klasik bir açıktır.

Savunmalar şunlardır. Ham uzunluk önekiyle asla `with_capacity` çağrılmaz; `min(n, MAX_REASONABLE)` kullanılır veya hiç rezerve edilmeyip `Vec::new()` ile artımlı push yapılır, çünkü allocator zaten amortize eder. `bytes` crate'i ile zero-copy dilimleme yapılır; kopya ve ayırma olmaz. `std::io::Read::take(n)` ile stream sert kesilir.

`cap` crate'i 0.1.2 (26 Mart 2023, aylık yaklaşık 77.580 indirme, Alec Mocatta) başka bir allocator'ı sarmalayıp bellek kullanımını izler ve tavan koyar:

```rust
#[global_allocator]
static ALLOCATOR: Cap<std::alloc::System> = Cap::new(std::alloc::System, usize::MAX);
ALLOCATOR.set_limit(30 * 1024 * 1024).unwrap();
```

> **Argus için değerlendirme.** `cap` çekicidir ancak iki problemi vardır: 2023'ten beri güncellenmemiştir ve global bir tavan aşıldığında ayırma `null` döner, ki Rust'ta bu `handle_alloc_error` ve abort demektir, yani yine süreç ölümüdür. DoS'u önlemez, yalnızca OOM-killer yerine kendimiz ölürüz.
>
> Daha iyi yaklaşım global tavan yerine istek başına bütçedir. Her handler'ın işleyebileceği azami veri boyutu tower katmanında sınırlanır ve cgroup bellek limiti (K8s `resources.limits.memory`) son savunma hattını kurar. `cap` yalnızca gözlem için kullanılır (`ALLOCATOR.allocated()` metriği), limit olarak değil.

### F.5 Parser sertleştirme kontrol listesi

1. Her özyinelemeli parser'da açık derinlik sayacı bulunur; azami 32'yi aşmaz.
2. Derinlik aşımında `Result::Err` döner; panic ve abort kullanılmaz.
3. Her parser için CI'da gecelik çalışan bir cargo-fuzz hedefi bulunur.
4. Fuzz corpus'unda 10.000 iç içe parantez, 10.000 iç içe süslü parantez ve 10.000 iç içe DER SEQUENCE yer alır.
5. Bir entegrasyon testi 12 KB derin iç içe filter POST eder; 400 dönmeli ve süreç yaşamalıdır.
6. `serde_json`'ın `unbounded_depth` özelliğinin hiçbir bağımlılıkta açık olmadığı CI'da assert edilir.
7. `quick-xml` 0.41.0 ve üstü kullanılır; DocType event'i görüldüğünde belge reddedilir.
8. Custom axum extractor'larının hepsi listelenir ve tehdit modellenir.
9. Auth middleware mümkünse pahalı extractor'lardan önce çalışır.
10. Body, query ve header boyut limitleri parser'a ulaşmadan uygulanır.
11. x509 ve DER ayrıştırması için boyut limiti 8 KB'yi aşmaz ve fuzz ile doğrulanır.
12. WebAuthn CBOR için boyut limiti ve derinlik kontrolü bulunur.

---

## G. Hizmet reddi savunması

### G.1 Boyut limitleri

**axum.** `DefaultBodyLimit` varsayılanı 2 MB'dir ve `Bytes`, `String`, `Json` ile `Form` extractor'larını kapsar. Güvenilmeyen kaynaklar için `DefaultBodyLimit::disable()` ile `tower_http::limit::RequestBodyLimitLayer` kullanılarak farklı bir limit konur. axum 0.7'de `RequestBodyLimitLayer` düzeltilmiştir; artık hangi middleware eklenirse eklensin `Request<Body>` extract edilebilmektedir.

**hyper HTTP/1 Builder.**

| Ayar | Varsayılan | Not |
|---|---|---|
| `max_buf_size` | Yaklaşık 400 KB | Asgari 8192 |
| `max_headers` | 100 | Aşılırsa HTTP 431 döner |
| `header_read_timeout` | 30 saniye | Timer gerektirir |
| `keep_alive` | `true` | — |
| `half_close` | `false` | — |

> **Slowloris tuzağı.** `header_read_timeout`'un çalışması için `Builder::timer()` ile bir Timer ayarlanmalıdır. Dokümantasyona göre Timer olmadan bir timeout yapılandırılmışsa `serve_connection` panic eder; yani ya Timer verilir ya panic alınır. `hyper-util`'in `auto::Builder`'ı kullanılıyorsa `TokioTimer`'ın ayarlandığı doğrulanır, aksi hâlde sistem slowloris'e açıktır.

**hyper HTTP/2 Builder.**

| Ayar | Varsayılan |
|---|---|
| `max_concurrent_streams` | 200; hyper'ın kararlılık taahhüdünün parçası değildir |
| `max_header_list_size` | 16 KB |
| `max_send_buf_size` | Yaklaşık 400 KB |
| `keep_alive_interval` | Devre dışı |
| `keep_alive_timeout` | 20 saniye |
| `max_pending_accept_reset_streams` | 20; h2 v0.4.0'dan itibaren |
| `max_local_error_reset_streams` | 1024 |
| `initial_stream_window_size`, `initial_connection_window_size`, `max_frame_size` | hyper bir varsayılan kullanır; belgelenmemiştir |

> **En önemli uyarı.** Dokümantasyonun kendi ifadesine göre seçeneklerin varsayılan değerleri kararlı sayılmamaktadır ve her an değişebilir. Argus için bu, tüm bu değerlerin açıkça ayarlanması gerektiği anlamına gelir. Varsayılana güvenmek, bir hyper minor sürüm yükseltmesinde sessizce DoS'a açılmak demektir. Bunlar bir yapılandırma struct'ında toplanır, değerler loglanır ve `/metrics` üzerinden dışa verilir.

### G.2 HTTP/2 saldırıları

**Rapid Reset (CVE-2023-44487).** 2023'ün Ağustos ve Ekim ayları arasında vahşi doğada sömürülmüştür. Saldırgan çok sayıda stream açıp her birini hemen `RST_STREAM` ile iptal eder ve kaynak açlığı yaratır.

Rust ekosistemindeki ilgili advisory'ler şunlardır.

RUSTSEC-2023-0034: saldırgan ağı, h2 uygulamasının kabul edebileceğinden daha hızlı biçimde HEADERS ile RST_STREAM frame çiftleriyle doldurursa bekleyen kabul kuyruğunun bellek kullanımı büyüyebilir ve sonunda bellek tükenmesi tetiklenir. Düzeltme hyperium/h2#668'dedir; uzaktan sıfırlanan stream sayısı varsayılan olarak sınırlandırılmıştır.

RUSTSEC-2024-0003: HTTP/2 bağlantısı olan bir saldırgan, reset frame üretimini zorlamak için sürekli geçersiz frame akışı gönderebilir ve alma penceresini kapatarak bu reset'lerin sınırsızca kuyruklanmasını sağlayabilir; sonuç bellek tükenmesi ve yüksek CPU kullanımıdır. Düzeltme hyperium/h2#737'dedir; dahili hata reset sayısına varsayılan 1024 eşiği konmuştur.

**CONTINUATION Flood** (3 Nisan 2024). Saldırıda sonsuz `CONTINUATION` frame'i gönderilir. hyper'da bellek büyümesi header limitinde sınırlanır, ancak sunucu frame'leri işlemeye devam eder ve CPU tüketimi ile hizmet kalitesi düşer. Düzeltme h2 v0.4.4 ve v0.3.26'dadır; `cargo update -p h2` ile alınır. Düzeltmenin mantığı sabit bir limit yerine, yapılandırılmış azami frame boyutu ve azami header list boyutuna göre meşru bir mesajın gerektirebileceği azami CONTINUATION frame sayısını hesaplamak ve buna padding eklemektir. CVE atanmamıştır; duyuru RustSec advisory'siyle yapılmıştır. Kullanıcı sorumluluğu şudur: kullanıcılar `SETTING_MAX_HEADER_LIST_SIZE` değerini kendi kullanım senaryoları için makul bir değere ayarlamalıdır; kütüphane ayarlanmadığında yüksek bir acil durum varsayılanı kullanır.

> **Argus için HTTP/2 yapılandırması.** 2026'da açıkça ayarlanması gerekenler şunlardır:
>
> ```rust
> builder
>     .max_concurrent_streams(100)                    // 200 fazladır; IdP için 100 yeterlidir
>     .max_header_list_size(8 * 1024)                 // 16 KB fazladır; JWT header'ları için 8 KB
>     .max_frame_size(16 * 1024)                      // asgari değer, açıkça
>     .initial_stream_window_size(64 * 1024)
>     .initial_connection_window_size(1024 * 1024)
>     .max_send_buf_size(256 * 1024)
>     .max_pending_accept_reset_streams(Some(20))
>     .max_local_error_reset_streams(Some(256))       // 1024 yerine daha sıkı
>     .keep_alive_interval(Some(Duration::from_secs(20)))
>     .keep_alive_timeout(Duration::from_secs(10))
>     .timer(TokioTimer::new())                       // zorunlu
> ```
>
> HTTP/1 tarafında `header_read_timeout` ve Timer ayarlanır. HTTP/3 (quinn) eklenirse RUSTSEC-2026-0185'e dikkat edilir.

### G.3 Timeout, eşzamanlılık ve yük atma

tower 0.5.3 şunları sunar: `timeout` istek başına süre sınırı; `limit::ConcurrencyLimit` eşzamanlı istek sayısı; `limit::RateLimit` zaman içinde istek frekansı; `load_shed`, iç servisler hazır olmadığında yük atmak için middleware, yani downstream hazır değilse isteği hemen reddeder ve kuyruğu büyütmez; `buffer`, bir servise tamponlanmış mpsc kanalı sağlar; `retry`, ancak retry DoS'u amplifiye edebilir ve rate limit ile birlikte, jitter'lı backoff ile kullanılmalıdır.

Özellik bayrakları `tower = { version = "0.5", features = ["timeout", "limit", "load_shed", "buffer"] }` biçimindedir.

> **Argus katman sırası, dıştan içe.**
>
> ```
> 1. Bağlantı limiti (accept döngüsünde semafor; tower dışı, elle)
> 2. tower_governor (IP başına rate limit)  ← ucuz, erken
> 3. RequestBodyLimitLayer veya DefaultBodyLimit
> 4. TimeoutLayer (toplam istek: 10 saniye)
> 5. LoadShedLayer
> 6. ConcurrencyLimitLayer (global: çekirdek sayısının yaklaşık iki katı)
> 7. TraceLayer
> 8. Auth middleware
> 9. Handler
>    └─ Argon2 için ayrı semafor
> ```
>
> Kural şudur: pahalı olan her şey, ucuz olan her şeyin arkasındadır. Kanidm CVE'sinin dersi tam olarak buydu; ayrıştırma ACL kontrolünden önce çalışıyordu.

### G.4 Rate limiting

`governor` 0.10.4 (5 Eylül 2026) GCRA, yani leaky bucket'ın hassas varyantını kullanır. Keyed rate limiter sunar (`DefaultKeyedRateLimiter`, `dashmap` ile). Async destekler (`RatelimitedSink`, `RatelimitedStream`). Dağıtık senaryolar hakkında hiçbir rehberlik vermez; tamamen süreç içidir.

`tower_governor` 0.8.0 (14 Ağustos 2025) governor crate'i tarafından desteklenen, yapılandırılabilir anahtar tabanlı ve global limitlere izin veren bir Tower rate limiting middleware'idir. Toplam 4.435.671 indirme ve son dönemde 1.654.323 indirme almıştır; iyi benimsenmiştir.

> **Argus için çok instance'lı rate limiting.**
>
> Yerel katmanda governor ile her instance kendi bellek içi limitini uygular; ucuzdur, gecikme yaratmaz ve tek bir instance'ı korur. Limit global limitin instance sayısına bölümü ile bir güvenlik payının çarpımıdır.
>
> Global katmanda Redis brute force ve credential stuffing için kesinlikle gereklidir, çünkü saldırgan yük dengeleyicide farklı instance'lara dağılır. Redis'te `INCR` ve `EXPIRE` veya bir sliding window script'i kullanılır. Anahtar hem IP, hem kullanıcı adı, hem IP ile kullanıcı adı üçlüsüdür.
>
> Proxy tuzağı şudur: `X-Forwarded-For` değerine asla körlemesine güvenilmez. Kaç proxy hop'u olduğu yapılandırılır ve sağdan sayılarak güvenilir IP alınır; aksi hâlde saldırgan header enjekte ederek rate limit'i atlar ve ayrıca meşru kullanıcıları bloklatır, yani limit zehirlemesi yapar.
>
> Rate limit'in fail-closed mı fail-open mı olduğu karara bağlanır: Redis düşerse login endpoint'i için fail-closed davranılır ve yerel governor sıkı limitle devreye girer, diğerleri için fail-open davranılır. Bu bilinçli bir karar olarak dokümante edilir.

### G.5 Argon2 DoS

Bu, bir IdP'ye özgü ve en çok gözden kaçan DoS vektörüdür. Argon2 tanım gereği bellek serttir. `m_cost = 64 MiB` ve 50 eşzamanlı login 3,2 GB anlık bellek demektir ve OOM ile öldürülmeye yol açar.

`argon2` crate'inin `Params` yapısında `DEFAULT_T_COST` 2, `DEFAULT_P_COST` 1 ve `DEFAULT_OUTPUT_LEN` 32'dir. `MIN_T_COST` 1, `MIN_P_COST` 1 ve `MIN_OUTPUT_LEN` 4'tür. `MAX_M_COST` ile `MAX_T_COST` `u32::MAX`, `MAX_P_COST` `0xFFFFFF` ve `MAX_OUTPUT_LEN` `0xFFFFFFFF`'tir. `m_cost` 1 KiB'lık bloklar hâlinde bellek boyutudur ve `8*p_cost` ile `2^32-1` arasında olmalıdır. `DEFAULT_M_COST`'un sayısal değeri doküman sayfasından çıkarılamamıştır ve kodda doğrulanmalıdır.

**Gerçek dünya örneği: Rauthy.** `hashing.max_hash_threads` varsayılanı 2'dir. Dokümantasyona göre uygulama, yeterli güvenlik marjını korurken sistem belleğinin aşılmasını önlemek için paralel parola hash işlemlerini kısıtlar. Varsayılan 2 ile tam olarak aynı anda yalnızca bir kullanıcı girişi mümkündür ve bu, küçük dağıtımlarda harici rate limiting'i gereksiz kılar. Admin arayüzünde Config altında Argon2 Parameters bölümünde bir ayar yardımcısı vardır; amacı azami güvenlik için hash'lemeye mümkün olduğunca çok kaynak ayırmak, aynı zamanda gerektiği kadar kısıtlamaktır. Container ortamlarında bellek limitlerinin izlenmesi konusunda açık bir uyarı bulunur; yetersiz limit çökmeye yol açar. Rauthy ayrıca login ve parola hash'leme rate limiting'i, brute force ile credential stuffing tespiti ve otomatik IP kara listesi, oturumun peer IP'sine bağlanması, ed25519 token imzalama ve veritabanı içinde kritik alanların ek şifrelenmesini sunar. Bağımsız güvenlik denetimi Radically Open Security tarafından v0.32.1 üzerinde yapılmıştır; güncel sürüm 0.36.2'dir. sudo-rs de iki bağımsız denetim geçirmiştir: Ağustos 2023 (v0.2.0) ve Ağustos 2025 (v0.2.8); Rust güvenlik projelerinde denetim artık normdur.

> **Argus için Argon2 mimarisi.**
>
> ```rust
> // Global, adil semafor — sınırlı worker havuzu
> static HASH_PERMITS: Semaphore = Semaphore::const_new(N);
> // N = floor(available_memory_bytes * 0.5 / (m_cost_kib * 1024))
> // Örnek: 2 GiB limit, m_cost = 64 MiB → N = floor(1024/64) = 16
>
> async fn verify_password(pw: &str, hash: &str) -> Result<bool> {
>     // 1. Semaforu zaman aşımıyla al — sonsuz kuyruk olmaz
>     let permit = timeout(Duration::from_millis(500), HASH_PERMITS.acquire())
>         .await
>         .map_err(|_| Error::Overloaded)?;   // HTTP 503 + Retry-After
>
>     // 2. spawn_blocking — Argon2 CPU bağımlıdır, async worker'ı bloklamamalıdır
>     let r = tokio::task::spawn_blocking(move || argon2_verify(pw, hash)).await?;
>     drop(permit);
>     r
> }
> ```
>
> Dört kritik nokta vardır. Semafor boyutu bellek limitinden türetilmelidir, elle sabitlenmemelidir; container limiti `/sys/fs/cgroup/memory.max` dosyasından okunur. `acquire()` zaman aşımlı olmalıdır; zaman aşımsız semafor sınırsız kuyruk demektir ve bellek DoS'unu gecikme DoS'una çevirir. `spawn_blocking` zorunludur; Argon2'yi async worker thread'inde çalıştırmak tüm runtime'ı dondurur ve ayrıca tokio blocking havuzunun kendi limiti (`max_blocking_threads`) semaforla uyumlu ayarlanmalıdır. Zamanlama açısından kullanıcı yoksa da hash hesaplanır (dummy hash), yoksa kullanıcı sayımı açığı doğar; ancak bu DoS bütçesini ikiye katlar ve semafor hesabına dahil edilmelidir.
>
> Ek olarak Argon2 ayrıcalık ayrıştırılmış signer sürecine taşınırsa bellek bütçesi tamamen ayrılır ve HTTP sürecinin bellek tükenmesi imkânsızlaşır.

### G.6 ReDoS

`regex` 1.13.1 dokümantasyonuna göre bu crate'teki tüm regex aramaları en kötü durumda `O(m * n)` zaman karmaşıklığına sahiptir; burada m regex'in boyutuyla, n aranan string'in boyutuyla orantılıdır.

Doğrulanmıştır: `regex` lineer zamanlıdır ve catastrophic backtracking yoktur. Backreference ve lookaround desteklenmez, çünkü crate bunları verimli biçimde implemente etmenin bilinmediği birkaç özellikten yoksundur.

Ancak bir uyarı vardır: güvenilmeyen desenler için, yani kullanıcı regex yazabiliyorsa, derleme zamanında bellek patlaması mümkündür; `a{5}{5}{5}{5}{5}{5}` gibi yığılmış tekrarlar buna örnektir. Dokümantasyon desen uzunluğunun küçük bir değerle sınırlanmasını ve gerektikçe genişletilmesini, `RegexBuilder::size_limit` değerinin küçük ayarlanıp gerektikçe artırılmasını önerir.

> **Argus için.** `regex` güvenlidir ve kullanılmaya devam edilir. `fancy-regex`, `onig` ve `pcre2` gibi backtracking motorları ReDoS'a açıktır; bu bu araştırmada doğrudan doğrulanmamıştır, ancak fancy-regex'in lookaround ve backreference desteği tanım gereği backtracking gerektirir. Bunlar `cargo-deny`'nin bans listesine eklenir. Argus'ta yöneticiler regex yazabiliyorsa, örneğin claim mapping veya grup eşleştirme kurallarında, desen uzunluğu 256 karakterle sınırlanır ve `RegexBuilder::size_limit(1MB)` ayarlanır.

### G.7 Slowloris ve TLS handshake DoS

**Slowloris.** `header_read_timeout` (hyper HTTP/1'de varsayılan 30 saniye, Timer ayarlanmışsa) ile bağlantı limiti ve accept döngüsünde semafor kullanılır. Otuz saniye hâlâ uzundur ve 5-10 saniyeye indirilir.

**TLS handshake DoS.** Handshake RSA ve ECDHE ile CPU maliyetlidir. rustls'in tehdit modeli bunu kapsar: uygunsuz ve saldırgan kontrolündeki karmaşıklığa sahip, kayda değer amplifikasyon üreten erişilebilir döngüler sayılmaktadır. Savunma accept'ten sonra, handshake'ten önce bir bağlantı semaforu koymak, handshake'e ayrı bir zaman aşımı vermek ve IP başına eşzamanlı bağlantı sınırı uygulamaktır.

rustls'in modern özellikleri TLS 1.2 ve 1.3, ECDHE ile forward secrecy, X25519MLKEM768 post-quantum hibrit anahtar değişimi, Encrypted Client Hello, OCSP stapling ve session resumption'dır. Renegotiation, SSL 1, 2 ve 3, TLS 1.0 ve 1.1, RC4, DES ile MAC-then-encrypt desteklenmez; bu iyidir, çünkü renegotiation bir DoS vektörüdür.

Kripto sağlayıcı seçiminde `rustls-aws-lc-rs` proje tarafından önerilir; mükemmel performans ve post-quantum algoritmalar dahil eksiksiz bir özellik seti sunar. `rustls-ring` daha kolay derlenir ancak özellik seti sınırlıdır. Ancak aws-lc-rs C ve assembly içerir ve bu, E bölümündeki unsafe politikasını etkiler.

Session resumption CPU'yu düşürür ancak ticket key yönetimi ve replay riski getirir. TLS 1.3 0-RTT replay nedeniyle kapalı tutulur.

---

## Argus için önceliklendirilmiş aksiyon listesi

### P0: yapılmazsa en güvenli iddiası geçersizdir

| # | Aksiyon | Maliyet | Gerekçe |
|---|---|---|---|
| 1 | Her özyinelemeli parser'a derinlik sınırı (32 ve altı) ve fuzz hedefi | 1 hafta | Kanidm GHSA-r5fr-9gmv-jggh ve GHSA-qcxq-75wr-5cm8 (Nisan ve Mayıs 2026); doğrudan rakipte aynı sorun |
| 2 | Release profilinde `overflow-checks = true` | Neredeyse sıfır | Wraparound bir IdP'de yetki mantığı hatasıdır |
| 3 | hyper HTTP/1 ve HTTP/2 limitlerinin tamamının açıkça ayarlanması ve `TokioTimer` | 1 gün | hyper varsayılan değerleri kararlı saymamaktadır |
| 4 | Bellek limitinden türetilmiş sınırlı Argon2 semaforu, zaman aşımı ve `spawn_blocking` | 2 gün | Rauthy'nin `max_hash_threads=2` emsali |
| 5 | K8s'te PSS restricted, `readOnlyRootFilesystem: true` (PSS'te yoktur), `drop: ALL` ve bellek limiti | 1 gün | PSS restricted'ın `readOnlyRootFilesystem` içermediği doğrulanmıştır |
| 6 | `cargo-deny` ve `cargo-vet` CI gate'i (RUSTSEC, lisans, yasaklı crate'ler) | 2 gün | h2, quick-xml, time ve protobuf advisory'leri |
| 7 | Tüm iş mantığı crate'lerinde `#![forbid(unsafe_code)]` | Baştan yapılırsa sıfır | rustls emsali; güven sınırı crate'i forbid etmektedir |

### P1: gerçek farklılaşma

| # | Aksiyon | Maliyet | Gerekçe |
|---|---|---|---|
| 8 | Landlock; ana thread'de, runtime'dan önce, `landlock` 0.4.7 ile | 2-3 gün | En yüksek fayda maliyet oranı. ABI 8 `all_threads()` best-effort'ta sessizce düşer; HardRequirement kullanılır |
| 9 | seccomp-bpf; `seccompiler` 0.5.0 ile iki fazlı (başlatma ve servis) | 1 hafta | Firecracker emsali |
| 10 | Capability düşürme, `no_new_privs` ve `PR_SET_DUMPABLE=0`; `caps` 0.5.6 ve `nix` prctl ile | 1 gün | Doğru sıra: dumpable, bind, no_new_privs, bounding, setgroups, setgid, setuid |
| 11 | Ayrıcalık ayrıştırma; `argus-signer` ayrı süreç, ağ sistem çağrıları yasak | 2-3 hafta | OpenSSH 9.8 sshd-session emsali; CVE-2023-38408'de ayrıcalık ayrıştırma RCE'yi etkisizleştirmiştir |
| 12 | glibc ile distroless `cc:nonroot`; musl seçilirse mimalloc zorunludur | 1 gün | musl gerçek iş yükünde yedi kat, sentetikte yaklaşık 700 kat yavaştır ve mallocng çözmemiştir |
| 13 | sigstore keyless imzalama ve policy-controller admission | 3 gün | Tag'in digest'e çözülmesi tek başına büyük kazançtır |
| 14 | io_uring kullanılmaması kararının dokümante edilmesi | Sıfır | io_uring seccomp'u bypass eder; Docker zaten bloklar |

### P2: değerlendirilecekler

| # | Aksiyon | Not |
|---|---|---|
| 15 | Gecelik CI'da ASan, LSan ve TSan (haftalık) | MSan atlanır; build-std ve C bağımlılıkları nedeniyle |
| 16 | Miri ile `argus-hsm` ve `argus-sandbox` birim testleri | Ağ ve tokio çalışmaz; FFI sınırlıdır |
| 17 | Bağımsız güvenlik denetimi | Rauthy (Radically Open Security) ve sudo-rs (iki denetim) emsali; en güvenli iddiası için gereklidir |
| 18 | CET ve BTI ELF property note'unun `readelf -n` ile ölçülmesi | Doğrulanamamıştır; rustc'nin bunu emit edip etmediği bilinmemektedir, ölçülüp raporlanmalıdır |
| 19 | SAML: mümkünse hiç desteklenmez; zorunluysa `gamlastan`, denetim ve izole süreç | Altı kopya yeniden export crate'i vardır; tedarik zinciri riskidir |

### Yapılmayacaklar

| Teknik | Neden |
|---|---|
| Üretimde `-Zsanitizer=cfi` | Nightly, LTO ve build-std gerektirir; yalnızca Rust içeren kodda marjinaldir ve tekrarlanabilir build'i bozar |
| `-Zstack-protector` | Hâlâ nightly'dedir (PR #146369, 13 Temmuz 2026 itibarıyla S-blocked); safe Rust'ta değeri sınırlıdır |
| `cackle` ve `cargo-acl`'e güvenlik zinciri kurmak | Son release 7 Eylül 2023'tür; atlatılabilir; çalışma zamanı seccomp ve Landlock daha güvenilirdir |
| `unshare` crate'i | Son release 4 Mayıs 2021'dir; bakımsızdır |
| `cap` crate'ini limit olarak kullanmak | Limit aşımı `handle_alloc_error` ve abort üretir; DoS'u önlemez, yalnızca metrik olarak kullanılır |
| gVisor'u varsayılan runtime yapmak | IdP hem sistem çağrısı hem CPU yoğundur; gVisor'un ağ yığını darboğazdır |
| `serde_stacker` ile `disable_recursion_limit` | Sınırsız derinlik bir IdP'de asla meşru değildir |
| musl'ı varsayılan allocator'ıyla kullanmak | Yedi ile 700 kat arası yavaşlama |

---

## Doğrulanamayan ve açık kalan noktalar

Bunları Argus ekibi kendisi ölçmelidir; iddia edilmez, ölçülür.

1. rustc x86-64'te `GNU_PROPERTY_X86_FEATURE_1_SHSTK` ve IBT note'unu emit ediyor mu; `readelf -n target/release/argus` ile bakılır.
2. Android'in Rust bileşenlerinde LLVM CFI açık mı; source.android.com CFI sayfası yalnızca C ve C++'tan bahsetmektedir.
3. `der` 0.8.2 ve `rasn` decoder'ları özyinelemeli mi ve derinlik sınırı var mı; `cargo-fuzz` ile derin iç içe DER beslenerek ölçülür.
4. `ciborium` 0.2.2'nin derinlik sınırı var mı; WebAuthn için kritiktir. `minicbor` alternatifinin derinlik kontrolü de doğrulanmamıştır.
5. tokio, hyper, h2 ve ring için yayımlanmış unsafe ölçümü bulunamamıştır; `cargo geiger` ile kendimiz üretiriz.
6. `argon2` crate'inin `DEFAULT_M_COST` sayısal değeri dokümantasyondan çıkarılamamıştır.
7. systemd, Docker, Firefox ve sudo-rs'in Landlock kullandığı doğrulanamamıştır.
8. Chainguard'ın FIPS variantları, Wolfi tabanı ve fiyatlandırması pazarlama sayfasından çıkarılamamıştır.
9. `fancy-regex`'in ReDoS'a açık olduğu doğrudan doğrulanmamıştır; tasarım gereği backtracking olduğu bilinmektedir ancak kaynakla teyit edilmemiştir.
10. Cackle yazarının Wild linker'a geçtiği doğrulanamamıştır; yalnızca release boşluğu gerçektir.
11. Tokio ve epoll için tam sistem çağrısı allowlist'i literatürden derlenmiş genel bir çerçevedir; Argus'un gerçek seti `strace -f -c` ile ölçülmelidir.

---

## Kaynaklar

**Rust derleyici ve sertleştirme.** rustc Exploit Mitigations sayfası; rust-lang/rust#146369 ve #114903; Unstable Book sanitizer sayfası; Codegen Options; Cargo Profiles; Rust Project Goals 2026 Rust for Linux sayfası; Android CFI dokümanı; Linux x86 shadow stack dokümanı; rust-lang/rust#31273, #43052 ve #69533.

**İzolasyon.** seccompiler (lib.rs ve rust-vmm/seccompiler); Firecracker seccomp dokümanı; extrasafe; libseccomp-rs; io_uring ve seccomp yazısı (27 Kasım 2022); caps; nix prctl; unshare; OpenSSH 9.8 release notu (1 Temmuz 2024); OpenSSH güvenlik sayfası.

**Landlock.** landlock.io; kernel userspace-api/landlock; landlock(7) man sayfası; docs.rs/landlock ve ABI enum'u; rust-landlock; island.

**Container.** musl allocator yazısı (2 Şubat 2025); andygrove musl yazısı (5 Mayıs 2020); distroless; cargo-chef; Kubernetes PSS sayfası ve kaynak markdown'ı; gVisor performans dokümanı; Docker seccomp dokümanı; sigstore policy-controller; Chainguard.

**Unsafe ve tedarik zinciri.** cargo-geiger ve CHANGELOG'u ile issue #71; cackle ve davidlattimore/cackle; cargo-vet; Miri; rustls SECURITY.md ve rustls features; memsec; sudo-rs.

**Parser ve advisory'ler.** GHSA-r5fr-9gmv-jggh (6 Mayıs 2026); GHSA-qcxq-75wr-5cm8 (30 Nisan 2026); Kanidm v1.9.3 (30 Nisan 2026); RUSTSEC-2026-0009, RUSTSEC-2026-0195 ve RUSTSEC-2024-0437; RustSec advisory listesi; cloudflare/pingora#807; serde_json de.rs; serde_stacker; stacker; quick-xml Event enum'u; gamlastan ve samlattacks.md; der; rasn; ciborium; cap.

**Hizmet reddi.** axum DefaultBodyLimit; axum 0.7 duyurusu (27 Kasım 2023); hyper http1::Builder ve http2::Builder; hyper CONTINUATION flood yazısı (3 Nisan 2024); RUSTSEC-2024-0003 ve RUSTSEC-2023-0034; hyperium/h2#737; CISA CVE-2023-44487 uyarısı (10 Ekim 2023); tower; governor; tower_governor; Rauthy ve Rauthy Argon2 yapılandırma dokümanı; argon2 Params; regex; Kanidm security hardening dokümanı.

---

## Argus için fuzzing ve property-based testing

---

## A. Rust fuzzing ekosistemi, 2026 durumu

### A.1 libFuzzer'ın durumu

LLVM'in kendi dokümantasyonu nettir: libFuzzer 2022 sonundan beri yalnızca bakım modundadır, yeni özellik gelmeyecektir ve orijinal yazarlar Centipede'e geçmiştir. Önemli hatalar düzeltilmektedir, ancak major özellik veya kod incelemesi beklenmemelidir. Trail of Bits 29 Nisan 2026'da bunu teyit etmiştir.

### A.2 cargo-fuzz'un LibAFL'e geçişi

Bu, 2026'nın en önemli haberidir ve kaynak koddan doğrulanmıştır.

cargo-fuzz 0.13.2 (9 Haziran 2026) `cargo fuzz init` komutuna `--fuzz-engine` bayrağını eklemiştir. Kaynak kodda desteklenen motorlar `src/options.rs` dosyasının 284-298 satırlarındadır:

```rust
pub enum FuzzEngine { LibFuzzer, LibAfl }
// "invalid fuzz engine: '{s}'. Must be one of: 'libfuzzer', 'libafl'"
```

`src/templates.rs` içindeki şablon `--fuzz-engine libafl` seçildiğinde `fuzz/Cargo.toml` dosyasına şunu yazar:

```toml
libfuzzer-sys = { version = "0.15.3", package = "libafl_libfuzzer" }
```

Yani cargo-fuzz, libFuzzer'dan LibAFL'e geçişi resmî olarak desteklemektedir ve mekanizma libfuzzer-sys yerine libafl_libfuzzer'ı yerine koymaktır. Tarihçe olarak cargo-fuzz issue #330 "LibAFL support?" 20 Aralık 2022'de açılmış ve kapanmıştır.

> **Argus için tavsiye.** Yeni fuzz projeleri `cargo fuzz init --fuzz-engine libafl` ile başlatılır; harness kodu (`fuzz_target!`) aynı kalır, yalnızca runtime değişir. libFuzzer'a geri dönmek tek satırlık bir Cargo.toml değişikliğidir.

### A.3 Sürüm ve bakım tablosu

crates.io API'sinden 8 Eylül 2026'da doğrulanmıştır.

| Araç | Son sürüm | Tarih | Durum | Argus'taki yeri |
|---|---|---|---|---|
| `cargo-fuzz` | 0.13.2 | 9 Haziran 2026 | Aktif | Ana giriş noktası; OSS-Fuzz zorunluluğudur |
| `libfuzzer-sys` | 0.4.13 | 4 Haziran 2026 | Aktif bağlayıcı | Varsayılan runtime |
| `libafl` | 0.16.1 | 11 Ağustos 2026 | Çok aktif | Özel fuzzer yazımı |
| `libafl_libfuzzer` | 0.16.1 | 11 Ağustos 2026 | Aktif | libFuzzer yerine geçer |
| `afl` ve `cargo-afl` | 0.18.2 | 11 Mayıs 2026 | Aktif | AFL++ 4.40c; persistent mode |
| `honggfuzz` | 0.5.62 | 4 Ağustos 2026 | Aktif ve düzenli | Alternatif motor |
| `bolero` ve `cargo-bolero` | 0.13.4 | 3 Temmuz 2025 | Yavaşlamıştır | Birleşik ön yüz |
| `arbitrary` | 1.4.2 | 14 Ağustos 2025 | Stabil ve olgun | Yapı farkında üretim |
| `mutatis` | 0.5.3 | 9 Haziran 2026 | Aktif | Yapı farkında mutasyon |
| `proptest` | 1.11.0 | 24 Mart 2026 | Aktif | Property-based testing |
| `proptest-state-machine` | 0.8.0 | 24 Mart 2026 (crate), 4 Temmuz 2026 (docs) | Aktif | Durumlu PBT |
| `quickcheck` | 1.1.0 | 10 Şubat 2026 | Beş yıl sonra canlanmıştır; öncesi 1.0.3, 15 Ocak 2021 | Basit PBT |
| `stateright` | 0.31.0 | 27 Temmuz 2025 | Yavaş | Model checking |
| `kani-verifier` | 0.67.0 | 16 Ocak 2026 | Aktif | Sınırlı model checking |

### A.4 Araç değerlendirmesi

**cargo-fuzz ile libFuzzer.** Olgunluğu yüksektir ve fiilî standarttır. Nightly toolchain zorunludur; x86-64 ve aarch64 Unix desteklenir. Windows desteği `--no-include-msvc` ile 0.13.0'dan (25 Haziran 2025) beri temel düzeydedir. Maliyeti neredeyse sıfırdır. Trail of Bits'in notuna göre unsafe içermeyen saf Rust kodda `--sanitizer none` yaklaşık iki kat hızlanma sağlar. Argus'ta JOSE parser'ı, SCIM filter parser'ı, LDAP BER decoder'ı, CBOR ile WebAuthn attestation'ı, OAuth query string parser'ı ve redirect_uri eşleştiricisi için kullanılır.

**LibAFL.** Araştırma sınıfıdır ancak üretimdedir. CCS 2022 makalesi (Fioraldi ve diğerleri) temelidir; 2026'da aktif kullanımı LibAFL-DiFuzz (Rust ve Go yönlendirilmiş fuzzing, arXiv 2601.22772, Ocak 2026), StorFuzz (ICSE 2026, LibAFL 0.13.1 tabanlı) ve Ruzzy'dir (Trail of Bits, Nisan 2026). Kazandırdıkları çok çekirdekli ve çok makineli ölçekleme, özel mutator, observer ve feedback, stacktrace ile tekilleştirme, grimoire mutasyonu ve TUI'dir. Maliyeti dik öğrenme eğrisidir; `libafl_libfuzzer` üzerinden kullanılırsa maliyet neredeyse sıfırdır. Platform olarak Rust, C ve C++ hedefleri Linux ile macOS'ta desteklenir; Windows yalnızca standalone kütüphane olarak desteklenir.

**afl.rs ve cargo-afl (AFL++).** Olgunluğu yüksektir ve aktiftir (0.18.2, 11 Mayıs 2026; AFL++ 4.40c). CMPLOG varsayılan olarak açıktır.

> **Kritik uyarı, Argus için doğrudan geçerlidir.** AFL++ persistent mode hedefi bir döngüde çalıştırır; `lazy_static` ve `OnceLock` gibi statik başlatmalar yalnızca ilk iterasyonda çalışır, dolayısıyla AFL'in kararlılık metriği düşer ve zaman aşımları raporlanmaz. Çözüm 0.18.0'da eklenen `fuzz_with_reset!` makrosuyla her iterasyondan sonra statik durumu temizleyen bir closure vermektir; ayrıca `rust-fuzz/resettable-lazy-static.rs` kullanılabilir. Bir IdP'de global anahtar cache'i, JWKS cache'i, session store'u ve rate limiter durumu hep statik veya lazy'dir; persistent mode kullanılacaksa reset şarttır.

**honggfuzz-rs.** Olgunluğu orta ile yüksek arasıdır ve sürümleri düzenlidir (0.5.62, 4 Ağustos 2026); toplam yaklaşık 7,8 milyon indirme almıştır. Farklılaştırıcısı donanım geri bildirimi (Intel PT ve BTS), kolay crash triyajı ile thread ve sinyal ağırlıklı koddur.

**bolero ve cargo-bolero.** Tek bir `bolero::check!` arayüzüyle libFuzzer, AFL, honggfuzz ve Kani'yi birleştirir; `--fuzzer` bayrağıyla motor değiştirilir. Sanitizer belirtilmediyse nightly gerekmez ve bu cargo-fuzz'a göre büyük bir avantajdır. Olgunluk uyarısı şudur: son sürüm 0.13.4 ve 3 Temmuz 2025 tarihlidir; 2026'da yeni sürüm yoktur. Repoda 44 açık issue ve 11 açık PR bulunmaktadır. Yani terk edilmiş değildir ancak momentum kaybetmiştir; ekosistemin geri kalanı 2026'da hareket ederken bolero durmuştur.

> **Argus için karar.** bolero'nun aynı property'yi hem birim testi hem fuzz hem Kani ispatı olarak çalıştırma modeli bir IdP için kavramsal olarak çok caziptir. Ancak tek noktadan bağımlılık riski vardır. Öneri property'leri bolero'ya değil kendi trait ve fonksiyonlarımıza yazmak, bolero'yu ince bir adaptör katmanı olarak kullanmak ve gerektiğinde cargo-fuzz ile proptest'e düşebilmektir.

### A.5 Coverage güdümlü ve yapı farkında üretim

`arbitrary` crate'i ham bayt dizisini bir DNA dizisi gibi okuyup yapılandırılmış tipe çevirir; `#[derive(Arbitrary)]` bunu otomatik üretir.

**2026'nın önemli deneysel sonucu** (Nick Fitzgerald, 1 Haziran 2026). Wasmtime'da dört yaklaşım karşılaştırılmıştır: `derive(Arbitrary)` ile düzeltme, aşağıdan yukarı üretim, yukarıdan aşağı üretim ve `derive(Mutate)` ile (mutatis crate'i) mutasyon tabanlı yaklaşım. 24 saatte mutasyon diğerlerinden %1-2 daha fazla coverage vermiştir. Beş dakikada ise mutasyon %36-49 daha fazla coverage vermiştir. Üretim yaklaşımları arasında yukarıdan aşağı, aşağıdan yukarıya üstündür. Sonuç mutasyon tabanlı fuzzing'in en iyi performansı gösterdiğidir ve yapı farkında iş için `arbitrary` yerine `mutatis` önerilir.

**Argus'a çevirisi.** CI'da PR başına 5-10 dakikalık fuzz koşusu yapılacaksa, yani CIFuzz benzeri bir kurulumda, mutasyon tabanlı yaklaşımın avantajı çok büyüktür. Uzun gece koşularında fark küçülür. Yani CI'da mutatis, gecelik koşuda her ikisi kullanılır.

Ayrıca `fuzz_mutator!` makrosuyla özel mutator yazılabilir; sıkıştırılmış veri için, örneğin JWE'nin `zip=DEF` alanı için kanonik desen şudur: aç, mutasyona uğrat, yeniden sıkıştır.

### A.6 Argus protokol mesajları için gramer tasarımı

| Yüzey | Yaklaşım | Notlar |
|---|---|---|
| JWS ve JWT compact | `#[derive(Arbitrary)]` ile `struct Jws { header: JoseHeader, payload: Vec<u8>, sig: Vec<u8> }` ve kanonik bir serializer | Header enum ile açık string karışımı olmalıdır: `alg` alanı `Known(Alg)` veya `Raw(String)` biçiminde olmalı ki `none`, `NONE`, `nOnE`, sondaki boşluklu `HS256 ` ve unicode homoglyph'ler üretilebilsin |
| JOSE header | `crit`, `jku`, `jwk`, `x5u`, `x5c`, `kid`, `zip`, `p2c`, `p2s`, `epk`, `apu` ve `apv` alanlarının hepsi opsiyonel ve tip karışık olmalıdır | jsonwebtoken CVE-2026-25537 tam olarak tip karışıklığından çıkmıştır; `exp` ve `nbf` için Number, String, Bool, Null ve Array üretilir |
| JWS JSON serialization | Ayrı bir hedef | JWT Format Confusion sınıfı buradan çıkar (NDSS 2026) |
| OAuth istek parametreleri | `Vec<(String, String)>` ve yüzde kodlama mutator'ı | Tekrarlanan parametreler (`scope=a&scope=b`), boş değer, `+` ile `%20` farkı, aşırı uzun `state` |
| `redirect_uri` | Ayrı ve yüksek öncelikli hedef | Diferansiyel test için idealdir |
| SAML XML | quick-xml veya roxmltree üstünde `arbitrary` tabanlı bir XML AST ve XSW mutator'ı | quick-xml advisory'lerine dikkat edilir |
| CBOR ve WebAuthn attestation | `ciborium` ve `coset` üstünde yapı farkında üretim; COSE_Key ile attStmt için ayrı gramer | — |
| SCIM JSON ve SCIM filter | Filter parser'ı ayrı fuzz edilir | Kanidm'in 2026'daki en ciddi iki açığı tam buradandır |

### A.7 Async Rust ve tokio fuzzing'i

Bunlar Argus için gerçek engellerdir.

Fuzz harness'ı senkron olmalıdır. `fuzz_target!` bir `&[u8]` alır ve döner. tokio kodu için her iterasyonda `Runtime::new()` yaratmak çok pahalıdır; tek bir `current_thread` runtime'ı `OnceLock` içinde tutup `block_on` kullanmak gerekir, ancak bu persistent modda durum sızıntısı yaratır.

AFL persistent mode ile lazy static çakışması A.4'te anlatılmıştır.

Coverage gürültüsü vardır: tokio scheduler'ı deterministik olmayan dallanma üretir ve coverage geri bildirimi bozulur. Pratik çözüm runtime'ı harness'tan tamamen çıkarmaktır; parser, validator ve durum makinesi katmanları async olmayan saf fonksiyonlar olarak tasarlanır ve onlar fuzz edilir.

Zaman aşımı ve bellek tükenmesi konusunda OSS-Fuzz'da hedef başına yaklaşık 25 saniye zaman aşımı ve 2,5 GB RAM sınırı vardır. `p2c` iterasyon DoS'u gibi CPU bağımlı hatalar burada zaman aşımı olarak yakalanır ve bu iyi haberdir.

> **Argus mimari tavsiyesi.** Hexagonal bir ayrım yapılır: `argus-core` saf, senkron ve I/O içermeyen olur (token doğrulama, politika kararı, filter ayrıştırma); `argus-http` axum ve tokio katmanıdır. Fuzzing ile PBT'nin %90'ı `argus-core`'a uygulanır ve orada hem hızlı hem deterministiktir. Bu tek karar fuzzing yatırımının getirisini katlar.

### A.8 Snapshot ve Nyx fuzzing

Nyx (USENIX Security 2021, Schumilo ve diğerleri) KVM-PT ile QEMU-PT kullanarak tam VM snapshot'ı alır ve saniyede binlerce geri yükleme yapar. Nyx-Net (EuroSys 2022) durumlu ağ servisleri için artımlı snapshot sunar; gürültüsüz fuzzing ve temiz duruma hızlı dönüş sağlar. Harness framework'ü Neodyme'nin HyperHook'udur.

2026 durumu doğrulanamamıştır; Nyx için 2025 ve 2026'ya ait yeni bir major sürüm veya duyuru bulunamamış, bulunan tüm kaynaklar 2021 ile 2022 tarihlidir. LibAFL tarafında `libafl_qemu` ve `libafl_nyx` entegrasyonu vardır ve LibAFL 0.16.1 (Ağustos 2026) aktiftir; snapshot fuzzing'in 2026'daki canlı yolu muhtemelen LibAFL üzerindendir.

> **Argus için karar.** Nyx aşırı ağırdır. Bir IdP'de kazanç maliyet oranı düşüktür, çünkü asıl risk bellek güvenliği değil (Rust kullanılmaktadır) mantık ve kaynak tüketimidir. Snapshot yerine A.7'deki mimari ayrım ve süreç içi HTTP harness'ı çok daha verimlidir.

---

## B. Diferansiyel fuzzing

### B.1 Kavram ve klasik örnekler

**Frankencerts** (Brubaker ve diğerleri, IEEE S&P 2014) gerçek sertifikaların parçalarını rastgele birleştirip frankencert üretmiş ve OpenSSL, NSS, CyaSSL, GnuTLS, PolarSSL ile MatrixSSL'i diferansiyel test etmiştir. 8.127.600 sertifika 208 tutarsızlık ve dokuz farklı kök neden ortaya çıkarmıştır.

**NEZHA** (Petsios ve diğerleri, IEEE S&P 2017) alandan bağımsız diferansiyel test sunar; davranışsal asimetriyi geri bildirim sinyali olarak kullanır. 10.000 iterasyonda ortalama yalnızca 98,3 sertifika üretip %81,74 çeşitlilik sağlamıştır ve frankencert'ten kat kat verimlidir.

**transcert** (TOSEM 2022, coverage yönlendirmeli) 10.000 iterasyonda 71 benzersiz doğrulama farkı bulmuştur; bu frankencert'in 12 katı, NEZHA'nın 1,4 katı ve RFCcert'in yedi katıdır.

**Project Wycheproof** kripto kütüphanelerini bilinen saldırılara karşı test vektörleriyle sınar: AES, DH, DSA, ECDH, ECDSA ve RSA; invalid curve saldırısı, biased nonce ve Bleichenbacher varyantları kapsanır. 2025 ve 2026'da C2SP çatısı altına taşınmış ve yeniden canlandırılmaktadır; öncelik tüm test vektörlerinin JSON şema tanımlarının tamamlanmasıdır. Son paket `wycheproof-testvectors-20251219`'dur.

> **Argus için.** JOSE imza ve şifreleme katmanının Wycheproof vektörleriyle beslenmesi zorunlu bir taban çizgisidir. Fuzzing'in bulamayacağı şeyleri, örneğin psychic signature ve invalid curve'ü, bunlar bulur.

**Cryptofuzz ve Cryptofuzz++** kripto kütüphanelerinin diferansiyel fuzzing'ini yapar; ICISC 2024'te hibrit fuzzing ve kriptoya özel mutasyonla genişletilmiştir.

**Risk Estimation in Differential Fuzzing via Extreme Value Theory** (arXiv 2511.02927) diferansiyel fuzzing'de kaçırılan hata riskini istatistiksel olarak tahmin etmeyi ele alır.

### B.2 JWT kütüphanelerinin diferansiyel fuzzing'i

Bu yapılmıştır ve 2026'nın en önemli çalışmasıdır.

Künye: "Token Time Bomb: Evaluating JWT Implementations for Vulnerability Discovery", NDSS Symposium 2026, 23-27 Şubat 2026, San Diego; DOI 10.14722/ndss.2026.240697. Yazarları Jingcheng Yang, Enze Wang (eş birinci yazar), Jianjun Chen (sorumlu yazar, Tsinghua), Qi Wang, Yuheng Zhang ve Haixin Duan (Tsinghua University) ile Wei Xie ve Baosheng Wang'dır (National University of Defense Technology).

**Metodoloji (JWTeemo).** FBNF, yani Function-extended Backus-Naur Form, ABNF'i genişleterek JWT'yi RFC'lerden modelleyen yeni bir gramer dilidir; semantik bağımlılıklar graf kenarları olarak modellenir, örneğin `signature` düğümünden `alg_value` düğümüne yönlü bir kenar vardır, çünkü imzanın üretimi `alg` değerine bağlıdır. UCT-Rand, Monte Carlo ağaç araması ile gramer grafındaki düğüm seçimini modelleyip hedef implementasyonun ayrıştırma geri bildirimiyle ağırlıkları günceller; örneğin JWE, p2s ve p2c yolu başarıyla ayrıştırılırken JWE ile p2s tek başına başarısızsa fuzzer `p2c`'nin `p2s` ile birlikte gerekli olduğunu öğrenir. Differential Analyzer iki strateji kullanır: ayrıştırma tutarsızlığı, yani aynı token'ı farklı implementasyonların farklı kabul veya reddetmesi; ve kaynak tükenmesi, yani `R > μ + k·σ` biçiminde istatistiksel bir eşik, Chebyshev eşitsizliğiyle. Ablasyon çalışmasında mutator'sız ve UCT'siz varyantlara karşı edge coverage'da net üstünlük gösterilmiştir.

**Sonuçlar.** On dilde 43 JWT implementasyonu incelenmiş, 17 kütüphanede 31 sıfır gün bulunmuş ve 20 CVE alınmıştır. Kubernetes'te kimlik doğrulama atlatması, Apache James'te hizmet reddi tespit edilmiştir. Apache, Connect2id, Kubernetes, Let's Encrypt ve RedHat'ten bug bounty alınmıştır. IETF bulguları kabul etmiş ve azaltmaları yeni bir RFC'ye alacağını belirtmiştir.

**Beş kök neden kategorisi.** Sign ve encryption confusion (iki adet): JWS doğrulama public key'i ile JWE üretip token'ı JWE zannettirmektir; saldırgan public key'i alır, normal login ile JWS alır, payload'daki `role` alanını `admin` yapar ve public key ile şifreleyip sahte bir JWE üretir; kurban implementasyon noktaların sayısına bakarak bunun JWE olduğuna karar verip private key ile açar ve yetki yükselmesi olur. Algorithm confusion (iki adet). JWT format confusion (dört implementasyon risklidir): JWS'in JSON serialization formatını ayrıştırmadan kaynaklanır. Billion hashes saldırısı (on adet): PBES2 `p2c` parametresinden kaynaklanır ve PBES2 destekleyen implementasyonların %71,9'u savunmasızdır. Compression DoS (on üç adet): JWE `zip=DEF` alanından kaynaklanır ve JWE destekleyen implementasyonların %86,7'si savunmasızdır.

Makalenin birinci tablosundan bulunan yeni açıklar:

| Dil | Kütüphane | Sürüm | Açık | CVE |
|---|---|---|---|---|
| Python | python-jose | 3.3.0 | Compression DoS | CVE-2024-29370 |
| Python | jwcrypto | 1.5.0 | Billion Hashes | CVE-2023-6681 |
| Python | jwcrypto | 1.5.0 | Compression DoS | CVE-2024-28102 |
| Python | jwcrypto | 1.5.0 | JWT Format Confusion | Düzeltilmiştir; CVE yoktur |
| Python | authlib | 1.2.1 | Compression DoS | Atanmamıştır |
| C | latchset/jose | 11 | Billion Hashes | CVE-2023-50967 |
| C | latchset/jose | 11 | JWT Format Confusion | Atanmamıştır |
| C | libjwt | 1.15.3 | Algorithm Confusion | CVE-2024-57453 |
| C++ | cpp-jwt | 1.4 | Algorithm Confusion | CVE-2024-57454 |
| Java | jjwt | 0.12.3 | Billion Hashes | CVE-2024-39960 |
| Java | jjwt | 0.12.3 | Compression DoS; JWS'te de | İki adet atanmamıştır |
| Java | jose4j | 0.9.3 | Billion Hashes | CVE-2023-51775 |
| Java | jose4j | 0.9.3 | Compression DoS | CVE-2024-29371 |
| Java | nimbus-jose-jwt | 9.37.1 | Billion Hashes | CVE-2023-52428 |
| Java | nimbus-jose-jwt | 9.37.1 | Compression DoS | Atanmamıştır |
| C# | jose-jwt | 4.1.0 | Sign ve Encrypt Confusion | CVE-2024-24238 |
| C# | jose-jwt | 4.1.0 | Compression DoS | CVE-2024-27663 |
| JavaScript | jose (panva) | 5.1.3 | Compression DoS | CVE-2024-28176 |
| JavaScript | node-jose | 2.2.0 | Billion Hashes | CVE-2024-39960 |
| JavaScript | node-jose | 2.2.0 | Compression DoS | Atanmamıştır |
| PHP | jwt-framework | 3.2.8 | Billion Hashes | Düzeltilmiştir |
| PHP | jwt-framework | 3.2.8 | Compression DoS | Atanmamıştır |
| Go | jose2go | 1.5.0 | Billion Hashes | CVE-2023-50658 |
| Go | jose2go | 1.5.0 | Compression DoS | CVE-2025-63811 |
| Go | go-jose | 3.0.1 | Compression DoS | CVE-2024-28180 |
| Go | go-jose | 3.0.1 | JWT Format Confusion | Atanmamıştır |
| Go | jwx (lestrrat) | 2.0.17 | Billion Hashes | CVE-2023-49290 |
| Go | jwx | 2.0.17 | Compression DoS | CVE-2024-28122 |
| Go | jwx | 2.0.17 | JWT Format Confusion | Düzeltilmiştir |
| Ruby | json-jwt | 1.16.3 | Sign ve Encrypt Confusion | CVE-2023-51774 |

> **Argus için kritik bulgu.** Makale metninde Rust kelimesi hiç geçmemektedir. Test edilen on dil Python, C, C++, Java, C#, JavaScript, PHP, Go, Ruby ve Swift'tir. Rust JOSE kütüphaneleri (jsonwebtoken, josekit, jwt-simple, biscuit) bu çalışmanın kapsamı dışındadır. Bu Argus için hem bir risktir, çünkü durum bilinmemektedir, hem bir fırsattır, çünkü JWTeemo metodolojisini Rust ekosistemine ilk uygulayan biz olabiliriz ve bu yayımlanabilir bir iştir.

### B.3 Chai

"Chai: Agentic Discovery of Cryptographic Misuse Vulnerabilities", arXiv 2606.26933. Yaklaşımı kütüphane seviyesindeki kusurları kataloglamak, sonra bunları kriptografik bağımlılık grafında yaymaktır. İki aşamalıdır: önce kütüphane içindeki gerçek güvenlik sorunlarını yüksek hassasiyetle bulur, sonra tutarsızlıkları bağımlı uygulamalardaki açık göstergesi olarak kullanır. Değerlendirme alanları X.509, JWT ve SAML'dir. Chai'nin yaklaşımı önceki araçlardan daha az girdiyle daha fazla benzersiz fark bulmaktadır. Sonuçları milyarlarca cihazda kullanılan bir SSL kütüphanesinde önceden bilinmeyen kritik bir açık, büyük bir web tarayıcısının kripto kütüphanesinde hatalar ve major Linux dağıtımlarıyla gelen kütüphanelerde açıklardır; toplam 100'den fazla açık bulunmuştur.

### B.4 Bir OAuth Authorization Server'ını diferansiyel test etmek

Referans implementasyonlar diff hedefi olarak şunlardır:

| Referans | Dil | Neden iyi bir oracle | Zorluk |
|---|---|---|---|
| ory/hydra | Go | OpenID Certified'dır, headless'tır ve kullanıcı yönetimi içermez, yani yalnızca protokoldür. En iyi diff hedefidir | Login ve consent URL'leri yapılandırılmalıdır |
| node oidc-provider (panva) | JavaScript | Spec'e en sadık olanıdır, süreç içi çalıştırılabilir ve çok esnektir | JavaScript runtime köprüsü gerekir |
| Keycloak | Java | En yaygın ve en çok özellikli olandır | Ağırdır, kendi login arayüzü vardır ve durumludur |
| Authlete | SaaS | API tabanlıdır ve sertifikalıdır | Ücretlidir ve ağa bağımlıdır |
| oauth2-server ve fosite | Go ve JavaScript | Kütüphane seviyesindedir ve gömülebilir | Tam bir AS değildir |

**OpenID Conformance Suite** (OIDF, açık kaynak) AS ve RP için test planları sunar; sahte bir OP ve AS sağlar; master dalı günde en az bir kez satıcı bulut ortamlarına karşı regresyon testinden geçer ve yerelde Docker ile kurulabilir. Argus için birinci gün hedefi olmalıdır.

**OAuch** (DistriNet ve KU Leuven) AS implementasyonlarının OAuth standartlarına ve tehdit modeline uyumunu analiz eder. AS'in desteklediği özellikleri otomatik tespit edip yalnızca ilgili testleri koşar. Kategorileri ve test sayıları şunlardır: doküman ve özellik desteği 29 test (RFC 6749, RFC 7636 PKCE, RFC 8705 mTLS, grant tipleri, OIDC); token güvenliği 39 test (token endpoint doğrulaması, client auth, code bağlama, refresh mekaniği, access token ile refresh token ve authorization code entropi ölçümü, zaman aşımı, rotasyon); kriptografi ve kimlik 26 test (JWT imza, exp ve aud doğrulaması, ID token claim'leri, PKCE downgrade koruması); endpoint güvenliği 39 test (HTTPS ve TLS, sertifika doğrulaması, cipher suite gücü, redirect URI doğrulaması, güvenlik başlıkları); token yönetimi 13 test (iptal, client bağlama, eşzamanlı token'lar, refresh token geçersizleştirme).

> **Gerçek dünya kanıtı.** Kanidm'e karşı OAuch koşulmuş ve GHSA-hh34-7jqq-3f73 (23 Haziran 2026, Low) doğmuştur. Dört bulgu vardır: authorization code ilk kullanımdan sonra geçersizleştirilmemektedir (RFC 9700 ihlali); 34 karakterden kısa PKCE code_verifier reddedilmemektedir (RFC 7636); authorization sayfasında X-Frame-Options yoktur (clickjacking); authorization akışında Referer başlığı bastırılmamaktadır (RFC 9700). Bildiren oliverpool, araç geliştiricisi pieterphilippaerts'tir.

**Argus için diferansiyel test mimarisi.**

```
┌─────────────────┐
│ Fuzzer (LibAFL) │  yapı farkında OAuth senaryo üreteci
└────────┬────────┘   (Arbitrary ve Mutate ile: client kaydı ve istek dizisi)
         │
    ┌────┴────┬──────────────┐
    ▼         ▼              ▼
 Argus AS   ory/hydra   node oidc-provider
    │         │              │
    └────┬────┴──────────────┘
         ▼
  Normalizer  →  aynı girdi için:
                 - HTTP status sınıfı (2xx, 3xx, 4xx)
                 - OAuth hata kodu (invalid_request, invalid_grant, ...)
                 - redirect Location'ın host, path ve query anahtarları
                 - token verildi mi; scope kümesi; aud; exp
         ▼
  Differ  →  kabul ile ret ayrışması yüksek öncelikli sinyaldir
```

**Diferansiyel testin en verimli altı yüzeyi, öncelik sırasıyla.**

Birincisi `redirect_uri` eşleştirmesidir ve tarihsel olarak en bereketli alandır. Üretilecekler sondaki eğik çizgi, `//`, `/../`, userinfo (`https://a@evil.com`), unicode host, IDN homoglyph, port varyasyonu, `?` ve `#` fragment'leri, kodlanmış `%2e%2e`, boş path, wildcard subdomain, `localhost` ile `127.0.0.1` ve `[::1]` farkı ile path traversal'dır. Argus kabul edip hydra reddediyorsa muhtemelen bir açık vardır.

İkincisi `scope` ayrıştırma ve verilmesidir. Boşlukla ayrılmış listede tekrarlanan scope, boş scope, `scope=` biçiminde boş değer, tab ve newline ayırıcı, aşırı uzun değer ve unicode boşluklar denenir. Verilen scope kümesinin, istenen kümenin ve client'ın izinli kümesinin kesişiminin alt kümesi olup olmadığı kontrol edilir.

Üçüncüsü PKCE'dir. `code_challenge_method` yok, `plain`, `S256` veya bilinmeyen olabilir; verifier uzunluğu sınırın dışında 42 denenir (sınır 43-128'dir); base64url padding'li ve padding'siz varyantlar; `+` ile `/` yerine `-` ile `_`; code_challenge ile code_verifier eşleşmesi test edilir.

Dördüncüsü token endpoint client authentication'dır. `client_secret_basic` ile `client_secret_post` ikisi birden gönderilirse ne olur; Basic auth'ta URL kodlaması nasıl ele alınır; `client_id` iki farklı yerde farklı değerlerle gelirse ne olur.

Beşincisi `grant_type` ve `response_type` kombinasyonlarıdır: bilinmeyen değerler, çoklu değerler ve sıra permütasyonları.

Altıncısı JWT doğrulamasıdır. Burada asıl referanslar JOSE kütüphaneleridir: Rust'ta `jsonwebtoken`, JavaScript'te `panva/jose`, Go'da `go-jose` ve Java'da `nimbus-jose-jwt`; aynı token'a farklı sonuç veriyorlarsa hangisinin doğru olduğu incelenir.

**Oracle problemi ve çözümü.** Diferansiyel testte iki implementasyon ayrıştığında hangisinin haklı olduğu sorusu çıkar. Cedar'ın çözümü bir tarafı kanıtlanmış bir model yapmaktır. Argus için uygulanabilir versiyonu şudur: `argus-core`'un token doğrulama ve politika karar mantığı için ayrı, minimal ve aşikâr biçimde doğru bir referans model, yani çalıştırılabilir bir spesifikasyon yazılır; asıl implementasyon optimizasyonlarla dolu olur. Model ile implementasyon arasında differential random testing koşulur. Bu, Cedar'ın tam formülüdür ve dış kütüphanelere bağımlılığı ortadan kaldırır.

---

## C. Erişim kontrolünün property-based testi

### C.1 proptest ile quickcheck

| | proptest | quickcheck |
|---|---|---|
| Üretim modeli | Strategy nesneleri; değer başına | Tip başına `Arbitrary` |
| Esneklik | Kompozisyon kolaydır; aynı tip için farklı stratejiler yazılabilir | Tip başına tek generator vardır; newtype sarmak gerekir |
| Shrinking | Gelişmiş ve entegredir | Basittir |
| Hız | Karmaşık değerlerde bir mertebe daha yavaş olabilir | Hızlıdır |
| Sürüm ve bakım | 1.11.0, 24 Mart 2026; aktiftir, Aralık 2024'ten beri 1.6'dan 1.11'e altı sürüm | 1.1.0, 10 Şubat 2026; Ocak 2021'den beri ilk sürümdür |
| Resmî not | Feature-complete'e yakındır, mimari değişiklik yoktur, pasif bakımdadır | — |

**Argus kararı proptest'tir.** Bir IdP'de üretilen değerler — politika ağaçları, rol grafları, token dizileri — karmaşık ve bağlama duyarlıdır; quickcheck'in tip başına modeli bunu taşımaz. proptest'in pasif bakım durumu bir risk değil olgunluk göstergesidir; 2026'da hâlâ minor sürümler çıkmaktadır.

proptest'in yanında `arbitrary` kullanılır; aynı `#[derive(Arbitrary)]` tipleri hem proptest testlerini hem fuzz hedeflerini besler. Bu, PBT'de bulunanın fuzz corpus'una atıldığı ve fuzz'da bulunanın PBT regresyonuna alındığı bir döngü kurar; bolero bunu yerleşik olarak yapar.

### C.2 Güvenlik invariantlarını property olarak yazmak

#### C.2.1 Altın standart: AWS Cedar'ın doğrulama güdümlü geliştirmesi

Bu, Argus'un doğrudan kopyalaması gereken modeldir.

Kaynaklar "How We Built Cedar: A Verification-Guided Approach" (arXiv 2407.01688, 1 Temmuz 2024, 13 yazar, iletişim Shaobo He), Amazon Science blogu, Lean'e taşınma RFC'si (0032), `cedar-policy/cedar-spec` deposu ve lean-lang.org'daki Cedar vaka çalışmasıdır.

**Üç ayak.** Çalıştırılabilir formel model yazılır (önce Dafny, sonra Lean 4'e taşınmıştır) ve model üzerinde teoremler mekanik olarak kanıtlanır. Differential random testing ile milyonlarca rastgele girdi üretilip hem modele hem Rust üretim koduna verilir; çıktılar aynı değilse bir hata vardır. Modellenmemiş parçalar için QuickCheck tarzı doğrudan property testleri yazılır.

**Somut sayılar.** Gecelik altı saat differential random testing ile günde yaklaşık 100 milyon test koşulur. Lean modeli test başına 5 µs, Rust üretim kodu 7 µs sürer; yani Lean modeli differential testing için yeterince hızlıdır. Lean modelleri Rust muadillerinden bir mertebe daha küçüktür. Toplam 25 hata bulunmuştur; dördü model kanıtlanırken, yirmi biri differential ve property-based testing ile bulunmuştur. Bulunan hata tipleri harici bir Rust IP adresi ayrıştırma paketindeki hata, Cedar politika parser'ındaki ince kusurlar, authorizer'ın eksik uygulama verisini ele alışındaki hatalar ve namespace prefix yorumlamasındaki hatadır. Kanıtlanan iki temel property explicit permit (erişim yalnızca açık bir `permit` politikası üzerinden verilir) ve forbid overrides permit'tir (uygulanabilir herhangi bir `forbid` politikası tüm `permit`'lere rağmen erişimi reddeder). Süreç kuralı şudur: modeli, kanıtları ve diferansiyel testleri güncel olmayan hiçbir Cedar sürümü yayımlanmaz.

Teknik yığın `cedar-lean` (Lean 4 formalizasyonu ve kanıtlar), `cedar-drt` (test framework'ü) ve `cedar-policy-generators`'tır (`arbitrary` crate'i ile şema, entity, politika ve istek üretimi). Çalıştırma `cargo fuzz run -s none <target>` biçimindedir.

#### C.2.2 Diğer yetkilendirme motorları

Cerbos'un deposunda bir fuzzing issue'su (#149) vardır; resmî bir fuzzer çıktığında motoru fuzz etme planı bulunmaktadır ve amaç nadir uç durumları yakalamaktır. Cerbos'un asıl test hikâyesi YAML politika test dosyaları ve Cerbos Hub'daki politika testi ile versiyonlamadır.

SpiceDB'de `internal/services/integrationtesting/` altında `consistencytestutil/`, `consistency_test.go`, `consistency_datastore_test.go` ve `queryconsistency/` bulunmaktadır; sistematik tutarlılık testi yapılmaktadır. Ancak dizin listesinden metodolojinin property-based mi klasik assertion mı olduğu çıkarılamamaktadır.

OpenFGA'da `tests/` altında `authzen/`, `check/`, `listobjects/`, `listusers/` ve `functional_test.go` bulunmaktadır; fuzzing veya PBT'ye dair kanıt doğrulanamamıştır.

Oso politika testi, karar izleme ve REPL sunmaktadır; PBT veya fuzzing kanıtı doğrulanamamıştır.

Zanzibar tutarlılığı açısından SpiceDB new enemy problemine karşı ZedToken ile snapshot tutarlılığı sağlar; OpenFGA yapılandırılabilir okuma modları ve transactional timestamp kullanır. Bu, Argus'un session ve permission cache'i için doğrudan bir invariant kaynağıdır.

> **Sonuç.** Cedar dışında yetkilendirme dünyasında ciddi ve yayımlanmış property veya differential testing pratiği yoktur. Argus en güvenli IdP iddiasını Cedar'ın doğrulama güdümlü geliştirme modelini benimseyerek somut ve savunulabilir hâle getirebilir; bu pazarda gerçek bir farklılaştırıcıdır.

#### C.2.3 Model tabanlı ve durumlu property testing araçları

**`proptest-state-machine` 0.8.0** (crate 24 Mart 2026, docs 4 Temmuz 2026; %95,65 doküman kapsamı; proptest 1.10 ve üstünü gerektirir) iki trait sunar.

`ReferenceStateMachine` trait'i `State` ve `Transition` (enum) tiplerini, `init_state()` (Strategy), `transitions(state)` (genelde `prop_oneof!`), `apply(state, transition)` ve `preconditions(state, transition)` metotlarını tanımlar; sonuncusu geçişin geçerliliği duruma bağlıysa kritiktir.

`StateMachineTest` trait'i `SystemUnderTest` ve `Reference` tiplerini, `init_test(ref_state)`, `apply(...)` (post-condition assert'leri buradadır), `check_invariants(state, ref_state)` (her geçişten sonra koşar) ve `teardown()` metotlarını tanımlar.

Makro `prop_state_machine! { #[test] fn t(sequential 1..20 => MyTest); }` biçimindedir.

Shrinking sırası şudur: önce sondan geçiş silinir, sonra baştan tek tek geçişler küçültülür, en son başlangıç durumu küçültülür. Bir güvenlik hatasını üç istekten oluşan bir diziye indirger ve triyaj için paha biçilmezdir.

Pratikte geliştirme sırasında `PROPTEST_CASES` yüksek tutulur; `PROPTEST_VERBOSE=1` uygulanan geçişleri gösterir.

**`proptest-stateful`** (ReadySet) alternatiftir; operasyon dizisi üretip tek tek çalıştırır ve her operasyondan sonra post-condition kontrol eder.

**`stateright` 0.31.0** (27 Temmuz 2025) dağıtık sistemler için bir model checker, actor runtime'ı, gömülü arayüz ve linearizability test edici sunar. TLA+ ve TLC'den farkı, Rust'ta yazılan sistemin hem model kontrol edilip hem gerçek ağda çalıştırılabilmesi, yani yeniden implementasyon gerektirmemesidir. Örnekleri Single Decree Paxos ve iki fazlı commit'tir. Uyarı olarak 0.30.2 (Haziran 2024), 0.31.0 (Temmuz 2025) ve sonrası yoktur; gelişim yavaştır. Argus'taki yeri çok düğümlü bir Argus kümesinde replikasyon ve iptal yayılımıdır; iptal edilmiş bir token'ın iptali henüz görmemiş bir replikada kabul edilip edilmediği tam bir stateright sorusudur.

**`kani-verifier` 0.67.0** (16 Ocak 2026) Rust MIR'ından CBMC'ye derleyen bir sınırlı model checker'dır. Otomatik kontrolleri aritmetik taşma, sıfıra bölme, null dereference ve assertion ihlalidir; anotasyon gerektirmez. Fonksiyon kontratları, döngü kontratları, niceleyiciler ve fonksiyon stubbing ile sınırlıdan sınırsıza çıkmaktadır; kontratlar panic yokluğundan fonksiyonel doğruluğa yükseltmiş ve altı yeni hata ortaya çıkarmıştır. Ölçek olarak Rust standart kütüphanesi doğrulama kampanyasında kod değişikliği başına 16.000'den fazla harness doğrulanmaktadır ve araç Amazon'un kritik altyapısında kullanılmaktadır. Argus'taki yeri `constant_time_eq`, base64url decode, varint ve uzunluk ayrıştırma ile `p2c` sınır kontrolü gibi küçük ve kritik fonksiyonlardır; tüm IdP'yi Kani ile doğrulamaya kalkışılmaz.

**TLA+ ve P** protokol durum makineleri içindir. OAuth ve OIDC'nin akademik formel analizinde kullanılan araçlar aslında Tamarin ve ProVerif'tir: "A Comprehensive Formal Security Analysis of OAuth 2.0" (arXiv 1601.01229); ETH Zürich lisans tezindeki OIDC Tamarin modeli (yaklaşık 50 multiset rewriting kuralı, 16 thread'de yaklaşık 3,5 saatte otomatik kanıt); "Automatic Verification of Security of OpenID Connect Protocol with ProVerif"; 2026'da "Unveiling Authentication Forgery in OpenID Connect under Web Frameworks: A Formal Analysis of CSRF-Based Attack Paths".

> Bunlar protokol seviyesinde, yani Dolev-Yao saldırgan modelinde çalışır ve implementasyonu doğrulamaz. Argus için doğru kombinasyon şudur: protokol tasarımı için Tamarin veya ProVerif, implementasyon durum makinesi için stateright veya proptest-state-machine, kritik fonksiyonlar için Kani, parser'lar için fuzzing.

### C.3 IdP'ye özgü somut invariantlar

Bunlar `check_invariants()` içine veya post-condition olarak girer. RFC 9700 (Best Current Practice for OAuth 2.0 Security) referans alınmıştır.

**Token yaşam döngüsü.**

1. `revoke(t)` sonrasında hiçbir `validate(t)` çağrısı geçerli dönmez; hangi sırayla, kaç kez ve hangi endpoint'ten sorulursa sorulsun. Bu bir monotonluk invariantıdır; iptal edilenler kümesi asla küçülmez.
2. `introspect(t).active == true` koşulu, `t`'nin iptal edilmemiş olmasına, `now < t.exp` ve `now ≥ t.nbf` olmasına ve `t.client_id`'nin aktif olmasına denktir.
3. Bir access token'ın scope'u, onu doğuran authorization code'un scope'unun alt kümesidir ve refresh ile asla genişlemez (RFC 6749 §6).
4. `exp - iat` yapılandırılmış azami ömrü aşmaz; her zaman ve her grant tipinde.
5. Token'ın `aud` değeri, istenen kaynağın tescilli tanımlayıcısı olmayan bir değer içeremez.

**Refresh token rotasyonu ve replay tespiti.** RFC 9700 §4.14'e göre public client'lar için refresh token'lar ya sender-constrained olmalı ya rotasyon kullanmalıdır.

6. `RT_n` kullanıldığında `RT_{n+1}` üretilir ve `RT_n` geçersizleşir.
7. Replay tespiti: `RT_n` ikinci kez sunulursa tüm zincir (`RT_0` ile `RT_{n+k}` arası) ve türetilmiş access token'lar iptal edilir. Bu durumlu bir property'dir; geçiş dizisi `[Use(RT0), Use(RT1), Use(RT0)]` üretilmeli ve sonrasında `Use(RT2)` başarısız olmalıdır.
8. Eşzamanlılık: `Use(RT_n)` iki kez paralel çağrılırsa en fazla biri başarılı olur, yani linearizability sağlanır. Bunun için stateright'ın linearizability test edicisi veya `prop_state_machine!` eşzamanlı modu kullanılır.

**Yetki yükseltmesi ve sıralama.**

9. Rol atama sırasından bağımsızlık: aynı rol atama kümesinin herhangi bir permütasyonu aynı efektif izin kümesini verir. proptest'te `shuffle` stratejisi ve sonuç eşitliği ile test edilir. Kanidm'in Critical GHSA-xxwr-vvr3-2g9f açığı tam bu ailedendir; küme modifikasyonlarının yanlış ele alınmasından kaynaklanmıştır.
10. Monotonluk kuralı: bir kullanıcıdan rol çıkarmak hiçbir zaman izin eklememelidir; `permissions(roles \ {r}) ⊆ permissions(roles)`.
11. Deny üstünlüğü (Cedar'ın forbid overrides permit'i): herhangi bir uygulanabilir deny varsa sonuç Deny'dır.
12. Explicit permit: hiçbir permit uygulanabilir değilse sonuç Deny'dır, yani varsayılan olarak reddedilir.

**Oturum.**

13. Oturum downgrade'inin imkânsızlığı: bir oturumun AMR ve ACR seviyesi (`pwd`, `mfa`, `hwk` sırasıyla) yalnızca artabilir; hiçbir istek dizisi onu düşüremez.
14. Oturum kimliği rotasyonu: ayrıcalık yükseltme olayında, yani login ve MFA yükseltmesinde, oturum tanımlayıcısı değişir.
15. `logout(s)` sonrasında `s` ile hiçbir kaynağa erişilemez ve türetilmiş tüm token'lar iptaldir.

**Onay.**

16. Onay öncelikli verme: `authorize` bir scope için code döndürüyorsa ya o scope için kayıtlı bir consent kaydı vardır ya client trusted veya first-party olarak işaretlidir; aksi hâlde consent ekranı gösterilmelidir. Bu her yol için geçerli bir property'dir ve durum makinesinde `Authorize` geçişinin post-condition'ıdır.
17. Onay geri çekildiğinde (`revoke_consent`) o onaya dayanan tüm aktif refresh token'lar iptal edilir.

**PKCE ve code.**

18. Authorization code tam olarak bir kez kullanılabilir; ikinci kullanımda code ve ondan doğan tüm token'lar iptal edilir (RFC 9700). Kanidm burada başarısız olmuştur; OAuch bulgusudur.
19. `code_verifier`, code'u yaratan `code_challenge` ile eşleşmelidir; challenge yoksa ve client public ise istek reddedilir.
20. Code, onu isteyen `client_id` ve `redirect_uri` ile bağlıdır ve farklı client veya redirect ile takas edilemez.

**Kripto ve kodlama.**

21. Round-trip: her `x` için `parse(serialize(x)) == x` sağlanır; JWT, SCIM filter, SAML assertion ve CBOR attestation için geçerlidir.
22. Idempotent kanonikleştirme: `canon(canon(x)) == canon(x)`.
23. Sabit zaman: `constant_time_eq(a,b)` çalışma süresi `a` ve `b` içeriğinden bağımsızdır; Kani ile kanıtlanabilir kısmı erken dönüş olmamasıdır.

### C.4 Metamorfik test

Metamorfik test oracle problemini çözer: mutlak doğru cevabı bilmek yerine girdi değişikliği ile çıktı değişikliği arasındaki ilişki, yani metamorfik ilişki, doğrulanır.

"Metamorphic Testing for Web System Security" (IEEE TSE 2023; Bayati Chaleshtari, Pastore, Goknil, Briand) OWASP kılavuzlarından ilham alan bir metamorfik ilişki kümesi, bu ilişkileri belirtmek için bir DSL ve veri toplama ile otomatik test framework'ü sunar. Örnek bir OWASP kaynaklı ilişki yetkilendirme şemasını atlatmaktır: admin arayüzündeki linkler toplanır ve aynı URL'lere başka bir kullanıcının kimlik bilgileriyle erişilir; sonuç 403 olmalıdır.

Erişim kontrolü politikası mutasyon testi konusunda Martin ve arkadaşları ilk olarak erişim kontrolü politikalarını mutasyon testiyle test etmeyi önermiştir; model tabanlı testler erişim kontrolü hata tespiti değerlendirmelerinde mutantların %99,7'sini öldürmüştür.

Argus için sekiz somut metamorfik ilişki şunlardır:

| # | İlişki | Beklenen |
|---|---|---|
| MR1 | Aynı istek farklı bir kullanıcının token'ıyla tekrarlanır | Yetkisizse 403 veya 404 döner, asla 200 dönmez |
| MR2 | Token'ın scope'u daraltılır | İzin kümesi öncekinin alt kümesi olur |
| MR3 | Kullanıcıya ilgisiz bir rol eklenir | İlgili kaynaktaki karar değişmez |
| MR4 | Politikaların değerlendirme sırası permüte edilir | Karar aynı kalır |
| MR5 | Aynı JWT başlıkta boşluk ve alan sırası değiştirilerek gönderilir | Aynı sonuç alınır; ya ikisi de kabul ya ikisi de reddedilir, asla biri kabul biri ret olmaz |
| MR6 | `redirect_uri` anlamsal olarak eşdeğer biçimde normalize edilir, örneğin sondaki eğik çizgi kaldırılır | Aynı karar verilir |
| MR7 | Kiracı A'daki bir işlem yapılır | Kiracı B'nin hiçbir kararı değişmez; izolasyon, çok kiracılı bir IdP için en önemli ilişkidir |
| MR8 | Zaman `exp` değerinin bir saniye ötesine ilerletilir | Geçerliden geçersize geçilir, asla tersi olmaz |

MR7 özellikle güçlüdür: rastgele iki kiracı üretilir, kiracı A'da rastgele mutasyonlar uygulanır ve B'nin karar vektörünün bit bit aynı kaldığı doğrulanır.

---

## D. JWT ve JOSE parser güvenliği

### D.1 Zafiyet sınıfları

| Sınıf | Mekanizma | Kanonik örnek |
|---|---|---|
| `alg=none` | `{"alg":"none"}` ile imza atlanır; büyük küçük harf varyantları (`NONE`, `nOnE`) filtreleri aşar | Auth0'ın 2015 bülteni |
| Algoritma karışıklığı (RS256'dan HS256'ya) | RSA public key'i HMAC secret'ı olarak kullandırılır | CVE-2022-23541 (node jsonwebtoken), CVE-2024-33663 (python-jose, OpenSSH ECDSA anahtarları) |
| Anahtar karışıklığı, DER ile PEM | Farklı anahtar formatlarının yanlış yorumlanması | CVE-2024-33663 |
| `jwk` header enjeksiyonu | Header'daki `jwk` doğrulama adayı olarak kabul edilir ve tam token sahteciliği mümkün olur | CVE-2026-27962 (Authlib, CVSS 9,1), CVE-2026-34240 (appsup-dart jose) |
| `jku` ve `x5u` enjeksiyonu ile SSRF | Sunucu saldırgan URL'sinden anahtar çeker; hem sahtecilik hem SSRF primitifi doğar | PortSwigger'ın jku header enjeksiyonu laboratuvarı |
| `kid` path traversal ve SQL enjeksiyonu | `kid: "../../dev/null"` boş anahtar verir; `kid: "' UNION SELECT ..."` SQL enjeksiyonu yapar | CerberAuth'un jwt kid enjeksiyonu dokümanı |
| Boş veya nil HMAC anahtarı | Boş secret ile HMAC hesaplanabiliyorsa sahtecilik mümkündür | CVE-2026-45363 (ruby-jwt), CVE-2026-44351, CVE-2026-49852 (joserfc) |
| ECDSA psychic signature | `r=0, s=0` reddedilmez ve her imza geçerli olur | CVE-2022-21449 (Java 15-18) |
| Invalid curve saldırısı (ECDH-ES) | `epk`'nin eğri üzerinde olduğu doğrulanmaz ve CRT ile private key kurtarılabilir | CVE-2017-16007 (node-jose 0.9.3 öncesi), ayrıca go-jose, jose2go, Nimbus ve jose4j |
| Billion hashes, `p2c` | PBES2 `p2c` üst sınırsızdır ve CPU tükenir | CVE-2023-51775 (jose4j), CVE-2023-52428 (Nimbus), CVE-2023-6681 (jwcrypto), CVE-2023-50658 (jose2go), CVE-2023-49290 (jwx), CVE-2023-50966 (erlang jose), CVE-2026-27932 (joserfc) |
| Compression DoS, `zip=DEF` | JWE açma işlemi sınırsızdır | CVE-2024-28176 (panva/jose), CVE-2024-28180 (go-jose), CVE-2024-29371 (jose4j), CVE-2024-33664 ve CVE-2024-29370 (python-jose), CVE-2024-27663 (jose-jwt), CVE-2024-28122 (jwx), CVE-2025-63811 (jose2go) |
| Billion laughs ve derin iç içe JSON | XML veya JSON entity ile derinlik | CVE-2025-53864 (Nimbus JOSE+JWT, derin iç içe JSON DoS) |
| `crit` header'ının yanlış ele alınması | Anlaşılmayan `crit` uzantısı reddedilmeli, sessizce yok sayılmamalıdır (RFC 7515 §4.1.11) | Sınıf gerçektir; spesifik bir CVE bulunamamıştır |
| JWE içine sarılmış PlainJWT | JWE içinden çıkan `alg:none` JWT'nin imzası doğrulanmaz | CVE-2026-29000 (pac4j-jwt) |
| Sign ve encrypt karışıklığı | Nokta sayısına bakıp JWS, JWE sanılır | CVE-2024-24238 (jose-jwt), CVE-2023-51774 (json-jwt); NDSS 2026 |
| JWT format karışıklığı | JWS'in JSON serialization'ı compact sanılır | latchset/jose, go-jose, jwx, jwcrypto; NDSS 2026 |
| Claim'lerde tip karışıklığı | `exp` ve `nbf` yanlış tipte geldiğinde yok sayılır | CVE-2026-25537, Rust `jsonwebtoken` |
| HMAC zamanlama yan kanalı | Sabit zamanlı olmayan karşılaştırma | GHSA-5vw4-v588-pgv8 (robbert229/jwt), Kanidm GHSA-53hj-r94p-8c8f |

> **Düzeltme: CVE-2023-51767.** Bu CVE bir JWE zip bomb değildir. Aslında OpenSSH 10.0 ve öncesinde row hammer tabanlı bir kimlik doğrulama atlatmasıdır; `mm_answer_authpassword` içindeki `authenticated` integer'ı tek bit çevrilmesine dayanıklı değildir. Üstelik satıcı tarafından itiraz edilmiştir, çünkü platform mimarisi zayıflıklarına karşı savunma uygulamanın sorumlulukları olmadığı belirtilmiştir; gerçek bir yapılandırmada sömürülebilirliği gösterilmemiştir. Aranan JWE zip bomb CVE'leri yukarıdaki tablodadır: CVE-2024-28176, 28180, 29371 ve 33664.

### D.2 Rust crate'leri: RustSec ve OSV taraması

Tarama 8 Eylül 2026'da doğrudan OSV API'sine sorgu atılarak yapılmıştır.

| Crate | Advisory | Sonuç |
|---|---|---|
| `jsonwebtoken` | GHSA-h395-gr6q-cpjc, CVE-2026-25537 | D.3'e bakınız; Argus için en önemli tek bulgudur |
| `josekit` | — | Advisory yoktur |
| `jwt` | — | Advisory yoktur |
| `jwt-simple` | — | Advisory yoktur |
| `jwtk` | — | Advisory yoktur |
| `biscuit-auth` | GHSA-75rw-34q6-72cr, CVE-2022-31053 | İmza sahteciliğidir; Γ-signature kriptanalizi (ePrint 2020/1484). v1'den v2'ye zorunlu geçiş gerekmiştir. CVSS 3.1 skoru 9,8'dir; 17 Haziran 2022 |
| `biscuit-auth` | GHSA-p9w4-585h-g3c7, CVE-2024-41949 ve CVE-2024-42350 | Third-party block'ta public key karışıklığıdır; kötü niyetli holder `ThirdPartyBlockRequest`'in `publicKeys` alanını değiştirerek üçüncü tarafı yanlış anahtar çiftine güvenen datalog üretmeye kandırır. 4.0.0 ile 5.0.0 arası etkilenmiştir; 31 Temmuz 2024 |
| `openidconnect` | — | Advisory yoktur |
| `oauth2` | — | Advisory yoktur |
| `webauthn-rs` | — | Advisory yoktur |

Yan ekosistem, yani IdP'nin bağımlılıkları, Argus için doğrudan risktir:

| Crate | Advisory | Tarih | Neden ilgilidir |
|---|---|---|---|
| `quick-xml` | RUSTSEC-2026-0194; start tag'de duplicate attribute kontrolü O(N²)'dir | 29 Haziran 2026 | SAML. 80.000 attribute yaklaşık altı saniye, 800.000 attribute yaklaşık on dakika sürer. Saf hesaplamadır ve `await` içermez, dolayısıyla I/O zaman aşımı kesemez. Birkaç on MB'lık tek bir start tag bir ayrıştırma thread'ini saatlerce kilitler |
| `quick-xml` | RUSTSEC-2026-0195; `NsReader`'da sınırsız namespace bildirimi ayırması | 29 Haziran 2026 | SAML. `NamespaceResolver::push` event caller'a dönmeden önce çalışır; M baytlık bir start tag yaklaşık 3M bayt resolver heap'i tüketir ve caller bunu görmez. Girdi boyutunu sınırlamak yetmez. Gerçek dünyada NLnet Labs Routinator OOM ile öldürülmüştür |
| `time` | RUSTSEC-2026-0009; RFC 2822 ayrıştırmasında stack tükenmesi DoS'u | 5 Şubat 2026 | JWT ve HTTP tarih ayrıştırması. v0.3.47'de özyineleme derinliği limiti eklenmiştir |
| `rsa` | RUSTSEC-2023-0071, CVE-2023-49092; Marvin saldırısı, zamanlama yan kanalıyla anahtar kurtarma | 22 Kasım 2023 | RSA imzalama ve şifre çözme |
| `rsa` | GHSA-9c48-w39g-hm26, CVE-2026-21895; asal bire eşitken panic | 6 Ocak 2026 | Anahtar import doğrulaması |
| `ring` | RUSTSEC-2025-0009; overflow kontrolü açıkken bazı AES fonksiyonları panic eder | 6 Mart 2025 | — |
| `ring` | RUSTSEC-2025-0010; 0.17 öncesi bakımsızdır | 5 Mart 2025 | — |
| `rustls` | RUSTSEC-2024-0336; `complete_io` ağ girdisine bağlı sonsuz döngüye girer | 19 Nisan 2024 | TLS sonlandırma |
| `rustls` | RUSTSEC-2024-0399; parçalanmış ClientHello'da `Acceptor::accept` panic eder, 0.23.13 regresyonudur | 22 Kasım 2024 | `tokio-rustls` `LazyConfigAcceptor` etkilenir |
| `openssl` (rust-openssl) | GHSA-8c75-8mhr-p7r9; AES key wrap'te hatalı sınır assertion'ı | 22 Nisan 2026 | JWE A128KW ve A256KW |
| `openssl` | GHSA-4fcv-w3qc-ppgg; `Md::fetch` ve `Cipher::fetch` use-after-free | 4 Nisan 2025 | `josekit` OpenSSL tabanlıdır |
| `serde_cbor` | RUSTSEC-2019-0025 stack overflow; RUSTSEC-2021-0127 bakımsızdır | 2019 ve 2021 | WebAuthn attestation; `ciborium` ve `coset`'e geçilir |

> **Argus için aksiyon.** `josekit` OpenSSL'e bağlı olduğu için rust-openssl'in tüm CVE yüzeyini miras alır. `jsonwebtoken` saf Rust'tır ancak D.3'teki mantık hatasına sahiptir. `biscuit-auth`'un iki ayrı kripto tasarım açığı geçmişi vardır. Hiçbiri güvenle bağımlılık olarak alınıp unutulabilecek kategoride değildir.

### D.3 `jsonwebtoken` CVE-2026-25537

Bu, Argus için en öğretici vakadır.

GHSA-h395-gr6q-cpjc ve CVE-2026-25537, yayın 3 Şubat 2026. CVSS v4 vektörü `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N`'dir ve PoC mevcuttur. Etkilenen `jsonwebtoken` 10.3.0'ın altıdır, yani tüm geçmiş sürümler. Düzeltme commit'i `abbc3076742c4161347bc6b8bf4aa5eb86e1dc01`'dir.

Mekanizma şudur:

```rust
enum TryParse<T> { Parsed(T), FailedToParse, NotPresent }
```

`src/validation.rs` dosyasının yaklaşık 288. satırında:

```rust
if matches!(claims.nbf, TryParse::Parsed(nbf) if options.validate_nbf && nbf > now + options.leeway) {
    return Err(new_error(ErrorKind::ImmatureSignature));
}
```

`{"nbf": "99999999999"}` biçiminde, yani sayı yerine string gönderildiğinde serde bunu `u64`'e ayrıştıramaz ve `FailedToParse` üretir. `matches!` yalnızca `Parsed(_)` durumunu yakaladığı için koşul false döner, blok atlanır ve hata oluşmaz. Yani `validate_nbf = true` olmasına rağmen Not Before kontrolü tamamen atlanır. Tek fallback `required_spec_claims` listesidir; ancak yaygın kullanım deseni validate_nbf'i açmak ve required listesine eklememektir. Test ortamı jsonwebtoken 10.2.0 ve rustc 1.90.0'dır.

**Bu vakanın Argus'un tez cümlesi olmasının nedenleri.** Bu bir bellek güvenliği hatası değildir; Rust'ın tip sistemi, borrow checker'ı ve unsafe yasağı hiçbiri yardımcı olmamıştır. Bu bir panic değildir; crash oracle'ı kullanan klasik coverage güdümlü fuzzing bunu asla bulamaz. Bunu bulan şey tip karışık claim üreten yapı farkında bir generator ile "validate_nbf açıksa geçersiz nbf'li token reddedilmelidir" property'sidir, yani tam olarak bu raporun C bölümüdür. Diferansiyel test de bulurdu: `panva/jose` bu token'ı reddeder, `jsonwebtoken` kabul ederdi.

Argus için doğrudan property şudur:

```
∀ token, ∀ claim c ∈ {exp, nbf, iat, aud, iss, sub, jti}:
  eğer c mevcut ancak beklenen tipte değilse
  → validate() Err döner (asla yok sayıldı davranışı olmaz)
```

### D.4 2025 ve 2026'nın yeni JOSE açıkları

| CVE | Kütüphane | Sınıf | CVSS | Tarih | Not |
|---|---|---|---|---|---|
| CVE-2026-27962 | Authlib (Python) | `jwk` header enjeksiyonuyla imza doğrulama atlatması | 9,1 Kritik | 2026 | `key=None` geçildiğinde JWS deserialize işlemi saldırgan kontrolündeki `jwk` header'ındaki anahtarı kullanır. Etkilenen yaygın desen JWKS aramasında bilinmeyen veya rotate edilmiş `kid` için resolver'ın `None` dönmesidir. RFC 7515 §4.1.3 ve §5.2 ihlalidir. Düzeltme 1.6.9 ve üstüdür |
| CVE-2026-29000 | pac4j-jwt (Java) | JWE içine sarılmış PlainJWT ile kimlik doğrulama atlatması | — | 2026 | Sunucunun RSA public key'ini bilen saldırgan keyfi `sub` ve rol claim'leriyle bir PlainJWT'yi JWE'ye sarar; imza doğrulaması atlanır ve admin dahil herkes olarak kimlik doğrulanır. 4.5.9, 5.7.9 ve 6.3.3 altındaki sürümler etkilenir |
| CVE-2026-27932 | joserfc | PBES2 `p2c` sınırsızdır | 7,5 | Advisory 28 Şubat 2026, NVD 6 Mart 2026 | `_rfc7518/jwe_algs.py` dosyasındaki `PBES2HSAlgKeyEncryption.decrypt_cek()` `p2c` değerini header'dan doğrudan okur ve üst sınır uygulamaz; `2^31-1` verilebilir. Claim ve imza doğrulamasından önce tetiklenir. Önerilen sınır yaklaşık 300.000'dir |
| CVE-2025-63811 | jose2go (Go) | Compression DoS | — | 2025 | NDSS 2026 kaynaklıdır |
| CVE-2025-53864 | Nimbus JOSE+JWT | Derin iç içe JSON ile DoS | — | 2025 | — |
| CVE-2026-55040 | Microsoft SharePoint | JWT token ile kimlik doğrulama atlatması; PoC yayımlandıktan sonra aktif sömürü | — | 2026 | — |

2026 trendi nettir: header `jwk` ve boş anahtar kaynaklı imza doğrulama atlatmaları artmıştır (Authlib 9,1; dart-jose; joserfc; ruby-jwt; pac4j). Bunların ortak paydası anahtar seçimi mantığıdır, kripto değildir. Argus'un anahtar çözümleme katmanı ayrı bir tip olmalı ve şu invariantı taşımalıdır:

```
∀ token: resolve_key(token) ∈ trusted_key_store
         ∧ resolve_key(token) ≠ ∅
         ∧ resolve_key(token).len() > 0
         ∧ resolve_key(token).alg_family == header.alg.family()
```

Ayrıca `Option<Key>` dönen bir resolver'ın `None` değeri asla header'daki anahtarı kullanmaya düşmemelidir; tip seviyesinde `resolve() -> Result<TrustedKey, KeyError>` kullanılır, `Option` kullanılmaz.

### D.5 Bir JOSE parser'ını etkili fuzz etmek

Harness ayrımı yapılır ve her biri ayrı bir fuzz hedefidir. `fuzz_jws_compact_decode` yalnızca ayrıştırma yapar, doğrulama yapmaz ve panic, bellek tükenmesi ile zaman aşımı arar. `fuzz_jws_verify` sabit ve bilinen bir anahtar setiyle doğrulama yapar; oracle şudur: `verify()` `Ok` dönerse imza gerçekten o anahtarla mı üretilmiştir; fuzzer anahtarı bilmediği için `Ok` dönmesi kendi başına bir bulgudur ve `alg=none`, boş anahtar ile psychic signature'ın hepsini yakalar. `fuzz_jwe_decrypt` `p2c`, `zip` ve `epk` alanlarını gramerde tutar. `fuzz_jose_header_json` JSON tip karışıklığını hedefler; CVE-2026-25537 sınıfıdır. `fuzz_jwks_parse` JWKS dokümanını hedefler. `fuzz_differential_jose` Argus ile referansı karşılaştırır.

Kritik oracle'lar yalnızca panic yokluğu değildir:

```rust
fuzz_target!(|data: JoseInput| {
    // O1: round-trip
    if let Ok(t) = parse(&data.bytes) { assert_eq!(parse(&serialize(&t)).unwrap(), t); }

    // O2: anahtar yokken asla kabul etme
    if verify_with_no_keys(&data.bytes).is_ok() { panic!("SECURITY: accepted with empty keyset"); }

    // O3: alg allowlist zorunlu
    let r = verify(&data.bytes, &KEYS, &Validation::new(&[Algorithm::ES256]));
    if let Ok(tok) = r { assert_eq!(tok.header.alg, Algorithm::ES256); }

    // O4: kaynak sınırı
    let t0 = Instant::now();
    let _ = decrypt(&data.bytes, &KEY);
    assert!(t0.elapsed() < Duration::from_millis(100), "resource DoS");

    // O5: açma sınırı
    // (zip=DEF çıktısı yapılandırılmış limiti aşmamalıdır)
});
```

Gramer ve corpus tohumlaması şöyledir. Seed corpus RFC 7515, 7516, 7517, 7518 ve 7519 örnekleri ile Wycheproof vektörlerini ve `jwt_tool` ile JWTEditor payload'larını içerir. Sözlük (libFuzzer `-dict=`) şu anahtar kelimeleri taşır: `"alg"`, `"none"`, `"HS256"`, `"RS256"`, `"dir"`, `"ECDH-ES"`, `"PBES2-HS256+A128KW"`, `"crit"`, `"jku"`, `"jwk"`, `"x5u"`, `"x5c"`, `"kid"`, `"zip"`, `"DEF"`, `"p2c"`, `"p2s"`, `"epk"`, `"enc"`, `"typ"`, `"cty"`, `"nbf"` ve `"exp"`. `zip=DEF` için özel mutator kanonik desendir: aç, payload'ı mutasyona uğrat, yeniden sıkıştır.

NDSS 2026'nın FBNF ve UCT-Rand yaklaşımı taklit edilir: `p2s` üretildiğinde `p2c`'nin de üretilmesi gerektiği fuzzer'a öğretilir; `Arbitrary` implementasyonunda alan bağımlılıkları kodlanır, örneğin `enum JweAlg { Pbes2 { p2s: Vec<u8>, p2c: u32 }, EcdhEs { epk: Jwk }, Dir, ... }` biçiminde. Bu, Monte Carlo ağaç araması olmadan aynı etkinin yaklaşık %80'ini verir.

---

## E. OSS-Fuzz

### E.1 Kabul kriterleri

Resmî ifadeye göre OSS-Fuzz'a kabul edilmek için bir açık kaynak projenin kayda değer bir kullanıcı tabanına sahip olması veya küresel BT altyapısı için kritik olması gerekir. SSS ayrıca altyapı ve kullanıcı güvenliği üzerinde kritik etkisi olan yerleşik projelerin kabul edildiğini, seçim kriterlerinin uzaktan saldırıya maruziyet ve downstream kullanıcı ile bağımlı proje sayısı olduğunu belirtir.

Başvuru gereksinimleri proje ana sayfası, ana repo URL'si, birincil dil ve Google hesabıyla ilişkili yerleşik bir proje committer'ının iletişim e-postasıdır.

> **Argus için gerçekçi değerlendirme.** Sıfırdan yazılmış ve henüz kullanıcı tabanı olmayan bir IdP muhtemelen ilk denemede reddedilir. Strateji şudur: önce kendi CI'mızda ClusterFuzzLite veya CIFuzz benzeri bir kurulum yapılır; benimsenme büyütülür; ya da Argus'un kritik alt crate'leri (JOSE parser'ı, SCIM filter parser'ı) ayrı ve bağımsız crate'ler olarak yayımlanır, bunlar başkaları tarafından da kullanılırsa OSS-Fuzz kriterini bağımsız olarak karşılayabilirler. Bu ikinci strateji hem mimari olarak hem OSS-Fuzz açısından doğrudur.

### E.2 Rust entegrasyonu

`cargo fuzz` kullanımı beklenir; doğru derleyici bayrakları ve OSS-Fuzz'ın kendi libFuzzer'ına linkleme onunla yapılır. Yapı `fuzz/` dizini, `fuzz/Cargo.toml` ve `fuzz/fuzz_targets/*.rs` dosyalarıdır. `project.yaml` dosyasında `language: rust` belirtilir; yalnızca libFuzzer ve AddressSanitizer desteklenir. `Dockerfile` `FROM gcr.io/oss-fuzz-base/base-builder-rust` satırıyla başlar ve Rust nightly ile cargo-fuzz hazır gelir. `build.sh` `cargo fuzz build -O` çalıştırır (release önerilir) ve binary'leri `$OUT/` dizinine kopyalar. Zarif bir kalıp fuzzing mantığını `#[cfg(fuzzing)]` bloklarına sarmaktır; test ve fuzz kodunu paylaşmak için `#[cfg(any(test, fuzzing))]` kullanılır.

Doğrulanmış gerçek örnekler (project.yaml dosyaları 8 Eylül 2026'da doğrudan çekilmiştir):

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
sanitizers: [address, memory, undefined]   # ring'de C vardır, bu yüzden üç sanitizer kullanılır
```

### E.3 Argus'la ilgili hangi Rust projeleri OSS-Fuzz'da

`raw.githubusercontent.com/google/oss-fuzz/master/projects/<isim>/project.yaml` adreslerinin HTTP durum kodlarıyla doğrulanmıştır.

| Proje | OSS-Fuzz'da mı |
|---|---|
| rustls | Evet |
| ring | Evet |
| quick-xml | Evet; SAML için önemlidir |
| serde_json | Evet |
| tokio | Evet |
| httparse | Evet |
| rust-regex | Evet |
| rust-lexical | Evet |
| trust-dns | Evet |
| openssl ve boringssl (C) | Evet |
| rust-openssl | Hayır |
| kanidm | Hayır |
| josekit ve rust-jwt | Hayır |
| rust-webpki | Hayır |
| x509-parser, der-parser, asn1-rs | Hayır |
| ciborium ve rust-cbor | Hayır |
| hyper ve axum | Hayır |

> **Boşluk analizi.** IdP yığınının tam kalbi — JOSE, X.509 ayrıştırma, CBOR ile WebAuthn, ASN.1 ile LDAP BER — OSS-Fuzz'da yoktur. Argus'un fuzzing yatırımı için en yüksek marjinal getiri tam buradadır.

### E.4 Ne kazandırır

ClusterFuzz üzerinde sürekli ve ücretsiz fuzzing sağlar. Build makineleri 32 CPU ve 28,8 GB RAM'e sahiptir. Fuzzing makineleri tek çekirdeklidir ve hedef başına 2,5 GB RAM sınırı vardır; yaklaşık 25 saniyelik zaman aşımı veya 2,5 GB aşımı bir hata raporu üretir.

CIFuzz, OSS-Fuzz'a entegre olduktan sonra tek bir GitHub Actions workflow'uyla her commit ve her PR'da fuzzing sağlar. Action'lar `google/oss-fuzz/infra/cifuzz/actions/build_fuzzers@master` ve `run_fuzzers@master`'dır; crash artifact'leri ile SARIF çıktısı yüklenir. Varsayılan toplam fuzzing süresi on dakikadır ve tüm fuzzer'lara bölünür. Proje code coverage destekliyorsa CIFuzz yalnızca PR'dan etkilenen fuzzer'ları koşar. 30 günlük eski ve public regresyon corpus'u OSS-Fuzz'dan yeniden kullanılır; bu, sıfırdan başlamaya göre devasa bir avantajdır. Gereksinimi projenin OSS-Fuzz'a entegre olması ve GitHub'da barındırılmasıdır.

Hata takibi varsayılan olarak ayrı bir OSS-Fuzz tracker'ında yapılır ve Google hesabı gerekir; `project.yaml` ile GitHub issue'larına opt-in yapılabilir.

### E.5 Açıklama takvimi

Google'ın standart politikası şudur: hatalar proje yazarlarına bildirimden 90 gün sonra veya düzeltme yayımlandığında, hangisi önce gelirse, otomatik olarak public olur. Son tarih hafta sonuna denk gelirse bir sonraki iş gününe kayar. Geliştiriciler ilk sürenin bitiminden sonraki 14 gün içinde yama çıkacağını teyit ederse 14 günlük ek süre verilir.

### E.6 Ödüller

OSS-Fuzz Reward Program 1 Mayıs 2026 itibarıyla sonlandırılmıştır. Bu tarihten sonra başvuru kabul edilmemektedir. Araştırmacılar Patch Rewards Program ile OSS Vulnerability Rewards Program'a yönlendirilmektedir. Gerekçe olarak güvenlik ortamının evrimi ve AI güdümlü otomasyondaki ilerlemeler gösterilmiştir.

> **Kısmen doğrulanmıştır.** İlgili kurallar sayfası şu anda 404 dönmektedir; bu da sonlandırmayla tutarlıdır, ancak sayfa artık erişilemez olduğu için birincil kaynaktan teyit edilememiştir. OSS-Fuzz SSS ve dokümantasyonunda ödül programından hiç bahsedilmemektedir. Bu madde kritik bir karara dayanak yapılmadan önce Google Bug Hunters'ın güncel program listesi kontrol edilmelidir.

### E.7 OSS-Fuzz-Gen ve AI ile fuzz hedefi üretimi

Framework, LLM'lerle gerçek dünya C, C++, Java ve Python projeleri için fuzz hedefi üretir ve OSS-Fuzz platformunda benchmark eder. Desteklenen modeller Google Vertex AI (code-bison), Gemini serisi (Pro, Ultra, 1.5) ile OpenAI GPT-3.5-turbo, GPT-4, GPT-4o, GPT-4o-mini ve GPT-4-turbo'dur; Azure varyantları da dahildir.

Sonuçlar şöyledir: 297 açık kaynak projeden 1.300'den fazla benchmark üretilmiştir. 160 C ve C++ projesinde geçerli ve işlevsel fuzz hedefi üretilmiştir; insan yazımı hedeflere göre azami %29 satır kapsaması artışı sağlanmıştır, phmap'te %205,75 göreli kazanç elde edilmiştir. Otuz yeni zafiyet bulunmuştur; bunlardan biri CVE-2024-9143'tür, yani OpenSSL'de 20 yıldır var olan bir hatadır.

Zaman çizelgesi şudur: framework Ağustos 2023'te kurulmuş, Ocak 2024'te açık kaynak yapılmış, Kasım 2024'te zafiyetler bildirilmiş ve toplamda 26 zafiyet medyaya duyurulmuştur.

Yeni bileşenler LLM güdümlü Function Analyzer (Constraint Satisfaction Ratio'yu %38,9'dan %63,1'e çıkarmıştır) ve Crash Validation Agent'tır (sahte crash'lerin %65'ini filtrelemektedir).

2026'da ICSE 2026 SEIP'te "Fixing Security Vulnerabilities with Agentic AI in OSS-Fuzz" sunulmuştur.

> **Rust desteği.** OSS-Fuzz-Gen README'sinde belirtilen diller C, C++, Java ve Python'dur; Rust listede yoktur ve bu yokluk doğrulanmıştır. Argus için doğrudan kullanılabilir değildir; ancak aynı fikir, yani LLM ile harness taslağı üretimi ve derleme hatası düzeltmesi, kendi repomuzda uygulanabilir.

### E.8 Tipik efor

İlk entegrasyon üç dosya (`project.yaml`, `Dockerfile`, `build.sh`) ve mevcut `fuzz/` dizini ile birkaç saat sürer; `cargo fuzz` zaten kuruluysa. Asıl efor harness yazımı ve oracle tasarımındadır, altyapıda değildir. Argus için gerçekçi tahmin iyi tasarlanmış 8-12 fuzz hedefi için 2-4 kişi-hafta ile sürekli triyaj yüküdür.

---

## F. Fuzzing gerçekte ne bulur, ne bulmaz

### F.1 Kanıt: Kanidm'in 2026 advisory serisi

Kanidm, Rust ile yazılmış üretim kalitesinde bir IdP'dir ve Argus'un en yakın karşılaştırma noktasıdır. GitHub Security Advisories sayfası on advisory listelemektedir.

| GHSA | Başlık | Şiddet | Tarih | Detay |
|---|---|---|---|---|
| GHSA-2pm5-6m23-h692 | SCIM filter parser'ı üzerinden kimlik doğrulamasız stack overflow çökmesi | High | 2 Ağustos 2026 | PEG grameri her parantez seviyesinde özyineleme yapmaktadır. `SCIM_FILTER_MAX_DEPTH = 128` eklenmiştir ancak limit kurallara inildikten sonra kontrol edilmektedir, dolayısıyla özyineleme sınırsızdır. Yaklaşık 10 KB ve yaklaşık 5.000 iç içe parantez ölümcül bir stack overflow üretmektedir. Daemon'ın varsayılan worker stack'i 2 MiB'dir; 8 MiB override'ı yorum satırındadır. Öneri kabul edilen ağaç derinliğini değil özyinelemenin kendisini sınırlamaktır; ya limite ulaşınca özyinelemeye girmeden reddedilir ya iteratif bir parser yazılır. Advisory tarihinde yamalı sürüm yoktur |
| GHSA-qcrp-p3rq-pffr | Anonim iç içe LDAP filtresiyle stack overflow ve kanidmd'nin sonlanması | High; CVSS 7,5 | 23 Haziran 2026 | Kök neden `lber` 0.4.2'de BER wire decoding sırasındaki kontrolsüz özyinelemedir; derinlik limiti yoktur. `FramedRead::new(r, LdapCodec::default())` kullanılmakta ve kanidm'in filtre derinliği doğrulaması codec ayrıştırmayı bitirdikten sonra çalışmaktadır, yani çok geçtir. Anonim bir istemci `0xa0` tag'ini yaklaşık 8.000 kez iç içe koyan bir SearchRequest gönderir; yaklaşık 32 KB'lık payload bayt boyutu limitinin altındadır ancak stack'i aşar. Etkisi hem LDAPS (3636) hem HTTPS ve OIDC API'sinin (8443) ölmesidir, yani tüm süreç sonlanır. Etkilenen 1.10.3 ve altıdır, yama yoktur. Ön koşul `ldapbindaddress`'in yapılandırılmış olmasıdır; varsayılan kapalıdır |
| GHSA-r5fr-9gmv-jggh | SCIM filter stack tükenmesi ve süreç abort'u | High | 30 Nisan 2026 (OSV'de 6 Mayıs 2026) | CVE-2026-46689'dur. Etkilenen crate'ler `scim_proto` ve `kanidm_proto`'dur. Birkaç bin iç içe parantez (yaklaşık 4-12 KB) özyinelemeli inişli PEG parser'ı stack guard page'in ötesine iter; Rust stack overflow'a `std::process::abort()` ile yanıt verir ve tüm kanidmd sonlanır. Ayrıştırma axum'un `Query<ScimEntryGetQuery>` extractor'ında, handler gövdesinden ve dolayısıyla her ACL kontrolünden önce çalışmaktadır. Düzeltme 1.9.3 ve üstüdür |
| GHSA-xxwr-vvr3-2g9f | Küme modifikasyonlarının yanlış ele alınması ve kimliği doğrulanmış keyfi yazma | Critical; CVSS 9,3 | 14 Mayıs 2026 | Advisory'ye göre tüketici olmayan bir enumeration `Modify::Set`'in attribute'larının istenen kaldırılan ve mevcut kümelerden dışlanmasına imkân vermiştir. Boş küme her kümenin alt kümesi olduğu için erişim kontrolü kontrolleri yanlışlıkla geçmektedir. Giriş yapmış herhangi bir kullanıcı, arayabildiği ve okuyabildiği nesnelerin attribute'larını değiştirebilmektedir. Tüm kimliği doğrulanmış kullanıcılar gruplara erişebildiği için grup üyeliği değiştirilip `system_admins` ve `idm_admins` üzerinden tüm kimlik veritabanının kontrolü ele geçirilebilir. Etkilenen 1.9.3'ün altı ve 1.10.1'dir; yama 1.9.4 ve 1.10.2 ve üstüdür. Geçici çözüm yoktur. Bildiren kmq'dur |
| GHSA-84jc-3hj2-hwc7 | Görsel yükleme doğrulayıcılarının yetkilendirmeden önce çalışması ve PNG doğrulayıcısının panic etmesi | Moderate; CVSS 6,9 | 30 Nisan 2026 | İki ayrı hata vardır. `POST /v1/domain/_image` ve `POST /v1/oauth2/{rs_name}/_image` handler'ları görseli admin yetkisi kontrolünden önce doğrulamaktadır; `VerifiedClientInformation` extractor'ı kimliği doğrulanmamış istekleri kabul etmekte ve doğrulama başarısız olursa yetkilendirme hiç çalışmamaktadır. PNG doğrulayıcısı sekiz bayttan kısa girdide veya chunk uzunluğu alanı `u32::MAX`'a yaklaştığında integer wraparound nedeniyle panic etmektedir. Varsayılan build'de yalnızca task seviyesinde panic oluşur; ancak `panic = "abort"` ile derleyen downstream'lerde kimliği doğrulanmamış tam süreç çökmesi olur. Etkilenen v1.1.0-rc.15'ten master'a kadardır. Yama 1.9.3 ve üstüdür. CVE yoktur. Bildiren mbarbero'dur |
| GHSA-53hj-r94p-8c8f | OAuth2 client_secret'ın sabit zamanlı olmayan karşılaştırması | Low; CVSS 3,7 | 30 Nisan 2026 | `/oauth2/token` ve `/oauth2/token/introspect` Rust'ın standart `PartialEq` string karşılaştırmasını kullanmaktadır ve bu ilk eşleşmeyen baytta kısa devre yapar. Advisory dürüstçe bunun pratikte sömürülebilir bir zafiyetten çok bir sertleştirme meselesi olduğunu söyler: secret'lar 48 karakterlik yüksek entropilidir, karşılaştırma şifreli TLS içindedir ve ağ jitter'ı tek bayt zamanlamasını fazlasıyla aşar. Yama 1.9.3 ve üstüdür ve sabit zamanlıdır |
| GHSA-gpxg-fx2g-qxj2 | passkey-enrolment kısmi şablonunda displayname üzerinden saklanan HTML enjeksiyonu ve htmx güdümlü kimliği doğrulanmış istek sahteciliği | Moderate | 30 Nisan 2026 | XSS ve HTML enjeksiyonudur |
| GHSA-x8cg-3c8h-gw55 | OAuth2 trust login sağlayıcısının subject'inin doğrulanmaması | Low; CVSS v4 2,3 | 27 Mayıs 2026 | OIDC `login_hint` parametresi kimlik kanıtı gibi kullanılmaktadır; oysa yalnızca sağlayıcı arayüzüne bir ipucudur ve güvenlik garantisi yoktur. `validate_access_token_response` upstream sağlayıcının gerçekten aynı subject'i doğrulayıp doğrulamadığını kontrol etmemektedir. HTTP login view'ı OIDC `id_token`'ı hiç doğrulamamakta, UserInfo'yu çağırmamakta ve dönen `sub` claim'ini beklenen değerle karşılaştırmamaktadır. Saldırıda upstream'de hesabı olan saldırgan kurbana ait bir login oturumunu başlatır veya ele geçirir, upstream'de kendisi olarak kimlik doğrular ve client hâlâ kurbanın oturumunu işlerken kurbanın yerel hesabı için bir bearer cookie üretilir. Etkilenen 1.10.2'dir; yama 1.11.0-dev'dir |
| GHSA-j4gj-f54h-56j5 | Python RADIUS modülünün RADIUS parolalarını loglaması ve düz metin secret döndürmesi | Low | 27 Mayıs 2026 | Sır sızıntısıdır |
| GHSA-hh34-7jqq-3f73 | OAuch ile OAuth 2.0 analizi | Low | 23 Haziran 2026 | B.4'e bakınız |

> **Kritik gözlem.** Kanidm'in `Cargo.toml` workspace bağımlılıklarında proptest, quickcheck, arbitrary ve libfuzzer'ın hiçbiri yoktur; workspace'te `fuzz/` dizini de yoktur. Test altyapısı `testkit` ve `testkit-macros`'tur. Sonuç şudur: üretim kalitesinde ve güvenlik odaklı bir Rust IdP 2026'da fuzzing veya property-based testing kullanmamaktadır ve 2026'nın ilk sekiz ayında üç High severity stack tükenmesi ile bir Critical yetki yükseltmesi almıştır. Argus için bu hem bir uyarı hem bir fırsattır.

### F.2 Fuzzing ne bulur

rust-fuzz/trophy-case deposu Rust kodunu fuzz ederek bulunan 600'den fazla hatayı ve 200'den fazla crate'i listeler. Baskın kategoriler aritmetik hatalar (taşma ve alt taşma), aralık dışı erişim, mantık hataları, panic'ler (unwrap başarısızlığı, assertion) ile bellek sorunları (stack overflow, bellek tükenmesi) ve UTF-8 işlemedir.

Güvenlik olarak işaretlenenler küçük bir alt kümedir: capnproto-rust (bellek güvenliği), claxon (bellek ifşası), lexical (unsafe kodda sınır dışı okuma), lz4_flex (heap buffer overflow), sxd-document (use-after-free), symbolic-minidump (segfault), v_escape ve zune-jpeg (heap buffer overflow). Ana keşif araçları libFuzzer ve AFL'dir.

Rust'a özgü gerçek şudur: saf ve unsafe içermeyen Rust'ta fuzzing'in bulduğu şeyler ezici çoğunlukla panic, yani hizmet reddidir; `unwrap()` başarısızlıkları, aralık dışı indeksleme, debug'da aritmetik taşma ve özyinelemeden kaynaklanan stack tükenmesi ile `process::abort()`. Kanidm'in 2026 tablosu tam olarak bunu göstermektedir; on advisory'nin üçü stack tükenmesidir.

Argus'un kaçınılmaz hata sınıfları şunlardır. Özyinelemeli inişli parser ile kullanıcı girdisi stack overflow üretir; SCIM filter, LDAP BER, JSON, XML ve JWT iç içe claim'leri bu sınıftadır. Rust bunu `abort()` ile karşılar ve kurtarılamaz; panic değil süreç ölümüdür. Doğrulama sırası hatası vardır: ayrıştırma ve doğrulama yetkilendirmeden önce çalışmaktadır ve Kanidm'de iki kez olmuştur (SCIM filter axum extractor'ında ve image validator handler'da); bu bir mimari hatadır ve fuzzer bunu ancak kimliği doğrulanmamış bir isteğin süreci öldürmesi olarak görür. Algoritmik karmaşıklık DoS'u vardır; quick-xml RUSTSEC-2026-0194'ün O(N²) attribute kontrolü buna örnektir, crash ve panic yoktur, yalnızca CPU tüketimi vardır ve fuzzer'ın zaman aşımı oracle'ı olmadan bulunamaz, OSS-Fuzz'ın 25 saniyelik zaman aşımı bunu yakalar. Bellek amplifikasyonu vardır; quick-xml RUSTSEC-2026-0195'te M bayt girdi 3M bayt iç heap üretir, girdi sınırı korumaz ve bellek tükenmesi oracle'ı gerekir. Integer wraparound panic'e yol açar; Kanidm'in PNG chunk uzunluğu `u32::MAX` vakası budur. Tip karışıklığı sessiz güvenlik atlamasına yol açar; `jsonwebtoken` CVE-2026-25537 budur.

### F.3 Fuzzing'in bulamadıkları

| Bulamaz | Neden | Kanidm'den örnek | Doğru araç |
|---|---|---|---|
| Mantık hataları ve yetki yükseltmesi | Gözlemlenebilir bir sinyal, yani crash üretmez; fuzzer arama uzayını crash sinyaliyle yönetir | GHSA-xxwr-vvr3-2g9f (Critical 9,3); `Modify::Set`'te boş kümenin her kümenin alt kümesi olması. Hiçbir şey çökmez, yalnızca yanlış bir izin verilir | Property-based ve differential testing; Cedar modeli |
| İş mantığı ve protokol uyumsuzluğu | Fuzzing beklenen davranışı bilmez | GHSA-hh34; authorization code geçersizleştirilmemekte, PKCE verifier uzunluğu kontrol edilmemektedir | Conformance süiti (OpenID), OAuch, spesifikasyon tabanlı test |
| Kimlik doğrulama mantığı | Yine oracle yoktur | GHSA-x8cg; `login_hint`'in kimlik kanıtı sanılması ve `sub` claim'inin karşılaştırılmaması | Model checking (Tamarin, ProVerif) ve durumlu PBT |
| Zamanlama yan kanalları | Coverage geri bildirimi zamanı ölçmez | GHSA-53hj; sabit zamanlı olmayan `client_secret` karşılaştırması | dudect ve ctgrind tarzı istatistiksel zamanlama analizi; Kani ile erken dönüş yokluğu kanıtı; kod incelemesi |
| XSS ve enjeksiyon, çıktı tarafı | Sunucu çökmez, kurban tarayıcıdır | GHSA-gpxg; displayname üzerinden saklanan HTML enjeksiyonu | Taint analizi, tip seviyesinde şablon otomatik kaçışı, DAST |
| Kriptografik tasarım hataları | Fuzzer bir imza şemasının matematiksel olarak kırık olduğunu söyleyemez | `biscuit-auth` CVE-2022-31053 (Γ-signature) | Kriptanaliz, Wycheproof vektörleri, formel analiz |
| Sır sızıntısı, loglama | Çıktı doğrudur ancak yanlış yere gitmektedir | GHSA-j4gj; RADIUS parolalarının loglanması | Tip seviyesinde `Secret<T>` sarmalayıcısı ile `Debug` ve `Display` yasağı, log denetimi |
| Kapsanmayan kod | Fuzzer yalnızca çalıştırdığı yolları görebilir | — | Coverage güdümlü harness genişletme, statik analiz |
| Çok istekli ve durumlu akışlar | Tek bir `&[u8]` girdisi bir OAuth akışını ifade edemez; harness özel tasarlanmadıkça | Refresh token replay'i | `proptest-state-machine`, stateright |

Akademik teyit şöyledir: mantık hataları crash gibi gözlemlenebilir sinyaller sergilemek zorunda değildir ve fuzzer'lar aramalarını yönlendirmek için bu sinyallere dayanır (arXiv 2605.10074, Agentic Fuzzing: Opportunities and Challenges). Fuzz testi iş mantığı hakkında akıl yürütmez (Akamai). Fuzzer'lar kapsanmayan kodda hata bulamaz (arXiv 2505.22052).

> **Sayısal özet, Kanidm 2026 verisiyle.** On advisory'nin dördünü iyi kurulmuş bir fuzzing hattı bulabilirdi; üç stack tükenmesi ve PNG panic'i. Altısını bulamazdı ve bunların içinde tek Critical (9,3) da vardır. Yani fuzzing bir IdP'nin güvenlik bütçesinin yaklaşık %40'ını karşılar; kalan %60 property-based, differential, formel ve conformance testing ile kod incelemesine aittir.

---

## G. Argus için sentez ve önceliklendirilmiş plan

### Katman 0: mimari

Bu her şeyin ön koşuludur ve araç maliyeti sıfırdır.

`argus-core` saf, senkron ve I/O içermeyen olur; parser'lar, token doğrulayıcı, politika motoru ve durum makinesi buradadır. Fuzzing ve PBT buraya uygulanır. `argus-http` axum ve tokio kullanır ve yalnızca bir adaptördür.

Her parser için açık bir derinlik limiti konur ve özyinelemeye girmeden önce kontrol edilir; Kanidm GHSA-2pm5'in tam olarak yaptığı hata budur. Tercihen iteratif veya açık stack kullanan bir parser yazılır.

Yetkilendirme ayrıştırmadan önce yapılır; extractor'larda ayrıştırma yapılmaz. Kanidm'in SCIM ve image vakaları bunu göstermektedir.

Anahtar çözümleme `fn resolve(&self, hdr: &Header) -> Result<TrustedKey, KeyError>` biçimindedir; `Option` yoktur ve `None` durumunda fallback yoktur. 2026'nın Authlib, joserfc, ruby-jwt ve dart-jose açık ailesinin tamamı burada durur.

`Secret<T>` tipi `Debug` ve `Display` implement etmez.

Üretim build'inde `panic = "abort"` kullanılmaz; Kanidm GHSA-84jc'nin downstream riski budur.

### Katman 1: fuzzing

Efor 2-4 kişi-haftadır ve para maliyeti neredeyse sıfırdır.

`cargo fuzz init --fuzz-engine libafl` ile başlanır (cargo-fuzz 0.13.2 ve üstü). On ile on iki hedef yazılır: JWS compact ayrıştırma, JWS doğrulama (anahtarsız kabul oracle'ıyla), JWE şifre çözme (`p2c` ve `zip` oracle'larıyla), JOSE header JSON tip karışıklığı, JWKS ayrıştırma, SCIM filter, SCIM JSON, LDAP BER, SAML XML, CBOR attestation, OAuth query parametreleri ve `redirect_uri` eşleştiricisi.

Yapı farkında üretim için `mutatis` (2026 kanıtına göre kısa koşularda %36-49 daha iyidir) ve `arbitrary` kullanılır.

Oracle'lar yalnızca panic yokluğu değildir: round-trip, anahtarsız ret, alg allowlist'i, süre sınırı, bellek sınırı ve açma sınırı kontrol edilir.

Wycheproof vektörleri seed corpus'a eklenir.

CI'da PR başına on dakika (CIFuzz deseni), gecelik koşuda altı saat (Cedar deseni) çalıştırılır.

### Katman 2: property-based testing

Efor 3-6 kişi-haftadır.

`proptest` 1.11 ve `proptest-state-machine` 0.8 kullanılır.

Tutarlı dünya üreteçleri yazılır; bu Cedar'ın en önemli dersidir: şemadan rollere, kullanıcılara ve isteklere giden bir üretim zinciri kurulur.

C.3'teki 23 invariant `check_invariants()` ve post-condition olarak kodlanır.

Metamorfik ilişkiler MR1 ile MR8 arası uygulanır; özellikle MR7, yani kiracı izolasyonu.

### Katman 3: diferansiyel test

Efor 4-8 kişi-haftadır ve en yüksek getiriye sahiptir.

Kısa vadede `ory/hydra` ve `node oidc-provider`'a karşı normalize edilmiş diff koşulur; B.4'teki altı yüzey kullanılır.

Orta vadede OpenID Conformance Suite yerel Docker ile ve OAuch çalıştırılır; bunlar zaten yazılmış oracle'lardır ve maliyetsizdir.

Uzun vadede, farklılaştırıcı olarak Cedar'ın doğrulama güdümlü geliştirme modeli benimsenir: `argus-core`'un yetkilendirme ve token doğrulama semantiği için ayrı bir çalıştırılabilir model yazılır (Lean 4 tercih edilir; Cedar'ın Lean modeli test başına 5 µs sürer ve Rust'tan bir mertebe küçüktür), gecelik differential random testing koşulur ve modeli, kanıtları ile testleri güncel olmayan sürüm yayımlanmaz kuralı uygulanır.

Yayımlanabilir bir iş olarak JWTeemo (NDSS 2026) metodolojisi Rust JOSE ekosistemine uygulanır; 43 kütüphaneli çalışmada hiç Rust yoktur. `jsonwebtoken`, `josekit`, `jwt-simple`, `jose-jwt` ve `biscuit` için FBNF tarzı diferansiyel fuzzing yapılır.

### Katman 4: formel doğrulama

Seçici olarak 2-4 kişi-hafta ayrılır.

Kani yalnızca küçük ve kritik fonksiyonlar için kullanılır: sabit zamanlı eşitlik, base64url, varint ve uzunluk ayrıştırma, `p2c` sınır kontrolü ve derinlik sayacı. Kani kontratları Rust standart kütüphanesi doğrulamasında altı yeni hata bulmuştur.

stateright çok düğümlü iptal ve oturum yayılımı için kullanılır.

Tamarin veya ProVerif, protokol tasarımı kararları spesifikasyondan sapıyorsa kullanılır.

### Katman 5: OSS-Fuzz

Uzun vadelidir.

Argus'un kritik alt crate'leri bağımsız crate olarak yayımlanır; benimsenme büyüdükçe OSS-Fuzz başvurusu yapılır.

Boşluk şudur: JOSE, X.509 ayrıştırma, CBOR ile WebAuthn ve ASN.1 ile LDAP BER OSS-Fuzz'da yoktur; burası boş arazidir.

Ödül programı beklentisi kurulmaz; OSS-Fuzz Rewards 1 Mayıs 2026'da sonlandırılmıştır ve bu kısmen doğrulanmıştır. Asıl değer ClusterFuzz, CIFuzz ve 30 günlük corpus'tur.

---

## H. Doğrulanmamış ve dikkat edilecek noktalar

1. OSS-Fuzz Rewards'ın 1 Mayıs 2026'da sonlandırılması: kaynak sayfa artık 404 dönmektedir ve tek dolaylı kanıt vardır. Karar öncesi teyit edilmelidir.
2. Nyx'in 2026 durumu: 2022 sonrası major gelişme kanıtı bulunamamıştır.
3. `crit` header'ının yanlış ele alınmasına dair spesifik bir CVE bulunamamıştır; sınıf gerçektir ve RFC 7515 §4.1.11 gereksinimi nettir, ancak numaralı bir örnek yoktur.
4. OpenFGA ve Oso'da property-based veya fuzz testing kanıtı yoktur. SpiceDB'de tutarlılık test dizinleri vardır ancak metodolojinin PBT mi assertion mı olduğu doğrulanmamıştır.
5. `libafl_libfuzzer`'ın Windows desteği yalnızca standalone kütüphane olarak vardır; Argus Windows hedefliyorsa bu bir engeldir.
6. Arama sonucu özetlerinde iki hata tespit edilip düzeltilmiştir: cargo-afl'in 0.15.17 ve AFL++ 4.31c olduğu iddiası yanlıştır, gerçek değerler 0.18.2 (11 Mayıs 2026) ve AFL++ 4.40c'dir; LibAFL sürüm tarihleri GitHub sayfasından yanlış çıkarılmıştı ve crates.io API'siyle doğrulanmıştır (0.16.1, 11 Ağustos 2026).
7. CVE-2023-51767 JWE ile ilgili değildir; OpenSSH row hammer zafiyetidir ve üstelik satıcı tarafından itiraz edilmiştir.
