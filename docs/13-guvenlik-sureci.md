# 13. Güvenlik süreci

> `ARGUS.md` §13'den taşındı. Numaralandırma korundu; bu dosyanın
> içindeki `§13 §X` referansları aynı anlamda.


*Tarih: 2026-09-08. "Argus": sıfırdan yazılmış, Rust tabanlı, Keycloak-sınıfı, "en güvenli olmayı" hedefleyen açık kaynak kimlik sağlayıcı (IdP).*

Her iddianın yanında kaynak URL + tarih vardır. **Doğrulanamayan** kalemler açıkça işaretlenmiştir. Hiçbir rakam uydurulmamıştır.

---

## A) BİR IdP İÇİN TEHDİT MODELLEME (THREAT MODELING)

### A.1 Çerçeveler (STRIDE, LINDDUN, PASTA, saldırı ağaçları)

- **STRIDE**: Klasik teknik-güvenlik çerçevesi (Spoofing, Tampering, Repudiation, Info disclosure, DoS, Elevation). Bir IdP için doğrudan uygulanabilir: kimlik taklidi (spoofing) IdP'nin temel savunma yüzeyidir. Araçlarla (Threat Dragon, MS TMT) yerleşik desteklenir.
- **LINDDUN**: Gizlilik (privacy) odaklı tehdit modelleme; bir IdP PII tuttuğu için son derece ilgili. Yedi tehdit türü: **L**inking (bağlanabilirlik), **I**dentifying (tanımlama), **N**on-repudiation, **D**etecting, **D**ata disclosure, **U**nawareness/Unintervenability, **N**on-compliance. LINDDUN açık bir çerçevedir, "threat tree" (tehdit ağacı) bilgi tabanı sunar. Kaynak: [KU Leuven LINDDUN tutorial (lirias.kuleuven.be)](https://lirias.kuleuven.be/retrieve/331950); genel tanım [arxiv 2308.02272](https://arxiv.org/pdf/2308.02272).
  - **IdP için LINDDUN özgülü — Linkability**: "İki ilgi nesnesinin (IOI) aynı özneye ait olup olmadığını ayırt edebilme" yeteneği. Bir IdP'de bu doğrudan **pairwise (çift-taraflı) subject identifier / PPID / sector identifier** tasarımına bağlanır. Farklı RP'lere aynı `sub` verilirse RP'ler kullanıcıyı çapraz izleyebilir (linkability→identification). NIST SP 800-63C bunu "PPII" olarak zorunlu kılar (aşağıda A.4). Not: arama sonuçları LINDDUN'ı PPID ile *doğrudan* eşleyen akademik metin döndürmedi — **bağlantı benim çıkarımım (doğrulanmamış eşleme)**, ancak her iki kavram bağımsız olarak doğrulanmıştır.
- **PASTA** (Process for Attack Simulation and Threat Analysis): İş-etki odaklı, 7 aşamalı, risk-merkezli. VerSprite'ın metodolojisi. Kaynak: [VerSprite threat modeling tools](https://versprite.com/threat-modeling-tools/threat-modeling-tools-compared/).
- **Saldırı ağaçları (attack trees)**: hedef→alt-hedef ayrıştırması; IdP için "Golden SAML üret", "oturum token'ı çal" gibi kökler.

### A.2 Araçlar — olgunluk ve maliyet
Kaynak: [VerSprite (2026 karşılaştırma)](https://versprite.com/threat-modeling-tools/threat-modeling-tools-compared/), [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/).

| Araç | Model | Maliyet | Argus'ta yeri |
|---|---|---|---|
| **OWASP Threat Dragon** | Görsel/diyagram; STRIDE, **LINDDUN**, CIA, DIE, PLOT4ai destekler | Ücretsiz, açık kaynak | Başlangıç için ideal; hem STRIDE hem LINDDUN tek araçta |
| **Microsoft Threat Modeling Tool** | Diyagram tabanlı, Windows-native | Ücretsiz | Windows ekipleri; ama Argus için daha az uygun |
| **Threagile** | YAML deklaratif, "threat-model-as-code", risk kuralları + diyagram üretir | Ücretsiz/açık | **Argus için en uygun "as-code" seçenek** — model kodla versiyonlanır, CI'a girer |
| **pytm** (OWASP) | Python ile model tanımı, DFD üretir | Ücretsiz/açık | Rust/CI hattına Python ek adımıyla girer |
| **IriusRisk** | Ticari, AI destekli tehdit kütüphanesi eşleme | Ticari (ücretli) | Kurumsal ölçek; erken aşama OSS için gereksiz |

Uyumluluk uyarısı: Threat Dragon dosya formatı pytm/Threagile/Open Threat Model ile uyumlu değildir (aynı kaynak). "Threat model as code" felsefesi (Threagile/pytm) Argus'un repo'suna model dosyası koyup PR'larda güncellemeye çok uygundur.

### A.3 Öğrenilecek yayımlanmış IdP/OAuth tehdit modelleri
- **RFC 9700 — "Best Current Practice for OAuth 2.0 Security"**: RFC numarası **doğrulandı**. Statü **BCP 240**, yayım **2025 (Ocak 2025)**, yazarlar **T. Lodderstedt, J. Bradley, A. Labunets, D. Fett**. RFC 6749, 6750 ve **6819'u günceller**. PKCE zorunluluğu, tam (exact) redirect_uri eşleştirme, implicit ve password grant'ın kullanımdan kaldırılması, mix-up saldırısı önlemleri, sender-constrained token (DPoP/mTLS), yüksek güvenlik için PAR. OAuth 2.1'e dahil edildi. Kaynak: [rfc-editor.org/info/rfc9700](https://www.rfc-editor.org/info/rfc9700/), [oauth.net/2/oauth-best-practice](https://oauth.net/2/oauth-best-practice/).
- **RFC 6819 — OAuth 2.0 Threat Model**: **Ocak 2013**, informational. İstemci/authorization endpoint/token endpoint/akış/kaynak-erişim olmak üzere beş tehdit kategorisi. RFC 9700 tarafından güncellendi. Kaynak: [rfc-editor.org/rfc/rfc6819](https://www.rfc-editor.org/rfc/rfc6819).
- **NIST SP 800-63C (Federation & Assertions)**: FAL1/2/3 seviyeleri, assertion imzalama (SHALL), replay önleme için benzersiz `jti`, PPII (pairwise pseudonymous), FAL2+ şifreleme, RP başına benzersiz simetrik anahtar. Kaynak: [pages.nist.gov/800-63-3/sp800-63c.html](https://pages.nist.gov/800-63-3/sp800-63c.html). (Argus'ta doğrudan SAML/OIDC assertion tasarımına uygulanır.)
- Keycloak / Ory tehdit modelleri: doğrudan yayımlanmış tekil "threat model dokümanı" bu araştırmada bulunamadı — **doğrulanamadı** (ayrı hedefli arama gerekir; WebSearch bütçesi tükendi).

### A.4 MITRE ATT&CK — kimlik teknikleri
Kaynak: [attack.mitre.org/techniques/T1606](https://attack.mitre.org/techniques/T1606/).
- **T1606 Forge Web Credentials** — mevcut kimlik bilgisini *çalmak* yerine *sahtesini üretmek*.
  - **T1606.001 Web Cookies**: oturum çerezlerini uydurma.
  - **T1606.002 SAML Tokens** = **"Golden SAML"**: IdP'nin imzalama anahtarı ele geçirilirse saldırgan istediği kullanıcı/rol için geçerli SAML assertion üretir, MFA'yı atlar. → Argus'ta imzalama anahtarının HSM/KMS'te tutulması, anahtar rotasyonu, ayrı imza anahtarı bu tehdide karşı birincil savunmadır.
  - Azaltımlar: ayrıcalıklı hesap yönetimi, JIT yönetim, gelişmiş denetim (audit).
- **T1556 Modify Authentication Process**: kimlik doğrulama akışının kendisini değiştirme (ör. sahte auth modülü). Argus'ta plugin/authenticator zincirinin bütünlüğü ve imzalı yapılandırma ile ilgilidir. (Teknik adı arama sonucundan doğrulandı; ayrıntı sayfası çekilmedi.)
- **T1550 Use Alternate Authentication Material** ve **T1621 MFA Request Generation (MFA fatigue/bombing)**: kullanıcı adlarıyla doğrulandı; ayrıntı sayfaları çekilmedi — **teknik varlığı doğrulandı, ayrıntı doğrulanmadı**. T1621 için Argus'ta number-matching/rate-limit/push kısıtlama önemlidir.

---

## B) GÜVENLİK AÇIĞI AÇIKLAMA PROGRAMI (VDP)

### B.1 security.txt (RFC 9116)
Kaynak: [rfc-editor.org/info/rfc9116](https://www.rfc-editor.org/info/rfc9116/), [ietf.org RFC 9116 PDF](https://www.ietf.org/ietf-ftp/rfc/rfc9116.pdf).
- **Zorunlu alanlar yalnızca ikisidir: `Contact` ve `Expires`.**
- `Contact`: en az bir yöntem (`mailto:`, `https:` veya `tel:`); tercih sırasına göre birden çok verilebilir.
- `Expires`: ISO 8601; **en fazla 1 yıl** ileride önerilir (dosyanın bayatlama tarihi).
- Konum: **`/.well-known/security.txt`**, **HTTPS** üzerinden servis edilmeli.
- Opsiyonel/önerilen: `Canonical`, `Encryption`, `Preferred-Languages`, `Policy`, `Acknowledgments`.
- Argus'ta: proje sitesine + demo instance'a koyulmalı; PGP anahtarı `Encryption` ile bağlanmalı.

### B.2 SECURITY.md + koordineli açıklama
- GitHub'da **private security advisory (GHSA taslakları)** ve **private fork** ile düzeltmeler embargo altında geliştirilebilir. GitHub, GHSA için sizin adınıza CVE talep edebilir. Kaynak: [rustsec.org/contributing.html](https://rustsec.org/contributing.html) (RustSec'in yönlendirmesi).
- Embargo süresi olarak endüstri normu **90 gün** (Argus SECURITY.md'de netleştirilmeli). Bu araştırmada 90 günü *IdP'ye özel* zorunlu kılan tekil kaynak bulunmadı — **90 gün genel norm, IdP-özel doğrulanmadı**.

### B.3 CNA olmak (CVE Numbering Authority)
Kaynak: [OSSF "becoming a CNA as an OSS project" kılavuzu](https://github.com/ossf/wg-vulnerability-disclosures/blob/main/docs/guides/becoming-a-cna-as-an-open-source-org-or-project.md), [CNA Rules v4.1.0 PDF (cve.org)](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.1.0.pdf).
- **Süre**: minimum **4 hafta** (ilk temastan kamu duyurusuna); ilk resmi görüşmeden en az 3 hafta önce başvuru.
- **Gereksinimler**: 2+ irtibat kişisi (isim/e-posta/telefon); net ve *dar* bir **scope statement** (başvuruların en çok takıldığı yer); yayımlanmış bir **VDP** (açıklama politikası) + triyaj süreci; itirazlara 3 gün onay / 5 gün karar; 6 ay hareketsizlik → CNA statüsü kaldırılır.
- **Süreç**: tercih edilen Root ile iletişim — OSS için **Red Hat** önerilir (`RootCNA-Coordination@redhat.com`); [cveform.mitre.org](https://cveform.mitre.org/) üzerinden talep; onboarding formu; 1 saatlik çağrı; alıştırma egzersizleri; onay + duyuru.
- **Alternatifler (Argus için pratik öneri)**: CNA olmak zorunlu değil. **GitHub, GHSA için CNA'dır** ve OSS projeleri adına CVE atar; MITRE de son-çare CNA-LR olarak CVE verir. Argus erken aşamada **GitHub'ı CNA olarak kullanmalı**, ölçek büyüyünce kendi CNA'sına geçebilir.
- **RustSec**: Rust crate açıklarını bildirmek için [rustsec/advisory-db](https://github.com/rustsec/advisory-db) reposuna **PR** açılır; `crates/<crate>/RUSTSEC-0000-0000.md` şablonu doldurulur, TOML+Markdown; onay sonrası **RUSTSEC-YYYY-NNNN** kimliği atanır. **Önce upstream'e bildirin.** RustSec **embargolu açık kabul etmez** — açık kamuya açıklanmadan PR açılamaz. Kaynak: [advisory-db/CONTRIBUTING.md](https://github.com/rustsec/advisory-db/blob/main/CONTRIBUTING.md), [rustsec.org/contributing.html](https://rustsec.org/contributing.html).
- **Rust Foundation CNA durumu**: AWS/Alpha-Omega blogunda "**Rust Foundation resmi bir CVE Numbering Authority oldu**" (2025) ifadesi geçiyor. Kaynak: [AWS Open Source Blog (2026)](https://aws.amazon.com/blogs/opensource/aws-and-others-invest-12-5m-to-defend-the-open-source-ecosystem-from-ai-threats/). **Not**: Rust Foundation'ın kendi news/security-initiative sayfalarında bunu doğrulayan doğrudan metin bu çekimde görünmedi — **ikincil kaynakla doğrulandı, birincil kaynakla doğrulanamadı.**

### B.4 Bug bounty (2026'da geçerlilik)
- **GitHub Secure Open Source Fund**: $1.25M, 125 proje, 2025 başında; rolling başvuru. Kaynak: [GitHub Blog duyurusu](https://github.blog/news-insights/company-news/announcing-github-secure-open-source-fund/), [github.com/open-source/github-secure-open-source-fund](https://github.com/open-source/github-secure-open-source-fund).
- **Google OSS VRP**: $100–$31,337 (proje önemi + ciddiyete göre); tedarik zinciri odaklı; Ağustos 2023 lansmanı, hâlâ aktif. Kaynak: [Google Security Blog (2023-08)](https://security.googleblog.com/2023/08/Announcing-Googles-Open-Source-Software-Vulnerability-Rewards-Program%20.html). Not: Argus **Google'ın kendi projesi olmadığı için OSS VRP kapsamına girmez**; ancak model olarak referanstır.
- **Internet Bug Bounty (IBB)** / HackerOne/Bugcrowd OSS: varlığı arama sonuçlarında geçti ancak IBB'nin Argus'u kapsayıp kapsamadığı **doğrulanamadı**.
- **Argus için gerçekçi yol**: kendi bütçesiyle bounty başlatmak yerine, kritik-altyapı fonlarına (aşağıda C) girip GitHub Secure Open Source Fund'a başvurmak.

---

## C) BAĞIMSIZ GÜVENLİK DENETİMİ (AUDIT)

### C.1 Rauthy denetimi — KİLİT VERİ NOKTASI (raporun tamamı incelendi)
Rauthy'nin (sebadob/rauthy) gerçek PDF denetim raporunu indirip metnini çıkardım.
Kaynak (PDF): [security_audit_report_v0.32.pdf](https://raw.githubusercontent.com/sebadob/rauthy/refs/heads/main/assets/security_audit_report_v0.32.pdf); proje notu: [sebadob.github.io/rauthy](https://sebadob.github.io/rauthy/); fonlama: [nlnet.nl/project/Rauthy](https://nlnet.nl/project/Rauthy/).

- **Denetleyen**: Radically Open Security B.V. (Amsterdam) — pentester'lar **Frank Plattel, Morgan Hill**; yazarlar Morgan Hill/Frank Plattel/Marcus Bointon; onay Melanie Rieback.
- **Rapor**: v1.0, **15 Eylül 2025** (taslak 22 Ağustos 2025).
- **Denetim dönemi**: **14 Temmuz – 22 Ağustos 2025**.
- **Fonlama**: **NGI Zero Core** (NLnet, AB Next Generation Internet, grant No. 101092990); dönem Ocak–Ağustos 2025.
- **Tür**: "**crystal-box**" (kaynak-kod erişimli) sızma testi / kod denetimi.
- **Sonuç**: **1 Elevated, 3 Low, 3 N/A**. Bulgular:
  - **RAUTHY-007 (Elevated) — Kalıcı XSS**: profil resmi olarak yüklenen **SVG içine JavaScript** enjeksiyonu; kullanıcı etkileşimiyle frontend ele geçirme. → *çözüldü (input validation/sanitization)*.
  - **RAUTHY-005 (Low) — Timing oracle**: `client_secret` **sabit-zamanlı olmayan** string karşılaştırması; teorik zamanlama saldırısı. → *çözüldü (constant-time comparison)*.
  - **RAUTHY-006 (Low) — Reachable unwrap / DoS**: house-made `hiqlite` bağımlılığında HTTP isteğiyle tetiklenen panic. → *çözüldü (unwrap yerine error)*.
  - **RAUTHY-009 (Low) — Exposed credentials**: repoda **statik CA zinciri + private key** shipping. → *çözüldü (kaldır; kurulumda üret)*.
  - **RAUTHY-001 (N/A) — Vulnerable dependency**: `rsa` crate CVE-2023-49092 (Marvin saldırısı) mevcut ama bu bağlamda sömürülemez. → *retest edilmedi*.
  - **RAUTHY-004 (N/A) — Logic bug**: `page_size=0` → get users/sessions'da divide-by-zero. → *çözüldü*.
  - **RAUTHY-008 (N/A) — Insecure config**: dev ortamı portları tüm arayüzlerde (`0.0.0.0`) dinliyor. → *retest edilmedi (loopback öner)*.
- **Genel kanı**: "Proje güvenliği baştan düşünmüş, çok iyi iş çıkarıyor; bulguların çoğu **saatler içinde** düzeltildi." Bulgular Rauthy **v0.32.1**'de giderildi.
- **Future Work önerileri**: Hiqlite ve PAM modülü için ayrı hedefli denetim; düzeltmelerin **retest**'i; düzenli periyodik denetim.
- **Argus için ders**: (1) Bir Rust IdP'sinde bile bulgular "mimari kripto kırılması" değil, **klasik web/impl hataları** (SVG XSS, non-constant-time compare, unwrap-panic, repoda gömülü anahtar, dependency CVE'si) etrafında yoğunlaşıyor — bunlar Argus'un regresyon test setinin çekirdeği olmalı. (2) NGI Zero + Radically Open Security kombinasyonu, açık kaynak IdP için **kanıtlanmış, tekrar edilebilir** bir denetim yoludur.

### C.2 NLnet / NGI Zero fonlama — 2026 durumu (ÖNEMLİ)
- **AB, Horizon Europe 2025 çalışma programından NGI fonunu çıkardı** (kesinti). Kaynak: [EDRi (2024)](https://edri.org/our-work/european-commission-cuts-funding-support-for-free-software-projects/), [FSFE (2024-07-19)](https://fsfe.org/news/2024/news-20240719-01.en.html).
- **Ancak 2026'da NGI Zero Commons Fund hâlâ açık**: çağrı **2026-06Z**, son başvuru **1 Haziran 2026**, toplam bütçe **€6,1M**; ilk başvuru **≤ €50.000**, sonraki ödüller **≤ €150.000**, üçüncü taraf başına yaşam boyu tavan **€500.000**. Kaynak: [DevelopmentAid (2026-06Z)](https://www.developmentaid.org/grants/view/1629511/ngi-zero-commons-fund-2026-06z), [EDRi/FSFE (kesinti bağlamı)].
- **Güvenlik denetimi ayni (in-kind) hizmet olarak sağlanıyor**: "NGI hibe alanları, bir **Radically Open Security denetimini destek hizmeti olarak** talep edebilir"; sonuçlar gizli iletilir, koordineli açıklamayla kamuya açılabilir; **erken talep edin** tavsiyesi. Kaynak: [nlnet.nl/events/20240111](https://nlnet.nl/events/20240111/).
- **Argus için**: NGI Zero Commons Fund'a başvurmak, hem küçük geliştirme hibesi hem de **ücretsiz bağımsız denetim** (Rauthy modeli) demektir — en yüksek getirili tek adım.

### C.3 Diğer fon/denetim programları
- **OSTIF (Open Source Technology Improvement Fund)**: kâr amacı gütmeyen; 10 yılda 800+ açık (121 kritik/yüksek), 13.000+ saat güvenlik çalışması; audit maliyetine **idari/lojistik destek dahil**. Kaynak: [ostif.org/ostif-helps-foundations](https://ostif.org/ostif-helps-foundations/), [github.com/ostif-org/OSTIF](https://github.com/ostif-org/OSTIF). (Not: STA rapor PDF'i 403 verdi; net dolar rakamı **doğrulanamadı**.)
- **Alpha-Omega (OpenSSF / Linux Foundation)**: 70+ hibe, $20M+; **Mart 2026'da AWS/Anthropic/Google/Microsoft/OpenAI'den $12,5M** (AI-üretimi açık raporları için); Rust'ın TLS (rustls) ve AV1 implementasyonlarını fonladı; 2025'te Rust Foundation'ın crates.io Trusted Publishing + CNA olmasını destekledi. Kaynak: [openssf.org/category/alpha-omega](https://openssf.org/category/alpha-omega/), [AWS blog](https://aws.amazon.com/blogs/opensource/aws-and-others-invest-12-5m-to-defend-the-open-source-ecosystem-from-ai-threats/).
- **Sovereign Tech Agency/Fund (Almanya)**: 2026'da aktif; Fund + 2026 Fellowship + yeni **Sovereign Tech Standards** (24 Ağu 2026); **EU-STF** çok-uluslu pilotu. Kaynak: [sovereign.tech](https://www.sovereign.tech/), [sovereign.tech/programs/fund](https://www.sovereign.tech/programs/fund), [GamingOnLinux (2026-04)](https://www.gamingonlinux.com/2026/04/germanys-sovereign-tech-agency-launches-sovereign-tech-standards-to-support-open-standards/).
- **Mozilla SOS Fund, Google OSS güvenlik çalışması**: model olarak varlar; Argus'a özel güncel uygunluk **doğrulanamadı** (WebSearch bütçesi tükendi).
- **Denetim firmaları** (Rust/kripto/protokol): Trail of Bits, **Radically Open Security** (Rauthy'yi denetleyen), Cure53, NCC Group, Include Security, Quarkslab, X41 D-Sec, 7ASecurity, Least Authority. Kaynaklar: [cure53.de](https://cure53.de/), [7asecurity.com/publications](https://7asecurity.com/publications). **Maliyet**: 2–6 haftalık bir denetim için *doğrulanmış tekil dolar rakamı bu araştırmada bulunamadı* — **doğrulanamadı**. Pratik olarak NLnet/OSTIF/Alpha-Omega bu maliyeti üstlenir; Argus'un cebinden ödemesi gerekmeyebilir.
- **İyi bir denetim kapsamı (SoW)**: Rauthy raporu şablon niteliğinde — hedef net tanımlı (IdP kodu), crystal-box (kaynak erişimli), risk sınıflandırması, bulgu+öneri+durum (resolved/accepted), "future work" (alt-bileşen denetimi + retest). **Denetimin bulmadıkları**: tam kapsam garantisi değil ("one-time snapshot"), embargolu 0-day'ler, denetim sonrası regresyonlar — bu yüzden **periyodik denetim + CI regresyon** şart.

---

## D) RED TEAM / DÜŞMANCA TEST

### D.1 Evilginx (v3.x) — AiTM phishing
Kaynak: [github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2), [darkreading (Evilginx MFA bypass)](https://www.darkreading.com/endpoint-security/evilginx-bypasses-mfa).
- Go ile yazılmış bağımsız **reverse-proxy AiTM** framework (v3.x, 2017 nginx tabanlı sürümden tam yeniden yazım); BSD-3-Clause; ~15.6k yıldız; aktif. Kurban ile gerçek site arasında oturur, **kimlik bilgisi + oturum çerezi + 2FA token** yakalar, oturumu replay eder. Star Blizzard gibi gerçek tehdit aktörlerince kullanılıyor.
- **Argus'un neyi durdurması gerekir**: **origin-bound WebAuthn/passkey**. FIDO2 kimlik bilgisi gerçek origin'e kriptografik bağlıdır; Evilginx farklı alan adı sunduğu için tarayıcı kimlik bilgisini **serbest bırakmaz** → Evilginx bu modeli kıramaz. Kaynak: [golinuxcloud Evilginx](https://www.golinuxcloud.com/evilginx-phishing-mfa-bypass/), [gottaphish AiTM](https://gottaphish.com/en/posts/evilginx-aitm).
- **Argus lab kullanımı**: kendi test ortamında Evilginx ile TOTP/SMS/push akışlarının kırıldığını, passkey akışının kırılmadığını **kanıtlayan bir kabul testi** koşulmalı.

### D.2 Browser-in-the-Middle (BitM) — passkey YETMEZ
Kaynak: [Google Cloud/Mandiant "BitM Up!"](https://cloud.google.com/blog/topics/threat-intelligence/session-stealing-browser-in-the-middle), [SpecterOps CuddlePhish docs](https://docs.specterops.io/cuddlephish-docs/overview), [github.com/Mayyhem/cuddlephish](https://github.com/Mayyhem/cuddlephish/blob/main/README.md).
- BitM: kurban, saldırganın sunucusundaki **gerçek bir Chrome örneğini** uzaktan kullanır; kimlik doğrulama gerçek sitede olur, saldırgan **oturum token'ını** ele geçirir. Mandiant'ın iç aracı **Delusion**; kamuya açık **CuddlePhish** (çok-kullanıcılı BitM).
- **Kritik nüans**: FIDO2/passkey origin-binding sayesinde BitM'in *kimlik doğrulama adımını* çözemez (kripto kanıtı üretilemez) — AMA doğrulama gerçek origin'de tamamlandıktan sonra **oturum çerezi hâlâ çalınabilir**. Yani passkey phishing'i durdurur, **oturum-token hırsızlığını durdurmaz**. Mandiant: token çalınınca MFA etkisizleşir.
- **Azaltım = oturumu cihaza bağlamak**: **DBSC (Device Bound Session Credentials)** ve/veya token binding/DPoP + device-bound session.

### D.3 DBSC — 2026 durumu
Kaynak: [developer.chrome.com/docs/web-platform/device-bound-session-credentials](https://developer.chrome.com/docs/web-platform/device-bound-session-credentials), [w3.org/TR/dbsc-1](https://www.w3.org/TR/dbsc-1), [Help Net Security (2026-04-10)](https://www.helpnetsecurity.com/2026/04/10/google-chrome-device-bound-session-credentials/), [Security Boulevard (2026-08)](https://securityboulevard.com/2026/08/googles-dbsc-raises-the-pressure-on-cookie-thieves/).
- **Chrome 146'da Windows'ta GA (Nisan 2026)**; macOS Secure Enclave desteği yolda. **W3C Web Application Security WG** standart yolunda (First Public Working Draft), Google + Microsoft ortak tasarım. Oturumu cihazın TPM/güvenli donanımına bağlar; çalınan çerez başka cihazda işe yaramaz. Google kendi servislerinde oturum hırsızlığında ölçülebilir düşüş bildirdi. Yol haritası: federated identity, mTLS/donanım anahtar kaydı, software-based keys.
- **Argus'ta yeri**: uzun vadeli oturumlar için DBSC entegrasyonu, infostealer-çalıntı-çerez replay'ine karşı en güncel savunma. Not: KnowBe4, DBSC'nin de "hâlâ phishlenebilir/hacklenebilir" olduğunu belirtiyor — tek başına sihir değil. Kaynak: [blog.knowbe4.com DBSC](https://blog.knowbe4.com/device-bound-session-credentials-phishable-hackable).

### D.4 Diğer araçlar
- BitM/AiTM: **Modlishka, Muraena, EvilnoVNC, CuddlePhish** (adları geçti; CuddlePhish doğrulandı, diğerleri isim düzeyinde).
- OAuth/SAML saldırı araçları (Burp eklentileri): **JWT Editor, EsPReSSO, SAML Raider, OAuth Scan** — bu araştırmada arama bütçesi bitti; isimler görevden geliyor, **bu oturumda doğrulanmadı** (işaretli).
- **Purple-team CI**: Evilginx/BitM lab senaryolarını, passkey akışının kırılmadığını doğrulayan otomatik regresyon testleri olarak koşmak (Rauthy'nin "future work: retest" felsefesiyle uyumlu).

---

## E) GÜVENLİK REGRESYON TESTİ

### E.1 Project Wycheproof — 2026'da bakımlı
Kaynak: [github.com/C2SP/wycheproof](https://github.com/C2SP/wycheproof), [docs.rs/wycheproof](https://docs.rs/wycheproof), [github.com/randombit/wycheproof-rs](https://github.com/randombit/wycheproof-rs), [appsec.guide/docs/crypto/wycheproof](https://appsec.guide/docs/crypto/wycheproof/).
- Wycheproof artık **C2SP projesi** olarak bakımı yeniden canlandırıldı; JSON test vektörleri + JSON şema.
- **Rust `wycheproof` crate DOĞRULANDI ve bakımlı**: randombit/wycheproof-rs, **v0.6.0 (5 Eylül 2026)**, Apache-2.0. Kapsam: **AES-GCM ve AEAD, ECDSA, EdDSA, DSA, ECDH + Montgomery eğrileri, RSA OAEP/PKCS1v1.5/PSS, HKDF, MAC, key wrapping, primality testleri**. Argus'un tüm imza/şifreleme yollarına (JWT/JWS için ECDSA/EdDSA/RSA-PSS, oturum şifreleme için AES-GCM, HKDF) CI'da uygulanmalı.

### E.2 OpenID Foundation Conformance Suite
Kaynak: [gitlab.com/openid/conformance-suite](https://gitlab.com/openid/conformance-suite), [openid.net/certification/fees](https://openid.net/certification/fees/), [openid.net/certification/certification-fapi_op_testing](https://openid.net/certification/certification-fapi_op_testing/).
- **Açık kaynak (MIT), GitLab'da, Docker ile çalışır, CI'a uygun** (Auto DevOps). Kapsam: OIDC OP (basic/implicit/hybrid/config/dynamic), FAPI 1 Advanced, FAPI 2.0, FAPI-CIBA, OpenBanking/CDR. Canlı örnek: certification.openid.net. → **Test suite'i çalıştırmak ücretsiz; Argus bunu CI'da koşabilir.**
- **Sertifikasyon (listeleme) ücreti**: **üye $700/deployment, üye-olmayan $3.500/deployment**; FAPI-CIBA üye toplam $1.000; pilot profiller ücretsiz. Sertifika talep eden **OIDF üyesi olmalı**. → Argus önce ücretsiz suite ile self-test yapmalı, ürün olgunlaşınca resmi sertifikasyona geçmeli.

### E.3 Diğer uygunluk/test setleri
- **SAML** (SAML2Int/Kantara), **SCIM** conformance: bu araştırmada doğrulanamadı — **işaretli, doğrulanmadı**.
- **WebAuthn/FIDO sertifikasyonu**: FIDO Alliance Functional Certification; seviyeler **L1, L1+, L2, L3, L3+**; 7 adım (NDA → conformance self-validation → interoperability → authenticator cert (min L1) → submission → trademark → MDS). Kaynak: [fidoalliance.org/certification/functional-certification](https://fidoalliance.org/certification/functional-certification/). Net ücret bu sayfada yayımlanmamış — **maliyet doğrulanamadı**. Argus bir *relying party/authenticator sağlayıcı* değilse tam FIDO sertifikası zorunlu değildir; conformance test araçları yine değerli.

### E.4 Bilinen-saldırı regresyon testleri (Argus CI çekirdeği)
Aşağıdakileri CI'da açık-negatif testler olarak kodlayın (kaynak: RFC 9700 + Rauthy bulguları): **`alg=none`**, **algorithm confusion (RS256↔HS256)**, **IdP mix-up**, **redirect_uri manipülasyonu / tam-eşleşme**, **PKCE downgrade**, **callback'te CSRF/state**, **assertion replay (jti)**, **XSW (XML Signature Wrapping)** SAML için, ve Rauthy'de çıkan pattern'ler: **SVG/XSS sanitizasyonu**, **constant-time secret compare**, **panic/DoS (unwrap) fuzzing**, **page_size gibi sınır-değer (0, u16::MAX) testleri**. Açık, hazır bir "korpus" tekil kaynak bulunamadı — **hazır korpus doğrulanamadı**; ancak RFC 9700 + OpenID conformance suite bunların çoğunu kapsar.

### E.5 FIPS / CAVP / ACVP
- NIST CAVP/ACVP ve **FIPS 140-3** kripto validasyonu: bir açık kaynak IdP için genellikle **kapsam dışı** (yüksek maliyet, resmi lab). NIST 800-63C yalnızca FAL/AAL2+ devlet dağıtımlarında imza/şifre anahtarları için **FIPS 140 Level 1+** ister ([sp800-63c](https://pages.nist.gov/800-63-3/sp800-63c.html)). Argus için not düşülmeli ama önceliklendirilmemeli.

### E.6 OWASP ASVS 5.0 ve Top 10 2025 (doğrulandı)
- **ASVS 5.0**: **30 Mayıs 2025** (Global AppSec EU Barcelona) yayımlandı; **17 bölüm, ~350 gereksinim**; her gereksinime izlenebilir kimlik. Argus için madde-madde checklist. Kaynak: [owasp.org/blog ASVS RC1](https://owasp.org/blog/2025/04/09/asvs-rc1-review), [github.com/OWASP/ASVS](https://github.com/OWASP/ASVS), [softwaremill ASVS 5.0](https://softwaremill.com/whats-new-in-asvs-5-0/).
- **OWASP Top 10:2025** yayımlandı: iki **yeni** kategori — **A03 Software Supply Chain Failures** ve **A10 Mishandling of Exceptional Conditions**; **SSRF, A01 Broken Access Control'e** katıldı (BOLA/BFLA dahil); Security Misconfiguration #5→#2; 175.000+ CVE analizi. Kaynak: [owasp.org/Top10/2025](https://owasp.org/Top10/2025/), [Qualys analizi](https://blog.qualys.com/qualys-insights/2026/06/15/what-changed-in-owasp-top-10-2025-and-recommendations-for-each-category). → Argus için: bağımlılık/supply-chain (A03) ve hata-yönetimi/fail-open (A10) doğrudan Rauthy bulgularıyla (dependency CVE, unwrap-panic) örtüşüyor.

---

## Argus için önceliklendirilmiş özet öneri
1. **Hemen**: security.txt (RFC 9116) + SECURITY.md + GitHub private advisories (GHSA'yı CNA olarak kullan). Threagile/pytm ile "threat-model-as-code" + STRIDE & LINDDUN (PPID/pairwise subject tasarımı).
2. **Kripto/regresyon**: `wycheproof` crate'i CI'a; RFC 9700 saldırı testlerini (`alg=none`, algo-confusion, mix-up, PKCE downgrade, XSW) kodla; OpenID conformance suite'i (ücretsiz, Docker) CI'da koş.
3. **Kimlik-avı direnci**: origin-bound WebAuthn/passkey birincil; Evilginx lab testiyle kanıtla; oturum-token hırsızlığına karşı DBSC (Chrome 146, 2026) + DPoP yol haritasına al.
4. **Bağımsız denetim**: **NGI Zero Commons Fund**'a başvur (2026-06Z, son 1 Haz 2026) → Radically Open Security ayni denetimi (Rauthy modeli); paralelde OSTIF/Alpha-Omega/Sovereign Tech.
5. **Standart uyum**: ASVS 5.0 (350 madde) checklist; Top 10:2025 A03/A10'a özel dikkat.

**Doğrulanamayan kalemler** (tekrar arama gerekir, WebSearch bütçesi 200/200 doldu): Keycloak/Ory yayımlı tehdit modeli; Rust Foundation CNA'sının birincil kaynak teyidi; denetim firması dolar-maliyet aralıkları; T1550/T1621/T1556 ayrıntı sayfaları; SAML2Int/SCIM conformance; Burp eklentilerinin (SAML Raider/JWT Editor/EsPReSSO) güncel teyidi; FIDO sertifikasyon ücretleri; IBB/Mozilla SOS güncel uygunluk.


---

# KISIM IV — PROTOKOLLER

*Argus'un konuşacağı protokoller: MCP ve ajan kimliğinden kurumsal protokollere ve gelecek standartlarına.*
