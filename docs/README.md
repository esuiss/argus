# Argus dokümanları

`ARGUS.md` 30 bin satır tek dosyaydı. Bölüm bölüm incelenip düzeltilebilsin
diye 27 bölümün hepsi buraya taşındı. Ana dosyada artık yalnızca içindekiler
ve her bölüm için bir işaretçi var.

| § | Dosya | İçerik | Satır |
|---|---|---|---|
| 1 | [01-architecture-decisions.md](01-architecture-decisions.md) | Mimari kararlar | 704 |
| 2 | [02-contradictions-and-resolutions.md](02-contradictions-and-resolutions.md) | Çelişkiler ve çözümleri | 236 |
| 3 | [03-p0-critical-findings.md](03-p0-critical-findings.md) | P0 kritik bulgular | 387 |
| 4 | [04-identity-authentication-reference.md](04-identity-authentication-reference.md) | Kimlik ve kimlik doğrulama — alan referansı | 1597 |
| 5 | [05-rust-ecosystem.md](05-rust-ecosystem.md) | Rust ekosistemi fizibilitesi | 394 |
| 6 | [06-performance.md](06-performance.md) | Performans mühendisliği | 732 |
| 7 | [07-verified-cryptography.md](07-verified-cryptography.md) | Formel doğrulanmış kriptografi | 879 |
| 8 | [08-side-channels.md](08-side-channels.md) | Yan kanal ve zamanlama saldırıları | 804 |
| 9 | [09-key-management.md](09-key-management.md) | Anahtar ve sır yönetimi | 1297 |
| 10 | [10-formal-verification.md](10-formal-verification.md) | Formel doğrulama ve model checking | 1375 |
| 11 | [11-runtime-hardening.md](11-runtime-hardening.md) | Runtime/binary sertleştirme ve izolasyon | 1926 |
| 12 | [12-supply-chain.md](12-supply-chain.md) | Yazılım tedarik zinciri güvenliği | 1490 |
| 13 | [13-security-process.md](13-security-process.md) | Güvenlik süreci | 192 |
| 14 | [14-mcp-authorization.md](14-mcp-authorization.md) | MCP yetkilendirme | 1148 |
| 15 | [15-agent-identity.md](15-agent-identity.md) | AI ajan kimliği | 1017 |
| 16 | [16-enterprise-protocols.md](16-enterprise-protocols.md) | Kurumsal protokoller — SAML, SCIM, LDAP, Kerberos, Federation | 2019 |
| 17 | [17-future-standards.md](17-future-standards.md) | Gelecek standartları — PQC, WebAuthn L3, CTAP, TLS | 1607 |
| 18 | [18-multi-tenancy.md](18-multi-tenancy.md) | Çok kiracılık mimarisi | 1304 |
| 19 | [19-high-availability.md](19-high-availability.md) | Yüksek erişilebilirlik ve dağıtık mimari | 1304 |
| 20 | [20-authorization-engine.md](20-authorization-engine.md) | Yetkilendirme motoru | 1603 |
| 21 | [21-session-security.md](21-session-security.md) | Oturum güvenliği ve hırsızlığa karşı savunmalar | 1242 |
| 22 | [22-account-lifecycle.md](22-account-lifecycle.md) | Hesap yaşam döngüsü | 3031 |
| 23 | [23-login-flows.md](23-login-flows.md) | Giriş akışları ve UX | 636 |
| 24 | [24-admin-api.md](24-admin-api.md) | Admin API ve delege yönetim | 675 |
| 25 | [25-observability.md](25-observability.md) | Gözlemlenebilirlik ve ölçekte denetim | 801 |
| 26 | [26-deployment-operations.md](26-deployment-operations.md) | Dağıtım ve operatör deneyimi | 777 |
| 27 | [27-test-strategy.md](27-test-strategy.md) | Test stratejisi | 673 |

Toplam 29,850 satır.

## Kurallar

**Taşırken içerik değiştirilmedi.** Taşıma bir önceki commit'e karşı satır satır
doğrulandı: sıfır eksik, sıfır fazla. Taşıma ve düzeltme ayrı adımlardır; ikisi
aynı commit'te yapılırsa neyin taşındığı neyin değiştiği ayırt edilemez.

**Başlık seviyeleri bir kademe yukarı alındı.** Ana dosyada `## 5.` olan bölüm
kendi dosyasında `# 5.`, altındaki `###` başlıklar `##` oldu. Kod bloklarının
içindeki `#` satırlarına dokunulmadı.

**Dosya adları İngilizce, içerik Türkçe.** Ad bir tanımlayıcıdır; koddaki
modül ve tip adlarıyla aynı kuralı izler. Metnin kendisi Türkçe kalır.

**Numaralandırma korundu.** Hem dosyalar arası referanslar (`§20 §7.5`) hem kod
yorumları (`§1 #24`) bu numaralara dayanıyor. `§1 #24` bir karar kimliğidir,
satır numarası değil; dosya taşınsa da geçerli.

## Gezinme

Satır numarası aramak yerine dosyayı açıp başlıkla gezin:

```bash
# bir dosyanın başlıkları
awk '/^#{1,3} /{print NR"\t"$0}' docs/20-authorization-engine.md

# konu belirsizse önce ara
grep -rn "aradığın şey" docs/
```
