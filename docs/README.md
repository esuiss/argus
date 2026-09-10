# Argus dokümanları

`ARGUS.md` 30 bin satır tek dosyaydı. Bölüm bölüm incelenip düzeltilebilsin
diye 27 bölümün hepsi buraya taşındı. Ana dosyada artık yalnızca içindekiler
ve her bölüm için bir işaretçi var.

| § | Dosya | İçerik | Satır |
|---|---|---|---|
| 1 | [01-mimari-kararlar.md](01-mimari-kararlar.md) | Mimari kararlar | 704 |
| 2 | [02-celiskiler-ve-kararlar.md](02-celiskiler-ve-kararlar.md) | Çelişkiler ve çözümleri | 236 |
| 3 | [03-p0-kritik-bulgular.md](03-p0-kritik-bulgular.md) | P0 kritik bulgular | 387 |
| 4 | [04-kimlik-dogrulama-referansi.md](04-kimlik-dogrulama-referansi.md) | Kimlik ve kimlik doğrulama — alan referansı | 1597 |
| 5 | [05-rust-ekosistemi.md](05-rust-ekosistemi.md) | Rust ekosistemi fizibilitesi | 394 |
| 6 | [06-performans.md](06-performans.md) | Performans mühendisliği | 732 |
| 7 | [07-dogrulanmis-kripto.md](07-dogrulanmis-kripto.md) | Formel doğrulanmış kriptografi | 879 |
| 8 | [08-yan-kanal.md](08-yan-kanal.md) | Yan kanal ve zamanlama saldırıları | 804 |
| 9 | [09-anahtar-yonetimi.md](09-anahtar-yonetimi.md) | Anahtar ve sır yönetimi | 1297 |
| 10 | [10-formel-dogrulama.md](10-formel-dogrulama.md) | Formel doğrulama ve model checking | 1375 |
| 11 | [11-sertlestirme.md](11-sertlestirme.md) | Runtime/binary sertleştirme ve izolasyon | 1926 |
| 12 | [12-tedarik-zinciri.md](12-tedarik-zinciri.md) | Yazılım tedarik zinciri güvenliği | 1490 |
| 13 | [13-guvenlik-sureci.md](13-guvenlik-sureci.md) | Güvenlik süreci | 192 |
| 14 | [14-mcp-yetkilendirme.md](14-mcp-yetkilendirme.md) | MCP yetkilendirme | 1148 |
| 15 | [15-ajan-kimligi.md](15-ajan-kimligi.md) | AI ajan kimliği | 1017 |
| 16 | [16-kurumsal-protokoller.md](16-kurumsal-protokoller.md) | Kurumsal protokoller — SAML, SCIM, LDAP, Kerberos, Federation | 2019 |
| 17 | [17-gelecek-standartlari.md](17-gelecek-standartlari.md) | Gelecek standartları — PQC, WebAuthn L3, CTAP, TLS | 1607 |
| 18 | [18-cok-kiracilik.md](18-cok-kiracilik.md) | Çok kiracılık mimarisi | 1304 |
| 19 | [19-ha-dagitik-mimari.md](19-ha-dagitik-mimari.md) | Yüksek erişilebilirlik ve dağıtık mimari | 1304 |
| 20 | [20-yetkilendirme-motoru.md](20-yetkilendirme-motoru.md) | Yetkilendirme motoru | 1603 |
| 21 | [21-oturum-guvenligi.md](21-oturum-guvenligi.md) | Oturum güvenliği ve hırsızlığa karşı savunmalar | 1242 |
| 22 | [22-hesap-yasam-dongusu.md](22-hesap-yasam-dongusu.md) | Hesap yaşam döngüsü | 3031 |
| 23 | [23-giris-akislari.md](23-giris-akislari.md) | Giriş akışları ve UX | 636 |
| 24 | [24-admin-api.md](24-admin-api.md) | Admin API ve delege yönetim | 675 |
| 25 | [25-gozlemlenebilirlik.md](25-gozlemlenebilirlik.md) | Gözlemlenebilirlik ve ölçekte denetim | 801 |
| 26 | [26-dagitim-operasyon.md](26-dagitim-operasyon.md) | Dağıtım ve operatör deneyimi | 777 |
| 27 | [27-test-stratejisi.md](27-test-stratejisi.md) | Test stratejisi | 673 |

Toplam 29,850 satır.

## Kurallar

**Taşırken içerik değiştirilmedi.** Taşıma bir önceki commit'e karşı satır satır
doğrulandı: sıfır eksik, sıfır fazla. Taşıma ve düzeltme ayrı adımlardır; ikisi
aynı commit'te yapılırsa neyin taşındığı neyin değiştiği ayırt edilemez.

**Başlık seviyeleri bir kademe yukarı alındı.** Ana dosyada `## 5.` olan bölüm
kendi dosyasında `# 5.`, altındaki `###` başlıklar `##` oldu. Kod bloklarının
içindeki `#` satırlarına dokunulmadı.

**Numaralandırma korundu.** Hem dosyalar arası referanslar (`§20 §7.5`) hem kod
yorumları (`§1 #24`) bu numaralara dayanıyor. `§1 #24` bir karar kimliğidir,
satır numarası değil; dosya taşınsa da geçerli.

## Gezinme

Satır numarası aramak yerine dosyayı açıp başlıkla gezin:

```bash
# bir dosyanın başlıkları
awk '/^#{1,3} /{print NR"\t"$0}' docs/20-yetkilendirme-motoru.md

# konu belirsizse önce ara
grep -rn "aradığın şey" docs/
```
