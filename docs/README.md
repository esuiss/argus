# Argus dokümanları

`ARGUS.md` 30 bin satır tek dosyaydı. Bölüm bölüm incelenip düzeltilmek üzere
buraya taşınıyor. Taşınan bir bölümün ana dosyadaki karşılığı yalnızca bir
işaretçi olur; içerik burada yaşar.

## Taşınanlar

| § | Dosya | İçerik |
|---|---|---|
| 1 | [01-mimari-kararlar.md](01-mimari-kararlar.md) | 27 gün-1 kararı, sonradan verilen kararlar (K28, K29), teknoloji yığını, crate topolojisi, faz planı, §10 açık kararlar |

## Henüz taşınmayanlar

Kalan 26 bölüm hâlâ `ARGUS.md` içinde. Bölüm haritası `CLAUDE.md`'de; satır
numaraları bir bölüm taşındığında kaydığı için yeniden üretmek gerekirse:

```bash
awk '/^## [0-9]+\./{print NR"\t"$0}' ARGUS.md
```

## Kurallar

**Taşırken içerik değiştirilmez.** Taşıma ve düzeltme ayrı adımlardır; ikisi
aynı commit'te yapılırsa neyin taşındığı neyin değiştiği ayırt edilemez.

**Başlık seviyeleri bir kademe yukarı alınır.** Ana dosyada `## 1.` olan bölüm
kendi dosyasında `# 1.` olur, altındaki `###` başlıklar `##` olur. Numaralandırma
korunur, çünkü hem `ARGUS.md`'nin başka bölümleri hem kod yorumları bu
numaralara referans veriyor (`§1 #24`, `§20 §7.5` gibi).

**Referanslar numarayla kalır.** `§1 #15` bir karar kimliğidir, satır numarası
değil; dosya taşınsa da geçerli.
