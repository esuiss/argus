# §21 — Oturum güvenliği ve hırsızlığa karşı savunmalar

Bu bölüm `ARGUS.md` dosyasının 21. kısmından taşınmıştır. Numaralandırma korunmuştur; dosya içindeki `§21 §X` referansları aynı anlamdadır.

---

## 0. Yönetici özeti: ne zaman ne yapılmalıdır

| Teknoloji | Sınıflandırma | Gerekçe |
|---|---|---|
| DPoP, RFC 9449 | Bugün gerçeklenmelidir | Nihai RFC'dir, olgundur, tarayıcı dışı tüm istemciler için çalışmaktadır ile karşı taraf desteği gerçektir |
| SSF ile CAEP vericisi | Bugün gerçeklenmelidir | Nihai şartnamedir, Eylül 2025; Okta üretimdedir ile birlikte çalışabilirlik profili Ekim 2026'da nihai olacaktır |
| RFC 9470 yükseltme meydan okuması | Bugün gerçeklenmelidir | Nihai RFC'dir, ucuzdur ile CAEP'in aksiyon tarafını kapatmaktadır |
| mTLS bağlama, RFC 8705 | Bugün, isteğe bağlı bir yol olarak | Nihai RFC'dir, FAPI 2.0'ın ana yoludur ile işletmeler arası ve yüksek güvence için uygundur |
| SSF ile CAEP alıcısı | Arayüz hazırlanmalıdır | Karşı taraf sayısı azdır; Google hâlâ standart öncesindedir ile Microsoft yoktur |
| DBSC sunucu tarafı | Arayüz hazırlanmalıdır, yani şema ile uç nokta iskeleti | Şartname editör taslağıdır, tek tarayıcı ile tek platform vardır ile Mozilla olumsuz pozisyondadır |
| DBSC federe ile çoklu oturum açma anahtar paylaşımı | Erkendir | Chrome'da önerilen statüsündedir ile şartnamede tek çıkış semantiği tanımsızdır |
| DBSC kurumsal genişletmesi | Erkendir | Ayrı bir genel bakış dokümanıdır ile W3C ana şartnamesine girmemiştir |
| Davranışsal biyometri | Yapılmamalıdır | Oturumlar arası yarı toplam hata oranı yaklaşık 0,19'dur; GDPR dokuzuncu madde, KVKK açık rıza ile alternatif sunma yükümlülüğü vardır |

Tek cümlelik strateji şudur: taşıyıcı token modelinden çıkılmalı, yani bugün DPoP ile mTLS, yarın DBSC kullanılmalı; iptal standart bir olay kanalına taşınmalı, yani SSF ile CAEP vericisi kurulmalı; ile sezgisel risk skoru asla nihai karar verici yapılmamalıdır.

---

## 1. DBSC, cihaza bağlı oturum kimlik bilgileri

### 1.1 Şartname durumu, doğrulanmıştır

W3C editör taslağıdır, 27 Ağustos 2026, w3c.github.io/webappsec-dbsc adresindedir. Editörü Google'dan Daniel Rubery'dir. Eski editörü Apple'dan Kristian Monsen'dir; Apple bir dönem editörlük yapmış ancak şu an pozisyon almamıştır.

Şartnamenin kendi ifadesi şudur: *"Note this is a very early drafting for writing collaboration only"*. Değişiklik günlüğü bölümü boştur ile bunun erken bir taslak olduğu belirtilmektedir. Yani W3C süreci açısından aday tavsiye aşamasına yakın değildir.

### 1.2 Tarayıcı desteği, gerçek durum

| Tarayıcı | Durum | Kaynak |
|---|---|---|
| Chrome | Windows'ta genel kullanıma açıktır; Chrome 146, kararlı sürüm 10 Mart 2026, duyuru 9 Nisan 2026 | blog.google ile chromestatus |
| Chrome macOS | Yaklaşan bir sürümde duyurulmuştur; bugüne kadar doğrulanamamıştır | Aşağıdaki nota bakınız |
| Chrome Linux, Android ile iOS | Yoktur | chromestatus; Android ile iOS alanları boştur |
| Firefox | Olumsuz standart pozisyonudur, 912 numaralı konu | mozilla/standards-positions birleşik veri dosyası |
| Safari ile WebKit | Pozisyon yoktur, yani sinyal yoktur; 281 numaralı konu, kullanılabilirlik kaygıları etiketiyle | WebKit/standards-positions özet dosyası |
| Edge | Köken denemesi Ekim 2025'te bitmiştir; genel kullanım duyurusu yoktur | İkincil kaynaktır |

macOS hakkında doğrulanmış bulgu şudur: Chrome Enterprise politika şablonu indirilmiştir. DBSC ile ilgili tek politika `BoundSessionCredentialsEnabled`'dır ile desteklenen platform alanı yalnızca Windows'u göstermektedir, yani `chrome.win:124-` değerindedir. Chrome kararlı sürümü şu an 152'dir. Bazı ikincil kaynaklar Chrome 147'de macOS desteği geldiğini söylemektedir; bu doğrulanamamıştır ile politika verisi aksini ima etmektedir. Ayrıca bu politikanın açıklaması özellikle Google kimlik doğrulama çerezlerinden söz etmektedir; bu, Chrome'un kendi Google hesabı çerez bağlama özelliğidir ile genel web API'si için ayrı bir kurumsal politika yoktur.

Mozilla'nın olumsuz pozisyonu, bunun bir web standardı olarak yakın vadede yaygınlaşmayacağının en güçlü işaretidir.

### 1.3 Protokol, sunucu tarafında tam gerçekleme

#### Başlık isimleri değişmiştir, kritiktir

İkinci köken denemesinde, yani Ekim 2025'te, başlık öneki `Sec-Session-*` biçiminden `Secure-Session-*` biçimine değişmiş ile meydan okuma için HTTP durum kodu 401'den 403'e geçmiştir. İnternetteki eski örneklerin çoğu yanlıştır.

| Başlık | Yön | Tip, RFC 9651 |
|---|---|---|
| `Secure-Session-Registration` | Yanıt | Yapılandırılmış alan listesi, iç liste ile parametrelerle |
| `Secure-Session-Challenge` | Yanıt | Yapılandırılmış dizgi artı `id` parametresi |
| `Secure-Session-Response` | İstek | Yapılandırılmış dizgi, yani JWT |
| `Sec-Secure-Session-Id` | İstek | Yapılandırılmış dizgi |
| `Secure-Session-Skipped` | İstek | Yapılandırılmış belirteç listesi |

#### Birinci adım: giriş yanıtında kaydı tetikleme

```http
HTTP/1.1 200 OK
Set-Cookie: auth_cookie=<uzun-ömürlü-grant>; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=2592000
Secure-Session-Registration: (ES256 RS256);path="/dbsc/register";challenge="<cv>";authorization="<ac>"
```

Parametreler şunlardır. `path` zorunludur; yoksa girdi yok sayılmaktadır ile göreli ya da tam bir adres olabilir. `challenge` isteğe bağlıdır ile JWT'de `jti` olarak geri gelmektedir. `authorization` isteğe bağlıdır ile JWT'de bir iddia olarak ve ayrıca yetkilendirme başlığı olarak gelmektedir; kullanıcıyı kayıt isteğine bağlamak için bu kullanılmalıdır. `provider_key`, `provider_session_id` ile `provider_url` federe anahtar paylaşımı içindir ile 1.6'da ele alınmaktadır.

Desteklenen algoritmalar ES256, RS256 ile none'dır; başka yoktur.

Aynı yanıtta birden fazla kayıt başlığı ya da iç liste gönderilebilir, yani çoklu oturum kurulabilir.

#### İkinci adım: kayıt uç noktası

Gelen istek şöyledir.

```http
POST /dbsc/register HTTP/1.1
Secure-Session-Response: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRic2Mrand0IiwiandrIjp7...}}.eyJqdGkiOiJjdiIsImF1dGhvcml6YXRpb24iOiJhYyJ9.<sig>"
Authorization: <ac>
```

JWT doğrulama algoritması, ki tip alanı `dbsc+jwt` olmalıdır, şöyledir.

1. Tip `dbsc+jwt` olmalıdır, aksi halde reddedilmelidir.
2. Algoritma ES256 ya da RS256 olmalıdır. Algoritma none gelirse `jwk` bulunmamalıdır; şartname bunu zorunlu kılmaktadır.
3. `jwk` başlık parametresi kayıtta zorunludur, yani ES256 ile RS256 için. Özel anahtar alanı içermemelidir, yani `d` alanının yokluğu kontrol edilmelidir.
4. İmza `jwk` içindeki açık anahtarla doğrulanmalıdır.
5. `jti` verilen meydan okumayla eşleşmelidir. Meydan okuma tek kullanımlık ile kısa ömürlü tutulmalıdır.
6. `authorization` iddiası, başlıkta gönderilenle bit bit aynı olmalıdır.
7. JWK parmak izi, yani RFC 7638, SHA-256 ile dolgusuz base64url, hesaplanmalı ile oturum kaydına yazılmalıdır.

En kritik birlikte çalışabilirlik tuzağı şudur: şartnamenin normatif yük gereksinimi yalnızca `jti`, artı varsa `authorization` alanıdır. Şartnamenin örneğindeki base64 çözüldüğünde `aud` ile `iat` de görünmektedir ancak bunlar normatif değildir. Üretimdeki bir DBSC sunucu kütüphanesinin gerçekleme raporu, yani 4 Eylül 2026 tarihli 267 numaralı W3C konusu, nettir: Chrome'un yayımlanan gerçeklemesi asgari kanıt yükleri göndermektedir, yani `jti` ile çok az başka şey. Dolayısıyla `aud`, `iat` ya da `sub` zorunlu tutulursa Chrome ile çalışmamaktadır. Ayrıca TLS sonlandıran bir vekil arkasında `aud` alanını iç adrese karşı doğrulamak her zaman başarısız olmaktadır; `aud` kontrolü tercihe bağlı olmalı ile genel kökene karşı yapılmalıdır.

Yanıt JSON oturum yönergeleridir.

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Set-Cookie: auth_cookie=<kısa-ömürlü>; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=600
```

```jsonc
{
  "session_identifier": "s_9f3...",       // ZORUNLU (continue:false değilse)
  "refresh_url": "/dbsc/refresh",         // opsiyonel; yoksa registration URL kullanılır
  "continue": true,                        // opsiyonel, default true
  "scope": {                               // ZORUNLU
    "origin": "https://example.com",       // opsiyonel; yoksa instruction veren URL'in origin'i
    "include_site": false,                 // ZORUNLU (true/false açıkça yazılmalı)
    "scope_specification": [               // opsiyonel
      { "type": "include", "domain": "api.example.com", "path": "/v1" },
      { "type": "exclude", "domain": "*.example.com",   "path": "/static" }
    ]
  },
  "credentials": [{                        // ZORUNLU
    "type": "cookie",                      // yalnızca "cookie" geçerli
    "name": "auth_cookie",
    "attributes": "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None"
  }],
  "allowed_refresh_initiators": ["example.com", "*.example.com"]  // opsiyonel, default []
}
```

Sunucu tarafında uyulması gereken kısıtlar şunlardır; aksi halde tarayıcı oturumu sonlandırmaktadır. Yenileme adresi HTTPS ya da yerel makine olmalı ile hedefle aynı sitede bulunmalıdır. Kapsam kökeni hedefle aynı sitede olmalıdır. Hiçbir kimlik bilgisi bölümlenmiş özniteliği taşıyamaz. Site dahil etme açıksa kökenin ana bilgisayarı etkin üst düzey alan artı bir olmalıdır; ayrıca ilk kayıtta ilgili iyi bilinen cihaza bağlı oturumlar adresi 200 dönmeli ile kayıt uç noktasının kökeni kayıtlı kökenler listesinde bulunmalıdır. Azami yaş ile sona erme öznitelikleri çerez eşleştirmesine dahil değildir; eşleşen öznitelikler alan, yol, güvenli, yalnızca HTTP ile aynı site öznitelikleridir.

Kayıt reddi şöyledir.

```http
HTTP/1.1 403
Secure-Session-Registration: (ES256 RS256);path="/dbsc/register";challenge="<yeni-cv>"
```

#### Üçüncü adım: yenileme uç noktası, kritik yol

Tarayıcı, bağlı çerez eksik ya da süresi dolmuş olduğunda isteği bloklamakta ile yenilemeyi çağırmaktadır.

```http
POST /dbsc/refresh HTTP/1.1
Sec-Secure-Session-Id: "s_9f3..."
Cookie: <bu isteğe uygulanan diğer çerezler>
```

Sunucu meydan okuma istemektedir.

```http
HTTP/1.1 403
Secure-Session-Challenge: "<yeni-challenge>";id="s_9f3..."
```

Tarayıcı imzalı kanıtla dönmektedir; bu kanıtta `jwk` yoktur, yalnızca `jti` vardır.

```http
POST /dbsc/refresh HTTP/1.1
Sec-Secure-Session-Id: "s_9f3..."
Secure-Session-Response: "<dbsc+jwt>"
```

Sunucu doğrulaması şöyledir.

1. Oturum kimliği başlığından oturum ile kayıtlı açık anahtar bulunmalıdır.
2. Tip `dbsc+jwt` olmalı ile `jwk` bulunmamalıdır; yenilemede bu zorunludur.
3. İmza kayıtlı açık anahtarla doğrulanmalıdır, kanıttaki anahtarla değil.
4. `jti`, bu oturum için verilen son birkaç meydan okumadan biri olmalıdır, tek bir meydan okuma değil. Şartname açıkça uyarmaktadır: *"due to network latency and race conditions, it's possible to receive a signature for an old challenge after issuing a new challenge."* Pratikte son iki üç meydan okuma yaklaşık 60 ile 120 saniyelik bir pencerede kabul edilmeli ile kullanılan yakılmalıdır.
5. Yeni bağlı çerez ayarlanmalı ile isteğe bağlı olarak yeni JSON yönergeleri gönderilmelidir.

Bir optimizasyon vardır: meydan okuma herhangi bir 200 yanıtına iliştirilebilmektedir ile bu, 403 gidiş dönüşünü ortadan kaldırmaktadır.

```http
HTTP/1.1 200 OK
Secure-Session-Challenge: "c1";id="s_1", "c2";id="s_2"
```

Oturumu sonlandırmak için devam alanı yanlış yapılmalıdır; tarayıcı oturum durumunu ile özel anahtarı silmektedir.

#### Dördüncü adım: tarayıcının HTTP durum kodu semantiği, sunucunun bilmesi zorunludur

| Durum | Tarayıcı davranışı |
|---|---|
| 403 | Önbeleklenmiş meydan okumayla tekrar denemektedir |
| 403 dışındaki dört yüzlü kodlar | Oturumu silmektedir; 401, 404 ile 400 hepsi ölümcüldür |
| Beş yüzlü kodlar | Ertelenmektedir; tarayıcı geri çekilme uygulayabilir |
| 407 ile 429 | İstek atlanmaktadır |
| Üç yüzlü kodlar | Dönülmektedir, yenileme yapılmamaktadır |
| Boş gövde ile oturum kimliği varsa | Dönülmektedir; yapılandırmanın değişmediği kabul edilmektedir |
| Ağ hatası | Atlandı başlığı erişilemez değeriyle gönderilmektedir |

Yanlış bir 404 oturum kaybı demektir. Yenileme uç noktası dağıtım sırasında 404 dönerse tüm bağlı oturumlar silinmektedir. Yönlendirme, hız sınırlayıcı ile web uygulaması güvenlik duvarı buna göre ayarlanmalıdır; 429 güvenlidir, diğer dört yüzlü kodlar değildir.

#### Beşinci adım: güvenlik sertleştirmesi, şartnamenin kendi önerileri

Yenileme uç noktası giriş durumunu zamanlama yan kanalıyla sızdırmaktadır. Geçerli bir oturum kimliği başlığı yoksa reddedilmelidir.

Yenileme uç noktası asla kimlik bilgisine izin veren köken paylaşım başlığı dönmemelidir. DBSC yenilemesi kimlik bilgilerini örtük olarak eklemektedir; bu sayede siteler arası getirme isteğiyle giriş durumu sızdırılamamaktadır.

Çerçeve seçenekleri ile kökenler arası kaynak politikası başlıklarıyla gömme reddedilmelidir.

Belirli zaman noktası meydan okuma deseni şudur: hassas bir işlemden önce cihaz kanıtı istemek için aynı uç noktaya 307 ile bağlı çerezi sona erdiren bir çerez ayarı dönülmelidir; tarayıcı önce yenileme yapmakta, sonra yönlendirmeyi tamamlamaktadır.

Federe oturumlarda bağlı taraf yalnızca servis sağlayıcıdan aldığı açık anahtarla kayıtlı oturumları kabul etmelidir.

Meydan okumalar kısa ömürlü olmalı ile bayat meydan okuma reddedilmelidir.

#### `/.well-known/device-bound-sessions`

```json
{
  "registering_origins": ["https://login.example.com", "https://sso.example.com:8443"],
  "relying_origins":     ["https://example.co.uk", "https://partner.example"],
  "provider_origin":     "https://idp.example.com"
}
```

Kayıt yapan kökenler, site kapsamlı oturum kaydedebilecek kökenlerdir. Kayıt uç noktası etkin üst düzey alan artı bir ana bilgisayarındaysa gerekmemektedir. Bağlı kökenler ile sağlayıcı kökeni federe anahtar paylaşımı için çift taraflı bir katılım beyanıdır.

### 1.4 Güvenli donanımı olmayan cihazlar

Şartname hiçbir donanım gereksinimi dayatmamaktadır: *"browser implementers are free to choose other key storage technologies, such as VBS keys."*

Chrome'un yayımlanmış ölçümleri şunlardır: Windows kullanıcılarının yaklaşık %60'ı, ki artmaktadır, güvenilir platform modülüne sahiptir ile koruma sunulabilmektedir. Modül imzalama gecikmesi 50. yüzdelikte 200, 95. yüzdelikte 600 milisaniyedir; hata oranı yaklaşık yüz binde birdir ile algoritma ECDSA P-256'dır.

Google'ın resmî yol haritasının, yani 9 Nisan 2026 tarihli blog yazısının, üçüncü maddesi şudur: özel güvenli donanımı olmayan cihazlara korumayı genişletmek için yazılım tabanlı anahtarların eklenmesi etkin biçimde araştırılmaktadır. Yani henüz yoktur.

Sunucu tarafı sonucu şudur: DBSC oturumu olan ile olmayan kullanıcılar arasında bir yetki farkı tasarlanmalıdır. Yazılım anahtarı geldiğinde bu oturumun donanım destekli olup olmadığı bilgisi protokolde taşınmamaktadır; güvenilir platform modülü sertifika zinciri kasıtlı olarak sunucuya gönderilmemektedir, ki parmak izi çıkarmaya karşı bir gizlilik hedefidir. Yani sunucu donanımla yazılım ayrımını yapamamaktadır. Bu, kanıtlamalı kurumsal varyantın var olma sebebidir.

### 1.5 Performans, gerçek üretim verisi

25 Ağustos 2026 tarihli 265 numaralı W3C konusu, üretimde DBSC çalıştıran bir ekipten şu verileri getirmektedir.

| İşlem | Medyan | 90. yüzdelik |
|---|---|---|
| Kayıt, meydan okumadan yanıta | Yaklaşık 3,0 saniye | Yaklaşık 15,0 saniye |
| Yenileme | Yaklaşık 0,3 saniye | Yaklaşık 0,6 saniye |

Ayrıca az sayıda kayıt, meydan okuma verildikten dakikalar sonra tamamlanmaktadır; dağılım ağır biçimde sağa çarpıktır.

Mimari sonuçlar şunlardır.

1. Kayıt meydan okumaları dakikalarca geçerli tutulmalıdır. 30 saniyelik bir yaşam süresi konursa 90. yüzdelik kaybedilmektedir.
2. Kayıt penceresi bir güvenlik boşluğudur. Chrome'un kanonik deseni şudur: girişte 30 günlük bağsız bir yetki çerezi, kayıttan sonra 10 dakikalık bağlı bir çerez. Chrome dokümanı açıktır: *"Chrome falls back to using the long-lived cookie if one is still present."* Yani üç ile 15 saniyelik kayıt penceresinde, ile kayıt hiç tamamlanmazsa süresiz olarak, oturumu koruyan şey bağsız bir taşıyıcı çerezdir. Bu çereze tam yetki verilmemelidir.
3. Bu boşluk tam olarak Google'ın DBSC JavaScript API önerisinin sebebidir; chromestatus'ta 9 Temmuz 2026'da oluşturulmuş ile önerilen statüsündedir. Gerekçeleri erken çerez verilmesi ile çoklu oturum açma devri zafiyetleridir.

Sunucu yükü hesabı şudur: yenileme sıklığı bağlı çerezin azami yaşına eşittir. Bir milyon aktif oturum ile 600 saniyelik çerez saniyede yaklaşık 1.667 yenileme demektir; her biri bir ECDSA P-256 doğrulaması artı bir meydan okuma aramasıdır. Rust'ta imza doğrulama maliyeti ihmal edilebilirdir, yani yaklaşık 20 ile 50 mikrosaniyedir; darboğaz meydan okuma deposunun giriş çıkış işlemleridir. Çerez ömrünü uzatmak yükü doğrusal azaltmakta ancak çalınmış bir çerezin geçerlilik penceresini uzatmaktadır; bu doğrudan bir takastır.

### 1.6 Federe ile kökenler arası çoklu oturum açma

Şartnamede tanımlı olan, yani 3.3 ile 8.11 bölümleri, şudur: bağlı taraf kayıt başlığına sağlayıcı anahtarını, yani servis sağlayıcı anahtarının base64url JWK parmak izini, sağlayıcı oturum kimliğini ile sağlayıcı adresini eklemektedir. Tarayıcı servis sağlayıcının mevcut özel anahtarını yeniden kullanmakta ile yeni anahtar üretmemektedir. Çift taraflı iyi bilinen katılım beyanı şarttır ile ayrıca bir cihaza bağlı oturum anahtar paylaşımı izin istemi vardır.

Chrome'daki durumu şudur: ayrı bir özelliktir, yani çoklu oturum açma için cihaza bağlı oturum kimlik bilgileridir. chromestatus kaydı 18 Şubat 2026'da oluşturulmuş ile 27 Mayıs 2026'da güncellenmiştir. Statüsü önerilendir, şartnamesi yoktur ile kilometre taşı yoktur.

Açık tasarım boşluğu şudur: 5 Mayıs 2026 tarihli 259 numaralı W3C konusu, servis sağlayıcı oturumu sonlandırıldığında bağlı tarafların DBSC oturumlarına ne olması gerektiğini sormaktadır ile cevapsızdır, uzlaşma yoktur. DBSC'de tek çıkış semantiği tanımlı değildir. Bu boşluğu SSF ile CAEP'in oturum iptal edildi olayı doldurmaktadır; ikisinin birlikte tasarlanması gerekmektedir.

### 1.7 Gerçek dünya gerçeklemeleri

| Kim | Ne |
|---|---|
| Google | Kendi hesap altyapısıdır; Workspace'te 25 Mayıs 2026'dan itibaren varsayılan olarak açıktır ile yönetici kapatamamaktadır |
| Okta | Köken denemesine katılmış ile Google dışı bir kimlik doğrulama ortamında test etmiştir; ikincil kaynaktır |
| `dbsc-server` | TypeScript'tir, yani Node, Bun ile Deno; MIT lisanslıdır ile sıfır bağımlılığı vardır. 4 Eylül 2026 tarihli 267 numaralı W3C konusudur |
| `dbsc-toolkit` | Node.js'tir; Express, Fastify, Hono ile Next.js artı Redis ve PostgreSQL adaptörleri vardır. 24 Mayıs 2026 tarihli 260 numaralı konudur |
| `dbsc-php` | Test vektörlerini paylaşmaktadır |
| Rust | crates.io'da hiçbir şey yoktur. İlgili aramalar boş dönmektedir. Sıfırdan yazılacaktır |

---

## 2. SSF, CAEP ile RISC

### 2.1 Standart durumu, doğrulanmıştır

| Şartname | Durum | Tarih |
|---|---|---|
| OpenID SSF 1.0 | Nihaidir | Doküman 29 Ağustos 2025; onay 2 Eylül 2025, 85 kabul, bir ret ile 25 çekimser, 111 oy, %25,6 katılım |
| OpenID CAEP 1.0 | Nihaidir | 29 Ağustos 2025 |
| OpenID RISC 1.0 | Nihaidir | 29 Ağustos 2025 |
| CAEP birlikte çalışabilirlik profili 1.0 | Gerçekleyici taslağıdır; kamuya açık inceleme 27 Temmuz ile 25 Eylül 2026, oylama 26 Eylül ile 10 Ekim 2026 | Taslak alt bilgisi Eylül 2026'dır |

Çalışma grubu taslağı hâlâ 29 Ağustos 2025 tarihlidir; SSF 1.1 yolda değildir.

### 2.2 Verici gerçeklemesi, tam liste

#### Keşif

```
GET /.well-known/ssf-configuration                    (issuer path'siz)
GET /.well-known/ssf-configuration/{path}             (multi-tenant için)
```

İçerik tipi `application/json`'dır. Yanıt şöyledir.

```json
{
  "spec_version": "1_0",
  "issuer": "https://idp.example.com",
  "jwks_uri": "https://idp.example.com/jwks.json",
  "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
  "configuration_endpoint": "https://idp.example.com/ssf/streams",
  "status_endpoint":        "https://idp.example.com/ssf/status",
  "add_subject_endpoint":   "https://idp.example.com/ssf/subjects:add",
  "remove_subject_endpoint":"https://idp.example.com/ssf/subjects:remove",
  "verification_endpoint":  "https://idp.example.com/ssf/verify",
  "critical_subject_members": ["tenant", "user"],
  "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}],
  "default_subjects": "NONE"
}
```

Veren alanı zorunludur, veren iddiasıyla birebir aynı olmalı ile keşif adresiyle de aynı olmalıdır. Şartname sürümü yoksa alıcı ilk gerçekleyici taslağını varsaymaktadır; dolayısıyla mutlaka yazılmalıdır. Birlikte çalışabilirlik profili için zorunlu olanlar şartname sürümünün 1.0 ya da üstü olması, desteklenen teslim yöntemleri, anahtar seti adresi, yapılandırma uç noktası, durum uç noktası, doğrulama uç noktası ile OAuth 2.0 şemasını içeren yetkilendirme şemaları listesidir. Yetkilendirme şemaları kimlik doğrulamasız erişilebilir olmalıdır.

#### Akış yönetimi API'si, beş uç nokta

Yapılandırma uç noktası oluşturma için gönderi, okuma için alma, ki akış kimliği isteğe bağlıdır ve yoksa liste dönmektedir, güncelleme için yama ya da yerleştirme ile silme yöntemlerini desteklemektedir.

Oluşturma isteği şöyledir; alıcının sağladığı alanlar istenen olaylar, teslim ile açıklamadır.

```http
POST /ssf/streams HTTP/1.1
Authorization: Bearer <at>
Content-Type: application/json

{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rp.example/events",
             "authorization_header":"Bearer rp-supplied-secret"},
 "events_requested":["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
 "description":"RP A"}
```

Yanıt 201 oluşturuldu ile tam yapılandırmadır.

```json
{"stream_id":"f67e...","iss":"https://idp.example.com","aud":["https://rp.example"],
 "delivery":{...},"events_supported":[...],"events_requested":[...],"events_delivered":[...],
 "min_verification_interval":60,"inactivity_timeout":2592000}
```

Teslim edilen olaylar, desteklenen olaylarla istenen olayların kesişimidir ile alıcı buna göre davranmaktadır. Teslim alanı yoksa yoklama, yani RFC 8936, varsayılmakta ile verici uç nokta adresini kendisi üretmektedir. Çoklu akış desteklenmiyorsa ikinci oluşturma isteğine 409 çakışma dönülmelidir. Hata kodları ayrıştırma için 400, yetkilendirme yoksa 401, izin yoksa 403 ile çoklu akış yoksa 409'dur.

Durum uç noktası akış kimliğiyle sorgulandığında akış kimliği, durum ile gerekçe dönmektedir; durum etkin, duraklatılmış ya da devre dışıdır. Gönderiyle güncellenebilmektedir. Duraklatılmış durumda olaylar tutulmalı ile etkin olunca gönderilmelidir; aynı özne için sıralı olarak ya da yalnızca son olay gönderilmektedir. Devre dışı durumda tutma yoktur. Verici kendi kararıyla durumu değiştirirse akış güncellendi olayı göndermek zorundadır; etkinden duraklatılmışa ya da devre dışına geçişte bunu durdurmadan önce yapmalıdır.

Özne ekleme ile çıkarma uç noktaları gönderi yöntemini kullanmaktadır. Karmaşık özne eşleştirmesinde tanımsız alanlar joker karakter gibi davranmaktadır: alıcı yalnızca kiracıyı eklerse, hem kiracı hem kullanıcı taşıyan özneli olaylar da gönderilmektedir.

Doğrulama uç noktası akış kimliği ile opak bir durum değeriyle gönderildiğinde 204 içerik yok dönmektedir. Sonra eşzamansız olarak bir güvenlik olayı belirteci gönderilmektedir. Hataları 400, 401, 404 ile asgari doğrulama aralığı aşımında 429'dur.

#### Güvenlik olayı belirteci formatı, tuzaklar

```json
{
  "typ": "secevent+jwt",       // JOSE header — explicit typing ZORUNLU
  "alg": "RS256"               // Interop profili: RS256 ≥2048-bit ZORUNLU
}
{
  "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
  "iss": "https://idp.example.com",
  "aud": "https://rp.example/caep",
  "iat": 1615305159,
  "txn": "8675309",
  "sub_id": { "format": "iss_sub", "iss": "...", "sub": "jane@example.com" },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1615304991,
      "initiating_entity": "policy",
      "reason_admin": {"en": "Landspeed Policy Violation: C076E82F"},
      "reason_user":  {"en": "Access attempt from multiple regions."}
    }
  }
}
```

Üç yasak vardır: `sub` iddiası yasaktır, `exp` iddiası yasaktır ile olaylar nesnesinde birden fazla olay yasaktır, ki birlikte çalışabilirlik profilinin zorunlu kuralıdır.

Özne her zaman üst seviye `sub_id` alanıyla taşınmaktadır; CAEP ile RISC'in eski özne alanı kullanılsa bile `sub_id` zorunludur.

İşlem alanı, aynı kök nedenden doğan farklı belirteçlerde, örneğin oturum iptali ile kimlik bilgisi değişikliğinde, aynı değeri taşımalıdır; korelasyon için kritiktir.

#### Teslim

İtme, yani RFC 8935, şöyledir.

```http
POST /events HTTP/1.1
Host: rp.example
Content-Type: application/secevent+jwt
Accept: application/json
Authorization: <stream config'teki authorization_header>

<JWT>
```

İçerik tipi ile kabul başlıkları zorunludur. Başarı 202 kabul edildi ile boş gövdedir. Hata 400 artı hata kodu ve açıklama nesnesi artı içerik dili başlığıdır. Hata kodları geçersiz istek, geçersiz anahtar, geçersiz veren, geçersiz izleyici kitle, kimlik doğrulama başarısız ile erişim reddedildi değerleridir.

SSF profili teslim yetkilendirme başlığı alanını tanımlamaktadır: alıcı vermekte ile verici her istekte aynen göndermektedir. Bu, sizin tarafınızda saklanan üçüncü taraf statik bir kimlik bilgisidir; şifreli saklanmalı ile bir rotasyon yolu bırakılmalıdır.

Yoklama, yani RFC 8936, JSON gönderisiyle çalışmaktadır. İstek azami olay sayısı, ki sıfır yalnızca onay demektir, hemen dön bayrağı, ki varsayılanı yanlıştır yani uzun yoklamadır, onaylanan belirteç kimlikleri listesi ile belirteç hataları eşlemesini taşımaktadır. Yanıt belirteç kimliğinden JWT'ye bir eşleme ile daha fazlası var bayrağını döndürmektedir. Onaylanana kadar belirteç saklanmalı, onay sonrası saklama yükümlülüğü kalkmakta ile belirteç tekrar teslim edilebilmektedir; alıcı etkisiz kılınabilir olmalıdır.

#### OAuth yetkilendirmesi, birlikte çalışabilirlik profilinde zorunludur

Roller şöyledir: kaynak sunucu vericidir, istemci alıcıdır ile yetkilendirme sunucusu ayrı bir varlık olabilir.

Yetkilendirme sunucusu istemci kimlik bilgileri ya da yetkilendirme kodu akışını desteklemelidir.

Kısa ömürlü token 60 dakika ya da altıdır; FAPI güvenlik değerlendirmelerine atıf yapılmaktadır.

Token yetkilendirme başlığında taşınmalıdır, yani RFC 6750 2.1; adres sorgu parametresinde taşınması yasaktır.

Verici token geçerliliğini, bütünlüğünü, sona ermesini ile iptalini kontrol etmeli ile yetki yeterliliğine bakmalıdır; yetersizse RFC 6750 3.1 hataları dönmelidir.

Kapsamlar zorunludur: `ssf.read` akış yapılandırmasını okuma ile akış durumunu alma yetkisi vermektedir; `ssf.manage` bunlara ek olarak akış oluşturma, silme ile doğrulama yetkisi vermektedir. `ssf.` ile başlayan kapsamlar rezervedir ile yalnızca SSF şartnameleri tanımlayabilir.

#### Birlikte çalışabilirlik profili, uçtan uca zorunluluklar

TLS 1.2 ya da üstü kullanılmalı ile RFC 9325 uyumlu olunmalıdır.

Özne tanımlayıcı formatları, yani RFC 9493, e-posta, veren ile özne çifti ile yalnızca doğrulama için opak formatıdır. Verici en az birini üretebilmeli ile alıcı hepsini kabul etmelidir.

Verici için zorunlu operasyonlar oluşturma, yapılandırma okuma, durum okuma, doğrulama ile silmedir.

En az bir kullanım senaryosu desteklenmelidir: oturum iptali, kimlik bilgisi değişikliği, cihaz uyumluluğu değişikliği ya da risk seviyesi değişikliği. Hepsinde yönetici gerekçesi boş olmayan bir nesne olmalıdır.

### 2.3 CAEP olay tipleri, tam liste ile şemalar

Temel adres `https://schemas.openid.net/secevent/caep/event-type/` biçimindedir.

Tüm olaylarda isteğe bağlı ortak iddialar olay zaman damgası, başlatan varlık, ki yönetici, kullanıcı, politika ya da sistem olabilir, yönetici gerekçesi ile kullanıcı gerekçesidir; son ikisi BCP 47 dil kodundan mesaja eşlemedir.

| Sıra | Olay | Zorunlu alanlar | İsteğe bağlı |
|---|---|---|---|
| 1 | `session-revoked` | Yoktur | — |
| 2 | `token-claims-change` | Yeni değerleri taşıyan iddialar nesnesi | — |
| 3 | `credential-change` | Kimlik bilgisi tipi ile değişiklik tipi | Dost adı, X.509 vereni, X.509 seri numarası ile FIDO2 kimlik damgası |
| 4 | `assurance-level-change` | Ad alanı ile mevcut seviye | Önceki seviye ile değişim yönü, yani artış ya da azalış |
| 5 | `device-compliance-change` | Önceki ile mevcut durum, yani uyumlu ya da uyumsuz | — |
| 6 | `session-established` | Yoktur | Kullanıcı aracısı parmak izi, kimlik doğrulama bağlam sınıfı, kimlik doğrulama yöntemleri ile dış kimlik |
| 7 | `session-presented` | Yoktur | Kullanıcı aracısı parmak izi ile dış kimlik |
| 8 | `risk-level-change` | Asıl ile mevcut seviye, yani düşük, orta ya da yüksek | Önceki seviye ile risk gerekçesi |

Detaylar şunlardır. Kimlik bilgisi tipi parola, PIN, X.509, platform FIDO2, gezici FIDO2, FIDO U2F, doğrulanabilir kimlik bilgisi, telefon sesi, telefon kısa mesajı ile uygulama değerlerini alabilmekte ile karşılıklı anlaşılan başka değerler de kullanılabilmektedir. Değişiklik tipi oluşturma, iptal, güncelleme ile silmedir. Ad alanı RFC 8176, RFC 6711, ISO/IEC 29115, NIST kimlik güvence seviyesi, NIST kimlik doğrulayıcı güvence seviyesi ile NIST federasyon güvence seviyesi değerlerini alabilmekte ile özel değerler de kullanılabilmektedir. Asıl kullanıcı, cihaz, oturum, kiracı, kurumsal birim ile grup değerlerini almakta ile SSF'in ikinci bölümündeki diğer varlıklar da geçerlidir.

SSF çerçeve olayları doğrulama ile akış güncellendi olaylarıdır; birincisi durum, ikincisi statü ile gerekçe alanlarını taşımaktadır. Bunlar teslim edilen olaylar listesinde olmasa da gönderilebilmektedir.

RISC 1.0 olayları, temel adresi `https://schemas.openid.net/secevent/risc/event-type/` olmak üzere, şunlardır: hesap kimlik bilgisi değişikliği gerekli, hesap devre dışı, hesap etkin, hesap temizlendi, kimlik bilgisi ele geçirildi, ki kimlik bilgisi tipi zorunludur, tanımlayıcı değişti, tanımlayıcı geri dönüştürüldü, katılım, çıkış başlatıldı, çıkış iptal edildi, çıkış yürürlükte, kurtarma etkinleştirildi, kurtarma bilgisi değişti ile oturumlar iptal edildi.

### 2.4 Karşı taraf desteği, gerçek durum

Bugün canlı olarak sorgulanan sonuçlar şunlardır.

Google hâlâ standart öncesindedir. Hesaplar alan adındaki iyi bilinen SSF yapılandırma adresi 404 dönmektedir. Çalışan tek şey RISC yapılandırmasıdır.

```json
{"issuer":"https://accounts.google.com",
 "jwks_uri":"https://www.googleapis.com/oauth2/v3/certs",
 "delivery_methods_supported":["http://schemas.openid.net/secevent/risc/delivery-method/push"],
 "add_subject_endpoint":"https://risc.googleapis.com/v1beta/subjects:add",
 "get_status_endpoint":"https://risc.googleapis.com/v1beta/stream/status",
 "get_configuration_endpoint":"https://risc.googleapis.com/v1beta/v1beta/stream",
 "update_configuration_endpoint":"https://risc.googleapis.com/v1beta/stream:update",
 "verification_endpoint":"https://risc.googleapis.com/v1beta/stream:verify"}
```

Dikkat edilmelidir: alan adları standart dışıdır, yani durum ile yapılandırma uç noktası adları şartnamedekilerle eşleşmemektedir; teslim yöntemi tekdüzen kaynak adı eskidir, yani RFC 8935 değildir; uç noktalar beta sürümdedir ile üstelik birinde yol iki kez tekrarlanmaktadır. Alıcı yazarken Google'a özel bir adaptör şarttır.

Test altyapısı çalışmaktadır: `ssf.caep.dev` üzerindeki iyi bilinen SSF yapılandırması canlıdır, ancak şartname sürümü ikinci gerçekleyici taslağıdır, nihai değildir. Birlikte çalışabilirlik testleriniz için kullanılabilir.

| Sağlayıcı | Verici | Alıcı | Not |
|---|---|---|---|
| Okta | Üretimdedir, CAEP ile RISC | Üretimdedir | Standart SSF'e en yakın ticari gerçeklemedir |
| Google | RISC'i standart öncesi biçimde sunmaktadır | Workspace SSF alıcısı kapalı betadadır; ikincil kaynaktır ile doğrulanmamıştır | |
| Microsoft Entra | Standart SSF vericisi yoktur | Standart SSF alıcı uç noktası yoktur | Kendi sürekli erişim değerlendirmesi vardır ancak RFC 9470 değildir; yetersiz iddia hatası ile base64 iddia alanı kullanmaktadır |
| Keycloak | Verici Temmuz 2026'da birleştirilmiştir, deneysel bayrak arkasındadır | Yoktur | İşlemsel giden kutusu deseni kopyalanmaya değerdir |
| SailPoint, Cisco, IBM, Omnissa, Thales, CrowdStrike, Zscaler ile Jamf | Birlikte çalışabilirlik etkinliklerinde gösterilmiştir | | Üretim durumu vaka bazındadır |

Sertifikasyon programı tarafında OpenID Foundation'ın sertifikasyon sayfasında SSF ile CAEP profili bulunamamıştır. Yani sertifikalı SSF diye bir rozet henüz yoktur.

Rust ekosisteminde `sigshare` 0.1.0-alpha.2, yani 24 Şubat 2026 tarihli ile 47 indirmeli sürüm, tek SSF, CAEP ile RISC crate'idir ile alfa aşamasındadır. Pratikte kendiniz yazacaksınız.

---

## 3. DPoP, RFC 9449, gerçekleme derinliği

### 3.1 Sunucu doğrulama algoritması, RFC 9449 4.3, birebir

1. Tam olarak bir DPoP başlığı olmalıdır.
2. Değer tek ile iyi biçimli bir JWT olmalıdır.
3. 4.2'deki tüm zorunlu iddialar bulunmalıdır.
4. Tip `dpop+jwt` olmalıdır.
5. Algoritma kayıtlı bir asimetrik imza algoritması olmalı, none olmamalı ile desteklenen ve politikaca kabul edilebilir olmalıdır.
6. İmza, başlıktaki `jwk` ile doğrulanmalıdır.
7. `jwk` özel anahtar içermemelidir.
8. `htm` isteğin HTTP yöntemiyle eşleşmelidir.
9. `htu` isteğin adresiyle, sorgu ile parça yok sayılarak, eşleşmelidir.
10. Nonce verilmişse nonce iddiası eşleşmelidir.
11. JWT oluşturma zamanı, yani veriliş zamanı ya da nonce'a gömülü sunucu zamanı, kabul edilebilir bir pencerede olmalıdır.
12. Access token ile birlikte sunulduysa erişim token'ı özeti iddiası token'ın özetiyle eşleşmeli ile token'ın bağlı olduğu açık anahtar kanıttaki anahtarla aynı olmalıdır.

Normalizasyon önerilmektedir: `htu` karşılaştırmasından önce RFC 3986'nın 6.2.2 sözdizimi tabanlı ile 6.2.3 şema tabanlı normalizasyonu uygulanmalıdır.

### 3.2 Nonce mekanizması

Yetkilendirme sunucusu tarafında, yani sekizinci bölümde, nonce yoksa ya da uyuşmuyorsa 400 hatalı istek dönülmektedir.

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}
```

Kaynak sunucu tarafında, yani dokuzuncu bölümde, 401 yetkisiz dönülmektedir.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof"
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v
```

Nonce'lar öngörülemez olmalıdır ile birden fazla kez kullanılabilmektedir, yani kriptografik anlamda bir nonce değildir. Yetkilendirme sunucusu nonce'ıyla kaynak sunucu nonce'ı farklıdır ile birbirinin yerine kabul edilmemelidir. 11.3 bölümü zorunlu kılmaktadır: istemciye nonce verilmişse nonce'suz bir kanıt asla kabul edilmemelidir, ki bir düşürme korumasıdır. Birden fazla nonce başlığı yasaktır.

Nonce'ın neden şart olduğu 11.2'de anlatılmaktadır: nonce olmadan, istemciyi kontrol eden bir saldırgan, ki meşru kullanıcı da olabilir, veriliş zamanını geleceğe ayarlayarak önceden kanıt üretip dışarı sızdırabilmektedir. O zaman kanıtlanan şey anahtar sahipliği değil bir kanıta sahip olmaktır. Erişim token'ı özeti iddiası bunu token ömrüyle sınırlamaktadır; nonce kullanılmıyorsa uzun ömürlü DPoP erişim token'ı verilmemelidir.

### 3.3 Yeniden oynatma önbelleği stratejisi

RFC'nin 11.1 bölümünde doğrudan söyledikleri şunlardır. Sunucular kanıtları yalnızca kısa bir süre kabul etmelidir, yani tercihen saniyeler ya da dakikalar mertebesinde. Önbellek anahtarı, hedef adres bağlamında benzersiz tanımlayıcı olmalıdır, yani yalnızca tanımlayıcı değil, yöntem, adres ile tanımlayıcı üçlüsü kullanılmalıdır. Tek kullanım zorunluluğu pratikte her zaman uygulanabilir olmayabilir, örneğin tek bir uç noktanın arkasındaki çok sunucu ortak durum paylaşmıyorsa; RFC dağıtık ortamda bunun zor olduğunu kabul etmektedir. Bellek tükenmesi saldırısına karşı aşırı büyük tanımlayıcılar reddedilmeli ya da yalnızca özeti saklanmalıdır. Saat kayması konusunda yakın gelecekteki veriliş zamanları kabul edilebilir; ancak kayma büyükse veriliş zamanı yerine nonce'a gömülü sunucu zamanı kullanılmalıdır, çünkü bu keyfi saat kaymasında bile aynı sonucu vermektedir.

Argus için pratik reçete şudur.

```
Anahtar:  BLAKE3(htm ‖ htu_normalized ‖ jti)  → 128 bit
TTL:      nonce ömrü (örn. 60 sn) veya iat penceresi (±30 sn) — hangisi kısaysa
Store:    tek-node → moka/dashmap; çok-node → Redis SETNX + EX
Kapasite: peak_rps × TTL × 16 byte
```

Saniyede 1000 istek ile 60 saniyelik yaşam süresi 60.000 girdi çarpı yaklaşık 32 bayt, yani yaklaşık iki mebibayt demektir. Redis gidiş dönüşü eklemek istenmiyorsa nonce bir düğüm yakınlığı taşıyıcısı yapılmalıdır, yani nonce'a düğüm kimliği gömülmelidir; böylece aynı kanıt aynı düğüme gelmekte ile yerel önbellek yetmektedir.

### 3.4 Performans

Rust'ta ES256 doğrulama yaklaşık 20 ile 50 mikrosaniyedir, yani `p256`, `ring` ya da `aws-lc-rs` ile. Saniyede 10.000 istek 0,2 ile 0,5 işlemci çekirdeği demektir ile ihmal edilebilirdir.

RS256 doğrulama ES256'dan hızlıdır, çünkü açık üs küçüktür; ancak kanıt üretimi istemcide çok daha yavaştır. İstemci donanım anahtarı kullanıyorsa ES256 tercih edilmelidir.

Asıl maliyet imza değildir: JWT ayrıştırma, base64 çözme ile JSON seri durumdan çıkarma; yeniden oynatma önbelleğinin giriş çıkış işlemleri; ile nonce gidiş dönüşünün eklediği ekstra HTTP isteğidir.

Nonce gidiş dönüşü gizlenmelidir: her başarılı yanıtta nonce başlığıyla öngörülü biçimde yeni bir nonce verilmelidir; böylece istemci hiçbir zaman 400 ya da 401 almamaktadır. Nonce'lar kayan bir pencerede, yani mevcut ile önceki olarak, kabul edilmelidir.

Bağımsız ile hakemli bir DPoP kıyaslaması bulunamamıştır. Yukarıdaki rakamlar genel ECDSA ölçümlerinden çıkarımdır ile kendi ortamınızda ölçülmelidir.

### 3.5 DPoP ile yenileme token'ı rotasyonu

RFC'nin beşinci bölümündeki normatif kuralları şunlardır.

Açık istemciye DPoP kanıtıyla yenileme token'ı verildiyse token o açık anahtara bağlanmak zorundadır ile her kullanımda bağ doğrulanmak zorundadır. İstemci, yenileme token'ını kullandığı her seferde aynı anahtarla kanıt sunmak zorundadır.

Gizli istemcinin yenileme token'ı DPoP anahtarına bağlanmamaktadır; zaten istemci kimlik doğrulamasıyla gönderen kısıtlıdır. RFC'nin gerekçesi mevcut mekanizmanın daha esnek olmasıdır ile yenileme token'larını geçersiz kılmadan istemci kimlik bilgisi rotasyonuna izin vermektedir.

Yetkilendirme sunucusu token tipini taşıyıcı olarak dönerek yalnızca yenileme token'ını DPoP'a bağlayabilmektedir; kaynak sunucular DPoP desteklemiyorsa bile bu bir güvenlik kazancı sağlamaktadır. Kademeli geçiş için doğru yol budur.

Anahtar rotasyonu konusunda RFC'de açık istemci için bir mekanizma yoktur. Anahtar değişirse yenileme token'ı ölmekte ile yeniden yetkilendirme gerekmektedir. Bu bilinçli tasarlanmalıdır; cihaz anahtarı kaybı yeniden giriş demektir.

Yetkilendirme kodunu anahtara bağlama, yani onuncu bölümdeki `dpop_jkt`, şöyledir: yetkilendirme isteğine JWK parmak izi eklenmelidir. Token uç noktasında kanıtın parmak iziyle karşılaştırılmalı ile eşleşmiyorsa reddedilmelidir. PKCE ile birlikte kullanılabilir; ancak koruma yalnızca her yetkilendirme isteği için ayrı bir DPoP anahtarı kullanılıyorsa PKCE'ye benzer bir düzeye çıkmaktadır. Anlık istek nesnesiyle de kullanılabilir.

### 3.6 IETF taslakları, 2026 durumu, datatracker'dan doğrulanmıştır

| Taslak | Revizyon | Tarih | Durum |
|---|---|---|---|
| `draft-parecki-oauth-dpop-device-flow` | 00 | 20 Eylül 2025; süresi 24 Mart 2026'da dolmuştur | Bireyseldir ile çalışma grubu benimsememiştir. Okta'dan Parecki ile Ping'den Campbell |
| `draft-rosomakho-oauth-dpop-rt` | 00 | 14 Ekim 2025; süresi dolmuştur | Bireyseldir ile bilgilendirme amaçlıdır. Zscaler |
| `draft-parecki-oauth-jwt-dpop-grant` | 01 | 3 Ağustos 2026 | Bireyseldir |
| `draft-ritz-idpop`, yani etkileşimli DPoP | 01 | 6 Temmuz 2026 | Bireyseldir |
| `draft-nandakumar-oauth-dpop-proof` | 00 | 19 Mart 2026 | Bireyseldir; uygulamadan bağımsız bir DPoP çerçevesidir |

Cihaz akışı taslağının neden önemli olduğu şudur: cihaz yetkilendirme yetkisine DPoP eklendiğinde cihaz kodu belirli bir açık anahtara bağlanmakta ile çalınmış bir cihaz kodunun kötü niyetli bir aktör tarafından kullanılması engellenmektedir. Bu, beşinci bölümde görülecek cihaz kodu kimlik avı salgınına doğrudan yapısal bir cevaptır. Ancak taslak sıfırıncı revizyondadır ile süresi dolmuştur; çalışma grubuna taşınması için itilmeye değerdir.

Yenileme token'ı taslağı DPoP yenileme token'ı ile nonce başlıklarıyla erişim ile yenileme token'larını farklı anahtarlara bağlamaktadır. Motivasyonu yenileme token'ının arka uçta ya da donanım güvenlik modülünde, erişim token'ının kısa ömürlü olarak ön yüzde bulunmasıdır. Sıfırıncı revizyondadır ile süresi dolmuştur; gerçeklenmemeli ancak haberdar olunmalıdır.

### 3.7 Bilinen tuzaklar, gerçekleme raporlarından ile RFC'den

1. Adres normalizasyonu: sondaki eğik çizgi, port, harf büyüklüğü ile yüzde kodlaması sorun çıkarmaktadır. RFC 3986'nın 6.2.2 ile 6.2.3 kuralları uygulanmalıdır.
2. TLS sonlandıran vekil ana bilgisayar başlığını yeniden yazıyorsa adres asla eşleşmemektedir. İletilen ana bilgisayar başlığından yapılandırılmış bir genel köken kullanılmalı ile istemciden gelen değere asla körü körüne güvenilmemelidir.
3. Yöntem harf büyüklüğü: RFC eşleşme demektedir ile HTTP yöntemleri harf büyüklüğüne duyarlıdır. Sıkı karşılaştırılmalıdır.
4. Erişim token'ı özeti yalnızca kaynak sunucudadır; token uç noktasında beklenmemelidir.
5. İçgözlem kullanan kaynak sunucu, erişim token'ının doğrulama anahtarı parmak izini içgözlem yanıtından almalı ile kanıtın parmak iziyle karşılaştırmalıdır.
6. Nonce karışıklığı: yetkilendirme sunucusu nonce'ı, kaynak sunucu nonce'ı ile OIDC kimlik token'ı nonce'ı üç ayrı şeydir. RFC bunu açıkça uyarmaktadır.
7. Algoritmanın none olması ile `jwk` içinde özel anahtar bulunması: ikisi de reddedilmelidir.
8. Desteklenen DPoP imzalama algoritmaları metadata alanı yetkilendirme sunucusu metadata'sında yayımlanmalıdır.

---

## 4. Token bağlama alternatifleri

### 4.1 mTLS ile DPoP: hangisi ne zaman

| | mTLS, RFC 8705 | DPoP, RFC 9449 |
|---|---|---|
| Katman | TLS'tir | Uygulamadır |
| Bağlama | İstemci sertifikasının DER kodlamasının base64url SHA-256 özetidir | JWK parmak izidir |
| İstemci kimlik doğrulama yöntemleri | PKI tabanlı TLS istemci kimlik doğrulaması, ki konu ayırt edici adı, alan adı, adres, IP ya da e-posta alternatif adından tam olarak biri kullanılır, ile kendinden imzalı varyanttır | — |
| Altyapı gereksinimi | TLS sonlandırma noktasında istemci sertifikasına erişim gerekmektedir; içerik dağıtım ağı ile vekil sorunludur | Yoktur; saf bir HTTP başlığıdır |
| İstek başına maliyet | Yaklaşık sıfırdır; TLS el sıkışmasında bir kez yapılmakta ile oturum devamıyla amorti edilmektedir | Her istekte bir imza doğrulaması artı yeniden oynatma önbelleğidir |
| Tarayıcı desteği | Zayıftır ile kullanıcı deneyimi kötüdür | JavaScript'ten kullanılabilir ancak anahtar dışa aktarılamaz olmalıdır |
| Uygun olduğu yer | İşletmeler arası, sunucudan sunucuya, FAPI, yüksek güvence ile sabit altyapıdır | Mobil, tek sayfa uygulaması, komut satırı, açık istemci ile dinamik istemci tabanıdır |

FAPI 2.0 her ikisini de kabul etmekte ile gönderen kısıtlamayı zorunlu kılmaktadır; taşıyıcı token'a izin vermemektedir. Bir kimlik sağlayıcının ikisini de desteklemesi doğru karardır; doğrulama anahtarı iddiası her iki durumda da doğrulama noktasını tekilleştirmektedir.

### 4.2 Token Binding, RFC 8471, 8472 ile 8473, neden ölmüştür

TLS katmanına derin müdahale gerektirmekteydi, yani bir TLS uzantısı ile dışa aktarılan anahtar materyali kullanmaktaydı.

TLS 1.3 ile birlikte yeniden tasarım gerekti ile ekosistem takip etmedi.

Sonlandırıcı problemi vardı: içerik dağıtım ağları, yük dengeleyiciler ile TLS denetimi yapan ara kutuların hepsi mekanizmayı kırmaktaydı; mTLS'in yaşadığı sorunun daha ağır hâliydi.

Chrome desteği kaldırdı; eski Edge ile birlikte pratik olarak yok oldu ile sunucu tarafı destek izole kaldı.

Ders şudur: TLS katmanında çalışan bağlama mekanizmaları modern web altyapısıyla uyumsuzdur. DPoP'un uygulama katmanında olması bir tesadüf değil Token Binding'in ölümünden çıkarılan derstir. DBSC de aynı sebeple HTTP başlığı ile JWT üzerine kurulmuştur.

### 4.3 Cihaz donanım anahtarına bağlama, sunucu tarafında ne doğrulanmaktadır

#### Android Keystore ile StrongBox anahtar kanıtlaması

2026'nın kritik değişikliği Google kanıtlama kök sertifikasının değişmesidir. Eski kök, seri numarası `f92009e853b6b045` olan sertifika, 1 Şubat 2026'ya kadar geçerlidir. Yeni kök `CN=Key Attestation CA1`, EC P-384'tür ile 1 Şubat 2026'dan itibaren geçerlidir. Kök listesi `android.googleapis.com/attestation/root` adresinde JSON olarak yayımlanmaktadır.

Sunucu doğrulama sırası şudur.

1. Anahtar deposundan gelen X.509 zinciri alınmalıdır.
2. Her sertifikanın bir sonrakini imzaladığı doğrulanmalıdır.
3. Kökün Google'ın yayımladığı listede olduğu doğrulanmalıdır.
4. İptal listesi kontrol edilmelidir: kanıtlama durum adresi, iptal edilmiş ya da askıya alınmış seri numaralarını ile gerekçelerini döndürmektedir. İptal edilmiş ya da askıda olan reddedilmelidir. Önbellek denetimi başlığına göre önbeleklenmelidir. 2021 öncesi cihazlarda fabrika anahtarlarının süresi dolmuş olabilmektedir ancak iptal listesinde yoksa güvenilirdir; bu durumda sona erme kontrolü uygulanmamalıdır.
5. Kanıtlama uzantısı köke en yakın sertifikada bulunmalıdır. Yalnızca ilk oluşuma güvenilmelidir; zincirde ikinci bir kanıtlama uzantısı varsa bu bir sahtecilik göstergesidir ile reddedilmelidir.
6. ASN.1 ile anahtar tanımı ayrıştırılmalıdır: kanıtlama sürümü, kanıtlama güvenlik seviyesi, anahtar yöneticisi güvenlik seviyesi, kanıtlama meydan okuması, yazılımla zorlanan ile güvenilir ortamda zorlanan yetki listeleri.
7. Kanıtlama meydan okuması gönderilen nonce ile eşleşmelidir; bu bir tazelik kanıtıdır.
8. Kanıtlama güvenlik seviyesi güvenilir ortam ya da StrongBox olmalıdır; yazılım ise donanım garantisi yoktur.
9. Kritik özellikler güvenilir ortamda zorlanan listeden okunmalıdır, yazılımla zorlanana güvenilmemelidir: amaç, algoritma, kimlik doğrulama gerekmiyor bayrağı, kullanıcı kimlik doğrulama tipi ile köken.
10. Doğrulama asla cihazda yapılmamalıdır; ele geçirilmiş bir Android sistemi kanıtlamayı taklit edebilmektedir.

Google'ın resmî Kotlin kütüphanesi github.com/android/keyattestation adresindedir.

#### Apple ile Secure Enclave

Uygulama kanıtlaması, yani iOS ile iPadOS uygulamaları için, şöyle çalışmaktadır: kanıtlama çağrısı bir CBOR kanıtlama nesnesi döndürmekte; sunucu zinciri Apple'ın kök sertifika otoritesine kadar, istemci veri özetinin nonce ile eşleşmesini, uygulama kimliği özetini, sayacı ile kanıtlama sertifikasındaki açık anahtarı doğrulamaktadır. Sonraki istekler için doğrulama çağrısı kullanılmakta ile sayaç monoton artmalıdır.

DeviceCheck cihaz başına iki bit artı bir risk metriği vermektedir ile kimlik doğrulama bağlamak için uygun değildir.

Web tarafında Secure Enclave'e doğrudan erişim yoktur; yalnızca WebAuthn platform kimlik doğrulayıcısı üzerinden dolaylı erişim vardır.

DBSC'nin macOS'ta Secure Enclave kullanacağı duyurulmuştur ancak sertifika zinciri sunucuya gönderilmemektedir, ki parmak izi çıkarmaya karşı bir tasarımdır; dolayısıyla sunucu donanım garantisini doğrulayamamaktadır.

#### TPM 2.0 ile Windows Hello

WebAuthn güvenilir platform modülü kanıtlama formatı sürüm, algoritma, kanıtlama kimlik anahtarı sertifika zinciri, imza, kanıtlama bilgisi ile açık anahtar alanını taşımaktadır. Sunucu şunları doğrulamalıdır: kanıtlama bilgisindeki ek verinin, kimlik doğrulayıcı verisi ile istemci veri özetinin birleşiminin özeti olması; kanıtlanan adın açık anahtar alanının adıyla eşleşmesi; kanıtlama kimlik anahtarı sertifikasının modül üreticisinin sertifika otoritesine zincirlenmesi; genişletilmiş anahtar kullanımının kanıtlama kimlik anahtarı sertifikası nesne tanımlayıcısı olması; ile konu alternatif adında üretici, model ile sürüm bilgisinin bulunması.

Windows Hello for Business, Entra kimliğine karşı bir FIDO2 kimlik bilgisi olarak sunulmaktadır.

2026 uyarısı şudur: Dirk-jan Mollema'nın Ağustos 2026 bulgusuna göre ele geçirilmiş bir kullanıcı oturumundaki düşük yetkili süreçler, Windows kripto arayüzlerini çağırarak Windows Hello anahtarlarını PIN ya da biyometrik yeniden doğrulama olmadan kullanabilmektedir. Ayrıca Entra'nın beş dakikalık WebAuthn meydan okumaları oturuma bağlı değildir. Yani modülde anahtar bulunması kullanıcının orada olduğu anlamına gelmemektedir.

Bir başka uyarı CVE-2026-34348'dir; SpecterOps tarafından 5 Ağustos 2026'da Black Hat USA'de açıklanmıştır. Windows olay günlükleme servisi, WebAuthn doğrulama imzalarını düz metin olarak yetkisiz okunabilir günlüklere yazmaktaydı; Entra'daki bir zayıflıkla zincirlenerek kimlik avına dirençli çok faktörlü kimlik doğrulama atlatılmıştır. Microsoft 14 Temmuz 2026 yamasıyla imza alanlarını altı bayta kısaltmıştır; SpecterOps 10 Ağustos 2026 itibarıyla Entra tarafında bir değişiklik gözlemlemediğini bildirmiştir.

#### WebAuthn cihaza bağlı açık anahtar uzantısı

Senkronize geçiş anahtarlarının yanında cihaza özgü ile senkronize olmayan ikinci bir anahtar sunmakta ile bu doğrulamanın hangi fiziksel cihazdan geldiği sorusuna cevap vermektedir. Yaygın platform desteği hâlâ yoktur; Eylül 2026 itibarıyla doğrulanamamıştır. İzlemeye değerdir ancak bugün üzerine mimari kurulmamalıdır.

### 4.4 Dördüncü seçenek: token'ı tarayıcıya hiç vermemek

Bu bölümün ilk üç alt başlığı aynı soruyu sormaktadır: tarayıcıdaki bir token nasıl çalınamaz hâle getirilir. Dördüncü bir cevap vardır ile en güçlüsüdür: token tarayıcıya hiç verilmez.

Duende'nin sunucu tarafı oturum modeli budur, kaynak kendi dokümanıdır, erişim 13 Eylül 2026. Çerez yalnızca bir oturum kimliği taşımaktadır; oturum durumu sunucuda, tipik olarak bir veritabanında ya da dağıtık önbellekte tutulmaktadır. Erişim ile yenileme token'ları sunucuda kalmaktadır ile tarayıcı standart bir HTTP oturum çerezi taşımaktadır. Ön yüz için arka uç çerçevesi, tarayıcı ile arka uç API'leri arasında bir güvenlik vekili olarak durmakta; oturum yönetimini, token işlemeyi ile API vekilliğini üstlenmektedir.

Bu modelin bu bölümün tehdit modeline karşı davranışı şudur. Bilgi hırsızı yazılımı, 5.6'daki ölçekte, tarayıcıdan çerez çalmaktadır; çerez bir oturum kimliği olduğu için sunucu tarafında iptal edilebilmektedir ile bu, taşıyıcı token'ın çalınmasından yapısal olarak farklıdır. Taşıyıcı token'ı iptal etmek için ya kısa ömür ya bir iptal listesi gerekmektedir; oturum kimliği zaten sunucuda aranmaktadır, dolayısıyla iptal ek bir mekanizma değil varsayılan davranıştır. Buna karşılık ortadaki tarayıcı, yani 5.3, bu modeli de yenmektedir: saldırgan kurbanın tarayıcısını sürüyorsa oturum kimliği yeterlidir. Yani sunucu tarafı oturum, hırsızlığa karşı güçlü, oturum sürmeye karşı zayıftır ile DBSC'nin yerine geçmemektedir.

Argus için üç bağlantı vardır. Birincisi, Argus'un kendi barındırılan girişi ile yönetim konsolu §1 kararı 20 gereği zaten doğrudan oturum çerezi kullanmaktadır; bu, aynı modelin Argus'un kendi yüzeyindeki hâlidir ile ayrı bir karar değildir. İkincisi, üçüncü taraf tek sayfa uygulamaları için önerilen desen ön yüz için arka uçtur; §23 §8'in on beşinci maddesi bunu zaten söylemektedir ve bu bölüm onun tehdit modeli gerekçesidir. Üçüncüsü, Duende'nin çok ön yüzlü modeli aynı barındırıcıda ön yüz başına ayrı OIDC ile çerez ayarı tutmakta ile her iş ortağının kendi kimlik sağlayıcısını getirebilmesini sağlamaktadır; bu, Argus'un kiracı başına yukarı akış federasyon tasarımıyla aynı şekildir ile o tasarımın istemci tarafındaki karşılığıdır.

Bir uyarı gerekmektedir: sunucu tarafı oturum, oturum deposunu bir sıcak yol bağımlılığı hâline getirmektedir. §19'un bozulmuş mod tartışması bu yüzden oturum deposunu da kapsamalıdır; veritabanı erişilemez olduğunda taşıyıcı token doğrulaması etkilenmemekte ancak sunucu tarafı oturum doğrulaması etkilenmektedir. İki mod aynı bozulma bütçesine sahip değildir.

---

## 5. Ortadaki saldırgan ile oturum hırsızlığı, 2026 tehdit verisi

### 5.1 Hizmet olarak kimlik avı piyasası: Tycoon operasyonu ile dersi

Zirve 2025'tedir: CrowdStrike'a göre Microsoft'un engellediği kimlik avı girişimlerinin %62'si Tycoon 2FA kaynaklıdır ile tek ayda 30 milyondan fazla kötü amaçlı e-posta gönderilmiştir. Okta yalnızca Temmuz 2025'te 11.199 tespit raporlamıştır.

Operasyon 4 Mart 2026'dadır: Europol siber suç merkezi koordinasyonunda, altı ülkede, 330 alan adı kapatılmıştır.

Sonuç şudur: CrowdStrike hacmin 4 ile 5 Mart'ta dörtte bire düştüğünü ancak günler içinde eski seviyeye döndüğünü raporlamıştır. Okta altyapının bir ile iki gün içinde dört yeni sağlayıcıya taşındığını gözlemlemiştir.

Barracuda'nın 16 Nisan 2026 tarihli raporuna göre Mamba 2FA, EvilProxy, Sneaky 2FA ile Whisper 2FA boşluğu doldurmuştur; dört büyük platformun toplam hacmi operasyon sonrasında artmıştır, yani yaklaşık 20 milyondan 23 milyonun üzerine çıkmıştır. Barracuda, Tycoon'un imza yorum satırlarını taşıyan ile %99 kod benzerliği gösteren bir cihaz kodu kimlik avı kampanyası tespit etmiştir.

Ders şudur: arz tarafına yönelik en büyük müdahale bile toplam hacmi düşürmemiş, yeniden dağıtmıştır. Savunma kit markasına değil tekniğe göre tasarlanmalıdır.

### 5.2 2026'da teknik olarak ne değişmiştir

1. Bot karşıtı kapılar standartlaşmıştır. Cloudflare Turnstile neredeyse her ciddi kittedir; hem kötü amaçlı kaynak yüklemesini geciktirmekte hem otomatik analizi engellemektedir.
2. Ters vekilden uzaklaşma iki yönde olmaktadır. Barracuda'nın 15 Ekim 2025 tarihli raporundaki Whisper 2FA vekil kullanmamakta ile AJAX tabanlı gerçek zamanlı bir dışa sızdırma döngüsü işletmektedir; kimlik bilgisini birden çok kez çalmakta, çok katmanlı Base64 ile XOR kullanmakta ile agresif hata ayıklama karşıtı önlemler almaktadır, örneğin geliştirici araçları açılırsa tarayıcıyı çökertmektedir. Bir ayda yaklaşık bir milyon saldırı yapmıştır. CSA Labs'ın 2026'da belgelediği Starkiller ise Docker içinde başsız Chrome ile gerçek giriş sayfasını vekillemekte ile kurban otantik sayfanın kendisiyle etkileşmektedir. Tuş vuruşu kaydı, canlı ekran akışı, parola yöneticisi modülleri ile OAuth cihaz akışı modülü vardır. Aylık 200 ile 350 dolardır.
3. İşletim sistemine duyarlı dinamik belge nesne modeli kullanılmaktadır. Sneaky2FA, Kasım 2025'te tarayıcı içinde tarayıcı tekniğini eklemiştir: sahte tarayıcı penceresi kurbanın işletim sistemine ile tarayıcısına göre boyutlandırılmakta ile stillendirilmektedir.
4. Konut vekili katmanlaması yapılmaktadır. Elastic'in Tycoon analizine göre otomatik aktarma katmanı bulut sanal sunucularındadır, yani `axios` ile `undici` kullanıcı aracılarını taşımaktadır; operatör konsolu ise konut vekilinden bağlanmaktadır. Bu, coğrafya ile otonom sistem numarası tespitini kasten etkisizleştirmektedir.
5. WebSocket ile Socket.IO aktarımı klasik akışta hâlâ baskındır; bazı kitler Socket.IO 4.7.5'i içerik dağıtım ağından yüklemektedir, ki ironik bir tespit fırsatıdır.

Tespit için en değerli iki davranışsal imza, Elastic'e göre şunlardır. Google Workspace tarafında aynı kullanıcı için yaklaşık bir saniye içinde birden fazla IP'den kimlik doğrulama görülmektedir; bu coğrafyaya değil zamansal imkânsızlığa dayanmaktadır. M365 tarafında Node.js kullanıcı aracılarıyla otomatik aktarma görülmektedir.

Elastic'in en operasyonel bulgusu şudur: kit cihaz tabanlı birincil yenileme token'ı kalıcılığı kurmakta ile bu oturum iptalinden sağ çıkmaktadır. Doğru müdahale sırası önce kayıtlı cihaz aslını silmek, sonra oturumları iptal etmektir. Ters sıra kalıcılığı kırmamaktadır. Kitten operatöre devir penceresi 10 ile 20 dakikadır; otomasyonla 10 saniyenin altında sınırlama mümkündür.

### 5.3 Ortadaki tarayıcı, DBSC'yi neden yenebilmektedir

Mandiant ile Google Cloud'un 17 Mart 2025 tarihli yayınına göre kurban sahte bir siteye bakmamakta, saldırganın sunucusunda çalışan gerçek bir tarayıcıyı noVNC ya da WebRTC üzerinden uzaktan kontrol etmektedir.

| | Ortadaki saldırgan, yani Evilginx ile Tycoon | Ortadaki tarayıcı, yani Delusion, CuddlePhish ile EvilnoVNC |
|---|---|---|
| Kurulum | Hedef başına kimlik avı şablonu yazımıdır, saatler sürmektedir | Herhangi bir siteye saniyeler içinde kurulmaktadır |
| Çalınan | Oturum çerezi ile kimlik bilgisidir | Tüm tarayıcı profilidir: çerez, yerel depolama, indekslenmiş veritabanı ile servis işçisi |
| Görsel | Fark olabilmektedir | Birebir gerçek sayfadır |

Kritik ile zor nokta şudur: ortadaki tarayıcı saldırısında oturum en baştan saldırganın tarayıcısında oluşmaktadır. Bu, çerezin başka bir makineye taşınması değildir. Dolayısıyla saldırganın tarayıcısı kendi güvenilir platform modülüyle DBSC kaydını meşru şekilde tamamlayabilmektedir; oturum saldırganın cihazına doğru şekilde bağlanmış olmaktadır. Aynı mantık Entra token koruması için de geçerlidir.

Bir belirsizlik notu gerekmektedir: bu, Google ya da Mandiant tarafından bu ifadeyle yayımlanmış bir tespit değildir. DBSC şartnamesinin, saldırgan oturum kaydı sırasında kullanıcı aracısını değiştiriyor ya da içine kod enjekte ediyorsa DBSC'nin saldırıyı engellemeyeceği ifadesinden ile ortadaki tarayıcı mimarisinden çıkan analitik bir sonuçtur.

Ortadaki tarayıcıyı durduran şey FIDO2 ile WebAuthn köken bağlamasıdır. Mandiant bunu açıkça belirtmektedir: kurbanın platform kimlik doğrulayıcısı uzaktan çağrılamamakta ile video akışı kriptografik imza üretememektedir. Tek teorik istisna hibrit karekod aktarımıdır ancak bu tasarım Bluetooth yakınlık doğrulaması gerektirmektedir. Bu konuda doğrulanmış bir 2026 araştırması bulunamamıştır; teorik bir risktir ile gözlemlenmemiştir.

### 5.4 Geçiş anahtarlarına saldırılar, kesin sınıflandırma

2026 itibarıyla WebAuthn kriptografisinin kırıldığına dair bir kanıt yoktur. Bilinen tüm atlatmalar beş kategoriden birindedir.

| Saldırı | Durum | Ön koşul |
|---|---|---|
| FIDO düşürme, Proofpoint, Ağustos 2025: Evilginx şablonu Windows'ta Safari kullanıcı aracısı taklit etmekte ile Entra FIDO'yu kapatıp tek kullanımlık şifre veya anlık bildirim yedeğine düşmektedir | Kavram kanıtıdır ile vahşi doğada gözlemlenmemiştir | Ortadaki saldırgan vekili ile yedek yolun açık olması |
| Zayıf hesap kurtarma; Netcraft 7 Nisan 2026'da bunun en çok kullanılacak yol olacağını öngörmektedir | Gerçek ile yaygındır | Zayıf kurtarma akışı |
| Altın geçiş anahtarı, Unit 42, 3 Ağustos 2026: Chrome'un 32 baytlık simetrik ana anahtarı FIDO tanılama günlüklerinde açıkta ile süreç belleğinde düz metindir; tüm senkronize geçiş anahtarı özel anahtarları açılmaktadır. Google'ın gerçeklemesinde bu sırrı döndürme ya da iptal etme yolu yoktur | Kavram kanıtıdır ile gözlemlenmemiştir | Uç noktada çalışan kötü amaçlı yazılım |
| CVE-2026-34348, yani geçiş anahtarını aktarma, SpecterOps, 5 Ağustos 2026 | Kavram kanıtıdır; Windows 14 Temmuz 2026'da yamalanmıştır ile Entra tarafı açıktır | Yerel günlük okuma |
| Windows Hello oturum içi kötüye kullanımı, Mollema, Ağustos 2026 | Kavram kanıtıdır | Ele geçirilmiş oturum |
| Hibrit karekod aktarımı | Bilinmemektedir; araştırma bulunamamıştır | — |
| Sözde rastgele fonksiyon ile büyük ikili veri uzantısı istismarı | Bilinmemektedir; araştırma bulunamamıştır | — |
| Cihaz kodu kimlik avıyla geçiş anahtarını tamamen atlama | Gerçektir, aktiftir ile yaygındır | Yoktur |

En önemli çıkarım şudur: geçiş anahtarlarının 2026'daki en büyük düşmanı bir geçiş anahtarı saldırısı değil cihaz kodu kimlik avıdır, çünkü geçiş anahtarı akışını hiç devreye sokmadan geçerli token vermektedir.

İkinci çıkarım şudur: altın geçiş anahtarı saldırısı, cihaza bağlı ile senkronize geçiş anahtarı ayrımının gerçek bir güvenlik sınırı olduğunun somut kanıtıdır. Donanım anahtarında bu saldırı sınıfı uygulanamamaktadır.

### 5.5 Cihaz kodu kimlik avı, 2026'nın ana hikâyesi

Push Security'nin özeti şudur: cihaz kodu yetkilendirmesi etkin biçimde kimlik doğrulamadan sonra gerçekleştirilmektedir. Dolayısıyla tüm çok faktörlü kimlik doğrulama ile geçiş anahtarı kontrollerini atlamakta, sahte bir giriş sayfası bulunmamakta ile yamalanacak bir zafiyet olmamaktadır; RFC 8628 tasarımı gereğidir.

| Veri | Kaynak |
|---|---|
| 2026'da cihaz kodu kimlik avı sayfalarında 37,5 kat artış vardır | Push Security, 4 Nisan 2026 |
| Dolaşımda 14'ten fazla araç takımı vardır ile EvilTokens liderdir | Push Security |
| Tek bir EvilTokens kampanyası, Şubat ile Mart 2026 arasında, 340'tan fazla M365 kuruluşunu ele geçirmiştir | CSA Labs, 4 Nisan 2026 |
| Storm-2372, Rusya bağlantılı orta güvenle, Ağustos 2024'ten beri aktiftir | Microsoft, 13 Şubat 2025 |
| Storm-2372 Microsoft kimlik doğrulama komisyoncusu istemci kimliğine geçmiş, saldırgan kontrollü cihaz kaydı ile birincil yenileme token'ı elde etmiştir | Microsoft |
| Yenileme token'ları 90 güne kadar geçerlidir ile her kullanımda yenilenmektedir; birincil yenileme token'ı parola sıfırlamalarından sağ çıkmaktadır | Microsoft |
| Scattered Lapsus$ Hunters sesli kimlik avı ile Salesforce cihaz kodunu birleştirerek 1000'den fazla kuruluşa ulaşmıştır | Push Security |

Savunma tarafında Microsoft'un önerisi, 25 günden az kullanım geçmişi olan kiracılarda koşullu erişimle cihaz kodu akışını bloklamaktır. Push Security'nin uyarısı şudur: bu tam bir koruma değildir, çünkü onay düzeltme gibi teknikler alternatif OAuth akışlarını istismar etmektedir.

Argus için doğrudan tasarım kararı şudur: cihaz yetkilendirme yetkisi varsayılan olarak kapalı olmalıdır. Açıksa cihaz akışı DPoP taslağının mantığı uygulanmalı, yani cihaz kodu DPoP anahtarına bağlanmalı; ile kullanıcı kodu girişi ayrı bir onay ekranında istemci adı, kapsam ile IP gösterilerek yapılmalıdır.

### 5.6 Bilgi hırsızı ölçek verisi, 2026

SpyCloud'un 19 Mart 2026 tarihli yıllık kimlik maruziyeti raporundan.

| Metrik | Değer |
|---|---|
| Veri gölünde toplam kimlik kaydı | 65,7 milyardır, yıllık %23 artmıştır |
| 2025'te ele geçirilen oturum çerezi | 8,6 milyardır |
| 2025'te bilgi hırsızı enfeksiyonu | 13,2 milyondur |
| Enfeksiyon başına ortalama kimlik bilgisi | Yaklaşık 50'dir |
| Uç nokta tespit ve yanıt ya da antivirüs korumalı uç noktalardaki enfeksiyon oranı | %40'tır |
| Parola yöneticisi ana parolası | 1,1 milyondur |
| Yapay zekâ aracı kimlik bilgisi ya da çerezi | 6,2 milyondur |
| Açığa çıkan API anahtarı ile token, yani insan olmayan kimlikler | 18,1 milyondur |
| Parola tekrar kullanımı | Bireysel %65, kurumsal %42'dir |

Flashpoint'in 2026 verisine göre 2025 tam yılında 11,1 milyondan fazla enfekte cihaz ile 3,3 milyardan fazla çalınmış kimlik bilgisi, çerez ile token vardır. 2026'nın ilk yarısında 7,4 milyon ana bilgisayar, yani dönemsel %27 artış, ile 1,7 milyar kimlik bilgisi görülmüştür.

Verizon'un 20 Mayıs 2026 tarihli veri ihlali araştırma raporundan. Zafiyet istismarı ilk erişim vektörü lideri olmuştur, yaklaşık %31; ancak kimlik bilgisi kötüye kullanımı tüm ihlallerin %39'unda, herhangi bir aşamada, bulunmaktadır. Fidye yazılımı kurbanlarının %73'ünde önceki yıl içinde ilişkili bir bilgi hırsızı enfeksiyonu ya da kimlik bilgisi sızıntısı vardır ile %50'sinde bu fidye yazılımından 95 gün öncedir. İlk erişim komisyoncusu günlüklerindeki cihazların %54'ünde en az bir bilgi hırsızı bulunmaktadır. Kurumsal e-posta alan adlarından aylık ortalama 2.362 ihlal edilmiş kimlik bilgisi çıkmaktadır. Uzaktan izleme ile yönetim aracı kötüye kullanımı yıllık %240 artmıştır. Sesli kimlik avı tıklama oranı %2, e-posta kimlik avı %1,4'tür.

IBM X-Force'un 2026 verisine göre 2025'te 300.000'den fazla ChatGPT kimlik bilgisi seti karanlık ağdadır; suçlular arasında veri hırsızlığı, yani %18, şifrelemeyi, yani %11, geçmiştir.

Aileler şunlardır. Lumma, Mayıs 2025 operasyonundan sağ çıkmıştır; Bitdefender 11 Şubat 2026'da aktif komuta kontrol doğrulamış ile Microsoft 5 Mart 2026'da yeni bir Windows Terminal varyantı bildirmiştir. Rhadamanthys, 13 Kasım 2025 tarihli Operation Endgame'den Tor yedeğiyle hayatta kalmıştır. Vidar Kasım 2025'ten beri baskındır ile Telegram ile Steam profillerini ölü bırakma çözücüsü olarak kullanmaktadır. StealC, uç nokta tespitli ortamlarda tercih edilmektedir, çünkü telemetri ayak izi düşüktür. VoidStealer Aralık 2025'te hizmet olarak kötü amaçlı yazılım hâline gelmiş ile ikinci ana sürümü 13 Mart 2026'da çıkmıştır. macOS tarafında AMOS için Jamf Ağustos 2025'te %300'lük bir sıçrama bildirmiş ile Sophos macOS kötü amaçlı yazılım koruma güncellemelerinin %40'ının buna ayrıldığını belirtmiştir.

Chrome uygulamaya bağlı şifreleme atlatma durumu şöyledir. Şifreleme Temmuz 2024'te Chrome 127 ile gelmiştir; Eylül ile Ekim 2024'te MeduzaStealer, Whitesnake, Lumma, Vidar ile StealC atlatma geliştirmiştir. Rhadamanthys geliştiricileri bunun on dakikalarını aldığını söylemiştir. Elastic'in Ekim 2024 tarihli kedi fare oyunu raporuna göre STEALC ile VIDAR, ChromeKatz aracıyla ağ servisi süreç belleğinden çerez yapılarını okumakta; METASTEALER bileşen nesne modeliyle sistem token'ını taklit edip yükseltme servisini çağırmakta; PHEMEDRONE ise uzaktan hata ayıklama portu ile tüm çerezleri alma çağrısını kullanmaktadır. 13 Mart 2026 tarihli VoidStealer ikinci ana sürümü en gelişmiş atlatmayı yapmaktadır: donanım kesme noktaları kullanmaktadır. Süreç hata ayıklama ile iş parçacığı bağlamı ayarlama çağrılarıyla tarayıcıya hata ayıklayıcı olarak bağlanmakta ile ana anahtarı çıkarmaktadır. Tarayıcı belleğini değiştirmemektedir, yani yazılım kesme noktalarından gizlidir, ile yetki yükseltme gerektirmemektedir; önceki tüm yöntemler yönetici yetkisi istemekteydi. Google'ın 2024'teki kendi öngörüsü doğru çıkmıştır: saldırgan davranışının enjeksiyon ya da bellek kazıma gibi daha gözlemlenebilir tekniklere kayması beklenmekteydi.

Uygulamaya bağlı şifreleme bir güvenlik sınırı değil bir maliyet artırıcıdır. Halefi DBSC'dir, çünkü çerezi korumak yerine çalınmış çerezi işe yaramaz kılmaktadır.

Bilgi hırsızlarının DBSC'yi hedefleyip hedeflemediği sorusunun cevabı şudur: doğrudan bir DBSC atlatma özelliği belgelenmemiştir ile mimari olarak atlatılamaz. Gözlenen adaptasyon yön değiştirmedir: çerez sızdırma yerine canlı oturumu yerinde kötüye kullanma, yenileme token'ı, birincil yenileme token'ı ile OAuth token'ı hedefleme ile parola hedefleme. Constella'ya göre bilgi hırsızı paketlerinin %98,6'sı aktif parola ile %99,54'ü kullanım adresleri içermektedir.

### 5.7 DBSC'nin gerçek dünya etkinliği

Eylül 2026 itibarıyla kamuya açık ile sayısallaştırılmış bir DBSC etkinlik ölçümü yoktur. Google'ın 9 Nisan 2026 tarihli blog yazısı lansmandan bu yana oturum hırsızlığında anlamlı bir azalma gözlemlendiğini söylemekte ancak bir metrik vermemektedir. 28 Mayıs 2026 tarihli Workspace duyurusu anlamlı ölçüde zorlaştırdığını söylemekte ancak sayı vermemektedir. Okta ile yapılan testler anlamlı azalmadan söz etmekte ancak sayı vermemektedir.

DBSC'nin kapsamadıkları, SpyCloud ile Constella verilerine göre, şunlardır: yenileme token'ı hırsızlığı, cihaz kodu kimlik avı, yerel kötü amaçlı yazılımın canlı oturumu yerinde kötüye kullanması, birincil yenileme token'ı ile Kerberos bilet verme bileti, yerel depolamadaki OAuth token'ları, ortadaki tarayıcı, dolaşımdaki mevcut kimlik bilgileri ile tüm parola vektörü.

---

## 6. Oturum içi anomali tespiti

### 6.1 Sinyal kanıt tablosu

| Sinyal | Kanıt gücü | Not |
|---|---|---|
| Kriptografik bağlama, yani DBSC, DPoP ya da mTLS | Yüksektir ile deterministiktir | Bir anomali tespiti değil bir kanıttır |
| Yenileme token'ı ya da oturum kimliği yeniden kullanım tespiti | Yüksektir, deterministiktir ile yanlış pozitifi yoktur | En yüksek getirili tek kontroldür |
| WebAuthn yeniden doğrulaması | Yüksektir | Olay tetiklemeli olmalıdır, periyodik değil |
| Cihaz duruşu, yani mobil cihaz yönetimi ya da uç nokta tespiti kanıtlaması | Orta ile yüksektir | Kriptografik doğrulanabilirdir; kendi cihazını getir senaryosunda kapsama yoktur |
| IP ya da otonom sistem numarası değişimi | Ortadır | Tek başına aksiyon için zayıftır |
| Zamansal imkânsızlık, yani yaklaşık bir saniye içinde farklı IP'ler | Yüksektir | Coğrafyaya değil fiziğe dayanmaktadır |
| JA4 TLS parmak izi | Ortadır | Yalnızca bir sınıf değişimi dedektörü olarak kullanılmalıdır |
| JA3 | Düşüktür ile pratikte ölüdür | Chrome uzantı sırası rastgeleleştirmesi ile GREASE nedeniyledir |
| HTTP/2 çerçeve parmak izi | Ortadır | Ters vekil arkasında bilgi kaybolmaktadır ile mimari maliyeti yüksektir |
| Kullanıcı aracısı tutarlılığı | Düşüktür | Taklidi önemsizdir |
| İmkânsız seyahat | Düşük ile ortadır, yanlış pozitifi yüksektir | Microsoft'ta bile çevrimdışı bir tespittir |
| Klavye ile fare biyometrisi | Düşüktür ile pratikte kanıtsızdır | Oturumlar arası yarı toplam hata oranı yaklaşık 0,19'dur |

Microsoft'un kendi sınıflandırması öğreticidir: anonim IP, alışılmadık oturum açma özellikleri, doğrulanmış tehdit aktörü IP'si ile şüpheli çok faktörlü onay gerçek zamanlıdır. Atipik seyahat, imkânsız seyahat, ortadaki saldırgan, kötü amaçlı IP, şüpheli tarayıcı ile sızmış kimlik bilgileri çevrimdışıdır ve raporlara 48 saate kadar sürede yansımaktadır. Dünyanın en büyük kimlik sağlayıcısında bile imkânsız seyahat gerçek zamanlı bir oturum içi kontrol değildir.

JA3'ün ölümü şöyledir: GREASE, yani RFC 8701, her bağlantıda değişmekte ile Chrome istemci merhaba uzantı sırasını rastgeleleştirmektedir; tek bir tarayıcı binlerce JA3 özeti üretmektedir. JA4 GREASE'i elemekte ile uzantıları sıralamaktadır, ancak kullanıcıyı değil istemci sınıfını ayırt etmektedir. Doğru kullanım şudur: oturum başında JA4 kaydedilmeli ile ortada bir sınıf değişimi olursa, yani tarayıcıdan bir HTTP kütüphanesine geçilirse, bu güçlü bir sinyaldir. Aynı kalırsa hiçbir şey kanıtlamamaktadır. Yanlış pozitifi düşük, duyarlılığı çok düşüktür; iyi bir ve koşulu, kötü bir birincil sinyaldir.

Davranışsal biyometrinin neden reddedildiği şudur: yayımlanan iyi rakamlar, yani %2,48 ile %3,60 arası eşit hata oranı, oturum içi ya da çapraz doğrulama ölçümlerindendir. Model ile eşik birinci oturumda sabitlenip ikinci oturuma değiştirilmeden uygulandığında sabit metinde eğri altındaki alan 0,895 ile yarı toplam hata oranı yaklaşık 0,19 olmaktadır; yani her beş kararda yaklaşık bir hata vardır. Fare dinamiklerinde durum daha kötüdür ile önceki çalışmaların sonuçları tekrarlanabilir değildir. Akademik eleştiri şudur: sözde sürekli kimlik doğrulama üzerine yapılan araştırmaların çoğu aslında periyodik kimlik doğrulamadır.

### 6.2 Risk tabanlı kimlik doğrulama, gerçek akademik kanıt

Wiefling ile ekibinin çalışmaları okumaya değerdir.

arXiv 2101.10681: 780 kullanıcı, 247 özellik ile 1,8 yıl. Ana bulgu şudur: risk tabanlı kimlik doğrulama her çevrim içi servise dikkatlice uyarlanmalıdır; küçük yapılandırma ayarlamaları bile güvenlik ile kullanılabilirlik özelliklerini büyük ölçüde etkileyebilmektedir. Yani taşınabilir bir doğru eşik yoktur.

arXiv 2206.15139: 3,3 milyon kullanıcı ile 31,3 milyon giriş. Makine öğrenimi tabanlı parametre optimizasyonu ile IP yerine gidiş dönüş süresi kullanımının gizlilik değerlendirmesi yapılmaktadır. Veri seti kamuya açıktır ile kendi modelinizi kalibre etmek için gerçek bir başlangıç noktasıdır.

arXiv 2308.15156: Google, Amazon ile Facebook yeniden test edilmiştir. Birçok test senaryosu risk tabanlı kimlik doğrulamayı nadiren tetiklemektedir; büyük sağlayıcılar bile az tetikle tarafında hata yapmaktadır.

### 6.3 Sinyalden aksiyona, katmanlı tasarım

```
KATMAN 0 — Kriptografik gerçekler (deterministik, itiraz kabul etmez)
  • revocation_epoch aşıldı mı?  • DBSC/DPoP proof geçerli mi?  • RT reuse?
  → BLOK / oturum iptali. Skor yok.

KATMAN 1 — Deterministik politika (yönetici yazmış, açıklanabilir, denetlenebilir)
  • IP named location dışında mı?  • Cihaz uyumlu mu?  • acr/auth_time yeterli mi?
  → RFC 9470 step-up challenge veya blok.

KATMAN 2 — Risk skoru (olasılıksal)
  • Unfamiliar sign-in props, ASN anomalisi, JA4 sınıf değişimi, TI eşleşmesi
  → Step-up TALEBİ + CAEP risk-level-change yayını + insan inceleme kuyruğu
  → ASLA otomatik kalıcı kilit YOK
```

İkinci katmanın asla nihai karar vermemesinin hukuki gerekçesi SCHUFA kararıdır, yani Avrupa Birliği Adalet Divanı'nın 7 Aralık 2023 tarihli C-634/21 kararı. Mahkeme, otomatik skorlamanın sonraki kararda belirleyici rol oynadığı için 22. madde anlamında otomatik bir karar olduğuna hükmetmiştir. Skor yalnızca bir girdidir savunması bu karardan sonra zayıftır. Lastik damga niteliğindeki insan onayı zinciri kırmamaktadır. Kullanıcıyı otomatik olarak kalıcı kilitlemek muhtemelen 22. madde kapsamındadır; yükseltme talep etmek çok daha savunulabilirdir.

RFC 9470 yükseltme akışı şöyledir.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A different authentication level is required",
  acr_values="urn:argus:acr:webauthn-uv", max_age="300"
```

İstemci bunları yetkilendirme isteğine taşımakta; yetkilendirme sunucusu kimlik doğrulama bağlam sınıfını ile kimlik doğrulama zamanını erişim token'ına, yani RFC 9068'e, ya da içgözlem yanıtına koymaktadır. Sunucu metadata'sında desteklenen bağlam sınıfı değerleri yayımlanmalıdır.

Microsoft'un sürekli erişim değerlendirmesi RFC 9470 kullanmamaktadır. Kendi mekanizması yetersiz iddia hatası ile base64 kodlu bir iddialar alanıdır; istemci yeteneği kütüphane yapılandırmasıyla bildirilmekte ile token'da bir yetenek iddiası olarak görünmektedir. Argus'ta RFC 9470 birincil yapılmalı; Microsoft tarzı yalnızca belirli bir andan sonra düzenlenmiş token semantiği gerekirse ek olarak desteklenmelidir. İkisi aynı 401 yanıtında birlikte yaşayabilmektedir.

### 6.4 İptal yayılım gecikmesi, gerçekçi bütçeler

| Sistem | Yayılım |
|---|---|
| Entra sürekli erişim değerlendirmesi kritik olayı | Hedef gerçek zamanlıya yakındır ancak 15 dakikaya kadar gözlenebilmektedir |
| Entra sürekli erişim değerlendirmesi IP konum politikası | Anlıktır; politika kaynağa replike edilmiştir |
| Entra koşullu erişim politikası ya da grup üyeliği değişikliği | İki saat ile bir gün arasındadır |
| Entra kimlik koruması çevrimdışı tespitinden rapora | 48 saate kadardır |
| Cloudflare Gateway cihaz duruşu | Yalnızca oturum başındadır; devam eden oturumlar kesilmemektedir |

Entra'nın sürekli erişim değerlendirmesinin dokümante sınırları şunlardır: yalnızca IP tabanlı adlandırılmış konumları görebilmektedir, yani ülke ya da bölge tabanlı olanlarda değerlendirme yoktur ile bir saatlik token verilmektedir; IP aralıkları toplamı 5.000'i aşarsa gerçek zamanlı uygulama yapamamaktadır; ile misafir kullanıcılar desteklenmemektedir. Değerlendirme farkındalıklı oturumlarda token 28 saate kadar uzamakta ile yapılandırılabilir token ömrü politikası onurlandırılmamaktadır.

Bunun anlattığı ders şudur: sürekli değerlendirme pratikte her istekte tam politika değerlendirmesi değildir; kaynağa replike edilmiş bir politika alt kümesi artı eşzamansız iptal olayları demektir. Replikasyon gecikmesi mimarinin ana zorluğudur, algoritma değil.

### 6.5 Yanlış pozitif kilitlenmelerinden kaçınma

1. Gölge mod zorunludur; yeni her kural önce yalnızca günlüğe yazmalıdır.
2. Kimlik sağlayıcının gördüğü IP ile bağlı tarafın gördüğü IP ayrı alanlar olarak günlüğe yazılmalıdır. Microsoft'un sıkı uygulama geçişinin ilk adımı tam olarak budur. Bu ayrımı yapmayan bir sistem sıkı moda hiç geçememektedir.
3. Öğrenme dönemi gerekmektedir; Entra'da alışılmadık oturum açma özellikleri için en az beş gün, atipik seyahat için 14 gün ya da 10 giriş gerekmektedir.
4. Blok yerine yükseltmeye düşülmelidir, yani açık başarısızlık yerine sürtünmeye.
5. Her risk kuralı için bir acil durum yolu bulunmalıdır.
6. Yanlış pozitif bütçesi bir hizmet seviyesi hedefi gibi yönetilmeli ile eşik aşılırsa kural otomatik olarak gölge moda dönmelidir.
7. Kademeli çıkış uygulanmalıdır: salt okunur, karantina ile iptal.
8. Acil şimdi zorla yolu bulunmalıdır, yani Entra'nın oturum iptal komutunun muadili.

### 6.6 Gecikme bütçesi, üç katman

| Katman | Ne | Bütçe |
|---|---|---|
| A, her istekte | JWT imzası, yani süreç içi anahtar seti önbelleğiyle; token veriliş zamanının kullanıcının iptal dönemiyle karşılaştırılması; önceden derlenmiş IP ağacı araması; bağlam sınıfı ile kimlik doğrulama zamanı aritmetiği; DPoP ile DBSC kanıtı | 99. yüzdelikte bir milisaniyenin altıdır; ayırma yapılmamalı ile ağ çağrısı olmamalıdır |
| B, token yenilemede | Tam politika değerlendirmesi, coğrafi konum ile otonom sistem numarası, tehdit istihbaratı, cihaz duruşu, risk skoru ile grup üyeliğinin taze okunması | 50 ile 200 milisaniye kabul edilebilirdir |
| C, eşzamansız | Davranışsal temel çizgi, atipik seyahat, makine öğrenimi çıkarımı ile kiracılar arası korelasyon; sonuçta bir CAEP olayı yayımlanmaktadır | Saniyelerden dakikalara |

Her istekte tam risk değerlendirmesinin neden yanlış bir hedef olduğu şudur. Sektörde kimse bunu yapmamaktadır: Entra IP politikasını replike etmekte, DBSC kanıtları çerez yenilemesinde alınmakta ile Cloudflare Gateway oturum başında bakmaktadır. Sinyaller saniyede bir değişmemektedir. Saniyede 10.000 istekte her isteğe 50 milisaniye eklemek 500 eşzamanlı uçuştaki istek demektir. Girdi aynıyken makine öğrenimi modeli ek bilgi üretmemekte, yalnızca skor gürültüsü eklemektedir.

Rust'a özgü öneriler şunlardır. Politikalar başlangıçta bir karar ağacına ya da bit maskesine derlenmeli ile sıcak yolda dizgi karşılaştırması olmamalıdır. IP eşleştirme için bir patricia ağacı kullanılmalı ile Entra'nın 5.000 aralık sınırı yaşanmamalıdır. İptal dönemi, anahtar seti ile politika anlık görüntüleri için `arc-swap` kullanılmalı ile sıcak yolda okuma yazma kilidi bulunmamalıdır. SSF için işlemsel giden kutusu kullanılmalıdır, yani olay iş işlemi içinde yazılmalı ile dışarıda teslim edilmelidir; Keycloak'ın 3 Temmuz 2026'da deneysel olarak yaptığı budur. Karar günlüğü sıcak yoldan çıkarılmalı, yani sınırlı bir kanala taşınmalıdır, ancak geri basınç ile düşürme politikası bilinçli seçilmelidir; denetim günlüğü kaybetmek bir uyum sorunudur.

### 6.7 Hukuki çerçeve, kısa

GDPR 22. madde ile SCHUFA kararı yukarıda, 6.3'te ele alınmıştır.

GDPR dokuzuncu madde ile KVKK açısından davranışsal biyometri, kişiyi benzersiz tanımlamak amacıyla işlendiğinde özel nitelikli veridir. KVKK'da açık rıza kuraldır; KVKK rehberi veri sorumlularının alternatif bir doğrulama yöntemi sunmasını istemektedir ile Haziran 2026'da mesai takibi biyometrisi için yeni bir ilke kararı yayımlanmıştır. Dolayısıyla zorunlu kılınamayan bir kontrolden saldırgan da çıkabilmekte ile kontrolün güvenlik değeri yapısal olarak sıfırlanmaktadır.

Avrupa Birliği yapay zekâ yasası açısından şunlar geçerlidir. Beşinci maddedeki yasaklar 2 Şubat 2025'ten beri yürürlüktedir: işyerinde duygu çıkarımı ile biyometriden korunan özellik çıkarsama yasaktır. Kurumsal bir kimlik sağlayıcıda stres tespiti gibi bir şey düşünülmemelidir. Kritik bir muafiyet vardır: üçüncü ekin birinci maddesi, tek amacı belirli bir gerçek kişinin iddia ettiği kişi olduğunu doğrulamak olan doğrulama sistemlerini hariç tutmaktadır; dolayısıyla bire bir biyometrik doğrulama, WebAuthn dahil, yüksek risk kapsamının dışındadır. Bir takvim uyarısı gerekmektedir: artificialintelligenceact.eu sitesindeki uygulama takvimi, ki son güncellemesi 31 Ağustos 2026'dır, üçüncü ek yüksek risk için 2 Aralık 2027 demektedir; birçok 2025 ile 2026 makalesi hâlâ 2 Ağustos 2026 yazmaktadır. Bunun hangi hukuki araçla değiştiği doğrulanamamıştır ile hukuk ekibinize resmî gazeteden teyit ettirilmelidir.

---

## 7. Argus için sentez ile öncelik sırası

#### Birinci faz: deterministik temel, sezgisel yok

1. Yenileme token'ı rotasyonu ile yeniden kullanım tespiti: klasiktir, yanlış pozitifi yoktur ile en yüksek getirili tek kontroldür.
2. Kullanıcı başına iptal dönemi: token veriliş zamanı dönemden küçükse token ölüdür. Sabit zamanlıdır, tüm iptal tiplerini kapsamaktadır ile bağlı tarafta tek bir önbellek araması demektir.
3. RFC 9470 yükseltmesi: bağlam sınıfı ile kimlik doğrulama zamanı iddiaları, yetersiz kullanıcı kimlik doğrulaması hatası ile desteklenen bağlam sınıfı listesi.
4. DPoP, RFC 9449: nonce açık olmalı, yeniden oynatma önbelleği yöntem, adres ile tanımlayıcı üçlüsüyle ve kısa yaşam süresiyle kurulmalı ile açık istemcinin yenileme token'ı bağlanmalıdır.
5. mTLS, RFC 8705, ikinci yol olarak: sertifika parmak izi iddiasıyla ile FAPI 2.0 uyumu için.
6. WebAuthn: bağlam sınıfı seviyelerine bağlanmalı ile yüksek değerli hesaplarda donanım anahtarı kullanılmalıdır; altın geçiş anahtarı saldırısı senkronizasyon riskini somutlaştırmıştır.
7. Cihaz yetkilendirme yetkisi varsayılan olarak kapalı olmalı; açıksa cihaz kodu DPoP anahtarına bağlanmalıdır.

#### İkinci faz: standart sinyal yayını, SSF vericisi

8. İyi bilinen SSF yapılandırması artı beş uç nokta artı itme ve yoklama teslimi kurulmalıdır.
9. CAEP olayları yayımlanmalıdır: oturum iptali, kimlik bilgisi değişikliği, token iddiası değişikliği, güvence seviyesi değişikliği ile risk seviyesi değişikliği. Yönetici gerekçesi boş olmayan bir nesne olmalıdır, ki birlikte çalışabilirlik profilinin zorunlu kuralıdır; kullanıcı gerekçesi dolu olmalı ile işlem alanıyla korelasyon kurulmalıdır.
10. İşlemsel giden kutusu, yani Keycloak deseni, kullanılmalıdır.
11. CAEP birlikte çalışabilirlik profili takip edilmelidir; 10 Ekim 2026'da nihai olması beklenmektedir.
12. Okuma ile yönetim kapsamları tanımlanmalı ile erişim token'ı 60 dakika ya da altı olmalıdır.

#### Üçüncü faz: DBSC arayüzü, gerçekleme değil iskele

13. Oturum deposu şeması kurulmalıdır: oturum kimliği, açık anahtar, parmak izi, kapsam, kimlik bilgileri, üç elemanlı meydan okuma halkası ile son yenileme zamanı.
14. Kayıt, yenileme ile iyi bilinen cihaza bağlı oturumlar uç noktaları bir özellik bayrağı arkasında açılmalıdır.
15. İzleyici kitle ile veriliş zamanı doğrulaması tercihe bağlı yapılmalıdır, çünkü Chrome asgari yük göndermektedir.
16. Dört yüzlü kodların oturum ölümü demek olduğu kuralı yönlendirmeye, güvenlik duvarına ile hız sınırlayıcıya işlenmelidir; 429 kullanılmalı, 404 kullanılmamalıdır.
17. Kayıt penceresindeki bağsız yetki çerezine tam yetki verilmemeli ile ayrı bir düşük yetki durumu tanımlanmalıdır.
18. Meydan okuma yaşam süresi dakikalar düzeyinde olmalıdır; 90. yüzdelik kayıt 15 saniyedir ile kuyruk dakikalara uzamaktadır.

#### Dördüncü faz: alıcı ile politika

19. SSF alıcısı kurulmalı ile cihaz uyumluluğu değişikliği tüketilmelidir. Google için özel bir adaptör yazılmalıdır, çünkü RISC yapılandırması, beta uç noktaları ile standart dışı alan adları kullanmaktadır.
20. SCIM olayları, yani RFC 9967, Mayıs 2026, kullanılmalıdır; yaşam döngüsü olaylarıdır ile Entra'nın bir günlük grup gecikmesi baştan tasarımdan çıkarılmalıdır.
21. IP adlandırılmış konumları bir patricia ağacıyla tutulmalı, kimlik sağlayıcının gördüğü IP ile bağlı tarafın gördüğü IP ayrı alanlar olmalı ile gölge mod zorunlu kılınmalıdır.

#### Beşinci faz: olasılıksal katman, dikkatle

22. Alışılmadık oturum açma özellikleri, Wiefling'in kamuya açık 3,3 milyon kullanıcılık veri setiyle kalibre edilmelidir.
23. Zamansal imkânsızlık, yani aynı kullanıcının yaklaşık bir saniye içinde farklı IP'lerden görünmesi, kullanılmalıdır; coğrafyadan çok daha güvenilirdir.
24. JA4 yalnızca bir sınıf değişimi dedektörü olmalı ile tek başına aksiyon üretmemelidir.
25. Çıktı bir yükseltme talebi ile bir CAEP risk seviyesi değişikliği olayı olmalıdır. Asla otomatik kalıcı kilit uygulanmamalıdır.

#### Yapılmayacaklar

Davranışsal biyometri kullanılmamalıdır; yarı toplam hata oranı yaklaşık 0,19'dur ile GDPR dokuzuncu madde, KVKK açık rıza ile alternatif sunma yükümlülüğü vardır.

İşyerinde duygu çıkarımı yapılmamalıdır; yapay zekâ yasası yasağı Şubat 2025'ten beri yürürlüktedir.

Ham imkânsız seyahat gerçek zamanlı bir blok tetikleyicisi yapılmamalıdır; Microsoft bile bunu çevrimdışı işlemektedir.

Kendi kimlik tehdidi tespit ve yanıt platformunuz yazılmamalıdır. İyi bir SSF vericisi olunmalıdır; pazar, kimlik sağlayıcının sinyal üretip genişletilmiş tespit ile yanıt ürünlerinin tüketmesi yönünde gitmektedir.

#### Olay müdahalesi, doğru sıra, Elastic

Önce kayıtlı cihaz aslı silinmeli, sonra oturumlar iptal edilmeli, sonra token'lar iptal edilmelidir. Ters sıra cihaz tabanlı birincil yenileme token'ı kalıcılığını kırmamaktadır. Saldırganın devir penceresi 10 ile 20 dakikadır; otomasyonla 10 saniyenin altında sınırlama mümkündür.

---

## 8. Belirsizlikler ile doğrulanamayanlar

1. DBSC macOS durumu yaklaşan sürümde diye duyurulmuştur, Nisan 2026. Bugün indirilen Chrome Enterprise politika şablonunda tek DBSC politikası yalnızca Windows'u kapsamaktadır. Bazı ikincil kaynaklar Chrome 147'de macOS demektedir; doğrulanamamıştır ile politika verisi aksini ima etmektedir.
2. DBSC'nin sayısal etkinliği: Google ile Constella yalnızca niteliksel ifadeler kullanmaktadır. Kamuya açık bir metrik yoktur.
3. Ortadaki tarayıcının DBSC'yi yendiği iddiası, şartnamenin kendi hedef dışı maddesinden ile saldırı mimarisinden çıkarılan analitik bir sonuçtur. Google ya da Mandiant tarafından bu ifadeyle yayımlanmış bir tespit bulunamamıştır.
4. Hibrit karekod aktarımı araştırması, 2026, bulunamamıştır. Bluetooth yakınlık gereksinimi bir tasarım savunmasıdır ancak gerçekleme sıkılığı doğrulanmamıştır.
5. Sözde rastgele fonksiyon ile büyük ikili veri istismarı araştırması, 2026, bulunamamıştır. Altın geçiş anahtarının bu çıktıları da açıp açmadığı sorusu spekülatiftir ile bir kaynağa dayanmamaktadır.
6. Google Workspace SSF alıcısının kapalı beta olduğu ikincil bir kaynaktandır ile doğrulanamamıştır. İlgili iyi bilinen adres 404 dönmektedir.
7. DPoP performans rakamları için bağımsız ile hakemli bir kıyaslama bulunamamıştır. Verilen 20 ile 50 mikrosaniye genel ECDSA ölçümlerinden çıkarımdır.
8. Yapay zekâ yasasının üçüncü ek tarihi: takvim sayfası 2 Aralık 2027, birçok makale 2 Ağustos 2026 demektedir. Değişikliğin hukuki aracı doğrulanamamıştır.
9. CISA, NCSC ile FIDO Alliance orijinal dokümanları 403 hatası ile arama bütçesi nedeniyle birinci elden okunamamış ile ikincil kaynaklar üzerinden çalışılmıştır.
10. Microsoft'un kimlik avına dirençli çok faktörlü kimlik doğrulamanın %99'dan fazlasını engellediği rakamı, orijinalinde genel çok faktörlü kimlik doğrulama için üretilmiş bir istatistiktir; kimlik avına dirençli olana atfedilmesi bir ikincil kaynak aktarımıdır.
11. SSF sertifikasyon programı: OpenID Foundation sertifikasyon sayfasında SSF ile CAEP profili bulunamamıştır.

---

### Ekler

Rust ekosistemi gerçeği, crates.io'da bugün sorgulanmıştır.

| Alan | Durum |
|---|---|
| DBSC | Hiçbir crate yoktur. Sıfırdan yazacaksınız |
| SSF, CAEP ile RISC | `sigshare` 0.1.0-alpha.2, 24 Şubat 2026, 47 indirme; alfadır ile tek seçenektir |
| DPoP | `dpop-verifier` 4.4.0, 12 bin indirme; `turbomcp-dpop` 3.2.0, Ağustos 2026; `skyauth` 0.3.2, 8 Eylül 2026 |

Test altyapısı `ssf.caep.dev` üzerindeki iyi bilinen SSF yapılandırmasıdır; canlı bir vericidir ile şartname sürümü ikinci gerçekleyici taslağıdır. Birlikte çalışabilirlik testleri için kullanılabilir; nihai şartname olmadığına dikkat edilmelidir.

Referans gerçeklemeleri github.com/CloudNua/dbsc-server, yani TypeScript, MIT ile sıfır bağımlılık; github.com/SulimanAbdulrazzaq/dbsc-toolkit, yani Node; ile github.com/android/keyattestation, yani Kotlin ile resmî Google kütüphanesidir.

Ana şartname adresleri şunlardır. DBSC editör taslağı w3c.github.io/webappsec-dbsc adresindedir, 27 Ağustos 2026. SSF 1.0 nihai sürümü openid.net/specs/openid-sharedsignals-framework-1_0-final.html adresindedir. CAEP 1.0 nihai sürümü openid.net/specs/openid-caep-1_0-final.html adresindedir. RISC 1.0 nihai sürümü openid.net/specs/openid-risc-1_0-final.html adresindedir. CAEP birlikte çalışabilirlik 1.0 taslağı openid.github.io/sharedsignals/openid-caep-interoperability-profile-1_0.txt adresindedir. İlgili RFC'ler DPoP için 9449, yükseltme için 9470, mTLS için 8705, güvenlik olayı belirteci teslimi için 8935 ile 8936, özne tanımlayıcıları için 9493 ile SCIM olayları için 9967'dir.

## Ek: DPoP, token bağlama ile donanım kanıtlaması, derinleştirme

### E.1 Acil aksiyon: Android kanıtlama kök rotasyonu

Bu, raporun tamamındaki tek şu anda kırılıyor olabilir maddesidir. Android anahtar kanıtlaması doğrulaması yapan herhangi bir kodunuz varsa aşağıdakilere bakılmalıdır.

| Kök | Konu ile algoritma | Geçerlilik |
|---|---|---|
| Yeni kök | `CN=Key Attestation CA 1, OU=Android, O=Google LLC, C=US`, ECDSA P-384 | 17 Temmuz 2025 ile 15 Temmuz 2035 arası; 1 Şubat 2026'dan itibaren geçerlidir |
| Mevcut kök | Seri numarası `f92009e853b6b045`, RSA 2048 | 20 Mart 2022 ile 15 Mart 2042 arası |
| Eski kök | 2016 kökü | 24 Mayıs 2026'da süresi dolmuştur |

Ayrıca uzaktan anahtar sağlama geçişi vardır: Android 16 ile üstünün standardıdır ile fabrika toplu anahtarları 1 Şubat 2026'da sona ermiştir. Sonuçları şunlardır. Yeni bir sağlama bilgisi uzantısı, yani `1.3.6.1.4.1.11129.2.1.16` nesne tanımlayıcısı, CBOR biçiminde ile köke en yakın sertifikada bulunmaktadır; uzaktan sağlanmış bayrağı, sağlama yöntemi, ki sıfır fabrika ile bir uzaktan sağlamadır, sağlama durumu, sağlamadan bu yana geçen süre ile sona ermeye kalan süreyi taşımaktadır. Uzaktan sağlanan sertifikalar kısa ömürlüdür; dolayısıyla sona erme tarihi artık gerçekten kontrol edilmelidir, çünkü eski fabrika anahtarları için kontrol edilmemekteydi. Cihaz başına iptal mümkündür ile bir toplu anahtar sızıntısının binlerce cihazı etkilemesi sorunu çözülmüştür.

Aksiyon şudur: kök güven deposu statik gömülmemeli, Google'ın kanıtlama kök adresinden dinamik beslenmelidir; resmî Kotlin kütüphanesinin mantığı taşınmalıdır.

### E.2 Düzeltme: WebAuthn cihaza bağlı açık anahtar uzantısı standartlaşmamış ile üçüncü seviyeden çıkarılmıştır

Ana raporda yaygın platform desteği yok, izlemeye değer denmişti. Doğrusu daha kesindir: uzantı standartlaşmamış ile WebAuthn üçüncü seviyesinden çıkarılmıştır. Üç bağımsız doğrulama vardır.

1. 25 Ağustos 2026 tarihli W3C WebAuthn üçüncü seviye tavsiyesinde ilgili ifade yoktur.
2. 3 Eylül 2026 tarihli editör taslağında tanımlı uzantı listesi uygulama kimliği, uygulama kimliği dışlama, kimlik bilgisi özellikleri, sözde rastgele fonksiyon, büyük ikili veri ile uzak istemci verisidir; cihaza bağlı açık anahtar yoktur.
3. IANA WebAuthn kayıtlarındaki 16 kayıtlı uzantı arasında yoktur.

Kaldırma kararının gerekçesi birincil kaynaktan doğrulanamamıştır.

Bunun anlamı önemlidir: senkronize geçiş anahtarı mı cihaza bağlı mı sorusu WebAuthn katmanında çözülememektedir. İhtiyaç ortadan kalkmamış katman değiştirmiştir: tarayıcı oturumu için DBSC, OAuth token'ı için DPoP artı platform kanıtlaması, kurumsal WebAuthn için politikayla kapılı kurumsal kanıtlama kullanılmalıdır, ki sonuncusu genel web'de kullanılamamaktadır.

Bu, altın geçiş anahtarı riskini mimari olarak yönetmenin tek yolunun yüksek değerli hesaplarda donanım anahtarı olduğunu pekiştirmektedir.

### E.3 Yeni: standartlaşma enerjisinin gerçekte olduğu yer

`draft-ietf-oauth-attestation-based-client-auth-11`, 3 Eylül 2026, aktif bir çalışma grubu dokümanıdır; çobanı Hannes Tschofenig'tir. DPoP çevresindeki bireysel taslakların neredeyse hepsinin süresi dolmuşken tek canlı standartlaşma çalışması budur.

İstemci kanıtlaması ile kanıtlama sahiplik kanıtı başlıklarını tanımlamaktadır. DPoP birleşik modunda istemci örnek anahtarıyla DPoP anahtarı aynı asimetrik anahtar çiftidir; tek bir DPoP kanıtı hem kanıtlama hem gönderen kısıtlama görevi görmektedir. Donanım destekli anahtarları taşıyabilmekte ancak kanıt toplama kapsam dışındadır.

Doğru mimari desen şudur: donanım kanıtlaması kayıt anında bir kez anahtarın donanımda yaşadığını kanıtlamakta; sonra her istekte DPoP kanıtı o anahtarın kullanıldığını kanıtlamaktadır. Bu taslak tam olarak bu iki katmanı birleştirmektedir. Argus'un anahtar kayıt akışı buna göre şekillendirilmelidir.

Diğer aktif doküman `draft-ietf-oauth-security-topics-update-03`'tür, 5 Temmuz 2026. Bireysel ile aktif olanlar şunlardır: JPMorgan, Oracle ile Telefónica'nın 20 Haziran 2026 tarihli TLS oturumuna bağlı token'lar taslağı, ki Token Binding'in dışa aktarılan anahtar materyali fikrini TLS uzantısı olmadan diriltmekte ile token ve bağlantı başına tek kanıt kullanmaktadır; 12 Ağustos 2026 tarihli koşula bağlı anahtarlar taslağı; ile 1 Eylül 2026 tarihli özne anahtarı bağlama taslağı.

Süresi dolmuş ya da benimsenmemiş olanlar cihaz akışı, yenileme token'ı, JWT DPoP yetkisi ile uygulamadan bağımsız DPoP taslaklarıdır. RFC 9449'u güncelleyen resmî bir şey yoktur; DPoP stabildir.

### E.4 DPoP performansı, ölçülmüş sayılar ile sezgiye aykırı sonuç

Bağımsız ölçüm Apple M4, Node 24.20.0, tek çekirdek ile 5.000 yinelemeyle yapılmıştır.

| Algoritma | Doğrulama, sunucu | İmzalama, istemci |
|---|---|---|
| RS256, RSA 2048 | 10,3 mikrosaniye | 321,1 mikrosaniye |
| PS256, RSA 2048 | 17,4 mikrosaniye | 328,3 mikrosaniye |
| EdDSA, Ed25519 | 35,3 mikrosaniye | 14,8 mikrosaniye |
| ES256, P-256 | 49,0 mikrosaniye | 28,3 mikrosaniye |

Sezgiye aykırı ancak doğrudur: doğrulamada RSA 2048, ECDSA P-256'dan yaklaşık 4,7 kat hızlıdır. ECDSA'nın hızlı olduğu taraf imzalamadır ile imzalayan istemcidir. Sunucu yalnızca doğrulamaktadır.

Ancak gerçek DPoP maliyeti imza değildir. Anahtar her kanıtın başlığında geldiği için, yani anahtar kimliğiyle önbeleklenemediği için, çünkü anahtar istemci ile oturum başına değişmektedir, doğrulayıcı her istekte JWK içe aktarmak zorundadır.

```
ES256 JWK-import + verify : 71,5 µs   ← gerçek per-request maliyet
ES256 JWK import ALONE    : 23,5 µs   ← toplamın ~%33'ü
RFC 7638 jkt thumbprint   :  0,95 µs  ← tamamen ihmal edilebilir
```

Çıkarımlar şunlardır. Tek çekirdekte saniyede yaklaşık 14.000 DPoP doğrulaması, sekiz çekirdekte yaklaşık 110.000 doğrulama yapılabilmektedir; DPoP'un işlemci maliyeti çoğu dağıtım için bir sorun değildir. Parmak izi karşılaştırması hiçbir zaman bir darboğaz değildir, yaklaşık bir mikrosaniyedir. Rust'ta JWK içe aktarma maliyetini düşürmek için JWK ayrıştırıldıktan sonra parmak izi ile doğrulama anahtarı çifti kısa ömürlü bir önbellekte tutulmalıdır, çünkü aynı oturum ardışık istekler yapmaktadır; bu, maliyetin üçte birini silmektedir. RS256'ya geçmek doğrulamayı yaklaşık %40 düşürmekte ancak istemci imzalamayı 20 kat yavaşlatmaktadır, ki mobil ile pil için kötüdür. ES256 doğru varsayılan olmaya devam etmektedir.

Yayımlanmış bağımsız bir DPoP kıyaslaması yoktur; bu sayılar tek bir ölçümdür ile dile ve çalışma zamanına göre değişmektedir.

### E.5 Yeniden oynatma önbelleği, somut boyutlandırma

Duende'nin 2 Şubat 2026 tarihli JWT taşıyıcı uzantıları 1.0.0 sürümü bulunan en somut sayısal veridir.

Yaşam süresi formülü kanıt ömrü artı iki kat saat kaymasıdır. Varsayılan beş saniye ömür artı beş saniye kayma 15 saniye demektir. Tanımlayıcı özetlenerek saklanmaktadır; sabit 67 karakterlik bir anahtar artı bir boolean tutulmaktadır, ki önbellek taşırmaya karşı kritiktir. Kapasite saniyede 1.000 istek çarpı 15 saniye, yani yaklaşık 15.000 kayıttır. Varsayılanlar beş saniyelik kanıt ömrü, açık yeniden oynatma tespiti ile nonce tabanlı sona erme modudur. Dağıtık kurulum hibrit önbellek ile Redis üzerinden yapılmaktadır.

Bu, DPoP yeniden oynatma önbelleği ölçeklenmez korkusuna karşı iyi bir gerçeklik kontrolüdür. Saniyede 10.000 istekte bile yaklaşık 150.000 kayıt çarpı yaklaşık 80 bayt, yani yaklaşık 12 mebibayt eder. Darboğaz boyut değil dağıtık senkronizasyon gecikmesidir; Curity'nin ifadesiyle bir önbellek kolayca bir darboğaz hâline gelebilmektedir.

Nonce stratejisi, dağıtım karşılaştırması, tasarım kararının kalbidir.

| Dağıtım | Nonce | Rotasyon | Sonuç |
|---|---|---|---|
| Okta | Zorunludur | 24 saat ömür artı üç gün ek süre | Gidiş dönüş maliyeti pratikte sıfırdır |
| ATProto ile Bluesky | Tüm istemci tipleri için zorunludur | En fazla beş dakika artı bayat nonce toleransı | Yüksek tazelik ile yumuşatılmış yarış koşulları |
| Auth0 | Yalnızca açık istemcide | Belirtilmemiştir | Gizli istemcide gidiş dönüş yoktur |
| Duende | İsteğe bağlıdır | Yapılandırılabilir | Varsayılan veriliş zamanı artı beş saniyedir |
| Keycloak | Dokümante edilmemiştir | — | — |

Bluesky ile ATProto, DPoP'un en agresif büyük dağıtımıdır ile kararları kopyalanmaya değerdir. DPoP tüm istemci tipleri için, yetkilendirme ile kaynak sunucu isteklerinde zorunludur. Sunucu nonce'ları zorunludur ile en fazla beş dakika ömürlüdür. Sunucular tüm istemci oturumlarında aynı nonce'ı kullanabilmektedir; yani nonce üretimi durumsuz ile ucuzdur. Sunucular, uçuşta birden çok eşzamanlı isteği olan istemciler için rotasyonu yumuşatmak amacıyla yakın zamanda bayatlamış nonce'ları kabul etmelidir; yani kayan bir pencere kullanılmaktadır. İstemci nonce başlığı eksikse yanıtı reddetmelidir, harf büyüklüğüne duyarsız biçimde. ES256 zorunlu tabandır, anlık istek nesnesi zorunludur ile PKCE zorunludur. Token ömürleri erişim için en fazla 30 dakika, yenileme için açık istemcide iki hafta ile gizli istemcide 180 gündür.

Argus için öneri Okta modeli artı ATProto'nun bayat nonce toleransıdır. Yani uzun ömürlü, saatler mertebesinde, tüm oturumlarda paylaşılan, durumsuz üretilen bir nonce; kayan pencerede eski nonce kabulü; ile her 200 yanıtında öngörülü nonce verilmesi. Bu birleşim hem gidiş dönüş maliyetini sıfırlamakta hem saat kayması sorununu tamamen ortadan kaldırmaktadır.

Satıcı gerçeği dikkat gerektirmektedir: Auth0 dokümantasyonu açıkça tüm Auth0 yazılım geliştirme kitlerinin kutudan çıkar çıkmaz yeniden oynatma korumasını zorlamadığını itiraf etmektedir. Okta da yeniden oynatma tespitini kaynak sunucuya devretmektedir. Yani DPoP kullanıyoruz demek yeniden oynatma korumasının var olduğu anlamına gelmemektedir; kaynak sunucu tarafını siz yazmalısınız.

### E.6 mTLS, dağıtımın gerçek acıları

Uç nokta takma adlarının neden zorunlu olduğu, ki ana raporda eksikti, şudur: TLS'te istemci sertifikası isteği el sıkışma seviyesinde ile ana bilgisayar bazında yapılmaktadır. Aynı ana bilgisayarda hem mTLS hem normal istemci varsa sunucu ya herkesten sertifika istemekte, ki tarayıcıda sertifika seçim penceresi açılmakta ya da bağlantı kırılmaktadır, ya da kimseden istememektedir. Çözüm mTLS'i ayrı bir ana bilgisayara ya da porta taşımak ile bunu uç nokta takma adlarıyla ilan etmektir.

HTTP/2 bunu zorunlu kılmaktadır: TLS yeniden anlaşması HTTP/2'de yasaktır, yani RFC 9113. Önce anonim bağlan, gerekince sertifika iste modeli çalışmamaktadır; sertifika baştan istenmelidir.

mTLS dağıtımlarındaki en ciddi güvenlik hatası şudur: TLS sonlandıran vekil sertifikayı bir başlıkta iletmektedir. Bu başlıklar dış dünyadan taklit edilebilmektedir. Vekil bunları gelen isteklerden mutlaka sıyırmalıdır. Yapılmazsa mTLS bağlaması tamamen atlatılmaktadır. Ayrıca format vekile özgüdür, yani Envoy adres kodlu PEM kullanmakta, nginx ile HAProxy farklı davranmaktadır; ayrıştırma mantığınız vekile bağımlı hâle gelmektedir.

TLS istemci kimlik doğrulamasının tam olarak biri kuralı şudur: istemci konu ayırt edici adı, alan adı, adres, IP ile e-posta alternatif ad parametrelerinden tam olarak birini kullanmak zorundadır. Birden fazlasını kaydetmek belirsizlik ile kimlik doğrulama atlatma riski yaratmaktadır.

Kaynak sunucu maliyeti karşılaştırması şudur: mTLS'te kaynak sunucu yalnızca TLS katmanından sertifikayı almakta, SHA-256 özetini hesaplamakta ile token'daki parmak iziyle karşılaştırmaktadır. İmza doğrulama, yeniden oynatma önbelleği, saat kayması ile nonce yoktur. DPoP'un yaklaşık 71 mikrosaniyesine karşı yaklaşık sıfırdır. mTLS'in en büyük operasyonel avantajı budur.

Sertifika rotasyonu konusunda RFC 8705'in 6.3 bölümü şunu söylemektedir: sertifika değişince erişim token'ları geçersiz olmaktadır. Ancak yenileme token'ı da aynı sertifikaya bağlıysa o da ölmekte ile tam yeniden yetkilendirme gerekmektedir. DPoP'un anahtar rotasyon sorununun birebir aynısıdır. Pratikte sertifika ömürleri token ömürlerinden çok uzun tutularak, yani bir ile iki yıl yapılarak, ertelenmektedir.

### E.7 FAPI 2.0: gönderen kısıtlama zorunludur, mekanizma serbesttir

FAPI 2.0 güvenlik profili 22 Şubat 2025'te nihai olmuştur. Stuttgart Üniversitesi tarafından formel güvenlik analizi yapılmıştır. İlk sertifikayı Authlete 11 Temmuz 2025'te almıştır.

| Gereksinim | Normatif ifade |
|---|---|
| Gönderen kısıtlama | Yetkilendirme sunucusu mTLS ya da DPoP'tan birini kullanmalıdır; mekanizma serbest, kendisi zorunludur |
| Anlık istek nesnesi | RFC 9126 desteklenmeli ile bu olmadan gönderilen yetkilendirme istekleri reddedilmelidir |
| PKCE | S256 yöntemiyle zorunludur |
| Veren parametresi | RFC 9207, karıştırma saldırısına karşıdır |
| Yenileme token'ı | Desteklenmeli ile rotasyonu yapılmalıdır |

Tarihsel bir not gerekmektedir: FAPI 1.0 gelişmiş profili mTLS ya da Token Binding demekteydi. Token Binding öldüğü için FAPI 2.0 onu DPoP ile değiştirmiştir. Bu tek başına, DPoP'un Token Binding'in bıraktığı boşluğu doldurduğunun en net kurumsal kanıtıdır.

Bir boşluk vardır: gönderen kısıtlama erişim token'ları için zorunludur ancak yenileme token'ları için açık bir gereksinim yoktur; FAPI 2.0 bunun yerine rotasyonu zorunlu kılmaktadır. DPoP yolu seçilirse RFC 9449 zaten açık istemci yenileme bağlamasını zorunlu kılmakta ile dolaylı olarak elde edilmektedir. mTLS yolu seçilirse RFC 8705 yalnızca önermektedir; bu kendiniz zorunlu hâle getirilmelidir.

### E.8 Token Binding'in ölümü, birincil kaynak

Chrome'un kaldırma niyeti bildirimi Nick Harper tarafından 1 Ağustos 2018'de blink-dev listesine gönderilmiştir. Tam alıntılar şunlardır.

> *"After weighing the security benefit of Token Binding against the engineering costs, maintenance costs, web compatibility risk, and adoption, it does not make sense to ship this feature."*

> *"less than 00.01% of HTTPS requests on Stable had Token Binding attempted."*

> *"for most features that we implement in Chrome, there are lots of third parties coming to us wanting to use the new features, which is something I've seen very little of with Token Binding."*

Harper ayrıca Chrome uzantı platformu ile geliştirici araçlarıyla uyumluluk riskini özellikle sorun olarak anmıştır; sebebi Token Binding'in TLS katmanında olması ile uzantıların ve geliştirici araçlarının gördüğü HTTP soyutlamasıyla uyuşmamasıdır.

Eski Edge bu özelliği yayımlamış ile tek tarayıcı olarak kalmıştır; Chromium'a geçince, yani 2020'de, destek kaybolmuştur. Firefox ile Safari hiç uygulamamıştır.

Bir not gerekmektedir: ara kutu ile TLS denetimi uyumsuzluğu gerekçesi Chrome'un kaldırma metninde açıkça bulunamamıştır; metin mühendislik maliyeti, uyumluluk riski ile benimsenme üzerine yoğunlaşmaktadır. Bu, genel kabul gören bir teknik değerlendirmedir, doğrudan bir alıntı değildir. Ana raporda daha kesin ifade edilmişti; burada düzeltilmektedir.

RFC durumu şudur: RFC 8471 hâlâ önerilen standart aşamasındadır, tarihî statüye taşınmamış ile geçersiz kılınmamıştır. Kâğıt üzerinde yaşamakta ancak uygulamada ölüdür.

### E.9 Donanım kanıtlaması, sunucu doğrulama listeleri

#### Apple uygulama kanıtlaması, Secure Enclave

Kayıt anındaki kanıtlama şöyle doğrulanmaktadır.

1. Sertifika zincirinden yaprak ile ara sertifikalar alınmalı ile Apple uygulama kanıtlama kökü ile doğrulanmalıdır.
2. İstemci veri özeti meydan okumanın SHA-256'sıdır ile kimlik doğrulayıcı verisinin sonuna eklenmelidir.
3. Birleşiğin SHA-256'sı nonce'ı vermektedir.
4. Yaprak sertifikanın `1.2.840.113635.100.8.2` nesne tanımlayıcılı uzantısındaki sekizli dizgi bu nonce ile eşleşmelidir; meydan okuma bağlaması buradadır.
5. Yaprak sertifika açık anahtarının sıkıştırılmamış nokta biçiminin SHA-256'sı anahtar tanımlayıcısıyla eşleşmelidir.
6. Uygulama kimliğinin SHA-256'sı, kimlik doğrulayıcı verisindeki bağlı taraf kimliği özetiyle eşleşmelidir.
7. Sayaç sıfır olmalıdır.
8. Kimlik damgası geliştirme ya da üretim değeriyle eşleşmelidir.
9. Kimlik bilgisi tanımlayıcısı anahtar tanımlayıcısıyla eşleşmelidir.
10. CBOR uzantılarında doğrulama kategorisi ile paket sürümü bulunmalıdır.

macOS'a özel bir adım vardır: dördüncü ile beşinci adım arasında erişim kontrol listesi ikili verisi `1.2.840.113635.100.8.6` nesne tanımlayıcısından alınmalı ile sabit bir base64 değerle karşılaştırılmalıdır.

Sonraki her istekteki doğrulama şöyledir: nonce, kimlik doğrulayıcı verisi ile istemci veri özetinin birleşiminin SHA-256'sıdır; imza saklanan açık anahtarla doğrulanmalı, bağlı taraf kimliği eşleşmeli, sayaç bir öncekinden büyük olmalı, ki bir klonlama tespitidir, gömülü meydan okuma eşleşmeli ile doğrulama kategorisi ve paket sürümü kontrol edilmelidir.

Saklama kuralları şunlardır: açık anahtar kullanıcıyla ile belirli bir cihazla ilişkilendirilmelidir; makbuz saklanmalıdır, çünkü sonradan Apple'dan sunucudan sunucuya risk metrikleri istemek için gereklidir; geliştirme ile üretim ayrılmalıdır; kullanıcı başına birden fazla çift olabilir; ile bir açık anahtar başka bir kullanıcıyla ilişkili olmamalıdır, ki bir yeniden oynatma önlemidir.

Sınırı şudur: uygulama kanıtlaması kullanıcıyı değil uygulama örneğini doğrulamaktadır ile kimlik doğrulamanın yerine geçmemektedir. Hız sınırı vardır; dolayısıyla bir kez kanıtlama, sonra doğrulama modeli kullanılmalıdır.

#### Android anahtar kanıtlaması, nesne tanımlayıcısı `1.3.6.1.4.1.11129.2.1.17`

```asn1
KeyDescription ::= SEQUENCE {
  attestationVersion INTEGER,           -- 1..6
  attestationSecurityLevel SecurityLevel,   -- Software(0)|TrustedEnvironment(1)|StrongBox(2)
  keyMintVersion INTEGER, keymasterVersion INTEGER,
  attestationChallenge OCTET STRING,    -- ← SUNUCU NONCE'U
  uniqueId OCTET STRING,
  softwareEnforced AuthorizationList, teeEnforced AuthorizationList }

RootOfTrust ::= SEQUENCE {
  verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
  verifiedBootState ENUMERATED { Verified(0), SelfSigned(1), Unverified(2), Failed(3) },
  verifiedBootHash OCTET STRING }   -- deprecated
```

Yetki listesi etiketleri amaç, algoritma, anahtar boyutu, özet, dolgu, eliptik eğri, RSA açık üssü, köken, geri alma direnci, güven kökü, işletim sistemi sürümü, yama seviyesi, CBOR biçimindeki kanıtlama uygulama kimliği ile oluşturma zamanıdır. Köken üretildi, içe aktarıldı ya da bilinmiyor değerlerini almaktadır.

Doğrulama sırası şudur: zincir doğrulanmalı, kök dinamik olarak alınmalı, iptal listesi kontrol edilmeli, yani seri numarasının küçük harf onaltılık gösterimiyle sorgulanmalı ile önbellek denetimi başlığına saygı gösterilmeli, altıncı sürüm ve üstünde sağlama bilgisi okunmalı, uzantı yaprağa en yakın ilk oluşumdan okunmalı ile başkasına güvenilmemeli, kanıtlama meydan okuması nonce ile eşleşmeli, güvenlik seviyesi güvenilir ortam ya da StrongBox olmalı ile yazılım reddedilmeli, doğrulanmış önyükleme durumu ile cihaz kilitli bayrağı yalnızca güvenilir ortamda zorlanan listeden okunmalı, köken üretildi olmalı ile içe aktarılmış olmamalı, kanıtlama uygulama kimliğiyle paket adı ile imza özeti kontrol edilmeli ile uzaktan sağlanmışsa sona erme tarihi kontrol edilmelidir.

Android, bu dört mekanizma arasında sunucunun en zengin bilgiyi doğrulayabildiği olandır: anahtarın nerede yaşadığından önyükleyicinin kilitli olup olmadığına kadar. Doğrulama asla cihazda yapılmamalıdır.

#### TPM 2.0, WebAuthn kanıtlama formatı, tek gerçek standart

Biçim sürüm, algoritma, kanıtlama kimlik anahtarı sertifika zinciri, imza, kanıtlama bilgisi ile açık anahtar alanından oluşmaktadır.

1. Açık anahtar alanındaki anahtar, kimlik bilgisi açık anahtarıyla eşleşmelidir.
2. Kanıtlama bilgisi ayrıştırılmalıdır.
3. Sihirli değer TPM tarafından üretildi sabitiyle eşleşmelidir; TPM bu sabitle başlayan dışarıdan gelen veriyi imzalamayı reddetmektedir.
4. Tip sertifikalama kanıtlaması olmalıdır.
5. Ek veri, kimlik doğrulayıcı verisi ile istemci veri özetinin birleşiminin özeti olmalıdır; meydan okuma bağlaması buradadır.
6. Kanıtlanan ad, açık anahtar alanının ad algoritmasıyla hesaplanan adıyla eşleşmelidir; bu, kanıtlama bilgisinin gerçekten o anahtarı sertifikaladığını göstermektedir.
7. İmza, zincirin ilk sertifikasıyla doğrulanmalı ile zincir doğrulanmalıdır.

Kanıtlama kimlik anahtarı sertifika gereksinimleri şunlardır: X.509 üçüncü sürüm olmalı, konu alanı boş olmalı, konu alternatif adında üretici, model ile sürüm nesne tanımlayıcıları bulunmalı, genişletilmiş anahtar kullanımı kanıtlama kimlik anahtarı sertifikası olmalı ile temel kısıtlarda sertifika otoritesi bayrağı kapalı olmalıdır.

Onay anahtarıyla kanıtlama kimlik anahtarı ayrımı şudur: onay anahtarı üretimde gömülmekte, değiştirilememekte ancak gizlilik nedeniyle doğrudan imzalamamaktadır, çünkü küresel izlenebilirlik doğurmaktadır. Kanıtlama kimlik anahtarları onay anahtarına bağlı olarak türetilmektedir. Kimlik bilgisi etkinleştirme komutu, bir kanıtlama kimlik anahtarının gerçekten belirli onay anahtarına sahip modülde yaşadığını kanıtlamaktadır: doğrulayıcı onay açık anahtarıyla şifrelenmiş bir sır göndermekte ile yalnızca o modül çözebilmektedir. Bir anahtarı bir cihaza ilk bağlarken gereklidir.

#### Microsoft sertifika servisleri modül anahtarı kanıtlaması, üç güven modeli

| Nesne tanımlayıcısı | Model | Sertifika otoritesi ne doğrulamaktadır | Güvence |
|---|---|---|---|
| `1.3.6.1.4.1.311.21.30` | Onay anahtarı | Onay açık anahtarının yöneticinin listesinde bulunması; dosya adı anahtarın SHA-2 özetidir | Yüksektir |
| `1.3.6.1.4.1.311.21.31` | Onay sertifikası | Sertifika zincirinin ilgili depolara ulaşması | Ortadır |
| `1.3.6.1.4.1.311.21.32` | Kullanıcı kimlik bilgileri | Hiçbir şey; yalnızca etki alanı kimlik bilgileridir | Düşüktür |

Sınırları şunlardır: yalnızca RSA desteklenmektedir; Microsoft platform kripto sağlayıcısı zorunludur; bağımsız sertifika otoritesinde çalışmamaktadır; onay sertifikası modeli o üreticinin tüm modüllerine güvenmek demektir; ile onay anahtarı modeli en güvenlidir ancak her cihazı elle listelemek gerekmektedir, ki ölçeklenmemektedir.

Bu mekanizmanın var olma sebebi dokümanın kendi ifadesidir: yerel yönetici kimlik bilgileriyle bir yazılım anahtar depolama sağlayıcısını modül sağlayıcısı gibi göstermek kolaydır. Yani kanıtlama olmadan bu anahtar modüldedir iddiası hiçbir şey ifade etmemektedir.

Windows Hello ile WebAuthn tarafında bir uyarı gerekmektedir: pratikte tarayıcılar çoğu zaman kanıtlama yok yanıtı dönmektedir, çünkü bağlı tarafın varsayılanı budur. Anlamlı bir kanıtlama için doğrudan ya da kurumsal kanıtlama istenmelidir; kurumsal kanıtlama tarayıcı ile işletim sistemi politikasıyla kapılıdır ile yalnızca izinli kurumsal bağlı taraf kimlikleri için geçerlidir. Ayrıca geçiş anahtarı senkronizasyonu devreye girince anahtar cihaza bağlı olmayabilmektedir; cihaza bağlı açık anahtar probleminin ta kendisidir.

---

### E.10 Ana rapordaki maddelerde değişen bir şey var mıdır

| Madde | Durum |
|---|---|
| Sınıflandırma tablosu, birinci ile beşinci faz | Değişmemiştir |
| DBSC sunucu gerçekleme adımları | Değişmemiştir; başlık isimleri ile akış doğrulanmıştır |
| SSF ile CAEP gerçekleme adımları | Değişmemiştir |
| Token Binding ölüm gerekçesi | Nüanslanmıştır; ara kutu gerekçesi Chrome'un metninde yoktur ile genel bir değerlendirmedir |
| Cihaza bağlı açık anahtar | Düzeltilmiştir; yaygın destek yok değil, standartlaşmamış ile üçüncü seviyeden çıkarılmıştır |
| ES256 ile RS256 | Eklenmiştir; doğrulamada RS256 daha hızlıdır ancak ES256 doğru varsayılandır |
| Android kanıtlaması | Acil bir madde eklenmiştir; kök rotasyonu ile uzaktan anahtar sağlama nedeniyle dinamik güven deposu şarttır |
| Standartlaşma yol haritası | Eklenmiştir; kanıtlama tabanlı istemci kimlik doğrulaması taslağı tek aktif çalışma grubu dokümanıdır ile DPoP birleşik modunu getirmektedir |

Birinci faza eklenecek tek somut madde şudur: DPoP nonce tasarımı Okta modeliyle, yani uzun ömür artı ek süreyle, ATProto'nun bayat nonce toleransıyla ile tüm oturumlarda paylaşılan durumsuz bir nonce ile kurgulanmalıdır. Bu üçlü, veriliş zamanı ile saat kayması sorununu tamamen ortadan kaldırmakta ile nonce gidiş dönüş maliyetini pratikte sıfırlamaktadır.

Ek olarak doğrulanamayanlar şunlardır: Keycloak'ın yeniden oynatma önbelleği iç yapısı ile artı eksi 15 saniyelik kayma değeri; Auth0'ın genel kullanım tarihi ile veriliş zamanı penceresi; API ağ geçitlerinin, yani Kong, Envoy ile Apigee'nin 2026 DPoP desteği; FAPI 2.0 mesaj imzalamanın nihai statüsü; cihaza bağlı açık anahtarın kaldırılma gerekçesi; Microsoft kanıtlama sertifika otoritesi köklerinin dağıtım kanalı; Apple uygulama kanıtlaması hız sınırı sayıları; ile WebAuthn üçüncü seviyesinin 25 Ağustos 2026 tarihli tavsiye tarihi, ki tek kaynağa dayanmaktadır.

---

# Kısım VI — Ürün akışları

Kullanıcının ile yöneticinin gördüğü akışlar: hesap yaşam döngüsü, giriş deneyimi ile yönetim API'si.
