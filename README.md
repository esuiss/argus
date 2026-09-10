# Argus

Rust ile sıfırdan yazılan genel amaçlı Identity Provider. OAuth 2.1 ve OpenID
Connect çekirdeği üzerine çok kiracılık, MCP ve ajan kimliği, kurumsal
protokoller ve OpenID Federation.

Tek kaynak doküman `ARGUS.md`. Buradaki her karar oraya bir bölüm numarasıyla
bağlıdır; çelişki varsa `ARGUS.md` kazanır.

---

## Çalıştırma

Üç adım: veritabanını hazırla, rolleri aç, sunucuyu başlat. Uygulama başlangıçta
şemayı yalnızca **doğrular**, göç uygulamaz (§1 #26).

### 1. Veritabanı

PostgreSQL 18 gerekir. Migration'lar dosya adı sırasıyla, tek tek uygulanır:

```bash
for f in crates/argus-store/migrations/*.sql; do
  psql -v ON_ERROR_STOP=1 -d argus_db -f "$f"
done
```

Her migration kendini doğrular: sonunda RLS'siz, `FORCE`'suz veya superuser'a
ait bir tablo kalırsa `RAISE EXCEPTION` ile durur.

### 2. Roller

Migration'lar üç rol oluşturur ve hiçbiri giriş yapamaz. Giriş rollerini
operatör açar, çünkü parolalar şemaya ait değildir.

| Rol | Ne görür | Kim üye olmalı |
|---|---|---|
| `argus_owner` | Tabloların sahibi. `NOSUPERUSER NOBYPASSRLS`. | Kimse. |
| `argus_app` | Kiracı trafiğini taşıyan her tablo, RLS politikası altında. | Uygulama giriş rolü. |
| `argus_platform` | **Yalnızca** `tenants`. Migration 0022 bunu kendi sonunda doğrular. | Kontrol düzlemi giriş rolü. |

```sql
CREATE ROLE argus_app_login   LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS IN ROLE argus_app;
CREATE ROLE argus_plane_login LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS IN ROLE argus_platform;
```

İki ayrı giriş olmasının sebebi §24 #21: kiracı trafiği taşıyan bir süreç,
kendi kodu istese bile kiracı kaydına ulaşamamalı. Aynı role hem uygulama hem
kontrol düzlemi üyeliği verirsen bu sınır süse dönüşür.

### 3. Kiracılar

Argus çok kiracılıdır ve bir isteğin hangi kiracıya ait olduğu **Host
başlığından** çözülür (§1 #8: issuer stratejisi subdomain birincil).

```sql
SET ROLE argus_platform;
INSERT INTO tenants (slug, issuer_host) VALUES ('acme', 'acme.example.com');
```

Kayıt defteri başlangıçta bu tablodan kurulur. Tanınmayan bir host **404
alır** — bilinen bir kiracıya düşmek, A'nın verisini B'nin adresinde sunmak
olurdu.

`ARGUS_PLATFORM_DATABASE_URL` verilmezse dağıtım tek kiracılıdır: kayıt defteri
`ARGUS_ISSUER`'dan tek girişle kurulur.

**Kiracı başına imzalama anahtarı (§1 #4).** Anahtarlar
`$ARGUS_SIGNING_KEY_DIR/<slug>/` altında aranır. Orada yoksa dağıtım anahtarına
düşülür ve bu **uyarılır**: paylaşımlı anahtar, bir kiracının token'ının başka
bir kiracının anahtarıyla doğrulanabilmesi demektir.

```
/etc/argus/keys/
├── k1.pkcs8          # paylaşımlı, yalnızca yedek
├── acme/k1.pkcs8     # acme'nin kendi anahtarı
└── globex/k1.pkcs8
```

Her kiracının WebAuthn relying party kimliği de kendi host'udur (§1 #12).

### 4. Başlatma

```bash
ARGUS_ENV=production \
ARGUS_ISSUER=https://as.example.com \
ARGUS_BIND=0.0.0.0:443 \
ARGUS_ADMIN_BIND=127.0.0.1:8443 \
ARGUS_DATABASE_URL=postgres://argus_app_login@db/argus_db \
ARGUS_TLS_CERT=/etc/argus/tls.pem ARGUS_TLS_KEY=/etc/argus/tls.key \
ARGUS_SIGNING_KEY_DIR=/etc/argus/keys ARGUS_ACTIVE_KID=k1 \
ARGUS_BLIND_INDEX_KEY=$(openssl rand -hex 32) \
  argus
```

`build` ve `start` diye iki adım yok (§9.5 #1). Dev ile üretim arasındaki tek
fark konfigürasyon değerleridir, ayrı bir kod yolu değil.

---

## Üretimde başlamayı reddettiği durumlar

§9.5 #2: güvensiz konfigürasyonda uyarmak yerine reddet. `ARGUS_ENV=production`
iken aşağıdakilerden biri eksikse süreç çıkış kodu 1 ile durur.

| Eksik olan | Neden reddediliyor |
|---|---|
| `ARGUS_ISSUER` | Tahmin edilen bir issuer, URL'i yönlendirebilen saldırgana kendi seçtiği issuer'dan token verdirir. |
| `ARGUS_ADMIN_BIND` | Yönetim yüzeyi genel yüzeyle aynı adresi paylaşmaz (§24 #34). |
| `ARGUS_TLS_CERT` / `ARGUS_TLS_KEY` | Düz metin bir IdP yoktur. |
| `ARGUS_BLIND_INDEX_KEY` | Kalıcı olmayan anahtarla kör indeks her yeniden başlatmada değişir. |
| `ARGUS_LDAP_CERT` / `ARGUS_LDAP_KEY` (LDAP açıksa) | TLS'siz LDAP dinleyicisi her parola bind'ını reddeder. |

Ayrıca `ARGUS_CIMD_ALLOW_LOOPBACK` ve `ARGUS_FEDERATION_ALLOW_PRIVATE`
üretimde yok sayılmaz, **reddedilir**: ikisi de SSRF korumasını gevşetir.

---

## Konfigürasyon

### Çekirdek

| Değişken | Varsayılan | Ne yapar |
|---|---|---|
| `ARGUS_ENV` | `dev` | `production` ise yukarıdaki reddetmeler devreye girer. |
| `ARGUS_ISSUER` | `http://localhost:8080` | Tek kiracılı dağıtımın issuer'ı. Çok kiracılıda her kiracının issuer'ı `tenants.issuer_host`'tan gelir. |
| `ARGUS_BIND` | `127.0.0.1:8080` | Genel dinleyici. |
| `ARGUS_ADMIN_BIND` | yok | Verilirse yönetim API'si buraya taşınır ve genel dinleyicide **görünmez**. |
| `ARGUS_DATABASE_URL` | yok | Verilmezse bellek içi depo ve DevAuthenticator. |
| `ARGUS_PLATFORM_DATABASE_URL` | yok | Kontrol düzlemi girişi. Yoksa `/admin/platform` route'ları hiç mount edilmez **ve dağıtım tek kiracılı olur** (kiracı tablosu okunamaz). |
| `ARGUS_TLS_CERT`, `ARGUS_TLS_KEY` | yok | İkisi birlikte verilir. |

### Anahtarlar

| Değişken | Ne yapar |
|---|---|
| `ARGUS_SIGNING_KEY_DIR` | `*.pkcs8` ES256 anahtarları. Kiracı başına alt dizin aranır (§1 #4). Yoksa geçici bir anahtar üretilir ve uyarı basılır. |
| `ARGUS_ACTIVE_KID` | Yeni imzaların hangi anahtarla atılacağı. Diğerleri doğrulama için yayında kalır. |
| `ARGUS_RSA_KEY_DIR` | RS256 anahtarları. Yalnızca RS256 isteyen federasyon karşı tarafları için. |
| `ARGUS_BLIND_INDEX_KEY` | 32 bayt hex. Şifreli alanlarda eşitlik araması için. |
| `ARGUS_VAULT_KEY` | 32 bayt base64. Kimlik bilgisi kasasının AES-256-GCM anahtarı. |
| `ARGUS_AGENT_CARD_KEY_DIR` | A2A Agent Card imzalama anahtarı. Yoksa `/agent-cards/*` mount edilmez. |

### Kurumsal ve federasyon

| Değişken | Ne yapar |
|---|---|
| `ARGUS_SAML_ENTITY_ID`, `ARGUS_SAML_CERT`, `ARGUS_SAML_KEY`, `ARGUS_SAML_SP_DIR` | SAML IdP. Hepsi birlikte gerekir. |
| `ARGUS_LDAP_BIND`, `ARGUS_LDAP_BASE_DN`, `ARGUS_LDAP_CERT`, `ARGUS_LDAP_KEY` | LDAP ağ geçidi. Ayrı bir dinleyici. |
| `ARGUS_SCIM_EVENT_AUDIENCE` | RFC 9967 güvenlik olaylarının `aud` değeri. |
| `ARGUS_FEDERATION_ENTITY_ID` | **https** olmalı. Ayrıştırılamazsa federasyon uçları mount edilmez ve sebep basılır. |
| `ARGUS_FEDERATION_KEY_DIR` | Entity statement imzalama anahtarları. |
| `ARGUS_FEDERATION_ROLE` | `trust_anchor` veya boş (leaf). |
| `ARGUS_FEDERATION_TRUST_ANCHORS` | Virgülle ayrılmış güven çıpaları. |
| `ARGUS_WEBAUTHN_RP_ID` | Tek kiracılı dağıtımda relying party kimliği. Çok kiracılıda her kiracı kendi host'unu alır (§1 #12). Verilmezse WebAuthn uçları 501 döner. |
| `ARGUS_FAPI_PROFILE` | `1` ise: yetkilendirme istekleri PAR'dan geçmek zorunda, token'lar gönderen-bağlı olmak zorunda, public client reddedilir. |

### Yalnızca geliştirme

| Değişken | Ne yapar |
|---|---|
| `ARGUS_CIMD_ALLOW_LOOPBACK` | CIMD dokümanları loopback'ten çekilebilir. Üretimde reddedilir. |
| `ARGUS_FEDERATION_ALLOW_PRIVATE` | Federasyon eşleri özel adres aralıklarından çekilebilir. Üretimde reddedilir. |
| `ARGUS_EXTRA_CA` | Ek kök sertifika. Yerel topolojide kendi imzalı zincir için. |

---

## Yönetim API'si

`/admin/api` kiracı yüzeyi, `/admin/platform` kontrol düzlemi. İkisi ayrı
audience taşır; birinin token'ı diğerinde geçmez (§24 #19).

Route'lar bir izin manifestosundan **üretilir** — izni bildirilmemiş bir
route mount edilemez (§24 #10). Çalışan sunucunun kendi OpenAPI dokümanı
`/admin/api/openapi/v1` adresinde, aynı manifestodan üretilir.

Yetkilendirme ilişki tabanlıdır (§20). Bir yöneticiyi başlatmak için tek bir
tuple yeter:

```
tenant:<tenant_id>#admin@user:<subject>
```

Bundan sonrası API üzerinden delege edilebilir. Hiçbir aktör kendi efektif izin
kümesinin üstünde bir izin veremez; bu kontrol tek bir merkezî fonksiyondan
geçer (§24 #13).

---

## Doğrulama

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
ARGUS_TEST_DATABASE_URL=postgres://argus_test:argus@localhost:55432/argus_db \
ARGUS_TEST_PLATFORM_DATABASE_URL=postgres://argus_platform_test:argus@localhost:55432/argus_db \
  cargo nextest run --workspace --all-features --profile ci
```

`ARGUS_TEST_DATABASE_URL` verilmezse veritabanına dokunan testler sessizce
atlanır. Test rolü `NOBYPASSRLS` olmalı, yoksa RLS testleri yanlış sebeple
geçer.

---

## Üretim yapısı için bir not

`bergshamra`'nın varsayılan arka ucu `rsa` crate'ini getiriyor ve o crate
RUSTSEC-2023-0071 (Marvin) yüzünden `deny.toml`'da yasaklı. Argus hiç RSA şifre
çözme yapmadığı için maruziyet yok, ama Linux'ta crate tamamen düşürülebilir:

```toml
bergshamra = { version = "0.9", default-features = false, features = ["aws-lc"] }
```

Bu bir cargo özelliği olarak sunulmuyor, çünkü o arka uç yalnızca Linux
x86_64/aarch64'te derleniyor ve `--all-features` kapısını kırardı.

---

## Lisans

AGPL-3.0. GPL/AGPL bağımlılık kabul edilmez; `cargo deny check` bunu zorlar.
