//! Authorization code akışı — durum makinesi.
//!
//! Bu modül Faz 1'in en riskli parçasıdır. §5'in ifadesiyle: *"OAuth2/OIDC AS'in
//! sıfırdan yazılması — hataların doğrudan kimlik doğrulama atlatması demek."*
//!
//! # Tasarım: I/O çağırmaz, I/O İSTER
//!
//! [ARGUS.md §3 §1176] bu bileşen için tasarımı açıkça veriyor: *"girdi bir
//! `Request` struct'ı, çıktı bir `Decision` enum'u. I/O çağıran değil, I/O isteyen
//! bir tasarım."* Sebebi Kani ile bounded model checking: karar mantığı yan
//! etkisizse durum uzayı sonlu ve taranabilir olur.
//!
//! Pratikte bu şu demek: [`redeem`] veritabanına yazmaz, token üretmez, log
//! basmaz. Ne **yapılması gerektiğini** [`Effect`] listesi olarak döndürür ve
//! çağıran uygular. Bu, güvenlik açısından kritik bir özelliği de beraberinde
//! getirir: **kod tekrarı tespit edildiğinde yapılması gereken iptal işlemi
//! unutulamaz**, çünkü kararın kendisinin bir parçasıdır.
//!
//! # Uygulanan kurallar
//!
//! | Kural | Kaynak |
//! |---|---|
//! | Kod **tek kullanımlıktır** | RFC 6749 §4.1.2, RFC 9700 §4.1.1 |
//! | Tekrar kullanımda o koddan türeyen **tüm token'lar iptal edilir** | RFC 9700 §4.1.1 |
//! | `redirect_uri` token isteğinde de doğrulanır | RFC 6749 §4.1.3 |
//! | `client_id` eşleşmeli | RFC 6749 §4.1.3 |
//! | PKCE zorunlu | OAuth 2.1, RFC 9700 |
//! | Kod kısa ömürlüdür | RFC 6749 §4.1.2 ("maximum of 10 minutes") |

use crate::effect::Effect;
use crate::error::PkceError;
use crate::id::{ClientId, TenantId, UserId};
use crate::pkce::{CodeChallenge, Sha256};
use crate::redirect_uri::RedirectUri;
use crate::time::{Duration, Timestamp};

/// RFC 6749 §4.1.2'nin üst sınırı. Argus varsayılanı çok daha kısadır; bu yalnızca
/// "hiçbir koşulda aşılamaz" sınırıdır ve [`AuthorizationCode::new`] onu zorlar.
pub const MAX_CODE_LIFETIME: Duration = Duration::from_seconds(600);

/// Argus'un varsayılan kod ömrü.
///
/// RFC 9700, kodun ömrünü "olabildiğince kısa" tutmayı öneriyor. 60 saniye,
/// tarayıcı yönlendirmesi + token isteği için fazlasıyla yeterlidir ve çalınmış
/// bir kodun kullanılabileceği pencereyi daraltır.
pub const DEFAULT_CODE_LIFETIME: Duration = Duration::from_seconds(60);

/// Kodun yaşam döngüsündeki durumu.
///
/// Ayrı bir tip olması bilinçli: `bool used` alanı, "kullanıldı ama ne zaman"
/// sorusunu cevaplayamaz ve denetim kaydı için o zaman gereklidir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeState {
    /// Verildi, henüz kullanılmadı.
    Issued,
    /// Bir token isteğiyle tüketildi.
    Redeemed {
        /// Tüketilme anı.
        at: Timestamp,
    },
}

/// Depodan okunan kaydın alanları.
///
/// `argus-store` satırı bu yapıya çevirir, `argus-core` da onu
/// [`AuthorizationCode::from_stored`] ile içeri alır.
#[derive(Debug, Clone)]
pub struct StoredCode {
    /// Kiracı.
    pub tenant: TenantId,
    /// Kodun verildiği istemci.
    pub client: ClientId,
    /// Özne.
    pub subject: UserId,
    /// Yetkilendirme isteğindeki `redirect_uri`.
    pub redirect_uri: RedirectUri,
    /// PKCE challenge.
    pub challenge: CodeChallenge,
    /// Verilme anı.
    pub issued_at: Timestamp,
    /// Sona erme anı.
    pub expires_at: Timestamp,
    /// Mevcut durum.
    pub state: CodeState,
}

/// Saklanan authorization code kaydı.
///
/// Kodun **kendisi** (rastgele dizge) burada yok: o, `argus-store` tarafında
/// hash'lenerek tutulur ve bu tip zaten çözülmüş kaydı temsil eder. Böylece kod
/// değeri karar mantığından hiç geçmez, dolayısıyla log'a veya panik mesajına
/// düşemez.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    tenant: TenantId,
    client: ClientId,
    subject: UserId,
    redirect_uri: RedirectUri,
    challenge: CodeChallenge,
    issued_at: Timestamp,
    expires_at: Timestamp,
    state: CodeState,
}

/// Token endpoint'ine gelen `grant_type=authorization_code` isteği.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    /// İsteği yapan client — client authentication ile **zaten doğrulanmış** olmalı.
    pub client: ClientId,
    /// İstek gövdesindeki `redirect_uri`.
    pub redirect_uri: String,
    /// İstek gövdesindeki `code_verifier`.
    pub code_verifier: String,
    /// İsteğin geldiği kiracı (host'tan çözülmüş, gövdeden DEĞİL).
    pub tenant: TenantId,
}

/// Başarılı tüketimin sonucu.
///
/// Token'ın kendisi burada üretilmez — imzalama `argus-crypto`'nun işidir.
/// Bu tip yalnızca "kime, hangi kiracıda, hangi istemci için token verilecek"
/// sorusunun cevabıdır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Token'ın öznesi.
    pub subject: UserId,
    /// Token'ın verildiği istemci.
    pub client: ClientId,
    /// Kiracı.
    pub tenant: TenantId,
}

/// Token endpoint'inin istemciye döneceği hata.
///
/// **Hepsi `invalid_grant` altında toplanır.** Ayrım yalnızca denetim kaydı ve
/// operatör içindir: istemciye "PKCE tutmadı" ile "kod süresi doldu" arasındaki
/// farkı söylemek, saldırgana hangi adımda olduğunu bildirmektir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// Kodun süresi dolmuş.
    Expired,
    /// Kod başka bir istemciye verilmişti.
    ClientMismatch,
    /// Kod başka bir kiracıya aitti.
    TenantMismatch,
    /// `redirect_uri` yetkilendirme isteğindekiyle aynı değil.
    RedirectUriMismatch,
    /// PKCE doğrulaması başarısız.
    Pkce(PkceError),
    /// **Kod ikinci kez sunuldu.** Bu ayrı bir sınıftır: diğerleri "istek hatalı"
    /// derken bu "bir güvenlik olayı oldu" der ve iptal etkisini tetikler.
    Replayed {
        /// İlk tüketimin zamanı — denetim kaydı için.
        first_redeemed_at: Timestamp,
    },
}

impl DenialReason {
    /// İstemciye dönecek OAuth hata kodu.
    ///
    /// RFC 6749 §5.2: geçersiz, süresi dolmuş, iptal edilmiş, başka bir istemciye
    /// verilmiş veya `redirect_uri` uyuşmayan kodun tamamı `invalid_grant`'tır.
    #[must_use]
    pub const fn oauth_error_code(&self) -> &'static str {
        "invalid_grant"
    }
}

/// [`redeem`] sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Token verilebilir.
    Grant {
        /// Kime, hangi istemci için.
        grant: Grant,
        /// Uygulanacak yan etkiler.
        effects: Vec<Effect>,
    },
    /// Reddedildi.
    Deny {
        /// İç sebep — denetim kaydına yazılır, istemciye ayrıntısı verilmez.
        reason: DenialReason,
        /// Uygulanacak yan etkiler.
        effects: Vec<Effect>,
    },
}

impl AuthorizationCode {
    /// Yeni bir kod kaydı kurar.
    ///
    /// # Errors
    ///
    /// Ömür [`MAX_CODE_LIFETIME`]'ı aşarsa veya sıfır/negatifse
    /// [`CodeLifetimeError`] döner. Bu, konfigürasyon hatasının üretime
    /// sızmasını engeller: RFC 6749 §4.1.2 on dakikayı üst sınır olarak veriyor.
    pub fn new(
        tenant: TenantId,
        client: ClientId,
        subject: UserId,
        redirect_uri: RedirectUri,
        challenge: CodeChallenge,
        issued_at: Timestamp,
        lifetime: Duration,
    ) -> Result<Self, CodeLifetimeError> {
        if lifetime.as_seconds() <= 0 {
            return Err(CodeLifetimeError::NotPositive {
                seconds: lifetime.as_seconds(),
            });
        }
        if lifetime.as_seconds() > MAX_CODE_LIFETIME.as_seconds() {
            return Err(CodeLifetimeError::TooLong {
                seconds: lifetime.as_seconds(),
                max: MAX_CODE_LIFETIME.as_seconds(),
            });
        }

        Ok(Self {
            tenant,
            client,
            subject,
            redirect_uri,
            challenge,
            issued_at,
            expires_at: issued_at.saturating_add(lifetime),
            state: CodeState::Issued,
        })
    }

    /// Depodan okunmuş bir kaydı yeniden kurar (durumuyla birlikte).
    ///
    /// Alanlar tek tek değil [`StoredCode`] ile verilir: sekiz konumsal argüman,
    /// aynı tipteki iki kimliğin (`tenant`/`subject`) sessizce yer değiştirmesine
    /// açık bir imzadır.
    #[must_use]
    pub fn from_stored(stored: StoredCode) -> Self {
        Self {
            tenant: stored.tenant,
            client: stored.client,
            subject: stored.subject,
            redirect_uri: stored.redirect_uri,
            challenge: stored.challenge,
            issued_at: stored.issued_at,
            expires_at: stored.expires_at,
            state: stored.state,
        }
    }

    /// Kodun sona erme anı.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Verilme anı.
    #[must_use]
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Mevcut durum.
    #[must_use]
    pub const fn state(&self) -> CodeState {
        self.state
    }
}

/// Kod ömrü konfigürasyon hatası.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CodeLifetimeError {
    /// Ömür sıfır veya negatif.
    #[error("authorization code lifetime must be positive, got {seconds}s")]
    NotPositive {
        /// Verilen değer.
        seconds: i64,
    },
    /// Ömür RFC 6749 §4.1.2'nin üst sınırını aşıyor.
    #[error("authorization code lifetime {seconds}s exceeds the {max}s maximum (RFC 6749 §4.1.2)")]
    TooLong {
        /// Verilen değer.
        seconds: i64,
        /// İzin verilen azami.
        max: i64,
    },
}

/// Bir authorization code'u token isteğiyle tüketmeye çalışır.
///
/// Saf fonksiyon: hiçbir şey yazmaz, saate bakmaz, token üretmez. Ne yapılması
/// gerektiğini [`Decision`] içinde bildirir.
///
/// # Kontrol sırası ve neden bu sırada
///
/// 1. **Tekrar kullanım** en başta. Süresi dolmuş bir kodun tekrar sunulması da
///    bir güvenlik olayıdır; "zaten süresi dolmuştu" diyerek iptali atlamak,
///    saldırganın kodu bekletmesini ödüllendirirdi.
/// 2. **Kiracı** — yanlış kiracıdan gelen istek hiçbir şey öğrenmemeli.
/// 3. **İstemci**, sonra **`redirect_uri`**, sonra **süre**, en son **PKCE**.
///    PKCE en pahalı kontrol (hash) olduğu için sona bırakıldı; ucuz kontroller
///    zaten reddedecekse hash hesaplamaya gerek yok.
#[must_use]
pub fn redeem(
    code: &AuthorizationCode,
    request: &TokenRequest,
    now: Timestamp,
    hasher: &impl Sha256,
) -> Decision {
    // 1. Tekrar kullanım — her şeyden önce.
    if let CodeState::Redeemed { at } = code.state {
        return Decision::Deny {
            reason: DenialReason::Replayed {
                first_redeemed_at: at,
            },
            // RFC 9700 §4.1.1: koddan türeyen her şey iptal edilir.
            effects: vec![
                Effect::RevokeTokensIssuedForCode,
                Effect::RecordAudit("oauth.authorization_code.replayed"),
            ],
        };
    }

    let deny = |reason: DenialReason, audit: &'static str| Decision::Deny {
        reason,
        // Tekrar kullanım DIŞINDAKİ her ret de kodu tüketir: başarısız bir deneme
        // kodu canlı bırakırsa saldırgan farklı parametrelerle tekrar deneyebilir.
        effects: vec![Effect::ConsumeCode, Effect::RecordAudit(audit)],
    };

    if code.tenant != request.tenant {
        return deny(
            DenialReason::TenantMismatch,
            "oauth.authorization_code.tenant_mismatch",
        );
    }

    if code.client != request.client {
        return deny(
            DenialReason::ClientMismatch,
            "oauth.authorization_code.client_mismatch",
        );
    }

    // RFC 6749 §4.1.3: `redirect_uri` token isteğinde de doğrulanır. Yetkilendirme
    // isteğinde hangi URI kullanıldıysa aynısı sunulmalı — §1 #24'ün exact match'i
    // ve loopback istisnası burada da geçerlidir.
    if code
        .redirect_uri
        .match_presented(&request.redirect_uri)
        .is_none()
    {
        return deny(
            DenialReason::RedirectUriMismatch,
            "oauth.authorization_code.redirect_uri_mismatch",
        );
    }

    if now.is_after(code.expires_at) {
        return deny(DenialReason::Expired, "oauth.authorization_code.expired");
    }

    if let Err(e) = code.challenge.verify(&request.code_verifier, hasher) {
        return deny(
            DenialReason::Pkce(e),
            "oauth.authorization_code.pkce_failed",
        );
    }

    Decision::Grant {
        grant: Grant {
            subject: code.subject,
            client: code.client.clone(),
            tenant: code.tenant,
        },
        effects: vec![
            Effect::ConsumeCode,
            Effect::RecordAudit("oauth.authorization_code.redeemed"),
        ],
    }
}
