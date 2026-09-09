//! OAuth hata yanıtları — RFC 6749 §5.2.

use serde::{Deserialize, Serialize};

/// RFC 6749 §5.2'nin token endpoint hata kodları.
///
/// # Neden enum, neden dizge değil
///
/// Hata kodu istemcinin davranışını belirler; yazım hatası sessizce yanlış
/// davranış üretir. Enum, kod yolunun yalnızca tanımlı kodları üretebilmesini
/// sağlar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    /// İstek eksik/tekrarlanan parametre içeriyor veya biçimsiz.
    InvalidRequest,
    /// İstemci kimlik doğrulaması başarısız.
    InvalidClient,
    /// Grant geçersiz, süresi dolmuş, iptal edilmiş, başka istemciye verilmiş
    /// veya `redirect_uri` uyuşmuyor.
    ///
    /// Argus'ta authorization code ve refresh token akışlarının **tüm** ret
    /// sebepleri buraya düşer: hangi kontrolde takıldığını söylemek saldırgana
    /// nerede olduğunu bildirmektir.
    InvalidGrant,
    /// İstemci bu grant tipini kullanmaya yetkili değil.
    UnauthorizedClient,
    /// Grant tipi desteklenmiyor.
    UnsupportedGrantType,
    /// İstenen kapsam geçersiz.
    InvalidScope,
    /// Sunucu hatası (yalnızca gerçekten beklenmeyen durumlarda).
    ServerError,
    /// Sunucu geçici olarak isteği karşılayamıyor.
    TemporarilyUnavailable,

    /// Sunulan access token geçersiz, süresi dolmuş veya bağlaması tutmuyor.
    ///
    /// ⚠️ Bu kod **`RFC` 6750 §3.1'e** aittir, §5.2'ye değil: token endpoint'i
    /// bunu asla döndürmez, **kaynak sunucu** döndürür. Aynı enum'da durmasının
    /// sebebi tel biçiminin ve serileştirme yolunun tek olması; anlamı ayrı.
    InvalidToken,
}

impl OAuthErrorCode {
    /// Tel üzerindeki dizge.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
        }
    }

    /// Bu hata için HTTP durum kodu.
    ///
    /// RFC 6749 §5.2: `invalid_client` **401** döner (ve `WWW-Authenticate`
    /// taşır), diğerleri **400**. Sunucu hataları 5xx'tir.
    ///
    /// ⚠️ §19 §7.1: kesinti veya failover sırasında **asla `invalid_grant`
    /// dönülmez** — `503` + `Retry-After` dönülür. `invalid_grant` istemciye
    /// "yeniden yetkilendir" dedirtir ve geçici bir arızayı kalıcı bir çıkışa
    /// çevirir.
    #[must_use]
    pub const fn http_status(self) -> u16 {
        match self {
            // `RFC` 6750 §3.1: geçersiz token 401'dir; 403 "yetkin yok" demek
            // olurdu ve bu farklı bir iddiadır.
            Self::InvalidClient | Self::InvalidToken => 401,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

/// RFC 6749 §5.2 hata yanıtı gövdesi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthError {
    /// Hata kodu.
    pub error: OAuthErrorCode,

    /// İnsan okunabilir açıklama.
    ///
    /// ⚠️ **Denetlenmemiş veri buraya konmaz.** Bu alan istemciye ve çoğu zaman
    /// kullanıcıya gider; içine istek parametresi yansıtmak siteler-arası betik ve bilgi sızıntısı
    /// yüzeyidir. Argus'ta yalnızca sabit dizgeler kullanılır.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<&'static str>,
}

impl OAuthError {
    /// Yalnızca kodla hata üretir.
    #[must_use]
    pub const fn new(error: OAuthErrorCode) -> Self {
        Self {
            error,
            error_description: None,
        }
    }

    /// Sabit bir açıklama ekler.
    #[must_use]
    pub const fn with_description(error: OAuthErrorCode, description: &'static str) -> Self {
        Self {
            error,
            error_description: Some(description),
        }
    }

    /// Bu hatanın HTTP durum kodu.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        self.error.http_status()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{OAuthError, OAuthErrorCode};

    #[test]
    fn error_codes_serialize_to_the_wire_names() {
        let json = serde_json::to_string(&OAuthError::new(OAuthErrorCode::InvalidGrant)).unwrap();
        assert_eq!(json, r#"{"error":"invalid_grant"}"#);
    }

    #[test]
    fn description_is_omitted_when_absent() {
        let json = serde_json::to_string(&OAuthError::new(OAuthErrorCode::InvalidRequest)).unwrap();
        assert!(!json.contains("error_description"));
    }

    /// RFC 6749 §5.2: `invalid_client` 401, geri kalanı 400.
    #[test]
    fn http_status_follows_rfc6749() {
        assert_eq!(OAuthErrorCode::InvalidClient.http_status(), 401);
        assert_eq!(OAuthErrorCode::InvalidGrant.http_status(), 400);
        assert_eq!(OAuthErrorCode::InvalidRequest.http_status(), 400);
        assert_eq!(OAuthErrorCode::ServerError.http_status(), 500);
        assert_eq!(OAuthErrorCode::TemporarilyUnavailable.http_status(), 503);
    }

    #[test]
    fn as_str_matches_serde_representation() {
        for code in [
            OAuthErrorCode::InvalidRequest,
            OAuthErrorCode::InvalidClient,
            OAuthErrorCode::InvalidGrant,
            OAuthErrorCode::UnauthorizedClient,
            OAuthErrorCode::UnsupportedGrantType,
            OAuthErrorCode::InvalidScope,
            OAuthErrorCode::ServerError,
            OAuthErrorCode::TemporarilyUnavailable,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }
}
