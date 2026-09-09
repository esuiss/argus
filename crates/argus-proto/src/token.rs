//! Token endpoint yanıtı — RFC 6749 §5.1.

use serde::{Deserialize, Serialize};

/// Başarılı token yanıtı.
///
/// # `Debug` neden elle yazıldı
///
/// Bu tip **iki sır** taşır: `access_token` ve `refresh_token`. Türetilmiş bir
/// `Debug`, herhangi bir `tracing` alanında ya da hata yolunda ikisini de düz
/// metin olarak log'a basardı (§25 K27). Elle yazılan gösterim yalnızca meta
/// bilgiyi verir.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Erişim token'ı.
    pub access_token: String,

    /// Token tipi. `DPoP` bağlı token'larda `DPoP`, aksi hâlde `Bearer`.
    ///
    /// §1 §4.1: **bearer varsayılan değildir.** `DPoP` ve mTLS-bound kabulü birinci
    /// sınıftır; `Bearer` yalnızca istemci başka bir şey desteklemiyorsa.
    pub token_type: String,

    /// Saniye cinsinden ömür.
    pub expires_in: i64,

    /// Refresh token — verilmişse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Verilen kapsam, istenenden farklıysa (RFC 6749 §5.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl core::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scope", &self.scope)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::TokenResponse;

    fn sample() -> TokenResponse {
        TokenResponse {
            access_token: "SUPER-SECRET-ACCESS".to_owned(),
            token_type: "DPoP".to_owned(),
            expires_in: 300,
            refresh_token: Some("SUPER-SECRET-REFRESH".to_owned()),
            scope: None,
        }
    }

    /// §25 K27: sır taşıyan tipin `Debug`'ı sırrı basmamalı.
    #[test]
    fn debug_redacts_both_tokens() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("SUPER-SECRET-ACCESS"), "leaked: {shown}");
        assert!(!shown.contains("SUPER-SECRET-REFRESH"), "leaked: {shown}");
        assert!(shown.contains("<redacted>"));
        // Meta bilgi görünür kalmalı, yoksa hata ayıklanamaz.
        assert!(shown.contains("DPoP"));
        assert!(shown.contains("300"));
    }

    #[test]
    fn absent_fields_are_omitted() {
        let r = TokenResponse {
            refresh_token: None,
            ..sample()
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("refresh_token"));
        assert!(!json.contains("scope"));
    }

    #[test]
    fn wire_format_matches_rfc6749() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(json.contains(r#""access_token":"SUPER-SECRET-ACCESS""#));
        assert!(json.contains(r#""token_type":"DPoP""#));
        assert!(json.contains(r#""expires_in":300"#));
    }
}
