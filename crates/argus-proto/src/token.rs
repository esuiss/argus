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

    /// OIDC Core §3.1.3.3: kapsam `openid` içeriyorsa kimlik iddiası.
    ///
    /// Access token'ın aksine bu alan **istemci tarafından okunur**; bu yüzden
    /// yalnızca `openid` istendiğinde vardır. Her yanıta koymak, kimlik
    /// iddiasını istemediğini söylemiş istemcilere kimlik dağıtmak olurdu.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
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
            // `id_token` sır DEĞİL — istemci onu okumak zorunda — ama içinde
            // `sub` var; log'a özne kimliği düşürmemek için yine gizleniyor.
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
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
            id_token: None,
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
        // `openid` istenmediyse yanıtta kimlik iddiası HİÇ olmamalı.
        assert!(!json.contains("id_token"));
    }

    /// `openid` istendiğinde alan tam adıyla telde görünmeli; istemciler onu
    /// bu adla arıyor.
    #[test]
    fn id_token_is_serialised_when_present() {
        let r = TokenResponse {
            id_token: Some("header.payload.sig".to_owned()),
            ..sample()
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""id_token":"header.payload.sig""#));
    }

    /// Kimlik iddiası `sub` taşır; `Debug` çıktısında görünmemeli.
    #[test]
    fn debug_hides_the_id_token() {
        let r = TokenResponse {
            id_token: Some("h.SUBJECT-INSIDE.s".to_owned()),
            ..sample()
        };
        let shown = format!("{r:?}");
        assert!(!shown.contains("SUBJECT-INSIDE"), "leaked: {shown}");
    }

    #[test]
    fn wire_format_matches_rfc6749() {
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(json.contains(r#""access_token":"SUPER-SECRET-ACCESS""#));
        assert!(json.contains(r#""token_type":"DPoP""#));
        assert!(json.contains(r#""expires_in":300"#));
    }
}
