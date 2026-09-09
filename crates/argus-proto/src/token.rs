use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,

    pub token_type: String,

    pub expires_in: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

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

    #[test]
    fn debug_redacts_both_tokens() {
        let shown = format!("{:?}", sample());
        assert!(!shown.contains("SUPER-SECRET-ACCESS"), "leaked: {shown}");
        assert!(!shown.contains("SUPER-SECRET-REFRESH"), "leaked: {shown}");
        assert!(shown.contains("<redacted>"));

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

        assert!(!json.contains("id_token"));
    }

    #[test]
    fn id_token_is_serialised_when_present() {
        let r = TokenResponse {
            id_token: Some("header.payload.sig".to_owned()),
            ..sample()
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""id_token":"header.payload.sig""#));
    }

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
