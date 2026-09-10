use base64ct::{Base64UrlUnpadded, Encoding as _};

pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageError {
    #[error("the cursor is not one this server issued")]
    InvalidCursor,

    #[error("a page of {actual} exceeds the {allowed} this server accepts")]
    LimitTooLarge { allowed: usize, actual: usize },

    #[error("a page must hold at least one record")]
    EmptyLimit,
}

// §24 #6 offset sayfalamayı reddediyor. Keycloak'ın kendi kullanıcısı
// (@Plasmadog, 17 Tem 2025) küme okuyucunun altında değişirken offset'in
// kayıt KAÇIRDIĞINI gösterdi; Keycloak v2 buna rağmen offset seçti. Yolların
// ayrıldığı yer burasıdır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub after: Option<String>,
    pub limit: usize,
}

impl PageRequest {
    pub fn parse(cursor: Option<&str>, limit: Option<&str>) -> Result<Self, PageError> {
        let limit = match limit {
            None => DEFAULT_LIMIT,
            Some(raw) => {
                let parsed: usize = raw.parse().map_err(|_| PageError::EmptyLimit)?;
                if parsed == 0 {
                    return Err(PageError::EmptyLimit);
                }
                if parsed > MAX_LIMIT {
                    return Err(PageError::LimitTooLarge {
                        allowed: MAX_LIMIT,
                        actual: parsed,
                    });
                }
                parsed
            }
        };

        let after = match cursor {
            None => None,
            Some(raw) => Some(decode_cursor(raw)?),
        };

        Ok(Self { after, limit })
    }
}

#[must_use]
pub fn encode_cursor(key: &str) -> String {
    Base64UrlUnpadded::encode_string(key.as_bytes())
}

pub fn decode_cursor(raw: &str) -> Result<String, PageError> {
    let mut buffer = [0_u8; 512];
    let decoded =
        Base64UrlUnpadded::decode(raw, &mut buffer).map_err(|_| PageError::InvalidCursor)?;
    core::str::from_utf8(decoded)
        .map(str::to_owned)
        .map_err(|_| PageError::InvalidCursor)
}

#[must_use]
// RFC 5988. §24 #6 ve Keycloak'ın kendi REST kılavuzu, sonraki sayfanın
// istemcinin hesapladığı bir aritmetik değil izlediği bir bağlantı olmasını
// istiyor.
pub fn link_header(base: &str, next: Option<&str>, previous: Option<&str>) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(cursor) = next {
        parts.push(format!("<{base}?cursor={cursor}>; rel=\"next\""));
    }
    if let Some(cursor) = previous {
        parts.push(format!("<{base}?cursor={cursor}>; rel=\"prev\""));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}
