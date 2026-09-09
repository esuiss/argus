use core::fmt;

use uuid::Uuid;

use crate::error::IdError;

pub const CLIENT_ID_MAX_LEN: usize = 255;

const ID_PREFIX_LEN: usize = 8;

fn write_redacted(f: &mut fmt::Formatter<'_>, id: Uuid) -> fmt::Result {
    let mut buf = Uuid::encode_buffer();
    let full = id.as_simple().encode_lower(&mut buf);

    let prefix = full.get(..ID_PREFIX_LEN).unwrap_or(full);
    write!(f, "{prefix}…")
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(Uuid);

impl TenantId {
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TenantId(")?;
        write_redacted(f, self.0)?;
        f.write_str(")")
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_redacted(f, self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(Uuid);

impl UserId {
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserId(")?;
        write_redacted(f, self.0)?;
        f.write_str(")")
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_redacted(f, self.0)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(String);

impl ClientId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();

        if value.is_empty() {
            return Err(IdError::ClientIdEmpty);
        }
        if value.len() > CLIENT_ID_MAX_LEN {
            return Err(IdError::ClientIdTooLong {
                len: value.len(),
                max: CLIENT_ID_MAX_LEN,
            });
        }

        if !value.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(IdError::ClientIdInvalidChar);
        }

        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientId({:?})", self.0)
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CLIENT_ID_MAX_LEN, ClientId, TenantId, UserId};
    use crate::error::IdError;
    use uuid::Uuid;

    fn sample() -> Uuid {
        Uuid::from_u128(0x0193_7f2e_1234_5678_9abc_def0_1234_5678)
    }

    #[test]
    fn tenant_id_debug_is_redacted() {
        let id = TenantId::from_uuid(sample());
        let shown = format!("{id:?}");
        assert_eq!(shown, "TenantId(01937f2e…)");

        assert!(!shown.contains("9abcdef0"));
    }

    #[test]
    fn user_id_debug_is_redacted() {
        let id = UserId::from_uuid(sample());
        assert_eq!(format!("{id:?}"), "UserId(01937f2e…)");
    }

    #[test]
    fn id_round_trips_through_uuid() {
        assert_eq!(TenantId::from_uuid(sample()).as_uuid(), sample());
        assert_eq!(UserId::from_uuid(sample()).as_uuid(), sample());
    }

    #[test]
    fn same_uuid_under_two_types_is_an_explicit_unwrap() {
        let tenant = TenantId::from_uuid(sample());
        let user = UserId::from_uuid(sample());
        assert_eq!(tenant.as_uuid(), user.as_uuid());
    }

    #[test]
    fn client_id_accepts_valid_values() {
        for value in ["s6BhdRkqt3", "https://example.com/client", "a b~"] {
            assert!(ClientId::new(value).is_ok(), "rejected: {value}");
        }
    }

    #[test]
    fn client_id_rejects_invalid_values() {
        let cases: [(&str, IdError); 4] = [
            ("", IdError::ClientIdEmpty),
            ("bad\nline", IdError::ClientIdInvalidChar),
            ("tab\there", IdError::ClientIdInvalidChar),
            ("caf\u{e9}", IdError::ClientIdInvalidChar),
        ];
        for (value, expected) in cases {
            assert_eq!(
                ClientId::new(value).unwrap_err(),
                expected,
                "input: {value:?}"
            );
        }
    }

    #[test]
    fn client_id_enforces_max_length() {
        let ok = "a".repeat(CLIENT_ID_MAX_LEN);
        assert!(ClientId::new(ok).is_ok());

        let too_long = "a".repeat(CLIENT_ID_MAX_LEN + 1);
        assert_eq!(
            ClientId::new(too_long).unwrap_err(),
            IdError::ClientIdTooLong {
                len: CLIENT_ID_MAX_LEN + 1,
                max: CLIENT_ID_MAX_LEN,
            }
        );
    }

    #[test]
    fn client_id_is_not_redacted() {
        let id = ClientId::new("s6BhdRkqt3").unwrap();
        assert_eq!(id.to_string(), "s6BhdRkqt3");
    }
}
