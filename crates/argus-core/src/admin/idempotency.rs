pub const MAX_KEY_BYTES: usize = 255;

pub const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("an idempotency key must not be empty")]
    Empty,

    #[error("an idempotency key of {actual} bytes exceeds the {allowed} this server accepts")]
    TooLong { allowed: usize, actual: usize },

    #[error("an idempotency key must be printable ASCII")]
    NotPrintable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl core::fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdempotencyKey(..)")
    }
}

impl IdempotencyKey {
    pub fn new(raw: &str) -> Result<Self, KeyError> {
        if raw.is_empty() {
            return Err(KeyError::Empty);
        }
        if raw.len() > MAX_KEY_BYTES {
            return Err(KeyError::TooLong {
                allowed: MAX_KEY_BYTES,
                actual: raw.len(),
            });
        }
        if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(KeyError::NotPrintable);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    InFlight,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub fingerprint: [u8; 32],
    pub state: RecordState,
    pub stored_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Execute,
    Replay,
    PayloadMismatch,
    InFlight,
}

#[must_use]
pub fn decide(existing: Option<&Record>, fingerprint: &[u8; 32], now: u64) -> Outcome {
    let Some(record) = existing else {
        return Outcome::Execute;
    };

    if now.saturating_sub(record.stored_at) > RETENTION_SECONDS {
        return Outcome::Execute;
    }

    if record.fingerprint != *fingerprint {
        return Outcome::PayloadMismatch;
    }

    match record.state {
        RecordState::Succeeded => Outcome::Replay,
        RecordState::InFlight => Outcome::InFlight,
        RecordState::Failed => Outcome::Execute,
    }
}
