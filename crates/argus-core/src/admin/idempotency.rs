pub const MAX_KEY_BYTES: usize = 255;

/// §24 #33 asks for the window to be published rather than left to the reader.
/// Stripe's thirty days is the reference.
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
        // The draft forbids PII in the key, and a server cannot enforce that,
        // so the value never reaches a log through this type.
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
    /// The request is running now. A second arrival must not start a second run.
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
    /// No usable record: run the request and store the result afterwards.
    Execute,
    /// The same key and the same payload already succeeded: return what it
    /// returned, do not run again.
    Replay,
    /// The same key with a different payload. §24 #33 wants these separated
    /// from an ordinary conflict so a client can tell a bug from a race.
    PayloadMismatch,
    /// The same key is mid-flight. Retrying now would double the effect.
    InFlight,
}

/// Stripe's v2 rule, which §24 #33 adopts: a success short circuits and a
/// failure is allowed to run again. A validation error is never stored in the
/// first place, so a client that fixes its payload is not locked out by its
/// own first attempt.
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
