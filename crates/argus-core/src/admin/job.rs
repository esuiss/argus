use serde_json::Value;

// §24 #28: AIP-151 yaklaşık on saniyeden uzun her işlemi long running
// operation sayıyor. İncelenen HER satıcı SCIM /Bulk'u desteklemediğini
// bildirip kendi async job API'sini yazdı; bu yüzden bulk burada bu şekli
// alır.
pub const LONG_RUNNING_THRESHOLD_SECONDS: u64 = 10;

pub const MAX_ITEMS: usize = 10_000;

// §24 #29: Auth0 job sonuçlarını 24 saatte siliyor, ki ertesi sabah bulunan
// kısmî bir hatayı incelemek için çok kısa.
pub const RESULT_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Running,
    Succeeded,
    // Bazı kalemler uygulandı, bazıları uygulanmadı. AIP-151 bunu terminal
    // yanıttan ayırıp metadata'da tutuyor, böylece çağıran kısmî bir koşumu
    // temiz sanamaz.
    PartiallySucceeded,
    Failed,
}

impl JobState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::PartiallySucceeded | Self::Failed
        )
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::PartiallySucceeded => "partially_succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JobFault {
    #[error("a job of {actual} items exceeds the {allowed} this server accepts")]
    TooManyItems { allowed: usize, actual: usize },

    #[error("a job must carry at least one item")]
    Empty,

    #[error("a job in state {from} cannot move to {to}")]
    IllegalTransition {
        from: &'static str,
        to: &'static str,
    },
}

// Tek bir kalemin sonucu. §24 #29 insan mesajının yanında makine kodu
// istiyor, çünkü on bin kaydı yeniden deneyen bir çağıran düzyazı
// ayrıştıramaz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemResult {
    pub index: usize,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: String,
    pub state: JobState,
    pub total: usize,
    pub completed: usize,
    pub failures: Vec<ItemResult>,
    pub created_at: u64,
}

impl Job {
    pub fn new(id: &str, total: usize, now: u64) -> Result<Self, JobFault> {
        if total == 0 {
            return Err(JobFault::Empty);
        }
        if total > MAX_ITEMS {
            return Err(JobFault::TooManyItems {
                allowed: MAX_ITEMS,
                actual: total,
            });
        }
        Ok(Self {
            id: id.to_owned(),
            state: JobState::Pending,
            total,
            completed: 0,
            failures: Vec::new(),
            created_at: now,
        })
    }

    pub fn start(&mut self) -> Result<(), JobFault> {
        if self.state != JobState::Pending {
            return Err(JobFault::IllegalTransition {
                from: self.state.as_str(),
                to: JobState::Running.as_str(),
            });
        }
        self.state = JobState::Running;
        Ok(())
    }

    pub fn record(&mut self, outcome: Option<ItemResult>) -> Result<(), JobFault> {
        if self.state != JobState::Running {
            return Err(JobFault::IllegalTransition {
                from: self.state.as_str(),
                to: JobState::Running.as_str(),
            });
        }
        self.completed = self.completed.saturating_add(1);
        if let Some(failure) = outcome {
            self.failures.push(failure);
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<JobState, JobFault> {
        if self.state != JobState::Running {
            return Err(JobFault::IllegalTransition {
                from: self.state.as_str(),
                to: JobState::Succeeded.as_str(),
            });
        }

        self.state = if self.failures.is_empty() {
            JobState::Succeeded
        } else if self.failures.len() == self.total {
            JobState::Failed
        } else {
            JobState::PartiallySucceeded
        };

        Ok(self.state)
    }

    #[must_use]
    // AIP-151 ilerlemeyi terminal sonuçtan ayırır. İlerleme job koşarken
    // okunabilir; sonuç ancak iş bittiğinde vardır.
    pub fn metadata(&self) -> Value {
        serde_json::json!({
            "state": self.state.as_str(),
            "total": self.total,
            "completed": self.completed,
            "failed": self.failures.len(),
        })
    }

    #[must_use]
    pub fn response(&self) -> Option<Value> {
        if !self.state.is_terminal() {
            return None;
        }

        let failures: Vec<Value> = self
            .failures
            .iter()
            .map(|f| {
                serde_json::json!({
                    "index": f.index,
                    "code": f.code,
                    "message": f.message,
                })
            })
            .collect();

        Some(serde_json::json!({
            "state": self.state.as_str(),
            "succeeded": self.total.saturating_sub(self.failures.len()),
            "failures": failures,
        }))
    }
}
