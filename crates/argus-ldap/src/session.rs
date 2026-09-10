use argus_core::ldap::{
    CONFIDENTIALITY_REQUIRED, INSUFFICIENT_ACCESS_RIGHTS, INVALID_CREDENTIALS, SUCCESS,
    UNWILLING_TO_PERFORM,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Anonymous,
    Person { dn: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidentiality {
    Plaintext,
    Protected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDecision {
    pub code: i64,
    pub message: &'static str,
    pub identity: Option<Identity>,
}

pub trait PasswordCheck {
    fn verify(&self, dn: &str, password: &[u8]) -> bool;
}

// RFC 4513 §5.1.2: adı olup parolası boş bir bind unauthenticated bind'dır ve
// yanlışlıkla başarılı okunur; §16 bunu reddettiriyor. Ve TLS olmadan parola
// bind'ı CONFIDENTIALITY_REQUIRED alır.
pub fn decide_bind(
    name: &str,
    password: &[u8],
    confidentiality: Confidentiality,
    resolve: impl Fn(&str) -> Option<String>,
    check: &impl PasswordCheck,
) -> BindDecision {
    let named = !name.trim().is_empty();
    let has_password = !password.is_empty();

    if !named && !has_password {
        return BindDecision {
            code: SUCCESS,
            message: "",
            identity: Some(Identity::Anonymous),
        };
    }

    if named && !has_password {
        return BindDecision {
            code: UNWILLING_TO_PERFORM,
            message: "an unauthenticated bind is not a way to log in",
            identity: None,
        };
    }

    if !named && has_password {
        return BindDecision {
            code: INVALID_CREDENTIALS,
            message: "",
            identity: None,
        };
    }

    if confidentiality == Confidentiality::Plaintext {
        return BindDecision {
            code: CONFIDENTIALITY_REQUIRED,
            message: "this connection must be protected before a password is sent",
            identity: None,
        };
    }

    let Some(dn) = resolve(name) else {
        return BindDecision {
            code: INVALID_CREDENTIALS,
            message: "",
            identity: None,
        };
    };

    if check.verify(&dn, password) {
        BindDecision {
            code: SUCCESS,
            message: "",
            identity: Some(Identity::Person { dn }),
        }
    } else {
        BindDecision {
            code: INVALID_CREDENTIALS,
            message: "",
            identity: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAccess {
    RootDseOnly,
    Everything,
}

#[must_use]
pub const fn access_of(identity: &Identity) -> ReadAccess {
    match identity {
        Identity::Anonymous => ReadAccess::RootDseOnly,
        Identity::Person { .. } => ReadAccess::Everything,
    }
}

#[must_use]
pub const fn refuse_search(access: ReadAccess, is_root_dse: bool) -> Option<i64> {
    match access {
        ReadAccess::Everything => None,
        ReadAccess::RootDseOnly => {
            if is_root_dse {
                None
            } else {
                Some(INSUFFICIENT_ACCESS_RIGHTS)
            }
        }
    }
}
