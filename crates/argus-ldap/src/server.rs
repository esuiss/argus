use std::sync::Arc;

use argus_core::ldap::{
    Dn, OID_START_TLS, OID_WHO_AM_I, PROTOCOL_ERROR, SIZE_LIMIT_EXCEEDED, SUCCESS,
    UNWILLING_TO_PERFORM,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::directory::{Directory, search};
use crate::message::{
    MAX_MESSAGE_BYTES, Message, MessageError, Operation, bind_response, compare_response, decode,
    extended_response, framed_length, search_result_done, search_result_entry,
};
use crate::session::{
    Confidentiality, Identity, PasswordCheck, access_of, decide_bind, refuse_search,
};

pub const READ_BUFFER: usize = 8 * 1024;

pub struct Service<P> {
    pub directory: Directory,
    pub passwords: P,
}

pub struct Connection {
    pub identity: Identity,
    pub confidentiality: Confidentiality,
}

impl Connection {
    #[must_use]
    pub const fn new(confidentiality: Confidentiality) -> Self {
        Self {
            identity: Identity::Anonymous,
            confidentiality,
        }
    }
}

pub enum Reply {
    Send(Vec<u8>),
    Silent,
    Close(Vec<u8>),
}

impl<P: PasswordCheck> Service<P> {
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per LDAP operation; splitting it hides which operations are answered"
    )]
    pub fn respond(&self, connection: &mut Connection, message: &Message) -> Reply {
        let id = message.id;

        match &message.operation {
            Operation::Unbind => Reply::Close(Vec::new()),

            Operation::Abandon { .. } => Reply::Silent,

            Operation::Bind(bind) => {
                let directory = &self.directory;
                let decision = decide_bind(
                    &bind.name,
                    &bind.password,
                    connection.confidentiality,
                    |candidate| {
                        directory
                            .find_by_bind_name(candidate)
                            .map(|person| directory.person_dn(&person.uid))
                    },
                    &self.passwords,
                );

                connection.identity = decision.identity.clone().unwrap_or(Identity::Anonymous);

                Reply::Send(bind_response(id, decision.code, decision.message))
            }

            Operation::Search(request) => {
                let is_root_dse = request.base.trim().is_empty();

                if let Some(code) = refuse_search(access_of(&connection.identity), is_root_dse) {
                    return Reply::Send(search_result_done(
                        id,
                        code,
                        "",
                        "bind before reading the directory",
                    ));
                }

                let outcome = search(
                    &self.directory,
                    &request.base,
                    request.scope,
                    &request.filter,
                    &request.attributes,
                    request.size_limit,
                );

                let mut out = Vec::new();
                for entry in &outcome.entries {
                    out.extend_from_slice(&search_result_entry(id, entry, request.types_only));
                }

                let code = if outcome.truncated {
                    SIZE_LIMIT_EXCEEDED
                } else {
                    SUCCESS
                };

                let matched = if outcome.entries.is_empty() && !is_root_dse {
                    self.matched_prefix(&request.base)
                } else {
                    String::new()
                };

                out.extend_from_slice(&search_result_done(id, code, &matched, ""));
                Reply::Send(out)
            }

            Operation::Compare {
                dn,
                attribute,
                value,
            } => {
                if refuse_search(access_of(&connection.identity), false).is_some() {
                    return Reply::Send(compare_response(
                        id,
                        argus_core::ldap::INSUFFICIENT_ACCESS_RIGHTS,
                    ));
                }

                let found = self.directory.entries().into_iter().find(|entry| {
                    Dn::parse(&entry.dn).is_ok_and(|parsed| {
                        Dn::parse(dn).is_ok_and(|target| parsed.equals(&target))
                    })
                });

                let code = match found {
                    None => argus_core::ldap::NO_SUCH_OBJECT,
                    Some(entry) => {
                        if entry.values(attribute).is_empty() {
                            argus_core::ldap::NO_SUCH_ATTRIBUTE
                        } else if entry
                            .values(attribute)
                            .iter()
                            .any(|candidate| candidate.eq_ignore_ascii_case(value))
                        {
                            argus_core::ldap::COMPARE_TRUE
                        } else {
                            argus_core::ldap::COMPARE_FALSE
                        }
                    }
                };

                Reply::Send(compare_response(id, code))
            }

            Operation::Extended { name, .. } => match name.as_str() {
                OID_WHO_AM_I => {
                    let authorization = match &connection.identity {
                        Identity::Anonymous => String::new(),
                        Identity::Person { dn } => format!("dn:{dn}"),
                    };
                    Reply::Send(extended_response(
                        id,
                        SUCCESS,
                        "",
                        None,
                        Some(authorization.as_bytes()),
                    ))
                }

                OID_START_TLS => Reply::Send(extended_response(
                    id,
                    UNWILLING_TO_PERFORM,
                    "this listener is already protected",
                    Some(OID_START_TLS),
                    None,
                )),

                _ => Reply::Send(extended_response(
                    id,
                    argus_core::ldap::PROTOCOL_ERROR,
                    "this server does not implement that extended operation",
                    None,
                    None,
                )),
            },

            Operation::Refused { .. } => Reply::Send(search_result_done(
                id,
                UNWILLING_TO_PERFORM,
                "",
                "this server exposes the directory for reading only",
            )),
        }
    }

    fn matched_prefix(&self, base: &str) -> String {
        let Ok(requested) = Dn::parse(base) else {
            return String::new();
        };

        self.directory
            .entries()
            .into_iter()
            .filter(|entry| Dn::parse(&entry.dn).is_ok_and(|parsed| requested.is_under(&parsed)))
            .max_by_key(|entry| entry.dn.len())
            .map(|entry| entry.dn)
            .unwrap_or_default()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the framing loop and the dispatch have to share one buffer"
)]
pub async fn serve<S, P>(
    stream: &mut S,
    service: &Arc<Service<P>>,
    confidentiality: Confidentiality,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: PasswordCheck,
{
    let mut connection = Connection::new(confidentiality);
    let mut buffer: Vec<u8> = Vec::with_capacity(READ_BUFFER);
    let mut chunk = [0_u8; READ_BUFFER];

    loop {
        let frame = match framed_length(&buffer) {
            Some(Err(_)) => {
                let _ = stream
                    .write_all(&search_result_done(
                        0,
                        PROTOCOL_ERROR,
                        "",
                        "the message could not be framed",
                    ))
                    .await;
                return Ok(());
            }
            Some(Ok(total)) if total <= buffer.len() => Some(total),
            _ => None,
        };

        let Some(total) = frame else {
            if buffer.len() > MAX_MESSAGE_BYTES {
                return Ok(());
            }

            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
            continue;
        };

        let message = buffer.drain(..total).collect::<Vec<u8>>();

        match decode(&message) {
            Err(MessageError::UnsupportedOperation { .. } | MessageError::Ber(_)) => {
                let _ = stream
                    .write_all(&search_result_done(
                        0,
                        PROTOCOL_ERROR,
                        "",
                        "the message could not be read",
                    ))
                    .await;
                return Ok(());
            }

            Err(_) => {
                let _ = stream
                    .write_all(&bind_response(
                        0,
                        PROTOCOL_ERROR,
                        "the request was not one this server accepts",
                    ))
                    .await;
            }

            Ok(decoded) => match service.respond(&mut connection, &decoded) {
                Reply::Silent => {}
                Reply::Send(bytes) => stream.write_all(&bytes).await?,
                Reply::Close(bytes) => {
                    if !bytes.is_empty() {
                        stream.write_all(&bytes).await?;
                    }
                    return Ok(());
                }
            },
        }
    }
}
