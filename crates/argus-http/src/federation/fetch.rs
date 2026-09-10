use std::sync::Arc;
use std::time::Duration as StdDuration;

use argus_core::federation::statement::EntityIdentifier;
use argus_core::ssrf::{AddressVerdict, classify};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

pub const FETCH_TIMEOUT: StdDuration = StdDuration::from_secs(5);
pub const MAX_STATEMENT_BYTES: usize = 256 * 1024;
pub const ENTITY_STATEMENT_MEDIA_TYPE: &str = "application/entity-statement+jwt";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchFault {
    #[error("the entity host does not resolve")]
    Unresolvable,

    #[error("the entity resolves to a special-use address: {0}")]
    BlockedAddress(AddressVerdict),

    #[error("the entity could not be reached")]
    Unreachable,

    #[error("the fetch did not complete in time")]
    TimedOut,

    #[error("the entity did not answer with 200 OK")]
    NotOk,

    #[error("the entity answered with a redirect, which must not be followed")]
    Redirected,

    #[error("the entity answered with the content type {found}")]
    WrongContentType { found: String },

    #[error("the response exceeded the maximum this server will read")]
    TooLarge,

    #[error("the entity identifier is not a usable target")]
    BadTarget,
}

pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Vec<core::net::IpAddr>, FetchFault>> + Send;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<core::net::IpAddr>, FetchFault> {
        let addresses = tokio::net::lookup_host(format!("{host}:{port}"))
            .await
            .map_err(|_| FetchFault::Unresolvable)?
            .map(|socket| socket.ip())
            .collect::<Vec<_>>();

        if addresses.is_empty() {
            return Err(FetchFault::Unresolvable);
        }
        Ok(addresses)
    }
}

pub struct Target {
    pub host: String,
    pub port: u16,
    pub request_target: String,
}

pub fn target_of(url: &str) -> Result<Target, FetchFault> {
    let rest = url.strip_prefix("https://").ok_or(FetchFault::BadTarget)?;

    let (authority, path) = match rest.find('/') {
        None => (rest, "/"),
        Some(index) => (
            rest.get(..index).ok_or(FetchFault::BadTarget)?,
            rest.get(index..).ok_or(FetchFault::BadTarget)?,
        ),
    };

    if authority.is_empty() || authority.contains('@') {
        return Err(FetchFault::BadTarget);
    }

    let (host, port) = match authority.rsplit_once(':') {
        None => (authority.to_owned(), 443_u16),
        Some((host, port)) => (
            host.to_owned(),
            port.parse().map_err(|_| FetchFault::BadTarget)?,
        ),
    };

    if host.is_empty() {
        return Err(FetchFault::BadTarget);
    }

    Ok(Target {
        host,
        port,
        request_target: path.to_owned(),
    })
}

pub async fn fetch_statement(
    url: &str,
    resolver: &impl Resolver,
    tls: &Arc<rustls::ClientConfig>,
    allow_loopback: bool,
) -> Result<String, FetchFault> {
    let target = target_of(url)?;

    let addresses = resolver.resolve(&target.host, target.port).await?;

    for address in &addresses {
        if let Some(verdict) = classify(*address) {
            if allow_loopback && verdict == AddressVerdict::Loopback {
                continue;
            }
            return Err(FetchFault::BlockedAddress(verdict));
        }
    }

    let address = *addresses.first().ok_or(FetchFault::Unresolvable)?;

    tokio::time::timeout(FETCH_TIMEOUT, read(&target, address, tls))
        .await
        .map_err(|_| FetchFault::TimedOut)?
}

pub async fn fetch_configuration(
    entity: &EntityIdentifier,
    resolver: &impl Resolver,
    tls: &Arc<rustls::ClientConfig>,
    allow_loopback: bool,
) -> Result<String, FetchFault> {
    fetch_statement(&entity.well_known(), resolver, tls, allow_loopback).await
}

pub async fn fetch_subordinate(
    fetch_endpoint: &str,
    subject: &EntityIdentifier,
    resolver: &impl Resolver,
    tls: &Arc<rustls::ClientConfig>,
    allow_loopback: bool,
) -> Result<String, FetchFault> {
    let separator = if fetch_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!(
        "{fetch_endpoint}{separator}sub={}",
        urlencode(subject.as_str())
    );
    fetch_statement(&url, resolver, tls, allow_loopback).await
}

#[must_use]
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&argus_core::hex::encode(&[byte]).to_uppercase());
        }
    }
    out
}

async fn read(
    target: &Target,
    address: core::net::IpAddr,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<String, FetchFault> {
    let stream = TcpStream::connect((address, target.port))
        .await
        .map_err(|_| FetchFault::Unreachable)?;

    let server_name = rustls::pki_types::ServerName::try_from(target.host.clone())
        .map_err(|_| FetchFault::Unresolvable)?;

    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    let mut protected = connector
        .connect(server_name, stream)
        .await
        .map_err(|_| FetchFault::Unreachable)?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: {ENTITY_STATEMENT_MEDIA_TYPE}\r\n\
         User-Agent: argus\r\nConnection: close\r\n\r\n",
        target.request_target, target.host
    );

    protected
        .write_all(request.as_bytes())
        .await
        .map_err(|_| FetchFault::Unreachable)?;

    let mut raw = Vec::new();
    let mut buffer = [0_u8; 4096];
    let ceiling = MAX_STATEMENT_BYTES.saturating_add(4096);

    loop {
        let read = protected
            .read(&mut buffer)
            .await
            .map_err(|_| FetchFault::Unreachable)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(buffer.get(..read).unwrap_or_default());
        if raw.len() > ceiling {
            return Err(FetchFault::TooLarge);
        }
    }

    parse_response(&raw)
}

pub fn parse_response(raw: &[u8]) -> Result<String, FetchFault> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or(FetchFault::NotOk)?;

    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(FetchFault::NotOk)?;

    if (300..400).contains(&status) {
        return Err(FetchFault::Redirected);
    }

    if status != 200 {
        return Err(FetchFault::NotOk);
    }

    let media_type = lines
        .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_ascii_lowercase())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();

    if media_type != ENTITY_STATEMENT_MEDIA_TYPE {
        return Err(FetchFault::WrongContentType { found: media_type });
    }

    let trimmed = body.trim();
    if trimmed.len() > MAX_STATEMENT_BYTES {
        return Err(FetchFault::TooLarge);
    }

    Ok(trimmed.to_owned())
}
