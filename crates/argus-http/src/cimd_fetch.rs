use std::sync::Arc;
use std::time::Duration as StdDuration;

use argus_core::cimd::ClientIdUrl;
use argus_core::ssrf::{AddressVerdict, classify};
use argus_proto::cimd::{ClientIdMetadataDocument, DocumentError, MAX_DOCUMENT_BYTES};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

pub const FETCH_TIMEOUT: StdDuration = StdDuration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    #[error("the client identifier host does not resolve")]
    Unresolvable,

    #[error("the client identifier resolves to a special-use address: {0}")]
    BlockedAddress(AddressVerdict),

    #[error("the client identifier host could not be reached")]
    Unreachable,

    #[error("the fetch did not complete in time")]
    TimedOut,

    #[error("the document was not served with 200 OK")]
    NotOk,

    #[error("the server answered with a redirect, which must not be followed")]
    Redirected,

    #[error("the response exceeded the maximum readable size")]
    TooLarge,

    #[error(transparent)]
    Document(#[from] DocumentError),
}

#[derive(Debug)]
pub struct FetchedDocument {
    pub document: ClientIdMetadataDocument,
    pub max_age: Option<u64>,
}

pub trait Resolver: Send + Sync {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Vec<core::net::IpAddr>, FetchError>> + Send;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<core::net::IpAddr>, FetchError> {
        let target = format!("{host}:{port}");
        let addresses = tokio::net::lookup_host(target)
            .await
            .map_err(|_| FetchError::Unresolvable)?
            .map(|socket| socket.ip())
            .collect::<Vec<_>>();

        if addresses.is_empty() {
            return Err(FetchError::Unresolvable);
        }
        Ok(addresses)
    }
}

pub async fn fetch(
    url: &ClientIdUrl,
    resolver: &impl Resolver,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<FetchedDocument, FetchError> {
    let addresses = resolver.resolve(url.host(), url.port()).await?;

    for address in &addresses {
        if let Some(verdict) = classify(*address) {
            return Err(FetchError::BlockedAddress(verdict));
        }
    }

    let address = *addresses.first().ok_or(FetchError::Unresolvable)?;

    let body = tokio::time::timeout(FETCH_TIMEOUT, read_document(url, address, tls))
        .await
        .map_err(|_| FetchError::TimedOut)??;

    let document = argus_proto::cimd::parse_and_validate(&body.body, url)?;

    Ok(FetchedDocument {
        document,
        max_age: body.max_age,
    })
}

#[derive(Debug)]
struct RawResponse {
    body: String,
    max_age: Option<u64>,
}

async fn read_document(
    url: &ClientIdUrl,
    address: core::net::IpAddr,
    tls: &Arc<rustls::ClientConfig>,
) -> Result<RawResponse, FetchError> {
    let stream = TcpStream::connect((address, url.port()))
        .await
        .map_err(|_| FetchError::Unreachable)?;

    let server_name = rustls::pki_types::ServerName::try_from(url.host().to_owned())
        .map_err(|_| FetchError::Unresolvable)?;

    let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|_| FetchError::Unreachable)?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\n\
         User-Agent: argus\r\nConnection: close\r\n\r\n",
        url.request_target(),
        url.host()
    );

    tls_stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| FetchError::Unreachable)?;

    let mut raw = Vec::new();
    let mut buffer = [0u8; 1024];
    let ceiling = MAX_DOCUMENT_BYTES + 4096;

    loop {
        let read = tls_stream
            .read(&mut buffer)
            .await
            .map_err(|_| FetchError::Unreachable)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(buffer.get(..read).unwrap_or_default());
        if raw.len() > ceiling {
            return Err(FetchError::TooLarge);
        }
    }

    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<RawResponse, FetchError> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or(FetchError::NotOk)?;

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(FetchError::NotOk)?;

    if (300..400).contains(&status) {
        return Err(FetchError::Redirected);
    }
    if status != 200 {
        return Err(FetchError::NotOk);
    }

    let max_age = lines
        .find(|line| line.to_ascii_lowercase().starts_with("cache-control:"))
        .and_then(|line| {
            line.to_ascii_lowercase()
                .split("max-age=")
                .nth(1)
                .and_then(|rest| {
                    rest.split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|digits| digits.parse::<u64>().ok())
                })
        });

    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(FetchError::TooLarge);
    }

    Ok(RawResponse {
        body: body.to_owned(),
        max_age,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{FetchError, parse_http_response};

    fn response(head: &str, body: &str) -> Vec<u8> {
        format!("{head}\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn only_200_is_accepted() {
        for status in [201, 204, 400, 401, 403, 404, 500, 503] {
            let raw = response(&format!("HTTP/1.1 {status} X"), "{}");
            assert_eq!(
                parse_http_response(&raw).unwrap_err(),
                FetchError::NotOk,
                "accepted {status}"
            );
        }
    }

    #[test]
    fn a_redirect_is_named_and_never_followed() {
        for status in [301, 302, 303, 307, 308] {
            let raw = response(
                &format!("HTTP/1.1 {status} Moved\r\nLocation: https://evil.test/x"),
                "",
            );
            assert_eq!(
                parse_http_response(&raw).unwrap_err(),
                FetchError::Redirected,
                "did not refuse {status}"
            );
        }
    }

    #[test]
    fn a_body_over_five_kilobytes_is_refused() {
        let big = "x".repeat(5121);
        let raw = response("HTTP/1.1 200 OK", &big);
        assert_eq!(parse_http_response(&raw).unwrap_err(), FetchError::TooLarge);

        let at_limit = "x".repeat(5120);
        let raw = response("HTTP/1.1 200 OK", &at_limit);
        assert!(parse_http_response(&raw).is_ok());
    }

    #[test]
    fn the_cache_lifetime_is_read_from_the_header() {
        let raw = response(
            "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=600",
            "{}",
        );
        assert_eq!(parse_http_response(&raw).unwrap().max_age, Some(600));

        let raw = response(
            "HTTP/1.1 200 OK\r\ncache-control: max-age=30, must-revalidate",
            "{}",
        );
        assert_eq!(parse_http_response(&raw).unwrap().max_age, Some(30));

        let raw = response("HTTP/1.1 200 OK", "{}");
        assert!(parse_http_response(&raw).unwrap().max_age.is_none());
    }

    #[test]
    fn a_truncated_response_is_refused() {
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK").unwrap_err(),
            FetchError::NotOk
        );
        assert_eq!(parse_http_response(b"").unwrap_err(), FetchError::NotOk);
    }
}
