#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl
)]

use std::sync::Arc;

use argus_core::cimd::ClientIdUrl;
use argus_core::ssrf::AddressVerdict;
use argus_http::cimd_fetch::{FetchError, Resolver, fetch};

struct FixedResolver(Vec<core::net::IpAddr>);

impl Resolver for FixedResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<core::net::IpAddr>, FetchError> {
        if self.0.is_empty() {
            return Err(FetchError::Unresolvable);
        }
        Ok(self.0.clone())
    }
}

fn tls() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn url() -> ClientIdUrl {
    ClientIdUrl::parse("https://client.example.com/client.json").expect("url")
}

fn resolver(addresses: &[&str]) -> FixedResolver {
    FixedResolver(
        addresses
            .iter()
            .map(|a| a.parse().expect("address"))
            .collect(),
    )
}

#[tokio::test]
async fn a_host_resolving_to_a_private_address_is_never_contacted() {
    for (address, expected) in [
        ("127.0.0.1", AddressVerdict::Loopback),
        ("10.0.0.5", AddressVerdict::Private),
        ("172.16.0.1", AddressVerdict::Private),
        ("192.168.1.1", AddressVerdict::Private),
        ("169.254.169.254", AddressVerdict::CloudMetadata),
        ("::1", AddressVerdict::Loopback),
        ("fd00::1", AddressVerdict::Private),
        ("fe80::1", AddressVerdict::LinkLocal),
    ] {
        let err = fetch(&url(), &resolver(&[address]), &tls(), false)
            .await
            .expect_err("must be blocked");
        assert_eq!(
            err,
            FetchError::BlockedAddress(expected),
            "{address} was not blocked"
        );
    }
}

#[tokio::test]
async fn an_ipv4_mapped_ipv6_answer_cannot_smuggle_a_private_address() {
    let err = fetch(
        &url(),
        &resolver(&["::ffff:169.254.169.254"]),
        &tls(),
        false,
    )
    .await
    .expect_err("must be blocked");
    assert_eq!(
        err,
        FetchError::BlockedAddress(AddressVerdict::CloudMetadata)
    );
}

#[tokio::test]
async fn one_bad_answer_among_many_blocks_the_whole_fetch() {
    let err = fetch(
        &url(),
        &resolver(&["93.184.216.34", "127.0.0.1"]),
        &tls(),
        false,
    )
    .await
    .expect_err("must be blocked");
    assert_eq!(err, FetchError::BlockedAddress(AddressVerdict::Loopback));
}

#[tokio::test]
async fn a_host_that_does_not_resolve_is_refused() {
    let err = fetch(&url(), &resolver(&[]), &tls(), false)
        .await
        .expect_err("must fail");
    assert_eq!(err, FetchError::Unresolvable);
}

#[tokio::test]
async fn the_development_loopback_exception_lets_loopback_through_but_nothing_else() {
    let err = fetch(&url(), &resolver(&["127.0.0.1"]), &tls(), true)
        .await
        .expect_err("the connection itself still fails");
    assert_ne!(
        err,
        FetchError::BlockedAddress(AddressVerdict::Loopback),
        "loopback must be allowed past the address check when the exception is on"
    );

    let err = fetch(&url(), &resolver(&["169.254.169.254"]), &tls(), true)
        .await
        .expect_err("cloud metadata must stay blocked");
    assert_eq!(
        err,
        FetchError::BlockedAddress(AddressVerdict::CloudMetadata)
    );

    let err = fetch(&url(), &resolver(&["10.0.0.5"]), &tls(), true)
        .await
        .expect_err("private ranges must stay blocked");
    assert_eq!(err, FetchError::BlockedAddress(AddressVerdict::Private));
}
