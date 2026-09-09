#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use argus_core::authz_code::{
    AuthorizationCode, CodeLifetimeError, CodeState, DEFAULT_CODE_LIFETIME, Decision, DenialReason,
    MAX_CODE_LIFETIME, StoredCode, TokenRequest, redeem,
};
use argus_core::effect::Effect;
use argus_core::pkce::{CodeChallenge, CodeChallengeMethod, Sha256};
use argus_core::time::Duration;
use argus_core::{ClientId, PkceError, RedirectUri, TenantId, Timestamp, UserId};
use uuid::Uuid;

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const DIGEST: [u8; 32] = [
    19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46, 8, 118, 168, 120, 173, 109,
    241, 68, 86, 110, 225, 137, 74, 203, 112, 249, 195,
];

struct FixedSha256;

impl Sha256 for FixedSha256 {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        if input == VERIFIER.as_bytes() {
            DIGEST
        } else {
            [0xFF; 32]
        }
    }
}

fn tenant_a() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0a))
}

fn tenant_b() -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(0x0b))
}

fn subject() -> UserId {
    UserId::from_uuid(Uuid::from_u128(0xa1))
}

fn client_a() -> ClientId {
    ClientId::new("acme-web").expect("valid client_id")
}

fn client_b() -> ClientId {
    ClientId::new("other-app").expect("valid client_id")
}

fn redirect() -> RedirectUri {
    RedirectUri::register("https://app.example.com/cb").expect("valid redirect_uri")
}

fn challenge() -> CodeChallenge {
    CodeChallenge::parse(CodeChallengeMethod::S256, CHALLENGE).expect("valid challenge")
}

const ISSUED: Timestamp = Timestamp::from_unix_seconds(1_000);

fn code_with(redirect_uri: RedirectUri) -> AuthorizationCode {
    AuthorizationCode::new(
        tenant_a(),
        client_a(),
        subject(),
        redirect_uri,
        challenge(),
        ISSUED,
        DEFAULT_CODE_LIFETIME,
    )
    .expect("valid lifetime")
}

fn code() -> AuthorizationCode {
    code_with(redirect())
}

fn request() -> TokenRequest {
    TokenRequest {
        client: client_a(),
        redirect_uri: "https://app.example.com/cb".to_owned(),
        code_verifier: VERIFIER.to_owned(),
        tenant: tenant_a(),
    }
}

fn deny_reason(d: &Decision) -> &DenialReason {
    match d {
        Decision::Deny { reason, .. } => reason,
        Decision::Grant { .. } => panic!("expected a denial, got a grant"),
    }
}

fn effects(d: &Decision) -> &[Effect] {
    match d {
        Decision::Deny { effects, .. } | Decision::Grant { effects, .. } => effects,
    }
}

#[test]
fn valid_request_is_granted() {
    let d = redeem(&code(), &request(), ISSUED, &FixedSha256);

    match &d {
        Decision::Grant { grant, .. } => {
            assert_eq!(grant.subject, subject());
            assert_eq!(grant.client, client_a());
            assert_eq!(grant.tenant, tenant_a());
        }
        Decision::Deny { reason, .. } => panic!("expected grant, denied with {reason:?}"),
    }

    assert!(effects(&d).contains(&Effect::ConsumeCode));
}

#[test]
fn code_is_valid_at_the_exact_expiry_instant() {
    let c = code();
    let d = redeem(&c, &request(), c.expires_at(), &FixedSha256);
    assert!(matches!(d, Decision::Grant { .. }));
}

#[test]
fn replay_revokes_every_token_derived_from_the_code() {
    let used = AuthorizationCode::from_stored(StoredCode {
        tenant: tenant_a(),
        client: client_a(),
        subject: subject(),
        redirect_uri: redirect(),
        challenge: challenge(),
        issued_at: ISSUED,
        expires_at: ISSUED.saturating_add(DEFAULT_CODE_LIFETIME),
        state: CodeState::Redeemed {
            at: Timestamp::from_unix_seconds(1_010),
        },
        nonce: None,
        scope: None,
        resources: Vec::new(),
    });

    let d = redeem(
        &used,
        &request(),
        Timestamp::from_unix_seconds(1_020),
        &FixedSha256,
    );

    assert_eq!(
        deny_reason(&d),
        &DenialReason::Replayed {
            first_redeemed_at: Timestamp::from_unix_seconds(1_010)
        }
    );
    assert!(
        effects(&d).contains(&Effect::RevokeTokensIssuedForCode),
        "replay must request revocation, got {:?}",
        effects(&d)
    );
}

#[test]
fn replay_of_an_expired_code_still_revokes() {
    let used = AuthorizationCode::from_stored(StoredCode {
        tenant: tenant_a(),
        client: client_a(),
        subject: subject(),
        redirect_uri: redirect(),
        challenge: challenge(),
        issued_at: ISSUED,
        expires_at: Timestamp::from_unix_seconds(1_060),
        state: CodeState::Redeemed {
            at: Timestamp::from_unix_seconds(1_010),
        },
        nonce: None,
        scope: None,
        resources: Vec::new(),
    });

    let d = redeem(
        &used,
        &request(),
        Timestamp::from_unix_seconds(9_999),
        &FixedSha256,
    );

    assert!(matches!(deny_reason(&d), DenialReason::Replayed { .. }));
    assert!(effects(&d).contains(&Effect::RevokeTokensIssuedForCode));
}

#[test]
fn code_is_bound_to_its_client() {
    let mut req = request();
    req.client = client_b();
    let d = redeem(&code(), &req, ISSUED, &FixedSha256);
    assert_eq!(deny_reason(&d), &DenialReason::ClientMismatch);
}

#[test]
fn code_is_bound_to_its_tenant() {
    let mut req = request();
    req.tenant = tenant_b();
    let d = redeem(&code(), &req, ISSUED, &FixedSha256);
    assert_eq!(deny_reason(&d), &DenialReason::TenantMismatch);
}

#[test]
fn redirect_uri_must_match_the_authorization_request() {
    let mut req = request();
    req.redirect_uri = "https://app.example.com/other".to_owned();
    let d = redeem(&code(), &req, ISSUED, &FixedSha256);
    assert_eq!(deny_reason(&d), &DenialReason::RedirectUriMismatch);
}

#[test]
fn loopback_port_variance_is_accepted_at_the_token_endpoint() {
    let loopback = RedirectUri::register("http://127.0.0.1/callback").expect("valid");
    let c = code_with(loopback);

    let req = TokenRequest {
        client: client_a(),
        redirect_uri: "http://127.0.0.1:3118/callback".to_owned(),
        code_verifier: VERIFIER.to_owned(),
        tenant: tenant_a(),
    };

    assert!(matches!(
        redeem(&c, &req, ISSUED, &FixedSha256),
        Decision::Grant { .. }
    ));
}

#[test]
fn expired_code_is_rejected() {
    let c = code();
    let after = Timestamp::from_unix_seconds(c.expires_at().as_unix_seconds() + 1);
    let d = redeem(&c, &request(), after, &FixedSha256);
    assert_eq!(deny_reason(&d), &DenialReason::Expired);
}

#[test]
fn wrong_pkce_verifier_is_rejected() {
    let mut req = request();
    req.code_verifier = "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned();
    let d = redeem(&code(), &req, ISSUED, &FixedSha256);
    assert_eq!(
        deny_reason(&d),
        &DenialReason::Pkce(PkceError::VerifierMismatch)
    );
}

#[test]
fn every_non_replay_denial_consumes_the_code() {
    let mut wrong_client = request();
    wrong_client.client = client_b();

    let mut wrong_tenant = request();
    wrong_tenant.tenant = tenant_b();

    let mut wrong_redirect = request();
    wrong_redirect.redirect_uri = "https://evil.test/cb".to_owned();

    let mut wrong_verifier = request();
    wrong_verifier.code_verifier = "z".repeat(43);

    for req in [wrong_client, wrong_tenant, wrong_redirect, wrong_verifier] {
        let d = redeem(&code(), &req, ISSUED, &FixedSha256);
        assert!(
            effects(&d).contains(&Effect::ConsumeCode),
            "denial did not consume the code: {:?}",
            deny_reason(&d)
        );
    }

    let c = code();
    let after = Timestamp::from_unix_seconds(c.expires_at().as_unix_seconds() + 1);
    let d = redeem(&c, &request(), after, &FixedSha256);
    assert!(effects(&d).contains(&Effect::ConsumeCode));
}

#[test]
fn every_decision_requests_an_audit_record() {
    let mut wrong_client = request();
    wrong_client.client = client_b();

    let decisions = [
        redeem(&code(), &request(), ISSUED, &FixedSha256),
        redeem(&code(), &wrong_client, ISSUED, &FixedSha256),
    ];

    for d in &decisions {
        assert!(
            effects(d)
                .iter()
                .any(|e| matches!(e, Effect::RecordAudit(_))),
            "decision without an audit effect: {d:?}"
        );
    }
}

#[test]
fn all_denials_surface_as_invalid_grant() {
    let mut wrong_client = request();
    wrong_client.client = client_b();

    let mut wrong_verifier = request();
    wrong_verifier.code_verifier = "z".repeat(43);

    for req in [wrong_client, wrong_verifier] {
        let d = redeem(&code(), &req, ISSUED, &FixedSha256);
        assert_eq!(deny_reason(&d).oauth_error_code(), "invalid_grant");
    }
}

#[test]
fn code_lifetime_is_bounded_by_the_rfc_maximum() {
    let too_long = Duration::from_seconds(MAX_CODE_LIFETIME.as_seconds() + 1);
    assert_eq!(
        AuthorizationCode::new(
            tenant_a(),
            client_a(),
            subject(),
            redirect(),
            challenge(),
            ISSUED,
            too_long,
        )
        .unwrap_err(),
        CodeLifetimeError::TooLong {
            seconds: 601,
            max: 600
        }
    );

    for bad in [0, -1] {
        assert_eq!(
            AuthorizationCode::new(
                tenant_a(),
                client_a(),
                subject(),
                redirect(),
                challenge(),
                ISSUED,
                Duration::from_seconds(bad),
            )
            .unwrap_err(),
            CodeLifetimeError::NotPositive { seconds: bad }
        );
    }
}
