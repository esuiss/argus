#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use argus_core::aal::Aal;
use argus_core::delegation::{
    DelegationFault, DelegationRecord, MAX_HOPS, actor_depth, canonical_actor, check,
    check_against_token, effective_expiry, effective_floor, effective_scope, outermost_actor,
    parse_chain, signing_input,
};
use argus_core::time::Timestamp;
use serde_json::json;

const NOW: Timestamp = Timestamp::from_unix_seconds(1_800_000_000);

fn at(offset: i64) -> Timestamp {
    Timestamp::from_unix_seconds(NOW.as_unix_seconds() + offset)
}

fn hop(delegator: &str, delegatee: &str, scope: &[&str], expires: i64) -> DelegationRecord {
    DelegationRecord {
        delegator_id: delegator.to_owned(),
        delegatee_id: delegatee.to_owned(),
        issued_at: at(-60),
        expires_at: at(expires),
        scope: scope.iter().map(|s| (*s).to_owned()).collect(),
        floor: None,
        as_signature: "as-sig".to_owned(),
        delegator_signature: "delegator-sig".to_owned(),
    }
}

fn two_hops() -> Vec<DelegationRecord> {
    vec![
        hop(
            "user:barbara",
            "agent:orchestrator",
            &["chat.read", "chat.write"],
            3_600,
        ),
        hop("agent:orchestrator", "agent:worker", &["chat.read"], 1_800),
    ]
}

#[test]
fn a_well_formed_chain_passes_every_invariant() {
    check(&two_hops(), 2, 4, NOW).expect("a chain this server issued has to verify");
}

#[test]
fn a_hop_delegated_by_somebody_the_previous_hop_never_handed_to_is_refused() {
    let mut chain = two_hops();
    chain[1].delegator_id = "agent:stranger".to_owned();

    assert!(
        matches!(
            check(&chain, 2, 4, NOW).unwrap_err(),
            DelegationFault::Unlinked { index: 1, .. }
        ),
        "a chain that does not link is a collection of unrelated grants, not a delegation"
    );
}

#[test]
fn a_hop_that_widens_the_scope_it_was_given_is_refused() {
    let mut chain = two_hops();
    chain[1].scope = vec!["chat.read".to_owned(), "chat.admin".to_owned()];

    assert!(matches!(
        check(&chain, 2, 4, NOW).unwrap_err(),
        DelegationFault::ScopeWidened { index: 1, .. }
    ));
}

#[test]
fn a_hop_may_narrow_the_scope_it_was_given() {
    let mut chain = two_hops();
    chain[1].scope = Vec::new();
    check(&chain, 2, 4, NOW).expect("giving away less than you hold is always allowed");
}

#[test]
fn a_hop_that_outlives_its_parent_is_refused() {
    let mut chain = two_hops();
    chain[1].expires_at = at(7_200);

    assert!(
        matches!(
            check(&chain, 2, 4, NOW).unwrap_err(),
            DelegationFault::ExpiryExtended { index: 1 }
        ),
        "a child that outlives its parent survives the revocation of the grant it came from"
    );
}

#[test]
fn a_hop_issued_before_the_delegation_it_came_from_is_refused() {
    let mut chain = two_hops();
    chain[1].issued_at = at(-3_600);

    assert!(matches!(
        check(&chain, 2, 4, NOW).unwrap_err(),
        DelegationFault::IssuedBeforeItsParent { index: 1 }
    ));
}

#[test]
fn a_hop_that_lowers_the_assurance_floor_is_refused() {
    let mut chain = two_hops();
    chain[0].floor = Some(Aal::Two);
    chain[1].floor = Some(Aal::One);

    assert!(matches!(
        check(&chain, 2, 4, NOW).unwrap_err(),
        DelegationFault::FloorRelaxed { index: 1 }
    ));
}

#[test]
fn a_hop_that_drops_the_assurance_floor_entirely_is_refused() {
    let mut chain = two_hops();
    chain[0].floor = Some(Aal::Two);
    chain[1].floor = None;

    assert!(
        matches!(
            check(&chain, 2, 4, NOW).unwrap_err(),
            DelegationFault::FloorRelaxed { index: 1 }
        ),
        "omitting the floor is the easiest way to relax it, so absence has to count as relaxation"
    );
}

#[test]
fn a_hop_that_raises_the_assurance_floor_is_allowed() {
    let mut chain = two_hops();
    chain[0].floor = Some(Aal::Two);
    chain[1].floor = Some(Aal::Three);
    check(&chain, 2, 4, NOW).expect("raising the floor narrows, and narrowing is allowed");
}

#[test]
fn a_chain_that_hands_back_to_a_party_already_in_it_is_refused() {
    let mut chain = two_hops();
    chain.push(hop(
        "agent:worker",
        "agent:orchestrator",
        &["chat.read"],
        900,
    ));

    assert!(matches!(
        check(&chain, 3, 4, NOW).unwrap_err(),
        DelegationFault::Cycle { .. }
    ));
}

#[test]
fn a_chain_that_hands_back_to_the_original_subject_is_refused() {
    let mut chain = two_hops();
    chain.push(hop("agent:worker", "user:barbara", &["chat.read"], 900));

    assert!(
        matches!(
            check(&chain, 3, 4, NOW).unwrap_err(),
            DelegationFault::Cycle { .. }
        ),
        "a loop back to the human would let an agent launder its own authority"
    );
}

#[test]
fn a_chain_longer_than_the_draft_allows_is_refused() {
    let mut chain = vec![hop("user:barbara", "agent:0", &["a"], 3_600)];
    for index in 0..MAX_HOPS {
        chain.push(hop(
            &format!("agent:{index}"),
            &format!("agent:{}", index + 1),
            &["a"],
            3_600 - i64::try_from(index).unwrap_or(0),
        ));
    }

    assert!(matches!(
        check(&chain, chain.len(), 16, NOW).unwrap_err(),
        DelegationFault::TooLong { .. }
    ));
}

#[test]
fn a_record_missing_either_signature_is_refused() {
    let mut chain = two_hops();
    chain[1].as_signature = String::new();
    assert!(matches!(
        check(&chain, 2, 4, NOW).unwrap_err(),
        DelegationFault::Unsigned {
            which: "authorization server",
            ..
        }
    ));

    let mut chain = two_hops();
    chain[0].delegator_signature = String::new();
    assert!(
        matches!(
            check(&chain, 2, 4, NOW).unwrap_err(),
            DelegationFault::Unsigned {
                which: "delegator",
                ..
            }
        ),
        "the delegator's own signature is what stops the server from inventing a delegation"
    );
}

#[test]
fn an_expired_hop_refuses_the_whole_chain() {
    let mut chain = two_hops();
    chain[1].expires_at = at(-1);

    assert_eq!(
        check(&chain, 2, 4, NOW).unwrap_err(),
        DelegationFault::Expired
    );
}

#[test]
fn a_declared_depth_that_does_not_match_the_records_is_refused() {
    assert!(matches!(
        check(&two_hops(), 1, 4, NOW).unwrap_err(),
        DelegationFault::DepthMismatch {
            declared: 1,
            actual: 2
        }
    ));
}

#[test]
fn a_declared_depth_above_the_declared_maximum_is_refused() {
    assert!(matches!(
        check(&two_hops(), 2, 1, NOW).unwrap_err(),
        DelegationFault::DepthAboveMaximum { .. }
    ));
}

#[test]
fn an_empty_chain_is_refused() {
    assert_eq!(check(&[], 0, 4, NOW).unwrap_err(), DelegationFault::Empty);
}

#[test]
fn the_token_subject_must_be_the_party_the_chain_starts_from() {
    let chain = two_hops();

    check_against_token(&chain, "user:barbara", "agent:worker").expect("consistent");

    assert_eq!(
        check_against_token(&chain, "user:someone-else", "agent:worker").unwrap_err(),
        DelegationFault::SubjectNotTheDelegator,
        "a chain that does not start at the token's subject describes somebody else's authority"
    );
}

#[test]
fn the_outermost_actor_must_be_the_party_the_chain_ends_at() {
    let chain = two_hops();

    assert_eq!(
        check_against_token(&chain, "user:barbara", "agent:orchestrator").unwrap_err(),
        DelegationFault::ActorNotTheDelegatee
    );
}

#[test]
fn the_effective_grant_is_the_narrowest_link_in_the_chain() {
    let chain = two_hops();

    assert_eq!(effective_scope(&chain), ["chat.read"]);
    assert_eq!(effective_expiry(&chain), Some(at(1_800)));
}

#[test]
fn the_effective_floor_is_the_highest_any_link_demanded() {
    let mut chain = two_hops();
    chain[0].floor = Some(Aal::Two);
    chain[1].floor = Some(Aal::Three);

    assert_eq!(effective_floor(&chain), Some(Aal::Three));
    assert_eq!(effective_floor(&two_hops()), None);
}

#[test]
fn the_signing_input_carries_the_terms_and_never_the_signatures() {
    let input = signing_input(&two_hops()[0]);

    assert_eq!(input["delegator_id"], "user:barbara");
    assert_eq!(input["delegatee_id"], "agent:orchestrator");
    assert_eq!(input["scope"], "chat.read chat.write");
    assert!(
        input.get("as_signature").is_none() && input.get("delegator_signature").is_none(),
        "a signature that covered itself could never be computed: {input}"
    );
}

#[test]
fn the_signing_input_changes_when_any_term_changes() {
    let base = signing_input(&two_hops()[0]);

    let mut widened = two_hops();
    widened[0].scope.push("chat.admin".to_owned());

    assert_ne!(base, signing_input(&widened[0]));
}

#[test]
fn a_chain_is_read_from_its_json_form() {
    let raw = json!([
        {
            "delegator_id": "user:barbara",
            "delegatee_id": "agent:orchestrator",
            "iat": at(-60).as_unix_seconds(),
            "exp": at(3_600).as_unix_seconds(),
            "scope": "chat.read chat.write",
            "acr_floor": "aal2",
            "as_signature": "a",
            "delegator_signature": "b"
        }
    ]);

    let chain = parse_chain(&raw).expect("parse");
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].scope, ["chat.read", "chat.write"]);
    assert_eq!(chain[0].floor, Some(Aal::Two));
}

#[test]
fn a_record_missing_a_required_field_is_refused_rather_than_defaulted() {
    let raw = json!([{ "delegator_id": "user:barbara" }]);

    assert!(matches!(
        parse_chain(&raw).unwrap_err(),
        DelegationFault::MissingField { .. }
    ));
}

#[test]
fn a_json_chain_longer_than_the_ceiling_is_refused_before_it_is_read() {
    let record = json!({
        "delegator_id": "a", "delegatee_id": "b",
        "iat": 1, "exp": 2, "scope": "",
        "as_signature": "x", "delegator_signature": "y"
    });

    let raw = serde_json::Value::Array(vec![record; 32]);

    assert!(matches!(
        parse_chain(&raw).unwrap_err(),
        DelegationFault::TooLong { .. }
    ));
}

#[test]
fn the_actor_chain_supports_the_depth_the_profile_asks_for() {
    let act = json!({
        "iss": "https://idp.test", "sub": "agent:d",
        "act": { "iss": "https://idp.test", "sub": "agent:c",
            "act": { "iss": "https://idp.test", "sub": "agent:b",
                "act": { "iss": "https://idp.test", "sub": "agent:a" } } }
    });

    assert_eq!(actor_depth(&act), 4);
    assert_eq!(outermost_actor(&act).as_deref(), Some("agent:d"));
    assert_eq!(
        canonical_actor(&act),
        Some(("https://idp.test".to_owned(), "agent:d".to_owned())),
        "the actor's identity is the issuer and subject together, not the subject alone"
    );
}

#[test]
fn an_actor_without_an_issuer_has_no_canonical_identity() {
    assert!(canonical_actor(&json!({ "sub": "agent:a" })).is_none());
}
