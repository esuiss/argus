#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use argus_core::authz::check::{
    BatchSemantics, CheckError, CheckRequest, batch_check, check, explain,
};
use argus_core::authz::grant::{GrantPolicy, GrantRefusal, TupleOp, may_apply};
use argus_core::authz::index::TupleIndex;
use argus_core::authz::model::{EntityRef, Model, ModelError, Rewrite, SubjectRef, Tuple, TypeDef};
use argus_core::authz::proof::{Action, Denied, authorize};
use argus_core::authz::search::{MAX_RESULTS, ResourceSearch, search_resources};

fn e(kind: &str, id: &str) -> EntityRef {
    EntityRef::new(kind, id).expect("entity")
}

fn user(id: &str) -> SubjectRef {
    SubjectRef::direct(e("user", id))
}

fn userset(kind: &str, id: &str, relation: &str) -> SubjectRef {
    SubjectRef::userset(e(kind, id), relation).expect("userset")
}

fn tuple(object: EntityRef, relation: &str, subject: SubjectRef) -> Tuple {
    Tuple::new(object, relation, subject).expect("tuple")
}

fn document_model() -> Model {
    Model::new()
        .with("user", TypeDef::new())
        .with("group", TypeDef::new().with("member", Rewrite::This))
        .with(
            "folder",
            TypeDef::new()
                .with("owner", Rewrite::This)
                .with("viewer", Rewrite::This)
                .with(
                    "can_view",
                    Rewrite::Union(vec![
                        Rewrite::ComputedUserset {
                            relation: "viewer".to_owned(),
                        },
                        Rewrite::ComputedUserset {
                            relation: "owner".to_owned(),
                        },
                    ]),
                ),
        )
        .with(
            "document",
            TypeDef::new()
                .with("parent", Rewrite::This)
                .with("viewer", Rewrite::This)
                .with("banned", Rewrite::This)
                .with(
                    "can_view",
                    Rewrite::Exclusion {
                        base: Box::new(Rewrite::Union(vec![
                            Rewrite::ComputedUserset {
                                relation: "viewer".to_owned(),
                            },
                            Rewrite::TupleToUserset {
                                tupleset: "parent".to_owned(),
                                computed: "can_view".to_owned(),
                            },
                        ])),
                        subtract: Box::new(Rewrite::ComputedUserset {
                            relation: "banned".to_owned(),
                        }),
                    },
                ),
        )
}

fn allowed(
    model: &Model,
    index: &TupleIndex,
    object: EntityRef,
    relation: &str,
    subject: SubjectRef,
) -> bool {
    check(
        model,
        index,
        &CheckRequest {
            object,
            relation: relation.to_owned(),
            subject,
        },
    )
    .expect("check")
    .allowed
}

#[test]
fn a_model_that_defines_a_relation_in_terms_of_itself_is_refused() {
    let model = Model::new().with(
        "document",
        TypeDef::new().with(
            "viewer",
            Rewrite::ComputedUserset {
                relation: "viewer".to_owned(),
            },
        ),
    );

    assert!(matches!(
        model.validate(),
        Err(ModelError::ImmediateSelfReference { .. })
    ));
}

#[test]
fn a_model_referring_to_a_relation_it_never_declares_is_refused() {
    let model = Model::new().with(
        "document",
        TypeDef::new().with(
            "can_view",
            Rewrite::ComputedUserset {
                relation: "editor".to_owned(),
            },
        ),
    );

    assert!(matches!(
        model.validate(),
        Err(ModelError::UnknownRelation { .. })
    ));
}

#[test]
fn the_example_model_is_well_formed() {
    document_model().validate().expect("valid");
}

#[test]
fn an_identifier_carrying_a_grammar_separator_is_refused() {
    for bad in [":", "#", "@"] {
        let id = format!("a{bad}b");
        assert!(
            matches!(
                EntityRef::new("user", &id),
                Err(ModelError::ReservedCharacter(_))
            ),
            "{bad} must not be accepted inside an identifier"
        );
    }
}

#[test]
fn a_directly_written_subject_is_permitted_and_nobody_else_is() {
    let model = document_model();
    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));

    assert!(allowed(
        &model,
        &index,
        e("document", "d1"),
        "viewer",
        user("alice")
    ));
    assert!(!allowed(
        &model,
        &index,
        e("document", "d1"),
        "viewer",
        user("bob")
    ));
}

#[test]
fn membership_of_a_group_that_is_a_member_of_a_group_reaches_through() {
    let model = document_model();
    let mut index = TupleIndex::new();

    index.insert(tuple(e("group", "eng"), "member", user("alice")));
    index.insert(tuple(
        e("group", "all"),
        "member",
        userset("group", "eng", "member"),
    ));
    index.insert(tuple(
        e("document", "d1"),
        "viewer",
        userset("group", "all", "member"),
    ));

    assert!(allowed(
        &model,
        &index,
        e("document", "d1"),
        "can_view",
        user("alice")
    ));
    assert!(!allowed(
        &model,
        &index,
        e("document", "d1"),
        "can_view",
        user("mallory")
    ));
}

#[test]
fn a_folders_viewer_views_the_documents_inside_it() {
    let model = document_model();
    let mut index = TupleIndex::new();

    index.insert(tuple(e("folder", "f1"), "viewer", user("alice")));
    index.insert(tuple(
        e("document", "d1"),
        "parent",
        SubjectRef::direct(e("folder", "f1")),
    ));

    assert!(allowed(
        &model,
        &index,
        e("document", "d1"),
        "can_view",
        user("alice")
    ));
}

#[test]
fn an_exclusion_revokes_what_the_base_granted() {
    let model = document_model();
    let mut index = TupleIndex::new();

    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));
    assert!(allowed(
        &model,
        &index,
        e("document", "d1"),
        "can_view",
        user("alice")
    ));

    index.insert(tuple(e("document", "d1"), "banned", user("alice")));
    assert!(
        !allowed(
            &model,
            &index,
            e("document", "d1"),
            "can_view",
            user("alice")
        ),
        "a ban must outrank the grant it subtracts from"
    );
}

#[test]
fn an_empty_intersection_grants_nothing() {
    let model = Model::new().with(
        "document",
        TypeDef::new()
            .with("viewer", Rewrite::This)
            .with("can_view", Rewrite::Intersection(Vec::new())),
    );
    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));

    assert!(
        !allowed(
            &model,
            &index,
            e("document", "d1"),
            "can_view",
            user("alice")
        ),
        "the vacuous reading of an empty intersection would hand out access"
    );
}

#[test]
fn an_intersection_needs_every_operand() {
    let model = Model::new().with(
        "document",
        TypeDef::new()
            .with("viewer", Rewrite::This)
            .with("employee", Rewrite::This)
            .with(
                "can_view",
                Rewrite::Intersection(vec![
                    Rewrite::ComputedUserset {
                        relation: "viewer".to_owned(),
                    },
                    Rewrite::ComputedUserset {
                        relation: "employee".to_owned(),
                    },
                ]),
            ),
    );

    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));
    assert!(!allowed(
        &model,
        &index,
        e("document", "d1"),
        "can_view",
        user("alice")
    ));

    index.insert(tuple(e("document", "d1"), "employee", user("alice")));
    assert!(allowed(
        &model,
        &index,
        e("document", "d1"),
        "can_view",
        user("alice")
    ));
}

#[test]
fn a_cycle_through_tuples_terminates_and_denies() {
    let model = Model::new().with("group", TypeDef::new().with("member", Rewrite::This));

    let mut index = TupleIndex::new();
    index.insert(tuple(
        e("group", "a"),
        "member",
        userset("group", "b", "member"),
    ));
    index.insert(tuple(
        e("group", "b"),
        "member",
        userset("group", "a", "member"),
    ));

    assert!(!allowed(
        &model,
        &index,
        e("group", "a"),
        "member",
        user("alice")
    ));
}

#[test]
fn a_chain_longer_than_the_depth_limit_is_refused_rather_than_walked() {
    let model = Model::new().with("group", TypeDef::new().with("member", Rewrite::This));

    let mut index = TupleIndex::new();
    for i in 0..40 {
        index.insert(tuple(
            e("group", &format!("g{i}")),
            "member",
            userset("group", &format!("g{}", i + 1), "member"),
        ));
    }
    index.insert(tuple(e("group", "g40"), "member", user("alice")));

    let outcome = check(
        &model,
        &index,
        &CheckRequest {
            object: e("group", "g0"),
            relation: "member".to_owned(),
            subject: user("alice"),
        },
    );

    assert!(
        matches!(outcome, Err(CheckError::DepthExceeded { .. })),
        "a deep chain must be refused, not resolved: {outcome:?}"
    );
}

#[test]
fn a_chain_inside_the_depth_limit_still_resolves() {
    let model = Model::new().with("group", TypeDef::new().with("member", Rewrite::This));

    let mut index = TupleIndex::new();
    for i in 0..5 {
        index.insert(tuple(
            e("group", &format!("g{i}")),
            "member",
            userset("group", &format!("g{}", i + 1), "member"),
        ));
    }
    index.insert(tuple(e("group", "g5"), "member", user("alice")));

    assert!(allowed(
        &model,
        &index,
        e("group", "g0"),
        "member",
        user("alice")
    ));
}

#[test]
fn a_relation_fanning_out_past_the_width_limit_is_refused() {
    let model = Model::new().with("group", TypeDef::new().with("member", Rewrite::This));

    let mut index = TupleIndex::new();
    for i in 0..20 {
        index.insert(tuple(
            e("group", "wide"),
            "member",
            userset("group", &format!("g{i}"), "member"),
        ));
    }

    let outcome = check(
        &model,
        &index,
        &CheckRequest {
            object: e("group", "wide"),
            relation: "member".to_owned(),
            subject: user("alice"),
        },
    );

    assert!(
        matches!(outcome, Err(CheckError::WidthExceeded { .. })),
        "a wide fan-out must be refused: {outcome:?}"
    );
}

#[test]
fn two_questions_that_would_collide_under_a_concatenated_key_stay_separate() {
    let model = Model::new().with(
        "group",
        TypeDef::new()
            .with("bc", Rewrite::This)
            .with("c", Rewrite::This),
    );

    let mut index = TupleIndex::new();
    index.insert(tuple(e("group", "a"), "bc", user("alice")));

    assert!(allowed(
        &model,
        &index,
        e("group", "a"),
        "bc",
        user("alice")
    ));
    assert!(
        !allowed(&model, &index, e("group", "ab"), "c", user("alice")),
        "the answer for group:a#bc must not be reused for group:ab#c"
    );
}

#[test]
fn an_explanation_names_the_rule_that_decided() {
    let model = document_model();
    let mut index = TupleIndex::new();
    index.insert(tuple(e("folder", "f1"), "viewer", user("alice")));
    index.insert(tuple(
        e("document", "d1"),
        "parent",
        SubjectRef::direct(e("folder", "f1")),
    ));

    let (decision, trace) = explain(
        &model,
        &index,
        &CheckRequest {
            object: e("document", "d1"),
            relation: "can_view".to_owned(),
            subject: user("alice"),
        },
    )
    .expect("explain");

    assert!(decision.allowed);
    assert!(
        trace
            .steps
            .iter()
            .any(|s| s.rule == "tuple-to-userset" && s.allowed),
        "the inheritance step must appear in the trace: {trace:?}"
    );
}

struct CanView;
impl Action for CanView {
    const RELATION: &'static str = "can_view";
}

#[test]
fn a_proof_of_authorization_cannot_be_produced_for_a_denied_subject() {
    let model = document_model();
    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));

    let granted = authorize::<_, CanView>(&model, &index, &user("alice"), e("document", "d1"));
    assert!(granted.is_ok());

    let refused = authorize::<_, CanView>(&model, &index, &user("mallory"), e("document", "d1"));
    assert!(matches!(refused, Err(Denied::NotPermitted { .. })));
}

#[test]
fn a_batch_that_short_circuits_reports_the_rest_as_denied() {
    let model = document_model();
    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));
    index.insert(tuple(e("document", "d2"), "viewer", user("alice")));

    let requests: Vec<CheckRequest> = ["dx", "d1", "d2"]
        .into_iter()
        .map(|id| CheckRequest {
            object: e("document", id),
            relation: "can_view".to_owned(),
            subject: user("alice"),
        })
        .collect();

    let out =
        batch_check(&model, &index, &requests, BatchSemantics::DenyOnFirstDeny).expect("batch");

    assert_eq!(out.len(), requests.len());
    assert!(!out.first().expect("a first decision").allowed);
    assert!(
        out.iter().skip(1).all(|d| !d.allowed),
        "an unevaluated entry must read as denied, never as a grant"
    );
}

fn admin_policy() -> GrantPolicy {
    GrantPolicy::new()
        .administered_by("document", "owner")
        .administered_by("folder", "owner")
        .administered_by("group", "owner")
        .structural("group", "parent")
        .structural("document", "parent")
}

fn grant_model() -> Model {
    Model::new()
        .with("user", TypeDef::new())
        .with(
            "group",
            TypeDef::new()
                .with("owner", Rewrite::This)
                .with("parent", Rewrite::This)
                .with(
                    "member",
                    Rewrite::Union(vec![
                        Rewrite::This,
                        Rewrite::TupleToUserset {
                            tupleset: "parent".to_owned(),
                            computed: "member".to_owned(),
                        },
                    ]),
                ),
        )
        .with(
            "document",
            TypeDef::new()
                .with("owner", Rewrite::This)
                .with("viewer", Rewrite::This),
        )
}

#[test]
fn an_actor_cannot_grant_a_relation_it_does_not_hold() {
    let model = grant_model();
    model.validate().expect("valid");

    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "owner", user("alice")));

    let ops = vec![TupleOp::Write(tuple(
        e("document", "d1"),
        "viewer",
        user("bob"),
    ))];

    assert!(matches!(
        may_apply(&model, &index, &admin_policy(), &user("alice"), &ops),
        Err(GrantRefusal::GrantsWhatItDoesNotHold { .. })
    ));

    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));
    may_apply(&model, &index, &admin_policy(), &user("alice"), &ops).expect("now she holds it");
}

#[test]
fn an_actor_with_no_administrative_relation_cannot_write_at_all() {
    let model = grant_model();
    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));

    let ops = vec![TupleOp::Write(tuple(
        e("document", "d1"),
        "viewer",
        user("bob"),
    ))];

    assert!(
        matches!(
            may_apply(&model, &index, &admin_policy(), &user("alice"), &ops),
            Err(GrantRefusal::NotAnAdministrator { .. })
        ),
        "holding a relation must not confer the power to hand it out"
    );
}

#[test]
fn a_type_with_no_administrative_relation_declared_accepts_no_writes() {
    let model = grant_model();
    let mut index = TupleIndex::new();
    index.insert(tuple(e("document", "d1"), "owner", user("alice")));
    index.insert(tuple(e("document", "d1"), "viewer", user("alice")));

    let ops = vec![TupleOp::Write(tuple(
        e("document", "d1"),
        "viewer",
        user("bob"),
    ))];

    let empty = GrantPolicy::new();
    assert!(
        matches!(
            may_apply(&model, &index, &empty, &user("alice"), &ops),
            Err(GrantRefusal::NotAnAdministrator { .. })
        ),
        "an undeclared type must fail closed, not open"
    );
}

#[test]
fn reparenting_a_privileged_group_under_ones_own_is_refused() {
    let model = grant_model();
    let mut index = TupleIndex::new();

    index.insert(tuple(e("group", "mine"), "owner", user("mallory")));
    index.insert(tuple(e("group", "mine"), "member", user("mallory")));
    index.insert(tuple(e("group", "admins"), "owner", user("mallory")));
    index.insert(tuple(e("group", "admins"), "member", user("root")));

    assert!(
        !allowed(
            &model,
            &index,
            e("group", "admins"),
            "member",
            user("mallory")
        ),
        "mallory must not be an admin before the move"
    );

    let ops = vec![TupleOp::Write(tuple(
        e("group", "admins"),
        "parent",
        SubjectRef::direct(e("group", "mine")),
    ))];

    let outcome = may_apply(&model, &index, &admin_policy(), &user("mallory"), &ops);
    assert!(
        matches!(
            outcome,
            Err(GrantRefusal::RaisesTheActorsOwnPermissions { .. })
        ),
        "a move that raises the mover's own permissions must be refused: {outcome:?}"
    );
}

#[test]
fn a_move_that_raises_nobody_is_still_allowed() {
    let model = grant_model();
    let mut index = TupleIndex::new();

    index.insert(tuple(e("group", "mine"), "owner", user("mallory")));
    index.insert(tuple(
        e("group", "mine"),
        "parent",
        SubjectRef::direct(e("group", "other")),
    ));
    index.insert(tuple(e("group", "other"), "owner", user("mallory")));

    let ops = vec![TupleOp::Delete(tuple(
        e("group", "mine"),
        "parent",
        SubjectRef::direct(e("group", "other")),
    ))];

    may_apply(&model, &index, &admin_policy(), &user("mallory"), &ops)
        .expect("removing a parent takes nothing from anyone");
}

#[test]
fn a_search_pages_and_never_exceeds_the_result_ceiling() {
    let model = document_model();
    let mut index = TupleIndex::new();

    for i in 0..25 {
        index.insert(tuple(
            e("document", &format!("d{i:03}")),
            "viewer",
            user("alice"),
        ));
    }

    let first = search_resources(
        &model,
        &index,
        &ResourceSearch {
            subject: user("alice"),
            relation: "can_view".to_owned(),
            object_kind: "document".to_owned(),
            limit: 10,
            after: None,
            step_budget: 50_000,
        },
    )
    .expect("search");

    assert_eq!(first.objects.len(), 10);
    assert!(!first.exhausted);
    let cursor = first.next.clone().expect("a further page");

    let second = search_resources(
        &model,
        &index,
        &ResourceSearch {
            subject: user("alice"),
            relation: "can_view".to_owned(),
            object_kind: "document".to_owned(),
            limit: 10,
            after: Some(cursor.clone()),
            step_budget: 50_000,
        },
    )
    .expect("search");

    assert_eq!(second.objects.len(), 10);
    assert!(
        second.objects.iter().all(|o| o.id() > cursor.as_str()),
        "a page must resume strictly after the cursor"
    );
    assert!(
        first.objects.iter().all(|a| !second.objects.contains(a)),
        "pages must not overlap"
    );
}

#[test]
fn a_search_that_runs_out_of_budget_says_so_instead_of_truncating_silently() {
    let model = document_model();
    let mut index = TupleIndex::new();

    for i in 0..50 {
        index.insert(tuple(
            e("document", &format!("d{i:03}")),
            "viewer",
            user("alice"),
        ));
    }

    let page = search_resources(
        &model,
        &index,
        &ResourceSearch {
            subject: user("alice"),
            relation: "can_view".to_owned(),
            object_kind: "document".to_owned(),
            limit: 100,
            after: None,
            step_budget: 5,
        },
    )
    .expect("search");

    assert!(
        page.exhausted,
        "a partial answer must be flagged, or a caller reads it as complete"
    );
}

#[test]
fn a_search_never_returns_a_resource_the_check_would_deny() {
    let model = document_model();
    let mut index = TupleIndex::new();

    for i in 0..15 {
        index.insert(tuple(
            e("document", &format!("d{i:03}")),
            "viewer",
            user("alice"),
        ));
    }
    index.insert(tuple(e("document", "d003"), "banned", user("alice")));

    let page = search_resources(
        &model,
        &index,
        &ResourceSearch {
            subject: user("alice"),
            relation: "can_view".to_owned(),
            object_kind: "document".to_owned(),
            limit: MAX_RESULTS,
            after: None,
            step_budget: 50_000,
        },
    )
    .expect("search");

    for object in &page.objects {
        assert!(
            allowed(&model, &index, object.clone(), "can_view", user("alice")),
            "{object} was listed but check denies it"
        );
    }
    assert!(
        !page.objects.contains(&e("document", "d003")),
        "the banned document must not be listed"
    );
}
