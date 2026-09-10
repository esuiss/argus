#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use argus_core::authz::check::{CheckError, CheckRequest, check};
use argus_core::authz::index::TupleIndex;
use argus_core::authz::model::{EntityRef, Model, Rewrite, SubjectRef, Tuple, TypeDef};
use argus_core::authz::search::{ResourceSearch, search_resources};
use proptest::prelude::*;

fn e(kind: &str, id: &str) -> EntityRef {
    EntityRef::new(kind, id).expect("entity")
}

// Dışlama YOK: bu model monotondur, dolayısıyla tuple eklemek asla bir erişimi
// kaldıramaz. Monotonluğu ölçmenin doğru yeri budur; `Exclusion` tanımı gereği
// monoton değildir ve ayrı test edilir.
fn monotone_model() -> Model {
    Model::new()
        .with("user", TypeDef::new())
        .with(
            "group",
            TypeDef::new().with("parent", Rewrite::This).with(
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
                .with("parent", Rewrite::This)
                .with("viewer", Rewrite::This)
                .with(
                    "can_view",
                    Rewrite::Union(vec![
                        Rewrite::ComputedUserset {
                            relation: "viewer".to_owned(),
                        },
                        Rewrite::TupleToUserset {
                            tupleset: "parent".to_owned(),
                            computed: "can_view".to_owned(),
                        },
                    ]),
                ),
        )
}

fn full_model() -> Model {
    monotone_model().with(
        "banned_document",
        TypeDef::new()
            .with("viewer", Rewrite::This)
            .with("banned", Rewrite::This)
            .with(
                "can_view",
                Rewrite::Exclusion {
                    base: Box::new(Rewrite::ComputedUserset {
                        relation: "viewer".to_owned(),
                    }),
                    subtract: Box::new(Rewrite::ComputedUserset {
                        relation: "banned".to_owned(),
                    }),
                },
            ),
    )
}

/// Rastgele ama HER ZAMAN iyi biçimli tuple'lar. Modelin reddedeceği bir tuple
/// üretmek çözümleyiciyi değil model doğrulamasını sınardı.
fn any_tuple() -> impl Strategy<Value = Tuple> {
    let user = (0_u8..6).prop_map(|i| SubjectRef::direct(e("user", &format!("u{i}"))));
    let group_member = (0_u8..4).prop_map(|i| {
        SubjectRef::userset(e("group", &format!("g{i}")), "member").expect("userset")
    });

    prop_oneof![
        // group:gN#member@user:uM
        (0_u8..4, user.clone()).prop_map(|(g, s)| {
            Tuple::new(e("group", &format!("g{g}")), "member", s).expect("tuple")
        }),
        // group:gN#parent@group:gM
        (0_u8..4, 0_u8..4).prop_map(|(a, b)| {
            Tuple::new(
                e("group", &format!("g{a}")),
                "parent",
                SubjectRef::direct(e("group", &format!("g{b}"))),
            )
            .expect("tuple")
        }),
        // document:dN#viewer@(user | group#member)
        (0_u8..4, prop_oneof![user.clone(), group_member]).prop_map(|(d, s)| {
            Tuple::new(e("document", &format!("d{d}")), "viewer", s).expect("tuple")
        }),
        // document:dN#parent@document:dM
        (0_u8..4, 0_u8..4).prop_map(|(a, b)| {
            Tuple::new(
                e("document", &format!("d{a}")),
                "parent",
                SubjectRef::direct(e("document", &format!("d{b}"))),
            )
            .expect("tuple")
        }),
    ]
}

fn index_of(tuples: &[Tuple]) -> TupleIndex {
    let mut index = TupleIndex::new();
    for tuple in tuples {
        index.insert(tuple.clone());
    }
    index
}

fn decide(
    model: &Model,
    index: &TupleIndex,
    object: EntityRef,
    relation: &str,
    subject: &SubjectRef,
) -> Result<bool, CheckError> {
    Ok(check(
        model,
        index,
        &CheckRequest {
            object,
            relation: relation.to_owned(),
            subject: subject.clone(),
        },
    )?
    .allowed)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// §20 §6.2: monoton bir modelde tuple eklemek erişimi ASLA kaldırmaz.
    /// Bu tersine dönerse birileri sessizce bir dışlama eklemiştir.
    #[test]
    fn adding_a_tuple_never_takes_access_away(
        tuples in prop::collection::vec(any_tuple(), 0..14),
        extra in any_tuple(),
        who in 0_u8..6,
        which in 0_u8..4,
    ) {
        let model = monotone_model();
        let subject = SubjectRef::direct(e("user", &format!("u{who}")));
        let object = e("document", &format!("d{which}"));

        let before = index_of(&tuples);
        let mut after = before.clone();
        after.insert(extra);

        let a = decide(&model, &before, object.clone(), "can_view", &subject);
        let b = decide(&model, &after, object, "can_view", &subject);

        // Sınır aşımı iki tarafta da meşru bir sonuçtur; karşılaştırılan yalnızca
        // ikisinin de karar verebildiği durumlar.
        if let (Ok(a), Ok(b)) = (a, b) {
            prop_assert!(!a || b, "a tuple removed access in a monotone model");
        }
    }

    /// §20 §6.2 invariant 4: search, check'in reddedeceği bir kaynağı asla
    /// listelemez. Bu bölümdeki beş CVE'nin sınıfı tam olarak ikisinin
    /// ayrışmasıdır.
    #[test]
    fn search_never_lists_what_check_would_deny(
        tuples in prop::collection::vec(any_tuple(), 0..14),
        who in 0_u8..6,
    ) {
        let model = full_model();
        let index = index_of(&tuples);
        let subject = SubjectRef::direct(e("user", &format!("u{who}")));

        let page = search_resources(
            &model,
            &index,
            &ResourceSearch {
                subject: subject.clone(),
                relation: "can_view".to_owned(),
                object_kind: "document".to_owned(),
                limit: 100,
                after: None,
                step_budget: 20_000,
            },
        );

        let Ok(page) = page else {
            return Ok(());
        };

        for object in &page.objects {
            if let Ok(allowed) = decide(&model, &index, object.clone(), "can_view", &subject) {
                prop_assert!(allowed, "{object} was listed but check denies it");
            }
        }
    }

    /// Karar deterministiktir: aynı grafik, aynı soru, aynı cevap. Memo
    /// anahtarlarının çakışması bunu ilk bozacak şeydir.
    #[test]
    fn the_same_question_always_gets_the_same_answer(
        tuples in prop::collection::vec(any_tuple(), 0..14),
        who in 0_u8..6,
        which in 0_u8..4,
    ) {
        let model = full_model();
        let index = index_of(&tuples);
        let subject = SubjectRef::direct(e("user", &format!("u{who}")));
        let object = e("document", &format!("d{which}"));

        let first = decide(&model, &index, object.clone(), "can_view", &subject);
        let second = decide(&model, &index, object, "can_view", &subject);

        prop_assert_eq!(first, second);
    }

    /// Hiçbir tuple kümesi çözümleyiciyi sonsuza sokmaz veya panikletmez.
    /// Döngüler ve derin zincirler dahil, her zaman bir cevap ya da bir sınır
    /// hatası döner.
    #[test]
    fn resolution_always_terminates(
        tuples in prop::collection::vec(any_tuple(), 0..24),
        who in 0_u8..6,
        which in 0_u8..4,
    ) {
        let model = full_model();
        let index = index_of(&tuples);
        let subject = SubjectRef::direct(e("user", &format!("u{who}")));

        let outcome = decide(
            &model,
            &index,
            e("group", &format!("g{}", which % 4)),
            "member",
            &subject,
        );

        let bounded = outcome.is_ok()
            || matches!(
                outcome,
                Err(CheckError::DepthExceeded { .. } | CheckError::WidthExceeded { .. })
            );
        prop_assert!(bounded);
    }

    /// Yazılmamış bir özne, hiçbir yoldan erişim kazanamaz. Grafikte hiç
    /// görünmeyen bir kullanıcı için cevap her zaman hayırdır.
    #[test]
    fn a_subject_that_appears_nowhere_is_never_permitted(
        tuples in prop::collection::vec(any_tuple(), 0..14),
        which in 0_u8..4,
    ) {
        let model = full_model();
        let index = index_of(&tuples);
        let stranger = SubjectRef::direct(e("user", "nobody-writes-this-one"));

        if let Ok(allowed) = decide(
            &model,
            &index,
            e("document", &format!("d{which}")),
            "can_view",
            &stranger,
        ) {
            prop_assert!(!allowed);
        }
    }
}
