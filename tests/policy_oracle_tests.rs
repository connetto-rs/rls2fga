//! The seam a consumer uses to classify what this crate refuses.

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::classifier::oracle::{
    consult_oracle, OracleAnswer, PolicyClause, PolicyOracle, RefusedExpr,
};
use rls2fga::classifier::patterns::{
    ClassifiedExpr, ClassifiedPolicy, ConstantBool, ExistsMembership, IndirectMembership,
    MembershipInCallerSet, MembershipJoinPair, ParentInheritance, PatternClass, ResidualPredicates,
};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{ColumnName, ConfidenceLevel, TableId, TranslationNote};

mod support;

/// Answers the bit test this crate has no translation for, claiming every marked row is
/// readable by anyone.
struct BitFlagIsPublic;

impl PolicyOracle for BitFlagIsPublic {
    fn classify(&self, refused: &RefusedExpr<'_>) -> OracleAnswer {
        if refused.sql_text().contains('&') {
            OracleAnswer::Classified(Box::new(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::A,
            }))
        } else {
            OracleAnswer::Bailed
        }
    }
}

/// Knows the same bit test, and knows it grants nobody.
struct BitFlagGrantsNobody;

impl PolicyOracle for BitFlagGrantsNobody {
    fn classify(&self, refused: &RefusedExpr<'_>) -> OracleAnswer {
        if refused.sql_text().contains('&') {
            OracleAnswer::Denied
        } else {
            OracleAnswer::Bailed
        }
    }
}

/// Implements nothing, which is the closed default.
struct Silent;

impl PolicyOracle for Silent {}

fn translator() -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(ConfidenceLevel::B)
        .build()
}

fn dsl_of(db: &ParserDB, classified: &[ClassifiedPolicy]) -> String {
    support::plan_at(
        classified.to_vec(),
        db,
        translator().registry(),
        ConfidenceLevel::B,
    )
    .model()
}

fn tuples_of(db: &ParserDB, classified: &[ClassifiedPolicy]) -> String {
    format_tuples(
        support::plan_at(
            classified.to_vec(),
            db,
            translator().registry(),
            ConfidenceLevel::B,
        )
        .tuple_queries(),
    )
}

fn relation(dsl: &str, relation: &str) -> Option<String> {
    dsl.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&format!("define {relation}: ")))
        .map(str::to_string)
}

/// A refusal sits two levels down here: the parent join is recognized, its parent-side
/// rule is an `OR`, and only one branch of that `OR` is refused. A walk that knows only
/// composites never reaches it, and nothing says so: the model just denies.
#[test]
fn a_refusal_nested_under_a_parent_join_reaches_the_oracle() {
    let schema = "CREATE TABLE folders(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, folder_id UUID REFERENCES folders(id));\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\
                  SELECT 1 FROM folders f WHERE f.id = docs.folder_id \
                  AND (f.owner_id = current_user OR (f.bits & 2) = 2)));\n";
    let db = parse_schema(schema).expect("schema parses");

    let mut classified = translator().classify(&db);
    let answered = consult_oracle(&mut classified, &BitFlagIsPublic);

    assert_eq!(
        answered.len(),
        1,
        "the nested refusal must reach the oracle, got {answered:?}"
    );
    assert_eq!(answered[0].sql_text(), "(bits & 2) = 2");
    assert_eq!(answered[0].clause(), PolicyClause::Using);
    assert_eq!(answered[0].policy_name(), "docs_sel");

    // And the answer has to survive the confidence filter, which means every pattern
    // enclosing the refusal was regraded.
    let dsl = dsl_of(&db, &classified);
    let select = relation(&dsl, "can_select").expect("docs defines can_select");
    assert_ne!(
        select, "no_access",
        "the answered clause must not be dropped:\n{dsl}"
    );
}

/// The grades are the whole reason a hand-rolled walk fails silently. Substituting the
/// leaf is not enough: every pattern above it still carries the grade the refusal
/// dragged it to, and the filter drops the clause for a refusal that no longer exists.
#[test]
fn every_pattern_enclosing_an_answered_refusal_is_regraded() {
    let schema = "CREATE TABLE folders(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, folder_id UUID REFERENCES folders(id));\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\
                  SELECT 1 FROM folders f WHERE f.id = docs.folder_id \
                  AND (f.owner_id = current_user OR (f.bits & 2) = 2)));\n";
    let db = parse_schema(schema).expect("schema parses");

    let mut classified = translator().classify(&db);
    let before = classified[0]
        .using_classification()
        .expect("the policy has a USING clause")
        .confidence;
    assert_eq!(
        before,
        ConfidenceLevel::D,
        "the refusal drags the outermost grade down"
    );

    consult_oracle(&mut classified, &BitFlagIsPublic);

    let outer = classified[0]
        .using_classification()
        .expect("the clause survives");
    assert_eq!(
        outer.confidence,
        ConfidenceLevel::B,
        "a composed pattern grades B once nothing below it is refused"
    );
    // The pattern in between was regraded too, not just the outermost one.
    let PatternClass::P5ParentInheritance(ParentInheritance { inner_pattern, .. }) = &outer.pattern
    else {
        panic!("expected a parent join, got {:?}", outer.pattern);
    };
    assert_eq!(
        inner_pattern.confidence,
        ConfidenceLevel::B,
        "the parent-side composite must be regraded as well"
    );
}

/// An oracle grades its own answer, and that grade still faces the operator's
/// threshold. Otherwise the seam is a way around the gate rather than a way through it,
/// and a guess an operator would have rejected reaches the model.
#[test]
fn an_oracle_answer_below_the_threshold_is_still_dropped() {
    /// Answers, but only claims C.
    struct Unsure;

    impl PolicyOracle for Unsure {
        fn classify(&self, _refused: &RefusedExpr<'_>) -> OracleAnswer {
            OracleAnswer::Classified(Box::new(ClassifiedExpr {
                pattern: PatternClass::P10ConstantBool(ConstantBool { value: true }),
                confidence: ConfidenceLevel::C,
            }))
        }
    }

    let schema = "CREATE TABLE folders(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  CREATE TABLE docs(id UUID PRIMARY KEY, folder_id UUID REFERENCES folders(id));\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (EXISTS (\
                  SELECT 1 FROM folders f WHERE f.id = docs.folder_id \
                  AND (f.owner_id = current_user OR (f.bits & 2) = 2)));\n";
    let db = parse_schema(schema).expect("schema parses");

    let mut classified = translator().classify(&db);
    let answered = consult_oracle(&mut classified, &Unsure);
    assert_eq!(answered.len(), 1, "the oracle did answer");
    assert_eq!(answered[0].confidence(), ConfidenceLevel::C);

    // The grade the oracle claimed has to propagate outward, not be assumed.
    let outer = classified[0]
        .using_classification()
        .expect("the clause is still there");
    assert_eq!(
        outer.confidence,
        ConfidenceLevel::C,
        "the claimed grade must reach the outermost pattern"
    );

    let dsl = dsl_of(&db, &classified);
    assert_eq!(
        relation(&dsl, "can_select").as_deref(),
        Some("no_access"),
        "a C answer must not pass a B threshold:\n{dsl}"
    );
}

/// Bailing is the closed default, it must stay closed, and it must keep reporting the
/// gap, because nobody has said what the expression means.
#[test]
fn an_oracle_that_bails_changes_nothing() {
    let schema = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";
    let db = parse_schema(schema).expect("schema parses");

    let untouched = translator().classify(&db);
    let mut classified = translator().classify(&db);
    let answered = consult_oracle(&mut classified, &Silent);

    assert!(answered.is_empty(), "a bail records nothing");
    assert_eq!(
        classified[0].using_classification(),
        untouched[0].using_classification(),
        "a bail leaves the classification exactly as it was"
    );
    let dsl = dsl_of(&db, &classified);
    assert_eq!(
        relation(&dsl, "can_select").as_deref(),
        Some("no_access"),
        "the refusal still denies:\n{dsl}"
    );
    assert!(
        claims_the_model_is_narrower_than_rls(&db, &classified),
        "a bail leaves the gap reported"
    );
}

/// Denying deliberately is the other half of what `None` used to mean. It denies just
/// as a bail does, and it is not a gap: someone looked at the expression and said it
/// grants nobody, so reporting "the model denies what RLS grants" would be wrong.
#[test]
fn an_oracle_that_denies_deliberately_reports_no_gap() {
    let schema = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";
    let db = parse_schema(schema).expect("schema parses");

    let mut classified = translator().classify(&db);
    let answered = consult_oracle(&mut classified, &BitFlagGrantsNobody);

    assert_eq!(answered.len(), 1, "the oracle took responsibility for it");
    let dsl = dsl_of(&db, &classified);
    assert_eq!(
        relation(&dsl, "can_select").as_deref(),
        Some("no_access"),
        "a deliberate denial denies:\n{dsl}"
    );
    assert!(
        !claims_the_model_is_narrower_than_rls(&db, &classified),
        "an answered expression is not a translation gap"
    );
}

/// Whether the report still claims the model is narrower than the database, which is
/// the sentence a deliberate denial makes untrue.
fn claims_the_model_is_narrower_than_rls(db: &ParserDB, classified: &[ClassifiedPolicy]) -> bool {
    support::plan_at(
        classified.to_vec(),
        db,
        translator().registry(),
        ConfidenceLevel::B,
    )
    .notes()
    .iter()
    .any(|note| note.message().contains("the model denies what RLS grants"))
}

/// `WITH CHECK` is a second clause, and a refusal there is just as closed.
#[test]
fn a_refusal_in_with_check_reaches_the_oracle() {
    let schema = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_ins ON docs FOR INSERT WITH CHECK ((bits & 2) = 2);\n";
    let db = parse_schema(schema).expect("schema parses");

    let mut classified = translator().classify(&db);
    let answered = consult_oracle(&mut classified, &BitFlagIsPublic);

    assert_eq!(answered.len(), 1, "got {answered:?}");
    assert_eq!(answered[0].clause(), PolicyClause::WithCheck);
    let dsl = dsl_of(&db, &classified);
    assert_ne!(
        relation(&dsl, "can_insert").as_deref(),
        Some("no_access"),
        "the answered WITH CHECK must reach can_insert:\n{dsl}"
    );
}

/// An oracle-supplied pattern is emitted exactly as one the crate recognized itself,
/// which is what makes the seam worth having rather than a second translation path.
#[test]
fn an_answered_pattern_emits_what_the_crate_emits_for_it() {
    let refused = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                   ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                   CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";
    let native = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                  ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY docs_sel ON docs FOR SELECT USING (TRUE);\n";

    let refused_db = parse_schema(refused).expect("schema parses");
    let mut answered = translator().classify(&refused_db);
    consult_oracle(&mut answered, &BitFlagIsPublic);

    let native_db = parse_schema(native).expect("schema parses");
    let recognized = translator().classify(&native_db);

    assert_eq!(
        dsl_of(&refused_db, &answered),
        dsl_of(&native_db, &recognized),
        "an answered pattern must produce the same model"
    );
    assert_eq!(
        tuples_of(&refused_db, &answered),
        tuples_of(&native_db, &recognized),
        "an answered pattern must produce the same tuples"
    );
}

/// Answers the bit test with a caller-set membership whose two pairs match no key of
/// either table, which the recognizer would never have produced.
struct UnkeyedShare;

impl PolicyOracle for UnkeyedShare {
    fn classify(&self, refused: &RefusedExpr<'_>) -> OracleAnswer {
        if !refused.sql_text().contains('&') {
            return OracleAnswer::Bailed;
        }
        let pair = |join: &str, outer: &str| MembershipJoinPair {
            join_column: ColumnName::from_stored(join),
            outer_column: ColumnName::from_stored(outer),
        };
        OracleAnswer::Classified(Box::new(ClassifiedExpr {
            pattern: PatternClass::P18MembershipInCallerSet(MembershipInCallerSet {
                membership: ExistsMembership {
                    join_table: TableId::from_stored(None, "shares".to_string()),
                    pairs: vec![pair("paper_batch", "batch"), pair("paper_lane", "lane")],
                    user_column: ColumnName::from_stored("viewer"),
                    extra_predicates: ResidualPredicates::default(),
                },
                separator: Some(",".to_string()),
                source: SessionAttribute::setting(
                    "app.subjects",
                    SessionAttributeKind::SetAttribute,
                ),
            }),
            confidence: ConfidenceLevel::A,
        }))
    }
}

/// The pairing rules are applied where the model is built, not only where a policy is
/// read, so an oracle handing over a membership the recognizer would have refused is
/// refused with the same reason and falls closed.
#[test]
fn an_oracle_supplied_membership_obeys_the_pairing_rules() {
    let schema = "CREATE TABLE papers(id INT PRIMARY KEY, batch TEXT, lane TEXT, bits INT);\n\
                  CREATE TABLE shares(id INT PRIMARY KEY, paper_batch TEXT, paper_lane TEXT, viewer TEXT);\n\
                  ALTER TABLE papers ENABLE ROW LEVEL SECURITY;\n\
                  CREATE POLICY papers_p ON papers FOR SELECT USING ((bits & 2) = 2);\n";
    let db = parse_schema(schema).expect("schema parses");

    let mut classified = translator().classify(&db);
    let answered = consult_oracle(&mut classified, &UnkeyedShare);
    assert_eq!(answered.len(), 1, "the oracle took responsibility for it");

    let outputs = support::plan_at(classified, &db, translator().registry(), ConfidenceLevel::B);
    let dsl = outputs.model();
    assert_eq!(
        relation(&dsl, "can_select").as_deref(),
        Some("no_access"),
        "an unkeyed pairing falls closed:\n{dsl}"
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ExpressionRefused { policy, reason }
                if policy == "papers_p" && reason.contains("match neither a declared foreign key")
        )),
        "the refusal names the pairing rule: {:?}",
        outputs.notes()
    );
}

#[test]
fn oracle_indirect_memberships_cannot_bypass_key_and_scope_validation() {
    struct Answer(IndirectMembership);

    impl PolicyOracle for Answer {
        fn classify(&self, _refused: &RefusedExpr<'_>) -> OracleAnswer {
            OracleAnswer::Classified(Box::new(ClassifiedExpr {
                pattern: PatternClass::P19IndirectMembership(self.0.clone()),
                confidence: ConfidenceLevel::B,
            }))
        }
    }

    fn pair(join: &str, outer: &str) -> MembershipJoinPair {
        MembershipJoinPair {
            join_column: ColumnName::from_stored(join),
            outer_column: ColumnName::from_stored(outer),
        }
    }

    let schema = "
        CREATE TABLE owners (tenant TEXT, id TEXT, PRIMARY KEY (tenant, id));
        CREATE TABLE other_owners (tenant TEXT, id TEXT, PRIMARY KEY (tenant, id));
        CREATE TABLE docs (tenant TEXT, id INT, bits INT, PRIMARY KEY (tenant, id));
        CREATE TABLE other_docs (tenant TEXT, id INT, PRIMARY KEY (tenant, id));
        CREATE TABLE links (
            doc_tenant TEXT, doc_id INT, owner_tenant TEXT, owner_id TEXT,
            other_tenant TEXT, other_id INT, unkeyed TEXT,
            PRIMARY KEY (doc_tenant, doc_id, owner_tenant, owner_id),
            FOREIGN KEY (doc_tenant, doc_id) REFERENCES docs(tenant, id),
            FOREIGN KEY (other_tenant, other_id) REFERENCES other_docs(tenant, id),
            FOREIGN KEY (owner_tenant, owner_id) REFERENCES owners(tenant, id));
        CREATE TABLE members (
            owner_tenant TEXT, owner_id TEXT, member TEXT, expires_at TIMESTAMPTZ,
            PRIMARY KEY (owner_tenant, owner_id, member),
            FOREIGN KEY (owner_tenant, owner_id) REFERENCES owners(tenant, id));
        ALTER TABLE docs ENABLE ROW LEVEL SECURITY;";
    let native = parse_schema(&format!(
        "{schema}
        CREATE POLICY docs_read ON docs FOR SELECT USING (EXISTS (
            SELECT 1 FROM links l
            WHERE l.doc_tenant = docs.tenant AND l.doc_id = docs.id
            AND EXISTS (SELECT 1 FROM members m
                WHERE m.owner_tenant = l.owner_tenant AND m.owner_id = l.owner_id
                AND m.member = current_user AND m.expires_at > now())));"
    ))
    .unwrap();
    let classified = translator().classify(&native);
    let PatternClass::P19IndirectMembership(original) =
        &classified[0].using_classification().unwrap().pattern
    else {
        panic!("expected indirect membership, got {classified:?}");
    };

    let mut cases = Vec::new();
    let mut invalid = original.clone();
    invalid.memberships.clear();
    cases.push(("no far membership", invalid));
    let mut invalid = original.clone();
    invalid.owner_columns = vec![ColumnName::from_stored("unkeyed")];
    cases.push(("undeclared owner key", invalid));
    let mut invalid = original.clone();
    invalid.owner_table = TableId::from_stored(None, "other_owners".to_string());
    cases.push(("different owner table", invalid));
    let mut invalid = original.clone();
    invalid.owner_columns.reverse();
    cases.push(("reversed owner key", invalid));
    let mut invalid = original.clone();
    invalid.pairs.clear();
    cases.push(("uncorrelated closure", invalid));
    let mut invalid = original.clone();
    invalid.pairs = vec![pair("other_tenant", "tenant"), pair("other_id", "id")];
    cases.push(("different guarded table", invalid));
    let mut invalid = original.clone();
    invalid.pairs = vec![pair("unkeyed", "bits")];
    cases.push(("unkeyed guarded row", invalid));
    let mut invalid = original.clone();
    invalid.pairs[0].join_column = ColumnName::from_stored("missing");
    cases.push(("missing closure column", invalid));
    let mut invalid = original.clone();
    invalid.memberships[0].pairs[0].outer_column = ColumnName::from_stored("wrong");
    cases.push(("different far owner key", invalid));
    let mut invalid = original.clone();
    invalid.extra_predicates = invalid.memberships[0].extra_predicates.clone();
    cases.push(("request-dependent closure", invalid));

    let db = parse_schema(&format!(
        "{schema} CREATE POLICY docs_read ON docs FOR SELECT USING ((bits & 2) = 2);"
    ))
    .unwrap();
    for (case, membership) in cases {
        let mut classified = translator().classify(&db);
        assert_eq!(
            consult_oracle(&mut classified, &Answer(membership)).len(),
            1
        );
        let outputs =
            support::plan_at(classified, &db, translator().registry(), ConfidenceLevel::B);
        assert_eq!(
            relation(&outputs.model(), "can_select").as_deref(),
            Some("no_access"),
            "{case}"
        );
        assert!(
            outputs.notes().iter().any(|note| matches!(
                note,
                TranslationNote::ExpressionRefused { policy, .. } if policy == "docs_read"
            )),
            "{case} must disclose the refused extension answer"
        );
    }
}
