//! Reaching the outputs, and what stops it.
use core::fmt::Write;

use rls2fga::classifier::function_registry::{SessionAttribute, SessionAttributeKind};
use rls2fga::generator::model_bounds::ModelBound;
use rls2fga::generator::well_known::WellKnownTypes;
use rls2fga::translator::PlanningError;

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::translator::{Translation, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{NoteSeverity, TranslationNote};

mod support;

use support::footgun::{db_of, translator};

/// A schema every clause of which translates.
const CLEAN: &str = "CREATE TABLE users(id UUID PRIMARY KEY);\n\
                     CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID NOT NULL REFERENCES users(id));\n\
                     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                     CREATE POLICY docs_all ON docs FOR ALL USING (owner_id = current_user) \
                     WITH CHECK (owner_id = current_user);\n";

/// A bit test this crate has no translation for.
const REFUSED: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, bits INT);\n\
                       ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                       CREATE POLICY docs_sel ON docs FOR SELECT USING ((bits & 2) = 2);\n";

/// A RESTRICTIVE barrier the caller's own threshold drops, beside a grant that
/// survives. `P6BooleanFlag` is confidence B by design, so requesting A drops the
/// barrier and nothing else.
const RESTRICTIVE_BELOW_THRESHOLD: &str =
    "CREATE TABLE docs(id UUID PRIMARY KEY, owner_id TEXT, is_public BOOLEAN);\n\
     ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
     CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);\n\
     CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT USING (is_public);\n";

/// An expression nobody classified means the model denies what the database grants, so
/// the outputs are refused until the caller has seen it.
#[test]
fn an_unhandled_expression_refuses_the_outputs() {
    let db = db_of(REFUSED);
    let error = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect_err("an unclassified expression must refuse");

    assert_eq!(error.notes().len(), 1, "got {:?}", error.notes());
    assert_eq!(error.notes()[0].severity(), NoteSeverity::Unhandled);
    assert!(matches!(
        error.notes()[0],
        TranslationNote::ExpressionRefused { .. }
    ));
}

/// Accepting the gaps is the same outputs, one visible line later.
#[test]
fn accepting_the_gaps_yields_the_same_outputs() {
    let db = db_of(REFUSED);
    let accepted = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();

    assert!(
        accepted.model().contains("define can_select: no_access"),
        "the narrower model is still a model:\n{}",
        accepted.model()
    );

    // Accepted outputs retain the non-diverging notes too.
    let refused = translator(ConfidenceLevel::D)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect_err("still refused");
    assert!(
        refused
            .notes()
            .iter()
            .all(|note| accepted.notes().contains(note)),
        "every refused note is among the accepted ones: {:?} vs {:?}",
        refused.notes(),
        accepted.notes()
    );
    assert!(
        accepted.notes().len() > refused.notes().len(),
        "and the accepted side keeps the notes that are not gaps"
    );
}

/// A schema that fully translates hands the outputs over without ceremony.
#[test]
fn a_translation_with_nothing_unhandled_answers() {
    let db = db_of(CLEAN);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect("nothing went unhandled");

    assert!(outputs.model().contains("type docs"));
}

#[test]
fn a_clause_the_callers_threshold_dropped_refuses() {
    let db = db_of(REFUSED);
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan");
    let error = translation
        .clone()
        .outputs()
        .expect_err("a dropped clause diverges");
    assert!(error
        .notes()
        .iter()
        .any(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. })));
    let outputs = translation.outputs_accepting_gaps();

    assert!(
        outputs
            .notes()
            .iter()
            .any(|note| note.severity() == NoteSeverity::BelowThreshold),
        "the loss is still reported: {:?}",
        outputs.notes()
    );
    assert!(outputs.model().contains("define can_select: no_access"));
}

#[test]
fn a_restrictive_clause_the_callers_threshold_dropped_refuses() {
    let db = db_of(RESTRICTIVE_BELOW_THRESHOLD);
    let translation = translator(ConfidenceLevel::A)
        .translate(&db)
        .expect("translation should plan");
    let error = translation
        .clone()
        .outputs()
        .expect_err("a dropped barrier diverges");
    assert!(error.notes().iter().any(|note| matches!(
        note,
        TranslationNote::ClauseBelowThreshold { policy, .. } if policy == "docs_bar"
    )));
    let outputs = translation.outputs_accepting_gaps();

    let dropped: Vec<&TranslationNote> = outputs
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::ClauseBelowThreshold { .. }))
        .collect();
    assert_eq!(
        dropped.len(),
        1,
        "the barrier's loss is reported once: {:?}",
        outputs.notes()
    );
    assert!(
        matches!(
            dropped[0],
            TranslationNote::ClauseBelowThreshold { mode, policy, .. }
                if mode == "RESTRICTIVE" && policy == "docs_bar"
        ),
        "and it names the barrier and its mode: {:?}",
        dropped[0]
    );
    assert!(
        !outputs
            .notes()
            .iter()
            .any(|note| matches!(note, TranslationNote::ExpressionRefused { .. })),
        "a clause the crate could read is not an expression nobody classified: {:?}",
        outputs.notes()
    );
    assert!(
        outputs
            .model()
            .contains("define can_select: owner and no_access"),
        "the barrier still denies, so the emitted model is unchanged:\n{}",
        outputs.model()
    );
}

fn membership_translation(
    read_rule: &str,
    extra_policy: &str,
    min_confidence: ConfidenceLevel,
) -> Translation {
    let db = db_of(&format!(
        "CREATE TABLE projects (id TEXT PRIMARY KEY);
         CREATE TABLE docs (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id), bits INT);
         CREATE TABLE members (
             project_id TEXT NOT NULL REFERENCES projects(id),
             member_id TEXT NOT NULL,
             enabled BOOLEAN NOT NULL,
             PRIMARY KEY (project_id, member_id));
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         ALTER TABLE members ENABLE ROW LEVEL SECURITY;
         CREATE POLICY own_rows ON members FOR SELECT USING ({read_rule});
         CREATE POLICY docs_read ON docs FOR SELECT USING (
             EXISTS (SELECT 1 FROM members m
                     WHERE m.project_id = docs.project_id
                       AND m.member_id = current_setting('app.user_id', true)));
         {extra_policy}"
    ));
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .with_session_attributes([SessionAttribute::setting(
            "app.user_id",
            SessionAttributeKind::CallerId,
        )])
        .build()
        .translate(&db)
        .expect("membership schema should plan")
}

#[test]
fn guarded_membership_refuses_even_when_the_guard_is_redundant() {
    for rule in [
        "member_id = current_setting('app.user_id', true)",
        "member_id = current_setting('app.user_id', true) AND enabled",
    ] {
        let translation = membership_translation(rule, "", ConfidenceLevel::B);
        let error = translation
            .clone()
            .outputs()
            .expect_err("guarded membership diverges");
        assert!(error.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGuarded { policy, join_table }
                if policy == "docs_read" && join_table.name() == "members"
        )));
        let accepted = translation.outputs_accepting_gaps();
        assert!(accepted.model().contains(" from projects"));
        assert!(accepted
            .tuple_queries()
            .iter()
            .any(|query| query.sql.contains("\"members\"")));
    }
}

#[test]
fn unguarded_membership_passes_the_checked_entry_point() {
    let translation = membership_translation("true", "", ConfidenceLevel::B);
    let accepted = translation.clone().outputs_accepting_gaps();
    let checked = translation.outputs().expect("open membership has no gap");
    assert_eq!(checked.model(), accepted.model());
    assert_eq!(checked.notes(), accepted.notes());
}

#[test]
fn an_attribute_left_to_runtime_enforcement_refuses() {
    let db = db_of(
        "CREATE TABLE docs(id INT PRIMARY KEY, owner_id TEXT, status TEXT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         CREATE POLICY docs_read ON docs FOR SELECT
             USING (owner_id = current_user AND status LIKE 'pub%');",
    );
    let translation = translator(ConfidenceLevel::C)
        .translate(&db)
        .expect("schema should plan");
    let error = translation
        .clone()
        .outputs()
        .expect_err("the attribute guard is missing");
    assert!(error.notes().iter().any(|note| matches!(
        note,
        TranslationNote::AttributeNeedsRuntimeEnforcement { policy, .. } if policy == "docs_read"
    )));
    assert!(translation
        .outputs_accepting_gaps()
        .model()
        .contains("define can_select: owner"));
}

#[test]
fn refusal_reports_all_diverging_notes_without_operator_requirements() {
    let translation = membership_translation(
        "member_id = current_setting('app.user_id', true) AND enabled",
        "CREATE POLICY unsupported ON docs FOR SELECT USING ((bits & 2) = 2);",
        ConfidenceLevel::D,
    );
    let expected: Vec<_> = translation
        .notes()
        .iter()
        .filter(|note| note.severity().diverges_from_database())
        .cloned()
        .collect();
    assert!(expected
        .iter()
        .any(|note| note.severity() == NoteSeverity::Partial));
    assert!(expected
        .iter()
        .any(|note| note.severity() == NoteSeverity::Unhandled));
    assert!(translation
        .notes()
        .iter()
        .any(|note| note.severity() == NoteSeverity::ActionRequired));
    let error = translation
        .clone()
        .outputs()
        .expect_err("both gaps must refuse");
    assert_eq!(error.notes(), expected);
    let accepted = translation.outputs_accepting_gaps();
    assert!(expected.iter().all(|note| accepted.notes().contains(note)));
    for note in error.notes() {
        assert!(error.to_string().contains(&note.to_string()));
    }
}

#[test]
fn operator_requirements_alone_do_not_refuse() {
    let db = db_of(
        "CREATE TABLE docs(id TEXT PRIMARY KEY, owner_id TEXT);
         ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
         ALTER TABLE docs FORCE ROW LEVEL SECURITY;
         CREATE POLICY docs_all ON docs FOR ALL USING (owner_id = current_user) WITH CHECK (owner_id = current_user);"
    );
    let translation = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("schema should plan");
    assert!(translation.notes().iter().any(|note| matches!(
        note,
        TranslationNote::RowIdentifierBudget { table, .. } if table.name() == "docs"
    )));
    assert!(
        translation
            .notes()
            .iter()
            .all(|note| note.severity() == NoteSeverity::ActionRequired),
        "{:?}",
        translation.notes()
    );
    let accepted = translation.clone().outputs_accepting_gaps();
    let checked = translation
        .outputs()
        .expect("operator requirements are not gaps");
    assert_eq!(checked.model(), accepted.model());
    assert_eq!(checked.notes(), accepted.notes());
}

/// One plan, three outputs. Asking for each of them twice must not change any of them,
/// which is what says the plan is held rather than rebuilt per call.
#[test]
fn every_output_renders_from_one_plan() {
    let db = db_of(CLEAN);
    let outputs = translator(ConfidenceLevel::B)
        .translate(&db)
        .expect("translation should plan")
        .outputs()
        .expect("nothing went unhandled");

    assert_eq!(outputs.model(), outputs.model());
    assert_eq!(
        format_tuples(outputs.tuple_queries()),
        format_tuples(outputs.tuple_queries())
    );
    assert_eq!(
        serde_json::to_string(&outputs.json_model()).expect("serializes"),
        serde_json::to_string(&outputs.json_model()).expect("serializes")
    );
}

#[test]
fn translation_note_table_serializes_as_string() {
    use rls2fga::types::TableId;
    let note = TranslationNote::NoPermissivePolicy {
        table: TableId::from_stored(Some("public".to_string()), "docs".to_string()),
        commands: vec!["SELECT".to_string()],
    };
    let json = serde_json::to_string(&note).expect("note serializes");
    assert_eq!(
        json,
        r#"{"NoPermissivePolicy":{"table":"public.docs","commands":["SELECT"]}}"#
    );
}

#[test]
fn translation_note_roundtrips_from_baseline_string_table_json() {
    use rls2fga::types::TranslationNote;
    let baseline = r#"{"NoPermissivePolicy":{"table":"public.docs","commands":["SELECT"]}}"#;
    let result: Result<TranslationNote, _> = serde_json::from_str(baseline);
    assert!(result.is_ok(), "baseline note JSON refused: {result:?}");
    let TranslationNote::NoPermissivePolicy { table, commands } = result.unwrap() else {
        panic!("wrong variant");
    };
    assert_eq!(table.schema(), Some("public"));
    assert_eq!(table.name(), "docs");
    assert_eq!(commands, vec!["SELECT".to_string()]);
}

#[test]
fn translation_note_roundtrips_quoted_table_parts() {
    use rls2fga::types::TranslationNote;
    let baseline =
        r#"{"NoPermissivePolicy":{"table":"\"my.schema\".\"ta\"\"ble\"","commands":["SELECT"]}}"#;
    let note: TranslationNote = serde_json::from_str(baseline).expect("note deserializes");
    let TranslationNote::NoPermissivePolicy { table, .. } = &note else {
        panic!("wrong variant");
    };
    assert_eq!(table.schema(), Some("my.schema"));
    assert_eq!(table.name(), "ta\"ble");
    assert_eq!(
        serde_json::to_string(&note).expect("note serializes"),
        baseline
    );
}

#[test]
fn relation_name_deserialization_rejects_invalid_strings() {
    use rls2fga::types::RelationName;
    let result: Result<RelationName, _> = serde_json::from_str(r#""not valid""#);
    assert!(
        result.is_err(),
        "invalid relation name accepted: {result:?}"
    );
}

/// One table guarded by the clock, so its read earns a condition.
const TEMPORAL: &str = "CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
                       ALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n\
                       CREATE POLICY docs_sel ON docs FOR SELECT USING (expires_at > now());\n";

/// `count` tables, each guarded by a temporal clause with its own offset, so every
/// guard is a distinct condition.
fn schema_with_temporal_guards(count: usize) -> String {
    let mut sql = String::new();
    for index in 0..count {
        writeln!(
            sql,
            "CREATE TABLE t{index:02}(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);\n\
             ALTER TABLE t{index:02} ENABLE ROW LEVEL SECURITY;\n\
             CREATE POLICY t{index:02}_sel ON t{index:02} FOR SELECT \
             USING (expires_at > now() - interval '{offset} days');\n",
            offset = index + 1,
        )
        .expect("schema writes");
    }
    sql
}

/// `OpenFGA` refuses a model declaring more than 25 conditions, and a model the
/// service would refuse must not leave the translator.
#[test]
fn twenty_six_conditions_refuse_the_translation() {
    let db = db_of(&schema_with_temporal_guards(26));
    let error = TranslatorBuilder::new()
        .build()
        .translate(&db)
        .expect_err("26 distinct conditions cross the bound");
    let PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        ref item,
    } = error
    else {
        panic!("the crossed bound must name itself: {error:?}");
    };
    assert!(matches!(bound, ModelBound::Conditions), "got {bound:?}");
    assert_eq!(measured, 26);
    assert_eq!(limit, 25);
    assert!(
        !item.is_empty(),
        "the item must name the condition it counts"
    );
    let message = error.to_string();
    assert!(
        message.contains("25") && message.contains("26"),
        "the message must name the limit and the count, got {message}"
    );
}

/// Sitting exactly on the bound is within it.
#[test]
fn twenty_five_conditions_still_translate() {
    let db = db_of(&schema_with_temporal_guards(25));
    let outputs = TranslatorBuilder::new()
        .build()
        .translate(&db)
        .expect("25 conditions sit exactly on the bound")
        .outputs_accepting_gaps();
    assert_eq!(
        outputs
            .json_model()
            .conditions
            .as_ref()
            .map_or(0, std::collections::BTreeMap::len),
        25,
        "the model must declare exactly the 25 distinct guards"
    );
}

/// The request-time parameter a deployment configures names the request side of
/// every temporal condition, so one past fifty characters crosses a bound the
/// write would refuse.
#[test]
fn a_request_time_parameter_over_fifty_characters_refuses_the_translation() {
    let db = db_of(TEMPORAL);
    let error = TranslatorBuilder::new()
        .with_request_time_parameter("t".repeat(55))
        .expect("fifty five letters are a valid identifier")
        .build()
        .translate(&db)
        .expect_err("the parameter name crosses its bound");
    let PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        ..
    } = error
    else {
        panic!("the crossed bound must name itself: {error:?}");
    };
    assert!(
        matches!(bound, ModelBound::ConditionParameterKey),
        "got {bound:?}"
    );
    assert_eq!(measured, 55);
    assert_eq!(limit, 50);
}

/// A configured well-known type name is length-checked only where the written
/// model is checked, since the constructor takes what the deployment spells.
#[test]
fn a_configured_type_name_past_two_hundred_fifty_four_refuses_the_translation() {
    let well_known = WellKnownTypes::new(
        "u".repeat(255),
        "team",
        "pg_role",
        "pg_role_scope",
        "request_gate",
        "nobody",
    )
    .expect("the name is otherwise valid");
    let db = db_of(CLEAN);
    let error = TranslatorBuilder::new()
        .with_well_known_types(well_known)
        .build()
        .translate(&db)
        .expect_err("the type name crosses its bound");
    let PlanningError::ModelBoundExceeded {
        bound,
        measured,
        limit,
        item,
    } = error
    else {
        panic!("the crossed bound must name itself: {error:?}");
    };
    assert!(matches!(bound, ModelBound::TypeName), "got {bound:?}");
    assert_eq!(measured, 255);
    assert_eq!(limit, 254);
    assert_eq!(item, "u".repeat(255));
}
