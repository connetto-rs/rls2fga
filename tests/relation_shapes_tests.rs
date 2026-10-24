//! The shapes a translation reports per relation.
//!
//! A consumer watching a change stream needs both halves together: which records
//! fill a relation, and whether one row decides them. Everything here drives the
//! public surface a second crate would use, so a shape reachable only from inside
//! rls2fga fails.

use std::collections::BTreeSet;

use rls2fga::classifier::function_registry::{FunctionRegistry, SessionAttribute};
use rls2fga::classifier::policy_classifier::classify_policies;
use rls2fga::generator::model_generator::GeneratorSettings;
use rls2fga::generator::tuple_generator::TupleQuery;
use rls2fga::generator::well_known::{
    can_select_relation, member_relation, PG_ROLE_SCOPE_TYPE, PG_ROLE_TYPE, TEAM_TYPE, USER_TYPE,
};
use rls2fga::parser::names::lookup_table;
use rls2fga::parser::sql_parser::{
    parse_schema, ColumnLike, DatabaseLike, ParserDB, PolicyLike, TableLike,
};
use rls2fga::translator::Translation;
use rls2fga::types::ConditionParameterName;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::TranslationNote;
use rls2fga::types::{
    BoundQuery, Guard, RecordDerivation, RecordDescription, ReplayScope, SubjectKey, TypeName,
    ValueSource,
};
use rls2fga::types::{ColumnName, RelationName, TableId};
use rls2fga::types::{
    RelationShapes, RequestAtom, RequestComparison, RequestPredicate, RowDecision,
};

mod support;

const OWNERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
";

const ACCESSOR_REGISTRY: &str =
    r#"{"auth_current_user_id": {"kind": "current_user_accessor", "returns": "text"}}"#;

/// An uncorrelated membership grants every row of the table at once, so the
/// generator mints a holder object standing for the whole member list.
const HOLDER: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE staff (user_id TEXT);
CREATE TABLE reviewers (user_id TEXT, active BOOLEAN, vetted_at TIMESTAMPTZ);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE memos (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_staff ON docs FOR SELECT USING (EXISTS (SELECT 1 FROM staff
    WHERE staff.user_id = auth_current_user_id()));
CREATE POLICY memos_reviewers ON memos FOR SELECT USING (EXISTS (SELECT 1 FROM reviewers
    WHERE reviewers.user_id = auth_current_user_id() AND reviewers.vetted_at > now()));
";

/// A role threshold naming a grant table, with neither a users nor a teams table
/// for the grantee to resolve against.
const GRANTS_WITHOUT_PRINCIPALS: &str = "
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE owner_grants (granted_owner_id TEXT, grantee_owner_id TEXT, role_id INT);
CREATE FUNCTION get_owner_role(a TEXT, b TEXT) RETURNS INT LANGUAGE sql STABLE
    AS 'SELECT 1';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (get_owner_role(current_user, id) >= 2);
";

const GRANT_REGISTRY: &str = r#"{
  "get_owner_role": {
    "kind": "role_threshold",
    "user_param_index": 0,
    "resource_param_index": 1,
    "role_levels": {"viewer": 2, "editor": 3, "admin": 4},
    "grant_table": "owner_grants",
    "grant_grantee_col": "grantee_owner_id",
    "grant_resource_col": "granted_owner_id",
    "grant_role_col": "role_id"
  }
}"#;

fn parsed(sql: &str, registry_json: &str) -> (ParserDB, FunctionRegistry) {
    let db = parse_schema(sql).expect("the schema parses");
    let mut registry = FunctionRegistry::new();
    registry
        .load_from_json(registry_json)
        .expect("the registry parses");
    (db, registry)
}

fn parsed_with_session_attributes(
    sql: &str,
    attributes_json: &str,
) -> (ParserDB, FunctionRegistry) {
    let (db, mut registry) = parsed(sql, "{}");
    let attributes: Vec<SessionAttribute> =
        serde_json::from_str(attributes_json).expect("the session attributes parse");
    registry.declare_session_attributes(attributes);
    (db, registry)
}

fn translation(
    db: &ParserDB,
    registry: &FunctionRegistry,
    level: ConfidenceLevel,
    settings: &GeneratorSettings,
) -> Translation {
    Translation::plan(
        classify_policies(db, registry),
        db,
        registry,
        level,
        settings,
    )
    .expect("translation should plan")
}

fn shapes_of(sql: &str, registry_json: &str) -> Vec<RelationShapes> {
    let (db, registry) = parsed(sql, registry_json);
    translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .relations()
    .to_vec()
}

fn shapes_at(sql: &str, registry_json: &str, level: ConfidenceLevel) -> Vec<RelationShapes> {
    let (db, registry) = parsed(sql, registry_json);
    translation(&db, &registry, level, &GeneratorSettings::default())
        .relations()
        .to_vec()
}

fn model_at(sql: &str, registry_json: &str, level: ConfidenceLevel) -> String {
    let (db, registry) = parsed(sql, registry_json);
    translation(&db, &registry, level, &GeneratorSettings::default())
        .outputs_accepting_gaps()
        .model()
}

fn entry<'a>(shapes: &'a [RelationShapes], type_name: &str, relation: &str) -> &'a RelationShapes {
    shapes
        .iter()
        .find(|entry| entry.type_name.as_str() == type_name && entry.relation == relation)
        .unwrap_or_else(|| panic!("{type_name}#{relation} should be reported"))
}

fn declared_relations(
    model: &rls2fga::generator::json_model::AuthorizationModel,
) -> BTreeSet<(TypeName, RelationName)> {
    model
        .type_definitions
        .iter()
        .flat_map(|definition| {
            definition
                .relations
                .iter()
                .flatten()
                .map(|(relation, _)| (definition.type_name.clone(), relation.clone()))
        })
        .collect()
}

fn relation_key_from_object(object: &str) -> TypeName {
    object.split_once(':').map_or_else(
        || panic!("record object should be typed: {object}"),
        |(type_name, _)| TypeName::canonicalized(type_name),
    )
}

fn scope_relations(scope: &ReplayScope) -> Vec<(TypeName, RelationName)> {
    match scope {
        ReplayScope::Object {
            object_type,
            relations,
        } => relations
            .iter()
            .cloned()
            .map(|relation| (object_type.clone(), relation))
            .collect(),
        ReplayScope::Subject {
            relation,
            object_type,
            ..
        } => vec![(object_type.clone(), relation.clone())],
    }
}

fn description_relations(description: &RecordDescription) -> Vec<(TypeName, RelationName)> {
    match &description.derivation {
        RecordDerivation::FromRow { template, .. } => {
            vec![(template.object_type.clone(), template.relation.clone())]
        }
        RecordDerivation::Constant { record } => {
            vec![(
                relation_key_from_object(&record.object),
                record.relation.clone(),
            )]
        }
        RecordDerivation::Joined { queries, .. } => queries
            .iter()
            .flat_map(|query| scope_relations(query.scope()))
            .collect(),
        _ => Vec::new(),
    }
}

fn split_top_level_args(body: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (index, ch) in body.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(body[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    args.push(body[start..].trim());
    args
}

fn first_quoted_identifier(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let start = bytes.iter().position(|byte| *byte == b'"')?;
    let mut end = start + 1;
    while end < bytes.len() {
        if bytes[end] == b'"' {
            if bytes.get(end + 1) == Some(&b'"') {
                end += 2;
                continue;
            }
            return Some(value[start..=end].to_string());
        }
        end += 1;
    }
    None
}

fn context_identifiers(sql: &str) -> Vec<String> {
    let Some((_, rest)) = sql.split_once("jsonb_build_object(") else {
        return Vec::new();
    };
    let Some((body, _)) = rest.split_once(") AS context") else {
        return Vec::new();
    };
    let args = split_top_level_args(body);
    args.chunks(2)
        .filter_map(|pair| pair.get(1).and_then(|value| first_quoted_identifier(value)))
        .collect()
}

/// Assertion 1. One policy, one relation the row fills, one shape.
#[test]
fn a_direct_ownership_relation_carries_one_shape_from_its_own_row() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);

    let filled: Vec<&RelationShapes> = shapes
        .iter()
        .filter(|entry| !entry.shapes.is_empty())
        .collect();
    assert_eq!(
        filled.len(),
        1,
        "one relation takes records from the row: {filled:#?}"
    );

    let owned = filled[0];
    assert!(
        owned.from_one_row,
        "{}#{} takes its records from the row it keys",
        owned.type_name, owned.relation
    );
    assert_eq!(owned.shapes.len(), 1, "one policy, one shape");

    let RecordDerivation::FromRow {
        table, template, ..
    } = &owned.shapes[0].derivation
    else {
        panic!("ownership resolves from the row: {:#?}", owned.shapes[0]);
    };
    assert_eq!(table.to_string(), "docs");
    assert_eq!(template.object_type, owned.type_name);
    assert_eq!(template.relation, owned.relation);
    assert_eq!(template.object_key.parts(), [ValueSource::column("id")]);
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(
        template.subject_key.part(),
        &ValueSource::column("owner_id")
    );
}

/// The same schema keyed on two columns. Phase 4 taught the whole crate to name such a
/// row, so a recipe over one is as decidable as a recipe over a single-column key: the
/// records still follow from that row and from nothing else.
///
/// The guard on the object's identity kept demanding a single column after the facts
/// started flowing, so ownership on a compound key emitted correct tuples while every
/// relation reported that no row decides them. That is a wrong deny at a consumer
/// answering locally, and it disagreed with the request-gated path, which accepts a
/// compound key because it settles earlier.
const COMPOUND_OWNERSHIP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE shares (paper_id TEXT, viewer TEXT, PRIMARY KEY (paper_id, viewer));
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE shares ENABLE ROW LEVEL SECURITY;
CREATE POLICY shares_owner ON shares FOR SELECT USING (viewer = auth_current_user_id());
";

#[test]
fn a_compound_key_ownership_relation_is_decided_by_its_own_row() {
    let shapes = shapes_of(COMPOUND_OWNERSHIP, ACCESSOR_REGISTRY);

    let owned = entry(&shapes, "shares", "viewer");
    assert!(
        owned.from_one_row,
        "a key spanning two columns names a row as surely as one does: {owned:#?}"
    );

    let RecordDerivation::FromRow {
        table, template, ..
    } = &owned.shapes[0].derivation
    else {
        panic!("ownership resolves from the row: {:#?}", owned.shapes[0]);
    };
    assert_eq!(table.to_string(), "shares");
    assert_eq!(
        template.object_key.parts(),
        [
            ValueSource::column("paper_id"),
            ValueSource::column("viewer"),
        ],
        "the object is named by every key column, in declared order"
    );
    assert_eq!(template.subject_key.part(), &ValueSource::column("viewer"));

    assert!(
        entry(&shapes, "shares", "can_select").from_one_row,
        "and the action relation reading it inherits that: {shapes:#?}"
    );
}

/// The guard still has to refuse a record keyed on something that is not the row's
/// identity, which is what it was written for. A foreign column names another object,
/// and a change to this row does not own it.
#[test]
fn a_record_keyed_on_a_foreign_column_is_still_not_decided_by_the_row() {
    let shapes = shapes_of(
        "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE links (id TEXT PRIMARY KEY, doc_id TEXT REFERENCES docs(id), user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_shared ON docs FOR SELECT USING (
  EXISTS (SELECT 1 FROM links l WHERE l.doc_id = docs.id AND l.user_id = auth_current_user_id()));
",
        ACCESSOR_REGISTRY,
    );

    assert!(
        !entry(&shapes, "docs", "can_select").from_one_row,
        "the grant is recorded on another table, so no row of docs settles it: {shapes:#?}"
    );
}

/// Assertion 2. A relation the model computes carries no shapes and is still answered.
#[test]
fn a_computed_relation_carries_no_shapes_and_keeps_its_own_answer() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);
    let can_select = entry(&shapes, "docs", "can_select");

    assert!(
        can_select.shapes.is_empty(),
        "a computed relation is filled by the relations it reads: {:#?}",
        can_select.shapes
    );
    assert!(
        can_select.from_one_row,
        "it computes from a relation the row decides, so it is decidable too"
    );
}

/// Assertion 3. Nothing the model declares is missing, and nothing carrying records
/// is dropped on the way.
#[test]
fn every_relation_the_model_declares_is_reported() {
    let mut checked = 0usize;

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        let reported: BTreeSet<(TypeName, RelationName)> = planned
            .translation()
            .relations()
            .iter()
            .map(|entry| (entry.type_name.clone(), entry.relation.clone()))
            .collect();

        let outputs = &planned;
        let declared: BTreeSet<(TypeName, RelationName)> = outputs
            .json_model()
            .type_definitions
            .iter()
            .flat_map(|definition| {
                definition
                    .relations
                    .iter()
                    .flatten()
                    .map(|(relation, _)| (definition.type_name.clone(), relation.clone()))
            })
            .collect();
        assert_eq!(
            reported, declared,
            "{fixture}: the reported relations are the declared ones"
        );

        // A source feeding a relation nobody declares would have its shape dropped
        // silently, so assert the direction the set equality cannot see.
        for query in outputs.tuple_queries() {
            let Some(RecordDescription {
                derivation: RecordDerivation::FromRow { template, .. },
                ..
            }) = query.description.as_ref()
            else {
                continue;
            };
            checked += 1;
            assert!(
                reported.contains(&(template.object_type.clone(), template.relation.clone())),
                "{fixture}: {}#{} produces records yet is not reported",
                template.object_type,
                template.relation
            );
        }
    }

    assert!(checked > 0, "no fixture produced a described tuple query");
}

#[test]
fn no_tuple_query_names_an_undeclared_relation() {
    let mut checked = 0usize;

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        let declared = declared_relations(&outputs.json_model());

        for query in outputs.tuple_queries() {
            let Some(description) = query.description.as_ref() else {
                continue;
            };
            for (type_name, relation) in description_relations(description) {
                checked += 1;
                assert!(
                    declared.contains(&(type_name.clone(), relation.clone())),
                    "{fixture}: tuple query '{}' names undeclared {}#{relation}",
                    query.comment,
                    type_name
                );
            }
        }
    }

    assert!(checked > 0, "no fixture produced a described tuple query");
}

#[test]
fn every_conditional_tuple_filters_its_context_columns() {
    let mut checked = 0usize;

    for (fixture, db, registry) in tuple_contract_cases() {
        let classified = classify_policies(&db, &registry);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

        for query in outputs.tuple_queries() {
            if query.condition.is_none() {
                continue;
            }
            let identifiers = context_identifiers(&query.sql);
            for identifier in identifiers {
                checked += 1;
                let guard = format!("{identifier} IS NOT NULL");
                assert!(
                    query.sql.contains(&guard),
                    "{fixture}: conditional tuple '{}' lacks guard {guard}:\n{}",
                    query.comment,
                    query.sql
                );
            }
        }
    }

    assert!(
        checked > 0,
        "no fixture produced a conditional tuple context"
    );
}

/// Two type plans can hold the same membership source and the renderer emits its
/// query once, so a consumer must not be handed the same shape twice.
#[test]
fn no_relation_reports_the_same_shape_twice() {
    let mut checked = 0usize;

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        for entry in planned.translation().relations() {
            for (index, shape) in entry.shapes.iter().enumerate() {
                checked += 1;
                assert!(
                    !entry.shapes[..index].contains(shape),
                    "{fixture}: {}#{} reports one shape twice:\n{shape:#?}",
                    entry.type_name,
                    entry.relation
                );
            }
        }
    }

    assert!(checked > 0, "no fixture produced a shape");
}

/// A role threshold over a table whose key spans two columns, which is the shape that
/// separates binding the whole key from binding its first column.
const COMPOSITE_KEY_GRANTS: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE readings (tenant_id TEXT, reading_id TEXT, owner_id TEXT,
    PRIMARY KEY (tenant_id, reading_id));
CREATE TABLE owner_grants (granted_owner_id TEXT, grantee_owner_id TEXT, role_id INT);
CREATE FUNCTION get_owner_role(a TEXT, b TEXT) RETURNS INT LANGUAGE sql STABLE
    AS 'SELECT 1';
ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_sel ON readings FOR SELECT
    USING (get_owner_role(current_user, owner_id) >= 2);
";

/// A shape naming a row of the object's own table has to name the whole row.
///
/// The two public surfaces have to agree: `row_naming` tells a consumer which columns key
/// a row of a type, and a shape building that type's objects out of that type's own table
/// has to use exactly those. Naming a row by a prefix of a compound key merges every row
/// sharing the prefix into one object, so a whole tenant would answer as one row.
///
/// A shape reading some **other** table names its objects from that table's own columns,
/// which is a different contract and is excluded here: a membership row names the parent
/// it points at, not itself.
#[test]
fn a_shape_naming_the_guarded_table_names_its_whole_key() {
    let mut compound = 0usize;
    let mut checked = 0usize;

    let mut cases: Vec<(String, ParserDB, FunctionRegistry)> = support::fixture_names()
        .into_iter()
        .map(|fixture| {
            let (_, db, registry) = support::try_load_fixture_classified(&fixture);
            (fixture, db, registry)
        })
        .collect();
    let (db, registry) = parsed(COMPOSITE_KEY_GRANTS, GRANT_REGISTRY);
    cases.push(("composite_key_grants".to_string(), db, registry));

    for (name, db, registry) in &cases {
        let planned = support::plan_at(
            classify_policies(db, registry),
            db,
            registry,
            ConfidenceLevel::B,
        );
        // Keyed by type, not by table: the same table is the object's own in one shape
        // and the join table of another type's shape in the next.
        let keys: Vec<(TableId, TypeName, Vec<ColumnName>)> = planned
            .translation()
            .row_naming()
            .iter()
            .map(|naming| {
                let columns = naming
                    .key
                    .parts()
                    .iter()
                    .filter_map(|part| match part {
                        ValueSource::Column(column) => Some(column.column().clone()),
                        _ => None,
                    })
                    .collect();
                (naming.table.clone(), naming.type_name.clone(), columns)
            })
            .collect();

        for entry in planned.translation().relations() {
            for shape in &entry.shapes {
                let RecordDerivation::FromRow {
                    table, template, ..
                } = &shape.derivation
                else {
                    continue;
                };
                let Some((.., key)) = keys.iter().find(|(named, type_name, _)| {
                    named == table && type_name.as_str() == entry.type_name.as_str()
                }) else {
                    continue;
                };
                let named: Vec<ColumnName> = template
                    .object_key
                    .parts()
                    .iter()
                    .filter_map(|part| match part {
                        ValueSource::Column(column) => Some(column.column().clone()),
                        _ => None,
                    })
                    .collect();
                checked += 1;
                compound += usize::from(key.len() > 1);
                assert_eq!(
                    &named, key,
                    "{name}: {}#{} names a row of {table} by {named:?}, which {key:?} keys",
                    entry.type_name, entry.relation
                );
            }
        }
    }

    assert!(checked > 0, "no shape names a table the model keys");
    assert!(
        compound > 0,
        "no case names a compound key, so this proves nothing"
    );
}

/// A row-derived shape's records have to be that row's, or withdrawing them takes
/// another row's facts with them.
///
/// [`RecordDerivation::FromRow`] means the records are a function of one row, which
/// `describe.rs` states as "a delete of that row reports its records as removed". A
/// template whose object key, subject key and context are all literals reads nothing,
/// so every row of the table yields the identical record and a consumer that removes
/// what a deleted row implied removes what its siblings still need.
#[test]
fn every_row_derived_shape_reads_the_row_it_names() {
    let mut checked = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        for entry in planned.translation().relations() {
            for shape in &entry.shapes {
                let RecordDerivation::FromRow {
                    table, template, ..
                } = &shape.derivation
                else {
                    continue;
                };
                checked += 1;
                let reads_row = template
                    .object_key
                    .parts()
                    .iter()
                    .any(|part| !matches!(part, ValueSource::Literal(_)))
                    || !matches!(template.subject_key.part(), ValueSource::Literal(_))
                    || template.context.as_ref().is_some_and(|context| {
                        context
                            .entries
                            .iter()
                            .any(|entry| !matches!(entry.value, ValueSource::Literal(_)))
                    });
                if !reads_row {
                    offenders.push(format!(
                        "{fixture}: {}#{} claims to follow from one row of {table} and reads none of it",
                        entry.type_name, entry.relation
                    ));
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no row-derived shape was read, so this proves nothing"
    );
    assert!(
        offenders.is_empty(),
        "every row-derived shape must read its row, found {}:\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}

/// A fact the policy decides is reported, and reported as nobody's row.
///
/// The consumer needs it, since nothing else tells it to write the roles a scope admits, so
/// silence is the wrong answer. It also must not arrive as a row's own record: that is what
/// makes a delete withdraw it and deny every surviving row. Read beside the pointer on the
/// same model, which is the row-derived neighbour it used to be confused with.
#[test]
fn a_constant_fact_is_reported_without_claiming_a_row_decides_it() {
    let (classified, db, registry) = support::try_load_fixture_classified("pg_role_gate");
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let shapes = planned.translation().relations();

    let roles = entry(shapes, PG_ROLE_SCOPE_TYPE, "roles");
    let [shape] = roles.shapes.as_slice() else {
        panic!(
            "one shape carries the roles a scope admits, got {:?}",
            roles.shapes
        );
    };
    assert!(
        shape.tables.is_empty(),
        "a constant reads no table, so no change stream can deliver it: {:?}",
        shape.tables
    );
    assert!(
        matches!(&shape.derivation, RecordDerivation::Constant { .. }),
        "the roles follow from the policy, got {:?}",
        shape.derivation
    );
    assert!(
        !roles.from_one_row && roles.decision.is_none(),
        "no row decides a constant, so the surface must not say one does"
    );

    // The pointer beside it is the row-derived neighbour, so this is not a model where
    // everything reads as undecidable.
    let pointer = shapes
        .iter()
        .find(|candidate| {
            candidate.type_name.as_str() == "docs"
                && candidate.relation.as_str().starts_with("scope_")
        })
        .expect("every row points at the scope judging it");
    let [pointer_shape] = pointer.shapes.as_slice() else {
        panic!(
            "one shape points the row at its scope, got {:?}",
            pointer.shapes
        );
    };
    let RecordDerivation::FromRow {
        table, template, ..
    } = &pointer_shape.derivation
    else {
        panic!(
            "the pointer is a row's own record, got {:?}",
            pointer_shape.derivation
        );
    };
    assert_eq!(table.to_string(), "docs");
    assert!(
        template
            .object_key
            .parts()
            .iter()
            .any(|part| matches!(part, ValueSource::Column(_))),
        "the pointer names the row it is about"
    );
}

/// Whether `bound` is `whole` with exactly one filtering line added, in a place that
/// leaves the statement runnable.
///
/// Not a prefix check: the added predicate belongs inside the `WHERE`, and an aggregated
/// query ends in `GROUP BY`, which the predicate has to precede. So the property is three
/// things at once: nothing else moved, the addition is a conjunct, and it lands before any
/// grouping. Appending it after the `GROUP BY` satisfies the first two and produces SQL
/// `PostgreSQL` rejects, which is why the third is here.
fn is_that_query_plus_one_line(whole: &str, bound: &str) -> bool {
    let lines = |sql: &str| -> Vec<String> {
        sql.trim_end_matches(';')
            .lines()
            .map(|line| line.trim_end_matches(';').to_string())
            .collect()
    };
    let (whole, bound) = (lines(whole), lines(bound));
    if bound.len() != whole.len() + 1 {
        return false;
    }
    let mut expected = whole.iter();
    let mut next = expected.next();
    let mut added: Vec<(usize, &String)> = Vec::new();
    for (index, line) in bound.iter().enumerate() {
        match next {
            Some(wanted) if wanted == line => next = expected.next(),
            _ => added.push((index, line)),
        }
    }
    let [(index, line)] = added.as_slice() else {
        return false;
    };
    next.is_none()
        && line.starts_with("AND ")
        && bound
            .iter()
            .enumerate()
            .all(|(at, other)| !other.starts_with("GROUP BY ") || at > *index)
}

/// The guarantee the describer owes: a bound query is the whole-table query plus one
/// condition, so the two cannot drift into answering differently.
#[test]
fn a_bound_query_is_its_whole_table_query_plus_one_condition() {
    let mut checked = 0usize;

    for (fixture, db, registry) in tuple_contract_cases() {
        let classified = classify_policies(&db, &registry);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        let shapes = planned.translation().relations();
        let whole_table: Vec<String> = planned
            .tuple_queries()
            .iter()
            .map(|query| query.sql.clone())
            .collect();

        for entry in shapes {
            for shape in &entry.shapes {
                let RecordDerivation::Joined { queries, .. } = &shape.derivation else {
                    continue;
                };
                assert!(
                    !queries.is_empty(),
                    "{fixture}: {}#{} joins yet offers no query to run",
                    entry.type_name,
                    entry.relation
                );
                for bound in queries {
                    checked += 1;
                    assert!(
                        whole_table
                            .iter()
                            .any(|sql| is_that_query_plus_one_line(sql, bound.sql())),
                        "{fixture}: {}#{} binds a query no whole-table query becomes:\n{}",
                        entry.type_name,
                        entry.relation,
                        bound.sql()
                    );
                }
            }
        }
    }

    assert!(checked > 0, "no fixture produced a joining shape");
}

#[test]
fn every_replay_slice_names_the_relation_its_shape_fills() {
    let mut checked = 0usize;

    for (fixture, entry, query) in joined_shape_queries() {
        checked += 1;
        let names_relation = match query.scope() {
            ReplayScope::Object {
                object_type,
                relations,
            } => object_type == entry.type_name.as_str() && relations.contains(&entry.relation),
            ReplayScope::Subject {
                object_type,
                relation,
                ..
            } => object_type == entry.type_name.as_str() && relation == &entry.relation,
        };
        assert!(
            names_relation,
            "{fixture}: {}#{} has a replay slice for {:?}",
            entry.type_name,
            entry.relation,
            query.scope()
        );
    }

    assert!(checked > 0, "no fixture produced a joining shape");
}

/// A column whose stored name carries a double quote, which `PostgreSQL` accepts and a
/// dump reproduces as `"us""er_id"`.
const QUOTED_MEMBERSHIP: &str = "
CREATE TABLE public.users (id TEXT PRIMARY KEY);
CREATE TABLE public.staff (\"us\"\"er_id\" TEXT, active BOOLEAN);
CREATE TABLE public.doc_members (\"do\"\"c_id\" TEXT, \"us\"\"er_id\" TEXT, role TEXT);
CREATE TABLE public.docs (id TEXT PRIMARY KEY);
CREATE TABLE public.memos (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_members ON docs FOR SELECT USING (EXISTS (SELECT 1 FROM doc_members
    WHERE doc_members.\"do\"\"c_id\" = docs.id
      AND doc_members.\"us\"\"er_id\" = auth_current_user_id()
      AND lower(doc_members.role) = 'admin'));
CREATE POLICY memos_staff ON memos FOR SELECT USING (EXISTS (SELECT 1 FROM staff
    WHERE staff.\"us\"\"er_id\" = auth_current_user_id() AND staff.active IS TRUE));
";

/// The identifier a bound query's appended condition names, with any table alias
/// dropped. `bind` appends its condition last, so the final `AND` is the one to read.
fn appended_predicate_identifier(sql: &str) -> String {
    let predicate = sql
        .rsplit("\nAND ")
        .next()
        .expect("rsplit yields at least one part");
    let column = predicate
        .strip_suffix(';')
        .and_then(|body| body.strip_suffix(" = $1"))
        .unwrap_or_else(|| panic!("a bound condition compares one column to $1: {predicate}"));
    if column.starts_with('"') {
        return column.to_string();
    }
    column
        .split_once('.')
        .map_or_else(|| column.to_string(), |(_, rest)| rest.to_string())
}

/// The other half of the guarantee above. A bound query is the whole-table query plus one
/// condition, and that condition has to spell its column the way the query already spells
/// it. An identifier escaped one way in the query and another way in the condition is not
/// the same column: `PostgreSQL` does not parse `"us"er_id"`, and a name chosen to close
/// the quote rather than break it makes the condition a predicate of someone else's
/// choosing.
#[test]
fn a_bound_condition_quotes_its_column_the_way_the_query_does() {
    let (db, registry) = parsed(QUOTED_MEMBERSHIP, ACCESSOR_REGISTRY);
    let planned = support::plan_at(
        classify_policies(&db, &registry),
        &db,
        &registry,
        ConfidenceLevel::B,
    );
    let shapes = planned.translation().relations();
    let whole_table: Vec<String> = planned
        .tuple_queries()
        .iter()
        .map(|query| query.sql.clone())
        .collect();

    let mut checked = 0usize;
    let mut escaped = 0usize;
    for entry in shapes {
        for shape in &entry.shapes {
            let RecordDerivation::Joined { queries, .. } = &shape.derivation else {
                continue;
            };
            for bound in queries {
                let identifier = appended_predicate_identifier(bound.sql());
                checked += 1;
                if identifier.contains("\"\"") {
                    escaped += 1;
                }
                assert!(
                    whole_table.iter().any(|sql| sql.contains(&identifier)),
                    "{}#{} binds {identifier}, which no whole-table query spells:\n{}",
                    entry.type_name,
                    entry.relation,
                    bound.sql()
                );
            }
        }
    }

    assert!(checked > 0, "the schema produces a joining shape");
    assert!(
        escaped > 0,
        "the schema exercises an identifier needing escaping, else this proves nothing"
    );
}

/// Assertion 5. The shapes come from the plan the translation holds, so a setting that
/// changes structure reaches them: the configured request parameter collides with the
/// row's column, and the suffix the plan chose shows in the record's own context key.
#[test]
fn the_shapes_read_the_plan_the_caller_configured() {
    let schema = "
CREATE TABLE jobs (id TEXT PRIMARY KEY, as_of TIMESTAMPTZ);
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY jobs_sel ON jobs FOR SELECT USING (as_of > now());
";
    let (db, registry) = parsed(schema, "{}");
    let settings = GeneratorSettings {
        request_time_parameter: ConditionParameterName::try_from("as_of")
            .expect("as_of is a valid parameter"),
        ..GeneratorSettings::default()
    };

    let context_keys: Vec<String> = translation(&db, &registry, ConfidenceLevel::B, &settings)
        .relations()
        .iter()
        .flat_map(|entry| entry.shapes.iter())
        .filter_map(|shape| match &shape.derivation {
            RecordDerivation::FromRow { template, .. } => template
                .context
                .as_ref()
                .and_then(|context| context.entries.first().map(|entry| entry.key.clone())),
            _ => None,
        })
        .collect();

    assert!(!context_keys.is_empty(), "the request-time gate settles");
    // The caller's name collides with the column, so the plan suffixes the row's
    // parameter. A plan rebuilt from the defaults would not.
    assert!(
        context_keys.iter().all(|key| key != "as_of"),
        "the default plan's parameter name must not appear:\n{context_keys:#?}"
    );
    assert!(
        context_keys.iter().any(|key| key.starts_with("as_of_")),
        "the configured plan suffixes the row's parameter:\n{context_keys:#?}"
    );
}

/// Assertion 4. A consumer reproducing "this subject is a concrete user" reads the
/// name from here rather than spelling it again.
#[test]
fn the_well_known_names_are_reachable_from_another_crate() {
    assert_eq!(USER_TYPE, "user");
    assert_eq!(TEAM_TYPE, "team");
    assert_eq!(PG_ROLE_TYPE, "pg_role");
    assert_eq!(member_relation(), "member");
}

/// Assertion 5. A reserved name is a relation name by construction, so nothing can hand
/// one to a place expecting a column or a type.
#[test]
fn a_reserved_name_is_a_relation_name() {
    let selected: RelationName = can_select_relation();
    assert_eq!(selected, "can_select");
    assert_eq!(member_relation(), "member");
}

/// Assertion 6. The column a record reads is a column name, folded the way `PostgreSQL`
/// stores it, so it cannot be handed to a place expecting a relation or a type.
#[test]
fn the_column_a_record_reads_is_a_column_name() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);
    let owner = entry(&shapes, "docs", "owner");
    let RecordDerivation::FromRow { template, .. } = &owner.shapes[0].derivation else {
        panic!("ownership reads the row itself: {owner:?}");
    };
    let ValueSource::Column(column) = template.subject_key.part() else {
        panic!("the subject is the owner column: {template:?}");
    };
    let column: &ColumnName = column;
    assert_eq!(column, "owner_id");
}

/// A holder stands for a whole member list, so both halves of it have to be
/// described: the row pointing at the holder, and the members it holds.
#[test]
fn a_holder_relation_carries_the_shapes_that_fill_it() {
    let shapes = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    let holder_type = entry(&shapes, "docs", "staff_holder")
        .shapes
        .first()
        .map(|shape| match &shape.derivation {
            RecordDerivation::FromRow { template, .. } => template.subject_type.clone(),
            other => panic!("the bridge resolves from the row, got {other:?}"),
        })
        .expect("the bridge to the holder is described");

    let bridge = entry(&shapes, "docs", "staff_holder");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &bridge.shapes[0].derivation
    else {
        unreachable!("checked above");
    };
    assert_eq!(table.to_string(), "docs");
    assert_eq!(template.object_type, bridge.type_name);
    assert_eq!(template.relation, bridge.relation);
    assert_eq!(template.object_key.parts(), [ValueSource::column("id")]);
    assert!(
        guards.is_empty(),
        "the key needs no NOT NULL guard: a missing part already yields no record"
    );
    assert_eq!(template.subject_type, holder_type);
    assert_eq!(
        template.subject_key.part(),
        &ValueSource::Literal("all".to_string()),
        "one holder object stands for the whole list"
    );

    let members = shapes
        .iter()
        .find(|entry| entry.type_name.as_str() == holder_type.as_str() && !entry.shapes.is_empty())
        .expect("the holder's member list is described");
    assert_eq!(members.shapes.len(), 1, "one member source, one shape");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &members.shapes[0].derivation
    else {
        panic!("a member list with no residual predicate follows from its own row");
    };
    assert_eq!(table.to_string(), "staff");
    assert_eq!(template.object_type, members.type_name);
    assert_eq!(template.relation, members.relation);
    assert_eq!(
        template.object_key.parts(),
        [ValueSource::Literal("all".to_string())],
        "every member row names the same holder object"
    );
    assert!(
        matches!(guards.as_slice(), [Guard::NotNull(column)] if column == "user_id"),
        "a null member is dropped exactly as the query's NULL guard drops it: {guards:?}"
    );
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(template.subject_key.part(), &ValueSource::column("user_id"));
}

/// The same member list carrying a clock comparison: the clock moves into the condition
/// its member tuple names. Several rows can name one user and the holder collapses them,
/// so the latest deadline is read by querying rather than settled from one row.
#[test]
fn a_holder_member_list_with_a_clock_conditions_its_member_tuple() {
    let schema = HOLDER;
    let shapes = shapes_of(schema, ACCESSOR_REGISTRY);
    let holder = shapes
        .iter()
        .find(|entry| {
            entry.type_name.as_str().starts_with("reviewers_holder") && !entry.shapes.is_empty()
        })
        .expect("the reviewers holder is reported");
    let RecordDerivation::Joined { queries, .. } = &holder.shapes[0].derivation else {
        panic!(
            "several rows can name one user, so the deadline is read by querying: {:?}",
            holder.shapes[0].derivation
        );
    };
    assert_eq!(queries.len(), 1, "one table carries the change");
    assert_eq!(queries[0].table().to_string(), "reviewers");
    assert_eq!(queries[0].key_columns(), ["user_id"]);
    assert_eq!(
        queries[0].scope(),
        &ReplayScope::Subject {
            subject_type: TypeName::canonicalized("user"),
            relation: holder.relation.clone(),
            object_type: holder.type_name.clone(),
        },
        "the replay determines what the one member holds through the holder"
    );
    let condition = queries[0]
        .condition()
        .expect("the clock rides the member tuple as a condition");
    let sql = queries[0].sql();
    assert!(
        sql.contains(&format!("'{condition}' AS condition")),
        "the replay names the condition its own SQL projects:\n{sql}"
    );
    assert!(
        sql.contains("MAX(\"vetted_at\")"),
        "several rows collapse to the latest deadline:\n{sql}"
    );
    assert!(
        sql.contains("GROUP BY \"user_id\""),
        "the holder groups by the user it collapses:\n{sql}"
    );
    assert!(
        !sql.contains("now()"),
        "the clock left the WHERE for the condition:\n{sql}"
    );
    assert!(
        sql.contains("\"user_id\" = $1"),
        "the replay binds the changed user's slice:\n{sql}"
    );
}

/// The same member list carrying a residual the row image can evaluate stays a
/// function of its own row, with the residual as a guard: a delete of the
/// member row then reports its record as removed, which a joining shape never
/// could.
#[test]
fn a_holder_member_list_with_a_row_decidable_residual_settles() {
    let schema = "
CREATE TABLE reviewers (user_id TEXT, active BOOLEAN);
CREATE TABLE memos (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY memos_reviewers ON memos FOR SELECT USING (EXISTS (SELECT 1 FROM reviewers
    WHERE reviewers.user_id = auth_current_user_id() AND reviewers.active));
";
    let shapes = shapes_of(schema, ACCESSOR_REGISTRY);
    let holder = shapes
        .iter()
        .find(|entry| entry.type_name.as_str().starts_with("reviewers_holder"))
        .expect("the reviewers holder is reported");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &holder.shapes[0].derivation
    else {
        panic!("the row decides the residual: {holder:?}");
    };
    assert_eq!(table.to_string(), "reviewers");
    assert_eq!(template.subject_key.part(), &ValueSource::column("user_id"));
    assert!(
        matches!(
            guards.as_slice(),
            [Guard::NotNull(user), Guard::IsTrue(active)]
                if user == "user_id" && active == "active"
        ),
        "the residual travels as a guard beside the NULL guard: {guards:?}"
    );
}

#[test]
fn a_text_ordering_attribute_gate_stays_joined() {
    let schema = "
CREATE TABLE public.docs (id TEXT PRIMARY KEY, status TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_status ON docs FOR SELECT USING (status > 'draft');
";
    let shapes = shapes_of(schema, "{}");
    let gate = shapes
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "docs"
                && entry.relation.as_str().starts_with("public_where_status_")
        })
        .expect("the status gate should be reported");
    let [shape] = gate.shapes.as_slice() else {
        panic!("one attribute gate shape, got {:?}", gate.shapes);
    };
    let RecordDerivation::Joined { queries, reason } = &shape.derivation else {
        panic!("text ordering needs SQL: {:?}", shape.derivation);
    };
    assert!(reason.contains("row comparison on status needs SQL"));
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].table().to_string(), "public.docs");
    assert_eq!(queries[0].key_columns().len(), 1);
    assert_eq!(queries[0].key_columns()[0].as_str(), "id");
}

#[test]
fn a_unique_holder_clock_settles_from_its_member_row() {
    let schema = "
CREATE TABLE reviewers (user_id TEXT PRIMARY KEY, active BOOLEAN, vetted_at TIMESTAMPTZ);
CREATE TABLE memos (id TEXT PRIMARY KEY);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE memos ENABLE ROW LEVEL SECURITY;
CREATE POLICY memos_reviewers ON memos FOR SELECT USING (EXISTS (SELECT 1 FROM reviewers
    WHERE reviewers.user_id = auth_current_user_id()
      AND reviewers.active
      AND reviewers.active IS NOT NULL
      AND reviewers.vetted_at > now()));
";
    let shapes = shapes_of(schema, ACCESSOR_REGISTRY);
    let holder = shapes
        .iter()
        .find(|entry| entry.type_name.as_str().starts_with("reviewers_holder"))
        .expect("the reviewers holder is reported");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &holder.shapes[0].derivation
    else {
        panic!("one unique member row decides the holder member: {holder:?}");
    };
    assert_eq!(table.to_string(), "reviewers");
    assert_eq!(template.subject_key.part(), &ValueSource::column("user_id"));
    let context = template
        .context
        .as_ref()
        .expect("the clock rides the member tuple");
    assert!(
        context
            .entries
            .iter()
            .any(|entry| entry.value == ValueSource::column("vetted_at")),
        "the row's timestamp reaches the condition: {:?}",
        context.entries
    );
    assert!(
        guards
            .iter()
            .any(|guard| matches!(guard, Guard::NotNull(column) if column == "vetted_at")),
        "a null timestamp writes no tuple: {guards:?}"
    );
    assert!(
        guards
            .iter()
            .any(|guard| matches!(guard, Guard::IsTrue(column) if column == "active")),
        "the residual boolean stays a row guard: {guards:?}"
    );
    assert!(
        guards
            .iter()
            .any(|guard| matches!(guard, Guard::NotNull(column) if column == "active")),
        "the residual not-null check stays a row guard: {guards:?}"
    );
}

/// A shared holder object is not decided by one row of its member table, since a
/// second row naming the same user keeps the record alive.
#[test]
fn a_holder_relation_is_never_decidable_from_one_row() {
    let shapes = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    for entry in shapes {
        if entry.type_name.as_str().contains("_holder")
            || entry.relation.as_str().contains("_holder")
        {
            assert!(
                !entry.from_one_row,
                "{}#{} holds a shared object, so one row cannot decide it",
                entry.type_name, entry.relation
            );
        }
    }
}

/// A query the loader runs with no shape behind it is a tuple the consumer never
/// learns to maintain, and an empty shape list cannot say so.
#[test]
fn every_query_the_loader_runs_has_a_shape() {
    let mut checked = 0usize;
    let mut cases: Vec<(String, ParserDB, FunctionRegistry)> = Vec::new();
    for fixture in support::fixture_names() {
        let (_, db, registry) = support::try_load_fixture_classified(&fixture);
        cases.push((fixture, db, registry));
    }
    for (label, sql, registry_json) in [
        ("holder", HOLDER, ACCESSOR_REGISTRY),
        ("ownership", OWNERSHIP, ACCESSOR_REGISTRY),
    ] {
        let (db, registry) = parsed(sql, registry_json);
        cases.push((label.to_string(), db, registry));
    }

    for (label, db, registry) in &cases {
        for query in translation(
            db,
            registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        )
        .outputs_accepting_gaps()
        .tuple_queries()
        {
            if query.skipped.is_some() {
                continue;
            }
            checked += 1;
            assert!(
                query.description.is_some(),
                "{label}: a real query must carry a shape:\n{}\n{}",
                query.comment,
                query.sql
            );
        }
    }

    assert!(checked > 0, "no fixture produced a real query");
}

/// A grant whose grantee resolves to no principal renders a comment rather than a
/// query, so there are no records to describe. Answering with a joining shape that
/// carries no query would tell a consumer to query and hand them nothing.
#[test]
fn a_grant_with_no_principal_describes_nothing() {
    let shapes = shapes_of(GRANTS_WITHOUT_PRINCIPALS, GRANT_REGISTRY);
    let graded: Vec<&RelationShapes> = shapes
        .iter()
        .filter(|entry| entry.relation.as_str().starts_with("grant_"))
        .collect();
    assert!(
        !graded.is_empty(),
        "the role threshold still mints its grant relations: {shapes:#?}"
    );
    for entry in graded {
        assert!(
            entry.shapes.is_empty(),
            "{}#{} has no query behind it, so it describes nothing: {:#?}",
            entry.type_name,
            entry.relation,
            entry.shapes
        );
    }
}

/// A role threshold called on the row's own key, beside an unrelated `owner_id` column.
const GRANTS_ON_THE_RESOURCE_KEY: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE TABLE owner_grants (granted_owner_id TEXT, grantee_owner_id TEXT, role_id INT);
CREATE FUNCTION get_owner_role(a TEXT, b TEXT) RETURNS INT LANGUAGE sql STABLE
    AS 'SELECT 1';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (get_owner_role(current_user, id) >= 2);
";

/// The row points at the owner the policy named, never at a column found by its name.
///
/// The ladder answers `get_owner_role(caller, X)` for the X the call passes, so pointing at
/// `owner_id` here would grant whoever equals `owner_id` on a comparison the database makes
/// against `id`, and the row would be readable by the wrong person.
#[test]
fn the_owner_pointer_names_the_column_the_policy_passed() {
    let shapes = shapes_of(GRANTS_ON_THE_RESOURCE_KEY, GRANT_REGISTRY);
    let pointers: Vec<&RecordDescription> = shapes
        .iter()
        .flat_map(|entry| &entry.shapes)
        .filter(|shape| match &shape.derivation {
            RecordDerivation::FromRow { template, .. } => {
                template.object_type == "docs" && template.subject_type == "owner_grants_owner"
            }
            _ => false,
        })
        .collect();
    assert_eq!(
        pointers.len(),
        1,
        "one pointer per guarded table: {pointers:#?}"
    );
    let RecordDerivation::FromRow { template, .. } = &pointers[0].derivation else {
        unreachable!("filtered to row-derived shapes");
    };
    assert_eq!(
        template.subject_key,
        SubjectKey::column("id"),
        "the pointer carries the value the call passed, not the owner-like column"
    );
}

/// Every conditional wildcard in a model, as `(type, relation, condition)`.
fn conditional_wildcards(json: &str) -> Vec<(String, String, String)> {
    let model: serde_json::Value = serde_json::from_str(json).expect("the JSON model parses");
    let mut found = Vec::new();
    for definition in model["type_definitions"].as_array().into_iter().flatten() {
        let type_name = definition["type"].as_str().unwrap_or_default().to_string();
        let relations = definition["metadata"]["relations"].as_object();
        for (relation, meta) in relations.into_iter().flatten() {
            for reference in meta["directly_related_user_types"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some(condition) = reference["condition"].as_str().filter(|c| !c.is_empty()) {
                    found.push((type_name.clone(), relation.clone(), condition.to_string()));
                }
            }
        }
    }
    found
}

/// A condition reads its row's value under a parameter name, and the tuple supplies that
/// value under a context key. The two are minted apart, and a mismatch denies every check
/// on the type while the model and the SQL each look right alone.
#[test]
fn every_condition_parameter_is_supplied_by_its_own_tuples() {
    let mut checked = 0usize;
    let residual = parsed_with_session_attributes(SQL_RESIDUAL_SHARE, EXPIRING_SHARE_ATTRIBUTES);
    for (fixture, db, registry) in [("sql-residual share".to_string(), residual.0, residual.1)] {
        let classified = classify_policies(&db, &registry);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        let json = serde_json::to_string(&outputs.json_model()).expect("the model serializes");
        let model: serde_json::Value = serde_json::from_str(&json).expect("parses");
        let queries = outputs.tuple_queries();

        for (type_name, relation, condition) in conditional_wildcards(&json) {
            checked += 1;
            let parameters = model["conditions"][&condition]["parameters"]
                .as_object()
                .unwrap_or_else(|| {
                    panic!("{fixture}: {type_name}#{relation} names condition '{condition}', which the model does not declare")
                });
            let query = queries
                .iter()
                .find(|query| {
                    query.sql.contains(&format!("'{relation}' AS relation"))
                        && query.sql.contains(&format!("'{condition}' AS condition"))
                })
                .unwrap_or_else(|| {
                    panic!("{fixture}: nothing loads {type_name}#{relation} under '{condition}'")
                });
            let supplied: BTreeSet<&str> = parameters
                .keys()
                .filter(|name| query.sql.contains(&format!("'{name}',")))
                .map(String::as_str)
                .collect();
            assert_eq!(
                supplied.len(),
                1,
                "{fixture}: condition '{condition}' declares {:?} and its tuples supply {supplied:?}, \
                 so exactly one parameter must come from the row:\n{}",
                parameters.keys().collect::<Vec<_>>(),
                query.sql
            );
        }
    }
    assert!(
        checked > 0,
        "no fixture exercises a condition, so this invariant checks nothing"
    );
}

/// Two ownership columns in one clause. Both spellings of it render
/// `define can_select: owner or editor`.
const OR_COLUMNS: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_read ON docs FOR SELECT
    USING (owner_id = auth_current_user_id() OR editor_id = auth_current_user_id());
";

/// The same grant written as two permissive policies.
const TWO_SELECT_POLICIES: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_editor ON docs FOR SELECT USING (editor_id = auth_current_user_id());
";

/// A barrier beside the ownership grant, rendering `define can_select: owner and editor`.
const RESTRICTIVE_BARRIER: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_barrier ON docs AS RESTRICTIVE FOR SELECT
    USING (editor_id = auth_current_user_id());
";

/// A per-row `DELETE` reads the table, so it renders `define can_delete: editor and
/// can_select` over `define can_select: owner`.
const DELETE_GATED_ON_READ: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, editor_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_purge ON docs FOR DELETE USING (editor_id = auth_current_user_id());
";

/// The reported entry's own decision shape. Reading the relation off the entry rather
/// than spelling it again is what keeps the two from disagreeing.
fn leaf(entry: &RelationShapes) -> RowDecision {
    RowDecision::Leaf {
        relation: entry.relation.clone(),
        shapes: entry.shapes.clone(),
    }
}

/// One leaf of a recipe, and what makes it decidable.
enum Leaf<'a> {
    /// The subjects are the ones the row names.
    Named {
        relation: &'a str,
        shapes: &'a [RecordDescription],
    },
    /// Every user, on a row the shapes yield a record for.
    Everyone {
        relation: &'a str,
        shapes: &'a [RecordDescription],
    },
    /// The row settles one side of a comparison the caller's own value completes, so the
    /// subject is a wildcard and the context is what stops it granting everyone.
    Gated {
        relation: &'a str,
        shapes: &'a [RecordDescription],
        context_key: &'a str,
        request_parameter: &'a str,
    },
}

impl<'a> Leaf<'a> {
    fn relation(&self) -> &'a str {
        match self {
            Self::Named { relation, .. }
            | Self::Everyone { relation, .. }
            | Self::Gated { relation, .. } => relation,
        }
    }

    fn shapes(&self) -> &'a [RecordDescription] {
        match self {
            Self::Named { shapes, .. }
            | Self::Everyone { shapes, .. }
            | Self::Gated { shapes, .. } => shapes,
        }
    }
}

/// Every leaf a recipe reaches, in the order it reaches them.
fn recipe_leaves(decision: &RowDecision) -> Vec<Leaf<'_>> {
    match decision {
        RowDecision::Leaf { relation, shapes } => vec![Leaf::Named {
            relation: relation.as_str(),
            shapes: shapes.as_slice(),
        }],
        RowDecision::Everyone { relation, shapes } => vec![Leaf::Everyone {
            relation: relation.as_str(),
            shapes: shapes.as_slice(),
        }],
        RowDecision::RequestGated {
            relation,
            shapes,
            context_key,
            request_parameter,
            ..
        } => vec![Leaf::Gated {
            relation: relation.as_str(),
            shapes: shapes.as_slice(),
            context_key: context_key.as_str(),
            request_parameter: request_parameter.as_str(),
        }],
        RowDecision::Any(children) | RowDecision::All(children) => {
            children.iter().flat_map(recipe_leaves).collect()
        }
        // Its link names the gate object rather than a user, so it adds no user leaf.
        RowDecision::Request { .. } => Vec::new(),
    }
}

/// Whether a recipe reaches a predicate the check context decides with no record.
fn reaches_the_request(decision: &RowDecision) -> bool {
    match decision {
        RowDecision::Request { .. } => true,
        RowDecision::Any(children) | RowDecision::All(children) => {
            children.iter().any(reaches_the_request)
        }
        _ => false,
    }
}

/// Assertion 1. The flag and the recipe leave one traversal, so a relation carrying a
/// recipe is exactly one the flag admits. Two answers derived apart could disagree,
/// which is the divergence this surface exists to remove.
#[test]
fn a_recipe_is_reported_exactly_when_the_flag_says_one_row_decides() {
    let mut with_recipe = 0usize;
    let mut without = 0usize;

    let mut check = |label: &str, reported: &[RelationShapes]| {
        for reported in reported {
            assert_eq!(
                reported.decision.is_some(),
                reported.from_one_row,
                "{label}: {}#{} answers the flag and the recipe differently",
                reported.type_name,
                reported.relation
            );
            if reported.decision.is_some() {
                with_recipe += 1;
            } else {
                without += 1;
            }
        }
    };

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        check(&fixture, planned.translation().relations());
    }
    for (label, sql) in [
        ("or_columns", OR_COLUMNS),
        ("two_select_policies", TWO_SELECT_POLICIES),
        ("restrictive_barrier", RESTRICTIVE_BARRIER),
        ("delete_gated_on_read", DELETE_GATED_ON_READ),
        ("holder", HOLDER),
    ] {
        check(label, &shapes_of(sql, ACCESSOR_REGISTRY));
    }

    assert!(
        with_recipe > 0 && without > 0,
        "the corpus has to exercise both answers, got {with_recipe} with a recipe and {without} without"
    );
}

/// Assertion 2. The relation whose records decide a read is named rather than left to
/// be read out of the DSL text.
#[test]
fn an_ownership_read_names_the_relation_whose_records_decide_it() {
    let shapes = shapes_of(OWNERSHIP, ACCESSOR_REGISTRY);
    let owner = entry(&shapes, "docs", "owner");

    assert!(
        !owner.shapes.is_empty(),
        "the recipe carries these, so an empty list would say nothing"
    );
    assert_eq!(
        entry(&shapes, "docs", "can_select").decision.as_ref(),
        Some(&leaf(owner)),
        "can_select is defined as owner, so its subjects are owner's records"
    );
}

/// Assertion 3. A union of two ownership columns composes, and the composition is a
/// mirror of the model rather than of the spelling: whichever operand order the DSL
/// renders, the recipe reaches its leaves in that order. Two permissive policies and
/// one `OR` clause therefore give the same recipe exactly when they render the same
/// definition, which is the property the flag would otherwise be trusted to imply.
#[test]
fn either_spelling_of_two_ownership_columns_composes_into_any() {
    let shapes = shapes_of(OR_COLUMNS, ACCESSOR_REGISTRY);
    let expected = RowDecision::Any(vec![
        leaf(entry(&shapes, "docs", "owner")),
        leaf(entry(&shapes, "docs", "editor")),
    ]);
    assert_eq!(
        entry(&shapes, "docs", "can_select").decision.as_ref(),
        Some(&expected),
        "either column admits the row, so the recipe is a union of both"
    );

    for (label, sql) in [
        ("one clause", OR_COLUMNS),
        ("two policies", TWO_SELECT_POLICIES),
    ] {
        let (db, registry) = parsed(sql, ACCESSOR_REGISTRY);
        let planned = translation(
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        let reported = planned.relations();
        let named: Vec<&str> = recipe_leaves(
            entry(reported, "docs", "can_select")
                .decision
                .as_ref()
                .expect("an ownership read decides from the row"),
        )
        .into_iter()
        .map(|leaf| leaf.relation())
        .collect();
        assert_eq!(
            named,
            rendered_operands(
                &planned.clone().outputs_accepting_gaps().model(),
                "can_select",
            ),
            "{label}: the recipe reaches the operands the model names, in that order"
        );
    }
}

/// The operands of one relation's rendered definition, which for these schemas is a
/// flat list of relation names.
fn rendered_operands<'a>(dsl: &'a str, relation: &str) -> Vec<&'a str> {
    let definition = format!("define {relation}:");
    dsl.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&definition))
        .unwrap_or_else(|| panic!("{relation} should be defined:\n{dsl}"))
        .split(" or ")
        .map(str::trim)
        .collect()
}

/// Assertion 4. The one that settles the design. A barrier renders `owner and editor`,
/// whose flag is true and whose subjects are an intersection, so a recipe flattened
/// into one list would let an owner who is not the editor read the row.
#[test]
fn a_restrictive_barrier_composes_into_all_rather_than_one_flat_list() {
    let shapes = shapes_of(RESTRICTIVE_BARRIER, ACCESSOR_REGISTRY);
    let can_select = entry(&shapes, "docs", "can_select");

    assert!(
        can_select.from_one_row,
        "both sides of the barrier resolve from the row"
    );
    let expected = RowDecision::All(vec![
        leaf(entry(&shapes, "docs", "owner")),
        leaf(entry(&shapes, "docs", "editor")),
    ]);
    assert_eq!(
        can_select.decision.as_ref(),
        Some(&expected),
        "the barrier removes subjects, so the recipe is an intersection"
    );
}

/// Assertion 5. A recipe names the relations records fill, so a relation the model
/// computes is flattened into whatever it names rather than reported as a hop the
/// consumer has to resolve.
#[test]
fn a_computed_relation_inside_a_recipe_flattens_into_what_it_names() {
    let shapes = shapes_of(DELETE_GATED_ON_READ, ACCESSOR_REGISTRY);
    let expected = RowDecision::All(vec![
        leaf(entry(&shapes, "docs", "editor")),
        leaf(entry(&shapes, "docs", "owner")),
    ]);
    assert_eq!(
        entry(&shapes, "docs", "can_delete").decision.as_ref(),
        Some(&expected),
        "can_delete is `editor and can_select` over `can_select: owner`"
    );
}

/// Assertion 6. What the recipe inherits from the flag: every leaf resolves from the
/// object's own row to a user the consumer can compare against, or to every user through
/// the typed wildcard and nothing else.
#[test]
fn every_leaf_of_every_recipe_names_a_user_from_the_objects_own_row() {
    let mut checked = 0usize;

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        for reported in planned.translation().relations() {
            let Some(decision) = reported.decision.as_ref() else {
                continue;
            };
            let reached = recipe_leaves(decision);
            assert!(
                !reached.is_empty() || reaches_the_request(decision),
                "{fixture}: {}#{} reports a recipe reaching no leaf, which grants either \
                 nobody or everybody depending on how it composes",
                reported.type_name,
                reported.relation
            );
            for leaf in reached {
                let relation = leaf.relation();
                assert!(
                    !leaf.shapes().is_empty(),
                    "{fixture}: leaf {}#{relation} carries no shape, so it decides nothing",
                    reported.type_name
                );
                for shape in leaf.shapes() {
                    checked += 1;
                    let RecordDerivation::FromRow {
                        table, template, ..
                    } = &shape.derivation
                    else {
                        panic!(
                            "{fixture}: leaf {}#{relation} needs a query: {shape:#?}",
                            reported.type_name
                        );
                    };
                    assert_eq!(
                        template.object_type, reported.type_name,
                        "{fixture}: leaf {relation} keys objects of another type"
                    );
                    assert_eq!(template.relation, relation, "{fixture}: leaf misattributed");
                    let expected_key: Vec<ValueSource> = primary_key_of(table, &db)
                        .into_iter()
                        .map(ValueSource::column)
                        .collect();
                    assert_eq!(
                        template.object_key.parts(),
                        expected_key,
                        "{fixture}: leaf {}#{relation} keys on columns that are not the \
                         row's identity",
                        reported.type_name
                    );
                    assert_eq!(
                        template.subject_type, USER_TYPE,
                        "{fixture}: leaf {}#{relation} names a subject the consumer cannot \
                         compare against",
                        reported.type_name
                    );
                    match &leaf {
                        Leaf::Named { .. } => assert!(
                            !matches!(template.subject_key.part(), &ValueSource::Literal(_)),
                            "{fixture}: leaf {}#{relation} carries a literal subject: {:?}",
                            reported.type_name,
                            template.subject_key
                        ),
                        // A condition on an everyone leaf would grant everyone past it.
                        Leaf::Everyone { .. } => assert!(
                            template.subject_key.is_wildcard() && template.context.is_none(),
                            "{fixture}: everyone leaf {}#{relation} is not an unconditional \
                             wildcard: {template:?}",
                            reported.type_name
                        ),
                        // A gated leaf grants the wildcard, so the context is the only
                        // thing standing between it and granting everyone. Losing the
                        // context or naming it differently from the recipe is a wrong
                        // allow no DSL assertion can see.
                        Leaf::Gated {
                            context_key,
                            request_parameter,
                            ..
                        } => {
                            assert_eq!(
                                template.subject_key.part(),
                                &ValueSource::Literal("*".to_string()),
                                "{fixture}: gated leaf {}#{relation} grants named subjects \
                                 rather than the wildcard the condition filters",
                                reported.type_name
                            );
                            let context = template.context.as_ref().unwrap_or_else(|| {
                                panic!(
                                    "{fixture}: gated leaf {}#{relation} carries no context, \
                                     so its records grant everyone",
                                    reported.type_name
                                )
                            });
                            assert!(
                                context
                                    .entries
                                    .iter()
                                    .any(|entry| entry.key == *context_key),
                                "{fixture}: gated leaf {}#{relation} fills a different \
                                 parameter from the one the recipe names",
                                reported.type_name
                            );
                            assert!(
                                !request_parameter.is_empty(),
                                "{fixture}: gated leaf {}#{relation} names no parameter for \
                                 the caller to supply",
                                reported.type_name
                            );
                        }
                    }
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no fixture reports a recipe, so this checks nothing"
    );
}

/// Every column the crate identifies rows by, in declared order: the declared primary
/// key whatever its arity, or the `id` column it falls back to when a table declares
/// none. This is what an object key holds.
fn primary_key_of(table: &TableId, db: &ParserDB) -> Vec<String> {
    let columns: Vec<String> = lookup_table(db, &table.to_string())
        .and_then(|found| found.primary_key_columns(db).ok())
        .map(|columns| {
            columns
                .map(|c| c.stored_column_name().into_owned())
                .collect()
        })
        .unwrap_or_default();
    if columns.is_empty() {
        vec!["id".to_string()]
    } else {
        columns
    }
}

/// An arm nothing can classify, so the threshold drops it while the ownership arm
/// beside it survives. `opaque_gate` is deliberately unregistered and bodyless, so
/// no later vocabulary work can make it recognizable and quietly retire these tests.
const PARTIAL_SELECT_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_opaque ON docs FOR SELECT USING (opaque_gate(id));
";

/// The same loss spread over every command. Neither policy stores a `WITH CHECK`, so
/// `PostgreSQL` mirrors each `USING` onto the check side and the dropped arm reaches
/// `can_insert` only through that mirror. Storing an explicit check instead would
/// reach `can_insert` through the check arm and leave the mirror untested.
const FOR_ALL_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR ALL USING (owner_id = auth_current_user_id());
CREATE POLICY docs_opaque ON docs FOR ALL USING (opaque_gate(id));
";

/// One UPDATE policy whose USING survives and whose WITH CHECK does not.
const WITH_CHECK_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_upd ON docs FOR UPDATE USING (owner_id = auth_current_user_id())
    WITH CHECK (opaque_gate(id));
";

/// A permissive policy `PostgreSQL` resolved to the DDL runner, so a dump cannot say
/// who it binds and the whole policy is dropped beside a surviving arm.
const DDL_ROLE_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, team_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY docs_cu ON docs FOR SELECT TO CURRENT_USER
    USING (team_id = auth_current_user_id());
";

/// The attribute half of a permissive conjunction is handed to the application, so
/// the emitted relation is WIDER than the database rather than narrower.
const GUARD_DISCARD: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, status TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT
    USING (owner_id = auth_current_user_id() AND status LIKE 'open%');
";

/// Phase 1, test 1. A permissive arm the threshold dropped makes the emitted
/// relation narrower than the database, so no row decides it. A consumer answering
/// from the recipe would otherwise hide rows `PostgreSQL` shows.
#[test]
fn a_dropped_permissive_arm_leaves_the_relation_it_narrowed_undecidable() {
    let shapes = shapes_at(PARTIAL_SELECT_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    let can_select = entry(&shapes, "docs", "can_select");
    assert!(
        !can_select.from_one_row,
        "the dropped arm makes can_select narrower than the database, so one row \
         cannot decide it: {can_select:#?}"
    );
    assert!(
        can_select.decision.is_none(),
        "and the recipe has to agree with the flag"
    );
    assert!(
        entry(&shapes, "docs", "owner").from_one_row,
        "the surviving arm still fills its own relation from the row, so the scar \
         is targeted rather than a blanket refusal"
    );
}

/// Phase 1, test 2. A FOR ALL pair loses every command at once, the INSERT side
/// through the USING to WITH CHECK mirror.
#[test]
fn a_dropped_for_all_arm_undecides_every_action_relation_it_fed() {
    let shapes = shapes_at(FOR_ALL_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    for relation in [
        "can_select",
        "can_insert",
        "can_update",
        "can_delete",
        "can_update_without_reading",
        "can_select_for_update",
    ] {
        let reported = entry(&shapes, "docs", relation);
        assert!(
            !reported.from_one_row,
            "docs#{relation} lost an arm, so one row cannot decide it"
        );
    }
    assert!(
        entry(&shapes, "docs", "owner").from_one_row,
        "the row still fills owner"
    );
}

/// Phase 1, test 3. Losing the WITH CHECK costs the update, and nothing else. A
/// locking read filters by the UPDATE USING alone, which survived, so it stays
/// decidable and the scar does not spread further than the loss.
#[test]
fn a_dropped_with_check_undecides_the_update_but_not_the_locking_read() {
    let shapes = shapes_at(WITH_CHECK_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    assert!(
        !entry(&shapes, "docs", "can_update").from_one_row,
        "the check half was lost, so can_update is not decidable"
    );
    assert!(
        entry(&shapes, "docs", "can_select_for_update").from_one_row,
        "a locking read filters by the surviving USING alone, so it stays decidable"
    );
    assert!(
        entry(&shapes, "docs", "can_select").from_one_row,
        "and the SELECT policy was never touched"
    );
}

/// Phase 1, test 7. The scar is metadata. An entry naming a relation the plan never
/// defines reaches nothing: `can_insert_returning` is folded away here because the
/// insert rule already implies the read.
#[test]
fn a_scar_on_a_relation_the_plan_never_defines_is_inert() {
    let shapes = shapes_at(FOR_ALL_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    assert!(
        !shapes
            .iter()
            .any(|reported| reported.relation == "can_insert_returning"),
        "a scar must not conjure a relation the model does not define"
    );
    assert_eq!(
        model_at(FOR_ALL_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B),
        "model\n  schema 1.1\n\
         \ntype user\n\
         \ntype docs\n  relations\n\
         \u{20}   define owner: [user]\n\
         \u{20}   define can_delete: owner\n\
         \u{20}   define can_insert: owner\n\
         \u{20}   define can_select: owner\n\
         \u{20}   define can_select_for_update: can_update\n\
         \u{20}   define can_update: owner\n\
         \u{20}   define can_update_without_reading: owner\n",
        "the scar changes no DSL byte"
    );
}

/// Phase 1, test 8a. A policy bound to a role only the DDL knew is dropped whole,
/// which narrows the survivor's relation exactly as a threshold drop does.
#[test]
fn a_policy_bound_to_a_ddl_time_role_undecides_what_it_would_have_widened() {
    let shapes = shapes_at(DDL_ROLE_DROP, ACCESSOR_REGISTRY, ConfidenceLevel::B);

    assert!(
        !entry(&shapes, "docs", "can_select").from_one_row,
        "the dropped TO CURRENT_USER policy granted rows the model no longer does"
    );
}

/// Phase 1, test 8b. A policy naming a table two schemas both bear belongs to one of
/// them and the schema cannot say which, so both candidates lost a grant. Reached
/// through the already-classified door, since `parse_schema` refuses the spelling
/// outright with `TableNotFoundForPolicy`.
#[test]
fn a_policy_whose_table_does_not_resolve_undecides_every_table_that_bears_the_name() {
    let sql = "
CREATE SCHEMA a;
CREATE SCHEMA b;
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE a.docs (id TEXT PRIMARY KEY, owner_id TEXT, team_id TEXT);
CREATE TABLE b.docs (id TEXT PRIMARY KEY, owner_id TEXT, team_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE a.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE b.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY a_owner ON a.docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY b_owner ON b.docs FOR SELECT USING (owner_id = auth_current_user_id());
CREATE POLICY a_team ON a.docs FOR SELECT USING (team_id = auth_current_user_id());
";
    let (db, registry) = parsed(sql, ACCESSOR_REGISTRY);
    let classified: Vec<_> = classify_policies(&db, &registry)
        .into_iter()
        .map(|cp| {
            if cp.name() == "a_team" {
                // Both schemas bear `docs`, so the catalog cannot place this spelling.
                cp.guarding_unresolvable_table("docs")
            } else {
                cp
            }
        })
        .collect();
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let shapes = planned.translation().relations();

    for type_name in ["docs", "docs_09be04be"] {
        assert!(
            !entry(shapes, type_name, "can_select").from_one_row,
            "{type_name} may be the table the unresolved policy granted, so it \
             cannot claim one row decides its reads"
        );
    }
}

/// Phase 1, test 8c. The one drift that widens. The attribute half is handed to the
/// application, so the model grants rows `PostgreSQL` hides, and a consumer answering
/// locally would allow rather than deny. The DSL is unchanged, so only the scar
/// separates this from a faithful ownership grant.
#[test]
fn a_discarded_attribute_guard_undecides_the_relation_it_widened() {
    let shapes = shapes_at(GUARD_DISCARD, ACCESSOR_REGISTRY, ConfidenceLevel::C);

    assert!(
        !entry(&shapes, "docs", "can_select").from_one_row,
        "the discarded status guard makes the model wider than the database"
    );
    assert!(
        model_at(GUARD_DISCARD, ACCESSOR_REGISTRY, ConfidenceLevel::C)
            .contains("define can_select: owner\n"),
        "and the emitted model is untouched, so the scar is the only difference"
    );
}

/// Phase 1, test 6. The standing guard that no path can lose a clause silently.
/// Every clause the schema declares either survives into the confidence summary or is
/// named by a machine readable note: keyed on its own policy, or, where the loss
/// belongs to the table's read graph rather than to any one policy, by the recursion
/// note that names the table and the cycle.
///
/// Deliberately not satisfied by a note that merely mentions the table, since
/// `TableOwnerBypassesPolicies` names every RLS-enabled table and would pass this
/// vacuously for the whole corpus.
#[test]
fn every_declared_clause_reaches_the_summary_or_a_note_that_names_it() {
    let mut checked = 0usize;
    let mut unaccounted: Vec<String> = Vec::new();

    for fixture in support::fixture_names() {
        let (classified, db, registry) = support::try_load_fixture_classified(&fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

        let surviving: BTreeSet<String> = outputs
            .confidence_summary()
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        let named: BTreeSet<String> = outputs
            .notes()
            .iter()
            .map(|note| note.subject().into_owned())
            .collect();
        let looping: BTreeSet<String> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::PolicyReadRecursion { table, .. } => Some(table.to_string()),
                _ => None,
            })
            .collect();

        for policy in db.policies() {
            let name = policy.name().to_string();
            let table = policy.target_table_name().to_string();
            for (label, stored) in [
                ("USING", policy.using_expression(&db).is_some()),
                ("WITH CHECK", policy.check_expression(&db).is_some()),
            ] {
                if !stored {
                    continue;
                }
                checked += 1;
                let survivor = if label == "USING" {
                    name.clone()
                } else {
                    format!("{name} (WITH CHECK)")
                };
                if surviving.contains(survivor.as_str())
                    || named.contains(name.as_str())
                    || looping.contains(table.as_str())
                {
                    continue;
                }
                unaccounted.push(format!("{fixture}: {name} ({label})"));
            }
        }
    }

    assert!(
        checked > 20,
        "the corpus should not have shrunk, only {checked} clauses seen"
    );
    assert!(
        unaccounted.is_empty(),
        "a clause the database evaluates reaches no machine readable surface: {unaccounted:#?}"
    );
}

/// A barrier the threshold dropped, beside a surviving ownership grant.
const RESTRICTIVE_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT, is_public BOOLEAN);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_sel ON docs FOR SELECT USING (owner_id = current_user);
CREATE POLICY docs_bar ON docs AS RESTRICTIVE FOR SELECT USING (is_public);
";

/// Nothing survives, so the command falls closed outright.
const TOTAL_DROP: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_opaque ON docs FOR SELECT USING (opaque_gate(id));
";

/// Phase 1, test 9. Shapes already non decidable before any scar existed, pinned so
/// the scar is not the only thing holding them up. Three different mechanisms: a
/// barrier that fell closed, a command left with nothing to grant it, and an arm kept
/// at a threshold low enough that it translates into a denial instead of vanishing.
#[test]
fn the_shapes_that_were_already_undecidable_stay_undecidable() {
    for (label, sql, level) in [
        ("a dropped barrier", RESTRICTIVE_DROP, ConfidenceLevel::A),
        ("every arm dropped", TOTAL_DROP, ConfidenceLevel::B),
        (
            "an unrecognized arm kept",
            PARTIAL_SELECT_DROP,
            ConfidenceLevel::D,
        ),
    ] {
        let shapes = shapes_at(sql, ACCESSOR_REGISTRY, level);
        assert!(
            !entry(&shapes, "docs", "can_select").from_one_row,
            "{label}: the model and the database disagree, so no row decides the read"
        );
    }
}

/// Phase 3, test 6. Where the six session-attribute fixtures stand once the request
/// vocabulary exists: each declares the values its deployment carries, and each is
/// translated or scarred accordingly.
///
/// This replaces `the_session_attribute_fixtures_are_refused_and_scarred_today`, phase
/// 2's declared flip target, which pinned all six as refused. Four now translate whole,
/// and `connetto_capability` keeps the two shapes phase 3 did not reach, so the
/// replacement asserts more than the pin it removes rather than less.
#[test]
fn the_session_attribute_fixtures_translate_or_scar_what_is_left() {
    let expected: [(&str, &[&str], &[&str]); 6] = [
        (
            "connetto_or_policy",
            &[],
            &[
                "notes#can_delete",
                "notes#can_insert",
                "notes#can_select",
                "notes#can_select_for_update",
                "notes#can_update",
                "notes#can_update_without_reading",
                "notes#gate_notes_p_dbaa5e0d",
                "notes#owner",
            ],
        ),
        (
            "connetto_two_policy",
            &[],
            &[
                "notes#can_delete",
                "notes#can_insert",
                "notes#can_select",
                "notes#can_select_for_update",
                "notes#can_update",
                "notes#can_update_without_reading",
                "notes#gate_notes_subject_c7ba450d",
                "notes#owner",
            ],
        ),
        // `papers_p` translates whole, the ownership arm and the share arm both, and
        // `shares_insert` translates as delegation to the parent even though connetto
        // declares no key, because the policy states the join itself. `paper_shares` has
        // a row identity built from its two-column key, so it reports no loss and its own
        // reads are decidable.
        //
        // The share arm settles from the share row: each share is its own object on
        // `paper_shares_share`. `shares_delete USING (true)` grants every user, so the
        // delete is decided by the row as well.
        (
            "connetto_capability",
            &[],
            &[
                "paper_shares#can_delete",
                "paper_shares#can_select",
                "paper_shares#gate_shares_read_abbc62d2",
                "paper_shares#public_viewer",
                "paper_shares_share#gate_papers_p_3b273139",
                "papers#owner",
            ],
        ),
        (
            "tenant_setting",
            &[],
            &[
                "documents#can_delete",
                "documents#can_insert",
                "documents#can_select",
                "documents#can_select_for_update",
                "documents#can_update",
                "documents#can_update_without_reading",
                "documents#gate_documents_tenant_78bd68be",
            ],
        ),
        (
            "supabase_mfa_restrictive",
            &[],
            &["documents#can_select", "documents#owner"],
        ),
        ("claims_role_gate", &[], &["audit_log#can_select"]),
    ];

    for (fixture, scars, decidable) in expected {
        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

        let reported: Vec<String> = planned
            .translation()
            .relations()
            .iter()
            .filter(|shape| shape.from_one_row)
            .map(|shape| format!("{}#{}", shape.type_name, shape.relation))
            .collect();
        assert_eq!(
            reported, decidable,
            "{fixture}: the relations the model fills from one row"
        );

        let outputs = &planned;
        let mut named: Vec<String> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::ClauseBelowThreshold { policy, .. } => {
                    Some(format!("ClauseBelowThreshold {policy}"))
                }
                TranslationNote::RowsCannotBeNamed { table, .. } => {
                    Some(format!("RowsCannotBeNamed {table}"))
                }
                _ => None,
            })
            .collect();
        named.sort();
        named.dedup();
        assert_eq!(
            named, scars,
            "{fixture}: what the translation says it lost, and about which policy"
        );
    }
}

/// A grant recorded on a sharing table is stated by the share row alone: the
/// object is keyed on the row's foreign key, and the viewer the request has to
/// hold travels in the record's context. Deleting the share then reports the
/// record as removed, which a shape answered only by replaying never says.
/// The recipe still delegates, because no row of the guarded table decides it.
#[test]
fn a_share_recorded_elsewhere_settles_from_the_share_row() {
    let (classified, db, registry) = support::try_load_fixture_classified("connetto_capability");
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let reported = planned.translation().relations();
    let gate = reported
        .iter()
        .find(|shape| {
            shape.type_name.as_str() == "paper_shares_share"
                && shape.relation.as_str().starts_with("gate_")
        })
        .expect("the share arm mints a gate relation on the share type");

    assert!(
        gate.from_one_row,
        "each share row is its own object, so the share row settles it"
    );
    let [shape] = gate.shapes.as_slice() else {
        panic!(
            "the gate is filled by exactly one shape, got {:?}",
            gate.shapes
        );
    };
    assert_eq!(
        shape
            .tables
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["paper_shares".to_string()],
        "the deciding rows live on the sharing table"
    );
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &shape.derivation
    else {
        panic!(
            "the share row alone states the record, got {:?}",
            shape.derivation
        );
    };
    assert_eq!(table.to_string(), "paper_shares");
    assert_eq!(template.object_type, "paper_shares_share");
    assert_eq!(
        template.object_key.parts(),
        [
            ValueSource::column("paper_id"),
            ValueSource::column("viewer")
        ],
        "each share is its own object, keyed on the whole join key"
    );
    assert_eq!(template.relation, gate.relation);
    assert_eq!(template.subject_type, USER_TYPE);
    assert_eq!(
        template.subject_key,
        SubjectKey::wildcard(),
        "the request supplies the viewer, so the subject is the wildcard"
    );
    let context = template
        .context
        .as_ref()
        .expect("the record carries the row's side of the comparison");
    assert_eq!(
        context.entries.len(),
        1,
        "the settled share carries only the viewer"
    );
    assert_eq!(context.entries[0].key, "viewer");
    assert_eq!(context.entries[0].value, ValueSource::column("viewer"));
    assert!(
        matches!(
            guards.as_slice(),
            [Guard::NotNull(member)] if member == "viewer"
        ),
        "the object key guards the share's own key, leaving the member NULL guard: {guards:?}"
    );

    let json = serde_json::to_string(&planned.json_model()).expect("the model serializes");
    let declared: Vec<String> = conditional_wildcards(&json)
        .into_iter()
        .filter(|(type_name, relation, _)| {
            type_name == "paper_shares_share" && relation == gate.relation.as_str()
        })
        .map(|(_, _, condition)| condition)
        .collect();
    assert_eq!(
        declared,
        core::slice::from_ref(&context.condition),
        "the record names the condition the model declares"
    );
}

/// A guarded row shared to two viewers must not collide at `OpenFGA` load. Keying every
/// share tuple on the paper put two viewers on one `(user:*, gate, papers:id)` triple,
/// which `OpenFGA` rejects as a duplicate write. Each share row now becomes its own object
/// reached through a tuple-to-userset, so two viewers are two objects that union.
#[test]
fn a_caller_set_share_gets_its_own_object_reached_by_userset() {
    let (classified, db, registry) = support::try_load_fixture_classified("connetto_capability");
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let dsl = outputs.model();

    assert!(
        dsl.contains("type paper_shares_share"),
        "each share row needs its own object type:\n{dsl}"
    );
    assert!(
        dsl.contains("define paper_shares_share: [paper_shares_share]"),
        "papers must link to its shares:\n{dsl}"
    );
    assert!(
        dsl.contains(" from paper_shares_share"),
        "the share arm must be reached by tuple-to-userset:\n{dsl}"
    );

    let queries = outputs.tuple_queries();
    let gate = queries
        .iter()
        .find(|query| query.condition.is_some() && query.sql.contains("gate_papers_p"))
        .expect("the membership arm emits a conditional gate query");
    assert!(
        gate.sql.contains("'paper_shares_share:'"),
        "the gate object is the share row, not the paper it collides on:\n{}",
        gate.sql
    );
    assert!(
        !gate.sql.contains("'papers:'"),
        "no gate tuple may be keyed on the paper, or two viewers collide:\n{}",
        gate.sql
    );
    assert!(
        queries.iter().any(|query| {
            query.condition.is_none()
                && query.sql.contains("'papers:'")
                && query.sql.contains("'paper_shares_share:'")
        }),
        "a bridge must link each paper to its share objects"
    );
}

/// A clock guard is settled by the request rather than the row, so the record carries
/// the condition and the row's own timestamp in its context, while the row alone
/// decides which record exists. Keyed on a whole compound key, which is the shape a
/// consumer holding one row has no other way to identify.
const CLOCK_GATE_COMPOUND_KEY: &str = "
CREATE TABLE readings (
    tenant_id INT,
    reading_id INT,
    starts_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, reading_id)
);
ALTER TABLE readings ENABLE ROW LEVEL SECURITY;
CREATE POLICY readings_visible ON readings FOR SELECT TO PUBLIC USING (starts_at <= now());
";

/// A consumer holds the record and not the whole-table query it came from, so the
/// record has to name the condition its context is judged by. Reading a conditional
/// record as unconditional takes the wildcard subject at face value.
#[test]
fn a_clock_gated_record_names_the_condition_its_context_carries() {
    let (db, registry) = parsed(CLOCK_GATE_COMPOUND_KEY, "{}");
    let planned = translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let reported = planned.relations();
    let gate = reported
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "readings" && entry.relation.as_str().starts_with("gate_")
        })
        .expect("a clock guard mints a gate relation on readings");
    let [shape] = gate.shapes.as_slice() else {
        panic!("the gate is filled by one shape, got {:?}", gate.shapes);
    };
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &shape.derivation
    else {
        panic!(
            "the row decides which record exists: {:?}",
            shape.derivation
        );
    };
    assert_eq!(table.to_string(), "readings");
    assert_eq!(
        template.object_key.parts(),
        [
            ValueSource::column("tenant_id"),
            ValueSource::column("reading_id")
        ],
        "the whole key names one row"
    );
    assert!(
        matches!(
            guards.as_slice(),
            [Guard::NotNull(column)] if column == "starts_at"
        ),
        "a row with no timestamp writes no record, as the query's WHERE drops it: {guards:?}"
    );
    let context = template
        .context
        .as_ref()
        .expect("the record carries the row's side of the comparison");
    assert_eq!(
        context.entries.len(),
        1,
        "the clock gate carries only starts_at"
    );
    assert_eq!(context.entries[0].value, ValueSource::column("starts_at"));

    let json = serde_json::to_string(&planned.clone().outputs_accepting_gaps().json_model())
        .expect("the model serializes");
    let declared: Vec<String> = conditional_wildcards(&json)
        .into_iter()
        .filter(|(type_name, relation, _)| {
            type_name == "readings" && relation == gate.relation.as_str()
        })
        .map(|(_, _, condition)| condition)
        .collect();
    assert_eq!(
        declared,
        core::slice::from_ref(&context.condition),
        "the record names the condition the model declares"
    );
}

/// The connetto share arm with an expiry on the share row. The viewer set is the
/// request's and the clock the request's too, so both comparisons move into the
/// condition and the share row alone decides the record.
const EXPIRING_SHARE: &str = "
CREATE TABLE public.papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE public.paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    owner = current_setting('app.user_id', true)
    OR EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now()
    )
);
";

const EXPIRING_SHARE_ATTRIBUTES: &str = r#"[
  { "key": "app.user_id", "kind": "caller_id" },
  { "key": "app.subjects", "kind": "set_attribute" }
]"#;

/// A share gated by the caller's set, with a residual only SQL can evaluate (a
/// column-to-column comparison), so the shape stays joined and its replay still carries
/// the viewer-set condition. Keeps the conditional-join projection covered now that an
/// expiring share settles from its row.
const SQL_RESIDUAL_SHARE: &str = "
CREATE TABLE public.papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE public.paper_shares (
    paper_id INT,
    viewer TEXT,
    granted_at TIMESTAMPTZ,
    reviewed_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.granted_at > s.reviewed_at
    )
);
";

fn tuple_contract_cases() -> Vec<(String, ParserDB, FunctionRegistry)> {
    let residual = parsed_with_session_attributes(SQL_RESIDUAL_SHARE, EXPIRING_SHARE_ATTRIBUTES);
    let plain = parsed(QUOTED_MEMBERSHIP, ACCESSOR_REGISTRY);
    let mut cases = vec![
        ("sql-residual share".to_string(), residual.0, residual.1),
        ("quoted membership".to_string(), plain.0, plain.1),
    ];
    for fixture in support::fixture_names() {
        let (_, db, registry) = support::try_load_fixture_classified(&fixture);
        cases.push((fixture, db, registry));
    }
    cases
}

fn joined_shape_queries() -> Vec<(String, RelationShapes, BoundQuery)> {
    let mut result = Vec::new();
    for (fixture, db, registry) in tuple_contract_cases() {
        let planned = translation(
            &db,
            &registry,
            ConfidenceLevel::B,
            &GeneratorSettings::default(),
        );
        for entry in planned.relations() {
            for shape in &entry.shapes {
                let RecordDerivation::Joined { queries, .. } = &shape.derivation else {
                    continue;
                };
                for query in queries {
                    result.push((fixture.clone(), entry.clone(), query.clone()));
                }
            }
        }
    }
    result
}

/// An expiring share settles from the share row: the clock comparison joins the viewer
/// set inside the condition, so the row alone decides the record and its context carries
/// the boundary. A record written today no longer grants tomorrow, because the check
/// re-evaluates the clock the request supplies.
#[test]
fn an_expiring_share_settles_from_its_row_with_the_clock_in_its_condition() {
    let (db, registry) = parsed_with_session_attributes(EXPIRING_SHARE, EXPIRING_SHARE_ATTRIBUTES);
    let planned = translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let reported = planned.relations();
    let gate = reported
        .iter()
        .find(|entry| {
            entry.type_name.as_str() == "paper_shares_share"
                && entry.relation.as_str().starts_with("gate_")
        })
        .expect("the share arm mints a gate relation on the share type");
    let [shape] = gate.shapes.as_slice() else {
        panic!("the gate is filled by one shape, got {:?}", gate.shapes);
    };
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &shape.derivation
    else {
        panic!(
            "the clock in the condition lets the share row alone decide: {:?}",
            shape.derivation
        );
    };
    assert_eq!(table.to_string(), "public.paper_shares");
    assert_eq!(template.object_type, "paper_shares_share");
    assert_eq!(
        template.object_key.parts(),
        [
            ValueSource::column("paper_id"),
            ValueSource::column("viewer")
        ]
    );
    assert_eq!(template.subject_key, SubjectKey::wildcard());
    let context = template
        .context
        .as_ref()
        .expect("the record carries both sides the request completes");
    assert!(
        context
            .entries
            .iter()
            .any(|entry| entry.value == ValueSource::column("viewer")),
        "the viewer set is one comparison: {:?}",
        context.entries
    );
    assert!(
        context
            .entries
            .iter()
            .any(|entry| entry.value == ValueSource::column("expires_at")),
        "the clock is the other, carried in the same context: {:?}",
        context.entries
    );
    assert!(
        guards
            .iter()
            .any(|guard| matches!(guard, Guard::NotNull(column) if column == "expires_at")),
        "a share with no expiry writes no record, as the query's WHERE drops it: {guards:?}"
    );

    let outputs = planned.outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        dsl.lines()
            .any(|line| line.contains("viewer in app_subjects && expires_at > request_time")),
        "the condition joins the viewer set and clock with &&, not ||:\n{dsl}"
    );

    let queries = outputs.tuple_queries();
    let query = queries
        .iter()
        .find(|query| query.condition.is_some() && query.sql.contains("paper_shares"))
        .expect("the share arm renders a conditional query");
    assert!(
        !query.sql.contains("now()"),
        "the clock left the WHERE for the condition:\n{}",
        query.sql
    );
    assert!(
        query.sql.contains("\"expires_at\" IS NOT NULL"),
        "a null expiry writes no tuple, matching PostgreSQL:\n{}",
        query.sql
    );
    assert!(
        query.sql.contains(
            "jsonb_build_object('viewer', \"viewer\"::text, 'expires_at', \"expires_at\")"
        ),
        "the boundary travels in the tuple context:\n{}",
        query.sql
    );

    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::CallerSuppliesConditionParameter { parameter, setting_key, .. }
                if parameter == "request_time" && setting_key.is_none()
        )),
        "the request supplies the clock: {:?}",
        outputs.notes()
    );
}

/// The membership arm carries a grace period, `s.expires_at > now() - interval '30 days'`.
/// The offset is the request clock's to apply, so it rides the condition as a duration
/// beside the viewer set rather than filtering the query. The single-table door's tests
/// cover the offset. This pins the shared path reaching the membership arm too.
const GRACE_SHARE: &str = "
CREATE TABLE public.papers (id INT PRIMARY KEY, owner TEXT);
CREATE TABLE public.paper_shares (
    paper_id INT,
    viewer TEXT,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (paper_id, viewer)
);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (
    EXISTS (
        SELECT 1
        FROM paper_shares s
        WHERE s.paper_id = papers.id
          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
          AND s.expires_at > now() - interval '30 days'
    )
);
";

#[test]
fn a_membership_grace_window_rides_the_clock_as_a_duration() {
    let (db, registry) = parsed_with_session_attributes(GRACE_SHARE, EXPIRING_SHARE_ATTRIBUTES);
    let outputs = translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        dsl.lines().any(|line| line
            .contains("viewer in app_subjects && expires_at > request_time - duration(\"720h\")")),
        "the membership condition joins the viewer set and grace offset with &&, not ||:\n{dsl}"
    );

    let queries = outputs.tuple_queries();
    let query = queries
        .iter()
        .find(|query| query.condition.is_some() && query.sql.contains("paper_shares_share:"))
        .expect("the share arm renders a conditional query on its own object");
    assert!(
        !query.sql.contains("interval"),
        "the offset left the WHERE for the condition:\n{}",
        query.sql
    );
    assert!(
        query.sql.contains(
            "jsonb_build_object('viewer', \"viewer\"::text, 'expires_at', \"expires_at\")"
        ),
        "the boundary travels in the tuple context:\n{}",
        query.sql
    );
}

/// An EXISTS membership with an expiry: the member tuple names a real user, so the clock
/// rides that tuple as a condition and the member relation admits a conditioned user.
const EXPIRING_EXISTS: &str = "
CREATE TABLE public.docs (id UUID PRIMARY KEY);
CREATE TABLE public.doc_shares (
    doc_id UUID,
    user_id UUID,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (doc_id, user_id)
);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_p ON docs FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM doc_shares s
        WHERE s.doc_id = docs.id AND s.user_id = current_user AND s.expires_at > now()
    )
);
";

#[test]
fn an_expiring_exists_membership_conditions_its_member_tuple() {
    let (db, registry) = parsed(EXPIRING_EXISTS, "{}");
    let planned = translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    );
    let reported = planned.relations();
    let member = reported
        .iter()
        .find(|entry| {
            entry.shapes.iter().any(|shape| {
                matches!(
                    &shape.derivation,
                    RecordDerivation::FromRow { table, .. } if table.name() == "doc_shares"
                )
            })
        })
        .expect("the membership feeds a member relation");
    let RecordDerivation::FromRow {
        table,
        template,
        guards,
    } = &member.shapes[0].derivation
    else {
        panic!(
            "the clock in the condition lets the share row alone decide: {:?}",
            member.shapes[0].derivation
        );
    };
    assert_eq!(table.to_string(), "public.doc_shares");
    assert!(
        matches!(template.subject_key.part(), ValueSource::Column(column) if column == "user_id"),
        "the member tuple still names the user the row supplies: {:?}",
        template.subject_key
    );
    let context = template
        .context
        .as_ref()
        .expect("the clock rides the member tuple as a condition");
    assert!(
        context
            .entries
            .iter()
            .any(|entry| entry.value == ValueSource::column("expires_at")),
        "the boundary travels in the context: {:?}",
        context.entries
    );
    assert!(
        guards
            .iter()
            .any(|guard| matches!(guard, Guard::NotNull(column) if column == "expires_at")),
        "a share with no expiry writes no record: {guards:?}"
    );

    let member_definition = format!("define {}:", member.relation.as_str());
    let outputs = planned.outputs_accepting_gaps();
    let dsl = outputs.model();
    assert!(
        dsl.lines()
            .any(|line| { line.contains(&member_definition) && line.contains("user with ") }),
        "the member relation admits a conditioned user:\n{dsl}"
    );
    let queries = outputs.tuple_queries();
    let query = queries
        .iter()
        .find(|query| query.condition.is_some() && query.sql.contains("doc_shares"))
        .expect("the membership renders a conditional query");
    assert!(
        !query.sql.contains("now()"),
        "the clock left the WHERE for the condition:\n{}",
        query.sql
    );
    assert!(
        query
            .sql
            .contains("jsonb_build_object('expires_at', \"expires_at\")"),
        "the boundary travels in the tuple context:\n{}",
        query.sql
    );
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::CallerSuppliesConditionParameter { parameter, .. }
                if parameter == "request_time"
        )),
        "the request supplies the clock: {:?}",
        outputs.notes()
    );
}

/// Every replay says which stored facts its result fully determines, so a consumer
/// can take out of its store what the result stopped returning. Swept over the
/// corpus so a new joining shape cannot omit it, and pinned on the grants fixture, where
/// the grant table's replay is keyed on the owner the grant names, which is an object of
/// its own and the only thing a grant row is about.
#[test]
fn every_replay_declares_the_slice_its_result_determines() {
    let mut swept = 0usize;
    for (fixture, entry, query) in joined_shape_queries() {
        swept += 1;
        match query.scope() {
            ReplayScope::Object {
                object_type,
                relations,
            } => {
                assert!(
                    !object_type.as_str().is_empty() && !relations.is_empty(),
                    "{fixture}: {}#{} declares an empty object slice",
                    entry.type_name,
                    entry.relation
                );
            }
            ReplayScope::Subject { relation, .. } => {
                assert_eq!(
                    query.key_columns().len(),
                    1,
                    "{fixture}: {}#{} keys a subject slice on several columns",
                    entry.type_name,
                    entry.relation
                );
                assert!(
                    !relation.as_str().is_empty(),
                    "{fixture}: {}#{} declares an empty subject slice",
                    entry.type_name,
                    entry.relation
                );
            }
        }
    }
    assert!(swept > 0, "the corpus produces joining shapes");

    let (classified, db, registry) = support::try_load_fixture_classified("earth_metabolome");
    let planned = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    let reported = planned.translation().relations();
    let joined: Vec<&BoundQuery> = reported
        .iter()
        .flat_map(|entry| &entry.shapes)
        .filter_map(|shape| match &shape.derivation {
            RecordDerivation::Joined { queries, .. } => Some(queries),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        !joined.is_empty(),
        "the grants fixture still answers one shape by querying"
    );
    // Ownership and the row's pointer follow from one row each, so the grant table is the
    // only thing left to replay, and it reads no guarded table at all.
    for query in &joined {
        assert_eq!(
            query.table().to_string(),
            "owner_grants",
            "only the grant table needs a replay here: {query:?}"
        );
        assert_eq!(
            query.key_columns(),
            ["granted_owner_id"],
            "a grant row is about the owner it names: {query:?}"
        );
        assert!(
            !query.sql().contains("\"ownables\""),
            "the grant query stopped fanning out over the rows an owner owns:\n{}",
            query.sql()
        );
        let ReplayScope::Object {
            object_type,
            relations,
        } = query.scope()
        else {
            panic!(
                "the bound owner is the object the facts are about: {:?}",
                query.scope()
            );
        };
        assert_eq!(object_type, "owner_grants_owner");
        assert_eq!(
            relations.len(),
            3,
            "one relation per role level the registry declares: {relations:?}"
        );
    }
}

const RESOLVED_MEMBERSHIP: &str = "
CREATE SCHEMA app;
CREATE TABLE public.docs (id TEXT PRIMARY KEY);
CREATE TABLE app.memberships (doc_id TEXT, user_id TEXT, role TEXT);
CREATE FUNCTION public.auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
SET search_path TO app, public;
ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON public.docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m
        WHERE m.doc_id = docs.id
          AND m.user_id = public.auth_current_user_id()
          AND lower(m.role) = 'editor'));
";

fn resolved_membership_query() -> TupleQuery {
    let (db, registry) = parsed(RESOLVED_MEMBERSHIP, ACCESSOR_REGISTRY);
    support::plan_at(
        classify_policies(&db, &registry),
        &db,
        &registry,
        ConfidenceLevel::B,
    )
    .tuple_queries()
    .iter()
    .find(|query| query.sql.contains("lower("))
    .cloned()
    .expect("the residual membership should emit a query")
}

#[test]
fn unqualified_membership_sql_uses_the_resolved_table() {
    let query = resolved_membership_query();
    assert!(
        query.sql.contains(r#"FROM "app"."memberships""#),
        "{}",
        query.sql
    );
}
#[test]
fn membership_records_carry_the_resolved_table_identity() {
    let description = resolved_membership_query()
        .description
        .expect("the query should be described");
    let [table] = description.tables.as_slice() else {
        panic!("expected one table, got {:?}", description.tables);
    };
    assert_eq!(table.schema(), Some("app"));
    assert_eq!(table.name(), "memberships");
    let RecordDerivation::Joined { queries, .. } = &description.derivation else {
        panic!("expected a joined description");
    };
    let [bound] = queries.as_slice() else {
        panic!("expected one bound query, got {queries:?}");
    };
    assert_eq!(bound.table(), table);
}

/// The named shapes above pin two cases, and a bound query reaches a consumer wherever
/// one is emitted. A field disagreeing with its own SQL is a wrong decode either way: too
/// few columns raises on the read, too many silently drop the condition. The corpus no
/// longer joins conditionally on its own, so a share whose residual only SQL can evaluate
/// joins the sweep.
#[test]
fn every_bound_query_agrees_with_its_own_projection() {
    let (mut conditional, mut plain) = (0usize, 0usize);
    for (fixture, entry, query) in joined_shape_queries() {
        let named = format!("{fixture}: {}#{}", entry.type_name, entry.relation);
        if let Some(condition) = query.condition() {
            conditional += 1;
            assert!(
                query.sql().contains(&format!("'{condition}' AS condition")),
                "{named} names condition '{condition}' for a replay that does \
             not project it:\n{}",
                query.sql()
            );
        } else {
            plain += 1;
            assert!(
                !query.sql().contains(" AS condition"),
                "{named} projects a condition its replay does not name:\n{}",
                query.sql()
            );
        }
    }
    assert!(
        conditional > 0 && plain > 0,
        "the corpus must exercise both projections, saw {conditional} conditional and \
         {plain} plain"
    );
}

/// The two sibling statements of the same fact, over every schema the corpus carries.
///
/// A loader reads a result row the way [`TupleQuery::condition`] says to, and an evaluator
/// decides whether a record carries a request context from the template's own field. Both
/// are minted apart from the SQL they describe, so either can drift into a silent wrong
/// decode: claiming three columns drops the condition and takes a conditional wildcard at
/// face value, and claiming five raises on a query that projects three.
///
/// The replay's own statement is swept by
/// `every_bound_query_agrees_with_its_own_projection`. This covers the other two, so no
/// member of the family rests on the fixtures a database-backed test happens to run.
#[test]
fn every_tuple_query_states_the_shape_of_its_own_rows() {
    let (mut conditional, mut plain) = (0usize, 0usize);
    let (mut carried, mut bare) = (0usize, 0usize);
    let expiring = parsed_with_session_attributes(EXPIRING_SHARE, EXPIRING_SHARE_ATTRIBUTES);
    let mut cases = tuple_contract_cases();
    cases.push(("expiring share".to_string(), expiring.0, expiring.1));
    for (fixture, db, registry) in cases {
        let classified = classify_policies(&db, &registry);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
        for query in outputs.tuple_queries() {
            let named = format!("{fixture}: {}", query.comment.trim());
            if query.skipped.is_some() {
                assert!(
                    query.condition.is_none(),
                    "{named} loads nothing, so it cannot claim a projection"
                );
                continue;
            }
            if let Some(condition) = &query.condition {
                conditional += 1;
                assert!(
                    query.sql.contains(&format!("'{condition}' AS condition")),
                    "{named} names condition '{condition}' for a load that does not project \
                     it:\n{}",
                    query.sql
                );
            } else {
                plain += 1;
                assert!(
                    !query.sql.contains(" AS condition"),
                    "{named} projects a condition its load does not name:\n{}",
                    query.sql
                );
            }

            // The same fact as the record says it, for the shapes one row decides.
            let Some(RecordDerivation::FromRow { template, .. }) =
                query.description.as_ref().map(|found| &found.derivation)
            else {
                continue;
            };
            match (&template.context, &query.condition) {
                (Some(context), Some(condition)) => {
                    carried += 1;
                    assert_eq!(
                        &context.condition, condition,
                        "{named}: the record names condition '{}' and its own query names \
                         '{condition}', so the two grant under different rules",
                        context.condition
                    );
                }
                (None, None) => bare += 1,
                (context, condition) => panic!(
                    "{named}: the record says {context:?} while its own query says \
                     {condition:?}, so one of them is wrong about every row"
                ),
            }
        }
    }
    assert!(
        conditional > 0 && plain > 0,
        "the corpus must exercise both loads, saw {conditional} conditional and {plain} plain"
    );
    assert!(
        carried > 0 && bare > 0,
        "and both records, saw {carried} carrying a context and {bare} bare"
    );
}

/// A value the caller supplies per request is a contract the model itself cannot carry,
/// and getting it wrong is the one place in this feature where a mistake grants rather
/// than denies. Every declared source that reaches the model says so.
#[test]
fn every_request_scoped_gate_states_its_contract_with_the_caller() {
    let mut checked = 0usize;
    for (fixture, expected) in [
        ("connetto_or_policy", vec![("app_subjects", Some(","))]),
        ("connetto_capability", vec![("app_subjects", Some(","))]),
        ("tenant_setting", vec![("app_tenant_id", None)]),
        ("claims_role_gate", vec![("app_roles", Some(","))]),
        (
            "supabase_mfa_restrictive",
            vec![("request_jwt_claims_aal", None)],
        ),
        // A real list carries no delimiter, so the contract states none rather than
        // leaking the delimited string hazard onto a shape that cannot have it.
        ("token_claim_set", vec![("request_jwt_claims_teams", None)]),
        // The wrapper's body does the splitting, so the separator survives the hop.
        ("function_carried_set", vec![("app_teams", Some(","))]),
    ] {
        let (classified, db, registry) = support::try_load_fixture_classified(fixture);
        let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);

        let mut stated: Vec<(String, Option<String>)> = outputs
            .notes()
            .iter()
            .filter_map(|note| match note {
                TranslationNote::CallerSuppliesConditionParameter {
                    parameter,
                    separator,
                    ..
                } => Some((parameter.clone(), separator.clone())),
                _ => None,
            })
            .collect();
        stated.sort();
        stated.dedup();
        let want: Vec<(String, Option<String>)> = expected
            .iter()
            .map(|(p, s)| ((*p).to_string(), s.map(str::to_string)))
            .collect();
        assert_eq!(
            stated, want,
            "{fixture}: the parameters a caller has to send, and how each is split"
        );
        checked += stated.len();

        // The parameter the note names is the one the model declares, or a caller
        // following the note would still have every check refused.
        let json = serde_json::to_string(&outputs.json_model()).expect("the model serializes");
        for (parameter, _) in &stated {
            assert!(
                json.contains(&format!("\"{parameter}\"")),
                "{fixture}: the model declares no parameter named {parameter}"
            );
        }
    }
    assert!(
        checked > 0,
        "no fixture states a contract, so this checks nothing"
    );
}

/// The clock has carried the same contract since it was built and never announced it.
#[test]
fn the_clock_parameter_states_its_contract_too() {
    let sql = "
CREATE TABLE docs (id TEXT PRIMARY KEY, expires_at TIMESTAMPTZ);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_unexpired ON docs FOR SELECT USING (expires_at > now());
";
    let (classified, db, registry) = support::classify_sql(sql, None);
    let outputs = support::plan_at(classified, &db, &registry, ConfidenceLevel::B);
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::CallerSuppliesConditionParameter { parameter, setting_key, .. }
                if parameter == "request_time" && setting_key.is_none()
        )),
        "the clock is a request value like any other: {:?}",
        outputs.notes()
    );
}

/// A relation that grants nobody and one that no single row can decide are different
/// answers, and they arrived byte-identical: `from_one_row` false, no shapes, no decision.
/// A consumer told the second delegates and is answered, a consumer told the first pays a
/// round trip whose answer is always no, and the only local inference available to it
/// (deny whatever has no readable recipe) turns the second into a wrong refusal.
#[test]
fn a_relation_that_grants_nobody_is_not_one_no_row_can_decide() {
    let reads_only = shapes_of(
        "CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE docs (id TEXT PRIMARY KEY, owner_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_id = auth_current_user_id());
",
        ACCESSOR_REGISTRY,
    );
    let refused = entry(&reads_only, "docs", "can_insert");
    assert!(
        refused.grants_nobody,
        "no policy admits an insert, so the model refuses it: {refused:#?}"
    );
    assert!(
        refused.decision.is_none() && refused.shapes.is_empty(),
        "which is why it looked like a relation nothing populates: {refused:#?}"
    );

    let readable = entry(&reads_only, "docs", "can_select");
    assert!(
        !readable.grants_nobody && readable.decision.is_some(),
        "the owner rule grants, and one row decides it: {readable:#?}"
    );

    let membership = shapes_of(HOLDER, ACCESSOR_REGISTRY);
    let undecidable = entry(&membership, "docs", "can_select");
    assert!(
        !undecidable.grants_nobody,
        "a membership grants whoever is in the list: {undecidable:#?}"
    );
    assert!(
        undecidable.decision.is_none(),
        "it just cannot be decided from the guarded row: {undecidable:#?}"
    );
}

/// The denial is the model's own, read through the walk the simplifier prunes with, so the
/// report and the emitted text cannot disagree about which relation refuses.
#[test]
fn every_relation_reported_as_granting_nobody_denies_in_the_emitted_model() {
    for (label, sql, registry) in [
        ("ownership", OWNERSHIP, ACCESSOR_REGISTRY),
        ("holder", HOLDER, ACCESSOR_REGISTRY),
        (
            "grants without principals",
            GRANTS_WITHOUT_PRINCIPALS,
            GRANT_REGISTRY,
        ),
    ] {
        let model = model_at(sql, registry, ConfidenceLevel::B);
        let mut refused = 0usize;
        for shape in shapes_at(sql, registry, ConfidenceLevel::B) {
            let denies = support::footgun::relation_denies(
                &model,
                shape.type_name.as_str(),
                shape.relation.as_str(),
            );
            assert_eq!(
                shape.grants_nobody,
                denies,
                "{label}: {}#{} disagrees with the model:\n{model}",
                shape.type_name.as_str(),
                shape.relation.as_str()
            );
            refused += usize::from(shape.grants_nobody);
        }
        assert!(
            refused > 0,
            "{label}: the corpus has to carry a refusal, or the check above proves nothing"
        );
    }
}

const UNQUALIFIED_MEMBERSHIPS: &str = "
CREATE TABLE docs (id TEXT PRIMARY KEY);
CREATE TABLE memberships (doc_id TEXT, user_id TEXT);
CREATE FUNCTION auth_current_user_id() RETURNS TEXT LANGUAGE sql STABLE
    AS 'SELECT current_setting(''app.current_user_id'')';
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_member ON docs FOR SELECT USING (
    EXISTS (SELECT 1 FROM memberships m
        WHERE m.doc_id = docs.id
          AND m.user_id = auth_current_user_id()));
";

#[test]
fn unqualified_table_declaration_does_not_produce_search_path_dependent_sql() {
    let (db, registry) = parsed(UNQUALIFIED_MEMBERSHIPS, ACCESSOR_REGISTRY);
    let outputs = support::plan_at(
        classify_policies(&db, &registry),
        &db,
        &registry,
        ConfidenceLevel::B,
    );
    for query in outputs.tuple_queries() {
        assert!(
            !query.sql.contains(r#"FROM "memberships""#),
            "unqualified tuple source: {}",
            query.sql
        );
    }
}

/// A membership qualified by a whole-table aggregate over open relations.
const CROSS_ROW_RESIDUAL: &str = "
CREATE TABLE users (id TEXT PRIMARY KEY);
CREATE TABLE papers (id TEXT PRIMARY KEY);
CREATE TABLE paper_shares (paper_id TEXT REFERENCES papers(id), viewer TEXT, weight INT);
CREATE TABLE tiers (cutoff INT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (EXISTS (
  SELECT 1 FROM paper_shares s
  WHERE s.paper_id = papers.id
    AND s.viewer = current_user
    AND s.weight > (SELECT max(cutoff) FROM tiers)));
";

/// A consumer refuses a table its change stream does not carry, so every table the
/// query reads has to be named.
#[test]
fn a_cross_row_residual_names_every_relation_it_reads() {
    let shapes = shapes_of(CROSS_ROW_RESIDUAL, "{}");
    let member = shapes
        .iter()
        .find(|entry| entry.type_name.as_str() == "papers" && !entry.shapes.is_empty())
        .expect("the membership is reported on papers");
    let tables: BTreeSet<String> = member
        .shapes
        .iter()
        .flat_map(|shape| shape.tables.iter())
        .map(ToString::to_string)
        .collect();
    assert!(
        tables.contains("paper_shares") && tables.contains("tiers"),
        "the aggregate's relation belongs in the table list, got {tables:?}"
    );
}

/// A global aggregate moves records for papers whose own shares never changed, so no
/// key narrows the replay.
#[test]
fn a_cross_row_residual_refuses_a_keyed_replay() {
    let shapes = shapes_of(CROSS_ROW_RESIDUAL, "{}");
    let member = shapes
        .iter()
        .find(|entry| entry.type_name.as_str() == "papers" && !entry.shapes.is_empty())
        .expect("the membership is reported on papers");
    let shape = member
        .shapes
        .first()
        .expect("the membership reports one shape");
    match &shape.derivation {
        RecordDerivation::WholeShape { scope, query, .. } => {
            assert!(
                query.contains("max(cutoff)"),
                "the unnarrowed query is the whole filter, got: {query}"
            );
            assert_eq!(
                scope,
                &ReplayScope::Object {
                    object_type: TypeName::canonicalized("papers"),
                    relations: vec![member.relation.clone()],
                },
                "the result is the whole truth for the membership facts on papers"
            );
        }
        other => panic!("a whole-table aggregate cannot be replayed per row, got {other:?}"),
    }
}

/// The disclosure names the relations the proof rests on, or nothing can be watched.
#[test]
fn a_cross_row_residual_discloses_the_relations_its_proof_rests_on() {
    let (db, registry) = parsed(CROSS_ROW_RESIDUAL, "{}");
    let notes = translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .notes()
    .to_vec();
    let disclosure = notes
        .iter()
        .find_map(|note| match note {
            TranslationNote::MembershipResidualReadsUnrestrictedTables { tables, .. } => {
                Some(tables.clone())
            }
            _ => None,
        })
        .expect("the exemption is disclosed");
    let named: BTreeSet<String> = disclosure.iter().map(ToString::to_string).collect();
    assert!(
        named.contains("tiers"),
        "the relation the proof rests on is named, got {named:?}"
    );
    assert!(
        notes
            .iter()
            .all(|note| !matches!(note, TranslationNote::MembershipExtraPredicate { .. })),
        "one residual is disclosed once, by the note that names its proof"
    );
}

/// The same residual reached through the caller's declared set.
const CALLER_SET_CROSS_ROW: &str = "
CREATE TABLE papers (id INT PRIMARY KEY);
CREATE TABLE paper_shares (
  paper_id INT REFERENCES papers(id),
  viewer TEXT,
  weight INT,
  PRIMARY KEY (paper_id, viewer)
);
CREATE TABLE tiers (cutoff INT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (EXISTS (
  SELECT 1 FROM paper_shares s
  WHERE s.paper_id = papers.id
    AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
    AND s.weight > (SELECT max(cutoff) FROM tiers)));
";

#[test]
fn a_caller_set_membership_discloses_the_relations_its_proof_rests_on() {
    let (db, registry) = parsed_with_session_attributes(
        CALLER_SET_CROSS_ROW,
        r#"[{ "key": "app.subjects", "kind": "set_attribute" }]"#,
    );
    let notes = translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .outputs_accepting_gaps()
    .notes()
    .to_vec();
    let disclosure = notes
        .iter()
        .find_map(|note| match note {
            TranslationNote::MembershipResidualReadsUnrestrictedTables { tables, .. } => {
                Some(tables.clone())
            }
            _ => None,
        })
        .expect("the exemption is disclosed on the caller-set route too");
    let named: BTreeSet<String> = disclosure.iter().map(ToString::to_string).collect();
    assert!(
        named.contains("tiers"),
        "the relation the proof rests on is named, got {named:?}"
    );
}

/// A temporal conjunct beside a cross-row one still yields the unnarrowed derivation, since
/// no clock gate forms while a conjunct neither the row nor the request decides remains.
const MIXED_CROSS_ROW: &str = "
CREATE TABLE papers (id INT PRIMARY KEY);
CREATE TABLE paper_shares (
  paper_id INT REFERENCES papers(id),
  viewer TEXT,
  weight INT,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (paper_id, viewer)
);
CREATE TABLE tiers (cutoff INT);
ALTER TABLE papers ENABLE ROW LEVEL SECURITY;
CREATE POLICY papers_p ON papers FOR SELECT USING (EXISTS (
  SELECT 1 FROM paper_shares s
  WHERE s.paper_id = papers.id
    AND s.viewer = current_user
    AND s.expires_at > now()
    AND s.weight > (SELECT max(cutoff) FROM tiers)));
";

#[test]
fn a_temporal_conjunct_beside_a_cross_row_one_keeps_the_unnarrowed_derivation() {
    let shapes = shapes_of(MIXED_CROSS_ROW, "{}");
    let member = shapes
        .iter()
        .find(|entry| entry.type_name.as_str() == "papers" && !entry.shapes.is_empty())
        .expect("the membership is reported on papers");
    for shape in &member.shapes {
        assert!(
            matches!(shape.derivation, RecordDerivation::WholeShape { .. }),
            "a cross-row conjunct forbids a row-derived record, got {:?}",
            shape.derivation
        );
        assert!(
            shape.tables.iter().any(|table| table.name() == "tiers"),
            "the relation the residual reads is named, got {:?}",
            shape.tables
        );
    }
    assert!(!member.shapes.is_empty(), "the membership reports a shape");
}

/// A table open to everybody, capped by a request-only gate on the caller's declared list.
const OPEN_UNDER_GATE: &str = "
CREATE TABLE orders (id INT PRIMARY KEY, quantity BIGINT NOT NULL);
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_open ON orders FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY orders_cap_read ON orders AS RESTRICTIVE FOR SELECT USING (
  'orders:read' = ANY(string_to_array(current_setting('app.bot_list', true), ','))
  OR '*' = ANY(string_to_array(current_setting('app.bot_list', true), ',')));
";

const BOT_LIST_ATTRIBUTES: &str = r#"[{ "key": "app.bot_list", "kind": "set_attribute" }]"#;

fn shapes_with_attributes(sql: &str, attributes_json: &str) -> Vec<RelationShapes> {
    let (db, registry) = parsed_with_session_attributes(sql, attributes_json);
    translation(
        &db,
        &registry,
        ConfidenceLevel::B,
        &GeneratorSettings::default(),
    )
    .relations()
    .to_vec()
}

/// `USING (true)` grants every user whatever the row holds, and the gate is settled by the
/// request, so the pair needs no stored fact and the recipe says so.
#[test]
fn an_open_table_under_a_request_gate_is_decided_without_a_round_trip() {
    let shapes = shapes_with_attributes(OPEN_UNDER_GATE, BOT_LIST_ATTRIBUTES);
    let open = entry(&shapes, "orders", "public_viewer");
    let everyone = RowDecision::Everyone {
        relation: open.relation.clone(),
        shapes: open.shapes.clone(),
    };
    assert!(open.from_one_row, "the open arm reads nothing but the row");
    assert_eq!(open.decision.as_ref(), Some(&everyone));

    let holds = |value: &str| {
        RequestPredicate::Holds(RequestAtom {
            request_parameter: "app_bot_list".to_string(),
            comparison: RequestComparison::CallerSetHolds,
            value: value.to_string(),
        })
    };
    let link = entry(&shapes, "orders", "request_gate");
    assert_eq!(
        entry(&shapes, "orders", "can_select").decision,
        Some(RowDecision::All(vec![
            everyone,
            RowDecision::Request {
                relation: link.relation.clone(),
                shapes: link.shapes.clone(),
                subject_type: TypeName::canonicalized(USER_TYPE),
                predicate: RequestPredicate::Any(vec![holds("*"), holds("orders:read")]),
            },
        ])),
        "the read is the open arm intersected with the gate the request decides"
    );
}

/// A public flag grants every user exactly on the rows whose flag holds, which the shape's
/// guard says, so the row decides it.
#[test]
fn a_public_flag_is_decided_from_its_own_row() {
    let shapes = shapes_of(
        "
CREATE TABLE docs (id TEXT PRIMARY KEY, is_public BOOLEAN NOT NULL);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY docs_public ON docs FOR SELECT USING (is_public = true);
",
        "{}",
    );
    let flag = shapes
        .iter()
        .find(|reported| {
            reported.type_name.as_str() == "docs"
                && reported.shapes.iter().any(|shape| {
                    matches!(
                        &shape.derivation,
                        RecordDerivation::FromRow { guards, .. }
                            if matches!(guards.as_slice(), [Guard::IsTrue(_)])
                    )
                })
        })
        .expect("the flag fills a relation");
    assert_eq!(
        flag.decision,
        Some(RowDecision::Everyone {
            relation: flag.relation.clone(),
            shapes: flag.shapes.clone(),
        })
    );
    assert!(
        entry(&shapes, "docs", "can_select").from_one_row,
        "the read is the flag alone"
    );
}
