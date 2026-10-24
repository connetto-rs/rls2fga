//! Helpers shared by the footgun regression suites.
//!
//! Split out of one 9441-line file so each family runs on its own. A helper only one
//! family uses lives with that family instead.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::generator::tuple_generator::{format_tuples, TupleQuery};
use rls2fga::generator::well_known::{NOBODY_TYPE, USER_TYPE};
use rls2fga::parser::sql_parser::{parse_schema, ParserDB};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::RecordDerivation;
use rls2fga::types::RelationName;
use rls2fga::types::TranslationNote;

pub(crate) fn db_of(sql: &str) -> ParserDB {
    parse_schema(sql).expect("schema should parse")
}

pub(crate) fn translator(min_confidence: ConfidenceLevel) -> Translator {
    TranslatorBuilder::new()
        .with_min_confidence(min_confidence)
        .build()
}

/// A table its owner reads and writes, limited per command by four RESTRICTIVE gates on
/// the caller's declared list `app.bot_list`, each admitting the list's entry for the
/// command (`<table>:read` and so on) or `*`.
pub(crate) fn gated_table(table: &str) -> String {
    let arm = |verb: &str| {
        format!(
            "('{table}:{verb}' = ANY(string_to_array(current_setting('app.bot_list', true), ',')) \
             OR '*' = ANY(string_to_array(current_setting('app.bot_list', true), ',')))"
        )
    };
    format!(
        "CREATE TABLE {table} (id TEXT PRIMARY KEY, owner TEXT NOT NULL);
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
CREATE POLICY {table}_own ON {table} FOR ALL USING (owner = current_setting('app.user_id', true))
  WITH CHECK (owner = current_setting('app.user_id', true));
CREATE POLICY {table}_cap_read ON {table} AS RESTRICTIVE FOR SELECT USING {read};
CREATE POLICY {table}_cap_insert ON {table} AS RESTRICTIVE FOR INSERT WITH CHECK {insert};
CREATE POLICY {table}_cap_update ON {table} AS RESTRICTIVE FOR UPDATE USING {update} WITH CHECK {update};
CREATE POLICY {table}_cap_delete ON {table} AS RESTRICTIVE FOR DELETE USING {delete};
",
        read = arm("read"),
        insert = arm("insert"),
        update = arm("update"),
        delete = arm("delete"),
    )
}

/// [`gated_table`] repeated as `t0` to `t<count - 1>`.
pub(crate) fn gated_tables(count: usize) -> String {
    (0..count)
        .map(|index| gated_table(&format!("t{index}")))
        .collect()
}

/// The `define <name>: <body>` lines inside `type <type_name>`, in declaration order.
pub(crate) fn defines_in_type<'a>(dsl: &'a str, type_name: &str) -> Vec<(&'a str, &'a str)> {
    let mut in_type = false;
    let mut defines = Vec::new();
    for line in dsl.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("type ") {
            in_type = name.trim() == type_name;
            continue;
        }
        if in_type {
            if let Some(rest) = trimmed.strip_prefix("define ") {
                if let Some((name, body)) = rest.split_once(':') {
                    defines.push((name.trim(), body.trim()));
                }
            }
        }
    }
    defines
}

/// Return the right-hand side of `define <relation>:` inside `type <type_name>`.
pub(crate) fn relation_definition(dsl: &str, type_name: &str, relation: &str) -> Option<String> {
    defines_in_type(dsl, type_name)
        .into_iter()
        .find(|(name, _)| *name == relation)
        .map(|(_, body)| body.to_string())
}

/// The `docs#can_select` definition translating `sql` at confidence A produces.
pub(crate) fn docs_read_definition(sql: &str) -> Option<String> {
    let dsl = translator(ConfidenceLevel::A)
        .translate(&db_of(sql))
        .expect("translation should plan")
        .outputs_accepting_gaps()
        .model();
    relation_definition(&dsl, "docs", "can_select")
}

/// Whether a relation of `type_name` grants nobody, resolving the body through the
/// operators the DSL spells: a name stands for its own definition, an intersection denies
/// as soon as one part does, a union only when every part does, and a subtraction follows
/// its base.
pub(crate) fn relation_denies(dsl: &str, type_name: &str, relation: &str) -> bool {
    relation_definition(dsl, type_name, relation)
        .is_some_and(|body| body_denies(dsl, type_name, &body, 0))
}

fn body_denies(dsl: &str, type_name: &str, body: &str, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    if body == "no_access" {
        return true;
    }
    if let Some((base, _)) = body.split_once(" but not ") {
        return body_denies(dsl, type_name, base.trim(), depth + 1);
    }
    if let Some((left, right)) = body.split_once(" and ") {
        return body_denies(dsl, type_name, left.trim(), depth + 1)
            || body_denies(dsl, type_name, right.trim(), depth + 1);
    }
    if let Some((left, right)) = body.split_once(" or ") {
        return body_denies(dsl, type_name, left.trim(), depth + 1)
            && body_denies(dsl, type_name, right.trim(), depth + 1);
    }
    relation_definition(dsl, type_name, body)
        .is_some_and(|inner| inner != body && body_denies(dsl, type_name, &inner, depth + 1))
}

/// Every relation `type_name` defines, paired with its body, in declaration order.
pub(crate) fn relation_definitions(dsl: &str, type_name: &str) -> Vec<(String, String)> {
    defines_in_type(dsl, type_name)
        .into_iter()
        .map(|(name, body)| (name.to_string(), body.to_string()))
        .collect()
}

/// Name of the relation `type_name` declares to reach its database-role scope, if any.
pub(crate) fn pg_role_relation(dsl: &str, type_name: &str) -> Option<String> {
    defines_in_type(dsl, type_name)
        .into_iter()
        .find(|(_, body)| *body == "[pg_role_scope]")
        .map(|(name, _)| name.to_string())
}

/// Whether the scope `scope_relation` reaches admits `role`, in both halves: a row of
/// `object_prefix` points at the scope, and the scope holds that role.
///
/// The roles a scope admits are a fact about the policy, so they are stored on the scope
/// object rather than on every row, and the two facts live in different queries.
pub(crate) fn scope_admits_role(
    tuples: &[TupleQuery],
    object_prefix: &str,
    scope_relation: &str,
    role: &str,
) -> bool {
    let scope_object = format!("'pg_role_scope:{scope_relation}'");
    let points_at_scope = tuples.iter().any(|query| {
        query.sql.contains(&format!("'{object_prefix}'"))
            && query
                .sql
                .contains(&format!("'{scope_relation}' AS relation"))
            && query.sql.contains(&format!("{scope_object} AS subject"))
    });
    let holds_role = tuples.iter().any(|query| {
        query.sql.contains(&format!("{scope_object} AS object"))
            && query.sql.contains(&format!("'pg_role:{role}' AS subject"))
    });
    points_at_scope && holds_role
}

pub(crate) fn type_names(dsl: &str) -> Vec<String> {
    dsl.lines()
        .filter_map(|line| line.trim().strip_prefix("type "))
        .map(|name| name.trim().to_string())
        .collect()
}

pub(crate) fn tuples_reading_from(tuples: &[TupleQuery], from_clause: &str) -> Vec<String> {
    tuples
        .iter()
        .filter(|q| q.sql.contains(from_clause))
        .map(|q| q.sql.clone())
        .collect()
}

/// Runs every structural check over a generated model.
pub(crate) fn assert_model_is_internally_consistent(
    json: &rls2fga::generator::json_model::AuthorizationModel,
) {
    let declared: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> = json
        .type_definitions
        .iter()
        .map(|definition| {
            let relations = definition
                .relations
                .iter()
                .flat_map(|relations| relations.keys())
                .map(RelationName::as_str)
                .collect();
            (definition.type_name.as_str(), relations)
        })
        .collect();

    let mut names = std::collections::BTreeSet::new();
    for definition in &json.type_definitions {
        assert!(
            names.insert(definition.type_name.as_str()),
            "the model declares '{}' twice, which OpenFGA refuses as a duplicate type",
            definition.type_name
        );
    }

    for definition in &json.type_definitions {
        for (relation, userset) in definition.relations.iter().flatten() {
            assert!(
                !matches!(relation.as_str(), "self" | "this"),
                "{}#{relation} is a relation name OpenFGA reserves",
                definition.type_name
            );
            check_userset_references(
                &declared,
                &json.type_definitions,
                definition.type_name.as_str(),
                relation.as_str(),
                userset,
            );
        }
        for (relation, metadata) in definition
            .metadata
            .iter()
            .flat_map(|metadata| &metadata.relations)
        {
            for reference in &metadata.directly_related_user_types {
                assert!(
                    declared.contains_key(reference.type_name.as_str()),
                    "{}#{relation} admits '{}', which the model does not define",
                    definition.type_name,
                    reference.type_name
                );
            }
        }
    }
}

/// The userset a type declares for one relation.
pub(crate) fn declared_userset<'model>(
    declared_types: &'model [rls2fga::generator::json_model::TypeDefinition],
    type_name: &str,
    relation: &str,
) -> Option<&'model rls2fga::generator::json_model::Userset> {
    declared_types
        .iter()
        .find(|definition| definition.type_name.as_str() == type_name)?
        .relations
        .as_ref()?
        .get(relation)
}

/// Types a tupleset relation can reach, from its declared subject types.
pub(crate) fn targets_of(
    declared_types: &[rls2fga::generator::json_model::TypeDefinition],
    type_name: &str,
    tupleset: &str,
) -> Vec<String> {
    declared_types
        .iter()
        .filter(|definition| definition.type_name.as_str() == type_name)
        .flat_map(|definition| definition.metadata.iter())
        .filter_map(|metadata| metadata.relations.get(tupleset))
        .flat_map(|relation| &relation.directly_related_user_types)
        .map(|reference| reference.type_name.to_string())
        .collect()
}

pub(crate) fn check_userset_references(
    declared: &std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>>,
    declared_types: &[rls2fga::generator::json_model::TypeDefinition],
    type_name: &str,
    relation: &str,
    userset: &rls2fga::generator::json_model::Userset,
) {
    use rls2fga::generator::json_model::Userset;
    let own = declared.get(type_name);
    match userset {
        Userset::This { .. } => {}
        Userset::ComputedUserset { computed_userset } => {
            assert!(
                own.is_some_and(|rels| rels.contains(computed_userset.relation.as_str())),
                "{type_name}#{relation} computes '{}', which {type_name} does not define",
                computed_userset.relation
            );
        }
        Userset::TupleToUserset { tuple_to_userset } => {
            let tupleset = tuple_to_userset.tupleset.relation.as_str();
            assert!(
                own.is_some_and(|rels| rels.contains(tupleset)),
                "{type_name}#{relation} walks '{tupleset}', which {type_name} does not define"
            );
            // `OpenFGA` rejects a tupleset that is computed or that admits a
            // wildcard, so an indirection has to start from a concrete assignment.
            assert!(
                matches!(
                    declared_userset(declared_types, type_name, tupleset),
                    Some(Userset::This { .. })
                ),
                "{type_name}#{relation} walks '{tupleset}', which must be directly assignable"
            );
            for reference in declared_types
                .iter()
                .filter(|definition| definition.type_name.as_str() == type_name)
                .flat_map(|definition| definition.metadata.iter())
                .filter_map(|metadata| metadata.relations.get(tupleset))
                .flat_map(|tupleset| &tupleset.directly_related_user_types)
            {
                assert!(
                    reference.wildcard.is_none(),
                    "{type_name}#{relation} walks '{tupleset}', which admits '{}:*'",
                    reference.type_name
                );
            }
            // `OpenFGA` yields nothing for an admitted type that lacks the relation.
            let computed = tuple_to_userset.computed_userset.relation.as_str();
            let targets = targets_of(declared_types, type_name, tupleset);
            assert!(
                targets.is_empty()
                    || targets.iter().any(|target| {
                        declared
                            .get(target.as_str())
                            .is_some_and(|rels| rels.contains(computed))
                    }),
                "{type_name}#{relation} walks '{tupleset}' and reads '{computed}', which none \
                 of {targets:?} defines"
            );
        }
        Userset::Union { union } => {
            for child in &union.child {
                check_userset_references(declared, declared_types, type_name, relation, child);
            }
        }
        Userset::Intersection { intersection } => {
            for child in &intersection.child {
                check_userset_references(declared, declared_types, type_name, relation, child);
            }
        }
        Userset::Difference { difference } => {
            for side in [&difference.base, &difference.subtract] {
                check_userset_references(declared, declared_types, type_name, relation, side);
            }
        }
    }
}

pub(crate) const MEMBERSHIP_SCHEMA: &str = "
CREATE TABLE docs(id UUID PRIMARY KEY, owner_id UUID);
CREATE TABLE doc_members(doc_id UUID REFERENCES docs(id), user_id TEXT, role TEXT);
ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
";

/// Model and tuples for a single `SELECT` policy over `MEMBERSHIP_SCHEMA`.
pub(crate) fn membership_translation(clause: &str) -> (String, String) {
    let db = db_of(&format!(
        "{MEMBERSHIP_SCHEMA}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
    ));
    let translator = translator(ConfidenceLevel::B);
    (
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model(),
        format_tuples(
            translator
                .translate(&db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries(),
        ),
    )
}

/// Whatever is wrong with the refusal of `clause`, across the classification, the model,
/// and the membership tuples alike. Empty when every output refuses it.
///
/// Collected rather than asserted so one test reports every spelling of a clause instead
/// of stopping at the first, which is how a guard wired into one extractor and not the
/// other stays hidden.
pub(crate) fn shaped_membership_subquery_complaints(clause: &str, shaping: &str) -> Vec<String> {
    let db = db_of(&format!(
        "{MEMBERSHIP_SCHEMA}CREATE POLICY docs_members ON docs FOR SELECT USING ({clause});"
    ));
    let translator = translator(ConfidenceLevel::B);
    let mut complaints = Vec::new();

    let classified = translator.classify(&db);
    let [policy] = classified.as_slice() else {
        panic!("expected one classified policy for `{clause}`");
    };
    let pattern = &policy
        .using_classification()
        .expect("USING should classify")
        .pattern;
    match pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) if reason.contains(shaping) => {}
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => {
            complaints.push(format!(
                "`{clause}` refuses without naming {shaping}: {reason}"
            ));
        }
        classified => {
            complaints.push(format!(
                "`{clause}` shapes its rows, yet classified {classified:?}"
            ));
        }
    }

    let outputs = translator
        .translate(&db)
        .expect("translation should plan")
        .outputs_accepting_gaps();
    let dsl = outputs.model();
    let can_select = relation_definition(&dsl, "docs", "can_select");
    if can_select.as_deref() != Some("no_access") {
        complaints.push(format!(
            "`{clause}` must fall closed, can_select is {can_select:?}"
        ));
    }
    let membership_tuples = tuples_reading_from(outputs.tuple_queries(), "doc_members");
    if !membership_tuples.is_empty() {
        complaints.push(format!(
            "`{clause}` must emit no membership tuples, got {membership_tuples:?}"
        ));
    }
    let denial_disclosed = outputs
        .notes()
        .iter()
        .map(TranslationNote::message)
        .any(|message| message.contains("the model denies what RLS grants"));
    if !denial_disclosed {
        complaints.push(format!(
            "`{clause}` narrows the grant, so a note must say so: {:#?}",
            outputs
                .notes()
                .iter()
                .map(TranslationNote::message)
                .collect::<Vec<_>>()
        ));
    }
    complaints
}

/// Model and tuples for `sql` at the default threshold.
pub(crate) fn translation(sql: &str) -> (String, String) {
    let db = db_of(sql);
    let translator = translator(ConfidenceLevel::B);
    (
        translator
            .translate(&db)
            .expect("translation should plan")
            .outputs_accepting_gaps()
            .model(),
        format_tuples(
            translator
                .translate(&db)
                .expect("translation should plan")
                .outputs_accepting_gaps()
                .tuple_queries(),
        ),
    )
}

/// Relations an exclusion subtracts, on the object's own type.
///
/// A `TupleToUserset` contributes its tupleset, which is a relation on the object,
/// and not its computed side, which resolves on whatever type the tupleset reaches.
pub(crate) fn subtracted_relations_on_the_object(
    userset: &rls2fga::generator::json_model::Userset,
    out: &mut std::collections::BTreeSet<String>,
) {
    use rls2fga::generator::json_model::Userset;
    match userset {
        Userset::This { .. } => {}
        Userset::ComputedUserset { computed_userset } => {
            out.insert(computed_userset.relation.clone().to_string());
        }
        Userset::TupleToUserset { tuple_to_userset } => {
            out.insert(tuple_to_userset.tupleset.relation.clone().to_string());
        }
        Userset::Union { union } => {
            for child in &union.child {
                subtracted_relations_on_the_object(child, out);
            }
        }
        Userset::Intersection { intersection } => {
            for child in &intersection.child {
                subtracted_relations_on_the_object(child, out);
            }
        }
        Userset::Difference { difference } => {
            subtracted_relations_on_the_object(&difference.base, out);
            subtracted_relations_on_the_object(&difference.subtract, out);
        }
    }
}

/// True when `description` populates `relation` on `type_name`.
pub(crate) fn feeds(
    description: &rls2fga::types::RecordDescription,
    type_name: &str,
    relation: &str,
) -> bool {
    match &description.derivation {
        RecordDerivation::FromRow { template, .. } => {
            template.object_type == type_name && template.relation == relation
        }
        // A joining description names no template, so it cannot be attributed to a
        // relation from here and is reported as not feeding it.
        _ => false,
    }
}

/// Whether the generator declares this type for structure rather than for a table's rows.
///
/// No query populates one and no expression mints one, so every invariant counting types a
/// translation invented has to skip them. `nobody` joined `user` when the denial stopped
/// admitting a person, and three tests spelled the exemption separately until then.
pub(crate) fn is_structural_type(type_name: &str) -> bool {
    type_name == USER_TYPE || type_name == NOBODY_TYPE
}

pub(crate) const TEAMS_SCHEMA: &str = "
CREATE TABLE teams(id UUID PRIMARY KEY, name TEXT);
CREATE TABLE members(id UUID PRIMARY KEY, team_id UUID REFERENCES teams(id), user_id TEXT);
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
";

pub(crate) const CORRELATION_SCHEMA: &str = "
CREATE TABLE customers (id TEXT PRIMARY KEY);
CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id TEXT REFERENCES customers(id), status TEXT);
CREATE TABLE line_items (id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES orders(id), sku TEXT, status TEXT);
";
