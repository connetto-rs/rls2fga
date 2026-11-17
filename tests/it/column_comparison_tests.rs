//! Two columns of the checked row compared with each other, which the row alone decides as it
//! decides a column compared with a literal.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::PatternClass;
use rls2fga::translator::{Outputs, Translator, TranslatorBuilder};
use rls2fga::types::{records_from_row, ConfidenceLevel, RecordDerivation};
use serde_json::json;
use sqlparser::ast::DataType;

use crate::support::deployment::{deployment, typed_caller};
use crate::support::footgun::{db_of, relation_definition, translator};
use crate::support::JsonRowValues;

/// Grants on resources whose root is the organization, as connetto's core schema writes
/// them. An organization's founder grants a role on the organization itself, which is the
/// grant whose resource is its own organization.
const GRANTS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO app_user, authz_owner;
GRANT USAGE ON SCHEMA public TO authz_owner;
CREATE TABLE organizations (id UUID PRIMARY KEY, created_by_id UUID NOT NULL);
CREATE TABLE resources (id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations (id), UNIQUE (organization_id, id));
CREATE TABLE grants (
  resource_id UUID NOT NULL,
  organization_id UUID NOT NULL,
  grantee_id UUID NOT NULL,
  PRIMARY KEY (resource_id, grantee_id),
  FOREIGN KEY (organization_id, resource_id) REFERENCES resources (organization_id, id)
);
GRANT SELECT ON organizations TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = '' AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
CREATE FUNCTION authz.founded_organizations() RETURNS SETOF UUID LANGUAGE sql STABLE
  SECURITY DEFINER SET search_path = '' AS $$
  SELECT organization.id FROM public.organizations organization
  WHERE organization.created_by_id = authz.caller_id() $$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.founded_organizations() OWNER TO authz_owner;
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY grants_on_own_root ON grants FOR SELECT USING (resource_id = organization_id);
CREATE POLICY grants_founder ON grants FOR INSERT
  WITH CHECK (resource_id = organization_id AND grantee_id = (SELECT authz.caller_id())
    AND organization_id = ANY (ARRAY(SELECT authz.founded_organizations())));
CREATE POLICY grants_founder_no_root ON grants FOR UPDATE
  USING (grantee_id = (SELECT authz.caller_id())
    AND organization_id = ANY (ARRAY(SELECT authz.founded_organizations())));
";

/// [`GRANTS`]' deployment, with `confirmed` registered as access attributes of `grants`.
/// `authz.caller_id` reads as the setting it returns, so only the set helper is declared.
fn grants_translator(confirmed: &[&str]) -> Translator {
    let mut registry = FunctionRegistry::new();
    registry.declare_helpers(["authz.founded_organizations"]);
    for column in confirmed {
        registry.register_attribute_column("grants", *column);
    }
    TranslatorBuilder::new(deployment([
        typed_caller("app.user_id", DataType::Uuid).may_be_unset()
    ]))
    .with_registry(registry)
    .build()
}

/// The grade of `policy` in [`GRANTS`], its `USING` clause or else its `WITH CHECK`, beside the
/// pattern it read.
fn grants_clause(confirmed: &[&str], policy: &str) -> (ConfidenceLevel, String) {
    let classified = grants_translator(confirmed).classify(&db_of(GRANTS));
    let policy = classified
        .iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"));
    let clause = policy
        .using_classification()
        .or_else(|| policy.with_check_classification())
        .unwrap_or_else(|| panic!("{} should carry a clause", policy.name()));
    (clause.confidence, format!("{:?}", clause.pattern))
}

/// The comparison alone and the founder clause carrying it translate, and grade A once the
/// deployment confirms both compared columns, as the founder clause without it does.
#[test]
fn the_comparison_grades_as_its_least_confirmed_column() {
    for policy in ["grants_on_own_root", "grants_founder"] {
        for (confirmed, grade) in [
            (&[][..], ConfidenceLevel::B),
            (&["resource_id"][..], ConfidenceLevel::B),
            (&["organization_id"][..], ConfidenceLevel::B),
            (&["resource_id", "organization_id"][..], ConfidenceLevel::A),
        ] {
            let (confidence, pattern) = grants_clause(confirmed, policy);
            assert_eq!(
                confidence, grade,
                "{policy} with {confirmed:?} confirmed: {pattern}"
            );
        }
    }
    assert_eq!(
        grants_clause(&[], "grants_founder_no_root").0,
        ConfidenceLevel::A
    );
}

/// The outputs for one `items` policy, refusing any clause below `B` as a deployment does.
fn outputs_for(columns: &str, policy: &str) -> Outputs {
    let schema = format!(
        "CREATE TABLE public.items(id UUID PRIMARY KEY, owner_id TEXT, {columns});\n\
         ALTER TABLE items ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY items_p ON items {policy};\n"
    );
    translator(ConfidenceLevel::B)
        .translate(&db_of(&schema))
        .expect("translation should plan")
        .outputs()
        .unwrap_or_else(|divergent| panic!("`{policy}` must translate in full: {divergent:?}"))
}

const NUMBERED: &str = "low INTEGER, high BIGINT, label TEXT, other_label TEXT, root_id UUID, \
     parent_id UUID, active BOOLEAN, archived BOOLEAN, starts_on DATE, ends_on DATE";

/// The gate relation `clause` grants `SELECT` through on `items` with [`NUMBERED`] columns.
fn gate_for(clause: &str) -> String {
    let can_select = relation_definition(
        &outputs_for(NUMBERED, &format!("FOR SELECT USING ({clause})")).model(),
        "items",
        "can_select",
    )
    .expect("items defines can_select");
    assert!(
        can_select.starts_with("public_where_"),
        "`{clause}` must grant through a gate, got `{can_select}`"
    );
    can_select
}

/// Every operator loads its gate from the rows the comparison admits, the columns named in
/// one order whichever side the policy wrote each on.
#[test]
fn each_operator_qualifies_rows_in_sql() {
    for (clause, sql) in [
        ("low = high", "AND \"high\" = \"low\";"),
        ("low <> high", "AND \"high\" <> \"low\";"),
        ("low != high", "AND \"high\" <> \"low\";"),
        ("low < high", "AND \"high\" > \"low\";"),
        ("low <= high", "AND \"high\" >= \"low\";"),
        ("low > high", "AND \"high\" < \"low\";"),
        ("low >= high", "AND \"high\" <= \"low\";"),
        ("high >= low", "AND \"high\" >= \"low\";"),
        ("items.high = (low)", "AND \"high\" = \"low\";"),
    ] {
        let outputs = outputs_for(NUMBERED, &format!("FOR SELECT USING ({clause})"));
        assert!(
            outputs
                .tuple_queries()
                .iter()
                .any(|query| query.sql.contains(sql)),
            "`{clause}` loads its gate from the rows it admits: {:#?}",
            outputs.tuple_queries()
        );
    }
}

/// One comparison mints one gate in either spelling, and each other comparison its own.
#[test]
fn each_comparison_is_a_gate_of_its_own() {
    let equal = gate_for("low = high");
    assert_eq!(equal, gate_for("high = low"));
    assert_eq!(gate_for("low < high"), gate_for("high > low"));
    for other in [
        "low <> high",
        "low < high",
        "low <= high",
        "label = other_label",
    ] {
        assert_ne!(equal, gate_for(other), "`{other}`");
    }
    assert_ne!(gate_for("low = 1"), gate_for("low = high"));
}

/// The comparison beside ownership, either way round, and either arm of an `OR` with it.
#[test]
fn the_comparison_composes_with_and_and_or() {
    for (clause, joiner) in [
        (
            "owner_id = current_setting('app.user_id', true) AND low = high",
            " and ",
        ),
        (
            "low = high AND owner_id = current_setting('app.user_id', true)",
            " and ",
        ),
        (
            "owner_id = current_setting('app.user_id', true) OR low < high",
            " or ",
        ),
    ] {
        let granted = relation_definition(
            &outputs_for(NUMBERED, &format!("FOR SELECT USING ({clause})")).model(),
            "items",
            "can_select",
        )
        .expect("items defines can_select");
        assert!(
            granted.contains("owner")
                && granted.contains("public_where_high_")
                && granted.contains(joiner),
            "`{clause}` reaches the model whole, got `{granted}`"
        );
    }
}

const ITEM_ID: &str = "11111111-1111-1111-1111-111111111111";

/// The records the gate `clause` grants through holds for `row`, or `None` where its
/// description needs SQL rather than the row alone.
fn gate_records(clause: &str, row: &serde_json::Value) -> Option<usize> {
    let outputs = outputs_for(NUMBERED, &format!("FOR SELECT USING ({clause})"));
    let description = outputs
        .tuple_queries()
        .iter()
        .find(|query| query.comment.starts_with("-- Attribute gate"))
        .and_then(|query| query.description.as_ref())
        .expect("the gate query describes its records");
    if !matches!(description.derivation, RecordDerivation::FromRow { .. }) {
        return None;
    }
    let records =
        records_from_row(description, &JsonRowValues(row)).expect("the row decides its records");
    Some(records.len())
}

/// The gate's record holds for a row whose columns compare as stated, and for no row where
/// either is NULL, as `PostgreSQL` reads a comparison with NULL.
#[test]
fn the_gate_record_follows_three_valued_logic() {
    for (clause, low, high, expected) in [
        ("low = high", json!(3), json!(3), 1),
        ("low = high", json!(3), json!(4), 0),
        ("low <> high", json!(3), json!(4), 1),
        ("low <> high", json!(3), json!(3), 0),
        ("low < high", json!(3), json!(10), 1),
        ("low < high", json!(10), json!(3), 0),
        ("low <= high", json!(3), json!(3), 1),
        ("low > high", json!(10), json!(3), 1),
        ("low >= high", json!(3), json!(4), 0),
        ("low = high", json!(null), json!(3), 0),
        ("low <> high", json!(3), json!(null), 0),
        ("low <> high", json!(null), json!(null), 0),
    ] {
        let row = json!({ "id": ITEM_ID, "low": low, "high": high });
        assert_eq!(
            gate_records(clause, &row),
            Some(expected),
            "`{clause}` on {low} and {high}"
        );
    }
}

/// Two text columns are equal byte for byte under the default collation, and two `uuid` or
/// `boolean` columns by value, which the row decides, while the order of text and of dates
/// follows rules only the database applies.
#[test]
fn columns_of_one_type_decide_what_the_row_can() {
    let root = "22222222-2222-2222-2222-22222222222a";
    for (clause, mut row, expected) in [
        (
            "label = other_label",
            json!({ "label": "a", "other_label": "a" }),
            Some(1),
        ),
        (
            "label = other_label",
            json!({ "label": "a", "other_label": "a " }),
            Some(0),
        ),
        (
            "label <> other_label",
            json!({ "label": "a", "other_label": "A" }),
            Some(1),
        ),
        (
            "label < other_label",
            json!({ "label": "a", "other_label": "b" }),
            None,
        ),
        (
            "root_id = parent_id",
            json!({ "root_id": root, "parent_id": root }),
            Some(1),
        ),
        (
            "root_id = parent_id",
            json!({ "root_id": root, "parent_id": root.to_uppercase() }),
            Some(1),
        ),
        (
            "root_id <> parent_id",
            json!({ "root_id": root, "parent_id": ITEM_ID }),
            Some(1),
        ),
        (
            "active = archived",
            json!({ "active": true, "archived": true }),
            Some(1),
        ),
        (
            "active < archived",
            json!({ "active": true, "archived": false }),
            Some(0),
        ),
        (
            "starts_on < ends_on",
            json!({ "starts_on": "2026-01-01", "ends_on": "2026-02-01" }),
            None,
        ),
    ] {
        row["id"] = json!(ITEM_ID);
        assert_eq!(gate_records(clause, &row), expected, "`{clause}` on {row}");
    }
}

/// The refusal `clause` earns on `items` with `columns`.
fn refusal(columns: &str, clause: &str) -> String {
    let schema = format!(
        "CREATE TABLE public.items(id UUID PRIMARY KEY, {columns});\n\
         ALTER TABLE items ENABLE ROW LEVEL SECURITY;\n\
         CREATE POLICY items_p ON items FOR SELECT USING ({clause});\n"
    );
    let classified = translator(ConfidenceLevel::B).classify(&db_of(&schema));
    let using = classified[0]
        .using_classification()
        .expect("the policy carries USING");
    let PatternClass::Unknown(unknown) = &using.pattern else {
        panic!(
            "`{clause}` over {columns} must be refused, got {:?}",
            using.pattern
        );
    };
    unknown.reason.clone()
}

/// Columns of two types `PostgreSQL` converts one of to compare are refused, naming both
/// types, and so are text columns under two collations, which `PostgreSQL` cannot choose
/// between, and a column the table does not declare.
#[test]
fn columns_compared_through_a_conversion_are_refused() {
    for (columns, clause, named) in [
        (
            "amount INTEGER, total NUMERIC",
            "amount = total",
            ["INT", "NUMERIC"],
        ),
        (
            "local_at TIMESTAMP, zoned_at TIMESTAMPTZ",
            "local_at < zoned_at",
            ["TIMESTAMP", "TIMESTAMP WITH TIME ZONE"],
        ),
        (
            "left_name TEXT COLLATE \"C\", right_name TEXT COLLATE \"POSIX\"",
            "left_name = right_name",
            ["\"C\"", "\"POSIX\""],
        ),
    ] {
        let reason = refusal(columns, clause);
        for name in named {
            assert!(reason.contains(name), "`{clause}` names {name}: {reason}");
        }
    }
    let reason = refusal("amount INTEGER", "amount = missing");
    assert!(reason.contains("missing"), "{reason}");
}
