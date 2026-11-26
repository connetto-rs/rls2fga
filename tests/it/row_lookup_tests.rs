//! A column compared with the one row a lookup selects, written inline as a scalar
//! subquery or as a call to a `LANGUAGE sql` function whose body is that lookup, reads as
//! membership in the selected rows once the schema proves the lookup returns at most one.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{
    ClassifiedExpr, ExpandedFunction, ParentInheritance, PatternClass, RequestValueAbsent,
    UnclassifiedExpr,
};
use rls2fga::parser::sql_parser::{Deployment, SessionSetting};
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::{ColumnName, ConfidenceLevel};
use sqlparser::ast::DataType;

use crate::support::deployment::{db, typed_caller, typed_scalar};

const USER_ARM: &str = "(SELECT authz.caller_id()) IS NOT NULL \
    AND (n.user_namespace_id, n.user_id) = \
        ('bc3cf2e2-768c-4af9-bf86-65f23378a212', (SELECT authz.caller_id()))";

const INSTALLATION_ARM: &str = "(SELECT authz.caller_id()) IS NULL \
    AND (n.installation_namespace_id, n.installation_id) = \
        (NULLIF(current_setting('app.installation_namespace_id', true), '')::uuid, \
         NULLIF(current_setting('app.installation_id', true), '')::uuid)";

/// The namespace schema with `lookup` as the body of `authz.caller_namespace()` and
/// `check` as the insert policy on `objects`.
fn schema(lookup: &str, check: &str) -> String {
    format!(
        "
CREATE ROLE app NOLOGIN;
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
CREATE TABLE namespaces (
  id UUID PRIMARY KEY,
  user_namespace_id UUID,
  user_id UUID,
  installation_namespace_id UUID,
  installation_id UUID,
  UNIQUE (user_namespace_id, user_id),
  UNIQUE (installation_namespace_id, installation_id)
);
CREATE TABLE objects (
  namespace_id UUID NOT NULL REFERENCES namespaces (id),
  id UUID NOT NULL,
  PRIMARY KEY (namespace_id, id)
);
GRANT SELECT ON namespaces TO authz_owner;
GRANT USAGE ON SCHEMA authz TO app, authz_owner;
GRANT SELECT, INSERT ON objects TO app;
GRANT SELECT ON namespaces TO app;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.caller_namespace() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  {lookup}
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.caller_namespace() OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY objects_insert ON objects FOR INSERT TO app WITH CHECK ({check});
"
    )
}

fn namespace_lookup(arms: &str) -> String {
    format!("SELECT n.id FROM public.namespaces n WHERE {arms}")
}

fn both_arms() -> String {
    format!("({USER_ARM}) OR ({INSTALLATION_ARM})")
}

fn caller(always_set: bool) -> SessionSetting {
    let setting = typed_caller("app.user_id", DataType::Uuid);
    if always_set {
        setting
    } else {
        setting.may_be_unset()
    }
}

fn settings(caller_always_set: bool) -> Vec<SessionSetting> {
    vec![
        caller(caller_always_set),
        typed_scalar("app.installation_namespace_id", DataType::Uuid).may_be_unset(),
        typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    ]
}

/// The insert check on `objects`, classified for a caller a request may leave unset.
fn classified(sql: &str) -> ClassifiedExpr {
    classified_for(sql, settings(false))
}

fn classified_for(sql: &str, settings: Vec<SessionSetting>) -> ClassifiedExpr {
    let mut registry = FunctionRegistry::new();
    registry.register_attribute_column("namespaces", "user_namespace_id");
    let translator = TranslatorBuilder::new(
        Deployment::new("app", ["app"], settings).expect("a valid deployment"),
    )
    .with_registry(registry)
    .build();
    translator
        .classify(&db(sql))
        .into_iter()
        .find(|policy| policy.table_name() == "objects")
        .and_then(|policy| policy.with_check_classification().cloned())
        .expect("the insert check classifies")
}

fn refusal(classified: &ClassifiedExpr) -> &str {
    match &classified.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn inherits_namespace(pattern: &PatternClass) -> bool {
    matches!(
        pattern,
        PatternClass::P5ParentInheritance(ParentInheritance { parent_table, fk_columns, .. })
            if parent_table.name() == "namespaces"
                && fk_columns.iter().map(ColumnName::as_str).eq(["namespace_id"])
    )
}

/// The lookup selects the caller's namespace where the request carries a caller, and the
/// installation's only where it carries none, each arm pinning one unique key, so the
/// accessor returns the one namespace the insert may name.
#[test]
fn a_lookup_accessor_compared_with_a_column_inherits_from_the_selected_row() {
    for check in [
        "namespace_id = (SELECT authz.caller_namespace())",
        "namespace_id = authz.caller_namespace()",
        "(SELECT authz.caller_namespace()) = namespace_id",
    ] {
        let classified = classified(&schema(&namespace_lookup(&both_arms()), check));
        assert_eq!(
            classified.confidence,
            ConfidenceLevel::A,
            "{check}: {classified:?}"
        );
        match &classified.pattern {
            PatternClass::ExpandedFunction(ExpandedFunction {
                function,
                reads_bypass_rls,
                inner,
                ..
            }) => {
                assert_eq!(function, "caller_namespace");
                assert!(reads_bypass_rls, "the owner bypasses row security");
                assert!(inherits_namespace(&inner.pattern), "{check}: {inner:?}");
            }
            other => panic!("{check}: expected the expanded lookup, got {other:?}"),
        }
    }
}

/// Written inline, the lookup is the set spelling of the same rows, which already
/// translates.
#[test]
fn an_inline_lookup_reads_as_membership_in_the_rows_it_selects() {
    let lookup = namespace_lookup(&both_arms());
    let set = classified(&schema(
        "SELECT NULL::uuid",
        &format!("namespace_id IN ({lookup})"),
    ));
    assert_eq!(set.confidence, ConfidenceLevel::A, "{set:?}");
    assert!(inherits_namespace(&set.pattern), "{set:?}");
    for check in [
        format!("namespace_id = ({lookup})"),
        format!("({lookup}) = namespace_id"),
    ] {
        assert_eq!(
            classified(&schema("SELECT NULL::uuid", &check)),
            set,
            "{check}"
        );
    }
}

/// `IS NULL` on the caller read through `NULLIF` is the request carrying no caller, and
/// `IS NOT NULL` the request carrying one.
#[test]
fn a_caller_absence_test_reads_as_the_request_omitting_the_caller() {
    for (check, negated) in [
        ("(SELECT authz.caller_id()) IS NULL", false),
        (
            "NULLIF(current_setting('app.user_id', true), '') IS NULL",
            false,
        ),
        ("(SELECT authz.caller_id()) IS NOT NULL", true),
    ] {
        let classified = classified(&schema("SELECT NULL::uuid", check));
        assert_eq!(classified.confidence, ConfidenceLevel::A, "{check}");
        match &classified.pattern {
            PatternClass::P28RequestValueAbsent(RequestValueAbsent {
                source,
                negated: read,
            }) => {
                assert_eq!(source.setting_key(), "app.user_id", "{check}");
                assert_eq!(*read, negated, "{check}");
            }
            other => panic!("{check}: expected an absence test, got {other:?}"),
        }
    }
    let always = classified_for(
        &schema("SELECT NULL::uuid", "(SELECT authz.caller_id()) IS NULL"),
        settings(true),
    );
    assert!(
        refusal(&always).contains("declared set by every request"),
        "{always:?}"
    );
}

/// A lookup that can select two rows hands the comparison one of them, the first its body
/// returns or an error where a scalar subquery reads it, while membership grants both.
#[test]
fn a_lookup_that_may_select_several_rows_is_refused() {
    for (arms, named) in [
        (
            "(SELECT authz.caller_id()) IS NOT NULL AND n.user_id = (SELECT authz.caller_id())"
                .to_string(),
            "pins no unique key",
        ),
        (
            format!(
                "({USER_ARM}) OR ((n.installation_namespace_id, n.installation_id) = \
                 (NULLIF(current_setting('app.installation_namespace_id', true), '')::uuid, \
                  NULLIF(current_setting('app.installation_id', true), '')::uuid))"
            ),
            "can both hold",
        ),
    ] {
        let lookup = namespace_lookup(&arms);
        for check in [
            "namespace_id = (SELECT authz.caller_namespace())".to_string(),
            format!("namespace_id = ({lookup})"),
        ] {
            let classified = classified(&schema(&lookup, &check));
            assert_eq!(classified.confidence, ConfidenceLevel::D, "{check}");
            let reason = refusal(&classified);
            assert!(
                reason.contains("more than one row") && reason.contains(named),
                "{check}: {reason}"
            );
        }
    }
}

/// A key held only by a deferrable constraint may hold duplicates until the transaction
/// checks it.
#[test]
fn a_deferrable_unique_key_pins_no_row() {
    let schema = schema(
        "SELECT NULL::uuid",
        "namespace_id = (SELECT n.id FROM public.namespaces n \
         WHERE n.installation_id = (SELECT authz.caller_id()))",
    )
    .replace(
        "  installation_id UUID,\n",
        "  installation_id UUID UNIQUE DEFERRABLE,\n",
    );
    let reason = refusal(&classified(&schema)).to_string();
    assert!(reason.contains("pins no unique key"), "{reason}");
}

/// A unique key holds within one table, and a scan of a table reads its inheritance
/// children too, which may repeat the key.
#[test]
fn a_lookup_over_an_inherited_table_is_refused() {
    let lookup = namespace_lookup(&both_arms());
    let schema = format!(
        "{}\nCREATE TABLE archived_namespaces () INHERITS (namespaces);",
        schema(&lookup, &format!("namespace_id = ({lookup})"))
    );
    let reason = refusal(&classified(&schema)).to_string();
    assert!(reason.contains("inherit"), "{reason}");
}

/// A key set equal to another column of the same row pins nothing, whichever qualified
/// spelling names that column.
#[test]
fn a_key_compared_with_its_own_row_pins_no_row() {
    for filter in [
        "id = user_id",
        "namespaces.id = namespaces.user_id",
        "namespaces.id = public.namespaces.user_id",
        "id = (namespaces).user_id",
    ] {
        let check = format!("namespace_id = (SELECT id FROM public.namespaces WHERE {filter})");
        let reason = refusal(&classified(&schema("SELECT NULL::uuid", &check))).to_string();
        assert!(reason.contains("pins no unique key"), "{filter}: {reason}");
    }
}

/// Column aliases rename what the filter's names read, so `n.id` may be another column.
#[test]
fn a_lookup_renaming_its_columns_is_not_read() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        "namespace_id = (SELECT n.id FROM public.namespaces n (user_namespace_id, id) \
         WHERE n.id = (SELECT authz.caller_id()))",
    ));
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
}

/// A function hands its value over as the type it declares, which may round the key the
/// lookup selects onto another one.
#[test]
fn a_lookup_accessor_returning_another_type_is_refused() {
    let schema = schema(
        &namespace_lookup(&both_arms()),
        "namespace_id = (SELECT authz.caller_namespace())",
    )
    .replace("  id UUID PRIMARY KEY,", "  id NUMERIC PRIMARY KEY,")
    .replace(
        "namespace_id UUID NOT NULL",
        "namespace_id NUMERIC NOT NULL",
    )
    .replace(
        "authz.caller_namespace() RETURNS UUID",
        "authz.caller_namespace() RETURNS INT",
    );
    let reason = refusal(&classified(&schema)).to_string();
    assert!(reason.contains("hands it over as INT"), "{reason}");
}

/// Why the insert check comparing with an accessor whose body is `lookup` is refused.
fn accessor_refusal(lookup: &str) -> String {
    refusal(&classified(&schema(
        lookup,
        "namespace_id = (SELECT authz.caller_namespace())",
    )))
    .to_string()
}

/// A lookup joining a second table, renaming its columns or projecting several of them may
/// select one row per row of something else, or another column than it names, so only one
/// column of one table read under its own names is proven.
#[test]
fn a_lookup_reading_anything_but_one_column_of_one_table_is_not_proven() {
    for lookup in [
        format!("SELECT n.id FROM public.namespaces n, public.objects o WHERE {USER_ARM}"),
        format!(
            "SELECT n.id FROM public.namespaces n JOIN public.objects o ON o.namespace_id = n.id \
             WHERE {USER_ARM}"
        ),
        format!(
            "SELECT n.id FROM public.namespaces n (user_id, id, user_namespace_id) \
             WHERE {USER_ARM}"
        ),
        format!("SELECT n.id, n.user_id FROM public.namespaces n WHERE {USER_ARM}"),
    ] {
        let reason = accessor_refusal(&lookup);
        assert!(
            reason.contains("selects no single column of one table"),
            "{lookup}: {reason}"
        );
    }
}

/// A name bound in `WITH` may shadow the table the lookup seems to read.
#[test]
fn a_lookup_binding_names_in_with_is_refused() {
    let reason = accessor_refusal(&format!(
        "WITH unused AS (SELECT 1) {}",
        namespace_lookup(USER_ARM)
    ));
    assert!(reason.contains("WITH clause"), "{reason}");
}

/// `LIMIT` on the query and `GROUP BY` on its select keep only some of the rows the filter
/// selects, which a membership in them does not read.
#[test]
fn a_lookup_shaping_its_rows_is_refused() {
    for (lookup, clause) in [
        (format!("{} LIMIT 1", namespace_lookup(USER_ARM)), "LIMIT"),
        (
            format!("{} GROUP BY n.id", namespace_lookup(USER_ARM)),
            "GROUP BY",
        ),
    ] {
        let reason = accessor_refusal(&lookup);
        assert!(reason.contains(&format!("through {clause}")), "{reason}");
    }
}

/// A lookup with no filter selects every row of its table.
#[test]
fn a_lookup_without_a_filter_is_refused() {
    let reason = accessor_refusal("SELECT n.id FROM public.namespaces n");
    assert!(reason.contains("pins no unique key"), "{reason}");
}

/// An intersection keeps the rows both selects return, which no membership in either
/// reads, and a body of several statements returns its last one's rows, so neither is
/// read as a lookup.
#[test]
fn an_intersection_or_a_body_of_several_statements_is_no_lookup() {
    for lookup in [
        format!(
            "{} INTERSECT {}",
            namespace_lookup(USER_ARM),
            namespace_lookup(INSTALLATION_ARM)
        ),
        format!("SELECT 1; {}", namespace_lookup(USER_ARM)),
    ] {
        let classified = classified(&schema(
            &lookup,
            "namespace_id = (SELECT authz.caller_namespace())",
        ));
        assert!(!inherits_namespace(&classified.pattern), "{classified:?}");
        assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
    }
}

/// A `STRICT` accessor called with `NULL` returns `NULL` without running its lookup, so
/// the comparison never holds.
#[test]
fn a_strict_lookup_accessor_called_with_null_is_refused() {
    let schema = schema(
        &namespace_lookup(
            "n.user_namespace_id = 'bc3cf2e2-768c-4af9-bf86-65f23378a212' AND n.user_id = owner",
        ),
        "namespace_id = (SELECT authz.caller_namespace(NULL))",
    )
    .replace(
        "authz.caller_namespace() RETURNS UUID\nLANGUAGE sql STABLE",
        "authz.caller_namespace(owner UUID) RETURNS UUID\nLANGUAGE sql STABLE STRICT",
    )
    .replace(
        "ALTER FUNCTION authz.caller_namespace()",
        "ALTER FUNCTION authz.caller_namespace(UUID)",
    );
    let reason = refusal(&classified(&schema)).to_string();
    assert!(
        reason.contains("is STRICT and this call passes NULL"),
        "{reason}"
    );
}

/// A derived table hides which table's key the filter pins, so an inline lookup over one
/// is not read.
#[test]
fn an_inline_lookup_over_a_derived_table_is_not_read() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        &format!(
            "namespace_id = (SELECT n.id FROM (SELECT * FROM public.namespaces) n \
             WHERE {USER_ARM})"
        ),
    ));
    assert!(!inherits_namespace(&classified.pattern), "{classified:?}");
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
}

/// A whole check calling a function reads its body only where that body is one
/// `LANGUAGE sql` expression, and names what keeps any other body unread.
#[test]
fn a_check_calling_a_body_it_cannot_read_names_why() {
    for (declaration, reason) in [
        (
            "CREATE FUNCTION authz.allowed() RETURNS BOOLEAN STABLE AS $$ SELECT true $$;",
            "declares no language",
        ),
        (
            "CREATE FUNCTION authz.allowed() RETURNS BOOLEAN LANGUAGE sql STABLE \
             BEGIN ATOMIC SELECT true; END;",
            "has no readable body",
        ),
    ] {
        let schema = schema("SELECT NULL::uuid", "authz.allowed()").replace(
            "ALTER TABLE objects ENABLE ROW LEVEL SECURITY;",
            &format!("{declaration}\nALTER TABLE objects ENABLE ROW LEVEL SECURITY;"),
        );
        let classified = classified(&schema);
        assert!(refusal(&classified).contains(reason), "{classified:?}");
    }
}
