//! A declared `TABLE` helper returning a key beside an enum label, read as the keys it pairs
//! with each label.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{BoolOp, ClassifiedExpr, Composite, PatternClass};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;

use crate::support::deployment::{caller, deployment};
use crate::support::footgun::db_of;

/// Grants a caller may share, as connetto's core schema writes them, an admin of a resource
/// sharing every role on it and a writer sharing the roles up to writer on a resource whose
/// writers may share. `grants` deletes the grants whose resource and role the caller may
/// share and reads those on a resource it may share any role on.
pub(crate) const SHARES: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TYPE authz.role AS ENUM ('reader', 'writer', 'admin');
CREATE TABLE resources (id TEXT PRIMARY KEY, writers_can_share BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE grants (
  resource_id TEXT NOT NULL REFERENCES resources (id), principal_id TEXT NOT NULL,
  role authz.role NOT NULL, PRIMARY KEY (resource_id, principal_id));
GRANT SELECT ON resources, grants TO authz_owner;
CREATE FUNCTION authz.resources_with(min_role authz.role) RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT g.resource_id FROM public.grants g
  WHERE g.principal_id = current_setting('app.user_id', true) AND g.role >= min_role
$$;
CREATE FUNCTION authz.sharable_grants() RETURNS TABLE (resource_id TEXT, role authz.role)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT resource.id, allowed.role
  FROM authz.resources_with('admin') resource(id)
  CROSS JOIN unnest(enum_range(NULL::authz.role)) allowed(role)
  UNION
  SELECT resource.id, allowed.role FROM public.resources resource
  CROSS JOIN (VALUES ('reader'::authz.role), ('writer'::authz.role)) allowed(role)
  WHERE resource.writers_can_share AND resource.id IN (SELECT authz.resources_with('writer'))
$$;
ALTER FUNCTION authz.resources_with(authz.role) OWNER TO authz_owner;
ALTER FUNCTION authz.sharable_grants() OWNER TO authz_owner;
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY grants_select ON grants FOR SELECT
  USING (resource_id IN (SELECT share.resource_id FROM authz.sharable_grants() share));
CREATE POLICY grants_delete ON grants FOR DELETE
  USING ((resource_id, role) IN (SELECT share.resource_id, share.role
    FROM authz.sharable_grants() share));
";

/// The helpers [`SHARES`] declares.
pub(crate) const SHARE_HELPERS: &[&str] = &["authz.resources_with", "authz.sharable_grants"];

/// The arm of `authz.sharable_grants` calling `authz.resources_with` beside every label.
const CALLED_ARM: &str = "SELECT resource.id, allowed.role
  FROM authz.resources_with('admin') resource(id)
  CROSS JOIN unnest(enum_range(NULL::authz.role)) allowed(role)
  UNION
  ";

/// The arm of `authz.sharable_grants` keeping the resources whose writers may share and the
/// caller writes, beside two labels.
const CAPPED_ARM: &str = "
  UNION
  SELECT resource.id, allowed.role FROM public.resources resource
  CROSS JOIN (VALUES ('reader'::authz.role), ('writer'::authz.role)) allowed(role)
  WHERE resource.writers_can_share AND resource.id IN (SELECT authz.resources_with('writer'))";

/// [`SHARES`] with `grants.role` confirmed as an access attribute.
fn translator() -> Translator {
    let mut registry = FunctionRegistry::new();
    registry.register_attribute_column("grants", "role");
    registry.declare_helpers(SHARE_HELPERS.iter().copied());
    TranslatorBuilder::new(deployment([caller("app.user_id")]))
        .with_registry(registry)
        .build()
}

/// The `USING` classification of each of `policies` in `schema`.
fn using_of(schema: &str, policies: &[&str]) -> Vec<ClassifiedExpr> {
    let classified = translator().classify(&db_of(schema));
    policies
        .iter()
        .map(|policy| {
            classified
                .iter()
                .find(|classified| classified.name() == *policy)
                .unwrap_or_else(|| panic!("{policy} should classify"))
                .using_classification()
                .unwrap_or_else(|| panic!("{policy} USING should classify"))
                .clone()
        })
        .collect()
}

/// `authz.sharable_grants` with one arm alone, its labels read off a grant's rows, another
/// helper's rows beside every label, or the rows a cap on the arm's own key keeps beside two
/// labels, and with both arms, grades A for the row value and the projection onto the key.
#[test]
fn each_arm_shape_alone_and_composed_grades_a() {
    let labels_alone = SHARES.replace(
        &format!("{CALLED_ARM}SELECT resource.id, allowed.role FROM public.resources resource"),
        "SELECT g.resource_id, allowed.role FROM public.grants g",
    );
    let labels_alone = labels_alone.replace(
        "WHERE resource.writers_can_share AND resource.id IN (SELECT authz.resources_with('writer'))",
        "WHERE g.principal_id = current_setting('app.user_id', true)",
    );
    for (shape, schema) in [
        ("labels read off a grant's rows", labels_alone),
        ("another helper's rows", SHARES.replace(CAPPED_ARM, "")),
        ("an own-key cap", SHARES.replace(CALLED_ARM, "")),
        ("both arms", SHARES.to_string()),
    ] {
        for (policy, using) in ["grants_delete", "grants_select"]
            .into_iter()
            .zip(using_of(&schema, &["grants_delete", "grants_select"]))
        {
            assert_eq!(
                using.confidence,
                ConfidenceLevel::A,
                "{shape}, {policy}: {:?}",
                using.pattern
            );
        }
    }
}

/// The row value reads as one test of the role per label, in the enum's order, beside the
/// keys the helper pairs with that label, and the projection onto the key as the keys of
/// every label.
#[test]
fn the_row_value_is_one_label_test_per_label_and_the_projection_every_label() {
    let [delete, select] =
        <[ClassifiedExpr; 2]>::try_from(using_of(SHARES, &["grants_delete", "grants_select"]))
            .expect("two policies");
    let PatternClass::P8Composite(Composite {
        op: BoolOp::Or,
        parts,
    }) = &delete.pattern
    else {
        panic!("one part per label, got {:?}", delete.pattern);
    };
    let read: Vec<(String, Vec<String>)> = parts
        .iter()
        .map(|part| match &part.pattern {
            PatternClass::P8Composite(Composite {
                op: BoolOp::And,
                parts,
            }) => match parts.as_slice() {
                [ClassifiedExpr {
                    pattern: PatternClass::P9AttributeCondition(tested),
                    ..
                }, ClassifiedExpr {
                    pattern: PatternClass::P20DeclaredHelper(helper),
                    ..
                }] => (tested.value_description.clone(), helper.call.labels.clone()),
                other => panic!("a label test beside the call, got {other:?}"),
            },
            other => panic!("a label test beside the call, got {other:?}"),
        })
        .collect();
    assert_eq!(
        read,
        ["'reader'", "'writer'", "'admin'"]
            .map(|label| (label.to_string(), vec![label.to_string()]))
    );
    let PatternClass::P20DeclaredHelper(projected) = &select.pattern else {
        panic!("the keys of every label, got {:?}", select.pattern);
    };
    assert!(projected.call.labels.is_empty(), "{projected:?}");
}

/// A label the helper never returns at a key reads no row, so `admin` holds only on the
/// resources the caller administers, and a column of labels holds no keys.
#[test]
fn a_label_holds_only_the_keys_its_rows_pair_with_it() {
    let model = translator()
        .translate(&db_of(SHARES))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .model();
    assert!(
        model.contains("define sharable_grants_admin: resources_with_admin"),
        "{model}"
    );
    let keyed_by_label = SHARES.replace(
        "resource_id IN (SELECT share.resource_id FROM authz.sharable_grants() share)",
        "role IN (SELECT share.role FROM authz.sharable_grants() share)",
    );
    let [_, select] = <[ClassifiedExpr; 2]>::try_from(using_of(
        &keyed_by_label,
        &["grants_delete", "grants_select"],
    ))
    .expect("two policies");
    assert_eq!(
        select.confidence,
        ConfidenceLevel::D,
        "{:?}",
        select.pattern
    );
}
