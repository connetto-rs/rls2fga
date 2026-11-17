//! A declared `TABLE` helper returning a key beside an enum label, read as the keys it pairs
//! with each label.

use rls2fga::classifier::function_registry::FunctionRegistry;
use rls2fga::classifier::patterns::{
    BoolOp, ClassifiedExpr, Composite, PatternClass, UnclassifiedExpr,
};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::ConfidenceLevel;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use crate::support::deployment::{caller, deployment, typed_scalar};
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

/// A translator confirming `grants.role` as an access attribute and declaring `helpers`.
fn translator_declaring(helpers: &[&str]) -> Translator {
    let mut registry = FunctionRegistry::new();
    registry.register_attribute_column("grants", "role");
    registry.declare_helpers(helpers.iter().copied());
    TranslatorBuilder::new(deployment([caller("app.user_id")]))
        .with_registry(registry)
        .build()
}

/// [`translator_declaring`] the helpers [`SHARES`] declares.
fn translator() -> Translator {
    translator_declaring(SHARE_HELPERS)
}

/// The `USING` classification of each of `policies` in `schema`, `helpers` declared.
fn using_declaring(schema: &str, helpers: &[&str], policies: &[&str]) -> Vec<ClassifiedExpr> {
    let classified = translator_declaring(helpers).classify(&db_of(schema));
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

/// The `USING` classification of each of `policies` in `schema`.
fn using_of(schema: &str, policies: &[&str]) -> Vec<ClassifiedExpr> {
    using_declaring(schema, SHARE_HELPERS, policies)
}

/// Why `policy` of `schema`, `helpers` declared, is refused.
fn refusal_of(schema: &str, helpers: &[&str], policy: &str) -> String {
    let [using] = <[ClassifiedExpr; 1]>::try_from(using_declaring(schema, helpers, &[policy]))
        .expect("one policy");
    match using.pattern {
        PatternClass::Unknown(UnclassifiedExpr { reason, .. }) => reason,
        other => panic!("{policy} should be refused, got {other:?}"),
    }
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
/// resources the caller administers, and a column of labels holds no keys, even where a
/// lookup table of roles makes each label a row.
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
    let keyed_by_label = SHARES
        .replace(
            "CREATE TABLE resources",
            "CREATE TABLE roles (role authz.role PRIMARY KEY);\nCREATE TABLE resources",
        )
        .replace(
            "role authz.role NOT NULL, PRIMARY KEY",
            "role authz.role NOT NULL REFERENCES roles (role), PRIMARY KEY",
        )
        .replace(
            "resource_id IN (SELECT share.resource_id FROM authz.sharable_grants() share)",
            "role IN (SELECT share.role FROM authz.sharable_grants() share)",
        );
    let refused = refusal_of(&keyed_by_label, SHARE_HELPERS, "grants_select");
    assert!(
        refused.contains("returns labels in the column read as keys"),
        "{refused}"
    );
}

/// The `USING` clause of `grants_delete` in [`SHARES`].
const DELETE_USING: &str = "(resource_id, role) IN (SELECT share.resource_id, share.role
    FROM authz.sharable_grants() share)";

/// A literal label reads the keys the helper pairs with it alone, and none where no arm
/// returns it, while a key spelled as a literal, a label column of no enum type and a label
/// operand computed from the row are refused.
#[test]
fn label_operands_are_columns_of_an_enum_or_literals() {
    let deleting = |using: &str| SHARES.replace(DELETE_USING, using);
    let literal = deleting(
        "(resource_id, 'reader'::authz.role) IN (SELECT share.resource_id, share.role \
         FROM authz.sharable_grants() share)",
    );
    let [reader] = <[ClassifiedExpr; 1]>::try_from(using_of(&literal, &["grants_delete"]))
        .expect("one policy");
    let PatternClass::P20DeclaredHelper(helper) = &reader.pattern else {
        panic!("the keys at 'reader', got {:?}", reader.pattern);
    };
    assert_eq!(helper.call.labels, ["'reader'"]);
    let report = translator()
        .translate(&db_of(&literal))
        .expect("the schema plans")
        .outputs()
        .expect("the schema translates")
        .report();
    assert!(
        report.contains("P20 (resource_id in authz.sharable_grants() at 'reader')"),
        "{report}"
    );
    let never = deleting(
        "(resource_id, 'admin'::authz.role) IN (SELECT share.resource_id, share.role \
         FROM authz.sharable_grants() share)",
    )
    .replace(CALLED_ARM, "");
    let [admin] =
        <[ClassifiedExpr; 1]>::try_from(using_of(&never, &["grants_delete"])).expect("one policy");
    assert!(
        matches!(admin.pattern, PatternClass::P10ConstantBool(ref constant) if !constant.value),
        "{:?}",
        admin.pattern
    );
    for (using, reason) in [
        (
            "('r1', role) IN (SELECT share.resource_id, share.role \
             FROM authz.sharable_grants() share)",
            "pairs literals with the rows 'authz.sharable_grants' returns beside no column",
        ),
        (
            "(resource_id, principal_id) IN (SELECT share.resource_id, share.role \
             FROM authz.sharable_grants() share)",
            "column 'principal_id' is compared with the labels",
        ),
        (
            "(resource_id, lower(principal_id)::authz.role) IN (SELECT share.resource_id, \
             share.role FROM authz.sharable_grants() share)",
            "which is no literal a pair is named by",
        ),
    ] {
        let refused = refusal_of(&deleting(using), SHARE_HELPERS, "grants_delete");
        assert!(refused.contains(reason), "`{using}`: {refused}");
    }
}

/// A helper returning two columns of keys beside labels names no one key.
#[test]
fn labelled_rows_with_two_columns_of_keys_are_refused() {
    let schema = SHARES.replace(
        "ALTER TABLE grants ENABLE",
        "CREATE FUNCTION authz.grant_triples()
         RETURNS TABLE (resource_id TEXT, principal_id TEXT, role authz.role)
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT g.resource_id, g.principal_id, allowed.role FROM public.grants g
           CROSS JOIN (VALUES ('reader'::authz.role)) allowed(role)
           WHERE g.principal_id = current_setting('app.user_id', true)
         $$;
         ALTER FUNCTION authz.grant_triples() OWNER TO authz_owner;
         CREATE POLICY grants_triples ON grants FOR UPDATE
           USING ((resource_id, principal_id, role) IN (SELECT * FROM authz.grant_triples()));
         ALTER TABLE grants ENABLE",
    );
    let refused = refusal_of(
        &schema,
        &[SHARE_HELPERS, &["authz.grant_triples"]].concat(),
        "grants_triples",
    );
    assert!(
        refused.contains("returns 2 columns no arm returns labels in"),
        "{refused}"
    );
}

/// An arm reading the label off its own row holds at a label on the rows holding it, an arm
/// returning another helper's rows at some labels only holds at those, and a helper reading
/// the label off another's rows reads that helper at the same label.
#[test]
fn labels_read_off_rows_and_called_helpers_follow_the_label() {
    let read_off_row = SHARES.replace(
        CAPPED_ARM,
        "
  UNION
  SELECT g.resource_id, g.role FROM public.grants g
  WHERE g.principal_id = current_setting('app.user_id', true)",
    );
    let admin_only = SHARES.replace(
        "FROM authz.resources_with('admin') resource(id)
  CROSS JOIN unnest(enum_range(NULL::authz.role)) allowed(role)",
        "FROM authz.resources_with('admin') resource(id)
  CROSS JOIN (VALUES ('admin'::authz.role)) allowed(role)",
    );
    let wrapped = SHARES
        .replace(
            "ALTER TABLE grants ENABLE",
            "CREATE FUNCTION authz.shared_again() RETURNS TABLE (resource_id TEXT, role authz.role)
             LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
               SELECT share.resource_id, share.role FROM authz.sharable_grants() share
             $$;
             ALTER FUNCTION authz.shared_again() OWNER TO authz_owner;
             ALTER TABLE grants ENABLE",
        )
        .replace(
            DELETE_USING,
            "(resource_id, role) IN (SELECT again.resource_id, again.role \
             FROM authz.shared_again() again)",
        );
    let wrapping = [SHARE_HELPERS, &["authz.shared_again"]].concat();
    for (shape, schema, helpers, reader_holds) in [
        (
            "label read off the row",
            &read_off_row,
            SHARE_HELPERS,
            "define sharable_grants_reader: resources_with_admin or member_",
        ),
        (
            "called helper at admin only",
            &admin_only,
            SHARE_HELPERS,
            "define sharable_grants_reader: resources_within_resources_with_writer",
        ),
        (
            "helper read at the label",
            &wrapped,
            wrapping.as_slice(),
            "define shared_again_reader: sharable_grants_reader",
        ),
    ] {
        let [delete] =
            <[ClassifiedExpr; 1]>::try_from(using_declaring(schema, helpers, &["grants_delete"]))
                .expect("one policy");
        assert_eq!(
            delete.confidence,
            ConfidenceLevel::A,
            "{shape}: {:?}",
            delete.pattern
        );
        let model = translator_declaring(helpers)
            .translate(&db_of(schema))
            .expect("the schema plans")
            .outputs()
            .expect("the schema translates")
            .model();
        assert!(
            model.contains(reader_holds),
            "{shape}: {reader_holds} in {model}"
        );
    }
}

/// A called or capping helper left undeclared, and a cap pairing a row with labelled rows,
/// are refused naming why.
#[test]
fn undeclared_callees_and_caps_by_labelled_rows_are_refused() {
    let sharable_only = &["authz.sharable_grants"][..];
    for (schema, reason) in [
        (
            SHARES.replace(CAPPED_ARM, ""),
            "calls 'authz.resources_with', which is not declared",
        ),
        (
            SHARES.replace(CALLED_ARM, ""),
            "calls 'authz.resources_with', which is not declared",
        ),
    ] {
        let refused = refusal_of(&schema, sharable_only, "grants_delete");
        assert!(refused.contains(reason), "{refused}");
    }
    let capped = SHARES.replace(
        "ALTER TABLE grants ENABLE",
        "CREATE FUNCTION authz.own_grants() RETURNS TABLE (resource_id TEXT, role authz.role)
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT g.resource_id, allowed.role FROM public.grants g
           CROSS JOIN (VALUES ('reader'::authz.role)) allowed(role)
           WHERE g.principal_id = current_setting('app.user_id', true)
         $$;
         CREATE FUNCTION authz.own_grant_resources() RETURNS SETOF TEXT
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT g.resource_id FROM public.grants g
           WHERE g.principal_id = current_setting('app.user_id', true)
             AND (g.resource_id, g.role) IN (SELECT * FROM authz.own_grants())
         $$;
         ALTER FUNCTION authz.own_grants() OWNER TO authz_owner;
         ALTER FUNCTION authz.own_grant_resources() OWNER TO authz_owner;
         CREATE POLICY grants_capped ON grants FOR UPDATE
           USING (resource_id IN (SELECT authz.own_grant_resources()));
         ALTER TABLE grants ENABLE",
    );
    let refused = refusal_of(
        &capped,
        &[
            SHARE_HELPERS,
            &["authz.own_grants", "authz.own_grant_resources"],
        ]
        .concat(),
        "grants_capped",
    );
    assert!(
        refused.contains("which returns labels beside its rows"),
        "{refused}"
    );
}

/// A key outside the keys of every label reads through each arm the helper calls, whose
/// keys are never `NULL`.
#[test]
fn a_key_outside_labelled_rows_reads_through_called_arms() {
    let schema = SHARES.replace(
        DELETE_USING,
        "principal_id = current_setting('app.user_id', true) AND resource_id NOT IN \
         (SELECT share.resource_id FROM authz.sharable_grants() share)",
    );
    let [delete] =
        <[ClassifiedExpr; 1]>::try_from(using_of(&schema, &["grants_delete"])).expect("one policy");
    assert_eq!(
        delete.confidence,
        ConfidenceLevel::A,
        "{:?}",
        delete.pattern
    );
}

/// [`SHARES`] with `authz.shared_again` returning the rows of `authz.sharable_grants`
/// `columns` lists, read in `grants_delete` as `using`.
fn sharing_again(columns: &str, returns: &str, using: &str) -> String {
    SHARES
        .replace(
            "ALTER TABLE grants ENABLE",
            &format!(
                "CREATE FUNCTION authz.shared_again() RETURNS TABLE ({returns})
                 LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
                   SELECT {columns} FROM authz.sharable_grants() share
                 $$;
                 ALTER FUNCTION authz.shared_again() OWNER TO authz_owner;
                 ALTER TABLE grants ENABLE"
            ),
        )
        .replace(DELETE_USING, using)
}

/// A helper read at labels the helper it calls never pairs, at one column or at two
/// columns it returns the same column of, holds no key, and reads that helper at the
/// labels it pairs.
#[test]
fn a_called_helper_holds_only_the_labels_it_pairs() {
    let helpers = [SHARE_HELPERS, &["authz.shared_again"]].concat();
    let never_admin = sharing_again(
        "share.resource_id, share.role",
        "resource_id TEXT, role authz.role",
        "(resource_id, 'admin'::authz.role) IN (SELECT * FROM authz.shared_again())",
    )
    .replace(CALLED_ARM, "");
    let twice = |first: &str, second: &str| {
        sharing_again(
            "share.resource_id, share.role, share.role",
            "resource_id TEXT, role authz.role, again authz.role",
            &format!(
                "(resource_id, '{first}'::authz.role, '{second}'::authz.role) IN \
                 (SELECT * FROM authz.shared_again())"
            ),
        )
    };
    for (shape, schema, holds) in [
        ("admin never paired", never_admin, false),
        ("reader read as admin", twice("reader", "admin"), false),
        ("admin read twice", twice("admin", "admin"), true),
    ] {
        let [delete] =
            <[ClassifiedExpr; 1]>::try_from(using_declaring(&schema, &helpers, &["grants_delete"]))
                .expect("one policy");
        match &delete.pattern {
            PatternClass::P10ConstantBool(constant) => {
                assert!(!holds && !constant.value, "{shape}: {constant:?}");
            }
            PatternClass::P20DeclaredHelper(helper) => {
                assert!(holds, "{shape}: {helper:?}");
                assert_eq!(helper.call.labels, ["'admin'", "'admin'"], "{shape}");
            }
            other => panic!("{shape}: {other:?}"),
        }
    }
}

/// A key outside the keys of a helper reads a `NULL` the helper it calls may return as
/// the key, which hides the row from the callers whose list is not empty.
#[test]
fn a_called_helper_returning_nullable_keys_is_refused_under_not_in() {
    let schema = SHARES
        .replace(
            "GRANT SELECT ON resources, grants TO authz_owner;",
            "CREATE TABLE memberships (id TEXT PRIMARY KEY,
               resource_id TEXT REFERENCES resources (id), principal_id TEXT NOT NULL,
               role authz.role NOT NULL);
             GRANT SELECT ON resources, grants, memberships TO authz_owner;",
        )
        .replace(
            "SELECT g.resource_id FROM public.grants g",
            "SELECT g.resource_id FROM public.memberships g",
        )
        .replace(
            DELETE_USING,
            "principal_id = current_setting('app.user_id', true) AND resource_id NOT IN \
             (SELECT share.resource_id FROM authz.sharable_grants() share)",
        );
    let refused = refusal_of(&schema, SHARE_HELPERS, "grants_delete");
    assert!(
        refused.contains("projection 'public.memberships.resource_id' must be provably non-null"),
        "{refused}"
    );
}

/// A role or a kind a closed column cannot hold returns no row, so the arm calling a
/// helper for such a role, the arm read within such a helper and the capped arm keeping
/// only such a kind hold no key.
#[test]
fn a_called_helper_returning_nothing_holds_no_key() {
    let closed = SHARES.replace(
        "role authz.role NOT NULL, PRIMARY KEY",
        "role authz.role NOT NULL CHECK (role IN ('reader', 'writer')), PRIMARY KEY",
    );
    let within_admin = closed.replace(
        "resource.id IN (SELECT authz.resources_with('writer'))",
        "resource.id IN (SELECT authz.resources_with('admin'))",
    );
    let no_folder = SHARES
        .replace(
            "writers_can_share BOOLEAN NOT NULL DEFAULT false",
            "writers_can_share BOOLEAN NOT NULL DEFAULT false, \
             kind TEXT NOT NULL CHECK (kind IN ('doc'))",
        )
        .replace(
            "WHERE resource.writers_can_share AND",
            "WHERE resource.writers_can_share AND resource.kind = 'folder' AND",
        );
    for (schema, absent) in [
        (closed, "resources_with_admin"),
        (within_admin, "resources_with_admin"),
        (no_folder, "_within_resources_with_writer"),
    ] {
        let model = translator()
            .translate(&db_of(&schema))
            .expect("the schema plans")
            .outputs()
            .expect("the schema translates")
            .model()
            .clone();
        assert!(!model.contains(absent), "{absent} in {model}");
    }
}

/// A request value of the label type compared with a helper returning labels names no row
/// its rows return.
#[test]
fn a_request_value_among_labels_is_refused() {
    let schema = SHARES.replace(
        "ALTER TABLE grants ENABLE",
        "CREATE FUNCTION authz.listed_roles() RETURNS SETOF authz.role
         LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
           SELECT allowed.role FROM public.resources resource
           CROSS JOIN (VALUES ('reader'::authz.role)) allowed(role)
         $$;
         ALTER FUNCTION authz.listed_roles() OWNER TO authz_owner;
         CREATE POLICY grants_listed ON grants FOR UPDATE
           USING (current_setting('app.role', true)::authz.role IN (SELECT authz.listed_roles()));
         ALTER TABLE grants ENABLE",
    );
    let mut registry = FunctionRegistry::new();
    registry.declare_helpers(["authz.listed_roles"]);
    let role = Parser::new(&PostgreSqlDialect {})
        .try_with_sql("authz.role")
        .and_then(|mut parser| parser.parse_data_type())
        .expect("a type name");
    let classified = TranslatorBuilder::new(deployment([
        caller("app.user_id"),
        typed_scalar("app.role", role),
    ]))
    .with_registry(registry)
    .build()
    .classify(&db_of(&schema));
    let using = classified
        .iter()
        .find(|classified| classified.name() == "grants_listed")
        .and_then(|classified| classified.using_classification())
        .expect("grants_listed USING should classify");
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &using.pattern else {
        panic!("grants_listed should be refused, got {:?}", using.pattern);
    };
    assert!(
        reason.contains("'authz.listed_roles' returns labels in the column read as keys"),
        "{reason}"
    );
}
