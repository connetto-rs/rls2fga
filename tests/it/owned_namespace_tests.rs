//! A namespace owned by the row a request names, a user's by the caller and an
//! installation's by the pair of identifiers the request sets together, looked up by one
//! lookup per owner table and compared with a column.

use rls2fga::classifier::patterns::{
    BoolOp, ClassifiedExpr, Composite, ExpandedFunction, MembershipOnRequestValues, PatternClass,
    RequestValueAbsent, UnclassifiedExpr,
};
use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::{Deployment, SessionSetting, SettingValue};
use rls2fga::translator::{Outputs, TranslatorBuilder};
use rls2fga::types::{ConfidenceLevel, TranslationNote};
use sqlparser::ast::DataType;

use crate::support::deployment::{db, json_setting, typed_caller, typed_scalar};

const RESERVED: &str = "'bc3cf2e2-768c-4af9-bf86-65f23378a212'";

/// The namespace schema with `lookup` as the body of `authz.caller_namespace()` and
/// `check` as the insert policy on `objects`. Each user and installation owns the
/// namespace its `owned_namespace_id` names.
fn schema(lookup: &str, check: &str) -> String {
    format!(
        "
CREATE ROLE app NOLOGIN;
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
CREATE TYPE grantee_kind AS ENUM ('user', 'installation');
CREATE TABLE namespaces (
  id UUID PRIMARY KEY,
  owner_kind grantee_kind,
  UNIQUE (id, owner_kind)
);
CREATE TABLE users (
  namespace_id UUID NOT NULL REFERENCES namespaces (id),
  id UUID NOT NULL,
  owned_namespace_id UUID NOT NULL UNIQUE,
  owned_namespace_kind grantee_kind NOT NULL DEFAULT 'user' CHECK (owned_namespace_kind = 'user'),
  PRIMARY KEY (namespace_id, id),
  FOREIGN KEY (owned_namespace_id, owned_namespace_kind) REFERENCES namespaces (id, owner_kind)
);
CREATE TABLE app_installations (
  namespace_id UUID NOT NULL REFERENCES namespaces (id),
  id UUID NOT NULL,
  owned_namespace_id UUID NOT NULL UNIQUE,
  owned_namespace_kind grantee_kind NOT NULL DEFAULT 'installation'
    CHECK (owned_namespace_kind = 'installation'),
  PRIMARY KEY (namespace_id, id),
  FOREIGN KEY (owned_namespace_id, owned_namespace_kind) REFERENCES namespaces (id, owner_kind)
);
CREATE TABLE objects (
  namespace_id UUID NOT NULL REFERENCES namespaces (id),
  id UUID NOT NULL,
  PRIMARY KEY (namespace_id, id)
);
GRANT SELECT ON namespaces, users, app_installations TO authz_owner;
GRANT USAGE ON SCHEMA authz TO app, authz_owner;
GRANT SELECT, INSERT ON objects TO app;
GRANT SELECT ON namespaces, users, app_installations TO app;
CREATE FUNCTION authz.caller_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
$$;
CREATE FUNCTION authz.acting_installation(OUT namespace_id UUID, OUT id UUID) RETURNS RECORD
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  namespace_id := NULLIF(current_setting('app.installation_namespace_id', true), '')::UUID;
  id := NULLIF(current_setting('app.installation_id', true), '')::UUID;
  IF (namespace_id IS NULL) <> (id IS NULL) THEN
    RAISE EXCEPTION 'incomplete installation identity' USING ERRCODE = '22023';
  END IF;
END
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT id FROM authz.acting_installation()
$$;
CREATE FUNCTION authz.acting_installation_namespace_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN id IS NOT NULL THEN namespace_id END FROM authz.acting_installation()
$$;
CREATE FUNCTION authz.caller_namespace() RETURNS SETOF UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  {lookup}
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_namespace_id() OWNER TO authz_owner;
ALTER FUNCTION authz.caller_namespace() OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY objects_insert ON objects FOR INSERT TO app WITH CHECK ({check});
"
    )
}

/// The user lookup, keyed by the reserved users namespace and the caller.
fn users() -> String {
    format!(
        "SELECT u.owned_namespace_id FROM public.users u \
         WHERE u.namespace_id = {RESERVED} AND u.id = (SELECT authz.caller_id())"
    )
}

/// The installation lookup, keyed by the installation pair the request sets.
const INSTALLATIONS: &str = "SELECT i.owned_namespace_id FROM public.app_installations i \
     WHERE i.namespace_id = (SELECT authz.acting_installation_namespace_id()) \
     AND i.id = (SELECT authz.acting_installation_id())";

/// The installation lookup, read only where the request carries no caller.
fn installations_without_caller() -> String {
    format!("{INSTALLATIONS} AND (SELECT authz.caller_id()) IS NULL")
}

/// The caller's namespace, or the installation's where the request carries no caller.
fn owned_namespace() -> String {
    format!("{} UNION ALL {}", users(), installations_without_caller())
}

fn settings() -> Vec<SessionSetting> {
    vec![
        typed_caller("app.user_id", DataType::Uuid).may_be_unset(),
        typed_scalar("app.installation_namespace_id", DataType::Uuid).may_be_unset(),
        typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    ]
}

fn installation_pair() -> Deployment {
    Deployment::new("app", ["app"], settings())
        .expect("a valid deployment")
        .with_settings_set_together(["app.installation_namespace_id", "app.installation_id"])
        .expect("both settings are declared")
}

/// The insert check on `objects`.
fn classified(sql: &str) -> ClassifiedExpr {
    classified_under(installation_pair(), sql)
}

fn classified_under(deployment: Deployment, sql: &str) -> ClassifiedExpr {
    TranslatorBuilder::new(deployment)
        .build()
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

/// The installation membership a pattern is, with the columns it compares and the
/// settings they are compared with.
fn installation_membership(pattern: &PatternClass) -> Option<Vec<(&str, &str)>> {
    let PatternClass::P32MembershipOnRequestValues(MembershipOnRequestValues {
        join_table,
        pairs,
        compared,
        ..
    }) = pattern
    else {
        return None;
    };
    (join_table.name() == "app_installations"
        && pairs
            .iter()
            .map(|pair| (pair.join_column.as_str(), pair.outer_column.as_str()))
            .eq([("owned_namespace_id", "namespace_id")]))
    .then(|| {
        compared
            .iter()
            .map(|compared| {
                (
                    compared.value_column.as_str(),
                    compared.source.setting_key(),
                )
            })
            .collect()
    })
}

/// A membership row keyed by values the request carries admits whoever presents them, so
/// the installation's namespace is the one whose owning row the request's pair names.
#[test]
fn a_membership_keyed_by_the_request_pair_reads_as_a_request_value_membership() {
    for installation in [
        INSTALLATIONS.to_string(),
        INSTALLATIONS.replace(
            "(SELECT authz.acting_installation_namespace_id())",
            "NULLIF(current_setting('app.installation_namespace_id', true), '')::uuid",
        ),
    ] {
        let classified = classified(&schema(
            "SELECT NULL::uuid",
            &format!("namespace_id IN ({installation})"),
        ));
        assert_eq!(classified.confidence, ConfidenceLevel::A, "{classified:?}");
        assert_eq!(
            installation_membership(&classified.pattern),
            Some(vec![
                ("namespace_id", "app.installation_namespace_id"),
                ("id", "app.installation_id"),
            ]),
            "{installation}: {classified:?}"
        );
    }
}

/// The caller compared beside a request value is a subject a tuple names, which the
/// request values cannot sit beside in one membership.
#[test]
fn a_request_value_beside_the_caller_is_no_request_value_membership() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        "namespace_id IN (SELECT i.owned_namespace_id FROM public.app_installations i \
         WHERE i.namespace_id = (SELECT authz.acting_installation_namespace_id()) \
         AND i.id = (SELECT authz.caller_id()))",
    ));
    assert!(
        installation_membership(&classified.pattern).is_none(),
        "{classified:?}"
    );
}

/// The accessor unites one lookup per owner table. Each selects at most one row, and the
/// installation's only where the request carries no caller, which the user's needs, so
/// the call is the one namespace the request owns.
#[test]
fn a_united_lookup_reads_as_either_membership() {
    let accessor = classified(&schema(
        &owned_namespace(),
        "namespace_id = (SELECT authz.caller_namespace())",
    ));
    assert_eq!(accessor.confidence, ConfidenceLevel::A, "{accessor:?}");
    let PatternClass::ExpandedFunction(ExpandedFunction {
        function, inner, ..
    }) = &accessor.pattern
    else {
        panic!("expected the expanded accessor, got {accessor:?}");
    };
    assert_eq!(function, "caller_namespace");
    let inline = classified(&schema(
        "SELECT NULL::uuid",
        &format!("namespace_id = ({})", owned_namespace()),
    ));
    assert_eq!(&inline, inner.as_ref());

    let PatternClass::P8Composite(Composite {
        op: BoolOp::Or,
        parts,
    }) = &inner.pattern
    else {
        panic!("expected either membership, got {inner:?}");
    };
    let [user, installation] = parts.as_slice() else {
        panic!("expected two memberships, got {parts:?}");
    };
    assert!(
        matches!(&user.pattern, PatternClass::P4ExistsMembership(membership)
            if membership.join_table.name() == "users"),
        "{user:?}"
    );
    let PatternClass::P8Composite(Composite {
        op: BoolOp::And,
        parts,
    }) = &installation.pattern
    else {
        panic!("expected the gated installation membership, got {installation:?}");
    };
    assert!(
        parts.iter().any(|part| matches!(
            &part.pattern,
            PatternClass::P28RequestValueAbsent(RequestValueAbsent { source, negated: false })
                if source.setting_key() == "app.user_id"
        )),
        "{parts:?}"
    );
    assert!(
        parts
            .iter()
            .any(|part| installation_membership(&part.pattern).is_some()),
        "{parts:?}"
    );
}

/// Without the caller test both lookups select a row for a request carrying a caller and
/// an installation, and the call hands over only the first.
#[test]
fn united_lookups_that_can_both_select_a_row_are_refused() {
    let both = format!("{} UNION ALL {INSTALLATIONS}", users());
    for check in [
        "namespace_id = (SELECT authz.caller_namespace())".to_string(),
        format!("namespace_id = ({both})"),
    ] {
        let classified = classified(&schema(&both, &check));
        assert_eq!(classified.confidence, ConfidenceLevel::D, "{check}");
        let reason = refusal(&classified);
        assert!(
            reason.contains("more than one row") && reason.contains("unites"),
            "{check}: {reason}"
        );
    }
}

/// Each united lookup has to select at most one row on its own.
#[test]
fn a_united_lookup_that_may_select_several_rows_is_refused() {
    let unkeyed = format!(
        "SELECT u.owned_namespace_id FROM public.users u WHERE u.id = (SELECT authz.caller_id()) \
         UNION ALL {}",
        installations_without_caller()
    );
    let reason = refusal(&classified(&schema(
        &unkeyed,
        "namespace_id = (SELECT authz.caller_namespace())",
    )))
    .to_string();
    assert!(reason.contains("more than one row of 'users'"), "{reason}");
}

/// A pair the deployment does not declare set together may arrive half set, so the
/// accessor reading half of it is no declared read.
#[test]
fn a_pair_not_set_together_is_refused() {
    let classified = classified_under(
        Deployment::new("app", ["app"], settings()).expect("a valid deployment"),
        &schema(
            &owned_namespace(),
            "namespace_id = (SELECT authz.caller_namespace())",
        ),
    );
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
}

/// A set-returning call in what the lookup orders by returns several rows for the one its
/// key selects, which `PostgreSQL` refuses as a scalar subquery.
#[test]
fn a_lookup_ordered_by_a_set_returning_call_is_refused() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        &format!(
            "namespace_id = ({} ORDER BY generate_series(1, 2))",
            users()
        ),
    ));
    assert!(refusal(&classified).contains("orders by"), "{classified:?}");
}

/// A field taken out of a declared document is indirection, so the membership compared
/// with one grades as such a read does elsewhere.
#[test]
fn a_membership_on_a_document_field_grades_b() {
    let deployment = Deployment::new(
        "app",
        ["app"],
        [
            typed_scalar("app.installation_namespace_id", DataType::Uuid),
            json_setting(
                "request.jwt.claims",
                [(&["installation_id"], SettingValue::Scalar(DataType::Uuid))],
            ),
        ],
    )
    .expect("a valid deployment");
    let classified = classified_under(
        deployment,
        &schema(
            "SELECT NULL::uuid",
            "namespace_id IN (SELECT i.owned_namespace_id FROM public.app_installations i \
             WHERE i.namespace_id = current_setting('app.installation_namespace_id')::uuid \
             AND i.id = (current_setting('request.jwt.claims')::jsonb ->> 'installation_id')::uuid)",
        ),
    );
    assert_eq!(classified.confidence, ConfidenceLevel::B, "{classified:?}");
    assert!(
        installation_membership(&classified.pattern).is_some(),
        "{classified:?}"
    );
}

/// A clock comparison beside a condition the row alone does not decide keeps no gate, so
/// the membership denies and says why.
#[test]
fn a_membership_on_request_values_whose_clock_no_gate_carries_is_disclosed() {
    let sql = "
CREATE ROLE app NOLOGIN;
CREATE TABLE installs (
  id TEXT PRIMARY KEY,
  owned TEXT NOT NULL,
  kind TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE objects (id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL);
GRANT SELECT ON installs, objects TO app;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY objects_read ON objects FOR SELECT TO app USING (
  namespace_id IN (SELECT i.owned FROM installs i
    WHERE i.id = current_setting('app.installation_id')
      AND i.expires_at > now() AND lower(i.kind) = 'app'));
";
    let outputs = TranslatorBuilder::new(
        Deployment::new(
            "app",
            ["app"],
            [typed_scalar("app.installation_id", DataType::Text)],
        )
        .expect("a valid deployment"),
    )
    .build()
    .translate(&db(sql))
    .expect("translation should plan")
    .outputs_accepting_gaps();
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::ExpressionRefused { reason, .. } if reason.contains("clock comparison")
        )),
        "{:?}",
        outputs.notes()
    );
}

/// A comparison written twice compares one value once.
#[test]
fn a_request_comparison_written_twice_is_compared_once() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        &format!(
            "namespace_id IN ({INSTALLATIONS} AND i.id = (SELECT authz.acting_installation_id()))"
        ),
    ));
    assert_eq!(
        installation_membership(&classified.pattern),
        Some(vec![
            ("namespace_id", "app.installation_namespace_id"),
            ("id", "app.installation_id"),
        ]),
        "{classified:?}"
    );
}

/// The rows a tuple query reads carry no `JOIN`, so a request value compared in one would
/// drop out of the gate.
#[test]
fn a_request_value_compared_in_a_join_is_refused() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        "namespace_id IN (SELECT i.owned_namespace_id FROM public.app_installations i \
         JOIN public.namespaces ns ON ns.id = i.owned_namespace_id \
         AND i.id = (SELECT authz.acting_installation_id()) \
         WHERE i.namespace_id = (SELECT authz.acting_installation_namespace_id()))",
    ));
    assert_eq!(classified.confidence, ConfidenceLevel::D, "{classified:?}");
}

/// Negation has no tuple to stand on, and the refusal names the membership it negates.
#[test]
fn a_negated_request_value_membership_is_refused_by_name() {
    let classified = classified(&schema(
        "SELECT NULL::uuid",
        &format!("NOT (namespace_id IN ({INSTALLATIONS}))"),
    ));
    assert!(
        refusal(&classified).contains("membership row holding values the request carries"),
        "{classified:?}"
    );
}

/// The schema translated under the installation pair, gaps kept.
fn translated(sql: &str) -> Outputs {
    TranslatorBuilder::new(installation_pair())
        .build()
        .translate(&db(sql))
        .expect("translation should plan")
        .outputs_accepting_gaps()
}

/// `schema` with the request-value membership as the insert check on `objects`.
fn installation_check() -> String {
    schema(
        "SELECT NULL::uuid",
        &format!("namespace_id IN ({INSTALLATIONS})"),
    )
}

/// The report names the scanned table and the columns the request's values key.
#[test]
fn the_report_names_a_request_value_membership() {
    let report = translated(&installation_check()).report();
    assert!(
        report.contains("P32 (EXISTS")
            && report.contains("app_installations on request values in namespace_id, id)"),
        "{report}"
    );
}

/// The subquery reads the membership table as the caller, so a table whose row security
/// shows the role no row admits nobody.
#[test]
fn a_request_value_membership_the_role_reads_no_row_of_admits_nobody() {
    let outputs = translated(&format!(
        "{}ALTER TABLE app_installations ENABLE ROW LEVEL SECURITY;\n",
        installation_check()
    ));
    assert!(
        outputs.notes().iter().any(|note| matches!(
            note,
            TranslationNote::MembershipTableGrantsNoReads { join_table, .. }
                if join_table.name() == "app_installations"
        )),
        "{:?}",
        outputs.notes()
    );
}

/// A guarded row nothing identifies cannot be linked to the namespace its shares reach, so
/// the check admits nobody and says why.
#[test]
fn a_request_value_membership_over_rows_nothing_identifies_writes_no_bridge() {
    let sql = installation_check().replace(
        "  id UUID NOT NULL,\n  PRIMARY KEY (namespace_id, id)\n);",
        "  id UUID NOT NULL\n);",
    );
    let outputs = translated(&sql);
    let tuples = format_tuples(outputs.tuple_queries());
    assert!(
        tuples.contains("skipped public.objects to namespaces bridge"),
        "{tuples}"
    );
    let model = outputs.model();
    assert_eq!(
        relation(&model, "objects", "can_insert"),
        "no_access",
        "{model}"
    );
}

/// The definition of `relation` on `type_name` in `model`.
fn relation<'m>(model: &'m str, type_name: &str, relation: &str) -> &'m str {
    let (_, declared) = model
        .split_once(&format!("type {type_name}\n"))
        .expect("the model declares the type");
    let prefix = format!("define {relation}: ");
    declared
        .lines()
        .take_while(|line| !line.starts_with("type "))
        .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
        .expect("the type defines the relation")
}

/// Each share is a row of the membership table, so a table nothing identifies a row of
/// writes no share.
#[test]
fn a_request_value_membership_in_rows_nothing_identifies_writes_no_share() {
    let sql = installation_check();
    let (head, installations) = sql
        .split_once("CREATE TABLE app_installations")
        .expect("the schema declares app_installations");
    let installations = installations.replacen(" UNIQUE,", ",", 1).replacen(
        "  PRIMARY KEY (namespace_id, id),\n",
        "",
        1,
    );
    let tuples = format_tuples(
        translated(&format!(
            "{head}CREATE TABLE app_installations{installations}"
        ))
        .tuple_queries(),
    );
    assert!(
        tuples.contains("skipped request value shares for"),
        "{tuples}"
    );
}

/// A membership naming the guarded row's own key reaches the shares from that row.
#[test]
fn a_request_value_membership_keyed_by_the_guarded_row_reaches_its_shares() {
    let sql = format!(
        "{}ALTER TABLE namespaces ENABLE ROW LEVEL SECURITY;
CREATE POLICY namespaces_read ON namespaces FOR SELECT TO app USING (id IN ({INSTALLATIONS}));
",
        installation_check()
    );
    let model = translated(&sql).model();
    let can_select = relation(&model, "namespaces", "can_select");
    assert!(
        can_select.starts_with("gate_namespaces_read_")
            && can_select.contains(" from app_installations_share and "),
        "{model}"
    );
}
