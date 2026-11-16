//! A principal the request acts for beside the caller, such as the app installation acting
//! for a user, read as a request value and as a grantee of a declared helper's arm.

use rls2fga::generator::model_generator::PlanningError;
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{ConfidenceLevel, RelationName, RequestPrincipal, TypeName};
use sqlparser::ast::DataType;

use crate::declared_helper_tests::{absent_installation_translator, ABSENT_INSTALLATION};
use crate::support::deployment::{caller, deployment, principal, typed_scalar};
use crate::support::footgun::{db_of, relation_definition, relation_definitions};

/// Organizations blocking principals, read by every request whose caller or acting
/// installation no organization of the project blocks. `keeps` is the helper's condition
/// on each block.
pub(crate) fn principal_blocks(keeps: &str) -> String {
    format!(
        "CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (id TEXT PRIMARY KEY);
CREATE TABLE projects (id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations (id));
CREATE TABLE organization_blocks (
  organization_id TEXT NOT NULL REFERENCES organizations (id),
  principal_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id, principal_id)
);
GRANT SELECT ON organization_blocks TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT b.organization_id FROM public.organization_blocks b
  WHERE {keeps}
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
CREATE POLICY projects_all ON projects FOR SELECT USING (true);
CREATE POLICY projects_unblocked ON projects AS RESTRICTIVE FOR SELECT
  USING (NOT (organization_id = ANY (ARRAY(SELECT authz.blocking_organizations()))));
"
    )
}

/// Blocks naming the caller or the acting installation.
pub(crate) const CALLER_OR_INSTALLATION: &str = "b.principal_id IN (\
     current_setting('app.user_id', true), current_setting('app.installation_id', true))";

pub(crate) const BLOCK_HELPERS: &[&str] = &["authz.blocking_organizations"];

/// A translator for the caller in `app.user_id` and the installation acting for it in
/// `app.installation_id`, either of which a request may leave unset.
pub(crate) fn principal_translator() -> Translator {
    TranslatorBuilder::new(deployment([
        caller("app.user_id").may_be_unset(),
        principal("app.installation_id", "installation", DataType::Text).may_be_unset(),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(BLOCK_HELPERS)
    .build()
}

fn model(sql: &str) -> String {
    principal_translator()
        .translate(&db_of(sql))
        .expect("the schema should plan")
        .outputs()
        .expect("every clause should translate")
        .model()
        .clone()
}

/// The arm naming the installation holds `installation:<id>` subjects, and the caller
/// reaches them as the installation's actor, so one check keeps the caller as its user.
#[test]
fn a_grant_to_a_request_principal_reaches_the_caller_acting_for_it() {
    let dsl = model(&principal_blocks(CALLER_OR_INSTALLATION));
    let blocking = relation_definition(&dsl, "organizations", "blocking_organizations")
        .unwrap_or_else(|| panic!("{dsl}"));
    let (caller_arm, principal_arm) = blocking
        .split_once(" or ")
        .unwrap_or_else(|| panic!("{dsl}"));
    assert_eq!(principal_arm, "actor from member_installation", "{dsl}");
    assert_eq!(
        relation_definition(&dsl, "organizations", caller_arm).as_deref(),
        Some("[user]"),
        "{dsl}"
    );
    assert_eq!(
        relation_definition(&dsl, "organizations", "member_installation").as_deref(),
        Some("[installation]"),
        "{dsl}"
    );
    assert_eq!(
        relation_definitions(&dsl, "installation"),
        [("actor".to_string(), "[user]".to_string())],
        "{dsl}"
    );
}

/// The installation's arm loads the blocks naming it as installations, and the caller's
/// arm the same rows as users, each from its own query.
#[test]
fn each_arm_loads_its_principal_type() {
    let outputs = principal_translator()
        .translate(&db_of(&principal_blocks(CALLER_OR_INSTALLATION)))
        .expect("the schema should plan")
        .outputs_accepting_gaps();
    let queries: Vec<&str> = outputs
        .tuple_queries()
        .iter()
        .map(|query| query.sql.as_str())
        .filter(|sql| sql.contains("FROM \"public\".\"organization_blocks\""))
        .collect();
    for (relation, subject) in [
        ("'member_installation' AS relation", "'installation:'"),
        ("'member_530a50e2' AS relation", "'user:'"),
    ] {
        assert!(
            queries
                .iter()
                .any(|sql| sql.contains(relation) && sql.contains(&format!("{subject} ||"))),
            "{relation}: {queries:#?}"
        );
    }
}

/// The translation names every principal a check states with a contextual tuple, keyed
/// by the parameter its identity travels under.
#[test]
fn the_translation_names_the_principals_a_check_states() {
    let translation = principal_translator()
        .translate(&db_of(&principal_blocks(CALLER_OR_INSTALLATION)))
        .expect("the schema should plan");
    assert_eq!(
        translation.request_principals(),
        [RequestPrincipal {
            setting_key: "app.installation_id".to_string(),
            request_parameter: "app_installation_id".to_string(),
            principal_type: TypeName::try_from("installation".to_string()).expect("a type name"),
            relation: RelationName::try_from("actor".to_string()).expect("a relation name"),
        }]
    );
    assert_eq!(
        translation.request_principals()[0].object("i-1"),
        "installation:i-1"
    );
}

/// A principal reads as one request value wherever a scalar does, so declaring the
/// installation a principal loses nothing the scalar declaration translated, and adds
/// only the type its checks name it as.
#[test]
fn a_principal_reads_as_the_request_value_a_scalar_reads_as() {
    let read = |installation| {
        absent_installation_translator(installation)
            .translate(&db_of(ABSENT_INSTALLATION))
            .expect("the schema should plan")
            .outputs()
            .expect("every clause should translate")
            .model()
            .clone()
    };
    let scalar = read(typed_scalar("app.installation_id", DataType::Uuid).may_be_unset());
    let principal =
        read(principal("app.installation_id", "installation", DataType::Uuid).may_be_unset());
    let principal_type = "type installation\n  relations\n    define actor: [user]\n\n";
    assert!(principal.contains(principal_type), "{principal}");
    assert_eq!(principal.replacen(principal_type, "", 1), scalar);
}

/// A gate excluding callers from an installation's rows names callers, while the rows name
/// installations, so the arm is refused rather than read as excluding nobody.
#[test]
fn a_caller_gate_on_a_principal_arm_is_refused() {
    let sql = principal_blocks(&format!(
        "{CALLER_OR_INSTALLATION} AND current_setting('app.user_id', true) <> 'anonymous'"
    ));
    let translator = TranslatorBuilder::new(deployment([
        caller("app.user_id"),
        principal("app.installation_id", "installation", DataType::Text),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(BLOCK_HELPERS)
    .build();
    let classified = translator.classify(&db_of(&sql));
    let shown = format!(
        "{:?}",
        classified
            .iter()
            .find(|policy| policy.name() == "projects_unblocked")
            .expect("the blocklist should classify")
            .using_classification()
    );
    assert!(
        shown.contains(
            "declared helper 'authz.blocking_organizations' excludes callers from rows \
             naming the installation the request acts for"
        ),
        "{shown}"
    );
}

/// A principal's type is the generator's, so a table claiming it, or a principal type
/// spelled as a well-known type or as no type name, is refused before planning.
#[test]
fn a_principal_type_claimed_twice_or_unspellable_is_refused() {
    let plan = |kind: &str, sql: &str| {
        TranslatorBuilder::new(deployment([
            caller("app.user_id"),
            principal("app.installation_id", kind, DataType::Text),
        ]))
        .build()
        .translate(&db_of(sql))
        .err()
    };
    let schema = principal_blocks(CALLER_OR_INSTALLATION);
    assert!(
        matches!(
            plan(
                "installation",
                &format!("{schema}CREATE TABLE installation (id TEXT PRIMARY KEY);")
            ),
            Some(PlanningError::PrincipalTypeName { table, type_name, .. })
                if table == "public.installation" && type_name.as_str() == "installation"
        ),
        "a table named after the principal type"
    );
    assert!(
        matches!(
            plan("user", &schema),
            Some(PlanningError::PrincipalTakesWellKnownType { setting, type_name, .. })
                if setting == "app.installation_id" && type_name.as_str() == "user"
        ),
        "a principal type named like the caller's"
    );
    assert!(
        matches!(
            plan("app installation", &schema),
            Some(PlanningError::InvalidPrincipalType { setting, .. })
                if setting == "app.installation_id"
        ),
        "a principal type no type name spells"
    );
}
