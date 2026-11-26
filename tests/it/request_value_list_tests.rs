//! Grant arms of a declared helper comparing several columns with values the request
//! carries, every comparison holding on the arm's one row.

use rls2fga::classifier::patterns::{PatternClass, UnclassifiedExpr};
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{CallerGate, ConfidenceLevel, RequestComparison, RowDecision};
use sqlparser::ast::DataType;

use crate::support::deployment::{deployment, typed_caller, typed_scalar};
use crate::support::footgun::db_of;

pub(crate) const INSTALLATION_PAIRS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE organizations (id TEXT PRIMARY KEY);
CREATE TABLE installation_permissions (
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  kind TEXT NOT NULL,
  installation_namespace_id TEXT NOT NULL,
  installation_id TEXT NOT NULL,
  PRIMARY KEY (organization_id, kind, installation_namespace_id, installation_id)
);
CREATE TABLE organization_blocks (
  organization_id TEXT NOT NULL REFERENCES organizations(id),
  principal_namespace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  PRIMARY KEY (organization_id, principal_namespace_id, principal_id)
);
GRANT SELECT ON installation_permissions, organization_blocks TO authz_owner;
CREATE FUNCTION authz.capped_kinds() RETURNS TABLE (organization_id TEXT, kind TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT permission.organization_id, permission.kind
  FROM public.installation_permissions permission
  WHERE permission.installation_namespace_id = current_setting('app.installation_namespace_id', true)
    AND permission.installation_id = current_setting('app.installation_id', true)
$$;
ALTER FUNCTION authz.capped_kinds() OWNER TO authz_owner;
CREATE FUNCTION authz.blocking_organizations() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT block.organization_id FROM public.organization_blocks block
  WHERE block.principal_namespace_id = 'reserved'
    AND block.principal_id = current_setting('app.user_id', true)
  UNION
  SELECT block.organization_id FROM public.organization_blocks block
  WHERE block.principal_namespace_id = current_setting('app.installation_namespace_id', true)
    AND block.principal_id = current_setting('app.installation_id', true)
$$;
ALTER FUNCTION authz.blocking_organizations() OWNER TO authz_owner;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY visible ON organizations FOR SELECT
USING ((id, 'organization') IN (SELECT * FROM authz.capped_kinds()));
CREATE POLICY unblocked ON organizations AS RESTRICTIVE FOR SELECT
USING (id NOT IN (SELECT authz.blocking_organizations()));
";

const PAIR_HELPERS: &[&str] = &["authz.capped_kinds", "authz.blocking_organizations"];

/// The caller as text, and the installation the request acts through as two scalars.
fn pair_translator() -> Translator {
    TranslatorBuilder::new(deployment([
        typed_caller("app.user_id", DataType::Text),
        typed_scalar("app.installation_namespace_id", DataType::Text),
        typed_scalar("app.installation_id", DataType::Text),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .with_declared_helpers(PAIR_HELPERS.iter().copied())
    .build()
}

fn value_gate(context_key: &str, request_parameter: &str) -> CallerGate {
    CallerGate {
        context_key: context_key.to_string(),
        request_parameter: request_parameter.to_string(),
        comparison: RequestComparison::CallerValueEquals,
    }
}

/// Both helpers classify, and each table holding an installation's rows gates every row on
/// both of its values at once, so no two rows each matching one value combine.
#[test]
fn an_installation_named_by_two_values_is_matched_on_one_row() {
    let classified = pair_translator().classify(&db_of(INSTALLATION_PAIRS));
    for policy in ["visible", "unblocked"] {
        let using = classified
            .iter()
            .find(|classified| classified.name() == policy)
            .unwrap_or_else(|| panic!("{policy} should classify"))
            .using_classification()
            .unwrap_or_else(|| panic!("{policy} USING should classify"));
        assert!(
            !matches!(using.pattern, PatternClass::Unknown(_)),
            "{policy}: {:?}",
            using.pattern
        );
    }
    let translation = pair_translator()
        .translate(&db_of(INSTALLATION_PAIRS))
        .expect("the schema should plan");
    let expected = [
        value_gate("installation_namespace_id", "app_installation_namespace_id"),
        value_gate("installation_id", "app_installation_id"),
    ];
    for (share_type, expected) in [
        ("installation_permissions_share", expected.as_slice()),
        (
            "organization_blocks_share",
            &[
                value_gate("principal_namespace_id", "app_installation_namespace_id"),
                value_gate("principal_id", "app_installation_id"),
            ],
        ),
    ] {
        let gated: Vec<_> = translation
            .relations()
            .iter()
            .filter(|relation| relation.type_name.as_str() == share_type)
            .filter(|relation| !relation.caller_gates.is_empty())
            .collect();
        let [gated] = gated.as_slice() else {
            let types: Vec<_> = translation
                .relations()
                .iter()
                .map(|relation| (relation.type_name.as_str(), relation.relation.as_str()))
                .collect();
            panic!(
                "{share_type} holds one gated relation, got {gated:#?} among {types:?}\n{:#?}",
                translation.notes()
            );
        };
        assert_eq!(gated.caller_gates, expected, "{share_type}");
        match &gated.decision {
            Some(RowDecision::RequestGated { gates, .. }) => {
                assert_eq!(gates, expected, "{share_type}");
            }
            other => panic!("{share_type}: one row decides its gate, got {other:?}"),
        }
    }
    let outputs = translation
        .outputs()
        .expect("every clause should translate");
    let model = outputs.model();
    assert!(
        model.contains(
            "\"app_installation_namespace_id\" in settings && \
             settings[\"app_installation_namespace_id\"] == installation_namespace_id && \
             \"app_installation_id\" in settings && \
             settings[\"app_installation_id\"] == installation_id"
        ),
        "{model}"
    );
    let shares = outputs
        .tuple_queries()
        .iter()
        .find(|query| {
            query
                .sql
                .contains("FROM \"public\".\"installation_permissions\"")
                && query.sql.contains("jsonb_build_object(")
        })
        .unwrap_or_else(|| panic!("installation_permissions loads its shares"));
    assert!(
        shares.sql.contains(
            "jsonb_build_object('installation_namespace_id', \
             \"installation_namespace_id\"::text, 'installation_id', \"installation_id\"::text)"
        ),
        "{}",
        shares.sql
    );
}

/// Two comparisons of one column each carry the row's value under a parameter of its own,
/// and the column is guarded once.
#[test]
fn two_comparisons_of_one_column_carry_it_twice() {
    let schema = INSTALLATION_PAIRS.replace(
        "permission.installation_id = current_setting('app.installation_id', true)",
        "permission.installation_namespace_id = current_setting('app.installation_id', true)",
    );
    let translation = pair_translator()
        .translate(&db_of(&schema))
        .expect("the schema should plan");
    let gated = translation
        .relations()
        .iter()
        .find(|relation| {
            relation.type_name.as_str() == "installation_permissions_share"
                && !relation.caller_gates.is_empty()
        })
        .expect("installation_permissions holds a gated relation");
    let [first, second] = gated.caller_gates.as_slice() else {
        panic!("two comparisons, got {:?}", gated.caller_gates);
    };
    assert_eq!(
        (
            first.request_parameter.as_str(),
            second.request_parameter.as_str()
        ),
        ("app_installation_namespace_id", "app_installation_id")
    );
    assert_ne!(first.context_key, second.context_key);
    let shares = translation
        .outputs()
        .expect("every clause should translate")
        .tuple_queries()
        .iter()
        .find(|query| {
            query
                .sql
                .contains("FROM \"public\".\"installation_permissions\"")
                && query.sql.contains("jsonb_build_object(")
        })
        .unwrap_or_else(|| panic!("installation_permissions loads its shares"))
        .sql
        .clone();
    assert_eq!(
        shares
            .matches("\"installation_namespace_id\" IS NOT NULL")
            .count(),
        1,
        "{shares}"
    );
    let (context, _) = shares
        .split_once("jsonb_build_object(")
        .and_then(|(_, rest)| rest.split_once(") AS context"))
        .unwrap_or_else(|| panic!("the shares carry a context: {shares}"));
    assert_eq!(
        context
            .matches("\"installation_namespace_id\"::text")
            .count(),
        2,
        "{context}"
    );
}

/// A tuple names one subject, so an arm comparing the caller beside a value the request
/// carries is refused rather than read as comparing either alone.
#[test]
fn the_caller_beside_a_request_value_is_refused() {
    let schema = INSTALLATION_PAIRS.replace(
        "WHERE block.principal_namespace_id = 'reserved'",
        "WHERE block.principal_namespace_id = current_setting('app.installation_namespace_id', \
         true)",
    );
    let using = pair_translator()
        .classify(&db_of(&schema))
        .into_iter()
        .find(|classified| classified.name() == "unblocked")
        .expect("unblocked should classify")
        .using_classification()
        .expect("unblocked USING should classify")
        .clone();
    let reason = "declared helper 'authz.blocking_organizations' compares column 'principal_id' \
                  of 'public.organization_blocks' with the caller or a principal the request \
                  acts for beside another comparison with the request";
    match using.pattern {
        PatternClass::Unknown(UnclassifiedExpr {
            reason: refused, ..
        }) => assert!(refused.contains(reason), "expected {reason}, got {refused}"),
        other => panic!("unblocked should be refused with {reason}, got {other:?}"),
    }
}
