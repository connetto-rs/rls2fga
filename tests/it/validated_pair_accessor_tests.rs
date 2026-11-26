//! A `LANGUAGE sql` accessor selecting an output of a PL/pgSQL validator that raises on half
//! of an identity pair reads as the setting read that output holds, once the deployment
//! declares the pair set together.

use rls2fga::classifier::patterns::{
    ClassifiedExpr, ClassifiedPolicy, PatternClass, UnclassifiedExpr,
};
use rls2fga::parser::sql_parser::Deployment;
use rls2fga::translator::TranslatorBuilder;
use rls2fga::types::ConfidenceLevel;
use sqlparser::ast::DataType;

use crate::support::deployment::{deployment, typed_scalar};
use crate::support::footgun::db_of;

const VALIDATOR: &str = "
  namespace_id := NULLIF(current_setting('app.installation_namespace_id', true), '')::UUID;
  id := NULLIF(current_setting('app.installation_id', true), '')::UUID;
  IF (namespace_id IS NULL) <> (id IS NULL) THEN
    RAISE EXCEPTION 'incomplete installation identity' USING ERRCODE = '22023';
  END IF;";

/// A schema whose validator runs `validator` and whose local accessor runs under `set`.
fn schema(validator: &str, set: &str) -> String {
    format!(
        "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE objects (id UUID PRIMARY KEY, installation_namespace_id UUID NOT NULL,
  installation_id UUID NOT NULL);
CREATE FUNCTION authz.acting_installation(OUT namespace_id UUID, OUT id UUID) RETURNS RECORD
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN{validator}
END
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp{set} AS $$
  SELECT id FROM authz.acting_installation()
$$;
CREATE FUNCTION authz.acting_installation_namespace_id() RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN id IS NOT NULL THEN namespace_id END FROM authz.acting_installation()
$$;
ALTER FUNCTION authz.acting_installation() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_namespace_id() OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY local_wrapped ON objects
  USING (installation_id = (SELECT authz.acting_installation_id()));
CREATE POLICY local_inline ON objects
  USING (installation_id = NULLIF(current_setting('app.installation_id', true), '')::uuid);
CREATE POLICY namespace_wrapped ON objects
  USING (installation_namespace_id = (SELECT authz.acting_installation_namespace_id()));
CREATE POLICY namespace_inline ON objects USING (installation_namespace_id =
  NULLIF(current_setting('app.installation_namespace_id', true), '')::uuid);
CREATE POLICY absent_wrapped ON objects USING ((SELECT authz.acting_installation_id()) IS NULL);
CREATE POLICY absent_inline ON objects
  USING (NULLIF(current_setting('app.installation_id', true), '')::uuid IS NULL);
"
    )
}

/// Both halves of the installation identity as `uuid` values a request may leave unset,
/// declared set together where `together`.
fn pair(together: bool) -> Deployment {
    let declared = deployment([
        typed_scalar("app.installation_namespace_id", DataType::Uuid).may_be_unset(),
        typed_scalar("app.installation_id", DataType::Uuid).may_be_unset(),
    ]);
    if together {
        declared
            .with_settings_set_together(["app.installation_namespace_id", "app.installation_id"])
            .expect("both settings are declared")
    } else {
        declared
    }
}

/// The policies `schema` classifies into under `deployment`.
fn classified(deployment: Deployment, schema: &str) -> Vec<ClassifiedPolicy> {
    TranslatorBuilder::new(deployment)
        .with_min_confidence(ConfidenceLevel::B)
        .build()
        .classify(&db_of(schema))
}

/// The `USING` classification of the policy named `policy`.
fn using_of<'p>(policies: &'p [ClassifiedPolicy], policy: &str) -> &'p ClassifiedExpr {
    policies
        .iter()
        .find(|classified| classified.name() == policy)
        .unwrap_or_else(|| panic!("{policy} should classify"))
        .using_classification()
        .expect("every policy has USING")
}

/// Why the policy named `policy` is refused.
fn refusal<'p>(policies: &'p [ClassifiedPolicy], policy: &str) -> &'p str {
    let using = using_of(policies, policy);
    assert_eq!(using.confidence, ConfidenceLevel::D, "{policy}: {using:?}");
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &using.pattern else {
        panic!("{policy} should be refused: {using:?}");
    };
    reason
}

/// Under the declaration the raise is unreachable, so the local output is the local read,
/// the namespace output guarded by the local one is the namespace read, and testing the
/// local output for `NULL` tests the request omitting it.
#[test]
fn a_validated_pair_reads_as_the_reads_it_guards() {
    let policies = classified(pair(true), &schema(VALIDATOR, ""));
    for (wrapped, inline) in [
        ("local_wrapped", "local_inline"),
        ("namespace_wrapped", "namespace_inline"),
        ("absent_wrapped", "absent_inline"),
    ] {
        let wrapped_using = using_of(&policies, wrapped);
        assert_eq!(
            wrapped_using.confidence,
            ConfidenceLevel::A,
            "{wrapped}: {wrapped_using:?}"
        );
        assert_eq!(
            wrapped_using,
            using_of(&policies, inline),
            "{wrapped} reads as {inline}"
        );
    }
}

/// Without the declaration a request may set one half alone, where `PostgreSQL` raises
/// `22023` for the whole statement, so every clause reading an output is refused naming
/// the validator.
#[test]
fn a_pair_not_declared_set_together_is_refused_naming_the_validator() {
    let policies = classified(pair(false), &schema(VALIDATOR, ""));
    for policy in ["local_wrapped", "namespace_wrapped", "absent_wrapped"] {
        let reason = refusal(&policies, policy);
        assert!(
            reason.contains("selects what 'authz.acting_installation' returns"),
            "{policy}: {reason}"
        );
    }
}

/// A validator that never raises hands over the local read on every request, while the
/// namespace output still equals the namespace read only where the two are set together.
#[test]
fn a_guarded_output_needs_the_pair_set_together() {
    let assigned = VALIDATOR
        .split_once("\n  IF")
        .map(|(assignments, _)| assignments)
        .expect("the validator assigns before it tests");
    let policies = classified(pair(false), &schema(assigned, ""));
    assert_eq!(
        using_of(&policies, "local_wrapped"),
        using_of(&policies, "local_inline")
    );
    let reason = refusal(&policies, "namespace_wrapped");
    assert!(
        reason.contains(
            "returns 'app.installation_namespace_id' only where 'app.installation_id' is \
             carried, and the deployment does not declare the two set together"
        ),
        "{reason}"
    );
}

/// An accessor setting the local half itself hands the validator its own value rather
/// than the request's.
#[test]
fn an_accessor_setting_what_the_validator_reads_is_refused() {
    let policies = classified(
        pair(true),
        &schema(VALIDATOR, " SET app.installation_id = ''"),
    );
    let reason = refusal(&policies, "local_wrapped");
    assert!(
        reason
            .contains("sets 'app.installation_id' itself, which 'authz.acting_installation' reads"),
        "{reason}"
    );
}

/// A validator returning a set hands its `FROM` any number of rows, so an output is no
/// one value.
#[test]
fn a_set_returning_validator_is_not_read() {
    let policies = classified(
        pair(true),
        &schema(&format!("{VALIDATOR}\n  RETURN NEXT;"), "")
            .replace("RETURNS RECORD", "RETURNS SETOF RECORD"),
    );
    let reason = refusal(&policies, "local_wrapped");
    assert!(
        reason.contains("whose outputs are not read (`acting_installation` returns a set)"),
        "{reason}"
    );
}
