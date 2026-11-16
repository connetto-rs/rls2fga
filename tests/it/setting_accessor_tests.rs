//! A zero-argument `LANGUAGE sql` accessor whose body returns a declared setting read
//! through `NULLIF(<read>, '')` reads as that expression written inline.

use rls2fga::classifier::patterns::{
    ClassifiedExpr, ClassifiedPolicy, PatternClass, UnclassifiedExpr,
};
use rls2fga::parser::sql_parser::SessionSetting;
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{ConfidenceLevel, TranslationNote};
use sqlparser::ast::DataType;

use crate::support::deployment::{deployment, typed_caller, typed_scalar};
use crate::support::footgun::db_of;

/// Two `SECURITY DEFINER` accessors reading a caller and an installation through
/// `NULLIF`, each compared by one policy through the accessor and one written inline.
const ACCESSORS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE objects (id UUID PRIMARY KEY, owner_id UUID NOT NULL, installation_id UUID NOT NULL);
CREATE FUNCTION authz.caller_id() RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = '' AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$;
CREATE FUNCTION authz.installation() RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = '' AS $$ SELECT NULLIF(current_setting('app.installation_id', true), '')::uuid $$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.installation() OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY caller_wrapped ON objects USING (owner_id = (SELECT authz.caller_id()));
CREATE POLICY caller_inline ON objects
  USING (owner_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
CREATE POLICY installation_wrapped ON objects
  USING (installation_id = (SELECT authz.installation()));
CREATE POLICY installation_inline ON objects
  USING (installation_id = NULLIF(current_setting('app.installation_id', true), '')::uuid);
CREATE POLICY installation_absent_wrapped ON objects
  USING ((SELECT authz.installation()) IS NULL);
CREATE POLICY installation_absent_inline ON objects
  USING (NULLIF(current_setting('app.installation_id', true), '')::uuid IS NULL);
";

/// The caller and the installation, each a `uuid` a request may leave unset or one every
/// request sets.
fn translator(may_be_unset: bool) -> Translator {
    let presence = |setting: SessionSetting| {
        if may_be_unset {
            setting.may_be_unset()
        } else {
            setting
        }
    };
    TranslatorBuilder::new(deployment([
        presence(typed_caller("app.user_id", DataType::Uuid)),
        presence(typed_scalar("app.installation_id", DataType::Uuid)),
    ]))
    .with_min_confidence(ConfidenceLevel::B)
    .build()
}

/// The policies `schema` classifies into.
fn classified(translator: &Translator, schema: &str) -> Vec<ClassifiedPolicy> {
    translator.classify(&db_of(schema))
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

/// The accessor and the inline read are one read, so each pair grades A alike and lands
/// on one pattern, the caller as ownership, the installation as a request value, and its
/// absence test as the request omitting the key.
#[test]
fn an_accessor_reads_as_the_nullif_read_it_returns() {
    let policies = classified(&translator(true), ACCESSORS);
    for (wrapped, inline) in [
        ("caller_wrapped", "caller_inline"),
        ("installation_wrapped", "installation_inline"),
        ("installation_absent_wrapped", "installation_absent_inline"),
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
    assert!(
        matches!(
            using_of(&policies, "caller_wrapped").pattern,
            PatternClass::P3DirectOwnership(_)
        ),
        "the caller compared with the owner is ownership"
    );
    assert!(
        matches!(
            using_of(&policies, "installation_absent_wrapped").pattern,
            PatternClass::P28RequestValueAbsent(_)
        ),
        "testing the accessor for NULL tests the request omitting the installation"
    );
}

/// `NULLIF` reads the `''` reading of an unset setting as `NULL`, so no comparison
/// through the accessor is named as one the `''` reading makes true.
#[test]
fn an_accessor_through_nullif_has_no_empty_reading() {
    let translation = translator(true)
        .translate(&db_of(ACCESSORS))
        .expect("the schema should plan");
    let named: Vec<&TranslationNote> = translation
        .notes()
        .iter()
        .filter(|note| matches!(note, TranslationNote::UnsetSettingReadAsEmpty { .. }))
        .collect();
    assert!(named.is_empty(), "{named:?}");
}

/// A value every request sets may be `''`, a caller the tuples spell `user:~` among
/// them, and the accessor's `NULLIF` would hide it, so a comparison through it is refused
/// as the inline one is, and so is its absence test, each naming why.
#[test]
fn an_accessor_hiding_a_value_every_request_sets_is_refused() {
    let policies = classified(&translator(false), ACCESSORS);
    for (policy, setting) in [
        ("caller_wrapped", "app.user_id"),
        ("caller_inline", "app.user_id"),
        ("installation_wrapped", "app.installation_id"),
        ("installation_inline", "app.installation_id"),
        ("installation_absent_wrapped", "app.installation_id"),
    ] {
        let using = using_of(&policies, policy);
        assert_eq!(using.confidence, ConfidenceLevel::D, "{policy}: {using:?}");
        let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &using.pattern else {
            panic!("{policy} should be refused");
        };
        assert!(
            reason.contains(&format!(
                "Setting '{setting}' is declared set by every request"
            )),
            "{policy}: {reason}"
        );
    }
}

/// A body wrapping the read in `NULLIF` against another value than `''` changes the
/// value the request carries, so it stays a body no reader reads.
#[test]
fn an_accessor_against_another_sentinel_stays_unread() {
    let schema = ACCESSORS.replace(
        "NULLIF(current_setting('app.user_id', true), '')::uuid $$",
        "NULLIF(current_setting('app.user_id', true), 'none')::uuid $$",
    );
    let policies = classified(&translator(true), &schema);
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) =
        &using_of(&policies, "caller_wrapped").pattern
    else {
        panic!("the accessor should stay unread");
    };
    assert!(reason.contains("The body of 'authz.caller_id'"), "{reason}");
}
