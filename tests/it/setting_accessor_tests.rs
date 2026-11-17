//! A zero-argument `LANGUAGE sql` accessor whose body returns a declared setting read
//! through `NULLIF(<read>, '')`, or `lower` of that read, reads as that expression
//! written inline.

use core::fmt::Write as _;

use rls2fga::classifier::patterns::{
    ClassifiedExpr, ClassifiedPolicy, PatternClass, UnclassifiedExpr,
};
use rls2fga::parser::sql_parser::SessionSetting;
use rls2fga::translator::{Translator, TranslatorBuilder};
use rls2fga::types::{ConfidenceLevel, RequestNormalization, TranslationNote};
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

/// An accessor returning the verified email as `lower` makes of it, and one returning
/// `upper` of it, which no reader reads.
const LOWERED: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE invitations (id UUID PRIMARY KEY, email TEXT NOT NULL CHECK (email = lower(email)));
CREATE FUNCTION authz.verified_email() RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = '' AS $$ SELECT lower(NULLIF(current_setting('app.verified_email', true), '')) $$;
CREATE FUNCTION authz.shouted_email() RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = '' AS $$ SELECT upper(NULLIF(current_setting('app.verified_email', true), '')) $$;
ALTER FUNCTION authz.verified_email() OWNER TO authz_owner;
ALTER FUNCTION authz.shouted_email() OWNER TO authz_owner;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
";

/// [`LOWERED`] with one policy on `invitations` per `(name, USING)` pair.
fn lowered_schema(policies: &[(&str, &str)]) -> String {
    policies
        .iter()
        .fold(LOWERED.to_string(), |mut schema, (name, using)| {
            writeln!(
                schema,
                "CREATE POLICY {name} ON invitations USING ({using});"
            )
            .expect("writing to a String cannot fail");
            schema
        })
}

/// The verified email, as text a request may leave unset or one every request sets.
fn email_translator(may_be_unset: bool) -> Translator {
    let email = typed_scalar("app.verified_email", DataType::Text);
    TranslatorBuilder::new(deployment([if may_be_unset {
        email.may_be_unset()
    } else {
        email
    }]))
    .with_min_confidence(ConfidenceLevel::A)
    .build()
}

/// The lowered read [`LOWERED`]'s accessor returns, written inline.
const INLINE_LOWERED: &str =
    "email = lower(NULLIF(current_setting('app.verified_email', true), ''))";

/// A call to an accessor returning `lower` of the wrapped read is that lowered read, bare
/// and inside a scalar subquery, so it grades A on the lowered value's own key as the
/// inline spelling does and translates to the same model and caller contract.
#[test]
fn an_accessor_returning_a_lowered_read_reads_as_the_lowered_read() {
    let translator = email_translator(true);
    let policies = classified(
        &translator,
        &lowered_schema(&[
            ("email_inline", INLINE_LOWERED),
            ("email_subquery", "email = (SELECT authz.verified_email())"),
            ("email_call", "authz.verified_email() = email"),
        ]),
    );
    let inline = using_of(&policies, "email_inline");
    assert_eq!(inline.confidence, ConfidenceLevel::A, "{inline:?}");
    let PatternClass::P15RowValueEqualsCallerScalar(compared) = &inline.pattern else {
        panic!("the inline read compares the row's email: {inline:?}");
    };
    assert_eq!(
        compared.source.normalization(),
        Some(RequestNormalization::Lower)
    );
    for wrapped in ["email_subquery", "email_call"] {
        assert_eq!(using_of(&policies, wrapped), inline, "{wrapped}");
    }

    let translated = |using: &str| {
        let translation = translator
            .translate(&db_of(&lowered_schema(&[("email_read", using)])))
            .expect("the schema should plan");
        let outputs = translation.outputs().expect("the clause should translate");
        (outputs.model().clone(), outputs.notes().to_vec())
    };
    let (model, notes) = translated(INLINE_LOWERED);
    assert!(
        notes.iter().any(|note| matches!(
            note,
            TranslationNote::CallerSuppliesConditionParameter {
                parameter,
                normalization: Some(RequestNormalization::Lower),
                ..
            } if parameter.as_str() == "app_verified_email_lower"
        )),
        "{notes:?}"
    );
    assert_eq!(
        translated("email = (SELECT authz.verified_email())"),
        (model, notes)
    );
}

/// A value every request sets may be `''`, which the accessor's `NULLIF` hides before
/// `lower` runs, so the call is refused naming why, and `lower` of the call lowers a
/// value the caller already sends lowered, which no reader reads, as inline.
#[test]
fn a_lowered_accessor_the_caller_cannot_send_is_refused() {
    let policies = classified(
        &email_translator(false),
        &lowered_schema(&[("email_call", "email = (SELECT authz.verified_email())")]),
    );
    let using = using_of(&policies, "email_call");
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) = &using.pattern else {
        panic!("the call should be refused: {using:?}");
    };
    assert!(
        reason.contains("Setting 'app.verified_email' is declared set by every request"),
        "{reason}"
    );

    let policies = classified(
        &email_translator(true),
        &lowered_schema(&[("email_relowered", "email = lower(authz.verified_email())")]),
    );
    let using = using_of(&policies, "email_relowered");
    assert!(
        matches!(using.pattern, PatternClass::Unknown(_)),
        "{using:?}"
    );
}

/// A body applying a function no reader reads changes the value the request carries, so
/// it stays a body no reader reads.
#[test]
fn an_accessor_applying_another_function_stays_unread() {
    let policies = classified(
        &email_translator(true),
        &lowered_schema(&[("email_shouted", "email = (SELECT authz.shouted_email())")]),
    );
    let PatternClass::Unknown(UnclassifiedExpr { reason, .. }) =
        &using_of(&policies, "email_shouted").pattern
    else {
        panic!("the accessor should stay unread");
    };
    assert!(
        reason.contains("The body of 'authz.shouted_email'"),
        "{reason}"
    );
}
