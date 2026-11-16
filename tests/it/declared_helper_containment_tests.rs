//! An array of the row's keys contained in the set a declared `SECURITY DEFINER` helper
//! returns is each key in that set.

use rls2fga::classifier::patterns::PatternClass;
use rls2fga::types::ConfidenceLevel;

use crate::declared_helper_tests::{model, refusal_of, using_of};

/// Folders owned by a caller, each under an optional parent folder.
pub(crate) const FOLDERS: &str = "
CREATE TABLE folders (id TEXT PRIMARY KEY, parent_id TEXT REFERENCES folders (id),
  owner_id TEXT NOT NULL, tags TEXT[]);
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
CREATE FUNCTION authz.owned_folders() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT f.id FROM public.folders f WHERE f.owner_id = current_setting('app.user_id', true)
$$;
ALTER FUNCTION authz.owned_folders() OWNER TO authz_owner;
GRANT USAGE ON SCHEMA authz TO authz_owner;
GRANT SELECT ON folders TO authz_owner;
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
";

pub(crate) const OWNED: &[&str] = &["authz.owned_folders"];

/// `FOLDERS` with one `SELECT` policy reading `using`.
fn reading(using: &str) -> String {
    format!("{FOLDERS}CREATE POLICY folders_read ON folders FOR SELECT USING ({using});")
}

#[test]
fn contained_row_keys_read_as_each_key_in_the_set() {
    let each = model(
        &reading(
            "id = ANY (ARRAY(SELECT authz.owned_folders())) \
             AND parent_id = ANY (ARRAY(SELECT authz.owned_folders()))",
        ),
        OWNED,
    );
    for containment in [
        "ARRAY[id, parent_id] <@ ARRAY(SELECT authz.owned_folders())",
        "ARRAY(SELECT authz.owned_folders()) @> ARRAY[id, parent_id]",
        "(ARRAY[folders.id, (parent_id)] <@ ARRAY( SELECT authz.owned_folders() AS owned_folders))",
    ] {
        assert_eq!(model(&reading(containment), OWNED), each, "{containment}");
    }
}

#[test]
fn a_repeated_key_reads_as_the_key_once() {
    let once = model(
        &reading("ARRAY[parent_id] <@ ARRAY(SELECT authz.owned_folders())"),
        OWNED,
    );
    assert_eq!(
        model(
            &reading("ARRAY[parent_id, parent_id] <@ ARRAY(SELECT authz.owned_folders())"),
            OWNED,
        ),
        once
    );
}

/// An element that is no key of the row, or an array the operator flattens, is refused
/// rather than compared with the set as a whole.
#[test]
fn an_element_other_than_a_scalar_column_is_refused() {
    for containment in [
        "ARRAY[id, lower(parent_id)] <@ ARRAY(SELECT authz.owned_folders())",
        "ARRAY[id, 'f1'] <@ ARRAY(SELECT authz.owned_folders())",
        "ARRAY[tags] <@ ARRAY(SELECT authz.owned_folders())",
        "ARRAY[ARRAY[id]] <@ ARRAY(SELECT authz.owned_folders())",
    ] {
        let reason = refusal_of(&reading(containment), OWNED, "folders_read");
        assert!(reason.contains("'<@'"), "{containment}: {reason}");
    }
}

/// A domain over an array is flattened by the operator as the array is.
#[test]
fn a_column_of_a_domain_over_an_array_is_refused() {
    let sql = format!(
        "CREATE DOMAIN tag_list AS TEXT[];{}",
        reading("ARRAY[id, tags] <@ ARRAY(SELECT authz.owned_folders())")
    )
    .replace("tags TEXT[]", "tags tag_list");
    let reason = refusal_of(&sql, OWNED, "folders_read");
    assert!(reason.contains("'<@'"), "{reason}");
}

/// Only a set built from a subquery is read, so containment in any other array keeps
/// its refusal.
#[test]
fn a_set_not_built_from_a_subquery_is_refused() {
    let reason = refusal_of(
        &reading("ARRAY[id, parent_id] <@ string_to_array('f1,f2', ',')"),
        OWNED,
        "folders_read",
    );
    assert!(reason.contains("'<@'"), "{reason}");
}

/// `NOT` turns the `false` a `NULL` key makes into `true`, which no conjunction of
/// memberships answers.
#[test]
fn a_negated_containment_is_refused() {
    let classified = using_of(
        &reading("NOT (ARRAY[id, parent_id] <@ ARRAY(SELECT authz.owned_folders()))"),
        OWNED,
        "folders_read",
    );
    assert!(
        matches!(classified.pattern, PatternClass::Unknown(_)),
        "{classified:?}"
    );
    assert_eq!(classified.confidence, ConfidenceLevel::D);
}
