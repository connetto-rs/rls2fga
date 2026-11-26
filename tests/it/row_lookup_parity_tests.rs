//! A column compared with the namespace a definer accessor looks up, the caller's taking
//! precedence over the installation's, compared against `PostgreSQL`.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::support;
use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

const NAMESPACES: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE namespaces (
  id TEXT PRIMARY KEY,
  user_namespace_id TEXT,
  user_id TEXT,
  installation_namespace_id TEXT,
  installation_id TEXT,
  UNIQUE (user_namespace_id, user_id),
  UNIQUE (installation_namespace_id, installation_id)
);
CREATE TABLE objects (id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL REFERENCES namespaces (id));
GRANT SELECT ON namespaces TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')
$$;
CREATE FUNCTION authz.caller_namespace() RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT namespace.id FROM public.namespaces namespace
  WHERE ((SELECT authz.caller_id()) IS NOT NULL
    AND (namespace.user_namespace_id, namespace.user_id) = ('users', (SELECT authz.caller_id())))
    OR ((SELECT authz.caller_id()) IS NULL
      AND (namespace.installation_namespace_id, namespace.installation_id) =
        (NULLIF(current_setting('app.installation_namespace_id', true), ''),
         NULLIF(current_setting('app.installation_id', true), '')))
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.caller_namespace() OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY objects_insert ON objects FOR INSERT
  WITH CHECK (namespace_id = (SELECT authz.caller_namespace()));
";

/// A request acting as `subject`, for the caller `caller` and through the installation
/// `installation` of namespace `apps` where they are set.
fn acting(subject: &str, caller: Option<&str>, installation: &[(&str, &str)]) -> Principal {
    let mut principal = Principal::as_role(subject, "app_reader");
    if let Some(caller) = caller {
        principal
            .session
            .push(("app.user_id".into(), caller.into()));
    }
    for (setting, value) in installation {
        principal.session.push(((*setting).into(), (*value).into()));
    }
    principal
}

fn namespace_case(loading_from_rows: bool) -> ParityCase {
    let installation = [
        ("app.installation_namespace_id", "apps"),
        ("app.installation_id", "i1"),
    ];
    let mut case = ParityCase::reading(
        &format!(
            "row-lookup-namespace{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        NAMESPACES,
        &[
            "INSERT INTO namespaces VALUES
               ('n_alice', 'users', 'alice', NULL, NULL),
               ('n_bob', 'users', 'bob', NULL, NULL),
               ('n_other', 'others', 'alice', NULL, NULL),
               ('n_i1', NULL, NULL, 'apps', 'i1'),
               ('n_i2', NULL, NULL, 'apps', 'i2');
             INSERT INTO objects VALUES ('o_alice', 'n_alice'), ('o_bob', 'n_bob'),
               ('o_other', 'n_other'), ('o_i1', 'n_i1'), ('o_i2', 'n_i2')",
            "CREATE ROLE app_reader LOGIN;
             GRANT INSERT ON objects TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader",
        ],
        vec![
            acting("alice", Some("alice"), &[]),
            acting("alice_via_i1", Some("alice"), &installation).acting_for("alice"),
            acting("carol", Some("carol"), &installation),
            acting("i1", None, &installation),
            acting("i1_alone", None, &installation[1..]),
            acting("anonymous", None, &[]),
        ],
    )
    .with_settings([
        support::deployment::caller("app.user_id").may_be_unset(),
        support::deployment::scalar("app.installation_namespace_id").may_be_unset(),
        support::deployment::scalar("app.installation_id").may_be_unset(),
    ])
    .with_attribute_columns(&[("namespaces", "user_namespace_id")]);
    case.loading_from_rows = loading_from_rows;
    case
}

/// The caller inserts into its own namespace only, an installation request into the
/// installation's only where no caller is set, and a caller owning no namespace into none
/// even through an installation.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn a_caller_namespace_lookup_agrees_with_postgres() {
    let cluster = Cluster::start().await;
    for loading_from_rows in [false, true] {
        let case = namespace_case(loading_from_rows);
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
        for (subject, allowed) in [
            ("alice", "o_alice"),
            ("alice_via_i1", "o_alice"),
            ("carol", ""),
            ("i1", "o_i1"),
            ("i1_alone", ""),
            ("anonymous", ""),
        ] {
            for object in ["o_alice", "o_bob", "o_other", "o_i1", "o_i2"] {
                assert_postgres(
                    &case,
                    &run,
                    subject,
                    &format!("objects:{object}"),
                    ActionStatement::Insert,
                    object == allowed,
                );
            }
        }
        assert_agrees(&case, &run);
    }
}
