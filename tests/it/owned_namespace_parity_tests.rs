//! A column compared with the namespace a definer accessor unites from one lookup per
//! owner table, the user's keyed by the caller and the installation's by the pair of
//! identifiers the request sets together, compared against `PostgreSQL`.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::support;
use crate::support::parity::{assert_agrees, assert_postgres, Cluster, ParityCase, Principal};

const OWNED_NAMESPACES: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE namespaces (id TEXT PRIMARY KEY);
CREATE TABLE users (
  namespace_id TEXT NOT NULL REFERENCES namespaces (id),
  id TEXT NOT NULL,
  owned_namespace_id TEXT NOT NULL UNIQUE REFERENCES namespaces (id),
  PRIMARY KEY (namespace_id, id)
);
CREATE TABLE app_installations (
  namespace_id TEXT NOT NULL REFERENCES namespaces (id),
  id TEXT NOT NULL,
  owned_namespace_id TEXT NOT NULL UNIQUE REFERENCES namespaces (id),
  PRIMARY KEY (namespace_id, id)
);
CREATE TABLE objects (id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL REFERENCES namespaces (id));
GRANT SELECT ON namespaces, users, app_installations TO authz_owner;
CREATE FUNCTION authz.caller_id() RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NULLIF(current_setting('app.user_id', true), '')
$$;
CREATE FUNCTION authz.acting_installation(OUT namespace_id TEXT, OUT id TEXT) RETURNS RECORD
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  namespace_id := NULLIF(current_setting('app.installation_namespace_id', true), '');
  id := NULLIF(current_setting('app.installation_id', true), '');
  IF (namespace_id IS NULL) <> (id IS NULL) THEN
    RAISE EXCEPTION 'incomplete installation identity' USING ERRCODE = '22023';
  END IF;
END
$$;
CREATE FUNCTION authz.acting_installation_id() RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT id FROM authz.acting_installation()
$$;
CREATE FUNCTION authz.acting_installation_namespace_id() RETURNS TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN id IS NOT NULL THEN namespace_id END FROM authz.acting_installation()
$$;
CREATE FUNCTION authz.caller_namespace() RETURNS SETOF TEXT
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT u.owned_namespace_id FROM public.users u
  WHERE u.namespace_id = 'users' AND u.id = (SELECT authz.caller_id())
  UNION ALL
  SELECT i.owned_namespace_id FROM public.app_installations i
  WHERE i.namespace_id = (SELECT authz.acting_installation_namespace_id())
    AND i.id = (SELECT authz.acting_installation_id())
    AND (SELECT authz.caller_id()) IS NULL
$$;
ALTER FUNCTION authz.caller_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_id() OWNER TO authz_owner;
ALTER FUNCTION authz.acting_installation_namespace_id() OWNER TO authz_owner;
ALTER FUNCTION authz.caller_namespace() OWNER TO authz_owner;
ALTER TABLE objects ENABLE ROW LEVEL SECURITY;
CREATE POLICY objects_insert ON objects FOR INSERT
  WITH CHECK (namespace_id = (SELECT authz.caller_namespace()));
";

/// A request acting as `subject`, for the caller `caller` where it is set, through the
/// installation `installation` names.
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

/// The installation `id` of the namespace `namespace`.
fn installation<'a>(namespace: &'a str, id: &'a str) -> [(&'a str, &'a str); 2] {
    [
        ("app.installation_namespace_id", namespace),
        ("app.installation_id", id),
    ]
}

fn owned_case(loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "owned-namespace{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        OWNED_NAMESPACES,
        &[
            "INSERT INTO namespaces VALUES ('users'), ('others'), ('apps'),
               ('n_alice'), ('n_bob'), ('n_other'), ('n_i1'), ('n_i2');
             INSERT INTO users VALUES ('users', 'alice', 'n_alice'), ('users', 'bob', 'n_bob'),
               ('others', 'alice', 'n_other');
             INSERT INTO app_installations VALUES ('apps', 'i1', 'n_i1'), ('apps', 'i2', 'n_i2');
             INSERT INTO objects VALUES ('o_alice', 'n_alice'), ('o_bob', 'n_bob'),
               ('o_other', 'n_other'), ('o_i1', 'n_i1'), ('o_i2', 'n_i2')",
            "CREATE ROLE app_reader LOGIN;
             GRANT INSERT ON objects TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader",
        ],
        vec![
            acting("alice", Some("alice"), &[]),
            acting("alice_via_i1", Some("alice"), &installation("apps", "i1")).acting_for("alice"),
            acting("carol", Some("carol"), &installation("apps", "i1")),
            acting("i1", None, &installation("apps", "i1")),
            acting("i1_elsewhere", None, &installation("others", "i1")),
            acting("anonymous", None, &[]),
        ],
    )
    .with_settings([
        support::deployment::caller("app.user_id").may_be_unset(),
        support::deployment::scalar("app.installation_namespace_id").may_be_unset(),
        support::deployment::scalar("app.installation_id").may_be_unset(),
    ])
    .with_settings_set_together(&["app.installation_namespace_id", "app.installation_id"]);
    case.loading_from_rows = loading_from_rows;
    case
}

/// The caller inserts into the namespace it owns only, an installation request into the
/// one its pair owns only where no caller is set, and a caller owning no namespace into
/// none even through an installation.
#[tokio::test]
#[ignore = "requires Docker, postgres:18, and openfga/openfga containers"]
async fn an_owned_namespace_lookup_agrees_with_postgres() {
    let cluster = Cluster::start().await;
    for loading_from_rows in [false, true] {
        let case = owned_case(loading_from_rows);
        let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
        for (subject, allowed) in [
            ("alice", "o_alice"),
            ("alice_via_i1", "o_alice"),
            ("carol", ""),
            ("i1", "o_i1"),
            ("i1_elsewhere", ""),
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
