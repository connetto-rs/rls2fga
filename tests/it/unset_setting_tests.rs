//! A setting a request may leave unset, read in both of `PostgreSQL`'s unset states.
//!
//! `current_setting(name, true)` reads `NULL` on a connection that never set the setting
//! and `''` once a transaction that set it locally has ended. A request leaving the
//! setting unset sends no value, so the model admits what the `NULL` reading admits, and
//! the translation names every comparison the `''` reading makes true.

use rls2fga::parser::sql_parser::SessionSetting;
use rls2fga::types::TranslationNote;

use crate::support::deployment::{caller, db, delimited_set, deployment, scalar};

/// Three tables, one per kind of read, the caller compared with a row value, a scalar
/// compared with a row value, and a negated membership in a delimited set.
const SCHEMA: &str = "
CREATE TABLE owned_docs (id TEXT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE tiered_docs (id TEXT PRIMARY KEY, tier TEXT NOT NULL);
CREATE TABLE open_docs (id TEXT PRIMARY KEY, owner TEXT NOT NULL);
ALTER TABLE owned_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tiered_docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY owned ON owned_docs FOR SELECT
    USING (owner = current_setting('app.user_id', true));
CREATE POLICY tiered ON tiered_docs FOR SELECT
    USING (tier = current_setting('app.tier', true));
CREATE POLICY unblocked ON open_docs FOR SELECT
    USING (NOT (owner = ANY (string_to_array(current_setting('app.blocked', true), ','))));
";

/// One scalar setting read as one value compared with literal lists, one policy per way
/// the `''` reading passes them, the `IN` and `= ANY (ARRAY[...])` spellings together,
/// and one list a non-literal element leaves undecided.
const LIST_SCHEMA: &str = "
CREATE TABLE listed_docs (id TEXT PRIMARY KEY, tier TEXT NOT NULL);
ALTER TABLE listed_docs ENABLE ROW LEVEL SECURITY;
CREATE POLICY in_empty ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) IN ('', 'gold'));
CREATE POLICY in_gold ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) IN ('gold', 'silver'));
CREATE POLICY not_in_gold ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) NOT IN ('gold', 'silver'));
CREATE POLICY not_in_empty ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) NOT IN ('', 'gold'));
CREATE POLICY any_empty ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) = ANY (ARRAY['', 'gold']));
CREATE POLICY any_gold ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) = ANY (ARRAY['gold', 'silver']));
CREATE POLICY in_column ON listed_docs FOR SELECT
    USING (current_setting('app.tier', true) IN ('gold', tier));
";

/// The deployment's three settings, each a request may leave unset or not.
fn settings(may_be_unset: bool) -> Vec<SessionSetting> {
    let presence = |setting: SessionSetting| {
        if may_be_unset {
            setting.may_be_unset()
        } else {
            setting
        }
    };
    vec![
        presence(caller("app.user_id")),
        presence(scalar("app.tier")),
        presence(delimited_set("app.blocked", ",")),
    ]
}

/// The comparisons the translation names as made true by the empty reading, by policy.
fn named_reads(schema: &str, may_be_unset: bool) -> Vec<(String, String)> {
    let translation =
        rls2fga::translator::TranslatorBuilder::new(deployment(settings(may_be_unset)))
            .build()
            .translate(&db(schema))
            .expect("the schema translates");
    translation
        .notes()
        .iter()
        .filter_map(|note| match note {
            TranslationNote::UnsetSettingReadAsEmpty {
                policy, setting, ..
            } => Some((policy.clone(), setting.clone())),
            _ => None,
        })
        .collect()
}

fn empty_readings(may_be_unset: bool) -> Vec<(String, String)> {
    named_reads(SCHEMA, may_be_unset)
}

fn list_readings(may_be_unset: bool) -> Vec<(String, String)> {
    named_reads(LIST_SCHEMA, may_be_unset)
}

/// Every read whose empty reading admits rows is named, each with its setting.
#[test]
fn every_read_an_empty_setting_admits_through_is_named() {
    let mut named = empty_readings(true);
    named.sort();
    assert_eq!(
        named,
        [
            ("owned".to_string(), "app.user_id".to_string()),
            ("tiered".to_string(), "app.tier".to_string()),
            ("unblocked".to_string(), "app.blocked".to_string()),
        ]
    );
}

/// A setting every request sets has no unset state, so nothing is named.
#[test]
fn a_setting_every_request_sets_names_nothing() {
    assert_eq!(empty_readings(false), Vec::<(String, String)>::new());
}

/// A list the `''` reading passes, and a negated list it passes, each earns a note, and
/// the list it fails, and the one a non-literal element leaves undecided, earn none.
#[test]
fn a_list_the_empty_reading_passes_is_named() {
    let mut named = list_readings(true);
    named.sort();
    assert_eq!(
        named,
        [
            ("any_empty".to_string(), "app.tier".to_string()),
            ("in_empty".to_string(), "app.tier".to_string()),
            ("not_in_gold".to_string(), "app.tier".to_string()),
        ]
    );
}

/// With no unset state there is no `''` reading, so a list the `''` reading would pass
/// names nothing either.
#[test]
fn a_list_the_empty_reading_passes_names_nothing_when_set_always() {
    assert_eq!(list_readings(false), Vec::<(String, String)>::new());
}

#[cfg(feature = "client")]
mod live {
    use diesel::connection::SimpleConnection;
    use diesel::pg::PgConnection;
    use diesel::prelude::*;

    use crate::support;
    use crate::support::containers::{PG_DB, PG_PASSWORD, PG_USER};

    diesel::table! {
        owned_docs (id) {
            id -> Text,
            owner -> Text,
        }
    }

    diesel::table! {
        tiered_docs (id) {
            id -> Text,
            tier -> Text,
        }
    }

    diesel::table! {
        open_docs (id) {
            id -> Text,
            owner -> Text,
        }
    }

    diesel::define_sql_function! {
        /// `PostgreSQL`'s `set_config(setting_name, new_value, is_local)`.
        fn set_config(
            setting: diesel::sql_types::Text,
            value: diesel::sql_types::Text,
            is_local: diesel::sql_types::Bool,
        ) -> diesel::sql_types::Text;
    }

    /// The rows each table shows the acting role, in one transaction that sets nothing.
    fn visible(conn: &mut PgConnection) -> [Vec<String>; 3] {
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            conn.batch_execute("SET LOCAL ROLE app_user")?;
            Ok([
                owned_docs::table
                    .select(owned_docs::id)
                    .order(owned_docs::id)
                    .load(conn)?,
                tiered_docs::table
                    .select(tiered_docs::id)
                    .order(tiered_docs::id)
                    .load(conn)?,
                open_docs::table
                    .select(open_docs::id)
                    .order(open_docs::id)
                    .load(conn)?,
            ])
        })
        .expect("the reads run")
    }

    /// On `PostgreSQL` 18 the `NULL` reading admits nothing, and the `''` reading admits
    /// the rows holding `''` and every row a negated empty set passes.
    #[tokio::test]
    #[ignore = "requires Docker: starts a PostgreSQL 18 container"]
    async fn the_empty_reading_admits_what_the_null_reading_hides() {
        let container = support::containers::start_postgres().await;
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://{PG_USER}:{PG_PASSWORD}@127.0.0.1:{port}/{PG_DB}");
        let mut conn = support::containers::connect_postgres_with_retry(&url);
        conn.batch_execute(&format!(
            "{}{}
             GRANT SELECT ON owned_docs, tiered_docs, open_docs TO app_user;",
            support::deployment::ROLES,
            super::SCHEMA
        ))
        .expect("the schema applies");
        diesel::insert_into(owned_docs::table)
            .values([
                (owned_docs::id.eq("d1"), owned_docs::owner.eq("alice")),
                (owned_docs::id.eq("d2"), owned_docs::owner.eq("")),
            ])
            .execute(&mut conn)
            .expect("owned rows insert");
        diesel::insert_into(tiered_docs::table)
            .values([
                (tiered_docs::id.eq("t1"), tiered_docs::tier.eq("gold")),
                (tiered_docs::id.eq("t2"), tiered_docs::tier.eq("")),
            ])
            .execute(&mut conn)
            .expect("tiered rows insert");
        diesel::insert_into(open_docs::table)
            .values([
                (open_docs::id.eq("o1"), open_docs::owner.eq("alice")),
                (open_docs::id.eq("o2"), open_docs::owner.eq("bob")),
            ])
            .execute(&mut conn)
            .expect("open rows insert");

        let none: [Vec<String>; 3] = [vec![], vec![], vec![]];
        assert_eq!(visible(&mut conn), none, "a fresh connection reads NULL");

        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            for setting in ["app.user_id", "app.tier", "app.blocked"] {
                diesel::select(set_config(setting, "set", true)).execute(conn)?;
            }
            Ok(())
        })
        .expect("a transaction sets each setting locally");
        assert_eq!(
            visible(&mut conn),
            [
                vec!["d2".to_string()],
                vec!["t2".to_string()],
                vec!["o1".to_string(), "o2".to_string()],
            ],
            "once the transaction ended every setting reads ''"
        );
    }
}
