//! Checks on the row a write produces, compared against `PostgreSQL` 17 and 18.
//!
//! A `WITH CHECK` clause reads the new row's own columns, while a helper it calls reads the
//! statement's snapshot, which never holds the row being written. Each case pins one shape
//! where the two differ.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use rls2fga::types::ActionStatement;

use crate::support;
use crate::support::parity::{
    assert_agrees, assert_postgres, ClauseKind, Cluster, ParityCase, Principal, Side,
};

/// The reason an `UPDATE` policy's `USING` that repeats the `SELECT` policy's can never be
/// the clause denying a compared answer.
const REPEATS_SELECT: &str = "repeats the SELECT policy's USING, which every UPDATE applies";

/// Teams whose members add members and move notes between teams, both checked through a
/// helper reading the membership table.
const TEAMS: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE teams (id TEXT PRIMARY KEY);
CREATE TABLE team_members (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams (id),
  user_id TEXT NOT NULL);
CREATE TABLE notes (id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams (id),
  body TEXT NOT NULL);
GRANT SELECT ON team_members TO authz_owner;
CREATE FUNCTION authz.is_member(team TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.team_members member
                 WHERE member.team_id = team
                   AND member.user_id = current_setting('app.user_id', true))
$$;
ALTER FUNCTION authz.is_member(TEXT) OWNER TO authz_owner;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY team_members_select ON team_members FOR SELECT USING (authz.is_member(team_id));
CREATE POLICY team_members_insert ON team_members FOR INSERT
  WITH CHECK (authz.is_member(team_id));
CREATE POLICY notes_select ON notes FOR SELECT USING (authz.is_member(team_id));
CREATE POLICY notes_update ON notes FOR UPDATE USING (authz.is_member(team_id))
  WITH CHECK (authz.is_member(team_id));
";

/// Resources their owner adds and changes unless already archived, the archive read through
/// a helper that looks the row's own table up by its key.
const ARCHIVE: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE resources (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, archived_at TIMESTAMPTZ,
  label TEXT NOT NULL);
GRANT SELECT ON resources TO authz_owner;
CREATE FUNCTION authz.is_archived(resource TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.resources archived
                 WHERE archived.id = resource AND archived.archived_at IS NOT NULL)
$$;
ALTER FUNCTION authz.is_archived(TEXT) OWNER TO authz_owner;
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
CREATE POLICY resources_select ON resources FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY resources_insert ON resources FOR INSERT
  WITH CHECK (owner_id = current_setting('app.user_id', true) AND NOT authz.is_archived(id));
CREATE POLICY resources_update ON resources FOR UPDATE
  USING (owner_id = current_setting('app.user_id', true))
  WITH CHECK (NOT authz.is_archived(id));
";

const READER: &str = "CREATE ROLE app_reader LOGIN;
     GRANT USAGE ON SCHEMA authz TO app_reader;
     REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
     GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader";

fn caller(subject: &str) -> Principal {
    Principal::with_setting(subject, "app_reader", "app.user_id", subject)
}

/// Alice belongs to `t1`, Bob to both teams, and Dave to none. Every member probe adds
/// Dave, so a row that names its own inserter never vouches for itself, and every note
/// update moves the note to `t2`.
fn teams_case(major: &str) -> ParityCase {
    ParityCase::reading(
        &format!("resulting-row-teams-pg{major}"),
        TEAMS,
        &[
            "INSERT INTO teams VALUES ('t1'), ('t2');
             INSERT INTO team_members VALUES
               ('m1', 't1', 'alice'), ('m2', 't2', 'bob'), ('m3', 't1', 'bob');
             INSERT INTO notes VALUES ('n1', 't1', 'x'), ('n2', 't2', 'y')",
            &format!(
                "{READER};
                 GRANT SELECT, INSERT ON team_members TO app_reader;
                 GRANT SELECT, UPDATE ON notes TO app_reader"
            ),
        ],
        vec![caller("alice"), caller("bob"), caller("dave")],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .inserting_values("team_members", &[("user_id", "dave")])
    .updating("notes", "team_id = 't2'")
    .unobservable(
        "notes",
        "notes_update",
        ClauseKind::Using,
        Side::Denies,
        REPEATS_SELECT,
    )
    .unobservable(
        "notes",
        "notes_update",
        ClauseKind::Check,
        Side::Denies,
        "repeats the SELECT policy's USING, which PostgreSQL also checks on the new row of an \
         UPDATE naming its rows",
    )
}

/// Alice owns the open `open` and the archived `shut`, and every update unarchives.
fn archive_case(major: &str) -> ParityCase {
    ParityCase::reading(
        &format!("resulting-row-archive-pg{major}"),
        ARCHIVE,
        &[
            "INSERT INTO resources VALUES
               ('open', 'alice', NULL, 'o'), ('shut', 'alice', now(), 's')",
            &format!("{READER};\n GRANT SELECT, INSERT, UPDATE ON resources TO app_reader"),
        ],
        vec![caller("alice"), caller("bob")],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .updating("resources", "archived_at = NULL")
    .unobservable(
        "resources",
        "resources_update",
        ClauseKind::Using,
        Side::Denies,
        REPEATS_SELECT,
    )
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_written_row_is_judged_where_it_lands_and_never_vouches_for_itself_on_postgres_17_and_18()
{
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        let case = teams_case(major);
        let run = support::parity::run(&cluster, &case).await;
        let expect = |subject: &str, object: &str, statement, allowed| {
            assert_postgres(&case, &run, subject, object, statement, allowed);
        };
        // The new member row names Dave, and the helper never sees it.
        expect("dave", "team_members:m1", ActionStatement::Insert, false);
        expect("alice", "team_members:m1", ActionStatement::Insert, true);
        expect("alice", "team_members:m2", ActionStatement::Insert, false);
        // Alice may change `n1` where it is, and not move it to a team she is not in.
        expect("alice", "notes:n1", ActionStatement::Update, false);
        expect("bob", "notes:n1", ActionStatement::Update, true);
        assert_agrees(&case, &run);
    }
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_check_looking_up_its_own_key_reads_the_stored_row_on_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        let case = archive_case(major);
        let run = support::parity::run(&cluster, &case).await;
        let expect = |subject: &str, object: &str, statement, allowed| {
            assert_postgres(&case, &run, subject, object, statement, allowed);
        };
        // A fresh key is no stored row, so copying an archived row is no archived row.
        expect("alice", "resources:shut", ActionStatement::Insert, true);
        // Unarchiving still reads the stored row, which is archived.
        expect("alice", "resources:shut", ActionStatement::Update, false);
        expect("alice", "resources:open", ActionStatement::Update, true);
        assert_agrees(&case, &run);
    }
}

/// A direct check keeps reading the new row where a helper reads the same flag of the
/// stored row, though both compile to one gate.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_shared_gate_keeps_direct_reads_on_the_written_row_on_postgres_17_and_18() {
    let schema = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE t (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, locked BOOLEAN NOT NULL);
GRANT SELECT ON t TO authz_owner;
CREATE FUNCTION authz.is_locked(target TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.t locked WHERE locked.id = target AND locked.locked = true)
$$;
ALTER FUNCTION authz.is_locked(TEXT) OWNER TO authz_owner;
ALTER TABLE t ENABLE ROW LEVEL SECURITY;
CREATE POLICY t_select ON t FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY t_insert ON t FOR INSERT
  WITH CHECK (owner_id = current_setting('app.user_id', true) AND locked = true);
CREATE POLICY t_update ON t FOR UPDATE
  USING (owner_id = current_setting('app.user_id', true))
  WITH CHECK (NOT authz.is_locked(id));
";
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        let case = ParityCase::reading(
            &format!("resulting-row-shared-gate-pg{major}"),
            schema,
            &[
                "INSERT INTO t VALUES ('open', 'alice', false), ('shut', 'alice', true)",
                &format!("{READER}; GRANT SELECT, INSERT, UPDATE ON t TO app_reader"),
            ],
            vec![caller("alice"), caller("bob")],
        )
        .with_settings([support::deployment::caller("app.user_id")])
        .updating("t", "locked = false")
        .unobservable(
            "t",
            "t_update",
            ClauseKind::Using,
            Side::Denies,
            REPEATS_SELECT,
        );
        let run = support::parity::run(&cluster, &case).await;
        // The new row states the flag, and a fresh key has no stored row to read it from.
        assert_postgres(
            &case,
            &run,
            "alice",
            "t:shut",
            ActionStatement::Insert,
            true,
        );
        assert_postgres(
            &case,
            &run,
            "alice",
            "t:open",
            ActionStatement::Insert,
            false,
        );
        // Unlocking reads the stored row through the helper, which is still locked.
        assert_postgres(
            &case,
            &run,
            "alice",
            "t:shut",
            ActionStatement::Update,
            false,
        );
        assert_postgres(
            &case,
            &run,
            "alice",
            "t:open",
            ActionStatement::Update,
            true,
        );
        assert_agrees(&case, &run);
    }
}

/// A check requiring a query refuses both changed and unchanged resulting values.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn an_unreadable_written_fact_denies_updates_on_postgres_17_and_18() {
    use crate::resulting_type_tests::UNREADABLE_METADATA;
    use crate::support::parity::{assert_disclosed_where_noted, Direction, Licence};

    let translation = support::deployment::translator_builder()
        .with_min_confidence(rls2fga::types::ConfidenceLevel::B)
        .build()
        .translate(&support::deployment::db(UNREADABLE_METADATA))
        .unwrap();
    let resulting = translation.resulting_rows().first().unwrap();
    assert!(translation.notes().iter().any(|note| matches!(
        note,
        rls2fga::types::TranslationNote::ResultingRowFactUnreadable { table, .. }
            if table == &resulting.table
    )));

    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        // One update clears the document of `cleared` and keeps the one of `kept`, so the
        // check both refuses and admits a written row.
        let case = ParityCase::reading(
            &format!("resulting-row-metadata-pg{major}"),
            UNREADABLE_METADATA,
            &[
                "INSERT INTO docs VALUES ('kept', 'alice', '{}'::jsonb),
                   ('cleared', 'alice', '{}'::jsonb)",
                "CREATE ROLE app_reader LOGIN; GRANT SELECT, UPDATE ON docs TO app_reader",
            ],
            vec![caller("alice"), caller("bob")],
        )
        .with_settings([support::deployment::caller("app.user_id")])
        .updating(
            "docs",
            "metadata = CASE WHEN id = 'cleared' THEN NULL ELSE metadata END",
        )
        .unobservable(
            "docs",
            "docs_update",
            ClauseKind::Using,
            Side::Denies,
            REPEATS_SELECT,
        );
        let run = support::parity::run_disclosing(&cluster, &case).await;
        for (object, allowed) in [("docs:kept", true), ("docs:cleared", false)] {
            assert_postgres(
                &case,
                &run,
                "alice",
                object,
                ActionStatement::Update,
                allowed,
            );
        }
        let updates: Vec<_> = run
            .observations
            .iter()
            .filter(|observation| observation.statement == ActionStatement::Update)
            .collect();
        assert!(!updates.is_empty(), "{}: no update was compared", case.name);
        assert!(updates.iter().all(|observation| !observation.openfga));
        assert!(!run.disclosures.is_empty());
        assert!(run.disclosures.iter().all(|disclosure| matches!(
            &disclosure.licence,
            Licence::Located {
                table,
                direction: Direction::Narrower,
                ..
            } if table == &resulting.table.sql_name()
        )));
        assert_disclosed_where_noted(&case, &run);
    }
}

/// A two-column key names the written row and its stored counterpart consistently.
#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_composite_key_insert_carries_its_stored_link_on_postgres_17_and_18() {
    let schema = "
CREATE TABLE pairs (a TEXT, b TEXT, owner_id TEXT NOT NULL, PRIMARY KEY (a, b));
ALTER TABLE pairs ENABLE ROW LEVEL SECURITY;
CREATE POLICY pairs_select ON pairs FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY pairs_insert ON pairs FOR INSERT
  WITH CHECK (owner_id = current_setting('app.user_id', true));
";
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        let case = ParityCase::reading(
            &format!("resulting-row-composite-pg{major}"),
            schema,
            &[
                "INSERT INTO pairs VALUES ('first', 'left', 'alice'), ('first', 'right', 'bob')",
                "CREATE ROLE app_reader LOGIN; GRANT SELECT, INSERT ON pairs TO app_reader",
            ],
            vec![caller("alice"), caller("bob")],
        )
        .with_settings([support::deployment::caller("app.user_id")]);
        let run = support::parity::run(&cluster, &case).await;
        assert_postgres(
            &case,
            &run,
            "alice",
            "pairs:first|left",
            ActionStatement::Insert,
            true,
        );
        assert_postgres(
            &case,
            &run,
            "alice",
            "pairs:first|right",
            ActionStatement::Insert,
            false,
        );
        assert_agrees(&case, &run);
    }
}
