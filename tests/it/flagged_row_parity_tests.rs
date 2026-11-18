//! Row flags compared against `PostgreSQL` 17 and 18, with both tuple loaders.

#![cfg(all(not(target_os = "windows"), feature = "client"))]

use core::time::Duration;

use rls2fga::types::ActionStatement;

use crate::support;
use crate::support::parity::{
    assert_agrees, assert_postgres, ClauseKind, Cluster, ParityCase, Principal, Side,
};

/// Resources their owner reads and changes, placed under parents by two edge tables,
/// archived when any ancestor is, and frozen below an archived resource while the archived
/// one stays open to restoring. Marks read the same test through their resource.
const FROZEN_BELOW: &str = "
CREATE ROLE authz_owner NOLOGIN BYPASSRLS;
CREATE SCHEMA authz;
GRANT USAGE ON SCHEMA authz TO authz_owner;
CREATE TABLE resources (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, archived_at TIMESTAMPTZ,
  label TEXT NOT NULL);
CREATE TABLE resource_parents (id TEXT PRIMARY KEY REFERENCES resources (id),
  parent_id TEXT NOT NULL REFERENCES resources (id));
CREATE TABLE ownables (id TEXT PRIMARY KEY REFERENCES resources (id),
  project_id TEXT NOT NULL REFERENCES resources (id));
CREATE TABLE marks (id TEXT PRIMARY KEY, resource_id TEXT NOT NULL REFERENCES resources (id));
GRANT SELECT ON resources, resource_parents, ownables TO authz_owner;
CREATE FUNCTION authz.is_archived(resource TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  WITH RECURSIVE ancestors (id) AS (
    SELECT resource
    UNION
    SELECT parent.id FROM ancestors CROSS JOIN LATERAL (
      SELECT edge.parent_id AS id FROM public.resource_parents edge WHERE edge.id = ancestors.id
      UNION ALL
      SELECT ownable.project_id FROM public.ownables ownable WHERE ownable.id = ancestors.id
    ) parent
  )
  SELECT EXISTS (
    SELECT 1 FROM ancestors JOIN public.resources ancestor ON ancestor.id = ancestors.id
    WHERE ancestor.archived_at IS NOT NULL
  )
$$;
CREATE FUNCTION authz.has_archived_ancestor(resource TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT EXISTS (SELECT 1 FROM public.resource_parents edge
                 WHERE edge.id = resource AND authz.is_archived(edge.parent_id))
    OR EXISTS (SELECT 1 FROM public.ownables ownable
               WHERE ownable.id = resource AND authz.is_archived(ownable.project_id))
$$;
ALTER FUNCTION authz.is_archived(TEXT) OWNER TO authz_owner;
ALTER FUNCTION authz.has_archived_ancestor(TEXT) OWNER TO authz_owner;
ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE marks ENABLE ROW LEVEL SECURITY;
CREATE POLICY resources_select ON resources FOR SELECT
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY resources_update ON resources FOR UPDATE
  USING (owner_id = current_setting('app.user_id', true));
CREATE POLICY resources_frozen_below ON resources AS RESTRICTIVE FOR UPDATE
  USING (NOT authz.has_archived_ancestor(id));
CREATE POLICY marks_below_archived ON marks FOR SELECT
  USING (authz.has_archived_ancestor(resource_id));
";

fn caller(subject: &str) -> Principal {
    Principal::with_setting(subject, "app_reader", "app.user_id", subject)
}

/// `root` is archived and holds `mid`, which holds `leaf`, both through `resource_parents`.
/// The archived `project` owns `item` and `mid` owns `item_mid`, both through `ownables`.
/// `other` stands alone and owns `item_other`, and the archived `cycle_a` and `cycle_b` are
/// each other's parent. Alice owns every resource, and each mark names the resource its key
/// ends with.
fn frozen_below_case(major: &str, loading_from_rows: bool) -> ParityCase {
    let mut case = ParityCase::reading(
        &format!(
            "flag-one-edge-up-pg{major}{}",
            if loading_from_rows { "-rows" } else { "" }
        ),
        FROZEN_BELOW,
        &[
            "INSERT INTO resources VALUES
               ('root', 'alice', now(), 'r'), ('mid', 'alice', NULL, 'm'),
               ('leaf', 'alice', NULL, 'l'), ('project', 'alice', now(), 'p'),
               ('item', 'alice', NULL, 'i'), ('item_mid', 'alice', NULL, 'i'),
               ('other', 'alice', NULL, 'o'), ('item_other', 'alice', NULL, 'i'),
               ('cycle_a', 'alice', now(), 'a'), ('cycle_b', 'alice', NULL, 'b'),
               ('change_owner', 'alice', NULL, 'c');
             INSERT INTO resource_parents VALUES
               ('mid', 'root'), ('leaf', 'mid'), ('cycle_a', 'cycle_b'), ('cycle_b', 'cycle_a');
             INSERT INTO ownables VALUES
               ('item', 'project'), ('item_mid', 'mid'), ('item_other', 'other');
             INSERT INTO marks VALUES
               ('m_root', 'root'), ('m_mid', 'mid'), ('m_leaf', 'leaf'), ('m_item', 'item'),
               ('m_other', 'other')",
            "CREATE ROLE app_reader LOGIN;
             GRANT SELECT, UPDATE (label, owner_id) ON resources TO app_reader;
             GRANT SELECT ON marks TO app_reader;
             GRANT USAGE ON SCHEMA authz TO app_reader;
             REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO app_reader",
        ],
        vec![
            caller("alice"),
            caller("bob"),
            Principal::as_role("anonymous", "app_reader"),
        ],
    )
    .with_settings([support::deployment::caller("app.user_id")])
    .updating(
        "resources",
        "label = 'changed', \
         owner_id = CASE WHEN id = 'change_owner' THEN 'bob' ELSE owner_id END",
    )
    .unobservable(
        "resources",
        "resources_update",
        ClauseKind::Using,
        Side::Denies,
        "The SELECT policy hides every row whose owner the UPDATE policy rejects",
    )
    .unobservable(
        "resources",
        "resources_update",
        ClauseKind::UsingAsCheck,
        Side::Denies,
        "repeats the SELECT policy's USING, which PostgreSQL also checks on the new row of an \
         UPDATE naming its rows",
    )
    .unobservable(
        "resources",
        "resources_frozen_below",
        ClauseKind::UsingAsCheck,
        Side::Denies,
        "A frozen new id belongs to another resource, which the primary key refuses",
    );
    case.loading_from_rows = loading_from_rows;
    case
}

#[tokio::test]
#[ignore = "requires Docker, postgres:17, postgres:18, and openfga/openfga containers"]
async fn a_flag_one_edge_up_either_edge_table_agrees_with_postgres_17_and_18() {
    for major in ["17", "18"] {
        let cluster = Cluster::start_on(major).await;
        for loading_from_rows in [false, true] {
            let case = frozen_below_case(major, loading_from_rows);
            let run = support::parity::run_before(&cluster, &case, Duration::from_secs(180)).await;
            let expect = |subject: &str, object: &str, statement, allowed| {
                assert_postgres(&case, &run, subject, object, statement, allowed);
            };
            // The archived row stays open to its owner, and every row below it is frozen.
            expect("alice", "resources:root", ActionStatement::Update, true);
            expect("alice", "resources:mid", ActionStatement::Update, false);
            expect("alice", "resources:leaf", ActionStatement::Update, false);
            expect("alice", "resources:mid", ActionStatement::Select, true);
            // Either edge table reaches the archived row, the walk past it too.
            expect("alice", "resources:project", ActionStatement::Update, true);
            expect("alice", "resources:item", ActionStatement::Update, false);
            expect(
                "alice",
                "resources:item_mid",
                ActionStatement::Update,
                false,
            );
            // A row with neither the flag nor a flagged ancestor stays open.
            expect("alice", "resources:other", ActionStatement::Update, true);
            expect(
                "alice",
                "resources:change_owner",
                ActionStatement::Update,
                false,
            );
            expect(
                "alice",
                "resources:item_other",
                ActionStatement::Update,
                true,
            );
            // Around a cycle each row is below the archived one, itself included.
            expect("alice", "resources:cycle_a", ActionStatement::Update, false);
            expect("alice", "resources:cycle_b", ActionStatement::Update, false);
            expect("bob", "resources:other", ActionStatement::Update, false);
            // The same test grants the marks on rows below an archived one, to anyone.
            expect("bob", "marks:m_mid", ActionStatement::Select, true);
            expect("bob", "marks:m_leaf", ActionStatement::Select, true);
            expect("bob", "marks:m_item", ActionStatement::Select, true);
            expect("bob", "marks:m_root", ActionStatement::Select, false);
            expect("bob", "marks:m_other", ActionStatement::Select, false);
            assert_agrees(&case, &run);
        }
    }
}
